//! Reading and updating session profiles in the shared credentials file.

use std::error::Error;
use std::io::Write;
use std::path::Path;
use std::time::Duration;
use std::{fs, io};

use aws_shared_config::{Document, FileKind};
use serde::{Deserialize, Serialize};
use tempfile::NamedTempFile;

use crate::session::{SessionCredentials, format_timestamp, parse_timestamp};

/// Session credentials stored as a profile in the shared credentials file.
pub struct SessionProfile<'a> {
    pub name: &'a str,
    pub credentials: &'a SessionCredentials,
    pub region: Option<&'a str>,
}

impl SessionProfile<'_> {
    fn stored(&self) -> StoredSession {
        StoredSession {
            aws_access_key_id: self.credentials.access_key_id.clone(),
            aws_secret_access_key: self.credentials.secret_access_key.clone(),
            aws_session_token: self.credentials.session_token.clone(),
            region: self.region.map(str::to_owned),
            expiration: self.credentials.expiration.map(format_timestamp),
        }
    }
}

/// The keys of a session profile.
///
/// `expiration` is not an AWS setting (AWS tools ignore it); it records when
/// the session ends so that a later run can tell whether it is still valid.
/// When saving, `None` removes a key, so a stale value never survives.
#[derive(Deserialize, Serialize)]
struct StoredSession {
    aws_access_key_id: String,
    aws_secret_access_key: String,
    aws_session_token: String,
    region: Option<String>,
    expiration: Option<String>,
}

/// Read and parse the credentials file; a missing file reads as empty.
pub fn load(path: &Path) -> io::Result<Document> {
    // A missing file is a valid starting point (e.g. env-var-only auth, fresh
    // setup): `save` creates it.
    let contents = match fs::read_to_string(path) {
        Err(e) if e.kind() == io::ErrorKind::NotFound => String::new(),
        result => result?,
    };
    Document::parse(&contents, FileKind::Credentials).map_err(invalid_data)
}

/// Read back the session credentials stored in the `[name]` profile, if it has
/// a complete set.
pub fn find_session(doc: &Document, name: &str) -> Option<SessionCredentials> {
    let stored: StoredSession = doc.profile(name)?.deserialize().ok()?;
    Some(SessionCredentials {
        access_key_id: stored.aws_access_key_id,
        secret_access_key: stored.aws_secret_access_key,
        session_token: stored.aws_session_token,
        expiration: stored.expiration.as_deref().and_then(parse_timestamp),
    })
}

/// Write `profile` into the credentials file at `path`, creating the file (and
/// its directory) if needed. Only the profile's session keys change: comments,
/// its other keys, and other profiles stay as they were. The file is replaced
/// atomically and left readable only by its owner.
pub fn save(path: &Path, profile: &SessionProfile) -> io::Result<()> {
    let mut doc = load(path)?;
    doc.profile_mut(profile.name)
        .serialize(&profile.stored())
        .map_err(invalid_data)?;
    let updated = doc.to_string();

    // Ensure the parent directory exists so the temp file can be created next to
    // the target (required for an atomic same-filesystem rename). Only adjust
    // permissions on a directory we create ourselves — never re-permission a
    // pre-existing directory the user owns.
    let dir = path.parent().unwrap_or_else(|| Path::new("."));
    if !dir.as_os_str().is_empty() && !dir.exists() {
        fs::create_dir_all(dir)?;
        // We just created ~/.aws; tighten it to owner-only. Best-effort: the
        // credentials file itself is forced to 0600 below regardless, so a
        // failure to chmod the directory must not abort the credential write.
        let _ = set_mode(dir, 0o700);
    }

    let mut temp_file = NamedTempFile::new_in(dir)?;
    temp_file.write_all(updated.as_bytes())?;
    // Flush to disk before the rename, so a crash cannot leave an empty file
    // in place of the user's credentials.
    temp_file.as_file().sync_all()?;

    // Enforce 0600 on the secret-bearing file rather than inheriting whatever
    // permissions the original had (which may have been group/world readable).
    // This is the critical protection, so its failure is propagated.
    set_mode(temp_file.path(), 0o600)?;

    persist_with_retry(temp_file, path)
}

fn invalid_data(error: impl Into<Box<dyn Error + Send + Sync>>) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, error)
}

/// Set the Unix permission bits of `path`. No-op on non-Unix platforms.
#[cfg(unix)]
fn set_mode(path: &Path, mode: u32) -> io::Result<()> {
    use std::os::unix::fs::PermissionsExt;
    fs::set_permissions(path, fs::Permissions::from_mode(mode))
}

#[cfg(not(unix))]
fn set_mode(_path: &Path, _mode: u32) -> io::Result<()> {
    Ok(())
}

/// Backoff delays between atomic-persist attempts. The number of entries is the
/// number of retries (total attempts = len + 1); the growth keeps the worst-case
/// wait under a second while giving a briefly-locked destination time to free up.
const PERSIST_RETRY_BACKOFF: [Duration; 5] = [
    Duration::from_millis(20),
    Duration::from_millis(40),
    Duration::from_millis(80),
    Duration::from_millis(160),
    Duration::from_millis(320),
];

/// Whether a failed atomic persist (rename) is worth retrying. Only Windows
/// exhibits the transient failures a short retry clears — when the destination
/// is briefly held open by another process (antivirus, search indexer):
/// ERROR_ACCESS_DENIED (5), ERROR_SHARING_VIOLATION (32), ERROR_LOCK_VIOLATION
/// (33). On other platforms a rename failure is terminal (and those same raw
/// codes mean unrelated errors, e.g. `EIO`), so never retry.
#[cfg(windows)]
fn is_transient_persist_error(error: &io::Error) -> bool {
    matches!(error.raw_os_error(), Some(5 | 32 | 33))
}

#[cfg(not(windows))]
fn is_transient_persist_error(_error: &io::Error) -> bool {
    false
}

/// Run `attempt` until it succeeds, sleeping between transient failures per the
/// `backoff` schedule and giving up once it is exhausted. Non-transient errors
/// return immediately. `is_transient` is injected (rather than calling the
/// classifier directly) so the retry policy is tested deterministically on every
/// platform, not only where the OS-specific classifier reports failures.
fn persist_retrying<F, T>(mut attempt: F, backoff: &[Duration], is_transient: T) -> io::Result<()>
where
    F: FnMut() -> io::Result<()>,
    T: Fn(&io::Error) -> bool,
{
    for delay in backoff {
        match attempt() {
            Ok(()) => return Ok(()),
            Err(e) if is_transient(&e) => std::thread::sleep(*delay),
            Err(e) => return Err(e),
        }
    }
    attempt()
}

/// Atomically move `temp_file` onto `dest`, retrying transient Windows rename
/// failures. The temp file is recovered from each failed attempt so the next one
/// can reuse it.
fn persist_with_retry(temp_file: NamedTempFile, dest: &Path) -> io::Result<()> {
    let mut slot = Some(temp_file);
    persist_retrying(
        || {
            let tf = slot
                .take()
                .expect("temp file is present before each attempt");
            tf.persist(dest).map(|_| ()).map_err(|e| {
                slot = Some(e.file);
                e.error
            })
        },
        &PERSIST_RETRY_BACKOFF,
        is_transient_persist_error,
    )
}

#[cfg(test)]
mod test {
    use super::*;
    use crate::session::tests::{at, sample_credentials};

    impl SessionProfile<'_> {
        /// The profile as it appears in a credentials file of its own.
        pub(crate) fn section(&self) -> String {
            let mut doc = Document::new(FileKind::Credentials);
            doc.profile_mut(self.name)
                .serialize(&self.stored())
                .unwrap();
            doc.to_string()
        }
    }

    /// The session in `[name]` of a credentials file with `contents`.
    fn session_in(contents: &str, name: &str) -> Option<SessionCredentials> {
        let doc = Document::parse(contents, FileKind::Credentials).unwrap();
        find_session(&doc, name)
    }

    /// A profile with long-term credentials, as users write them by hand.
    fn long_term(name: &str) -> String {
        format!("[{name}]\naws_access_key_id = AKIA\naws_secret_access_key = SECRET\n")
    }

    /// Assert the low 9 permission bits of `path`. No-op on non-Unix platforms.
    #[cfg(unix)]
    fn assert_mode(path: &Path, expected: u32, msg: &str) {
        use std::os::unix::fs::PermissionsExt;
        let mode = fs::metadata(path).unwrap().permissions().mode();
        assert_eq!(mode & 0o777, expected, "{msg}");
    }

    #[cfg(not(unix))]
    fn assert_mode(_path: &Path, _expected: u32, _msg: &str) {}

    #[test]
    fn test_section_with_all_fields() {
        let credentials = sample_credentials();
        let profile = SessionProfile {
            name: "test-session",
            credentials: &credentials,
            region: Some("us-west-2"),
        };
        assert_eq!(
            profile.section(),
            "[test-session]\n\
             aws_access_key_id = ASIATEST\n\
             aws_secret_access_key = secret\n\
             aws_session_token = token\n\
             region = us-west-2\n\
             expiration = 2027-01-15T08:00:00Z\n"
        );
    }

    #[test]
    fn test_section_without_optional_fields() {
        let credentials = SessionCredentials {
            expiration: None,
            ..sample_credentials()
        };
        let profile = SessionProfile {
            name: "minimal",
            credentials: &credentials,
            region: None,
        };
        let section = profile.section();
        assert!(section.ends_with("aws_session_token = token\n"));
        assert!(!section.contains("region"));
        assert!(!section.contains("expiration"));
    }

    #[test]
    fn test_find_session_round_trips_section() {
        let credentials = sample_credentials();
        let profile = SessionProfile {
            name: "session",
            credentials: &credentials,
            region: Some("eu-west-1"),
        };
        let contents = format!("{}\n{}", long_term("default"), profile.section());
        assert_eq!(session_in(&contents, "session"), Some(credentials));
    }

    #[test]
    fn test_find_session_tolerates_formatting() {
        let contents = "[other]\naws_session_token = WRONG\n\n\
                        [session]\r\n\
                        # a comment = not a value\r\n\
                        AWS_ACCESS_KEY_ID=KEY\r\n\
                        aws_secret_access_key   =   SECRET  \r\n\
                        aws_session_token = TOKEN==\r\n\
                        expiration = 2027-01-15T08:00:00Z\r\n";
        let found = session_in(contents, "session").unwrap();
        assert_eq!(found.access_key_id, "KEY");
        assert_eq!(found.secret_access_key, "SECRET");
        assert_eq!(found.session_token, "TOKEN==");
        assert_eq!(found.expiration, Some(at(1_800_000_000)));
    }

    #[test]
    fn test_find_session_requires_complete_credentials() {
        // Long-term credentials have no session token, so they are not a session.
        assert_eq!(session_in(&long_term("dev"), "dev"), None);
        assert_eq!(session_in(&long_term("dev"), "missing"), None);
        assert_eq!(session_in("", "dev"), None);
    }

    #[test]
    fn test_find_session_with_unparsable_expiration() {
        let contents = "[s]\naws_access_key_id = K\naws_secret_access_key = S\n\
                        aws_session_token = T\nexpiration = soon\n";
        assert_eq!(session_in(contents, "s").unwrap().expiration, None);
    }

    fn save_sample(path: &Path) -> io::Result<()> {
        let credentials = sample_credentials();
        save(
            path,
            &SessionProfile {
                name: "session",
                credentials: &credentials,
                region: Some("us-east-1"),
            },
        )
    }

    #[test]
    fn test_save_updates_profile_in_place() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("credentials");
        fs::write(
            &path,
            "# Long-term keys\n\
             [default]\n\
             aws_access_key_id = AKIA\n\
             \n\
             [session]\n\
             # Managed by aws-mfa-session\n\
             aws_access_key_id = OLD   # replaced in place\n\
             aws_secret_access_key = OLD\n\
             aws_session_token = OLD\n\
             expiration = 2020-01-01T00:00:00Z\n\
             output = json\n",
        )
        .unwrap();
        let credentials = SessionCredentials {
            expiration: None,
            ..sample_credentials()
        };

        save(
            &path,
            &SessionProfile {
                name: "session",
                credentials: &credentials,
                region: Some("eu-west-1"),
            },
        )
        .unwrap();

        // Comments and unrelated keys stay; the stale expiration goes.
        assert_eq!(
            fs::read_to_string(&path).unwrap(),
            "# Long-term keys\n\
             [default]\n\
             aws_access_key_id = AKIA\n\
             \n\
             [session]\n\
             # Managed by aws-mfa-session\n\
             aws_access_key_id = ASIATEST   # replaced in place\n\
             aws_secret_access_key = secret\n\
             aws_session_token = token\n\
             output = json\n\
             region = eu-west-1\n"
        );
    }

    #[test]
    fn test_save_refuses_invalid_file() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("credentials");
        let invalid = "aws_access_key_id = outside any profile\n";
        fs::write(&path, invalid).unwrap();

        let error = save_sample(&path).unwrap_err();

        assert_eq!(error.kind(), io::ErrorKind::InvalidData);
        assert!(error.to_string().contains("line 1"), "{error}");
        assert_eq!(fs::read_to_string(&path).unwrap(), invalid);
    }

    #[test]
    fn test_load_missing_file_is_empty() {
        let dir = tempfile::tempdir().unwrap();
        let doc = load(&dir.path().join("credentials")).unwrap();
        assert!(doc.profile_names().is_empty());
    }

    #[test]
    fn test_load_rejects_invalid_file() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("credentials");
        fs::write(&path, "not a credentials file\n").unwrap();

        let error = load(&path).unwrap_err();

        assert_eq!(error.kind(), io::ErrorKind::InvalidData);
        assert!(error.to_string().contains("line 1"), "{error}");
    }

    #[test]
    fn test_save_creates_missing_file() {
        let dir = tempfile::tempdir().unwrap();
        // Parent directory does not exist yet either.
        let path = dir.path().join("nested").join("credentials");
        save_sample(&path).unwrap();

        let written = fs::read_to_string(&path).unwrap();
        assert!(written.starts_with("[session]\naws_access_key_id = ASIATEST\n"));
        assert_eq!(session_in(&written, "session"), Some(sample_credentials()));

        assert_mode(&path, 0o600, "newly created credentials file must be 0600");
        assert_mode(
            path.parent().unwrap(),
            0o700,
            "a created directory is owner-only",
        );
    }

    #[test]
    fn test_save_enforces_0600_permissions() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("credentials");
        fs::write(&path, "[existing]\naws_access_key_id = OLD\n").unwrap();
        set_mode(&path, 0o644).unwrap();

        save_sample(&path).unwrap();

        let written = fs::read_to_string(&path).unwrap();
        assert!(written.contains("[existing]")); // pre-existing content preserved
        assert!(written.contains("[session]")); // new profile appended
        assert_mode(
            &path,
            0o600,
            "loose 0644 permissions must be tightened to 0600",
        );
    }

    #[test]
    fn test_save_does_not_repermission_existing_dir() {
        let dir = tempfile::tempdir().unwrap();
        // The parent directory already exists with perms the tool must not change.
        set_mode(dir.path(), 0o755).unwrap();
        let path = dir.path().join("credentials");

        save_sample(&path).unwrap();

        assert_mode(
            dir.path(),
            0o755,
            "a pre-existing parent directory must be left untouched",
        );
        assert_mode(
            &path,
            0o600,
            "the credentials file itself is still written 0600",
        );
    }

    // Zero-delay schedule so the retry-policy tests stay instant and deterministic
    // (the production schedule is PERSIST_RETRY_BACKOFF). Length defines the retry
    // count: total attempts = len + 1.
    const NO_DELAY: [Duration; 3] = [Duration::ZERO; 3];

    // Test classifier: treat only raw OS error 5 as transient, so the retry loop
    // is exercised identically on every platform (the production classifier is
    // Windows-gated and reports nothing off Windows).
    fn only_5_is_transient(error: &io::Error) -> bool {
        error.raw_os_error() == Some(5)
    }

    #[cfg(windows)]
    #[test]
    fn test_is_transient_persist_error_windows() {
        use io::{Error, ErrorKind};
        // The Windows rename codes we recover from (code 5 is the observed CI flake).
        for code in [5, 32, 33] {
            assert!(
                is_transient_persist_error(&Error::from_raw_os_error(code)),
                "os error {code} should be treated as transient on Windows"
            );
        }
        // Terminal conditions must not be retried.
        assert!(!is_transient_persist_error(&Error::from_raw_os_error(2)));
        assert!(!is_transient_persist_error(&Error::new(
            ErrorKind::NotFound,
            "gone"
        )));
        assert!(!is_transient_persist_error(&Error::other("no os code")));
    }

    #[cfg(not(windows))]
    #[test]
    fn test_is_transient_persist_error_non_windows() {
        use io::Error;
        // Off Windows there are no transient rename failures to recover from, and
        // these raw codes mean unrelated errors (e.g. EIO=5), so never retry.
        for code in [5, 32, 33, 2] {
            assert!(!is_transient_persist_error(&Error::from_raw_os_error(code)));
        }
    }

    #[test]
    fn test_persist_retrying_succeeds_without_retry() {
        let mut calls = 0;
        let result = persist_retrying(
            || {
                calls += 1;
                Ok(())
            },
            &NO_DELAY,
            only_5_is_transient,
        );
        assert!(result.is_ok());
        assert_eq!(calls, 1, "a first-try success must not retry");
    }

    #[test]
    fn test_persist_retrying_recovers_after_transient_failures() {
        let mut calls = 0;
        let result = persist_retrying(
            || {
                calls += 1;
                if calls < 3 {
                    Err(io::Error::from_raw_os_error(5))
                } else {
                    Ok(())
                }
            },
            &NO_DELAY,
            only_5_is_transient,
        );
        assert!(result.is_ok());
        assert_eq!(
            calls, 3,
            "must keep retrying until the transient error clears"
        );
    }

    #[test]
    fn test_persist_retrying_gives_up_after_exhausting_retries() {
        let mut calls = 0;
        let result = persist_retrying(
            || {
                calls += 1;
                Err(io::Error::from_raw_os_error(5))
            },
            &NO_DELAY,
            only_5_is_transient,
        );
        assert!(result.is_err());
        assert_eq!(
            calls,
            NO_DELAY.len() + 1,
            "one attempt per backoff slot plus a final attempt"
        );
    }

    #[test]
    fn test_persist_retrying_non_transient_fails_fast() {
        let mut calls = 0;
        let result = persist_retrying(
            || {
                calls += 1;
                Err(io::Error::new(io::ErrorKind::NotFound, "gone"))
            },
            &NO_DELAY,
            only_5_is_transient,
        );
        assert!(result.is_err());
        assert_eq!(calls, 1, "a terminal error must not be retried");
    }
}
