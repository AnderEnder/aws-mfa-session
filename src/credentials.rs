//! Reading and updating session profiles in the shared credentials file.

use std::ops::Range;
use std::path::Path;
use std::time::Duration;
use std::{fs, io};

use tempfile::NamedTempFile;

use crate::session::{SessionCredentials, format_timestamp, parse_timestamp};

/// Session credentials stored as a profile in the shared credentials file.
pub struct SessionProfile<'a> {
    pub name: &'a str,
    pub credentials: &'a SessionCredentials,
    pub region: Option<&'a str>,
}

impl SessionProfile<'_> {
    /// The profile's INI section, ending with a single newline.
    ///
    /// `expiration` is not an AWS setting (AWS tools ignore it); it records when
    /// the session ends so that a later run can tell whether it is still valid.
    pub fn section(&self) -> String {
        let expiration = self.credentials.expiration.map(format_timestamp);
        let entries = [
            (
                "aws_access_key_id",
                Some(self.credentials.access_key_id.as_str()),
            ),
            (
                "aws_secret_access_key",
                Some(self.credentials.secret_access_key.as_str()),
            ),
            (
                "aws_session_token",
                Some(self.credentials.session_token.as_str()),
            ),
            ("region", self.region),
            ("expiration", expiration.as_deref()),
        ];

        let mut section = format!("[{}]\n", self.name);
        for (key, value) in entries {
            if let Some(value) = value {
                section.push_str(&format!("{key} = {value}\n"));
            }
        }
        section
    }
}

/// Read back the session credentials stored in the `[name]` profile, if it has
/// a complete set.
pub fn find_session(contents: &str, name: &str) -> Option<SessionCredentials> {
    let lines: Vec<&str> = contents.split_inclusive('\n').collect();
    let span = section_span(&lines, name)?;
    let entries: Vec<(&str, &str)> = lines[span]
        .iter()
        .skip(1) // the header
        .map(|line| line.trim())
        .filter(|line| !line.starts_with(['#', ';']))
        .filter_map(|line| line.split_once('='))
        .map(|(key, value)| (key.trim(), value.trim()))
        .collect();
    let get = |key: &str| {
        entries
            .iter()
            .find(|(k, _)| *k == key)
            .map(|(_, value)| value.to_string())
    };

    Some(SessionCredentials {
        access_key_id: get("aws_access_key_id")?,
        secret_access_key: get("aws_secret_access_key")?,
        session_token: get("aws_session_token")?,
        expiration: get("expiration").and_then(|value| parse_timestamp(&value)),
    })
}

/// Insert or replace the `[name]` section of an INI `contents` with `section`,
/// touching only the target section. Everything else — comments, ordering,
/// spacing of other sections — is preserved byte-for-byte.
pub fn replace_section(contents: &str, name: &str, section: &str) -> String {
    // Keep line endings attached so the untouched parts are rebuilt verbatim
    // (also handles "\r\n" since trimming removes the trailing '\r').
    let lines: Vec<&str> = contents.split_inclusive('\n').collect();

    match section_span(&lines, name) {
        Some(span) => {
            let mut out = String::with_capacity(contents.len() + section.len());
            out.extend(lines[..span.start].iter().copied());
            out.push_str(section);
            out.extend(lines[span.end..].iter().copied());
            out
        }
        None if contents.is_empty() => section.to_owned(),
        None => {
            // Append after the existing content with exactly one blank-line separator.
            let mut out = contents.to_owned();
            if !out.ends_with('\n') {
                out.push('\n');
            }
            if !out.ends_with("\n\n") {
                out.push('\n');
            }
            out.push_str(section);
            out
        }
    }
}

/// The lines of the `[name]` section: from its header up to the next section
/// header, excluding trailing blank lines, which act as separators.
///
/// Section detection is line-based: a header is any line whose left-trimmed text
/// starts with `[`, and the target section is the header line whose fully-trimmed
/// text equals `[name]` exactly. This avoids the substring/prefix hazards of
/// matching names inside other headers, values, or comments.
fn section_span(lines: &[&str], name: &str) -> Option<Range<usize>> {
    let header = format!("[{name}]");
    let is_header = |line: &&str| line.trim_start().starts_with('[');

    let start = lines.iter().position(|line| line.trim() == header)?;
    let mut end = lines[start + 1..]
        .iter()
        .position(is_header)
        .map_or(lines.len(), |i| start + 1 + i);
    while end - 1 > start && lines[end - 1].trim().is_empty() {
        end -= 1;
    }
    Some(start..end)
}

/// Read the credentials file; a missing file reads as empty.
pub fn read(path: &Path) -> io::Result<String> {
    match fs::read_to_string(path) {
        Err(e) if e.kind() == io::ErrorKind::NotFound => Ok(String::new()),
        result => result,
    }
}

/// Write `profile` into the credentials file at `path`, creating the file (and
/// its directory) if needed. The file is replaced atomically and left readable
/// only by its owner.
pub fn save(path: &Path, profile: &SessionProfile) -> io::Result<()> {
    // A missing credentials file is a valid starting point (e.g. env-var-only
    // auth, fresh setup): treat it as empty and create it below.
    let contents = read(path)?;
    let updated = replace_section(&contents, profile.name, &profile.section());

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

    let temp_file = NamedTempFile::new_in(dir)?;
    fs::write(temp_file.path(), updated)?;

    // Enforce 0600 on the secret-bearing file rather than inheriting whatever
    // permissions the original had (which may have been group/world readable).
    // This is the critical protection, so its failure is propagated.
    set_mode(temp_file.path(), 0o600)?;

    persist_with_retry(temp_file, path)
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

    /// A minimal section like the ones in hand-written credentials files.
    fn section(name: &str, key: &str, secret: &str) -> String {
        format!("[{name}]\naws_access_key_id = {key}\naws_secret_access_key = {secret}\n")
    }

    fn new_section(name: &str) -> String {
        section(name, "AACCCCEESSSSKKEEYY/NEW", "SEC123RET/NEW")
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
    fn test_section_values_are_literal() {
        // Regression: an earlier `Regex::replace` expanded `$1`/`${name}` in the
        // replacement string, silently dropping characters. Values must be literal.
        let credentials = SessionCredentials {
            secret_access_key: "se$1cret".to_owned(),
            session_token: "tok${en}".to_owned(),
            ..sample_credentials()
        };
        let profile = SessionProfile {
            name: "session",
            credentials: &credentials,
            region: Some("us-$0-1"),
        };
        let original = "[session]\naws_access_key_id = OLD\naws_secret_access_key = OLD\n";
        let updated = replace_section(original, "session", &profile.section());
        assert!(
            updated.contains("aws_secret_access_key = se$1cret"),
            "got:\n{updated}"
        );
        assert!(updated.contains("aws_session_token = tok${en}"));
        assert!(updated.contains("region = us-$0-1"));
    }

    #[test]
    fn test_find_session_round_trips_section() {
        let credentials = sample_credentials();
        let profile = SessionProfile {
            name: "session",
            credentials: &credentials,
            region: Some("eu-west-1"),
        };
        let contents = format!("{}\n{}", section("default", "K", "S"), profile.section());
        assert_eq!(find_session(&contents, "session"), Some(credentials));
    }

    #[test]
    fn test_find_session_tolerates_formatting() {
        let contents = "[other]\naws_session_token = WRONG\n\n\
                        [session]\r\n\
                        # a comment = not a value\r\n\
                        aws_access_key_id=KEY\r\n\
                        aws_secret_access_key   =   SECRET  \r\n\
                        aws_session_token = TOKEN==\r\n\
                        expiration = 2027-01-15T08:00:00Z\r\n";
        let found = find_session(contents, "session").unwrap();
        assert_eq!(found.access_key_id, "KEY");
        assert_eq!(found.secret_access_key, "SECRET");
        assert_eq!(found.session_token, "TOKEN==");
        assert_eq!(found.expiration, Some(at(1_800_000_000)));
    }

    #[test]
    fn test_find_session_requires_complete_credentials() {
        // Long-term credentials have no session token, so they are not a session.
        assert_eq!(find_session(&section("dev", "K", "S"), "dev"), None);
        assert_eq!(find_session(&section("dev", "K", "S"), "missing"), None);
        assert_eq!(find_session("", "dev"), None);
    }

    #[test]
    fn test_find_session_with_unparsable_expiration() {
        let contents = "[s]\naws_access_key_id = K\naws_secret_access_key = S\n\
                        aws_session_token = T\nexpiration = soon\n";
        assert_eq!(find_session(contents, "s").unwrap().expiration, None);
    }

    #[test]
    fn test_replace_section_empty() {
        // An empty config yields just the section (no leading blank lines).
        let updated = replace_section("", "session-production", &new_section("session-production"));
        assert_eq!(updated, new_section("session-production"));
    }

    #[test]
    fn test_replace_section_append() {
        let original = r##"[default]
aws_access_key_id = AACCCCEESSSSKKEEYY/DEFAULT
aws_secret_access_key = SEC123RET/DEFAULT

[production]
aws_access_key_id = AACCCCEESSSSKKEEYY/PROD
aws_secret_access_key = SEC123RET/PROD
"##;

        // Appended after the existing content with a single blank-line separator.
        let updated = replace_section(
            original,
            "session-production",
            &new_section("session-production"),
        );
        assert_eq!(
            updated,
            r##"[default]
aws_access_key_id = AACCCCEESSSSKKEEYY/DEFAULT
aws_secret_access_key = SEC123RET/DEFAULT

[production]
aws_access_key_id = AACCCCEESSSSKKEEYY/PROD
aws_secret_access_key = SEC123RET/PROD

[session-production]
aws_access_key_id = AACCCCEESSSSKKEEYY/NEW
aws_secret_access_key = SEC123RET/NEW
"##
        )
    }

    #[test]
    fn test_replace_section_first() {
        let original = r##"[session-production]
aws_access_key_id = AACCCCEESSSSKKEEYY/OLD
aws_secret_access_key = SEC123RET/OLD

[default]
aws_access_key_id = AACCCCEESSSSKKEEYY/DEFAULT
aws_secret_access_key = SEC123RET/DEFAULT

[production]
aws_access_key_id = AACCCCEESSSSKKEEYY/PROD
aws_secret_access_key = SEC123RET/PROD"##;

        let updated = replace_section(
            original,
            "session-production",
            &new_section("session-production"),
        );
        assert_eq!(
            updated,
            r##"[session-production]
aws_access_key_id = AACCCCEESSSSKKEEYY/NEW
aws_secret_access_key = SEC123RET/NEW

[default]
aws_access_key_id = AACCCCEESSSSKKEEYY/DEFAULT
aws_secret_access_key = SEC123RET/DEFAULT

[production]
aws_access_key_id = AACCCCEESSSSKKEEYY/PROD
aws_secret_access_key = SEC123RET/PROD"##
        );
    }

    const SESSION_INSIDE: &str = r##"[default]
aws_access_key_id = AACCCCEESSSSKKEEYY/DEFAULT
aws_secret_access_key = SEC123RET/DEFAULT

[session-production]
aws_access_key_id = AACCCCEESSSSKKEEYY/OLD
aws_secret_access_key = SEC123RET/OLD

[production]
aws_access_key_id = AACCCCEESSSSKKEEYY/PROD
aws_secret_access_key = SEC123RET/PROD"##;

    const SESSION_INSIDE_REPLACED: &str = r##"[default]
aws_access_key_id = AACCCCEESSSSKKEEYY/DEFAULT
aws_secret_access_key = SEC123RET/DEFAULT

[session-production]
aws_access_key_id = AACCCCEESSSSKKEEYY/NEW
aws_secret_access_key = SEC123RET/NEW

[production]
aws_access_key_id = AACCCCEESSSSKKEEYY/PROD
aws_secret_access_key = SEC123RET/PROD"##;

    #[test]
    fn test_replace_section_inside() {
        let updated = replace_section(
            SESSION_INSIDE,
            "session-production",
            &new_section("session-production"),
        );
        assert_eq!(updated, SESSION_INSIDE_REPLACED);
    }

    #[test]
    fn test_replace_section_inside_is_idempotent() {
        let section = new_section("session-production");
        let once = replace_section(SESSION_INSIDE, "session-production", &section);
        let twice = replace_section(&once, "session-production", &section);
        assert_eq!(twice, SESSION_INSIDE_REPLACED);
    }

    const SESSION_LAST: &str = r##"[default]
aws_access_key_id = AACCCCEESSSSKKEEYY/DEFAULT
aws_secret_access_key = SEC123RET/DEFAULT

[production]
aws_access_key_id = AACCCCEESSSSKKEEYY/PROD
aws_secret_access_key = SEC123RET/PROD

[session-production]
aws_access_key_id = AACCCCEESSSSKKEEYY/OLD
aws_secret_access_key = SEC123RET/OLD"##;

    const SESSION_LAST_REPLACED: &str = r##"[default]
aws_access_key_id = AACCCCEESSSSKKEEYY/DEFAULT
aws_secret_access_key = SEC123RET/DEFAULT

[production]
aws_access_key_id = AACCCCEESSSSKKEEYY/PROD
aws_secret_access_key = SEC123RET/PROD

[session-production]
aws_access_key_id = AACCCCEESSSSKKEEYY/NEW
aws_secret_access_key = SEC123RET/NEW
"##;

    #[test]
    fn test_replace_section_last() {
        // Replacing the last section leaves a single trailing newline (no extra blank line).
        let updated = replace_section(
            SESSION_LAST,
            "session-production",
            &new_section("session-production"),
        );
        assert_eq!(updated, SESSION_LAST_REPLACED);
    }

    #[test]
    fn test_replace_section_last_is_idempotent() {
        let section = new_section("session-production");
        let once = replace_section(SESSION_LAST, "session-production", &section);
        let twice = replace_section(&once, "session-production", &section);
        assert_eq!(twice, SESSION_LAST_REPLACED);
    }

    #[test]
    fn test_replace_section_preserves_comments() {
        let original = "\
# top comment
[default]
aws_access_key_id = DEFAULTKEY
; keep this comment between keys
aws_secret_access_key = DEFAULTSECRET

[session]
aws_access_key_id = OLD
aws_secret_access_key = OLD
";
        let updated = replace_section(original, "session", &new_section("session"));
        // Untouched section (and its comments) survive byte-for-byte.
        assert!(updated.contains(
            "# top comment\n[default]\naws_access_key_id = DEFAULTKEY\n; keep this comment between keys\naws_secret_access_key = DEFAULTSECRET\n"
        ));
        // Target section was rewritten.
        assert!(updated.contains("[session]\naws_access_key_id = AACCCCEESSSSKKEEYY/NEW\n"));
        assert!(!updated.contains("aws_access_key_id = OLD"));
    }

    #[test]
    fn test_replace_section_prefix_names_dont_collide() {
        let original = "\
[prod]
aws_access_key_id = PRODKEY
aws_secret_access_key = PRODSECRET

[production]
aws_access_key_id = PRODUCTIONKEY
aws_secret_access_key = PRODUCTIONSECRET
";
        let updated = replace_section(original, "prod", &new_section("prod"));
        assert!(updated.contains("[prod]\naws_access_key_id = AACCCCEESSSSKKEEYY/NEW\n"));
        // [production] must be untouched even though [prod] is a prefix of it.
        assert!(updated.contains(
            "[production]\naws_access_key_id = PRODUCTIONKEY\naws_secret_access_key = PRODUCTIONSECRET\n"
        ));
        assert!(!updated.contains("PRODKEY"));
    }

    #[test]
    fn test_replace_section_comment_mentioning_section_is_not_a_header() {
        // A comment that merely mentions [session] must not be treated as the
        // section header (an earlier `config.contains()` check had this bug).
        let original = "\
# remember to rotate [session] keys
[default]
aws_access_key_id = DEFAULTKEY
aws_secret_access_key = DEFAULTSECRET
";
        let updated = replace_section(original, "session", &new_section("session"));
        assert!(updated.contains("# remember to rotate [session] keys"));
        // The profile is appended; the only real `[session]` header is the new one.
        assert_eq!(updated.matches("[session]\n").count(), 1);
        assert!(updated.ends_with(&new_section("session")));
    }

    #[test]
    fn test_replace_section_last_without_trailing_newline() {
        let original = "[default]\naws_access_key_id = D\n\n[session]\naws_access_key_id = OLD\naws_secret_access_key = OLD";
        let updated = replace_section(original, "session", &new_section("session"));
        assert_eq!(
            updated,
            format!(
                "[default]\naws_access_key_id = D\n\n{}",
                new_section("session")
            )
        );
    }

    #[test]
    fn test_replace_section_bracket_in_value_does_not_split_section() {
        // A `[` that is not at the start of a line is not a section boundary, so
        // the span scan must run past it to the real next header ([session]).
        let original = "[default]\naws_access_key_id = OLDKEY\nnote = see [archive] dump\naws_secret_access_key = OLDSECRET\n\n[session]\naws_access_key_id = KEEP\n";
        let updated = replace_section(original, "default", &new_section("default"));
        // [default] replaced wholesale (note line gone); [session] untouched.
        assert!(!updated.contains("note = see [archive] dump"));
        assert!(!updated.contains("OLDKEY"));
        assert!(updated.contains("[default]\naws_access_key_id = AACCCCEESSSSKKEEYY/NEW\n"));
        assert!(updated.contains("[session]\naws_access_key_id = KEEP\n"));
    }

    #[test]
    fn test_replace_section_handles_crlf_in_untouched_sections() {
        let original =
            "[default]\r\naws_access_key_id = D\r\n\r\n[session]\r\naws_access_key_id = OLD\r\n";
        let updated = replace_section(original, "session", &new_section("session"));
        // CRLF content outside the target is preserved verbatim.
        assert!(updated.contains("[default]\r\naws_access_key_id = D\r\n"));
        assert!(updated.contains("[session]\naws_access_key_id = AACCCCEESSSSKKEEYY/NEW\n"));
        assert!(!updated.contains("OLD"));
    }

    #[test]
    fn test_replace_section_append_then_replace_is_idempotent() {
        let base = "[default]\naws_access_key_id = D\naws_secret_access_key = S\n";
        let once = replace_section(base, "session", &new_section("session"));
        let twice = replace_section(&once, "session", &new_section("session"));
        assert_eq!(once, twice);
        assert!(twice.contains("[default]\naws_access_key_id = D\n"));
        assert_eq!(twice.matches("[session]\n").count(), 1);
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
    fn test_read_missing_file_is_empty() {
        let dir = tempfile::tempdir().unwrap();
        assert_eq!(read(&dir.path().join("credentials")).unwrap(), "");
    }

    #[test]
    fn test_save_creates_missing_file() {
        let dir = tempfile::tempdir().unwrap();
        // Parent directory does not exist yet either.
        let path = dir.path().join("nested").join("credentials");
        save_sample(&path).unwrap();

        let written = fs::read_to_string(&path).unwrap();
        assert!(written.starts_with("[session]\naws_access_key_id = ASIATEST\n"));
        assert_eq!(
            find_session(&written, "session"),
            Some(sample_credentials())
        );

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
