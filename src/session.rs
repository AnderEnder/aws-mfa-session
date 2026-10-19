//! Session credentials and the identity they belong to, independent of the
//! AWS SDK types so the rest of the code (and its tests) can use plain values.

use std::fmt;
use std::time::{Duration, SystemTime};

use aws_sdk_sts::primitives::{DateTime, DateTimeFormat};

/// Temporary credentials for an MFA-authenticated session.
#[derive(Clone, PartialEq, Eq)]
pub struct SessionCredentials {
    pub access_key_id: String,
    pub secret_access_key: String,
    pub session_token: String,
    pub expiration: Option<SystemTime>,
}

impl SessionCredentials {
    /// Time left before the credentials expire (zero once expired), or `None`
    /// when the expiration is unknown.
    pub fn remaining(&self, now: SystemTime) -> Option<Duration> {
        self.expiration
            .map(|expiration| expiration.duration_since(now).unwrap_or(Duration::ZERO))
    }

    /// The environment variables that hand these credentials to AWS tools.
    /// `AWS_CREDENTIAL_EXPIRATION` is read by some SDKs and shell prompts.
    pub fn env_vars(&self) -> Vec<(&'static str, String)> {
        let mut vars = vec![
            ("AWS_ACCESS_KEY_ID", self.access_key_id.clone()),
            ("AWS_SECRET_ACCESS_KEY", self.secret_access_key.clone()),
            ("AWS_SESSION_TOKEN", self.session_token.clone()),
        ];
        if let Some(expiration) = self.expiration {
            vars.push(("AWS_CREDENTIAL_EXPIRATION", format_timestamp(expiration)));
        }
        vars
    }

    /// Human-readable validity for status messages, e.g.
    /// `2026-10-18T15:04:05Z (11h 59m left)`.
    pub fn describe_validity(&self, now: SystemTime) -> String {
        match (self.expiration, self.remaining(now)) {
            (Some(expiration), Some(left)) => {
                format!("{} ({} left)", format_timestamp(expiration), humanize(left))
            }
            _ => "an unknown time".to_owned(),
        }
    }
}

// Secrets are redacted so that credentials can never leak through debug
// output, logs, or bug reports.
impl fmt::Debug for SessionCredentials {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("SessionCredentials")
            .field("access_key_id", &self.access_key_id)
            .field("secret_access_key", &"** redacted **")
            .field("session_token", &"** redacted **")
            .field("expiration", &self.expiration.map(format_timestamp))
            .finish()
    }
}

/// Credentials ready for the outputs, and who they belong to when known.
pub struct Session {
    pub credentials: SessionCredentials,
    pub identity: Option<Identity>,
}

/// The IAM principal the credentials belong to: the user whose long-term
/// credentials request the session, or the role assumed with it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Identity {
    pub account: String,
    pub arn: String,
}

impl Identity {
    /// The identity of `arn`, whose fifth field is the account.
    pub fn from_arn(arn: &str) -> Self {
        Self {
            account: arn.split(':').nth(4).unwrap_or_default().to_owned(),
            arn: arn.to_owned(),
        }
    }

    /// The name for prompts: `alice` for
    /// `arn:aws:iam::123456789012:user/team/alice`, `root` for the root user,
    /// and the role, `Admin`, for
    /// `arn:aws:sts::123456789012:assumed-role/Admin/session-name`.
    pub fn name(&self) -> &str {
        if let Some((_, role)) = self.arn.split_once(":assumed-role/") {
            return role.split('/').next().unwrap_or(role);
        }
        self.arn.rsplit(['/', ':']).next().unwrap_or(&self.arn)
    }

    /// Marker for shell prompts, e.g. `AWS:alice@123456789012`.
    pub fn prompt_label(&self) -> String {
        format!("AWS:{}@{}", self.name(), self.account)
    }
}

/// Format as RFC 3339 in UTC, e.g. `2026-10-18T15:04:05Z` — the format STS,
/// the AWS CLI, and `credential_process` use.
pub fn format_timestamp(time: SystemTime) -> String {
    DateTime::from(time)
        .fmt(DateTimeFormat::DateTime)
        // Only years outside 0001-9999 fail, which no real expiration hits.
        .unwrap_or_else(|_| format!("{time:?}"))
}

/// Parse a timestamp written by [`format_timestamp`].
pub fn parse_timestamp(text: &str) -> Option<SystemTime> {
    let time = DateTime::from_str(text.trim(), DateTimeFormat::DateTime).ok()?;
    SystemTime::try_from(time).ok()
}

/// Format a duration coarsely for status messages, e.g. `11h 59m` or `4m`.
pub fn humanize(duration: Duration) -> String {
    let minutes = duration.as_secs() / 60;
    match (minutes / 60, minutes % 60) {
        (0, minutes) => format!("{minutes}m"),
        (hours, minutes) => format!("{hours}h {minutes:02}m"),
    }
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;

    /// 2027-01-15T08:00:00Z
    pub const EXPIRATION_SECS: u64 = 1_800_000_000;

    pub fn at(secs: u64) -> SystemTime {
        SystemTime::UNIX_EPOCH + Duration::from_secs(secs)
    }

    pub fn sample_credentials() -> SessionCredentials {
        SessionCredentials {
            access_key_id: "ASIATEST".to_owned(),
            secret_access_key: "secret".to_owned(),
            session_token: "token".to_owned(),
            expiration: Some(at(EXPIRATION_SECS)),
        }
    }

    #[test]
    fn test_remaining() {
        let credentials = sample_credentials();
        assert_eq!(
            credentials.remaining(at(EXPIRATION_SECS - 90)),
            Some(Duration::from_secs(90))
        );
        assert_eq!(
            credentials.remaining(at(EXPIRATION_SECS + 90)),
            Some(Duration::ZERO),
            "expired credentials have nothing left, not a negative duration"
        );

        let unknown = SessionCredentials {
            expiration: None,
            ..credentials
        };
        assert_eq!(unknown.remaining(at(0)), None);
    }

    #[test]
    fn test_env_vars() {
        let vars = sample_credentials().env_vars();
        assert_eq!(
            vars,
            [
                ("AWS_ACCESS_KEY_ID", "ASIATEST".to_owned()),
                ("AWS_SECRET_ACCESS_KEY", "secret".to_owned()),
                ("AWS_SESSION_TOKEN", "token".to_owned()),
                (
                    "AWS_CREDENTIAL_EXPIRATION",
                    "2027-01-15T08:00:00Z".to_owned()
                ),
            ]
        );
    }

    #[test]
    fn test_env_vars_without_expiration() {
        let credentials = SessionCredentials {
            expiration: None,
            ..sample_credentials()
        };
        let names: Vec<_> = credentials.env_vars().into_iter().map(|(n, _)| n).collect();
        assert_eq!(
            names,
            [
                "AWS_ACCESS_KEY_ID",
                "AWS_SECRET_ACCESS_KEY",
                "AWS_SESSION_TOKEN"
            ]
        );
    }

    #[test]
    fn test_describe_validity() {
        let credentials = sample_credentials();
        assert_eq!(
            credentials.describe_validity(at(EXPIRATION_SECS - 3 * 3600 - 5 * 60)),
            "2027-01-15T08:00:00Z (3h 05m left)"
        );
        let unknown = SessionCredentials {
            expiration: None,
            ..credentials
        };
        assert_eq!(unknown.describe_validity(at(0)), "an unknown time");
    }

    #[test]
    fn test_debug_redacts_secrets() {
        let debug = format!("{:?}", sample_credentials());
        assert!(debug.contains("ASIATEST"));
        assert!(!debug.contains("secret\""), "got: {debug}");
        assert!(!debug.contains("\"token\""), "got: {debug}");
        assert!(debug.contains("redacted"));
    }

    #[test]
    fn test_identity_name() {
        let name = |arn: &str| Identity::from_arn(arn).name().to_owned();
        assert_eq!(name("arn:aws:iam::123456789012:user/alice"), "alice");
        assert_eq!(name("arn:aws:iam::123456789012:user/team/ops/bob"), "bob");
        assert_eq!(name("arn:aws:iam::123456789012:root"), "root");
        assert_eq!(
            name("arn:aws:sts::222222222222:assumed-role/AdminRole/aws-mfa-session"),
            "AdminRole"
        );
    }

    #[test]
    fn test_identity_from_arn() {
        let identity = Identity::from_arn("arn:aws:sts::222222222222:assumed-role/Admin/s");
        assert_eq!(identity.account, "222222222222");
        assert_eq!(identity.prompt_label(), "AWS:Admin@222222222222");
        assert_eq!(Identity::from_arn("not-an-arn").account, "");
    }

    #[test]
    fn test_timestamp_round_trip() {
        let time = at(EXPIRATION_SECS);
        let text = format_timestamp(time);
        assert_eq!(text, "2027-01-15T08:00:00Z");
        assert_eq!(parse_timestamp(&text), Some(time));
        assert_eq!(parse_timestamp(" 2027-01-15T08:00:00Z \r"), Some(time));
    }

    #[test]
    fn test_parse_timestamp_rejects_garbage() {
        assert_eq!(parse_timestamp(""), None);
        assert_eq!(parse_timestamp("tomorrow"), None);
        assert_eq!(parse_timestamp("2027-01-15 08:00:00"), None);
    }

    #[test]
    fn test_humanize() {
        assert_eq!(humanize(Duration::from_secs(59)), "0m");
        assert_eq!(humanize(Duration::from_secs(4 * 60 + 59)), "4m");
        assert_eq!(humanize(Duration::from_secs(3600)), "1h 00m");
        assert_eq!(humanize(Duration::from_secs(36 * 3600 - 60)), "35h 59m");
    }
}
