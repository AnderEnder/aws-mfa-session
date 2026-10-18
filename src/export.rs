//! Printing session credentials for `--export`.

use std::fmt::Write;

use crate::session::{Identity, SessionCredentials, format_timestamp};
use crate::shell::Shell;

/// How `--export` prints the credentials.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ExportFormat {
    /// Commands that set environment variables in the given shell.
    Shell(Shell),
    /// The JSON document the AWS CLI and SDKs expect from a `credential_process`.
    Json,
}

impl ExportFormat {
    /// Render the credentials. Shell formats also change the prompt to show
    /// `identity`, when it is known.
    pub fn render(self, credentials: &SessionCredentials, identity: Option<&Identity>) -> String {
        match self {
            ExportFormat::Shell(shell) => {
                let label = identity.map(Identity::prompt_label);
                shell.export_script(&credentials.env_vars(), label.as_deref())
            }
            ExportFormat::Json => credential_process_json(credentials),
        }
    }

    /// Whether [`render`](Self::render) shows the identity in a prompt.
    pub fn shows_prompt(self) -> bool {
        matches!(self, ExportFormat::Shell(_))
    }
}

/// See <https://docs.aws.amazon.com/cli/latest/userguide/cli-configure-sourcing-external.html>.
fn credential_process_json(credentials: &SessionCredentials) -> String {
    let mut fields = vec![
        ("Version", "1".to_owned()),
        ("AccessKeyId", json_string(&credentials.access_key_id)),
        (
            "SecretAccessKey",
            json_string(&credentials.secret_access_key),
        ),
        ("SessionToken", json_string(&credentials.session_token)),
    ];
    if let Some(expiration) = credentials.expiration {
        fields.push(("Expiration", json_string(&format_timestamp(expiration))));
    }
    let body: Vec<String> = fields
        .iter()
        .map(|(key, value)| format!("  \"{key}\": {value}"))
        .collect();
    format!("{{\n{}\n}}\n", body.join(",\n"))
}

fn json_string(value: &str) -> String {
    let mut out = String::with_capacity(value.len() + 2);
    out.push('"');
    for c in value.chars() {
        match c {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            c if c < '\u{20}' => {
                let _ = write!(out, "\\u{:04x}", u32::from(c));
            }
            c => out.push(c),
        }
    }
    out.push('"');
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::session::tests::sample_credentials;

    fn identity() -> Identity {
        Identity {
            account: "123456789012".to_owned(),
            arn: "arn:aws:iam::123456789012:user/alice".to_owned(),
        }
    }

    #[test]
    fn test_json_matches_credential_process_schema() {
        let json = ExportFormat::Json.render(&sample_credentials(), Some(&identity()));
        assert_eq!(
            json,
            r#"{
  "Version": 1,
  "AccessKeyId": "ASIATEST",
  "SecretAccessKey": "secret",
  "SessionToken": "token",
  "Expiration": "2027-01-15T08:00:00Z"
}
"#
        );
    }

    #[test]
    fn test_json_omits_unknown_expiration() {
        let credentials = SessionCredentials {
            expiration: None,
            ..sample_credentials()
        };
        let json = ExportFormat::Json.render(&credentials, None);
        assert!(!json.contains("Expiration"));
        assert!(json.contains("\"SessionToken\": \"token\"\n}"));
    }

    #[test]
    fn test_json_string_escaping() {
        assert_eq!(json_string("plain"), r#""plain""#);
        assert_eq!(json_string(r#"a"b\c"#), r#""a\"b\\c""#);
        assert_eq!(json_string("tab\tnl\n"), r#""tab\u0009nl\u000a""#);
        assert_eq!(json_string("ünïcode/+="), "\"ünïcode/+=\"");
    }

    #[test]
    fn test_shell_render_includes_expiration_and_prompt() {
        let script =
            ExportFormat::Shell(Shell::Bash).render(&sample_credentials(), Some(&identity()));
        assert!(script.contains("export AWS_SESSION_TOKEN='token'\n"));
        assert!(script.contains("export AWS_CREDENTIAL_EXPIRATION='2027-01-15T08:00:00Z'\n"));
        assert!(script.ends_with("export PS1='AWS:alice@123456789012 \\$ '\n"));
    }

    #[test]
    fn test_shell_render_without_identity_skips_prompt() {
        let script = ExportFormat::Shell(Shell::Bash).render(&sample_credentials(), None);
        assert!(!script.contains("PS1"));
    }

    #[test]
    fn test_shows_prompt() {
        assert!(ExportFormat::Shell(Shell::Fish).shows_prompt());
        assert!(!ExportFormat::Json.shows_prompt());
    }
}
