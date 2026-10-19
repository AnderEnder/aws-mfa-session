//! The role `--role` assumes: a role ARN, or a profile's role settings.

use crate::error::CliError;

/// The session name when the profile sets no `role_session_name`. CloudTrail
/// shows it as the last part of the assumed-role ARN.
const DEFAULT_SESSION_NAME: &str = "aws-mfa-session";

/// What to ask AssumeRole for.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RoleRequest {
    pub arn: String,
    pub session_name: String,
    /// `external_id`, for roles whose trust policy requires one.
    pub external_id: Option<String>,
    /// `duration_seconds`; AWS defaults to one hour.
    pub duration_secs: Option<i32>,
    /// `role_session_policy_arns`: managed policies that narrow the session.
    pub policy_arns: Vec<String>,
    /// `role_session_policy`: an inline JSON policy that narrows the session.
    pub policy: Option<String>,
}

impl RoleRequest {
    /// The role `--role` names: a role ARN as is, or a profile whose role
    /// settings `setting` looks up by key.
    pub fn resolve(role: &str, setting: impl Fn(&str) -> Option<String>) -> Result<Self, CliError> {
        if role.starts_with("arn:") {
            return Ok(Self::new(role.to_owned()));
        }
        // Empty values count as unset, as they do for the AWS CLI.
        let setting = |key| setting(key).filter(|value| !value.trim().is_empty());
        let arn = setting("role_arn").ok_or_else(|| CliError::NoRoleArn {
            profile: role.to_owned(),
        })?;
        let duration_secs = setting("duration_seconds")
            .map(|value| {
                value.trim().parse().map_err(|_| CliError::InvalidSetting {
                    profile: role.to_owned(),
                    key: "duration_seconds",
                    value,
                })
            })
            .transpose()?;
        let policy_arns = setting("role_session_policy_arns")
            .map(|arns| {
                arns.split(',')
                    .map(str::trim)
                    .filter(|arn| !arn.is_empty())
                    .map(str::to_owned)
                    .collect()
            })
            .unwrap_or_default();
        Ok(Self {
            session_name: setting("role_session_name")
                .unwrap_or_else(|| DEFAULT_SESSION_NAME.to_owned()),
            external_id: setting("external_id"),
            duration_secs,
            policy_arns,
            policy: setting("role_session_policy"),
            ..Self::new(arn)
        })
    }

    fn new(arn: String) -> Self {
        Self {
            arn,
            session_name: DEFAULT_SESSION_NAME.to_owned(),
            external_id: None,
            duration_secs: None,
            policy_arns: Vec::new(),
            policy: None,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const ROLE_ARN: &str = "arn:aws:iam::222222222222:role/AdminRole";

    /// Resolve `role` against a profile with `settings`.
    fn resolve(role: &str, settings: &[(&str, &str)]) -> Result<RoleRequest, CliError> {
        RoleRequest::resolve(role, |key| {
            settings
                .iter()
                .find(|(name, _)| *name == key)
                .map(|(_, value)| (*value).to_owned())
        })
    }

    #[test]
    fn test_arn_is_used_as_is() {
        let request = resolve(ROLE_ARN, &[("role_arn", "ignored")]).unwrap();
        assert_eq!(request, RoleRequest::new(ROLE_ARN.to_owned()));
        assert_eq!(request.session_name, "aws-mfa-session");
    }

    #[test]
    fn test_profile_settings() {
        let request = resolve(
            "dev",
            &[
                ("role_arn", ROLE_ARN),
                ("role_session_name", "alice"),
                ("external_id", "partner-42"),
                ("duration_seconds", "7200"),
                (
                    "role_session_policy_arns",
                    "arn:aws:iam::aws:policy/ReadOnlyAccess, arn:aws:iam::aws:policy/SecurityAudit",
                ),
                ("role_session_policy", r#"{"Version":"2012-10-17"}"#),
            ],
        )
        .unwrap();
        assert_eq!(
            request,
            RoleRequest {
                arn: ROLE_ARN.to_owned(),
                session_name: "alice".to_owned(),
                external_id: Some("partner-42".to_owned()),
                duration_secs: Some(7200),
                policy_arns: vec![
                    "arn:aws:iam::aws:policy/ReadOnlyAccess".to_owned(),
                    "arn:aws:iam::aws:policy/SecurityAudit".to_owned(),
                ],
                policy: Some(r#"{"Version":"2012-10-17"}"#.to_owned()),
            }
        );
    }

    #[test]
    fn test_profile_with_only_role_arn() {
        let request = resolve("dev", &[("role_arn", ROLE_ARN)]).unwrap();
        assert_eq!(request, RoleRequest::new(ROLE_ARN.to_owned()));
    }

    #[test]
    fn test_empty_settings_are_unset() {
        let request = resolve(
            "dev",
            &[
                ("role_arn", ROLE_ARN),
                ("external_id", ""),
                ("role_session_name", " "),
                ("role_session_policy_arns", ""),
            ],
        )
        .unwrap();
        assert_eq!(request, RoleRequest::new(ROLE_ARN.to_owned()));
    }

    #[test]
    fn test_profile_without_role_arn() {
        let error = resolve("dev", &[("region", "eu-west-1"), ("role_arn", "")]).unwrap_err();
        assert!(
            matches!(&error, CliError::NoRoleArn { profile } if profile == "dev"),
            "{error:?}"
        );
    }

    #[test]
    fn test_invalid_duration() {
        let error =
            resolve("dev", &[("role_arn", ROLE_ARN), ("duration_seconds", "1h")]).unwrap_err();
        assert_eq!(
            error.to_string(),
            "profile 'dev' has an invalid duration_seconds: 1h"
        );
    }
}
