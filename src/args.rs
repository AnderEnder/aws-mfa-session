use crate::error::CliError;
use aws_config::Region;
use clap::Parser;

const AWS_DEFAULT_REGION: &str = "AWS_DEFAULT_REGION";

pub fn region(s: &str) -> Result<Region, CliError> {
    Ok(Region::new(s.to_owned()))
}

pub fn default_region() -> Region {
    match std::env::var(AWS_DEFAULT_REGION) {
        Ok(s) => region(&s).expect("Failed to parse default region"),
        _ => Region::new("us-east-1"),
    }
}

fn parse_code(s: &str) -> Result<String, CliError> {
    if s.chars().all(char::is_numeric) && s.len() == 6 {
        Ok(s.to_string())
    } else {
        Err(CliError::ValidationError(
            "MFA code must be exactly 6 digits".to_string(),
        ))
    }
}

#[derive(Parser, Debug, Clone)]
#[command(
    name = "aws-mfa-session",
    about = "AWS MFA session manager",
    long_about = None,
)]
pub struct Args {
    /// AWS credential profile to use. AWS_PROFILE is used by default
    #[arg(long = "profile", short = 'p')]
    pub profile: Option<String>,
    /// AWS credentials file location to use. AWS_SHARED_CREDENTIALS_FILE is used if not defined
    #[arg(long = "credentials-file", short = 'f')]
    pub file: Option<String>,
    /// AWS region. AWS_REGION is used if not defined
    #[arg(long = "region", short = 'r', value_parser = region, default_value_t = default_region())]
    pub region: Region,
    /// MFA code from MFA resource
    #[arg(long = "code", short = 'c', value_parser = parse_code)]
    pub code: String,
    /// MFA device ARN from user profile. It could be detected automatically
    #[arg(long = "arn", short = 'a')]
    pub arn: Option<String>,
    /// Session duration in seconds (900-129600)
    #[arg(long = "duration", short = 'd', default_value_t = 3600, value_parser = clap::value_parser!(i32).range(900..129600))]
    pub duration: i32,
    /// Run shell with AWS credentials as environment variables
    #[arg(short = 's')]
    pub shell: bool,
    /// Print(export) AWS credentials as environment variables
    #[arg(short = 'e')]
    pub export: bool,
    /// Update AWS credential profile with temporary session credentials
    #[arg(long = "update-profile", short = 'u')]
    pub session_profile: Option<String>,
}
