//! Generate temporary AWS credentials with a virtual MFA device, and export them
//! to the environment, a new shell, or the shared credentials file.
//!
//! The flow lives in `app`, which depends on AWS and the terminal only through
//! the `AwsApi` and `Terminal` traits; [`run`] plugs in the real implementations.

mod app;
mod args;
mod aws;
mod config;
mod credentials;
mod error;
mod export;
mod mfa;
mod profile;
mod session;
mod shell;
mod terminal;

use std::time::SystemTime;

pub use args::Args;
pub use error::CliError;
pub use export::ExportFormat;
pub use mfa::MfaCode;
pub use shell::Shell;

use aws::SdkAws;
use config::{Config, Env};
use terminal::SystemTerminal;

/// Run with the process environment, AWS, and the user's terminal.
pub async fn run(args: Args) -> Result<(), CliError> {
    let config = Config::new(args, &Env::from_process())?;
    let aws = SdkAws::new(config.sdk.clone());
    app::run(&config, &aws, &mut SystemTerminal, SystemTime::now()).await
}
