use aws_mfa_session::{Args, run};
use clap::Parser;
use tracing_subscriber::EnvFilter;

#[tokio::main]
async fn main() -> miette::Result<()> {
    // Diagnostics are off unless requested with RUST_LOG, and go to stderr so
    // they never mix with the credentials printed by --export.
    let filter = EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("off"));
    tracing_subscriber::fmt()
        .with_env_filter(filter)
        .with_writer(std::io::stderr)
        .init();

    run(Args::parse()).await?;
    Ok(())
}
