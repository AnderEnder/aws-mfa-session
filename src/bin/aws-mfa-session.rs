use aws_mfa_session::{Args, run};
use clap::Parser;
use std::process::exit;
use tracing_subscriber::{EnvFilter, fmt};

#[tokio::main]
async fn main() {
    let mut opts = Args::parse();

    // Configure tracing
    let level = "off";
    let filter = EnvFilter::try_new(level).unwrap_or_else(|_| EnvFilter::new("info"));
    fmt().with_env_filter(filter).init();

    if let Err(e) = opts.get_code() {
        eprintln!("Error: {e}");
        tracing::error!(?e, "application error");
        // Print a fancy error report using miette
        eprintln!("{}", miette::Report::new(e));
        exit(1);
    }

    if let Err(e) = run(opts).await {
        eprintln!("Error: {e}");
        exit(1);
    }
}
