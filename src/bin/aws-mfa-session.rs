use aws_mfa_session::{Args, run};
use clap::Parser;
use std::process::exit;

#[tokio::main]
async fn main() {
    let opts = Args::parse();

    if let Err(e) = run(opts).await {
        eprintln!("Error: {}", e);
        exit(1);
    }
}
