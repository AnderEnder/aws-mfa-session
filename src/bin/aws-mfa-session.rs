use aws_mfa_session::{run, Args};
use std::process::exit;
use structopt::StructOpt;

#[tokio::main]
async fn main() {
    let args = Args::from_args();
    if let Err(err) = run(args).await {
        eprintln!("{}", err);
        exit(1);
    }
}
