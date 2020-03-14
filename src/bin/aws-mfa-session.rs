use mfa_session::{run, Args};
use std::process::exit;
use structopt::StructOpt;

fn main() {
    tokio_compat::run_std(async {
        let args = Args::from_args();
        if let Err(err) = run(args).await {
            eprintln!("{}", err);
            exit(1);
        }
    });
}
