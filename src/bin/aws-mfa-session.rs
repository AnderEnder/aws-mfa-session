use mfa_session::{run, Args};
use std::process::exit;
use structopt::StructOpt;
fn main() {
    let args = Args::from_args();
    if let Err(err) = run(args) {
        eprintln!("{}", err);
        exit(1);
    }
}
