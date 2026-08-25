#![forbid(unsafe_code)]

use std::process::ExitCode;

fn main() -> ExitCode {
    let args: Vec<String> = std::env::args().skip(1).collect();
    match scicapsule::run(&args) {
        Ok(output) => {
            print!("{output}");
            ExitCode::SUCCESS
        }
        Err(error) => {
            eprintln!("error: {error}");
            if error.is_usage() {
                eprintln!("run `scicapsule --help` for usage");
                ExitCode::from(2)
            } else {
                ExitCode::FAILURE
            }
        }
    }
}
