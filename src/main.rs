#![forbid(unsafe_code)]

use std::process::ExitCode;

fn main() -> ExitCode {
    let mut args = std::env::args().skip(1);
    match (args.next().as_deref(), args.next()) {
        (None, None) | (Some("-h" | "--help"), None) => {
            print!("{}", scicapsule::help_text());
            ExitCode::SUCCESS
        }
        (Some("-V" | "--version"), None) => {
            println!("scicapsule {}", scicapsule::version());
            ExitCode::SUCCESS
        }
        (Some(argument), _) => {
            eprintln!("unknown argument: {argument}");
            eprintln!("run `scicapsule --help` for usage");
            ExitCode::from(2)
        }
    }
}
