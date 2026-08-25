#![forbid(unsafe_code)]

use std::process::ExitCode;

fn main() -> ExitCode {
    let args: Vec<String> = std::env::args().skip(1).collect();
    match args.as_slice() {
        [] => {
            print!("{}", scicapsule::help_text());
            ExitCode::SUCCESS
        }
        [argument] if argument == "-h" || argument == "--help" => {
            print!("{}", scicapsule::help_text());
            ExitCode::SUCCESS
        }
        [argument] if argument == "-V" || argument == "--version" => {
            println!("scicapsule {}", scicapsule::version());
            ExitCode::SUCCESS
        }
        [argument, ..] => {
            eprintln!("unknown argument: {argument}");
            eprintln!("run `scicapsule --help` for usage");
            ExitCode::from(2)
        }
    }
}
