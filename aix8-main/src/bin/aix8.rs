use anyhow::Result;
use clap::{Parser, Subcommand};
use std::path::PathBuf;

use aix8_lib::{encrypt, decrypt};

#[derive(Parser)]
#[command(author, version, about)]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    Encrypt {
        input: PathBuf,
        output: Option<PathBuf>,
    },
    Decrypt {
        input: PathBuf,
        output: Option<PathBuf>,
    },
}

fn main() -> Result<()> {
    let cli = Cli::parse();

    match cli.command {
        Commands::Encrypt { input, output } => {

            let output = output.unwrap_or_else(|| {
                let mut p = input.clone();
                p.set_extension("ai");
                p
            });

            let password = rpassword::prompt_password("Password: ")?;

            encrypt(&input, &output, &password)?;

            println!("Encrypted successfully -> {:?}", output);
        }

        Commands::Decrypt { input, output } => {

            let output = output.unwrap_or_else(|| {
                let mut p = input.clone();
                p.set_extension("");
                p
            });

            let password = rpassword::prompt_password("Password: ")?;

            decrypt(&input, &output, &password)?;

            println!("Decrypted successfully -> {:?}", output);
        }
    }

    Ok(())
}