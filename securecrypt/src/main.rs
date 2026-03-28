use std::{
    fs::{File, rename},
    io::{Read, Write},
    path::{Path, PathBuf},
};

use anyhow::{Result, bail};
use clap::{Parser, Subcommand, ArgAction};
use rand::{RngCore, rngs::OsRng};

use chacha20poly1305::{
    aead::{Aead, KeyInit, Payload},
    XChaCha20Poly1305, XNonce,
};

use argon2::Argon2;

use secrecy::{SecretString, ExposeSecret};
use zeroize::Zeroize;

const MAGIC: &[u8; 6] = b"SCRYPT";
const VERSION: u8 = 1;
const CHUNK_SIZE: usize = 1024 * 1024;

// Hardcoded key
const DEFAULT_KEY: &[u8] = &[
    0x93, 0x2a, 0x7f, 0x11, 0x55, 0x88, 0xaa, 0x42,
    0x19, 0xfe, 0x77, 0x03, 0x90, 0x6b, 0xcd, 0x21,
    0x44, 0x21, 0x99, 0x10, 0x88, 0x73, 0x56, 0x61,
    0xde, 0xad, 0xbe, 0xef, 0x01, 0x02, 0x03, 0x04,
];

#[derive(Parser)]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    Encrypt {
        input: PathBuf,
        output: PathBuf,

        #[arg(short = 'k', long = "keyfile", action = ArgAction::SetTrue)]
        keyfile: bool,

        #[arg(short = 'd', long = "default-key", action = ArgAction::SetTrue)]
        default_key: bool,
    },
    Decrypt {
        input: PathBuf,
        output: PathBuf,

        #[arg(short = 'k', long = "keyfile", action = ArgAction::SetTrue)]
        keyfile: bool,

        #[arg(short = 'd', long = "default-key", action = ArgAction::SetTrue)]
        default_key: bool,
    },
}

enum SecretInput {
    Password(SecretString),
    Keyfile(Vec<u8>),
    DefaultKey,
}

fn main() -> Result<()> {
    let cli = Cli::parse();

    match cli.command {
        Commands::Encrypt { input, output, keyfile, default_key } => {
            if keyfile && default_key {
                bail!("Cannot use -k and -d together");
            }

            let secret = if default_key {
                SecretInput::DefaultKey
            } else if keyfile {
                load_keyfile()?
            } else {
                prompt_password(true)?
            };

            encrypt(input, output, secret)?
        }
        Commands::Decrypt { input, output, keyfile, default_key } => {
            if keyfile && default_key {
                bail!("Cannot use -k and -d together");
            }

            let secret = if default_key {
                SecretInput::DefaultKey
            } else if keyfile {
                load_keyfile()?
            } else {
                prompt_password(false)?
            };

            decrypt(input, output, secret)?
        }
    }

    Ok(())
}

fn prompt_password(confirm: bool) -> Result<SecretInput> {
    use rpassword::prompt_password;

    let pass1 = prompt_password("Enter password: ")?;

    if confirm {
        let pass2 = prompt_password("Confirm password: ")?;
        if pass1 != pass2 {
            bail!("Passwords do not match");
        }
    }

    Ok(SecretInput::Password(SecretString::new(pass1)))
}

fn get_keyfile_path() -> Result<PathBuf> {
    let exe = std::env::current_exe()?;
    let dir = exe.parent().ok_or_else(|| anyhow::anyhow!("Cannot get exe dir"))?;
    Ok(dir.join("key.key"))
}

fn load_keyfile() -> Result<SecretInput> {
    let path = get_keyfile_path()?;

    let data = std::fs::read(&path)
        .map_err(|_| anyhow::anyhow!("Failed to read key.key"))?;

    if data.len() < 32 {
        bail!("Keyfile must be at least 32 bytes");
    }

    Ok(SecretInput::Keyfile(data))
}

fn derive_key(secret: &SecretInput, salt: &[u8]) -> Result<[u8; 32]> {
    let mut key = [0u8; 32];
    let argon2 = Argon2::default();

    match secret {
        SecretInput::Password(pw) => {
            argon2.hash_password_into(
                pw.expose_secret().as_bytes(),
                salt,
                &mut key,
            ).map_err(|e| anyhow::anyhow!("argon2 failure: {:?}", e))?;
        }
        SecretInput::Keyfile(bytes) => {
            argon2.hash_password_into(
                bytes,
                salt,
                &mut key,
            ).map_err(|e| anyhow::anyhow!("argon2 failure: {:?}", e))?;
        }
        SecretInput::DefaultKey => {
            argon2.hash_password_into(
                DEFAULT_KEY,
                salt,
                &mut key,
            ).map_err(|e| anyhow::anyhow!("argon2 failure: {:?}", e))?;
        }
    }

    Ok(key)
}

fn encrypt(input: PathBuf, output: PathBuf, secret: SecretInput) -> Result<()> {
    let mut infile = File::open(&input)?;

    let out_dir = output.parent().unwrap_or(Path::new("."));
    let mut tmp = tempfile::Builder::new()
        .prefix(".securecrypt.tmp.")
        .tempfile_in(out_dir)?;

    let mut salt = [0u8; 16];
    OsRng.fill_bytes(&mut salt);

    let mut nonce_base = [0u8; 24];
    OsRng.fill_bytes(&mut nonce_base);

    tmp.write_all(MAGIC)?;
    tmp.write_all(&[VERSION])?;
    tmp.write_all(&salt)?;
    tmp.write_all(&nonce_base)?;

    let mut header = Vec::new();
    header.extend_from_slice(MAGIC);
    header.push(VERSION);
    header.extend_from_slice(&salt);
    header.extend_from_slice(&nonce_base);

    let key = derive_key(&secret, &salt)?;
    let cipher = XChaCha20Poly1305::new((&key).into());

    let mut buffer = vec![0u8; CHUNK_SIZE];
    let mut counter: u64 = 0;

    loop {
        let n = infile.read(&mut buffer)?;
        if n == 0 {
            break;
        }

        let mut nonce = nonce_base;
        nonce[16..24].copy_from_slice(&counter.to_le_bytes());

        let ciphertext = cipher.encrypt(
            XNonce::from_slice(&nonce),
            Payload { msg: &buffer[..n], aad: &header },
        ).map_err(|_| anyhow::anyhow!("encryption failure"))?;

        tmp.write_all(&(ciphertext.len() as u32).to_le_bytes())?;
        tmp.write_all(&ciphertext)?;

        counter += 1;
    }

    tmp.flush()?;
    rename(tmp.path(), output)?;

    let mut key = key;
    key.zeroize();

    Ok(())
}

fn decrypt(input: PathBuf, output: PathBuf, secret: SecretInput) -> Result<()> {
    let mut infile = File::open(&input)?;

    let out_dir = output.parent().unwrap_or(Path::new("."));
    let mut tmp = tempfile::Builder::new()
        .prefix(".securecrypt.tmp.")
        .tempfile_in(out_dir)?;

    let mut magic = [0u8; 6];
    infile.read_exact(&mut magic)?;
    if &magic != MAGIC {
        bail!("Invalid file format");
    }

    let mut version = [0u8; 1];
    infile.read_exact(&mut version)?;
    if version[0] != VERSION {
        bail!("Unsupported file version");
    }

    let mut salt = [0u8; 16];
    infile.read_exact(&mut salt)?;

    let mut nonce_base = [0u8; 24];
    infile.read_exact(&mut nonce_base)?;

    let mut header = Vec::new();
    header.extend_from_slice(&magic);
    header.push(version[0]);
    header.extend_from_slice(&salt);
    header.extend_from_slice(&nonce_base);

    let key = derive_key(&secret, &salt)?;
    let cipher = XChaCha20Poly1305::new((&key).into());

    let mut counter: u64 = 0;

    loop {
        let mut len_buf = [0u8; 4];

        let len = match infile.read_exact(&mut len_buf) {
            Ok(_) => u32::from_le_bytes(len_buf) as usize,
            Err(e) if e.kind() == std::io::ErrorKind::UnexpectedEof => break,
            Err(e) => return Err(e.into()),
        };

        if len > CHUNK_SIZE + 1024 {
            bail!("Invalid chunk size");
        }

        let mut ciphertext = vec![0u8; len];
        infile.read_exact(&mut ciphertext)?;

        let mut nonce = nonce_base;
        nonce[16..24].copy_from_slice(&counter.to_le_bytes());

        let plaintext = cipher.decrypt(
            XNonce::from_slice(&nonce),
            Payload { msg: ciphertext.as_ref(), aad: &header },
        ).map_err(|_| anyhow::anyhow!("decryption failed"))?;

        tmp.write_all(&plaintext)?;
        counter += 1;
    }

    tmp.flush()?;
    rename(tmp.path(), output)?;

    let mut key = key;
    key.zeroize();

    Ok(())
}