use std::{
    env,
    fs::{self, File},
    io::Write,
    path::{Path, PathBuf},
};

use rand::RngCore;
use zeroize::Zeroize;

use aes_gcm_siv::{
    aead::{Aead, KeyInit},
    Aes256GcmSiv, Nonce as AesNonce,
};

use chacha20poly1305::{XChaCha20Poly1305, XNonce};

use hkdf::Hkdf;
use sha2::{Digest, Sha256};

// File format:
// [magic (5 bytes)] [salt (16 bytes)] [nonce (12 or 24 bytes)] [ciphertext + tag]

const AES_MAGIC: &[u8; 5] = b"RSEA1";
const X_MAGIC: &[u8; 5] = b"RSXC1";

fn main() {
    if let Err(e) = run() {
        println!("{}", e);
        std::process::exit(1);
    } else {
        println!("ok");
    }
}

fn run() -> Result<(), &'static str> {
    let args: Vec<String> = env::args().collect();

    // standalone key generation
    if args.len() == 2 && args[1] == "-dk" {
        return generate_default_keys();
    }

    if args.len() != 3 {
        return Err("invalid argument");
    }

    let file = &args[1];
    let flag = &args[2];

    match flag.as_str() {
        "-a" => process(file, Mode::Aes),
        "-x" => process(file, Mode::XChaCha),
        _ => Err("invalid argument"),
    }
}

#[derive(Copy, Clone)]
enum Mode {
    Aes,
    XChaCha,
}

fn process(path: &str, mode: Mode) -> Result<(), &'static str> {
    let path = Path::new(path);

    let data = fs::read(path).map_err(|_| "io error")?;

    let result = match mode {
        Mode::Aes => handle_aes(&data),
        Mode::XChaCha => handle_x(&data),
    }?;

    atomic_write(path, &result)
}

fn handle_aes(data: &[u8]) -> Result<Vec<u8>, &'static str> {
    if data.starts_with(AES_MAGIC) {
        decrypt_aes(data)
    } else {
        encrypt_aes(data)
    }
}

fn handle_x(data: &[u8]) -> Result<Vec<u8>, &'static str> {
    if data.starts_with(X_MAGIC) {
        decrypt_x(data)
    } else {
        encrypt_x(data)
    }
}

// 🔑 Get directory where the binary lives
fn app_dir() -> Result<PathBuf, &'static str> {
    let exe = env::current_exe().map_err(|_| "io error")?;
    let dir = exe.parent().ok_or("io error")?;
    Ok(dir.to_path_buf())
}

// 🔑 Read key from binary directory
fn read_key(name: &str) -> Result<[u8; 32], &'static str> {
    let dir = app_dir()?;
    let key_path = dir.join(name);

    let mut key = fs::read(key_path).map_err(|_| "missing key file")?;

    if key.len() != 32 {
        return Err("invalid key size");
    }

    let mut out = [0u8; 32];
    out.copy_from_slice(&key);
    key.zeroize();

    Ok(out)
}

// 🔑 Generate default keys next to binary
fn generate_default_keys() -> Result<(), &'static str> {
    let dir = app_dir()?;

    let mut aes_hasher = Sha256::new();
    aes_hasher.update(b"default-aes-key");
    let aes_key = aes_hasher.finalize();

    let mut x_hasher = Sha256::new();
    x_hasher.update(b"default-xchacha-key");
    let x_key = x_hasher.finalize();

    fs::write(dir.join("aes.key"), &aes_key).map_err(|_| "io error")?;
    fs::write(dir.join("x.key"), &x_key).map_err(|_| "io error")?;

    Ok(())
}

fn encrypt_aes(data: &[u8]) -> Result<Vec<u8>, &'static str> {
    let key = read_key("aes.key")?;

    let mut salt = [0u8; 16];
    rand::thread_rng().fill_bytes(&mut salt);

    let hk = Hkdf::<Sha256>::new(Some(&salt), &key);
    let mut derived = [0u8; 32];
    hk.expand(b"aes", &mut derived).map_err(|_| "hkdf error")?;

    let cipher =
        Aes256GcmSiv::new_from_slice(&derived).map_err(|_| "crypto error")?;

    let mut nonce = [0u8; 12];
    rand::thread_rng().fill_bytes(&mut nonce);

    let ciphertext = cipher
        .encrypt(AesNonce::from_slice(&nonce), data)
        .map_err(|_| "crypto error")?;

    let mut out = Vec::new();
    out.extend_from_slice(AES_MAGIC);
    out.extend_from_slice(&salt);
    out.extend_from_slice(&nonce);
    out.extend_from_slice(&ciphertext);

    derived.zeroize();

    Ok(out)
}

fn decrypt_aes(data: &[u8]) -> Result<Vec<u8>, &'static str> {
    if data.len() < 5 + 16 + 12 {
        return Err("invalid format");
    }

    let key = read_key("aes.key")?;

    let salt = &data[5..21];
    let nonce = &data[21..33];
    let ciphertext = &data[33..];

    let hk = Hkdf::<Sha256>::new(Some(salt), &key);
    let mut derived = [0u8; 32];
    hk.expand(b"aes", &mut derived).map_err(|_| "hkdf error")?;

    let cipher =
        Aes256GcmSiv::new_from_slice(&derived).map_err(|_| "crypto error")?;

    let plaintext = cipher
        .decrypt(AesNonce::from_slice(nonce), ciphertext)
        .map_err(|_| "auth failed")?;

    derived.zeroize();

    Ok(plaintext)
}

fn encrypt_x(data: &[u8]) -> Result<Vec<u8>, &'static str> {
    let key = read_key("x.key")?;

    let mut salt = [0u8; 16];
    rand::thread_rng().fill_bytes(&mut salt);

    let hk = Hkdf::<Sha256>::new(Some(&salt), &key);
    let mut derived = [0u8; 32];
    hk.expand(b"xchacha", &mut derived).map_err(|_| "hkdf error")?;

    let cipher =
        XChaCha20Poly1305::new_from_slice(&derived).map_err(|_| "crypto error")?;

    let mut nonce = [0u8; 24];
    rand::thread_rng().fill_bytes(&mut nonce);

    let ciphertext = cipher
        .encrypt(XNonce::from_slice(&nonce), data)
        .map_err(|_| "crypto error")?;

    let mut out = Vec::new();
    out.extend_from_slice(X_MAGIC);
    out.extend_from_slice(&salt);
    out.extend_from_slice(&nonce);
    out.extend_from_slice(&ciphertext);

    derived.zeroize();

    Ok(out)
}

fn decrypt_x(data: &[u8]) -> Result<Vec<u8>, &'static str> {
    if data.len() < 5 + 16 + 24 {
        return Err("invalid format");
    }

    let key = read_key("x.key")?;

    let salt = &data[5..21];
    let nonce = &data[21..45];
    let ciphertext = &data[45..];

    let hk = Hkdf::<Sha256>::new(Some(salt), &key);
    let mut derived = [0u8; 32];
    hk.expand(b"xchacha", &mut derived).map_err(|_| "hkdf error")?;

    let cipher =
        XChaCha20Poly1305::new_from_slice(&derived).map_err(|_| "crypto error")?;

    let plaintext = cipher
        .decrypt(XNonce::from_slice(nonce), ciphertext)
        .map_err(|_| "auth failed")?;

    derived.zeroize();

    Ok(plaintext)
}

fn atomic_write(path: &Path, data: &[u8]) -> Result<(), &'static str> {
    let tmp_path = path.with_extension("tmp");

    {
        let mut f = File::create(&tmp_path).map_err(|_| "io error")?;
        f.write_all(data).map_err(|_| "io error")?;
        f.sync_all().map_err(|_| "io error")?;
    }

    if let Err(_) = fs::rename(&tmp_path, path) {
        let _ = fs::remove_file(&tmp_path);
        return Err("io error");
    }

    Ok(())
}