use anyhow::{anyhow, Result};
use std::fs;
use std::path::Path;

use argon2::Argon2;

use sodiumoxide::crypto::aead::xchacha20poly1305_ietf as aead;
use sodiumoxide::randombytes::randombytes;

const SALT_LEN: usize = 16;
const KEY_LEN: usize = aead::KEYBYTES;
const NONCE_LEN: usize = aead::NONCEBYTES;

pub fn encrypt_bytes(data: &[u8], password: &str) -> Result<Vec<u8>> {
    sodiumoxide::init().map_err(|_| anyhow!("failed to init sodium"))?;

    let salt = randombytes(SALT_LEN);

    let mut key = [0u8; KEY_LEN];

    Argon2::default()
        .hash_password_into(password.as_bytes(), &salt, &mut key)
        .map_err(|_| anyhow!("argon2 key derivation failed"))?;

    let nonce = aead::gen_nonce();

    let ciphertext =
        aead::seal(data, None, &nonce, &aead::Key::from_slice(&key).unwrap());

    let mut out = Vec::new();

    out.extend_from_slice(b"AIX1"); // file magic
    out.extend_from_slice(&salt);
    out.extend_from_slice(&nonce.0);
    out.extend_from_slice(&ciphertext);

    Ok(out)
}

pub fn decrypt_bytes(data: &[u8], password: &str) -> Result<Vec<u8>> {
    sodiumoxide::init().map_err(|_| anyhow!("failed to init sodium"))?;

    if data.len() < 4 + SALT_LEN + NONCE_LEN {
        return Err(anyhow!("file too small"));
    }

    if &data[0..4] != b"AIX1" {
        return Err(anyhow!("invalid header"));
    }

    let salt = &data[4..20];

    let nonce = aead::Nonce::from_slice(&data[20..44])
        .ok_or_else(|| anyhow!("invalid nonce"))?;

    let ciphertext = &data[44..];

    let mut key = [0u8; KEY_LEN];

    Argon2::default()
        .hash_password_into(password.as_bytes(), salt, &mut key)
        .map_err(|_| anyhow!("argon2 key derivation failed"))?;

    let plaintext = aead::open(
        ciphertext,
        None,
        &nonce,
        &aead::Key::from_slice(&key).unwrap(),
    )
    .map_err(|_| anyhow!("authentication failed"))?;

    Ok(plaintext)
}

pub fn encrypt(input: &Path, output: &Path, password: &str) -> Result<()> {
    let data = fs::read(input)?;

    let encrypted = encrypt_bytes(&data, password)?;

    fs::write(output, encrypted)?;

    Ok(())
}

pub fn decrypt(input: &Path, output: &Path, password: &str) -> Result<()> {
    let data = fs::read(input)?;

    let decrypted = decrypt_bytes(&data, password)?;

    fs::write(output, decrypted)?;

    Ok(())
}