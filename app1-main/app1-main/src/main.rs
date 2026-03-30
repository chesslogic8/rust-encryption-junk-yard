use std::{
    env,
    error::Error,
    fs::{File, rename, remove_file, metadata, set_permissions},
    io::{Read, Write},
    path::Path,
};

use rand::RngCore;
use zeroize::Zeroize;

use argon2::{Argon2, Params, Algorithm, Version};
use sodiumoxide::crypto::secretstream::xchacha20poly1305 as stream;
use rpassword::read_password;

const MAGIC: &[u8; 5] = b"RSV1\0";
const SALT_LEN: usize = 16;
const CHUNK: usize = 64 * 1024;

fn main() {
    sodiumoxide::init().unwrap();

    if let Err(e) = run() {
        eprintln!("error: {}", e);
        std::process::exit(1);
    }
}

fn run() -> Result<(), Box<dyn Error>> {
    let args: Vec<String> = env::args().collect();

    if args.len() != 2 {
        return Err("usage: app1 <file>".into());
    }

    let path = &args[1];

    let mut f = File::open(path)?;
    let mut magic = [0u8; 5];

    let is_encrypted = match f.read_exact(&mut magic) {
        Ok(_) => &magic == MAGIC,
        Err(_) => false,
    };

    if is_encrypted {
        decrypt(path)
    } else {
        encrypt(path)
    }
}

fn argon2() -> Argon2<'static> {
    Argon2::new(
        Algorithm::Argon2id,
        Version::V0x13,
        Params::new(64 * 1024, 3, 1, None).unwrap(),
    )
}

fn derive_key(password: &str, salt: &[u8]) -> Result<stream::Key, Box<dyn Error>> {
    let mut key = [0u8; stream::KEYBYTES];

    argon2()
        .hash_password_into(password.as_bytes(), salt, &mut key)
        .map_err(|_| "argon2 error")?;

    let k = stream::Key::from_slice(&key).ok_or("key error")?;
    key.zeroize();

    Ok(k)
}

fn prompt_password(confirm: bool) -> Result<String, Box<dyn Error>> {
    print!("password: ");
    std::io::stdout().flush()?;
    let p1 = read_password()?;

    if confirm {
        print!("confirm password: ");
        std::io::stdout().flush()?;
        let p2 = read_password()?;

        if p1 != p2 {
            return Err("passwords do not match".into());
        }
    }

    Ok(p1)
}

// 🔥 always .enc
fn enc_name(path: &str) -> String {
    let p = Path::new(path);
    let stem = p.file_stem().unwrap().to_string_lossy();
    format!("{}.enc", stem)
}

// 🔥 atomic swap
fn safe_replace(original: &str, tmp: &str, final_path: &str) -> Result<(), Box<dyn Error>> {
    let backup = format!("{}.bak", original);

    if Path::new(original).exists() {
        rename(original, &backup)?;
    }

    if let Err(e) = rename(tmp, final_path) {
        if Path::new(&backup).exists() {
            let _ = rename(&backup, original);
        }
        return Err(e.into());
    }

    if Path::new(&backup).exists() {
        remove_file(&backup)?;
    }

    Ok(())
}

fn preserve_permissions(src: &str, dst: &str) -> Result<(), Box<dyn Error>> {
    let meta = metadata(src)?;
    set_permissions(dst, meta.permissions())?;
    Ok(())
}

fn encrypt(path: &str) -> Result<(), Box<dyn Error>> {
    let password = prompt_password(true)?;

    let mut input = File::open(path)?;

    let final_path = enc_name(path);
    let tmp_path = format!("{}.tmp", final_path);
    let mut output = File::create(&tmp_path)?;

    let filename = Path::new(path)
        .file_name()
        .unwrap()
        .to_string_lossy()
        .into_owned();

    let mut salt = [0u8; SALT_LEN];
    rand::thread_rng().fill_bytes(&mut salt);

    let key = derive_key(&password, &salt)?;

    let (mut push, header) =
        stream::Stream::init_push(&key).map_err(|_| "crypto error")?;

    // write header
    output.write_all(MAGIC)?;
    output.write_all(&salt)?;
    output.write_all(&header.0)?;

    let name_bytes = filename.as_bytes();
    let name_len = name_bytes.len() as u16;
    output.write_all(&name_len.to_le_bytes())?;
    output.write_all(name_bytes)?;

    // AAD includes filename
    let mut aad = Vec::new();
    aad.extend_from_slice(MAGIC);
    aad.extend_from_slice(&salt);
    aad.extend_from_slice(&header.0);
    aad.extend_from_slice(&name_len.to_le_bytes());
    aad.extend_from_slice(name_bytes);

    let mut buffer = [0u8; CHUNK];

    loop {
        let n = input.read(&mut buffer)?;
        if n == 0 { break; }

        let tag = if n < CHUNK {
            stream::Tag::Final
        } else {
            stream::Tag::Message
        };

        let ciphertext = push
            .push(&buffer[..n], Some(&aad), tag)
            .map_err(|_| "crypto error")?;

        output.write_all(&ciphertext)?;

        if tag == stream::Tag::Final { break; }
    }

    output.sync_all()?;

    preserve_permissions(path, &tmp_path)?;
    safe_replace(path, &tmp_path, &final_path)?;

    Ok(())
}

fn decrypt(path: &str) -> Result<(), Box<dyn Error>> {
    let password = prompt_password(false)?;

    let mut input = File::open(path)?;

    let mut magic = [0u8; 5];
    input.read_exact(&mut magic)?;
    if &magic != MAGIC {
        return Err("invalid file".into());
    }

    let mut salt = [0u8; SALT_LEN];
    input.read_exact(&mut salt)?;

    let mut header_bytes = [0u8; stream::HEADERBYTES];
    input.read_exact(&mut header_bytes)?;

    let mut name_len_bytes = [0u8; 2];
    input.read_exact(&mut name_len_bytes)?;
    let name_len = u16::from_le_bytes(name_len_bytes) as usize;

    let mut name_buf = vec![0u8; name_len];
    input.read_exact(&mut name_buf)?;
    let filename = String::from_utf8(name_buf)?;

    let tmp_path = format!("{}.tmp", filename);
    let mut output = File::create(&tmp_path)?;

    let header = stream::Header::from_slice(&header_bytes)
        .ok_or("header error")?;

    let key = derive_key(&password, &salt)?;

    let mut pull = stream::Stream::init_pull(&header, &key)
        .map_err(|_| "crypto error")?;

    let mut aad = Vec::new();
    aad.extend_from_slice(MAGIC);
    aad.extend_from_slice(&salt);
    aad.extend_from_slice(&header_bytes);
    aad.extend_from_slice(&name_len_bytes);
    aad.extend_from_slice(filename.as_bytes());

    let mut buffer = vec![0u8; CHUNK + stream::ABYTES];

    loop {
        let n = input.read(&mut buffer)?;
        if n == 0 { break; }

        let (plaintext, tag) = pull
            .pull(&buffer[..n], Some(&aad))
            .map_err(|_| "auth failed")?;

        output.write_all(&plaintext)?;

        if tag == stream::Tag::Final { break; }
    }

    output.sync_all()?;

    preserve_permissions(path, &tmp_path)?;
    safe_replace(path, &tmp_path, &filename)?;

    Ok(())
}