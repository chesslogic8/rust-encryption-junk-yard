use aix8_lib::{decrypt, encrypt};
use rand::{Rng, RngCore};
use std::fs;
use std::io::Write;
use std::thread;
use std::time::Instant;
use tempdir::TempDir;

const PASSWORD: &str = "correct horse battery staple";

#[test]
fn roundtrip_empty_file() {
    let dir = TempDir::new("aix8").unwrap();

    let input = dir.path().join("empty");
    let enc = dir.path().join("empty.aix8");
    let out = dir.path().join("out");

    fs::write(&input, b"").unwrap();

    encrypt(&input, &enc, PASSWORD).unwrap();
    decrypt(&enc, &out, PASSWORD).unwrap();

    assert_eq!(fs::read(&out).unwrap(), b"");
}

#[test]
fn roundtrip_small_file() {
    let dir = TempDir::new("aix8").unwrap();

    let input = dir.path().join("small");
    let enc = dir.path().join("small.aix8");
    let out = dir.path().join("out");

    fs::write(&input, b"hello secure world").unwrap();

    encrypt(&input, &enc, PASSWORD).unwrap();
    decrypt(&enc, &out, PASSWORD).unwrap();

    assert_eq!(fs::read(&out).unwrap(), b"hello secure world");
}

#[test]
fn roundtrip_random_data() {
    let dir = TempDir::new("aix8").unwrap();
    let mut rng = rand::thread_rng();

    for _ in 0..100 {
        let size = rng.gen_range(0..1_000_000);

        let mut data = vec![0u8; size];
        rng.fill_bytes(&mut data);

        let input = dir.path().join("rand");
        let enc = dir.path().join("rand.aix8");
        let out = dir.path().join("out");

        fs::write(&input, &data).unwrap();

        encrypt(&input, &enc, PASSWORD).unwrap();
        decrypt(&enc, &out, PASSWORD).unwrap();

        assert_eq!(fs::read(&out).unwrap(), data);
    }
}

#[test]
fn wrong_password_fails() {
    let dir = TempDir::new("aix8").unwrap();

    let input = dir.path().join("data");
    let enc = dir.path().join("data.aix8");
    let out = dir.path().join("out");

    fs::write(&input, b"secret data").unwrap();

    encrypt(&input, &enc, PASSWORD).unwrap();

    assert!(decrypt(&enc, &out, "bad password").is_err());
}

#[test]
fn corruption_detection() {
    let dir = TempDir::new("aix8").unwrap();

    let input = dir.path().join("data");
    let enc = dir.path().join("data.aix8");
    let out = dir.path().join("out");

    fs::write(&input, b"important").unwrap();

    encrypt(&input, &enc, PASSWORD).unwrap();

    let mut bytes = fs::read(&enc).unwrap();

    let mid = bytes.len() / 2;
    bytes[mid] ^= 0xFF;

    fs::write(&enc, bytes).unwrap();

    assert!(decrypt(&enc, &out, PASSWORD).is_err());
}

#[test]
fn truncated_ciphertext_fails() {
    let dir = TempDir::new("aix8").unwrap();

    let input = dir.path().join("data");
    let enc = dir.path().join("data.aix8");
    let out = dir.path().join("out");

    fs::write(&input, b"truncate test").unwrap();

    encrypt(&input, &enc, PASSWORD).unwrap();

    let mut bytes = fs::read(&enc).unwrap();
    bytes.truncate(bytes.len() / 2);

    fs::write(&enc, bytes).unwrap();

    assert!(decrypt(&enc, &out, PASSWORD).is_err());
}

#[test]
fn header_corruption_fails() {
    let dir = TempDir::new("aix8").unwrap();

    let input = dir.path().join("data");
    let enc = dir.path().join("data.aix8");
    let out = dir.path().join("out");

    fs::write(&input, b"header tamper").unwrap();

    encrypt(&input, &enc, PASSWORD).unwrap();

    let mut bytes = fs::read(&enc).unwrap();
    bytes[0] ^= 0xAA;

    fs::write(&enc, bytes).unwrap();

    assert!(decrypt(&enc, &out, PASSWORD).is_err());
}

#[test]
fn repeated_encryption_uniqueness() {
    let dir = TempDir::new("aix8").unwrap();

    let input = dir.path().join("data");
    fs::write(&input, b"same plaintext").unwrap();

    let mut ciphertexts = Vec::new();

    for i in 0..10 {
        let enc = dir.path().join(format!("out{i}.aix8"));

        encrypt(&input, &enc, PASSWORD).unwrap();
        ciphertexts.push(fs::read(enc).unwrap());
    }

    for i in 0..ciphertexts.len() {
        for j in i + 1..ciphertexts.len() {
            assert_ne!(ciphertexts[i], ciphertexts[j]);
        }
    }
}

#[test]
fn parallel_encryption_stress() {
    let mut handles = Vec::new();

    for _ in 0..8 {
        handles.push(thread::spawn(|| {
            let dir = TempDir::new("aix8").unwrap();
            let mut rng = rand::thread_rng();

            for _ in 0..60 {
                let size = rng.gen_range(0..1_000_000);

                let mut data = vec![0u8; size];
                rng.fill_bytes(&mut data);

                let input = dir.path().join("data");
                let enc = dir.path().join("data.aix8");
                let out = dir.path().join("out");

                fs::write(&input, &data).unwrap();

                encrypt(&input, &enc, PASSWORD).unwrap();
                decrypt(&enc, &out, PASSWORD).unwrap();

                assert_eq!(fs::read(&out).unwrap(), data);
            }
        }));
    }

    for h in handles {
        h.join().unwrap();
    }
}

#[test]
fn timing_consistency_check() {
    let dir = TempDir::new("aix8").unwrap();

    let input = dir.path().join("data");
    let enc = dir.path().join("data.aix8");
    let out = dir.path().join("out");

    fs::write(&input, b"timing test").unwrap();

    encrypt(&input, &enc, PASSWORD).unwrap();

    let start_ok = Instant::now();
    let _ = decrypt(&enc, &out, PASSWORD);
    let ok_time = start_ok.elapsed();

    let start_bad = Instant::now();
    let _ = decrypt(&enc, &out, "wrong password");
    let bad_time = start_bad.elapsed();

    let diff = ok_time.abs_diff(bad_time);

    assert!(diff.as_millis() < 50);
}

#[test]
fn mutation_attack_test() {
    let dir = TempDir::new("aix8").unwrap();

    let mut data = vec![0u8; 1024 * 1024];
    rand::thread_rng().fill_bytes(&mut data);

    let input = dir.path().join("data");
    let enc = dir.path().join("data.aix8");
    let out = dir.path().join("out");

    fs::write(&input, &data).unwrap();
    encrypt(&input, &enc, PASSWORD).unwrap();

    let original = fs::read(&enc).unwrap();

    for _ in 0..300 {
        let mut mutated = original.clone();

        let pos = rand::thread_rng().gen_range(0..mutated.len());
        mutated[pos] ^= 0xFF;

        let test = dir.path().join("mut.aix8");
        fs::write(&test, mutated).unwrap();

        assert!(decrypt(&test, &out, PASSWORD).is_err());
    }
}

#[test]
#[ignore]
fn massive_10gb_streaming_torture_test() {
    let dir = TempDir::new("aix8_big").unwrap();

    let input = dir.path().join("huge.bin");
    let enc = dir.path().join("huge.aix8");
    let out = dir.path().join("huge_out.bin");

    let size = 10 * 1024 * 1024 * 1024usize;

    let mut rng = rand::thread_rng();
    let mut file = fs::File::create(&input).unwrap();

    let mut remaining = size;
    let mut buffer = [0u8; 8192];

    while remaining > 0 {
        let chunk = remaining.min(buffer.len());
        rng.fill_bytes(&mut buffer[..chunk]);
        file.write_all(&buffer[..chunk]).unwrap();
        remaining -= chunk;
    }

    encrypt(&input, &enc, PASSWORD).unwrap();
    decrypt(&enc, &out, PASSWORD).unwrap();

    let original = fs::read(&input).unwrap();
    let decrypted = fs::read(&out).unwrap();

    assert_eq!(original, decrypted);
}