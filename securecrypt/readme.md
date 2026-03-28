# SecureCrypt

A simple, secure, and flexible file encryption CLI written in Rust.

SecureCrypt is designed for **reliable local encryption** of files before storage or upload (e.g., cloud backups). It focuses on strong cryptography, clean UX, and minimal dependencies.

---

## 🔐 Features

* **Authenticated encryption (AEAD)** using XChaCha20-Poly1305
* **Argon2 key derivation** (resistant to brute-force attacks)
* **Streaming encryption** (handles large files efficiently)
* **Multiple key modes:**

  * Password-based
  * Keyfile-based
  * Built-in default key (`-d`)
* **Tamper detection** (modification breaks decryption)
* **Safe file writes** (no partial output corruption)
* **Minimal, clean CLI UX**

---

## ⚙️ Installation

```bash
git clone <your-repo>
cd securecrypt
cargo build --release
```

Binary will be located at:

```text
target/release/securecrypt
```

---

## 🚀 Usage

### 🔑 Password Mode (default)

Encrypt:

```bash
securecrypt encrypt input.txt output.enc
```

Decrypt:

```bash
securecrypt decrypt output.enc input.txt
```

You will be prompted for a password (with confirmation during encryption).

---

### 📁 Keyfile Mode (`-k`)

Uses a file named `key.key` located in the **same directory as the executable**.

Encrypt:

```bash
securecrypt encrypt input.txt output.enc -k
```

Decrypt:

```bash
securecrypt decrypt output.enc input.txt -k
```

#### Create a secure keyfile:

```bash
head -c 64 /dev/urandom > key.key
chmod 600 key.key
```

---

### ⚡ Default Key Mode (`-d`)

Encrypt:

```bash
securecrypt encrypt input.txt output.enc -d
```

Decrypt:

```bash
securecrypt decrypt output.enc input.txt -d
```

This uses a **hardcoded key embedded in the binary**.

---

## 🔐 Security Model

### Encryption

* Algorithm: **XChaCha20-Poly1305**
* Each file uses:

  * Random salt
  * Random base nonce
  * Per-chunk derived nonce

### Key Derivation

* **Argon2** is used for all modes:

  * Password
  * Keyfile (raw bytes)
  * Default key

### Integrity

* Full-file authentication via AEAD
* Header is included as **AAD (Additional Authenticated Data)**

---

## 📦 File Format

```
[MAGIC][VERSION][SALT][NONCE_BASE][CHUNKS...]
```

Each chunk:

```
[length][ciphertext + auth tag]
```

---

## ⚠️ Security Notes

### Password Mode

* Security depends on password strength
* Protected by Argon2

### Keyfile Mode

* Strongest option
* Use ≥32 random bytes (64 recommended)
* Keep the file safe — loss = data loss

### Default Key Mode (`-d`)

* Uses a built-in static key
* **Not secure against reverse engineering**
* Intended for:

  * Convenience
  * Informal privacy
  * Non-adversarial use

---

## ❗ Important Warnings

* **Losing your password or keyfile = permanent data loss**
* There is **no recovery mechanism**
* Do not mix up modes when decrypting
* Do not edit encrypted files manually

---

## 📊 Performance

* Uses **1 MB chunk size** for efficient disk throughput
* Streaming design avoids loading entire files into memory
* Optimized for reliability over raw speed

---

## 🧼 Reliability Features

* Atomic writes (prevents partial file corruption)
* Cross-filesystem safe temp file handling
* Strict error handling (no silent failures)
* Input validation (prevents malformed file issues)

---

## 🛠 Future Ideas

* Two-factor encryption (password + keyfile)
* Progress indicator
* Configurable chunk size
* Secure file overwrite

---

## 📄 License

MIT License

---

## 💡 Summary

SecureCrypt provides:

* Strong modern cryptography
* Flexible key options
* Reliable file handling
* Clean command-line experience

It is suitable for **personal encryption workflows**, backups, and secure file storage.

---
