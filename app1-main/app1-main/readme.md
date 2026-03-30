
# 🔐 app1 — Secure Streaming File Encryption (Rust)

A fast, memory-safe, and cryptographically sound file encryption tool written in Rust.

Designed for securely encrypting files (e.g., for cloud storage) using modern primitives:

* **Argon2id** (password-based key derivation)
* **XChaCha20-Poly1305 (secretstream)** (streaming authenticated encryption)
* **Authenticated metadata (AAD)**

---

# ✨ Features

* 🔐 Strong password-based encryption (Argon2id)
* 📦 Streaming encryption (handles very large files safely)
* 🧠 Constant memory usage (~64 KB chunks)
* 🛡️ Authenticated encryption (AEAD)
* 📛 Original filename preserved and authenticated
* 🔄 Automatic encrypt/decrypt detection
* 💾 Atomic file replacement (crash-safe)
* 🔁 Rollback protection on failure
* 🧾 File permission preservation (Linux)
* 🔍 Tamper detection (fail-fast on corruption)

---

# 🚀 Usage


./app1 <file>


## Examples

### Encrypt a file


./app1 notes.txt


Output:


notes.enc


---

### Decrypt a file


./app1 notes.enc


Output:


notes.txt


---

# 🔑 Password Handling

* Prompts securely (no echo)
* Requires confirmation on encryption
* Uses **Argon2id** with:

  * 64 MB memory
  * 3 iterations
  * 1 thread

---

# 🧠 How It Works

## Encryption Pipeline


Password
   ↓
Argon2id (salted)
   ↓
Derived Key
   ↓
XChaCha20-Poly1305 (secretstream)
   ↓
Encrypted File


---

# 📦 File Format


[MAGIC (5 bytes)]
[SALT (16 bytes)]
[STREAM HEADER (24 bytes)]
[FILENAME LENGTH (2 bytes)]
[FILENAME (variable)]
[CIPHERTEXT STREAM...]


---

# 🛡️ Authenticated Data (AAD)

The following is authenticated (tamper-proof):


MAGIC + SALT + HEADER + FILENAME


If any of these are modified:

* ❌ Decryption fails
* ❌ No partial output is trusted

---

# 🔐 Cryptography Choices

## Argon2id

* Resistant to GPU/ASIC attacks
* Memory-hard (64 MB)
* Industry standard for password hashing

## XChaCha20-Poly1305 (secretstream)

* Modern AEAD construction
* Safe for streaming
* Large nonce space (192-bit)
* Built-in chunk authentication

---

# ⚠️ Security Properties

| Property            | Status          |
| ------------------- | --------------- |
| Confidentiality     | ✅ Strong        |
| Integrity           | ✅ Authenticated |
| Tamper detection    | ✅ Yes           |
| Streaming safety    | ✅ Yes           |
| Key reuse safety    | ✅ Salted        |
| Metadata protection | ✅ AAD           |

---

# ⚠️ Limitations

* ❌ No multi-recipient support
* ❌ No keyfile support (password only)
* ❌ Filename is visible (but authenticated)
* ❌ No compression
* ❌ No secure memory locking

---

# 🧨 Threat Model

This tool protects against:

* Cloud storage compromise
* Unauthorized file access
* File tampering
* Offline brute-force (with strong passwords)

This tool does NOT protect against:

* Weak passwords
* Compromised system at runtime
* Malware/keyloggers

---

# 💾 Atomic File Safety

All operations use:

1. Temporary file (`.tmp`)
2. Backup file (`.bak`)
3. Atomic rename
4. Rollback on failure

This ensures:

* No data loss on crash
* No partial writes
* Safe overwrites

---

# 🐧 Platform Support

* Linux (primary target)
* Uses Unix file semantics
* Preserves file permissions

---

# ⚙️ Build


cargo build --release


Binary:


./target/release/app1


---

# 🧪 Example Workflow


echo "secret" > file.txt

./app1 file.txt
# → file.enc

./app1 file.enc
# → file.txt


---

# 🧠 Design Philosophy

* Minimal surface area
* Correct cryptography over features
* Safe file handling
* No unnecessary abstractions
* Explicit over implicit

---

# 🔮 Future Improvements

* Multi-recipient encryption (like age)
* Keyfile + password hybrid
* Progress bars
* Directory encryption
* Hardware-backed keys (TPM/YubiKey)

---

# 🤖 Reproducible AI Prompt

Use this prompt to regenerate the entire project with a future AI:

---

**PROMPT:**

> Build a production-quality Rust CLI tool for file encryption with the following requirements:
>
> * Use Rust edition 2024
> * Enforce toolchain 1.94.1
> * Use Argon2id for password-based key derivation
>
>   * 64 MB memory
>   * 3 iterations
>   * 1 thread
> * Use XChaCha20-Poly1305 secretstream for encryption
>
>   * Must support streaming large files
>   * Use chunk size ~64 KB
> * Use authenticated encryption (AEAD)
> * Include AAD that covers:
>
>   * magic bytes
>   * salt
>   * stream header
>   * original filename
> * File format must include:
>
>   * magic (5 bytes)
>   * salt (16 bytes)
>   * stream header
>   * filename length (u16)
>   * filename
>   * ciphertext stream
> * Automatically detect encrypt vs decrypt based on magic bytes
> * Prompt user for password securely (no echo)
>
>   * require confirmation on encryption
> * Perform encryption/decryption in streaming mode (constant memory)
> * Preserve original filename in encrypted file and restore on decrypt
> * Output file naming:
>
>   * encrypt: `<name>.enc`
>   * decrypt: restore original filename
> * Implement atomic file replacement:
>
>   * write to temp file
>   * backup original
>   * rename with rollback on failure
> * Preserve file permissions (Linux)
> * fsync file and parent directory for durability
> * Use proper Rust error handling (`Box<dyn Error>`)
> * Zeroize sensitive key material
> * Avoid unsafe code
> * Provide a single-file `main.rs` implementation
>
> The result should be secure, minimal, and correct.

---

# 📜 License

MIT (or your choice)

---

# 🧾 Final Note

This tool prioritizes:

> **Correctness > Convenience**

If used with a strong password, it provides **real-world secure file encryption** suitable for cloud storage.

---

---

