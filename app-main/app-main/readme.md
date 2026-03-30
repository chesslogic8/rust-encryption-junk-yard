yes, i named it "app". ALL the app logic and crypto logic, cli construction, even this readme- ALL OF IT was made in less than 2 minutes by ai. The secret? ALL it took was the right prompt. see /notes for the exact prompt i used !! Ai gets better, and also this app can be improved by ai more. This app, the first one, just shows what ai is capable of in 2 minutes. It shows why learning to code is a waste of time and it shows how powerful ai is when you use it right. 

# 🔐 Simple File Encryption CLI (Rust)

A minimal, production-grade Linux CLI tool for secure file encryption and decryption using modern authenticated encryption algorithms.

This tool is designed to be:

* **Simple**
* **Deterministic**
* **Composable**
* **Secure (when used correctly)**

No unnecessary features. No noisy output. Just reliable encryption.

---

# 📦 Features

## Core Functionality

* Encrypts and decrypts files using:

  * **AES-256-GCM-SIV**
  * **XChaCha20-Poly1305**
* Uses **authenticated encryption (AEAD)**:

  * Ensures both confidentiality and integrity
* Automatically detects whether to:

  * Encrypt → if file is plaintext
  * Decrypt → if file matches the algorithm format

---

## Minimal CLI Design


app <file> -a   # AES mode
app <file> -x   # XChaCha mode


Same command toggles behavior:

* Run once → encrypt
* Run again → decrypt

---

## Output Behavior

The program intentionally avoids all noise:

### Success


ok


### Errors (examples)


invalid argument
missing key file
invalid key size
auth failed
invalid format
io error


No help menus. No usage hints. Fully deterministic output.

---

## Key-Based Encryption (No Passwords)

* AES uses: `aes.key`
* XChaCha uses: `x.key`
* Keys must:

  * Be exactly **32 bytes**
  * Exist in the **same directory as the file**

Example:


example.txt
aes.key
x.key


---

## Deterministic Test Keys

Generate default keys:


./app -dk


Creates:


aes.key
x.key


These keys are:

* Deterministic (same every time)
* Intended **only for testing or informal use**

⚠️ Do NOT use `-dk` keys for real security.

---

# 🔐 Encryption Design

## Algorithms Used

### AES-256-GCM-SIV

* Misuse-resistant AEAD mode
* Safer against nonce reuse than standard GCM

### XChaCha20-Poly1305

* Modern stream cipher AEAD
* Large nonce (24 bytes)
* Excellent for general-purpose use

---

## Key Derivation (HKDF)

Each file uses a **unique derived key**, even if the same key file is reused.

Process:

1. Read key from `aes.key` or `x.key`
2. Generate random 16-byte salt
3. Derive per-file key using HKDF-SHA256

Result:

* Strong key separation between files
* Prevents cross-file attacks

---

## Nonce Handling

Each encryption uses a fresh random nonce:

* AES: 12 bytes
* XChaCha: 24 bytes

Stored in the file header.

Never reused. Never predictable.

---

## File Format

Each algorithm has its own header.

### AES Format


[ "RSEA1" magic ]
[ 16-byte salt ]
[ 12-byte nonce ]
[ ciphertext + auth tag ]


### XChaCha Format


[ "RSXC1" magic ]
[ 16-byte salt ]
[ 24-byte nonce ]
[ ciphertext + auth tag ]


---

## Automatic Detection

The program checks the file header:

* If it matches → decrypt
* Otherwise → encrypt

---

# 🔁 Cascade Encryption (Manual Layering)

This tool does NOT implement built-in cascade.

Instead, it allows **manual composition**:

### Encrypt with both


./app file -a
./app file -x


Result:


XChaCha(AES(plaintext))


### Decrypt


./app file -x
./app file -a


---

## Why this design?

* Simpler implementation
* Avoids complex nested formats
* Fully composable
* Easier to audit and debug

---

# 💾 File Safety (Atomic Writes)

The tool never modifies files in-place.

Instead:

1. Reads original file
2. Writes encrypted/decrypted output to temp file
3. `fsync()` ensures it’s written to disk
4. Atomically replaces original file

Result:

* No corruption on crash
* Always valid file state

---

# ⚠️ Error Handling

## Authentication Failure


auth failed


Occurs when:

* Wrong key is used
* File is corrupted
* Decryption order is wrong (cascade)

---

## Invalid Format


invalid format


Occurs when:

* File is too small
* Header is incomplete or invalid

---

## Missing Key


missing key file


---

# 🧠 Security Model

## What this tool does well

* Uses modern AEAD encryption
* Protects against tampering
* Uses per-file key derivation
* Avoids nonce reuse
* Prevents partial writes

---

## What this tool does NOT do

* No password-based encryption
* No key management
* No secure key storage
* No streaming (loads full file into memory)

---

# ⚠️ Important Limitations

## 1) Key Management is External

You are responsible for:

* Generating secure keys
* Storing them safely
* Backing them up

If you lose the key:
→ Data is permanently unrecoverable

---

## 2) Default Keys Are Not Secure

The `-dk` mode is:

* Deterministic
* Predictable

Use only for:

* Testing
* Temporary usage

---

## 3) Memory Usage

* Entire file is loaded into memory
* Large files may cause issues

---

# 🔄 Algorithm Flexibility

This tool is designed around **AEAD encryption**.

## Safe to swap algorithms (if needed):

* AES-GCM
* XChaCha20-Poly1305
* ChaCha20-Poly1305
* AES-GCM-SIV

## NOT recommended:

* Raw block ciphers (e.g. Serpent, AES-CBC)

Why?

* They lack built-in authentication
* Require manual MAC handling
* Easy to misuse

---

## Rule

> Only use **authenticated encryption (AEAD)** algorithms

---

# 🧪 Example Usage


echo "hello world" > example.txt

./app -dk

./app example.txt -a
cat example.txt   # unreadable

./app example.txt -a
cat example.txt   # "hello world"


---

# 🏗 Project Structure


Cargo.toml
rust-toolchain.toml
src/main.rs


* `Cargo.toml` → dependencies and Rust version
* `rust-toolchain.toml` → exact compiler version
* `main.rs` → full application logic

---

# 🎯 Design Philosophy

This tool is intentionally:

* **Minimal**
* **Predictable**
* **Explicit**
* **Compositional**

No hidden behavior. No magic.

---

# 🚀 Summary

This application provides:

* Strong, modern encryption
* Simple CLI usage
* Deterministic behavior
* Safe file handling
* Manual composability

It is small, focused, and reliable — designed to do one thing well.

---

If you extend it later, keep the same philosophy:

> Simplicity + correctness > feature complexity

---

/notes has the exact prompt i used to make this app !! 

* Ai made this app (and the readme)
* To do the same level of app from zero, it would take any human about 4 years.
* The human brain is not as capable as ai is. Accept the truth and let it empower you. 
