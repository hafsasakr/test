# Viva Guide – Data Integrity Verification System Using SHA-256

Read this with the source open next to it. Goal: you can explain *every line* in your own words.

---

## 1. The big idea in 30 seconds

> "My program computes a SHA-256 fingerprint of a message and stores it as a trusted reference. Later it computes the fingerprint of the message again. If the two fingerprints are identical, no modification was detected. If they differ, the message changed. SHA-256 does not *stop* changes; it helps *detect* them, and only if the reference hash is trustworthy."

---

## 2. Purpose of every file

| File | Purpose |
|---|---|
| `src/main.cpp` | Talks to the user: menu, reading input, printing results. Contains no cryptography. |
| `src/integrity.h` | The "contract": declares the functions `main.cpp` may call. |
| `src/integrity.cpp` | Does the real work: asks OpenSSL for SHA-256, turns bytes into hex, compares hashes. |
| `tests/test_plan.md` | List of tests with inputs, expected results, and blank columns for your real results. |
| `docs/report.md` | Draft of the written report. |
| `README.md` | How to install, build, run, plus references and limitations. |
| `.gitignore` | Stops `.exe`/`.o` files from being committed. |

Why split into `.h` and `.cpp`? The header says *what* exists; the `.cpp` says *how*. `main.cpp` includes the header (`#include "integrity.h"`) and the linker joins the compiled pieces.

---

## 3. How data moves through the program

```
user types text ──► main.cpp (getline) ──► std::string message
        │
        ▼
integrity::computeSha256Hex(message, hash, error)
        │   (integrity.cpp → OpenSSL EVP: init → update → final → 32 bytes)
        ▼
32 raw bytes ──► bytesToHex ──► 64-character hex string (hash)
        │
        ▼
Option 2: stored in ReferenceData   |  Option 3/4: hashesMatch(new, reference)
        │
        ▼
main.cpp prints "match" or "DIFFER"
```

---

## 4. `integrity.h` line by line

- `#ifndef INTEGRITY_H / #define INTEGRITY_H / #endif` – **include guard**. If the header is included twice, the second time it is skipped, avoiding "already defined" errors.
- `#include <cstddef>` – gives `std::size_t` (an unsigned number type used for sizes/counts).
- `#include <string>` – gives `std::string`.
- `namespace integrity { ... }` – groups our functions so names don't clash; you call them as `integrity::name`.
- `constexpr std::size_t SHA256_HEX_LENGTH = 64;` – a compile-time constant. 256 bits = 32 bytes; 2 hex characters per byte → 64.
- `const std::string&` – a **reference to const**: passes the string without copying, and promises not to change it.
- `std::string&` (non-const) – an **output parameter**: the function writes its result into the caller's variable.

---

## 5. Functions: parameters and return values

### `bool computeSha256Hex(const std::string& message, std::string& hexDigest, std::string& errorMessage)`
- **message** – input data.
- **hexDigest** – output, 64 lowercase hex characters on success (cleared first).
- **errorMessage** – output, explanation on failure.
- **Returns** `true` on success, `false` on failure. Callers must check it.

### `bool hashesMatch(const std::string& computedHash, const std::string& referenceHash)`
Returns `true` only if the strings are exactly equal (`==`).

### `std::size_t countDifferentHexChars(const std::string& hashA, const std::string& hashB)`
Counts positions where the two strings differ. Used only to *show* how many of the 64 characters changed.

### Helpers inside `integrity.cpp` (anonymous namespace = private to that file)
- `bytesToHex(const unsigned char* bytes, std::size_t length)` → returns hex text.
- `describeOpenSslError(const std::string& step)` → returns a message like "OpenSSL failed during: …", adding OpenSSL's own error text if available.

### Functions in `main.cpp`
- `trim(text)` – strips spaces/tabs/newlines from both ends (used only for the *menu choice*).
- `readMessage(prompt, message)` – prints the prompt, reads a full line, returns `InputResult::Ok`, `Empty` or `Closed`.
- `printMenu()`, `printEmptyInputError()` – printing only.
- `hashOrReportError(message, hash)` – calls the hash function; prints an error and returns `false` if it fails.
- `handleCalculateHash()` (option 1), `handleSetReference(reference)` (2), `handleVerify(reference)` (3), `handleDemonstrateModification(reference)` (4). They return `false` only if the input stream closed, telling `main` to stop.
- `main()` – the loop that shows the menu and dispatches.

---

## 6. `integrity.cpp` – how OpenSSL calculates the digest

1. `EVP_MD_CTX_new()` – create a **context**: a work area holding the hash's running state. Returns `nullptr` if it fails (so we check).
2. `EVP_DigestInit_ex(context, EVP_sha256(), nullptr)` – select the algorithm SHA-256. Returns `1` for success. (`nullptr` = use the default engine.)
3. `EVP_DigestUpdate(context, message.data(), message.size())` – feed the raw bytes. Can be called many times for big data.
4. `EVP_DigestFinal_ex(context, digest, &digestLength)` – finish padding/processing and write the 32-byte result into `digest`; the length goes into `digestLength`. `&digestLength` passes the variable's address so the function can fill it.
5. `EVP_MD_CTX_free(context)` – release memory. We call it on **every** exit path (success and each failure) so nothing leaks.
6. Check `digestLength == 32`, then `bytesToHex`.

Why EVP? It is OpenSSL 3's recommended high-level API; the older `SHA256_Init` functions are deprecated.

### `bytesToHex`
`std::ostringstream` is a text builder. `std::hex` prints numbers in base 16; `std::setfill('0')` pads with zeros; `std::setw(2)` makes each byte two characters wide (so byte `0x0A` → `0a`, not `a`). `static_cast<int>` stops the stream from printing a character instead of a number.

### Other syntax a beginner may not know
- `&&`/`||` – logical and/or. `!` – not.
- `nullptr` – "points to nothing".
- `++i` – add 1 to `i`.
- `a ? b : c` – "if a then b else c".
- `std::getline(std::cin, s)` – reads a whole line, including spaces; returns false when input ends.
- `enum class InputResult { Ok, Empty, Closed }` – a named set of possible results.
- `struct ReferenceData { ... }` – bundles related variables (isSet, message, hash).
- `const ReferenceData&` as a parameter in `handleVerify` – the function can read the reference but **cannot change it** (this enforces "verification doesn't replace the reference").
- `#ifdef INTEGRITY_SIMULATE_FAILURE` – code compiled only when that flag is given (our test hook).

---

## 7. How verification works

1. The reference hash was computed from the original message in option 2 and stored.
2. For a new message, we compute its hash the same way.
3. `hashesMatch` checks `newHash == referenceHash`.
4. Equal ⇒ "no modification detected". Different ⇒ "changed or doesn't match".
5. The reference is passed as `const`, so verification cannot overwrite it.

"No modification detected" is not a proof of authenticity; it means the data matches the reference.

---

## 8. What happens if I remove or change something? (viva "what if")

| Change | Effect |
|---|---|
| Remove `EVP_MD_CTX_free` calls | Memory leak (small here, bad in long-running programs). |
| Ignore the return value of `EVP_DigestUpdate`/`Final` | A failure could go unnoticed and a wrong/empty hash be shown or stored as "trusted". |
| Remove `std::setw(2)`/`setfill('0')` | Bytes below `0x10` print as one character; the string is shorter than 64 and wrong. |
| Remove `static_cast<int>` | Bytes print as characters, not hex numbers. |
| Remove the include guard | "Redefinition" errors if the header is included twice. |
| Forget `-lcrypto` | Linker error: `undefined reference to EVP_...`. |
| Make the reference non-const in `handleVerify` and overwrite it | A tampered message would silently become "trusted" — breaking the purpose. |
| Trim the messages | Spaces would be removed before hashing; `"hello "` and `"hello"` would wrongly look identical. |
| Remove the `isSet` check | Verifying before setting a reference would compare against an empty string and always say "differ". |
| Remove the `\r` cleanup | On some Windows input the hash would include a hidden carriage return and not match. |
| Replace `hashesMatch` with `return true;` | Every message "verifies" — a security failure. |
| Remove the EOF check on `getline` | Infinite loop when input is closed. |

---

## 9. Common viva questions with model answers

**What is data integrity?** Assurance that data has not been changed in an unauthorized way. Hashing helps *detect* changes; it does not prevent them.

**What is a cryptographic hash function?** A function that maps any input to a fixed-size digest, is deterministic, easy to compute, and designed so that it is infeasible to recover the input from the digest, to find another input with the same digest, or to find any two inputs that collide.

**How does SHA-256 work (high level)?** Pad the message to a multiple of 512 bits, split into blocks, start with a fixed 256-bit state, and for each block run 64 rounds of rotations, bitwise operations, additions and constants. The final state is the 256-bit digest (FIPS 180-4).

**Why does changing one character change the digest?** The avalanche effect: each input bit influences many rounds, so a tiny change typically changes about half the output bits (in my demo, usually around 60 of 64 hex characters).

**Is hashing the same as encryption?** No. Encryption is reversible with a key and protects confidentiality. A hash is one-way, has no key, and is a fingerprint.

**Why do you need a trusted original hash?** A hash by itself says nothing; you need a known-good value to compare to.

**Does a hash authenticate the sender?** No. Anyone can compute SHA-256 of any message. Authentication needs a secret (HMAC) or a signature.

**What if an attacker can replace both the message and the hash?** Then the new pair matches and the attack is not detected. The reference must be protected or sent over a separate trusted channel.

**Limitations of storing the reference only in memory?** It disappears when the program closes and nothing protects it from being changed. Fine for a demo, not for real systems.

**Does SHA-256 prevent modification?** No. It only helps detect modification when compared with a trustworthy reference.

**Why OpenSSL and not your own code?** Implementing cryptography yourself is error-prone; a well-tested library is the standard practice. `std::hash` is not cryptographic.

**Why EVP and not `SHA256()`?** EVP is the recommended high-level interface in OpenSSL 3; the low-level SHA256 functions are deprecated.

**Is SHA-256 secure?** No practical collision or preimage attacks are known; it is widely used. (Hashing passwords needs specialised slow hashes, a different topic.)

**What would you improve?** HMAC for authenticity, hashing files in chunks, protected storage for the reference, automated tests.

**Is it production-grade?** No; it's an educational demonstration.

**Why 64 characters?** 256 bits ÷ 4 bits per hex character = 64.

**Did you test it on Windows?** *Answer honestly with what you actually ran.* (The generating environment tested on Linux only.)

---

## 10. Demo script (about 3–4 minutes)

1. **Build and start:** compile with the README command, run `integrity.exe`.
2. **Show the menu** and say the program is a demonstration.
3. **Option 3 first (no reference)** → shows "No reference has been set yet." *(error handling)*
4. **Option 1**, message `abc` → digest starts `ba7816bf...`; point out 64 characters = 256 bits and say this equals the NIST published value.
5. **Option 1** `abc` again → same digest *(deterministic)*.
6. **Option 2**, message `Hello World` → reference stored; point out the "memory only" warning.
7. **Option 3**, `Hello World` → "No modification was detected."
8. **Option 3**, `Hello World!` → "hashes DIFFER". Say: one added character.
9. **Option 4**, `Hello Xorld` → shows both hashes and how many of 64 hex characters differ *(avalanche)*.
10. **Option 3**, `Hello World` again → still matches *(reference was not replaced)*.
11. **Empty input and bad menu choice:** press Enter at a prompt; type `9` at the menu.
12. **Option 5** to exit.
13. Finish by stating limitations: no sender authentication; attacker replacing both message and hash wins; reference not persisted; HMAC/signatures as future work.

Tip: practise once beforehand and record what you actually see in the test plan.
