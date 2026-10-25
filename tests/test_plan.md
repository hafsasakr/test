# Test Plan

Project: Data Integrity Verification System Using SHA-256

**Important:** the "Actual result" column is intentionally blank. Run each test on your own machine and record what you really see. Do not copy the expected results as if they were observed.

Build first (see README section 4): `g++ -std=c++17 -Wall -Wextra -o integrity.exe src/main.cpp src/integrity.cpp -lcrypto`

Known reference value (NIST example, for cross-checking): SHA-256("abc") = `ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad`

| ID | Test | Input (menu choices / text) | Expected result | What it demonstrates | Actual result | Pass? |
|---|---|---|---|---|---|---|
| T1 | Hash a normal message | `1`, then `abc` | Prints a 64-character hex digest; for `abc` it equals the NIST value above; text states 256 bits | Correct, real SHA-256 via OpenSSL; fixed-length output | | |
| T2 | Hash the same message twice | `1` `abc`, then `1` `abc` again | Both digests are identical | Hashing is deterministic | | |
| T3 | One-character modification | `2` `Hello World`, then `3` `Hello World!` (or `4` `Hello Xorld`) | Verification fails; message says hashes differ (option 4 also shows how many of 64 hex characters differ, normally most of them) | A tiny change produces a different digest, so modification is detected | | |
| T4 | Completely different message | `2` `Hello World`, then `3` `Totally different` | Hashes differ; "message has changed or does not match" | Different data does not match the reference | | |
| T5 | Verify an unchanged message | `2` `Hello World`, then `3` `Hello World` | Hashes match; "No modification was detected" | Successful verification path | | |
| T6 | Reference not replaced by verification | After T3/T4, run `3` `Hello World` | Still matches the original reference | Verification never overwrites the trusted reference | | |
| T7 | Verify before a reference exists | Start program, choose `3` (and also `4`) | "No reference has been set yet. Choose option 2 first." No crash | Program handles missing state | | |
| T8 | Empty message | `1` then press Enter with nothing; also `2` and `3` | "input cannot be empty" message; menu returns | Input validation for empty text | | |
| T9 | Empty/blank menu choice | Press Enter at the menu | "no choice entered" message; menu returns | Input validation | | |
| T10 | Invalid menu choices | `0`, `9`, `abc`, `1.5`, `-1` | "not a valid choice" message each time; no crash | Robust handling of unexpected input | | |
| T11 | Input closed | At the menu press Ctrl+Z then Enter (Windows) / Ctrl+D (Linux) | "Input closed. Exiting." and normal exit | No infinite loop when input ends | | |
| T12 | Spaces are part of the data | `2` `hello`, then `3` `hello ` (trailing space) | Hashes differ | Every byte, including spaces, affects the digest | | |
| T13 | Replacing the reference by choice | `2` twice with different text | Second time prints a note that the previous reference was replaced | Reference changes only when the user explicitly chooses option 2 | | |
| T14 | Hashing failure (simulated) | Build with `-DINTEGRITY_SIMULATE_FAILURE` (README section 6), choose `1` then `abc`; also `2` | "could not calculate the hash" + reason; for option 2 "The reference was not changed."; no crash | Errors from the hash function are reported, not ignored | | |
| T15 | Exit | `5` | "Goodbye." and exit | Clean termination | | |

Notes:
- A real OpenSSL failure is very hard to trigger deliberately, so T14 uses a compile-time test hook that makes `computeSha256Hex` return `false`.
- Do not claim a test passed unless you ran it.
