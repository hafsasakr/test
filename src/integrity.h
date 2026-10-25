// integrity.h
// Declarations for the SHA-256 hashing and integrity-verification helpers.
//
// This file is the "public face" of integrity.cpp: main.cpp only needs to
// include this header to use the functions below.

#ifndef INTEGRITY_H   // Include guard: stops this header being processed twice
#define INTEGRITY_H

#include <cstddef>
#include <string>

namespace integrity {

// A SHA-256 digest is 256 bits = 32 bytes. Written in hexadecimal, each byte
// becomes 2 characters, so the text form is always 64 characters long.
constexpr std::size_t SHA256_HEX_LENGTH = 64;

// Calculates the SHA-256 digest of `message` using OpenSSL.
//
// Parameters:
//   message      - the data to hash (read only, not copied).
//   hexDigest    - output: set to 64 lowercase hex characters on success.
//   errorMessage - output: set to a description of the problem on failure.
//
// Returns: true on success, false if OpenSSL reported an error.
bool computeSha256Hex(const std::string& message,
                      std::string& hexDigest,
                      std::string& errorMessage);

// Compares a newly computed hash with a trusted reference hash.
// Returns true only if both strings are exactly identical.
bool hashesMatch(const std::string& computedHash,
                 const std::string& referenceHash);

// Counts how many positions differ between two hex digests.
// Only used to make the "small change" demonstration easy to see.
// If the lengths differ, the extra characters count as differences.
std::size_t countDifferentHexChars(const std::string& hashA,
                                   const std::string& hashB);

}  // namespace integrity

#endif  // INTEGRITY_H
