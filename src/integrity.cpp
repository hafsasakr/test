// integrity.cpp
// Implementation of SHA-256 hashing (via OpenSSL) and hash comparison.

#include "integrity.h"

#include <openssl/err.h>   // Reads OpenSSL's error queue for readable messages
#include <openssl/evp.h>   // EVP = OpenSSL's high-level "envelope" digest API

#include <iomanip>
#include <sstream>

namespace {  // Anonymous namespace: these helpers are private to this file.

// Converts raw bytes into lowercase hexadecimal text.
// Example: the single byte 0x0A becomes "0a" (two characters, never just "a").
std::string bytesToHex(const unsigned char* bytes, std::size_t length) {
    std::ostringstream stream;
    // std::hex prints numbers in base 16. setfill('0') pads with zeros.
    // setfill stays active; setw(2) must be repeated for every byte.
    stream << std::hex << std::setfill('0');
    for (std::size_t i = 0; i < length; ++i) {
        // Cast to int, otherwise the stream would print the byte as a character.
        stream << std::setw(2) << static_cast<int>(bytes[i]);
    }
    return stream.str();
}

// Builds an error message that includes OpenSSL's own explanation (if any).
std::string describeOpenSslError(const std::string& step) {
    std::string text = "OpenSSL failed during: " + step;
    const unsigned long code = ERR_get_error();  // 0 means "no error recorded"
    if (code != 0) {
        char buffer[256];
        ERR_error_string_n(code, buffer, sizeof(buffer));
        text += " (";
        text += buffer;
        text += ")";
    }
    return text;
}

}  // namespace

namespace integrity {

bool computeSha256Hex(const std::string& message,
                      std::string& hexDigest,
                      std::string& errorMessage) {
    hexDigest.clear();      // Never leave an old value behind
    errorMessage.clear();

#ifdef INTEGRITY_SIMULATE_FAILURE
    // Test hook: compile with -DINTEGRITY_SIMULATE_FAILURE to prove that the
    // program handles a hashing failure without crashing (see tests/test_plan.md).
    errorMessage = "Simulated hashing failure (test build only).";
    return false;
#endif

    // 1. Create a context: a work area where OpenSSL keeps the hash state.
    EVP_MD_CTX* context = EVP_MD_CTX_new();
    if (context == nullptr) {
        errorMessage = describeOpenSslError("creating the digest context");
        return false;
    }

    // 2. Tell OpenSSL which algorithm to use: SHA-256. Returns 1 on success.
    if (EVP_DigestInit_ex(context, EVP_sha256(), nullptr) != 1) {
        errorMessage = describeOpenSslError("initialising SHA-256");
        EVP_MD_CTX_free(context);  // Always free what we allocated
        return false;
    }

    // 3. Feed the message bytes into the hash. Returns 1 on success.
    if (EVP_DigestUpdate(context, message.data(), message.size()) != 1) {
        errorMessage = describeOpenSslError("feeding data into SHA-256");
        EVP_MD_CTX_free(context);
        return false;
    }

    // 4. Finish and fetch the digest. EVP_MAX_MD_SIZE is big enough for any
    //    digest OpenSSL supports; for SHA-256 only 32 bytes are used.
    unsigned char digest[EVP_MAX_MD_SIZE];
    unsigned int digestLength = 0;
    if (EVP_DigestFinal_ex(context, digest, &digestLength) != 1) {
        errorMessage = describeOpenSslError("finishing SHA-256");
        EVP_MD_CTX_free(context);
        return false;
    }

    EVP_MD_CTX_free(context);  // Done with the context

    // Sanity check: SHA-256 must always produce exactly 32 bytes.
    if (digestLength != SHA256_HEX_LENGTH / 2) {
        errorMessage = "Unexpected digest length from OpenSSL.";
        return false;
    }

    hexDigest = bytesToHex(digest, digestLength);
    return true;
}

bool hashesMatch(const std::string& computedHash,
                 const std::string& referenceHash) {
    // std::string's == compares length and every character.
    // (Both hashes are public values here, so a timing-safe comparison is not
    // needed for this demonstration.)
    return computedHash == referenceHash;
}

std::size_t countDifferentHexChars(const std::string& hashA,
                                   const std::string& hashB) {
    const std::size_t shorter = hashA.size() < hashB.size() ? hashA.size() : hashB.size();
    const std::size_t longer = hashA.size() < hashB.size() ? hashB.size() : hashA.size();

    std::size_t differences = longer - shorter;  // Unmatched extra characters
    for (std::size_t i = 0; i < shorter; ++i) {
        if (hashA[i] != hashB[i]) {
            ++differences;
        }
    }
    return differences;
}

}  // namespace integrity
