// main.cpp
// Menu, user input and overall program flow for the
// "Data Integrity Verification System Using SHA-256" demonstration.
//
// All hashing is done in integrity.cpp (OpenSSL). This file only talks to the user.

#include <iostream>
#include <string>

#include "integrity.h"

namespace {

// The trusted reference lives only in memory for this run of the program.
struct ReferenceData {
    bool isSet = false;
    std::string message;
    std::string hash;
};

// Result of asking the user for a line of text.
enum class InputResult { Ok, Empty, Closed };

// Removes spaces, tabs and line-ending characters from both ends of `text`.
std::string trim(const std::string& text) {
    const std::string whitespace = " \t\r\n";
    const std::size_t first = text.find_first_not_of(whitespace);
    if (first == std::string::npos) {
        return "";  // The string was empty or only whitespace
    }
    const std::size_t last = text.find_last_not_of(whitespace);
    return text.substr(first, last - first + 1);
}

// Prints a prompt and reads one whole line (spaces allowed).
// Returns Closed if input ended (Ctrl+Z / Ctrl+D), Empty for a zero-length
// line, otherwise Ok. The message is NOT trimmed, because spaces are part of
// the data and would change the hash.
InputResult readMessage(const std::string& prompt, std::string& message) {
    std::cout << prompt;
    if (!std::getline(std::cin, message)) {
        return InputResult::Closed;
    }
    // Windows files/terminals may leave a trailing '\r'; it is not user data.
    if (!message.empty() && message.back() == '\r') {
        message.pop_back();
    }
    return message.empty() ? InputResult::Empty : InputResult::Ok;
}

void printMenu() {
    std::cout << "\n=== Data Integrity Verification (SHA-256) ===\n"
              << "1. Calculate a message hash\n"
              << "2. Set the original reference message\n"
              << "3. Verify a message\n"
              << "4. Demonstrate a message modification\n"
              << "5. Exit\n"
              << "Enter your choice (1-5): ";
}

void printEmptyInputError() {
    std::cout << "Error: input cannot be empty. Please type at least one character.\n";
}

// Computes a hash and, on failure, prints the reason. Returns true on success.
bool hashOrReportError(const std::string& message, std::string& hash) {
    std::string errorMessage;
    if (!integrity::computeSha256Hex(message, hash, errorMessage)) {
        std::cout << "Error: could not calculate the hash. " << errorMessage << "\n";
        return false;
    }
    return true;
}

// Each handler returns false only when the input stream has closed,
// which tells main() to stop the program cleanly.

// Feature A
bool handleCalculateHash() {
    std::string message;
    const InputResult result = readMessage("Enter a message to hash: ", message);
    if (result == InputResult::Closed) return false;
    if (result == InputResult::Empty) {
        printEmptyInputError();
        return true;
    }

    std::string hash;
    if (!hashOrReportError(message, hash)) return true;

    std::cout << "SHA-256 digest (" << hash.size() << " hex characters):\n"
              << hash << "\n"
              << "A SHA-256 digest is 256 bits long. Each hex character shows 4 bits,\n"
              << "so 256 / 4 = 64 characters.\n";
    return true;
}

// Feature B
bool handleSetReference(ReferenceData& reference) {
    std::string message;
    const InputResult result =
        readMessage("Enter the ORIGINAL message to use as the trusted reference: ", message);
    if (result == InputResult::Closed) return false;
    if (result == InputResult::Empty) {
        printEmptyInputError();
        return true;
    }

    std::string hash;
    if (!hashOrReportError(message, hash)) {
        std::cout << "The reference was not changed.\n";
        return true;
    }

    if (reference.isSet) {
        std::cout << "Note: the previous reference has been replaced at your request.\n";
    }
    reference.isSet = true;
    reference.message = message;
    reference.hash = hash;

    std::cout << "Reference stored.\n"
              << "Reference SHA-256: " << reference.hash << "\n"
              << "DEMONSTRATION ONLY: the reference is kept in memory for this session,\n"
              << "is not saved to disk, and is not protected against tampering.\n";
    return true;
}

// Feature C
bool handleVerify(const ReferenceData& reference) {
    if (!reference.isSet) {
        std::cout << "No reference has been set yet. Choose option 2 first.\n";
        return true;
    }

    std::string message;
    const InputResult result = readMessage("Enter the message to verify: ", message);
    if (result == InputResult::Closed) return false;
    if (result == InputResult::Empty) {
        printEmptyInputError();
        return true;
    }

    std::string newHash;
    if (!hashOrReportError(message, newHash)) {
        std::cout << "Verification could not be completed.\n";
        return true;
    }

    std::cout << "Trusted reference hash: " << reference.hash << "\n"
              << "Hash of your message:   " << newHash << "\n";

    if (integrity::hashesMatch(newHash, reference.hash)) {
        std::cout << "RESULT: hashes match. No modification was detected.\n";
    } else {
        std::cout << "RESULT: hashes DIFFER. The message has changed or does not match the reference.\n";
    }
    // The reference is deliberately left untouched here.
    return true;
}

// Feature D
bool handleDemonstrateModification(const ReferenceData& reference) {
    if (!reference.isSet) {
        std::cout << "No reference has been set yet. Choose option 2 first.\n";
        return true;
    }

    std::cout << "Original reference message: \"" << reference.message << "\"\n"
              << "Try changing ONE character (e.g. a letter or a digit), or type the\n"
              << "original text again to see a successful verification.\n";

    std::string modified;
    const InputResult result = readMessage("Enter the modified message: ", modified);
    if (result == InputResult::Closed) return false;
    if (result == InputResult::Empty) {
        printEmptyInputError();
        return true;
    }

    std::string modifiedHash;
    if (!hashOrReportError(modified, modifiedHash)) {
        std::cout << "The demonstration could not be completed.\n";
        return true;
    }

    std::cout << "Original hash: " << reference.hash << "\n"
              << "Modified hash: " << modifiedHash << "\n";

    if (integrity::hashesMatch(modifiedHash, reference.hash)) {
        std::cout << "RESULT: hashes match - the message is identical to the original.\n"
                  << "Verification SUCCEEDED (no modification detected).\n";
    } else {
        const std::size_t different =
            integrity::countDifferentHexChars(modifiedHash, reference.hash);
        std::cout << "RESULT: hashes differ in " << different << " of "
                  << integrity::SHA256_HEX_LENGTH << " hex characters.\n"
                  << "Verification FAILED (modification detected).\n"
                  << "A tiny change normally alters the digest completely.\n";
    }
    return true;
}

}  // namespace

int main() {
    ReferenceData reference;

    std::cout << "Data Integrity Verification System Using SHA-256\n"
              << "Educational demonstration - not a production security system.\n";

    bool running = true;
    while (running) {
        printMenu();

        std::string choiceLine;
        if (!std::getline(std::cin, choiceLine)) {
            std::cout << "\nInput closed. Exiting.\n";
            break;
        }
        const std::string choice = trim(choiceLine);

        if (choice.empty()) {
            std::cout << "Error: no choice entered. Please type a number from 1 to 5.\n";
        } else if (choice == "1") {
            running = handleCalculateHash();
        } else if (choice == "2") {
            running = handleSetReference(reference);
        } else if (choice == "3") {
            running = handleVerify(reference);
        } else if (choice == "4") {
            running = handleDemonstrateModification(reference);
        } else if (choice == "5") {
            std::cout << "Goodbye.\n";
            running = false;
        } else {
            std::cout << "Error: \"" << choice << "\" is not a valid choice. Please type a number from 1 to 5.\n";
        }

        if (!running && choice != "5") {
            std::cout << "\nInput closed. Exiting.\n";
        }
    }
    return 0;
}
