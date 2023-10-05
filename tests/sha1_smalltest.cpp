#include <iomanip>
#include <iostream>

#include "sha1.hpp"
#include "sha1_util.hpp"

using namespace amzcrypto;

int main() {
    const std::array<std::string, 5> test_inputs{
        "This is a test of SHA-1.",
        "Kerckhoff's principle is the foundation on which modern cryptography "
        "is "
        "built.",
        "SHA-1 is no longer considered a secure hashing algorithm.",
        "SHA-2 or SHA-3 should be used in place of SHA-1.",
        "Never roll your own crypto!"};

    for (const auto &m : test_inputs) {
        auto digest = SHA1::hash(SHA1::pad(m));
        print_digest(digest);
    }

    return 0;
}
