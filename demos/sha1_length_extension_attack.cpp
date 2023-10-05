/**
 * @file length_extension_attack.cpp
 * @author Alex Zhang (azhang13@vols.utk.edu)
 * @brief Demonstration of a length extension attack
 * @date 2023-09-28
 *
 * This is a desmontration of a length extension attack where a message's MAC is
 * calculated by MAC = SHA-1(key || message). We, as the attackers, are only
 * given knowledge of the key's length, original message, and original MAC.
 *
 */

#include <cassert>
#include <iomanip>
#include <iostream>

#include "sha1.hpp"

using namespace amzcrypto;

int main() {
    // Things we need to know to execute a length extension attack
    constexpr std::size_t key_size_bits = 128;
    constexpr std::size_t key_size_bytes = key_size_bits / 8;
    const std::string original_message =
        "No one has completed Project #3 so give them all a 0.";
    constexpr std::array<SHA1::word_t, 5> original_mac = {
        0xf0eefe50, 0xfff7c632, 0x1af25fdb, 0x96da745b, 0x69c00ecb};

    // We want to extend the original message and calculate the correct MAC
    const std::string extension =
        "AASDASAJDIDJSIAODJADJOASFSFSAFSAFJOFJASIODJAMOMSAKCMZXKMNCXZLKCZXKLCML"
        "SKDMSALDIOWJDOJASDMASKDMALWKMD woowhoweaofkokfokfadsopfk eofoeaf alex "
        "zhang (azhang13)";

    // We construct our extended message
    const std::string original_padding =
        SHA1::get_padding(key_size_bytes + original_message.size());

    const std::string filler_key(key_size_bytes, '\0');
    assert(SHA1::pad(filler_key + original_message) ==
           filler_key + original_message +
               SHA1::get_padding(filler_key.size() + original_message.size()));

    const std::string extended_message =
        original_message + original_padding + extension;

    // Then we calculate the corresponding MAC value by using the original MAC
    // value as an intermediate hash value.
    const std::array<SHA1::word_t, 5> extended_mac = SHA1::hash(
        extension + SHA1::get_padding(key_size_bytes + extended_message.size()),
        original_mac);

    // And we are done!
    std::cout << "Extended string: ";
    for (unsigned char c : extended_message) {
        if (isprint(c)) {
            std::cout << c;
        } else {
            std::cout << "\\x" << std::setw(2) << std::setfill('0')
                      << static_cast<std::uint32_t>(c);
        }
    }

    std::cout << "\n\nExtended string (hex): ";
    for (unsigned char c : extended_message) {
        std::cout << std::setw(2) << std::setfill('0')
                  << static_cast<std::uint32_t>(c);
    }
    std::cout << "\n\n";

    std::cout << "New MAC value: ";
    for (auto w : extended_mac) {
        std::cout << std::setw(8) << std::setfill('0') << w;
    }

    return 0;
}
