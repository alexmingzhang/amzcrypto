#include <iostream>

#include "aes.hpp"

using namespace amzcrypto;

int main() {
    using AES128 = AES::Engine<4>;

    constexpr AES::byte_block_t plaintext = {0x00, 0x11, 0x22, 0x33, 0x44, 0x55,
                                             0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb,
                                             0xcc, 0xdd, 0xee, 0xff};
    constexpr AES128::cipher_key_t key = {0x00, 0x01, 0x02, 0x03, 0x04, 0x05,
                                          0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b,
                                          0x0c, 0x0d, 0x0e, 0x0f};

    std::cout << std::setw(20)
              << "PLAINTEXT:" << AES::bytes_to_string(plaintext) << '\n';
    std::cout << std::setw(20) << "KEY:" << AES::bytes_to_string(key) << "\n\n";

    constexpr AES128 aes128(key);

    constexpr AES::byte_block_t ciphertext = aes128.cipher(plaintext);
    std::cout << "CIPHER (ENCRYPT):" << AES::bytes_to_string(ciphertext)
              << '\n';

    // static_assert(static_cast<int>(ciphertext[0].get_value()) == 0x69);

    std::cout << "\nINVERSE CIPHER (DECRYPT):\n";
    constexpr AES::byte_block_t plaintext2 = aes128.invcipher(ciphertext);
    // static_assert(plaintext == plaintext2);

    std::cout << "\nEQUIVALENT INVERSE CIPHER (DECRYPT):\n";
    constexpr AES::byte_block_t plaintext3 = aes128.eqinvcipher(ciphertext);
    // static_assert(plaintext == plaintext3);

    return 0;
}
