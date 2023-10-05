/**
 * @file appendix_c_test.cpp
 * @author Alex Zhang (azhang13)
 * @brief Outputs example vectors from the FIPS 197 specification, Appendix C
 * @date 2023-08-30
 */

#include <iomanip>
#include <iostream>
#include <memory>
#include <sstream>

#include "aes.hpp"

using namespace amzcrypto;

int main() {
    std::cout << std::left;
    {  // Appendix C.1
        using AES128 = AES::Engine<4>;
        std::cout << "C.1   AES-128 (Nk=4, Nr=10)\n\n";

        AES::byte_block_t plaintext = {0x00, 0x11, 0x22, 0x33, 0x44, 0x55,
                                       0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb,
                                       0xcc, 0xdd, 0xee, 0xff};
        AES128::cipher_key_t key = {0x00, 0x01, 0x02, 0x03, 0x04, 0x05,
                                    0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b,
                                    0x0c, 0x0d, 0x0e, 0x0f};

        std::cout << std::setw(20)
                  << "PLAINTEXT:" << AES::bytes_to_string(plaintext) << '\n';
        std::cout << std::setw(20) << "KEY:" << AES::bytes_to_string(key)
                  << "\n\n";

        AES128 aes128(key);

        std::cout << "CIPHER (ENCRYPT):\n";
        AES::byte_block_t ciphertext = aes128.cipher(plaintext);

        std::cout << "\nINVERSE CIPHER (DECRYPT):\n";
        AES::byte_block_t plaintext2 = aes128.invcipher(ciphertext);
        // assert(plaintext == plaintext2);

        std::cout << "\nEQUIVALENT INVERSE CIPHER (DECRYPT):\n";
        AES::byte_block_t plaintext3 = aes128.eqinvcipher(ciphertext);
        // assert(plaintext == plaintext3);
    }

    {  // Appendix C.2
        using AES192 = AES::Engine<6>;
        std::cout << "\nC.2   AES-192 (Nk=6, Nr=12)\n\n";

        AES::byte_block_t plaintext = {0x00, 0x11, 0x22, 0x33, 0x44, 0x55,
                                       0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb,
                                       0xcc, 0xdd, 0xee, 0xff};
        AES192::cipher_key_t key = {0x00, 0x01, 0x02, 0x03, 0x04, 0x05,
                                    0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b,
                                    0x0c, 0x0d, 0x0e, 0x0f, 0x10, 0x11,
                                    0x12, 0x13, 0x14, 0x15, 0x16, 0x17};

        std::cout << std::setw(20)
                  << "PLAINTEXT:" << AES::bytes_to_string(plaintext) << '\n';
        std::cout << std::setw(20) << "KEY:" << AES::bytes_to_string(key)
                  << "\n\n";

        AES192 aes192(key);

        std::cout << "CIPHER (ENCRYPT):\n";
        AES::byte_block_t ciphertext = aes192.cipher(plaintext);

        std::cout << "\nINVERSE CIPHER (DECRYPT):\n";
        AES::byte_block_t plaintext2 = aes192.invcipher(ciphertext);
        // assert(plaintext == plaintext2);

        std::cout << "\nEQUIVALENT INVERSE CIPHER (DECRYPT):\n";
        AES::byte_block_t plaintext3 = aes192.eqinvcipher(ciphertext);
        // assert(plaintext == plaintext3);
    }

    {  // Appendix C.3
        using AES256 = AES::Engine<8>;
        std::cout << "\nC.3   AES-256 (Nk=8, Nr=14)\n\n";

        AES::byte_block_t plaintext = {0x00, 0x11, 0x22, 0x33, 0x44, 0x55,
                                       0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb,
                                       0xcc, 0xdd, 0xee, 0xff};
        constexpr AES256::cipher_key_t key = {
            0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a,
            0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15,
            0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f};

        std::cout << std::setw(20)
                  << "PLAINTEXT:" << AES::bytes_to_string(plaintext) << '\n';
        std::cout << std::setw(20) << "KEY:" << AES::bytes_to_string(key)
                  << "\n\n";

        AES256 aes256(key);

        std::cout << "CIPHER (ENCRYPT):\n";
        AES::byte_block_t ciphertext = aes256.cipher(plaintext);

        std::cout << "\nINVERSE CIPHER (DECRYPT):\n";
        AES::byte_block_t plaintext2 = aes256.invcipher(ciphertext);
        // assert(plaintext == plaintext2);

        std::cout << "\nEQUIVALENT INVERSE CIPHER (DECRYPT):\n";
        AES::byte_block_t plaintext3 = aes256.eqinvcipher(ciphertext);
        // assert(plaintext == plaintext3);
    }

    return 0;
}
