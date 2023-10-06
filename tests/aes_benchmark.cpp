#include <openssl/aes.h>

#include <chrono>
#include <cstdint>
#include <iostream>
#include <random>

#include "aes.hpp"

using namespace amzcrypto;

AES::Byte random_byte() {
    static std::mt19937 rng(std::random_device{}());
    static std::uniform_int_distribution<uint8_t> dist(0, 255);
    return AES::Byte{dist(rng)};
}

volatile std::uint8_t sink;

int main() {
    AES::byte_block_t plaintext;
    AES::byte_block_t ciphertext_amzcrypto;
    unsigned char ciphertext_openssl[16];

    AES::Engine<4>::cipher_key_t key_amzcrypto;
    for (AES::Byte& byte : key_amzcrypto) {
        byte = random_byte();
    }
    AES::Engine<4> aes(key_amzcrypto);

    AES_KEY key_openssl;
    AES_set_encrypt_key(reinterpret_cast<unsigned char*>(key_amzcrypto.data()),
                        128, &key_openssl);

    std::chrono::nanoseconds amzcrypto_elapsed{};
    std::chrono::nanoseconds openssl_elapsed{};

    constexpr int num_blocks_to_encrypt = 10000;

    for (int i = 0; i < num_blocks_to_encrypt; ++i) {
        for (AES::Byte& byte : plaintext) {
            byte = random_byte();
        }

        auto start = std::chrono::high_resolution_clock::now();
        ciphertext_amzcrypto = aes.cipher(plaintext);
        auto stop = std::chrono::high_resolution_clock::now();
        amzcrypto_elapsed += stop - start;

        start = std::chrono::high_resolution_clock::now();
        AES_encrypt(reinterpret_cast<unsigned char*>(plaintext.data()),
                    ciphertext_openssl, &key_openssl);
        stop = std::chrono::high_resolution_clock::now();
        openssl_elapsed += stop - start;

        for (int i = 0; i < 16; ++i) {
            assert(ciphertext_amzcrypto[i].get_value() ==
                   ciphertext_openssl[i]);
        }
    }

    std::cout << "amzcrypto: "
              << amzcrypto_elapsed / static_cast<double>(num_blocks_to_encrypt)
              << " per block.\n";
    std::cout << "OpenSSL:   "
              << openssl_elapsed / static_cast<double>(num_blocks_to_encrypt)
              << " per block.\n";

    return 0;
}
