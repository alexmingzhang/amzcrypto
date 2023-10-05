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

std::size_t random_index() {
    static std::mt19937 rng(std::random_device{}());
    static std::uniform_int_distribution<std::size_t> dist(0, 15);
    return dist(rng);
}

volatile std::uint8_t sink;

int main() {
    AES::byte_block_t plaintext;
    AES::byte_block_t ciphertext;

    AES::Engine<4>::cipher_key_t key;
    for (AES::Byte& byte : key) {
        byte = random_byte();
    }

    AES::Engine<4> aes(key);

    std::chrono::duration<double> accumulated_time(0);

    constexpr int num_blocks_to_encrypt = 10000;

    for (int i = 0; i < num_blocks_to_encrypt; ++i) {
        for (AES::Byte& byte : plaintext) {
            byte = random_byte();
        }

        std::size_t index = random_index();
        auto start_time = std::chrono::high_resolution_clock::now();
        ciphertext = aes.cipher(plaintext);
        auto end_time = std::chrono::high_resolution_clock::now();

        sink = ciphertext[index].get_value();

        accumulated_time += end_time - start_time;
    }

    std::cout << "Encrypted " << num_blocks_to_encrypt * 16 << " bytes in "
              << accumulated_time << " seconds.\n";

    return 0;
}
