#include <openssl/sha.h>

#include <chrono>
#include <iomanip>
#include <iostream>

#include "sha1.hpp"
#include "sha1_util.hpp"

volatile amzcrypto::SHA1::word_t a, b, c, d, e;

int main() {
    constexpr std::size_t num_iterations = 1000000;
    constexpr std::size_t string_len = 119;

    std::chrono::nanoseconds random_string_elapsed{};
    std::chrono::nanoseconds amzcrypto_padding_elapsed{};
    std::chrono::nanoseconds amzcrypto_hashing_elapsed{};
    std::chrono::nanoseconds openssl_hashing_elapsed{};

    for (std::size_t i = 0; i < num_iterations; ++i) {
        auto start = std::chrono::high_resolution_clock::now();
        std::string message = random_string(string_len);
        auto stop = std::chrono::high_resolution_clock::now();
        random_string_elapsed += stop - start;

        start = std::chrono::high_resolution_clock::now();
        auto padded_message = amzcrypto::SHA1::pad_in_place(message);
        stop = std::chrono::high_resolution_clock::now();
        amzcrypto_padding_elapsed += stop - start;

        start = std::chrono::high_resolution_clock::now();
        std::array<amzcrypto::SHA1::word_t, 5> amzcrypto_digest =
            amzcrypto::SHA1::hash(padded_message);
        stop = std::chrono::high_resolution_clock::now();
        amzcrypto_hashing_elapsed += stop - start;

        start = std::chrono::high_resolution_clock::now();
        unsigned char openssl_digest[20];
        SHA1(reinterpret_cast<const unsigned char *>(message.c_str()),
             message.size(), openssl_digest);
        stop = std::chrono::high_resolution_clock::now();
        openssl_hashing_elapsed += stop - start;

        // for (int i = 0; i < 5; ++i) {
        //     assert(amzcrypto_digest[i] == ((openssl_digest[i * 4] << 24)) |
        //            (openssl_digest[i * 4 + 1] << 16) |
        //            (openssl_digest[i * 4 + 2] << 8) |
        //            openssl_digest[i * 4 + 3]);
        // }

        // Ensure a side-effect to avoid unwanted optimization
        a = amzcrypto_digest[0];
        b = amzcrypto_digest[1];
        c = amzcrypto_digest[2];
        d = amzcrypto_digest[3];
        e = amzcrypto_digest[4];
    }

    std::cout << num_iterations << " strings of length " << string_len << " ("
              << string_len * num_iterations << " bytes)" << std::endl;
    std::cout << "Random string:     " << random_string_elapsed << "\n";
    std::cout << "amzcrypto padding: " << amzcrypto_padding_elapsed << "\n";
    std::cout << "amzcrypto hashing: " << amzcrypto_hashing_elapsed << "\n";
    std::cout << "openssl hashing:   " << openssl_hashing_elapsed << "\n";

    return 0;
}
