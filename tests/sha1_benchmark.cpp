#include <chrono>
#include <iomanip>
#include <iostream>

#include "sha1.hpp"
#include "sha1_util.hpp"

using namespace amzcrypto;

volatile SHA1::word_t a, b, c, d, e;

int main() {
    constexpr std::size_t num_iterations = 1000000;
    constexpr std::size_t string_len = 119;

    std::chrono::nanoseconds random_string_elapsed{};
    std::chrono::nanoseconds padding_elapsed{};
    std::chrono::nanoseconds hashing_elapsed{};

    for (std::size_t i = 0; i < num_iterations; ++i) {
        auto random_string_start = std::chrono::high_resolution_clock::now();
        std::string message = random_string(string_len);
        auto random_string_stop = std::chrono::high_resolution_clock::now();
        random_string_elapsed += random_string_stop - random_string_start;

        auto padding_start = std::chrono::high_resolution_clock::now();
        SHA1::pad_in_place(message);
        auto padding_stop = std::chrono::high_resolution_clock::now();
        padding_elapsed += padding_stop - padding_start;

        auto hashing_start = std::chrono::high_resolution_clock::now();
        std::array<SHA1::word_t, 5> digest = SHA1::hash(message);
        auto hashing_stop = std::chrono::high_resolution_clock::now();
        hashing_elapsed += hashing_stop - hashing_start;

        // Ensure a side-effect to avoid unwanted optimization
        a = digest[0];
        b = digest[1];
        c = digest[2];
        d = digest[3];
        e = digest[4];
    }

    std::cout << num_iterations << " strings of length " << string_len << " ("
              << string_len * num_iterations << " bytes)" << std::endl;
    std::cout << "Random string generation: "
              << random_string_elapsed.count() / 1'000'000.0 << "ms\n";
    std::cout << "Padding: " << padding_elapsed.count() / 1'000'000.0 << "ms\n";
    std::cout << "Hashing: " << hashing_elapsed.count() / 1'000'000.0 << "ms\n";

    return 0;
}
