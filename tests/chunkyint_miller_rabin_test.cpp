#include <openssl/bn.h>

#include <chrono>
#include <iostream>

#include "chunkyint.hpp"

using namespace amzcrypto;

int main() {
    constexpr std::size_t num_iterations = 1000;
    constexpr int num_checks = 40;
    std::size_t num_successful = 0;

    std::chrono::nanoseconds openssl_elapsed{};
    std::chrono::nanoseconds chunkyint_elapsed{};

    for (std::size_t i = 0; i < num_iterations; ++i) {
        if (i % 100 == 0) {
            std::cout << num_successful << "/" << i
                      << " successful miller-rabin checks.\n";
        }

        ChunkyInts::ChunkyInt p;
        p.randomize_bits(2048);

        auto start = std::chrono::high_resolution_clock::now();
        bool is_prime_1 = p.is_prime();  // OpenSSL primality check
        auto stop = std::chrono::high_resolution_clock::now();
        openssl_elapsed += stop - start;

        start = std::chrono::high_resolution_clock::now();
        bool is_prime_2 =
            p.miller_rabin(num_checks);  // ChunkyInt primality check
        stop = std::chrono::high_resolution_clock::now();
        chunkyint_elapsed += stop - start;

        if (is_prime_1 == is_prime_2) {
            ++num_successful;
        } else {
            std::cerr << p << " is " << (is_prime_1 ? "prime" : "composite")
                      << " but miller rabin-failed!\n\n";
        }
    }

    std::cout << num_successful << "/" << num_iterations
              << " successful miller-rabin checks.\n";

    std::cout << "OpenSSL miller-rabin:   " << openssl_elapsed << '\n';
    std::cout << "ChunkyInt miller-rabin: " << chunkyint_elapsed << '\n';

    return 0;
}
