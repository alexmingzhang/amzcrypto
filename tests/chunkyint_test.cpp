#include <openssl/bn.h>

#include <chrono>
#include <iostream>

// clang-format off
#include "chunkyint.hpp"
// clang-format on

using namespace amzcrypto;

int main() {
    ChunkyInts::ChunkyInt a = 5;

    std::cout << (a == a) << std::endl;

    ChunkyInts::ChunkyInt b;
    ChunkyInts::ChunkyInt e;
    ChunkyInts::ChunkyInt m;

    std::chrono::nanoseconds mod_exp_elapsed{};
    std::chrono::nanoseconds mod_exp_cool_elapsed{};

    // Test modular exponentiation
    for (int i = 0; i < 1000; ++i) {
        b.randomize_bits(2048);
        e.randomize_bits(2048);
        m.randomize_bits(1024);

        auto start = std::chrono::high_resolution_clock::now();
        ChunkyInts::ChunkyInt res1 = ChunkyInts::mod_exp(b, e, m);
        auto stop = std::chrono::high_resolution_clock::now();
        mod_exp_elapsed += stop - start;

        start = std::chrono::high_resolution_clock::now();
        ChunkyInts::ChunkyInt res2 = ChunkyInts::mod_exp_cool(b, e, m);
        stop = std::chrono::high_resolution_clock::now();
        mod_exp_cool_elapsed += stop - start;

        bool equals = res1 == res2;

        if (!equals) {
            std::cerr << res1 << " == " << res2 << std::boolalpha << equals
                      << "\n\n";
        } else {
            std::cout << "Successful modular exponentiation\n";
        }
    }

    std::cout << mod_exp_elapsed << '\n';
    std::cout << mod_exp_cool_elapsed << '\n';

    // Test miller-rabin primality test

    for (int i = 0; i < 1000; ++i) {
        ChunkyInts::ChunkyInt p;
        p.randomize_bits(2048);

        bool is_prime_1 = p.is_prime();
        bool is_prime_2 = p.miller_rabin(40);

        if (is_prime_1 != is_prime_2) {
            std::cerr << p << " is " << (is_prime_1 ? "prime" : "composite")
                      << " but miller rabin-failed!\n\n";
        } else {
            std::cout << "Successful miller-rabin test\n";
        }
    }

    return 0;
}
