#include <openssl/bn.h>

#include <chrono>
#include <iostream>

#include "chunkyint.hpp"

using namespace amzcrypto;

int main() {
    constexpr std::size_t num_iterations = 1000;
    std::size_t num_successful = 0;

    std::chrono::nanoseconds mod_exp_elapsed{};
    std::chrono::nanoseconds mod_exp_cool_elapsed{};

    ChunkyInts::ChunkyInt b;
    ChunkyInts::ChunkyInt e;
    ChunkyInts::ChunkyInt m;

    for (std::size_t i = 0; i < num_iterations; ++i) {
        if (i % 100 == 0) {
            std::cout << num_successful << "/" << i
                      << " successful ChunkyInt modular exponentiation "
                         "operations.\n";
        }

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

        if (equals) {
            ++num_successful;
        } else {
            std::cerr << res1 << " != " << res2 << "\n\n";
        }
    }

    std::cout << num_successful << "/" << num_iterations
              << " successful ChunkyInt modular exponentiation "
                 "operations.\n";

    std::cout << "OpenSSL modular exponentiation:   " << mod_exp_elapsed
              << '\n';

    std::cout << "ChunkyInt modular exponentiation: " << mod_exp_cool_elapsed
              << '\n';

    return 0;
}
