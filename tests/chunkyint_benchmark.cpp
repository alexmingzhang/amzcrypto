// Probably not a good benchmark

#include <chrono>
#include <iostream>

#include "chunkyint.hpp"

using namespace amzcrypto;

BIGNUM* volatile sink = BN_new();
ChunkyInts::ChunkyInt sink2;

int main() {
    constexpr std::size_t num_iterations = 500000uz;

    {
        BIGNUM* a = BN_new();
        BIGNUM* b = BN_new();
        BN_CTX* ctx = BN_CTX_new();

        std::chrono::nanoseconds elapsed{};

        for (std::size_t i = 0; i < num_iterations; ++i) {
            BN_rand(a, 2048, 0, false);
            BN_rand(b, 2048, 0, false);

            auto start = std::chrono::high_resolution_clock::now();
            BN_mul(sink, a, b, ctx);
            auto stop = std::chrono::high_resolution_clock::now();

            elapsed += stop - start;
        }

        std::cout << "BN_mul: " << elapsed / static_cast<double>(num_iterations)
                  << " per operation.\n";

        BN_free(a);
        BN_free(b);
        BN_CTX_free(ctx);
    }

    {
        ChunkyInts::ChunkyInt a;
        ChunkyInts::ChunkyInt b;

        BIGNUM* abn = BN_new();
        BIGNUM* bbn = BN_new();

        std::chrono::nanoseconds elapsed{};
        BN_CTX* ctx = BN_CTX_new();

        for (std::size_t i = 0; i < num_iterations; ++i) {
            BN_rand(a.get_bn(), 2048, 0, false);
            BN_rand(b.get_bn(), 2048, 0, false);
            BN_rand(abn, 2048, 0, false);
            BN_rand(bbn, 2048, 0, false);

            auto start = std::chrono::high_resolution_clock::now();
            sink2 = a * b;
            // a.mul(sink, b);
            // BN_mul(sink, a.get_bn(), b.get_bn(), ctx);
            auto stop = std::chrono::high_resolution_clock::now();

            elapsed += stop - start;
        }

        std::cout << "ChunkyInt operator*: "
                  << elapsed / static_cast<double>(num_iterations)
                  << " per operation.\n";

        BN_CTX_free(ctx);
    }

    return 0;
}
