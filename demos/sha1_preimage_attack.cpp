#include <bitset>
#include <cassert>
#include <iomanip>
#include <iostream>
#include <numeric>
#include <random>
#include <set>
#include <unordered_map>
#include <unordered_set>

#include "sha1.hpp"
#include "sha1_util.hpp"

using namespace amzcrypto;

int main() {
    constexpr std::size_t hash_bit_size = 10;
    constexpr std::size_t num_attacks = 1000;
    constexpr std::size_t max_string_len = 256;
    using truncdigest_t = std::bitset<hash_bit_size>;

    std::random_device rd;
    std::mt19937 rng{rd()};
    std::uniform_int_distribution<std::size_t> dist(1, max_string_len);

    // std::cout << "Performing " << num_attacks
    //           << " preimage attacks with truncated digest (" << hash_bit_size
    //           << " bits)\n";

    // Digest for string "Hello world"
    constexpr std::array<SHA1::word_t, 5> d1_full{
        0x7b502c3a, 0x1f48c860, 0x9ae212cd, 0xfb639dee, 0x39673f5e};
    constexpr truncdigest_t d1(d1_full[0]);

    // std::cout << "Using string '" << m1 << "'\n";
    // std::cout << "Full digest: ";
    // print_digest(SHA1::hash(SHA1::pad(m1)));
    // std::cout << "Truncated digest: " << d1 << '\n';

    std::cout << "bit_size num_attempts\n";

    std::multiset<std::size_t> samples;
    std::size_t total_num_hashes = 0;

    for (std::size_t i = 0; i < num_attacks; ++i) {
        std::unordered_set<std::string> used_strings;
        std::size_t num_hashes = 0;

        for (;;) {
            // Get a random string we haven't seen before
            std::string m2 = random_string(dist(rng));
            while (used_strings.contains(m2)) {
                m2 = random_string(dist(rng));
            }
            used_strings.insert(m2);

            truncdigest_t d2 = truncated_hash<hash_bit_size>(SHA1::pad(m2));

            ++num_hashes;

            if (d1 == d2) {
                break;
            }
        }

        samples.insert(num_hashes);
        total_num_hashes += num_hashes;

        // std::cout << "Found a collision after " << std::dec << num_hashes
        //           << " hashes!\n";

        std::cout << hash_bit_size << " " << num_hashes << '\n';
    }

    std::cout << '\n';

    assert(std::accumulate(samples.begin(), samples.end(), std::size_t{}) ==
           total_num_hashes);

    std::cout << "Average num hashes to find a collision: "
              << static_cast<double>(total_num_hashes) /
                     static_cast<double>(num_attacks)
              << '\n';

    std::cout << "Expected average: " << std::pow(2UL, hash_bit_size) << "\n\n";

    auto [min, lq, med, uq, max] = get_stats(samples);
    std::cout << min << ' ' << lq << ' ' << med << ' ' << uq << ' ' << max
              << '\n';

    return 0;
}
