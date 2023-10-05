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
    constexpr std::size_t hash_bit_size = 22;
    constexpr std::size_t num_attacks = 1000;
    constexpr std::size_t max_string_len = 256;
    using truncdigest_t = std::bitset<hash_bit_size>;

    std::random_device rd;
    std::mt19937 rng{rd()};
    std::uniform_int_distribution<std::size_t> dist(1, max_string_len);

    // std::cout << "Performing " << num_attacks
    //           << " collision attacks with truncated digest ("
    //           << hash_bit_size << " bits)\n";

    std::cout << "bit_size num_attempts\n";

    std::multiset<std::size_t> samples;
    std::size_t total_num_hashes = 0;

    for (std::size_t i = 0; i < num_attacks; ++i) {
        std::unordered_map<truncdigest_t, std::string> digests;
        std::unordered_set<std::string> used_strings;
        std::size_t num_hashes = 0;

        for (;;) {
            // Get a random string we haven't seen before
            std::string input = random_string(dist(rng));
            while (used_strings.contains(input)) {
                input = random_string(dist(rng));
            }
            used_strings.insert(input);

            truncdigest_t digest =
                truncated_hash<hash_bit_size>(SHA1::pad(input));

            ++num_hashes;

            if (digests.contains(digest)) {
                break;
            } else {
                digests[digest] = input;
            }
        }

        samples.insert(num_hashes);
        total_num_hashes += num_hashes;

        std::cout << hash_bit_size << ' ' << num_hashes << '\n';
    }

    std::cout << '\n';

    assert(std::accumulate(samples.begin(), samples.end(), std::size_t{}) ==
           total_num_hashes);

    std::cout << "Average num hashes to find a collision: "
              << static_cast<double>(total_num_hashes) /
                     static_cast<double>(num_attacks)
              << '\n';

    std::cout << "Expected average: " << std::pow(2UL, hash_bit_size / 2)
              << "\n\n";

    auto [min, lq, med, uq, max] = get_stats(samples);
    std::cout << min << ' ' << lq << ' ' << med << ' ' << uq << ' ' << max
              << '\n';

    return 0;
}
