/**
 * @file sha1.hpp
 * @author Alex Zhang (azhang13@vols.utk.edu)
 * @brief SHA-1 Implementation for Modern C++
 * @date 2023-09-16
 *
 */

#ifndef AMZCRYPTO_SHA1_HPP
#define AMZCRYPTO_SHA1_HPP
#pragma once

#include <array>
#include <bit>
#include <bitset>
#include <cassert>
#include <cstdint>
#include <iomanip>
#include <iostream>
#include <limits>
#include <span>
#include <stdexcept>
#include <vector>

namespace amzcrypto {

namespace SHA1 {

using word_t = std::uint32_t;
using digest_t = std::array<word_t, 5>;

constexpr std::array<word_t, 5> H0 = {0x67452301, 0xefcdab89, 0x98badcfe,
                                      0x10325476, 0xc3d2e1f0};

constexpr word_t K0_19 = 0x5a827999;
constexpr word_t K20_39 = 0x6ed9eba1;
constexpr word_t K40_59 = 0x8f1bbcdc;
constexpr word_t K60_79 = 0xca62c1d6;

constexpr std::size_t block_size_words = 16;
constexpr std::size_t block_size_bytes = block_size_words * 4;
constexpr std::size_t block_size_bits = block_size_words * 32;

static_assert(block_size_bits == 512);

[[nodiscard]] constexpr word_t Ch(word_t x, word_t y, word_t z) noexcept {
    return (x & y) ^ (~x & z);
}

[[nodiscard]] constexpr word_t Parity(word_t x, word_t y, word_t z) noexcept {
    return x ^ y ^ z;
}

[[nodiscard]] constexpr word_t Maj(word_t x, word_t y, word_t z) noexcept {
    return (x & y) ^ (x & z) ^ (y & z);
}

[[nodiscard]] constexpr word_t f(int t, word_t x, word_t y, word_t z) {
    if (0 <= t && t <= 19) {
        return Ch(x, y, z);
    } else if (t <= 39) {
        return Parity(x, y, z);
    } else if (t <= 59) {
        return Maj(x, y, z);
    } else if (t <= 79) {
        return Parity(x, y, z);
    } else [[unlikely]] {
        throw std::invalid_argument("t must be between 0 and 79 (inclusive)");
    }
}

/**
 * @brief Constant value to be used for the iteration t of the hash computation
 *
 * @param t Iteration number
 * @return Constant value to be used for the iteration t of the hash computation
 */
[[nodiscard]] constexpr word_t K(int t) {
    if (0 <= t && t <= 19) {
        return K0_19;
    } else if (t <= 39) {
        return K20_39;
    } else if (t <= 59) {
        return K40_59;
    } else if (t <= 79) {
        return K60_79;
    } else [[unlikely]] {
        throw std::invalid_argument("t must be between 0 and 79 (inclusive)");
    }
}

/**
 * @brief Gets the padding given the length of the message to be padded.
 *
 * @param len Length of the message to be padded.
 * @return std::string of the padding.
 */
constexpr std::string get_padding(std::size_t len) {
    const std::size_t last_block_size = (len + 1) % block_size_bytes;
    const std::size_t padding_size =
        (last_block_size + sizeof(std::uint64_t) > block_size_bytes)
            ? ((block_size_bytes * 2) - last_block_size + 1)
            : (block_size_bytes - last_block_size + 1);

    std::string padding;
    padding.reserve(padding_size);
    padding.push_back('\x80');
    padding.resize(padding_size - sizeof(std::uint64_t), '\0');

    const std::size_t len_bits = len * 8;
    for (int i = sizeof(std::uint64_t) - 1; i >= 0; --i) {
        char c = (len_bits >> (i * 8)) & 0xFF;
        padding.push_back(c);
    }

    return padding;
}

/**
 * @brief Pads a message according to the SHA-1 specification.
 *
 * @param message A mutable reference to the message.
 * @return A reference to the message which has been padded in-place.
 */
constexpr std::string &pad_in_place(std::string &message) {
    // Make sure we can fit the length of the message into 64 bits
    if constexpr (sizeof(std::size_t) < sizeof(std::uint64_t)) {
        assert(message.size() * 8 <= std::numeric_limits<std::uint64_t>::max());
    }

    const std::uint64_t message_bits = message.size() * 8;

    const std::size_t last_block_size = (message.size() + 1) % block_size_bytes;
    const std::size_t padded_message_size =
        (last_block_size + sizeof(std::uint64_t) > block_size_bytes)
            ? ((message.size() + 1) + (block_size_bytes * 2) - last_block_size)
            : ((message.size() + 1) + block_size_bytes - last_block_size);

    message.reserve(padded_message_size);
    message.push_back('\x80');
    message.resize(padded_message_size - sizeof(std::uint64_t), '\0');

    // Add on the length of the original message in big endian
    for (int i = sizeof(std::uint64_t) - 1; i >= 0; --i) {
        char c = (message_bits >> (i * 8)) & 0xFF;
        message.push_back(c);
    }

    return message;
}

/**
 * @brief Returns the padded version of a message according to the SHA-1
 * specification
 *
 * @param message The message to pad
 * @return A copy of the message which has been padded
 */
constexpr std::string pad(std::string message) { return pad_in_place(message); }

/**
 * @brief Creates a message schedule from a given message and round i.
 *
 * @param M String to use.
 * @param i Round number.
 * @return Message schedule as a std::array<word_t, 80>
 */
[[nodiscard]] constexpr std::array<word_t, 80> create_message_schedule(
    std::string_view M, std::size_t i) {
    std::array<word_t, 80> W;
    const std::size_t offset = i * 64;

    for (std::size_t t = 0; t <= 15; ++t) {
        const std::size_t ind = t * 4 + offset;
        W[t] = ((static_cast<word_t>(M[ind + 0]) << 24) & 0xFF000000) |
               ((static_cast<word_t>(M[ind + 1]) << 16) & 0x00FF0000) |
               ((static_cast<word_t>(M[ind + 2]) << 8) & 0x0000FF00) |
               ((static_cast<word_t>(M[ind + 3]) << 0) & 0x000000FF);
    }

    for (std::size_t t = 16; t <= 79; ++t) {
        W[t] = std::rotl(W[t - 3] ^ W[t - 8] ^ W[t - 14] ^ W[t - 16], 1);
    }

    return W;
}

void print_digest(std::span<const word_t, 5> d) {
    for (word_t w : d) {
        std::cout << std::hex << std::setw(8) << std::setfill('0') << w;
    }
    std::cout << '\n';
}

/**
 * @brief Hashes a padded string using SHA-1.
 *
 * @param M std::string to be hashed.
 * @param IV The initialization vector (default is the hardcoded H0).
 * @param first_block The first block to start computation (default is 0, i.e.
 * first block).
 * @return SHA-1 digest as a std::array<word_t, 5>.
 */
[[nodiscard]] constexpr std::array<word_t, 5> hash(
    std::string_view M, const std::array<word_t, 5> &IV = H0,
    std::size_t first_block = 0) {
    // TODO: IV should be span?
    if (M.size() % 64 != 0) [[unlikely]] {
        throw std::invalid_argument(
            "Message must be padded to a multiple of 64 bytes (512 bits)!");
    }

    const std::size_t N = M.size() / block_size_bytes;
    std::array<word_t, 5> curr_H = IV;

    for (std::size_t i = first_block; i < N; ++i) {
        std::array<word_t, 80> W = create_message_schedule(M, i);

        auto [a, b, c, d, e] = curr_H;

        for (std::size_t t = 0; t <= 19; ++t) {
            word_t T = std::rotl(a, 5) + Ch(b, c, d) + e + K0_19 + W[t];
            e = d;
            d = c;
            c = std::rotl(b, 30);
            b = a;
            a = T;
        }

        for (std::size_t t = 20; t <= 39; ++t) {
            word_t T = std::rotl(a, 5) + Parity(b, c, d) + e + K20_39 + W[t];
            e = d;
            d = c;
            c = std::rotl(b, 30);
            b = a;
            a = T;
        }

        for (std::size_t t = 40; t <= 59; ++t) {
            word_t T = std::rotl(a, 5) + Maj(b, c, d) + e + K40_59 + W[t];
            e = d;
            d = c;
            c = std::rotl(b, 30);
            b = a;
            a = T;
        }

        for (std::size_t t = 60; t <= 79; ++t) {
            word_t T = std::rotl(a, 5) + Parity(b, c, d) + e + K60_79 + W[t];
            e = d;
            d = c;
            c = std::rotl(b, 30);
            b = a;
            a = T;
        }

        curr_H[0] += a;
        curr_H[1] += b;
        curr_H[2] += c;
        curr_H[3] += d;
        curr_H[4] += e;
    }

    return curr_H;
}

}  // namespace SHA1

}  // namespace amzcrypto

#endif  // #ifndef AMZCRYPTO_SHA1_HPP
