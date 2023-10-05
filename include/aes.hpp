/**
 * @file aes.hpp
 * @author Alex Zhang (azhang13@vols.utk.edu)
 * @brief Modern C++ Implementation of the Advanced Encryption Standard (AES)
 * @date 2023-08-30
 * @warning For educational purposes only; should not be used for any practical
 * cryptographic application.
 *
 * Implemented according to the Federal Information Processing Standards
 * Publication 197 (FIPS197). For more information on this specification,
 * see https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.197.pdf
 *
 */

// TODO: Move implementation of things here to a source file (if possible)
// TODO: use more auto??
// TODO: doxygen comments (maybe get rid of defgroups?)
// TOOD: remove byte class; just use std::byte and have a helper function for
// ffmult
// TODO: make liberal use of std::span instead of passing around references to
// arrays

#ifndef AMZCRYPTO_AES_HPP
#define AMZCRYPTO_AES_HPP
#pragma once

#include <algorithm>
#include <array>
#include <bit>
#include <cassert>
#include <compare>
#include <cstddef>
#include <cstdint>
#include <exception>
#include <iomanip>
#include <iostream>
#include <iterator>
#include <ranges>
#include <span>
#include <sstream>
#include <string>

#include "aesbyte.hpp"
#include "aeslogger.hpp"

namespace amzcrypto {

namespace AES {

/// @defgroup typedefs Type Definitions
/// @{

using word_t = std::uint32_t;
using byte_block_t = std::array<Byte, 16>;

/// @}

/// @defgroup constants Constants
/// @{

/// @brief Number of columns (32-bit words) comprising the state; fixed to 4 by
/// the FIPS197 specification
constexpr int Nb = 4;

/// @brief Size of a block in bytes (usually 16 bytes)
constexpr int block_size = 4 * Nb;

static_assert(sizeof(byte_block_t) == block_size);

// clang-format off

/// @brief Substitution values used in @ref sub_bytes()
constexpr std::array<Byte, 256> S_BOX{
    0x63, 0x7C, 0x77, 0x7B, 0xF2, 0x6B, 0x6F, 0xC5, 0x30, 0x01, 0x67, 0x2B, 0xFE, 0xD7, 0xAB, 0x76,
    0xCA, 0x82, 0xC9, 0x7D, 0xFA, 0x59, 0x47, 0xF0, 0xAD, 0xD4, 0xA2, 0xAF, 0x9C, 0xA4, 0x72, 0xC0,
    0xB7, 0xFD, 0x93, 0x26, 0x36, 0x3F, 0xF7, 0xCC, 0x34, 0xA5, 0xE5, 0xF1, 0x71, 0xD8, 0x31, 0x15,
    0x04, 0xC7, 0x23, 0xC3, 0x18, 0x96, 0x05, 0x9A, 0x07, 0x12, 0x80, 0xE2, 0xEB, 0x27, 0xB2, 0x75,
    0x09, 0x83, 0x2C, 0x1A, 0x1B, 0x6E, 0x5A, 0xA0, 0x52, 0x3B, 0xD6, 0xB3, 0x29, 0xE3, 0x2F, 0x84,
    0x53, 0xD1, 0x00, 0xED, 0x20, 0xFC, 0xB1, 0x5B, 0x6A, 0xCB, 0xBE, 0x39, 0x4A, 0x4C, 0x58, 0xCF,
    0xD0, 0xEF, 0xAA, 0xFB, 0x43, 0x4D, 0x33, 0x85, 0x45, 0xF9, 0x02, 0x7F, 0x50, 0x3C, 0x9F, 0xA8,
    0x51, 0xA3, 0x40, 0x8F, 0x92, 0x9D, 0x38, 0xF5, 0xBC, 0xB6, 0xDA, 0x21, 0x10, 0xFF, 0xF3, 0xD2,
    0xCD, 0x0C, 0x13, 0xEC, 0x5F, 0x97, 0x44, 0x17, 0xC4, 0xA7, 0x7E, 0x3D, 0x64, 0x5D, 0x19, 0x73,
    0x60, 0x81, 0x4F, 0xDC, 0x22, 0x2A, 0x90, 0x88, 0x46, 0xEE, 0xB8, 0x14, 0xDE, 0x5E, 0x0B, 0xDB,
    0xE0, 0x32, 0x3A, 0x0A, 0x49, 0x06, 0x24, 0x5C, 0xC2, 0xD3, 0xAC, 0x62, 0x91, 0x95, 0xE4, 0x79,
    0xE7, 0xC8, 0x37, 0x6D, 0x8D, 0xD5, 0x4E, 0xA9, 0x6C, 0x56, 0xF4, 0xEA, 0x65, 0x7A, 0xAE, 0x08,
    0xBA, 0x78, 0x25, 0x2E, 0x1C, 0xA6, 0xB4, 0xC6, 0xE8, 0xDD, 0x74, 0x1F, 0x4B, 0xBD, 0x8B, 0x8A,
    0x70, 0x3E, 0xB5, 0x66, 0x48, 0x03, 0xF6, 0x0E, 0x61, 0x35, 0x57, 0xB9, 0x86, 0xC1, 0x1D, 0x9E,
    0xE1, 0xF8, 0x98, 0x11, 0x69, 0xD9, 0x8E, 0x94, 0x9B, 0x1E, 0x87, 0xE9, 0xCE, 0x55, 0x28, 0xDF,
    0x8C, 0xA1, 0x89, 0x0D, 0xBF, 0xE6, 0x42, 0x68, 0x41, 0x99, 0x2D, 0x0F, 0xB0, 0x54, 0xBB, 0x16
};

/// @brief Substitution values used in @ref inv_sub_bytes()
constexpr std::array<Byte, 256> IS_BOX{
    0x52, 0x09, 0x6A, 0xD5, 0x30, 0x36, 0xA5, 0x38, 0xBF, 0x40, 0xA3, 0x9E, 0x81, 0xF3, 0xD7, 0xFB,
    0x7C, 0xE3, 0x39, 0x82, 0x9B, 0x2F, 0xFF, 0x87, 0x34, 0x8E, 0x43, 0x44, 0xC4, 0xDE, 0xE9, 0xCB,
    0x54, 0x7B, 0x94, 0x32, 0xA6, 0xC2, 0x23, 0x3D, 0xEE, 0x4C, 0x95, 0x0B, 0x42, 0xFA, 0xC3, 0x4E,
    0x08, 0x2E, 0xA1, 0x66, 0x28, 0xD9, 0x24, 0xB2, 0x76, 0x5B, 0xA2, 0x49, 0x6D, 0x8B, 0xD1, 0x25,
    0x72, 0xF8, 0xF6, 0x64, 0x86, 0x68, 0x98, 0x16, 0xD4, 0xA4, 0x5C, 0xCC, 0x5D, 0x65, 0xB6, 0x92,
    0x6C, 0x70, 0x48, 0x50, 0xFD, 0xED, 0xB9, 0xDA, 0x5E, 0x15, 0x46, 0x57, 0xA7, 0x8D, 0x9D, 0x84,
    0x90, 0xD8, 0xAB, 0x00, 0x8C, 0xBC, 0xD3, 0x0A, 0xF7, 0xE4, 0x58, 0x05, 0xB8, 0xB3, 0x45, 0x06,
    0xD0, 0x2C, 0x1E, 0x8F, 0xCA, 0x3F, 0x0F, 0x02, 0xC1, 0xAF, 0xBD, 0x03, 0x01, 0x13, 0x8A, 0x6B,
    0x3A, 0x91, 0x11, 0x41, 0x4F, 0x67, 0xDC, 0xEA, 0x97, 0xF2, 0xCF, 0xCE, 0xF0, 0xB4, 0xE6, 0x73,
    0x96, 0xAC, 0x74, 0x22, 0xE7, 0xAD, 0x35, 0x85, 0xE2, 0xF9, 0x37, 0xE8, 0x1C, 0x75, 0xDF, 0x6E,
    0x47, 0xF1, 0x1A, 0x71, 0x1D, 0x29, 0xC5, 0x89, 0x6F, 0xB7, 0x62, 0x0E, 0xAA, 0x18, 0xBE, 0x1B,
    0xFC, 0x56, 0x3E, 0x4B, 0xC6, 0xD2, 0x79, 0x20, 0x9A, 0xDB, 0xC0, 0xFE, 0x78, 0xCD, 0x5A, 0xF4,
    0x1F, 0xDD, 0xA8, 0x33, 0x88, 0x07, 0xC7, 0x31, 0xB1, 0x12, 0x10, 0x59, 0x27, 0x80, 0xEC, 0x5F,
    0x60, 0x51, 0x7F, 0xA9, 0x19, 0xB5, 0x4A, 0x0D, 0x2D, 0xE5, 0x7A, 0x9F, 0x93, 0xC9, 0x9C, 0xEF,
    0xA0, 0xE0, 0x3B, 0x4D, 0xAE, 0x2A, 0xF5, 0xB0, 0xC8, 0xEB, 0xBB, 0x3C, 0x83, 0x53, 0x99, 0x61,
    0x17, 0x2B, 0x04, 0x7E, 0xBA, 0x77, 0xD6, 0x26, 0xE1, 0x69, 0x14, 0x63, 0x55, 0x21, 0x0C, 0x7D
};

// clang-format on

/// @brief The round constant word array
constexpr std::array<word_t, 11> Rcon{0x00, 0x01, 0x02, 0x04, 0x08, 0x10,
                                      0x20, 0x40, 0x80, 0x1b, 0x36};

/// @}

/// @defgroup helper_functions Helper Functions
/// @{

[[nodiscard]] std::string bytes_to_string(std::span<const Byte> bytes) {
    std::ostringstream to_return;
    to_return << std::hex;
    for (auto b : bytes) {
        to_return << std::setw(2) << std::setfill('0')
                  << static_cast<int>(b.get_value());
    }

    return to_return.str();
}

[[nodiscard]] constexpr std::array<Byte, 4> word_to_bytes(word_t word) {
    if constexpr (std::endian::native == std::endian::little) {
        return {(word & 0xFF000000) >> 24, (word & 0x00FF0000) >> 16,
                (word & 0x0000FF00) >> 8, (word & 0x000000FF) >> 0};
    } else {
        // return {(word & 0xFF000000) >> 0, (word & 0x00FF0000) >> 8,
        //         (word & 0x0000FF00) >> 16, (word & 0x000000FF) >> 24};
        throw std::runtime_error("No support for big-endian machines.");
    }
}

[[nodiscard]] constexpr word_t bytes_to_word(std::span<const Byte, 4> bytes) {
    if constexpr (std::endian::native == std::endian::little) {
        return (static_cast<word_t>(bytes[0].get_value()) << 0) |
               (static_cast<word_t>(bytes[1].get_value()) << 8) |
               (static_cast<word_t>(bytes[2].get_value()) << 16) |
               (static_cast<word_t>(bytes[3].get_value()) << 24);
    } else {
        // return (static_cast<word_t>(bytes[0].get_value()) << 24) |
        //        (static_cast<word_t>(bytes[1].get_value()) << 16) |
        //        (static_cast<word_t>(bytes[2].get_value()) << 8) |
        //        (static_cast<word_t>(bytes[3].get_value()) << 0);
        throw std::runtime_error("No support for big-endian machines.");
    }
}

// Make sure this shit works cuz little endian!!!!!!!!!!!!!!!!!!!!!!!!
constexpr std::array<Byte, 4> __test = {0x1a, 0x2b, 0x3c, 0x4d};
static_assert(bytes_to_word(__test) == 0x4d3c2b1a);
static_assert(word_to_bytes(0x1a2b3c4d) == __test);

[[nodiscard]] constexpr word_t get_word(std::span<const Byte> data,
                                        std::size_t index) {
    if constexpr (std::endian::native == std::endian::little) {
        return (static_cast<word_t>(data[index].get_value())) |
               (static_cast<word_t>(data[index + 1].get_value()) << 8) |
               (static_cast<word_t>(data[index + 2].get_value()) << 16) |
               (static_cast<word_t>(data[index + 3].get_value()) << 24);
    } else {
        throw std::runtime_error("No support for big-endian machines.");
    }
}

constexpr void set_word(std::span<Byte> data, std::size_t index, word_t word) {
    if constexpr (std::endian::native == std::endian::little) {
        data[index + 3] = static_cast<Byte>((word >> 24) & 0xFF);
        data[index + 2] = static_cast<Byte>((word >> 16) & 0xFF);
        data[index + 1] = static_cast<Byte>((word >> 8) & 0xFF);
        data[index] = static_cast<Byte>(word & 0xFF);
    } else {
        throw std::runtime_error("No support for big-endian machines.");
    }
}

/**
 * @brief Function used in the Key Expansion routine that takes a four-byte
 * input word and applies an S-box to each of the four bytes to produce an
 * output word.
 * @param word A 32-bit word
 */
[[nodiscard]] constexpr word_t sub_word(word_t word) {
    auto bytes = std::bit_cast<std::array<Byte, sizeof(word)>>(word);
    std::ranges::transform(bytes, bytes.begin(),
                           [](Byte b) { return S_BOX[b.get_value()]; });
    return std::bit_cast<word_t>(bytes);
}

/**
 * @brief Function used in the Key Expansion routine that takes a four-byte
 * word and performs a cyclic permutation.
 * @param word A 32-bit word
 */
[[nodiscard]] constexpr word_t rot_word(word_t word) {
    return std::rotr(word, 8);
}

// TODO: comments for index state helpers
[[nodiscard]] constexpr Byte& index_state(byte_block_t& block, std::size_t i,
                                          std::size_t j) {
    return block[i + j * Nb];
}

[[nodiscard]] constexpr const Byte& index_state(const byte_block_t& block,
                                                std::size_t i, std::size_t j) {
    return block[i + j * Nb];
}

[[nodiscard]] constexpr Byte& index_state(std::span<Byte, block_size> block,
                                          std::size_t i, std::size_t j) {
    return block[i + j * Nb];
}

[[nodiscard]] constexpr const Byte& index_state(
    std::span<const Byte, block_size> block, std::size_t i, std::size_t j) {
    return block[i + j * Nb];
}

constexpr void add_round_key(std::span<Byte, block_size> state,
                             std::span<const Byte, block_size> round_key) {
    std::ranges::transform(state, round_key, state.begin(), std::plus<>());
}

constexpr void mix_columns(std::span<Byte, block_size> state) {
    byte_block_t copy;
    std::ranges::copy(state, copy.begin());

    for (std::size_t c = 0; c < static_cast<std::size_t>(Nb); ++c) {
        index_state(state, 0, c) = index_state(copy, 0, c) * Byte{0x02} +
                                   index_state(copy, 1, c) * Byte{0x03} +
                                   index_state(copy, 2, c) +
                                   index_state(copy, 3, c);

        index_state(state, 1, c) =
            index_state(copy, 0, c) + index_state(copy, 1, c) * Byte{0x02} +
            index_state(copy, 2, c) * Byte{0x03} + index_state(copy, 3, c);

        index_state(state, 2, c) = index_state(copy, 0, c) +
                                   index_state(copy, 1, c) +
                                   index_state(copy, 2, c) * Byte{0x02} +
                                   index_state(copy, 3, c) * Byte{0x03};

        index_state(state, 3, c) =
            index_state(copy, 0, c) * Byte{0x03} + index_state(copy, 1, c) +
            index_state(copy, 2, c) + index_state(copy, 3, c) * Byte{0x02};
    }
}

constexpr void shift_rows(std::span<Byte, block_size> state) {
    {  // Shift second row
        Byte this_1_0 = index_state(state, 1, 0);
        index_state(state, 1, 0) = index_state(state, 1, 1);
        index_state(state, 1, 1) = index_state(state, 1, 2);
        index_state(state, 1, 2) = index_state(state, 1, 3);
        index_state(state, 1, 3) = this_1_0;
    }

    {  // Shift third row
        Byte this_2_0 = index_state(state, 2, 0);
        Byte this_2_1 = index_state(state, 2, 1);
        index_state(state, 2, 0) = index_state(state, 2, 2);
        index_state(state, 2, 1) = index_state(state, 2, 3);
        index_state(state, 2, 2) = this_2_0;
        index_state(state, 2, 3) = this_2_1;
    }

    {  // Shift fourth row
        Byte this_3_3 = index_state(state, 3, 3);
        index_state(state, 3, 3) = index_state(state, 3, 2);
        index_state(state, 3, 2) = index_state(state, 3, 1);
        index_state(state, 3, 1) = index_state(state, 3, 0);
        index_state(state, 3, 0) = this_3_3;
    }
}

constexpr void sub_bytes(std::span<Byte, block_size> state) {
    std::ranges::transform(state, state.begin(),
                           [](Byte b) { return S_BOX[b.get_value()]; });
}

constexpr void inv_mix_columns(std::span<Byte, block_size> state) {
    byte_block_t copy;
    std::ranges::copy(state, copy.begin());

    for (std::size_t c = 0; c < static_cast<std::size_t>(Nb); ++c) {
        index_state(state, 0, c) = (Byte{0x0e} * index_state(copy, 0, c)) +
                                   (Byte{0x0b} * index_state(copy, 1, c)) +
                                   (Byte{0x0d} * index_state(copy, 2, c)) +
                                   (Byte{0x09} * index_state(copy, 3, c));
        index_state(state, 1, c) = (Byte{0x09} * index_state(copy, 0, c)) +
                                   (Byte{0x0e} * index_state(copy, 1, c)) +
                                   (Byte{0x0b} * index_state(copy, 2, c)) +
                                   (Byte{0x0d} * index_state(copy, 3, c));
        index_state(state, 2, c) = (Byte{0x0d} * index_state(copy, 0, c)) +
                                   (Byte{0x09} * index_state(copy, 1, c)) +
                                   (Byte{0x0e} * index_state(copy, 2, c)) +
                                   (Byte{0x0b} * index_state(copy, 3, c));
        index_state(state, 3, c) = (Byte{0x0b} * index_state(copy, 0, c)) +
                                   (Byte{0x0d} * index_state(copy, 1, c)) +
                                   (Byte{0x09} * index_state(copy, 2, c)) +
                                   (Byte{0x0e} * index_state(copy, 3, c));
    }
}

constexpr void inv_shift_rows(std::span<Byte, block_size> state) {
    {  // Shift second row
        Byte this_1_3 = index_state(state, 1, 3);
        index_state(state, 1, 3) = index_state(state, 1, 2);
        index_state(state, 1, 2) = index_state(state, 1, 1);
        index_state(state, 1, 1) = index_state(state, 1, 0);
        index_state(state, 1, 0) = this_1_3;
    }

    {  // Shift third row
        Byte this_2_2 = index_state(state, 2, 2);
        Byte this_2_3 = index_state(state, 2, 3);
        index_state(state, 2, 2) = index_state(state, 2, 0);
        index_state(state, 2, 3) = index_state(state, 2, 1);
        index_state(state, 2, 0) = this_2_2;
        index_state(state, 2, 1) = this_2_3;
    }

    {  // Shift fourth row
        Byte this_3_0 = index_state(state, 3, 0);
        index_state(state, 3, 0) = index_state(state, 3, 1);
        index_state(state, 3, 1) = index_state(state, 3, 2);
        index_state(state, 3, 2) = index_state(state, 3, 3);
        index_state(state, 3, 3) = this_3_0;
    }
}

constexpr void inv_sub_bytes(std::span<Byte, block_size> state) {
    std::ranges::transform(state, state.begin(),
                           [](Byte b) { return IS_BOX[b.get_value()]; });
}

/// @}

/**
 * @brief Instantiation of AES that performs encryption and decryption
 * @tparam Nk Number of 32-bit words that comprise the cipher key
 */
template <int Nk>
    requires(Nk == 4 || Nk == 6 || Nk == 8)
class Engine {
public:
    /// @brief Number of rounds used in cipher (formula based on the
    /// original Rijndael proposal)
    static constexpr int Nr = std::max(Nb, Nk) + 6;

    /// @brief Size of the cipher key in bytes
    static constexpr std::size_t cipher_key_size = 4 * Nk;

    /// @brief Size of the key schedule in 32-bit wods
    static constexpr std::size_t key_schedule_size_words = Nb * (Nr + 1);

    /// @brief Size of the key schedule in bytes
    static constexpr std::size_t key_schedule_size_bytes =
        4 * key_schedule_size_words;

    using cipher_key_t = std::array<Byte, cipher_key_size>;

    constexpr Engine() = default;
    constexpr Engine(const cipher_key_t& key) : cipher_key(key) {
        populate_key_schedule();
    }
    constexpr Engine(cipher_key_t&& key) : cipher_key(std::move(key)) {
        populate_key_schedule();
    }
    constexpr ~Engine() = default;
    constexpr Engine<Nk>& operator=(const Engine<Nk>&) = default;
    constexpr Engine<Nk>& operator=(Engine<Nk>&&) = default;
    constexpr bool operator==(const Engine<Nk>&) const = default;

    constexpr void set_cipher_key(const cipher_key_t& key) {
        cipher_key = key;
        populate_key_schedule();
    }

    constexpr void set_cipher_key(cipher_key_t&& key) {
        cipher_key = std::move(key);
        populate_key_schedule();
    }

    [[nodiscard]] constexpr const cipher_key_t& get_cipher_key()
        const noexcept {
        return cipher_key;
    }

    [[nodiscard]] constexpr std::span<const Byte, block_size> get_round_key(
        std::size_t round) const {
        return std::span<const Byte, block_size>(
            key_schedule_bytes.cbegin() + round * block_size, block_size);
    }

    [[nodiscard]] constexpr std::span<const Byte, block_size>
    get_eqinv_round_key(std::size_t round) const {
        return std::span<const Byte, block_size>(
            eqinv_key_schedule_bytes.cbegin() + round * block_size, block_size);
    }

    /**
     * @brief Generates a key schedule from a cipher key
     *
     * Analogous to KeyExpansion() in the AES specification.
     */
    constexpr void populate_key_schedule() {
        std::ranges::copy(cipher_key, key_schedule_bytes.begin());

        for (std::size_t i = Nk; i < key_schedule_size_words; ++i) {
            word_t temp = get_word(key_schedule_bytes, 4 * (i - 1));

            if (i % Nk == 0) {
                temp = rot_word(temp);
                temp = sub_word(temp);
                temp ^= Rcon[i / Nk];
            } else if (Nk > 6 && i % Nk == 4) {
                temp = sub_word(temp);
            }

            word_t previous_word = get_word(key_schedule_bytes, 4 * (i - Nk));
            word_t new_word = previous_word ^ temp;
            set_word(key_schedule_bytes, 4 * i, new_word);
        }

        // Generate equivalent inverse cipher key schedule
        std::ranges::copy(key_schedule_bytes, eqinv_key_schedule_bytes.begin());

        for (std::size_t i = block_size;
             i < key_schedule_size_bytes - block_size; i += block_size) {
            inv_mix_columns(std::span<Byte, block_size>(
                eqinv_key_schedule_bytes.begin() + i, block_size));
        }
    }

    /**
     * @brief Encrypts a 16-byte block of plaintext
     * @param plaintext 16-byte block to encrypt
     * @return A 16-byte block of ciphertext
     */
    [[nodiscard]] constexpr byte_block_t cipher(
        std::span<const Byte, block_size> plaintext) const {
        byte_block_t ciphertext;
        std::ranges::copy(plaintext, ciphertext.begin());
        std::size_t round = 0;

#ifdef AES_DEBUG
        static auto round_str = [&]() {
            std::ostringstream round_oss;
            round_oss << "round[" << std::setw(2) << round << "].";
            return round_oss.str();
        };
#endif
        DEBUG_LOG(round_str(), "input     ", bytes_to_string(ciphertext));

        add_round_key(ciphertext, get_round_key(round));
        DEBUG_LOG(round_str(), "k_sch     ",
                  bytes_to_string(get_round_key(round)));

        for (round = 1; round < Nr; ++round) {
            DEBUG_LOG(round_str(), "start     ", bytes_to_string(ciphertext));

            sub_bytes(ciphertext);
            DEBUG_LOG(round_str(), "s_box     ", bytes_to_string(ciphertext));

            shift_rows(ciphertext);
            DEBUG_LOG(round_str(), "s_row     ", bytes_to_string(ciphertext));

            mix_columns(ciphertext);
            DEBUG_LOG(round_str(), "m_col     ", bytes_to_string(ciphertext));

            add_round_key(ciphertext, get_round_key(round));
            DEBUG_LOG(round_str(), "k_sch     ",
                      bytes_to_string(get_round_key(round)));
        }

        assert(round == Nr);
        DEBUG_LOG(round_str(), "start     ", bytes_to_string(ciphertext));

        sub_bytes(ciphertext);
        DEBUG_LOG(round_str(), "s_box     ", bytes_to_string(ciphertext));

        shift_rows(ciphertext);
        DEBUG_LOG(round_str(), "s_row     ", bytes_to_string(ciphertext));

        add_round_key(ciphertext, get_round_key(round));
        DEBUG_LOG(round_str(), "k_sch     ",
                  bytes_to_string(get_round_key(round)));

        DEBUG_LOG(round_str(), "output    ", bytes_to_string(ciphertext));
        return ciphertext;
    }

    [[nodiscard]] constexpr byte_block_t invcipher(
        std::span<const Byte, block_size> ciphertext) const {
        byte_block_t plaintext;
        std::ranges::copy(ciphertext, plaintext.begin());
        std::size_t round = Nr;

#ifdef AES_DEBUG
        static auto round_str = [&]() {
            std::ostringstream round_oss;
            round_oss << "round[" << std::setw(2) << Nr - round << "].";
            return round_oss.str();
        };
#endif
        DEBUG_LOG(round_str(), "iinput    ", bytes_to_string(plaintext));

        add_round_key(plaintext, get_round_key(round));
        DEBUG_LOG(round_str(), "ik_sch    ",
                  bytes_to_string(get_round_key(round)));

        for (round = Nr - 1; round > 0; --round) {
            DEBUG_LOG(round_str(), "istart    ", bytes_to_string(plaintext));

            inv_shift_rows(plaintext);
            DEBUG_LOG(round_str(), "is_row    ", bytes_to_string(plaintext));

            inv_sub_bytes(plaintext);
            DEBUG_LOG(round_str(), "is_box    ", bytes_to_string(plaintext));

            add_round_key(plaintext, get_round_key(round));
            DEBUG_LOG(round_str(), "ik_sch    ",
                      bytes_to_string(get_round_key(round)));
            DEBUG_LOG(round_str(), "ik_add    ", bytes_to_string(plaintext));

            inv_mix_columns(plaintext);
        }

        assert(round == 0);
        DEBUG_LOG(round_str(), "istart    ", bytes_to_string(plaintext));

        inv_shift_rows(plaintext);
        DEBUG_LOG(round_str(), "is_row    ", bytes_to_string(plaintext));

        inv_sub_bytes(plaintext);
        DEBUG_LOG(round_str(), "is_box    ", bytes_to_string(plaintext));

        add_round_key(plaintext, get_round_key(round));
        DEBUG_LOG(round_str(), "ik_sch    ",
                  bytes_to_string(get_round_key(round)));

        DEBUG_LOG(round_str(), "ioutput   ", bytes_to_string(plaintext));
        return plaintext;
    }

    [[nodiscard]] constexpr byte_block_t eqinvcipher(
        std::span<const Byte, block_size> ciphertext) const {
        byte_block_t plaintext;
        std::ranges::copy(ciphertext, plaintext.begin());
        std::size_t round = Nr;

#ifdef AES_DEBUG
        static auto round_str = [&]() {
            std::ostringstream round_oss;
            round_oss << "round[" << std::setw(2) << Nr - round << "].";
            return round_oss.str();
        };
#endif
        DEBUG_LOG(round_str(), "iinput    ", bytes_to_string(plaintext));

        add_round_key(plaintext, get_eqinv_round_key(round));
        DEBUG_LOG(round_str(), "ik_sch    ",
                  bytes_to_string(get_eqinv_round_key(round)));

        for (round = Nr - 1; round > 0; --round) {
            DEBUG_LOG(round_str(), "istart    ", bytes_to_string(plaintext));

            inv_sub_bytes(plaintext);
            DEBUG_LOG(round_str(), "is_box    ", bytes_to_string(plaintext));

            inv_shift_rows(plaintext);
            DEBUG_LOG(round_str(), "is_row    ", bytes_to_string(plaintext));

            inv_mix_columns(plaintext);
            DEBUG_LOG(round_str(), "im_col    ", bytes_to_string(plaintext));

            add_round_key(plaintext, get_eqinv_round_key(round));
            DEBUG_LOG(round_str(), "ik_sch    ",
                      bytes_to_string(get_eqinv_round_key(round)));
        }

        assert(round == 0);
        DEBUG_LOG(round_str(), "istart    ", bytes_to_string(plaintext));

        inv_sub_bytes(plaintext);
        DEBUG_LOG(round_str(), "is_box    ", bytes_to_string(plaintext));

        inv_shift_rows(plaintext);
        DEBUG_LOG(round_str(), "is_row    ", bytes_to_string(plaintext));

        add_round_key(plaintext, get_eqinv_round_key(round));
        DEBUG_LOG(round_str(), "ik_sch    ",
                  bytes_to_string(get_eqinv_round_key(round)));

        DEBUG_LOG(round_str(), "ioutput   ", bytes_to_string(plaintext));
        return plaintext;
    }

private:
    /// @brief Raw bytes of the user-provided cipher key
    cipher_key_t cipher_key;

    std::array<Byte, key_schedule_size_bytes> key_schedule_bytes;
    std::array<Byte, key_schedule_size_bytes> eqinv_key_schedule_bytes;
};

}  // namespace AES

}  // namespace amzcrypto

#endif  // #ifndef AMZCRYPTO_AES_HPP
