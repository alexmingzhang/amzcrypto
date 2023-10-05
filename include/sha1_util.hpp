#ifndef AMZCRYPTO_SHA1_UTIL_HPP
#define AMZCRYPTO_SHA1_UTIL_HPP
#pragma once

#include <array>
#include <iomanip>
#include <iostream>
#include <random>
#include <set>
#include <string>
#include <tuple>

#include "sha1.hpp"

// TODO: remove this
using namespace amzcrypto;

std::string random_string(std::size_t len) {
    static std::random_device rd;
    static std::mt19937 rng{rd()};
    // static std::uniform_int_distribution<int> dist(
    //     std::numeric_limits<char>::min(), std::numeric_limits<char>::max());
    static std::uniform_int_distribution<int> dist(0x40, 0x60);

    std::string to_return;
    to_return.reserve(len);

    for (std::size_t i = 0; i < len; ++i) {
        to_return.push_back(dist(rng));
    }

    return to_return;
}

void print_digest(const std::array<SHA1::word_t, 5>& digest) {
    for (auto word : digest) {
        std::cout << std::setw(8) << std::setfill('0') << std::hex << word;
    }
    std::cout << '\n';
}

template <std::size_t N>
    requires(N <= 32)
std::bitset<N> truncated_hash(const std::string& m) {
    return std::bitset<N>(SHA1::hash(m)[0]);
}

bool is_printable(char c) { return (c >= 0x20) && (c <= 0x7e); }

void print_goofy_string(const std::string& s) {
    for (auto c : s) {
        if (is_printable(c)) {
            std::cout << c;
        } else {
            std::cout << "\\x" << std::hex << std::setw(2) << std::setfill('0')
                      << static_cast<int>(c);
        }
    }
    std::cout << '\n';
}

template <typename T>
std::array<int, 5> get_stats(const std::multiset<T>& s) {
    size_t size = s.size();

    if (size == 0) {
        throw std::invalid_argument("Set is empty.");
    }

    auto it = s.begin();

    int min = *it;

    std::advance(it, (size - 1) * 0.25);
    int lq = *it;

    it = s.begin();
    std::advance(it, (size - 1) * 0.5);
    int med = *it;

    it = s.begin();
    std::advance(it, (size - 1) * 0.75);
    int uq = *it;

    int max = *(s.rbegin());

    return {min, lq, med, uq, max};
}

#endif  // #ifndef AMZCRYPTO_SHA1_UTIL_HPP
