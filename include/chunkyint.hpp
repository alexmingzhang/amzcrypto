/**
 * @file chunkyint.hpp
 * @author Alex Zhang (azhang13@vols.utk.edu)
 * @brief A modern C++ wrapper of the OpenSSL big number library.
 * @date 2023-10-02
 *
 * ChunkyInt provides modern C++ niceities for OpenSSL's big number library,
 * such as memory management via RAII, improved syntax using overloaded
 * operators, and automatic management of BIGNUM contexts.
 *
 */

#ifndef AMZCRYPTO_CHUNKYINT_HPP
#define AMZCRYPTO_CHUNKYINT_HPP
#pragma once

#include <openssl/bn.h>
#include <openssl/err.h>

#include <ostream>

namespace amzcrypto {

namespace ChunkyInts {

class ChunkyInt {
public:
    // TODO: some of these should definitely be explicit constructors
    ChunkyInt() noexcept : bn(BN_new()) {}
    ChunkyInt(BIGNUM* bn) noexcept : bn(bn) {}
    ChunkyInt(unsigned long w) : bn(BN_new()) { BN_set_word(bn, w); }
    ChunkyInt(const char*);
    ChunkyInt(std::string_view);
    ~ChunkyInt() noexcept { BN_clear_free(bn); }
    ChunkyInt(const ChunkyInt& other) : bn(BN_dup(other.bn)) {}
    ChunkyInt(ChunkyInt&& other) : bn(other.bn) { other.bn = nullptr; }
    ChunkyInt& operator=(const ChunkyInt& other);
    ChunkyInt& operator=(ChunkyInt&& other);

    void clear() { BN_clear(bn); }
    [[nodiscard]] BIGNUM* get_bn() noexcept { return bn; }
    [[nodiscard]] const BIGNUM* get_bn() const noexcept { return bn; }
    [[nodiscard]] int num_bits() const { return BN_num_bits(bn); }
    [[nodiscard]] int num_bytes() const { return BN_num_bytes(bn); }

    [[nodiscard]] bool check_bit(int n) const {
        return BN_is_bit_set(bn, n) == 1;
    }

    [[nodiscard]] bool is_zero() const { return BN_is_zero(bn); }
    [[nodiscard]] bool is_one() const { return BN_is_one(bn); }
    [[nodiscard]] bool is_odd() const { return BN_is_odd(bn); }
    [[nodiscard]] bool is_negative() const { return BN_is_negative(bn); }
    [[nodiscard]] bool is_prime() const;

    [[nodiscard]] bool miller_rabin(int num_checks) const;

    // Randomizes this ChunkyInt to some int in the closed interval [min, max]
    void randomize_range(const ChunkyInt& min, const ChunkyInt& max) {
        BN_rand_range(bn, (max - min).bn);
        *this += min;
    }

    void randomize_bits(int bits, int top = 0, bool odd = false) {
        BN_rand(bn, bits, top, odd);
    }

    void make_random_prime(int bits, bool safe = false);

private:
    BIGNUM* bn;

    friend ChunkyInt operator+(const ChunkyInt&, const ChunkyInt&);
    friend ChunkyInt operator+(const ChunkyInt&, unsigned long);
    friend ChunkyInt operator+(unsigned long, const ChunkyInt&);
    friend ChunkyInt operator-(const ChunkyInt&, const ChunkyInt&);
    friend ChunkyInt operator-(const ChunkyInt&, unsigned long);
    friend ChunkyInt operator-(unsigned long, const ChunkyInt&);
    friend ChunkyInt operator*(const ChunkyInt&, const ChunkyInt&);
    friend ChunkyInt operator*(const ChunkyInt&, unsigned long);
    friend ChunkyInt operator*(unsigned long, const ChunkyInt&);
    friend ChunkyInt operator/(const ChunkyInt&, const ChunkyInt&);
    friend ChunkyInt operator/(const ChunkyInt&, unsigned long);
    friend ChunkyInt operator/(unsigned long, const ChunkyInt&);
    friend ChunkyInt operator%(const ChunkyInt&, const ChunkyInt&);
    friend ChunkyInt operator%(const ChunkyInt&, unsigned long);
    friend ChunkyInt operator%(unsigned long, const ChunkyInt&);

    friend ChunkyInt& operator+=(ChunkyInt&, const ChunkyInt&);
    friend ChunkyInt& operator+=(ChunkyInt&, unsigned long);
    friend ChunkyInt& operator-=(ChunkyInt&, const ChunkyInt&);
    friend ChunkyInt& operator-=(ChunkyInt&, unsigned long);
    friend ChunkyInt& operator*=(ChunkyInt&, const ChunkyInt&);
    friend ChunkyInt& operator*=(ChunkyInt&, unsigned long);
    friend ChunkyInt& operator/=(ChunkyInt&, const ChunkyInt&);
    friend ChunkyInt& operator/=(ChunkyInt&, unsigned long);
    friend ChunkyInt& operator%=(ChunkyInt&, const ChunkyInt&);
    friend ChunkyInt& operator%=(ChunkyInt&, unsigned long);

    friend bool operator==(const ChunkyInt&, const ChunkyInt&);
    friend bool operator==(const ChunkyInt&, unsigned long);
    friend bool operator==(unsigned long, const ChunkyInt&);

    friend bool operator!=(const ChunkyInt&, const ChunkyInt&);
    friend bool operator<(const ChunkyInt&, const ChunkyInt&);
    friend bool operator>(const ChunkyInt&, const ChunkyInt&);
    friend bool operator<=(const ChunkyInt&, const ChunkyInt&);
    friend bool operator>=(const ChunkyInt&, const ChunkyInt&);

    friend ChunkyInt gcd(const ChunkyInt&, const ChunkyInt&);
    friend bool is_rel_prime(const ChunkyInt&, const ChunkyInt&);
    friend ChunkyInt mod_exp(const ChunkyInt&, const ChunkyInt&,
                             const ChunkyInt&);
    friend ChunkyInt mod_exp_cool(ChunkyInt, const ChunkyInt&,
                                  const ChunkyInt&);

    friend std::ostream& operator<<(std::ostream&, const ChunkyInt&);
};

[[nodiscard]] ChunkyInt gcd(const ChunkyInt& a, const ChunkyInt& b);
[[nodiscard]] bool is_rel_prime(const ChunkyInt& a, const ChunkyInt& b);
[[nodiscard]] ChunkyInt mod_exp(const ChunkyInt& a, const ChunkyInt& p,
                                const ChunkyInt& m);
[[nodiscard]] ChunkyInt mod_exp_cool(ChunkyInt a, const ChunkyInt& p,
                                     const ChunkyInt& m);

}  // namespace ChunkyInts

}  // namespace amzcrypto

#endif  // #ifndef AMZCRYPTO_CHUNKYINT_HPP
