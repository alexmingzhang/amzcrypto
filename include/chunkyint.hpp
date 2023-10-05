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

// TODO: better error messages (use OpenSSL's error messages)
// TODO: move stuff to a separate source file?
// TODO: what methods should be noexcept?
// TODO: add [[nodiscard]] to operator+ and others?

#ifndef AMZCRYPTO_CHUNKYINT_HPP
#define AMZCRYPTO_CHUNKYINT_HPP
#pragma once

#include <openssl/bn.h>
#include <openssl/err.h>

#include <ostream>
#include <stdexcept>
#include <thread>

namespace amzcrypto {

namespace ChunkyInts {

// TODO: manage the lifetime of local_ctx
// maybe maintain a counter? or just register a function when program ends to
// free local_ctx???
thread_local BN_CTX* local_ctx = BN_CTX_new();

class ChunkyInt {
public:
    // Constructors
    // TODO: some of these should definitely be explicit constructors
    ChunkyInt() noexcept { bn = BN_new(); }

    ChunkyInt(BIGNUM* bn) noexcept : bn(bn) {}

    ChunkyInt(unsigned long w) {
        bn = BN_new();
        BN_set_word(bn, w);
    }

    ChunkyInt(const char* num_str) {
        bn = BN_new();

        // TODO: might be bad here? what if num_str does not have more than 1
        // character
        if (num_str[0] == '0' && num_str[1] == 'x') {
            BN_hex2bn(&bn, num_str + 2);
        } else {
            BN_dec2bn(&bn, num_str);
        }
    }

    // Destructor
    ~ChunkyInt() noexcept { BN_clear_free(bn); }

    // Copy constructor
    ChunkyInt(const ChunkyInt& other) { bn = BN_dup(other.bn); }

    // Move constructor
    ChunkyInt(ChunkyInt&& other) {
        bn = other.bn;
        other.bn = nullptr;
    }

    // Copy assignment
    ChunkyInt& operator=(const ChunkyInt& other) {
        BN_copy(bn, other.bn);
        return *this;
    }

    // Move assignment
    ChunkyInt& operator=(ChunkyInt&& other) {
        BN_free(bn);
        bn = other.bn;
        other.bn = nullptr;
        return *this;
    }

    void clear() { BN_clear(bn); }
    [[nodiscard]] BIGNUM* get_bn() noexcept { return bn; }
    [[nodiscard]] const BIGNUM* get_bn() const noexcept { return bn; }
    [[nodiscard]] int num_bits() const { return BN_num_bits(bn); }
    [[nodiscard]] int num_bytes() const { return BN_num_bytes(bn); }

    [[nodiscard]] bool check_bit(int n) const { return BN_is_bit_set(bn, n); }

    [[nodiscard]] bool is_zero() const { return BN_is_zero(bn); }
    [[nodiscard]] bool is_one() const { return BN_is_one(bn); }
    [[nodiscard]] bool is_odd() const { return BN_is_odd(bn); }
    [[nodiscard]] bool is_negative() const { return BN_is_negative(bn); }
    [[nodiscard]] bool is_prime() const {
        // TODO: error handling; check_prime might return -1 on error
        return BN_check_prime(bn, local_ctx, nullptr) == 1;
    }

    [[nodiscard]] bool miller_rabin(int num_checks) const;

    // Randomizes this ChunkyInt to some int in the closed interval [min, max]
    void randomize_range(const ChunkyInt& min, const ChunkyInt& max) {
        BN_rand_range(bn, (max - min).bn);
        *this += min;
    }

    void randomize_bits(int bits, int top = 0, bool odd = false) {
        BN_rand(bn, bits, top, odd);
    }

    void make_random_prime(int bits, bool safe);

private:
    BIGNUM* bn;

    // TODO: the rest of the operators aoiefjaojfodsjfoadsfaos
    friend ChunkyInt operator+(const ChunkyInt&, const ChunkyInt&);
    friend ChunkyInt operator-(const ChunkyInt&, const ChunkyInt&);
    friend ChunkyInt operator-(const ChunkyInt&, unsigned long);

    friend ChunkyInt operator*(const ChunkyInt&, const ChunkyInt&);
    friend ChunkyInt operator/(const ChunkyInt&, const ChunkyInt&);
    friend ChunkyInt operator%(const ChunkyInt&, const ChunkyInt&);

    friend ChunkyInt& operator+=(ChunkyInt&, const ChunkyInt&);
    friend ChunkyInt& operator+=(ChunkyInt&, unsigned long);

    friend ChunkyInt& operator/=(ChunkyInt&, unsigned long);

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

/**
 * @brief Performs miller-rabin primality checks on a ChunkyInt.
 *
 * @param num_checks Number of checks to perform
 * @return true If the number is (probably) prime.
 * @return false If the number is (probably) composite.
 */
[[nodiscard]] bool ChunkyInt::miller_rabin(int num_checks) const {
    if (*this == 2) [[unlikely]] {
        return true;
    }

    if (!this->is_odd()) [[unlikely]] {
        return false;
    }

    const ChunkyInt& p = *this;
    ChunkyInt s = 0UL;
    ChunkyInt d = p - 1;

    // factor out powers of 2 from p-1
    while (!d.is_odd()) {
        s += 1;
        d /= 2;
    }

    for (int i = 0; i < num_checks; ++i) {
        ChunkyInt a;
        a.randomize_range(1, p - 1);

        ChunkyInt x = mod_exp_cool(a, d, p);

        if (x == 1 || x == p - 1) {
            continue;
        }

        bool to_continue = false;

        for (int j = 0; j < s - 1; ++j) {
            x = mod_exp_cool(x, 2, p);

            if (x == p - 1) {
                to_continue = true;
                break;
            }
        }

        if (to_continue) {
            continue;
        }

        return false;
    }

    return true;
}

void ChunkyInt::make_random_prime(int bits, bool safe = false) {
    if (BN_generate_prime_ex(bn, bits, safe, nullptr, nullptr, nullptr) != 1)
        [[unlikely]] {
        throw std::runtime_error("Could not make random prime.");
    };
}

ChunkyInt operator+(const ChunkyInt& a, const ChunkyInt& b) {
    ChunkyInt result;
    if (BN_add(result.bn, a.bn, b.bn) != 1) [[unlikely]] {
        throw std::runtime_error("Could not add ChunkyInts.");
    }
    return result;
}

ChunkyInt operator-(const ChunkyInt& a, const ChunkyInt& b) {
    ChunkyInt result;
    if (BN_sub(result.bn, a.bn, b.bn) != 1) [[unlikely]] {
        throw std::runtime_error("Could not subtract ChunkyInts.");
    }
    return result;
}

ChunkyInt operator-(const ChunkyInt& a, unsigned long b) {
    ChunkyInt result(a);
    if (BN_sub_word(result.bn, b) != 1) [[unlikely]] {
        throw std::runtime_error(
            "Could not subtract unsigned long from ChunkyInt.");
    }
    return result;
}

ChunkyInt operator*(const ChunkyInt& a, const ChunkyInt& b) {
    ChunkyInt result;
    if (BN_mul(result.bn, a.bn, b.bn, local_ctx) != 1) [[unlikely]] {
        throw std::runtime_error("Could not multiply ChunkyInts.");
    }
    return result;
}

ChunkyInt operator/(const ChunkyInt& a, const ChunkyInt& b) {
    ChunkyInt result;
    if (BN_div(result.bn, nullptr, a.bn, b.bn, local_ctx) != 1) [[unlikely]] {
        throw std::runtime_error("Could not multiply ChunkyInts.");
    }
    return result;
}

ChunkyInt operator%(const ChunkyInt& a, const ChunkyInt& b) {
    ChunkyInt result;
    if (BN_mod(result.bn, a.bn, b.bn, local_ctx) != 1) [[unlikely]] {
        throw std::runtime_error("Could not take modulo of ChunkyInts.");
    }
    return result;
}

ChunkyInt& operator+=(ChunkyInt& a, const ChunkyInt& b) {
    if (BN_add(a.bn, a.bn, b.bn) != 1) [[unlikely]] {
        throw std::runtime_error("Could not take modulo of ChunkyInts.");
    }
    return a;
}

ChunkyInt& operator+=(ChunkyInt& a, unsigned long b) {
    if (BN_add_word(a.bn, b) != 1) [[unlikely]] {
        throw std::runtime_error("Could not add ChunkyInt and unsigned long.");
    }
    return a;
}

ChunkyInt& operator/=(ChunkyInt& a, unsigned long b) {
    constexpr auto error_return_val = static_cast<BN_ULONG>(-1);
    if (BN_div_word(a.bn, b) == error_return_val) [[unlikely]] {
        throw std::runtime_error(
            "Could not divide ChunkyInt by unsigned long.");
    }
    return a;
}

bool operator==(const ChunkyInt& a, const ChunkyInt& b) {
    return BN_cmp(a.bn, b.bn) == 0;
}

bool operator==(const ChunkyInt& a, unsigned long b) {
    return BN_is_word(a.bn, b) == 1;
}

bool operator==(unsigned long a, const ChunkyInt& b) {
    return BN_is_word(b.bn, a) == 1;
}

bool operator!=(const ChunkyInt& a, const ChunkyInt& b) {
    return BN_cmp(a.bn, b.bn) != 0;
}

bool operator<(const ChunkyInt& a, const ChunkyInt& b) {
    return BN_cmp(a.bn, b.bn) == -1;
}

bool operator>(const ChunkyInt& a, const ChunkyInt& b) {
    return BN_cmp(a.bn, b.bn) == 1;
}

bool operator<=(const ChunkyInt& a, const ChunkyInt& b) {
    return BN_cmp(a.bn, b.bn) <= 0;
}

bool operator>=(const ChunkyInt& a, const ChunkyInt& b) {
    return BN_cmp(a.bn, b.bn) >= 0;
}

ChunkyInt gcd(const ChunkyInt& a, const ChunkyInt& b) {
    ChunkyInt result;
    if (BN_gcd(result.bn, a.bn, b.bn, local_ctx) != 1) [[unlikely]] {
        throw std::runtime_error("Could not take gcd of ChunkyInts.");
    }
    return result;
}

[[nodiscard]] bool is_rel_prime(const ChunkyInt& a, const ChunkyInt& b) {
    return BN_is_one(gcd(a, b).get_bn());
}

ChunkyInt mod_exp(const ChunkyInt& a, const ChunkyInt& p, const ChunkyInt& m) {
    ChunkyInt result;
    if (BN_mod_exp(result.bn, a.bn, p.bn, m.bn, local_ctx) != 1) [[unlikely]] {
        throw std::runtime_error(
            "Could not take modular exponent of ChunkyInts.");
    }
    return result;
}

/**
 * @brief Computes (a^p) mod n.
 *
 * @param a The base.
 * @param p The power.
 * @param m The modulus.
 * @return (a^p) mod n.
 */
ChunkyInt mod_exp_cool(ChunkyInt a, const ChunkyInt& p, const ChunkyInt& m) {
    ChunkyInt result = 1;

    for (int i = 0; i < p.num_bits(); ++i) {
        if (p.check_bit(i)) {
            result = (result * a) % m;
        }

        a = (a * a) % m;
    }

    return result;
}

std::ostream& operator<<(std::ostream& os, const ChunkyInt& c) {
    if (os.flags() & std::ios_base::hex) {
        const char* str = BN_bn2hex(c.bn);
        os << str;
        OPENSSL_free((void*)str);
    } else {
        const char* str = BN_bn2dec(c.bn);
        os << str;
        OPENSSL_free((void*)str);
    }

    return os;
}

}  // namespace ChunkyInts

}  // namespace amzcrypto

#endif  // #ifndef AMZCRYPTO_CHUNKYINT_HPP
