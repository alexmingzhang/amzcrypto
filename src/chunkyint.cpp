#include "chunkyint.hpp"

#include <cstring>
#include <stdexcept>
#include <thread>

namespace amzcrypto {
namespace ChunkyInts {

// BN_mod_word() and BN_div_word() returnn (BN_ULONG)-1 if an error occurred.
constexpr auto BN_mod_div_word_error = static_cast<BN_ULONG>(-1);

static void throw_with_error() {
    auto e = ERR_get_error();
    char buffer[256];
    ERR_error_string_n(e, buffer, sizeof(buffer));
    throw std::runtime_error(buffer);
}

// Automatically manage lifetime of BN_CTX
class ContextManager {
public:
    ContextManager() { ctx = BN_CTX_new(); }
    ~ContextManager() { BN_CTX_free(ctx); }
    BN_CTX* get() const noexcept { return ctx; }

private:
    BN_CTX* ctx;
};

thread_local ContextManager local_context;

ChunkyInt::ChunkyInt(const char* num_str) : bn(BN_new()) {
    if (std::strlen(num_str) > 2 && num_str[0] == '0' && num_str[1] == 'x') {
        BN_hex2bn(&bn, num_str + 2);
    } else {
        BN_dec2bn(&bn, num_str);
    }
}

ChunkyInt::ChunkyInt(std::string_view num_str) : bn(BN_new()) {
    if (num_str.size() > 2 && num_str[0] == '0' && num_str[1] == 'x') {
        std::string tmp_str(num_str.begin() + 2, num_str.end());
        BN_hex2bn(&bn, tmp_str.c_str());
    } else {
        std::string tmp_str(num_str.begin(), num_str.end());
        BN_dec2bn(&bn, tmp_str.c_str());
    }
}

ChunkyInt& ChunkyInt::operator=(const ChunkyInt& other) {
    BN_copy(bn, other.bn);
    return *this;
}

ChunkyInt& ChunkyInt::operator=(ChunkyInt&& other) {
    BN_free(bn);
    bn = other.bn;
    other.bn = nullptr;
    return *this;
}

[[nodiscard]] bool ChunkyInt::is_prime() const {
    const auto result = BN_check_prime(bn, local_context.get(), nullptr);

    if (result == -1) [[unlikely]] {
        throw_with_error();
    }

    return result == 1;
}

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

void ChunkyInt::make_random_prime(int bits, bool safe) {
    if (BN_generate_prime_ex(bn, bits, safe, nullptr, nullptr, nullptr) != 1)
        [[unlikely]] {
        throw_with_error();
    };
}

ChunkyInt operator+(const ChunkyInt& a, const ChunkyInt& b) {
    ChunkyInt result;
    if (BN_add(result.bn, a.bn, b.bn) != 1) [[unlikely]] {
        throw_with_error();
    }
    return result;
}

ChunkyInt operator+(const ChunkyInt& a, unsigned long b) {
    ChunkyInt result(a);
    if (BN_add_word(result.bn, b) != 1) [[unlikely]] {
        throw_with_error();
    }
    return result;
}

ChunkyInt operator+(unsigned long a, const ChunkyInt& b) {
    ChunkyInt result(b);
    if (BN_add_word(result.bn, a) != 1) [[unlikely]] {
        throw_with_error();
    }
    return result;
}

ChunkyInt operator-(const ChunkyInt& a, const ChunkyInt& b) {
    ChunkyInt result;
    if (BN_sub(result.bn, a.bn, b.bn) != 1) [[unlikely]] {
        throw_with_error();
    }
    return result;
}

ChunkyInt operator-(const ChunkyInt& a, unsigned long b) {
    ChunkyInt result(a);
    if (BN_sub_word(result.bn, b) != 1) [[unlikely]] {
        throw_with_error();
    }
    return result;
}

ChunkyInt operator-(unsigned long a, const ChunkyInt& b) {
    ChunkyInt result(b);
    if (BN_sub_word(result.bn, a) != 1) [[unlikely]] {
        throw_with_error();
    }
    return result;
}

ChunkyInt operator*(const ChunkyInt& a, const ChunkyInt& b) {
    ChunkyInt result;
    if (BN_mul(result.bn, a.bn, b.bn, local_context.get()) != 1) [[unlikely]] {
        throw_with_error();
    }
    return result;
}

ChunkyInt operator*(const ChunkyInt& a, unsigned long b) {
    ChunkyInt result(a);
    if (BN_mul_word(result.bn, b) != 1) [[unlikely]] {
        throw_with_error();
    }
    return result;
}

ChunkyInt operator*(unsigned long a, const ChunkyInt& b) {
    ChunkyInt result(b);
    if (BN_mul_word(result.bn, a) != 1) [[unlikely]] {
        throw_with_error();
    }
    return result;
}

ChunkyInt operator/(const ChunkyInt& a, const ChunkyInt& b) {
    ChunkyInt result;
    if (BN_div(result.bn, nullptr, a.bn, b.bn, local_context.get()) != 1)
        [[unlikely]] {
        throw_with_error();
    }
    return result;
}

ChunkyInt operator/(const ChunkyInt& a, unsigned long b) {
    ChunkyInt result(a);
    if (BN_div_word(result.bn, b) == BN_mod_div_word_error) [[unlikely]] {
        throw_with_error();
    }
    return result;
}

ChunkyInt operator/(unsigned long a, const ChunkyInt& b) {
    ChunkyInt result(b);
    if (BN_div_word(result.bn, a) == BN_mod_div_word_error) [[unlikely]] {
        throw_with_error();
    }
    return result;
}

ChunkyInt operator%(const ChunkyInt& a, const ChunkyInt& b) {
    ChunkyInt result;
    if (BN_mod(result.bn, a.bn, b.bn, local_context.get()) != 1) [[unlikely]] {
        throw_with_error();
    }
    return result;
}

ChunkyInt operator%(const ChunkyInt& a, unsigned long b) {
    ChunkyInt result(a);
    if (BN_mod_word(result.bn, b) == BN_mod_div_word_error) [[unlikely]] {
        throw_with_error();
    }
    return result;
}

ChunkyInt operator%(unsigned long a, const ChunkyInt& b) {
    ChunkyInt result(b);
    if (BN_mod_word(result.bn, a) == BN_mod_div_word_error) [[unlikely]] {
        throw_with_error();
    }
    return result;
}

ChunkyInt& operator+=(ChunkyInt& a, const ChunkyInt& b) {
    if (BN_add(a.bn, a.bn, b.bn) != 1) [[unlikely]] {
        throw_with_error();
    }
    return a;
}

ChunkyInt& operator+=(ChunkyInt& a, unsigned long b) {
    if (BN_add_word(a.bn, b) != 1) [[unlikely]] {
        throw_with_error();
    }
    return a;
}

ChunkyInt& operator-=(ChunkyInt& a, const ChunkyInt& b) {
    if (BN_sub(a.bn, a.bn, b.bn) != 1) [[unlikely]] {
        throw_with_error();
    }
    return a;
}

ChunkyInt& operator-=(ChunkyInt& a, unsigned long b) {
    if (BN_sub_word(a.bn, b) != 1) [[unlikely]] {
        throw_with_error();
    }
    return a;
}

ChunkyInt& operator*=(ChunkyInt& a, const ChunkyInt& b) {
    if (BN_mul(a.bn, a.bn, b.bn, local_context.get()) != 1) [[unlikely]] {
        throw_with_error();
    }
    return a;
}

ChunkyInt& operator*=(ChunkyInt& a, unsigned long b) {
    if (BN_mul_word(a.bn, b) != 1) [[unlikely]] {
        throw_with_error();
    }
    return a;
}

ChunkyInt& operator/=(ChunkyInt& a, const ChunkyInt& b) {
    if (BN_div(a.bn, nullptr, a.bn, b.bn, local_context.get()) != 1)
        [[unlikely]] {
        throw_with_error();
    }
    return a;
}

ChunkyInt& operator/=(ChunkyInt& a, unsigned long b) {
    if (BN_div_word(a.bn, b) == BN_mod_div_word_error) [[unlikely]] {
        throw_with_error();
    }
    return a;
}

ChunkyInt& operator%=(ChunkyInt& a, const ChunkyInt& b) {
    if (BN_mod(a.bn, a.bn, b.bn, local_context.get()) != 1) [[unlikely]] {
        throw_with_error();
    }
    return a;
}

ChunkyInt& operator%=(ChunkyInt& a, unsigned long b) {
    if (BN_mod_word(a.bn, b) == BN_mod_div_word_error) [[unlikely]] {
        throw_with_error();
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
    if (BN_gcd(result.bn, a.bn, b.bn, local_context.get()) != 1) [[unlikely]] {
        throw std::runtime_error("Could not take gcd of ChunkyInts.");
    }
    return result;
}

[[nodiscard]] bool is_rel_prime(const ChunkyInt& a, const ChunkyInt& b) {
    return BN_is_one(gcd(a, b).get_bn());
}

ChunkyInt mod_exp(const ChunkyInt& a, const ChunkyInt& p, const ChunkyInt& m) {
    ChunkyInt result;
    if (BN_mod_exp(result.bn, a.bn, p.bn, m.bn, local_context.get()) != 1)
        [[unlikely]] {
        throw_with_error();
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
    int num_bits = p.num_bits();

    for (int i = 0; i < num_bits; ++i) {
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
