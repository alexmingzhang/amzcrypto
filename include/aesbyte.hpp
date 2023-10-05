/**
 * @file aesbyte.hpp
 * @author Alex Zhang (azhang13)
 * @brief Implements bytes as finite field elements as per the AES specification
 * @date 2023-08-30
 */

#ifndef AMZCRYPTO_AESBYTE_HPP
#define AMZCRYPTO_AESBYTE_HPP
#pragma once

#include <concepts>
#include <cstdint>

namespace amzcrypto {

namespace AES {

/**
 * @brief Enforces a type must be an integer type
 * @tparam T An integer type
 */
template <class T>
concept Integral = std::is_integral<T>::value;

/**
 * @brief Implementation of a byte interpreted as a finite field element
 * @tparam Nk Number of 32-bit words that comprise the cipher key
 */
class Byte {
public:
    constexpr Byte() noexcept : value(0) {}
    constexpr Byte(std::uint8_t u) noexcept : value(u) {}

    constexpr std::uint8_t get_value() const noexcept { return value; }

    // TODO: FIGURE OUT WHY CANT HAVE TIHS???
    // static constexpr Byte modulus{static_cast<std::uint8_t>(0x1b)};

    constexpr auto operator<=>(const Byte&) const noexcept = default;

    template <Integral IntegerType>
    friend constexpr Byte operator<<(Byte lhs, IntegerType shift) noexcept {
        return lhs.value << shift;
    }

    template <Integral IntegerType>
    friend constexpr Byte operator>>(Byte lhs, IntegerType shift) noexcept {
        return lhs.value >> shift;
    }

    template <Integral IntegerType>
    friend constexpr Byte& operator<<=(Byte& b, IntegerType shift) noexcept {
        return b = b << shift;
    }

    template <Integral IntegerType>
    friend constexpr Byte& operator>>=(Byte& b, IntegerType shift) noexcept {
        return b = b >> shift;
    }

    friend constexpr Byte operator|(Byte lhs, Byte rhs) noexcept {
        return lhs.value | rhs.value;
    }

    friend constexpr Byte operator&(Byte lhs, Byte rhs) noexcept {
        return lhs.value & rhs.value;
    }

    friend constexpr Byte operator^(Byte lhs, Byte rhs) noexcept {
        return lhs.value ^ rhs.value;
    }

    friend constexpr Byte operator~(Byte b) noexcept { return ~b.value; }

    friend constexpr Byte& operator|=(Byte& lhs, Byte rhs) noexcept {
        return lhs = lhs | rhs;
    }

    friend constexpr Byte& operator&=(Byte& lhs, Byte rhs) noexcept {
        return lhs = lhs & rhs;
    }

    friend constexpr Byte& operator^=(Byte& lhs, Byte rhs) noexcept {
        return lhs = lhs ^ rhs;
    }

    /// @brief Finite field addition
    friend constexpr Byte operator+(Byte lhs, Byte rhs) noexcept {
        return lhs ^ rhs;
    }

    /// @brief Finite field multiplication
    friend constexpr Byte operator*(Byte lhs, Byte rhs) noexcept {
        Byte running_sum{0};

        for (int i = 0; i < 8; ++i) {
            if (lhs.value & (1 << i)) {
                running_sum += rhs;
            }

            rhs.xtime_in_place();
        }

        return running_sum;
    }

    friend constexpr Byte& operator+=(Byte& lhs, Byte rhs) noexcept {
        return lhs = lhs + rhs;
    }

    friend constexpr Byte& operator*=(Byte& lhs, Byte rhs) noexcept {
        return lhs = lhs * rhs;
    }

private:
    std::uint8_t value;

    static constexpr std::uint8_t modulus = 0x1b;

    [[nodiscard]] constexpr Byte xtime() const {
        Byte copy = *this;

        if (copy.value & 0b1000'0000) {
            copy <<= 1;
            copy += modulus;
        } else {
            copy <<= 1;
        }

        return copy;
    }

    constexpr Byte& xtime_in_place() {
        if (this->value & 0b1000'0000) {
            *this <<= 1;
            *this += 0x1b;
        } else {
            *this <<= 1;
        }

        return *this;
    }
};

}  // namespace AES

}  // namespace amzcrypto

#endif
