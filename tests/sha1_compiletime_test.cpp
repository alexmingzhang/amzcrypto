#include <iomanip>
#include <iostream>

#include "sha1.hpp"
#include "sha1_util.hpp"

using namespace amzcrypto;

int main() {
    constexpr auto D1 = SHA1::hash(SHA1::pad("This is a test of SHA-1."));
    static_assert(D1[0] == 0x8e35b472);
    static_assert(D1[1] == 0x13acb9fa);
    static_assert(D1[2] == 0x620d8e88);
    static_assert(D1[3] == 0x4d3f6338);
    static_assert(D1[4] == 0x166f34d7);

    constexpr auto D2 =
        SHA1::hash(SHA1::pad("Kerckhoff's principle is the foundation on which "
                             "modern cryptography is built."));
    static_assert(D2[0] == 0xf801ea3e);
    static_assert(D2[1] == 0x4c55ca85);
    static_assert(D2[2] == 0x0928bbf1);
    static_assert(D2[3] == 0xbb24776d);
    static_assert(D2[4] == 0x61e3fe09);

    constexpr auto D3 = SHA1::hash(
        SHA1::pad("SHA-1 is no longer considered a secure hashing algorithm."));
    static_assert(D3[0] == 0xa0773c12);
    static_assert(D3[1] == 0xa8851bcf);
    static_assert(D3[2] == 0x9697b57c);
    static_assert(D3[3] == 0xe3e3b494);
    static_assert(D3[4] == 0x36f02cfe);

    constexpr auto D4 = SHA1::hash(
        SHA1::pad("SHA-2 or SHA-3 should be used in place of SHA-1."));
    static_assert(D4[0] == 0xdd102182);
    static_assert(D4[1] == 0xaabb5778);
    static_assert(D4[2] == 0xe925eb2f);
    static_assert(D4[3] == 0x536bab90);
    static_assert(D4[4] == 0x4b97c9b5);

    constexpr auto D5 = SHA1::hash(SHA1::pad("Never roll your own crypto!"));
    static_assert(D5[0] == 0xae912752);
    static_assert(D5[1] == 0x721c0f7b);
    static_assert(D5[2] == 0x5857cc8c);
    static_assert(D5[3] == 0x314fb9a3);
    static_assert(D5[4] == 0xe94ca1c0);

    return 0;
}
