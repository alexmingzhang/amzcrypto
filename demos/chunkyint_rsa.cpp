#include <array>
#include <cassert>
#include <cstring>
#include <iomanip>
#include <iostream>

#include "chunkyint.hpp"

using namespace amzcrypto;

/**
 * @brief Finds the gcd of a and b, and finds two integers x and y such that
 * gcd(a, b) = ax + yb
 *
 * @param a a ChunkyInt
 * @param b a ChunkyInt
 * @return A tuple (gcd, x, y)
 */
std::tuple<ChunkyInts::ChunkyInt, ChunkyInts::ChunkyInt, ChunkyInts::ChunkyInt>
extended_euclidean(const ChunkyInts::ChunkyInt& a,
                   const ChunkyInts::ChunkyInt& b) {
    if (a.is_zero()) {
        return {b, 0, 1};
    }

    auto [gcd, x, y] = extended_euclidean(b % a, a);
    return {gcd, y - (b / a) * x, x};
}

void generate_key() {
    constexpr int key_bits = 1024;
    ChunkyInts::ChunkyInt e = 65537;

    ChunkyInts::ChunkyInt p;
    ChunkyInts::ChunkyInt q;
    ChunkyInts::ChunkyInt totient;
    do {
        p.make_random_prime(key_bits);
        q.make_random_prime(key_bits);
        totient = (p - 1) * (q - 1);
    } while (!ChunkyInts::is_rel_prime(totient, e));

    ChunkyInts::ChunkyInt n = p * q;

    std::cout << "e = " << e << "\n\n";
    std::cout << "p = " << p << "\n\n";
    std::cout << "q = " << q << "\n\n";
    std::cout << "n = " << n << "\n\n";
    std::cout << "φ = " << totient << "\n\n";

    auto [gcd, d, __ignore] = extended_euclidean(e, totient);

    assert(gcd.is_one());

    while (d.is_negative()) {
        d += totient;
    }

    std::cout << "d = " << d << "\n\n";

    // At this stage in key generation, we should delete our values of p and q
    p.clear();
    q.clear();
}

void encrypt() {
    constexpr const char* m_ascii = "coincidency";
    constexpr std::size_t m_ascii_len = std::strlen(m_ascii);

    std::cout << "0x";
    for (std::size_t i = 0; i < m_ascii_len; ++i) {
        std::cout << std::hex << std::setw(2) << std::setfill('0')
                  << static_cast<int>(m_ascii[i]);
    }
    std::cout << "\n\n";

    ChunkyInts::ChunkyInt m = "0x636f696e636964656e6379";
    std::cout << std::hex << m << "\n\n";

    ChunkyInts::ChunkyInt e = 65537;
    ChunkyInts::ChunkyInt n =
        "2601805820861554640907112661900942725458279555338737647497157288586637"
        "5103169217140020747328602459000528977796282391894651327774435295347102"
        "5573331414766289552734993568612910996869427272946103482566717059270673"
        "9840179645835944759165063977421591691532596246908286768374103851275398"
        "7172209486925046848063651479204567296701708308217839653031286716906223"
        "5593087037030218206549132907210254551937726301896336578514210560003519"
        "1168336621623577631862159927058243678799747040820000770249325389168423"
        "2373853979206855673542149608651533248534120337922194660855039858196246"
        "857083500628229864709795417644897579442574691443886326809";

    ChunkyInts::ChunkyInt c = ChunkyInts::mod_exp(m, e, n);

    std::cout << std::dec << c << "\n\n";
}

void decrypt() {
    ChunkyInts::ChunkyInt c =
        "2036453662646647553101933299208298246722925103506144823716379649542509"
        "1401391280411115329290109400937133508690030879431351681169352639317592"
        "7900550157550354872343030798185432122315400186335940146940027222486009"
        "0412327266733490954013738123471972181785799069589902461641960359003916"
        "1453179982987287834368331020465628715765531077282187093342017976457007"
        "6156700956153699699254868582327741692752550868898860785960112303710869"
        "9314198721720874549511648919680687871228408618823290757259616189379090"
        "2246168166820818918805558469644442380675385307939730487655765030863588"
        "57671707879642696233392062002355031602242409677476862699";

    ChunkyInts::ChunkyInt d =
        "9883662315359150455471485852371312402613688116592644227244034340395948"
        "4652715386715589136746095613054788811086294219846688047404113876582917"
        "3241628225585782795198193369270340750730314385349679158640308208737461"
        "2060532594218789496646693132411911859315427340743199625469839858606943"
        "6293899230432574931625290632503833628279522031305429701051190194403760"
        "0611857144004703587019936662426929163941029739898237650713126317512258"
        "8845345945600647525231620442549043694338964803561179114312232037894124"
        "7711945612002668316699212209676071825082168908806291066421535990055178"
        "96027758119462164284040357380366336035987626724647293953";

    ChunkyInts::ChunkyInt n =
        "2601805820861554640907112661900942725458279555338737647497157288586637"
        "5103169217140020747328602459000528977796282391894651327774435295347102"
        "5573331414766289552734993568612910996869427272946103482566717059270673"
        "9840179645835944759165063977421591691532596246908286768374103851275398"
        "7172209486925046848063651479204567296701708308217839653031286716906223"
        "5593087037030218206549132907210254551937726301896336578514210560003519"
        "1168336621623577631862159927058243678799747040820000770249325389168423"
        "2373853979206855673542149608651533248534120337922194660855039858196246"
        "857083500628229864709795417644897579442574691443886326809";

    ChunkyInts::ChunkyInt m = ChunkyInts::mod_exp(c, d, n);

    std::cout << std::hex << m << "\n\n";

    std::cout << "\x74\x65\x6C\x66\x65\x72\x65\x64"
              << "\n\n";
}

int main() {
    decrypt();
    return 0;
}
