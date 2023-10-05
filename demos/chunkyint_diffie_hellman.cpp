#include <openssl/aes.h>
#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/sha.h>

#include <array>
#include <iomanip>
#include <iostream>

#include "chunkyint.hpp"

using namespace amzcrypto;

void handleErrors(void) {
    ERR_print_errors_fp(stderr);
    abort();
}

// https://wiki.openssl.org/index.php/EVP_Symmetric_Encryption_and_Decryption
int decrypt(unsigned char *ciphertext, int ciphertext_len, unsigned char *key,
            unsigned char *iv, unsigned char *plaintext) {
    EVP_CIPHER_CTX *ctx;

    int len;

    int plaintext_len;

    /* Create and initialise the context */
    if (!(ctx = EVP_CIPHER_CTX_new())) {
        std::cout << 1 << std::endl;

        handleErrors();
    }

    /*
     * Initialise the decryption operation. IMPORTANT - ensure you use a key
     * and IV size appropriate for your cipher
     * In this example we are using 256 bit AES (i.e. a 256 bit key). The
     * IV size for *most* modes is the same as the block size. For AES this
     * is 128 bits
     */
    if (1 != EVP_DecryptInit_ex(ctx, EVP_aes_128_cbc(), NULL, key, iv)) {
        std::cout << 2 << std::endl;

        handleErrors();
    }

    /*
     * Provide the message to be decrypted, and obtain the plaintext output.
     * EVP_DecryptUpdate can be called multiple times if necessary.
     */
    if (1 !=
        EVP_DecryptUpdate(ctx, plaintext, &len, ciphertext, ciphertext_len)) {
        std::cout << 3 << std::endl;

        handleErrors();
    }
    plaintext_len = len;

    /*
     * Finalise the decryption. Further plaintext bytes may be written at
     * this stage.
     */
    if (1 != EVP_DecryptFinal_ex(ctx, plaintext + len, &len)) {
        std::cout << 4 << std::endl;
        handleErrors();
    }

    plaintext_len += len;

    /* Clean up */
    EVP_CIPHER_CTX_free(ctx);

    return plaintext_len;
}

int main() {
    ChunkyInts::ChunkyInt g = 5;

    if (false) {
        constexpr int key_bits = 2048;
        ChunkyInts::ChunkyInt chunky_key_bits = key_bits;
        ChunkyInts::ChunkyInt chunky_1;

        // First, we choose a safe prime number p
        ChunkyInts::ChunkyInt p;
        p.make_random_prime(key_bits,
                            true);  // TODO: need more conditions here?

        // We select a as our random private key, which must be an element of
        // Z_2048. That is, 1 <= a < 2048, and gcd(a, 2048) = 1.
        ChunkyInts::ChunkyInt a;
        do {
            BN_rand(a.get_bn(), key_bits - 1, -1, true);
        } while (!is_rel_prime(a, chunky_key_bits));

        // Our public key is (g^a) mod p
        ChunkyInts::ChunkyInt public_key = ChunkyInts::mod_exp(g, a, p);

        std::cout << "p = " << p << "\n\n";
        std::cout << "a= " << a << "\n\n";
        std::cout << " public_key = " << public_key << "\n\n";
    }

    if (true) {
        ChunkyInts::ChunkyInt p =
            "306416698288443664342687390553859270650816662693951712760480909873"
            "630489195427351376233609593229244455249501075424068964166853559491"
            "739631515659206068288111205326405228711756277389854315534938048751"
            "821749894484325212458340275141021924402693680548553915342345067506"
            "839473811761988434526090816670316628476310037252334463320495064283"
            "273925387838196703769230929444316381256017298747670784622086488921"
            "320189434862451164183104223207168655857855999592546834003689354796"
            "078056553446188910729619629894061377035645550519788742647849922967"
            "131060169832904315259392634652858695972482671688382005268273442647"
            "58695112861305790546699";

        ChunkyInts::ChunkyInt a =
            "255467545016755842693795452488757539804203582239285452896143605962"
            "213453916722084063983988454964976237979907599328574296036909236173"
            "755143784885785756629853565872652060205224590082845903481506269084"
            "960860465449955095586374316742038891862587656559846054299514209414"
            "504907553295512615203881094383103519132620431379955279190516759210"
            "904347181673915625933461349196493554134301295198663226253880789809"
            "825288746357824440768617815162249547517655077684688372315706128391"
            "831567656246925909184407069073361033408890728766627444523979411163"
            "367127318469894696347184733857120029517085871371045634047945573159"
            "1131466146653186728139";

        ChunkyInts::ChunkyInt my_public_key =
            "159058533696467069570052833064731921901658200266832503652312803615"
            "110213571000448649081094336106025004975710763552669555292810230334"
            "257561098600477020773346357632486265696784325519868092622677078921"
            "877194390560550012165374059048898412044499775742509931020479209332"
            "221430387282754250482376724469287224243508249997626771466110222078"
            "635589991204944118511190563911638047819626426315511775585612249700"
            "893676166153497187854181945905634064876660351114124124378695727052"
            "332495545188866765789585064456781825856595516575003050875122240754"
            "225074248837444680576859029798717832821712046774715791607649937411"
            "50744247198205267481619";

        ChunkyInts::ChunkyInt their_public_key =
            "845681500637046854644945062612341564157955956804265720815526959687"
            "082374799466500292797411544609850908356955456457264956591227302445"
            "287199460166286440574252653267969963788371144378743559384834058900"
            "292539168098685187266318923979524684100193273506645609339221679425"
            "758360437325142868650402689471701021478078290146680807968359644063"
            "632344554404176189810662034438858187065082963952769900372886550697"
            "492049929317418042613233000805473663462875566284888339252685703935"
            "903307446837966288441864425854429808649208377537623521065550925318"
            "553468272167179540149290399821123434949529076343944944484893913572"
            "906324053328245085719";

        ChunkyInts::ChunkyInt shared_key =
            ChunkyInts::mod_exp(their_public_key, a, p);

        std::cout << "shared diffie-hellman key: " << std::dec << shared_key
                  << "\n\n";

        // Hash the darn thing
        const auto bytes_len = shared_key.num_bytes();
        unsigned char *bytes = new unsigned char[bytes_len];

        std::cout << "bytes=" << bytes_len << ", bits=" << shared_key.num_bits()
                  << '\n';
        BN_bn2bin(shared_key.get_bn(), bytes);

        unsigned char hash[SHA256_DIGEST_LENGTH];
        SHA256(bytes, bytes_len, hash);

        std::cout << "AES Key: ";
        for (int i = 0; i < 16; ++i) {
            std::cout << std::hex << std::setw(2) << std::setfill('0')
                      << (static_cast<int>(hash[i]) & 0xFF);
        }
        std::cout << "\n\n";

        unsigned char iv[] = {0x82, 0xc6, 0x1e, 0xfe, 0x9f, 0x60, 0x1d, 0x9b,
                              0x2c, 0xdd, 0x5f, 0x53, 0xbb, 0x6e, 0xf5, 0x01};

        unsigned char ciphertext[] = {
            0x10, 0x86, 0xcb, 0x14, 0xf8, 0x90, 0x4a, 0x1c, 0x32, 0x04, 0xf0,
            0x12, 0xd6, 0x69, 0xc6, 0x72, 0xf3, 0xfb, 0x89, 0x00, 0xe9, 0xb3,
            0xbb, 0x9e, 0x3b, 0x6a, 0xc4, 0x51, 0x4b, 0xc8, 0x20, 0x6b, 0x07,
            0x5b, 0xdc, 0xda, 0x3b, 0xae, 0x5e, 0x1a, 0x37, 0x7b, 0x0a, 0x19,
            0x8b, 0x4b, 0x8b, 0xe6, 0xb0, 0x1a, 0x53, 0x4f, 0xba, 0x48, 0x3b,
            0x0e, 0xf2, 0x63, 0x91, 0xf2, 0xca, 0x5a, 0x7f, 0x48, 0x2b, 0x4d,
            0xe6, 0x03, 0xe4, 0xe4, 0x37, 0xfc, 0xc0, 0xfe, 0x5b, 0xf8, 0xad,
            0xef, 0x6f, 0xda, 0x00, 0xe2, 0xab, 0x39, 0xb7, 0x46, 0x55, 0x80,
            0x5e, 0x1f, 0x01, 0xcf, 0x4b, 0xf0, 0xf6, 0x65, 0x6f, 0xbb, 0x0a,
            0x7b, 0x40, 0x3d, 0x55, 0xcb, 0x76, 0x2b, 0x00, 0x14, 0x4c, 0x46,
            0xa8, 0x45, 0x16, 0x00, 0x02, 0xf3, 0x9b, 0x74, 0x05, 0x3d, 0x20,
            0x4e, 0x88, 0x9a, 0xcf, 0x66, 0xa7, 0x0a, 0x52, 0xe5, 0xb0, 0x89,
            0x71, 0x7a, 0x8a, 0xa0, 0x81, 0x46, 0x5c, 0xb9, 0x4a, 0xe5, 0x62,
            0xed, 0x90, 0xb0, 0x9b, 0x90, 0x15, 0xca, 0x79, 0x5d, 0x8a, 0x55,
            0xfc, 0x31, 0xb9, 0xf1, 0xd7, 0x0b};
        int ciphertext_len = 160;

        unsigned char plaintext[1024];

        auto plaintext_len =
            decrypt(ciphertext, ciphertext_len, hash, iv, plaintext);

        for (int i = 0; i < plaintext_len; ++i) {
            std::cout << static_cast<char>(plaintext[i]);
        }
        std::cout << '\n';
    }

    return 0;
}
