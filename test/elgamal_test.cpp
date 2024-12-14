//
// Created by Masha on 2024-12-13.
//
#include <gtest/gtest.h>

#include "../src/cryptography/cryptography.h"
#include "../src/cryptography/tools.h"

using namespace boost::multiprecision;

TEST(ElGamal_GeneratePrime, Basic) {
    ElGamal el_gamal;
    for (int i = 0; i < 10; i++) {
        auto prime = el_gamal.GeneratePrime();
        EXPECT_TRUE(MillerRabin(prime, 10));
        EXPECT_TRUE(MillerRabin((prime - 1) / 2, 10));
    }
}

TEST(ElGamal_GenerateGenerator, Basic) {
    ElGamal el_gamal;
    el_gamal.SetPrime(11);
    auto gen = el_gamal.GenerateGenerator();
    std::vector<uint128_t> gens = {2, 6, 7, 8};
    EXPECT_TRUE(std::find(gens.begin(), gens.end(), gen) != gens.end());

    el_gamal.SetPrime(23);
    gen = el_gamal.GenerateGenerator();
    gens = {5, 7, 10, 11, 14, 15, 17, 19, 20, 21};
    EXPECT_TRUE(std::find(gens.begin(), gens.end(), gen) != gens.end());

    el_gamal.SetPrime(59);
    gen = el_gamal.GenerateGenerator();
    gens = {
        2, 6, 8, 10, 11, 13, 14, 18, 23, 24, 30, 31, 32, 33, 34, 37, 38, 39, 40,
        42, 43, 44, 47, 50, 52, 54, 55, 56
    };
    EXPECT_TRUE(std::find(gens.begin(), gens.end(), gen) != gens.end());

    el_gamal.SetPrime(107);
    gen = el_gamal.GenerateGenerator();
    gens = {
        2, 5, 6, 7, 8, 15, 17, 18, 20, 21, 22, 24, 26, 28, 31, 32, 38, 43, 45,
        46, 50, 51, 54, 55, 58, 59, 60, 63, 65,
        66, 67, 68, 70, 71, 72, 73, 74, 77, 78, 80, 82, 84, 88, 91, 93, 94, 95,
        96, 97, 98, 103, 104
    };
    EXPECT_TRUE(std::find(gens.begin(), gens.end(), gen) != gens.end());
}

TEST(ElGamal_GeneratePublicKey, Basic) {
    ElGamal el_gamal;
    el_gamal.SetPrime(107);
    el_gamal.SetGenerator(24);

    EXPECT_EQ(el_gamal.GeneratePublicKey(2).second, 41);
    EXPECT_EQ(el_gamal.GeneratePublicKey(1).second, 24);
    EXPECT_EQ(el_gamal.GeneratePublicKey(80).second, 61);
    EXPECT_EQ(el_gamal.GeneratePublicKey(100).second, 33);
}

// Example from https://www.slideshare.net/slideshow/elgamal-digital-signature-253463577/253463577
TEST(ElGamal_Test1, Sign) {
    uint128_t prime = 19;
    ElGamal el_gamal;
    el_gamal.SetPrime(prime);
    el_gamal.SetGenerator(10);
    auto y = el_gamal.GeneratePublicKey(16);
    EXPECT_EQ(y.second, 4);

    std::string message = "n"; // hash = 14
    EXPECT_EQ(HashModulo(message, prime), 14);

    auto signature = el_gamal.Sign(message, 5);
    EXPECT_EQ(signature.first, uint128_t(3));
    EXPECT_EQ(signature.second, uint128_t(4));
}

TEST(ElGamal_Test1, Verify_Success) {
    uint128_t prime = 19;
    Signature signature = {prime, 10, 4, 3, 4};
    std::string message = "n"; // hash = 14
    EXPECT_EQ(HashModulo(message, prime), 14);
    EXPECT_TRUE(ElGamal::Verify(message, signature));
}

TEST(ElGamal_Test1, Verfiy_Failure) {
    uint128_t prime = 19;
    Signature signature = {prime, 10, 4, 3, 4};

    std::string message = "wrong";
    EXPECT_NE(HashModulo(message, prime), 14);
    EXPECT_FALSE(ElGamal::Verify(message, signature));
}

// For such small prime number, the collision is expected. This test case tests that for different message with same
// hash value the signature will be verified.
TEST(ElGamal_Test1, Verify_Collision) {
    uint128_t prime = 19;
    Signature signature = {prime, 10, 4, 3, 4};

    std::string message = "G";
    EXPECT_EQ(HashModulo(message, prime), 14);
    EXPECT_TRUE(ElGamal::Verify(message, signature));
}

// Example from https://www.youtube.com/watch?v=UE1bVsVFEAY
TEST(ElGamal_Test2, Sign) {
    uint128_t prime = 211;
    ElGamal el_gamal;
    el_gamal.SetPrime(prime);
    el_gamal.SetGenerator(32);
    auto y = el_gamal.GeneratePublicKey(17);
    EXPECT_EQ(y.second, 110);

    std::string message = "Fb"; // hash = 154
    EXPECT_EQ(HashModulo(message, prime), 154);
    auto signature = el_gamal.Sign(message, 47);
    EXPECT_EQ(signature.first, uint128_t(157));
    EXPECT_EQ(signature.second, uint128_t(85));
}

TEST(ElGamal_Test2, Verify_Success) {
    uint128_t prime = 211;
    Signature signature = {prime, 32, 110, 157, 85};
    std::string message = "Fb"; // hash = 154
    EXPECT_EQ(HashModulo(message, prime), 154);

    EXPECT_TRUE(ElGamal::Verify(message, signature));
}

TEST(ElGamal_Test2, Verify_Failure) {
    uint128_t prime = 211;
    Signature signature = {prime, 32, 110, 157, 85};
    std::string message = "wrong_message";
    EXPECT_NE(HashModulo(message, prime), 154);
    EXPECT_FALSE(ElGamal::Verify(message, signature));
}

// Example from https://www.flt-info.eu/wp-content/uploads/2022/06/Signatures.pdf
TEST(ElGamal_Test3, Sign) {
    uint128_t prime = 467;
    ElGamal el_gamal;
    el_gamal.SetPrime(prime);
    el_gamal.SetGenerator(2);
    auto y = el_gamal.GeneratePublicKey(127);
    EXPECT_EQ(y.second, 132);

    std::string message = "Ma"; // hash = 100
    EXPECT_EQ(HashModulo(message, prime), 100);
    auto signature = el_gamal.Sign(message, 213);
    EXPECT_EQ(signature.first, uint128_t(29));
    EXPECT_EQ(signature.second, uint128_t(51));
}

TEST(ElGamal_Test3, Verify_Success) {
    uint128_t prime = 467;
    Signature signature = {prime, 2, 132, 29, 51};
    std::string message = "Ma"; // hash = 100
    EXPECT_EQ(HashModulo(message, prime), 100);
    EXPECT_TRUE(ElGamal::Verify(message, signature));
}

TEST(ElGamal_Test3, Verify_Failure) {
    uint128_t prime = 467;
    Signature signature = {prime, 2, 132, 29, 51};
    std::string message = "wrong_message";
    EXPECT_NE(HashModulo(message, prime), 100);
    EXPECT_FALSE(ElGamal::Verify(message, signature));
}

// Example from https://cacr.uwaterloo.ca/hac/about/chap11.pdf
TEST(ElGamal_Test4, Sign) {
    uint128_t prime = 2357;
    ElGamal el_gamal;
    el_gamal.SetPrime(prime);
    el_gamal.SetGenerator(2);
    auto y = el_gamal.GeneratePublicKey(1751);
    EXPECT_EQ(y.second, 1185);

    std::string message = "7w"; // hash = 1463
    EXPECT_EQ(HashModulo(message, prime), 1463);
    auto signature = el_gamal.Sign(message, 1529);
    EXPECT_EQ(signature.first, uint128_t(1490));
    EXPECT_EQ(signature.second, uint128_t(1777));
}

TEST(ElGamal_Test4, Verify_Success) {
    uint128_t prime = 2357;
    Signature signature = {prime, 2, 1185, 1490, 1777};
    std::string message = "7w"; // hash = 1463
    EXPECT_EQ(HashModulo(message, prime), 1463);
    EXPECT_TRUE(ElGamal::Verify(message, signature));
}

TEST(ElGamal_Test4, Verify_Failure) {
    uint128_t prime = 2357;
    Signature signature = {prime, 2, 1185, 1490, 1777};
    std::string message = "wrong_message";
    EXPECT_NE(HashModulo(message, prime), 1463);
    EXPECT_FALSE(ElGamal::Verify(message, signature));
}

// Example from https://math.stackexchange.com/questions/4673884/elgamal-digital-signature-scheme-question
TEST(ElGamal_Test5, Sign) {
    uint128_t prime = 479;
    ElGamal el_gamal;
    el_gamal.SetPrime(prime);
    el_gamal.SetGenerator(13);
    auto y = el_gamal.GeneratePublicKey(300);
    EXPECT_EQ(y.second, 168);

    std::string message = "mf"; // hash = 379
    EXPECT_EQ(HashModulo(message, prime), 379);
    auto signature = el_gamal.Sign(message, 11);
    EXPECT_EQ(signature.first, uint128_t(237));
    EXPECT_EQ(signature.second, uint128_t(89));
}

TEST(ElGamal_Test5, Verify_Success) {
    uint128_t prime = 479;
    Signature signature = {prime, 13, 168, 237, 89};

    std::string message = "mf"; // hash = 379
    EXPECT_EQ(HashModulo(message, prime), 379);
    EXPECT_TRUE(ElGamal::Verify(message, signature));
}

TEST(ElGamal_Test5, Verify_Failure) {
    uint128_t prime = 479;
    Signature signature = {prime, 13, 168, 237, 89};

    std::string message = "wrong_message";
    EXPECT_NE(HashModulo(message, prime), 379);
    EXPECT_FALSE(ElGamal::Verify(message, signature));
}

// The following examples were generated using online ElGamal calculator as a source of truth:
// https://cryptocalc.com.au/digital-signature-calc

TEST(ElGamal_Test6, Sign) {
    uint128_t prime = 295777;
    uint128_t generator = 204538;
    uint128_t private_key = 288290;
    uint128_t public_key = 13448;
    std::string message = "abcd";
    uint128_t hash = 31879;
    uint128_t k_value = 164971;
    uint128_t r_signature = 269381;
    uint128_t s_signature = 191607;

    ElGamal el_gamal;
    el_gamal.SetPrime(prime);
    el_gamal.SetGenerator(generator);
    auto y = el_gamal.GeneratePublicKey(private_key);
    EXPECT_EQ(y.second, public_key);

    EXPECT_EQ(HashModulo(message, prime), hash);
    auto signature = el_gamal.Sign(message, k_value);
    EXPECT_EQ(signature.first, uint128_t(r_signature));
    EXPECT_EQ(signature.second, uint128_t(s_signature));
}

TEST(ElGamal_Test6, Verify_Success) {
    uint128_t prime = 295777;
    uint128_t generator = 204538;
    uint128_t public_key = 13448;
    std::string message = "abcd";
    uint128_t hash = 31879;
    uint128_t r_signature = 269381;
    uint128_t s_signature = 191607;

    Signature signature = {
        prime, generator, public_key, r_signature, s_signature
    };

    EXPECT_EQ(HashModulo(message, prime), hash);
    EXPECT_TRUE(ElGamal::Verify(message, signature));
}

TEST(ElGamal_Test6, Verify_Failure) {
    uint128_t prime = 295777;
    uint128_t generator = 204538;
    uint128_t public_key = 13448;
    std::string message = "wrong_message";
    uint128_t hash = 31879;
    uint128_t r_signature = 269381;
    uint128_t s_signature = 191607;

    Signature signature = {
        prime, generator, public_key, r_signature, s_signature
    };

    EXPECT_NE(HashModulo(message, prime), hash);
    EXPECT_FALSE(ElGamal::Verify(message, signature));
}

TEST(ElGamal_Test7, Sign) {
    uint128_t prime = 767909;
    uint128_t generator = 256024;
    uint128_t private_key = 712647;
    uint128_t public_key = 125724;
    std::string message = "abcd";
    uint128_t hash = 151301;
    uint128_t k_value = 548009;
    uint128_t r_signature = 634214;
    uint128_t s_signature = 503947;

    ElGamal el_gamal;
    el_gamal.SetPrime(prime);
    el_gamal.SetGenerator(generator);
    auto y = el_gamal.GeneratePublicKey(private_key);
    EXPECT_EQ(y.second, public_key);

    EXPECT_EQ(HashModulo(message, prime), hash);
    auto signature = el_gamal.Sign(message, k_value);
    EXPECT_EQ(signature.first, uint128_t(r_signature));
    EXPECT_EQ(signature.second, uint128_t(s_signature));
}

TEST(ElGamal_Test7, Verify_Success) {
    uint128_t prime = 767909;
    uint128_t generator = 256024;
    uint128_t public_key = 125724;
    std::string message = "abcd";
    uint128_t hash = 151301;
    uint128_t r_signature = 634214;
    uint128_t s_signature = 503947;

    Signature signature = {
        prime, generator, public_key, r_signature, s_signature
    };

    EXPECT_EQ(HashModulo(message, prime), hash);
    EXPECT_TRUE(ElGamal::Verify(message, signature));
}

TEST(ElGamal_Test7, Verify_Failure) {
    uint128_t prime = 767909;
    uint128_t generator = 256024;
    uint128_t public_key = 125724;
    std::string message = "wrong_message";
    uint128_t hash = 151301;
    uint128_t r_signature = 634214;
    uint128_t s_signature = 503947;

    Signature signature = {
        prime, generator, public_key, r_signature, s_signature
    };

    EXPECT_NE(HashModulo(message, prime), hash);
    EXPECT_FALSE(ElGamal::Verify(message, signature));
}

TEST(ElGamal_Test8, Sign) {
    uint128_t prime = 868999;
    uint128_t generator = 413329;
    uint128_t private_key = 424073;
    uint128_t public_key = 99445;
    std::string message = "abcd";
    uint128_t hash = 50211;
    uint128_t k_value = 527693;
    uint128_t r_signature = 311152;
    uint128_t s_signature = 594497;

    ElGamal el_gamal;
    el_gamal.SetPrime(prime);
    el_gamal.SetGenerator(generator);
    auto y = el_gamal.GeneratePublicKey(private_key);
    EXPECT_EQ(y.second, public_key);

    EXPECT_EQ(HashModulo(message, prime), hash);
    auto signature = el_gamal.Sign(message, k_value);
    EXPECT_EQ(signature.first, uint128_t(r_signature));
    EXPECT_EQ(signature.second, uint128_t(s_signature));
}

TEST(ElGamal_Test8, Verify_Success) {
    uint128_t prime = 868999;
    uint128_t generator = 413329;
    uint128_t public_key = 99445;
    std::string message = "abcd";
    uint128_t hash = 50211;
    uint128_t r_signature = 311152;
    uint128_t s_signature = 594497;

    Signature signature = {
        prime, generator, public_key, r_signature, s_signature
    };

    EXPECT_EQ(HashModulo(message, prime), hash);
    EXPECT_TRUE(ElGamal::Verify(message, signature));
}

TEST(ElGamal_Test8, Verify_Failure) {
    uint128_t prime = 868999;
    uint128_t generator = 413329;
    uint128_t public_key = 99445;
    std::string message = "wrong_message";
    uint128_t hash = 50211;
    uint128_t r_signature = 311152;
    uint128_t s_signature = 594497;

    Signature signature = {
        prime, generator, public_key, r_signature, s_signature
    };

    EXPECT_NE(HashModulo(message, prime), hash);
    EXPECT_FALSE(ElGamal::Verify(message, signature));
}
