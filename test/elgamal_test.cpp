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

// ----------------------------------------------------------------------------
// Helper functions for testing different particular cases.
void ElGamal_Sign_Test(uint128_t prime, uint128_t generator,
                       uint128_t private_key, uint128_t public_key,
                       const std::string& message, uint128_t hash,
                       uint128_t k_value,
                       uint128_t r_signature, uint128_t s_signature) {
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

void ElGamal_Verify_Success(uint128_t prime, uint128_t generator,
                            uint128_t public_key, const std::string& message,
                            uint128_t hash, uint128_t r_signature,
                            uint128_t s_signature) {
    Signature signature = {
        prime, generator, public_key, r_signature, s_signature
    };
    EXPECT_EQ(HashModulo(message, prime), hash);
    EXPECT_TRUE(ElGamal::Verify(message, signature));
}

void ElGamal_Verify_Failure(uint128_t prime, uint128_t generator,
                            uint128_t public_key, const std::string& message,
                            uint128_t hash, uint128_t r_signature,
                            uint128_t s_signature) {
    Signature signature = {
        prime, generator, public_key, r_signature, s_signature
    };
    EXPECT_NE(HashModulo(message, prime), hash);
    EXPECT_FALSE(ElGamal::Verify(message, signature));
}
// ----------------------------------------------------------------------------

// Example from https://www.slideshare.net/slideshow/elgamal-digital-signature-253463577/253463577
TEST(ElGamalSignature, Test1) {
    uint128_t prime = 19;
    uint128_t generator = 10;
    uint128_t private_key = 16;
    uint128_t public_key = 4;
    std::string message = "n";
    uint128_t hash = 14;
    uint128_t k_value = 5;
    uint128_t r_signature = 3;
    uint128_t s_signature = 4;

    ElGamal_Sign_Test(prime, generator, private_key, public_key, message, hash,
                      k_value, r_signature, s_signature);
    ElGamal_Verify_Success(prime, generator, public_key, message, hash,
                           r_signature, s_signature);
    ElGamal_Verify_Failure(prime, generator, public_key, "wrong", hash,
                           r_signature, s_signature);
}

// For such small prime number, the collision is expected. This test case tests that for different message with same
// hash value the signature will be verified.
TEST(ElGamalSignature, Test1_Collision) {
    uint128_t prime = 19;
    Signature signature = {prime, 10, 4, 3, 4};

    std::string message = "G";
    EXPECT_EQ(HashModulo(message, prime), 14);
    EXPECT_TRUE(ElGamal::Verify(message, signature));
}

// Example from https://www.youtube.com/watch?v=UE1bVsVFEAY
TEST(ElGamalSignature, Test2) {
    uint128_t prime = 211;
    uint128_t generator = 32;
    uint128_t private_key = 17;
    uint128_t public_key = 110;
    std::string message = "Fb";
    uint128_t hash = 154;
    uint128_t k_value = 47;
    uint128_t r_signature = 157;
    uint128_t s_signature = 85;

    ElGamal_Sign_Test(prime, generator, private_key, public_key, message, hash,
                      k_value, r_signature, s_signature);
    ElGamal_Verify_Success(prime, generator, public_key, message, hash,
                           r_signature, s_signature);
    ElGamal_Verify_Failure(prime, generator, public_key, "wrong_message", hash,
                           r_signature, s_signature);
}

// Example from https://www.flt-info.eu/wp-content/uploads/2022/06/Signatures.pdf
TEST(ElGamalSignature, Test3) {
    uint128_t prime = 467;
    uint128_t generator = 2;
    uint128_t private_key = 127;
    uint128_t public_key = 132;
    std::string message = "Ma";
    uint128_t hash = 100;
    uint128_t k_value = 213;
    uint128_t r_signature = 29;
    uint128_t s_signature = 51;

    ElGamal_Sign_Test(prime, generator, private_key, public_key, message, hash,
                      k_value, r_signature, s_signature);
    ElGamal_Verify_Success(prime, generator, public_key, message, hash,
                           r_signature, s_signature);
    ElGamal_Verify_Failure(prime, generator, public_key, "wrong_message", hash,
                           r_signature, s_signature);
}

// Example from https://cacr.uwaterloo.ca/hac/about/chap11.pdf
TEST(ElGamalSignature, Test4) {
    uint128_t prime = 2357;
    uint128_t generator = 2;
    uint128_t private_key = 1751;
    uint128_t public_key = 1185;
    std::string message = "7w";
    uint128_t hash = 1463;
    uint128_t k_value = 1529;
    uint128_t r_signature = 1490;
    uint128_t s_signature = 1777;

    ElGamal_Sign_Test(prime, generator, private_key, public_key, message, hash,
                      k_value, r_signature, s_signature);
    ElGamal_Verify_Success(prime, generator, public_key, message, hash,
                           r_signature, s_signature);
    ElGamal_Verify_Failure(prime, generator, public_key, "wrong_message", hash,
                           r_signature, s_signature);
}

// Example from https://math.stackexchange.com/questions/4673884/elgamal-digital-signature-scheme-question
TEST(ElGamalSignature, Test5) {
    uint128_t prime = 479;
    uint128_t generator = 13;
    uint128_t private_key = 300;
    uint128_t public_key = 168;
    std::string message = "mf";
    uint128_t hash = 379;
    uint128_t k_value = 11;
    uint128_t r_signature = 237;
    uint128_t s_signature = 89;

    ElGamal_Sign_Test(prime, generator, private_key, public_key, message, hash,
                      k_value, r_signature, s_signature);
    ElGamal_Verify_Success(prime, generator, public_key, message, hash,
                           r_signature, s_signature);
    ElGamal_Verify_Failure(prime, generator, public_key, "wrong_message", hash,
                           r_signature, s_signature);
}

// The following examples were generated using online ElGamal calculator as a source of truth:
// https://cryptocalc.com.au/digital-signature-calc
TEST(ElGamalSignature, Test6) {
    uint128_t prime = 295777;
    uint128_t generator = 204538;
    uint128_t private_key = 288290;
    uint128_t public_key = 13448;
    std::string message = "abcd";
    uint128_t hash = 31879;
    uint128_t k_value = 164971;
    uint128_t r_signature = 269381;
    uint128_t s_signature = 191607;

    ElGamal_Sign_Test(prime, generator, private_key, public_key, message, hash,
                      k_value, r_signature, s_signature);
    ElGamal_Verify_Success(prime, generator, public_key, message, hash,
                           r_signature, s_signature);
    ElGamal_Verify_Failure(prime, generator, public_key, "wrong_message", hash,
                           r_signature, s_signature);
}

TEST(ElGamalSignature, Test7) {
    uint128_t prime = 767909;
    uint128_t generator = 256024;
    uint128_t private_key = 712647;
    uint128_t public_key = 125724;
    std::string message = "abcd";
    uint128_t hash = 151301;
    uint128_t k_value = 548009;
    uint128_t r_signature = 634214;
    uint128_t s_signature = 503947;

    ElGamal_Sign_Test(prime, generator, private_key, public_key, message, hash,
                      k_value, r_signature, s_signature);
    ElGamal_Verify_Success(prime, generator, public_key, message, hash,
                           r_signature, s_signature);
    ElGamal_Verify_Failure(prime, generator, public_key, "wrong_message", hash,
                           r_signature, s_signature);
}

TEST(ElGamalSignature, Test8) {
    uint128_t prime = 868999;
    uint128_t generator = 413329;
    uint128_t private_key = 424073;
    uint128_t public_key = 99445;
    std::string message = "abcd";
    uint128_t hash = 50211;
    uint128_t k_value = 527693;
    uint128_t r_signature = 311152;
    uint128_t s_signature = 594497;

    ElGamal_Sign_Test(prime, generator, private_key, public_key, message, hash,
                      k_value, r_signature, s_signature);
    ElGamal_Verify_Success(prime, generator, public_key, message, hash,
                           r_signature, s_signature);
    ElGamal_Verify_Failure(prime, generator, public_key, "wrong_message", hash,
                           r_signature, s_signature);
}
