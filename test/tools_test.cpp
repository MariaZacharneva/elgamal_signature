//
// Created by Masha on 2024-12-12.
//
#include <gtest/gtest.h>

#include "../src/cryptography/cryptography.h"
#include "../src/cryptography/tools.h"

using namespace boost::multiprecision;

TEST(MillerRabinTest, Basic) {
    EXPECT_TRUE(MillerRabin(StringToUint128("13"), 10));
    EXPECT_TRUE(MillerRabin(StringToUint128("890774428839653"), 10));
    EXPECT_TRUE(MillerRabin(StringToUint128("890774428839653"), 10));
    EXPECT_TRUE(MillerRabin(StringToUint128("2370884506768417"), 10));
    EXPECT_TRUE(MillerRabin(StringToUint128("2515669008093797"), 10));
    EXPECT_TRUE(MillerRabin(StringToUint128("20404537980081407"), 10));
    EXPECT_TRUE(MillerRabin(StringToUint128("48940438466271823"), 10));
    EXPECT_TRUE(MillerRabin(StringToUint128("983766264069727601"), 10));

    EXPECT_FALSE(MillerRabin(StringToUint128("13") - 1, 10));
    EXPECT_FALSE(MillerRabin(StringToUint128("890774428839653") - 1, 10));
    EXPECT_FALSE(MillerRabin(StringToUint128("890774428839653") - 1, 10));
    EXPECT_FALSE(MillerRabin(StringToUint128("2370884506768417") - 1, 10));
    EXPECT_FALSE(MillerRabin(StringToUint128("2515669008093797") - 1, 10));
    EXPECT_FALSE(MillerRabin(StringToUint128("20404537980081407") - 1, 10));
    EXPECT_FALSE(MillerRabin(StringToUint128("48940438466271823") - 1, 10));
    EXPECT_FALSE(MillerRabin(StringToUint128("983766264069727601") - 1, 10));
}

TEST(SafePrimeNumberTest, Basic) {
    for (int i = 0; i < 10; i++) {
        auto prime = GetSafePrime();
        EXPECT_TRUE(MillerRabin(prime, 10));
        EXPECT_TRUE(MillerRabin((prime - 1) / 2, 10));
    }
}

TEST(GeneratorForSafePrime, Basic) {
    auto gen = GeneratorForSafePrime(11);
    std::vector<uint128_t> gens = {2, 6, 7, 8};
    EXPECT_TRUE(std::find(gens.begin(), gens.end(), gen) != gens.end());

    gen = GeneratorForSafePrime(23);
    gens = {5, 7, 10, 11, 14, 15, 17, 19, 20, 21};
    EXPECT_TRUE(std::find(gens.begin(), gens.end(), gen) != gens.end());

    gen = GeneratorForSafePrime(59);
    gens = {
        2, 6, 8, 10, 11, 13, 14, 18, 23, 24, 30, 31, 32, 33, 34, 37, 38, 39, 40, 42, 43, 44, 47, 50, 52, 54, 55, 56
    };
    EXPECT_TRUE(std::find(gens.begin(), gens.end(), gen) != gens.end());

    gen = GeneratorForSafePrime(107);
    gens = {
        2, 5, 6, 7, 8, 15, 17, 18, 20, 21, 22, 24, 26, 28, 31, 32, 38, 43, 45, 46, 50, 51, 54, 55, 58, 59, 60, 63, 65,
        66, 67, 68, 70, 71, 72, 73, 74, 77, 78, 80, 82, 84, 88, 91, 93, 94, 95, 96, 97, 98, 103, 104
    };
    EXPECT_TRUE(std::find(gens.begin(), gens.end(), gen) != gens.end());
}

// Verified by hand.
TEST(HashModuloTest, Basic) {
    std::string m = "cat";
    auto hash = HashModulo(m, uint128_t(100000));
    EXPECT_EQ(hash, 74484);

    m = "DOG";
    hash = HashModulo(m, uint128_t(100000));
    EXPECT_EQ(hash, 25324);

    m = "123";
    hash = HashModulo(m, uint128_t(100000));
    EXPECT_EQ(hash, 11785);
}

// Verified by hand.
TEST(PowModulo, Basic) {
    EXPECT_EQ(PowModulo(2, 100, 1000), 376);
    EXPECT_EQ(PowModulo(3, 100, 1000), 1);
    EXPECT_EQ(PowModulo(5, 20, 666), 493);
    EXPECT_EQ(PowModulo(0, 100, 1000), 0);
    EXPECT_EQ(PowModulo(1, 100, 1000), 1);
    EXPECT_EQ(PowModulo(999, 100, 1000), 1);
}

TEST(InverseTest, Basic) {
    EXPECT_EQ(Inverse(5, 13), 8);
    EXPECT_EQ(Inverse(1, 53), 1);
    EXPECT_EQ(Inverse(22, 23), 22);
    EXPECT_EQ(Inverse(77, 107), 82);
    EXPECT_EQ(Inverse(20, 1907), 1621);
}
