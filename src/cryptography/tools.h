//
// Created by Masha on 2024-12-13.
//

#ifndef TOOLS_H
#define TOOLS_H
#include <boost/multiprecision/cpp_int.hpp>

void log(const std::string& s);

// StringToUint128 casts string to uint128_t ignoring all non-digit characters.
boost::multiprecision::uint128_t StringToUint128(const std::string& s);

// GenerateRandom generates a random value.
boost::multiprecision::uint128_t GenerateRandom();

// GetLowLevelPrime checks if generated number is not divisible by first 70
// primes. After passing this test, the number is being checked by Miller-Rabin
// algorithm for a more accurate identification of bit primes.
boost::multiprecision::uint128_t GetLowLevelPrime();

// GetBigPrime retuns a big prime number, which has been checked by applying
// Miller-Rabin primality test.
boost::multiprecision::uint128_t GetBigPrime();

// GetSafePrime returns a "safe" prime. The prime number p is called "safe"
// if (p - 1) has only two dividers: 2 and another prime number. Such numbers
// allow to find generator for Z_p group much easier.
// https://en.wikipedia.org/wiki/Safe_and_Sophie_Germain_primes
boost::multiprecision::uint128_t GetSafePrime();

// GeneratorForSafePrime finds a generator for group Z_p, where p is a "safe"
// prime.
// NOTE: Please make sure that the input is a safe prime, as the function does
// not check for the validity of the input.
boost::multiprecision::uint128_t GeneratorForSafePrime(
    const boost::multiprecision::uint128_t& prime);

// MillerRabin determines if a number is likely to be prime by applying
// Miller-Rabin primality test. Input parameter "accuracy" specifies the number
// of rounds conducted. The result is accurate with probability
// 1 - (1/4)^{accuracy}.
// https://en.wikipedia.org/wiki/Miller%E2%80%93Rabin_primality_test
bool MillerRabin(const boost::multiprecision::uint128_t& candidate,
                 int accuracy);

// PowModulo calculate result of (base ^ power) % mod using binary
// exponentiation algorithm.
boost::multiprecision::uint128_t PowModulo(
    boost::multiprecision::uint128_t base,
    boost::multiprecision::uint128_t power,
    const boost::multiprecision::uint128_t& mod);

// HashModulo calculates the hash for a given string using polynomial rolling
// hash function with p = 61.
// https://en.wikipedia.org/wiki/Rolling_hash
boost::multiprecision::uint128_t HashModulo(const std::string& message,
                                            const
                                            boost::multiprecision::uint128_t&
                                            mod);
// Inverse calculates multiplicative inverse for a given number num by modulo
// mod. The algotithm uses Extended Euclidean algorithm for calculating modular
// multiplicative inverse.
boost::multiprecision::uint128_t Inverse(
    const boost::multiprecision::uint128_t& num,
    const boost::multiprecision::uint128_t& mod);

#endif //TOOLS_H
