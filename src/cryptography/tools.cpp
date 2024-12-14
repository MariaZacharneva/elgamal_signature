//
// Created by Masha on 2024-12-13.
//

#include "tools.h"
#include <boost/multiprecision/cpp_int.hpp>
#include <boost/random.hpp>

using namespace boost::multiprecision;
using namespace boost::random;

const std::pmr::vector<uint128_t> kFirstPrimes = {
    2, 3, 5, 7, 11, 13, 17, 19, 23, 29,
    31, 37, 41, 43, 47, 53, 59, 61, 67,
    71, 73, 79, 83, 89, 97, 101, 103,
    107, 109, 113, 127, 131, 137, 139,
    149, 151, 157, 163, 167, 173, 179,
    181, 191, 193, 197, 199, 211, 223,
    227, 229, 233, 239, 241, 251, 257,
    263, 269, 271, 277, 281, 283, 293,
    307, 311, 313, 317, 331, 337, 347, 349
};

independent_bits_engine<mt19937, 64, uint128_t> kGen;

// kAccuracy is used for defining the number of iterations in Miller-Rabin
// algorithm.
const int kAccuracy = 10;
// kHashPrime is used for calculating a hash value for a string message.
const int kHashPrime = 61;

void log(const std::string& s) {
    std::cout << s << std::endl;
}

uint128_t GenerateRandom() {
    return kGen();
}

uint128_t GetLowLevelPrime() {
    while (true) {
        uint128_t candidate = GenerateRandom();
        if (candidate % 2 == 0) {
            ++candidate;
        }
        bool is_prime = true;
        for (const auto& prime : kFirstPrimes) {
            if (candidate % prime == 0) {
                is_prime = false;
                break;
            }
        }
        if (is_prime) {
            return candidate;
        }
    }
}

uint128_t PowModulo(uint128_t base, uint128_t power, const uint128_t& mod) {
    uint128_t result = 1;
    while (power > 0) {
        if (power % 2 == 1) {
            power -= 1;
            result = (result * base) % mod;
        }
        power >>= 1;
        base = (base * base) % mod;
    }
    return result;
}

bool MillerRabin(const uint128_t& candidate, int accuracy) {
    uint128_t d = candidate - 1;
    uint128_t s = 0;
    while (d % 2 == 0) {
        d >>= 1;
        ++s;
    }
    for (int i = 0; i < accuracy; i++) {
        uint128_t a = GenerateRandom() % (candidate - 2);
        uint128_t x = PowModulo(a, d, candidate);
        if (a == 0 || x == 1 || x == candidate - 1) {
            continue;
        }
        bool probably_prime = false;
        for (int j = 1; j < s; j++) {
            x = (x * x) % candidate;
            if (x == 1) {
                return false;
            }
            if (x == candidate - 1) {
                probably_prime = true;
                break;
            }
        }
        if (!probably_prime) {
            return false;
        }
    }
    return true;
}

uint128_t GetBigPrime() {
    while (true) {
        uint128_t candidate = GetLowLevelPrime();
        auto miller_rabin = MillerRabin(candidate, kAccuracy);
        if (miller_rabin) {
            return candidate;
        }
    }
}

uint128_t GetSafePrime() {
    int i = 0;
    while (true) {
        i++;
        uint128_t prime = GetBigPrime();
        if (MillerRabin((prime - 1) / 2, 7)) {
            log("GetSafePrime: candidate" + to_string(prime) + "\n iteration: "
                + std::to_string(i));
            return prime;
        }
    }
}

uint128_t GeneratorForSafePrime(const uint128_t& prime) {
    uint128_t half_prime = (prime - 1) / 2;
    for (int i = 2; i < prime - 1; i++) {
        if (PowModulo(i, half_prime, prime) != 1) {
            return i;
        }
    }
    throw std::invalid_argument("cannot find a generator");
}

// SymbolToInt maps char value to integer values. It assumes the input to be in
// a-zA-Z0-9.
// The mapping goes as following: a-z -> 1-26; A-Z -> 27-52; 0-9 -> 53-63
uint128_t SymbolToInt(char c) {
    if (std::islower(c)) {
        return c - 'a' + 1;
    }
    if (std::isupper(c)) {
        return c - 'A' + 1 + 26;
    }
    if (std::isdigit(c)) {
        return c - '0' + 1 + 26 + 26;
    }
    return 42;
}

uint128_t HashModulo(const std::string& message, const uint128_t& mod) {
    uint128_t hash_value = 0;
    uint128_t p_pow = 1;
    for (auto c : message) {
        hash_value = (hash_value + SymbolToInt(c) * p_pow) % mod;
        p_pow = (p_pow * kHashPrime) % mod;
    }
    return hash_value;
}

// EEA holds values needed for each iteration of Extended Euclidean Algorithm.
struct EEA {
    // Reminder in a given iteration of EEA.
    int128_t r;
    // Bezout coefficients in a given iteration of EEA.
    int128_t s;
    int128_t t;
};

uint128_t Inverse(const uint128_t& num, const uint128_t& mod) {
    EEA prev = {num, 1, 0};
    EEA curr = {mod, 0, 1};
    while (curr.r) {
        auto temp = curr;
        int128_t q = prev.r / curr.r;
        curr.r = (prev.r - q * curr.r) % mod;
        curr.s = (prev.s - q * curr.s) % mod;
        curr.t = (prev.t - q * curr.t) % mod;
        prev = temp;
    }
    if (prev.s < 0) {
        prev.s += mod;
    }
    return uint128_t(prev.s);
}

uint128_t StringToUint128(const std::string& s) {
    uint128_t result = 0;
    for (auto c : s) {
        if (c < '0' || c > '9') {
            continue;
        }
        if (result > (UINT128_MAX - (c - '0')) / 10) {
            throw std::overflow_error("uint128_t overflow;");
        }
        result = result * 10 + (c - '0');
    }
    return result;
}
