//
// Created by Masha on 2024-12-11.
//

#include "cryptography.h"
#include <boost/multiprecision/cpp_int.hpp>
#include <boost/random.hpp>
#include <utility>

#include "signature.h"
#include "tools.h"

using namespace boost::multiprecision;
using namespace boost::random;

void ElGamal::SetPrime(uint128_t p) {
    prime_ = std::move(p);
}

void ElGamal::SetGenerator(uint128_t g) {
    generator_ = std::move(g);
}

uint128_t ElGamal::GeneratePrime() {
    prime_ = GetSafePrime();
    return prime_;
}

uint128_t ElGamal::GenerateGenerator() {
    if (prime_ == 0) {
        throw std::invalid_argument("Cannot generate generator: prime not set");
    }
    uint128_t half_prime = (prime_ - 1) / 2;
    for (int i = 2; i < prime_ - 1; i++) {
        if (PowModulo(i, half_prime, prime_) != 1) {
            generator_ = i;
            log("Generator: " + to_string(generator_));
            return i;
        }
    }
    throw std::invalid_argument("Cannot generate a generator");
}

std::pair<uint128_t, uint128_t> ElGamal::GeneratePublicKey(
    const uint128_t& private_key) {
    if (prime_ == 0 || generator_ == 0) {
        throw std::invalid_argument(
            "Cannot generate public key: prime or generator not set");
    }

    // If private key is not set explicitely, it is generated randomly.
    if (private_key != 0) {
        private_key_ = private_key;
    } else {
        private_key_ = 0;
        while (private_key_ == 0 || private_key_ == 1) {
            private_key_ = GenerateRandom() % prime_;
        }
    }

    public_key_ = PowModulo(generator_, private_key_, prime_);
    log("Private key: " + to_string(private_key_) + "Public key: " + to_string(
            public_key_));
    return std::make_pair(private_key_, public_key_);
}

std::pair<uint128_t, uint128_t> ElGamal::Sign(const std::string& message,
                                              uint128_t k) const {
    if (prime_ == 0 || generator_ == 0
        || public_key_ == 0 || private_key_ == 0) {
        throw std::invalid_argument(
            "Cannot sign the message: not enough parameters");
    }

    // If k is not set, generating k which is relatively prime to p - 1.
    while (k == 0 || k % 2 == 0 || k % ((prime_ - 1) / 2) == 0) {
        k = GenerateRandom() % (prime_ - 2);
    }

    uint128_t r = PowModulo(generator_, k, prime_);
    uint128_t k_inverse = Inverse(k, prime_ - 1);
    uint128_t s = (HashModulo(message, prime_) + prime_ - 1 - (private_key_ * r)
                   % (prime_ - 1))
                  * k_inverse % (prime_ - 1);
    return std::make_pair(r, s);
}

bool ElGamal::Verify(const std::string& message, const Signature& signature) {
    if (signature.signature_r <= 0
        || signature.signature_r >= signature.prime
        || signature.signature_s <= 0
        || signature.signature_s >= signature.prime - 1) {
        return false;
    }
    // Checking ElGamal signature condition: g^H(m) = (y^r) * (r^s).
    uint128_t hash = HashModulo(message, signature.prime);
    uint128_t g_H = PowModulo(signature.generator, hash, signature.prime);
    uint128_t y_r = PowModulo(signature.public_key, signature.signature_r,
                              signature.prime);
    uint128_t r_s = PowModulo(signature.signature_r, signature.signature_s,
                              signature.prime);
    uint128_t y_r_r_s = (y_r * r_s) % signature.prime;
    return g_H == y_r_r_s;
}
