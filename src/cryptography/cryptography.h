//
// Created by Masha on 2024-12-11.
//

#ifndef CRYPTOGRAPHY_H
#define CRYPTOGRAPHY_H
#include <string>
#include <vector>
#include <boost/multiprecision/cpp_int.hpp>

#include "signature.h"


class ElGamal {
public:
    ElGamal() = default;
    // Generates a safe prime to be used later for singing messages.
    boost::multiprecision::uint128_t GeneratePrime();
    // Finds a generator of Z_p. Expects prime to be already set.
    boost::multiprecision::uint128_t GenerateGenerator();
    // Generates public key from given private key. If private_key is not set,
    // it will be generated randomly. The function expects prime and generator to be set.
    std::pair<boost::multiprecision::uint128_t,
        boost::multiprecision::uint128_t> GeneratePublicKey(
        const boost::multiprecision::uint128_t& private_key = 0);

    void SetPrime(boost::multiprecision::uint128_t p);
    void SetGenerator(boost::multiprecision::uint128_t g);

    // Sings a message with given parameter k. It is advised to not set k
    // explicitely and allow it to be generated randomly. The function expects
    // prime, generator, private key and public key to be set.
    std::pair<boost::multiprecision::uint128_t,
        boost::multiprecision::uint128_t> Sign(const std::string& message,
                                               boost::multiprecision::uint128_t
                                               k = 0) const;
    // Verifies if a given signature is correct for a given message.
    static bool Verify(const std::string& message, const Signature& signature);

private:
    boost::multiprecision::uint128_t prime_;
    boost::multiprecision::uint128_t generator_;
    boost::multiprecision::uint128_t private_key_;
    boost::multiprecision::uint128_t public_key_;
};

#endif //CRYPTOGRAPHY_H
