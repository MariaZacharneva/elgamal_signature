//
// Created by Masha on 2024-12-11.
//

#ifndef SIGNATURE_H
#define SIGNATURE_H
#include <string>
#include <boost/multiprecision/cpp_int.hpp>


struct Signature {
    boost::multiprecision::uint128_t prime;
    boost::multiprecision::uint128_t generator;
    boost::multiprecision::uint128_t public_key;
    boost::multiprecision::uint128_t signature_r;
    boost::multiprecision::uint128_t signature_s;
};

struct StringSignature {
    std::string message;
    std::string prime;
    std::string generator;
    std::string public_key;
    std::string signature_r;
    std::string signature_s;
};


#endif //SIGNATURE_H
