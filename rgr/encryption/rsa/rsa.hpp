//
//  rsa.hpp
//  rgr
//
//  Created by Stanislav Klepikov on 28.05.2025.
//

#ifndef rsa_hpp
#define rsa_hpp
#define RSA_BIGINT_HPP
#include <string>
#include <vector>
#include <boost/multiprecision/cpp_int.hpp>
#include <boost/multiprecision/miller_rabin.hpp>
#include <boost/random.hpp>
#include <boost/integer/mod_inverse.hpp>
using BigInt = boost::multiprecision::cpp_int;
struct PublicKey {
    BigInt n;
    BigInt e;
};
struct PrivateKey {
    BigInt n;
    BigInt d;
};
struct KeyPair {
    PublicKey pubKey;
    PrivateKey privKey;
};
KeyPair generateKeys(unsigned int bits, boost::random::mt19937& rng);
BigInt encryptBlock(const std::vector<unsigned char>& block, const PublicKey& key);
std::vector<unsigned char> decryptBlock(const BigInt& encrypted_block, const PrivateKey& key, size_t expected_byte_length);
std::vector<BigInt> encryptText(const std::string& text, const PublicKey& key, size_t key_byte_length);
std::string decryptText(const std::vector<BigInt>& encrypted_data, const PrivateKey& key, size_t key_byte_length);
bool encryptFile(const std::string& inputFilePath, const std::string& outputFilePath, const PublicKey& key, size_t key_byte_length);
bool decryptFile(const std::string& inputFilePath, const std::string& outputFilePath, const PrivateKey& key, size_t key_byte_length);
std::vector<unsigned char> bigIntToBytes(const BigInt& val, size_t fixed_output_byte_length = 0);
BigInt bytesToBigInt(const std::vector<unsigned char>& bytes);
size_t getApproximateByteLength(const BigInt& n);
#endif /* rsa_hpp */
