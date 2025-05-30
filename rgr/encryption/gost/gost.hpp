//
//  gost.hpp
//  rgr
//
//  Created by Stanislav Klepikov on 30.05.2025.
//

#ifndef GOST_CIPHER_HPP
#define GOST_CIPHER_HPP

#include <string>
#include <vector>
#include <stdexcept>
const unsigned int GOST_KEY_SIZE_BITS = 256;
const unsigned int GOST_KEY_SIZE_BYTES = GOST_KEY_SIZE_BITS / 8;
const unsigned int GOST_BLOCK_SIZE_BYTES = 8; // 64-bit blocks
const unsigned int GOST_IV_SIZE_BYTES = GOST_BLOCK_SIZE_BYTES;
std::vector<unsigned char> hexStringToBytes(const std::string& hex);
std::string bytesToHexString(const std::vector<unsigned char>& bytes);
void generateRandomBytes(std::vector<unsigned char>& buffer, size_t length);
void gost_cbc_encrypt_placeholder(const std::vector<unsigned char>& plaintext,
                                  std::vector<unsigned char>& ciphertext,
                                  const std::vector<unsigned char>& key,
                                  const std::vector<unsigned char>& iv);
bool gost_cbc_decrypt_placeholder(const std::vector<unsigned char>& ciphertext,
                                   std::vector<unsigned char>& plaintext,
                                   const std::vector<unsigned char>& key,
                                   const std::vector<unsigned char>& iv);
std::vector<unsigned char> gost_encrypt_data(const std::vector<unsigned char>& plaintext,
                                             const std::vector<unsigned char>& key,
                                             const std::vector<unsigned char>& iv);
std::vector<unsigned char> gost_decrypt_data(const std::vector<unsigned char>& ciphertext,
                                             const std::vector<unsigned char>& key,
                                             const std::vector<unsigned char>& iv);
struct GostEncryptedTextResult {
    std::string iv_hex;
    std::string ciphertext_hex;
    bool success = false;
    std::string error_message;
};

GostEncryptedTextResult encryptTextGOST(const std::string& plaintext,
                                        const std::string& key_hex,
                                        const std::string& iv_hex = ""); // Optional IV hex, if empty, generate

struct GostDecryptedTextResult {
    std::string plaintext;
    bool success = false;
    std::string error_message;
};

GostDecryptedTextResult decryptTextGOST(const std::string& iv_hex,
                                        const std::string& ciphertext_hex,
                                        const std::string& key_hex);
struct GostFileOperationResult {
    bool success = false;
    std::string message;
    std::string used_iv_hex;
};
GostFileOperationResult encryptFileGOST(const std::string& inputFilePath,
                                        const std::string& outputFilePath,
                                        const std::string& key_hex,
                                        const std::string& initial_iv_hex = "");
GostFileOperationResult decryptFileGOST(const std::string& inputFilePath,
                                        const std::string& outputFilePath,
                                        const std::string& key_hex);

#endif // GOST_CIPHER_HPP
