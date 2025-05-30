//
//  permutation_cipher.hpp
//  rgr
//
//  Created by Stanislav Klepikov on 30.05.2025.
//

#ifndef PERMUTATION_CIPHER_HPP
#define PERMUTATION_CIPHER_HPP

#include <stdexcept>
#include <string>
#include <vector>

bool parse_permutation_key_cpp(const std::string &key_str,
                               std::vector<size_t> &p_map);
std::vector<size_t> invert_permutation_cpp(const std::vector<size_t> &p_map);
std::vector<unsigned char>
apply_permutation_cpp(const std::vector<unsigned char> &block,
                      const std::vector<size_t> &p_map);
void pkcs7_pad_perm(std::vector<unsigned char> &data, size_t block_size);
bool pkcs7_unpad_perm(std::vector<unsigned char> &data,
                      size_t block_size_hint); 
std::vector<unsigned char>
permutation_encrypt_data_cpp(const std::vector<unsigned char> &plaintext,
                             const std::string &key_str);
std::vector<unsigned char>
permutation_decrypt_data_cpp(const std::vector<unsigned char> &ciphertext,
                             const std::string &key_str);
struct PermutationTextResultCpp {
    std::string data_hex;
    bool success = false;
    std::string error_message;
};
PermutationTextResultCpp encryptTextPermutationCpp(const std::string &plaintext,
                                                   const std::string &key_str);
PermutationTextResultCpp
decryptTextPermutationCpp(const std::string &ciphertext_hex,
                          const std::string &key_str);
struct PermutationFileResultCpp {
    bool success = false;
    std::string message;
};
PermutationFileResultCpp
encryptFilePermutationCpp(const std::string &inputFilePath,
                          const std::string &outputFilePath,
                          const std::string &key_str);
PermutationFileResultCpp
decryptFilePermutationCpp(const std::string &inputFilePath,
                          const std::string &outputFilePath,
                          const std::string &key_str);
std::vector<unsigned char> hexStringToBytes_perm_cpp(const std::string &hex);
std::string bytesToHexString_perm_cpp(const std::vector<unsigned char> &bytes);

#endif // PERMUTATION_CIPHER_HPP
