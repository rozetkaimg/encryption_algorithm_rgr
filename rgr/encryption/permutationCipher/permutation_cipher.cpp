//
//  permutation_cipher.cpp
//  rgr
//
//  Created by Stanislav Klepikov on 30.05.2025.
//
#include "permutation_cipher.hpp"
#include <vector>
#include <string>
#include <numeric>
#include <algorithm>
#include <stdexcept>
#include <fstream>
#include <sstream>
#include <iomanip>
std::vector<unsigned char> hexStringToBytes_perm_cpp(const std::string& hex) {
    if (hex.length() % 2 != 0) {
        throw std::invalid_argument("Hex string must have an even number of characters for permutation cipher.");
    }
    std::vector<unsigned char> bytes;
    bytes.reserve(hex.length() / 2);
    for (unsigned int i = 0; i < hex.length(); i += 2) {
        std::string byteString = hex.substr(i, 2);
        try {
            unsigned char byte = static_cast<unsigned char>(std::stoul(byteString, nullptr, 16));
            bytes.push_back(byte);
        } catch (const std::invalid_argument& e) {
            throw std::invalid_argument("Invalid character in hex string for permutation: " + byteString);
        } catch (const std::out_of_range& e) {
            throw std::out_of_range("Hex string value out of range for permutation: " + byteString);
        }
    }
    return bytes;
}

std::string bytesToHexString_perm_cpp(const std::vector<unsigned char>& bytes) {
    std::ostringstream oss;
    oss << std::hex << std::setfill('0');
    for (unsigned char byte : bytes) {
        oss << std::setw(2) << static_cast<int>(byte);
    }
    return oss.str();
}


void pkcs7_pad_perm(std::vector<unsigned char>& data, size_t block_size) {
    if (block_size == 0) throw std::invalid_argument("Block size cannot be zero for padding.");
    size_t padding_len = block_size - (data.size() % block_size);
    if (data.size() % block_size == 0) {
         padding_len = block_size;
    } else {
         padding_len = block_size - (data.size() % block_size);
    }
    if (padding_len > 255) throw std::runtime_error("Padding length exceeds 255.");


    for (size_t i = 0; i < padding_len; ++i) {
        data.push_back(static_cast<unsigned char>(padding_len));
    }
}

bool pkcs7_unpad_perm(std::vector<unsigned char>& data, size_t block_size_hint) {
    if (data.empty()) return false; // Cannot unpad empty data

    unsigned char padding_len = data.back();

    if (padding_len == 0 || padding_len > data.size()) {
        return false; // Invalid padding length (cannot be 0 or larger than data)
    }

    if (block_size_hint > 0 && padding_len > block_size_hint) {
        return false;
    }

    for (size_t i = 0; i < padding_len; ++i) {
        if (data[data.size() - 1 - i] != padding_len) {
            return false; // Invalid padding bytes
        }
    }
    data.resize(data.size() - padding_len);
    return true;
}

bool parse_permutation_key_cpp(const std::string& key_str, std::vector<size_t>& p_map) {
    p_map.clear();
    if (key_str.empty()) return false;

    p_map.resize(key_str.length());
    std::vector<bool> seen(key_str.length(), false);
    size_t n = key_str.length();

    for (size_t i = 0; i < n; ++i) {
        if (!isdigit(key_str[i])) return false;
        size_t val = static_cast<size_t>(key_str[i] - '0');
        if (val >= n) return false;
        if (seen[val]) return false;
        seen[val] = true;
        p_map[i] = val;
    }

    for(size_t i=0; i<n; ++i) if(!seen[i]) return false;

    return true;
}

std::vector<size_t> invert_permutation_cpp(const std::vector<size_t>& p_map) {
    if (p_map.empty()) return {};
    size_t n = p_map.size();
    std::vector<size_t> inv_map(n);
    for (size_t i = 0; i < n; ++i) {
        inv_map[p_map[i]] = i;
    }
    return inv_map;
}

std::vector<unsigned char> apply_permutation_cpp(const std::vector<unsigned char>& block, const std::vector<size_t>& p_map) {
    if (block.size() != p_map.size()) {
        throw std::invalid_argument("Block size must match permutation map size.");
    }
    size_t n = block.size();
    std::vector<unsigned char> result(n);
    for (size_t i = 0; i < n; ++i) {
        result[i] = block[p_map[i]];
    }
    return result;
}

std::vector<unsigned char> permutation_encrypt_data_cpp(const std::vector<unsigned char>& plaintext, const std::string& key_str) {
    std::vector<size_t> p_map;
    if (!parse_permutation_key_cpp(key_str, p_map) || p_map.empty()) {
        throw std::invalid_argument("Invalid permutation key string for encryption.");
    }
    size_t block_size = p_map.size();
    std::vector<unsigned char> padded_plaintext = plaintext;
    pkcs7_pad_perm(padded_plaintext, block_size);

    std::vector<unsigned char> ciphertext;
    ciphertext.reserve(padded_plaintext.size());

    for (size_t i = 0; i < padded_plaintext.size(); i += block_size) {
        std::vector<unsigned char> current_block(padded_plaintext.begin() + i, padded_plaintext.begin() + i + block_size);
        std::vector<unsigned char> permuted_block = apply_permutation_cpp(current_block, p_map);
        ciphertext.insert(ciphertext.end(), permuted_block.begin(), permuted_block.end());
    }
    return ciphertext;
}

std::vector<unsigned char> permutation_decrypt_data_cpp(const std::vector<unsigned char>& ciphertext, const std::string& key_str) {
    std::vector<size_t> p_map_encrypt;
    if (!parse_permutation_key_cpp(key_str, p_map_encrypt) || p_map_encrypt.empty()) {
        throw std::invalid_argument("Invalid permutation key string for decryption.");
    }
    size_t block_size = p_map_encrypt.size();
    if (ciphertext.size() % block_size != 0) {
        throw std::invalid_argument("Ciphertext size is not a multiple of the block size defined by the key.");
    }

    std::vector<size_t> p_map_decrypt = invert_permutation_cpp(p_map_encrypt);
    std::vector<unsigned char> padded_plaintext;
    padded_plaintext.reserve(ciphertext.size());

    for (size_t i = 0; i < ciphertext.size(); i += block_size) {
        std::vector<unsigned char> current_block(ciphertext.begin() + i, ciphertext.begin() + i + block_size);
        std::vector<unsigned char> unpermuted_block = apply_permutation_cpp(current_block, p_map_decrypt);
        padded_plaintext.insert(padded_plaintext.end(), unpermuted_block.begin(), unpermuted_block.end());
    }

    if (!pkcs7_unpad_perm(padded_plaintext, block_size)) {
        throw std::runtime_error("Permutation decryption failed due to invalid padding.");
    }
    return padded_plaintext;
}

PermutationTextResultCpp encryptTextPermutationCpp(const std::string& plaintext, const std::string& key_str) {
    PermutationTextResultCpp result;
    try {
        std::vector<unsigned char> plaintext_bytes(plaintext.begin(), plaintext.end());
        std::vector<unsigned char> ciphertext_bytes = permutation_encrypt_data_cpp(plaintext_bytes, key_str);
        result.data_hex = bytesToHexString_perm_cpp(ciphertext_bytes);
        result.success = true;
    } catch (const std::exception& e) {
        result.error_message = std::string("C++ Permutation Encrypt Text: ") + e.what();
    }
    return result;
}

PermutationTextResultCpp decryptTextPermutationCpp(const std::string& ciphertext_hex, const std::string& key_str) {
    PermutationTextResultCpp result;
    try {
        std::vector<unsigned char> ciphertext_bytes = hexStringToBytes_perm_cpp(ciphertext_hex);
        std::vector<unsigned char> plaintext_bytes = permutation_decrypt_data_cpp(ciphertext_bytes, key_str);
        result.data_hex = std::string(plaintext_bytes.begin(), plaintext_bytes.end()); // Decrypted text is string, not hex
        result.success = true;
    } catch (const std::exception& e) {
        result.error_message = std::string("C++ Permutation Decrypt Text: ") + e.what();
    }
    return result;
}

PermutationFileResultCpp encryptFilePermutationCpp(const std::string& inputFilePath, const std::string& outputFilePath, const std::string& key_str) {
    PermutationFileResultCpp fres;
    std::ifstream inputFile(inputFilePath, std::ios::binary);
    if (!inputFile) {
        fres.message = "Error opening input file: " + inputFilePath;
        return fres;
    }
    std::ofstream outputFile(outputFilePath, std::ios::binary | std::ios::trunc);
    if (!outputFile) {
        fres.message = "Error opening output file: " + outputFilePath;
        return fres;
    }

    try {
        inputFile.seekg(0, std::ios::end);
        std::streamsize fileSize = inputFile.tellg();
        inputFile.seekg(0, std::ios::beg);
        std::vector<unsigned char> plaintext_bytes(static_cast<size_t>(fileSize));
        if (fileSize > 0) {
            inputFile.read(reinterpret_cast<char*>(plaintext_bytes.data()), fileSize);
        }
        if (!inputFile && !inputFile.eof() && fileSize > 0) {
            fres.message = "Error reading input file content.";
            return fres;
        }

        std::vector<unsigned char> ciphertext_bytes = permutation_encrypt_data_cpp(plaintext_bytes, key_str);
        if (!ciphertext_bytes.empty() || (plaintext_bytes.empty() && fileSize == 0) ) {
             outputFile.write(reinterpret_cast<const char*>(ciphertext_bytes.data()), ciphertext_bytes.size());
        }
       
        if (!outputFile) {
            fres.message = "Error writing ciphertext to output file.";
            return fres;
        }
        
        fres.success = true;
        fres.message = "File successfully encrypted with permutation cipher.";
    } catch (const std::exception& e) {
        fres.message = std::string("C++ Permutation Encrypt File: ") + e.what();
    }
    inputFile.close();
    outputFile.close();
    return fres;
}

PermutationFileResultCpp decryptFilePermutationCpp(const std::string& inputFilePath, const std::string& outputFilePath, const std::string& key_str) {
    PermutationFileResultCpp fres;
    std::ifstream inputFile(inputFilePath, std::ios::binary);
    if (!inputFile) {
        fres.message = "Error opening input file: " + inputFilePath;
        return fres;
    }
    std::ofstream outputFile(outputFilePath, std::ios::binary | std::ios::trunc);
    if (!outputFile) {
        fres.message = "Error opening output file: " + outputFilePath;
        return fres;
    }

    try {
        inputFile.seekg(0, std::ios::end);
        std::streamsize fileSize = inputFile.tellg();
        inputFile.seekg(0, std::ios::beg);
        std::vector<unsigned char> ciphertext_bytes(static_cast<size_t>(fileSize));
         if (fileSize > 0) {
            inputFile.read(reinterpret_cast<char*>(ciphertext_bytes.data()), fileSize);
        }
        if (!inputFile && !inputFile.eof() && fileSize > 0) {
            fres.message = "Error reading input file content.";
            return fres;
        }

        std::vector<unsigned char> plaintext_bytes = permutation_decrypt_data_cpp(ciphertext_bytes, key_str);
         if (!plaintext_bytes.empty() || (ciphertext_bytes.empty() && fileSize == 0) ) {
            outputFile.write(reinterpret_cast<const char*>(plaintext_bytes.data()), plaintext_bytes.size());
        }
        if (!outputFile) {
            fres.message = "Error writing plaintext to output file.";
            return fres;
        }

        fres.success = true;
        fres.message = "File successfully decrypted with permutation cipher.";
    } catch (const std::exception& e) {
        fres.message = std::string("C++ Permutation Decrypt File: ") + e.what();
    }
    inputFile.close();
    outputFile.close();
    return fres;
}
