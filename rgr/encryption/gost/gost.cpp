//
//  gost.cpp
//  rgr
//
//  Created by Stanislav Klepikov on 30.05.2025.
//

#include "gost.hpp"
#include <fstream>
#include <iostream>
#include <iomanip>
#include <algorithm>
#include <sstream>
#include <random>
std::vector<unsigned char> hexStringToBytes(const std::string& hex) {
    if (hex.length() % 2 != 0) {
        throw std::invalid_argument("Hex string must have an even number of characters.");
    }
    std::vector<unsigned char> bytes;
    bytes.reserve(hex.length() / 2);
    for (unsigned int i = 0; i < hex.length(); i += 2) {
        std::string byteString = hex.substr(i, 2);
        try {
            unsigned char byte = static_cast<unsigned char>(std::stoul(byteString, nullptr, 16));
            bytes.push_back(byte);
        } catch (const std::invalid_argument& e) {
            throw std::invalid_argument("Invalid character in hex string: " + byteString);
        } catch (const std::out_of_range& e) {
            throw std::out_of_range("Hex string value out of range: " + byteString);
        }
    }
    return bytes;
}

std::string bytesToHexString(const std::vector<unsigned char>& bytes) {
    std::ostringstream oss;
    oss << std::hex << std::setfill('0');
    for (unsigned char byte : bytes) {
        oss << std::setw(2) << static_cast<int>(byte);
    }
    return oss.str();
}

void generateRandomBytes(std::vector<unsigned char>& buffer, size_t length) {
    buffer.resize(length);
    // Using a simple random number generator for demonstration.
    // For cryptographic purposes, a cryptographically secure RNG is necessary.
    std::random_device rd;
    std::mt19937 gen(rd());
    std::uniform_int_distribution<> distrib(0, 255);
    for (size_t i = 0; i < length; ++i) {
        buffer[i] = static_cast<unsigned char>(distrib(gen));
    }
}

// --- PKCS#7 Padding ---
void pkcs7_pad(std::vector<unsigned char>& data, size_t block_size) {
    size_t padding_len = block_size - (data.size() % block_size);
    if (padding_len == 0) padding_len = block_size; // Add a full block of padding if already aligned
    for (size_t i = 0; i < padding_len; ++i) {
        data.push_back(static_cast<unsigned char>(padding_len));
    }
}

bool pkcs7_unpad(std::vector<unsigned char>& data) {
    if (data.empty()) return false;
    unsigned char padding_len = data.back();
    if (padding_len == 0 || padding_len > data.size() || padding_len > GOST_BLOCK_SIZE_BYTES) {
        return false; // Invalid padding length
    }
    for (size_t i = 0; i < padding_len; ++i) {
        if (data[data.size() - 1 - i] != padding_len) {
            return false; // Invalid padding bytes
        }
    }
    data.resize(data.size() - padding_len);
    return true;
}
void gost_cbc_encrypt_placeholder(const std::vector<unsigned char>& plaintext,
                                  std::vector<unsigned char>& ciphertext,
                                  const std::vector<unsigned char>& key,
                                  const std::vector<unsigned char>& iv) {
    if (key.size() != GOST_KEY_SIZE_BYTES || iv.size() != GOST_IV_SIZE_BYTES) {
        throw std::invalid_argument("Invalid key or IV size for GOST placeholder.");
    }
    std::vector<unsigned char> padded_plaintext = plaintext;
    pkcs7_pad(padded_plaintext, GOST_BLOCK_SIZE_BYTES);
    
    ciphertext.resize(padded_plaintext.size());
    // Example (dummy) operation: XOR with a repeating pattern from key and IV
    for(size_t i = 0; i < padded_plaintext.size(); ++i) {
        ciphertext[i] = padded_plaintext[i] ^ key[i % key.size()] ^ iv[i % iv.size()];
    }
}

bool gost_cbc_decrypt_placeholder(const std::vector<unsigned char>& ciphertext,
                                   std::vector<unsigned char>& plaintext,
                                   const std::vector<unsigned char>& key,
                                   const std::vector<unsigned char>& iv) {
    if (key.size() != GOST_KEY_SIZE_BYTES || iv.size() != GOST_IV_SIZE_BYTES) {
        throw std::invalid_argument("Invalid key or IV size for GOST placeholder.");
    }
    if (ciphertext.empty() || ciphertext.size() % GOST_BLOCK_SIZE_BYTES != 0) {

    }

    std::vector<unsigned char> decrypted_padded_data(ciphertext.size());
    // Example (dummy) operation: XOR with a repeating pattern from key and IV
     for(size_t i = 0; i < ciphertext.size(); ++i) {
        decrypted_padded_data[i] = ciphertext[i] ^ key[i % key.size()] ^ iv[i % iv.size()];
    }
    if (!pkcs7_unpad(decrypted_padded_data)) {
        // std::cerr << "Warning: PKCS#7 unpadding failed in decrypt placeholder." << std::endl;
        plaintext.clear(); // Or handle error more explicitly
        return false;
    }
    plaintext = decrypted_padded_data;
    return true;
}

// --- High-Level Data Encryption/Decryption Implementation ---
std::vector<unsigned char> gost_encrypt_data(const std::vector<unsigned char>& plaintext,
                                             const std::vector<unsigned char>& key,
                                             const std::vector<unsigned char>& iv) {
    if (key.size() != GOST_KEY_SIZE_BYTES) {
        throw std::invalid_argument("Encryption key must be " + std::to_string(GOST_KEY_SIZE_BYTES) + " bytes.");
    }
    if (iv.size() != GOST_IV_SIZE_BYTES) {
        throw std::invalid_argument("Encryption IV must be " + std::to_string(GOST_IV_SIZE_BYTES) + " bytes.");
    }
    std::vector<unsigned char> ciphertext;
    gost_cbc_encrypt_placeholder(plaintext, ciphertext, key, iv);
    return ciphertext;
}

std::vector<unsigned char> gost_decrypt_data(const std::vector<unsigned char>& ciphertext,
                                             const std::vector<unsigned char>& key,
                                             const std::vector<unsigned char>& iv) {
    if (key.size() != GOST_KEY_SIZE_BYTES) {
        throw std::invalid_argument("Decryption key must be " + std::to_string(GOST_KEY_SIZE_BYTES) + " bytes.");
    }
    if (iv.size() != GOST_IV_SIZE_BYTES) {
        throw std::invalid_argument("Decryption IV must be " + std::to_string(GOST_IV_SIZE_BYTES) + " bytes.");
    }
    if (ciphertext.empty()) { // Added check
        // Or throw, depends on desired behavior for empty ciphertext.
        // std::cerr << "Warning: Attempting to decrypt empty ciphertext." << std::endl;
        return {};
    }

    std::vector<unsigned char> plaintext;
    if (!gost_cbc_decrypt_placeholder(ciphertext, plaintext, key, iv)) {
        throw std::runtime_error("Decryption failed (e.g., invalid padding).");
    }
    return plaintext;
}


// --- Text Encryption/Decryption Implementation ---
GostEncryptedTextResult encryptTextGOST(const std::string& plaintext_str,
                                        const std::string& key_hex,
                                        const std::string& initial_iv_hex) {
    GostEncryptedTextResult result;
    try {
        std::vector<unsigned char> key = hexStringToBytes(key_hex);
        if (key.size() != GOST_KEY_SIZE_BYTES) {
            result.error_message = "Invalid key length. Must be " + std::to_string(GOST_KEY_SIZE_BYTES * 2) + " hex characters.";
            return result;
        }

        std::vector<unsigned char> iv;
        if (!initial_iv_hex.empty()) {
            iv = hexStringToBytes(initial_iv_hex);
            if (iv.size() != GOST_IV_SIZE_BYTES) {
                result.error_message = "Invalid IV length. Must be " + std::to_string(GOST_IV_SIZE_BYTES * 2) + " hex characters if provided.";
                return result;
            }
        } else {
            generateRandomBytes(iv, GOST_IV_SIZE_BYTES);
        }

        std::vector<unsigned char> plaintext_bytes(plaintext_str.begin(), plaintext_str.end());
        std::vector<unsigned char> ciphertext_bytes = gost_encrypt_data(plaintext_bytes, key, iv);

        result.iv_hex = bytesToHexString(iv);
        result.ciphertext_hex = bytesToHexString(ciphertext_bytes);
        result.success = true;
    } catch (const std::exception& e) {
        result.error_message = std::string("C++ Exception in encryptTextGOST: ") + e.what();
    }
    return result;
}

GostDecryptedTextResult decryptTextGOST(const std::string& iv_hex,
                                        const std::string& ciphertext_hex,
                                        const std::string& key_hex) {
    GostDecryptedTextResult result;
    try {
        std::vector<unsigned char> key = hexStringToBytes(key_hex);
        if (key.size() != GOST_KEY_SIZE_BYTES) {
            result.error_message = "Invalid key length. Must be " + std::to_string(GOST_KEY_SIZE_BYTES * 2) + " hex characters.";
            return result;
        }

        std::vector<unsigned char> iv = hexStringToBytes(iv_hex);
        if (iv.size() != GOST_IV_SIZE_BYTES) {
            result.error_message = "Invalid IV length. Must be " + std::to_string(GOST_IV_SIZE_BYTES * 2) + " hex characters.";
            return result;
        }

        std::vector<unsigned char> ciphertext_bytes = hexStringToBytes(ciphertext_hex);
        std::vector<unsigned char> plaintext_bytes = gost_decrypt_data(ciphertext_bytes, key, iv);
        
        result.plaintext = std::string(plaintext_bytes.begin(), plaintext_bytes.end());
        result.success = true;
    } catch (const std::exception& e) {
        result.error_message = std::string("C++ Exception in decryptTextGOST: ") + e.what();
    }
    return result;
}

// --- File Encryption/Decryption Implementation ---
GostFileOperationResult encryptFileGOST(const std::string& inputFilePath,
                                        const std::string& outputFilePath,
                                        const std::string& key_hex,
                                        const std::string& initial_iv_hex) {
    GostFileOperationResult fres;
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
        std::vector<unsigned char> key = hexStringToBytes(key_hex);
        if (key.size() != GOST_KEY_SIZE_BYTES) {
            fres.message = "Invalid key length for file encryption.";
            return fres;
        }

        std::vector<unsigned char> iv;
        if (!initial_iv_hex.empty()) {
            iv = hexStringToBytes(initial_iv_hex);
            if (iv.size() != GOST_IV_SIZE_BYTES) {
                fres.message = "Invalid IV length for file encryption.";
                return fres;
            }
        } else {
            generateRandomBytes(iv, GOST_IV_SIZE_BYTES);
        }
        fres.used_iv_hex = bytesToHexString(iv);

        // Write IV to the beginning of the output file
        outputFile.write(reinterpret_cast<const char*>(iv.data()), iv.size());
        if (!outputFile) {
            fres.message = "Error writing IV to output file.";
            return fres;
        }

        // Read entire file content
        inputFile.seekg(0, std::ios::end);
        std::streamsize fileSize = inputFile.tellg();
        inputFile.seekg(0, std::ios::beg);
        std::vector<unsigned char> plaintext_bytes(static_cast<size_t>(fileSize));
        if (fileSize > 0) {
             inputFile.read(reinterpret_cast<char*>(plaintext_bytes.data()), fileSize);
        }
       

        if (!inputFile && !inputFile.eof()) { // Check for read errors other than EOF
            fres.message = "Error reading input file content.";
            return fres;
        }

        if (plaintext_bytes.empty() && fileSize > 0) {
             // This case can happen if allocation failed or read failed silently
             // but usually inputFile flags would indicate error. For robustness:
            if (fileSize > 0) {
                fres.message = "Input file has size > 0 but no data was read.";
                return fres;
            }
            // If fileSize is 0, plaintext_bytes will be empty, which is fine.
        }


        std::vector<unsigned char> ciphertext_bytes = gost_encrypt_data(plaintext_bytes, key, iv);
        outputFile.write(reinterpret_cast<const char*>(ciphertext_bytes.data()), ciphertext_bytes.size());
        if (!outputFile) {
            fres.message = "Error writing ciphertext to output file.";
            return fres;
        }
        
        fres.success = true;
        fres.message = "File encrypted successfully.";

    } catch (const std::exception& e) {
        fres.message = std::string("C++ Exception during file encryption: ") + e.what();
    }

    inputFile.close();
    outputFile.close();
    return fres;
}

GostFileOperationResult decryptFileGOST(const std::string& inputFilePath,
                                        const std::string& outputFilePath,
                                        const std::string& key_hex) {
    GostFileOperationResult fres;
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
        std::vector<unsigned char> key = hexStringToBytes(key_hex);
        if (key.size() != GOST_KEY_SIZE_BYTES) {
            fres.message = "Invalid key length for file decryption.";
            return fres;
        }

        // Read IV from the beginning of the input file
        std::vector<unsigned char> iv(GOST_IV_SIZE_BYTES);
        inputFile.read(reinterpret_cast<char*>(iv.data()), iv.size());
        if (static_cast<size_t>(inputFile.gcount()) != GOST_IV_SIZE_BYTES) {
            fres.message = "Error reading IV from input file (file too short or read error).";
            return fres;
        }
        fres.used_iv_hex = bytesToHexString(iv);

    
        inputFile.seekg(0, std::ios::end);
        std::streamsize totalFileSize = inputFile.tellg();
        inputFile.seekg(GOST_IV_SIZE_BYTES, std::ios::beg);
        
        std::streamsize ciphertextFileSize = totalFileSize - GOST_IV_SIZE_BYTES;
        if (ciphertextFileSize < 0) { // Should not happen if IV read was successful
             fres.message = "Input file is smaller than IV size.";
             return fres;
        }

        std::vector<unsigned char> ciphertext_bytes(static_cast<size_t>(ciphertextFileSize));
        if (ciphertextFileSize > 0) {
             inputFile.read(reinterpret_cast<char*>(ciphertext_bytes.data()), ciphertextFileSize);
        }
       

        if (!inputFile && !inputFile.eof()) {
            fres.message = "Error reading ciphertext from input file.";
            return fres;
        }
         if (ciphertext_bytes.empty() && ciphertextFileSize > 0) {
            if (ciphertextFileSize > 0) {
                 fres.message = "Ciphertext in file has size > 0 but no data was read.";
                 return fres;
            }
        }


        std::vector<unsigned char> plaintext_bytes = gost_decrypt_data(ciphertext_bytes, key, iv);
        if (!plaintext_bytes.empty() || (ciphertext_bytes.empty() && ciphertextFileSize == 0)) {
             outputFile.write(reinterpret_cast<const char*>(plaintext_bytes.data()), plaintext_bytes.size());
             if (!outputFile) {
                 fres.message = "Error writing plaintext to output file.";
                 return fres;
             }
        } else if (!ciphertext_bytes.empty()) {
             fres.message = "Decryption resulted in empty plaintext from non-empty ciphertext (check for padding errors).";
             return fres;
        }


        fres.success = true;
        fres.message = "File decrypted successfully.";

    } catch (const std::exception& e) {
        fres.message = std::string("C++ Exception during file decryption: ") + e.what();
    }

    inputFile.close();
    outputFile.close();
    return fres;
}
