#include "rsa.hpp"
#include <fstream>
#include <iostream>
#include <stdexcept>
#include <iomanip>
#include <algorithm>
#include <vector>
#include <string>
#include <sstream>

BigInt generateProbablePrime(unsigned int bits, boost::random::mt19937& rng) {
    if (bits < 64) {
        std::cerr << "Warning: Prime bit length " << bits << " is very short for security demonstrations." << std::endl;
        if (bits < 3) throw std::invalid_argument("Prime bit length must be at least 3.");
    }

    BigInt lower_bound = BigInt(1) << (bits - 1);
    BigInt upper_bound = (BigInt(1) << bits) - 1;

    if (lower_bound < 2) lower_bound = 2;
    if (upper_bound < lower_bound) upper_bound = lower_bound + 1;

    boost::random::uniform_int_distribution<BigInt> dist(lower_bound, upper_bound);
    BigInt num_candidate;
    unsigned int miller_rabin_iterations = 25;

    while (true) {
        num_candidate = dist(rng);
        num_candidate |= BigInt(1);

        if (num_candidate > upper_bound || num_candidate < lower_bound) continue;
        if (num_candidate < 3) continue;

        if (boost::multiprecision::miller_rabin_test(num_candidate, miller_rabin_iterations, rng)) {
            return num_candidate;
        }
    }
}

KeyPair generateKeys(unsigned int bits, boost::random::mt19937& rng) {
    if (bits < 128) {
        std::cerr << "Warning: Key bit length " << bits << " is too short for any security. Demonstration only." << std::endl;
        if (bits < 6) throw std::invalid_argument("Total key bit length must be at least 6 for two 3-bit primes.");
    }
    unsigned int prime_bits = bits / 2;
    if (prime_bits < 3) prime_bits = 3;

    BigInt p = generateProbablePrime(prime_bits, rng);
    BigInt q = generateProbablePrime(prime_bits, rng);

    while (p == q) {
        q = generateProbablePrime(prime_bits, rng);
    }

    BigInt n = p * q;
    BigInt phi_n = (p - 1) * (q - 1);

    BigInt e = 65537;
    if (e >= phi_n || boost::multiprecision::gcd(e, phi_n) != 1) {
        e = 3;
        while (e < phi_n && boost::multiprecision::gcd(e, phi_n) != 1) {
            e += 2;
        }
        if (e >= phi_n) {
            throw std::runtime_error("Failed to find a suitable public exponent e.");
        }
    }

    BigInt d = boost::integer::mod_inverse(e, phi_n);
    if (d == 0 && phi_n != 1) {
        throw std::runtime_error("Modular inverse for e and phi_n could not be found.");
    }

    return {{n, e}, {n, d}};
}

BigInt bytesToBigInt(const std::vector<unsigned char>& bytes) {
    BigInt res = 0;
    if (bytes.empty()) return res;
    for (unsigned char byte : bytes) {
        res <<= 8;
        res |= byte;
    }
    return res;
}

std::vector<unsigned char> bigIntToBytes(const BigInt& val, size_t fixed_output_byte_length) {
    std::vector<unsigned char> bytes;
    BigInt temp = val;

    while (temp > 0) {
        bytes.insert(bytes.begin(), static_cast<unsigned char>(temp & 0xFF));
        temp >>= 8;
    }

    if (fixed_output_byte_length > 0) {
        if (bytes.size() < fixed_output_byte_length) {
            bytes.insert(bytes.begin(), fixed_output_byte_length - bytes.size(), 0);
        } else if (bytes.size() > fixed_output_byte_length) {
            std::cerr << "Warning: BigIntToBytes conversion resulted in " << bytes.size()
                      << " bytes, but expected " << fixed_output_byte_length
                      << ". Truncating (this might indicate an issue)." << std::endl;
            bytes.erase(bytes.begin(), bytes.begin() + (bytes.size() - fixed_output_byte_length));
        }
    } else if (val == 0) {
         bytes.push_back(0);
    }
    
    if (val == 0 && fixed_output_byte_length > 0) {
        bytes.assign(fixed_output_byte_length, 0);
    }

    return bytes;
}

size_t getApproximateByteLength(const BigInt& n) {
    if (n == 0) return 1;
    return (static_cast<size_t>(msb(n)) + 8) / 8;
}

BigInt encryptBlock(const std::vector<unsigned char>& block, const PublicKey& key) {
    BigInt m = bytesToBigInt(block);
    if (m >= key.n) {
        throw std::runtime_error("Plaintext block integer m is too large for the key modulus n.");
    }
    return boost::multiprecision::powm(m, key.e, key.n);
}

std::vector<unsigned char> decryptBlock(const BigInt& encrypted_block, const PrivateKey& key, size_t expected_byte_length) {
    if (encrypted_block >= key.n) {
        throw std::runtime_error("Ciphertext block integer C is too large for the key modulus n.");
    }
    BigInt m = boost::multiprecision::powm(encrypted_block, key.d, key.n);
    return bigIntToBytes(m, expected_byte_length);
}

std::vector<BigInt> encryptText(const std::string& text, const PublicKey& key, size_t key_n_byte_length) {
    std::vector<BigInt> encrypted_blocks;
    std::vector<unsigned char> byte_text(text.begin(), text.end());

    size_t block_size_data = key_n_byte_length > 1 ? key_n_byte_length - 1 : 1;
    if (key_n_byte_length <= 1) throw std::runtime_error("Key modulus n is too small (<=1 byte).");

    for (size_t i = 0; i < byte_text.size(); i += block_size_data) {
        size_t current_block_actual_size = std::min(block_size_data, byte_text.size() - i);
        std::vector<unsigned char> block(byte_text.begin() + i, byte_text.begin() + i + current_block_actual_size);
        encrypted_blocks.push_back(encryptBlock(block, key));
    }
    return encrypted_blocks;
}

std::string decryptText(const std::vector<BigInt>& encrypted_data, const PrivateKey& key, size_t key_n_byte_length) {
    std::vector<unsigned char> all_decrypted_bytes;
    size_t block_size_data = key_n_byte_length > 1 ? key_n_byte_length - 1 : 1;

    for (const auto& encrypted_block_val : encrypted_data) {
        std::vector<unsigned char> decrypted_padded_block_bytes = decryptBlock(encrypted_block_val, key, block_size_data);

        all_decrypted_bytes.insert(all_decrypted_bytes.end(),
                                     decrypted_padded_block_bytes.begin(),
                                     decrypted_padded_block_bytes.end());
    }

    size_t last_block_start = encrypted_data.empty() ? 0 : (encrypted_data.size() - 1) * block_size_data;
    size_t first_zero = std::string::npos;

    for(size_t i = last_block_start; i < all_decrypted_bytes.size(); ++i){
        if(all_decrypted_bytes[i] == 0) {
            bool all_zeros_after = true;
            for(size_t j = i + 1; j < all_decrypted_bytes.size(); ++j) {
                if(all_decrypted_bytes[j] != 0) {
                    all_zeros_after = false;
                    break;
                }
            }
            if(all_zeros_after){
                first_zero = i;
                break;
            }
        }
    }
    
    if(first_zero != std::string::npos && first_zero < all_decrypted_bytes.size()){
        all_decrypted_bytes.resize(first_zero);
    }
    
    return std::string(all_decrypted_bytes.begin(), all_decrypted_bytes.end());
}


bool encryptFile(const std::string& inputFilePath, const std::string& outputFilePath, const PublicKey& key, size_t key_n_byte_length) {
    std::ifstream inputFile(inputFilePath, std::ios::binary);
    std::ofstream outputFile(outputFilePath);

    if (!inputFile.is_open()) {
        std::cerr << "Error opening input file: " << inputFilePath << std::endl;
        return false;
    }
    if (!outputFile.is_open()) {
        std::cerr << "Error opening output file: " << outputFilePath << std::endl;
        return false;
    }

    size_t block_size_data = key_n_byte_length > 1 ? key_n_byte_length - 1 : 1;
    if (key_n_byte_length <= 1) {
        std::cerr << "Key modulus n is too small for file encryption." << std::endl;
        return false;
    }

    std::vector<unsigned char> buffer(block_size_data);
    while (inputFile) {
        inputFile.read(reinterpret_cast<char*>(buffer.data()), block_size_data);
        size_t bytes_read = static_cast<size_t>(inputFile.gcount());

        if (bytes_read == 0) break;

        std::vector<unsigned char> current_block(buffer.begin(), buffer.begin() + bytes_read);

        BigInt encrypted_val = encryptBlock(current_block, key);
        outputFile << std::hex << encrypted_val << std::endl;
    }

    inputFile.close();
    outputFile.close();
    return true;
}



// Вспомогательная функция is_string_all_whitespace должна быть определена где-то
bool is_string_all_whitespace(const std::string& s) {
    if (s.empty()) {
        return true; // Считаем пустую строку пробельной для пропуска
    }
    return std::all_of(s.begin(), s.end(), [](unsigned char c){
        return std::isspace(c);
    });
}

bool decryptFile(const std::string& inputFilePath, const std::string& outputFilePath, const PrivateKey& key, size_t key_n_byte_length) {
    std::ifstream inputFile(inputFilePath);
    std::ofstream outputFile(outputFilePath, std::ios::binary | std::ios::trunc);

    if (!inputFile.is_open()) {
        std::cerr << "Error opening input file: " << inputFilePath << std::endl;
        return false;
    }
    if (!outputFile.is_open()) {
        std::cerr << "Error opening output file: " << outputFilePath << std::endl;
        inputFile.close();
        return false;
    }

    size_t block_size_data = key_n_byte_length > 1 ? key_n_byte_length - 1 : 1;
    if (key_n_byte_length <= 1) {
        std::cerr << "Key modulus n is too small for file decryption." << std::endl;
        inputFile.close();
        outputFile.close();
        return false;
    }

    std::string original_hex_line;
    bool SucceededAtLeastOnce = false;
    bool hadProcessableLines = false;
    int lineNumber = 0;
    std::vector<BigInt> encrypted_blocks;

    while (std::getline(inputFile, original_hex_line)) {
        lineNumber++;

        std::string processed_line = original_hex_line;

        // 1. Тщательная очистка строки от начальных/конечных пробелов
        processed_line.erase(0, processed_line.find_first_not_of(" \t\n\r\f\v"));
        processed_line.erase(processed_line.find_last_not_of(" \t\n\r\f\v") + 1);

        // 2. Удаляем квадратные скобки, если они обрамляют строку
        if (!processed_line.empty() && processed_line.front() == '[' && processed_line.back() == ']') {
            if (processed_line.length() >= 2) {
                 processed_line = processed_line.substr(1, processed_line.length() - 2);
            } else { // Строка была "[]", "[", или "]"
                 processed_line.clear();
            }
            // Повторная обрезка на случай, если внутри скобок были пробелы по краям
            processed_line.erase(0, processed_line.find_first_not_of(" \t\n\r\f\v"));
            processed_line.erase(processed_line.find_last_not_of(" \t\n\r\f\v") + 1);
        }

        if (processed_line.empty()) { // Если строка стала пустой после очистки, пропускаем
            continue;
        }
        hadProcessableLines = true;

        std::istringstream iss(processed_line);
        BigInt encrypted_block_val;
        iss >> std::hex >> encrypted_block_val;

        // Строгая проверка:
        // 1. iss.fail() будет true, если формат HEX нарушен.
        // 2. !iss.eof() будет true, если после успешного чтения числа в строке остались еще какие-то символы.
        //    Мы ожидаем, что вся processed_line будет валидным HEX и будет полностью считана.
        if (iss.fail() || !iss.eof()) {
            std::cerr << "Line " << lineNumber << ": Error parsing hex string or trailing data. Original: [" << original_hex_line << "], Processed for parsing: [" << processed_line << "]" << std::endl;
            // Для детальной отладки можно раскомментировать:
            // std::cerr << "    Stream state: good=" << iss.good() << ", eof=" << iss.eof() << ", fail=" << iss.fail() << ", bad=" << iss.bad();
            // if (!iss.fail() && !iss.eof()) {
            //     std::cerr << ", peek char ASCII: " << static_cast<int>(iss.peek());
            // }
            // std::cerr << std::endl;
            continue;
        }
        encrypted_blocks.push_back(encrypted_block_val);
    }

    inputFile.close();

    if (!hadProcessableLines && encrypted_blocks.empty()) {
         outputFile.close();
         return true;
    }

    std::vector<unsigned char> all_decrypted_bytes;
    for (size_t i = 0; i < encrypted_blocks.size(); ++i) {
        const auto& encrypted_block_val = encrypted_blocks[i];
        std::vector<unsigned char> decrypted_bytes = decryptBlock(encrypted_block_val, key, block_size_data);

        if (!decrypted_bytes.empty()) {
             all_decrypted_bytes.insert(all_decrypted_bytes.end(), decrypted_bytes.begin(), decrypted_bytes.end());
             SucceededAtLeastOnce = true;
        } else if (block_size_data > 0) { // Только если ожидались непустые данные
             // Можно добавить предупреждение, если блок данных ожидался, но дешифровался в пустой вектор.
             // std::cerr << "Warning: Decryption of block " << i+1 << " (hex: " << encrypted_blocks[i] << ") resulted in empty data when " << block_size_data << " bytes were expected." << std::endl;
        }
    }

    // --- Начало эвристического удаления паддинга (заполнения) ---
    // Эта логика пытается удалить нулевые байты, которые могли быть добавлены как паддинг
    // к последнему блоку данных. Она не идеальна.
    if (!all_decrypted_bytes.empty() && !encrypted_blocks.empty()) { // Только если есть что удалять
        size_t first_zero_in_potential_padding = std::string::npos;
        // Ищем с конца, но не раньше начала последнего блока данных
        size_t start_search_index = (all_decrypted_bytes.size() > block_size_data) ? (all_decrypted_bytes.size() - block_size_data) : 0;

        for (size_t i = all_decrypted_bytes.size(); i > start_search_index; --i) {
            if (all_decrypted_bytes[i-1] == 0) {
                bool all_zeros_before_this = true;
                for (size_t j = i-1; j > start_search_index; --j) { // Проверяем, все ли нули до этой позиции в пределах последнего блока
                     if(all_decrypted_bytes[j-1] != 0) {
                        all_zeros_before_this = false;
                        break;
                     }
                }
                 if (all_zeros_before_this) { // Если это начало последовательности нулей в конце
                    first_zero_in_potential_padding = i-1;
                 } else { // Наткнулись на не-ноль, значит, последовательность нулей (если была) закончилась
                    break;
                 }

            } else { // Наткнулись на не-ноль, значит, паддинга нет (или он уже закончился)
                break;
            }
        }
        
        if(first_zero_in_potential_padding != std::string::npos){
            all_decrypted_bytes.resize(first_zero_in_potential_padding);
        }
    }
    // --- Конец эвристического удаления паддинга ---


    if (!all_decrypted_bytes.empty()) {
        outputFile.write(reinterpret_cast<const char*>(all_decrypted_bytes.data()), all_decrypted_bytes.size());
        if (!outputFile) {
            std::cerr << "Critical error writing decrypted data to output file." << std::endl;
            outputFile.close();
            return false;
        }
    }

    outputFile.close();

    if (hadProcessableLines && !SucceededAtLeastOnce) {
        std::cerr << "Warning: Input file contained processable lines, but no blocks were successfully decrypted." << std::endl;
        return false;
    }

    return SucceededAtLeastOnce || !hadProcessableLines;
}
