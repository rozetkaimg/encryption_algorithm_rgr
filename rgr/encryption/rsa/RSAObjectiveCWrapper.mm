#import "RSAObjectiveCWrapper.h"


#include "rsa.hpp"
#import <string>
#import <vector>
#import <sstream>
#import <iomanip>
#import <random>
#import <chrono>


static std::string NSStringToStdString(NSString *nsString) {
    if (nsString == nil) {
        return "";
    }
    return std::string([nsString UTF8String]);
}

static NSString *StdStringToNSString(const std::string& stdString) {
    return [NSString stringWithUTF8String:stdString.c_str()];
}

// Вспомогательная функция для конвертации 16-ричного NSString в BigInt
static BigInt HexNSStringToBigInt(NSString *hexNSString) {
    if (hexNSString == nil || [hexNSString length] == 0) {
        throw std::runtime_error("Hex string for BigInt is empty or nil");
    }
    std::string hexStdString = NSStringToStdString(hexNSString);
    BigInt val;
    std::stringstream ss;
    ss << std::hex << hexStdString;
    ss >> val;
    if (ss.fail() && !ss.eof()) { // Проверка на ошибку парсинга
        throw std::runtime_error("Failed to parse hex string to BigInt: " + hexStdString);
    }
    return val;
}

// Вспомогательная функция для конвертации BigInt в 16-ричный NSString
static NSString *BigIntToHexNSString(const BigInt& val) {
    std::ostringstream oss;
    oss << std::hex << val;
    return StdStringToNSString(oss.str());
}


@implementation RSAObjectiveCWrapper


static boost::random::mt19937& get_rng() {
    static boost::random::mt19937 rng(static_cast<unsigned long>(
        std::chrono::system_clock::now().time_since_epoch().count()
    ));
    return rng;
}

- (NSString *)generateRSAKeysWithBits:(unsigned int)bits {
    try {
        KeyPair keys = generateKeys(bits, get_rng()); // Вызов C++ функции

        NSString *n_hex = BigIntToHexNSString(keys.pubKey.n);
        NSString *e_hex = BigIntToHexNSString(keys.pubKey.e);
        NSString *d_hex = BigIntToHexNSString(keys.privKey.d);

        return [NSString stringWithFormat:@"%@;%@;%@", n_hex, e_hex, d_hex];
    } catch (const std::exception& e) {
        return [NSString stringWithFormat:@"Error: C++ Exception during key generation - %s", e.what()];
    } catch (...) {
        return @"Error: Unknown C++ exception during key generation.";
    }
}

- (NSString *)encryptRSAWithPlaintext:(NSString *)plaintext nHex:(NSString *)nHex eHex:(NSString *)eHex {
    if (plaintext == nil || nHex == nil || eHex == nil) {
        return @"Error: Input parameters cannot be nil.";
    }
    if ([plaintext length] == 0) {
        return @"Error: Plaintext cannot be empty.";
    }
    try {
        std::string std_plaintext = NSStringToStdString(plaintext);
        PublicKey pubKey;
        pubKey.n = HexNSStringToBigInt(nHex);
        pubKey.e = HexNSStringToBigInt(eHex);

        size_t key_n_byte_length = getApproximateByteLength(pubKey.n);
        if (key_n_byte_length == 0) { // Дополнительная проверка
             return @"Error: Key modulus N results in zero byte length.";
        }

        // Вызов C++ функции шифрования текста
        std::vector<BigInt> encrypted_blocks = encryptText(std_plaintext, pubKey, key_n_byte_length);

        // Конвертируем вектор BigInt в одну строку (hex-значения, разделенные пробелом)
        std::ostringstream oss;
        for (size_t i = 0; i < encrypted_blocks.size(); ++i) {
            oss << std::hex << encrypted_blocks[i];
            if (i < encrypted_blocks.size() - 1) {
                oss << " "; // Разделитель
            }
        }
        return StdStringToNSString(oss.str());

    } catch (const std::exception& e) {
        return [NSString stringWithFormat:@"Error: C++ Exception during encryption - %s", e.what()];
    } catch (...) {
        return @"Error: Unknown C++ exception during encryption.";
    }
}

- (NSString *)decryptRSAWithCiphertext:(NSString *)hexCiphertext nHex:(NSString *)nHex dHex:(NSString *)dHex {
    if (hexCiphertext == nil || nHex == nil || dHex == nil) {
        return @"Error: Input parameters cannot be nil.";
    }
     if ([hexCiphertext length] == 0) {
        return @"Error: Ciphertext cannot be empty.";
    }

    try {
        PrivateKey privKey;
        privKey.n = HexNSStringToBigInt(nHex);
        privKey.d = HexNSStringToBigInt(dHex);

        size_t key_n_byte_length = getApproximateByteLength(privKey.n);
         if (key_n_byte_length == 0) {
             return @"Error: Key modulus N results in zero byte length.";
        }

        // Парсим входную строку hexCiphertext (hex-значения BigInt, разделенные пробелом) в std::vector<BigInt>
        std::vector<BigInt> encrypted_blocks_vec;
        std::string std_hex_ciphertext = NSStringToStdString(hexCiphertext);
        std::stringstream ss_parser(std_hex_ciphertext);
        std::string segment;

        while(std::getline(ss_parser, segment, ' ')) { // Разделяем по пробелу
            if (segment.empty()) continue;
            BigInt val;
            std::stringstream ss_segment;
            ss_segment << std::hex << segment;
            ss_segment >> val;
             if (ss_segment.fail() && !ss_segment.eof()) {
                throw std::runtime_error("Failed to parse ciphertext segment: " + segment);
            }
            encrypted_blocks_vec.push_back(val);
        }
        
        if (encrypted_blocks_vec.empty() && ![hexCiphertext isEqualToString:@"0"] && [hexCiphertext length] > 0) {
        
             bool hasSpace = false;
             for (NSUInteger i = 0; i < [hexCiphertext length]; ++i) {
                 if ([hexCiphertext characterAtIndex:i] == ' ') {
                     hasSpace = true;
                     break;
                 }
             }
             if (!hasSpace) { // Если пробелов нет, пробуем как один блок
                 encrypted_blocks_vec.clear();
                 encrypted_blocks_vec.push_back(HexNSStringToBigInt(hexCiphertext));
             } else if (encrypted_blocks_vec.empty()) { // Если пробелы были, но ничего не распарсили
                 throw std::runtime_error("Ciphertext format error: contains spaces but no valid hex blocks parsed.");
             }
        }


        // Вызов C++ функции расшифрования текста
        std::string decrypted_std_string = decryptText(encrypted_blocks_vec, privKey, key_n_byte_length);
        
        return StdStringToNSString(decrypted_std_string);

    } catch (const std::exception& e) {
        return [NSString stringWithFormat:@"Error: C++ Exception during decryption - %s", e.what()];
    } catch (...) {
        return @"Error: Unknown C++ exception during decryption.";
    }
}


- (NSString *)encryptFileRSA:(NSString *)inputFilePath
              toOutputFile:(NSString *)outputFilePath
                      nHex:(NSString *)nHex
                      eHex:(NSString *)eHex {
    if (inputFilePath == nil || outputFilePath == nil || nHex == nil || eHex == nil) {
        return @"Error: Входные параметры для шифрования файла не могут быть nil.";
    }
    if ([inputFilePath length] == 0 || [outputFilePath length] == 0 || [nHex length] == 0 || [eHex length] == 0) {
        return @"Error: Входные параметры для шифрования файла не могут быть пустыми строками.";
    }

    try {
        std::string std_input_path = NSStringToStdString(inputFilePath);
        std::string std_output_path = NSStringToStdString(outputFilePath);

        PublicKey pubKey;
        pubKey.n = HexNSStringToBigInt(nHex); // Убедитесь, что BigInt и HexNSStringToBigInt определены и работают
        pubKey.e = HexNSStringToBigInt(eHex);

        size_t key_n_byte_length = getApproximateByteLength(pubKey.n); // Убедитесь, что эта C++ функция существует
        if (key_n_byte_length == 0) {
             return @"Error: Модуль ключа RSA N приводит к нулевой длине в байтах (шифрование файла).";
        }

    
        bool success = encryptFile(std_input_path, std_output_path, pubKey, key_n_byte_length);

        if (success) {
            return [NSString stringWithFormat:@"Файл успешно зашифрован в: %@", [outputFilePath lastPathComponent]];
        } else {
            return @"Error: Ошибка C++ при шифровании файла. Проверьте консоль на предмет C++ ошибок.";
        }

    } catch (const std::exception& e) {
        return [NSString stringWithFormat:@"Error: C++ Исключение во время шифрования файла - %s", e.what()];
    } catch (...) {
        return @"Error: Неизвестное C++ исключение во время шифрования файла.";
    }
}

- (NSString *)decryptFileRSA:(NSString *)inputFilePath
              toOutputFile:(NSString *)outputFilePath
                      nHex:(NSString *)nHex
                      dHex:(NSString *)dHex {
    if (inputFilePath == nil || outputFilePath == nil || nHex == nil || dHex == nil) {
        return @"Error: Входные параметры для расшифрования файла не могут быть nil.";
    }
    if ([inputFilePath length] == 0 || [outputFilePath length] == 0 || [nHex length] == 0 || [dHex length] == 0) {
        return @"Error: Входные параметры для расшифрования файла не могут быть пустыми строками.";
    }
    
    try {
        std::string std_input_path = NSStringToStdString(inputFilePath);
        std::string std_output_path = NSStringToStdString(outputFilePath);

        PrivateKey privKey;
        privKey.n = HexNSStringToBigInt(nHex);
        privKey.d = HexNSStringToBigInt(dHex);
        
        size_t key_n_byte_length = getApproximateByteLength(privKey.n);
         if (key_n_byte_length == 0) {
             return @"Error: Модуль ключа RSA N приводит к нулевой длине в байтах (расшифрование файла).";
        }

        bool success = decryptFile(std_input_path, std_output_path, privKey, key_n_byte_length);

        if (success) {
            return [NSString stringWithFormat:@"Файл успешно расшифрован в: %@", [outputFilePath lastPathComponent]];
        } else {
            return @"Error: Ошибка C++ при расшифровании файла. Проверьте консоль на предмет C++ ошибок.";
        }

    } catch (const std::exception& e) {
        return [NSString stringWithFormat:@"Error: C++ Исключение во время расшифрования файла - %s", e.what()];
    } catch (...) {
        return @"Error: Неизвестное C++ исключение во время расшифрования файла.";
    }
}
@end
