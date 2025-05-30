//
//  GOSTObjectiveCWrapper.mm
//  rgr
//
//  Created by Stanislav Klepikov on 30.05.2025.
//

#import "GOSTObjectiveCWrapper.h"
#include "gost.hpp"

#import <string>
#import <vector>
#import <sstream>
#import <iomanip>

static std::string NSStringToStdString(NSString *nsString) {
    if (nsString == nil) {
        return "";
    }
    return std::string([nsString UTF8String]);
}

static NSString *StdStringToNSString(const std::string& stdString) {
    return [NSString stringWithUTF8String:stdString.c_str()];
}


@implementation GOSTObjectiveCWrapper

- (NSString *)generateGOSTKeyHex {
    try {
        std::vector<unsigned char> key_bytes;
        generateRandomBytes(key_bytes, GOST_KEY_SIZE_BYTES);
        return StdStringToNSString(bytesToHexString(key_bytes));
    } catch (const std::exception& e) {
        return [NSString stringWithFormat:@"Error: C++ Exception during key generation - %s", e.what()];
    } catch (...) {
        return @"Error: Unknown C++ exception during key generation.";
    }
}

- (NSString *)generateGOSTIvHex {
    try {
        std::vector<unsigned char> iv_bytes;
        generateRandomBytes(iv_bytes, GOST_IV_SIZE_BYTES);
        return StdStringToNSString(bytesToHexString(iv_bytes));
    } catch (const std::exception& e) {
        return [NSString stringWithFormat:@"Error: C++ Exception during IV generation - %s", e.what()];
    } catch (...) {
        return @"Error: Unknown C++ exception during IV generation.";
    }
}

- (NSString *)encryptTextGOST:(NSString *)plaintext
                       keyHex:(NSString *)keyHex
               initialIvHex:(nullable NSString *)initialIvHex {
    if (plaintext == nil || keyHex == nil) {
        return @"Error: Plaintext and KeyHex parameters cannot be nil.";
    }
    if ([plaintext length] == 0) {
    }
    if ([keyHex length] != GOST_KEY_SIZE_BYTES * 2) {
        return [NSString stringWithFormat:@"Error: KeyHex must be %u characters long.", GOST_KEY_SIZE_BYTES * 2];
    }
    if (initialIvHex != nil && [initialIvHex length] > 0 && [initialIvHex length] != GOST_IV_SIZE_BYTES * 2) {
         return [NSString stringWithFormat:@"Error: If provided, InitialIvHex must be %u characters long.", GOST_IV_SIZE_BYTES * 2];
    }

    try {
        std::string std_plaintext = NSStringToStdString(plaintext);
        std::string std_key_hex = NSStringToStdString(keyHex);
        std::string std_initial_iv_hex = (initialIvHex != nil) ? NSStringToStdString(initialIvHex) : "";

        GostEncryptedTextResult cpp_result = encryptTextGOST(std_plaintext, std_key_hex, std_initial_iv_hex);

        if (cpp_result.success) {
            return StdStringToNSString(cpp_result.iv_hex + ":" + cpp_result.ciphertext_hex);
        } else {
            return [NSString stringWithFormat:@"Error: Encryption failed - %s", cpp_result.error_message.c_str()];
        }

    } catch (const std::exception& e) {
        return [NSString stringWithFormat:@"Error: C++ Exception during text encryption - %s", e.what()];
    } catch (...) {
        return @"Error: Unknown C++ exception during text encryption.";
    }
}

- (NSString *)decryptTextGOST:(NSString *)combinedIvCiphertextHex
                       keyHex:(NSString *)keyHex {
    if (combinedIvCiphertextHex == nil || keyHex == nil) {
        return @"Error: CombinedIVCiphertextHex and KeyHex parameters cannot be nil.";
    }
     if ([combinedIvCiphertextHex length] == 0) {
        return @"Error: CombinedIVCiphertextHex cannot be empty.";
    }
    if ([keyHex length] != GOST_KEY_SIZE_BYTES * 2) {
        return [NSString stringWithFormat:@"Error: KeyHex must be %u characters long.", GOST_KEY_SIZE_BYTES * 2];
    }
    
    // Split combinedIvCiphertextHex into IV hex and Ciphertext hex
    NSArray<NSString *> *parts = [combinedIvCiphertextHex componentsSeparatedByString:@":"];
    if ([parts count] != 2) {
        return @"Error: combinedIvCiphertextHex format is invalid. Expected 'ivHex:ciphertextHex'.";
    }
    NSString *ivHexStr = parts[0];
    NSString *ciphertextHexStr = parts[1];

    if ([ivHexStr length] != GOST_IV_SIZE_BYTES * 2) {
        return [NSString stringWithFormat:@"Error: IV part of combined string must be %u hex characters.", GOST_IV_SIZE_BYTES * 2];
    }

    try {
        std::string std_iv_hex = NSStringToStdString(ivHexStr);
        std::string std_ciphertext_hex = NSStringToStdString(ciphertextHexStr);
        std::string std_key_hex = NSStringToStdString(keyHex);

        GostDecryptedTextResult cpp_result = decryptTextGOST(std_iv_hex, std_ciphertext_hex, std_key_hex);

        if (cpp_result.success) {
            return StdStringToNSString(cpp_result.plaintext);
        } else {
            return [NSString stringWithFormat:@"Error: Decryption failed - %s", cpp_result.error_message.c_str()];
        }

    } catch (const std::exception& e) {
        return [NSString stringWithFormat:@"Error: C++ Exception during text decryption - %s", e.what()];
    } catch (...) {
        return @"Error: Unknown C++ exception during text decryption.";
    }
}


- (NSString *)encryptFileGOST:(NSString *)inputFilePath
                 toOutputFile:(NSString *)outputFilePath
                       keyHex:(NSString *)keyHex
               initialIvHex:(nullable NSString *)initialIvHex {

    if (inputFilePath == nil || outputFilePath == nil || keyHex == nil) {
        return @"Error: InputFilePath, OutputFilePath, and KeyHex parameters cannot be nil for file encryption.";
    }
    if ([inputFilePath length] == 0 || [outputFilePath length] == 0 || [keyHex length] == 0) {
        return @"Error: InputFilePath, OutputFilePath, and KeyHex parameters cannot be empty strings for file encryption.";
    }
    if ([keyHex length] != GOST_KEY_SIZE_BYTES * 2) {
        return [NSString stringWithFormat:@"Error: KeyHex must be %u characters long.", GOST_KEY_SIZE_BYTES * 2];
    }
    if (initialIvHex != nil && [initialIvHex length] > 0 && [initialIvHex length] != GOST_IV_SIZE_BYTES * 2) {
         return [NSString stringWithFormat:@"Error: If provided, InitialIvHex must be %u characters long.", GOST_IV_SIZE_BYTES * 2];
    }

    try {
        std::string std_input_path = NSStringToStdString(inputFilePath);
        std::string std_output_path = NSStringToStdString(outputFilePath);
        std::string std_key_hex = NSStringToStdString(keyHex);
        std::string std_initial_iv_hex = (initialIvHex != nil) ? NSStringToStdString(initialIvHex) : "";

        GostFileOperationResult cpp_fres = encryptFileGOST(std_input_path, std_output_path, std_key_hex, std_initial_iv_hex);

        if (cpp_fres.success) {
            return [NSString stringWithFormat:@"Success: File '%@' encrypted. IV Used: %s",
                    [outputFilePath lastPathComponent], cpp_fres.used_iv_hex.c_str()];
        } else {
            return [NSString stringWithFormat:@"Error: File encryption failed - %s", cpp_fres.message.c_str()];
        }

    } catch (const std::exception& e) {
        return [NSString stringWithFormat:@"Error: C++ Exception during file encryption - %s", e.what()];
    } catch (...) {
        return @"Error: Unknown C++ exception during file encryption.";
    }
}

- (NSString *)decryptFileGOST:(NSString *)inputFilePath
                 toOutputFile:(NSString *)outputFilePath
                       keyHex:(NSString *)keyHex {
    if (inputFilePath == nil || outputFilePath == nil || keyHex == nil) {
        return @"Error: InputFilePath, OutputFilePath, and KeyHex parameters cannot be nil for file decryption.";
    }
    if ([inputFilePath length] == 0 || [outputFilePath length] == 0 || [keyHex length] == 0) {
        return @"Error: InputFilePath, OutputFilePath, and KeyHex parameters cannot be empty strings for file decryption.";
    }
     if ([keyHex length] != GOST_KEY_SIZE_BYTES * 2) {
        return [NSString stringWithFormat:@"Error: KeyHex must be %u characters long.", GOST_KEY_SIZE_BYTES * 2];
    }

    try {
        std::string std_input_path = NSStringToStdString(inputFilePath);
        std::string std_output_path = NSStringToStdString(outputFilePath);
        std::string std_key_hex = NSStringToStdString(keyHex);

        GostFileOperationResult cpp_fres = decryptFileGOST(std_input_path, std_output_path, std_key_hex);

        if (cpp_fres.success) {
             return [NSString stringWithFormat:@"Success: File '%@' decrypted. IV Used (read from file): %s",
                    [outputFilePath lastPathComponent], cpp_fres.used_iv_hex.c_str()];
        } else {
            return [NSString stringWithFormat:@"Error: File decryption failed - %s", cpp_fres.message.c_str()];
        }
    } catch (const std::exception& e) {
        return [NSString stringWithFormat:@"Error: C++ Exception during file decryption - %s", e.what()];
    } catch (...) {
        return @"Error: Unknown C++ exception during file decryption.";
    }
}

@end
