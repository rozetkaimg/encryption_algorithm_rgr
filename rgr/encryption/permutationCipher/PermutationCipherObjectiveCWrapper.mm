//
//  PermutationCipherObjectiveCWrapper.mm
//  rgr
//
//  Created by Stanislav Klepikov on 30.05.2025.
//

#import "PermutationCipherObjectiveCWrapper.h"
#include "permutation_cipher.hpp"

#import <string>
#import <vector>
#import <sstream>
#import <iomanip>

static std::string NSStringToStdString_Perm(NSString *nsString) {
    if (nsString == nil) {
        return "";
    }
    return std::string([nsString UTF8String]);
}

static NSString *StdStringToNSString_Perm(const std::string& stdString) {
    return [NSString stringWithUTF8String:stdString.c_str()];
}

@implementation PermutationCipherObjectiveCWrapper

- (NSString *)encryptTextPermutation:(NSString *)plaintext keyString:(NSString *)keyString {
    if (plaintext == nil || keyString == nil) {
        return @"Error: Plaintext and KeyString parameters cannot be nil for permutation.";
    }
    if ([keyString length] == 0) {
        return @"Error: Permutation KeyString cannot be empty.";
    }

    try {
        std::string std_plaintext = NSStringToStdString_Perm(plaintext);
        std::string std_key_string = NSStringToStdString_Perm(keyString);

        PermutationTextResultCpp cpp_result = encryptTextPermutationCpp(std_plaintext, std_key_string);

        if (cpp_result.success) {
            return StdStringToNSString_Perm(cpp_result.data_hex);
        } else {
            return [NSString stringWithFormat:@"Error: Permutation Encrypt Text - %s", cpp_result.error_message.c_str()];
        }
    } catch (const std::exception& e) {
        return [NSString stringWithFormat:@"Error: C++ Exception during permutation text encryption - %s", e.what()];
    } catch (...) {
        return @"Error: Unknown C++ exception during permutation text encryption.";
    }
}

- (NSString *)decryptTextPermutation:(NSString *)hexCiphertext keyString:(NSString *)keyString {
    if (hexCiphertext == nil || keyString == nil) {
        return @"Error: HexCiphertext and KeyString parameters cannot be nil for permutation.";
    }
    if ([keyString length] == 0) {
        return @"Error: Permutation KeyString cannot be empty.";
    }
    if ([hexCiphertext length] == 0 && [keyString length] > 0) {
        return @"";
    }

    try {
        std::string std_hex_ciphertext = NSStringToStdString_Perm(hexCiphertext);
        std::string std_key_string = NSStringToStdString_Perm(keyString);

        PermutationTextResultCpp cpp_result = decryptTextPermutationCpp(std_hex_ciphertext, std_key_string);

        if (cpp_result.success) {
            return StdStringToNSString_Perm(cpp_result.data_hex); 
        } else {
            return [NSString stringWithFormat:@"Error: Permutation Decrypt Text - %s", cpp_result.error_message.c_str()];
        }
    } catch (const std::exception& e) {
        return [NSString stringWithFormat:@"Error: C++ Exception during permutation text decryption - %s", e.what()];
    } catch (...) {
        return @"Error: Unknown C++ exception during permutation text decryption.";
    }
}

- (NSString *)encryptFilePermutation:(NSString *)inputFilePath
                        toOutputFile:(NSString *)outputFilePath
                           keyString:(NSString *)keyString {
    if (inputFilePath == nil || outputFilePath == nil || keyString == nil) {
        return @"Error: File paths and KeyString cannot be nil for permutation file encryption.";
    }
    if ([inputFilePath length] == 0 || [outputFilePath length] == 0 || [keyString length] == 0) {
        return @"Error: File paths and KeyString cannot be empty for permutation file encryption.";
    }

    try {
        std::string std_input_path = NSStringToStdString_Perm(inputFilePath);
        std::string std_output_path = NSStringToStdString_Perm(outputFilePath);
        std::string std_key_string = NSStringToStdString_Perm(keyString);

        PermutationFileResultCpp cpp_fres = encryptFilePermutationCpp(std_input_path, std_output_path, std_key_string);

        if (cpp_fres.success) {
            return StdStringToNSString_Perm(cpp_fres.message);
        } else {
            return [NSString stringWithFormat:@"Error: Permutation Encrypt File - %s", cpp_fres.message.c_str()];
        }
    } catch (const std::exception& e) {
        return [NSString stringWithFormat:@"Error: C++ Exception during permutation file encryption - %s", e.what()];
    } catch (...) {
        return @"Error: Unknown C++ exception during permutation file encryption.";
    }
}

- (NSString *)decryptFilePermutation:(NSString *)inputFilePath
                        toOutputFile:(NSString *)outputFilePath
                           keyString:(NSString *)keyString {
    if (inputFilePath == nil || outputFilePath == nil || keyString == nil) {
        return @"Error: File paths and KeyString cannot be nil for permutation file decryption.";
    }
    if ([inputFilePath length] == 0 || [outputFilePath length] == 0 || [keyString length] == 0) {
        return @"Error: File paths and KeyString cannot be empty for permutation file decryption.";
    }

    try {
        std::string std_input_path = NSStringToStdString_Perm(inputFilePath);
        std::string std_output_path = NSStringToStdString_Perm(outputFilePath);
        std::string std_key_string = NSStringToStdString_Perm(keyString);

        PermutationFileResultCpp cpp_fres = decryptFilePermutationCpp(std_input_path, std_output_path, std_key_string);

        if (cpp_fres.success) {
            return StdStringToNSString_Perm(cpp_fres.message);
        } else {
            return [NSString stringWithFormat:@"Error: Permutation Decrypt File - %s", cpp_fres.message.c_str()];
        }
    } catch (const std::exception& e) {
        return [NSString stringWithFormat:@"Error: C++ Exception during permutation file decryption - %s", e.what()];
    } catch (...) {
        return @"Error: Unknown C++ exception during permutation file decryption.";
    }
}

@end
