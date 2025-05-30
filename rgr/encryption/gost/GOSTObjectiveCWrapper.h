//
//  GOSTObjectiveCWrapper.h
//  rgr
//
//  Created by Stanislav Klepikov on 30.05.2025.
//

#import <Foundation/Foundation.h>

NS_ASSUME_NONNULL_BEGIN

@interface GOSTObjectiveCWrapper : NSObject

/**
 * Generates a random 256-bit GOST key and returns it as a hexadecimal string.
 * @return A 64-character hexadecimal string representing the 256-bit key, or an error message.
 */
- (NSString *)generateGOSTKeyHex;

/**
 * Generates a random 64-bit GOST IV and returns it as a hexadecimal string.
 * @return A 16-character hexadecimal string representing the 64-bit IV, or an error message.
 */
- (NSString *)generateGOSTIvHex;

/**
 * Encrypts a plaintext string using GOST 28147-89 in CBC mode with PKCS#7 padding.
 *
 * @param plaintext The string to encrypt.
 * @param keyHex A 64-character hexadecimal string representing the 256-bit encryption key.
 * @param initialIvHex An optional 16-character hexadecimal string for the 64-bit Initialization Vector (IV).
 * If nil or empty, a random IV will be generated and used.
 * @return A string in the format "ivHex:ciphertextHex" on success (e.g., "0123...def:abc012...789").
 * Returns an error message string (often prefixed with "Error:") on failure.
 */
- (NSString *)encryptTextGOST:(NSString *)plaintext
                       keyHex:(NSString *)keyHex
               initialIvHex:(nullable NSString *)initialIvHex;

/**
 * Decrypts a combined IV and ciphertext hexadecimal string using GOST 28147-89.
 *
 * @param combinedIvCiphertextHex A string in the format "ivHex:ciphertextHex", where ivHex is the 16-character
 * hex IV and ciphertextHex is the hex-encoded ciphertext.
 * @param keyHex A 64-character hexadecimal string representing the 256-bit decryption key.
 * @return The decrypted plaintext string on success.
 * Returns an error message string (often prefixed with "Error:") on failure (e.g., bad key, corrupted data, padding error).
 */
- (NSString *)decryptTextGOST:(NSString *)combinedIvCiphertextHex
                       keyHex:(NSString *)keyHex;

/**
 * Encrypts a file using GOST 28147-89 in CBC mode.
 * The 8-byte IV (either provided or randomly generated) is prepended to the ciphertext in the output file.
 *
 * @param inputFilePath Path to the file to encrypt.
 * @param outputFilePath Path where the encrypted file will be saved.
 * @param keyHex A 64-character hexadecimal string (256-bit key).
 * @param initialIvHex An optional 16-character hexadecimal string (64-bit IV). If nil or empty, a random IV is generated.
 * @return A success message string including the output file name and the hexadecimal representation of the IV used
 * (e.g., "Success: File 'out.enc' encrypted. IV Used: 0123...def").
 * Returns an error message string (often prefixed with "Error:") on failure.
 */
- (NSString *)encryptFileGOST:(NSString *)inputFilePath
                 toOutputFile:(NSString *)outputFilePath
                       keyHex:(NSString *)keyHex
               initialIvHex:(nullable NSString *)initialIvHex;

/**
 * Decrypts a file that was encrypted using GOST 28147-89 (CBC mode).
 * The input file is expected to have the 8-byte IV prepended to the ciphertext.
 *
 * @param inputFilePath Path to the encrypted file.
 * @param outputFilePath Path where the decrypted file will be saved.
 * @param keyHex A 64-character hexadecimal string (256-bit key).
 * @return A success message string including the output file name and the IV read from file (e.g. "Success: File 'out.txt' decrypted. IV Used: 0123...def").
 * Returns an error message string (often prefixed with "Error:") on failure.
 */
- (NSString *)decryptFileGOST:(NSString *)inputFilePath
                 toOutputFile:(NSString *)outputFilePath
                       keyHex:(NSString *)keyHex;

@end

NS_ASSUME_NONNULL_END
