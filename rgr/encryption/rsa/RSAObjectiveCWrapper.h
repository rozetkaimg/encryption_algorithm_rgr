//
//  RSAObjectiveCWrapper.h
//  rgr
//
//  Created by Stanislav Klepikov on 28.05.2025.
//
#import <Foundation/Foundation.h>

NS_ASSUME_NONNULL_BEGIN

@interface RSAObjectiveCWrapper : NSObject

- (NSString *)generateRSAKeysWithBits:(unsigned int)bits;

- (NSString *)encryptRSAWithPlaintext:(NSString *)plaintext
                                 nHex:(NSString *)nHex
                                 eHex:(NSString *)eHex;

- (NSString *)decryptRSAWithCiphertext:(NSString *)hexCiphertextBlocks
                                  nHex:(NSString *)nHex
                                  dHex:(NSString *)dHex;

- (NSString *)encryptFileRSA:(NSString *)inputFilePath
              toOutputFile:(NSString *)outputFilePath
                      nHex:(NSString *)nHex
                      eHex:(NSString *)eHex;

- (NSString *)decryptFileRSA:(NSString *)inputFilePath
              toOutputFile:(NSString *)outputFilePath
                      nHex:(NSString *)nHex
                      dHex:(NSString *)dHex;
@end
NS_ASSUME_NONNULL_END
