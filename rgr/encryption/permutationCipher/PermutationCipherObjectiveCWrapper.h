//
//  PermutationCipherObjectiveCWrapper.h
//  rgr
//
//  Created by Stanislav Klepikov on 30.05.2025.
//

#import <Foundation/Foundation.h>

NS_ASSUME_NONNULL_BEGIN

@interface PermutationCipherObjectiveCWrapper : NSObject

- (NSString *)encryptTextPermutation:(NSString *)plaintext keyString:(NSString *)keyString;

- (NSString *)decryptTextPermutation:(NSString *)hexCiphertext keyString:(NSString *)keyString;
- (NSString *)encryptFilePermutation:(NSString *)inputFilePath
                        toOutputFile:(NSString *)outputFilePath
                           keyString:(NSString *)keyString;
- (NSString *)decryptFilePermutation:(NSString *)inputFilePath
                        toOutputFile:(NSString *)outputFilePath
                           keyString:(NSString *)keyString;

@end

NS_ASSUME_NONNULL_END
