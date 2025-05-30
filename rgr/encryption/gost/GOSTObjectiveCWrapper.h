//
//  GOSTObjectiveCWrapper.h
//  rgr
//
//  Created by Stanislav Klepikov on 30.05.2025.
//

#import <Foundation/Foundation.h>

NS_ASSUME_NONNULL_BEGIN

@interface GOSTObjectiveCWrapper : NSObject

 -(NSString *)generateGOSTKeyHex;

- (NSString *)generateGOSTIvHex;

- (NSString *)encryptTextGOST:(NSString *)plaintext
                       keyHex:(NSString *)keyHex
                 initialIvHex:(nullable NSString *)initialIvHex;

- (NSString *)decryptTextGOST:(NSString *)combinedIvCiphertextHex
                       keyHex:(NSString *)keyHex;
- (NSString *)encryptFileGOST:(NSString *)inputFilePath
                 toOutputFile:(NSString *)outputFilePath
                       keyHex:(NSString *)keyHex
                 initialIvHex:(nullable NSString *)initialIvHex;
- (NSString *)decryptFileGOST:(NSString *)inputFilePath
                 toOutputFile:(NSString *)outputFilePath
                       keyHex:(NSString *)keyHex;

@end

NS_ASSUME_NONNULL_END
