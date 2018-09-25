//
//  Tools.m
//  PCSC-UI
//
//  Created by 刘维凯 on 2018/9/20.
//  Copyright © 2018年 刘维凯. All rights reserved.
//

#import "Tools.h"
#import <CommonCrypto/CommonCryptor.h>
#import <CommonCrypto/CommonDigest.h>
#import "PCSC/winscard.h"
#import "GTMBase64.h"

@implementation Tools

+ (BOOL)isNullToString:(id)string
{
    if ([string isEqual:@"NULL"] || [string isKindOfClass:[NSNull class]] || [string isEqual:[NSNull null]] || [string isEqual:NULL] || [[string class] isSubclassOfClass:[NSNull class]] || string == nil || string == NULL || [string isKindOfClass:[NSNull class]] || [[string stringByTrimmingCharactersInSet:[NSCharacterSet whitespaceAndNewlineCharacterSet]] length]==0 || [string isEqualToString:@"<null>"] || [string isEqualToString:@"(null)"])
    {
        return YES;
    }else
    {
        return NO;
    }
}

+ (NSString *)ByteToString:(unsigned char *)inData
{
    NSMutableString *hexString = [NSMutableString string];
    for (int i=0; i<sizeof(inData); i++)
    {
        [hexString appendFormat:@"%02X", inData[i]];
    }
    return [NSString stringWithFormat:@"%@",hexString];
}

+ (NSString *)ByteToString:(unsigned char *)inData andDataLen:(uint32_t)len{
    NSMutableString *hexString = [NSMutableString string];
    for (int i=0; i < len; i++)
    {
        [hexString appendFormat:@"%02X", inData[i]];
    }
    return [NSString stringWithFormat:@"%@",hexString];
}

+ (NSData*)stringToByte:(NSString*)string
{
    NSString *hexString=[[string uppercaseString] stringByReplacingOccurrencesOfString:@" " withString:@""];
    if ([hexString length]%2!=0) {
        return nil;
    }
    Byte tempbyt[1]={0};
    NSMutableData* bytes=[NSMutableData data];
    for(int i=0;i<[hexString length];i++)
    {
        unichar hex_char1 = [hexString characterAtIndex:i];
        int int_ch1;
        if(hex_char1 >= '0' && hex_char1 <='9')
            int_ch1 = (hex_char1-48)*16;
        else if(hex_char1 >= 'A' && hex_char1 <='F')
            int_ch1 = (hex_char1-55)*16;
        else
            return nil;
        i++;
        
        unichar hex_char2 = [hexString characterAtIndex:i];
        int int_ch2;
        if(hex_char2 >= '0' && hex_char2 <='9')
            int_ch2 = (hex_char2-48);
        else if(hex_char2 >= 'A' && hex_char2 <='F')
            int_ch2 = hex_char2-55;
        else
            return nil;
        
        tempbyt[0] = int_ch1+int_ch2;
        [bytes appendBytes:tempbyt length:1];
    }
    return bytes;
}

//加密
+(NSString *) encryptUseDES:(NSString *)clearText key:(NSString *)key
{
    NSString *ciphertext = nil;
    NSData *textData = [self stringToByte:clearText];
    NSData *textKey = [self stringToByte:key];
    NSUInteger dataLength = [textData length];
    unsigned char buffer[1024];
    memset(buffer, 0, sizeof(char));
    size_t numBytesEncrypted = 0;
    //const void *iv = (const void *) [key UTF8String];
    
    CCCryptorStatus cryptStatus = CCCrypt(kCCEncrypt,//加密
                                          kCCAlgorithmDES ,//加密根据那个标准
                                          kCCOptionPKCS7Padding ,// 选项分组密码算法
                                          [textKey bytes],//秘钥
                                          kCCKeySizeDES,//DES秘钥大小
                                          NULL ,//可选的初始矢量
                                          [textData bytes]  ,//数据的存储单元
                                          dataLength,//数据的大小
                                          buffer,
                                          1024,
                                          &numBytesEncrypted);
    if (cryptStatus == kCCSuccess) {
        NSLog(@"DES加密成功");
        NSData *d = [NSData dataWithBytes:buffer length:(NSUInteger)numBytesEncrypted];
        ciphertext = [self ByteToString:[d bytes]];
        
    }else{
        NSLog(@"DES加密失败");
    }
    
    //free(buffer);
    return ciphertext;
}

//解密
+(NSString *) decryptUseDES:(NSString *)plainText key:(NSString *)key
{
    NSString *cleartext ;
    NSData *textData = [self stringToByte:plainText];
    NSUInteger dataLength = [textData length];
    NSUInteger bufferSize=([textData length] + kCCKeySizeDES) & ~(kCCKeySizeDES -1);
    
    unsigned char buffer[bufferSize];
    memset(buffer, 0, sizeof(char));
    size_t numBytesEncrypted ;
    const void *iv = (const void *) [key UTF8String];
    
    CCCryptorStatus cryptStatus = CCCrypt(kCCDecrypt,
                                          kCCAlgorithmDES,
                                          kCCOptionPKCS7Padding ,
                                          [key UTF8String],
                                          kCCKeySizeDES,
                                          iv,
                                          [textData bytes]  ,
                                          dataLength,
                                          buffer,
                                          bufferSize,
                                          &numBytesEncrypted);
    
    if (cryptStatus == kCCSuccess) {
        NSLog(@"DES解密成功");
        NSData *data = [NSData dataWithBytes:buffer length:numBytesEncrypted];
        cleartext = [[NSString alloc]initWithData:data encoding:NSUTF8StringEncoding];
    }else{
        NSLog(@"DES解密失败");
    }
    
    // free(buffer);
    return cleartext;
    
}

+ (NSString*)TripleDES:(NSString*)plainText key:(NSString *)key encryptOrDecrypt:(CCOperation)encryptOrDecrypt
{
    
    const void *vplainText;
    size_t plainTextBufferSize;
    if (encryptOrDecrypt == kCCDecrypt)//解密
    {
        NSData *EncryptData = [GTMBase64 decodeData:[plainText dataUsingEncoding:NSUTF8StringEncoding]];
        plainTextBufferSize = [EncryptData length];
        vplainText = [EncryptData bytes];
    }
    else //加密
    {
        NSData* data = [self stringToByte:plainText];
        plainTextBufferSize = [data length];
        vplainText = (const void *)[data bytes];
    }
    
    CCCryptorStatus ccStatus;
    uint8_t *bufferPtr = NULL;
    size_t bufferPtrSize = 0;
    size_t movedBytes = 0;
    
    bufferPtrSize = (plainTextBufferSize + kCCBlockSize3DES) & ~(kCCBlockSize3DES - 1);
    bufferPtr = malloc( bufferPtrSize * sizeof(uint8_t));
    memset((void *)bufferPtr, 0x0, bufferPtrSize);
    // memset((void *) iv, 0x0, (size_t) sizeof(iv));
    NSData *textKey = [self stringToByte:key];
    //const void *vkey = (const void *)[key UTF8String];
    // NSString *initVec = @"init Vec";
    //const void *vinitVec = (const void *) [initVec UTF8String];
    //  Byte iv[] = {0x12, 0x34, 0x56, 0x78, 0x90, 0xAB, 0xCD, 0xEF};
    ccStatus = CCCrypt(encryptOrDecrypt,
                       kCCAlgorithm3DES,
                       kCCOptionPKCS7Padding,
                       [textKey bytes],
                       kCCKeySize3DES,
                       nil,
                       vplainText,
                       plainTextBufferSize,
                       (void *)bufferPtr,
                       bufferPtrSize,
                       &movedBytes);
    if (ccStatus == kCCSuccess) NSLog(@"SUCCESS");
    else if (ccStatus == kCCParamError) return @"PARAM ERROR";
     else if (ccStatus == kCCBufferTooSmall) return @"BUFFER TOO SMALL";
     else if (ccStatus == kCCMemoryFailure) return @"MEMORY FAILURE";
     else if (ccStatus == kCCAlignmentError) return @"ALIGNMENT";
     else if (ccStatus == kCCDecodeError) return @"DECODE ERROR";
     else if (ccStatus == kCCUnimplemented) return @"UNIMPLEMENTED";
    
    NSString *ciphertext = nil;
    
    if (encryptOrDecrypt == kCCDecrypt)
    {
        ciphertext = [[NSString alloc] initWithData:[NSData dataWithBytes:(const void *)bufferPtr
                                                               length:(NSUInteger)movedBytes]
                                       encoding:NSUTF8StringEncoding];
    }
    else
    {
        NSData *d = [NSData dataWithBytes:bufferPtr length:(NSUInteger)movedBytes];
        ciphertext = [self ByteToString:[d bytes]];
    }
    
    return ciphertext;
}

@end
