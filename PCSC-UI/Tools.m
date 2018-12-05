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

+ (NSString*)TripleDES:(NSString*)plainText key:(NSString *)key encryptOrDecrypt:(CCOperation)encryptOrDecrypt
{
    
    const void *vplainText;
    size_t plainTextBufferSize;
    if (encryptOrDecrypt == kCCDecrypt)//解密
    {
        // 未实现
        return nil;
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
        // 未实现
    }
    else
    {
        NSData *d = [NSData dataWithBytes:bufferPtr length:(NSUInteger)movedBytes];
        ciphertext = [self ByteToString:[d bytes]];
    }
    
    return ciphertext;
}

+ (NSString*)PBOC_DES_MAC:(NSString*)key data:(NSString *)data
{
    unsigned char I0[8];
    memset(I0, 0, 8);
    int TLen = 0;
    int DBz = 0;
    if (data.length % 16 != 0 || data.length % 16 == 0){
        TLen = (((int)(data.length / 16)) + 1) * 16;
        DBz = (int)(data.length / 16) + 1;
        data = [data stringByAppendingString:@"8"];
        TLen = (int)TLen - (int)data.length;
        for (int i = 0; i < TLen; i++){
            data = [data stringByAppendingString:@"0"];
        }
    }
    NSData *mData = [self stringToByte:data];
    unsigned char *fillData = [mData bytes];
    NSLog(@"加密数据:%@\n",[self ByteToString:fillData andDataLen:[mData length]]);
    unsigned char D1[8];
    unsigned char D2[8];
    unsigned char I2[8];
    unsigned char I3[8];
    unsigned char bytTemp[8];
    unsigned char bytTempX[8];
    if (DBz >= 1){
        for (int i = 0; i < 8; i++){
            D1[i] = fillData[i];
        }
        for (int i = 0; i < 8; i++){
            bytTemp[i] = (unsigned char)(I0[i] ^ D1[i]);
        }
        memcpy(I2, bytTemp, 8);
        NSLog(@"I2:%@\n",[self ByteToString:I2 andDataLen:8]);
        NSString *enRet = [self encryptUseDES:[self ByteToString:I2 andDataLen:8] key:key];
        memcpy(bytTempX, [[self stringToByte:enRet] bytes], 8);
        NSLog(@"bytTempX:%@\n",[self ByteToString:bytTempX andDataLen:8]);
    }
    memset(bytTemp, 0, 8);
    if (DBz >= 2){
        for (int j = 2; j <= DBz; j++){
            for (int i = (j - 1) * 8; i < j * 8; i++)
            {
                D2[i - (j - 1) * 8] = fillData[i];
            }
            for (int i = 0; i < 8; i++)
            {
                bytTemp[i] =  (unsigned char)(bytTempX[i] ^ D2[i]);
                
            }
            memcpy(I3, bytTemp, 8);
            NSLog(@"I3:%@\n",[self ByteToString:I3 andDataLen:8]);
            NSString *enRet = [self encryptUseDES:[self ByteToString:I3 andDataLen:8] key:key];
            memcpy(bytTempX, [[self stringToByte:enRet] bytes], 8);
            NSLog(@"bytTempX:%@\n",[self ByteToString:bytTempX andDataLen:8]);
        }
        return [self ByteToString:bytTempX andDataLen:8];
    }
    return nil;
}

@end
