//
//  ViewController.m
//  PCSC-UI
//
//  Created by 刘维凯 on 2018/9/19.
//  Copyright © 2018年 刘维凯. All rights reserved.
//

#import "ViewController.h"
#import "PCSC/winscard.h"
#import "Tools.h"

@implementation ViewController

- (void)viewDidLoad {
    [super viewDidLoad];
    // Do any additional setup after loading the view.
    arrReaders = [[NSArray alloc] init];
    [popUpBtnReaders removeAllItems];
    alert = [[NSAlert alloc] init];
    textSendRandomCmd.stringValue = @"";
    textRecvRandom.stringValue = @"";
    textCryptRandom.stringValue = @"";
    textSendAuth.stringValue = @"";
    textRecvAuth.stringValue = @"";
    textAuthCode.stringValue = @"";
    [authTypeDES setState:NSOnState];
    authType = @"DES";
    textClearCardCmd.stringValue = @"";
    textClearCardResult.stringValue = @"";
    textCreateMFKeyFileCmd.stringValue = @"";
    textCreateMFKeyFileResult.stringValue = @"";
    
    textRecvData.stringValue = @"";
    textWriteCardCmd.stringValue = @"";
}


- (void)setRepresentedObject:(id)representedObject {
    [super setRepresentedObject:representedObject];

    // Update the view, if already loaded.
    
}

- (IBAction)connectDevice:(id)sender {
    int iResult = SCardEstablishContext(SCARD_SCOPE_USER, NULL, NULL, &m_hContext);
    if(iResult != SCARD_S_SUCCESS){
        [alert setMessageText:@"未能获取读卡设备句柄"];
        [alert runModal];
        return;
    }
    
    char cReaderName[100];
    uint32_t ui32ReadNameSize = 100;
    iResult = SCardListReaders(m_hContext, NULL, cReaderName, &ui32ReadNameSize);
    if(iResult != SCARD_S_SUCCESS || ui32ReadNameSize == 1){
        [alert setMessageText:@"取读卡器设备列表不成功!"];
        [alert runModal];
        return;
    }
    
    [popUpBtnReaders removeAllItems];
    
    uint32_t i = 0;
    int iReaderIndex = 0;
    while(i < ui32ReadNameSize) {
        if(strlen(cReaderName + i) > 0){
            NSString *string_content = [NSString stringWithCString:(const char*)(cReaderName + i)encoding:NSUTF8StringEncoding];
            [popUpBtnReaders addItemWithTitle:string_content];
            iReaderIndex += 1;
        }
        i += strlen(cReaderName);
        i ++;
    }
    
    [popUpBtnReaders setTarget:self];
    [popUpBtnReaders setAction:@selector(handlePopBtn:)];
    currentReader = popUpBtnReaders.selectedItem.title;
}

- (void)handlePopBtn:(NSPopUpButton *)popBtn {
    currentReader = popBtn.selectedItem.title;
}

- (IBAction)readCard:(id)sender {
    if(m_hContext == 0){
        [alert setMessageText:@"请先连接读卡器!"];
        [alert runModal];
        return;
    }
    
    BOOL isSelReader = [Tools isNullToString:currentReader];
    if(isSelReader){
        [alert setMessageText:@"请先连接读卡器!"];
        [alert runModal];
        return;
    }
    
    /*
    //暂时不判断
    BOOL isT0 = [cardProtocol0OfRound state] == NSOnState;
    BOOL isT1 = [cardProtocol0OfRound state] == NSOnState;
    uint32_t dwPreferredProtocols = SCARD_PROTOCOL_T0;
    if(isT0){
        dwPreferredProtocols = SCARD_PROTOCOL_T0;
    }
    if(isT1){
        dwPreferredProtocols |= SCARD_PROTOCOL_T1;
    }
     */
    const char *cReader = [currentReader UTF8String];
    int iResult = SCardConnect(m_hContext, cReader, SCARD_SHARE_SHARED, SCARD_PROTOCOL_ANY, &m_hCard, &m_io.dwProtocol);
    if(iResult  !=  SCARD_S_SUCCESS) {
        [alert setMessageText:@"取卡句柄错误!"];
        [alert runModal];
        return;
    }else{
        [alert setMessageText:@"取卡句柄成功,可操作卡!"];
        [alert runModal];
    }
}

- (IBAction)getAuthRandom:(id)sender {
    NSString* cmd = @"0084000008";
    textSendRandomCmd.stringValue = [@"send:" stringByAppendingString:cmd];
    currentRandom = [self sendCmdAndRecvData:cmd];
    if(currentRandom == nil){
        return;
    }
    
    textRecvRandom.stringValue = [@"recv:" stringByAppendingString:currentRandom];
    if(![textRecvRandom.stringValue hasSuffix:@"9000"]){
        [alert setMessageText:@"指令结果出错!"];
        [alert runModal];
        return;
    }
    currentRandom = [currentRandom substringWithRange:NSMakeRange(0, currentRandom.length - 4)];
}

- (IBAction)calcDESEncryptValue:(id)sender {
    if(currentRandom.length < 8 * 2){
        [alert setMessageText:@"当前无随机数!"];
        [alert runModal];
        return;
    }
    
    size_t szAuthCodeLen = 0;
    if([authType isEqual:@"DES"] == YES){
        szAuthCodeLen = kCCKeySizeDES;
    }else if([authType isEqual:@"3DES"] == YES){
        szAuthCodeLen = kCCKeySize3DES;
    }
    
    if(textAuthCode.stringValue.length != szAuthCodeLen * 2){
        [alert setMessageText:@"外部认证密钥长度错误!"];
        [alert runModal];
        return;
    }
    if([authType isEqual:@"DES"] == YES){
        textCryptRandom.stringValue = [Tools encryptUseDES:currentRandom key:textAuthCode.stringValue];
    }
    else if([authType isEqual:@"3DES"] == YES){
        textCryptRandom.stringValue = [Tools TripleDES:currentRandom key:textAuthCode.stringValue encryptOrDecrypt:kCCEncrypt];
    }
    textSendAuth.stringValue = [@"send:0082000008" stringByAppendingString:textCryptRandom.stringValue];
    
    
}

- (IBAction)sendAuthCmd:(id)sender {
    NSString *sendCmd = [@"0082000008" stringByAppendingString:textCryptRandom.stringValue];
    NSString *recvData = [self sendCmdAndRecvData:sendCmd];
    if(recvData == nil){
        return;
    }
    textRecvAuth.stringValue = [@"recv:" stringByAppendingString:recvData];
}

- (IBAction)selectAuthType:(id)sender {
    if([authTypeDES state] == YES){
        authType = @"DES";
        return;
    }
    if([authType3DES state] == YES){
        authType = @"3DES";
        return;
    }
}

- (IBAction)clearCard:(id)sender {
    NSString *sendCmd = @"800E000000";
    textClearCardCmd.stringValue = [@"send:" stringByAppendingString:sendCmd];
    NSString *recvData = [self sendCmdAndRecvData:sendCmd];
    if(recvData == nil){
        return;
    }
    textClearCardResult.stringValue = [@"recv:" stringByAppendingString:recvData];
}
- (IBAction)createMFKey:(id)sender {
    NSString *sendCmd = @"80E00000073F004001F0FFFF";
    textCreateMFKeyFileCmd.stringValue = [@"send:" stringByAppendingString:sendCmd];
    NSString *recvData = [self sendCmdAndRecvData:sendCmd];
    if(recvData == nil){
        return;
    }
    textCreateMFKeyFileResult.stringValue = [@"recv:" stringByAppendingString:recvData];
}
- (IBAction)executeCmd:(id)sender {
    NSString *sendCmd = textSendCmd.stringValue;
    
    NSString *recvData = [self sendCmdAndRecvData:sendCmd];
    if(recvData == nil){
        return;
    }
    textRecvData.stringValue = [@"recv:" stringByAppendingString:recvData];
}
- (IBAction)createWriteCardCmd:(id)sender {
    NSString *initQuancunRecv = textQuancunInitCmd.stringValue;
    //卡内余额
    NSString *balenceAmt = [initQuancunRecv substringWithRange:NSMakeRange(0, 8)];
    //联机交易序号
    NSString *txSeq = [initQuancunRecv substringWithRange:NSMakeRange(8, 4)];
    //密钥版本号
    NSString *keyIndex = [initQuancunRecv substringWithRange:NSMakeRange(12, 2)];
    //算法标示
    NSString *calcFlag = [initQuancunRecv substringWithRange:NSMakeRange(14, 2)];
    //伪随机数
    NSString *random = [initQuancunRecv substringWithRange:NSMakeRange(16, 8)];
    //NSString *random = @"3948BC11";
    //MAC1
    NSString *mac1 = [initQuancunRecv substringWithRange:NSMakeRange(24, 8)];
    NSLog(@"\n圈存初始化返回:%@\n卡内余额:%@\n联机交易序号:%@\n密钥版本号:%@\n算法标示:%@\n伪随机数:%@\nMAC1:%@\n", initQuancunRecv,balenceAmt,txSeq,keyIndex,calcFlag,random,mac1);
    
    NSString *quancunKey1 = @"39333933393339333933393339333933";
    //NSString *quancunKey1 = @"00112233445566778899AABBCCDDEEFF";
    NSString *quancunKey2 = @"39343934393439343934393439343934";
    NSString *quancunKeyReal = @"";
    NSString *checkMAC1Key = @"";
    if([keyIndex isEqualToString:@"00" ] == YES){
        quancunKeyReal = quancunKey1;
    }else if([keyIndex isEqualToString:@"01" ] == YES){
        quancunKeyReal = quancunKey2;
    }else{
        [alert setMessageText:@"未知的密钥版本号!"];
        [alert runModal];
        return;
    }
    
    //校验MAC1
    NSString *inputData = [random stringByAppendingString:txSeq];
    inputData = [inputData stringByAppendingString:@"8000"];//填充inputData的长度为8的倍数并以x80为结束符
    
    if([calcFlag isEqualToString:@"00" ] == YES){
        NSLog(@"DES算法");
    }else if([calcFlag isEqualToString:@"01" ] == YES){
        NSLog(@"3DES算法");
        quancunKeyReal = [quancunKeyReal stringByAppendingString:[quancunKeyReal substringWithRange:NSMakeRange(0, 16)]];
        NSLog(@"扩展后的Key1%@\n",quancunKeyReal);
        //过程密钥
        checkMAC1Key = [Tools TripleDES:inputData key:quancunKeyReal encryptOrDecrypt:kCCEncrypt];
    }else{
        [alert setMessageText:@"未知的算法标识!"];
        [alert runModal];
        return;
    }
    
    NSLog(@"过程密钥:%@\n",checkMAC1Key);
    
    NSString *nsData = @"000000010000000102000000000001";
    NSString *ret = [Tools PBOC_DES_MAC:checkMAC1Key data:nsData];
    NSLog(@"计算得到的MAC1:%@\n",ret);
    
    
    if([quancunKeyReal isEqualToString:mac1] != YES){
        [alert setMessageText:@"MAC1校验失败!"];
        [alert runModal];
        return;
    }
}

- (NSString*) sendCmdAndRecvData:(NSString*)cmd
{
    NSData *cmdData = [Tools stringToByte:cmd];
    uint32_t ui32SendBufferLen = (uint32_t)cmdData.length;
    Byte *byteArray = (Byte *)cmdData.bytes;
    uint32_t ui32APDUCmdLen = 1024 * 8;
    unsigned char bRecvData[ui32APDUCmdLen];
    int iResult = SCardTransmit(m_hCard, &m_io, byteArray, ui32SendBufferLen, NULL, bRecvData, &ui32APDUCmdLen);
    if(iResult != SCARD_S_SUCCESS){
        NSLog(@"error:%x\n", iResult);
        [alert setMessageText:@"执行指令出错!"];
        [alert runModal];
        return nil;
    }
    NSString *recvData = [Tools ByteToString:bRecvData andDataLen:ui32APDUCmdLen];
    return recvData;
}

@end
