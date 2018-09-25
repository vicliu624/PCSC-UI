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
        [alert setMessageText:@"指令结果出错!"];
        [alert runModal];
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
    textClearCardResult.stringValue = [@"recv:" stringByAppendingString:recvData];
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
