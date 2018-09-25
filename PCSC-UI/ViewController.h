//
//  ViewController.h
//  PCSC-UI
//
//  Created by 刘维凯 on 2018/9/19.
//  Copyright © 2018年 刘维凯. All rights reserved.
//

#import <Cocoa/Cocoa.h>
#import "PCSC/winscard.h"

@interface ViewController : NSViewController{
    @public
    SCARDCONTEXT m_hContext;
    SCARD_IO_REQUEST m_io;
    SCARDHANDLE m_hCard;
    IBOutlet NSPopUpButton *popUpBtnReaders;
    IBOutlet NSButton *cardProtocol0OfRound;
    IBOutlet NSButton *cardProtocol1OfRound;
    IBOutlet NSTabView *tabView;
    IBOutlet NSTextField *textSendRandomCmd;
    IBOutlet NSTextField *textRecvRandom;
    IBOutlet NSTextField *textCryptRandom;
    IBOutlet NSTextField *textSendAuth;
    IBOutlet NSTextField *textRecvAuth;
    IBOutlet NSTextField *textAuthCode;
    IBOutlet NSButton *authTypeDES;
    IBOutlet NSButton *authType3DES;
    NSArray *arrReaders;
    NSString *currentReader;
    NSAlert *alert;
    NSString *currentRandom;
    NSString *authType;
    IBOutlet NSTextField *textClearCardCmd;
    IBOutlet NSTextField *textClearCardResult;
}
- (NSString*) sendCmdAndRecvData:(NSString*)cmd;
@end

