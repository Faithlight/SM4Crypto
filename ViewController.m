//
//  ViewController.m
//  SM4Crypto
//
//  Created by 戴领 on 2018/4/17.
//  Copyright © 2018年 戴领. All rights reserved.
//

#import "ViewController.h"
#import "SM4Crypto.h"
@interface ViewController () <NSStreamDelegate>
@property (nonatomic, strong)NSInputStream *inputStream;
@property (nonatomic, strong)NSOutputStream *outputStream;

@end

@implementation ViewController

- (void)viewDidLoad {
    [super viewDidLoad];
    // Do any additional setup after loading the view, typically from a nib.
 


//    [self fileStreamTest];

}
- (void)fileStreamDecryptTest {
    NSString *inputpath = [NSHomeDirectory() stringByAppendingPathComponent:@"test.mp4.sm4"];
    self.inputStream = [[NSInputStream alloc] initWithFileAtPath:inputpath];
//    self.inputStream.delegate = self;
    [self.inputStream scheduleInRunLoop:[NSRunLoop currentRunLoop] forMode:NSDefaultRunLoopMode];
    [self.inputStream open];
    
    NSString *outputPath = [NSHomeDirectory() stringByAppendingPathComponent:@"test.mp4"];
    NSLog(@"%@", NSHomeDirectory());
    self.outputStream = [[NSOutputStream alloc] initToFileAtPath:outputPath append:YES];
    
    [self.outputStream scheduleInRunLoop:[NSRunLoop currentRunLoop] forMode:NSDefaultRunLoopMode];
//    self.outputStream.delegate = self;
    [self.outputStream open];
    
    while (self.inputStream.hasBytesAvailable) {
        NSLog(@"....");
        @autoreleasepool {
                //读取的字节长度
            NSInteger maxLength = 1024*1024 +16;
                //缓冲区
            uint8_t readBuffer [maxLength];
                //从输出流中读取数据，读到缓冲区中
            NSInteger bytesRead = [self.inputStream read: readBuffer
                                               maxLength:maxLength];
            NSLog(@"%ld",(long)bytesRead);
                //如果长度大于0就追加数据
            if (bytesRead > 0)
                {
                

//                NSData *key =[@"asdfgh" dataUsingEncoding:NSUTF8StringEncoding];
                
                NSData *buffData = [NSData dataWithBytes:readBuffer length:bytesRead];
//                NSData *cryptData = [buffData SM4CryptoWithOptionOperation:Operaton_Decrypt optionMode:OptionMode_ECB IV:nil key:key];
                [self.outputStream write:buffData.bytes maxLength:buffData.length];
                    //                [self.outputStream write:readBuffer maxLength:bytesRead];
                }
        }
    }
}
- (void)stream:(NSStream *)aStream handleEvent:(NSStreamEvent)eventCode
{
    switch (eventCode) {
        case NSStreamEventOpenCompleted:
            NSLog(@"流打开完成");
            break;
        case NSStreamEventHasBytesAvailable:
        {
        @autoreleasepool {
                //读取的字节长度
            NSInteger maxLength = 1024*1024 +16;
                //缓冲区
            uint8_t readBuffer [maxLength];
                //从输出流中读取数据，读到缓冲区中
            NSInteger bytesRead = [self.inputStream read: readBuffer
                                               maxLength:maxLength];
            NSLog(@"%ld",(long)bytesRead);
                //如果长度大于0就追加数据
            if (bytesRead > 0)
                {
                
//                unsigned char plainKey[16]   = {0x01,0x23,0x45,0x67,0x89,0xab,0xcd,0xef,0xfe,0xdc,0xba,0x98,0x76,0x54,0x32,0x10};
//                NSData *key =[NSData dataWithBytes:plainKey length:16];
                
                NSData *buffData = [NSData dataWithBytes:readBuffer length:bytesRead];
//                NSData *cryptData = [buffData SM4CryptoWithOptionOperation:Operaton_Decrypt optionMode:OptionMode_ECB IV:nil key:key];
                [self.outputStream write:buffData.bytes maxLength:buffData.length];
                    //                [self.outputStream write:readBuffer maxLength:bytesRead];
                }
        }
 
            NSLog(@"流传输中");
            break;
        }
        case NSStreamEventEndEncountered:
            NSLog(@"流结束");
            [aStream close];
            [aStream removeFromRunLoop:[NSRunLoop currentRunLoop]  forMode:NSDefaultRunLoopMode];
            break;
        case NSStreamEventErrorOccurred:
            NSLog(@"流错误");
            break;
        case NSStreamEventHasSpaceAvailable:
            NSLog(@"流空间可用");
            break;
        case NSStreamEventNone:
            NSLog(@"无事件");
            break;
        default:
            break;
    }
    
}
- (void)didReceiveMemoryWarning {
    [super didReceiveMemoryWarning];
    // Dispose of any resources that can be recreated.
}


@end
