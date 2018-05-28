//
//  ViewController.m
//  QCAES
//
//  Created by EricZhang on 2018/5/28.
//  Copyright © 2018年 BYX. All rights reserved.
//

#import "ViewController.h"
#import "QCAESTool.h"

@interface ViewController ()

@end

@implementation ViewController

- (void)viewDidLoad {
    [super viewDidLoad];
    // Do any additional setup after loading the view, typically from a nib.
    self.view.backgroundColor = [UIColor whiteColor];
    //用于加密和解密的字段
    NSString *plainText = @"IM_THE_TEST_STRING";
    //key值
    NSString *key = @"1234567812345678";
    
    
    //加密
    NSString *cipherText = aesEncryptString(plainText, key);
    
    NSLog(@"%@", cipherText);
    
    //解密
    NSString *decryptedText = aesDecryptString(cipherText, key);
    
    NSLog(@"%@", decryptedText);
}
    



- (void)didReceiveMemoryWarning {
    [super didReceiveMemoryWarning];
    // Dispose of any resources that can be recreated.
}


@end
