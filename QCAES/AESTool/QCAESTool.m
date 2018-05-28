//
//  QCAESTool.m
//  QCAES
//
//  Created by EricZhang on 2018/5/28.
//  Copyright © 2018年 BYX. All rights reserved.
//

#import "QCAESTool.h"
//一定要记得倒入头文件
#import <CommonCrypto/CommonCryptor.h>
//初始向量
/*
 可以使用不同的初始向量来避免相同的明文，产生相同的密文，抵抗字典攻击
 */
NSString const *kInitVector = @"A_16_Byte_String";
//密钥长度
size_t const kKeySize = kCCKeySizeAES128;
@implementation QCAESTool

/*
 
 参数：
 输入的明文内容content
 和后台统一的key值
 
 */


/*
 
 加密
 
 */


NSString * aesEncryptString(NSString *content, NSString *key) {
    
    //参数合理性判断
    NSCParameterAssert(content);
    NSCParameterAssert(key);
    
    //将明文,和key转化为data类型
    NSData *contentData = [content dataUsingEncoding:NSUTF8StringEncoding];
    
    NSData *keyData = [key dataUsingEncoding:NSUTF8StringEncoding];
    
    
    //对contentData进行加密
    NSData *encrptedData = aesEncryptData(contentData, keyData);
    
    
    //将结果转化为字符串并进行base64加密
    return [encrptedData base64EncodedStringWithOptions:NSDataBase64EncodingEndLineWithLineFeed];
    
}

/*
 
 解密
 
 */


NSString * aesDecryptString(NSString *content, NSString *key) {
    NSCParameterAssert(content);
    NSCParameterAssert(key);
    
    //先将传进来的字符串转化为contentData
    NSData *contentData = [[NSData alloc] initWithBase64EncodedString:content options:NSDataBase64DecodingIgnoreUnknownCharacters];
    //key转化为data类型
    NSData *keyData = [key dataUsingEncoding:NSUTF8StringEncoding];
    
    //对contentData进行解密
    NSData *decryptedData = aesDecryptData(contentData, keyData);
    
    //返回字符串
    return [[NSString alloc] initWithData:decryptedData encoding:NSUTF8StringEncoding];
}






/*
 data加密
 */


NSData * aesEncryptData(NSData *contentData, NSData *keyData) {
    NSCParameterAssert(contentData);
    NSCParameterAssert(keyData);
    
    //长度要求提示：一个英文字符是一个字节，8位
    NSString *hint = [NSString stringWithFormat:@"The key size of AES-%lu should be %lu bytes!", kKeySize * 8, kKeySize];
    //如果长度符合就通过，如果长度不符合就输出上边字符串
    NSCAssert(keyData.length == kKeySize, hint);
    //进行加密操作
    return cipherOperation(contentData, keyData, kCCEncrypt);
}

/*
 
 data解密
 
 */

NSData * aesDecryptData(NSData *contentData, NSData *keyData) {
    
    NSCParameterAssert(contentData);
    NSCParameterAssert(keyData);
    
    //长度要求提示
    NSString *hint = [NSString stringWithFormat:@"The key size of AES-%lu should be %lu bytes!", kKeySize * 8, kKeySize];
    //长度判断
    NSCAssert(keyData.length == kKeySize, hint);
    //进行解密操作
    return cipherOperation(contentData, keyData, kCCDecrypt);
    
}


/*
 
 加密解密最根本的方法，分配内存，进行处理，返回结果，清空内存
 
 */

NSData * cipherOperation(NSData *contentData, NSData *keyData, CCOperation operation) {
    
    
    
    /*
     const与define。两者都可以用来定义常量，但是const定义时，定义了常量的类型，所以更精确一些。
     
     void的字面意思是“无类型”，void *则为“无类型指针”，void *可以指向任何类型的数据。
     
     const void *a这是定义了一个指针a，a可以指向任意类型的值，但它指向的值必须是常量。在这种情况下，我们不能修改被指向的对象，但可以使指针指向其他对象。
     */
    
    
    //得到初始向量byte的个数
    void const *initVectorBytes = [kInitVector dataUsingEncoding:NSUTF8StringEncoding].bytes;
    
    //得到内容的byte个数
    void const *contentBytes = contentData.bytes;
    
    //得到key的byte个数
    void const *keyBytes = keyData.bytes;
    
    
    
    //加密内容的长度
    NSUInteger dataLength = contentData.length;
    
    //本身长度 +为了防止最后一个明(密)文块不完整，所以加上16bytes
    size_t operationSize = dataLength + kCCBlockSizeAES128;
    
    
    
    
    //内存自动分配函数，最后得到的是一个自动分配的存储区，operationBytes是地址，此存储区的初始内容不确定，如果失败返回NULL
    void *operationBytes = malloc(operationSize);
    
    
    if (operationBytes == NULL) {
        return nil;
    }
    //初始化输出尺寸
    size_t actualOutSize = 0;
    
    //执行CCCrypt加密解密方法
    //operation指的是加密解密的类型
    //我们传入的指针变量contentBytes实际上对应的是存储区的地址，当然我们要在加密方法中，在地址中放入密文块或者名文块，方便后期获取
    //把actualOutSize的地址放到函数内，在函数中对地址中对应的数字进行操作，最后我们得到的是输出时候的长度
    CCCryptorStatus cryptStatus = CCCrypt(operation,
                                          kCCAlgorithmAES,
                                          kCCOptionPKCS7Padding,
                                          keyBytes,
                                          kKeySize,
                                          initVectorBytes,
                                          contentBytes,
                                          dataLength,
                                          operationBytes,
                                          operationSize,
                                          &actualOutSize);
    
    //如果判断状态是成功的话
    if (cryptStatus == kCCSuccess) {
        //从一个给定的给定字节数的存储区地址,创建并返回一个数据对象。从存储区地址获取存储区内容，内容在方法中已经放好了 operationBytes本身是一个地址
        return [NSData dataWithBytesNoCopy:operationBytes length:actualOutSize];
    }
    
    
    //malloc()函数自动分配内存，最后是一定要释放的
    free(operationBytes);
    operationBytes = NULL;
    return nil;
    
    
    
}





@end
