//
//  ViewController.m
//  ceshishi
//
//  Created by gaoyang on 16/4/18.
//  Copyright © 2016年 gaoyang. All rights reserved.
//

#import "ViewController.h"
#import "AFNetworking.h"
@interface ViewController ()
@property (strong ,nonatomic)UILabel *label;
@end

@implementation ViewController

- (void)viewDidLoad {
    [super viewDidLoad];
    // Do any additional setup after loading the view, typically from a nib.
    
    self.label=[[UILabel alloc]init];
    self.label.frame=CGRectMake(0, 0, [UIScreen mainScreen].bounds.size.width, [UIScreen mainScreen].bounds.size.height);
    self.label.textColor=[UIColor blackColor];
    self.label.numberOfLines=0;
    [self.view addSubview:self.label];
    [self btnAction];
}

- (void)btnAction{
    
   
    
    NSString *urlString=@"https://192.168.30.91/";
    
    AFSecurityPolicy *securityPolicy = [AFSecurityPolicy policyWithPinningMode:AFSSLPinningModeNone];
    
    //是否允许,NO-- 不允许无效的证书...
    //因为大多数都是自己给自己颁布的证书,对于苹果来说是不被信任的,是无效的,所以要设置YES.
    securityPolicy.allowInvalidCertificates=YES;
    
    //设置证书 如果不设置,可以自动读取工程里的cer文件
    
   // 1.zhengshu.cer ca.cer   (一个是服务器证书,一个服务器CA根证书,哪一个都可以)
    //service.cer 2.服务器证书
   //securityPolicy.pinnedCertificates=set;
    
    //validatesDomainName 是否需要验证域名，默认为YES；
    //假如证书的域名与你请求的域名不一致，需把该项设置为NO；如设成NO的话，即服务器使用其他可信任机构颁发的证书，也可以建立连接，这个非常危险，建议打开。
    //置为NO，主要用于这种情况:客户端请求的是子域名，而证书上的是另外一个域名。因为SSL证书上的域名是独立的，假如证书上注册的域名是www.google.com，那么mail.google.com是无法验证通过的；当然，有钱可以注册通配符的域名*.google.com，但这个还是比较贵的。
    //如置为NO，建议自己添加对应域名的校验逻辑。
    
    //一.zhengshu.cer https://192.168.30.91/ 无需设置infoplist
    
    //二.service.cer https://192.168.30.55:8443/IEMS_APP/  //模拟器必须设置info.plist YES   真机不用设置info.plist
    
    //两种都可以加密数据安全,防止中间人 抓包工具
    
    securityPolicy.validatesDomainName=NO;
    
    AFHTTPSessionManager * manager = [AFHTTPSessionManager manager];
    manager.responseSerializer.acceptableContentTypes =  [NSSet setWithObjects: @"text/html", nil];
    manager.requestSerializer.cachePolicy = NSURLRequestReloadIgnoringLocalCacheData;
    __weak typeof(self)weakSelf = self;
    
    //重写这个方法就能提供客户端验证
    [manager setSessionDidBecomeInvalidBlock:^(NSURLSession * _Nonnull session, NSError * _Nonnull error) {
        NSLog(@"setSessionDidBecomeInvalidBlock");
    }];
    [manager setSessionDidReceiveAuthenticationChallengeBlock:^NSURLSessionAuthChallengeDisposition(NSURLSession*session, NSURLAuthenticationChallenge *challenge, NSURLCredential *__autoreleasing*_credential) {
        NSURLSessionAuthChallengeDisposition disposition = NSURLSessionAuthChallengePerformDefaultHandling;
        __autoreleasing NSURLCredential *credential =nil;
        if([challenge.protectionSpace.authenticationMethod isEqualToString:NSURLAuthenticationMethodServerTrust]) {
            if([manager.securityPolicy evaluateServerTrust:challenge.protectionSpace.serverTrust forDomain:challenge.protectionSpace.host]) {
                credential = [NSURLCredential credentialForTrust:challenge.protectionSpace.serverTrust];
                if(credential) {
                    disposition =NSURLSessionAuthChallengeUseCredential;
                } else {
                    disposition =NSURLSessionAuthChallengePerformDefaultHandling;
                }
            } else {
                disposition = NSURLSessionAuthChallengeCancelAuthenticationChallenge;
            }
        } else {
            // client authentication
            SecIdentityRef identity = NULL;
            SecTrustRef trust = NULL;
            NSString *p12 = [[NSBundle mainBundle] pathForResource:@"client.key"ofType:@"p12"];
            NSFileManager *fileManager =[NSFileManager defaultManager];
            
            if(![fileManager fileExistsAtPath:p12])
            {
                NSLog(@"client.p12:not exist");
            }
            else
            {
                NSData *PKCS12Data = [NSData dataWithContentsOfFile:p12];
                
                if ([[weakSelf class]extractIdentity:&identity andTrust:&trust fromPKCS12Data:PKCS12Data])
                {
                    SecCertificateRef certificate = NULL;
                    SecIdentityCopyCertificate(identity, &certificate);
                    const void*certs[] = {certificate};
                    CFArrayRef certArray =CFArrayCreate(kCFAllocatorDefault, certs,1,NULL);
                    credential =[NSURLCredential credentialWithIdentity:identity certificates:(__bridge  NSArray*)certArray persistence:NSURLCredentialPersistencePermanent];
                    disposition =NSURLSessionAuthChallengeUseCredential;
                }
            }
        }
        *_credential = credential;
        return disposition;
    }];

   manager.securityPolicy = securityPolicy;
    
   manager.responseSerializer = [AFHTTPResponseSerializer serializer];

    [manager GET:urlString parameters:nil progress:^(NSProgress * _Nonnull downloadProgress) {
        
    } success:^(NSURLSessionDataTask * _Nonnull task, id  _Nullable responseObject) {
        
        
        NSString *html=[[NSString alloc]initWithData:responseObject encoding:NSUTF8StringEncoding];
        
        self.label.text=html;
        
        
    } failure:^(NSURLSessionDataTask * _Nullable task, NSError * _Nonnull error) {
        self.label.textColor=[UIColor redColor];
        self.label.text=error.debugDescription;
        
    }];
    

}
+(BOOL)extractIdentity:(SecIdentityRef*)outIdentity andTrust:(SecTrustRef *)outTrust fromPKCS12Data:(NSData *)inPKCS12Data {
    OSStatus securityError = errSecSuccess;
    //client certificate password
    NSDictionary*optionsDictionary = [NSDictionary dictionaryWithObject:@"123456"
                                                                 forKey:(__bridge id)kSecImportExportPassphrase];
    
    CFArrayRef items = CFArrayCreate(NULL, 0, 0, NULL);
    securityError = SecPKCS12Import((__bridge CFDataRef)inPKCS12Data,(__bridge CFDictionaryRef)optionsDictionary,&items);
    
    if(securityError == 0) {
        CFDictionaryRef myIdentityAndTrust =CFArrayGetValueAtIndex(items,0);
        const void*tempIdentity =NULL;
        tempIdentity= CFDictionaryGetValue (myIdentityAndTrust,kSecImportItemIdentity);
        *outIdentity = (SecIdentityRef)tempIdentity;
        const void*tempTrust =NULL;
        tempTrust = CFDictionaryGetValue(myIdentityAndTrust,kSecImportItemTrust);
        *outTrust = (SecTrustRef)tempTrust;
    } else {
        NSLog(@"Failedwith error code %d",(int)securityError);
        return NO;
    }
    return YES;
}


/**
 
 
 一.非浏览器应用(iOS app)与服务器 AFNetworking HTTPS ssl认证
 
 虽然是HTTPS 的网站,但是服务器端也要设置对客户端提供认证证书忽略(此处与浏览器与服务器SSl双向认证不太一样).
 
 AFSecurityPolicy *securityPolicy = [AFSecurityPolicy policyWithPinningMode:AFSSLPinningModePublicKey];
 
 //是否允许,NO-- 不允许无效的证书,设置允许(YES)(因为我们的证书一般都是自签名的,并不是像谷歌那种大型网站权威颁布的官方认证证书)
 
 securityPolicy.allowInvalidCertificates=YES;
 
 //validatesDomainName 是否需要验证域名，默认为YES；
 //假如证书的域名与你请求的域名不一致，需把该项设置为NO；如设成NO的话，即服务器使用其他可信任机构颁发的证书，也可以建立连接，这个非常危险，建议打开。
 //置为NO，主要用于这种情况：客户端请求的是子域名，而证书上的是另外一个域名。因为SSL证书上的域名是独立的，假如证书上注册的域名是www.google.com，那么mail.google.com是无法验证通过的；当然，有钱可以注册通配符的域名*.google.com，但这个还是比较贵的。
 //如置为NO，建议自己添加对应域名的校验逻辑。
 //securityPolicy.validatesDomainName=NO;
 
 manager.securityPolicy = securityPolicy;
 
 这几句代码是必需的,访问HTTPS(比http多加这些).
 
 AFSSLPinningModeNone,AFSSLPinningModePublicKey,AFSSLPinningModeCertificate,这三个属性是上边红色位置的三种情况.
 
 SSL Pinning可以理解为证书绑定，是指客户端直接保存服务端的证书，建立https连接时直接对比服务端返回的和客户端保存的两个证书是否一样，一样就表明证书 是真的，不再去系统的信任证书机构里寻找验证。这适用于非浏览器应用，因为浏览器跟很多未知服务端打交道，无法把每个服务端的证书都保存到本地，但CS架 构的像手机APP事先已经知道要进行通信的服务端，可以直接在客户端保存这个服务端的证书用于校验。
 
 为什么直接对比就能保证证书没问题？如果中间人从客户端取出证书，再伪装成服务端跟其他客户端通信，它发送给客户端的这个证书不就能通过验证吗？确 实可以通过验证，但后续的流程走不下去，因为下一步客户端会用证书里的公钥加密，中间人没有这个证书的私钥就解不出内容，也就截获不到数据，这个证书的私 钥只有真正的服务端有，中间人伪造证书主要伪造的是公钥。
 
 为什么要用SSL  Pinning？正常的验证方式不够吗？如果服务端的证书是从受信任的的CA机构颁发的，验证是没问题的，但CA机构颁发证书比较昂贵，小企业或个人用户 可能会选择自己颁发证书，这样就无法通过系统受信任的CA机构列表验证这个证书的真伪了，所以需要SSL Pinning这样的方式去验证。
 
 在iOS开发中,从Xcode7和iOS9开始,Apple提升了App的网络安全性,App默认只能进行对采用权威机构签名颁发证书的Web站点进行访问(信任的HTTPS),而自签名的证书的HTTPS站点也被列为属于例外,所以我们需要在App的Info.plist中单独为我们的域名设置Exception Domains"白名单”.也可以使用放开全部的设置NSAllowsArbitraryLoads为true.
 
 1.AFSSLPinningModeNone
 
 这个模式表示不做SSL pinning，只跟浏览器一样在系统的信任机构列表里验证服务端返回的证书。若证书是信任机构签发的就会通过，若是自己服务器生成的证书，这里是不会通过的。
 
 所以要用到上面securityPolicy.allowInvalidCertificates=YES;
 
 必须修改infoplist文件 即:像http请求一样(App TransportSecurity Settings——>Allow Arbitrary Loads  YES.)
 
 这个属性使数据不安全,一些中间人(抓包工具)会截取到数据接口.
 
 2.AFSSLPinningModeCertificate:
 
 这个模式表示用证书绑定方式验证证书，需要客户端保存有服务端的证书拷贝，这里验证分两步，第一步验证证书的域名/有效期等信息，第二步是对比服务端返回的证书跟客户端返回的是否一致。
 
 验证服务器身份在没有使用代理的时候可以正常访问服务器的资源,但是一旦用户给手机网络设置使用了如Charle那样的HTTPS/SSL代理服务,则会出现服务器证书验证失败,SSL网络连接会断开,老板再也不用担心数据接口被人抓包或者代理给扒出来了.故达到防止中间人攻击的效果.
 
 无需修改infoplist(自己测试了).
 
 这个证书是服务器端的证书(.cer文件)(可以是根证书,也可以是证书,总之必须是服务器的),把这个证书直接copy到Xcode工程,程序会自动读取.cer文件.
 
 3.AFSSLPinningModePublicKey (和第二个差不多)
 
 这个模式同样是用证书绑定方式验证，客户端要有服务端的证书拷贝，只是验证时只验证证书里的公钥，不验证证书的有效期等信息。只要公钥是正确的，就能保证通信不会被窃听，因为中间人没有私钥，无法解开通过公钥加密的数据。
 
 
 
 二.客户端浏览器与服务器端 HTTPS 双向认证
 
 ① 浏览器发送一个连接请求给安全服务器。
 
 ② 服务器将自己的证书，以及同证书相关的信息发送给客户浏览器。
 
 ③ 客户浏览器检查服务器送过来的证书是否是由自己信赖的 CA 中心所签发的。如果是，就继续执行协议；如果不是，客户浏览器就给客户一个警告消息：警告客户这个证书不是可以信赖的，询问客户是否需要继续。
 
 ④ 接着客户浏览器比较证书里的消息，例如域名和公钥，与服务器刚刚发送的相关消息是否一致，如果是一致的，客户浏览器认可这个服务器的合法身份。
 
 ⑤ 服务器要求客户发送客户自己的证书。收到后，服务器验证客户的证书，如果没有通过验证，拒绝连接；如果通过验证，服务器获得用户的公钥。
 
 ⑥ 客户浏览器告诉服务器自己所能够支持的通讯对称密码方案。
 
 ⑦ 服务器从客户发送过来的密码方案中，选择一种加密程度最高的密码方案，用客户的公钥加过密后通知浏览器。
 
 ⑧ 浏览器针对这个密码方案，选择一个通话密钥，接着用服务器的公钥加过密后发送给服务器。
 
 ⑨ 服务器接收到浏览器送过来的消息，用自己的私钥解密，获得通话密钥。
 
 ⑩ 服务器、浏览器接下来的通讯都是用对称密码方案，对称密钥是加过密的。
 
这两种形式虽然同样是ssl认证,本人感觉并不是一个意思.开始的时候是按照浏览器与服务器端的ssl双向认证来做AFNetworking,服务器端设置必须客户端提供证书才能访问网站,否则403,但是试了好多次都是请求失败(万念俱灰).查看别人的HTTPS接口例子不一样和之前做的.于是认为这两种验证方式是不同的.把服务器端必需的客户端证书,改成忽略,经过测试,用AFNetworking使用服务器端证书,也能达到加密的作用,而且AFNetworking,确实是这么应用的.代码很少,但是这里面是非浏览器应用如何应用,以及和浏览器的双向认证区分开.
 
 我是从下面这些个说法中总结的:
 
 //浏览器与服务端双向认证
 http://www.jianshu.com/p/8b4312c34808
 http://www.jianshu.com/p/20d5fb4cd76d
 
 //https为什么还要改infoplist  如何防止抓包(中间人)
 http://www.jianshu.com/p/c6a903da8346
 
 非浏览器应用  AFNetworking SSLPINNing (双向认证)
 http://www.cocoachina.com/ios/20140916/9632.html
 
 HTTPS接口例子:
 https://tv.diveinedu.com/channel/
 
 https://daka.facenano.com/checkin/v1/app_binding?phone_number=18700000001&app_version_code=2&device=mobile_ios&company_tag=iPhone-demo&phone_imei=6D56F277-0AAA-4F32-AD01-6C55AEE75964&verification_code=3216

 
*/


@end
