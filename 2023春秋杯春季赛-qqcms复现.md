title: 2023春秋杯春季赛 qqcms复现
author: bmth
tags:
  - CMS
categories:
  - 代码审计
top_img: 'https://img-blog.csdnimg.cn/84ea6e9809a9458bb47c4f99d39804f7.png'
cover: 'https://img-blog.csdnimg.cn/84ea6e9809a9458bb47c4f99d39804f7.png'

date: 2023-06-28 19:07:00
---
![](https://img-blog.csdnimg.cn/84ea6e9809a9458bb47c4f99d39804f7.png)

闲着无聊，发现phpstorm中还留有一个代码审计的题，当时比赛的时候没做出来，那么就复现一下

## 环境搭建
直接在官网中下载源码：[https://down.q-cms.cn/QCMS_V6.0.1_220515.zip](https://down.q-cms.cn/QCMS_V6.0.1_220515.zip)

用phpstudy搭建，web目录如下
![](https://img-blog.csdnimg.cn/b7f880df8f1447598213e1d66c4f334a.png)

然后创建一个数据库，导入sql文件，设置手机号以及密码就安装成功了
![](https://img-blog.csdnimg.cn/a680f9f0421b4326baabf55e63e2ffb0.png)

但是我不是在本机搭建的，就需要添加远程调试，phpstudy扩展开启xdebug，然后修改php.ini为：
```
[Xdebug]
zend_extension=C:/phpstudy_pro/Extensions/php/php7.3.4nts/ext/php_xdebug.dll
xdebug.collect_params=1
xdebug.collect_return=1
xdebug.auto_trace=On
xdebug.trace_output_dir=C:/phpstudy_pro/Extensions/php_log/php7.3.4nts.xdebug.trace
xdebug.profiler_enable=On
xdebug.profiler_output_dir=C:/phpstudy_pro/Extensions/php_log/php7.3.4nts.xdebug.profiler
xdebug.remote_enable=On
xdebug.remote_host=192.168.111.1
xdebug.remote_port=9002
xdebug.remote_handler=dbgp
xdebug.idekey = PHPSTORM
```
注意的事`xdebug.remote_host`需要为本机ip，最后搞个路径映射即可


## 代码审计(前台)
可以看到注册的时候执行了`$this->UserObj->ExecDelete();`将默认管理员用户给删除了
![](https://img-blog.csdnimg.cn/a4a777ec7d5c4c59abc1e8045fef166f.png)

所以说我们不能通过默认账号密码进后台，又使用了PDO预编译处理，无法进行sql注入
看到`Lib/Config/Controllers.php`中的ControllersAdmin
![](https://img-blog.csdnimg.cn/442af7c7b5fd4d1e81881f456779a3eb.png)

不仅仅验证了`User_Token`，还验证了qc_user表中的UserId是否存在，所以说通过token登录也失败了

就看看前台的相关功能了，相关的文件为：
```
System/Controller/index.php
System/Controller/install.php
System/Controller/home.php
System/Controller/api/common.php
```
### mysql探针
先看到 install.php 的 checkDb_Action 函数，存在一个PDO远程连接数据库
![](https://img-blog.csdnimg.cn/960aa368a736418b9cda632ffffcd700.png)

随便设置一个POST进行测试：
`Name=123&Host=192.168.111.1&Port=6666&Accounts=1&Password=1`
![](https://img-blog.csdnimg.cn/7505c3a7e3a049e783dd474bae0eb981.png)

那么是不是可以 mysql client 任意文件读取呢，很可惜的是php pdo默认禁用

可参考：
[CSS-T | Mysql Client 任意文件读取攻击链拓展](https://paper.seebug.org/1112/)
[2022春秋杯联赛 传说殿堂赛道 sql_debug题目解析](https://mp.weixin.qq.com/s/KTx0ltG7cstozDfzsX5tbA)

### phpinfo泄露
在home.php倒是存在 phpinfo_Action ，但也没啥用
![](https://img-blog.csdnimg.cn/e5da7c4cdc6f43458262826053523b67.png)

### 默认Secret登录
最后看到index.php，发现有个大的 muLogin_Action，如果Secret为`md5($this->SysRs['Secret'])`，就直接成为管理员登录
![](https://img-blog.csdnimg.cn/39b92736be1d452fb4f1d1d6feefd5cd.png)

而 Secret 在 qcms.sql 也给了默认值为 123456 ，md5后为 e10adc3949ba59abbe56e057f20f883e
![](https://img-blog.csdnimg.cn/a2ef5933fa914a71b1e4387e563a7d73.png)

直接`/index/muLogin?Secret=e10adc3949ba59abbe56e057f20f883e`，成功登录后台，妥妥的后门

可以配合`/api/common/sys`获取系统信息
![](https://img-blog.csdnimg.cn/226c69ed6c824ffdb313c4f8490f5d07.png)

访问得到 Secret 
![](https://img-blog.csdnimg.cn/e8b7c861033d4575876683b66dd28c3e.png)

### 标签内sql注入
万能标签：列表形式调用数据库里任何数据
```
{{loop sql='select * from qc_user'}}
```

首先搜索这里很明显存在反射型xss，没啥好说的`/index/search.html?Search="><script>alert(1)</script>`

看到search_Action
![](https://img-blog.csdnimg.cn/2be75b3ee41c4c88aebf6b037007a4f0.png)

跟进tempRun，发现对页面解析了所有的标签
![](https://img-blog.csdnimg.cn/8565ea01231d40349d60c8b4ace70ce0.png)

跟进loop_Tmp，看到对页面进行了正则匹配，正好我们通过Search传参可以在页面写入标签
![](https://img-blog.csdnimg.cn/ccbc5682074f4e90b1e4afb338eec46b.png)

执行sql语句，修改账号密码
```sql
{{loop sql='update qc_user set Password=md5(114514),Phone=16666666666'}}test{{/loop}}
```
![](https://img-blog.csdnimg.cn/aa3cb043f5d444519a3b11ffafae41a8.png)

即可登录后台

参考：
[2023年春秋杯春季赛-WriteUp By EDISEC](https://mp.weixin.qq.com/s/uk7aBZcTuXd4bNiXCDSo0A)

## 代码审计(后台)
后台漏洞就很多了，简单看看吧
### 后台任意文件读取
引入组件：引入一些通用代码页面，比如一个网站的导航和底部都是一样的，就单独做一个组件，通过include标签引入
```
{{include filename='component_header.html'/}}
```

直接在模版标签测试这里使用引入组件，尝试目录穿越到 win.ini
`{{include  filename='../../../../Windows/win.ini'/}}`
![](https://img-blog.csdnimg.cn/a0f7b00b1bb447caaa0d4fa9c1e60e0d.png)

根据相关功能，看到`System/Controller/admin/templates.php`
![](https://img-blog.csdnimg.cn/6f5ed86407754c308970f5fd2db5b2b9.png)

没有任何过滤的文件读取，通过`/admin/templates/edit.html?Name=../../../../../Windows/win.ini`读文件
![](https://img-blog.csdnimg.cn/55843c094af9421984024e1b4e57c222.png)

### 后台目录遍历
看到`System/Controller/admin/api.php`
![](https://img-blog.csdnimg.cn/b1197309856a4f76a76c0f5a365b5fd7.png)

直接进行的拼接，使用`../`穿越即可
![](https://img-blog.csdnimg.cn/c9494d542caf41a9bb55a54d55538845.png)

配合文件读取利用

## 总结
文件上传白名单写死了
![](https://img-blog.csdnimg.cn/0a76b676f1b5408ea252300b8d3f407b.png)

也找不到反序列化与命令执行，开摆！

代码审计，一定要耐心+动调，这样才称得上健全
