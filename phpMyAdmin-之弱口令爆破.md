title: phpMyAdmin 之弱口令爆破~
author: Bmth
tags: []
categories:
  - 渗透测试
top_img: 'https://i-blog.csdnimg.cn/direct/e6d81e9332f2449a8d9c76e21f115dba.png'
cover: 'https://i-blog.csdnimg.cn/direct/e6d81e9332f2449a8d9c76e21f115dba.png'
date: 2025-10-16 20:23:00
---
## 前言
在网上找了一圈，发现phpMyAdmin的弱口令爆破工具已经是好几年前的了：[phpMyAdmin多线程破解工具](https://cloud.tencent.com/developer/article/2148802)，比较新的版本根本无法使用，并且存在无法自定义路径字典，无法多线程爆破等等问题

既然网上找的工具不顺手，那么直接~~自己写一个~~(Cursor)！此篇仅用作记载，并非奇技淫巧，毫无技术含量，主要太久没update了

## 分析
这里先拿phpStudy下载的phpMyAdmin4.8.5进行分析
![](https://i-blog.csdnimg.cn/direct/e6d81e9332f2449a8d9c76e21f115dba.png)

可以看出首页没有什么变化的，但我们查看一下网页源码，发现
![](https://i-blog.csdnimg.cn/direct/6fdb0d8a4df246baa4f550e8a52b937b.png)

在所有的js文件后面存在`?v=4.8.5`，这个就是phpMyAdmin具体的版本了
我们还可以通过访问`/doc/html/index.html`获取版本信息：
![](https://i-blog.csdnimg.cn/direct/924af841608e46eab75cec9543fce922.png)

相关的路径还有：
```
/README
/ChangeLog
```
等等，但不同版本可能存在差异
### 爆破逻辑
看一下登录成功的请求包
![](https://i-blog.csdnimg.cn/direct/d4ea27590dd449a1b506c0d5baa26d28.png)

这里有一个参数token，很经典的CSRF防御：
>每次加载登录页面时 token 都会改变。如果你的爆破脚本没有在每次尝试前先获取这个最新的 token 并随表单提交，那么所有的登录请求都会因“令牌错误”而失败，即我们再次请求就会发现登录失败了：
![](https://i-blog.csdnimg.cn/direct/e7c54a27622644bab79ff7b2c77b8f71.png)

我们可以得到信息
```
登录成功的状态码：302
登录失败的状态码：200
```
注意这里的requests需要设置`allow_redirects=False`，获取跳转前的状态码
通过正则匹配获取到token和session
```python
token = re.search(r'(?<=name="token" value=")[^"]+', r.text)
session = re.search(r'(?<=name="set_session" value=")[^"]+', r.text)
```
然后传参登录即可，这里的token有特殊字符，需要使用`html.unescape`转义一下

phpmyadmin历史版本：[https://www.phpmyadmin.net/files/](https://www.phpmyadmin.net/files/)

通过遍历，我们可以发现是在4.8.0之后增加了set_session参数，而在这之前是只有token的

phpMyAdmin-4.6.6：
![](https://i-blog.csdnimg.cn/direct/5e1a481318584270acc30d6d9abc7383.png)

phpMyAdmin-4.8.5：
![](https://i-blog.csdnimg.cn/direct/e4d4b47b8eb2455d8fe80e2ed5318e24.png)

这样我们区分一下版本，然后不同版本用不同的POST请求就可以了？

哪有这么简单，在测试版本phpMyAdmin-4.1.10的时候发现，在登录的时候不管正确与否都是直接302跳转的。。。
![](https://i-blog.csdnimg.cn/direct/b39208b400084c168bba31bb97b5744f.png)

解决方案其实也很简单，在登录之后抓取这四个Cookie字段和token，传入302跳转中
![](https://i-blog.csdnimg.cn/direct/7710a4d1aa5d4534a956e3abf3a6398b.png)


如果响应中存在后台的一些敏感字段，则账号密码正确
### 未授权逻辑
我们需要先判断是否为未授权，然后再去执行爆破，我们看一下phpmyadmin后台的界面
![](https://i-blog.csdnimg.cn/direct/19a877c6f6ab4703a783ee7e15ff397d.png)


这里给出当前的检测方案
```php
def check_unauthorized_access(self, response_text: str) -> bool:
    """
    检查是否存在未授权访问
    
    Args:
        response_text: 响应文本
    
    Returns:
        True: 存在未授权访问（无需登录）
        False: 需要登录
    """
    # 检测关键字段，这些字段只在已登录状态下出现
    unauthorized_keywords = [
        'General settings',
        'Web server',
        'Appearance settings',
        'Database server',
        'Version information',
        'Server type',
        'PHP version',
        'Server:',
        'Server charset'
    ]
    
    # 同时检查是否不存在登录表单
    login_indicators = [
        'pma_username',
        'pma_password',
        'Log in'
    ]
    
    # 如果存在多个未授权访问的关键词，并且不存在登录表单
    keyword_count = sum(1 for keyword in unauthorized_keywords if keyword in response_text)
    has_login_form = any(indicator in response_text for indicator in login_indicators)
    
    # 如果有3个以上的关键词且没有登录表单，则判断为未授权访问
    return keyword_count >= 3 and not has_login_form
```
其实就是登录后的判断逻辑，检测关键词，如果存在则说明进入了后台界面，为未授权访问


## 总结
目前就到这里了，如果后续碰到了其他特殊版本再更新
工具：[https://github.com/bmth666/phpMyAdminCrack](https://github.com/bmth666/phpMyAdminCrack)

测了2天，修修补补，最终感觉还行，跑500个站，能跑出来1~2个弱口令。。。