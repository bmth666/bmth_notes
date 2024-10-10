title: 小程序&APP 渗透测试初探
author: Bmth
tags:
  - Android
categories:
  - 渗透测试
top_img: 'https://img-blog.csdnimg.cn/direct/e7f1b4f4cb50485fbd5044491ed9fae9.png'
cover: 'https://img-blog.csdnimg.cn/direct/e7f1b4f4cb50485fbd5044491ed9fae9.png'
date: 2024-06-18 22:30:00
---
![](https://img-blog.csdnimg.cn/direct/e7f1b4f4cb50485fbd5044491ed9fae9.png)

余操业之时，常有小程序&APP渗透，遂小作一文，以记之

mumu模拟器->永遠の神だ

## 抓包
The source of all things

### Method one
chose this
![](https://img-blog.csdnimg.cn/direct/178809c43b734985a94678ed8ba6cb2e.png)

root need
![](https://img-blog.csdnimg.cn/direct/e6cc7d474e8f4ec086aacba81c229c98.png)

Download burp certificate：http://127.0.0.1:8080/cert

Convert certificate to pem format，get md5
```bash
openssl x509 -inform DER -in cacert.der -out cacert.pem
openssl x509 -inform PEM -subject_hash_old -in cacert.pem
```
![](https://img-blog.csdnimg.cn/direct/58e7988fadfc47d29c762f0eef21db9a.png)

Change the certificate filename to 9a5ba575.0

Copy the certificate to `/system/etc/security/cacerts/`(MT管理器 is a good tool)
![](https://img-blog.csdnimg.cn/direct/dd04b6dc470741dc8e7f0a38e8adef9a.png)

Modify permissions
![](https://img-blog.csdnimg.cn/direct/d0c40ebe9f6a4d78b809d6865820e2bb.png)

Finally，just add an agent that will do
![](https://img-blog.csdnimg.cn/direct/74bbe075c9e44bce84bdfbb30cf294c5.png)

wx kfc applet test：
![](https://img-blog.csdnimg.cn/direct/abd92235b7af413d8de1faeb641b2f26.png)

But this method has many bugs，so i suggest another tool

### Method two
[先进API生产力工具 | Reqable](https://reqable.com/zh-CN/)

Just do it
![](https://img-blog.csdnimg.cn/direct/a8beba44564a4ba4b6d2d728f5ebfd79.png)

## Magisk
多开鸭：[MuMu12安装Magisk官版和狐狸面具教程](https://www.duokaiya.com/928.html)
![](https://img-blog.csdnimg.cn/direct/fcb9ab8c72064b51b92a41f93ea04344.png)

Delete the file `/system/xbin/su`，as well as the entire folder of `/system/app/SuperUser`
![](https://img-blog.csdnimg.cn/direct/86f9d37ade7947cda3fc88a33841f07f.png)

Restart
![](https://img-blog.csdnimg.cn/direct/052657082ed842e3a986ef29ec1d61a4.png)

The official version is Similarly

## 工具推荐
ApkCheckPack：[https://github.com/moyuwa/ApkCheckPack/](https://github.com/moyuwa/ApkCheckPack/)
apk文件加固特征检查工具，汇总收集已知特征和手动收集大家提交的app加固特征，目前总计约170条特征，支持40个厂商的加固检测

AppMessenger：[https://github.com/sulab999/AppMessenger](https://github.com/sulab999/AppMessenger)
一款适用于以APP病毒分析、APP漏洞挖掘、APP开发、HW行动/红队/渗透测试团队为场景的移动端(Android、iOS、鸿蒙)辅助分析工具

AppInfoScanner：[https://github.com/kelvinBen/AppInfoScanner](https://github.com/kelvinBen/AppInfoScanner)
一款适用于以HW行动/红队/渗透测试团队为场景的移动端(Android、iOS、WEB、H5、静态网站)信息收集扫描工具，可以帮助渗透测试工程师、攻击队成员、红队成员快速收集到移动端或者静态WEB站点中关键的资产信息并提供基本的信息输出,如：Title、Domain、CDN、指纹信息、状态信息等

APKDeepLens：[https://github.com/d78ui98/APKDeepLens](https://github.com/d78ui98/APKDeepLens)
Android security insights in full spectrum.

MobSF：[https://github.com/MobSF/Mobile-Security-Framework-MobSF](https://github.com/MobSF/Mobile-Security-Framework-MobSF)
 Mobile Security Framework (MobSF) is an automated, all-in-one mobile application (Android/iOS/Windows) pen-testing, malware analysis and security assessment framework capable of performing static and dynamic analysis. 
 

Apktool：[https://apktool.org/](https://apktool.org/)
反编译APK神器

Android Killer：[https://github.com/Charlott2/android-killer](https://github.com/Charlott2/android-killer)
经典的安卓反编译工具

GDA：[https://github.com/charles2gan/GDA-android-reversing-Tool](https://github.com/charles2gan/GDA-android-reversing-Tool)
亚洲第一款全交互式的现代反编译器，同时也是世界上最早实现的dalvik字节码反编译器。 GDA不只是一款反编译器，同时也是一款轻便且功能强大的综合性逆向分析利器，其不依赖java且支持apk, dex, odex, oat, jar, class, aar文件的反编译， 支持python及java脚本自动化分析。其包含多个由作者独立研究的高速分析引擎:反编译引擎、漏洞检测引擎、 恶意行为检测引擎、污点传播分析引擎、反混淆引擎、apk壳检测引擎等等

wxapkg：[https://github.com/wux1an/wxapkg](https://github.com/wux1an/wxapkg)
微信小程序反编译工具，.wxapkg 文件扫描 + 解密 + 解包工具

wxapkg-convertor：[https://github.com/ezshine/wxapkg-convertor](https://github.com/ezshine/wxapkg-convertor)
一个反编译微信小程序的工具

BlackDex：[https://github.com/CodingGay/BlackDex](https://github.com/CodingGay/BlackDex)
BlackDex是一个运行在Android手机上的脱壳工具，支持5.0～12，无需依赖任何环境任何手机都可以使用，包括模拟器。只需几秒，即可对已安装包括未安装的APK进行脱壳

JsHook：[https://github.com/Xposed-Modules-Repo/me.jsonet.jshook](https://github.com/Xposed-Modules-Repo/me.jsonet.jshook)
用js实现hook 支持java层和native层

算法助手：[https://github.com/Xposed-Modules-Repo/com.junge.algorithmaide](https://github.com/Xposed-Modules-Repo/com.junge.algorithmaide)
神器！

