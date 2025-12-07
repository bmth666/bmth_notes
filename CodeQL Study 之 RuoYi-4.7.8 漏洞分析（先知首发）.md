
## 前提概要
前段时间看到了1ue师傅的poc：[https://github.com/luelueking/RuoYi-v4.7.8-RCE-POC](https://github.com/luelueking/RuoYi-v4.7.8-RCE-POC)

恰好最近在学习codeql，拿来练手了

下载最新版本的[https://github.com/yangzongzhuan/RuoYi/releases/tag/v4.7.8](https://github.com/yangzongzhuan/RuoYi/releases/tag/v4.7.8)，并安装依赖
官方文档：[https://doc.ruoyi.vip/ruoyi/](https://doc.ruoyi.vip/ruoyi/)
![](https://i-blog.csdnimg.cn/blog_migrate/8c4251af08c90902de637308383990c8.png)

后台定时任务处支持两种调用：
1. Bean调用示例：需要添加对应Bean注解`@Component`或`@Service`
2. Class类调用示例：添加类和方法指定包即可，调用目标字符串

### 黑&白名单限制
看到`com.ruoyi.quartz.controller.SysJobController#addSave`
![](https://i-blog.csdnimg.cn/blog_migrate/332f670f5da96457806ed88251c366dd.png)

黑名单：
```java
public static final String LOOKUP_RMI = "rmi:";
public static final String LOOKUP_LDAP = "ldap:";
public static final String LOOKUP_LDAPS = "ldaps:";
public static final String HTTP = "http://";
public static final String HTTPS = "https://";
public static final String[] JOB_ERROR_STR = { "java.net.URL", "javax.naming.InitialContext", "org.yaml.snakeyaml","org.springframework", "org.apache", "com.ruoyi.common.utils.file", "com.ruoyi.common.config" };
```
白名单：
```java
public static final String[] JOB_WHITELIST_STR = { "com.ruoyi" };
```
### 定时任务执行逻辑
看到`com.ruoyi.quartz.util.JobInvokeUtil#invokeMethod`
![](https://i-blog.csdnimg.cn/blog_migrate/fd64891f78c2126cc7ccedf4581d0fbe.png)

获取beanName、methodName、methodParams一系列的值，然后反射调用
![](https://i-blog.csdnimg.cn/blog_migrate/155299f590696f5bf6ca08df11a8d337.png)

具体就不分析了，直接给出结论：
1. 若是spring容器中注册过的bean，则可直接从spring容器中取出，若是指定class名称，则会通过反射newInstance()创建对象，因此必须保证class中存在无参构造函数
2. 方法必须是public修饰的方法
3. 方法参数类型只能为String、Boolean、Long、Double、Integer


## codeql分析


搭建数据库（注意路径不能包含中文）：
```bash
codeql database create ruoyi-database --language=java --command='mvn clean package -f "pom.xml"'
```
写一个查询语句：
```java
import java

from Method m

where 
    m.getDeclaringType().getAConstructor().hasNoParameters()
    and m.isPublic()
    and m.getAParamType() instanceof TypeString
    and m.getDeclaringType().getPackage().getName().matches("com.ruoyi%")
    and not m.isAbstract()
    and not m.getDeclaringType().getPackage().getName().matches("com.ruoyi.common.config%")
    and not m.getDeclaringType().getPackage().getName().matches("com.ruoyi.common.utils.file%")
    and not m.getName().matches("get%")
    and not m.getName().matches("is%")
    and not m.getName().matches("has%")

select m.getDeclaringType().getPackage().getName(),m.getDeclaringType(),m
```
将一些不太可能实现利用的方法去除得到：
![](https://i-blog.csdnimg.cn/blog_migrate/a36b6ab5c81325a3a44fffff8eb97f6a.png)

### 利用类
 `com.ruoyi.common.utils.http.HttpUtils#sendGet`
是一个无回显的SSRF
![](https://i-blog.csdnimg.cn/blog_migrate/5db835854b75c7763e424d847ecec52d.png)

可以使用file、ftp、jar等协议，但由于禁用了http和https，用处不大
```java
com.ruoyi.common.utils.http.HttpUtils.sendGet("ftp://d8lmq0s1.dnslog.pw")
```
 `com.ruoyi.generator.service.impl.GenTableServiceImpl#createTable`
![](https://i-blog.csdnimg.cn/blog_migrate/2c367150f8666d0c926026ff94570110.png)

跟进到文件`GenTableMapper.xml`
![](https://i-blog.csdnimg.cn/blog_migrate/9b76707a8fe0954d3a596868ed673cfe.png)

>MyBatis支持两种参数符号，一种`#`使用预编译向占位符中设置值，可有效防止sql注入，另一种`$`拼接SQL，触发sql注入的关键，也就是前几个版本的sql注入

其实我们需要的就是update的功能，即：
```java
genTableServiceImpl.createTable('UPDATE sys_job SET invoke_target = 0x6a61... WHERE job_id = 1;')
```
这样就绕过了新建任务的限制，直接修改数据库中的内容了

### RCE利用
黑名单的几个类：
1. `javax.naming.InitialContext#lookup`
2. `org.yaml.snakeyaml.Yaml#load`
3. `org.springframework.jndi.JndiLocatorDelegate#lookup`
4. `org.springframework.jdbc.datasource.lookup.JndiDataSourceLookup#getDataSource`
5. `org.apache.velocity.runtime.RuntimeInstance#init`


已经有师傅总结过了，就不多赘述了

实测可以打snakeyaml，或者JNDI注入->反序列化


可参考：
[某依rce黑名单多种bypass方法分析](https://xz.aliyun.com/t/10957)
[定时任务功能点绕过黑白名单执行任意sql语句](https://xz.aliyun.com/t/11336)

