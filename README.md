# pynmap

- [pynmap](#pynmap)
  - [需求](#%e9%9c%80%e6%b1%82)
  - [原理](#%e5%8e%9f%e7%90%86)
    - [TCP 三次握手](#tcp-%e4%b8%89%e6%ac%a1%e6%8f%a1%e6%89%8b)
  - [实现](#%e5%ae%9e%e7%8e%b0)
  - [复盘](#%e5%a4%8d%e7%9b%98)
    - [多线程等待所有线程函数结束](#%e5%a4%9a%e7%ba%bf%e7%a8%8b%e7%ad%89%e5%be%85%e6%89%80%e6%9c%89%e7%ba%bf%e7%a8%8b%e5%87%bd%e6%95%b0%e7%bb%93%e6%9d%9f)
    - [ICMP Ping 遇到一个问题](#icmp-ping-%e9%81%87%e5%88%b0%e4%b8%80%e4%b8%aa%e9%97%ae%e9%a2%98)
  - [参考](#%e5%8f%82%e8%80%83)

基于 Scapy 实现的仿 nmap SYN 扫描器

## 需求

1. 基于 Scapy 实现
2. 利用 SYN 扫描开放端口
3. 多线程
4. 1-65535 全端口扫描
5. 结果采用类似 nmap 的方式展示

```sh
$ nmap -v -sS bing.com

Starting Nmap 7.01 ( https://nmap.org ) at 2020-04-24 11:58 CST
Initiating Ping Scan at 11:58
Scanning bing.com (13.107.21.200) [4 ports]
Completed Ping Scan at 11:58, 0.20s elapsed (1 total hosts)
Initiating Parallel DNS resolution of 1 host. at 11:58
Completed Parallel DNS resolution of 1 host. at 11:58, 0.03s elapsed
Initiating SYN Stealth Scan at 11:58
Scanning bing.com (13.107.21.200) [1000 ports]
Discovered open port 443/tcp on 13.107.21.200
Discovered open port 80/tcp on 13.107.21.200
Completed SYN Stealth Scan at 11:59, 18.81s elapsed (1000 total ports)
Nmap scan report for bing.com (13.107.21.200)
Host is up (0.035s latency).
Other addresses for bing.com (not scanned): 204.79.197.200 2620:1ec:c11::200
Not shown: 997 filtered ports
PORT    STATE  SERVICE
53/tcp  closed domain
80/tcp  open   http
443/tcp open   https
```

## 原理

### TCP 三次握手

TCP 三次握手几乎是程序员面试时一定会被问到的问题，握手的目的是为了建立连接


## 实现

有命令行接口，为了方便使用 [click](https://click.palletsprojects.com/en/7.x/)。

分析一下命令行的参数

```sh
--verbose 用于控制显示粒度
--port 用于选择端口范围
--timeout 控制每个数据包的等待时间
--size 控制一个线程发送的数据包数目
dst 是要扫描的 IP 地址
```

函数原型代码如下：

```python
@click.command()
@click.option("--verbose", help="Increase verbosity level", required=False, default=False)
@click.option("--port", help="Port ranges", default="1-65535")
@click.option("--size", help="Thread group size", default=1000)
@click.option("--timeout",
              help="how much time to wait after the last packet has been sent",
              default=3)
@click.argument("dst", required=True, type=str)
def pynmap(verbose, timeout, dst, port, size):
    """A simple SYN scanner."""
    pass
```


## 复盘

### 多线程等待所有线程函数结束

最开始的时候忘记了，写了这样的代码：

```python
th_li = [th1, th2, ...]  # several threads
for th in th_li:
    th.start()
    th.join()
```

这就导致每个线程都等待上一个线程结束了才会开始，跟一个线程再跑没有区别，要等待子线程结束应该先全部 `start` 之后再 `join`。

```python
th_li = [th1, th2, ...]  # several threads

[th.start() for th in th_li]
[th.join() for th in th_li]
```

### ICMP Ping 遇到一个问题

官方文档的写法是：

```python
>>> ans, unans = sr(IP(dst="192.168.1.1-254")/ICMP())
```

但是按照这种写法一直收不到响应的包，搜索以后发现需要给 ICMP 添加一个 id 参数就好了

```python
>>> ans, unans = sr(IP(dst="192.168.1.1-254")/ICMP(id=100))
```



## 参考

1. [python multithreading wait till all threads finished](https://stackoverflow.com/questions/11968689/python-multithreading-wait-till-all-threads-finished)

2. [Example of sending ICMP is not working #1490](https://github.com/secdev/scapy/issues/1490#issuecomment-416294800)