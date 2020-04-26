# pynmap

- [pynmap](#pynmap)
  - [需求](#%e9%9c%80%e6%b1%82)
  - [原理](#%e5%8e%9f%e7%90%86)
  - [实现](#%e5%ae%9e%e7%8e%b0)
  - [演示](#%e6%bc%94%e7%a4%ba)
  - [复盘](#%e5%a4%8d%e7%9b%98)
    - [多线程等待所有线程函数结束](#%e5%a4%9a%e7%ba%bf%e7%a8%8b%e7%ad%89%e5%be%85%e6%89%80%e6%9c%89%e7%ba%bf%e7%a8%8b%e5%87%bd%e6%95%b0%e7%bb%93%e6%9d%9f)
    - [ICMP Ping 遇到一个问题](#icmp-ping-%e9%81%87%e5%88%b0%e4%b8%80%e4%b8%aa%e9%97%ae%e9%a2%98)
  - [完整代码](#%e5%ae%8c%e6%95%b4%e4%bb%a3%e7%a0%81)
  - [参考](#%e5%8f%82%e8%80%83)

基于 Scapy 实现的仿 nmap SYN 扫描器

## 需求

1. 基于 Scapy 实现
2. 利用 SYN 扫描开放端口
3. 多线程
4. 支持 1-65535 全端口扫描
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

**TCP 三次握手**几乎是程序员面试时一定会被问到的问题，握手的目的是为了建立连接，连接的本质是通过一组数据结构维护通信两端的状态，以保证数据包的**不丢失、不乱序、不重复**，达到可靠传输的目的。

TCP 三次握手可以概括成下面三个步骤，三次握手成功后连接建立，此时对于通信的每一端来说都发送并接收到了一个数据包。

> “请求 -> 应答 -> 应答之应答”

如果两次握手能够成功那么就可以知道某个数据包是可以到达特定主机的特定端口的，也就是说可以用于探测一个主机开放的 TCP 端口，SYN 扫描就是这个原理。

## 实现

有命令行接口，为了方便使用 [click](https://click.palletsprojects.com/en/7.x/)。

分析一下命令行的参数

- --verbose 用于控制显示粒度
- --port 用于选择端口范围
- --timeout 控制每个数据包的等待时间
- --size 控制一个线程发送的数据包数目
- --ping 扫描之前先 ping 目标主机是否在线
- dst 是要扫描的 IP 地址

函数原型代码如下：

```python
@click.command()
@click.option("--verbose", help="Increase verbosity level", required=False, default=False)
@click.option("--port", help="Port ranges", default="1-65535")
@click.option("--ping", help="Ping before scan", default=False)
@click.option("--size", help="Thread group size", default=1000)
@click.option("--timeout",
              help="how much time to wait after the last packet has been sent",
              default=3)
@click.argument("dst", required=True, type=str)
def pynmap(verbose, timeout, dst, port, ping, size):
    """A simple SYN scanner
    """    
    global OPEN_PORTS  # 用于多线程保存数据的全局变量
    start_time = time.time()
    if ping:
        # 构建一个 ICMP Ping 包
        ans, _ = sr(IP(dst=dst)/ICMP(id=RandShort()), verbose=0, retry=2, timeout=timeout)
        if not ans:
            elapsed = time.time() - start_time
            print("Note: Host seems down.")
            print(f"pynmap done: 1 IP address(0 hosts up) scanned in {round(elapsed)} seconds")
            return
            
    if verbose:
        show_info(start_info)

    if '-' in port:
        start, end = list(map(int, port.split('-')))
        assert start >= 1 and end <= 65535 and start <= end, "Invalid port range"
        if verbose:
            show_info(f"Scanning {dst}[{end - start + 1} ports]")
    else:
        start = end = int(port)  # only one port to scan
        if verbose:
            show_info(f"Scanning {dst}[{1} ports]")

    # 执行 SYN 扫描的函数
    scan_range(dst, start, end, verbose=verbose, timeout=timeout, size=size)
    end_time = time.time()
    elapsed = end_time - start_time
    if verbose:
        show_info("Completed SYN Stealth Scan",
                f"{round(elapsed)}s elapsed ({end - start + 1} total ports)")
    
    print(f"pynmap scan report for {dst}")
    print(f"Not shown: {end - start + 1 - len(OPEN_PORTS)} filtered ports")
    if OPEN_PORTS:
        print("PORT\t\tSTATE\t\tSERVICE")
        for port in OPEN_PORTS:
            port_str = str(port) + "/tcp"
            open_str = "open"
            print(f"{port_str:<8s}\t{open_str:<8s}\t{m.get(str(port), 'UNKNOWN')}")
    print()
    print(f"pynmap done: 1 IP address(up) scanned in {round(elapsed)} seconds")
```

然后是 `scan_range` 函数的实现，逻辑是将要扫描的端口分成若干个组，一个线程扫描一组端口。

```python
def scan_range(dst, start, end, timeout=timeout, verbose=False, size=size):
    """Scan a range of ports

    Arguments:
        dst {str} -- target IP address
        start {int} -- start port
        end {int} -- end port

    Keyword Arguments:
        timeout {number} -- time wait for a response packet (default: {timeout})
        verbose {bool} -- verbose or not (default: {False})
        size {int} -- how many ports assign to a thread (default: {size})
    """    
    if start == end:
        scan(dst, start, timeout, verbose)
        return

    th_li = []
    for i in range(start, end + 1, size):
        if i + size > 65535:
            ports = list(range(i, 65536))
        else:
            ports = list(range(i, i + size))
        th_li.append(threading.Thread(target=scan,
                                      args=(dst, ports, timeout, verbose)))

    [x.start() for x in th_li]
    [x.join() for x in th_li]
```

扫描函数 scan 的实现。

```python
def scan(ip, ports, timeout=timeout, verbose=False):
    """Do SYN scan on a specific ip and port

    Arguments:
        ip {str} -- ip address
        port {int} -- port number

    Keyword Arguments:
        timeout {number} -- how much time to wait after the last packet has been sent (default: {3})
    """
    # show_info(f"Scan {ip} {port}")
    global OPEN_PORTS
    sport = RandShort()
    # sr 是发送并接收（send, receive）数据包的意思
    # 标志位设置为 SYN
    ans, _ = sr(IP(dst=ip)/TCP(sport=sport, dport=ports, flags="S"),
                    timeout=timeout,
                    verbose=0)

    if verbose and ans:
        for port in [x[1][TCP].sport for x in ans]:
            show_discovery(port, ip)

    if ans:
        locker.acquire()
        OPEN_PORTS.extend([x[1][TCP].sport for x in ans])
        locker.release()

    return True if ans else False
```

## 演示

查看帮助和命令行接口：

```sh
$ pynmap.py --help

Usage: pynmap.py [OPTIONS] DST

  A simple SYN scanner.

Options:
  --verbose BOOLEAN  Verbose or not (default False)
  --port TEXT        Port ranges(default 1-65535)
  --ping TEXT        Ping before scan
  --size INTEGER     Thread group size
  --timeout FLOAT    how much time to wait after the last packet has been sent
  --help             Show this message and exit.
```

扫描开放端口：

```sh
$ pynmap.py --port 1-1024 baidu.com

pynmap scan report for baidu.com
Not shown: 1022 filtered ports
PORT            STATE           SERVICE
80/tcp          open            http
443/tcp         open            https

pynmap done: 1 IP address(up) scanned in 5 seconds

$ pynmap.py --port 1-1024 --verbose True bing.com

Starting pynmap 0.0.1 at Sat Apr 25 21:22:15 2020
Scanning bing.com[1024 ports] at Sat Apr 25 21:22:15 2020
Discovered open port 53/tcp on bing.com
Discovered open port 80/tcp on bing.com
Discovered open port 443/tcp on bing.com
Completed SYN Stealth Scan at Sat Apr 25 21:22:19 2020 5s elapsed (1024 total ports)
pynmap scan report for bing.com
Not shown: 1021 filtered ports
PORT            STATE           SERVICE
53/tcp          open            dns
80/tcp          open            http
443/tcp         open            https

pynmap done: 1 IP address(up) scanned in 5 seconds
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

然而多线程速度并没有变快多少...不知道是因为写法有问题还是怎么了，后面再慢慢查查看吧。

### ICMP Ping 遇到一个问题

官方文档的写法是：

```python
>>> ans, unans = sr(IP(dst="192.168.1.1-254")/ICMP())
```

但是按照这种写法一直收不到响应的包，搜索以后发现需要给 ICMP 添加一个 id 参数就好了

```python
>>> ans, unans = sr(IP(dst="192.168.1.1-254")/ICMP(id=100))
```

## 完整代码

```python
import time
import threading


import click
from scapy.all import sr, sr1, IP, ICMP, TCP, RandShort


OPEN_PORTS = []
timeout = 1.5
size = 10000
start_info = "Starting pynmap 0.0.1"
locker = threading.Lock()
m = {
    "22": "ssh",
    "53": "dns",
    "80": "http",
    "443": "https",
}


def show_info(info, extra=""):
    if extra:
        print(f"{info} at {time.asctime()} {extra}")
    else:
        print(f"{info} at {time.asctime()}")

    
def show_discovery(port, dst):
    print(f"Discovered open port {port}/tcp on {dst}")


def scan(ip, ports, timeout=timeout, verbose=False):
    """Do SYN scan on a specific ip and port

    Arguments:
        ip {str} -- ip address
        port {int} -- port number

    Keyword Arguments:
        timeout {number} -- how much time to wait after the last packet has been sent (default: {3})
    """
    # show_info(f"Scan {ip} {port}")
    global OPEN_PORTS
    sport = RandShort()
    ans, _ = sr(IP(dst=ip)/TCP(sport=sport, dport=ports, flags="S"),
                    timeout=timeout,
                    verbose=0)

    if verbose and ans:
        for port in [x[1][TCP].sport for x in ans]:
            show_discovery(port, ip)

    if ans:
        locker.acquire()
        OPEN_PORTS.extend([x[1][TCP].sport for x in ans])
        locker.release()

    return True if ans else False

    
def scan_range(dst, start, end, timeout=timeout, verbose=False, size=size):
    """Scan a range of ports

    Arguments:
        dst {str} -- target IP address
        start {int} -- start port
        end {int} -- end port

    Keyword Arguments:
        timeout {number} -- time wait for a response packet (default: {timeout})
        verbose {bool} -- verbose or not (default: {False})
        size {int} -- how many ports assign to a thread (default: {size})
    """    
    if start == end:
        scan(dst, start, timeout, verbose)
        return

    th_li = []
    for i in range(start, end + 1, size):
        if i + size > 65535:
            ports = list(range(i, 65536))
        else:
            ports = list(range(i, i + size))
        th_li.append(threading.Thread(target=scan,
                                      args=(dst, ports, timeout, verbose)))

    [x.start() for x in th_li]
    [x.join() for x in th_li]
   

@click.command()
@click.option("--verbose", help="Verbose or not (default False)", type=bool,
               required=False, default=False)
@click.option("--port", help="Port ranges(default 1-65535)", default="1-65535")
@click.option("--ping", help="Ping before scan", default=False)
@click.option("--size", help="Thread group size", default=1000)
@click.option("--timeout",
              help="how much time to wait after the last packet has been sent",
              default=3.0)
@click.argument("dst", required=True, type=str)
def pynmap(verbose, timeout, dst, port, ping, size):
    """A simple SYN scanner.
    """
    global OPEN_PORTS
    start_time = time.time()
    if ping:
        ans, _ = sr(IP(dst=dst)/ICMP(id=RandShort()), verbose=0, retry=2, timeout=timeout)
        if not ans:
            elapsed = time.time() - start_time
            print("Note: Host seems down.")
            print(f"pynmap done: 1 IP address(0 hosts up) scanned in {round(elapsed)} seconds")
            return
            
    if verbose:
        show_info(start_info)

    if '-' in port:
        start, end = list(map(int, port.split('-')))
        assert start >= 1 and end <= 65535 and start <= end, "Invalid port range"
        if verbose:
            show_info(f"Scanning {dst}[{end - start + 1} ports]")
    else:
        start = end = int(port)  # only one port to scan
        if verbose:
            show_info(f"Scanning {dst}[{1} ports]")

    scan_range(dst, start, end, verbose=verbose, timeout=timeout, size=size)
    end_time = time.time()
    elapsed = end_time - start_time
    if verbose:
        show_info("Completed SYN Stealth Scan",
                f"{round(elapsed)}s elapsed ({end - start + 1} total ports)")
    
    print(f"pynmap scan report for {dst}")
    print(f"Not shown: {end - start + 1 - len(OPEN_PORTS)} filtered ports")
    if OPEN_PORTS:
        print("PORT\t\tSTATE\t\tSERVICE")
        for port in OPEN_PORTS:
            port_str = str(port) + "/tcp"
            open_str = "open"
            print(f"{port_str:<8s}\t{open_str:<8s}\t{m.get(str(port), 'UNKNOWN')}")
    print()
    print(f"pynmap done: 1 IP address(up) scanned in {round(elapsed)} seconds")


if __name__ == "__main__":
    pynmap()
```

## 参考

1. [python multithreading wait till all threads finished](https://stackoverflow.com/questions/11968689/python-multithreading-wait-till-all-threads-finished)

2. [Example of sending ICMP is not working #1490](https://github.com/secdev/scapy/issues/1490#issuecomment-416294800)

3. [极课时间——趣谈网络协议](https://time.geekbang.org/column/intro/85)