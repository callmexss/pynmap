# pynmap

基于 Scapy 实现的仿 nmap SYN 扫描器

## 需求

1. 基于 Scapy 包实现
2. 利用 SYN 扫描开放端口
3. 多线程
4. 全端口扫描
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

## 实现

有命令行接口，为了方便采用 click 这个包。