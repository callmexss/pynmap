import os
import time
import logging
import threading


import click
from scapy.all import sr1, IP, TCP


# logging.basicConfig(level=logging.DEBUG,
#                     filename="pynmap.log",
#                     format='%(asctime)s : %(levelname)s : %(filename)s : '
#                            '%(lineno)s : %(funcName)s : %(message)s')


OPEN_PORTS = []
timeout = 3
start_info = "Starting pynmap 0.01"
locker = threading.Lock()


def show_info(info, extra=""):
    if extra:
        print(f"{info} at {time.asctime()} {extra}")
    else:
        print(f"{info} at {time.asctime()}")

    
def show_discovery(port, dst):
    print(f"Discovered open port {port}/tcp on {dst}")

    
def scan_batch(ip, ports, timeout=timeout, verbose=False):
    th_li = []
    for port in ports:
        th_li.append(threading.Thread(target=scan,
                                      args=(ip, port, timeout, verbose)))
    for th in th_li:
        th.start()
        th.join()


def scan(ip, port, timeout=timeout, verbose=False):
    """Do SYN scan on a specific ip and port

    Arguments:
        ip {str} -- ip address
        port {int} -- port number

    Keyword Arguments:
        timeout {int} -- how much time to wait after the last packet has been sent (default: {3})
    """    
    # show_info(f"Scan {ip} {port}")
    global OPEN_PORTS
    ret = sr1(IP(dst=ip)/TCP(dport=int(port), flags="S"),
              timeout=timeout,
              verbose=0)

    if verbose and ret:
        show_discovery(port, ip)
        OPEN_PORTS.append(port)

    if ret:
        locker.acquire()
        OPEN_PORTS.append(ret)
        locker.release()

    return True if ret else False

    
def scan_range(dst, start, end, timeout=timeout, verbose=False):
    port_li = [[] for x in range(os.cpu_count())]  # create several thread lists
    for port in range(start, end + 1):
        i = port % os.cpu_count()
        port_li[i].append(port)

    th_li = []
    for each in port_li:
        th_li.append(threading.Thread(target=scan_batch,
                                      args=(dst, each, timeout, verbose)))

    for th in th_li:
        th.start()
    

@click.command()
@click.option("--verbose", help="Increase verbosity level", required=False, default=False)
@click.option("--port", help="Port ranges", default="1-65535")
@click.option("--timeout",
              help="how much time to wait after the last packet has been sent",
              default=3)
@click.argument("dst", required=True, type=str)
def pynmap(verbose, timeout, dst, port):
    """A simple SYN scanner."""
    global OPEN_PORTS
    start_time = time.time()
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

    scan_range(dst, start, end, verbose=verbose, timeout=timeout)
    end_time = time.time()
    elapsed = end_time - start_time
    if verbose:
        show_info("Completed SYN Stealth Scan",
                f"{round(elapsed)}s elapsed ({end - start + 1} total ports)")
    
    print(f"pynmap scan report for {dst}")
    print(f"Not shown: {end - start + 1 - len(OPEN_PORTS)} filtered ports")
    print(OPEN_PORTS)
    if OPEN_PORTS:
        print("PORT\tSTATE\tSERVICE")
        for port in OPEN_PORTS:
            print(f"{port}/tcp\topen\{m.get(str(port), 'UNKNOWN')}")


if __name__ == "__main__":
    pynmap()