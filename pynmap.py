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