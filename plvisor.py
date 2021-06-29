from scapy.all import *
import argparse
import concurrent.futures


class Port:
    """Class for sending and capturing ICMP requests via specific interface"""

    def __init__(self, iface):
        self.iface = iface
        self.iface_ip = get_if_addr(iface)
        self.router_ip = conf.route.route("0.0.0.0")[2]

    def send_icmp(self, count=20, inter=1):
        pkt = Ether() / IP(src=self.iface_ip, dst=self.router_ip, ttl=64) / ICMP() / "Hi, Scapy!"
        sendp(pkt, iface=self.iface, count=count, inter=inter)
        return None

    def capture(self, timeout=20, filter="icmp") -> list:
        # for more fancy output: prn=lambda x: f'{x[IP].src} > {x[IP].dst} : {str(x[Raw].load)}')
        packets = sniff(iface=self.iface,
                        timeout=timeout,
                        filter="icmp",
                        lfilter=lambda p: p.haslayer(Raw) and b"Hi, Scapy!" in p[Raw].load,
                        prn=lambda x: x.summary())
        return packets


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description="This module can send/capture packets.")
    parser.add_argument("interface")
    parser.add_argument("action")
    args = parser.parse_args()

    ifaces = get_if_list()
    input_ifaces = args.interface.split(",")

    ports = [Port(iface) for iface in input_ifaces if iface in ifaces]

    # Parallel sending/capturing
    with concurrent.futures.ThreadPoolExecutor() as executor:
        if args.action == "send":
            threads = [executor.submit(port.send_icmp) for port in ports]
        elif args.action == "capture":
            threads = [executor.submit(port.capture) for port in ports]

        for f in concurrent.futures.as_completed(threads):
            f.result()
