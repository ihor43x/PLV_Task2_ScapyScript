import argparse
from scapy.all import sendp, send, sniff, IP, ICMP, get_if_list


# import scapy.all as scapy

class Port:

    def __init__(self, iface):
        self.iface = iface
        # self.action = action

    def send_icmp(self, count=5, inter=1, loop=1) -> bool:
        # p = send(IP(dst="127.0.0.1") / ICMP(), count=count, inter=inter, loop=loop)
        # p = send(IP(dst="192.168.1.1") / ICMP(), count=count, inter=inter, loop=loop)
        p = send(IP(dst="8.8.8.8") / ICMP(), count=count, inter=inter, loop=loop)
        return p

    def capture(self, timeout=10) -> list:
        packets = sniff(iface=self.iface, filter="icmp", timeout=timeout, prn=lambda x: x.summary())
        return [p.summary() for p in packets]


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description="This module can send/capture packets.")
    parser.add_argument("interface")
    parser.add_argument("action")
    args = parser.parse_args()
    p1 = Port(args.interface)

    ifaces = get_if_list()
    if args.interface not in ifaces:
        print(f"There is no such interface: {args.interface}")
        exit()

    if args.action == "send":
        p1.send_icmp()
    elif args.action == "capture":
        p1.capture()

    # print(p1.iface)
    # print(p1.action)
