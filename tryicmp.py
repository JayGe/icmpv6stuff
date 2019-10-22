#!/usr/bin/end python 

from scapy.all import *
import time

destip = ""

def main():
    type = 128 # starting at 128, could start at 1
    while type < 256:
        payload = chr(type)+"\x00\xc5\x5d\x00\x00\x00\x00"
        print("Sending", type)
        send(IPv6(dst=destip, nh=58)/payload)
        type += 1
        time.sleep(0.5)

if __name__ == "__main__":
    main()

