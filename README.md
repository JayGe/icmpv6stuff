A couple of scapy ICMPv6 scripts for testing running commands over, no security at all. 

receiveecho.py - listens on defined interface for icmpv6 echo requests and executed the content, will likely require having to block the legitimate echo responses: ip6tables -I <interface> -p icmpv6  --icmpv6-type echo-reply -j DROP
sendecho.py - sends commands to defined host over icmpv6 echo queries and shows their response. 

receivehaad.py - listens on defined interface for ICMPv6HAADRequest and executes the content sending response in ICMPv6HAADReply, not valid HAAD packets
sendhaad.py - sends commands to defined host over icmpv6 with an ICMPv6HAADRequest type, not   valid HAAD packet. 

tryicmp.py cycles through sending different icmpv6 type packets
