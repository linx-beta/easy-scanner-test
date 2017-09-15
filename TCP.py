#!/usr/bin/python

import logging
logging.getLogger("scapy.runtime").setLevel(logging.ERROR)
from scapy.all import*

SYN=IP(dst="1.1.1.1")/TCP(doprt=80,flags="S")

print"-- SENT --"
SYN.display()

print"\n\n-- REVEIED"
response=sr1(SYN,timeout=1,verbose=0)
response.diplay()

if int(response[TCP],flags)==18:
   print "\n\n-- SENT --"
   A=IP(dst="192.168.1.134")/TCP(dport=25,flags="A",ack=(response[TCP].seq+1))
   A.display()
   print"\n\n-- RECEIVED --"
   response2=sr1(A,timeout=1,verbose=0)
   response2.display()
else:
   print "SYN-ACK not returned"
