#!/usr/bin/python

import logging
import subprocess
logging.getLogger("scapy.runtime").setLevel(logging.ERROR)
from scapy.all import*
import sys

if len( sys.argv ) !=4:
   print "Usage - ./syn_scan.py [Target.IP] [StartPort] [End Port]"
   print "Example - ./syn_scan.py 1.1.1.1 1 100"
   print "Example will TCP SYN scan ports 1 through 100 on 1.1.1.1"
   sys.exit()

ip = str(sys.argv[1])
start = int(sys.argv[2])
end = int(sys.argv[3])


for port in range(start,end):
   a=sr1(IP(dst=ip)/TCP(dport=port),timeout=0.1,verbose=0)
   if a ==None:
     pass
   else:
     if int(a[TCP].flags)==18:
        print port
     else:
        pass
