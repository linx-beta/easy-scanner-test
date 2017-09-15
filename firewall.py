#！/usr/bin/python

import sys
import logging
logging.getLogger('scapy.runtime').setLevel(logging.ERROR)
from scapy.all import *

if len(sys.argv) !=3
	print ""
	
ip = sys.argv[1]
port = int(sys.argv[2])

ACK_response = sr1(IP(dst=ip)/TCP(dport=prot.flags='A'),timeout=1,verbose=0)
SYN_response = sr1(IP(dst=ip)/TCP(dport=prot.flags='S'),timeout=1,verbose=0)
if (ACK_response == None) and (SYN_response == None):
	print 'Port is
elif ((ACK_response == None) or (SYN_response == None)) and not ((ACK_response == None) and (SYN_response == None)):

elif int(SYN_response[TCP].flags) == 18:

elif int(SYN_response[TCP].flags) == 20:

else:
