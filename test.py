from scapy.all import *

dnsSource = "192.168.68.108"
dnsDestination = "8.8.8.8"
queryName = "google.com"

dnsQuery = IP(src=dnsSource, dst=dnsDestination) / UDP(sport=RandShort(), dport=53) / DNS(rd=1, ad=0, cd=1, qd=DNSQR(qname=queryName, qtype="A"), ar=DNSRROPT(rclass=8192))

try:
    response = sr1(dnsQuery, verbose=0, timeout=1)
    response.show()

except Exception as e:
    print(f"An exception occurred: {e}\n")
    print(dnsQuery)