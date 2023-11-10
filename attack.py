from scapy.all import *

dnsSource = "192.168.68.114"
dnsDestination = "192.168.68.53"
queryTypes = ["ANY", "A", "AAAA", "CNAME", "MX", "NS", "PTR", "SOA", "TXT"]

queryNames = []
with open("tld-list.txt", "r") as f:
    tmp = f.readlines()

    for line in tmp:
        queryNames.append(line.replace("\n", ""))

packetNumer = 0
for domain in queryNames:
    successes = []

    for queryType in queryTypes:
        packetNumber += 1

        dnsQuery = IP(src=dnsSource, dst=dnsDestination) / UDP(sport=RandShort(), dport=53) / DNS(rd=1, do=0, qd=DNSQR(qname=domain, qtype=queryType), ar=DNSRROPT(rclass=8192))

        try:
            response = sr1(dnsQuery, verbose=0, timeout=1)
            print(response.summary())
            
            # Check if the response was transmitted via TCP
            if response[DNS].tc == 1:
                successes.append(0)
            else:
                successes.append(1)
        except:
            successes.append(0)

    # Check if the sum of successes is equal to the len of queryTypes
    if sum(successes) == len(queryTypes):
        # Write the domain to a file
        with open("valid-domains.txt", "a") as f:
            f.write(domain + "\n")    