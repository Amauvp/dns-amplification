import argparse
from scapy.all import *
import json

global queriesInfo, responsesInfo
queriesInfo = {}
responsesInfo = {}

def packetHandler(packet, srcIP, dstIP, qname):
    """
    This function is called for every packet sniffed.
    The packet is then parsed, stored and used to calculate the amplification factor.

    :param packet: The packet sniffed by Scapy (scapy.packet.Packet)
    :param srcIP: The source IP address (str)
    :param dstIP: The destination IP address (str)
    :param qname: The query name (str)
    """
    if IP in packet and UDP in packet and DNS in packet:
        if packet[IP].src == srcIP and packet[IP].dst == dstIP and packet[DNS].qr == 0 and str(packet[DNS].qd.qname.decode()) == qname + '.':
            queryInfo = [packet[DNSQR].qtype, len(packet[DNS])]
            queriesInfo[packet[DNS].id] = queryInfo

        elif packet[IP].src == dstIP and packet[IP].dst == srcIP and packet[DNS].qr == 1 and str(packet[DNS].qd.qname.decode()) == qname + '.':
            responseInfo = [packet[DNS].qd.qtype, len(packet[DNS])]
            responsesInfo[packet[DNS].id] = responseInfo

def sniffPackets(srcIP, dstIP, qname):
    """
    This function is used to sniff the packets.

    :param srcIP: The source IP address (str)
    :param dstIP: The destination IP address (str)
    :param qname: The query name (str)
    """
    sniff(filter=f"udp and port 53", timeout=60, prn=lambda x: packetHandler(x, srcIP, dstIP, qname))

def calculateAmplificationFactors():
    """
    This function is used to calculate the amplification factor.

    :return: The amplification factor (dict)
    """
    results = {'255': [], '1': [], '28': [], '5': [], '15': [], '2': [], '6': [], '16': []}
    for queryId in queriesInfo:
        for responseId in responsesInfo:
            if queryId == responseId:
                amplificationFactor = responsesInfo[responseId][1] / queriesInfo[queryId][1]
                results[str(queriesInfo[queryId][0])].append(amplificationFactor)
    
    return results

def meanAmplificationFactor(allFactors):
    """
    This function is used to calculate the mean amplification factor.

    :param allFactors: The amplification factors (dict)
    :return: The mean amplification factor (dict)
    """
    meanFactors = {}
    for queryType in allFactors:
        meanFactors[queryType] = sum(allFactors[queryType]) / len(allFactors[queryType])

    return meanFactors

if __name__ == '__main__':
    parser = argparse.ArgumentParser(description='Calculate Amplification Factor')
    parser.add_argument('-s', '--srcIP', type=str, help='Source IP')
    parser.add_argument('-d', '--dstIP', type=str, help='Destination IP')
    parser.add_argument('-q', '--qname', type=str, help='Query name')

    args = parser.parse_args()

    sniffPackets(args.srcIP, args.dstIP, args.qname)
    results = calculateAmplificationFactors()
    with open("./queries.json", 'w') as f2:
        json.dump(queriesInfo, f2)

    with open("./responses.json", 'w') as f3:
        json.dump(responsesInfo, f3)
        
    meanFactors = meanAmplificationFactor(results)

    print('Number of queries: ', len(queriesInfo))
    print('Number of responses: ', len(responsesInfo))

    print('Number of ANY requests: ', len(results['255']))
    print('Number of A requests: ', len(results['1']))
    print('Number of AAAA requests: ', len(results['28']))
    print('Number of CNAME requests: ', len(results['5']))
    print('Number of MX requests: ', len(results['15']))
    print('Number of NS requests: ', len(results['2']))
    print('Number of SOA requests: ', len(results['6']))
    print('Number of TXT requests: ', len(results['16']))

    print('Mean amplification factors: ', meanFactors)

    with open("./AF.json", 'w') as f:
        json.dump(results, f)

    with open("./meanAF.json", 'w') as f1:
        json.dump(meanFactors, f1)