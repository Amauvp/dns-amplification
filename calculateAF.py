from scapy.all import *
import time

global udp_header
udp_header = 8

global queries_info
queries_info = {}

global responses_info
responses_info = {}

global lastPacketTime
lastPacketTime = time.time()

def packet_handler(packet):

    if IP in packet and UDP in packet and DNS in packet:
        if packet[IP].src == "victim_ip" and packet[IP].dst == "192.168.68.53" and packet[DNS].qr == 0:
            query_info = [packet[DNSQR].qtype, len(packet[DNS].payload)]
            queries_info[packet[DNS].id] = query_info

        elif packet[IP].src == "192.168.68.53" and packet[IP].dst == "victim_ip" and packet[DNS].qr == 1:
            response_info = [packet[DNSRR].type, len(packet[DNS].payload)]
            responses_info[packet[DNS].id] = response_info
    
    lastPacketTime = time.time()

def sniffAllPackets():
    sniff(filter="udp and port 53", timeout=60, prn=packet_handler)

def calculateAF():

    all_factors = {'255': [], '1': [], '28': [], '5': [], '15': [], '2': [], '6': [], '16': []}
    # ANY = 255, A = 1, AAAA = 28, CNAME = 5, MX = 15, NS = 2, SOA = 6, TXT = 16
    for query_id in queries_info:
        for response_id in responses_info:
            if query_id == response_id:
                amplification_factor = responses_info[response_id][1] / queries_info[query_id][1]
                all_factors[str(queries_info[query_id][0])].append(amplification_factor)
    
    return all_factors