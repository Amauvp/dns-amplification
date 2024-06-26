from flask import Flask, render_template
from scapy.all import *
from flask_socketio import SocketIO, emit
import time
import threading
from io import StringIO
import sys
import psutil

app = Flask(__name__)
app.config['SECRET_KEY'] = 'secret!'
socketio = SocketIO(app)

global captureTime

def packet_handler(packet):
    """
    This function is called for every packet sniffed. 
    The packet is then parsed and the information is sent to the client.

    :param packet: The packet sniffed by Scapy 
    :type packet: scapy.packet.Packet
    """
    packetInfo = {'Number': '', 'Time': '', 'Source': '', 'Destination': '', 'Protocol': '', 
                 'Length': '', 'Info': '', 'Summary': ''}
    queryType = None

    if IP in packet and UDP in packet and DNS in packet:
        # DNS query
        # print(packet[DNSQR].qname.decode())
        if packet[DNSQR].qname.decode() == "amaury.thesis.io.":
            if packet[DNS].qr == 0:
                packetInfo['Number'] = packet[DNS].id
                packetInfo['Time'] = time.time() - captureTime
                packetInfo['Source'] = packet[IP].src
                packetInfo['Destination'] = packet[IP].dst
                packetInfo['Protocol'] = 'DNS'
                packetInfo['Length'] = len(packet[DNS])

                # Get the query type
                if packet[DNS].qd.qtype == 1:
                    queryType = 'A'
                elif packet[DNS].qd.qtype == 2:
                    queryType = 'NS'
                elif packet[DNS].qd.qtype == 5:
                    queryType = 'CNAME'
                elif packet[DNS].qd.qtype == 6:
                    queryType = 'SOA'
                elif packet[DNS].qd.qtype == 15:
                    queryType = 'MX'
                elif packet[DNS].qd.qtype == 16:
                    queryType = 'TXT'
                elif packet[DNS].qd.qtype == 28:
                    queryType = 'AAAA'
                elif packet[DNS].qd.qtype == 255:
                    queryType = 'ANY'
                else:
                    queryType = ''
            
                packetInfo['Info'] += "Standard query <br>" + queryType + ' ' + str(packet[DNSQR].qname.decode())

                # Store the summary of the packet
                old_stdout = sys.stdout
                sys.stdout = buffer = StringIO()
                packet.show()
                packetInfo['Summary'] += buffer.getvalue()
                sys.stdout = old_stdout
                socketio.emit('dns_packet', {'data': packetInfo})

            # DNS response
            elif packet[DNS].qr == 1:
                packetInfo['Number'] = packet[DNS].id
                packetInfo['Time'] = time.time() - captureTime
                packetInfo['Source'] = packet[IP].src
                packetInfo['Destination'] = packet[IP].dst
                packetInfo['Protocol'] = 'DNS'
                packetInfo['Length'] = len(packet[DNS])

                # Get the query type
                if packet[DNSQR].qtype == 1:
                    queryType = 'A'
                elif packet[DNSQR].qtype == 2:
                    queryType = 'NS'
                elif packet[DNSQR].qtype == 5:
                    queryType = 'CNAME'
                elif packet[DNSQR].qtype == 6:
                    queryType = 'SOA'
                elif packet[DNSQR].qtype == 15:
                    queryType = 'MX'
                elif packet[DNSQR].qtype == 16:
                    queryType = 'TXT'
                elif packet[DNSQR].qtype == 28:
                    queryType = 'AAAA'
                elif packet[DNSQR].qtype == 255:
                    queryType = 'ANY'
                elif packet[DNSQR].qtype == 43:
                    queryType = 'DS'
                elif packet[DNSQR].qtype == 46:
                    queryType = 'RRSIG'
                elif packet[DNSQR].qtype == 47:
                    queryType = 'NSEC'
                elif packet[DNSQR].qtype == 48:
                    queryType = 'DNSKEY'
                elif packet[DNSQR].qtype == 50:
                    queryType = 'NSEC3'
                else: 
                    queryType = ''

                packetInfo['Info'] += 'Standard query response ' + queryType + ' ' + str(packet[DNSQR].qname.decode()) + "<br>"

                # if packet[DNS].arcount > 0:
                #     for j in range(packet[DNS].arcount):
                #         if packet[DNS].ar[j].type == 48:
                #             to_print = "DNSKEY"
                #             to_print += " " + packet[DNS].ar[j].flags
                #             to_print += " " + packet[DNS].ar[j].protocol
                #             to_print += " " + packet[DNS].ar[j].algorithm
                #             to_print += " " + packet[DNS].ar[j].publickey
                #             print(to_print)
                #         elif packet[DNS].ar[j].type == 43:
                #             to_print = "DS"
                #             to_print += " " + packet[DNS].ar[j].keytag
                #             to_print += " " + packet[DNS].ar[j].algorithm
                #             to_print += " " + packet[DNS].ar[j].digesttype
                #             to_print += " " + packet[DNS].ar[j].digest.decode()
                #             print(to_print)
                #         elif packet[DNS].ar[j].type == 47:
                #             to_print = "NSEC"
                #             to_print += " " + packet[DNS].ar[j].nextname
                #             to_print += " " + packet[DNS].ar[j].typebitmaps
                #             print(to_print)
                #         elif packet[DNS].ar[j].type == 50:
                #             to_print = "NSEC3"
                #             to_print += " " + packet[DNS].ar[j].hashalg
                #             to_print += " " + packet[DNS].ar[j].flags
                #             to_print += " " + packet[DNS].ar[j].iterations
                #             to_print += " " + packet[DNS].ar[j].salt.decode()
                #             to_print += " " + packet[DNS].ar[j].nexthashedownername.decode()
                #             to_print += " " + packet[DNS].ar[j].typebitmaps
                #             print(to_print)
                #         elif packet[DNS].ar[j].type == 46:
                #             to_print = "RRSIG"
                #             to_print += " " + packet[DNS].ar[j].typecovered
                #             to_print += " " + packet[DNS].ar[j].algorithm
                #             to_print += " " + packet[DNS].ar[j].labels
                #             to_print += " " + packet[DNS].ar[j].originalttl
                #             to_print += " " + packet[DNS].ar[j].expiration
                #             to_print += " " + packet[DNS].ar[j].inception
                #             to_print += " " + packet[DNS].ar[j].keytag
                #             to_print += " " + packet[DNS].ar[j].signersname.decode()
                #             to_print += " " + packet[DNS].ar[j].signature.decode()
                #             print(to_print)
                # Get the answer type and all the answers
                if packet[DNS].ancount > 0:
                    for i in range(packet[DNS].ancount):
                        if packet[DNS].an[i].type == 1:
                            queryType = 'A'
                        elif packet[DNS].an[i].type == 2:
                            queryType = 'NS'
                        elif packet[DNS].an[i].type == 5:
                            queryType = 'CNAME'
                        elif packet[DNS].an[i].type == 6:
                            queryType = 'SOA'
                        elif packet[DNS].an[i].type == 15:
                            queryType = 'MX'
                        elif packet[DNS].an[i].type == 16:
                            queryType = 'TXT'
                        elif packet[DNS].an[i].type == 28:
                            queryType = 'AAAA'
                        elif packet[DNS].an[i].type == 255:
                            queryType = 'ANY'
                        elif packet[DNS].an[i].type == 43:
                            queryType = 'DS'
                        elif packet[DNS].an[i].type == 46:
                            queryType = 'RRSIG'
                            print(packet[DNS].an[i].signature.decode('utf-8'))
                        elif packet[DNS].an[i].type == 47:
                            queryType = 'NSEC'
                        elif packet[DNS].an[i].type == 48:
                            queryType = 'DNSKEY'
                        elif packet[DNS].an[i].type == 50:
                            queryType = 'NSEC3'
                        else:
                            queryType = ''

                        if hasattr(packet[DNS].an[i], 'rdata'):
                            if isinstance(packet[DNS].an[i].rdata, bytes):
                                packetInfo['Info'] += '\n' + queryType + ' ' + str(packet[DNS].an[i].rdata.decode()) + "<br>"
                            else:
                                packetInfo['Info'] += '\n' + queryType + ' ' + str(packet[DNS].an[i].rdata) + "<br>"
                        else:
                            packetInfo['Info'] += '\n' + queryType + '<br>'

            # Store the summary of the packet
            old_stdout = sys.stdout
            sys.stdout = buffer = StringIO()
            packet.show()
            packetInfo['Summary'] += buffer.getvalue()
            sys.stdout = old_stdout
            socketio.emit('dns_packet', {'data': packetInfo})

def sniffAllPackets():
    """
    This function is called when the server starts.
    It starts sniffing all the packets on port 53.
    """
    sniff(filter="udp and port 53", timeout=120, prn=packet_handler)

def getPerformances():
    while True:
        cpuPercent = psutil.cpu_percent()
        memoryPercent = psutil.virtual_memory().percent
        bandwidth = (psutil.net_io_counters().bytes_sent + psutil.net_io_counters().bytes_recv) * 8/1000000
        performanceData = {'CPU': cpuPercent, 'memory': memoryPercent, 'bandwidth': bandwidth}
        socketio.emit('performanceData', performanceData)
        time.sleep(2)

@app.route('/')
def index():
    return render_template('index.html')

if __name__ == '__main__':
    captureTime = time.time()
    captureThread = threading.Thread(target=sniffAllPackets)
    captureThread.daemon = True
    captureThread.start()
    capturePerf = threading.Thread(target=getPerformances)
    capturePerf.daemon = True
    capturePerf.start()
    socketio.run(app)