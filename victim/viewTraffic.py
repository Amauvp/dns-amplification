from flask import Flask, render_template
from scapy.all import *
from flask_socketio import SocketIO, emit
import time
import threading
from io import StringIO
import sys
import psutil
import binascii
import base64

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

            # DNS response
            elif packet[DNS].qr == 1:
                print("Type of response: " + str(packet[DNS].qd.qtype))
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
                elif packet[DNS].id == anyRequest:
                    queryType = 'ANY'
                else: 
                    queryType = ''

                packetInfo['Info'] += 'Standard query response ' + queryType + ' ' + str(packet[DNSQR].qname.decode()) + "<br>"

                # Get the answer type and all the answers
                if packet[DNS].ancount > 0:
                    for i in range(packet[DNS].ancount):
                        if packet[DNS].an[i].type == 1:
                            recordType = 'A'
                        elif packet[DNS].an[i].type == 2:
                            recordType = 'NS'
                        elif packet[DNS].an[i].type == 5:
                            recordType = 'CNAME'
                        elif packet[DNS].an[i].type == 6:
                            recordType = 'SOA'
                            complete_record = recordType + " " + str(packet[DNS].an[i].mname.decode()) + " " + str(packet[DNS].an[i].rname.decode()) + " " + str(packet[DNS].an[i].serial)
                            complete_record += " " + str(packet[DNS].an[i].refresh) + " " + str(packet[DNS].an[i].retry) + " " + str(packet[DNS].an[i].expire) + " " + str(packet[DNS].an[i].minimum)
                            packetInfo['Info'] += '\n' + complete_record + "<br>"
                        elif packet[DNS].an[i].type == 15:
                            recordType = 'MX'
                            complete_record = recordType + " " + str(packet[DNS].an[i].ttl) + " " + str(packet[DNS].an[i].preference) + " " + str(packet[DNS].an[i].exchange.decode())
                            packetInfo['Info'] += '\n' + complete_record + "<br>"
                        elif packet[DNS].an[i].type == 16:
                            recordType = 'TXT'
                        elif packet[DNS].an[i].type == 28:
                            recordType = 'AAAA'
                        elif packet[DNS].an[i].type == 43:
                            recordType = 'DS'
                            complete_record = recordType
                            complete_record += " " + str(packet[DNS].an[i].keytag) + " " + str(packet[DNS].an[i].algorithm) + " " + str(packet[DNS].an[i].digesttype) + " " + str(packet[DNS].an[i].digest.decode())
                            packetInfo['Info'] += '\n' + complete_record + "<br>"
                        elif packet[DNS].an[i].type == 46:
                            recordType = 'RRSIG'
                            complete_record = recordType + " " + str(packet[DNS].an[i].typecovered) + " " + str(packet[DNS].an[i].algorithm) + " " + str(packet[DNS].an[i].labels)
                            complete_record += " " + str(packet[DNS].an[i].originalttl) + " " + str(packet[DNS].an[i].expiration) + " " + str(packet[DNS].an[i].inception) + " " + str(packet[DNS].an[i].keytag)
                            complete_record += " " + str(packet[DNS].an[i].signersname.decode()) + " " + base64.b64encode(packet[DNS].an[i].signature).decode('ascii')
                            
                            packetInfo['Info'] += '\n' + complete_record + "<br>"
                        elif packet[DNS].an[i].type == 47:
                            recordType = 'NSEC'
                            complete_record = recordType + " " + str(packet[DNS].an[i].nextname.decode()) + " " + str(packet[DNS].an[i].typebitmaps)
                            packetInfo += '\n' + complete_record + "<br>"
                        elif packet[DNS].an[i].type == 48:
                            recordType = 'DNSKEY'
                            complete_record = recordType + " " + str(packet[DNS].an[i].flags) + " " + str(packet[DNS].an[i].protocol) + " " + str(packet[DNS].an[i].algorithm) + " " + packet[DNS].an[i].publickey.decode()
                            packetInfo += '\n' + complete_record + "<br>"
                        elif packet[DNS].an[i].type == 50:
                            recordType = 'NSEC3'
                            complete_record = recordType + " " + str(packet[DNS].an[i].hashalg) + " " + str(packet[DNS].an[i].flags) + " " + str(packet[DNS].an[i].iterations)
                            complete_record += " " + str(packet[DNS].an[i].salt.decode()) + " " + str(packet[DNS].an[i].hashalg) + " " + str(packet[DNS].an[i].nexthashedownername.decode())
                            complete_record += " " + str(packet[DNS].an[i].typebitmaps)

                            packetInfo += '\n' + complete_record + "<br>"
                        else:
                            queryType = ''

                        if hasattr(packet[DNS].an[i], 'rdata'):
                            if isinstance(packet[DNS].an[i].rdata, bytes):
                                packetInfo['Info'] += '\n' + recordType + ' ' + str(packet[DNS].an[i].rdata.decode()) + "<br>"
                            else:
                                packetInfo['Info'] += '\n' + recordType + ' ' + str(packet[DNS].an[i].rdata) + "<br>"

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