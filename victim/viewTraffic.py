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
    
    packetInfo = {'Number': '', 'Time': '', 'Source': '', 'Destination': '', 'Protocol': '', 
                 'Length': '', 'Info': '', 'Summary': ''}
    queryType = None

    if IP in packet and UDP in packet and DNS in packet:
        if packet[DNSQR].qname.decode() == "amaury.thesis.io.":
            packetInfo['Number'] = packet[DNS].id
            packetInfo['Time'] = time.time() - captureTime
            packetInfo['Source'] = packet[IP].src
            packetInfo['Destination'] = packet[IP].dst
            packetInfo['Protocol'] = 'DNS'
            packetInfo['Length'] = len(packet[DNS])

            # DNS query
            if packet[DNS].qr == 0:
                queryType = packet[DNSQR].qtype
                queryTypeName = dns_query_type_to_string(queryType)
                packetInfo['Info'] += "Standard query <br>" + queryTypeName + ' ' + str(packet[DNSQR].qname.decode())

            # DNS response
            elif packet[DNS].qr == 1:
                queryType = packet[DNSQR].qtype
                queryTypeName = dns_query_type_to_string(queryType)
                packetInfo['Info'] += 'Standard query response ' + queryTypeName + ' ' + str(packet[DNSQR].qname.decode()) + "<br>"

                # Get the answer type and all the answers
                if packet[DNS].ancount > 0:
                    for i in range(packet[DNS].ancount):
                        recordType = packet[DNS].an[i].type
                        recordTypeName = dns_query_type_to_string(recordType)
                        complete_record = recordTypeName

                        if recordType in [6, 15, 43, 46, 47, 48, 50]:  # SOA, MX, DS, RRSIG, NSEC, DNSKEY, NSEC3
                            complete_record += ' ' + extract_special_record_data(packet[DNS].an[i])

                        if hasattr(packet[DNS].an[i], 'rdata'):
                            if isinstance(packet[DNS].an[i].rdata, bytes):
                                complete_record += ' ' + str(packet[DNS].an[i].rdata.decode())
                            else:
                                complete_record += ' ' + str(packet[DNS].an[i].rdata)

                        packetInfo['Info'] += '\n' + complete_record + "<br>"

            # Store the summary of the packet
            old_stdout = sys.stdout
            sys.stdout = buffer = StringIO()
            packet.show()
            packetInfo['Summary'] += buffer.getvalue()
            sys.stdout = old_stdout
            socketio.emit('dns_packet', {'data': packetInfo})

def dns_query_type_to_string(qtype):
    """
    Convert DNS query type to string.
    """
    query_type_dict = {
        1: 'A',
        2: 'NS',
        5: 'CNAME',
        6: 'SOA',
        15: 'MX',
        16: 'TXT',
        28: 'AAAA',
        255: 'ANY'
    }
    return query_type_dict.get(qtype, '')

def extract_special_record_data(record):
    """
    Extract data from special DNS records such as SOA, MX, etc.
    """
    if record.type == 6:  # SOA
        return f"{record.mname.decode()} {record.rname.decode()} {record.serial} {record.refresh} {record.retry} {record.expire} {record.minimum}"
    elif record.type == 15:  # MX
        return f"{record.ttl} {record.preference} {record.exchange.decode()}"
    elif record.type == 43:  # DS
        return f"{record.keytag} {record.algorithm} {record.digesttype} {record.digest.decode()}"
    elif record.type == 46:  # RRSIG
        return f"{record.typecovered} {record.algorithm} {record.labels} {record.originalttl} {record.expiration} {record.inception} {record.keytag} {record.signersname.decode()} {base64.b64encode(record.signature).decode('ascii')}"
    elif record.type == 47:  # NSEC
        return f"{record.nextname.decode()} {record.typebitmaps}"
    elif record.type == 48:  # DNSKEY
        return f"{record.flags} {record.protocol} {record.algorithm} {record.publickey.decode()}"
    elif record.type == 50:  # NSEC3
        return f"{record.hashalg} {record.flags} {record.iterations} {record.salt.decode()} {record.hashalg} {record.nexthashedownername.decode()} {record.typebitmaps}"
    
    return ''


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