from flask import Flask, render_template
from scapy.all import *
from flask_socketio import SocketIO, emit
import time

app = Flask(__name__)
app.config['SECRET_KEY'] = 'secret!'
socketio = SocketIO(app)

def packet_handler(packet):
    packetInfo = {'Number': '', 'Time': '', 'Source': '', 'Destination': '', 'Protocol': '', 
                 'Length': '', 'Info': ''}
    if IP in packet and UDP in packet and DNS in packet:
        if packet[DNS].qr == 0:
            packetInfo['Number'] = packet[DNS].id
            packetInfo['Time'] = time.time()
            packetInfo['Source'] = packet[IP].src
            packetInfo['Destination'] = packet[IP].dst
            packetInfo['Protocol'] = 'DNS'
            packetInfo['Length'] = len(packet[DNS])
            packetInfo['Info'] += 'Standard query ' + str(packet[DNSQR].qtype) + ': ' + str(packet[DNSQR].qname.decode('utf-8'))
            socketio.emit('dns_packet', {'data': packetInfo})

        elif packet[DNS].qr == 1:
            packetInfo['Number'] = packet[DNS].id
            packetInfo['Time'] = time.time()
            packetInfo['Source'] = packet[IP].src
            packetInfo['Destination'] = packet[IP].dst
            packetInfo['Protocol'] = 'DNS'
            packetInfo['Length'] = len(packet[DNS])
            packetInfo['Info'] += 'Standard query response ' + str(packet[DNSQR].qtype) + ': ' + str(packet[DNSQR].qname.decode('utf-8'))
            for rr in packet[DNS].an:
                packetInfo['Info'] += '\n\t' + str(rr.type) + ' ' + str(rr.rdata)

            socketio.emit('dns_packet', {'data': packetInfo})

def sniffAllPackets():
    sniff(filter="udp and port 53", timeout=120, prn=packet_handler)

@app.route('/')
def index():
    return render_template('index.html')

if __name__ == '__main__':
    sniffAllPackets()
    socketio.run(app)