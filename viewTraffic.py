from flask import Flask, render_template_string
from scapy.all import *
import threading
import signal
import sys

app = Flask(__name__)

# Filtrer le trafic DNS pour un nom de domaine spécifique
def dns_traffic(pkt):
    if pkt.haslayer(DNS) and pkt.haslayer(IP):
        dns = pkt[DNS]
        if dns.qname == b'amaury.thesis.io.':  # Remplacez 'example.com' par le nom de domaine recherché
            return True
    return False

def packet_handler(pkt, packets):
    if dns_traffic(pkt):
        packets.append(pkt.summary())

# Fonction pour capturer les paquets de manière continue
def continuous_packet_capture():
    packets = []
    while True:
        sniff(filter="udp port 53", prn=packet_handler(packets), timeout=60)  # Capturer pendant 2 secondes

# Fonction à exécuter dans un thread pour la capture continue
def start_continuous_capture():
    capture_thread = threading.Thread(target=continuous_packet_capture)
    capture_thread.start()

# Gérer le signal d'interruption (Ctrl+C)
def signal_handler(sig, frame):
    print("Arrêt de la capture.")
    sys.exit(0)

# Route pour afficher les paquets capturés en temps réel
@app.route('/')
def show_live_pcap():
    html = """
    <!DOCTYPE html>
    <html>
    <head>
        <title>Live PCAP Viewer</title>
        <script src="https://ajax.googleapis.com/ajax/libs/jquery/3.5.1/jquery.min.js"></script>
        <script>
            $(document).ready(function(){
                function updatePackets() {
                    $.get('/get_packets', function(data){
                        $('#packet_info').html(data);
                    });
                }

                setInterval(updatePackets, 1000); // Actualiser toutes les 2 secondes
            });
        </script>
    </head>
    <body>
        <h1>Paquets capturés en temps réel</h1>
        <div id="packet_info"></div>
    </body>
    </html>
    """
    return render_template_string(html)

# Route pour obtenir les paquets capturés au format HTML
@app.route('/get_packets')
def get_packets():
    global packets
    return "<br>".join(packets) + "<br>"

if __name__ == '__main__':
    start_continuous_capture()  # Démarrer la capture dans un thread séparé
    signal.signal(signal.SIGINT, signal_handler)  # Capturer le signal d'interruption (Ctrl+C)
    app.run(debug=True)
