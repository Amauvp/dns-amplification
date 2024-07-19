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

## Scenarios of use

To illustrate how different scripts can be used to observe and study this attack, here are several videos featuring different usage scenarios.

### First Scenario

This scenario shows how an attacker can run the sendQuery.py script to launch DNS queries designed to measure amplification factors. This scenario also shows how to run the calculateAF.py script on the DNS server in order to calculate and observe amplification factors. Finally, this scenario shows how to run the viewTraffic.py script on the victim machine, in order to observe DNS traffic and performance on this machine.

#### Without DNSSEC
![](video/dns-calculateAF-full.gif)

#### With DNSSEC
![](video/dnssec-calculateAF-full.gif)

### Second Scenario

This scenario shows how to run the viewTraffic.py script on the victim machine to observe DNS traffic and performance. This script also shows how to run the dnsAttack.py script to launch the attack from the attacking machine, in order to observe the consequences of this attack on the victim's side.

#### Without DNSSEC
![](video/dnsAttack-without-dnssec-full.gif)

#### With DNSSEC
![](video/dnsAttack-dnssec-full.gif)
