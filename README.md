# NetWarden

NetWarden is a Python-based network vulnerability scanner that discovers active hosts, identifies open ports and running services, queries the NVD database for known CVEs, and generates a detailed HTML report with severity-coded findings.

## Features

- ARP-based host discovery using Scapy
- Port scanning and service version detection with Nmap (-sV)
- CVE lookup via NVD API for each detected service
- Color-coded HTML report (HIGH/MEDIUM/LOW) generated with Jinja2
- Supports single IPs and full network ranges (CIDR notation)

## Requirements

It needs the next libraries instaled in the system:
- Python 3
- Nmap 
- scapy
- python-nmap
- nvdlib
- jinja2

## Usage

Run the scanner with:
sudo python3 netwarden.py

Then enter the target IP or network range (e.g. 192.168.1.0/24)

## Screenshots

<img width="1913" height="657" alt="image" src="https://github.com/user-attachments/assets/55430bd1-6d51-417f-b23c-2b70212f8e0e" />
<img width="1886" height="859" alt="image" src="https://github.com/user-attachments/assets/c968fcbb-92ca-4ac2-b847-acec62bda1df" />
<img width="1893" height="861" alt="image" src="https://github.com/user-attachments/assets/3f88ca32-fd17-43fb-b3a5-d3dc745adc27" />

