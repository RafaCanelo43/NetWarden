#Rafael Rodriguez Botello Fierro
#Proyecto Escaner de vulnerbailiudades en la red


#Import all the necessary libraries for the project, including scapy for network packet manipulation, nmap for port scanning, nvdlib for vulnerability data retrieval, and jinja2 for HTML report generation.
from scapy.all import Ether, ARP, srp
import nmap
import nvdlib
from jinja2 import Environment, FileSystemLoader

#We create the first function called host_discovery, this function is responsible for discovering active hosts on the network using ARP requests. It sends ARP requests to the specified network and collects responses from active hosts. The results are stored in a list of dictionaries containing the IP and MAC addresses of each active host.
def host_discovery(network):
    arp_req = ARP(pdst = network)
    broadcast = Ether(dst="ff:ff:ff:ff:ff:ff")

    packet = broadcast/arp_req

    answered, unanswared = srp(packet, verbose = 0, timeout = 3, iface="wlo1")
    print(f"Responses received: {len(answered)}")

    active_hosts = []
    for response in answered: 
        host_info = {"IP": response[1].psrc, "MAC": response[1].hwsrc}
        active_hosts.append(host_info)
        print(f"IP:{response[1].psrc} | MAC: {response[1].hwsrc}")
    
    return active_hosts

#We create the second function called scan_ports, this function is responsible for scanning the ports of each active host using the nmap library. For this, we create a PortScanner object and use the scan method to perform a service version detection scan on the specified IP and port range. The results are stored in a list of dictionaries containing the host information, open ports, and their corresponding services.
def scan_ports(hosts, ports):
    nm = nmap.PortScanner()
    scan_results = []

#Create a loop to iterate through each host in the list of active hosts. For each host, we perform a port scan using nmap and collect information about open ports, their state, service name, and version. This information is stored in a structured format for later use in vulnerability assessment and report generation.
    for host in hosts:
        nm.scan(host["IP"], ports, "-sV")
        host_info = {"IP": host["IP"], "MAC": host["MAC"], "Ports": []}

#Create a nested loop to iterate through each protocol (TCP/UDP) and port for the current host. For each open port, we retrieve its state, service name, and version. This information is stored in a list of dictionaries under the "Ports" key for each host, which will be used later to check for known vulnerabilities and generate the final report. 
        for protocol in nm[host["IP"]].all_protocols():
            ports_list = nm[host["IP"]][protocol].keys()

#Create another nested loop to iterate through each port in the list of open ports for the current protocol. For each port, we retrieve its state, service name, and version. This information is stored in a list of dictionaries under the "Ports" key for each host, which will be used later to check for known vulnerabilities and generate the final report. Additionally, we can use the nvdlib library to search for known CVEs based on the service name and version, and store this information in the same structure for comprehensive vulnerability assessment.
            for port in sorted(ports_list):
                state = nm[host["IP"]][protocol][port]["state"]
                name = nm[host["IP"]][protocol][port]["name"]
                version = nm[host["IP"]][protocol][port]["version"]
                port_info = {"Port": port, "State": state, "Name": name, "Version": version}
                host_info["Ports"].append(port_info)
        
        scan_results.append(host_info)
    
    return scan_results

#Create a function to find known CVEs for each scanned port and service.
def cves_finder(scan_results):
    cve_results = []
    for host in scan_results:
        host_result = {"ip": host["IP"],"ports": []}
        for port in host["Ports"]:
            keyword = port["Name"] + " " + port["Version"]
            search = nvdlib.searchCVE(keywordSearch=keyword)
            cve_info = {"Port": port["Port"],"Name": port["Name"], "Version": port["Version"], "State": port["State"], "CVEs": []}

#Create a conditional statement to check if there ares any known CVEs for the given service and version. If there are no CVEs found, we can add a message indicating that there are no known vulnerabilities. If CVEs are found, we can iterate through the results and extract relevant information such as severity, score, and description, and store it in a structured format for later use in report generation.
            if len(search) == 0:
                cve_info["CVEs"] = [] #No known CVEs found for this service and version
            else:
                for eachCVE in search:
                    cve_details = {"Severity": eachCVE.v31severity, "Score": eachCVE.v31score, "Description": eachCVE.descriptions[0].value}
                    cve_info["CVEs"].append(cve_details)
            host_result["ports"].append(cve_info)
        cve_results.append(host_result)
    return cve_results

#Create a function to generate an HTML report using Jinja2 templating engine. This function takes the scan results and CVE information, renders it into an HTML template, and saves the report to a specified location for review.
def generate_report(cve_results):
    env = Environment(loader=FileSystemLoader('templates'))
    template = env.get_template('report.html')
    output = template.render(hosts=cve_results)

    with open('reports/report.html', 'w') as f:
        f.write(output)


    print("Reporte generado en reports/report.html")

#Finaly call the functions in the correct order to perform the host discovery, port scanning, CVE finding, and report generation based on the user input for IP address and port range.

#1-Ask the user for the IP address they want to scan. This input will be used in the host discovery and port scanning functions to specify the target network or host for the vulnerability assessment.
IP = input("Add the IP address you want to scan: ")
active_hosts = host_discovery(IP)
if len(active_hosts) == 0:
    active_hosts = [{"IP": IP, "MAC": "N/A"}] #If no active hosts are found, we can still proceed with the scan using the provided IP address, but we will indicate that the MAC address is not available.
scan_results = scan_ports(active_hosts, "1-1024")
cve_results = cves_finder(scan_results)
generate_report(cve_results)
