#Script para escanear puertos con SCAPPY y Nmap
#Autor: Rafael Rodriguez Botello Fierro

from scapy.all import Ether, ARP, srp

IP = input("Ingrese la direccion de IP que desea escanear: ")

def scapy_scan(IP):
    arp_req = ARP(pdst = IP)
    broadcast = Ether(dst="ff:ff:ff:ff:ff:ff")

    packet = broadcast/arp_req

    answered, unanswared = srp(packet, verbose = 0, timeout = 3, iface="wlo1")
    print(f"Respuestas recibidas: {len(answered)}")

    for response in answered: 
        print(f"IP:{response[1].psrc} | MAC: {response[1].hwsrc}")

scapy_scan(IP)
