#Proyecto de scanner de puertos usando Python-Nmap
#Autor Rafael Rodriguez Botello Fierro

import nmap
#importamos la libreria nmap

nm = nmap.PortScanner()
#creamos la funcion nm para escanear puertos

IP= input("Ingrese la IP que desee escanear ")
Ports= input("Ingrese los puertos que desee escanear ")
#pedimos Ip y los puertos

nm.scan(IP,Ports, "-sV")
print(nm[IP].all_protocols())
#usamos la funcion scan para poder hacer el escaneo con los argumentos(IP, rango de puertos, sV que hace un escaneo completo)

for host in nm.all_hosts():
	print("Host", nm[IP].hostname())
	print("Estado", nm[IP].state())
#aqui creamos un for loop para cada Host que si respondio en este ip
	for protocolo in nm[host].all_protocols():
		print("Protocolo", protocolo)
		ports = nm[host][protocolo].keys()
#Se anida este for loop para conocer el protocolo por el cual se conectaron
#aqui anidamos otro for loop que nos aydua a definir si es TCP o UDP la conexion con cada host y definimos la funcion ports que ya tienen un host y un protocolo
		for port in  sorted(ports):
			state = nm[host][protocolo][port]["state"]
			name = nm[host][protocolo][port]["name"]
			version = nm[host][protocolo][port]["version"]
			print("Puerto", port)
			print("Estado", state)
			print("Nombre", name)
			print("Version", version)
#Por ultimo se anida este for para analizar los puertos uno por uno, observando su estado su nombre y la vaersion

