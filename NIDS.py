import pyshark
import socket
import sqlite3
from datetime import datetime
import netifaces
#définir l'interface de capture et et le nomnbre de packets à capturer
capture=pyshark.LiveCapture(interface='eth0')
packet_count=1000
#initialisations
count_arp=0
count_icmp_req=0
count_tcp_syn_req=0
count_udp=0
count_telnet=0
count_http=0
ip_destination=""
ip_source=""
protocole=""
arp_source=[] #la liste des ip sources des machines envoyant des paquets arp
icmp_source=[] # ...des paquets icmp
tcp_source=[] # ... tcp
udp_source=[] # ... udp
telnet_source=[] #... telnet
http_source=[]
arp_reported=[] #liste des machines qui ont déjà fait une attaque arp 
icmp_reported=[] #... attaque icmp
tcp_reported=[] #... attaque tcp
udp_reported=[] #... attaque udp
telnet_reported=[] #... une requete d'ouverture de cnx telnet
http_reported=[]
xss_reported=[]
command_reported=[]
directory_reported=[]
c=0
#stocker la nouvelle adresse ip de cette machine dans la varibale local_adresse à chaque fois que ce script s'execute
hostname=socket.getfqdn() 
local_address=socket.gethostbyname(hostname)
local_address=str(local_address)
#stocker l'adresse mac de cette machine dans la variable mac
macs = netifaces.ifaddresses('eth0')[netifaces.AF_LINK]
print(macs)
mac=""
for k, v in macs[0].items():	
	if v!="ff:ff:ff:ff:ff:ff":
		mac+=str(v)
print("-------------------------BEGIN-------------------------")
#connexion à la base de données
conn = sqlite3.connect('attack.db')
cur = conn.cursor()
#creation des tables
cur.execute('''CREATE TABLE IF NOT EXISTS attack
               (attack_name text, protocol_used text, ip_source text, ip_dest text, mac_source text, mac_dest text, description text, time text)''')
cur.execute('''CREATE TABLE IF NOT EXISTS traffic
               (ip_source text, ip_dest text, protocol text, mac_source text, mac_dest text, time text)''')
#filtrage paquet par paquet pour la journalisation et détection de traffic douteux
for packet in capture.sniff_continuously(packet_count):
    try:
#Code pour détécter les attaques ARP FLOOD
        try: #try aide à gérer les erreurs 
            if packet['eth'].type=='0x00000806':
                count_arp+=1
                if packet.arp.get_field_by_showname('Sender IP address') not in arp_reported and packet.arp.get_field_by_showname('Target IP address')==local_address:
                    arp_source.append(packet.arp.get_field_by_showname('Sender IP address'))
                        if arp_source.count(packet.arp.get_field_by_showname('Sender IP address'))>=4:	
                            now = datetime.now()
                            var="arp flooding packets from: "+str(packet.arp.get_field_by_showname('Sender IP address'))+", to : "+str(local_address)
                            print(var)
                            arp_reported.append(str(packet.arp.get_field_by_showname('Sender IP address')))
                            cur.execute("insert into attack values (?, ?, ?, ?, ?, ?, ?, ?)", ("ARP FLOOD", "ARP", str(packet.arp.get_field_by_showname('Sender IP address')), str(local_address), str(packet.eth.get_field_by_showname('Source')),str(packet.eth.get_field_by_showname('Destination')) , var, str(now)  ))
        except:
            pass
#Code pour détécter les attaques ICMP FLOOD
        try: 
            if str(packet.icmp.get_field_by_showname('Type'))=='8'and packet['ip'].src!=local_address and packet['ip'].dst==local_address :
                count_icmp_req+=1
                if packet['ip'].src not in icmp_reported:
                    icmp_source.append(packet['ip'].src)
                    if icmp_source.count(packet['ip'].src)>=10:
                        now = datetime.now()
                        icmp_reported.append(packet['ip'].src)
                        var="icmp flood from :"+str(packet['ip'].src)+", to : "+str(local_address)
                        print(var)	
                        cur.execute("insert into attack values (?, ?, ?, ?, ?, ?, ?, ?)", ("ICMP FLOOD", "ICMP", str(packet['ip'].src), str(local_address), str(packet.eth.get_field_by_showname('Source')),str(packet.eth.get_field_by_showname('Destination')) , var, str(now)  ))

        except:
            pass
#Code pour détécter les attaques  TCP SYN FLOOD
        try: 
            if str(packet.tcp.get_field_by_showname('Flags'))=='0x00000002' and packet['ip'].src!=local_address and packet['ip'].dst==local_address :
                count_tcp_syn_req+=1			
                if packet['ip'].src not in tcp_reported:
                    tcp_source.append(packet['ip'].src)
                    if tcp_source.count(packet['ip'].src)>=10:
                        now = datetime.now()
                        tcp_reported.append(packet['ip'].src)
                        var="TCP SYN SCAN FROM : "+str(packet['ip'].src)+", to : "+str(packet['ip'].dst)
                        print(var)							
                        cur.execute("insert into attack values (?, ?, ?, ?, ?, ?, ?, ?)", ("TCP SYN FLOOD", "TCP", str(packet['ip'].src), str(local_address), str(packet.eth.get_field_by_showname('Source')),str(packet.eth.get_field_by_showname('Destination')) , var, str(now)  ))
        except:
            pass
#Code pour détécter les attaques  UDP FLOOD
        try:
            if packet.ip.get_field_by_showname('Protocol')=='17' and packet['ip'].src!=local_address and packet['ip'].dst==local_address:
                count_udp+=1
                if packet['ip'].src not in udp_reported:
                    udp_source.append(packet['ip'].src)
                    if udp_source.count(packet['ip'].src)>=10:
                        now = datetime.now()
                        udp_reported.append(packet['ip'].src)
                        var="UDP FLOOD from :"+str(packet['ip'].src)+", to : "+str(local_address)
                        print(var)      
                        cur.execute("insert into attack values (?, ?, ?, ?, ?, ?, ?, ?)", ("UDP FLOOD", "UDP", str(packet['ip'].src), str(local_address), str(packet.eth.get_field_by_showname('Source')),str(packet.eth.get_field_by_showname('Destination')) , var, str(now)  ))				
        except:
            pass
#Code pour détécter les tentatives de connexion à distance par telnet
        try:
            if str(packet.tcp.get_field_by_showname('Destination Port'))=='23'and packet['ip'].src!=local_address and packet['ip'].dst==local_address:
                count_telnet+=1
                now = datetime.now()
                if packet['ip'].src not in telnet_reported:
                    telnet_source.append(packet['ip'].src)
                    telnet_reported.append(packet['ip'].src)
                    var="Open a TELNET CONNECTION from "+str(packet['ip'].src)+", to "+str(local_address)	
                    print(var)
                    cur.execute("insert into attack values (?, ?, ?, ?, ?, ?, ?, ?)", ("TELNET CONNECTION", "TELNET", str(packet['ip'].src), str(local_address), str(packet.eth.get_field_by_showname('Source')),str(packet.eth.get_field_by_showname('Destination')) , var, str(now)  )) 
        except:
            pass
#Code pour détécter les attaques SQL INJECTION
        try:
            if 'HTTP' in packet and packet['ip'].dst==local_address:
                count_http+=1
                now = datetime.now()
                if '%20' and '%27' in packet.http.get_field_by_showname('Request URI'):
                    if packet['ip'].src not in http_reported:
                        http_reported.append(packet['ip'].src)
                        var="Possible SQLInjection from :"+str(packet['ip'].src)+", to : "+str(local_address)
                        print(var)      
                        cur.execute("insert into attack values (?, ?, ?, ?, ?, ?, ?, ?)", ("Possible SQLInjection", "HTTP", str(packet['ip'].src), str(local_address), str(packet.eth.get_field_by_showname('Source')),str(packet.eth.get_field_by_showname('Destination')) , var, str(now)  ))  
        except:
            pass
#Code pour détécter les attaques Cross-Site Scripting (XSS)
        try:
            if 'URLENCODED-FORM' in packet and packet['ip'].dst==local_address:
                if '<script' or '<img' or '<svg' or 'eval' or 'alert' in packet['urlencoded-form'].get_field_by_showname('Value'):
                    now = datetime.now()
                    if packet['ip'].src not in xss_reported:
                        xss_reported.append(packet['ip'].src)
                        var="XSS ATTACK from :"+str(packet['ip'].src)+", to : "+str(local_address)
                        print(var)
                        cur.execute("insert into attack values (?, ?, ?, ?, ?, ?, ?, ?)", ("XSS ATTACK", "HTTP", str(packet['ip'].src), str(local_address), str(packet.eth.get_field_by_showname('Source')),str(packet.eth.get_field_by_showname('Destination')),  var, str(now)  ))  
        except:
            pass
#Code pour détécter les attaques Directory Traversal
        try:
            if 'URLENCODED-FORM' in packet and packet['ip'].dst==local_address:
                if '../' or '%252e%252e%252f' in packet['urlencoded-form'].get_field_by_showname('Value'):
                    now = datetime.now()
                    if packet['ip'].src not in directory_reported:
                        directory_reported.append(packet['ip'].src)
                        var="DIRECTORY TRAVERSAL ATTACK from :"+str(packet['ip'].src)+", to : "+str(local_address)
                        print(var)
                        cur.execute("insert into attack values (?, ?, ?, ?, ?, ?, ?, ?)", ("DIRECTORY TRAVERSAL ATTACK", "HTTP", str(packet['ip'].src), str(local_address), str(packet.eth.get_field_by_showname('Source')),str(packet.eth.get_field_by_showname('Destination')),  var, str(now)  ))
        except:
            pass
#Code pour détécter les attaques 'Command Injection'
        try:
            if 'URLENCODED-FORM' in packet and packet['ip'].dst==local_address:
                if ';' in packet['urlencoded-form'].get_field_by_showname('Value'):
                    now = datetime.now()
                    if packet['ip'].src not in command_reported:
                        command_reported.append(packet['ip'].src)
                        var="Command INJECTION from: "+str(packet['ip'].src)+", to : "+str(local_address)
                        print(var)
                        cur.execute("insert into attack values (?, ?, ?, ?, ?, ?, ?, ?)", ("Command INJECTION", "HTTP", str(packet['ip'].src), str(local_address), str(packet.eth.get_field_by_showname('Source')),str(packet.eth.get_field_by_showname('Destination')),  var, str(now)  ))
        except:
            pass
#Code pour détécter les attaques ARP SPOOFING
        try:
            if packet['eth'].type=='0x00000806' and str(packet.arp.get_field_by_showname('Sender IP address'))==local_address and str(packet.arp.get_field_by_showname('Target IP address'))=="192.168.1.1":
                mac=str(packet.arp.get_field_by_showname('Target MAC address'))
            if packet['eth'].type=='0x00000806' and str(packet.arp.get_field_by_showname('Sender IP address'))=="192.168.1.1" and str(packet.arp.get_field_by_showname('Target IP address'))==local_address:
                if c==0:	
                    if mac!=str(packet.arp.get_field_by_showname('Sender MAC address')):						
                        now = datetime.now()
                        var="ARP SPOOFING ATTACK to poison ARP Cache of "+local_address+" with a wrong gateway mac address"
                        print(var)
                        c+=1
                        cur.execute("insert into attack values (?, ?, ?, ?, ?, ?, ?, ?)", ("ARP SPOOFING", "ARP",  '-', str(local_address), mac_address,str(packet.arp.get_field_by_showname('Sender MAC address')) , var, str(now)  ))
        except:
            pass
#Journalisation de chaque paquet transmis dans le réseau et ses détails dans une base de données
        try:
            if 'ARP' in packet:
                protocole="ARP"
                ip_source=packet.arp.get_field_by_showname('Sender IP address')
                ip_destination=packet.arp.get_field_by_showname('Target IP address')
            elif 'IP' or 'TCP' or 'UDP' in packet :
                ip_source=str(packet['ip'].src)
                ip_destination=str(packet['ip'].dst)
                if 'SSL' in packet:
                    protocole="SSL"
                elif 'DNS' in packet:
                    protocole="DNS"
                elif 'TELNET' in packet:
                    protocole="TELNET"
                elif 'HTTP' in packet:
                    protocole="HTTP"
                elif 'TCP' in packet: 
                    protocole="TCP"
                elif 'UDP' in packet: 
                    protocole="UDP"
                else:
                    protocole="IP"	
            cur.execute("insert into traffic values ( ?, ?, ?, ?, ?, ?)", (str(ip_source), str(ip_destination), protocole, str(packet.eth.get_field_by_showname('Source')),str(packet.eth.get_field_by_showname('Destination')), datetime.now() )) 			
        except:
            pass
    except:
        pass
#affichage de statistiques sur les types des paquets transmis durant l'execution du script
print("--------END OF DETECTION--------")
print("NUMBER OF PACKETS: ")
print("   =>ALL PACKETS : "+str(packet_count))
print("   =>ARP PACKETS : "+str(count_arp))
print("   =>ICMP PACKETS : "+str(count_icmp_req))
print("   =>TCP PACKETS : "+str(count_tcp_syn_req))
print("   =>UDP PACKETS : "+str(count_udp))
print("   =>TELNET PACKETS : "+str(count_telnet))
print("   =>HTTP PACKETS : "+str(count_http))
print("-------------------------THE END-------------------------")
# Enregistre (commit) les modifications dans la base de données
conn.commit()
conn.close() 
exit()
