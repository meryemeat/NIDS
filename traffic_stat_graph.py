from tkinter import *
import sqlite3
from tkinter.messagebox import showinfo
from tkinter import ttk
from tkinter.ttk import Treeview
import matplotlib.pyplot as plt
from matplotlib.backends.backend_tkagg import FigureCanvasTkAgg
from pandas import DataFrame
#cnx à la base de données:
conn = sqlite3.connect('attack.db')
# créer le curseurr
c = conn.cursor()
#remplir les listes suivantes par les données des attaques réalisés (attaques et leurs nombre d'occurence) 
protocols = []
numb_of_packets= []
var=c.execute("SELECT DISTINCT protocol, COUNT(*) from traffic group by protocol") # DISTINCT protocol from traffic")
records=var.fetchall()
conn.commit()
for row in records:
    protocols.append(row[0])
    numb_of_packets.append(row[1])
#calcul des pourcentages représentants le nombre de paquets d'un type de protocole par rapport au nombre total des paquets
total=0
for numb in numb_of_packets:
    total+=numb
prc_arp, prc_http, prc_telnet, prc_dns, prc_tcp, prc_udp, prc_ip=0, 0, 0, 0, 0, 0, 0
for i in range(0,len(protocols)):
    var=protocols[i]
    if var=="ARP":
        prc_arp=((numb_of_packets[i])/(total))*100	
    elif var=="HTTP":
        prc_http=((numb_of_packets[i])/(total))*100
    elif var=="TELNET":
        prc_telnet=((numb_of_packets[i])/(total))*100
    elif var=="DNS":
        prc_dns=((numb_of_packets[i])/(total))*100
    elif var=="TCP":
        prc_tcp=((numb_of_packets[i])/(total))*100
    elif var=="UDP":
        prc_udp=((numb_of_packets[i])/(total))*100
    elif var=="IP":
        prc_ip=((numb_of_packets[i])/(total))*100
#les labels qu'on affiche sur les deux catégories dans le dessin:
liste=protocols
#ajouter les pourcentages calculer dans une liste pour les representer dans le graphe:
fracs=[]
for prot in protocols:
    if prot=="ARP":
        fracs.append(str(prc_arp))
    elif prot=="HTTP":
        fracs.append(str(prc_http))
    elif prot=="TELNET":
        fracs.append(str(prc_telnet))
    elif prot=="DNS":
        fracs.append(str(prc_dns))
    elif prot=="TCP":
        fracs.append(str(prc_tcp))
    elif prot=="UDP":
        fracs.append(str(prc_udp))
    elif prot=="IP":
        fracs.append(str(prc_ip))
for i in range(0, len(fracs)):
    if fracs[i]=="0":
        fracs.remove(fracs[i])		
        liste.remove(str(protocols[i]))
labels=tuple(liste)
#afficher le pourcentage de chaque protocole
print(fracs)
#afficher les noms des protocoles dans le même ordre que les pourcentages affichés
print(labels)
figureObject, axesObject = plt.subplots()
# dessiner le graphe en camembert
axesObject.pie(fracs,labels=labels,autopct='%1.2f%%',startangle=90)
#le graphe est un cercle:
axesObject.axis('equal')
plt.show()
# close connection 
conn.close()   

