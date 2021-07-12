from tkinter import *
import sqlite3
from tkinter.messagebox import showinfo
from tkinter import ttk
from tkinter.ttk import Treeview
import matplotlib.pyplot as plt
from matplotlib.backends.backend_tkagg import FigureCanvasTkAgg
from pandas import DataFrame
#cnx à la BD:
conn = sqlite3.connect('attack.db')
# créer le curseur
c = conn.cursor()
#remplir les listes suivantes par les données des attaques réalisés (attaques et leurs nombre d'occurence) 
attacks = []
numb_of_occurence= []
var=c.execute("SELECT DISTINCT attack_name, COUNT(*) from attack group by attack_name") 
records=var.fetchall()
conn.commit()
for row in records:
        attacks.append(row[0])
        numb_of_occurence.append(row[1]) 
#calcul des pourcentages représentants le nombre d'occurence d'une attaque par rapport au total des attaques réalisés
total=0
for numb in numb_of_occurence:
    total+=numb
prc_traversal, prc_sqli, prc_exec, prc_tcp, prc_udp, prc_xss, prc_arpf, prc_arps, prc_telnet, prc_icmpf=0, 0, 0, 0, 0, 0, 0, 0, 0, 0
for i in range(0,len(attacks)):
    var=attacks[i]
    if var=="DIRECTORY TRAVERSAL ATTACK":
        prc_traversal=((numb_of_occurence[i])/(total))*100	
    elif var=="ICMP FLOOD":
        prc_icmpf=((numb_of_occurence[i])/(total))*100
    elif var=="Possible SQLInjection":
        prc_sqli=((numb_of_occurence[i])/(total))*100
    elif var=="Command INJECTION":
        prc_exec=((numb_of_occurence[i])/(total))*100
    elif var=="TCP SYN FLOOD":
        prc_tcp=((numb_of_occurence[i])/(total))*100
    elif var=="UDP FLOOD":
        prc_udp=((numb_of_occurence[i])/(total))*100
    elif var=="XSS ATTACK":
        prc_xss=((numb_of_occurence[i])/(total))*100
    elif var=="TELNET CONNECTION":
        prc_telnet=((numb_of_occurence[i])/(total))*100
    elif var=="ARP FLOOD":
        prc_arpf=((numb_of_occurence[i])/(total))*100
    elif var=="ARP SPOOFING":
        prc_arps=((numb_of_occurence[i])/(total))*100
#les labels qu'on affiche sur les deux catégories dans le dessin:
liste=attacks
#ajouter les pourcentages calculés dans une liste pour les representer dans le graphe:
fracs=[]
for at in attacks:
    if at=="DIRECTORY TRAVERSAL ATTACK":
        fracs.append(str(prc_traversal))
    elif at=="ICMP FLOOD":
        fracs.append(str(prc_icmpf))
    elif at=="Possible SQLInjection":
        fracs.append(str(prc_sqli))
    elif at=="Command INJECTION":
        fracs.append(str(prc_exec))
    elif at=="TCP SYN FLOOD":
        fracs.append(str(prc_tcp))
    elif at=="UDP FLOOD":
        fracs.append(str(prc_udp))
    elif at=="XSS ATTACK":
        fracs.append(str(prc_xss))
    elif at=="TELNET CONNECTION":
        fracs.append(str(prc_telnet))
    elif at=="ARP FLOOD":
        fracs.append(str(prc_arpf))
    elif at=="ARP SPOOFING":
        fracs.append(str(prc_arps))
for i in range(0, len(fracs)):
    if fracs[i]=="0":
        fracs.remove(fracs[i])		
        liste.remove(str(protocols[i]))
labels=tuple(liste)
#afficher le pourcentage de chaque attaque réalisée
print(fracs)
#afficher les noms des attaques dans le même ordre que les pourcentages affichés
print(labels)
figureObject, axesObject = plt.subplots()
# dessiner le graphe en camembert
axesObject.pie(fracs,labels=labels,autopct='%1.2f%%',startangle=90)
#le graphe est un cercle:
axesObject.axis('equal')
plt.show()
# close connection 
conn.close()   

