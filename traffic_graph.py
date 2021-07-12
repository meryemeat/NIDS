from tkinter import *
import sqlite3
from tkinter.messagebox import showinfo
from tkinter import ttk
from tkinter.ttk import Treeview
import matplotlib.pyplot as plt
from matplotlib.backends.backend_tkagg import FigureCanvasTkAgg
from pandas import DataFrame
#connecion à la Base de Données:
conn = sqlite3.connect('attack.db')
# créer le curseur
c = conn.cursor()
#ces listes vont contenir tous les noms et notes des etudiants de la tables:
protocols = []
numb_of_packets= []
var=c.execute("SELECT DISTINCT protocol, COUNT(*) from traffic group by protocol") 
records=var.fetchall()
conn.commit()
for row in records:
    protocols.append(row[0])
    numb_of_packets.append(row[1])
#afficher les deux listes montrant les types de protocoles et le nombre de paquets pour chaque type
print(protocols)
print(numb_of_packets)	
#dessiner le graphe à partir de ces données
plt.xticks(range(len(protocols)), protocols)
plt.xlabel('protocols')
plt.ylabel('number of packets ')
plt.title('Statistics of traffic')
plt.bar(range(len(numb_of_packets)), numb_of_packets)
plt.show()
# close connection 
conn.close()   

