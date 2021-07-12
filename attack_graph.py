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

attacks = []
numb_of_occurence= []
var=c.execute("SELECT DISTINCT attack_name, COUNT(*) from attack group by attack_name") 
records=var.fetchall()
conn.commit()
for row in records:
    attacks.append(row[0])
    numb_of_occurence.append(row[1])
#afficher les listes montrant le type d'attaque et le nombre d'occurences de ce dernier
print(attacks)
print(numb_of_occurence)	
#dessiner le graphe
plt.xticks(range(len(attacks)), attacks)
plt.xlabel('Attacks')
plt.ylabel('Number of Occurence ')
plt.title('Statistics of Alerts')
plt.bar(range(len(numb_of_occurence)), numb_of_occurence)
plt.show()
# close connection
conn.close()

