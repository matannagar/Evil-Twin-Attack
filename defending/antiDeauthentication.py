import os
from scapy.layers.dot11 import Dot11FCS
from scapy.all import get_if_list,sniff
import threading
import subprocess



counter = 0

def resetCounter():
    global counter
    t = threading.Timer
    t.daemon = True
    t(300,resetCounter).start()
    counter = 0 

def countDeauthenticationPackages(pkt):
    
    global counter
    counter+=1
    if(pkt.haslayer(Dot11FCS)):
        if pkt.type==0:
            if pkt.subtype == 12:
                counter+=1
    
    if(counter > 100):
        os.system('notify-send "ERROR" "error"')
        print("warning!")

if __name__=='__main__':
    
    
    print(f"list of available interfaces:\n{get_if_list()}")
    
    wlan = input("\nSpecify the interface you wish to protect from Disassociation attacks:\n")
    
    resetCounter()
    
    sniff(iface=wlan,prn = countDeauthenticationPackages)
    
    