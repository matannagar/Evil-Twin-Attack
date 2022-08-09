from scapy.all import sniff
from scapy.layers.dot11 import Dot11, Dot11Beacon, Dot11Elt, Dot11ProbeReq, Dot11ProbeResp, RadioTap
import time
import codecs
from datetime import datetime
import os
from threading import Thread


def switch_channel(interface: str, timeout_seconds, channel: int = 1):
    """
    This function changing the channel searching. (to identify networks and clients that uses other channels)
    :param timeout_seconds: function timeout
    :param interface: the interface that used to identify the networks / clients. (wlan0 for example)
    :param channel: the starting channel default is 1.
    """
    start_time = datetime.now()
    channel = channel
    while (datetime.now() - start_time).seconds < timeout_seconds:
        channel = (channel % 14) + 1
        os.system('iwconfig {} channel {}'.format(interface, channel))
        time.sleep(1)


def getClients(pkt):
    '''Identifies packets and extracts the MAC address of the client
    @param pkt: captured packet

    Based on:
    https://www.youtube.com/watch?v=owsr3X453Z4&ab_channel=PentesterAcademyTV
    '''
    if pkt.haslayer(Dot11):  # is it a Wi-Fi packet? 802.11
        bssid = pkt[Dot11].addr3
        target_bssid = a
        if (pkt.addr2 == target_bssid or pkt.addr3 == target_bssid) and pkt.addr1 != "ff:ff:ff:ff:ff:ff":
            if pkt.addr1 not in voc and pkt.addr2 != pkt.addr1 and pkt.addr1 != pkt.addr3 and pkt.addr1:
                print(pkt.addr1)
                voc.append(pkt.addr1)


def sniffClients(interface, BSSID):
    '''Detects all available users of a given AP.
    @param interface - the given monitor card we are using for sniffing
    @param BSSID - given Acess Point ID.
    '''
    global voc
    voc = []
    global a
    a = BSSID
    interupted = False
    try:
        sniff(iface=interface, prn=getClients, stop_filter=interupted)
    except KeyboardInterrupt:
        interupted = True


def scanNetworks(interface):
    '''Gets the names of all availale Wi-Fi networks around me.
    Performs sniffing for packets on a specific monitor card.
    Picks out only packets that has layer of Dot11 - Meaning Wi-Fi layers - specifies a 802.11 packet.
    For each packet, extracts the AP information SSID, BBSID, channel.
    @param interface - name of the monitor card
    '''
    # we arrange all of the networks we have found in known so that we will not print the network information twice on the terminal.
    known = {}

    def callback(pkt):
        if pkt.haslayer(Dot11):  # is it a Wi-Fi packet? 802.11
            # Beacon frame is one of the management frames in IEEE 802.11 based WLANs. It contains all the information about the network.
            # The WLAN clients or stations use probe request frame to scan the area for availability of WLAN network.
            # we should ask if pkt.type == 0 and (pkt.subtype == 8 or pkt.subtype == 5)
            if pkt.haslayer(Dot11Beacon) or pkt.haslayer(Dot11ProbeResp):
                src = pkt[Dot11].addr2  # src mac of transmitter 
                if src not in known:  # if the network we found is not in 'known'
                    ssid = pkt[Dot11Elt][0].info.decode()  # save the ssid

                    '''save the channel of the network supplied by the radiotap header (which offer additional information that is added
                    to each 802.11 frame when capturing frame. Radiotaps are not part of standard 802.11 frames.)'''
                    channel = pkt[RadioTap].channel

                    ''' prints the networks information.
                    The BSSID uniquely identifies the access point's radio using a MAC address, 
                    while the SSID is the name of the network that allows devices to connect.'''
                    print("SSID: '{}', BSSID: {}, channel: {}".format(
                        ssid, src, channel))
                    # add the network to list
                    known[src] = (ssid, channel)

    channel_thread = Thread(target=switch_channel,
                            args=(interface, 60), daemon=True)
    channel_thread.start()
    print('*********')
    print('networks:')
    print('*********')
    sniff(prn=callback, iface=interface) # timeout=60
    channel_thread.join()  # waiting for channel switching to end

    return known
