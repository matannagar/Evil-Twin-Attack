from scapy.all import sniff
from scapy.layers.dot11 import Dot11, Dot11Beacon, Dot11Elt, Dot11ProbeReq, Dot11ProbeResp
import time
import codecs

'''
Wireless LAN is a network where devices are using wireless to communicate with each other in a defined area.
Wireless LAN is ultimately connected to a wired network. 

WAP - wireless access point - a device that accepts wireless signals from multiple devices and retransmits them to the rest of the network.
AP - access point is layer 2 device because it is like a bridge connecting 2 types of networks, wireless and wired.
These two networks are not seperate, they belong to one broadcast domain.
In other word, they belong to one local area network.

802.11 - Wi-Fi - 
* designed for use in a limited geographical area
* 

Frames - 

MAC addresses - 

AP broadcast - by default, an AP brodcats its SSID in its service area

BSS - basic service set - is a group of wireless network devices that are working with the same AP

BSSID is a unique identifier used by a client to establish a connection to a particular wireless network.
It is the phsyical or MAC address which is 48-bit long hexadecimal numbers.
As a wireless user we cannot see BSSID, but they are included in the packages. 

SSID is the name of a WiFi network that acts as a single shared password between access points and clients.

An AP can provide multiple SSIDs on the same channel through the use of the same or multiple interfaces.

Dot11 is a fast, secure and reliable Wi-Fi service which delivers seamless, building-wide network connectivity in an increasing number of London building centres.
dot11 = 802.11 specification

Dot11Beacon Frame - Beacon frame is one of the management frames in IEEE 802.11 based WLANs. It contains all the information about the network. 
Beacon frames are transmitted periodically, they serve to announce the presence of a wireless LAN and to synchronise the members of the service set.

Dot11Elt

Dot11ProbeReq

Dot11ProbeResp

addr1	Destination MAC address.
addr2	Source MAC address of sender.
addr3	MAC address of Access Point.


How to get SSID list?
Detect beacon frames, access the 802.11 frame -> SSID parameter 
'''


def getClients(pkt):
    '''Identifies beacon packets and extracts the name and BSSID address
    @param pkt: captured packet

    Based on:
    https://www.youtube.com/watch?v=owsr3X453Z4&ab_channel=PentesterAcademyTV
    '''
    bssid = pkt[Dot11].addr3
    target_bssid = a
    if target_bssid == bssid and not pkt.haslayer(Dot11Beacon) and not pkt.haslayer(Dot11ProbeReq) and not pkt.haslayer(Dot11ProbeResp):
        if str(pkt.summary()) not in voc:
            print(pkt.summary())
        voc[str(pkt.summary())] = True


def sniffClients(interface, BSSID):
    '''Detects all available users of a given AP.
    @param interface - the given monitor card we are using for sniffing
    @param BSSID - given Acess Point ID.
    '''
    global voc
    voc = {}
    global a
    a = BSSID
    interupted = False
    try:
        sniff(iface=interface, prn=getClients, stop_filter=interupted)
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        interupted = True


def scanNetworks(interface):
    '''Gets the names of all availale Wi-Fi networks around me.
    Performs sniffing for packets on a specific monitor card.
    Picks out only packets that has layer of Dot11 - Meaning Wi-Fi layers - specifies a 802.11 packet.
    For each packet, extracts the AP information SSID, BBSID, channel.
    @param interface - name of the monitor card
    '''
    print("Press Ctrl-C to finish scanning for networks")
    # we arrange all of the networks we have found in known so that we will not print the network information twice on the terminal.
    known = {}

    def callback(pkt):
        if pkt.haslayer(Dot11):  # is it a Wi-Fi packet? 802.11
            # Beacon frame is one of the management frames in IEEE 802.11 based WLANs. It contains all the information about the network.
            # The WLAN clients or stations use probe request frame to scan the area for availability of WLAN network.
            if pkt.haslayer(Dot11Beacon) or pkt.haslayer(Dot11ProbeResp):
                src = pkt[Dot11].addr2  # src mac of sender
                if src not in known:  # if the network we found is not in 'known'
                    ssid = pkt[Dot11Elt][0].info  # save the ssid
                    # save the channel of the network
                    channel = pkt[Dot11Elt][2].info
                    # transfer it to hex numbers.
                    print(channel)
                    channel = int(codecs.getencoder('hex')(channel)[0], 16)
                    # print the network information.
                    print("SSID: '{}', BSSID: {}, channel: {}".format(
                        ssid, src, channel))
                    # add the network to list
                    known[src] = (ssid, channel)

    sniff(iface=interface, prn=callback, store=0)

    return known
