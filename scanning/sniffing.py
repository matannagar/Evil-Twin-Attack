from scapy.all import sniff
from scapy.layers.dot11 import Dot11,Dot11Beacon, Dot11Elt, Dot11ProbeReq , Dot11ProbeResp
import time
import codecs

def getClients(pkt):
    # print(a)
    global voc
    voc = {}  # vocabulary for all the pkt info
    #voc[str(a)] = str(a)
    bssid = pkt[Dot11].addr3
    target_bssid = a
    if target_bssid == bssid and not pkt.haslayer(Dot11Beacon) and not pkt.haslayer(Dot11ProbeReq) and not pkt.haslayer(Dot11ProbeResp):
        if str(pkt.summary()) not in voc:
            print(pkt.summary())
        voc[str(pkt.summary())] = True
        

def sniffClients(wlan, BSSID):
    global a
    a = BSSID
    interupted = False
    try:
        sniff(iface=wlan, prn=getClients, stop_filter=interupted)
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        interupted = True
        

def scanNetworks(interface):
    print("Press Ctrl-C to finish scanning for networks")
    # we arrange all of the networks we have found in known so that we will not print the network information twice on the terminal.
    known = {}

    def callback(frame):
        if frame.haslayer(Dot11):
            if frame.haslayer(Dot11Beacon) or frame.haslayer(Dot11ProbeResp):

                source = frame[Dot11].addr2
                if source not in known:  # if the network we found is not in 'known'
                    ssid = frame[Dot11Elt][0].info  # save the ssid
                    # save the channel of the network
                    channel = frame[Dot11Elt][2].info
                    # transfer it to hex numbers.
                    print(channel)
                    channel = int(codecs.getencoder('hex')(channel)[0], 16)
                    # print the network information.
                    print("SSID: '{}', BSSID: {}, channel: {}".format(
                        ssid, source, channel))
                    # add the network to 'known'
                    known[source] = (ssid, channel)

    sniff(iface=interface, prn=callback, store=0)

    return known