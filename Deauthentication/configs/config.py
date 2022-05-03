import os


def setMonitorMode(wlan):
    """Gets from the user the full interface name to set to Monitor Mode and sets him.
    @param wlan: The wlan address"""
    print("\nSetting" + wlan + "to monitor mode!")
    
    os.system("sudo ip link set " + wlan + " down")
    os.system("sudo iw " + wlan + " set type monitor")
    os.system("sudo ip link set " + wlan + " up")


def updateHostAP(known, BSSID):
    """updates hostapd.conf channel to the victim's wifi channel (will be used to assign IP subnets to link-layer addresses).
    @param known: All the networks we have found in known
    @param BSSID: The target address"""
    filename = "./configs/hostapd.conf"
    text = str("#Set wifi interface" + "\n" + "interface=wlan0" + "\n" + "#Set network name" + "\n" + "ssid=" +
               str(known[BSSID][0]) + "\n" + "#Set channel" + "\n" + "channel=" + str(
                   known[BSSID][1]) + "\n" + "#Set driver" + "\n" + "driver=nl80211")
    f = open(filename, 'w')
    f.close()
    f = open(filename, 'w')
    f.write(text)
    f.close()


def setManagerMode(wlan):
    """Changing the interface back to managed mode.
    @param wlan: wlan address"""
    os.system("sudo ip link set " + wlan + " down")
    os.system("sudo iw  "+ wlan + " set type managed")
    os.system("sudo ip link set " + wlan + " up")
    
    print("\n"+wlan + " is set back to managed mode")
