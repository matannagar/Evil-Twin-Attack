import os


def setMonitorMode(wlan):
    """Gets from the user the full interface name to set to Monitor Mode and sets him.
    @param wlan: The wlan address"""
    os.system('ifconfig ' + wlan + ' down')
    os.system('iwconfig ' + wlan + ' mode monitor')
    os.system('ifconfig ' + wlan + ' up')


def setManagerMode(wlan):
    """Changing the interface back to managed mode.
    @param wlan: wlan address"""
    #os.system("sudo ip link set " + wlan + " down")
    #os.system("sudo iw  "+ wlan + " set type managed")
    os.system('ifconfig ' + wlan + ' up')