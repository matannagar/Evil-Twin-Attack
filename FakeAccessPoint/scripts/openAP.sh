#!/bin/sh

# Reason to stop network manager is so that it does not prevent the fake AP from broadcasting a wifi signal
service network-manager stop     

# Next, we should enable IP forwarding so that packets can flow through the computer without being dropped.
echo 1 > /proc/sys/net/ipv4/ip_forward  

# Not only that, we must also delete any IP table rules that might interfere with what we are trying to achieve.
# Hence, the below commands must be entered in the terminal to clear any firewall rules that might be redirecting packets to somewhere else.
# By default there should not be any IP table rules, however to be on the safe side,
# if a program modifies and adds IP tables rules then the fake AP will fail, hence the following commands are a precaution.
iptables --flush
iptables --table nat --flush
iptables --delete-chain
iptables --table nat --delete-chain
iptables -P FORWARD ACCEPT

# start DHCP server and DNS server
dnsmasq -C FakeAccessPoint/configs/dnsmasq.conf

# start hostapd and to begin broadcasting a signal.
# -B is used so that it will execute the above command in the background.
hostapd FakeAccessPoint/configs/hostapd.conf -B

