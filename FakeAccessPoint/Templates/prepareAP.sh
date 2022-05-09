#!/bin/sh


service network-manager stop
echo 1 > /proc/sys/net/ipv4/ip_forward

iptables --flush
iptables --table nat --flush
iptables --delete-chain
iptables --table nat --delete-chain
iptables -P FORWARD ACCEPT

dnsmasq -C build/dnsmasq.conf
hostapd build/hostapd.conf -B
ifconfig ${INTERFACE} 10.0.0.1 netmask 255.255.255.0
service apache2 start
