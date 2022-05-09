#!/bin/sh
service hostapd stop
service apache2 stop
service dnsmasq stop
service rpcbind stop
killall dnsmasq
killall hostapd
rm -f build/hostapd.conf
rm -f build/dnsmasq.conf
#systemctl enable systemd-resolved.service
#systemctl start systemd-resolved
echo sudo ifconfig ${AP} down
echo sudo iwconfig ${AP} mode managed
sudo ifconfig ${AP} down
sudo iwconfig ${AP} mode managed
sudo ifconfig ${AP} up
rm -rf build/
