#!/bin/sh
service hostapd stop
service apache2 stop
service dnsmasq stop
service rpcbind stop
killall dnsmasq
killall hostapd
rm -f build/hostapd.conf
rm -f build/dnsmasq.conf
systemctl enable systemd-resolved.service
systemctl start systemd-resolved
rm -rf build/
ifconfig ${AP} down
iwconfig ${AP} mode managed
ifconfig ${AP} up
