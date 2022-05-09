#!/bin/sh
service hostapd stop
service apache2 stop
service dnsmasq stop
killall dnsmasq
killall hostapd
