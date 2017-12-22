#!/bin/sh


IPT="/sbin/iptables"

$IPT -F
$IPT -F INPUT
$IPT -F OUTPUT
$IPT -F FORWARD
$IPT -F -t mangle
$IPT -F -t nat
$IPT -X

$IPT -P INPUT ACCEPT
$IPT -P OUTPUT ACCEPT
$IPT -P FORWARD ACCEPT

echo 1 > /proc/sys/net/ipv4/ip_forward



# firewall chain
$IPT -N firewall
$IPT -A firewall -m limit --limit 15/minute -j LOG --log-prefix Firewall:
$IPT -A firewall -j DROP

# dropwall chain
$IPT -N dropwall
$IPT -A dropwall -m limit --limit 15/minute -j LOG --log-prefix Dropwall:
$IPT -A dropwall -j DROP

# badflags chain
$IPT -N badflags
$IPT -A badflags -m limit --limit 15/minute -j LOG --log-prefix Badflags:
$IPT -A badflags -j DROP

# badports chain
$IPT -N badports
$IPT -A badports -m limit --limit 15/minute -j LOG --log-prefix Badports:
$IPT -A badports -j DROP


# badsources chain
$IPT -N badsources
$IPT -A badsources -m limit --limit 15/minute -j LOG --log-prefix Badsources:
$IPT -A badsources -j DROP

$IPT -N silent
$IPT -A silent -j DROP

# localhost
$IPT -A INPUT -i lo -j ACCEPT

# SPAMD
$IPT -A INPUT -p tcp -i eth1 --dport 25 -j firewall


$IPT -A INPUT -p tcp -s 0/0 --dport 25  -j badsources




