#!/usr/bin/perl -w
#
# Detect hosts vulnerable to DDoS amplification attacks.
# Prerequisites: apt install nmap libnmap-parser-perl
# Usage: amplification-detect.pl <ip/mask> <ip/mask> ...
# (c) <sa-dev@odd.systems> 2020
#

use strict;
use utf8;
use Nmap::Parser;


my $nmap_path = "nmap";
my $nmap_args = "-n -Pn -sU -pU:17,19,53,111,123,137,138,139,161,1900,11211 --script=dns-recursion,rpcinfo,ntp-monlist,snmp-sysdescr,upnp-info,memcached-info";
my @hosts = @ARGV;

my ($np, $ip, $host, $udp_ports, $port, $o);


$np = new Nmap::Parser;
$np->parsescan($nmap_path, $nmap_args, @hosts);

for $ip ($np->get_ips("up")){
    print $ip."\n";
    $host = $np->get_host($ip);
    $udp_ports = $host->{ports}->{udp};
    for $port ($host->udp_open_ports()) {
        #print "open port: ".$port."\n";
        if ($port == 17) {
            print "    qotd\n";
        }
        if ($port == 19) {
            print "    chargen\n";
        }
        if ($port == 53) {
            $o = $udp_ports->{53}->{service}->{script}->{'dns-recursion'}->{output};
            if ((defined $o) and $o =~ /recursion.*enabled/i) {
                print "    dns\n";
            }
        }
        if ($port == 111) {
            $o = $udp_ports->{111}->{service}->{script}->{rpcinfo}->{output};
            if ((defined $o) and $o =~ /program\s+version/) {
                print "    portmap\n";
            }
        }
        if ($port == 123) {
            $o = $udp_ports->{123}->{service}->{script}->{'ntp-monlist'}->{output};
            if ((defined $o) and $o =~ /synchronised|Servers|Clients/i) {
                print "    ntp\n";
            }
        }
        if ($port >= 137 and $port <= 139) {
            # TODO: script to check?
            print "    smb\n";
        }
        if ($port == 161) {
            $o = $udp_ports->{161}->{service}->{script}->{'snmp-sysdescr'}->{output};
            if ((defined $o) and $o =~ /System/i) {
                print "    snmp\n";
            }
        }
        if ($port == 520) {
            # TODO: script to check?
            print "    ripv1\n";
        }
        if ($port == 1900) {
            $o = $udp_ports->{1900}->{service}->{script}->{'upnp-info'}->{output};
            if (defined $o) {
                print "    ssdp\n";
            }
        }
        if ($port == 11211) {
            $o = $udp_ports->{11211}->{service}->{script}->{'memcached-info'}->{output};
            if (defined $o) {
                print "    memcached\n";
            }
        }
    }
}

1;
