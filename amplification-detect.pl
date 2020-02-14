#!/usr/bin/perl -w
#
# Detect hosts vulnerable to DDoS amplification attacks.
# Prerequisites: apt install nmap libnmap-parser-perl
# Usage: amplification-detect.pl <ip/mask> <ip/mask> ...
# (c) <sa-dev@odd.systems> 2020
#

use strict;
no warnings "experimental::smartmatch";
use utf8;
use Nmap::Parser;


my $nmap_path = "nmap";
my $nmap_args = "-n -Pn -sU -pU:53,111,123,137,161,1900,11211 --script=dns-recursion,rpcinfo,ntp-monlist,nbstat,snmp-sysdescr,upnp-info,memcached-info";
my $client_by_ip = "./client_by_ip";  # must print single line, if present
my @hosts = @ARGV;

my ($np, $ip, $host, @c_arg, $udp_ports, @open_ports, $port, $o, $vuln);
my (%h, $c); # result, client


$np = new Nmap::Parser;
$np->parsescan($nmap_path, $nmap_args, @hosts);

IP: for $ip ($np->get_ips("up")){
    $host = $np->get_host($ip);
    @open_ports = $host->udp_open_ports();
    if (scalar(@open_ports) < 1) { next IP }
    if (-x $client_by_ip) {
        @c_arg = ($client_by_ip, $ip);
        open (CBI, "-|", @c_arg);
        $c = <CBI>;
        if (defined $c) { chomp ($c); }
        close CBI;
    }
    if ((not defined ($c)) or $c eq "") {
        $c = "undefined client";
    }
    $udp_ports = $host->{ports}->{udp};
    for $port (@open_ports) {
        $vuln = undef;
        #if ($port == 17) {
        # TODO: script to check
        #   $vuln = "qotd";
        #   }
        #if ($port == 19) {
        # TODO: script to check
        #    $vuln = "chargen";
        #}
        if ($port == 53) {
            $o = $udp_ports->{53}->{service}->{script}->{'dns-recursion'}->{output};
            if ((defined $o) and $o =~ /recursion.*enabled/i) {
                $vuln = "dns";
            }
        }
        if ($port == 111) {
            $o = $udp_ports->{111}->{service}->{script}->{rpcinfo}->{output};
            if ((defined $o) and $o =~ /program\s+version/) {
                $vuln = "portmap";
            }
        }
        if ($port == 123) {
            $o = $udp_ports->{123}->{service}->{script}->{'ntp-monlist'}->{output};
            if ((defined $o) and $o =~ /synchronised|Servers|Clients/i) {
                $vuln = "ntp";
            }
        }
        if ($port == 137) {
            # NetBIOS Name Service
            if ((defined $o) and $o =~ /name/i) {
                $vuln = "smb";
            }
            # TODO: consider NetBIOS Datagram Service (NBDS) (138/udp) too
        }
        if ($port == 161) {
            $o = $udp_ports->{161}->{service}->{script}->{'snmp-sysdescr'}->{output};
            if ((defined $o) and $o =~ /System/i) {
                $vuln = "snmp";
            }
        }
        #if ($port == 520) {
        # TODO: script to check
        #    $vuln = "ripv1";
        #}
        if ($port == 1900) {
            $o = $udp_ports->{1900}->{service}->{script}->{'upnp-info'}->{output};
            if (defined $o) {
                $vuln = "ssdp";
            }
        }
        if ($port == 11211) {
            $o = $udp_ports->{11211}->{service}->{script}->{'memcached-info'}->{output};
            if (defined $o) {
                $vuln = "memcached";
            }
        }
        if (defined $vuln and not ($vuln ~~ @{$h{$c}->{$ip}})) {
            push @{$h{$c}->{$ip}}, $vuln;
        }
    }
}

for $c (keys %h) {
    print $c."\n";
    for $ip (keys %{$h{$c}}) {
        print "    ".$ip."\n";
        for $vuln (@{$h{$c}->{$ip}}) {
            print "        ".$vuln."\n";
        }
    }
    print "\n";
}

1;
