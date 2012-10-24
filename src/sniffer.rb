#-------------------------------------------------------------------------------
# Sniffer.rb
#-------------------------------------------------------------------------------

require "rubygems"
require "packetfu"
require "thread"
require "./dns"
require "./arp"
#require "./trollop"

#------
# Trollop Command Line Argument Parsing
#------

#------
# Preparations
#------

# Check if user is running as root
raise "Must run as root or `sudo ruby #{$0}`" unless Process.uid == 0

#-----
# ARP Spoofing
#-----
def arpspoof(iface = "em1")
    arp = ARPSpoof.new("insert MAC Address here", "insert IPaddress here")
    while caught == false do
        sleep 5
        arp.send
    end # while caught == false
end # arpspoof

#-----
# Start Capturing
#-----
def sniff(iface)
    # Sniff only DNS requests
    filter = "udp and dst port 53"
    pcap = Packetfu::Capture.new(:iface => iface, :start => true, 
                                 :filter => filter)

    pcap.stream.each do |pkt|
        packet = Packetfu::Packet.parse pkt
    end # pcap.stream.each do |pkt|
end # sniff

begin
    arp_thread = Thread.new { arpspoof }
    sniff_thread = Thread.new{ sniff("em1") }
    arp_thread.join
    sniff_thread.join
    rescue Interrupt
    Thread.kill(arp_thread)
    Thread.kill(sniff_thread)
    exit 0
end
