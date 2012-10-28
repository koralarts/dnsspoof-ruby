#!/usr/bin/env ruby

#-------------------------------------------------------------------------------
# spoof.rb
#
# Super class for all the spoofing classes
#
# Author: Karl Castillo
#
# Date: October 26, 2012
#
# Functions:
# send - send packet
#
# Revisions: (Date and Description)
#
# Notes:
#
#-------------------------------------------------------------------------------
require 'rubygems'
require 'packetfu'

class Spoof

    def send(packet)
        packet.to_w(@interface)
    end
    
end # spoofer
