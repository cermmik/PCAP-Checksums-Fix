#! /usr/bin/env python3
# -*- coding: utf-8 -*-

#
# Copyright (c) 2022 Milan Cermak, Institute of Computer Science of Masaryk University
#
# Permission is hereby granted, free of charge, to any person
# obtaining a copy of this software and associated documentation
# files (the "Software"), to deal in the Software without
# restriction, including without limitation the rights to use,
# copy, modify, merge, publish, distribute, sublicense, and/or sell
# copies of the Software, and to permit persons to whom the
# Software is furnished to do so, subject to the following
# conditions:
#
# The above copyright notice and this permission notice shall be
# included in all copies or substantial portions of the Software.
#
# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
# EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES
# OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND
# NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT
# HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY,
# WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING
# FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR
# OTHER DEALINGS IN THE SOFTWARE.
#


"""Simple script based on Scapy library for checksums recomputation (IP, UDP, and TCP layer) in the given PCAP file.

See the Scapy library documentation at https://scapy.net/ for more details.
"""

import argparse             # Arguments parser
import logging, coloredlogs                 # Standard logging functionality with colors functionality
from scapy.all import *     # PCAP manipulation library
from scapy.layers.inet import IP, UDP, TCP  # Scapy packet layers definition

if __name__ == "__main__":
    # Define application arguments (automatically creates -h argument)
    parser = argparse.ArgumentParser()
    parser.add_argument("-i", "--input_pcap", metavar="PCAP_FILE_PATH", help="Input PCAP file path", required=True, type=str)
    parser.add_argument("-o", "--output_pcap", metavar="PCAP_FILE_PATH", help="Output PCAP file path", required=True, type=str)
    parser.add_argument("-l", "--log", choices=["debug", "info", "warning", "error", "critical"], help="Log level", required=False, default="INFO")
    args = parser.parse_args()

    # Set logging
    coloredlogs.install(level=getattr(logging, args.log.upper()), fmt="%(asctime)s [%(levelname)s]: %(message)s")

    # Open output PCAP file stream
    output_file = PcapWriter(args.output_pcap)
    logging.debug("Output PCP file stream opened.")

    # Read stream of packets from the input PCAP file
    for input_packet in PcapReader(args.input_pcap):
        logging.debug("Input PCAP file processing started.")
        try:
            # Delete current checksums
            if IP in input_packet:
                del input_packet[IP].chksum
            if UDP in input_packet:
                del input_packet[UDP].chksum
            if TCP in input_packet:
                del input_packet[TCP].chksum
            # Recompute the checksum and write the packet to output PCAP file stream
            output_file.write(input_packet)
        except Exception as e:
            logging.warning("Packet processing error: " + str(e))
    
    # Flush all remaining packets
    output_file.flush()
    logging.debug("All packets have been processed.")
