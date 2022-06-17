# PCAP Checksums Fix

Simple Python script based on Scapy library for checksums recomputation (IP, UDP, and TCP layer) in the PCAP file.

For more details about the PCAP file processing in the Scapy library, see the documentation at [https://scapy.net/](https://scapy.net/).


## Requirements

- Python3
- Python3 packages in [requirements.txt](requirements.txt)

The installation can be performed using the following commands:

```bash
$ git clone https://github.com/cermmik/PCAP-Checksums-Fix.git
$ pip3 install -r ./PCAP-Checksums-Fix/requirements.txt
```


## Usage

Read PCP file, recompute checksum of all packets, and write fixed packets to the output file:

```bash
$ ./pcap_checksums_fix.py -i <INPUT_PCAP> -o <OUTPUT_PCAP>
```
