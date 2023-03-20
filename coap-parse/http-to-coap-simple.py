#!/usr/bin/python
#
#Bertrone Matteo - Polytechnic of Turin
#November 2015
#
#eBPF application that parses HTTP packets
#and extracts (and prints on screen) the URL contained in the GET/POST request.
#
#eBPF program http_filter is used as SOCKET_FILTER attached to eth0 interface.
#only packet of type ip and tcp containing HTTP GET/POST are returned to userspace, others dropped
#
#python script uses bcc BPF Compiler Collection by iovisor (https://github.com/iovisor/bcc)
#and prints on stdout the first line of the HTTP GET/POST request containing the url

from __future__ import print_function
from bcc import BPF
from sys import argv

import sys
import binascii
import socket
import os

#args
def usage():
    print("USAGE: %s [-i <if_name>]" % argv[0])
    print("")
    print("Try '%s -h' for more options." % argv[0])
    exit()

#help
def help():
    print("USAGE: %s [-i <if_name>]" % argv[0])
    print("")
    print("optional arguments:")
    print("   -h                       print this help")
    print("   -i if_name               select interface if_name. Default is eth0")
    print("")
    print("examples:")
    print("    http-parse              # bind socket to eth0")
    print("    http-parse -i wlan0     # bind socket to wlan0")
    exit()

#arguments
interface="eth0"

if len(argv) == 2:
  if str(argv[1]) == '-h':
    help()
  else:
    usage()

if len(argv) == 3:
  if str(argv[1]) == '-i':
    interface = argv[2]
  else:
    usage()

if len(argv) > 3:
  usage()

print ("binding socket to '%s'" % interface)

# initialize BPF - load source code from http-parse-simple.c
bpf = BPF(src_file = "http-to-coap-filter.c",debug = 0)

#load eBPF program http_filter of type SOCKET_FILTER into the kernel eBPF vm
#more info about eBPF program types
#http://man7.org/linux/man-pages/man2/bpf.2.html
function_http_filter = bpf.load_func("http_filter", BPF.SOCKET_FILTER)

#create raw socket, bind it to interface
#attach bpf program to socket created
BPF.attach_raw_socket(function_http_filter, interface)

#get file descriptor of the socket previously created inside BPF.attach_raw_socket
socket_fd = function_http_filter.sock

#create python socket object, from the file descriptor
sock = socket.fromfd(socket_fd,socket.PF_PACKET,socket.SOCK_RAW,socket.IPPROTO_IP)
#set it as blocking socket
sock.setblocking(True)
print("ready to filter")
while 1:
  #retrieve raw packet from socket
  packet_str = os.read(socket_fd,2048)

  #DEBUG - print raw packet in hex format
  packet_hex = binascii.hexlify(packet_str)
  print ("%s" % packet_hex)

  #convert packet into bytearray
  packet_bytearray = bytearray(packet_str)

  #ethernet header length
  ETH_HLEN = 14

  #IP HEADER
  #https://tools.ietf.org/html/rfc791
  #  0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
  # +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
  # |Version|  IHL  |Type of Service|          Total Length         |
  # +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
  # |         Identification        |Flags|      Fragment Offset    |
  # +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
  # |  Time to Live |    Protocol   |         Header Checksum       |
  # +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
  # |                       Source Address                          |
  # +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
  # |                    Destination Address                        |
  # +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
  # |                    Options                    |    Padding    |
  # +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
  #
  #IHL : Internet Header Length is the length of the internet header
  #value to multiply * 4 byte
  #e.g. IHL = 5 ; IP Header Length = 5 * 4 byte = 20 byte
  #
  #Total length: This 16-bit field defines the entire packet size,
  #including header and data, in bytes.

  #calculate packet total length
  total_length = packet_bytearray[ETH_HLEN + 2]               #load MSB
  total_length = total_length << 8                            #shift MSB
  total_length = total_length + packet_bytearray[ETH_HLEN+3]  #add LSB

  #calculate ip header length
  ip_header_length = packet_bytearray[ETH_HLEN]               #load Byte
  ip_header_length = ip_header_length & 0x0F                  #mask bits 0..3
  ip_header_length = ip_header_length << 2                    #shift to obtain length

  ip_src_addr = ETH_HLEN + 12
  ip_src_str = "Source IP:    {}.{}.{}.{}".format(packet_bytearray[ip_src_addr], packet_bytearray[ip_src_addr+1], packet_bytearray[ip_src_addr+2], packet_bytearray[ip_src_addr+3])
  print(ip_src_str)
  ip_dst_addr = ETH_HLEN + 16
  ip_dst_str = "Dest IP:      {}.{}.{}.{}".format(packet_bytearray[ip_dst_addr], packet_bytearray[ip_dst_addr+1], packet_bytearray[ip_dst_addr+2], packet_bytearray[ip_dst_addr+3])
  print(ip_dst_str)

  #TCP HEADER
  #https://www.rfc-editor.org/rfc/rfc793.txt
  #  0                   1                   2                   3   
  #  0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 
  # +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
  # |          Source Port          |       Destination Port        |
  # +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
  # |                        Sequence Number                        |
  # +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
  # |                    Acknowledgment Number                      |
  # +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

  #  12              13              14              15
  #  0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
  # +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
  # |  Data |           |U|A|P|R|S|F|                               |
  # | Offset| Reserved  |R|C|S|S|Y|I|            Window             |
  # |       |           |G|K|H|T|N|N|                               |
  # +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
  #
  #Data Offset: This indicates where the data begins.
  #The TCP header is an integral number of 32 bits long.
  #value to multiply * 4 byte
  #e.g. DataOffset = 5 ; TCP Header Length = 5 * 4 byte = 20 byte

  #calculate tcp header length
  tcp_header_length = packet_bytearray[ETH_HLEN + ip_header_length + 12]  #load Byte
  tcp_header_length = tcp_header_length & 0xF0                            #mask bit 4..7
  tcp_header_length = tcp_header_length >> 2                              #SHR 4 ; SHL 2 -> SHR 2

  #calculate payload offset
  payload_offset = ETH_HLEN + ip_header_length + tcp_header_length

  tcp_src_port = ETH_HLEN + ip_header_length
  tcp_src = int.from_bytes(packet_bytearray[tcp_src_port:tcp_src_port + 2], 'big')
  print("Source Port:  {}".format(tcp_src))

  tcp_dst_port = tcp_src_port + 2
  tcp_dst = int.from_bytes(packet_bytearray[tcp_dst_port:tcp_dst_port + 2], 'big')
  print("Dest Port:    {}".format(tcp_dst))

  #print first line of the HTTP GET/POST request
  #line ends with 0xOD 0xOA (\r\n)
  #(if we want to print all the header print until \r\n\r\n)
  # for i in range (payload_offset,len(packet_bytearray)-1):
  #   if (packet_bytearray[i] == 0x0A):
  #     if (packet_bytearray[i-1] == 0x0D):
  #       if (packet_bytearray[i-2] == 0x0A):
  #         if (packet_bytearray[i-3] == 0x0D):
  #           break
  #   print ("%c" % chr(packet_bytearray[i]), end = "")
  # print("")
  
  coap_offset = payload_offset + 23
  whole_payload = packet_bytearray[payload_offset:]
  print(whole_payload)
  coap_data = packet_bytearray[coap_offset:]
  print(coap_data)

  ip_header  = bytearray(b'\x45\x00\x00\x28')  # Version, IHL, Type of Service | Total Length
  ip_header += bytearray(b'\xab\xcd\x40\x00')  # Identification | Flags, Fragment Offset
  ip_header += bytearray(b'\x40\x11\xa6\xec')  # TTL, Protocol | Header Checksum
  ip_header += packet_bytearray[ip_src_addr:ip_src_addr+4]  # Source Address
  ip_header += packet_bytearray[ip_dst_addr:ip_dst_addr+4]  # Destination Address

  udp_header  = packet_bytearray[tcp_src_port:tcp_src_port + 2] # Source Port 
  udp_header += packet_bytearray[tcp_dst_port:tcp_dst_port + 2] # Destination Port
  udp_header += bytearray(b'\x00\x00\x00\x00')

  packet = ip_header + udp_header + coap_data
  packet[2] = len(packet) >> 8
  packet[3] = len(packet) & 0x00FF

  s = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_UDP)
  s.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)

  s.sendto(packet, (url, tcp_dst))
  # s.sendto(packet, ('10.10.10.1', 0))
  s.close()