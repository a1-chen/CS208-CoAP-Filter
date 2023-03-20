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
import socket
import binascii
import os

import asyncio
import random
from aiocoap import *
import base64

import requests

#args
# async def send_request():
#   context = await Context.create_client_context()
#   alarm_state = random.choice([True, False])
#   payload = b"OFF"

#   if alarm_state:
#       payload = b"ON"

#   request = Message(code=PUT, payload=payload, uri="coap://[128.110.217.72]/alarm")

#   response = await context.request(request).response
#   #print('Result: %s\n%r'%(response.code, response.payload))
#   # print("payload: ", response.payload)
#   # print("mtype: ", response.mtype)
#   # print("code: ", response.code)
#   # print("opt: ", response.opt)
#   # print("mid: ", response.mid)
#   # print("token: ", response.token)
#   # print("remote: ", response.remote)
#   # print("request: ", response.request)
#   return response

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
bpf = BPF(src_file = "coap-parse-simple.c",debug = 0)

#load eBPF program http_filter of type SOCKET_FILTER into the kernel eBPF vm
#more info about eBPF program types
#http://man7.org/linux/man-pages/man2/bpf.2.html
#function_http_filter = bpf.load_func("http_filter", BPF.SOCKET_FILTER)
function_coap_filter = bpf.load_func("coap_filter", BPF.SOCKET_FILTER)

#create raw socket, bind it to interface
#attach bpf program to socket created
#BPF.attach_raw_socket(function_http_filter, interface)
BPF.attach_raw_socket(function_coap_filter, interface)

#get file descriptor of the socket previously created inside BPF.attach_raw_socket
#socket_fd = function_http_filter.sock
socket_fd = function_coap_filter.sock

#create python socket object, from the file descriptor
sock = socket.fromfd(socket_fd,socket.PF_PACKET,socket.SOCK_RAW,socket.IPPROTO_IP)
#set it as blocking socket
sock.setblocking(True)

print("ready to filter")
while 1:
  # pkt = asyncio.run(send_request())

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
  print("Total Length: {}".format(total_length))

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
  

  #UDP HEADER
  #https://www.rfc-editor.org/rfc/rfc768.txt
  #   0      7 8     15 16    23 24    31  
  #  +--------+--------+--------+--------+ 
  #  |     Source      |   Destination   | 
  #  |      Port       |      Port       | 
  #  +--------+--------+--------+--------+ 
  #  |                 |                 | 
  #  |     Length      |    Checksum     | 
  #  +--------+--------+--------+--------+ 
  #  |                                     
  #  |          data octets ...            
  #  +---------------- ...                 
  #
  # UDP header length is always 8 bytes
  udp_header_length = 8
  
  #calculate payload offset
  coap_offset = ETH_HLEN + ip_header_length + udp_header_length
  udp_src_port = ETH_HLEN + ip_header_length
  udp_src = int.from_bytes(packet_bytearray[udp_src_port:udp_src_port + 2], 'big')
  print("Source Port:  {}".format(udp_src))

  udp_dst_port = udp_src_port + 2
  udp_dst = int.from_bytes(packet_bytearray[udp_dst_port:udp_dst_port + 2], 'big')
  print("Dest Port:    {}".format(udp_dst))
  
  udp_pkt_length = udp_dst_port + 2
  udp_length = int.from_bytes(packet_bytearray[udp_pkt_length:udp_pkt_length+2], 'big')
  print("UDP Length:   {}".format(udp_length))

  udp_chksum = packet_bytearray[udp_pkt_length+2:udp_pkt_length+4] 
  
  
  #print first line of the HTTP GET/POST request
  #line ends with 0xOD 0xOA (\r\n)
  #(if we want to print all the header print until \r\n\r\n)
  # for i in range (coap_offset,len(packet_bytearray)-1):
  #   if (packet_bytearray[i]== 0x0A):
  #     if (packet_bytearray[i-1] == 0x0D):
  #       break
  #   print ("%c" % chr(packet_bytearray[i]), end = "")
  # print("")


  #  0                   1                   2                   3
  #   0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
  #  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
  #  |Ver| T |  TKL  |      Code     |          Message ID           |
  #  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
  #  |   Token (if any, TKL bytes) ...
  #  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
  #  |   Options (if any) ...
  #  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
  #  |1 1 1 1 1 1 1 1|    Payload (if any) ...
  #  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    
  # Version
  pkt_ver = (packet_bytearray[coap_offset] & 0xC0) >> 6
  if (pkt_ver == 0):
    break
  print("Version:      %i" % pkt_ver)
  
  # Type
  pkt_type = (packet_bytearray[coap_offset] & 0x30) >> 4
  if (pkt_type == 0):
    print("Type:         0 (Confirmable)")
  if (pkt_type == 1):
    print("Type:         1 (Non-Confirmable)")
  if (pkt_type == 2):
    print("Type:         2 (Acknowledgement)")
  if (pkt_type == 3):
    print("Type:         3 (Reset)")
  
  # Token Length (TKL)
  pkt_tkl = (packet_bytearray[coap_offset] & 0x0F) >> 0
  print("TKL:          %i" % pkt_tkl)
  
  # Code
  pkt_class = (packet_bytearray[coap_offset + 1] >> 5) & 0x07
  pkt_code = (packet_bytearray[coap_offset + 1] >> 0) & 0x1F
  print("Code:         {}.{}".format(pkt_class, repr(pkt_code).zfill(2)))

  # Message ID
  pkt_mid = int.from_bytes(packet_bytearray[(coap_offset + 2):(coap_offset + 4)], 'big')
  print("Message ID:   {}".format(pkt_mid))


  # Token
  pkt_token = 0
  if (pkt_tkl > 0):
    pkt_token = int.from_bytes(packet_bytearray[(coap_offset + 4):(coap_offset + 4 + pkt_tkl)], 'big')
  if (pkt_token != 0):
    print("Token:        {}".format(binascii.hexlify(packet_bytearray[(coap_offset + 4):(coap_offset + 4 + pkt_tkl)])))
  else:
    print("Token:        None (zero-length)")
  
  # Options
  options_offset = coap_offset + 4 + pkt_tkl
  pkt_options = 0
  payload_offset = options_offset + 1
  #options_to_payload_offset = 0
  options_length = 0
  delta_num = 0
  payload_marker = 0
  #print("options offset: {}".format(options_offset))
  while 1:
    if (options_offset > len(packet_bytearray)-1):
      print("reached end of packet, no Payload")
      break
    if (packet_bytearray[options_offset] == 0xFF):
      print("Payload marker at: {}".format(options_offset))
      payload_marker = 1
      break
    if (delta_num > 2053):
      break
    delta_offset = 0
    length_offset = 0
    value_offset = 0
    opt_delta = (packet_bytearray[options_offset] & 0xF0) >> 4 #get option delta
    # if delta = 13 = 0x0D, An 8-bit unsigned integer follows the initial
    #   byte and indicates the Option Delta minus 13.
    if (opt_delta == 0x0D):
      delta_offset = 1
      opt_delta = int.from_bytes(packet_bytearray[options_offset + 1], 'big') - 13
    # if delta = 14 = 0x0E, A 16-bit unsigned integer in network byte order follows the
    #   initial byte and indicates the Option Delta minus 269.
    if (opt_delta == 0x0E):
      delta_offset = 2
      opt_delta = int.from_bytes(packet_bytearray[options_offset + 1:options_offset + 3], 'big') - 269
    # if delta = 15 = 0x0F, message error
    if (opt_delta == 0x0F):
      print("opt_delta broke lol")
      break
    # print option num from delta
    delta_num += opt_delta

    # option length
    opt_length = (packet_bytearray[options_offset] & 0x0F) >> 0
    if (opt_length == 0x0D):
      length_offset = 1
      opt_length = int.from_bytes(packet_bytearray[options_offset + delta_offset + 1], 'big') - 13
    if (opt_length == 0x0E):
      length_offset = 2
      opt_length = int.from_bytes(packet_bytearray[options_offset + delta_offset + 1 : options_offset + delta_offset + 3], 'big') - 269
    if (opt_length == 0x0F):
      print("opt_length broke lol")
      break
    #options_to_payload_offset += delta_offset + length_offset + opt_length + 1
    print("Option #:     {}".format(delta_num))
    pkt_options += 1
    options_offset += delta_offset + length_offset + opt_length + 1
  
  # Payload
  #print("opt to payload: {}".format(options_to_payload_offset))
  #print("opt offset fnal {}".format(options_offset))
  if (pkt_options == 0):
    print("Options:      None (zero-length)")
  if (payload_marker != 0):
    payload_offset = options_offset + 1
    print("Payload:      ", end = "")
    for i in range(payload_offset, len(packet_bytearray)):
      print("%c" %chr(packet_bytearray[i]), end = "")
  else:
    print("Payload:      empty")
  
  print("")
  
  # TODO: slap it into the http tcp post packet
  url = "{}.{}.{}.{}".format(packet_bytearray[ip_dst_addr], packet_bytearray[ip_dst_addr+1], packet_bytearray[ip_dst_addr+2], packet_bytearray[ip_dst_addr+3])
  # packet_bytearray[ip_src_addr+2], packet_bytearray[ip_src_addr+3]
  # print(url)
  # requests.post(url, "buh")
  # r = requests.get('https://api.github.com/events')

  coap_data = packet_bytearray[coap_offset:]
  print(coap_data)
  # coap_hex = binascii.hexlify(coap_data)
  # print(coap_hex)
  # data = base64.b64encode(coap_data)
  # print(data)
  # decoded = base64.b64decode(data)
  # print(decoded)

  ip_header  = bytearray(b'\x45\x00\x00\x28')  # Version, IHL, Type of Service | Total Length
  ip_header += bytearray(b'\xab\xcd\x40\x00')  # Identification | Flags, Fragment Offset
  ip_header += bytearray(b'\x40\x06\xa6\xec')  # TTL, Protocol | Header Checksum
  ip_header += packet_bytearray[ip_src_addr:ip_src_addr+4]  # Source Address
  ip_header += packet_bytearray[ip_dst_addr:ip_dst_addr+4]  # Destination Address

  tcp_header  = packet_bytearray[udp_src_port:udp_src_port + 2] # Source Port 
  tcp_header += packet_bytearray[udp_dst_port:udp_dst_port + 2] # Destination Port
  tcp_header += bytearray(b'\x00\x00\x00\x00') # Sequence Number
  tcp_header += bytearray(b'\x00\x00\x00\x00') # Acknowledgement Number
  tcp_header += bytearray(b'\x50\x18\x01\xfb') # Data Offset, Reserved, Flags | Window Size
  tcp_header += bytearray(b'\xe6\x32\x00\x00') # Checksum | Urgent Pointer

  # http_header = b'\x47\x45\x54\x20\x2f\x20\x48\x54\x54\x50\x2f\x31\x2e\x31\x0d\x0a' # "GET \ HTTP\1.1"
  http_header = bytearray(b"POST / HTTP/1.1\x0d\x0a")
  http_header += coap_data
  http_header += bytearray(b"\x0d\x0a\x0d\x0a")


  packet = ip_header + tcp_header + http_header
  packet[2] = len(packet) >> 8
  packet[3] = len(packet) & 0x00FF

  s = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_TCP)
  s.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)

  s.sendto(packet, (url, udp_dst))
  # s.sendto(packet, ('10.10.10.1', 0))
  s.close()
  print("")
  print("")
 