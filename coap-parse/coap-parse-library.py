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
import os

import asyncio
import random
from aiocoap import *

#args
async def send_request():
  context = await Context.create_client_context()
  alarm_state = random.choice([True, False])
  payload = b"OFF"

  if alarm_state:
      payload = b"ON"

  request = Message(code=PUT, payload=payload, uri="coap://[128.110.217.72]/alarm")

  response = await context.request(request).response
  #print('Result: %s\n%r'%(response.code, response.payload))
  # print("payload: ", response.payload)
  # print("mtype: ", response.mtype)
  # print("code: ", response.code)
  # print("opt: ", response.opt)
  # print("mid: ", response.mid)
  # print("token: ", response.token)
  # print("remote: ", response.remote)
  # print("request: ", response.request)
  return response

def observe_callback(response):
  if response.code.is_successful():
      print("Alarm status: %s" % (response.payload.decode('ascii')))
  else:
      print('Error code %s' % response.code)

async def observe():
  context = await Context.create_client_context()

  request = Message(code=GET)
  request.set_request_uri('coap://[128.110.217.72]/alarm')
  request.opt.observe = 0
  observation_is_over = asyncio.Future()

  try:
      context_request = context.request(request)
      context_request.observation.register_callback(observe_callback)
      response = await context_request.response
      exit_reason = await observation_is_over
      print('Observation is over: %r' % exit_reason)
  finally:
      if not context_request.response.done():
          context_request.response.cancel()
      if not context_request.observation.cancelled:
          context_request.observation.cancel()

  return response

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

while 1:
  #pkt = asyncio.run(send_request())
  pkt = asyncio.run(observe())

  #retrieve raw packet from socket
  packet_str = os.read(socket_fd,2048)

  #DEBUG - print raw packet in hex format
  #packet_hex = toHex(packet_str)
  #print ("%s" % packet_hex)

  #convert packet into bytearray
  packet_bytearray = bytearray(packet_str)

  #ethernet header length
  ETH_HLEN = 14

  #IP HEADER
  #https://tools.ietf.org/html/rfc791
  # 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
  # +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
  # |Version|  IHL  |Type of Service|          Total Length         |
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
  payload_offset = ETH_HLEN + ip_header_length + udp_header_length

  #print first line of the HTTP GET/POST request
  #line ends with 0xOD 0xOA (\r\n)
  #(if we want to print all the header print until \r\n\r\n)
  # for i in range (payload_offset,len(packet_bytearray)-1):
  #   if (packet_bytearray[i]== 0x0A):
  #     if (packet_bytearray[i-1] == 0x0D):
  #       break
  #   print ("%c" % chr(packet_bytearray[i]), end = "")
  # print("")
  ### TODO: add code to test coap packet by printing?


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
  # print CoAP packet mID
  # ver = (packet_bytearray[payload_offset] & 0xC0) >> 6
  # print(ver)

  print(pkt.payload)

