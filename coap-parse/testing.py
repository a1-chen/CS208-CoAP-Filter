import socket
import binascii

s = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_TCP)
s.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)

ip_header  = bytearray(b'\x45\x00\x00\x28')  # Version, IHL, Type of Service | Total Length
ip_header += bytearray(b'\xab\xcd\x00\x00')  # Identification | Flags, Fragment Offset
ip_header += bytearray(b'\x40\x06\xa6\xec')  # TTL, Protocol | Header Checksum
ip_header += bytearray(b'\x0a\x0a\x0a\x02')  # Source Address
# ip_header += packet_bytearray[ip_src_addr:ip_src_addr+4]  # Source Address
ip_header += bytearray(b'\x0a\x0a\x0a\x01')  # Destination Address
# ip_header += packet_bytearray[ip_dst_addr:ip_dst_addr+4]  # Destination Address

tcp_header  = bytearray(b'\x30\x39\x00\x50') # Source Port | Destination Port
# tcp_header  = packet_bytearray[udp_src_port:udp_src_port + 2] # Source Port 
# tcp_header += packet_bytearray[udp_dst_port:udp_dst_port + 2] # Destination Port
tcp_header += bytearray(b'\x00\x00\x00\x00') # Sequence Number
tcp_header += bytearray(b'\x00\x00\x00\x00') # Acknowledgement Number
tcp_header += bytearray(b'\x50\x02\x71\x10') # Data Offset, Reserved, Flags | Window Size
tcp_header += bytearray(b'\xe6\x32\x00\x00') # Checksum | Urgent Pointer

# http_header = b'\x47\x45\x54\x20\x2f\x20\x48\x54\x54\x50\x2f\x31\x2e\x31\x0d\x0a' # "GET \ HTTP\1.1"
http_header = bytearray(b"POST \\ HTTP\\1.1\x0d\x0a")
# http_header += coap_data
http_header += bytearray(b"\x0d\x0a\x0d\x0a")


packet = ip_header + tcp_header + http_header
print(len(packet))
print("msb: {} lsb: {}".format(packet[2], packet[3]))

print((len(packet) >> 8))
print (len(packet) & 0x00FF)
packet[2] = len(packet) >> 8
packet[3] = len(packet) & 0x00FF
print("msb: {} lsb: {}".format(packet[2], packet[3]))

print("{}".format(bytearray([61])))
s.sendto(packet, ('10.10.10.1', 0))