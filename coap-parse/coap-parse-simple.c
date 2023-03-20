#include <uapi/linux/ptrace.h>
#include <net/sock.h>
#include <bcc/proto.h>

#define IP_TCP 	6
#define IP_UDP  17
#define ETH_HLEN 14
#define COAP_HEADER_VERSION(data)  ( (0xC0 & (data)[0]) >> 6      )
#define COAP_HEADER_TYPE(data)     ( (0x30 & (data)[0]) >> 4      )
#define COAP_HEADER_TKL(data)      ( (0x0F & (data)[0]) >> 0      )
#define COAP_HEADER_CLASS(data)    ( ((data)[1] >> 5) & 0x07      )
#define COAP_HEADER_CODE(data)     ( ((data)[1] >> 0) & 0x1F      )
#define COAP_HEADER_MID(data)      ( ((data)[2] << 8) | (data)[3] )

/*eBPF program.
  Filter IP and UDP packets, having payload not empty
  and containing "HTTP", "GET", "POST" ... as first bytes of payload
  if the program is loaded as PROG_TYPE_SOCKET_FILTER
  and attached to a socket
  return  0 -> DROP the packet
  return -1 -> KEEP the packet and return it to user space (userspace can read it from the socket_fd )
*/
int coap_filter(struct __sk_buff *skb) {

	u8 *cursor = 0;

	struct ethernet_t *ethernet = cursor_advance(cursor, sizeof(*ethernet));
	//filter IP packets (ethernet type = 0x0800)
	if (!(ethernet->type == 0x0800)) {
		goto DROP;
	}

  struct ip_t *ip = cursor_advance(cursor, sizeof(*ip));
  //filter UDP packets (ip next protocol = 0x08)
  if (ip->nextp != IP_UDP) {
    goto DROP;
  }
  if (ip->nextp == IP_TCP) {
    goto DROP;
  }

	u32  udp_header_length = 0;
	u32  ip_header_length = 0;
	u32  payload_offset = 0;
	u32  payload_length = 0;

	//calculate ip header length
	//value to multiply * 4
	//e.g. ip->hlen = 5 ; IP Header Length = 5 x 4 byte = 20 byte
	ip_header_length = ip->hlen << 2;    //SHL 2 -> *4 multiply

  //check ip header length against minimum
	if (ip_header_length < sizeof(*ip)) {
		goto DROP;
	}
  u32 ip_src_offset = ETH_HLEN + 12;
  u32 ip_dst_offset = ETH_HLEN + 16;

  //load source and destination address into addr[] (address array)
  unsigned long addr[8];
	int j = 0;
	for (j = 0; j < 8; j++) {
		addr[j] = load_byte(skb, ip_src_offset + j);
	}

  //if source is DNS IP
  if (addr[0] == 198) {
    if (addr[1] == 22) {
      if (addr[2] == 255) {
        if (addr[3] == 3) {
          goto DROP;
        }
      }
    }
  }

  //if destination is DNS IP
  if (addr[4] == 198) {
    if (addr[5] == 22) {
      if (addr[6] == 255) {
        if (addr[7] == 3) {
          goto DROP;
        }
      }
    }
  }

  // bool match = 0;
  // //if source is server, keep
  // if (addr[0] == 10) {
  //   if (addr[1] == 244) {
  //     if (addr[2] == 1) {
  //       if (addr[3] == 19) {
  //         match = 1;
  //       }
  //     }
  //   }
  // }

  // //if destination is server, keep
  // if (addr[4] == 10) {
  //   if (addr[5] == 244) {
  //     if (addr[6] == 1) {
  //       if (addr[7] == 19) {
  //         match = 1;
  //       }
  //     }
  //   }
  // }
  
  // if (!match) 
  //   goto DROP;
  
  //shift cursor forward for dynamic ip header size
  void *_ = cursor_advance(cursor, (ip_header_length-sizeof(*ip)));

	struct udp_t *udp = cursor_advance(cursor, sizeof(*udp));

  // check if udp packet length is smaller than minimum
  if (udp->length < 8) {
    goto DROP;
  }

	// udp header length is always 8 bytes
	udp_header_length = 8;

	//calculate payload offset and length
	payload_offset = ETH_HLEN + ip_header_length + udp_header_length;
	payload_length = ip->tlen - ip_header_length - udp_header_length;

	//minimum length of coap packet is always 4 bytes or greater
	//avoid invalid access memory
	//include empty payload (4 bytes)
	if(payload_length < 4) {
		goto DROP;
	}

	//load first 4 byte of payload into p (payload_array)
	//direct access to skb not allowed
	unsigned long p[4];
	int i = 0;
	for (i = 0; i < 4; i++) {
		p[i] = load_byte(skb, payload_offset + i);
	}

  if (COAP_HEADER_VERSION(p) != 1){
    goto DROP;
  }

  if (COAP_HEADER_TKL(p) >= 9) {
    goto DROP;
  }

  unsigned int coap_class = COAP_HEADER_CLASS(p);
  unsigned int coap_code = COAP_HEADER_CODE(p);

  if (coap_class == 0) { // Method class
    if(coap_code > 7) {
      goto DROP;
    }
    goto KEEP;
  }

  if (coap_class == 1) { // Reserved
    goto DROP;
  }

  if (coap_class == 2) { // Success
    if(coap_code == 0 || (coap_code > 5 && coap_code < 31)) {
      goto DROP;
    }
    goto KEEP;
  }

  if (coap_class == 3) { // Reserved
    goto DROP;
  }

  if (coap_class == 4) { // Client Error
    if (coap_code == 7 || coap_code == 10 || coap_code == 11 || coap_code == 14) {
      goto DROP;
    }
    if (coap_code > 15 && coap_code < 22) {
      goto DROP;
    }
    if (coap_code > 22 && coap_code < 29) {
      goto DROP;
    }
    if(coap_code > 29) {
      goto DROP;
    }
    goto KEEP;
  }

  if (coap_class == 5) { // Server Error
    if (coap_code > 5 && coap_code < 8) {
      goto DROP;
    }
    if (coap_code > 8) {
      goto DROP;
    }
    goto KEEP;
  }

  if (coap_class == 6) { // Reserved
    goto DROP;
  }

  if (coap_class == 7) { // Reserved
    goto DROP;
  }
	
	//no CoAP match
	goto DROP;

	//keep the packet and send it to userspace returning -1
	KEEP:
	return -1;

	//drop the packet returning 0
	DROP:
	return 0;

}