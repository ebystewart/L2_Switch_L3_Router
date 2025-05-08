#ifndef IP_H
#define IP_H
#include <stdint.h>
#include "../net.h"

#pragma pack(push,1)
typedef struct ip_hdr_{
    unsigned short int version :4;    /* IP Protocol version. For IPv4 its 4; For IPv6 its 6 */
    unsigned short int hdr_len :4 ;   /* Length of IP header in DWord */
    char tos;
    unsigned short total_length;      /* length  of hdr + payload */

    /* Fragmentation related */
    unsigned short int identification;
    unsigned short int unused_flag : 1;
    unsigned short int DF_flag : 1;
    unsigned short int MORE_flag : 1;
    unsigned long int frag_offset : 13;

    char ttl;
    char protocol;
    unsigned short int checksum;
    unsigned int src_ip;
    unsigned int dst_ip;
}ip_hdr_t;
#pragma pop

void layer3_ip_pkt_recv_from_bottom(node_t *node, interface_t *interface, ip_hdr_t *pkt, unsigned int pkt_size);

#endif //IP_H