#include <stdio.h>
#include <stdint.h>

typedef unsigned int u32;
typedef unsigned long __u64;
typedef unsigned int __u32;
typedef unsigned short __u16;

#ifdef __CHECKER__
#define __bitwise__ __attribute__((bitwise))
#else
#define __bitwise__
#endif
#define __bitwise __bitwise__

typedef __u16 __bitwise __le16;
typedef __u16 __bitwise __be16;
typedef __u32 __bitwise __le32;
typedef __u32 __bitwise __be32;
typedef __u64 __bitwise __le64;
typedef __u64 __bitwise __be64;

typedef __u16 __bitwise __sum16;
typedef __u32 __bitwise __wsum;


uint8_t ip_header[] = {0x45, 0x00, 0x00, 0x30, 0xcc, 0x61, 0x40, 0x00, 
                       0x40, 0x06, 0x4c, 0x02, 0x0a, 0x05, 0x04, 0x6b, 
                       0x0a, 0x08, 0x09, 0xed};

uint8_t tcp_header[] = {0xf3, 0xdd, 0x0c, 0xd3, 0xd9, 0xfa, 0xf8, 0x26, 
                        0x00, 0x00, 0x00, 0x00, 0x70, 0x02, 0xff, 0xff, 
                        0x8e, 0xe9, 0x00, 0x00, 0x02, 0x04, 0x05, 0xb4, 
                        0x04, 0x02, 0x00, 0x00};
uint8_t tcp_pseudo_heaer[] = {0x0a, 0x05, 0x04, 0x6b, 0x0a, 0x08, 
                              0x09, 0xed, 0x00, 0x06, 0x00, 0x1c};
uint8_t tcp_payload[] = {}; 

uint8_t udp_header[] = {0xf3, 0x42, 0x00, 0x35, 0x00, 0x28, 0x73, 0xc2};
uint8_t udp_pseudo_heaer[] = {0x0a, 0x05, 0x04, 0x6b, 0x08, 0x08, 
                              0x08, 0x08, 0x00, 0x11, 0x00, 0x28};
uint8_t udp_payload[] = {0xeb, 0x3c, 0x01, 0x00, 0x00, 0x01, 0x00, 0x00, 
                         0x00, 0x00, 0x00, 0x00, 0x03, 0x77, 0x77, 0x77, 
                         0x06, 0x67, 0x6f, 0x6f, 0x67, 0x6c, 0x65, 0x03, 
                         0x63, 0x6f, 0x6d, 0x00, 0x00, 0x01, 0x00, 0x01};

uint16_t summing(uint8_t *data, uint16_t prior_cksum, uint32_t size)
{
    uint32_t cksum = prior_cksum;
    uint32_t index = 0;

    if (size % 2 != 0) return 0;

    while (index < size) {
        cksum += *(data + index + 1) & 0x00ff; 
        cksum += *(data + index) << 8 & 0xff00;
        index += 2;
    }
    
    cksum = (__sum16)(cksum + (cksum >= 0xFFFF));

//    while (cksum > 0xffff) {
//        cksum = (cksum >> 16) + (cksum & 0xffff);
//    }

    printf("cksum = %u, cksum = %x\n", cksum, cksum);

    return cksum;
}

uint16_t getipcheck(uint8_t *data, uint32_t size)
{
    uint32_t cksum = 0;

    *(data + 10) = 0;
    *(data + 11) = 0;

    cksum = summing(data, 0, size);

    return ~cksum;
}

uint16_t gettcpcheck(uint8_t *data, uint32_t size)
{
    uint32_t cksum = 0;

    *(data + 16) = 0;
    *(data + 17) = 0;

    cksum = summing(data, 0, size);
    cksum = summing(tcp_pseudo_heaer, cksum, sizeof(tcp_pseudo_heaer));
    cksum = summing(tcp_payload, cksum, sizeof(tcp_payload));

    return ~cksum;
}

uint16_t getudpcheck(uint8_t *data, uint32_t size)
{
    uint32_t cksum = 0;

    *(data + 6) = 0;
    *(data + 7) = 0;

    cksum = summing(data, 0, size);
    cksum = summing(udp_pseudo_heaer, cksum, sizeof(udp_pseudo_heaer));
    cksum = summing(udp_payload, cksum, sizeof(udp_payload));

    return ~cksum;
}

int main()
{
    uint16_t ip_cksum = 0, tcp_cksum = 0, udp_cksum = 0;

    ip_cksum  = getipcheck(ip_header,   sizeof(ip_header));
    tcp_cksum = gettcpcheck(tcp_header, sizeof(tcp_header));
    udp_cksum = getudpcheck(udp_header, sizeof(udp_header));

    printf("IP header checksum = %#x\n", ip_cksum);
    printf("TCP header checksum = %#x\n", tcp_cksum);
    printf("UDP header checksum = %#x\n", udp_cksum);

    return 0;
}
