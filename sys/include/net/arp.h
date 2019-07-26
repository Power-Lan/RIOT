#ifndef NET_ARP_H
#define NET_ARP_H

#include "kernel_types.h"
#include "thread.h"

#include "net/ipv4/addr.h"

#ifdef __cplusplus
extern "C" {
#endif

#define ARP_MAC_SIZE (6)

#define ARP_FLAG_COMPLETE  (1)

typedef struct __attribute__((packed)) {
    ipv4_addr_t ipv4;
    ipv4_addr_t mask;
    uint8_t mac[ARP_MAC_SIZE];
    uint8_t flags;
    kernel_pid_t iface;
} arp_t;

typedef struct __attribute__((packed)) {
    uint16_t hw_type;
    uint16_t protocol_type;
    uint8_t hw_size;
    uint8_t protocol_size;
    uint16_t opcode;
    uint16_t sender_hw_addr[3];
    uint16_t sender_protocol_addr[3];
    uint16_t target_hw_addr[3];
    uint16_t target_protocol_addr[3];
} arp_payload_t;

#ifdef __cplusplus
}
#endif

#endif /* NET_ARP_H */
/**
 * @}
 */
