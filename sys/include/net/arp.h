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

#ifdef __cplusplus
}
#endif

#endif /* NET_ARP_H */
/**
 * @}
 */
