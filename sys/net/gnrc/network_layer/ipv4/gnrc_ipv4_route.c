/*
 * Copyright (C) 2015 Martine Lenders <mlenders@inf.fu-berlin.de>
 *
 * This file is subject to the terms and conditions of the GNU Lesser
 * General Public License v2.1. See the file LICENSE in the top level
 * directory for more details.
 */

/**
 * @{
 *
 * @file
 */
#include <assert.h>
#include <errno.h>
#include <inttypes.h>
#include <stdbool.h>

#include "byteorder.h"
#include "cpu_conf.h"
#include "kernel_types.h"
#include "net/gnrc/icmpv4.h"
#include "net/protnum.h"
#include "thread.h"
#include "utlist.h"

#include "net/arp.h"
#include "net/netopt.h"
#include "net/gnrc.h"
#include "net/gnrc/netif.h"
#include "net/gnrc/netif/internal.h"

#include "net/gnrc/ipv4.h"
#include "net/gnrc/ipv4/arp/arp.h"

#define ENABLE_DEBUG    (1)
#include "debug.h"

gnrc_ipv4_route_t gnrc_ipv4_route[GNRC_IPV4_ROUTE_TABLE_SIZE];

void gnrc_ipv4_route_clear(void)
{
  for (size_t i=0; i<GNRC_IPV4_ROUTE_TABLE_SIZE; i++) {
    gnrc_ipv4_route[i].network = ipv4_addr_unspecified;
  }
}

void gnrc_ipv4_route_add(void)
{

}

void gnrc_ipv4_route_delete(void)
{

}

/*
 *  Check if the destination is in a IPv4 network attached to this iface
 */
static bool gnrc_ipv4_route_same_network(const ipv4_addr_t *dst, gnrc_netif_t *netif, ipv4_addr_t *hop)
{
  int res;
  ipv4_addr_t addrs[GNRC_NETIF_IPV4_ADDRS_NUMOF];
  res = gnrc_netapi_get(netif->pid, NETOPT_IPV4_ADDR, 0, addrs, sizeof(addrs));
  assert(res == 0);

  ipv4_addr_t masks[GNRC_NETIF_IPV4_ADDRS_NUMOF];
  res = gnrc_netapi_get(netif->pid, NETOPT_IPV4_MASK, 0, masks, sizeof(masks));
  assert(res == 0);

  for (size_t i=0; i < (size_t)(res / sizeof(ipv4_addr_t)); i++) {
    if (ipv4_addr_is_unspecified(&addrs[i])) {
      continue;
    }

    if (ipv4_addr_match_prefix(&addrs[i], &masks[i], dst)) {
      *hop = addrs[i];
      return true;
    }
  }

  return false;
}

void gnrc_ipv4_route_get_next_hop_l2addr(const ipv4_addr_t *dst, gnrc_netif_t **netif, ipv4_addr_t *hop)
{
  /* Search if the destination can be contacted directly */
  if (*netif != NULL) {
    if (gnrc_ipv4_route_same_network(dst, *netif, hop)) {
      return;
    }
  } else {
    gnrc_netif_t *it = NULL;
    while ((it = gnrc_netif_iter(it))) {
      if (gnrc_ipv4_route_same_network(dst, it, hop)) {
        *netif = it;
        return;
      }
    }
  }

  /* Search in the routing table */
  for (size_t i=0; i<GNRC_IPV4_ROUTE_TABLE_SIZE; i++) {
    if (ipv4_addr_is_unspecified(&gnrc_ipv4_route[i].network)) {
      continue;
    }

    if (ipv4_addr_match_prefix(&gnrc_ipv4_route[i].network, &gnrc_ipv4_route[i].mask, dst)) {
      *hop = gnrc_ipv4_route[i].dst;
      *netif = gnrc_netif_get_by_pid(gnrc_ipv4_route[i].iface);
      break;
    }
  }

  /* Not found */
  *netif = NULL;
}
