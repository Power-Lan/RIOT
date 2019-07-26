/*
 * Copyright (C) 2019 William MARTIN <william.martin@power-lan.com>
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
#include "utlist.h"

#include "net/gnrc.h"
#include "net/gnrc/netif.h"
#include "net/gnrc/netif/internal.h"
#include "net/gnrc/ipv4/arp/arp.h"
#include "net/arp.h"

#define ENABLE_DEBUG    (1)
#include "debug.h"

#if ENABLE_DEBUG
static char _stack[GNRC_IPV4_ARP_STACK_SIZE + THREAD_EXTRA_STACKSIZE_PRINTF];
#else
static char _stack[GNRC_IPV4_ARP_STACK_SIZE];
#endif

static char ipv4_addr[IPV4_ADDR_MAX_STR_LEN];

kernel_pid_t gnrc_ipv4_arp_pid = KERNEL_PID_UNDEF;

static void _receive(msg_t *msg)
{

  assert(msg != NULL);

  // Ensure pkt is ARP
  gnrc_pktsnip_t *pkt = msg->content.ptr;
  if (pkt->type != GNRC_NETTYPE_ARP) {
      DEBUG("ipv4_arp: unexpected packet type\n");
      gnrc_pktbuf_release_error(pkt, EINVAL);
      return;
  }
  arp_payload_t *payload = (arp_payload_t *)pkt->data;

  // Check protocol type
  if (byteorder_ntohs(payload->protocol_type) != ETHERTYPE_IPV4) {
      DEBUG("ipv4_arp: wrong protocol_type\n");
      gnrc_pktbuf_release_error(pkt, EINVAL);
      return;
  }

  // Check hw/protocol length
  if (payload->hw_size != 6 || payload->protocol_size != 4) {
      DEBUG("ipv4_arp: unexpected hw_size or protocol_size\n");
      gnrc_pktbuf_release_error(pkt, EINVAL);
      return;
  }

  // Ensure this is a request
  if (byteorder_ntohs(payload->opcode) != 1) {
      DEBUG("ipv4_arp: not an arp request\n");
      gnrc_pktbuf_release_error(pkt, EINVAL);
      return;
  }

  // Get network interface
  gnrc_netif_t *netif = NULL;
  netif = gnrc_netif_get_by_pid(msg->sender_pid);
  assert(netif != NULL);

  // Extract MAC source
  if (pkt->size != sizeof(arp_payload_t)) {
    DEBUG("ipv4_arp: wrong packet size %d instead of %d\n", pkt->size, sizeof(arp_payload_t));
    gnrc_pktbuf_release_error(pkt, EINVAL);
    return;
  }

  // We love debugs
  DEBUG("ipv4_arp: opcode = %d\n", byteorder_ntohs(payload->opcode));
  DEBUG("ipv4_arp: sender_hw_addr = %02X:%02X:%02X:%02X:%02X:%02X\n",
    payload->sender_hw_addr[0],
    payload->sender_hw_addr[1],
    payload->sender_hw_addr[2],
    payload->sender_hw_addr[3],
    payload->sender_hw_addr[4],
    payload->sender_hw_addr[5]);
  DEBUG("ipv4_arp: sender_protocol_addr = %s\n", ipv4_addr_to_str(ipv4_addr, &payload->sender_protocol_addr, IPV4_ADDR_MAX_STR_LEN));
  DEBUG("ipv4_arp: target_hw_addr = %02X:%02X:%02X:%02X:%02X:%02X\n",
    payload->target_hw_addr[0],
    payload->target_hw_addr[1],
    payload->target_hw_addr[2],
    payload->target_hw_addr[3],
    payload->target_hw_addr[4],
    payload->target_hw_addr[5]);
  DEBUG("ipv4_arp: target_protocol_addr = %s\n", ipv4_addr_to_str(ipv4_addr, &payload->target_protocol_addr, IPV4_ADDR_MAX_STR_LEN));

  // List IP
  ipv4_addr_t ipv4_addrs[GNRC_NETIF_IPV4_ADDRS_NUMOF];
  int res = gnrc_netapi_get(netif->pid, NETOPT_IPV4_ADDR, 0, ipv4_addrs, sizeof(ipv4_addrs));
  if (res < 0) {
    DEBUG("ipv4_arp: Failed to list IPs on interface %d\n", netif->pid);
    gnrc_pktbuf_release(pkt);
    return;
  }

  for (unsigned i = 0; i < (unsigned)(res / sizeof(ipv4_addr_t)); i++) {
    if (ipv4_addr_equal(&ipv4_addrs[i], &payload->target_protocol_addr)) {
      DEBUG("ipv4_arp: It's me ! Mario\n");
    }
  }


  gnrc_pktbuf_release(pkt);
}

static void *_event_loop(void *args)
{
    msg_t msg, reply, msg_q[GNRC_IPV4_ARP_MSG_QUEUE_SIZE];
    gnrc_netreg_entry_t me_reg = GNRC_NETREG_ENTRY_INIT_PID(GNRC_NETREG_DEMUX_CTX_ALL,
                                                            sched_active_pid);

    (void)args;
    msg_init_queue(msg_q, GNRC_IPV4_ARP_MSG_QUEUE_SIZE);

    /* register interest in all IPv4 packets */
    gnrc_netreg_register(GNRC_NETTYPE_ARP, &me_reg);

    /* preinitialize ACK */
    reply.type = GNRC_NETAPI_MSG_TYPE_ACK;

    /* start event loop */
    while (1) {
        DEBUG("ipv4_arp: waiting for incoming message.\n");
        msg_receive(&msg);

        switch (msg.type) {
            case GNRC_NETAPI_MSG_TYPE_RCV:
                DEBUG("ipv4_arp: GNRC_NETAPI_MSG_TYPE_RCV received\n");
                //printf("ipv4_arp: sender_pid:%d\n", msg.sender_pid);
                //gnrc_pktbuf_release(msg.content.ptr);
                _receive(&msg);
                break;

            case GNRC_NETAPI_MSG_TYPE_SND:
                DEBUG("ipv4_arp: GNRC_NETAPI_MSG_TYPE_SND received\n");
                break;

            case GNRC_NETAPI_MSG_TYPE_GET:
            case GNRC_NETAPI_MSG_TYPE_SET:
                DEBUG("ipv4: reply to unsupported get/set\n");
                reply.content.value = -ENOTSUP;
                msg_reply(&msg, &reply);
                break;

            default:
                break;
        }
    }

    return NULL;
}

kernel_pid_t gnrc_ipv4_arp_init(void)
{
    if (gnrc_ipv4_arp_pid == KERNEL_PID_UNDEF) {
        gnrc_ipv4_arp_pid = thread_create(_stack, sizeof(_stack), GNRC_IPV4_ARP_PRIO,
                                          THREAD_CREATE_STACKTEST,
                                          _event_loop, NULL, "ipv4_arp");
    }

    return gnrc_ipv4_arp_pid;
}
