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

kernel_pid_t gnrc_ipv4_arp_pid = KERNEL_PID_UNDEF;

static void _receive(msg_t *msg)
{
  gnrc_netif_t *netif = NULL;

  // Ensure pkt is ARP
  gnrc_pktsnip_t *pkt = msg.content.ptr;
  if (pkt->type != GNRC_NETTYPE_ARP) {
      DEBUG("ipv4_arp: unexpected packet type\n");
      gnrc_pktbuf_release_error(pkt, EINVAL);
      return;
  }


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
