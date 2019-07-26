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
//#include "net/gnrc/icmpv4.h"
#include "net/protnum.h"
#include "thread.h"
#include "utlist.h"

#include "net/gnrc.h"
#include "net/gnrc/netif.h"
#include "net/gnrc/netif/internal.h"
#include "net/gnrc/ipv4.h"

#define ENABLE_DEBUG    (1)
#include "debug.h"

#define _MAX_L2_ADDR_LEN    (8U)

#if ENABLE_DEBUG
static char _stack[GNRC_IPV4_STACK_SIZE + THREAD_EXTRA_STACKSIZE_PRINTF];
#else
static char _stack[GNRC_IPV4_STACK_SIZE];
#endif


static char addr_str[IPV4_ADDR_MAX_STR_LEN];

kernel_pid_t gnrc_ipv4_pid = KERNEL_PID_UNDEF;

/* handles GNRC_NETAPI_MSG_TYPE_RCV commands */
//static void _receive(gnrc_pktsnip_t *pkt);
/* Sends packet over the appropriate interface(s).
 * prep_hdr: prepare header for sending (call to _fill_ipv4_hdr()), otherwise
 * assume it is already prepared */
static void _send(gnrc_pktsnip_t *pkt, bool prep_hdr);

/* Main event loop for IPv4 */
static void *_event_loop(void *args);

kernel_pid_t gnrc_ipv4_init(void)
{
    gnrc_ipv4_arp_init();
    
    if (gnrc_ipv4_pid == KERNEL_PID_UNDEF) {
        gnrc_ipv4_pid = thread_create(_stack, sizeof(_stack), GNRC_IPV4_PRIO,
                                      THREAD_CREATE_STACKTEST,
                                      _event_loop, NULL, "ipv4");
    }

    return gnrc_ipv4_pid;
}

static void *_event_loop(void *args)
{
    msg_t msg, reply, msg_q[GNRC_IPV4_MSG_QUEUE_SIZE];
    gnrc_netreg_entry_t me_reg = GNRC_NETREG_ENTRY_INIT_PID(GNRC_NETREG_DEMUX_CTX_ALL,
                                                            sched_active_pid);

    (void)args;
    msg_init_queue(msg_q, GNRC_IPV4_MSG_QUEUE_SIZE);

    /* register interest in all IPv4 packets */
    gnrc_netreg_register(GNRC_NETTYPE_IPV4, &me_reg);

    /* preinitialize ACK */
    reply.type = GNRC_NETAPI_MSG_TYPE_ACK;

    /* start event loop */
    while (1) {
        DEBUG("ipv4: waiting for incoming message.\n");
        msg_receive(&msg);

        switch (msg.type) {
            case GNRC_NETAPI_MSG_TYPE_RCV:
                DEBUG("ipv4: GNRC_NETAPI_MSG_TYPE_RCV received\n");
                //_receive(msg.content.ptr);
                break;

            case GNRC_NETAPI_MSG_TYPE_SND:
                DEBUG("ipv4: GNRC_NETAPI_MSG_TYPE_SND received\n");
                _send(msg.content.ptr, true);
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

static inline bool _is_ipv4_hdr(gnrc_pktsnip_t *hdr)
{
    return (hdr->type == GNRC_NETTYPE_IPV4);
}

static int _fill_ipv4_hdr(gnrc_netif_t *netif, gnrc_pktsnip_t *ipv4)
{
    int res;
    ipv4_hdr_t *hdr = ipv4->data;
    gnrc_pktsnip_t *payload, *prev;

    // Set protocol
    if (hdr->protocol == PROTNUM_RESERVED) {
        if (ipv4->next == NULL) {
            hdr->protocol = PROTNUM_IPV6_NONXT;
        }
        else {
            hdr->protocol = gnrc_nettype_to_protnum(ipv4->next->type);

            /* if still reserved: mark no next header */
            if (hdr->protocol == PROTNUM_RESERVED) {
                hdr->protocol = PROTNUM_IPV6_NONXT;
            }
        }
    }

    // Total len
    hdr->tl = byteorder_htons(gnrc_pkt_len(ipv4));

    // TTL
    if (hdr->ttl == 0) {
        if (netif == NULL) {
            hdr->ttl = GNRC_NETIF_DEFAULT_HL;
        }
        else {
            hdr->ttl = netif->cur_hl;
        }
    }

    // Check source ip
    if (ipv4_addr_is_unspecified(&hdr->src)) {
        if (ipv4_addr_is_loopback(&hdr->dst)) {
            ipv4_addr_set_loopback(&hdr->src);
        }
        else {

            ipv4_addr_t *src = gnrc_netif_ipv4_addr_best_src(netif, &hdr->dst,
                                                             false);

            if (src != NULL) {
                char addr_str[IPV4_ADDR_MAX_STR_LEN];
                DEBUG("ipv4: set packet source to %s\n",
                      ipv4_addr_to_str(addr_str, src, sizeof(addr_str)));
                memcpy(&hdr->src, src, sizeof(ipv4_addr_t));
            }
            /* Otherwise leave unspecified */
        }
    }

    DEBUG("ipv4: write protect up to payload to calculate checksum\n");
    payload = ipv4;
    prev = ipv4;
    while (_is_ipv4_hdr(payload) && (payload->next != NULL)) {
        /* IPv4 header itself was already write-protected in caller function,
         * just write protect extension headers and payload header */
        if ((payload = gnrc_pktbuf_start_write(payload->next)) == NULL) {
            DEBUG("ipv4: unable to get write access to IPv4 extension or payload header\n");
            /* packet duplicated to this point will be released by caller,
             * original packet by other subscriber */
            return -ENOMEM;
        }
        prev->next = payload;
        prev = payload;
    }

    DEBUG("ipv4: calculate checksum for upper header.\n");
    if ((res = gnrc_netreg_calc_csum(payload, ipv4)) < 0) {
        if (res != -ENOENT) {   /* if there is no checksum we are okay */
            DEBUG("ipv4: checksum calculation failed.\n");
            /* packet will be released by caller */
            return res;
        }
    }

    DEBUG("ipv4: calculate checksum.\n");
    ipv4_hdr_inet_csum(ipv4->data);

    return 0;
}

static bool _safe_fill_ipv4_hdr(gnrc_netif_t *netif, gnrc_pktsnip_t *pkt,
                                bool prep_hdr)
{
    if (prep_hdr && (_fill_ipv4_hdr(netif, pkt) < 0)) {
        /* error on filling up header */
        gnrc_pktbuf_release(pkt);
        return false;
    }
    return true;
}

static void _send_to_self(gnrc_pktsnip_t *pkt, bool prep_hdr,
                          gnrc_netif_t *netif)
{
    if (!_safe_fill_ipv4_hdr(netif, pkt, prep_hdr) ||
        /* no netif header so we just merge the whole packet. */
        (gnrc_pktbuf_merge(pkt) != 0)) {
        DEBUG("ipv4: error looping packet to sender.\n");
        gnrc_pktbuf_release(pkt);
        return;
    }

    DEBUG("ipv4: packet is addressed to myself => loopback\n");

    if (gnrc_netapi_dispatch_receive(GNRC_NETTYPE_IPV4,
                                     GNRC_NETREG_DEMUX_CTX_ALL,
                                     pkt) == 0) {
        DEBUG("ipv4: unable to deliver looped back packet\n");
        gnrc_pktbuf_release(pkt);
    }
}

static void _send_multicast(gnrc_pktsnip_t *pkt, bool prep_hdr,
                            gnrc_netif_t *netif, uint8_t netif_hdr_flags)
{
  gnrc_pktbuf_release_error(pkt, EINVAL);
}

static void _send_to_iface(gnrc_netif_t *netif, gnrc_pktsnip_t *pkt)
{
    const ipv4_hdr_t *hdr = pkt->next->data;

    assert(netif != NULL);
    ((gnrc_netif_hdr_t *)pkt->data)->if_pid = netif->pid;
    /*if (gnrc_pkt_len(pkt->next) > netif->ipv4.mtu) {
        DEBUG("ipv4: packet too big\n");
        //gnrc_icmpv4_error_pkt_too_big_send(netif->ipv4.mtu, pkt);
        gnrc_pktbuf_release_error(pkt, EMSGSIZE);
        return;
    }*/
    DEBUG("ipv4: Sending (src = %s, ",
          ipv4_addr_to_str(addr_str, &hdr->src, sizeof(addr_str)));
    DEBUG("dst = %s, next header = %u, length = %u)\n",
          ipv4_addr_to_str(addr_str, &hdr->dst, sizeof(addr_str)), hdr->protocol,
          byteorder_ntohs(hdr->tl));

    if (gnrc_netapi_send(netif->pid, pkt) < 1) {
        DEBUG("ipv4: unable to send packet\n");
        gnrc_pktbuf_release(pkt);
    }
}

static gnrc_pktsnip_t *_create_netif_hdr(uint8_t *dst_l2addr,
                                         unsigned dst_l2addr_len,
                                         gnrc_pktsnip_t *pkt,
                                         uint8_t flags)
{
    gnrc_pktsnip_t *netif_hdr = gnrc_netif_hdr_build(NULL, 0, dst_l2addr, dst_l2addr_len);
    gnrc_netif_hdr_t *hdr;

    if (netif_hdr == NULL) {
        DEBUG("ipv4: error on interface header allocation, dropping packet\n");
        gnrc_pktbuf_release(pkt);
        return NULL;
    }
    hdr = netif_hdr->data;
    /* previous netif header might have been allocated by some higher layer
     * to provide some flags (provided to us via netif_flags). */
    hdr->flags = flags;

    /* add netif_hdr to front of the pkt list */
    LL_PREPEND(pkt, netif_hdr);

    return pkt;
}

typedef struct {
    /**
     * @brief   Neighbor's link-layer address
     */
    uint8_t l2addr[6];
    /**
     * @brief   Neighbor information as defined in
     *          @ref net_gnrc_ipv6_nib_nc_info "info values"
     */
    uint16_t info;
    uint8_t l2addr_len;     /**< Length of gnrc_ipv6_nib_nc_t::l2addr in bytes */
} gnrc_ipv6_nib_nc_t;

static void _send_unicast(gnrc_pktsnip_t *pkt, bool prep_hdr,
                          gnrc_netif_t *netif, ipv4_hdr_t *ipv4_hdr,
                          uint8_t netif_hdr_flags)
{
    gnrc_ipv4_nib_nc_t nce;

    nce.l2addr[0] = 0x00;
    nce.l2addr[1] = 0x01;
    nce.l2addr[2] = 0x02;
    nce.l2addr[3] = 0x03;
    nce.l2addr[4] = 0x04;
    nce.l2addr[5] = 0x05;
    nce.l2addr[6] = 0x06;
    nce.l2addr[7] = 0x07;
    nce.l2addr_len = 8;

    DEBUG("ipv4: send unicast\n");
#if 0
    if (gnrc_ipv4_nib_get_next_hop_l2addr(&ipv4_hdr->dst, netif, pkt,
                                          &nce) < 0) {
        /* packet is released by NIB */
        DEBUG("ipv4: no link-layer address or interface for next hop to %s",
              ipv4_addr_to_str(addr_str, &ipv4_hdr->dst, sizeof(addr_str)));
        return;
    }

    netif = gnrc_netif_get_by_pid(gnrc_ipv4_nib_nc_get_iface(&nce));
    assert(netif != NULL);
#endif
    if (_safe_fill_ipv4_hdr(netif, pkt, prep_hdr)) {
        DEBUG("ipv4: add interface header to packet\n");
        if ((pkt = _create_netif_hdr(nce.l2addr, nce.l2addr_len, pkt,
                                     netif_hdr_flags)) == NULL) {
            return;
        }

        DEBUG("ipv4: send unicast over interface %" PRIkernel_pid "\n",
              netif->pid);

        /* and send to interface */
#ifdef MODULE_NETSTATS_IPV4
        netif->ipv4.stats.tx_unicast_count++;
#endif
        _send_to_iface(netif, pkt);
    }
}

static void _send(gnrc_pktsnip_t *pkt, bool prep_hdr)
{
    gnrc_netif_t *netif = NULL;
    gnrc_pktsnip_t *tmp_pkt;
    ipv4_hdr_t *ipv4_hdr;
    uint8_t netif_hdr_flags = 0U;

    /* get IPv4 snip and (if present) generic interface header */
    if (pkt->type == GNRC_NETTYPE_NETIF) {
        /* If there is already a netif header (routing protocols and
         * neighbor discovery might add them to preset sending interface or
         * higher layers wants to provide flags to the interface ) */
        const gnrc_netif_hdr_t *netif_hdr = pkt->data;

        netif = gnrc_netif_hdr_get_netif(pkt->data);
        /* discard broadcast and multicast flags because those could be
         * potentially wrong (dst is later checked to assure that multicast is
         * set if dst is a multicast address) */
        netif_hdr_flags = netif_hdr->flags &
                          ~(GNRC_NETIF_HDR_FLAGS_BROADCAST |
                            GNRC_NETIF_HDR_FLAGS_MULTICAST);

        tmp_pkt = gnrc_pktbuf_start_write(pkt);
        if (tmp_pkt == NULL) {
            DEBUG("ipv4: unable to get write access to netif header, dropping packet\n");
            gnrc_pktbuf_release(pkt);
            return;
        }
        /* discard to avoid complex checks for correctness (will be re-added
         * with correct addresses anyway as for the case were there is no
         * netif header provided)
         * Also re-establish temporary pointer used for write protection as
         * actual pointer */
        pkt = gnrc_pktbuf_remove_snip(tmp_pkt, tmp_pkt);
    }

    // Ensure is IPv4
    if (pkt->type != GNRC_NETTYPE_IPV4) {
        DEBUG("ipv4: unexpected packet type\n");
        gnrc_pktbuf_release_error(pkt, EINVAL);
        return;
    }

    // Ensure is a dst IP is set
    if (ipv4_addr_is_unspecified(&((ipv4_hdr_t *)pkt->data)->dst)) {
        DEBUG("ipv4: destination address is unspecified address (0.0.0.0), "
              "dropping packet \n");
        gnrc_pktbuf_release_error(pkt, EINVAL);
        return;
    }

    tmp_pkt = gnrc_pktbuf_start_write(pkt);
    if (tmp_pkt == NULL) {
        DEBUG("ipv4: unable to get write access to IPv4 header, dropping packet\n");
        gnrc_pktbuf_release(pkt);
        return;
    }
    pkt = tmp_pkt;

    ipv4_hdr = pkt->data;

    if (ipv4_addr_is_multicast(&ipv4_hdr->dst)) {
        _send_multicast(pkt, prep_hdr, netif, netif_hdr_flags);
    }
    else {
        gnrc_netif_t *tmp_netif = gnrc_netif_get_by_ipv4_addr(&ipv4_hdr->dst);

        if (ipv4_addr_is_loopback(&ipv4_hdr->dst) ||    /* dst is loopback address */
            /* or dst registered to a local interface */
            (tmp_netif != NULL)) {
            _send_to_self(pkt, prep_hdr, tmp_netif);
        }
        else {
            _send_unicast(pkt, prep_hdr, netif, ipv4_hdr, netif_hdr_flags);
        }
    }
}

/** @} */
