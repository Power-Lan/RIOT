/*
 * Copyright (C) 2015 Martine Lenders <mlenders@inf.fu-berlin.de>
 *
 * This file is subject to the terms and conditions of the GNU Lesser General
 * Public License v2.1. See the file LICENSE in the top level directory for
 * more details.
 */

/**
 * @ingroup     net_gnrc_icmpv4
 * @{
 *
 * @file
 *
 * @author      Martine Lenders <mlenders@inf.fu-berlin.de>
 */

#include <errno.h>
#include <inttypes.h>
#include <stdlib.h>

#include "byteorder.h"
#include "net/ipv4/hdr.h"
#include "net/gnrc.h"
#include "net/protnum.h"
#include "od.h"
#include "utlist.h"

#include "net/gnrc/icmpv4.h"
#include "net/gnrc/icmpv4/echo.h"

#define ENABLE_DEBUG    (1)
#include "debug.h"

static inline uint16_t _calc_csum(gnrc_pktsnip_t *hdr,
                                  gnrc_pktsnip_t *pseudo_hdr,
                                  gnrc_pktsnip_t *payload)
{
    uint16_t csum = 0;
    uint16_t len = (uint16_t)hdr->size;

    while (payload && (payload != hdr)) {
        csum = inet_csum_slice(csum, payload->data, payload->size, len);
        len += (uint16_t)payload->size;
        payload = payload->next;
    }

    csum = inet_csum(csum, hdr->data, hdr->size);

    return ~csum;
}

void gnrc_icmpv4_demux(gnrc_netif_t *netif, gnrc_pktsnip_t *pkt)
{
    gnrc_pktsnip_t *icmpv4, *ipv4;
    icmpv4_hdr_t *hdr;

    icmpv4 = gnrc_pktsnip_search_type(pkt, GNRC_NETTYPE_ICMPV4);
    assert(icmpv4 != NULL);

    /* there can be extension headers between IPv4 and ICMPv4 header so we have
     * to search it */
    ipv4 = gnrc_pktsnip_search_type(icmpv4, GNRC_NETTYPE_IPV4);
    assert(ipv4 != NULL);

    if (icmpv4->size < sizeof(icmpv4_hdr_t)) {
        DEBUG("icmpv4: packet too short.\n");
        gnrc_pktbuf_release(pkt);
        return;
    }
    DEBUG("icmpv4: size:%d\n", icmpv4->size);

    /* Resize pkt using realsize of icmp payload */
    /* TODO fix this icmpv4->size=20 and it's wrong   */
    /*if (icmpv4->size < pkt->size) {
        gnrc_pktbuf_realloc_data(pkt, icmpv4->size);
    }*/

    /* Note: size will be checked again in packet handlers */

    hdr = (icmpv4_hdr_t *)icmpv4->data;

    /* TODO Verify icmp checksum */
   /* if (_calc_csum(icmpv4, ipv4, pkt)) {
        DEBUG("icmpv4: wrong checksum.\n");
        gnrc_pktbuf_release(pkt);
        return;
    }*/
ipv4_hdr_t * ipv4_hdr = (ipv4_hdr_t *) ipv4->data;
    switch (hdr->type) {
        /* TODO: handle ICMPv4 errors */
#ifdef MODULE_GNRC_ICMPV4_ECHO
        case ICMPV4_ECHO_REQ:
            DEBUG("icmpv4: handle echo request.\n");
            gnrc_icmpv4_echo_req_handle(netif, ipv4_hdr, (icmpv4_echo_t *)hdr, byteorder_ntohs(ipv4_hdr->tl) -sizeof(ipv4_hdr_t) -8 + sizeof(icmpv4_echo_t));
            break;
#endif

        default:
            DEBUG("icmpv4: unknown type field %u\n", hdr->type);
            (void)netif;
            break;
    }

    /* ICMPv4-all will be send in gnrc_ipv4.c so only dispatch of subtypes is
     * needed */
    if (!gnrc_netapi_dispatch_receive(GNRC_NETTYPE_ICMPV4, hdr->type, pkt)) {
        DEBUG("icmpv4: no one interested in type %d\n", hdr->type);
        gnrc_pktbuf_release(pkt);
    }
}

gnrc_pktsnip_t *gnrc_icmpv4_build(gnrc_pktsnip_t *next, uint8_t type,
                                  uint8_t code, size_t size)
{
    gnrc_pktsnip_t *pkt;
    icmpv4_hdr_t *icmpv4;

    if ((pkt = gnrc_pktbuf_add(next, NULL, size, GNRC_NETTYPE_ICMPV4)) == NULL) {
        DEBUG("icmpv4: no space left in packet buffer\n");
        return NULL;
    }

    DEBUG("icmpv4: Building ICMPv4 message with type=%u, code=%u\n",
          type, code);
    icmpv4 = (icmpv4_hdr_t *)pkt->data;
    icmpv4->type = type;
    icmpv4->code = code;
    icmpv4->csum.u16 = 0;

    return pkt;
}

int gnrc_icmpv4_calc_csum(gnrc_pktsnip_t *hdr, gnrc_pktsnip_t *pseudo_hdr)
{
    uint32_t csum = 0;

    if (hdr == NULL) {
        return -EFAULT;
    }
    if (hdr->type != GNRC_NETTYPE_ICMPV4) {
        return -EBADMSG;
    }

    csum = _calc_csum(hdr, pseudo_hdr, hdr->next);
    DEBUG("icmpv4: checksum is %x\n", csum);
    if (csum == 0) {
        return -ENOENT;
    }

    ((icmpv4_hdr_t *)hdr->data)->csum = byteorder_htons(csum);

    return 0;
}

/**
 * @}
 */
