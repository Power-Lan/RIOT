/*
 * Copyright (C) 2015 Inria
 *
 * This file is subject to the terms and conditions of the GNU Lesser
 * General Public License v2.1. See the file LICENSE in the top level
 * directory for more details.
 */

/**
 * @ingroup     examples
 * @{
 *
 * @file
 * @brief       Showing minimum memory footprint of gnrc network stack
 *
 * @author      Oliver Hahm <oliver.hahm@inria.fr>
 *
 * @}
 */

#include <stdio.h>

#include "msg.h"
#include "net/ipv4/addr.h"
#include "net/gnrc.h"
#include "net/gnrc/netif.h"
#include "shell.h"


#define MAIN_QUEUE_SIZE     (8)
static msg_t _main_msg_queue[MAIN_QUEUE_SIZE];

extern int udp_cmd(int argc, char **argv);
//extern int _gnrc_icmpv6_ping(int argc, char **argv);

static const shell_command_t shell_commands[] = {
    { "udp", "send data over UDP and listen on UDP ports", udp_cmd },
    //{ "ping6", "Ping via ICMPv6", _icmpv6_ping },
    { NULL, NULL, NULL }
};

int main(void)
{

    puts("RIOT network stack example application");

    /* get interfaces and print their addresses */
    gnrc_netif_t *netif = NULL;
    netif = gnrc_netif_iter(netif);
        ipv4_addr_t ipv4_addrs[GNRC_NETIF_IPV4_ADDRS_NUMOF];
        int res = gnrc_netapi_get(netif->pid, NETOPT_IPV4_ADDR, 0, ipv4_addrs,
                                  sizeof(ipv4_addrs));

        if (res < 0) {
            
        } else {
        for (unsigned i = 0; i < (unsigned)(res / sizeof(ipv4_addr_t)); i++) {
            //char ipv4_addr[IPV4_ADDR_MAX_STR_LEN];

            //ipv4_addr = ipv4_addr_to_str(ipv4_addr, &ipv4_addrs[i], IPV4_ADDR_MAX_STR_LEN);
            //printf("My address is %s\n", ipv4_addr_to_str(ipv4_addr, &ipv4_addrs[i], IPV4_ADDR_MAX_STR_LEN));
        }
	}




    /* we need a message queue for the thread running the shell in order to
     * receive potentially fast incoming networking packets */
    msg_init_queue(_main_msg_queue, MAIN_QUEUE_SIZE);
    puts("RIOT network stack example application");

    /* start shell */
    puts("All up, running the shell now");
    char line_buf[SHELL_DEFAULT_BUFSIZE];
    shell_run(shell_commands, line_buf, SHELL_DEFAULT_BUFSIZE);

    /* should be never reached */
    return 0;
}
