#include <queue.h>
#include "skel.h"

int main(int argc, char *argv[]) {
	packet m;
	int rc;

	init(argc - 2, argv + 2);

	route_table_entry *table_router = malloc(MAX_ENTRIES_RTABLE * sizeof(route_table_entry));
	int length = parse_table_router(argv[1], table_router);
	sort_table_router(length, table_router);

	int dim_arp_table = 0;
	arp_entry *arp_table = malloc(MAX_ENTRIES_ARPTABLE * sizeof(arp_entry));

	queue delayed_packets = queue_create();
	
	while (1) {
		/* receive the packet */
		rc = get_packet(&m);
		DIE(rc < 0, "get_message");

		struct ether_header *eth_hdr = (struct ether_header *) m.payload;
		struct arp_header *arp_hdr = parse_arp(eth_hdr);

		/* if the packet is ARP type */ 
		if (arp_hdr) {
			/* if the packet is ARP request */
			if (ntohs(arp_hdr->op) == ARPOP_REQUEST) {
				send_arp_reply(m, eth_hdr, arp_hdr);
			/* If the packet is ARP REPLY */
			} else {
				if (!queue_empty(delayed_packets)) {
					/* dequeue the packet from queue */
					packet *first_packet = (packet *) queue_deq(delayed_packets);
					struct iphdr *ip_hdr = (struct iphdr *) (first_packet->payload + sizeof(struct ether_header));
					struct ether_header *first_eth_hdr = (struct ether_header *) first_packet->payload;

					/* add the arp_table entry */
					dim_arp_table = update_arp_table(dim_arp_table, arp_table, arp_hdr, ip_hdr);
					
					/* find best_route for this packet */
					struct route_table_entry *best_route = get_best_route(ip_hdr->daddr, length, table_router);

					/* change the mac addresses + forward */
					get_interface_mac(best_route->interface, first_eth_hdr->ether_shost);
					memcpy(first_eth_hdr->ether_dhost, arp_hdr->sha, sizeof(arp_hdr->sha));
					first_packet->interface = best_route->interface;

					send_packet(best_route->interface, first_packet);
				}
			}
		} else {
			struct icmphdr *icmp_hdr = parse_icmp(eth_hdr);
			struct iphdr *ip_hdr = (struct iphdr *) (m.payload + sizeof(struct ether_header));
			
			/* if the packet is for the router */
			if (inet_addr(get_interface_ip(m.interface)) == ip_hdr->daddr) {
				/* if the packet is icmp echo */
				if (icmp_hdr && icmp_hdr->type == ICMP_ECHO) {
					send_icmp(ip_hdr->saddr, ip_hdr->daddr, eth_hdr->ether_dhost, eth_hdr->ether_shost, 0, 0, m.interface, icmp_hdr->un.echo.id, icmp_hdr->un.echo.sequence);
				}
				
				/* drop the packet */
				continue;
			}

			/* check the time limit exceeded condition */
			if (ip_hdr->ttl <= 1) {
				send_icmp_error(ip_hdr->saddr, inet_addr(get_interface_ip(m.interface)), eth_hdr->ether_dhost,
				eth_hdr->ether_shost, ICMP_TIME_EXCEEDED, 0, m.interface);
				continue;
			}

			/* check if checksum is correct */
			if (ip_checksum(ip_hdr, sizeof(struct iphdr))) {
				continue;
			}

			/* update ttl and checksum of ip_hdr */
			update_ttl_and_checksum(ip_hdr);
			
			/* find best route */
			struct route_table_entry *best_route = get_best_route(ip_hdr->daddr, length, table_router);
			
			/* send destination unreachable message if there is no route */
			if (!best_route) {
				send_icmp_error(ip_hdr->saddr, inet_addr(get_interface_ip(m.interface)), eth_hdr->ether_dhost, eth_hdr->ether_shost, 3, 0, m.interface);
				continue;
			}

			/* find the arp_entry with the next_hop ip address */
			arp_entry *entry = get_arp_entry(best_route->next_hop, dim_arp_table, arp_table);

			/* if there is no correct entry in arp_table */
			if (!entry) {
				/* enqueue the packet */
				packet *copy_m = malloc(sizeof(packet));
				memcpy(copy_m, &m, sizeof(packet));
				queue_enq(delayed_packets, copy_m);

				/* update the fields from ether_header */
				int res = hwaddr_aton("ff:ff:ff:ff:ff:ff", eth_hdr->ether_dhost);
				DIE(res == -1, "hwaddr_aton");
				get_interface_mac(best_route->interface, eth_hdr->ether_shost);
				eth_hdr->ether_type = htons(ETHERTYPE_ARP);
				
				/* send arp request */
				send_arp(best_route->next_hop, inet_addr(get_interface_ip(best_route->interface)), eth_hdr, best_route->interface, htons(ARPOP_REQUEST)); // request;
				continue;
			}

			/* change the mac addresses + forward */
			get_interface_mac(best_route->interface, eth_hdr->ether_shost);
			memcpy(eth_hdr->ether_dhost, entry->mac, sizeof(entry->mac));

			send_packet(best_route->interface, &m);
		}
	}
}
