#include <stdlib.h>
#include <string.h>
#include <net/ethernet.h>
#include <net/if_arp.h>
#include <arpa/inet.h>
#include <netinet/ip.h>
#include <netinet/udp.h>
#include <netinet/tcp.h>
#include "callback.h"
#include "display.h"



void my_callback(u_char * args, const struct pcap_pkthdr * header, const u_char * packet)
{
    (void)header;
    
    static long pktcount = 0;
    pktcount++;
    
    int verbose = atoi((char *)args);
    const struct ether_header * eth_hdr;
    const struct ether_arp * arp;
    const struct iphdr * ip_hdr;
    const struct udphdr * udp_hdr;
    const struct tcphdr * tcp_hdr;
    
    eth_hdr = (const struct ether_header *)&packet[0];
    
    printf("#%ld\n", pktcount);
    
    /***************** affichage des infos de niveau LIAISON ******************/
    if (header->caplen < sizeof(struct ether_header) || ntohs(eth_hdr->ether_type) < 0x600)
    {
        printf("                     Protocole non pris en charge\n");
        printf("********************************************************************************\n");
        printf("********************************************************************************\n");
        return;
    }
    
    // Ethernet
    display_ethernet(eth_hdr, verbose);
    
    /****************** affichage des infos de niveau RESEAU ******************/
    if (ntohs(eth_hdr->ether_type) != 0x806 && ntohs(eth_hdr->ether_type) != 0x800)
    {
        printf("\n--------------------------------------------------------------------------------\n");
        printf("                  Protocole superieur non pris en charge\n");
    }
    
    // ARP
    if (ntohs(eth_hdr->ether_type) == 0x806)
    {
        arp = (const struct ether_arp *)&packet[sizeof(struct ether_header)];
        
        display_arp(arp, verbose);
    }
    
    // IPv4
    if (ntohs(eth_hdr->ether_type) == 0x800)
    {
        ip_hdr = (const struct iphdr *)&packet[sizeof(struct ether_header)];
        
        display_ipv4(ip_hdr, verbose);
        
        /************** affichage des infos de niveau TRANSPORT ***************/
        if (ip_hdr->protocol != 0x06 && ip_hdr->protocol != 0x11)
        {
            printf("\n--------------------------------------------------------------------------------\n");
            printf("                  Protocole superieur non pris en charge\n");
        }
        
        // TCP
        if (ip_hdr->protocol == 0x06)
        {
            tcp_hdr = (const struct tcphdr *)&packet[sizeof(struct ether_header)+4*ip_hdr->ihl];
            
            display_tcp(tcp_hdr, verbose);
            
            /************ affichage des infos de niveau APPLICATIF ************/
            if (ntohs(tcp_hdr->source) != 23 && ntohs(tcp_hdr->dest) != 23 &&
                ntohs(tcp_hdr->source) != 80 && ntohs(tcp_hdr->dest) != 80 &&
                ntohs(tcp_hdr->source) != 25 && ntohs(tcp_hdr->dest) != 25 &&
                ntohs(tcp_hdr->source) != 143 && ntohs(tcp_hdr->dest) != 143 &&
                ntohs(tcp_hdr->source) != 110 && ntohs(tcp_hdr->dest) != 110 &&
                ntohs(tcp_hdr->source) != 20 && ntohs(tcp_hdr->dest) != 20 &&
                ntohs(tcp_hdr->source) != 21 && ntohs(tcp_hdr->dest) != 21 &&
                ntohs(tcp_hdr->source) != 53 && ntohs(tcp_hdr->dest) != 53)
            {
                printf("\n--------------------------------------------------------------------------------\n");
                printf("                  Protocole superieur non pris en charge");
                
                if (ntohs(tcp_hdr->source) == 443 || ntohs(tcp_hdr->dest) == 443)
                    printf(" (HTTPS)");
                
                printf("\n");
                
            }
            
            // Telnet
            if (ntohs(tcp_hdr->source) == 23 || ntohs(tcp_hdr->dest) == 23)
                display_telnet(&packet[sizeof(struct ether_header)+4*ip_hdr->ihl+4*tcp_hdr->doff], header->caplen-(sizeof(struct ether_header)+4*ip_hdr->ihl+4*tcp_hdr->doff), verbose);
            
            // HTTP
            if (ntohs(tcp_hdr->source) == 80 || ntohs(tcp_hdr->dest) == 80)
                display_http(&packet[sizeof(struct ether_header)+4*ip_hdr->ihl+4*tcp_hdr->doff], header->caplen-(sizeof(struct ether_header)+4*ip_hdr->ihl+4*tcp_hdr->doff), verbose);
            
            // SMTP
            if (ntohs(tcp_hdr->source) == 25 || ntohs(tcp_hdr->dest) == 25)
                display_smtp(&packet[sizeof(struct ether_header)+4*ip_hdr->ihl+4*tcp_hdr->doff], header->caplen-(sizeof(struct ether_header)+4*ip_hdr->ihl+4*tcp_hdr->doff), verbose);
            
            // IMAP
            if (ntohs(tcp_hdr->source) == 143 || ntohs(tcp_hdr->dest) == 143)
                display_imap(&packet[sizeof(struct ether_header)+4*ip_hdr->ihl+4*tcp_hdr->doff], header->caplen-(sizeof(struct ether_header)+4*ip_hdr->ihl+4*tcp_hdr->doff), verbose);
            
            // POP3
            if (ntohs(tcp_hdr->source) == 110 || ntohs(tcp_hdr->dest) == 110)
                display_pop3(&packet[sizeof(struct ether_header)+4*ip_hdr->ihl+4*tcp_hdr->doff], header->caplen-(sizeof(struct ether_header)+4*ip_hdr->ihl+4*tcp_hdr->doff), verbose);
            
            // FTP data
            if (ntohs(tcp_hdr->source) == 20 || ntohs(tcp_hdr->dest) == 20)
                display_ftpdata(&packet[sizeof(struct ether_header)+4*ip_hdr->ihl+4*tcp_hdr->doff], header->caplen-(sizeof(struct ether_header)+4*ip_hdr->ihl+4*tcp_hdr->doff), verbose);
            
            // FTP controle
            if (ntohs(tcp_hdr->source) == 21 || ntohs(tcp_hdr->dest) == 21)
                display_ftpcontrol(&packet[sizeof(struct ether_header)+4*ip_hdr->ihl+4*tcp_hdr->doff], header->caplen-(sizeof(struct ether_header)+4*ip_hdr->ihl+4*tcp_hdr->doff), verbose);
            
            // DNS
            if (ntohs(tcp_hdr->source) == 53 || ntohs(tcp_hdr->dest) == 53)
                display_dns(&packet[sizeof(struct ether_header)+4*ip_hdr->ihl+4*tcp_hdr->doff], header->caplen-(sizeof(struct ether_header)+4*ip_hdr->ihl+4*tcp_hdr->doff), verbose, 1);
        }
        
        // UDP
        if (ip_hdr->protocol == 0x11)
        {
            udp_hdr = (const struct udphdr *)&packet[sizeof(struct ether_header)+4*ip_hdr->ihl];
            
            display_udp(udp_hdr, verbose);
            
            /************ affichage des infos de niveau APPLICATIF ************/
            if (ntohs(udp_hdr->source) != 67 && ntohs(udp_hdr->dest) != 67 &&
                ntohs(udp_hdr->source) != 68 && ntohs(udp_hdr->dest) != 68 &&
                ntohs(udp_hdr->source) != 53 && ntohs(udp_hdr->dest) != 53)
            {
                printf("\n--------------------------------------------------------------------------------\n");
                printf("                  Protocole superieur non pris en charge\n");
            }
            
            // BOOTP/DHCP
            if (ntohs(udp_hdr->source) == 67 || ntohs(udp_hdr->dest) == 67 ||
                ntohs(udp_hdr->source) == 68 || ntohs(udp_hdr->dest) == 68)
                display_bootp(&packet[sizeof(struct ether_header)+4*ip_hdr->ihl+8], header->caplen-(sizeof(struct ether_header)+4*ip_hdr->ihl+8), verbose);
            
            // DNS
            if (ntohs(udp_hdr->source) == 53 || ntohs(udp_hdr->dest) == 53)
                display_dns(&packet[sizeof(struct ether_header)+4*ip_hdr->ihl+8], header->caplen-(sizeof(struct ether_header)+4*ip_hdr->ihl+8), verbose, 0);
        }
    }
    
    printf("********************************************************************************\n");
    printf("********************************************************************************\n");
    
    return;
}

