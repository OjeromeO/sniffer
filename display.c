#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <arpa/inet.h>
#include <net/ethernet.h>
#include <net/if_arp.h>
#include <netinet/if_ether.h>
#include <netinet/ip.h>
#include <netinet/udp.h>
#include <netinet/tcp.h>
#include "display.h"
#include "bootp.h"
#include "dns.h"

/*TODO
- verifier checksum correct ou non
http://www.frameip.com/entete-udp/#3.4_-_Checksum
- options ip
- options tcp
- X acquitte Y
- completer DNS
*/

void display_ethernet(const struct ether_header * eth_hdr, int verbose)
{
    int i = 0;
    
    if (!(verbose >= 1 && verbose <= 3))
        verbose = 1;
    
    printf("----------------------------------Ethernet------------------------------------\n");
    
    if (verbose == 1)
    {
        printf("%.2x", eth_hdr->ether_dhost[0]);
        for(i=1;i<ETH_ALEN;i++)
            printf(":%.2x", eth_hdr->ether_dhost[i]);
        
        printf(" -> ");
        
        printf("%.2x", eth_hdr->ether_shost[0]);
        for(i=1;i<ETH_ALEN;i++)
            printf(":%.2x", eth_hdr->ether_shost[i]);
        
        printf("\n");
    }
    
    if (verbose == 2 || verbose == 3)
    {
        printf("%.2x", eth_hdr->ether_dhost[0]);
        for(i=1;i<ETH_ALEN;i++)
            printf(":%.2x", eth_hdr->ether_dhost[i]);
            
        printf(" -> ");
        
        printf("%.2x", eth_hdr->ether_shost[0]);
        for(i=1;i<ETH_ALEN;i++)
            printf(":%.2x", eth_hdr->ether_shost[i]);
        
        printf(", ether_type: %x", ntohs(eth_hdr->ether_type));
        if (ntohs(eth_hdr->ether_type) == 0x800) printf(" (IPv4)");
        if (ntohs(eth_hdr->ether_type) == 0x806) printf(" (ARP)");
        if (ntohs(eth_hdr->ether_type) == 0x8035) printf(" (RARP)");
        if (ntohs(eth_hdr->ether_type) == 0x86DD) printf(" (IPv6)");
        if (ntohs(eth_hdr->ether_type) == 0x8863) printf(" (PPPoE)");
        if (ntohs(eth_hdr->ether_type) == 0x8864) printf(" (PPPoE)");
        printf("\n");
    }
}



void display_arp(const struct ether_arp * arp, int verbose)
{
    int i = 0;
    
    if (!(verbose >= 1 && verbose <= 3))
        verbose = 1;
    
    printf("\n----------------------------------ARP---------------------------------\n");
    if (verbose == 1)
    {
        if (ntohs(arp->ea_hdr.ar_op) == 1)
        {
            printf("requete: qui est ");
            printf("%d.%d.%d.%d ?\n", arp->arp_tpa[0], arp->arp_tpa[1],
                                   arp->arp_tpa[2], arp->arp_tpa[3]);
        }
        
        if (ntohs(arp->ea_hdr.ar_op) == 2)
        {
            printf("reponse: ");
            printf("%d.%d.%d.%d ", arp->arp_tpa[0], arp->arp_tpa[1],
                                   arp->arp_tpa[2], arp->arp_tpa[3]);
            
            printf("est a ");
            printf("%.2x", arp->arp_tha[0]);
            for(i=1;i<ETH_ALEN;i++)
                printf(":%.2x", arp->arp_tha[i]);
            
            printf("\n");
        }
    }
    
    if (verbose == 2)
    {
        printf("opcode: %x", ntohs(arp->ea_hdr.ar_op));
        if (ntohs(arp->ea_hdr.ar_op) == 1)
            printf(" (requete)\n");
        else
            printf(" (reponse)\n");
        
        printf("@ materielle emetteur: ");
        printf("%.2x", arp->arp_sha[0]);
        for(i=1;i<ETH_ALEN;i++)
            printf(":%.2x", arp->arp_sha[i]);
        
        printf("\n@ IP emetteur: ");
        printf("%d.%d.%d.%d ", arp->arp_spa[0], arp->arp_spa[1],
                               arp->arp_spa[2], arp->arp_spa[3]);
        
        printf("\n@ materielle cible: ");
        printf("%.2x", arp->arp_tha[0]);
        for(i=1;i<ETH_ALEN;i++)
            printf(":%.2x", arp->arp_tha[i]);
        
        printf("\n@ IP cible: ");
        printf("%d.%d.%d.%d \n", arp->arp_tpa[0], arp->arp_tpa[1],
                                 arp->arp_tpa[2], arp->arp_tpa[3]);
    }
    
    if (verbose == 3)
    {
        printf("format @ materielle: %x\n", ntohs(arp->ea_hdr.ar_hrd));
        printf("format @ protocole: %x\n", ntohs(arp->ea_hdr.ar_pro));
        printf("taille @ materielle: %x\n", arp->ea_hdr.ar_hln);
        printf("taille @ protocole: %x\n", arp->ea_hdr.ar_pln);
        
        printf("opcode: %x", ntohs(arp->ea_hdr.ar_op));
        if (ntohs(arp->ea_hdr.ar_op) == 1)
            printf(" (requete)\n");
        else
            printf(" (reponse)\n");
        
        printf("@ materielle emetteur: ");
        printf("%.2x", arp->arp_sha[0]);
        for(i=1;i<ETH_ALEN;i++)
            printf(":%.2x", arp->arp_sha[i]);
        
        printf("\n@ IP emetteur: ");
        printf("%d.%d.%d.%d ", arp->arp_spa[0], arp->arp_spa[1],
                               arp->arp_spa[2], arp->arp_spa[3]);
        
        printf("\n@ materielle cible: ");
        printf("%.2x", arp->arp_tha[0]);
        for(i=1;i<ETH_ALEN;i++)
            printf(":%.2x", arp->arp_tha[i]);
        
        printf("\n@ IP cible: ");
        printf("%d.%d.%d.%d \n", arp->arp_tpa[0], arp->arp_tpa[1],
                                 arp->arp_tpa[2], arp->arp_tpa[3]);
    }
}



void display_ipv4(const struct iphdr * ip_hdr, int verbose)
{
    if (!(verbose >= 1 && verbose <= 3))
        verbose = 1;
    
    unsigned char ipsrc[4];
    ipsrc[0] = (ip_hdr->saddr & 0xFF000000) >> 24;
    ipsrc[1] = (ip_hdr->saddr & 0x00FF0000) >> 16;
    ipsrc[2] = (ip_hdr->saddr & 0x0000FF00) >> 8;
    ipsrc[3] = (ip_hdr->saddr & 0x000000FF);
    
    unsigned char ipdst[4];
    ipdst[0] = (ip_hdr->daddr & 0xFF000000) >> 24;
    ipdst[1] = (ip_hdr->daddr & 0x00FF0000) >> 16;
    ipdst[2] = (ip_hdr->daddr & 0x0000FF00) >> 8;
    ipdst[3] = (ip_hdr->daddr & 0x000000FF);
    
    printf("\n---------------------------------IPv4----------------------------------\n");
    
    if (verbose == 1)
    {
        printf("%d.%d.%d.%d", ipsrc[3], ipsrc[2], ipsrc[1], ipsrc[0]);
        printf(" -> ");
        printf("%d.%d.%d.%d\n", ipdst[3], ipdst[2], ipdst[1], ipdst[0]);
    }
    
    if (verbose == 2)
    {
        printf("%d.%d.%d.%d", ipsrc[3], ipsrc[2], ipsrc[1], ipsrc[0]);
        printf(" -> ");
        printf("%d.%d.%d.%d\n", ipdst[3], ipdst[2], ipdst[1], ipdst[0]);
        
        printf("protocole superieur: %x", ip_hdr->protocol);
        if (ip_hdr->protocol == 0x01) printf(" (ICMP)");
        if (ip_hdr->protocol == 0x02) printf(" (IGMP)");
        if (ip_hdr->protocol == 0x06) printf(" (TCP)");
        if (ip_hdr->protocol == 0x11) printf(" (UDP)");
        if (ip_hdr->protocol == 0x29) printf(" (IPv6)");
        if (ip_hdr->protocol == 0x38) printf(" (TLSP)");
        if (ip_hdr->protocol == 0x3A) printf(" (ICMPv6)");
        if (ip_hdr->protocol == 0x59) printf(" (OSPF)");
        if (ip_hdr->protocol == 0x84) printf(" (SCTP)");
        printf("\n");
        
        printf("taille header: %d octets\n", 4 * ip_hdr->ihl);
        printf("taille header+donnees: %d octets\n", ntohs(ip_hdr->tot_len));
        
        //TODO verifier checksum correct ou non
    }
    
    if (verbose == 3)
    {
        printf("%d.%d.%d.%d", ipsrc[3], ipsrc[2], ipsrc[1], ipsrc[0]);
        printf(" -> ");
        printf("%d.%d.%d.%d\n", ipdst[3], ipdst[2], ipdst[1], ipdst[0]);
        
        printf("version: %d\n", ip_hdr->version);
        printf("taille header: %d octets\n", 4 * ip_hdr->ihl);
        
        if ((ip_hdr->tos & 0xE0) >> 5 || (ip_hdr->tos & 0x10) >> 4 ||
            (ip_hdr->tos & 0x8) >> 3 || (ip_hdr->tos & 0x4) >> 2 ||
            (ip_hdr->tos & 0x2) >> 1)
        {
            printf("ToS:");
            
            if ((ip_hdr->tos & 0xE0) >> 5)
            {
                printf(" Priorite = %d ", (ip_hdr->tos & 0xE0) >> 5);
                if (((ip_hdr->tos & 0xE0) >> 5) == 1) printf("(Prioritaire)");
                if (((ip_hdr->tos & 0xE0) >> 5) == 2) printf("(Immediat)");
                if (((ip_hdr->tos & 0xE0) >> 5) == 3) printf("(Urgent)");
                if (((ip_hdr->tos & 0xE0) >> 5) == 4) printf("(Tres urgent)");
                if (((ip_hdr->tos & 0xE0) >> 5) == 5) printf("(Critique)");
                if (((ip_hdr->tos & 0xE0) >> 5) == 6) printf("(Supervision interconnexion)");
                if (((ip_hdr->tos & 0xE0) >> 5) == 7) printf("(Supervision réseau)");
            }
            
            printf("\n    ");
            
            if ((ip_hdr->tos & 0x10) >> 4)
                printf("Delai ");
            
            if ((ip_hdr->tos & 0x8) >> 3)
                printf("Debit ");
            
            if ((ip_hdr->tos & 0x4) >> 2)
                printf("Fiabilite ");
            
            if ((ip_hdr->tos & 0x2) >> 1)
                printf("Cout ");
            
            printf("\n");
        }
        
        printf("taille header+donnees: %d octets\n", ntohs(ip_hdr->tot_len));
        printf("identification: 0x%x\n", ntohs(ip_hdr->id));
        
    	if (ip_hdr->frag_off & 0x4000 || ip_hdr->frag_off & 0x2000)
    	{
            printf("Flags: ");
            if (ip_hdr->frag_off & 0x4000) printf("Don't Fragment ");
            if (ip_hdr->frag_off & 0x2000) printf("More Fragments ");
            printf("\n");
        }
        
        if (ip_hdr->frag_off & 0x2000)
            printf("offset du fragment: %d\n", ntohs(ip_hdr->frag_off & 0x1FFF));
        
        printf("TTL: %d\n", ip_hdr->ttl);
        
        printf("protocole superieur: %x", ip_hdr->protocol);
        if (ip_hdr->protocol == 0x01) printf(" (ICMP)");
        if (ip_hdr->protocol == 0x02) printf(" (IGMP)");
        if (ip_hdr->protocol == 0x06) printf(" (TCP)");
        if (ip_hdr->protocol == 0x11) printf(" (UDP)");
        if (ip_hdr->protocol == 0x29) printf(" (IPv6)");
        if (ip_hdr->protocol == 0x38) printf(" (TLSP)");
        if (ip_hdr->protocol == 0x3A) printf(" (ICMPv6)");
        if (ip_hdr->protocol == 0x59) printf(" (OSPF)");
        if (ip_hdr->protocol == 0x84) printf(" (SCTP)");
        printf("\n");
        
        //TODO verifier checksum correct ou non
        //TODO: options
    }
}



void display_udp(const struct udphdr * udp_hdr, int verbose)
{
    if (!(verbose >= 1 && verbose <= 3))
        verbose = 1;
    
    printf("\n-------------------------------UDP---------------------------------\n");
    
    if (verbose == 1)
    {
        printf("port %d", ntohs(udp_hdr->source));
        printf(" -> ");
        printf("port %d\n", ntohs(udp_hdr->dest));
    }
    
    if (verbose == 2 || verbose == 3)
    {
        printf("port %d", ntohs(udp_hdr->source));
        printf(" -> ");
        printf("port %d\n", ntohs(udp_hdr->dest));
        
        printf("taille header+donnees: %d octets\n", ntohs(udp_hdr->len));
        //TODO: verifier checksum correct ou non
    }
}



void display_tcp(const struct tcphdr * tcp_hdr, int verbose)
{
    if (!(verbose >= 1 && verbose <= 3))
        verbose = 1;
    
    printf("\n--------------------------------TCP--------------------------------\n");
    
    if (verbose == 1)
    {
        printf("port %d", ntohs(tcp_hdr->source));
        printf(" -> ");
        printf("port %d\n", ntohs(tcp_hdr->dest));
        
        // affiche les flags principaux s'il y en a
        if (tcp_hdr->syn || tcp_hdr->fin || tcp_hdr->ack)
        {
            printf("Flags: ");
            if (tcp_hdr->syn) printf("SYN ");
            if (tcp_hdr->fin) printf("FIN ");
            if (tcp_hdr->ack) printf("ACK ");
            printf("\n");
        }
        
        //TODO: (acquitte #X, ...)
    }
    
    if (verbose == 2)
    {
        printf("port %d", ntohs(tcp_hdr->source));
        printf(" -> ");
        printf("port %d\n", ntohs(tcp_hdr->dest));
        
        // affiche les flags principaux s'il y en a
        if (tcp_hdr->syn || tcp_hdr->fin || tcp_hdr->ack)
        {
            printf("Flags: ");
            if (tcp_hdr->syn) printf("SYN ");
            if (tcp_hdr->fin) printf("FIN ");
            if (tcp_hdr->ack) printf("ACK ");
            printf("\n");
        }
        
        printf("taille header tcp: %d octets\n", 4 * tcp_hdr->doff);
        printf("# sequence: %lu, ", (unsigned long)ntohl(tcp_hdr->seq));
        printf("# acquittement: %lu\n", (unsigned long)ntohl(tcp_hdr->ack_seq));
        
        //TODO: verifier checksum correct ou nn
    }
    
    if (verbose == 3)
    {
        printf("port %d", ntohs(tcp_hdr->source));
        printf(" -> ");
        printf("port %d\n", ntohs(tcp_hdr->dest));
        
        printf("# sequence: %lu, ", (unsigned long)ntohl(tcp_hdr->seq));
        printf("# acquittement: %lu\n", (unsigned long)ntohl(tcp_hdr->ack_seq));
        printf("taille header tcp: %d octets\n", 4 * tcp_hdr->doff);
        
        // affiche les flags principaux s'il y en a
        if (tcp_hdr->syn || tcp_hdr->fin || tcp_hdr->ack
           || tcp_hdr->psh || tcp_hdr->urg || tcp_hdr->rst)
        {
            printf("Flags: ");
            if (tcp_hdr->syn) printf("SYN ");
            if (tcp_hdr->fin) printf("FIN ");
            if (tcp_hdr->ack) printf("ACK ");
            if (tcp_hdr->psh) printf("PSH ");
            if (tcp_hdr->urg) printf("URG ");
            if (tcp_hdr->rst) printf("RST ");
            printf("\n");
        }
        
        printf("fenetre de reception de l'emetteur: %d octets\n", ntohs(tcp_hdr->window));
        
        //TODO: verifier checksum correct ou nn
        
        if (tcp_hdr->urg)
            printf("pointeur urgent: %d\n", ntohs(tcp_hdr->urg_ptr));
        
        //TODO: options
    }
}



void display_http(const u_char * httpdata, int len, int verbose)
{
    if (!(verbose >= 1 && verbose <= 3))
        verbose = 1;
    
    int i = 0;
    int j = 0;
    
    printf("\n------------------------------------HTTP----------------------------------\n");
    
    if (len == 0)
        return;
    
    if (verbose == 1)
    {
        // on a une requete ou une reponse
        if (strstr((const char *)httpdata, "HTTP/0.9\r\n") != NULL ||
            strstr((const char *)httpdata, "HTTP/1.0\r\n") != NULL ||
            strstr((const char *)httpdata, "HTTP/1.1\r\n") != NULL ||
            strstr((const char *)httpdata, "HTTP/1.2\r\n") != NULL ||
            strncmp((const char *)httpdata, "HTTP/0.9 ", 9) == 0 ||
            strncmp((const char *)httpdata, "HTTP/1.0 ", 9) == 0 ||
            strncmp((const char *)httpdata, "HTTP/1.1 ", 9) == 0 ||
            strncmp((const char *)httpdata, "HTTP/1.2 ", 9) == 0)
        {
            while (strncmp((const char *)&httpdata[i], "\r\n", 2) != 0 && i < len)
            {
                printf("%c", httpdata[i]);
                i++;
            }
            
            printf("\n");
        }
        else    // on n'a que des donnees
            printf("...donnees...\n");
    }
    
    if (verbose == 2)
    {
        // que des donnees
        if (strstr((const char *)httpdata, "\r\n\r\n") == NULL)
            printf("...donnees...\n");
        else    // reponse ou requete avec des donnees
        {
            while (strncmp((const char *)&httpdata[i], "\r\n\r\n", 4) != 0 && i < len)
            {
                printf("%c", httpdata[i]);
                i++;
            }
            
            printf("\n");
            
            if (i+4 < len)
                printf("...donnees...\n");
        }
    }
    
    if (verbose == 3)
    {
        // que des donnees
        if (strstr((const char *)httpdata, "\r\n\r\n") == NULL)
        {
            for(i=0;i<len;i++)
                printf(".");
            
            printf("\n");
        }
        else    // reponse ou requete avec des donnees
        {
            while (strncmp((const char *)&httpdata[i], "\r\n\r\n", 4) != 0 && i < len)
            {
                printf("%c", httpdata[i]);
                i++;
            }
            
            printf("\n");
            
            for(j=0;j < (len-i-4);j++)
                printf(".");
            
            printf("\n");
        }
    }
}



void display_smtp(const u_char * smtpdata, int len, int verbose)
{
    if (!(verbose >= 1 && verbose <= 3))
        verbose = 1;
    
    int i = 0;
    
    printf("\n-----------------------------------SMTP-----------------------------------\n");
    
    if (len == 0)
        return;
    
    if (verbose == 1)
    {
        // on a le paquet de contenu du mail
        if (strstr((const char *)smtpdata, "\r\n\r\n") != NULL)
            printf("...contenu du mail...\n");
        else
        {
            // on affiche jusqu'au premier \r\n (donc pas les options apres EHLO)
            while (strncmp((const char *)&smtpdata[i], "\r\n", 2) != 0 && i < len)
            {
                printf("%c", smtpdata[i]);
                i++;
            }
            
            printf("\n");
        }
    }
    
    if (verbose == 2)
    {
        // on a le paquet de contenu du mail
        if (strstr((const char *)smtpdata, "\r\n\r\n") != NULL)
            printf("...contenu du mail...\n");
        else
        {
            for(i=0;i<len;i++)
                printf("%c", smtpdata[i]);
        }
    }
    
    if (verbose == 3)
    {
        for(i=0;i<len;i++)
            printf("%c", smtpdata[i]);
    }
}



void display_imap(const u_char * imapdata, int len, int verbose)
{
    if (!(verbose >= 1 && verbose <= 3))
        verbose = 1;
    
    int i = 0;
    //char * statut = NULL;
    //char * s = NULL;
    //statut = malloc(len*sizeof(char));
    //memcpy(statut, imapdata, len);
    
    printf("\n---------------------------------IMAP-------------------------------------\n");
    
    if (len == 0)
        return;
    
    if (verbose == 1 || verbose == 2)
    {
        // si on a juste une ligne de statut
        if (strncmp((const char *)imapdata, "* ", 2) != 0)
        {
            for(i=0;i<len;i++)
                printf("%c", imapdata[i]);
        }
        else    // la ligne de statut est a la fin
        {
            /*
            // genere une segfault du au 2eme while et printf qui ne s'arrete jamais
            // (or même sans condition sur i, cela devrait s'arreter ???)
            
            s=strtok(statut, "\r\n");
            
            while (s != NULL)
            {
                if (strncmp((const char *)s, "* ", 2) != 0)
                {
                    // on affiche jusqu'au premier \r\n
                    while (strncmp((const char *)&s[i], "\r\n", 2) != 0)
                    {
                        printf("%c", s[i]);
                        i++;
                    }
                    
                    return;
                }
                
                s=strtok(NULL, "\r\n");
            }*/
            
            printf("...donnees...\n");
        }
    }
    
    if (verbose == 3)
    {
        for(i=0;i<len;i++)
            printf("%c", imapdata[i]);
    }
    
    //free(statut);
}



void display_pop3(const u_char * popdata, int len, int verbose)
{
    if (!(verbose >= 1 && verbose <= 3))
        verbose = 1;
    
    int i = 0;
    
    printf("\n-----------------------------------POP3-----------------------------------\n");
    
    if (len == 0)
        return;
    
    if (verbose == 1 || verbose == 2)
    {
        // on a un message ne contenant que des donnees ASCII
        if (strncmp((const char *)popdata, "+OK ", 4) != 0 &&
            strncmp((const char *)popdata, "-ERR ", 5) != 0)
            printf("...donnees...\n");
        else
        {
            // on affiche jusqu'au premier \r\n (donc pas les reponses multi-lignes)
            while (strncmp((const char *)&popdata[i], "\r\n", 2) != 0 && i < len)
            {
                printf("%c", popdata[i]);
                i++;
            }
            
            printf("\n");
        }
    }
    
    if (verbose == 3)
    {
        for(i=0;i<len;i++)
            printf("%c", popdata[i]);
    }
}



void display_ftpdata(const u_char * ftpdata, int len, int verbose)
{
    if (!(verbose >= 1 && verbose <= 3))
        verbose = 1;
    
    int i = 0;
    int isdata = 0;
    int testsize = (len > 10) ? 10 : len; // nombre d'octets sur lesquels on teste
                                          // la presence de non affichables
    
    printf("\n----------------------------------FTP-donnees------------------------------------\n");
    
    if (len == 0)
        return;
    
    if (verbose == 1 || verbose == 2)
        printf("...donnees...\n");
    
    if (verbose == 3)
    {
        // verifie si on a des donnees non affichables
        for(i=0;i<testsize;i++)
        {
            if (ftpdata[i] <= 0x9 ||
               (ftpdata[i] >= 0xB && ftpdata[i] <= 0xC) ||
               (ftpdata[i] >= 0xE && ftpdata[i] <= 0x1F) ||
               ftpdata[i] == 0x7F)
               isdata = 1;
        }
        
        for(i=0;i<len;i++)
            printf("%c", isdata ? '.' : ftpdata[i]);
        
        printf("\n");
    }
}



void display_ftpcontrol(const u_char * ftpcontrol, int len, int verbose)
{
    if (!(verbose >= 1 && verbose <= 3))
        verbose = 1;
    
    int i = 0;
    
    printf("\n----------------------------------FTP-controle------------------------------------\n");
    
    if (len == 0)
        return;
    
    if (verbose == 1 || verbose == 2)
    {
        // on affiche jusqu'au premier \r\n
        while (strncmp((const char *)&ftpcontrol[i], "\r\n", 2) != 0 && i < len)
        {
            printf("%c", ftpcontrol[i]);
            i++;
        }
        
        printf("\n");
    }
    
    if (verbose == 3)
    {
        for(i=0;i<len;i++)
            printf("%c", ftpcontrol[i]);
    }
}



void display_telnet(const u_char * telnetdata, int len, int verbose)
{
    if (!(verbose >= 1 && verbose <= 3))
        verbose = 1;
    
    int i = 0;
    int isdata = 0;
    int testsize = (len > 10) ? 10 : len; // nombre d'octets sur lesquels on teste
                                          // la presence de non affichables
    
    printf("\n-----------------------------------Telnet-----------------------------------\n");
    
    if (len == 0)
        return;
    
    if (verbose == 1 || verbose == 2)
    {
        if (telnetdata[0] == 0xFF)
            printf("...controle de la session...\n");
        else
            printf("...donnees...\n");
    }
    
    if (verbose == 3)
    {
        // verifie si on a des donnees non affichables
        for(i=0;i<testsize;i++)
        {
            if (telnetdata[i] <= 0x9 ||
               (telnetdata[i] >= 0xB && telnetdata[i] <= 0xC) ||
               (telnetdata[i] >= 0xE && telnetdata[i] <= 0x1F) ||
               telnetdata[i] == 0x7F)
               isdata = 1;
        }
        
        for(i=0;i<len;i++)
            printf("%c", isdata ? '.' : telnetdata[i]);
        
        printf("\n");
    }
}



void display_bootp(const u_char * bootpdata, int len, int verbose)
{
    if (!(verbose >= 1 && verbose <= 3))
        verbose = 1;
    
    int i = 0;
    int j = 0;
    int nextop = 0;                         // index de la prochaine option
    const struct bootp * message = NULL;    // pointeur vers le header bootp/dhcp
    const u_char * options = NULL;          // pointeur vers les options
    
    message = (const struct bootp *)bootpdata;
    
    printf("\n-----------------------------------BOOTP/DHCP-----------------------------------\n");
    
    if (len == 0)
        return;
    
    if (verbose == 1)
    {
        if (message->op == 1)
            printf("requete\n");
        
        if (message->op == 2)
            printf("reponse\n");
        
        if (message->ciaddr[0] || message->ciaddr[1] || message->ciaddr[2] || message->ciaddr[3])
            printf("client IP @: %d.%d.%d.%d\n", message->ciaddr[0], message->ciaddr[1], message->ciaddr[2], message->ciaddr[3]);
        
        if (message->yiaddr[0] || message->yiaddr[1] || message->yiaddr[2] || message->yiaddr[3])
            printf("your IP @: %d.%d.%d.%d\n", message->yiaddr[0], message->yiaddr[1], message->yiaddr[2], message->yiaddr[3]);
        
        if (strlen((const char *)message->file))
            printf("fichier de boot: %s\n", message->file);
        
        // si aucune option car taille trop faible
        if (len <= (int)sizeof(struct bootp))
            return;
        
        // si aucune option car pas de magic cookie
        if (!(bootpdata[sizeof(struct bootp)] == 0x63 &&
              bootpdata[sizeof(struct bootp)+1] == 0x82 &&
              bootpdata[sizeof(struct bootp)+2] == 0x53 &&
              bootpdata[sizeof(struct bootp)+3] == 0x63))
            return;
        
        options = &bootpdata[sizeof(struct bootp)+4];
        
        while (options[nextop] != 0xFF)
        {
            switch (options[nextop])
            {
                case 53:
                    if (options[nextop+2] == 1) printf("DHCP DISCOVER\n");
                    if (options[nextop+2] == 2) printf("DHCP OFFER\n");
                    if (options[nextop+2] == 3) printf("DHCP REQUEST\n");
                    if (options[nextop+2] == 4) printf("DHCP DECLINE\n");
                    if (options[nextop+2] == 5) printf("DHCP ACK\n");
                    if (options[nextop+2] == 6) printf("DHCP NACK\n");
                    if (options[nextop+2] == 7) printf("DHCP RELEASE\n");
                    break;
                case 50:
                    printf("@ IP demandee: %d.%d.%d.%d\n",
                            options[nextop+2], options[nextop+3],
                            options[nextop+4], options[nextop+5]);
                    break;
                default:
                    break;
            }
            
            nextop += 2+options[nextop+1];
        }
    }
    
    if (verbose == 2)
    {
        printf("opcode: %d", message->op);
        if (message->op == 1) printf(" (requete)\n");
        if (message->op == 2) printf(" (reponse)\n");
        
        if (message->ciaddr[0] || message->ciaddr[1] || message->ciaddr[2] || message->ciaddr[3])
            printf("client IP @: %d.%d.%d.%d\n", message->ciaddr[0], message->ciaddr[1], message->ciaddr[2], message->ciaddr[3]);
        
        if (message->yiaddr[0] || message->yiaddr[1] || message->yiaddr[2] || message->yiaddr[3])
            printf("your IP @: %d.%d.%d.%d\n", message->yiaddr[0], message->yiaddr[1], message->yiaddr[2], message->yiaddr[3]);
        
        if (message->siaddr[0] || message->siaddr[1] || message->siaddr[2] || message->siaddr[3])
            printf("server IP @: %d.%d.%d.%d\n", message->siaddr[0], message->siaddr[1], message->siaddr[2], message->siaddr[3]);
        
        if (message->giaddr[0] || message->giaddr[1] || message->giaddr[2] || message->giaddr[3])
            printf("gateway IP @: %d.%d.%d.%d\n", message->giaddr[0], message->giaddr[1], message->giaddr[2], message->giaddr[3]);
        
        printf("@ materielle client: ");
        printf("%.2x", message->chaddr[0]);
        for(i=1;i<message->hlen;i++)
            printf(":%.2x", message->chaddr[i]);
        
        printf("\n");
        
        if (strlen((const char *)message->sname))
            printf("nom du serveur: %s\n", message->sname);
        
        if (strlen((const char *)message->file))
            printf("fichier de boot: %s\n", message->file);
        
        // si aucune option car taille trop faible
        if (len <= (int)sizeof(struct bootp))
            return;
        
        // si aucune option car pas de magic cookie
        if (!(bootpdata[sizeof(struct bootp)] == 0x63 &&
              bootpdata[sizeof(struct bootp)+1] == 0x82 &&
              bootpdata[sizeof(struct bootp)+2] == 0x53 &&
              bootpdata[sizeof(struct bootp)+3] == 0x63))
            return;
        
        options = &bootpdata[sizeof(struct bootp)+4];
        
        while (options[nextop] != 0xFF)
        {
            switch (options[nextop])
            {
                case 53:
                    if (options[nextop+2] == 1) printf("DHCP DISCOVER\n");
                    if (options[nextop+2] == 2) printf("DHCP OFFER\n");
                    if (options[nextop+2] == 3) printf("DHCP REQUEST\n");
                    if (options[nextop+2] == 4) printf("DHCP DECLINE\n");
                    if (options[nextop+2] == 5) printf("DHCP ACK\n");
                    if (options[nextop+2] == 6) printf("DHCP NACK\n");
                    if (options[nextop+2] == 7) printf("DHCP RELEASE\n");
                    break;
                case 50:
                    printf("@ IP demandee: %d.%d.%d.%d\n",
                            options[nextop+2], options[nextop+3],
                            options[nextop+4], options[nextop+5]);
                    break;
                default:
                    break;
            }
            
            nextop += 2+options[nextop+1];
        }
    }
    
    if (verbose == 3)
    {
        printf("opcode: %d", message->op);
        if (message->op == 1) printf(" (requete)\n");
        if (message->op == 2) printf(" (reponse)\n");
        
        printf("format @ materielle: %d\n", message->htype);
        printf("taille @ materielle: %d\n", message->hlen);
        printf("nombre de sauts: %d\n", message->hops);
        printf("ID de transaction: 0x%x\n", ntohl(message->xid));
        printf("secondes ecoulees: %d\n", ntohs(message->secs));
        
        if (message->flags & 0x8000)
            printf("Flags: broadcast\n");
        else
            printf("Flags: aucun\n");
        
        if (message->ciaddr[0] || message->ciaddr[1] || message->ciaddr[2] || message->ciaddr[3])
            printf("client IP @: %d.%d.%d.%d\n", message->ciaddr[0], message->ciaddr[1], message->ciaddr[2], message->ciaddr[3]);
        
        if (message->yiaddr[0] || message->yiaddr[1] || message->yiaddr[2] || message->yiaddr[3])
            printf("your IP @: %d.%d.%d.%d\n", message->yiaddr[0], message->yiaddr[1], message->yiaddr[2], message->yiaddr[3]);
        
        if (message->siaddr[0] || message->siaddr[1] || message->siaddr[2] || message->siaddr[3])
            printf("server IP @: %d.%d.%d.%d\n", message->siaddr[0], message->siaddr[1], message->siaddr[2], message->siaddr[3]);
        
        if (message->giaddr[0] || message->giaddr[1] || message->giaddr[2] || message->giaddr[3])
            printf("gateway IP @: %d.%d.%d.%d\n", message->giaddr[0], message->giaddr[1], message->giaddr[2], message->giaddr[3]);
        
        printf("@ materielle client: ");
        printf("%.2x", message->chaddr[0]);
        for(i=1;i<message->hlen;i++)
            printf(":%.2x", message->chaddr[i]);
        
        printf("\n");
        
        if (strlen((const char *)message->sname))
            printf("nom du serveur: %s\n", message->sname);
        
        if (strlen((const char *)message->file))
            printf("fichier de boot: %s\n", message->file);
        
        // si aucune option car taille trop faible
        if (len <= (int)sizeof(struct bootp))
            return;
        
        // si aucune option car pas de magic cookie
        if (!(bootpdata[sizeof(struct bootp)] == 0x63 &&
              bootpdata[sizeof(struct bootp)+1] == 0x82 &&
              bootpdata[sizeof(struct bootp)+2] == 0x53 &&
              bootpdata[sizeof(struct bootp)+3] == 0x63))
            return;
        
        printf("Options:\n");
        
        options = &bootpdata[sizeof(struct bootp)+4];
        
        while (options[nextop] != 0xFF)
        {
            switch (options[nextop])
            {
                case 1:
                    printf(" masque de sous-reseau: %d.%d.%d.%d\n",
                            options[nextop+2], options[nextop+3],
                            options[nextop+4], options[nextop+5]);
                    break;
                case 3:
                    printf(" @ IP routeurs:\n");
                    for(j=0;j<(options[nextop+1]/4);j++)
                        printf("  %d.%d.%d.%d\n",
                               options[nextop+2+4*j], options[nextop+2+4*j+1],
                               options[nextop+2+4*j+2], options[nextop+2+4*j+3]);
                    break;
                case 6:
                    printf(" @ IP serveurs DNS:\n");
                    for(j=0;j<(options[nextop+1]/4);j++)
                        printf("  %d.%d.%d.%d\n",
                               options[nextop+2+4*j], options[nextop+2+4*j+1],
                               options[nextop+2+4*j+2], options[nextop+2+4*j+3]);
                    break;
                case 12:
                    printf(" nom d'hote: ");
                    for(j=0;j<options[nextop+1];j++)
                        printf("%c", options[nextop+2+j]);
                    printf("\n");
                    break;
                case 15:
                    printf(" nom de domaine: ");
                    for(j=0;j<options[nextop+1];j++)
                        printf("%c", options[nextop+2+j]);
                    printf("\n");
                    break;
                case 28:
                    printf(" @ de broadcast: %d.%d.%d.%d\n",
                            options[nextop+2], options[nextop+3],
                            options[nextop+4], options[nextop+5]);
                    break;
                case 50:
                    printf(" @ IP demandee: %d.%d.%d.%d\n",
                            options[nextop+2], options[nextop+3],
                            options[nextop+4], options[nextop+5]);
                    break;
                case 51:
                    printf(" temps de bail: %u secondes\n", options[nextop+5]+options[nextop+4]*256+options[nextop+3]*256*256+options[nextop+2]*256*256*256);
                    break;
                case 53:
                    if (options[nextop+2] == 1) printf(" DHCP DISCOVER\n");
                    if (options[nextop+2] == 2) printf(" DHCP OFFER\n");
                    if (options[nextop+2] == 3) printf(" DHCP REQUEST\n");
                    if (options[nextop+2] == 4) printf(" DHCP DECLINE\n");
                    if (options[nextop+2] == 5) printf(" DHCP ACK\n");
                    if (options[nextop+2] == 6) printf(" DHCP NACK\n");
                    if (options[nextop+2] == 7) printf(" DHCP RELEASE\n");
                    break;
                case 54:
                    printf(" @ IP serveur: %d.%d.%d.%d\n",
                            options[nextop+2], options[nextop+3],
                            options[nextop+4], options[nextop+5]);
                    break;
                case 55:
                    printf(" liste des parametres demandes:\n");
                    for(j=0;j<options[nextop+1];j++)
                    {
                        printf("%d ", options[nextop+2+j]);
                        
                        if (options[nextop+2+j] == 1) printf("  (masque de sous-reseau)");
                        if (options[nextop+2+j] == 2) printf("  (decalage de temps)");
                        if (options[nextop+2+j] == 3) printf("  (@ IP routeurs)");
                        if (options[nextop+2+j] == 6) printf("  (@ IP serveurs DNS)");
                        if (options[nextop+2+j] == 12) printf(" (nom d'hote)");
                        if (options[nextop+2+j] == 15) printf(" (nom de domaine)");
                        if (options[nextop+2+j] == 26) printf(" (MTU)");
                        if (options[nextop+2+j] == 28) printf(" (@ de broadcast)");
                        if (options[nextop+2+j] == 42) printf(" (serveurs NTP)");
                        if (options[nextop+2+j] == 44) printf(" (noms de serveurs NetBIOS)");
                        if (options[nextop+2+j] == 47) printf(" (portee NetBIOS)");
                        if (options[nextop+2+j] == 50) printf(" (@ IP demandee)");
                        if (options[nextop+2+j] == 51) printf(" (temps de bail)");
                        if (options[nextop+2+j] == 54) printf(" (@ IP serveur)");
                        if (options[nextop+2+j] == 119) printf("(liste de recherche de DNS)");
                        if (options[nextop+2+j] == 121) printf("(route statique)");
                        printf("\n");
                    }
                    printf("\n");
                    break;
                case 61:
                    if (options[nextop+1] == 7 && options[nextop+2] == 1)
                        printf(" @ materielle client: %.2x:%.2x:%.2x:%.2x:%.2x:%.2x\n",
                                options[nextop+3], options[nextop+4],
                                options[nextop+5], options[nextop+6],
                                options[nextop+7], options[nextop+8]);
                    else
                    {
                        printf(" identifiant client: ");
                        for(j=0;j<options[nextop+1];j++)
                            printf("%.2x ", options[nextop+2+j]);
                        printf("\n");
                    }
                    break;
                default:
                    break;
            }
            
            nextop += 2+options[nextop+1];
        }
    }
}


// protocole = 0 pour UDP
// protocole = 1 pour TCP
void display_dns(const u_char * dnsdata, int len, int verbose, int proto)
{
    if (!(verbose >= 1 && verbose <= 3))
        verbose = 1;
    
    int tcp_bytes = 0;
    int i = 0;
    int j = 0;
    const struct Dns_Header * message = NULL;
    const struct Dns_Question * question = NULL;
    const char * qname = NULL;

    tcp_bytes = (proto == 1) ? 2 : 0;    
    message = (const struct Dns_Header *)&dnsdata[tcp_bytes];
    qname = (const char *)&dnsdata[tcp_bytes + sizeof(struct Dns_Header)];
    
    printf("\n----------------------------------DNS------------------------------------\n");
    
    if (len == 0)
        return;
    
    if (verbose == 1)
    {
        if (message->qr == 0)
        {
            printf("requete");
            if (message->opcode == 0) printf(" standard");
            if (message->opcode == 1) printf(" inverse");
            if (message->opcode == 2) printf(" de statut");
            printf("\n");
            
            printf("=> ");
            
            // on cherche et affiche les caracteres du nom dans la requete
            while (qname[i] != 0)
            {
                for(j=i+1;j<=i+qname[i];j++)
                    printf("%c", qname[j]);
                
                printf(".");
                
                i += qname[i]+1;
            }
            
            printf("\n");
            
            question = (const struct Dns_Question *)&qname[i+1];
            
            printf("=> enregistrement: ");
            if (ntohs(question->qtype) == 1) printf("A");
            if (ntohs(question->qtype) == 2) printf("NS");
            if (ntohs(question->qtype) == 3) printf("MD");
            if (ntohs(question->qtype) == 4) printf("MF");
            if (ntohs(question->qtype) == 5) printf("CNAME");
            if (ntohs(question->qtype) == 6) printf("SOA");
            if (ntohs(question->qtype) == 7) printf("MB");
            if (ntohs(question->qtype) == 8) printf("MG");
            if (ntohs(question->qtype) == 9) printf("MR");
            if (ntohs(question->qtype) == 10) printf("NULL");
            if (ntohs(question->qtype) == 11) printf("WKS");
            if (ntohs(question->qtype) == 12) printf("PTR");
            if (ntohs(question->qtype) == 13) printf("HINFO");
            if (ntohs(question->qtype) == 14) printf("MINFO");
            if (ntohs(question->qtype) == 15) printf("MX");
            if (ntohs(question->qtype) == 16) printf("TXT");
            if (ntohs(question->qtype) == 28) printf("AAAA");
            if (ntohs(question->qtype) == 29) printf("LOC");
            if (ntohs(question->qtype) == 33) printf("SRV");
            printf("\n");
            
            printf("=> classe: ");
            if (ntohs(question->qclass) == 1) printf("Internet");
            if (ntohs(question->qclass) == 2) printf("Csnet");
            if (ntohs(question->qclass) == 3) printf("Chaosnet");
            if (ntohs(question->qclass) == 4) printf("Hesiod");
            if (ntohs(question->qclass) == 254) printf("NONE");
            if (ntohs(question->qclass) == 255) printf("ANY");
            printf("\n");
        }
        
        if (message->qr == 1)
        {
            printf("reponse");
            if (message->aa == 1) printf(" d'autorite");
            if (message->opcode == 0) printf(" a une requete standard");
            if (message->opcode == 1) printf(" a une requete inverse");
            if (message->opcode == 2) printf(" a une requete de statut");
            printf("\n");
            if (message->rcode) printf("impossible de repondre a la requete\n");
            
            //TODO: afficher la premiere reponse s'il y en a une
        }
    }
    
    if (verbose == 2)
    {
        if (message->qr == 0)
        {
            printf("requete");
            if (message->opcode == 0) printf(" standard");
            if (message->opcode == 1) printf(" inverse");
            if (message->opcode == 2) printf(" de statut");
            printf("\n");
            
            printf("=> ");
            
            // on cherche et affiche les caracteres du nom dans la requete
            while (qname[i] != 0)
            {
                for(j=i+1;j<=i+qname[i];j++)
                    printf("%c", qname[j]);
                
                printf(".");
                
                i += qname[i]+1;
            }
            
            printf("\n");
            
            question = (const struct Dns_Question *)&qname[i+1];
            
            printf("=> enregistrement: ");
            if (ntohs(question->qtype) == 1) printf("A");
            if (ntohs(question->qtype) == 2) printf("NS");
            if (ntohs(question->qtype) == 3) printf("MD");
            if (ntohs(question->qtype) == 4) printf("MF");
            if (ntohs(question->qtype) == 5) printf("CNAME");
            if (ntohs(question->qtype) == 6) printf("SOA");
            if (ntohs(question->qtype) == 7) printf("MB");
            if (ntohs(question->qtype) == 8) printf("MG");
            if (ntohs(question->qtype) == 9) printf("MR");
            if (ntohs(question->qtype) == 10) printf("NULL");
            if (ntohs(question->qtype) == 11) printf("WKS");
            if (ntohs(question->qtype) == 12) printf("PTR");
            if (ntohs(question->qtype) == 13) printf("HINFO");
            if (ntohs(question->qtype) == 14) printf("MINFO");
            if (ntohs(question->qtype) == 15) printf("MX");
            if (ntohs(question->qtype) == 16) printf("TXT");
            if (ntohs(question->qtype) == 28) printf("AAAA");
            if (ntohs(question->qtype) == 29) printf("LOC");
            if (ntohs(question->qtype) == 33) printf("SRV");
            printf("\n");
            
            printf("=> classe: ");
            if (ntohs(question->qclass) == 1) printf("Internet");
            if (ntohs(question->qclass) == 2) printf("Csnet");
            if (ntohs(question->qclass) == 3) printf("Chaosnet");
            if (ntohs(question->qclass) == 4) printf("Hesiod");
            if (ntohs(question->qclass) == 254) printf("NONE");
            if (ntohs(question->qclass) == 255) printf("ANY");
            printf("\n");
        }
        
        if (message->qr == 1)
        {
            printf("reponse");
            if (message->aa == 1) printf(" d'autorite");
            if (message->opcode == 0) printf(" a une requete standard");
            if (message->opcode == 1) printf(" a une requete inverse");
            if (message->opcode == 2) printf(" a une requete de statut");
            
            if (message->ra && message->rd)
                printf(" (mode recursif)\n");
            else
                printf(" (mode iteratif)\n");
            
            if (message->rcode) printf("impossible de repondre a la requete\n");
        }
        
        printf("# questions: %d\n", ntohs(message->qdcount));
        printf("# reponses: %d\n", ntohs(message->ancount));
        printf("# reponses d'autorite: %d\n", ntohs(message->nscount));
        printf("# reponses additionnelles: %d\n", ntohs(message->arcount));
        
        //TODO: afficher toutes les questions et reponses de la partie reponse standard
    }
    
    if (verbose == 3)
    {
        if (message->qr == 0)
        {
            printf("requete");
            if (message->opcode == 0) printf(" standard");
            if (message->opcode == 1) printf(" inverse");
            if (message->opcode == 2) printf(" de statut");
            printf("\n");
            
            printf("=> ");
            
            // on cherche et affiche les caracteres du nom dans la requete
            while (qname[i] != 0)
            {
                for(j=i+1;j<=i+qname[i];j++)
                    printf("%c", qname[j]);
                
                printf(".");
                
                i += qname[i]+1;
            }
            
            printf("\n");
            
            question = (const struct Dns_Question *)&qname[i+1];
            
            printf("=> enregistrement: ");
            if (ntohs(question->qtype) == 1) printf("A");
            if (ntohs(question->qtype) == 2) printf("NS");
            if (ntohs(question->qtype) == 3) printf("MD");
            if (ntohs(question->qtype) == 4) printf("MF");
            if (ntohs(question->qtype) == 5) printf("CNAME");
            if (ntohs(question->qtype) == 6) printf("SOA");
            if (ntohs(question->qtype) == 7) printf("MB");
            if (ntohs(question->qtype) == 8) printf("MG");
            if (ntohs(question->qtype) == 9) printf("MR");
            if (ntohs(question->qtype) == 10) printf("NULL");
            if (ntohs(question->qtype) == 11) printf("WKS");
            if (ntohs(question->qtype) == 12) printf("PTR");
            if (ntohs(question->qtype) == 13) printf("HINFO");
            if (ntohs(question->qtype) == 14) printf("MINFO");
            if (ntohs(question->qtype) == 15) printf("MX");
            if (ntohs(question->qtype) == 16) printf("TXT");
            if (ntohs(question->qtype) == 28) printf("AAAA");
            if (ntohs(question->qtype) == 29) printf("LOC");
            if (ntohs(question->qtype) == 33) printf("SRV");
            printf("\n");
            
            printf("=> classe: ");
            if (ntohs(question->qclass) == 1) printf("Internet");
            if (ntohs(question->qclass) == 2) printf("Csnet");
            if (ntohs(question->qclass) == 3) printf("Chaosnet");
            if (ntohs(question->qclass) == 4) printf("Hesiod");
            if (ntohs(question->qclass) == 254) printf("NONE");
            if (ntohs(question->qclass) == 255) printf("ANY");
            printf("\n");
        }
        
        if (message->qr == 1)
        {
            printf("reponse");
            if (message->aa == 1) printf(" d'autorite");
            if (message->opcode == 0) printf(" a une requete standard");
            if (message->opcode == 1) printf(" a une requete inverse");
            if (message->opcode == 2) printf(" a une requete de statut");
            printf("\n");
            
            if (message->ra && message->rd)
                printf("mode recursif\n");
            else
                printf("mode iteratif\n");
            
            if (message->rcode == 1) printf("erreur de format dans la requete\n");
            if (message->rcode == 2) printf("probleme serveur\n");
            if (message->rcode == 3) printf("le nom n'existe pas\n");
            if (message->rcode == 4) printf("requete non implementee\n");
            if (message->rcode == 5) printf("refus de la requete\n");
        }
        
        printf("# questions: %d\n", ntohs(message->qdcount));
        printf("# reponses: %d\n", ntohs(message->ancount));
        printf("# reponses d'autorite: %d\n", ntohs(message->nscount));
        printf("# reponses additionnelles: %d\n", ntohs(message->arcount));
        
        //TODO: afficher toutes les questions et reponses des 4 categories
    }
}

