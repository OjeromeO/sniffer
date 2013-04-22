#ifndef _DISPLAY_H_
#define _DISPLAY_H_

#include <netinet/if_ether.h>



void display_ethernet(const struct ether_header * eth_hdr, int verbose);
void display_arp(const struct ether_arp * arp, int verbose);
void display_ipv4(const struct iphdr * ip_hdr, int verbose);
void display_udp(const struct udphdr * udp_hdr, int verbose);
void display_tcp(const struct tcphdr * tcp_hdr, int verbose);
void display_http(const u_char * httpdata, int len, int verbose);
void display_smtp(const u_char * smtpdata, int len, int verbose);
void display_imap(const u_char * imapdata, int len, int verbose);
void display_pop3(const u_char * popdata, int len, int verbose);
void display_ftpdata(const u_char * ftpdata, int len, int verbose);
void display_ftpcontrol(const u_char * ftpcontrol, int len, int verbose);
void display_telnet(const u_char * telnetdata, int len, int verbose);
void display_bootp(const u_char * bootpdata, int len, int verbose);
void display_dns(const u_char * dnsdata, int len, int verbose, int proto);



#endif

