#ifndef _CALLBACK_H_
#define _CALLBACK_H_

#include <pcap.h>



void my_callback(u_char * args, const struct pcap_pkthdr * header, const u_char * packet);



#endif

