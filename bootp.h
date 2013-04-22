#ifndef _BOOTP_H_
#define _BOOTP_H_



#pragma pack(push, 1)
struct bootp
{
	unsigned char op;
	unsigned char htype;
	unsigned char hlen;
	unsigned char hops;
	unsigned int xid;
	unsigned short secs;
	unsigned short flags;
	unsigned char ciaddr[4];
	unsigned char yiaddr[4];
	unsigned char siaddr[4];
	unsigned char giaddr[4];
	unsigned char chaddr[16];
	unsigned char sname[64];
	unsigned char file[128];
};
#pragma pack(pop)



#endif

