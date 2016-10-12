#include <stdio.h>
#include "getDeviceInfo.h"
#include "libnet.h"


//
// device로부터 정보 얻기
//
PIP_ADAPTER_INFO getDeviceInfo()
{
	PIP_ADAPTER_INFO Deviceinfo;
	PIP_ADAPTER_INFO Device = NULL;
	DWORD return_value = 0;
	int i;
	ULONG buff = sizeof(IP_ADAPTER_INFO);

	Deviceinfo = (IP_ADAPTER_INFO *)malloc(sizeof(IP_ADAPTER_INFO));
	if (Deviceinfo == NULL)
	{
		printf("에러 : 메모리를 할당에 실패했습니다\n");
		return NULL;
	}

	if (GetAdaptersInfo(Deviceinfo, &buff) == ERROR_BUFFER_OVERFLOW)
	{
		free(Deviceinfo);
		Deviceinfo = (IP_ADAPTER_INFO *)malloc(buff);

		if (Deviceinfo == NULL)
		{
			printf("에러 : 메모리를 할당에 실패했습니다\n");
			return NULL;
		}
	}

	if ((return_value = GetAdaptersInfo(Deviceinfo, &buff)) == NO_ERROR)
	{
		Device = Deviceinfo;

		while (Device)
		{
			if ((Device->IpAddressList.IpAddress.String[0] != '0') && (Device->GatewayList.IpAddress.String[0] != '0'))
				break;
			Device = Device->Next;
		}

		printf("\n------------------------------------------------------------------\n");
		printf(" Device des: \t%s\n", Device->Description);
		printf(" Device Addr: \t");
		for (i = 0; i < (int)Device->AddressLength; i++)
		{
			if (i == (Device->AddressLength - 1))
				printf("%.2X\n", (int)Device->Address[i]);
			else
				printf("%.2X-", Device->Address[i]);
		}

		printf(" IP Address: \t%s\n", Device->IpAddressList.IpAddress.String);
		printf(" Gateway: \t%s\n", Device->GatewayList.IpAddress.String);
		printf("------------------------------------------------------------------\n\n");

		return Device;
	}
	else
	{
		printf("GetAdaptersInfo failed with error: %d\n", return_value);

		return NULL;
	}
}


//
// IP 주소를 얻기
//
void getIP(PIP_ADAPTER_INFO Device, int myIP[], int gateIP[])
{
	int i, j, k;
	char ipstring[4];
	char temp;
	int tempaddr[4];

	//
	// get myIP addr
	//
	i = 0;
	j = 0;
	k = 0;
	while (1)
	{
		temp = Device->IpAddressList.IpAddress.String[i];
		if (temp == '.')
		{
			tempaddr[k] = atoi(ipstring);
			for (j = 0; j < 4; j++)
				ipstring[j] = 0;
			i++;
			k++;
			j = 0;
			continue;
		}
		else if (temp == '\0')
		{
			tempaddr[k] = atoi(ipstring);
			break;
		}

		ipstring[j] = temp;
		i++;
		j++;
	}
	for (i = 0; i < 4; i++)
		myIP[i] = tempaddr[i];

	//
	// get gateway addr
	//
	for (i = 0; i < 4; i++)
	{
		ipstring[i] = '\0';
		tempaddr[i] = 0;
	}

	i = 0;
	j = 0;
	k = 0;
	while (1)
	{
		temp = Device->GatewayList.IpAddress.String[i];
		if (temp == '.')
		{
			tempaddr[k] = atoi(ipstring);
			for (j = 0; j < 4; j++)
				ipstring[j] = 0;
			i++;
			k++;
			j = 0;
			continue;
		}
		else if (temp == '\0')
		{
			tempaddr[k] = atoi(ipstring);
			break;
		}

		ipstring[j] = temp;
		i++;
		j++;
	}
	for (i = 0; i < 4; i++)
		gateIP[i] = tempaddr[i];
}


//
// MAC 주소를 얻기
//
void getMAC(pcap_t *handle, const int myIP[], const u_int8_t myMAC[], const int targetIP[], u_int8_t targetMAC[])
{
	UCHAR packetdata[2048];
	ETH_HDR *EH = (ETH_HDR *)packetdata;
	ARP_HDR *AH = (ARP_HDR *)(packetdata + 14);
	int i;
	bool find = true;
	const u_char *packet;
	struct pcap_pkthdr *hdr;
	ETH_HDR *TempEH;
	ARP_HDR *TempAH;
	int res;

	memset(packetdata, 0, sizeof(packetdata));

	for (i = 0; i < ETHER_ADDR_LEN; i++)
	{
		EH->ether_shost[i] = myMAC[i];
		EH->ether_dhost[i] = 0xFF;
	}

	EH->ether_type = ntohs(ETHERTYPE_ARP);

	memcpy(packetdata, EH, sizeof(ETH_HDR));
	
	//
	// set arp_hdr
	//
	AH->ar_hrd = ntohs(1);
	AH->ar_pro = ntohs(0x0800);
	AH->ar_hln = 6;
	AH->ar_pln = 4;
	AH->ar_op = ntohs(ARPOP_REQUEST);

	for (i = 0; i < ETHER_ADDR_LEN; i++)
	{
		AH->ar_sa[i] = myMAC[i];
		AH->ar_ta[i] = 0x00;
	}
	for (i = 0; i < IPv4_ADDR_LEN; i++)
	{
		AH->ar_si[i] = myIP[i];
		AH->ar_ti[i] = targetIP[i];
	}

	memcpy(packetdata + sizeof(ETH_HDR), AH, sizeof(ARP_HDR));

	while (find)
	{
		if (pcap_sendpacket(handle, (u_char*)packetdata, (sizeof(ETH_HDR) + sizeof(ARP_HDR))) != 0) //pcap으로 전송
			printf("arp error\n");
		printf("sned ARP packet\n");
		for (i = 0; i < 100; i++)
		{
			if (res = pcap_next_ex(handle, &hdr, &packet))
			{
				if (res < 0)
					break;
				else if (res == 0)
					continue;
			}

			TempEH = (ETH_HDR *)packet;
			TempAH = (ARP_HDR *)(packet + sizeof(ETH_HDR));

			if ((ntohs(TempEH->ether_type) == ETHERTYPE_ARP)
				&& (ntohs(TempAH->ar_op) == ARPOP_REPLY)
				&& (TempAH->ar_si[0] == targetIP[0])
				&& (TempAH->ar_si[1] == targetIP[1])
				&& (TempAH->ar_si[2] == targetIP[2])
				&& (TempAH->ar_si[3] == targetIP[3]))
			{
				find = false;
				printf("MAC 얻기 성공!\n\n");
				for (int i = 0; i < ETHER_ADDR_LEN; i++)
					targetMAC[i] = TempAH->ar_sa[i];
				break;
			}
		}
	}
}