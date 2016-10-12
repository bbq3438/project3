#pragma once

#include <pcap.h>
#include <iphlpapi.h>

#pragma comment(lib, "IPHLPAPI.lib")

//
// Device�� ������ ���´�
//
PIP_ADAPTER_INFO getDeviceInfo();


//
// IP �ּҸ� ���´�
//
void getIP(PIP_ADAPTER_INFO Device, int myIP[], int gateIP[]);


//
// MAC �ּҸ� ���´�
//
void getMAC(pcap_t *handle, const int myIP[], const u_int8_t myMAC[], const int targetIP[], u_int8_t targetMAC[]);