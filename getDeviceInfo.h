#pragma once

#include <pcap.h>
#include <iphlpapi.h>

#pragma comment(lib, "IPHLPAPI.lib")

//
// Device의 정보를 얻어온다
//
PIP_ADAPTER_INFO getDeviceInfo();


//
// IP 주소를 얻어온다
//
void getIP(PIP_ADAPTER_INFO Device, int myIP[], int gateIP[]);


//
// MAC 주소를 얻어온다
//
void getMAC(pcap_t *handle, const int myIP[], const u_int8_t myMAC[], const int targetIP[], u_int8_t targetMAC[]);