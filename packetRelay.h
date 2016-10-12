#pragma once
#include "pcap.h"
#include "libnet.h"
#include "makeInfPacket.h"
#include <string.h>

//
// packet 릴레이 시켜주기
//
void packetRelay(pcap_t *handle, const u_int8_t myMAC[], const int myIP[], const u_int8_t victimMAC[], const int victimIP[], const u_int8_t gateMAC[], const int gateIP[]);


//
// mac address 비교하기
//
bool macCMP(const u_int8_t mac1[], const u_int8_t mac2[]);


//
// ip address 비교하기
//
bool ipCMP(const UCHAR ip1[], const int ip2[]);


//
// send infected packet
//
void sendInfPacket(pcap_t *handle, const UCHAR *packetdata,int size);


//
// send packet
//
void sendPacket(pcap_t *handle, const UCHAR *packetdata, int size);


//
// 내 맥주소로 복사하기
//
void macCPY(u_int8_t sa[], const u_int8_t myMAC[]);