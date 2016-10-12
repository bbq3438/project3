#pragma once
#include "pcap.h"
#include "libnet.h"
#include "makeInfPacket.h"
#include <string.h>

//
// packet ������ �����ֱ�
//
void packetRelay(pcap_t *handle, const u_int8_t myMAC[], const int myIP[], const u_int8_t victimMAC[], const int victimIP[], const u_int8_t gateMAC[], const int gateIP[]);


//
// mac address ���ϱ�
//
bool macCMP(const u_int8_t mac1[], const u_int8_t mac2[]);


//
// ip address ���ϱ�
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
// �� ���ּҷ� �����ϱ�
//
void macCPY(u_int8_t sa[], const u_int8_t myMAC[]);