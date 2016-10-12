#pragma once
#include "libnet.h"

//
// 감염패킷 만들기
//
void makeInfPacket(UCHAR packet[], const u_int8_t sa[], const u_int8_t ta[], const int si[], const int ti[]);
