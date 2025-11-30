#ifndef DETECT_H
#define DETECT_H

#include "packet.h"
#include "rules.h"

void detect_attacks(const PacketInfo *pkt);

#endif