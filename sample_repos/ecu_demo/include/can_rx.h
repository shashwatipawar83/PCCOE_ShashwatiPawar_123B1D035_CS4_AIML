#ifndef CAN_RX_H
#define CAN_RX_H
#include <stdint.h>
typedef struct { uint16_t id; char name[16]; } SignalDesc;
void CanRx_Store(const uint8_t *payload, uint8_t dlc);
#endif
