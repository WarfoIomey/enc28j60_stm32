/*
 * udp.h
 *
 *  Created on: 14 окт. 2022 г.
 *      Author: kiril
 */

#ifndef INC_UDP_H_
#define INC_UDP_H_

//--------------------------------------------------
#include "stm32f1xx_hal.h"
#include <string.h>
#include <stdlib.h>
#include <stdint.h>
#include "enc28j60.h"
#include "net.h"
//--------------------------------------------------
#define LOCAL_PORT 333
//--------------------------------------------------
typedef struct udp_pkt {
  uint16_t port_src;//порт отправителя
  uint16_t port_dst;//порт получателя
  uint16_t len;//длина
  uint16_t cs;//контрольная сумма заголовка
  uint8_t data[];//данные
} udp_pkt_ptr;
//--------------------------------------------------
 uint8_t udp_read(enc28j60_frame_ptr *frame, uint16_t len);
uint8_t udp_send(uint8_t *ip_addr, uint16_t port);
//--------------------------------------------------

#endif /* INC_UDP_H_ */
