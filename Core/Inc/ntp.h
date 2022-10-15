/*
 * ntp.h
 *
 *  Created on: 14 окт. 2022 г.
 *      Author: kiril
 */

#ifndef INC_NTP_H_
#define INC_NTP_H_

//--------------------------------------------------
#include "stm32f1xx_hal.h"
#include <string.h>
#include <stdlib.h>
#include <stdint.h>
#include "enc28j60.h"
#include "net.h"
#include <time.h>
//--------------------------------------------------
#define LOCAL_PORT_FOR_NTP 14444
#define TIMEZONE 3
//--------------------------------------------------
typedef struct ntp_ts {
  uint32_t sec;//целая часть
  uint32_t frac;//дробная часть
} ntp_ts_ptr;
//--------------------------------------------------
typedef struct ntp_pkt {
  uint8_t flags; //флаги
  uint8_t peer_clock_stratum;//страта
  uint8_t peer_pooling_interval;//Интервал опроса
  uint8_t peer_clock_precision;//Точность
  uint32_t root_delay;//Задержка
  uint32_t root_dispersion;//Дисперсия
  uint32_t ref_id;//Идентификатор источника
  ntp_ts_ptr ref_ts;//Время обновления
  ntp_ts_ptr orig_ts;//Начальное время
  ntp_ts_ptr rcv_ts;//Время приёма
  ntp_ts_ptr tx_ts;//Время отправки
} ntp_pkt_ptr;
//--------------------------------------------------
typedef struct ntp_prop{
  uint8_t ntp_cnt; //количество оставшихся попыток получить время
  int32_t ntp_timer; //таймер для следующей попытки
  uint8_t set; //флаг получения времени
  uint8_t macaddr_dst[6];
  uint8_t ip_dst[4];
  uint16_t port_dst;//порт получателя
} ntp_prop_ptr;
//----------------------------------------------
uint8_t ntp_request(uint8_t *ip_addr, uint16_t port);
uint8_t ntp_read(enc28j60_frame_ptr *frame, uint16_t len);
//--------------------------------------------------

#endif /* INC_NTP_H_ */
