/*
 * net.h
 *
 *  Created on: 14 окт. 2022 г.
 *      Author: kiril
 */

#ifndef INC_NET_H_
#define INC_NET_H_

//--------------------------------------------------
#include "stm32f1xx_hal.h"
#include <string.h>
#include <stdlib.h>
#include <stdint.h>
#include "enc28j60.h"
//--------------------------------------------------
#define IP_ADDR {192,168,1,197}//ip адрес устройства
#define IP_GATE {192,168,1,1}
#define IP_MASK {255,255,255,0}
#define MAC_BROADCAST {0xFF,0xFF,0xFF,0xFF,0xFF,0xFF}//широковещательного MAC-адресов
#define MAC_NULL {0x00,0x00,0x00,0x00,0x00,0x00}//нулевой mac
//----------------Cтруктура для фрейма----------------------------------
typedef struct enc28j60_frame{
	uint8_t addr_dest[6];
	uint8_t addr_src[6];
	uint16_t  type;
	uint8_t data[];
} enc28j60_frame_ptr;
//----------Структура для заголовка ARP----------------------------------------
typedef struct arp_msg{
	uint16_t  net_tp;
	uint16_t  proto_tp;
	uint8_t macaddr_len;
	uint8_t ipaddr_len;
	uint16_t  op;
	uint8_t macaddr_src[6];
	uint8_t ipaddr_src[4];
	uint8_t macaddr_dst[6];
	uint8_t ipaddr_dst[4];
} arp_msg_ptr;
//----------------Структура ip пакета---------------------------------
typedef struct ip_pkt{
	uint8_t verlen;//версия протокола и длина заголовка
	uint8_t ts;//тип севриса
	uint16_t len;//длина
	uint16_t id;//идентификатор пакета
	uint16_t fl_frg_of;//флаги и смещение фрагмента
	uint8_t ttl;//время жизни
	uint8_t prt;//тип протокола
	uint16_t cs;//контрольная сумма заголовка
	uint8_t ipaddr_src[4];//IP-адрес отправителя
	uint8_t ipaddr_dst[4];//IP-адрес получателя
	uint8_t data[];//данные
} ip_pkt_ptr;
//---------------Структура заголовка ICMP пакета-----------------------------------
typedef struct icmp_pkt{
	uint8_t msg_tp;//тип севриса
	uint8_t msg_cd;//код сообщения
	uint16_t cs;//контрольная сумма заголовка
	uint16_t id;//идентификатор пакета
	uint16_t num;//номер пакета
	uint8_t data[];//данные
} icmp_pkt_ptr;
//-----------------Структура со свойствами---------------------------------
 typedef struct USART_prop{
  uint8_t usart_buf[25];
  uint8_t usart_cnt;
  uint8_t is_ip;
} USART_prop_ptr;
//--------------------------------------------------
#define be16toword(a)	((((a)>>8)&0xff)|(((a)<<8)&0xff00))
#define be32todword(a) ((((a)>>24)&0xff)|(((a)>>8)&0xff00)|(((a)<<8)&0xff0000)|(((a)<<24)&0xff000000))
//--------------------------------------------------
#define ETH_ARP	be16toword(0x0806)
#define ETH_IP	be16toword(0x0800)
//--------------------------------------------------
#define ARP_ETH	be16toword(0x0001)
#define ARP_IP	be16toword(0x0800)
#define ARP_REQUEST	be16toword(1)
#define ARP_REPLY	be16toword(2)
//---------------Протоколы-----------------------------------
#define IP_ICMP	1
#define IP_TCP	6
#define IP_UDP	17
//------------------типы сообщений--------------------------------
#define ICMP_REQ	8
#define ICMP_REPLY	0
//--------------------------------------------------
void net_ini(void);
void net_poll(void);
void eth_send(enc28j60_frame_ptr *frame, uint16_t len);
void UART1_RxCpltCallback(void);
void TIM_PeriodElapsedCallback(void);
uint8_t ip_send(enc28j60_frame_ptr *frame, uint16_t len);
uint16_t checksum(uint8_t *ptr, uint16_t len, uint8_t type);
void net_cmd(void);
//--------------------------------------------------
#include "arp.h"
#include "udp.h"
#include "ntp.h"
#include "tcp.h"
//--------------------------------------------------


#endif /* INC_NET_H_ */
