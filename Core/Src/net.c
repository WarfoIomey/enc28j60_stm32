/*
 * net.c
 *
 *  Created on: 14 окт. 2022 г.
 *      Author: kiril
 */
#include "net.h"
#include <stdio.h>
//-----------------------------------------------
extern UART_HandleTypeDef huart2;
//-----------------------------------------------
uint8_t net_buf[ENC28J60_MAXFRAME];//глобальный строковый массив
extern uint8_t macaddr[6];
uint8_t ipaddr[4]=IP_ADDR;
uint8_t ipgate[4]=IP_GATE;
uint8_t ipmask[4]=IP_MASK;
uint32_t clock_cnt=0;//счетчик секунд
char str1[60]={0};
uint32_t ping_cnt=0;//счетчик отправленных пингов
extern char str[20];
USART_prop_ptr usartprop;
extern ntp_prop_ptr ntpprop;
//-----------------------------------------------
void net_ini(void)
{
	usartprop.usart_buf[0]=0;//инициализируем свойства
	usartprop.usart_cnt=0;//инициализируем свойства
	usartprop.is_ip=0;//инициализируем свойства
	HAL_UART_Transmit(&huart2,(uint8_t*)"123456\r\n",8,0x1000);
	enc28j60_ini();//функция инициализации enc28j60
	ntpprop.set=0;
	ntpprop.ntp_cnt=0;
	ntpprop.ntp_timer=0;
}
//-----------------Расчёт контрольной суммы заголовка------------------------------
uint16_t checksum(uint8_t *ptr, uint16_t len, uint8_t type)
{
	uint32_t sum=0;
	if(type==1)
	{
		sum+=IP_UDP;
		sum+=len-8;
	}
	if(type==2)
	{
		sum+=IP_TCP;
		sum+=len-8;
	}
	while(len>0)//цикл, отслеживающий окончание заголовка
	{
		sum += (uint16_t) (((uint32_t)*ptr<<8)|*(ptr+1));//посчитаем и прибавим к общей сумме очередную двухбайтовую величину
		ptr+=2;//сместим указатель дальше на 2 пункта
		len-=2;//значение длины заголовка уменьшим на 2
	}
	if(len) sum+=((uint32_t)*ptr)<<8;//роверим длину заголовка на чётность
	//постоянно складываем между собой старшую и младшую части суммы до тех пор, пока сумма не уместится в 16-битный размер
	while(sum>>16) sum=(uint16_t)sum+(sum>>16);
	// сконвертировать сумму в формат big endian, затем её проинвертировать и вернуть из функции
	return ~be16toword((uint16_t)sum);
}
//-----------------функцию для отправки кадра по протоколу Ethernet------------------------------
void eth_send(enc28j60_frame_ptr *frame, uint16_t len)
{
	memcpy(frame->addr_src,macaddr,6);
	enc28j60_packetSend((void*)frame,len+sizeof(enc28j60_frame_ptr));
}
//-------------------- функцию для отправки IP-пакета---------------------------
uint8_t ip_send(enc28j60_frame_ptr *frame, uint16_t len)
{
	uint8_t res=0;
	ip_pkt_ptr *ip_pkt = (void*)(frame->data);//установим указатель на пакет IP
	//Заполним заголовок пакета IP
	ip_pkt->len=be16toword(len);
	ip_pkt->fl_frg_of=0;
	ip_pkt->ttl=128;
	ip_pkt->cs=0;
	memcpy(ip_pkt->ipaddr_dst,ip_pkt->ipaddr_src,4);
	memcpy(ip_pkt->ipaddr_src,ipaddr,4);
	ip_pkt->cs=checksum((void*)ip_pkt,sizeof(ip_pkt_ptr),0);
	//отправим фрейм
	eth_send(frame,len);
	return res;
}
//---------------функцию чтения ICMP-пакета--------------------------------
uint8_t icmp_read(enc28j60_frame_ptr *frame, uint16_t len)
{
	uint8_t res=0;//переменную для результата
	ip_pkt_ptr *ip_pkt = (void*)(frame->data);//указатель на пакет IP
	icmp_pkt_ptr *icmp_pkt = (void*)(ip_pkt->data);//установим указатель на пакет ICMP
	if(len>=sizeof(icmp_pkt_ptr))//Отфильтруем пакет по длине и типу сообщения — эхо-запрос
	{
		//Выведем сообщение в терминальной программе, что у нас именно такой запрос
		if(icmp_pkt->msg_tp==ICMP_REQ)
		{
			icmp_pkt->msg_tp=ICMP_REPLY;
			icmp_pkt->cs=0;
			icmp_pkt->cs=checksum((void*)icmp_pkt,len,0);
			memcpy(frame->addr_dest,frame->addr_src,6);
			ip_send(frame,len+sizeof(ip_pkt_ptr));
			sprintf(str1,"%d.%d.%d.%d-%d.%d.%d.%d icmp request\r\n",
				ip_pkt->ipaddr_dst[0],ip_pkt->ipaddr_dst[1],ip_pkt->ipaddr_dst[2],ip_pkt->ipaddr_dst[3],
				ip_pkt->ipaddr_src[0],ip_pkt->ipaddr_src[1],ip_pkt->ipaddr_src[2],ip_pkt->ipaddr_src[3]);
			HAL_UART_Transmit(&huart2,(uint8_t*)str1,strlen(str1),0x1000);
		}
		else if (icmp_pkt->msg_tp==ICMP_REPLY)
		{
			sprintf(str1,"%d.%d.%d.%d-%d.%d.%d.%d icmp reply\r\n",
			ip_pkt->ipaddr_src[0],ip_pkt->ipaddr_src[1],ip_pkt->ipaddr_src[2],ip_pkt->ipaddr_src[3],
			ip_pkt->ipaddr_dst[0],ip_pkt->ipaddr_dst[1],ip_pkt->ipaddr_dst[2],ip_pkt->ipaddr_dst[3]);
			HAL_UART_Transmit(&huart2,(uint8_t*)str1,strlen(str1),0x1000);
		}
	}
	return res;
}
//-------------------функцию чтения пакета IP----------------------------
uint8_t ip_read(enc28j60_frame_ptr *frame, uint16_t len)
{
	uint8_t res = 0;//переменная для результата
	ip_pkt_ptr *ip_pkt = (void*)(frame->data);//указатель на пакет
	//фильтрацию по версии протокола, длине заголовка и соответствию адреса получателя нашему IP
	if((ip_pkt->verlen==0x45)&&(!memcmp(ip_pkt->ipaddr_dst,ipaddr,4)))
	{
		//длина данных
		len = be16toword(ip_pkt->len) - sizeof(ip_pkt_ptr);//Вычислим размер данных в байтах
		//узнаем тип протокола
		if(ip_pkt->prt==IP_ICMP)
		{
			icmp_read(frame,len);
		}
		else if(ip_pkt->prt==IP_TCP)
		{
			tcp_read(frame,len);
		}
		else if(ip_pkt->prt==IP_UDP)
		{
			udp_read(frame,len);
		}
	}
	return res;
}
//-----------------------------------------------
uint8_t icmp_request(uint8_t* ip_addr)
{
  uint8_t res=0;
	uint16_t len;
	enc28j60_frame_ptr *frame=(void*) net_buf;
	ip_pkt_ptr *ip_pkt = (void*)(frame->data);
	icmp_pkt_ptr *icmp_pkt = (void*)ip_pkt->data;
	//Заполним заголовок пакета ICMP
	icmp_pkt->msg_tp = 8;
	icmp_pkt->msg_cd = 0;
	icmp_pkt->id = be16toword(1);
	icmp_pkt->num = be16toword(ping_cnt);
	ping_cnt++;
	strcpy((char*)icmp_pkt->data,"abcdefghijklmnopqrstuvwabcdefghi");
	icmp_pkt->cs = 0;
	len = strlen((char*)icmp_pkt->data) + sizeof(icmp_pkt_ptr);
	icmp_pkt->cs=checksum((void*)icmp_pkt,len,0);
	//Заполним заголовок пакета IP
	len+=sizeof(ip_pkt_ptr);
	ip_pkt->len=be16toword(len);
	ip_pkt->id = 0;
	ip_pkt->ts = 0;
	ip_pkt->verlen = 0x45;
	ip_pkt->fl_frg_of=0;
	ip_pkt->ttl=128;
	ip_pkt->cs = 0;
	ip_pkt->prt=IP_ICMP;
	memcpy(ip_pkt->ipaddr_dst,ip_addr,4);
	memcpy(ip_pkt->ipaddr_src,ipaddr,4);
	ip_pkt->cs = checksum((void*)ip_pkt,sizeof(ip_pkt_ptr),0);
	//Заполним заголовок пакета Ethernet
  memcpy(frame->addr_src,macaddr,6);
  frame->type=ETH_IP;
  enc28j60_packetSend((void*)frame,len + sizeof(enc28j60_frame_ptr));
  return res;
}
//--------------------------------------------------
uint16_t port_extract(char* ip_str, uint8_t len)
{
  uint16_t port=0;
  int ch1=':';
  char *ss1;
  uint8_t offset = 0;
  ss1=strchr(ip_str,ch1);
  offset=ss1-ip_str+1;
  ip_str+=offset;
  port = atoi(ip_str);
  return port;
}
//--------------функция преобразования строкового значения IP в 32-битное числовое------------------------------------
void ip_extract(char* ip_str, uint8_t len, uint8_t* ipextp)
{
	uint8_t offset = 0;
  uint8_t i;
  char ss2[5] = {0};
  char *ss1;
  int ch1 = '.';//пробежим по функции на предмет появления точек
  int ch2 = ':';
	for(i=0;i<3;i++)
	{
		ss1 = strchr(ip_str,ch1);
		offset = ss1-ip_str+1;//смещением относительно начала строки с IP-адресом, поэтому вычислим это смещение
		strncpy(ss2,ip_str,offset);//скопируем ещё в одну строку часть нашей строки до точки
		ss2[offset]=0;
		ipextp[i] = atoi(ss2);//преобразовав вышесозданную строку в число, запишем его в соответствующий элемент массива для адреса
		ip_str+=offset;//сдвинем указатели нашей строки с IP-адресом и длины этой строки
		len-=offset;
	}
	//мы уже работаем с последним байтом IP-адреса, после которого уже точки нет и
	//также записываем его в соответствующий элемент возвращаемого массива адреса IP
	ss1=strchr(ip_str,ch2);
	if (ss1!=NULL)
	{
		offset=ss1-ip_str+1;
		strncpy(ss2,ip_str,offset);
		ss2[offset]=0;
		ipextp[3] = atoi(ss2);
		return;
	}
	strncpy(ss2,ip_str,len);
	ss2[len]=0;
	ipextp[3] = atoi(ss2);
}
//----------------функция чтения фрейма-------------------------------
void eth_read(enc28j60_frame_ptr *frame, uint16_t len)
{
	uint8_t res=0;
	if(len>sizeof(enc28j60_frame_ptr))
	{
		//отправлять ответ ARP только в случае, если ARP-запрос вернёт единицу
		if(frame->type==ETH_ARP)
		{
			res = arp_read(frame,len-sizeof(enc28j60_frame_ptr));
			if(res==1)
			{
				arp_send(frame);//ответим на ARP запрос
			}
			else if(res==2)
			{
				arp_table_fill(frame);
				if((usartprop.is_ip==3)||(usartprop.is_ip==5)||(usartprop.is_ip==7))//статус отправки UDP-, ICMP- или NTP пакета
				{
					memcpy(frame->addr_dest,frame->addr_src,6);
					net_cmd();
				}
			}
		}
		else if(frame->type==ETH_IP)
		{
			ip_read(frame,len-sizeof(ip_pkt_ptr));
		}
		else
		{
			//вывод в терминальную программу адрес источника, отправившего кадр, адрес приёмника и тип протокола
			sprintf(str1,"%02X:%02X:%02X:%02X:%02X:%02X-%02X:%02X:%02X:%02X:%02X:%02X; %d; %04X",
			frame->addr_src[0],frame->addr_src[1],frame->addr_src[2],frame->addr_src[3],frame->addr_src[4],frame->addr_src[5],
			frame->addr_dest[0],frame->addr_dest[1],frame->addr_dest[2],frame->addr_dest[3],frame->addr_dest[4],frame->addr_dest[5],
			len, be16toword(frame->type));
			HAL_UART_Transmit(&huart2,(uint8_t*)str1,strlen(str1),0x1000);
			HAL_UART_Transmit(&huart2,(uint8_t*)"\r\n",2,0x1000);
		}
	}
}
//-----------------функция постоянного опроса сети------------------------------
void net_poll(void)
{
	uint16_t len;
	//uint8_t ip[4]={0};
	//приёма информации из буфера чтения
	enc28j60_frame_ptr *frame=(void*)net_buf;
	while((len=enc28j60_packetReceive(net_buf,sizeof(net_buf)))>0)
	{
		eth_read(frame,len);
	}
}
//-----------------------------------------------
void net_cmd(void)
{
  static uint8_t ip[4]={0};
	static uint16_t port=0;
	enc28j60_frame_ptr *frame=(void*)net_buf;
  if(usartprop.is_ip==1)//статус отправки ARP-запроса
  {
    ip_extract((char*)usartprop.usart_buf,usartprop.usart_cnt,ip);
    arp_request(ip);
    usartprop.is_ip = 0;
    usartprop.usart_cnt=0;
  }
	else if(usartprop.is_ip==2)//статус попытки отправить UDP-пакет
	{
		ip_extract((char*)usartprop.usart_buf,usartprop.usart_cnt,ip);
		usartprop.is_ip=3;//статус отправки UDP-пакета
		usartprop.usart_cnt=0;
		arp_request(ip);//узнаем mac-адрес
	}
  else if(usartprop.is_ip==3)//статус отправки UDP-пакета
  {
		port=port_extract((char*)usartprop.usart_buf,usartprop.usart_cnt);
		udp_send(ip,port);
    usartprop.is_ip=0;
  }
	else if(usartprop.is_ip==4)//статус попытки отправить ICMP-пакет
  {
    ip_extract((char*)usartprop.usart_buf,usartprop.usart_cnt,ip);
    usartprop.is_ip=5;//статус отправки ICMP-пакета
    usartprop.usart_cnt=0;
    arp_request(ip);//узнаем mac-адрес
  }
  else if(usartprop.is_ip==5)//статус отправки ICMP-пакета
  {
    icmp_request(ip);
    usartprop.is_ip=0;
  }
	else if(usartprop.is_ip==6)//статус попытки отправить NTP-пакет
	{
		ip_extract((char*)usartprop.usart_buf,usartprop.usart_cnt,ip);
		memcpy(ntpprop.ip_dst,ip,4);
		usartprop.is_ip=7;//статус отправки NTP-пакета
		usartprop.usart_cnt=0;
		arp_request(ip);//узнаем mac-адрес
	}
	else if(usartprop.is_ip==7)//статус отправки NTP-пакета
	{
		port=port_extract((char*)usartprop.usart_buf,usartprop.usart_cnt);
		ntpprop.port_dst = port;
		ntpprop.ntp_cnt = 10; //10 попыток
		ntpprop.ntp_timer = 5;//5 секунд до следующей попытки
		ntpprop.set=1;//флаг запроса времени взведен
		memcpy(ntpprop.macaddr_dst,frame->addr_dest,6);
		ntp_request(ntpprop.ip_dst,ntpprop.port_dst);
		usartprop.is_ip=0;
	}
}
//-----------------функцию-обработчик прерываний по окончанию приема заданного количества байт в шину USART------------------------------
void UART2_RxCpltCallback(void)
{
	uint8_t b;
	b=str[0];
	//если вдруг случайно превысим длину буфера
	if(usartprop.usart_cnt>25)
	{
		usartprop.usart_cnt=0;
	}
	else if(b == 'a')
	{
		usartprop.is_ip=1;//статус отправки ARP-запроса
		net_cmd();
	}
	else if (b=='u')
	{
		usartprop.is_ip=2;//статус попытки отправить UDP-пакет
		net_cmd();
	}
	else if (b=='p')
	{
		usartprop.is_ip=4;//статус попытки отправить ICMP-пакет
		net_cmd();
	}
	else if (b=='n')
	{
		usartprop.is_ip=6;//статус попытки отправить NTP-пакет
		net_cmd();
	}
	else
	{
		usartprop.usart_buf[usartprop.usart_cnt] = b;
		usartprop.usart_cnt++;
	}
	HAL_UART_Receive_IT(&huart2, (uint8_t*)str,1);
}
//---------------функцию-обработчик прерывания по совпадению данного таймера--------------------------------
void TIM_PeriodElapsedCallback(void)
{
  //считаем секунды и записываем их в clock_cnt
  clock_cnt++;
	if (ntpprop.set)
	{
		ntpprop.ntp_timer--;
		if ((ntpprop.ntp_timer<0)&&(ntpprop.ntp_cnt>0))
		{
			ntpprop.ntp_timer = 5;
			ntpprop.ntp_cnt--;
			sprintf(str1,"ntp_cnt: %d\r\n",ntpprop.ntp_cnt);
			HAL_UART_Transmit(&huart2,(uint8_t*)str1,strlen(str1),0x1000);
			ntp_request(ntpprop.ip_dst,ntpprop.port_dst);
		}
		else if (ntpprop.ntp_cnt<=0)
		{
			//сбросим все флаги и счетчики
			ntpprop.set=0;
			ntpprop.ntp_cnt=0;
			ntpprop.ntp_timer=0;
		}
	}
}
//-----------------------------------------------


