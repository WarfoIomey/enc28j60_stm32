/*
 * ecn28j60.c
 *
 *  Created on: 14 окт. 2022 г.
 *      Author: kiril
 */
#include "enc28j60.h"
//-----------------------------------------------
extern SPI_HandleTypeDef hspi2;
extern UART_HandleTypeDef huart2;
//-----------------------------------------------
static uint8_t Enc28j60Bank;//переменная для хранения номера текущего банка
static int gNextPacketPtr;
uint8_t macaddr[6]=MAC_ADDR;//наш физический адрес
//----------------функцию задержки в микросекундах-------------------------------
__STATIC_INLINE void DelayMicro(__IO uint32_t micros)
{
	micros *= (SystemCoreClock / 1000000) / 5;
	/* Wait till done */
	while (micros--) ;
}
//-----------------------------------------------
static void Error (void)
{
	//LD_ON;
}
//------------------функция для работы с шиной SPI -----------------------------
uint8_t SPIx_WriteRead(uint8_t Byte)
{
	uint8_t receivedbyte = 0;
	if(HAL_SPI_TransmitReceive(&hspi2,(uint8_t*) &Byte,(uint8_t*) &receivedbyte,1,0x1000)!=HAL_OK)
	{
		Error();
	}
	return receivedbyte;
}
//-----------------функция для работы с шиной SPI------------------------------
void SPI_SendByte(uint8_t bt)
{
	SPIx_WriteRead(bt);
}
//----------------функция для работы с шиной SPI-------------------------------
uint8_t SPI_ReceiveByte(void)
{
	uint8_t bt = SPIx_WriteRead(0xFF);
	return bt;
}
//-----------------Операция записи байта в регистр------------------------------
void enc28j60_writeOp(uint8_t op, uint8_t addres, uint8_t data)
{
	SS_SELECT();
	SPI_SendByte(op|(addres&ADDR_MASK));
	SPI_SendByte(data);
	SS_DESELECT();
}
//-----------------операция чтения------------------------------
static uint8_t enc28j60_readOp(uint8_t op, uint8_t addres)
{
	uint8_t result;
	SS_SELECT();
	SPI_SendByte(op|(addres&ADDR_MASK));
	SPI_SendByte(0x00);
	//пропускаем ложный байт
	if(addres & 0x80) SPI_ReceiveByte();
	result = SPI_ReceiveByte();
	SS_DESELECT();
	return result;
}
//-------------------чтение буфера----------------------------
static void enc28j60_readBuf(uint16_t len, uint8_t* data)
{
	SS_SELECT();
	SPI_SendByte(ENC28J60_READ_BUF_MEM);
	while(len--){
		*data++=SPIx_WriteRead(0x00);
	}
	SS_DESELECT();
}
//--------------------запись буфера---------------------------
static void enc28j60_writeBuf(uint16_t len, uint8_t* data)
{
	SS_SELECT();
	SPI_SendByte(ENC28J60_WRITE_BUF_MEM);
	while(len--)
		SPI_SendByte(*data++);
	SS_DESELECT();
}
//-----------------функция установки текущего банка------------------------------
void enc28j60_SetBank(uint8_t addres)
{
	if((addres&BANK_MASK)!=Enc28j60Bank)
	{
		enc28j60_writeOp(ENC28J60_BIT_FIELD_CLR,ECON1,ECON1_BSEL1|ECON1_BSEL0);
		Enc28j60Bank = addres&BANK_MASK;
		enc28j60_writeOp(ENC28J60_BIT_FIELD_SET,ECON1,Enc28j60Bank>>5);
	}
}
//-------------------запись обычного регистра управленния----------------------------
void enc28j60_writeRegByte(uint8_t addres, uint8_t data)
{
	enc28j60_SetBank(addres);
	enc28j60_writeOp(ENC28J60_WRITE_CTRL_REG,addres,data);
}
//---------------------чтение обычного регистра управления--------------------------
static uint8_t enc28j60_readRegByte(uint8_t addres)
{
	enc28j60_SetBank(addres);
	return enc28j60_readOp(ENC28J60_READ_CTRL_REG,addres);
}
//--------------------запись данных в двухбайтовые регистры---------------------------
void enc28j60_writeReg(uint8_t addres, uint16_t data)
{
	enc28j60_writeRegByte(addres, data);
	enc28j60_writeRegByte(addres+1, data>>8);
}
//------------------запись в регистр Phy-----------------------------
static void enc28j60_writePhy(uint8_t addres, uint16_t data)
{
	enc28j60_writeRegByte(MIREGADR, addres);
	enc28j60_writeRegByte(MIWR, data);
	while(enc28j60_readRegByte(MISTAT)&MISTAT_BUSY)
	;
}
//-----------------------------------------------
void enc28j60_ini(void)
{
	//LD_OFF;
	enc28j60_writeOp(ENC28J60_SOFT_RESET,ENC28J60_SOFT_RESET,0);
	HAL_Delay(2);
	//проверим, что всё перезагрузилось
	while(!enc28j60_readOp(ENC28J60_READ_CTRL_REG,ESTAT)&ESTAT_CLKRDY)
		;
	//настроим буферы
	enc28j60_writeReg(ERXST,RXSTART_INIT);
	enc28j60_writeReg(ERXRDPT,RXSTART_INIT);
	enc28j60_writeReg(ERXND,RXSTOP_INIT);
	enc28j60_writeReg(ETXST,TXSTART_INIT);
	enc28j60_writeReg(ETXND,TXSTOP_INIT);
	//Enable Broadcast
	enc28j60_writeRegByte(ERXFCON,enc28j60_readRegByte(ERXFCON)|ERXFCON_BCEN);
	//настраиваем канальный уровень
	enc28j60_writeRegByte(MACON1,MACON1_MARXEN|MACON1_TXPAUS|MACON1_RXPAUS);
	enc28j60_writeRegByte(MACON2,0x00);
	enc28j60_writeOp(ENC28J60_BIT_FIELD_SET,MACON3,MACON3_PADCFG0|MACON3_TXCRCEN|MACON3_FRMLNEN);
	enc28j60_writeReg(MAIPG,0x0C12);
	enc28j60_writeRegByte(MABBIPG,0x12);//промежуток между фреймами
	enc28j60_writeReg(MAMXFL,MAX_FRAMELEN);//максимальный размер фрейма
	enc28j60_writeRegByte(MAADR5,macaddr[0]);//Set MAC addres
	enc28j60_writeRegByte(MAADR4,macaddr[1]);
	enc28j60_writeRegByte(MAADR3,macaddr[2]);
	enc28j60_writeRegByte(MAADR2,macaddr[3]);
	enc28j60_writeRegByte(MAADR1,macaddr[4]);
	enc28j60_writeRegByte(MAADR0,macaddr[5]);
	//настраиваем физический уровень
	enc28j60_writePhy(PHCON2,PHCON2_HDLDIS);//отключаем loopback
	enc28j60_writePhy(PHLCON,PHLCON_LACFG2| //светодиоды
		PHLCON_LBCFG2|PHLCON_LBCFG1|PHLCON_LBCFG0|
		PHLCON_LFRQ0|PHLCON_STRCH);
	enc28j60_SetBank(ECON1);
	enc28j60_writeOp(ENC28J60_BIT_FIELD_SET,EIE,EIE_INTIE|EIE_PKTIE);
	enc28j60_writeOp(ENC28J60_BIT_FIELD_SET,ECON1,ECON1_RXEN);//разрешаем приём пакетов
	//Включим делитель частоты генератора 2
	enc28j60_writeRegByte(ECOCON,0x02);
	DelayMicro(15);
}
//-------------------функция приема пакета и его последующего возврата----------------------------
uint16_t enc28j60_packetReceive(uint8_t* buf, uint16_t buflen)
{
	uint16_t len=0;
	if(enc28j60_readRegByte(EPKTCNT)>0)//проверка количества принятых на данный момент пакетов
	{
		enc28j60_writeReg(ERDPT,gNextPacketPtr);// установим указатель в регистр ERDPT установим указатель
		//считаем заголовок
		struct{
			uint16_t nextPacket;
			uint16_t byteCount;
			uint16_t status;
		} header;
		enc28j60_readBuf(sizeof(header), (uint8_t*)&header);//считаем заголовок пакета, содержащий укзатель на следующий пакет, количество байтов и статус пакета
		gNextPacketPtr=header.nextPacket;//запись значения указателя в глобальную переменную
		len = header.byteCount-4;//Инициализируем переменную длины пакеты, отрезав от неё контрольную сумму
		if(len>buflen) len=buflen;//Укоротим длину до заданной во входном параметре
		if((header.status&0x80)==0) len=0;//Проверим статус и считаем буфер
		else enc28j60_readBuf(len, buf);
		buf[len]=0;//Завершим буфер нулём
		if(gNextPacketPtr-1>RXSTOP_INIT)//Инициализируем указатель буфера на адрес следующего пакета
			enc28j60_writeReg(ERXRDPT, RXSTOP_INIT);
		else
			enc28j60_writeReg(ERXRDPT, gNextPacketPtr-1);
		enc28j60_writeOp(ENC28J60_BIT_FIELD_SET,ECON2,ECON2_PKTDEC);//Счётчик принятых пакетов также уменьшим на 1 и выйдем из условия
	}
	return len;//Возвратим длину принятого пакета
}
//-----------------функция передачи пакетов------------------------------
void enc28j60_packetSend(uint8_t* buf, uint16_t buflen)
{
	//Подождём, пока установится бит TXRTS в регистре ECON1, что означает готовность нашего передатчика передавать информацию
	while(!(enc28j60_readOp(ENC28J60_READ_CTRL_REG,ECON1))&ECON1_TXRTS)
	{
		if(enc28j60_readRegByte(EIR)&EIR_TXERIF)
		{
			enc28j60_writeOp(ENC28J60_BIT_FIELD_SET, ECON1,ECON1_TXRST);
			enc28j60_writeOp(ENC28J60_BIT_FIELD_CLR, ECON1,ECON1_TXRST);
		}
	}
	//записываем и отправляем пакет
	enc28j60_writeReg(EWRPT, TXSTART_INIT);
	enc28j60_writeReg(ETXND, TXSTART_INIT+buflen);
	enc28j60_writeBuf(1,(uint8_t*)"\x00");
	enc28j60_writeBuf(buflen,buf);
	enc28j60_writeOp(ENC28J60_BIT_FIELD_SET, ECON1,ECON1_TXRTS);
}
//-----------------------------------------------

