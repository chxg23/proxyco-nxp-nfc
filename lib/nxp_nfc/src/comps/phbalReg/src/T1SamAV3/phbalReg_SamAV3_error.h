#ifndef PHBALREG_T1SAMAV3_ERROR_H
#define PHBALREG_T1SAMAV3_ERROR_H

#include <assert.h>

#define PHBAL_REG_T1SAMAV3_ASSERT assert

typedef int32_t phbalReg_T1SamAV3_error_t;

#define PHBAL_REG_T1SAMAV3_SUCCESS					0x0000

#define PHBAL_REG_T1SAMAV3_BASE_ERR					0x1000
#define PHBAL_REG_T1SAMAV3_INVALID_ARGS				0x1001			// Arguments provided are not valid
#define PHBAL_REG_T1SAMAV3_INVALID_PK				0x1002			// PK provided is not valid
#define PHBAL_REG_T1SAMAV3_INVALID_SIG				0x1003			// Signature check failed
#define PHBAL_REG_T1SAMAV3_INVALID_PLAIN			0x1004			// Plain data invalid
#define PHBAL_REG_T1SAMAV3_VERIFY_FAILURE			0x1005			// Signature check failed

#define PHBAL_REG_T1SAMAV3_RCV_BASE_ERR				0x2000
#define PHBAL_REG_T1SAMAV3_RCV_UNEXPECTED_LEN		0x2001			// Block received has unexpected length
#define PHBAL_REG_T1SAMAV3_RCV_UNEXPECED_SEQ		0x2002			// Block reeceived has unexpected sequence number
#define PHBAL_REG_T1SAMAV3_RCV_UNEXPECTED_PCB		0x2003			// Block receved has unexpected PCB value
#define PHBAL_REG_T1SAMAV3_RCV_UNEXPECTED_LRC		0x2004			// Block received has unexpected LRC value
#define PHBAL_REG_T1SAMAV3_RCV_UNEXPECTED_NAD		0x2005			// Block received has unexpected NAD value
#define PHBAL_REG_T1SAMAV3_RCV_LRC_ERR				0x2006			// Received LRC error ack
#define PHBAL_REG_T1SAMAV3_RCV_OTHER_ERR			0x2007			// Received other error ack
#define PHBAL_REG_T1SAMAV3_RCV_INVALID_ERR			0x2008			// Received invalid error ack

#define PHBAL_REG_T1SAMAV3_APDU_BASE_ERR			0x4000
#define PHBAL_REG_T1SAMAV3_APDU_NOT_STARTED			0x4001			// APDU payload was added before starting any apdu
#define PHBAL_REG_T1SAMAV3_APDU_PENDING				0x4002			// There is another APDU pending to be sent or aborted
#define PHBAL_REG_T1SAMAV3_APDU_TOO_LONG			0x4003			// APDU too long
#define PHBAL_REG_T1SAMAV3_APDU_TLV_NOT_STARTED		0x4004			// TLV data is being added to the APDU before any TLV payload was started
#define PHBAL_REG_T1SAMAV3_APDU_INCOMPLETE			0x4005			// TLV was not completed
#define PHBAL_REG_T1SAMAV3_APDU_INVALID_CMD			0x4006			// Invalid APDU

#define PHBAL_REG_T1SAMAV3_ISO7816_UART_INVALID_INIT	0x5000
#define PHBAL_REG_T1SAMAV3_ISO7816_UART_BUSY			0x5001		//Driver doing some operation
#define PHBAL_REG_T1SAMAV3_ISO7816_UART_TX_BUSY			0x5002		//Driver already sending data
#define PHBAL_REG_T1SAMAV3_ISO7816_UART_TX_ABORTED		0x5003		//Transfer is aborted
#define PHBAL_REG_T1SAMAV3_ISO7816_UART_TX_INVALID_ADD	0x5004		//Invalid data recipient
#define PHBAL_REG_T1SAMAV3_ISO7816_UART_RX_NO_DATA		0x5005		//There is no data to read, retry again
#define PHBAL_REG_T1SAMAV3_ISO7816_UART_RX_BUSY			0x5006		//Driver already receiving data
#define PHBAL_REG_T1SAMAV3_ISO7816_UART_RX_ABORTED		0x5007		//Reception is aborted
#define PHBAL_REG_T1SAMAV3_ISO7816_UART_RX_INVALID_ADD	0x5008		//Invalid data recipient
#define PHBAL_REG_T1SAMAV3_ISO7816_UART_RX_INTERNAL		0x5009		//UARTE peripheral error
#define PHBAL_REG_T1SAMAV3_ISO7816_UART_RX				0x500A		//UARTE peripheral RX error
#define PHBAL_REG_T1SAMAV3_ISO7816_CLK_INVALID_INIT		0x500B		//PWM instance is already initialized

#endif /* PHBALREG_T1SAMAV3_ERROR_H */
