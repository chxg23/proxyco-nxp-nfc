/*
*         Copyright (c), NXP Semiconductors Bengaluru / India
*
*                     (C)NXP Semiconductors
*       All rights are reserved. Reproduction in whole or in part is
*      prohibited without the written consent of the copyright owner.
*  NXP reserves the right to make changes without notice at any time.
* NXP makes no warranty, expressed, implied or statutory, including but
* not limited to any implied warranty of merchantability or fitness for any
*particular purpose, or that the use will not infringe any third party patent,
* copyright or trademark. NXP must not be liable for any loss or damage
*                          arising from its use.
*/

#ifndef PHHALHW_SAMAV3_CMD_H
#define PHHALHW_SAMAV3_CMD_H

#include <nxp_nfc/ph_Status.h>
#include <nxp_nfc/phhalHw.h>

#ifdef __cplusplus
extern "C" {
#endif	/* __cplusplus */

#ifdef NXPBUILD__PHHAL_HW_SAMAV3

#define PHHAL_HW_SAMAV3_HC_SAM_UID_SIZE								0x07U   /**< Length of the SAM UID */
#define PHHAL_HW_SAMAV3_CMD_GET_VERSION_RESPONSE_LENGTH				0x1F    /**< Response length for GetVersion command */
#define PHHAL_HW_SAMAV3_CMD_GET_VERSION_RESPONSE_UID_OFFSET			0x0E    /**< Offset of first UID byte field in the Version field */
#define PHHAL_HW_SAMAV3_KEYENTRY_SIZE								0x40U   /**< Define the maximum possible size of a key entry. */
#define PHHAL_HW_SAMAV3_CMD_UPDATE_LIMIT_MASK						0x80U
#define PHHAL_HW_SAMAV3_CMD_UPDATE_KEYNO_CKUC_MASK					0x40U
#define PHHAL_HW_SAMAV3_CMD_UPDATE_KEY_VCKUC_MASK					0x20U

/** \defgroup phhalHw_SamAV3_Cmd_Status SAM Status Codes
 * \brief Defines used accross the whole SAM implementation for the status codes returned by Sam hardware.
 * @{
 */
#define PHHAL_HW_SAMAV3_RET_CODE_HW_EEPROM							0x6400	/**< EEProm failure. */
#define PHHAL_HW_SAMAV3_RET_CODE_HW_RC5XX							0x6401	/**< RC failure. */
#define PHHAL_HW_SAMAV3_RET_CODE_KEY_CREATE_FAILED					0x6501	/**< Key creation failure. */
#define PHHAL_HW_SAMAV3_RET_CODE_KEY_REF_NO_INVALID					0x6502	/**< SAM key reference error. */
#define PHHAL_HW_SAMAV3_RET_CODE_KEY_KUC_NO_INVALID					0x6503	/**< SAM key usage counter error. */
#define PHHAL_HW_SAMAV3_RET_CODE_HW_EE_HIGH_VOLTAGE					0x6581	/**< Memory failure. */
#define PHHAL_HW_SAMAV3_RET_CODE_ISO7816_WRONG_LENGTH_LC			0x6700	/**< Wrong length; no further indication. */
#define PHHAL_HW_SAMAV3_RET_CODE_INCOMPLETE_REFERENCE_DATA			0x6781	/**< Incompatible referenced data. */
#define PHHAL_HW_SAMAV3_RET_CODE_SECURITY_STATUS_NOT_SATISFIED		0x6782	/**< Security status not satisfied. */
#define PHHAL_HW_SAMAV3_RET_CODE_SECURE_MESSAGING_NOT_SUPPORTED		0x6882	/**< Secure messaging not supported. */
#define PHHAL_HW_SAMAV3_RET_CODE_INCOMPLETE_CHAINING				0x6883	/**< Command aborted - final chained command expected; running command aborted, new command ignored. */
#define PHHAL_HW_SAMAV3_RET_CODE_COMMAND_CHAINING_NOT_SUPPORTED		0x6884	/**< Command chaining not supported. */
#define PHHAL_HW_SAMAV3_RET_CODE_INTEGRITY_ERROR					0x6982	/**< Security status not satisfied. */
#define PHHAL_HW_SAMAV3_RET_CODE_INCORRECT_LENGTH					0x6983	/**< Incorrect length. */
#define PHHAL_HW_SAMAV3_RET_CODE_KEY_INTEGRITY_ERROR				0x6984	/**< Referenced data invalid. */
#define PHHAL_HW_SAMAV3_RET_CODE_COND_USE_NOT_SATISFIED				0x6985	/**< Conditions of use not satisfied. */
#define PHHAL_HW_SAMAV3_RET_CODE_ISO7816_COMMAND_NOT_ALLOWED		0x6986	/**< Command not allowed. */
#define PHHAL_HW_SAMAV3_RET_CODE_INCORRECT_SECURE_MESSAGING_DATA	0x6988	/**< Incorrect secure messaging data objects. */
#define PHHAL_HW_SAMAV3_RET_CODE_ISO7816_WRONG_PARAMS_FOR_INS		0x6A80	/**< Wrong datafield parameter. */
#define PHHAL_HW_SAMAV3_RET_CODE_FUNCTION_NOT_SUPPORTED				0x6A81	/**< Function not supported. */
#define PHHAL_HW_SAMAV3_RET_CODE_KEY_VERSION_INVALID				0x6A82	/**< Key version not found. */
#define PHHAL_HW_SAMAV3_RET_CODE_RECORD_NOT_FOUND					0x6A83	/**< Record not found. */
#define PHHAL_HW_SAMAV3_RET_CODE_HOST_PROTECTION_ERROR				0x6A84	/**< Host protocol error. */
#define PHHAL_HW_SAMAV3_RET_CODE_ISO7816_WRONG_P1P2					0x6A86	/**< Incorrect parameters P1-P2. */
#define PHHAL_HW_SAMAV3_RET_CODE_REFERENCED_DATA_NOT_FOUND			0x6A88	/**< Referenced data or reference data not found. */
#define PHHAL_HW_SAMAV3_RET_CODE_ISO7816_WRONG_LE					0x6C00	/**< Incorrect Le value. */
#define PHHAL_HW_SAMAV3_RET_CODE_ISO7816_UNKNOWN_INS				0x6D00	/**< Instruction code not supported or invalid or not available in the current state of the SAM. */
#define PHHAL_HW_SAMAV3_RET_CODE_ISO7816_WRONG_CLASS				0x6E00	/**< Class not supported. */
#define PHHAL_HW_SAMAV3_RET_CODE_NO_PRECISE_DIAGNOSIS				0x6F00	/**< No precise diagnosis. */
#define PHHAL_HW_SAMAV3_RET_CODE_OK									0x9000	/**< Correct execution. */
#define PHHAL_HW_SAMAV3_RET_CODE_OK_1BIT							0x9001  /**< Correct execution, 1 bits received */
#define PHHAL_HW_SAMAV3_RET_CODE_OK_2BIT							0x9002  /**< Correct execution, 2 bits received */
#define PHHAL_HW_SAMAV3_RET_CODE_OK_3BIT							0x9003  /**< Correct execution, 3 bits received */
#define PHHAL_HW_SAMAV3_RET_CODE_OK_4BIT							0x9004  /**< Correct execution, 4 bits received */
#define PHHAL_HW_SAMAV3_RET_CODE_OK_5BIT							0x9005  /**< Correct execution, 5 bits received */
#define PHHAL_HW_SAMAV3_RET_CODE_OK_6BIT							0x9006  /**< Correct execution, 6 bits received */
#define PHHAL_HW_SAMAV3_RET_CODE_OK_7BIT							0x9007  /**< Correct execution, 7 bits received */
#define PHHAL_HW_SAMAV3_RET_CODE_CRYPTO_FAILURE						0x901E	/**< Correct execution - authentication failed. */
#define PHHAL_HW_SAMAV3_RET_CODE_OK_CHAINING_ACTIVE					0x90AF	/**< Correct execution - more date expected. */
#define PHHAL_HW_SAMAV3_RET_CODE_OK_CHAINING_ACTIVE_EXT				0x90AE	/**< Correct execution - more date expected (SAM-Host secure messaging to be applied on each command exchange) */
#define PHHAL_HW_SAMAV3_RET_CODE_PROT_MIFARE_PLUS_ERROR				0x90BE	/**< Correct execution - MIFARE Plus PICC protocol error. */
#define PHHAL_HW_SAMAV3_RET_CODE_INS_MIFARE_PLUS_ERROR				0x90BF	/**< Correct execution - error code returned by MIFARE Plus PICC. */
#define PHHAL_HW_SAMAV3_RET_CODE_ISO_UID_INCOMPLETE					0x90C0	/**< Correct execution - UID not complete. */
#define PHHAL_HW_SAMAV3_RET_CODE_PROT_DESFIRE_ERROR					0x90DF	/**< Correct execution - error code returned by DESFire PICC. */
#define PHHAL_HW_SAMAV3_RET_CODE_COMM_IO_TIMEOUT					0x90E0	/**< Correct execution - no card in field. */
#define PHHAL_HW_SAMAV3_RET_CODE_COMM_BITCNT_PROTOCOL				0x90E1	/**< ISO/IEC 14443 protocol error. */
#define PHHAL_HW_SAMAV3_RET_CODE_COMM_PARITY						0x90E2	/**< Parity or CRC error. */
#define PHHAL_HW_SAMAV3_RET_CODE_COMM_FIFO_BUF_OVERFLOW				0x90E3	/**< Buffer overflow. */
#define PHHAL_HW_SAMAV3_RET_CODE_COMM_CRC_FAILURE					0x90E4	/**< BFL Integrity error. */
#define PHHAL_HW_SAMAV3_RET_CODE_COMM_RF_FAILURE					0x90E5	/**< RF Field inactive. */
#define PHHAL_HW_SAMAV3_RET_CODE_COMM_TEMP_FAILURE					0x90E6	/**< Temperature error. */
#define PHHAL_HW_SAMAV3_RET_CODE_COMM_FIFO_WRITE					0x90E7	/**< FIFO write error. */
#define PHHAL_HW_SAMAV3_RET_CODE_COMM_COLLISION						0x90E8	/**< Collision error. */
#define PHHAL_HW_SAMAV3_RET_CODE_COMM_INTERNAL_BUF_OVERFLOW			0x90E9	/**< Internal transaction buffer overflow error. */
#define PHHAL_HW_SAMAV3_RET_CODE_ISO_WRONG_BNR						0x90EB	/**< Incorrect block number. */
#define PHHAL_HW_SAMAV3_RET_CODE_ISO_INVALID_FORMAT					0x90EC	/**< Invalid format. */
#define PHHAL_HW_SAMAV3_RET_CODE_ISO_INVALID_PARAMETER				0x90ED	/**< Invalid parameter. */
#define PHHAL_HW_SAMAV3_RET_CODE_PROT_MIFARE_ERROR					0x90EF	/**< Correct execution - error code returned by PICC. */
#define PHHAL_HW_SAMAV3_RET_CODE_PROT_MIFARE_NACK_0					0x90F0	/**< MIFARE (R) NACK 0 received. */
#define PHHAL_HW_SAMAV3_RET_CODE_PROT_MIFARE_NACK_1					0x90F1	/**< MIFARE (R) NACK 1 received. */
#define PHHAL_HW_SAMAV3_RET_CODE_PROT_MIFARE_NACK_4					0x90F4	/**< MIFARE (R) NACK 4 received. */
#define PHHAL_HW_SAMAV3_RET_CODE_PROT_MIFARE_NACK_5					0x90F5	/**< MIFARE (R) NACK 5 received. */
/**
 * end of phhalHw_SamAV3_Cmd_Status
 * @}
 */

/** \defgroup phhalHw_SamAV3_Cmd_Cust_Errors SAM Custom Error Codes
 * \brief SamAV3 Custom Error Codes for the respective status codes returned by Sam hardwre.
 * @{
 */

/** \name Custom error codes compatible with Sam AV2 hardware. */
/* @{ */
#define PHHAL_HW_SAMAV3_ERR_HW_EEPROM						(PH_ERR_CUSTOM_BEGIN + 0)	/**< Custom error code for Sam's Resp.ISO6400 */
#define PHHAL_HW_SAMAV3_ERR_HW_RC5XX						(PH_ERR_CUSTOM_BEGIN + 1)	/**< Custom error code for Sam's Resp.ISO6401 */
#define PHHAL_HW_SAMAV3_ERR_KEY_CREATE_FAILED				(PH_ERR_CUSTOM_BEGIN + 2)	/**< Custom error code for Sam's Resp.ISO6501 */
#define PHHAL_HW_SAMAV3_ERR_KEY_REF_NO_INVALID				(PH_ERR_CUSTOM_BEGIN + 3)	/**< Custom error code for Sam's Resp.ISO6502 */
#define PHHAL_HW_SAMAV3_ERR_KEY_KUC_NO_INVALID				(PH_ERR_CUSTOM_BEGIN + 4)	/**< Custom error code for Sam's Resp.ISO6503 */
#define PHHAL_HW_SAMAV3_ERR_HW_EE_HIGH_VOLTAGE				(PH_ERR_CUSTOM_BEGIN + 5)	/**< Custom error code for Sam's Resp.ISO6581 */
#define PHHAL_HW_SAMAV3_ERR_ISO7816_WRONG_LENGTH_LC			(PH_ERR_CUSTOM_BEGIN + 6)	/**< Custom error code for Sam's Resp.ISO6700 */
#define PHHAL_HW_SAMAV3_ERR_INCOMPLETE_CHAINING				(PH_ERR_CUSTOM_BEGIN + 7)	/**< Custom error code for Sam's Resp.ISO6883 */
#define PHHAL_HW_SAMAV3_ERR_INTEGRITY_ERROR					(PH_ERR_CUSTOM_BEGIN + 8)	/**< Custom error code for Sam's Resp.ISO6982 */
#define PHHAL_HW_SAMAV3_ERR_KEY_INTEGRITY_ERROR				(PH_ERR_CUSTOM_BEGIN + 9)	/**< Custom error code for Sam's Resp.ISO6984 */
#define PHHAL_HW_SAMAV3_ERR_COND_USE_NOT_SATISFIED			(PH_ERR_CUSTOM_BEGIN + 10)	/**< Custom error code for Sam's Resp.ISO6985 */
#define PHHAL_HW_SAMAV3_ERR_ISO7816_COMMAND_NOT_ALLOWED		(PH_ERR_CUSTOM_BEGIN + 11)	/**< Custom error code for Sam's Resp.ISO6986 */
#define PHHAL_HW_SAMAV3_ERR_ISO7816_WRONG_PARAMS_FOR_INS	(PH_ERR_CUSTOM_BEGIN + 12)	/**< Custom error code for Sam's Resp.ISO6A80 */
#define PHHAL_HW_SAMAV3_ERR_KEY_VERSION_INVALID				(PH_ERR_CUSTOM_BEGIN + 13)	/**< Custom error code for Sam's Resp.ISO6A82 */
#define PHHAL_HW_SAMAV3_ERR_HOST_PROTECTION					(PH_ERR_CUSTOM_BEGIN + 14)	/**< Custom error code for Sam's Resp.ISO6A84 */
#define PHHAL_HW_SAMAV3_ERR_ISO7816_WRONG_P1P2				(PH_ERR_CUSTOM_BEGIN + 15)	/**< Custom error code for Sam's Resp.ISO6A86 */
#define PHHAL_HW_SAMAV3_ERR_ISO7816_WRONG_LE				(PH_ERR_CUSTOM_BEGIN + 16)	/**< Custom error code for Sam's Resp.ISO6C00 */
#define PHHAL_HW_SAMAV3_ERR_ISO7816_UNKNOWN_INS				(PH_ERR_CUSTOM_BEGIN + 17)	/**< Custom error code for Sam's Resp.ISO6D00 */
#define PHHAL_HW_SAMAV3_ERR_ISO7816_UNKNOWN_CLASS			(PH_ERR_CUSTOM_BEGIN + 18)	/**< Custom error code for Sam's Resp.ISO6E00 */
#define PHHAL_HW_SAMAV3_ERR_CRYPTO							(PH_ERR_CUSTOM_BEGIN + 19)	/**< Custom error code for Sam's Resp.ISO901E */
#define PHHAL_HW_SAMAV3_ERR_MIFARE_PLUS_CRYPTO				(PH_ERR_CUSTOM_BEGIN + 20)	/**< Custom error code for Sam's Resp.ISO90BE */
#define PHHAL_HW_SAMAV3_ERR_MIFARE_PLUS_GEN					(PH_ERR_CUSTOM_BEGIN + 21)	/**< Custom error code for Sam's Resp.ISO90BF */
#define PHHAL_HW_SAMAV3_ERR_ISO_UID_INCOMPLETE				(PH_ERR_CUSTOM_BEGIN + 22)	/**< Custom error code for Sam's Resp.ISO90C0 */
#define PHHAL_HW_SAMAV3_ERR_DESFIRE_GEN						(PH_ERR_CUSTOM_BEGIN + 23)	/**< Custom error code for Sam's Resp.ISO90DF */
#define PHHAL_HW_SAMAV3_ERR_ISO_WRONG_BNR					(PH_ERR_CUSTOM_BEGIN + 25)	/**< Custom error code for Sam's Resp.ISO90EB */
#define PHHAL_HW_SAMAV3_ERR_ISO_INVALID_FORMAT				(PH_ERR_CUSTOM_BEGIN + 26)	/**< Custom error code for Sam's Resp.ISO90EC */
#define PHHAL_HW_SAMAV3_ERR_ISO_INVALID_PARAMETER			(PH_ERR_CUSTOM_BEGIN + 27)	/**< Custom error code for Sam's Resp.ISO90ED */
#define PHHAL_HW_SAMAV3_ERR_MIFARE_GEN						(PH_ERR_CUSTOM_BEGIN + 28)	/**< Custom error code for Sam's Resp.ISO90EF */
#define PHHAL_HW_SAMAV3_ERR_MIFARE_NAK0						(PH_ERR_CUSTOM_BEGIN + 29)	/**< Custom error code for Sam's Resp.ISO90F0 */
#define PHHAL_HW_SAMAV3_ERR_MIFARE_NAK1						(PH_ERR_CUSTOM_BEGIN + 30)	/**< Custom error code for Sam's Resp.ISO90F1 */
#define PHHAL_HW_SAMAV3_ERR_MIFARE_NAK4						(PH_ERR_CUSTOM_BEGIN + 31)	/**< Custom error code for Sam's Resp.ISO90F4 */
#define PHHAL_HW_SAMAV3_ERR_MIFARE_NAK5						(PH_ERR_CUSTOM_BEGIN + 32)	/**< Custom error code for Sam's Resp.ISO90F5 */
#define PHHAL_HW_SAMAV3_ERR_OK_CHAINING_ACTIVE				(PH_ERR_CUSTOM_BEGIN + 35)	/**< Custom error code for Sam's Resp.ISO90AF */
/* @} */

/** \name Custom error codes for Sam AV3 hardware. These error codes are not backward compatible with Sam AV2 hardware. */
/* @{ */
#define PHHAL_HW_SAMAV3_ERR_INCOMPLETE_REFERENCE_DATA		(PH_ERR_CUSTOM_BEGIN + 36)	/**< Custom error code for Sam's Resp.ISO6781 */
#define PHHAL_HW_SAMAV3_ERR_SECURITY_STATUS_NOT_SATISFIED	(PH_ERR_CUSTOM_BEGIN + 37)	/**< Custom error code for Sam's Resp.ISO6782 */
#define PHHAL_HW_SAMAV3_ERR_SECURE_MESSAGING_NOT_SUPPORTED	(PH_ERR_CUSTOM_BEGIN + 38)	/**< Custom error code for Sam's Resp.ISO6882 */
#define PHHAL_HW_SAMAV3_ERR_COMMAND_CHAINING_NOT_SUPPORTED	(PH_ERR_CUSTOM_BEGIN + 39)	/**< Custom error code for Sam's Resp.ISO6884 */
#define PHHAL_HW_SAMAV3_ERR_INCORRECT_LENGTH				(PH_ERR_CUSTOM_BEGIN + 40)	/**< Custom error code for Sam's Resp.ISO6983 */
#define PHHAL_HW_SAMAV3_ERR_INCORRECT_SECURE_MESSAGING_DATA	(PH_ERR_CUSTOM_BEGIN + 41)	/**< Custom error code for Sam's Resp.ISO6988 */
#define PHHAL_HW_SAMAV3_ERR_FUNCTION_NOT_SUPPORTED			(PH_ERR_CUSTOM_BEGIN + 42)	/**< Custom error code for Sam's Resp.ISO6A81 */
#define PHHAL_HW_SAMAV3_ERR_RECORD_NOT_FOUND				(PH_ERR_CUSTOM_BEGIN + 43)	/**< Custom error code for Sam's Resp.ISO6A83 */
#define PHHAL_HW_SAMAV3_ERR_REFERENCED_DATA_NOT_FOUND		(PH_ERR_CUSTOM_BEGIN + 44)	/**< Custom error code for Sam's Resp.ISOA88 */
#define PHHAL_HW_SAMAV3_ERR_NO_PRECISE_DIAGNOSIS			(PH_ERR_CUSTOM_BEGIN + 45)	/**< Custom error code for Sam's Resp.ISO6F00 */
#define PHHAL_HW_SAMAV3_ERR_PROGRAMMABLE_LOGIC				(PH_ERR_CUSTOM_BEGIN + 46)	/**< Custom error code for Sam's Resp.ISOXXXX */
#define PHHAL_HW_SAMAV3_ERR_OK_CHAINING_ACTIVE_EXT			(PH_ERR_CUSTOM_BEGIN + 47)	/**< Custom error code for Sam's Resp.ISO90Ae */
/* @} */

/**
 * end of phhalHw_SamAV3_Cmd_Cust_Errors
 * @}
 */

/** \defgroup phhalHw_SamAV3_Cmd_Global SAM Global values.
 * \brief SamAV3 Global macro values that are used for most of the commands.
 * @{
 */

#define PHHAL_HW_SAMAV3_ISO7816_LAST_FRAME							0x00U	/**< Indication last frame in a cipher sequence */
#define PHHAL_HW_SAMAV3_ISO7816_CHAINED_FRAME						0xAFU	/**< Indication lnon ast frame in a cipher sequence */

/**
 * end of phhalHw_SamAV3_Cmd_Global
 * @}
 */

/** Macros used for command buffer and other buffer processing. */
#define PHHAL_HW_SAMAV3_ISO7816_HEADER_LENGTH						0x05U	/**< Length of ISO7816 header */
#define PHHAL_HW_SAMAV3_ISO7816_HEADER_LE_LENGTH					0x06U	/**< Length of ISO7816 header including LE byte*/
#define PHHAL_HW_SAMAV3_ISO7816_HEADER_NO_LC_LENGTH					0x04U	/**< Length of ISO7816 header excluding LC byte*/
#define PHHAL_HW_SAMAV3_ISO7816_CLA_POS								0x00U	/**< Pos of CLA byte in ISO7816 header */
#define PHHAL_HW_SAMAV3_ISO7816_INS_POS								0x01U	/**< Pos of INS byte in ISO7816 header */
#define PHHAL_HW_SAMAV3_ISO7816_P1_POS								0x02U	/**< Pos of P1 byte in ISO7816 header */
#define PHHAL_HW_SAMAV3_ISO7816_P2_POS								0x03U	/**< Pos of P2 byte in ISO7816 header */
#define PHHAL_HW_SAMAV3_ISO7816_LC_POS								0x04U	/**< Pos of LC byte in ISO7816 header */
#define PHHAL_HW_SAMAV3_ISO7816_LE_NO_LC_POS						0x04U	/**< Pos of LE byte in ISO7816 header and no LC */
#define PHHAL_HW_SAMAV3_ISO7816_SW1SW2_LENGTH						0x02U	/**< Length of SW1SW2 in ISO7816 */
#define PHHAL_HW_SAMAV3_ISO7816_EXCHANGE_RESPONSE_MAX				0xF8U	/**< Max Length of Transparent Exchange Response */
#define PHHAL_HW_SAMAV3_ISO7816_MAX_LC_MULTIPLE_AESBLOCK   			0xF0U	/**< Maximum data field length, which is still a multiple of AES block length. */
#define PHHAL_HW_CMD_SAMAV3_TRUNCATED_MAC_SIZE						0x08U	/**< Truncated MAC size. */
#define PHHAL_HW_SAMAV3_ISO7816_CLA_BYTE							0x80U	/**< Cla Byte of SamAV2 Commands */
#define PHHAL_HW_SAMAV3_ISO7816_DEFAULT_P1_BYTE						0x00U	/**< Default Ins Byte of SamAV3 Commands */
#define PHHAL_HW_SAMAV3_ISO7816_DEFAULT_P2_BYTE						0x00U	/**< Default Ins Byte of SamAV3 Commands */
#define PHHAL_HW_SAMAV3_ISO7816_DEFAULT_LC_BYTE						0x00U	/**< Default Lc Byte of SamAV3 Commands */
#define PHHAL_HW_SAMAV3_ISO7816_DEFAULT_LE_BYTE						0x00U	/**< Default Le Byte of SamAV3 Commands */

/**
 * \brief Exchange commands with the SAM.
 *
 * \return Status code
 * \retval #PH_ERR_SUCCESS Operation successful.
 * \retval #PHHAL_HW_SAMAV3_ERR_OK_CHAINING_ACTIVE Operation successful chaining.
 * \retval #PHHAL_HW_SAMAV3_ERR_OK_CHAINING_ACTIVE_EXT Operation successful chaining.
 * \retval Other Depending on implementation and underlaying component.
 */
phStatus_t phhalHw_SamAV3_Cmd_7816Exchange(
    phhalHw_SamAV3_DataParams_t
    *pDataParams,							/**< [In] Pointer to this layer's parameter structure. */
    uint16_t wOption,													/**< [In] Buffering options.
																			 *			\arg #PH_EXCHANGE_DEFAULT
																			 *			\arg #PH_EXCHANGE_BUFFER_FIRST
																			 *			\arg #PH_EXCHANGE_BUFFER_CONT
																			 *			\arg #PH_EXCHANGE_BUFFER_LAST
																			 *			\arg #PH_EXCHANGE_TXCHAINING
																			 *			\arg #PH_EXCHANGE_RXCHAINING
																			 *
																			 *			#PH_EXCHANGE_TXCHAINING should be used to exchange chunks of data.
																			 *			#PH_EXCHANGE_RXCHAINING should be used to receive chunks of data.
																			 */
    uint8_t *pTxBuffer,												/**< [In] The command to be be sent to Sam hardware. */
    uint16_t wTxLength,													/**< [In] Length of bytes available in TxBuffer. */
    uint8_t **ppRxBuffer,												/**< [Out] The data received form SAM hardware. */
    uint16_t *pRxLength												/**< [Out] Length of bytes available in RxBuffer. */
);

/*************************************************************************************************************************/
/*********************************************** Security and Configuration **********************************************/
/*************************************************************************************************************************/

/** \defgroup phhalHw_SamAV3_Cmd_Security_Configuration Security and Configuration
 * \brief SAM commands used for host communication and security related configuration.
 * @{
 */

/** \name Sam AV3 command code for Sam Security and configuration feature. */
/* @{ */
#define PHHAL_HW_SAMAV3_CMD_LOCK_UNLOCK_INS							0x10	/**< Sam AV3 Insturction code for SAM_LockUnlock command. */
#define PHHAL_HW_SAMAV3_CMD_AUTHENTICATE_HOST_INS					0xA4	/**< Sam AV3 Insturction code for SAM_AuthenticateHost command. */
#define PHHAL_HW_SAMAV3_CMD_GET_VERSION_INS							0x60	/**< Sam AV3 Insturction code for SAM_GetVersion command. */
#define PHHAL_HW_SAMAV3_CMD_DISABLE_CRYPTO_INS						0xDC	/**< Sam AV3 Insturction code for SAM_DisableCrypto command. */
#define PHHAL_HW_SAMAV3_CMD_ACTIVATE_OFFLINE_KEY_INS				0x01	/**< Sam AV3 Insturction code for SAM_ActivateOfflineKey command. */
#define PHHAL_HW_SAMAV3_CMD_LOAD_INIT_VECTOR_INS					0x71	/**< Sam AV3 Insturction code for SAM_LoadInitVector command. */
#define PHHAL_HW_SAMAV3_CMD_KILL_AUTHENTICATION_INS					0xCA	/**< Sam AV3 Insturction code for SAM_KillAuthenticate command. */
#define PHHAL_HW_SAMAV3_CMD_SELECT_APPLICATION_INS					0x5A	/**< Sam AV3 Insturction code for SAM_SelectApplication command. */
#define PHHAL_HW_SAMAV3_CMD_GET_CHALLENGE_INS						0X84	/**< Sam AV3 Insturction code for SAM_GetChallenge command. */
#define PHHAL_HW_SAMAV3_CMD_SLEEP_INS								0x51	/**< Sam AV3 Insturction code for SAM_Sleep command. */
#define PHHAL_HW_SAMAV3_CMD_SETCONFIGURATION_INS					0x3C    /**< Sam AV3 Insturction code for SAM_SetConfiguration command. */
/* @} */

/** \name Option macros for Sam AV3 Security and Configuration Cmd.SAM_LockUnlock command. */
/* @{ */
#define PHHAL_HW_SAMAV3_CMD_SAM_LOCK_UNLOCK_TYPE_UNLOCK				0x00	/**< Option mask for Sub-command type as unlock. */
#define PHHAL_HW_SAMAV3_CMD_SAM_LOCK_UNLOCK_TYPE_LOCK_NO_KEY		0x01	/**< Option mask for Sub-command type as lock without specifying unlock key. */
#define PHHAL_HW_SAMAV3_CMD_SAM_LOCK_UNLOCK_TYPE_LOCK_KEY			0x02	/**< Option mask for Sub-command type as lock with specifying unlock key. */
#define PHHAL_HW_SAMAV3_CMD_SAM_LOCK_UNLOCK_TYPE_ACTIVATE_SAM		0x03	/**< Option mask for Sub-command type as activate MIFARE SAM to AV3. */
#define PHHAL_HW_SAMAV3_CMD_SAM_LOCK_UNLOCK_TYPE_UNLOCK_PL			0x04	/**< Option mask for Sub-command type as unlock PL. */
/* @} */

/**
 * \brief Lock or Unlock the SAM. Its important to perform Host Authentication after successfull LockUnlock operation to set the new session keys.
 * Host Authentication is required because, LockUnlock interface will utilize the same Cryptoparams which was utilized by Host Authentication
 * interface. Since the Cryptoparams are common, the keys will be updated by LockUnlock interface and the exisiting Host Authentication session
 * keys will not be available.
 *
 * \return Status code
 * \retval #PH_ERR_SUCCESS Operation successful.
 * \retval Other Depending on implementation and underlaying component.
 */
phStatus_t phhalHw_SamAV3_Cmd_SAM_LockUnlock(
    phhalHw_SamAV3_DataParams_t
    *pDataParams,							/**< [In] Pointer to this layer's parameter structure. */
    uint8_t bCmdType,													/**< [In] Sub Command type.
																			 *			\arg #PHHAL_HW_SAMAV3_CMD_SAM_LOCK_UNLOCK_TYPE_UNLOCK
																			 *			\arg #PHHAL_HW_SAMAV3_CMD_SAM_LOCK_UNLOCK_TYPE_LOCK_NO_KEY
																			 *			\arg #PHHAL_HW_SAMAV3_CMD_SAM_LOCK_UNLOCK_TYPE_LOCK_KEY
																			 *			\arg #PHHAL_HW_SAMAV3_CMD_SAM_LOCK_UNLOCK_TYPE_ACTIVATE_SAM
																			 *			\arg #PHHAL_HW_SAMAV3_CMD_SAM_LOCK_UNLOCK_TYPE_UNLOCK_PL
																			 */
    uint16_t wRdKeyNo,													/**< [In] Key reference number to be used in software key store. */
    uint16_t wRdKeyVer,													/**< [In] Key version to be used in software keystore. */
    uint8_t bSamKeyNo,													/**< [In] Key reference number in hardware keytsore. */
    uint8_t bSamKeyVer,													/**< [In] Key version to be used in hardware key store. */
    uint8_t bUnlockKeyNo,												/**< [In] Unlock Key Number to be used in hardware key store (only used when bCmdType = 0x01). */
    uint8_t bUnlockKeyVer,												/**< [In] Unlock Key Version to be used in hardware key store (only used when bCmdType = 0x01). */
    uint32_t dwMaxChainBlocks											/**< [In] Maximal message size under command chaining in MAC or Full Protection (only used during switch from AV2 to AV3). */
);

/** \name Option macros for Sam AV3 Security and Configuration Cmd.SAM_AuthenticateHost command. */
/* @{ */
#define PHHAL_HW_SAMAV3_CMD_SAM_AUTHENTICATE_HOST_MODE_PLAIN		0x00	/**< Option mask for protection mode as plain. */
#define PHHAL_HW_SAMAV3_CMD_SAM_AUTHENTICATE_HOST_MODE_MAC			0x01	/**< Option mask for protection mode as MAC protection. */
#define PHHAL_HW_SAMAV3_CMD_SAM_AUTHENTICATE_HOST_MODE_FULL			0x02	/**< Option mask for protection mode as Full protection. */
/* @} */

/**
 * \brief Mutual 3-pass-AV2 or 3-Pass AV3 authentication between Host and SAM.
 * \return Status code
 * \retval #PH_ERR_SUCCESS Operation successful.
 * \retval Other Depending on implementation and underlaying component.
 */
phStatus_t phhalHw_SamAV3_Cmd_SAM_AuthenticateHost(
    phhalHw_SamAV3_DataParams_t
    *pDataParams,							/**< [In] Pointer to this layer's parameter structure. */
    uint8_t bHostMode,													/**< [In] Type of Protection mode to be applied. \n
																			 *			#PHHAL_HW_SAMAV3_CMD_SAM_AUTHENTICATE_HOST_MODE_PLAIN \n
																			 *			#PHHAL_HW_SAMAV3_CMD_SAM_AUTHENTICATE_HOST_MODE_MAC \n
																			 *			#PHHAL_HW_SAMAV3_CMD_SAM_AUTHENTICATE_HOST_MODE_FULL
																			 */
    uint16_t wRdKeyNo,													/**< [In] Key reference number to be used in software key store. */
    uint16_t wRdKeyV,													/**< [In] Key version to be used in software keystore. */
    uint8_t bSamKeyNo,													/**< [In] Key reference number in hardware keytsore. */
    uint8_t bSamKeyV													/**< [In] Key version to be used in hardware key store. */
);

/**
 * \brief Get version information from the SAM.
 *
 * \return Status code
 * \retval #PH_ERR_SUCCESS Operation successful.
 * \retval Other Depending on implementation and underlaying component.
 */
phStatus_t phhalHw_SamAV3_Cmd_SAM_GetVersion(
    phhalHw_SamAV3_DataParams_t
    *pDataParams,							/**< [In] Pointer to this layer's parameter structure. */
    uint8_t *pVersion,													/**< [Out] Buffer containing the read version. It has to be 31 bytes long. */
    uint8_t *pVersionLen												/**< [Out] Amount of valid bytes in the version buffer. */
);

/** \name Option macros for Sam AV3 Security and Configuration Cmd.SAM_DisableCrypto command. */
/* @{ */
#define PHHAL_HW_SAMAV3_CMD_SAM_CRYPTO_DISABLE_NO_CHANGE			0x0000	/**< Option mask for Disable Crypto with no change for programming mask bit. */
#define PHHAL_HW_SAMAV3_CMD_SAM_CRYPTO_DISABLE_DES_PICC_CHANGE_KEY	0x0800	/**< Option mask for Disable Crypto to disable DESFire Key change. */
#define PHHAL_HW_SAMAV3_CMD_SAM_CRYPTO_DISABLE_DECRYPTION			0x1000	/**< Option mask for Disable Crypto to disable the decryption of data. */
#define PHHAL_HW_SAMAV3_CMD_SAM_CRYPTO_DISABLE_ENCRYPTION			0x2000	/**< Option mask for Disable Crypto to disable encryption of data. */
#define PHHAL_HW_SAMAV3_CMD_SAM_CRYPTO_DISABLE_MAC_VERIFICATION		0x4000	/**< Option mask for Disable Crypto to disable verification of MAC. */
#define PHHAL_HW_SAMAV3_CMD_SAM_CRYPTO_DISABLE_MAC_GENERATION		0x8000	/**< Option mask for Disable Crypto to disable generation of MAC. */
/* @} */

/**
 * \brief Disable cryto-related features of the SAM permanently and is irreversible.
 *
 * \return Status code
 * \retval #PH_ERR_SUCCESS Operation successful.
 * \retval Other Depending on implementation and underlaying component.
 */
phStatus_t phhalHw_SamAV3_Cmd_SAM_DisableCrypto(
    phhalHw_SamAV3_DataParams_t
    *pDataParams,							/**< [In] Pointer to this layer's parameter structure. */
    uint16_t wProMas													/**< [In] Two byte mask to specify the desired settings for cryptography-related features.
																			 *			\arg #PHHAL_HW_SAMAV3_CMD_SAM_CRYPTO_DISABLE_NO_CHANGE
																			 *			\arg #PHHAL_HW_SAMAV3_CMD_SAM_CRYPTO_DISABLE_DES_PICC_CHANGE_KEY
																			 *			\arg #PHHAL_HW_SAMAV3_CMD_SAM_CRYPTO_DISABLE_DECRYPTION
																			 *			\arg #PHHAL_HW_SAMAV3_CMD_SAM_CRYPTO_DISABLE_ENCRYPTION
																			 *			\arg #PHHAL_HW_SAMAV3_CMD_SAM_CRYPTO_DISABLE_MAC_VERIFICATION
																			 *			\arg #PHHAL_HW_SAMAV3_CMD_SAM_CRYPTO_DISABLE_MAC_GENERATION
																			 */
);

/** \name Option macros for Sam AV3 Security and Configuration Cmd.SAM_ActivateOffline command. */
/* @{ */
#define PHHAL_HW_SAMAV3_CMD_SAM_AO_LRP_UPDATE_KEY_RFU				0x00	/**< Option mask for ActivateOffline with P1 information Bit 1 set to zero in case of
																			 *	 non AES_128 LPR keytype.
																			 */
#define PHHAL_HW_SAMAV3_CMD_SAM_AO_LRP_UPDATE_KEY_ONE				0x00	/**< Option mask for ActivateOffline with LRP Update keys to generate One
																			 *	 updated key (KeyID.LRPUpdate).
																			 */
#define PHHAL_HW_SAMAV3_CMD_SAM_AO_LRP_UPDATE_KEY_TWO				0x02	/**< Option mask for ActivateOffline with LRP Update keys to generate Two
																			 *	 updated key (KeyID.LRPMACUpdate and KeyID.LRPENCUpdate).
																			 */
/* @} */

/**
 * \brief Activation of an OfflineCrypto or an OfflineChange Key. This command is available in both AV2 and AV3 mode.
 *
 * \return Status code
 * \retval #PH_ERR_SUCCESS Operation successful.
 * \retval Other Depending on implementation and underlaying component.
 */
phStatus_t phhalHw_SamAV3_Cmd_SAM_ActivateOfflineKey(
    phhalHw_SamAV3_DataParams_t
    *pDataParams,							/**< [In] Pointer to this layer's parameter structure. */
    uint8_t bOption,													/**< [In] Option to update the P1 information if Keytype is AES_128LRP.
																			 *			\arg #PHHAL_HW_SAMAV3_CMD_SAM_AO_LRP_UPDATE_KEY_ONE
																			 *			\arg #PHHAL_HW_SAMAV3_CMD_SAM_AO_LRP_UPDATE_KEY_TWO
																			 *		  \n
																			 *		  \arg #PHHAL_HW_SAMAV3_CMD_SAM_AO_LRP_UPDATE_KEY_RFU if keytype is
																			 *		  other than AES_128LRP.
																			 */
    uint8_t bKeyNo,														/**< [In] Key reference number in hardware keytsore. */
    uint8_t bKeyVer,													/**< [In] Key version to be used in hardware key store. */
    uint8_t *pDivInput,												/**< [In] Diversification Input used to diversify the key. */
    uint8_t bDivInputLen												/**< [In] Length of diversification input used to diversify the key. */
);

/** \name Option macros for Sam AV3 Security and Configuration Cmd.LoadInitVector command. */
/* @{ */
#define PHHAL_HW_SAMAV3_CMD_SAM_LOAD_IV_MODE_SET_IV					0x00	/**< Option mask for Load Init Vector to set the IV. */
#define PHHAL_HW_SAMAV3_CMD_SAM_LOAD_IV_MODE_SET_LRP_ENC_CTR		0x01	/**< Option mask for Load Init Vector to set the LRP_EncCtr. */
/* @} */

/**
 * \brief Load an Init Vector for the next cryptographic operation into the SAM.
 *
 * \return Status code
 * \retval #PH_ERR_SUCCESS Operation successful.
 * \retval Other Depending on implementation and underlaying component.
 */
phStatus_t phhalHw_SamAV3_Cmd_SAM_LoadInitVector(
    phhalHw_SamAV3_DataParams_t
    *pDataParams,							/**< [In] Pointer to this layer's parameter structure. */
    uint8_t bOption,													/**< [In] One of the below option.
																			 *			\arg #PHHAL_HW_SAMAV3_CMD_SAM_LOAD_IV_MODE_SET_IV
																			 *			\arg #PHHAL_HW_SAMAV3_CMD_SAM_LOAD_IV_MODE_SET_LRP_ENC_CTR
																			 */
    uint8_t *pData,													/**< [In] Data based on the option selected. \n
																			 *			If \arg #PHHAL_HW_SAMAV3_CMD_SAM_LOAD_IV_MODE_SET_IV,
																			 *				8 bytes of initializtion vector for DES or
																			 *				16 bytes of initializtion vector for AES.
																			 *			\n
																			 *			If \arg #PHHAL_HW_SAMAV3_CMD_SAM_LOAD_IV_MODE_SET_LRP_ENC_CTR,
																			 *				16 bytes Encryption counter.
																			 */
    uint8_t bDataLen													/**< [In] The length of bytes available in Data buffer. */
);

/** \name Option macros for Sam AV3 Security and Configuration Cmd.SAM_KillAuthentication command. */
/* @{ */
#define PHHAL_HW_SAMAV3_CMD_SAM_KILL_AUTHENTICATION_FULL			0x00	/**< Option mask for killing any authentication on corresponding LC. */
#define PHHAL_HW_SAMAV3_CMD_SAM_KILL_AUTHENTICATION_PARTIAL			0x01	/**< Option mask for killing PICC or offline key activation but preserving any Host Authentication. */
/* @} */

/**
 * \brief Kill all active authentications in this logical channel.
 *
 * \return Status code
 * \retval #PH_ERR_SUCCESS Operation successful.
 * \retval Other Depending on implementation and underlaying component.
 */
phStatus_t phhalHw_SamAV3_Cmd_SAM_KillAuthentication(
    phhalHw_SamAV3_DataParams_t
    *pDataParams,							/**< [In] Pointer to this layer's parameter structure. */
    uint8_t bOption														/**< [In] The type of authentication to be killed.
																			 *			\arg #PHHAL_HW_SAMAV3_CMD_SAM_KILL_AUTHENTICATION_FULL
																			 *			\arg #PHHAL_HW_SAMAV3_CMD_SAM_KILL_AUTHENTICATION_PARTIAL
																			 */
);

/**
 * \brief Select an application by the DF_AID
 *
 * \return Status code
 * \retval #PH_ERR_SUCCESS Operation successful.
 * \retval Other Depending on implementation and underlaying component.
 */
phStatus_t phhalHw_SamAV3_Cmd_SAM_SelectApplication(
    phhalHw_SamAV3_DataParams_t
    *pDataParams,							/**< [In] Pointer to this layer's parameter structure. */
    uint8_t *pDF_Aid													/**< [In] DESFire application identifier (3 bytes). */
);

/**
 * \brief Gets a random number.
 *
 * \return Status code
 * \retval #PH_ERR_SUCCESS Operation successful.
 * \retval Other Depending on implementation and underlaying component.
 */
phStatus_t phhalHw_SamAV3_Cmd_SAM_GetRandom(
    phhalHw_SamAV3_DataParams_t
    *pDataParams,							/**< [In] Pointer to this layer's parameter structure. */
    uint8_t
    bExpLen,													/**< [In] The length of random bytes expected form Sam hardware. */
    uint8_t   *pRnd														/**< [Out] The random number returned by Sam. */
);

/**
 * \brief Set the SAM into power down mode.
 *
 * \return Status code
 * \retval #PH_ERR_SUCCESS Operation successful.
 * \retval Other Depending on implementation and underlaying component.
 */
phStatus_t phhalHw_SamAV3_Cmd_SAM_Sleep(
    phhalHw_SamAV3_DataParams_t
    *pDataParams							/**< [In] Pointer to this layer's parameter structure. */
);

/** \name Option macros for Sam AV3 Security and Configuration Cmd.SAM_SetConfiguration command. */
/* @{ */
#define PHHAL_HW_SAMAV3_CMD_SAM_SET_CONFIGURATION_HISTORICAL_BYTES	0x00	/**< Option mask for exchanging the historical bytes. */
#define PHHAL_HW_SAMAV3_CMD_SAM_SET_CONFIGURATION_READER_IC_CONFIG	0x01	/**< Option mask for exchanging the reader IC configuration. */
#define PHHAL_HW_SAMAV3_CMD_SAM_SET_CONFIGURATION_I2C_CLOCK_SPEED	0x02	/**< Option mask for exchanging the I2C processing clock speed configuration. */
#define PHHAL_HW_SAMAV3_CMD_SAM_SET_CONFIGURATION_EMV_CHANGE_KEYS	0x03	/**< Option mask for exchanging the Default EMV Change keys configuration. */
#define PHHAL_HW_SAMAV3_CMD_SAM_SET_CONFIGURATION_FULL_ATR			0x04	/**< Option mask for exchanging the Full ATR configuration. */

#define PHHAL_HW_SAMAV3_CMD_SAM_READER_IC_CONFIG_RC512				0x01	/**< Option mask for exchanging the reader IC configuration as RC512. */
#define PHHAL_HW_SAMAV3_CMD_SAM_READER_IC_CONFIG_RC523				0x02	/**< Option mask for exchanging the reader IC configuration as RC523. */
#define PHHAL_HW_SAMAV3_CMD_SAM_READER_IC_CONFIG_RC663				0x03	/**< Option mask for exchanging the reader IC configuration as RC663. */
/* @} */

/**
 * \brief Used to update SAM configuration settings.
 *
 * \return Status code
 * \retval #PH_ERR_SUCCESS Operation successful.
 * \retval Other Depending on implementation and underlaying component.
 */
phStatus_t phhalHw_SamAV3_Cmd_SAM_SetConfiguration(
    phhalHw_SamAV3_DataParams_t
    *pDataParams,							/**< [In] Pointer to this layer's parameter structure. */
    uint8_t bOption,													/**< [In] Configuration setting ID. Define length and content of the Data parameter.
																			 *			\arg #PHHAL_HW_SAMAV3_CMD_SAM_SET_CONFIGURATION_HISTORICAL_BYTES
																			 *			\arg #PHHAL_HW_SAMAV3_CMD_SAM_SET_CONFIGURATION_READER_IC_CONFIG
																			 *			\arg #PHHAL_HW_SAMAV3_CMD_SAM_SET_CONFIGURATION_I2C_CLOCK_SPEED
																			 *			\arg #PHHAL_HW_SAMAV3_CMD_SAM_SET_CONFIGURATION_EMV_CHANGE_KEYS
																			 *			\arg #PHHAL_HW_SAMAV3_CMD_SAM_SET_CONFIGURATION_FULL_ATR
																			 */
    uint8_t *pData,													/**< [In] Configuration setting data.
																			 *			\arg If #PHHAL_HW_SAMAV3_CMD_SAM_SET_CONFIGURATION_HISTORICAL_BYTES,
																			 *				the historical bytes should be exchanged.
																			 *
																			 *			\arg If #PHHAL_HW_SAMAV3_CMD_SAM_SET_CONFIGURATION_READER_IC_CONFIG,
																			 *				 one of the below values \n
																			 *				\c #PHHAL_HW_SAMAV3_CMD_SAM_READER_IC_CONFIG_RC512 \n
																			 *				\c #PHHAL_HW_SAMAV3_CMD_SAM_READER_IC_CONFIG_RC523 \n
																			 *				\c #PHHAL_HW_SAMAV3_CMD_SAM_READER_IC_CONFIG_RC663
																			 *
																			 *			\arg If #PHHAL_HW_SAMAV3_CMD_SAM_SET_CONFIGURATION_I2C_CLOCK_SPEED,
																			 *				 one of the below values \n
																			 *				\c 0x00 - 0x01: Contact external Clock. \n
																			 *				\c 0x04       : 0.5 MHz. \n
																			 *				\c 0x05       : 1 MHz. \n
																			 *				\c 0x06       : 2 MHz. \n
																			 *				\c 0x07       : 3 MHz. \n
																			 *				\c 0x08       : 4 MHz. \n
																			 *				\c 0x09       : 6 MHz. \n
																			 *				\c 0x0A       : 8 MHz. \n
																			 *				\c 0x0B       : 12 MHz. (Default) \n
																			 *				\c 0x0C       : 16 MHz. \n
																			 *				\c 0x0F       : Free Running mode. \n
																			 *
																			 *			\arg If #PHHAL_HW_SAMAV3_CMD_SAM_SET_CONFIGURATION_EMV_CHANGE_KEYS,
																			 *				 4 bytes key information as EMV_DefaultKeyNoCEK1, EMV_DefaultVCEK1,
																			 *				 EMV_DefaultKeyNoCEK2, EMV_DefaultVCEK2 \n
																			 *
																			 *			\arg If #PHHAL_HW_SAMAV3_CMD_SAM_SET_CONFIGURATION_FULL_ATR,
																			 *				 Full ATR update
																			 */
    uint8_t bDataLen													/**< [In] Length of Configuration setting data. */
);

/**
 * end of phhalHw_SamAV3_Cmd_Security_Configuration
 * @}
 */

/*************************************************************************************************************************/
/***************************************************** Key Management ****************************************************/
/*************************************************************************************************************************/

/** \defgroup phhalHw_SamAV3_Cmd_KeyManagment Key Management
 * \brief SAM commands used for key management related configuration.
 * @{
 */

/** \name Sam AV3 command code for Sam Key Management feature. */
/* @{ */
#define PHHAL_HW_SAMAV3_CMD_SAM_CHANGE_KEY_ENTRY_INS				0xC1U	/**< Sam AV3 Insturction code for SAM_ChangeKeyEntry command. */
#define PHHAL_HW_SAMAV3_CMD_SAM_GET_KEY_ENTRY_INS					0x64U	/**< Sam AV3 Insturction code for SAM_GetKeyEntry command. */
#define PHHAL_HW_SAMAV3_CMD_SAM_CHANGE_KUC_ENTRY_INS				0xCCU	/**< Sam AV3 Insturction code for SAM_ChangeKUCEntry command. */
#define PHHAL_HW_SAMAV3_CMD_SAM_GET_KUC_ENTRY_INS					0x6CU	/**< Sam AV3 Insturction code for SAM_GetKUCEntry command. */
#define PHHAL_HW_SAMAV3_CMD_SAM_DUMP_SESSION_KEY_INS				0xD5U   /**< Sam AV3 Insturction code for SAM_DumpSessionKey command. */
#define PHHAL_HW_SAMAV3_CMD_SAM_DUMP_SECRET_KEY_INS					0xD6U   /**< Sam AV3 Insturction code for SAM_DumpSecretKey command. */
#define PHHAL_HW_SAMAV3_CMD_SAM_DISABLE_KEY_ENTRY_INS				0xD8U   /**< Sam AV3 Insturction code for SAM_DisableKeyEntry command. */
#define PHHAL_HW_SAMAV3_CMD_SAM_ENCHIPHER_KEY_ENTRY_INS				0xE1U	/**< Sam AV3 Insturction code for SAM_EnchipherKeyEntry command. */
#define PHHAL_HW_SAMAV3_CMD_SAM_DERIVE_KEY_INS						0xD7U	/**< Sam AV3 Insturction code for SAM_DeriveKey command. */
#define PHHAL_HW_SAMAV3_CMD_SAM_GENERATE_MFC_LIC_MAC				0x7DU	/**< Sam AV3 Insturction code for SAM_Generate_MFCLicMAC command. */
/* @} */

/** \name Option macros for Sam AV3 Key Management Cmd.SAM_ChangeKeyEntry command. */
/* @{ */
#define PHHAL_HW_SAMAV3_CMD_SAM_CHANGE_KEY_ENTRY_UPDATE_KEY_VA		0x80	/**< Option mask for updating key number and version A. */
#define PHHAL_HW_SAMAV3_CMD_SAM_CHANGE_KEY_ENTRY_UPDATE_KEY_VB		0x40	/**< Option mask for updating key number and version B. */
#define PHHAL_HW_SAMAV3_CMD_SAM_CHANGE_KEY_ENTRY_UPDATE_KEY_VC		0x20	/**< Option mask for updating key number and version C. */
#define PHHAL_HW_SAMAV3_CMD_SAM_CHANGE_KEY_ENTRY_UPDATE_DF_AID		0x10	/**< Option mask for updating DESFire application identifier. */
#define PHHAL_HW_SAMAV3_CMD_SAM_CHANGE_KEY_ENTRY_UPDATE_KEY_CEK		0x08	/**< Option mask for updating key number and version of change entry key (CEK). */
#define PHHAL_HW_SAMAV3_CMD_SAM_CHANGE_KEY_ENTRY_UPDATE_REF_NO_KUC	0x04	/**< Option mask for updating reference key usage counter. */
#define PHHAL_HW_SAMAV3_CMD_SAM_CHANGE_KEY_ENTRY_UPDATE_SET_EXTSET	0x02	/**< Option mask for updating SET and Extended SET. */
#define PHHAL_HW_SAMAV3_CMD_SAM_CHANGE_KEY_ENTRY_INCLUDE_VERSION	0x01	/**< Option mask for specifying the versions in the data field after SET and ExtSET. */
/* @} */

/**
 * \brief Change a symmetric key entry in the key table of the SAM.
 *
 * \return Status code
 * \retval #PH_ERR_SUCCESS Operation successful.
 * \retval Other Depending on implementation and underlaying component.
 */
phStatus_t phhalHw_SamAV3_Cmd_SAM_ChangeKeyEntry(
    phhalHw_SamAV3_DataParams_t
    *pDataParams,							/**< [In] Pointer to this layer's parameter structure. */
    uint8_t bKeyNo,														/**< [In] Reference number of the key entry to be changed (00h to 7Fh). */
    uint8_t bProMas,													/**< [In] Program mask indicating the fields that should be changed. All the below
																			 *		  option can be combined by using bitwise OR operator.
																			 *          \arg #PHHAL_HW_SAMAV3_CMD_SAM_CHANGE_KEY_ENTRY_UPDATE_KEY_VA
																			 *          \arg #PHHAL_HW_SAMAV3_CMD_SAM_CHANGE_KEY_ENTRY_UPDATE_KEY_VB
																			 *          \arg #PHHAL_HW_SAMAV3_CMD_SAM_CHANGE_KEY_ENTRY_UPDATE_KEY_VC
																			 *          \arg #PHHAL_HW_SAMAV3_CMD_SAM_CHANGE_KEY_ENTRY_UPDATE_DF_AID
																			 *          \arg #PHHAL_HW_SAMAV3_CMD_SAM_CHANGE_KEY_ENTRY_UPDATE_KEY_CEK
																			 *          \arg #PHHAL_HW_SAMAV3_CMD_SAM_CHANGE_KEY_ENTRY_UPDATE_REF_NO_KUC
																			 *          \arg #PHHAL_HW_SAMAV3_CMD_SAM_CHANGE_KEY_ENTRY_UPDATE_SET_EXTSET
																			 *          \arg #PHHAL_HW_SAMAV3_CMD_SAM_CHANGE_KEY_ENTRY_INCLUDE_VERSION
																			 */
    uint8_t *pKeyData,													/**< [In] Buffer containing the key data. */
    uint8_t bKeyDataLen													/**< [In] Length of the key data buffer. */
);

/**
 * \brief Change a Offline symmetric key entry in the key entry table of the SAM.
 *
 * \return Status code
 * \retval #PH_ERR_SUCCESS Operation successful.
 * \retval Other Depending on implementation and underlaying component.
 */
phStatus_t phhalHw_SamAV3_Cmd_SAM_ChangeKeyEntryOffline(
    phhalHw_SamAV3_DataParams_t
    *pDataParams,							/**< [In] Pointer to this layer's parameter structure. */
    uint8_t bKeyNo,														/**< [In] Reference number of the key entry to be changed (00h to 7Fh). */
    uint8_t bProMas,													/**< [In] Program mask indicating the fields that should be changed. All the below
																			 *		  option can be combined by using bitwise OR operator.
																			 *          \arg #PHHAL_HW_SAMAV3_CMD_SAM_CHANGE_KEY_ENTRY_UPDATE_KEY_VA
																			 *          \arg #PHHAL_HW_SAMAV3_CMD_SAM_CHANGE_KEY_ENTRY_UPDATE_KEY_VB
																			 *          \arg #PHHAL_HW_SAMAV3_CMD_SAM_CHANGE_KEY_ENTRY_UPDATE_KEY_VC
																			 *          \arg #PHHAL_HW_SAMAV3_CMD_SAM_CHANGE_KEY_ENTRY_UPDATE_DF_AID
																			 *          \arg #PHHAL_HW_SAMAV3_CMD_SAM_CHANGE_KEY_ENTRY_UPDATE_KEY_CEK
																			 *          \arg #PHHAL_HW_SAMAV3_CMD_SAM_CHANGE_KEY_ENTRY_UPDATE_REF_NO_KUC
																			 *          \arg #PHHAL_HW_SAMAV3_CMD_SAM_CHANGE_KEY_ENTRY_UPDATE_SET_EXTSET
																			 *          \arg #PHHAL_HW_SAMAV3_CMD_SAM_CHANGE_KEY_ENTRY_INCLUDE_VERSION
																			 */
    uint16_t wChangeCtr,												/**< [In] Change Counter to avoid replay attacks. */
    uint8_t *pOfflineCrypto,											/**< [In] Offline Cryptogram returned from SAM (EncKeyEntry[80] + OfflineMAC[8]) */
    uint8_t bOfflineCryptLen,											/**< [In] Offline Cryptogram Length */
    uint8_t bEnableOfflineAck,											/**< [In] To Enable reception of Offline Acknowledge \n
																			 *			\c 0x00: Disable \n
																			 *			\c 0x01: Enable
																			 */
    uint8_t *pOfflineAck												/**< [Out] Offline Acknowledge information. */
);

/** \name Option macros for Sam AV3 Key Management Cmd.SAM_GetKeyEntry command. */
/* @{ */
#define PHHAL_HW_SAMAV3_CMD_SAM_GET_KEY_ENTRY_KEY_ENTRY_SAM_AV2		0x00	/**< Option mask for enabling Sam AV2 Format as key entry format. */
#define PHHAL_HW_SAMAV3_CMD_SAM_GET_KEY_ENTRY_KEY_ENTRY_NEW			0x01	/**< Option mask for enabling New Format as key entry format. */
#define PHHAL_HW_SAMAV3_CMD_SAM_GET_KEY_ENTRY_RAM_KEY				0x00	/**< Option mask for receiving the Ram key. */
/* @} */

/**
 * \brief Get information about a key entry.
 *
 * \return Status code
 * \retval #PH_ERR_SUCCESS Operation successful.
 * \retval Other Depending on implementation and underlaying component.
 */
phStatus_t phhalHw_SamAV3_Cmd_SAM_GetKeyEntry(
    phhalHw_SamAV3_DataParams_t
    *pDataParams,							/**< [In] Pointer to this layer's parameter structure. */
    uint8_t bKeyNo,														/**< [In] Reference number of the key entry to be returned (00h to 7Fh). */
    uint8_t bMode,														/**< [In] Key entry format to be used.
																			 *			\arg #PHHAL_HW_SAMAV3_CMD_SAM_GET_KEY_ENTRY_KEY_ENTRY_SAM_AV2
																			 *			\arg #PHHAL_HW_SAMAV3_CMD_SAM_GET_KEY_ENTRY_KEY_ENTRY_NEW
																			 *			\arg #PHHAL_HW_SAMAV3_CMD_SAM_GET_KEY_ENTRY_RAM_KEY
																			 */
    uint8_t *pKeyEntry,												/**< [Out] Buffer containing the information about the key entry. */
    uint8_t *pKeyEntryLen												/**< [Out] Amount of valid bytes in pKeyEntry. */
);

/** \name Option macros for Sam AV3 Key Management Cmd.SAM_ChangeKeyEntry command. */
/* @{ */
#define PHHAL_HW_SAMAV3_CMD_SAM_CHANGE_KUC_ENTRY_UPDATE_LIMIT		0x80	/**< Option mask for updating the limit. */
#define PHHAL_HW_SAMAV3_CMD_SAM_CHANGE_KUC_ENTRY_UPDATE_KEY_NO_CKUC	0x40	/**< Option mask for updating CKUC key number. */
#define PHHAL_HW_SAMAV3_CMD_SAM_CHANGE_KUC_ENTRY_UPDATE_VCKUC		0x20	/**< Option mask for updating the VCKUC. */
/* @} */

/**
 * \brief Change the key usage counter (KUC). Selection is done by its reference number.
 *
 * \return Status code
 * \retval #PH_ERR_SUCCESS Operation successful.
 * \retval Other Depending on implementation and underlaying component.
 */
phStatus_t phhalHw_SamAV3_Cmd_SAM_ChangeKUCEntry(
    phhalHw_SamAV3_DataParams_t
    *pDataParams,							/**< [In] Pointer to this layer's parameter structure. */
    uint8_t bKucNo,														/**< [In] Reference number of the key usage counter to be updated (00h to 0Fh). */
    uint8_t bProMas,													/**< [In] Program mask indicating the fields that should be changed. All the below
																			 *		  option can be combined by using bitwise OR operator.
																			 *			\arg #PHHAL_HW_SAMAV3_CMD_SAM_CHANGE_KUC_ENTRY_UPDATE_LIMIT
																			 *			\arg #PHHAL_HW_SAMAV3_CMD_SAM_CHANGE_KUC_ENTRY_UPDATE_KEY_NO_CKUC
																			 *			\arg #PHHAL_HW_SAMAV3_CMD_SAM_CHANGE_KUC_ENTRY_UPDATE_VCKUC
																			 */
    uint8_t *pKucData,													/**< [In] Buffer containing the KUC data. */
    uint8_t bKucDataLen													/**< [In] Length of the KUC data. */
);

/**
 * \brief Change a Offline KUC entry in the key entry table of the SAM.
 *
 * \return Status code
 * \retval #PH_ERR_SUCCESS Operation successful.
 * \retval Other Depending on implementation and underlaying component.
 */
phStatus_t phhalHw_SamAV3_Cmd_SAM_ChangeKUCEntryOffline(
    phhalHw_SamAV3_DataParams_t
    *pDataParams,							/**< [In] Pointer to this layer's parameter structure. */
    uint8_t bKucNo,														/**< [In] Reference number of the key usage counter to be updated (00h to 0Fh). */
    uint8_t bProMas,													/**< [In] Program mask indicating the fields that should be changed. All the below
																			 *		  option can be combined by using bitwise OR operator.
																			 *			\arg #PHHAL_HW_SAMAV3_CMD_SAM_CHANGE_KUC_ENTRY_UPDATE_LIMIT
																			 *			\arg #PHHAL_HW_SAMAV3_CMD_SAM_CHANGE_KUC_ENTRY_UPDATE_KEY_NO_CKUC
																			 *			\arg #PHHAL_HW_SAMAV3_CMD_SAM_CHANGE_KUC_ENTRY_UPDATE_VCKUC
																			 */
    uint16_t wChangeCtr,												/**< [In] Change Counter to avoid replay attacks. */
    uint8_t *pOfflineCrypto,											/**< [In] Offline Cryptogram returned from SAM (EncKUCEntry[16] + OfflineMAC[8]) */
    uint8_t bOfflineCryptLen,											/**< [In] Offline Cryptogram Length */
    uint8_t bEnableOfflineAck,											/**< [In] To Enable reception of Offline Acknowledge \n
																			 *			\c 0x00: Disable \n
																			 *			\c 0x01: Enable
																			 */
    uint8_t *pOfflineAck												/**< [Out] Offline Acknowledge information. */
);

/**
 * \brief Get information about a key usage counter (KUC).
 *
 * \return Status code
 * \retval #PH_ERR_SUCCESS Operation successful.
 * \retval Other Depending on implementation and underlaying component.
 */
phStatus_t phhalHw_SamAV3_Cmd_SAM_GetKUCEntry(
    phhalHw_SamAV3_DataParams_t
    *pDataParams,							/**< [In] Pointer to this layer's parameter structure. */
    uint8_t bKucNo,														/**< [In] Reference number of the key usage counter to be returned (00h to 0Fh). */
    uint8_t *pKucEntry													/**< [Out] Buffer containing the KUC entry. This buffer has to be 10 bytes long. */
);

/** \name Option macros for Sam AV3 Key Management Cmd.SAM_DumpSessionKey and Cmd.SAM_DumpSecretKey command. */
/* @{ */
#define PHHAL_HW_SAMAV3_CMD_SAM_DUMP_MODE_PLAIN						0x00	/**< Option mask for dumping session or seceret keys in plain. */
#define PHHAL_HW_SAMAV3_CMD_SAM_DUMP_MODE_ENCIPHERED				0x01	/**< Option mask for dumping session or seceret keys in enciphered. */
#define PHHAL_HW_SAMAV3_CMD_SAM_DUMP_MODE_DIVERSIFICATION_OFF		0x00	/**< Option mask for disabling the diversification of the provided key. */
#define PHHAL_HW_SAMAV3_CMD_SAM_DUMP_MODE_DIVERSIFICATION_ON		0x02	/**< Option mask for enabling the diversification of the provided key. */
/* @} */

/**
 * \brief Dump the current session key.
 *
 *
 * \return Status code
 * \retval #PH_ERR_SUCCESS Operation successful.
 * \retval Other Depending on implementation and underlaying component.
 */
phStatus_t phhalHw_SamAV3_Cmd_SAM_DumpSessionKey(
    phhalHw_SamAV3_DataParams_t
    *pDataParams,							/**< [In] Pointer to this layer's parameter structure. */
    uint8_t bDumpMode,													/**< [In] Crypto settings.
																			 *			\arg #PHHAL_HW_SAMAV3_CMD_SAM_DUMP_MODE_PLAIN
																			 *			\arg #PHHAL_HW_SAMAV3_CMD_SAM_DUMP_MODE_ENCIPHERED
																			 */
    uint8_t *pSessionKey,												/**< [Out] Buffer containig the session key. */
    uint8_t *pSessionKeyLen											/**< [Out] Amount of valid bytes in session key buffer. */
);

/**
 * \brief Retrive a PICC key stored in the key table. This command is only available in AV2 and AV3.
 *
 * \return Status code
 * \retval #PH_ERR_SUCCESS Operation successful.
 * \retval Other Depending on implementation and underlaying component.
 */
phStatus_t phhalHw_SamAV3_Cmd_SAM_DumpSecretKey(
    phhalHw_SamAV3_DataParams_t
    *pDataParams,							/**< [In] Pointer to this layer's parameter structure. */
    uint8_t bDumpMode,													/**< [In] Crypto settings.
																			 *			\arg #PHHAL_HW_SAMAV3_CMD_SAM_DUMP_MODE_PLAIN
																			 *			\arg #PHHAL_HW_SAMAV3_CMD_SAM_DUMP_MODE_ENCIPHERED
																			 *			\arg #PHHAL_HW_SAMAV3_CMD_SAM_DUMP_MODE_DIVERSIFICATION_OFF
																			 *			\arg #PHHAL_HW_SAMAV3_CMD_SAM_DUMP_MODE_DIVERSIFICATION_ON
																			 */
    uint8_t bKeyNo,														/**< [In] Reference number of the key entry to be dumped. */
    uint8_t bKeyVer,													/**< [In] Reference version of the key entry to be dumped. */
    uint8_t *pDivInput,												/**< [In] Diversification Input used to diversify the key. */
    uint8_t bDivInputLen,												/**< [In] Length of diversification input used to diversify the key. */
    uint8_t *pSecretKey,												/**< [Out] Buffer containing the plain secret key. */
    uint8_t *pSecretKeyLen												/**< [Out] Amount of valid bytes in secret key buffer. */
);

/**
 * \brief Disable a key entry.
 *
 * \return Status code
 * \retval #PH_ERR_SUCCESS Operation successful.
 * \retval Other Depending on implementation and underlaying component.
 */
phStatus_t phhalHw_SamAV3_Cmd_SAM_DisableKeyEntry(
    phhalHw_SamAV3_DataParams_t
    *pDataParams,							/**< [In] Pointer to this layer's parameter structure. */
    uint8_t bKeyNo,														/**< [In] Number of the key entry to be disabled (00h to 7Fh). */
    uint8_t *pOfflineCrypto,											/**< [In] Buffer containing the cryptogram for offline key deactivation. */
    uint8_t bCryptoLen													/**< [In] Length of the offline cryptogram. If set to 00h no offline cryptogram is sent. */
);

/**
 * \brief Disable a key entry using offline cryptogram.
 *
 * \return Status code
 * \retval #PH_ERR_SUCCESS Operation successful.
 * \retval Other Depending on implementation and underlaying component.
 */
phStatus_t phhalHw_SamAV3_Cmd_SAM_DisableKeyEntryOffline(
    phhalHw_SamAV3_DataParams_t
    *pDataParams,							/**< [In] Pointer to this layer's parameter structure. */
    uint8_t bKeyNo,														/**< [In] Reference number of the key entry to be disabled (00h to 7Fh). */
    uint16_t wChangeCtr,												/**< [In] Change Counter to avoid replay attacks. */
    uint8_t *pOfflineCrypto,											/**< [In] Offline Cryptogram returned from SAM (EncGoldField[16] + OfflineMAC[8]) */
    uint8_t bOfflineCryptLen,											/**< [In] Offline Cryptogram Length */
    uint8_t bEnableOfflineAck,											/**< [In] To Enable reception of Offline Acknowledge \n
																			 *			\c 0x00: Disable \n
																			 *			\c 0x01: Enable
																			 */
    uint8_t *pOfflineAck												/**< [Out] Offline Acknowledge information. */
);

/** \name Option macros for Sam AV3 Key Management Cmd.SAM_EncipherKeyEntry command. */
/* @{ */
#define PHHAL_HW_SAMAV3_CMD_SAM_ENCIPHER_KEY_ENTRY_DIV_OFF			0x00	/**< Option mask to exclude the diversification input in command frame. */
#define PHHAL_HW_SAMAV3_CMD_SAM_ENCIPHER_KEY_ENTRY_DIV_ON			0x01	/**< Option mask to include the diversification input in command frame. */
#define PHHAL_HW_SAMAV3_CMD_SAM_ENCIPHER_KEY_ENTRY_SAM_UID_OFF		0x00	/**< Option mask to exclude the Sam UID in command frame. */
#define PHHAL_HW_SAMAV3_CMD_SAM_ENCIPHER_KEY_ENTRY_SAM_UID_ON		0x02	/**< Option mask to include the Sam UID in command frame. */
/* @} */

/**
 * \brief Is a Personalization SAM command, used to prepare a cryptogram (according to Offline change protection) for the
 * OfflineChange key on a target SAM.
 *
 * \return Status code
 * \retval #PH_ERR_SUCCESS Operation successful.
 * \retval Other Depending on implementation and underlaying component.
 */
phStatus_t phhalHw_SamAV3_Cmd_SAM_EncipherKeyEntry(
    phhalHw_SamAV3_DataParams_t
    *pDataParams,							/**< [In] Pointer to this layer's parameter structure. */
    uint8_t bPersoKeyNo,												/**< [In] Reference number of the key entry with Perso enabled. */
    uint8_t bKeyNo,														/**< [In] Reference number of the key entry to be encrypted. */
    uint8_t bOption,													/**< [In] Option to include Key diversification and SAM UID in command.
																			 *			\arg #PHHAL_HW_SAMAV3_CMD_SAM_ENCIPHER_KEY_ENTRY_DIV_OFF
																			 *			\arg #PHHAL_HW_SAMAV3_CMD_SAM_ENCIPHER_KEY_ENTRY_DIV_ON
																			 *			\arg #PHHAL_HW_SAMAV3_CMD_SAM_ENCIPHER_KEY_ENTRY_SAM_UID_OFF
																			 *			\arg #PHHAL_HW_SAMAV3_CMD_SAM_ENCIPHER_KEY_ENTRY_SAM_UID_ON
																			 */
    uint16_t wPersoCtr,													/**< [In] Change Counter to avoid replay attacks */
    uint8_t *pDivInput,												/**< [In] Diversification Input used to diversify the key. */
    uint8_t bDivInputLen,												/**< [In] Length of diversification input used to diversify the key. */
    uint8_t *pOfflineCryptogram,										/**< [Out] Offline Cryptogram returned from SAM (EncKeyEntry[80] + OfflineMAC[8]) */
    uint8_t *pCryptogramLen											/**< [Out] Offline Cryptogram Length */
);

/**
 * \brief Is used to derive a key from a source key (in other contexts often called master key) based on a CMAC operation. In a MIFARE context,
 * this command can be used to support session key generations for the Transaction MAC and Secure Dynamic Messaging features, for backend (and /
 * or reader) interpretation and validation of the cryptograms created by the PICC.
 *
 * \return Status code
 * \retval #PH_ERR_SUCCESS Operation successful.
 * \retval Other Depending on implementation and underlaying component.
 */
phStatus_t phhalHw_SamAV3_Cmd_SAM_DeriveKey(
    phhalHw_SamAV3_DataParams_t
    *pDataParams,							/**< [In] Pointer to this layer's parameter structure. */
    uint8_t bSrcKeyNo,													/**< [In] Reference key number of the key entry (00h to 7Fh). */
    uint8_t bSrcKeyVer,													/**< [In] Reference key version of the key entry (00h to FFh). */
    uint8_t bDstKeyNo,													/**< [In] Reference key number of the ram key entry (E0h to E3h). */
    uint8_t *pDeriveIn, 												/**< [In] The derivation input for deriving the key. */
    uint8_t bDeriveInLen												/**< [In] Length of derivation input used to derive the key. */
);

/** \name Option macros for Sam AV3 Key Management Cmd.SAM_Generate_MFCLicMAC command. */
/* @{ */
#define PHHAL_HW_SAMAV3_CMD_SAM_GENERATE_MFC_LIC_MAC_DIV_OFF		0x00	/**< Option mask to exclude the diversification input in command frame. */
#define PHHAL_HW_SAMAV3_CMD_SAM_GENERATE_MFC_LIC_MAC_DIV_ON			0x01	/**< Option mask to include the diversification input in command frame. */
/* @} */

/**
 * \brief Is used to generate the MIFARE License key.
 *
 * \return Status code
 * \retval #PH_ERR_SUCCESS Operation successful.
 * \retval Other Depending on implementation and underlaying component.
 */
phStatus_t phhalHw_SamAV3_Cmd_SAM_GenerateMFCLicMAC(
    phhalHw_SamAV3_DataParams_t
    *pDataParams,							/**< [In] Pointer to this layer's parameter structure. */
    uint8_t bOption,													/**< [In] One of the below values.
																			 *			\arg PHHAL_HW_SAMAV3_CMD_SAM_GENERATE_MFC_LIC_MAC_DIV_OFF
																			 *			\arg PHHAL_HW_SAMAV3_CMD_SAM_GENERATE_MFC_LIC_MAC_DIV_ON
																			 */
    uint8_t bInputLen,													/**< [In] The length of bytes available in Input buffer. */
    uint8_t *pInput, 													/**< [In] Length N of the input data for the MAC computation. */
    uint8_t bKeyCount,													/**< [In] Length of bytes available in MFCSectorKeys buffer. */
    uint8_t *pMFCSectorKeys, 											/**< [In] Length N of the input data for the MAC computation. */
    uint8_t *pMFUID, 													/**< [In] MIFARE standard UID. Here the last four bytes of the UID should be passed
																			 *		  regardless of 4 or 7 byte UID. This is an optional parameter, so can be NULL.
																			 */
    uint8_t *pMFCLicMAC												/**< [Out] Generated MIFARE Classic License MAC information. */
);

/**
 * end of phhalHw_SamAV3_Cmd_KeyManagment
 * @}
 */

/*************************************************************************************************************************/
/**************************************************** Data Processing ****************************************************/
/*************************************************************************************************************************/

/** \defgroup phhalHw_SamAV3_Cmd_DataProcessing Data Processing
 * \brief SAM commands used for data processing.
 * @{
 */

/** \name Sam AV3 command code for Sam Data Processing feature. */
/* @{ */
#define PHHAL_HW_SAMAV3_CMD_SAM_APPLY_SM_INS						0xAE    /**< Sam AV3 Insturction code for SAM_ApplySM command. */
#define PHHAL_HW_SAMAV3_CMD_SAM_REMOVE_SM_INS						0xAD    /**< Sam AV3 Insturction code for SAM_UndoSM command. */
#define PHHAL_HW_SAMAV3_CMD_SAM_VERIFY_MAC_INS						0x5C    /**< Sam AV3 Insturction code for SAM_VerifyMac command. */
#define PHHAL_HW_SAMAV3_CMD_SAM_GENERATE_MAC_INS					0x7C    /**< Sam AV3 Insturction code for SAM_GenerateMac command. */
#define PHHAL_HW_SAMAV3_CMD_SAM_DECIPHER_DATA_INS					0xDD    /**< Sam AV3 Insturction code for SAM_DecipherData command. */
#define PHHAL_HW_SAMAV3_CMD_SAM_ENCIPHER_DATA_INS					0xED    /**< Sam AV3 Insturction code for SAM_EncipherData command. */
#define PHHAL_HW_SAMAV3_CMD_SAM_DECIPHER_OFFLINE_DATA_INS			0x0D    /**< Sam AV3 Insturction code for SAM_DecipherOfflineData command. */
#define PHHAL_HW_SAMAV3_CMD_SAM_ENCIPHER_OFFLINE_DATA_INS			0x0E    /**< Sam AV3 Insturction code for SAM_EncipherOfflineData command. */
/* @} */

/** \name Option macros for Sam AV3 Data Processing Cmd.SAM_Apply_SM and Cmd.SAM_Remove_SM command. */
/* @{ */
#define PHHAL_HW_SAMAV3_CMD_APPLY_SM_COMM_MODE_PLAIN				0x00	/**< Option mask for communication mode as plain for Cmd.SAM_Apply_SM command. */
#define PHHAL_HW_SAMAV3_CMD_APPLY_REMOVE_SM_COMM_MODE_MAC			0x10	/**< Option mask for communication mode as MAC for Cmd.SAM_Apply_SM and Cmd.SAM_Remove_SM command. */
#define PHHAL_HW_SAMAV3_CMD_APPLY_REMOVE_SM_COMM_MODE_FULL			0x30	/**< Option mask for communication mode as FULL for Cmd.SAM_Apply_SM and Cmd.SAM_Remove_SM command. */
/* @} */

/** \name Option macros for Sam AV3 Data Processing Cmd.SAM_Apply_SM. */
/* @{ */
#define PHHAL_HW_SAMAV3_CMD_APPLY_SM_EXCLUDE_OFFSET					0x00	/**< Option mask for not exchanging the Offset information for Cmd.SAM_Apply_SM command. */
#define PHHAL_HW_SAMAV3_CMD_APPLY_SM_INCLUDE_OFFSET					0x80	/**< Option mask for exchanging the Offset information for Cmd.SAM_Apply_SM command. */
/* @} */

/**
 * \brief Applys the DESFire EV2 Secure Messaging in S-mode on the provided DESFire EV2 command according to the required
 * mode and the currently activated session keys. The required protection mode is selected via the command parameter bCommMode.
 *
 * \return Status code
 * \retval #PH_ERR_SUCCESS Operation successful.
 * \retval #PH_ERR_SUCCESS_CHAINING Operation successful, chaining ongoing.
 * \retval Other Depending on implementation and underlaying component.
 */
phStatus_t phhalHw_SamAV3_Cmd_SAM_ApplySM(
    phhalHw_SamAV3_DataParams_t
    *pDataParams,							/**< [In] Pointer to this layer's parameter structure. */
    uint16_t wOption,													/**< [In] Option for including the length information in command frame.
																			 *			\arg #PHHAL_HW_SAMAV3_CMD_APPLY_SM_EXCLUDE_OFFSET
																			 *			\arg #PHHAL_HW_SAMAV3_CMD_APPLY_SM_INCLUDE_OFFSET
																			 *
																			 *		  Buffering options.
																			 *			\arg #PH_EXCHANGE_DEFAULT
																			 *			\arg #PH_EXCHANGE_BUFFER_FIRST
																			 *			\arg #PH_EXCHANGE_BUFFER_CONT
																			 *			\arg #PH_EXCHANGE_BUFFER_LAST
																			 *			\arg #PH_EXCHANGE_TXCHAINING
																			 *
																			 *			#PH_EXCHANGE_TXCHAINING should be used to exchange chunks of data.
																			 */
    uint8_t bCommMode,													/**< [In] Communication mode to be used.
																			 *			\arg #PHHAL_HW_SAMAV3_CMD_APPLY_SM_COMM_MODE_PLAIN
																			 *			\arg #PHHAL_HW_SAMAV3_CMD_APPLY_REMOVE_SM_COMM_MODE_MAC
																			 *			\arg #PHHAL_HW_SAMAV3_CMD_APPLY_REMOVE_SM_COMM_MODE_FULL
																			 */
    uint8_t bOffset,													/**< [In] Command offset. Index of the first byte in data field of the PICC command data. */
    uint8_t bCmdCtrIncr,												/**< [In] Command counter increment value. Value by which to increase the CmdCtr. */
    uint8_t *pTxData,													/**< [In] Plain data to be protected according to the communication mode specified. */
    uint8_t bTxDataLen,													/**< [In] Length of plain data to be sent for protection. */
    uint8_t **ppRxData,												/**< [Out] The protected data returned by Sam according to communication mode specified. */
    uint16_t *pRxDataLen												/**< [Out] Length of protected data returned. */
);

/**
 * \brief Removes the DESFire EV2 Secure Messaging in S-mode ([22]) from the provided PICC response payload according
 * to the required mode and the currently activated session keys. The required protection mode is selected via the
 * command parameter bCommMode.
 *
 * \return Status code
 * \retval #PH_ERR_SUCCESS Operation successful.
 * \retval #PH_ERR_SUCCESS_CHAINING Operation successful, chaining ongoing.
 * \retval Other Depending on implementation and underlaying component.
 */
phStatus_t phhalHw_SamAV3_Cmd_SAM_RemoveSM(
    phhalHw_SamAV3_DataParams_t
    *pDataParams,							/**< [In] Pointer to this layer's parameter structure. */
    uint16_t wOption,													/**< [In] Buffering options.
																			 *			\arg #PH_EXCHANGE_DEFAULT
																			 *			\arg #PH_EXCHANGE_BUFFER_FIRST
																			 *			\arg #PH_EXCHANGE_BUFFER_CONT
																			 *			\arg #PH_EXCHANGE_BUFFER_LAST
																			 *			\arg #PH_EXCHANGE_TXCHAINING
																			 *
																			 *			#PH_EXCHANGE_TXCHAINING should be used to exchange chunks of data.
																			 */
    uint8_t bCommMode,													/**< [In] Communication mode to be used.
																			 *			\arg #PHHAL_HW_SAMAV3_CMD_APPLY_REMOVE_SM_COMM_MODE_MAC
																			 *			\arg #PHHAL_HW_SAMAV3_CMD_APPLY_REMOVE_SM_COMM_MODE_FULL
																			 */
    uint8_t *pTxData,													/**< [In] The complete data received form the PICC including the status code. */
    uint8_t bTxDataLen,													/**< [In] Length of data available in TxData buffer. */
    uint8_t **ppRxData,												/**< [Out] The plain data returned by Sam according to communication mode specified. */
    uint16_t *pRxDataLen												/**< [Out] Length of plain data returned. */
);

/** \name Option macros for Sam AV3 Data Processing Cmd.SAM_Verify_MAC and Cmd.SAM_GenerateMAC command. */
/* @{ */
#define PHHAL_HW_SAMAV3_TRUNCATION_MODE_STANDARD					0x00	/**< Option mask for truncation mode as standard trunction. */
#define PHHAL_HW_SAMAV3_TRUNCATION_MODE_MFP							0x80	/**< Option mask for truncation mode as MFP trunction. */
/* @} */

/**
 * \brief Verifies the MAC which was sent by the PICC or any other system based on the given MACed plain text data
 * and the currently valid cryptographic key.
 *
 * \return Status code
 * \retval #PH_ERR_SUCCESS Operation successful.
 * \retval #PH_ERR_SUCCESS_CHAINING Operation successful, chaining ongoing.
 * \retval Other Depending on implementation and underlaying component.
 */
phStatus_t phhalHw_SamAV3_Cmd_SAM_VerifyMAC(
    phhalHw_SamAV3_DataParams_t
    *pDataParams,							/**< [In] Pointer to this layer's parameter structure. */
    uint16_t wOption,													/**< [In] Buffering options.
																			 *			\arg #PH_EXCHANGE_DEFAULT
																			 *			\arg #PH_EXCHANGE_BUFFER_FIRST
																			 *			\arg #PH_EXCHANGE_BUFFER_CONT
																			 *			\arg #PH_EXCHANGE_BUFFER_LAST
																			 *			\arg #PH_EXCHANGE_TXCHAINING
																			 *
																			 *			#PH_EXCHANGE_TXCHAINING should be used to exchange chunks of data.
																			 */
    uint8_t bNum,														/**< [In] Type of truncation mode to be applied if AES key type is used.
																			 *			\arg #PHHAL_HW_SAMAV3_TRUNCATION_MODE_STANDARD
																			 *			\arg #PHHAL_HW_SAMAV3_TRUNCATION_MODE_MFP
																			 *
																			 *		  Number of MAC bytes to check in the plain data buffer.
																			 *		  Number of Bytes should be combined with one of the above two options.
																			 */
    uint8_t *pTxData,													/**< [In] Plain data including the MAC to be checked. */
    uint8_t bTxDataLen													/**< [In] Length of data available in TxData buffer. */
);

/** \name Option macros for Sam AV3 Data Processing Cmd.SAM_GenerateMAC command. */
/* @{ */
#define PHHAL_HW_SAMAV3_GENERATE_MAC_INCLUDE_LC						0x80	/**< Option mask for inclusion of LC in the command frame. */
/* @} */

/**
 * \brief Generates a MAC which is meant to be sent to the PICC or any other system based on the given plain text data
 * and the currently valid cryptographic key.
 *
 * \return Status code
 * \retval #PH_ERR_SUCCESS Operation successful.
 * \retval #PH_ERR_SUCCESS_CHAINING Operation successful, chaining ongoing.
 * \retval Other Depending on implementation and underlaying component.
 */
phStatus_t phhalHw_SamAV3_Cmd_SAM_GenerateMAC(
    phhalHw_SamAV3_DataParams_t
    *pDataParams,							/**< [In] Pointer to this layer's parameter structure. */
    uint16_t wOption,													/**< [In] Buffering options.
																			 *			\arg #PH_EXCHANGE_DEFAULT
																			 *			\arg #PH_EXCHANGE_BUFFER_FIRST
																			 *			\arg #PH_EXCHANGE_BUFFER_CONT
																			 *			\arg #PH_EXCHANGE_BUFFER_LAST
																			 *			\arg #PH_EXCHANGE_TXCHAINING
																			 *
																			 *			\arg #PH_EXCHANGE_TXCHAINING should be used to exchange chunks of data.
																			 *			\arg #PHHAL_HW_SAMAV3_GENERATE_MAC_INCLUDE_LC should be used for inclusion of
																			 *			LC when #PH_EXCHANGE_BUFFER_FIRST is used and TxDataLen is not available but
																			 *			TxDataLen is part of #PH_EXCHANGE_BUFFER_CONT or #PH_EXCHANGE_BUFFER_LAST.
																			 */
    uint8_t bNum,														/**< [In] Type of truncation mode to be applied if AES key type is used.
																			 *			\arg #PHHAL_HW_SAMAV3_TRUNCATION_MODE_STANDARD
																			 *			\arg #PHHAL_HW_SAMAV3_TRUNCATION_MODE_MFP
																			 *
																			 *		  Number of MAC bytes to check in the plain data buffer.
																			 *		  Number of Bytes should be combined with one of the above two options.
																			 */
    uint8_t *pTxData,													/**< [In] Plain data to be maced. Can be null if there is no data. */
    uint8_t bTxDataLen,													/**< [In] Length of input data. Can be zero if there is no Plain data. */
    uint8_t **ppRxData,												/**< [Out] The generated MAC returned by Sam hardware. */
    uint16_t *pRxDataLen												/**< [Out] Length of Maced data returned. */
);

/** \name Option macros for Sam AV3 Data Processing Cmd.SAM_Decipher_Data command. */
/* @{ */
#define PHHAL_HW_SAMAV3_DECIPHER_LENGTH_EXCLUDE						0x00	/**< Option mask for excluding the length intformation in the command frame. */
#define PHHAL_HW_SAMAV3_DECIPHER_LENGTH_INCLUDE						0x80	/**< Option mask for including the length intformation in the command frame. */
/* @} */

/**
 * \brief Deciphers data packages sent by a PICC, any other system or a MIFARE card based on the currently valid
 * cryptographic key and returns plain data to the host.
 *
 * \return Status code
 * \retval #PH_ERR_SUCCESS Operation successful.
 * \retval #PH_ERR_SUCCESS_CHAINING Operation successful, chaining ongoing.
 * \retval Other Depending on implementation and underlaying component.
 */
phStatus_t phhalHw_SamAV3_Cmd_SAM_DecipherData(
    phhalHw_SamAV3_DataParams_t
    *pDataParams,							/**< [In] Pointer to this layer's parameter structure. */
    uint16_t wOption,													/**< [In] Option for including the length information in command frame.
																			 *			\arg #PHHAL_HW_SAMAV3_DECIPHER_LENGTH_EXCLUDE
																			 *			\arg #PHHAL_HW_SAMAV3_DECIPHER_LENGTH_INCLUDE
																			 *
																			 *		  Buffering options.
																			 *			\arg #PH_EXCHANGE_DEFAULT
																			 *			\arg #PH_EXCHANGE_BUFFER_FIRST
																			 *			\arg #PH_EXCHANGE_BUFFER_CONT
																			 *			\arg #PH_EXCHANGE_BUFFER_LAST
																			 *			\arg #PH_EXCHANGE_TXCHAINING
																			 *
																			 *			#PH_EXCHANGE_TXCHAINING should be used to exchange chunks of data.
																			 */
    uint8_t *pEncData,													/**< [In] Encrypted data to be deciphered. */
    uint8_t bEncDataLen,												/**< [In] Length of Encrypted data. */
    uint8_t *pLength,													/**< [In] Overall length of encrypted input data. This 3 byte value is only used if indicated by wOption. */
    uint8_t **ppPlainData,												/**< [Out] Deciphered data returned by Sam hardware. */
    uint16_t *pPlainDataLen											/**< [Out] Length of deciphered data. */
);

/**
 * \brief Enciphers data packages which are meant to be sent to a PICC or any other system based on the given
 * plain text data and the currently valid cryptographic key.
 *
 * \return Status code
 * \retval #PH_ERR_SUCCESS Operation successful.
 * \retval #PH_ERR_SUCCESS_CHAINING Operation successful, chaining ongoing.
 * \retval Other Depending on implementation and underlaying component.
 */
phStatus_t phhalHw_SamAV3_Cmd_SAM_EncipherData(
    phhalHw_SamAV3_DataParams_t
    *pDataParams,							/**< [In] Pointer to this layer's parameter structure. */
    uint16_t wOption,													/**< [In] Buffering options.
																			 *			\arg #PH_EXCHANGE_DEFAULT
																			 *			\arg #PH_EXCHANGE_BUFFER_FIRST
																			 *			\arg #PH_EXCHANGE_BUFFER_CONT
																			 *			\arg #PH_EXCHANGE_BUFFER_LAST
																			 *			\arg #PH_EXCHANGE_TXCHAINING
																			 *
																			 *			#PH_EXCHANGE_TXCHAINING should be used to exchange chunks of data.
																			 */
    uint8_t *pPlainData,												/**< [In] Data to be enciphered. */
    uint8_t bPlainDataLen,												/**< [In] Length of input data. */
    uint8_t bOffset,													/**< [In] Offset into the input data indicating the first data byte to be enciphered. */
    uint8_t **ppEncData,												/**< [Out] Enciphered data returned by Sam hardware. */
    uint16_t *pEncDataLen												/**< [Out] Length of enciphered data. */
);

/**
 * \brief Decrypts data received from any other system based on the given cipher text data and the currently valid
 * cryptographic OfflineCrypto Key. The valid key has been activated using a valid key activation (Cmd.SAM_ActivateOfflineKey).
 *
 * \return Status code
 * \retval #PH_ERR_SUCCESS Operation successful.
 * \retval #PH_ERR_SUCCESS_CHAINING Operation successful, chaining ongoing.
 * \retval Other Depending on implementation and underlaying component.
 */
phStatus_t phhalHw_SamAV3_Cmd_SAM_DecipherOfflineData(
    phhalHw_SamAV3_DataParams_t
    *pDataParams,							/**< [In] Pointer to this layer's parameter structure. */
    uint16_t wOption,													/**< [In] Buffering options.
																			 *			\arg #PH_EXCHANGE_DEFAULT
																			 *			\arg #PH_EXCHANGE_BUFFER_FIRST
																			 *			\arg #PH_EXCHANGE_BUFFER_CONT
																			 *			\arg #PH_EXCHANGE_BUFFER_LAST
																			 *			\arg #PH_EXCHANGE_TXCHAINING
																			 *
																			 *			#PH_EXCHANGE_TXCHAINING should be used to exchange chunks of data.
																			 */
    uint8_t *pEncData,													/**< [In] Encrypted data to be deciphered. */
    uint8_t bEncDataLen,												/**< [In] Length of Encrypted data. */
    uint8_t **ppPlainData,												/**< [Out Deciphered data returned by Sam hardware. */
    uint16_t *pPlainDataLen											/**< [Out] Length of deciphered data. */
);

/**
 * \brief Encrypts data received from any other system based on the given cipher text data and the currently valid
 * cryptographic OfflineCrypto Key. The valid key has been activated using a valid key activation (Cmd.SAM_ActivateOfflineKey).
 *
 * \return Status code
 * \retval #PH_ERR_SUCCESS Operation successful.
 * \retval #PH_ERR_SUCCESS_CHAINING Operation successful, chaining ongoing.
 * \retval Other Depending on implementation and underlaying component.
 */
phStatus_t phhalHw_SamAV3_Cmd_SAM_EncipherOfflineData(
    phhalHw_SamAV3_DataParams_t
    *pDataParams,							/**< [In] Pointer to this layer's parameter structure. */
    uint16_t wOption,													/**< [In] Buffering options.
																			 *			\arg #PH_EXCHANGE_DEFAULT
																			 *			\arg #PH_EXCHANGE_BUFFER_FIRST
																			 *			\arg #PH_EXCHANGE_BUFFER_CONT
																			 *			\arg #PH_EXCHANGE_BUFFER_LAST
																			 *			\arg #PH_EXCHANGE_TXCHAINING
																			 *
																			 *			#PH_EXCHANGE_TXCHAINING should be used to exchange chunks of data.
																			 */
    uint8_t *pPlainData,												/**< [In] Plain data to be enciphered. */
    uint8_t bPlainDataLen,												/**< [In] Length of plain data. */
    uint8_t **ppEncData,												/**< [Out] Enciphered data returned by Sam hardware. */
    uint16_t *pEncDataLen												/**< [Out] Length of enciphered data. */
);

/**
 * end of phhalHw_SamAV3_Cmd_DataProcessing
 * @}
 */

/*************************************************************************************************************************/
/*********************************************** Public Key Infrastructure ***********************************************/
/*************************************************************************************************************************/

/** \defgroup phhalHw_SamAV3_Cmd_PKI Public Key Infrastructure
 * \see
 * \brief SAM commands used for asymmetric key management, signature handling and symmetric key updates based on PKI.
 * @{
 */

/**
 * \name Option macros for Sam AV3 Public Key Infrastructure ImportKey and ImportEccKey command.
 */
/* @{ */
#define PHHAL_HW_SAMAV3_CMD_PKI_UPDATE_KEY_SETTINGS_VALUE		0x00	/**< Option mask for updating key settings and key values. */
#define PHHAL_HW_SAMAV3_CMD_PKI_UPDATE_KEY_SETTINGS_ONLY		0x01	/**< Option mask for updating key settings only. */
/* @} */

/** \defgroup phhalHw_SamAV3_Cmd_PKI_RSA RSA
 * \see
 * \brief SAM commands used for asymmetric RSA key management, signature handling and symmetric key updates based on PKI.
 * @{
 */

/**
 * \name Sam AV3 command code for Public Key Infrastructure features.
 */
/* @{ */
#define PHHAL_HW_SAMAV3_CMD_PKI_GENERATE_KEY_PAIR_INS			0x15	/**< Sam AV3 Instruction code for Cmd.PKI_GenerateKeyPair command. */
#define PHHAL_HW_SAMAV3_CMD_PKI_IMPORT_KEY_INS					0x19	/**< Sam AV3 Instruction code for Cmd.PKI_ImportKey command. */
#define PHHAL_HW_SAMAV3_CMD_PKI_EXPORT_PRIVATE_KEY_INS			0x1F	/**< Sam AV3 Instruction code for Cmd.PKI_ExportPrivateKey command. */
#define PHHAL_HW_SAMAV3_CMD_PKI_EXPORT_PUBLIC_KEY_INS			0x18	/**< Sam AV3 Instruction code for Cmd.PKI_ExportPublicKey command. */
#define PHHAL_HW_SAMAV3_CMD_PKI_UPDATE_KEY_ENTRIES_INS			0x1D	/**< Sam AV3 Instruction code for Cmd.PKI_UpdateKeyEntries command. */
#define PHHAL_HW_SAMAV3_CMD_PKI_ENCIPHER_KEY_ENTRIES_INS		0x12	/**< Sam AV3 Instruction code for Cmd.PKI_EncipherKeyEntries command. */
#define PHHAL_HW_SAMAV3_CMD_PKI_GENERATE_HASH_INS				0x17	/**< Sam AV3 Instruction code for Cmd.PKI_GenerateHsh command. */
#define PHHAL_HW_SAMAV3_CMD_PKI_GENERATE_SIGNATURE_INS			0x16    /**< Sam AV3 Instruction code for Cmd.PKI_GenerateSignature command */
#define PHHAL_HW_SAMAV3_CMD_PKI_SEND_SIGNATURE_INS				0x1A    /**< Sam AV3 Instruction code for Cmd.PKI_SendSignature command. */
#define PHHAL_HW_SAMAV3_CMD_PKI_VERIFY_SIGNATURE_INS			0x1B    /**< Sam AV3 Instruction code for Cmd.PKI_VerifySignature command. */
#define PHHAL_HW_SAMAV3_CMD_PKI_ENCIPHER_DATA_INS				0x13    /**< Sam AV3 Instruction code for Cmd.PKI_EncipherData command. */
#define PHHAL_HW_SAMAV3_CMD_PKI_DECIPHER_DATA_INS				0x14    /**< Sam AV3 Instruction code for Cmd.PKI_Decipher command. */
/* @} */

/**
 * \name Option macros for Sam AV3 Public Key Infrastructure GenerateKeyPair command.
 */
/* @{ */
#define PHHAL_HW_SAMAV3_CMD_PKI_GENERATE_KEY_PAIR_RANDOM_E		0x00	/**< Option mask for a key generation with a randomly selected exponent e. */
#define PHHAL_HW_SAMAV3_CMD_PKI_GENERATE_KEY_PAIR_HOST_E		0x01	/**< Option mask for a key generation with a given exponent e. */

#define PHHAL_HW_SAMAV3_CMD_PKI_GENERATE_KEY_PAIR_AEK_EXCLUDE	0x00	/**< Option mask for a key generation with Access Entry Key excluded. */
#define PHHAL_HW_SAMAV3_CMD_PKI_GENERATE_KEY_PAIR_AEK_INCLUDE	0x02	/**< Option mask for a key generation with Access Entry Key included. */
/* @} */

/**
 * \name Option macros for Sam AV3 Public Key Infrastructure ImportKey command.
 */
/* @{ */
#define PHHAL_HW_SAMAV3_CMD_PKI_IMPORT_KEY_AEK_EXCLUDE			0x00	/**< Option mask for importing a key with Access Entry Key excluded. */
#define PHHAL_HW_SAMAV3_CMD_PKI_IMPORT_KEY_AEK_INCLUDE			0x02	/**< Option mask for importing a key with Access Entry Key included. */
/* @} */

/**
 * \name Option macros for Sam AV3 Public Key Infrastructure ExportPrivateKey command.
 */
/* @{ */
#define PHHAL_HW_SAMAV3_CMD_PKI_EXPORT_PRIVATE_KEY_AEK_EXCLUDE	0x0000	/**< Option mask for disabling export of Access Entry Key number and version. */
#define PHHAL_HW_SAMAV3_CMD_PKI_EXPORT_PRIVATE_KEY_AEK_INCLUDE	0x0080	/**< Option mask for enabling export of Access Entry Key number and version. */
/* @} */

/**
 * \name Option macros for Sam AV3 Public Key Infrastructure ExportPublicKey command.
 */
/* @{ */
#define PHHAL_HW_SAMAV3_CMD_PKI_EXPORT_PUBLIC_KEY_AEK_EXCLUDE	0x0000	/**< Option mask for disabling export of Access Entry Key number and version. */
#define PHHAL_HW_SAMAV3_CMD_PKI_EXPORT_PUBLIC_KEY_AEK_INCLUDE	0x0080	/**< Option mask for enabling export of Access Entry Key number and version. */
/* @} */

/**
 * \name Option macros for Sam AV3 Public Key Infrastructure hash algorithms.
 */
/* @{ */
#define PHHAL_HW_SAMAV3_CMD_PKI_HASH_ALGORITHM_SHA_1			0x00	/**< Option mask for SHA 1 hashing algorithm to be used. */
#define PHHAL_HW_SAMAV3_CMD_PKI_HASH_ALGORITHM_SHA_224			0x01	/**< Option mask for SHA 224 hashing algorithm to be used. */
#define PHHAL_HW_SAMAV3_CMD_PKI_HASH_ALGORITHM_RFU				0x02	/**< Option mask for RFU hashing algorithm to be used. */
#define PHHAL_HW_SAMAV3_CMD_PKI_HASH_ALGORITHM_SHA_256			0x03	/**< Option mask for SHA 256 hashing algorithm to be used. */
/* @} */

/**
 * \name Option macros for Sam AV3 Public Key Infrastructure UpdateKeyEntries command.
 */
/* @{ */
#define PHHAL_HW_SAMAV3_CMD_PKI_UPDATE_KEY_ENTRY_ACK_EXCLUDE	0x00	/**< Option mask for excluding the LE byte and Acknowledge key number. */
#define PHHAL_HW_SAMAV3_CMD_PKI_UPDATE_KEY_ENTRY_ACK_INCLUDE	0x80	/**< Option mask for including the LE byte and Acknowledge key number. */
/* @} */

/**
 * \name Option macros for Sam AV3 Public Key Infrastructure key diversification.
 */
/* @{ */
#define PHHAL_HW_SAMAV3_CMD_PKI_DIVERSIFICATION_OFF				0x00	/**< Option mask disabling the key diversification. */
#define PHHAL_HW_SAMAV3_CMD_PKI_DIVERSIFICATION_ON				0x10	/**< Option mask enabling the key diversification. */
/* @} */

/**
 * \name Option macros for Sam AV3 Public Key Infrastructure GenerateHash command.
 */
/* @{ */
#define PHHAL_HW_SAMAV3_CMD_PKI_GENERATE_HASH_FIRST_FRAME		0x04	/**< Option mask for a framing the first frame of Generate hash command. */
/* @} */

#define PHHAL_HW_SAMAV3_CMD_PKI_GENERATE_KEY_PAIR_CMD_SIZE		17U		/**< Macro to represent the PKI_GenerateKeyPair command size. */
#define PHHAL_HW_SAMAV3_CMD_PKI_IMPORT_KEY_CMD_SIZE				21U		/**< Macro to represent the PKI_ImportKey command size. */
#define PHHAL_HW_SAMAV3_CMD_PKI_GENERATE_HASH_CMD_SIZE			9U		/**< Macro to represent the PKI_GenerateHash command size. */
#define PHHAL_HW_SAMAV3_CMD_PKI_ENCIPHER_KEY_ENTRIES_CMD_SIZE	11U		/**< Macro to represent the PKI_EncipherKeyEntries command size. */
#define PHHAL_HW_SAMAV3_CMD_PKI_ENCIPHER_DATA_CMD_SIZE			6U		/**< Macro to represent the PKI_EncipherData command size. */
#define PHHAL_HW_SAMAV3_CMD_PKI_DECIPHER_DATA_CMD_SIZE			6U		/**< Macro to represent the PKI_DecipherData command size. */

#define PHHAL_HW_SAMAV3_CMD_PKI_GENERATE_KEY_PAIR_LC_MIN		10U		/**< Minimun Length of LC data for PKI_GenerateKeyPair command. */
#define PHHAL_HW_SAMAV3_CMD_PKI_IMPORT_KEY_LC_MIN				6U		/**< Minimun Length of LC data for PKI_ImportKey command. */

/**
 * \brief Create an RSA key pair. This command is available for AV2 and AV3 version(s).
 * \return Status code
 * \retval #PH_ERR_SUCCESS Operation successful.
 * \retval Other Depending on implementation and underlaying component.
 */
phStatus_t phhalHw_SamAV3_Cmd_PKI_GenerateKeyPair(
    phhalHw_SamAV3_DataParams_t
    *pDataParams,						/**< [In] Pointer to this layer's parameter structure. */
    uint8_t bOption,												/**< [In] Option for P1 information byte.
																		  *			\arg #PHHAL_HW_SAMAV3_CMD_PKI_GENERATE_KEY_PAIR_RANDOM_E
																		  *			\arg #PHHAL_HW_SAMAV3_CMD_PKI_GENERATE_KEY_PAIR_HOST_E
																		  *			\arg #PHHAL_HW_SAMAV3_CMD_PKI_GENERATE_KEY_PAIR_AEK_EXCLUDE
																		  *			\arg #PHHAL_HW_SAMAV3_CMD_PKI_GENERATE_KEY_PAIR_AEK_INCLUDE
																		  */
    uint8_t bPKI_KeyNo,												/**< [In] Reference number of the key entry where the created key should be stored (00h to 01h). */
    uint16_t wPKI_Set,												/**< [In] Configuration settings of the created key entry. */
    uint8_t bPKI_KeyNoCEK,											/**< [In] Reference number to the change key of the created key entry. */
    uint8_t bPKI_KeyVCEK,											/**< [In] Version of the change key of the created key entry. */
    uint8_t bPKI_RefNoKUC,  										/**< [In] Reference number to the KUC of the created key entry. */
    uint8_t bPKI_KeyNoAEK,											/**< [In] Reference number to the created access key entry.  \n
																		  *			\c 0xFE			: No Access Restrictions \n
																		  *			\c 0xFF			: Entry Disabled \n
																		  *			\c 0x00 - 0x7F	: Access key entry number \n
																		  */
    uint8_t bPKI_KeyVAEK,											/**< [In] Version of the created acces key entry. */
    uint16_t wPKI_NLen,     										/**< [In] Length of the modulus N (multiple of 8 and in [32;256]). */
    uint16_t wPKI_eLen,     										/**< [In] Length of the exponent e (multiple of 4 and in [4;256]). */
    uint8_t *pPKI_e        										/**< [In] Buffer containing the exponent e provided by user or host. */
);

/**
 * \brief Import a public or private RSA key.
 * \return Status code
 * \retval #PH_ERR_SUCCESS Operation successful.
 * \retval Other Depending on implementation and underlaying component.
 */
phStatus_t phhalHw_SamAV3_Cmd_PKI_ImportKey(
    phhalHw_SamAV3_DataParams_t
    *pDataParams,						/**< [In] Pointer to this layer's parameter structure. */
    uint8_t bOption,												/**< [In] Option for P1 information byte.
																		  *			\arg #PHHAL_HW_SAMAV3_CMD_PKI_UPDATE_KEY_SETTINGS_VALUE
																		  *			\arg #PHHAL_HW_SAMAV3_CMD_PKI_UPDATE_KEY_SETTINGS_ONLY
																		  *			\arg #PHHAL_HW_SAMAV3_CMD_PKI_IMPORT_KEY_AEK_INCLUDE
																		  *			\arg #PHHAL_HW_SAMAV3_CMD_PKI_IMPORT_KEY_AEK_EXCLUDE
																		  */
    uint8_t bPKI_KeyNo,												/**< [In] Reference Number of the key entry to be imported (00h to 01h if private key is included or 00h to 02h if not included). */
    uint16_t wPKI_Set,												/**< [In] Configuration settings of the imported key entry. It indicates wheter a private of public key shall be imported.  */
    uint8_t bPKI_KeyNoCEK,											/**< [In] Reference number to the change key of the imported key entry.
																		 *			\c 0xFE       : No Restrictions \n
																		 *			\c 0xFF       : Entry Locked \n
																		 *			\c 0x00 - 0x7F: Restricted to specific permanent KST Key Entry \n
																		 */
    uint8_t bPKI_KeyVCEK,											/**< [In] Version of the change key of the imported key entry. */
    uint8_t bPKI_RefNoKUC,											/**< [In] Reference number to the KUC of the created key entry. */
    uint8_t bPKI_KeyNoAEK,											/**< [In] Reference number to the created access key entry.  \n
																		  *			\c 0xFE			: No Access Restrictions \n
																		  *			\c 0xFF			: Entry Disabled \n
																		  *			\c 0x00 - 0x7F	: Access key entry number \n
																		  */
    uint8_t bPKI_KeyVAEK,											/**< [In] Version of the created acces key entry. */
    uint16_t wPKI_NLen,												/**< [In] Length of Modulus N (multiple of 8 and in [32;256]). */
    uint16_t wPKI_eLen,												/**< [In] Length of exponent e (multiple of 4 and in [4;256]). */
    uint16_t wPKI_PLen,												/**< [In] Length of prime P. */
    uint16_t wPKI_QLen,												/**< [In] Length of prime Q. */
    uint8_t *pPKI_N,												/**< [In] Buffer containing the Modulus N. */
    uint8_t *pPKI_e,												/**< [In] Buffer containing the Exponent e. */
    uint8_t *pPKI_p,												/**< [In] Buffer containing the Prime P. */
    uint8_t *pPKI_q,												/**< [In] Buffer containing the Prime Q. */
    uint8_t *pPKI_dP,												/**< [In] Parameter dP padded up to a length of wPKI_PLen. */
    uint8_t *pPKI_dQ,												/**< [In] Parameter dQ padded up to a length of wPKI_QLen. */
    uint8_t *pPKI_ipq												/**< [In] Inverse P(-1) mod Q padded up to a length of wPKI_QLen. */
);

/**
 * \brief Export the private part of an RSA key pair. This command is only available for AV2 and AV3 version(s).
 * \return Status code
 * \retval #PH_ERR_SUCCESS Operation successful, command completed.
 * \retval #PH_ERR_SUCCESS_CHAINING Operation successful, chaining ongoing.
 * \retval Other Depending on implementation and underlaying component.
 */
phStatus_t phhalHw_SamAV3_Cmd_PKI_ExportPrivateKey(
    phhalHw_SamAV3_DataParams_t
    *pDataParams,						/**< [In] Pointer to this layer's parameter structure. */
    uint16_t wOption,												/**< [In] Option for AEK selection and differentiating between first part and last part of data.
																		  *			\arg #PHHAL_HW_SAMAV3_CMD_PKI_EXPORT_PRIVATE_KEY_AEK_EXCLUDE
																		  *			\arg #PHHAL_HW_SAMAV3_CMD_PKI_EXPORT_PRIVATE_KEY_AEK_INCLUDE
																		  *			\n
																		  *			Should be combined with the above option
																		  *			\arg #PH_EXCHANGE_DEFAULT (for receiving the first part of data)
																		  *			\arg #PH_EXCHANGE_RXCHAINING (for receiving the final part of data)
																		  */
    uint8_t bPKI_KeyNo,												/**< [In] Reference number of the key entry to be exported (00h to 01h). */
    uint8_t **ppKeyData,											/**< [Out] Pointer to received key data.*/
    uint16_t *pKeyDataLen											/**< [Out] Length of received data. */
);

/**
 * \brief Export the public part of an RSA key pair. This command is only available for AV2 and AV3 version(s).
 * \return Status code
 * \retval #PH_ERR_SUCCESS Operation successful, command completed.
 * \retval #PH_ERR_SUCCESS_CHAINING Operation successful, chaining ongoing.
 * \retval Other Depending on implementation and underlaying component.
 */
phStatus_t phhalHw_SamAV3_Cmd_PKI_ExportPublicKey(
    phhalHw_SamAV3_DataParams_t
    *pDataParams,						/**< [In] Pointer to this layer's parameter structure. */
    uint16_t wOption,												/**< [In] Option for AEK selection and differentiating between first part and last part of data.
																		  *			\arg #PHHAL_HW_SAMAV3_CMD_PKI_EXPORT_PUBLIC_KEY_AEK_EXCLUDE
																		  *			\arg #PHHAL_HW_SAMAV3_CMD_PKI_EXPORT_PUBLIC_KEY_AEK_INCLUDE
																		  *			\n
																		  *			Should be combined with the above option
																		  *			\arg #PH_EXCHANGE_DEFAULT (for receiving the first part of data)
																		  *			\arg #PH_EXCHANGE_RXCHAINING (for receiving the final part of data)
																		  */
    uint8_t bPKI_KeyNo,												/**< [In] Reference number of the key entry to be exported (00h to 01h). */
    uint8_t **ppKeyData,											/**< [Out] Pointer to received key data.*/
    uint16_t *pKeyDataLen											/**< [Out] Length of received data. */
);

/**
 * \brief Change up to 3 symmetric key entries by using PKI.
 * \return Status code
 * \retval #PH_ERR_SUCCESS Operation successful.
 * \retval Other Depending on implementation and underlaying component.
 */
phStatus_t phhalHw_SamAV3_Cmd_PKI_UpdateKeyEntries(
    phhalHw_SamAV3_DataParams_t
    *pDataParams,						/**< [In] Pointer to this layer's parameter structure. */
    uint8_t bOption,												/**< [In] Option to receive the UploadACK.
																		  *			\arg #PH_EXCHANGE_DEFAULT
																		  *			\arg #PH_EXCHANGE_RXCHAINING (If #PH_ERR_SUCCESS_CHAINING is returned as the status.)
																		  *		  \n
																		  *		  Should be combined with the above option
																		  *		  Option to include Le byte and Acknowledge key number to command frame for receiving
																		  *		  the UpdateAck data from Sam hardware.
																		  *			\arg #PHHAL_HW_SAMAV3_CMD_PKI_UPDATE_KEY_ENTRY_ACK_EXCLUDE
																		  *			\arg #PHHAL_HW_SAMAV3_CMD_PKI_UPDATE_KEY_ENTRY_ACK_INCLUDE
																		  */
    uint8_t bNoOfKeyEntries,										/**< [In] Number of symmetric key entries to update. \n
																		  *			\c 0x00: RFU \n
																		  *			\c 0x01: 1 Key Entry \n
																		  *			\c 0x02: 2 Key Entry \n
																		  *			\c 0x03: 3 Key Entry \n
																		  */
    uint8_t bHashingAlg,											/**< [In] Hashing algorithm selection (for padding MGFs and digital signature).
																		  *			\arg #PHHAL_HW_SAMAV3_CMD_PKI_HASH_ALGORITHM_SHA_1
																		  *			\arg #PHHAL_HW_SAMAV3_CMD_PKI_HASH_ALGORITHM_SHA_224
																		  *			\arg #PHHAL_HW_SAMAV3_CMD_PKI_HASH_ALGORITHM_SHA_256
																		  *			\arg #PHHAL_HW_SAMAV3_CMD_PKI_HASH_ALGORITHM_RFU
																		  */
    uint8_t bPKI_KeyNo_Enc,											/**< [In] Reference number of the RSA key entry to be used for decryption (00h to 01h). */
    uint8_t bPKI_KeyNo_Sign,										/**< [In] Reference number of the RSA key entry to be used for signature verification (00h to 02h). */
    uint8_t bPKI_KeyNo_Ack,											/**< [In] Reference number of the RSA key entry to be used for acknowledge signature generation (00h to 01h). */
    uint8_t *pKeyFrame,											/**< [In] Buffer containing the RSA encrypted key entries and the signature. */
    uint16_t wKeyFrameLen,											/**< [In] Length of RSA encrypted key entries and the signature. */
    uint8_t **ppUpdateACK,											/**< [Out] Buffer containing the RSA encrypted Acknowledge signature. */
    uint16_t *pUpdateACKLen										/**< [Out] Length of RSA encrypted Acknowledge signature. */
);

/**
 * \brief Prepare a cryptogram (according to Asymmetric Offline Change Cryptogram) for the PKI offline update of
 * KST key entries on a target SAM. This command is only available for AV3 version(s).
 * \return Status code
 * \retval #PH_ERR_SUCCESS Operation successful, command completed.
 * \retval #PH_ERR_SUCCESS_CHAINING Operation successful, chaining ongoing.
 * \retval Other Depending on implementation and underlaying component.
 */
phStatus_t phhalHw_SamAV3_Cmd_PKI_EncipherKeyEntries(
    phhalHw_SamAV3_DataParams_t
    *pDataParams,						/**< [In] Pointer to this layer's parameter structure. */
    uint16_t wOption,												/**< [In] Option to differentiate between the command frame to be exchanged.
																		  *			\arg #PH_EXCHANGE_DEFAULT (for receiving the first part of data)
																		  *			\arg #PH_EXCHANGE_RXCHAINING (for receiving the final part of data)
																		  *		  \n
																		  *		  For enabling or disabling of key diversification. Should be combined with
																		  *		  the above options
																		  *			\arg #PHHAL_HW_SAMAV3_CMD_PKI_DIVERSIFICATION_OFF
																		  *			\arg # PHHAL_HW_SAMAV3_CMD_PKI_DIVERSIFICATION_ON
																		  */
    uint8_t bNoOfKeyEntries,										/**< [In] Number of key entries to include in the cryptogram. \n
																		  *			\c 0x00: RFU \n
																		  *			\c 0x01: 1 Key Entry \n
																		  *			\c 0x02: 2 Key Entry \n
																		  *			\c 0x03: 3 Key Entry \n
																		  */
    uint8_t bHashingAlg,											/**< [In] Hashing algorithm selection (for padding MGFs and digital signature).
																		  *			\arg #PHHAL_HW_SAMAV3_CMD_PKI_HASH_ALGORITHM_SHA_1
																		  *			\arg #PHHAL_HW_SAMAV3_CMD_PKI_HASH_ALGORITHM_SHA_224
																		  *			\arg #PHHAL_HW_SAMAV3_CMD_PKI_HASH_ALGORITHM_SHA_256
																		  *			\arg #PHHAL_HW_SAMAV3_CMD_PKI_HASH_ALGORITHM_RFU
																		  */
    uint8_t bPKI_KeyNo_Enc,											/**< [In] Reference number of the RSA key entry to be used for encryption (00h to 02h). */
    uint8_t bPKI_KeyNo_Sign,										/**< [In] Reference number of the RSA key entry to be used for signature verification (00h to 01h). */
    uint8_t bPKI_KeyNo_Dec,											/**< [In] Reference number of the RSA key entry to be used for decryption (00h to 01h). */
    uint8_t bPKI_KeyNo_Verif,										/**< [In] Reference number of the RSA key entry to be used for signature verification (00h to 02h). */
    uint16_t wPerso_Ctr,											/**< [In] Targeted offline change counter data. */
    uint8_t *pKeyEntries,											/**< [In] Set of 01h - 03h reference number(s) of \n
																		  *			\c Perso key entry: 00h - 7Fh (NVRam key) or E0h - E3h (Ram key) \n
																		  *			\c key number     : 00h - 7Fh
																		  */
    uint8_t bKeyEntriesLen,											/**< [In] Length of key entries. */
    uint8_t *pDivInput,											/**< [In] Diversification input for key diversification. (1 to 31 byte(s) input). */
    uint8_t bDivInputLen,											/**< [In] Length of diversification input. */
    uint8_t **ppEncKeyFrame_Sign,									/**< [Out] The Encrypted Key frame and Signature as returned by Sam hardware. */
    uint16_t *pEncKeyFrame_Sign_Len								/**< [Out] The length of Encrypted Key frame and Signature returned by Sam hardware. */
);

/**
 * \brief Generate Hash dataframe from Data
 * \return Status code
 * \retval #PH_ERR_SUCCESS Operation successful, command completed.
 * \retval #PH_ERR_SUCCESS_CHAINING Operation successful, chaining ongoing.
 * \retval Other Depending on implementation and underlaying component.
 */
phStatus_t phhalHw_SamAV3_Cmd_PKI_GenerateHash(
    phhalHw_SamAV3_DataParams_t
    *pDataParams,						/**< [In] Pointer to this layer's parameter structure. */
    uint16_t wOption,												/**< [In] Option parameter: \n
																		  *         Local buffering is implemented by the flags
																		  *				\arg #PH_EXCHANGE_BUFFER_FIRST
																		  *				\arg #PH_EXCHANGE_BUFFER_CONT
																		  *				\arg #PH_EXCHANGE_BUFFER_LAST (the command is sent to the SAM)
																		  *				\arg #PH_EXCHANGE_TXCHAINING (The LFI is set to AFh if the flag)
																		  *         \n
																		  *         On the first frame of the command chain the flag #PHHAL_HW_SAMAV3_CMD_PKI_GENERATE_HASH_FIRST_FRAME \n
																		  *			has to be set to force the appending of the length of the overall message.
																		  */
    uint8_t bHashingAlg,											/**< [In] Hashing algorithm selection (for padding MGFs and digital signature).
																		  *			\arg #PHHAL_HW_SAMAV3_CMD_PKI_HASH_ALGORITHM_SHA_1
																		  *			\arg #PHHAL_HW_SAMAV3_CMD_PKI_HASH_ALGORITHM_SHA_224
																		  *			\arg #PHHAL_HW_SAMAV3_CMD_PKI_HASH_ALGORITHM_SHA_256
																		  *			\arg #PHHAL_HW_SAMAV3_CMD_PKI_HASH_ALGORITHM_RFU
																		  */
    uint32_t dwMLen,												/**< [In] Overall message length (4 byte). */
    uint8_t *pMessage,												/**< [In] Message chunk to be hashed. */
    uint16_t wMsgLen,												/**< [In] Length of message chunk. */
    uint8_t **ppHash,												/**< [Out] Buffer containing the hash after sending the last message chunk. */
    uint16_t *pHashLen												/**< [Out] Amount of valid data in hash buffer. */
);

/**
 * \brief Generate a signature with a given RSA key entry.
 * \return Status code
 * \retval #PH_ERR_SUCCESS Operation successful.
 * \retval Other Depending on implementation and underlaying component.
 */
phStatus_t phhalHw_SamAV3_Cmd_PKI_GenerateSignature(
    phhalHw_SamAV3_DataParams_t
    *pDataParams,						/**< [In] Pointer to this layer's parameter structure. */
    uint8_t bHashingAlg,											/**< [In] Hashing algorithm selection (for padding MGFs and digital signature).
																		  *			\arg #PHHAL_HW_SAMAV3_CMD_PKI_HASH_ALGORITHM_SHA_1
																		  *			\arg #PHHAL_HW_SAMAV3_CMD_PKI_HASH_ALGORITHM_SHA_224
																		  *			\arg #PHHAL_HW_SAMAV3_CMD_PKI_HASH_ALGORITHM_SHA_256
																		  *			\arg #PHHAL_HW_SAMAV3_CMD_PKI_HASH_ALGORITHM_RFU
																		  */
    uint8_t bPKI_KeyNo_Sign,										/**< [In] Number of the key entry to be used for signing (00h to 01h). */
    uint8_t *pHash,												/**< [In] Hash message to be signed. */
    uint8_t bHashLen												/**< [In] Hash message length. */
);

/**
 * \brief Get a previously generated signature. This command is only available for AV2 and AV3 version(s).
 * \return Status code
 * \retval #PH_ERR_SUCCESS Operation successful.
 * \retval Other Depending on implementation and underlaying component.
 */
phStatus_t phhalHw_SamAV3_Cmd_PKI_SendSignature(
    phhalHw_SamAV3_DataParams_t
    *pDataParams,						/**< [In] Pointer to this layer's parameter structure. */
    uint8_t **ppSignature,											/**< [Out] The signature received from Sam hardware. */
    uint16_t *pSignatureLen										/**< [Out] Length of signature received. */
);

/**
 * \brief Verify a hash / signature pair with a given RSA key.
 * \return Status code
 * \retval #PH_ERR_SUCCESS Operation successful.
 * \retval Other Depending on implementation and underlaying component.
 */
phStatus_t phhalHw_SamAV3_Cmd_PKI_VerifySignature(
    phhalHw_SamAV3_DataParams_t
    *pDataParams,						/**< [In] Pointer to this layer's parameter structure. */
    uint8_t bPKI_KeyNo_Verif,										/**< [In] Key reference number of the PKI Key Entry to be used for the cryptogram signature verification (00h to 02h) */
    uint8_t bHashingAlg,											/**< [In] Hashing algorithm selection (for padding MGFs and digital signature).
																		  *			\arg #PHHAL_HW_SAMAV3_CMD_PKI_HASH_ALGORITHM_SHA_1
																		  *			\arg #PHHAL_HW_SAMAV3_CMD_PKI_HASH_ALGORITHM_SHA_224
																		  *			\arg #PHHAL_HW_SAMAV3_CMD_PKI_HASH_ALGORITHM_SHA_256
																		  *			\arg #PHHAL_HW_SAMAV3_CMD_PKI_HASH_ALGORITHM_RFU
																		  */
    uint8_t *pHash,												/**< [In] Hash data. */
    uint8_t bHashLen,												/**< [In] Hash data length. */
    uint8_t *pSignature,											/**< [In] RSA digital signature. */
    uint16_t wSignatureLen											/**< [In] RSA digital signature length. */
);

/**
 * \brief Performs the offline encryption of plain RSA data. This is only supported by
 * Sam AV3 version.
 * \return Status code
 * \retval #PH_ERR_SUCCESS Operation successful.
 * \retval Other Depending on implementation and underlaying component.
 */
phStatus_t phhalHw_SamAV3_Cmd_PKI_EncipherData(
    phhalHw_SamAV3_DataParams_t
    *pDataParams,						/**< [In] Pointer to this layer's parameter structure. */
    uint8_t bHashingAlg,											/**< [In] Hashing algorithm selection (for padding MGFs and digital signature).
																		  *			\arg #PHHAL_HW_SAMAV3_CMD_PKI_HASH_ALGORITHM_SHA_1
																		  *			\arg #PHHAL_HW_SAMAV3_CMD_PKI_HASH_ALGORITHM_SHA_224
																		  *			\arg #PHHAL_HW_SAMAV3_CMD_PKI_HASH_ALGORITHM_SHA_256
																		  *			\arg #PHHAL_HW_SAMAV3_CMD_PKI_HASH_ALGORITHM_RFU
																		  */
    uint8_t bPKI_KeyNo_Enc,											/**< [In] Reference number of the RSA key entry to be used for encryption (00h to 02h). */
    uint8_t *pPlainData,											/**< [In] RSA Plain Data to be encrypted. */
    uint16_t wPlainDataLen,											/**< [In] Length of plain data. */
    uint8_t **ppEncData,											/**< [Out] The RSA encrypted data returned by Sam hardware. */
    uint16_t *pEncDataLen											/**< [Out] Length of encrypted data. */
);

/**
 * \name Option macros for Sam AV3 Public Key Infrastructure DecipherData command.
 */
/* @{ */
#define PHHAL_HW_SAMAV3_CMD_PKI_DECIPHER_DATA_FIRST_FRAME		0x80	/**< Option mask for a framing the first frame of Decipher Data command. */
/* @} */

/**
 * \brief Performs the offline decryption of encrypted RSA data. This is only supported by Sam AV3 version.
 * \return Status code
 * \retval #PH_ERR_SUCCESS Operation successful.
 * \retval #PH_ERR_SUCCESS_CHAINING Operation successful, chaining ongoing.
 * \retval Other Depending on implementation and underlaying component.
 */
phStatus_t phhalHw_SamAV3_Cmd_PKI_DecipherData(
    phhalHw_SamAV3_DataParams_t
    *pDataParams,						/**< [In] Pointer to this layer's parameter structure. */
    uint16_t wOption,												/**< [In] Option parameter: \n
																		  *         Local buffering is implemented by the flags
																		  *				\arg #PH_EXCHANGE_DEFAULT
																		  *				\arg #PH_EXCHANGE_TXCHAINING (The LFI is set to AFh if the flag)
																		  *			\n
																		  *			Usage:\n
																		  *				For chainned data \n
																		  *				For First Frame     : Use flags #PHHAL_HW_SAMAV3_CMD_PKI_DECIPHER_DATA_FIRST_FRAME |
																		  *				#PH_EXCHANGE_TXCHAINING \n
																		  *				For Next N Frame(s) : Use flags #PH_EXCHANGE_TXCHAINING \n
																		  *				For Last Frame      : Use flags #PH_EXCHANGE_DEFAULT \n
																		  *			\n
																		  *			For non chainned data i.e. only single frame use #PHHAL_HW_SAMAV3_CMD_PKI_DECIPHER_DATA_FIRST_FRAME |
																		  *				#PH_EXCHANGE_DEFAULT
																		  */
    uint8_t bHashingAlg,											/**< [In] Hashing algorithm selection (for padding MGFs and digital signature).
																		  *			\arg #PHHAL_HW_SAMAV3_CMD_PKI_HASH_ALGORITHM_SHA_1
																		  *			\arg #PHHAL_HW_SAMAV3_CMD_PKI_HASH_ALGORITHM_SHA_224
																		  *			\arg #PHHAL_HW_SAMAV3_CMD_PKI_HASH_ALGORITHM_SHA_256
																		  *			\arg #PHHAL_HW_SAMAV3_CMD_PKI_HASH_ALGORITHM_RFU
																		  */
    uint8_t bPKI_KeyNo_Dec,											/**< [In] Reference number of the RSA key entry to be used for decryption (00h to 01h). */
    uint8_t *pEncData,												/**< [In] The RSA encrypted data to be decrypted. */
    uint16_t wEncDataLen,											/**< [In] Length of encrypted data. */
    uint8_t **ppPlainData,											/**< [In] RSA Plain Data returned by Sam hardware. */
    uint16_t *pPlainDataLen										/**< [In] Length of plain data. */
);
/** @}
 * end of defgroup phhalHw_SamAV3_Cmd_PKI_RSA
 */

/** \defgroup phhalHw_SamAV3_Cmd_PKI_ECC ECC
 * \see
 * \brief SAM commands used for asymmetric ECC key management, signature handling and verification.
 * @{
 */

/**
 * \name Sam AV3 command code for Public Key Infrastructure features.
 */
/* @{ */
#define PHHAL_HW_SAMAV3_CMD_PKI_IMPORT_ECC_KEY_INS				0x21	/**< Sam AV3 Instruction code for Cmd.PKI_ImportEccKey command. */
#define PHHAL_HW_SAMAV3_CMD_PKI_IMPORT_ECC_CURVE_INS			0x22	/**< Sam AV3 Instruction code for Cmd.PKI_ImportEccCurve command. */
#define PHHAL_HW_SAMAV3_CMD_PKI_EXPORT_ECC_PUBLIC_KEY_INS		0x23	/**< Sam AV3 Instruction code for Cmd.PKI_ExportEccPublicKey command. */
#define PHHAL_HW_SAMAV3_CMD_PKI_VERIFY_ECC_SIGNATURE_INS		0x20	/**< Sam AV3 Instruction code for Cmd.PKI_VerifyEccSignature command. */
/* @} */

/**
 * \name Option macros for Sam AV3 Public Key Infrastructure ImportEccCurve command.
 */
/* @{ */
#define PHHAL_HW_SAMAV3_CMD_PKI_UPDATE_CURVE_SETTINGS_VALUE		0x00	/**< Option mask for updating curve settings and curve values. */
#define PHHAL_HW_SAMAV3_CMD_PKI_UPDATE_CURVE_SETTINGS_ONLY		0x01	/**< Option mask for updating curve settings only. */
/* @} */

#define PHHAL_HW_SAMAV3_CMD_PKI_IMPORT_ECC_KEY_CMD_SIZE			15U		/**< Macro to represent the PKI_ImportEccKey command size. */
#define PHHAL_HW_SAMAV3_CMD_PKI_IMPORT_ECC_KEY_LC_MIN			8U		/**< Minimun Length of LC data for PKI_ImportEccKey command. */

#define PHHAL_HW_SAMAV3_CMD_PKI_IMPORT_ECC_CURVE_CMD_SIZE		10U		/**< Macro to represent the PKI_ImportEccCurve command size. */
#define PHHAL_HW_SAMAV3_CMD_PKI_IMPORT_ECC_CURVE_LC_MIN			3U		/**< Minimun Length of LC data for PKI_ImportEccCurve command. */

#define PHHAL_HW_SAMAV3_CMD_PKI_VERIFY_ECC_SIGNATURE_CMD_SIZE	8U		/**< Macro to represent the PKI_VerifyEccSignature command size. */
#define PHHAL_HW_SAMAV3_CMD_PKI_VERIFY_ECC_SIGNATURE_LC_MIN		3U		/**< Minimun Length of LC data for PKI_VerifyEccSignature command. */

/**
 * \brief Imports the ECC public key to Key Storage. This is only supported by Sam AV3 version.
 * \return Status code
 * \retval #PH_ERR_SUCCESS Operation successful.
 * \retval Other Depending on implementation and underlaying component.
 */
phStatus_t phhalHw_SamAV3_Cmd_PKI_ImportEccKey(
    phhalHw_SamAV3_DataParams_t
    *pDataParams,						/**< [In] Pointer to this layer's parameter structure. */
    uint8_t bOption,												/**< [In] Option for P1 information byte.
																		  *			\arg #PHHAL_HW_SAMAV3_CMD_PKI_UPDATE_KEY_SETTINGS_VALUE
																		  *			\arg #PHHAL_HW_SAMAV3_CMD_PKI_UPDATE_KEY_SETTINGS_ONLY
																		  */
    uint8_t bECC_KeyNo,												/**< [In] The key reference number of the ECC key entry to be update (00h to 07h). */
    uint16_t wECC_Set,												/**< [In] Configuration settings of the key entry. */
    uint8_t bECC_KeyNoCEK,											/**< [In] Key reference number of change entry key.
																		  *			\c 0xFE       : No Restrictions \n
																		  *			\c 0xFF       : Entry Locked \n
																		  *			\c 0x00 - 0x7F: Restricted to specific permanent KST Key Entry \n
																		  */
    uint8_t bECC_KeyVCEK,											/**< [In] Key version of change entry key. */
    uint8_t bECC_RefNoKUC,											/**< [In] Reference number of key usage counter. */
    uint8_t bECC_KeyNoAEK,											/**< [In] Key version of access entry key.  \n
																		  *			\c 0xFE       : No Access Restrictions \n
																		  *			\c 0xFF       : Entry Disabled \n
																		  *			\c 0x00 - 0x7F: Restricted to specific permanent KST Key Entry \n
																		  */
    uint8_t bECC_KeyVAEK,											/**< [In] Version of the created acces key entry. */
    uint16_t wECC_Len,												/**< [In] ECC bit field size in bytes. */
    uint8_t *pECC_xy,												/**< [In] Public key point coordinate. Ranges from 33 - 65 bytes. */
    uint8_t bECC_xyLen												/**< [In] Length of Plublic key point coordinates. */
);

/**
 * \brief Imports the full ECC Curve description to the ECC Curve Storage Table. This is
 * only supported by Sam AV3 version.
 * \return Status code
 * \retval #PH_ERR_SUCCESS Operation successful.
 * \retval Other Depending on implementation and underlaying component.
 */
phStatus_t phhalHw_SamAV3_Cmd_PKI_ImportEccCurve(
    phhalHw_SamAV3_DataParams_t
    *pDataParams,						/**< [In] Pointer to this layer's parameter structure. */
    uint8_t bOption,												/**< [In] Option for P1 information byte.
																		  *			\arg #PHHAL_HW_SAMAV3_CMD_PKI_UPDATE_CURVE_SETTINGS_VALUE
																		  *			\arg #PHHAL_HW_SAMAV3_CMD_PKI_UPDATE_CURVE_SETTINGS_ONLY
																		  */
    uint8_t bECC_CurveNo,											/**< [In] Curve reference number of the ECC curve entry to update (00h to 03h). */
    uint8_t bECC_KeyNoCCK,											/**< [In] Key reference number to change the curve entry.
																		  *			\c 0xFE       : No Restrictions \n
																		  *			\c 0xFF       : Entry Locked \n
																		  *			\c 0x00 - 0x7F: Restricted to specific permanent KST Key Entry \n
																		  */
    uint8_t bECC_KeyVCCK,											/**< [In] Key version to change curve entry. */
    uint8_t bECC_N,													/**< [In] Size of the field in bytes. Ranges from 16 to 32 bytes. */
    uint8_t bECC_M,													/**< [In] Size of the order in bytes. Ranges from 16 to 32 bytes. */
    uint8_t *pECC_Prime,											/**< [In] Prime, field definition: ECC_N bytes. */
    uint8_t *pECC_ParamA,											/**< [In] Curve parameter (a): ECC_N bytes. */
    uint8_t *pECC_ParamB,											/**< [In] Curve parameter (b): ECC_N bytes. */
    uint8_t *pECC_Px,												/**< [In] x-coordinate of basepoint: ECC_N bytes. */
    uint8_t *pECC_Py,												/**< [In] y-coordinate of basepoint: ECC_N bytes. */
    uint8_t *pECC_Order											/**< [In] Order of basepoint: ECC_M bytes. */
);

/**
 * \brief Exports the ECC public key from Key Storage. This is only supported by Sam AV3 version.
 * \return Status code
 * \retval #PH_ERR_SUCCESS Operation successful.
 * \retval Other Depending on implementation and underlaying component.
 */
phStatus_t phhalHw_SamAV3_Cmd_PKI_ExportEccPublicKey(
    phhalHw_SamAV3_DataParams_t
    *pDataParams,						/**< [In] Pointer to this layer's parameter structure. */
    uint8_t bECC_KeyNo,												/**< [In] The key reference number of the ECC key entry to be update (00h to 07h). */
    uint16_t *pECC_Set,											/**< [Out] Configuration settings of the key entry. */
    uint8_t *pECC_KeyNoCEK,										/**< [Out] Key reference number of change entry key.
																		  *			\c 0xFE       : No Restrictions \n
																		  *			\c 0xFF       : Entry Locked \n
																		  *			\c 0x00 - 0x7F: Restricted to specific permanent KST Key Entry \n
																		  */
    uint8_t *pECC_KeyVCEK,											/**< [Out] Key version of change entry key. */
    uint8_t *pECC_RefNoKUC,										/**< [Out] Reference number of key usage counter. */
    uint8_t *pECC_KeyNoAEK,										/**< [Out] Key version of access entry key.  \n
																		  *			\c 0xFE       : No Access Restrictions \n
																		  *			\c 0xFF       : Entry Disabled \n
																		  *			\c 0x00 - 0x7F: Restricted to specific permanent KST Key Entry \n
																		  */
    uint8_t *pECC_KeyVAEK,											/**< [Out] Version of the created acces key entry. */
    uint16_t *pECC_Len,											/**< [Out] ECC bit field size in bytes. */
    uint8_t **ppECC_xy,											/**< [Out] Public key point coordinate. Ranges from 33 - 65 bytes. */
    uint8_t *pECC_xyLen											/**< [Out] Length of Plublic key point coordinates. */
);

/**
 * \brief The command verifies the correctness of an ECC signature (i.e.: NXPOriginalitySignature) obtained from the
 * product to verify. The signature is computed according to Elliptic Curve DSA (ECDSA) algorithm. This is only
 * supported by Sam AV3 version.
 * \return Status code
 * \retval #PH_ERR_SUCCESS Operation successful.
 * \retval Other Depending on implementation and underlaying component.
 */
phStatus_t phhalHw_SamAV3_Cmd_PKI_VerifyEccSignature(
    phhalHw_SamAV3_DataParams_t
    *pDataParams,						/**< [In] Pointer to this layer's parameter structure. */
    uint8_t bECC_KeyNo,												/**< [In] The key reference number of the ECC key entry to be used for signature verification (00h to 07h). */
    uint8_t bECC_CurveNo,											/**< [In] The curve reference number of the ECC curve entry to be used for signature verification (00h to 03h). */
    uint8_t bLen,													/**< [In] Length in bytes of the message to verify. */
    uint8_t *pMessage,												/**< [In] Signed input data. */
    uint8_t *pSignature,											/**< [In] The ECC digital signature where N is 2  ECC_Len of ECC_KeyNo key entry. */
    uint16_t wSignatureLen											/**< [In] Length of ECC digital signature. */
);
/** @}
 * end of defgroup phhalHw_SamAV3_Cmd_PKI_ECC
 */

/** \defgroup phhalHw_SamAV3_Cmd_PKI_EMV EMV
 * \see
 * \brief SAM commands used for asymmetric ECC key management, signature handling and verification.
 * @{
 */

/**
 * \name Sam AV3 command code for Public Key Infrastructure features.
 */
/* @{ */
#define PHHAL_HW_SAMAV3_CMD_PKI_IMPORT_CAPK_INS					0x24	/**< Sam AV3 Instruction code for Cmd.PKI_ImportCaPk command. */
#define PHHAL_HW_SAMAV3_CMD_PKI_REMOVE_CAPK_INS					0x2F	/**< Sam AV3 Instruction code for Cmd.PKI_RemoveCaPk command. */
#define PHHAL_HW_SAMAV3_CMD_PKI_EXPORT_CAPK_INS					0x3D	/**< Sam AV3 Instruction code for Cmd.PKI_ExportCaPk command. */
#define PHHAL_HW_SAMAV3_CMD_PKI_LOAD_ISSUER_PK_INS				0x27	/**< Sam AV3 Instruction code for Cmd.PKI_LoadIssuerPk command. */
#define PHHAL_HW_SAMAV3_CMD_PKI_LOAD_ICC_PK_INS					0x28	/**< Sam AV3 Instruction code for Cmd.PKI_LoadIccPk command. */
/* @} */

/**
 * \name Option macros for Sam AV3 Public Key Infrastructure ImportCaPK command.
 */
/* @{ */
#define PHHAL_HW_SAMAV3_CMD_PKI_IMPORT_KEY_SETTINGS_VALUE		0x00	/**< Option mask for updating key settings and key values. */
#define PHHAL_HW_SAMAV3_CMD_PKI_IMPORT_KEY_SETTINGS_ONLY		0x80	/**< Option mask for updating key settings only. */
/* @} */

/**
 * \name Option macros for Sam AV3 Public Key Infrastructure ImportCaPkOffline, RemoveCaPKOffline.
 */
/* @{ */
#define PHHAL_HW_SAMAV3_CMD_PKI_OFFLINE_ACK_RECEPTION_OFF		0x00	/**< Option mask for not exchanging the Le and no reception of offline acknowledgement. */
#define PHHAL_HW_SAMAV3_CMD_PKI_OFFLINE_ACK_RECEPTION_ON		0x01	/**< Option mask for exchanging the Le and no reception of offline acknowledgement. */
/* @} */

/**
 * \brief Imports a CaPk key to Sam hardware. This command is used to import a Certificate Authority Public Key in the SAM for a given
 * RID (Registered Application Provider Identifier)
 *
 * \return Status code
 * \retval #PH_ERR_SUCCESS Operation successful.
 * \retval Other Depending on implementation and underlaying component.
 */
phStatus_t phhalHw_SamAV3_Cmd_PKI_ImportCaPk(
    phhalHw_SamAV3_DataParams_t
    *pDataParams,						/**< [In] Pointer to this layer's parameter structure. */
    uint8_t bOption,												/**< [In] Option for P2 information byte.
																		 *			\arg #PHHAL_HW_SAMAV3_CMD_PKI_IMPORT_KEY_SETTINGS_VALUE
																		 *			\arg #PHHAL_HW_SAMAV3_CMD_PKI_IMPORT_KEY_SETTINGS_ONLY
																		 */
    uint8_t *pCaPkData,											/**< [In] Certification Authority Public Key Related Data. This data
																		 *		  buffer should have the complete data based on the selected
																		 *		  option.
																		 */
    uint8_t bCaPkDataLen											/**< [In] Certification Authority Public Key Related Data length. */
);

/**
 * \brief Imports a offline CaPk key to Sam hardware. This command is used to import a Certificate Authority Public Key in the SAM
 *
 * \return Status code
 * \retval #PH_ERR_SUCCESS Operation successful.
 * \retval Other Depending on implementation and underlaying component.
 */
phStatus_t phhalHw_SamAV3_Cmd_PKI_ImportCaPkOffline(
    phhalHw_SamAV3_DataParams_t
    *pDataParams,						/**< [In] Pointer to this layer's parameter structure. */
    uint8_t bReceiveOfflineAck,										/**< [In] Flag to exchange LE and receive the offline acknowledgement. \n
																		 *			\arg #PHHAL_HW_SAMAV3_CMD_PKI_OFFLINE_ACK_RECEPTION_OFF
																		 *			\arg #PHHAL_HW_SAMAV3_CMD_PKI_OFFLINE_ACK_RECEPTION_ON
																		 */
    uint8_t bOption,												/**< [In] Option for P2 information byte.
																		 *			\arg #PHHAL_HW_SAMAV3_CMD_PKI_IMPORT_KEY_SETTINGS_VALUE
																		 *			\arg #PHHAL_HW_SAMAV3_CMD_PKI_IMPORT_KEY_SETTINGS_ONLY
																		 */
    uint8_t *pOfflineCryptogram,									/**< [In] Offline change cryptogram. This data buffer should have the
																		 *		  complete data based on the selected option.
																		 */
    uint8_t bOfflineCryptogramLen,									/**< [In] Length of bytes available in OfflineCryptogram buffer. */
    uint8_t **ppOfflineAck,										/**< [Out] Offline remove acknowledge as MACt(Kcm, 0x90 || 0x00 || INS || Change_Ctr || RID || PkID ||
																		 *		  SAMUID).
																		 */
    uint16_t *pOfflineAckLen										/**< [Out] Length of bytes available in OfflineAck buffer. */
);

/**
 * \brief Removes a CaPk key to Sam hardware. This command is used to permanently remove a Certificate Authority Public Key from the
 * EMV key storage table (EMV_KST). The command shall clear and reset the permanent storage containg the CAPk related data.
 *
 * \return Status code
 * \retval #PH_ERR_SUCCESS Operation successful.
 * \retval Other Depending on implementation and underlaying component.
 */
phStatus_t phhalHw_SamAV3_Cmd_PKI_RemoveCaPk(
    phhalHw_SamAV3_DataParams_t
    *pDataParams,						/**< [In] Pointer to this layer's parameter structure. */
    uint8_t *pRID,													/**< [In] Registered Application provider Identifier. This buffer should contain 5 bytes of RID. */
    uint8_t bPkID													/**< [In] Certification Authority Public Key Index. */
);

/**
 * \brief Removes a CaPk key to Sam hardware. This command is used to permanently remove a Certificate Authority Public Key from the
 * EMV key storage table (EMV_KST). The command shall clear and reset the permanent storage containg the CAPk related data.
 *
 * \return Status code
 * \retval #PH_ERR_SUCCESS Operation successful.
 * \retval Other Depending on implementation and underlaying component.
 */
phStatus_t phhalHw_SamAV3_Cmd_PKI_RemoveCaPkOffline(
    phhalHw_SamAV3_DataParams_t
    *pDataParams,						/**< [In] Pointer to this layer's parameter structure. */
    uint8_t bReceiveOfflineAck,										/**< [In] Flag to exchange LE and receive the offline acknowledgement. \n
																		 *			\arg #PHHAL_HW_SAMAV3_CMD_PKI_OFFLINE_ACK_RECEPTION_OFF
																		 *			\arg #PHHAL_HW_SAMAV3_CMD_PKI_OFFLINE_ACK_RECEPTION_ON
																		 */
    uint8_t *pOfflineCryptogram,									/**< [In] Offline change cryptogram. This data buffer should have the
																		 *		  complete data based on the selected option.
																		 */
    uint8_t bOfflineCryptogramLen,									/**< [In] Length of bytes available in OfflineCryptogram buffer. */
    uint8_t **ppOfflineAck,										/**< [Out] Offline remove acknowledge as MACt(Kcm, 0x90 || 0x00 || INS || Change_Ctr || RID || PkID ||
																		 *		  SAMUID).
																		 */
    uint16_t *pOfflineAckLen										/**< [Out] Length of bytes available in OfflineAck buffer. */
);

/**
 * \name Option macros for Sam AV3 Public Key Infrastructure ExportCaPK command.
 */
/* @{ */
#define PHHAL_HW_SAMAV3_CMD_PKI_EXPORT_KEY_SETTINGS_VALUE		0x0000	/**< Option mask for exporting key settings and key values. */
#define PHHAL_HW_SAMAV3_CMD_PKI_EXPORT_KEY_SETTINGS_ONLY		0x0080	/**< Option mask for exporting key settings only. */
/* @} */

/**
 * \brief Exports a CaPk key to Sam hardware. This command is used export a Certificate Authority Public Key from the EMV CA public keys
 * key set entry (KST). The CA Pk entry is selected with the RID and PkID.
 *
 * \return Status code
 * \retval #PH_ERR_SUCCESS Operation successful.
 *		   #PH_ERR_SUCCESS_CHAINING for successfull chaining operation.
 * \retval Other Depending on implementation and underlaying component.
 */
phStatus_t phhalHw_SamAV3_Cmd_PKI_ExportCaPk(
    phhalHw_SamAV3_DataParams_t
    *pDataParams,						/**< [In] Pointer to this layer's parameter structure. */
    uint16_t wOption,												/**< [In] Option for P1 information byte.
																		 *			\arg #PHHAL_HW_SAMAV3_CMD_PKI_EXPORT_KEY_SETTINGS_VALUE
																		 *			\arg #PHHAL_HW_SAMAV3_CMD_PKI_EXPORT_KEY_SETTINGS_ONLY
																		 *		  \n
																		 *		  Bufferring options to command exchange and CaPk keyentry reception.
																		 *			\arg #PH_EXCHANGE_DEFAULT    : To frame and exchange the Export CaPk command information.
																		 *										   Here the command header, RID, PkID and LE will be exchanged.
																		 *			\arg #PH_EXCHANGE_RXCHAINING : To exchange command header only and for reception of parts of
																		 *										   keyentry.
																		 */
    uint8_t *pRID,													/**< [In] Registered Application provider Identifier. This buffer should contain 5 bytes of RID. */
    uint8_t bPkID,													/**< [In] Certification Authority Public Key Index. */
    uint8_t **ppKeyEntry,											/**< [Out] CAPk key entry information returned by Sam hardware. */
    uint16_t *pKeyEntryLen											/**< [Out] Length of bytes available in KeyEntry buffer. */
);

/**
 * \brief Loads a Issuer Public Key. This command is used to load an Issuer Public Key. The SAM only accepts Issuer Public Key Certificate
 * signed by the selected Certification Authority identified by RID and PkID. The required Certification Authority Public Key must be
 * stored in the CA Key Storage otherwise Cmd.PKI_LoadIssuerPk will fail.
 *
 * \return Status code
 * \retval #PH_ERR_SUCCESS Operation successful.
 *		   #PH_ERR_SUCCESS_CHAINING for successfull chaining operation.
 * \retval Other Depending on implementation and underlaying component.
 */
phStatus_t phhalHw_SamAV3_Cmd_PKI_LoadIssuerPk(
    phhalHw_SamAV3_DataParams_t
    *pDataParams,						/**< [In] Pointer to this layer's parameter structure. */
    uint8_t bLFI,													/**< [In] Option for P1 information byte.
																		 *			\arg #PHHAL_HW_SAMAV3_ISO7816_LAST_FRAME
																		 *			\arg #PHHAL_HW_SAMAV3_ISO7816_CHAINED_FRAME
																		 */
    uint16_t wOption,												/**< [In] Bufferring options for exchanging the payload information.
																		 *			\arg #PH_EXCHANGE_DEFAULT      : To frame and exchange the complete payload information. If this
																		 *											 flag is passed, this is one complete and single frame. There will
																		 *											 not be more data to be sent by the HOST to Sam hardware, meaning
																		 *											 LFI parameter equals #PHHAL_HW_SAMAV3_ISO7816_LAST_FRAME
																		 *			\arg #PH_EXCHANGE_BUFFER_FIRST : To buffer initial set of payload information.
																		 *			\arg #PH_EXCHANGE_BUFFER_CONT  : To buffer the intermediate set of payload information.
																		 *			\arg #PH_EXCHANGE_BUFFER_LAST  : To buffer the final set of payload information and exchange to
																		 *											 Sam hardware.
																		 *		  \n
																		 *		  \c Note: For option #PH_EXCHANGE_BUFFER_FIRST, #PH_EXCHANGE_BUFFER_CONT and #PH_EXCHANGE_BUFFER_LAST \n
																		 *		           LFI parameter depends as per the maximum frame size of Sam hardware. \n
																		 *		           \n
																		 *		           The payload information shall have RID, PkID, CertLen, PkCert, PkRemLen, PkRem and PkExp
																		 */
    uint8_t *pData,												/**< [In] The payload to be exchanged or bufferred. */
    uint8_t bDataLen,												/**< [In] Length of bytes available in Data buffer. */
    uint8_t *pIssureID,											/**< [Out] Issuer Identifier. This buffer will have 4 bytes of ID. */
    uint8_t *pExpDate,												/**< [Out] Certificate Expiration Date (MMYY). The buffer will have 2 bytes of data. */
    uint8_t *pSerialNo												/**< [Out] Certificate Serial Number. The buffer will have 3 bytes of serial number. */
);

/**
 * \brief Loads a ICC Public Key. This command is used to load an ICC Public Key or an ICC PIN Encipherment Public Key. The SAM only
 * accepts Public Key Certificate signed by the Issuer identified by the Issuer Public Key previously loaded with Cmd.PKI_LoadIssuerPk
 * Cmd.PKI_LoadIccPk fails if the Issuer Public Key is not previously loaded, or has not signed the ICC (PIN Encipherment) Public Key
 * Certificate.
 *
 * \return Status code
 * \retval #PH_ERR_SUCCESS Operation successful.
 *		   #PH_ERR_SUCCESS_CHAINING for successfull chaining operation.
 * \retval Other Depending on implementation and underlaying component.
 */
phStatus_t phhalHw_SamAV3_Cmd_PKI_LoadIccPk(
    phhalHw_SamAV3_DataParams_t
    *pDataParams,						/**< [In] Pointer to this layer's parameter structure. */
    uint8_t bLFI,													/**< [In] Option for P1 information byte.
																		 *			\arg #PHHAL_HW_SAMAV3_ISO7816_LAST_FRAME
																		 *			\arg #PHHAL_HW_SAMAV3_ISO7816_CHAINED_FRAME
																		 */
    uint16_t wOption,												/**< [In] Bufferring options for exchanging the payload information.
																		 *			\arg #PH_EXCHANGE_DEFAULT      : To frame and exchange the complete payload information. If this
																		 *											 flag is passed, this is one complete and single frame. There will
																		 *											 not be more data to be sent by the HOST to Sam hardware, meaning
																		 *											 LFI parameter equals #PHHAL_HW_SAMAV3_ISO7816_LAST_FRAME
																		 *			\arg #PH_EXCHANGE_BUFFER_FIRST : To buffer initial set of payload information.
																		 *			\arg #PH_EXCHANGE_BUFFER_CONT  : To buffer the intermediate set of payload information.
																		 *			\arg #PH_EXCHANGE_BUFFER_LAST  : To buffer the final set of payload information and exchange to
																		 *											 Sam hardware.
																		 *		  \n
																		 *		  \c Note: For option #PH_EXCHANGE_BUFFER_FIRST, #PH_EXCHANGE_BUFFER_CONT and #PH_EXCHANGE_BUFFER_LAST \n
																		 *		           LFI parameter depends as per the maximum frame size of Sam hardware. \n
																		 *		           \n
																		 *		           The payload information shall have CertLen, PkCert, PkRemLen, PkRem, PkExp and SData.
																		 */
    uint8_t *pData,												/**< [In] The payload to be exchanged or bufferred. */
    uint8_t bDataLen,												/**< [In] Length of bytes available in Data buffer. */
    uint8_t *pPAN,													/**< [Out] Application PAN. This buffer will have 10 bytes of information. */
    uint8_t *pExpDate,												/**< [Out] Certificate Expiration Date (MMYY). The buffer will have 2 bytes of data. */
    uint8_t *pSerialNo,											/**< [Out] Certificate Serial Number. The buffer will have 3 bytes of serial number. */
    uint8_t *pAlgoPk												/**< [Out] ICC Public Key Algorithm Indicator. The buffer will have 1 bytes of algorithm information. */
);

/** @}
 * end of defgroup phhalHw_SamAV3_Cmd_PKI_EMV
 */

/** @}
 * end of defgroup phhalHw_SamAV3_Cmd_PKI
 */

/*************************************************************************************************************************/
/*********************************************** Virtual Card and Proximity **********************************************/
/*************************************************************************************************************************/

/** \defgroup phhalHw_SamAV3_Cmd_VCA Virtual Card
 * \brief SAM commands used for Virtaul Card communication in X and S Mode.
 * @{
 */

/** \name Option macros for Sam AV3 VCA / PC diversification inputs for Virtual Card Select MAC and ENC keys. */
/* @{ */
#define PHHAL_HW_SAMAV3_CMD_SELECT_DIV_DEFAULT					0x00	/**< Default option mask to disable the diversification of VcSelect MAC and ENC key. */
#define PHHAL_HW_SAMAV3_CMD_SELECT_MAC_KEY_DIV_OFF				0x00	/**< Option mask to disable the diversification of VC SelectMAC key. */
#define PHHAL_HW_SAMAV3_CMD_SELECT_MAC_KEY_DIV_INPUT			0x02	/**< Option mask to perform diversification of VC SelectMAC key using the diversification input provided. */
#define PHHAL_HW_SAMAV3_CMD_SELECT_MAC_KEY_DIV_VCUID			0x04	/**< Option mask to perform diversification of VC SelectMAC key using Virtual Card Identifier. */
#define PHHAL_HW_SAMAV3_CMD_SELECT_MAC_KEY_DIV_INPUT_VCUID		0x06	/**< Option mask to perform diversification of VC SelectMAC key using Virtual Card Identifier and Diversification input provided. */
#define PHHAL_HW_SAMAV3_CMD_SELECT_ENC_KEY_DIV_OFF				0x00	/**< Option mask to disable the diversification of VC SelectENC key. */
#define PHHAL_HW_SAMAV3_CMD_SELECT_ENC_KEY_DIV_INPUT			0x01	/**< Option mask to perform diversification of VC SelectENC key using the diversification input provided. */
/* @} */

/** \name Option macros for Sam AV3 VCA / PC Proximity check command. */
/* @{ */
#define PHHAL_HW_SAMAV3_CMD_PROXIMITY_CHECK_DIV_OFF				0x00	/**< Option mask to disable diversification of ProximityCheck key. */
#define PHHAL_HW_SAMAV3_CMD_PROXIMITY_CHECK_DIV_ON				0x01	/**< Option mask to perform diversification of ProximityCheck key using the diversification input provided. */
#define PHHAL_HW_SAMAV3_CMD_PROXIMITY_CHECK_PART1_EXCHANGE		0x01	/**< Option mask to perform part 1 exchange of data. */
#define PHHAL_HW_SAMAV3_CMD_PROXIMITY_CHECK_PART2_EXCHANGE		0x02	/**< Option mask to perform part 2 exchange of data. */
/* @} */

/** \defgroup phhalHw_SamAV3_Cmd_VCA_S S Mode
 * \brief SAM commands used for Virtaul Card communication in S-Mode.
 * @{
 */

/** \name Sam AV3 command code for Sam Virtual Card feature in S mode. */
/* @{ */
#define PHHAL_HW_SAMAV3_CMD_SAM_SELECT_VC_INS					0x44	/**< Sam AV3 Insturction code for SAM_SelectVC command. */
#define PHHAL_HW_SAMAV3_CMD_SAM_PROXIMITY_CHECK_INS				0xFA	/**< Sam AV3 Insturction code for SAM_ProximityCheck command. */
/* @} */

/**
 * \brief Performs Virtual card selection based on the response of ISOSelect command.
 *
 * \return Status code
 * \retval #PH_ERR_SUCCESS Operation successful.
 * \retval Other Depending on implementation and underlaying component.
 */
phStatus_t phhalHw_SamAV3_Cmd_SAM_SelectVC(
    phhalHw_SamAV3_DataParams_t
    *pDataParams,						/**< [In] Pointer to this layer's parameter structure. */
    uint8_t bOption,												/**< [In] Option to update the P1 information. The options can be combined by bitwise oring.
																		 *			Option for diversification of VCSelectENCKey.
 																		 *				\arg #PHHAL_HW_SAMAV3_CMD_SELECT_ENC_KEY_DIV_OFF
  																		 *  			\arg #PHHAL_HW_SAMAV3_CMD_SELECT_ENC_KEY_DIV_INPUT
  																		 *			\n
  																		 *			Option for diversification of VCSelectMACKey.
  																		 *  			\arg #PHHAL_HW_SAMAV3_CMD_SELECT_MAC_KEY_DIV_OFF
  																		 *  			\arg #PHHAL_HW_SAMAV3_CMD_SELECT_MAC_KEY_DIV_INPUT
  																		 *  			\arg #PHHAL_HW_SAMAV3_CMD_SELECT_MAC_KEY_DIV_VCUID
  																		 *  			\arg #PHHAL_HW_SAMAV3_CMD_SELECT_MAC_KEY_DIV_INPUT_VCUID
																		 *        \n
																		 *		  Option to disable the diversification for VcSelect MAC and ENC keys.
																		 *			\arg #PHHAL_HW_SAMAV3_CMD_SELECT_DIV_DEFAULT
																		 */
    uint8_t bEncKeyNo,												/**< [In] Reference key number to be used in hardware keystore as VCSelectEncKey.*/
    uint8_t bEncKeyVer,												/**< [In] Reference key version to be used in hardware keystore as VCSelectEncKey.*/
    uint8_t bMacKeyNo,												/**< [In] Reference key number to be used in hardware keystore as VCSelectMacKey.*/
    uint8_t bMacKeyVer,												/**< [In] Reference key version to be used in hardware keystore as VCSelectMacKey.*/
    uint8_t *pData,												/**< [In] Cmd.ISOSelect response payload (32 Bytes) without TLV headers, including the VC related data. */
    uint8_t bDataLen,												/**< [In] Length of bytes available in Data buffer. */
    uint8_t *pDivInput,											/**< [In] Diversification Input used to diversify the key. */
    uint8_t bDivInputLen,											/**< [In] Length of diversification input used to diversify the key. */
    uint8_t **ppResponse, 											/**< [Out] Response to Challenge as MACt(DivKey(KVCSelMAC)), RndChal || VCData) */
    uint16_t *pRespLen												/**< [Out] Length of bytes available in Response buffer. */
);

/**
 * \brief Performs Proximity Check Part 1 command execution.
 *
 * \return Status code
 * \retval #PH_ERR_SUCCESS Operation successful.
 * \retval Other Depending on implementation and underlaying component.
 */
phStatus_t phhalHw_SamAV3_Cmd_SAM_ProximityCheck_Part1(
    phhalHw_SamAV3_DataParams_t
    *pDataParams,						/**< [In] Pointer to this layer's parameter structure. */
    uint8_t  bOption,												/**< [In] Option to update the P1 information.
 																		 *			\arg #PHHAL_HW_SAMAV3_CMD_PROXIMITY_CHECK_DIV_OFF
  																		 *  		\arg #PHHAL_HW_SAMAV3_CMD_PROXIMITY_CHECK_DIV_ON
																		 */
    uint8_t bKeyNo,													/**< [In] Reference key number to be used in hardware keystore. */
    uint8_t bKeyVer,												/**< [In] Reference key version to be used in hardware keystore. */
    uint8_t *PPCData,												/**< [In] Cmd.PreparePC response data. \n
																		 *			\c For DESFIRE PICC: Option (1byte) || PubRespTime (2byte) [|| PPS1 (1byte)] \n
																		 *			\c For PLUS PICC   : Option (1byte) || PubRespTime (2byte) [|| PPS1 (1byte)] [|| ActBitRate (N byte)]
																		 */
    uint8_t bPPCDataLen,											/**< [In] Length of bytes available in PPCData buffer. */
    uint8_t *pPCData,												/**< [In] Response and challenge bytes exchanged during the proximity check protocol as
																		 *		  (pRndR1 || pRndC1) || ... || (pRndR8 || pRndC8)
																		 */
    uint8_t  bPCDataLen,											/**< [In] Length of bytes available in PCData buffer. */
    uint8_t *pDivInput,											/**< [In] Diversification Input used to diversify the key. */
    uint8_t bDivInputLen,											/**< [In] Length of diversification input used to diversify the key. */
    uint8_t **ppMac,												/**< [Out] The MAC to be exchanged to the PICC. */
    uint16_t *pMacLen												/**< [Out] Length of bytes available in MAC buffer. */
);

/**
* \brief Performs Proximity Check Part 2 command execution.
*
* \return Status code
* \retval #PH_ERR_SUCCESS Operation successful.
* \retval Other Depending on implementation and underlaying component.
*/
phStatus_t phhalHw_SamAV3_Cmd_SAM_ProximityCheck_Part2(
    phhalHw_SamAV3_DataParams_t
    *pDataParams,						/**< [In] Pointer to this layer's parameter structure. */
    uint8_t *pData,												/**< [In] The data to be exchaned to SAM hardware. \n
																		 *			\c For PICC Error  : The PICC error code should be passed and bDataLen should be 1. \n
																		 *			\c For PICC Success: The MAC received from PICC should be passed and bDataLen should be 8.
																		 */
    uint8_t bDataLen,												/**< [In] Length of bytes available in Data bffer. */
    uint8_t *pPiccRetCode											/**< [Out] The response code PICC echoed back by the Sam hardware. */
);

/**
 * end of phhalHw_SamAV3_Cmd_VCA_S
 * @}
 */

/** \defgroup phhalHw_SamAV3_Cmd_VCA_X X Mode
 * \brief SAM commands used for Virtual Card communication in X-Mode.
* @{
*/

/** \name Sam AV3 command code for VCA / PC X mode features. */
/* @{ */
#define PHHAL_HW_SAMAV3_CMD_VCA_SELECT_INS						0x45	/**< Sam AV3 Instruction code for Cmd.VCA_SelectVC command. */
#define PHHAL_HW_SAMAV3_CMD_VCA_PROXIMITY_CHECK_INS				0xFB	/**< Sam AV3 Instruction code for Cmd.VCA_ProximityCheck command. */
/* @} */

/** \name Option macros for Sam AV3 VCA / PC 2-part variants for VC selection. */
/* @{ */
#define PHHAL_HW_SAMAV3_CMD_VCA_SELECT_VARIANT_PART1			0x00	/**< Option mask for complete VC selection in 1 part. */
#define PHHAL_HW_SAMAV3_CMD_VCA_SELECT_VARIANT_PART2			0x08	/**< Option mask for complete VC selection in 2 part. */
/* @} */

/**
 * \brief Performs Virtual card selection in X-Mode.
 *
 * \return Status code
 * \retval #PH_ERR_SUCCESS Operation successful.
 * \retval Other Depending on implementation and underlaying component.
 */
phStatus_t phhalHw_SamAV3_Cmd_VCA_Select(
    phhalHw_SamAV3_DataParams_t
    *pDataParams,						/**< [In] Pointer to this layer's parameter structure. */
    uint8_t bOption,												/**< [In] Option to indicate diversification options for VCSelectMAC key.
																		 *			\arg #PHHAL_HW_SAMAV3_CMD_SELECT_MAC_KEY_DIV_OFF
																		 *			\arg #PHHAL_HW_SAMAV3_CMD_SELECT_MAC_KEY_DIV_INPUT
																		 *			\arg #PHHAL_HW_SAMAV3_CMD_SELECT_MAC_KEY_DIV_VCUID
																		 *			\arg #PHHAL_HW_SAMAV3_CMD_SELECT_MAC_KEY_DIV_INPUT_VCUID
																		 *
																		 *		  Option to indicate diversification options for VcSelectENC key.
																		 *			\arg #PHHAL_HW_SAMAV3_CMD_SELECT_ENC_KEY_DIV_OFF
																		 *			\arg #PHHAL_HW_SAMAV3_CMD_SELECT_ENC_KEY_DIV_INPUT
																		 *
																		 *		  Option to disable the diversification for VcSelect MAC and ENC keys.
																		 *			\arg #PHHAL_HW_SAMAV3_CMD_SELECT_DIV_DEFAULT
																		 *
																		 *		  VC selection can be done in 1-part of 2-parts.
																		 *			\arg #PHHAL_HW_SAMAV3_CMD_VCA_SELECT_VARIANT_PART1
																		 *			\arg #PHHAL_HW_SAMAV3_CMD_VCA_SELECT_VARIANT_PART2
																		 */
    uint8_t bEncKeyNo,												/**< [In] Reference key number to be used in hardware keystore for VCSelectENC key. */
    uint8_t bEncKeyVer,												/**< [In] Reference key version to be used in hardware keystore for VCSelectENC key. */
    uint8_t bMacKeyNo,												/**< [In] Reference key number to be used in hardware keystore for VCSelectMAC key. */
    uint8_t bMacKeyVer,												/**< [In] Reference key version to be used in hardware keystore for VCSelectMAC key. */
    uint8_t *pIID,													/**< [In] The Installation Identifier (IID) to be selected. */
    uint8_t bIIDLen,												/**< [In] Length of the IID. */
    uint8_t *pDivInput,											/**< [In] Diversification Input used to diversify the key. */
    uint8_t bDivInputLen,											/**< [In] Length of diversification input used to diversify the key. */
    uint8_t **pResponse,											/**< [Out] Response received from SAM based on the variants and AuthVCMandatory settings \n
																		 *			\c AuthVC Not Mandatory & Variant 1 : Conf0 (1byte), FCI (N bytes) \n
																		 *			\c AuthVC Mandatory & Variant 1     : Conf1 (1byte), VC Data (16 bytes) \n
																		 *			\c AuthVC Mandatory & Variant 2     : VC Data (16 bytes)
																		 */
    uint16_t *pRespLen,											/**< [Out] Length bytes available in response buffer. */
    uint16_t *pPiccRetCode											/**< [Out] The status code returned from the PICC. This will be applicable for both the variants. */
);

/** \name Option macros for Sam AV3 VCA / PC Proximity check command format (Native or Wrapped). */
/* @{ */
#define PHHAL_HW_SAMAV3_CMD_PC_NATIVE_FORMAT					0x00	/**< Option mask to perform Proximity Check in native format. */
#define PHHAL_HW_SAMAV3_CMD_PC_WRAPPED_FORMAT					0x04	/**< Option mask to perform Proximity Check in Iso7816-4 wrapped format. */
/* @} */

/** \name Option macros for Sam AV3 VCA / PC Proximity check random or normal processing. */
/* @{ */
#define PHHAL_HW_SAMAV3_CMD_PC_NORMAL_PROCESSING				0x00	/**< Option mask to perform Normal Cmd.VerifyPC processing. */
#define PHHAL_HW_SAMAV3_CMD_PC_RANDOM_PROCESSING				0x02	/**< Option mask to perform Random Cmd.VerifyPC processing. */
/* @} */

/**
 * \brief Performs Proximity Check command execution in X-Mode.
 *
 * \return Status code
 * \retval #PH_ERR_SUCCESS Operation successful.
 * \retval Other Depending on implementation and underlaying component.
 */
phStatus_t phhalHw_SamAV3_Cmd_VCA_ProximityCheck(
    phhalHw_SamAV3_DataParams_t
    *pDataParams,						/**< [In] Pointer to this layer's parameter structure. */
    uint8_t  bOption,												/**< [In] Option to indicate diversification options.
																		 *			\arg #PHHAL_HW_SAMAV3_CMD_PROXIMITY_CHECK_DIV_OFF
																		 *			\arg #PHHAL_HW_SAMAV3_CMD_PROXIMITY_CHECK_DIV_ON
																		 *
																		 *		  Option to indicate Cmd.VerifyPC processing.
																		 *			\arg #PHHAL_HW_SAMAV3_CMD_PC_NORMAL_PROCESSING
																		 *			\arg #PHHAL_HW_SAMAV3_CMD_PC_RANDOM_PROCESSING
																		 *
																		 *		  The command format to be used to communicated to PICC.
																		 *			\arg #PHHAL_HW_SAMAV3_CMD_PC_NATIVE_FORMAT
																		 *			\arg #PHHAL_HW_SAMAV3_CMD_PC_WRAPPED_FORMAT
																		 */
    uint8_t bKeyNo,													/**< [In] Reference key number to be used in hardware keystore. */
    uint8_t bKeyVer,												/**< [In] Reference key version to be used in hardware keystore. */
    uint8_t  bNumOfRand,											/**< [In] Maximum number of random bytes sent in one Cmd.ProxmityCheck */
    uint8_t *pDivInput,											/**< [In] Diversification Input used to diversify the key. */
    uint8_t bDivInputLen,											/**< [In] Length of diversification input used to diversify the key. */
    uint8_t **ppResponse,											/**< [Out] Response received from SAM. \n
																		 *			\c For PICC Error  : The PICC error code will be returned. \n
																		 *			\c For PICC Success: The PPCDataLen and PPCData will be returned.
																		 */
    uint16_t *pRespLen												/**< [Out] Length bytes available in response buffer. */
);

/**
 * end of phhalHw_SamAV3_Cmd_VCA_X
 * @}
 */

/**
 * end of phhalHw_SamAV3_Cmd_VCA
 * @}
 */

/*************************************************************************************************************************/
/**************************************************** MIFARE DESFire *****************************************************/
/*************************************************************************************************************************/

/** \defgroup phhalHw_SamAV3_Cmd_MFD MIFARE DESFire
 * \brief SAM commands used for MIFARE DESFire PICC communication in X and S Mode.
 * @{
 */

/** \name Option macros for SAM AV3 Cmd.SAM_AuthenticatePICC, Cmd.SAM_IsoAuthenticatePICC, Cmd.DESFIRE_AuthenticatePICC command. */
/* @{ */
#define PHHAL_HW_CMD_SAMAV3_AUTH_MODE_D40_EV1					0x00	/**< Sam DESFire Authentication mode as D40 and EV1. */
#define PHHAL_HW_CMD_SAMAV3_AUTH_MODE_EV2_FIRST_AUTH			0x80	/**< Sam DESFire Authentication mode as EV2 First. */
#define PHHAL_HW_CMD_SAMAV3_AUTH_MODE_EV2_NON_FIRST_AUTH		0xC0	/**< Sam DESFire Authentication mode as EV2 Non First. */
#define PHHAL_HW_CMD_SAMAV3_ALLOW_SECURE_MESSAGING				0x00	/**< Sam DESFire Allow Secure Messaging. */
#define PHHAL_HW_CMD_SAMAV3_SUPPRESS_SECURE_MESSAGING			0x20	/**< Sam DESFire Supress Secure Messaging. To be used if originality keys are used. */
#define PHHAL_HW_CMD_SAMAV3_KDF_AV1								0x00	/**< Sam DESFire key derivation type as AV1. */
#define PHHAL_HW_CMD_SAMAV3_KDF_AV1_DOUBLE_ENCRYPTION			0x00	/**< Sam DESFire key derivation type as AV1 double encryption round. */
#define PHHAL_HW_CMD_SAMAV3_KDF_AV1_SINGLE_ENCRYPTION			0x08	/**< Sam DESFire key derivation type as AV1 single encryption round. */
#define PHHAL_HW_CMD_SAMAV3_KDF_AV2								0x10	/**< Sam DESFire key derivation type as AV2. */
#define PHHAL_HW_CMD_SAMAV3_KDF_RFU								0x18	/**< Sam DESFire key derivation type as RFU */
#define PHHAL_HW_CMD_SAMAV3_KEY_SELECTION_KEY_ENTRY_NUMBER		0x00	/**< Sam DESFire key selection by key entry number. */
#define PHHAL_HW_CMD_SAMAV3_KEY_SELECTION_DESFIRE_KEY_NUMBER	0x02	/**< Sam DESFire key selection by DESFIRE key number. */
#define PHHAL_HW_CMD_SAMAV3_KEY_DIVERSIFICATION_OFF				0x00	/**< Sam DESFire key derivation disabled. */
#define PHHAL_HW_CMD_SAMAV3_KEY_DIVERSIFICATION_ON				0x01	/**< Sam DESFire key derivation enabled. */
/* @} */

/** \name Option macros for Key to be used for when EV2 Authentication is selected. */
/* @{ */
#define PHHAL_HW_CMD_SAMAV3_AUTH_MODE_NONE						0x00	/**< Sam DESFire Auth mode as D40, EV1. */
#define PHHAL_HW_CMD_SAMAV3_AUTH_MODE_EV2						0x00	/**< Sam DESFire Auth mode as EV2. */
#define PHHAL_HW_CMD_SAMAV3_AUTH_MODE_LRP						0x01	/**< Sam DESFire Auth mode as LRP. */
/* @} */

/** \name Option macros for ISO mode selection. */
/* @{ */
#define PHHAL_HW_CMD_SAMAV3_ISO_MODE_NATIVE						0x00	/**< Sam DESFire ISO mode selection for Native command set. */
#define PHHAL_HW_CMD_SAMAV3_ISO_MODE_ISO7816					0x40	/**< Sam DESFire ISO mode selection for ISO 7816-4 command set. */
#define PHHAL_HW_CMD_SAMAV3_ISO_MODE_ISO_AUTHENTICATION			0x80	/**< Sam DESFire ISO mode selection for Iso complaint Authentication. */
/* @} */

/** \name Option macros for SAM AV3 Cmd.SAM_ChangeKey command */
/* @{ */
#define PHHAL_HW_CMD_SAMAV3_DIV_METHOD_AV1						0x00	/**< Sam DESFire diversification method as AV1. */
#define PHHAL_HW_CMD_SAMAV3_DIV_METHOD_AV2						0x20	/**< Sam DESFire diversification method as AV2. */
#define PHHAL_HW_CMD_SAMAV3_KDF_SAMAV2_RFU						0x00	/**< Sam DESFire diversification method as RFU if its SAM AV2. */
#define PHHAL_HW_CMD_SAMAV3_KDF_CURRENT_KEY_DOUBLE_ENCRYPTION	0x00	/**< Sam DESFire diversification method of current key for AV1 as double encryption. */
#define PHHAL_HW_CMD_SAMAV3_KDF_CURRENT_KEY_SINGLE_ENCRYPTION	0x10	/**< Sam DESFire diversification method of current key for AV1 as single encryption. */
#define PHHAL_HW_CMD_SAMAV3_KDF_NEW_KEY_DOUBLE_ENCRYPTION		0x00	/**< Sam DESFire diversification method of new key for AV1 as double encryption. */
#define PHHAL_HW_CMD_SAMAV3_KDF_NEW_KEY_SINGLE_ENCRYPTION		0x08	/**< Sam DESFire diversification method of new key for AV1 as single encryption. */
#define PHHAL_HW_CMD_SAMAV3_KDF_CURRENT_KEY_OFF					0x00	/**< Sam DESFire diversification usage for current key is disabled. */
#define PHHAL_HW_CMD_SAMAV3_KDF_CURRENT_KEY_ON					0x04	/**< Sam DESFire diversification usage for current key is enabled. */
#define PHHAL_HW_CMD_SAMAV3_KDF_NEW_KEY_OFF						0x00	/**< Sam DESFire diversification usage for new key is disabled. */
#define PHHAL_HW_CMD_SAMAV3_KDF_NEW_KEY_ON						0x02	/**< Sam DESFire diversification usage for new key is enabled. */
#define PHHAL_HW_CMD_SAMAV3_CRYPTO_MODE_DIFFERENT_KEY			0x00	/**< Sam DESFire crypto computation mode are different for target and auth keys. */
#define PHHAL_HW_CMD_SAMAV3_CRYPTO_MODE_SAME_KEY				0x01	/**< Sam DESFire crypto computation mode are same for target and auth keys. */
#define PHHAL_HW_CMD_SAMAV3_CMD_TYPE_CHANGE_KEY					0x00	/**< Sam DESFire Change Key command type as Change Key. */
#define PHHAL_HW_CMD_SAMAV3_CMD_TYPE_CHANGE_KEY_EV2				0x20	/**< Sam DESFire Change Key command type as Change Key EV2. */
#define PHHAL_HW_CMD_SAMAV3_MASTER_KEY_UPDATE_EXCLUDE_KEYTYPE	0x00	/**< Sam DESFire PICC Master key update to exclude key type in cryptogram. */
#define PHHAL_HW_CMD_SAMAV3_MASTER_KEY_UPDATE_INCLUDE_KEYTYPE	0x10	/**< Sam DESFire PICC Master key update to include key type in cryptogram.
																		 *	 This byte will be right shifted 2 time to update the bit 4.
																		 */
/* @} */

/** \name Option for Cmd.DESFire_CreateTMFilePICC command. */
/* @{ */
#define PHHAL_HW_CMD_SAMAV3_CREATE_TM_FILE_COMM_MODE_PLAIN		0x00	/**< Sam DESFire communication mode as Plain. */
#define PHHAL_HW_CMD_SAMAV3_CREATE_TM_FILE_COMM_MODE_MAC		0x01	/**< Sam DESFire communication mode as MAC. */
#define PHHAL_HW_CMD_SAMAV3_CREATE_TM_FILE_COMM_MODE_FULL		0x03	/**< Sam DESFire communication mode as Full. */
#define PHHAL_HW_CMD_SAMAV3_CREATE_TM_FILE_AES_KEY				0x02	/**< Sam DESFire TMKeyOption as AES. */
/* @} */

/** \defgroup phhalHw_SamAV3_Cmd_MFD_S S Mode
 * \brief SAM commands used for MIFARE DESFire communication in S-Mode.
* @{
*/

/** \name Sam AV3 command code for MIFARE DESFire S features. */
/* @{ */
#define PHHAL_HW_SAMAV3_CMD_SAM_AUTHENTICATE_PICC_INS			0x0A	/**< Sam AV3 Instruction code for Cmd.SAM_AuthenticatePICC command. */
#define PHHAL_HW_SAMAV3_CMD_SAM_ISO_AUTHENTICATE_PICC_INS		0x8E	/**< Sam AV3 Instruction code for Cmd.SAM_IsoAuthenticatePICC command. */
#define PHHAL_HW_SAMAV3_CMD_SAM_CHANGE_KEY_PICC_INS				0xC4	/**< Sam AV3 Instruction code for Cmd.SAM_ChangeKeyPICC command. */
#define PHHAL_HW_SAMAV3_CMD_SAM_CREATE_TM_FILE_PICC_INS			0xC6	/**< Sam AV3 Instruction code for Cmd.SAM_CreateTMFilePICC command. */
/* @} */

/**
 * \brief Performs first part of encryption and decryption of data received from Card and to be sent to Card. Here the Encrypted RndB data will be
 * sent to Sam hardware. Sam hardware will Decrypt the data and Encrpyt RndA with RndB'. This encrypted RndA and RndB' will be returned to the caller
 * for further transmission to the Card.
 *
 * \return Status code
 * \retval #PH_ERR_SUCCESS_CHAINING for successfull chaining operation.
 * \retval Other Depending on implementation and underlaying component.
 */
phStatus_t phhalHw_SamAV3_Cmd_SAM_AuthenticatePICC_Part1(
    phhalHw_SamAV3_DataParams_t
    *pDataParams,						/**< [In] Pointer to this layer's parameter structure. */
    uint8_t bOption,												/**< [In] Option to update the P1 information. The options can be combined by bitwise oring.
																		 *			Option for Authentication mode and Authentication type
 																		 *				\arg #PHHAL_HW_CMD_SAMAV3_AUTH_MODE_D40_EV1
  																		 *  			\arg #PHHAL_HW_CMD_SAMAV3_AUTH_MODE_EV2_FIRST_AUTH
  																		 *  			\arg #PHHAL_HW_CMD_SAMAV3_AUTH_MODE_EV2_NON_FIRST_AUTH
  																		 *			\n
																		 *			Option for Supressing secure messaging
 																		 *				\arg #PHHAL_HW_CMD_SAMAV3_ALLOW_SECURE_MESSAGING
  																		 *  			\arg #PHHAL_HW_CMD_SAMAV3_SUPPRESS_SECURE_MESSAGING
  																		 *			\n
  																		 *			Option for Key Derivation Information and Key Diversification Types.
  																		 *  			\arg #PHHAL_HW_CMD_SAMAV3_KDF_AV1
  																		 *  			\arg #PHHAL_HW_CMD_SAMAV3_KDF_AV1_DOUBLE_ENCRYPTION
  																		 *  			\arg #PHHAL_HW_CMD_SAMAV3_KDF_AV1_SINGLE_ENCRYPTION
  																		 *  			\arg #PHHAL_HW_CMD_SAMAV3_KDF_AV2
  																		 *  			\arg #PHHAL_HW_CMD_SAMAV3_KDF_RFU
  																		 *			\n
  																		 *			Option for Key Selection
  																		 *  			\arg #PHHAL_HW_CMD_SAMAV3_KEY_SELECTION_KEY_ENTRY_NUMBER
  																		 *  			\arg #PHHAL_HW_CMD_SAMAV3_KEY_SELECTION_DESFIRE_KEY_NUMBER
  																		 *			\n
  																		 *			Option for Key Diversification
  																		 *  			\arg #PHHAL_HW_CMD_SAMAV3_KEY_DIVERSIFICATION_OFF
  																		 *				\arg #PHHAL_HW_CMD_SAMAV3_KEY_DIVERSIFICATION_ON
																		 */
    uint8_t bKeyNo,													/**< [In] Reference key number to be used in hardware keystore. */
    uint8_t bKeyVer,												/**< [In] Reference key version to be used in hardware keystore. */
    uint8_t bAuthMode,												/**< [In] The type of key to be used for EV2 authentication.
 																		 *				\arg #PHHAL_HW_CMD_SAMAV3_AUTH_MODE_EV2
  																		 *  			\arg #PHHAL_HW_CMD_SAMAV3_AUTH_MODE_LRP
																		 */
    uint8_t *pDivInput,											/**< [In] Diversification Input used to diversify the key. */
    uint8_t bDivInputLen,											/**< [In] Length of diversification input used to diversify the key. */
    uint8_t *pCardResponse,										/**< [In] Encrypted RndB data returned by the card. */
    uint8_t bCardRespLen,											/**< [In] Length of Encrypted RndB data. */
    uint8_t **ppSamResponse,										/**< [Out] Encrypted RndA and RndB' returned by the Sam hardware. */
    uint16_t *pSamRespLen											/**< [Out] Length of Encrypted RndA and RndB' data. */
);

/**
 * \brief Performs second part of decryption of data received from Card. Here the Encrypted RndA' data will be sent to Sam hardware. Sam hardware will
 * Decrypt the data and extract PCD and PD Capabilities for EV2 First Auth and null in case of rest of Authentication modes. This PCD and PD
 * information will be returned to the caller. Also the status code of Card will be returned to the
 * caller in case of error.
 *
 * \return Status code
 * \retval #PH_ERR_SUCCESS Operation successful.
 * \retval Other Depending on implementation and underlaying component.
 */
phStatus_t phhalHw_SamAV3_Cmd_SAM_AuthenticatePICC_Part2(
    phhalHw_SamAV3_DataParams_t
    *pDataParams,						/**< [In] Pointer to this layer's parameter structure. */
    uint8_t bPiccErrorCode,											/**< [In] Status code returned by the Card in case of failure else 90 for success. */
    uint8_t *pCardResponse,										/**< [In] Encrypted RndA' returned by the Sam hardware. */
    uint8_t bCardRespLen,											/**< [In] Length of Encrypted RndA' data. */
    uint8_t *pPDcap2,												/**< [Out] Buffer containing the output PD capabilities. This will contain 6 bytes of valid PD information. */
    uint8_t *pPCDcap2,												/**< [Out] Buffer containing the output PCD capabilities. This will contain 6 bytes of valid PCD information. */
    uint8_t *pStatusCode											/**< [Out] Status code from Desfire PICC if available else zero. */
);

/**
 * \brief Performs first part of encryption and decryption of data received from Card and to be sent to Card. Here the Encrypted
 * RndB data will be sent to Sam hardware. Sam hardware will Decrypt the data and Encrpyt RndA with RndB'. This encrypted RndA and
 * RndB' will be returned to the caller for further transmission to the Card.
 *
 * \return Status code
 * \retval #PH_ERR_SUCCESS_CHAINING for successfull chaining operation
 * \retval Other Depending on implementation and underlaying component.
 */
phStatus_t phhalHw_SamAV3_Cmd_SAM_IsoAuthenticatePICC_Part1(
    phhalHw_SamAV3_DataParams_t
    *pDataParams,						/**< [In] Pointer to this layer's parameter structure. */
    uint8_t bOption,												/**< [In] Options mentioned in the description. The options can be combined by bitwise oring.
  																		 *			Option for Key Derivation Information and Key Diversification Types.
  																		 *  			\arg #PHHAL_HW_CMD_SAMAV3_KDF_AV1
  																		 *  			\arg #PHHAL_HW_CMD_SAMAV3_KDF_AV1_DOUBLE_ENCRYPTION
  																		 *  			\arg #PHHAL_HW_CMD_SAMAV3_KDF_AV1_SINGLE_ENCRYPTION
  																		 *  			\arg #PHHAL_HW_CMD_SAMAV3_KDF_AV2
  																		 *  			\arg #PHHAL_HW_CMD_SAMAV3_KDF_RFU
  																		 *			\n
  																		 *			Option for Key Selection
  																		 *  			\arg #PHHAL_HW_CMD_SAMAV3_KEY_SELECTION_KEY_ENTRY_NUMBER
  																		 *  			\arg #PHHAL_HW_CMD_SAMAV3_KEY_SELECTION_DESFIRE_KEY_NUMBER
  																		 *			\n
  																		 *			Option for Key Diversification
  																		 *  			\arg #PHHAL_HW_CMD_SAMAV3_KEY_DIVERSIFICATION_OFF
  																		 *				\arg #PHHAL_HW_CMD_SAMAV3_KEY_DIVERSIFICATION_ON
																		 */
    uint8_t bKeyNo,													/**< [In] Reference key number to be used in hardware keystore. */
    uint8_t bKeyVer,												/**< [In] Reference key version to be used in hardware keystore. */
    uint8_t *pDivInput,											/**< [In] Diversification Input used to diversify the key. */
    uint8_t bDivInputLen,											/**< [In] Length of diversification input used to diversify the key. */
    uint8_t *pCardResponse,										/**< [In] Encrypted RndB data returned by the card. */
    uint8_t bCardRespLen,											/**< [In] Length of Encrypted RndB data. */
    uint8_t **ppSamResponse,										/**< [Out] Encrypted RndA and RndB' returned by the Sam hardware. */
    uint16_t *pSamRespLen											/**< [Out] Length of Encrypted RndA and RndB' data. */
);

/**
 * Performs second part of decryption of data received from Card. Here the Encrypted RndA' data will be sent to Sam hardware. Sam hardware will
 * Decrypt the data and extract PCD and PD Capabilities for EV2 First Auth and null in case of rest of Authentication modes. This PCD and PD
 * information will be returned to the caller. Also the status code of Card will be returned to the caller in case of error.
 *
 * \return Status code
 * \retval #PH_ERR_SUCCESS Operation successful.
 * \retval Other Depending on implementation and underlaying component.
 */
phStatus_t phhalHw_SamAV3_Cmd_SAM_IsoAuthenticatePICC_Part2(
    phhalHw_SamAV3_DataParams_t
    *pDataParams,						/**< [In] Pointer to this layer's parameter structure. */
    uint8_t *pCardResponse,										/**< [In] Encrypted RndA' returned by the Sam hardware. */
    uint8_t bCardRespLen											/**< [In] Length of Encrypted RndA' data. */
);

/**
 * \brief Performs key change for the specified current key to a new key. The crypto operation of the key to be changed will be calculated
 * by SAM hardware. This crypto data will then sent to card to perform Change Key operations.
 *
 * \return Status code
 * \retval #PH_ERR_SUCCESS Operation successful.
 * \retval Other Depending on implementation and underlaying component.
 */
phStatus_t phhalHw_SamAV3_Cmd_SAM_ChangeKeyPICC(
    phhalHw_SamAV3_DataParams_t
    *pDataParams,						/**< [In] Pointer to this layer's parameter structure. */
    uint8_t bCryptoMethod,											/**< [In] Options for P1 information byte
																		 *		  Key diversification method
																		 *			\arg #PHHAL_HW_CMD_SAMAV3_DIV_METHOD_AV1
																		 *			\arg #PHHAL_HW_CMD_SAMAV3_DIV_METHOD_AV2
																		 *		  \n
																		 *		  Sam AV1 and Sam AV2 Key diversification method
																		 *			\arg #PHHAL_HW_CMD_SAMAV3_KDF_SAMAV2_RFU
																		 * 			\arg #PHHAL_HW_CMD_SAMAV3_KDF_CURRENT_KEY_DOUBLE_ENCRYPTION
																		 * 			\arg #PHHAL_HW_CMD_SAMAV3_KDF_CURRENT_KEY_SINGLE_ENCRYPTION
																		 * 			\arg #PHHAL_HW_CMD_SAMAV3_KDF_NEW_KEY_DOUBLE_ENCRYPTION
																		 *			\arg #PHHAL_HW_CMD_SAMAV3_KDF_NEW_KEY_SINGLE_ENCRYPTION
																		 *			\arg #PHHAL_HW_CMD_SAMAV3_KDF_CURRENT_KEY_OFF
																		 *			\arg #PHHAL_HW_CMD_SAMAV3_KDF_CURRENT_KEY_ON
																		 *			\arg #PHHAL_HW_CMD_SAMAV3_KDF_NEW_KEY_OFF
																		 *			\arg #PHHAL_HW_CMD_SAMAV3_KDF_NEW_KEY_ON
																		 *		  \n
																		 * 		  Cryptogram computation mode
																		 * 			\arg #PHHAL_HW_CMD_SAMAV3_CRYPTO_MODE_DIFFERENT_KEY
																		 * 			\arg #PHHAL_HW_CMD_SAMAV3_CRYPTO_MODE_SAME_KEY
																		 */
    uint8_t bConfig,												/**< [In] Options for P2 information byte.
																		 *		  ISO mode to be used.
 																		 *			\arg #PHHAL_HW_CMD_SAMAV3_ISO_MODE_NATIVE
 																		 *  		\arg #PHHAL_HW_CMD_SAMAV3_ISO_MODE_ISO7816
																		 *		  \n
																		 *		  Command Type
																		 * 			\arg #PHHAL_HW_CMD_SAMAV3_CMD_TYPE_CHANGE_KEY
																		 * 			\arg #PHHAL_HW_CMD_SAMAV3_CMD_TYPE_CHANGE_KEY_EV2
																		 *		  \n
																		 * 		  PICC master key update
																		 * 			\arg #PHHAL_HW_CMD_SAMAV3_MASTER_KEY_UPDATE_EXCLUDE_KEYTYPE
																		 * 			\arg #PHHAL_HW_CMD_SAMAV3_MASTER_KEY_UPDATE_INCLUDE_KEYTYPE
																		 */
    uint8_t bKeySetNo,												/**< [In] Key set number to which the key to be changed belongs to. */
    uint8_t bDFKeyNo,												/**< [In] Block number of the key available in the card. This will be used while
																		 *		  exchanging the command with card. The lower nibble will be used for P2
																		 *		  information byte if command type is ChangeKey and the complete byte
																		 *		  will be used if command type is ChangeKeyEV2.
																		 */
    uint8_t bCurrKeyNo,												/**< [In] Reference key number to be used in hardware keystore for CurrentKey. */
    uint8_t bCurrKeyVer,											/**< [In] Reference key version to be used in hardware keystore for CurrentKey. */
    uint8_t bNewKeyNo,												/**< [In] Reference key number to be used in hardware keystore for NewKey. */
    uint8_t bNewKeyVer,												/**< [In] Reference key version to be used in hardware keystore for NewKey. */
    uint8_t *pDivInput,											/**< [In] Diversification Input used to diversify the key. */
    uint8_t bDivInputLen,											/**< [In] Length of diversification input used to diversify the key. */
    uint8_t **ppSamResponse,										/**< [Out] Cryptogram holding key data. */
    uint16_t *pSamRespLen											/**< [Out] Length of Cryptogram data. */
);

/**
 * \brief Performs creation of cryptogram for Transaction MAC file creation.
 *
 * \return Status code
 * \retval #PH_ERR_SUCCESS Operation successful.
 * \retval Other Depending on implementation and underlaying component.
 */
phStatus_t phhalHw_SamAV3_Cmd_SAM_CreateTMFilePICC(
    phhalHw_SamAV3_DataParams_t
    *pDataParams,						/**< [In] Pointer to this layer's parameter structure. */
    uint8_t bOption,												/**< [In] Options for P1 information byte.
																		 *			\arg #PHHAL_HW_CMD_SAMAV3_KEY_DIVERSIFICATION_OFF
																		 *			\arg #PHHAL_HW_CMD_SAMAV3_KEY_DIVERSIFICATION_ON
																		 */
    uint8_t bKeyNo,													/**< [In] Reference key number to be used in hardware keystore. */
    uint8_t bKeyVer,												/**< [In] Reference key version to be used in hardware keystore. */
    uint8_t bFileNo,												/**< [In] File number of the file to be created. */
    uint8_t bFileOption,											/**< [In] Options for the targeted file.
																		 *			\arg #PHHAL_HW_CMD_SAMAV3_CREATE_TM_FILE_COMM_MODE_PLAIN
																		 *			\arg #PHHAL_HW_CMD_SAMAV3_CREATE_TM_FILE_COMM_MODE_MAC
																		 *			\arg #PHHAL_HW_CMD_SAMAV3_CREATE_TM_FILE_COMM_MODE_FULL
																		 */
    uint8_t *pAccessRights,										/**< [In] Access conditions to be applied for the file. Refer DESFire EV2 datasheet for access
																		 *		  rights information. This should be two bytes long.
																		 */
    uint8_t bTMKeyOptions,											/**< [In] Option for the TransactionMAC Key. #PHHAL_HW_CMD_SAMAV3_CREATE_TM_FILE_AES_KEY is currently
																		 *		  supported option as per DESFireEV2 datasheet.
																		 */
    uint8_t *pDivInput,											/**< [In] Diversification Input used to diversify the key. */
    uint8_t bDivInputLen,											/**< [In] Length of diversification input used to diversify the key. */
    uint8_t **ppSamResponse,										/**< [Out] Cryptogram holding Transaction MAC Key data. */
    uint16_t *pSamRespLen											/**< [Out] Length of Cryptogram data. */
);

/**
 * end of phhalHw_SamAV3_Cmd_MFD_S
 * @}
 */

/** \defgroup phhalHw_SamAV3_Cmd_MFD_X X Mode
 * \brief SAM commands used for MIFARE DESFire communication in X-Mode.
* @{
*/

/** \name Sam AV3 command code for MIFARE DESFire X features. */
/* @{ */
#define PHHAL_HW_SAMAV3_CMD_DESFIRE_AUTHENTICATE_INS			0xDA	/**< Sam AV3 Instruction code for Cmd.DESFIRE_Authenticate command. */
#define PHHAL_HW_SAMAV3_CMD_DESFIRE_CHANGE_KEY_INS				0xDE	/**< Sam AV3 Instruction code for Cmd.DESFIRE_ChangeKey command. */
#define PHHAL_HW_SAMAV3_CMD_DESFIRE_WRITE_X_INS					0xD3	/**< Sam AV3 Instruction code for Cmd.DESFIRE_WriteX command. */
#define PHHAL_HW_SAMAV3_CMD_DESFIRE_READ_X_INS					0xD2	/**< Sam AV3 Instruction code for Cmd.DESFIRE_ReadX command. */
#define PHHAL_HW_SAMAV3_CMD_DESFIRE_CREATE_TM_FILE_INS			0xD1	/**< Sam AV3 Instruction code for Cmd.DESFIRE_CreateTMFilePICC command. */
/* @} */

/**
 * \brief Perform an authentication procedure between SAM AV3 and DESFire.
 *
 * \return Status code
 * \retval #PH_ERR_SUCCESS Operation successful.
 * \retval Other Depending on implementation and underlaying component.
 */
phStatus_t phhalHw_SamAV3_Cmd_DESFire_AuthenticatePICC(
    phhalHw_SamAV3_DataParams_t
    *pDataParams,						/**< [In] Pointer to this layer's parameter structure. */
    uint8_t bOption,												/**< [In] Option to update the P1 information. The options can be combined by bitwise oring.
																		 *			Option for Authentication mode and Authentication type
 																		 *				\arg #PHHAL_HW_CMD_SAMAV3_AUTH_MODE_D40_EV1
  																		 *  			\arg #PHHAL_HW_CMD_SAMAV3_AUTH_MODE_EV2_FIRST_AUTH
  																		 *  			\arg #PHHAL_HW_CMD_SAMAV3_AUTH_MODE_EV2_NON_FIRST_AUTH
  																		 *			\n
																		 *			Option for Supressing secure messaging
 																		 *				\arg #PHHAL_HW_CMD_SAMAV3_ALLOW_SECURE_MESSAGING
  																		 *  			\arg #PHHAL_HW_CMD_SAMAV3_SUPPRESS_SECURE_MESSAGING
  																		 *			\n
  																		 *			Option for Key Derivation Information and Key Diversification Types.
  																		 *  			\arg #PHHAL_HW_CMD_SAMAV3_KDF_AV1
  																		 *  			\arg #PHHAL_HW_CMD_SAMAV3_KDF_AV1_DOUBLE_ENCRYPTION
  																		 *  			\arg #PHHAL_HW_CMD_SAMAV3_KDF_AV1_SINGLE_ENCRYPTION
  																		 *  			\arg #PHHAL_HW_CMD_SAMAV3_KDF_AV2
  																		 *  			\arg #PHHAL_HW_CMD_SAMAV3_KDF_RFU
  																		 *			\n
  																		 *			Option for Key Selection
  																		 *  			\arg #PHHAL_HW_CMD_SAMAV3_KEY_SELECTION_KEY_ENTRY_NUMBER
  																		 *  			\arg #PHHAL_HW_CMD_SAMAV3_KEY_SELECTION_DESFIRE_KEY_NUMBER
  																		 *			\n
  																		 *			Option for Key Diversification
  																		 *  			\arg #PHHAL_HW_CMD_SAMAV3_KEY_DIVERSIFICATION_OFF
  																		 *				\arg #PHHAL_HW_CMD_SAMAV3_KEY_DIVERSIFICATION_ON
																		 */
    uint8_t bISOMode,												/**< [In] ISO mode to be used.
 																		 *				\arg #PHHAL_HW_CMD_SAMAV3_ISO_MODE_NATIVE
 																		 *  			\arg #PHHAL_HW_CMD_SAMAV3_ISO_MODE_ISO7816
  																		 *  			\arg #PHHAL_HW_CMD_SAMAV3_ISO_MODE_ISO_AUTHENTICATION
																		 */
    uint8_t bDFKeyNo,												/**< [In] DESFire Key Number to be used for authentication. */
    uint8_t bKeyNo,													/**< [In] Reference key number to be used in hardware keystore. */
    uint8_t bKeyVer,												/**< [In] Reference key version to be used in hardware keystore. */
    uint8_t bPCDcap2InLen,											/**< [In] Length of PCDcap2 field in bytes. \n
																		 *			\c 0x00       : For NonFirst Authentication. \n
																		 *			\c 0x00       : For First Authentication with no input PCDCaps to use. \n
																		 *			\c 0xFF       : For First Authentication with default input PCDCaps to use. \n
																		 *			\c 0x01 - 0x06: For First Authentication with user defined PCDCaps to use.
																		 */
    uint8_t *pPCDcap2In,											/**< [In] Input PCD capabilites to be exchanged. \n
																		 *			\c NonFirstAuth                             : Should be null. \n
																		 *			\c FirstAuth with no Input PCD capabilities : Should be null. \n
																		 *			\c FirstAuth with PCDcap2InLen = 0xFF       : Should be null. \n
																		 *			\c FirstAuth with PCDcap2InLen = 0x01 - 0x06: Should not be null. The PCD input
																		 *														  capabilities should be passed.
																		 */
    uint8_t *pDivInput,											/**< [In] Diversification Input used to diversify the key. */
    uint8_t bDivInputLen,											/**< [In] Length of diversification input used to diversify the key. */
    uint8_t *pPDcap2,												/**< [Out] Buffer containing the output PD capabilities. This will contain 6 bytes of valid PD information. */
    uint8_t *pPCDcap2,												/**< [Out] Buffer containing the output PCD capabilities. This will contain 6 bytes of valid PCD information. */
    uint8_t *pPiccReturnCode										/**< [Out] Error code returned by PICC. This will of 1 byte in length for Native error code and two byte for rest. */
);

/**
 * \brief Change a key of a DESFire PICC.
 *
 * \return Status code
 * \retval #PH_ERR_SUCCESS Operation successful.
 * \retval Other Depending on implementation and underlaying component.
 */
phStatus_t phhalHw_SamAV3_Cmd_DESFire_ChangeKeyPICC(
    phhalHw_SamAV3_DataParams_t
    *pDataParams,						/**< [In] Pointer to this layer's parameter structure. */
    uint8_t bCryptoMethod,											/**< [In] Options for P1 information byte
																		 *		  Key diversification method
																		 *			\arg #PHHAL_HW_CMD_SAMAV3_DIV_METHOD_AV1
																		 *			\arg #PHHAL_HW_CMD_SAMAV3_DIV_METHOD_AV2
																		 *		  \n
																		 *		  Sam AV1 and Sam AV2 Key diversification method
																		 *			\arg #PHHAL_HW_CMD_SAMAV3_KDF_SAMAV2_RFU
																		 * 			\arg #PHHAL_HW_CMD_SAMAV3_KDF_CURRENT_KEY_DOUBLE_ENCRYPTION
																		 * 			\arg #PHHAL_HW_CMD_SAMAV3_KDF_CURRENT_KEY_SINGLE_ENCRYPTION
																		 * 			\arg #PHHAL_HW_CMD_SAMAV3_KDF_NEW_KEY_DOUBLE_ENCRYPTION
																		 *			\arg #PHHAL_HW_CMD_SAMAV3_KDF_NEW_KEY_SINGLE_ENCRYPTION
																		 *			\arg #PHHAL_HW_CMD_SAMAV3_KDF_CURRENT_KEY_OFF
																		 *			\arg #PHHAL_HW_CMD_SAMAV3_KDF_CURRENT_KEY_ON
																		 *			\arg #PHHAL_HW_CMD_SAMAV3_KDF_NEW_KEY_OFF
																		 *			\arg #PHHAL_HW_CMD_SAMAV3_KDF_NEW_KEY_ON
																		 *		  \n
																		 * 		  Cryptogram computation mode
																		 * 			\arg #PHHAL_HW_CMD_SAMAV3_CRYPTO_MODE_DIFFERENT_KEY
																		 * 			\arg #PHHAL_HW_CMD_SAMAV3_CRYPTO_MODE_SAME_KEY
																		 */
    uint8_t bConfig,												/**< [In] Options for P2 information byte.
																		 *		  ISO mode to be used.
 																		 *			\arg #PHHAL_HW_CMD_SAMAV3_ISO_MODE_NATIVE
 																		 *  		\arg #PHHAL_HW_CMD_SAMAV3_ISO_MODE_ISO7816
																		 *		  \n
																		 *		  Command Type
																		 * 			\arg #PHHAL_HW_CMD_SAMAV3_CMD_TYPE_CHANGE_KEY
																		 * 			\arg #PHHAL_HW_CMD_SAMAV3_CMD_TYPE_CHANGE_KEY_EV2
																		 *		  \n
																		 * 		  PICC master key update
																		 * 			\arg #PHHAL_HW_CMD_SAMAV3_MASTER_KEY_UPDATE_EXCLUDE_KEYTYPE
																		 * 			\arg #PHHAL_HW_CMD_SAMAV3_MASTER_KEY_UPDATE_INCLUDE_KEYTYPE
																		 *
																		 *		  \n
																		 *		  Number of DESFire PICC key to be changed. This should be present only if
																		 *		  command type is Cmd.ChangeKey.
																		 */
    uint8_t bKeySetNo,												/**< [In] Key set number to which the key to be changed belongs to. */
    uint8_t bDFKeyNo,												/**< [In] Number of DESFire PICC key to be changed. This should be present only if
																		 *		  command type is Cmd.ChangeKeyEV2.
																		 */
    uint8_t bCurrKeyNo,												/**< [In] Reference key number to be used in hardware keystore for CurrentKey. */
    uint8_t bCurrKeyVer,											/**< [In] Reference key version to be used in hardware keystore for CurrentKey. */
    uint8_t bNewKeyNo,												/**< [In] Reference key number to be used in hardware keystore for NewKey. */
    uint8_t bNewKeyVer,												/**< [In] Reference key version to be used in hardware keystore for NewKey. */
    uint8_t *pDivInput,											/**< [In] Diversification Input used to diversify the key. */
    uint8_t bDivInputLen,											/**< [In] Length of diversification input used to diversify the key. */
    uint8_t *pPiccReturnCode										/**< [Out] Error code returned by PICC. This will of 1 byte in length for Native error code and two byte for rest. */
);

/** \name Option macros to update the Crypto configuration information for Cmd.DESFire_WriteX and Cmd.DESFire_ReadX commands. */
/* @{ */
#define PHHAL_HW_CMD_SAMAV3_NATIVE_CHAINING						0x00	/**< Sam DESFire chaining as Native. */
#define PHHAL_HW_CMD_SAMAV3_ISO_CHAINING						0x08	/**< Sam DESFire chaining as ISO. */
#define PHHAL_HW_CMD_SAMAV3_CRYPTO_CONFIG_COMM_MODE_PLAIN		0x00	/**< Sam DESFire communication mode as Plain. */
#define PHHAL_HW_CMD_SAMAV3_CRYPTO_CONFIG_COMM_MODE_MAC			0x10	/**< Sam DESFire communication mode as MAC. */
#define PHHAL_HW_CMD_SAMAV3_CRYPTO_CONFIG_COMM_MODE_FULL		0x30	/**< Sam DESFire communication mode as Full. */
#define PHHAL_HW_CMD_SAMAV3_CRYPTO_CONFIG_DESFIRE_CHAINING		0x00	/**< Sam DESFire chaining mode as DESFire application chaining. */
#define PHHAL_HW_CMD_SAMAV3_CRYPTO_CONFIG_ISO_CHAINING			0x40	/**< Sam DESFire chaining mode as ISO/IEC 14443-4 chaining. */
#define PHHAL_HW_CMD_SAMAV3_CRYPTO_CONFIG_LEGACY_MODE			0x00	/**< Sam DESFire Extended offset mode as legacy mode (Sam AV2). */
#define PHHAL_HW_CMD_SAMAV3_CRYPTO_CONFIG_EXTENDED_OFFSET		0x80	/**< Sam DESFire Extended offset mode as EV2 mode. */
/* @} */

/**
 * \brief Write data to a DESFire encrypted or MACed.
 *
 * \return Status code
 * \retval #PH_ERR_SUCCESS Operation successful.
 * \retval Other Depending on implementation and underlaying component.
 */
phStatus_t phhalHw_SamAV3_Cmd_DESFire_WriteX(
    phhalHw_SamAV3_DataParams_t
    *pDataParams,						/**< [In] Pointer to this layer's parameter structure. */
    uint16_t wOption,												/**< [In] Buffering options.
																		 *        To buffer the data locally use the below flags.
																		 *				\arg #PH_EXCHANGE_DEFAULT
																		 *				\arg #PH_EXCHANGE_BUFFER_FIRST
																		 *				\arg #PH_EXCHANGE_BUFFER_CONT
																		 *				\arg #PH_EXCHANGE_BUFFER_LAST
																		 *		  \n
																		 *        To exchange data in chaining mode use\arg #PH_EXCHANGE_TXCHAINING buffering flag.
																		 */
    uint8_t bCrypto,												/**< [In] Option to set the P2 information byte.
																		 *			Extended offset
																		 *				\arg #PHHAL_HW_CMD_SAMAV3_CRYPTO_CONFIG_LEGACY_MODE
																		 *				\arg #PHHAL_HW_CMD_SAMAV3_CRYPTO_CONFIG_EXTENDED_OFFSET
																		 *			\n
																		 *			Chaining configuration.
																		 *				\arg #PHHAL_HW_CMD_SAMAV3_CRYPTO_CONFIG_DESFIRE_CHAINING
																		 *				\arg #PHHAL_HW_CMD_SAMAV3_CRYPTO_CONFIG_ISO_CHAINING
																		 *			\n
																		 *			Communication Mode.
																		 *				\arg #PHHAL_HW_CMD_SAMAV3_CRYPTO_CONFIG_COMM_MODE_PLAIN
																		 *				\arg #PHHAL_HW_CMD_SAMAV3_CRYPTO_CONFIG_COMM_MODE_MAC
																		 *				\arg #PHHAL_HW_CMD_SAMAV3_CRYPTO_CONFIG_COMM_MODE_FULL
																		 */
    uint8_t *pData,												/**< [In] The data to be written to the DESFire PICC. \n
																		 *			If \arg #PHHAL_HW_CMD_SAMAV3_CRYPTO_CONFIG_LEGACY_MODE, the buffer should contain only the PICC related data.\n
																		 *			If \arg #PHHAL_HW_CMD_SAMAV3_CRYPTO_CONFIG_EXTENDED_OFFSET, the buffer should contain offset followed by the
																		 *																   PICC related data.\n
																		 */
    uint8_t bDataLen,												/**< [In] Length of bytes available in Data buffer. */
    uint8_t *pPiccReturnCode,										/**< [Out] Error code returned by PICC. This will of 1 byte in length for Native error code and two byte for rest. */
    uint8_t *pErrLen												/**< [Out] Length of bytes available in PiccReturnCode buffer. */
);

/**
 * \brief Read data from a DESFire encrypted or MACed.
 *
 * \return Status code
 * \retval #PH_ERR_SUCCESS Operation successful.
 * \retval Other Depending on implementation and underlaying component.
 */
phStatus_t phhalHw_SamAV3_Cmd_DESFire_ReadX(
    phhalHw_SamAV3_DataParams_t
    *pDataParams,						/**< [In] Pointer to this layer's parameter structure. */
    uint16_t wOption,												/**< [In] Buffering options.
																		 *        \arg #PH_EXCHANGE_DEFAULT: To buffer the initial command information. Use this flag to buffer the Length
																		 *		  information also in case of FULL (P2 = 0x30) communication mode and more data
																		 *		  is expected.
																		 *
																		 *        \arg #PH_EXCHANGE_RXCHAINING: To receive data in Native chaining mode.
																		 *        \arg #PH_EXCHANGE_RXCHAINING | #PHHAL_HW_CMD_SAMAV3_ISO_CHAINING: To receive data in ISO chaining mode.																		 */
    uint8_t bCrypto,												/**< [In] Option to set the P2 information byte.
																		 *			Crypto configuration.
																		 *				\arg #PHHAL_HW_CMD_SAMAV3_CRYPTO_CONFIG_COMM_MODE_PLAIN
																		 *				\arg #PHHAL_HW_CMD_SAMAV3_CRYPTO_CONFIG_COMM_MODE_MAC
																		 *				\arg #PHHAL_HW_CMD_SAMAV3_CRYPTO_CONFIG_COMM_MODE_FULL
																		 */
    uint8_t *pAppData,												/**< [In] The following information should be passed. \n
																		 *			\c 3 bytes length information in case if Communication mode is FULL and more
																		 *			   data is expected. \n
																		 *			\c Complete PICC command header and data to be sent to PICC for initial exchange. \n
																		 *			\c DESFire Chaining command code in case more data is expected.
																		 */
    uint8_t bAppDataLen,											/**< [In] Length of bytes available in Data buffer. */
    uint8_t **ppResponse,											/**< [Out] The data received from Sam hardware. */
    uint16_t *pRespLen,											/**< [Out] Length of bytes available in Response buffer. */
    uint8_t *pPiccReturnCode,										/**< [Out] Error code returned by PICC. This will of 1 byte in length for Native error code and two byte for rest. */
    uint8_t *pErrLen												/**< [Out] Length of bytes available in PiccReturnCode buffer. */
);

/**
 * \brief Performs Create Transaction MAC file.
 *
 * \return Status code
 * \retval #PH_ERR_SUCCESS Operation successful.
 * \retval Other Depending on implementation and underlaying component.
 */
phStatus_t phhalHw_SamAV3_Cmd_DESFire_CreateTMFilePICC(
    phhalHw_SamAV3_DataParams_t
    *pDataParams,						/**< [In] Pointer to this layer's parameter structure. */
    uint8_t bOption,												/**< [In] Options for P1 information byte.
																		 *			\arg #PHHAL_HW_CMD_SAMAV3_KEY_DIVERSIFICATION_OFF
																		 *			\arg #PHHAL_HW_CMD_SAMAV3_KEY_DIVERSIFICATION_ON
																		 */
    uint8_t bISOMode,												/**< [In] Options for P2 information byte.
 																		 *			\arg #PHHAL_HW_CMD_SAMAV3_ISO_MODE_NATIVE
 																		 *  		\arg #PHHAL_HW_CMD_SAMAV3_ISO_MODE_ISO7816
																		 */
    uint8_t bKeyNo,													/**< [In] Reference key number to be used in hardware keystore. */
    uint8_t bKeyVer,												/**< [In] Reference key version to be used in hardware keystore. */
    uint8_t bFileNo,												/**< [In] File number of the file to be created. */
    uint8_t bFileOption,											/**< [In] Options for the targeted file.
																		 *			\arg #PHHAL_HW_CMD_SAMAV3_CREATE_TM_FILE_COMM_MODE_PLAIN
																		 *			\arg #PHHAL_HW_CMD_SAMAV3_CREATE_TM_FILE_COMM_MODE_MAC
																		 *			\arg #PHHAL_HW_CMD_SAMAV3_CREATE_TM_FILE_COMM_MODE_FULL
																		 */
    uint8_t *pAccessRights,										/**< [In] Access conditions to be applied for the file. Refer DESFire EV2 datasheet for access
																		 *		  rights information. This should be two bytes long.
																		 */
    uint8_t bTMKeyOptions,											/**< [In] Option for the TransactionMAC Key. #PHHAL_HW_CMD_SAMAV3_CREATE_TM_FILE_AES_KEY is currently
																		 *		  supported option as per DESFireEV2 datasheet.
																		 */
    uint8_t *pDivInput,											/**< [In] Diversification Input used to diversify the key. */
    uint8_t bDivInputLen,											/**< [In] Length of diversification input used to diversify the key. */
    uint8_t *pPiccReturnCode										/**< [Out] Error code returned by PICC. This will of 1 byte in length for Native error code and two byte for rest. */
);

/**
 * end of phhalHw_SamAV3_Cmd_MFD_X
 * @}
 */

/**
 * end of phhalHw_SamAV3_Cmd_MFD
 * @}
 */

/*************************************************************************************************************************/
/************************************************* MIFARE Plus Commands **************************************************/
/*************************************************************************************************************************/

/** \defgroup phhalHw_SamAV3_Cmd_MFP MIFARE Plus
 * \brief SAM commands used for MIFARE Plus PICC communication in X and S Mode.
 * @{
 */

/**
 * \name MIFARE Plus options to update the P1 information byte of Authenticate command. These flags are common for both X
 * and S mode MIFARE Plus Authenticate command.
 */
/** @{ */
#define PHHAL_HW_SAMAV3_MFP_AUTHENTICATE_DIVERSIFICATION_OFF			0x00	/**< Option to disable the key diversification. */
#define PHHAL_HW_SAMAV3_MFP_AUTHENTICATE_DIVERSIFICATION_ON				0x01	/**< Option to enable the key diversification. */
#define PHHAL_HW_SAMAV3_MFP_AUTHENTICATE_FIRST							0x00	/**< Option to perform First authentication. */
#define PHHAL_HW_SAMAV3_MFP_AUTHENTICATE_NON_FIRST						0x02	/**< Option to perform NonFirst (following) authentication. */
#define PHHAL_HW_SAMAV3_MFP_AUTHENTICATE_SL1_NO_KDF						0x00	/**< Option to set the key derivation info for SL0 or SL1 layer. */
#define PHHAL_HW_SAMAV3_MFP_AUTHENTICATE_SL3_KDF						0x0C	/**< Option to set the key derivation info for SL3 layer. */
/** @} */

/**
 * \name MIFARE Plus options to update the P1 information byte of Sector Switch Authenticate command. These flags are common
 * for both X and S mode MIFARE Plus SectorSwitch Authenticate command.
 */
/** @{ */
#define PHHAL_HW_SAMAV3_MFP_SSAUTH_SECTOR_SWITCH_DIV_OFF				0x00	/**< Option to disable the Sector Switch key diversification. */
#define PHHAL_HW_SAMAV3_MFP_SSAUTH_SECTOR_SWITCH_DIV_ON					0x01	/**< Option to enable the Sector Switch key diversification. */
#define PHHAL_HW_SAMAV3_MFP_SSAUTH_SECTOR_DIV_OFF						0x00	/**< Option to disable the Sector key diversification. */
#define PHHAL_HW_SAMAV3_MFP_SSAUTH_SECTOR_DIV_ON						0x02	/**< Option to enable the Sector key diversification. */
#define PHHAL_HW_SAMAV3_MFP_SSAUTH_MASTER_SECTOR_DIV_OFF				0x00	/**< Option to disable the Master Sector key diversification. */
#define PHHAL_HW_SAMAV3_MFP_SSAUTH_MASTER_SECTOR_DIV_ON					0x04	/**< Option to enable the Master Sector key diversification with given sector number. */
#define PHHAL_HW_SAMAV3_MFP_SSAUTH_BUFFER_KEY_BLOCKS					0x10	/**< Option to buffer the KeyBlocks information. */
#define PHHAL_HW_SAMAV3_MFP_SSAUTH_BUFFER_DIV_INPUT						0x20	/**< Option to buffer the Diversification input information. */
/** @} */

/**
 * \name MIFARE Plus options to update the P1 information byte of PDC Authenticate command. These flags are common
 * for both X and S mode MIFARE Plus PDCAuthenticate command.
 */
/** @{ */
#define PHHAL_HW_SAMAV3_PDC_AUTH_DERIVATION_OFF							0x00	/**< Option to disable the key diversification. */
#define PHHAL_HW_SAMAV3_PDC_AUTH_DERIVATION_RFU							0x01    /**< Option to indicate the Key diversification selection as RFU. */
#define PHHAL_HW_SAMAV3_PDC_AUTH_DERIVE_UPGRADE_KEY						0x02    /**< Option to indicate the UpgradeKey derivation form ICUpgradeKey given UpgradeInfo. */
#define PHHAL_HW_SAMAV3_PDC_AUTH_DIVERSIFY_YEAR_UPGRADE_KEY				0x03    /**< Option to indicate the diversification of YearUpgradeKey with the given DivInput
																				 *	 and then derive the actual UpgradeKey with UpgradeInfo.
																				 */
/** @} */

/**
 * \name MIFARE Plus options to update the P1 information byte of ChangeKey command. These flags are common for both X
 * mode MIFARE Plus ChangeKey command.
 */
/** @{ */
#define PHHAL_HW_SAMAV3_MFP_CHANGE_KEY_DIVERSIFICATION_OFF				0x00	/**<  Option to disable the key diversification. */
#define PHHAL_HW_SAMAV3_MFP_CHANGE_KEY_DIVERSIFICATION_ON				0x02	/**<  Option to enable the key diversification. */
/** @} */

/** \defgroup phhalHw_SamAV3_Cmd_MFP_S S Mode
 * \brief SAM commands used for MIFARE Plus PICC communication in S-Mode.
* @{
*/

/**
* \name MIFARE Plus command for SAM AV3 hardware.
*/
/** @{ */
#define PHHAL_HW_SAMAV3_CMD_AUTHENTICATE_MFP_INS					0xA3    /**< CMD Byte for SAM_AuthenticateMFP command */
#define PHHAL_HW_SAMAV3_CMD_AUTH_SECTOR_SWITCH_MFP_INS				0x38    /**< CMD Byte for SAM_AuthSectorSwitchMFP command */
#define PHHAL_HW_SAMAV3_CMD_AUTHENTICATE_PDC_INS					0xAC    /**< CMD Byte for SAM_AuthenticatePDC command */
#define PHHAL_HW_SAMAV3_CMD_COMBINED_READ_MFP_INS					0x33    /**< CMD Byte for SAM_CombinedReadMFP command */
#define PHHAL_HW_SAMAV3_CMD_COMBINED_WRITE_MFP_INS					0x34    /**< CMD Byte for SAM_CombinedWriteMFP command */
#define PHHAL_HW_SAMAV3_CMD_CHANGE_KEY_MFP_INS						0x35    /**< CMD Byte for SAM_ChangeKeyMFP command */
/** @} */

/**
 * \brief Perform a MFP Authenticate command part1. This command will generate a 16 byte random number with the one received from
 * card and return an 32 byte encrypted data which will be sent to card.
 *
 * \return Status code
 * \retval #PH_ERR_SUCCESS_CHAINING successfull chaining operation.
 * \retval Other Depending on implementation and underlaying component.
 */
phStatus_t phhalHw_SamAV3_Cmd_SAM_AuthenticateMFP_Part1(
    phhalHw_SamAV3_DataParams_t
    *pDataParams,								/**< [In] Pointer to this layer's parameter structure. */
    uint8_t bOption,														/**< [In] Option for Authenticate command.
																				 *			\arg #PHHAL_HW_SAMAV3_MFP_AUTHENTICATE_DIVERSIFICATION_OFF
																				 *			\arg #PHHAL_HW_SAMAV3_MFP_AUTHENTICATE_DIVERSIFICATION_ON
																				 *			\arg #PHHAL_HW_SAMAV3_MFP_AUTHENTICATE_FIRST
																				 *			\arg #PHHAL_HW_SAMAV3_MFP_AUTHENTICATE_NON_FIRST
																				 *			\arg #PHHAL_HW_SAMAV3_MFP_AUTHENTICATE_SL1_NO_KDF
																				 *			\arg #PHHAL_HW_SAMAV3_MFP_AUTHENTICATE_SL3_KDF
																				 */
    uint8_t bKeyNo,															/**< [In] Key number to be used from Sam keystore. */
    uint8_t bKeyVer,														/**< [In] Key version to be used from Sam keystore. */
    uint8_t *pPDChal,														/**< [In] Buffer containing the challange generated by the card. */
    uint8_t bPDChalLen,														/**< [In] Length of bytes available in PDChal buffer. */
    uint8_t *pDivInput,													/**< [In] Diversification Input used to diversify the key. */
    uint8_t bDivInputLen,													/**< [In] Length of diversification input used to diversify the key. */
    uint8_t **ppPCDChalResp,												/**< [Out] Buffer containing the PCD challenge response to be sent to card. */
    uint16_t *pPCDChalRespLen												/**< [Out] Length bytes available in PCD challange response buffer. */
);

/**
 * \brief Perform a MFP Authenticate command part2. This command will decrypt the response received from card and will return
 * the PC capabilities and PCD capabilites.
 *
 * \return Status code
 * \retval #PH_ERR_SUCCESS Operation successful.
 * \retval Other Depending on implementation and underlaying component.
 */
phStatus_t phhalHw_SamAV3_Cmd_SAM_AuthenticateMFP_Part2(
    phhalHw_SamAV3_DataParams_t
    *pDataParams,								/**< [In] Pointer to this layer's parameter structure. */
    uint8_t bPiccErrCode,													/**< [In] Error Code sent by the MFP card. For success it should be 0x90. */
    uint8_t *pPDResp,														/**< [In] Buffer containing the input received from card. */
    uint8_t bPDRespLen,														/**< [In] Length of bytes available in PDResp buffer. */
    uint8_t **ppPDCap2,													/**< [Out] Buffer containing the Output PCD capabilities. This will be of 6 bytes. */
    uint8_t **ppPCDCap2,													/**< [Out] Buffer containing the Output PD capabilities. This will be of 6 bytes. */
    uint8_t *pPiccReturnCode												/**< [Out] Error code returned by MIFARE PICC. This will of 1 byte in length. */
);

/**
 * \brief Perform a MFP Sector Switch Authenticate command part1. This command will generate a 16 byte random number with the one received from
 * card and return an 32 byte encrypted data which will be sent to card.
 *
 * \return Status code
 * \retval #PH_ERR_SUCCESS_CHAINING successfull chaining operation.
 * \retval Other Depending on implementation and underlaying component.
 */
phStatus_t phhalHw_SamAV3_Cmd_SAM_AuthSectorSwitchMFP_Part1(
    phhalHw_SamAV3_DataParams_t
    *pDataParams,								/**< [In] Pointer to this layer's parameter structure. */
    uint8_t bOption,														/**< [In] Option to set the P1 information bytes.
																				 *			\arg #PHHAL_HW_SAMAV3_MFP_SSAUTH_SECTOR_SWITCH_DIV_OFF
																				 *			\arg #PHHAL_HW_SAMAV3_MFP_SSAUTH_SECTOR_SWITCH_DIV_ON
																				 *			\arg #PHHAL_HW_SAMAV3_MFP_SSAUTH_SECTOR_DIV_OFF
																				 *			\arg #PHHAL_HW_SAMAV3_MFP_SSAUTH_SECTOR_DIV_ON
																				 *			\arg #PHHAL_HW_SAMAV3_MFP_SSAUTH_MASTER_SECTOR_DIV_OFF
																				 *			\arg #PHHAL_HW_SAMAV3_MFP_SSAUTH_MASTER_SECTOR_DIV_ON
																				 */
    uint8_t *pPDChal,														/**< [In] Buffer containing the challange generated by the card. */
    uint8_t bPDChalLen,														/**< [In] Length of bytes available in PDChal buffer. */
    uint16_t wSSKeyBNr,														/**< [In] PICC Sector Switch key block number to be used for authentication. */
    uint8_t bSSKeyNo,														/**< [In] Key number to be used from Sam keystore. */
    uint8_t bSSKeyVer,														/**< [In] Key version to be used from Sam keystore. */
    uint8_t bMSKeyNo,														/**< [In] Key number to be used from Sam keystore if master sector key in enabled. */
    uint8_t bMSKeyVer,														/**< [In] Key version to be used from Sam keystore if master sector key in enabled. */
    uint8_t bSectorCount,													/**< [In] Number of sectors to be switched inside the PICC. */
    uint8_t *pKeyBlocks,													/**< [In] Buffer containing the PICC KeyB block number and reference key number and
																				 *		  version to be used form Sam keystore. \n
																				 *			\c The format of the buffer should be, \n
																				 *			   KeyBxBNr_1 + KeyNo_1 + KeyVer_1, KeyBxBNr_2 + KeyNo_2 + KeyVer_2, ...,
																				 *			   KeyBxBNr_N + KeyNo_N + KeyVer_N, Where N equal to the SectorCount information.
																				 */
    uint8_t bKeyBlocksLen,													/**< [In] Length of bytes available in KeyBlocks buffer. It should be equal to
																				 *		 (KeyBxBNr + KeyNo + KeyVer) * SectorCount
																				 */
    uint8_t *pDivInput,													/**< [In] Buffer containing the diversification inputs to be used for diversifying the key. \n
																				 *			\c The format of the buffer should be, \n
																				 *			   SSKeyDivLen + SSKeyDivInput + KeyBxDivLen + KeyBxDivInput
																				 */
    uint8_t bDivInputLen,													/**< [In] Length of bytes available in DivInput buffer. */
    uint8_t **ppPCDChalResp,												/**< [Out] Buffer containing the PCD challenge response to be sent to card. */
    uint16_t *pPCDChalRespLen												/**< [Out] Length of PCD challange response. */
);

/**
 * \brief Perform a MFP Sector Switch Authenticate Authenticate command part2. This command will decrypt the response received from
 * card and will return success status if the challanges matches.
 *
 * \return Status code
 * \retval #PH_ERR_SUCCESS Operation successful.
 * \retval Other Depending on implementation and underlaying component.
 */
phStatus_t phhalHw_SamAV3_Cmd_SAM_AuthSectorSwitchMFP_Part2(
    phhalHw_SamAV3_DataParams_t
    *pDataParams, 								/**< [In] Pointer to this layer's parameter structure. */
    uint8_t bPiccErrCode,													/**< [In] Error Code sent by the MFP card. For success it should be 0x90. */
    uint8_t *pPDResp,														/**< [In] Buffer containing the input received from card. */
    uint8_t bPDRespLen,														/**< [In] Length of bytes available in PDResp buffer. */
    uint8_t *pPiccReturnCode												/**< [Out] Error code returned by MIFARE PICC. This will of 1 byte in length. */
);

/**
 * \brief Perform a Post delivery configuration Authenticate command part1. This command will generate a 16 byte random number
 * with the one received from card and return an 32 byte encrypted data which will be sent to card.
 *
 * \return Status code
 * \retval #PH_ERR_SUCCESS_CHAINING successfull chaining operation.
 * \retval Other Depending on implementation and underlaying component.
 */
phStatus_t phhalHw_SamAV3_Cmd_SAM_AuthenticatePDC_Part1(
    phhalHw_SamAV3_DataParams_t
    *pDataParams,								/**< [In] Pointer to this layer's parameter structure. */
    uint8_t bOption,														/**< [In] Option to set the P1 information byte.
																				 *			\arg #PHHAL_HW_SAMAV3_PDC_AUTH_DERIVATION_OFF
																				 *			\arg #PHHAL_HW_SAMAV3_PDC_AUTH_DERIVATION_RFU
																				 *			\arg #PHHAL_HW_SAMAV3_PDC_AUTH_DERIVE_UPGRADE_KEY
																				 *			\arg #PHHAL_HW_SAMAV3_PDC_AUTH_DIVERSIFY_YEAR_UPGRADE_KEY
																				 */
    uint8_t bKeyNo,															/**< [In] Key number to be used from Sam keystore. */
    uint8_t bKeyVer,														/**< [In] Key version to be used from Sam keystore. */
    uint8_t *pPDChal,														/**< [In] Buffer containing the challange generated by the card. */
    uint8_t bPDChalLen,														/**< [In] Length of bytes available in PDChal buffer. */
    uint8_t *pUpgradeInfo,													/**< [In] Upgrade information of the target product state.  */
    uint8_t bLen,															/**< [In] Length of bytes available in UpgradeInfo buffer. */
    uint8_t *pDivInput,													/**< [In] Diversification Input used to diversify the key. */
    uint8_t bDivInputLen,													/**< [In] Length of diversification input used to diversify the key. */
    uint8_t **ppPCDChalResp,												/**< [Out] Buffer containing the PCD challenge response to be sent to card. */
    uint16_t *pPCDChalRespLen												/**< [Out] Length of PCD challange response. */
);

/**
 * \brief Perform a Post delivery configuration Authenticate command part2. This command will decrypt the response received from
 * card and will return success status if the challanges matches.
 *
 * \return Status code
 * \retval #PH_ERR_SUCCESS Operation successful.
 * \retval Other Depending on implementation and underlaying component.
 */
phStatus_t phhalHw_SamAV3_Cmd_SAM_AuthenticatePDC_Part2(
    phhalHw_SamAV3_DataParams_t
    *pDataParams, 								/**< [In] Pointer to this layer's parameter structure. */
    uint8_t bPiccErrCode,													/**< [In] Error Code sent by the MFP card. For success it should be 0x90. */
    uint8_t *pPDResp,														/**< [In] Buffer containing the input received from card. */
    uint8_t bPDRespLen,														/**< [In] Length of bytes available in PDResp buffer. */
    uint8_t *pPiccReturnCode												/**< [Out] Error code returned by MIFARE PICC. This will of 1 byte in length. */
);

/** \name MIFARE Plus options macros for differentiating between command and response for Cmd.SAM_CombinedReadMFP command. */
/** @{ */
#define PHHAL_HW_SAMAV3_OPTION_COMBINED_READ_MFP_COMMAND				0x0000	/**< Option value for Combined Read - Command. */
#define PHHAL_HW_SAMAV3_OPTION_COMBINED_READ_MFP_RESPONSE				0x0001	/**< Option value for Combined Read - Response. */
#define PHHAL_HW_SAMAV3_OPTION_COMBINED_READ_MFP_BOTH					0x0002	/**< Option value for Combined Read - Both Command and Response. */
#define PHHAL_HW_SAMAV3_OPTION_COMBINED_READ_MASK						0x0003	/**< Option mask for Combined Read */
/** @} */

/**
 * \brief Perform a MIFARE Plus Combined Read command. This command is used to perform GetVersion, ReadSignature and all Read
 * related operations.
 *
 * \return Status code
 * \retval #PH_ERR_SUCCESS_CHAINING successfull chaining operation.
 * \retval #PH_ERR_SUCCESS Operation successful.
 * \retval Other Depending on implementation and underlaying component.
 */
phStatus_t phhalHw_SamAV3_Cmd_SAM_CombinedReadMFP(
    phhalHw_SamAV3_DataParams_t
    *pDataParams,								/**< [In] Pointer to this layer's parameter structure. */
    uint8_t bLFI,															/**< [In] Option for updating the P2 information of Sam frame.
																				 *			\arg #PHHAL_HW_SAMAV3_ISO7816_LAST_FRAME
 																				 *			\arg #PHHAL_HW_SAMAV3_ISO7816_CHAINED_FRAME
																				 */
    uint16_t wOption,														/**< [In] Option flag to buffer the payload information.
																				 *			\arg #PH_EXCHANGE_DEFAULT      : Framing the single payload which has all the information.
																				 *			\arg #PH_EXCHANGE_BUFFER_FIRST : For buffering command information and first set of data
																				 *											 information.
																				 *			\arg #PH_EXCHANGE_BUFFER_CONT  : For buffering Intermediate set of data information
																				 *			\arg #PH_EXCHANGE_BUFFER_LAST  : For buffering Final set of data information.
																				 *		  \n
																				 *		  The below flags should be used to switch between command and resposne.
																				 *			\arg #PHHAL_HW_SAMAV3_OPTION_COMBINED_READ_MFP_COMMAND
																				 *			\arg #PHHAL_HW_SAMAV3_OPTION_COMBINED_READ_MFP_RESPONSE
																				 *			\arg #PHHAL_HW_SAMAV3_OPTION_COMBINED_READ_MFP_BOTH
																				 */
    uint8_t *pData,														/**< [In] The data to be sent to Sam hardware. Should be one of the following. \n
																				 *			For Command: \n
																				 *				\c For READxyz  : Read Cmd (1byte) + BNR (2byte) + No.Of Blocks (1byte) \n
																				 *				\c For GetV     : GetVersion command (1byte) \n
																				 *				\c For Read_Sign: Read_Sign Cmd (1byte) + Address (1btye) \n
																				 *			\n
																				 *			For Response: \n
																				 *				\c Maced / Encrypted data \n
																				 *				\c Error Code  \n
																				 *			\n
																				 *			For Command + Response: \n
																				 *				\c READxyU + BNr + No.Of Blocks + RC + Data + MAC (Optional) \n
																				 *				\c RC
																				 */
    uint8_t bDataLen,														/**< [In] Length of bytes available in Data buffer. */
    uint8_t **ppOutput,													/**< [Out] The complete information received from PICC. */
    uint16_t *pOutputLen,													/**< [Out] Length bytes available in Output buffer. */
    uint8_t *pPiccReturnCode												/**< [Out] Error code returned by MIFARE PICC. This will of 1 byte in length. */
);

/** \name MIFARE Plus options macros for differentiating between command and response for Cmd.SAM_CombinedWriteMFP command. */
/** @{ */
#define PHHAL_HW_SAMAV3_OPTION_COMBINED_WRITE_MFP_COMMAND				0x00	/**< Option value for Combined Write - Command. */
#define PHHAL_HW_SAMAV3_OPTION_COMBINED_WRITE_MFP_RESPONSE				0x01	/**< Option mask for Combined Write - Response. */
#define PHHAL_HW_SAMAV3_OPTION_COMBINED_WRITE_MASK						0x01	/**< Option mask for Combined Write */
/** @} */

/** \name MIFARE Plus options macros for specifying the Plain data in response information. */
/** @{ */
#define PHHAL_HW_SAMAV3_OPTION_COMBINED_WRITE_RETURN_PLAIN				0x00	/**< Option macro to return the plain data in response. */
#define PHHAL_HW_SAMAV3_OPTION_COMBINED_WRITE_SKIP_PLAIN				0x02	/**< Option macro to skip the plain data in response. */
#define PHHAL_HW_SAMAV3_OPTION_COMBINED_WRITE_PLIAN_RESPONSE_MASK		0x02	/**< Option mask for Combined Write Plain */
/** @} */

/**
 * \brief Perform a MFP CombinedWrite command. This command is common for Write, WriteValue, Increment, Decrement, IncrementTransfer,
 * DecrementTransfer, Transfer and Restore.
 *
 * \return Status code
 * \retval #PH_ERR_SUCCESS Operation successful.
 * \retval Other Depending on implementation and underlaying component.
 */
phStatus_t phhalHw_SamAV3_Cmd_SAM_CombinedWriteMFP(
    phhalHw_SamAV3_DataParams_t
    *pDataParams,								/**< [In] Pointer to this layer's parameter structure. */
    uint16_t wOption,														/**< [In] Option flag to buffer the payload information.
																				 *			\arg #PH_EXCHANGE_DEFAULT      : Framing the single payload which has all the information.
																				 *			\arg #PH_EXCHANGE_BUFFER_FIRST : For buffering command information and first set of data
																				 *											 information.
																				 *			\arg #PH_EXCHANGE_BUFFER_CONT  : For buffering Intermediate set of data information
																				 *			\arg #PH_EXCHANGE_BUFFER_LAST  : For buffering Final set of data information.
																				 *		  \n
																				 *		  The below flags should be used to switch between command and resposne.
																				 *			\arg #PHHAL_HW_SAMAV3_OPTION_COMBINED_WRITE_MFP_COMMAND
																				 *			\arg #PHHAL_HW_SAMAV3_OPTION_COMBINED_WRITE_MFP_RESPONSE
																				 *		  \n
																				 *		  The below flags should be used to update the Plain data in response.
																				 *			\arg #PHHAL_HW_SAMAV3_OPTION_COMBINED_WRITE_RETURN_PLAIN
																				 *			\arg #PHHAL_HW_SAMAV3_OPTION_COMBINED_WRITE_SKIP_PLAIN
																				 */
    uint8_t *pData,														/**< [In] The data to be sent to Sam hardware. Should be one of the following. \n
																				 *			For Command: \n
																				 *				\c For WRITExy : Write Cmd (1byte) + BNR (2byte) + PlainData (N * 16 bytes) \n
																				 *				\c For INCx    : Inc Cmd (1byte) + BNR (2byte) + PlainData (4bytes) \n
																				 *				\c For DECx    : Dec Cmd (1byte) + BNR (2byte) + PlainData (4bytes) \n
																				 *				\c For INCTx   : Inc Transfer Cmd (1byte) + BNR (4byte) + PlainData (4bytes) \n
																				 *				\c For DECTx   : Dec Transfer Cmd (1byte) + BNR (4byte) + PlainData (4bytes) \n
																				 *				\c For TRFx    : Transfer Cmd (1byte) + BNR (2byte) \n
																				 *				\c For RESx    : Restore Cmd (1byte) + BNR (2byte) \n
																				 *			\n
																				 *			For Response: \n
																				 *				\c RC \n
																				 *				\c RC + MAC \n
																				 *				\c RC + TMC + TMV \n
																				 *				\c RC + TMC + TMV + MAC
																				 */
    uint8_t bDataLen,														/**< [In] Length of bytes available in Data buffer. */
    uint8_t **ppOutput,													/**< [Out] The complete information received from PICC. */
    uint16_t *pOutputLen,													/**< [Out] Length bytes available in Output buffer. */
    uint8_t *pPiccReturnCode												/**< [Out] Error code returned by MIFARE PICC. This will of 1 byte in length. */
);

/** \name MIFARE Plus options macros for differentiating between command and response for Cmd.SAM_ChangeKeyMFP command. */
/** @{ */
#define PHHAL_HW_SAMAV3_OPTION_MFP_CHANGE_KEY_COMMAND					0x00	/**< Option value for ChangeKey - Command. */
#define PHHAL_HW_SAMAV3_OPTION_MFP_CHANGE_KEY_RESPONSE					0x01	/**< Option mask for ChangeKey - Response. */
/** @} */

/**
 * \brief Prepare the MFP Change Key command. This command will return the protected data to be written to card.
 *
 * \return Status code
 * \retval #PH_ERR_SUCCESS Operation successful.
 * \retval Other Depending on implementation and underlaying component.
 */
phStatus_t phhalHw_SamAV3_Cmd_SAM_ChangeKeyMFP(
    phhalHw_SamAV3_DataParams_t
    *pDataParams,  							/**< [In] Pointer to this layer's parameter structure. */
    uint8_t bOption,														/**< [In] The below flags should be for updating the P1 information byte.
																				 *			\arg #PHHAL_HW_SAMAV3_OPTION_MFP_CHANGE_KEY_COMMAND
																				 *			\arg #PHHAL_HW_SAMAV3_OPTION_MFP_CHANGE_KEY_RESPONSE
																				 *			\arg #PHHAL_HW_SAMAV3_MFP_CHANGE_KEY_DIVERSIFICATION_OFF
																				 *			\arg #PHHAL_HW_SAMAV3_MFP_CHANGE_KEY_DIVERSIFICATION_ON
																				 */
    uint8_t *pData,														/**< [In] The information to be exchange to Sam hardware.\n
																				 *			\c For Command : The buffer should contain CmdCode, KeyBNo, KeyNo, KeyVer and DivInput. \n
																				 *			\c For Response: The buffer should contain PICC Status and MAC.
																				 */
    uint8_t bDataLen,														/**< [In] Length of bytes available in Data buffer. */
    uint8_t **ppProtectedData,												/**< [Out] The protected key data from SAM hardware. */
    uint16_t *pProtectedDataLen,											/**< [Out] The length of the protected data. */
    uint8_t *pPiccReturnCode												/**< [Out] Error code returned by MIFARE PICC. This will of 1 byte in length. */
);

/**
 * end of phhalHw_SamAV3_Cmd_MFP_S
 * @}
 */

/** \defgroup phhalHw_SamAV3_Cmd_MFP_X X Mode
 * \brief SAM commands used for MIFARE Plus PICC communication in X-Mode.
 * @{
 */

/** \name MIFARE Plus instruction codes. */
/* @{ */
#define PHHAL_HW_SAMAV3_CMD_MFP_AUTHENTICATE_INS						0x70    /**< Sam AV3 Insturction code for MFP_Authenticate command. */
#define PHHAL_HW_SAMAV3_CMD_MFP_AUTH_SECTOR_SWITCH_INS					0x72    /**< Sam AV3 Insturction code for MFP_AuthentSectorSwitch command. */
#define PHHAL_HW_SAMAV3_CMD_PDC_AUTHENTICATE_INS						0x73    /**< CMD Byte for MFPEV1_AuthenticatePDC command */
#define PHHAL_HW_SAMAV3_CMD_MFP_COMBINED_READ_INS						0x31	/**< Sam AV3 Insturction code for MFP_CombinedRead command. */
#define PHHAL_HW_SAMAV3_CMD_MFP_COMBINED_WRITE_INS						0x32    /**< Sam AV3 Insturction code for MFP_CombinedWrite command. */
#define PHHAL_HW_SAMAV3_CMD_MFP_CHANGE_KEY_INS							0xA5    /**< CMD Byte for MFPEV1_ChangeKey command */
#define PHHAL_HW_SAMAV3_CMD_MFP_WRITE_PERSO_INS							0xA8	/**< Sam AV3 Insturction code for MFP_WritePerso command. */
/* @} */

/**
 * \brief Perform a MIFARE Plus Authenticate command in X mode.
 *
 * \return Status code
 * \retval #PH_ERR_SUCCESS Operation successful.
 * \retval Other Depending on implementation and underlaying component.
 */
phStatus_t phhalHw_SamAV3_Cmd_MFP_Authenticate(
    phhalHw_SamAV3_DataParams_t
    *pDataParams,								/**< [In] Pointer to this layer's parameter structure. */
    uint8_t bOption,														/**< [In] Option for Authenticate command.
																				 *			\arg #PHHAL_HW_SAMAV3_MFP_AUTHENTICATE_DIVERSIFICATION_OFF
																				 *			\arg #PHHAL_HW_SAMAV3_MFP_AUTHENTICATE_DIVERSIFICATION_ON
																				 *			\arg #PHHAL_HW_SAMAV3_MFP_AUTHENTICATE_FIRST
																				 *			\arg #PHHAL_HW_SAMAV3_MFP_AUTHENTICATE_NON_FIRST
																				 *			\arg #PHHAL_HW_SAMAV3_MFP_AUTHENTICATE_SL1_NO_KDF
																				 *			\arg #PHHAL_HW_SAMAV3_MFP_AUTHENTICATE_SL3_KDF
																				 */
    uint8_t bKeyNo,															/**< [In] Key number to be used from Sam keystore. */
    uint8_t bKeyVer,														/**< [In] Key version to be used from Sam keystore. */
    uint16_t wBlockNo,														/**< [In] PICC block number to be used for authentication. */
    uint8_t *pPcdCapsIn,													/**< [In] Buffer containing the input PcdCaps. */
    uint8_t bPcdCapsInLen,													/**< [In] Input PCD capabilites to be exchanged. */
    uint8_t *pDivInput,													/**< [In] Diversification Input used to diversify the key. */
    uint8_t bDivInputLen,													/**< [In] Length of diversification input used to diversify the key. */
    uint8_t *pPcdCapsOut,													/**< [Out] Buffer containing the Output PCD capabilities. This will be of 6 bytes. */
    uint8_t *pPdCaps,														/**< [Out] Buffer containing the Output PD capabilities. This will be of 6 bytes. */
    uint8_t *pPiccReturnCode												/**< [Out] Error code returned by MIFARE PICC. This will of 1 byte in length. */
);

/**
 * \brief Perform a MIFARE Plus Sector Switch Authenticate command in X mode.
 *
 * \return Status code
 * \retval #PH_ERR_SUCCESS Operation successful.
 * \retval Other Depending on implementation and underlaying component.
 */
phStatus_t phhalHw_SamAV3_Cmd_MFP_AuthSectorSwitch(
    phhalHw_SamAV3_DataParams_t
    *pDataParams,								/**< [In] Pointer to this layer's parameter structure. */
    uint16_t wOption,														/**< [In] Option flag to buffer the payload information.
																				 *			\arg #PH_EXCHANGE_DEFAULT      : Framing the single command which has
																				 *											 all the information.
																				 *			\arg #PH_EXCHANGE_BUFFER_FIRST : For framing ISO7816 command header, SSKeyBNr,
																				 *											 SSKeyNo, SSKeyVer, MsKeyNo, MsKeyVer, SectorCount,
																				 *											 KeyBlocks.
																				 *			\arg #PH_EXCHANGE_BUFFER_CONT  : For buffering Intermediate / Final Key Blocks or
																				 *											 First / Intermediate DivInput
																				 *			\arg #PH_EXCHANGE_BUFFER_LAST  : For buffering Final DivInput and exchanging the command.
																				 *			\arg #PHHAL_HW_SAMAV3_MFP_SSAUTH_BUFFER_KEY_BLOCKS
																				 *			\arg #PHHAL_HW_SAMAV3_MFP_SSAUTH_BUFFER_DIV_INPUT
																				 *		  \n
																				 *		  Option to set the P1 information bytes.
																				 *			\arg #PHHAL_HW_SAMAV3_MFP_SSAUTH_SECTOR_SWITCH_DIV_OFF
																				 *			\arg #PHHAL_HW_SAMAV3_MFP_SSAUTH_SECTOR_SWITCH_DIV_ON
																				 *			\arg #PHHAL_HW_SAMAV3_MFP_SSAUTH_SECTOR_DIV_OFF
																				 *			\arg #PHHAL_HW_SAMAV3_MFP_SSAUTH_SECTOR_DIV_ON
																				 *			\arg #PHHAL_HW_SAMAV3_MFP_SSAUTH_MASTER_SECTOR_DIV_OFF
																				 *			\arg #PHHAL_HW_SAMAV3_MFP_SSAUTH_MASTER_SECTOR_DIV_ON
																				 */
    uint16_t wSSKeyBNr,														/**< [In] PICC Sector Switch key block number to be used for authentication. */
    uint8_t bSSKeyNo,														/**< [In] Key number to be used from Sam keystore. */
    uint8_t bSSKeyVer,														/**< [In] Key version to be used from Sam keystore. */
    uint8_t bMSKeyNo,														/**< [In] Key number to be used from Sam keystore if master sector key in enabled. */
    uint8_t bMSKeyVer,														/**< [In] Key version to be used from Sam keystore if master sector key in enabled. */
    uint8_t bSectorCount,													/**< [In] Number of sectors to be switched inside the PICC. */
    uint8_t *pKeyBlocks,													/**< [In] Buffer containing the PICC KeyB block number and reference key number and
																				 *		  version to be used form Sam keystore. \n
																				 *			\c The format of the buffer should be, \n
																				 *			   KeyBxBNr_1 + KeyNo_1 + KeyVer_1, KeyBxBNr_2 + KeyNo_2 + KeyVer_2, ...,
																				 *			   KeyBxBNr_N + KeyNo_N + KeyVer_N, Where N equal to the SectorCount information.
																				 */
    uint8_t bKeyBlocksLen,													/**< [In] Length of bytes available in KeyBlocks buffer. It should be equal to
																				 *		 (KeyBxBNr + KeyNo + KeyVer) * SectorCount
																				 */
    uint8_t *pDivInput,													/**< [In] Buffer containing the diversification inputs to be used for diversifying the key. \n
																				 *			\c The format of the buffer should be, \n
																				 *			   SSKeyDivLen + SSKeyDivInput + KeyBxDivLen + KeyBxDivInput
																				 */
    uint8_t bDivInputLen,													/**< [In] Length of bytes available in DivInput buffer. */
    uint8_t *pPiccReturnCode												/**< [Out] Error code returned by MIFARE PICC. This will of 1 byte in length. */
);

/**
 * \brief Perform a MIFARE Plus Post Delivery configuration Authenticate command in X mode.
 *
 * \return Status code
 * \retval #PH_ERR_SUCCESS Operation successful.
 * \retval Other Depending on implementation and underlaying component.
 */
phStatus_t phhalHw_SamAV3_Cmd_PDC_Authenticate(
    phhalHw_SamAV3_DataParams_t
    *pDataParams,								/**< [In] Pointer to this layer's parameter structure. */
    uint8_t bOption,														/**< [In] Option to set the P1 information byte.
																				 *			\arg #PHHAL_HW_SAMAV3_PDC_AUTH_DERIVATION_OFF
																				 *			\arg #PHHAL_HW_SAMAV3_PDC_AUTH_DERIVATION_RFU
																				 *			\arg #PHHAL_HW_SAMAV3_PDC_AUTH_DERIVE_UPGRADE_KEY
																				 *			\arg #PHHAL_HW_SAMAV3_PDC_AUTH_DIVERSIFY_YEAR_UPGRADE_KEY
																				 */
    uint8_t bKeyNo,															/**< [In] Key number to be used from Sam keystore. */
    uint8_t bKeyVer,														/**< [In] Key version to be used from Sam keystore. */
    uint16_t wUpgradeKey,													/**< [In] PICC UpgradeKey to be used for authentication. */
    uint8_t *pUpgradeInfo,													/**< [In] Upgrade information of the target product state.  */
    uint8_t bLen,															/**< [In] Length of bytes available in UpgradeInfo buffer. */
    uint8_t *pDivInput,													/**< [In] Diversification Input used to diversify the key. */
    uint8_t bDivInputLen,													/**< [In] Length of diversification input used to diversify the key. */
    uint8_t *pPiccReturnCode												/**< [Out] Error code returned by MIFARE PICC. This will of 1 byte in length. */
);

/**
 * \brief Perform a MIFARE Plus Combined Read command in X mode. This command is used to perform GetVersion, ReadSignature and all Read
 * related operations.
 *
 * \return Status code
 * \retval #PH_ERR_SUCCESS_CHAINING successfull chaining operation.
 * \retval #PH_ERR_SUCCESS Operation successful.
 * \retval Other Depending on implementation and underlaying component.
 */
phStatus_t phhalHw_SamAV3_Cmd_MFP_CombinedRead(
    phhalHw_SamAV3_DataParams_t
    *pDataParams,								/**< [In] Pointer to this layer's parameter structure. */
    uint16_t wOption,														/**< [In] Option for receiving the next data chunk if previous status was chaining.
																				 *         \arg #PH_EXCHANGE_DEFAULT   : To exchange the MifarePlus PICC commands.
																				 *         \arg #PH_EXCHANGE_RXCHAINING: The next set of data will be received.
																				 */
    uint8_t *pReadCmd,														/**< [In] The different types of command to be sent. \n
																				 *			\c GetVersion: GetVersion cmd (1byte) \n
																				 *			\c ReadSig   : Read Signature cmd (1byte) + Address (1byte) \n
																				 *			\c Read      : Read cmd (1byte) + BlockNr (2byte) + NoBlocks (1byte) \n
																				 */
    uint8_t bReadCmdLen,													/**< [In] Length of bytes available in ReadCmd buffer. */
    uint8_t **ppData,														/**< [Out] The information returned by Sam hardware for the mentioned command in ReadCmd buffer. */
    uint16_t *pDataLen,													/**< [Out] Length of bytes available in Data buffer. */
    uint8_t *pPiccReturnCode												/**< [Out] Error code returned by MIFARE PICC. This will of 1 byte in length. */
);

/**
 * \brief Perform a MIFARE Plus Combined Write command in X mode. This command performs Write, Increment, Decrement, Transfer,
 * Restore, IncrementTransfer and DecrementTransfer commands of the PICC.
 *
 * \return Status code
 * \retval #PH_ERR_SUCCESS Operation successful.
 * \retval Other Depending on implementation and underlaying component.
 */
phStatus_t phhalHw_SamAV3_Cmd_MFP_CombinedWrite(
    phhalHw_SamAV3_DataParams_t
    *pDataParams,								/**< [In] Pointer to this layer's parameter structure. */
    uint16_t wOption,														/**< [In] Option flag to buffer the payload information.
																				 *			\arg #PH_EXCHANGE_DEFAULT
																				 *			\arg #PH_EXCHANGE_BUFFER_FIRST
																				 *			\arg #PH_EXCHANGE_BUFFER_CONT
																				 *			\arg #PH_EXCHANGE_BUFFER_LAST
																				 */
    uint8_t *pData,														/**< [In] The data to be sent to Sam hardware. Should be one of the following. \n
																				 *			\c For WRITExy : Write Cmd (1byte) + BNR (2byte) + PlainData (N * 16 bytes) \n
																				 *			\c For INCx    : Inc Cmd (1byte) + BNR (2byte) + PlainData (4bytes) \n
																				 *			\c For DECx    : Dec Cmd (1byte) + BNR (2byte) + PlainData (4bytes) \n
																				 *			\c For INCTx   : Inc Transfer Cmd (1byte) + BNR (4byte) + PlainData (4bytes) \n
																				 *			\c For DECTx   : Dec Transfer Cmd (1byte) + BNR (4byte) + PlainData (4bytes) \n
																				 *			\c For TRFx    : Transfer Cmd (1byte) + BNR (2byte) \n
																				 *			\c For RESx    : Restore Cmd (1byte) + BNR (2byte) \n
																				 */
    uint8_t bDataLen,														/**< [In] Length of bytes available in Data buffer. */
    uint8_t *pTMC,															/**< [Out] Only available is the block is a TMProtected block. The buffer will have 4
																				 *		   bytes of Transaction MAC counter information. */
    uint8_t *pTMV,															/**< [Out] Only available is the block is a TMProtected block. The buffer will have 8
																				 *		   bytes of Transaction MAC value. */
    uint8_t *pPiccReturnCode												/**< [Out] Error code returned by MIFARE PICC. This will of 1 byte in length. */
);

/**
 * \brief Perform a MIFARE Plus Change Key command in X mode.
 *
 * \return Status code
 * \retval #PH_ERR_SUCCESS Operation successful.
 * \retval Other Depending on implementation and underlaying component.
 */
phStatus_t phhalHw_SamAV3_Cmd_MFP_ChangeKey(
    phhalHw_SamAV3_DataParams_t
    *pDataParams,								/**< [In] Pointer to this layer's parameter structure. */
    uint8_t bOption,														/**< [In] Option flag to update the P1 information byte.
																				 *			\arg #PHHAL_HW_SAMAV3_MFP_CHANGE_KEY_DIVERSIFICATION_OFF
																				 *			\arg #PHHAL_HW_SAMAV3_MFP_CHANGE_KEY_DIVERSIFICATION_ON
																				 */
    uint8_t bCmdCode,														/**< [In] The write comamnd code to be used for writting the key. (0xA0 or 0xA1) */
    uint16_t wBlockNo,														/**< [In] PICC block number to be used for changing the key.  */
    uint8_t bKeyNo,															/**< [In] Key number to be used from Sam keystore. */
    uint8_t bKeyVer,														/**< [In] Key version to be used from Sam keystore. */
    uint8_t *pDivInput,													/**< [In] Diversification Input used to diversify the key. */
    uint8_t bDivInputLen,													/**< [In] Length of diversification input used to diversify the key. */
    uint8_t *pPiccReturnCode												/**< [Out] Error code returned by MIFARE PICC. This will of 1 byte in length. */
);

/**
 * \brief Perform a MIFARE Plus Write Perso command in X mode.
 *
 * \return Status code
 * \retval #PH_ERR_SUCCESS Operation successful.
 * \retval Other Depending on implementation and underlaying component.
 */
phStatus_t phhalHw_SamAV3_Cmd_MFP_WritePerso(
    phhalHw_SamAV3_DataParams_t
    *pDataParams,								/**< [In] Pointer to this layer's parameter structure. */
    uint16_t wOption,														/**< [In] Option flag to buffer the payload information.
																				 *			\arg #PH_EXCHANGE_DEFAULT
																				 *			\arg #PH_EXCHANGE_BUFFER_FIRST
																				 *			\arg #PH_EXCHANGE_BUFFER_CONT
																				 *			\arg #PH_EXCHANGE_BUFFER_LAST
																				 */
    uint8_t *pBlocks,														/**< [In] Buffer containing the Block and Data pair to be written to card by Sam hardware. \n
																				 *        Should be holding an array of block number and data like
																				 *		  BNR_1 + Data, BNR_2 + Data, BNR_3 + Data, ..., BNR_N + Data \n
																				 *		  BNR_x should be 2 bytes and Data should 16 bytes.
																				 */
    uint8_t bBlocksLen,														/**< [In] Length representing the block and data pair available in pBlocks parameter. */
    uint8_t *pPiccReturnCode												/**< [Out] Error code returned by MIFARE PICC. This will of 1 byte in length. */
);

/**
 * end of phhalHw_SamAV3_Cmd_MFP_X
 * @}
 */

/**
 * end of phhalHw_SamAV3_Cmd_MFP
 * @}
 */

/*************************************************************************************************************************/
/**************************************************** MIFARE Classic *****************************************************/
/*************************************************************************************************************************/

#define PHHAL_HW_SAMAV3_CMD_CHANGE_KEY_MIFARE_DIV_MASK					0x06	/**< Macro to mask the diversification bits. */
#define PHHAL_HW_SAMAV3_CMD_CHANGE_KEY_MIFARE_CRYPTO_MASK				0x01	/**< Macro to mask the crypto bits. */

/** \defgroup phhalHw_SamAV3_Cmd_MFC MIFARE Classic
 * \brief SAM commands use for MIFARE Classic PICC communication in X and Non-X mode.
 * @{
 */

/** \name Option macros for Sam AV3 MIFARE Authentication key diversification. */
/* @{ */
#define PHHAL_HW_SAMAV3_CMD_AUTHENTICATE_MIFARE_DIV_OFF					0x00	/**< Option mask to disable the exchange of diversification block number. */
#define PHHAL_HW_SAMAV3_CMD_AUTHENTICATE_MIFARE_DIV_ON					0x01	/**< Option mask to enable the exchange of diversification block number. */
/* @} */

/** \name Option macros for Sam AV3 MIFARE Change Key diversification. */
/* @{ */
#define PHHAL_HW_SAMAV3_CMD_CHANGE_KEY_MIFARE_DIV_OFF					0x00	/**< Option mask to disable diverification of key A and B. */
#define PHHAL_HW_SAMAV3_CMD_CHANGE_KEY_MIFARE_DIV_A_OFF					0x00	/**< Option mask to disable diverification of key A. */
#define PHHAL_HW_SAMAV3_CMD_CHANGE_KEY_MIFARE_DIV_A_ON					0x02	/**< Option mask to enable diverification of key A. */
#define PHHAL_HW_SAMAV3_CMD_CHANGE_KEY_MIFARE_DIV_B_OFF					0x00	/**< Option mask to disable diverification of key B. */
#define PHHAL_HW_SAMAV3_CMD_CHANGE_KEY_MIFARE_DIV_B_ON					0x04	/**< Option mask to enable diverification of key B. */
/* @} */

/** \defgroup phhalHw_SamAV3_Cmd_MFC_S S Mode
 * \brief SAM commands used for MIFARE Classic S communication
 * @{
 */

/** \name Sam AV3 command code for MIFARE Classic NonX features. */
/* @{ */
#define PHHAL_HW_SAMAV3_CMD_SAM_AUTHENTICATE_MIFARE_INS					0x1C	/**< Sam AV3 Instruction code for Cmd.SAM_AuthenticateMifare command. */
#define PHHAL_HW_SAMAV3_CMD_SAM_CHANGE_KEY_MIFARE_INS					0xC5	/**< Sam AV3 Instruction code for Cmd.SAM_ChangeKeyMIFARE command. */
/* @} */

#define PHHAL_HW_SAMAV3_CMD_SAM_AUTH_MIFARE_LC_MIN						13U		/**< Minimun Length of LC data for SAM_AuthenticateMifare command. */
#define PHHAL_HW_SAMAV3_CMD_SAM_CHANGE_KEY_MIFARE_DUMP_CMD_SIZE			13U		/**< Macro to represent the SAM_ChangeKeyMIFAREDump command size. */
#define PHHAL_HW_SAMAV3_CMD_SAM_CHANGE_KEY_MIFARE_DUMP_LC_MIN			3U		/**< Minimun Length of LC data for SAM_ChangeKeyMIFAREDump command. */

/**
 * \brief Performs the MIFARE Classic authentication in S mode. This interfaces exchanges the first
 * part of random challange received from PICC to Sam hardware.
 *
 * \return Status code
 * \retval #PH_ERR_SUCCESS_CHAINING Operation successful, chaining ongoing.
 * \retval Other Depending on implementation and underlaying component.
 */
phStatus_t phhalHw_SamAV3_Cmd_SAM_AuthenticateMIFARE_Part1(
    phhalHw_SamAV3_DataParams_t
    *pDataParams,								/**< [In] Pointer to this layer's parameter structure. */
    uint8_t bOption,														/**< [In] Specify whether diversification block number should be exchanged or not.
																				 *			\arg #PHHAL_HW_SAMAV3_CMD_AUTHENTICATE_MIFARE_DIV_OFF
																				 *			\arg #PHHAL_HW_SAMAV3_CMD_AUTHENTICATE_MIFARE_DIV_ON
																				 */
    uint8_t *pMFUID,														/**< [In] MIFARE classic UID. Here the last four bytes of the UID should be passed regardless of 4 or 7 byte UID. */
    uint8_t bKeyNo,															/**< [In] Key number of MIFARE key available in Sam keystore. */
    uint8_t bKeyVer,														/**< [In] Key Version of MIFARE key available in Sam keystore. */
    uint8_t bKeyType,														/**< [In] Type of key to be used.
																				 *			\arg #PHHAL_HW_MFC_KEYA
																				 *			\arg #PHHAL_HW_MFC_KEYB
																				 */
    uint8_t bMFBlockNo,														/**< [In] MIFARE block number used for authentication. */
    uint8_t bDivBlockNo,													/**< [In] Block number to be used for Key diversification in Sam. */
    uint8_t *pNumberRB,													/**< [In] Should have the 5bytes (4 bytes of Rnd + 1 byte of Parity) of information (Token RB) returned by PICC. */
    uint8_t bNumRBLen,														/**< [In] Length of Number RB returned by PICC. */
    uint8_t **ppEncToken,													/**< [Out] The encrypted (Token	AB) information to be send to PICC. This will have 9 bytes (8 bytes of encrypted
																				 *		   information + 1 byte of Parity)
																				 */
    uint16_t *pEncTokenLen													/**< [Out] Length of encrypted token returned. */
);

/**
 * \brief Performs the MIFARE Classic authentication in S mode. This interfaces exchanges the second
 * part of random challange received from PICC to Sam hardware.
 *
 * \return Status code
 * \retval #PH_ERR_SUCCESS Operation successful.
 * \retval Other Depending on implementation and underlaying component.
 */
phStatus_t phhalHw_SamAV3_Cmd_SAM_AuthenticateMIFARE_Part2(
    phhalHw_SamAV3_DataParams_t
    *pDataParams,								/**< [In] Pointer to this layer's parameter structure. */
    uint8_t *pEncToken,													/**< [In] Should have the 5bytes (4 bytes of Rnd + 1 byte of Parity) of information (Token BA) returned by PICC. */
    uint8_t bEncTokenLen													/**< [In] Length of Enc token returned by PICC. */
);

/**
 * \brief Performs the MIFARE Classic key change in S mode.
 *
 * \return Status code
 * \retval #PH_ERR_SUCCESS Operation successful.
 * \retval Other Depending on implementation and underlaying component.
 */
phStatus_t phhalHw_SamAV3_Cmd_SAM_ChangeKeyMIFARE(
    phhalHw_SamAV3_DataParams_t
    *pDataParams,								/**< [In] Pointer to this layer's parameter structure. */
    uint8_t bOption,														/**< [In] Specify whether diversification block number and UID should be exchanged or not.
																				 *			\arg #PHHAL_HW_SAMAV3_CMD_CHANGE_KEY_MIFARE_DIV_OFF
																				 *			\arg #PHHAL_HW_SAMAV3_CMD_CHANGE_KEY_MIFARE_DIV_A_OFF
																				 *			\arg #PHHAL_HW_SAMAV3_CMD_CHANGE_KEY_MIFARE_DIV_A_ON
																				 *			\arg #PHHAL_HW_SAMAV3_CMD_CHANGE_KEY_MIFARE_DIV_B_OFF
																				 *			\arg #PHHAL_HW_SAMAV3_CMD_CHANGE_KEY_MIFARE_DIV_B_ON
																				 */
    uint8_t bKeyNo,															/**< [In] Key number of MIFARE key available in Sam keystore. */
    uint8_t bKeyVerA,														/**< [In] Key Version of MIFARE key A available in Sam keystore. */
    uint8_t bKeyVerB,														/**< [In] Key Version of MIFARE key B available in Sam keystore. */
    uint8_t *pAccCond,														/**< [In] MIFARE classic access conditions. */
    uint8_t *pMFUID,														/**< [In] MIFARE classic UID. Here the last four bytes of the UID should be passed regardless of 4 or 7 byte UID. */
    uint8_t bDivBlockNo,													/**< [In] Block number to be used for Key diversification in Sam. */
    uint8_t **ppProtData,													/**< [Out] The protected information to be sent to PICC. */
    uint16_t *pProtDataLen													/**< [Out] Length of protected information returned. */
);

/** \name Option macros for Sam AV3 MIFARE Change Key Crypto. */
/* @{ */
#define PHHAL_HW_SAMAV3_CMD_CHANGE_KEY_MIFARE_PLAIN						0x00	/**< Option mask to disable the encryption of SecretKey given by SAM. */
#define PHHAL_HW_SAMAV3_CMD_CHANGE_KEY_MIFARE_ENCRYPT					0x01	/**< Option mask to enable the encryption of SecretKey given by SAM. */
/* @} */

/**
 * \brief Performs the MIFARE Classic key dump in S mode.
 *
 * \return Status code
 * \retval #PH_ERR_SUCCESS Operation successful.
 * \retval Other Depending on implementation and underlaying component.
 */
phStatus_t phhalHw_SamAV3_Cmd_SAM_ChangeKeyMIFAREDump(
    phhalHw_SamAV3_DataParams_t
    *pDataParams,								/**< [In] Pointer to this layer's parameter structure. */
    uint8_t bOption,														/**< [In] Specify whether diversification block number and UID should be exchanged or not.
																				 *			\arg #PHHAL_HW_SAMAV3_CMD_CHANGE_KEY_MIFARE_PLAIN
																				 *			\arg #PHHAL_HW_SAMAV3_CMD_CHANGE_KEY_MIFARE_ENCRYPT
																				 *			\arg #PHHAL_HW_SAMAV3_CMD_CHANGE_KEY_MIFARE_DIV_OFF
																				 *			\arg #PHHAL_HW_SAMAV3_CMD_CHANGE_KEY_MIFARE_DIV_A_OFF
																				 *			\arg #PHHAL_HW_SAMAV3_CMD_CHANGE_KEY_MIFARE_DIV_A_ON
																				 *			\arg #PHHAL_HW_SAMAV3_CMD_CHANGE_KEY_MIFARE_DIV_B_OFF
																				 *			\arg #PHHAL_HW_SAMAV3_CMD_CHANGE_KEY_MIFARE_DIV_B_ON
																				 */
    uint8_t bKeyNo,															/**< [In] Key number of MIFARE key available in Sam keystore. */
    uint8_t bKeyVer,														/**< [In] Key Version of MIFARE key available in Sam keystore. */
    uint8_t bKeyType,														/**< [In] Key Version of MIFARE key B available in Sam keystore. Type of key to be used.
																				 *			\arg #PHHAL_HW_MFC_KEYA
																				 *			\arg #PHHAL_HW_MFC_KEYB
																				 */
    uint8_t *pMFUID,														/**< [In] MIFARE classic UID. Here the last four bytes of the UID should be passed regardless of 4 or 7 byte UID. */
    uint8_t bDivBlockNo,													/**< [In] Block number to be used for Key diversification in Sam. */
    uint8_t **ppSecretKey,													/**< [Out] The Secret key information to be sent to PICC. */
    uint16_t *pSecretKeyLen												/**< [Out] Length of Secret key information returned. */
);

/**
 * end of phhalHw_SamAV3_Cmd_MFC_S
 * @}
 */

/** \defgroup phhalHw_SamAV3_Cmd_MFC_X X Mode
 * \brief SAM commands used for MIFARE Classic X communication
 * @{
 */

/** \name Sam AV3 command code for MIFARE Classic X features. */
/* @{ */
#define PHHAL_HW_SAMAV3_CMD_MF_AUTHENTICATE_INS							0x0C	/**< Sam AV3 Instruction code for Cmd.MF_Authenticate command. */
#define PHHAL_HW_SAMAV3_CMD_MF_READ_INS									0x30	/**< Sam AV3 Instruction code for Cmd.MF_Read command. */
#define PHHAL_HW_SAMAV3_CMD_MF_WRITE_INS								0xA0	/**< Sam AV3 Instruction code for Cmd.MF_Write command. */
#define PHHAL_HW_SAMAV3_CMD_MF_VALUE_WRITE_INS							0xA2	/**< Sam AV3 Instruction code for Cmd.MF_ValueWtire command. */
#define PHHAL_HW_SAMAV3_CMD_MF_INCREMENT_INS							0xC3	/**< Sam AV3 Instruction code for Cmd.MF_Increment command. */
#define PHHAL_HW_SAMAV3_CMD_MF_DECREMENT_INS							0xC0	/**< Sam AV3 Instruction code for Cmd.MF_Decrement command. */
#define PHHAL_HW_SAMAV3_CMD_MF_RESTORE_INS								0xC2	/**< Sam AV3 Instruction code for Cmd.MF_Restore command. */
#define PHHAL_HW_SAMAV3_CMD_MF_AUTHENTICATED_READ_INS					0x3A	/**< Sam AV3 Instruction code for Cmd.MF_AuthenticatedRead command. */
#define PHHAL_HW_SAMAV3_CMD_MF_AUTHENTICATED_WRITE_INS					0xAA	/**< Sam AV3 Instruction code for Cmd.MF_AuthenticatedWrite command. */
#define PHHAL_HW_SAMAV3_CMD_MF_CHANGE_KEY_INS							0xA1	/**< Sam AV3 Instruction code for Cmd.MF_ChangeKey command. */
/* @} */

/**
 * \brief Perform a MIFARE Classic Authenticate command in X mode.
 *
 * \return Status code
 * \retval #PH_ERR_SUCCESS Operation successful.
 * \retval Other Depending on implementation and underlaying component.
 */
phStatus_t phhalHw_SamAV3_Cmd_MF_Authenticate(
    phhalHw_SamAV3_DataParams_t
    *pDataParams,								/**< [In] Pointer to this layer's parameter structure. */
    uint8_t bOption,														/**< [In] Specify whether diversification block number should be exchanged or not.
																				 *			\arg #PHHAL_HW_SAMAV3_CMD_AUTHENTICATE_MIFARE_DIV_OFF
																				 *			\arg #PHHAL_HW_SAMAV3_CMD_AUTHENTICATE_MIFARE_DIV_ON
																				 */
    uint8_t *pMFUID,														/**< [In] MIFARE classic UID. Here the last four bytes of the UID should be passed regardless of 4 or 7 byte UID. */
    uint8_t bKeyNo,															/**< [In] Key number of MIFARE key available in Sam keystore. */
    uint8_t bKeyVer,														/**< [In] Key Version of MIFARE key available in Sam keystore. */
    uint8_t bKeyType,														/**< [In] Type of key to be used.
																				 *			\arg #PHHAL_HW_MFC_KEYA
																				 *			\arg #PHHAL_HW_MFC_KEYB
																				 */
    uint8_t bMFBlockNo,														/**< [In] MIFARE block number used for authentication. */
    uint8_t bDivBlockNo														/**< [In] Block number to be used for Key diversification in Sam. */
);

/**
 * \brief Perform a MIFARE Classic Read command in X mode.
 *
 * \return Status code
 * \retval #PH_ERR_SUCCESS Operation successful.
 * \retval Other Depending on implementation and underlaying component.
 */
phStatus_t phhalHw_SamAV3_Cmd_MF_Read(
    phhalHw_SamAV3_DataParams_t
    *pDataParams,								/**< [In] Pointer to this layer's parameter structure. */
    uint8_t *pBlocks,														/**< [In] The block numbers from where the data should be read. \n
																				 *         Should be holding an array of block numbers like \n
																				 *		   BNR_1, BNR_2, BNR_3, ..., BNR_N
																				 */
    uint8_t bBlocksLen,														/**< [In] Length representing the blocks available in pBlocks parameter. */
    uint8_t **ppData,														/**< [Out] Data returned by Sam hardware. */
    uint16_t *pDataLen														/**< [Out] Amount of valid bytes returned by Sam hardware. */
);

/** \name Option macros for Sam AV3 MIFARE Classic Write command in X mode communication. */
/* @{ */
#define PHHAL_HW_SAMAV3_CMD_MF_WRITE_CLASSIC							0x00	/**< Option mask for writting data to MIFARE Classic product. */
#define PHHAL_HW_SAMAV3_CMD_MF_WRITE_ULTRALIGHT							0x01	/**< Option mask for writting data to MIFARE Ultralight product. */
#define PHHAL_HW_SAMAV3_CMD_MF_WRITE_TMDATA_NOT_RETURNED				0x00	/**< Option mask for not exchanging the LE byte to SAM. */
#define PHHAL_HW_SAMAV3_CMD_MF_WRITE_TMDATA_RETURNED					0x80	/**< Option mask for exchanging the LE byte to SAM for retrieval of TMC and TMV information. */
/* @} */

/**
 * \brief Perform a MIFARE Classic Write command in X mode.
 *
 * \return Status code
 * \retval #PH_ERR_SUCCESS Operation successful.
 * \retval Other Depending on implementation and underlaying component.
 */
phStatus_t phhalHw_SamAV3_Cmd_MF_Write(
    phhalHw_SamAV3_DataParams_t
    *pDataParams,								/**< [In] Pointer to this layer's parameter structure. */
    uint8_t bOption,														/**< [In] One of the below options. \n
																				 *			For Updating the P1 information byte.
																				 *          \arg #PHHAL_HW_SAMAV3_CMD_MF_WRITE_CLASSIC
																				 *          \arg #PHHAL_HW_SAMAV3_CMD_MF_WRITE_ULTRALIGHT
																				 *		  \n
																				 *			For exchanging the LE byte. To be ored with above options
																				 *          \arg #PHHAL_HW_SAMAV3_CMD_MF_WRITE_TMDATA_NOT_RETURNED
																				 *          \arg #PHHAL_HW_SAMAV3_CMD_MF_WRITE_TMDATA_RETURNED
																				 */
    uint8_t *pData,														/**< [In] Buffer containing the Block and Data pair to be written to card by Sam hardware. \n
																				 *        Should be holding an array of block number and data like
																				 *		  BNR_1 + Data, BNR_2 + Data, BNR_3 + Data, ..., BNR_N + Data \n
																				 *		  Data could be 4 bytes or 16 bytes depending on the option specified.
																				 */
    uint8_t bDataLen,														/**< [In] Length representing the block and data pair available in pBlocks parameter. */
    uint8_t **ppTMData,													/**< [Out] The Transaction Mac Value and Counter of each block returned by MIFARE Classic PICC if \n
																				 *		  its a TMProtected block. Null in case of Ultralight or not a TMProtected block in case \n
																				 *		  of Classic.
																		 		 */
    uint16_t *pTMDataLen													/**< [Out] Amount of valid bytes returned by Sam hardware. */
);

/** \name Option macros for Sam AV3 MIFARE Classic ValueWrite command in X mode communication. */
/* @{ */
#define PHHAL_HW_SAMAV3_CMD_MF_VALUE_WRITE_TMDATA_NOT_RETURNED			0x00	/**< Option mask for not exchanging the LE byte to SAM. */
#define PHHAL_HW_SAMAV3_CMD_MF_VALUE_WRITE_TMDATA_RETURNED				0x80	/**< Option mask for exchanging the LE byte to SAM for retrieval of TMC and TMV information. */
/* @} */

/**
 * \brief Perform a MIFARE Classic Write Value command in X mode.
 *
 * \return Status code
 * \retval #PH_ERR_SUCCESS Operation successful.
 * \retval Other Depending on implementation and underlaying component.
 */
phStatus_t phhalHw_SamAV3_Cmd_MF_ValueWrite(
    phhalHw_SamAV3_DataParams_t
    *pDataParams,								/**< [In] Pointer to this layer's parameter structure. */
    uint8_t bOption,														/**< [In] For exchanging the LE byte.
																				 *          \arg #PHHAL_HW_SAMAV3_CMD_MF_VALUE_WRITE_TMDATA_NOT_RETURNED
																				 *          \arg #PHHAL_HW_SAMAV3_CMD_MF_VALUE_WRITE_TMDATA_RETURNED
																				 */
    uint8_t *pBlocks,														/**< [In] Buffer containing the Block, Value and Address pair to be written to card by Sam hardware. \n
																				 *        Should be holding an array of block number, value and address like \n
																				 *		  BNR_1 + Value + Address, BNR_2 + Value + Address, ..., BNR_N + Value + Address
																				 */
    uint8_t bBlocksLen,														/**< [In] Length of the pBlocks buffer. */
    uint8_t **ppTMData,													/**< [Out] The Transaction Mac Value and Counter of each block returned by MIFARE Classic PICC if \n
																				 *		  its a TMProtected block. Null in case of not a TMProtected block.
																				 */
    uint16_t *pTMDataLen													/**< [Out] Amount of valid bytes returned by Sam hardware. */
);

/** \name Option macros for Sam AV3 MIFARE Classic Increment command in X mode communication. */
/* @{ */
#define PHHAL_HW_SAMAV3_CMD_MF_INCREMENT_TMDATA_NOT_RETURNED			0x00	/**< Option mask for not exchanging the LE byte to SAM. */
#define PHHAL_HW_SAMAV3_CMD_MF_INCREMENT_TMDATA_RETURNED				0x80	/**< Option mask for exchanging the LE byte to SAM for retrieval of TMC and TMV information. */
/* @} */

/**
 * \brief Perform a MIFARE Classic Increment command in X mode.
 * \return Status code
 * \retval #PH_ERR_SUCCESS Operation successful.
 * \retval Other Depending on implementation and underlaying component.
 */
phStatus_t phhalHw_SamAV3_Cmd_MF_Increment(
    phhalHw_SamAV3_DataParams_t
    *pDataParams,								/**< [In] Pointer to this layer's parameter structure. */
    uint8_t bOption,														/**< [In] For exchanging the LE byte.
																				 *          \arg #PHHAL_HW_SAMAV3_CMD_MF_INCREMENT_TMDATA_NOT_RETURNED
																				 *          \arg #PHHAL_HW_SAMAV3_CMD_MF_INCREMENT_TMDATA_RETURNED
																				 */
    uint8_t *pBlocks,														/**< [In] Buffer containing the Source Block, Destination Block and Value pair to be \n
																				 *		  written to card by Sam hardware. Should be holding an array of source block number, \n
																				 *        destination block number and value like \n
																				 *		  SRC_BNR_1 + DST_BNR_1 + Value, SRC_BNR_2 + DST_BNR_2 + Value, ...,
																				 *		  SRC_BNR_N + DST_BNR_N + Value
																				 */
    uint8_t bBlocksLen,														/**< [In] Length of the pBlocks buffer. */
    uint8_t **ppTMData,													/**< [Out] The Transaction Mac Value and Counter of each block returned by MIFARE Classic PICC if \n
																				 *		  its a TMProtected block. Null in case of not a TMProtected block.
																				 */
    uint16_t *pTMDataLen													/**< [Out] Amount of valid bytes returned by Sam hardware. */
);

/** \name Option macros for Sam AV3 MIFARE Classic Decrement command in X mode communication. */
/* @{ */
#define PHHAL_HW_SAMAV3_CMD_MF_DECREMENT_TMDATA_NOT_RETURNED			0x00	/**< Option mask for not exchanging the LE byte to SAM. */
#define PHHAL_HW_SAMAV3_CMD_MF_DECREMENT_TMDATA_RETURNED				0x80	/**< Option mask for exchanging the LE byte to SAM for retrieval of TMC and TMV information. */
/* @} */

/**
 * \brief Perform a MIFARE Classic Decrement command in X mode.
 *
 * \return Status code
 * \retval #PH_ERR_SUCCESS Operation successful.
 * \retval Other Depending on implementation and underlaying component.
 */
phStatus_t phhalHw_SamAV3_Cmd_MF_Decrement(
    phhalHw_SamAV3_DataParams_t
    *pDataParams,								/**< [In] Pointer to this layer's parameter structure. */
    uint8_t bOption,														/**< [In] For exchanging the LE byte.
																				 *          \arg #PHHAL_HW_SAMAV3_CMD_MF_DECREMENT_TMDATA_NOT_RETURNED
																				 *          \arg #PHHAL_HW_SAMAV3_CMD_MF_DECREMENT_TMDATA_RETURNED
																				 */
    uint8_t *pBlocks,														/**< [In] Buffer containing the Source Block, Destination Block and Value pair to be \n
																				 *		  written to card by Sam hardware. Should be holding an array of source block number, \n
																				 *        destination block number and value like \n
																				 *		  SRC_BNR_1 + DST_BNR_1 + Value, SRC_BNR_2 + DST_BNR_2 + Value, ...,
																				 *		  SRC_BNR_N + DST_BNR_N + Value
																				 */
    uint8_t bBlocksLen,														/**< [In] Length of the pBlocks buffer. */
    uint8_t **ppTMData,													/**< [Out] The Transaction Mac Value and Counter of each block returned by MIFARE Classic PICC if \n
																				 *		  its a TMProtected block. Null in case of not a TMProtected block.
																				 */
    uint16_t *pTMDataLen													/**< [Out] Amount of valid bytes returned by Sam hardware. */
);

/** \name Option macros for Sam AV3 MIFARE Classic Restore command in X mode communication. */
/* @{ */
#define PHHAL_HW_SAMAV3_CMD_MF_RESTORE_TMDATA_NOT_RETURNED			0x00	/**< Option mask for not exchanging the LE byte to SAM. */
#define PHHAL_HW_SAMAV3_CMD_MF_RESTORE_TMDATA_RETURNED				0x80	/**< Option mask for exchanging the LE byte to SAM for retrieval of TMC and TMV information. */
/* @} */

/**
 * \brief Perform a MIFARE Classic Restore command in X mode.
 *
 * \return Status code
 * \retval #PH_ERR_SUCCESS Operation successful.
 * \retval Other Depending on implementation and underlaying component.
 */
phStatus_t phhalHw_SamAV3_Cmd_MF_Restore(
    phhalHw_SamAV3_DataParams_t
    *pDataParams,								/**< [In] Pointer to this layer's parameter structure. */
    uint8_t bOption,														/**< [In] For exchanging the LE byte.
																				 *          \arg #PHHAL_HW_SAMAV3_CMD_MF_RESTORE_TMDATA_NOT_RETURNED
																				 *          \arg #PHHAL_HW_SAMAV3_CMD_MF_RESTORE_TMDATA_RETURNED
																				 */
    uint8_t *pBlocks,														/**< [In] Buffer containing the Source Block and Destination Block pair to be \n
																				 *		  written to card by Sam hardware. Should be holding an array of source \n
																				 *        block number and destination block numbe like \n
																				 *		  SRC_BNR_1 + DST_BNR_1, SRC_BNR_2 + DST_BNR_2, ..., SRC_BNR_N + DST_BNR_N
																				 */
    uint8_t bBlocksLen,														/**< [In] Length of the pBlocks buffer. */
    uint8_t **ppTMData,													/**< [Out] The Transaction Mac Value and Counter of each block returned by MIFARE Classic PICC if \n
																				 *		  its a TMProtected block. Null in case of not a TMProtected block.
																		 		 */
    uint16_t *pTMDataLen													/**< [Out] Amount of valid bytes returned by Sam hardware. */
);

/** \name Option macros for Sam AV3 MIFARE Classic Write command in X mode communication. */
/* @{ */
#define PHHAL_HW_SAMAV3_CMD_MF_AUTH_RW_KEY_INFO_AVAILABLE				0x00	/**< Option mask to include the key information for authentication block. */
#define PHHAL_HW_SAMAV3_CMD_MF_AUTH_RW_KEY_INFO_NOT_AVAILABLE			0x01	/**< Option mask to exclude the key information for authentication block. */
#define PHHAL_HW_SAMAV3_CMD_MF_AUTH_RW_CMD_SET_DIV_OFF					0x00	/**< Option mask to disable the key diversification. */
#define PHHAL_HW_SAMAV3_CMD_MF_AUTH_RW_CMD_SET_DIV_ON					0x02	/**< Option mask to enable the key diversification. */
/* @} */

/**
 * \brief Perform a MIFARE Authenticate followed by a MIFARE Read command in X mode.
 *
 * \return Status code
 * \retval #PH_ERR_SUCCESS Operation successful.
 * \retval Other Depending on implementation and underlaying component.
 */
phStatus_t phhalHw_SamAV3_Cmd_MF_AuthenticatedRead(
    phhalHw_SamAV3_DataParams_t
    *pDataParams,								/**< [In] Pointer to this layer's parameter structure. */
    uint16_t wOption,														/**< [In] Option mask for this command. On every call a single data cycle is buffered. \n
																				 *        A cycle is one sequence of CmdSettingss | KeyNo | KeyV | KeyType | AuthBlockNo |
																				 *		  DivBlockNo| NumBlocks | Blocks \n
																				 *
																				 *		  One of the below mentioned options to be used.
																				 *			\arg #PH_EXCHANGE_DEFAULT      (Single command frame to be exchanged with Sam hardware)
																				 *			\arg #PH_EXCHANGE_BUFFER_FIRST (The header and the initial paylod information will be bufferred internally.)
																				 *			\arg #PH_EXCHANGE_BUFFER_CONT  (The final payload if available and bufferred information will be sent to the SAM hardware)
																				 *			\arg #PH_EXCHANGE_BUFFER_LAST  (The bufferred information will be sent to the SAM hardware)
																				 */
    uint8_t *pMFUid,														/**< [In] MIFARE standard UID. Here the last four bytes of the UID should be passed regardless of 4 or 7 byte UID. \n
																				 *		  This buffer is only used if wOption is set to #PH_EXCHANGE_DEFAULT or #PH_EXCHANGE_BUFFER_FIRST.
																				 */
    uint8_t bCmdSettings,													/**< [In] One of the below mentioned options to be used to update the CmdSettings
																				 *			\arg #PHHAL_HW_SAMAV3_CMD_MF_AUTH_RW_KEY_INFO_AVAILABLE
																				 *			\arg #PHHAL_HW_SAMAV3_CMD_MF_AUTH_RW_KEY_INFO_NOT_AVAILABLE
																				 *			\arg #PHHAL_HW_SAMAV3_CMD_MF_AUTH_RW_CMD_SET_DIV_OFF
																				 *			\arg #PHHAL_HW_SAMAV3_CMD_MF_AUTH_RW_CMD_SET_DIV_ON
																				 */
    uint8_t bKeyNo,															/**< [In] Key number of MIFARE key available in Sam keystore. */
    uint8_t bKeyVer,														/**< [In] Key Version of MIFARE key available in Sam keystore. */
    uint8_t bKeyType,														/**< [In] Type of key to be used.
																				 *			\arg #PHHAL_HW_MFC_KEYA
																				 *			\arg #PHHAL_HW_MFC_KEYB
																				 */
    uint8_t bAuthBlockNo,													/**< [In] MIFARE block number used for authentication. */
    uint8_t bDivBlockNo,													/**< [In] Block number to be used for Key diversification in Sam. */
    uint8_t *pBlocks,														/**< [In] The block numbers from where the data should be read. */
    uint8_t bBlocksLen,														/**< [In] Length representing the blocks available in pBlocks parameter. */
    uint8_t **ppData,														/**< [Out] Data returned by Sam hardware. */
    uint16_t *pDataLen														/**< [Out] Amount of valid bytes returned by Sam hardware. */
);

/** \name Option macros for Sam AV3 MIFARE Classic AuthenticateWrite command in X mode communication. */
/* @{ */
#define PHHAL_HW_SAMAV3_CMD_MF_AUTH_WRITE_TMDATA_NOT_RETURNED		0x0000	/**< Option mask for not exchanging the LE byte to SAM. */
#define PHHAL_HW_SAMAV3_CMD_MF_AUTH_WRITE_TMDATA_RETURNED			0x0080	/**< Option mask for exchanging the LE byte to SAM for retrieval of TMC and TMV information. */
/* @} */

/**
 * \brief Perform a MIFARE Authenticate followed by a MIFARE Write command in X mode.
 *
 * \return Status code
 * \retval #PH_ERR_SUCCESS Operation successful.
 * \retval Other Depending on implementation and underlaying component.
 */
phStatus_t phhalHw_SamAV3_Cmd_MF_AuthenticatedWrite(
    phhalHw_SamAV3_DataParams_t
    *pDataParams,								/**< [In] Pointer to this layer's parameter structure. */
    uint16_t wOption,														/**< [In] Option mask for this command. On every call a single data cycle is buffered. \n
																				 *        A cycle is one sequence of CmdSettingss | KeyNo | KeyV | KeyType | AuthBlockNo |
																				 *		  DivBlockNo| NumBlocks | Blocks \n
																				 *
																				 *		  One of the below mentioned blocks to be used.
																				 *			\arg #PH_EXCHANGE_DEFAULT      (Single command frame to be exchanged with Sam hardware)
																				 *			\arg #PH_EXCHANGE_BUFFER_FIRST (The header and the initial paylod information will be bufferred internally.)
																				 *			\arg #PH_EXCHANGE_BUFFER_CONT  (The final payload if available and bufferred information will be sent to the SAM hardware)
																				 *			\arg #PH_EXCHANGE_BUFFER_LAST  (The bufferred information will be sent to the SAM hardware)
																				 *		  \n
																				 *		 One of the below option ORED with above ones for LE byte exchange.
																				 *			\arg #PHHAL_HW_SAMAV3_CMD_MF_AUTH_WRITE_TMDATA_NOT_RETURNED
																				 *			\arg #PHHAL_HW_SAMAV3_CMD_MF_AUTH_WRITE_TMDATA_RETURNED
																				 */
    uint8_t *pMFUid,														/**< [In] MIFARE standard UID. Here the last four bytes of the UID should be passed regardless of 4 or 7 byte UID. \n
																				 *		  This buffer is only used if wOption is set to #PH_EXCHANGE_DEFAULT or #PH_EXCHANGE_BUFFER_FIRST.
																				 */
    uint8_t bCmdSettings,													/**< [In] One of the below mentioned options to be used to update the CmdSettings
																				 *			\arg #PHHAL_HW_SAMAV3_CMD_MF_AUTH_RW_KEY_INFO_AVAILABLE
																				 *			\arg #PHHAL_HW_SAMAV3_CMD_MF_AUTH_RW_KEY_INFO_NOT_AVAILABLE
																				 *			\arg #PHHAL_HW_SAMAV3_CMD_MF_AUTH_RW_CMD_SET_DIV_OFF
																				 *			\arg #PHHAL_HW_SAMAV3_CMD_MF_AUTH_RW_CMD_SET_DIV_ON
																				 */
    uint8_t bKeyNo,															/**< [In] Key number of MIFARE key available in Sam keystore. */
    uint8_t bKeyVer,														/**< [In] Key Version of MIFARE key available in Sam keystore. */
    uint8_t bKeyType,														/**< [In] Type of key to be used.
																				 *			\arg #PHHAL_HW_MFC_KEYA
																				 *			\arg #PHHAL_HW_MFC_KEYB
																				 */
    uint8_t bAuthBlockNo,													/**< [In] MIFARE block number used for authentication. */
    uint8_t bDivBlockNo,													/**< [In] Block number to be used for Key diversification in Sam. */
    uint8_t *pBlocks,														/**< [In] Buffer containing the Block and Data pair to be written to card by Sam hardware. \n
																				 *        Should be holding an array of block number and data like
																				 *		  BNR_1 + Data, BNR_2 + Data, BNR_3 + Data, ..., BNR_N + Data \n
																				 *		  (where Data is of 16 bytes)
																				 */
    uint8_t bBlocksLen,														/**< [In] Length representing the block and data pair available in pBlocks parameter. */
    uint8_t **ppTMData,													/**< [Out] The Transaction Mac Value and Counter of each block returned by MIFARE Classic PICC if \n
																				 *		  its a TMProtected block. Null in case of not a TMProtected block.
																				 */
    uint16_t *pTMDataLen													/**< [Out] Amount of valid bytes returned by Sam hardware. */
);

/**
 * \brief Performs the MIFARE Classic key change in X mode.
 *
 * \return Status code
 * \retval #PH_ERR_SUCCESS Operation successful.
 * \retval Other Depending on implementation and underlaying component.
 */
phStatus_t phhalHw_SamAV3_Cmd_MF_ChangeKey(
    phhalHw_SamAV3_DataParams_t
    *pDataParams,								/**< [In] Pointer to this layer's parameter structure. */
    uint8_t bOption,														/**< [In] Specify whether diversification block number and UID should be exchanged or not.
																				 *			\arg #PHHAL_HW_SAMAV3_CMD_CHANGE_KEY_MIFARE_DIV_OFF
																				 *			\arg #PHHAL_HW_SAMAV3_CMD_CHANGE_KEY_MIFARE_DIV_A_OFF
																				 *			\arg #PHHAL_HW_SAMAV3_CMD_CHANGE_KEY_MIFARE_DIV_A_ON
																				 *			\arg #PHHAL_HW_SAMAV3_CMD_CHANGE_KEY_MIFARE_DIV_B_OFF
																				 *			\arg #PHHAL_HW_SAMAV3_CMD_CHANGE_KEY_MIFARE_DIV_B_ON
																				 */
    uint8_t bKeyNo,															/**< [In] Key number of MIFARE key available in Sam keystore. */
    uint8_t bKeyVerA,														/**< [In] Key Version of MIFARE key A available in Sam keystore. */
    uint8_t bKeyVerB,														/**< [In] Key Version of MIFARE key B available in Sam keystore. */
    uint8_t bMFBlockNo,														/**< [In] Block number of the block to store the new key(s) */
    uint8_t *pAccCond,														/**< [In] MIFARE classic access conditions. */
    uint8_t *pMFUID,														/**< [In] MIFARE classic UID. Here the last four bytes of the UID should be passed regardless of 4 or 7 byte UID. */
    uint8_t bDivBlockNo														/**< [In] Block number to be used for Key diversification in Sam. */
);

/**
 * end of phhalHw_SamAV3_Cmd_MFC_X
 * @}
 */

/**
 * end of phhalHw_SamAV3_Cmd_MFC
 * @}
 */

/*************************************************************************************************************************/
/*************************************************** MIFARE Ultralight ***************************************************/
/*************************************************************************************************************************/

/** \defgroup phhalHw_SamAV3_Cmd_UL MIFARE Ultralight
 * \brief SAM commands use for MIFARE Ultralight PICC communication in X and Non-X mode.
 * @{
 */

/** \defgroup phhalHw_SamAV3_Cmd_UL_S S Mode
 * \brief SAM commands used for MIFARE Ultralight PICC communication in S-Mode.
 * @{
 */

/** \name Sam AV3 command code for PwdAuthUL feature. */
/* @{ */
#define PHHAL_HW_SAMAV3_CMD_SAM_PWD_AUTH_UL_INS					0x0B	/**< Sam AV3 X mode Instruction code for PwdAuthUL command. */
/* @} */

/**
 * \brief Performs PwdAuthUL command execution part 1 in S mode. The first part includes the header, Key number,
 * Key Version,Diversification input and returns Message
 *
 * \retval #PH_ERR_SUCCESS_CHAINING Operation successful.
 * \retval Other Depending on implementation and underlaying component.
 */
phStatus_t phhalHw_SamAV3_Cmd_SAM_PwdAuthUL_Part1(
    phhalHw_SamAV3_DataParams_t
    *pDataParams,						/**< [In] Pointer to this layer's parameter structure. */
    uint8_t bKeyNo,													/**< [In] Key number available in Sam keystore. */
    uint8_t bKeyVer,												/**< [In] Key version available in Sam keystore. */
    uint8_t *pDivInput,											/**< [In] Diversification input for key diversification. (1 to 31 byte(s) input). */
    uint8_t bDivInputLen,											/**< [In] Length of diversification input. */
    uint8_t **ppPwd,												/**< [Out] Overall message (4 byte). */
    uint16_t *pPwdLen												/**< [Out] Overall message Lenght (4 byte). */
);

/**
 * \brief Performs PwdAuthUL command execution part 2 in S mode. The Last part includes the header and Password authentication acknowledge
 *
 * \return Status code
 * \retval #PH_ERR_SUCCESS Operation successful.
 * \retval Other Depending on implementation and underlaying component.
 */
phStatus_t phhalHw_SamAV3_Cmd_SAM_PwdAuthUL_Part2(
    phhalHw_SamAV3_DataParams_t
    *pDataParams,						/**< [In] Pointer to this layer's parameter structure. */
    uint16_t wPack													/**< [In] Passwork Authentication Acknowledge. */
);

/**
 * end of phhalHw_SamAV3_Cmd_UL_S
 * @}
 */

/** \defgroup phhalHw_SamAV3_Cmd_UL_X X Mode
 * \brief Sam AV3 commands for MIFARE Ultralight X mode feature.
 * @{
 */

/** \name Sam AV3 command code for PwdAuthUL feature. */
/* @{ */
#define PHHAL_HW_SAMAV3_CMD_UL_PWD_AUTH_PICC_INS				0x2D	/**< Sam AV3 X mode Instruction code for PwdAuthUL command. */
#define PHHAL_HW_SAMAV3_CMD_ULC_AUTHENTICATE_PICC_INS			0x2C	/**< Sam AV3 X mode Instruction code for PwdAuthUL command. */
/* @} */

/** \name Option macros for Sam AV3 MIFARE Ultralight key diversification.Includes the header, Key number,
 * Key Version,Diversification input. */
/* @{ */
#define PHHAL_HW_SAMAV3_CMD_ULC_AUTHENTICATE_DIV_OFF			0x00	/**< Option mask to disable the exchange of diversification input. */
#define PHHAL_HW_SAMAV3_CMD_ULC_AUTHENTICATE_DIV_ON				0x01	/**< Option mask to enable the exchange of diversification input. */
#define PHHAL_HW_SAMAV3_CMD_ULC_AUTHENTICATE_EXCLUDE_LE			0x00	/**< Option mask to exclude LE in exchange buffer. */
#define PHHAL_HW_SAMAV3_CMD_ULC_AUTHENTICATE_INCLUDE_LE			0x02	/**< Option mask to include LE in exchange buffer. */
/* @} */

/**
 * \brief SAM commands used for MIFARE Ultralight PICC communication in X-Mode.
 *
 * \return Status code
 * \retval #PH_ERR_SUCCESS Operation successful.
 * \retval Other Depending on implementation and underlaying component.
 */
phStatus_t phhalHw_SamAV3_Cmd_UL_PwdAuthUL(
    phhalHw_SamAV3_DataParams_t
    *pDataParams,						/**< [In] Pointer to this layer's parameter structure. */
    uint8_t bKeyNo,													/**< [In] Key number available in Sam keystore. */
    uint8_t bKeyVer,												/**< [In] Key version available in Sam keystore. */
    uint8_t *pDivInput,											/**< [In] Diversification input for key diversification. (1 to 31 byte(s) input). */
    uint8_t bDivInputLen,											/**< [In] Length of diversification input. */
    uint8_t *pStatusCode											/**< [Out] Status code returned by PICC.*/
);

/**
 * \brief Performs AuthenticatePICC command execution in X mode.Includes the header, Key number,
 * Key Version,Diversification input based on Option Field.
 *
 * \return Status code
 * \retval #PH_ERR_SUCCESS Operation successful.
 * \retval Other Depending on implementation and underlaying component.
 */
phStatus_t phhalHw_SamAV3_Cmd_ULC_AuthenticatePICC(
    phhalHw_SamAV3_DataParams_t
    *pDataParams,						/**< [In] Pointer to this layer's parameter structure. */
    uint8_t bOption,												/**< [In] Option for P1 information byte.
																		 *			\arg #PHHAL_HW_SAMAV3_CMD_ULC_AUTHENTICATE_DIV_OFF
																		 *			\arg #PHHAL_HW_SAMAV3_CMD_ULC_AUTHENTICATE_DIV_ON
																		 *			\arg #PHHAL_HW_SAMAV3_CMD_ULC_AUTHENTICATE_EXCLUDE_LE
																		 *			\arg #PHHAL_HW_SAMAV3_CMD_ULC_AUTHENTICATE_INCLUDE_LE
																		 */
    uint8_t bKeyNo,													/**< [In] Key number available in Sam keystore. */
    uint8_t bKeyVer,												/**< [In] Key version available in Sam keystore. */
    uint8_t *pDivInput,											/**< [In] Diversification input for key diversification. (1 to 31 byte(s) input). */
    uint8_t bDivInputLen,											/**< [In] Length of diversification input. */
    uint8_t *pStatusCode											/**< [Out] Status code returned by PICC.*/
);

/**
 * end of phhalHw_SamAV3_Cmd_UL_X
 * @}
 */

/**
 * end of phhalHw_SamAV3_Cmd_UL
 * @}
 */

/*************************************************************************************************************************/
/**************************************************** Common commands ****************************************************/
/*************************************************************************************************************************/

/** \defgroup phhalHw_SamAV3_Cmd_Common Common
 * \brief SAM commands used for performing CommitReaderID in both X and S mode.
 * @{
 */

/** \name Options to differentiate the state of PICC authentication. */
#define PHHAL_HW_CMD_SAMAV3_COMMIT_READER_ID_PICC_STATE_MFP		0x00	/**< Option to indicate the PICC state as MIFARE Plus EV1. */
#define PHHAL_HW_CMD_SAMAV3_COMMIT_READER_ID_PICC_STATE_DESFIRE	0x01	/**< Option to indicate the PICC state as MIFARE DESFire EV2. */
/* @} */

/** \defgroup phhalHw_SamAV3_Cmd_Common_S S Mode
 * \brief SAM commands used for performing CommitReaderID in S mode for MifarePlus EV1 and MIFARE DESFire EV2 PICC.
 * @{
 */

/** \name Sam AV3 command code for CommitReaderID feature. */
/* @{ */
#define PHHAL_HW_CMD_SAMAV3_COMMIT_READER_ID_INS				0x36	/**< Sam AV3 S mode Instruction code for CommitReaderID command. */
/* @} */

/**
 * \brief Performs CommitReaderID command execution part 1 in S mode. The first part includes the header, block number if
 * its MifarePlus state or only header if its DESFire state.
 *
 * \return Status code
 * \retval #PH_ERR_SUCCESS_CHAINING Operation successful.
 * \retval Other Depending on implementation and underlaying component.
 */
phStatus_t phhalHw_SamAV3_Cmd_SAM_CommitReaderID_Part1(
    phhalHw_SamAV3_DataParams_t
    *pDataParams,						/**< [In] Pointer to this layer's parameter structure. */
    uint8_t bState,													/**< [In] Options for framing the command. Below options should be used.
																		 *			\c #PHHAL_HW_CMD_SAMAV3_COMMIT_READER_ID_PICC_STATE_MFP;
																		 *			\c #PHHAL_HW_CMD_SAMAV3_COMMIT_READER_ID_PICC_STATE_DESFIRE;
																		 */
    uint16_t wBlockNr,												/**< [In] Two bytes of block number if the state is MFP. */
    uint8_t **ppResponse,											/**< [Out] Transaction MAC Reader ID and MAC to be sent to MIFARE Plus or DESFire PICC. */
    uint16_t *pRespLen												/**< [Out] Length of TMRI returned by MIFARE Plus or DESFire PICC. */
);

/**
 * \brief Performs CommitReaderID command execution part 2 in S mode. The last part includes the header and the response received
 * from Mfifare Plus or DESFire PICC.
 *
 * \return Status code
 * \retval #PH_ERR_SUCCESS Operation successful.
 * \retval Other Depending on implementation and underlaying component.
 */
phStatus_t phhalHw_SamAV3_Cmd_SAM_CommitReaderID_Part2(
    phhalHw_SamAV3_DataParams_t
    *pDataParams,						/**< [In] Pointer to this layer's parameter structure. */
    uint8_t bPiccErrCode,											/**< [In] Error Code sent by the MFP card. For success it should be 0x90. */
    uint8_t *pData,												/**< [In] The complete data (ENCTMRI and MAC) received from MIFARE Plus or DESFire PICC. */
    uint8_t bDataLen,												/**< [In] Length of the data returned by MIFARE Plus or DESFire PICC. */
    uint8_t *pPiccReturnCode										/**< [Out] Error code returned by MIFARE PICC. This will of 1 byte in length. */
);

/**
 * end of phhalHw_SamAV3_Cmd_Common_S
 * @}
 */

/** \defgroup phhalHw_SamAV3_Cmd_Common_X X Mode
 * \brief SAM commands used for performing CommitReaderID in X mode for MifarePlus EV1 and MIFARE DESFire EV2 PICC.
 * @{
 */

/** \name MIFARE Plus command for SAM AV3 hardware. */
/** @{ */
#define PHHAL_HW_CMD_SAMAV3_TMRI_COMMIT_READER_ID_INS			0x37	/**< Sam AV3 X mode Instruction code for CommitReaderID command. */
/* @} */

/** \name Option macros for ISO mode selection. */
/* @{ */
#define PHHAL_HW_CMD_SAMAV3_TMRI_ISO_MODE_NATIVE					0x00	/**< Sam CommitReaderID ISO mode selection for Native command set. */
#define PHHAL_HW_CMD_SAMAV3_TMRI_ISO_MODE_ISO7816					0x40	/**< Sam CommitReaderID ISO mode selection for ISO 7816-4 command set. */
/* @} */

/**
 * \brief Performs CommitReaderID command execution in X mode. If success is returned the PICC return code will
 * have 0x00 as the value else the actual error code.
 *
 * \return Status code
 * \retval #PH_ERR_SUCCESS Operation successful.
 * \retval Other Depending on implementation and underlaying component.
 */
phStatus_t phhalHw_SamAV3_Cmd_TMRI_CommitReaderID(
    phhalHw_SamAV3_DataParams_t
    *pDataParams,						/**< [In] Pointer to this layer's parameter structure. */
    uint8_t bISOMode,												/**< [In] Options for P2 information byte.
 																		 *			\arg #PHHAL_HW_CMD_SAMAV3_TMRI_ISO_MODE_NATIVE
 																		 *  		\arg #PHHAL_HW_CMD_SAMAV3_TMRI_ISO_MODE_ISO7816
																		 */
    uint8_t bState,													/**< [In] The PICC state in which the Sam is currenlty authenticated to.
																		 *			\arg #PHHAL_HW_CMD_SAMAV3_COMMIT_READER_ID_PICC_STATE_MFP
																		 *			\arg #PHHAL_HW_CMD_SAMAV3_COMMIT_READER_ID_PICC_STATE_DESFIRE
																		 */
    uint16_t wBlockNr,												/**< [In] Block to be used if PICC state is MIFARE Plus EV1. */
    uint8_t **ppEncTMRI,											/**< [Out] Encrypted TM Reader ID as returned by PICC. */
    uint16_t *pEncTMRILen,											/**< [Out] Length of Encrypted TMRI. */
    uint8_t *pStatusCode											/**< [Out] Status code returned by PICC.*/
);

/**
 * end of phhalHw_SamAV3_Cmd_Common_X
 * @}
 */

/**
 * end of phhalHw_SamAV3_Cmd_Common
 * @}
 */

/*************************************************************************************************************************/
/*************************************************** ISO / IEC 29167-10 **************************************************/
/*************************************************************************************************************************/

/** \defgroup phhalHw_SamAV3_Cmd_ISO29167 ISO / IEC 29167-10
 * \brief SAM commands used for ICODE DNA Authentication in Non-X-Mode.
 * @{
 */

/** \name Sam AV3 command codes for ISO / IEC 29167-10 feature. */
/* @{ */
#define PHHAL_HW_SAMAV3_CMD_AUTHENTICATE_TAM_INS				0xB0	/**< Sam AV3 Instruction code for Cmd.SAM_AuthenticateTAM command. */
#define PHHAL_HW_SAMAV3_CMD_AUTHENTICATE_MAM_INS				0xB2	/**< Sam AV3 Instruction code for Cmd.SAM_AuthenticateMAM command. */
/* @} */

/** \name Buffer size */
/* @{ */
#define PHHAL_HW_SAMAV3_CMD_TAM2_COMMAND_SIZE					40U		/**< Macro to represent the size of the TAM2 command. */
/* @} */

/** \name Option for updating the Custom data flag. */
/* @{ */
#define PHHAL_HW_SAMAV3_CMD_TAM_CLEAR							0x00U	/**< Macro to represent the custom data value for Tag authentication cleared. */
#define PHHAL_HW_SAMAV3_CMD_TAM_SET								0x02U	/**< Macro to represent the custom data value for Tag authentication set. */
/* @} */

/** \name Option macros to differentiate between part 1 and part2 command exchange. */
/* @{ */
#define PHHAL_HW_SAMAV3_CMD_TAM_GET_RND							0x00U	/**< Option for exchanging Key and Div input and receive the IChallange as response. */
#define PHHAL_HW_SAMAV3_CMD_TAM_PROCESS_TRESPONE				0x01U	/**< Option for exchanging TResponse and validating it. */
/* @} */

/**
 * \brief Generates 10 bytes of random challange to be given to card. Also Decrypts the TResponse received from
 * card and verifies the decrypted data for authenticity.
 *
 * \return Status code
 * \retval #PH_ERR_SUCCESS Operation successful.
 * \retval #PH_ERR_SUCCESS_CHAINING for successfull chaining operation.
 * \retval Other Depending on implementation and underlaying component.
 */
phStatus_t phhalHw_SamAV3_Cmd_SAM_AuthenticateTAM1(
    phhalHw_SamAV3_DataParams_t
    *pDataParams,						/**< [In] Pointer to this layer's parameter structure. */
    uint8_t bOption,												/**< [In] The command to be framed for SAM.
																		 *			\arg #PHHAL_HW_SAMAV3_CMD_TAM_GET_RND
																		 *			\arg #PHHAL_HW_SAMAV3_CMD_TAM_PROCESS_TRESPONE
																		 */
    uint8_t bKeyNo,													/**< [In] Key reference number in hardware keytsore. */
    uint8_t bKeyVer,												/**< [In] Key version to be used in hardware key store. */
    uint8_t *pData,												/**< [In] Diversification Input or TResponse received from card. */
    uint8_t bDataLen,												/**< [In] Length of diversification input. If 0, no diversification is performed. Or length of TResponse */
    uint8_t **ppIChallange,										/**< [Out] The IChallange to be sent to card. This will contain 10 bytes of random challange data. */
    uint16_t *pIChallangeLen										/**< [Out] The length of challange data received from sam. */
);

/**
 * \brief Generates 10 bytes of random challange to be given to card. Also Decrypts the TResponse received from
 * card and verifies the decrypted data for authenticity and provides the custom data received form card.
 *
 * \return Status code
 * \retval #PH_ERR_SUCCESS Operation successful.
 * \retval Other Depending on implementation and underlaying component.
 */
phStatus_t phhalHw_SamAV3_Cmd_SAM_AuthenticateTAM2(
    phhalHw_SamAV3_DataParams_t
    *pDataParams,						/**< [In] Pointer to this layer's parameter structure. */
    uint8_t bOption,												/**< [In] The command to be framed for SAM.
																		 *		  \arg #PHHAL_HW_SAMAV3_CMD_TAM_GET_RND
																		 *		  \arg #PHHAL_HW_SAMAV3_CMD_TAM_PROCESS_TRESPONE
																		 */
    uint16_t wKeyNo,												/**< [In] Key reference number in hardware keytsore. */
    uint16_t wKeyVer,												/**< [In] Key version to be used in hardware key store. */
    uint8_t *pData,												/**< [In] Diversification Input or TResponse received from card. */
    uint8_t bDataLen,												/**< [In] Length of diversification input. If 0, no diversification is performed. Or length of TResponse. */
    uint8_t bBlockSize,												/**< [In] To select the size of custom data block to be used.
																		 *		  The value should either be 0x00 for 16 bit block size or 0x01 for 64 bit
																		 *		  block size. As per ISO 29167
																		 */
    uint8_t bBlockCount,											/**< [In] To select the custom data block to be used from the offset specified.
																	 	 *		  The BlockCount range is from 1 - 16.
																		 */
    uint8_t bProtMode,												/**< [In] To specify the mode of operation to be used for encryption/decryption.
																		 *		  The ProtMode ranges form 0 - 3. As per ISO 29167
																		 */
    uint8_t **ppResponse,											/**< [Out] The IChallange to be sent to card. This will contain 10 bytes of random challange data.
																		 *		   Or the Custom Data received from card.
																		 */
    uint16_t *pResponseLen											/**< [Out] The length of challange data received from sam or the length of Custom Data. */
);

/** \name Option macros for updating the PurposeMAM2 information of Cmd.SAM_AuthenticteMAM. */
/* @{ */
#define PHHAL_HW_SAMAV3_CMD_MAM_NONE							0x00U	/**< Option to indicate PurposeMAM2 value as None. Here only authentication will be performed. */
#define PHHAL_HW_SAMAV3_CMD_MAM_DISABLE_PRIVACY_HF_RESET		0x08U	/**< Option to indicate PurposeMAM2 value as Privacy disable until HF reset. */
#define PHHAL_HW_SAMAV3_CMD_MAM_ENABLE_PRIVACY					0x09U	/**< Option to indicate PurposeMAM2 value as Privacy enable. */
#define PHHAL_HW_SAMAV3_CMD_MAM_DISABLE_PRIVACY					0x0AU	/**< Option to indicate PurposeMAM2 value as Privacy disable. */
#define PHHAL_HW_SAMAV3_CMD_MAM_DESTROY							0x0BU	/**< Option to indicate PurposeMAM2 value as Destroy. */
/* @} */

/**
 * \brief Generates 10 bytes of random challange to be given to card.
 *
 * \return Status code
 * \retval #PH_ERR_SUCCESS Operation successful.
 * \retval Other Depending on implementation and underlaying component.
 */
phStatus_t phhalHw_SamAV3_Cmd_SAM_AuthenticateMAM1(
    phhalHw_SamAV3_DataParams_t
    *pDataParams,						/**< [In] Pointer to this layer's parameter structure. */
    uint8_t bKeyNo,													/**< [In] Key reference number in hardware keytsore.*/
    uint8_t bKeyVer,												/**< [In] Key version to be used in hardware key store.*/
    uint8_t *pData,												/**< [In] Diversification Input. */
    uint8_t bDataLen,												/**< [In] Length of diversification input. If 0, no diversification is performed. */
    uint8_t bPurposeMAM2,											/**< [In] Purpose MAM 2 data. A 4 bit value.
																		 *			\arg #PHHAL_HW_SAMAV3_CMD_MAM_NONE
																		 *			\arg #PHHAL_HW_SAMAV3_CMD_MAM_DISABLE_PRIVACY_HF_RESET
																		 *			\arg #PHHAL_HW_SAMAV3_CMD_MAM_ENABLE_PRIVACY
																		 *			\arg #PHHAL_HW_SAMAV3_CMD_MAM_DISABLE_PRIVACY
																		 *			\arg #PHHAL_HW_SAMAV3_CMD_MAM_DESTROY
																		 */
    uint8_t **ppIChallange,										/**< [Out] The IChallange to be sent to card. This will contain 10 bytes of random challange data. */
    uint16_t *pIChallangeLen										/**< [Out] The length of challange data received from sam. */
);

/**
 * \brief Decrypts the TResponse received from card and verifies the decrypted data for authenticity. Also
 * frames the IResponse with will be sent to the card.
 *
 * \return Status code
 * \retval #PH_ERR_SUCCESS Operation successful.
 * \retval Other Depending on implementation and underlaying component.
 */
phStatus_t phhalHw_SamAV3_Cmd_SAM_AuthenticateMAM2(
    phhalHw_SamAV3_DataParams_t
    *pDataParams,						/**< [In] Pointer to this layer's parameter structure. */
    uint8_t *pData,												/**< [In] TResponse received from card. */
    uint8_t bDataLen,												/**< [In] Length of TResponse */
    uint8_t **ppIResponse,											/**< [Out] The IResponse generated by SAM that will be sent to card. This will contain 16 bytes of data. */
    uint16_t *pIResponseLen										/**< [Out] The length of IResponse data received from sam. */
);

/**
 * end of phhalHw_SamAV3_Cmd_ISO29167
 * @}
 */

/*************************************************************************************************************************/
/****************************************************** EMV Commands *****************************************************/
/*************************************************************************************************************************/

/** \defgroup phhalHw_SamAV3_Cmd_Emv EMV Commands
 * \brief SAM command for EMV feature.
 * @{
 */

/** \name Sam AV3 command code for EMVCo feature. */
/* @{ */
#define PHHAL_HW_SAMAV3_CMD_EMVCO_RECOVER_STATIC_DATA_INS		0x29U	/**< Sam AV3 Instruction code for Cmd.SAM_RecoverStaticData command. */
#define PHHAL_HW_SAMAV3_CMD_EMVCO_RECOVER_DYNAMIC_DATA_INS		0x2AU	/**< Sam AV3 Instruction code for Cmd.SAM_RecoverDynamicData command. */
#define PHHAL_HW_SAMAV3_CMD_EMVCO_RECOVER_ENCIPHER_PIN_INS		0x2BU	/**< Sam AV3 Instruction code for Cmd.SAM_EncipherPIN command. */
/* @} */

/**
 * \brief Performs EMV Offline Static Data Authentication. This command recovers the static application data for the Static Data
 * Authentication.
 *
 * \return Status code
 * \retval #PH_ERR_SUCCESS Operation successful.
 * \retval #PH_ERR_SUCCESS_CHAINING successfull chaining.
 * \retval Other Depending on implementation and underlaying component.
 */
phStatus_t phhalHw_SamAV3_Cmd_EMVCo_RecoverStaticData(
    phhalHw_SamAV3_DataParams_t
    *pDataParams,						/**< [In] Pointer to this layer's parameter structure. */
    uint16_t wOption,												/**< [In] Option for exchanging the data in chaining or in one frame.
																		 *         \arg #PH_EXCHANGE_DEFAULT   : To exchange the non-chained or the final set of data.
																		 *										 Here the LFI will be set to 0x00.
																		 *         \arg #PH_EXCHANGE_TXCHAINING: To exchange the chained data. Here the LFI will be set to 0xAF.
																		 */
    uint8_t *pSignedStaticAppData,									/**< [In] Signed Static Application Data. */
    uint8_t bSignedStaticAppDataLen,								/**< [In] Signed Static Application Data length. */
    uint8_t **ppResponse,											/**< [Out] Buffer containing Hash Algorithm Indicator, Data
																		 *		   Authentication Code and Hash Result.
																		 */
    uint8_t *pRespLen												/**< [Out] Length of the output data */
);

/**
 * \brief Performs EMV Offline Dynamic Data Authentication. This command recovers the dynamic application data for
 * the Dynamic Data Authentication or Combined Dynamic Data Authentication with Application Cryptogram Generation.
 * The ICC Public Key or ICC PIN Encipherment Public Key must have been loaded previously with
 * Cmd.PKI_LoadIccPk
 *
 * \return Status code
 * \retval #PH_ERR_SUCCESS Operation successful.
 * \retval Other Depending on implementation and underlaying component.
 */
phStatus_t phhalHw_SamAV3_Cmd_EMVCo_RecoverDynamicData(
    phhalHw_SamAV3_DataParams_t
    *pDataParams,						/**< [In] Pointer to this layer's parameter structure. */
    uint16_t wOption,												/**< [In] Option for exchanging the data in chaining or in one frame.
																		 *         \arg #PH_EXCHANGE_DEFAULT   : To exchange the non-chained or the final set of data.
																		 *										 Here the LFI will be set to 0x00.
																		 *         \arg #PH_EXCHANGE_TXCHAINING: To exchange the chained data. Here the LFI will be set to 0xAF.
																		 */
    uint8_t *pSignedDynamicAppData,								/**< [In] Signed Dynamic Application Data. */
    uint8_t bSignedDynamicAppDataLen,								/**< [In] Length of Signed Dynamic Application Data. */
    uint8_t **ppResponse,											/**< [Out] Buffer containing Hash Algorithm Indicator, ICC Dynamic Data Length,
																		 *		   ICC Dynamic Data and Hash result.
																		 */
    uint8_t *pRespLen												/**< [Out] Length of the output data. */
);

/**
 * \brief Performs EMV Personal Identification Number Encipherment. This command is used to encipher the PIN to support offline PIN
 * verification by the ICC. The ICC Public Key or ICC PIN Encipherment Public Key must have been loaded previously with
 * Cmd.PKI_LoadIccPk
 *
 * \return Status code
 * \retval #PH_ERR_SUCCESS Operation successful.
 * \retval Other Depending on implementation and underlaying component.
 */
phStatus_t phhalHw_SamAV3_Cmd_EMVCo_EncipherPin(
    phhalHw_SamAV3_DataParams_t
    *pDataParams,						/**< [In] Pointer to this layer's parameter structure. */
    uint8_t *pPinBlock,											/**< [In] Pin Block Number. */
    uint8_t *pIccNum,												/**< [In] ICC Unpredictable Number. */
    uint8_t **ppEncPin,											/**< [Out] Enciphered PIN Data. */
    uint8_t *pEncPinLen											/**< [Out] Length of the Enciphered PIN Data. */
);

/**
 * end of phhalHw_SamAV3_Cmd_Emv
 * @}
 */

/*************************************************************************************************************************/
/************************************************** Programmable Logic ***************************************************/
/*************************************************************************************************************************/

/** \defgroup phhalHw_SamAV3_Cmd_ProgLogic Programmable Logic
 * SAM commands used for Programmable Logic feature.
 * @{
 */

/** \name Sam AV3 INS command code for Programmable Logic feature. */
/* @{ */
#define PHHAL_HW_CMD_SAMAV3_PL_EXEC_INS							0xBE	/**< Sam Programmable Logic Instruction code for PL Execute command. */
#define PHHAL_HW_CMD_SAMAV3_PL_UPLOAD_INS						0xBF	/**< Sam Programmable Logic Instruction code for PL Upload command. */
/* @} */

/** \name Option macros for PLExec and PLUpload command's P1 inforamtion byte. */
/* @{ */
#define PHHAL_HW_CMD_SAMAV3_PROG_LOGIC_LFI_LAST					0x00	/**< Sam Programmable logic P1 information byte as not the last frame. */
#define PHHAL_HW_CMD_SAMAV3_PROG_LOGIC_LFI_NON_LAST				0xAF	/**< Sam Programmable logic P1 information byte as the last frame. */
/* @} */

/**
 * \brief Performs Programmable Logic execution.
 *
 * \return Status code
 * \retval #PH_ERR_SUCCESS Operation successful.
 * \retval #PH_ERR_SUCCESS_CHAINING for chaining response.
 * \retval Other Depending on implementation and underlaying component.
 */
phStatus_t phhalHw_SamAV3_Cmd_SAM_PLExec(
    phhalHw_SamAV3_DataParams_t
    *pDataParams,						/**< [In] Pointer to this layer's parameter structure. */
    uint8_t bLFI,													/**< [In] Option for updating the P1 information of Sam frame.
																		 *			\arg #PHHAL_HW_CMD_SAMAV3_PROG_LOGIC_LFI_LAST;
 																		 *			\arg #PHHAL_HW_CMD_SAMAV3_PROG_LOGIC_LFI_NON_LAST;
 																		 */
    uint8_t *pPLData,												/**< [In] Programmable Logic command data. */
    uint8_t bPLDataLen,												/**< [In] Length of Programmable Logic command data. */
    uint8_t **ppPLResp,											/**< [Out] Buffer holding the Programmable Logic response data.\n
																		 *			\c Actual data received from SAM.\n
																		 *			\c Actual error data received from SAM. The response will be of 2 bytes.
																		 */
    uint16_t *pPLRespLen											/**< [Out] Length of Programmable Logic response data. */
);

/**
 * \brief Performs Programmable Logic code upload.
 *
 * \return Status code
 * \retval #PH_ERR_SUCCESS Operation successful.
 * \retval #PH_ERR_SUCCESS_CHAINING for chaining response.
 * \retval Other Depending on implementation and underlaying component.
 */
phStatus_t phhalHw_SamAV3_Cmd_SAM_PLUpload(
    phhalHw_SamAV3_DataParams_t
    *pDataParams,							/**< [In] Pointer to this layer's parameter structure. */
    uint8_t bIsFirstFrame,												/**< [In] Option to represent the first frame where the UploadCtr will be exchanged.
																			 *			\arg #PH_OFF
 																			 *			\arg #PH_ON
 																			 */
    uint8_t bIsFinalFrame,												/**< [In] Option to represent the last frame. If set, the LE byte will be exchanged and
																			 *		  PLUploadACK will be received from SAM and will be validated internally.
																			 *			\arg #PH_OFF
 																			 *			\arg #PH_ON
 																			 */
    uint16_t wUploadCtr,												/**< [In] The upload counter value. This should be greater than the one availabe in SAM. */
    uint8_t bKeyNo,														/**< [In] Key number of Upload key (Ku) in software keystore. */
    uint8_t bKeyVer,													/**< [In] Key version of Upload key (Ku) in software keystore. */
    uint8_t *pPLCode,													/**< [In] Plain Programmable Logic code. */
    uint16_t wPLCodeLen,													/**< [In] Plain Programmable Logic code length. */
    uint8_t *pPLReKey,													/**< [In] The Rekey to be used for next crypto segment. This should have the next SessionENC
																			 *		  key followed by the SessionMAC key.
																			 */
    uint8_t bPLReKeyLen													/**< [In] Length of bytes available in PLReKey buffer. The length should be equal to double
																			 *		  AES key size.
																			 */
);

/*
 * end of phhalHw_SamAV3_Cmd_ProgLogic
 * @}
 */

/*************************************************************************************************************************/
/****************************************************** Reader Chips *****************************************************/
/*************************************************************************************************************************/

/** \defgroup phhalHw_SamAV3_Cmd_ReaderChips Reader Chips
 * \brief SAM commands used for reader IC communication.
 * @{
 */

/** \name Sam AV3 command code for Sam Reader Chips feature. */
/* @{ */
#define PHHAL_HW_SAMAV3_CMD_RC_READ_REGISTER_INS					0xEE	/**< Sam AV3 Insturction code for RC_ReadRegister command. */
#define PHHAL_HW_SAMAV3_CMD_RC_WRITE_REGISTER_INS					0x1E    /**< Sam AV3 Insturction code for RC_WriteRegister command. */
#define PHHAL_HW_SAMAV3_CMD_RC_RF_CONTROL_INS						0xCF    /**< Sam AV3 Insturction code for RC_RFControl command. */
#define PHHAL_HW_SAMAV3_CMD_RC_INIT_INS								0xE5    /**< Sam AV3 Insturction code for RC_Int command. */
#define PHHAL_HW_SAMAV3_CMD_RC_LOAD_REGISTER_VALUE_SET_INS			0x2E    /**< Sam AV3 Insturction code for RC_LoadRegisterValueSet command. */
/* @} */

/**
 * \brief Read the content of one or more register(s) of the connected reader chip.
 *
 * \return Status code
 * \retval #PH_ERR_SUCCESS Operation successful.
 * \retval Other Depending on implementation and underlaying component.
 */
phStatus_t phhalHw_SamAV3_Cmd_RC_ReadRegister(
    phhalHw_SamAV3_DataParams_t
    *pDataParams,							/**< [In] Pointer to this layer's parameter structure. */
    uint8_t *pRegAddr,													/**< [In] Address for the registers to be read. */
    uint8_t bRegAddrLen,												/**< [In] The length of bytes available in RegAddr buffer. */
    uint8_t *pValue													/**< [Out] Register(s) content in the same order as the command data field address(es). */
);

/**
 * \brief Write the content of one or more register(s) of the connected reader chip.
 *
 * \return Status code
 * \retval #PH_ERR_SUCCESS Operation successful.
 * \retval Other Depending on implementation and underlaying component.
 */
phStatus_t phhalHw_SamAV3_Cmd_RC_WriteRegister(
    phhalHw_SamAV3_DataParams_t
    *pDataParams,							/**< [In] Pointer to this layer's parameter structure. */
    uint8_t *pData,													/**< [In] The registers to tbe updated. This buffer should contain register address followed by value. \n
																			 *		  The format should be as mentioned below. \n
																			 *		  RegAdd + Value + RegAdd + Value + ... + RegAdd + Value
																			 */
    uint8_t bDataLen													/**< [In] The length of bytes available in Data buffer. */
);

/**
 * \brief Turn the radio frequency field On or Off
 *
 * \return Status code
 * \retval #PH_ERR_SUCCESS Operation successful.
 * \retval Other Depending on implementation and underlaying component.
 */
phStatus_t phhalHw_SamAV3_Cmd_RC_RFControl(
    phhalHw_SamAV3_DataParams_t
    *pDataParams,							/**< [In] Pointer to this layer's parameter structure. */
    uint16_t wTime														/**< [In] Shut-down time for the RF field, zero turns the field off. */
);

/**
 * \brief Initializes the reader chip.
 *
 * \return Status code
 * \retval #PH_ERR_SUCCESS Operation successful.
 * \retval Other Depending on implementation and underlaying component.
 */
phStatus_t phhalHw_SamAV3_Cmd_RC_Init(
    phhalHw_SamAV3_DataParams_t
    *pDataParams,							/**< [In] Pointer to this layer's parameter structure. */
    uint8_t bLoadReg													/**< [In] The Load register information. */
);

/**
 * \brief Stores a customer defined register value set.
 *
 * \return Status code
 * \retval #PH_ERR_SUCCESS Operation successful.
 * \retval Other Depending on implementation and underlaying component.
 */
phStatus_t phhalHw_SamAV3_Cmd_RC_LoadRegisterValueSet(
    phhalHw_SamAV3_DataParams_t
    *pDataParams,							/**< [In] Pointer to this layer's parameter structure. */
    uint8_t bStoreReg,													/**< [In] Number of register value set to be used for storing the values. */
    uint8_t *pData,													/**< [In] List of Register descriptions. This buffer should be as meniotned below. \n
																			 *			\c If TD1AR1070: SpeedID + ItemCount + RegAddr + RegValue \n
																			 *			\c If TD1AR2060: RegAddr + RegValue
																			 */
    uint8_t bDataLen													/**< [In] The length of bytes available in Data buffer. */
);

/**
 * end of phhalHw_SamAV3_Cmd_ReaderChips
 * @}
 */

/*************************************************************************************************************************/
/****************************************************** ISO14443-3 *******************************************************/
/*************************************************************************************************************************/

/** \defgroup phhalHw_SamAV3_Cmd_ISO14443_3 ISO14443-3
 * \brief SAM commands used for ISO14443 layer 3 communication in X-Mode.
 * @{
 */

/** \name Sam AV3 command code for Sam ISO1443-3 feature. */
/* @{ */
#define PHHAL_HW_SAMAV3_CMD_ISO14443_3_REQUEST_WAKEUP_INS			0x25	/**< Sam AV3 Insturction code for Cmd.ISO14443-3_Request_Wakeup command. */
#define PHHAL_HW_SAMAV3_CMD_ISO14443_3_ANTICOLLSION_SELECT_INS		0x93	/**< Sam AV3 Insturction code for Cmd.ISO14443-3_Anticollision_Select command. */
#define PHHAL_HW_SAMAV3_CMD_ISO14443_3_ACTIVATE_IDLE_INS			0x26	/**< Sam AV3 Insturction code for Cmd.ISO14443-3_ActivateIdle command. */
#define PHHAL_HW_SAMAV3_CMD_ISO14443_3_ACTIVATE_WAKEUP_INS			0x52	/**< Sam AV3 Insturction code for Cmd.ISO14443-3_ActivateWakeup command. */
#define PHHAL_HW_SAMAV3_CMD_ISO14443_3_HALTA_INS					0x50	/**< Sam AV3 Insturction code for Cmd.ISO14443-3_HaltA command. */
#define PHHAL_HW_SAMAV3_CMD_ISO14443_3_TRANSPARENT_EXCHANGE_INS		0x7E	/**< Sam AV3 Insturction code for Cmd.ISO14443-3_TransparentExchange command. */
/* @} */

/** \name Option for Cmd.ISO14443-3_Request_Wakeup command. */
/* @{ */
#define PHHAL_HW_SAMAV3_CMD_ISO14443_3_REQUEST_WAKEUP_REQA			0x26    /**<  Request command code. */
#define PHHAL_HW_SAMAV3_CMD_ISO14443_3_REQUEST_WAKEUP_WUPA			0x52    /**<  Wakeup command code. */
/* @} */

/**
 * \brief Perform a request or wake-up command (type A).
 *
 * \return Status code
 * \retval #PH_ERR_SUCCESS Operation successful.
 * \retval Other Depending on implementation and underlaying component.
 */
phStatus_t phhalHw_SamAV3_Cmd_X_ISO14443_3_RequestA_Wakeup(
    phhalHw_SamAV3_DataParams_t
    *pDataParams,							/**< [In] Pointer to this layer's parameter structure. */
    uint8_t bCmdCode,													/**< [In] Command code.
																			 *			\arg #PHHAL_HW_SAMAV3_CMD_ISO14443_3_REQUEST_WAKEUP_REQA
																			 *			\arg #PHHAL_HW_SAMAV3_CMD_ISO14443_3_REQUEST_WAKEUP_WUPA
																			 */
    uint8_t *pAtqa														/**< [Out] AtqA returned by the card. The buffer has to be 2 bytes long. */
);

/**
 * \brief Perform a bit-wise anticollision and select. (type A).
 *
 * \return Status code
 * \retval #PH_ERR_SUCCESS Operation successful.
 * \retval Other Depending on implementation and underlaying component.
 */
phStatus_t phhalHw_SamAV3_Cmd_X_ISO14443_3_AnticollisionSelect(
    phhalHw_SamAV3_DataParams_t
    *pDataParams,							/**< [In] Pointer to this layer's parameter structure. */
    uint8_t *pSelCodes,												/**< [In] Buffer containing the SEL sequence bytes (93h, 95h and 97h). */
    uint8_t bSelCodesLen,												/**< [In] Length of the SEL sequence buffer (01h to 03h). */
    uint8_t *pSak,														/**< [Out] Pointer to the 1 byte Select Acknowledge reveived from card. */
    uint8_t *pUid,														/**< [Out] Buffer containing the received UID. This buffer has to be 10 bytes long. */
    uint8_t *pUidLen													/**< [Out] Amount of valid bytes in UID buffer. */
);

/** \name Option for Cmd.ISO14443-3_ActivateIdle command. */
/* @{ */
#define PHHAL_HW_SAMAV3_CMD_ISO14443_3_ACTIVATEIDLE_DEFAULT			0x00    /**<  Default option mask for ActivateIdle. */
#define PHHAL_HW_SAMAV3_CMD_ISO14443_3_ACTIVATEIDLE_APPLY_ATQA		0x01    /**<  Option flag for applying the ATQA filter. */
#define PHHAL_HW_SAMAV3_CMD_ISO14443_3_ACTIVATEIDLE_APPLY_SAK		0x02    /**<  Option flag for applying the SAK filter. */
#define PHHAL_HW_SAMAV3_CMD_ISO14443_3_ACTIVATEIDLE_APPLY_TIME		0x04    /**<  Option flag for setting the time to wait. */
/* @} */

/**
 * \brief Perform one or several request - anticollision - select sequences (type A).
 *
 * \return Status code
 * \retval #PH_ERR_SUCCESS Operation successful.
 * \retval Other Depending on implementation and underlaying component.
 */
phStatus_t phhalHw_SamAV3_Cmd_X_ISO14443_3_ActivateIdle(
    phhalHw_SamAV3_DataParams_t
    *pDataParams,							/**< [In] Pointer to this layer's parameter structure. */
    uint8_t bOption,													/**< [In] Option parameter:
																			 *         \arg #PHHAL_HW_SAMAV3_CMD_ISO14443_3_ACTIVATEIDLE_DEFAULT
																			 *         \arg #PHHAL_HW_SAMAV3_CMD_ISO14443_3_ACTIVATEIDLE_APPLY_ATQA
																			 *         \arg #PHHAL_HW_SAMAV3_CMD_ISO14443_3_ACTIVATEIDLE_APPLY_SAK
																			 *         \arg #PHHAL_HW_SAMAV3_CMD_ISO14443_3_ACTIVATEIDLE_APPLY_TIME
																			 */
    uint8_t bNumCards,													/**< [In] Holds the number of cards to activate. */
    uint16_t wTime,														/**< [In] Time to wait for a card. */
    uint8_t *pAtqaIn,													/**< [In] Buffer containing the AtqA filter. This buffer has to be 4 bytes long. */
    uint8_t *pSakIn,													/**< [In] Buffer containing the Sak filter. This buffer has to be 2 bytes long. */
    uint8_t **ppResponse,												/**< [Out] Pointer to the buffer containing the received data. */
    uint16_t *pRespLen													/**< [Out] Amount of valid bytes in Response buffer. */
);

/**
 * \brief Perform a reactivate and select for a card in halt state (type A).
 *
 * \return Status code
 * \retval #PH_ERR_SUCCESS Operation successful.
 * \retval Other Depending on implementation and underlaying component.
 */
phStatus_t phhalHw_SamAV3_Cmd_X_ISO14443_3_ActivateWakeUp(
    phhalHw_SamAV3_DataParams_t
    *pDataParams,							/**< [In] Pointer to this layer's parameter structure. */
    uint8_t *pUid,														/**< [In] UID of the card to reactivate. */
    uint8_t bUidLen														/**< [In] Length of UID (4, 7 or 10 bytes). */
);

/**
 * \brief Perform a halt command (type A).
 *
 * \return Status code
 * \retval #PH_ERR_SUCCESS Operation successful.
 * \retval Other Depending on implementation and underlaying component.
 */
phStatus_t phhalHw_SamAV3_Cmd_X_ISO14443_3_HaltA(
    phhalHw_SamAV3_DataParams_t
    *pDataParams							/**< [In] Pointer to this layer's parameter structure. */
);

/**
 * \brief Perform a transparent exchange command (type A).
 *
 * \return Status code
 * \retval #PH_ERR_SUCCESS Operation successful.
 * \retval Other Depending on implementation and underlaying component.
 */
phStatus_t phhalHw_SamAV3_Cmd_X_ISO14443_3_TransparentExchange(
    phhalHw_SamAV3_DataParams_t
    *pDataParams,							/**< [In] Pointer to this layer's parameter structure. */
    uint8_t *pTxBuf,													/**< [In] Buffer containing the data to be sent. The buffer has to be bTxLength bytes long. */
    uint8_t bTxLen,														/**< [In] Number of bytes to be sent to the card. */
    uint8_t bTxBitLen,													/**< [In] Number valid bits in the last byte of the bTxBuffer. If set to 00h all bits are valid. */
    uint8_t **ppRxBuf,													/**< [Out] Pointer to the buffer containing the received data. */
    uint16_t *pRxLen,													/**< [Out] Amount of valid bytes in RxBuffer. */
    uint8_t *pRxBitLen													/**< [Out] Amount of valid bits in the last byte in case of an incomplete byte. */
);

/**
 * end of phhalHw_SamAV3_Cmd_ISO14443_3
 * @}
 */

/*************************************************************************************************************************/
/****************************************************** ISO14443-3 *******************************************************/
/*************************************************************************************************************************/

/** \defgroup phhalHw_SamAV3_Cmd_ISO14443_4 ISO14443-4
 * \brief SAM commands used for ISO14443 layer 4 communication in X-Mode.
 * @{
 */

/** \name Sam AV3 command code for Sam ISO1443-4 feature. */
/* @{ */
#define PHHAL_HW_SAMAV3_CMD_ISO14443_4_RATS_PPS_INS					0xE0	/**< Sam AV3 Insturction code for Cmd.ISO14443-4_RATS_PPS command. */
#define PHHAL_HW_SAMAV3_CMD_ISO14443_4_INIT_INS						0x11	/**< Sam AV3 Insturction code for Cmd.ISO14443-4_Init command. */
#define PHHAL_HW_SAMAV3_CMD_ISO14443_4_EXCHANGE_INS					0xEC    /**< Sam AV3 Insturction code for Cmd.ISO14443-4_Exchange command. */
#define PHHAL_HW_SAMAV3_CMD_ISO14443_4_PRESENCE_CHECK_INS			0x4C    /**< Sam AV3 Insturction code for Cmd.ISO14443-4_Init command. */
#define PHHAL_HW_SAMAV3_CMD_ISO14443_4_DESELECT_INS					0xD4    /**< Sam AV3 Insturction code for Cmd.ISO14443-4_Deselect command. */
#define PHHAL_HW_SAMAV3_CMD_ISO14443_4_FREE_CID_INS					0xFC    /**< Sam AV3 Insturction code for Cmd.ISO14443-4_Init command. */
/* @} */

/**
 * \brief Perform a combined RATS and PPS to prepare a card for T=CL data exchange.
 *
 * \return Status code
 * \retval #PH_ERR_SUCCESS Operation successful.
 * \retval Other Depending on implementation and underlaying component.
 */
phStatus_t phhalHw_SamAV3_Cmd_X_ISO14443_4_RATS_PPS(
    phhalHw_SamAV3_DataParams_t
    *pDataParams,							/**< [In] Pointer to this layer's parameter structure. */
    uint8_t bCidIn,														/**< [In] CID to be sent. */
    uint8_t bDsiIn,														/**< [In] DSI to be sent. */
    uint8_t bDriIn,														/**< [In] DRI to be sent. */
    uint8_t *pCidOut,													/**< [Out] CID used (1 byte). */
    uint8_t *pDsiOut,													/**< [Out] DSI used (1 byte). */
    uint8_t *pDriOut,													/**< [Out] DRI used (1 byte). */
    uint8_t *pAts														/**< [Out] Pointer to a buffer containing the received ATS. The length of the
																			 *		   ATS can be found on the first position.
																			 */
);

/**
 * \brief Perform a init of ISO-14443-4 layer (init T=CL protocol).
 *
 * \return Status code
 * \retval #PH_ERR_SUCCESS Operation successful.
 * \retval Other Depending on implementation and underlaying component.
 */
phStatus_t phhalHw_SamAV3_Cmd_X_ISO14443_4_Init(
    phhalHw_SamAV3_DataParams_t
    *pDataParams,							/**< [In] Pointer to this layer's parameter structure. */
    uint8_t bCid,														/**< [In] CID to apply. */
    uint8_t bDri,														/**< [In] Bit rate PCD -> PICC.
																			 *			\arg #PHHAL_HW_RF_DATARATE_106
																			 *			\arg #PHHAL_HW_RF_DATARATE_212
																			 *			\arg #PHHAL_HW_RF_DATARATE_424
																			 *			\arg #PHHAL_HW_RF_DATARATE_848
																			 */
    uint8_t bDsi,														/**< [In] Bit rate PICC -> PCD.
																			 *			\arg #PHHAL_HW_RF_DATARATE_106
																			 *			\arg #PHHAL_HW_RF_DATARATE_212
																			 *			\arg #PHHAL_HW_RF_DATARATE_424
																			 *			\arg #PHHAL_HW_RF_DATARATE_848
																			 */
    uint8_t bFwi,														/**< [In] Frame waiting time indicator. */
    uint8_t bFsci														/**< [In] Frame size card indicator. */
);

/**
 * \brief Perform an exchange bytes according ISO14443-4 T=CL protocol.
 *
 * \return Status code
 * \retval #PH_ERR_SUCCESS Operation successful.
 * \retval Other Depending on implementation and underlaying component.
 */
phStatus_t phhalHw_SamAV3_Cmd_X_ISO14443_4_Exchange(
    phhalHw_SamAV3_DataParams_t
    *pDataParams,							/**< [In] Pointer to this layer's parameter structure. */
    uint16_t wOption,													/**< [In] Bufferring Option.
																			 *			\arg #PH_EXCHANGE_DEFAULT   : To send and receive complete data
																			 *			\arg #PH_EXCHANGE_TXCHAINING: To excahnge intermediate data
																			 */
    uint8_t *pAppDataIn,												/**< [In] Buffer containing application data to sent. */
    uint8_t bLenAppData,												/**< [In] Length of application data to sent. */
    uint8_t **ppAppDataOut,											/**< [Out] Pointer to buffer containing the data returned by the PICC. */
    uint16_t *pAppDataOutLen											/**< [Out] Amount of valid bytes in ppAppDataOut. */
);

/**
 * \brief Check if an activated card is still in the field.
 *
 * \return Status code
 * \retval #PH_ERR_SUCCESS Operation successful.
 * \retval Other Depending on implementation and underlaying component.
 */
phStatus_t phhalHw_SamAV3_Cmd_X_ISO14443_4_PresenceCheck(
    phhalHw_SamAV3_DataParams_t
    *pDataParams							/**< [In] Pointer to this layer's parameter structure. */
);

/** \name Option for Cmd.ISO14443-4_Deselect command. */
/* @{ */
#define PHHAL_HW_SAMAV3_CMD_ISO14443_4_DESELECT_DO_NOT_FREE_CID		0x00    /**< Option to not free CID is deselect fails. */
#define PHHAL_HW_SAMAV3_CMD_ISO14443_4_DESELECT_FORCE_FREE_CID		0x01    /**< Option to forcefully free CID in any case. */
/* @} */

/**
 * \brief Perform a Deselect command.
 *
 * \return Status code
 * \retval #PH_ERR_SUCCESS Operation successful.
 * \retval Other Depending on implementation and underlaying component.
 */
phStatus_t phhalHw_SamAV3_Cmd_X_ISO14443_4_Deselect(
    phhalHw_SamAV3_DataParams_t
    *pDataParams,							/**< [In] Pointer to this layer's parameter structure. */
    uint8_t bFreeCid													/**< [In] Bitmask for deselect option.
																			 *			\arg #PHHAL_HW_SAMAV3_CMD_ISO14443_4_DESELECT_DO_NOT_FREE_CID
																			 *			\arg #PHHAL_HW_SAMAV3_CMD_ISO14443_4_DESELECT_FORCE_FREE_CID
																			 */
);

/**
 * \brief Free one or more currently assigned CIDs.
 *
 * \return Status code
 * \retval #PH_ERR_SUCCESS Operation successful.
 * \retval Other Depending on implementation and underlaying component.
 */
phStatus_t phhalHw_SamAV3_Cmd_X_ISO14443_4_FreeCid(
    phhalHw_SamAV3_DataParams_t
    *pDataParams,							/**< [In] Pointer to this layer's parameter structure. */
    uint8_t *pCid,														/**< [In] Buffer containing all CIDs to be freed. */
    uint8_t bCidLen														/**< [In] Length of the CID buffer (01h to 0Eh). */
);

/**
 * end of phhalHw_SamAV3_Cmd_ISO14443_4
 * @}
 */

/** @} */

#endif /* NXPBUILD__PHHAL_HW_SAMAV3 */

#ifdef __cplusplus
} /* Extern C */
#endif

#endif /* PHHALHW_SAMAV3_CMD_H */
