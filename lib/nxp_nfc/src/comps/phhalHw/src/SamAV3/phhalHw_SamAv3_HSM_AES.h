/*
*         Copyright (c), NXP Semiconductors Bangalore / India
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

/** \file
 * Secure Messaging Component of Reader Library Framework.
 * $Author: nxp60813 $
 * $Revision: 124 $
 * $Date: 2013-04-22 12:10:31 +0530 (Mon, 22 Apr 2013) $
 *
 * History:
 *  CHu: Generated 27. July 2009
 *
 */

#ifndef PHHALHW_SAMAV3_HSM_AES_H
#define PHHALHW_SAMAV3_HSM_AES_H

#include <nxp_nfc/ph_Status.h>

/** \defgroup phhalHw_SamAV3_HSM_AES AES Host Secure Messaging
 * \brief Provides a Secure Messaging interface for AES mode.
 * @{
 */

/**
 * \brief Perform Encryption using SamAV3 Host Protocol
 * \return Status code
 * \retval #PH_ERR_SUCCESS Operation successful.
 * \retval Other Depending on implementation and underlaying component.
 */
phStatus_t phhalHw_SamAV3_HSM_AES_Encrypt(
		phhalHw_SamAV3_DataParams_t * pDataParams,							/**< [In] Pointer to this layer's parameter structure. */
		uint8_t * pBuffer,													/**< [In] Data to encrypt. */
		uint16_t wTxLength,													/**< [In] Length of data to encrypt. */
		uint16_t wBufferSize,												/**< [In] Size of the buffer. */
		uint16_t * pTxLength,												/**< [Out] Number of encrypted data bytes. */
		uint8_t bFirst,														/**< [In] Whether this is the first block. */
		uint8_t bLast														/**< [In] Whether this is the last block. */
	);

/**
 * \brief Perform Decryption using SamAV3 Host Protocol
 * \return Status code
 * \retval #PH_ERR_SUCCESS Operation successful.
 * \retval Other Depending on implementation and underlaying component.
 */
phStatus_t phhalHw_SamAV3_HSM_AES_Decrypt(
		phhalHw_SamAV3_DataParams_t * pDataParams,							/**< [In] Pointer to this layer's parameter structure. */
		uint8_t * pBuffer,													/**< [In] Data to decrypt. */
		uint16_t wRxLength,													/**< [In] Length of data to decrypt. */
		uint16_t * pRxLength,												/**< [Out] Number of decrypted data bytes. */
		uint8_t bFirst,														/**< [In] Whether this is the first block. */
		uint8_t bLast														/**< [In] Whether this is the last block. */
	);

/**
 * \brief Append MAC to a data stream using SamAV3 Host Protocol
 * \return Status code
 * \retval #PH_ERR_SUCCESS Operation successful.
 * \retval Other Depending on implementation and underlaying component.
 */
phStatus_t phhalHw_SamAV3_HSM_AES_AppendMac(
		phhalHw_SamAV3_DataParams_t * pDataParams,							/**< [In] Pointer to this layer's parameter structure. */
		uint8_t * pBuffer,													/**< [In] Data to mac. */
		uint16_t wTxLength,													/**< [In] Length of data to mac. */
		uint16_t wBufferSize,												/**< [In] Size of the buffer. */
		uint16_t * pTxLength,												/**< [Out] Number of data bytes incl. MAC. */
		uint8_t bFirst,														/**< [In] Whether this is the first block. */
		uint8_t bLast														/**< [In] Whether this is the last block. */
	);

/**
 * \brief Remove Mac and verify it using SamAV3 Host Protocol
 * \return Status code
 * \retval #PH_ERR_SUCCESS Operation successful.
 * \retval Other Depending on implementation and underlaying component.
 */
phStatus_t phhalHw_SamAV3_HSM_AES_VerifyRemoveMac(
		phhalHw_SamAV3_DataParams_t * pDataParams,							/**< [In] Pointer to this layer's parameter structure. */
		uint8_t * pBuffer,													/**< [In] data to unmac. */
		uint16_t wRxLength,													/**< [In] length of data to unmac. */
		uint16_t * pRxLength,												/**< [Out] number of unmaced data bytes. */
		uint8_t bFirst,														/**< [In] Whether this is the first block. */
		uint8_t bLast														/**< [In] Whether this is the last block. */
	);


phStatus_t phhalHw_SamAV3_HSM_AES_GetFirstLastCommand(
		phhalHw_SamAV3_DataParams_t * pDataParams,							/**< [In] Pointer to this layer's parameter structure. */
		uint8_t bCmd,														/**< [In] Command code. */
		uint8_t bP1,														/**< [In] P1 of command. */
		uint8_t bP2,														/**< [In] P2 of command. */
		uint8_t * pFirstCmd,												/**< [Out] Whether this is the first block. */
		uint8_t * pLastCmd													/**< [Out] Whether this is the last block. */
	);

phStatus_t phhalHw_SamAV3_HSM_AES_GetFirstLastResponse(
		phhalHw_SamAV3_DataParams_t * pDataParams,							/**< [In] Pointer to this layer's parameter structure. */
		uint8_t bSw1,														/**< [In] SW1 of response. */
		uint8_t bSw2,														/**< [In] SW2 of response. */
		uint8_t * pFirstResponse,											/**< [Out] Whether this is the first block. */
		uint8_t * pLastResponse												/**< [Out] Whether this is the last block. */
	);

phStatus_t phhalHw_SamAV3_HSM_AES_InitAndLoadIV(
		phhalHw_SamAV3_DataParams_t * pDataParams,
		uint8_t* pIV,
		uint8_t encryptionIV
	);

/** @}
* end of phhalHw_SamAV3_HSM_AES group
*/

#endif /* PHHALHW_SAMAV3_HSM_AES_H */
