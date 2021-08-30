/*
*         Copyright (c), NXP Semiconductors Bangalore / India
*
*                     (C)NXP Semiconductors
*       All rights are reserved. Reproduction in whole or in part is
*      prohibited without the written consent of the copyright owner.
*  NXP reserves the right to make changes without notice at any time.
* NXP makes no warranty, expressed, implied or statutory, including but
* not limited to any implied warranty of merchantability or fitness for any
* particular purpose, or that the use will not infringe any third party patent,
* copyright or trademark. NXP must not be liable for any loss or damage
*                          arising from its use.
*/

/** \file
* Internal logic file of Sam Av3 keystore component.
* $Author: nxp60813 $
* $Revision: 124 $
* $Date: 2013-04-22 12:10:31 +0530 (Mon, 22 Apr 2013) $
*
* History:
*  CHu: Generated 19. May 2009
*
*/

#ifndef PHKEYSTORE_SAMAV3_INT_H
#define PHKEYSTORE_SAMAV3_INT_H

#include <nxp_nfc/ph_Status.h>
#include <nxp_nfc/phKeyStore.h>

#define PH_KEYSTORE_SAMAV3_NVM_KEY_MAX							0x7FU
#define PH_KEYSTORE_SAMAV3_KEYTYPE_MASK							0x78U
#define PH_KEYSTORE_SAMAV3_KEYCLASS_MASK						0x07U

/* Key types for Sam AV3. Maros to update the SET configuration's first byte information. */
#define PH_KEYSTORE_SAMAV3_KEYTYPE_3DESDF4_MASK					0x00U	/* KeyType.DESFire4 */
#define PH_KEYSTORE_SAMAV3_KEYTYPE_2K3DES_MASK					0x01U	/* KeyType.ISO_TDEA16 */
#define PH_KEYSTORE_SAMAV3_KEYTYPE_MIFARE_MASK					0x02U	/* KeyType.MIFARE */
#define PH_KEYSTORE_SAMAV3_KETYPE_3K3DES_MASK					0x03U	/* KeyType.3TDEA */
#define PH_KEYSTORE_SAMAV3_KEYTYPE_AES128_MASK					0x04U	/* KeyType.AES_128 */
#define PH_KEYSTORE_SAMAV3_KEYTYPE_AES192_MASK					0x05U	/* KeyType.AES_192 */
#define PH_KEYSTORE_SAMAV3_KEYTYPE_2K3DESDF8_MASK				0x06U	/* KeyType.ISO_TDEA32 */
#define PH_KEYSTORE_SAMAV3_KEYTYPE_AES256_MASK					0x07U	/* KeyType.AES_256 */
#define PH_KEYSTORE_SAMAV3_KEYTYPE_LRP_AES128_MASK				0x08U	/* KeyType.AES_128LRP */

/* Maros to update the SET configuration's first byte information. */
#define PH_KEYSTORE_SAMAV3_SET0_ALLOW_DUMP_SESSION_KEY			0x01U
#define PH_KEYSTORE_SAMAV3_SET0_KEEP_IV							0x04U
#define PH_KEYSTORE_SAMAV3_SET0_PL_KEY							0x80U

/* Maros to update the SET configuration's second byte information. */
#define PH_KEYSTORE_SAMAV3_SET1_AUTH_KEY						0x01U
#define PH_KEYSTORE_SAMAV3_SET1_DISABLE_KEY_ENTRY				0x02U
#define PH_KEYSTORE_SAMAV3_SET1_LOCK_KEY						0x04U
#define PH_KEYSTORE_SAMAV3_SET1_DISABLE_CHANGE_KEY_PICC			0x08U
#define PH_KEYSTORE_SAMAV3_SET1_DISABLE_DECRYPTION				0x10U
#define PH_KEYSTORE_SAMAV3_SET1_DISABLE_ENCRYPTION				0x20U
#define PH_KEYSTORE_SAMAV3_SET1_DISABLE_VERIFY_MAC				0x40U
#define PH_KEYSTORE_SAMAV3_SET1_DISABLE_GENERATE_MAC			0x80U

/* Maros to update the ExtSET configuration's first byte information. */
#define PH_KEYSTORE_SAMAV3_EXTSET0_ALLOW_DUMP_SECRET_KEY		0x08U
#define PH_KEYSTORE_SAMAV3_EXTSET0_MANDATE_KEY_DIVERSIFICATION	0x10U
#define PH_KEYSTORE_SAMAV3_EXTSET0_PERSONALIZATION_SAM			0x20U

/* Maros to update the ExtSET configuration's second byte information. */
#define PH_KEYSTORE_SAMAV3_EXTSET1_KEY_USAGE_INT_HOST			0x01U
#define PH_KEYSTORE_SAMAV3_EXTSET1_KEY_CHANGE_INT_HOST			0x02U
#define PH_KEYSTORE_SAMAV3_EXTSET1_SESSION_KEY_USAGE_INT_HOST	0x04U
#define PH_KEYSTORE_SAMAV3_EXTSET1_DUMP_SECRET_KEY_INT_HOST		0x08U
#define PH_KEYSTORE_SAMAV3_EXTSET1_DUMP_SESSION_KEY_INT_HOST	0x10U

/* Macros to represent the key entry length returned by Sam for Cmd.GetKeyEntry command. */
#define PH_KEYSTORE_SAMAV3_KEY_ENTRY_LEN_SAMAV2_FORMAT_VER_ABC	13U
#define PH_KEYSTORE_SAMAV3_KEY_ENTRY_LEN_SAMAV2_FORMAT_VER_AB	12U
#define PH_KEYSTORE_SAMAV3_KEY_ENTRY_LEN_SAMAV3_FORMAT_VER_ABC	16U
#define PH_KEYSTORE_SAMAV3_KEY_ENTRY_LEN_SAMAV3_FORMAT_VER_AB	15U
#define PH_KEYSTORE_SAMAV3_KEY_ENTRY_LEN_SAMAV3_FORMAT_VER_A	14U
#define PH_KEYSTORE_SAMAV3_KEY_ENTRY_LEN_SAMAV3_RAM_KEY			9U

/* Macros to represent the version positions. */
#define PH_KEYSTORE_SAMAV3_VERSION_POSITION_A					0U
#define PH_KEYSTORE_SAMAV3_VERSION_POSITION_B					1U
#define PH_KEYSTORE_SAMAV3_VERSION_POSITION_C					2U

/**
 * Gets the inforamtion available in the key entry structure.
 *
 * Input Parameters:
 *		pDataParams		 : Pointer to this layer's parameter structure.
 *		bKeyNo			 : The key number to used for retreiving the key entry information form Sam hardware.
 *		bIsRamKey		 : The key number provided in bKeyNo parameter is NVM key or RAM key.
 *
 * Output Parameters:
 *		pKeyEntry		 : The key entry information for the mentioned key number.
 *
 * Return:
 *			PH_ERR_SUCCESS for successfull operation.
 *			Other Depending on implementation and underlaying component.
 */
phStatus_t phKeyStore_SamAV3_Int_GetKeyEntry(phKeyStore_SamAV3_DataParams_t * pDataParams, uint8_t bKeyNo, uint8_t bIsRamKey,
	phKeyStore_SamAV3_KeyEntry_t * pKeyEntry);

/**
 * Convert the inforamtion available in the key entry structure to bytes.
 *
 * Input Parameters:
 *		pDataParams		 : Pointer to this layer's parameter structure.
 *		pKeyEntry		 : Pointer to Key Entry structure.
 *		pKey			 : The buffer containing the Key information. Here the KeyA, KeyB and KeyC will be combined together.
 *		bKeyLen			 : The length of bytes available in pKey buffer.
 *
 * Output Parameters:
 *		pKeyEntryBuff	 : The bytes buffer containing the KeyEntry information.
 *		pKeyEntryBuffLen : The length of pKeyEntryBuffer.
 *
 * Return:
 *			PH_ERR_SUCCESS for successfull operation.
 *			Other Depending on implementation and underlaying component.
 */
phStatus_t phKeyStore_SamAV3_Int_ConvertKeyEntryToBuffer(phKeyStore_SamAV3_DataParams_t * pDataParams, phKeyStore_SamAV3_KeyEntry_t * pKeyEntry,
	uint8_t * pKey, uint8_t bKeyLen, uint8_t * pKeyEntryBuff, uint8_t * pKeyEntryBuffLen);

/**
 * Sets the KeyType of the key entry.
 *
 * Input Parameters:
 *		pKeyEntry		: Pointer to Key Entry structure.
 *		wKeyType		: The key type of the KeyEntry.
 *		b2K3DESOption	: Option to represent the different DES key types.
 *		bIsLRPKey		: Option to represent that the AES key to be used is for LRP.
 *
 * Return:
 *			PH_ERR_SUCCESS for successfull operation.
 *			Other Depending on implementation and underlaying component.
 */
phStatus_t phKeyStore_SamAV3_Int_SetKeyType(phKeyStore_SamAV3_KeyEntry_t * pKeyEntry, uint16_t wKeyType, uint8_t b2K3DESOption, uint8_t bIsLRPKey);

/**
 * Gets the KeyType of the key entry.
 *
 * Input Parameters:
 *		pKeyEntry		 : Pointer to Key Entry structure.
 *
 * Output Parameters:
 *		pKeyType		 : The key type of the KeyEntry.
 *		pIsLRPKey		 : Is the key type represents LRP key.
 *
 * Return:
 *			PH_ERR_SUCCESS for successfull operation.
 *			Other Depending on implementation and underlaying component.
 */
phStatus_t phKeyStore_SamAV3_Int_GetKeyType(phKeyStore_SamAV3_KeyEntry_t * pKeyEntry, uint16_t * pKeyType, uint8_t * pIsLRPKey);

/**
 * Gets the size of key.
 *
 * Input Parameters:
 *		wKeyType		 : The key type.
 *
 * Output Parameters:
 *		pKeySize		 : The size of key for the provided key type.
 *
 * Return:
 *			PH_ERR_SUCCESS for successfull operation.
 *			Other Depending on implementation and underlaying component.
 */
phStatus_t phKeyStore_SamAV3_Int_GetKeySize(uint16_t wKeyType, uint8_t * pKeySize);

#endif /* PHKEYSTORE_SAMAV3_INT_H */
