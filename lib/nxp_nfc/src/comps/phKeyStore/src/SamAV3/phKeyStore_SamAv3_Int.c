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

#include <nxp_nfc/ph_Status.h>
#include <nxp_nfc/ph_RefDefs.h>
#include <nxp_nfc/phhalHw.h>

#ifdef NXPBUILD__PH_KEYSTORE_SAMAV3

#include <nxp_nfc/phhalHw_SamAv3_Cmd.h>
#include "phKeyStore_SamAv3.h"
#include "phKeyStore_SamAv3_Int.h"
#include "../../../phhalHw/src/SamAV3/phhalHw_SamAv3.h"

/**
 * Gets the inforamtion available in the key entry structure.
 *
 * Input Parameters:
 *		pDataParams		 : Pointer to this layer's parameter structure.
 *		bKeyNo			 : The key number to used for retreiving the key entry information form Sam hardware.
 *
 * Output Parameters:
 *		pKeyEntry		 : The key entry information for the mentioned key number.
 *
 * Return:
 *			PH_ERR_SUCCESS for successfull operation.
 *			Other Depending on implementation and underlaying component.
 */
phStatus_t phKeyStore_SamAV3_Int_GetKeyEntry(phKeyStore_SamAV3_DataParams_t * pDataParams, uint8_t bKeyNo, uint8_t bIsRamKey,
    phKeyStore_SamAV3_KeyEntry_t * pKeyEntry)
{
	phStatus_t	PH_MEMLOC_REM wStatus = 0;
	uint16_t	PH_MEMLOC_REM wHostMode = 0;
	uint8_t		PH_MEMLOC_REM bKeyEntryFormat = 0;
	uint8_t		PH_MEMLOC_REM aKeyEntryBuff[PHHAL_HW_SAMAV3_KEYENTRY_SIZE];
	uint8_t		PH_MEMLOC_REM bKeyEntryLen = 0;
	uint8_t		PH_MEMLOC_REM bKeyEntryOffset = 0;

	/* Get the Host Mode. */
	PH_CHECK_SUCCESS_FCT(wStatus, phhalHw_SamAV3_GetConfig(
		pDataParams->pHalDataParams,
		PHHAL_HW_SAMAV3_CONFIG_HOSTMODE,
		&wHostMode));

	/* Set the Key entry format to be used for NVM keys. */
	if(!bIsRamKey)
	{
		bKeyEntryFormat = (uint8_t) (wHostMode == PHHAL_HW_SAMAV3_HC_AV2_MODE) ? PHHAL_HW_SAMAV3_CMD_SAM_GET_KEY_ENTRY_KEY_ENTRY_SAM_AV2 :
			PHHAL_HW_SAMAV3_CMD_SAM_GET_KEY_ENTRY_KEY_ENTRY_NEW;
	}

	/* Get the key entry information from Sam.  */
	PH_CHECK_SUCCESS_FCT(wStatus, phhalHw_SamAV3_Cmd_SAM_GetKeyEntry(
		pDataParams->pHalDataParams,
		bKeyNo,
		bKeyEntryFormat,
		aKeyEntryBuff,
		&bKeyEntryLen));

	/* Clear the Key data member. */
	memset(pKeyEntry->aKeyData, 0x00, 48);	/* PRQA S 3200 */

	/* Update the version members. */
	switch(bKeyEntryLen)
	{
		case PH_KEYSTORE_SAMAV3_KEY_ENTRY_LEN_SAMAV2_FORMAT_VER_ABC:
		case PH_KEYSTORE_SAMAV3_KEY_ENTRY_LEN_SAMAV3_FORMAT_VER_ABC:
			pKeyEntry->bVersionKeyA = aKeyEntryBuff[bKeyEntryOffset++];
            pKeyEntry->bVersionKeyB = aKeyEntryBuff[bKeyEntryOffset++];
			pKeyEntry->bVersionKeyC = aKeyEntryBuff[bKeyEntryOffset++];

			pKeyEntry->bVersionKeyBValid = PH_ON;
			pKeyEntry->bVersionKeyCValid = PH_ON;
			break;

		case PH_KEYSTORE_SAMAV3_KEY_ENTRY_LEN_SAMAV2_FORMAT_VER_AB:
		case PH_KEYSTORE_SAMAV3_KEY_ENTRY_LEN_SAMAV3_FORMAT_VER_AB:
			pKeyEntry->bVersionKeyA = aKeyEntryBuff[bKeyEntryOffset++];
            pKeyEntry->bVersionKeyB = aKeyEntryBuff[bKeyEntryOffset++];
			pKeyEntry->bVersionKeyC = 0x00;

			pKeyEntry->bVersionKeyBValid = PH_ON;
			pKeyEntry->bVersionKeyCValid = PH_OFF;
			break;

		case PH_KEYSTORE_SAMAV3_KEY_ENTRY_LEN_SAMAV3_FORMAT_VER_A:
			pKeyEntry->bVersionKeyA = aKeyEntryBuff[bKeyEntryOffset++];
            pKeyEntry->bVersionKeyB = 0x00;
			pKeyEntry->bVersionKeyC = 0x00;

			pKeyEntry->bVersionKeyBValid = PH_OFF;
			pKeyEntry->bVersionKeyCValid = PH_OFF;
			break;

		case PH_KEYSTORE_SAMAV3_KEY_ENTRY_LEN_SAMAV3_RAM_KEY:
			pKeyEntry->bVersionKeyA = 0x00;
            pKeyEntry->bVersionKeyB = 0x00;
			pKeyEntry->bVersionKeyC = 0x00;

			pKeyEntry->bVersionKeyBValid = PH_OFF;
			pKeyEntry->bVersionKeyCValid = PH_OFF;
			break;

		default:
			return PH_ADD_COMPCODE(PH_ERR_LENGTH_ERROR, PH_COMP_KEYSTORE);
	}

	/* Update DF_AID and DF_KeyNo members. */
	if(!bIsRamKey)
	{
		memcpy(pKeyEntry->aDFAid, &aKeyEntryBuff[bKeyEntryOffset], 3);	/* PRQA S 3200 */
		bKeyEntryOffset += (uint8_t) 3;

		pKeyEntry->bDFKeyNo   = aKeyEntryBuff[bKeyEntryOffset++];
	}

	/* Update KeyNo and KeyV members for Change Entry Key. */
	pKeyEntry->bKeyNoCEK  = aKeyEntryBuff[bKeyEntryOffset++];
	pKeyEntry->bKeyVCEK   = aKeyEntryBuff[bKeyEntryOffset++];

	/* Update member for Reference number of Key Usage Counter. */
	pKeyEntry->bRefNoKUC  = aKeyEntryBuff[bKeyEntryOffset++];

	/* Update SET configuration member. */
	memcpy(pKeyEntry->aSet, &aKeyEntryBuff[bKeyEntryOffset], 2);	/* PRQA S 3200 */
	bKeyEntryOffset += (uint8_t) 2;

	/* Update ExtSET configuration member. */
	pKeyEntry->aExtSet[0] = aKeyEntryBuff[bKeyEntryOffset++];
	pKeyEntry->aExtSet[1] = 0x00;

	/* Update ExtSet and KeyNo / KeyV of Access Key Entry in case of SamAV3. */
	if(wHostMode == PHHAL_HW_SAMAV3_HC_AV3_MODE)
	{
		/* Update ExtSET configuration member. */
		pKeyEntry->aExtSet[1] = aKeyEntryBuff[bKeyEntryOffset++];

		/* Update KeyNo and KeyV members of Access Entry Key. */
		pKeyEntry->bKeyNoAEK = aKeyEntryBuff[bKeyEntryOffset++];
		pKeyEntry->bKeyVAEK  = aKeyEntryBuff[bKeyEntryOffset++];
	}

    return PH_ADD_COMPCODE(PH_ERR_SUCCESS, PH_COMP_KEYSTORE);
}

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
	uint8_t * pKey, uint8_t bKeyLen, uint8_t * pKeyEntryBuff, uint8_t * pKeyEntryBuffLen)
{
	phStatus_t	PH_MEMLOC_REM wStatus = 0;
	uint16_t	PH_MEMLOC_REM wHostMode = 0;
	uint8_t		PH_MEMLOC_REM bKeyEntryBuffLen = 0;

	/* Get the Host Mode. */
	PH_CHECK_SUCCESS_FCT(wStatus, phhalHw_SamAV3_GetConfig(
		pDataParams->pHalDataParams,
		PHHAL_HW_SAMAV3_CONFIG_HOSTMODE,
		&wHostMode));

	/* Reset the Key Entry buffer. */
	memset(pKeyEntryBuff, 0x00, PHHAL_HW_SAMAV3_KEYENTRY_SIZE);			/* PRQA S 3200 */

	/* Copy the Key information to KeyEntry buffer. */
	memcpy(pKeyEntryBuff, pKey, bKeyLen);								/* PRQA S 3200 */
	bKeyEntryBuffLen += (uint8_t) ( PH_KEYSTORE_KEY_TYPE_AES128_SIZE * 3);

	/* Copy DF_AID to KeyEntry buffer. */
	memcpy(&pKeyEntryBuff[bKeyEntryBuffLen], pKeyEntry->aDFAid, 3);		/* PRQA S 3200 */
	bKeyEntryBuffLen += (uint8_t) 3;

    /* Copy DF_KeyNo to KeyEntry buffer. */
	pKeyEntryBuff[bKeyEntryBuffLen++] = pKeyEntry->bDFKeyNo;

	/* Copy KeyNo and KeyVer of Change Entry Key to KeyEntry buffer. */
    pKeyEntryBuff[bKeyEntryBuffLen++] = pKeyEntry->bKeyNoCEK;
    pKeyEntryBuff[bKeyEntryBuffLen++] = pKeyEntry->bKeyVCEK;

	/* Copy Reference number of Key Usage Counter to KeyEntry buffer. */
    pKeyEntryBuff[bKeyEntryBuffLen++] = pKeyEntry->bRefNoKUC;

	/* Copy SET configuration to KeyEntry buffer. */
	memcpy(&pKeyEntryBuff[bKeyEntryBuffLen], pKeyEntry->aSet, 2);		/* PRQA S 3200 */
	bKeyEntryBuffLen += (uint8_t) 2;

    /* Copy Versions to KeyEntry buffer. */
    pKeyEntryBuff[bKeyEntryBuffLen++] = pKeyEntry->bVersionKeyA;
    pKeyEntryBuff[bKeyEntryBuffLen++] = pKeyEntry->bVersionKeyB;
    pKeyEntryBuff[bKeyEntryBuffLen++] = pKeyEntry->bVersionKeyC;

	/* Copy ExtSET configuration to KeyEntry buffer. */
    pKeyEntryBuff[bKeyEntryBuffLen++] = pKeyEntry->aExtSet[0];

	/* Copy ExtSET configuration and KeyNo / KeyVer of Access Entry Key. */
	if(wHostMode == PHHAL_HW_SAMAV3_HC_AV3_MODE)
	{
		/* Copy ExtSET configuration */
		pKeyEntryBuff[bKeyEntryBuffLen++] = pKeyEntry->aExtSet[1];

		/*  */
		pKeyEntryBuff[bKeyEntryBuffLen++] = pKeyEntry->bKeyNoAEK;
		pKeyEntryBuff[bKeyEntryBuffLen++] = pKeyEntry->bKeyVAEK;
	}

	/* Update the Buffer length parameter. */
	*pKeyEntryBuffLen = bKeyEntryBuffLen;

    return PH_ADD_COMPCODE(PH_ERR_SUCCESS, PH_COMP_KEYSTORE);
}

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
phStatus_t phKeyStore_SamAV3_Int_SetKeyType(phKeyStore_SamAV3_KeyEntry_t * pKeyEntry, uint16_t wKeyType, uint8_t b2K3DESOption, uint8_t bIsLRPKey)
{
	switch(wKeyType)
	{
		case PH_KEYSTORE_KEY_TYPE_AES128:
			if(bIsLRPKey)
			{
				pKeyEntry->aSet[0] |= (uint8_t)(PH_KEYSTORE_SAMAV3_KEYTYPE_LRP_AES128_MASK << 3);
			}
			else
			{
				pKeyEntry->aSet[0] |= (uint8_t)(PH_KEYSTORE_SAMAV3_KEYTYPE_AES128_MASK << 3);
			}

			pKeyEntry->bVersionKeyBValid = 0x01;
			pKeyEntry->bVersionKeyCValid = 0x01;
			break;

		case PH_KEYSTORE_KEY_TYPE_AES192:
			pKeyEntry->aSet[0] |= (uint8_t)(PH_KEYSTORE_SAMAV3_KEYTYPE_AES192_MASK << 3);
			pKeyEntry->bVersionKeyBValid = 0x01;
			pKeyEntry->bVersionKeyCValid = 0x00;
			break;

		case PH_KEYSTORE_KEY_TYPE_AES256:
			pKeyEntry->aSet[0] |= (uint8_t) (PH_KEYSTORE_SAMAV3_KEYTYPE_AES256_MASK << 3);
			pKeyEntry->bVersionKeyBValid = 0x00;
			pKeyEntry->bVersionKeyCValid = 0x00;
			break;

		case PH_KEYSTORE_KEY_TYPE_DES:
		case PH_KEYSTORE_KEY_TYPE_2K3DES:
			if (b2K3DESOption == PH_KEYSTORE_SAMAV3_DES_OPTION_DESFIRE4)
			{
				pKeyEntry->aSet[0] |= (uint8_t)(PH_KEYSTORE_SAMAV3_KEYTYPE_3DESDF4_MASK << 3);
			}
			else if (b2K3DESOption == PH_KEYSTORE_SAMAV3_DES_OPTION_ISO_CRC16)
			{
				pKeyEntry->aSet[0] |= (uint8_t)(PH_KEYSTORE_SAMAV3_KEYTYPE_2K3DES_MASK << 3);
			}
			else if (b2K3DESOption == PH_KEYSTORE_SAMAV3_DES_OPTION_ISO_CRC32)
			{
				pKeyEntry->aSet[0] |= (uint8_t)(PH_KEYSTORE_SAMAV3_KEYTYPE_2K3DESDF8_MASK << 3);
			}
			else
			{
				return PH_ADD_COMPCODE(PH_ERR_INVALID_PARAMETER, PH_COMP_KEYSTORE);
			}

			pKeyEntry->bVersionKeyBValid = 0x01;
			pKeyEntry->bVersionKeyCValid = 0x01;
			break;

		case PH_KEYSTORE_KEY_TYPE_3K3DES:
			pKeyEntry->aSet[0] |= (uint8_t)(PH_KEYSTORE_SAMAV3_KETYPE_3K3DES_MASK << 3);
			pKeyEntry->bVersionKeyBValid = 0x01;
			pKeyEntry->bVersionKeyCValid = 0x00;
			break;

		case PH_KEYSTORE_KEY_TYPE_MIFARE:
			pKeyEntry->aSet[0] |= (uint8_t)(PH_KEYSTORE_SAMAV3_KEYTYPE_MIFARE_MASK << 3);
			pKeyEntry->bVersionKeyBValid = 0x01;
			pKeyEntry->bVersionKeyCValid = 0x01;
			break;

		default:
			return PH_ADD_COMPCODE(PH_ERR_INVALID_PARAMETER, PH_COMP_KEYSTORE);
	}

	return PH_ADD_COMPCODE(PH_ERR_SUCCESS, PH_COMP_KEYSTORE);
}

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
phStatus_t phKeyStore_SamAV3_Int_GetKeyType(phKeyStore_SamAV3_KeyEntry_t * pKeyEntry, uint16_t * pKeyType, uint8_t * pIsLRPKey)
{
	/* Get the KeyType loaded to Keystore. */
	switch (((pKeyEntry->aSet[0] & PH_KEYSTORE_SAMAV3_KEYTYPE_MASK) >> 3))
	{
		case PH_KEYSTORE_SAMAV3_KEYTYPE_AES128_MASK:
			*pKeyType = PH_KEYSTORE_KEY_TYPE_AES128;
			*pIsLRPKey = PH_OFF;
			break;

		case PH_KEYSTORE_SAMAV3_KEYTYPE_LRP_AES128_MASK:
			*pKeyType = PH_KEYSTORE_KEY_TYPE_AES128;
			*pIsLRPKey = PH_ON;
			break;

		case PH_KEYSTORE_SAMAV3_KEYTYPE_AES192_MASK:
			*pKeyType = PH_KEYSTORE_KEY_TYPE_AES192;
			break;

		case PH_KEYSTORE_SAMAV3_KEYTYPE_AES256_MASK:
			*pKeyType = PH_KEYSTORE_KEY_TYPE_AES256;
			break;

		case PH_KEYSTORE_SAMAV3_KEYTYPE_2K3DES_MASK:
			*pKeyType = PH_KEYSTORE_KEY_TYPE_2K3DES;
			break;

		case PH_KEYSTORE_SAMAV3_KETYPE_3K3DES_MASK:
			*pKeyType = PH_KEYSTORE_KEY_TYPE_3K3DES;
			break;

		case PH_KEYSTORE_SAMAV3_KEYTYPE_MIFARE_MASK:
			*pKeyType = PH_KEYSTORE_KEY_TYPE_MIFARE;
			break;

		case PH_KEYSTORE_SAMAV3_KEYTYPE_3DESDF4_MASK:
			*pKeyType = PH_KEYSTORE_KEY_TYPE_2K3DES;
			break;

		case PH_KEYSTORE_SAMAV3_KEYTYPE_2K3DESDF8_MASK:
			*pKeyType = PH_KEYSTORE_KEY_TYPE_2K3DES;
			break;

		default:
			return PH_ADD_COMPCODE(PH_ERR_INVALID_PARAMETER, PH_COMP_KEYSTORE);
	}

	return PH_ADD_COMPCODE(PH_ERR_SUCCESS, PH_COMP_KEYSTORE);
}

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
phStatus_t phKeyStore_SamAV3_Int_GetKeySize(uint16_t wKeyType, uint8_t * pKeySize)
{
	switch (wKeyType)
	{
		case PH_KEYSTORE_KEY_TYPE_MIFARE:
		case PH_KEYSTORE_KEY_TYPE_AES128:
		case PH_KEYSTORE_KEY_TYPE_DES:
		case PH_KEYSTORE_KEY_TYPE_2K3DES:
			*pKeySize = 16;
			break;

		case PH_KEYSTORE_KEY_TYPE_AES192:
		case PH_KEYSTORE_KEY_TYPE_3K3DES:
			*pKeySize = 24;
			break;

		case PH_KEYSTORE_KEY_TYPE_AES256:
			*pKeySize = 32;
			break;

		default:
			return PH_ADD_COMPCODE(PH_ERR_INVALID_PARAMETER, PH_COMP_KEYSTORE);
	}

	return PH_ADD_COMPCODE(PH_ERR_SUCCESS, PH_COMP_KEYSTORE);
}

#endif /* NXPBUILD__PH_KEYSTORE_SAMAV3 */
