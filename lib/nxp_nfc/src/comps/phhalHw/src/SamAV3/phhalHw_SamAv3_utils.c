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

#include <nxp_nfc/ph_Status.h>
#include <nxp_nfc/ph_RefDefs.h>
#include <nxp_nfc/phKeyStore.h>
#include <nxp_nfc/phCryptoSym.h>

#ifdef NXPBUILD__PHHAL_HW_SAMAV3

#include <nxp_nfc/phhalHw_SamAv3_Cmd.h>
#include "phhalHw_SamAv3_utils.h"

/* Private constants */
static const uint8_t PH_MEMLOC_CONST_ROM phhalHw_SamAV3_HcUtils_FirstIv[PH_CRYPTOSYM_AES_BLOCK_SIZE] = { 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00};

phStatus_t phhalHw_SamAV3_Utils_GetCheckLcLe(uint8_t * pCmd, uint16_t wCmdLen, uint8_t * pIsLcPresent, uint8_t * pLcLen, uint8_t * pIsLePresent)
{
    /* There are four cases: */
    /*1 CLA INS P1 P2 */
    /*2 CLA INS P1 P2 LE */
    /*3 CLA INS P1 P2 LC DATA */
    /*4 CLA INS P1 P2 LC DATA LE */

    if (wCmdLen < PHHAL_HW_SAMAV3_ISO7816_HEADER_NO_LC_LENGTH)
    {
        return PH_ADD_COMPCODE(PH_ERR_FRAMING_ERROR, PH_COMP_HAL);
    }

    /* @1*/
    if (wCmdLen == PHHAL_HW_SAMAV3_ISO7816_HEADER_NO_LC_LENGTH)
    {
        *pLcLen = 0;
        *pIsLcPresent = PH_OFF;
        *pIsLePresent = PH_OFF;
    }

    /* @2*/
    else if (wCmdLen == PHHAL_HW_SAMAV3_ISO7816_HEADER_LENGTH)
    {
        *pLcLen = 0;
        *pIsLcPresent = PH_OFF;
        *pIsLePresent = PH_ON;
    }

    /* @3*/
    else if (wCmdLen == (PHHAL_HW_SAMAV3_ISO7816_HEADER_LENGTH + pCmd[PHHAL_HW_SAMAV3_ISO7816_LC_POS]))
    {
        *pLcLen = pCmd[PHHAL_HW_SAMAV3_ISO7816_LC_POS];
        *pIsLcPresent = PH_ON;
        *pIsLePresent = PH_OFF;
    }

    /* @4*/
    else if (wCmdLen == (PHHAL_HW_SAMAV3_ISO7816_HEADER_LE_LENGTH + pCmd[PHHAL_HW_SAMAV3_ISO7816_LC_POS]))
    {
        *pLcLen = pCmd[PHHAL_HW_SAMAV3_ISO7816_LC_POS];
        *pIsLcPresent = PH_ON;
        *pIsLePresent = PH_ON;
    }
	else
    {
        return PH_ADD_COMPCODE(PH_ERR_FRAMING_ERROR, PH_COMP_HAL);
    }

    return PH_ADD_COMPCODE(PH_ERR_SUCCESS, PH_COMP_HAL);
}

phStatus_t phhalHw_SamAV3_Utils_TruncateMacBuffer(uint8_t * pIoBuffer, uint8_t * pMacLen)
{
	uint8_t bCount, bTruncateCount = 0;

    for (bCount = 1; bCount < (*pMacLen); bCount += 2)
    {
        pIoBuffer[bTruncateCount++] = pIoBuffer[bCount] ;
    }

    *pMacLen = bTruncateCount;

    return PH_ADD_COMPCODE(PH_ERR_SUCCESS, PH_COMP_HAL);
}

phStatus_t phhalHw_SamAV3_Utils_ResolveErrorCode(uint8_t * pSw1Sw2)
{
    phStatus_t	PH_MEMLOC_REM wStatus = 0;

    switch((phStatus_t) ((pSw1Sw2[0] << 8) | pSw1Sw2[1]))
    {
		case  PHHAL_HW_SAMAV3_RET_CODE_HW_EEPROM:
			wStatus = PHHAL_HW_SAMAV3_ERR_HW_EEPROM;
			break;

		case PHHAL_HW_SAMAV3_RET_CODE_HW_RC5XX:
			wStatus = PHHAL_HW_SAMAV3_ERR_HW_RC5XX;
			break;

		case PHHAL_HW_SAMAV3_RET_CODE_KEY_CREATE_FAILED:
			wStatus = PHHAL_HW_SAMAV3_ERR_KEY_CREATE_FAILED;
			break;

		case PHHAL_HW_SAMAV3_RET_CODE_KEY_REF_NO_INVALID:
			wStatus = PHHAL_HW_SAMAV3_ERR_KEY_REF_NO_INVALID;
			break;

		case PHHAL_HW_SAMAV3_RET_CODE_KEY_KUC_NO_INVALID:
			wStatus = PHHAL_HW_SAMAV3_ERR_KEY_KUC_NO_INVALID;
			break;

		case PHHAL_HW_SAMAV3_RET_CODE_HW_EE_HIGH_VOLTAGE:
			wStatus = PHHAL_HW_SAMAV3_ERR_HW_EE_HIGH_VOLTAGE;
			break;

		case PHHAL_HW_SAMAV3_RET_CODE_ISO7816_WRONG_LENGTH_LC:
			wStatus = PHHAL_HW_SAMAV3_ERR_ISO7816_WRONG_LENGTH_LC;
			break;

		case PHHAL_HW_SAMAV3_RET_CODE_INCOMPLETE_REFERENCE_DATA:
			wStatus = PHHAL_HW_SAMAV3_ERR_INCOMPLETE_REFERENCE_DATA;
			break;

		case PHHAL_HW_SAMAV3_RET_CODE_SECURITY_STATUS_NOT_SATISFIED:
			wStatus = PHHAL_HW_SAMAV3_ERR_SECURITY_STATUS_NOT_SATISFIED;
			break;

		case PHHAL_HW_SAMAV3_RET_CODE_SECURE_MESSAGING_NOT_SUPPORTED:
			wStatus = PHHAL_HW_SAMAV3_ERR_SECURE_MESSAGING_NOT_SUPPORTED;
			break;

		case PHHAL_HW_SAMAV3_RET_CODE_INCOMPLETE_CHAINING:
			wStatus = PHHAL_HW_SAMAV3_ERR_INCOMPLETE_CHAINING;
			break;

		case PHHAL_HW_SAMAV3_RET_CODE_COMMAND_CHAINING_NOT_SUPPORTED:
			wStatus = PHHAL_HW_SAMAV3_ERR_COMMAND_CHAINING_NOT_SUPPORTED;
			break;

		case PHHAL_HW_SAMAV3_RET_CODE_INTEGRITY_ERROR:
			wStatus = PHHAL_HW_SAMAV3_ERR_INTEGRITY_ERROR;
			break;

		case PHHAL_HW_SAMAV3_RET_CODE_INCORRECT_LENGTH:
			wStatus = PHHAL_HW_SAMAV3_ERR_INCORRECT_LENGTH;
			break;

		case PHHAL_HW_SAMAV3_RET_CODE_KEY_INTEGRITY_ERROR:
			wStatus = PHHAL_HW_SAMAV3_ERR_KEY_INTEGRITY_ERROR;
			break;

		case PHHAL_HW_SAMAV3_RET_CODE_COND_USE_NOT_SATISFIED:
			wStatus = PHHAL_HW_SAMAV3_ERR_COND_USE_NOT_SATISFIED;
			break;

		case PHHAL_HW_SAMAV3_RET_CODE_ISO7816_COMMAND_NOT_ALLOWED:
			wStatus = PHHAL_HW_SAMAV3_ERR_ISO7816_COMMAND_NOT_ALLOWED;
			break;

		case PHHAL_HW_SAMAV3_RET_CODE_INCORRECT_SECURE_MESSAGING_DATA:
			wStatus = PHHAL_HW_SAMAV3_ERR_INCORRECT_SECURE_MESSAGING_DATA;
			break;

		case PHHAL_HW_SAMAV3_RET_CODE_ISO7816_WRONG_PARAMS_FOR_INS:
			wStatus = PHHAL_HW_SAMAV3_ERR_ISO7816_WRONG_PARAMS_FOR_INS;
			break;

		case PHHAL_HW_SAMAV3_RET_CODE_FUNCTION_NOT_SUPPORTED:
			wStatus = PHHAL_HW_SAMAV3_ERR_FUNCTION_NOT_SUPPORTED;
			break;

		case PHHAL_HW_SAMAV3_RET_CODE_KEY_VERSION_INVALID:
			wStatus = PHHAL_HW_SAMAV3_ERR_KEY_VERSION_INVALID;
			break;

		case PHHAL_HW_SAMAV3_RET_CODE_RECORD_NOT_FOUND:
			wStatus = PHHAL_HW_SAMAV3_ERR_RECORD_NOT_FOUND;
			break;

		case PHHAL_HW_SAMAV3_RET_CODE_HOST_PROTECTION_ERROR:
			wStatus = PHHAL_HW_SAMAV3_ERR_HOST_PROTECTION;
			break;

		case PHHAL_HW_SAMAV3_RET_CODE_ISO7816_WRONG_P1P2:
			wStatus = PHHAL_HW_SAMAV3_ERR_ISO7816_WRONG_P1P2;
			break;

		case PHHAL_HW_SAMAV3_RET_CODE_REFERENCED_DATA_NOT_FOUND:
			wStatus = PHHAL_HW_SAMAV3_ERR_REFERENCED_DATA_NOT_FOUND;
			break;

		case PHHAL_HW_SAMAV3_RET_CODE_ISO7816_WRONG_LE:
			wStatus = PHHAL_HW_SAMAV3_ERR_ISO7816_WRONG_LE;
			break;

		case PHHAL_HW_SAMAV3_RET_CODE_ISO7816_UNKNOWN_INS:
			wStatus = PHHAL_HW_SAMAV3_ERR_ISO7816_UNKNOWN_INS;
			break;

		case PHHAL_HW_SAMAV3_RET_CODE_ISO7816_WRONG_CLASS:
			wStatus = PHHAL_HW_SAMAV3_ERR_ISO7816_UNKNOWN_CLASS;
			break;

		case PHHAL_HW_SAMAV3_RET_CODE_NO_PRECISE_DIAGNOSIS:
			wStatus = PHHAL_HW_SAMAV3_ERR_NO_PRECISE_DIAGNOSIS;
			break;

		case PHHAL_HW_SAMAV3_RET_CODE_OK:
			wStatus = PH_ERR_SUCCESS;
			break;

		case PHHAL_HW_SAMAV3_RET_CODE_OK_1BIT:
		case PHHAL_HW_SAMAV3_RET_CODE_OK_2BIT:
		case PHHAL_HW_SAMAV3_RET_CODE_OK_3BIT:
		case PHHAL_HW_SAMAV3_RET_CODE_OK_4BIT:
		case PHHAL_HW_SAMAV3_RET_CODE_OK_5BIT:
		case PHHAL_HW_SAMAV3_RET_CODE_OK_6BIT:
		case PHHAL_HW_SAMAV3_RET_CODE_OK_7BIT:
			wStatus = PH_ERR_SUCCESS_INCOMPLETE_BYTE;
			break;

		case PHHAL_HW_SAMAV3_RET_CODE_CRYPTO_FAILURE:
			wStatus = PHHAL_HW_SAMAV3_ERR_CRYPTO;
			break;

		case PHHAL_HW_SAMAV3_RET_CODE_OK_CHAINING_ACTIVE:
			wStatus = PHHAL_HW_SAMAV3_ERR_OK_CHAINING_ACTIVE;
			break;

		case PHHAL_HW_SAMAV3_RET_CODE_PROT_MIFARE_PLUS_ERROR:
			wStatus = PHHAL_HW_SAMAV3_ERR_MIFARE_PLUS_CRYPTO;
			break;

		case PHHAL_HW_SAMAV3_RET_CODE_INS_MIFARE_PLUS_ERROR:
			wStatus = PHHAL_HW_SAMAV3_ERR_MIFARE_PLUS_GEN;
			break;

		case PHHAL_HW_SAMAV3_RET_CODE_ISO_UID_INCOMPLETE:
			wStatus = PHHAL_HW_SAMAV3_ERR_ISO_UID_INCOMPLETE;
			break;

		case PHHAL_HW_SAMAV3_RET_CODE_PROT_DESFIRE_ERROR:
			wStatus = PHHAL_HW_SAMAV3_ERR_DESFIRE_GEN;
			break;

		case PHHAL_HW_SAMAV3_RET_CODE_COMM_IO_TIMEOUT:
			wStatus = PH_ERR_IO_TIMEOUT;
			break;

		case PHHAL_HW_SAMAV3_RET_CODE_COMM_BITCNT_PROTOCOL:
			wStatus = PH_ERR_PROTOCOL_ERROR;
			break;

		case PHHAL_HW_SAMAV3_RET_CODE_COMM_PARITY:
		case PHHAL_HW_SAMAV3_RET_CODE_COMM_CRC_FAILURE:
			wStatus = PH_ERR_INTEGRITY_ERROR;
			break;

		case PHHAL_HW_SAMAV3_RET_CODE_COMM_FIFO_BUF_OVERFLOW:
			wStatus = PH_ERR_BUFFER_OVERFLOW;
			break;

		case PHHAL_HW_SAMAV3_RET_CODE_COMM_RF_FAILURE:
			wStatus = PH_ERR_RF_ERROR;
			break;

		case PHHAL_HW_SAMAV3_RET_CODE_COMM_TEMP_FAILURE:
			wStatus = PH_ERR_TEMPERATURE_ERROR;
			break;

		case PHHAL_HW_SAMAV3_RET_CODE_COMM_FIFO_WRITE:
			wStatus = PH_ERR_READ_WRITE_ERROR;
			break;

		case PHHAL_HW_SAMAV3_RET_CODE_COMM_COLLISION:
			wStatus = PH_ERR_COLLISION_ERROR;
			break;

		case PHHAL_HW_SAMAV3_RET_CODE_COMM_INTERNAL_BUF_OVERFLOW:
			wStatus = PH_ERR_BUFFER_OVERFLOW;
			break;

		case PHHAL_HW_SAMAV3_RET_CODE_ISO_WRONG_BNR:
			wStatus = PHHAL_HW_SAMAV3_ERR_ISO_WRONG_BNR;
			break;

		case PHHAL_HW_SAMAV3_RET_CODE_ISO_INVALID_FORMAT:
			wStatus = PHHAL_HW_SAMAV3_ERR_ISO_INVALID_FORMAT;
			break;

		case PHHAL_HW_SAMAV3_RET_CODE_ISO_INVALID_PARAMETER:
			wStatus = PHHAL_HW_SAMAV3_ERR_ISO_INVALID_PARAMETER;
			break;

		case PHHAL_HW_SAMAV3_RET_CODE_PROT_MIFARE_ERROR:
			wStatus = PHHAL_HW_SAMAV3_ERR_MIFARE_GEN;
			break;

		case PHHAL_HW_SAMAV3_RET_CODE_PROT_MIFARE_NACK_0:
			wStatus = PHHAL_HW_SAMAV3_ERR_MIFARE_NAK0;
			break;

		case PHHAL_HW_SAMAV3_RET_CODE_PROT_MIFARE_NACK_1:
			wStatus = PHHAL_HW_SAMAV3_ERR_MIFARE_NAK1;
			break;

		case PHHAL_HW_SAMAV3_RET_CODE_PROT_MIFARE_NACK_4:
			wStatus = PHHAL_HW_SAMAV3_ERR_MIFARE_NAK4;
			break;

		case PHHAL_HW_SAMAV3_RET_CODE_PROT_MIFARE_NACK_5:
			wStatus = PHHAL_HW_SAMAV3_ERR_MIFARE_NAK5;
			break;

		case PHHAL_HW_SAMAV3_RET_CODE_OK_CHAINING_ACTIVE_EXT:
			wStatus = PHHAL_HW_SAMAV3_ERR_OK_CHAINING_ACTIVE_EXT;
			break;

		default:
			wStatus = PHHAL_HW_SAMAV3_ERR_PROGRAMMABLE_LOGIC;
			break;
	}

	return PH_ADD_COMPCODE(wStatus, PH_COMP_HAL);
}

phStatus_t phhalHw_SamAV3_Utils_GenerateHostAuthSessionKey(phhalHw_SamAV3_DataParams_t * pDataParams, uint8_t bKeyType, uint8_t * pRnd1, uint8_t * pRnd2,
	uint8_t * pSessionKey, uint8_t * pKeyLen)
{
	phStatus_t	PH_MEMLOC_REM wStatus = 0;
	uint8_t		PH_MEMLOC_REM aSv1a[PH_CRYPTOSYM_AES_BLOCK_SIZE];
	uint8_t		PH_MEMLOC_REM aSv1b[PH_CRYPTOSYM_AES_BLOCK_SIZE];
	uint8_t		PH_MEMLOC_REM aKxea[PH_CRYPTOSYM_AES_BLOCK_SIZE];
	uint8_t		PH_MEMLOC_REM aKxeb[PH_CRYPTOSYM_AES_BLOCK_SIZE];
	uint8_t		PH_MEMLOC_COUNT bCount = 0;

	/* Frame the session vector A. */
	memcpy(&aSv1a[0], &pRnd1[7], 5);			/* PRQA S 3200 */
	memcpy(&aSv1a[5], &pRnd2[7], 5);			/* PRQA S 3200 */
	aSv1a[10] = pRnd1[0] ^ pRnd2[0];
	aSv1a[11] = pRnd1[1] ^ pRnd2[1];
	aSv1a[12] = pRnd1[2] ^ pRnd2[2];
	aSv1a[13] = pRnd1[3] ^ pRnd2[3];
	aSv1a[14] = pRnd1[4] ^ pRnd2[4];

	/* Frame the session vector B. */
	memcpy(&aSv1b[0], &pRnd1[6], 5);			/* PRQA S 3200 */
	memcpy(&aSv1b[5], &pRnd2[6], 5);			/* PRQA S 3200 */
	aSv1b[10] = pRnd1[1] ^ pRnd2[1];
	aSv1b[11] = pRnd1[2] ^ pRnd2[2];
	aSv1b[12] = pRnd1[3] ^ pRnd2[3];
	aSv1b[13] = pRnd1[4] ^ pRnd2[4];
	aSv1b[14] = pRnd1[5] ^ pRnd2[5];

	/* Load initial IV. */
	PH_CHECK_SUCCESS_FCT(wStatus, phCryptoSym_LoadIv(
		pDataParams->pMACCryptoDataParams,
		phhalHw_SamAV3_HcUtils_FirstIv,
		PH_CRYPTOSYM_AES_BLOCK_SIZE));

	/* Add the constant according to keytype and calculate the session key. */
	switch (bKeyType)
	{
		case PH_CRYPTOSYM_KEY_TYPE_AES128:
			aSv1a[15] = 0x91;

			/* Calculate the session key using session vector A. */
			PH_CHECK_SUCCESS_FCT(wStatus, phCryptoSym_Encrypt(
				pDataParams->pMACCryptoDataParams,
				PH_CRYPTOSYM_CIPHER_MODE_CBC,
				aSv1a,
				PH_CRYPTOSYM_AES_BLOCK_SIZE,
				pSessionKey));

			/* Update the Session key length. */
			*pKeyLen = PH_CRYPTOSYM_AES128_KEY_SIZE;
			break;

		case PH_CRYPTOSYM_KEY_TYPE_AES192:
			aSv1a[15] = 0x93;
			aSv1b[15] = 0x94;

			/* Calculate the session key using session vector A. */
			PH_CHECK_SUCCESS_FCT(wStatus, phCryptoSym_Encrypt(
				pDataParams->pMACCryptoDataParams,
				PH_CRYPTOSYM_CIPHER_MODE_CBC,
				aSv1a,
				PH_CRYPTOSYM_AES_BLOCK_SIZE,
				aKxea));

			/* Calculate the session key using session vector B. */
			PH_CHECK_SUCCESS_FCT(wStatus, phCryptoSym_Encrypt(
				pDataParams->pMACCryptoDataParams,
				PH_CRYPTOSYM_CIPHER_MODE_CBC,
				aSv1b,
				PH_CRYPTOSYM_AES_BLOCK_SIZE,
				aKxeb));

			/* Copy calculated Session Key A to Session key parameter. */
			memcpy(pSessionKey, aKxea, PH_CRYPTOSYM_AES_BLOCK_SIZE);  /* PRQA S 3200 */

			/* XOR calculated Session Key A with calculated Session Key B. */
			for (bCount = 0; bCount <= 7; ++bCount)
				pSessionKey[bCount + 8] ^= aKxeb[bCount];

			/* Copy remaining Session Key B to Session key parameter. */
			memcpy(&pSessionKey[16], &aKxeb[8], 8); /* PRQA S 3200 */

			/* Update the Session key length. */
			*pKeyLen = PH_CRYPTOSYM_AES192_KEY_SIZE;
			break;

		case PH_CRYPTOSYM_KEY_TYPE_AES256:
			aSv1a[15] = 0x95;
			aSv1b[15] = 0x96;

			/* Calculate the session key using session vector A. */
			PH_CHECK_SUCCESS_FCT(wStatus, phCryptoSym_Encrypt(
				pDataParams->pMACCryptoDataParams,
				PH_CRYPTOSYM_CIPHER_MODE_CBC,
				aSv1a,
				PH_CRYPTOSYM_AES_BLOCK_SIZE,
				aKxea));

			/* Calculate the session key using session vector B. */
			PH_CHECK_SUCCESS_FCT(wStatus, phCryptoSym_Encrypt(
				pDataParams->pMACCryptoDataParams,
				PH_CRYPTOSYM_CIPHER_MODE_CBC,
				aSv1b,
				PH_CRYPTOSYM_AES_BLOCK_SIZE,
				aKxeb));

			/* Compute the session key. */
			/* Kxe = Kxea || Kxeb */
			memcpy(&pSessionKey[0], aKxea, 16);    /* PRQA S 3200 */
			memcpy(&pSessionKey[16], aKxeb, 16);    /* PRQA S 3200 */
			break;

		default:
			return PH_ADD_COMPCODE(PH_ERR_INTERNAL_ERROR, PH_COMP_HAL);
	}

	return PH_ADD_COMPCODE(PH_ERR_SUCCESS, PH_COMP_HAL);
}

phStatus_t phhalHw_SamAV3_Utils_GenerateSessionKey(phhalHw_SamAV3_DataParams_t * pDataParams, uint8_t bKeyType, uint8_t * pRnd1, uint8_t * pRnd2,
	uint8_t * pSessionEncKey, uint8_t * pSessionMacKey, uint8_t * pKeyLen)
{
	phStatus_t	PH_MEMLOC_REM wStatus = 0;
	uint8_t		PH_MEMLOC_REM bCount = 0;
	uint8_t		PH_MEMLOC_REM aSv1a[PH_KEYSTORE_KEY_TYPE_AES128_SIZE];
	uint8_t		PH_MEMLOC_REM aSv1b[PH_KEYSTORE_KEY_TYPE_AES128_SIZE];
	uint8_t		PH_MEMLOC_REM aSv2a[PH_KEYSTORE_KEY_TYPE_AES128_SIZE];
	uint8_t		PH_MEMLOC_REM aSv2b[PH_KEYSTORE_KEY_TYPE_AES128_SIZE];
	uint8_t		PH_MEMLOC_REM aSessionEncKeyA[PH_KEYSTORE_KEY_TYPE_AES128_SIZE];
	uint8_t		PH_MEMLOC_REM aSessionEncKeyB[PH_KEYSTORE_KEY_TYPE_AES128_SIZE];
	uint8_t		PH_MEMLOC_REM aSessionMacKeyA[PH_KEYSTORE_KEY_TYPE_AES128_SIZE];
	uint8_t		PH_MEMLOC_REM aSessionMacKeyB[PH_KEYSTORE_KEY_TYPE_AES128_SIZE];

	/* Frame the session vector 1A. */
	memcpy(&aSv1a[0], &pRnd1[11], 5);		/* PRQA S 3200 */
	memcpy(&aSv1a[5], &pRnd2[11], 5);		/* PRQA S 3200 */
	aSv1a[10] = pRnd1[4] ^ pRnd2[4];
	aSv1a[11] = pRnd1[5] ^ pRnd2[5];
	aSv1a[12] = pRnd1[6] ^ pRnd2[6];
	aSv1a[13] = pRnd1[7] ^ pRnd2[7];
	aSv1a[14] = pRnd1[8] ^ pRnd2[8];

	/* Frame the session vector 2A. */
	memcpy(&aSv2a[0], &pRnd1[7], 5);		/* PRQA S 3200 */
	memcpy(&aSv2a[5], &pRnd2[7], 5);		/* PRQA S 3200 */
	aSv2a[10] = pRnd1[0] ^ pRnd2[0];
	aSv2a[11] = pRnd1[1] ^ pRnd2[1];
	aSv2a[12] = pRnd1[2] ^ pRnd2[2];
	aSv2a[13] = pRnd1[3] ^ pRnd2[3];
	aSv2a[14] = pRnd1[4] ^ pRnd2[4];

	/* Frame the session vector 1B. */
	memcpy(&aSv1b[0], &pRnd1[10], 5);		/* PRQA S 3200 */
	memcpy(&aSv1b[5], &pRnd2[10], 5);		/* PRQA S 3200 */
	aSv1b[10] = pRnd1[5] ^ pRnd2[5];
	aSv1b[11] = pRnd1[6] ^ pRnd2[6];
	aSv1b[12] = pRnd1[7] ^ pRnd2[7];
	aSv1b[13] = pRnd1[8] ^ pRnd2[8];
	aSv1b[14] = pRnd1[9] ^ pRnd2[9];

	/* Frame the session vector 2B. */
	memcpy(&aSv2b[0], &pRnd1[6], 5);		/* PRQA S 3200 */
	memcpy(&aSv2b[5], &pRnd2[6], 5);		/* PRQA S 3200 */
	aSv2b[10] = pRnd1[1] ^ pRnd2[1];
	aSv2b[11] = pRnd1[2] ^ pRnd2[2];
	aSv2b[12] = pRnd1[3] ^ pRnd2[3];
	aSv2b[13] = pRnd1[4] ^ pRnd2[4];
	aSv2b[14] = pRnd1[5] ^ pRnd2[5];

	/* Load initial IV. */
	PH_CHECK_SUCCESS_FCT(wStatus, phCryptoSym_LoadIv(
		pDataParams->pMACCryptoDataParams,
		phhalHw_SamAV3_HcUtils_FirstIv,
		PH_CRYPTOSYM_AES_BLOCK_SIZE));

	/* Add the constant according to keytype and calculate the session key. */
	switch(bKeyType)
	{
		case PH_KEYSTORE_KEY_TYPE_AES128:
			aSv1a[15] = 0x81;
			aSv2a[15] = 0x82;

			/* Calculate the session encryption key using session vector 1A. */
			PH_CHECK_SUCCESS_FCT(wStatus, phCryptoSym_Encrypt(
				pDataParams->pMACCryptoDataParams,
				PH_CRYPTOSYM_CIPHER_MODE_CBC,
				aSv1a,
				PH_CRYPTOSYM_AES_BLOCK_SIZE,
				pSessionEncKey));

			/* Calculate the session mac key using session vector 2A. */
			PH_CHECK_SUCCESS_FCT(wStatus, phCryptoSym_Encrypt(
				pDataParams->pMACCryptoDataParams,
				PH_CRYPTOSYM_CIPHER_MODE_CBC,
				aSv2a,
				PH_CRYPTOSYM_AES_BLOCK_SIZE,
				pSessionMacKey));

			/* Update the Session key length. */
			*pKeyLen = PH_CRYPTOSYM_AES128_KEY_SIZE;
			break;

		case PH_KEYSTORE_KEY_TYPE_AES192:
			aSv1a[15] = 0x83;
			aSv1b[15] = 0x84;
			aSv2a[15] = 0x85;
			aSv2b[15] = 0x86;

			/* Calculate the session encryption key A using session vector 1A. */
			PH_CHECK_SUCCESS_FCT(wStatus, phCryptoSym_Encrypt(
				pDataParams->pMACCryptoDataParams,
				PH_CRYPTOSYM_CIPHER_MODE_CBC,
				aSv1a,
				PH_CRYPTOSYM_AES_BLOCK_SIZE,
				aSessionEncKeyA));

			/* Calculate the session encryption key B using session vector 1B. */
			PH_CHECK_SUCCESS_FCT(wStatus, phCryptoSym_Encrypt(
				pDataParams->pMACCryptoDataParams,
				PH_CRYPTOSYM_CIPHER_MODE_CBC,
				aSv1b,
				PH_CRYPTOSYM_AES_BLOCK_SIZE,
				aSessionEncKeyB));

			/* Calculate the session mac key A using session vector 2A. */
			PH_CHECK_SUCCESS_FCT(wStatus, phCryptoSym_Encrypt(
				pDataParams->pMACCryptoDataParams,
				PH_CRYPTOSYM_CIPHER_MODE_CBC,
				aSv2a,
				PH_CRYPTOSYM_AES_BLOCK_SIZE,
				aSessionMacKeyA));

			/* Calculate the session mac key B using session vector 2B. */
			PH_CHECK_SUCCESS_FCT(wStatus, phCryptoSym_Encrypt(
				pDataParams->pMACCryptoDataParams,
				PH_CRYPTOSYM_CIPHER_MODE_CBC,
				aSv2b,
				PH_CRYPTOSYM_AES_BLOCK_SIZE,
				aSessionMacKeyB));

			/* Copy calculated Enc Session Key A to Enc Session key parameter. */
			memcpy(pSessionEncKey, aSessionEncKeyA, 8); /* PRQA S 3200 */

			/* XOR calculated Enc Session Key A with calculated Enc Session Key B. */
			for (bCount = 0; bCount <= 7; ++bCount)
				pSessionEncKey[bCount + 8] = aSessionEncKeyA[bCount + 8] ^ aSessionEncKeyB[bCount];

			/* Copy remaining Enc Session Key B to Session key parameter. */
			memcpy(&pSessionEncKey[16], &aSessionEncKeyB[8], 8); /* PRQA S 3200 */

			/* Copy calculated Mac Session Key A to Mac Session key parameter. */
			memcpy(pSessionMacKey, aSessionMacKeyA, 8); /* PRQA S 3200 */

			/* XOR calculated Mac Session Key A with calculated Mac Session Key B. */
			for (bCount = 0; bCount <= 7; ++bCount)
				pSessionMacKey[bCount + 8] = aSessionMacKeyA[bCount + 8] ^ aSessionMacKeyB[bCount];

			/* Copy remaining Mac Session Key B to Session key parameter. */
			memcpy(&pSessionMacKey[16], &aSessionMacKeyB[8], 8); /* PRQA S 3200 */

			/* Update the Session key length. */
			*pKeyLen = PH_CRYPTOSYM_AES192_KEY_SIZE;
			break;

		case PH_CRYPTOSYM_KEY_TYPE_AES256:
			aSv1a[15] = 0x87;
			aSv1b[15] = 0x88;
			aSv2a[15] = 0x89;
			aSv2b[15] = 0x8A;

			/* Calculate the session encryption key A using session vector 1A. */
			PH_CHECK_SUCCESS_FCT(wStatus, phCryptoSym_Encrypt(
				pDataParams->pMACCryptoDataParams,
				PH_CRYPTOSYM_CIPHER_MODE_CBC,
				aSv1a,
				PH_CRYPTOSYM_AES_BLOCK_SIZE,
				aSessionEncKeyA));

			/* Calculate the session encryption key B using session vector 1B. */
			PH_CHECK_SUCCESS_FCT(wStatus, phCryptoSym_Encrypt(
				pDataParams->pMACCryptoDataParams,
				PH_CRYPTOSYM_CIPHER_MODE_CBC,
				aSv1b,
				PH_CRYPTOSYM_AES_BLOCK_SIZE,
				aSessionEncKeyB));

			/* Calculate the session mac key A using session vector 2A. */
			PH_CHECK_SUCCESS_FCT(wStatus, phCryptoSym_Encrypt(
				pDataParams->pMACCryptoDataParams,
				PH_CRYPTOSYM_CIPHER_MODE_CBC,
				aSv2a,
				PH_CRYPTOSYM_AES_BLOCK_SIZE,
				aSessionMacKeyA));

			/* Calculate the session mac key B using session vector 2B. */
			PH_CHECK_SUCCESS_FCT(wStatus, phCryptoSym_Encrypt(
				pDataParams->pMACCryptoDataParams,
				PH_CRYPTOSYM_CIPHER_MODE_CBC,
				aSv2b,
				PH_CRYPTOSYM_AES_BLOCK_SIZE,
				aSessionMacKeyB));

			/* Compute Session ENC key. */
			/* Ke = Kea || Keb */
			memcpy(&pSessionEncKey[0], aSessionEncKeyA, 16);    /* PRQA S 3200 */
			memcpy(&pSessionEncKey[16], aSessionEncKeyB, 16);    /* PRQA S 3200 */

			/* Compute Session MAC key. */
			/* Km = Kma || Kmb */
			memcpy(&pSessionMacKey[0], aSessionMacKeyA, 16);    /* PRQA S 3200 */
			memcpy(&pSessionMacKey[16], aSessionMacKeyB, 16);    /* PRQA S 3200 */
			break;

		default:
			return PH_ADD_COMPCODE(PH_ERR_INTERNAL_ERROR, PH_COMP_HAL);
	}

	return PH_ADD_COMPCODE(PH_ERR_SUCCESS, PH_COMP_HAL);
}

phStatus_t phhalHw_SamAV3_Utils_GetSessionUploadKey(phhalHw_SamAV3_DataParams_t * pDataParams, uint8_t bMode, uint16_t wUploadCtr, uint8_t bKeyNo,
	uint8_t bKeyVer, uint8_t * pSessionKey, uint8_t * pKeyType)
{
	phStatus_t	PH_MEMLOC_REM wStatus = 0;

	uint16_t	PH_MEMLOC_REM wKeyType = 0;
	uint8_t		PH_MEMLOC_REM bKeyLen = 0;
	uint8_t		PH_MEMLOC_REM aDefault_Iv[PH_CRYPTOSYM_AES128_KEY_SIZE];
	uint8_t		PH_MEMLOC_REM aSva[PH_CRYPTOSYM_AES128_KEY_SIZE];
	uint8_t		PH_MEMLOC_REM aSvb[PH_CRYPTOSYM_AES128_KEY_SIZE];
	uint8_t		PH_MEMLOC_REM aKey[PH_CRYPTOSYM_AES256_KEY_SIZE];
	uint8_t		PH_MEMLOC_REM aSessionKeyA[PH_CRYPTOSYM_AES128_KEY_SIZE];
	uint8_t		PH_MEMLOC_REM aSessionKeyB[PH_CRYPTOSYM_AES128_KEY_SIZE];
	uint8_t		PH_MEMLOC_REM aSessionKey[PH_CRYPTOSYM_AES256_KEY_SIZE];

	/* Get the Key and Key Type from keystore. */
	PH_CHECK_SUCCESS_FCT(wStatus, phKeyStore_GetKey(pDataParams->pKeyStoreDataParams,
		bKeyNo,
		bKeyVer,
		sizeof(aKey),
		aKey,
		&wKeyType));

	/* Update the key type to the parameter. */
	*pKeyType = (uint8_t) wKeyType;

	/* Load the key to CryptoSym for macing the session vector. */
	PH_CHECK_SUCCESS_FCT(wStatus, phCryptoSym_LoadKeyDirect(
		pDataParams->pPLUpload_MACCryptoDataParams,
		aKey,
		wKeyType));

	/* Load zero IV is required to Crypto data params. */
	PH_CHECK_SUCCESS_FCT(wStatus, phCryptoSym_LoadIv(
            pDataParams->pPLUpload_MACCryptoDataParams,
        aDefault_Iv,
        PH_CRYPTOSYM_AES_BLOCK_SIZE));

	/* Update the session vector array with the required values. */
	switch(wKeyType)
	{
		case PH_KEYSTORE_KEY_TYPE_AES128:
			memset(aSva, (uint8_t) ((bMode == PHHAL_HW_CMD_SAMAV3_SESSION_KEY_ENC) ? 0x71 : 0x72), sizeof(aSva));	/* PRQA S 3200 */

			/* Update the session vector with upload counter value. */
			aSva[0] = (uint8_t) ((wUploadCtr & 0xFF00) >> 8);
			aSva[1] = (uint8_t) (wUploadCtr & 0x00FF);

			PH_CHECK_SUCCESS_FCT(wStatus, phCryptoSym_CalculateMac(
				pDataParams->pPLUpload_MACCryptoDataParams,
				(PH_CRYPTOSYM_MAC_MODE_CBCMAC | PH_EXCHANGE_DEFAULT),
				aSva,
				PH_CRYPTOSYM_AES_BLOCK_SIZE,
				pSessionKey,
				&bKeyLen));
			break;

		case PH_KEYSTORE_KEY_TYPE_AES192:
			memset(aSva, (uint8_t) ((bMode == PHHAL_HW_CMD_SAMAV3_SESSION_KEY_ENC) ? 0x73 : 0x75), sizeof(aSva));	/* PRQA S 3200 */
			memset(aSvb, (uint8_t) ((bMode == PHHAL_HW_CMD_SAMAV3_SESSION_KEY_ENC) ? 0x74 : 0x76), sizeof(aSvb));	/* PRQA S 3200 */

			/* Update the session vector with upload counter value. */
			aSva[0] = (uint8_t) ((wUploadCtr & 0xFF00) >> 8);
			aSva[1] = (uint8_t) (wUploadCtr & 0x00FF);
			aSvb[0] = (uint8_t) ((wUploadCtr & 0xFF00) >> 8);
			aSvb[1] = (uint8_t) (wUploadCtr & 0x00FF);

			/* Load the session vector value to CryptoMAC data params. */
			PH_CHECK_SUCCESS_FCT(wStatus, phCryptoSym_CalculateMac(
				pDataParams->pPLUpload_MACCryptoDataParams,
				(PH_CRYPTOSYM_MAC_MODE_CBCMAC | PH_EXCHANGE_DEFAULT),
				aSva,
				PH_CRYPTOSYM_AES_BLOCK_SIZE,
				aSessionKeyA,
				&bKeyLen));

			PH_CHECK_SUCCESS_FCT(wStatus, phCryptoSym_CalculateMac(
				pDataParams->pPLUpload_MACCryptoDataParams,
				(PH_CRYPTOSYM_MAC_MODE_CBCMAC | PH_EXCHANGE_DEFAULT),
				aSvb,
				PH_CRYPTOSYM_AES_BLOCK_SIZE,
				aSessionKeyB,
				&bKeyLen));

			/* Compute the session key. */
			/* SessionKey = SessionKeyA[15 : 8]	|| (SessionA[7 : 0] ^ SessionB[15 : 8]) || SessionKeyB[7:0] */
			aSessionKey[0x00] = aSessionKeyA[0x00];		aSessionKey[0x08] = (uint8_t) (aSessionKeyA[0x08] ^ aSessionKeyB[0x00]);		aSessionKey[0x10] = aSessionKeyB[0x08];
			aSessionKey[0x01] = aSessionKeyA[0x01];		aSessionKey[0x09] = (uint8_t) (aSessionKeyA[0x09] ^ aSessionKeyB[0x01]);		aSessionKey[0x11] = aSessionKeyB[0x09];
			aSessionKey[0x02] = aSessionKeyA[0x02];		aSessionKey[0x0A] = (uint8_t) (aSessionKeyA[0x0A] ^ aSessionKeyB[0x02]);		aSessionKey[0x12] = aSessionKeyB[0x0A];
			aSessionKey[0x03] = aSessionKeyA[0x03];		aSessionKey[0x0B] = (uint8_t) (aSessionKeyA[0x0B] ^ aSessionKeyB[0x03]);		aSessionKey[0x13] = aSessionKeyB[0x0B];
			aSessionKey[0x04] = aSessionKeyA[0x04];		aSessionKey[0x0C] = (uint8_t) (aSessionKeyA[0x0C] ^ aSessionKeyB[0x04]);		aSessionKey[0x14] = aSessionKeyB[0x0C];
			aSessionKey[0x05] = aSessionKeyA[0x05];		aSessionKey[0x0D] = (uint8_t) (aSessionKeyA[0x0D] ^ aSessionKeyB[0x05]);		aSessionKey[0x15] = aSessionKeyB[0x0D];
			aSessionKey[0x06] = aSessionKeyA[0x06];		aSessionKey[0x0E] = (uint8_t) (aSessionKeyA[0x0E] ^ aSessionKeyB[0x06]);		aSessionKey[0x16] = aSessionKeyB[0x0E];
			aSessionKey[0x07] = aSessionKeyA[0x07];		aSessionKey[0x0F] = (uint8_t) (aSessionKeyA[0x0F] ^ aSessionKeyB[0x07]);		aSessionKey[0x17] = aSessionKeyB[0x0F];

			/* Update the pSessionKey parameter with the computed session key data. */
			memcpy(pSessionKey, aSessionKey, PH_CRYPTOSYM_AES192_KEY_SIZE);    /* PRQA S 3200 */
			break;

		case PH_KEYSTORE_KEY_TYPE_AES256:
			memset(aSva, (uint8_t) ((bMode == PHHAL_HW_CMD_SAMAV3_SESSION_KEY_ENC) ? 0x77 : 0x79), sizeof(aSva));	/* PRQA S 3200 */
			memset(aSvb, (uint8_t) ((bMode == PHHAL_HW_CMD_SAMAV3_SESSION_KEY_ENC) ? 0x78 : 0x7A), sizeof(aSvb));	/* PRQA S 3200 */

			/* Update the session vector with upload counter value. */
			aSva[0] = (uint8_t) ((wUploadCtr & 0xFF00) >> 8);
			aSva[1] = (uint8_t) (wUploadCtr & 0x00FF);
			aSvb[0] = (uint8_t) ((wUploadCtr & 0xFF00) >> 8);
			aSvb[1] = (uint8_t) (wUploadCtr & 0x00FF);

			/* Load the session vector value to CryptoMAC data params. */
			PH_CHECK_SUCCESS_FCT(wStatus, phCryptoSym_CalculateMac(
				pDataParams->pPLUpload_MACCryptoDataParams,
				(PH_CRYPTOSYM_MAC_MODE_CBCMAC | PH_EXCHANGE_DEFAULT),
				aSva,
				PH_CRYPTOSYM_AES_BLOCK_SIZE,
				aSessionKeyA,
				&bKeyLen));

			PH_CHECK_SUCCESS_FCT(wStatus, phCryptoSym_CalculateMac(
				pDataParams->pPLUpload_MACCryptoDataParams,
				(PH_CRYPTOSYM_MAC_MODE_CBCMAC | PH_EXCHANGE_DEFAULT),
				aSvb,
				PH_CRYPTOSYM_AES_BLOCK_SIZE,
				aSessionKeyB,
				&bKeyLen));

			/* Compute the session key. */
			/* SessionKey = SessionKeyA || SessionKeyB */
			memcpy(&pSessionKey[0], aSessionKeyA, 16);    /* PRQA S 3200 */
			memcpy(&pSessionKey[16], aSessionKeyB, 16);    /* PRQA S 3200 */
			break;

		default:
			return PH_ADD_COMPCODE(PH_ERR_KEY, PH_COMP_HAL);
	}

	return PH_ADD_COMPCODE(PH_ERR_SUCCESS, PH_COMP_HAL);
}
#endif /* NXPBUILD__PHHAL_HW_SAMAV3 */
