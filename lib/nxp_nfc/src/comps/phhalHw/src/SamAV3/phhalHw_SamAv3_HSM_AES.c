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
#include <nxp_nfc/phKeyStore.h>
#include <nxp_nfc/phCryptoSym.h>
#include <nxp_nfc/phCryptoRng.h>
#include <nxp_nfc/ph_RefDefs.h>

#ifdef NXPBUILD__PHHAL_HW_SAMAV3

#include <nxp_nfc/phhalHw_SamAv3_Cmd.h>
#include "phhalHw_SamAv3_HSM_AES.h"
#include "phhalHw_SamAv3.h"
#include "phhalHw_SamAv3_utils.h"

/*
* Private constants
*/
static const uint8_t PH_MEMLOC_CONST_ROM phhalHw_SamAV3_Hc_AV2_FirstIv[PH_CRYPTOSYM_AES_BLOCK_SIZE] = { 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00};

phStatus_t phhalHw_SamAV3_HSM_AES_GetFirstLastCommand(phhalHw_SamAV3_DataParams_t * pDataParams, uint8_t aCmd, uint8_t p1, uint8_t p2, uint8_t * bFirstCmd,
	uint8_t * bLastCmd)
{
    *bFirstCmd = PH_ON;
    *bLastCmd = PH_ON;

    /* Reset CommandChaining per default */
    if (pDataParams->bCommandChaining == PHHAL_HW_SAMAV3_HSM_AES_CHAINING)
    {
		*bFirstCmd = PH_OFF;
    }

    /* In case of response chaining no CMD counter increment is allowed as well */
    if (pDataParams->bResponseChaining == PHHAL_HW_SAMAV3_HSM_AES_CHAINING)
    {
        *bFirstCmd = PH_OFF;

        /* DESFire ReadX command needs special treatment */
        if (aCmd == PHHAL_HW_SAMAV3_CMD_DESFIRE_READ_X_INS)
        {
            pDataParams->bCmdSM = PHHAL_HW_SAMAV3_HSM_AES_NO_CHAINING;
            *bLastCmd = PH_OFF;
        }
    }

    pDataParams->bCommandChaining = PHHAL_HW_SAMAV3_HSM_AES_NO_CHAINING;

    /* Is the current command a chained one or not? */
    if (p1 == PHHAL_HW_SAMAV3_ISO7816_CHAINED_FRAME)
    {
        switch (aCmd)
        {
			/* Data Processing Instruction Codes. */
			case PHHAL_HW_SAMAV3_CMD_SAM_APPLY_SM_INS:
			case PHHAL_HW_SAMAV3_CMD_SAM_REMOVE_SM_INS:
			case PHHAL_HW_SAMAV3_CMD_SAM_VERIFY_MAC_INS:
			case PHHAL_HW_SAMAV3_CMD_SAM_GENERATE_MAC_INS:
			case PHHAL_HW_SAMAV3_CMD_SAM_DECIPHER_DATA_INS:
			case PHHAL_HW_SAMAV3_CMD_SAM_ENCIPHER_DATA_INS:
			case PHHAL_HW_SAMAV3_CMD_SAM_DECIPHER_OFFLINE_DATA_INS:
			case PHHAL_HW_SAMAV3_CMD_SAM_ENCIPHER_OFFLINE_DATA_INS:

			/* Desfire X-Mode Instruction Codes. */
			case PHHAL_HW_SAMAV3_CMD_DESFIRE_WRITE_X_INS:

			/* Programmable Logic Instruction Codes. */
			case PHHAL_HW_CMD_SAMAV3_PL_EXEC_INS:
			case PHHAL_HW_CMD_SAMAV3_PL_UPLOAD_INS:

            /* PKI EMV Commands. */
            case PHHAL_HW_SAMAV3_CMD_PKI_IMPORT_CAPK_INS:
            case PHHAL_HW_SAMAV3_CMD_PKI_LOAD_ISSUER_PK_INS:
            case PHHAL_HW_SAMAV3_CMD_PKI_LOAD_ICC_PK_INS:

			/* EMV Commands. */
			case PHHAL_HW_SAMAV3_CMD_EMVCO_RECOVER_STATIC_DATA_INS:
			case PHHAL_HW_SAMAV3_CMD_EMVCO_RECOVER_DYNAMIC_DATA_INS:

			/* ISO14443-4 Instruction Codes. */
			case PHHAL_HW_SAMAV3_CMD_ISO14443_4_EXCHANGE_INS:
				pDataParams->bCommandChaining = PHHAL_HW_SAMAV3_HSM_AES_CHAINING;
				*bLastCmd = PH_OFF;
				break;
			default:
				break;
        }
    }

    if (p2 == PHHAL_HW_SAMAV3_ISO7816_CHAINED_FRAME)
    {
        switch (aCmd)
        {
			/* PKI RSA Instruction Codes. */
			case PHHAL_HW_SAMAV3_CMD_PKI_GENERATE_KEY_PAIR_INS:
			case PHHAL_HW_SAMAV3_CMD_PKI_IMPORT_KEY_INS:
			case PHHAL_HW_SAMAV3_CMD_PKI_UPDATE_KEY_ENTRIES_INS:
			case PHHAL_HW_SAMAV3_CMD_PKI_GENERATE_HASH_INS:
			case PHHAL_HW_SAMAV3_CMD_PKI_VERIFY_SIGNATURE_INS:
			case PHHAL_HW_SAMAV3_CMD_PKI_DECIPHER_DATA_INS:

			/* MIFARE Plus S-Mode Instruction Codes. */
			case PHHAL_HW_SAMAV3_CMD_COMBINED_READ_MFP_INS:
				pDataParams->bCommandChaining = PHHAL_HW_SAMAV3_HSM_AES_CHAINING;
				*bLastCmd = PH_OFF;
				break;
			default:
				break;
        }
    }

	/* Set bFirstCmd is the status is 90AE. */
	switch ( aCmd )
	{
		/* For Cmd.VCA_Select, for every command Command counter should be incremented. This is with
		 * respect to the new error code added (0x90AE). Because for every command CmdCtr needs to be
		 * incremented the below check is required.
		 */
		case PHHAL_HW_SAMAV3_CMD_VCA_SELECT_INS:
			*bFirstCmd = PH_ON;
			break;

		default:
			break;
	}

	/* Move out if the Host Protection Mode is PLAIN. */
	if (pDataParams->bAuthType == 0x00)
	{
		pDataParams->bCmdSM = PHHAL_HW_SAMAV3_HSM_AES_NO_SM;
		pDataParams->bRespSM = PHHAL_HW_SAMAV3_HSM_AES_NO_SM;
	}

	/* Apply the Host Protection. */
	else
	{
		if (*bFirstCmd)
		{
			/*
			 * This flag is set by default for all commands. The command which require additional secure messaging options like
			 * Ommit or NA is updated in the below switch statement.
			 * Apply SM: Command.Enc, Command.Mac, Response.Enc, Response.MAC
			 */

			/* Host Protection Mode is MAC. */
			if (pDataParams->bAuthType == 0x01)
			{
				pDataParams->bCmdSM = PHHAL_HW_SAMAV3_HSM_AES_MAC;
				pDataParams->bRespSM = PHHAL_HW_SAMAV3_HSM_AES_MAC;
			}
			/* Host Protection Mode is FULL. */
			else if (pDataParams->bAuthType == 0x02)
			{
				pDataParams->bCmdSM = (PHHAL_HW_SAMAV3_HSM_AES_MAC | PHHAL_HW_SAMAV3_HSM_AES_ENC);
				pDataParams->bRespSM = (PHHAL_HW_SAMAV3_HSM_AES_MAC | PHHAL_HW_SAMAV3_HSM_AES_ENC);
			}

			switch (aCmd)
			{
				/*
				 * Commands that falls under below mentioned Secure-Messaging.
				 * NA: Command.Enc, Command.Mac, Response.Enc, Response.MAC
				 */
				case PHHAL_HW_SAMAV3_CMD_LOCK_UNLOCK_INS:
				case PHHAL_HW_SAMAV3_CMD_AUTHENTICATE_HOST_INS:
					pDataParams->bCmdSM = PHHAL_HW_SAMAV3_HSM_AES_NO_SM;
					pDataParams->bRespSM = PHHAL_HW_SAMAV3_HSM_AES_NO_SM;
					break;

				/*
				 * Commands that falls under below mentioned Secure-Messaging.
				 * Apply SM: Command.Enc, Command.Mac
				 * Ommit SM: Response.Enc, Response.MAC
				 */
				case PHHAL_HW_SAMAV3_CMD_SAM_APPLY_SM_INS:
				case PHHAL_HW_SAMAV3_CMD_SAM_SELECT_VC_INS:
				case PHHAL_HW_SAMAV3_CMD_SAM_CHANGE_KEY_PICC_INS:
				case PHHAL_HW_SAMAV3_CMD_SAM_CREATE_TM_FILE_PICC_INS:
					pDataParams->bRespSM = PHHAL_HW_SAMAV3_HSM_AES_NO_SM;
					break;

				/*
				 * Commands that falls under below mentioned Secure-Messaging.
				 *	First Part
				 *		Apply SM: Command.Enc, Command.Mac
				 *		Ommit SM: Response.Enc, Response.MAC
				 *	Second Part
				 *		Apply SM: Response.Enc, Response.MAC
				 *		Ommit SM: Command.Enc, Command.Mac
				 */
				case PHHAL_HW_SAMAV3_CMD_SAM_PROXIMITY_CHECK_INS:
				case PHHAL_HW_SAMAV3_CMD_AUTHENTICATE_MFP_INS:
				case PHHAL_HW_SAMAV3_CMD_AUTHENTICATE_PDC_INS:
				case PHHAL_HW_SAMAV3_CMD_SAM_AUTHENTICATE_MIFARE_INS:
				case PHHAL_HW_SAMAV3_CMD_SAM_PWD_AUTH_UL_INS:
				case PHHAL_HW_SAMAV3_CMD_AUTHENTICATE_TAM_INS:
					if (pDataParams->bResponseChaining == PHHAL_HW_SAMAV3_HSM_AES_CHAINING_NO_SM)
					{
						pDataParams->bCmdSM = PHHAL_HW_SAMAV3_HSM_AES_NO_SM;
					}
					else
					{
						/* Note: In SamAV2, the commmand of this command is neither MACed nor Encrypted */
						pDataParams->bRespSM = PHHAL_HW_SAMAV3_HSM_AES_NO_SM;
					}
					break;

				/*
				 * Commands that falls under below mentioned Secure-Messaging.
				 * Apply SM		: Command.MAC, Response.MAC
				 * Ommit, N/A	: Command.Enc, Response.Enc
				 */
				case PHHAL_HW_SAMAV3_CMD_KILL_AUTHENTICATION_INS:
				case PHHAL_HW_SAMAV3_CMD_SLEEP_INS:
				case PHHAL_HW_SAMAV3_CMD_RC_INIT_INS:
				case PHHAL_HW_SAMAV3_CMD_ISO14443_3_HALTA_INS:
				case PHHAL_HW_SAMAV3_CMD_ISO14443_4_PRESENCE_CHECK_INS:
				case PHHAL_HW_SAMAV3_CMD_ISO14443_4_DESELECT_INS:
					pDataParams->bCmdSM = PHHAL_HW_SAMAV3_HSM_AES_MAC;
					pDataParams->bRespSM = PHHAL_HW_SAMAV3_HSM_AES_MAC;
					break;

				/*
				 * Commands that falls under below mentioned Secure-Messaging.
				 * Apply SM: Command.Mac, Response.Enc, Response.MAC
				 * Ommit SM: Command.Enc
				 */
				case PHHAL_HW_SAMAV3_CMD_GET_VERSION_INS:
				case PHHAL_HW_SAMAV3_CMD_GET_CHALLENGE_INS:
				case PHHAL_HW_SAMAV3_CMD_SAM_GET_KEY_ENTRY_INS:
				case PHHAL_HW_SAMAV3_CMD_SAM_GET_KUC_ENTRY_INS:
				case PHHAL_HW_SAMAV3_CMD_SAM_REMOVE_SM_INS:
				case PHHAL_HW_SAMAV3_CMD_SAM_DECIPHER_DATA_INS:
				case PHHAL_HW_SAMAV3_CMD_SAM_DECIPHER_OFFLINE_DATA_INS:
				/*case PHHAL_HW_SAMAV3_CMD_PKI_EXPORT_PRIVATE_KEY_INS:
				case PHHAL_HW_SAMAV3_CMD_PKI_EXPORT_PUBLIC_KEY_INS:
				case PHHAL_HW_SAMAV3_CMD_PKI_SEND_SIGNATURE_INS:*/
				case PHHAL_HW_SAMAV3_CMD_PKI_DECIPHER_DATA_INS:
				case PHHAL_HW_SAMAV3_CMD_PKI_EXPORT_ECC_PUBLIC_KEY_INS:
				case PHHAL_HW_CMD_SAMAV3_PL_UPLOAD_INS:
					pDataParams->bCmdSM = PHHAL_HW_SAMAV3_HSM_AES_MAC;
					break;

				/*
				 * Commands that falls under below mentioned Secure-Messaging.
				 * Apply SM		: Command.Enc, Command.Mac, Response.MAC
				 * Ommit, N/A	: Response.Enc
				 */
				case PHHAL_HW_SAMAV3_CMD_DISABLE_CRYPTO_INS:
				case PHHAL_HW_SAMAV3_CMD_ACTIVATE_OFFLINE_KEY_INS:
				case PHHAL_HW_SAMAV3_CMD_LOAD_INIT_VECTOR_INS:
				case PHHAL_HW_SAMAV3_CMD_SELECT_APPLICATION_INS:
				case PHHAL_HW_SAMAV3_CMD_SETCONFIGURATION_INS:
				case PHHAL_HW_SAMAV3_CMD_SAM_CHANGE_KEY_ENTRY_INS:
				case PHHAL_HW_SAMAV3_CMD_SAM_CHANGE_KUC_ENTRY_INS:
				case PHHAL_HW_SAMAV3_CMD_SAM_DISABLE_KEY_ENTRY_INS:
				case PHHAL_HW_SAMAV3_CMD_SAM_ENCHIPHER_KEY_ENTRY_INS:
				case PHHAL_HW_SAMAV3_CMD_SAM_DERIVE_KEY_INS:
				case PHHAL_HW_SAMAV3_CMD_SAM_VERIFY_MAC_INS:
				case PHHAL_HW_SAMAV3_CMD_SAM_ENCIPHER_DATA_INS:
				case PHHAL_HW_SAMAV3_CMD_SAM_ENCIPHER_OFFLINE_DATA_INS:
				/*case PHHAL_HW_SAMAV3_CMD_PKI_GENERATE_KEY_PAIR_INS:
				case PHHAL_HW_SAMAV3_CMD_PKI_IMPORT_KEY_INS:
				case PHHAL_HW_SAMAV3_CMD_PKI_UPDATE_KEY_ENTRIES_INS:*/
				case PHHAL_HW_SAMAV3_CMD_PKI_ENCIPHER_KEY_ENTRIES_INS:
				/*case PHHAL_HW_SAMAV3_CMD_PKI_GENERATE_SIGNATURE_INS:
				case PHHAL_HW_SAMAV3_CMD_PKI_VERIFY_SIGNATURE_INS:*/
				case PHHAL_HW_SAMAV3_CMD_PKI_ENCIPHER_DATA_INS:
				case PHHAL_HW_SAMAV3_CMD_PKI_IMPORT_ECC_KEY_INS:
				case PHHAL_HW_SAMAV3_CMD_PKI_IMPORT_ECC_CURVE_INS:
				case PHHAL_HW_SAMAV3_CMD_PKI_VERIFY_ECC_SIGNATURE_INS:
				case PHHAL_HW_SAMAV3_CMD_MF_AUTHENTICATE_INS:
				case PHHAL_HW_SAMAV3_CMD_MF_WRITE_INS:
				case PHHAL_HW_SAMAV3_CMD_MF_VALUE_WRITE_INS:
				case PHHAL_HW_SAMAV3_CMD_MF_INCREMENT_INS:
				case PHHAL_HW_SAMAV3_CMD_MF_DECREMENT_INS:
				case PHHAL_HW_SAMAV3_CMD_MF_RESTORE_INS:
				case PHHAL_HW_SAMAV3_CMD_MF_AUTHENTICATED_WRITE_INS:
				case PHHAL_HW_SAMAV3_CMD_MF_CHANGE_KEY_INS:
				case PHHAL_HW_SAMAV3_CMD_EMVCO_RECOVER_ENCIPHER_PIN_INS:
				case PHHAL_HW_SAMAV3_CMD_RC_WRITE_REGISTER_INS:
				case PHHAL_HW_SAMAV3_CMD_RC_RF_CONTROL_INS:
				case PHHAL_HW_SAMAV3_CMD_RC_LOAD_REGISTER_VALUE_SET_INS:
				case PHHAL_HW_SAMAV3_CMD_ISO14443_3_ACTIVATE_WAKEUP_INS:
				case PHHAL_HW_SAMAV3_CMD_ISO14443_4_INIT_INS:
				case PHHAL_HW_SAMAV3_CMD_ISO14443_4_FREE_CID_INS:
				case PHHAL_HW_SAMAV3_CMD_PKI_IMPORT_CAPK_INS:
				case PHHAL_HW_SAMAV3_CMD_PKI_REMOVE_CAPK_INS:
				case PHHAL_HW_SAMAV3_CMD_PKI_EXPORT_CAPK_INS:
					pDataParams->bRespSM = PHHAL_HW_SAMAV3_HSM_AES_MAC;
					break;

				/*
				 * Commands that falls under below mentioned Secure-Messaging.
				 *	First Part
				 *		Apply SM: Command.Enc, Command.Mac
				 *		Ommit SM: Response.Enc, Response.MAC
				 *	Second Part
				 *		Apply SM: Response.MAC
				 *		Ommit SM: Command.Enc, Command.Mac, Response.Enc
				 */
				case PHHAL_HW_SAMAV3_CMD_SAM_AUTHENTICATE_PICC_INS:
				case PHHAL_HW_SAMAV3_CMD_SAM_ISO_AUTHENTICATE_PICC_INS:
				case PHHAL_HW_SAMAV3_CMD_AUTH_SECTOR_SWITCH_MFP_INS:
				case PHHAL_HW_SAMAV3_CMD_AUTHENTICATE_MAM_INS:
					if (pDataParams->bResponseChaining == PHHAL_HW_SAMAV3_HSM_AES_CHAINING_NO_SM)
					{
						pDataParams->bCmdSM = PHHAL_HW_SAMAV3_HSM_AES_NO_SM;
						pDataParams->bRespSM = PHHAL_HW_SAMAV3_HSM_AES_MAC;
					}else
					{
						/* Note: In SamAV2, the commmand of this command is neither MACed nor Encrypted */
						pDataParams->bRespSM = PHHAL_HW_SAMAV3_HSM_AES_NO_SM;
					}
					break;

				/*
				 * Commands that falls under below mentioned Secure-Messaging.
				 *	First Part
				 *		Apply SM: Command.MAC
				 *		Ommit SM: Response.Enc, Response.Mac, Command.ENC
				 *	Second Part
				 *		Apply SM: Response.Enc, Response.MAC
				 *		Ommit SM: Command.Enc, Command.Mac
				 */
				case PHHAL_HW_CMD_SAMAV3_COMMIT_READER_ID_INS:
					if (pDataParams->bResponseChaining == PHHAL_HW_SAMAV3_HSM_AES_CHAINING_NO_SM)
					{
						pDataParams->bCmdSM = PHHAL_HW_SAMAV3_HSM_AES_NO_SM;
					}
					else
					{
						pDataParams->bCmdSM = PHHAL_HW_SAMAV3_HSM_AES_MAC;
						pDataParams->bRespSM = PHHAL_HW_SAMAV3_HSM_AES_NO_SM;
					}
					break;

				/*
				 * Commands that falls under below mentioned Secure-Messaging.
				 *	Command
				 *		Apply SM: Command.Enc, Command.MAC
				 *		Ommit SM: Response.Enc, Response.Mac
				 *	Response
				 *		Apply SM: Response.Enc, Response.MAC
				 *		Ommit SM: Command.Enc, Command.Mac
				 *	Command + Response
				 *		Apply SM: Command.Enc, Command.Mac, Response.Enc, Response.MAC
				 */
				case PHHAL_HW_SAMAV3_CMD_COMBINED_READ_MFP_INS:
					if (p1 == PHHAL_HW_SAMAV3_OPTION_COMBINED_READ_MFP_COMMAND)
					{
						pDataParams->bRespSM = PHHAL_HW_SAMAV3_HSM_AES_NO_SM;
					}
					else if (p1 == PHHAL_HW_SAMAV3_OPTION_COMBINED_READ_MFP_RESPONSE)
					{
						pDataParams->bCmdSM = PHHAL_HW_SAMAV3_HSM_AES_NO_SM;
					}
					else
					{
						/* Else, nothing changed */
					}
					break;

				/*
				 * Commands that falls under below mentioned Secure-Messaging.
				 *	Command
				 *		Apply SM: Command.Enc, Command.MAC
				 *		Ommit SM: Response.Enc, Response.Mac
				 *	Response
				 *		Apply SM: Response.Enc, Response.MAC
				 *		Ommit SM: Command.Enc, Command.Mac
				 */
				case PHHAL_HW_SAMAV3_CMD_COMBINED_WRITE_MFP_INS:
				case PHHAL_HW_SAMAV3_CMD_CHANGE_KEY_MFP_INS:
					if (p1 & PHHAL_HW_SAMAV3_OPTION_COMBINED_WRITE_MFP_RESPONSE)
					{
						pDataParams->bCmdSM = PHHAL_HW_SAMAV3_HSM_AES_NO_SM;
					}
					else
					{
						pDataParams->bRespSM = PHHAL_HW_SAMAV3_HSM_AES_NO_SM;
					}
					break;

				/*
				 * Commands that falls under below mentioned Secure-Messaging.
				 * Plain: No SM
				 * Mac  :
				 *			If  P1 = 0x00, Apply SM: Command.MAC Response.Enc Response.MAC and N/A: Command.Enc
				 *			If  P1 = 0x01, Apply SM: Command.MAC Response.Enc Response.MAC Command.Enc
				 * Enc  :
				 *			If  P1 = 0x00, Apply SM: Command.MAC Response.Enc Response.MAC Command.Enc
				 *			If  P1 = 0x01, Apply SM: Command.MAC Response.Enc Response.MAC Command.Enc
				 */
				case PHHAL_HW_SAMAV3_CMD_SAM_DUMP_SESSION_KEY_INS:
				case PHHAL_HW_SAMAV3_CMD_SAM_DUMP_SECRET_KEY_INS:
					if ((p1 & 0x01) && (pDataParams->bAuthType == 0x01))
					{
						pDataParams->bRespSM |= PHHAL_HW_SAMAV3_HSM_AES_ENC;
					}
					break;

				/*
				 * Commands that falls under below mentioned Secure-Messaging.
				 * Plain: No SM
				 * Mac  :
				 *			If  P2 = 0x00, Apply SM: Command.MAC Response.Enc Response.MAC and N/A: Command.Enc
				 *			If  P2 = 0x01, Apply SM: Command.MAC Response.Enc Response.MAC Command.Enc
				 * Enc  :
				 *			If  P2 = 0x00, Apply SM: Command.MAC Response.Enc Response.MAC Command.Enc
				 *			If  P2 = 0x01, Apply SM: Command.MAC Response.Enc Response.MAC Command.Enc
				 */
				case PHHAL_HW_SAMAV3_CMD_SAM_CHANGE_KEY_MIFARE_INS:
					/* Allow encryption for key dump in case of MAC protection. */
					if ((p2 & 0x01) && (pDataParams->bAuthType == 0x01))
					{
						pDataParams->bRespSM |= PHHAL_HW_SAMAV3_HSM_AES_ENC;
					}
					break;
			}
		}
	}

    return PH_ADD_COMPCODE(PH_ERR_SUCCESS, PH_COMP_HAL);
}

phStatus_t phhalHw_SamAV3_HSM_AES_GetFirstLastResponse(phhalHw_SamAV3_DataParams_t * pDataParams, uint8_t sw1, uint8_t sw2, uint8_t * bFirstResponse,
	uint8_t * bLastResponse)
{
    *bFirstResponse = PH_ON;
    *bLastResponse = PH_ON;

    /* Reset ResponseChaining per default */
    if (pDataParams->bResponseChaining == PHHAL_HW_SAMAV3_HSM_AES_CHAINING)
    {
        *bFirstResponse = PH_OFF;
    }

    pDataParams->bResponseChaining = PHHAL_HW_SAMAV3_HSM_AES_NO_CHAINING;

    /* Check for 0x90AF - in case of MACing of response is enabled, we should set the chaining option*/
    if ((sw1 != 0x90) || (sw2 != 0x00))
    {
        if ((sw1 == 0x90) && (sw2 == 0xAF))
        {
            if (pDataParams->bRespSM != PHHAL_HW_SAMAV3_HSM_AES_NO_SM)
            {
                pDataParams->bResponseChaining = PHHAL_HW_SAMAV3_HSM_AES_CHAINING;
            }
			else
            {
                pDataParams->bResponseChaining = PHHAL_HW_SAMAV3_HSM_AES_CHAINING_NO_SM;
            }

            *bLastResponse = PH_OFF;
        }
		else if ((sw1 == 0x90) && (sw2 == 0xAE))
		{
			pDataParams->bResponseChaining = PHHAL_HW_SAMAV3_HSM_AES_CHAINING_NO_SM;

			*bFirstResponse = PH_ON;
			*bLastResponse = PH_ON;
		}
        else
        {
            *bFirstResponse = PH_ON;
            pDataParams->bCommandChaining = PHHAL_HW_SAMAV3_HSM_AES_NO_CHAINING;
        }
    }

    return PH_ADD_COMPCODE(PH_ERR_SUCCESS, PH_COMP_HAL);
}

phStatus_t phhalHw_SamAV3_HSM_AES_AppendMac(phhalHw_SamAV3_DataParams_t * pDataParams, uint8_t * pBuffer, uint16_t wTxLength, uint16_t wBufferSize,
	uint16_t * pTxLength, uint8_t bFirst, uint8_t bLast)
{
    phStatus_t  PH_MEMLOC_REM statusTmp;
    uint8_t     PH_MEMLOC_REM bLcPresent = PH_OFF;
    uint8_t     PH_MEMLOC_REM bLePresent = PH_OFF;
    uint8_t     PH_MEMLOC_REM bLc = 0;
    uint8_t     PH_MEMLOC_REM bLeValue = 0;
    uint8_t     PH_MEMLOC_REM aTmpBuf[16];
    uint16_t    PH_MEMLOC_REM wHelper;
    uint16_t    PH_MEMLOC_REM wValidMacData = 0;
    uint8_t     PH_MEMLOC_REM bMacLength;

    *pTxLength = wTxLength;

    PH_CHECK_SUCCESS_FCT(statusTmp, phhalHw_SamAV3_Utils_GetCheckLcLe(pBuffer, wTxLength, &bLcPresent, &bLc, &bLePresent));

    /* check the buffer size compare to the size of data to MAC*/
    if ((wTxLength) > (wBufferSize - 8))
    {
        return PH_ADD_COMPCODE(PH_ERR_BUFFER_OVERFLOW, PH_COMP_HAL);
    }

    /* In case of non-first command and LC == 0 (response chaining no MAC should be appended */
    if ((!bFirst) && (!bLcPresent))
    {
        return PH_ADD_COMPCODE(PH_ERR_SUCCESS, PH_COMP_HAL);
    }

    /* Remember Le */
    bLeValue = pBuffer[wTxLength - 1];

    if (bFirst)
    {
        pDataParams->bPendingMacCmdDataLength = 0;

        /* load the initial IV, because we start a new MAC calculation */
        PH_CHECK_SUCCESS_FCT(statusTmp, phCryptoSym_LoadIv(
            pDataParams->pMACCryptoDataParams,
            phhalHw_SamAV3_Hc_AV2_FirstIv,
            PH_CRYPTOSYM_AES_BLOCK_SIZE));

        /* Also set the pending MAC to 0 */
        memset(pDataParams->bPendingCmdMac, 0, sizeof(pDataParams->bPendingCmdMac)); /* PRQA S 3200 */

        /* Build the buffer to MAC */
        aTmpBuf[wValidMacData++] = pBuffer[PHHAL_HW_SAMAV3_ISO7816_CLA_POS];
        aTmpBuf[wValidMacData++] = pBuffer[PHHAL_HW_SAMAV3_ISO7816_INS_POS];
        aTmpBuf[wValidMacData++] = (uint8_t)((pDataParams->Cmd_Ctr & 0xFF000000) >> 24);
        aTmpBuf[wValidMacData++] = (uint8_t)((pDataParams->Cmd_Ctr & 0x00FF0000) >> 16);
        aTmpBuf[wValidMacData++] = (uint8_t)((pDataParams->Cmd_Ctr & 0x0000FF00) >> 8);
        aTmpBuf[wValidMacData++] = (uint8_t)((pDataParams->Cmd_Ctr & 0x000000FF) >> 0);

        /* In case of chaining detected, we need to load 0x00 for LFI */
        if ((!bLast) &&(pBuffer[PHHAL_HW_SAMAV3_ISO7816_P1_POS] == 0xAF))
        {
            aTmpBuf[wValidMacData++] = 0x00;
        }
        else
        {
            aTmpBuf[wValidMacData++] = pBuffer[PHHAL_HW_SAMAV3_ISO7816_P1_POS];
        }

        if ((!bLast) &&(pBuffer[PHHAL_HW_SAMAV3_ISO7816_P2_POS] == 0xAF))
        {
            aTmpBuf[wValidMacData++] = 0x00;
        }
        else
        {
            aTmpBuf[wValidMacData++] = pBuffer[PHHAL_HW_SAMAV3_ISO7816_P2_POS];
        }

        /* Chained commands have a LC == 0 */
        if (bLast)
        {
            aTmpBuf[wValidMacData++] = bLc + 8;
            /* Also set updated LC in original buffer */
            pBuffer[PHHAL_HW_SAMAV3_ISO7816_LC_POS] = bLc + 8;

            /* As we have updated LC, we also need to update LE... */
            if ((!bLcPresent)&&(bLePresent))
            {
                aTmpBuf[wValidMacData++] = bLeValue;
            }
        }
        else
        {
            aTmpBuf[wValidMacData++] = 0;
            /* we definitively have had LC in here */
        }

        pDataParams->bPendingMacCmdDataLength = 0;
    }
    else
    {
        /* Update LC in case of Last frame */
        if (bLast)
        {
            pBuffer[PHHAL_HW_SAMAV3_ISO7816_LC_POS] = bLc + 8;
        }

        /* Copy pending data */
        memcpy(aTmpBuf, pDataParams->bPendingMacCmdData, (uint16_t)pDataParams->bPendingMacCmdDataLength);  /* PRQA S 3200 */
        wValidMacData = pDataParams->bPendingMacCmdDataLength;
        pDataParams->bPendingMacCmdDataLength = 0;

        /* Load pending command MAC */
        PH_CHECK_SUCCESS_FCT(statusTmp, phCryptoSym_LoadIv(
            pDataParams->pMACCryptoDataParams,
            pDataParams->bPendingCmdMac,
            PH_CRYPTOSYM_AES_BLOCK_SIZE));
    }

    /* Start MACing Process */
    /* Now recopy the remaining data into the aTmpBuf in case of we have at least 5 bytes in the buffer */
    wHelper = 16 - wValidMacData;

    /* The helper should not be bigger than bLc (also bLc = 0 is covered) */
    if (wHelper > bLc)
    {
        wHelper = bLc;
    }

    memcpy(&aTmpBuf[wValidMacData], &pBuffer[PHHAL_HW_SAMAV3_ISO7816_LC_POS + 1], (uint16_t)wHelper);  /* PRQA S 3200 */
    wValidMacData = wValidMacData + wHelper;

    /* If we have a complete pending block, we can always use it. */
    if (wValidMacData == 16)
    {
        /* Do we have remaining data? */
        if ((bLc > wHelper) || (bLePresent))
        {
            /* Switch to CMAC mode without padding */
            PH_CHECK_SUCCESS_FCT(statusTmp, phCryptoSym_CalculateMac(
                pDataParams->pMACCryptoDataParams,
                PH_CRYPTOSYM_MAC_MODE_CMAC | PH_EXCHANGE_BUFFER_CONT,
                aTmpBuf,
                wValidMacData,
                pDataParams->bPendingCmdMac,
                &bMacLength));

            wValidMacData = 0;

            /* now we calculate all blocks but the last one*/
            wValidMacData = ((uint16_t)bLc - wHelper);
            /* calculate pending data of last block */
            bLc = (uint8_t)(wValidMacData % 16);
            wValidMacData = (wValidMacData - bLc);

            /* skip MACing of the last block. */
            if (bLc==0 && !bLePresent)
            {
                if (wValidMacData >= 16)
                {
                    wValidMacData -= 16;
                }
                bLc += 16;
            }

            /* If we have data, we can now MAC it */
            if (wValidMacData)
            {
                /* we have remaining data */
                PH_CHECK_SUCCESS_FCT(statusTmp, phCryptoSym_CalculateMac(
                    pDataParams->pMACCryptoDataParams,
                    PH_CRYPTOSYM_MAC_MODE_CMAC | PH_EXCHANGE_BUFFER_CONT,
                    &pBuffer[wHelper + PHHAL_HW_SAMAV3_ISO7816_HEADER_LENGTH],
                    wValidMacData,
                    pDataParams->bPendingCmdMac,
                    &bMacLength));
            }

            /* Recopy the last chunk into the tmp Buffer */
            memcpy(aTmpBuf, &pBuffer[wHelper + PHHAL_HW_SAMAV3_ISO7816_HEADER_LENGTH + wValidMacData], (uint16_t)bLc);  /* PRQA S 3200 */
            wValidMacData = bLc;
        }
    }

    /* Now let's distinguish, what to do with the pending data */
    if (bLast)
    {
        /* Do we need to append Le?*/
        if ((bLcPresent)&&(bLePresent))
        {
            if (wValidMacData >= 16)
            {
                return PH_ADD_COMPCODE(PH_ERR_PROTOCOL_ERROR, PH_COMP_HAL);
            }
            aTmpBuf[wValidMacData++] = bLeValue;
        }

        /* Switch to CMAC mode with padding*/
        PH_CHECK_SUCCESS_FCT(statusTmp, phCryptoSym_CalculateMac(
            pDataParams->pMACCryptoDataParams,
            PH_CRYPTOSYM_MAC_MODE_CMAC | PH_EXCHANGE_BUFFER_LAST,
            aTmpBuf,
            wValidMacData,
            pDataParams->bPendingCmdMac,
            &bMacLength));

        /* we have to truncate the MAC*/
        PH_CHECK_SUCCESS_FCT(statusTmp, phhalHw_SamAV3_Utils_TruncateMacBuffer(pDataParams->bPendingCmdMac, &bMacLength));

        /* Append MAC at end of buffer */
        if ((bLcPresent) && (bLePresent))
        {
            /* Le is still on the correct position, so copy mac and move Le */
            memcpy(&pBuffer[wTxLength - 1], pDataParams->bPendingCmdMac, (uint16_t)bMacLength);  /* PRQA S 3200 */
            wTxLength = wTxLength + bMacLength;
            pBuffer[wTxLength - 1] = bLeValue;
        }
        else if (bLcPresent)
        {
            /* Before, there was no Lc byte - this is newly introduced Le needs to be recopied*/
            memcpy(&pBuffer[wTxLength], pDataParams->bPendingCmdMac, (uint16_t)bMacLength);  /* PRQA S 3200 */
            wTxLength = wTxLength + bMacLength;
        }
        else if (bLePresent)
        {
            /* Le is still on the correct position, so copy mac and move Le */
            memcpy(&pBuffer[PHHAL_HW_SAMAV3_ISO7816_HEADER_LENGTH], pDataParams->bPendingCmdMac, (uint16_t)bMacLength);  /* PRQA S 3200 */
            wTxLength = PHHAL_HW_SAMAV3_ISO7816_HEADER_LENGTH + bMacLength + 1;
            pBuffer[wTxLength - 1] = bLeValue;
        }
        else
        {
            /* We do not have Le or Lc before, now we have Lc */
            memcpy(&pBuffer[PHHAL_HW_SAMAV3_ISO7816_HEADER_LENGTH], pDataParams->bPendingCmdMac, (uint16_t)bMacLength);  /* PRQA S 3200 */
            wTxLength = PHHAL_HW_SAMAV3_ISO7816_HEADER_LENGTH + bMacLength;
        }
    }
    else
    {
        /* Setup pending data*/
        memcpy(pDataParams->bPendingMacCmdData, aTmpBuf, (uint16_t)wValidMacData);  /* PRQA S 3200 */
        pDataParams->bPendingMacCmdDataLength = (uint8_t)wValidMacData;
    }

    *pTxLength = wTxLength;
    /* End MACing Process */
    return PH_ADD_COMPCODE(PH_ERR_SUCCESS, PH_COMP_HAL);
}

phStatus_t phhalHw_SamAV3_HSM_AES_Decrypt(phhalHw_SamAV3_DataParams_t * pDataParams, uint8_t * pBuffer, uint16_t wRxLength, uint16_t * pRxLength, uint8_t bFirst,
	uint8_t bLast)
{
    phStatus_t statusTmp;
    *pRxLength = 0;

    if (bFirst)
    {
        /* load the InitializationVector (phCryptoSym_CryptoPP_LoadIv), because we start a new decryption.
        This has to be done even if no data is returned by the SAM. */
        PH_CHECK_SUCCESS_FCT(statusTmp, phhalHw_SamAV3_HSM_AES_InitAndLoadIV(
            pDataParams,
            pDataParams->bPendingRespIv,
            false));
    }
    else
    {
        /* Load decryption IV */
        PH_CHECK_SUCCESS_FCT(statusTmp, phCryptoSym_LoadIv(
            pDataParams->pENCCryptoDataParams,
            pDataParams->bPendingRespIv,
            PH_CRYPTOSYM_AES_BLOCK_SIZE));
    }

    if (wRxLength < (16 /* Data */ + PHHAL_HW_SAMAV3_ISO7816_SW1SW2_LENGTH))
    {
        *pRxLength = wRxLength;
        /* Obviously, no data is available */
        return PH_ADD_COMPCODE(PH_ERR_SUCCESS, PH_COMP_HAL);
    }

    if (((wRxLength - PHHAL_HW_SAMAV3_ISO7816_SW1SW2_LENGTH) % 16) != 0)
    {
        return PH_ADD_COMPCODE(PH_ERR_LENGTH_ERROR, PH_COMP_HAL);
    }

    if (!bLast)
    {
        /* Recopy last block of the encrypted data into the temporary IV space */
        memcpy(pDataParams->bPendingRespIv, &pBuffer[wRxLength - PHHAL_HW_SAMAV3_ISO7816_SW1SW2_LENGTH - 16], sizeof(pDataParams->bPendingRespIv));  /* PRQA S 3200 */
    }

    PH_CHECK_SUCCESS_FCT(statusTmp, phCryptoSym_Decrypt(
        pDataParams->pENCCryptoDataParams,
        (PH_CRYPTOSYM_CIPHER_MODE_CBC | PH_EXCHANGE_BUFFER_CONT),
        pBuffer,
        (wRxLength - PHHAL_HW_SAMAV3_ISO7816_SW1SW2_LENGTH),
        pBuffer));

    if (bLast)
    {
        /* remove padding in pPlainBuffer and Update the size of decrypted buffer*/
        PH_CHECK_SUCCESS_FCT(statusTmp, phCryptoSym_RemovePadding(
            PH_CRYPTOSYM_PADDING_MODE_2,
            pBuffer,
            wRxLength - PHHAL_HW_SAMAV3_ISO7816_SW1SW2_LENGTH,
            PH_CRYPTOSYM_AES_BLOCK_SIZE,
            wRxLength - PHHAL_HW_SAMAV3_ISO7816_SW1SW2_LENGTH,
            pBuffer,
            pRxLength));

        /* Reorder SW1 SW2 */
        pBuffer[(*pRxLength)++] = pBuffer[wRxLength - PHHAL_HW_SAMAV3_ISO7816_SW1SW2_LENGTH];
        pBuffer[(*pRxLength)++] = pBuffer[wRxLength - 1];
    }
    else
    {
        /* Set response length only */
        *pRxLength = wRxLength;
    }

    return PH_ADD_COMPCODE(PH_ERR_SUCCESS, PH_COMP_HAL);
}

phStatus_t phhalHw_SamAV3_HSM_AES_VerifyRemoveMac(phhalHw_SamAV3_DataParams_t * pDataParams, uint8_t * pBuffer, uint16_t wRxLength, uint16_t * pRxLength, uint8_t bFirst,
	uint8_t bLast)
{
    phStatus_t  PH_MEMLOC_REM statusTmp;
    uint8_t     PH_MEMLOC_REM bMacLength;
    uint8_t     PH_MEMLOC_REM aTmpBuf[16];
    uint16_t    PH_MEMLOC_REM wValidMacData = 0;
    uint16_t    PH_MEMLOC_REM wHelper;
    uint16_t    PH_MEMLOC_REM wPayloadLength;
    uint8_t     PH_MEMLOC_REM bOldPendingRespDataLength = 0;

    /* Begin Checks */
    memset(aTmpBuf, 0, 16); /* PRQA S 3200 */

    /* In case of chaining the last 16 bytes of the rx data could be padding or MAC data. */
    if (wRxLength>2 && ((pDataParams->bResponseChaining == PHHAL_HW_SAMAV3_HSM_AES_CHAINING) || (!bFirst && bLast)))
    {
        if (bFirst)
        {
            pDataParams->bPendingRespDataLength = 0;
        }
        else
        {
            memcpy(aTmpBuf, pDataParams->bPendingRespData, pDataParams->bPendingRespDataLength);  /* PRQA S 3200 */
            bOldPendingRespDataLength = pDataParams->bPendingRespDataLength;
        }

        if (!bLast)
        {
            if ((wRxLength-2) >= 16)
            {
                pDataParams->bPendingRespDataLength = 16;
            }
            else
            {
                pDataParams->bPendingRespDataLength=(uint8_t) (wRxLength-2);
            }

            /* if the response is only MACed skip MACing of the last 8 bytes if it is not the last frame */
            memcpy(pDataParams->bPendingRespData, &pBuffer[(wRxLength-2) - pDataParams->bPendingRespDataLength], pDataParams->bPendingRespDataLength);  /* PRQA S 3200 */
            memcpy(&pBuffer[(wRxLength-2) - pDataParams->bPendingRespDataLength], &pBuffer[(wRxLength-2)], PHHAL_HW_SAMAV3_ISO7816_SW1SW2_LENGTH);  /* PRQA S 3200 */
            wRxLength = wRxLength - (uint16_t) pDataParams->bPendingRespDataLength;
        }

        if (!bFirst && bOldPendingRespDataLength)
        {
            memmove(&pBuffer[bOldPendingRespDataLength], pBuffer, wRxLength);   /* PRQA S 3200 */
            memcpy(pBuffer, aTmpBuf, bOldPendingRespDataLength);  /* PRQA S 3200 */
            wRxLength = wRxLength + (uint16_t) bOldPendingRespDataLength;
        }

        if (bLast)
        {
            pDataParams->bPendingRespDataLength = 0;
        }
    }

    *pRxLength = 0;

    if (bLast)
    {
        /* Received length needs to be at least 10 bytes or 2 bytes in case of Tx Chaining! */
        if (wRxLength < (PHHAL_HW_SAMAV3_ISO7816_SW1SW2_LENGTH + 8 /*MAC*/))
        {
            return PH_ADD_COMPCODE(PH_ERR_LENGTH_ERROR, PH_COMP_HAL);
        }
        wPayloadLength  = (wRxLength - (PHHAL_HW_SAMAV3_ISO7816_SW1SW2_LENGTH + 8 /*MAC*/));
    }
    else
    {
        wPayloadLength  = (wRxLength - (PHHAL_HW_SAMAV3_ISO7816_SW1SW2_LENGTH));
    }

    /* Start UnMACing Process */
    if (bFirst)
    {
        pDataParams->bPendingMacRespDataLength = 0;

        /* load the InitializationVector, because we start a new MAC calculation */
        PH_CHECK_SUCCESS_FCT(statusTmp, phCryptoSym_LoadIv(pDataParams->pMACCryptoDataParams,
            phhalHw_SamAV3_Hc_AV2_FirstIv,
            PH_CRYPTOSYM_AES_BLOCK_SIZE));

        /* Also set the pending MAC to 0 */
        memset(pDataParams->bPendingRespMac, 0, sizeof(pDataParams->bPendingRespMac)); /* PRQA S 3200 */

        /* calculate the MAC according to the response pMacedBuffer */
        aTmpBuf[wValidMacData++] = pBuffer[wRxLength - PHHAL_HW_SAMAV3_ISO7816_SW1SW2_LENGTH];
        /* In case of chaining detected, we need to load 0x00 */
        if ((pBuffer[wRxLength - PHHAL_HW_SAMAV3_ISO7816_SW1SW2_LENGTH] == 0x90) &&(pBuffer[wRxLength - 1] == 0xAF))
        {
            aTmpBuf[wValidMacData++] = 0x00;
        }else
        {
            aTmpBuf[wValidMacData++] =  pBuffer[wRxLength - 1];
        }
        aTmpBuf[wValidMacData++] =    (uint8_t)((pDataParams->Cmd_Ctr & 0xFF000000) >> 24);
        aTmpBuf[wValidMacData++] = (uint8_t)((pDataParams->Cmd_Ctr & 0x00FF0000) >> 16);
        aTmpBuf[wValidMacData++] = (uint8_t)((pDataParams->Cmd_Ctr & 0x0000FF00) >> 8);
        aTmpBuf[wValidMacData++] = (uint8_t)((pDataParams->Cmd_Ctr & 0x000000FF) >> 0);
    }
    else
    {
        /* Get pending data*/
        memcpy(aTmpBuf, pDataParams->bPendingMacRespData, (uint16_t)pDataParams->bPendingMacRespDataLength);  /* PRQA S 3200 */
        wValidMacData = pDataParams->bPendingMacRespDataLength;
        pDataParams->bPendingMacRespDataLength = 0;

        /* Load pending response MAC */
        PH_CHECK_SUCCESS_FCT(statusTmp, phCryptoSym_LoadIv(
            pDataParams->pMACCryptoDataParams,
            pDataParams->bPendingRespMac,
            PH_CRYPTOSYM_AES_BLOCK_SIZE));
    }

    /* Now recopy the remaining data into the aTmpBuf in case of we have user data */
    wHelper = 16 - wValidMacData;
    if (wPayloadLength)
    {
        if (wHelper > wPayloadLength)
        {
            wHelper = wPayloadLength;
            wPayloadLength = 0;
        }
        else
        {
            /* wHelper is ok */
            wPayloadLength = wPayloadLength - wHelper;
        }
    }
    else
    {
        wHelper = 0;
    }

    memcpy(&aTmpBuf[wValidMacData], pBuffer, (uint16_t)wHelper);  /* PRQA S 3200 */

    wValidMacData = wValidMacData + wHelper;

    if (wValidMacData == 16 && wPayloadLength != 0)
    {
        /* Switch to CMAC mode without padding*/
        PH_CHECK_SUCCESS_FCT(statusTmp, phCryptoSym_CalculateMac(
            pDataParams->pMACCryptoDataParams,
            PH_CRYPTOSYM_MAC_MODE_CMAC | PH_EXCHANGE_BUFFER_CONT,
            aTmpBuf,
            wValidMacData,
            pDataParams->bPendingRespMac,
            &bMacLength));

        /* Now add everything but the last block */
        /* now we calculate all blocks but the last one*/
        wValidMacData = wPayloadLength;

        /* calculate pending data of last block */
        wPayloadLength = (wValidMacData % 16);
        if ((wValidMacData >= 16) && (wPayloadLength == 0))
        {
            wValidMacData = (wValidMacData - 16);
            wPayloadLength = 16;
        }
        else
        {
            wValidMacData = (wValidMacData - wPayloadLength);
        }

        /* If we have data, we can now MAC it */
        if (wValidMacData)
        {
            PH_CHECK_SUCCESS_FCT(statusTmp, phCryptoSym_CalculateMac(
                pDataParams->pMACCryptoDataParams,
                PH_CRYPTOSYM_MAC_MODE_CMAC | PH_EXCHANGE_BUFFER_CONT,
                &pBuffer[wHelper],
                wValidMacData,
                pDataParams->bPendingRespMac,
                &bMacLength));
        }

        /* Recopy the last chunk into the tmp Buffer */
        memcpy(aTmpBuf, &pBuffer[wHelper + wValidMacData], (uint16_t)wPayloadLength);  /* PRQA S 3200 */
        wValidMacData = wPayloadLength;
    }

    /* Last block - Verify MAC */
    if (bLast)
    {
        pDataParams->bPendingMacRespDataLength  = 0;

        /* CMAC mode with padding*/
        PH_CHECK_SUCCESS_FCT(statusTmp, phCryptoSym_CalculateMac(
            pDataParams->pMACCryptoDataParams,
            PH_CRYPTOSYM_MAC_MODE_CMAC | PH_EXCHANGE_BUFFER_LAST,
            aTmpBuf,
            wValidMacData,
            pDataParams->bPendingRespMac,
            &bMacLength));

        /* we have to truncate the MAC*/
        PH_CHECK_SUCCESS_FCT(statusTmp, phhalHw_SamAV3_Utils_TruncateMacBuffer(pDataParams->bPendingRespMac, &bMacLength));

        if ((bMacLength != 8) || (wRxLength < (PHHAL_HW_SAMAV3_ISO7816_SW1SW2_LENGTH + bMacLength)))
        {
            return PH_ADD_COMPCODE(PHHAL_HW_SAMAV3_ERR_CRYPTO, PH_COMP_HAL);
        }

        /* compare the MACed in response with the calculated MAC*/
        if (memcmp(pDataParams->bPendingRespMac, &pBuffer[wRxLength - (PHHAL_HW_SAMAV3_ISO7816_SW1SW2_LENGTH + bMacLength)], bMacLength))
        {
            return PH_ADD_COMPCODE(PHHAL_HW_SAMAV3_ERR_CRYPTO, PH_COMP_HAL);
        }

        /* now, we can remove the MAC*/
        *pRxLength = wRxLength - bMacLength;

        /* Reorder SW1 SW2 */
        pBuffer[wRxLength - (PHHAL_HW_SAMAV3_ISO7816_SW1SW2_LENGTH + bMacLength)] = pBuffer[wRxLength - PHHAL_HW_SAMAV3_ISO7816_SW1SW2_LENGTH];
        pBuffer[wRxLength - (1 + bMacLength)] = pBuffer[wRxLength - 1];
    }
    else
    {
        /* Setup pending data*/
        memcpy(pDataParams->bPendingMacRespData, aTmpBuf, (uint16_t)wValidMacData);  /* PRQA S 3200 */
        pDataParams->bPendingMacRespDataLength = (uint8_t)wValidMacData;

        /* End UnMACing Process */
        *pRxLength = wRxLength;
    }

    return PH_ADD_COMPCODE(PH_ERR_SUCCESS, PH_COMP_HAL);
}

phStatus_t phhalHw_SamAV3_HSM_AES_Encrypt(phhalHw_SamAV3_DataParams_t * pDataParams, uint8_t * pBuffer, uint16_t wTxLength, uint16_t wBufferSize, uint16_t * pTxLength,
	uint8_t bFirst, uint8_t bLast)
{
    phStatus_t statusTmp;
    uint8_t LePresent =  PH_OFF;
    uint8_t LcPresent =  PH_OFF;
    uint8_t bLc = 0;
    uint8_t bLe;
    uint8_t bTmpBuf[16];

    uint16_t wHelper;
    uint16_t wCurrentEncryptedDataSize;
    uint16_t wRemainingDataSize;

    *pTxLength = wTxLength;

    PH_CHECK_SUCCESS_FCT(statusTmp, phhalHw_SamAV3_Utils_GetCheckLcLe(pBuffer, wTxLength, &LcPresent, &bLc, &LePresent));

    if (bFirst)
    {
        /* load the InitializationVector, because we start a new Encryption.
        This has to be done even if no data are send to the SAM. */
        PH_CHECK_SUCCESS_FCT(statusTmp, phhalHw_SamAV3_HSM_AES_InitAndLoadIV(pDataParams, pDataParams->bPendingCmdIv, true));
    }
    else
    {
        /* Load encryption IV */
        PH_CHECK_SUCCESS_FCT(statusTmp, phCryptoSym_LoadIv(
            pDataParams->pENCCryptoDataParams,
            pDataParams->bPendingCmdIv,
            PH_CRYPTOSYM_AES_BLOCK_SIZE));
    }

    /* Do we need encryption at all? */
    if (!bLc)
    {
        return PH_ADD_COMPCODE(PH_ERR_SUCCESS, PH_COMP_HAL);
    }

    /* Check for overall size */
    if ((wTxLength) > (wBufferSize - 15))
    {
        return PH_ADD_COMPCODE(PH_ERR_BUFFER_OVERFLOW, PH_COMP_HAL);
    }

    /*/////////////////////////
    // Start Encryption Process
    ///////////////////////////
    // At this point, the encryption process can be started and processed
    // we only have to know if a frame chaining was running*/

    /* save Le byte */
    bLe = pBuffer[wTxLength - 1];

    if (bFirst)
    {
        /* Find all blocks but the last block */
        wRemainingDataSize = (bLc % 16);

        wCurrentEncryptedDataSize = ((uint16_t)bLc - wRemainingDataSize);

        if (wCurrentEncryptedDataSize)
        {
            /* Encrypt everything but the last block*/
            PH_CHECK_SUCCESS_FCT(statusTmp, phCryptoSym_Encrypt(
                pDataParams->pENCCryptoDataParams,
                PH_CRYPTOSYM_CIPHER_MODE_CBC | PH_EXCHANGE_BUFFER_CONT,
                &pBuffer[PHHAL_HW_SAMAV3_ISO7816_HEADER_LENGTH],
                wCurrentEncryptedDataSize,
                &pBuffer[PHHAL_HW_SAMAV3_ISO7816_HEADER_LENGTH]));
        }

        /* Recopy remaining part */
        memcpy(bTmpBuf, &pBuffer[PHHAL_HW_SAMAV3_ISO7816_HEADER_LENGTH + wCurrentEncryptedDataSize], wRemainingDataSize);  /* PRQA S 3200 */
    }
    else
    {
        /* How much data do we still have? - wHelper contains already consumed data out of pBuffer */
        wHelper = 16 - pDataParams->bPendingEncCmdDataLength;
        wCurrentEncryptedDataSize = 0;

        /* Do we have sufficient user Payload? */
        if (wHelper > bLc)
        {
            memcpy(bTmpBuf, pDataParams->bPendingEncCmdData, pDataParams->bPendingEncCmdDataLength);  /* PRQA S 3200 */
            memcpy(&bTmpBuf[pDataParams->bPendingEncCmdDataLength], &pBuffer[PHHAL_HW_SAMAV3_ISO7816_HEADER_LENGTH], bLc);  /* PRQA S 3200 */
            wRemainingDataSize = pDataParams->bPendingEncCmdDataLength + bLc;
        }
        else
        {
            memcpy(&pDataParams->bPendingEncCmdData[pDataParams->bPendingEncCmdDataLength], &pBuffer[PHHAL_HW_SAMAV3_ISO7816_HEADER_LENGTH], wHelper);  /* PRQA S 3200 */

            /* Encrypt first block*/
            PH_CHECK_SUCCESS_FCT(statusTmp, phCryptoSym_Encrypt(
                pDataParams->pENCCryptoDataParams,
                PH_CRYPTOSYM_CIPHER_MODE_CBC | PH_EXCHANGE_BUFFER_CONT,
                pDataParams->bPendingEncCmdData,
                16,
                pDataParams->bPendingEncCmdData));

            wRemainingDataSize = (((uint16_t)bLc - wHelper) % 16);

            /* Next blocks we can now encipher inline */
            wCurrentEncryptedDataSize = ((uint16_t)bLc - wRemainingDataSize - wHelper);

            if (wCurrentEncryptedDataSize)
            {
                PH_CHECK_SUCCESS_FCT(statusTmp, phCryptoSym_Encrypt(
                    pDataParams->pENCCryptoDataParams,
                    PH_CRYPTOSYM_CIPHER_MODE_CBC | PH_EXCHANGE_BUFFER_CONT,
                    &pBuffer[PHHAL_HW_SAMAV3_ISO7816_HEADER_LENGTH + wHelper],
                    wCurrentEncryptedDataSize,
                    &pBuffer[PHHAL_HW_SAMAV3_ISO7816_HEADER_LENGTH + wHelper]));

                /* Now move the data to the TmpBuf*/
                memcpy(bTmpBuf, &pBuffer[PHHAL_HW_SAMAV3_ISO7816_HEADER_LENGTH + wHelper + wCurrentEncryptedDataSize ], wRemainingDataSize);  /* PRQA S 3200 */

                /* Now move encrypted payload to the end */
                memmove(&pBuffer[PHHAL_HW_SAMAV3_ISO7816_HEADER_LENGTH + 16], &pBuffer[PHHAL_HW_SAMAV3_ISO7816_HEADER_LENGTH + wHelper], (uint16_t)wCurrentEncryptedDataSize);  /* PRQA S 3200 */

            }else
            {
                /* Recopy remaining part */
                memcpy(bTmpBuf, &pBuffer[PHHAL_HW_SAMAV3_ISO7816_HEADER_LENGTH + wHelper], wRemainingDataSize);  /* PRQA S 3200 */
            }

            /* Now copy the stuff to the front */
            memcpy(&pBuffer[PHHAL_HW_SAMAV3_ISO7816_HEADER_LENGTH], pDataParams->bPendingEncCmdData, 16);  /* PRQA S 3200 */
            wCurrentEncryptedDataSize = wCurrentEncryptedDataSize + 16;
        }
    }

    /* Is this the last command in a sequence? */
    if (bLast)
    {
        /* copy temporary buffer to the end of the Tx Buffer */
        PH_CHECK_SUCCESS_FCT(statusTmp, phCryptoSym_ApplyPadding(
            PH_CRYPTOSYM_PADDING_MODE_2,
            bTmpBuf,
            wRemainingDataSize,
            PH_CRYPTOSYM_AES_BLOCK_SIZE,
            16,
            bTmpBuf,
            &wRemainingDataSize));

        /* now encrypt the data */
        PH_CHECK_SUCCESS_FCT(statusTmp, phCryptoSym_Encrypt(
            pDataParams->pENCCryptoDataParams,
            PH_CRYPTOSYM_CIPHER_MODE_CBC | PH_EXCHANGE_BUFFER_LAST,
            bTmpBuf,
            wRemainingDataSize,
            &pBuffer[PHHAL_HW_SAMAV3_ISO7816_HEADER_LENGTH + wCurrentEncryptedDataSize]));

        wCurrentEncryptedDataSize = wCurrentEncryptedDataSize + 16;
    }
    else
    {
        if (wCurrentEncryptedDataSize >= 16)
        {
            /* Recopy last block of the encrypted data into the temporary IV space */
            memcpy(pDataParams->bPendingCmdIv, &pBuffer[PHHAL_HW_SAMAV3_ISO7816_HEADER_LENGTH + wCurrentEncryptedDataSize - 16], sizeof(pDataParams->bPendingCmdIv));  /* PRQA S 3200 */
        }

        /* Copy data into pending data structure */
        memcpy(pDataParams->bPendingEncCmdData, bTmpBuf, wRemainingDataSize);  /* PRQA S 3200 */
        pDataParams->bPendingEncCmdDataLength = (uint8_t)(wRemainingDataSize);
    }

    /* Update Lc */
    pBuffer[PHHAL_HW_SAMAV3_ISO7816_LC_POS] = (uint8_t)wCurrentEncryptedDataSize;

    /* Update overall length */
    if (bLc > wCurrentEncryptedDataSize)
    {
        bLc = (uint8_t)(bLc - wCurrentEncryptedDataSize);
        wTxLength = wTxLength - bLc;
    }
    else
    {
        bLc = (uint8_t)(wCurrentEncryptedDataSize - bLc);
        wTxLength = wTxLength + bLc;
    }

    /* Update Le */
    if (LePresent)
    {
        pBuffer[wTxLength - 1] = bLe;
    }

    *pTxLength = wTxLength;
    /* End Encryption Process */
    return PH_ADD_COMPCODE(PH_ERR_SUCCESS, PH_COMP_HAL);
}

phStatus_t phhalHw_SamAV3_HSM_AES_InitAndLoadIV(phhalHw_SamAV3_DataParams_t * pDataParams, uint8_t* pIV, uint8_t encryptionIV)
{
    phStatus_t statusTmp;
    /*    IV(16 bytes) = 0x1|0x1|0x1|0x1|cmd_ctr[0..3]|cmd_ctr[0..3]|cmd_ctr[0..3] */
    /* build the IV */
    uint8_t i;

    /* Load null keys to encrypt IV */
    PH_CHECK_SUCCESS_FCT(statusTmp, phCryptoSym_LoadIv(
        pDataParams->pENCCryptoDataParams,
        phhalHw_SamAV3_Hc_AV2_FirstIv,
        PH_CRYPTOSYM_AES_BLOCK_SIZE));

    if (encryptionIV)
    {
        for (i = 0; i < 4; i++)
            pIV[i] = 0x01;
        for ( i = 1; i < 4; i++)
        {
            pIV[4*i] = (uint8_t)((pDataParams->Cmd_Ctr & 0xFF000000) >> 24);
            pIV[4*i+1] = (uint8_t)((pDataParams->Cmd_Ctr & 0x00FF0000) >> 16);
            pIV[4*i+2] = (uint8_t)((pDataParams->Cmd_Ctr & 0x0000FF00) >> 8);
            pIV[4*i+3] = (uint8_t)((pDataParams->Cmd_Ctr & 0x000000FF) >> 0);
        }
    }
    else
    {
        for (i = 0; i < 4; i++)
            pIV[i] = 0x02;
        for ( i = 1; i < 4; i++)
        {
            pIV[4*i] = (uint8_t)((pDataParams->Cmd_Ctr & 0xFF000000) >> 24);
            pIV[4*i+1] = (uint8_t)((pDataParams->Cmd_Ctr & 0x00FF0000) >> 16);
            pIV[4*i+2] = (uint8_t)((pDataParams->Cmd_Ctr & 0x0000FF00) >> 8);
            pIV[4*i+3] = (uint8_t)((pDataParams->Cmd_Ctr & 0x000000FF) >> 0);
        }
    }

    /* Encrypt IV */
    PH_CHECK_SUCCESS_FCT(statusTmp, phCryptoSym_Encrypt(
        pDataParams->pENCCryptoDataParams,
        PH_CRYPTOSYM_CIPHER_MODE_CBC | PH_EXCHANGE_BUFFER_FIRST,
        pIV,
        16,
        pIV));

    return PH_ADD_COMPCODE(PH_ERR_SUCCESS, PH_COMP_HAL);
}
#endif /* NXPBUILD__PHHAL_HW_SAMAV3 */
