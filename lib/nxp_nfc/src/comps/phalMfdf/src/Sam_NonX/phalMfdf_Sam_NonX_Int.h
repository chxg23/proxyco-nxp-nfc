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

#ifndef PHALMFDF_SAM_NONX_INT_H
#define PHALMFDF_SAM_NONX_INT_H

#include <nxp_nfc/ph_Status.h>
#include <nxp_nfc/phalMfdf.h>
#ifdef NXPBUILD__PHAL_MFUL_SAMAV3_X
#include <phhalHw_SamAV3_Cmd.h>
#endif /* NXPBUILD__PHAL_MFUL_SAMAV3_X */

#ifdef NXPBUILD__PHAL_MFUL_SAMAV2_X
#include <phhalHw_SamAV2_Cmd.h>
#endif /* NXPBUILD__PHAL_MFUL_SAMAV2_X */

/** Mifare Desfire  frame lengths */
#define PHALMFDF_SAM_DATA_FRAME_LENGTH						224		/* Maximum data that can be exchanged in case of secure messaging computation by SAM. */

/** MIFARE Desfire  ISO 7816-4 wrapped response information */
#define PHALMFDF_RESP_WRAPPED_MSB_BYTE						0x9100U   /* MSB response information in case of Iso7816 wrapping of Native commands. */

/** MIFARE Desfire  Sam Non X command options. This flag will be used to compute the response. */
#define PHALMFDF_SAM_NONX_CMD_OPTION_NONE					0U		/**< Command option as None. This flag is used to discard the processing of last command exchange. */
#define PHALMFDF_SAM_NONX_CMD_OPTION_COMPLETE				1U		/**< Command option as complete. This flag is used to check the response other than AF. */
#define PHALMFDF_SAM_NONX_CMD_OPTION_PENDING				2U		/**< Command option as complete. This flag is used to check for AF response. */

/** MIFARE Desfire  Sam Non X command options. This flag will be used to compute the MAc on command or not. */
#define PHALMFDF_SAM_NONX_NO_MAC_ON_CMD						0x00	/**< Mac on command is not available. */
#define PHALMFDF_SAM_NONX_MAC_ON_CMD						0x01	/**< Mac on commnd is available. */
#define PHALMFDF_SAM_NONX_EXCHANGE_DATA_PICC				0x02	/**< Exchange the data to PICC. */
#define PHALMFDF_SAM_NONX_EXCHANGE_PICC_STATUS				0x10	/**< Exchange the status. */
#define PHALMFDF_SAM_NONX_RETURN_CHAINING_STATUS			0x20	/**< Return the chaining status to the user if available. */
#define PHALMFDF_SAM_NONX_EXCHANGE_WITHOUT_SM				0x40	/**< Exchange the information to / from PICC with Secure messaging in command or response. */
#define PHALMFDF_SAM_NONX_PICC_STATUS_WRAPPED				0x80	/**< The PICC status is wrapped. */

/* Pal Exchange L4 command =========================================================================================================================================== */
#ifdef NXPBUILD__PHAL_MFDF_SAMAV3_NONX
#define PHPAL_MIFARE_EXCHANGE_L4(DataParams, Option, TxData, TxDataLen, RxData, RxDataLen)																	\																																		\
			(PH_GET_COMPID(DataParams) == PHAL_MFDF_SAMAV3_NONX_ID) ?																						\
				phpalMifare_ExchangeL4(((phalMfdf_SamAV3_NonX_DataParams_t *) DataParams)->pPalMifareDataParams, Option, TxData, TxDataLen, RxData,			\
				RxDataLen) :																																\
																																							\
				PH_ADD_COMPCODE(PH_ERR_INVALID_DATA_PARAMS, PH_COMP_AL_MFDF)
#endif /* NXPBUILD__PHAL_MFDF_SAMAV3_NONX */
#ifdef NXPBUILD__PHAL_MFDF_SAMAV2_NONX
#define PHPAL_MIFARE_EXCHANGE_L4(DataParams, Option, TxData, TxDataLen, RxData, RxDataLen)																	\
			(PH_GET_COMPID(DataParams) == PHAL_MFDF_SAMAV2_ID) ? 																							\
				phpalMifare_ExchangeL4(((phalMfdf_SamAV2_DataParams_t *) DataParams)->pPalMifareDataParams, Option, TxData, TxDataLen, RxData, RxDataLen) :	\
																																							\
				PH_ADD_COMPCODE(PH_ERR_INVALID_DATA_PARAMS, PH_COMP_AL_MFDF)
#endif /* NXPBUILD__PHAL_MFDF_SAMAV2_NONX */

/* Pal GetConfig L4 command ========================================================================================================================================== */
#ifdef NXPBUILD__PHAL_MFDF_SAMAV3_NONX
#define PHPAL_MIFARE_GETCONFIG(DataParams, Config, Value)																									\																																	\
			(PH_GET_COMPID(DataParams) == PHAL_MFDF_SAMAV3_NONX_ID) ?																						\
				phpalMifare_GetConfig(((phalMfdf_SamAV3_NonX_DataParams_t *) DataParams)->pPalMifareDataParams, Config, Value) :							\
																																							\
				PH_ADD_COMPCODE(PH_ERR_INVALID_DATA_PARAMS, PH_COMP_AL_MFDF)
#endif /* NXPBUILD__PHAL_MFDF_SAMAV3_NONX */
#ifdef NXPBUILD__PHAL_MFDF_SAMAV2_NONX
#define PHPAL_MIFARE_GETCONFIG(DataParams, Config, Value)																									\
			(PH_GET_COMPID(DataParams) == PHAL_MFDF_SAMAV2_ID) ? 																							\
				phpalMifare_GetConfig(((phalMfdf_SamAV2_DataParams_t *) DataParams)->pPalMifareDataParams, Config, Value) :									\
																																							\
				PH_ADD_COMPCODE(PH_ERR_INVALID_DATA_PARAMS, PH_COMP_AL_MFDF)
#endif /* NXPBUILD__PHAL_MFDF_SAMAV2_NONX */

/* Authenticate Part1 command ======================================================================================================================================== */
#ifdef NXPBUILD__PHAL_MFDF_SAMAV3_NONX
#define PHHAL_HW_CMD_SAM_AUTHENTICATE_PART1(DataParams, Option, KeyNo, KeyVer, DivInput, DivInputLen, CardResp, CardRespLen, SamResp, SamRespLen)			\
			(PH_GET_COMPID(DataParams) == PHAL_MFDF_SAMAV3_NONX_ID) ?																						\
				phhalHw_SamAV3_Cmd_SAM_AuthenticatePICC_Part1(((phalMfdf_SamAV3_NonX_DataParams_t *) DataParams)->pHalSamDataParams, Option, KeyNo, KeyVer,	\
					0x00, DivInput, DivInputLen, CardResp, CardRespLen, &SamResp, &SamRespLen) :															\
																																							\
				PH_ADD_COMPCODE(PH_ERR_INVALID_DATA_PARAMS, PH_COMP_AL_MFDF)
#endif /* NXPBUILD__PHAL_MFDF_SAMAV3_NONX */
#ifdef NXPBUILD__PHAL_MFDF_SAMAV2_NONX
#define PHHAL_HW_CMD_SAM_AUTHENTICATE_PART1(DataParams, Option, KeyNo, KeyVer, DivInput, DivInputLen, CardResp, CardRespLen, SamResp, SamRespLen)			\
			(PH_GET_COMPID(DataParams) == PHAL_MFDF_SAMAV2_ID) ? 																							\
				phhalHw_SamAV2_Cmd_SAM_AuthenticatePICC_Part1(((phalMfdf_SamAV2_DataParams_t *) DataParams)->pHalSamDataParams, Option, KeyNo, KeyVer,		\
					CardResp, CardRespLen, DivInput, DivInputLen, SamResp, (uint8_t *) &SamRespLen) :														\
																																							\
				PH_ADD_COMPCODE(PH_ERR_INVALID_DATA_PARAMS, PH_COMP_AL_MFDF)
#endif /* NXPBUILD__PHAL_MFDF_SAMAV2_NONX */

/* Authenticate Part1 command ======================================================================================================================================== */
#ifdef NXPBUILD__PHAL_MFDF_SAMAV3_NONX
#define PHHAL_HW_CMD_SAM_AUTHENTICATE_PART2(DataParams, PICCErrCode, CardResp, CardRespLen, SamResp)														\
			(PH_GET_COMPID(DataParams) == PHAL_MFDF_SAMAV3_NONX_ID) ?																						\
				phhalHw_SamAV3_Cmd_SAM_AuthenticatePICC_Part2(((phalMfdf_SamAV3_NonX_DataParams_t *) DataParams)->pHalSamDataParams, PICCErrCode, CardResp, \
				CardRespLen, NULL, NULL, SamResp) :																											\
																																							\
				PH_ADD_COMPCODE(PH_ERR_INVALID_DATA_PARAMS, PH_COMP_AL_MFDF)
#endif /* NXPBUILD__PHAL_MFDF_SAMAV3_NONX */
#ifdef NXPBUILD__PHAL_MFDF_SAMAV2_NONX
#define PHHAL_HW_CMD_SAM_AUTHENTICATE_PART2(DataParams, PICCErrCode, CardResp, CardRespLen, SamResp)														\
			(PH_GET_COMPID(DataParams) == PHAL_MFDF_SAMAV2_ID) ? 																							\
				phhalHw_SamAV2_Cmd_SAM_AuthenticatePICC_Part2(((phalMfdf_SamAV2_DataParams_t *) DataParams)->pHalSamDataParams, CardResp, CardRespLen) :	\
																																							\
				PH_ADD_COMPCODE(PH_ERR_INVALID_DATA_PARAMS, PH_COMP_AL_MFDF)
#endif /* NXPBUILD__PHAL_MFDF_SAMAV2_NONX */

/* ChangeKey command ================================================================================================================================================= */
#ifdef NXPBUILD__PHAL_MFDF_SAMAV3_NONX
#define PHHAL_HW_CMD_SAM_CHANGE_KEY(DataParams, CryptoMethod, Config, CurrKeyNo, CurrKeyVer, NewKeyNo, NewKeyVer, DivInput, DivInputLen, SamResponse,		\
			SamRespLen)																																		\
			(PH_GET_COMPID(DataParams) == PHAL_MFDF_SAMAV3_NONX_ID) ?																						\
				phhalHw_SamAV3_Cmd_SAM_ChangeKeyPICC(((phalMfdf_SamAV3_NonX_DataParams_t *) DataParams)->pHalSamDataParams, CryptoMethod, Config, 0, 0,		\
					CurrKeyNo, CurrKeyVer, NewKeyNo, NewKeyVer,	DivInput, DivInputLen, &SamResponse, &SamRespLen):											\
																																							\
				PH_ADD_COMPCODE(PH_ERR_INVALID_DATA_PARAMS, PH_COMP_AL_MFDF)
#endif /* NXPBUILD__PHAL_MFDF_SAMAV3_NONX */
#ifdef NXPBUILD__PHAL_MFDF_SAMAV2_NONX
#define PHHAL_HW_CMD_SAM_CHANGE_KEY(DataParams, CryptoMethod, Config, CurrKeyNo, CurrKeyVer, NewKeyNo, NewKeyVer, DivInput, DivInputLen, SamResponse,		\
			SamRespLen)																																		\
			(PH_GET_COMPID(DataParams) == PHAL_MFDF_SAMAV2_ID) ? 																							\
				phhalHw_SamAV2_Cmd_SAM_ChangeKeyPICC(((phalMfdf_SamAV2_DataParams_t *) DataParams)->pHalSamDataParams, CryptoMethod, Config, CurrKeyNo,		\
					CurrKeyVer, NewKeyNo, NewKeyVer, DivInput, DivInputLen, SamResponse, (uint8_t * ) &SamRespLen) :										\
																																							\
				PH_ADD_COMPCODE(PH_ERR_INVALID_DATA_PARAMS, PH_COMP_AL_MFDF)
#endif /* NXPBUILD__PHAL_MFDF_SAMAV2_NONX */

/* GenerateMAC command =============================================================================================================================================== */
#ifdef NXPBUILD__PHAL_MFDF_SAMAV3_NONX
#define PHHAL_HW_CMD_SAM_GENERATE_MAC(DataParams, Option, Num, TxData, TxDataLen, SamResp, SamRespLen)														\
			(PH_GET_COMPID(DataParams) == PHAL_MFDF_SAMAV3_NONX_ID) ?																						\
				phhalHw_SamAV3_Cmd_SAM_GenerateMAC(((phalMfdf_SamAV3_NonX_DataParams_t *) DataParams)->pHalSamDataParams, Option, Num, TxData, TxDataLen,	\
					SamResp, SamRespLen):																													\
																																							\
				PH_ADD_COMPCODE(PH_ERR_INVALID_DATA_PARAMS, PH_COMP_AL_MFDF)
#endif /* NXPBUILD__PHAL_MFDF_SAMAV3_NONX */
#ifdef NXPBUILD__PHAL_MFDF_SAMAV2_NONX
#define PHHAL_HW_CMD_SAM_GENERATE_MAC(DataParams, Option, Num, TxData, TxDataLen, SamResp, SamRespLen)														\
			(PH_GET_COMPID(DataParams) == PHAL_MFDF_SAMAV2_ID) ? 																							\
				phhalHw_SamAV2_Cmd_SAM_GenerateMAC(((phalMfdf_SamAV2_DataParams_t *) DataParams)->pHalSamDataParams, Option, Num, TxData, TxDataLen,		\
					SamResp, SamRespLen):																													\
																																							\
				PH_ADD_COMPCODE(PH_ERR_INVALID_DATA_PARAMS, PH_COMP_AL_MFDF)
#endif /* NXPBUILD__PHAL_MFDF_SAMAV2_NONX */

/* Verify command ==================================================================================================================================================== */
#ifdef NXPBUILD__PHAL_MFDF_SAMAV3_NONX
#define PHHAL_HW_CMD_SAM_VERIFY_MAC(DataParams, Option, Num, TxData, TxDataLen)																				\
			(PH_GET_COMPID(DataParams) == PHAL_MFDF_SAMAV3_NONX_ID) ?																						\
				phhalHw_SamAV3_Cmd_SAM_VerifyMAC(((phalMfdf_SamAV3_NonX_DataParams_t *) DataParams)->pHalSamDataParams, Option, Num, TxData, TxDataLen):	\
																																							\
				PH_ADD_COMPCODE(PH_ERR_INVALID_DATA_PARAMS, PH_COMP_AL_MFDF)
#endif /* NXPBUILD__PHAL_MFDF_SAMAV3_NONX */
#ifdef NXPBUILD__PHAL_MFDF_SAMAV2_NONX
#define PHHAL_HW_CMD_SAM_VERIFY_MAC(DataParams, Option, Num, TxData, TxDataLen)																				\
			(PH_GET_COMPID(DataParams) == PHAL_MFDF_SAMAV2_ID) ? 																							\
				phhalHw_SamAV2_Cmd_SAM_VerifyMAC(((phalMfdf_SamAV2_DataParams_t *) DataParams)->pHalSamDataParams, Option, Num, TxData, TxDataLen) :		\
																																							\
				PH_ADD_COMPCODE(PH_ERR_INVALID_DATA_PARAMS, PH_COMP_AL_MFDF)
#endif /* NXPBUILD__PHAL_MFDF_SAMAV2_NONX */

/* Encipher command ================================================================================================================================================== */
#ifdef NXPBUILD__PHAL_MFDF_SAMAV3_NONX
#define PHHAL_HW_CMD_SAM_ENCIPHER_DATA(DataParams, Option, TxData, TxDataLen, Offset, SamResp, SamRespLen)													\
			(PH_GET_COMPID(DataParams) == PHAL_MFDF_SAMAV3_NONX_ID) ?																						\
				phhalHw_SamAV3_Cmd_SAM_EncipherData(((phalMfdf_SamAV3_NonX_DataParams_t *) DataParams)->pHalSamDataParams, Option, TxData, TxDataLen,		\
					Offset, SamResp, SamRespLen):																											\
																																							\
				PH_ADD_COMPCODE(PH_ERR_INVALID_DATA_PARAMS, PH_COMP_AL_MFDF)
#endif /* NXPBUILD__PHAL_MFDF_SAMAV3_NONX */
#ifdef NXPBUILD__PHAL_MFDF_SAMAV2_NONX
#define PHHAL_HW_CMD_SAM_ENCIPHER_DATA(DataParams, Option, TxData, TxDataLen, Offset, SamResp, SamRespLen)													\
			(PH_GET_COMPID(DataParams) == PHAL_MFDF_SAMAV2_ID) ? 																							\
				phhalHw_SamAV2_Cmd_SAM_EncipherData(((phalMfdf_SamAV2_DataParams_t *) DataParams)->pHalSamDataParams, Option, TxData, TxDataLen,			\
					Offset, SamResp, SamRespLen):																											\
																																							\
				PH_ADD_COMPCODE(PH_ERR_INVALID_DATA_PARAMS, PH_COMP_AL_MFDF)
#endif /* NXPBUILD__PHAL_MFDF_SAMAV2_NONX */

/* Decipher command ================================================================================================================================================== */
#ifdef NXPBUILD__PHAL_MFDF_SAMAV3_NONX
#define PHHAL_HW_CMD_SAM_DECIPHER_DATA(DataParams, Option, TxData, TxDataLen, Length, SamResp, SamRespLen)													\
			(PH_GET_COMPID(DataParams) == PHAL_MFDF_SAMAV3_NONX_ID) ?																						\
				phhalHw_SamAV3_Cmd_SAM_DecipherData(((phalMfdf_SamAV3_NonX_DataParams_t *) DataParams)->pHalSamDataParams, Option, TxData, TxDataLen,		\
					Length, SamResp, SamRespLen):																											\
																																							\
				PH_ADD_COMPCODE(PH_ERR_INVALID_DATA_PARAMS, PH_COMP_AL_MFDF)
#endif /* NXPBUILD__PHAL_MFDF_SAMAV3_NONX */
#ifdef NXPBUILD__PHAL_MFDF_SAMAV2_NONX
#define PHHAL_HW_CMD_SAM_DECIPHER_DATA(DataParams, Option, TxData, TxDataLen, Length, SamResp, SamRespLen)													\
			(PH_GET_COMPID(DataParams) == PHAL_MFDF_SAMAV2_ID) ? 																							\
				phhalHw_SamAV2_Cmd_SAM_DecipherData(((phalMfdf_SamAV2_DataParams_t *) DataParams)->pHalSamDataParams, Option, TxData, TxDataLen,			\
					Length, SamResp, SamRespLen):																											\
																																							\
				PH_ADD_COMPCODE(PH_ERR_INVALID_DATA_PARAMS, PH_COMP_AL_MFDF)
#endif /* NXPBUILD__PHAL_MFDF_SAMAV2_NONX */

/* HAL GetConfig command ============================================================================================================================================= */
#ifdef NXPBUILD__PHAL_MFDF_SAMAV3_NONX
#define PHHAL_HW_GET_CONFIG(DataParams, Config, Value)																										\
			(PH_GET_COMPID(DataParams) == PHAL_MFDF_SAMAV3_NONX_ID) ?																						\
				phhalHw_GetConfig(((phalMfdf_SamAV3_NonX_DataParams_t *) DataParams)->pHalSamDataParams, Config, Value ) :									\
																																							\
				PH_ADD_COMPCODE(PH_ERR_INVALID_DATA_PARAMS, PH_COMP_AL_MFDF)
#endif /* NXPBUILD__PHAL_MFDF_SAMAV3_NONX */
#ifdef NXPBUILD__PHAL_MFDF_SAMAV2_NONX
#define PHHAL_HW_GET_CONFIG(DataParams, Config, Value)																										\
			(PH_GET_COMPID(DataParams) == PHAL_MFDF_SAMAV2_ID) ? 																							\
				phhalHw_GetConfig(((phalMfdf_SamAV2_DataParams_t *) DataParams)->pHalSamDataParams, Config, Value ) :										\
																																							\
				PH_ADD_COMPCODE(PH_ERR_INVALID_DATA_PARAMS, PH_COMP_AL_MFDF)
#endif /* NXPBUILD__PHAL_MFDF_SAMAV2_NONX */

/* HAL GetKeyEntry command =========================================================================================================================================== */
#ifdef NXPBUILD__PHAL_MFDF_SAMAV3_NONX
#define PHHAL_HW_CMD_SAM_GET_KEY_ENTRY(DataParams, KeyNo, KeyEntry, KeyEntryLen)																			\
			(PH_GET_COMPID(DataParams) == PHAL_MFDF_SAMAV3_NONX_ID) ?																						\
				phhalHw_SamAV3_Cmd_SAM_GetKeyEntry(((phalMfdf_SamAV3_NonX_DataParams_t *) DataParams)->pHalSamDataParams, KeyNo,							\
					PHHAL_HW_SAMAV3_CMD_SAM_GET_KEY_ENTRY_KEY_ENTRY_SAM_AV2, KeyEntry, KeyEntryLen) :														\
																																							\
				PH_ADD_COMPCODE(PH_ERR_INVALID_DATA_PARAMS, PH_COMP_AL_MFDF)
#endif /* NXPBUILD__PHAL_MFDF_SAMAV3_NONX */
#ifdef NXPBUILD__PHAL_MFDF_SAMAV2_NONX
#define PHHAL_HW_CMD_SAM_GET_KEY_ENTRY(DataParams, KeyNo, KeyEntry, KeyEntryLen)																			\
			(PH_GET_COMPID(DataParams) == PHAL_MFDF_SAMAV2_ID) ? 																							\
				phhalHw_SamAV2_Cmd_SAM_GetKeyEntry(((phalMfdf_SamAV2_DataParams_t *) DataParams)->pHalSamDataParams, KeyNo, KeyEntry, KeyEntryLen ) :		\
																																							\
				PH_ADD_COMPCODE(PH_ERR_INVALID_DATA_PARAMS, PH_COMP_AL_MFDF)
#endif /* NXPBUILD__PHAL_MFDF_SAMAV2_NONX */

/* KillAuthentication command ======================================================================================================================================== */
#ifdef NXPBUILD__PHAL_MFDF_SAMAV3_NONX
#define PHHAL_HW_KILL_AUTHENTICATION(DataParams)																											\
			(PH_GET_COMPID(DataParams) == PHAL_MFDF_SAMAV3_NONX_ID) ?																						\
				phhalHw_SamAV3_Cmd_SAM_KillAuthentication(((phalMfdf_SamAV3_NonX_DataParams_t *) DataParams)->pHalSamDataParams, 0x01 ) :					\
																																							\
				PH_ADD_COMPCODE(PH_ERR_INVALID_DATA_PARAMS, PH_COMP_AL_MFDF)
#endif /* NXPBUILD__PHAL_MFDF_SAMAV3_NONX */
#ifdef NXPBUILD__PHAL_MFDF_SAMAV2_NONX
#define PHHAL_HW_KILL_AUTHENTICATION(DataParams)																											\
			(PH_GET_COMPID(DataParams) == PHAL_MFDF_SAMAV2_ID) ? 																							\
				phhalHw_SamAV2_Cmd_SAM_KillAuthentication(((phalMfdf_SamAV2_DataParams_t *) DataParams)->pHalSamDataParams, 0x01 ) :						\
																																							\
				PH_ADD_COMPCODE(PH_ERR_INVALID_DATA_PARAMS, PH_COMP_AL_MFDF)
#endif /* NXPBUILD__PHAL_MFDF_SAMAV2_NONX */

/* ISOAuthenticate Part1 command ===================================================================================================================================== */
#ifdef NXPBUILD__PHAL_MFDF_SAMAV3_NONX
#define PHHAL_HW_CMD_SAM_ISO_AUTHENTICATE_PART1(DataParams, Option, KeyNo, KeyVer, DivInput, DivInputLen, CardResp, CardRespLen, SamResp, SamRespLen)		\
			(PH_GET_COMPID(DataParams) == PHAL_MFDF_SAMAV3_NONX_ID) ?																						\
				phhalHw_SamAV3_Cmd_SAM_IsoAuthenticatePICC_Part1(((phalMfdf_SamAV3_NonX_DataParams_t *) DataParams)->pHalSamDataParams, Option, KeyNo,		\
					KeyVer, DivInput, DivInputLen, CardResp, CardRespLen, &SamResp, &SamRespLen) :															\
																																							\
				PH_ADD_COMPCODE(PH_ERR_INVALID_DATA_PARAMS, PH_COMP_AL_MFDF)
#endif /* NXPBUILD__PHAL_MFDF_SAMAV3_NONX */
#ifdef NXPBUILD__PHAL_MFDF_SAMAV2_NONX
#define PHHAL_HW_CMD_SAM_ISO_AUTHENTICATE_PART1(DataParams, Option, KeyNo, KeyVer, DivInput, DivInputLen, CardResp, CardRespLen, SamResp, SamRespLen)		\
			(PH_GET_COMPID(DataParams) == PHAL_MFDF_SAMAV2_ID) ? 																							\
				phhalHw_SamAV2_Cmd_SAM_IsoAuthenticatePICC_Part1(((phalMfdf_SamAV2_DataParams_t *) DataParams)->pHalSamDataParams, Option, KeyNo,			\
					KeyVer, CardResp, CardRespLen, DivInput, DivInputLen, SamResp, (uint8_t *) &SamRespLen) :												\
																																							\
				PH_ADD_COMPCODE(PH_ERR_INVALID_DATA_PARAMS, PH_COMP_AL_MFDF)
#endif /* NXPBUILD__PHAL_MFDF_SAMAV2_NONX */

/* ISOAuthenticate Part2 command ===================================================================================================================================== */
#ifdef NXPBUILD__PHAL_MFDF_SAMAV3_NONX
#define PHHAL_HW_CMD_SAM_ISO_AUTHENTICATE_PART2(DataParams, CardResp, CardRespLen)																			\
			(PH_GET_COMPID(DataParams) == PHAL_MFDF_SAMAV3_NONX_ID) ?																						\
				phhalHw_SamAV3_Cmd_SAM_IsoAuthenticatePICC_Part2(((phalMfdf_SamAV3_NonX_DataParams_t *) DataParams)->pHalSamDataParams, CardResp,			\
					CardRespLen) :																															\
																																							\
				PH_ADD_COMPCODE(PH_ERR_INVALID_DATA_PARAMS, PH_COMP_AL_MFDF)
#endif /* NXPBUILD__PHAL_MFDF_SAMAV3_NONX */
#ifdef NXPBUILD__PHAL_MFDF_SAMAV2_NONX
#define PHHAL_HW_CMD_SAM_ISO_AUTHENTICATE_PART2(DataParams, CardResp, CardRespLen)																			\
			(PH_GET_COMPID(DataParams) == PHAL_MFDF_SAMAV2_ID) ? 																							\
				phhalHw_SamAV2_Cmd_SAM_IsoAuthenticatePICC_Part2(((phalMfdf_SamAV2_DataParams_t *) DataParams)->pHalSamDataParams, CardResp,				\
					CardRespLen) :																															\
																																							\
				PH_ADD_COMPCODE(PH_ERR_INVALID_DATA_PARAMS, PH_COMP_AL_MFDF)
#endif /* NXPBUILD__PHAL_MFDF_SAMAV2_NONX */


phStatus_t phalMfdf_Sam_NonX_Int_SetAuthMode(void * pDataParams, uint8_t bAuthMode);
phStatus_t phalMfdf_Sam_NonX_Int_GetAuthMode(void * pDataParams, uint8_t * pAuthMode);

phStatus_t phalMfdf_Sam_NonX_Int_SetKeyNo(void * pDataParams, uint8_t bKeyNo);
phStatus_t phalMfdf_Sam_NonX_Int_GetKeyNo(void * pDataParams, uint8_t * pKeyNo);

phStatus_t phalMfdf_Sam_NonX_Int_SetWrappedMode(void * pDataParams, uint8_t bWrappedMode);
phStatus_t phalMfdf_Sam_NonX_Int_GetWrappedMode(void * pDataParams, uint8_t * pWrappedMode);

phStatus_t phalMfdf_Sam_NonX_Int_SetAdditionalInfo(void * pDataParams, uint16_t wAdditionalInfo);
phStatus_t phalMfdf_Sam_NonX_Int_GetAdditionalInfo(void * pDataParams, uint16_t * pAdditionalInfo);

phStatus_t phalMfdf_Sam_NonX_Int_SetAid(void * pDataParams, uint8_t * pAid);
phStatus_t phalMfdf_Sam_NonX_Int_GetAid(void * pDataParams, uint8_t * pAid);

phStatus_t phalMfdf_Sam_NonX_Int_ValidateResponse(void * pDataParams, uint16_t wStatus, uint16_t wPiccRetCode);

phStatus_t phalMfdf_Sam_NonX_Int_CardExchange(void * pDataParams, uint16_t wBufferOption, uint8_t bCmdOption, uint16_t wTotDataLen, uint8_t bExchangeLE, uint8_t * pData,
	uint16_t wDataLen, uint8_t ** ppResponse, uint16_t * pRespLen, uint8_t * pPiccErrCode);

phStatus_t phalMfdf_Sam_NonX_Int_AuthenticatePICC(void * pDataParams, uint8_t bAuthType, uint16_t wOption, uint16_t wKeyNo, uint16_t wKeyVer, uint8_t bKeyNoCard,
	uint8_t * pDivInput, uint8_t bDivInputLen);

phStatus_t phalMfdf_Sam_NonX_Int_ChangeKeyPICC(void * pDataParams, uint16_t wOption, uint8_t bKeyNoCard, uint16_t wCurrKeyNo, uint16_t wCurrKeyVer, uint16_t wNewKeyNo,
	uint16_t wNewKeyVer, uint8_t * pDivInput, uint8_t bDivInputLen);

phStatus_t phalMfdf_Sam_NonX_Int_GenerateSM(void * pDataParams, uint16_t wOption, uint8_t bIsWriteCmd, uint8_t bIsReadCmd, uint8_t bCommMode, uint8_t * pCmdBuff,
	uint16_t wCmdBufLen, uint8_t * pData, uint16_t wDataLen, uint8_t ** ppOutBuffer, uint16_t * pOutBufLen);

phStatus_t phalMfdf_Sam_NonX_Int_VerifySM(void * pDataParams, uint16_t wOption, uint8_t bCommMode, uint32_t dwLength, uint8_t * pResponse, uint16_t wRespLen,
	uint8_t bPiccStat, uint8_t * pRespMac, uint16_t wRespMacLen, uint8_t ** ppOutBuffer, uint16_t * pOutBufLen);

phStatus_t phalMfdf_Sam_NonX_Int_ReadData(void * pDataParams, uint16_t wOption, uint8_t bIsDataCmd, uint8_t bCmd_ComMode, uint8_t bResp_ComMode, uint32_t dwLength,
	uint8_t * pCmdBuff, uint16_t wCmdLen, uint8_t ** ppResponse, uint16_t * pRespLen);

phStatus_t phalMfdf_Sam_NonX_Int_WriteData(void * pDataParams, uint16_t wOption, uint8_t bIsDataCmd, uint8_t bCmd_ComMode, uint8_t bResp_ComMode, uint8_t bResetAuth,
	uint8_t * pCmdBuff, uint16_t wCmdLen, uint8_t * pData, uint32_t dwDataLen, uint8_t ** ppResponse, uint16_t * pRespLen);

phStatus_t phalMfdf_Sam_NonX_Int_ResetAuthStatus(void * pDataParams);

phStatus_t phalMfdf_Sam_NonX_Int_GetFrameLen(void * pDataParams, uint16_t * pFrameLen);

#endif /* PHALMFDF_SAM_NONX_INT_H */
