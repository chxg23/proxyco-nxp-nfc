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

/**
* \file
* Desfire application SamAV3 NonX component of Reader Library framework.
* $Author: nxp60813 $
* $Revision: 124 $
* $Date: 2013-04-22 12:10:31 +0530 (Mon, 22 Apr 2013) $
*
* History:
*/

#include <nxp_nfc/ph_Status.h>
#include <nxp_nfc/ph_RefDefs.h>
#include <nxp_nfc/ph_TypeDefs.h>
#include <nxp_nfc/phhalHw.h>
#include <nxp_nfc/phpalMifare.h>
#include <string.h>

#include <nxp_nfc/phCryptoSym.h>
#include <nxp_nfc/phCryptoRng.h>
#include <nxp_nfc/phKeyStore.h>
#ifdef NXPBUILD__PHAL_MFDF_SAM_NONX

#include "../phalMfdf_Int.h"
#include "phalMfdf_Sam_NonX.h"
#include "phalMfdf_Sam_NonX_Int.h"

#ifdef NXPBUILD__PHAL_MFP_SAMAV2_NONX
#include <phhalHw_SamAV2_Cmd.h>
#endif /* NXPBUILD__PHAL_MFP_SAMAV2_NONX */

#ifdef NXPBUILD__PHAL_MFP_SAMAV3_NONX
#include <phhalHw_SamAV3_Cmd.h>
#endif /* NXPBUILD__PHAL_MFP_SAMAV3_NONX */

#ifdef NXPBUILD__PHAL_MFP_SAMAV2_NONX
phStatus_t
phalMfdf_SamAV2_Init(phalMfdf_SamAV2_DataParams_t *pDataParams, uint16_t wSizeOfDataParams,
    phhalHw_SamAV2_DataParams_t *pHalSamDataParams,
    void *pHalDataParams, void *pPalMifareDataParams)
{
  PH_ASSERT_NULL_DATA_PARAM(pDataParams, PH_COMP_AL_MFDF);
  PH_ASSERT_NULL_PARAM(pHalSamDataParams, PH_COMP_AL_MFDF);
  PH_ASSERT_NULL_PARAM(pHalDataParams, PH_COMP_AL_MFDF);
  PH_ASSERT_NULL_PARAM(pPalMifareDataParams, PH_COMP_AL_MFDF);

  /* Data Params size Check. */
  if (sizeof(phalMfdf_SamAV2_DataParams_t) != wSizeOfDataParams) {
    return PH_ADD_COMPCODE(PH_ERR_INVALID_DATA_PARAMS, PH_COMP_AL_MFDF);
  }

  /* Initialize dataparams structure members. */
  pDataParams->wId                    = PH_COMP_AL_MFDF | PHAL_MFDF_SAMAV2_ID;
  pDataParams->pPalMifareDataParams   = pPalMifareDataParams;
  pDataParams->pHalSamDataParams      = pHalSamDataParams;
  pDataParams->pHalDataParams         = pHalDataParams;
  pDataParams->bKeyNo                 = 0xFF; /* Set to invalid */
  pDataParams->bAuthMode              = PHAL_MFDF_NOT_AUTHENTICATED; /* Set to invalid */
  pDataParams->bWrappedMode           = 0x00; /* Set to false */
  pDataParams->wAdditionalInfo        = 0x0000;

  return PH_ADD_COMPCODE(PH_ERR_SUCCESS, PH_COMP_AL_MFDF);
#endif /* NXPBUILD__PHAL_MFP_SAMAV2_NONX */

#ifdef NXPBUILD__PHAL_MFP_SAMAV3_NONX
  phStatus_t phalMfdf_SamAV3_NonX_Init(phalMfdf_SamAV3_NonX_DataParams_t *pDataParams,
      uint16_t wSizeOfDataParams, phhalHw_SamAV3_DataParams_t *pHalSamDataParams,
      void *pPalMifareDataParams) {
    PH_ASSERT_NULL_DATA_PARAM(pDataParams, PH_COMP_AL_MFDF);
    PH_ASSERT_NULL_PARAM(pHalSamDataParams, PH_COMP_AL_MFDF);
    PH_ASSERT_NULL_PARAM(pPalMifareDataParams, PH_COMP_AL_MFDF);

    /* Data Params size Check. */
    if (sizeof(phalMfdf_SamAV3_NonX_DataParams_t) != wSizeOfDataParams) {
      return PH_ADD_COMPCODE(PH_ERR_INVALID_DATA_PARAMS, PH_COMP_AL_MFDF);
    }

    /* Initialize dataparams structure members. */
    pDataParams->wId                    = PH_COMP_AL_MFDF | PHAL_MFDF_SAMAV3_NONX_ID;
    pDataParams->pHalSamDataParams      = pHalSamDataParams;
    pDataParams->pPalMifareDataParams   = pPalMifareDataParams;
    pDataParams->bKeyNo                 = 0xFF;
    pDataParams->bAuthMode              = PHAL_MFDF_NOT_AUTHENTICATED;
    pDataParams->bWrappedMode           = PH_OFF;
    pDataParams->wAdditionalInfo        = 0x0000;

    return PH_ADD_COMPCODE(PH_ERR_SUCCESS, PH_COMP_AL_MFDF);
  }
#endif /* NXPBUILD__PHAL_MFP_SAMAV3_NONX */

  /* MIFARE DESFire security related commands. ----------------------------------------------------------------------------------------- */
  phStatus_t phalMfdf_Sam_NonX_Authenticate(void *pDataParams, uint16_t wOption, uint16_t wKeyNo,
      uint16_t wKeyVer, uint8_t bKeyNoCard, uint8_t *pDivInput,
      uint8_t bDivInputLen) {
    phStatus_t	PH_MEMLOC_REM wStatus = 0;

    /* Exchange the commands between Card and SAM hardware to complete Authentication. */
    PH_CHECK_SUCCESS_FCT(wStatus, phalMfdf_Sam_NonX_Int_AuthenticatePICC(
            pDataParams,
            PHAL_MFDF_CMD_AUTHENTICATE,
            wOption,
            wKeyNo,
            wKeyVer,
            bKeyNoCard,
            pDivInput,
            bDivInputLen));

    PH_CHECK_SUCCESS_FCT(wStatus, phalMfdf_Sam_NonX_Int_SetAuthMode(pDataParams,
            PHAL_MFDF_AUTHENTICATE));
    PH_CHECK_SUCCESS_FCT(wStatus, phalMfdf_Sam_NonX_Int_SetKeyNo(pDataParams, bKeyNoCard));

    return PH_ADD_COMPCODE(PH_ERR_SUCCESS, PH_COMP_AL_MFDF);
  }

  phStatus_t phalMfdf_Sam_NonX_AuthenticateISO(void *pDataParams, uint16_t wOption, uint16_t wKeyNo,
      uint16_t wKeyVer, uint8_t bKeyNoCard, uint8_t *pDivInput,
      uint8_t bDivInputLen) {
    phStatus_t	PH_MEMLOC_REM wStatus = 0;

    /* Exchange the commands between Card and SAM hardware to complete Authentication. */
    PH_CHECK_SUCCESS_FCT(wStatus, phalMfdf_Sam_NonX_Int_AuthenticatePICC(
            pDataParams,
            PHAL_MFDF_CMD_AUTHENTICATE_ISO,
            wOption,
            wKeyNo,
            wKeyVer,
            bKeyNoCard,
            pDivInput,
            bDivInputLen));

    PH_CHECK_SUCCESS_FCT(wStatus, phalMfdf_Sam_NonX_Int_SetAuthMode(pDataParams,
            PHAL_MFDF_AUTHENTICATEISO));
    PH_CHECK_SUCCESS_FCT(wStatus, phalMfdf_Sam_NonX_Int_SetKeyNo(pDataParams, bKeyNoCard));

    return PH_ADD_COMPCODE(PH_ERR_SUCCESS, PH_COMP_AL_MFDF);
  }

  phStatus_t phalMfdf_Sam_NonX_AuthenticateAES(void *pDataParams, uint16_t wOption, uint16_t wKeyNo,
      uint16_t wKeyVer, uint8_t bKeyNoCard, uint8_t *pDivInput,
      uint8_t bDivInputLen) {
    phStatus_t	PH_MEMLOC_REM wStatus = 0;

    /* Exchange the commands between Card and SAM hardware to complete Authentication. */
    PH_CHECK_SUCCESS_FCT(wStatus, phalMfdf_Sam_NonX_Int_AuthenticatePICC(
            pDataParams,
            PHAL_MFDF_CMD_AUTHENTICATE_AES,
            wOption,
            wKeyNo,
            wKeyVer,
            bKeyNoCard,
            pDivInput,
            bDivInputLen));

    PH_CHECK_SUCCESS_FCT(wStatus, phalMfdf_Sam_NonX_Int_SetAuthMode(pDataParams,
            PHAL_MFDF_AUTHENTICATEAES));
    PH_CHECK_SUCCESS_FCT(wStatus, phalMfdf_Sam_NonX_Int_SetKeyNo(pDataParams, bKeyNoCard));

    return PH_ADD_COMPCODE(PH_ERR_SUCCESS, PH_COMP_AL_MFDF);
  }

  phStatus_t phalMfdf_Sam_NonX_ChangeKeySettings(void *pDataParams, uint8_t bKeySettings) {
    phStatus_t	PH_MEMLOC_REM wStatus = 0;
    uint8_t     PH_MEMLOC_REM aCmdBuff[2];

    /* Frame the command information. */
    aCmdBuff[0] = PHAL_MFDF_CMD_CHANGE_KEY_SETTINGS;
    aCmdBuff[1] = bKeySettings;

    /* Exchange Cmd.ChangeKeySettings information to Sam and PICC. */
    PH_CHECK_SUCCESS_FCT(wStatus, phalMfdf_Sam_NonX_Int_WriteData(
            pDataParams,
            PH_EXCHANGE_DEFAULT,
            PH_OFF,
            PHAL_MFDF_COMMUNICATION_ENC,
            PHAL_MFDF_COMMUNICATION_MACD,
            PH_OFF,
            &aCmdBuff[0],
            1,
            &aCmdBuff[1],
            1,
            NULL,
            NULL));

    return PH_ADD_COMPCODE(PH_ERR_SUCCESS, PH_COMP_AL_MFDF);
  }

  phStatus_t phalMfdf_Sam_NonX_GetKeySettings(void *pDataParams, uint8_t *pKeySettings) {
    phStatus_t	PH_MEMLOC_REM wStatus = 0;
    uint8_t		PH_MEMLOC_REM aCmdBuff[1];
    uint8_t		PH_MEMLOC_REM bComMode = 0;
    uint16_t	PH_MEMLOC_REM wRespLen = 0;
    uint8_t		PH_MEMLOC_REM bAuthMode = 0;

    /* Get the dataparams information. */
    PH_CHECK_SUCCESS_FCT(wStatus, phalMfdf_Sam_NonX_Int_GetAuthMode(pDataParams, &bAuthMode));

    /* Frame the command information. */
    aCmdBuff[0] = PHAL_MFDF_CMD_GET_KEY_SETTINGS;

    /* Frame the communication mode to be applied. */
    bComMode = (uint8_t)((bAuthMode == PHAL_MFDF_AUTHENTICATE) ? PHAL_MFDF_COMMUNICATION_MACD :
            PHAL_MFDF_COMMUNICATION_PLAIN);

    /* Exchange Cmd.GetKeySettings information to Sam and PICC. */
    PH_CHECK_SUCCESS_FCT(wStatus, phalMfdf_Sam_NonX_Int_ReadData(
            pDataParams,
            PH_EXCHANGE_DEFAULT,
            PH_OFF,
            bComMode,
            bComMode,
            0,
            aCmdBuff,
            1,
            &pKeySettings,
            &wRespLen));

    return PH_ADD_COMPCODE(PH_ERR_SUCCESS, PH_COMP_AL_MFDF);
  }

  phStatus_t phalMfdf_Sam_NonX_ChangeKey(void *pDataParams, uint16_t wOption, uint16_t wCurrKeyNo,
      uint16_t wCurrKeyVer, uint16_t wNewKeyNo, uint16_t wNewKeyVer,
      uint8_t bKeyNoCard, uint8_t *pDivInput, uint8_t bDivInputLen) {
    phStatus_t	PH_MEMLOC_REM wStatus = 0;

    /* Exchange the commands between Card and SAM hardware to Change Key. */
    PH_CHECK_SUCCESS_FCT(wStatus, phalMfdf_Sam_NonX_Int_ChangeKeyPICC(
            pDataParams,
            wOption,
            bKeyNoCard,
            wCurrKeyNo,
            wCurrKeyVer,
            wNewKeyNo,
            wNewKeyVer,
            pDivInput,
            bDivInputLen));

    return PH_ADD_COMPCODE(PH_ERR_SUCCESS, PH_COMP_AL_MFDF);
  }

  phStatus_t phalMfdf_Sam_NonX_GetKeyVersion(void *pDataParams, uint8_t bKeyNo,
      uint8_t *pKeyVersion) {
    phStatus_t	PH_MEMLOC_REM wStatus = 0;
    uint8_t		PH_MEMLOC_REM aCmdBuff[3];
    uint16_t    PH_MEMLOC_REM wCmdLen = 0;
    uint8_t		PH_MEMLOC_REM bComMode = 0;
    uint16_t	PH_MEMLOC_REM wRespLen = 0;
    uint8_t		PH_MEMLOC_REM bAuthMode = 0;

    /* Validate parameters. */
    if ((bKeyNo & 0x0F) > 0x0D) {
      return PH_ADD_COMPCODE(PH_ERR_INVALID_PARAMETER, PH_COMP_AL_MFDF);
    }

    /* Get the dataparams information. */
    PH_CHECK_SUCCESS_FCT(wStatus, phalMfdf_Sam_NonX_Int_GetAuthMode(pDataParams, &bAuthMode));

    /* Frame the command information. */
    aCmdBuff[wCmdLen++] = PHAL_MFDF_CMD_GET_KEY_VERSION;
    aCmdBuff[wCmdLen++] = bKeyNo;

    /* Frame the communication mode to be applied. */
    bComMode = (uint8_t)((bAuthMode == PHAL_MFDF_AUTHENTICATE) ? PHAL_MFDF_COMMUNICATION_MACD :
            PHAL_MFDF_COMMUNICATION_PLAIN);

    /* Exchange Cmd.GetKeyVersion information to Sam and PICC. */
    PH_CHECK_SUCCESS_FCT(wStatus, phalMfdf_Sam_NonX_Int_ReadData(
            pDataParams,
            PH_EXCHANGE_DEFAULT,
            PH_OFF,
            bComMode,
            bComMode,
            0,
            aCmdBuff,
            wCmdLen,
            &pKeyVersion,
            &wRespLen));

    return PH_ADD_COMPCODE(PH_ERR_SUCCESS, PH_COMP_AL_MFDF);
  }

  /* MIFARE DESFire PICC level commands. ----------------------------------------------------------------------------------------------- */
  phStatus_t phalMfdf_Sam_NonX_CreateApplication(void *pDataParams, uint8_t bOption, uint8_t *pAid,
      uint8_t bKeySettings1, uint8_t bKeySettings2,
      uint8_t *pISOFileId, uint8_t *pISODFName, uint8_t bISODFNameLen) {
    phStatus_t	PH_MEMLOC_REM wStatus = 0;
    uint8_t     PH_MEMLOC_REM aCmdBuff[30];
    uint16_t    PH_MEMLOC_REM wCmdLen = 0;
    uint8_t     PH_MEMLOC_REM bComMode = 0;
    uint8_t		PH_MEMLOC_REM bAuthMode = 0;

    /* Check for valid ISO DFName */
    if ((bISODFNameLen > 16) || (bOption == 0x02) || (bOption > 0x03)) {
      return PH_ADD_COMPCODE(PH_ERR_INVALID_PARAMETER, PH_COMP_AL_MFDF);
    }

    /* Get the dataparams information. */
    PH_CHECK_SUCCESS_FCT(wStatus, phalMfdf_Sam_NonX_Int_GetAuthMode(pDataParams, &bAuthMode));

    /* Frame the command information. */
    aCmdBuff[wCmdLen++] = PHAL_MFDF_CMD_CREATE_APPLN;

    /* Buffer Application identifier to the command frame. */
    memcpy(&aCmdBuff[wCmdLen], pAid, 3); /* PRQA S 3200 */
    wCmdLen += 3;

    /* Buffer Key settings information to command frame. */
    aCmdBuff[wCmdLen++] = bKeySettings1;
    aCmdBuff[wCmdLen++] = bKeySettings2;

    /* Buffer ISO FileID to exchange buffer. */
    if ((bOption & 0x01) == 0x01) {
      aCmdBuff[wCmdLen++] = pISOFileId[0];
      aCmdBuff[wCmdLen++] = pISOFileId[1];
    }

    /* Buffer ISO DFName to exchange buffer. */
    if ((bOption & 0x02) == 0x02) {
      memcpy(&aCmdBuff[wCmdLen], pISODFName, bISODFNameLen); /* PRQA S 3200 */
      wCmdLen += bISODFNameLen;
    }

    /* Frame the communication mode to be applied. */
    bComMode = (uint8_t)((bAuthMode == PHAL_MFDF_AUTHENTICATE) ? PHAL_MFDF_COMMUNICATION_MACD :
            PHAL_MFDF_COMMUNICATION_PLAIN);

    /* Exchange Cmd.CreateApplication information to Sam and PICC. */
    PH_CHECK_SUCCESS_FCT(wStatus, phalMfdf_Sam_NonX_Int_WriteData(
            pDataParams,
            PH_EXCHANGE_DEFAULT,
            PH_OFF,
            bComMode,
            PHAL_MFDF_COMMUNICATION_MACD,
            PH_OFF,
            aCmdBuff,
            wCmdLen,
            NULL,
            0,
            NULL,
            NULL));

    return PH_ADD_COMPCODE(PH_ERR_SUCCESS, PH_COMP_AL_MFDF);
  }

  phStatus_t phalMfdf_Sam_NonX_DeleteApplication(void *pDataParams, uint8_t *pAid) {
    phStatus_t	PH_MEMLOC_REM wStatus = 0;
    uint8_t     PH_MEMLOC_REM aCmdBuff[4];
    uint16_t    PH_MEMLOC_REM wCmdLen = 0;
    uint8_t		PH_MEMLOC_REM bComMode = 0;
    uint8_t		PH_MEMLOC_REM bResetAuth = 0;
    uint8_t     PH_MEMLOC_REM bAuthMode = 0;
    uint8_t		PH_MEMLOC_REM aAppId[3] = {0x00, 0x00, 0x00};

    /* Get the data params info. */
    PH_CHECK_SUCCESS_FCT(wStatus, phalMfdf_Sam_NonX_Int_GetAuthMode(pDataParams, &bAuthMode));
    PH_CHECK_SUCCESS_FCT(wStatus, phalMfdf_Sam_NonX_Int_GetAid(pDataParams, aAppId));

    /* Frame the command information. */
    aCmdBuff[wCmdLen++] = PHAL_MFDF_CMD_DELETE_APPLN;

    /* Buffer Application identifier to the command frame. */
    memcpy(&aCmdBuff[wCmdLen], pAid, 3); /* PRQA S 3200 */
    wCmdLen += 3;

    /* Frame the Crypto information. */
    bComMode = (uint8_t)((bAuthMode == PHAL_MFDF_AUTHENTICATE) ? PHAL_MFDF_COMMUNICATION_MACD :
            PHAL_MFDF_COMMUNICATION_PLAIN);

    /*
     * At APP level, the MAC is not returned. The authenticate state should be reset.
     * At PICC level, 8 bytes MAC is returned. The authenticate state should not be reset.
     * So to check whether its in APP level or PICC level. To do this, check for pDataParams->pAid. If its 0x00, then its PICC level
     * else its in APP level.
     */
    bResetAuth = PH_ON;
    if ((aAppId[0] == 0) && (aAppId[1] == 0) && (aAppId[2] == 0)) {
      bResetAuth = PH_OFF;
    }

    /* Exchange Cmd.DeleteApplication information to Sam and PICC. */
    PH_CHECK_SUCCESS_FCT(wStatus, phalMfdf_Sam_NonX_Int_WriteData(
            pDataParams,
            PH_EXCHANGE_DEFAULT,
            PH_OFF,
            bComMode,
            PHAL_MFDF_COMMUNICATION_MACD,
            bResetAuth,
            aCmdBuff,
            wCmdLen,
            NULL,
            0,
            NULL,
            NULL));

    /* Copy the AID to the params. */
    PH_CHECK_SUCCESS_FCT(wStatus, phalMfdf_Sam_NonX_Int_SetAid(pDataParams, aAppId));

    return PH_ADD_COMPCODE(PH_ERR_SUCCESS, PH_COMP_AL_MFDF);
  }

  phStatus_t phalMfdf_Sam_NonX_GetApplicationIDs(void *pDataParams, uint8_t *pAidBuff,
      uint8_t *pNumAIDs) {
    phStatus_t	PH_MEMLOC_REM wStatus = 0;
    uint8_t		PH_MEMLOC_REM aCmdBuff[1];
    uint8_t		PH_MEMLOC_REM bComMode = 0;
    uint16_t	PH_MEMLOC_REM wRespLen = 0;
    uint8_t		PH_MEMLOC_REM bAuthMode = 0;

    /* Get the dataparams information. */
    PH_CHECK_SUCCESS_FCT(wStatus, phalMfdf_Sam_NonX_Int_GetAuthMode(pDataParams, &bAuthMode));

    /* Frame the command information. */
    aCmdBuff[0] = PHAL_MFDF_CMD_GET_APPLN_IDS;

    /* Frame the communication mode to be applied. */
    bComMode = (uint8_t)((bAuthMode == PHAL_MFDF_AUTHENTICATE) ? PHAL_MFDF_COMMUNICATION_MACD :
            PHAL_MFDF_COMMUNICATION_PLAIN);

    /* Exchange Cmd.GetApplicationIds information to Sam and PICC. */
    PH_CHECK_SUCCESS_FCT(wStatus, phalMfdf_Sam_NonX_Int_ReadData(
            pDataParams,
            PH_EXCHANGE_DEFAULT,
            PH_OFF,
            bComMode,
            PHAL_MFDF_COMMUNICATION_MACD,
            0,
            aCmdBuff,
            1,
            &pAidBuff,
            &wRespLen));

    /* Copy the data to the parameter */
    *pNumAIDs = (uint8_t)(wRespLen / 3);

    return wStatus;
  }

  phStatus_t phalMfdf_Sam_NonX_GetDFNames(void *pDataParams, uint8_t bOption, uint8_t *pDFBuffer,
      uint8_t *bSize) {
    phStatus_t	PH_MEMLOC_REM wStatus = 0;
    uint8_t		PH_MEMLOC_REM aCmdBuff[1];
    uint8_t		PH_MEMLOC_REM bComMode = 0;
    uint16_t	PH_MEMLOC_REM wRespLen = 0;
    uint8_t		PH_MEMLOC_REM bAuthMode = 0;

    /* Validate the parameter. */
    if (((bOption & 0x0FU) != PH_EXCHANGE_DEFAULT) && ((bOption & 0x0FU) != PH_EXCHANGE_RXCHAINING)) {
      return PH_ADD_COMPCODE(PH_ERR_INVALID_PARAMETER, PH_COMP_AL_MFDF);
    }

    /* Get the dataparams information. */
    PH_CHECK_SUCCESS_FCT(wStatus, phalMfdf_Sam_NonX_Int_GetAuthMode(pDataParams, &bAuthMode));

    if ((bAuthMode == PHAL_MFDF_AUTHENTICATEISO) ||
        (bAuthMode == PHAL_MFDF_AUTHENTICATEAES)) {
      /*
       * Should return, invalid scenario error. Card will be disabled
           * in case this command is sent in these modes.
       */
      return PH_ADD_COMPCODE(PH_ERR_USE_CONDITION, PH_COMP_AL_MFDF);
    }

    /* Frame the command information. */
    aCmdBuff[0] = (uint8_t)(((bOption & 0x0FU) == PH_EXCHANGE_DEFAULT) ? PHAL_MFDF_CMD_GET_DF_NAMES :
            PHAL_MFDF_RESP_ADDITIONAL_FRAME);

    /* Frame the communication mode to be applied. */
    bComMode = (uint8_t)((bAuthMode == PHAL_MFDF_AUTHENTICATE) ? PHAL_MFDF_COMMUNICATION_MACD :
            PHAL_MFDF_COMMUNICATION_PLAIN);

    /* Exchange Cmd.GetDFNames information to Sam and PICC. */
    wStatus = phalMfdf_Sam_NonX_Int_ReadData(
            pDataParams,
            (uint8_t)(bOption | PHALMFDF_SAM_NONX_RETURN_CHAINING_STATUS),
            PH_OFF,
            bComMode,
            PHAL_MFDF_COMMUNICATION_MACD,
            0,
            aCmdBuff,
            1,
            &pDFBuffer,
            &wRespLen);

    /* Copy the data to the parameter */
    if ((wStatus == PH_ERR_SUCCESS) || ((wStatus & PH_ERR_MASK) == PH_ERR_SUCCESS_CHAINING)) {
      *bSize = (uint8_t) wRespLen;
    }

    return wStatus;
  }

  phStatus_t phalMfdf_Sam_NonX_SelectApplication(void *pDataParams, uint8_t *pAppId) {
    phStatus_t	PH_MEMLOC_REM wStatus = 0;
    uint8_t     PH_MEMLOC_REM aCmdBuff[4];
    uint16_t    PH_MEMLOC_REM wCmdLen = 0;

    /* Reset the Auth states. */
    PH_CHECK_SUCCESS_FCT(wStatus, phalMfdf_Sam_NonX_Int_ResetAuthStatus(pDataParams));

    /* Frame the command information. */
    aCmdBuff[wCmdLen++] = PHAL_MFDF_CMD_SELECT_APPLN;

    /* Buffer Application identifier to the command frame. */
    memcpy(&aCmdBuff[wCmdLen], pAppId, 3); /* PRQA S 3200 */
    wCmdLen += 3;

    /* Exchange Cmd.SelectApplication information to Sam and PICC. */
    PH_CHECK_SUCCESS_FCT(wStatus, phalMfdf_Sam_NonX_Int_WriteData(
            pDataParams,
            PH_EXCHANGE_DEFAULT,
            PH_OFF,
            PHAL_MFDF_COMMUNICATION_PLAIN,
            PHAL_MFDF_COMMUNICATION_PLAIN,
            PH_OFF,
            aCmdBuff,
            wCmdLen,
            NULL,
            0,
            NULL,
            NULL));

    /* Copy the AID to the params. */
    PH_CHECK_SUCCESS_FCT(wStatus, phalMfdf_Sam_NonX_Int_SetAid(pDataParams, pAppId));

    return PH_ADD_COMPCODE(PH_ERR_SUCCESS, PH_COMP_AL_MFDF);
  }

  phStatus_t phalMfdf_Sam_NonX_FormatPICC(void *pDataParams) {
    phStatus_t	PH_MEMLOC_REM wStatus = 0;
    uint8_t		PH_MEMLOC_REM aCmdBuff[1];
    uint8_t		PH_MEMLOC_REM bComMode = 0;
    uint8_t		PH_MEMLOC_REM bAuthMode = 0;

    /* Get the dataparams information. */
    PH_CHECK_SUCCESS_FCT(wStatus, phalMfdf_Sam_NonX_Int_GetAuthMode(pDataParams, &bAuthMode));

    /* Frame the command information. */
    aCmdBuff[0] = PHAL_MFDF_CMD_FORMAT_PICC;

    /* Frame the communication mode to be applied. */
    bComMode = (uint8_t)((bAuthMode == PHAL_MFDF_AUTHENTICATE) ? PHAL_MFDF_COMMUNICATION_MACD :
            PHAL_MFDF_COMMUNICATION_PLAIN);

    /* Exchange Cmd.Format information to Sam and PICC. */
    PH_CHECK_SUCCESS_FCT(wStatus, phalMfdf_Sam_NonX_Int_ReadData(
            pDataParams,
            PH_EXCHANGE_DEFAULT,
            PH_OFF,
            bComMode,
            bComMode,
            0,
            aCmdBuff,
            1,
            NULL,
            NULL));

    return PH_ADD_COMPCODE(PH_ERR_SUCCESS, PH_COMP_AL_MFDF);
  }

  phStatus_t phalMfdf_Sam_NonX_GetVersion(void *pDataParams, uint8_t *pVerInfo) {
    phStatus_t	PH_MEMLOC_REM wStatus = 0;
    uint8_t		PH_MEMLOC_REM aCmdBuff[1];
    uint8_t		PH_MEMLOC_REM bComMode = 0;
    uint16_t	PH_MEMLOC_REM wRespLen = 0;
    uint8_t		PH_MEMLOC_REM bAuthMode = 0;

    /* Get the dataparams information. */
    PH_CHECK_SUCCESS_FCT(wStatus, phalMfdf_Sam_NonX_Int_GetAuthMode(pDataParams, &bAuthMode));

    /* Frame the command information. */
    aCmdBuff[0] = PHAL_MFDF_CMD_GET_VERSION;

    /* Frame the communication mode to be applied. */
    bComMode = (uint8_t)((bAuthMode == PHAL_MFDF_AUTHENTICATE) ? PHAL_MFDF_COMMUNICATION_MACD :
            PHAL_MFDF_COMMUNICATION_PLAIN);

    /* Exchange Cmd.GetVersion information to Sam and PICC. */
    PH_CHECK_SUCCESS_FCT(wStatus, phalMfdf_Sam_NonX_Int_ReadData(
            pDataParams,
            PH_EXCHANGE_DEFAULT,
            PH_OFF,
            bComMode,
            bComMode,
            0,
            aCmdBuff,
            1,
            &pVerInfo,
            &wRespLen));

    PH_CHECK_SUCCESS_FCT(wStatus, phalMfdf_SetConfig(pDataParams, PHAL_MFDF_ADDITIONAL_INFO,
            wRespLen));

    return PH_ADD_COMPCODE(PH_ERR_SUCCESS, PH_COMP_AL_MFDF);
  }

  phStatus_t phalMfdf_Sam_NonX_FreeMem(void *pDataParams, uint8_t *pMemInfo) {
    phStatus_t	PH_MEMLOC_REM wStatus = 0;
    uint8_t		PH_MEMLOC_REM aCmdBuff[1];
    uint8_t		PH_MEMLOC_REM bComMode = 0;
    uint16_t	PH_MEMLOC_REM wRespLen = 0;
    uint8_t		PH_MEMLOC_REM bAuthMode = 0;

    /* Get the dataparams information. */
    PH_CHECK_SUCCESS_FCT(wStatus, phalMfdf_Sam_NonX_Int_GetAuthMode(pDataParams, &bAuthMode));

    /* Frame the command information. */
    aCmdBuff[0] = PHAL_MFDF_CMD_FREE_MEM;

    /* Frame the communication mode to be applied. */
    bComMode = (uint8_t)((bAuthMode == PHAL_MFDF_AUTHENTICATE) ? PHAL_MFDF_COMMUNICATION_MACD :
            PHAL_MFDF_COMMUNICATION_PLAIN);

    /* Exchange Cmd.FreeMem information to Sam and PICC. */
    PH_CHECK_SUCCESS_FCT(wStatus, phalMfdf_Sam_NonX_Int_ReadData(
            pDataParams,
            PH_EXCHANGE_DEFAULT,
            PH_OFF,
            bComMode,
            bComMode,
            0,
            aCmdBuff,
            1,
            &pMemInfo,
            &wRespLen));

    return PH_ADD_COMPCODE(PH_ERR_SUCCESS, PH_COMP_AL_MFDF);
  }

  phStatus_t phalMfdf_Sam_NonX_SetConfiguration(void *pDataParams, uint8_t bOption, uint8_t *pData,
      uint8_t bDataLen) {
    phStatus_t	PH_MEMLOC_REM wStatus = 0;
    uint8_t     PH_MEMLOC_REM aCmdBuff[2];

    /* Frame the command information. */
    aCmdBuff[0] = PHAL_MFDF_CMD_SET_CONFIG;
    aCmdBuff[1] = bOption;

    /* Exchange Cmd.SetConfiguration information to Sam and PICC. */
    PH_CHECK_SUCCESS_FCT(wStatus, phalMfdf_Sam_NonX_Int_WriteData(
            pDataParams,
            PH_EXCHANGE_DEFAULT,
            PH_OFF,
            PHAL_MFDF_COMMUNICATION_ENC,
            PHAL_MFDF_COMMUNICATION_MACD,
            PH_OFF,
            aCmdBuff,
            2,
            pData,
            bDataLen,
            NULL,
            NULL));

    return PH_ADD_COMPCODE(PH_ERR_SUCCESS, PH_COMP_AL_MFDF);
  }

  phStatus_t phalMfdf_Sam_NonX_GetCardUID(void *pDataParams, uint8_t *pUid) {
    phStatus_t	PH_MEMLOC_REM wStatus = 0;
    uint8_t		PH_MEMLOC_REM aCmdBuff[1];
    uint16_t	PH_MEMLOC_REM wRespLen = 0;
    uint8_t		PH_MEMLOC_REM bAuthMode = 0;

    /* Get the dataparams information. */
    PH_CHECK_SUCCESS_FCT(wStatus, phalMfdf_Sam_NonX_Int_GetAuthMode(pDataParams, &bAuthMode));
    if (bAuthMode == PHAL_MFDF_NOT_AUTHENTICATED) {
      return PH_ADD_COMPCODE(PH_ERR_USE_CONDITION, PH_COMP_AL_MFDF);
    }

    /* Frame the command information. */
    aCmdBuff[0] = PHAL_MFDF_CMD_GET_CARD_UID;

    /* Exchange Cmd.GetCardUID information to Sam and PICC. */
    PH_CHECK_SUCCESS_FCT(wStatus, phalMfdf_Sam_NonX_Int_ReadData(
            pDataParams,
            PH_EXCHANGE_DEFAULT,
            PH_OFF,
            PHAL_MFDF_COMMUNICATION_PLAIN,
            PHAL_MFDF_COMMUNICATION_ENC,
            7,
            aCmdBuff,
            1,
            &pUid,
            &wRespLen));

    return PH_ADD_COMPCODE(PH_ERR_SUCCESS, PH_COMP_AL_MFDF);
  }

  /* MIFARE DESFire Application level commands. ---------------------------------------------------------------------------------------- */
  phStatus_t phalMfdf_Sam_NonX_GetFileIDs(void *pDataParams, uint8_t *pFid, uint8_t *pNumFid) {
    phStatus_t	PH_MEMLOC_REM wStatus = 0;
    uint8_t		PH_MEMLOC_REM aCmdBuff[1];
    uint8_t		PH_MEMLOC_REM bComMode = 0;
    uint16_t	PH_MEMLOC_REM wRespLen = 0;
    uint8_t		PH_MEMLOC_REM bAuthMode = 0;

    /* Get the dataparams information. */
    PH_CHECK_SUCCESS_FCT(wStatus, phalMfdf_Sam_NonX_Int_GetAuthMode(pDataParams, &bAuthMode));

    /* Frame the command information. */
    aCmdBuff[0] = PHAL_MFDF_CMD_GET_FILE_IDS;

    /* Frame the communication mode to be applied. */
    bComMode = (uint8_t)((bAuthMode == PHAL_MFDF_AUTHENTICATE) ? PHAL_MFDF_COMMUNICATION_MACD :
            PHAL_MFDF_COMMUNICATION_PLAIN);

    /* Exchange Cmd.GetFileIDs information to Sam and PICC. */
    PH_CHECK_SUCCESS_FCT(wStatus, phalMfdf_Sam_NonX_Int_ReadData(
            pDataParams,
            PH_EXCHANGE_DEFAULT,
            PH_OFF,
            bComMode,
            PHAL_MFDF_COMMUNICATION_MACD,
            0,
            aCmdBuff,
            1,
            &pFid,
            &wRespLen));

    *pNumFid = (uint8_t) wRespLen;

    return PH_ADD_COMPCODE(PH_ERR_SUCCESS, PH_COMP_AL_MFDF);
  }

  phStatus_t phalMfdf_Sam_NonX_GetISOFileIDs(void *pDataParams, uint8_t *pFidBuffer,
      uint8_t *pNumFid) {
    phStatus_t	PH_MEMLOC_REM wStatus = 0;
    uint8_t		PH_MEMLOC_REM aCmdBuff[1];
    uint8_t		PH_MEMLOC_REM bComMode = 0;
    uint16_t	PH_MEMLOC_REM wRespLen = 0;
    uint8_t		PH_MEMLOC_REM bAuthMode = 0;

    /* Get the dataparams information. */
    PH_CHECK_SUCCESS_FCT(wStatus, phalMfdf_Sam_NonX_Int_GetAuthMode(pDataParams, &bAuthMode));

    /* Frame the command information. */
    aCmdBuff[0] = PHAL_MFDF_CMD_GET_ISO_FILE_IDS;

    /* Frame the communication mode to be applied. */
    bComMode = (uint8_t)((bAuthMode == PHAL_MFDF_AUTHENTICATE) ? PHAL_MFDF_COMMUNICATION_MACD :
            PHAL_MFDF_COMMUNICATION_PLAIN);

    /* Exchange Cmd.GetISOFileIDs information to Sam and PICC. */
    PH_CHECK_SUCCESS_FCT(wStatus, phalMfdf_Sam_NonX_Int_ReadData(
            pDataParams,
            PH_EXCHANGE_DEFAULT,
            PH_OFF,
            bComMode,
            PHAL_MFDF_COMMUNICATION_MACD,
            0,
            aCmdBuff,
            1,
            &pFidBuffer,
            &wRespLen));

    /* Update the length. */
    *pNumFid = (uint8_t)(wRespLen / 2);

    return PH_ADD_COMPCODE(PH_ERR_SUCCESS, PH_COMP_AL_MFDF);
  }

  phStatus_t phalMfdf_Sam_NonX_GetFileSettings(void *pDataParams, uint8_t bFileNo,
      uint8_t *pFSBuffer, uint8_t *bBufferLen) {
    phStatus_t	PH_MEMLOC_REM wStatus = 0;
    uint8_t		PH_MEMLOC_REM aCmdBuff[2];
    uint8_t		PH_MEMLOC_REM bComMode = 0;
    uint16_t	PH_MEMLOC_REM wRespLen = 0;
    uint8_t		PH_MEMLOC_REM bAuthMode = 0;

    /* Validate the parameters. */
    if (bFileNo > 0x1f) {
      return PH_ADD_COMPCODE(PH_ERR_INVALID_PARAMETER, PH_COMP_AL_MFDF);
    }

    /* Get the dataparams information. */
    PH_CHECK_SUCCESS_FCT(wStatus, phalMfdf_Sam_NonX_Int_GetAuthMode(pDataParams, &bAuthMode));

    /* Frame the command information. */
    aCmdBuff[0] = PHAL_MFDF_CMD_GET_FILE_SETTINGS;
    aCmdBuff[1] = bFileNo;

    /* Frame the communication mode to be applied. */
    bComMode = (uint8_t)((bAuthMode == PHAL_MFDF_AUTHENTICATE) ? PHAL_MFDF_COMMUNICATION_MACD :
            PHAL_MFDF_COMMUNICATION_PLAIN);

    /* Exchange Cmd.GetFileSettings information to Sam and PICC. */
    PH_CHECK_SUCCESS_FCT(wStatus, phalMfdf_Sam_NonX_Int_ReadData(
            pDataParams,
            PH_EXCHANGE_DEFAULT,
            PH_OFF,
            bComMode,
            PHAL_MFDF_COMMUNICATION_MACD,
            0,
            aCmdBuff,
            2,
            &pFSBuffer,
            &wRespLen));

    /* Update the length. */
    *bBufferLen = (uint8_t) wRespLen;

    return PH_ADD_COMPCODE(PH_ERR_SUCCESS, PH_COMP_AL_MFDF);
  }

  phStatus_t phalMfdf_Sam_NonX_ChangeFileSettings(void *pDataParams, uint8_t bOption,
      uint8_t bFileNo, uint8_t bFileOption, uint8_t *pAccessRights) {
    phStatus_t	PH_MEMLOC_REM wStatus = 0;
    uint8_t     PH_MEMLOC_REM aCmdBuff[26];
    uint16_t    PH_MEMLOC_REM wCmdLen = 0;
    uint8_t		PH_MEMLOC_REM bComMode = 0;

    /* Validate the parameters */
    if ((bFileNo & 0x3f) > 0x1f) {
      return PH_ADD_COMPCODE(PH_ERR_INVALID_PARAMETER, PH_COMP_AL_MFDF);
    }

    if (((bFileOption & 0x3f) != PHAL_MFDF_COMMUNICATION_PLAIN) &&
        ((bFileOption & 0x3f) != PHAL_MFDF_COMMUNICATION_ENC) &&
        ((bFileOption & 0x3f) != PHAL_MFDF_COMMUNICATION_MACD)) {
      return PH_ADD_COMPCODE(PH_ERR_INVALID_PARAMETER, PH_COMP_AL_MFDF);
    }

    if (((bOption & 0xF0U) != PHAL_MFDF_COMMUNICATION_PLAIN) &&
        ((bOption & 0xF0U) != PHAL_MFDF_COMMUNICATION_ENC) &&
        ((bOption & 0xF0U) != PHAL_MFDF_COMMUNICATION_MACD)) {
      return PH_ADD_COMPCODE(PH_ERR_INVALID_PARAMETER, PH_COMP_AL_MFDF);
    }

    /* Frame the command information. */
    aCmdBuff[wCmdLen++] = PHAL_MFDF_CMD_CHANGE_FILE_SETTINGS;
    aCmdBuff[wCmdLen++] = bFileNo;
    aCmdBuff[wCmdLen++]   = (uint8_t)((bFileOption & 0x30) >> 4);

    /* Append access rights. */
    memcpy(&aCmdBuff[wCmdLen], pAccessRights, 2); /* PRQA S 3200 */
    wCmdLen += 2;

    /* Frame the Crypto information. */
    bComMode = (uint8_t)(((bOption & 0xF0U) == PHAL_MFDF_COMMUNICATION_ENC) ?
            PHAL_MFDF_COMMUNICATION_ENC : PHAL_MFDF_COMMUNICATION_PLAIN);

    /* Exchange Cmd.ChangeFileSettings information to Sam and PICC. */
    PH_CHECK_SUCCESS_FCT(wStatus, phalMfdf_Sam_NonX_Int_WriteData(
            pDataParams,
            PH_EXCHANGE_DEFAULT,
            PH_OFF,
            bComMode,
            PHAL_MFDF_COMMUNICATION_MACD,
            PH_OFF,
            aCmdBuff,
            (uint16_t)((bComMode == PHAL_MFDF_COMMUNICATION_PLAIN) ? wCmdLen : 2),
            &aCmdBuff[2],
            (uint16_t)((bComMode == PHAL_MFDF_COMMUNICATION_PLAIN) ? 0 : (wCmdLen - 2)),
            NULL,
            NULL));

    return PH_ADD_COMPCODE(PH_ERR_SUCCESS, PH_COMP_AL_MFDF);
  }

  phStatus_t phalMfdf_Sam_NonX_CreateStdDataFile(void *pDataParams, uint8_t bOption,
      uint8_t bFileNo, uint8_t *pISOFileId, uint8_t bFileOption, uint8_t *pAccessRights,
      uint8_t *pFileSize) {
    phStatus_t	PH_MEMLOC_REM wStatus = 0;
    uint8_t     PH_MEMLOC_REM aCmdBuff[10];
    uint16_t    PH_MEMLOC_REM wCmdLen = 0;
    uint8_t		PH_MEMLOC_REM bComMode = 0;
    uint8_t		PH_MEMLOC_REM bAuthMode = 0;

    /* Validate the parameters. */
    if (((bFileNo & 0x7f) > 0x1f) || (bOption > 0x01)) {
      return PH_ADD_COMPCODE(PH_ERR_INVALID_PARAMETER, PH_COMP_AL_MFDF);
    }

    if (((bFileOption & 0x7f) != PHAL_MFDF_COMMUNICATION_PLAIN) &&
        ((bFileOption & 0x7f) != PHAL_MFDF_COMMUNICATION_ENC) &&
        ((bFileOption & 0x7f) != PHAL_MFDF_COMMUNICATION_MACD)) {
      return PH_ADD_COMPCODE(PH_ERR_INVALID_PARAMETER, PH_COMP_AL_MFDF);
    }

    /* Get the dataparams information. */
    PH_CHECK_SUCCESS_FCT(wStatus, phalMfdf_Sam_NonX_Int_GetAuthMode(pDataParams, &bAuthMode));

    /* Frame the command information. */
    aCmdBuff[wCmdLen++] = PHAL_MFDF_CMD_CREATE_STD_DATAFILE;
    aCmdBuff[wCmdLen++] = bFileNo;

    /* Append ISOFileID is available. */
    if (bOption == 0x01) {
      memcpy(&aCmdBuff[wCmdLen], pISOFileId, 2); /* PRQA S 3200 */
      wCmdLen += 2;
    }

    /* Append communication settings */
    aCmdBuff[wCmdLen++] = (uint8_t)(bFileOption >> 4);

    /* Append access rights. */
    memcpy(&aCmdBuff[wCmdLen], pAccessRights, 2); /* PRQA S 3200 */
    wCmdLen += 2;

    /* Append FileSize. */
    memcpy(&aCmdBuff[wCmdLen], pFileSize, 3); /* PRQA S 3200 */
    wCmdLen += 3;

    /* Frame the Crypto information. */
    bComMode = (uint8_t)((bAuthMode == PHAL_MFDF_AUTHENTICATE) ? PHAL_MFDF_COMMUNICATION_MACD :
            PHAL_MFDF_COMMUNICATION_PLAIN);

    /* Exchange Cmd.CreateStdDataFile information to Sam and PICC. */
    PH_CHECK_SUCCESS_FCT(wStatus, phalMfdf_Sam_NonX_Int_WriteData(
            pDataParams,
            PH_EXCHANGE_DEFAULT,
            PH_OFF,
            bComMode,
            PHAL_MFDF_COMMUNICATION_MACD,
            PH_OFF,
            aCmdBuff,
            wCmdLen,
            NULL,
            0,
            NULL,
            NULL));

    return PH_ADD_COMPCODE(PH_ERR_SUCCESS, PH_COMP_AL_MFDF);
  }

  phStatus_t phalMfdf_Sam_NonX_CreateBackupDataFile(void *pDataParams, uint8_t bOption,
      uint8_t bFileNo, uint8_t *pISOFileId, uint8_t bFileOption, uint8_t *pAccessRights,
      uint8_t *pFileSize) {
    phStatus_t	PH_MEMLOC_REM wStatus = 0;
    uint8_t     PH_MEMLOC_REM aCmdBuff[10];
    uint16_t    PH_MEMLOC_REM wCmdLen = 0;
    uint8_t		PH_MEMLOC_REM bComMode = 0;
    uint8_t		PH_MEMLOC_REM bAuthMode = 0;

    /* Validate the parameters. */
    if (((bFileNo & 0x7f) > 0x1f) || (bOption > 0x01)) {
      return PH_ADD_COMPCODE(PH_ERR_INVALID_PARAMETER, PH_COMP_AL_MFDF);
    }

    if (((bFileOption & 0x7f) != PHAL_MFDF_COMMUNICATION_PLAIN) &&
        ((bFileOption & 0x7f) != PHAL_MFDF_COMMUNICATION_ENC) &&
        ((bFileOption & 0x7f) != PHAL_MFDF_COMMUNICATION_MACD)) {
      return PH_ADD_COMPCODE(PH_ERR_INVALID_PARAMETER, PH_COMP_AL_MFDF);
    }

    /* Get the dataparams information. */
    PH_CHECK_SUCCESS_FCT(wStatus, phalMfdf_Sam_NonX_Int_GetAuthMode(pDataParams, &bAuthMode));

    /* Frame the command information. */
    aCmdBuff[wCmdLen++] = PHAL_MFDF_CMD_CREATE_BKUP_DATAFILE;
    aCmdBuff[wCmdLen++] = bFileNo;

    /* Append ISOFileID is available. */
    if (bOption == 0x01) {
      memcpy(&aCmdBuff[wCmdLen], pISOFileId, 2); /* PRQA S 3200 */
      wCmdLen += 2;
    }

    /* Append communication settings */
    aCmdBuff[wCmdLen++] = (uint8_t)(bFileOption >> 4);

    /* Append access rights. */
    memcpy(&aCmdBuff[wCmdLen], pAccessRights, 2); /* PRQA S 3200 */
    wCmdLen += 2;

    /* Append FileSize. */
    memcpy(&aCmdBuff[wCmdLen], pFileSize, 3); /* PRQA S 3200 */
    wCmdLen += 3;

    /* Frame the Crypto information. */
    bComMode = (uint8_t)((bAuthMode == PHAL_MFDF_AUTHENTICATE) ? PHAL_MFDF_COMMUNICATION_MACD :
            PHAL_MFDF_COMMUNICATION_PLAIN);

    /* Exchange Cmd.CreateBackupDataFile information to Sam and PICC. */
    PH_CHECK_SUCCESS_FCT(wStatus, phalMfdf_Sam_NonX_Int_WriteData(
            pDataParams,
            PH_EXCHANGE_DEFAULT,
            PH_OFF,
            bComMode,
            PHAL_MFDF_COMMUNICATION_MACD,
            PH_OFF,
            aCmdBuff,
            wCmdLen,
            NULL,
            0,
            NULL,
            NULL));

    return PH_ADD_COMPCODE(PH_ERR_SUCCESS, PH_COMP_AL_MFDF);
  }

  phStatus_t phalMfdf_Sam_NonX_CreateValueFile(void *pDataParams, uint8_t bFileNo,
      uint8_t bFileOption, uint8_t *pAccessRights, uint8_t *pLowerLmit, uint8_t *pUpperLmit,
      uint8_t *pValue, uint8_t bLimitedCredit) {
    phStatus_t	PH_MEMLOC_REM wStatus = 0;
    uint8_t     PH_MEMLOC_REM aCmdBuff[18];
    uint16_t    PH_MEMLOC_REM wCmdLen = 0;
    uint8_t		PH_MEMLOC_REM bComMode = 0;
    uint8_t		PH_MEMLOC_REM bAuthMode = 0;

    /* Validate the parameters. */
    if ((bFileNo & 0x7f) > 0x1f) {
      return PH_ADD_COMPCODE(PH_ERR_INVALID_PARAMETER, PH_COMP_AL_MFDF);
    }

    if (((bFileOption & 0x7f) != PHAL_MFDF_COMMUNICATION_PLAIN) &&
        ((bFileOption & 0x7f) != PHAL_MFDF_COMMUNICATION_ENC) &&
        ((bFileOption & 0x7f) != PHAL_MFDF_COMMUNICATION_MACD)) {
      return PH_ADD_COMPCODE(PH_ERR_INVALID_PARAMETER, PH_COMP_AL_MFDF);
    }

    /* Get the dataparams information. */
    PH_CHECK_SUCCESS_FCT(wStatus, phalMfdf_Sam_NonX_Int_GetAuthMode(pDataParams, &bAuthMode));

    /* Frame the command information. */
    aCmdBuff[wCmdLen++] = PHAL_MFDF_CMD_CREATE_VALUE_FILE;
    aCmdBuff[wCmdLen++] = bFileNo;

    /* Append communication settings */
    aCmdBuff[wCmdLen++] = (uint8_t)(bFileOption >> 4);

    /* Append access rights. */
    memcpy(&aCmdBuff[wCmdLen], pAccessRights, 2); /* PRQA S 3200 */
    wCmdLen += 2;

    /* Append lower limit. */
    memcpy(&aCmdBuff[wCmdLen], pLowerLmit, 4); /* PRQA S 3200 */
    wCmdLen += 4;

    /* Append upper limit. */
    memcpy(&aCmdBuff[wCmdLen], pUpperLmit, 4); /* PRQA S 3200 */
    wCmdLen += 4;

    /* Append value. */
    memcpy(&aCmdBuff[wCmdLen], pValue, 4); /* PRQA S 3200 */
    wCmdLen += 4;

    /* Append LimitedCreditEnabled information. */
    aCmdBuff[wCmdLen++] = bLimitedCredit;

    /* Frame the Crypto information. */
    bComMode = (uint8_t)((bAuthMode == PHAL_MFDF_AUTHENTICATE) ? PHAL_MFDF_COMMUNICATION_MACD :
            PHAL_MFDF_COMMUNICATION_PLAIN);

    /* Exchange Cmd.CreateValueFile information to Sam and PICC. */
    PH_CHECK_SUCCESS_FCT(wStatus, phalMfdf_Sam_NonX_Int_WriteData(
            pDataParams,
            PH_EXCHANGE_DEFAULT,
            PH_OFF,
            bComMode,
            PHAL_MFDF_COMMUNICATION_MACD,
            PH_OFF,
            aCmdBuff,
            wCmdLen,
            NULL,
            0,
            NULL,
            NULL));

    return PH_ADD_COMPCODE(PH_ERR_SUCCESS, PH_COMP_AL_MFDF);
  }

  phStatus_t phalMfdf_Sam_NonX_CreateLinearRecordFile(void *pDataParams, uint8_t bOption,
      uint8_t  bFileNo, uint8_t *pISOFileId, uint8_t bFileOption, uint8_t *pAccessRights,
      uint8_t *pRecordSize, uint8_t *pMaxNoOfRec) {
    phStatus_t	PH_MEMLOC_REM wStatus = 0;
    uint8_t     PH_MEMLOC_REM aCmdBuff[13];
    uint16_t    PH_MEMLOC_REM wCmdLen = 0;
    uint8_t		PH_MEMLOC_REM bComMode = 0;
    uint8_t		PH_MEMLOC_REM bAuthMode = 0;

    /* Validate the parameters. */
    if (((bFileNo & 0x7f) > 0x1f) || (bOption > 0x01)) {
      return PH_ADD_COMPCODE(PH_ERR_INVALID_PARAMETER, PH_COMP_AL_MFDF);
    }

    if (((bFileOption & 0x7f) != PHAL_MFDF_COMMUNICATION_PLAIN) &&
        ((bFileOption & 0x7f) != PHAL_MFDF_COMMUNICATION_ENC) &&
        ((bFileOption & 0x7f) != PHAL_MFDF_COMMUNICATION_MACD)) {
      return PH_ADD_COMPCODE(PH_ERR_INVALID_PARAMETER, PH_COMP_AL_MFDF);
    }

    /* Get the dataparams information. */
    PH_CHECK_SUCCESS_FCT(wStatus, phalMfdf_Sam_NonX_Int_GetAuthMode(pDataParams, &bAuthMode));

    /* Frame the command information. */
    aCmdBuff[wCmdLen++] = PHAL_MFDF_CMD_CREATE_LINEAR_RECFILE;
    aCmdBuff[wCmdLen++] = bFileNo;

    /* Append ISOFileID is available. */
    if (bOption == 0x01) {
      memcpy(&aCmdBuff[wCmdLen], pISOFileId, 2); /* PRQA S 3200 */
      wCmdLen += 2;
    }

    /* Append communication settings */
    aCmdBuff[wCmdLen++] = (uint8_t)(bFileOption >> 4);

    /* Append access rights. */
    memcpy(&aCmdBuff[wCmdLen], pAccessRights, 2); /* PRQA S 3200 */
    wCmdLen += 2;

    /* Append RecordSize. */
    memcpy(&aCmdBuff[wCmdLen], pRecordSize, 3); /* PRQA S 3200 */
    wCmdLen += 3;

    /* Append maximim number of records. */
    memcpy(&aCmdBuff[wCmdLen], pMaxNoOfRec, 3); /* PRQA S 3200 */
    wCmdLen += 3;

    /* Frame the Crypto information. */
    bComMode = (uint8_t)((bAuthMode == PHAL_MFDF_AUTHENTICATE) ? PHAL_MFDF_COMMUNICATION_MACD :
            PHAL_MFDF_COMMUNICATION_PLAIN);

    /* Exchange Cmd.CreateLinearRecordFile information to Sam and PICC. */
    PH_CHECK_SUCCESS_FCT(wStatus, phalMfdf_Sam_NonX_Int_WriteData(
            pDataParams,
            PH_EXCHANGE_DEFAULT,
            PH_OFF,
            bComMode,
            PHAL_MFDF_COMMUNICATION_MACD,
            PH_OFF,
            aCmdBuff,
            wCmdLen,
            NULL,
            0,
            NULL,
            NULL));

    return PH_ADD_COMPCODE(PH_ERR_SUCCESS, PH_COMP_AL_MFDF);
  }

  phStatus_t phalMfdf_Sam_NonX_CreateCyclicRecordFile(void *pDataParams, uint8_t bOption,
      uint8_t  bFileNo, uint8_t *pISOFileId, uint8_t bFileOption, uint8_t *pAccessRights,
      uint8_t *pRecordSize, uint8_t *pMaxNoOfRec) {
    phStatus_t	PH_MEMLOC_REM wStatus = 0;
    uint8_t     PH_MEMLOC_REM aCmdBuff[13];
    uint16_t    PH_MEMLOC_REM wCmdLen = 0;
    uint8_t		PH_MEMLOC_REM bComMode = 0;
    uint8_t		PH_MEMLOC_REM bAuthMode = 0;

    /* Validate the parameters. */
    if (((bFileNo & 0x7f) > 0x1f) || (bOption > 0x01)) {
      return PH_ADD_COMPCODE(PH_ERR_INVALID_PARAMETER, PH_COMP_AL_MFDF);
    }

    if (((bFileOption & 0x7f) != PHAL_MFDF_COMMUNICATION_PLAIN) &&
        ((bFileOption & 0x7f) != PHAL_MFDF_COMMUNICATION_ENC) &&
        ((bFileOption & 0x7f) != PHAL_MFDF_COMMUNICATION_MACD)) {
      return PH_ADD_COMPCODE(PH_ERR_INVALID_PARAMETER, PH_COMP_AL_MFDF);
    }

    /* Get the dataparams information. */
    PH_CHECK_SUCCESS_FCT(wStatus, phalMfdf_Sam_NonX_Int_GetAuthMode(pDataParams, &bAuthMode));

    /* Frame the command information. */
    aCmdBuff[wCmdLen++] = PHAL_MFDF_CMD_CREATE_CYCLIC_RECFILE;
    aCmdBuff[wCmdLen++] = bFileNo;

    /* Append ISOFileID is available. */
    if (bOption == 0x01) {
      memcpy(&aCmdBuff[wCmdLen], pISOFileId, 2); /* PRQA S 3200 */
      wCmdLen += 2;
    }

    /* Append communication settings */
    aCmdBuff[wCmdLen++] = (uint8_t)(bFileOption >> 4);

    /* Append access rights. */
    memcpy(&aCmdBuff[wCmdLen], pAccessRights, 2); /* PRQA S 3200 */
    wCmdLen += 2;

    /* Append RecordSize. */
    memcpy(&aCmdBuff[wCmdLen], pRecordSize, 3); /* PRQA S 3200 */
    wCmdLen += 3;

    /* Append maximim number of records. */
    memcpy(&aCmdBuff[wCmdLen], pMaxNoOfRec, 3); /* PRQA S 3200 */
    wCmdLen += 3;

    /* Frame the Crypto information. */
    bComMode = (uint8_t)((bAuthMode == PHAL_MFDF_AUTHENTICATE) ? PHAL_MFDF_COMMUNICATION_MACD :
            PHAL_MFDF_COMMUNICATION_PLAIN);

    /* Exchange Cmd.CreateCyclicRecordFile information to Sam and PICC. */
    PH_CHECK_SUCCESS_FCT(wStatus, phalMfdf_Sam_NonX_Int_WriteData(
            pDataParams,
            PH_EXCHANGE_DEFAULT,
            PH_OFF,
            bComMode,
            PHAL_MFDF_COMMUNICATION_MACD,
            PH_OFF,
            aCmdBuff,
            wCmdLen,
            NULL,
            0,
            NULL,
            NULL));

    return PH_ADD_COMPCODE(PH_ERR_SUCCESS, PH_COMP_AL_MFDF);
  }

  phStatus_t phalMfdf_Sam_NonX_DeleteFile(void *pDataParams, uint8_t bFileNo) {
    phStatus_t	PH_MEMLOC_REM wStatus = 0;
    uint8_t     PH_MEMLOC_REM aCmdBuff[2];
    uint16_t    PH_MEMLOC_REM wCmdLen = 0;
    uint8_t		PH_MEMLOC_REM bComMode = 0;
    uint8_t		PH_MEMLOC_REM bAuthMode = 0;

    /* Validate the parameters. */
    if ((bFileNo & 0x7f) > 0x1f) {
      return PH_ADD_COMPCODE(PH_ERR_INVALID_PARAMETER, PH_COMP_AL_MFDF);
    }

    /* Get the dataparams information. */
    PH_CHECK_SUCCESS_FCT(wStatus, phalMfdf_Sam_NonX_Int_GetAuthMode(pDataParams, &bAuthMode));

    /* Frame the command information. */
    aCmdBuff[wCmdLen++] = PHAL_MFDF_CMD_DELETE_FILE;
    aCmdBuff[wCmdLen++] = bFileNo;

    /* Frame the Crypto information. */
    bComMode = (uint8_t)((bAuthMode == PHAL_MFDF_AUTHENTICATE) ? PHAL_MFDF_COMMUNICATION_MACD :
            PHAL_MFDF_COMMUNICATION_PLAIN);

    /* Exchange Cmd.DeleteFile information to Sam and PICC. */
    PH_CHECK_SUCCESS_FCT(wStatus, phalMfdf_Sam_NonX_Int_WriteData(
            pDataParams,
            PH_EXCHANGE_DEFAULT,
            PH_OFF,
            bComMode,
            PHAL_MFDF_COMMUNICATION_MACD,
            PH_OFF,
            aCmdBuff,
            wCmdLen,
            NULL,
            0,
            NULL,
            NULL));

    return PH_ADD_COMPCODE(PH_ERR_SUCCESS, PH_COMP_AL_MFDF);
  }

  /* MIFARE DESFire Data Manipulation commands. ---------------------------------------------------------------------------------------- */
  phStatus_t phalMfdf_Sam_NonX_ReadData(void *pDataParams, uint8_t bOption, uint8_t bFileNo,
      uint8_t *pOffset, uint8_t *pLength, uint8_t **ppResponse,
      uint16_t *pRespLen) {
    phStatus_t	PH_MEMLOC_REM wStatus = 0;
    uint8_t		PH_MEMLOC_REM aCmdBuff[8];
    uint16_t	PH_MEMLOC_REM wCmdLen = 0;
    uint8_t		PH_MEMLOC_REM bCmd_ComMode = 0;
    uint8_t		PH_MEMLOC_REM bResp_ComMode = 0;
    uint16_t	PH_MEMLOC_REM wOption = 0;
    uint32_t	PH_MEMLOC_REM dwLength = 0;
    uint8_t		PH_MEMLOC_REM bAuthMode = 0;

    /* Validate the parameter. */
    if ((bFileNo & 0x7f) > 0x1f) {
      return PH_ADD_COMPCODE(PH_ERR_INVALID_PARAMETER, PH_COMP_AL_MFDF);
    }

    if (((bOption & 0xF0) != PHAL_MFDF_COMMUNICATION_PLAIN) &&
        ((bOption & 0xF0) != PHAL_MFDF_COMMUNICATION_ENC) &&
        ((bOption & 0xF0) != PHAL_MFDF_COMMUNICATION_MACD)) {
      return PH_ADD_COMPCODE(PH_ERR_INVALID_PARAMETER, PH_COMP_AL_MFDF);
    }

    if (((bOption & 0x0FU) != PH_EXCHANGE_DEFAULT) && ((bOption & 0x0FU) != PH_EXCHANGE_RXCHAINING)) {
      return PH_ADD_COMPCODE(PH_ERR_INVALID_PARAMETER, PH_COMP_AL_MFDF);
    }

    /* Get the dataparams information. */
    PH_CHECK_SUCCESS_FCT(wStatus, phalMfdf_Sam_NonX_Int_GetAuthMode(pDataParams, &bAuthMode));

    /* Frame the command information based on the option. */
    if ((bOption & 0x0FU) == PH_EXCHANGE_RXCHAINING) {
      /* Frame additional frame code. */
      aCmdBuff[wCmdLen++] = PHAL_MFDF_RESP_ADDITIONAL_FRAME;
    } else {
      /* Frame Presence of length information in the command frame.
       * The first three bytes specifies number of bytes to be received from PICC.
       */
      if ((bOption & 0xF0) == PHAL_MFDF_COMMUNICATION_ENC) {
        dwLength = pLength[2];
        dwLength = dwLength << 8 | pLength[1];
        dwLength = dwLength << 8 | pLength[0];
      }

      /* Frame the command information. */
      aCmdBuff[wCmdLen++] = PHAL_MFDF_CMD_READ_DATA;
      aCmdBuff[wCmdLen++] = bFileNo;

      memcpy(&aCmdBuff[wCmdLen], pOffset, 3); /* PRQA S 3200 */
      wCmdLen += 3;

      memcpy(&aCmdBuff[wCmdLen], pLength, 3); /* PRQA S 3200 */
      wCmdLen += 3;
    }

    /* Frame the SM to be applied for command. */
    bCmd_ComMode = (uint8_t)(bOption & 0xF0);
    bCmd_ComMode = (uint8_t)(((bAuthMode != PHAL_MFDF_AUTHENTICATE) ||
                (bCmd_ComMode == PHAL_MFDF_COMMUNICATION_MACD)) ?
            PHAL_MFDF_COMMUNICATION_MACD : PHAL_MFDF_COMMUNICATION_PLAIN);
    bCmd_ComMode = (uint8_t)(((bAuthMode == PHAL_MFDF_AUTHENTICATE) &&
                ((bOption & 0xF0) == PHAL_MFDF_COMMUNICATION_PLAIN)) ?
            PHAL_MFDF_COMMUNICATION_PLAIN : bCmd_ComMode);

    /* Frame the SM to be applied for response. */
    bResp_ComMode = (uint8_t)(bOption & 0xF0);

    /* Frame Option parameter. */
    wOption = (uint16_t)(bOption & 0x0FU) ;

    /* Exchange Cmd.ReadData information to Sam and PICC. */
    wStatus = phalMfdf_Sam_NonX_Int_ReadData(
            pDataParams,
            (uint8_t)(wOption | PHALMFDF_SAM_NONX_RETURN_CHAINING_STATUS),
            PH_ON,
            bCmd_ComMode,
            bResp_ComMode,
            dwLength,
            aCmdBuff,
            wCmdLen,
            ppResponse,
            pRespLen);

    return wStatus;
  }

  phStatus_t phalMfdf_Sam_NonX_WriteData(void *pDataParams, uint8_t bOption, uint8_t bFileNo,
      uint8_t *pOffset, uint8_t *pData, uint8_t *pDataLen) {
    phStatus_t	PH_MEMLOC_REM wStatus = 0;
    uint8_t     PH_MEMLOC_REM aCmdBuff[8];
    uint16_t	PH_MEMLOC_REM wCmdLen = 0;
    uint32_t	PH_MEMLOC_REM dwDataLen = 0;
    uint8_t		PH_MEMLOC_REM bCmd_ComMode = 0;
    uint8_t		PH_MEMLOC_REM bResp_ComMode = 0;
    uint8_t		PH_MEMLOC_REM bAuthMode = 0;

    /* Validate the parameters */
    if ((bFileNo & 0x7f) > 0x1f) {
      return PH_ADD_COMPCODE(PH_ERR_INVALID_PARAMETER, PH_COMP_AL_MFDF);
    }
    if ((bOption != PHAL_MFDF_COMMUNICATION_PLAIN) &&
        (bOption != PHAL_MFDF_COMMUNICATION_ENC) &&
        (bOption != PHAL_MFDF_COMMUNICATION_MACD)) {
      return PH_ADD_COMPCODE(PH_ERR_INVALID_PARAMETER, PH_COMP_AL_MFDF);
    }

    /* Get the dataparams information. */
    PH_CHECK_SUCCESS_FCT(wStatus, phalMfdf_Sam_NonX_Int_GetAuthMode(pDataParams, &bAuthMode));

    /* Frame the command information. */
    aCmdBuff[wCmdLen++] = PHAL_MFDF_CMD_WRITE_DATA;
    aCmdBuff[wCmdLen++] = bFileNo;

    memcpy(&aCmdBuff[wCmdLen], pOffset, 3);
    wCmdLen += 3;

    memcpy(&aCmdBuff[wCmdLen], pDataLen, 3);
    wCmdLen += 3;

    /* Set the lengths. */
    dwDataLen = (uint32_t)(pDataLen[0] | (pDataLen[1] << 8) | (pDataLen[2] << 16));

    /* Frame the SM to be applied for command. */
    bCmd_ComMode = (uint8_t)(bOption & 0xF0);

    /* Frame the SM to be applied for command. */
    bResp_ComMode = (uint8_t)((bAuthMode == PHAL_MFDF_AUTHENTICATE) ? PHAL_MFDF_COMMUNICATION_PLAIN :
            PHAL_MFDF_COMMUNICATION_MACD);
    bResp_ComMode = (uint8_t)(((bAuthMode == PHAL_MFDF_AUTHENTICATE) &&
                ((bOption & 0xF0) == PHAL_MFDF_COMMUNICATION_PLAIN)) ?
            PHAL_MFDF_COMMUNICATION_PLAIN : bResp_ComMode);

    /* Exchange Cmd.WriteData information to Sam and PICC. */
    PH_CHECK_SUCCESS_FCT(wStatus, phalMfdf_Sam_NonX_Int_WriteData(
            pDataParams,
            PH_EXCHANGE_DEFAULT,
            PH_ON,
            bCmd_ComMode,
            bResp_ComMode,
            PH_OFF,
            aCmdBuff,
            wCmdLen,
            pData,
            dwDataLen,
            NULL,
            NULL));

    return PH_ADD_COMPCODE(PH_ERR_SUCCESS, PH_COMP_AL_MFDF);
  }

  phStatus_t phalMfdf_Sam_NonX_GetValue(void *pDataParams, uint8_t bCommOption, uint8_t bFileNo,
      uint8_t *pValue) {
    phStatus_t	PH_MEMLOC_REM wStatus = 0;
    uint8_t		PH_MEMLOC_REM aCmdBuff[2];
    uint8_t		PH_MEMLOC_REM bCmd_ComMode = 0;
    uint8_t		PH_MEMLOC_REM bResp_ComMode = 0;
    uint16_t	PH_MEMLOC_REM wRespLen = 0;
    uint8_t		PH_MEMLOC_REM bAuthMode = 0;

    /* Validate the parameters. */
    if ((bFileNo & 0x7f) > 0x1f) {
      return PH_ADD_COMPCODE(PH_ERR_INVALID_PARAMETER, PH_COMP_AL_MFDF);
    }

    if ((bCommOption != PHAL_MFDF_COMMUNICATION_PLAIN) &&
        (bCommOption != PHAL_MFDF_COMMUNICATION_ENC) &&
        (bCommOption != PHAL_MFDF_COMMUNICATION_MACD)) {
      return PH_ADD_COMPCODE(PH_ERR_INVALID_PARAMETER, PH_COMP_AL_MFDF);
    }

    /* Get the dataparams information. */
    PH_CHECK_SUCCESS_FCT(wStatus, phalMfdf_Sam_NonX_Int_GetAuthMode(pDataParams, &bAuthMode));

    /* Frame the command information. */
    aCmdBuff[0] = PHAL_MFDF_CMD_GET_VALUE;
    aCmdBuff[1] = bFileNo;

    /* Frame the SM to be applied for command. */
    bCmd_ComMode = bCommOption;
    bCmd_ComMode = (uint8_t)(((bAuthMode != PHAL_MFDF_AUTHENTICATE) ||
                (bCmd_ComMode == PHAL_MFDF_COMMUNICATION_MACD)) ?
            PHAL_MFDF_COMMUNICATION_MACD : PHAL_MFDF_COMMUNICATION_PLAIN);
    bCmd_ComMode = (uint8_t)(((bAuthMode == PHAL_MFDF_AUTHENTICATE) &&
                (bCommOption == PHAL_MFDF_COMMUNICATION_PLAIN)) ?
            PHAL_MFDF_COMMUNICATION_PLAIN : bCmd_ComMode);

    /* Frame the SM to be applied for response. */
    bResp_ComMode = bCommOption;

    /* Exchange Cmd.GetValue information to Sam and PICC. */
    PH_CHECK_SUCCESS_FCT(wStatus, phalMfdf_Sam_NonX_Int_ReadData(
            pDataParams,
            PH_EXCHANGE_DEFAULT,
            PH_ON,
            bCmd_ComMode,
            bResp_ComMode,
            4,
            aCmdBuff,
            2,
            &pValue,
            &wRespLen));

    return wStatus;
  }

  phStatus_t phalMfdf_Sam_NonX_Credit(void *pDataParams, uint8_t bCommOption, uint8_t bFileNo,
      uint8_t *pValue) {
    phStatus_t	PH_MEMLOC_REM wStatus = 0;
    uint8_t     PH_MEMLOC_REM aCmdBuff[2];
    uint8_t		PH_MEMLOC_REM bCmd_ComMode = 0;
    uint8_t		PH_MEMLOC_REM bResp_ComMode = 0;
    uint8_t		PH_MEMLOC_REM bAuthMode = 0;

    /* Validate the parameters */
    if ((bFileNo & 0x3f) > 0x1f) {
      return PH_ADD_COMPCODE(PH_ERR_INVALID_PARAMETER, PH_COMP_AL_MFDF);
    }

    if (((bCommOption & 0x3f) != PHAL_MFDF_COMMUNICATION_PLAIN) &&
        ((bCommOption & 0x3f) != PHAL_MFDF_COMMUNICATION_ENC) &&
        ((bCommOption & 0x3f) != PHAL_MFDF_COMMUNICATION_MACD)) {
      return PH_ADD_COMPCODE(PH_ERR_INVALID_PARAMETER, PH_COMP_AL_MFDF);
    }

    /* Get the dataparams information. */
    PH_CHECK_SUCCESS_FCT(wStatus, phalMfdf_Sam_NonX_Int_GetAuthMode(pDataParams, &bAuthMode));

    /* Frame the command information. */
    aCmdBuff[0] = PHAL_MFDF_CMD_CREDIT;
    aCmdBuff[1] = bFileNo;

    /* Frame the SM to be applied for command. */
    bCmd_ComMode = bCommOption;

    /* Frame the SM to be applied for command. */
    bResp_ComMode = (uint8_t)((bAuthMode == PHAL_MFDF_AUTHENTICATE) ? PHAL_MFDF_COMMUNICATION_PLAIN :
            PHAL_MFDF_COMMUNICATION_MACD);
    bResp_ComMode = (uint8_t)(((bAuthMode == PHAL_MFDF_AUTHENTICATE) &&
                (bCommOption == PHAL_MFDF_COMMUNICATION_PLAIN)) ?
            PHAL_MFDF_COMMUNICATION_PLAIN : bResp_ComMode);

    /* Exchange Cmd.Credit information to Sam and PICC. */
    PH_CHECK_SUCCESS_FCT(wStatus, phalMfdf_Sam_NonX_Int_WriteData(
            pDataParams,
            PH_EXCHANGE_DEFAULT,
            PH_ON,
            bCmd_ComMode,
            bResp_ComMode,
            PH_OFF,
            aCmdBuff,
            2,
            pValue,
            4,
            NULL,
            NULL));

    return PH_ADD_COMPCODE(PH_ERR_SUCCESS, PH_COMP_AL_MFDF);
  }

  phStatus_t phalMfdf_Sam_NonX_Debit(void *pDataParams, uint8_t bCommOption, uint8_t bFileNo,
      uint8_t *pValue) {
    phStatus_t	PH_MEMLOC_REM wStatus = 0;
    uint8_t     PH_MEMLOC_REM aCmdBuff[2];
    uint8_t		PH_MEMLOC_REM bCmd_ComMode = 0;
    uint8_t		PH_MEMLOC_REM bResp_ComMode = 0;
    uint8_t		PH_MEMLOC_REM bAuthMode = 0;

    /* Validate the parameters */
    if ((bFileNo & 0x3f) > 0x1f) {
      return PH_ADD_COMPCODE(PH_ERR_INVALID_PARAMETER, PH_COMP_AL_MFDF);
    }

    if (((bCommOption & 0x3f) != PHAL_MFDF_COMMUNICATION_PLAIN) &&
        ((bCommOption & 0x3f) != PHAL_MFDF_COMMUNICATION_ENC) &&
        ((bCommOption & 0x3f) != PHAL_MFDF_COMMUNICATION_MACD)) {
      return PH_ADD_COMPCODE(PH_ERR_INVALID_PARAMETER, PH_COMP_AL_MFDF);
    }

    /* Get the dataparams information. */
    PH_CHECK_SUCCESS_FCT(wStatus, phalMfdf_Sam_NonX_Int_GetAuthMode(pDataParams, &bAuthMode));

    /* Frame the command information. */
    aCmdBuff[0] = PHAL_MFDF_CMD_DEBIT;
    aCmdBuff[1] = bFileNo;

    /* Frame the SM to be applied for command. */
    bCmd_ComMode = bCommOption;

    /* Frame the SM to be applied for command. */
    bResp_ComMode = (uint8_t)((bAuthMode == PHAL_MFDF_AUTHENTICATE) ? PHAL_MFDF_COMMUNICATION_PLAIN :
            PHAL_MFDF_COMMUNICATION_MACD);
    bResp_ComMode = (uint8_t)(((bAuthMode == PHAL_MFDF_AUTHENTICATE) &&
                (bCommOption == PHAL_MFDF_COMMUNICATION_PLAIN)) ?
            PHAL_MFDF_COMMUNICATION_PLAIN : bResp_ComMode);

    /* Exchange Cmd.Debit information to Sam and PICC. */
    PH_CHECK_SUCCESS_FCT(wStatus, phalMfdf_Sam_NonX_Int_WriteData(
            pDataParams,
            PH_EXCHANGE_DEFAULT,
            PH_ON,
            bCmd_ComMode,
            bResp_ComMode,
            PH_OFF,
            aCmdBuff,
            2,
            pValue,
            4,
            NULL,
            NULL));

    return PH_ADD_COMPCODE(PH_ERR_SUCCESS, PH_COMP_AL_MFDF);
  }

  phStatus_t phalMfdf_Sam_NonX_LimitedCredit(void *pDataParams, uint8_t bCommOption,
      uint8_t bFileNo, uint8_t *pValue) {
    phStatus_t	PH_MEMLOC_REM wStatus = 0;
    uint8_t     PH_MEMLOC_REM aCmdBuff[2];
    uint8_t		PH_MEMLOC_REM bCmd_ComMode = 0;
    uint8_t		PH_MEMLOC_REM bResp_ComMode = 0;
    uint8_t		PH_MEMLOC_REM bAuthMode = 0;

    /* Validate the parameters */
    if ((bFileNo & 0x3f) > 0x1f) {
      return PH_ADD_COMPCODE(PH_ERR_INVALID_PARAMETER, PH_COMP_AL_MFDF);
    }

    if (((bCommOption & 0x3f) != PHAL_MFDF_COMMUNICATION_PLAIN) &&
        ((bCommOption & 0x3f) != PHAL_MFDF_COMMUNICATION_ENC) &&
        ((bCommOption & 0x3f) != PHAL_MFDF_COMMUNICATION_MACD)) {
      return PH_ADD_COMPCODE(PH_ERR_INVALID_PARAMETER, PH_COMP_AL_MFDF);
    }

    /* Get the dataparams information. */
    PH_CHECK_SUCCESS_FCT(wStatus, phalMfdf_Sam_NonX_Int_GetAuthMode(pDataParams, &bAuthMode));

    /* Frame the command information. */
    aCmdBuff[0] = PHAL_MFDF_CMD_LIMITED_CREDIT;
    aCmdBuff[1] = bFileNo;

    /* Frame the SM to be applied for command. */
    bCmd_ComMode = bCommOption;

    /* Frame the SM to be applied for command. */
    bResp_ComMode = (uint8_t)((bAuthMode == PHAL_MFDF_AUTHENTICATE) ? PHAL_MFDF_COMMUNICATION_PLAIN :
            PHAL_MFDF_COMMUNICATION_MACD);
    bResp_ComMode = (uint8_t)(((bAuthMode == PHAL_MFDF_AUTHENTICATE) &&
                (bCommOption == PHAL_MFDF_COMMUNICATION_PLAIN)) ?
            PHAL_MFDF_COMMUNICATION_PLAIN : bResp_ComMode);

    /* Exchange Cmd.LimitedCredit information to Sam and PICC. */
    PH_CHECK_SUCCESS_FCT(wStatus, phalMfdf_Sam_NonX_Int_WriteData(
            pDataParams,
            PH_EXCHANGE_DEFAULT,
            PH_ON,
            bCmd_ComMode,
            bResp_ComMode,
            PH_OFF,
            aCmdBuff,
            2,
            pValue,
            4,
            NULL,
            NULL));

    return PH_ADD_COMPCODE(PH_ERR_SUCCESS, PH_COMP_AL_MFDF);
  }

  phStatus_t phalMfdf_Sam_NonX_ReadRecords(void *pDataParams, uint8_t bOption, uint8_t bFileNo,
      uint8_t *pRecNo, uint8_t *pRecCount, uint8_t *pRecSize,
      uint8_t **ppResponse, uint16_t *pRespLen) {
    phStatus_t	PH_MEMLOC_REM wStatus = 0;
    uint8_t		PH_MEMLOC_REM aCmdBuff[8];
    uint16_t	PH_MEMLOC_REM wCmdLen = 0;
    uint8_t		PH_MEMLOC_REM bCmd_ComMode = 0;
    uint8_t		PH_MEMLOC_REM bResp_ComMode = 0;
    uint16_t	PH_MEMLOC_REM wOption = 0;
    uint32_t	PH_MEMLOC_REM dwLength = 0;
    uint8_t		PH_MEMLOC_REM bAuthMode = 0;

    /* Validate the parameter. */
    if ((bFileNo & 0x7f) > 0x1f) {
      return PH_ADD_COMPCODE(PH_ERR_INVALID_PARAMETER, PH_COMP_AL_MFDF);
    }

    if (((bOption & 0xF0) != PHAL_MFDF_COMMUNICATION_PLAIN) &&
        ((bOption & 0xF0) != PHAL_MFDF_COMMUNICATION_ENC) &&
        ((bOption & 0xF0) != PHAL_MFDF_COMMUNICATION_MACD)) {
      return PH_ADD_COMPCODE(PH_ERR_INVALID_PARAMETER, PH_COMP_AL_MFDF);
    }

    if (((bOption & 0x0FU) != PH_EXCHANGE_DEFAULT) && ((bOption & 0x0FU) != PH_EXCHANGE_RXCHAINING)) {
      return PH_ADD_COMPCODE(PH_ERR_INVALID_PARAMETER, PH_COMP_AL_MFDF);
    }

    /* Get the dataparams information. */
    PH_CHECK_SUCCESS_FCT(wStatus, phalMfdf_Sam_NonX_Int_GetAuthMode(pDataParams, &bAuthMode));

    /* Frame the command information based on the option. */
    if ((bOption & 0x0FU) == PH_EXCHANGE_RXCHAINING) {
      /* Frame additional frame code. */
      aCmdBuff[wCmdLen++] = PHAL_MFDF_RESP_ADDITIONAL_FRAME;
    } else {
      /* Frame Presence of length information in the command frame.
       * The first three bytes specifies number of bytes to be received from PICC.
       */
      if ((bOption & 0xF0) == PHAL_MFDF_COMMUNICATION_ENC) {
        dwLength = pRecSize[2];
        dwLength = dwLength << 8 | pRecSize[1];
        dwLength = dwLength << 8 | pRecSize[0];
      }

      /* Frame the command information. */
      aCmdBuff[wCmdLen++] = PHAL_MFDF_CMD_READ_RECORDS;
      aCmdBuff[wCmdLen++] = bFileNo;

      memcpy(&aCmdBuff[wCmdLen], pRecNo, 3); /* PRQA S 3200 */
      wCmdLen += 3;

      memcpy(&aCmdBuff[wCmdLen], pRecCount, 3); /* PRQA S 3200 */
      wCmdLen += 3;
    }

    /* Frame the SM to be applied for command. */
    bCmd_ComMode = (uint8_t)(bOption & 0xF0);
    bCmd_ComMode = (uint8_t)(((bAuthMode != PHAL_MFDF_AUTHENTICATE) ||
                (bCmd_ComMode == PHAL_MFDF_COMMUNICATION_MACD)) ?
            PHAL_MFDF_COMMUNICATION_MACD : PHAL_MFDF_COMMUNICATION_PLAIN);
    bCmd_ComMode = (uint8_t)(((bAuthMode == PHAL_MFDF_AUTHENTICATE) &&
                ((bOption & 0xF0) == PHAL_MFDF_COMMUNICATION_PLAIN)) ?
            PHAL_MFDF_COMMUNICATION_PLAIN : bCmd_ComMode);

    /* Frame the SM to be applied for response. */
    bResp_ComMode = (uint8_t)(bOption & 0xF0);

    /* Frame Option parameter. */
    wOption = (uint16_t)(bOption & 0x0FU) ;

    /* Exchange Cmd.ReadRecords information to Sam and PICC. */
    wStatus = phalMfdf_Sam_NonX_Int_ReadData(
            pDataParams,
            (uint8_t)(wOption | PHALMFDF_SAM_NONX_RETURN_CHAINING_STATUS),
            PH_ON,
            bCmd_ComMode,
            bResp_ComMode,
            dwLength,
            aCmdBuff,
            wCmdLen,
            ppResponse,
            pRespLen);

    return wStatus;
  }

  phStatus_t phalMfdf_Sam_NonX_WriteRecord(void *pDataParams, uint8_t bOption, uint8_t bFileNo,
      uint8_t *pOffset, uint8_t *pData, uint8_t *pDataLen) {
    phStatus_t	PH_MEMLOC_REM wStatus = 0;
    uint8_t     PH_MEMLOC_REM aCmdBuff[8];
    uint16_t	PH_MEMLOC_REM wCmdLen = 0;
    uint32_t	PH_MEMLOC_REM dwDataLen = 0;
    uint8_t		PH_MEMLOC_REM bCmd_ComMode = 0;
    uint8_t		PH_MEMLOC_REM bResp_ComMode = 0;
    uint8_t		PH_MEMLOC_REM bAuthMode = 0;

    /* Validate the parameters */
    if ((bFileNo & 0x7f) > 0x1f) {
      return PH_ADD_COMPCODE(PH_ERR_INVALID_PARAMETER, PH_COMP_AL_MFDF);
    }
    if ((bOption != PHAL_MFDF_COMMUNICATION_PLAIN) &&
        (bOption != PHAL_MFDF_COMMUNICATION_ENC) &&
        (bOption != PHAL_MFDF_COMMUNICATION_MACD)) {
      return PH_ADD_COMPCODE(PH_ERR_INVALID_PARAMETER, PH_COMP_AL_MFDF);
    }

    /* Get the dataparams information. */
    PH_CHECK_SUCCESS_FCT(wStatus, phalMfdf_Sam_NonX_Int_GetAuthMode(pDataParams, &bAuthMode));

    /* Frame the command information. */
    aCmdBuff[wCmdLen++] = PHAL_MFDF_CMD_WRITE_RECORD;
    aCmdBuff[wCmdLen++] = bFileNo;

    memcpy(&aCmdBuff[wCmdLen], pOffset, 3);
    wCmdLen += 3;

    memcpy(&aCmdBuff[wCmdLen], pDataLen, 3);
    wCmdLen += 3;

    /* Set the lengths. */
    dwDataLen = (uint32_t)(pDataLen[0] | (pDataLen[1] << 8) | (pDataLen[2] << 16));

    /* Frame the SM to be applied for command. */
    bCmd_ComMode = (uint8_t)(bOption & 0xF0);

    /* Frame the SM to be applied for command. */
    bResp_ComMode = (uint8_t)((bAuthMode == PHAL_MFDF_AUTHENTICATE) ? PHAL_MFDF_COMMUNICATION_PLAIN :
            PHAL_MFDF_COMMUNICATION_MACD);
    bResp_ComMode = (uint8_t)(((bAuthMode == PHAL_MFDF_AUTHENTICATE) &&
                ((bOption & 0xF0) == PHAL_MFDF_COMMUNICATION_PLAIN)) ?
            PHAL_MFDF_COMMUNICATION_PLAIN : bResp_ComMode);

    /* Exchange Cmd.WriteRecord information to Sam and PICC. */
    PH_CHECK_SUCCESS_FCT(wStatus, phalMfdf_Sam_NonX_Int_WriteData(
            pDataParams,
            PH_EXCHANGE_DEFAULT,
            PH_ON,
            bCmd_ComMode,
            bResp_ComMode,
            PH_OFF,
            aCmdBuff,
            wCmdLen,
            pData,
            dwDataLen,
            NULL,
            NULL));

    return PH_ADD_COMPCODE(PH_ERR_SUCCESS, PH_COMP_AL_MFDF);
  }

  phStatus_t phalMfdf_Sam_NonX_ClearRecordFile(void *pDataParams, uint8_t bFileNo) {
    phStatus_t	PH_MEMLOC_REM wStatus = 0;
    uint8_t     PH_MEMLOC_REM aCmdBuff[2];
    uint8_t		PH_MEMLOC_REM bComMode = 0;
    uint8_t		PH_MEMLOC_REM bAuthMode = 0;

    /* Validate the parameters. */
    if ((bFileNo & 0x7f) > 0x1f) {
      return PH_ADD_COMPCODE(PH_ERR_INVALID_PARAMETER, PH_COMP_AL_MFDF);
    }

    /* Get the dataparams information. */
    PH_CHECK_SUCCESS_FCT(wStatus, phalMfdf_Sam_NonX_Int_GetAuthMode(pDataParams, &bAuthMode));

    /* Frame the command information. */
    aCmdBuff[0] = PHAL_MFDF_CMD_CLEAR_RECORDS_FILE;
    aCmdBuff[1] = bFileNo;

    /* Frame the Crypto information. */
    bComMode = (uint8_t)((bAuthMode == PHAL_MFDF_AUTHENTICATE) ? PHAL_MFDF_COMMUNICATION_MACD :
            PHAL_MFDF_COMMUNICATION_PLAIN);

    /* Exchange Cmd.ClearRecordFile information to Sam and PICC. */
    PH_CHECK_SUCCESS_FCT(wStatus, phalMfdf_Sam_NonX_Int_WriteData(
            pDataParams,
            PH_EXCHANGE_DEFAULT,
            PH_OFF,
            bComMode,
            PHAL_MFDF_COMMUNICATION_MACD,
            PH_OFF,
            aCmdBuff,
            2,
            NULL,
            0,
            NULL,
            NULL));

    return PH_ADD_COMPCODE(PH_ERR_SUCCESS, PH_COMP_AL_MFDF);
  }

  phStatus_t phalMfdf_Sam_NonX_CommitTransaction(void *pDataParams) {
    phStatus_t	PH_MEMLOC_REM wStatus = 0;
    uint8_t     PH_MEMLOC_REM aCmdBuff[2];
    uint8_t		PH_MEMLOC_REM bCmdLen = 0;
    uint8_t		PH_MEMLOC_REM bComMode = 0;
    uint8_t		*PH_MEMLOC_REM pResponse = NULL;
    uint16_t	PH_MEMLOC_REM wRespLen = 0;
    uint8_t		PH_MEMLOC_REM bAuthMode = 0;

    /* Get the dataparams information. */
    PH_CHECK_SUCCESS_FCT(wStatus, phalMfdf_Sam_NonX_Int_GetAuthMode(pDataParams, &bAuthMode));

    /* Frame the command information. */
    aCmdBuff[bCmdLen++] = PHAL_MFDF_CMD_COMMIT_TXN;

    /* Frame the Crypto information. */
    bComMode = (uint8_t)((bAuthMode == PHAL_MFDF_AUTHENTICATE) ? PHAL_MFDF_COMMUNICATION_MACD :
            PHAL_MFDF_COMMUNICATION_PLAIN);

    /* Exchange Cmd.CommitTransaction information to Sam and PICC. */
    PH_CHECK_SUCCESS_FCT(wStatus, phalMfdf_Sam_NonX_Int_WriteData(
            pDataParams,
            PH_EXCHANGE_DEFAULT,
            PH_OFF,
            bComMode,
            PHAL_MFDF_COMMUNICATION_MACD,
            PH_OFF,
            aCmdBuff,
            bCmdLen,
            NULL,
            0,
            &pResponse,
            &wRespLen));

    return PH_ADD_COMPCODE(PH_ERR_SUCCESS, PH_COMP_AL_MFDF);
  }

  phStatus_t phalMfdf_Sam_NonX_AbortTransaction(void *pDataParams) {
    phStatus_t	PH_MEMLOC_REM wStatus = 0;
    uint8_t     PH_MEMLOC_REM aCmdBuff[1];
    uint8_t		PH_MEMLOC_REM bComMode = 0;
    uint8_t		PH_MEMLOC_REM bAuthMode = 0;

    /* Get the dataparams information. */
    PH_CHECK_SUCCESS_FCT(wStatus, phalMfdf_Sam_NonX_Int_GetAuthMode(pDataParams, &bAuthMode));

    /* Frame the command information. */
    aCmdBuff[0] = PHAL_MFDF_CMD_ABORT_TXN;

    /* Frame the Crypto information. */
    bComMode = (uint8_t)((bAuthMode == PHAL_MFDF_AUTHENTICATE) ? PHAL_MFDF_COMMUNICATION_MACD :
            PHAL_MFDF_COMMUNICATION_PLAIN);

    /* Exchange Cmd.AbortTransaction information to Sam and PICC. */
    PH_CHECK_SUCCESS_FCT(wStatus, phalMfdf_Sam_NonX_Int_WriteData(
            pDataParams,
            PH_EXCHANGE_DEFAULT,
            PH_OFF,
            bComMode,
            PHAL_MFDF_COMMUNICATION_MACD,
            PH_OFF,
            aCmdBuff,
            1,
            NULL,
            0,
            NULL,
            NULL));

    return PH_ADD_COMPCODE(PH_ERR_SUCCESS, PH_COMP_AL_MFDF);
  }

  /* MIFARE DESFire ISO7816 commands. -------------------------------------------------------------------------------------------------- */
  phStatus_t phalMfdf_Sam_NonX_IsoSelectFile(void *pDataParams, uint8_t bOption, uint8_t bSelector,
      uint8_t *pFid, uint8_t *pDFname, uint8_t bDFnameLen,
      uint8_t **ppFCI, uint16_t *pFCILen) {
    phStatus_t  PH_MEMLOC_REM wStatus = 0;
    uint8_t		PH_MEMLOC_REM aCmdBuff[25];
    uint16_t	PH_MEMLOC_REM wCmdLen = 0;
    uint8_t		*PH_MEMLOC_REM pResponse = NULL;
    uint16_t	PH_MEMLOC_REM wRespLen = 0;
    uint8_t		PH_MEMLOC_REM aFileId[3] = {'\0'};
    uint8_t		PH_MEMLOC_REM bWrappedMode = 0;
    uint8_t		PH_MEMLOC_REM aPiccDfName[7] = {0xD2, 0x76, 0x00, 0x00, 0x85, 0x01, 0x00};

    /* Validate the parameters. */
    if ((bDFnameLen > 16) || ((bOption != 0x00) && (bOption != 0x0C))) {
      return PH_ADD_COMPCODE(PH_ERR_INVALID_PARAMETER, PH_COMP_AL_MFDF);
    }

    if ((bSelector !=  0x00) && (bSelector !=  0x02) && (bSelector != 0x04)) {
      return PH_ADD_COMPCODE(PH_ERR_INVALID_PARAMETER, PH_COMP_AL_MFDF);
    }

    /* Frame the command. */
    aCmdBuff[wCmdLen++] = 0x00;
    aCmdBuff[wCmdLen++] = PHAL_MFDF_CMD_ISO7816_SELECT_FILE;
    aCmdBuff[wCmdLen++] = bSelector;
    aCmdBuff[wCmdLen++] = bOption;

    /* Append the payload and LC. */
    if (bSelector == 0x04) {
      /* Append LC. */
      aCmdBuff[wCmdLen++] = bDFnameLen;

      memcpy(&aCmdBuff[wCmdLen], pDFname, bDFnameLen); /* PRQA S 3200 */
      wCmdLen += bDFnameLen;
    } else {
      /* Append LC. */
      aCmdBuff[wCmdLen++] = 2;

      /* Select MF, DF or EF, by file identifier
       * Select child DF
       * Select EF under the current DF, by file identifier
       * Select parent DF of the current DF
       */
      aFileId[1] = aCmdBuff[wCmdLen++] = pFid[1];
      aFileId[0] = aCmdBuff[wCmdLen++] = pFid[0];
      aFileId[2] = 0;
    }

    /* Append LE. */
    aCmdBuff[wCmdLen++] = 0;

    /* Backup the existing information. */
    PH_CHECK_SUCCESS_FCT(wStatus, phalMfdf_Sam_NonX_Int_GetWrappedMode(pDataParams, &bWrappedMode));

    /* Disable the wrapping because internally it should be exchanged in non wrapped mode. */
    PH_CHECK_SUCCESS_FCT(wStatus, phalMfdf_Sam_NonX_Int_SetWrappedMode(pDataParams, PH_OFF));

    /* Exchange Cmd.ISOSelectFile information to PICC. */
    PH_CHECK_SUCCESS_FCT(wStatus, phalMfdf_Sam_NonX_Int_WriteData(
            pDataParams,
            (uint16_t)(PH_EXCHANGE_DEFAULT | PHALMFDF_SAM_NONX_EXCHANGE_WITHOUT_SM |
                PHALMFDF_SAM_NONX_PICC_STATUS_WRAPPED),
            PH_OFF,
            PHAL_MFDF_COMMUNICATION_PLAIN,
            PHAL_MFDF_COMMUNICATION_PLAIN,
            PH_OFF,
            aCmdBuff,
            wCmdLen,
            NULL,
            NULL,
            NULL,
            NULL));

    /* Restore the backedup information. */
    PH_CHECK_SUCCESS_FCT(wStatus, phalMfdf_Sam_NonX_Int_SetWrappedMode(pDataParams, bWrappedMode));

    /* Reset Authentication should not be targeted for elementary file selection using file ID */
    if (bSelector !=  0x02) {
      /* Reset Authentication Status here */
      phalMfdf_Sam_NonX_ResetAuthStatus(pDataParams);
    }

    /* ISO wrapped mode is on */
    PH_CHECK_SUCCESS_FCT(wStatus, phalMfdf_Sam_NonX_Int_SetWrappedMode(pDataParams, PH_ON));

    /* once the selection Success, update the File Id to master data structure if the selection is done through AID */
    if ((bSelector ==  0x00) || (bSelector == 0x02)) {
      PH_CHECK_SUCCESS_FCT(wStatus, phalMfdf_Sam_NonX_Int_SetAid(pDataParams, aFileId));
    } else {
      /* Update the file ID to all zeros if DF Name is of PICC. */
      if (memcmp(pDFname, aPiccDfName, 7) == 0) {
        aFileId[0] = 0x00;
        aFileId[1] = 0x00;
        aFileId[2] = 0x00;
      } else {
        aFileId[0] = 0xff;
        aFileId[1] = 0xff;
        aFileId[2] = 0xff;
      }

      PH_CHECK_SUCCESS_FCT(wStatus, phalMfdf_Sam_NonX_Int_SetAid(pDataParams, aFileId));
    }

    /* Copy the response to the buffer */
    *ppFCI = pResponse;
    *pFCILen = wRespLen;

    return PH_ADD_COMPCODE(PH_ERR_SUCCESS, PH_COMP_AL_MFDF);
  }

  phStatus_t phalMfdf_Sam_NonX_IsoReadBinary(void *pDataParams, uint16_t wOption, uint8_t bOffset,
      uint8_t bSfid, uint8_t bBytesToRead,
      uint8_t **ppResponse, uint16_t *pBytesRead) {
    phStatus_t	PH_MEMLOC_REM wStatus = 0;
    uint8_t		PH_MEMLOC_REM aCmdBuff[8];
    uint16_t	PH_MEMLOC_REM wCmdLen = 0;
    uint16_t	PH_MEMLOC_REM wRespLen = 0;
    uint8_t		PH_MEMLOC_REM bWrappedMode = 0;

    /* Validate the parameter. */
    if (bSfid & 0x80) {
      /* Short file id is supplied */
      if ((bSfid & 0x7FU) > 0x1F) {
        /* Error condition */
        return PH_ADD_COMPCODE(PH_ERR_INVALID_PARAMETER, PH_COMP_AL_MFDF);
      }
    }

    if ((wOption != PH_EXCHANGE_DEFAULT) && (wOption != PH_EXCHANGE_RXCHAINING)) {
      return PH_ADD_COMPCODE(PH_ERR_INVALID_PARAMETER, PH_COMP_AL_MFDF);
    }

    if (wOption == PH_EXCHANGE_DEFAULT) {
      /* Frame the command information based on the option. */
      aCmdBuff[wCmdLen++] = 0x00;
      aCmdBuff[wCmdLen++] = PHAL_MFDF_CMD_ISO7816_READ_BINARY;
      aCmdBuff[wCmdLen++] = bSfid;
      aCmdBuff[wCmdLen++] = bOffset;
      aCmdBuff[wCmdLen++] = bBytesToRead;
    } else {
      /* Do nothing. */
    }

    /* Backup the existing information. */
    PH_CHECK_SUCCESS_FCT(wStatus, phalMfdf_Sam_NonX_Int_GetWrappedMode(pDataParams, &bWrappedMode));

    /* Disable the wrapping because internally it should be exchanged in non wrapped mode. */
    PH_CHECK_SUCCESS_FCT(wStatus, phalMfdf_Sam_NonX_Int_SetWrappedMode(pDataParams, PH_OFF));

    /* Exchange Cmd.ISOReadBinary information to Sam and PICC. */
    wStatus = phalMfdf_Sam_NonX_Int_ReadData(
            pDataParams,
            (uint16_t)(wOption | PHALMFDF_SAM_NONX_EXCHANGE_WITHOUT_SM |
                PHALMFDF_SAM_NONX_PICC_STATUS_WRAPPED),
            PH_ON,
            PHAL_MFDF_COMMUNICATION_PLAIN,
            PHAL_MFDF_COMMUNICATION_PLAIN,
            0,
            aCmdBuff,
            wCmdLen,
            ppResponse,
            &wRespLen);

    *pBytesRead = wRespLen;

    /* Restore the backedup information. */
    PH_CHECK_SUCCESS_FCT(wStatus, phalMfdf_Sam_NonX_Int_SetWrappedMode(pDataParams, bWrappedMode));

    return wStatus;
  }

  phStatus_t phalMfdf_Sam_NonX_IsoUpdateBinary(void *pDataParams, uint8_t bOffset, uint8_t bSfid,
      uint8_t *pData, uint32_t dwDataLen) {
    phStatus_t  PH_MEMLOC_REM wStatus = 0;
    uint8_t		PH_MEMLOC_REM aCmdBuff[7];
    uint16_t	PH_MEMLOC_REM wCmdLen = 0;
    uint8_t		PH_MEMLOC_REM bWrappedMode = 0;

    /* Validate the parameters */
    if (bSfid & 0x80) {
      /* Short file id is supplied */
      if ((bSfid & 0x7FU) > 0x1F) {
        /* Error condition */
        return PH_ADD_COMPCODE(PH_ERR_INVALID_PARAMETER, PH_COMP_AL_MFDF);
      }
    }

    /* Frame the command. */
    aCmdBuff[wCmdLen++] = 0x00;										/* CLA */
    aCmdBuff[wCmdLen++] = PHAL_MFDF_CMD_ISO7816_UPDATE_BINARY;	/* INS */
    aCmdBuff[wCmdLen++] = bSfid;									/* P1 */
    aCmdBuff[wCmdLen++] = bOffset;
    aCmdBuff[wCmdLen++] = (uint8_t)(dwDataLen & 0x000000FF);

    /* Backup the existing information. */
    PH_CHECK_SUCCESS_FCT(wStatus, phalMfdf_Sam_NonX_Int_GetWrappedMode(pDataParams, &bWrappedMode));

    /* Disable the wrapping because internally it should be exchanged in non wrapped mode. */
    PH_CHECK_SUCCESS_FCT(wStatus, phalMfdf_Sam_NonX_Int_SetWrappedMode(pDataParams, PH_OFF));

    /* Exchange Cmd.ISOUpdateBinary information to PICC. */
    PH_CHECK_SUCCESS_FCT(wStatus, phalMfdf_Sam_NonX_Int_WriteData(
            pDataParams,
            (uint16_t)(PH_EXCHANGE_DEFAULT | PHALMFDF_SAM_NONX_EXCHANGE_WITHOUT_SM |
                PHALMFDF_SAM_NONX_PICC_STATUS_WRAPPED),
            PH_ON,
            PHAL_MFDF_COMMUNICATION_PLAIN,
            PHAL_MFDF_COMMUNICATION_PLAIN,
            PH_OFF,
            aCmdBuff,
            wCmdLen,
            pData,
            dwDataLen,
            NULL,
            NULL));

    /* Restore the backedup information. */
    PH_CHECK_SUCCESS_FCT(wStatus, phalMfdf_Sam_NonX_Int_SetWrappedMode(pDataParams, bWrappedMode));

    return PH_ADD_COMPCODE(PH_ERR_SUCCESS, PH_COMP_AL_MFDF);
  }

  phStatus_t phalMfdf_Sam_NonX_IsoReadRecords(void *pDataParams, uint16_t wOption, uint8_t bRecNo,
      uint8_t bReadAllFromP1, uint8_t bSfid, uint8_t bBytesToRead,
      uint8_t **ppResponse, uint16_t *pBytesRead) {
    phStatus_t	PH_MEMLOC_REM wStatus = 0;
    uint8_t		PH_MEMLOC_REM aCmdBuff[8];
    uint16_t	PH_MEMLOC_REM wCmdLen = 0;
    uint8_t		PH_MEMLOC_REM bWrappedMode = 0;
    uint16_t	PH_MEMLOC_REM wRespLen = 0;

    /* Validate the parameter. */
    if (bSfid > 0x1F) {
      return PH_ADD_COMPCODE(PH_ERR_INVALID_PARAMETER, PH_COMP_AL_MFDF);
    }

    if ((wOption != PH_EXCHANGE_DEFAULT) && (wOption != PH_EXCHANGE_RXCHAINING)) {
      return PH_ADD_COMPCODE(PH_ERR_INVALID_PARAMETER, PH_COMP_AL_MFDF);
    }

    if (wOption == PH_EXCHANGE_DEFAULT) {
      /* Frame the command information based on the option. */
      aCmdBuff[wCmdLen++] = 0x00;
      aCmdBuff[wCmdLen++] = PHAL_MFDF_CMD_ISO7816_READ_RECORDS;
      aCmdBuff[wCmdLen++] = bRecNo;
      aCmdBuff[wCmdLen++] = (uint8_t)((bSfid <<= 3) | (bReadAllFromP1 ? 0x05 : 0x04));
      aCmdBuff[wCmdLen++] = bBytesToRead;
    } else {
      /* Do nothing. */
    }

    /* Backup the existing information. */
    PH_CHECK_SUCCESS_FCT(wStatus, phalMfdf_Sam_NonX_Int_GetWrappedMode(pDataParams, &bWrappedMode));

    /* Disable the wrapping because internally it should be exchanged in non wrapped mode. */
    PH_CHECK_SUCCESS_FCT(wStatus, phalMfdf_Sam_NonX_Int_SetWrappedMode(pDataParams, PH_OFF));

    /* Exchange Cmd.ISOReadRecord information to Sam and PICC. */
    wStatus = phalMfdf_Sam_NonX_Int_ReadData(
            pDataParams,
            (uint16_t)(wOption | PHALMFDF_SAM_NONX_EXCHANGE_WITHOUT_SM |
                PHALMFDF_SAM_NONX_PICC_STATUS_WRAPPED),
            PH_ON,
            PHAL_MFDF_COMMUNICATION_PLAIN,
            PHAL_MFDF_COMMUNICATION_PLAIN,
            0,
            aCmdBuff,
            wCmdLen,
            ppResponse,
            &wRespLen);

    *pBytesRead = wRespLen;

    /* Restore the backedup information. */
    PH_CHECK_SUCCESS_FCT(wStatus, phalMfdf_Sam_NonX_Int_SetWrappedMode(pDataParams, bWrappedMode));

    return wStatus;
  }

  phStatus_t phalMfdf_Sam_NonX_IsoAppendRecord(void *pDataParams, uint8_t bSfid, uint8_t *pData,
      uint32_t dwDataLen) {
    phStatus_t  PH_MEMLOC_REM wStatus = 0;
    uint8_t		PH_MEMLOC_REM aCmdBuff[7];
    uint16_t	PH_MEMLOC_REM wCmdLen = 0;
    uint8_t		PH_MEMLOC_REM bWrappedMode = 0;

    /* Short file id is supplied */
    if ((bSfid & 0x7FU) > 0x1F) {
      /* Error condition */
      return PH_ADD_COMPCODE(PH_ERR_INVALID_PARAMETER, PH_COMP_AL_MFDF);
    }

    /* Frame the command. */
    aCmdBuff[wCmdLen++] = 0x00;
    aCmdBuff[wCmdLen++] = PHAL_MFDF_CMD_ISO7816_APPEND_RECORD;
    aCmdBuff[wCmdLen++] = 0x00;
    aCmdBuff[wCmdLen++] = (uint8_t)(bSfid << 3);
    aCmdBuff[wCmdLen++] = (uint8_t)(dwDataLen & 0x000000FF);

    /* Backup the existing information. */
    PH_CHECK_SUCCESS_FCT(wStatus, phalMfdf_Sam_NonX_Int_GetWrappedMode(pDataParams, &bWrappedMode));

    /* Disable the wrapping because internally it should be exchanged in non wrapped mode. */
    PH_CHECK_SUCCESS_FCT(wStatus, phalMfdf_Sam_NonX_Int_SetWrappedMode(pDataParams, PH_OFF));

    /* Exchange Cmd.ISOAppendRecord information to PICC. */
    PH_CHECK_SUCCESS_FCT(wStatus, phalMfdf_Sam_NonX_Int_WriteData(
            pDataParams,
            (uint16_t)(PH_EXCHANGE_DEFAULT | PHALMFDF_SAM_NONX_EXCHANGE_WITHOUT_SM |
                PHALMFDF_SAM_NONX_PICC_STATUS_WRAPPED),
            PH_ON,
            PHAL_MFDF_COMMUNICATION_PLAIN,
            PHAL_MFDF_COMMUNICATION_PLAIN,
            PH_OFF,
            aCmdBuff,
            wCmdLen,
            pData,
            dwDataLen,
            NULL,
            NULL));

    /* Restore the backedup information. */
    PH_CHECK_SUCCESS_FCT(wStatus, phalMfdf_Sam_NonX_Int_SetWrappedMode(pDataParams, bWrappedMode));

    return PH_ADD_COMPCODE(PH_ERR_SUCCESS, PH_COMP_AL_MFDF);
  }

  phStatus_t phalMfdf_Sam_NonX_IsoGetChallenge(void *pDataParams, uint16_t wKeyNo, uint16_t wKeyVer,
      uint32_t dwLe, uint8_t *pRPICC1) {
    phStatus_t	PH_MEMLOC_REM wStatus = 0;
    uint8_t		PH_MEMLOC_REM aCmdBuff[8];
    uint16_t	PH_MEMLOC_REM wCmdLen = 0;
    uint16_t	PH_MEMLOC_REM wRespLen = 0;
    uint8_t		PH_MEMLOC_REM bWrappedMode = 0;

    PHAL_MFDF_UNUSED_VARIABLE(wKeyNo);
    PHAL_MFDF_UNUSED_VARIABLE(wKeyVer);

    /* Frame the command information based on the option. */
    aCmdBuff[wCmdLen++] = 0x00;
    aCmdBuff[wCmdLen++] = PHAL_MFDF_CMD_ISO7816_GET_CHALLENGE;
    aCmdBuff[wCmdLen++] = 0x00;
    aCmdBuff[wCmdLen++] = 0x00;
    aCmdBuff[wCmdLen++] = (uint8_t)(dwLe & 0x000000FF);

    /* Backup the existing information. */
    PH_CHECK_SUCCESS_FCT(wStatus, phalMfdf_Sam_NonX_Int_GetWrappedMode(pDataParams, &bWrappedMode));

    /* Disable the wrapping because internally it should be exchanged in non wrapped mode. */
    PH_CHECK_SUCCESS_FCT(wStatus, phalMfdf_Sam_NonX_Int_SetWrappedMode(pDataParams, PH_OFF));

    /* Exchange Cmd.ISOGetChallange information to Sam and PICC. */
    PH_CHECK_SUCCESS_FCT(wStatus, phalMfdf_Sam_NonX_Int_ReadData(
            pDataParams,
            (uint16_t)(PH_EXCHANGE_DEFAULT | PHALMFDF_SAM_NONX_EXCHANGE_WITHOUT_SM |
                PHALMFDF_SAM_NONX_PICC_STATUS_WRAPPED),
            PH_ON,
            PHAL_MFDF_COMMUNICATION_PLAIN,
            PHAL_MFDF_COMMUNICATION_PLAIN,
            0,
            aCmdBuff,
            wCmdLen,
            &pRPICC1,
            &wRespLen));

    /* Restore the backedup information. */
    PH_CHECK_SUCCESS_FCT(wStatus, phalMfdf_Sam_NonX_Int_SetWrappedMode(pDataParams, bWrappedMode));

    return PH_ADD_COMPCODE(PH_ERR_SUCCESS, PH_COMP_AL_MFDF);
  }

  phStatus_t phalMfdf_Sam_NonX_IsoExternalAuthenticate(void *pDataParams, uint8_t *pDataIn,
      uint8_t bInputLen, uint8_t *pDataOut, uint8_t *pOutLen) {
    phStatus_t  PH_MEMLOC_REM wStatus = 0;
    phStatus_t  PH_MEMLOC_REM wStatus1 = 0;
    uint8_t		PH_MEMLOC_REM aCmdBuff[8];
    uint16_t	PH_MEMLOC_REM wCmdLen = 0;
    uint8_t     PH_MEMLOC_REM bInOffset = 0;
    uint8_t     PH_MEMLOC_REM bAlgo = 0;
    uint8_t     PH_MEMLOC_REM bIsDFkey = 0;
    uint8_t     PH_MEMLOC_REM bKeyNoCard = 0;
    uint8_t     PH_MEMLOC_REM bRndLen = 0;
    uint16_t    PH_MEMLOC_REM wKeyNo = 0;
    uint16_t    PH_MEMLOC_REM wKeyVer = 0;
    uint8_t     PH_MEMLOC_REM aRPICC1[16];
    uint8_t     PH_MEMLOC_REM aRPCD2[16];
    uint8_t		PH_MEMLOC_REM aResponse[50];
    uint8_t		*PH_MEMLOC_REM pResponse = NULL;
    uint16_t	PH_MEMLOC_REM wRespLen = 0;
    uint8_t		PH_MEMLOC_REM bWrappedMode = 0;

    /* Validate the parameters. */
    if ((bInputLen != 16) && (bInputLen != 24)) {
      return PH_ADD_COMPCODE(PH_ERR_INVALID_PARAMETER, PH_COMP_AL_MFDF);
    }

    /* Extract the information from Input buffer. */
    bAlgo		= pDataIn[bInOffset++];
    bIsDFkey	= pDataIn[bInOffset++];
    bKeyNoCard	= pDataIn[bInOffset++];
    bRndLen		= pDataIn[bInOffset++];

    if (bKeyNoCard > 0x0d) {
      return PH_ADD_COMPCODE(PH_ERR_INVALID_PARAMETER, PH_COMP_AL_MFDF);
    }

    if ((bAlgo != 0x00) && (bAlgo != 0x02) && (bAlgo != 0x04) && (bAlgo != 0x09)) {
      return PH_ADD_COMPCODE(PH_ERR_INVALID_PARAMETER, PH_COMP_AL_MFDF);
    }

    memcpy(aRPICC1, &pDataIn[bInOffset], bRndLen); /* PRQA S 3200 */
    bInOffset += bRndLen;

    memcpy(&wKeyNo, &pDataIn[bInOffset], 2); /* PRQA S 3200 */
    bInOffset += 2;

    memcpy(&wKeyVer, &pDataIn[bInOffset], 2); /* PRQA S 3200 */
    bInOffset += 2;

    /* Exchange the input information to SAM ------------------------------------------------------------------------------------- */
    pResponse = aResponse;
    wStatus1 = PHHAL_HW_CMD_SAM_ISO_AUTHENTICATE_PART1(
            pDataParams,
            0x00,
            (uint8_t) wKeyNo,
            (uint8_t) wKeyVer,
            NULL,
            0x00,
            aRPICC1,
            bRndLen,
            pResponse,
            wRespLen);

    if ((wStatus1 & PH_ERR_MASK) != PH_ERR_SUCCESS_CHAINING) {
      phalMfdf_Sam_NonX_Int_ResetAuthStatus(pDataParams);
      return wStatus1;
    }

    /* Copy RPDC2 received from Sam. */
    memcpy(aRPCD2, &pResponse[wRespLen - bRndLen], bRndLen); /* PRQA S 3200 */

    /* Exchange the information to PICC ------------------------------------------------------------------------------------------ */
    aCmdBuff[wCmdLen++] = 0x00;
    aCmdBuff[wCmdLen++] = PHAL_MFDF_CMD_ISO7816_EXT_AUTHENTICATE;
    aCmdBuff[wCmdLen++] = bAlgo;
    aCmdBuff[wCmdLen++] = (uint8_t)((bIsDFkey << 7) | bKeyNoCard);
    aCmdBuff[wCmdLen++] = (uint8_t)((wRespLen - bRndLen) & 0x000000FF);

    /* Backup the existing information. */
    PH_CHECK_SUCCESS_FCT(wStatus, phalMfdf_Sam_NonX_Int_GetWrappedMode(pDataParams, &bWrappedMode));

    /* Disable the wrapping because internally it should be exchanged in non wrapped mode. */
    PH_CHECK_SUCCESS_FCT(wStatus, phalMfdf_Sam_NonX_Int_SetWrappedMode(pDataParams, PH_OFF));

    /* Exchange Cmd.ISOExternalAuthenticate information to PICC. */
    wStatus = phalMfdf_Sam_NonX_Int_WriteData(
            pDataParams,
            (uint16_t)(PH_EXCHANGE_DEFAULT | PHALMFDF_SAM_NONX_EXCHANGE_WITHOUT_SM |
                PHALMFDF_SAM_NONX_PICC_STATUS_WRAPPED),
            PH_ON,
            PHAL_MFDF_COMMUNICATION_PLAIN,
            PHAL_MFDF_COMMUNICATION_PLAIN,
            PH_OFF,
            aCmdBuff,
            wCmdLen,
            pResponse,
            (wRespLen - bRndLen),
            &pResponse,
            &wRespLen);

    /* Copy RPCD2 to output buffer. */
    if (wStatus == PH_ERR_SUCCESS) {
      memcpy(pDataOut, aRPCD2, bRndLen); /* PRQA S 3200 */
      *pOutLen = bRndLen;

      /* Restore the backedup information. */
      PH_CHECK_SUCCESS_FCT(wStatus, phalMfdf_Sam_NonX_Int_SetWrappedMode(pDataParams, bWrappedMode));
    } else {
      phalMfdf_Sam_NonX_Int_ResetAuthStatus(pDataParams);
    }

    return wStatus;
  }

  phStatus_t phalMfdf_Sam_NonX_IsoInternalAuthenticate(void *pDataParams, uint8_t *pDataIn,
      uint8_t bInputLen, uint8_t *pDataOut, uint8_t *pOutLen) {
    phStatus_t  PH_MEMLOC_REM wStatus = 0;
    uint8_t		PH_MEMLOC_REM aCmdBuff[25];
    uint16_t	PH_MEMLOC_REM wCmdLen = 0;
    uint8_t     PH_MEMLOC_REM bInOffset = 0;
    uint8_t     PH_MEMLOC_REM bAlgo = 0;
    uint8_t     PH_MEMLOC_REM bIsDFkey = 0;
    uint8_t     PH_MEMLOC_REM bKeyNoCard = 0;
    uint8_t     PH_MEMLOC_REM bRndLen = 0;
    uint16_t    PH_MEMLOC_REM wKeyNo = 0;
    uint16_t    PH_MEMLOC_REM wKeyVer = 0;
    uint8_t     PH_MEMLOC_REM aData[16];
    uint8_t		PH_MEMLOC_REM bDataLen = 0;
    uint8_t		*PH_MEMLOC_REM pResponse = NULL;
    uint16_t	PH_MEMLOC_REM wRespLen = 0;
    uint8_t		PH_MEMLOC_REM bWrappedMode = 0;
    uint16_t    PH_MEMLOC_REM wHostMode = 0;
    uint8_t		PH_MEMLOC_REM bKeyType = 0;

    PHAL_MFDF_UNUSED_VARIABLE(pDataOut);
    PHAL_MFDF_UNUSED_VARIABLE(pOutLen);

    /* Validate the parameters. */
    if ((bInputLen != 16) && (bInputLen != 24)) {
      return PH_ADD_COMPCODE(PH_ERR_INVALID_PARAMETER, PH_COMP_AL_MFDF);
    }

    /* Extract the information from Input buffer. */
    bAlgo		= pDataIn[bInOffset++];
    bIsDFkey	= pDataIn[bInOffset++];
    bKeyNoCard	= pDataIn[bInOffset++];
    bRndLen		= pDataIn[bInOffset++];

    if (bKeyNoCard > 0x0d) {
      return PH_ADD_COMPCODE(PH_ERR_INVALID_PARAMETER, PH_COMP_AL_MFDF);
    }

    if ((bAlgo != 0x00) && (bAlgo != 0x02) && (bAlgo != 0x04) && (bAlgo != 0x09)) {
      return PH_ADD_COMPCODE(PH_ERR_INVALID_PARAMETER, PH_COMP_AL_MFDF);
    }

    memcpy(aData, &pDataIn[bInOffset], bRndLen); /* PRQA S 3200 */
    bInOffset += bRndLen;

    memcpy(&wKeyNo, &pDataIn[bInOffset], 2); /* PRQA S 3200 */
    bInOffset += 2;

    memcpy(&wKeyVer, &pDataIn[bInOffset], 2); /* PRQA S 3200 */
    bInOffset += 2;

    /* Exchange the information to PICC ------------------------------------------------------------------------------------------ */
    aCmdBuff[wCmdLen++] = 0x00;
    aCmdBuff[wCmdLen++] = PHAL_MFDF_CMD_ISO7816_INT_AUTHENTICATE;
    aCmdBuff[wCmdLen++] = bAlgo;
    aCmdBuff[wCmdLen++] = (uint8_t)((bIsDFkey << 7) | bKeyNoCard);
    aCmdBuff[wCmdLen++] = (uint8_t)(bRndLen & 0x000000FF);

    memcpy(&aCmdBuff[wCmdLen], aData, bRndLen); /* PRQA S 3200 */
    wCmdLen += bRndLen;

    aCmdBuff[wCmdLen++] = (uint8_t)((bRndLen == 8) ? 16 : 32);

    /* Backup the existing information. */
    PH_CHECK_SUCCESS_FCT(wStatus, phalMfdf_Sam_NonX_Int_GetWrappedMode(pDataParams, &bWrappedMode));

    /* Disable the wrapping because internally it should be exchanged in non wrapped mode. */
    PH_CHECK_SUCCESS_FCT(wStatus, phalMfdf_Sam_NonX_Int_SetWrappedMode(pDataParams, PH_OFF));

    /* Exchange Cmd.ISOExternalAuthenticate information to PICC. */
    wStatus = phalMfdf_Sam_NonX_Int_WriteData(
            pDataParams,
            (uint16_t)(PH_EXCHANGE_DEFAULT | PHALMFDF_SAM_NONX_EXCHANGE_WITHOUT_SM |
                PHALMFDF_SAM_NONX_PICC_STATUS_WRAPPED),
            PH_ON,
            PHAL_MFDF_COMMUNICATION_PLAIN,
            PHAL_MFDF_COMMUNICATION_PLAIN,
            PH_OFF,
            aCmdBuff,
            wCmdLen,
            NULL,
            0,
            &pResponse,
            &wRespLen);

    /* Reset the Authentication. */
    if (wStatus != PH_ERR_SUCCESS) {
      phalMfdf_Sam_NonX_Int_ResetAuthStatus(pDataParams);
      return wStatus;
    }

    /* Restore the backedup information. */
    PH_CHECK_SUCCESS_FCT(wStatus, phalMfdf_Sam_NonX_Int_SetWrappedMode(pDataParams, PH_ON));

    /* Exchange the information to SAM ------------------------------------------------------------------------------------------- */
    wStatus = PHHAL_HW_CMD_SAM_ISO_AUTHENTICATE_PART2(
            pDataParams,
            pResponse,
            (uint8_t) wRespLen);

    /* Return error. */
    if (wStatus != PH_ERR_SUCCESS) {
      if ((wStatus & PH_ERR_MASK) != (PH_ERR_CUSTOM_BEGIN + 19)) {
        return PH_ADD_COMPCODE(PH_ERR_AUTH_ERROR, PH_COMP_AL_MFDF);
      } else {
        return wStatus;
      }
    }

    /* Get the Host mode. */
    PH_CHECK_SUCCESS_FCT(wStatus, PHHAL_HW_GET_CONFIG(
            pDataParams,
            PH_CONFIG_CUSTOM_BEGIN,
            &wHostMode));

    /* Getkey entry from SAM to switch the key type */
    PH_CHECK_SUCCESS_FCT(wStatus, PHHAL_HW_CMD_SAM_GET_KEY_ENTRY(
            pDataParams,
            (uint8_t) wKeyNo,
            aData,
            &bDataLen));

    /* Extract the Keytype. */
    bKeyType = (uint8_t)((aData[(bDataLen - 3)] & 0x38) >> 3);

    /* Set the authentication based on the keytype. */
    switch (bKeyType) {
      case 0x00:
      case 0x03:
        /* 2K3DES keys or 3K3DES */
        PH_CHECK_SUCCESS_FCT(wStatus, phalMfdf_Sam_NonX_Int_SetAuthMode(pDataParams,
                PHAL_MFDF_AUTHENTICATEISO));
        break;

      case 0x04:
        /* AES KEYS */
        PH_CHECK_SUCCESS_FCT(wStatus, phalMfdf_Sam_NonX_Int_SetAuthMode(pDataParams,
                PHAL_MFDF_AUTHENTICATEAES));
        break;

      default:
        return PH_ADD_COMPCODE(PH_ERR_INVALID_PARAMETER, PH_COMP_AL_MFDF);
    }

    PH_CHECK_SUCCESS_FCT(wStatus, phalMfdf_Sam_NonX_Int_SetKeyNo(pDataParams, bKeyNoCard));
    PH_CHECK_SUCCESS_FCT(wStatus, phalMfdf_Sam_NonX_Int_SetWrappedMode(pDataParams, PH_ON));

    return PH_ADD_COMPCODE(PH_ERR_SUCCESS, PH_COMP_AL_MFDF);
  }

  phStatus_t phalMfdf_Sam_NonX_IsoAuthenticate(void *pDataParams, uint16_t wKeyNo, uint16_t wKeyVer,
      uint8_t bKeyNoCard, uint8_t bIsPICCkey) {
    phStatus_t  PH_MEMLOC_REM wStatus = 0;
    uint16_t    PH_MEMLOC_REM wHostMode = 0;
    uint8_t		PH_MEMLOC_REM bKeyType = 0;
    uint8_t     PH_MEMLOC_REM aRnd[16];
    uint8_t     PH_MEMLOC_REM aData[25];
    uint8_t		PH_MEMLOC_REM bDataLen = 0;
    uint8_t		PH_MEMLOC_REM bRndLen = 0;
    uint8_t     PH_MEMLOC_REM bAlgo = 0;

    /* Validate the parameters */
    if ((bKeyNoCard > 0x0d) || (wKeyNo > 0x7F) || (wKeyVer > 0xFF)) {
      return PH_ADD_COMPCODE(PH_ERR_INVALID_PARAMETER, PH_COMP_AL_MFDF);
    }

    /* Get the Host mode. */
    PH_CHECK_SUCCESS_FCT(wStatus, PHHAL_HW_GET_CONFIG(
            pDataParams,
            PHHAL_HW_SAMAV3_CONFIG_HOSTMODE,
            &wHostMode));

    /* Getkey entry from SAM to switch the key type */
    PH_CHECK_SUCCESS_FCT(wStatus, PHHAL_HW_CMD_SAM_GET_KEY_ENTRY(
            pDataParams,
            (uint8_t) wKeyNo,
            aData,
            &bDataLen));

    /* Extract the Keytype. */
    bKeyType = (uint8_t)((aData[(bDataLen - 3)] & 0x38) >> 3);

    /* Set the random length. */
    switch (bKeyType) {
      case 0x00:
        bAlgo = 0x02;
        bRndLen = 8;
        break;

      case 0x03:
        bAlgo = 0x04;
        bRndLen = 16;
        break;

      case 0x04:
        bAlgo = 0x09;
        bRndLen = 16;
        break;

      default:
        return PH_ADD_COMPCODE(PH_ERR_KEY, PH_COMP_AL_MFDF);
    }

    /* Perform ISOGetChallange ----------------------------------------------------------------------------------------------- */
    PH_CHECK_SUCCESS_FCT(wStatus, phalMfdf_Sam_NonX_IsoGetChallenge(pDataParams, wKeyNo, wKeyVer,
            bRndLen, aRnd));

    /* Perform ISOExternalAuthenticate --------------------------------------------------------------------------------------- */
    bDataLen = 0;
    aData[bDataLen++] = bAlgo;
    aData[bDataLen++] = !bIsPICCkey;
    aData[bDataLen++] = bKeyNoCard;
    aData[bDataLen++] = bRndLen;

    memcpy(&aData[bDataLen], aRnd, bRndLen); /* PRQA S 3200 */
    bDataLen += bRndLen;

    memcpy(&aData[bDataLen], &wKeyNo, 2); /* PRQA S 3200 */
    bDataLen += 2;

    memcpy(&aData[bDataLen], &wKeyVer, 2); /* PRQA S 3200 */
    bDataLen += 2;

    PH_CHECK_SUCCESS_FCT(wStatus, phalMfdf_Sam_NonX_IsoExternalAuthenticate(pDataParams, aData,
            bDataLen, aRnd,
            &bDataLen));

    /* Perform ISOInternalAuthenticate --------------------------------------------------------------------------------------- */
    bDataLen = 0;
    aData[bDataLen++] = bAlgo;
    aData[bDataLen++] = !bIsPICCkey;
    aData[bDataLen++] = bKeyNoCard;
    aData[bDataLen++] = bRndLen;

    memcpy(&aData[bDataLen], aRnd, bRndLen); /* PRQA S 3200 */
    bDataLen += bRndLen;

    memcpy(&aData[bDataLen], &wKeyNo, 2); /* PRQA S 3200 */
    bDataLen += 2;

    memcpy(&aData[bDataLen], &wKeyVer, 2); /* PRQA S 3200 */
    bDataLen += 2;

    PH_CHECK_SUCCESS_FCT(wStatus, phalMfdf_Sam_NonX_IsoInternalAuthenticate(pDataParams, aData,
            bDataLen, NULL, NULL));

    /* Set the authentication based on the keytype. */
    switch (bKeyType) {
      case 0x00:
      case 0x03:
        /* 2K3DES keys or 3K3DES */
        PH_CHECK_SUCCESS_FCT(wStatus, phalMfdf_Sam_NonX_Int_SetAuthMode(pDataParams,
                PHAL_MFDF_AUTHENTICATEISO));
        break;

      case 0x04:
        /* AES KEYS */
        PH_CHECK_SUCCESS_FCT(wStatus, phalMfdf_Sam_NonX_Int_SetAuthMode(pDataParams,
                PHAL_MFDF_AUTHENTICATEAES));
        break;

      default:
        break;
    }

    PH_CHECK_SUCCESS_FCT(wStatus, phalMfdf_Sam_NonX_Int_SetKeyNo(pDataParams, bKeyNoCard));
    PH_CHECK_SUCCESS_FCT(wStatus, phalMfdf_Sam_NonX_Int_SetWrappedMode(pDataParams, PH_ON));

    return PH_ADD_COMPCODE(PH_ERR_SUCCESS, PH_COMP_AL_MFDF);
  }

  /* MIFARE DESFire Miscellaneous functions. ------------------------------------------------------------------------------------------- */
  phStatus_t phalMfdf_Sam_NonX_GetConfig(void *pDataParams, uint16_t wConfig, uint16_t *pValue) {
    phStatus_t  PH_MEMLOC_REM wStatus = 0;
    uint8_t		PH_MEMLOC_REM bValue = 0;

    switch (wConfig) {
      case PHAL_MFDF_ADDITIONAL_INFO:
        PH_CHECK_SUCCESS_FCT(wStatus, phalMfdf_Sam_NonX_Int_GetAdditionalInfo(pDataParams, pValue));
        break;

      case PHAL_MFDF_WRAPPED_MODE:
        PH_CHECK_SUCCESS_FCT(wStatus, phalMfdf_Sam_NonX_Int_GetWrappedMode(pDataParams, &bValue));
        *pValue = bValue;
        break;

      default:
        return PH_ADD_COMPCODE(PH_ERR_UNSUPPORTED_PARAMETER, PH_COMP_AL_MFDF);
    }

    return PH_ADD_COMPCODE(PH_ERR_SUCCESS, PH_COMP_AL_MFDF);
  }

  phStatus_t phalMfdf_Sam_NonX_SetConfig(void *pDataParams, uint16_t wConfig, uint16_t wValue) {
    phStatus_t  PH_MEMLOC_REM wStatus = 0;

    switch (wConfig) {
      case PHAL_MFDF_ADDITIONAL_INFO:
        PH_CHECK_SUCCESS_FCT(wStatus, phalMfdf_Sam_NonX_Int_SetAdditionalInfo(pDataParams, wValue));
        break;

      case PHAL_MFDF_WRAPPED_MODE:
        PH_CHECK_SUCCESS_FCT(wStatus, phalMfdf_Sam_NonX_Int_SetWrappedMode(pDataParams,
                (uint8_t) wValue));
        break;

      default:
        return PH_ADD_COMPCODE(PH_ERR_UNSUPPORTED_PARAMETER, PH_COMP_AL_MFDF);
    }

    return PH_ADD_COMPCODE(PH_ERR_SUCCESS, PH_COMP_AL_MFDF);
  }

  phStatus_t phalMfdf_Sam_NonX_ResetAuthStatus(void *pDataParams) {
    phalMfdf_Sam_NonX_Int_ResetAuthStatus(pDataParams);

    return PH_ADD_COMPCODE(PH_ERR_SUCCESS, PH_COMP_AL_MFDF);
  }

#endif /* NXPBUILD__PHAL_MFDF_SAM_NONX */
