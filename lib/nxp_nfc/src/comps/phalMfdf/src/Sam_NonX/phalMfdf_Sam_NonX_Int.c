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
* Software MIFARE DESFire Application Component of Reader Library Framework.
* $Author: nxp60813 $
* $Revision: 124 $
* $Date: 2013-04-22 12:10:31 +0530 (Mon, 22 Apr 2013) $
*
* History:
*/

#include <nxp_nfc/ph_Status.h>
#include <nxp_nfc/phhalHw.h>
#include <nxp_nfc/phCryptoSym.h>
#include <nxp_nfc/phCryptoRng.h>
#include <nxp_nfc/phKeyStore.h>
#include <nxp_nfc/ph_RefDefs.h>
#include <string.h>
#include <nxp_nfc/ph_TypeDefs.h>

#ifdef NXPBUILD__PHAL_MFDF_SAM_NONX
#include "../phalMfdf_Int.h"
#include "phalMfdf_Sam_NonX_Int.h"

phStatus_t
phalMfdf_Sam_NonX_Int_SetAuthMode(void *pDataParams, uint8_t bAuthMode)
{
  switch (PH_GET_COMPID(pDataParams)) {
#ifdef NXPBUILD__PHAL_MFDF_SAMAV2_NONX
    case PHAL_MFDF_SAMAV2_ID:
      ((phalMfdf_SamAV2_DataParams_t *) pDataParams)->bAuthMode = bAuthMode;
      break;
#endif /* NXPBUILD__PHAL_MFDF_SAMAV2_NONX */

#ifdef NXPBUILD__PHAL_MFDF_SAMAV3_NONX
    case PHAL_MFDF_SAMAV3_NONX_ID:
      ((phalMfdf_SamAV3_NonX_DataParams_t *) pDataParams)->bAuthMode = bAuthMode;
      break;
#endif /* NXPBUILD__PHAL_MFDF_SAMAV3_NONX */

    default:
      PH_ADD_COMPCODE(PH_ERR_INVALID_DATA_PARAMS, PH_COMP_AL_MFDF);
  }

  return PH_ADD_COMPCODE(PH_ERR_SUCCESS, PH_COMP_AL_MFDF);
}
phStatus_t
phalMfdf_Sam_NonX_Int_GetAuthMode(void *pDataParams, uint8_t *pAuthMode)
{
  switch (PH_GET_COMPID(pDataParams)) {
#ifdef NXPBUILD__PHAL_MFDF_SAMAV2_NONX
    case PHAL_MFDF_SAMAV2_ID:
      *pAuthMode = ((phalMfdf_SamAV2_DataParams_t *) pDataParams)->bAuthMode;
      break;
#endif /* NXPBUILD__PHAL_MFDF_SAMAV2_NONX */

#ifdef NXPBUILD__PHAL_MFDF_SAMAV3_NONX
    case PHAL_MFDF_SAMAV3_NONX_ID:
      *pAuthMode = ((phalMfdf_SamAV3_NonX_DataParams_t *) pDataParams)->bAuthMode;
      break;
#endif /* NXPBUILD__PHAL_MFDF_SAMAV3_NONX */

    default:
      PH_ADD_COMPCODE(PH_ERR_INVALID_DATA_PARAMS, PH_COMP_AL_MFDF);
  }

  return PH_ADD_COMPCODE(PH_ERR_SUCCESS, PH_COMP_AL_MFDF);
}

phStatus_t
phalMfdf_Sam_NonX_Int_SetKeyNo(void *pDataParams, uint8_t bKeyNo)
{
  switch (PH_GET_COMPID(pDataParams)) {
#ifdef NXPBUILD__PHAL_MFDF_SAMAV2_NONX
    case PHAL_MFDF_SAMAV2_ID:
      ((phalMfdf_SamAV2_DataParams_t *) pDataParams)->bKeyNo = bKeyNo;
      break;
#endif /* NXPBUILD__PHAL_MFDF_SAMAV2_NONX */

#ifdef NXPBUILD__PHAL_MFDF_SAMAV3_NONX
    case PHAL_MFDF_SAMAV3_NONX_ID:
      ((phalMfdf_SamAV3_NonX_DataParams_t *) pDataParams)->bKeyNo = bKeyNo;
      break;
#endif /* NXPBUILD__PHAL_MFDF_SAMAV3_NONX */

    default:
      PH_ADD_COMPCODE(PH_ERR_INVALID_DATA_PARAMS, PH_COMP_AL_MFDF);
  }

  return PH_ADD_COMPCODE(PH_ERR_SUCCESS, PH_COMP_AL_MFDF);
}
phStatus_t
phalMfdf_Sam_NonX_Int_GetKeyNo(void *pDataParams, uint8_t *pKeyNo)
{
  switch (PH_GET_COMPID(pDataParams)) {
#ifdef NXPBUILD__PHAL_MFDF_SAMAV2_NONX
    case PHAL_MFDF_SAMAV2_ID:
      *pKeyNo = ((phalMfdf_SamAV2_DataParams_t *) pDataParams)->bKeyNo;
      break;
#endif /* NXPBUILD__PHAL_MFDF_SAMAV2_NONX */

#ifdef NXPBUILD__PHAL_MFDF_SAMAV3_NONX
    case PHAL_MFDF_SAMAV3_NONX_ID:
      *pKeyNo = ((phalMfdf_SamAV3_NonX_DataParams_t *) pDataParams)->bKeyNo;
      break;
#endif /* NXPBUILD__PHAL_MFDF_SAMAV3_NONX */

    default:
      PH_ADD_COMPCODE(PH_ERR_INVALID_DATA_PARAMS, PH_COMP_AL_MFDF);
  }

  return PH_ADD_COMPCODE(PH_ERR_SUCCESS, PH_COMP_AL_MFDF);
}

phStatus_t
phalMfdf_Sam_NonX_Int_SetWrappedMode(void *pDataParams, uint8_t bWrappedMode)
{
  switch (PH_GET_COMPID(pDataParams)) {
#ifdef NXPBUILD__PHAL_MFDF_SAMAV2_NONX
    case PHAL_MFDF_SAMAV2_ID:
      ((phalMfdf_SamAV2_DataParams_t *) pDataParams)->bWrappedMode = bWrappedMode;
      break;
#endif /* NXPBUILD__PHAL_MFDF_SAMAV2_NONX */

#ifdef NXPBUILD__PHAL_MFDF_SAMAV3_NONX
    case PHAL_MFDF_SAMAV3_NONX_ID:
      ((phalMfdf_SamAV3_NonX_DataParams_t *) pDataParams)->bWrappedMode = bWrappedMode;
      break;
#endif /* NXPBUILD__PHAL_MFDF_SAMAV3_NONX */

    default:
      PH_ADD_COMPCODE(PH_ERR_INVALID_DATA_PARAMS, PH_COMP_AL_MFDF);
  }

  return PH_ADD_COMPCODE(PH_ERR_SUCCESS, PH_COMP_AL_MFDF);
}
phStatus_t
phalMfdf_Sam_NonX_Int_GetWrappedMode(void *pDataParams, uint8_t *pWrappedMode)
{
  switch (PH_GET_COMPID(pDataParams)) {
#ifdef NXPBUILD__PHAL_MFDF_SAMAV2_NONX
    case PHAL_MFDF_SAMAV2_ID:
      *pWrappedMode = ((phalMfdf_SamAV2_DataParams_t *) pDataParams)->bWrappedMode;
      break;
#endif /* NXPBUILD__PHAL_MFDF_SAMAV2_NONX */

#ifdef NXPBUILD__PHAL_MFDF_SAMAV3_NONX
    case PHAL_MFDF_SAMAV3_NONX_ID:
      *pWrappedMode = ((phalMfdf_SamAV3_NonX_DataParams_t *) pDataParams)->bWrappedMode;
      break;
#endif /* NXPBUILD__PHAL_MFDF_SAMAV3_NONX */

    default:
      PH_ADD_COMPCODE(PH_ERR_INVALID_DATA_PARAMS, PH_COMP_AL_MFDF);
  }

  return PH_ADD_COMPCODE(PH_ERR_SUCCESS, PH_COMP_AL_MFDF);
}

phStatus_t
phalMfdf_Sam_NonX_Int_SetAdditionalInfo(void *pDataParams, uint16_t wAdditionalInfo)
{
  switch (PH_GET_COMPID(pDataParams)) {
#ifdef NXPBUILD__PHAL_MFDF_SAMAV2_NONX
    case PHAL_MFDF_SAMAV2_ID:
      ((phalMfdf_SamAV2_DataParams_t *) pDataParams)->wAdditionalInfo = wAdditionalInfo;
      break;
#endif /* NXPBUILD__PHAL_MFDF_SAMAV2_NONX */

#ifdef NXPBUILD__PHAL_MFDF_SAMAV3_NONX
    case PHAL_MFDF_SAMAV3_NONX_ID:
      ((phalMfdf_SamAV3_NonX_DataParams_t *) pDataParams)->wAdditionalInfo = wAdditionalInfo;
      break;
#endif /* NXPBUILD__PHAL_MFDF_SAMAV3_NONX */

    default:
      PH_ADD_COMPCODE(PH_ERR_INVALID_DATA_PARAMS, PH_COMP_AL_MFDF);
  }

  return PH_ADD_COMPCODE(PH_ERR_SUCCESS, PH_COMP_AL_MFDF);
}
phStatus_t
phalMfdf_Sam_NonX_Int_GetAdditionalInfo(void *pDataParams, uint16_t *pAdditionalInfo)
{
  switch (PH_GET_COMPID(pDataParams)) {
#ifdef NXPBUILD__PHAL_MFDF_SAMAV2_NONX
    case PHAL_MFDF_SAMAV2_ID:
      *pAdditionalInfo = ((phalMfdf_SamAV2_DataParams_t *) pDataParams)->wAdditionalInfo;
      break;
#endif /* NXPBUILD__PHAL_MFDF_SAMAV2_NONX */

#ifdef NXPBUILD__PHAL_MFDF_SAMAV3_NONX
    case PHAL_MFDF_SAMAV3_NONX_ID:
      *pAdditionalInfo = ((phalMfdf_SamAV3_NonX_DataParams_t *) pDataParams)->wAdditionalInfo;
      break;
#endif /* NXPBUILD__PHAL_MFDF_SAMAV3_NONX */

    default:
      PH_ADD_COMPCODE(PH_ERR_INVALID_DATA_PARAMS, PH_COMP_AL_MFDF);
  }

  return PH_ADD_COMPCODE(PH_ERR_SUCCESS, PH_COMP_AL_MFDF);
}

phStatus_t
phalMfdf_Sam_NonX_Int_SetAid(void *pDataParams, uint8_t *pAid)
{
  switch (PH_GET_COMPID(pDataParams)) {
#ifdef NXPBUILD__PHAL_MFDF_SAMAV2_NONX
    case PHAL_MFDF_SAMAV2_ID:
      memcpy(((phalMfdf_SamAV2_DataParams_t *) pDataParams)->pAid, pAid, 3);	/* PRQA S 3200 */
      break;
#endif /* NXPBUILD__PHAL_MFDF_SAMAV2_NONX */

#ifdef NXPBUILD__PHAL_MFDF_SAMAV3_NONX
    case PHAL_MFDF_SAMAV3_NONX_ID:
      memcpy(((phalMfdf_SamAV3_NonX_DataParams_t *) pDataParams)->pAid, pAid, 3);	/* PRQA S 3200 */
      break;
#endif /* NXPBUILD__PHAL_MFDF_SAMAV3_NONX */

    default:
      PH_ADD_COMPCODE(PH_ERR_INVALID_DATA_PARAMS, PH_COMP_AL_MFDF);
  }

  return PH_ADD_COMPCODE(PH_ERR_SUCCESS, PH_COMP_AL_MFDF);
}
phStatus_t
phalMfdf_Sam_NonX_Int_GetAid(void *pDataParams, uint8_t *pAid)
{
  switch (PH_GET_COMPID(pDataParams)) {
#ifdef NXPBUILD__PHAL_MFDF_SAMAV2_NONX
    case PHAL_MFDF_SAMAV2_ID:
      memcpy(pAid, ((phalMfdf_SamAV2_DataParams_t *) pDataParams)->pAid, 3);	/* PRQA S 3200 */
      break;
#endif /* NXPBUILD__PHAL_MFDF_SAMAV2_NONX */

#ifdef NXPBUILD__PHAL_MFDF_SAMAV3_NONX
    case PHAL_MFDF_SAMAV3_NONX_ID:
      memcpy(pAid, ((phalMfdf_SamAV3_NonX_DataParams_t *) pDataParams)->pAid, 3);	/* PRQA S 3200 */
      break;
#endif /* NXPBUILD__PHAL_MFDF_SAMAV3_NONX */

    default:
      PH_ADD_COMPCODE(PH_ERR_INVALID_DATA_PARAMS, PH_COMP_AL_MFDF);
  }

  return PH_ADD_COMPCODE(PH_ERR_SUCCESS, PH_COMP_AL_MFDF);
}

phStatus_t
phalMfdf_Sam_NonX_Int_ValidateResponse(void *pDataParams, uint16_t wStatus, uint16_t wPiccRetCode)
{
  /* Evaluate the response. */
  if ((wStatus == PH_ERR_SUCCESS) ||
      ((wStatus & PH_ERR_MASK) == (PH_ERR_CUSTOM_BEGIN + 23) /* DESFire General Errors */)) {
    /* Validate the PICC Status. */
    PH_CHECK_SUCCESS_FCT(wStatus, phalMfdf_Int_ComputeErrorResponse(pDataParams,
            (uint16_t)(wPiccRetCode & 0x00FF)));
  } else {
    if ((wStatus & PH_ERR_MASK) == PH_ERR_SUCCESS_CHAINING) {
      wStatus = PH_ADD_COMPCODE(PH_ERR_SUCCESS_CHAINING, PH_COMP_AL_MFDF);
    }

    PH_CHECK_SUCCESS(wStatus);
  }

  return PH_ADD_COMPCODE(PH_ERR_SUCCESS, PH_COMP_AL_MFDF);
}

phStatus_t
phalMfdf_Sam_NonX_Int_CardExchange(void *pDataParams, uint16_t wBufferOption, uint8_t bCmdOption,
    uint16_t wTotDataLen, uint8_t bExchangeLE, uint8_t *pData,
    uint16_t wDataLen, uint8_t **ppResponse, uint16_t *pRespLen, uint8_t *pPiccErrCode)
{
  phStatus_t		PH_MEMLOC_REM wStatus = 0;
  uint8_t			PH_MEMLOC_REM bWrappedMode = 0;
  phStatus_t		PH_MEMLOC_REM wPICCStatus = 0;
  uint8_t			PH_MEMLOC_REM bPICCStatLen = 0;
  uint16_t		PH_MEMLOC_REM wLc = 0;
  uint16_t		PH_MEMLOC_REM wRespLen = 0;
  uint8_t		*PH_MEMLOC_REM pResponse = NULL;

  uint8_t			PH_MEMLOC_REM aLc[3] = {0x00, 0x00, 0x00};
  uint8_t			PH_MEMLOC_REM aLe[3] = {0x00, 0x00, 0x00};
  uint8_t			PH_MEMLOC_REM bLcLen = 0;
  uint8_t			PH_MEMLOC_REM aISO7816Header[8] = {PHAL_MFDF_WRAPPEDAPDU_CLA, 0x00, PHAL_MFDF_WRAPPEDAPDU_P1, PHAL_MFDF_WRAPPEDAPDU_P2};
  uint8_t			PH_MEMLOC_REM bISO7816HeaderLen = 4;
  static uint8_t	PH_MEMLOC_REM bLeLen;

  /* Exchange the command in Iso7816 wrapped formmat. ----------------------------------------------------------------- */
  PH_CHECK_SUCCESS_FCT(wStatus, phalMfdf_Sam_NonX_Int_GetWrappedMode(pDataParams, &bWrappedMode));
  if (bWrappedMode) {
    if ((wBufferOption == PH_EXCHANGE_BUFFER_FIRST) || (wBufferOption == PH_EXCHANGE_DEFAULT)) {
      bLeLen = 1;

      /* Set the LC information. */
      wLc = (uint16_t)(wTotDataLen - 1 /* Excluding the command code. */);

      /* Update the command code to Iso7816 header */
      aISO7816Header[1] = pData[0];

      /* Add the ISO 7816 header to layer 4 buffer. */
      PH_CHECK_SUCCESS_FCT(wStatus, PHPAL_MIFARE_EXCHANGE_L4(
              pDataParams,
              PH_EXCHANGE_BUFFER_FIRST,
              &aISO7816Header[0],
              bISO7816HeaderLen,
              NULL,
              NULL));

      /* Add Lc if available */
      if (wLc) {
        /* Update Lc bytes according to Extended APDU option. */
        aLc[bLcLen++] = (uint8_t)(wLc & 0x00FF);

        /* Add the Lc to layer 4 buffer. */
        PH_CHECK_SUCCESS_FCT(wStatus, PHPAL_MIFARE_EXCHANGE_L4(
                pDataParams,
                PH_EXCHANGE_BUFFER_CONT,
                &aLc[0],
                bLcLen,
                NULL,
                NULL));

        /* Add the data to layer 4 buffer. */
        PH_CHECK_SUCCESS_FCT(wStatus, PHPAL_MIFARE_EXCHANGE_L4(
                pDataParams,
                PH_EXCHANGE_BUFFER_CONT,
                &pData[1],	/* Exclude the command code because it is added to INS. */
                (uint16_t)(wDataLen - 1),
                NULL,
                NULL));
      } else {

      }
    }

    if (wBufferOption == PH_EXCHANGE_BUFFER_CONT) {
      /* Add the data to layer 4 buffer. */
      PH_CHECK_SUCCESS_FCT(wStatus, PHPAL_MIFARE_EXCHANGE_L4(
              pDataParams,
              PH_EXCHANGE_BUFFER_CONT,
              pData,
              wDataLen,
              NULL,
              NULL));
    }

    if ((wBufferOption == PH_EXCHANGE_BUFFER_LAST) || (wBufferOption == PH_EXCHANGE_DEFAULT)) {
      if (wBufferOption == PH_EXCHANGE_BUFFER_LAST) {
        /* Add the data to layer 4 buffer. */
        PH_CHECK_SUCCESS_FCT(wStatus, PHPAL_MIFARE_EXCHANGE_L4(
                pDataParams,
                PH_EXCHANGE_BUFFER_CONT,
                pData,
                wDataLen,
                NULL,
                NULL));
      }

      /* Add Le to L4 buffer and exchange the command. */
      PH_CHECK_SUCCESS_FCT(wStatus, PHPAL_MIFARE_EXCHANGE_L4(
              pDataParams,
              PH_EXCHANGE_BUFFER_LAST,
              &aLe[0],
              (uint8_t)(bExchangeLE ?  bLeLen : 0),
              &pResponse,
              &wRespLen));

      /* Combine Sw1 and Sw2 status codes. */
      wPICCStatus = (uint16_t)((pResponse[wRespLen - 2] << 8) | pResponse[wRespLen - 1]);

      /* Evaluate the response. */
      wStatus = phalMfdf_Sam_NonX_Int_ValidateResponse(pDataParams, wStatus, wPICCStatus);

      /* Create memory for updating the response of ISO 14443 format. */
      *ppResponse = pResponse;

      /* Update the response buffer length excluding SW1SW2. */
      *pRespLen = wRespLen - 2;

      /* Copy the second byte of response (SW2) to RxBuffer */
      *pPiccErrCode = pResponse[wRespLen - 1];
    }

    if (wBufferOption == PH_EXCHANGE_RXCHAINING) {
      /* Exchange the command */
      PH_CHECK_SUCCESS_FCT(wStatus, PHPAL_MIFARE_EXCHANGE_L4(
              pDataParams,
              wBufferOption,
              pData,
              wDataLen,
              &pResponse,
              &wRespLen));

      if (wRespLen != 0) {
        /* Combine Sw1 and Sw2 status codes. */
        wPICCStatus = (uint16_t)((pResponse[wRespLen - 2] << 8) | pResponse[wRespLen - 1]);

        /* Evaluate the response. */
        wStatus = phalMfdf_Sam_NonX_Int_ValidateResponse(pDataParams, wStatus, wPICCStatus);

        /* Create memory for updating the response of ISO 14443 format. */
        *ppResponse = pResponse;

        /* Update the response buffer length excluding SW1SW2. */
        *pRespLen = wRespLen - 2;

        /* Copy the second byte of response (SW2) to RxBuffer */
        *pPiccErrCode = pResponse[wRespLen - 1];
      }
    }
  }

  /* Exchange the command in Native formmat. -------------------------------------------------------------------------- */
  else {
    /* Exchange the data to the card in Native format. */
    PH_CHECK_SUCCESS_FCT(wStatus, PHPAL_MIFARE_EXCHANGE_L4(
            pDataParams,
            wBufferOption,
            pData,
            wDataLen,
            &pResponse,
            &wRespLen));

    /* Verify the received data and update the response buffer with received data. */
    if ((bCmdOption & PHALMFDF_SAM_NONX_CMD_OPTION_PENDING) ||
        (bCmdOption & PHALMFDF_SAM_NONX_CMD_OPTION_COMPLETE)) {
      if (bCmdOption & PHALMFDF_SAM_NONX_PICC_STATUS_WRAPPED) {
        /* Combine Sw1 and Sw2 status codes. */
        wPICCStatus = (uint16_t)((pResponse[wRespLen - 2] << 8) | pResponse[wRespLen - 1]);
        bPICCStatLen = 2;
      } else {
        wPICCStatus = pResponse[0];
        bPICCStatLen = 1;
      }

      /* Evaluate the response. */
      wStatus = phalMfdf_Int_ComputeErrorResponse(pDataParams, wPICCStatus);

      /* Add the status code. */
      *pPiccErrCode = pResponse[(bCmdOption & PHALMFDF_SAM_NONX_PICC_STATUS_WRAPPED) ?
                                                                   (wRespLen - 1) : 0];

      /* Update the response buffer length excluding CHAINING(0xAF). */
      *pRespLen = wRespLen - bPICCStatLen;

      /* Add the Response data excluding the status code. */
      *ppResponse = &pResponse[(bCmdOption & PHALMFDF_SAM_NONX_PICC_STATUS_WRAPPED) ? 0 : 1];
    }
  }

  return wStatus;
}

phStatus_t
phalMfdf_Sam_NonX_Int_AuthenticatePICC(void *pDataParams, uint8_t bAuthType, uint16_t wOption,
    uint16_t wKeyNo, uint16_t wKeyVer, uint8_t bKeyNoCard,
    uint8_t *pDivInput, uint8_t bDivInputLen)
{
  phStatus_t	PH_MEMLOC_REM wStatus = 0;
  phStatus_t	PH_MEMLOC_REM wStatus1 = 0;
  uint8_t     PH_MEMLOC_REM bAuthMode = 0;
  uint16_t	PH_MEMLOC_REM wCmdLen = 0;
  uint8_t 	*PH_MEMLOC_REM pCardResponse = NULL;
  uint16_t	PH_MEMLOC_REM wCardRespLen = 0;
  uint8_t		PH_MEMLOC_REM aSamResponse[32];
  uint8_t	*PH_MEMLOC_REM pSamResponse = NULL;
  uint16_t	PH_MEMLOC_REM wSamRespLen = 0;
  uint8_t		PH_MEMLOC_REM bPiccErrCode = 0;
  uint8_t		PH_MEMLOC_REM aCmdBuff[34];

  /* Check for valid card key number. */
  if ((bKeyNoCard & 0x0F) > 0x0D) {
    return PH_ADD_COMPCODE(PH_ERR_INVALID_PARAMETER, PH_COMP_AL_MFDF);
  }

  /* Check for valid SAM keystore number and version. */
  if ((wKeyNo > 0x7f) || (wKeyVer > 0xff)) {
    return PH_ADD_COMPCODE(PH_ERR_INVALID_PARAMETER, PH_COMP_AL_MFDF);
  }

  /* Change for valid diversification options. */
  if ((wOption != PHAL_MFDF_NO_DIVERSIFICATION) &&
      (wOption != (PH_CRYPTOSYM_DIV_MODE_DESFIRE | PH_CRYPTOSYM_DIV_OPTION_2K3DES_HALF)) &&
      (wOption != (PH_CRYPTOSYM_DIV_MODE_DESFIRE | PH_CRYPTOSYM_DIV_OPTION_2K3DES_FULL)) &&
      (wOption != PH_CRYPTOSYM_DIV_MODE_MIFARE_PLUS)) {
    return PH_ADD_COMPCODE(PH_ERR_INVALID_PARAMETER, PH_COMP_AL_MFDF);
  }

  /* Validate diversification input length. */
  if ((wOption != PHAL_MFDF_NO_DIVERSIFICATION) && ((bDivInputLen > 31) || (bDivInputLen == 0))) {
    return PH_ADD_COMPCODE(PH_ERR_INVALID_PARAMETER, PH_COMP_AL_MFDF);
  }

  /* Reset the Authentication state. */
  PH_CHECK_SUCCESS_FCT(wStatus, phalMfdf_Sam_NonX_Int_SetAuthMode(pDataParams,
          PHAL_MFDF_NOT_AUTHENTICATED));
  PH_CHECK_SUCCESS_FCT(wStatus, phalMfdf_Sam_NonX_Int_SetKeyNo(pDataParams, 0xFF));

  /* Clear the command buffer and length. */
  wCmdLen = 0;
  memset(aCmdBuff, 0x00, sizeof(aCmdBuff));	/* PRQA S 3200 */

  /* Frame the command buffer to be exchanged with PICC---------------------------------------------------------------------------------- */

  /* Add the Auth code to Command Buffer . */
  aCmdBuff[wCmdLen++] = bAuthType;
  aCmdBuff[wCmdLen++] = bKeyNoCard;

  /* Exchange the command with the card. */
  wStatus = phalMfdf_Sam_NonX_Int_CardExchange(
          pDataParams,
          PH_EXCHANGE_DEFAULT,
          PHALMFDF_SAM_NONX_CMD_OPTION_PENDING,
          wCmdLen,
          PH_ON,
          aCmdBuff,
          wCmdLen,
          &pCardResponse,
          &wCardRespLen,
          &bPiccErrCode);

  /* Validate the response for chaining. */
  if ((wStatus & PH_ERR_MASK) != PH_ERR_SUCCESS_CHAINING) {
    return wStatus;
  }

  /* First part of Exchange with Sam hardware. ------------------------------------------------------------------------------------------- */

  /* Set Auth mode with diversification enabled. */
  bAuthMode |= (uint8_t)((wOption != PHAL_MFDF_NO_DIVERSIFICATION) ? 0x01 : 0x00);

  /* Set Diversification flags.
   * For AV1 compatibility mode key diversification methods, TDEA Key, diversified using one encryption round
   */
  if (wOption == PH_CRYPTOSYM_DIV_OPTION_2K3DES_HALF) {
    bAuthMode |= (uint8_t) 0x08;
  }

  /* Set Diversification flags.
   * AV2 compatibility mode key diversification methods, 3TDEA, AES key
   */
  if (wOption == PH_CRYPTOSYM_DIV_MODE_MIFARE_PLUS) {
    bAuthMode |= (uint8_t) 0x10;
  }

  /* Set the pointer. */
  pSamResponse = aSamResponse;
  wStatus1 = PHHAL_HW_CMD_SAM_AUTHENTICATE_PART1(
          pDataParams,
          bAuthMode,
          (uint8_t) wKeyNo,
          (uint8_t) wKeyVer,
          pDivInput,
          bDivInputLen,
          pCardResponse,
          (uint8_t) wCardRespLen,
          pSamResponse,
          wSamRespLen);

  /* Check for the Chaining active */
  if ((wStatus1 & PH_ERR_MASK) != PH_ERR_SUCCESS_CHAINING) {
    return wStatus1;
  }

  /* Second part of Exchange with card. -------------------------------------------------------------------------------------------------- */
  wCmdLen = 0;
  bPiccErrCode = 0;
  memset(aCmdBuff, 0x00, sizeof(aCmdBuff));	/* PRQA S 3200 */

  /* Frame the command for Exchange to card. */
  aCmdBuff[wCmdLen++] = PHAL_MFDF_CMD_CHAINING;

  /* Copy the response received from SAM to Command buffer. */
  memcpy(&aCmdBuff[wCmdLen], pSamResponse, wSamRespLen);	/* PRQA S 3200 */
  wCmdLen += wSamRespLen;

  /* Exchange the command with the card. */
  wStatus = phalMfdf_Sam_NonX_Int_CardExchange(
          pDataParams,
          PH_EXCHANGE_DEFAULT,
          PHALMFDF_SAM_NONX_CMD_OPTION_COMPLETE,
          wCmdLen,
          PH_ON,
          aCmdBuff,
          wCmdLen,
          &pCardResponse,
          &wCardRespLen,
          &bPiccErrCode);

  /* Second part of Exchange with Sam hardware. ----------------------------------------------------------------- */

  if (wStatus == PH_ERR_SUCCESS) {
    PH_CHECK_SUCCESS_FCT(wStatus1, PHHAL_HW_CMD_SAM_AUTHENTICATE_PART2(
            pDataParams,
            bPiccErrCode,
            pCardResponse,
            (uint8_t) wCardRespLen,
            &bPiccErrCode));
  } else {
    /* Reset the Authentication. */
    wStatus1 = phalMfdf_Sam_NonX_Int_ResetAuthStatus(pDataParams);
  }

  return wStatus;
}

phStatus_t
phalMfdf_Sam_NonX_Int_ChangeKeyPICC(void *pDataParams, uint16_t wOption, uint8_t bKeyNoCard,
    uint16_t wCurrKeyNo, uint16_t wCurrKeyVer, uint16_t wNewKeyNo,
    uint16_t wNewKeyVer, uint8_t *pDivInput, uint8_t bDivInputLen)
{
  phStatus_t	PH_MEMLOC_REM wStatus = 0;
  phStatus_t	PH_MEMLOC_REM wStatus1 = 0;
  uint8_t     PH_MEMLOC_REM bKeyCompMeth = 0;
  uint8_t     PH_MEMLOC_REM bCfg = 0;
  uint8_t		PH_MEMLOC_REM aCmdBuff[43];
  uint16_t	PH_MEMLOC_REM wCmdLen = 0;
  uint8_t 	*PH_MEMLOC_REM pCardResponse = NULL;
  uint16_t	PH_MEMLOC_REM wCardRespLen = 0;
  uint8_t 	PH_MEMLOC_REM aSamResponse[40];
  uint8_t 	*PH_MEMLOC_REM pSamResponse = NULL;
  uint16_t	PH_MEMLOC_REM wSamRespLen = 0;
  uint8_t		PH_MEMLOC_REM bPiccErrCode = 0;
  uint8_t		PH_MEMLOC_REM aAppId_Act[3] = { 0x00, 0x00, 0x00 };
  uint8_t		PH_MEMLOC_REM aAppId_Exp[3] = {0x00, 0x00, 0x00};
  uint8_t     PH_MEMLOC_REM bAuthMode = 0;
  uint8_t     PH_MEMLOC_REM bKeyNo = 0;

  /* Only if seleted Aid is 0x000000. */
  PH_CHECK_SUCCESS_FCT(wStatus, phalMfdf_Sam_NonX_Int_GetAid(pDataParams, aAppId_Act));
  if ((memcmp(aAppId_Exp, aAppId_Act, 3) == 0) && ((bKeyNoCard & 0x3FU) == 0x00)) {
    /* Only if seleted Aid is 0x000000, and card key number is X0, then
         * it is likely to be the PICC master key that has to be changed.
     */
    if ((bKeyNoCard != 0x80) && (bKeyNoCard != 0x40) && (bKeyNoCard != 0x00)) {
      /* Invalid card key number supplied */
      return PH_ADD_COMPCODE(PH_ERR_INVALID_PARAMETER, PH_COMP_AL_MFDF);
    }
  } else {
    if (bKeyNoCard > 0x0D) {
      /* Invalid application key specified */
      return PH_ADD_COMPCODE(PH_ERR_INVALID_PARAMETER, PH_COMP_AL_MFDF);
    }
  }

  /* Check for valid SAM key number and version. */
  if ((wCurrKeyNo > 0x7f) || (wCurrKeyVer > 0xff) || (wNewKeyNo > 0x7f) || (wNewKeyVer > 0xff)) {
    return PH_ADD_COMPCODE(PH_ERR_INVALID_PARAMETER, PH_COMP_AL_MFDF);
  }

  /* Check for diversification options. */
  if ((wOption != PHAL_MFDF_NO_DIVERSIFICATION) && (wOption != PHAL_MFDF_CHGKEY_DIV_NEW_KEY) &&
      (wOption != PHAL_MFDF_CHGKEY_DIV_OLD_KEY) &&
      (wOption != (PHAL_MFDF_CHGKEY_DIV_NEW_KEY | PHAL_MFDF_CHGKEY_DIV_METHOD_CMAC)) &&
      (wOption != (PHAL_MFDF_CHGKEY_DIV_NEW_KEY | PHAL_MFDF_CHGKEY_DIV_NEW_KEY_ONERND)) &&
      (wOption != (PHAL_MFDF_CHGKEY_DIV_OLD_KEY | PHAL_MFDF_CHGKEY_DIV_METHOD_CMAC)) &&
      (wOption != (PHAL_MFDF_CHGKEY_DIV_OLD_KEY | PHAL_MFDF_CHGKEY_DIV_OLD_KEY_ONERND)) &&
      (wOption != (PHAL_MFDF_CHGKEY_DIV_OLD_KEY | PHAL_MFDF_CHGKEY_DIV_OLD_KEY_ONERND |
              PHAL_MFDF_CHGKEY_DIV_NEW_KEY)) &&
      (wOption != (PHAL_MFDF_CHGKEY_DIV_NEW_KEY | PHAL_MFDF_CHGKEY_DIV_OLD_KEY |
              PHAL_MFDF_CHGKEY_DIV_METHOD_CMAC)) &&
      (wOption != (PHAL_MFDF_CHGKEY_DIV_NEW_KEY | PHAL_MFDF_CHGKEY_DIV_OLD_KEY |
              PHAL_MFDF_CHGKEY_DIV_NEW_KEY_ONERND | PHAL_MFDF_CHGKEY_DIV_OLD_KEY_ONERND))) {
    return PH_ADD_COMPCODE(PH_ERR_INVALID_PARAMETER, PH_COMP_AL_MFDF);
  }

  /* Get the data params info. */
  PH_CHECK_SUCCESS_FCT(wStatus1, phalMfdf_Sam_NonX_Int_GetAuthMode(pDataParams, &bAuthMode));
  PH_CHECK_SUCCESS_FCT(wStatus1, phalMfdf_Sam_NonX_Int_GetKeyNo(pDataParams, &bKeyNo));

  /* Command Exchange with SAM. ---------------------------------------------------------------------------------------------------------- */
  /* Set the key compilation method. */
  if (wOption == PHAL_MFDF_NO_DIVERSIFICATION) {
    bKeyCompMeth = 0x00;
  } else {
    /* Validate diversification input length. */
    if (bDivInputLen > 31) {
      return PH_ADD_COMPCODE(PH_ERR_INVALID_PARAMETER, PH_COMP_AL_MFDF);
    }

    /* Assin the option to local variable. */
    bKeyCompMeth = (uint8_t) wOption;
  }

  /* Desfire key number to be changed. */
  bCfg = (uint8_t)(0x0f & bKeyNoCard);

  /* Set if PICC targeted key equal to PICC authenticated key. */
  if ((bKeyNoCard & 0x3f) == 0) {
    bKeyCompMeth = (uint8_t)(bKeyCompMeth | 0x01);
  }

  /* Include the key type in the cryptogram for Master Key */
  if (memcmp(aAppId_Exp, aAppId_Act, 3) == 0) {
    bCfg = (uint8_t)(bCfg | 0x10);
  }

  pSamResponse = aSamResponse;
  PH_CHECK_SUCCESS_FCT(wStatus, PHHAL_HW_CMD_SAM_CHANGE_KEY(
          pDataParams,
          bKeyCompMeth,
          bCfg,
          (uint8_t) wCurrKeyNo,
          (uint8_t) wCurrKeyVer,
          (uint8_t) wNewKeyNo,
          (uint8_t) wNewKeyVer,
          pDivInput,
          bDivInputLen,
          pSamResponse,
          wSamRespLen));

  /* Command Exchange with Card. -------------------------------------------------------------------------------- */
  wCmdLen = 0;
  memset(aCmdBuff, 0x00, sizeof(aCmdBuff));	/* PRQA S 3200 */

  /* Frame the command information with command type. */
  aCmdBuff[wCmdLen++] = PHAL_MFDF_CMD_CHANGE_KEY;

  /* Add CardKey number to command buffer. */
  aCmdBuff[wCmdLen++] = bKeyNoCard;

  /* Copy the response received from SAM to Command buffer. */
  memcpy(&aCmdBuff[wCmdLen], pSamResponse, wSamRespLen);	/* PRQA S 3200 */
  wCmdLen += wSamRespLen;

  /* Exchange the command with the card. */
  wStatus = phalMfdf_Sam_NonX_Int_CardExchange(
          pDataParams,
          PH_EXCHANGE_DEFAULT,
          PHALMFDF_SAM_NONX_CMD_OPTION_COMPLETE,
          wCmdLen,
          PH_ON,
          aCmdBuff,
          wCmdLen,
          &pCardResponse,
          &wCardRespLen,
          &bPiccErrCode);

  /* Evaluate the response. */
  wStatus = phalMfdf_Sam_NonX_Int_ValidateResponse(pDataParams, wStatus, bPiccErrCode);

  /* Reset the Auth state. */
  if (wStatus != PH_ERR_SUCCESS) {
    if (bAuthMode != PHAL_MFDF_AUTHENTICATE) {
      PH_CHECK_SUCCESS_FCT(wStatus1, phalMfdf_Sam_NonX_Int_ResetAuthStatus(pDataParams));
    }

    return wStatus;
  } else {
    /* Verify the MAC. */
    if (wCardRespLen) {
      PH_CHECK_SUCCESS_FCT(wStatus, phalMfdf_Sam_NonX_Int_VerifySM(
              pDataParams,
              (uint16_t)(PH_EXCHANGE_DEFAULT | PHALMFDF_SAM_NONX_EXCHANGE_PICC_STATUS),
              PHAL_MFDF_COMMUNICATION_MACD,
              0,
              NULL,
              0,
              bPiccErrCode,
              pCardResponse,
              wCardRespLen,
              &pSamResponse,
              &wSamRespLen));
    }

    /* Reset authentication status only if the key authenticated with is changed. */
    if (bKeyNo == (bKeyNoCard & 0x3FU)) {
      PH_CHECK_SUCCESS_FCT(wStatus1, phalMfdf_Sam_NonX_Int_ResetAuthStatus(pDataParams));
    }
  }

  return PH_ADD_COMPCODE(PH_ERR_SUCCESS, PH_COMP_AL_MFDF);
}

phStatus_t
phalMfdf_Sam_NonX_Int_GenerateSM(void *pDataParams, uint16_t wOption, uint8_t bIsWriteCmd,
    uint8_t bIsReadCmd, uint8_t bCommMode, uint8_t *pCmdBuff,
    uint16_t wCmdLen, uint8_t *pData, uint16_t wDataLen, uint8_t **ppOutBuffer, uint16_t *pOutBufLen)
{
  phStatus_t	PH_MEMLOC_REM wStatus = 0;
  uint16_t	PH_MEMLOC_REM wBuffOption = 0;
  uint8_t     PH_MEMLOC_REM bAuthMode = 0;

  /* Get the data params info. */
  PH_CHECK_SUCCESS_FCT(wStatus, phalMfdf_Sam_NonX_Int_GetAuthMode(pDataParams, &bAuthMode));

  /* Exchange the information to Sam hardware to get the MAC information.
   * This computed MAC might not be exchanged. This is computed to initial crypto informationin SAM which will be used for MAC verification.
   */
  if (bAuthMode != PHAL_MFDF_NOT_AUTHENTICATED) {
    /* Encipher the data. */
    if (bCommMode == PHAL_MFDF_COMMUNICATION_ENC) {
      if (!bIsReadCmd) {
        /* Set the buffering flag to Default. */
        wBuffOption = PH_EXCHANGE_DEFAULT;

        /* Set the buffering flag to Default. */
        wBuffOption = (uint16_t)((bAuthMode != PHAL_MFDF_AUTHENTICATE) ? PH_EXCHANGE_BUFFER_FIRST :
                PH_EXCHANGE_DEFAULT);
        wBuffOption |= (uint16_t)(((wOption & 0xFF0F) == PH_EXCHANGE_DEFAULT) ? wBuffOption :
                PH_EXCHANGE_TXCHAINING);

        /* If authmode is 0x0A, CRC is needed only on the data */
        if (bAuthMode != PHAL_MFDF_AUTHENTICATE) {
          /* Buffer Cmd + Params information to SAM buffer. */
          PH_CHECK_SUCCESS_FCT(wStatus, PHHAL_HW_CMD_SAM_ENCIPHER_DATA(
                  pDataParams,
                  wBuffOption,
                  pCmdBuff,
                  (uint8_t) wCmdLen,
                  (uint8_t) wCmdLen,
                  ppOutBuffer,
                  pOutBufLen));

          /* Update the Bufferring flag. */
          wBuffOption = PH_EXCHANGE_BUFFER_LAST;
        }

        PH_CHECK_SUCCESS_FCT(wStatus, PHHAL_HW_CMD_SAM_ENCIPHER_DATA(
                pDataParams,
                wBuffOption,
                pData,
                (uint8_t) wDataLen,
                0x00,
                ppOutBuffer,
                pOutBufLen));
      }
    } else {
      /* Generate the MAC for AES and DES3K3 key types only. */
      if (bIsWriteCmd || (bAuthMode != PHAL_MFDF_AUTHENTICATE)) {
        /* Set the buffering flag to Default. */
        wBuffOption = (uint16_t)((bAuthMode != PHAL_MFDF_AUTHENTICATE) ? PH_EXCHANGE_BUFFER_FIRST :
                PH_EXCHANGE_DEFAULT);
        wBuffOption |= (uint16_t)(((wOption & 0xFF0F) == PH_EXCHANGE_DEFAULT) ? wBuffOption :
                PH_EXCHANGE_TXCHAINING);

#ifdef NXPBUILD__PHAL_MFDF_SAMAV3_NONX
        if (PH_GET_COMPID(pDataParams) == PHAL_MFDF_SAMAV3_NONX_ID) {
          wBuffOption |= PHHAL_HW_SAMAV3_GENERATE_MAC_INCLUDE_LC;
        }
#endif /* NXPBUILD__PHAL_MFDF_SAMAV3_NONX */

        /* Buffer command information. */
        if (bAuthMode != PHAL_MFDF_AUTHENTICATE) {
          PH_CHECK_SUCCESS_FCT(wStatus, PHHAL_HW_CMD_SAM_GENERATE_MAC(
                  pDataParams,
                  wBuffOption,
                  0x00, /* Mac based on the Keytype. */
                  pCmdBuff,
                  (uint8_t)((pCmdBuff[0] != 0xAF) ? wCmdLen : 0),
                  ppOutBuffer,
                  pOutBufLen));

          /* Add TxChaining for chainned frame. */
#ifdef NXPBUILD__PHAL_MFDF_SAMAV2_NONX
          if ((PH_GET_COMPID(pDataParams) == PHAL_MFDF_SAMAV2_ID) &&
              (wBuffOption & PH_EXCHANGE_TXCHAINING)) {
            wBuffOption = (uint16_t)(PH_EXCHANGE_TXCHAINING | PH_EXCHANGE_BUFFER_LAST);
          } else {
            /* Update the Bufferring flag. */
            wBuffOption = PH_EXCHANGE_BUFFER_LAST;
          }

#else
          wBuffOption = PH_EXCHANGE_BUFFER_LAST;
#endif /* NXPBUILD__PHAL_MFDF_SAMAV2_NONX */
        }

        /* Buffer command information. */
        PH_CHECK_SUCCESS_FCT(wStatus, PHHAL_HW_CMD_SAM_GENERATE_MAC(
                pDataParams,
                wBuffOption,
                0x00, /* Mac based on the Keytype. */
                pData,
                (uint8_t) wDataLen,
                ppOutBuffer,
                pOutBufLen));
      }
    }
  }

  return PH_ADD_COMPCODE(PH_ERR_SUCCESS, PH_COMP_AL_MFDF);
}

phStatus_t
phalMfdf_Sam_NonX_Int_VerifySM(void *pDataParams, uint16_t wOption, uint8_t bCommMode,
    uint32_t dwLength, uint8_t *pResponse, uint16_t wRespLen,
    uint8_t bPiccStat, uint8_t *pRespMac, uint16_t wRespMacLen, uint8_t **ppOutBuffer,
    uint16_t *pOutBufLen)
{
  phStatus_t	PH_MEMLOC_REM wStatus = 0;
  uint8_t		PH_MEMLOC_REM bExchangeStatus = 0;
  uint16_t	PH_MEMLOC_REM wBuffOption = 0;
  uint8_t		PH_MEMLOC_REM aLength[3];
  uint8_t     PH_MEMLOC_REM bAuthMode = 0;

  /* Get the data params info. */
  PH_CHECK_SUCCESS_FCT(wStatus, phalMfdf_Sam_NonX_Int_GetAuthMode(pDataParams, &bAuthMode));

  /* Exchange the information to Sam hardware to get the MAC information. */
  if (bAuthMode != PHAL_MFDF_NOT_AUTHENTICATED) {
    /* Decipher the data. */
    if (bCommMode == PHAL_MFDF_COMMUNICATION_ENC) {
      /* Set the buffering flag to Default. */
      wBuffOption = PH_EXCHANGE_BUFFER_FIRST;
      wBuffOption |= (uint16_t)(((wOption & 0xFF0F) == PH_EXCHANGE_DEFAULT) ? wBuffOption :
              PH_EXCHANGE_TXCHAINING);

      /* Set whether to exchange Status or not. */
      bExchangeStatus = (uint8_t)(bAuthMode != PHAL_MFDF_AUTHENTICATE ? PH_ON : PH_OFF);
      bExchangeStatus = (uint8_t)(((wOption & PH_EXCHANGE_CUSTOM_BITS_MASK) !=
                  PHALMFDF_SAM_NONX_EXCHANGE_PICC_STATUS) ? PH_OFF : bExchangeStatus);

      /* Set the Length to be exchagned. */
      if ((bCommMode == PHAL_MFDF_COMMUNICATION_ENC) && (dwLength != 0)) {
        aLength[0] = (uint8_t) dwLength;
        aLength[1] = (uint8_t)(dwLength >> 8);
        aLength[2] = (uint8_t)(dwLength >> 16);

#ifdef NXPBUILD__PHAL_MFDF_SAMAV2_NONX
        if (PH_GET_COMPID(pDataParams) == PHAL_MFDF_SAMAV2_ID) {
          wBuffOption |= PHHAL_HW_SAMAV2_CMD_DECIPHERDATA_OPTION_WITHLENGTH;
        } else {
#ifdef NXPBUILD__PHAL_MFDF_SAMAV3_NONX
          wBuffOption |= PHHAL_HW_SAMAV3_DECIPHER_LENGTH_INCLUDE;
#endif /* NXPBUILD__PHAL_MFDF_SAMAV3_NONX */
        }
#else
#ifdef NXPBUILD__PHAL_MFDF_SAMAV3_NONX
        wBuffOption |= PHHAL_HW_SAMAV3_DECIPHER_LENGTH_INCLUDE;
#endif /* NXPBUILD__PHAL_MFDF_SAMAV3_NONX */
#endif
      }

      /* Buffer initial set of response. */
      PH_CHECK_SUCCESS_FCT(wStatus, PHHAL_HW_CMD_SAM_DECIPHER_DATA(
              pDataParams,
              wBuffOption,
              pResponse,
              (uint8_t) wRespLen,
              aLength,
              ppOutBuffer,
              pOutBufLen));

      /* Buffer the final set of response. */
      PH_CHECK_SUCCESS_FCT(wStatus, PHHAL_HW_CMD_SAM_DECIPHER_DATA(
              pDataParams,
              PH_EXCHANGE_BUFFER_CONT,
              pRespMac,
              (uint8_t) wRespMacLen,
              0,
              ppOutBuffer,
              pOutBufLen));

      /* Buffer Status information. */
      PH_CHECK_SUCCESS_FCT(wStatus, PHHAL_HW_CMD_SAM_DECIPHER_DATA(
              pDataParams,
              PH_EXCHANGE_BUFFER_LAST,
              &bPiccStat,
              (uint8_t)(bExchangeStatus ? 1 : 0),
              0,
              ppOutBuffer,
              pOutBufLen));
    } else {
      if (bAuthMode != PHAL_MFDF_AUTHENTICATE) {
        /* Set the buffering flag to Default. */
        wBuffOption = PH_EXCHANGE_BUFFER_FIRST;
        wBuffOption |= (uint16_t)(((wOption & 0xFF0F) == PH_EXCHANGE_DEFAULT) ? wBuffOption :
                PH_EXCHANGE_TXCHAINING);

        /* Buffer the Plain response information to Sam buffer. */
        PH_CHECK_SUCCESS_FCT(wStatus, PHHAL_HW_CMD_SAM_VERIFY_MAC(
                pDataParams,
                wBuffOption,
                0x00, /* Mac based on the Keytype. */
                pResponse,
                (uint8_t) wRespLen));

        /* Buffer the PICC status information to Sam buffer. */
        if ((wOption & PH_EXCHANGE_CUSTOM_BITS_MASK) == PHALMFDF_SAM_NONX_EXCHANGE_PICC_STATUS) {
          PH_CHECK_SUCCESS_FCT(wStatus, PHHAL_HW_CMD_SAM_VERIFY_MAC(
                  pDataParams,
                  PH_EXCHANGE_BUFFER_CONT,
                  0x00, /* Mac based on the Keytype. */
                  &bPiccStat,
                  1));
        }

        /* Buffer Mac and Exchagne the bufferred information to Sam hardware. */
        PH_CHECK_SUCCESS_FCT(wStatus, PHHAL_HW_CMD_SAM_VERIFY_MAC(
                pDataParams,
                PH_EXCHANGE_BUFFER_LAST,
                0x00, /* Mac based on the Keytype. */
                pRespMac,
                (uint8_t) wRespMacLen));
      }
    }
  }

  return PH_ADD_COMPCODE(PH_ERR_SUCCESS, PH_COMP_AL_MFDF);
}

phStatus_t
phalMfdf_Sam_NonX_Int_ReadData(void *pDataParams, uint16_t wOption, uint8_t bIsDataCmd,
    uint8_t bCmd_ComMode, uint8_t bResp_ComMode, uint32_t dwLength,
    uint8_t *pCmdBuff, uint16_t wCmdLen, uint8_t **ppResponse, uint16_t *pRespLen)
{
  phStatus_t	PH_MEMLOC_REM wStatus = 0;
  phStatus_t	PH_MEMLOC_REM wStatus1 = 0;
  uint8_t		PH_MEMLOC_REM bOption = 0;
  uint16_t	PH_MEMLOC_REM wBuffOption = 0;
  uint16_t	PH_MEMLOC_REM wBuffOption1 = 0;
  uint8_t		PH_MEMLOC_REM bFirstFrame = 0;
  uint8_t		PH_MEMLOC_REM bLastFrame = 0;
  uint8_t		PH_MEMLOC_REM bLargeData = 0;
  uint8_t		PH_MEMLOC_REM bFinished = 0;
  uint8_t		PH_MEMLOC_REM bFinished1 = 0;
  uint8_t		PH_MEMLOC_REM bExchangeMac = 0;
  uint8_t		*PH_MEMLOC_REM pMac = NULL;
  uint16_t	PH_MEMLOC_REM wMacLen = 0;
  uint16_t	PH_MEMLOC_REM wOffset = 0;
  uint16_t	PH_MEMLOC_REM wTotLen = 0;
  uint16_t	PH_MEMLOC_REM wRemData = 0;
  uint8_t		*PH_MEMLOC_REM pCardResponse = NULL;
  uint8_t		*PH_MEMLOC_REM pResponse = NULL;
  uint16_t	PH_MEMLOC_REM wCardRespLen = 0;
  uint16_t	PH_MEMLOC_REM wRespLen = 0;
  uint8_t		PH_MEMLOC_REM bPiccErrCode = 0;
  uint8_t		PH_MEMLOC_REM bAuthMode = 0;

  /* Get the dataparams information. */
  PH_CHECK_SUCCESS_FCT(wStatus, phalMfdf_Sam_NonX_Int_GetAuthMode(pDataParams, &bAuthMode));

  /* Secure the information to be exchanged. */
  if (((wOption & 0xFF0F) == PH_EXCHANGE_DEFAULT) &&
      !(wOption & PHALMFDF_SAM_NONX_EXCHANGE_WITHOUT_SM)) {
    PH_CHECK_SUCCESS_FCT(wStatus, phalMfdf_Sam_NonX_Int_GenerateSM(
            pDataParams,
            PH_EXCHANGE_DEFAULT,
            PH_OFF,
            bIsDataCmd,
            bCmd_ComMode,
            pCmdBuff,
            wCmdLen,
            NULL,
            0,
            &pMac,
            &wMacLen));
  }

  /* Set if Mac on command is required. */
  bExchangeMac = (uint8_t)((bAuthMode == PHAL_MFDF_AUTHENTICATE) ? PHALMFDF_SAM_NONX_MAC_ON_CMD :
          PHALMFDF_SAM_NONX_NO_MAC_ON_CMD);

  /* Frame the total length. */
  wTotLen = wCmdLen;

  /* Set exchange optionto First. */
  wBuffOption = (uint16_t)(((wOption & 0xFF0F) == PH_EXCHANGE_RXCHAINING) ?
          (wOption & 0xFF0F) : PH_EXCHANGE_BUFFER_FIRST);

  /* Set PICC error validation flag. */
  bOption = (uint8_t)((wBuffOption == PH_EXCHANGE_RXCHAINING) ?
          PHALMFDF_SAM_NONX_CMD_OPTION_COMPLETE : PHALMFDF_SAM_NONX_CMD_OPTION_NONE);

  do {
    /* Buffer the command information. */
    wStatus1 = phalMfdf_Sam_NonX_Int_CardExchange(
            pDataParams,
            (uint16_t)((wBuffOption == PH_EXCHANGE_RXCHAINING) ? PH_EXCHANGE_DEFAULT : wBuffOption),
            bOption,
            wTotLen,
            PH_ON,
            pCmdBuff,
            wCmdLen,
            &pCardResponse,
            &wCardRespLen,
            &bPiccErrCode);

    /* Buffer the Mac information and exchange the complete information to PICC. */
    if ((wBuffOption != PH_EXCHANGE_DEFAULT) && ((wBuffOption != PH_EXCHANGE_RXCHAINING))) {
      wStatus1 = phalMfdf_Sam_NonX_Int_CardExchange(
              pDataParams,
              PH_EXCHANGE_BUFFER_LAST,
              (uint8_t)(PHALMFDF_SAM_NONX_CMD_OPTION_COMPLETE | (wOption & PH_EXCHANGE_CUSTOM_BITS_MASK)),
              0,
              PH_ON,
              pMac,
              (uint16_t)(bExchangeMac ? wMacLen : 0),
              &pCardResponse,
              &wCardRespLen,
              &bPiccErrCode);

      /* Update PICC error validation flag. */
      bOption = (uint8_t)(PHALMFDF_SAM_NONX_CMD_OPTION_COMPLETE | (wOption &
                  PH_EXCHANGE_CUSTOM_BITS_MASK));

      /* Set First Frame. */
      bFirstFrame = PH_ON;

      /* Subtract the total length with MAC. */
      wTotLen -= (uint16_t)(bExchangeMac ? wMacLen : 0);
    }

    /* Evaluate the response. */
    wStatus1 = phalMfdf_Sam_NonX_Int_ValidateResponse(pDataParams, wStatus1, bPiccErrCode);

    /* Set the last frame to end the looping. */
    bLastFrame = (uint8_t)((wStatus1 == PH_ERR_SUCCESS) ? PH_ON : PH_OFF);

    /* Update command information. */
    pCmdBuff[0] = PHAL_MFDF_RESP_ADDITIONAL_FRAME;
    wCmdLen = 1;

    /* Set the exchange option to RxChaining if there is still more information to be exchanged. */
    wBuffOption = PH_EXCHANGE_DEFAULT;

    /* Update the variables and parameters. */
    if (ppResponse != NULL) {
      if (ppResponse[0] != NULL) {
        memcpy(&ppResponse[0][wOffset], pCardResponse,
            (bLastFrame ? (wCardRespLen - wMacLen) : wCardRespLen));	/* PRQA S 3200 */
      } else {
        ppResponse[0] = pCardResponse;
      }

      *pRespLen += wCardRespLen;
      wOffset += (uint16_t) wCardRespLen;
    }

    /* Set Largedata flag. */
    bLargeData = (uint8_t)((wCardRespLen > PHALMFDF_SAM_DATA_FRAME_LENGTH) ? PH_ON : PH_OFF);

    /* Reset the Auth state of PICC only. */
    if ((wStatus1 != PH_ERR_SUCCESS) && ((wStatus1 & PH_ERR_MASK) != PH_ERR_SUCCESS_CHAINING)) {
      PH_CHECK_SUCCESS_FCT(wStatus, phalMfdf_Sam_NonX_Int_ResetAuthStatus(pDataParams));
      bFinished = PH_ON;
    } else {
      /* Perform Secure messaging verification only if required. */
      if (!(wOption & PHALMFDF_SAM_NONX_EXCHANGE_WITHOUT_SM)) {
        /* Exchange the data to SAM in chunks in case of large amount of data. */
        if (bLargeData) {
          bFirstFrame = PH_ON;
          bLastFrame = PH_OFF;
          wTotLen = wCardRespLen;
          wRemData = wTotLen;
          wOffset = 0;
          wCardRespLen = PHALMFDF_SAM_DATA_FRAME_LENGTH;
        }

        do {
          /* Set the information for the last frame to be exchanged. */
          if (bLargeData) {
            if (wRemData < PHALMFDF_SAM_DATA_FRAME_LENGTH) {
              wCardRespLen = wRemData;
              bLastFrame = PH_ON;
              bFinished1 = PH_ON;
            }
          } else {
            bFinished1 = PH_ON;
          }

          /* Set the buffering options. */
          wBuffOption1 = (uint16_t)(bLastFrame ? PH_EXCHANGE_DEFAULT : PH_EXCHANGE_RXCHAINING);

          /* Set the PICC status utilization. */
          if ((bAuthMode == PHAL_MFDF_AUTHENTICATE) && bFirstFrame) {
            wBuffOption1 |= (uint16_t) PHALMFDF_SAM_NONX_EXCHANGE_PICC_STATUS;
          } else {
            if ((bAuthMode != PHAL_MFDF_AUTHENTICATE) && bLastFrame) {
              wBuffOption1 |= (uint16_t) PHALMFDF_SAM_NONX_EXCHANGE_PICC_STATUS;
            }
          }

          /* Set the Mac Length. */
          if (bResp_ComMode != PHAL_MFDF_COMMUNICATION_ENC) {
            wMacLen = (uint16_t)(((bAuthMode == PHAL_MFDF_AUTHENTICATE) ||
                        (bAuthMode == PHAL_MFDF_NOT_AUTHENTICATED) ||
                        ((wOption & 0xFF0F) == PH_EXCHANGE_RXCHAINING) && !bLastFrame) ? 0 : 8);

            /* Set the Mac length for read related command. */
            if (bIsDataCmd) {
              wMacLen = (uint16_t)(((bResp_ComMode != PHAL_MFDF_COMMUNICATION_PLAIN) &&
                          (bAuthMode == PHAL_MFDF_AUTHENTICATE)) ? 4 : wMacLen);

              /* Set Mac length for  Authenticate state. */
              wMacLen = (uint8_t)(((bAuthMode == PHAL_MFDF_AUTHENTICATE) &&
                          (bResp_ComMode == PHAL_MFDF_COMMUNICATION_PLAIN)) ? 0 : wMacLen);
            }
          }

          /* Verify the security of the received information. */
          wStatus = phalMfdf_Sam_NonX_Int_VerifySM(
                  pDataParams,
                  wBuffOption1,
                  bResp_ComMode,
                  (bFirstFrame ? dwLength : 0),
                  &pCardResponse[bLargeData ? wOffset : 0],
                  (uint16_t)(wCardRespLen - (bLastFrame ? wMacLen : 0)),
                  bPiccErrCode,
                  &pCardResponse[bLargeData ? (wTotLen - (bLastFrame ? wMacLen : 0)) : (wCardRespLen -
                                     (bLastFrame ? wMacLen : 0))],
                  (uint16_t)(bLastFrame ? wMacLen : 0),
                  &pResponse,
                  &wRespLen);

          /* Copy the response to the buffer. */
          if ((wStatus == PH_ERR_SUCCESS) || ((wStatus & PH_ERR_MASK) == PH_ERR_SUCCESS_CHAINING)) {
            if (bResp_ComMode == PHAL_MFDF_COMMUNICATION_ENC) {
              /* Reset the length buffer. */
              if (bFirstFrame ||
                  ((wOption & PH_EXCHANGE_CUSTOM_BITS_MASK) == PHALMFDF_SAM_NONX_RETURN_CHAINING_STATUS)) {
                *pRespLen = 0;
              }

              memcpy(&ppResponse[0][*pRespLen], pResponse, wRespLen);
              *pRespLen = (uint16_t)(bLargeData ? (*pRespLen + wRespLen) : wRespLen);
            }
          }

          /* Subtract if Mac is available. */
          if (pRespLen != NULL) {
            *pRespLen -= (uint16_t)((bLastFrame &&
                        (bResp_ComMode != PHAL_MFDF_COMMUNICATION_ENC)) ? wMacLen : 0);
          }

          /* Validate the status. */
          if ((wStatus & PH_ERR_MASK) != PH_ERR_SUCCESS_CHAINING) {
            PH_CHECK_SUCCESS(wStatus);
          }

          /* Update offset for large amount of data only. */
          if (bLargeData) {
            /* Update the offsets and length. */
            wOffset += PHALMFDF_SAM_DATA_FRAME_LENGTH;

            /* Set the remaining data length to be exchanged. */
            wRemData -= PHALMFDF_SAM_DATA_FRAME_LENGTH;
          }

          /* Clear First Frame. */
          bFirstFrame = PH_OFF;
        } while (!bFinished1);
      }
    }

    /* Set finished flag. */
    if ((wStatus1 == PH_ERR_SUCCESS) ||
        ((wOption & PH_EXCHANGE_CUSTOM_BITS_MASK) == PHALMFDF_SAM_NONX_RETURN_CHAINING_STATUS)) {
      bFinished = PH_ON;
    }
  } while (!bFinished);

  return wStatus1;
}

phStatus_t
phalMfdf_Sam_NonX_Int_WriteData(void *pDataParams, uint16_t wOption, uint8_t bIsDataCmd,
    uint8_t bCmd_ComMode, uint8_t bResp_ComMode, uint8_t bResetAuth,
    uint8_t *pCmdBuff, uint16_t wCmdLen, uint8_t *pData, uint32_t dwDataLen, uint8_t **ppResponse,
    uint16_t *pRespLen)
{
  phStatus_t	PH_MEMLOC_REM wStatus = 0;
  phStatus_t	PH_MEMLOC_REM wStatus1 = 0;
  uint8_t		PH_MEMLOC_REM bAuthMode = 0;
  uint8_t		PH_MEMLOC_REM bWrappedMode = 0;
  uint16_t	PH_MEMLOC_REM wTotLen = 0;
  uint8_t		PH_MEMLOC_REM aCmdBuf_Tmp[50];
  uint16_t	PH_MEMLOC_REM wCmdLen_Tmp = 0;
  uint8_t		PH_MEMLOC_REM bExchangeMac = 0;
  uint8_t		*PH_MEMLOC_REM pSMData = NULL;
  uint16_t	PH_MEMLOC_REM wSMDataLen = 0;
  uint8_t		*PH_MEMLOC_REM pCardResponse = NULL;
  uint16_t	PH_MEMLOC_REM wCardRespLen = 0;
  uint8_t		PH_MEMLOC_REM bPiccErrCode = 0;
  uint16_t	PH_MEMLOC_REM wPICCFrameLen = 0;
  uint8_t		PH_MEMLOC_REM bFirstFrame = PH_ON;
  uint8_t		PH_MEMLOC_REM bLastFrame = PH_OFF;
  uint8_t		PH_MEMLOC_REM bDataLen = 0;
  uint8_t		PH_MEMLOC_REM bCmdOption = 0;
  uint8_t		PH_MEMLOC_REM bIsLargeData = 0;
  uint32_t	PH_MEMLOC_REM dwRemLen = 0;

  uint16_t	PH_MEMLOC_REM wBuffOption_PICC = 0;
  uint8_t		PH_MEMLOC_REM bFinished_PICC = PH_OFF;
  uint8_t		PH_MEMLOC_REM bPiccExchangeComplete = PH_OFF;
  uint32_t	PH_MEMLOC_REM dwOffset_PICC = 0;

  uint16_t	PH_MEMLOC_REM wBuffOption_SAM = 0;
  uint8_t		PH_MEMLOC_REM bFrameLen_SAM = 0;
  uint32_t	PH_MEMLOC_REM dwOffset_SAM = 0;
  uint32_t	PH_MEMLOC_REM dwRemLen_SAM = 0;
  uint8_t		PH_MEMLOC_REM bSamExchangeComplete = PH_OFF;
  uint8_t		PH_MEMLOC_REM bFinished_SAM = PH_OFF;

  /* GEt DataParams information. */
  PH_CHECK_SUCCESS_FCT(wStatus, phalMfdf_Sam_NonX_Int_GetAuthMode(pDataParams, &bAuthMode));
  PH_CHECK_SUCCESS_FCT(wStatus, phalMfdf_Sam_NonX_Int_GetWrappedMode(pDataParams, &bWrappedMode));

  if ((bCmd_ComMode == PHAL_MFDF_COMMUNICATION_ENC) && (bAuthMode == PHAL_MFDF_NOT_AUTHENTICATED)) {
    return PH_ADD_COMPCODE(PH_ERR_USE_CONDITION, PH_COMP_AL_MFDF);
  }

  /* Save the command information and it length because in course . */
  memcpy(aCmdBuf_Tmp, pCmdBuff, wCmdLen);
  wCmdLen_Tmp = wCmdLen;

  /* Set the Initial Frame length. */
  bFrameLen_SAM = (uint8_t) dwDataLen;
  dwRemLen_SAM = dwDataLen;

  /* Get the PICC Frame length. */
  PH_CHECK_SUCCESS_FCT(wStatus, phalMfdf_Sam_NonX_Int_GetFrameLen(
          pDataParams,
          &wPICCFrameLen));

  do {
    /* Encrypt the information. */
    if (!(wOption & PHALMFDF_SAM_NONX_EXCHANGE_WITHOUT_SM) &&
        (bAuthMode != PHAL_MFDF_NOT_AUTHENTICATED)) {
      if ((dwRemLen_SAM > PHALMFDF_SAM_DATA_FRAME_LENGTH)) {
        bFrameLen_SAM = PHALMFDF_SAM_DATA_FRAME_LENGTH;
        wBuffOption_SAM = PH_EXCHANGE_TXCHAINING;
      } else {
        bFrameLen_SAM = (uint8_t) dwRemLen_SAM;
        wBuffOption_SAM = (uint16_t)((wOption & PH_EXCHANGE_TXCHAINING) ? PH_EXCHANGE_TXCHAINING :
                PH_EXCHANGE_DEFAULT);
        bFinished_SAM = PH_ON;
      }

      wStatus = phalMfdf_Sam_NonX_Int_GenerateSM(
              pDataParams,
              wBuffOption_SAM,
              bIsDataCmd,
              PH_OFF,
              bCmd_ComMode,
              aCmdBuf_Tmp,
              wCmdLen_Tmp,
              &pData[dwOffset_SAM],
              bFrameLen_SAM,
              &pSMData,
              &wSMDataLen);

      /* Validate the status. */
      if ((wStatus != PH_ERR_SUCCESS) && ((wStatus & PH_ERR_MASK) != PH_ERR_SUCCESS_CHAINING)) {
        return wStatus;
      } else {
        if (wStatus == PH_ERR_SUCCESS) {
          /* Set Sam complete exchagne flag. */
          bSamExchangeComplete = PH_ON;

          if (wSMDataLen < wPICCFrameLen) {
            bIsLargeData = PH_OFF;
            dwRemLen = (uint8_t)((wOption & PHALMFDF_SAM_NONX_EXCHANGE_DATA_PICC) ? dwDataLen : 0);

            /* Set if Mac on command is required. */
            bExchangeMac = (uint8_t)((bCmd_ComMode == PHAL_MFDF_COMMUNICATION_MACD) ?
                    PHALMFDF_SAM_NONX_MAC_ON_CMD :
                    PHALMFDF_SAM_NONX_NO_MAC_ON_CMD);
          } else {
            bFirstFrame = (uint8_t)((bCmd_ComMode == PHAL_MFDF_COMMUNICATION_ENC) ? PH_ON : PH_OFF);
          }
        }
      }

      /* Update the lengths. */
      dwRemLen_SAM = dwRemLen_SAM - PHALMFDF_SAM_DATA_FRAME_LENGTH;
      dwOffset_SAM += PHALMFDF_SAM_DATA_FRAME_LENGTH;
    } else {
      bFinished_SAM = PH_ON;
      bSamExchangeComplete = PH_ON;
    }

    /* Set First Frame. */
    if (bCmd_ComMode == PHAL_MFDF_COMMUNICATION_ENC) {
      bFirstFrame = PH_ON;
    }

    if (!bPiccExchangeComplete) {
      do {
        if (bIsDataCmd) {
          /* Get the frame size that can be transmitted to PICC. */
          if (bFirstFrame) {
            /* Set the lengths. */
            dwRemLen = (bCmd_ComMode == PHAL_MFDF_COMMUNICATION_ENC) ? wSMDataLen : dwDataLen;

            /* Check if large amount of data needs to be exchanged. */
            bIsLargeData = (uint8_t)(((wCmdLen_Tmp + dwRemLen) > wPICCFrameLen) ? PH_ON : PH_OFF);
          }

          /* Performing chunk exchange if large data flag is set. */
          if (bIsLargeData) {
            bDataLen = (uint8_t)(wPICCFrameLen - wCmdLen_Tmp);
            bDataLen = (uint8_t)(bWrappedMode ? (bDataLen - 6) : bDataLen);

            /* Set the completion flag. */
            if (dwRemLen <= bDataLen) {
              bDataLen = (uint8_t) dwRemLen;
              bFinished_PICC = PH_ON;
              bLastFrame = PH_ON;
              dwRemLen = 0;
            }
          } else {
            bFinished_PICC = PH_ON;
            bLastFrame = PH_ON;
            bDataLen = (uint8_t) dwRemLen;
          }

          /* Set PICC Exchange complete for MAC and PLAIN communication. */
          bPiccExchangeComplete = (uint8_t)((bCmd_ComMode == PHAL_MFDF_COMMUNICATION_ENC) ? PH_OFF : PH_ON);

          /* Set the command comunication mode. */
          bCmd_ComMode = (uint8_t)(((bCmd_ComMode == PHAL_MFDF_COMMUNICATION_PLAIN) &&
                      ((bAuthMode == PHAL_MFDF_AUTHENTICATEISO) || (bAuthMode == PHAL_MFDF_AUTHENTICATEAES))) ?
                  PH_OFF : bCmd_ComMode);
        } else {
          bFinished_PICC = PH_ON;
          bLastFrame = PH_ON;
          bDataLen = (uint8_t) dwRemLen;

          if (!bIsDataCmd && (bCmd_ComMode == PHAL_MFDF_COMMUNICATION_ENC)) {
            bDataLen = (uint8_t) wSMDataLen;
          }
        }

        /* Frame the total length. */
        wTotLen = 0;
        wTotLen = (uint16_t)(wCmdLen_Tmp + ((bCmd_ComMode == PHAL_MFDF_COMMUNICATION_ENC) ? bDataLen :
                    dwDataLen));
        wTotLen = (uint16_t)(bWrappedMode ? (wCmdLen_Tmp + bDataLen) : wTotLen);
        wTotLen = (uint16_t)((bExchangeMac && bLastFrame) ? (wTotLen + wSMDataLen) : wTotLen);

        /* Set the Bufferring option. */
        wBuffOption_PICC = PH_EXCHANGE_BUFFER_FIRST;
        wBuffOption_PICC = (uint16_t)(!wCmdLen_Tmp ? PH_EXCHANGE_BUFFER_CONT : wBuffOption_PICC);

        /* Buffer the command information. */
        PH_CHECK_SUCCESS_FCT(wStatus1, phalMfdf_Sam_NonX_Int_CardExchange(
                pDataParams,
                wBuffOption_PICC,
                PHALMFDF_SAM_NONX_CMD_OPTION_NONE,
                wTotLen,
                PH_OFF,
                aCmdBuf_Tmp,
                wCmdLen_Tmp,
                NULL,
                NULL,
                NULL));

        /* Buffer the data information. */
        if (bCmd_ComMode != PHAL_MFDF_COMMUNICATION_ENC) {
          PH_CHECK_SUCCESS_FCT(wStatus1, phalMfdf_Sam_NonX_Int_CardExchange(
                  pDataParams,
                  PH_EXCHANGE_BUFFER_CONT,
                  PHALMFDF_SAM_NONX_CMD_OPTION_NONE,
                  0,
                  PH_OFF,
                  &pData[dwOffset_PICC],
                  (uint16_t)(bIsLargeData ? bDataLen : dwRemLen),
                  NULL,
                  NULL,
                  NULL));
        }

        /* Set the Bufferring option. */
        wBuffOption_PICC = PH_EXCHANGE_BUFFER_LAST;

        /* Set the PICC status verification. */
        bCmdOption = (uint8_t)((wBuffOption_PICC == PH_EXCHANGE_BUFFER_LAST) ?
                PHALMFDF_SAM_NONX_CMD_OPTION_COMPLETE :
                PHALMFDF_SAM_NONX_CMD_OPTION_NONE);
        bCmdOption |= (uint8_t)(wOption & PH_EXCHANGE_CUSTOM_BITS_MASK);

        /* Buffer the Mac information exchange the complete information to PICC. */
        wStatus1 = phalMfdf_Sam_NonX_Int_CardExchange(
                pDataParams,
                wBuffOption_PICC,
                bCmdOption,
                0,
                PH_ON,
                &pSMData[(bCmd_ComMode == PHAL_MFDF_COMMUNICATION_ENC) ? dwOffset_PICC : 0],
                (uint16_t)((bCmd_ComMode == PHAL_MFDF_COMMUNICATION_ENC) ? bDataLen : ((bLastFrame &&
                            bExchangeMac) ? wSMDataLen : 0)),
                &pCardResponse,
                &wCardRespLen,
                &bPiccErrCode);

        /* Validate the status. */
        if ((wStatus1 != PH_ERR_SUCCESS) && ((wStatus1 & PH_ERR_MASK) != PH_ERR_SUCCESS_CHAINING)) {
          bFinished_PICC = PH_ON;
        }

        /* Complete the Exchange and return the status to caller. */
        if (((wOption & PH_EXCHANGE_CUSTOM_BITS_MASK) == PHALMFDF_SAM_NONX_RETURN_CHAINING_STATUS) &&
            ((wStatus1 & PH_ERR_MASK) == PH_ERR_SUCCESS_CHAINING)) {
          bFinished_PICC = PH_ON;
        }

        /* Reset the command information. */
        wCmdLen_Tmp = 0;
        aCmdBuf_Tmp[wCmdLen_Tmp++] = PHAL_MFDF_RESP_ADDITIONAL_FRAME;

        if (bIsDataCmd && bIsLargeData) {
          /* Clear the First frame flag. */
          bFirstFrame = PH_OFF;

          /* Update length. */
          dwOffset_PICC += bDataLen;
          dwRemLen = (uint32_t)(dwRemLen - bDataLen);
        }
      } while (!bFinished_PICC);

      /* Reset the variables. */
      dwOffset_PICC = 0;
      bDataLen = 0;
      bFinished_PICC = PH_OFF;
    } else {
      if (wSMDataLen && (bCmd_ComMode != PHAL_MFDF_COMMUNICATION_PLAIN)) {
        wCmdLen_Tmp = 0;

        aCmdBuf_Tmp[wCmdLen_Tmp++] = PHAL_MFDF_RESP_ADDITIONAL_FRAME;
        wBuffOption_PICC = PH_EXCHANGE_DEFAULT;

        /* Copy the MAC information */
        memcpy(&aCmdBuf_Tmp[wCmdLen_Tmp], pSMData, wSMDataLen);	/* PRQA S 3200 */
        wCmdLen_Tmp += wSMDataLen;

        /* Buffer the command information. */
        wStatus1 = phalMfdf_Sam_NonX_Int_CardExchange(
                pDataParams,
                wBuffOption_PICC,
                PHALMFDF_SAM_NONX_CMD_OPTION_COMPLETE,
                wCmdLen_Tmp,
                PH_ON,
                aCmdBuf_Tmp,
                wCmdLen_Tmp,
                &pCardResponse,
                &wCardRespLen,
                &bPiccErrCode);
      }
    }
  } while (!bFinished_SAM);

  /* Perform Secure messaging verification only if required. */
  if (!(wOption & PHALMFDF_SAM_NONX_EXCHANGE_WITHOUT_SM) &&
      !(wOption & PHALMFDF_SAM_NONX_RETURN_CHAINING_STATUS)) {
    /* Reset the Authentication. */
    if (bResetAuth && (wStatus1 == PH_ERR_SUCCESS)) {
      if ((bAuthMode == PHAL_MFDF_AUTHENTICATEISO) || (bAuthMode == PHAL_MFDF_AUTHENTICATEAES) ||
          (bAuthMode == PHAL_MFDF_AUTHENTICATE)) {
        PH_CHECK_SUCCESS_FCT(wStatus, phalMfdf_Sam_NonX_Int_ResetAuthStatus(pDataParams));
      }
    }

    /* Verify the security of the received information. */
    else {
      /* Reset the Authentication state if there is an error. */
      if (wStatus1 != PH_ERR_SUCCESS) {
        PH_CHECK_SUCCESS_FCT(wStatus, phalMfdf_Sam_NonX_Int_ResetAuthStatus(pDataParams));
      } else {
        if (bResp_ComMode != PHAL_MFDF_COMMUNICATION_PLAIN) {
          PH_CHECK_SUCCESS_FCT(wStatus, phalMfdf_Sam_NonX_Int_VerifySM(
                  pDataParams,
                  (uint16_t)(PH_EXCHANGE_DEFAULT | PHALMFDF_SAM_NONX_EXCHANGE_PICC_STATUS),
                  bResp_ComMode,
                  0,
                  ((pCmdBuff[0] == PHAL_MFDF_CMD_COMMIT_TXN) && (wCmdLen == 2)) ? pCardResponse : NULL,
                  (uint16_t)(((pCmdBuff[0] == PHAL_MFDF_CMD_COMMIT_TXN) && (wCmdLen == 2)) ? 12 : 0),
                  bPiccErrCode,
                  ((pCmdBuff[0] == PHAL_MFDF_CMD_COMMIT_TXN) &&
                      (wCmdLen == 2)) ? &pCardResponse[12] : pCardResponse,
                  (uint16_t)(((pCmdBuff[0] == PHAL_MFDF_CMD_COMMIT_TXN) &&
                          (wCmdLen == 2)) ? (wCardRespLen - 12) : wCardRespLen),
                  ppResponse,
                  pRespLen));

          if ((pRespLen != NULL) && (bResp_ComMode != PHAL_MFDF_COMMUNICATION_ENC)) {
            *ppResponse = pCardResponse;
            *pRespLen = wCardRespLen;
          }
        }
      }
    }

    /* Evaluate the response. */
    PH_CHECK_SUCCESS_FCT(wStatus, phalMfdf_Sam_NonX_Int_ValidateResponse(pDataParams, wStatus1,
            bPiccErrCode));
  } else {
    if (pRespLen != NULL) {
      *ppResponse = pCardResponse;
      *pRespLen = wCardRespLen;
    }
  }

  return wStatus1;
}

phStatus_t
phalMfdf_Sam_NonX_Int_ResetAuthStatus(void *pDataParams)
{
  phStatus_t  PH_MEMLOC_REM wStatus = 0;

  /* Reset the Authmode and Key number */
  PH_CHECK_SUCCESS_FCT(wStatus, phalMfdf_Sam_NonX_Int_SetAuthMode(pDataParams,
          PHAL_MFDF_NOT_AUTHENTICATED));
  PH_CHECK_SUCCESS_FCT(wStatus, phalMfdf_Sam_NonX_Int_SetKeyNo(pDataParams, 0xFF));

  /* Reset PICC Authentication. */
  PH_CHECK_SUCCESS_FCT(wStatus, PHHAL_HW_KILL_AUTHENTICATION(pDataParams));

  return PH_ADD_COMPCODE(PH_ERR_SUCCESS, PH_COMP_AL_MFDF);
}

phStatus_t
phalMfdf_Sam_NonX_Int_GetFrameLen(void *pDataParams, uint16_t *pFrameLen)
{
  phStatus_t	PH_MEMLOC_REM wStatus = 0;
  uint16_t	PH_MEMLOC_REM wFrameLen = 0;

  /* Get the frame size that can be transmitted to PICC. */
  PH_CHECK_SUCCESS_FCT(wStatus, PHPAL_MIFARE_GETCONFIG(
          pDataParams,
          0x04, /* Get the frame length of PICC and PCD. */
          &wFrameLen));

  /* Update the parameter. */
  switch ((uint8_t)(wFrameLen & 0x000F)) {
    case 0:
      *pFrameLen = 16;
      break;
    case 1:
      *pFrameLen = 24;
      break;
    case 2:
      *pFrameLen = 32;
      break;
    case 3:
      *pFrameLen = 40;
      break;
    case 4:
      *pFrameLen = 48;
      break;
    case 5:
      *pFrameLen = 64;
      break;
    case 6:
      *pFrameLen = 96;
      break;
    case 7:
      *pFrameLen = 128;
      break;
    case 8:
      *pFrameLen = 256;
      break;

    default:
      break;
  }

  /* Remove the ISO header. */
  *pFrameLen -= 4;

  return PH_ADD_COMPCODE(PH_ERR_SUCCESS, PH_COMP_AL_MFDF);
}

#endif /* NXPBUILD__PHAL_MFDF_SAM_NONX */
