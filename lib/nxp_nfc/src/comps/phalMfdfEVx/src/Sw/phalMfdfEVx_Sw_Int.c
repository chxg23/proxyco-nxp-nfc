/*----------------------------------------------------------------------------*/
/* Copyright 2014-2020 NXP                                                    */
/*                                                                            */
/* NXP Confidential. This software is owned or controlled by NXP and may only */
/* be used strictly in accordance with the applicable license terms.          */
/* By expressly accepting such terms or by downloading, installing,           */
/* activating and/or otherwise using the software, you are agreeing that you  */
/* have read, and that you agree to comply with and are bound by, such        */
/* license terms. If you do not agree to be bound by the applicable license   */
/* terms, then you may not retain, install, activate or otherwise use the     */
/* software.                                                                  */
/*----------------------------------------------------------------------------*/

#include <nxp_nfc/ph_Status.h>
#include <nxp_nfc/phpalMifare.h>
#include <nxp_nfc/phpalI14443p4.h>
#include <nxp_nfc/ph_RefDefs.h>
#include <nxp_nfc/ph_TypeDefs.h>
#include <nxp_nfc/phTools.h>
#include <string.h>
#ifdef NXPBUILD__PH_CRYPTOSYM
#include <nxp_nfc/phCryptoSym.h>
#endif /* NXPBUILD__PH_CRYPTOSYM */
#include <nxp_nfc/phKeyStore.h>
#include <nxp_nfc/phTMIUtils.h>
#include <nxp_nfc/phalVca.h>

#ifdef NXPBUILD__PHAL_MFDFEVX_SW

#include "../phalMfdfEVx_Int.h"
#include "nxp_nfc/phalMfdfEVx_Sw_Int.h"

phStatus_t phalMfdfEVx_Sw_Int_CardExchange(phalMfdfEVx_Sw_DataParams_t *pDataParams,
    uint16_t wBufferOption, uint16_t wTotDataLen,
    uint8_t bExchangeLE, uint8_t *pData, uint16_t wDataLen, uint8_t **ppResponse, uint16_t *pRespLen,
    uint8_t *pPiccRetCode)
{
  phStatus_t  PH_MEMLOC_REM wStatus = 0;
  uint16_t    PH_MEMLOC_REM wLc = 0;
  uint8_t    *PH_MEMLOC_REM pResponse;
  uint16_t    PH_MEMLOC_REM wRespLen = 0;

  uint8_t         PH_MEMLOC_REM aLc[1] = { 0x00 };
  uint8_t         PH_MEMLOC_REM aLe[1] = { 0x00 };
  uint8_t         PH_MEMLOC_REM bLcLen = 0;
  uint8_t         PH_MEMLOC_REM aISO7816Header[8] = { PHAL_MFDFEVX_WRAPPEDAPDU_CLA, 0x00, PHAL_MFDFEVX_WRAPPEDAPDU_P1, PHAL_MFDFEVX_WRAPPEDAPDU_P2 };
  uint8_t         PH_MEMLOC_REM bISO7816HeaderLen = 4;
  uint8_t         PH_MEMLOC_REM bIsIsoChainnedCmd = PH_OFF;
  static uint8_t  PH_MEMLOC_REM bLeLen;

  /* Exchange the command in Iso7816 wrapped formmat. ----------------------------------------------------------------- */
  if (0U != (pDataParams->bWrappedMode)) {
    if ((wBufferOption == PH_EXCHANGE_BUFFER_FIRST) || (wBufferOption == PH_EXCHANGE_DEFAULT)) {
      /* Set the flag for data operation commands. */
      bIsIsoChainnedCmd = (uint8_t)(((pData[0] == PHAL_MFDFEVX_CMD_READ_DATA_ISO) ||
                  (pData[0] == PHAL_MFDFEVX_CMD_READ_RECORDS_ISO) ||
                  (pData[0] == PHAL_MFDFEVX_CMD_WRITE_DATA_ISO) ||
                  (pData[0] == PHAL_MFDFEVX_CMD_WRITE_RECORD_ISO) ||
                  (pData[0] == PHAL_MFDFEVX_CMD_UPDATE_RECORD_ISO)) ? PH_ON : PH_OFF);

      bLeLen = 1;

      /* Set the LC information. */
      wLc = (uint16_t)(wTotDataLen - 1 /* Excluding the command code. */);

      /* Update the command code to Iso7816 header */
      aISO7816Header[1] = pData[0];

      /* Add the ISO 7816 header to layer 4 buffer. */
      PH_CHECK_SUCCESS_FCT(wStatus, phpalMifare_ExchangeL4(
              pDataParams->pPalMifareDataParams,
              PH_EXCHANGE_BUFFER_FIRST,
              &aISO7816Header[0],
              bISO7816HeaderLen,
              NULL,
              NULL));

      /* Add Lc if available */
      if (wLc) {
        /* Update Lc bytes */
        aLc[bLcLen++] = (uint8_t)(wLc & 0x00FF);

        /* Add the Lc to layer 4 buffer. */
        PH_CHECK_SUCCESS_FCT(wStatus, phpalMifare_ExchangeL4(
                pDataParams->pPalMifareDataParams,
                PH_EXCHANGE_BUFFER_CONT,
                &aLc[0],
                bLcLen,
                NULL,
                NULL));

        /* Add the data to layer 4 buffer. */
        PH_CHECK_SUCCESS_FCT(wStatus, phpalMifare_ExchangeL4(
                pDataParams->pPalMifareDataParams,
                PH_EXCHANGE_BUFFER_CONT,
                &pData[1],  /* Exclude the command code because it is added to INS. */
                (uint16_t)(wDataLen - 1),
                NULL,
                NULL));
      } else {
        ;
      }
    }

    if (wBufferOption == PH_EXCHANGE_BUFFER_CONT) {
      /* Add the data to layer 4 buffer. */
      PH_CHECK_SUCCESS_FCT(wStatus, phpalMifare_ExchangeL4(
              pDataParams->pPalMifareDataParams,
              PH_EXCHANGE_BUFFER_CONT,
              pData,
              wDataLen,
              NULL,
              NULL));
    }

    if ((wBufferOption == PH_EXCHANGE_BUFFER_LAST) || (wBufferOption == PH_EXCHANGE_DEFAULT)) {
      if (wBufferOption == PH_EXCHANGE_BUFFER_LAST) {
        /* Add the data to layer 4 buffer. */
        PH_CHECK_SUCCESS_FCT(wStatus, phpalMifare_ExchangeL4(
                pDataParams->pPalMifareDataParams,
                PH_EXCHANGE_BUFFER_CONT,
                pData,
                wDataLen,
                NULL,
                NULL));
      }

      /* Add Le to L4 buffer and exchange the command. */
      PH_CHECK_SUCCESS_FCT(wStatus, phpalMifare_ExchangeL4(
              pDataParams->pPalMifareDataParams,
              PH_EXCHANGE_BUFFER_LAST,
              &aLe[0],
              (uint8_t)(bExchangeLE ? bLeLen : 0),
              &pResponse,
              &wRespLen));

      /* Evaluate the response. */
      PH_CHECK_SUCCESS_FCT(wStatus, phalMfdfEVx_Int_ComputeErrorResponse(pDataParams,
              pResponse[wRespLen - 1U]));

      /* Create memory for updating the response of ISO 14443 format. */
      *ppResponse = pResponse;

      /* Update the response buffer length excluding SW1SW2. */
      *pRespLen = wRespLen - 2U;

      /* Copy the second byte of response (SW2) to RxBuffer */
      *pPiccRetCode = pResponse[wRespLen - 1U];
    }

    if (wBufferOption == PH_EXCHANGE_RXCHAINING) {
      /* Exchange the command */
      PH_CHECK_SUCCESS_FCT(wStatus, phpalMifare_ExchangeL4(
              pDataParams->pPalMifareDataParams,
              wBufferOption,
              pData,
              wDataLen,
              &pResponse,
              &wRespLen));

      /* Evaluate the response. */
      PH_CHECK_SUCCESS_FCT(wStatus, phalMfdfEVx_Int_ComputeErrorResponse(pDataParams,
              pResponse[wRespLen - 1]));

      /* Create memory for updating the response of ISO 14443 format. */
      *ppResponse = pResponse;

      /* Update the response buffer length excluding SW1SW2. */
      *pRespLen = wRespLen - 2U;

      /* Copy the second byte of response (SW2) to RxBuffer */
      *pPiccRetCode = pResponse[wRespLen - 1U];
    }
  }

  /* Exchange the command in Native formmat. -------------------------------------------------------------------------- */
  else {
    /* Exchange the data to the card in Native format. */
    PH_CHECK_SUCCESS_FCT(wStatus, phpalMifare_ExchangeL4(
            pDataParams->pPalMifareDataParams,
            wBufferOption,
            pData,
            wDataLen,
            &pResponse,
            &wRespLen));

    /* Evaluate the response. */
    if ((wBufferOption == PH_EXCHANGE_BUFFER_LAST) || (wBufferOption == PH_EXCHANGE_DEFAULT)) {
      PH_CHECK_SUCCESS_FCT(wStatus, phalMfdfEVx_Int_ComputeErrorResponse(pDataParams, pResponse[0]));

      /* Create memory for updating the response of ISO 14443 format. */
      *ppResponse = &pResponse[1];

      /* Update the response buffer length excluding SW1. */
      *pRespLen = wRespLen - 1U;

      /* Copy the second byte of response (SW2) to RxBuffer */
      *pPiccRetCode = pResponse[0];
    }
  }

  PH_UNUSED_VARIABLE(bIsIsoChainnedCmd);
  return wStatus;
}

phStatus_t phalMfdfEVx_Sw_Int_GetData(phalMfdfEVx_Sw_DataParams_t *pDataParams,
    uint8_t *pSendBuff, uint16_t wCmdLen,
    uint8_t **pResponse, uint16_t *pRxlen)
{
  uint16_t   PH_MEMLOC_REM wOption;
  uint8_t    PH_MEMLOC_REM *pRecv = NULL;
  phStatus_t PH_MEMLOC_REM statusTmp = 0;
  uint8_t    PH_MEMLOC_REM bStatusByte = 0xFF;
  uint8_t    PH_MEMLOC_REM bCmdBuff[10];
  uint8_t    PH_MEMLOC_REM bBackupByte = 0;
  uint16_t   PH_MEMLOC_REM wNextPos = 0;
  uint16_t   PH_MEMLOC_REM wRxBufferSize = 0;
  uint8_t    PH_MEMLOC_REM bBackupBytes[3];
  uint8_t    PH_MEMLOC_REM pApdu[5] = { PHAL_MFDFEVX_WRAPPEDAPDU_CLA, 0x00, PHAL_MFDFEVX_WRAPPEDAPDU_P1, PHAL_MFDFEVX_WRAPPEDAPDU_P2, 0x00 };
  uint8_t    PH_MEMLOC_REM bBackUpByte;
  uint8_t    PH_MEMLOC_REM bBackUpByte1;
  uint16_t   PH_MEMLOC_REM wBackUpLen;
  uint8_t    PH_MEMLOC_REM bIvLen = 0;
  uint16_t   PH_MEMLOC_REM wTmp = 0;

  /* Status and two other bytes to be backed up before getting new frame of data */
  (void)memset(bBackupBytes, 0x00, 3);

  PH_CHECK_SUCCESS_FCT(statusTmp, phhalHw_GetConfig(
          pDataParams->pHalDataParams,
          PHHAL_HW_CONFIG_RXBUFFER_STARTPOS,
          &wTmp
      ));

  wOption = PH_EXCHANGE_DEFAULT;
  if (0U != (pDataParams->bWrappedMode)) {
    if (wCmdLen > PHAL_MFDFEVX_MAXWRAPPEDAPDU_SIZE) {
      return PH_ADD_COMPCODE_FIXED(PH_ERR_BUFFER_OVERFLOW, PH_COMP_AL_MFDFEVX);
    }

    pApdu[1] = pSendBuff[0];  /* DESFire command code. */
    /* Encode APDU Length*/
    pApdu[4] = (uint8_t) wCmdLen - 1u; /* Set APDU Length. */

    statusTmp = phpalMifare_ExchangeL4(
            pDataParams->pPalMifareDataParams,
            (pApdu[4] == 0x00U) ? PH_EXCHANGE_DEFAULT : PH_EXCHANGE_BUFFER_FIRST,
            pApdu,
            PHAL_MFDFEVX_WRAP_HDR_LEN,
            &pRecv,
            pRxlen
        );
    if ((pApdu[4] != 0x00U) && (statusTmp == PH_ERR_SUCCESS)) {
      PH_CHECK_SUCCESS_FCT(statusTmp, phpalMifare_ExchangeL4(
              pDataParams->pPalMifareDataParams,
              PH_EXCHANGE_BUFFER_CONT,
              &pSendBuff[1],
              wCmdLen - 1u,
              &pRecv,
              pRxlen
          ));

      statusTmp = phpalMifare_ExchangeL4(
              pDataParams->pPalMifareDataParams,
              PH_EXCHANGE_BUFFER_LAST,
              &pApdu[2],
              0x01,
              &pRecv,
              pRxlen
          );
    }
    /* To handle the case where the card returns only status 91 and returns
    AF in the next frame */
    if ((statusTmp & PH_ERR_MASK) == PH_ERR_SUCCESS_CHAINING) {
      if (((pDataParams->bWrappedMode) && (*pRxlen == 2U)) ||
          ((!(pDataParams->bWrappedMode)) && (*pRxlen == 1U))) {
        /* AF should always be accompanied by data. Otherwise
        it is a protocol error */
        return PH_ADD_COMPCODE_FIXED(PH_ERR_PROTOCOL_ERROR, PH_COMP_AL_MFDFEVX);
      }
      /* One more status byte to read from DesFire */
      bBackUpByte = pRecv[0];
      bBackUpByte1 = pRecv[1];
      wBackUpLen = *pRxlen;

      PH_CHECK_SUCCESS_FCT(statusTmp, phpalMifare_ExchangeL4(
              pDataParams->pPalMifareDataParams,
              PH_EXCHANGE_RXCHAINING,
              &pApdu[2],
              0x01,
              &pRecv,
              pRxlen
          ));

      /* Received length can be one or two Ex: 0x91 0xAF */
      if (*pRxlen == 2U) {
        pRecv[wBackUpLen] = pRecv[0];
        pRecv[wBackUpLen + 1U] = pRecv[1];
        bStatusByte = pRecv[1];
      } else if (*pRxlen == 1U) {
        bStatusByte = pRecv[0];
        pRecv[wBackUpLen] = bStatusByte;
      } else {
        return PH_ADD_COMPCODE_FIXED(PH_ERR_PROTOCOL_ERROR, PH_COMP_AL_MFDFEVX);
      }

      *pRxlen = wBackUpLen + *pRxlen;

      /* Set back the backed up bytes */
      pRecv[0] = bBackUpByte;
      pRecv[1] = bBackUpByte1;
    } else {
      if (statusTmp != PH_ERR_SUCCESS) {
        return statusTmp;
      }
    }
  } else {
    /* Normal mode */
    if (wCmdLen > PHAL_MFDFEVX_MAXDFAPDU_SIZE) {
      return PH_ADD_COMPCODE_FIXED(PH_ERR_BUFFER_OVERFLOW, PH_COMP_AL_MFDFEVX);
    }

    /* Send this on L4 */
    PH_CHECK_SUCCESS_FCT(statusTmp, phpalMifare_ExchangeL4(
            pDataParams->pPalMifareDataParams,
            wOption,
            pSendBuff,
            wCmdLen,
            &pRecv,
            pRxlen
        ));
  }

  /* Storing the original pointer */
  *pResponse = pRecv;

  /* Status is 0xAF or 0x00? */
  if (*pRxlen > 0x0000U) {
    if (0U != (pDataParams->bWrappedMode)) {
      bStatusByte = (*pResponse)[(*pRxlen) - 1];
    } else {
      bStatusByte = (*pResponse)[wTmp];
    }
  }

  if (bStatusByte == PHAL_MFDFEVX_RESP_ADDITIONAL_FRAME) {
    if (((pDataParams->bWrappedMode) && (*pRxlen == 2U)) ||
        ((!(pDataParams->bWrappedMode)) && (*pRxlen == 1U))) {
      /* AF should always be accompanied by data. Otherwise
      it is a protocol error */
      return PH_ADD_COMPCODE_FIXED(PH_ERR_PROTOCOL_ERROR, PH_COMP_AL_MFDFEVX);
    }

    if (0U != (pDataParams->bWrappedMode)) {
      /* Next position will ensure overwriting on the
      SW1SW2 received from previous command */
      wNextPos = (*pRxlen) - 2U;
      (void)memcpy(bBackupBytes, &(*pResponse)[wNextPos - 3u], 3);
    } else {
      /* Backup the last byte */
      bBackupByte = (*pResponse)[(*pRxlen - 1)];
      (void)memcpy(bBackupBytes, &(*pResponse)[(*pRxlen - 3)], 3);
      wNextPos = (*pRxlen) - 1U;
    }

    PH_CHECK_SUCCESS_FCT(statusTmp, phhalHw_GetConfig(
            pDataParams->pHalDataParams,
            PHHAL_HW_CONFIG_RXBUFFER_BUFSIZE,
            &wRxBufferSize
        ));

    if (pDataParams->bAuthMode == PHAL_MFDFEVX_AUTHENTICATEAES) {
      bIvLen = 16;
    } else if ((pDataParams->bAuthMode == PHAL_MFDFEVX_AUTHENTICATEISO) ||
        (pDataParams->bAuthMode == PHAL_MFDFEVX_AUTHENTICATE)) {
      bIvLen = 8;
    } else {
      bIvLen = 0;
    }
  }

  while (bStatusByte == PHAL_MFDFEVX_RESP_ADDITIONAL_FRAME) {
    if (((pDataParams->bWrappedMode) && (*pRxlen == 2U)) ||
        ((!(pDataParams->bWrappedMode)) && (*pRxlen == 1U))) {
      /* AF should always be accompanied by data. Otherwise
      it is a protocol error */
      return PH_ADD_COMPCODE_FIXED(PH_ERR_PROTOCOL_ERROR, PH_COMP_AL_MFDFEVX);
    }
    if ((wNextPos + PHAL_MFDFEVX_MAX_FRAME_SIZE) >= wRxBufferSize) {
      /* Return 0xAF and let the caller recall the function with
      option = PH_EXCHANGE_RXCHAINING */
      /* Return the data accumulated till now and its length */
      if (0U != (pDataParams->bWrappedMode)) {
        (*pRxlen) -= 2u;
      } else {
        (*pRxlen) -= 1u;
        (*pResponse)++;
      }
      return PH_ADD_COMPCODE_FIXED(PH_ERR_SUCCESS_CHAINING, PH_COMP_AL_MFDFEVX);
    }
    PH_CHECK_SUCCESS_FCT(statusTmp, phhalHw_SetConfig(pDataParams->pHalDataParams,
            PHHAL_HW_CONFIG_RXBUFFER_STARTPOS,
            wNextPos
        ));

    bCmdBuff[0] = PHAL_MFDFEVX_RESP_ADDITIONAL_FRAME;
    wCmdLen = 1;
    if (0U != (pDataParams->bWrappedMode)) {
      pApdu[1] = bCmdBuff[0];  /* DESFire command code. */
      /* Encode APDU Length*/
      pApdu[4] = (uint8_t) wCmdLen - 1u; /* Set APDU Length. */

      statusTmp = phpalMifare_ExchangeL4(
              pDataParams->pPalMifareDataParams,
              (pApdu[4] == 0x00U) ? PH_EXCHANGE_DEFAULT : PH_EXCHANGE_BUFFER_FIRST,
              pApdu,
              PHAL_MFDFEVX_WRAP_HDR_LEN,
              &pRecv,
              pRxlen
          );
      if ((pApdu[4] != 0x00U) && (statusTmp == PH_ERR_SUCCESS)) {
        PH_CHECK_SUCCESS_FCT(statusTmp, phpalMifare_ExchangeL4(
                pDataParams->pPalMifareDataParams,
                PH_EXCHANGE_BUFFER_CONT,
                bCmdBuff,
                wCmdLen,
                &pRecv,
                pRxlen
            ));

        bCmdBuff[0] = 0x00; /* Le */
        statusTmp = phpalMifare_ExchangeL4(
                pDataParams->pPalMifareDataParams,
                PH_EXCHANGE_BUFFER_LAST,
                bCmdBuff,
                0x01,
                &pRecv,
                pRxlen
            );
      }
      /* To handle the case where the card returns only status 91 and returns
      AF in the next frame */
      if ((statusTmp & PH_ERR_MASK) == PH_ERR_SUCCESS_CHAINING) {
        /* One or two more status bytes to read from DesFire */
        bBackUpByte = pRecv[0];
        bBackUpByte1 = pRecv[1];
        wBackUpLen = *pRxlen;

        PH_CHECK_SUCCESS_FCT(statusTmp, phpalMifare_ExchangeL4(
                pDataParams->pPalMifareDataParams,
                PH_EXCHANGE_RXCHAINING,
                &pApdu[2],
                0x01,
                &pRecv,
                pRxlen
            ));

        /* Received length can be one or two Ex: 0x91 0xAF */
        if (*pRxlen == 2U) {
          pRecv[wBackUpLen] = pRecv[0];
          pRecv[wBackUpLen + 1U] = pRecv[1];
          bStatusByte = pRecv[1];
        } else if (*pRxlen == 1U) {
          bStatusByte = pRecv[0];
          pRecv[wBackUpLen] = bStatusByte;
        } else {
          return PH_ADD_COMPCODE_FIXED(PH_ERR_PROTOCOL_ERROR, PH_COMP_AL_MFDFEVX);
        }

        *pRxlen = wBackUpLen + *pRxlen;

        /* Set back the backed up bytes */
        pRecv[0] = bBackUpByte;
        pRecv[1] = bBackUpByte1;
      } else {
        if (statusTmp != PH_ERR_SUCCESS) {
          return statusTmp;
        }
      }
    } else {
      /* Send this on L4 */
      PH_CHECK_SUCCESS_FCT(statusTmp, phpalMifare_ExchangeL4(
              pDataParams->pPalMifareDataParams,
              wOption,
              bCmdBuff,
              wCmdLen,
              &pRecv,
              pRxlen
          ));
    }

    /* Update wNextPos */
    if (0U != (pDataParams->bWrappedMode)) {
      bStatusByte = (*pResponse)[(*pRxlen) - 1];

      /* Putback the backed up bytes */
      (void)memcpy(&(*pResponse)[wNextPos - 3u], bBackupBytes, 3);

      wNextPos = (*pRxlen) - 2U;
      (void)memcpy(bBackupBytes, &(*pResponse)[wNextPos - 3u], 3);
    } else {
      bStatusByte = (*pResponse)[wNextPos];

      /* Put back the previously backedup byte */
      (*pResponse)[wNextPos] = bBackupByte;

      /* Putback the backed up bytes */
      (void)memcpy(&(*pResponse)[wNextPos - 2u], bBackupBytes, 3);

      wNextPos = (*pRxlen) - 1U;
      bBackupByte = (*pResponse)[wNextPos];

      /* Backup 3 bytes. The nxt frame will overwrite these */
      (void)memcpy(bBackupBytes, &(*pResponse)[wNextPos - 2u], 3);
    }
  }
  if (0U != (pDataParams->bWrappedMode)) {
    (*pRxlen) -= 2u;
  } else {
    (*pRxlen) -= 1u;
    (*pResponse)++;
  }

  /* satisfy compiler */
  PH_UNUSED_VARIABLE(bIvLen);

  return phalMfdfEVx_Int_ComputeErrorResponse(pDataParams, bStatusByte);
}

phStatus_t phalMfdfEVx_Sw_Int_ISOGetData(phalMfdfEVx_Sw_DataParams_t *pDataParams,
    uint8_t *pSendBuff, uint16_t wCmdLen,
    uint8_t **pResponse, uint16_t *pRxlen)
{
  uint16_t   PH_MEMLOC_REM wOption;
  uint8_t    PH_MEMLOC_REM *pRecv = NULL;
  phStatus_t PH_MEMLOC_REM statusTmp = 0;
  phStatus_t PH_MEMLOC_REM status = 0;
  uint8_t    PH_MEMLOC_REM bCmdBuff[10];
  uint8_t    PH_MEMLOC_REM bApduLen =
      4;  /* Initializing with 4 since Length of the Data(Lc) starts from 4th element of pApdu[] */
  uint16_t   PH_MEMLOC_REM wNextPos = 0;
  uint16_t   PH_MEMLOC_REM wRxBufferSize = 0;
  uint8_t    PH_MEMLOC_REM bBackupBytes[3];
  uint8_t    PH_MEMLOC_REM pApdu[7] = { PHAL_MFDFEVX_WRAPPEDAPDU_CLA, 0x00, PHAL_MFDFEVX_WRAPPEDAPDU_P1, PHAL_MFDFEVX_WRAPPEDAPDU_P2, 0x00,/* Extended Length Apdu */ 0x00, 0x00 };
  uint8_t    PH_MEMLOC_REM bLe[2] = { 0x00, 0x00 };
  uint8_t    PH_MEMLOC_REM bExtendedLenApdu = 0;
  uint16_t    PH_MEMLOC_REM wFSD = 0;
  uint16_t    PH_MEMLOC_REM wFSC = 0;
  uint16_t   PH_MEMLOC_REM wTmp = 0;
  uint16_t   pValue;

  /* Status and two other bytes to be backed up before getting new frame of data */
  (void)memset(bBackupBytes, 0x00, 3);

  PH_CHECK_SUCCESS_FCT(statusTmp, phhalHw_GetConfig(
          pDataParams->pHalDataParams,
          PHHAL_HW_CONFIG_RXBUFFER_STARTPOS,
          &wTmp
      ));

  wOption = PH_EXCHANGE_DEFAULT;
  /*
     0xAF is just an indication that this is a call
     to the function to get remaining data
  */
  if (pSendBuff[0] != PHAL_MFDFEVX_RESP_ADDITIONAL_FRAME) {
    if (0U != (pDataParams->bWrappedMode)) {
      /* Check for permissible CmdBuff size */
      if (wCmdLen > PHAL_MFDFEVX_MAXWRAPPEDAPDU_SIZE) {
        return PH_ADD_COMPCODE_FIXED(PH_ERR_BUFFER_OVERFLOW, PH_COMP_AL_MFDFEVX);
      }

      pApdu[1] = pSendBuff[0];  /* DESFire command code. */
      switch (pApdu[1]) {
        case PHAL_MFDFEVX_CMD_READ_DATA:
        case PHAL_MFDFEVX_CMD_READ_DATA_ISO:
        case PHAL_MFDFEVX_CMD_READ_RECORDS:
        case PHAL_MFDFEVX_CMD_READ_RECORDS_ISO:
          /* Get the format value(Whether to use short APDU or extended APDU */
          PH_CHECK_SUCCESS_FCT(statusTmp, phalMfdfEVx_GetConfig(pDataParams,
                  PHAL_MFDFEVX_SHORT_LENGTH_APDU,
                  &pValue));
          /* To Note: Short APDU will be used,
           *  1. when user force the 'length' to be sent as short APDU in case of BIG ISO.
           *  2. When the data to read is not BIG ISO(less than 256 bytes).
           */
          if (0U != (pValue & 0x0001U)) {
            /* Encode 'Length' in Short APDU format */
            pApdu[bApduLen++] = (uint8_t) wCmdLen - 1u; /* Set APDU Length. */
          } else {
            /* Encode 'Length' in extended Length format */
            bExtendedLenApdu = 0x01;
            pApdu[bApduLen++] = 0x00;
            pApdu[bApduLen++] = 0x00;
            pApdu[bApduLen++] = (uint8_t) wCmdLen - 1u; /* Set APDU Length. */
          }
          break;

        default:
          /* Rest other commands, retain existing implementation which is Short APDU */
          pApdu[bApduLen++] = (uint8_t) wCmdLen - 1u; /* Set APDU Length. */
          break;
      }
      status = phpalMifare_ExchangeL4(
              pDataParams->pPalMifareDataParams,
              (pApdu[bApduLen - 1] == 0x00) ? PH_EXCHANGE_DEFAULT : PH_EXCHANGE_BUFFER_FIRST,
              pApdu,
              bApduLen,
              &pRecv,
              pRxlen
          );
      /* Check if pApdu[4] is valid in case of Short APDU or
       * Check if pAdpu[6] is valid in case of Extended APDU
       */
      if (((pApdu[4] != 0x00U) && (status == PH_ERR_SUCCESS)) ||
          ((bExtendedLenApdu && (pApdu[6] != 0x00U)) && (status == PH_ERR_SUCCESS))) {
        PH_CHECK_SUCCESS_FCT(statusTmp, phpalMifare_ExchangeL4(
                pDataParams->pPalMifareDataParams,
                PH_EXCHANGE_BUFFER_CONT,
                &pSendBuff[1],
                wCmdLen - 1u,
                &pRecv,
                pRxlen
            ));

        PH_CHECK_SUCCESS_FCT(statusTmp, phpalMifare_ExchangeL4(
                pDataParams->pPalMifareDataParams,
                PH_EXCHANGE_BUFFER_LAST,
                bLe,
                bExtendedLenApdu ? 0x02 : 0x01,
                &pRecv,
                pRxlen
            ));
      }
    } else {
      /* Normal mode */
      if (wCmdLen > PHAL_MFDFEVX_MAXDFAPDU_SIZE) {
        return PH_ADD_COMPCODE_FIXED(PH_ERR_BUFFER_OVERFLOW, PH_COMP_AL_MFDFEVX);
      }

      /* Send this on L4 */
      status = phpalMifare_ExchangeL4(
              pDataParams->pPalMifareDataParams,
              wOption,
              pSendBuff,
              wCmdLen,
              &pRecv,
              pRxlen
          );
    }
  } else {
    /* Send this on L4 */
    status = phpalMifare_ExchangeL4(
            pDataParams->pPalMifareDataParams,
            PH_EXCHANGE_RXCHAINING,
            pSendBuff,
            wCmdLen,
            &pRecv,
            pRxlen
        );
  }

  if ((status != PH_ERR_SUCCESS) && ((status & PH_ERR_MASK) != PH_ERR_SUCCESS_CHAINING)) {
    return status;
  }

  /* Storing the original pointer */
  *pResponse = pRecv;

  if ((status & PH_ERR_MASK) == PH_ERR_SUCCESS_CHAINING) {
    if (0U != (pDataParams->bWrappedMode)) {
      /* Next position will ensure overwriting on the
      SW1SW2 received from previous command */
      wNextPos = (*pRxlen) - 2U;
      (void)memcpy(bBackupBytes, &(*pResponse)[wNextPos - 3u], 3);
    } else {
      /* Backup the last byte */
      (void)memcpy(bBackupBytes, &(*pResponse)[(*pRxlen - 3)], 3);
      wNextPos = *pRxlen;
    }

    PH_CHECK_SUCCESS_FCT(statusTmp, phhalHw_GetConfig(
            pDataParams->pHalDataParams,
            PHHAL_HW_CONFIG_RXBUFFER_BUFSIZE,
            &wRxBufferSize
        ));
  }

  while ((status & PH_ERR_MASK) == PH_ERR_SUCCESS_CHAINING) {
    /* Get the Frame length */
    PH_CHECK_SUCCESS_FCT(statusTmp, phalMfdfEVx_Sw_Int_GetFrameLength(
            pDataParams,
            &wFSD,
            &wFSC
        ));

    if (wFSD > wFSC) {
      if ((wNextPos + wFSC) >= wRxBufferSize) {
        /* Return Chaining and let the caller recall the function with
        option = PH_EXCHANGE_RXCHAINING */
        /* Return the data accumulated till now and its length */
        if ((pSendBuff[0] != PHAL_MFDFEVX_RESP_ADDITIONAL_FRAME) && (!pDataParams->bWrappedMode)) {
          (*pRxlen) -= 1u;
          (*pResponse)++;
        }
        return PH_ADD_COMPCODE_FIXED(PH_ERR_SUCCESS_CHAINING, PH_COMP_AL_MFDFEVX);
      }
    } else {
      if ((wNextPos + wFSD) >= wRxBufferSize) {
        /* Return Chaining and let the caller recall the function with
        option = PH_EXCHANGE_RXCHAINING */
        /* Return the data accumulated till now and its length */
        if (0U != (pDataParams->bWrappedMode)) {
          (*pRxlen) -= 2u;
        }

        return PH_ADD_COMPCODE_FIXED(PH_ERR_SUCCESS_CHAINING, PH_COMP_AL_MFDFEVX);
      }
    }

    PH_CHECK_SUCCESS_FCT(statusTmp, phhalHw_SetConfig(
            pDataParams->pHalDataParams,
            PHHAL_HW_CONFIG_RXBUFFER_STARTPOS,
            wNextPos
        ));

    /* Send this on L4 */
    status = phpalMifare_ExchangeL4(
            pDataParams->pPalMifareDataParams,
            PH_EXCHANGE_RXCHAINING,
            bCmdBuff,
            wCmdLen,
            &pRecv,
            pRxlen
        );

    /* Update wNextPos */
    if (0U != (pDataParams->bWrappedMode)) {
      /* Putback the backed up bytes */
      (void)memcpy(&(*pResponse)[wNextPos - 3u], bBackupBytes, 3);

      /* Update the Buffer Position */
      wNextPos = (*pRxlen) - 2U;
    } else {
      /* Putback the backed up bytes */
      (void)memcpy(&(*pResponse)[wNextPos - 3u], bBackupBytes, 3);

      /* Update the Buffer Position */
      wNextPos = *pRxlen;
    }
    /* Backup 3 bytes. The nxt frame will overwrite these */
    (void)memcpy(bBackupBytes, &(*pResponse)[wNextPos - 3u], 3);
  }

  /* Status is 0x00? */
  if (0U != (pDataParams->bWrappedMode)) {
    statusTmp = pRecv[(*pRxlen) - 1];
    (*pRxlen) -= 2u;
  } else {
    if (pSendBuff[0] != PHAL_MFDFEVX_RESP_ADDITIONAL_FRAME) {
      statusTmp = pRecv[wTmp];
      (*pRxlen) -= 1u;
      (*pResponse)++;
    } else {
      statusTmp = status;
    }
  }

  return phalMfdfEVx_Int_ComputeErrorResponse(pDataParams, statusTmp);
}

phStatus_t phalMfdfEVx_Sw_Int_ReadData_Plain(phalMfdfEVx_Sw_DataParams_t *pDataParams,
    uint8_t bOption, uint8_t *bCmdBuff,
    uint16_t wCmdLen, uint8_t **ppRxdata, uint16_t *pRxdataLen)
{
  uint16_t    PH_MEMLOC_REM status = 0;
  uint16_t    PH_MEMLOC_REM wRxlen = 0;
  uint8_t     PH_MEMLOC_REM *pRecv = NULL;
  uint8_t     PH_MEMLOC_REM bWorkBuffer[32];
#ifdef NXPBUILD__PHAL_MFDFEVX_NDA
  uint16_t    PH_MEMLOC_REM statusTmp = 0;
  uint16_t    PH_MEMLOC_REM wNumBlocks = 0;
  uint8_t     PH_MEMLOC_REM bCMAC[PH_CRYPTOSYM_AES_BLOCK_SIZE];
  uint16_t    PH_MEMLOC_REM wTmp = 0;
  uint8_t     PH_MEMLOC_REM bCMacCard[8];
  uint8_t     PH_MEMLOC_REM *pTmp = NULL;
  uint8_t     PH_MEMLOC_REM bMacLen = 0;
  uint8_t     PH_MEMLOC_REM bIvLen = 0;
#endif /* NXPBUILD__PHAL_MFDFEVX_NDA */
  uint16_t    PH_MEMLOC_REM wWorkBufferLen = 0;

  (void)memset(bWorkBuffer, 0x00, 32);
#ifdef NXPBUILD__PHAL_MFDFEVX_NDA
  (void)memset(bCMAC, 0x00, PH_CRYPTOSYM_AES_BLOCK_SIZE);
  (void)memset(bCMacCard, 0x00, 8);
#endif /* NXPBUILD__PHAL_MFDFEVX_NDA */

  /* Copy the bCmdBuff data to the bWorkBuff */
  (void)memcpy(bWorkBuffer, bCmdBuff, wCmdLen);
  wWorkBufferLen = wCmdLen;

#ifdef NXPBUILD__PHAL_MFDFEVX_NDA
  if ((pDataParams->bAuthMode == PHAL_MFDFEVX_AUTHENTICATEAES) ||
      (pDataParams->bAuthMode == PHAL_MFDFEVX_AUTHENTICATEEV2)) {
    bIvLen = PH_CRYPTOSYM_AES_BLOCK_SIZE;
  } else {
    bIvLen = PH_CRYPTOSYM_DES_BLOCK_SIZE;
  }

  if (bCmdBuff[0] != PHAL_MFDFEVX_RESP_ADDITIONAL_FRAME) {
    /* Check for 0xAF added above to ensure that we dont update the
    IV or calculate CMAC for cases where in the application has called
    this API with bOption = PH_EXCHANGE_RXCHAINING */
    if ((pDataParams->bAuthMode == PHAL_MFDFEVX_AUTHENTICATEISO) ||
        (pDataParams->bAuthMode == PHAL_MFDFEVX_AUTHENTICATEAES)) {
      /* Load Iv */
      PH_CHECK_SUCCESS_FCT(statusTmp, phCryptoSym_LoadIv(
              pDataParams->pCryptoDataParamsEnc,
              pDataParams->bIv,
              bIvLen
          ));

      /* Calculate MAC to update the init vector */
      PH_CHECK_SUCCESS_FCT(statusTmp, phCryptoSym_CalculateMac(
              pDataParams->pCryptoDataParamsEnc,
              (PH_CRYPTOSYM_MAC_MODE_CMAC),
              bWorkBuffer,
              wWorkBufferLen,
              bCMAC,
              &bMacLen
          ));
      /* Store the IV */
      (void)memcpy(pDataParams->bIv, bCMAC, bIvLen);
      bMacLen = 0;

      if ((bOption & PHAL_MFDFEVX_COMMUNICATION_MAC_ON_CMD) == PHAL_MFDFEVX_COMMUNICATION_MAC_ON_CMD) {
        /* Append MAC for ISO/AES mode- in case of AES, the 16 byte
         * CMAC is truncated to the 8 leftmost bytes.
         */
        (void)memcpy(&bWorkBuffer[wWorkBufferLen], &bCMAC[0], PH_CRYPTOSYM_DES_BLOCK_SIZE);
        wWorkBufferLen += PH_CRYPTOSYM_DES_BLOCK_SIZE;
      }
    } else if ((pDataParams->bAuthMode == PHAL_MFDFEVX_AUTHENTICATEEV2) &&
        ((bOption & 0xF0U) == PHAL_MFDFEVX_COMMUNICATION_MACD)) {
      (void)memset(pDataParams->bIv, 0x00, bIvLen);
      wWorkBufferLen = 0;
      bWorkBuffer[wWorkBufferLen++] = bCmdBuff[0];
      /* Add CmdCtr and TI for MAC calculation */
      bWorkBuffer[wWorkBufferLen++] = (uint8_t)(pDataParams->wCmdCtr);
      bWorkBuffer[wWorkBufferLen++] = (uint8_t)(pDataParams->wCmdCtr >> 8U);
      (void)memcpy(&bWorkBuffer[wWorkBufferLen], pDataParams->bTi, PHAL_MFDFEVX_SIZE_TI);
      wWorkBufferLen += PHAL_MFDFEVX_SIZE_TI;

      /* Assumed here that a read-like commands cannot in any case have cmd+header+data > 24 bytes */

      if (wCmdLen > 1U) {
        (void)memcpy(&bWorkBuffer[wWorkBufferLen], &bCmdBuff[1], (wCmdLen - 1u));
        wWorkBufferLen += (wCmdLen - 1u);
      }

      /* Load Iv */
      PH_CHECK_SUCCESS_FCT(statusTmp, phCryptoSym_LoadIv(
              pDataParams->pCryptoDataParamsMac,
              pDataParams->bIv,
              bIvLen
          ));

      /* Calculate MAC */
      PH_CHECK_SUCCESS_FCT(statusTmp, phCryptoSym_CalculateMac(
              pDataParams->pCryptoDataParamsMac,
              (PH_CRYPTOSYM_MAC_MODE_CMAC),
              bWorkBuffer,
              wWorkBufferLen,
              bCMAC,
              &bMacLen
          ));

      /* Truncate the MAC generated */
      phalMfdfEVx_Sw_Int_TruncateMac(bCMAC);

      /* Get the original command in the work buffer. */
      (void)memcpy(bWorkBuffer, bCmdBuff, wCmdLen);
      /* Append MAC for EV2 mode. */
      (void)memcpy(&bWorkBuffer[wCmdLen], bCMAC, PHAL_MFDFEVX_TRUNCATED_MAC_SIZE);
      wWorkBufferLen = wCmdLen + PHAL_MFDFEVX_TRUNCATED_MAC_SIZE;
    } else if ((pDataParams->bAuthMode == PHAL_MFDFEVX_AUTHENTICATE) &&
        ((bOption & PHAL_MFDFEVX_COMMUNICATION_MAC_ON_CMD) == PHAL_MFDFEVX_COMMUNICATION_MAC_ON_CMD)) {
      /* Load Iv */
      (void)memset(pDataParams->bIv, 0, bIvLen);

      PH_CHECK_SUCCESS_FCT(statusTmp, phCryptoSym_LoadIv(
              pDataParams->pCryptoDataParamsEnc,
              pDataParams->bIv,
              bIvLen
          ));

      /* Calculate MAC to update the init vector */
      PH_CHECK_SUCCESS_FCT(statusTmp, phCryptoSym_CalculateMac(
              pDataParams->pCryptoDataParamsEnc,
              (PH_CRYPTOSYM_MAC_MODE_CBCMAC),
              &bWorkBuffer[1],
              wWorkBufferLen - 1,
              bCMAC,
              &bMacLen
          ));

      /* Append MAC for D40 mode- truncated to the leftmost 4 bytes. */
      (void)memcpy(&bWorkBuffer[wWorkBufferLen], &bCMAC[0], 4);

      wWorkBufferLen += 4U;
    } else {
      /*Do Nothing. This is for PRQA compliance */
    }
  }
#endif /* NXPBUILD__PHAL_MFDFEVX_NDA */

  if (0U != (bOption & PHAL_MFDFEVX_ISO_CHAINING_MODE)) {
    status = phalMfdfEVx_Sw_Int_ISOGetData(
            pDataParams,
            bWorkBuffer,
            wWorkBufferLen,
            &pRecv,
            &wRxlen
        );
  } else {
    /* Send the command */
    status = phalMfdfEVx_Sw_Int_GetData(
            pDataParams,
            bWorkBuffer,
            wWorkBufferLen,
            &pRecv,
            &wRxlen
        );
  }

  if (((status & PH_ERR_MASK) != PH_ERR_SUCCESS) &&
      ((status & PH_ERR_MASK) != PH_ERR_SUCCESS_CHAINING)) {
#ifdef NXPBUILD__PHAL_MFDFEVX_NDA
    /* Reset authentication status */
    if ((pDataParams->bAuthMode == PHAL_MFDFEVX_AUTHENTICATEISO) ||
        (pDataParams->bAuthMode == PHAL_MFDFEVX_AUTHENTICATEAES) ||
        (pDataParams->bAuthMode == PHAL_MFDFEVX_AUTHENTICATEEV2)) {
      phalMfdfEVx_Sw_Int_ResetAuthStatus(pDataParams);
    }
    /* Set the length pointer with valid value. Otherwise there will be an error in AL while logging. (Access violation in addess 0xccccccc) */
    *pRxdataLen = wRxlen;
    *ppRxdata = pRecv;
    /* Component code is already added by GetData */
#endif /* NXPBUILD__PHAL_MFDFEVX_NDA */
    return status;
  }

  if ((pDataParams->bAuthMode == PHAL_MFDFEVX_AUTHENTICATEEV2) &&
      (bCmdBuff[0] != PHAL_MFDFEVX_RESP_ADDITIONAL_FRAME)) {
    /* Increment the command counter. This increments irrespective of
    * Plain mode or MAC mode. Ensuring here that it is incremented
    * only for the case where the user has called this for the first
    * time i.e., without PH_EXCHANGE_RXCHAINING option
    */
    pDataParams->wCmdCtr++;
  }

#ifdef NXPBUILD__PHAL_MFDFEVX_NDA
  /* Verify the MAC */
  if ((pDataParams->bAuthMode == PHAL_MFDFEVX_AUTHENTICATEISO) ||
      (pDataParams->bAuthMode == PHAL_MFDFEVX_AUTHENTICATEAES)) {
    if (bCmdBuff[0] != PHAL_MFDFEVX_RESP_ADDITIONAL_FRAME) {
      PH_CHECK_SUCCESS_FCT(statusTmp, phCryptoSym_LoadIv(
              pDataParams->pCryptoDataParamsEnc,
              pDataParams->bIv,
              bIvLen
          ));
    }

    if ((status & PH_ERR_MASK) != PH_ERR_SUCCESS_CHAINING) {
      (void)memcpy(bCMacCard, &pRecv[wRxlen - 8u], 8);
      wRxlen -= 8u;
      pRecv[wRxlen] = (uint8_t) status;

      /* Calculate CMAC */
      PH_CHECK_SUCCESS_FCT(statusTmp, phCryptoSym_CalculateMac(
              pDataParams->pCryptoDataParamsEnc,
              PH_CRYPTOSYM_MAC_MODE_CMAC | PH_EXCHANGE_BUFFER_LAST,
              pRecv,
              wRxlen + 1U,
              bCMAC,
              &bMacLen
          ));

      if (memcmp(bCMAC, bCMacCard, 8) != 0) {
        /* CMAC validation failed */
        return PH_ADD_COMPCODE_FIXED(PH_ERR_INTEGRITY_ERROR, PH_COMP_AL_MFDFEVX);
      }

      /* Update IV to be used for next commands */
      (void)memcpy(pDataParams->bIv, bCMAC, bIvLen);
    } else {
      /* Calculate CMAC. Here the data length should be multiple of IV size */
      PH_CHECK_SUCCESS_FCT(statusTmp, phCryptoSym_CalculateMac(
              pDataParams->pCryptoDataParamsEnc,
              (PH_CRYPTOSYM_MAC_MODE_CMAC | PH_EXCHANGE_BUFFER_CONT),
              pRecv,
              wRxlen,
              bCMAC,
              &bMacLen
          ));
    }
  } else if ((pDataParams->bAuthMode == PHAL_MFDFEVX_AUTHENTICATEEV2) &&
      ((bOption & 0xF0U) == PHAL_MFDFEVX_COMMUNICATION_MACD)) {
    if (bCmdBuff[0] != PHAL_MFDFEVX_RESP_ADDITIONAL_FRAME) {
      PH_CHECK_SUCCESS_FCT(statusTmp, phCryptoSym_LoadIv(
              pDataParams->pCryptoDataParamsMac,
              pDataParams->bIv,
              bIvLen
          ));

      pDataParams->bNoUnprocBytes = 0;
      /* Return code */
      pDataParams->pUnprocByteBuff[pDataParams->bNoUnprocBytes++] = 0x00;
      /* Lower byte of CmdCtr */
      pDataParams->pUnprocByteBuff[pDataParams->bNoUnprocBytes++] = (uint8_t)(pDataParams->wCmdCtr);
      /* Higher byte of CmdCtr */
      pDataParams->pUnprocByteBuff[pDataParams->bNoUnprocBytes++] = (uint8_t)(
              pDataParams->wCmdCtr >> 8U);
      /* TI */
      (void)memcpy(&pDataParams->pUnprocByteBuff[pDataParams->bNoUnprocBytes], pDataParams->bTi,
          PHAL_MFDFEVX_SIZE_TI);
      pDataParams->bNoUnprocBytes += PHAL_MFDFEVX_SIZE_TI;
    }

    if ((status & PH_ERR_MASK) == PH_ERR_SUCCESS) {
      (void)memcpy(bCMacCard, &pRecv[wRxlen - 8u], 8);
      wRxlen -= 8u;

      /* If receieved data is not multiple of block size */
      wTmp = (PH_CRYPTOSYM_AES_BLOCK_SIZE - pDataParams->bNoUnprocBytes);
      if (wTmp >= wRxlen) {
        wTmp = wRxlen;
      }
      (void)memcpy(&pDataParams->pUnprocByteBuff[pDataParams->bNoUnprocBytes], pRecv, wTmp);
      pDataParams->bNoUnprocBytes += (uint8_t) wTmp;

      if (wTmp == wRxlen) {
        /* Conclude the CMAC calculation. */
        PH_CHECK_SUCCESS_FCT(statusTmp, phCryptoSym_CalculateMac(
                pDataParams->pCryptoDataParamsMac,
                (PH_CRYPTOSYM_MAC_MODE_CMAC | PH_EXCHANGE_BUFFER_LAST),
                pDataParams->pUnprocByteBuff,
                (pDataParams->bNoUnprocBytes),
                bCMAC,
                &bMacLen
            ));
      } else {
        /* First send the 16 byte block for cmac calculation */
        PH_CHECK_SUCCESS_FCT(statusTmp, phCryptoSym_CalculateMac(
                pDataParams->pCryptoDataParamsMac,
                (PH_CRYPTOSYM_MAC_MODE_CMAC | PH_EXCHANGE_BUFFER_CONT),
                pDataParams->pUnprocByteBuff,
                (pDataParams->bNoUnprocBytes),
                bCMAC,
                &bMacLen
            ));

        /* Send rest of the received data */
        PH_CHECK_SUCCESS_FCT(statusTmp, phCryptoSym_CalculateMac(
                pDataParams->pCryptoDataParamsMac,
                (PH_CRYPTOSYM_MAC_MODE_CMAC | PH_EXCHANGE_BUFFER_LAST),
                &pRecv[wTmp],
                wRxlen - wTmp,
                bCMAC,
                &bMacLen
            ));
      }

      /* Since end of response is reached reset the pDataParams bNoUnprocBytes member to 0 */
      pDataParams->bNoUnprocBytes = 0;

      /* Truncate the MAC generated */
      phalMfdfEVx_Sw_Int_TruncateMac(bCMAC);

      /* Compare the CMAC received and Calculated MAC */
      if (memcmp(bCMAC, bCMacCard, 8) != 0) {
        /* CMAC validation failed */
        return PH_ADD_COMPCODE_FIXED(PH_ERR_INTEGRITY_ERROR, PH_COMP_AL_MFDFEVX);
      }
    } else {
      /* Handling of chaining. */
      /* Include the left over data for CMAC calculation */
      wTmp = (PH_CRYPTOSYM_AES_BLOCK_SIZE - pDataParams->bNoUnprocBytes);
      (void)memcpy(&pDataParams->pUnprocByteBuff[pDataParams->bNoUnprocBytes], pRecv, wTmp);
      pDataParams->bNoUnprocBytes += (uint8_t) wTmp;

      /* Start MAC calculation with one full block size data */
      PH_CHECK_SUCCESS_FCT(statusTmp, phCryptoSym_CalculateMac(
              pDataParams->pCryptoDataParamsMac,
              (PH_CRYPTOSYM_MAC_MODE_CMAC | PH_EXCHANGE_BUFFER_CONT),
              pDataParams->pUnprocByteBuff,
              (pDataParams->bNoUnprocBytes),
              bCMAC,
              &bMacLen
          ));

      PH_CHECK_SUCCESS_FCT(statusTmp, phCryptoSym_CalculateMac(
              pDataParams->pCryptoDataParamsMac,
              (PH_CRYPTOSYM_MAC_MODE_CMAC | PH_EXCHANGE_BUFFER_CONT),
              &pRecv[wTmp],
              ((wRxlen - wTmp) / PH_CRYPTOSYM_AES_BLOCK_SIZE) * PH_CRYPTOSYM_AES_BLOCK_SIZE,
              bCMAC,
              &bMacLen
          ));

      /* Remaining bytes */
      wTmp = (wRxlen - wTmp) % PH_CRYPTOSYM_AES_BLOCK_SIZE;

      /* Update the UnprocByteBuffer with bytes not used for mac calculation */
      (void)memcpy(pDataParams->pUnprocByteBuff, &pRecv[wRxlen - wTmp], wTmp);
      pDataParams->bNoUnprocBytes = (uint8_t) wTmp;
    }
  } else if ((pDataParams->bAuthMode == PHAL_MFDFEVX_AUTHENTICATE)
      && ((bOption & 0xF3U) == (PHAL_MFDFEVX_COMMUNICATION_MACD |
              PHAL_MFDFEVX_COMMUNICATION_MAC_ON_RC))) {
    PH_CHECK_SUCCESS_FCT(statusTmp, phCryptoSym_LoadIv(
            pDataParams->pCryptoDataParamsEnc,
            pDataParams->bIv,
            bIvLen
        ));

    if ((status & PH_ERR_MASK) != PH_ERR_SUCCESS_CHAINING) {
      (void)memcpy(bCMacCard, &pRecv[wRxlen - 4u], 4);
      wRxlen -= 4u;
    }

    wNumBlocks = wRxlen / bIvLen;
    pTmp = pRecv;
    while (0U != wNumBlocks) {
      /* Encrypt */
      PH_CHECK_SUCCESS_FCT(statusTmp, phCryptoSym_Encrypt(
              pDataParams->pCryptoDataParamsEnc,
              (PH_CRYPTOSYM_CIPHER_MODE_CBC),
              pTmp,
              bIvLen,
              bWorkBuffer
          ));
      pTmp += bIvLen;
      wNumBlocks--;
      (void)memcpy(pDataParams->bIv, bWorkBuffer, bIvLen);

      PH_CHECK_SUCCESS_FCT(statusTmp, phCryptoSym_LoadIv(
              pDataParams->pCryptoDataParamsEnc,
              pDataParams->bIv,
              bIvLen
          ));
    }
    if (0U != (wRxlen % bIvLen)) {
      /* In case data to be read is longer than the RxBuffer size,
      the data is always sent in multiples of iv sizes from the card.
      Control should never come here when data read is still not
      complete */

      PH_CHECK_SUCCESS_FCT(statusTmp, phCryptoSym_LoadIv(
              pDataParams->pCryptoDataParamsEnc,
              pDataParams->bIv,
              bIvLen
          ));
      (void)memcpy(bWorkBuffer, &pRecv[wRxlen - (wRxlen % bIvLen)], wRxlen % bIvLen);

      /* Apply padding */
      PH_CHECK_SUCCESS_FCT(statusTmp, phCryptoSym_ApplyPadding(
              PH_CRYPTOSYM_PADDING_MODE_1,
              bWorkBuffer,
              wRxlen % bIvLen,
              bIvLen,
              (uint16_t)(sizeof(bWorkBuffer)),
              bWorkBuffer,
              &wTmp
          ));
      /* Encrypt */
      PH_CHECK_SUCCESS_FCT(statusTmp, phCryptoSym_Encrypt(
              pDataParams->pCryptoDataParamsEnc,
              (PH_CRYPTOSYM_CIPHER_MODE_CBC),
              bWorkBuffer,
              wTmp,
              bWorkBuffer
          ));
    }
    if ((status & PH_ERR_MASK) != PH_ERR_SUCCESS_CHAINING) {
      (void)memcpy(bCMAC, bWorkBuffer, 4);
      if (memcmp(bCMAC, bCMacCard, 4) != 0) {
        /* MAC validation failed */
        return PH_ADD_COMPCODE_FIXED(PH_ERR_INTEGRITY_ERROR, PH_COMP_AL_MFDFEVX);
      }
      /* Reset IV */
      (void)memset(pDataParams->bIv, 0x00, bIvLen);
    }
  } else {
    /* Will come here in case data transfer is plain
    and auth mode is 0x0A */
    bIvLen = 0x00;
  }
#endif /* NXPBUILD__PHAL_MFDFEVX_NDA */

  *ppRxdata = pRecv;
  *pRxdataLen = wRxlen;

  if ((status & PH_ERR_MASK) == PH_ERR_SUCCESS_CHAINING) {
    return PH_ADD_COMPCODE_FIXED(PH_ERR_SUCCESS_CHAINING, PH_COMP_AL_MFDFEVX);;
  }

  return PH_ERR_SUCCESS;
}

#ifdef NXPBUILD__PHAL_MFDFEVX_NDA
phStatus_t phalMfdfEVx_Sw_Int_ReadData_Enc(phalMfdfEVx_Sw_DataParams_t *UNALIGNED pDataParams,
    uint8_t bOption, uint8_t *bCmdBuff,
    uint16_t wCmdLen, uint8_t **ppRxdata, uint16_t *pRxdataLen)
{
  uint16_t    PH_MEMLOC_REM status;
  uint16_t    PH_MEMLOC_REM statusTmp;
  uint16_t    PH_MEMLOC_REM wRxlen = 0;
  uint8_t     PH_MEMLOC_REM bCMAC[PH_CRYPTOSYM_AES_BLOCK_SIZE] = {0};
  uint8_t     PH_MEMLOC_REM bMacLen;
  uint32_t    PH_MEMLOC_REM dwIndex;
  uint8_t     PH_MEMLOC_REM bNumPaddingBytes;
  uint8_t     PH_MEMLOC_REM bIvLen = 0;
  uint8_t     PH_MEMLOC_REM *pRecv = NULL;
  uint8_t     PH_MEMLOC_REM *pCrc = NULL;
  uint8_t     PH_MEMLOC_REM *bTmpIV[16];
  uint8_t     PH_MEMLOC_REM bWorkBuffer[32];
  uint16_t    PH_MEMLOC_REM wWorkBufferLen = 0;
  uint8_t     PH_MEMLOC_REM bCMacCard[8];
  uint16_t    PH_MEMLOC_REM wTmp = 0;
  uint8_t     PH_MEMLOC_REM bPiccStatus = 0;

  /* Copy the bCmdBuff data to the bWorkBuff */
  (void)memcpy(bWorkBuffer, bCmdBuff, wCmdLen);
  wWorkBufferLen = wCmdLen;

  if (((pDataParams->bAuthMode == PHAL_MFDFEVX_NOT_AUTHENTICATED) ||
          ((bOption & 0xF0U) != PHAL_MFDFEVX_COMMUNICATION_ENC))) {
    return PH_ADD_COMPCODE_FIXED(PH_ERR_USE_CONDITION, PH_COMP_AL_MFDFEVX);
  }
  if ((pDataParams->bAuthMode == PHAL_MFDFEVX_AUTHENTICATEAES) ||
      (pDataParams->bAuthMode == PHAL_MFDFEVX_AUTHENTICATEEV2)) {
    bIvLen = PH_CRYPTOSYM_AES_BLOCK_SIZE;
  } else {
    bIvLen = PH_CRYPTOSYM_DES_BLOCK_SIZE;
  }

  if (((pDataParams->bAuthMode == PHAL_MFDFEVX_AUTHENTICATEISO) ||
          (pDataParams->bAuthMode == PHAL_MFDFEVX_AUTHENTICATEAES)) &&
      (bCmdBuff[0] != PHAL_MFDFEVX_RESP_ADDITIONAL_FRAME)) {
    /* Load Iv */
    PH_CHECK_SUCCESS_FCT(statusTmp, phCryptoSym_LoadIv(
            pDataParams->pCryptoDataParamsEnc,
            pDataParams->bIv,
            bIvLen
        ));

    /* Calculate MAC to update the init vector */
    PH_CHECK_SUCCESS_FCT(statusTmp, phCryptoSym_CalculateMac(
            pDataParams->pCryptoDataParamsEnc,
            (PH_CRYPTOSYM_MAC_MODE_CMAC),
            bCmdBuff,
            wCmdLen,
            bCMAC,
            &bMacLen
        ));
    /* Store the IV */
    (void)memcpy(pDataParams->bIv, bCMAC, bIvLen);
  } else if ((pDataParams->bAuthMode == PHAL_MFDFEVX_AUTHENTICATEEV2) &&
      (bCmdBuff[0] != PHAL_MFDFEVX_RESP_ADDITIONAL_FRAME)) {
    (void)memset(pDataParams->bIv, 0x00, bIvLen);
    wWorkBufferLen = 0;
    bWorkBuffer[wWorkBufferLen++] = bCmdBuff[0];
    /* Add CmdCtr and TI for MAC calculation */
    bWorkBuffer[wWorkBufferLen++] = (uint8_t)(pDataParams->wCmdCtr);
    bWorkBuffer[wWorkBufferLen++] = (uint8_t)(pDataParams->wCmdCtr >> 8U);
    (void)memcpy(&bWorkBuffer[wWorkBufferLen], pDataParams->bTi, PHAL_MFDFEVX_SIZE_TI);
    wWorkBufferLen += PHAL_MFDFEVX_SIZE_TI;

    if (wCmdLen > 1U) {
      (void)memcpy(&bWorkBuffer[wWorkBufferLen], &bCmdBuff[1], (wCmdLen - 1u));
      wWorkBufferLen += (wCmdLen - 1u);
    }

    /* Load Iv */
    PH_CHECK_SUCCESS_FCT(statusTmp, phCryptoSym_LoadIv(
            pDataParams->pCryptoDataParamsMac,
            pDataParams->bIv,
            bIvLen
        ));

    /* Calculate MAC */
    PH_CHECK_SUCCESS_FCT(statusTmp, phCryptoSym_CalculateMac(
            pDataParams->pCryptoDataParamsMac,
            PH_CRYPTOSYM_MAC_MODE_CMAC,
            bWorkBuffer,
            wWorkBufferLen,
            bCMAC,
            &bMacLen
        ));

    /* Truncate the MAC generated */
    phalMfdfEVx_Sw_Int_TruncateMac(bCMAC);

    /* Get the original command in the work buffer. */
    (void)memcpy(bWorkBuffer, bCmdBuff, wCmdLen);
    /* Append MAC for EV2 mode. */
    (void)memcpy(&bWorkBuffer[wCmdLen], bCMAC, PHAL_MFDFEVX_TRUNCATED_MAC_SIZE);
    wWorkBufferLen = wCmdLen + PHAL_MFDFEVX_TRUNCATED_MAC_SIZE;
  } else {
    /*Do Nothing. This is for PRQA compliance */
  }

  if (0U != (bOption & PHAL_MFDFEVX_ISO_CHAINING_MODE)) {
    /* Send the command */
    status = phalMfdfEVx_Sw_Int_ISOGetData(
            pDataParams,
            bWorkBuffer,
            wWorkBufferLen,
            &pRecv,
            &wRxlen
        );
  } else {
    /* Send the command */
    status = phalMfdfEVx_Sw_Int_GetData(
            pDataParams,
            bWorkBuffer,
            wWorkBufferLen,
            &pRecv,
            &wRxlen
        );
  }
  if (((status & PH_ERR_MASK) != PH_ERR_SUCCESS) &&
      ((status & PH_ERR_MASK) != PH_ERR_SUCCESS_CHAINING)) {
    /* Reset authentication status */
    if ((pDataParams->bAuthMode == PHAL_MFDFEVX_AUTHENTICATEISO) ||
        (pDataParams->bAuthMode == PHAL_MFDFEVX_AUTHENTICATEAES) ||
        (pDataParams->bAuthMode == PHAL_MFDFEVX_AUTHENTICATEEV2)) {
      phalMfdfEVx_Sw_Int_ResetAuthStatus(pDataParams);
    }
    /* Set the length pointer with valid value. Otherwise there will be an error in AL while logging. (Access violation in addess 0xccccccc) */
    *pRxdataLen = wRxlen;
    *ppRxdata = pRecv;
    return status;
  }

  /* Update the PICC Status as this will be used for CRC calculation. */
  bPiccStatus = (uint8_t)((bCmdBuff[0] == PHAL_MFDFEVX_CMD_READ_SIG) ? 0x90 : 0x00);

  if (pDataParams->bAuthMode == PHAL_MFDFEVX_AUTHENTICATEEV2) {
    if (bCmdBuff[0] != PHAL_MFDFEVX_RESP_ADDITIONAL_FRAME) {
      /* Increment the command counter */
      pDataParams->wCmdCtr++;

      pDataParams->bNoUnprocBytes = 0;
      /* Return code */
      if (bCmdBuff[0] == PHAL_MFDFEVX_CMD_READ_SIG) {
        pDataParams->pUnprocByteBuff[pDataParams->bNoUnprocBytes++] = 0x90;
      } else {
        pDataParams->pUnprocByteBuff[pDataParams->bNoUnprocBytes++] = 0x00;
      }

      /* Lower byte of CmdCtr */
      pDataParams->pUnprocByteBuff[pDataParams->bNoUnprocBytes++] = (uint8_t)(pDataParams->wCmdCtr);
      /* Higher byte of CmdCtr */
      pDataParams->pUnprocByteBuff[pDataParams->bNoUnprocBytes++] = (uint8_t)(
              pDataParams->wCmdCtr >> 8U);
      /* TI */
      (void)memcpy(&pDataParams->pUnprocByteBuff[pDataParams->bNoUnprocBytes], pDataParams->bTi,
          PHAL_MFDFEVX_SIZE_TI);
      pDataParams->bNoUnprocBytes += PHAL_MFDFEVX_SIZE_TI;

      /* the IV is constructed by encrypting with KeyID.SesAuthENCKey according to the ECB mode
       * As ECB encription doesnot use IV during the encription so we need not backup/ update with zero IV*/
      PH_CHECK_SUCCESS_FCT(statusTmp, phalMfdfEVx_Sw_Int_ComputeIv(PH_ON,
              pDataParams->bTi,
              pDataParams->wCmdCtr,
              pDataParams->bIv
          ));

      /* Encrypt IV */
      PH_CHECK_SUCCESS_FCT(statusTmp, phCryptoSym_Encrypt(
              pDataParams->pCryptoDataParamsEnc,
              PH_CRYPTOSYM_CIPHER_MODE_ECB,
              pDataParams->bIv,
              bIvLen,
              pDataParams->bIv
          ));

      PH_CHECK_SUCCESS_FCT(statusTmp, phCryptoSym_LoadIv(
              pDataParams->pCryptoDataParamsEnc,
              pDataParams->bIv,
              bIvLen
          ));

      /* Handling of chaining. */

      (void)memset(pDataParams->bIv, 0x00, bIvLen);

      /* Load IV */
      PH_CHECK_SUCCESS_FCT(statusTmp, phCryptoSym_LoadIv(
              pDataParams->pCryptoDataParamsMac,
              pDataParams->bIv,
              bIvLen
          ));

    }
    if ((status & PH_ERR_MASK) == PH_ERR_SUCCESS) {
      (void)memcpy(bCMacCard, &pRecv[wRxlen - 8u], 8);
      wRxlen -= 8u;

      /* If receieved data is not multiple of block size */
      wTmp = (PH_CRYPTOSYM_AES_BLOCK_SIZE - pDataParams->bNoUnprocBytes);
      if (wTmp >= wRxlen) {
        wTmp = wRxlen;
      }
      (void)memcpy(&pDataParams->pUnprocByteBuff[pDataParams->bNoUnprocBytes], pRecv, wTmp);
      pDataParams->bNoUnprocBytes += (uint8_t) wTmp;

      if (wTmp == wRxlen) {
        /* Conclude the CMAC calculation. */
        PH_CHECK_SUCCESS_FCT(statusTmp, phCryptoSym_CalculateMac(
                pDataParams->pCryptoDataParamsMac,
                (PH_CRYPTOSYM_MAC_MODE_CMAC | PH_EXCHANGE_BUFFER_LAST),
                pDataParams->pUnprocByteBuff,
                (pDataParams->bNoUnprocBytes),
                bCMAC,
                &bMacLen
            ));
      } else {
        /* First send the 16 byte block for CMAC calculation */
        PH_CHECK_SUCCESS_FCT(statusTmp, phCryptoSym_CalculateMac(
                pDataParams->pCryptoDataParamsMac,
                (PH_CRYPTOSYM_MAC_MODE_CMAC | PH_EXCHANGE_BUFFER_CONT),
                pDataParams->pUnprocByteBuff,
                (pDataParams->bNoUnprocBytes),
                bCMAC,
                &bMacLen
            ));

        /* Send rest of the received data */
        PH_CHECK_SUCCESS_FCT(statusTmp, phCryptoSym_CalculateMac(
                pDataParams->pCryptoDataParamsMac,
                (PH_CRYPTOSYM_MAC_MODE_CMAC | PH_EXCHANGE_BUFFER_LAST),
                &pRecv[wTmp],
                wRxlen - wTmp,
                bCMAC,
                &bMacLen
            ));
      }

      /* Since end of response is reached reset the pDataParams bNoUnprocBytes member to 0 */
      pDataParams->bNoUnprocBytes = 0;

      /* Truncate the MAC generated */
      phalMfdfEVx_Sw_Int_TruncateMac(bCMAC);

      /* Compare the CMAC received and Calculated MAC */
      if (memcmp(bCMAC, bCMacCard, 8) != 0) {
        /* CMAC validation failed */
        return PH_ADD_COMPCODE_FIXED(PH_ERR_INTEGRITY_ERROR, PH_COMP_AL_MFDFEVX);
      }

      /* the IV is constructed by encrypting with KeyID.SesAuthENCKey according to the ECB mode
       * As ECB encription doesnot use IV during the encription so we need not backup/ update with zero IV*/
      PH_CHECK_SUCCESS_FCT(statusTmp, phalMfdfEVx_Sw_Int_ComputeIv(PH_ON,
              pDataParams->bTi,
              pDataParams->wCmdCtr,
              pDataParams->bIv
          ));

      /* Encrypt IV */
      PH_CHECK_SUCCESS_FCT(statusTmp, phCryptoSym_Encrypt(
              pDataParams->pCryptoDataParamsEnc,
              PH_CRYPTOSYM_CIPHER_MODE_ECB,
              pDataParams->bIv,
              bIvLen,
              pDataParams->bIv
          ));

      PH_CHECK_SUCCESS_FCT(statusTmp, phCryptoSym_LoadIv(
              pDataParams->pCryptoDataParamsEnc,
              pDataParams->bIv,
              bIvLen
          ));

      /* Decrypt */
      PH_CHECK_SUCCESS_FCT(statusTmp, phCryptoSym_Decrypt(
              pDataParams->pCryptoDataParamsEnc,
              (PH_CRYPTOSYM_CIPHER_MODE_CBC),
              pRecv,
              wRxlen,
              pRecv
          ));

      /* Remove padding */
      PH_CHECK_SUCCESS_FCT(statusTmp, phCryptoSym_RemovePadding(
              PH_CRYPTOSYM_PADDING_MODE_2,
              pRecv,
              wRxlen,
              bIvLen,
              wRxlen,
              pRecv,
              &wRxlen
          ));
    } else {
      /* Include the left over data for CMAC calculation */
      wTmp = (PH_CRYPTOSYM_AES_BLOCK_SIZE - pDataParams->bNoUnprocBytes);
      (void)memcpy(&pDataParams->pUnprocByteBuff[pDataParams->bNoUnprocBytes], pRecv, wTmp);
      pDataParams->bNoUnprocBytes += (uint8_t) wTmp;

      /* Start MAC calculation with one full block size data */
      PH_CHECK_SUCCESS_FCT(statusTmp, phCryptoSym_CalculateMac(
              pDataParams->pCryptoDataParamsMac,
              (PH_CRYPTOSYM_MAC_MODE_CMAC | PH_EXCHANGE_BUFFER_CONT),
              pDataParams->pUnprocByteBuff,
              (pDataParams->bNoUnprocBytes),
              bCMAC,
              &bMacLen
          ));

      PH_CHECK_SUCCESS_FCT(statusTmp, phCryptoSym_CalculateMac(
              pDataParams->pCryptoDataParamsMac,
              (PH_CRYPTOSYM_MAC_MODE_CMAC | PH_EXCHANGE_BUFFER_CONT),
              &pRecv[wTmp],
              ((wRxlen - wTmp) / PH_CRYPTOSYM_AES_BLOCK_SIZE) * PH_CRYPTOSYM_AES_BLOCK_SIZE,
              bCMAC,
              &bMacLen
          ));

      /* Remaining bytes */
      wTmp = (wRxlen - wTmp) % PH_CRYPTOSYM_AES_BLOCK_SIZE;

      /* Update the UnprocByteBuffer with bytes not used for mac calculation */
      (void)memcpy(pDataParams->pUnprocByteBuff, &pRecv[wRxlen - wTmp], wTmp);
      pDataParams->bNoUnprocBytes = (uint8_t) wTmp;

      /* Decrypt */
      PH_CHECK_SUCCESS_FCT(statusTmp, phCryptoSym_Decrypt(
              pDataParams->pCryptoDataParamsEnc,
              (PH_CRYPTOSYM_CIPHER_MODE_CBC),
              pRecv,
              wRxlen,
              pRecv
          ));
    }
  } else if ((pDataParams->bAuthMode == PHAL_MFDFEVX_AUTHENTICATEISO) ||
      (pDataParams->bAuthMode == PHAL_MFDFEVX_AUTHENTICATEAES)) {
    PH_CHECK_SUCCESS_FCT(statusTmp, phCryptoSym_LoadIv(
            pDataParams->pCryptoDataParamsEnc,
            pDataParams->bIv,
            bIvLen
        ));

    if ((status & PH_ERR_MASK) == PH_ERR_SUCCESS_CHAINING) {
      /* Store the IV temporarily */
      (void)memcpy(bTmpIV, &pRecv[wRxlen - (2 * bIvLen)], bIvLen);

      if (bCmdBuff[0] != PHAL_MFDFEVX_RESP_ADDITIONAL_FRAME) {
        (void)memcpy(pDataParams->bLastBlockBuffer, &pRecv[wRxlen - bIvLen], bIvLen);
        wRxlen -= bIvLen;
        pDataParams->bLastBlockIndex = bIvLen;
      } else {
        (void)memcpy(pRecv, pDataParams->bLastBlockBuffer, bIvLen);
        (void)memcpy(pDataParams->bLastBlockBuffer, &pRecv[wRxlen - bIvLen], bIvLen);
        wRxlen -= bIvLen;
        pDataParams->bLastBlockIndex = bIvLen;
      }
      PH_CHECK_SUCCESS_FCT(statusTmp, phhalHw_SetConfig(
              pDataParams->pHalDataParams,
              PHHAL_HW_CONFIG_RXBUFFER_STARTPOS,
              bIvLen
          ));
    } else {
      /* Store the IV temporarily */
      (void)memcpy(bTmpIV, &pRecv[wRxlen - bIvLen], bIvLen);
      if (0U != (pDataParams->bLastBlockIndex)) {
        (void)memcpy(pRecv, pDataParams->bLastBlockBuffer, bIvLen);
        pDataParams->bLastBlockIndex = 0;
      }
    }

    /* Decrypt */
    PH_CHECK_SUCCESS_FCT(statusTmp, phCryptoSym_Decrypt(
            pDataParams->pCryptoDataParamsEnc,
            (PH_CRYPTOSYM_CIPHER_MODE_CBC),
            pRecv,
            wRxlen,
            pRecv
        ));

    /* Verify Padding and CRC */
    if ((status & PH_ERR_MASK) != PH_ERR_SUCCESS_CHAINING) {
      dwIndex = wRxlen;

      /* calculate pDataParams->dwPayLoadLen for GetCardUID command */
      if (bCmdBuff[0] == PHAL_MFDFEVX_CMD_GET_CARD_UID) {
        /* Response will be received as
         * 1. 7 byte UID
         * 2. [1 Byte UID Format] + [1 byte UID Length(0x04)] + 4 byte UID
         * 3. [1 Byte UID Format] + [1 byte UID Length(0x0A)] + 10 byte UID
         */
        if (pRecv[1] == 0x04U) {
          /* Indicates 4 byte UID. Set the payload length as (2 optional bytes + 4 bytes UID )*/
          pDataParams->dwPayLoadLen = 0x06;
        } else if (pRecv[1] == 0x0AU) {
          /* Indicates 10 byte UID. Set the payload length as (2 optional bytes + 10 bytes UID ) */
          pDataParams->dwPayLoadLen = 0x0C;
        } else {
          /* default 7 byte UID */
          pDataParams->dwPayLoadLen = 0x07;
        }

        /* Add the NUID length if available. */
        if (wCmdLen == 2) {
          pDataParams->dwPayLoadLen = (bCmdBuff[1] ? (pDataParams->dwPayLoadLen + 4) :
                  pDataParams->dwPayLoadLen);
        }
      }

      /* calculate pDataParams->dwPayLoadLen for Get File Counters command */
      if (bCmdBuff[0] == PHAL_MFDFEVX_CMD_GET_FILE_COUNTERS) {
        /* 3Bytes of SDMReadCtr +  2bytes of Reserved */
        pDataParams->dwPayLoadLen = 0x05;
      }

      if (pDataParams->dwPayLoadLen == 0U) {
        do {
          dwIndex--;
          if (pRecv[dwIndex] != 0x00U) {
            break;
          }
        } while (dwIndex != 0x00U);

        if (pRecv[dwIndex] != 0x80U) {
          /* Reset dwCrc to default */
          pDataParams->dwCrc = PH_TOOLS_CRC32_PRESET_DF8;
          return PH_ADD_COMPCODE_FIXED(PH_ERR_INTEGRITY_ERROR, PH_COMP_AL_MFDFEVX);
        }

        /* CRC is in the 4 bytes before this */
        pCrc = &pRecv[(uint16_t) dwIndex - 4u];
        bNumPaddingBytes = (uint8_t)(wRxlen - dwIndex);
      } else {
        /* Recv length should be equal to wPayLoadLen + 4 byte crc + padding */
        if (wRxlen < (pDataParams->dwPayLoadLen + 4U)) {
          /* Reset dwCrc to default */
          pDataParams->dwCrc = PH_TOOLS_CRC32_PRESET_DF8;
          return PH_ADD_COMPCODE_FIXED(PH_ERR_PROTOCOL_ERROR, PH_COMP_AL_MFDFEVX);
        }
        /* CRC Bytes */
        pCrc = &pRecv[pDataParams->dwPayLoadLen];
        bNumPaddingBytes = (uint8_t)(wRxlen - pDataParams->dwPayLoadLen - 4u);

        /* Verify the padding bytes */
        dwIndex = pDataParams->dwPayLoadLen + 4U;
        for (; dwIndex < wRxlen; dwIndex++) {
          if (pRecv[dwIndex] != 0U) {
            /* Reset dwCrc to default */
            pDataParams->dwCrc = PH_TOOLS_CRC32_PRESET_DF8;
            return PH_ADD_COMPCODE_FIXED(PH_ERR_INTEGRITY_ERROR, PH_COMP_AL_MFDFEVX);
          }
        }
      }

      /* Calculate CRC on data received */
      PH_CHECK_SUCCESS_FCT(statusTmp, phTools_CalculateCrc32(
              PH_TOOLS_CRC_OPTION_DEFAULT,
              pDataParams->dwCrc,
              PH_TOOLS_CRC32_POLY_DF8,
              pRecv,
              wRxlen - bNumPaddingBytes - 4,
              (uint32_t *) & (pDataParams->dwCrc)
          ));

      /* CRC to be calculated on data + status */
      PH_CHECK_SUCCESS_FCT(statusTmp, phTools_CalculateCrc32(
              PH_TOOLS_CRC_OPTION_DEFAULT,
              pDataParams->dwCrc,
              PH_TOOLS_CRC32_POLY_DF8,
              (uint8_t *) &bPiccStatus,
              0x01,
              (uint32_t *) & (pDataParams->dwCrc)
          ));

      if (memcmp(&(pDataParams->dwCrc), pCrc, 4) != 0) {
        /* Reset dwCrc to default */
        pDataParams->dwCrc = PH_TOOLS_CRC32_PRESET_DF8;
        return PH_ADD_COMPCODE_FIXED(PH_ERR_INTEGRITY_ERROR, PH_COMP_AL_MFDFEVX);
      }

      /* Return length of only the required bytes */
      wRxlen = wRxlen - bNumPaddingBytes - 4;

      /* Reset to default */
      pDataParams->dwCrc = PH_TOOLS_CRC32_PRESET_DF8;
    } else {
      /* Calculate CRC on data received */
      PH_CHECK_SUCCESS_FCT(statusTmp, phTools_CalculateCrc32(
              PH_TOOLS_CRC_OPTION_DEFAULT,
              pDataParams->dwCrc,
              PH_TOOLS_CRC32_POLY_DF8,
              pRecv,
              wRxlen,
              (uint32_t *) & (pDataParams->dwCrc)
          ));
    }
    /* Update IV to be used for next commands if no error */
    (void)memcpy(pDataParams->bIv, bTmpIV, bIvLen);

    /* Update the remaining length */
    if (pDataParams->dwPayLoadLen != 0U) {
      pDataParams->dwPayLoadLen -= wRxlen;
    }
  } else { /* pDataParams->bAuthMode == PHAL_MFDFEVX_AUTHENTICATE */
    /* Load Iv */
    PH_CHECK_SUCCESS_FCT(statusTmp, phCryptoSym_LoadIv(
            pDataParams->pCryptoDataParamsEnc,
            pDataParams->bIv,
            bIvLen
        ));

    if ((status & PH_ERR_MASK) == PH_ERR_SUCCESS_CHAINING) {
      /* Update IV to be used for next set of data decryption */
      (void)memcpy(pDataParams->bIv, &pRecv[wRxlen - (2 * bIvLen)], bIvLen);

      if (bCmdBuff[0] != PHAL_MFDFEVX_RESP_ADDITIONAL_FRAME) {
        (void)memcpy(pDataParams->bLastBlockBuffer, &pRecv[wRxlen - bIvLen], bIvLen);
        wRxlen -= bIvLen;
        pDataParams->bLastBlockIndex = bIvLen;
      } else {
        (void)memcpy(pRecv, pDataParams->bLastBlockBuffer, bIvLen);
        (void)memcpy(pDataParams->bLastBlockBuffer, &pRecv[wRxlen - bIvLen], bIvLen);
        wRxlen -= bIvLen;
        pDataParams->bLastBlockIndex = bIvLen;
      }
      PH_CHECK_SUCCESS_FCT(statusTmp, phhalHw_SetConfig(
              pDataParams->pHalDataParams,
              PHHAL_HW_CONFIG_RXBUFFER_STARTPOS,
              bIvLen
          ));
    } else {
      /* Reset the IV to 00 */
      (void)memset(pDataParams->bIv, 0x00, bIvLen);

      if (0U != (pDataParams->bLastBlockIndex)) {
        (void)memcpy(pRecv, pDataParams->bLastBlockBuffer, bIvLen);
        pDataParams->bLastBlockIndex = 0;
      }
    }

    /* Decrypt */
    PH_CHECK_SUCCESS_FCT(statusTmp, phCryptoSym_Decrypt(
            pDataParams->pCryptoDataParamsEnc,
            (PH_CRYPTOSYM_CIPHER_MODE_CBC),
            pRecv,
            wRxlen,
            pRecv
        ));
    /* Verify Padding and CRC */
    if ((status & PH_ERR_MASK) != PH_ERR_SUCCESS_CHAINING) {
      dwIndex = wRxlen;
      if (bCmdBuff[0] == PHAL_MFDFEVX_CMD_GET_CARD_UID) {
        /* Response will be received as
         * 1. 7 byte UID
         * 2. [1 Byte UID Format] + [1 byte UID Length(0x04)] + 4 byte UID
         * 3. [1 Byte UID Format] + [1 byte UID Length(0x0A)] + 10 byte UID
         */
        if (pRecv[1] == 0x04U) {
          /* Indicates 4 byte UID. Set the payload length as (2 optional bytes + 4 bytes UID )*/
          pDataParams->dwPayLoadLen = 0x06;
        } else if (pRecv[1] == 0x0AU) {
          /* Indicates 10 byte UID. Set the payload length as (2 optional bytes + 10 bytes UID ) */
          pDataParams->dwPayLoadLen = 0x0C;
        } else {
          /* default 7 byte UID */
          pDataParams->dwPayLoadLen = 0x07;
        }

        /* Add the NUID length if available. */
        if (wCmdLen == 2U) {
          pDataParams->dwPayLoadLen = (bCmdBuff[1] ? (pDataParams->dwPayLoadLen + 4) :
                  pDataParams->dwPayLoadLen);
        }
      }

      if (pDataParams->dwPayLoadLen == 0U) {
        do {
          dwIndex--;
          if (pRecv[dwIndex] != 0x00U) {
            break;
          }
        } while (dwIndex != 0x00U);

        if (pRecv[dwIndex] != 0x80U) {
          /* Reset dwCrc to default */
          pDataParams->wCrc = PH_TOOLS_CRC16_PRESET_ISO14443A;
          return PH_ADD_COMPCODE_FIXED(PH_ERR_INTEGRITY_ERROR, PH_COMP_AL_MFDFEVX);
        }

        /* CRC is in the 2 bytes before this */
        pCrc = &pRecv[(uint16_t) dwIndex - 2u];
        bNumPaddingBytes = (uint8_t)(wRxlen - dwIndex);
      } else {
        /* Recv length should be equal to wPayLoadLen + 2 byte crc + padding */
        if (wRxlen < (pDataParams->dwPayLoadLen + 2U)) {
          /* Reset dwCrc to default */
          pDataParams->wCrc = PH_TOOLS_CRC16_PRESET_ISO14443A;
          return PH_ADD_COMPCODE_FIXED(PH_ERR_PROTOCOL_ERROR, PH_COMP_AL_MFDFEVX);
        }
        /* CRC Bytes */
        pCrc = &pRecv[pDataParams->dwPayLoadLen];
        bNumPaddingBytes = (uint8_t)(wRxlen - pDataParams->dwPayLoadLen - 2u);

        /* Verify the padding bytes */
        dwIndex = pDataParams->dwPayLoadLen + 2U;
        for (; dwIndex < wRxlen; dwIndex++) {
          if (pRecv[dwIndex] != 0U) {
            /* Reset dwCrc to default */
            pDataParams->wCrc = PH_TOOLS_CRC16_PRESET_ISO14443A;
            return PH_ADD_COMPCODE_FIXED(PH_ERR_INTEGRITY_ERROR, PH_COMP_AL_MFDFEVX);
          }
        }
      }

      /* Calculate CRC on data received */
      PH_CHECK_SUCCESS_FCT(statusTmp, phTools_CalculateCrc16(
              PH_TOOLS_CRC_OPTION_DEFAULT,
              pDataParams->wCrc,
              PH_TOOLS_CRC16_POLY_ISO14443,
              pRecv,
              wRxlen - bNumPaddingBytes - 2,
              (uint16_t *) & (pDataParams->wCrc)
          ));

      if (memcmp(&(pDataParams->wCrc), pCrc, 2) != 0) {
        /* Reset wCrc to default */
        pDataParams->wCrc = PH_TOOLS_CRC16_PRESET_ISO14443A;
        return PH_ADD_COMPCODE_FIXED(PH_ERR_INTEGRITY_ERROR, PH_COMP_AL_MFDFEVX);
      }

      /* Return length of only the required bytes */
      wRxlen = wRxlen - bNumPaddingBytes - 2;

      /* Reset crc to default */
      pDataParams->wCrc = PH_TOOLS_CRC16_PRESET_ISO14443A;
    } else {
      /* Calculate CRC on data received */
      PH_CHECK_SUCCESS_FCT(statusTmp, phTools_CalculateCrc16(
              PH_TOOLS_CRC_OPTION_DEFAULT,
              pDataParams->wCrc,
              PH_TOOLS_CRC16_POLY_ISO14443,
              pRecv,
              wRxlen,
              (uint16_t *) & (pDataParams->wCrc)
          ));

      /* Update the remaining length: */
      if (pDataParams->dwPayLoadLen != 0U) {
        pDataParams->dwPayLoadLen -= wRxlen;
      }
    }
  }
  *ppRxdata = pRecv;
  *pRxdataLen = wRxlen;

  return status;
}

phStatus_t phalMfdfEVx_Sw_Int_Write_Enc(phalMfdfEVx_Sw_DataParams_t *pDataParams, uint8_t bIns,
    uint8_t *bCmdBuff,
    uint16_t wCmdLen, uint8_t bPaddingOption, uint8_t bCommOption, uint8_t *pData, uint16_t wDataLen)
{
  phStatus_t  PH_MEMLOC_REM statusTmp = 0;
  uint16_t    PH_MEMLOC_REM status = 0;
  uint16_t    PH_MEMLOC_REM wRxlen = 0;
  uint16_t    PH_MEMLOC_REM wTmp = 0;
  uint8_t     PH_MEMLOC_REM bCMAC[PH_CRYPTOSYM_AES_BLOCK_SIZE];
  uint8_t     PH_MEMLOC_REM bWorkBuffer[32];
  uint16_t    PH_MEMLOC_REM wWorkBufferLen = 0;
  uint8_t     PH_MEMLOC_REM bCMacCard[8];
  uint8_t     PH_MEMLOC_REM pResp[16];
  uint8_t     PH_MEMLOC_REM bMacLen = 0;
  uint8_t     PH_MEMLOC_REM bIvLen = 0;
  uint16_t    PH_MEMLOC_REM wCrc = PH_TOOLS_CRC16_PRESET_ISO14443A;
  uint32_t    PH_MEMLOC_REM dwCrc = PH_TOOLS_CRC32_PRESET_DF8;
  uint16_t    PH_MEMLOC_REM wFrameLen = 0;
  uint16_t    PH_MEMLOC_REM wTotalLen = 0;
  uint16_t    PH_MEMLOC_REM wLastChunkLen = 0;
  uint16_t    PH_MEMLOC_REM wDataLen1 = 0;
  uint16_t    PH_MEMLOC_REM wIndex = 0;
  uint16_t    PH_MEMLOC_REM wNumDataBlocks = 0;
  uint8_t     PH_MEMLOC_REM bLastChunk[32];
  uint16_t    PH_MEMLOC_REM wCommMode = PH_EXCHANGE_BUFFER_CONT;
  uint8_t     PH_MEMLOC_REM *pRecv = NULL;
  uint8_t     PH_MEMLOC_REM pApdu[5] = { PHAL_MFDFEVX_WRAPPEDAPDU_CLA, 0x00, PHAL_MFDFEVX_WRAPPEDAPDU_P1, PHAL_MFDFEVX_WRAPPEDAPDU_P2, 0x00 };
  uint16_t    PH_MEMLOC_REM wFSD = 0;
  uint16_t    PH_MEMLOC_REM wFSC = 0;
  uint8_t     PH_MEMLOC_REM bIvBackup[16];
  uint16_t    PH_MEMLOC_REM wApduLen = 0;

  (void)memset(bWorkBuffer, 0x00, 20);
  (void)memset(bCMacCard, 0x00, 8);
  (void)memset(bCMAC, 0x00, PH_CRYPTOSYM_AES_BLOCK_SIZE);
  (void)memset(bLastChunk, 0x00, 32);

  if ((pDataParams->bAuthMode == PHAL_MFDFEVX_AUTHENTICATEAES) ||
      (pDataParams->bAuthMode == PHAL_MFDFEVX_AUTHENTICATEEV2)) {
    bIvLen = PH_CRYPTOSYM_AES_BLOCK_SIZE;
  } else if ((pDataParams->bAuthMode == PHAL_MFDFEVX_AUTHENTICATEISO) ||
      (pDataParams->bAuthMode == PHAL_MFDFEVX_AUTHENTICATE)) {
    bIvLen = PH_CRYPTOSYM_DES_BLOCK_SIZE;
  } else {
    /* This function cannot be used without authentication */
    return PH_ADD_COMPCODE_FIXED(PH_ERR_USE_CONDITION, PH_COMP_AL_MFDFEVX);
  }

  if ((pDataParams->bAuthMode == PHAL_MFDFEVX_AUTHENTICATEISO) ||
      (pDataParams->bAuthMode == PHAL_MFDFEVX_AUTHENTICATEAES)) {
    /* Load Iv */
    PH_CHECK_SUCCESS_FCT(statusTmp, phCryptoSym_LoadIv(
            pDataParams->pCryptoDataParamsEnc,
            pDataParams->bIv,
            bIvLen
        ));

    /* encrypt only Cmd data with KsesauthEnc */
    if (bCmdBuff[0] != PHAL_MFDFEVX_RESP_ADDITIONAL_FRAME) {
      /* First calculate CRC on the cmd+params */
      PH_CHECK_SUCCESS_FCT(statusTmp, phTools_CalculateCrc32(
              PH_TOOLS_CRC_OPTION_DEFAULT,
              dwCrc,
              PH_TOOLS_CRC32_POLY_DF8,
              bCmdBuff,
              wCmdLen,
              &dwCrc
          ));
    }

    wNumDataBlocks = (wDataLen / bIvLen);
    if (wNumDataBlocks > 0U) {
      /* Calculate CRC32 for these blocks */
      PH_CHECK_SUCCESS_FCT(statusTmp, phTools_CalculateCrc32(
              PH_TOOLS_CRC_OPTION_DEFAULT,
              dwCrc,
              PH_TOOLS_CRC32_POLY_DF8,
              pData,
              wNumDataBlocks * bIvLen,
              &dwCrc
          ));
      /* Encrypt these blocks. Encrypted data put back on pData */
      PH_CHECK_SUCCESS_FCT(statusTmp, phCryptoSym_Encrypt(
              pDataParams->pCryptoDataParamsEnc,
              (PH_CRYPTOSYM_CIPHER_MODE_CBC | PH_EXCHANGE_BUFFER_CONT),
              pData,
              wNumDataBlocks * bIvLen,
              pData
          ));
      /* Update the data index */
      wDataLen1 = wNumDataBlocks * bIvLen;

      /* Update the IV */
      (void)memcpy(pDataParams->bIv, &pData[(wNumDataBlocks * bIvLen) - bIvLen], bIvLen);
    }
    if ((bCommOption & PHAL_MFDFEVX_MAC_DATA_INCOMPLETE) != PHAL_MFDFEVX_MAC_DATA_INCOMPLETE) {
      /* Last remaining bytes */
      if (0U != (wDataLen - wDataLen1)) {
        /* Calculate CRC32 for the remainin data  */
        PH_CHECK_SUCCESS_FCT(statusTmp, phTools_CalculateCrc32(
                PH_TOOLS_CRC_OPTION_DEFAULT,
                dwCrc,
                PH_TOOLS_CRC32_POLY_DF8,
                &pData[wDataLen1],
                wDataLen - wDataLen1,
                &dwCrc
            ));
        /* Prepare the last frame of data */
        (void)memcpy(bLastChunk, &pData[wDataLen1], wDataLen - wDataLen1);
      }

      /* Add CRC */
      (void)memcpy(&bLastChunk[wDataLen - wDataLen1], &dwCrc, 4);

      /* Has a last frame */
      wLastChunkLen = wDataLen - wDataLen1 + 4U;

      /* Apply padding. If padding option is 2, we
      need to pad even if the data is already multiple
      of bIvLen */
      if ((wLastChunkLen % bIvLen) ||
          ((bPaddingOption == PH_CRYPTOSYM_PADDING_MODE_2) && (wLastChunkLen % bIvLen == 0U))) {
        /* Apply padding */
        PH_CHECK_SUCCESS_FCT(statusTmp, phCryptoSym_ApplyPadding(
                bPaddingOption,
                bLastChunk,
                wLastChunkLen,
                bIvLen,
                sizeof(bLastChunk),
                bLastChunk,
                &wLastChunkLen
            ));
      }
      /* Load Iv */
      PH_CHECK_SUCCESS_FCT(statusTmp, phCryptoSym_LoadIv(
              pDataParams->pCryptoDataParamsEnc,
              pDataParams->bIv,
              bIvLen
          ));

      /* Encrypt */
      PH_CHECK_SUCCESS_FCT(statusTmp, phCryptoSym_Encrypt(
              pDataParams->pCryptoDataParamsEnc,
              PH_CRYPTOSYM_CIPHER_MODE_CBC | PH_EXCHANGE_BUFFER_LAST,
              bLastChunk,
              wLastChunkLen,
              bLastChunk
          ));

      /* Reset dwCrc to default */
      /* pDataParams->dwCrc = PH_TOOLS_CRC32_PRESET_DF8; */

      /* Update the IV */
      (void)memcpy(pDataParams->bIv, &bLastChunk[wLastChunkLen - bIvLen], bIvLen);
    }
    wTotalLen = wDataLen1 + wLastChunkLen;
  } else if (pDataParams->bAuthMode == PHAL_MFDFEVX_AUTHENTICATEEV2) {
    /* Encrypt the CmdData with KsesAuthENC, If required padding needs to be done */
    /* the IV is constructed by encrypting with KeyID.SesAuthENCKey according to the ECB mode
    * As ECB encription doesnot use IV during the encription so we need not backup/ update with zero IV*/

    /* encrypt only Cmd data with KsesauthEnc */
    if (bCmdBuff[0] != PHAL_MFDFEVX_RESP_ADDITIONAL_FRAME) {
      PH_CHECK_SUCCESS_FCT(statusTmp, phalMfdfEVx_Sw_Int_ComputeIv(PH_OFF,
              pDataParams->bTi,
              pDataParams->wCmdCtr,
              pDataParams->bIv
          ));

      /* Encrypt IV */
      PH_CHECK_SUCCESS_FCT(statusTmp, phCryptoSym_Encrypt(
              pDataParams->pCryptoDataParamsEnc,
              PH_CRYPTOSYM_CIPHER_MODE_ECB,
              pDataParams->bIv,
              bIvLen,
              pDataParams->bIv
          ));

      wCommMode = PH_EXCHANGE_BUFFER_FIRST;
    }

    /* Load Iv */
    PH_CHECK_SUCCESS_FCT(statusTmp, phCryptoSym_LoadIv(
            pDataParams->pCryptoDataParamsEnc,
            pDataParams->bIv,
            bIvLen
        ));

    wNumDataBlocks = (wDataLen / bIvLen);

    if (wNumDataBlocks > 0U) {
      /* Encrypt these blocks. Encrypted data put back on pData */
      PH_CHECK_SUCCESS_FCT(statusTmp, phCryptoSym_Encrypt(
              pDataParams->pCryptoDataParamsEnc,
              (PH_CRYPTOSYM_CIPHER_MODE_CBC | wCommMode),
              pData,
              wNumDataBlocks * bIvLen,
              pData
          ));

      /* Update the data index this hold the data encrypted */
      wDataLen1 = wNumDataBlocks * bIvLen;

      /* Update the IV */
      (void)memcpy(pDataParams->bIv, &pData[(wNumDataBlocks * bIvLen) - bIvLen], bIvLen);
    }

    if ((bCommOption & PHAL_MFDFEVX_MAC_DATA_INCOMPLETE) != PHAL_MFDFEVX_MAC_DATA_INCOMPLETE) {
      /*check for remaining bytes if present*/
      if (0U != (wDataLen - wDataLen1)) {
        /* Prepare the last frame of data */
        (void)memcpy(bLastChunk, &pData[wDataLen1], wDataLen - wDataLen1);
        /* Has a last frame */
        wLastChunkLen = wDataLen - wDataLen1;
      }

      /* Apply padding */
      PH_CHECK_SUCCESS_FCT(statusTmp, phCryptoSym_ApplyPadding(
              PH_CRYPTOSYM_PADDING_MODE_2,
              bLastChunk,
              wLastChunkLen,
              16,
              sizeof(bLastChunk),
              bLastChunk,
              &wLastChunkLen
          ));

      /* Load Iv */
      PH_CHECK_SUCCESS_FCT(statusTmp, phCryptoSym_LoadIv(
              pDataParams->pCryptoDataParamsEnc,
              pDataParams->bIv,
              bIvLen
          ));

      /* Encrypt the last frame*/
      PH_CHECK_SUCCESS_FCT(statusTmp, phCryptoSym_Encrypt(
              pDataParams->pCryptoDataParamsEnc,
              PH_CRYPTOSYM_CIPHER_MODE_CBC | (((wDataLen1 == 0U) &&
                      (bCmdBuff[0] != PHAL_MFDFEVX_RESP_ADDITIONAL_FRAME)) ? PH_EXCHANGE_DEFAULT :
                  PH_EXCHANGE_BUFFER_LAST),
              bLastChunk,
              wLastChunkLen,
              bLastChunk
          ));
    }

    /* size of encrypted data */
    wTotalLen = wDataLen1 + wLastChunkLen;

    if (bCmdBuff[0] != PHAL_MFDFEVX_RESP_ADDITIONAL_FRAME) {
      /* back up encryption IV */
      (void)memcpy(bIvBackup, pDataParams->bIv, bIvLen);

      /* set Iv value  for CMAC caluclation*/
      (void)memset(pDataParams->bIv, 0x00, bIvLen);
      pDataParams->bNoUnprocBytes = 0;

      /* Load Iv */
      PH_CHECK_SUCCESS_FCT(statusTmp, phCryptoSym_LoadIv(
              pDataParams->pCryptoDataParamsMac,
              pDataParams->bIv,
              bIvLen
          ));

      /* copy original encrypted IV */
      (void)memcpy(pDataParams->bIv, bIvBackup, bIvLen);

      /* Calculate MAC on Cmd || wCmdCtr || TI || CmdHeader || CmdData */
      bWorkBuffer[wWorkBufferLen++] = bCmdBuff[0];
      bWorkBuffer[wWorkBufferLen++] = (uint8_t)(pDataParams->wCmdCtr);
      bWorkBuffer[wWorkBufferLen++] = (uint8_t)(pDataParams->wCmdCtr >> 8U);
      (void)memcpy(&bWorkBuffer[wWorkBufferLen], pDataParams->bTi, PHAL_MFDFEVX_SIZE_TI);
      wWorkBufferLen += PHAL_MFDFEVX_SIZE_TI;
    } else {
      (void)memcpy(bWorkBuffer, pDataParams->pUnprocByteBuff, pDataParams->bNoUnprocBytes);
      wWorkBufferLen = pDataParams->bNoUnprocBytes;
      pDataParams->bNoUnprocBytes = 0;
    }

    /* Check for presence of command header */
    if (wCmdLen > 1U) {
      /* Calculate the total length of data for MAC calculation */
      wTmp = ((wCmdLen - 1u) + (wWorkBufferLen));

      /* Since bWorkbuffer can accomodate 32 bytes, check for buffer overflow */
      if (wTmp > 32U) {
        (void)memcpy(&bWorkBuffer[wWorkBufferLen], &bCmdBuff[1], (32 - wWorkBufferLen));
        /* Calculate CMAC */
        PH_CHECK_SUCCESS_FCT(statusTmp, phCryptoSym_CalculateMac(
                pDataParams->pCryptoDataParamsMac,
                PH_CRYPTOSYM_MAC_MODE_CMAC | PH_EXCHANGE_BUFFER_FIRST,
                bWorkBuffer,
                32,
                bCMAC,
                &bMacLen
            ));

        /* Copy the remaining bCmdBuff into bWorkBuffer */
        (void)memcpy(bWorkBuffer, &bCmdBuff[(32 - wWorkBufferLen) + 1U], (wTmp - 32u));
        wWorkBufferLen = (wTmp - 32u);
        wCommMode = PH_EXCHANGE_BUFFER_CONT;
      } else {
        (void)memcpy(&bWorkBuffer[wWorkBufferLen], &bCmdBuff[1], (wCmdLen - 1u));
        wWorkBufferLen += (wCmdLen - 1u);
      }
    }

    /* calculate the MAC value for encrypted CmdData */
    if (0U != (wDataLen1)) {
      if ((wTmp < 32U) && ((bCmdBuff[0] != PHAL_MFDFEVX_RESP_ADDITIONAL_FRAME))) {
        wCommMode = PH_EXCHANGE_BUFFER_FIRST;
      }

      /* check for remaining number of data to make multiple of IV length */
      wTmp = (PH_CRYPTOSYM_AES_BLOCK_SIZE - (wWorkBufferLen % PH_CRYPTOSYM_AES_BLOCK_SIZE));

      (void)memcpy(&bWorkBuffer[wWorkBufferLen], pData, wTmp);

      PH_CHECK_SUCCESS_FCT(statusTmp, phCryptoSym_CalculateMac(
              pDataParams->pCryptoDataParamsMac,
              (PH_CRYPTOSYM_MAC_MODE_CMAC | wCommMode),
              bWorkBuffer,
              wWorkBufferLen + wTmp,
              bCMAC,
              &bMacLen
          ));

      if ((wDataLen1 - wTmp) > PH_CRYPTOSYM_AES_BLOCK_SIZE) {
        PH_CHECK_SUCCESS_FCT(statusTmp, phCryptoSym_CalculateMac(
                pDataParams->pCryptoDataParamsMac,
                (PH_CRYPTOSYM_MAC_MODE_CMAC | PH_EXCHANGE_BUFFER_CONT),
                &pData[wTmp],
                (((wDataLen1 - wTmp) / PH_CRYPTOSYM_AES_BLOCK_SIZE) * PH_CRYPTOSYM_AES_BLOCK_SIZE),
                bCMAC,
                &bMacLen
            ));
      }

      wCommMode = PH_EXCHANGE_BUFFER_LAST;

      /* copy reaming data present in pdata */
      wWorkBufferLen = ((wDataLen1 - wTmp) % PH_CRYPTOSYM_AES_BLOCK_SIZE);
      (void)memcpy(bWorkBuffer, &pData[wDataLen1 - wWorkBufferLen], wWorkBufferLen);
    }
    /* if Last packet of data is sent */
    if ((bCommOption & PHAL_MFDFEVX_MAC_DATA_INCOMPLETE) != PHAL_MFDFEVX_MAC_DATA_INCOMPLETE) {
      /* copy remaing data to work buffer */
      wTmp = wWorkBufferLen + wLastChunkLen;

      if (wTmp < 32U) {
        (void)memcpy(&bWorkBuffer[wWorkBufferLen], &bLastChunk[0], wLastChunkLen);

        PH_CHECK_SUCCESS_FCT(statusTmp, phCryptoSym_CalculateMac(
                pDataParams->pCryptoDataParamsMac,
                (PH_CRYPTOSYM_MAC_MODE_CMAC | PH_EXCHANGE_BUFFER_LAST),
                bWorkBuffer,
                wTmp,
                bCMAC,
                &bMacLen
            ));
      } else {
        wTmp = 32 - wWorkBufferLen;
        (void)memcpy(&bWorkBuffer[wWorkBufferLen], bLastChunk, wTmp);

        PH_CHECK_SUCCESS_FCT(statusTmp, phCryptoSym_CalculateMac(
                pDataParams->pCryptoDataParamsMac,
                (PH_CRYPTOSYM_MAC_MODE_CMAC | PH_EXCHANGE_BUFFER_CONT),
                bWorkBuffer,
                32,
                bCMAC,
                &bMacLen
            ));

        /* this If condition is added to suppress QAC warning */
        if (wLastChunkLen > 0U) {
          PH_CHECK_SUCCESS_FCT(statusTmp, phCryptoSym_CalculateMac(
                  pDataParams->pCryptoDataParamsMac,
                  (PH_CRYPTOSYM_MAC_MODE_CMAC | PH_EXCHANGE_BUFFER_LAST),
                  &bLastChunk[wTmp],
                  wLastChunkLen - wTmp,
                  bCMAC,
                  &bMacLen
              ));
        }
      }

      /* Truncate the MAC generated */
      phalMfdfEVx_Sw_Int_TruncateMac(bCMAC);
      (void)memcpy(&bLastChunk[wLastChunkLen], bCMAC, 8);
      wLastChunkLen += 8U;
    } else {
      /* calculate CMAC for if data is multiple of IV */
      if (wWorkBufferLen > PH_CRYPTOSYM_AES_BLOCK_SIZE) {
        PH_CHECK_SUCCESS_FCT(statusTmp, phCryptoSym_CalculateMac(
                pDataParams->pCryptoDataParamsMac,
                (PH_CRYPTOSYM_MAC_MODE_CMAC | PH_EXCHANGE_BUFFER_CONT),
                bWorkBuffer,
                ((wWorkBufferLen / PH_CRYPTOSYM_AES_BLOCK_SIZE) * PH_CRYPTOSYM_AES_BLOCK_SIZE),
                bCMAC,
                &bMacLen
            ));
      } else {
        /* copy reaming data present in pdata */
        pDataParams->bNoUnprocBytes = (uint8_t)(wWorkBufferLen % PH_CRYPTOSYM_AES_BLOCK_SIZE);
        (void)memcpy(pDataParams->pUnprocByteBuff, bWorkBuffer, pDataParams->bNoUnprocBytes);
      }
    }
    /* Update Total Length */
    wTotalLen = wDataLen1 + wLastChunkLen;

  } else if (pDataParams->bAuthMode == PHAL_MFDFEVX_AUTHENTICATE) {
    /* Load Iv */
    PH_CHECK_SUCCESS_FCT(statusTmp, phCryptoSym_LoadIv(
            pDataParams->pCryptoDataParamsEnc,
            pDataParams->bIv,
            bIvLen
        ));

    wNumDataBlocks = wDataLen / bIvLen;
    if (wNumDataBlocks > 0U) {
      /* Calculate CRC16 for these blocks */
      PH_CHECK_SUCCESS_FCT(statusTmp, phTools_CalculateCrc16(
              PH_TOOLS_CRC_OPTION_DEFAULT,
              wCrc,
              PH_TOOLS_CRC16_POLY_ISO14443,
              pData,
              wNumDataBlocks * bIvLen,
              &wCrc
          ));

      /* Decrypt these blocks. decrypted dat put back on pData.*/
      PH_CHECK_SUCCESS_FCT(statusTmp, phCryptoSym_Encrypt(
              pDataParams->pCryptoDataParamsEnc,
              PH_CRYPTOSYM_CIPHER_MODE_CBC_DF4 | PH_EXCHANGE_BUFFER_CONT,
              pData,
              wNumDataBlocks * bIvLen,
              pData
          ));
      /* Update the data index */
      wDataLen1 = wNumDataBlocks * bIvLen;

      /* Update the IV */
      (void)memcpy(pDataParams->bIv, &pData[(wNumDataBlocks * bIvLen) - bIvLen], bIvLen);
    }

    if ((bCommOption & PHAL_MFDFEVX_MAC_DATA_INCOMPLETE) != PHAL_MFDFEVX_MAC_DATA_INCOMPLETE) {
      /* Last remaining bytes */
      if (0U != (wDataLen - wDataLen1)) {
        /* Calculate CRC16 for the remainin data  */
        PH_CHECK_SUCCESS_FCT(statusTmp, phTools_CalculateCrc16(
                PH_TOOLS_CRC_OPTION_DEFAULT,
                wCrc,
                PH_TOOLS_CRC16_POLY_ISO14443,
                &pData[wDataLen1],
                wDataLen - wDataLen1,
                &wCrc
            ));

        /* Prepare the last frame of data */
        (void)memcpy(bLastChunk, &pData[wDataLen1], wDataLen - wDataLen1);
      }

      /* Add CRC */
      (void)memcpy(&bLastChunk[wDataLen - wDataLen1], &wCrc, 2);

      /* Has a last frame */
      wLastChunkLen = wDataLen - wDataLen1 + 2U;

      /* Apply padding. If padding option is 2, we
      need to pad even if the data is already multiple
      of bIvLen */
      if ((wLastChunkLen % bIvLen) ||
          ((bPaddingOption == PH_CRYPTOSYM_PADDING_MODE_2) && (wLastChunkLen % bIvLen == 0U))) {
        /* Apply padding */
        PH_CHECK_SUCCESS_FCT(statusTmp, phCryptoSym_ApplyPadding(
                bPaddingOption,
                bLastChunk,
                wLastChunkLen,
                bIvLen,
                sizeof(bLastChunk),
                bLastChunk,
                &wLastChunkLen
            ));
      }
      /* Load Iv.  Use the last IV. But will reset the IV after encryption operation*/
      PH_CHECK_SUCCESS_FCT(statusTmp, phCryptoSym_LoadIv(
              pDataParams->pCryptoDataParamsEnc,
              pDataParams->bIv,
              bIvLen
          ));

      /* DF4 Decrypt */
      PH_CHECK_SUCCESS_FCT(statusTmp, phCryptoSym_Encrypt(
              pDataParams->pCryptoDataParamsEnc,
              PH_CRYPTOSYM_CIPHER_MODE_CBC_DF4 | PH_EXCHANGE_BUFFER_LAST,
              bLastChunk,
              wLastChunkLen,
              bLastChunk
          ));

      /* Reset dwCrc to default */
      /* pDataParams->wCrc = PH_TOOLS_CRC16_PRESET_ISO14443A; */

      /* Set IV to 00 for DF4 mode*/
      (void)memset(pDataParams->bIv, 0x00, bIvLen);
    }

    wTotalLen = wDataLen1 + wLastChunkLen;
  } else {
    return PH_ADD_COMPCODE_FIXED(PH_ERR_AUTH_ERROR, PH_COMP_AL_MFDFEVX);
  }

  /* At this point have proper data to be transmitted in the
  * buffer provided by the user.
  * wTotalLength should have the total length to be transmitted
  * First Frame: Cmd+Params+Data
  * wTotalLength -= wDataLen;
  while (wTotalLength)
  {
  Break the data into chunks of maxdata size and transmit.
  For ISO wrapped mode, max of 55 bytes can be sent in one frame.
  For native mode, max of 60 bytes can be sent in one frame.
  }
  */

  /* First copy the cmd+params+data(upto 52 bytes) and transmit
  * Next put AF+upto 59 bytes of data and transmit.
  * Continue till all data in Pdata is transferred, lastly include
  * the contents of bLastChunk also
  */

  if (bIns != PHAL_MFDFEVX_ISO_CHAINING_MODE) {
    if (0U != (pDataParams->bWrappedMode)) {
      wFrameLen = PHAL_MFDFEVX_MAXWRAPPEDAPDU_SIZE;
    } else {
      wFrameLen = PHAL_MFDFEVX_MAXDFAPDU_SIZE;
    }
  } else {
    /* Get the Frame length */
    PH_CHECK_SUCCESS_FCT(statusTmp, phalMfdfEVx_Sw_Int_GetFrameLength(
            pDataParams,
            &wFSD,
            &wFSC
        ));

    if (0U != (pDataParams->bWrappedMode)) {
      wFrameLen = wFSC - 9u;
    } else {
      wFrameLen = wFSC - 4u;
    }
  }

  wIndex = 0;
  /* satisfy compiler */
  PH_UNUSED_VARIABLE(wIndex);

  wTmp = wTotalLen;

  if (wTmp <= (wFrameLen - wCmdLen)) {
    wApduLen = ((wCmdLen == 0x01U) &&
            (bIns == PHAL_MFDFEVX_ISO_CHAINING_MODE)) ? 0 : PHAL_MFDFEVX_WRAP_HDR_LEN;
    wCmdLen = ((wCmdLen == 0x01U) && (bIns == PHAL_MFDFEVX_ISO_CHAINING_MODE)) ? 0 : wCmdLen;

    /* Send in one shot */
    if (0U != (pDataParams->bWrappedMode)) {
      pApdu[1] = bCmdBuff[0]; /* DESFire cmd code in INS */
      if (wCmdLen > 0U) {
        pApdu[4] = (uint8_t)(wCmdLen + wTotalLen) - 0x01u;
      }

      PH_CHECK_SUCCESS_FCT(statusTmp, phpalMifare_ExchangeL4(
              pDataParams->pPalMifareDataParams,
              PH_EXCHANGE_BUFFER_FIRST |
              (((bIns == PHAL_MFDFEVX_ISO_CHAINING_MODE) &&
                      (0U != (bCommOption & PHAL_MFDFEVX_MAC_DATA_INCOMPLETE))) ? PH_EXCHANGE_TXCHAINING : 0),
              pApdu,
              wApduLen,
              &pRecv,
              &wRxlen));

      if (wCmdLen > 0U) {
        PH_CHECK_SUCCESS_FCT(statusTmp, phpalMifare_ExchangeL4(
                pDataParams->pPalMifareDataParams,
                PH_EXCHANGE_BUFFER_CONT |
                (((bIns == PHAL_MFDFEVX_ISO_CHAINING_MODE) &&
                        (0U != (bCommOption & PHAL_MFDFEVX_MAC_DATA_INCOMPLETE))) ? PH_EXCHANGE_TXCHAINING : 0),
                &bCmdBuff[1],
                wCmdLen - 1u,
                &pRecv,
                &wRxlen));
      }

      PH_CHECK_SUCCESS_FCT(statusTmp, phpalMifare_ExchangeL4(
              pDataParams->pPalMifareDataParams,
              PH_EXCHANGE_BUFFER_CONT |
              (((bIns == PHAL_MFDFEVX_ISO_CHAINING_MODE) &&
                      (0U != (bCommOption & PHAL_MFDFEVX_MAC_DATA_INCOMPLETE))) ? PH_EXCHANGE_TXCHAINING : 0),
              pData,
              wDataLen1,
              &pRecv,
              &wRxlen));

      if (wLastChunkLen != 0x0000U) {
        PH_CHECK_SUCCESS_FCT(statusTmp, phpalMifare_ExchangeL4(
                pDataParams->pPalMifareDataParams,
                PH_EXCHANGE_BUFFER_CONT |
                (((bIns == PHAL_MFDFEVX_ISO_CHAINING_MODE) &&
                        (0U != (bCommOption & PHAL_MFDFEVX_MAC_DATA_INCOMPLETE))) ? PH_EXCHANGE_TXCHAINING : 0),
                bLastChunk,
                wLastChunkLen,
                &pRecv,
                &wRxlen));
      }

      /* Le byte */
      PH_CHECK_SUCCESS_FCT(statusTmp, phpalMifare_ExchangeL4(
              pDataParams->pPalMifareDataParams,
              PH_EXCHANGE_BUFFER_LAST |
              (((bIns == PHAL_MFDFEVX_ISO_CHAINING_MODE) &&
                      (0U != ((bCommOption & PHAL_MFDFEVX_MAC_DATA_INCOMPLETE)))) ? PH_EXCHANGE_TXCHAINING : 0),
              &pApdu[2],
              (uint16_t)((pDataParams->dwPayLoadLen > 0xFEU) &&
                  (bIns == PHAL_MFDFEVX_ISO_CHAINING_MODE)) ? 0x02U : 0x01U,
              &pRecv,
              &wRxlen));
    } else {
      PH_CHECK_SUCCESS_FCT(statusTmp, phpalMifare_ExchangeL4(
              pDataParams->pPalMifareDataParams,
              PH_EXCHANGE_BUFFER_FIRST |
              (((bIns == PHAL_MFDFEVX_ISO_CHAINING_MODE) &&
                      (0U != ((bCommOption & PHAL_MFDFEVX_MAC_DATA_INCOMPLETE)))) ? PH_EXCHANGE_TXCHAINING : 0),
              bCmdBuff,
              wCmdLen,
              &pRecv,
              &wRxlen));

      PH_CHECK_SUCCESS_FCT(statusTmp, phpalMifare_ExchangeL4(
              pDataParams->pPalMifareDataParams,
              ((wLastChunkLen == 0x0000U) ? PH_EXCHANGE_BUFFER_LAST : PH_EXCHANGE_BUFFER_CONT) |
              (((bIns == PHAL_MFDFEVX_ISO_CHAINING_MODE) &&
                      (0U != (bCommOption & PHAL_MFDFEVX_MAC_DATA_INCOMPLETE))) ? PH_EXCHANGE_TXCHAINING : 0),
              pData,
              wDataLen1, /* This is the size that is multiple of IV size */
              &pRecv,
              &wRxlen));

      if (wLastChunkLen != 0x0000U) {
        PH_CHECK_SUCCESS_FCT(statusTmp, phpalMifare_ExchangeL4(
                pDataParams->pPalMifareDataParams,
                PH_EXCHANGE_BUFFER_LAST |
                (((bIns == PHAL_MFDFEVX_ISO_CHAINING_MODE) &&
                        (0U != ((bCommOption & PHAL_MFDFEVX_MAC_DATA_INCOMPLETE)))) ? PH_EXCHANGE_TXCHAINING : 0),
                bLastChunk,
                wLastChunkLen,
                &pRecv,
                &wRxlen));
      }
    }

    if (0U != (pDataParams->bWrappedMode)) {
      status = (uint8_t)pRecv[wRxlen - 1u];
      wRxlen -= 2u;
    } else {
      status = (uint8_t) pRecv[0];
      pRecv++; /* Increment pointer to point only to data */
      wRxlen -= 1u;
    }

    if (status != PH_ERR_SUCCESS) {
      /* Reset authentication status */
      if ((pDataParams->bAuthMode == PHAL_MFDFEVX_AUTHENTICATEISO) ||
          (pDataParams->bAuthMode == PHAL_MFDFEVX_AUTHENTICATEAES) ||
          (pDataParams->bAuthMode == PHAL_MFDFEVX_AUTHENTICATEEV2)) {
        phalMfdfEVx_Sw_Int_ResetAuthStatus(pDataParams);
      }
      return phalMfdfEVx_Int_ComputeErrorResponse(pDataParams, (uint8_t) status);
    }

    (void)memcpy(pResp, pRecv, wRxlen);
  } else {
    if (wDataLen1 > 0x0200U) {
      statusTmp = phalMfdfEVx_Sw_Int_SendDataAndAddDataToPICC(
              pDataParams,
              bIns,
              bCmdBuff,
              wCmdLen,
              pData,
              wDataLen1,
              bLastChunk,
              wLastChunkLen,
              pResp,
              &wRxlen
          );
    } else {
      statusTmp = phalMfdfEVx_Sw_Int_SendDataToPICC(
              pDataParams,
              bIns,
              (bCommOption & PHAL_MFDFEVX_MAC_DATA_INCOMPLETE),
              bCmdBuff,
              wCmdLen,
              pData,
              wDataLen1,
              bLastChunk,
              wLastChunkLen,
              pResp,
              &wRxlen
          );
    }

    if ((statusTmp & PH_ERR_MASK) == PHAL_MFDFEVX_RESP_CHAINING) {
      return statusTmp;
    }

    if (((statusTmp & PH_ERR_MASK) != PH_ERR_SUCCESS) &&
        ((statusTmp & PH_ERR_MASK) != PH_ERR_SUCCESS_CHAINING)) {
      /* Reset authentication status */
      if ((pDataParams->bAuthMode == PHAL_MFDFEVX_AUTHENTICATEISO) ||
          (pDataParams->bAuthMode == PHAL_MFDFEVX_AUTHENTICATEAES) ||
          (pDataParams->bAuthMode == PHAL_MFDFEVX_AUTHENTICATEEV2)) {
        phalMfdfEVx_Sw_Int_ResetAuthStatus(pDataParams);
      }
      return statusTmp;
    }
  }

  /* Verify the MAC. MAC is not received if in 0x0A MAC'd mode */
  if ((pDataParams->bAuthMode == PHAL_MFDFEVX_AUTHENTICATEISO) ||
      (pDataParams->bAuthMode == PHAL_MFDFEVX_AUTHENTICATEAES)) {
    if (wRxlen < 8U) { /* If no CMAC received */
      return PH_ADD_COMPCODE_FIXED(PH_ERR_PROTOCOL_ERROR, PH_COMP_AL_MFDFEVX);
    }

    /* Decrypt the bWorkBuffer*/
    PH_CHECK_SUCCESS_FCT(statusTmp, phCryptoSym_LoadIv(
            pDataParams->pCryptoDataParamsEnc,
            pDataParams->bIv,
            bIvLen
        ));

    /* copy CMAC received from card*/
    (void)memcpy(bCMacCard, &pResp[wRxlen - 8u], 8);
    wRxlen -= 8u;

    /* Copy the status byte at the end */
    pResp[wRxlen] = (uint8_t) status;

    /* verify the MAC */
    PH_CHECK_SUCCESS_FCT(statusTmp, phCryptoSym_CalculateMac(
            pDataParams->pCryptoDataParamsEnc,
            (PH_CRYPTOSYM_MAC_MODE_CMAC),
            pResp,
            wRxlen + 1U,
            bCMAC,
            &bMacLen
        ));

    if (memcmp(bCMacCard, bCMAC, 8) != 0) {
      phalMfdfEVx_Sw_Int_ResetAuthStatus(pDataParams);
      return PH_ADD_COMPCODE_FIXED(PH_ERR_INTEGRITY_ERROR, PH_COMP_AL_MFDFEVX);
    }

    /* Update IV */
    (void)memcpy(pDataParams->bIv, bCMAC, bIvLen);
  } else if (pDataParams->bAuthMode == PHAL_MFDFEVX_AUTHENTICATEEV2) {
    /* Increment the command counter */
    pDataParams->wCmdCtr++;

    if (wRxlen < 8U) { /* If no CMAC received */
      return PH_ADD_COMPCODE_FIXED(PH_ERR_PROTOCOL_ERROR, PH_COMP_AL_MFDFEVX);
    }

    (void)memset(pDataParams->bIv, 0x00, bIvLen);

    /* Load IV */
    PH_CHECK_SUCCESS_FCT(statusTmp, phCryptoSym_LoadIv(
            pDataParams->pCryptoDataParamsMac,
            pDataParams->bIv,
            bIvLen
        ));

    /* copy CMAC received from card*/
    (void)memcpy(bCMacCard, &pResp[wRxlen - 8u], 8);
    wRxlen -= 8u;

    /*
    * Calculate MAC on RC || wCmdCtr || TI || RespData
    */
    pDataParams->bNoUnprocBytes = 0x00;
    pDataParams->pUnprocByteBuff[pDataParams->bNoUnprocBytes++] = 0x00;
    pDataParams->pUnprocByteBuff[pDataParams->bNoUnprocBytes++] = (uint8_t)(pDataParams->wCmdCtr);
    pDataParams->pUnprocByteBuff[pDataParams->bNoUnprocBytes++] = (uint8_t)(
            pDataParams->wCmdCtr >> 8U);
    (void)memcpy(&pDataParams->pUnprocByteBuff[pDataParams->bNoUnprocBytes], pDataParams->bTi,
        PHAL_MFDFEVX_SIZE_TI);
    pDataParams->bNoUnprocBytes += PHAL_MFDFEVX_SIZE_TI;

    /*Required ?*/
    (void)memcpy(&pDataParams->pUnprocByteBuff[pDataParams->bNoUnprocBytes], pResp, wRxlen);
    pDataParams->bNoUnprocBytes += (uint8_t) wRxlen;

    /* verify the MAC */
    PH_CHECK_SUCCESS_FCT(statusTmp, phCryptoSym_CalculateMac(
            pDataParams->pCryptoDataParamsMac,
            (PH_CRYPTOSYM_MAC_MODE_CMAC | PH_EXCHANGE_DEFAULT),
            pDataParams->pUnprocByteBuff,
            pDataParams->bNoUnprocBytes,
            bCMAC,
            &bMacLen
        ));

    /* Truncate the MAC generated */
    phalMfdfEVx_Sw_Int_TruncateMac(bCMAC);

    if (memcmp(bCMacCard, bCMAC, 8) != 0) {
      phalMfdfEVx_Sw_Int_ResetAuthStatus(pDataParams);
      return PH_ADD_COMPCODE_FIXED(PH_ERR_INTEGRITY_ERROR, PH_COMP_AL_MFDFEVX);
    }
  } else {
    /*Do Nothing. This is for PRQA compliance */
  }
  return PH_ERR_SUCCESS;
}
#endif /* NXPBUILD__PHAL_MFDFEVX_NDA */

phStatus_t phalMfdfEVx_Sw_Int_Write_New(phalMfdfEVx_Sw_DataParams_t *pDataParams,
    uint8_t bCommOption, uint8_t *pCmdBuff,
    uint16_t wCmdLen, uint8_t *pData, uint16_t wDataLen)
{
  uint16_t    PH_MEMLOC_REM wStatus = 0;
  uint8_t    *PH_MEMLOC_REM pResponse = NULL;
  uint16_t    PH_MEMLOC_REM wRespLen = 0;
  uint8_t     PH_MEMLOC_REM bPiccRetCode = 0;
  uint8_t     PH_MEMLOC_REM aEncBuffer[256];
  uint16_t    PH_MEMLOC_REM wEncBufLen = 0;
  uint8_t     PH_MEMLOC_REM aMac[16];
  uint8_t     PH_MEMLOC_REM bMacLen = 0;
#ifdef NXPBUILD__PHAL_MFDFEVX_NDA
  uint16_t    PH_MEMLOC_REM wCrc = PH_TOOLS_CRC16_PRESET_ISO14443A;
  uint32_t    PH_MEMLOC_REM dwCrc = PH_TOOLS_CRC32_PRESET_DF8;
  uint8_t     PH_MEMLOC_REM aSMBuffer[256];
  uint16_t    PH_MEMLOC_REM wSMBufLen = 0;
  uint8_t     PH_MEMLOC_REM bIvLen = 0;
  uint8_t     PH_MEMLOC_REM aIvBackup[16];
#endif /* NXPBUILD__PHAL_MFDFEVX_NDA */

#ifdef NXPBUILD__PHAL_MFDFEVX_NDA
  (void)memset(aEncBuffer, 0x00, sizeof(aEncBuffer));
  (void)memset(aMac, 0x00, sizeof(aMac));

  (void)memset(aSMBuffer, 0x00, sizeof(aSMBuffer));
  (void)memset(aIvBackup, 0x00, sizeof(aIvBackup));

  /* Apply Secure Messaging only if Communication Option is FULL. */
  if (bCommOption == PHAL_MFDFEVX_COMMUNICATION_ENC) {
    /* Apply D40 Secure Messaging. */
    if (pDataParams->bAuthMode == PHAL_MFDFEVX_AUTHENTICATE) {
      bIvLen = PH_CRYPTOSYM_DES_BLOCK_SIZE;

      /* Load Iv */
      PH_CHECK_SUCCESS_FCT(wStatus, phCryptoSym_LoadIv(
              pDataParams->pCryptoDataParamsEnc,
              pDataParams->bIv,
              bIvLen));

      /* Reset SMBuffer len. */
      wSMBufLen = 0;

      /* Calculate CRC16 for these blocks */
      PH_CHECK_SUCCESS_FCT(wStatus, phTools_CalculateCrc16(
              PH_TOOLS_CRC_OPTION_DEFAULT,
              wCrc,
              PH_TOOLS_CRC16_POLY_ISO14443,
              pData,
              wDataLen,
              &wCrc));

      /* Copy the Data information. */
      (void)memcpy(&aSMBuffer[wSMBufLen], pData, wDataLen);
      wSMBufLen += wDataLen;

      /* Copy CRC information. */
      (void)memcpy(&aSMBuffer[wSMBufLen], &wCrc, 2);
      wSMBufLen += 2;

      /* Apply padding. */
      PH_CHECK_SUCCESS_FCT(wStatus, phCryptoSym_ApplyPadding(
              PH_CRYPTOSYM_PADDING_MODE_1,
              aSMBuffer,
              wSMBufLen,
              bIvLen,
              sizeof(aEncBuffer),
              aEncBuffer,
              &wEncBufLen));

      /* Encrypt the data.*/
      PH_CHECK_SUCCESS_FCT(wStatus, phCryptoSym_Encrypt(
              pDataParams->pCryptoDataParamsEnc,
              PH_CRYPTOSYM_CIPHER_MODE_CBC_DF4 | PH_EXCHANGE_DEFAULT,
              aEncBuffer,
              wEncBufLen,
              aEncBuffer));

      /* Set IV to 00 for DF4 mode. */
      (void)memset(pDataParams->bIv, 0x00, bIvLen);
    }

    /* Apply EV1 Secure Messaging */
    else if ((pDataParams->bAuthMode == PHAL_MFDFEVX_AUTHENTICATEISO) ||
        (pDataParams->bAuthMode == PHAL_MFDFEVX_AUTHENTICATEAES)) {
      /* Set the IV length */
      bIvLen = (uint8_t)((pDataParams->bAuthMode == PHAL_MFDFEVX_AUTHENTICATEISO) ?
              PH_CRYPTOSYM_DES_BLOCK_SIZE :
              PH_CRYPTOSYM_AES_BLOCK_SIZE);

      /* Load Iv */
      PH_CHECK_SUCCESS_FCT(wStatus, phCryptoSym_LoadIv(
              pDataParams->pCryptoDataParamsEnc,
              pDataParams->bIv,
              bIvLen));

      /* Reset SMBuffer len. */
      wSMBufLen = 0;

      /* Calculate CRC32 for Cmd || Cmd Header. */
      PH_CHECK_SUCCESS_FCT(wStatus, phTools_CalculateCrc32(
              PH_TOOLS_CRC_OPTION_DEFAULT,
              dwCrc,
              PH_TOOLS_CRC32_POLY_DF8,
              pCmdBuff,
              wCmdLen,
              &dwCrc));

      /* Calculate CRC16 for data. */
      PH_CHECK_SUCCESS_FCT(wStatus, phTools_CalculateCrc32(
              PH_TOOLS_CRC_OPTION_DEFAULT,
              dwCrc,
              PH_TOOLS_CRC32_POLY_DF8,
              pData,
              wDataLen,
              &dwCrc));

      /* Copy the Data information. */
      (void)memcpy(&aSMBuffer[wSMBufLen], pData, wDataLen);
      wSMBufLen += wDataLen;

      /* Copy CRC information. */
      (void)memcpy(&aSMBuffer[wSMBufLen], &dwCrc, 4);
      wSMBufLen += 4;

      /* Apply padding. */
      PH_CHECK_SUCCESS_FCT(wStatus, phCryptoSym_ApplyPadding(
              PH_CRYPTOSYM_PADDING_MODE_1,
              aSMBuffer,
              wSMBufLen,
              bIvLen,
              sizeof(aEncBuffer),
              aEncBuffer,
              &wEncBufLen));

      /* Encrypt the data.*/
      PH_CHECK_SUCCESS_FCT(wStatus, phCryptoSym_Encrypt(
              pDataParams->pCryptoDataParamsEnc,
              PH_CRYPTOSYM_CIPHER_MODE_CBC | PH_EXCHANGE_DEFAULT,
              aEncBuffer,
              wEncBufLen,
              aEncBuffer));

      /* Update the IV. */
      (void)memcpy(pDataParams->bIv, &aEncBuffer[wEncBufLen - bIvLen], bIvLen);
    }

    /* Apply EV2 Secure Messaging. */
    else if (pDataParams->bAuthMode == PHAL_MFDFEVX_AUTHENTICATEEV2) {
      bIvLen = PH_CRYPTOSYM_AES_BLOCK_SIZE;

      /* Encrypt the CmdData with KsesAuthENC, If required padding needs to be done.
       * The IV is constructed by encrypting with KeyID.SesAuthENCKey according to the ECB mode
       * As ECB encryption does not use IV during the encryption so we need not backup / update
       * with zero IV
       */

      /* Compute the IV. */
      PH_CHECK_SUCCESS_FCT(wStatus, phalMfdfEVx_Sw_Int_ComputeIv(PH_OFF,
              pDataParams->bTi,
              pDataParams->wCmdCtr,
              pDataParams->bIv));

      /* Encrypt IV. */
      PH_CHECK_SUCCESS_FCT(wStatus, phCryptoSym_Encrypt(
              pDataParams->pCryptoDataParamsEnc,
              PH_CRYPTOSYM_CIPHER_MODE_ECB,
              pDataParams->bIv,
              bIvLen,
              pDataParams->bIv));

      /* Load the Encrypted Iv. */
      PH_CHECK_SUCCESS_FCT(wStatus, phCryptoSym_LoadIv(
              pDataParams->pCryptoDataParamsEnc,
              pDataParams->bIv,
              bIvLen));

      /* Apply padding */
      PH_CHECK_SUCCESS_FCT(wStatus, phCryptoSym_ApplyPadding(
              PH_CRYPTOSYM_PADDING_MODE_2,
              pData,
              wDataLen,
              bIvLen,
              sizeof(aEncBuffer),
              aEncBuffer,
              &wEncBufLen));

      /* Encrypt the Data. */
      PH_CHECK_SUCCESS_FCT(wStatus, phCryptoSym_Encrypt(
              pDataParams->pCryptoDataParamsEnc,
              (PH_CRYPTOSYM_CIPHER_MODE_CBC | PH_EXCHANGE_DEFAULT),
              aEncBuffer,
              wEncBufLen,
              aEncBuffer));

      /* Backup the current IV. */
      (void)memcpy(aIvBackup, pDataParams->bIv, bIvLen);

      /* Set Iv value for CMAC calculation. */
      (void)memset(pDataParams->bIv, 0x00, bIvLen);
      pDataParams->bNoUnprocBytes = 0;

      /* Load Iv */
      PH_CHECK_SUCCESS_FCT(wStatus, phCryptoSym_LoadIv(
              pDataParams->pCryptoDataParamsMac,
              pDataParams->bIv,
              bIvLen));

      /* Copy original encrypted IV. */
      (void)memcpy(pDataParams->bIv, aIvBackup, bIvLen);

      /* Frame the input buffer for MAC computation.
          * Cmd || wCmdCtr || TI || CmdHeader || CmdData
          */
      aSMBuffer[wSMBufLen++] = pCmdBuff[0];
      aSMBuffer[wSMBufLen++] = (uint8_t)(pDataParams->wCmdCtr);
      aSMBuffer[wSMBufLen++] = (uint8_t)(pDataParams->wCmdCtr >> 8);
      (void)memcpy(&aSMBuffer[wSMBufLen], pDataParams->bTi, PHAL_MFDFEVX_SIZE_TI);
      wSMBufLen += PHAL_MFDFEVX_SIZE_TI;

      /* Copy Remaining command information. */
      (void)memcpy(&aSMBuffer[wSMBufLen], &pCmdBuff[1], wCmdLen - 1);
      wSMBufLen += (uint16_t)(wCmdLen - 1);

      /* Copy Encrypted MFCLicenseMAC information. */
      (void)memcpy(&aSMBuffer[wSMBufLen], aEncBuffer, wEncBufLen);
      wSMBufLen += wEncBufLen;

      /* Compute EV2 SecureMessaging MAC. */
      PH_CHECK_SUCCESS_FCT(wStatus, phCryptoSym_CalculateMac(
              pDataParams->pCryptoDataParamsMac,
              PH_CRYPTOSYM_MAC_MODE_CMAC | PH_EXCHANGE_DEFAULT,
              aSMBuffer,
              wSMBufLen,
              aMac,
              &bMacLen));

      /* Truncate the MAC. */
      phalMfdfEVx_Sw_Int_TruncateMac(aMac);
      bMacLen = 8;
    } else {
      /* This function cannot be used without authentication */
      return PH_ADD_COMPCODE_FIXED(PH_ERR_AUTH_ERROR, PH_COMP_AL_MFDFEVX);
    }
  } else {
    /* Do nothing. */
  }
#endif /* NXPBUILD__PHAL_MFDFEVX_NDA */

  /* Buffer Command Information to PAL. */
  PH_CHECK_SUCCESS_FCT(wStatus, phalMfdfEVx_Sw_Int_CardExchange(
          pDataParams,
          PH_EXCHANGE_BUFFER_FIRST,
          (uint16_t)(wCmdLen + ((bCommOption == PHAL_MFDFEVX_COMMUNICATION_ENC) ? wEncBufLen : wDataLen) +
              bMacLen),
          PH_OFF,
          pCmdBuff,
          wCmdLen,
          NULL,
          NULL,
          NULL));

  /* Buffer Encrypted / Plain MFCLicenseMAC Information to PAL. */
  PH_CHECK_SUCCESS_FCT(wStatus, phalMfdfEVx_Sw_Int_CardExchange(
          pDataParams,
          PH_EXCHANGE_BUFFER_CONT,
          0,
          PH_OFF,
          (bCommOption == PHAL_MFDFEVX_COMMUNICATION_ENC) ? aEncBuffer : pData,
          (uint16_t)(bCommOption == PHAL_MFDFEVX_COMMUNICATION_ENC) ? wEncBufLen : wDataLen,
          NULL,
          NULL,
          NULL));

  /* Buffer and Exchange Secure Messaging MAC to PICC. */
  wStatus = phalMfdfEVx_Sw_Int_CardExchange(
          pDataParams,
          PH_EXCHANGE_BUFFER_LAST,
          0,
          PH_ON,
          aMac,
          bMacLen,
          &pResponse,
          &wRespLen,
          &bPiccRetCode);

  /* Verify the status. */
  if ((wStatus & PH_ERR_MASK) != PH_ERR_SUCCESS) {
    /* Reset authentication status */
    if ((pDataParams->bAuthMode == PHAL_MFDFEVX_AUTHENTICATEISO) ||
        (pDataParams->bAuthMode == PHAL_MFDFEVX_AUTHENTICATEAES) ||
        (pDataParams->bAuthMode == PHAL_MFDFEVX_AUTHENTICATEEV2)) {
      phalMfdfEVx_Sw_Int_ResetAuthStatus(pDataParams);
    }

    return wStatus;
  }

#ifdef NXPBUILD__PHAL_MFDFEVX_NDA
  /* Verify / Remove Secure Messaging only if Communication Option is FULL. */
  if (bCommOption == PHAL_MFDFEVX_COMMUNICATION_ENC) {
    /* Verify EV1 Secure Messaging. */
    if ((pDataParams->bAuthMode == PHAL_MFDFEVX_AUTHENTICATEISO) ||
        (pDataParams->bAuthMode == PHAL_MFDFEVX_AUTHENTICATEAES)) {
      /* Load IV */
      PH_CHECK_SUCCESS_FCT(wStatus, phCryptoSym_LoadIv(
              pDataParams->pCryptoDataParamsEnc,
              pDataParams->bIv,
              bIvLen));

      /* Compute the Response MAC. */
      PH_CHECK_SUCCESS_FCT(wStatus, phCryptoSym_CalculateMac(
              pDataParams->pCryptoDataParamsEnc,
              (PH_CRYPTOSYM_MAC_MODE_CMAC | PH_EXCHANGE_DEFAULT),
              &bPiccRetCode,
              1,
              aMac,
              &bMacLen));

      if (memcmp(pResponse, aMac, 8) != 0U) {
        phalMfdfEVx_Sw_Int_ResetAuthStatus(pDataParams);
        return PH_ADD_COMPCODE_FIXED(PH_ERR_INTEGRITY_ERROR, PH_COMP_AL_MFDFEVX);
      }

      /* Update the IV. */
      (void)memcpy(pDataParams->bIv, aMac, bIvLen);
    }

    /* Verify EV2 Secure Messaging. */
    else if (pDataParams->bAuthMode == PHAL_MFDFEVX_AUTHENTICATEEV2) {
      /* Increment the command counter */
      pDataParams->wCmdCtr++;

      /* Reset the IV buffer. */
      (void)memset(pDataParams->bIv, 0x00, bIvLen);

      /* Load IV */
      PH_CHECK_SUCCESS_FCT(wStatus, phCryptoSym_LoadIv(
              pDataParams->pCryptoDataParamsMac,
              pDataParams->bIv,
              bIvLen));

      /* Calculate MAC on RC || wCmdCtr || TI || RespData */
      pDataParams->bNoUnprocBytes = 0x00;
      pDataParams->pUnprocByteBuff[pDataParams->bNoUnprocBytes++] = bPiccRetCode;
      pDataParams->pUnprocByteBuff[pDataParams->bNoUnprocBytes++] = (uint8_t)(pDataParams->wCmdCtr);
      pDataParams->pUnprocByteBuff[pDataParams->bNoUnprocBytes++] = (uint8_t)(
              pDataParams->wCmdCtr >> 8);
      (void)memcpy(&pDataParams->pUnprocByteBuff[pDataParams->bNoUnprocBytes], pDataParams->bTi,
          PHAL_MFDFEVX_SIZE_TI);
      pDataParams->bNoUnprocBytes += PHAL_MFDFEVX_SIZE_TI;

      /* Copy the response.  */
      (void)memcpy(&pDataParams->pUnprocByteBuff[pDataParams->bNoUnprocBytes], pResponse,
          (wRespLen - 8));
      pDataParams->bNoUnprocBytes += (uint8_t)(wRespLen - 8);

      /* Compute the Response MAC. */
      PH_CHECK_SUCCESS_FCT(wStatus, phCryptoSym_CalculateMac(
              pDataParams->pCryptoDataParamsMac,
              (PH_CRYPTOSYM_MAC_MODE_CMAC | PH_EXCHANGE_DEFAULT),
              pDataParams->pUnprocByteBuff,
              pDataParams->bNoUnprocBytes,
              aMac,
              &bMacLen));

      /* Truncate the MAC generated */
      phalMfdfEVx_Sw_Int_TruncateMac(aMac);

      if (memcmp(&pResponse[wRespLen - 8], aMac, 8) != 0U) {
        phalMfdfEVx_Sw_Int_ResetAuthStatus(pDataParams);

        return PH_ADD_COMPCODE_FIXED(PH_ERR_INTEGRITY_ERROR, PH_COMP_AL_MFDFEVX);
      }
    } else {
      /* Do Nothing. */
    }
  }
#endif /* NXPBUILD__PHAL_MFDFEVX_NDA */

  return PH_ERR_SUCCESS;
}

phStatus_t phalMfdfEVx_Sw_Int_Write_Plain(phalMfdfEVx_Sw_DataParams_t *pDataParams, uint8_t bIns,
    uint8_t *bCmdBuff,
    uint16_t wCmdLen, uint8_t bCommOption, uint8_t *pData, uint16_t wDataLen)
{
  phStatus_t  PH_MEMLOC_REM statusTmp = 0;
  uint16_t    PH_MEMLOC_REM status = 0;
  uint16_t    PH_MEMLOC_REM wRxlen = 0;
  uint8_t     PH_MEMLOC_REM bWorkBuffer[32];
  uint16_t    PH_MEMLOC_REM wFrameLen = 0;
  uint16_t    PH_MEMLOC_REM wTotalLen = 0;
  uint16_t    PH_MEMLOC_REM wTmp = 0;
  uint8_t     PH_MEMLOC_REM *pRecv = NULL;
  uint8_t     PH_MEMLOC_REM pApdu[5] = { PHAL_MFDFEVX_WRAPPEDAPDU_CLA, 0x00, PHAL_MFDFEVX_WRAPPEDAPDU_P1, PHAL_MFDFEVX_WRAPPEDAPDU_P2, 0x00 };
#ifdef NXPBUILD__PHAL_MFDFEVX_NDA
  uint16_t    PH_MEMLOC_REM wIndex = 0;
  uint16_t    PH_MEMLOC_REM wNumDataBlocks = 0;
  uint8_t     PH_MEMLOC_REM bCMAC[PH_CRYPTOSYM_AES_BLOCK_SIZE];
#endif /* NXPBUILD__PHAL_MFDFEVX_NDA */
  uint8_t     PH_MEMLOC_REM bCMacCard[8];
  uint8_t     PH_MEMLOC_REM bMacLen = 0;
  uint8_t     PH_MEMLOC_REM bIvLen = 0;
  uint16_t    PH_MEMLOC_REM wWorkBufferLen = 0;
  uint16_t    PH_MEMLOC_REM wFSD = 0;
  uint16_t    PH_MEMLOC_REM wFSC = 0;
  uint16_t    PH_MEMLOC_REM wApduLen = 0;
  uint8_t     PH_MEMLOC_REM bAppId[3] = { 0x00, 0x00, 0x00 };
#ifdef NXPBUILD__PHAL_MFDFEVX_NDA
  (void)memset(bCMAC, 0x00, PH_CRYPTOSYM_AES_BLOCK_SIZE);
  (void)memset(bCMacCard, 0x00, 8);
#endif /* NXPBUILD__PHAL_MFDFEVX_NDA */

  (void)memset(bWorkBuffer, 0x00, 32);
#ifdef NXPBUILD__PHAL_MFDFEVX_NDA
  if ((pDataParams->bAuthMode == PHAL_MFDFEVX_AUTHENTICATEAES) ||
      (pDataParams->bAuthMode == PHAL_MFDFEVX_AUTHENTICATEEV2)) {
    bIvLen = PH_CRYPTOSYM_AES_BLOCK_SIZE;
  } else {
    bIvLen = PH_CRYPTOSYM_DES_BLOCK_SIZE;
  }
#endif /*NXPBUILD__PHAL_MFDFEVX_NDA */

  if ((pDataParams->bAuthMode == PHAL_MFDFEVX_AUTHENTICATEISO) ||
      (pDataParams->bAuthMode == PHAL_MFDFEVX_AUTHENTICATEAES)) {
#ifdef NXPBUILD__PHAL_MFDFEVX_NDA
    /* MAC(KsesAuth, Cmd [||CmdHeader][||CmdData]) and MAC is used as IV for next operation */
    /* check for first frame and load IV and copy only cmd */
    if (bCmdBuff[0] != PHAL_MFDFEVX_RESP_ADDITIONAL_FRAME) {
      /* Load Iv */
      PH_CHECK_SUCCESS_FCT(statusTmp, phCryptoSym_LoadIv(
              pDataParams->pCryptoDataParamsEnc,
              pDataParams->bIv,
              bIvLen
          ));
      pDataParams->bNoUnprocBytes = 0;
      /* copy only cmd */
      bWorkBuffer[wWorkBufferLen++] = bCmdBuff[0];
    } else {
      /* copy the data for CMAC calculation from previous packet if present */
      (void)memcpy(bWorkBuffer, pDataParams->pUnprocByteBuff, pDataParams->bNoUnprocBytes);
      wWorkBufferLen = pDataParams->bNoUnprocBytes;
      pDataParams->bNoUnprocBytes = 0;
    }
    if (((wCmdLen + wDataLen) <= bIvLen) &&
        ((bCommOption & PHAL_MFDFEVX_MAC_DATA_INCOMPLETE) != PHAL_MFDFEVX_MAC_DATA_INCOMPLETE) &&
        (bCmdBuff[0] != PHAL_MFDFEVX_RESP_ADDITIONAL_FRAME)) {
      (void)memcpy(bWorkBuffer, bCmdBuff, wCmdLen);
      /* Really small amount of data. Calculate in one shot */
      (void)memcpy(&bWorkBuffer[wCmdLen], pData, wDataLen);

      /*Calculate CMAC over the cmd+params first */
      PH_CHECK_SUCCESS_FCT(statusTmp, phCryptoSym_CalculateMac(
              pDataParams->pCryptoDataParamsEnc,
              PH_CRYPTOSYM_MAC_MODE_CMAC,
              bWorkBuffer,
              wCmdLen + wDataLen,
              bCMAC,
              &bMacLen
          ));
      /* Update the IV */
      (void)memcpy(pDataParams->bIv, bCMAC, bMacLen);
    } else {
      /* check if cmd header id present */
      if (wCmdLen > 1U) {
        /* Calculate the total length of data for MAC calculation */
        wTmp = ((wCmdLen - 1u) + (wWorkBufferLen));
        /* Since bWorkbuffer can accomodate 32 bytes, check for buffer overflow */
        if (wTmp > 32U) {
          (void)memcpy(&bWorkBuffer[wWorkBufferLen], &bCmdBuff[1], (32 - wWorkBufferLen));

          /* Calculate CMAC */
          PH_CHECK_SUCCESS_FCT(statusTmp, phCryptoSym_CalculateMac(
                  pDataParams->pCryptoDataParamsEnc,
                  PH_CRYPTOSYM_MAC_MODE_CMAC | PH_EXCHANGE_BUFFER_CONT,
                  bWorkBuffer,
                  32,
                  bCMAC,
                  &bMacLen
              ));

          /* Copy the remaining bCmdBuff into bWorkBuffer */
          (void)memcpy(bWorkBuffer, &bCmdBuff[(32 - wWorkBufferLen) + 1U], (wTmp - 32u));
          wWorkBufferLen = (wTmp - 32u);
        } else {
          /* if cmdheader + previous data packet(if present ) is less the 32 byte copy it to
           * bWorkBuffer and calculate CMAC with next frame */
          (void)memcpy(&bWorkBuffer[wWorkBufferLen], &bCmdBuff[1], (wCmdLen - 1u));
          wWorkBufferLen += (wCmdLen - 1u);
        }
      }
      /* complete the calculation if recevied data is last frame or only one frame */
      if ((bCommOption & PHAL_MFDFEVX_MAC_DATA_INCOMPLETE) != PHAL_MFDFEVX_MAC_DATA_INCOMPLETE) {
        /*  complet CMAC calculation if there is no data */
        if (!(wDataLen)) {
          /* Calculate CMAC in one shot */
          PH_CHECK_SUCCESS_FCT(statusTmp, phCryptoSym_CalculateMac(
                  pDataParams->pCryptoDataParamsEnc,
                  (PH_CRYPTOSYM_MAC_MODE_CMAC | ((wTmp > 32U) ? PH_EXCHANGE_BUFFER_LAST : PH_EXCHANGE_DEFAULT)),
                  bWorkBuffer,
                  wWorkBufferLen,
                  bCMAC,
                  &bMacLen
              ));
        } else {
          wTmp = (bIvLen - (wWorkBufferLen % bIvLen));
          if (wDataLen < wTmp) {
            wTmp = wDataLen;
          }
          (void)memcpy(&bWorkBuffer[wWorkBufferLen], pData, wTmp);

          PH_CHECK_SUCCESS_FCT(statusTmp, phCryptoSym_CalculateMac(
                  pDataParams->pCryptoDataParamsEnc,
                  (PH_CRYPTOSYM_MAC_MODE_CMAC | ((wTmp == wDataLen) ? PH_EXCHANGE_BUFFER_LAST :
                          PH_EXCHANGE_BUFFER_CONT)),
                  bWorkBuffer,
                  wWorkBufferLen + wTmp,
                  bCMAC,
                  &bMacLen
              ));

          if (wTmp != wDataLen) {
            PH_CHECK_SUCCESS_FCT(statusTmp, phCryptoSym_CalculateMac(
                    pDataParams->pCryptoDataParamsEnc,
                    PH_CRYPTOSYM_MAC_MODE_CMAC | PH_EXCHANGE_BUFFER_LAST,
                    &pData[wTmp],
                    wDataLen - wTmp,
                    bCMAC,
                    &bMacLen
                ));
          }
        }
      } else {
        if (!(wDataLen)) {
          if (0u != (((wWorkBufferLen / bIvLen) * bIvLen))) {
            /* Calculate CMAC */
            PH_CHECK_SUCCESS_FCT(statusTmp, phCryptoSym_CalculateMac(
                    pDataParams->pCryptoDataParamsEnc,
                    (PH_CRYPTOSYM_MAC_MODE_CMAC | PH_EXCHANGE_BUFFER_CONT),
                    bWorkBuffer,
                    ((wWorkBufferLen / bIvLen) * bIvLen),
                    bCMAC,
                    &bMacLen
                ));
          }
          pDataParams->bNoUnprocBytes = (uint8_t)(wWorkBufferLen % bIvLen);
          (void)memcpy(pDataParams->pUnprocByteBuff,
              &bWorkBuffer[wWorkBufferLen - pDataParams->bNoUnprocBytes], pDataParams->bNoUnprocBytes);
        } else {
          wTmp = (bIvLen - (wWorkBufferLen % bIvLen));
          if (wDataLen < wTmp) {
            wTmp = wDataLen;
            pDataParams->bNoUnprocBytes = (uint8_t)(wTmp % bIvLen);
            (void)memcpy(pDataParams->pUnprocByteBuff, &pData[wTmp - pDataParams->bNoUnprocBytes],
                pDataParams->bNoUnprocBytes);
          }
          (void)memcpy(&bWorkBuffer[wWorkBufferLen], pData, (wTmp - pDataParams->bNoUnprocBytes));

          PH_CHECK_SUCCESS_FCT(statusTmp, phCryptoSym_CalculateMac(
                  pDataParams->pCryptoDataParamsEnc,
                  (PH_CRYPTOSYM_MAC_MODE_CMAC | PH_EXCHANGE_BUFFER_CONT),
                  bWorkBuffer,
                  (wWorkBufferLen + (wTmp - pDataParams->bNoUnprocBytes)),
                  bCMAC,
                  &bMacLen
              ));

          if (wTmp != wDataLen) {
            PH_CHECK_SUCCESS_FCT(statusTmp, phCryptoSym_CalculateMac(
                    pDataParams->pCryptoDataParamsEnc,
                    PH_CRYPTOSYM_MAC_MODE_CMAC | PH_EXCHANGE_BUFFER_CONT,
                    &pData[wTmp],
                    (((wDataLen - wTmp) / bIvLen) * bIvLen),
                    bCMAC,
                    &bMacLen
                ));

            pDataParams->bNoUnprocBytes = (uint8_t)((wDataLen - wTmp) % bIvLen);
            (void)memcpy(pDataParams->pUnprocByteBuff, &pData[wDataLen - pDataParams->bNoUnprocBytes],
                pDataParams->bNoUnprocBytes);
          }
        }
      }
      if ((bCommOption & PHAL_MFDFEVX_MAC_DATA_INCOMPLETE) != PHAL_MFDFEVX_MAC_DATA_INCOMPLETE) {
        /* MAC value is used as IV for next operation. So update the IV if it last packet */
        (void)memcpy(pDataParams->bIv, bCMAC, bMacLen);
      }
    }
#endif /* NXPBUILD__PHAL_MFDFEVX_NDA */

    /* If communication mode is set to plain
     * or bCommOption equals PHAL_MFDFEVX_MAC_DATA_INCOMPLETE, then MAC is only
     * calculated to update the init vector but is not sent with the data
     */
    if (((bCommOption & 0xF0U) == PHAL_MFDFEVX_COMMUNICATION_PLAIN) ||
        ((bCommOption & PHAL_MFDFEVX_MAC_DATA_INCOMPLETE) == PHAL_MFDFEVX_MAC_DATA_INCOMPLETE)) {
      bMacLen = 0;
    } else {
      bMacLen = 8;
    }
  } else if ((pDataParams->bAuthMode == PHAL_MFDFEVX_AUTHENTICATEEV2) &&
      ((bCommOption & 0xF0U) == PHAL_MFDFEVX_COMMUNICATION_MACD)) {
    if ((bCmdBuff[0] != PHAL_MFDFEVX_RESP_ADDITIONAL_FRAME)) {
      (void)memset(pDataParams->bIv, 0x00, bIvLen);
      pDataParams->bNoUnprocBytes = 0;
#ifdef NXPBUILD__PHAL_MFDFEVX_NDA
      /* Load Iv */
      PH_CHECK_SUCCESS_FCT(statusTmp, phCryptoSym_LoadIv(
              pDataParams->pCryptoDataParamsMac,
              pDataParams->bIv,
              bIvLen
          ));
#endif /*NXPBUILD__PHAL_MFDFEVX_NDA*/
      /* Calculate MAC on Cmd || wCmdCtr || TI || CmdHeader || CmdData */
      bWorkBuffer[wWorkBufferLen++] = bCmdBuff[0];
      bWorkBuffer[wWorkBufferLen++] = (uint8_t)(pDataParams->wCmdCtr);
      bWorkBuffer[wWorkBufferLen++] = (uint8_t)(pDataParams->wCmdCtr >> 8U);
      (void)memcpy(&bWorkBuffer[wWorkBufferLen], pDataParams->bTi, PHAL_MFDFEVX_SIZE_TI);
      wWorkBufferLen += PHAL_MFDFEVX_SIZE_TI;
    } else {
      (void)memcpy(bWorkBuffer, pDataParams->pUnprocByteBuff, pDataParams->bNoUnprocBytes);
      wWorkBufferLen = pDataParams->bNoUnprocBytes;
      pDataParams->bNoUnprocBytes = 0;
    }
    /* Check for presence of command header */
    if (wCmdLen > 1U) {
      /* Calculate the total length of data for MAC calculation */
      wTmp = ((wCmdLen - 1u) + (wWorkBufferLen));
      /* Since bWorkbuffer can accomodate 32 bytes, check for buffer overflow */
      if (wTmp > 32U) {
        (void)memcpy(&bWorkBuffer[wWorkBufferLen], &bCmdBuff[1], (32 - wWorkBufferLen));
#ifdef NXPBUILD__PHAL_MFDFEVX_NDA
        /* Calculate CMAC */
        PH_CHECK_SUCCESS_FCT(statusTmp, phCryptoSym_CalculateMac(
                pDataParams->pCryptoDataParamsMac,
                PH_CRYPTOSYM_MAC_MODE_CMAC | PH_EXCHANGE_BUFFER_CONT,
                bWorkBuffer,
                32,
                bCMAC,
                &bMacLen
            ));
#endif /*NXPBUILD__PHAL_MFDFEVX_NDA*/
        /* Copy the remaining bCmdBuff into bWorkBuffer */
        (void)memcpy(bWorkBuffer, &bCmdBuff[(32 - wWorkBufferLen) + 1U], (wTmp - 32u));
        wWorkBufferLen = (wTmp - 32u);
      } else {
        (void)memcpy(&bWorkBuffer[wWorkBufferLen], &bCmdBuff[1], (wCmdLen - 1u));
        wWorkBufferLen += (wCmdLen - 1u);
      }
    }
#ifdef NXPBUILD__PHAL_MFDFEVX_NDA
    if ((bCommOption & PHAL_MFDFEVX_MAC_DATA_INCOMPLETE) != PHAL_MFDFEVX_MAC_DATA_INCOMPLETE) {
      if (!(wDataLen)) {
        /* Calculate CMAC in one shot */
        PH_CHECK_SUCCESS_FCT(statusTmp, phCryptoSym_CalculateMac(
                pDataParams->pCryptoDataParamsMac,
                (PH_CRYPTOSYM_MAC_MODE_CMAC | ((wTmp > 32U) ? PH_EXCHANGE_BUFFER_LAST : PH_EXCHANGE_DEFAULT)),
                bWorkBuffer,
                wWorkBufferLen,
                bCMAC,
                &bMacLen
            ));
      } else {
        wTmp = (PH_CRYPTOSYM_AES_BLOCK_SIZE - (wWorkBufferLen % PH_CRYPTOSYM_AES_BLOCK_SIZE));
        if (wDataLen < wTmp) {
          wTmp = wDataLen;
        }
        (void)memcpy(&bWorkBuffer[wWorkBufferLen], pData, wTmp);

        PH_CHECK_SUCCESS_FCT(statusTmp, phCryptoSym_CalculateMac(
                pDataParams->pCryptoDataParamsMac,
                (PH_CRYPTOSYM_MAC_MODE_CMAC | ((wTmp == wDataLen) ? PH_EXCHANGE_BUFFER_LAST :
                        PH_EXCHANGE_BUFFER_CONT)),
                bWorkBuffer,
                wWorkBufferLen + wTmp,
                bCMAC,
                &bMacLen
            ));

        if (wTmp != wDataLen) {
          PH_CHECK_SUCCESS_FCT(statusTmp, phCryptoSym_CalculateMac(
                  pDataParams->pCryptoDataParamsMac,
                  PH_CRYPTOSYM_MAC_MODE_CMAC | PH_EXCHANGE_BUFFER_LAST,
                  &pData[wTmp],
                  wDataLen - wTmp,
                  bCMAC,
                  &bMacLen
              ));
        }
      }

      /* Truncate the MAC generated */
      phalMfdfEVx_Sw_Int_TruncateMac(bCMAC);
      bMacLen = 8;
    } else {
      if (!(wDataLen)) {

        if (0u != (((wWorkBufferLen / PH_CRYPTOSYM_AES_BLOCK_SIZE) * PH_CRYPTOSYM_AES_BLOCK_SIZE))) {
          /* Calculate CMAC */
          PH_CHECK_SUCCESS_FCT(statusTmp, phCryptoSym_CalculateMac(
                  pDataParams->pCryptoDataParamsMac,
                  (PH_CRYPTOSYM_MAC_MODE_CMAC | PH_EXCHANGE_BUFFER_CONT),
                  bWorkBuffer,
                  ((wWorkBufferLen / PH_CRYPTOSYM_AES_BLOCK_SIZE) * PH_CRYPTOSYM_AES_BLOCK_SIZE),
                  bCMAC,
                  &bMacLen
              ));
        }

        pDataParams->bNoUnprocBytes = (uint8_t)(wWorkBufferLen % PH_CRYPTOSYM_AES_BLOCK_SIZE);
        (void)memcpy(pDataParams->pUnprocByteBuff,
            &bWorkBuffer[wWorkBufferLen - pDataParams->bNoUnprocBytes], pDataParams->bNoUnprocBytes);
      } else {
        wTmp = (PH_CRYPTOSYM_AES_BLOCK_SIZE - (wWorkBufferLen % PH_CRYPTOSYM_AES_BLOCK_SIZE));
        if (wDataLen < wTmp) {
          wTmp = wDataLen;
          pDataParams->bNoUnprocBytes = (uint8_t)(wTmp % PH_CRYPTOSYM_AES_BLOCK_SIZE);
          (void)memcpy(pDataParams->pUnprocByteBuff, &pData[wTmp - pDataParams->bNoUnprocBytes],
              pDataParams->bNoUnprocBytes);
        }
        (void)memcpy(&bWorkBuffer[wWorkBufferLen], pData, (wTmp - pDataParams->bNoUnprocBytes));

        PH_CHECK_SUCCESS_FCT(statusTmp, phCryptoSym_CalculateMac(
                pDataParams->pCryptoDataParamsMac,
                (PH_CRYPTOSYM_MAC_MODE_CMAC | PH_EXCHANGE_BUFFER_CONT),
                bWorkBuffer,
                (wWorkBufferLen + (wTmp - pDataParams->bNoUnprocBytes)),
                bCMAC,
                &bMacLen
            ));

        if (wTmp != wDataLen) {
          PH_CHECK_SUCCESS_FCT(statusTmp, phCryptoSym_CalculateMac(
                  pDataParams->pCryptoDataParamsMac,
                  PH_CRYPTOSYM_MAC_MODE_CMAC | PH_EXCHANGE_BUFFER_CONT,
                  &pData[wTmp],
                  (((wDataLen - wTmp) / PH_CRYPTOSYM_AES_BLOCK_SIZE) * PH_CRYPTOSYM_AES_BLOCK_SIZE),
                  bCMAC,
                  &bMacLen
              ));

          pDataParams->bNoUnprocBytes = (uint8_t)((wDataLen - wTmp) % PH_CRYPTOSYM_AES_BLOCK_SIZE);
          (void)memcpy(pDataParams->pUnprocByteBuff, &pData[wDataLen - pDataParams->bNoUnprocBytes],
              pDataParams->bNoUnprocBytes);
        }
      }
    }
#endif /*NXPBUILD__PHAL_MFDFEVX_NDA*/
    if ((bCommOption & PHAL_MFDFEVX_MAC_DATA_INCOMPLETE) == PHAL_MFDFEVX_MAC_DATA_INCOMPLETE) {
      bMacLen = 0;
    }
  } else if (pDataParams->bAuthMode == PHAL_MFDFEVX_AUTHENTICATE) {
    if ((bCommOption & 0xF0U) == PHAL_MFDFEVX_COMMUNICATION_MACD) {
      if (bCmdBuff[0] != PHAL_MFDFEVX_RESP_ADDITIONAL_FRAME) {
        pDataParams->bNoUnprocBytes = 0;
      }
#ifdef NXPBUILD__PHAL_MFDFEVX_NDA
      /* Load Iv */
      PH_CHECK_SUCCESS_FCT(statusTmp, phCryptoSym_LoadIv(
              pDataParams->pCryptoDataParamsEnc,
              pDataParams->bIv,
              bIvLen
          ));

      /* Encipher all the data except the last odd block */
      wIndex = 0;
      wNumDataBlocks = (wDataLen / bIvLen);

      /* Need to put in loop because we dont know how big the buffer is.
      Also we really dont need the encrypted data. Only MAC is required
      which is the last block of the cipher operation */
      while (0U != (wNumDataBlocks)) {
        PH_CHECK_SUCCESS_FCT(statusTmp, phCryptoSym_Encrypt(
                pDataParams->pCryptoDataParamsEnc,
                PH_CRYPTOSYM_CIPHER_MODE_CBC | PH_EXCHANGE_BUFFER_CONT,
                &pData[wIndex],
                bIvLen,
                bWorkBuffer
            ));

        (void)memcpy(pDataParams->bIv, bWorkBuffer, bIvLen);

        /* Load Iv */
        PH_CHECK_SUCCESS_FCT(statusTmp, phCryptoSym_LoadIv(
                pDataParams->pCryptoDataParamsEnc,
                pDataParams->bIv,
                bIvLen
            ));
        wNumDataBlocks--;
        wIndex = wIndex + bIvLen;
      }

      wWorkBufferLen = wDataLen % bIvLen;

      /* Check and encrypt the residual bytes of data */
      if (0U != (wWorkBufferLen)) {
        (void)memcpy(bWorkBuffer, &pData[wIndex], wWorkBufferLen);

        /* Apply padding. Always padding mode 1 is used while calculating MAC
        in AUTHENTICATE mode*/
        PH_CHECK_SUCCESS_FCT(statusTmp, phCryptoSym_ApplyPadding(
                PH_CRYPTOSYM_PADDING_MODE_1,
                bWorkBuffer,
                wWorkBufferLen,
                bIvLen,
                sizeof(bWorkBuffer),
                bWorkBuffer,
                &wTmp
            ));

        /* IV is already loaded in the while loop. Encipher the last block */
        PH_CHECK_SUCCESS_FCT(statusTmp, phCryptoSym_Encrypt(
                pDataParams->pCryptoDataParamsEnc,
                PH_CRYPTOSYM_CIPHER_MODE_CBC | PH_EXCHANGE_BUFFER_LAST,
                bWorkBuffer,
                wTmp,
                bWorkBuffer
            ));
      }

      /* If communication mode is set to plain
      * or bCommOption equals PHAL_MFDFEVX_MAC_DATA_INCOMPLETE, then MAC is only
      * calculated to update the init vector but is not sent with the data
      */
      if ((bCommOption & PHAL_MFDFEVX_MAC_DATA_INCOMPLETE) != PHAL_MFDFEVX_MAC_DATA_INCOMPLETE) {
        /* Reset the IV */
        (void)memset(pDataParams->bIv, 0x00, bIvLen);
        bMacLen = 0x04;
      }

      /*          bMacLen = ((bCommOption & PHAL_MFDFEVX_MAC_DATA_INCOMPLETE) == PHAL_MFDFEVX_MAC_DATA_INCOMPLETE) ? 0: 0x04;       */

      /* MAC is the MSB bytes of the last block */
      (void)memcpy(bCMAC, bWorkBuffer, 4);
#endif /*NXPBUILD__PHAL_MFDFEVX_NDA*/
    }
  } else {
    /* Else statement due to else if above. */
    bMacLen = 0;
  }

  /* Update wTotalLen = datalen + CMAClen*/
  wTotalLen = wDataLen + bMacLen;

  if (bIns != PHAL_MFDFEVX_ISO_CHAINING_MODE) {
    if (0U != (pDataParams->bWrappedMode)) {
      wFrameLen = PHAL_MFDFEVX_MAXWRAPPEDAPDU_SIZE;
    } else {
      wFrameLen = PHAL_MFDFEVX_MAXDFAPDU_SIZE;
    }
  } else {
    /* Get the Frame length */
    PH_CHECK_SUCCESS_FCT(statusTmp, phalMfdfEVx_Sw_Int_GetFrameLength(
            pDataParams,
            &wFSD,
            &wFSC
        ));

    if (0U != (pDataParams->bWrappedMode)) {
      wFrameLen = wFSC - 9u;
    } else {
      wFrameLen = wFSC - 4u;
    }
  }
#ifdef NXPBUILD__PHAL_MFDFEVX_NDA
  wIndex = 0;
#endif /* NXPBUILD__PHAL_MFDFEVX_NDA */

  if (wTotalLen == 0x0000U) {
    /* Single frame cmd without any data. Just send it */
    status = phalMfdfEVx_ExchangeCmd(
            pDataParams,
            pDataParams->pPalMifareDataParams,
            pDataParams->bWrappedMode,
            bCmdBuff,
            wCmdLen,
            &pRecv,
            &wRxlen
        );
    if (((status & PH_ERR_MASK) != PH_ERR_SUCCESS) &&
        ((status & PH_ERR_MASK) != PH_ERR_SUCCESS_CHAINING)) {
      /* Reset authentication status */
      if ((pDataParams->bAuthMode == PHAL_MFDFEVX_AUTHENTICATEISO) ||
          (pDataParams->bAuthMode == PHAL_MFDFEVX_AUTHENTICATEAES) ||
          (pDataParams->bAuthMode == PHAL_MFDFEVX_AUTHENTICATEEV2)) {
        phalMfdfEVx_Sw_Int_ResetAuthStatus(pDataParams);
      }

      return PH_ADD_COMPCODE(status, PH_COMP_AL_MFDFEVX);
    }
    if (wRxlen > 32U) {
      return PH_ADD_COMPCODE_FIXED(PH_ERR_PROTOCOL_ERROR, PH_COMP_AL_MFDFEVX);
    }
    (void)memcpy(bWorkBuffer, pRecv, wRxlen);
  } else {
    if (bIns != PHAL_MFDFEVX_ISO_CHAINING_MODE) {
      if (0U != (pDataParams->bWrappedMode)) {
        wFrameLen = PHAL_MFDFEVX_MAXWRAPPEDAPDU_SIZE;
      } else {
        wFrameLen = PHAL_MFDFEVX_MAXDFAPDU_SIZE;
      }
    } else {
      /* Get the Frame length */
      PH_CHECK_SUCCESS_FCT(statusTmp, phalMfdfEVx_Sw_Int_GetFrameLength(
              pDataParams,
              &wFSD,
              &wFSC
          ));

      if (0U != (pDataParams->bWrappedMode)) {
        wFrameLen = wFSC - 9u;
      } else {
        wFrameLen = wFSC - 4u;
      }
    }

#ifdef NXPBUILD__PHAL_MFDFEVX_NDA
    wIndex = 0;
#endif /* NXPBUILD__PHAL_MFDFEVX_NDA */
    wTmp = wTotalLen;

    if (wTmp <= (wFrameLen - wCmdLen)) {
      wApduLen = ((wCmdLen == 0x01U) &&
              (bIns == PHAL_MFDFEVX_ISO_CHAINING_MODE)) ? 0 : PHAL_MFDFEVX_WRAP_HDR_LEN;
      wCmdLen = ((wCmdLen == 0x01U) && (bIns == PHAL_MFDFEVX_ISO_CHAINING_MODE)) ? 0 : wCmdLen;

      /* Send in one shot */
      if (0U != (pDataParams->bWrappedMode)) {
        pApdu[1] = bCmdBuff[0]; /* DESFire cmd code in INS */

        if (wCmdLen > 0U) {
          pApdu[4] = (uint8_t)(wCmdLen + wTotalLen) - 0x01u;
        }

        PH_CHECK_SUCCESS_FCT(statusTmp, phpalMifare_ExchangeL4(
                pDataParams->pPalMifareDataParams,
                PH_EXCHANGE_BUFFER_FIRST |
                (((bIns == PHAL_MFDFEVX_ISO_CHAINING_MODE) &&
                        (0U != ((bCommOption & PHAL_MFDFEVX_MAC_DATA_INCOMPLETE)))) ? PH_EXCHANGE_TXCHAINING : 0),
                pApdu,
                wApduLen,
                &pRecv,
                &wRxlen));

        if (wCmdLen > 0U) {
          PH_CHECK_SUCCESS_FCT(statusTmp, phpalMifare_ExchangeL4(
                  pDataParams->pPalMifareDataParams,
                  PH_EXCHANGE_BUFFER_CONT |
                  (((bIns == PHAL_MFDFEVX_ISO_CHAINING_MODE) &&
                          (0U != (bCommOption & PHAL_MFDFEVX_MAC_DATA_INCOMPLETE))) ? PH_EXCHANGE_TXCHAINING : 0),
                  &bCmdBuff[1],
                  wCmdLen - 1u,
                  &pRecv,
                  &wRxlen));
        }

        PH_CHECK_SUCCESS_FCT(statusTmp, phpalMifare_ExchangeL4(
                pDataParams->pPalMifareDataParams,
                PH_EXCHANGE_BUFFER_CONT |
                (((bIns == PHAL_MFDFEVX_ISO_CHAINING_MODE) &&
                        (0U != ((bCommOption & PHAL_MFDFEVX_MAC_DATA_INCOMPLETE)))) ? PH_EXCHANGE_TXCHAINING : 0),
                pData,
                wDataLen,
                &pRecv,
                &wRxlen));

#ifdef NXPBUILD__PHAL_MFDFEVX_NDA
        if (bMacLen != 0x0000U) {
          PH_CHECK_SUCCESS_FCT(statusTmp, phpalMifare_ExchangeL4(
                  pDataParams->pPalMifareDataParams,
                  PH_EXCHANGE_BUFFER_CONT |
                  (((bIns == PHAL_MFDFEVX_ISO_CHAINING_MODE) &&
                          (0U != ((bCommOption & PHAL_MFDFEVX_MAC_DATA_INCOMPLETE)))) ? PH_EXCHANGE_TXCHAINING : 0),
                  bCMAC,
                  bMacLen,
                  &pRecv,
                  &wRxlen));
        }
#endif /*NXPBUILD__PHAL_MFDFEVX_NDA*/
        /* Le byte */
        PH_CHECK_SUCCESS_FCT(statusTmp, phpalMifare_ExchangeL4(
                pDataParams->pPalMifareDataParams,
                PH_EXCHANGE_BUFFER_LAST | (((bIns == PHAL_MFDFEVX_ISO_CHAINING_MODE) &&
                        (0U != ((bCommOption & PHAL_MFDFEVX_MAC_DATA_INCOMPLETE)))) ? PH_EXCHANGE_TXCHAINING : 0),
                &pApdu[2],
                (uint16_t)((pDataParams->dwPayLoadLen > 0xFEU) &&
                    (bIns == PHAL_MFDFEVX_ISO_CHAINING_MODE)) ? 0x02U : 0x01U,
                &pRecv,
                &wRxlen));
      } else {
        PH_CHECK_SUCCESS_FCT(statusTmp, phpalMifare_ExchangeL4(
                pDataParams->pPalMifareDataParams,
                PH_EXCHANGE_BUFFER_FIRST |
                (((bIns == PHAL_MFDFEVX_ISO_CHAINING_MODE) &&
                        (0U != ((bCommOption & PHAL_MFDFEVX_MAC_DATA_INCOMPLETE)))) ? PH_EXCHANGE_TXCHAINING : 0),
                bCmdBuff,
                wCmdLen,
                &pRecv,
                &wRxlen));

        PH_CHECK_SUCCESS_FCT(statusTmp, phpalMifare_ExchangeL4(
                pDataParams->pPalMifareDataParams,
                (((bMacLen == 0x00U) ? PH_EXCHANGE_BUFFER_LAST : PH_EXCHANGE_BUFFER_CONT)) |
                (((bIns == PHAL_MFDFEVX_ISO_CHAINING_MODE) &&
                        (0U != ((bCommOption & PHAL_MFDFEVX_MAC_DATA_INCOMPLETE)))) ? PH_EXCHANGE_TXCHAINING : 0),
                pData,
                wDataLen,
                &pRecv,
                &wRxlen));

#ifdef NXPBUILD__PHAL_MFDFEVX_NDA
        if (bMacLen != 0x0000U) {
          PH_CHECK_SUCCESS_FCT(statusTmp, phpalMifare_ExchangeL4(
                  pDataParams->pPalMifareDataParams,
                  PH_EXCHANGE_BUFFER_LAST |
                  (((bIns == PHAL_MFDFEVX_ISO_CHAINING_MODE) &&
                          (0U != ((bCommOption & PHAL_MFDFEVX_MAC_DATA_INCOMPLETE)))) ? PH_EXCHANGE_TXCHAINING : 0),
                  bCMAC,
                  bMacLen,
                  &pRecv,
                  &wRxlen));
        }
#endif /*NXPBUILD__PHAL_MFDFEVX_NDA*/
      }
      if (0U != (pDataParams->bWrappedMode)) {
        status = pRecv[wRxlen - 1u];
        wRxlen -= 2u;
      } else {
        status = pRecv[0];
        pRecv++; /* Increment pointer to point only to data */
        wRxlen -= 1u;
      }

      if ((status != PH_ERR_SUCCESS) &&
          ((status & PH_ERR_MASK) != PHAL_MFDFEVX_RESP_ADDITIONAL_FRAME)) {

        /* Reset authentication status */
        if ((pDataParams->bAuthMode == PHAL_MFDFEVX_AUTHENTICATEISO) ||
            (pDataParams->bAuthMode == PHAL_MFDFEVX_AUTHENTICATEAES) ||
            (pDataParams->bAuthMode == PHAL_MFDFEVX_AUTHENTICATEEV2)) {
          phalMfdfEVx_Sw_Int_ResetAuthStatus(pDataParams);
        }

        return phalMfdfEVx_Int_ComputeErrorResponse(pDataParams, (uint8_t) status);
      }

      (void)memcpy(bWorkBuffer, pRecv, wRxlen);
    } else {
#ifdef NXPBUILD__PHAL_MFDFEVX_NDA
      /* Send command and data. Chain data to PICC */
      if (wDataLen > 0x0200U) {
        statusTmp = phalMfdfEVx_Sw_Int_SendDataAndAddDataToPICC(
                pDataParams,
                bIns,
                bCmdBuff,
                wCmdLen,
                pData,
                wDataLen,
                bCMAC,
                bMacLen,
                bWorkBuffer,
                &wRxlen
            );
      } else {
        statusTmp = phalMfdfEVx_Sw_Int_SendDataToPICC(
                pDataParams,
                bIns,
                (bCommOption & PHAL_MFDFEVX_MAC_DATA_INCOMPLETE),
                bCmdBuff,
                wCmdLen,
                pData,
                wDataLen,
                bCMAC,
                bMacLen,
                bWorkBuffer,
                &wRxlen
            );
      }

      if ((statusTmp & PH_ERR_MASK) == PHAL_MFDFEVX_RESP_CHAINING) {
        return statusTmp;
      }

      if (((statusTmp & PH_ERR_MASK) != PH_ERR_SUCCESS) &&
          ((statusTmp & PH_ERR_MASK) != PH_ERR_SUCCESS_CHAINING)) {
        /* Reset authentication status */
        if ((pDataParams->bAuthMode == PHAL_MFDFEVX_AUTHENTICATEISO) ||
            (pDataParams->bAuthMode == PHAL_MFDFEVX_AUTHENTICATEAES) ||
            (pDataParams->bAuthMode == PHAL_MFDFEVX_AUTHENTICATEEV2)) {
          phalMfdfEVx_Sw_Int_ResetAuthStatus(pDataParams);
        }
        return statusTmp;
      }
#endif /*NXPBUILD__PHAL_MFDFEVX_NDA*/
    }
  }

  if ((status == PH_ERR_SUCCESS) &&
      ((bCommOption & PHAL_MFDFEVX_AUTHENTICATE_RESET) == PHAL_MFDFEVX_AUTHENTICATE_RESET)) {
    /* Reset authentication status */
    if ((pDataParams->bAuthMode == PHAL_MFDFEVX_AUTHENTICATEISO) ||
        (pDataParams->bAuthMode == PHAL_MFDFEVX_AUTHENTICATEAES) ||
        (pDataParams->bAuthMode == PHAL_MFDFEVX_AUTHENTICATEEV2)) {
      phalMfdfEVx_Sw_Int_ResetAuthStatus(pDataParams);
    }
    return PH_ERR_SUCCESS;
  }

  /* Verify the MAC. MAC is not received if in 0x0A MAC'd mode */
  if ((pDataParams->bAuthMode == PHAL_MFDFEVX_AUTHENTICATEISO) ||
      (pDataParams->bAuthMode == PHAL_MFDFEVX_AUTHENTICATEAES)) {
    if ((status & PH_ERR_MASK) != PH_ERR_SUCCESS_CHAINING) { /* if no chaining ongoing */
      /*
       * In case of delete app, check whether the command is called at APP level or PICC level.
       * 1. At APP level, the MAC is not returned.
       * 2. At PICC level, 8 bytes MAC is returned.
       * So to check whether its in APP level or PICC level. To do this, check for pDataParams->pAid. If its 0x00, then its PICC level
       * else its in APP level.
       */
      if (PHAL_MFDFEVX_CMD_DELETE_APPLN == bCmdBuff[0]) {
        /* if PICC level selected */
        if (memcmp(pDataParams->pAid, bAppId, 3) == 0x00) {
          /* If NO Mac is returned */
          if (wRxlen < 8U) {
            return PH_ADD_COMPCODE_FIXED(PH_ERR_PROTOCOL_ERROR, PH_COMP_AL_MFDFEVX);
          }
        }
        /* if APP level selected */
        else {
          /* Before returning status code, reset auth and set app ID to Master APP */
          phalMfdfEVx_Sw_Int_ResetAuthStatus(pDataParams);

          if ((memset(pDataParams->pAid, 0x00, 3)) == NULL) {
            return PH_ADD_COMPCODE_FIXED(PH_ERR_INTERNAL_ERROR, PH_COMP_AL_MFDFEVX);
          }
          /* return error if Mac is returned */
          if (wRxlen >= 8U) {
            return PH_ADD_COMPCODE_FIXED(PH_ERR_PROTOCOL_ERROR, PH_COMP_AL_MFDFEVX);
          } else {
            return PH_ERR_SUCCESS;
          }
        }
      } else {
        if (wRxlen < 8U) { /* If no CMAC received */
          return PH_ADD_COMPCODE_FIXED(PH_ERR_PROTOCOL_ERROR, PH_COMP_AL_MFDFEVX);
        }
      }
#ifdef NXPBUILD__PHAL_MFDFEVX_NDA
      if ((bCmdBuff[0] != PHAL_MFDFEVX_RESP_ADDITIONAL_FRAME)) {
        /* Load IV */
        PH_CHECK_SUCCESS_FCT(statusTmp, phCryptoSym_LoadIv(
                pDataParams->pCryptoDataParamsEnc,
                pDataParams->bIv,
                bIvLen
            ));
      }
#endif /*NXPBUILD__PHAL_MFDFEVX_NDA*/
      if ((statusTmp & PH_ERR_MASK) == PH_ERR_SUCCESS) {
        /* copy CMAC received from card*/
        (void)memcpy(bCMacCard, &bWorkBuffer[wRxlen - 8u], 8);
        wRxlen -= 8u;
        /* Copy the status byte at the end */
        bWorkBuffer[wRxlen] = (uint8_t) status;
#ifdef NXPBUILD__PHAL_MFDFEVX_NDA
        /* verify the MAC */
        PH_CHECK_SUCCESS_FCT(statusTmp, phCryptoSym_CalculateMac(
                pDataParams->pCryptoDataParamsEnc,
                (PH_CRYPTOSYM_MAC_MODE_CMAC),
                bWorkBuffer,
                wRxlen + 1U,
                bCMAC,
                &bMacLen
            ));

        if (memcmp(bCMacCard, bCMAC, 8) != 0) {
          phalMfdfEVx_Sw_Int_ResetAuthStatus(pDataParams);
          return PH_ADD_COMPCODE_FIXED(PH_ERR_INTEGRITY_ERROR, PH_COMP_AL_MFDFEVX);
        }

        /* Update IV */
        (void)memcpy(pDataParams->bIv, bCMAC, bIvLen);
#endif /*NXPBUILD__PHAL_MFDFEVX_NDA*/
      }
    }
  } else if (pDataParams->bAuthMode == PHAL_MFDFEVX_AUTHENTICATEEV2) {
    /*
    * In case of delete app, check whether the command is called at APP level or PICC level.
    * 1. At APP level, the MAC is not returned.
    * 2. At PICC level, 8 bytes MAC is returned.
    * So to check whether its in APP level or PICC level. To do this, check for pDataParams->pAid. If its 0x00, then its PICC level
    * else its in APP level.
    */
    if (PHAL_MFDFEVX_CMD_DELETE_APPLN == bCmdBuff[0]) {
      /* If PICC level is selected */
      if (memcmp(pDataParams->pAid, bAppId, 3) == 0x00) {
        /* If NO Mac is returned */
        if (wRxlen < 8U) {
          return PH_ADD_COMPCODE_FIXED(PH_ERR_PROTOCOL_ERROR, PH_COMP_AL_MFDFEVX);
        }
      }
      /* if APP level selected */
      else {
        /* Before returning status code, reset auth and set app ID to Master APP */
        phalMfdfEVx_Sw_Int_ResetAuthStatus(pDataParams);

        if ((memset(pDataParams->pAid, 0x00, 3)) == NULL) {
          return PH_ADD_COMPCODE_FIXED(PH_ERR_INTERNAL_ERROR, PH_COMP_AL_MFDFEVX);
        }
        /* return error if Mac is returned */
        if (wRxlen >= 8U) {
          return PH_ADD_COMPCODE_FIXED(PH_ERR_PROTOCOL_ERROR, PH_COMP_AL_MFDFEVX);
        } else {
          /* Increment the command counter. */
          pDataParams->wCmdCtr++;
          return PH_ERR_SUCCESS;
        }
      }
    }
    if ((status & PH_ERR_MASK) != PH_ERR_SUCCESS_CHAINING) { /* if no chaining ongoing */

      if ((statusTmp & PH_ERR_MASK) == PH_ERR_SUCCESS) {
        /* Increment the command counter.
        *  This increments irrespective of Plain mode or MAC mode.
        */
        pDataParams->wCmdCtr++;
      }

      if ((bCommOption & 0xF0U) == PHAL_MFDFEVX_COMMUNICATION_MACD) {
        if (wRxlen < 8U) { /* If no CMAC received */
          return PH_ADD_COMPCODE_FIXED(PH_ERR_PROTOCOL_ERROR, PH_COMP_AL_MFDFEVX);
        }
#ifdef NXPBUILD__PHAL_MFDFEVX_NDA
        if ((bCmdBuff[0] != PHAL_MFDFEVX_RESP_ADDITIONAL_FRAME)) {
          /* Load IV */
          PH_CHECK_SUCCESS_FCT(statusTmp, phCryptoSym_LoadIv(
                  pDataParams->pCryptoDataParamsMac,
                  pDataParams->bIv,
                  bIvLen
              ));
        }

        if ((statusTmp & PH_ERR_MASK) == PH_ERR_SUCCESS) {
          /* copy CMAC received from card*/
          (void)memcpy(bCMacCard, &bWorkBuffer[wRxlen - 8u], 8);
          wRxlen -= 8u;

          /*
          * Calculate MAC on RC || wCmdCtr || TI || RespData
          * bWorkBuffer is used as receive buffer so pDataParams->pUnprocByteBuff is used
          */
          pDataParams->bNoUnprocBytes = 0x00;
          pDataParams->pUnprocByteBuff[pDataParams->bNoUnprocBytes++] = 0x00;
          pDataParams->pUnprocByteBuff[pDataParams->bNoUnprocBytes++] = (uint8_t)(pDataParams->wCmdCtr);
          pDataParams->pUnprocByteBuff[pDataParams->bNoUnprocBytes++] = (uint8_t)(
                  pDataParams->wCmdCtr >> 8U);
          (void)memcpy(&pDataParams->pUnprocByteBuff[pDataParams->bNoUnprocBytes], pDataParams->bTi,
              PHAL_MFDFEVX_SIZE_TI);
          pDataParams->bNoUnprocBytes += PHAL_MFDFEVX_SIZE_TI;

          /* TBD:Required */
          (void)memcpy(&pDataParams->pUnprocByteBuff[pDataParams->bNoUnprocBytes], bWorkBuffer, wRxlen);
          pDataParams->bNoUnprocBytes += (uint8_t) wRxlen;

          /* verify the MAC */
          PH_CHECK_SUCCESS_FCT(statusTmp, phCryptoSym_CalculateMac(
                  pDataParams->pCryptoDataParamsMac,
                  (PH_CRYPTOSYM_MAC_MODE_CMAC | PH_EXCHANGE_DEFAULT),
                  pDataParams->pUnprocByteBuff,
                  pDataParams->bNoUnprocBytes,
                  bCMAC,
                  &bMacLen
              ));

          /* Truncate the MAC generated */
          phalMfdfEVx_Sw_Int_TruncateMac(bCMAC);

          /* Compare the CMAC from card and CMAC calculated */
          if (memcmp(bCMacCard, bCMAC, 8) != 0) {
            phalMfdfEVx_Sw_Int_ResetAuthStatus(pDataParams);
            return PH_ADD_COMPCODE_FIXED(PH_ERR_INTEGRITY_ERROR, PH_COMP_AL_MFDFEVX);
          }
        }
#endif /*NXPBUILD__PHAL_MFDFEVX_NDA*/
      }

    }

  } else {
    /* Should not get more bytes than the status bytes in case
    of no authentication */
    if (wRxlen > 0U) {
      return PH_ADD_COMPCODE_FIXED(PH_ERR_PROTOCOL_ERROR, PH_COMP_AL_MFDFEVX);
    }
  }

  return PH_ERR_SUCCESS;
}

void phalMfdfEVx_Sw_Int_ResetAuthStatus(phalMfdfEVx_Sw_DataParams_t *pDataParams)
{
  phStatus_t PH_MEMLOC_REM statusTmp;
  (void)memset(pDataParams->bSesAuthENCKey, 0x00, (size_t)sizeof(pDataParams->bSesAuthENCKey));
  (void)memset(pDataParams->bSesAuthMACKey, 0x00, (size_t)sizeof(pDataParams->bSesAuthMACKey));
  pDataParams->bKeyNo = 0xFF;
  (void)memset(pDataParams->bIv, 0x00, (size_t)sizeof(pDataParams->bIv));
  pDataParams->bAuthMode = PHAL_MFDFEVX_NOT_AUTHENTICATED;
  pDataParams->bCryptoMethod = 0xFF;
  pDataParams->wCmdCtr = 0;
  (void)memset(pDataParams->bTi, 0x00, PHAL_MFDFEVX_SIZE_TI);
  pDataParams->bNoUnprocBytes = 0;
  pDataParams->bLastBlockIndex = 0;
  statusTmp = phTMIUtils_ActivateTMICollection((phTMIUtils_t *) pDataParams->pTMIDataParams,
          PH_TMIUTILS_RESET_TMI);

  pDataParams->bCmdCode = PHAL_MFDFEVX_CMD_INVALID;

  /* Update the authentication state if VCA PC feature is required by the application. */
  if (pDataParams->pVCADataParams != NULL) {
    statusTmp = phalVca_SetSessionKeyUtility((phalVca_Sw_DataParams_t *) pDataParams->pVCADataParams,
            pDataParams->bSesAuthENCKey,
            pDataParams->bAuthMode);
  }

  /* satisfy compiler */
  PH_UNUSED_VARIABLE(statusTmp);
}

phStatus_t phalMfdfEVx_Sw_Int_SendDataToPICC(phalMfdfEVx_Sw_DataParams_t *pDataParams,
    uint8_t bIns, uint8_t bCommOption,
    uint8_t *pCmd, uint16_t wCmdLen, uint8_t *pData, uint16_t wDataLen, uint8_t *bLastChunk,
    uint16_t wLastChunkLen,
    uint8_t *pResp, uint16_t *pRespLen)
{
  /* Utility function to send data to PICC if more then wFrameLen*/
  phStatus_t  PH_MEMLOC_REM statusTmp;
  uint8_t     PH_MEMLOC_REM bStatusByte;
  uint16_t    PH_MEMLOC_REM wIndexDataLen = 0;
  uint16_t    PH_MEMLOC_REM wFrameLen = 0;
  uint8_t     PH_MEMLOC_REM pApdu[7] = { PHAL_MFDFEVX_WRAPPEDAPDU_CLA, 0x00, PHAL_MFDFEVX_WRAPPEDAPDU_P1, PHAL_MFDFEVX_WRAPPEDAPDU_P2, 0x00, 0x00, 0x00 };
  uint8_t     PH_MEMLOC_REM *pRecv = NULL;
  uint8_t     PH_MEMLOC_REM bExtended7816 = 0;
  uint8_t     PH_MEMLOC_REM bCommOptionTmp;
  uint16_t    PH_MEMLOC_REM wFSD = 0;
  uint16_t    PH_MEMLOC_REM wFSC = 0;
  uint16_t    PH_MEMLOC_REM wDataToBeSent = 0;
  uint16_t    PH_MEMLOC_REM wCopyDataLen = 0;
  uint16_t    PH_MEMLOC_REM wTmpDataLen = 0;
  uint16_t    PH_MEMLOC_REM wCopyLastChunkLen = 0;
  uint16_t    PH_MEMLOC_REM wTmpLastChunkLen = 0;
  uint16_t    PH_MEMLOC_REM wIndexLastChunkLen = 0;
  uint16_t    PH_MEMLOC_REM wApduHeaderLen = 0;
  uint16_t    PH_MEMLOC_REM wLeFieldLen = 0;
  uint16_t    PH_MEMLOC_REM wIndexCmdLen = 1;
  uint16_t    PH_MEMLOC_REM wTmpData;
  uint16_t    PH_MEMLOC_REM wTemLen = 0;

  if (bIns != PHAL_MFDFEVX_ISO_CHAINING_MODE) {
    if (0U != (pDataParams->bWrappedMode)) {
      wFrameLen = PHAL_MFDFEVX_MAXWRAPPEDAPDU_SIZE;
      wApduHeaderLen = PHAL_MFDFEVX_WRAP_HDR_LEN;
    } else {
      wFrameLen = PHAL_MFDFEVX_MAXDFAPDU_SIZE;
    }
  } else {
    /* Get the Frame length */
    PH_CHECK_SUCCESS_FCT(statusTmp, phalMfdfEVx_Sw_Int_GetFrameLength(
            pDataParams,
            &wFSD,
            &wFSC
        ));

    if (0U != (pDataParams->bWrappedMode)) {
      bExtended7816 = (uint8_t)(pDataParams->dwPayLoadLen > 0xFEU) ? 1 : 0;
      /* if Lc is more then 0xFF, length of Lc should be 3 bytes */
      wApduHeaderLen = PHAL_MFDFEVX_WRAP_HDR_LEN + (bExtended7816 ? 2 : 0);
    }
    wFrameLen = wFSC - 4u;
  }

  /* If Ins mode and wrapped mode are enable Le is sent with the last packet. So update Le when only last packet is sent */
  wLeFieldLen = ((bIns != PHAL_MFDFEVX_ISO_CHAINING_MODE) &&
          (pDataParams->bWrappedMode == 1U)) ? 1 : 0;

  /* Send the data to PICC */
  wTmpDataLen = wDataLen;
  wTmpLastChunkLen = wLastChunkLen;

  do {
    /* In case of wrapped mode, cmd byte is added as a part of Apdu Header. */
    wIndexCmdLen = wApduHeaderLen ? 1 : 0;

    /* this If condition is added to suppress QAC warning */
    wTemLen = wCmdLen;
    if (wCmdLen > 0U) {
      wTemLen = wCmdLen - wIndexCmdLen;
    }
    /* If Ins mode and wrapped mode are enable Le is sent with the last packet */
    if (pDataParams->bWrappedMode && (bIns == PHAL_MFDFEVX_ISO_CHAINING_MODE) &&
        ((wTmpDataLen + wTmpLastChunkLen + wTemLen) <= wFrameLen)) {
      wLeFieldLen = 1 + bExtended7816;
    }
    if (wTmpDataLen > 0U) {
      wCopyDataLen = (wTmpDataLen < (wFrameLen - (wTemLen + wApduHeaderLen + wLeFieldLen))) ?
          wTmpDataLen : (wFrameLen - (wTemLen + wApduHeaderLen + wLeFieldLen));
    }

    if (wTmpLastChunkLen > 0U) {
      wTmpData = wTemLen + wCopyDataLen + wApduHeaderLen + wLeFieldLen;
      wCopyLastChunkLen = (wTmpLastChunkLen < (wFrameLen - wTmpData)) ? wTmpLastChunkLen :
          (wFrameLen - wTmpData);
    }

    /* remaining data to be sent */
    /* this If condition is added to suppress QAC warning */
    wDataToBeSent = (wTmpDataLen - wCopyDataLen) + (wTmpLastChunkLen - wCopyLastChunkLen);

    wCmdLen = ((wCmdLen == 0x01U) && (bIns == PHAL_MFDFEVX_ISO_CHAINING_MODE)) ? 0 : wCmdLen;

    bCommOptionTmp = (uint8_t)(((!wDataToBeSent) && (!bCommOption)) ? 0 : 1);

    if (0U != (pDataParams->bWrappedMode)) {
      pApdu[1] = pCmd[0]; /* DESFire cmd code in INS */

      /* in case of ISO chaining mode, total length of data should be sent with the first frame*/
      if (bExtended7816 && (bIns == PHAL_MFDFEVX_ISO_CHAINING_MODE)) {
        pDataParams->dwPayLoadLen = pDataParams->dwPayLoadLen + wTemLen;
        pApdu[4] = (uint8_t)((pDataParams->dwPayLoadLen >> 16U) & 0xFFU);
        pApdu[5] = (uint8_t)((pDataParams->dwPayLoadLen >> 8U) & 0xFFU);
        pApdu[6] = (uint8_t)(pDataParams->dwPayLoadLen & 0xFFU);
      } else {
        pApdu[4] = (uint8_t)(wTemLen + ((bIns == PHAL_MFDFEVX_ISO_CHAINING_MODE) ?
                    pDataParams->dwPayLoadLen : (wCopyDataLen + wCopyLastChunkLen)));
      }

      wApduHeaderLen = ((bIns == PHAL_MFDFEVX_ISO_CHAINING_MODE) &&
              (wTemLen == 0U)) ? 0 : wApduHeaderLen;

      PH_CHECK_SUCCESS_FCT(statusTmp, phpalMifare_ExchangeL4(
              pDataParams->pPalMifareDataParams,
              PH_EXCHANGE_BUFFER_FIRST | (((bIns == PHAL_MFDFEVX_ISO_CHAINING_MODE) &&
                      (bCommOptionTmp != 0U)) ? PH_EXCHANGE_TXCHAINING : 0),
              pApdu,
              wApduHeaderLen,
              &pRecv,
              pRespLen));

      PH_CHECK_SUCCESS_FCT(statusTmp, phpalMifare_ExchangeL4(
              pDataParams->pPalMifareDataParams,
              PH_EXCHANGE_BUFFER_CONT | (((bIns == PHAL_MFDFEVX_ISO_CHAINING_MODE) &&
                      (bCommOptionTmp != 0U)) ? PH_EXCHANGE_TXCHAINING : 0),
              &pCmd[wIndexCmdLen],
              wTemLen,
              &pRecv,
              pRespLen));

      PH_CHECK_SUCCESS_FCT(statusTmp, phpalMifare_ExchangeL4(
              pDataParams->pPalMifareDataParams,
              PH_EXCHANGE_BUFFER_CONT | (((bIns == PHAL_MFDFEVX_ISO_CHAINING_MODE) &&
                      (bCommOptionTmp != 0U)) ? PH_EXCHANGE_TXCHAINING : 0),
              &pData[wIndexDataLen],
              wCopyDataLen,
              &pRecv,
              pRespLen));

      /* send last chunk */
      PH_CHECK_SUCCESS_FCT(statusTmp, phpalMifare_ExchangeL4(
              pDataParams->pPalMifareDataParams,
              PH_EXCHANGE_BUFFER_CONT | (((bIns == PHAL_MFDFEVX_ISO_CHAINING_MODE) &&
                      (bCommOptionTmp != 0U)) ? PH_EXCHANGE_TXCHAINING : 0),
              &bLastChunk[wIndexLastChunkLen],
              wCopyLastChunkLen,
              &pRecv,
              pRespLen));

      wLeFieldLen = ((bIns == PHAL_MFDFEVX_ISO_CHAINING_MODE) &&
              (bCommOptionTmp != 0U)) ? 0 : wLeFieldLen;

      /* Le byte */
      PH_CHECK_SUCCESS_FCT(statusTmp, phpalMifare_ExchangeL4(
              pDataParams->pPalMifareDataParams,
              PH_EXCHANGE_BUFFER_LAST | (((bIns == PHAL_MFDFEVX_ISO_CHAINING_MODE) &&
                      (bCommOptionTmp != 0U)) ? PH_EXCHANGE_TXCHAINING : 0),
              &pApdu[2],
              wLeFieldLen,
              &pRecv,
              pRespLen));
    } else {
      /* send cmd */
      PH_CHECK_SUCCESS_FCT(statusTmp, phpalMifare_ExchangeL4(
              pDataParams->pPalMifareDataParams,
              PH_EXCHANGE_BUFFER_FIRST | (((bIns == PHAL_MFDFEVX_ISO_CHAINING_MODE) &&
                      (bCommOptionTmp != 0U)) ? PH_EXCHANGE_TXCHAINING : 0),
              pCmd,
              wCmdLen,
              &pRecv,
              pRespLen));

      if (0U != (wCopyDataLen)) {
        /*  send data */
        PH_CHECK_SUCCESS_FCT(statusTmp, phpalMifare_ExchangeL4(
                pDataParams->pPalMifareDataParams,
                PH_EXCHANGE_BUFFER_CONT | (((bIns == PHAL_MFDFEVX_ISO_CHAINING_MODE) &&
                        (bCommOptionTmp != 0U)) ? PH_EXCHANGE_TXCHAINING : 0),
                &pData[wIndexDataLen],
                wCopyDataLen,
                &pRecv,
                pRespLen));
      }

      /* send last chunk */
      PH_CHECK_SUCCESS_FCT(statusTmp, phpalMifare_ExchangeL4(
              pDataParams->pPalMifareDataParams,
              PH_EXCHANGE_BUFFER_LAST | (((bIns == PHAL_MFDFEVX_ISO_CHAINING_MODE) &&
                      (bCommOptionTmp != 0U)) ? PH_EXCHANGE_TXCHAINING : 0),
              &bLastChunk[wIndexLastChunkLen],
              wCopyLastChunkLen,
              &pRecv,
              pRespLen));
    }

    /* copy number of data sent */
    wIndexDataLen += wCopyDataLen;
    wIndexLastChunkLen += wCopyLastChunkLen;

    /* copy the remaining data to be sent */
    /* this If condition is added to suppress QAC warning */
    if (wTmpDataLen > 0U) {
      wTmpDataLen = wTmpDataLen - wCopyDataLen;
    }

    /* this If condition is added to suppress QAC warning */
    if (wTmpLastChunkLen > 0U) {
      wTmpLastChunkLen = wTmpLastChunkLen - wCopyLastChunkLen;
    }

    wCopyDataLen = 0;
    wCopyLastChunkLen = 0;

    /* in case of 14443-4 chaining R-block that indicates a positive acknowledge */
    if ((bIns == PHAL_MFDFEVX_ISO_CHAINING_MODE) && (bCommOptionTmp != 0U)) {
      bStatusByte = (uint8_t)((pRecv[0] & 0xF0U) == 0xA0U) ? PHAL_MFDFEVX_RESP_ADDITIONAL_FRAME :
          PH_ERR_PROTOCOL_ERROR;
    } else {
      /* validate the response byte */
      if (0U != (pDataParams->bWrappedMode)) {
        (void)memcpy(pResp, pRecv, (*pRespLen) - 2);
        bStatusByte = pRecv[(*pRespLen) - 1];
        (*pRespLen) -= 2u;
      } else {
        (void)memcpy(pResp, &pRecv[1], (*pRespLen) - 1);
        bStatusByte = pRecv[0];
        (*pRespLen) -= 1u;
      }
    }

    if ((bStatusByte != PHAL_MFDFEVX_RESP_ADDITIONAL_FRAME) &&
        (bStatusByte != PH_ERR_SUCCESS)) {
      /* Reset authentication status */
      if ((pDataParams->bAuthMode == PHAL_MFDFEVX_AUTHENTICATEISO) ||
          (pDataParams->bAuthMode == PHAL_MFDFEVX_AUTHENTICATEAES)) {
        phalMfdfEVx_Sw_Int_ResetAuthStatus(pDataParams);
      }

      return phalMfdfEVx_Int_ComputeErrorResponse(pDataParams, bStatusByte);
    }

    /* Success returned even before writing all data? protocol error */
    if ((bStatusByte == PH_ERR_SUCCESS) && (bCommOptionTmp != 0U)) {
      /* Reset authentication status */
      if ((pDataParams->bAuthMode == PHAL_MFDFEVX_AUTHENTICATEISO) ||
          (pDataParams->bAuthMode == PHAL_MFDFEVX_AUTHENTICATEAES)) {
        phalMfdfEVx_Sw_Int_ResetAuthStatus(pDataParams);
      }

      return PH_ADD_COMPCODE_FIXED(PH_ERR_PROTOCOL_ERROR, PH_COMP_AL_MFDFEVX);
    }

    if (bStatusByte != 0x00U) {
      pCmd[0] = PHAL_MFDFEVX_RESP_ADDITIONAL_FRAME;
      wCmdLen = (bIns == PHAL_MFDFEVX_ISO_CHAINING_MODE) ? 0 : 1;
      wApduHeaderLen = (bIns == PHAL_MFDFEVX_ISO_CHAINING_MODE) ? 0 : wApduHeaderLen;
    }

  } while (0U != wDataToBeSent);

  return phalMfdfEVx_Int_ComputeErrorResponse(pDataParams, bStatusByte);
}

phStatus_t phalMfdfEVx_Sw_Int_SendDataAndAddDataToPICC(phalMfdfEVx_Sw_DataParams_t *pDataParams,
    uint8_t bIns, uint8_t *pCmd,
    uint16_t wCmdLen, uint8_t *pData, uint16_t wDataLen, uint8_t *pAddData, uint16_t wAddDataLen,
    uint8_t *pResp,
    uint16_t *pRespLen)
{
  /* Utility function to send encrypted data to PICC as and when it is available from SAM */
  phStatus_t  PH_MEMLOC_REM statusTmp;
  uint8_t     PH_MEMLOC_REM bStatusByte = 0;
  uint16_t    PH_MEMLOC_REM wIndex = 0;
  uint16_t    PH_MEMLOC_REM wDataLeft;
  uint16_t    PH_MEMLOC_REM wFrameLen = 0;
  uint8_t     PH_MEMLOC_REM pApdu[7] = { PHAL_MFDFEVX_WRAPPEDAPDU_CLA, 0x00, PHAL_MFDFEVX_WRAPPEDAPDU_P1, PHAL_MFDFEVX_WRAPPEDAPDU_P2, 0x00, 0x00, 0x00 };
  uint8_t     PH_MEMLOC_REM pLe[2] = { 0x00, 0x00 };
  uint8_t     PH_MEMLOC_REM *pRecv = NULL;
  uint16_t    PH_MEMLOC_REM wFSD = 0;
  uint16_t    PH_MEMLOC_REM wFSC = 0;
  uint16_t    PH_MEMLOC_REM wrappedApduHeaderLen = PHAL_MFDFEVX_WRAP_HDR_LEN;
  uint16_t    PH_MEMLOC_REM wrappedApduTrailerLen = 1;
  uint8_t     PH_MEMLOC_REM bIsExtended7816 = 0;
  uint16_t    PH_MEMLOC_REM wHeaderIdx = 0;
  uint16_t    PH_MEMLOC_REM wCmdIdx = 0;
  uint16_t    PH_MEMLOC_REM wAddDataIdx = 0;
  uint16_t    PH_MEMLOC_REM wTrailerIdx = 0;
  uint16_t    PH_MEMLOC_REM wWrappedApduHeaderLenLeft = 0;
  uint16_t    PH_MEMLOC_REM wWrappedApduTrailerLenLeft = 0;
  uint16_t    PH_MEMLOC_REM wCmdLenLeft = 0;
  uint16_t    PH_MEMLOC_REM wAddDataLenLeft = 0;
  uint16_t    PH_MEMLOC_REM wAddDataLenTotal = 0;
  uint16_t    PH_MEMLOC_REM wCmdLenTotal = 0;
  uint16_t    PH_MEMLOC_REM wDataLenTotal = 0;
  uint16_t    PH_MEMLOC_REM wMoreDataToTransmit = 0;

  if (bIns != PHAL_MFDFEVX_ISO_CHAINING_MODE_MAPPED) {
    if (0U != (pDataParams->bWrappedMode)) {
      wFrameLen = PHAL_MFDFEVX_MAXDFAPDU_SIZE;
    } else {
      wFrameLen = PHAL_MFDFEVX_MAXDFAPDU_SIZE;
    }
  } else {
    /* Get the Frame length */
    PH_CHECK_SUCCESS_FCT(statusTmp, phalMfdfEVx_Sw_Int_GetFrameLength(
            pDataParams,
            &wFSD,
            &wFSC
        ));

    if (0U != (pDataParams->bWrappedMode)) {
      bIsExtended7816 = (uint8_t)((wCmdLen + wDataLen + wAddDataLen - 0x01u) > 255U);
      wrappedApduHeaderLen += (bIsExtended7816 ? 2 : 0);
      wrappedApduTrailerLen += (bIsExtended7816 ? 1 : 0);
    }
    wFrameLen = wFSC - 4u;
  }

  wWrappedApduHeaderLenLeft = wrappedApduHeaderLen;
  wCmdLenLeft = wCmdLenTotal = (pDataParams->bWrappedMode) ? ((wCmdLen > 0) ? wCmdLen - 1 : 0) :
          wCmdLen; /* subtract instruction byte */
  wDataLeft = wDataLenTotal = wDataLen;
  wAddDataLenLeft = wAddDataLenTotal = wAddDataLen;
  wWrappedApduTrailerLenLeft = wrappedApduTrailerLen;

  do {
    if (0U != (pDataParams->bWrappedMode)) {
      if (bIns == PHAL_MFDFEVX_ISO_CHAINING_MODE_MAPPED) {
        if (wWrappedApduHeaderLenLeft > 0U) {
          wrappedApduHeaderLen = (wFrameLen / wWrappedApduHeaderLenLeft) ? wWrappedApduHeaderLenLeft :
              (wFrameLen % wWrappedApduHeaderLenLeft);
        } else {
          wrappedApduHeaderLen = 0;
        }
        if (wCmdLenLeft > 0U) {
          wCmdLen = ((wFrameLen - wrappedApduHeaderLen) / wCmdLenLeft) ? wCmdLenLeft : ((
                      wFrameLen - wrappedApduHeaderLen) % wCmdLenLeft);
        } else {
          wCmdLen = 0;
        }
        if (wDataLeft > 0U) {
          wDataLen = ((wFrameLen - wrappedApduHeaderLen - wCmdLen) / wDataLeft) ? wDataLeft : ((
                      wFrameLen - wrappedApduHeaderLen - wCmdLen) % wDataLeft);
        } else {
          wDataLen = 0;
        }
        if (wAddDataLenLeft > 0U) {
          wAddDataLen = ((wFrameLen - wrappedApduHeaderLen - wCmdLen - wDataLen) / wAddDataLenLeft)
              ? wAddDataLenLeft
              : ((wFrameLen - wrappedApduHeaderLen - wCmdLen - wDataLen) % wAddDataLenLeft);
        } else {
          wAddDataLen = 0;
        }
        if (wWrappedApduTrailerLenLeft > 0U) {
          wrappedApduTrailerLen = (0u != ((wFrameLen - wrappedApduHeaderLen - wCmdLen - wDataLen -
                          wAddDataLen) / wWrappedApduTrailerLenLeft))
              ? wWrappedApduTrailerLenLeft
              : ((wFrameLen - wrappedApduHeaderLen - wCmdLen - wDataLen - wAddDataLen) %
                  wWrappedApduTrailerLenLeft);
        }
      } else {
        if (wWrappedApduHeaderLenLeft > 0U) {
          wrappedApduHeaderLen = (0u != (wFrameLen / wWrappedApduHeaderLenLeft)) ?
              wWrappedApduHeaderLenLeft : (wFrameLen % wWrappedApduHeaderLenLeft);
        } else {
          wrappedApduHeaderLen = 0;
        }
        if (wWrappedApduTrailerLenLeft > 0U) {
          wrappedApduTrailerLen = (0u != ((wFrameLen - wrappedApduHeaderLen)) / wWrappedApduTrailerLenLeft)
              ? wWrappedApduTrailerLenLeft
              : ((wFrameLen - wrappedApduHeaderLen) % wWrappedApduTrailerLenLeft);
        } else {
          wrappedApduTrailerLen = 0;
        }
        if (wCmdLenLeft > 0U) {
          wCmdLen = (0u != ((wFrameLen - wrappedApduHeaderLen - wrappedApduTrailerLen) / wCmdLenLeft))
              ? wCmdLenLeft
              : ((wFrameLen - wrappedApduHeaderLen - wrappedApduTrailerLen) % wCmdLenLeft);
        } else {
          wCmdLen = 0;
        }
        if (wDataLeft > 0U) {
          wDataLen = (0u != ((wFrameLen - wrappedApduHeaderLen - wrappedApduTrailerLen - wCmdLen) /
                      wDataLeft))
              ? wDataLeft
              : ((wFrameLen - wrappedApduHeaderLen - wrappedApduTrailerLen - wCmdLen) % wDataLeft);
        } else {
          wDataLen = 0;
        }
        if (wAddDataLenLeft > 0U) {
          wAddDataLen = (0u != ((wFrameLen - wrappedApduHeaderLen - wrappedApduTrailerLen - wCmdLen -
                          wDataLen) / wAddDataLenLeft))
              ? wAddDataLenLeft
              : ((wFrameLen - wrappedApduHeaderLen - wrappedApduTrailerLen - wCmdLen - wDataLen) %
                  wAddDataLenLeft);
        } else {
          wAddDataLen = 0;
        }
      }

      pApdu[1] = pCmd[0]; /* DESFire cmd code in INS */
      if (bIsExtended7816 && (bIns == PHAL_MFDFEVX_ISO_CHAINING_MODE_MAPPED)) {
        pApdu[6] = (uint8_t)(wCmdLenTotal + wDataLenTotal + wAddDataLenTotal);
        pApdu[5] = (uint8_t)((wCmdLenTotal + wDataLenTotal + wAddDataLenTotal) >> 8U);
        /*pApdu[4] = 0; */
      } else {
        pApdu[4] = (uint8_t)(wCmdLen + ((bIns == PHAL_MFDFEVX_ISO_CHAINING_MODE_MAPPED) ?
                    (wDataLenTotal + wAddDataLenTotal) : (wDataLen + wAddDataLen)));
      }

      wMoreDataToTransmit = (wWrappedApduHeaderLenLeft - wrappedApduHeaderLen) +
          (wCmdLenLeft - wCmdLen) +
          (wDataLeft - wDataLen) +
          (wAddDataLenLeft - wAddDataLen) +
          (wWrappedApduTrailerLenLeft - wrappedApduTrailerLen);

      PH_CHECK_SUCCESS_FCT(statusTmp, phpalMifare_ExchangeL4(
              pDataParams->pPalMifareDataParams,
              PH_EXCHANGE_BUFFER_FIRST | (((bIns == PHAL_MFDFEVX_ISO_CHAINING_MODE_MAPPED) &&
                      (0u != wMoreDataToTransmit)) ? PH_EXCHANGE_TXCHAINING : 0),
              &pApdu[wHeaderIdx],
              wrappedApduHeaderLen,
              &pRecv,
              pRespLen));

      PH_CHECK_SUCCESS_FCT(statusTmp, phpalMifare_ExchangeL4(
              pDataParams->pPalMifareDataParams,
              PH_EXCHANGE_BUFFER_CONT | (((bIns == PHAL_MFDFEVX_ISO_CHAINING_MODE_MAPPED) &&
                      (0u != wMoreDataToTransmit)) ? PH_EXCHANGE_TXCHAINING : 0),
              &pCmd[1U + wCmdIdx],
              wCmdLen,
              &pRecv,
              pRespLen));

      PH_CHECK_SUCCESS_FCT(statusTmp, phpalMifare_ExchangeL4(
              pDataParams->pPalMifareDataParams,
              PH_EXCHANGE_BUFFER_CONT | (((bIns == PHAL_MFDFEVX_ISO_CHAINING_MODE_MAPPED) &&
                      (0u != wMoreDataToTransmit)) ? PH_EXCHANGE_TXCHAINING : 0),
              &pData[wIndex],
              wDataLen,
              &pRecv,
              pRespLen));

      PH_CHECK_SUCCESS_FCT(statusTmp, phpalMifare_ExchangeL4(
              pDataParams->pPalMifareDataParams,
              PH_EXCHANGE_BUFFER_CONT | (((bIns == PHAL_MFDFEVX_ISO_CHAINING_MODE_MAPPED) &&
                      (0u != wMoreDataToTransmit)) ? PH_EXCHANGE_TXCHAINING : 0),
              &pAddData[wAddDataIdx],
              wAddDataLen,
              &pRecv,
              pRespLen));

      /* Le byte */
      PH_CHECK_SUCCESS_FCT(statusTmp, phpalMifare_ExchangeL4(
              pDataParams->pPalMifareDataParams,
              PH_EXCHANGE_BUFFER_LAST | (((bIns == PHAL_MFDFEVX_ISO_CHAINING_MODE_MAPPED) &&
                      (0u != wMoreDataToTransmit)) ? PH_EXCHANGE_TXCHAINING : 0),
              &pLe[wTrailerIdx],
              wrappedApduTrailerLen,
              &pRecv,
              pRespLen));

      if (bIns == PHAL_MFDFEVX_ISO_CHAINING_MODE_MAPPED) {
        wHeaderIdx += wrappedApduHeaderLen;
        wWrappedApduHeaderLenLeft -= wrappedApduHeaderLen;
        wCmdIdx += wCmdLen;
        wCmdLenLeft -= wCmdLen;
        wTrailerIdx += wrappedApduTrailerLen;
        wWrappedApduTrailerLenLeft -= wrappedApduTrailerLen;
      }
    } else {
      if (wCmdLenLeft > 0U) {
        wCmdLen = ((wFrameLen) / wCmdLenLeft) ? wCmdLenLeft : ((wFrameLen) % wCmdLenLeft);
      } else {
        wCmdLen = 0;
      }
      if (wDataLeft > 0U) {
        wDataLen = ((wFrameLen - wCmdLen) / wDataLeft) ? wDataLeft : ((wFrameLen - wCmdLen) % wDataLeft);
      } else {
        wDataLen = 0;
      }
      if (wAddDataLenLeft > 0U) {
        wAddDataLen = ((wFrameLen - wCmdLen - wDataLen) / wAddDataLenLeft) ? wAddDataLenLeft : ((
                    wFrameLen - wCmdLen - wDataLen) % wAddDataLenLeft);
      } else {
        wAddDataLen = 0;
      }

      wMoreDataToTransmit = (wCmdLenLeft - wCmdLen) +
          (wDataLeft - wDataLen) +
          (wAddDataLenLeft - wAddDataLen);

      PH_CHECK_SUCCESS_FCT(statusTmp, phpalMifare_ExchangeL4(
              pDataParams->pPalMifareDataParams,
              PH_EXCHANGE_BUFFER_FIRST | (((bIns == PHAL_MFDFEVX_ISO_CHAINING_MODE_MAPPED) &&
                      (0u != wMoreDataToTransmit)) ? PH_EXCHANGE_TXCHAINING : 0),
              &pCmd[wCmdIdx],
              wCmdLen,
              &pRecv,
              pRespLen));

      PH_CHECK_SUCCESS_FCT(statusTmp, phpalMifare_ExchangeL4(
              pDataParams->pPalMifareDataParams,
              PH_EXCHANGE_BUFFER_CONT | (((bIns == PHAL_MFDFEVX_ISO_CHAINING_MODE_MAPPED) &&
                      (0u != wMoreDataToTransmit)) ? PH_EXCHANGE_TXCHAINING : 0),
              &pData[wIndex],
              wDataLen,
              &pRecv,
              pRespLen));

      PH_CHECK_SUCCESS_FCT(statusTmp, phpalMifare_ExchangeL4(
              pDataParams->pPalMifareDataParams,
              PH_EXCHANGE_BUFFER_LAST | (((bIns == PHAL_MFDFEVX_ISO_CHAINING_MODE_MAPPED) &&
                      (0u != wMoreDataToTransmit)) ? PH_EXCHANGE_TXCHAINING : 0),
              &pAddData[wAddDataIdx],
              wAddDataLen,
              &pRecv,
              pRespLen));

      wCmdIdx += wCmdLen;
      wCmdLenLeft -= wCmdLen;
    }

    wIndex += wDataLen;
    wDataLeft -= wDataLen;
    wAddDataIdx += wAddDataLen;
    wAddDataLenLeft -= wAddDataLen;

    /* in case of BIGISO, iso chaining is expected, and therefore R(ACK) block*/
    if ((bIns == PHAL_MFDFEVX_ISO_CHAINING_MODE_MAPPED) && (0u != wMoreDataToTransmit)) {
      /* in case of ACK */
      if ((pRecv[0] & 0xF0U) == 0xA0U) {
        continue;
      }
    }

    if (0U != (pDataParams->bWrappedMode)) {
      if ((*pRespLen) < 2U) {
        return PH_ADD_COMPCODE_FIXED(PH_ERR_PROTOCOL_ERROR, PH_COMP_AL_MFDFEVX);
      }
      (void)memcpy(pResp, pRecv, (*pRespLen) - 2);
      bStatusByte = pRecv[(*pRespLen) - 1];
      (*pRespLen) -= 2u;
    } else {
      if ((*pRespLen) < 1U) {
        return PH_ADD_COMPCODE_FIXED(PH_ERR_PROTOCOL_ERROR, PH_COMP_AL_MFDFEVX);
      }
      (void)memcpy(pResp, &pRecv[1], (*pRespLen) - 1);
      bStatusByte = pRecv[0];
      (*pRespLen) -= 1u;
    }

    if ((bStatusByte != PHAL_MFDFEVX_RESP_ADDITIONAL_FRAME) &&
        (bStatusByte != PH_ERR_SUCCESS)) {

      /* Reset authentication status */
      if ((pDataParams->bAuthMode == PHAL_MFDFEVX_AUTHENTICATEISO) ||
          (pDataParams->bAuthMode == PHAL_MFDFEVX_AUTHENTICATEAES)) {
        phalMfdfEVx_Sw_Int_ResetAuthStatus(pDataParams);
      }

      return phalMfdfEVx_Int_ComputeErrorResponse(pDataParams, bStatusByte);
    }

    /* Success returned even before writing all data? protocol error */
    if ((bStatusByte == PH_ERR_SUCCESS) && (wDataLeft != 0U)) {
      /* Reset authentication status */
      if ((pDataParams->bAuthMode == PHAL_MFDFEVX_AUTHENTICATEISO) ||
          (pDataParams->bAuthMode == PHAL_MFDFEVX_AUTHENTICATEAES)) {
        phalMfdfEVx_Sw_Int_ResetAuthStatus(pDataParams);
      }

      return PH_ADD_COMPCODE_FIXED(PH_ERR_PROTOCOL_ERROR, PH_COMP_AL_MFDFEVX);
    }

    if (bStatusByte != 0x00U) {
      pCmd[0] = PHAL_MFDFEVX_RESP_ADDITIONAL_FRAME;
      wCmdIdx = 0;
      wCmdLenLeft = (pDataParams->bWrappedMode) ? 0 : 1;
    }
  } while (0U != wMoreDataToTransmit);

  return phalMfdfEVx_Int_ComputeErrorResponse(pDataParams, bStatusByte);
}

phStatus_t phalMfdfEVx_Sw_Int_IsoRead(phalMfdfEVx_Sw_DataParams_t *pDataParams, uint16_t wOption,
    uint8_t *bCmdBuff,
    uint16_t wCmdLen, uint8_t **ppRxBuffer, uint32_t *pBytesRead)
{
  phStatus_t  PH_MEMLOC_REM status;
  uint16_t    PH_MEMLOC_REM statusTmp;
  uint16_t    PH_MEMLOC_REM wRxBufferSize;
  uint32_t    PH_MEMLOC_REM wNextPos;
  uint32_t    PH_MEMLOC_REM wRxlen;
  uint8_t     PH_MEMLOC_REM *pRecv = NULL;
  uint8_t     PH_MEMLOC_REM bBackupBytes[3];
#ifdef NXPBUILD__PHAL_MFDFEVX_NDA
  uint8_t     PH_MEMLOC_REM bMacLenComputed = 0;
  uint8_t     PH_MEMLOC_REM bCMacCard[8];
  uint8_t     PH_MEMLOC_REM bCMAC[16];
  uint8_t     PH_MEMLOC_REM bMacLen;
  uint8_t     PH_MEMLOC_REM bIvLen;
  uint16_t    PH_MEMLOC_REM wIntOption = PH_CRYPTOSYM_MAC_MODE_CMAC;
  uint32_t    PH_MEMLOC_REM wNumBlocks = 0;
  uint16_t    PH_MEMLOC_REM wIndex = 0;
  uint16_t    PH_MEMLOC_REM wDataLen = 0;
#endif /* NXPBUILD__PHAL_MFDFEVX_NDA */

#ifdef NXPBUILD__PHAL_MFDFEVX_NDA
  (void)memset(bCMAC, 0, 16);

  if (pDataParams->bAuthMode == PHAL_MFDFEVX_AUTHENTICATEAES) {
    bIvLen = PH_CRYPTOSYM_AES_BLOCK_SIZE;
  } else {
    bIvLen = PH_CRYPTOSYM_DES_BLOCK_SIZE;
  }

  if (wOption == PH_EXCHANGE_DEFAULT) {
    if ((pDataParams->bAuthMode == PHAL_MFDFEVX_AUTHENTICATEISO) ||
        (pDataParams->bAuthMode == PHAL_MFDFEVX_AUTHENTICATEAES) ||
        (pDataParams->bAuthMode == PHAL_MFDFEVX_AUTHENTICATE)) {
      PH_CHECK_SUCCESS_FCT(statusTmp, phCryptoSym_LoadIv(
              pDataParams->pCryptoDataParamsEnc,
              pDataParams->bIv,
              bIvLen
          ));
    }
    if (pDataParams->bAuthMode == PHAL_MFDFEVX_AUTHENTICATEEV2) {
      (void)memset(pDataParams->bIv, 0x00, bIvLen);
    }
  }
#endif /* NXPBUILD__PHAL_MFDFEVX_NDA */
  status = phpalMifare_ExchangeL4(
          pDataParams->pPalMifareDataParams,
          (wOption & PH_EXCHANGE_MODE_MASK),
          bCmdBuff,
          wCmdLen,
          ppRxBuffer,
          (uint16_t *) pBytesRead
      );

  /* First put everything on the reader Rx buffer upto buffer size - 60 */
  wRxlen = *pBytesRead;
  pRecv = *ppRxBuffer;

  if ((status != PH_ERR_SUCCESS) && ((status & PH_ERR_MASK) != PH_ERR_SUCCESS_CHAINING)) {
    /* Authentication should be reset */
#ifdef NXPBUILD__PHAL_MFDFEVX_NDA
    phalMfdfEVx_Sw_Int_ResetAuthStatus(pDataParams);
#endif /* NXPBUILD__PHAL_MFDFEVX_NDA */
    return status;
  }

  while ((status & PH_ERR_MASK) == PH_ERR_SUCCESS_CHAINING) {
    PH_CHECK_SUCCESS_FCT(statusTmp, phhalHw_GetConfig(
            pDataParams->pHalDataParams,
            PHHAL_HW_CONFIG_RXBUFFER_BUFSIZE,
            &wRxBufferSize
        ));

    wNextPos = *pBytesRead;
    (void)memcpy(bBackupBytes, &pRecv[wNextPos - 3u], 3);

    if ((wNextPos + PHAL_MFDFEVX_MAX_FRAME_SIZE) >= wRxBufferSize) {
      /* Calculate partical cmac if authenticated and return PH_ERR_SUCCESS_CHAINING */
      break;
    }

    PH_CHECK_SUCCESS_FCT(statusTmp, phhalHw_SetConfig(
            pDataParams->pHalDataParams,
            PHHAL_HW_CONFIG_RXBUFFER_STARTPOS,
            (uint16_t) wNextPos
        ));
    status = phpalMifare_ExchangeL4(
            pDataParams->pPalMifareDataParams,
            PH_EXCHANGE_RXCHAINING,
            bCmdBuff,
            wCmdLen,
            ppRxBuffer,
            (uint16_t *) pBytesRead
        );

    /* Put back the backed up bytes */
    (void)memcpy(&pRecv[wNextPos - 3u], bBackupBytes, 3);

    if ((status != PH_ERR_SUCCESS) &&
        ((status & PH_ERR_MASK) != PH_ERR_SUCCESS_CHAINING)) {
#ifdef NXPBUILD__PHAL_MFDFEVX_NDA
      /* Authentication should be reset */
      phalMfdfEVx_Sw_Int_ResetAuthStatus(pDataParams);
#endif /* NXPBUILD__PHAL_MFDFEVX_NDA */
      return status;
    }
    wRxlen = *pBytesRead;
  }

  /* The data is now in *ppRxBuffer, length = wRxlen */
  /* satisfy compiler */
  PH_UNUSED_VARIABLE(wRxlen);

#ifdef NXPBUILD__PHAL_MFDFEVX_NDA
  /* Size of MAC bytes */
  bMacLen = (pDataParams->bAuthMode == PHAL_MFDFEVX_AUTHENTICATE) ? 0x04 : 0x08;
#endif /* NXPBUILD__PHAL_MFDFEVX_NDA */
  if (status == PH_ERR_SUCCESS) {
    statusTmp = (*ppRxBuffer)[*pBytesRead - 2]; /* SW1 */
    statusTmp = statusTmp << 8U; /* Shift SW1 to MSB */
    statusTmp |= (*ppRxBuffer)[*pBytesRead - 1]; /* SW2 */

    if ((pDataParams->bAuthMode == PHAL_MFDFEVX_NOT_AUTHENTICATED) ||
        ((pDataParams->bAuthMode == PHAL_MFDFEVX_AUTHENTICATE) &&
            ((wOption & PH_EXCHANGE_CUSTOM_BITS_MASK) == PHAL_MFDFEVX_COMMUNICATION_PLAIN))) {
      *pBytesRead -= 2;
      return phalMfdfEVx_Int_ComputeErrorResponse(pDataParams, statusTmp);
    }
    statusTmp = phalMfdfEVx_Int_ComputeErrorResponse(pDataParams, statusTmp);

    if (statusTmp != PH_ERR_SUCCESS) {
#ifdef NXPBUILD__PHAL_MFDFEVX_NDA
      /* Authentication should be reset */
      phalMfdfEVx_Sw_Int_ResetAuthStatus(pDataParams);
#endif /* NXPBUILD__PHAL_MFDFEVX_NDA */
      return statusTmp;
    }
#ifdef NXPBUILD__PHAL_MFDFEVX_NDA
    /* Verify MAC. Dont consider SW1SW2 as MAC bytes */
    (void)memcpy(bCMacCard, &(*ppRxBuffer)[*pBytesRead - (bMacLen + 2U)], bMacLen);

    /* Subtract the MAC bytes */
    *pBytesRead -= (bMacLen + 2U);

    (*ppRxBuffer)[(*pBytesRead)] = 0x00;

    if (pDataParams->bAuthMode == PHAL_MFDFEVX_AUTHENTICATE) {
      wNumBlocks = *pBytesRead / bIvLen;

      while (0U != wNumBlocks) {
        /* Encrypt */
        PH_CHECK_SUCCESS_FCT(statusTmp, phCryptoSym_Encrypt(
                pDataParams->pCryptoDataParamsEnc,
                PH_CRYPTOSYM_CIPHER_MODE_CBC | PH_EXCHANGE_BUFFER_CONT,
                &(*ppRxBuffer)[wIndex],
                bIvLen,
                bCMAC
            ));

        wNumBlocks--;
        wIndex += bIvLen;

        (void)memcpy(pDataParams->bIv, bCMAC, bIvLen);

        PH_CHECK_SUCCESS_FCT(statusTmp, phCryptoSym_LoadIv(
                pDataParams->pCryptoDataParamsEnc,
                pDataParams->bIv,
                bIvLen
            ));
      }

      if (0U != (*pBytesRead % bIvLen)) {
        /* In case data to be read is longer than the RxBuffer size,
        the data is always sent in multiples of iv sizes from the card.
        Control should never come here when data read is still not
        complete */
        (void)memcpy(bCMAC, &(*ppRxBuffer)[wIndex], *pBytesRead % bIvLen);

        /* Apply padding */
        PH_CHECK_SUCCESS_FCT(statusTmp, phCryptoSym_ApplyPadding(
                PH_CRYPTOSYM_PADDING_MODE_1,
                bCMAC,
                (uint16_t)(*pBytesRead % bIvLen),
                bIvLen,
                sizeof(bCMAC),
                bCMAC,
                &wDataLen
            ));

        /* Encrypt */
        PH_CHECK_SUCCESS_FCT(statusTmp, phCryptoSym_Encrypt(
                pDataParams->pCryptoDataParamsEnc,
                PH_CRYPTOSYM_CIPHER_MODE_CBC | PH_EXCHANGE_BUFFER_CONT,
                bCMAC,
                wDataLen,
                bCMAC
            ));
      }
    } else if ((pDataParams->bAuthMode == PHAL_MFDFEVX_AUTHENTICATEISO) ||
        (pDataParams->bAuthMode == PHAL_MFDFEVX_AUTHENTICATEAES)) {
      wIntOption = PH_EXCHANGE_BUFFER_LAST | PH_CRYPTOSYM_MAC_MODE_CMAC;

      /* Calculate CMAC */
      PH_CHECK_SUCCESS_FCT(statusTmp, phCryptoSym_CalculateMac(
              pDataParams->pCryptoDataParamsEnc,
              wIntOption,
              *ppRxBuffer,
              (uint16_t) *pBytesRead + 1U,
              bCMAC,
              &bMacLenComputed
          ));
    } else {

      /* EV2 Auth mode needs to be handled */
    }

    if (memcmp(bCMAC, bCMacCard, bMacLen) != 0x00) {
      return PH_ADD_COMPCODE_FIXED(PH_ERR_INTEGRITY_ERROR, PH_COMP_AL_MFDFEVX);
    }

    if ((pDataParams->bAuthMode == PHAL_MFDFEVX_AUTHENTICATEISO) ||
        (pDataParams->bAuthMode == PHAL_MFDFEVX_AUTHENTICATEAES)) {
      /* Update IV */
      (void)memcpy(pDataParams->bIv, bCMAC, bMacLenComputed);
    }
#endif /* NXPBUILD__PHAL_MFDFEVX_NDA */
  } else {

  }
  return PH_ADD_COMPCODE((status & PH_ERR_MASK), PH_COMP_AL_MFDFEVX);
}

#ifdef NXPBUILD__PHAL_MFDFEVX_NDA
void phalMfdfEVx_Sw_Int_TruncateMac(uint8_t *pMac)
{
  uint8_t PH_MEMLOC_REM bIndex;
  uint8_t PH_MEMLOC_REM bIndex2;

  for (bIndex = 1U, bIndex2 = 0; bIndex < 16U; bIndex += 2U, bIndex2++) {
    pMac[bIndex2] = pMac[bIndex];
  }
}

phStatus_t phalMfdfEVx_Sw_Int_ComputeIv(uint8_t bIsResponse, uint8_t *pTi, uint16_t wCmdCtr,
    uint8_t *pIv)
{
  uint8_t PH_MEMLOC_REM bIndex = 0;
  uint8_t PH_MEMLOC_REM bCmdCtrMsb = (uint8_t)(wCmdCtr >> 8U);
  uint8_t PH_MEMLOC_REM bCmdCtrLsb = (uint8_t)(wCmdCtr & 0x00ffU);

  (void)memset(pIv, 0, PH_CRYPTOSYM_AES_BLOCK_SIZE);

  /* parameter checking */
  if ((pTi == NULL) || (pIv == NULL)) {
    return PH_ADD_COMPCODE_FIXED(PH_ERR_INTERNAL_ERROR, PH_COMP_AL_MFDFEVX);
  }

  if (0U != (bIsResponse)) {
    /* Form the IV for RespData as 0x5A||0xA5||TI||CmdCtr||0x0000000000000000 */
    pIv[bIndex++] = 0x5A;
    pIv[bIndex++] = 0xA5;
  } else {
    /* Form the IV for CmdData as 0xA5||0x5A||TI||CmdCtr||0x0000000000000000  */
    pIv[bIndex++] = 0xA5;
    pIv[bIndex++] = 0x5A;
  }

  pIv[bIndex++] = pTi[0];
  pIv[bIndex++] = pTi[1];
  pIv[bIndex++] = pTi[2];
  pIv[bIndex++] = pTi[3];
  pIv[bIndex++] = bCmdCtrLsb;
  pIv[bIndex++] = bCmdCtrMsb;

  return PH_ERR_SUCCESS;
}
#endif /* NXPBUILD__PHAL_MFDFEVX_NDA */

phStatus_t phalMfdfEVx_Sw_Int_GetFrameLength(phalMfdfEVx_Sw_DataParams_t *pDataParams,
    uint16_t *pFSD, uint16_t *pFSC)
{
  uint16_t    PH_MEMLOC_REM statusTmp;
  uint16_t    PH_MEMLOC_REM wTmp = 0;

  PH_CHECK_SUCCESS_FCT(statusTmp, phpalMifare_GetConfig(
          pDataParams->pPalMifareDataParams,
          PHPAL_I14443P4_CONFIG_FSI,
          &wTmp
      ));

  /* Get FSD */
  switch ((uint8_t)(wTmp >> 8U)) {
    case 0:
      *pFSD = 16;
      break;
    case 1:
      *pFSD = 24;
      break;
    case 2:
      *pFSD = 32;
      break;
    case 3:
      *pFSD = 40;
      break;
    case 4:
      *pFSD = 48;
      break;
    case 5:
      *pFSD = 64;
      break;
    case 6:
      *pFSD = 96;
      break;
    case 7:
      *pFSD = 128;
      break;
    case 8:
      *pFSD = 256;
      break;
    default:
      break;
  }

  /* Get FSC */
  switch ((uint8_t)(wTmp)) {
    case 0:
      *pFSC = 16;
      break;
    case 1:
      *pFSC = 24;
      break;
    case 2:
      *pFSC = 32;
      break;
    case 3:
      *pFSC = 40;
      break;
    case 4:
      *pFSC = 48;
      break;
    case 5:
      *pFSC = 64;
      break;
    case 6:
      *pFSC = 96;
      break;
    case 7:
      *pFSC = 128;
      break;
    case 8:
      *pFSC = 256;
      break;
    default:
      break;
  }

  return PH_ERR_SUCCESS;
}

#ifdef NXPBUILD__PHAL_MFDFEVX_NDA
phStatus_t phalMfdfEVx_Sw_Int_DecryptSDMData(phalMfdfEVx_Sw_DataParams_t *pDataParams,
    uint8_t *pSessEncKey, uint8_t *pIv,
    uint8_t *pInputOutputData, uint16_t wInputDataLen)
{
  phStatus_t statusTmp = PH_ERR_SUCCESS;

  if (pSessEncKey == NULL || pIv == NULL) {
    return PH_ADD_COMPCODE_FIXED(PH_ERR_INVALID_PARAMETER, PH_COMP_AL_MFDFEVX);
  }

  /* Load the session ENC Key to Crypto Object */
  PH_CHECK_SUCCESS_FCT(statusTmp, phCryptoSym_LoadKeyDirect(
          pDataParams->pCryptoDataParamsEnc,
          pSessEncKey,
          PH_CRYPTOSYM_KEY_TYPE_AES128));

  /* Load IV */
  PH_CHECK_SUCCESS_FCT(statusTmp, phCryptoSym_LoadIv(
          pDataParams->pCryptoDataParamsEnc,
          pIv,
          PH_CRYPTOSYM_AES_BLOCK_SIZE));

  /* Decrypt Data */
  PH_CHECK_SUCCESS_FCT(statusTmp, phCryptoSym_Decrypt(
          pDataParams->pCryptoDataParamsEnc,
          PH_CRYPTOSYM_CIPHER_MODE_CBC | PH_EXCHANGE_DEFAULT,
          pInputOutputData,
          wInputDataLen,
          pInputOutputData));

  return PH_ERR_SUCCESS;
}

phStatus_t phalMfdfEVx_Sw_Int_ComputeSDMSessionVectors(phalMfdfEVx_Sw_DataParams_t *pDataParams,
    uint8_t bOption,
    uint8_t bSdmOption, uint16_t wSrcKeyNo, uint16_t wSrcKeyVer, uint8_t *pUid, uint8_t bUidLen,
    uint8_t *pSDMReadCtr, uint8_t *pSessionKey)
{
  phStatus_t  PH_MEMLOC_REM statusTmp = PH_ERR_SUCCESS;
  uint16_t    PH_MEMLOC_REM wKeyType = 0x0000;
  uint8_t     PH_MEMLOC_REM aSV[32];
  uint8_t     PH_MEMLOC_REM bSvLen = 0;
  uint32_t    PH_MEMLOC_REM dwSDMReadCtr = 0;
  uint8_t     PH_MEMLOC_REM bKey[16] = { '\0' };
  uint8_t     PH_MEMLOC_REM bLen = 0x00;
  uint8_t     PH_MEMLOC_REM bTmpIV[16] = { '\0' };

  /* Validate the Counter value. */
  if (pSDMReadCtr != NULL) {
    dwSDMReadCtr = (uint32_t)(pSDMReadCtr[0] | (pSDMReadCtr[1] << 8) | (pSDMReadCtr[2] << 16) |
            (pSDMReadCtr[3] << 24));
    if (dwSDMReadCtr == 0xFFFFFFU) {
      return PH_ADD_COMPCODE_FIXED(PH_ERR_PARAMETER_OVERFLOW, PH_COMP_AL_MFDFEVX);
    }
  }

  /* Clear the session vector SV. */
  (void)memset(aSV, 0, sizeof(aSV));

  /* Frame the default values in session vector. */
  aSV[bSvLen++] = (uint8_t)((bOption == PHAL_MFDFEVX_SESSION_ENC) ? 0xC3 : 0x3C);
  aSV[bSvLen++] = (uint8_t)((bOption == PHAL_MFDFEVX_SESSION_ENC) ? 0x3C : 0xC3);
  aSV[bSvLen++] = 0x00;
  aSV[bSvLen++] = 0x01;
  aSV[bSvLen++] = 0x00;
  aSV[bSvLen++] = 0x80;

  /* Append the UID */
  if (0U != (bSdmOption & PHAL_MFDFEVX_VCUID_PRESENT)) {
    if (pUid != NULL) {
      (void)memcpy(&aSV[bSvLen], pUid, bUidLen);
      bSvLen += bUidLen;
    } else {
      return PH_ADD_COMPCODE_FIXED(PH_ERR_INVALID_PARAMETER, PH_COMP_AL_MFDFEVX);
    }
  }

  /* Append the SDM ReadCtr information. */
  if (bSdmOption & PHAL_MFDFEVX_RDCTR_PRESENT) {
    if (dwSDMReadCtr != 0U) {
      aSV[bSvLen++] = (uint8_t)(dwSDMReadCtr & 0xFF);
      aSV[bSvLen++] = (uint8_t)((dwSDMReadCtr & 0xFF00) >> 8U);
      aSV[bSvLen++] = (uint8_t)((dwSDMReadCtr & 0xFF0000) >> 16U);
    }
  }

  /* Update the SV length */
  if ((bSdmOption & PHAL_MFDFEVX_RDCTR_PRESENT) && (bSvLen > 16U)) {
    bSvLen = 32;
  } else {
    bSvLen = 16;
  }

  /* Now Get the Keys from SW Key Store */
  PH_CHECK_SUCCESS_FCT(statusTmp, phKeyStore_GetKey(
          pDataParams->pKeyStoreDataParams,
          wSrcKeyNo,
          wSrcKeyVer,
          PH_CRYPTOSYM_AES128_KEY_SIZE,
          bKey,
          &wKeyType));

  if (wKeyType != PH_CRYPTOSYM_KEY_TYPE_AES128) {
    return PH_ADD_COMPCODE_FIXED(PH_ERR_KEY, PH_COMP_AL_MFDFEVX);
  }

  /* load key */
  PH_CHECK_SUCCESS_FCT(statusTmp, phCryptoSym_LoadKeyDirect(
          pDataParams->pCryptoDataParamsMac,
          bKey,
          wKeyType));

  /* Create a Back up of the current IV */
  (void)memcpy(bTmpIV, pDataParams->bIv, PH_CRYPTOSYM_AES_BLOCK_SIZE);

  /* Load zero to IV */
  (void)memset(pDataParams->bIv, 0x00, PH_CRYPTOSYM_AES_BLOCK_SIZE);

  /* Load Iv */
  PH_CHECK_SUCCESS_FCT(statusTmp, phCryptoSym_LoadIv(
          pDataParams->pCryptoDataParamsMac,
          pDataParams->bIv,
          PH_CRYPTOSYM_AES_BLOCK_SIZE
      ));

  /* MAC SV1 to obtain KSesSDMFileReadEnc */
  PH_CHECK_SUCCESS_FCT(statusTmp, phCryptoSym_CalculateMac(
          pDataParams->pCryptoDataParamsMac,
          (PH_CRYPTOSYM_MAC_MODE_CMAC | PH_EXCHANGE_DEFAULT),
          aSV,
          bSvLen,
          bKey,
          &bLen));

  /* Copy the session  Key */
  (void)memcpy(pSessionKey, bKey, PH_CRYPTOSYM_AES_BLOCK_SIZE);

  /* Reload Back up IV */
  (void)memcpy(pDataParams->bIv, bTmpIV, PH_CRYPTOSYM_AES_BLOCK_SIZE);

  /* Load Iv */
  PH_CHECK_SUCCESS_FCT(statusTmp, phCryptoSym_LoadIv(
          pDataParams->pCryptoDataParamsMac,
          pDataParams->bIv,
          PH_CRYPTOSYM_AES_BLOCK_SIZE));

  return PH_ERR_SUCCESS;
}

phStatus_t phalMfdfEVx_Sw_Int_GenerateSDMSessionKeysAES(phalMfdfEVx_Sw_DataParams_t *pDataParams,
    uint8_t bSdmOption,
    uint16_t wKeyNo, uint16_t wKeyVer, uint8_t *pSDMReadCtr, uint8_t *pVCUID, uint8_t bUidLen,
    uint8_t *pSessEncKey,
    uint8_t *pSessMacKey)
{
  phStatus_t statusTmp = PH_ERR_SUCCESS;
  uint8_t PH_MEMLOC_REM bSV1[16] = { '\0' };
  uint8_t PH_MEMLOC_REM bSV2[16] = { '\0' };
  uint8_t PH_MEMLOC_REM bKey[16] = { '\0' };
  uint8_t PH_MEMLOC_REM bCmdLenMac = 0;
  uint8_t PH_MEMLOC_REM bCmdLenEnc = 0;
  uint16_t PH_MEMLOC_REM wKeyType = 0x0000;
  uint8_t PH_MEMLOC_REM bTmpIV[16] = { '\0' };
  uint8_t PH_MEMLOC_REM bMacLen = 0x00;

  if ((pSDMReadCtr == NULL) || (pVCUID == NULL)) {
    return PH_ADD_COMPCODE_FIXED(PH_ERR_INVALID_PARAMETER, PH_COMP_AL_MFDFEVX);
  }

  /* Validate the Output Buffers */
  if ((pSessEncKey == NULL) || (pSessMacKey == NULL)) {
    return PH_ADD_COMPCODE_FIXED(PH_ERR_INVALID_PARAMETER, PH_COMP_AL_MFDFEVX);
  }

  /* Clear the session vector.  */
  (void)memset(bSV1, 0x00, sizeof(bSV1));
  (void)memset(bSV2, 0x00, sizeof(bSV2));

  /* Prepare SV1 Buffer */
  bSV1[bCmdLenEnc++] = 0xC3;
  bSV1[bCmdLenEnc++] = 0x3C;

  bSV2[bCmdLenMac++] = 0x3C;
  bSV2[bCmdLenMac++] = 0xC3;

  bSV2[bCmdLenMac++] = bSV1[bCmdLenEnc++] = 0x00;
  bSV2[bCmdLenMac++] = bSV1[bCmdLenEnc++] = 0x01;
  bSV2[bCmdLenMac++] = bSV1[bCmdLenEnc++] = 0x00;
  bSV2[bCmdLenMac++] = bSV1[bCmdLenEnc++] = 0x80;

  /* Copy UID into bSV1 */
  if (0U != (bSdmOption & PHAL_MFDFEVX_VCUID_PRESENT)) {
    /* If VCUID should be considered for MAC calcluation, and pUID is passed as NULL, throw error */
    if (pVCUID != NULL) {
      (void)memcpy(&bSV1[bCmdLenEnc], pVCUID, bUidLen);
      bCmdLenEnc += bUidLen;
    } else {
      return PH_ADD_COMPCODE_FIXED(PH_ERR_INVALID_PARAMETER, PH_COMP_AL_MFDFEVX);
    }
  }

  /* Copy UID into bSV2 */
  if (0U != (bSdmOption & PHAL_MFDFEVX_VCUID_PRESENT)) {
    /* If VCUID should be considered for MAC calcluation, and pUID is passed as NULL, throw error */
    if (pVCUID != NULL) {
      (void)memcpy(&bSV2[bCmdLenMac], pVCUID, bUidLen);
      bCmdLenMac += bUidLen;
    } else {
      return PH_ADD_COMPCODE_FIXED(PH_ERR_INVALID_PARAMETER, PH_COMP_AL_MFDFEVX);
    }
  }

  /* Copy SDMReadCtr into bSV1 */
  if (0U != (bSdmOption & PHAL_MFDFEVX_RDCTR_PRESENT)) {
    /* If SDMReadCounter should be considered for MAC calcluation, and pUID is passed as NULL, throw error */
    if (pSDMReadCtr != NULL) {
      (void)memcpy(&bSV1[bCmdLenEnc], pSDMReadCtr, 0x03);
      bCmdLenEnc += 0x03;
    } else {
      return PH_ADD_COMPCODE_FIXED(PH_ERR_INVALID_PARAMETER, PH_COMP_AL_MFNTAG42XDNA);
    }
  }

  /* Copy SDMReadCtr into bSV2 */
  if (0U != (bSdmOption & PHAL_MFDFEVX_RDCTR_PRESENT)) {
    /* If SDMReadCounter should be considered for MAC calcluation, and pUID is passed as NULL, throw error */
    if (pSDMReadCtr != NULL) {
      (void)memcpy(&bSV2[bCmdLenMac], pSDMReadCtr, 0x03);
      bCmdLenMac += 0x03;
    } else {
      return PH_ADD_COMPCODE_FIXED(PH_ERR_INVALID_PARAMETER, PH_COMP_AL_MFNTAG42XDNA);
    }
  }

  /* Now Get the Keys from SW Key Store */
  PH_CHECK_SUCCESS_FCT(statusTmp, phKeyStore_GetKey(
          pDataParams->pKeyStoreDataParams,
          wKeyNo,
          wKeyVer,
          PH_CRYPTOSYM_AES128_KEY_SIZE,
          bKey,
          &wKeyType));

  if (wKeyType != PH_CRYPTOSYM_KEY_TYPE_AES128) {
    return PH_ADD_COMPCODE_FIXED(PH_ERR_KEY, PH_COMP_AL_MFDFEVX);
  }

  /* load key */
  PH_CHECK_SUCCESS_FCT(statusTmp, phCryptoSym_LoadKeyDirect(
          pDataParams->pCryptoDataParamsMac,
          bKey,
          wKeyType));

  /* Create a Back up of the current IV */
  (void)memcpy(bTmpIV, pDataParams->bIv, PH_CRYPTOSYM_AES_BLOCK_SIZE);

  /* Load zero to IV */
  (void)memset(pDataParams->bIv, 0x00, PH_CRYPTOSYM_AES_BLOCK_SIZE);

  /* Load Iv */
  PH_CHECK_SUCCESS_FCT(statusTmp, phCryptoSym_LoadIv(
          pDataParams->pCryptoDataParamsMac,
          pDataParams->bIv,
          PH_CRYPTOSYM_AES_BLOCK_SIZE));

  /* MAC SV1 to obtain KSesSDMFileReadEnc */
  PH_CHECK_SUCCESS_FCT(statusTmp, phCryptoSym_CalculateMac(
          pDataParams->pCryptoDataParamsMac,
          (PH_CRYPTOSYM_MAC_MODE_CMAC | PH_EXCHANGE_DEFAULT),
          bSV1,
          bCmdLenEnc,
          bKey,
          &bMacLen));

  /* Copy the session Enc Key */
  (void)memcpy(pSessEncKey, bKey, PH_CRYPTOSYM_AES_BLOCK_SIZE);

  (void)memset(bKey, 0x00, PH_CRYPTOSYM_AES_BLOCK_SIZE);

  /* MAC SV2 to obtain KSesSDMFileReadMac */
  PH_CHECK_SUCCESS_FCT(statusTmp, phCryptoSym_CalculateMac(
          pDataParams->pCryptoDataParamsMac,
          (PH_CRYPTOSYM_MAC_MODE_CMAC | PH_EXCHANGE_DEFAULT),
          bSV2,
          bCmdLenMac,
          bKey,
          &bMacLen));

  /* Copy session Mac Key */
  (void)memcpy(pSessMacKey, bKey, PH_CRYPTOSYM_AES_BLOCK_SIZE);

  /* Reload Back up IV */
  (void)memcpy(pDataParams->bIv, bTmpIV, PH_CRYPTOSYM_AES_BLOCK_SIZE);

  /* Load Iv */
  PH_CHECK_SUCCESS_FCT(statusTmp, phCryptoSym_LoadIv(
          pDataParams->pCryptoDataParamsMac,
          pDataParams->bIv,
          PH_CRYPTOSYM_AES_BLOCK_SIZE));

  return PH_ERR_SUCCESS;
}

phStatus_t phalMfdfEVx_Sw_Int_ComputeSDMIV(phalMfdfEVx_Sw_DataParams_t *pDataParams,
    uint8_t *pSessEncKey, uint8_t *pSDMReadCtr,
    uint8_t *pIV)
{
  phStatus_t statusTmp = PH_ERR_SUCCESS;
  uint8_t PH_MEMLOC_REM bTmpIV[16] = { '\0' };
  uint8_t PH_MEMLOC_REM bDataBuf[16] = { '\0' };

  /* Validate the IP Parameters */
  if ((pSessEncKey == NULL) || (pSDMReadCtr == NULL)) {
    return PH_ADD_COMPCODE_FIXED(PH_ERR_INVALID_PARAMETER, PH_COMP_AL_MFDFEVX);
  }
  /* Create a Back up of the current IV */
  (void)memcpy(bTmpIV, pDataParams->bIv, PH_CRYPTOSYM_AES_BLOCK_SIZE);

  /* Load zero to IV */
  (void)memset(pDataParams->bIv, 0x00, PH_CRYPTOSYM_AES_BLOCK_SIZE);

  /* Load Iv */
  PH_CHECK_SUCCESS_FCT(statusTmp, phCryptoSym_LoadIv(
          pDataParams->pCryptoDataParamsEnc,
          pDataParams->bIv,
          PH_CRYPTOSYM_AES_BLOCK_SIZE));

  /* load key */
  PH_CHECK_SUCCESS_FCT(statusTmp, phCryptoSym_LoadKeyDirect(
          pDataParams->pCryptoDataParamsEnc,
          pSessEncKey,
          PH_CRYPTOSYM_KEY_TYPE_AES128));

  /* Clear data buffer */
  (void)memset(bDataBuf, 0x00, PH_CRYPTOSYM_AES_BLOCK_SIZE);

  /* Prepare Data buffer to derive IV */
  bDataBuf[0] = pSDMReadCtr[0];
  bDataBuf[1] = pSDMReadCtr[1];
  bDataBuf[2] = pSDMReadCtr[2];

  /* Now Encrypt the data Buffer to derive IV */
  PH_CHECK_SUCCESS_FCT(statusTmp, phCryptoSym_Encrypt(
          pDataParams->pCryptoDataParamsEnc,
          PH_CRYPTOSYM_CIPHER_MODE_CBC,
          bDataBuf,
          PH_CRYPTOSYM_AES_BLOCK_SIZE,
          bDataBuf));

  (void)memcpy(pIV, bDataBuf, PH_CRYPTOSYM_AES_BLOCK_SIZE);

  /* Restore the IV */
  (void)memcpy(pDataParams->bIv, bTmpIV, PH_CRYPTOSYM_AES_BLOCK_SIZE);

  /* Load Iv */
  PH_CHECK_SUCCESS_FCT(statusTmp, phCryptoSym_LoadIv(
          pDataParams->pCryptoDataParamsEnc,
          pDataParams->bIv,
          PH_CRYPTOSYM_AES_BLOCK_SIZE));

  return PH_ERR_SUCCESS;
}
#endif /* NXPBUILD__PHAL_MFDFEVX_NDA */

#endif /* NXPBUILD__PHAL_MFDFEVX_SW */
