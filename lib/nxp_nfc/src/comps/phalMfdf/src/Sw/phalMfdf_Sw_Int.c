/*
*                     Copyright 2010-2019, NXP
*
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
* Internal functions of Software implementation of MIFARE DESFire EV1 contactless IC
* Application layer.
* $Author$
* $Revision$ (v06.11.00)
* $Date$
*/

#include <nxp_nfc/ph_Status.h>
#include <nxp_nfc/phpalMifare.h>
#include <nxp_nfc/ph_RefDefs.h>
#include <nxp_nfc/ph_TypeDefs.h>
#include <nxp_nfc/phTools.h>
#include <string.h>

#ifdef NXPBUILD__PH_CRYPTOSYM
#include <nxp_nfc/phCryptoSym.h>
#endif /* NXPBUILD__PH_CRYPTOSYM */

#ifdef NXPBUILD__PHAL_MFDF_SW

#include "../phalMfdf_Int.h"
#include "phalMfdf_Sw.h"
#include "phalMfdf_Sw_Int.h"

phStatus_t
phalMfdf_Sw_Int_GetData(
    phalMfdf_Sw_DataParams_t *pDataParams,
    uint8_t *pSendBuff,
    uint16_t wCmdLen,
    uint8_t **pResponse,
    uint16_t *pRxlen
)
{
  uint16_t   PH_MEMLOC_REM wOption;
  uint8_t    PH_MEMLOC_REM *pRecv = NULL;
  phStatus_t PH_MEMLOC_REM statusTmp = 0;
  uint8_t    PH_MEMLOC_REM bStatusByte = 0xFF;
  uint8_t    PH_MEMLOC_REM bCmdBuff[10];
  uint16_t   PH_MEMLOC_REM wNextPos = 0;
  uint16_t   PH_MEMLOC_REM wRxBufferSize = 0;
  uint8_t    PH_MEMLOC_REM bBackupBytes[3];
  uint8_t    PH_MEMLOC_REM pApdu[5] = { PHAL_MFDF_WRAPPEDAPDU_CLA, 0x00, PHAL_MFDF_WRAPPEDAPDU_P1, PHAL_MFDF_WRAPPEDAPDU_P2, 0x00 };
  uint8_t    PH_MEMLOC_REM bBackUpByte0;
  uint8_t    PH_MEMLOC_REM bBackUpByte1;
  uint8_t    PH_MEMLOC_REM bBackUpByte3 = 0;
  uint16_t   PH_MEMLOC_REM wBackUpLen = 0;
  uint16_t   PH_MEMLOC_REM wTmp = 0;

  /* Status and two other bytes to be backed up before getting new frame of data */
  (void)memset(bBackupBytes, 0x00, 3);

  PH_CHECK_SUCCESS_FCT(statusTmp, phhalHw_GetConfig(pDataParams->pHalDataParams,
          PHHAL_HW_CONFIG_RXBUFFER_STARTPOS,
          &wTmp
      ));

  wOption = PH_EXCHANGE_DEFAULT;
  if (0U != (pDataParams->bWrappedMode)) {
    if (wCmdLen > PHAL_MFDF_MAXWRAPPEDAPDU_SIZE) {
      return PH_ADD_COMPCODE_FIXED(PH_ERR_BUFFER_OVERFLOW, PH_COMP_AL_MFDF);
    }

    pApdu[1] = pSendBuff[0];  /* MIFARE DESFire contactless IC command code. */
    /* Encode APDU Length*/
    pApdu[4] = (uint8_t)wCmdLen - 1u; /* Set APDU Length. */

    statusTmp = phpalMifare_ExchangeL4(
            pDataParams->pPalMifareDataParams,
            (pApdu[4] == 0x00U) ? PH_EXCHANGE_DEFAULT : PH_EXCHANGE_BUFFER_FIRST,
            pApdu,
            PHAL_MFDF_WRAP_HDR_LEN,
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
      if (((0U != (pDataParams->bWrappedMode)) && (*pRxlen == 2U)) ||
          ((0U == (pDataParams->bWrappedMode)) && (*pRxlen == 1U))) {
        /* AF should always be accompanied by data. Otherwise
        it is a protocol error */
        return PH_ADD_COMPCODE_FIXED(PH_ERR_PROTOCOL_ERROR, PH_COMP_AL_MFDF);
      }
      /* One more status byte to read from MIFARE DESFire */
      bBackUpByte0 = pRecv[0];
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
        return PH_ADD_COMPCODE_FIXED(PH_ERR_PROTOCOL_ERROR, PH_COMP_AL_MFDF);
      }

      *pRxlen = wBackUpLen + *pRxlen;

      /* Set back the backed up bytes */
      pRecv[0] = bBackUpByte0;
      pRecv[1] = bBackUpByte1;
    } else {
      if (statusTmp != PH_ERR_SUCCESS) {
        return statusTmp;
      }
    }
  } else {
    /* Normal mode */
    if (wCmdLen > PHAL_MFDF_MAXDFAPDU_SIZE) {
      return PH_ADD_COMPCODE_FIXED(PH_ERR_BUFFER_OVERFLOW, PH_COMP_AL_MFDF);
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

  /* Status is 0xAF or Ox00? */
  if (*pRxlen > 0x0000U) {
    if (0U != (pDataParams->bWrappedMode)) {
      bStatusByte = (*pResponse)[(*pRxlen) - 1U];
    } else {
      bStatusByte = (*pResponse)[wTmp];
    }
  }

  if (bStatusByte == PHAL_MFDF_RESP_ADDITIONAL_FRAME) {
    if (((pDataParams->bWrappedMode > 0U) && (*pRxlen == 2U)) ||
        ((!(pDataParams->bWrappedMode > 0U)) && (*pRxlen == 1U))) {
      /* AF should always be accompanied by data. Otherwise
      it is a protocol error */
      return PH_ADD_COMPCODE_FIXED(PH_ERR_PROTOCOL_ERROR, PH_COMP_AL_MFDF);
    }

    if (0U != (pDataParams->bWrappedMode)) {
      /* Next position will ensure overwriting on the
      SW1SW2 received from previous command */
      wNextPos = (*pRxlen) - 2U;
      (void)memcpy(bBackupBytes, &(*pResponse)[wNextPos - 3u], 3U);
    } else {
      /* Backup the last byte */
      bBackUpByte3 = (*pResponse)[(*pRxlen - 1U)];
      (void)memcpy(bBackupBytes, &(*pResponse)[(*pRxlen - 3U)], 3U);
      wNextPos = (*pRxlen) - 1U;
    }

    PH_CHECK_SUCCESS_FCT(statusTmp, phhalHw_GetConfig(
            pDataParams->pHalDataParams,
            PHHAL_HW_CONFIG_RXBUFFER_BUFSIZE,
            &wRxBufferSize
        ));
  }

  while (bStatusByte == PHAL_MFDF_RESP_ADDITIONAL_FRAME) {
    if (((pDataParams->bWrappedMode > 0U) && (*pRxlen == 2U)) ||
        ((!(pDataParams->bWrappedMode > 0U)) && (*pRxlen == 1U))) {
      /* AF should always be accompanied by data. Otherwise
      it is a protocol error */
      return PH_ADD_COMPCODE_FIXED(PH_ERR_PROTOCOL_ERROR, PH_COMP_AL_MFDF);
    }
    if ((wNextPos + PHAL_MFDF_MAX_FRAME_SIZE) >= wRxBufferSize) {
      /* Return 0xAF and let the caller recall the function with
      option = PH_EXCHANGE_RXCHAINING */
      /* Return the data accumulated till now and its length */
      if (0U != (pDataParams->bWrappedMode)) {
        (*pRxlen) -= 2u;
      } else {
        (*pRxlen) -= 1u;
        (*pResponse)++;
      }
      return PH_ADD_COMPCODE_FIXED(PH_ERR_SUCCESS_CHAINING, PH_COMP_AL_MFDF);
    }
    PH_CHECK_SUCCESS_FCT(statusTmp, phhalHw_SetConfig(pDataParams->pHalDataParams,
            PHHAL_HW_CONFIG_RXBUFFER_STARTPOS,
            wNextPos
        ));

    bCmdBuff[0] = PHAL_MFDF_RESP_ADDITIONAL_FRAME;
    wCmdLen = 1;
    if (0U != (pDataParams->bWrappedMode)) {
      pApdu[1] = bCmdBuff[0];  /* MIFARE DESFire command code. */
      /* Encode APDU Length*/
      pApdu[4] = (uint8_t)wCmdLen - 1u; /* Set APDU Length. */

      statusTmp = phpalMifare_ExchangeL4(
              pDataParams->pPalMifareDataParams,
              (pApdu[4] == 0x00U) ? PH_EXCHANGE_DEFAULT : PH_EXCHANGE_BUFFER_FIRST,
              pApdu,
              PHAL_MFDF_WRAP_HDR_LEN,
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
        /* One or two more status bytes to read from MIFARE DESFire */
        bBackUpByte0 = pRecv[0];
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
        } else if (*pRxlen == 1U) {
          bStatusByte = pRecv[0];
          pRecv[wBackUpLen] = bStatusByte;
        } else {
          return PH_ADD_COMPCODE_FIXED(PH_ERR_PROTOCOL_ERROR, PH_COMP_AL_MFDF);
        }

        *pRxlen = wBackUpLen + *pRxlen;

        /* Set back the backed up bytes */
        pRecv[0] = bBackUpByte0;
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
      bStatusByte = (*pResponse)[(*pRxlen) - 1U];

      /* Putback the backed up bytes */
      (void)memcpy(&(*pResponse)[wNextPos - 3u], bBackupBytes, 3);

      wNextPos = (*pRxlen) - 2U;
      (void)memcpy(bBackupBytes, &(*pResponse)[wNextPos - 3u], 3);
    } else {
      bStatusByte = (*pResponse)[wNextPos];

      /* Put back the previously backedup byte */
      (*pResponse)[wNextPos] = bBackUpByte3;

      /* Putback the backed up bytes */
      (void)memcpy(&(*pResponse)[wNextPos - 2u], bBackupBytes, 3);

      wNextPos = (*pRxlen) - 1U;
      bBackUpByte3 = (*pResponse)[wNextPos];

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
  return phalMfdf_Int_ComputeErrorResponse(pDataParams, bStatusByte);
}

phStatus_t
phalMfdf_Sw_Int_ReadData_Plain(
    phalMfdf_Sw_DataParams_t *pDataParams,
    uint8_t bOption,
    uint8_t *bCmdBuff,
    uint16_t wCmdLen,
    uint8_t **ppRxdata,
    uint16_t *pRxdataLen
)
{
  uint16_t    PH_MEMLOC_REM status = 0;
  uint16_t    PH_MEMLOC_REM wRxlen = 0;
  uint8_t     PH_MEMLOC_REM *pRecv = NULL;

#ifdef NXPBUILD__PH_NDA_MFDF

  uint8_t     PH_MEMLOC_REM bWorkBuffer[24];
  uint16_t    PH_MEMLOC_REM wNumBlocks = 0;
  uint16_t    PH_MEMLOC_REM statusTmp = 0;
  uint8_t     PH_MEMLOC_REM bCMAC[PH_CRYPTOSYM_AES_BLOCK_SIZE];
  uint8_t     PH_MEMLOC_REM bCMacCard[8];
  uint8_t     PH_MEMLOC_REM bMacLen = 0;
  uint8_t     PH_MEMLOC_REM bIvLen = 0;
  uint8_t     PH_MEMLOC_REM *pTmp = NULL;
  uint16_t    PH_MEMLOC_REM wTmp = 0;

  (void)memset(bWorkBuffer, 0x00, 24);
  (void)memset(bCMAC, 0x00, PH_CRYPTOSYM_AES_BLOCK_SIZE);
  (void)memset(bCMacCard, 0x00, 8);

  if (pDataParams->bAuthMode == PHAL_MFDF_AUTHENTICATEAES) {
    bIvLen = PH_CRYPTOSYM_AES_BLOCK_SIZE;
  } else {
    bIvLen = PH_CRYPTOSYM_DES_BLOCK_SIZE;
  }

  if (((pDataParams->bAuthMode == PHAL_MFDF_AUTHENTICATEISO) ||
          (pDataParams->bAuthMode == PHAL_MFDF_AUTHENTICATEAES)) &&
      (bCmdBuff[0] != PHAL_MFDF_RESP_ADDITIONAL_FRAME)) {
    /* Check for 0xAF added above to ensure that we dont update the
    IV or calculate CMAC for cases where in the application has called
    this API with bOption = PHAL_MFDF_INFO_MOREDATA */

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

  }

#endif /* NXPBUILD__PH_NDA_MFDF */

  /* Send the command */
  status = phalMfdf_Sw_Int_GetData(
          pDataParams,
          bCmdBuff,
          wCmdLen,
          &pRecv,
          &wRxlen
      );

  if (((status & PH_ERR_MASK) != PH_ERR_SUCCESS) &&
      ((status & PH_ERR_MASK) != PH_ERR_SUCCESS_CHAINING)) {
#ifdef NXPBUILD__PH_NDA_MFDF

    /* Reset authentication status */
    if ((pDataParams->bAuthMode == PHAL_MFDF_AUTHENTICATEISO) ||
        (pDataParams->bAuthMode == PHAL_MFDF_AUTHENTICATEAES)) {
      phalMfdf_Sw_Int_ResetAuthStatus(pDataParams);
    }
    /* Component code is already added by GetData */

#endif /* NXPBUILD__PH_NDA_MFDF */

    return status;
  }

#ifdef NXPBUILD__PH_NDA_MFDF

  /* Verify the MAC */
  if ((pDataParams->bAuthMode == PHAL_MFDF_AUTHENTICATEISO) ||
      (pDataParams->bAuthMode == PHAL_MFDF_AUTHENTICATEAES)) {
    if (bCmdBuff[0] != PHAL_MFDF_RESP_ADDITIONAL_FRAME) {
      PH_CHECK_SUCCESS_FCT(statusTmp, phCryptoSym_LoadIv(
              pDataParams->pCryptoDataParamsEnc,
              pDataParams->bIv,
              bIvLen
          ));
    }

    if ((status & PH_ERR_MASK) != PH_ERR_SUCCESS_CHAINING) {
      (void)memcpy(bCMacCard, &pRecv[wRxlen - 8u], 8);
      wRxlen -= 8u;
      pRecv[wRxlen] = (uint8_t)status;

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
        return PH_ADD_COMPCODE_FIXED(PH_ERR_INTEGRITY_ERROR, PH_COMP_AL_MFDF);
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
  } else if ((pDataParams->bAuthMode == PHAL_MFDF_AUTHENTICATE)
      && ((bOption & 0xF0U) == PHAL_MFDF_COMMUNICATION_MACD)) {
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
      (void)memcpy(bWorkBuffer, &pRecv[wRxlen - (wRxlen % bIvLen)], (size_t)(wRxlen % bIvLen));

      /* Apply padding */
      PH_CHECK_SUCCESS_FCT(statusTmp, phCryptoSym_ApplyPadding(
              PH_CRYPTOSYM_PADDING_MODE_1,
              bWorkBuffer,
              wRxlen % bIvLen,
              bIvLen,
              sizeof(bWorkBuffer),
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
        return PH_ADD_COMPCODE_FIXED(PH_ERR_INTEGRITY_ERROR, PH_COMP_AL_MFDF);
      }
      /* Reset IV */
      (void)memset(pDataParams->bIv, 0x00, bIvLen);
    }
  } else {
    /* Will come here in case data transfer is plain
    and auth mode is 0x0A */
    bIvLen = 0x00;
  }

#endif /* NXPBUILD__PH_NDA_MFDF */

  *ppRxdata = pRecv;
  *pRxdataLen = wRxlen;

  if ((status & PH_ERR_MASK) == PH_ERR_SUCCESS_CHAINING) {
    return PH_ADD_COMPCODE_FIXED(PH_ERR_SUCCESS_CHAINING, PH_COMP_AL_MFDF);;
  }

  return PH_ERR_SUCCESS;
}

#ifdef NXPBUILD__PH_NDA_MFDF

phStatus_t
phalMfdf_Sw_Int_ReadData_Enc(
    phalMfdf_Sw_DataParams_t *pDataParams,
    uint8_t bOption,
    uint8_t *bCmdBuff,
    uint16_t wCmdLen,
    uint8_t **ppRxdata,
    uint16_t *pRxdataLen
)
{
  uint16_t    PH_MEMLOC_REM status;
  uint16_t    PH_MEMLOC_REM statusTmp;
  uint16_t    PH_MEMLOC_REM wRxlen;
  uint8_t     PH_MEMLOC_REM bCMAC[PH_CRYPTOSYM_AES_BLOCK_SIZE] = {0};
  uint8_t     PH_MEMLOC_REM bMacLen;
  uint16_t    PH_MEMLOC_REM wIndex;
  uint8_t     PH_MEMLOC_REM bNumPaddingBytes;
  uint8_t     PH_MEMLOC_REM bIvLen = 0;
  uint8_t     PH_MEMLOC_REM *pRecv = NULL;
  uint8_t     PH_MEMLOC_REM *pCrc = NULL;
  uint8_t     PH_MEMLOC_REM *bTmpIV[16];

  if (((pDataParams->bAuthMode == PHAL_MFDF_NOT_AUTHENTICATED) ||
          ((bOption & 0xF0U) != PHAL_MFDF_COMMUNICATION_ENC))) {
    return PH_ADD_COMPCODE_FIXED(PH_ERR_USE_CONDITION, PH_COMP_AL_MFDF);
  }
  if (pDataParams->bAuthMode == PHAL_MFDF_AUTHENTICATEAES) {
    bIvLen = PH_CRYPTOSYM_AES_BLOCK_SIZE;
  } else {
    bIvLen = PH_CRYPTOSYM_DES_BLOCK_SIZE;
  }

  if (((pDataParams->bAuthMode == PHAL_MFDF_AUTHENTICATEISO) ||
          (pDataParams->bAuthMode == PHAL_MFDF_AUTHENTICATEAES)) &&
      (bCmdBuff[0] != PHAL_MFDF_RESP_ADDITIONAL_FRAME)) {
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
  }

  /* Send the command */
  status = phalMfdf_Sw_Int_GetData(
          pDataParams,
          bCmdBuff,
          wCmdLen,
          &pRecv,
          &wRxlen
      );

  if (((status & PH_ERR_MASK) != PH_ERR_SUCCESS) &&
      ((status & PH_ERR_MASK) != PH_ERR_SUCCESS_CHAINING)) {
    /* Reset authentication status */
    if ((pDataParams->bAuthMode == PHAL_MFDF_AUTHENTICATEISO) ||
        (pDataParams->bAuthMode == PHAL_MFDF_AUTHENTICATEAES)) {
      phalMfdf_Sw_Int_ResetAuthStatus(pDataParams);
    }
    return status;
  }

  /* Decrypt the received data */
  if ((pDataParams->bAuthMode == PHAL_MFDF_AUTHENTICATEISO) ||
      (pDataParams->bAuthMode == PHAL_MFDF_AUTHENTICATEAES)) {
    PH_CHECK_SUCCESS_FCT(statusTmp, phCryptoSym_LoadIv(
            pDataParams->pCryptoDataParamsEnc,
            pDataParams->bIv,
            bIvLen
        ));

    if ((status & PH_ERR_MASK) == PH_ERR_SUCCESS_CHAINING) {
      /* Store the IV temporarily */
      (void)memcpy(bTmpIV, &pRecv[wRxlen - (2 * bIvLen)], bIvLen);

      if (bCmdBuff[0] != PHAL_MFDF_RESP_ADDITIONAL_FRAME) {
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
      wIndex = wRxlen;

      if (pDataParams->wPayLoadLen == 0U) {
        do {
          wIndex --;
          if (pRecv[wIndex] != 0x00U) {
            break;
          }
        } while (wIndex != 0x00U);

        if (pRecv[wIndex] != 0x80U) {
          /* Reset dwCrc to default */
          pDataParams->dwCrc = PH_TOOLS_CRC32_PRESET_DF8;
          return PH_ADD_COMPCODE_FIXED(PH_ERR_INTEGRITY_ERROR, PH_COMP_AL_MFDF);
        }

        /* CRC is in the 4 bytes before this */
        pCrc = &pRecv[wIndex - 4U];
        bNumPaddingBytes = (uint8_t)(wRxlen - wIndex);
      } else {
        /* Recv length should be equal to wPayLoadLen + 4 byte crc + padding */
        if (wRxlen < (pDataParams->wPayLoadLen + /* */ 4U)) {
          /* Reset dwCrc to default */
          pDataParams->dwCrc = PH_TOOLS_CRC32_PRESET_DF8;
          return PH_ADD_COMPCODE_FIXED(PH_ERR_PROTOCOL_ERROR, PH_COMP_AL_MFDF);
        }
        /* CRC Bytes */
        pCrc = &pRecv[pDataParams->wPayLoadLen];
        bNumPaddingBytes = (uint8_t)(wRxlen - pDataParams->wPayLoadLen - 4u);

        /* Verify the padding bytes */
        wIndex = pDataParams->wPayLoadLen + 4U;
        for (; wIndex < wRxlen; wIndex++) {
          if (pRecv[wIndex] != 0U) {
            /* Reset dwCrc to default */
            pDataParams->dwCrc = PH_TOOLS_CRC32_PRESET_DF8;
            return PH_ADD_COMPCODE_FIXED(PH_ERR_INTEGRITY_ERROR, PH_COMP_AL_MFDF);
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
              &(pDataParams->dwCrc)
          ));

      /* CRC to be calculated on data + status */
      PH_CHECK_SUCCESS_FCT(statusTmp, phTools_CalculateCrc32(
              PH_TOOLS_CRC_OPTION_DEFAULT,
              pDataParams->dwCrc,
              PH_TOOLS_CRC32_POLY_DF8,
              (uint8_t *)&status,
              0x01,
              &(pDataParams->dwCrc)
          ));

      if (memcmp(&(pDataParams->dwCrc), pCrc, 4) != 0) {
        /* Reset dwCrc to default */
        pDataParams->dwCrc = PH_TOOLS_CRC32_PRESET_DF8;
        return PH_ADD_COMPCODE_FIXED(PH_ERR_INTEGRITY_ERROR, PH_COMP_AL_MFDF);
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
              &(pDataParams->dwCrc)
          ));
    }
    /* Update IV to be used for next commands if no error */
    (void)memcpy(pDataParams->bIv, bTmpIV, bIvLen);

    /* Update the remaining length */
    if (pDataParams->wPayLoadLen != 0U) {
      pDataParams->wPayLoadLen -= wRxlen;
    }
  } else { /* pDataParams->bAuthMode == PHAL_MFDF_AUTHENTICATE */
    /* Load Iv */
    PH_CHECK_SUCCESS_FCT(statusTmp, phCryptoSym_LoadIv(
            pDataParams->pCryptoDataParamsEnc,
            pDataParams->bIv,
            bIvLen
        ));

    if ((status & PH_ERR_MASK) == PH_ERR_SUCCESS_CHAINING) {
      /* Update IV to be used for next set of data decryption */
      (void)memcpy(pDataParams->bIv, &pRecv[wRxlen - (2 * bIvLen)], bIvLen);

      if (bCmdBuff[0] != PHAL_MFDF_RESP_ADDITIONAL_FRAME) {
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
      wIndex = wRxlen;

      if (pDataParams->wPayLoadLen == 0U) {
        do {
          wIndex --;
          if (pRecv[wIndex] != 0x00U) {
            break;
          }
        } while (wIndex != 0x00U);

        if (pRecv[wIndex] != 0x80U) {
          /* Reset dwCrc to default */
          pDataParams->wCrc = PH_TOOLS_CRC16_PRESET_ISO14443A;
          return PH_ADD_COMPCODE_FIXED(PH_ERR_INTEGRITY_ERROR, PH_COMP_AL_MFDF);
        }

        /* CRC is in the 2 bytes before this */
        pCrc = &pRecv[wIndex - 2u];
        bNumPaddingBytes = (uint8_t)(wRxlen - wIndex);
      } else {
        /* Recv length should be equal to wPayLoadLen + 2 byte crc + padding */
        if (wRxlen < (pDataParams->wPayLoadLen + /* */ 2U)) {
          /* Reset dwCrc to default */
          pDataParams->wCrc = PH_TOOLS_CRC16_PRESET_ISO14443A;
          return PH_ADD_COMPCODE_FIXED(PH_ERR_PROTOCOL_ERROR, PH_COMP_AL_MFDF);
        }
        /* CRC Bytes */
        pCrc = &pRecv[pDataParams->wPayLoadLen];
        bNumPaddingBytes = (uint8_t)(wRxlen - pDataParams->wPayLoadLen - 2u);

        /* Verify the padding bytes */
        wIndex = pDataParams->wPayLoadLen + 2U;
        for (; wIndex < wRxlen; wIndex++) {
          if (pRecv[wIndex] != 0U) {
            /* Reset dwCrc to default */
            pDataParams->wCrc = PH_TOOLS_CRC16_PRESET_ISO14443A;
            return PH_ADD_COMPCODE_FIXED(PH_ERR_INTEGRITY_ERROR, PH_COMP_AL_MFDF);
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
              &(pDataParams->wCrc)
          ));

      if (memcmp(&(pDataParams->wCrc), pCrc, 2) != 0) {
        /* Reset wCrc to default */
        pDataParams->wCrc = PH_TOOLS_CRC16_PRESET_ISO14443A;
        return PH_ADD_COMPCODE_FIXED(PH_ERR_INTEGRITY_ERROR, PH_COMP_AL_MFDF);
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
              &(pDataParams->wCrc)
          ));

      /* Update the remaining length: */
      if (pDataParams->wPayLoadLen != 0U) {
        pDataParams->wPayLoadLen -= wRxlen;
      }
    }
  }
  *ppRxdata = pRecv;
  *pRxdataLen = wRxlen;

  return status;
}

phStatus_t
phalMfdf_Sw_Int_Write_Enc(
    phalMfdf_Sw_DataParams_t *pDataParams,
    uint8_t *bCmdBuff,
    uint16_t wCmdLen,
    uint8_t bPaddingOption,
    uint8_t *pData,
    uint16_t wDataLen
)

{
  phStatus_t  PH_MEMLOC_REM statusTmp = 0;
  uint16_t    PH_MEMLOC_REM status = 0;
  uint16_t    PH_MEMLOC_REM wRxlen = 0;
  uint16_t    PH_MEMLOC_REM wTmp = 0;
  uint8_t     PH_MEMLOC_REM bCMAC[PH_CRYPTOSYM_AES_BLOCK_SIZE];
  uint8_t     PH_MEMLOC_REM bCMacCard[8];
  uint8_t     PH_MEMLOC_REM pResp[16];
  uint8_t     PH_MEMLOC_REM bMacLen = 0;
  uint8_t     PH_MEMLOC_REM bIvLen = 0;
  uint8_t     PH_MEMLOC_REM bWorkBuffer[20];
  uint16_t    PH_MEMLOC_REM wCrc = PH_TOOLS_CRC16_PRESET_ISO14443A;
  uint32_t    PH_MEMLOC_REM dwCrc = PH_TOOLS_CRC32_PRESET_DF8;
  uint16_t    PH_MEMLOC_REM wFrameLen = 0;
  uint16_t    PH_MEMLOC_REM wTotalLen = 0;
  uint16_t    PH_MEMLOC_REM wLastChunkLen = 0;
  uint16_t    PH_MEMLOC_REM wDataLen1 = 0;
  uint16_t    PH_MEMLOC_REM wNumDataBlocks = 0;
  uint8_t     PH_MEMLOC_REM bLastChunk[32];
  uint8_t     PH_MEMLOC_REM *pRecv = NULL;
  uint8_t     PH_MEMLOC_REM pApdu[5] = { PHAL_MFDF_WRAPPEDAPDU_CLA, 0x00, PHAL_MFDF_WRAPPEDAPDU_P1, PHAL_MFDF_WRAPPEDAPDU_P2, 0x00 };

  (void)memset(bWorkBuffer, 0x00, 20);
  (void)memset(bCMacCard, 0x00, 8);
  (void)memset(bCMAC, 0x00, PH_CRYPTOSYM_AES_BLOCK_SIZE);
  (void)memset(bLastChunk, 0x00, 32);

  if (pDataParams->bAuthMode == PHAL_MFDF_AUTHENTICATEAES) {
    bIvLen = PH_CRYPTOSYM_AES_BLOCK_SIZE;
  } else if ((pDataParams->bAuthMode == PHAL_MFDF_AUTHENTICATEISO) ||
      (pDataParams->bAuthMode == PHAL_MFDF_AUTHENTICATE)) {
    bIvLen = PH_CRYPTOSYM_DES_BLOCK_SIZE;
  } else {
    /* This function cannot be used without authentication */
    return PH_ADD_COMPCODE_FIXED(PH_ERR_USE_CONDITION, PH_COMP_AL_MFDF);
  }

  if ((pDataParams->bAuthMode == PHAL_MFDF_AUTHENTICATEISO) ||
      (pDataParams->bAuthMode == PHAL_MFDF_AUTHENTICATEAES)) {
    /* Load Iv */
    PH_CHECK_SUCCESS_FCT(statusTmp, phCryptoSym_LoadIv(
            pDataParams->pCryptoDataParamsEnc,
            pDataParams->bIv,
            bIvLen
        ));

    /* First calculate CRC on the cmd+params */
    PH_CHECK_SUCCESS_FCT(statusTmp, phTools_CalculateCrc32(
            PH_TOOLS_CRC_OPTION_DEFAULT,
            dwCrc,
            PH_TOOLS_CRC32_POLY_DF8,
            bCmdBuff,
            wCmdLen,
            &dwCrc
        ));

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
      (void)memcpy(bLastChunk, &pData[wDataLen1], (size_t)(wDataLen - wDataLen1));
    }

    /* Add CRC */
    (void)memcpy(&bLastChunk[wDataLen - wDataLen1], &dwCrc, 4);

    /* Has a last frame */
    wLastChunkLen = wDataLen - wDataLen1 + 4U;

    /* Apply padding. If padding option is 2, we
       need to pad even if the data is already multiple
       of bIvLen */
    if ((0U != (wLastChunkLen % bIvLen)) ||
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
            PH_CRYPTOSYM_CIPHER_MODE_CBC | PH_EXCHANGE_BUFFER_CONT,
            bLastChunk,
            wLastChunkLen,
            bLastChunk
        ));

    wTotalLen = wDataLen1 + wLastChunkLen;

    /* Update the IV */
    (void)memcpy(pDataParams->bIv, &bLastChunk[wLastChunkLen - bIvLen], bIvLen);

  } else if (pDataParams->bAuthMode == PHAL_MFDF_AUTHENTICATE) {
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
    if ((0U != (wLastChunkLen % bIvLen)) ||
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
    /* Load Iv.  Use the last IV. But will reset the IV after decrypt operation*/
    PH_CHECK_SUCCESS_FCT(statusTmp, phCryptoSym_LoadIv(
            pDataParams->pCryptoDataParamsEnc,
            pDataParams->bIv,
            bIvLen
        ));

    /* DF4 Decrypt */
    PH_CHECK_SUCCESS_FCT(statusTmp, phCryptoSym_Encrypt(
            pDataParams->pCryptoDataParamsEnc,
            PH_CRYPTOSYM_CIPHER_MODE_CBC_DF4 | PH_EXCHANGE_BUFFER_CONT,
            bLastChunk,
            wLastChunkLen,
            bLastChunk
        ));

    wTotalLen = wDataLen1 + wLastChunkLen;

    /* Set IV to 00 for DF4 mode*/
    (void)memset(pDataParams->bIv, 0x00, bIvLen);
  } else {
    return PH_ADD_COMPCODE_FIXED(PH_ERR_AUTH_ERROR, PH_COMP_AL_MFDF);
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

  if (0U != (pDataParams->bWrappedMode)) {
    wFrameLen = PHAL_MFDF_MAXWRAPPEDAPDU_SIZE;
  } else {
    wFrameLen = PHAL_MFDF_MAXDFAPDU_SIZE;
  }

  wTmp = wTotalLen;

  if (wTmp <= (wFrameLen - wCmdLen)) {
    /* Send in one shot */
    if (0U != (pDataParams->bWrappedMode)) {
      pApdu[1] = bCmdBuff[0]; /* MIFARE DESFire cmd code in INS */
      pApdu[4] = (uint8_t)(wCmdLen + wTotalLen) - 0x01u;

      PH_CHECK_SUCCESS_FCT(statusTmp, phpalMifare_ExchangeL4(
              pDataParams->pPalMifareDataParams,
              PH_EXCHANGE_BUFFER_FIRST,
              pApdu,
              PHAL_MFDF_WRAP_HDR_LEN,
              &pRecv,
              &wRxlen));

      PH_CHECK_SUCCESS_FCT(statusTmp,  phpalMifare_ExchangeL4(
              pDataParams->pPalMifareDataParams,
              PH_EXCHANGE_BUFFER_CONT,
              &bCmdBuff[1],
              wCmdLen - 1u,
              &pRecv,
              &wRxlen));

      PH_CHECK_SUCCESS_FCT(statusTmp, phpalMifare_ExchangeL4(
              pDataParams->pPalMifareDataParams,
              PH_EXCHANGE_BUFFER_CONT,
              pData,
              wDataLen1,
              &pRecv,
              &wRxlen));

      if (wLastChunkLen != 0x0000U) {
        PH_CHECK_SUCCESS_FCT(statusTmp, phpalMifare_ExchangeL4(
                pDataParams->pPalMifareDataParams,
                PH_EXCHANGE_BUFFER_CONT,
                bLastChunk,
                wLastChunkLen,
                &pRecv,
                &wRxlen));
      }

      /* Le byte */
      PH_CHECK_SUCCESS_FCT(statusTmp, phpalMifare_ExchangeL4(
              pDataParams->pPalMifareDataParams,
              PH_EXCHANGE_BUFFER_LAST,
              &pApdu[2],
              0x01,
              &pRecv,
              &wRxlen));
    } else {
      PH_CHECK_SUCCESS_FCT(statusTmp, phpalMifare_ExchangeL4(
              pDataParams->pPalMifareDataParams,
              PH_EXCHANGE_BUFFER_FIRST,
              bCmdBuff,
              wCmdLen,
              &pRecv,
              &wRxlen));

      PH_CHECK_SUCCESS_FCT(statusTmp, phpalMifare_ExchangeL4(
              pDataParams->pPalMifareDataParams,
              (wLastChunkLen == 0x0000U) ? PH_EXCHANGE_BUFFER_LAST : PH_EXCHANGE_BUFFER_CONT,
              pData,
              wDataLen1, /* This is the size that is multiple of IV size */
              &pRecv,
              &wRxlen));

      if (wLastChunkLen != 0x0000U) {
        PH_CHECK_SUCCESS_FCT(statusTmp, phpalMifare_ExchangeL4(
                pDataParams->pPalMifareDataParams,
                PH_EXCHANGE_BUFFER_LAST,
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
      status = (uint8_t)pRecv[0];
      pRecv++; /* Increment pointer to point only to data */
      wRxlen -= 1u;
    }

    if (status != PH_ERR_SUCCESS) {
      /* Reset authentication status */
      if ((pDataParams->bAuthMode == PHAL_MFDF_AUTHENTICATEISO) ||
          (pDataParams->bAuthMode == PHAL_MFDF_AUTHENTICATEAES)) {
        phalMfdf_Sw_Int_ResetAuthStatus(pDataParams);
      }
      return phalMfdf_Int_ComputeErrorResponse(pDataParams, (uint8_t)status);
    }

    (void)memcpy(pResp, pRecv, wRxlen);
  } else {
    /* Send command and data. Chain data to PICC */
    statusTmp = phalMfdf_Sw_Int_SendDataToPICC(
            pDataParams,
            bCmdBuff,
            wCmdLen,
            pData,
            wDataLen1,
            pResp,
            &wRxlen
        );

    if (((wLastChunkLen != 0x0000U) &&
            ((statusTmp & PH_ERR_MASK) != PH_ERR_SUCCESS_CHAINING)) ||
        ((wLastChunkLen == 0x0000U) && ((statusTmp & PH_ERR_MASK) != PH_ERR_SUCCESS))) {
      /* Reset authentication status */
      if ((pDataParams->bAuthMode == PHAL_MFDF_AUTHENTICATEISO) ||
          (pDataParams->bAuthMode == PHAL_MFDF_AUTHENTICATEAES)) {
        phalMfdf_Sw_Int_ResetAuthStatus(pDataParams);
      }
      return statusTmp;
    }

    if (0U != (wLastChunkLen)) {
      bCmdBuff[0] = 0xAF;
      wCmdLen = 1;
      statusTmp = phalMfdf_Sw_Int_SendDataToPICC(
              pDataParams,
              bCmdBuff,
              wCmdLen,
              bLastChunk,
              wLastChunkLen,
              pResp,
              &wRxlen
          );

      if ((statusTmp & PH_ERR_MASK) != PH_ERR_SUCCESS) {
        /* Reset authentication status */
        if ((pDataParams->bAuthMode == PHAL_MFDF_AUTHENTICATEISO) ||
            (pDataParams->bAuthMode == PHAL_MFDF_AUTHENTICATEAES)) {
          phalMfdf_Sw_Int_ResetAuthStatus(pDataParams);
        }
        return statusTmp;
      }
    }
  }

  /* Verify the MAC. MAC is not received if in 0x0A MAC'd mode */
  if ((pDataParams->bAuthMode == PHAL_MFDF_AUTHENTICATEISO) ||
      (pDataParams->bAuthMode == PHAL_MFDF_AUTHENTICATEAES)) {
    if (wRxlen < 8U) { /* If no CMAC received */
      return PH_ADD_COMPCODE_FIXED(PH_ERR_PROTOCOL_ERROR, PH_COMP_AL_MFDF);
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
    pResp[wRxlen] = (uint8_t)status;

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
      phalMfdf_Sw_Int_ResetAuthStatus(pDataParams);
      return PH_ADD_COMPCODE_FIXED(PH_ERR_INTEGRITY_ERROR, PH_COMP_AL_MFDF);
    }

    /* Update IV */
    (void)memcpy(pDataParams->bIv, bCMAC, bIvLen);
  }
  return PH_ERR_SUCCESS;
}

#endif /* NXPBUILD__PH_NDA_MFDF */

phStatus_t
phalMfdf_Sw_Int_Write_Plain(
    phalMfdf_Sw_DataParams_t *pDataParams,
    uint8_t *bCmdBuff,
    uint16_t wCmdLen,
    uint8_t bCommOption,
    uint8_t *pData,
    uint16_t wDataLen
)
{
  phStatus_t  PH_MEMLOC_REM statusTmp = 0;
  uint16_t    PH_MEMLOC_REM status = 0;
  uint16_t    PH_MEMLOC_REM wRxlen = 0;
  uint8_t     PH_MEMLOC_REM bWorkBuffer[32];
  uint16_t    PH_MEMLOC_REM wFrameLen = 0;
  uint16_t    PH_MEMLOC_REM wTotalLen = 0;
  uint16_t    PH_MEMLOC_REM wTmp = 0;
  uint8_t     PH_MEMLOC_REM *pRecv = NULL;
  uint8_t     PH_MEMLOC_REM pApdu[5] = { PHAL_MFDF_WRAPPEDAPDU_CLA, 0x00, PHAL_MFDF_WRAPPEDAPDU_P1, PHAL_MFDF_WRAPPEDAPDU_P2, 0x00 };

#ifdef NXPBUILD__PH_NDA_MFDF
  uint16_t    PH_MEMLOC_REM wIndex = 0;
  uint16_t    PH_MEMLOC_REM wNumDataBlocks = 0;
  uint8_t     PH_MEMLOC_REM bCMAC[PH_CRYPTOSYM_AES_BLOCK_SIZE];
  uint8_t     PH_MEMLOC_REM bCMacCard[8];
  uint8_t     PH_MEMLOC_REM bMacLen = 0;
  uint8_t     PH_MEMLOC_REM bIvLen = 0;

  (void)memset(bCMAC, 0x00, PH_CRYPTOSYM_AES_BLOCK_SIZE);
  (void)memset(bCMacCard, 0x00, 8);
#endif /* NXPBUILD__PH_NDA_MFDF */

  (void)memset(bWorkBuffer, 0x00, 16);

#ifdef NXPBUILD__PH_NDA_MFDF

  if (pDataParams->bAuthMode == PHAL_MFDF_AUTHENTICATEAES) {
    bIvLen = PH_CRYPTOSYM_AES_BLOCK_SIZE;
  } else {
    bIvLen = PH_CRYPTOSYM_DES_BLOCK_SIZE;
  }

  if ((pDataParams->bAuthMode == PHAL_MFDF_AUTHENTICATEISO) ||
      (pDataParams->bAuthMode == PHAL_MFDF_AUTHENTICATEAES)) {
    /* Load Iv */
    PH_CHECK_SUCCESS_FCT(statusTmp, phCryptoSym_LoadIv(
            pDataParams->pCryptoDataParamsEnc,
            pDataParams->bIv,
            bIvLen
        ));
    if ((wCmdLen + wDataLen) <= bIvLen) {

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
      /* Need to calculate incomplete CMAC but need data size equal to block length */
      (void)memcpy(bWorkBuffer, bCmdBuff, wCmdLen);

      if (wDataLen != 0U) {
        if (0U != (wCmdLen % bIvLen)) {
          /* Copy data to make it multiple of IVlen */
          (void)memcpy(&bWorkBuffer[wCmdLen], pData, (size_t)(bIvLen - (wCmdLen % bIvLen)));
          wIndex = bIvLen - (wCmdLen % bIvLen);
        }

        /* Calculate incomplete CMAC over the cmd+params+somedata first */
        PH_CHECK_SUCCESS_FCT(statusTmp, phCryptoSym_CalculateMac(
                pDataParams->pCryptoDataParamsEnc,
                PH_CRYPTOSYM_MAC_MODE_CMAC | PH_EXCHANGE_BUFFER_CONT,
                bWorkBuffer,
                wCmdLen + wIndex,
                bCMAC,
                &bMacLen
            ));

        /* Calculate CMAC over the data now */
        PH_CHECK_SUCCESS_FCT(statusTmp, phCryptoSym_CalculateMac(
                pDataParams->pCryptoDataParamsEnc,
                PH_CRYPTOSYM_MAC_MODE_CMAC | PH_EXCHANGE_BUFFER_LAST,
                &pData[wIndex],
                wDataLen - wIndex,
                bCMAC,
                &bMacLen
            ));
      } else {
        /* Calculate MAC one shot */
        PH_CHECK_SUCCESS_FCT(statusTmp, phCryptoSym_CalculateMac(
                pDataParams->pCryptoDataParamsEnc,
                PH_CRYPTOSYM_MAC_MODE_CMAC,
                bWorkBuffer,
                wCmdLen,
                bCMAC,
                &bMacLen
            ));
      }
      /* Update the IV */
      (void)memcpy(pDataParams->bIv, bCMAC, bMacLen);
    }

    /* If communication mode is set to plain, then MAC is only
    calculated to update the init vector but is not sent with the data */
    if ((bCommOption & 0xF0U) ==  PHAL_MFDF_COMMUNICATION_PLAIN) {
      bMacLen = 0;
    } else {
      bMacLen = 8;
    }
  } else if (pDataParams->bAuthMode == PHAL_MFDF_AUTHENTICATE) {
    if ((bCommOption & 0xF0U) == PHAL_MFDF_COMMUNICATION_MACD) {
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

      /* Check and encrypt the residual bytes of data */
      if (0U != (wDataLen % bIvLen)) {
        (void)memcpy(bWorkBuffer, &pData[wIndex], (size_t)(wDataLen % bIvLen));

        /* Apply padding. Always padding mode 1 is used while calculating MAC
        in AUTHENTICATE mode*/
        PH_CHECK_SUCCESS_FCT(statusTmp, phCryptoSym_ApplyPadding(
                PH_CRYPTOSYM_PADDING_MODE_1,
                bWorkBuffer,
                (wDataLen % bIvLen),
                bIvLen,
                sizeof(bWorkBuffer),
                bWorkBuffer,
                &wTmp
            ));

        /* IV is already loaded in the while loop. Encipher the last block */
        PH_CHECK_SUCCESS_FCT(statusTmp, phCryptoSym_Encrypt(
                pDataParams->pCryptoDataParamsEnc,
                PH_CRYPTOSYM_CIPHER_MODE_CBC | PH_EXCHANGE_BUFFER_CONT,
                bWorkBuffer,
                wTmp,
                bWorkBuffer
            ));
      }

      /* Reset the IV */
      (void)memset(pDataParams->bIv, 0x00, bIvLen);

      /* MAC is the MSB bytes of the last block */
      (void)memcpy(bCMAC, bWorkBuffer, 4);
      bMacLen = 4;
    }
  } else {
    /* Else statement due to else if above. */
    bMacLen = 0;
  }

  /* Update wTotalLen = datalen + CMAClen*/
  wTotalLen = wDataLen + bMacLen;

#endif /* NXPBUILD__PH_NDA_MFDF */

  if (0U != (pDataParams->bWrappedMode)) {
    wFrameLen = PHAL_MFDF_MAXWRAPPEDAPDU_SIZE;
  } else {
    wFrameLen = PHAL_MFDF_MAXDFAPDU_SIZE;
  }

  if (wTotalLen == 0x0000U) {
    /* Single frame cmd without any data. Just send it */
    status = phalMfdf_ExchangeCmd(
            pDataParams,
            pDataParams->pPalMifareDataParams,
            pDataParams->bWrappedMode,
            bCmdBuff,
            wCmdLen,
            &pRecv,
            &wRxlen
        );
    if ((status & PH_ERR_MASK) != PH_ERR_SUCCESS) {
#ifdef NXPBUILD__PH_NDA_MFDF

      /* Reset authentication status */
      if ((pDataParams->bAuthMode == PHAL_MFDF_AUTHENTICATEISO) ||
          (pDataParams->bAuthMode == PHAL_MFDF_AUTHENTICATEAES)) {
        phalMfdf_Sw_Int_ResetAuthStatus(pDataParams);
      }

#endif /* NXPBUILD__PH_NDA_MFDF */

      return PH_ADD_COMPCODE(status, PH_COMP_AL_MFDF);
    }

    /* TBD: SA */
    if (wRxlen > 32U) {
      return PH_ADD_COMPCODE_FIXED(PH_ERR_PROTOCOL_ERROR, PH_COMP_AL_MFDF);
    }

    if (wRxlen > 0U) {
      (void)memcpy(bWorkBuffer, pRecv, (size_t) wRxlen);
    }
  } else {
    if (0U != (pDataParams->bWrappedMode)) {
      wFrameLen = PHAL_MFDF_MAXWRAPPEDAPDU_SIZE;
    } else {
      wFrameLen = PHAL_MFDF_MAXDFAPDU_SIZE;
    }

    wTmp = wTotalLen;

    if (wTmp <= (wFrameLen - wCmdLen)) {
      /* Send in one shot */
      if (0U != (pDataParams->bWrappedMode)) {
        pApdu[1] = bCmdBuff[0]; /* MIFARE DESFire cmd code in INS */
        pApdu[4] = (uint8_t)(wCmdLen + wTotalLen) - 0x01u;

        PH_CHECK_SUCCESS_FCT(statusTmp, phpalMifare_ExchangeL4(
                pDataParams->pPalMifareDataParams,
                PH_EXCHANGE_BUFFER_FIRST,
                pApdu,
                PHAL_MFDF_WRAP_HDR_LEN,
                &pRecv,
                &wRxlen));

        PH_CHECK_SUCCESS_FCT(statusTmp,  phpalMifare_ExchangeL4(
                pDataParams->pPalMifareDataParams,
                PH_EXCHANGE_BUFFER_CONT,
                &bCmdBuff[1],
                wCmdLen - 1u,
                &pRecv,
                &wRxlen));

        PH_CHECK_SUCCESS_FCT(statusTmp, phpalMifare_ExchangeL4(
                pDataParams->pPalMifareDataParams,
                PH_EXCHANGE_BUFFER_CONT,
                pData,
                wDataLen,
                &pRecv,
                &wRxlen));

#ifdef NXPBUILD__PH_NDA_MFDF

        if (bMacLen != 0x0000U) {
          PH_CHECK_SUCCESS_FCT(statusTmp, phpalMifare_ExchangeL4(
                  pDataParams->pPalMifareDataParams,
                  PH_EXCHANGE_BUFFER_CONT,
                  bCMAC,
                  bMacLen,
                  &pRecv,
                  &wRxlen));
        }

#endif /* NXPBUILD__PH_NDA_MFDF */

        /* Le byte */
        PH_CHECK_SUCCESS_FCT(statusTmp, phpalMifare_ExchangeL4(
                pDataParams->pPalMifareDataParams,
                PH_EXCHANGE_BUFFER_LAST,
                &pApdu[2],
                0x01,
                &pRecv,
                &wRxlen));
      } else {
        PH_CHECK_SUCCESS_FCT(statusTmp, phpalMifare_ExchangeL4(
                pDataParams->pPalMifareDataParams,
                PH_EXCHANGE_BUFFER_FIRST,
                bCmdBuff,
                wCmdLen,
                &pRecv,
                &wRxlen));

#ifdef NXPBUILD__PH_NDA_MFDF

        PH_CHECK_SUCCESS_FCT(statusTmp, phpalMifare_ExchangeL4(
                pDataParams->pPalMifareDataParams,
                (bMacLen == 0x00U) ? PH_EXCHANGE_BUFFER_LAST : PH_EXCHANGE_BUFFER_CONT,
                pData,
                wDataLen,
                &pRecv,
                &wRxlen));

        if (bMacLen != 0x0000U) {
          PH_CHECK_SUCCESS_FCT(statusTmp, phpalMifare_ExchangeL4(
                  pDataParams->pPalMifareDataParams,
                  PH_EXCHANGE_BUFFER_LAST,
                  bCMAC,
                  bMacLen,
                  &pRecv,
                  &wRxlen));
        }

#endif /* NXPBUILD__PH_NDA_MFDF */

      }
      if (0U != (pDataParams->bWrappedMode)) {
        status = pRecv[wRxlen - 1u];
        wRxlen -= 2u;
      } else {
        status = pRecv[0];
        pRecv++; /* Increment pointer to point only to data */
        wRxlen -= 1u;
      }

      if (status != PH_ERR_SUCCESS) {

#ifdef NXPBUILD__PH_NDA_MFDF

        /* Reset authentication status */
        if ((pDataParams->bAuthMode == PHAL_MFDF_AUTHENTICATEISO) ||
            (pDataParams->bAuthMode == PHAL_MFDF_AUTHENTICATEAES)) {
          phalMfdf_Sw_Int_ResetAuthStatus(pDataParams);
        }

#endif /* NXPBUILD__PH_NDA_MFDF */

        return phalMfdf_Int_ComputeErrorResponse(pDataParams, (uint8_t)status);
      }

      (void)memcpy(bWorkBuffer, pRecv, wRxlen);
    } else {
      /* Send command and data. Chain data to PICC */
      statusTmp = phalMfdf_Sw_Int_SendDataToPICC(
              pDataParams,
              bCmdBuff,
              wCmdLen,
              pData,
              wDataLen,
              bWorkBuffer,
              &wRxlen
          );

#ifdef NXPBUILD__PH_NDA_MFDF

      if (((bMacLen != 0x00U) &&
              ((statusTmp & PH_ERR_MASK) != PH_ERR_SUCCESS_CHAINING)) ||
          ((bMacLen == 0x00U) && ((statusTmp & PH_ERR_MASK) != PH_ERR_SUCCESS))) {
        /* Reset authentication status */
        if ((pDataParams->bAuthMode == PHAL_MFDF_AUTHENTICATEISO) ||
            (pDataParams->bAuthMode == PHAL_MFDF_AUTHENTICATEAES)) {
          phalMfdf_Sw_Int_ResetAuthStatus(pDataParams);
        }
        return statusTmp;
      }

      if (0U != (bMacLen)) {
        bCmdBuff[0] = 0xAF;
        wCmdLen = 1;
        statusTmp = phalMfdf_Sw_Int_SendDataToPICC(
                pDataParams,
                bCmdBuff,
                wCmdLen,
                bCMAC,
                bMacLen,
                bWorkBuffer,
                &wRxlen
            );

        if ((statusTmp & PH_ERR_MASK) != PH_ERR_SUCCESS) {
          /* Reset authentication status */
          if ((pDataParams->bAuthMode == PHAL_MFDF_AUTHENTICATEISO) ||
              (pDataParams->bAuthMode == PHAL_MFDF_AUTHENTICATEAES)) {
            phalMfdf_Sw_Int_ResetAuthStatus(pDataParams);
          }
          return statusTmp;
        }
      }

#endif /* NXPBUILD__PH_NDA_MFDF */

    }
  }

#ifdef NXPBUILD__PH_NDA_MFDF

  /* Verify the MAC. MAC is not received if in 0x0A MAC'd mode */
  if ((pDataParams->bAuthMode == PHAL_MFDF_AUTHENTICATEISO) ||
      (pDataParams->bAuthMode == PHAL_MFDF_AUTHENTICATEAES)) {
    if (wRxlen < 8U) { /* If no CMAC received */
      if (PHAL_MFDF_CMD_DELETE_APPLN == bCmdBuff[0]) {
        return PH_ERR_SUCCESS;
      } else {
        return PH_ADD_COMPCODE_FIXED(PH_ERR_PROTOCOL_ERROR, PH_COMP_AL_MFDF);
      }
    }

    /* Decrypt the bWorkBuffer*/
    PH_CHECK_SUCCESS_FCT(statusTmp, phCryptoSym_LoadIv(
            pDataParams->pCryptoDataParamsEnc,
            pDataParams->bIv,
            bIvLen
        ));

    /* copy CMAC received from card*/
    (void)memcpy(bCMacCard, &bWorkBuffer[wRxlen - 8u], 8);
    wRxlen -= 8u;

    /* Copy the status byte at the end */
    bWorkBuffer[wRxlen] = (uint8_t)status;

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
      phalMfdf_Sw_Int_ResetAuthStatus(pDataParams);
      return PH_ADD_COMPCODE_FIXED(PH_ERR_INTEGRITY_ERROR, PH_COMP_AL_MFDF);
    }

    /* Update IV */
    (void)memcpy(pDataParams->bIv, bCMAC, bIvLen);
  } else {
    /* Should not get more bytes than the status bytes in case
    of no authentication */
    if (wRxlen > 0U) {
      return PH_ADD_COMPCODE_FIXED(PH_ERR_PROTOCOL_ERROR, PH_COMP_AL_MFDF);
    }
  }

#endif /* NXPBUILD__PH_NDA_MFDF */

  return PH_ERR_SUCCESS;
}

#ifdef NXPBUILD__PH_NDA_MFDF

void
phalMfdf_Sw_Int_ResetAuthStatus(phalMfdf_Sw_DataParams_t *pDataParams)
{
  (void)memset(pDataParams->bSessionKey, 0x00, (size_t)sizeof(pDataParams->bSessionKey));
  pDataParams->bKeyNo = 0xFF;
  (void)memset(pDataParams->bIv, 0x00, (size_t)sizeof(pDataParams->bIv));
  pDataParams->bAuthMode = PHAL_MFDF_NOT_AUTHENTICATED;
  pDataParams->bCryptoMethod = 0xFF;
  pDataParams->bLastBlockIndex = 0;
}

#endif /* NXPBUILD__PH_NDA_MFDF */

phStatus_t
phalMfdf_Sw_Int_SendDataToPICC(
    phalMfdf_Sw_DataParams_t *pDataParams,
    uint8_t *pCmd,
    uint16_t wCmdLen,
    uint8_t *pData,
    uint16_t wDataLen,
    uint8_t *pResp,
    uint16_t *pRespLen
)
{
  /* Utility function to send encrypted data to PICC as and when it is available from SAM */
  phStatus_t  PH_MEMLOC_REM statusTmp;
  uint8_t     PH_MEMLOC_REM bStatusByte;
  uint16_t    PH_MEMLOC_REM wIndex;
  uint16_t    PH_MEMLOC_REM wTmp;
  uint16_t    PH_MEMLOC_REM wLen;
  uint16_t    PH_MEMLOC_REM wFrameLen = 0;
  uint8_t     PH_MEMLOC_REM pApdu[5] = { PHAL_MFDF_WRAPPEDAPDU_CLA, 0x00, PHAL_MFDF_WRAPPEDAPDU_P1, PHAL_MFDF_WRAPPEDAPDU_P2, 0x00 };
  uint8_t     PH_MEMLOC_REM *pRecv = NULL;

  if (0U != (pDataParams->bWrappedMode)) {
    wFrameLen = PHAL_MFDF_MAXWRAPPEDAPDU_SIZE;
  } else {
    wFrameLen = PHAL_MFDF_MAXDFAPDU_SIZE;
  }

  /* Send the data to PICC */
  wIndex = 0;
  wTmp = wDataLen;

  do {
    wLen = (wTmp < (wFrameLen - wCmdLen)) ? wTmp : (wFrameLen - wCmdLen);

    if (0U != (pDataParams->bWrappedMode)) {
      pApdu[1] = pCmd[0]; /* MIFARE DESFire cmd code in INS */
      pApdu[4] = (uint8_t)(wCmdLen + wLen) - 0x01u;

      PH_CHECK_SUCCESS_FCT(statusTmp, phpalMifare_ExchangeL4(
              pDataParams->pPalMifareDataParams,
              PH_EXCHANGE_BUFFER_FIRST,
              pApdu,
              PHAL_MFDF_WRAP_HDR_LEN,
              &pRecv,
              pRespLen));

      PH_CHECK_SUCCESS_FCT(statusTmp,  phpalMifare_ExchangeL4(
              pDataParams->pPalMifareDataParams,
              PH_EXCHANGE_BUFFER_CONT,
              &pCmd[1],
              wCmdLen - 1u,
              &pRecv,
              pRespLen));

      PH_CHECK_SUCCESS_FCT(statusTmp, phpalMifare_ExchangeL4(
              pDataParams->pPalMifareDataParams,
              PH_EXCHANGE_BUFFER_CONT,
              &pData[wIndex],
              wLen,
              &pRecv,
              pRespLen));

      /* Le byte */
      PH_CHECK_SUCCESS_FCT(statusTmp, phpalMifare_ExchangeL4(
              pDataParams->pPalMifareDataParams,
              PH_EXCHANGE_BUFFER_LAST,
              &pApdu[2],
              0x01,
              &pRecv,
              pRespLen));
    } else {
      PH_CHECK_SUCCESS_FCT(statusTmp, phpalMifare_ExchangeL4(
              pDataParams->pPalMifareDataParams,
              PH_EXCHANGE_BUFFER_FIRST,
              pCmd,
              wCmdLen,
              &pRecv,
              pRespLen));

      PH_CHECK_SUCCESS_FCT(statusTmp, phpalMifare_ExchangeL4(
              pDataParams->pPalMifareDataParams,
              PH_EXCHANGE_BUFFER_LAST,
              &pData[wIndex],
              wLen,
              &pRecv,
              pRespLen));
    }
    wIndex = wIndex + wLen;
    wTmp = wTmp - wLen;

    if (0U != (pDataParams->bWrappedMode)) {
      (void)memcpy(pResp, pRecv, ((uint32_t)(*pRespLen) - 2U));
      bStatusByte = pRecv[(*pRespLen) - 1U];
      (*pRespLen) -= 2u;
    } else {
      (void)memcpy(pResp, &pRecv[1], ((uint32_t)(*pRespLen) - 1U));
      bStatusByte = pRecv[0];
      (*pRespLen) -= 1u;
    }

    if ((bStatusByte != PHAL_MFDF_RESP_ADDITIONAL_FRAME) &&
        (bStatusByte != PH_ERR_SUCCESS)) {

#ifdef NXPBUILD__PH_NDA_MFDF

      /* Reset authentication status */
      if ((pDataParams->bAuthMode == PHAL_MFDF_AUTHENTICATEISO) ||
          (pDataParams->bAuthMode == PHAL_MFDF_AUTHENTICATEAES)) {
        phalMfdf_Sw_Int_ResetAuthStatus(pDataParams);
      }

#endif /* NXPBUILD__PH_NDA_MFDF */

      return phalMfdf_Int_ComputeErrorResponse(pDataParams, bStatusByte);
    }

    /* Success returned even before writing all data? protocol error */
    if ((bStatusByte == PH_ERR_SUCCESS) && (wTmp != 0U)) {

#ifdef NXPBUILD__PH_NDA_MFDF

      /* Reset authentication status */
      if ((pDataParams->bAuthMode == PHAL_MFDF_AUTHENTICATEISO) ||
          (pDataParams->bAuthMode == PHAL_MFDF_AUTHENTICATEAES)) {
        phalMfdf_Sw_Int_ResetAuthStatus(pDataParams);
      }

#endif /* NXPBUILD__PH_NDA_MFDF */

      return PH_ADD_COMPCODE_FIXED(PH_ERR_PROTOCOL_ERROR, PH_COMP_AL_MFDF);
    }

    if (bStatusByte != 0x00U) {
      pCmd[0] = PHAL_MFDF_RESP_ADDITIONAL_FRAME;
      wCmdLen = 1;
    }
  } while (0U != wTmp);

  return phalMfdf_Int_ComputeErrorResponse(pDataParams, bStatusByte);
}

phStatus_t
phalMfdf_Sw_Int_IsoRead(
    phalMfdf_Sw_DataParams_t *pDataParams,
    uint16_t wOption,
    uint8_t *bCmdBuff,
    uint16_t wCmdLen,
    uint8_t **ppRxBuffer,
    uint16_t *pBytesRead
)
{
  phStatus_t  PH_MEMLOC_REM status;
  uint16_t    PH_MEMLOC_REM statusTmp;
  uint16_t    PH_MEMLOC_REM wRxBufferSize = 0;
  uint16_t    PH_MEMLOC_REM wNextPos;
  uint8_t     PH_MEMLOC_REM *pRecv = NULL;
  uint8_t     PH_MEMLOC_REM bBackupBytes[3];

#ifdef NXPBUILD__PH_NDA_MFDF

  uint8_t     PH_MEMLOC_REM bCMacCard[8];
  uint8_t     PH_MEMLOC_REM bCMAC[16];
  uint8_t     PH_MEMLOC_REM bMacLen;
  uint8_t     PH_MEMLOC_REM bIvLen;
  uint16_t    PH_MEMLOC_REM wIntOption = PH_CRYPTOSYM_MAC_MODE_CMAC;

  if (pDataParams->bAuthMode == PHAL_MFDF_AUTHENTICATEAES) {
    bIvLen = PH_CRYPTOSYM_AES_BLOCK_SIZE;
  } else {
    bIvLen = PH_CRYPTOSYM_DES_BLOCK_SIZE;
  }

#endif /* NXPBUILD__PH_NDA_MFDF */

  status = phpalMifare_ExchangeL4(
          pDataParams->pPalMifareDataParams,
          wOption,
          bCmdBuff,
          wCmdLen,
          ppRxBuffer,
          pBytesRead
      );

  /* First put everything on the reader Rx buffer upto buffer size - 60 */

  pRecv = *ppRxBuffer;

  if ((status != PH_ERR_SUCCESS) && ((status & PH_ERR_MASK) != PH_ERR_SUCCESS_CHAINING)) {

#ifdef NXPBUILD__PH_NDA_MFDF

    /* Authentication should be reset */
    phalMfdf_Sw_Int_ResetAuthStatus(pDataParams);

#endif /* NXPBUILD__PH_NDA_MFDF */

    return status;
  }

#ifdef NXPBUILD__PH_NDA_MFDF

  if ((wOption == PH_EXCHANGE_DEFAULT) &&
      (pDataParams->bAuthMode != PHAL_MFDF_NOT_AUTHENTICATED)) {
    PH_CHECK_SUCCESS_FCT(statusTmp, phCryptoSym_LoadIv(
            pDataParams->pCryptoDataParamsEnc,
            pDataParams->bIv,
            bIvLen
        ));
  }

#endif /* NXPBUILD__PH_NDA_MFDF */

  while ((status & PH_ERR_MASK) == PH_ERR_SUCCESS_CHAINING) {
    PH_CHECK_SUCCESS_FCT(statusTmp, phhalHw_GetConfig(
            pDataParams->pHalDataParams,
            PHHAL_HW_CONFIG_RXBUFFER_BUFSIZE,
            &wRxBufferSize
        ));

    wNextPos = *pBytesRead;
    (void)memcpy(bBackupBytes, &pRecv[wNextPos - 3u], 3);

    if ((wNextPos + PHAL_MFDF_MAX_FRAME_SIZE) >= wRxBufferSize) {
      /* Calculate partical cmac if authenticated and return PH_ERR_SUCCESS_CHAINING */
      break;
    }

    PH_CHECK_SUCCESS_FCT(statusTmp, phhalHw_SetConfig(
            pDataParams->pHalDataParams,
            PHHAL_HW_CONFIG_RXBUFFER_STARTPOS,
            wNextPos
        ));
    status = phpalMifare_ExchangeL4(
            pDataParams->pPalMifareDataParams,
            PH_EXCHANGE_RXCHAINING,
            bCmdBuff,
            wCmdLen,
            ppRxBuffer,
            pBytesRead
        );

    /* Put back the backed up bytes */
    (void)memcpy(&pRecv[wNextPos - 3u], bBackupBytes, 3);

    if ((status != PH_ERR_SUCCESS) &&
        ((status & PH_ERR_MASK) != PH_ERR_SUCCESS_CHAINING)) {

#ifdef NXPBUILD__PH_NDA_MFDF

      /* Authentication should be reset */
      phalMfdf_Sw_Int_ResetAuthStatus(pDataParams);

#endif /* NXPBUILD__PH_NDA_MFDF */

      return status;
    }
  }

  /* The data is now in *ppRxBuffer, length = wRxlen */

  /* Size of MAC bytes */

  if (status == PH_ERR_SUCCESS) {
    statusTmp = (*ppRxBuffer)[*pBytesRead - 2U]; /* SW1 */
    statusTmp = statusTmp << 8U; /* Shift SW1 to MSB */
    statusTmp |= (*ppRxBuffer)[*pBytesRead - 1U]; /* SW2 */

    if (pDataParams->bAuthMode == PHAL_MFDF_NOT_AUTHENTICATED) {
      *pBytesRead -= 2U;
      return phalMfdf_Int_ComputeErrorResponse(pDataParams, statusTmp);
    }

    statusTmp = phalMfdf_Int_ComputeErrorResponse(pDataParams, statusTmp);
    if (statusTmp != PH_ERR_SUCCESS) {

#ifdef NXPBUILD__PH_NDA_MFDF

      /* Authentication should be reset */
      phalMfdf_Sw_Int_ResetAuthStatus(pDataParams);

#endif /* NXPBUILD__PH_NDA_MFDF */

      return statusTmp;
    }

#ifdef NXPBUILD__PH_NDA_MFDF

    wIntOption = PH_EXCHANGE_BUFFER_LAST | PH_CRYPTOSYM_MAC_MODE_CMAC;

    /* Verify MAC. Don't consider SW1SW2 as MAC bytes */
    (void)memcpy(bCMacCard, &(*ppRxBuffer)[*pBytesRead - 10], 8);

    /* Subtract the MAC bytes */
    *pBytesRead -= 10;

    (*ppRxBuffer)[(*pBytesRead)] = 0x00;

    /* Calculate CMAC */
    PH_CHECK_SUCCESS_FCT(statusTmp, phCryptoSym_CalculateMac(
            pDataParams->pCryptoDataParamsEnc,
            wIntOption,
            *ppRxBuffer,
            *pBytesRead + 1U,
            bCMAC,
            &bMacLen
        ));

    if (memcmp(bCMAC, bCMacCard, 8) != 0x00) {
      return PH_ADD_COMPCODE_FIXED(PH_ERR_INTEGRITY_ERROR, PH_COMP_AL_MFDF);
    }

    /* Update IV */
    (void)memcpy(pDataParams->bIv, bCMAC, bMacLen);
  } else {
    if (pDataParams->bAuthMode != PHAL_MFDF_NOT_AUTHENTICATED) {
      wIntOption = PH_EXCHANGE_BUFFER_CONT | PH_CRYPTOSYM_MAC_MODE_CMAC;

      /* Calculate partial CMAC */
      PH_CHECK_SUCCESS_FCT(statusTmp, phCryptoSym_CalculateMac(
              pDataParams->pCryptoDataParamsEnc,
              wIntOption,
              *ppRxBuffer,
              *pBytesRead,
              bCMAC,
              &bMacLen
          ));
    }

#endif /* NXPBUILD__PH_NDA_MFDF */
  }
  return PH_ADD_COMPCODE((status & PH_ERR_MASK), PH_COMP_AL_MFDF);
}
#endif /* NXPBUILD__PHAL_MFDF_SW */
