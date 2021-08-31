/*
*         Copyright(c), NXP Semiconductors Bangalore / India
*
*                    (C)NXP Semiconductors
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
#include <nxp_nfc/phbalReg.h>
#include <nxp_nfc/phhalHw.h>
#include <nxp_nfc/phKeyStore.h>
#include <nxp_nfc/phCryptoRng.h>
#include <nxp_nfc/phCryptoSym.h>
#include <nxp_nfc/phpalMifare.h>
#include <nxp_nfc/ph_RefDefs.h>
#include <nxp_nfc/phTools.h>
#include <console/console.h>

#ifdef NXPBUILD__PHHAL_HW_SAMAV3

#include <nxp_nfc/phhalHw_SamAv3_Cmd.h>
#include "phhalHw_SamAv3.h"
#include "phhalHw_SamAv3_utils.h"
#include "phhalHw_SamAv3_HSM_AES.h"

/* Static variables */
static uint8_t gaDefaultLe[1] = {PHHAL_HW_SAMAV3_ISO7816_DEFAULT_LE_BYTE};
static const uint8_t PH_MEMLOC_CONST_ROM gaFirstIv[PH_CRYPTOSYM_AES_BLOCK_SIZE] = {0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00};

phStatus_t
phhalHw_SamAV3_Cmd_7816Exchange(phhalHw_SamAV3_DataParams_t *pDataParams, uint16_t wOption,
    uint8_t *pTxBuffer, uint16_t wTxLength, uint8_t **ppRxBuffer,
    uint16_t *pRxLength)
{
  phStatus_t  PH_MEMLOC_REM status;
  phStatus_t  PH_MEMLOC_REM statusTmp;
  uint8_t     PH_MEMLOC_REM bSamCommand;
  uint8_t     PH_MEMLOC_REM bP1;
  uint8_t     PH_MEMLOC_REM bP2;
  uint8_t     PH_MEMLOC_REM bFirstResp = PH_OFF;
  uint8_t     PH_MEMLOC_REM bFirstCmd = PH_OFF;
  uint8_t     PH_MEMLOC_REM bLast = PH_OFF;
  uint8_t    *PH_MEMLOC_REM pTmpBuffer;
  uint16_t    PH_MEMLOC_REM wTmpBufferSize;
  uint8_t    *PH_MEMLOC_REM pRxBufferTmp;
  uint16_t    PH_MEMLOC_REM wRxLengthTmp;
  uint16_t    PH_MEMLOC_REM wTxStartPosTmp;
  uint16_t    PH_MEMLOC_REM wTxLengthTmp;

  PH_LOG_HELPER_ALLOCATE_PARAMNAME(SentFrmHost);
  PH_LOG_HELPER_ALLOCATE_PARAMNAME(GivenToHost);

  /* reset received length */
  if (pRxLength != NULL) {
    *pRxLength = 0;
  }

  /* Check if caller has provided valid RxBuffer */
  if (ppRxBuffer == NULL) {
    ppRxBuffer = &pRxBufferTmp;
  }
  if (pRxLength == NULL) {
    pRxLength = &wRxLengthTmp;
  }

  /* Get / Check command */
  if (!(wOption & PH_EXCHANGE_LEAVE_BUFFER_BIT)) {
    /* Check minimum length for first call */
    if (wTxLength < PHHAL_HW_SAMAV3_ISO7816_HEADER_NO_LC_LENGTH) {
      return PH_ADD_COMPCODE(PH_ERR_INVALID_PARAMETER, PH_COMP_HAL);
    }

    bSamCommand = pTxBuffer[PHHAL_HW_SAMAV3_ISO7816_INS_POS];
  } else {
    /* Preserved commands(all except exchange) */
    if (pDataParams->wTxBufLen_Cmd != 0) {
      /* Ensure SAM command is unequal exchange */
      bSamCommand = PHHAL_HW_SAMAV3_CMD_ISO14443_3_TRANSPARENT_EXCHANGE_INS ^ 0x01;
    } else {
      /* Exchange command */
      if (pDataParams->wTxBufLen != 0) {
        bSamCommand = PHHAL_HW_SAMAV3_CMD_ISO14443_3_TRANSPARENT_EXCHANGE_INS;
      }
      /* Everything else is definitely an internal error */
      /*(minimum length for first call is > 0) */
      else {
        return PH_ADD_COMPCODE(PH_ERR_INTERNAL_ERROR, PH_COMP_HAL);
      }
    }
  }

  /* Exchange command can use default buffers */
  if (bSamCommand == PHHAL_HW_SAMAV3_CMD_ISO14443_3_TRANSPARENT_EXCHANGE_INS) {
    /* Reset TxLength */
    if (!(wOption & PH_EXCHANGE_LEAVE_BUFFER_BIT)) {
      pDataParams->wTxBufLen = 0;
      pDataParams->wTxBufLen_Cmd = 0;
    }

    wTxStartPosTmp = pDataParams->wTxBufStartPos;
    pTmpBuffer = &pDataParams->pTxBuffer[wTxStartPosTmp + pDataParams->wTxBufLen];
    wTmpBufferSize = pDataParams->wTxBufSize - (wTxStartPosTmp + pDataParams->wTxBufLen);
  }
  /* Other commands -> Preserve all buffer data */
  else {
    /* Reset TxLength */
    if (!(wOption & PH_EXCHANGE_LEAVE_BUFFER_BIT)) {
      pDataParams->wTxBufLen_Cmd = 0;
    }

    /* TxBuffer equals RxBuffer */
    if (pDataParams->pTxBuffer == pDataParams->pRxBuffer) {
      /* Start at TxLength if neccessary */
      if ((pDataParams->wTxBufStartPos + pDataParams->wTxBufLen) >=
          (pDataParams->wRxBufLen)) {
        wTxStartPosTmp = pDataParams->wTxBufStartPos + pDataParams->wTxBufLen;
        pTmpBuffer = &pDataParams->pTxBuffer[wTxStartPosTmp + pDataParams->wTxBufLen_Cmd];
        wTmpBufferSize = pDataParams->wTxBufSize - (wTxStartPosTmp + pDataParams->wTxBufLen_Cmd);
      }
      /* Start at RxLength if neccessary */
      else {
        wTxStartPosTmp = pDataParams->wRxBufLen;
        pTmpBuffer = &pDataParams->pTxBuffer[wTxStartPosTmp + pDataParams->wTxBufLen_Cmd];
        wTmpBufferSize = pDataParams->wTxBufSize - (wTxStartPosTmp + pDataParams->wTxBufLen_Cmd);
      }
    }
    /* Buffers are different */
    else {
      wTxStartPosTmp = pDataParams->wTxBufLen;
      pTmpBuffer = &pDataParams->pTxBuffer[wTxStartPosTmp + pDataParams->wTxBufLen_Cmd];
      wTmpBufferSize = pDataParams->wTxBufSize - (wTxStartPosTmp + pDataParams->wTxBufLen_Cmd);
    }
  }

  /* Check for buffer overflow */
  if (wTxLength > wTmpBufferSize) {
    return PH_ADD_COMPCODE(PH_ERR_BUFFER_OVERFLOW, PH_COMP_HAL);
  }

  /* Copy TxBuffer contents */
  memcpy(pTmpBuffer, pTxBuffer, wTxLength);  /* PRQA S 3200 */

  /* Exchange uses wTxBufLen */
  if (bSamCommand == PHHAL_HW_SAMAV3_CMD_ISO14443_3_TRANSPARENT_EXCHANGE_INS) {
    pDataParams->wTxBufLen = pDataParams->wTxBufLen + wTxLength;
    wTxLengthTmp = pDataParams->wTxBufLen;
  }
  /* Other commands use wTxBufLen_Cmd */
  else {
    pDataParams->wTxBufLen_Cmd = pDataParams->wTxBufLen_Cmd + wTxLength;
    wTxLengthTmp = pDataParams->wTxBufLen_Cmd;
  }

  /* Shall we already perform the Exchange? */
  if (wOption & PH_EXCHANGE_BUFFERED_BIT) {
    return PH_ADD_COMPCODE(PH_ERR_SUCCESS, PH_COMP_HAL);
  }

  /* Set the corresponding logical channel in the CLA Byte */
  pDataParams->pTxBuffer[wTxStartPosTmp + PHHAL_HW_SAMAV3_ISO7816_CLA_POS] |=
      pDataParams->bLogicalChannel;

  /* Retrieve some command information */
  bSamCommand = pDataParams->pTxBuffer[wTxStartPosTmp + PHHAL_HW_SAMAV3_ISO7816_INS_POS];
  bP1 = pDataParams->pTxBuffer[wTxStartPosTmp + PHHAL_HW_SAMAV3_ISO7816_P1_POS];
  bP2 = pDataParams->pTxBuffer[wTxStartPosTmp + PHHAL_HW_SAMAV3_ISO7816_P2_POS];

  /* RIGHT PLACE  */
  PH_LOG_HELPER_ADDPARAM_BUFFER(PH_LOG_LOGTYPE_DEBUG, SentFrmHost_log, pDataParams->pTxBuffer,
      wTxLengthTmp);
  PH_LOG_HELPER_EXECUTE(PH_LOG_OPTION_CATEGORY_GEN);

  /* Get the Host Protection to be applied for the commands. */
  PH_CHECK_SUCCESS_FCT(statusTmp, phhalHw_SamAV3_HSM_AES_GetFirstLastCommand(
          pDataParams,
          bSamCommand,
          bP1,
          bP2,
          &bFirstCmd,
          &bLast));

  /* Perform encryption of the payload data. */
  if (pDataParams->bCmdSM & PHHAL_HW_SAMAV3_HSM_AES_ENC) {
    PH_CHECK_SUCCESS_FCT(statusTmp, phhalHw_SamAV3_HSM_AES_Encrypt(
            pDataParams,
            &pDataParams->pTxBuffer[wTxStartPosTmp],
            wTxLengthTmp,
            wTmpBufferSize + wTxLengthTmp,
            &wTxLengthTmp,
            bFirstCmd,
            bLast));
  }

  /* Perform macing of the payload data. */
  if (pDataParams->bCmdSM & PHHAL_HW_SAMAV3_HSM_AES_MAC) {
    PH_CHECK_SUCCESS_FCT(statusTmp, phhalHw_SamAV3_HSM_AES_AppendMac(
            pDataParams,
            &pDataParams->pTxBuffer[wTxStartPosTmp],
            wTxLengthTmp,
            wTmpBufferSize + wTxLengthTmp,
            &wTxLengthTmp,
            bFirstCmd,
            bLast));
  }

  /* Increment CmdCtr */
  if (bFirstCmd) {
    switch (bSamCommand) {
      case PHHAL_HW_SAMAV3_CMD_AUTHENTICATE_HOST_INS:
      case PHHAL_HW_SAMAV3_CMD_LOCK_UNLOCK_INS:
        break;
      default:
        /* Increment the command counter in case we have a first response */
        ++(pDataParams->Cmd_Ctr);
        break;
    }
  }

  /* Exchange and Decipher command can use default buffers */
  if ((bSamCommand == PHHAL_HW_SAMAV3_CMD_ISO14443_3_TRANSPARENT_EXCHANGE_INS) ||
      (bSamCommand == PHHAL_HW_SAMAV3_CMD_SAM_DECIPHER_DATA_INS)) {
    *ppRxBuffer = &pDataParams->pRxBuffer[pDataParams->wRxBufStartPos];
    wTmpBufferSize = pDataParams->wRxBufSize - pDataParams->wRxBufStartPos;
  }
  /* Other commands -> Preserve all buffer data */
  else {
    /* TxBuffer equals RxBuffer */
    if (pDataParams->pTxBuffer == pDataParams->pRxBuffer) {
      /* Start after TxBuffer contents */
      if (pDataParams->wTxBufLen > pDataParams->wRxBufLen) {
        *ppRxBuffer = &pDataParams->pTxBuffer[pDataParams->wTxBufStartPos + pDataParams->wTxBufLen];
        wTmpBufferSize = pDataParams->wTxBufSize - (pDataParams->wTxBufStartPos + pDataParams->wTxBufLen);
      }
      /* Start after RxBuffer contents */
      else {
        *ppRxBuffer = &pDataParams->pRxBuffer[pDataParams->wRxBufLen];
        wTmpBufferSize = pDataParams->wRxBufSize - pDataParams->wRxBufLen;
      }
    }
    /* Buffers are different */
    else {
      /* Use TxBuffer if it has more space */
      if ((pDataParams->wTxBufSize - pDataParams->wTxBufLen) > (pDataParams->wRxBufSize -
              pDataParams->wRxBufLen)) {
        *ppRxBuffer = &pDataParams->pTxBuffer[pDataParams->wTxBufStartPos + pDataParams->wTxBufLen];
        wTmpBufferSize = pDataParams->wTxBufSize - (pDataParams->wTxBufStartPos + pDataParams->wTxBufLen);
      }
      /* Else use RxBuffer */
      else {
        *ppRxBuffer = &pDataParams->pRxBuffer[pDataParams->wRxBufLen];
        wTmpBufferSize = pDataParams->wRxBufSize - pDataParams->wRxBufLen;
      }
    }
  }

  PN5180_LOG_INFO("\n%s: Call to phbalReg_Exchange with this data: \n 0x ", __func__);
  for (uint8_t i = wTxStartPosTmp; i < (wTxStartPosTmp + wTxLengthTmp); i++) {
    PN5180_LOG_INFO("%02X ", pTxBuffer[i]);
  }
  PN5180_LOG_INFO("\n");

  /* Perform command exchange */
  status = phbalReg_Exchange(
          pDataParams->pBalDataParams,
          PH_EXCHANGE_DEFAULT,
          &pDataParams->pTxBuffer[wTxStartPosTmp],
          wTxLengthTmp,
          wTmpBufferSize,
          *ppRxBuffer,
          pRxLength);

  /* Reset TxBufferLength */
  if (bSamCommand == PHHAL_HW_SAMAV3_CMD_ISO14443_3_TRANSPARENT_EXCHANGE_INS) {
    pDataParams->wTxBufLen = 0;
  } else {
    pDataParams->wTxBufLen_Cmd = 0;
  }

  /* Success check */
  PH_CHECK_SUCCESS(status);

  /* We need at least 2 bytes in the answer */
  if (*pRxLength < PHHAL_HW_SAMAV3_ISO7816_SW1SW2_LENGTH) {
    pDataParams->bCmdSM = PHHAL_HW_SAMAV3_HSM_AES_NO_SM;
    pDataParams->bRespSM = PHHAL_HW_SAMAV3_HSM_AES_NO_SM;
    pDataParams->bCommandChaining = PHHAL_HW_SAMAV3_HSM_AES_NO_CHAINING;
    pDataParams->bResponseChaining = PHHAL_HW_SAMAV3_HSM_AES_NO_CHAINING;

    /* Remapping of return values */
    return PH_ADD_COMPCODE(PH_ERR_LENGTH_ERROR, PH_COMP_HAL);
  }

  /* catch host protocol error */
  if ((*pRxLength == 2) && ((*ppRxBuffer)[0] == 0x6A) && ((*ppRxBuffer)[1] == 0x84)) {
    PH_CHECK_SUCCESS_FCT(statusTmp, phCryptoSym_InvalidateKey(pDataParams->pENCCryptoDataParams));
    PH_CHECK_SUCCESS_FCT(statusTmp, phCryptoSym_InvalidateKey(pDataParams->pMACCryptoDataParams));
    pDataParams->bCmdSM = PHHAL_HW_SAMAV3_HSM_AES_NO_SM;
    pDataParams->bRespSM = PHHAL_HW_SAMAV3_HSM_AES_NO_SM;
  }

  PH_CHECK_SUCCESS_FCT(statusTmp, phhalHw_SamAV3_HSM_AES_GetFirstLastResponse(
          pDataParams,
          (*ppRxBuffer)[*pRxLength - PHHAL_HW_SAMAV3_ISO7816_SW1SW2_LENGTH],
          (*ppRxBuffer)[*pRxLength - (PHHAL_HW_SAMAV3_ISO7816_SW1SW2_LENGTH - 1)],
          &bFirstResp,
          &bLast));

  /*
  * Special operation for some of the Part 1 commands.
  * In case of error, the error code will be echoed back with MAC applied.
  */
  if (bFirstCmd) {
    if (*pRxLength == 11 /* PICC Code + MAC + Status Code */) {
      switch (bSamCommand) {
        case PHHAL_HW_SAMAV3_CMD_AUTHENTICATE_MFP_INS:
          pDataParams->bRespSM = PHHAL_HW_SAMAV3_HSM_AES_MAC;
          break;

        default:
          /* Do nothing. */
          break;
      }
    }
  }

  if (pDataParams->bRespSM & PHHAL_HW_SAMAV3_HSM_AES_MAC) {
    PH_CHECK_SUCCESS_FCT(statusTmp, phhalHw_SamAV3_HSM_AES_VerifyRemoveMac(
            pDataParams,
            *ppRxBuffer,
            *pRxLength,
            pRxLength,
            bFirstResp,
            bLast));
  }

  if (pDataParams->bRespSM & PHHAL_HW_SAMAV3_HSM_AES_ENC) {
    PH_CHECK_SUCCESS_FCT(statusTmp, phhalHw_SamAV3_HSM_AES_Decrypt(
            pDataParams,
            *ppRxBuffer,
            *pRxLength,
            pRxLength,
            bFirstResp,
            bLast));
  }

  PH_LOG_HELPER_ADDPARAM_BUFFER(PH_LOG_LOGTYPE_DEBUG, GivenToHost_log, *ppRxBuffer, *pRxLength);
  PH_LOG_HELPER_EXECUTE(PH_LOG_OPTION_CATEGORY_GEN);

  /* Check the return code */
  *pRxLength = *pRxLength - PHHAL_HW_SAMAV3_ISO7816_SW1SW2_LENGTH;
  status = phhalHw_SamAV3_Utils_ResolveErrorCode(&((*ppRxBuffer)[*pRxLength]));

  /* Increment the length by 2 if its a PL error code. */
  if ((status & PH_ERR_MASK) == PHHAL_HW_SAMAV3_ERR_PROGRAMMABLE_LOGIC) {
    *pRxLength = 2;
  }

  /* Always return complete buffer on exchange */
  if (bSamCommand == PHHAL_HW_SAMAV3_CMD_ISO14443_3_TRANSPARENT_EXCHANGE_INS) {
    *ppRxBuffer = pDataParams->pRxBuffer;
    *pRxLength = *pRxLength + pDataParams->wRxBufStartPos;
    pDataParams->wRxBufLen = *pRxLength;
  }

  /* Special handling for certain status codes */
  switch ((status & PH_ERR_MASK)) {
    case PH_ERR_SUCCESS_INCOMPLETE_BYTE:
      /* Retrieve number of bits from second byte of status code */
      pDataParams->wAdditionalInfo = ((*ppRxBuffer)[*pRxLength + 1]);
      break;
    case PHHAL_HW_SAMAV3_ERR_DESFIRE_GEN:
      /* Retrieve return code from card from first data byte */
      if (*pRxLength == 1) {
        pDataParams->wAdditionalInfo = (*ppRxBuffer)[0];
      } else {
        if (*pRxLength == 2) {
          pDataParams->wAdditionalInfo = ((uint16_t)((*ppRxBuffer)[0]) << 8) | (uint16_t)(*ppRxBuffer)[1];
        }
      }
      break;
    default:
      break;
  }

  return status;
}

/**********************************************************************************************************************************************************************************************/
/* Security and Configuration																								 																  */
/**********************************************************************************************************************************************************************************************/

phStatus_t
phhalHw_SamAV3_Cmd_SAM_LockUnlock(phhalHw_SamAV3_DataParams_t *pDataParams, uint8_t bCmdType,
    uint16_t wRdKeyNo, uint16_t wRdKeyVer, uint8_t bSamKeyNo,
    uint8_t bSamKeyVer, uint8_t bUnlockKeyNo, uint8_t bUnlockKeyVer, uint32_t dwMaxChainBlocks)
{
  phStatus_t	PH_MEMLOC_REM wStatus = 0;
  uint8_t		PH_MEMLOC_REM aCmdBuf[13];
  uint8_t		PH_MEMLOC_REM aRnd1[16];
  uint8_t		PH_MEMLOC_REM aRnd2[16];
  uint8_t		PH_MEMLOC_REM aKey[32];
  uint8_t		PH_MEMLOC_REM aMac[16];
  uint16_t	PH_MEMLOC_REM wKeyType = 0;
  uint8_t		PH_MEMLOC_REM aKxeKey[32];
  uint8_t		PH_MEMLOC_REM aRndAB[32];
  uint8_t		PH_MEMLOC_REM bKeyLen = 0;
  uint8_t		PH_MEMLOC_REM bMacLen = 0;
  uint8_t 	*PH_MEMLOC_REM pResponse = NULL;
  uint16_t	PH_MEMLOC_REM wRespLen = 0;
  uint8_t		PH_MEMLOC_REM bLcLen = 2;

  /* Verify the parameters. */
  PH_ASSERT_NULL_DATA_PARAM(pDataParams, PH_COMP_HAL);

  /* Reset the command buffer. */
  memset(aCmdBuf, 0, sizeof(aCmdBuf));  /* PRQA S 3200 */

  /* Get Key from software keystore. */
  PH_CHECK_SUCCESS_FCT(wStatus, phKeyStore_GetKey(
          pDataParams->pKeyStoreDataParams,
          wRdKeyNo,
          wRdKeyVer,
          sizeof(aKey),
          aKey,
          &wKeyType));

  /* Check for valid key type. */
  if ((wKeyType != PH_KEYSTORE_KEY_TYPE_AES128) && (wKeyType != PH_KEYSTORE_KEY_TYPE_AES192) &&
      (wKeyType != PH_KEYSTORE_KEY_TYPE_AES256)) {
    return PH_ADD_COMPCODE(PH_ERR_KEY, PH_COMP_HAL);
  }

  /* Frame first part of Cmd.SAM_LockUnlock information. */
  aCmdBuf[PHHAL_HW_SAMAV3_ISO7816_CLA_POS]	 = PHHAL_HW_SAMAV3_ISO7816_CLA_BYTE;
  aCmdBuf[PHHAL_HW_SAMAV3_ISO7816_INS_POS]	 = PHHAL_HW_SAMAV3_CMD_LOCK_UNLOCK_INS;
  aCmdBuf[PHHAL_HW_SAMAV3_ISO7816_P1_POS]	 = bCmdType;
  aCmdBuf[PHHAL_HW_SAMAV3_ISO7816_P2_POS]	 = PHHAL_HW_SAMAV3_ISO7816_DEFAULT_P2_BYTE;
  aCmdBuf[PHHAL_HW_SAMAV3_ISO7816_LC_POS + 1] = bSamKeyNo;
  aCmdBuf[PHHAL_HW_SAMAV3_ISO7816_LC_POS + 2] = bSamKeyVer;

  /* Add the key number and version information according to bCmdType value. */
  switch (bCmdType) {
    case PHHAL_HW_SAMAV3_CMD_SAM_LOCK_UNLOCK_TYPE_UNLOCK:
    case PHHAL_HW_SAMAV3_CMD_SAM_LOCK_UNLOCK_TYPE_UNLOCK_PL:
    case PHHAL_HW_SAMAV3_CMD_SAM_LOCK_UNLOCK_TYPE_LOCK_NO_KEY:
      /* bLc is already ok*/
      break;

    case PHHAL_HW_SAMAV3_CMD_SAM_LOCK_UNLOCK_TYPE_LOCK_KEY:
      bLcLen = bLcLen + 2;
      aCmdBuf[PHHAL_HW_SAMAV3_ISO7816_LC_POS + 3] = bUnlockKeyNo;
      aCmdBuf[PHHAL_HW_SAMAV3_ISO7816_LC_POS + 4] = bUnlockKeyVer;
      break;

    case PHHAL_HW_SAMAV3_CMD_SAM_LOCK_UNLOCK_TYPE_ACTIVATE_SAM:
      bLcLen = bLcLen + 3;
      aCmdBuf[PHHAL_HW_SAMAV3_ISO7816_LC_POS + 3] = (uint8_t)(dwMaxChainBlocks);
      aCmdBuf[PHHAL_HW_SAMAV3_ISO7816_LC_POS + 4] = (uint8_t)(dwMaxChainBlocks >> 8);
      aCmdBuf[PHHAL_HW_SAMAV3_ISO7816_LC_POS + 5] = (uint8_t)(dwMaxChainBlocks >> 16);
      break;

    default:
      return PH_ADD_COMPCODE(PH_ERR_INVALID_PARAMETER, PH_COMP_HAL);
  }

  /* Update Lc. */
  aCmdBuf[PHHAL_HW_SAMAV3_ISO7816_LC_POS] = bLcLen;

  /* Buffer the command information to exchange buffer and exchange the bufferred information to Sam hardware. */
  PN5180_LOG_INFO("\n %s: Send to Exchange: 0x ", __func__);
  for (int i = 0; i < (bLcLen + PHHAL_HW_SAMAV3_ISO7816_HEADER_LE_LENGTH) ; i++) {
    PN5180_LOG_INFO("%02X ", aCmdBuf[i]);
  }
  PN5180_LOG_INFO("\n ");

  wStatus = phhalHw_SamAV3_Cmd_7816Exchange(
          pDataParams,
          PH_EXCHANGE_DEFAULT,
          aCmdBuf,
          bLcLen + PHHAL_HW_SAMAV3_ISO7816_HEADER_LE_LENGTH,
          &pResponse,
          &wRespLen);
//	uint8_t r[14] = {
//		0x19, 0x28, 0x0A, 0x7A, 0xF3, 0xE3, 0xF3, 0x81,
//		0x49, 0x26, 0x6D, 0x3C, 0x90, 0xAF
//	};
//	wRespLen = 0x0C;
//	pResponse = &r[0];
//	wStatus = (PH_COMP_HAL | PHHAL_HW_SAMAV3_ERR_OK_CHAINING_ACTIVE);

  PN5180_LOG_INFO("\n %s: Response: 0x ", __func__);
  for (int i = 0; i < 14 ; i++) {
    PN5180_LOG_INFO("%02X ", pResponse[i]);
  }
  PN5180_LOG_INFO("\n ");

  /* Reset P1 information byte to default value in command buffer. */
  aCmdBuf[PHHAL_HW_SAMAV3_ISO7816_P1_POS] = 0;

  /* We expect chaining as the status from Sam hardware. */
  if (wStatus != (PH_COMP_HAL | PHHAL_HW_SAMAV3_ERR_OK_CHAINING_ACTIVE)) {
    return wStatus;
  }

  /* Check if response if of not the expected size. */
  if (wRespLen != 0x0C) {
    return PH_ADD_COMPCODE(PH_ERR_LENGTH_ERROR, PH_COMP_HAL);
  }

  /* Calculate MACHost = MAC(Kx, Rnd2 || P1 || (MaxChainBlocks or Unlock Key number and version or Zero padded)  */

  /* Prepare the payload for second part of Cmd.SAM_LockUnlock command. */
  memcpy(aRnd2, pResponse, 0x0C);  /* PRQA S 3200 */
  aRnd2[12] = bCmdType;
  memset(&aRnd2[13], 0, 3);  /* PRQA S 3200 */
  memcpy(&aRnd2[13], &aCmdBuf[PHHAL_HW_SAMAV3_ISO7816_LC_POS + 3], bLcLen - 2); /* PRQA S 3200 */

  /* Load the key to CryptoSym. */
  PH_CHECK_SUCCESS_FCT(wStatus, phCryptoSym_LoadKeyDirect(
          pDataParams->pMACCryptoDataParams,
          aKey,
          wKeyType));

  /* Comupte the Mac. */
  PH_CHECK_SUCCESS_FCT(wStatus, phCryptoSym_CalculateMac(
          pDataParams->pMACCryptoDataParams,
          PH_CRYPTOSYM_MAC_MODE_CMAC,
          aRnd2,
          PH_CRYPTOSYM_AES_BLOCK_SIZE,
          aMac,
          &bMacLen));

  /* Truncate the MAC. */
  PH_CHECK_SUCCESS_FCT(wStatus, phhalHw_SamAV3_Utils_TruncateMacBuffer(aMac, &bMacLen));

  /* Generate the Random number to be sent to Sam hardware. */
  PH_CHECK_SUCCESS_FCT(wStatus, phCryptoRng_Rnd(pDataParams->pCryptoRngDataParams, 12, aRnd1));

  /* Update Lc */
  aCmdBuf[PHHAL_HW_SAMAV3_ISO7816_LC_POS] = bMacLen /* MAC */ + 12/* RND1 */ ;

  /* Buffer the command information to exchange buffer. */
//	PN5180_LOG_INFO("\n %s: Send to phhalHw_SamAV3_Cmd_7816Exchange: 0x ", __func__);
//	for(int i=0; i< 5 ; i++)
//		PN5180_LOG_INFO("%02X ", aCmdBuf[i]);
//	PN5180_LOG_INFO("  ");
//	for(int i=0; i< bMacLen ; i++)
//		PN5180_LOG_INFO("%02X ", aMac[i]);
//	PN5180_LOG_INFO("  ");
//	for(int i=0; i< 12 ; i++)
//		PN5180_LOG_INFO("%02X ", aRnd1[i]);
//	PN5180_LOG_INFO("  ");
//	for(int i=0; i< 1; i++)
//		PN5180_LOG_INFO("%02X ", gaDefaultLe[i]);
//	PN5180_LOG_INFO("\n ");

  PH_CHECK_SUCCESS_FCT(wStatus, phhalHw_SamAV3_Cmd_7816Exchange(
          pDataParams,
          PH_EXCHANGE_BUFFER_FIRST,
          aCmdBuf,
          5,
          NULL,
          NULL));

  /* Buffer the calculated MACHost information to exchange buffer. */
  PH_CHECK_SUCCESS_FCT(wStatus, phhalHw_SamAV3_Cmd_7816Exchange(
          pDataParams,
          PH_EXCHANGE_BUFFER_CONT,
          aMac,
          bMacLen,
          NULL,
          NULL));

  /* Buffer the generate randon numeber to exchange buffer. */
  PH_CHECK_SUCCESS_FCT(wStatus, phhalHw_SamAV3_Cmd_7816Exchange(
          pDataParams,
          PH_EXCHANGE_BUFFER_CONT,
          aRnd1,
          12,
          NULL,
          NULL));

  /* Buffer Le to exchange buffer and exchange the bufferred information to Sam hardware. */
  wStatus = phhalHw_SamAV3_Cmd_7816Exchange(
          pDataParams,
          PH_EXCHANGE_BUFFER_LAST,
          gaDefaultLe,
          1,
          &pResponse,
          &wRespLen);

  /* We expect chaining as the status frm Sam hardware. */
  if (wStatus != (PH_COMP_HAL | PHHAL_HW_SAMAV3_ERR_OK_CHAINING_ACTIVE)) {
    return wStatus;
  }

  /* Check if response if of not the expected size. */
  if (wRespLen != 0x18) {
    return PH_ADD_COMPCODE(PH_ERR_LENGTH_ERROR, PH_COMP_HAL);
  }

  /* Prepare the payload for MAC calculation. */
  aRnd1[12] = bCmdType;
  memset(&aRnd1[13], 0, 3);  /* PRQA S 3200 */
  memcpy(&aRnd1[13], &aCmdBuf[PHHAL_HW_SAMAV3_ISO7816_LC_POS + 3], bLcLen - 2);  /* PRQA S 3200 */

  /* Calcualte the Mac to verify it with the received data from Sam hardware. */
  PH_CHECK_SUCCESS_FCT(wStatus, phCryptoSym_CalculateMac(
          pDataParams->pMACCryptoDataParams,
          PH_CRYPTOSYM_MAC_MODE_CMAC,
          aRnd1,
          PH_CRYPTOSYM_AES_BLOCK_SIZE,
          aMac,
          &bMacLen));

  /* Truncate the MAC. */
  PH_CHECK_SUCCESS_FCT(wStatus, phhalHw_SamAV3_Utils_TruncateMacBuffer(aMac, &bMacLen));

  /* Check if the received MAC and calculated MAC are same. */
  if (memcmp(aMac, pResponse, bMacLen)) {
    return PH_ADD_COMPCODE(PH_ERR_PROTOCOL_ERROR, PH_COMP_HAL);
  }

  /* Derive the Kxe key from kx using Rnd1 and Rnd2 - note: Secret key needs to be loaded into MAC data params*/
  PH_CHECK_SUCCESS_FCT(wStatus, phhalHw_SamAV3_Utils_GenerateHostAuthSessionKey(
          pDataParams,
          (uint8_t)wKeyType,
          aRnd1,
          aRnd2,
          aKxeKey,
          &bKeyLen));

  /* Load the generated Session key to crypto params. */
  PH_CHECK_SUCCESS_FCT(wStatus, phCryptoSym_LoadKeyDirect(
          pDataParams->pENCCryptoDataParams,
          aKxeKey,
          wKeyType));

  /* Load default initialization vector. */
  PH_CHECK_SUCCESS_FCT(wStatus, phCryptoSym_LoadIv(
          pDataParams->pENCCryptoDataParams,
          gaFirstIv,
          PH_CRYPTOSYM_AES_BLOCK_SIZE));

  PH_CHECK_SUCCESS_FCT(wStatus, phCryptoSym_Decrypt(
          pDataParams->pENCCryptoDataParams,
          (PH_CRYPTOSYM_CIPHER_MODE_CBC),
          &pResponse[8],
          PH_CRYPTOSYM_AES_BLOCK_SIZE,
          aRnd2));

  /* Now we start with part 3 exchange */
  /* Initialize the RndA array*/
  PH_CHECK_SUCCESS_FCT(wStatus, phCryptoRng_Rnd(pDataParams->pCryptoRngDataParams,
          PH_CRYPTOSYM_AES_BLOCK_SIZE, aRnd1));
  memcpy(aRndAB, aRnd1, PH_CRYPTOSYM_AES_BLOCK_SIZE);  /* PRQA S 3200 */
  /* calculate RndB'*/
  memcpy(&aRndAB[16], &aRnd2[2], 14);  /* PRQA S 3200 */
  aRndAB[30] = aRnd2[0];
  aRndAB[31] = aRnd2[1];

  /* Load default initialization vector. */
  PH_CHECK_SUCCESS_FCT(wStatus, phCryptoSym_LoadIv(
          pDataParams->pENCCryptoDataParams,
          gaFirstIv,
          PH_CRYPTOSYM_AES_BLOCK_SIZE));

  /* Key is already loaded */
  PH_CHECK_SUCCESS_FCT(wStatus, phCryptoSym_Encrypt(
          pDataParams->pENCCryptoDataParams,
          PH_CRYPTOSYM_CIPHER_MODE_CBC,
          aRndAB,
          32,
          aRndAB));

  /* prepare the buffer*/
  aCmdBuf[PHHAL_HW_SAMAV3_ISO7816_LC_POS] = 32;    /*LC*/

  /* Exchange first part of the command */
  PH_CHECK_SUCCESS_FCT(wStatus, phhalHw_SamAV3_Cmd_7816Exchange(
          pDataParams,
          PH_EXCHANGE_BUFFER_FIRST,
          aCmdBuf,
          5,
          NULL,
          NULL));

  /* Exchange RNDAB part of the command */
  PH_CHECK_SUCCESS_FCT(wStatus, phhalHw_SamAV3_Cmd_7816Exchange(
          pDataParams,
          PH_EXCHANGE_BUFFER_CONT,
          aRndAB,
          32,
          NULL,
          NULL));

  /* Exchange LE part of the command */
  PH_CHECK_SUCCESS_FCT(wStatus, phhalHw_SamAV3_Cmd_7816Exchange(
          pDataParams,
          PH_EXCHANGE_BUFFER_LAST,
          gaDefaultLe,
          1,
          &pResponse,
          &wRespLen));

  if (wRespLen != 0x10) {
    return PH_ADD_COMPCODE(PH_ERR_LENGTH_ERROR, PH_COMP_HAL);
  }

  /* Load default init vector */
  PH_CHECK_SUCCESS_FCT(wStatus, phCryptoSym_LoadIv(
          pDataParams->pENCCryptoDataParams,
          gaFirstIv,
          PH_CRYPTOSYM_AES_BLOCK_SIZE));

  /* Key is already loaded */
  PH_CHECK_SUCCESS_FCT(wStatus, phCryptoSym_Decrypt(
          pDataParams->pENCCryptoDataParams,
          PH_CRYPTOSYM_CIPHER_MODE_CBC,
          pResponse,
          16,
          aRndAB));

  /* The response for RndA is not equal to sent RndA, Authentication failed PH_ERR_AUTH_ERROR. */
  if (memcmp(aRndAB, &aRnd1[2], 14) != 0) {
    return PH_ADD_COMPCODE(PH_ERR_AUTH_ERROR, PH_COMP_HAL);
  }

  /* The response for RndA is not equal to sent RndA, Authentication failed PH_ERR_AUTH_ERROR. */
  if ((aRnd1[0] != aRndAB[14]) || (aRnd1[1] != aRndAB[15])) {
    return PH_ADD_COMPCODE(PH_ERR_AUTH_ERROR, PH_COMP_HAL);
  }

  /* SAM resets all the Authentication state when LockUnlock command is called for Lock variant.
   * Refer the document section, 6.2.2.3 SAM Unlocked State, Tab. 6.7, description of ActLock.
   */
  if ((bCmdType == PHHAL_HW_SAMAV3_CMD_SAM_LOCK_UNLOCK_TYPE_LOCK_NO_KEY) ||
      (bCmdType == PHHAL_HW_SAMAV3_CMD_SAM_LOCK_UNLOCK_TYPE_LOCK_KEY)) {
    pDataParams->bAuthType = PHHAL_HW_SAMAV3_CMD_SAM_AUTHENTICATE_HOST_MODE_PLAIN;
    PH_CHECK_SUCCESS_FCT(wStatus, phCryptoSym_InvalidateKey(pDataParams->pENCCryptoDataParams));
    PH_CHECK_SUCCESS_FCT(wStatus, phCryptoSym_InvalidateKey(pDataParams->pMACCryptoDataParams));
  }

  return PH_ADD_COMPCODE(PH_ERR_SUCCESS, PH_COMP_HAL);
}

phStatus_t
phhalHw_SamAV3_Cmd_SAM_AuthenticateHost(phhalHw_SamAV3_DataParams_t *pDataParams,
    uint8_t bHostMode, uint16_t wRdKeyNo, uint16_t wRdKeyV, uint8_t bSamKeyNo,
    uint8_t bSamKeyVer)
{
  phStatus_t	PH_MEMLOC_REM wStatus = 0;
  uint8_t		PH_MEMLOC_REM aCmdBuf[9];
  uint8_t		PH_MEMLOC_REM bCmdLen = 0;
  uint8_t 	*PH_MEMLOC_REM pResponse = NULL;
  uint16_t	PH_MEMLOC_REM wRespLen;
  uint8_t		PH_MEMLOC_REM aRnd2[16];
  uint8_t		PH_MEMLOC_REM aRnd1[16];
  uint8_t		PH_MEMLOC_REM aKey[32];
  uint8_t		PH_MEMLOC_REM aMac[16];
  uint16_t	PH_MEMLOC_REM wKeyType = 0;
  uint8_t		PH_MEMLOC_REM aKxeKey[32];
  uint8_t		PH_MEMLOC_REM aRndAB[32];
  uint8_t		PH_MEMLOC_REM aSessionEncKey[32];
  uint8_t		PH_MEMLOC_REM aSessionMacKey[32];
  uint8_t		PH_MEMLOC_REM bKeyLen = 0;
  uint8_t		PH_MEMLOC_REM bMacLen = 0;

  PH_LOG_HELPER_ALLOCATE_PARAMNAME(SessKey_Enc_SAM_HOST);
  PH_LOG_HELPER_ALLOCATE_PARAMNAME(SessKey_Mac_SAM_HOST);

  /* Verify the parameters. */
  PH_ASSERT_NULL_DATA_PARAM(pDataParams, PH_COMP_HAL);

  /* Get Key from software keystore. */
  PH_CHECK_SUCCESS_FCT(wStatus, phKeyStore_GetKey(
          pDataParams->pKeyStoreDataParams,
          wRdKeyNo,
          wRdKeyV,
          sizeof(aKey),
          aKey,
          &wKeyType));

  /* Check for valid key type. */
  if ((wKeyType != PH_KEYSTORE_KEY_TYPE_AES128) && (wKeyType != PH_KEYSTORE_KEY_TYPE_AES192) &&
      (wKeyType != PH_KEYSTORE_KEY_TYPE_AES256)) {
    return PH_ADD_COMPCODE(PH_ERR_KEY, PH_COMP_HAL);
  }

  /* Update the AuthType member. */
  pDataParams->bAuthType = 0;

  /* Reset the command buffer and its length variable. */
  bCmdLen = 0;
  memset(aCmdBuf, 0, sizeof(aCmdBuf));  /* PRQA S 3200 */

  /* Frame first part of Cmd.SAM_AuthenticateHost information. */
  aCmdBuf[bCmdLen++] = PHHAL_HW_SAMAV3_ISO7816_CLA_BYTE;
  aCmdBuf[bCmdLen++] = PHHAL_HW_SAMAV3_CMD_AUTHENTICATE_HOST_INS;
  aCmdBuf[bCmdLen++] = PHHAL_HW_SAMAV3_ISO7816_DEFAULT_P1_BYTE;
  aCmdBuf[bCmdLen++] = PHHAL_HW_SAMAV3_ISO7816_DEFAULT_P2_BYTE;
  aCmdBuf[bCmdLen++] = 3 /* Sam KeyNo, Version and HostMode */;
  aCmdBuf[bCmdLen++] = bSamKeyNo;
  aCmdBuf[bCmdLen++] = bSamKeyVer;
  aCmdBuf[bCmdLen++] = bHostMode;
  aCmdBuf[bCmdLen++] = PHHAL_HW_SAMAV3_ISO7816_DEFAULT_LE_BYTE;

  /* Buffer the command information to exchange buffer and exchange the bufferred information to Sam hardware. */
  wStatus = phhalHw_SamAV3_Cmd_7816Exchange(
          pDataParams,
          PH_EXCHANGE_DEFAULT,
          aCmdBuf,
          bCmdLen,
          &pResponse,
          &wRespLen);

  /* We expect chaining as the status from Sam hardware. */
  if (wStatus != (PH_COMP_HAL | PHHAL_HW_SAMAV3_ERR_OK_CHAINING_ACTIVE)) {
    return wStatus;
  }

  /* Check if response if of not the expected size. */
  if (wRespLen != 0x0C) {
    return PH_ADD_COMPCODE(PH_ERR_LENGTH_ERROR, PH_COMP_HAL);
  }

  /* Calculate MACHost = MAC(Kx, Rnd2 || HostMode || 0x00 || 0x00 || 0x00)  */

  /* Prepare the payload for second part of Cmd.SAM_AuthenticateHost command. */
  memcpy(aRnd2, pResponse, 0x0C);  /* PRQA S 3200 */
  aRnd2[12] = bHostMode;
  memset(&aRnd2[13], 0, 3); /* PRQA S 3200 */

  /* Load the key to CryptoSym. */
  PH_CHECK_SUCCESS_FCT(wStatus, phCryptoSym_LoadKeyDirect(
          pDataParams->pMACCryptoDataParams,
          aKey,
          wKeyType));

  /* Comupte the Mac. */
  PH_CHECK_SUCCESS_FCT(wStatus, phCryptoSym_CalculateMac(
          pDataParams->pMACCryptoDataParams,
          PH_CRYPTOSYM_MAC_MODE_CMAC,
          aRnd2,
          PH_CRYPTOSYM_AES_BLOCK_SIZE,
          aMac,
          &bMacLen));

  /* Truncate the MAC. */
  PH_CHECK_SUCCESS_FCT(wStatus, phhalHw_SamAV3_Utils_TruncateMacBuffer(aMac, &bMacLen));

  /* Generate the Random number to be sent to Sam hardware. */
  PH_CHECK_SUCCESS_FCT(wStatus, phCryptoRng_Rnd(pDataParams->pCryptoRngDataParams, 12, aRnd1));

  /* Buffer the command information to exchange buffer. */
  PH_CHECK_SUCCESS_FCT(wStatus, phhalHw_SamAV3_Cmd_7816Exchange(
          pDataParams,
          PH_EXCHANGE_BUFFER_FIRST,
          aCmdBuf,
          5,
          NULL,
          NULL));

  /* Buffer the calculated MACHost information to exchange buffer. */
  PH_CHECK_SUCCESS_FCT(wStatus, phhalHw_SamAV3_Cmd_7816Exchange(
          pDataParams,
          PH_EXCHANGE_BUFFER_CONT,
          aMac,
          bMacLen,
          NULL,
          NULL));

  /* Buffer the generate randon numeber to exchange buffer. */
  PH_CHECK_SUCCESS_FCT(wStatus, phhalHw_SamAV3_Cmd_7816Exchange(
          pDataParams,
          PH_EXCHANGE_BUFFER_CONT,
          aRnd1,
          12,
          NULL,
          NULL));

  /* Update Lc */
  PH_CHECK_SUCCESS_FCT(wStatus, phhalHw_SamAV3_Utils_UpdateLc(pDataParams));

  /* Buffer Le to exchange buffer and exchange the bufferred information to Sam hardware. */
  wStatus = phhalHw_SamAV3_Cmd_7816Exchange(
          pDataParams,
          PH_EXCHANGE_BUFFER_LAST,
          gaDefaultLe,
          1,
          &pResponse,
          &wRespLen);

  /* We expect chaining as the status frm Sam hardware. */
  if (wStatus != (PH_COMP_HAL | PHHAL_HW_SAMAV3_ERR_OK_CHAINING_ACTIVE)) {
    return wStatus;
  }

  /* Check if response if of not the expected size. */
  if (wRespLen != 0x18) {
    return PH_ADD_COMPCODE(PH_ERR_LENGTH_ERROR, PH_COMP_HAL);
  }

  /* Prepare the payload for MAC calculation. */
  aRnd1[12] = bHostMode;
  memset(&aRnd1[13], 0, 3); /* PRQA S 3200 */

  /* Calcualte the Mac to verify it with the received data from Sam hardware. */
  PH_CHECK_SUCCESS_FCT(wStatus, phCryptoSym_CalculateMac(
          pDataParams->pMACCryptoDataParams,
          PH_CRYPTOSYM_MAC_MODE_CMAC,
          aRnd1,
          PH_CRYPTOSYM_AES_BLOCK_SIZE,
          aMac,
          &bMacLen));

  /* Truncate the MAC. */
  PH_CHECK_SUCCESS_FCT(wStatus, phhalHw_SamAV3_Utils_TruncateMacBuffer(aMac, &bMacLen));

  /* Check if the received MAC and calculated MAC are same. */
  if (memcmp(aMac, pResponse, bMacLen)) {
    return PH_ADD_COMPCODE(PH_ERR_PROTOCOL_ERROR, PH_COMP_HAL);
  }

  /* Derive the Kxe key from kx using Rnd1 and Rnd2 - note: Secret key needs to be loaded into MAC data params*/
  PH_CHECK_SUCCESS_FCT(wStatus, phhalHw_SamAV3_Utils_GenerateHostAuthSessionKey(
          pDataParams,
          (uint8_t)wKeyType,
          aRnd1,
          aRnd2,
          aKxeKey,
          &bKeyLen));

  /* Load the generated Session key to crypto params. */
  PH_CHECK_SUCCESS_FCT(wStatus, phCryptoSym_LoadKeyDirect(
          pDataParams->pENCCryptoDataParams,
          aKxeKey,
          wKeyType));

  /* Load default initialization vector. */
  PH_CHECK_SUCCESS_FCT(wStatus, phCryptoSym_LoadIv(
          pDataParams->pENCCryptoDataParams,
          gaFirstIv,
          PH_CRYPTOSYM_AES_BLOCK_SIZE));

  /* Get the Encrypted(Kxe, RndB) in Rnd2*/
  PH_CHECK_SUCCESS_FCT(wStatus, phCryptoSym_Decrypt(
          pDataParams->pENCCryptoDataParams,
          (PH_CRYPTOSYM_CIPHER_MODE_CBC),
          &pResponse[8],
          PH_CRYPTOSYM_AES_BLOCK_SIZE,
          aRnd2));

  /* Now we start with part 3 exchange */
  /* Initialize the RndA array*/
  PH_CHECK_SUCCESS_FCT(wStatus, phCryptoRng_Rnd(pDataParams->pCryptoRngDataParams,
          PH_CRYPTOSYM_AES_BLOCK_SIZE, aRnd1));
  memcpy(aRndAB, aRnd1, PH_CRYPTOSYM_AES_BLOCK_SIZE);  /* PRQA S 3200 */

  /* calculate RndB'*/
  memcpy(&aRndAB[16], &aRnd2[2], 14);  /* PRQA S 3200 */
  aRndAB[30] = aRnd2[0];
  aRndAB[31] = aRnd2[1];

  /* Encrypt aRndAB*/
  PH_CHECK_SUCCESS_FCT(wStatus, phCryptoSym_Encrypt(
          pDataParams->pENCCryptoDataParams,
          PH_CRYPTOSYM_CIPHER_MODE_CBC,
          aRndAB,
          32,
          aRndAB));

  /* Exchange first part of the command */
  PH_CHECK_SUCCESS_FCT(wStatus, phhalHw_SamAV3_Cmd_7816Exchange(
          pDataParams,
          PH_EXCHANGE_BUFFER_FIRST,
          aCmdBuf,
          5,
          NULL,
          NULL));

  /* Exchange RNDAB part of the command */
  PH_CHECK_SUCCESS_FCT(wStatus, phhalHw_SamAV3_Cmd_7816Exchange(
          pDataParams,
          PH_EXCHANGE_BUFFER_CONT,
          aRndAB,
          32,
          NULL,
          NULL));

  /* Update Lc */
  PH_CHECK_SUCCESS_FCT(wStatus, phhalHw_SamAV3_Utils_UpdateLc(pDataParams));

  /* Exchange LE part of the command */
  PH_CHECK_SUCCESS_FCT(wStatus, phhalHw_SamAV3_Cmd_7816Exchange(
          pDataParams,
          PH_EXCHANGE_BUFFER_LAST,
          gaDefaultLe,
          1,
          &pResponse,
          &wRespLen));

  if (wRespLen != 0x10) {
    return PH_ADD_COMPCODE(PH_ERR_LENGTH_ERROR, PH_COMP_HAL);
  }

  /* Load initial IV */
  PH_CHECK_SUCCESS_FCT(wStatus, phCryptoSym_LoadIv(
          pDataParams->pENCCryptoDataParams,
          gaFirstIv,
          PH_CRYPTOSYM_AES_BLOCK_SIZE));

  /* decrypt the Response3 and check RndA'*/
  PH_CHECK_SUCCESS_FCT(wStatus, phCryptoSym_Decrypt(
          pDataParams->pENCCryptoDataParams,
          (PH_CRYPTOSYM_CIPHER_MODE_CBC),
          pResponse,
          16,
          aRndAB));

  if (memcmp(aRndAB, &aRnd1[2], 14) != 0)
    /* The response for RndA is not equal to sent RndA, Authentication failed PH_ERR_AUTH_ERROR*/
  {
    return PH_ADD_COMPCODE(PH_ERR_AUTH_ERROR, PH_COMP_HAL);
  }

  if ((aRnd1[0] != aRndAB[14]) || (aRnd1[1] != aRndAB[15]))
    /* The response for RndA is not equal to sent RndA, Authentication failed PH_ERR_AUTH_ERROR*/
  {
    return PH_ADD_COMPCODE(PH_ERR_AUTH_ERROR, PH_COMP_HAL);
  }

  /* Host Authentication is successfully completed */
  /* Generate the current SessionKey for this HostAuthentication*/
  PH_CHECK_SUCCESS_FCT(wStatus, phhalHw_SamAV3_Utils_GenerateSessionKey(
          pDataParams,
          (uint8_t)wKeyType,
          aRnd1,
          aRnd2,
          aSessionEncKey,
          aSessionMacKey,
          &bKeyLen));

  PH_LOG_HELPER_ADDPARAM_BUFFER(PH_LOG_LOGTYPE_DEBUG, SessKey_Enc_SAM_HOST_log, aSessionEncKey,
      bKeyLen);
  PH_LOG_HELPER_ADDPARAM_BUFFER(PH_LOG_LOGTYPE_DEBUG, SessKey_Mac_SAM_HOST_log, aSessionMacKey,
      bKeyLen);
  PH_LOG_HELPER_EXECUTE(PH_LOG_OPTION_CATEGORY_GEN);

  /* reset both pENCCryptoDataParams and pMACCryptoDataParams with Sessionkey*/
  PH_CHECK_SUCCESS_FCT(wStatus, phCryptoSym_LoadKeyDirect(
          pDataParams->pENCCryptoDataParams,
          aSessionEncKey,
          wKeyType));

  /* Load initial IV */
  PH_CHECK_SUCCESS_FCT(wStatus, phCryptoSym_LoadIv(
          pDataParams->pENCCryptoDataParams,
          gaFirstIv,
          PH_CRYPTOSYM_AES_BLOCK_SIZE));

  PH_CHECK_SUCCESS_FCT(wStatus, phCryptoSym_LoadKeyDirect(
          pDataParams->pMACCryptoDataParams,
          aSessionMacKey,
          wKeyType));

  /* Load initial IV */
  PH_CHECK_SUCCESS_FCT(wStatus, phCryptoSym_LoadIv(
          pDataParams->pMACCryptoDataParams,
          gaFirstIv,
          PH_CRYPTOSYM_AES_BLOCK_SIZE));

  /* reset the Command counter */
  pDataParams->Cmd_Ctr = 0;
  pDataParams->bAuthType = bHostMode;
  pDataParams->bKeyNo = bSamKeyNo;

  return PH_ADD_COMPCODE(PH_ERR_SUCCESS, PH_COMP_HAL);
}

phStatus_t
phhalHw_SamAV3_Cmd_SAM_GetVersion(phhalHw_SamAV3_DataParams_t *pDataParams, uint8_t *pVersion,
    uint8_t *pVersionLen)
{
  phStatus_t	PH_MEMLOC_REM wStatus = 0;
  uint8_t		PH_MEMLOC_REM aCmdBuf[PHHAL_HW_SAMAV3_ISO7816_HEADER_LENGTH];
  uint8_t 	*PH_MEMLOC_REM pResponse = NULL;
  uint16_t	PH_MEMLOC_REM wRespLen = 0;

  /* Verify the parameters. */
  PH_ASSERT_NULL_DATA_PARAM(pDataParams, PH_COMP_HAL);
  PH_ASSERT_NULL_PARAM(pVersion, PH_COMP_HAL);
  PH_ASSERT_NULL_PARAM(pVersionLen, PH_COMP_HAL);

  /* Reset the command buffer. */
  memset(aCmdBuf, 0x00, sizeof(aCmdBuf));	/* PRQA S 3200 */

  /* Frame Cmd.SAM_GetVersion command information. */
  aCmdBuf[PHHAL_HW_SAMAV3_ISO7816_CLA_POS]		= PHHAL_HW_SAMAV3_ISO7816_CLA_BYTE;
  aCmdBuf[PHHAL_HW_SAMAV3_ISO7816_INS_POS]		= PHHAL_HW_SAMAV3_CMD_GET_VERSION_INS;
  aCmdBuf[PHHAL_HW_SAMAV3_ISO7816_P1_POS]			= PHHAL_HW_SAMAV3_ISO7816_DEFAULT_P1_BYTE;
  aCmdBuf[PHHAL_HW_SAMAV3_ISO7816_P2_POS]			= PHHAL_HW_SAMAV3_ISO7816_DEFAULT_P2_BYTE;
  aCmdBuf[PHHAL_HW_SAMAV3_ISO7816_LE_NO_LC_POS]	= PHHAL_HW_SAMAV3_ISO7816_DEFAULT_LE_BYTE;

  PN5180_LOG_INFO("\n%s: Call to phhalHw_SamAV3_Cmd_7816Exchange with this data: \n 0x ", __func__);
  for (uint8_t i = PHHAL_HW_SAMAV3_ISO7816_CLA_POS;
      i < (PHHAL_HW_SAMAV3_ISO7816_CLA_POS + PHHAL_HW_SAMAV3_ISO7816_HEADER_LENGTH); i++) {
    PN5180_LOG_INFO("%02X ", aCmdBuf[i]);
  }
  PN5180_LOG_INFO("\n ");

  /* Exchange the command information to Sam hardware. */
  PH_CHECK_SUCCESS_FCT(wStatus, phhalHw_SamAV3_Cmd_7816Exchange(
          pDataParams,
          PH_EXCHANGE_DEFAULT,
          aCmdBuf,
          PHHAL_HW_SAMAV3_ISO7816_HEADER_LENGTH,
          &pResponse,
          &wRespLen));

  /* Copy the length to the actual parameter. */
  memcpy(pVersion, pResponse, wRespLen);	/* PRQA S 3200 */
  *pVersionLen = (uint8_t) wRespLen;

  return PH_ADD_COMPCODE(PH_ERR_SUCCESS, PH_COMP_HAL);
}

phStatus_t
phhalHw_SamAV3_Cmd_SAM_DisableCrypto(phhalHw_SamAV3_DataParams_t *pDataParams, uint16_t wProMas)
{
  phStatus_t	PH_MEMLOC_REM wStatus = 0;
  uint8_t		PH_MEMLOC_REM aCmdBuf[PHHAL_HW_SAMAV3_ISO7816_HEADER_LENGTH +
                                            2 /* Non-volatile programming bitmask */];
  uint8_t		PH_MEMLOC_REM bCmdLen = 0;
  uint8_t 	*PH_MEMLOC_REM pResponse = NULL;
  uint16_t	PH_MEMLOC_REM wRespLen = 0;

  /* Verify the parameters. */
  PH_ASSERT_NULL_DATA_PARAM(pDataParams, PH_COMP_HAL);

  /* Reset the command buffer and its length variable. */
  bCmdLen = 0;
  memset(aCmdBuf, 0, sizeof(aCmdBuf));  /* PRQA S 3200 */

  /* Frame Cmd.SAM_DisableCrypto command information. */
  aCmdBuf[bCmdLen++] = PHHAL_HW_SAMAV3_ISO7816_CLA_BYTE;
  aCmdBuf[bCmdLen++] = PHHAL_HW_SAMAV3_CMD_DISABLE_CRYPTO_INS;
  aCmdBuf[bCmdLen++] = PHHAL_HW_SAMAV3_ISO7816_DEFAULT_P1_BYTE;
  aCmdBuf[bCmdLen++] = PHHAL_HW_SAMAV3_ISO7816_DEFAULT_P2_BYTE;
  aCmdBuf[bCmdLen++] = 2 /* Non-volatile programming bitmask */;

  /* Add ProMas information to command buffer. */
  aCmdBuf[bCmdLen++] = (uint8_t)(wProMas & 0x00FF);
  aCmdBuf[bCmdLen++] = (uint8_t)((wProMas & 0xFF00) >> 8);

  /* Exchange the command information to Sam hardware. */
  PH_CHECK_SUCCESS_FCT(wStatus, phhalHw_SamAV3_Cmd_7816Exchange(
          pDataParams,
          PH_EXCHANGE_DEFAULT,
          aCmdBuf,
          bCmdLen,
          &pResponse,
          &wRespLen));

  return PH_ADD_COMPCODE(PH_ERR_SUCCESS, PH_COMP_HAL);
}

phStatus_t
phhalHw_SamAV3_Cmd_SAM_ActivateOfflineKey(phhalHw_SamAV3_DataParams_t *pDataParams,
    uint8_t bOption, uint8_t bKeyNo, uint8_t bKeyV, uint8_t *pDivInput,
    uint8_t bDivInputLen)
{
  phStatus_t	PH_MEMLOC_REM wStatus = 0;
  uint8_t		PH_MEMLOC_REM aCmdBuf[PHHAL_HW_SAMAV3_ISO7816_HEADER_LENGTH + 2 /* Key No and KeyVer */];
  uint8_t		PH_MEMLOC_REM bCmdLen = 0;
  uint8_t 	*PH_MEMLOC_REM pResponse = NULL;
  uint16_t	PH_MEMLOC_REM wRespLen = 0;

  /* Verify the parameters. */
  PH_ASSERT_NULL_DATA_PARAM(pDataParams, PH_COMP_HAL);
  if (bDivInputLen) {
    PH_ASSERT_NULL_PARAM(pDivInput, PH_COMP_HAL);
  }

  /* Reset the command buffer and its length variable. */
  bCmdLen = 0;
  memset(aCmdBuf, 0, sizeof(aCmdBuf));  /* PRQA S 3200 */

  /* Frame Cmd.SAM_ActivateOfflineKey command information. */
  aCmdBuf[bCmdLen++] = PHHAL_HW_SAMAV3_ISO7816_CLA_BYTE;
  aCmdBuf[bCmdLen++] = PHHAL_HW_SAMAV3_CMD_ACTIVATE_OFFLINE_KEY_INS;
  aCmdBuf[bCmdLen++] = PHHAL_HW_SAMAV3_ISO7816_DEFAULT_P1_BYTE;
  aCmdBuf[bCmdLen++] = PHHAL_HW_SAMAV3_ISO7816_DEFAULT_P2_BYTE;
  aCmdBuf[bCmdLen++] = 2 /* Key No and Key Version */ + bDivInputLen;

  /* Add the key number and version to command buffer. */
  aCmdBuf[bCmdLen++] = bKeyNo;
  aCmdBuf[bCmdLen++] = bKeyV;

  /* Update P1 information byte. */
  aCmdBuf[PHHAL_HW_SAMAV3_ISO7816_P1_POS] = bOption;
  if (bDivInputLen) {
    aCmdBuf[PHHAL_HW_SAMAV3_ISO7816_P1_POS] |= 0x01;
  }

  /* Buffer the command information to exchande buffer. */
  PH_CHECK_SUCCESS_FCT(wStatus, phhalHw_SamAV3_Cmd_7816Exchange(
          pDataParams,
          PH_EXCHANGE_BUFFER_FIRST,
          aCmdBuf,
          bCmdLen,
          NULL,
          NULL));

  /* Buffer diversification input to exchange buffer */
  PH_CHECK_SUCCESS_FCT(wStatus, phhalHw_SamAV3_Cmd_7816Exchange(
          pDataParams,
          PH_EXCHANGE_BUFFER_CONT,
          pDivInput,
          bDivInputLen,
          &pResponse,
          &wRespLen));

  /* Update Lc */
  PH_CHECK_SUCCESS_FCT(wStatus, phhalHw_SamAV3_Utils_UpdateLc(pDataParams));

  /* Exchange the bufferred information to Sam hardware. */
  PH_CHECK_SUCCESS_FCT(wStatus, phhalHw_SamAV3_Cmd_7816Exchange(
          pDataParams,
          PH_EXCHANGE_BUFFER_LAST,
          NULL,
          0,
          &pResponse,
          &wRespLen));

  return PH_ADD_COMPCODE(PH_ERR_SUCCESS, PH_COMP_HAL);
}

phStatus_t
phhalHw_SamAV3_Cmd_SAM_LoadInitVector(phhalHw_SamAV3_DataParams_t *pDataParams, uint8_t bOption,
    uint8_t *pData, uint8_t bDataLen)
{
  phStatus_t	PH_MEMLOC_REM wStatus = 0;
  uint8_t		PH_MEMLOC_REM aCmdBuf[PHHAL_HW_SAMAV3_ISO7816_HEADER_LENGTH];
  uint8_t 	*PH_MEMLOC_REM pResponse = NULL;
  uint16_t	PH_MEMLOC_REM wRespLen = 0;

  /* Parameter validation. */
  PH_ASSERT_NULL_DATA_PARAM(pDataParams, PH_COMP_HAL);
  PH_ASSERT_NULL_PARAM(pData, PH_COMP_HAL);

  /* Reset the command buffer. */
  memset(aCmdBuf, 0, sizeof(aCmdBuf));  /* PRQA S 3200 */

  /* Frame Cmd.SAM_LoadInitVector information. */
  aCmdBuf[PHHAL_HW_SAMAV3_ISO7816_CLA_POS] = PHHAL_HW_SAMAV3_ISO7816_CLA_BYTE;
  aCmdBuf[PHHAL_HW_SAMAV3_ISO7816_INS_POS] = PHHAL_HW_SAMAV3_CMD_LOAD_INIT_VECTOR_INS;
  aCmdBuf[PHHAL_HW_SAMAV3_ISO7816_P1_POS]  = bOption;
  aCmdBuf[PHHAL_HW_SAMAV3_ISO7816_P2_POS]  = PHHAL_HW_SAMAV3_ISO7816_DEFAULT_P2_BYTE;
  aCmdBuf[PHHAL_HW_SAMAV3_ISO7816_LC_POS]  = bDataLen;

  /* Buffer the command information to exchange buffer. */
  PH_CHECK_SUCCESS_FCT(wStatus, phhalHw_SamAV3_Cmd_7816Exchange(
          pDataParams,
          PH_EXCHANGE_BUFFER_FIRST,
          aCmdBuf,
          PHHAL_HW_SAMAV3_ISO7816_HEADER_LENGTH,
          NULL,
          NULL));

  /* Exchange final part with lower layer */
  PH_CHECK_SUCCESS_FCT(wStatus, phhalHw_SamAV3_Cmd_7816Exchange(
          pDataParams,
          PH_EXCHANGE_BUFFER_LAST,
          pData,
          bDataLen,
          &pResponse,
          &wRespLen));

  return PH_ADD_COMPCODE(PH_ERR_SUCCESS, PH_COMP_HAL);
}

phStatus_t
phhalHw_SamAV3_Cmd_SAM_KillAuthentication(phhalHw_SamAV3_DataParams_t *pDataParams,
    uint8_t bOption)
{
  phStatus_t	PH_MEMLOC_REM wStatus = 0;
  uint8_t		PH_MEMLOC_REM aCmdBuf[PHHAL_HW_SAMAV3_ISO7816_HEADER_NO_LC_LENGTH];
  uint8_t 	*PH_MEMLOC_REM pResponse = NULL;
  uint16_t	PH_MEMLOC_REM RespLen = 0;

  /* Verify the parameters. */
  PH_ASSERT_NULL_DATA_PARAM(pDataParams, PH_COMP_HAL);

  /* Reset the command buffer. */
  memset(aCmdBuf, 0, sizeof(aCmdBuf));  /* PRQA S 3200 */

  /* Frame Cmd.SAM_KillAuthentication command information. */
  aCmdBuf[PHHAL_HW_SAMAV3_ISO7816_CLA_POS] = PHHAL_HW_SAMAV3_ISO7816_CLA_BYTE;
  aCmdBuf[PHHAL_HW_SAMAV3_ISO7816_INS_POS] = PHHAL_HW_SAMAV3_CMD_KILL_AUTHENTICATION_INS;
  aCmdBuf[PHHAL_HW_SAMAV3_ISO7816_P1_POS] = bOption;
  aCmdBuf[PHHAL_HW_SAMAV3_ISO7816_P2_POS] = PHHAL_HW_SAMAV3_ISO7816_DEFAULT_P2_BYTE;

  /* Exchange the command information to Sam hardware. */
  PH_CHECK_SUCCESS_FCT(wStatus, phhalHw_SamAV3_Cmd_7816Exchange(
          pDataParams,
          PH_EXCHANGE_DEFAULT,
          aCmdBuf,
          PHHAL_HW_SAMAV3_ISO7816_HEADER_NO_LC_LENGTH,
          &pResponse,
          &RespLen));

  /* Reset Crypto in case of success and P1 == 0x00 */
  if (!bOption) {
    /* Reset the session keys data params. */
    PH_CHECK_SUCCESS_FCT(wStatus, phCryptoSym_InvalidateKey(pDataParams->pENCCryptoDataParams));
    PH_CHECK_SUCCESS_FCT(wStatus, phCryptoSym_InvalidateKey(pDataParams->pMACCryptoDataParams));

    /* Reset the secure messaging members.  */
    pDataParams->bCmdSM = PHHAL_HW_SAMAV3_HSM_AES_NO_SM;
    pDataParams->bRespSM = PHHAL_HW_SAMAV3_HSM_AES_NO_SM;

    /* Reset the Authentication host mode to plain. */
    pDataParams->bAuthType = PHHAL_HW_SAMAV3_CMD_SAM_AUTHENTICATE_HOST_MODE_PLAIN;

    /* Reset the MAC and ENC buffers and length. */
    memset(pDataParams->bPendingCmdIv, 0x00,
        sizeof(pDataParams->bPendingCmdIv));        /* PRQA S 3200 */
    memset(pDataParams->bPendingCmdMac, 0x00,
        sizeof(pDataParams->bPendingCmdMac));        /* PRQA S 3200 */
    memset(pDataParams->bPendingEncCmdData, 0x00,
        sizeof(pDataParams->bPendingEncCmdData));        /* PRQA S 3200 */
    memset(pDataParams->bPendingMacCmdData, 0x00,
        sizeof(pDataParams->bPendingMacCmdData));        /* PRQA S 3200 */
    memset(pDataParams->bPendingMacRespData, 0x00,
        sizeof(pDataParams->bPendingMacRespData));        /* PRQA S 3200 */
    memset(pDataParams->bPendingRespData, 0x00,
        sizeof(pDataParams->bPendingRespData));        /* PRQA S 3200 */
    memset(pDataParams->bPendingRespIv, 0x00,
        sizeof(pDataParams->bPendingRespIv));        /* PRQA S 3200 */
    memset(pDataParams->bPendingRespMac, 0x00,
        sizeof(pDataParams->bPendingRespMac));        /* PRQA S 3200 */

    pDataParams->bPendingEncCmdDataLength = 0;
    pDataParams->bPendingMacCmdDataLength = 0;
    pDataParams->bPendingMacRespDataLength = 0;
    pDataParams->bPendingRespDataLength = 0;
  } else {
    pDataParams->bMifareCryptoDisabled = PH_ON;
  }

  return PH_ADD_COMPCODE(PH_ERR_SUCCESS, PH_COMP_HAL);
}

phStatus_t
phhalHw_SamAV3_Cmd_SAM_SelectApplication(phhalHw_SamAV3_DataParams_t *pDataParams,
    uint8_t *pDF_Aid)
{
  phStatus_t	PH_MEMLOC_REM wStatus = 0;
  uint8_t		PH_MEMLOC_REM aCmdBuf[PHHAL_HW_SAMAV3_ISO7816_HEADER_LENGTH];
  uint8_t 	*PH_MEMLOC_REM pResponse = NULL;
  uint16_t	PH_MEMLOC_REM wRespLen = 0;

  /* Parameter validation. */
  PH_ASSERT_NULL_PARAM(pDF_Aid, PH_COMP_HAL);

  /* Reset the command buffer. */
  memset(aCmdBuf, 0, sizeof(aCmdBuf));  /* PRQA S 3200 */

  /* Frame Cmd.SAM_SelectApplication command information. */
  aCmdBuf[PHHAL_HW_SAMAV3_ISO7816_CLA_POS] = PHHAL_HW_SAMAV3_ISO7816_CLA_BYTE;
  aCmdBuf[PHHAL_HW_SAMAV3_ISO7816_INS_POS] = PHHAL_HW_SAMAV3_CMD_SELECT_APPLICATION_INS;
  aCmdBuf[PHHAL_HW_SAMAV3_ISO7816_P1_POS]  = PHHAL_HW_SAMAV3_ISO7816_DEFAULT_P1_BYTE;
  aCmdBuf[PHHAL_HW_SAMAV3_ISO7816_P2_POS]  = PHHAL_HW_SAMAV3_ISO7816_DEFAULT_P2_BYTE;
  aCmdBuf[PHHAL_HW_SAMAV3_ISO7816_LC_POS]  = 3 /* DESFire Application ID length. */;

  /* Buffer the command information to exchange buffer. */
  PH_CHECK_SUCCESS_FCT(wStatus, phhalHw_SamAV3_Cmd_7816Exchange(
          pDataParams,
          PH_EXCHANGE_BUFFER_FIRST,
          aCmdBuf,
          PHHAL_HW_SAMAV3_ISO7816_HEADER_LENGTH,
          NULL,
          NULL));

  /* Buffer AID to exchange buffer and exchange the bufferred information to Sam hardware. */
  PH_CHECK_SUCCESS_FCT(wStatus, phhalHw_SamAV3_Cmd_7816Exchange(
          pDataParams,
          PH_EXCHANGE_BUFFER_LAST,
          pDF_Aid,
          3, /* LE is not present in that command*/
          &pResponse,
          &wRespLen));

  return PH_ADD_COMPCODE(PH_ERR_SUCCESS, PH_COMP_HAL);
}

phStatus_t
phhalHw_SamAV3_Cmd_SAM_GetRandom(phhalHw_SamAV3_DataParams_t *pDataParams, uint8_t bExpLen,
    uint8_t *pRnd)
{
  phStatus_t	PH_MEMLOC_REM wStatus = 0;
  uint8_t		PH_MEMLOC_REM aCmdBuf[PHHAL_HW_SAMAV3_ISO7816_HEADER_LENGTH];
  uint8_t 	*PH_MEMLOC_REM pResponse = NULL;
  uint16_t	PH_MEMLOC_REM wRespLen = 0;

  /* Reset the command buffer. */
  memset(aCmdBuf, 0, sizeof(aCmdBuf));  /* PRQA S 3200 */

  /* Frame Cmd.SAM_GetRandom information */
  aCmdBuf[PHHAL_HW_SAMAV3_ISO7816_CLA_POS]       = PHHAL_HW_SAMAV3_ISO7816_CLA_BYTE;
  aCmdBuf[PHHAL_HW_SAMAV3_ISO7816_INS_POS]       = PHHAL_HW_SAMAV3_CMD_GET_CHALLENGE_INS;
  aCmdBuf[PHHAL_HW_SAMAV3_ISO7816_P1_POS]        = PHHAL_HW_SAMAV3_ISO7816_DEFAULT_P1_BYTE;
  aCmdBuf[PHHAL_HW_SAMAV3_ISO7816_P2_POS]        = PHHAL_HW_SAMAV3_ISO7816_DEFAULT_P2_BYTE;
  aCmdBuf[PHHAL_HW_SAMAV3_ISO7816_LE_NO_LC_POS]  = bExpLen;

  /* Exchange the command information to Sam hardware. */
  PH_CHECK_SUCCESS_FCT(wStatus, phhalHw_SamAV3_Cmd_7816Exchange(
          pDataParams,
          PH_EXCHANGE_DEFAULT,
          aCmdBuf,
          PHHAL_HW_SAMAV3_ISO7816_HEADER_LENGTH,
          &pResponse,
          &wRespLen));

  /* Check if required number of bytes are returned by Sam hardware. */
  if (wRespLen != bExpLen) {
    return PH_ADD_COMPCODE(PH_ERR_LENGTH_ERROR, PH_COMP_HAL);
  }

  /* Copy the response to parameter.  */
  memcpy(pRnd, pResponse, bExpLen);  /* PRQA S 3200 */

  return PH_ADD_COMPCODE(PH_ERR_SUCCESS, PH_COMP_HAL);
}

phStatus_t
phhalHw_SamAV3_Cmd_SAM_Sleep(phhalHw_SamAV3_DataParams_t *pDataParams)
{
  phStatus_t	PH_MEMLOC_REM wStatus = 0;
  uint8_t		PH_MEMLOC_REM aCmdBuf[PHHAL_HW_SAMAV3_ISO7816_HEADER_NO_LC_LENGTH];
  uint8_t 	*PH_MEMLOC_REM pResponse = NULL;
  uint16_t	PH_MEMLOC_REM wRespLen = 0;

  /* Verify the parameters. */
  PH_ASSERT_NULL_DATA_PARAM(pDataParams, PH_COMP_HAL);

  /* Reset the command buffer. */
  memset(aCmdBuf, 0, sizeof(aCmdBuf));  /* PRQA S 3200 */

  /* Frame Cmd.SAM_Sleep command information. */
  aCmdBuf[PHHAL_HW_SAMAV3_ISO7816_CLA_POS] = PHHAL_HW_SAMAV3_ISO7816_CLA_BYTE;
  aCmdBuf[PHHAL_HW_SAMAV3_ISO7816_INS_POS] = PHHAL_HW_SAMAV3_CMD_SLEEP_INS;
  aCmdBuf[PHHAL_HW_SAMAV3_ISO7816_P1_POS]  = PHHAL_HW_SAMAV3_ISO7816_DEFAULT_P1_BYTE;
  aCmdBuf[PHHAL_HW_SAMAV3_ISO7816_P2_POS]  = PHHAL_HW_SAMAV3_ISO7816_DEFAULT_P2_BYTE;

  /* Exchange the command information to Sam hardware. */
  PH_CHECK_SUCCESS_FCT(wStatus, phhalHw_SamAV3_Cmd_7816Exchange(
          pDataParams,
          PH_EXCHANGE_DEFAULT,
          aCmdBuf,
          PHHAL_HW_SAMAV3_ISO7816_HEADER_NO_LC_LENGTH,
          &pResponse,
          &wRespLen));

  return PH_ADD_COMPCODE(PH_ERR_SUCCESS, PH_COMP_HAL);
}

phStatus_t
phhalHw_SamAV3_Cmd_SAM_SetConfiguration(phhalHw_SamAV3_DataParams_t *pDataParams, uint8_t bOption,
    uint8_t *pData, uint8_t bDataLen)
{
  phStatus_t	PH_MEMLOC_REM wStatus = 0;
  uint8_t		PH_MEMLOC_REM aCmdBuf[PHHAL_HW_SAMAV3_ISO7816_HEADER_LENGTH];
  uint8_t		PH_MEMLOC_REM bCmdLen = 0;
  uint8_t 	*PH_MEMLOC_REM pResponse = NULL;
  uint16_t	PH_MEMLOC_REM wRespLen = 0;

  /* Parameter validation. */
  PH_ASSERT_NULL_DATA_PARAM(pDataParams, PH_COMP_HAL);
  if (bOption <= PHHAL_HW_SAMAV3_CMD_SAM_SET_CONFIGURATION_FULL_ATR) {
    PH_ASSERT_NULL_PARAM(pData, PH_COMP_HAL);
  }

  /* Reset the command buffer and its length variable. */
  bCmdLen = 0;
  memset(aCmdBuf, 0, sizeof(aCmdBuf));  /* PRQA S 3200 */

  /* Frame Cmd.SAM_SetConfiguration command information. */
  aCmdBuf[bCmdLen++] = PHHAL_HW_SAMAV3_ISO7816_CLA_BYTE;
  aCmdBuf[bCmdLen++] = PHHAL_HW_SAMAV3_CMD_SETCONFIGURATION_INS;
  aCmdBuf[bCmdLen++] =  bOption;
  aCmdBuf[bCmdLen++] = PHHAL_HW_SAMAV3_ISO7816_DEFAULT_P2_BYTE;

  /* Add LC to command buffer if required. */
  if (bOption <= PHHAL_HW_SAMAV3_CMD_SAM_SET_CONFIGURATION_FULL_ATR) {
    aCmdBuf[bCmdLen++] = bDataLen;
  }

  /* Buffer command information to exchange buffer. */
  PH_CHECK_SUCCESS_FCT(wStatus, phhalHw_SamAV3_Cmd_7816Exchange(
          pDataParams,
          PH_EXCHANGE_BUFFER_FIRST,
          aCmdBuf,
          bCmdLen,
          NULL,
          NULL));

  /* Buffer data to exchange buffer. */
  PH_CHECK_SUCCESS_FCT(wStatus, phhalHw_SamAV3_Cmd_7816Exchange(
          pDataParams,
          PH_EXCHANGE_BUFFER_LAST,
          pData,
          bDataLen,
          &pResponse,
          &wRespLen));

  return PH_ADD_COMPCODE(PH_ERR_SUCCESS, PH_COMP_HAL);
}

/*************************************************************************************************************************/
/***************************************************** Key Management ****************************************************/
/*************************************************************************************************************************/

phStatus_t
phhalHw_SamAV3_Cmd_SAM_ChangeKeyEntry(phhalHw_SamAV3_DataParams_t *pDataParams, uint8_t bKeyNo,
    uint8_t bProMas, uint8_t *pKeyData, uint8_t bKeyDataLen)
{
  phStatus_t	PH_MEMLOC_REM wStatus = 0;
  uint8_t		PH_MEMLOC_REM aCmdBuf[PHHAL_HW_SAMAV3_ISO7816_HEADER_LENGTH];
  uint8_t 	*PH_MEMLOC_REM pResponse = NULL;
  uint16_t	PH_MEMLOC_REM wRespLen = 0;

  /* Parameter validation. */
  PH_ASSERT_NULL_DATA_PARAM(pDataParams, PH_COMP_HAL);
  PH_ASSERT_NULL_PARAM(pKeyData, PH_COMP_HAL);

  /* Frame Cmd.SAM_ChangeKeyEntry command information. */
  aCmdBuf[PHHAL_HW_SAMAV3_ISO7816_CLA_POS] = PHHAL_HW_SAMAV3_ISO7816_CLA_BYTE;
  aCmdBuf[PHHAL_HW_SAMAV3_ISO7816_INS_POS] = PHHAL_HW_SAMAV3_CMD_SAM_CHANGE_KEY_ENTRY_INS;
  aCmdBuf[PHHAL_HW_SAMAV3_ISO7816_P1_POS]  = bKeyNo;
  aCmdBuf[PHHAL_HW_SAMAV3_ISO7816_P2_POS]  = bProMas;
  aCmdBuf[PHHAL_HW_SAMAV3_ISO7816_LC_POS]  = bKeyDataLen;

  /* Buffer the command information to exchange buffer. */
  PH_CHECK_SUCCESS_FCT(wStatus, phhalHw_SamAV3_Cmd_7816Exchange(
          pDataParams,
          PH_EXCHANGE_BUFFER_FIRST,
          aCmdBuf,
          PHHAL_HW_SAMAV3_ISO7816_HEADER_LENGTH,
          NULL,
          NULL));

  /* Buffer the key information to exchange buffer and exchange the bufferred information to Sam hardware. */
  PH_CHECK_SUCCESS_FCT(wStatus, phhalHw_SamAV3_Cmd_7816Exchange(
          pDataParams,
          PH_EXCHANGE_BUFFER_LAST,
          pKeyData,
          bKeyDataLen,
          &pResponse,
          &wRespLen));

  /* Reset Authentication states if ChangeKey = AuthKey. */
  if (pDataParams->bKeyNo == bKeyNo) {
    /* Invalidate the session keys and set the SM to PLAIN. */
    pDataParams->bAuthType = PHHAL_HW_SAMAV3_CMD_SAM_AUTHENTICATE_HOST_MODE_PLAIN;
    PH_CHECK_SUCCESS_FCT(wStatus, phCryptoSym_InvalidateKey(pDataParams->pENCCryptoDataParams));
    PH_CHECK_SUCCESS_FCT(wStatus, phCryptoSym_InvalidateKey(pDataParams->pMACCryptoDataParams));
  }

  return PH_ADD_COMPCODE(PH_ERR_SUCCESS, PH_COMP_HAL);
}

phStatus_t
phhalHw_SamAV3_Cmd_SAM_ChangeKeyEntryOffline(phhalHw_SamAV3_DataParams_t *pDataParams,
    uint8_t bKeyNo, uint8_t bProMas, uint16_t wChangeCtr, uint8_t *pOfflineCrypto,
    uint8_t bOfflineCryptoLen, uint8_t bEnableOfflineAck, uint8_t *pOfflineAck)
{
  phStatus_t	PH_MEMLOC_REM wStatus = 0;
  uint8_t		PH_MEMLOC_REM aCmdBuf[PHHAL_HW_SAMAV3_ISO7816_HEADER_LENGTH + 2 /* ChangeCtr */];
  uint8_t		PH_MEMLOC_REM bCmdLen = 0;
  uint8_t 	*PH_MEMLOC_REM pResponse = NULL;
  uint16_t	PH_MEMLOC_REM wRespLen = 0;

  /* Parameter validation. */
  PH_ASSERT_NULL_DATA_PARAM(pDataParams, PH_COMP_HAL);
  PH_ASSERT_NULL_PARAM(pOfflineCrypto, PH_COMP_HAL);
  if (bEnableOfflineAck) {
    PH_ASSERT_NULL_PARAM(pOfflineAck, PH_COMP_HAL);
  }

  /* Reset the command buffer. */
  memset(aCmdBuf, 0, sizeof(aCmdBuf));  /* PRQA S 3200 */

  /* Frame Cmd.SAM_ChangeKeyEntryOffline command information. */
  aCmdBuf[bCmdLen++] = PHHAL_HW_SAMAV3_ISO7816_CLA_BYTE;
  aCmdBuf[bCmdLen++] = PHHAL_HW_SAMAV3_CMD_SAM_CHANGE_KEY_ENTRY_INS;
  aCmdBuf[bCmdLen++] = bKeyNo;
  aCmdBuf[bCmdLen++] = bProMas;
  aCmdBuf[bCmdLen++] = PHHAL_HW_SAMAV3_ISO7816_DEFAULT_LC_BYTE;

  /* Add Change counter. */
  aCmdBuf[bCmdLen++] = (uint8_t)((wChangeCtr & 0xFF00) >> 8);
  aCmdBuf[bCmdLen++] = (uint8_t)(wChangeCtr & 0x00FF);

  /* Buffer the command information to exchange buffer. */
  PH_CHECK_SUCCESS_FCT(wStatus, phhalHw_SamAV3_Cmd_7816Exchange(
          pDataParams,
          PH_EXCHANGE_BUFFER_FIRST,
          aCmdBuf,
          bCmdLen,
          NULL,
          NULL));

  /* Buffer offline crypto information to exchange buffer. */
  PH_CHECK_SUCCESS_FCT(wStatus, phhalHw_SamAV3_Cmd_7816Exchange(
          pDataParams,
          PH_EXCHANGE_BUFFER_CONT,
          pOfflineCrypto,
          bOfflineCryptoLen,
          NULL,
          NULL));

  /* Update LC. */
  PH_CHECK_SUCCESS_FCT(wStatus, phhalHw_SamAV3_Utils_UpdateLc(pDataParams));

  /* Exchange the bufferred inforamtion to Sam hardware. */
  PH_CHECK_SUCCESS_FCT(wStatus, phhalHw_SamAV3_Cmd_7816Exchange(
          pDataParams,
          PH_EXCHANGE_BUFFER_LAST,
          gaDefaultLe,
          (uint8_t)((bEnableOfflineAck) ? 1 : 0),
          &pResponse,
          &wRespLen));

  memcpy(pOfflineAck, pResponse, wRespLen); /* PRQA S 3200 */

  /* Reset Authentication states if ChangeKey = AuthKey. */
  if (pDataParams->bKeyNo == bKeyNo) {
    /* Perform Kill Authentication. */
    PH_CHECK_SUCCESS_FCT(wStatus, phhalHw_SamAV3_Cmd_SAM_KillAuthentication(pDataParams,
            PHHAL_HW_SAMAV3_CMD_SAM_KILL_AUTHENTICATION_FULL));

    /* Invalidate the session keys and set the SM to PLAIN. */
    pDataParams->bAuthType = PHHAL_HW_SAMAV3_CMD_SAM_AUTHENTICATE_HOST_MODE_PLAIN;
    PH_CHECK_SUCCESS_FCT(wStatus, phCryptoSym_InvalidateKey(pDataParams->pENCCryptoDataParams));
    PH_CHECK_SUCCESS_FCT(wStatus, phCryptoSym_InvalidateKey(pDataParams->pMACCryptoDataParams));
  }

  return PH_ADD_COMPCODE(PH_ERR_SUCCESS, PH_COMP_HAL);
}

phStatus_t
phhalHw_SamAV3_Cmd_SAM_GetKeyEntry(phhalHw_SamAV3_DataParams_t *pDataParams, uint8_t bKeyNo,
    uint8_t bMode, uint8_t *pKeyEntry, uint8_t *pKeyEntryLen)
{
  phStatus_t	PH_MEMLOC_REM wStatus = 0;
  uint8_t		PH_MEMLOC_REM aCmdBuf[PHHAL_HW_SAMAV3_ISO7816_HEADER_LENGTH];
  uint8_t		*PH_MEMLOC_REM pResponse = NULL;
  uint16_t	PH_MEMLOC_REM wRespLen = 0;

  /* Parameter validation. */
  PH_ASSERT_NULL_DATA_PARAM(pDataParams, PH_COMP_HAL);
  PH_ASSERT_NULL_PARAM(pKeyEntry, PH_COMP_HAL);
  PH_ASSERT_NULL_PARAM(pKeyEntryLen, PH_COMP_HAL);

  /* Frame Cmd.SAM_GetKeyEntry / Cmd.SAM_GetRAMKeyEntry command information.
   * LE is always present for these command.
   * Refer the artifact artf906788, artf909787 and the mail with
   * subject "ICODE Positive tests" for more details.
   */
  aCmdBuf[PHHAL_HW_SAMAV3_ISO7816_CLA_POS]		= PHHAL_HW_SAMAV3_ISO7816_CLA_BYTE;
  aCmdBuf[PHHAL_HW_SAMAV3_ISO7816_INS_POS]		= PHHAL_HW_SAMAV3_CMD_SAM_GET_KEY_ENTRY_INS;
  aCmdBuf[PHHAL_HW_SAMAV3_ISO7816_P1_POS]			= bKeyNo;
  aCmdBuf[PHHAL_HW_SAMAV3_ISO7816_P2_POS]			= bMode;
  aCmdBuf[PHHAL_HW_SAMAV3_ISO7816_LE_NO_LC_POS]	= PHHAL_HW_SAMAV3_ISO7816_DEFAULT_LE_BYTE;

  /* Exchange the command information to Sam hardware. */
  PH_CHECK_SUCCESS_FCT(wStatus, phhalHw_SamAV3_Cmd_7816Exchange(
          pDataParams,
          PH_EXCHANGE_DEFAULT,
          aCmdBuf,
          PHHAL_HW_SAMAV3_ISO7816_HEADER_LENGTH,
          &pResponse,
          &wRespLen));

  /* Copy the data into the buffer. */
  memcpy(pKeyEntry, pResponse, wRespLen); /* PRQA S 3200 */
  *pKeyEntryLen = (uint8_t) wRespLen;

  return PH_ADD_COMPCODE(PH_ERR_SUCCESS, PH_COMP_HAL);
}

phStatus_t
phhalHw_SamAV3_Cmd_SAM_ChangeKUCEntry(phhalHw_SamAV3_DataParams_t *pDataParams, uint8_t bKucNo,
    uint8_t bProMas, uint8_t *pKucData, uint8_t bKucDataLen)
{
  phStatus_t	PH_MEMLOC_REM wStatus = 0;
  uint8_t		PH_MEMLOC_REM aCmdBuf[PHHAL_HW_SAMAV3_ISO7816_HEADER_LENGTH];
  uint8_t 	*PH_MEMLOC_REM pResponse = NULL;
  uint16_t	PH_MEMLOC_REM wRespLen = 0;

  /* Parameter validation. */
  PH_ASSERT_NULL_DATA_PARAM(pDataParams, PH_COMP_HAL);
  PH_ASSERT_NULL_PARAM(pKucData, PH_COMP_HAL);

  /* Frame Cmd.SAM_ChangeKUCEntry command information. */
  aCmdBuf[PHHAL_HW_SAMAV3_ISO7816_CLA_POS] = PHHAL_HW_SAMAV3_ISO7816_CLA_BYTE;
  aCmdBuf[PHHAL_HW_SAMAV3_ISO7816_INS_POS] = PHHAL_HW_SAMAV3_CMD_SAM_CHANGE_KUC_ENTRY_INS;
  aCmdBuf[PHHAL_HW_SAMAV3_ISO7816_P1_POS]  = bKucNo;
  aCmdBuf[PHHAL_HW_SAMAV3_ISO7816_P2_POS]  = bProMas;
  aCmdBuf[PHHAL_HW_SAMAV3_ISO7816_LC_POS]  = bKucDataLen;

  /* Buffer the command information to exchange buffer. */
  PH_CHECK_SUCCESS_FCT(wStatus, phhalHw_SamAV3_Cmd_7816Exchange(
          pDataParams,
          PH_EXCHANGE_BUFFER_FIRST,
          aCmdBuf,
          PHHAL_HW_SAMAV3_ISO7816_HEADER_LENGTH,
          NULL,
          NULL));

  /* Buffer KucData to exchange buffer and exchange the bufferred inforamtion to Sam hardware. */
  PH_CHECK_SUCCESS_FCT(wStatus, phhalHw_SamAV3_Cmd_7816Exchange(
          pDataParams,
          PH_EXCHANGE_BUFFER_LAST,
          pKucData,
          bKucDataLen,
          &pResponse,
          &wRespLen));

  return PH_ADD_COMPCODE(PH_ERR_SUCCESS, PH_COMP_HAL);
}

phStatus_t
phhalHw_SamAV3_Cmd_SAM_ChangeKUCEntryOffline(phhalHw_SamAV3_DataParams_t *pDataParams,
    uint8_t bKucNo, uint8_t bProMas, uint16_t wChangeCtr, uint8_t *pOfflineCrypto,
    uint8_t bOfflineCryptoLen, uint8_t bEnableOfflineAck, uint8_t *pOfflineAck)
{
  phStatus_t	PH_MEMLOC_REM wStatus = 0;
  uint8_t		PH_MEMLOC_REM aCmdBuf[PHHAL_HW_SAMAV3_ISO7816_HEADER_LENGTH + 2 /* ChangeCtr */];
  uint8_t		PH_MEMLOC_REM bCmdLen = 0;
  uint8_t 	*PH_MEMLOC_REM pResponse = NULL;
  uint16_t	PH_MEMLOC_REM wRespLen = 0;

  /* Parameter validation. */
  PH_ASSERT_NULL_DATA_PARAM(pDataParams, PH_COMP_HAL);
  PH_ASSERT_NULL_PARAM(pOfflineCrypto, PH_COMP_HAL);
  if (bEnableOfflineAck) {
    PH_ASSERT_NULL_PARAM(pOfflineAck, PH_COMP_HAL);
  }

  /* Reset the command buffer. */
  memset(aCmdBuf, 0, sizeof(aCmdBuf));  /* PRQA S 3200 */

  /* Frame Cmd.SAM_ChangeKUCEntryOffline command information. */
  aCmdBuf[bCmdLen++] = PHHAL_HW_SAMAV3_ISO7816_CLA_BYTE;
  aCmdBuf[bCmdLen++] = PHHAL_HW_SAMAV3_CMD_SAM_CHANGE_KUC_ENTRY_INS;
  aCmdBuf[bCmdLen++] = bKucNo;
  aCmdBuf[bCmdLen++] = bProMas;
  aCmdBuf[bCmdLen++] = PHHAL_HW_SAMAV3_ISO7816_DEFAULT_LC_BYTE;

  /* Add Change counter. */
  aCmdBuf[bCmdLen++] = (uint8_t)((wChangeCtr & 0xFF00) >> 8);
  aCmdBuf[bCmdLen++] = (uint8_t)(wChangeCtr & 0x00FF);

  /* Buffer the command information to exchange buffer. */
  PH_CHECK_SUCCESS_FCT(wStatus, phhalHw_SamAV3_Cmd_7816Exchange(
          pDataParams,
          PH_EXCHANGE_BUFFER_FIRST,
          aCmdBuf,
          bCmdLen,
          NULL,
          NULL));

  /* Buffer offline crypto information to exchange buffer. */
  PH_CHECK_SUCCESS_FCT(wStatus, phhalHw_SamAV3_Cmd_7816Exchange(
          pDataParams,
          PH_EXCHANGE_BUFFER_CONT,
          pOfflineCrypto,
          bOfflineCryptoLen,
          NULL,
          NULL));

  /* Update LC. */
  PH_CHECK_SUCCESS_FCT(wStatus, phhalHw_SamAV3_Utils_UpdateLc(pDataParams));

  /* Exchange the bufferred inforamtion to Sam hardware. */
  PH_CHECK_SUCCESS_FCT(wStatus, phhalHw_SamAV3_Cmd_7816Exchange(
          pDataParams,
          PH_EXCHANGE_BUFFER_LAST,
          gaDefaultLe,
          (uint8_t)((bEnableOfflineAck) ? 1 : 0),
          &pResponse,
          &wRespLen));

  memcpy(pOfflineAck, pResponse, wRespLen); /* PRQA S 3200 */

  return PH_ADD_COMPCODE(PH_ERR_SUCCESS, PH_COMP_HAL);
}

phStatus_t
phhalHw_SamAV3_Cmd_SAM_GetKUCEntry(phhalHw_SamAV3_DataParams_t *pDataParams, uint8_t bKucNo,
    uint8_t *pKucEntry)
{
  phStatus_t	PH_MEMLOC_REM wStatus = 0;
  uint8_t		PH_MEMLOC_REM aCmdBuf[PHHAL_HW_SAMAV3_ISO7816_HEADER_LENGTH];
  uint8_t 	*PH_MEMLOC_REM pResponse = NULL;
  uint16_t	PH_MEMLOC_REM wRespLen = 0;

  /* Parameter validation. */
  PH_ASSERT_NULL_DATA_PARAM(pDataParams, PH_COMP_HAL);
  PH_ASSERT_NULL_PARAM(pKucEntry, PH_COMP_HAL);

  /* Frame Cmd.SAM_GetKUCEntry command information. */
  aCmdBuf[PHHAL_HW_SAMAV3_ISO7816_CLA_POS]		= PHHAL_HW_SAMAV3_ISO7816_CLA_BYTE;
  aCmdBuf[PHHAL_HW_SAMAV3_ISO7816_INS_POS]		= PHHAL_HW_SAMAV3_CMD_SAM_GET_KUC_ENTRY_INS;
  aCmdBuf[PHHAL_HW_SAMAV3_ISO7816_P1_POS]			= bKucNo;
  aCmdBuf[PHHAL_HW_SAMAV3_ISO7816_P2_POS]			= PHHAL_HW_SAMAV3_ISO7816_DEFAULT_P2_BYTE;
  aCmdBuf[PHHAL_HW_SAMAV3_ISO7816_LE_NO_LC_POS]	= PHHAL_HW_SAMAV3_ISO7816_DEFAULT_LE_BYTE;

  /* Exchange command information to Sam hardware. */
  PH_CHECK_SUCCESS_FCT(wStatus, phhalHw_SamAV3_Cmd_7816Exchange(
          pDataParams,
          PH_EXCHANGE_DEFAULT,
          aCmdBuf,
          PHHAL_HW_SAMAV3_ISO7816_HEADER_LENGTH,
          &pResponse,
          &wRespLen));

  /* Copy the response to function's parameter. */
  memcpy(pKucEntry, pResponse, wRespLen); /* PRQA S 3200 */

  return PH_ADD_COMPCODE(PH_ERR_SUCCESS, PH_COMP_HAL);
}

phStatus_t
phhalHw_SamAV3_Cmd_SAM_DumpSessionKey(phhalHw_SamAV3_DataParams_t *pDataParams, uint8_t bDumpMode,
    uint8_t *pSessionKey, uint8_t *pSessionKeyLen)
{
  phStatus_t	PH_MEMLOC_REM wStatus = 0;
  uint8_t		PH_MEMLOC_REM aCmdBuf[PHHAL_HW_SAMAV3_ISO7816_HEADER_LENGTH];
  uint8_t		*PH_MEMLOC_REM pResponse = NULL;
  uint16_t	PH_MEMLOC_REM wRespLen = 0;

  /* Parameter validation. */
  PH_ASSERT_NULL_DATA_PARAM(pDataParams, PH_COMP_HAL);
  PH_ASSERT_NULL_PARAM(pSessionKey, PH_COMP_HAL);
  PH_ASSERT_NULL_PARAM(pSessionKeyLen, PH_COMP_HAL);

  /* Frame Cmd.SAM_DumpSessionKey command information. */
  aCmdBuf[PHHAL_HW_SAMAV3_ISO7816_CLA_POS]		= PHHAL_HW_SAMAV3_ISO7816_CLA_BYTE;
  aCmdBuf[PHHAL_HW_SAMAV3_ISO7816_INS_POS]		= PHHAL_HW_SAMAV3_CMD_SAM_DUMP_SESSION_KEY_INS;
  aCmdBuf[PHHAL_HW_SAMAV3_ISO7816_P1_POS]			= bDumpMode;
  aCmdBuf[PHHAL_HW_SAMAV3_ISO7816_P2_POS]			= PHHAL_HW_SAMAV3_ISO7816_DEFAULT_P2_BYTE;
  aCmdBuf[PHHAL_HW_SAMAV3_ISO7816_LE_NO_LC_POS]	= PHHAL_HW_SAMAV3_ISO7816_DEFAULT_LE_BYTE;

  /* Exchange the command information to Sam hardware. */
  PH_CHECK_SUCCESS_FCT(wStatus, phhalHw_SamAV3_Cmd_7816Exchange(
          pDataParams,
          PH_EXCHANGE_DEFAULT,
          aCmdBuf,
          PHHAL_HW_SAMAV3_ISO7816_HEADER_LENGTH,
          &pResponse,
          &wRespLen));

  /* Copy the response to the parameters. */
  memcpy(pSessionKey, pResponse, wRespLen); /* PRQA S 3200 */
  *pSessionKeyLen = (uint8_t) wRespLen;

  return PH_ADD_COMPCODE(PH_ERR_SUCCESS, PH_COMP_HAL);
}

phStatus_t
phhalHw_SamAV3_Cmd_SAM_DumpSecretKey(phhalHw_SamAV3_DataParams_t *pDataParams, uint8_t bDumpMode,
    uint8_t bKeyNo, uint8_t bKeyVer, uint8_t *pDivInput,
    uint8_t bDivInputLen, uint8_t *pSecretKey, uint8_t *pSecretKeyLen)
{
  phStatus_t	PH_MEMLOC_REM wStatus = 0;
  uint8_t		PH_MEMLOC_REM aCmdBuf[PHHAL_HW_SAMAV3_ISO7816_HEADER_LENGTH +
                                            2 /* Key number and version */];
  uint8_t		*PH_MEMLOC_REM pResponse = NULL;
  uint16_t	PH_MEMLOC_REM wRespLen = 0;

  /* Parameter validation. */
  PH_ASSERT_NULL_DATA_PARAM(pDataParams, PH_COMP_HAL);
  PH_ASSERT_NULL_PARAM(pSecretKey, PH_COMP_HAL);
  PH_ASSERT_NULL_PARAM(pSecretKeyLen, PH_COMP_HAL);
  if (bDivInputLen) {
    PH_ASSERT_NULL_PARAM(pDivInput, PH_COMP_HAL);
  }

  /* Frame Cmd.SAM_DumpSecretKey command information. */
  aCmdBuf[PHHAL_HW_SAMAV3_ISO7816_CLA_POS] = PHHAL_HW_SAMAV3_ISO7816_CLA_BYTE;
  aCmdBuf[PHHAL_HW_SAMAV3_ISO7816_INS_POS] = PHHAL_HW_SAMAV3_CMD_SAM_DUMP_SECRET_KEY_INS;
  aCmdBuf[PHHAL_HW_SAMAV3_ISO7816_P1_POS]  = bDumpMode;
  aCmdBuf[PHHAL_HW_SAMAV3_ISO7816_P2_POS]  = PHHAL_HW_SAMAV3_ISO7816_DEFAULT_P2_BYTE;
  aCmdBuf[PHHAL_HW_SAMAV3_ISO7816_LC_POS]  = (uint8_t)(2 /* Key number and version */ +
          bDivInputLen);

  /* Add key number and version to command buffer. */
  aCmdBuf[PHHAL_HW_SAMAV3_ISO7816_LC_POS + 1] = bKeyNo;
  aCmdBuf[PHHAL_HW_SAMAV3_ISO7816_LC_POS + 2] = bKeyVer;

  /* Buffer the command information to exchange buffer. */
  PH_CHECK_SUCCESS_FCT(wStatus, phhalHw_SamAV3_Cmd_7816Exchange(
          pDataParams,
          PH_EXCHANGE_BUFFER_FIRST,
          aCmdBuf,
          (PHHAL_HW_SAMAV3_ISO7816_HEADER_LENGTH + 2),
          NULL,
          NULL));

  /* Buffer diversification input to exchange buffer. */
  PH_CHECK_SUCCESS_FCT(wStatus, phhalHw_SamAV3_Cmd_7816Exchange(
          pDataParams,
          PH_EXCHANGE_BUFFER_CONT,
          pDivInput,
          bDivInputLen,
          NULL,
          NULL));

  /* Buffer Le to exchange buffer and exchange the bufferred information to Sam hardware. */
  PH_CHECK_SUCCESS_FCT(wStatus, phhalHw_SamAV3_Cmd_7816Exchange(
          pDataParams,
          PH_EXCHANGE_BUFFER_LAST,
          gaDefaultLe,
          1,
          &pResponse,
          &wRespLen));

  /* Copy the response to the parameters. */
  memcpy(pSecretKey, pResponse, wRespLen); /* PRQA S 3200 */
  *pSecretKeyLen = (uint8_t) wRespLen;

  return PH_ADD_COMPCODE(PH_ERR_SUCCESS, PH_COMP_HAL);
}

phStatus_t
phhalHw_SamAV3_Cmd_SAM_DisableKeyEntry(phhalHw_SamAV3_DataParams_t *pDataParams, uint8_t bKeyNo,
    uint8_t *pOfflineCrypto, uint8_t bCryptoLen)
{
  phStatus_t	PH_MEMLOC_REM wStatus = 0;
  uint8_t		PH_MEMLOC_REM aCmdBuf[PHHAL_HW_SAMAV3_ISO7816_HEADER_LENGTH];
  uint8_t 	*PH_MEMLOC_REM pResponse = NULL;
  uint16_t	PH_MEMLOC_REM wRespLen = 0;

  /* Parameter validation. */
  PH_ASSERT_NULL_DATA_PARAM(pDataParams, PH_COMP_HAL);
  if (bCryptoLen) {
    PH_ASSERT_NULL_PARAM(pOfflineCrypto, PH_COMP_HAL);
  }

  /* Filling in ISO7816 header */
  aCmdBuf[PHHAL_HW_SAMAV3_ISO7816_CLA_POS] = PHHAL_HW_SAMAV3_ISO7816_CLA_BYTE;
  aCmdBuf[PHHAL_HW_SAMAV3_ISO7816_INS_POS] = PHHAL_HW_SAMAV3_CMD_SAM_DISABLE_KEY_ENTRY_INS;
  aCmdBuf[PHHAL_HW_SAMAV3_ISO7816_P1_POS]  = bKeyNo;
  aCmdBuf[PHHAL_HW_SAMAV3_ISO7816_P2_POS]  = PHHAL_HW_SAMAV3_ISO7816_DEFAULT_P2_BYTE;

  /* Add Crypto information to exchange buffer if available. */
  if (bCryptoLen) {
    /* Add Lc to command buffer. */
    aCmdBuf[PHHAL_HW_SAMAV3_ISO7816_LC_POS] = bCryptoLen;

    /* Buffer the command information to exchange buffer. */
    PH_CHECK_SUCCESS_FCT(wStatus, phhalHw_SamAV3_Cmd_7816Exchange(
            pDataParams,
            PH_EXCHANGE_BUFFER_FIRST,
            aCmdBuf,
            PHHAL_HW_SAMAV3_ISO7816_HEADER_LENGTH,
            NULL,
            NULL));

    /* Buffer crypto information to exchange buffer and exchange the bufferred information to Sam hardware. */
    PH_CHECK_SUCCESS_FCT(wStatus, phhalHw_SamAV3_Cmd_7816Exchange(
            pDataParams,
            PH_EXCHANGE_BUFFER_LAST,
            pOfflineCrypto,
            bCryptoLen,
            &pResponse,
            &wRespLen));
  } else {
    /* Exchange with lower layer */
    PH_CHECK_SUCCESS_FCT(wStatus, phhalHw_SamAV3_Cmd_7816Exchange(
            pDataParams,
            PH_EXCHANGE_DEFAULT,
            aCmdBuf,
            PHHAL_HW_SAMAV3_ISO7816_HEADER_NO_LC_LENGTH,
            &pResponse,
            &wRespLen));
  }

  /* Reset Authentication states if ChangeKey = AuthKey. */
  if (pDataParams->bKeyNo == bKeyNo) {
    /* Perform Kill Authentication. */
    PH_CHECK_SUCCESS_FCT(wStatus, phhalHw_SamAV3_Cmd_SAM_KillAuthentication(pDataParams,
            PHHAL_HW_SAMAV3_CMD_SAM_KILL_AUTHENTICATION_FULL));

    /* Invalidate the session keys and set the SM to PLAIN. */
    pDataParams->bAuthType = PHHAL_HW_SAMAV3_CMD_SAM_AUTHENTICATE_HOST_MODE_PLAIN;
    PH_CHECK_SUCCESS_FCT(wStatus, phCryptoSym_InvalidateKey(pDataParams->pENCCryptoDataParams));
    PH_CHECK_SUCCESS_FCT(wStatus, phCryptoSym_InvalidateKey(pDataParams->pMACCryptoDataParams));
  }

  return PH_ADD_COMPCODE(PH_ERR_SUCCESS, PH_COMP_HAL);
}

phStatus_t
phhalHw_SamAV3_Cmd_SAM_DisableKeyEntryOffline(phhalHw_SamAV3_DataParams_t *pDataParams,
    uint8_t bKeyNo, uint16_t wChangeCtr, uint8_t *pOfflineCrypto,
    uint8_t bOfflineCryptoLen, uint8_t bEnableOfflineAck, uint8_t *pOfflineAck)
{
  phStatus_t	PH_MEMLOC_REM wStatus = 0;
  uint8_t		PH_MEMLOC_REM aCmdBuf[PHHAL_HW_SAMAV3_ISO7816_HEADER_LENGTH + 2 /* ChangeCtr */];
  uint8_t		PH_MEMLOC_REM bCmdLen = 0;
  uint8_t 	*PH_MEMLOC_REM pResponse = NULL;
  uint16_t	PH_MEMLOC_REM wRespLen = 0;

  /* Parameter validation. */
  PH_ASSERT_NULL_DATA_PARAM(pDataParams, PH_COMP_HAL);
  PH_ASSERT_NULL_PARAM(pOfflineCrypto, PH_COMP_HAL);
  if (bEnableOfflineAck) {
    PH_ASSERT_NULL_PARAM(pOfflineAck, PH_COMP_HAL);
  }

  /* Reset the command buffer. */
  memset(aCmdBuf, 0, sizeof(aCmdBuf));  /* PRQA S 3200 */

  /* Frame Cmd.SAM_DisableKeyEntryOffline command information. */
  aCmdBuf[bCmdLen++] = PHHAL_HW_SAMAV3_ISO7816_CLA_BYTE;
  aCmdBuf[bCmdLen++] = PHHAL_HW_SAMAV3_CMD_SAM_DISABLE_KEY_ENTRY_INS;
  aCmdBuf[bCmdLen++] = bKeyNo;
  aCmdBuf[bCmdLen++] = PHHAL_HW_SAMAV3_ISO7816_DEFAULT_P2_BYTE;
  aCmdBuf[bCmdLen++] = PHHAL_HW_SAMAV3_ISO7816_DEFAULT_LC_BYTE;

  /* Add Change counter. */
  aCmdBuf[bCmdLen++] = (uint8_t)((wChangeCtr & 0xFF00) >> 8);
  aCmdBuf[bCmdLen++] = (uint8_t)(wChangeCtr & 0x00FF);

  /* Buffer the command information to exchange buffer. */
  PH_CHECK_SUCCESS_FCT(wStatus, phhalHw_SamAV3_Cmd_7816Exchange(
          pDataParams,
          PH_EXCHANGE_BUFFER_FIRST,
          aCmdBuf,
          bCmdLen,
          NULL,
          NULL));

  /* Buffer offline crypto information to exchange buffer. */
  PH_CHECK_SUCCESS_FCT(wStatus, phhalHw_SamAV3_Cmd_7816Exchange(
          pDataParams,
          PH_EXCHANGE_BUFFER_CONT,
          pOfflineCrypto,
          bOfflineCryptoLen,
          NULL,
          NULL));

  /* Update LC. */
  PH_CHECK_SUCCESS_FCT(wStatus, phhalHw_SamAV3_Utils_UpdateLc(pDataParams));

  /* Exchange the bufferred inforamtion to Sam hardware. */
  PH_CHECK_SUCCESS_FCT(wStatus, phhalHw_SamAV3_Cmd_7816Exchange(
          pDataParams,
          PH_EXCHANGE_BUFFER_LAST,
          gaDefaultLe,
          (uint8_t)((bEnableOfflineAck) ? 1 : 0),
          &pResponse,
          &wRespLen));

  memcpy(pOfflineAck, pResponse, wRespLen); /* PRQA S 3200 */

  /* Reset Authentication states if ChangeKey = AuthKey. */
  if (pDataParams->bKeyNo == bKeyNo) {
    /* Perform Kill Authentication. */
    PH_CHECK_SUCCESS_FCT(wStatus, phhalHw_SamAV3_Cmd_SAM_KillAuthentication(pDataParams,
            PHHAL_HW_SAMAV3_CMD_SAM_KILL_AUTHENTICATION_FULL));

    /* Invalidate the session keys and set the SM to PLAIN. */
    pDataParams->bAuthType = PHHAL_HW_SAMAV3_CMD_SAM_AUTHENTICATE_HOST_MODE_PLAIN;
    PH_CHECK_SUCCESS_FCT(wStatus, phCryptoSym_InvalidateKey(pDataParams->pENCCryptoDataParams));
    PH_CHECK_SUCCESS_FCT(wStatus, phCryptoSym_InvalidateKey(pDataParams->pMACCryptoDataParams));
  }

  return PH_ADD_COMPCODE(PH_ERR_SUCCESS, PH_COMP_HAL);
}

phStatus_t
phhalHw_SamAV3_Cmd_SAM_EncipherKeyEntry(phhalHw_SamAV3_DataParams_t *pDataParams,
    uint8_t bPersoKeyNo, uint8_t bKeyNo, uint8_t bOption, uint16_t wPersoCtr,
    uint8_t *pDivInput, uint8_t bDivInputLen, uint8_t *pOfflineCryptogram,
    uint8_t *pOfflineCryptogramLen)
{
  phStatus_t	PH_MEMLOC_REM wStatus = 0;
  uint8_t		PH_MEMLOC_REM aCmdBuf[PHHAL_HW_SAMAV3_ISO7816_HEADER_LENGTH +
                                            4 /* Logical Channel, KeyNo, Perso Counter*/];
  uint8_t		PH_MEMLOC_REM bCmdLen = 0;
  uint8_t 	*PH_MEMLOC_REM pResponse = NULL;
  uint16_t	PH_MEMLOC_REM wRespLen = 0;

  /* Parameter validation. */
  PH_ASSERT_NULL_DATA_PARAM(pDataParams, PH_COMP_HAL);
  PH_ASSERT_NULL_PARAM(pOfflineCryptogram, PH_COMP_HAL);
  PH_ASSERT_NULL_PARAM(pOfflineCryptogramLen, PH_COMP_HAL);
  if (bOption & PHHAL_HW_SAMAV3_CMD_SAM_ENCIPHER_KEY_ENTRY_DIV_ON) {
    PH_ASSERT_NULL_PARAM(pDivInput, PH_COMP_HAL);
  }

  /* Frame Cmd.SAM_EncipherKeyEntry command information. */
  aCmdBuf[bCmdLen++] = PHHAL_HW_SAMAV3_ISO7816_CLA_BYTE;
  aCmdBuf[bCmdLen++] = PHHAL_HW_SAMAV3_CMD_SAM_ENCHIPHER_KEY_ENTRY_INS;
  aCmdBuf[bCmdLen++] = bPersoKeyNo;
  aCmdBuf[bCmdLen++] = bOption;
  aCmdBuf[bCmdLen++] = PHHAL_HW_SAMAV3_ISO7816_DEFAULT_LC_BYTE;

  /* Add payload information to command buffer. */
  aCmdBuf[bCmdLen++] = (uint8_t)(0x80 | pDataParams->bLogicalChannel);
  aCmdBuf[bCmdLen++] = bKeyNo;
  aCmdBuf[bCmdLen++] = (uint8_t)((wPersoCtr & 0xFF00) >> 8);
  aCmdBuf[bCmdLen++] = (uint8_t)(wPersoCtr & 0x00FF);

  /* Buffer the command information to exchange buffer. */
  PH_CHECK_SUCCESS_FCT(wStatus, phhalHw_SamAV3_Cmd_7816Exchange(
          pDataParams,
          PH_EXCHANGE_BUFFER_FIRST,
          aCmdBuf,
          bCmdLen,
          NULL,
          NULL));

  /* Buffer Sam UID to exchange buffer. */
  if (bOption & PHHAL_HW_SAMAV3_CMD_SAM_ENCIPHER_KEY_ENTRY_SAM_UID_ON) {
    /* Exchange SAM UID as first part data with lower layer */
    PH_CHECK_SUCCESS_FCT(wStatus, phhalHw_SamAV3_Cmd_7816Exchange(
            pDataParams,
            PH_EXCHANGE_BUFFER_CONT,
            pDataParams->bUid,
            PHHAL_HW_SAMAV3_HC_SAM_UID_SIZE, /* SAM UID Length i.e. 0x07 bytes */
            NULL,
            NULL));
  }

  /* Buffer Diversification input to exchange buffer. */
  PH_CHECK_SUCCESS_FCT(wStatus, phhalHw_SamAV3_Cmd_7816Exchange(
          pDataParams,
          PH_EXCHANGE_BUFFER_CONT,
          pDivInput,
          bDivInputLen,
          NULL,
          NULL));

  /* Update LC. */
  PH_CHECK_SUCCESS_FCT(wStatus, phhalHw_SamAV3_Utils_UpdateLc(pDataParams));

  /* Buffer Le to exchange buffer and exchange the bufferred information to Sam hardware. */
  PH_CHECK_SUCCESS_FCT(wStatus, phhalHw_SamAV3_Cmd_7816Exchange(
          pDataParams,
          PH_EXCHANGE_BUFFER_LAST,
          gaDefaultLe,
          1,
          &pResponse,
          &wRespLen));

  /* Copy the response to parameters. */
  memcpy(pOfflineCryptogram, pResponse, wRespLen); /* PRQA S 3200 */
  *pOfflineCryptogramLen = (uint8_t) wRespLen;

  return PH_ADD_COMPCODE(PH_ERR_SUCCESS, PH_COMP_HAL);
}

phStatus_t
phhalHw_SamAV3_Cmd_SAM_DeriveKey(phhalHw_SamAV3_DataParams_t *pDataParams, uint8_t bSrcKeyNo,
    uint8_t bSrcKeyVer, uint8_t bDstKeyNo, uint8_t *pDeriveIn,
    uint8_t bDeriveInLen)
{
  phStatus_t	PH_MEMLOC_REM wStatus = 0;
  uint8_t		PH_MEMLOC_REM aCmdBuf[PHHAL_HW_SAMAV3_ISO7816_HEADER_LENGTH + 3 /* Key information */];
  uint8_t		PH_MEMLOC_REM bCmdLen = 0;
  uint8_t 	*PH_MEMLOC_REM pResponse = NULL;
  uint16_t	PH_MEMLOC_REM wRespLen = 0;

  /* Parameter validation. */
  PH_ASSERT_NULL_DATA_PARAM(pDataParams, PH_COMP_HAL);
  PH_ASSERT_NULL_PARAM(pDeriveIn, PH_COMP_HAL);

  /* Frame Cmd.SAM_DeriveKey command information. */
  aCmdBuf[bCmdLen++] = PHHAL_HW_SAMAV3_ISO7816_CLA_BYTE;
  aCmdBuf[bCmdLen++] = PHHAL_HW_SAMAV3_CMD_SAM_DERIVE_KEY_INS;
  aCmdBuf[bCmdLen++] = PHHAL_HW_SAMAV3_ISO7816_DEFAULT_P1_BYTE;
  aCmdBuf[bCmdLen++] = PHHAL_HW_SAMAV3_ISO7816_DEFAULT_P2_BYTE;
  aCmdBuf[bCmdLen++] = PHHAL_HW_SAMAV3_ISO7816_DEFAULT_LC_BYTE;

  /* Add payload information to command buffer. */
  aCmdBuf[bCmdLen++] = bSrcKeyNo;
  aCmdBuf[bCmdLen++] = bSrcKeyVer;
  aCmdBuf[bCmdLen++] = bDstKeyNo;

  /* Buffer the command information to exchange buffer. */
  PH_CHECK_SUCCESS_FCT(wStatus, phhalHw_SamAV3_Cmd_7816Exchange(
          pDataParams,
          PH_EXCHANGE_BUFFER_FIRST,
          aCmdBuf,
          bCmdLen,
          NULL,
          NULL));

  /* Buffer Derivation input to exchange buffer. */
  PH_CHECK_SUCCESS_FCT(wStatus, phhalHw_SamAV3_Cmd_7816Exchange(
          pDataParams,
          PH_EXCHANGE_BUFFER_CONT,
          pDeriveIn,
          bDeriveInLen,
          NULL,
          NULL));

  /* Update LC. */
  PH_CHECK_SUCCESS_FCT(wStatus, phhalHw_SamAV3_Utils_UpdateLc(pDataParams));

  /* Exchange the bufferred information to Sam hardware. */
  PH_CHECK_SUCCESS_FCT(wStatus, phhalHw_SamAV3_Cmd_7816Exchange(
          pDataParams,
          PH_EXCHANGE_BUFFER_LAST,
          NULL,
          0,
          &pResponse,
          &wRespLen));

  return PH_ADD_COMPCODE(PH_ERR_SUCCESS, PH_COMP_HAL);
}

phStatus_t
phhalHw_SamAV3_Cmd_SAM_GenerateMFCLicMAC(phhalHw_SamAV3_DataParams_t *pDataParams,
    uint8_t bOption, uint8_t bInputLen, uint8_t *pInput, uint8_t bKeyCount,
    uint8_t *pMFCSectorKeys, uint8_t *pMFUID, uint8_t *pMFCLicMAC)
{
  phStatus_t	PH_MEMLOC_REM wStatus = 0;
  uint8_t		PH_MEMLOC_REM aCmdBuf[PHHAL_HW_SAMAV3_ISO7816_HEADER_LENGTH];
  uint8_t 	*PH_MEMLOC_REM pResponse = NULL;
  uint16_t	PH_MEMLOC_REM wRespLen = 0;

  /* Parameter validation. */
  PH_ASSERT_NULL_DATA_PARAM(pDataParams, PH_COMP_HAL);
  PH_ASSERT_NULL_PARAM(pInput, PH_COMP_HAL);
  PH_ASSERT_NULL_PARAM(pMFCSectorKeys, PH_COMP_HAL);
  PH_ASSERT_NULL_PARAM(pMFCLicMAC, PH_COMP_HAL);

  /* Frame Cmd.SAM_Generate_MFCLicMAC command information. */
  aCmdBuf[PHHAL_HW_SAMAV3_ISO7816_CLA_POS] = PHHAL_HW_SAMAV3_ISO7816_CLA_BYTE;
  aCmdBuf[PHHAL_HW_SAMAV3_ISO7816_INS_POS] = PHHAL_HW_SAMAV3_CMD_SAM_GENERATE_MFC_LIC_MAC;
  aCmdBuf[PHHAL_HW_SAMAV3_ISO7816_P1_POS]	 = bOption;
  aCmdBuf[PHHAL_HW_SAMAV3_ISO7816_P2_POS]  = PHHAL_HW_SAMAV3_ISO7816_DEFAULT_P2_BYTE;
  aCmdBuf[PHHAL_HW_SAMAV3_ISO7816_LC_POS]  = PHHAL_HW_SAMAV3_ISO7816_DEFAULT_LC_BYTE;

  /* Buffer the command information to exchange buffer. */
  PH_CHECK_SUCCESS_FCT(wStatus, phhalHw_SamAV3_Cmd_7816Exchange(
          pDataParams,
          PH_EXCHANGE_BUFFER_FIRST,
          aCmdBuf,
          PHHAL_HW_SAMAV3_ISO7816_HEADER_LENGTH,
          NULL,
          NULL));

  /* Buffer the Length information to exchange buffer. */
  PH_CHECK_SUCCESS_FCT(wStatus, phhalHw_SamAV3_Cmd_7816Exchange(
          pDataParams,
          PH_EXCHANGE_BUFFER_CONT,
          &bInputLen,
          1,
          NULL,
          NULL));

  /* Buffer the InputLength buffer information to exchange buffer. */
  PH_CHECK_SUCCESS_FCT(wStatus, phhalHw_SamAV3_Cmd_7816Exchange(
          pDataParams,
          PH_EXCHANGE_BUFFER_CONT,
          pInput,
          bInputLen,
          NULL,
          NULL));

  /* Buffer the KeyCount information to exchange buffer. */
  PH_CHECK_SUCCESS_FCT(wStatus, phhalHw_SamAV3_Cmd_7816Exchange(
          pDataParams,
          PH_EXCHANGE_BUFFER_CONT,
          &bKeyCount,
          1,
          NULL,
          NULL));

  /* Buffer the MFCSectorKeys buffer information to exchange buffer. */
  PH_CHECK_SUCCESS_FCT(wStatus, phhalHw_SamAV3_Cmd_7816Exchange(
          pDataParams,
          PH_EXCHANGE_BUFFER_CONT,
          pMFCSectorKeys,
          bKeyCount,
          NULL,
          NULL));

  /* Buffer the MFUID buffer information to exchange buffer. */
  PH_CHECK_SUCCESS_FCT(wStatus, phhalHw_SamAV3_Cmd_7816Exchange(
          pDataParams,
          PH_EXCHANGE_BUFFER_CONT,
          pMFUID,
          (uint16_t)((pMFUID == NULL) ? 0 : 4),
          NULL,
          NULL));

  /* Update LC. */
  PH_CHECK_SUCCESS_FCT(wStatus, phhalHw_SamAV3_Utils_UpdateLc(pDataParams));

  /* Exchange the bufferred inforamtion to SAM hardware. */
  PH_CHECK_SUCCESS_FCT(wStatus, phhalHw_SamAV3_Cmd_7816Exchange(
          pDataParams,
          PH_EXCHANGE_BUFFER_LAST,
          NULL,
          0,
          &pResponse,
          &wRespLen));

  /* Copy the response to the parameter. */
  memcpy(pMFCLicMAC, pResponse, wRespLen); /* PRQA S 3200 */

  return PH_ADD_COMPCODE(PH_ERR_SUCCESS, PH_COMP_HAL);
}

/*************************************************************************************************************************/
/**************************************************** Data Processing ****************************************************/
/*************************************************************************************************************************/

phStatus_t
phhalHw_SamAV3_Cmd_SAM_ApplySM(phhalHw_SamAV3_DataParams_t *pDataParams, uint16_t wOption,
    uint8_t bCommMode, uint8_t bOffset, uint8_t bCmdCtrIncr,
    uint8_t *pTxData, uint8_t bTxDataLen, uint8_t **ppRxData, uint16_t *pRxDataLen)
{
  phStatus_t	PH_MEMLOC_REM wStatus = 0;
  uint8_t		PH_MEMLOC_REM aCmdBuf[PHHAL_HW_SAMAV3_ISO7816_HEADER_LENGTH + 2];
  uint8_t		PH_MEMLOC_REM bCmdLen = 0;

  /* Parameter validation. */
  PH_ASSERT_NULL_DATA_PARAM(pDataParams, PH_COMP_HAL);
  if (bTxDataLen) {
    PH_ASSERT_NULL_PARAM(pTxData, PH_COMP_HAL);
  }
  PH_ASSERT_NULL_PARAM(pRxDataLen, PH_COMP_HAL);

  if (!(wOption & PH_EXCHANGE_LEAVE_BUFFER_BIT)) {
    /* Reset the command buffer and its length variable. */
    bCmdLen = 0;
    memset(aCmdBuf, 0, sizeof(aCmdBuf));  /* PRQA S 3200 */

    /* Frame Cmd.SAM_ApplySM command information. */
    aCmdBuf[bCmdLen++] = PHHAL_HW_SAMAV3_ISO7816_CLA_BYTE;
    aCmdBuf[bCmdLen++] = PHHAL_HW_SAMAV3_CMD_SAM_APPLY_SM_INS;
    aCmdBuf[bCmdLen++] = PHHAL_HW_SAMAV3_ISO7816_LAST_FRAME;
    aCmdBuf[bCmdLen++] = bCommMode;
    aCmdBuf[bCmdLen++] = bTxDataLen;

    /* Update P1 byte. */
    if (wOption & PH_EXCHANGE_TXCHAINING) {
      aCmdBuf[PHHAL_HW_SAMAV3_ISO7816_P1_POS] = PHHAL_HW_SAMAV3_ISO7816_CHAINED_FRAME;
    }

    /* Add Offset to command buffer. */
    if ((bCommMode == PHHAL_HW_SAMAV3_CMD_APPLY_REMOVE_SM_COMM_MODE_FULL) &&
        (wOption & PHHAL_HW_SAMAV3_CMD_APPLY_SM_INCLUDE_OFFSET)) {
      aCmdBuf[bCmdLen++] = bOffset;
    }

    /* Add Command Counter to command buffer. */
    if (bCommMode == PHHAL_HW_SAMAV3_CMD_APPLY_SM_COMM_MODE_PLAIN) {
      aCmdBuf[bCmdLen++] = bCmdCtrIncr;
    }

    /* Buffer command information to exchange buffer. */
    PH_CHECK_SUCCESS_FCT(wStatus, phhalHw_SamAV3_Cmd_7816Exchange(
            pDataParams,
            PH_EXCHANGE_BUFFER_FIRST,
            aCmdBuf,
            bCmdLen,
            NULL,
            NULL));
  }

  /* Buffer data to exchange buffer. */
  PH_CHECK_SUCCESS_FCT(wStatus, phhalHw_SamAV3_Cmd_7816Exchange(
          pDataParams,
          PH_EXCHANGE_BUFFER_CONT,
          pTxData,
          bTxDataLen,
          NULL,
          NULL));

  /* Update LC. */
  PH_CHECK_SUCCESS_FCT(wStatus, phhalHw_SamAV3_Utils_UpdateLc(pDataParams));

  /* Buffer LE and exchange the bufferred informatation to SAM hardware. */
  if (!(wOption & PH_EXCHANGE_BUFFERED_BIT)) {
    wStatus = phhalHw_SamAV3_Cmd_7816Exchange(
            pDataParams,
            PH_EXCHANGE_BUFFER_LAST,
            gaDefaultLe,
            1,
            ppRxData,
            pRxDataLen);

    /* Check status. */
    if ((wStatus & PH_ERR_MASK) == PHHAL_HW_SAMAV3_ERR_OK_CHAINING_ACTIVE) {
      wStatus = PH_ADD_COMPCODE(PH_ERR_SUCCESS_CHAINING, PH_COMP_HAL);
    }
  }

  return wStatus;
}

phStatus_t
phhalHw_SamAV3_Cmd_SAM_RemoveSM(phhalHw_SamAV3_DataParams_t *pDataParams, uint16_t wOption,
    uint8_t bCommMode, uint8_t *pTxData, uint8_t bTxDataLen,
    uint8_t **ppRxData, uint16_t *pRxDataLen)
{
  phStatus_t	PH_MEMLOC_REM wStatus = 0;
  uint8_t		PH_MEMLOC_REM aCmdBuf[PHHAL_HW_SAMAV3_ISO7816_HEADER_LENGTH];

  /* Parameter validation. */
  PH_ASSERT_NULL_DATA_PARAM(pDataParams, PH_COMP_HAL);
  if (bTxDataLen) {
    PH_ASSERT_NULL_PARAM(pTxData, PH_COMP_HAL);
  }

  if (!(wOption & PH_EXCHANGE_LEAVE_BUFFER_BIT)) {
    /* Reset the command buffer. */
    memset(aCmdBuf, 0, sizeof(aCmdBuf));  /* PRQA S 3200 */

    /* Frame Cmd.SAM_RemoveSM command information. */
    aCmdBuf[PHHAL_HW_SAMAV3_ISO7816_CLA_POS] = PHHAL_HW_SAMAV3_ISO7816_CLA_BYTE;
    aCmdBuf[PHHAL_HW_SAMAV3_ISO7816_INS_POS] = PHHAL_HW_SAMAV3_CMD_SAM_REMOVE_SM_INS;
    aCmdBuf[PHHAL_HW_SAMAV3_ISO7816_P1_POS]  = PHHAL_HW_SAMAV3_ISO7816_LAST_FRAME;
    aCmdBuf[PHHAL_HW_SAMAV3_ISO7816_P2_POS]  = bCommMode;
    aCmdBuf[PHHAL_HW_SAMAV3_ISO7816_LC_POS]  = bTxDataLen;

    /* Update P1 byte. */
    if (wOption & PH_EXCHANGE_TXCHAINING) {
      aCmdBuf[PHHAL_HW_SAMAV3_ISO7816_P1_POS] = PHHAL_HW_SAMAV3_ISO7816_CHAINED_FRAME;
    }

    /* Buffer command information to exchange buffer. */
    PH_CHECK_SUCCESS_FCT(wStatus, phhalHw_SamAV3_Cmd_7816Exchange(
            pDataParams,
            PH_EXCHANGE_BUFFER_FIRST,
            aCmdBuf,
            PHHAL_HW_SAMAV3_ISO7816_HEADER_LENGTH,
            NULL,
            NULL));
  }

  /* Buffer data to exchange buffer. */
  PH_CHECK_SUCCESS_FCT(wStatus, phhalHw_SamAV3_Cmd_7816Exchange(
          pDataParams,
          PH_EXCHANGE_BUFFER_CONT,
          pTxData,
          bTxDataLen,
          NULL,
          NULL));

  /* Update LC. */
  PH_CHECK_SUCCESS_FCT(wStatus, phhalHw_SamAV3_Utils_UpdateLc(pDataParams));

  /* Buffer LE and exchange the bufferred informatation to SAM hardware. */
  if (!(wOption & PH_EXCHANGE_BUFFERED_BIT)) {
    wStatus = phhalHw_SamAV3_Cmd_7816Exchange(
            pDataParams,
            PH_EXCHANGE_BUFFER_LAST,
            gaDefaultLe,
            1,
            ppRxData,
            pRxDataLen);

    /* Check status. */
    if ((wStatus & PH_ERR_MASK) == PHHAL_HW_SAMAV3_ERR_OK_CHAINING_ACTIVE) {
      wStatus = PH_ADD_COMPCODE(PH_ERR_SUCCESS_CHAINING, PH_COMP_HAL);
    }
  }

  return wStatus;
}

phStatus_t
phhalHw_SamAV3_Cmd_SAM_VerifyMAC(phhalHw_SamAV3_DataParams_t *pDataParams, uint16_t wOption,
    uint8_t bNum, uint8_t *pTxData, uint8_t bTxDataLen)
{
  phStatus_t	PH_MEMLOC_REM wStatus = 0;
  uint8_t		PH_MEMLOC_REM aCmdBuf[PHHAL_HW_SAMAV3_ISO7816_HEADER_LENGTH];
  uint8_t		*PH_MEMLOC_REM pResponse = NULL;
  uint16_t	PH_MEMLOC_REM wRespLen = 0;

  /* Parameter validation. */
  PH_ASSERT_NULL_DATA_PARAM(pDataParams, PH_COMP_HAL);

  if (!(wOption & PH_EXCHANGE_LEAVE_BUFFER_BIT)) {
    /* Reset the command buffer. */
    memset(aCmdBuf, 0, sizeof(aCmdBuf));  /* PRQA S 3200 */

    /* Frame Cmd.SAM_VerifyMAC command information. */
    aCmdBuf[PHHAL_HW_SAMAV3_ISO7816_CLA_POS] = PHHAL_HW_SAMAV3_ISO7816_CLA_BYTE;
    aCmdBuf[PHHAL_HW_SAMAV3_ISO7816_INS_POS] = PHHAL_HW_SAMAV3_CMD_SAM_VERIFY_MAC_INS;
    aCmdBuf[PHHAL_HW_SAMAV3_ISO7816_P1_POS]  = PHHAL_HW_SAMAV3_ISO7816_LAST_FRAME;
    aCmdBuf[PHHAL_HW_SAMAV3_ISO7816_P2_POS]  = bNum;
    aCmdBuf[PHHAL_HW_SAMAV3_ISO7816_LC_POS]  = bTxDataLen;

    /* Update P1 byte. */
    if (wOption & PH_EXCHANGE_TXCHAINING) {
      aCmdBuf[PHHAL_HW_SAMAV3_ISO7816_P1_POS] = PHHAL_HW_SAMAV3_ISO7816_CHAINED_FRAME;
    }

    /* Buffer command information to exchange buffer. */
    PH_CHECK_SUCCESS_FCT(wStatus, phhalHw_SamAV3_Cmd_7816Exchange(
            pDataParams,
            PH_EXCHANGE_BUFFER_FIRST,
            aCmdBuf,
            PHHAL_HW_SAMAV3_ISO7816_HEADER_LENGTH,
            NULL,
            NULL));
  }

  /* Buffer data to exchange buffer. */
  PH_CHECK_SUCCESS_FCT(wStatus, phhalHw_SamAV3_Cmd_7816Exchange(
          pDataParams,
          PH_EXCHANGE_BUFFER_CONT,
          pTxData,
          bTxDataLen,
          NULL,
          NULL));

  /* Update LC. */
  PH_CHECK_SUCCESS_FCT(wStatus, phhalHw_SamAV3_Utils_UpdateLc(pDataParams));

  /* Exchange the bufferred informatation to SAM hardware. */
  if (!(wOption & PH_EXCHANGE_BUFFERED_BIT)) {
    wStatus = phhalHw_SamAV3_Cmd_7816Exchange(
            pDataParams,
            PH_EXCHANGE_BUFFER_LAST,
            NULL,
            0,
            &pResponse,
            &wRespLen);

    /* Check status. */
    if ((wStatus & PH_ERR_MASK) == PHHAL_HW_SAMAV3_ERR_OK_CHAINING_ACTIVE) {
      wStatus = PH_ADD_COMPCODE(PH_ERR_SUCCESS_CHAINING, PH_COMP_HAL);
    }
  }

  return wStatus;
}

phStatus_t
phhalHw_SamAV3_Cmd_SAM_GenerateMAC(phhalHw_SamAV3_DataParams_t *pDataParams, uint16_t wOption,
    uint8_t bNum, uint8_t *pTxData, uint8_t bTxDataLen,
    uint8_t **ppRxData, uint16_t *pRxDataLen)
{
  phStatus_t	PH_MEMLOC_REM wStatus = 0;
  uint8_t		PH_MEMLOC_REM aCmdBuf[PHHAL_HW_SAMAV3_ISO7816_HEADER_LENGTH];
  uint8_t		PH_MEMLOC_REM bCmdLen = 0;

  /* Parameter validation. */
  PH_ASSERT_NULL_DATA_PARAM(pDataParams, PH_COMP_HAL);
  if (bTxDataLen) {
    PH_ASSERT_NULL_PARAM(pTxData, PH_COMP_HAL);
  }
  if (!(wOption & PH_EXCHANGE_BUFFERED_BIT)) {
    PH_ASSERT_NULL_PARAM(pRxDataLen, PH_COMP_HAL);
  }

  if (!(wOption & PH_EXCHANGE_LEAVE_BUFFER_BIT)) {
    /* Reset the command buffer. */
    memset(aCmdBuf, 0, sizeof(aCmdBuf));  /* PRQA S 3200 */

    /* Frame Cmd.SAM_GenerateMAC command information. */
    aCmdBuf[bCmdLen++] = PHHAL_HW_SAMAV3_ISO7816_CLA_BYTE;
    aCmdBuf[bCmdLen++] = PHHAL_HW_SAMAV3_CMD_SAM_GENERATE_MAC_INS;
    aCmdBuf[bCmdLen++]  = PHHAL_HW_SAMAV3_ISO7816_LAST_FRAME;
    aCmdBuf[bCmdLen++]  = bNum;

    /* Append LC only if data is available. */
    if ((wOption & PHHAL_HW_SAMAV3_GENERATE_MAC_INCLUDE_LC) || bTxDataLen) {
      aCmdBuf[bCmdLen++]  = bTxDataLen;
    }

    /* Update P1 byte. */
    if (wOption & PH_EXCHANGE_TXCHAINING) {
      aCmdBuf[PHHAL_HW_SAMAV3_ISO7816_P1_POS] = PHHAL_HW_SAMAV3_ISO7816_CHAINED_FRAME;
    }

    /* Buffer command information to exchange buffer. */
    PH_CHECK_SUCCESS_FCT(wStatus, phhalHw_SamAV3_Cmd_7816Exchange(
            pDataParams,
            PH_EXCHANGE_BUFFER_FIRST,
            aCmdBuf,
            bCmdLen,
            NULL,
            NULL));
  }

  /* Buffer data to exchange buffer. */
  PH_CHECK_SUCCESS_FCT(wStatus, phhalHw_SamAV3_Cmd_7816Exchange(
          pDataParams,
          PH_EXCHANGE_BUFFER_CONT,
          pTxData,
          bTxDataLen,
          NULL,
          NULL));

  /* Update LC. */
  if ((wOption & PHHAL_HW_SAMAV3_GENERATE_MAC_INCLUDE_LC) || bTxDataLen) {
    PH_CHECK_SUCCESS_FCT(wStatus, phhalHw_SamAV3_Utils_UpdateLc(pDataParams));
  }

  /* Buffer LE and exchange the bufferred informatation to SAM hardware. */
  if (!(wOption & PH_EXCHANGE_BUFFERED_BIT)) {
    /* Add LE to exchange buffer if its the last frame. */
    if (pDataParams->pTxBuffer[PHHAL_HW_SAMAV3_ISO7816_P1_POS] !=
        PHHAL_HW_SAMAV3_ISO7816_CHAINED_FRAME) {
      wStatus = phhalHw_SamAV3_Cmd_7816Exchange(
              pDataParams,
              PH_EXCHANGE_BUFFER_CONT,
              gaDefaultLe,
              1,
              NULL,
              NULL);
    }

    /* Exchange the bufferred information to SAM hardware. */
    wStatus = phhalHw_SamAV3_Cmd_7816Exchange(
            pDataParams,
            PH_EXCHANGE_BUFFER_LAST,
            NULL,
            0,
            ppRxData,
            pRxDataLen);

    /* Check status. */
    if ((wStatus & PH_ERR_MASK) == PHHAL_HW_SAMAV3_ERR_OK_CHAINING_ACTIVE) {
      wStatus = PH_ADD_COMPCODE(PH_ERR_SUCCESS_CHAINING, PH_COMP_HAL);
    }
  }

  return wStatus;
}

phStatus_t
phhalHw_SamAV3_Cmd_SAM_DecipherData(phhalHw_SamAV3_DataParams_t *pDataParams, uint16_t wOption,
    uint8_t *pEncData, uint8_t bEncDataLen, uint8_t *pLength,
    uint8_t **ppPlainData, uint16_t *pPlainDataLen)
{
  phStatus_t	PH_MEMLOC_REM wStatus = 0;
  uint8_t		PH_MEMLOC_REM aCmdBuf[PHHAL_HW_SAMAV3_ISO7816_HEADER_LENGTH];

  /* Parameter validation. */
  PH_ASSERT_NULL_DATA_PARAM(pDataParams, PH_COMP_HAL);
  if (wOption & PHHAL_HW_SAMAV3_DECIPHER_LENGTH_INCLUDE) {
    PH_ASSERT_NULL_PARAM(pLength, PH_COMP_HAL);
  }
  PH_ASSERT_NULL_PARAM(pEncData, PH_COMP_HAL);
  PH_ASSERT_NULL_PARAM(pPlainDataLen, PH_COMP_HAL);

  if (!(wOption & PH_EXCHANGE_LEAVE_BUFFER_BIT)) {
    /* Reset the command buffer. */
    memset(aCmdBuf, 0, sizeof(aCmdBuf));  /* PRQA S 3200 */

    /* Frame Cmd.SAM_DecipherData command information. */
    aCmdBuf[PHHAL_HW_SAMAV3_ISO7816_CLA_POS] = PHHAL_HW_SAMAV3_ISO7816_CLA_BYTE;
    aCmdBuf[PHHAL_HW_SAMAV3_ISO7816_INS_POS] = PHHAL_HW_SAMAV3_CMD_SAM_DECIPHER_DATA_INS;
    aCmdBuf[PHHAL_HW_SAMAV3_ISO7816_P1_POS]  = PHHAL_HW_SAMAV3_ISO7816_LAST_FRAME;
    aCmdBuf[PHHAL_HW_SAMAV3_ISO7816_P2_POS]  = PHHAL_HW_SAMAV3_ISO7816_DEFAULT_P2_BYTE;
    aCmdBuf[PHHAL_HW_SAMAV3_ISO7816_LC_POS]  = PHHAL_HW_SAMAV3_ISO7816_DEFAULT_LC_BYTE;

    /* Update P1 byte. */
    if (wOption & PH_EXCHANGE_TXCHAINING) {
      aCmdBuf[PHHAL_HW_SAMAV3_ISO7816_P1_POS] = PHHAL_HW_SAMAV3_ISO7816_CHAINED_FRAME;
    }

    /* Buffer command information to exchange buffer. */
    PH_CHECK_SUCCESS_FCT(wStatus, phhalHw_SamAV3_Cmd_7816Exchange(
            pDataParams,
            PH_EXCHANGE_BUFFER_FIRST,
            aCmdBuf,
            PHHAL_HW_SAMAV3_ISO7816_HEADER_LENGTH,
            NULL,
            NULL));

    /* Buffer length information to exchange buffer. */
    if (wOption & PHHAL_HW_SAMAV3_DECIPHER_LENGTH_INCLUDE) {
      PH_CHECK_SUCCESS_FCT(wStatus, phhalHw_SamAV3_Cmd_7816Exchange(
              pDataParams,
              PH_EXCHANGE_BUFFER_CONT,
              pLength,
              3,
              NULL,
              NULL));
    }
  }

  /* Buffer data to exchange buffer. */
  PH_CHECK_SUCCESS_FCT(wStatus, phhalHw_SamAV3_Cmd_7816Exchange(
          pDataParams,
          PH_EXCHANGE_BUFFER_CONT,
          pEncData,
          bEncDataLen,
          NULL,
          NULL));

  /* Update LC. */
  PH_CHECK_SUCCESS_FCT(wStatus, phhalHw_SamAV3_Utils_UpdateLc(pDataParams));

  /* Buffer LE and exchange the bufferred informatation to SAM hardware. */
  if (!(wOption & PH_EXCHANGE_BUFFERED_BIT)) {
    /* Buffer LE and exchange the bufferred information to SAM hardware. */
    wStatus = phhalHw_SamAV3_Cmd_7816Exchange(
            pDataParams,
            PH_EXCHANGE_BUFFER_LAST,
            gaDefaultLe,
            1,
            ppPlainData,
            pPlainDataLen);

    /* Check status. */
    if ((wStatus & PH_ERR_MASK) == PHHAL_HW_SAMAV3_ERR_OK_CHAINING_ACTIVE) {
      wStatus = PH_ADD_COMPCODE(PH_ERR_SUCCESS_CHAINING, PH_COMP_HAL);
    }
  }

  return wStatus;
}

phStatus_t
phhalHw_SamAV3_Cmd_SAM_EncipherData(phhalHw_SamAV3_DataParams_t *pDataParams, uint16_t wOption,
    uint8_t *pPlainData, uint8_t bPlainDataLen, uint8_t bOffset,
    uint8_t **ppEncData, uint16_t *pEncDataLen)
{
  phStatus_t	PH_MEMLOC_REM wStatus = 0;
  uint8_t		PH_MEMLOC_REM aCmdBuf[PHHAL_HW_SAMAV3_ISO7816_HEADER_LENGTH];

  /* Parameter validation. */
  PH_ASSERT_NULL_DATA_PARAM(pDataParams, PH_COMP_HAL);
  if (bPlainDataLen) {
    PH_ASSERT_NULL_PARAM(pPlainData, PH_COMP_HAL);
  }
  PH_ASSERT_NULL_PARAM(pEncDataLen, PH_COMP_HAL);

  if (!(wOption & PH_EXCHANGE_LEAVE_BUFFER_BIT)) {
    /* Reset the command buffer. */
    memset(aCmdBuf, 0, sizeof(aCmdBuf));  /* PRQA S 3200 */

    /* Frame Cmd.SAM_EncipherData command information. */
    aCmdBuf[PHHAL_HW_SAMAV3_ISO7816_CLA_POS] = PHHAL_HW_SAMAV3_ISO7816_CLA_BYTE;
    aCmdBuf[PHHAL_HW_SAMAV3_ISO7816_INS_POS] = PHHAL_HW_SAMAV3_CMD_SAM_ENCIPHER_DATA_INS;
    aCmdBuf[PHHAL_HW_SAMAV3_ISO7816_P1_POS]  = PHHAL_HW_SAMAV3_ISO7816_LAST_FRAME;
    aCmdBuf[PHHAL_HW_SAMAV3_ISO7816_P2_POS]  = bOffset;
    aCmdBuf[PHHAL_HW_SAMAV3_ISO7816_LC_POS]  = PHHAL_HW_SAMAV3_ISO7816_DEFAULT_LC_BYTE;

    /* Update P1 byte. */
    if (wOption & PH_EXCHANGE_TXCHAINING) {
      aCmdBuf[PHHAL_HW_SAMAV3_ISO7816_P1_POS] = PHHAL_HW_SAMAV3_ISO7816_CHAINED_FRAME;
    }

    /* Buffer command information to exchange buffer. */
    PH_CHECK_SUCCESS_FCT(wStatus, phhalHw_SamAV3_Cmd_7816Exchange(
            pDataParams,
            PH_EXCHANGE_BUFFER_FIRST,
            aCmdBuf,
            PHHAL_HW_SAMAV3_ISO7816_HEADER_LENGTH,
            NULL,
            NULL));
  }

  /* Exchange second part with lower layer */
  PH_CHECK_SUCCESS_FCT(wStatus, phhalHw_SamAV3_Cmd_7816Exchange(
          pDataParams,
          PH_EXCHANGE_BUFFER_CONT,
          pPlainData,
          bPlainDataLen,
          NULL,
          NULL));

  /* Update LC. */
  PH_CHECK_SUCCESS_FCT(wStatus, phhalHw_SamAV3_Utils_UpdateLc(pDataParams));

  /* Buffer LE and exchange the bufferred informatation to SAM hardware. */
  if (!(wOption & PH_EXCHANGE_BUFFERED_BIT)) {
    /* Buffer LE and exchange the bufferred information to SAM hardware. */
    wStatus = phhalHw_SamAV3_Cmd_7816Exchange(
            pDataParams,
            PH_EXCHANGE_BUFFER_LAST,
            gaDefaultLe,
            1,
            ppEncData,
            pEncDataLen);

    /* Check status. */
    if ((wStatus & PH_ERR_MASK) == PHHAL_HW_SAMAV3_ERR_OK_CHAINING_ACTIVE) {
      wStatus = PH_ADD_COMPCODE(PH_ERR_SUCCESS_CHAINING, PH_COMP_HAL);
    }
  }

  return wStatus;
}

phStatus_t
phhalHw_SamAV3_Cmd_SAM_DecipherOfflineData(phhalHw_SamAV3_DataParams_t *pDataParams,
    uint16_t wOption, uint8_t *pEncData, uint8_t bEncDataLen,
    uint8_t **ppPlainData, uint16_t *pPlainDataLen)
{
  phStatus_t	PH_MEMLOC_REM wStatus = 0;
  uint8_t		PH_MEMLOC_REM aCmdBuf[PHHAL_HW_SAMAV3_ISO7816_HEADER_LENGTH];

  /* Parameter validation. */
  PH_ASSERT_NULL_DATA_PARAM(pDataParams, PH_COMP_HAL);
  PH_ASSERT_NULL_PARAM(pEncData, PH_COMP_HAL);
  PH_ASSERT_NULL_PARAM(pPlainDataLen, PH_COMP_HAL);

  if (!(wOption & PH_EXCHANGE_LEAVE_BUFFER_BIT)) {
    /* Reset the command buffer. */
    memset(aCmdBuf, 0, sizeof(aCmdBuf));  /* PRQA S 3200 */

    /* Frame Cmd.SAM_DecipherOffline_Data command information. */
    aCmdBuf[PHHAL_HW_SAMAV3_ISO7816_CLA_POS] = PHHAL_HW_SAMAV3_ISO7816_CLA_BYTE;
    aCmdBuf[PHHAL_HW_SAMAV3_ISO7816_INS_POS] = PHHAL_HW_SAMAV3_CMD_SAM_DECIPHER_OFFLINE_DATA_INS;
    aCmdBuf[PHHAL_HW_SAMAV3_ISO7816_P1_POS]  = PHHAL_HW_SAMAV3_ISO7816_LAST_FRAME;
    aCmdBuf[PHHAL_HW_SAMAV3_ISO7816_P2_POS]  = PHHAL_HW_SAMAV3_ISO7816_DEFAULT_P2_BYTE;
    aCmdBuf[PHHAL_HW_SAMAV3_ISO7816_LC_POS]  = PHHAL_HW_SAMAV3_ISO7816_DEFAULT_LC_BYTE;

    /* Update P1 byte. */
    if (wOption & PH_EXCHANGE_TXCHAINING) {
      aCmdBuf[PHHAL_HW_SAMAV3_ISO7816_P1_POS] = PHHAL_HW_SAMAV3_ISO7816_CHAINED_FRAME;
    }

    /* Buffer command information to exchange buffer. */
    PH_CHECK_SUCCESS_FCT(wStatus, phhalHw_SamAV3_Cmd_7816Exchange(
            pDataParams,
            PH_EXCHANGE_BUFFER_FIRST,
            aCmdBuf,
            PHHAL_HW_SAMAV3_ISO7816_HEADER_LENGTH,
            NULL,
            NULL));
  }

  /* Buffer data to exchange buffer. */
  PH_CHECK_SUCCESS_FCT(wStatus, phhalHw_SamAV3_Cmd_7816Exchange(
          pDataParams,
          PH_EXCHANGE_BUFFER_CONT,
          pEncData,
          bEncDataLen,
          NULL,
          NULL));

  /* Update LC. */
  PH_CHECK_SUCCESS_FCT(wStatus, phhalHw_SamAV3_Utils_UpdateLc(pDataParams));

  /* Buffer LE and exchange the bufferred informatation to SAM hardware. */
  if (!(wOption & PH_EXCHANGE_BUFFERED_BIT)) {
    /* Buffer LE and exchange the bufferred information to SAM hardware. */
    wStatus = phhalHw_SamAV3_Cmd_7816Exchange(
            pDataParams,
            PH_EXCHANGE_BUFFER_LAST,
            gaDefaultLe,
            1,
            ppPlainData,
            pPlainDataLen);

    /* Check status. */
    if ((wStatus & PH_ERR_MASK) == PHHAL_HW_SAMAV3_ERR_OK_CHAINING_ACTIVE) {
      wStatus = PH_ADD_COMPCODE(PH_ERR_SUCCESS_CHAINING, PH_COMP_HAL);
    }
  }

  return wStatus;
}

phStatus_t
phhalHw_SamAV3_Cmd_SAM_EncipherOfflineData(phhalHw_SamAV3_DataParams_t *pDataParams,
    uint16_t wOption, uint8_t *pPlainData, uint8_t bPlainDataLen,
    uint8_t **ppEncData, uint16_t *pEncDataLen)
{
  phStatus_t	PH_MEMLOC_REM wStatus = 0;
  uint8_t		PH_MEMLOC_REM aCmdBuf[PHHAL_HW_SAMAV3_ISO7816_HEADER_LENGTH];

  /* Parameter validation. */
  PH_ASSERT_NULL_DATA_PARAM(pDataParams, PH_COMP_HAL);
  PH_ASSERT_NULL_PARAM(pPlainData, PH_COMP_HAL);
  PH_ASSERT_NULL_PARAM(pEncDataLen, PH_COMP_HAL);

  if (!(wOption & PH_EXCHANGE_LEAVE_BUFFER_BIT)) {
    /* Reset the command buffer. */
    memset(aCmdBuf, 0, sizeof(aCmdBuf));  /* PRQA S 3200 */

    /* Frame Cmd.SAM_EncipherOffline_Data command information. */
    aCmdBuf[PHHAL_HW_SAMAV3_ISO7816_CLA_POS] = PHHAL_HW_SAMAV3_ISO7816_CLA_BYTE;
    aCmdBuf[PHHAL_HW_SAMAV3_ISO7816_INS_POS] = PHHAL_HW_SAMAV3_CMD_SAM_ENCIPHER_OFFLINE_DATA_INS;
    aCmdBuf[PHHAL_HW_SAMAV3_ISO7816_P1_POS]  = PHHAL_HW_SAMAV3_ISO7816_LAST_FRAME;
    aCmdBuf[PHHAL_HW_SAMAV3_ISO7816_P2_POS]  = PHHAL_HW_SAMAV3_ISO7816_DEFAULT_P2_BYTE;
    aCmdBuf[PHHAL_HW_SAMAV3_ISO7816_LC_POS]  = PHHAL_HW_SAMAV3_ISO7816_DEFAULT_LC_BYTE;

    /* Update P1 byte. */
    if (wOption & PH_EXCHANGE_TXCHAINING) {
      aCmdBuf[PHHAL_HW_SAMAV3_ISO7816_P1_POS] = PHHAL_HW_SAMAV3_ISO7816_CHAINED_FRAME;
    }

    /* Buffer command information to exchange buffer. */
    PH_CHECK_SUCCESS_FCT(wStatus, phhalHw_SamAV3_Cmd_7816Exchange(
            pDataParams,
            PH_EXCHANGE_BUFFER_FIRST,
            aCmdBuf,
            PHHAL_HW_SAMAV3_ISO7816_HEADER_LENGTH,
            NULL,
            NULL));
  }

  /* Exchange second part with lower layer */
  PH_CHECK_SUCCESS_FCT(wStatus, phhalHw_SamAV3_Cmd_7816Exchange(
          pDataParams,
          PH_EXCHANGE_BUFFER_CONT,
          pPlainData,
          bPlainDataLen,
          NULL,
          NULL));

  /* Update LC. */
  PH_CHECK_SUCCESS_FCT(wStatus, phhalHw_SamAV3_Utils_UpdateLc(pDataParams));

  /* Buffer LE and exchange the bufferred informatation to SAM hardware. */
  if (!(wOption & PH_EXCHANGE_BUFFERED_BIT)) {
    /* Buffer LE and exchange the bufferred information to SAM hardware. */
    wStatus = phhalHw_SamAV3_Cmd_7816Exchange(
            pDataParams,
            PH_EXCHANGE_BUFFER_LAST,
            gaDefaultLe,
            1,
            ppEncData,
            pEncDataLen);

    /* Check status. */
    if ((wStatus & PH_ERR_MASK) == PHHAL_HW_SAMAV3_ERR_OK_CHAINING_ACTIVE) {
      wStatus = PH_ADD_COMPCODE(PH_ERR_SUCCESS_CHAINING, PH_COMP_HAL);
    }
  }

  return wStatus;
}

/*************************************************************************************************************************/
/**************************************************** PKI - RSA, ECC *****************************************************/
/*************************************************************************************************************************/

/* RSA Commands -------------------------------------------------------------------------------------------------------- */

phStatus_t
phhalHw_SamAV3_Cmd_PKI_GenerateKeyPair(phhalHw_SamAV3_DataParams_t *pDataParams, uint8_t bOption,
    uint8_t bPKI_KeyNo, uint16_t wPKI_Set, uint8_t bPKI_KeyNoCEK,
    uint8_t bPKI_KeyVCEK, uint8_t bPKI_RefNoKUC, uint8_t bPKI_KeyNoAEK, uint8_t bPKI_KeyVAEK,
    uint16_t wPKI_NLen, uint16_t wPKI_eLen, uint8_t *pPKI_e)
{
  phStatus_t	PH_MEMLOC_REM wStatus = 0;
  uint8_t		PH_MEMLOC_REM aCmdBuf[PHHAL_HW_SAMAV3_CMD_PKI_GENERATE_KEY_PAIR_CMD_SIZE];
  uint8_t		PH_MEMLOC_REM bCmdLen = 0;
  uint8_t 	*PH_MEMLOC_REM pResponse = NULL;
  uint16_t	PH_MEMLOC_REM wRespLen = 0;

  /* Validate the parameters. */
  PH_ASSERT_NULL_DATA_PARAM(pDataParams, PH_COMP_HAL);
  if (bOption & PHHAL_HW_SAMAV3_CMD_PKI_GENERATE_KEY_PAIR_HOST_E) {
    PH_ASSERT_NULL_PARAM(pPKI_e, PH_COMP_HAL);
  }

  /* Reset the command buffer. */
  memset(aCmdBuf, 0x00, sizeof(aCmdBuf));	/* PRQA S 3200 */

  /* Frame the PKI_GenerateKeyPair command header. */
  aCmdBuf[bCmdLen++] = PHHAL_HW_SAMAV3_ISO7816_CLA_BYTE;
  aCmdBuf[bCmdLen++] = PHHAL_HW_SAMAV3_CMD_PKI_GENERATE_KEY_PAIR_INS;
  aCmdBuf[bCmdLen++] = bOption;
  aCmdBuf[bCmdLen++] = PHHAL_HW_SAMAV3_ISO7816_DEFAULT_P2_BYTE;
  aCmdBuf[bCmdLen++] = PHHAL_HW_SAMAV3_CMD_PKI_GENERATE_KEY_PAIR_LC_MIN;

  /* Update LC byte if Access Entry Key information is available. */
  if (bOption & PHHAL_HW_SAMAV3_CMD_PKI_GENERATE_KEY_PAIR_AEK_INCLUDE) {
    aCmdBuf[PHHAL_HW_SAMAV3_ISO7816_LC_POS] += 2 /* PKI_KeyNoAEK and PKI_KeyVAEK. */;
  }

  /* Update P2 information and LC byte. */
  if ((wPKI_eLen >= 228) && (bOption & PHHAL_HW_SAMAV3_CMD_PKI_GENERATE_KEY_PAIR_HOST_E)) {
    aCmdBuf[PHHAL_HW_SAMAV3_ISO7816_P2_POS] = PHHAL_HW_SAMAV3_ISO7816_CHAINED_FRAME;
    aCmdBuf[PHHAL_HW_SAMAV3_ISO7816_LC_POS] += 228 /* First part of PKI_e information. */;
  } else {
    aCmdBuf[PHHAL_HW_SAMAV3_ISO7816_P2_POS] = PHHAL_HW_SAMAV3_ISO7816_LAST_FRAME;
    if (bOption & PHHAL_HW_SAMAV3_CMD_PKI_GENERATE_KEY_PAIR_HOST_E) {
      aCmdBuf[PHHAL_HW_SAMAV3_ISO7816_LC_POS] += (uint8_t) wPKI_eLen;
    }
  }

  /* Append the payload information to command buffer. */
  aCmdBuf[bCmdLen++] = bPKI_KeyNo;
  aCmdBuf[bCmdLen++] = (uint8_t)((wPKI_Set & 0xFF00) >> 8);
  aCmdBuf[bCmdLen++] = (uint8_t)((wPKI_Set & 0x00FF) >> 0);
  aCmdBuf[bCmdLen++] = bPKI_KeyNoCEK;
  aCmdBuf[bCmdLen++] = bPKI_KeyVCEK;
  aCmdBuf[bCmdLen++] = bPKI_RefNoKUC;

  /* Add AEK key number and version if set in P1.1 */
  if (bOption & PHHAL_HW_SAMAV3_CMD_PKI_GENERATE_KEY_PAIR_AEK_INCLUDE) {
    aCmdBuf[bCmdLen++] = bPKI_KeyNoAEK;
    aCmdBuf[bCmdLen++] = bPKI_KeyVAEK;
  }

  /* Append the rest of the Payload information to command buffer. */
  aCmdBuf[bCmdLen++] = (uint8_t)((wPKI_NLen & 0xFF00) >> 8);
  aCmdBuf[bCmdLen++] = (uint8_t)((wPKI_NLen & 0x00FF) >> 0);
  aCmdBuf[bCmdLen++] = (uint8_t)((wPKI_eLen & 0xFF00) >> 8);
  aCmdBuf[bCmdLen++] = (uint8_t)((wPKI_eLen & 0x00FF) >> 0);

  /* Buffer the command information to exchange buffer. */
  PH_CHECK_SUCCESS_FCT(wStatus, phhalHw_SamAV3_Cmd_7816Exchange(
          pDataParams,
          PH_EXCHANGE_BUFFER_FIRST,
          aCmdBuf,
          bCmdLen,
          NULL,
          NULL));

  /* Exchange the final information to SAM hardware in case of last frame. */
  if (aCmdBuf[PHHAL_HW_SAMAV3_ISO7816_P2_POS] == PHHAL_HW_SAMAV3_ISO7816_LAST_FRAME) {
    /* Check if User / Host has provided the exponent information. */
    if (bOption & PHHAL_HW_SAMAV3_CMD_PKI_GENERATE_KEY_PAIR_HOST_E) {
      /* PKI_e has to be send */
      PH_CHECK_SUCCESS_FCT(wStatus, phhalHw_SamAV3_Cmd_7816Exchange(
              pDataParams,
              PH_EXCHANGE_BUFFER_LAST,
              pPKI_e,
              wPKI_eLen,
              &pResponse,
              &wRespLen));
    } else {
      /* No PKI_e has to be send. It will be randomanly generated by SAM hardwae. */
      PH_CHECK_SUCCESS_FCT(wStatus, phhalHw_SamAV3_Cmd_7816Exchange(
              pDataParams,
              PH_EXCHANGE_BUFFER_LAST,
              NULL,
              0,
              &pResponse,
              &wRespLen));
    }
  }
  /* Exchange the final frame to SAM hardware and perform a second part of command / information exchange to SAM hardware. */
  else {
    /* Append exponent payload and perform final exchange with SAM hardware. */
    wStatus = phhalHw_SamAV3_Cmd_7816Exchange(
            pDataParams,
            PH_EXCHANGE_BUFFER_LAST,
            pPKI_e,
            228, /* LE is not present in that command */
            &pResponse,
            &wRespLen);

    /* Return the status code if its not chaining. */
    if ((wStatus & PH_ERR_MASK) != PHHAL_HW_SAMAV3_ERR_OK_CHAINING_ACTIVE) {
      return wStatus;
    }

    /* Reset the command buffer amd its length. */
    memset(aCmdBuf, 0x00, sizeof(aCmdBuf));	/* PRQA S 3200 */
    bCmdLen = 0;

    /* Frame the PKI_GenerateKeyPair command header. */
    aCmdBuf[bCmdLen++] = PHHAL_HW_SAMAV3_ISO7816_CLA_BYTE;
    aCmdBuf[bCmdLen++] = PHHAL_HW_SAMAV3_CMD_PKI_GENERATE_KEY_PAIR_INS;
    aCmdBuf[bCmdLen++] = PHHAL_HW_SAMAV3_ISO7816_DEFAULT_P1_BYTE;
    aCmdBuf[bCmdLen++] = PHHAL_HW_SAMAV3_ISO7816_DEFAULT_P2_BYTE;
    aCmdBuf[bCmdLen++] = (uint8_t)(wPKI_eLen - 228);

    /* Buffer the header information to exchange buffer. */
    PH_CHECK_SUCCESS_FCT(wStatus, phhalHw_SamAV3_Cmd_7816Exchange(
            pDataParams,
            PH_EXCHANGE_BUFFER_FIRST,
            aCmdBuf,
            bCmdLen,
            NULL,
            NULL));

    PH_CHECK_SUCCESS_FCT(wStatus, phhalHw_SamAV3_Cmd_7816Exchange(
            pDataParams,
            PH_EXCHANGE_BUFFER_LAST,
            pPKI_e + 228,
            (uint16_t)(wPKI_eLen - 228),
            &pResponse,
            &wRespLen));
  }

  return PH_ADD_COMPCODE(PH_ERR_SUCCESS, PH_COMP_HAL);
}

phStatus_t
phhalHw_SamAV3_Cmd_PKI_ImportKey(phhalHw_SamAV3_DataParams_t *pDataParams, uint8_t bOption,
    uint8_t bPKI_KeyNo, uint16_t wPKI_Set, uint8_t bPKI_KeyNoCEK,
    uint8_t bPKI_KeyVCEK, uint8_t bPKI_RefNoKUC, uint8_t bPKI_KeyNoAEK, uint8_t bPKI_KeyVAEK,
    uint16_t wPKI_NLen, uint16_t wPKI_eLen, uint16_t wPKI_PLen, uint16_t wPKI_QLen,
    uint8_t *pPKI_N, uint8_t *pPKI_e, uint8_t *pPKI_p, uint8_t *pPKI_q, uint8_t *pPKI_dP,
    uint8_t *pPKI_dQ, uint8_t *pPKI_ipq)
{
  phStatus_t	PH_MEMLOC_REM wStatus = 0;
  uint8_t		PH_MEMLOC_REM aCmdBuf[PHHAL_HW_SAMAV3_CMD_PKI_IMPORT_KEY_CMD_SIZE];
  uint16_t	PH_MEMLOC_REM wCmdLen = 0;
  uint8_t 	*PH_MEMLOC_REM pResponse = NULL;
  uint16_t	PH_MEMLOC_REM wRespLen = 0;
  uint8_t		PH_MEMLOC_REM bIsPrivateKeyIncluded = 0;
  uint16_t	PH_MEMLOC_REM wRemainingMsgLen = 0;
  uint8_t 	*PH_MEMLOC_REM pPayload = NULL;
  uint16_t	PH_MEMLOC_REM wPayLoadLen = 0;
  uint16_t	PH_MEMLOC_REM wPayLoadSize = 0;
  uint8_t		PH_MEMLOC_REM bState = 0;

  /* Validate the parameters. */
  PH_ASSERT_NULL_DATA_PARAM(pDataParams, PH_COMP_HAL);

  /* Check if private key is included. */
  if (wPKI_Set & 0x01) {
    bIsPrivateKeyIncluded = PH_ON;
  }

  /* Parameter validation. */
  if ((bOption & PHHAL_HW_SAMAV3_CMD_PKI_UPDATE_KEY_SETTINGS_ONLY) !=
      PHHAL_HW_SAMAV3_CMD_PKI_UPDATE_KEY_SETTINGS_ONLY) {
    PH_ASSERT_NULL_PARAM(pPKI_N, PH_COMP_HAL);
    PH_ASSERT_NULL_PARAM(pPKI_e, PH_COMP_HAL);

    if (bIsPrivateKeyIncluded) {
      PH_ASSERT_NULL_PARAM(pPKI_p, PH_COMP_HAL);
      PH_ASSERT_NULL_PARAM(pPKI_q, PH_COMP_HAL);
      PH_ASSERT_NULL_PARAM(pPKI_dP, PH_COMP_HAL);
      PH_ASSERT_NULL_PARAM(pPKI_dQ, PH_COMP_HAL);
      PH_ASSERT_NULL_PARAM(pPKI_ipq, PH_COMP_HAL);
    }
  }

  /* Reset the command buffer. */
  memset(aCmdBuf, 0x00, sizeof(aCmdBuf));	/* PRQA S 3200 */

  /* Frame the PKI_ImportKey command header. */
  aCmdBuf[wCmdLen++] = PHHAL_HW_SAMAV3_ISO7816_CLA_BYTE;
  aCmdBuf[wCmdLen++] = PHHAL_HW_SAMAV3_CMD_PKI_IMPORT_KEY_INS;
  aCmdBuf[wCmdLen++] = bOption;
  aCmdBuf[wCmdLen++] = PHHAL_HW_SAMAV3_ISO7816_DEFAULT_P2_BYTE;
  aCmdBuf[wCmdLen++] = PHHAL_HW_SAMAV3_CMD_PKI_IMPORT_KEY_LC_MIN;

  /* Update Remaining message length valiable. */
  wRemainingMsgLen    = PHHAL_HW_SAMAV3_ISO7816_HEADER_LENGTH;

  /* Update LC byte if Access Entry Key information is available. */
  if ((bOption & PHHAL_HW_SAMAV3_CMD_PKI_IMPORT_KEY_AEK_INCLUDE) ==
      PHHAL_HW_SAMAV3_CMD_PKI_IMPORT_KEY_AEK_INCLUDE) {
    aCmdBuf[PHHAL_HW_SAMAV3_ISO7816_LC_POS] += 2 /* PKI_KeyNoAEK and PKI_KeyVAEK. */;
  }

  /* Append the payload information to command buffer. */
  aCmdBuf[wCmdLen++] = bPKI_KeyNo;
  aCmdBuf[wCmdLen++] = (uint8_t)((wPKI_Set & 0xFF00) >> 8);
  aCmdBuf[wCmdLen++] = (uint8_t)((wPKI_Set & 0x00FF) >> 0);
  aCmdBuf[wCmdLen++] = bPKI_KeyNoCEK;
  aCmdBuf[wCmdLen++] = bPKI_KeyVCEK;
  aCmdBuf[wCmdLen++] = bPKI_RefNoKUC;

  /* Add AEK key number and version if set in P1.1 */
  if ((bOption & PHHAL_HW_SAMAV3_CMD_PKI_IMPORT_KEY_AEK_INCLUDE) ==
      PHHAL_HW_SAMAV3_CMD_PKI_IMPORT_KEY_AEK_INCLUDE) {
    aCmdBuf[wCmdLen++] = bPKI_KeyNoAEK;
    aCmdBuf[wCmdLen++] = bPKI_KeyVAEK;
  }

  if ((bOption & PHHAL_HW_SAMAV3_CMD_PKI_UPDATE_KEY_SETTINGS_ONLY) ==
      PHHAL_HW_SAMAV3_CMD_PKI_UPDATE_KEY_SETTINGS_ONLY) {
    /* Update the P2 information byte with Last frame as indicator. */
    aCmdBuf[PHHAL_HW_SAMAV3_ISO7816_P2_POS] = PHHAL_HW_SAMAV3_ISO7816_LAST_FRAME;

    /* Buffer the command information to exchange buffer. */
    PH_CHECK_SUCCESS_FCT(wStatus, phhalHw_SamAV3_Cmd_7816Exchange(
            pDataParams,
            PH_EXCHANGE_DEFAULT,
            aCmdBuf,
            wCmdLen,
            &pResponse,
            &wRespLen));

    /* Only settings have to be sent, so return success status. */
    return PH_ADD_COMPCODE(PH_ERR_SUCCESS, PH_COMP_HAL);
  }

  /* Add modulus and exponent lengths to command buffer. */
  aCmdBuf[wCmdLen++] = (uint8_t)((wPKI_NLen & 0xFF00) >> 8);
  aCmdBuf[wCmdLen++] = (uint8_t)((wPKI_NLen & 0x00FF) >> 0);
  aCmdBuf[wCmdLen++] = (uint8_t)((wPKI_eLen & 0xFF00) >> 8);
  aCmdBuf[wCmdLen++] = (uint8_t)((wPKI_eLen & 0x00FF) >> 0);

  /* Update remaining message length valiable with modolus and exponent length. */
  wRemainingMsgLen += wPKI_NLen + wPKI_eLen;

  /* Include Prime P and Q lengths to command buffer if private key is included. */
  if (bIsPrivateKeyIncluded) {
    aCmdBuf[wCmdLen++] = (uint8_t)((wPKI_PLen & 0xFF00) >> 8);
    aCmdBuf[wCmdLen++] = (uint8_t)((wPKI_PLen & 0x00FF) >> 0);
    aCmdBuf[wCmdLen++] = (uint8_t)((wPKI_QLen & 0xFF00) >> 8);
    aCmdBuf[wCmdLen++] = (uint8_t)((wPKI_QLen & 0x00FF) >> 0);

    /* Update remaining message length valiable with Prime P and Q length. */
    wRemainingMsgLen += (wPKI_PLen * 2) + (wPKI_QLen * 3);
  }

  /* Update Remaining message length valiable with the key entry length componenets (wCmdLen - I7816 Header). */
  wRemainingMsgLen += (uint8_t)(wCmdLen - PHHAL_HW_SAMAV3_ISO7816_HEADER_LENGTH);

  /* Check whether we have to indicate chaining or not */
  if (wRemainingMsgLen > (PHHAL_HW_SAMAV3_ISO7816_MAX_LC_MULTIPLE_AESBLOCK - 16)) {
    aCmdBuf[PHHAL_HW_SAMAV3_ISO7816_P2_POS] = PHHAL_HW_SAMAV3_ISO7816_CHAINED_FRAME;
  }

  /* Buffer the command information to exchange buffer. */
  PH_CHECK_SUCCESS_FCT(wStatus, phhalHw_SamAV3_Cmd_7816Exchange(
          pDataParams,
          PH_EXCHANGE_BUFFER_FIRST,
          aCmdBuf,
          wCmdLen,
          NULL,
          NULL));

  /* Exchange PKI_N, PKI_e, PK_p, PKI_q, PKI_dP, PKI_dQ, PKI_ipq. */
  bState = 0;
  wPayLoadLen = 0;
  wPayLoadSize = 0;
  do {
    /* Updated the states to echange idfferent payloads. */
    switch (bState) {
      case 0:		/* State to exchange PKI_N information. */
        pPayload = &pPKI_N[wPayLoadLen];
        wPayLoadSize = wPKI_NLen - wPayLoadLen;
        break;

      case 1:		/* State to exchange PKI_e information. */
        pPayload = &pPKI_e[wPayLoadLen];
        wPayLoadSize = wPKI_eLen - wPayLoadLen;
        break;
      case 2:		/* State to exchange PKI_p information. */
        pPayload = &pPKI_p[wPayLoadLen];
        wPayLoadSize = wPKI_PLen - wPayLoadLen;
        break;
      case 3:		/* State to exchange PKI_q information. */
        pPayload = &pPKI_q[wPayLoadLen];
        wPayLoadSize = wPKI_QLen - wPayLoadLen;
        break;

      case 4:		/* State to exchange PKI_dP information. */
        pPayload = &pPKI_dP[wPayLoadLen];
        wPayLoadSize = wPKI_PLen - wPayLoadLen;
        break;

      case 5:		/* State to exchange PKI_dQ information. */
        pPayload = &pPKI_dQ[wPayLoadLen];
        wPayLoadSize = wPKI_QLen - wPayLoadLen;
        break;

      case 6:		/* State to exchange PKI_ipq information. */
        pPayload = &pPKI_ipq[wPayLoadLen];
        wPayLoadSize = wPKI_QLen - wPayLoadLen;
        break;

      default:		/* State to reset variables. */
        pPayload = NULL;
        wPayLoadSize = 0;
        break;
    }

    /* Append payload to the buffer */
    if (wPayLoadSize > 0) {
      /* Payload fits into current frame without truncation */
      if ((wCmdLen + wPayLoadSize) < (PHHAL_HW_SAMAV3_ISO7816_MAX_LC_MULTIPLE_AESBLOCK - 16)) {
        /* Checkif its the last frame and perform final exchange. */
        if ((wRemainingMsgLen - (wCmdLen + wPayLoadSize)) == 0) {
          /* Append rest of data. */
          PH_CHECK_SUCCESS_FCT(wStatus, phhalHw_SamAV3_Cmd_7816Exchange(
                  pDataParams,
                  PH_EXCHANGE_BUFFER_CONT,
                  pPayload,
                  wPayLoadSize,
                  NULL,
                  NULL));

          /* Update LC */
          PH_CHECK_SUCCESS_FCT(wStatus, phhalHw_SamAV3_Utils_UpdateLc(pDataParams));

          /* perform exchange */
          PH_CHECK_SUCCESS_FCT(wStatus, phhalHw_SamAV3_Cmd_7816Exchange(
                  pDataParams,
                  PH_EXCHANGE_BUFFER_LAST,
                  NULL,
                  0,
                  &pResponse,
                  &wRespLen));
        }
        /* Just buffer the frame. */
        else {
          PH_CHECK_SUCCESS_FCT(wStatus, phhalHw_SamAV3_Cmd_7816Exchange(
                  pDataParams,
                  PH_EXCHANGE_BUFFER_CONT,
                  pPayload,
                  wPayLoadSize,
                  NULL,
                  NULL));

          /* Update current frame length */
          wCmdLen = wCmdLen + wPayLoadSize;
        }

        /* Reset payload length */
        wPayLoadLen = 0;

        /* Advance to next payload */
        ++bState;

        /* Set bState to zero if private key is not included. */
        if (!bIsPrivateKeyIncluded && (bState == 2)) {
          bState = 0xFF;
        }
      }
      /* Else send maximum amount of possible data to SAM. */
      else {
        wPayLoadSize = (PHHAL_HW_SAMAV3_ISO7816_MAX_LC_MULTIPLE_AESBLOCK - 16) - wCmdLen;
        wPayLoadLen = wPayLoadLen + wPayLoadSize;

        /* Append rest of data */
        PH_CHECK_SUCCESS_FCT(wStatus, phhalHw_SamAV3_Cmd_7816Exchange(
                pDataParams,
                PH_EXCHANGE_BUFFER_CONT,
                pPayload,
                wPayLoadSize,
                NULL,
                NULL));

        /* Update LC */
        PH_CHECK_SUCCESS_FCT(wStatus, phhalHw_SamAV3_Utils_UpdateLc(pDataParams));

        /* perform exchange */
        wStatus = phhalHw_SamAV3_Cmd_7816Exchange(
                pDataParams,
                PH_EXCHANGE_BUFFER_LAST,
                NULL,
                0,
                &pResponse,
                &wRespLen);

        /* status check */
        if ((wStatus & PH_ERR_MASK) != PHHAL_HW_SAMAV3_ERR_OK_CHAINING_ACTIVE) {
          return wStatus;
        }

        /* Update current frame length */
        wCmdLen = wCmdLen + wPayLoadSize;

        /* Check for internal error */
        if (wRemainingMsgLen < wCmdLen) {
          return PH_ADD_COMPCODE(PH_ERR_INTERNAL_ERROR, PH_COMP_HAL);
        }

        /* Update remaining message length */
        wRemainingMsgLen = wRemainingMsgLen - wCmdLen;

        /* Check whether we have to indicate chaining or not */
        if (wRemainingMsgLen > (PHHAL_HW_SAMAV3_ISO7816_MAX_LC_MULTIPLE_AESBLOCK - 16)) {
          aCmdBuf[PHHAL_HW_SAMAV3_ISO7816_P2_POS] = PHHAL_HW_SAMAV3_ISO7816_CHAINED_FRAME;
        } else {
          aCmdBuf[PHHAL_HW_SAMAV3_ISO7816_P2_POS] = PHHAL_HW_SAMAV3_ISO7816_LAST_FRAME;
        }

        /* Buffer the command header */
        PH_CHECK_SUCCESS_FCT(wStatus, phhalHw_SamAV3_Cmd_7816Exchange(
                pDataParams,
                PH_EXCHANGE_BUFFER_FIRST,
                aCmdBuf,
                PHHAL_HW_SAMAV3_ISO7816_HEADER_LENGTH,
                NULL,
                NULL));

        /* Reset current frame length */
        wCmdLen = 0;
      }
    }
  } while (wPayLoadSize > 0);

  return PH_ADD_COMPCODE(PH_ERR_SUCCESS, PH_COMP_HAL);
}

phStatus_t
phhalHw_SamAV3_Cmd_PKI_ExportPrivateKey(phhalHw_SamAV3_DataParams_t *pDataParams,
    uint16_t wOption, uint8_t bPKI_KeyNo, uint8_t **ppKeyData, uint16_t *pKeyDataLen)
{
  phStatus_t  PH_MEMLOC_REM wStatus = 0;
  uint8_t     PH_MEMLOC_REM aCmdBuf[PHHAL_HW_SAMAV3_ISO7816_HEADER_LENGTH];
  uint8_t    *PH_MEMLOC_REM pResponse = NULL;
  uint16_t    PH_MEMLOC_REM wRespLen = 0;

  /* Validate the parameters. */
  PH_ASSERT_NULL_DATA_PARAM(pDataParams, PH_COMP_HAL);
  PH_ASSERT_NULL_PARAM(pKeyDataLen, PH_COMP_HAL);

  /* Reset the command buffer. */
  memset(aCmdBuf, 0x00, sizeof(aCmdBuf));	/* PRQA S 3200 */

  /* Frame the command for Cmd.PKI_ExportPrivateKey command. */
  aCmdBuf[PHHAL_HW_SAMAV3_ISO7816_CLA_POS] = PHHAL_HW_SAMAV3_ISO7816_CLA_BYTE;
  aCmdBuf[PHHAL_HW_SAMAV3_ISO7816_INS_POS] = PHHAL_HW_SAMAV3_CMD_PKI_EXPORT_PRIVATE_KEY_INS;
  aCmdBuf[PHHAL_HW_SAMAV3_ISO7816_P1_POS] = bPKI_KeyNo;
  aCmdBuf[PHHAL_HW_SAMAV3_ISO7816_P2_POS] = (uint8_t)(wOption &
          PHHAL_HW_SAMAV3_CMD_PKI_EXPORT_PRIVATE_KEY_AEK_INCLUDE);
  aCmdBuf[PHHAL_HW_SAMAV3_ISO7816_LE_NO_LC_POS] = PHHAL_HW_SAMAV3_ISO7816_DEFAULT_LE_BYTE;

  /* Update the P1 information with default value. */
  if (wOption & PH_EXCHANGE_RXCHAINING) {
    aCmdBuf[PHHAL_HW_SAMAV3_ISO7816_P1_POS] = PHHAL_HW_SAMAV3_ISO7816_DEFAULT_P1_BYTE;
  }

  /* Exchange the command to Sam hardware. */
  wStatus =  phhalHw_SamAV3_Cmd_7816Exchange(
          pDataParams,
          PH_EXCHANGE_DEFAULT,
          aCmdBuf,
          PHHAL_HW_SAMAV3_ISO7816_HEADER_LENGTH,
          &pResponse,
          &wRespLen);

  /* status check */
  if ((wStatus & PH_ERR_MASK) != PHHAL_HW_SAMAV3_ERR_OK_CHAINING_ACTIVE) {
    PH_CHECK_SUCCESS(wStatus);
  } else {
    wStatus = PH_ADD_COMPCODE(PH_ERR_SUCCESS_CHAINING, PH_COMP_HAL);
  }

  *ppKeyData = pResponse;
  *pKeyDataLen = wRespLen;

  return wStatus;
}

phStatus_t
phhalHw_SamAV3_Cmd_PKI_ExportPublicKey(phhalHw_SamAV3_DataParams_t *pDataParams, uint16_t wOption,
    uint8_t bPKI_KeyNo, uint8_t **ppKeyData, uint16_t *pKeyDataLen)
{
  phStatus_t  PH_MEMLOC_REM wStatus = 0;
  uint8_t     PH_MEMLOC_REM aCmdBuf[PHHAL_HW_SAMAV3_ISO7816_HEADER_LENGTH];

  /* Validate the parameters. */
  PH_ASSERT_NULL_DATA_PARAM(pDataParams, PH_COMP_HAL);
  PH_ASSERT_NULL_PARAM(pKeyDataLen, PH_COMP_HAL);

  /* Reset the command buffer. */
  memset(aCmdBuf, 0x00, sizeof(aCmdBuf));	/* PRQA S 3200 */

  /* Frame the command for Cmd.PKI_ExportPublicKey command. */
  aCmdBuf[PHHAL_HW_SAMAV3_ISO7816_CLA_POS] = PHHAL_HW_SAMAV3_ISO7816_CLA_BYTE;
  aCmdBuf[PHHAL_HW_SAMAV3_ISO7816_INS_POS] = PHHAL_HW_SAMAV3_CMD_PKI_EXPORT_PUBLIC_KEY_INS;
  aCmdBuf[PHHAL_HW_SAMAV3_ISO7816_P1_POS] = bPKI_KeyNo;
  aCmdBuf[PHHAL_HW_SAMAV3_ISO7816_P2_POS] = (uint8_t)(wOption &
          PHHAL_HW_SAMAV3_CMD_PKI_EXPORT_PUBLIC_KEY_AEK_INCLUDE);
  aCmdBuf[PHHAL_HW_SAMAV3_ISO7816_LE_NO_LC_POS] = PHHAL_HW_SAMAV3_ISO7816_DEFAULT_LE_BYTE;

  /* Update the P1 information with default value. */
  if (wOption & PH_EXCHANGE_RXCHAINING) {
    aCmdBuf[PHHAL_HW_SAMAV3_ISO7816_P1_POS] = PHHAL_HW_SAMAV3_ISO7816_DEFAULT_P1_BYTE;
  }

  /* Exchange the command to Sam hardware. */
  wStatus = phhalHw_SamAV3_Cmd_7816Exchange(
          pDataParams,
          PH_EXCHANGE_DEFAULT,
          aCmdBuf,
          PHHAL_HW_SAMAV3_ISO7816_HEADER_LENGTH,
          ppKeyData,
          pKeyDataLen);

  /* status check */
  if ((wStatus & PH_ERR_MASK) != PHHAL_HW_SAMAV3_ERR_OK_CHAINING_ACTIVE) {
    PH_CHECK_SUCCESS(wStatus);
  } else {
    wStatus = PH_ADD_COMPCODE(PH_ERR_SUCCESS_CHAINING, PH_COMP_HAL);
  }

  return wStatus;
}

phStatus_t
phhalHw_SamAV3_Cmd_PKI_UpdateKeyEntries(phhalHw_SamAV3_DataParams_t *pDataParams, uint8_t bOption,
    uint8_t bNoOfKeyEntries, uint8_t bHashingAlg,
    uint8_t bPKI_KeyNo_Enc, uint8_t bPKI_KeyNo_Sign, uint8_t bPKI_KeyNo_Ack, uint8_t *pKeyFrame,
    uint16_t wKeyFrameLen, uint8_t **ppUpdateACK, uint16_t *pUpdateACKLen)
{
  phStatus_t	PH_MEMLOC_REM wStatus = 0;
  uint8_t		PH_MEMLOC_REM aCmdBuf[PHHAL_HW_SAMAV3_CMD_PKI_IMPORT_KEY_CMD_SIZE];
  uint8_t		PH_MEMLOC_REM bCmdLen = 0;
  uint16_t	PH_MEMLOC_REM wBufPos = 0;
  uint8_t		PH_MEMLOC_REM bSendHeader = 0;
  uint8_t		PH_MEMLOC_REM bPayloadLen = 0;

  /* Validate the parameters. */
  PH_ASSERT_NULL_DATA_PARAM(pDataParams, PH_COMP_HAL);
  PH_ASSERT_NULL_PARAM(pKeyFrame, PH_COMP_HAL);
  if (bOption & PHHAL_HW_SAMAV3_CMD_PKI_UPDATE_KEY_ENTRY_ACK_INCLUDE) {
    PH_ASSERT_NULL_PARAM(pUpdateACKLen, PH_COMP_HAL);
  }

  /* Reset the command buffer and its length. */
  bCmdLen = 0;
  memset(aCmdBuf, 0x00, sizeof(aCmdBuf));	/* PRQA S 3200 */

  /* Frame the PKI_UpdateKeyEntries command. */
  aCmdBuf[bCmdLen++] = PHHAL_HW_SAMAV3_ISO7816_CLA_BYTE;
  aCmdBuf[bCmdLen++] = PHHAL_HW_SAMAV3_CMD_PKI_UPDATE_KEY_ENTRIES_INS;
  aCmdBuf[bCmdLen++] = bHashingAlg | (uint8_t)(bNoOfKeyEntries << 2);
  aCmdBuf[bCmdLen++] = PHHAL_HW_SAMAV3_ISO7816_LAST_FRAME;

  /* Add Enc and Sign key numbers to command buffer. */
  if (bOption & PH_EXCHANGE_RXCHAINING) {
    aCmdBuf[PHHAL_HW_SAMAV3_ISO7816_P1_POS] = PHHAL_HW_SAMAV3_ISO7816_DEFAULT_P1_BYTE;
  } else {
    aCmdBuf[bCmdLen++] = PHHAL_HW_SAMAV3_ISO7816_DEFAULT_LC_BYTE;

    aCmdBuf[bCmdLen++] = bPKI_KeyNo_Enc;
    aCmdBuf[bCmdLen++] = bPKI_KeyNo_Sign;

    /* Add Ack key numbers to command buffer if required. */
    if (bOption & PHHAL_HW_SAMAV3_CMD_PKI_UPDATE_KEY_ENTRY_ACK_INCLUDE) {
      aCmdBuf[bCmdLen++] = bPKI_KeyNo_Ack;
    }
  }

  /* Buffer the command information to exchange buffer. */
  PH_CHECK_SUCCESS_FCT(wStatus, phhalHw_SamAV3_Cmd_7816Exchange(
          pDataParams,
          PH_EXCHANGE_BUFFER_FIRST,
          aCmdBuf,
          bCmdLen,
          NULL,
          NULL));

  if (bOption & PH_EXCHANGE_RXCHAINING) {
    /* Include LE if required and exchange the bufferred information. */
    wStatus = phhalHw_SamAV3_Cmd_7816Exchange(
            pDataParams,
            PH_EXCHANGE_BUFFER_LAST,
            gaDefaultLe,
            (uint8_t)((bOption & PHHAL_HW_SAMAV3_CMD_PKI_UPDATE_KEY_ENTRY_ACK_INCLUDE) ? 1 : 0),
            ppUpdateACK,
            pUpdateACKLen);

    /* Return the chaining code. */
    if ((wStatus & PH_ERR_MASK) == PHHAL_HW_SAMAV3_ERR_OK_CHAINING_ACTIVE) {
      return PH_ADD_COMPCODE(PH_ERR_SUCCESS_CHAINING, PH_COMP_HAL);
    }
  } else {
    bPayloadLen = (uint8_t)(bCmdLen - PHHAL_HW_SAMAV3_ISO7816_HEADER_LENGTH);
    wBufPos = 0;
    bSendHeader = PH_OFF;

    do {
      if (bSendHeader == PH_ON) {
        /* Update the header information. */
        aCmdBuf[PHHAL_HW_SAMAV3_ISO7816_P1_POS] = PHHAL_HW_SAMAV3_ISO7816_DEFAULT_P1_BYTE;
        aCmdBuf[PHHAL_HW_SAMAV3_ISO7816_P2_POS] = PHHAL_HW_SAMAV3_ISO7816_LAST_FRAME;
        aCmdBuf[PHHAL_HW_SAMAV3_ISO7816_LC_POS] = PHHAL_HW_SAMAV3_ISO7816_DEFAULT_LC_BYTE;

        /* Buffer the command information to exchange buffer. */
        PH_CHECK_SUCCESS_FCT(wStatus, phhalHw_SamAV3_Cmd_7816Exchange(
                pDataParams,
                PH_EXCHANGE_BUFFER_FIRST,
                aCmdBuf,
                PHHAL_HW_SAMAV3_ISO7816_HEADER_LENGTH,
                NULL,
                NULL));

        bSendHeader = PH_OFF;
      }

      if ((uint16_t)(wKeyFrameLen - wBufPos) > (uint16_t)(
              PHHAL_HW_SAMAV3_ISO7816_MAX_LC_MULTIPLE_AESBLOCK - bPayloadLen)) {
        PH_CHECK_SUCCESS_FCT(wStatus, phhalHw_SamAV3_Utils_UpdateP2(pDataParams,
                PHHAL_HW_SAMAV3_ISO7816_CHAINED_FRAME));

        /* Buffer the next part of payload to exchange buffer. */
        PH_CHECK_SUCCESS_FCT(wStatus, phhalHw_SamAV3_Cmd_7816Exchange(
                pDataParams,
                PH_EXCHANGE_BUFFER_CONT,
                pKeyFrame + wBufPos,
                (uint16_t)(PHHAL_HW_SAMAV3_ISO7816_MAX_LC_MULTIPLE_AESBLOCK - bPayloadLen),
                NULL,
                NULL));

        /* Update Lc */
        PH_CHECK_SUCCESS_FCT(wStatus, phhalHw_SamAV3_Utils_UpdateLc(pDataParams));

        /* Exchange last frame to Sam hardware. */
        wStatus = phhalHw_SamAV3_Cmd_7816Exchange(
                pDataParams,
                PH_EXCHANGE_BUFFER_LAST,
                NULL,
                0,
                ppUpdateACK,
                pUpdateACKLen);

        /* Check for Success chaining response. */
        if ((wStatus & PH_ERR_MASK) != PHHAL_HW_SAMAV3_ERR_OK_CHAINING_ACTIVE) {
          return wStatus;
        }

        bSendHeader = PH_ON;
        wBufPos = (uint16_t)(wBufPos + (PHHAL_HW_SAMAV3_ISO7816_MAX_LC_MULTIPLE_AESBLOCK - bPayloadLen));
        bPayloadLen = 0;
      } else {
        /* Buffer the next part of payload to exchange buffer. */
        PH_CHECK_SUCCESS_FCT(wStatus, phhalHw_SamAV3_Cmd_7816Exchange(
                pDataParams,
                PH_EXCHANGE_BUFFER_CONT,
                pKeyFrame + wBufPos,
                (uint16_t)(wKeyFrameLen - wBufPos),
                NULL,
                NULL));

        /* Update Lc */
        PH_CHECK_SUCCESS_FCT(wStatus, phhalHw_SamAV3_Utils_UpdateLc(pDataParams));

        /* Include LE if required and exchange the bufferred information. */
        wStatus = phhalHw_SamAV3_Cmd_7816Exchange(
                pDataParams,
                PH_EXCHANGE_BUFFER_LAST,
                gaDefaultLe,
                (uint8_t)((bOption & PHHAL_HW_SAMAV3_CMD_PKI_UPDATE_KEY_ENTRY_ACK_INCLUDE) ? 1 : 0),
                ppUpdateACK,
                pUpdateACKLen);

        wBufPos = wKeyFrameLen;

        /* Check for the Chaining active */
        if ((wStatus & PH_ERR_MASK) != PHHAL_HW_SAMAV3_ERR_OK_CHAINING_ACTIVE) {
          return wStatus;
        } else {
          return PH_ADD_COMPCODE(PH_ERR_SUCCESS_CHAINING, PH_COMP_HAL);
        }
      }

    } while (wBufPos < wKeyFrameLen);

    /* Reset Authentication states. */
    if (pDataParams->bKeyNo == bPKI_KeyNo_Enc) {
      /* Perform Kill Authentication. */
      PH_CHECK_SUCCESS_FCT(wStatus, phhalHw_SamAV3_Cmd_SAM_KillAuthentication(pDataParams,
              PHHAL_HW_SAMAV3_CMD_SAM_KILL_AUTHENTICATION_FULL));

      /* Invalidate the session keys and set the SM to PLAIN. */
      pDataParams->bAuthType = PHHAL_HW_SAMAV3_CMD_SAM_AUTHENTICATE_HOST_MODE_PLAIN;
      PH_CHECK_SUCCESS_FCT(wStatus, phCryptoSym_InvalidateKey(pDataParams->pENCCryptoDataParams));
      PH_CHECK_SUCCESS_FCT(wStatus, phCryptoSym_InvalidateKey(pDataParams->pMACCryptoDataParams));
    }
  }

  return wStatus;
}

phStatus_t
phhalHw_SamAV3_Cmd_PKI_EncipherKeyEntries(phhalHw_SamAV3_DataParams_t *pDataParams,
    uint16_t wOption, uint8_t bNoOfKeyEntries, uint8_t bHashingAlg, uint8_t bPKI_KeyNo_Enc,
    uint8_t bPKI_KeyNo_Sign, uint8_t bPKI_KeyNo_Dec, uint8_t bPKI_KeyNo_Verif, uint16_t wPerso_Ctr,
    uint8_t *pKeyEntries, uint8_t bKeyEntriesLen, uint8_t *pDivInput, uint8_t bDivInputLen,
    uint8_t **ppEncKeyFrame_Sign, uint16_t *pEncKeyFrame_Sign_Len)
{
  phStatus_t  PH_MEMLOC_REM wStatus = 0;
  uint8_t     PH_MEMLOC_REM aCmdBuf[PHHAL_HW_SAMAV3_CMD_PKI_ENCIPHER_KEY_ENTRIES_CMD_SIZE];
  uint8_t		PH_MEMLOC_REM bCmdLen = 0;

  /* Validate the parameters. */
  PH_ASSERT_NULL_DATA_PARAM(pDataParams, PH_COMP_HAL);
  PH_ASSERT_NULL_PARAM(pKeyEntries, PH_COMP_HAL);
  PH_ASSERT_NULL_PARAM(pEncKeyFrame_Sign_Len, PH_COMP_HAL);
  if ((wOption & PHHAL_HW_SAMAV3_CMD_PKI_DIVERSIFICATION_ON)) {
    PH_ASSERT_NULL_PARAM(pDivInput, PH_COMP_HAL);
  }

  /* Reset the command buffer. */
  memset(aCmdBuf, 0x00, sizeof(aCmdBuf));	/* PRQA S 3200 */

  /* Frame the command for Cmd.PKI_EncipherKeyEntries command. */
  aCmdBuf[bCmdLen++] = PHHAL_HW_SAMAV3_ISO7816_CLA_BYTE;
  aCmdBuf[bCmdLen++] = PHHAL_HW_SAMAV3_CMD_PKI_ENCIPHER_KEY_ENTRIES_INS;
  aCmdBuf[bCmdLen++] = PHHAL_HW_SAMAV3_ISO7816_DEFAULT_P1_BYTE;
  aCmdBuf[bCmdLen++] = PHHAL_HW_SAMAV3_ISO7816_DEFAULT_P2_BYTE;

  /* Add the key information and perso counter if its first frame. */
  if ((wOption & PH_EXCHANGE_DEFAULT) == PH_EXCHANGE_DEFAULT) {
    /* Update P1 information byte. */
    aCmdBuf[PHHAL_HW_SAMAV3_ISO7816_P1_POS] = (uint8_t)(wOption &
            PHHAL_HW_SAMAV3_CMD_PKI_DIVERSIFICATION_ON);
    aCmdBuf[PHHAL_HW_SAMAV3_ISO7816_P1_POS] |= (uint8_t)((bNoOfKeyEntries << 2) | bHashingAlg);

    /* Add Default LC to command buffer. */
    aCmdBuf[bCmdLen++] = PHHAL_HW_SAMAV3_ISO7816_DEFAULT_LC_BYTE;

    /* Add key information to command buffer. */
    aCmdBuf[bCmdLen++] = bPKI_KeyNo_Enc;
    aCmdBuf[bCmdLen++] = bPKI_KeyNo_Sign;
    aCmdBuf[bCmdLen++] = bPKI_KeyNo_Dec;
    aCmdBuf[bCmdLen++] = bPKI_KeyNo_Verif;

    /* Add perso counter to command buffer. */
    aCmdBuf[bCmdLen++] = (uint8_t)((wPerso_Ctr & 0xFF00) >> 8);
    aCmdBuf[bCmdLen++] = (uint8_t)(wPerso_Ctr & 0x00FF);
  }

  /* Buffer the command to exchange buffer. */
  PH_CHECK_SUCCESS_FCT(wStatus, phhalHw_SamAV3_Cmd_7816Exchange(
          pDataParams,
          PH_EXCHANGE_BUFFER_FIRST,
          aCmdBuf,
          bCmdLen,
          NULL,
          NULL));

  /* Add key entries and diversification input to exchange buffer if its first frame. */
  if ((wOption & PH_EXCHANGE_DEFAULT) == PH_EXCHANGE_DEFAULT) {
    /* Add key entries to exchange buffer. */
    PH_CHECK_SUCCESS_FCT(wStatus, phhalHw_SamAV3_Cmd_7816Exchange(
            pDataParams,
            PH_EXCHANGE_BUFFER_CONT,
            pKeyEntries,
            bKeyEntriesLen,
            NULL,
            NULL));

    /* Add diversification input to exchange buffer. */
    PH_CHECK_SUCCESS_FCT(wStatus, phhalHw_SamAV3_Cmd_7816Exchange(
            pDataParams,
            PH_EXCHANGE_BUFFER_CONT,
            pDivInput,
            bDivInputLen,
            NULL,
            NULL));

    /* Update Lc */
    PH_CHECK_SUCCESS_FCT(wStatus, phhalHw_SamAV3_Utils_UpdateLc(pDataParams));
  }

  /* Add Le byte to exchange buffer and perform the final exchange. */
  wStatus = phhalHw_SamAV3_Cmd_7816Exchange(
          pDataParams,
          PH_EXCHANGE_BUFFER_LAST,
          gaDefaultLe,
          1,
          ppEncKeyFrame_Sign,
          pEncKeyFrame_Sign_Len);

  /* Update the proper status to be returned in case of chaining. */
  if ((wStatus & PH_ERR_MASK) == PHHAL_HW_SAMAV3_ERR_OK_CHAINING_ACTIVE) {
    return PH_ADD_COMPCODE(PH_ERR_SUCCESS_CHAINING, PH_COMP_HAL);
  }

  return wStatus;
}

phStatus_t
phhalHw_SamAV3_Cmd_PKI_GenerateHash(phhalHw_SamAV3_DataParams_t *pDataParams, uint16_t wOption,
    uint8_t bHashingAlg, uint32_t dwMLen, uint8_t *pMessage, uint16_t wMsgLen,
    uint8_t **ppHash, uint16_t *pHashLen)
{
  phStatus_t	PH_MEMLOC_REM wStatus = 0;
  uint8_t		PH_MEMLOC_REM aCmdBuf[PHHAL_HW_SAMAV3_CMD_PKI_GENERATE_HASH_CMD_SIZE];
  uint8_t		PH_MEMLOC_REM bCmdLen = 0;

  /* Validate the parameters. */
  PH_ASSERT_NULL_DATA_PARAM(pDataParams, PH_COMP_HAL);
  PH_ASSERT_NULL_PARAM(pMessage, PH_COMP_HAL);
  PH_ASSERT_NULL_PARAM(pHashLen, PH_COMP_HAL);

  /* Reset the command buffer and its length variable. */
  bCmdLen = 0;
  memset(aCmdBuf, 0x00, sizeof(aCmdBuf));	/* PRQA S 3200 */

  if (!(wOption & PH_EXCHANGE_LEAVE_BUFFER_BIT)) {
    /* Frame the Cmd.PKI_GenerateHash command. */
    aCmdBuf[bCmdLen++] = PHHAL_HW_SAMAV3_ISO7816_CLA_BYTE;
    aCmdBuf[bCmdLen++] = PHHAL_HW_SAMAV3_CMD_PKI_GENERATE_HASH_INS;
    aCmdBuf[bCmdLen++] = PHHAL_HW_SAMAV3_ISO7816_DEFAULT_P1_BYTE;
    aCmdBuf[bCmdLen++] = PHHAL_HW_SAMAV3_ISO7816_LAST_FRAME;
    aCmdBuf[bCmdLen++] = PHHAL_HW_SAMAV3_ISO7816_DEFAULT_LC_BYTE;

    /* Update P1 information byte with hashing algorithm and Message Length to
       command buffer if its first frame. */
    if (wOption & PHHAL_HW_SAMAV3_CMD_PKI_GENERATE_HASH_FIRST_FRAME) {
      /* Update P1 information byte with hashing algorithm. */
      aCmdBuf[PHHAL_HW_SAMAV3_ISO7816_P1_POS] = bHashingAlg;

      /* Add message length to command buffer. */
      aCmdBuf[bCmdLen++] = (uint8_t)(dwMLen >> 24);
      aCmdBuf[bCmdLen++] = (uint8_t)(dwMLen >> 16);
      aCmdBuf[bCmdLen++] = (uint8_t)(dwMLen >> 8);
      aCmdBuf[bCmdLen++] = (uint8_t)(dwMLen >> 0);
    }

    /* Update P2 information byte with chaining frame. */
    if (wOption & PH_EXCHANGE_TXCHAINING) {
      aCmdBuf[PHHAL_HW_SAMAV3_ISO7816_P2_POS] = PHHAL_HW_SAMAV3_ISO7816_CHAINED_FRAME;
    }

    /* Buffer the command information to exchange buffer. */
    PH_CHECK_SUCCESS_FCT(wStatus, phhalHw_SamAV3_Cmd_7816Exchange(
            pDataParams,
            PH_EXCHANGE_BUFFER_FIRST,
            aCmdBuf,
            bCmdLen,
            NULL,
            NULL));
  }

  /* Buffer the message information to exchange buffer. */
  PH_CHECK_SUCCESS_FCT(wStatus, phhalHw_SamAV3_Cmd_7816Exchange(
          pDataParams,
          PH_EXCHANGE_BUFFER_CONT,
          pMessage,
          wMsgLen,
          NULL,
          NULL));

  /* Update Lc information. */
  PH_CHECK_SUCCESS_FCT(wStatus, phhalHw_SamAV3_Utils_UpdateLc(pDataParams));

  /* Check if the bufferred information in exchange buffer should be exchanged with Sam hardware. */
  if (!(wOption & PH_EXCHANGE_BUFFERED_BIT)) {
    /* Add LE byte to exchange buffer if its the final frame. */
    if (!(wOption & PH_EXCHANGE_TXCHAINING)) {
      PH_CHECK_SUCCESS_FCT(wStatus, phhalHw_SamAV3_Cmd_7816Exchange(
              pDataParams,
              PH_EXCHANGE_BUFFER_CONT,
              gaDefaultLe,
              1,
              NULL,
              NULL));
    }

    /* Exchange the bufferred information to Sam hardware. */
    wStatus = phhalHw_SamAV3_Cmd_7816Exchange(
            pDataParams,
            PH_EXCHANGE_BUFFER_LAST,
            NULL,
            0,
            ppHash,
            pHashLen);

    /* Return Chaining Status. */
    if ((wStatus & PH_ERR_MASK) == PHHAL_HW_SAMAV3_ERR_OK_CHAINING_ACTIVE) {
      wStatus = PH_ADD_COMPCODE(PH_ERR_SUCCESS_CHAINING, PH_COMP_HAL);
    }
  }
  return wStatus;
}

phStatus_t
phhalHw_SamAV3_Cmd_PKI_GenerateSignature(phhalHw_SamAV3_DataParams_t *pDataParams,
    uint8_t bHashingAlg, uint8_t bPKI_KeyNo_Sign, uint8_t *pHash, uint8_t bHashLen)
{
  phStatus_t  PH_MEMLOC_REM wStatus = 0;
  uint8_t     PH_MEMLOC_REM aCmdBuf[PHHAL_HW_SAMAV3_ISO7816_HEADER_LENGTH +
                                            1 /* bPKI_KeyNo_Sign */];
  uint8_t    *PH_MEMLOC_REM pResponse = NULL;
  uint16_t    PH_MEMLOC_REM wRespLen = 0;

  /* Validate the parameters. */
  PH_ASSERT_NULL_DATA_PARAM(pDataParams, PH_COMP_HAL);
  PH_ASSERT_NULL_PARAM(pHash, PH_COMP_HAL);

  /* Reset the command buffer. */
  memset(aCmdBuf, 0x00, sizeof(aCmdBuf));	/* PRQA S 3200 */

  /* Frame the Cmd.PKI_GenerateSignature command. */
  aCmdBuf[PHHAL_HW_SAMAV3_ISO7816_CLA_POS] = PHHAL_HW_SAMAV3_ISO7816_CLA_BYTE;
  aCmdBuf[PHHAL_HW_SAMAV3_ISO7816_INS_POS] = PHHAL_HW_SAMAV3_CMD_PKI_GENERATE_SIGNATURE_INS;
  aCmdBuf[PHHAL_HW_SAMAV3_ISO7816_P1_POS] = bHashingAlg;
  aCmdBuf[PHHAL_HW_SAMAV3_ISO7816_P2_POS] = PHHAL_HW_SAMAV3_ISO7816_DEFAULT_P2_BYTE;
  aCmdBuf[PHHAL_HW_SAMAV3_ISO7816_LC_POS] = (uint8_t)(1 /* bPKI_KeyNo_Sign */ + bHashLen);
  aCmdBuf[PHHAL_HW_SAMAV3_ISO7816_LC_POS + 1] = bPKI_KeyNo_Sign;

  /* Buffer the command information to exchange buffer. */
  PH_CHECK_SUCCESS_FCT(wStatus, phhalHw_SamAV3_Cmd_7816Exchange(
          pDataParams,
          PH_EXCHANGE_BUFFER_FIRST,
          aCmdBuf,
          (PHHAL_HW_SAMAV3_ISO7816_HEADER_LENGTH + 1),
          NULL,
          NULL));

  /* Buffer the Hash information and exchange to Sam hardware. */
  PH_CHECK_SUCCESS_FCT(wStatus, phhalHw_SamAV3_Cmd_7816Exchange(
          pDataParams,
          PH_EXCHANGE_BUFFER_LAST,
          pHash,
          bHashLen,
          &pResponse,
          &wRespLen));

  return PH_ADD_COMPCODE(PH_ERR_SUCCESS, PH_COMP_HAL);
}

phStatus_t
phhalHw_SamAV3_Cmd_PKI_SendSignature(phhalHw_SamAV3_DataParams_t *pDataParams,
    uint8_t **ppSignature, uint16_t *pSignatureLen)
{
  phStatus_t  PH_MEMLOC_REM wStatus = 0;
  uint8_t     PH_MEMLOC_REM aCmdBuf[PHHAL_HW_SAMAV3_ISO7816_HEADER_LENGTH];

  /* Validate the parameters. */
  PH_ASSERT_NULL_DATA_PARAM(pDataParams, PH_COMP_HAL);
  PH_ASSERT_NULL_PARAM(pSignatureLen, PH_COMP_HAL);

  /* Reset the command buffer. */
  memset(aCmdBuf, 0x00, sizeof(aCmdBuf));	/* PRQA S 3200 */

  /* Filling in ISO7816 header */
  aCmdBuf[PHHAL_HW_SAMAV3_ISO7816_CLA_POS] = PHHAL_HW_SAMAV3_ISO7816_CLA_BYTE;
  aCmdBuf[PHHAL_HW_SAMAV3_ISO7816_INS_POS] = PHHAL_HW_SAMAV3_CMD_PKI_SEND_SIGNATURE_INS;
  aCmdBuf[PHHAL_HW_SAMAV3_ISO7816_P1_POS] = PHHAL_HW_SAMAV3_ISO7816_DEFAULT_P1_BYTE;
  aCmdBuf[PHHAL_HW_SAMAV3_ISO7816_P2_POS] = PHHAL_HW_SAMAV3_ISO7816_DEFAULT_P2_BYTE;
  aCmdBuf[PHHAL_HW_SAMAV3_ISO7816_LE_NO_LC_POS] = PHHAL_HW_SAMAV3_ISO7816_DEFAULT_LE_BYTE;

  /* Frame the Cmd.PKI_SendSignature command and exchange with Sam hardware. */
  PH_CHECK_SUCCESS_FCT(wStatus, phhalHw_SamAV3_Cmd_7816Exchange(
          pDataParams,
          PH_EXCHANGE_DEFAULT,
          aCmdBuf,
          PHHAL_HW_SAMAV3_ISO7816_HEADER_LENGTH,
          ppSignature,
          pSignatureLen));

  return PH_ADD_COMPCODE(PH_ERR_SUCCESS, PH_COMP_HAL);
}

phStatus_t
phhalHw_SamAV3_Cmd_PKI_VerifySignature(phhalHw_SamAV3_DataParams_t *pDataParams,
    uint8_t bPKI_KeyNo_Verif, uint8_t bHashingAlg, uint8_t *pHash, uint8_t bHashLen,
    uint8_t *pSignature, uint16_t wSignatureLen)
{
  phStatus_t	PH_MEMLOC_REM wStatus = 0;
  uint8_t		PH_MEMLOC_REM aCmdBuf[PHHAL_HW_SAMAV3_ISO7816_HEADER_LENGTH + 1 /* bPKI_KeyNo_Verif */];
  uint8_t 	*PH_MEMLOC_REM pResponse = NULL;
  uint16_t	PH_MEMLOC_REM wRespLen = 0;
  uint8_t		PH_MEMLOC_REM bBufPos = 0;

  /* Validate the parameters. */
  PH_ASSERT_NULL_DATA_PARAM(pDataParams, PH_COMP_HAL);
  PH_ASSERT_NULL_PARAM(pHash, PH_COMP_HAL);
  PH_ASSERT_NULL_PARAM(pSignature, PH_COMP_HAL);

  /* Reset the command buffer. */
  memset(aCmdBuf, 0x00, sizeof(aCmdBuf));	/* PRQA S 3200 */

  /* Frame Cmd.PKI_VerifySignature comamnd. */
  aCmdBuf[PHHAL_HW_SAMAV3_ISO7816_CLA_POS] = PHHAL_HW_SAMAV3_ISO7816_CLA_BYTE;
  aCmdBuf[PHHAL_HW_SAMAV3_ISO7816_INS_POS] = PHHAL_HW_SAMAV3_CMD_PKI_VERIFY_SIGNATURE_INS;
  aCmdBuf[PHHAL_HW_SAMAV3_ISO7816_P1_POS] = bHashingAlg;
  aCmdBuf[PHHAL_HW_SAMAV3_ISO7816_P2_POS] = PHHAL_HW_SAMAV3_ISO7816_DEFAULT_P2_BYTE;
  aCmdBuf[PHHAL_HW_SAMAV3_ISO7816_LC_POS] = (uint8_t)(1 /* bPKI_KeyNo_Verif */ + bHashLen +
          wSignatureLen);
  aCmdBuf[PHHAL_HW_SAMAV3_ISO7816_LC_POS + 1] = bPKI_KeyNo_Verif;

  /* Update P2 information and LC byte with chaining status and length. */
  if ((1 /* bPKI_KeyNo_Verif */ + bHashLen + wSignatureLen) >
      PHHAL_HW_SAMAV3_ISO7816_MAX_LC_MULTIPLE_AESBLOCK) {
    aCmdBuf[PHHAL_HW_SAMAV3_ISO7816_P2_POS] = PHHAL_HW_SAMAV3_ISO7816_CHAINED_FRAME;
    aCmdBuf[PHHAL_HW_SAMAV3_ISO7816_LC_POS] = PHHAL_HW_SAMAV3_ISO7816_MAX_LC_MULTIPLE_AESBLOCK;
  }

  /* Buffer the command information to command buffer. */
  PH_CHECK_SUCCESS_FCT(wStatus, phhalHw_SamAV3_Cmd_7816Exchange(
          pDataParams,
          PH_EXCHANGE_BUFFER_FIRST,
          aCmdBuf,
          PHHAL_HW_SAMAV3_ISO7816_HEADER_LENGTH + 1,
          NULL,
          NULL));

  /* Buffer the Hash information to exchange buffer. */
  PH_CHECK_SUCCESS_FCT(wStatus, phhalHw_SamAV3_Cmd_7816Exchange(
          pDataParams,
          PH_EXCHANGE_BUFFER_CONT,
          pHash,
          bHashLen,
          NULL,
          NULL));

  /* Buffer Signature inforamtion to exchange buffer and exchange the bufferred information to Sam hardware. */
  if (aCmdBuf[PHHAL_HW_SAMAV3_ISO7816_P2_POS] == PHHAL_HW_SAMAV3_ISO7816_DEFAULT_P2_BYTE) {
    wStatus = phhalHw_SamAV3_Cmd_7816Exchange(
            pDataParams,
            PH_EXCHANGE_BUFFER_LAST,
            pSignature,
            wSignatureLen,
            &pResponse,
            &wRespLen);
  } else {
    /* Update the position for exchanging next chunk of signature information. */
    bBufPos = (uint8_t)(PHHAL_HW_SAMAV3_ISO7816_MAX_LC_MULTIPLE_AESBLOCK - 1 - bHashLen);

    wStatus = phhalHw_SamAV3_Cmd_7816Exchange(
            pDataParams,
            PH_EXCHANGE_BUFFER_LAST,
            pSignature,
            bBufPos,
            &pResponse,
            &wRespLen);

    /* Return the status if chaining response is not received from Sam hardware. */
    if ((wStatus & PH_ERR_MASK) != PHHAL_HW_SAMAV3_ERR_OK_CHAINING_ACTIVE) {
      return wStatus;
    }

    /* Uupdate the P1 information byte to default value and P2 infomation byte Last frame.  */
    aCmdBuf[PHHAL_HW_SAMAV3_ISO7816_P1_POS] = PHHAL_HW_SAMAV3_ISO7816_DEFAULT_P1_BYTE;
    aCmdBuf[PHHAL_HW_SAMAV3_ISO7816_P2_POS] = PHHAL_HW_SAMAV3_ISO7816_DEFAULT_P2_BYTE;
    aCmdBuf[PHHAL_HW_SAMAV3_ISO7816_LC_POS] = (uint8_t)(wSignatureLen - bBufPos);

    /* Exchange second part with lower layer */
    PH_CHECK_SUCCESS_FCT(wStatus, phhalHw_SamAV3_Cmd_7816Exchange(
            pDataParams,
            PH_EXCHANGE_BUFFER_FIRST,
            aCmdBuf,
            PHHAL_HW_SAMAV3_ISO7816_HEADER_LENGTH,
            NULL,
            NULL));

    wStatus = phhalHw_SamAV3_Cmd_7816Exchange(
            pDataParams,
            PH_EXCHANGE_BUFFER_LAST,
            pSignature + bBufPos,
            (uint8_t)(wSignatureLen - bBufPos),
            &pResponse,
            &wRespLen);
  }

  return wStatus;
}

phStatus_t
phhalHw_SamAV3_Cmd_PKI_EncipherData(phhalHw_SamAV3_DataParams_t *pDataParams, uint8_t bHashingAlg,
    uint8_t bPKI_KeyNo_Enc, uint8_t *pPlainData, uint16_t wPlainDataLen,
    uint8_t **ppEncData, uint16_t *pEncDataLen)
{
  phStatus_t	PH_MEMLOC_REM wStatus = 0;
  uint8_t		PH_MEMLOC_REM aCmdBuf[PHHAL_HW_SAMAV3_CMD_PKI_ENCIPHER_DATA_CMD_SIZE];

  /* Validate the parameters. */
  PH_ASSERT_NULL_DATA_PARAM(pDataParams, PH_COMP_HAL);
  PH_ASSERT_NULL_PARAM(pPlainData, PH_COMP_HAL);
  PH_ASSERT_NULL_PARAM(pEncDataLen, PH_COMP_HAL);

  /* Reset the command buffer. */
  memset(aCmdBuf, 0x00, sizeof(aCmdBuf));	/* PRQA S 3200 */

  /* Frame Cmd.PKI_EncipherData comamnd. */
  aCmdBuf[PHHAL_HW_SAMAV3_ISO7816_CLA_POS] = PHHAL_HW_SAMAV3_ISO7816_CLA_BYTE;
  aCmdBuf[PHHAL_HW_SAMAV3_ISO7816_INS_POS] = PHHAL_HW_SAMAV3_CMD_PKI_ENCIPHER_DATA_INS;
  aCmdBuf[PHHAL_HW_SAMAV3_ISO7816_P1_POS] = bHashingAlg;
  aCmdBuf[PHHAL_HW_SAMAV3_ISO7816_P2_POS] = PHHAL_HW_SAMAV3_ISO7816_DEFAULT_P2_BYTE;
  aCmdBuf[PHHAL_HW_SAMAV3_ISO7816_LC_POS] = (uint8_t)(1 /* bPKI_KeyNo_Enc */ + wPlainDataLen);
  aCmdBuf[PHHAL_HW_SAMAV3_ISO7816_LC_POS + 1] = bPKI_KeyNo_Enc;

  /* Buffer the command information to command buffer. */
  PH_CHECK_SUCCESS_FCT(wStatus, phhalHw_SamAV3_Cmd_7816Exchange(
          pDataParams,
          PH_EXCHANGE_BUFFER_FIRST,
          aCmdBuf,
          (uint16_t)(PHHAL_HW_SAMAV3_ISO7816_HEADER_LENGTH + 1 /* bPKI_KeyNo_Enc */),
          NULL,
          NULL));

  /* Buffer the Plain Data to exchange buffer. */
  PH_CHECK_SUCCESS_FCT(wStatus, phhalHw_SamAV3_Cmd_7816Exchange(
          pDataParams,
          PH_EXCHANGE_BUFFER_CONT,
          pPlainData,
          wPlainDataLen,
          NULL,
          NULL));

  /* Add LE byte to exchange buffer and exchange the information with Sam hardware. */
  PH_CHECK_SUCCESS_FCT(wStatus, phhalHw_SamAV3_Cmd_7816Exchange(
          pDataParams,
          PH_EXCHANGE_BUFFER_LAST,
          gaDefaultLe,
          1,
          ppEncData,
          pEncDataLen));

  return PH_ADD_COMPCODE(PH_ERR_SUCCESS, PH_COMP_HAL);
}

phStatus_t
phhalHw_SamAV3_Cmd_PKI_DecipherData(phhalHw_SamAV3_DataParams_t *pDataParams, uint16_t wOption,
    uint8_t bHashingAlg, uint8_t bPKI_KeyNo_Dec, uint8_t *pEncData,
    uint16_t wEncDataLen, uint8_t **ppPlainData, uint16_t *pPlainDataLen)
{
  phStatus_t	PH_MEMLOC_REM wStatus = 0;
  uint8_t		PH_MEMLOC_REM aCmdBuf[PHHAL_HW_SAMAV3_CMD_PKI_ENCIPHER_DATA_CMD_SIZE];
  uint8_t		PH_MEMLOC_REM bCmdLen = 0;

  /* Reset the command buffer. */
  memset(aCmdBuf, 0x00, sizeof(aCmdBuf));	/* PRQA S 3200 */

  /* Validate the parameters. */
  PH_ASSERT_NULL_DATA_PARAM(pDataParams, PH_COMP_HAL);
  PH_ASSERT_NULL_PARAM(pEncData, PH_COMP_HAL);
  PH_ASSERT_NULL_PARAM(pPlainDataLen, PH_COMP_HAL);

  /* Frame Cmd.PKI_DecipherData comamnd. */
  aCmdBuf[bCmdLen++] = PHHAL_HW_SAMAV3_ISO7816_CLA_BYTE;
  aCmdBuf[bCmdLen++] = PHHAL_HW_SAMAV3_CMD_PKI_DECIPHER_DATA_INS;
  aCmdBuf[bCmdLen++] = bHashingAlg;
  aCmdBuf[bCmdLen++] = PHHAL_HW_SAMAV3_ISO7816_LAST_FRAME;
  aCmdBuf[bCmdLen++] = PHHAL_HW_SAMAV3_ISO7816_DEFAULT_LC_BYTE;

  /* Add key number for the first frame only. */
  if ((wOption & PH_EXCHANGE_CUSTOM_BITS_MASK) ==
      PHHAL_HW_SAMAV3_CMD_PKI_DECIPHER_DATA_FIRST_FRAME) {
    aCmdBuf[bCmdLen++] = bPKI_KeyNo_Dec;
  }

  /* Set P2 information with chaining flag. */
  if ((wOption & PH_EXCHANGE_MODE_MASK) == PH_EXCHANGE_TXCHAINING) {
    aCmdBuf[PHHAL_HW_SAMAV3_ISO7816_P2_POS] = PHHAL_HW_SAMAV3_ISO7816_CHAINED_FRAME;
  }

  /* Buffer the command information to command buffer. */
  PH_CHECK_SUCCESS_FCT(wStatus, phhalHw_SamAV3_Cmd_7816Exchange(
          pDataParams,
          PH_EXCHANGE_BUFFER_FIRST,
          aCmdBuf,
          bCmdLen,
          NULL,
          NULL));

  /* Buffer the Encrypted Data to exchange buffer. */
  PH_CHECK_SUCCESS_FCT(wStatus, phhalHw_SamAV3_Cmd_7816Exchange(
          pDataParams,
          PH_EXCHANGE_BUFFER_CONT,
          pEncData,
          wEncDataLen,
          NULL,
          NULL));

  /* Update Lc information. */
  PH_CHECK_SUCCESS_FCT(wStatus, phhalHw_SamAV3_Utils_UpdateLc(pDataParams));

  /* Add LE byte to exchange buffer and exchange the information with Sam hardware. */
  wStatus = phhalHw_SamAV3_Cmd_7816Exchange(
          pDataParams,
          PH_EXCHANGE_BUFFER_LAST,
          gaDefaultLe,
          1,
          ppPlainData,
          pPlainDataLen);

  /* Update the proper status to be returned in case of chaining. */
  if ((wStatus & PH_ERR_MASK) == PHHAL_HW_SAMAV3_ERR_OK_CHAINING_ACTIVE) {
    return PH_ADD_COMPCODE(PH_ERR_SUCCESS_CHAINING, PH_COMP_HAL);
  }

  return wStatus;
}

/* ECC Commands -------------------------------------------------------------------------------------------------------- */

phStatus_t
phhalHw_SamAV3_Cmd_PKI_ImportEccKey(phhalHw_SamAV3_DataParams_t *pDataParams, uint8_t bOption,
    uint8_t bECC_KeyNo, uint16_t wECC_Set, uint8_t bECC_KeyNoCEK,
    uint8_t bECC_KeyVCEK, uint8_t bECC_RefNoKUC, uint8_t bECC_KeyNoAEK, uint8_t bECC_KeyVAEK,
    uint16_t wECC_Len, uint8_t *pECC_xy, uint8_t bECC_xyLen)
{
  phStatus_t	PH_MEMLOC_REM wStatus = 0;
  uint8_t		PH_MEMLOC_REM aCmdBuf[PHHAL_HW_SAMAV3_CMD_PKI_IMPORT_ECC_KEY_CMD_SIZE];
  uint8_t		PH_MEMLOC_REM bCmdLen = 0;
  uint8_t 	*PH_MEMLOC_REM pResponse = NULL;
  uint16_t	PH_MEMLOC_REM wRespLen = 0;

  /* Parameter validation. */
  if (bOption == PHHAL_HW_SAMAV3_CMD_PKI_UPDATE_KEY_SETTINGS_VALUE) {
    PH_ASSERT_NULL_PARAM(pECC_xy, PH_COMP_HAL);
  }

  /* Reset the command buffer and its length variable. */
  bCmdLen = 0;
  memset(aCmdBuf, 0x00, sizeof(aCmdBuf));	/* PRQA S 3200 */

  /* Frame Cmd.PKI_ImportEccKey comamnd. */
  aCmdBuf[bCmdLen++] = PHHAL_HW_SAMAV3_ISO7816_CLA_BYTE;
  aCmdBuf[bCmdLen++] = PHHAL_HW_SAMAV3_CMD_PKI_IMPORT_ECC_KEY_INS;
  aCmdBuf[bCmdLen++] = bOption;
  aCmdBuf[bCmdLen++] = PHHAL_HW_SAMAV3_ISO7816_DEFAULT_P2_BYTE;
  aCmdBuf[bCmdLen++] = PHHAL_HW_SAMAV3_CMD_PKI_IMPORT_ECC_KEY_LC_MIN;

  /* Add key information to command buffer. */
  aCmdBuf[bCmdLen++] = bECC_KeyNo;
  aCmdBuf[bCmdLen++] = (uint8_t)((wECC_Set & 0xFF00) >> 8);
  aCmdBuf[bCmdLen++] = (uint8_t)(wECC_Set & 0x00FF);
  aCmdBuf[bCmdLen++] = bECC_KeyNoCEK;
  aCmdBuf[bCmdLen++] = bECC_KeyVCEK;
  aCmdBuf[bCmdLen++] = bECC_RefNoKUC;
  aCmdBuf[bCmdLen++] = bECC_KeyNoAEK;
  aCmdBuf[bCmdLen++] = bECC_KeyVAEK;

  /* Check if only key settings should be exchanged to Sam hardware . */
  if (bOption & PHHAL_HW_SAMAV3_CMD_PKI_UPDATE_KEY_SETTINGS_ONLY) {
    /* Exchange the command information to Sam hardware. */
    PH_CHECK_SUCCESS_FCT(wStatus, phhalHw_SamAV3_Cmd_7816Exchange(
            pDataParams,
            PH_EXCHANGE_DEFAULT,
            aCmdBuf,
            bCmdLen,
            &pResponse,
            &wRespLen));
  }
  /* Add ECC_Len and ECC_xy to exchange buffer if required. */
  else {
    /* Update LC */
    aCmdBuf[PHHAL_HW_SAMAV3_ISO7816_LC_POS] += (uint8_t)(2 /* ECC_Len */ + bECC_xyLen);

    /* Add ECC_Len to command buffer. */
    aCmdBuf[bCmdLen++] = (uint8_t)((wECC_Len & 0xFF00) >> 8);
    aCmdBuf[bCmdLen++] = (uint8_t)(wECC_Len & 0x00FF);

    /* Add the command information to exchange buffer. */
    PH_CHECK_SUCCESS_FCT(wStatus, phhalHw_SamAV3_Cmd_7816Exchange(
            pDataParams,
            PH_EXCHANGE_BUFFER_FIRST,
            aCmdBuf,
            bCmdLen,
            NULL,
            NULL));

    /* Add ECC_xy information to exchange buffer and exchange the bufferred information to Sam hardware. */
    PH_CHECK_SUCCESS_FCT(wStatus, phhalHw_SamAV3_Cmd_7816Exchange(
            pDataParams,
            PH_EXCHANGE_BUFFER_LAST,
            pECC_xy,
            bECC_xyLen,
            &pResponse,
            &wRespLen));
  }

  return PH_ADD_COMPCODE(PH_ERR_SUCCESS, PH_COMP_HAL);
}

phStatus_t
phhalHw_SamAV3_Cmd_PKI_ImportEccCurve(phhalHw_SamAV3_DataParams_t *pDataParams, uint8_t bOption,
    uint8_t bECC_CurveNo, uint8_t bECC_KeyNoCCK, uint8_t bECC_KeyVCCK,
    uint8_t bECC_N, uint8_t bECC_M, uint8_t *pECC_Prime, uint8_t *pECC_ParamA, uint8_t *pECC_ParamB,
    uint8_t *pECC_Px, uint8_t *pECC_Py, uint8_t *pECC_Order)
{
  phStatus_t	PH_MEMLOC_REM wStatus = 0;
  uint8_t		PH_MEMLOC_REM aCmdBuf[PHHAL_HW_SAMAV3_CMD_PKI_IMPORT_ECC_CURVE_CMD_SIZE];
  uint8_t		PH_MEMLOC_REM bCmdLen = 0;
  uint8_t 	*PH_MEMLOC_REM pResponse = NULL;
  uint16_t	PH_MEMLOC_REM wRespLen = 0;

  /* Parameter validation. */
  if (bOption == PHHAL_HW_SAMAV3_CMD_PKI_UPDATE_CURVE_SETTINGS_VALUE) {
    PH_ASSERT_NULL_PARAM(pECC_Prime, PH_COMP_HAL);
    PH_ASSERT_NULL_PARAM(pECC_ParamA, PH_COMP_HAL);
    PH_ASSERT_NULL_PARAM(pECC_ParamB, PH_COMP_HAL);
    PH_ASSERT_NULL_PARAM(pECC_Px, PH_COMP_HAL);
    PH_ASSERT_NULL_PARAM(pECC_Py, PH_COMP_HAL);
    PH_ASSERT_NULL_PARAM(pECC_Order, PH_COMP_HAL);
  }

  /* Reset the command buffer and its length variable. */
  bCmdLen = 0;
  memset(aCmdBuf, 0x00, sizeof(aCmdBuf));	/* PRQA S 3200 */

  /* Frame Cmd.PKI_ImportEccKey comamnd. */
  aCmdBuf[bCmdLen++] = PHHAL_HW_SAMAV3_ISO7816_CLA_BYTE;
  aCmdBuf[bCmdLen++] = PHHAL_HW_SAMAV3_CMD_PKI_IMPORT_ECC_CURVE_INS;
  aCmdBuf[bCmdLen++] = bOption;
  aCmdBuf[bCmdLen++] = PHHAL_HW_SAMAV3_ISO7816_DEFAULT_P2_BYTE;
  aCmdBuf[bCmdLen++] = PHHAL_HW_SAMAV3_CMD_PKI_IMPORT_ECC_CURVE_LC_MIN;

  /* Add key information to command buffer. */
  aCmdBuf[bCmdLen++] = bECC_CurveNo;
  aCmdBuf[bCmdLen++] = bECC_KeyNoCCK;
  aCmdBuf[bCmdLen++] = bECC_KeyVCCK;

  /* Check if only key settings should be exchanged to Sam hardware . */
  if (bOption & PHHAL_HW_SAMAV3_CMD_PKI_UPDATE_CURVE_SETTINGS_ONLY) {
    /* Exchange the command information to Sam hardware. */
    PH_CHECK_SUCCESS_FCT(wStatus, phhalHw_SamAV3_Cmd_7816Exchange(
            pDataParams,
            PH_EXCHANGE_DEFAULT,
            aCmdBuf,
            bCmdLen,
            &pResponse,
            &wRespLen));
  }
  /* Add Curve values to exchange buffer if required. */
  else {
    /* Update LC */
    aCmdBuf[PHHAL_HW_SAMAV3_ISO7816_LC_POS] += (uint8_t)(2 /* ECC_N, ECC_M */ +
            (5 /* ECC_Prime, ECC_ParamA, ECC_ParamB, ECC_Px, ECC_Py, ECC_Order */ * bECC_N) + bECC_M);

    /* Add ECC_Len to command buffer. */
    aCmdBuf[bCmdLen++] = bECC_N;
    aCmdBuf[bCmdLen++] = bECC_M;

    /* Add the command information to exchange buffer. */
    PH_CHECK_SUCCESS_FCT(wStatus, phhalHw_SamAV3_Cmd_7816Exchange(
            pDataParams,
            PH_EXCHANGE_BUFFER_FIRST,
            aCmdBuf,
            bCmdLen,
            NULL,
            NULL));

    /* Add the ECC_Prime information to exchange buffer. */
    PH_CHECK_SUCCESS_FCT(wStatus, phhalHw_SamAV3_Cmd_7816Exchange(
            pDataParams,
            PH_EXCHANGE_BUFFER_CONT,
            pECC_Prime,
            bECC_N,
            NULL,
            NULL));

    /* Add the ECC_ParamA information to exchange buffer. */
    PH_CHECK_SUCCESS_FCT(wStatus, phhalHw_SamAV3_Cmd_7816Exchange(
            pDataParams,
            PH_EXCHANGE_BUFFER_CONT,
            pECC_ParamA,
            bECC_N,
            NULL,
            NULL));

    /* Add the ECC_ParamB information to exchange buffer. */
    PH_CHECK_SUCCESS_FCT(wStatus, phhalHw_SamAV3_Cmd_7816Exchange(
            pDataParams,
            PH_EXCHANGE_BUFFER_CONT,
            pECC_ParamB,
            bECC_N,
            NULL,
            NULL));

    /* Add the ECC_Px information to exchange buffer. */
    PH_CHECK_SUCCESS_FCT(wStatus, phhalHw_SamAV3_Cmd_7816Exchange(
            pDataParams,
            PH_EXCHANGE_BUFFER_CONT,
            pECC_Px,
            bECC_N,
            NULL,
            NULL));

    /* Add the ECC_Py information to exchange buffer. */
    PH_CHECK_SUCCESS_FCT(wStatus, phhalHw_SamAV3_Cmd_7816Exchange(
            pDataParams,
            PH_EXCHANGE_BUFFER_CONT,
            pECC_Py,
            bECC_N,
            NULL,
            NULL));

    /* Add ECC_Order to exchange buffer and exchange the bufferred information to Sam hardware. */
    PH_CHECK_SUCCESS_FCT(wStatus, phhalHw_SamAV3_Cmd_7816Exchange(
            pDataParams,
            PH_EXCHANGE_BUFFER_LAST,
            pECC_Order,
            bECC_M,
            &pResponse,
            &wRespLen));
  }

  return PH_ADD_COMPCODE(PH_ERR_SUCCESS, PH_COMP_HAL);
}

phStatus_t
phhalHw_SamAV3_Cmd_PKI_ExportEccPublicKey(phhalHw_SamAV3_DataParams_t *pDataParams,
    uint8_t bECC_KeyNo, uint16_t *pECC_Set, uint8_t *pECC_KeyNoCEK,
    uint8_t *pECC_KeyVCEK, uint8_t *pECC_RefNoKUC, uint8_t *pECC_KeyNoAEK, uint8_t *pECC_KeyVAEK,
    uint16_t *pECC_Len, uint8_t **ppECC_xy, uint8_t *pECC_xyLen)
{
  phStatus_t	PH_MEMLOC_REM wStatus = 0;
  uint8_t		PH_MEMLOC_REM aCmdBuf[PHHAL_HW_SAMAV3_ISO7816_HEADER_LENGTH];
  uint8_t 	*PH_MEMLOC_REM pResponse = NULL;
  uint16_t	PH_MEMLOC_REM wRespLen = 0;

  /* Validate the parameters. */
  PH_ASSERT_NULL_PARAM(pECC_Set, PH_COMP_HAL);
  PH_ASSERT_NULL_PARAM(pECC_KeyNoCEK, PH_COMP_HAL);
  PH_ASSERT_NULL_PARAM(pECC_KeyVCEK, PH_COMP_HAL);
  PH_ASSERT_NULL_PARAM(pECC_RefNoKUC, PH_COMP_HAL);
  PH_ASSERT_NULL_PARAM(pECC_KeyNoAEK, PH_COMP_HAL);
  PH_ASSERT_NULL_PARAM(pECC_KeyVAEK, PH_COMP_HAL);
  PH_ASSERT_NULL_PARAM(pECC_Len, PH_COMP_HAL);
  PH_ASSERT_NULL_PARAM(ppECC_xy, PH_COMP_HAL);
  PH_ASSERT_NULL_PARAM(pECC_xyLen, PH_COMP_HAL);

  /* Reset the command buffer. */
  memset(aCmdBuf, 0x00, sizeof(aCmdBuf));	/* PRQA S 3200 */

  /* Frame Cmd.PKI_ImportEccKey comamnd. */
  aCmdBuf[PHHAL_HW_SAMAV3_ISO7816_CLA_POS] = PHHAL_HW_SAMAV3_ISO7816_CLA_BYTE;
  aCmdBuf[PHHAL_HW_SAMAV3_ISO7816_INS_POS] = PHHAL_HW_SAMAV3_CMD_PKI_EXPORT_ECC_PUBLIC_KEY_INS;
  aCmdBuf[PHHAL_HW_SAMAV3_ISO7816_P1_POS] = bECC_KeyNo;
  aCmdBuf[PHHAL_HW_SAMAV3_ISO7816_P2_POS] = PHHAL_HW_SAMAV3_ISO7816_DEFAULT_P2_BYTE;
  aCmdBuf[PHHAL_HW_SAMAV3_ISO7816_LE_NO_LC_POS] = PHHAL_HW_SAMAV3_ISO7816_DEFAULT_LE_BYTE;

  /* Exchange the command information to Sam hardware. */
  PH_CHECK_SUCCESS_FCT(wStatus, phhalHw_SamAV3_Cmd_7816Exchange(
          pDataParams,
          PH_EXCHANGE_DEFAULT,
          aCmdBuf,
          PHHAL_HW_SAMAV3_ISO7816_HEADER_LENGTH,
          &pResponse,
          &wRespLen));

  /* Extract the information from response. */
  *pECC_Set = (uint16_t)((pResponse[0] << 8) | pResponse[1]);

  *pECC_KeyNoCEK = pResponse[2];
  *pECC_KeyVCEK = pResponse[3];

  *pECC_RefNoKUC = pResponse[4];

  *pECC_KeyNoAEK = pResponse[5];
  *pECC_KeyVAEK = pResponse[6];

  *pECC_Len = (uint16_t)((pResponse[7] << 8) | pResponse[8]);

  *ppECC_xy = &pResponse[9];
  *pECC_xyLen = (uint8_t)(wRespLen - 9);

  return PH_ADD_COMPCODE(PH_ERR_SUCCESS, PH_COMP_HAL);
}

phStatus_t
phhalHw_SamAV3_Cmd_PKI_VerifyEccSignature(phhalHw_SamAV3_DataParams_t *pDataParams,
    uint8_t bECC_KeyNo, uint8_t bECC_CurveNo, uint8_t bLen, uint8_t *pMessage,
    uint8_t *pSignature, uint16_t wSignatureLen)
{
  phStatus_t	PH_MEMLOC_REM wStatus = 0;
  uint8_t		PH_MEMLOC_REM aCmdBuf[PHHAL_HW_SAMAV3_CMD_PKI_VERIFY_ECC_SIGNATURE_CMD_SIZE];
  uint8_t		PH_MEMLOC_REM bCmdLen = 0;
  uint8_t 	*PH_MEMLOC_REM pResponse = NULL;
  uint16_t	PH_MEMLOC_REM wRespLen = 0;

  /* Validate the parameters. */
  if (bLen) {
    PH_ASSERT_NULL_PARAM(pMessage, PH_COMP_HAL);
  }

  if (wSignatureLen) {
    PH_ASSERT_NULL_PARAM(pSignature, PH_COMP_HAL);
  }

  /* Reset the command buffer and its length variable. */
  bCmdLen = 0;
  memset(aCmdBuf, 0x00, sizeof(aCmdBuf));	/* PRQA S 3200 */

  /* Frame Cmd.PKI_ImportEccKey comamnd. */
  aCmdBuf[bCmdLen++] = PHHAL_HW_SAMAV3_ISO7816_CLA_BYTE;
  aCmdBuf[bCmdLen++] = PHHAL_HW_SAMAV3_CMD_PKI_VERIFY_ECC_SIGNATURE_INS;
  aCmdBuf[bCmdLen++] = PHHAL_HW_SAMAV3_ISO7816_DEFAULT_P1_BYTE;
  aCmdBuf[bCmdLen++] = PHHAL_HW_SAMAV3_ISO7816_DEFAULT_P2_BYTE;
  aCmdBuf[bCmdLen++] = (uint8_t)(PHHAL_HW_SAMAV3_CMD_PKI_VERIFY_ECC_SIGNATURE_LC_MIN + bLen +
          wSignatureLen);

  /* Add the key and len information to command buffer. */
  aCmdBuf[bCmdLen++] = bECC_KeyNo;
  aCmdBuf[bCmdLen++] = bECC_CurveNo;
  aCmdBuf[bCmdLen++] = bLen;

  /* Add command information to exchange buffer. */
  PH_CHECK_SUCCESS_FCT(wStatus, phhalHw_SamAV3_Cmd_7816Exchange(
          pDataParams,
          PH_EXCHANGE_BUFFER_FIRST,
          aCmdBuf,
          bCmdLen,
          NULL,
          NULL));

  /* Add message to exchange buffer. */
  PH_CHECK_SUCCESS_FCT(wStatus, phhalHw_SamAV3_Cmd_7816Exchange(
          pDataParams,
          PH_EXCHANGE_BUFFER_CONT,
          pMessage,
          bLen,
          NULL,
          NULL));

  /* Add signature to exchange buffer and exchange the bufferred information to Sam hardware. */
  PH_CHECK_SUCCESS_FCT(wStatus, phhalHw_SamAV3_Cmd_7816Exchange(
          pDataParams,
          PH_EXCHANGE_BUFFER_LAST,
          pSignature,
          wSignatureLen,
          &pResponse,
          &wRespLen));

  return PH_ADD_COMPCODE(PH_ERR_SUCCESS, PH_COMP_HAL);
}

/* EMV Commands -------------------------------------------------------------------------------------------------------- */

phStatus_t
phhalHw_SamAV3_Cmd_PKI_ImportCaPk(phhalHw_SamAV3_DataParams_t *pDataParams, uint8_t bOption,
    uint8_t *pCaPkData, uint8_t bCaPkDataLen)
{
  phStatus_t	PH_MEMLOC_REM wStatus = 0;
  uint8_t		PH_MEMLOC_REM aCmdBuf[PHHAL_HW_SAMAV3_ISO7816_HEADER_LENGTH];
  uint8_t 	*PH_MEMLOC_REM pResponse = NULL;
  uint16_t	PH_MEMLOC_REM wRespLen = 0;
  uint8_t		PH_MEMLOC_REM bLastExchange = 0;
  uint8_t		PH_MEMLOC_REM bCaPkOffset = 0;
  uint8_t		PH_MEMLOC_REM bCaPkLen = 0;

  /* Validate the parameters. */
  PH_ASSERT_NULL_DATA_PARAM(pDataParams, PH_COMP_HAL);
  if (bCaPkDataLen) {
    PH_ASSERT_NULL_PARAM(pCaPkData, PH_COMP_HAL);
  }

  /* Update the CaPk buffer length to temporary length variable. */
  bCaPkLen = bCaPkDataLen;

  do {
    /* Reset the command buffer. */
    memset(aCmdBuf, 0x00, sizeof(aCmdBuf));	/* PRQA S 3200 */

    /* Frame Cmd.PKI_ImportCaPk comamnd information. */
    aCmdBuf[PHHAL_HW_SAMAV3_ISO7816_CLA_POS] = PHHAL_HW_SAMAV3_ISO7816_CLA_BYTE;
    aCmdBuf[PHHAL_HW_SAMAV3_ISO7816_INS_POS] = PHHAL_HW_SAMAV3_CMD_PKI_IMPORT_CAPK_INS;
    aCmdBuf[PHHAL_HW_SAMAV3_ISO7816_P1_POS]  = PHHAL_HW_SAMAV3_ISO7816_DEFAULT_P1_BYTE;
    aCmdBuf[PHHAL_HW_SAMAV3_ISO7816_P2_POS]  = bOption;
    aCmdBuf[PHHAL_HW_SAMAV3_ISO7816_LC_POS]  = PHHAL_HW_SAMAV3_ISO7816_DEFAULT_LC_BYTE;

    /* Buffer command information to exchange buffer. */
    PH_CHECK_SUCCESS_FCT(wStatus, phhalHw_SamAV3_Cmd_7816Exchange(
            pDataParams,
            PH_EXCHANGE_BUFFER_FIRST,
            aCmdBuf,
            PHHAL_HW_SAMAV3_ISO7816_HEADER_LENGTH,
            NULL,
            NULL));

    /* Update P1 and other informations. */
    if (bCaPkLen > 250 /* Max CaPk data that can fit in one frame. */) {
      PH_CHECK_SUCCESS_FCT(wStatus, phhalHw_SamAV3_Utils_UpdateP1(pDataParams,
              PHHAL_HW_SAMAV3_ISO7816_CHAINED_FRAME));

      /* Update the temporary CaPk buffer length. */
      bCaPkLen = 250;
    } else {
      PH_CHECK_SUCCESS_FCT(wStatus, phhalHw_SamAV3_Utils_UpdateP1(pDataParams,
              PHHAL_HW_SAMAV3_ISO7816_LAST_FRAME));

      /* Update the finished flag. */
      bLastExchange = 1;
    }

    /* Buffer CaPkData information to exchange buffer. */
    PH_CHECK_SUCCESS_FCT(wStatus, phhalHw_SamAV3_Cmd_7816Exchange(
            pDataParams,
            PH_EXCHANGE_BUFFER_CONT,
            &pCaPkData[bCaPkOffset],
            bCaPkLen,
            NULL,
            NULL));

    /* Update LC. */
    PH_CHECK_SUCCESS_FCT(wStatus, phhalHw_SamAV3_Utils_UpdateLc(pDataParams));

    /* Exchange the bufferred information to Sam hardware. */
    wStatus = phhalHw_SamAV3_Cmd_7816Exchange(
            pDataParams,
            PH_EXCHANGE_BUFFER_LAST,
            NULL,
            0,
            &pResponse,
            &wRespLen);

    /* Check for the chaining response is case of haining. */
    if ((wStatus & PH_ERR_MASK) == PHHAL_HW_SAMAV3_ERR_OK_CHAINING_ACTIVE) {
      /* Update the offset and length to be exchanged. */
      bCaPkOffset = 250 /* CaPk information exchanged in the previous frame. */;
      bCaPkLen = (uint8_t)(bCaPkDataLen - 250 /* Max CaPk data that can fit in one frame. */);
    }

    /* Check for response code other than chaining. */
    if ((wStatus & PH_ERR_MASK) != PHHAL_HW_SAMAV3_ERR_OK_CHAINING_ACTIVE) {
      PH_CHECK_SUCCESS(wStatus);
    }
  } while (!bLastExchange);

  return PH_ADD_COMPCODE(PH_ERR_SUCCESS, PH_COMP_HAL);
}

phStatus_t
phhalHw_SamAV3_Cmd_PKI_ImportCaPkOffline(phhalHw_SamAV3_DataParams_t *pDataParams,
    uint8_t bReceiveOfflineAck, uint8_t bOption, uint8_t *pOfflineCryptogram,
    uint8_t bOfflineCryptogramLen, uint8_t **ppOfflineAck, uint16_t *pOfflineAckLen)
{
  phStatus_t	PH_MEMLOC_REM wStatus = 0;
  uint8_t		PH_MEMLOC_REM aCmdBuf[PHHAL_HW_SAMAV3_ISO7816_HEADER_LENGTH];
  uint8_t		PH_MEMLOC_REM bLastExchange = 0;
  uint8_t		PH_MEMLOC_REM bOfflineCryptOffset = 0;
  uint8_t		PH_MEMLOC_REM bOfflineCryptoLen = 0;

  /* Validate the parameters. */
  PH_ASSERT_NULL_DATA_PARAM(pDataParams, PH_COMP_HAL);
  if (bOfflineCryptogramLen) {
    PH_ASSERT_NULL_PARAM(pOfflineCryptogram, PH_COMP_HAL);
  }
  if (bReceiveOfflineAck) {
    PH_ASSERT_NULL_PARAM(pOfflineAckLen, PH_COMP_HAL);
  }
  if (bReceiveOfflineAck > PHHAL_HW_SAMAV3_CMD_PKI_OFFLINE_ACK_RECEPTION_ON) {
    return PH_ADD_COMPCODE(PH_ERR_INVALID_PARAMETER, PH_COMP_HAL);
  }

  /* Update the OfflineCryptogram buffer length to temporary length variable. */
  bOfflineCryptoLen = bOfflineCryptogramLen;

  do {
    /* Reset the command buffer. */
    memset(aCmdBuf, 0x00, sizeof(aCmdBuf));	/* PRQA S 3200 */

    /* Frame Cmd.PKI_ImportCaPkOffline comamnd information. */
    aCmdBuf[PHHAL_HW_SAMAV3_ISO7816_CLA_POS] = PHHAL_HW_SAMAV3_ISO7816_CLA_BYTE;
    aCmdBuf[PHHAL_HW_SAMAV3_ISO7816_INS_POS] = PHHAL_HW_SAMAV3_CMD_PKI_IMPORT_CAPK_INS;
    aCmdBuf[PHHAL_HW_SAMAV3_ISO7816_P1_POS]  = PHHAL_HW_SAMAV3_ISO7816_DEFAULT_P1_BYTE;
    aCmdBuf[PHHAL_HW_SAMAV3_ISO7816_P2_POS]  = bOption;
    aCmdBuf[PHHAL_HW_SAMAV3_ISO7816_LC_POS]  = PHHAL_HW_SAMAV3_ISO7816_DEFAULT_LC_BYTE;

    /* Buffer command information to exchange buffer. */
    PH_CHECK_SUCCESS_FCT(wStatus, phhalHw_SamAV3_Cmd_7816Exchange(
            pDataParams,
            PH_EXCHANGE_BUFFER_FIRST,
            aCmdBuf,
            PHHAL_HW_SAMAV3_ISO7816_HEADER_LENGTH,
            NULL,
            NULL));

    /* Update P1 and other informations. */
    if (bOfflineCryptoLen > 250 /* Max Offline Cryptogram data that can fit in one frame. */) {
      PH_CHECK_SUCCESS_FCT(wStatus, phhalHw_SamAV3_Utils_UpdateP1(pDataParams,
              PHHAL_HW_SAMAV3_ISO7816_CHAINED_FRAME));

      /* Update the temporary Offline Cryptogram buffer length. */
      bOfflineCryptoLen = 250;
    } else {
      PH_CHECK_SUCCESS_FCT(wStatus, phhalHw_SamAV3_Utils_UpdateP1(pDataParams,
              PHHAL_HW_SAMAV3_ISO7816_LAST_FRAME));

      /* Update the finished flag. */
      bLastExchange = 1;
    }

    /* Buffer OfflineCryptogram information to exchange buffer. */
    PH_CHECK_SUCCESS_FCT(wStatus, phhalHw_SamAV3_Cmd_7816Exchange(
            pDataParams,
            PH_EXCHANGE_BUFFER_CONT,
            &pOfflineCryptogram[bOfflineCryptOffset],
            bOfflineCryptoLen,
            NULL,
            NULL));

    /* Update LC. */
    PH_CHECK_SUCCESS_FCT(wStatus, phhalHw_SamAV3_Utils_UpdateLc(pDataParams));

    /* Buffer LE to exchange buffer. */
    if (bReceiveOfflineAck) {
      PH_CHECK_SUCCESS_FCT(wStatus, phhalHw_SamAV3_Cmd_7816Exchange(
              pDataParams,
              PH_EXCHANGE_BUFFER_CONT,
              gaDefaultLe,
              1,
              NULL,
              NULL));
    }

    /* Exchange the bufferred information to Sam hardware. */
    wStatus = phhalHw_SamAV3_Cmd_7816Exchange(
            pDataParams,
            PH_EXCHANGE_BUFFER_LAST,
            NULL,
            0,
            ppOfflineAck,
            pOfflineAckLen);

    /* Check for the chaining response is case of haining. */
    if ((wStatus & PH_ERR_MASK) == PHHAL_HW_SAMAV3_ERR_OK_CHAINING_ACTIVE) {
      /* Update the offset and length to be exchanged. */
      bOfflineCryptOffset = 250 /* Offline Crpytogram information exchanged in the previous frame. */;
      bOfflineCryptoLen = (uint8_t)(bOfflineCryptogramLen -
              250 /* Max Offline Crpytogram data that can fit in one frame. */);
    }

    /* Check for response code other than chaining. */
    if ((wStatus & PH_ERR_MASK) != PHHAL_HW_SAMAV3_ERR_OK_CHAINING_ACTIVE) {
      PH_CHECK_SUCCESS(wStatus);
    }
  } while (!bLastExchange);

  return PH_ADD_COMPCODE(PH_ERR_SUCCESS, PH_COMP_HAL);
}

phStatus_t
phhalHw_SamAV3_Cmd_PKI_RemoveCaPk(phhalHw_SamAV3_DataParams_t *pDataParams, uint8_t *pRID,
    uint8_t bPkID)
{
  phStatus_t	PH_MEMLOC_REM wStatus = 0;
  uint8_t		PH_MEMLOC_REM aCmdBuf[PHHAL_HW_SAMAV3_ISO7816_HEADER_LENGTH + 6 /* RID and PkID */];
  uint8_t		PH_MEMLOC_REM bCmdLen = 0;
  uint8_t 	*PH_MEMLOC_REM pResponse = NULL;
  uint16_t	PH_MEMLOC_REM wRespLen = 0;

  /* Validate the parameters. */
  PH_ASSERT_NULL_DATA_PARAM(pDataParams, PH_COMP_HAL);
  PH_ASSERT_NULL_PARAM(pRID, PH_COMP_HAL);

  /* Reset the command buffer and its length variable. */
  bCmdLen = 0;
  memset(aCmdBuf, 0x00, sizeof(aCmdBuf));	/* PRQA S 3200 */

  /* Frame Cmd.PKI_RemoveCaPk comamnd information. */
  aCmdBuf[bCmdLen++] = PHHAL_HW_SAMAV3_ISO7816_CLA_BYTE;
  aCmdBuf[bCmdLen++] = PHHAL_HW_SAMAV3_CMD_PKI_REMOVE_CAPK_INS;
  aCmdBuf[bCmdLen++] = PHHAL_HW_SAMAV3_ISO7816_DEFAULT_P1_BYTE;
  aCmdBuf[bCmdLen++] = PHHAL_HW_SAMAV3_ISO7816_DEFAULT_P2_BYTE;
  aCmdBuf[bCmdLen++] = 6 /* RID and PkID */;

  /* Add the RID information to command buffer. */
  memcpy(&aCmdBuf[bCmdLen], pRID, 5);		/* PRQA S 3200 */
  bCmdLen += 5 /* RID length. */;

  /* Add PkID to command buffer. */
  aCmdBuf[bCmdLen++] = bPkID;

  /* Exchange the command information to Sam hardware. */
  PH_CHECK_SUCCESS_FCT(wStatus, phhalHw_SamAV3_Cmd_7816Exchange(
          pDataParams,
          PH_EXCHANGE_DEFAULT,
          aCmdBuf,
          bCmdLen,
          &pResponse,
          &wRespLen));

  return PH_ADD_COMPCODE(PH_ERR_SUCCESS, PH_COMP_HAL);
}

phStatus_t
phhalHw_SamAV3_Cmd_PKI_RemoveCaPkOffline(phhalHw_SamAV3_DataParams_t *pDataParams,
    uint8_t bReceiveOfflineAck, uint8_t *pOfflineCryptogram, uint8_t bOfflineCryptogramLen,
    uint8_t **ppOfflineAck, uint16_t *pOfflineAckLen)
{
  phStatus_t	PH_MEMLOC_REM wStatus = 0;
  uint8_t		PH_MEMLOC_REM aCmdBuf[PHHAL_HW_SAMAV3_ISO7816_HEADER_LENGTH];

  /* Validate the parameters. */
  PH_ASSERT_NULL_DATA_PARAM(pDataParams, PH_COMP_HAL);
  if (bOfflineCryptogramLen) {
    PH_ASSERT_NULL_PARAM(pOfflineCryptogram, PH_COMP_HAL);
  }
  if (bReceiveOfflineAck) {
    PH_ASSERT_NULL_PARAM(pOfflineAckLen, PH_COMP_HAL);
  }
  if (bReceiveOfflineAck > PHHAL_HW_SAMAV3_CMD_PKI_OFFLINE_ACK_RECEPTION_ON) {
    return PH_ADD_COMPCODE(PH_ERR_INVALID_PARAMETER, PH_COMP_HAL);
  }

  /* Reset the command buffer. */
  memset(aCmdBuf, 0x00, sizeof(aCmdBuf));	/* PRQA S 3200 */

  /* Frame Cmd.PKI_RemoveCaPkOffline comamnd information. */
  aCmdBuf[PHHAL_HW_SAMAV3_ISO7816_CLA_POS] = PHHAL_HW_SAMAV3_ISO7816_CLA_BYTE;
  aCmdBuf[PHHAL_HW_SAMAV3_ISO7816_INS_POS] = PHHAL_HW_SAMAV3_CMD_PKI_REMOVE_CAPK_INS;
  aCmdBuf[PHHAL_HW_SAMAV3_ISO7816_P1_POS]  = PHHAL_HW_SAMAV3_ISO7816_DEFAULT_P1_BYTE;
  aCmdBuf[PHHAL_HW_SAMAV3_ISO7816_P2_POS]  = PHHAL_HW_SAMAV3_ISO7816_DEFAULT_P2_BYTE;
  aCmdBuf[PHHAL_HW_SAMAV3_ISO7816_LC_POS]  = bOfflineCryptogramLen;

  /* Buffer the command information to exchange buffer. */
  PH_CHECK_SUCCESS_FCT(wStatus, phhalHw_SamAV3_Cmd_7816Exchange(
          pDataParams,
          PH_EXCHANGE_BUFFER_FIRST,
          aCmdBuf,
          PHHAL_HW_SAMAV3_ISO7816_HEADER_LENGTH,
          NULL,
          NULL));

  /* Buffer Offline Cryptogram information to exchange buffer. */
  PH_CHECK_SUCCESS_FCT(wStatus, phhalHw_SamAV3_Cmd_7816Exchange(
          pDataParams,
          PH_EXCHANGE_BUFFER_CONT,
          pOfflineCryptogram,
          bOfflineCryptogramLen,
          NULL,
          NULL));

  /* Add LE to exchange buffer is OfflineAck is required. */
  if (bReceiveOfflineAck) {
    /* Buffer the OfflineMAC information to exchange buffer. */
    PH_CHECK_SUCCESS_FCT(wStatus, phhalHw_SamAV3_Cmd_7816Exchange(
            pDataParams,
            PH_EXCHANGE_BUFFER_CONT,
            gaDefaultLe,
            1,
            NULL,
            NULL));
  }

  /* Exchange the bufferred information to Sam hardware. */
  PH_CHECK_SUCCESS_FCT(wStatus, phhalHw_SamAV3_Cmd_7816Exchange(
          pDataParams,
          PH_EXCHANGE_BUFFER_LAST,
          NULL,
          0,
          ppOfflineAck,
          pOfflineAckLen));

  return PH_ADD_COMPCODE(PH_ERR_SUCCESS, PH_COMP_HAL);
}

phStatus_t
phhalHw_SamAV3_Cmd_PKI_ExportCaPk(phhalHw_SamAV3_DataParams_t *pDataParams, uint16_t wOption,
    uint8_t *pRID, uint8_t bPkID, uint8_t **ppKeyEntry, uint16_t *pKeyEntryLen)
{
  phStatus_t	PH_MEMLOC_REM wStatus = 0;
  uint8_t		PH_MEMLOC_REM aCmdBuf[PHHAL_HW_SAMAV3_ISO7816_HEADER_LENGTH + 6 /* RID, PkID */];
  uint8_t		PH_MEMLOC_REM bCmdLen = 0;

  /* Verify the parameter. */
  PH_ASSERT_NULL_DATA_PARAM(pDataParams, PH_COMP_HAL);
  if ((wOption & PH_EXCHANGE_BUFFER_MASK) == PH_EXCHANGE_DEFAULT) {
    PH_ASSERT_NULL_PARAM(pRID, PH_COMP_HAL);
  }
  PH_ASSERT_NULL_PARAM(pKeyEntryLen, PH_COMP_HAL);

  /* Reset the command buffer and its length. */
  bCmdLen = 0;
  memset(aCmdBuf, 0x00, sizeof(aCmdBuf));	/* PRQA S 3200 */

  /* Frame Cmd.PKI_ExportCaPk command information. */
  aCmdBuf[bCmdLen++]	= PHHAL_HW_SAMAV3_ISO7816_CLA_BYTE;
  aCmdBuf[bCmdLen++]	= PHHAL_HW_SAMAV3_CMD_PKI_EXPORT_CAPK_INS;
  aCmdBuf[bCmdLen++]	= (uint8_t)(wOption & PHHAL_HW_SAMAV3_CMD_PKI_EXPORT_KEY_SETTINGS_ONLY);
  aCmdBuf[bCmdLen++]	= PHHAL_HW_SAMAV3_ISO7816_DEFAULT_P2_BYTE;

  /* Add LC is the option if not chaining. */
  if ((wOption & PH_EXCHANGE_BUFFER_MASK) == PH_EXCHANGE_DEFAULT) {
    /* Update LC. */
    aCmdBuf[bCmdLen++]	= 6 /* RID, PkID */;

    /* Add RID to exchange buffer. */
    memcpy(&aCmdBuf[bCmdLen], pRID, 5);		/* PRQA S 3200 */
    bCmdLen += 5 /* RID length. */;

    /* Add PkID to command buffer. */
    aCmdBuf[bCmdLen++] = bPkID;
  }

  /* Buffer the command information to exchange buffer. */
  PH_CHECK_SUCCESS_FCT(wStatus, phhalHw_SamAV3_Cmd_7816Exchange(
          pDataParams,
          PH_EXCHANGE_BUFFER_FIRST,
          aCmdBuf,
          bCmdLen,
          NULL,
          NULL));

  /* Buffer Le to exchange buffer and exchange the bufferred information to SAM hardware. */
  wStatus = phhalHw_SamAV3_Cmd_7816Exchange(
          pDataParams,
          PH_EXCHANGE_BUFFER_LAST,
          gaDefaultLe,
          1,
          ppKeyEntry,
          pKeyEntryLen);

  /* Return the chaining code. */
  if ((wStatus & PH_ERR_MASK) == PHHAL_HW_SAMAV3_ERR_OK_CHAINING_ACTIVE) {
    return PH_ADD_COMPCODE(PH_ERR_SUCCESS_CHAINING, PH_COMP_HAL);
  }

  return wStatus;
}

phStatus_t
phhalHw_SamAV3_Cmd_PKI_LoadIssuerPk(phhalHw_SamAV3_DataParams_t *pDataParams, uint8_t bLFI,
    uint16_t wOption, uint8_t *pData, uint8_t bDataLen, uint8_t *pIssureID,
    uint8_t *pExpDate, uint8_t *pSerialNo)
{
  phStatus_t	PH_MEMLOC_REM wStatus = 0;
  uint8_t		PH_MEMLOC_REM aCmdBuf[PHHAL_HW_SAMAV3_ISO7816_HEADER_LENGTH];
  uint8_t 	*PH_MEMLOC_REM pResponse = NULL;
  uint16_t	PH_MEMLOC_REM wRespLen = 0;

  /* Validate the parameters. */
  PH_ASSERT_NULL_DATA_PARAM(pDataParams, PH_COMP_HAL);
  if (bDataLen) {
    PH_ASSERT_NULL_PARAM(pData, PH_COMP_HAL);
  }

  if (((wOption & PH_EXCHANGE_BUFFER_MASK) == PH_EXCHANGE_DEFAULT) ||
      ((wOption & PH_EXCHANGE_BUFFER_MASK) == PH_EXCHANGE_BUFFER_LAST)) {
    PH_ASSERT_NULL_PARAM(pIssureID, PH_COMP_HAL);
    PH_ASSERT_NULL_PARAM(pExpDate, PH_COMP_HAL);
    PH_ASSERT_NULL_PARAM(pSerialNo, PH_COMP_HAL);
  }

  /* Buffer the command information and initial payload information to exchange buffer. */
  if (((wOption & PH_EXCHANGE_BUFFER_MASK) == PH_EXCHANGE_DEFAULT) ||
      ((wOption & PH_EXCHANGE_BUFFER_MASK) == PH_EXCHANGE_BUFFER_FIRST)) {
    /* Reset the command buffer. */
    memset(aCmdBuf, 0x00, sizeof(aCmdBuf));	/* PRQA S 3200 */

    /* Frame Cmd.PKI_LoadIssuerPk comamnd information. */
    aCmdBuf[PHHAL_HW_SAMAV3_ISO7816_CLA_POS] = PHHAL_HW_SAMAV3_ISO7816_CLA_BYTE;
    aCmdBuf[PHHAL_HW_SAMAV3_ISO7816_CLA_POS] = PHHAL_HW_SAMAV3_CMD_PKI_LOAD_ISSUER_PK_INS;
    aCmdBuf[PHHAL_HW_SAMAV3_ISO7816_P1_POS]  = bLFI;
    aCmdBuf[PHHAL_HW_SAMAV3_ISO7816_P2_POS]  = PHHAL_HW_SAMAV3_ISO7816_DEFAULT_P2_BYTE;
    aCmdBuf[PHHAL_HW_SAMAV3_ISO7816_LC_POS]  = PHHAL_HW_SAMAV3_ISO7816_DEFAULT_LC_BYTE;

    /* Buffer command information to exchange buffer. */
    PH_CHECK_SUCCESS_FCT(wStatus, phhalHw_SamAV3_Cmd_7816Exchange(
            pDataParams,
            PH_EXCHANGE_BUFFER_FIRST,
            aCmdBuf,
            PHHAL_HW_SAMAV3_ISO7816_HEADER_LENGTH,
            NULL,
            NULL));

    /* Buffer intial payload to exchange buffer. */
    PH_CHECK_SUCCESS_FCT(wStatus, phhalHw_SamAV3_Cmd_7816Exchange(
            pDataParams,
            PH_EXCHANGE_BUFFER_CONT,
            pData,
            bDataLen,
            NULL,
            NULL));
  }

  /* Buffer the intermediate payload information to exchange buffer. */
  if ((wOption & PH_EXCHANGE_BUFFER_MASK) == PH_EXCHANGE_BUFFER_CONT) {
    PH_CHECK_SUCCESS_FCT(wStatus, phhalHw_SamAV3_Cmd_7816Exchange(
            pDataParams,
            PH_EXCHANGE_BUFFER_CONT,
            pData,
            bDataLen,
            NULL,
            NULL));
  }

  /* Buffer final Remainder information to exchange buffer and exchange the bufferred information to SAM hardware. */
  if (((wOption & PH_EXCHANGE_BUFFER_MASK) == PH_EXCHANGE_DEFAULT) ||
      ((wOption & PH_EXCHANGE_BUFFER_MASK) == PH_EXCHANGE_BUFFER_LAST)) {
    /* Buffer the final payload information to exchange buffer. */
    if ((wOption & PH_EXCHANGE_BUFFER_MASK) != PH_EXCHANGE_DEFAULT) {
      PH_CHECK_SUCCESS_FCT(wStatus, phhalHw_SamAV3_Cmd_7816Exchange(
              pDataParams,
              PH_EXCHANGE_BUFFER_CONT,
              pData,
              bDataLen,
              NULL,
              NULL));
    }

    /* Update LC. */
    PH_CHECK_SUCCESS_FCT(wStatus, phhalHw_SamAV3_Utils_UpdateLc(pDataParams));

    /* Buffer LE to exchange buffer and exchange the bufferred information to Sam hardware. */
    wStatus = phhalHw_SamAV3_Cmd_7816Exchange(
            pDataParams,
            PH_EXCHANGE_BUFFER_LAST,
            gaDefaultLe,
            1,
            &pResponse,
            &wRespLen);

    /* Return the chaining code. */
    if ((wStatus & PH_ERR_MASK) == PHHAL_HW_SAMAV3_ERR_OK_CHAINING_ACTIVE) {
      return PH_ADD_COMPCODE(PH_ERR_SUCCESS_CHAINING, PH_COMP_HAL);
    }

    /* Extract the IssuerID, ExpDate and SerialNo if status is success. */
    if ((wStatus & PH_ERR_MASK) == PH_ERR_SUCCESS) {
      /* Verify the response length before extracting the informations.
       * 9 => IssuerID (4 byte), ExpData (2byte) and SerialNo (3 byte)
       */
      if (wRespLen != 9) {
        return PH_ADD_COMPCODE(PH_ERR_PROTOCOL_ERROR, PH_COMP_HAL);
      }

      memcpy(pIssureID, &pResponse[0], 4);		/* PRQA S 3200 */
      memcpy(pExpDate, &pResponse[4], 2);			/* PRQA S 3200 */
      memcpy(pSerialNo, &pResponse[6], 3);		/* PRQA S 3200 */
    }
  }

  return wStatus;
}

phStatus_t
phhalHw_SamAV3_Cmd_PKI_LoadIccPk(phhalHw_SamAV3_DataParams_t *pDataParams, uint8_t bLFI,
    uint16_t wOption, uint8_t *pData, uint8_t bDataLen, uint8_t *pPAN, uint8_t *pExpDate,
    uint8_t *pSerialNo, uint8_t *pAlgoPk)
{
  phStatus_t	PH_MEMLOC_REM wStatus = 0;
  uint8_t		PH_MEMLOC_REM aCmdBuf[PHHAL_HW_SAMAV3_ISO7816_HEADER_LENGTH];
  uint8_t 	*PH_MEMLOC_REM pResponse = NULL;
  uint16_t	PH_MEMLOC_REM wRespLen = 0;

  /* Validate the parameters. */
  PH_ASSERT_NULL_DATA_PARAM(pDataParams, PH_COMP_HAL);
  if (bDataLen) {
    PH_ASSERT_NULL_PARAM(pData, PH_COMP_HAL);
  }

  if (((wOption & PH_EXCHANGE_BUFFER_MASK) == PH_EXCHANGE_DEFAULT) ||
      ((wOption & PH_EXCHANGE_BUFFER_MASK) == PH_EXCHANGE_BUFFER_LAST)) {
    PH_ASSERT_NULL_PARAM(pPAN, PH_COMP_HAL);
    PH_ASSERT_NULL_PARAM(pExpDate, PH_COMP_HAL);
    PH_ASSERT_NULL_PARAM(pSerialNo, PH_COMP_HAL);
    PH_ASSERT_NULL_PARAM(pAlgoPk, PH_COMP_HAL);
  }

  /* Buffer the command information and initial CaPk data information to exchange buffer. */
  if (((wOption & PH_EXCHANGE_BUFFER_MASK) == PH_EXCHANGE_DEFAULT) ||
      ((wOption & PH_EXCHANGE_BUFFER_MASK) == PH_EXCHANGE_BUFFER_FIRST)) {
    /* Reset the command buffer. */
    memset(aCmdBuf, 0x00, sizeof(aCmdBuf));	/* PRQA S 3200 */

    /* Frame Cmd.PKI_LoadIccPk comamnd information. */
    aCmdBuf[PHHAL_HW_SAMAV3_ISO7816_CLA_POS] = PHHAL_HW_SAMAV3_ISO7816_CLA_BYTE;
    aCmdBuf[PHHAL_HW_SAMAV3_ISO7816_INS_POS] = PHHAL_HW_SAMAV3_CMD_PKI_LOAD_ICC_PK_INS;
    aCmdBuf[PHHAL_HW_SAMAV3_ISO7816_P1_POS]  = bLFI;
    aCmdBuf[PHHAL_HW_SAMAV3_ISO7816_P2_POS]  = PHHAL_HW_SAMAV3_ISO7816_DEFAULT_P2_BYTE;
    aCmdBuf[PHHAL_HW_SAMAV3_ISO7816_LC_POS]  = PHHAL_HW_SAMAV3_ISO7816_DEFAULT_LC_BYTE;

    /* Buffer command information to exchange buffer. */
    PH_CHECK_SUCCESS_FCT(wStatus, phhalHw_SamAV3_Cmd_7816Exchange(
            pDataParams,
            PH_EXCHANGE_BUFFER_FIRST,
            aCmdBuf,
            PHHAL_HW_SAMAV3_ISO7816_HEADER_LENGTH,
            NULL,
            NULL));

    /* Buffer inital payload information to exchange buffer. */
    PH_CHECK_SUCCESS_FCT(wStatus, phhalHw_SamAV3_Cmd_7816Exchange(
            pDataParams,
            PH_EXCHANGE_BUFFER_CONT,
            pData,
            bDataLen,
            NULL,
            NULL));
  }

  /* Buffer the intermediate payload information to exchange buffer. */
  if ((wOption & PH_EXCHANGE_BUFFER_MASK) == PH_EXCHANGE_BUFFER_CONT) {
    PH_CHECK_SUCCESS_FCT(wStatus, phhalHw_SamAV3_Cmd_7816Exchange(
            pDataParams,
            PH_EXCHANGE_BUFFER_CONT,
            pData,
            bDataLen,
            NULL,
            NULL));
  }

  /* Buffer final payload information to exchange buffer and exchange the bufferred information to SAM hardware. */
  if (((wOption & PH_EXCHANGE_BUFFER_MASK) == PH_EXCHANGE_DEFAULT) ||
      ((wOption & PH_EXCHANGE_BUFFER_MASK) == PH_EXCHANGE_BUFFER_LAST)) {
    /* Buffer the final payload information to exchange buffer. */
    if ((wOption & PH_EXCHANGE_BUFFER_MASK) != PH_EXCHANGE_DEFAULT) {
      PH_CHECK_SUCCESS_FCT(wStatus, phhalHw_SamAV3_Cmd_7816Exchange(
              pDataParams,
              PH_EXCHANGE_BUFFER_CONT,
              pData,
              bDataLen,
              NULL,
              NULL));
    }

    /* Update LC. */
    PH_CHECK_SUCCESS_FCT(wStatus, phhalHw_SamAV3_Utils_UpdateLc(pDataParams));

    /* Buffer LE to exchange buffer and exchange the bufferred information to Sam hardware. */
    wStatus = phhalHw_SamAV3_Cmd_7816Exchange(
            pDataParams,
            PH_EXCHANGE_BUFFER_LAST,
            gaDefaultLe,
            1,
            &pResponse,
            &wRespLen);

    /* Return the chaining code. */
    if ((wStatus & PH_ERR_MASK) == PHHAL_HW_SAMAV3_ERR_OK_CHAINING_ACTIVE) {
      return PH_ADD_COMPCODE(PH_ERR_SUCCESS_CHAINING, PH_COMP_HAL);
    }

    /* Extract the PAN, ExpDate, SerialNo and AlgoPk if status is success. */
    if ((wStatus & PH_ERR_MASK) == PH_ERR_SUCCESS) {
      /* Verify the response length before extracting the informations.
       * 16 => PAN (10 byte), ExpData (2byte), SerialNo (3 byte) and AlgoPk (1byte)
       */
      if (wRespLen != 16) {
        return PH_ADD_COMPCODE(PH_ERR_PROTOCOL_ERROR, PH_COMP_HAL);
      }

      memcpy(pPAN, &pResponse[0], 10);		/* PRQA S 3200 */
      memcpy(pExpDate, &pResponse[10], 2);	/* PRQA S 3200 */
      memcpy(pSerialNo, &pResponse[12], 3);	/* PRQA S 3200 */
      memcpy(pAlgoPk, &pResponse[15], 1);		/* PRQA S 3200 */
    }
  }

  return wStatus;
}

/*************************************************************************************************************************/
/*********************************************** Virtual Card and Proximity **********************************************/
/*************************************************************************************************************************/

/* S - Mode Commands --------------------------------------------------------------------------------------------------- */

phStatus_t
phhalHw_SamAV3_Cmd_SAM_SelectVC(phhalHw_SamAV3_DataParams_t *pDataParams, uint8_t bOption,
    uint8_t bEncKeyNo, uint8_t bEncKeyVer, uint8_t bMacKeyNo,
    uint8_t bMacKeyVer, uint8_t *pData, uint8_t bDataLen, uint8_t *pDivInput, uint8_t  bDivInputLen,
    uint8_t **ppResponse, uint16_t *pRespLen)
{
  phStatus_t	PH_MEMLOC_REM wStatus = 0;
  uint8_t		PH_MEMLOC_REM aCmdBuf[PHHAL_HW_SAMAV3_ISO7816_HEADER_LENGTH + 4 /* Key information */];
  uint8_t		PH_MEMLOC_REM bCmdLen = 0;

  /* Validate the parameters. */
  PH_ASSERT_NULL_DATA_PARAM(pDataParams, PH_COMP_HAL);
  PH_ASSERT_NULL_PARAM(pData, PH_COMP_HAL);
  PH_ASSERT_NULL_PARAM(pRespLen, PH_COMP_HAL);
  if (bDivInputLen && (bOption != PHHAL_HW_SAMAV3_CMD_SELECT_DIV_DEFAULT)) {
    PH_ASSERT_NULL_PARAM(pDivInput, PH_COMP_HAL);
  }

  /* Reset the command buffer and its length. */
  bCmdLen = 0;
  memset(aCmdBuf, 0x00, sizeof(aCmdBuf));	/* PRQA S 3200 */

  /* Frame Cmd.SAM_SelectVC command information. */
  aCmdBuf[bCmdLen++] = PHHAL_HW_SAMAV3_ISO7816_CLA_BYTE;
  aCmdBuf[bCmdLen++] = PHHAL_HW_SAMAV3_CMD_SAM_SELECT_VC_INS;
  aCmdBuf[bCmdLen++] = bOption;
  aCmdBuf[bCmdLen++] = PHHAL_HW_SAMAV3_ISO7816_DEFAULT_P2_BYTE;
  aCmdBuf[bCmdLen++] = PHHAL_HW_SAMAV3_ISO7816_DEFAULT_LC_BYTE;

  /* Append the Key number and Key version. */
  aCmdBuf[bCmdLen++] = bEncKeyNo;
  aCmdBuf[bCmdLen++] = bEncKeyVer;
  aCmdBuf[bCmdLen++] = bMacKeyNo;
  aCmdBuf[bCmdLen++] = bMacKeyVer;

  /* Buffer command information to exchange buffer. */
  PH_CHECK_SUCCESS_FCT(wStatus, phhalHw_SamAV3_Cmd_7816Exchange(
          pDataParams,
          PH_EXCHANGE_BUFFER_FIRST,
          aCmdBuf,
          bCmdLen,
          NULL,
          NULL));

  /* Buffer data information to exchange buffer. */
  PH_CHECK_SUCCESS_FCT(wStatus, phhalHw_SamAV3_Cmd_7816Exchange(
          pDataParams,
          PH_EXCHANGE_BUFFER_CONT,
          pData,
          bDataLen,
          NULL,
          NULL));

  /* Buffer the diversification input information to command buffer. */
  PH_CHECK_SUCCESS_FCT(wStatus, phhalHw_SamAV3_Cmd_7816Exchange(
          pDataParams,
          PH_EXCHANGE_BUFFER_CONT,
          pDivInput,
          bDivInputLen,
          NULL,
          NULL));

  /* Update LC. */
  PH_CHECK_SUCCESS_FCT(wStatus, phhalHw_SamAV3_Utils_UpdateLc(pDataParams));

  /* Buffer LE and exchange the bufferred information to SAM hardware. */
  PH_CHECK_SUCCESS_FCT(wStatus, phhalHw_SamAV3_Cmd_7816Exchange(
          pDataParams,
          PH_EXCHANGE_BUFFER_LAST,
          gaDefaultLe,
          1,
          ppResponse,
          pRespLen));

  return PH_ADD_COMPCODE(PH_ERR_SUCCESS, PH_COMP_HAL);
}

phStatus_t
phhalHw_SamAV3_Cmd_SAM_ProximityCheck_Part1(phhalHw_SamAV3_DataParams_t *pDataParams,
    uint8_t  bOption, uint8_t  bKeyNo, uint8_t  bKeyVer,
    uint8_t *pPPCData, uint8_t  bPPCDataLen, uint8_t *pPCData, uint8_t  bPCDataLen,
    uint8_t *pDivInput, uint8_t bDivInputLen, uint8_t **ppMac, uint16_t *pMacLen)
{
  phStatus_t	PH_MEMLOC_REM wStatus = 0;
  uint8_t		PH_MEMLOC_REM aCmdBuff[PHHAL_HW_SAMAV3_ISO7816_HEADER_LENGTH +
                                            3 /* Key No, Key Ver and PPC Data Length */];
  uint8_t		PH_MEMLOC_REM bCmdLen = 0;

  /* Validate the parameters. */
  PH_ASSERT_NULL_DATA_PARAM(pDataParams, PH_COMP_HAL);
  PH_ASSERT_NULL_PARAM(pPPCData, PH_COMP_HAL);
  PH_ASSERT_NULL_PARAM(pPCData, PH_COMP_HAL);
  if (bOption) {
    PH_ASSERT_NULL_PARAM(pDivInput, PH_COMP_HAL);
  }
  PH_ASSERT_NULL_PARAM(pMacLen, PH_COMP_HAL);

  /* Reset the command buffer and its length. */
  bCmdLen = 0;
  memset(aCmdBuff, 0x00, sizeof(aCmdBuff));	/* PRQA S 3200 */

  /* Frame Cmd.SAM_ProximityCheck part 1 command information. */
  aCmdBuff[bCmdLen++] = PHHAL_HW_SAMAV3_ISO7816_CLA_BYTE;
  aCmdBuff[bCmdLen++] = PHHAL_HW_SAMAV3_CMD_SAM_PROXIMITY_CHECK_INS;
  aCmdBuff[bCmdLen++] = bOption;
  aCmdBuff[bCmdLen++] = PHHAL_HW_SAMAV3_ISO7816_DEFAULT_P2_BYTE;
  aCmdBuff[bCmdLen++] = PHHAL_HW_SAMAV3_ISO7816_DEFAULT_LC_BYTE;

  /* Add the payload information to command buffer. */
  aCmdBuff[bCmdLen++] = bKeyNo;
  aCmdBuff[bCmdLen++] = bKeyVer;
  aCmdBuff[bCmdLen++] = bPPCDataLen;

  /* Buffer the command information to exchange buffer. */
  PH_CHECK_SUCCESS_FCT(wStatus, phhalHw_SamAV3_Cmd_7816Exchange(
          pDataParams,
          PH_EXCHANGE_BUFFER_FIRST,
          aCmdBuff,
          bCmdLen,
          NULL,
          NULL));

  /* Buffer PPCData information to exchange buffer. */
  PH_CHECK_SUCCESS_FCT(wStatus, phhalHw_SamAV3_Cmd_7816Exchange(
          pDataParams,
          PH_EXCHANGE_BUFFER_CONT,
          pPPCData,
          bPPCDataLen,
          NULL,
          NULL));

  /* Buffer PCData information to exchange buffer. */
  PH_CHECK_SUCCESS_FCT(wStatus, phhalHw_SamAV3_Cmd_7816Exchange(
          pDataParams,
          PH_EXCHANGE_BUFFER_CONT,
          pPCData,
          bPCDataLen,
          NULL,
          NULL));

  /* Buffer diversification input information to exchange buffer. */
  PH_CHECK_SUCCESS_FCT(wStatus, phhalHw_SamAV3_Cmd_7816Exchange(
          pDataParams,
          PH_EXCHANGE_BUFFER_CONT,
          pDivInput,
          bDivInputLen,
          NULL,
          NULL));

  /* Update LC. */
  PH_CHECK_SUCCESS_FCT(wStatus, phhalHw_SamAV3_Utils_UpdateLc(pDataParams));

  /* Buffer LE and exchange the bufferred information to SAM hardware. */
  wStatus = phhalHw_SamAV3_Cmd_7816Exchange(
          pDataParams,
          PH_EXCHANGE_BUFFER_LAST,
          gaDefaultLe,
          1,
          ppMac,
          pMacLen);

  /* Check for the Chaining active */
  if ((wStatus & PH_ERR_MASK) != PHHAL_HW_SAMAV3_ERR_OK_CHAINING_ACTIVE) {
    return wStatus;
  }

  return PH_ADD_COMPCODE(PH_ERR_SUCCESS_CHAINING, PH_COMP_HAL);
}

phStatus_t
phhalHw_SamAV3_Cmd_SAM_ProximityCheck_Part2(phhalHw_SamAV3_DataParams_t *pDataParams,
    uint8_t *pData, uint8_t bDataLen, uint8_t *pPiccRetCode)
{
  phStatus_t	PH_MEMLOC_REM wStatus = 0;
  uint8_t		PH_MEMLOC_REM aCmdBuff[PHHAL_HW_SAMAV3_ISO7816_HEADER_LENGTH];
  uint8_t 	*PH_MEMLOC_REM pResponse = NULL;
  uint16_t	PH_MEMLOC_REM wRespLen = 0;

  /* Validate the parameters. */
  PH_ASSERT_NULL_DATA_PARAM(pDataParams, PH_COMP_HAL);
  PH_ASSERT_NULL_PARAM(pData, PH_COMP_HAL);
  PH_ASSERT_NULL_PARAM(pPiccRetCode, PH_COMP_HAL);

  /* Reset the command buffer. */
  memset(aCmdBuff, 0x00, sizeof(aCmdBuff));	/* PRQA S 3200 */

  /* Frame Cmd.SAM_ProximityCheck part 2 command information. */
  aCmdBuff[PHHAL_HW_SAMAV3_ISO7816_CLA_POS] = PHHAL_HW_SAMAV3_ISO7816_CLA_BYTE;
  aCmdBuff[PHHAL_HW_SAMAV3_ISO7816_INS_POS] = PHHAL_HW_SAMAV3_CMD_SAM_PROXIMITY_CHECK_INS;
  aCmdBuff[PHHAL_HW_SAMAV3_ISO7816_P1_POS]  = PHHAL_HW_SAMAV3_ISO7816_DEFAULT_P1_BYTE;
  aCmdBuff[PHHAL_HW_SAMAV3_ISO7816_P2_POS]  = PHHAL_HW_SAMAV3_ISO7816_DEFAULT_P2_BYTE;
  aCmdBuff[PHHAL_HW_SAMAV3_ISO7816_LC_POS]  = PHHAL_HW_SAMAV3_ISO7816_DEFAULT_LC_BYTE;

  /* Buffer the command information to exchange buffer. */
  PH_CHECK_SUCCESS_FCT(wStatus, phhalHw_SamAV3_Cmd_7816Exchange(
          pDataParams,
          PH_EXCHANGE_BUFFER_FIRST,
          aCmdBuff,
          PHHAL_HW_SAMAV3_ISO7816_HEADER_LENGTH,
          NULL,
          NULL));

  /* Buffer Data information to exchange buffer. */
  PH_CHECK_SUCCESS_FCT(wStatus, phhalHw_SamAV3_Cmd_7816Exchange(
          pDataParams,
          PH_EXCHANGE_BUFFER_CONT,
          pData,
          bDataLen,
          NULL,
          NULL));

  /* Update LC. */
  PH_CHECK_SUCCESS_FCT(wStatus, phhalHw_SamAV3_Utils_UpdateLc(pDataParams));

  /* Buffer LE and exchange the bufferred information to SAM hardware. */
  wStatus = phhalHw_SamAV3_Cmd_7816Exchange(
          pDataParams,
          PH_EXCHANGE_BUFFER_LAST,
          gaDefaultLe,
          1,
          &pResponse,
          &wRespLen);

  /* Extract the PICC error code. */
  if ((wStatus & PH_ERR_MASK) == PHHAL_HW_SAMAV3_ERR_MIFARE_GEN) {
    /* Assign the PICC response code the parameter. */
    *pPiccRetCode = pResponse[0];
  }

  return wStatus;
}

/* X - Mode Commands --------------------------------------------------------------------------------------------------- */

phStatus_t
phhalHw_SamAV3_Cmd_VCA_Select(phhalHw_SamAV3_DataParams_t *pDataParams, uint8_t bOption,
    uint8_t bEncKeyNo, uint8_t bEncKeyVer, uint8_t bMacKeyNo,
    uint8_t bMacKeyVer, uint8_t *pIID, uint8_t bIIDLen, uint8_t *pDivInput, uint8_t bDivInputLen,
    uint8_t **ppResponse, uint16_t *pRespLen, uint16_t *pPiccRetCode)
{
  phStatus_t	PH_MEMLOC_REM wStatus = 0;
  uint8_t		PH_MEMLOC_REM aCmdBuff[PHHAL_HW_SAMAV3_ISO7816_HEADER_LENGTH +
                                            5 /* Key Information, IID len */];
  uint8_t		PH_MEMLOC_REM bCmdLen = 0;
  uint8_t 	*PH_MEMLOC_REM pResponse = NULL;
  uint16_t	PH_MEMLOC_REM wRespLen = 0;

  /* Validate the parameters. */
  PH_ASSERT_NULL_DATA_PARAM(pDataParams, PH_COMP_HAL);
  PH_ASSERT_NULL_PARAM(pIID, PH_COMP_HAL);
  PH_ASSERT_NULL_PARAM(ppResponse, PH_COMP_HAL);
  PH_ASSERT_NULL_PARAM(pRespLen, PH_COMP_HAL);
  PH_ASSERT_NULL_PARAM(pPiccRetCode, PH_COMP_HAL);

  /* Reset the command buffer. */
  memset(aCmdBuff, 0x00, sizeof(aCmdBuff));	/* PRQA S 3200 */

  /* Frame Cmd.VCA_Select part1 variant command information. */
  aCmdBuff[bCmdLen++] = PHHAL_HW_SAMAV3_ISO7816_CLA_BYTE;
  aCmdBuff[bCmdLen++] = PHHAL_HW_SAMAV3_CMD_VCA_SELECT_INS;
  aCmdBuff[bCmdLen++] = bOption;
  aCmdBuff[bCmdLen++] = PHHAL_HW_SAMAV3_ISO7816_DEFAULT_P2_BYTE;
  aCmdBuff[bCmdLen++] = PHHAL_HW_SAMAV3_ISO7816_DEFAULT_LC_BYTE;

  /* Frame the payload information. */
  aCmdBuff[bCmdLen++] = bEncKeyNo;
  aCmdBuff[bCmdLen++] = bEncKeyVer;
  aCmdBuff[bCmdLen++] = bMacKeyNo;
  aCmdBuff[bCmdLen++] = bMacKeyVer;
  aCmdBuff[bCmdLen++] = bIIDLen;

  /* Buffer the command information to exchange buffer. */
  PH_CHECK_SUCCESS_FCT(wStatus, phhalHw_SamAV3_Cmd_7816Exchange(
          pDataParams,
          PH_EXCHANGE_BUFFER_FIRST,
          aCmdBuff,
          bCmdLen,
          NULL,
          NULL));

  /* Buffer the IID information to exchange buffer. */
  PH_CHECK_SUCCESS_FCT(wStatus, phhalHw_SamAV3_Cmd_7816Exchange(
          pDataParams,
          PH_EXCHANGE_BUFFER_CONT,
          pIID,
          bIIDLen,
          NULL,
          NULL));

  /* Buffer the diversification input information to exchange buffer. */
  if (bOption & 0x07) {
    PH_CHECK_SUCCESS_FCT(wStatus, phhalHw_SamAV3_Cmd_7816Exchange(
            pDataParams,
            PH_EXCHANGE_BUFFER_CONT,
            pDivInput,
            bDivInputLen,
            NULL,
            NULL));
  }

  /* Update LC. */
  PH_CHECK_SUCCESS_FCT(wStatus, phhalHw_SamAV3_Utils_UpdateLc(pDataParams));

  /* Buffer LE and exchange the bufferred information to SAM hardware. */
  wStatus = phhalHw_SamAV3_Cmd_7816Exchange(
          pDataParams,
          PH_EXCHANGE_BUFFER_LAST,
          gaDefaultLe,
          1,
          &pResponse,
          &wRespLen);

  /* Update the PICC status code. */
  if ((wStatus & PH_ERR_MASK) == PHHAL_HW_SAMAV3_ERR_MIFARE_GEN) {
    *pPiccRetCode = (uint16_t)((pResponse[wRespLen - 2] << 8) | pResponse[wRespLen - 1]);
    *pRespLen = wRespLen;
  } else {
    memcpy(ppResponse[0], pResponse, wRespLen);	/* PRQA S 3200 */
    *pRespLen = wRespLen;
  }

  /* Verify the status if 2Part variant and exchange the second command frame. */
  if (bOption & PHHAL_HW_SAMAV3_CMD_VCA_SELECT_VARIANT_PART2) {
    /* Check for OK_CHAINING_ACTIVE_EXT */
    if ((wStatus & PH_ERR_MASK) != PHHAL_HW_SAMAV3_ERR_OK_CHAINING_ACTIVE_EXT) {
      return wStatus;
    }

    /* Reset the command buffer. */
    bCmdLen = 0;
    memset(aCmdBuff, 0x00, sizeof(aCmdBuff));	/* PRQA S 3200 */

    /* Frame Cmd.VCA_Select part1 variant command information. */
    aCmdBuff[bCmdLen++] = PHHAL_HW_SAMAV3_ISO7816_CLA_BYTE;
    aCmdBuff[bCmdLen++] = PHHAL_HW_SAMAV3_CMD_VCA_SELECT_INS;
    aCmdBuff[bCmdLen++] = PHHAL_HW_SAMAV3_ISO7816_DEFAULT_P1_BYTE;
    aCmdBuff[bCmdLen++] = PHHAL_HW_SAMAV3_ISO7816_DEFAULT_P2_BYTE;
    aCmdBuff[bCmdLen++] = PHHAL_HW_SAMAV3_ISO7816_DEFAULT_LC_BYTE;

    /* Buffer the command information to exchange buffer. */
    PH_CHECK_SUCCESS_FCT(wStatus, phhalHw_SamAV3_Cmd_7816Exchange(
            pDataParams,
            PH_EXCHANGE_BUFFER_FIRST,
            aCmdBuff,
            bCmdLen,
            NULL,
            NULL));

    /* Buffer the diversification input information to exchange buffer. */
    PH_CHECK_SUCCESS_FCT(wStatus, phhalHw_SamAV3_Cmd_7816Exchange(
            pDataParams,
            PH_EXCHANGE_BUFFER_CONT,
            pDivInput,
            bDivInputLen,
            NULL,
            NULL));

    /* Update LC. */
    PH_CHECK_SUCCESS_FCT(wStatus, phhalHw_SamAV3_Utils_UpdateLc(pDataParams));

    /* Buffer LE and exchange the bufferred information to SAM hardware. */
    PH_CHECK_SUCCESS_FCT(wStatus, phhalHw_SamAV3_Cmd_7816Exchange(
            pDataParams,
            PH_EXCHANGE_BUFFER_LAST,
            gaDefaultLe,
            1,
            &pResponse,
            &wRespLen));

    /* Update the PICC status code. */
    if ((wStatus & PH_ERR_MASK) == PHHAL_HW_SAMAV3_ERR_MIFARE_GEN) {
      *pPiccRetCode = (uint16_t)((pResponse[wRespLen - 2] << 8) | pResponse[wRespLen - 1]);
      *pRespLen = wRespLen;
    }
  } else {
    PH_CHECK_SUCCESS(wStatus);
  }

  return PH_ADD_COMPCODE(PH_ERR_SUCCESS, PH_COMP_HAL);
}

phStatus_t
phhalHw_SamAV3_Cmd_VCA_ProximityCheck(phhalHw_SamAV3_DataParams_t *pDataParams, uint8_t bOption,
    uint8_t bKeyNo, uint8_t bKeyVer, uint8_t bNumOfRand,
    uint8_t *pDivInput, uint8_t bDivInputLen, uint8_t **ppResponse, uint16_t *pRespLen)
{
  phStatus_t	PH_MEMLOC_REM wStatus = 0;
  uint8_t		PH_MEMLOC_REM aCmdBuff[PHHAL_HW_SAMAV3_ISO7816_HEADER_LENGTH + 3 /* KeyNo, KeyVer, M */];
  uint8_t		PH_MEMLOC_REM bCmdLen = 0;

  /* Validate the parameters. */
  PH_ASSERT_NULL_DATA_PARAM(pDataParams, PH_COMP_HAL);
  if (bOption & PHHAL_HW_SAMAV3_CMD_PROXIMITY_CHECK_DIV_ON) {
    PH_ASSERT_NULL_PARAM(pDivInput, PH_COMP_HAL);
  }
  PH_ASSERT_NULL_PARAM(pRespLen, PH_COMP_HAL);

  /* Reset the command buffer and its length variable. */
  bCmdLen = 0;
  memset(aCmdBuff, 0x00, sizeof(aCmdBuff));	/* PRQA S 3200 */

  /* Frame Cmd.VCA_ProximityCheck command information. */
  aCmdBuff[bCmdLen++] = PHHAL_HW_SAMAV3_ISO7816_CLA_BYTE;
  aCmdBuff[bCmdLen++] = PHHAL_HW_SAMAV3_CMD_VCA_PROXIMITY_CHECK_INS;
  aCmdBuff[bCmdLen++] = bOption;
  aCmdBuff[bCmdLen++] = PHHAL_HW_SAMAV3_ISO7816_DEFAULT_P2_BYTE;
  aCmdBuff[bCmdLen++] = PHHAL_HW_SAMAV3_ISO7816_DEFAULT_LC_BYTE;

  /* Add the payload information to command buffer. */
  aCmdBuff[bCmdLen++] = bKeyNo;
  aCmdBuff[bCmdLen++] = bKeyVer;
  aCmdBuff[bCmdLen++] = bNumOfRand;

  /* Buffer the command information to exchange buffer. */
  PH_CHECK_SUCCESS_FCT(wStatus, phhalHw_SamAV3_Cmd_7816Exchange(
          pDataParams,
          PH_EXCHANGE_BUFFER_FIRST,
          aCmdBuff,
          bCmdLen,
          NULL,
          NULL));

  /* Buffer Data information to exchange buffer. */
  PH_CHECK_SUCCESS_FCT(wStatus, phhalHw_SamAV3_Cmd_7816Exchange(
          pDataParams,
          PH_EXCHANGE_BUFFER_CONT,
          pDivInput,
          bDivInputLen,
          NULL,
          NULL));

  /* Update LC. */
  PH_CHECK_SUCCESS_FCT(wStatus, phhalHw_SamAV3_Utils_UpdateLc(pDataParams));

  /* Buffer LE and exchange the bufferred information to SAM hardware. */
  PH_CHECK_SUCCESS_FCT(wStatus, phhalHw_SamAV3_Cmd_7816Exchange(
          pDataParams,
          PH_EXCHANGE_BUFFER_LAST,
          gaDefaultLe,
          1,
          ppResponse,
          pRespLen));

  return PH_ADD_COMPCODE(PH_ERR_SUCCESS, PH_COMP_HAL);
}

/*************************************************************************************************************************/
/**************************************************** MIFARE DESFire *****************************************************/
/*************************************************************************************************************************/

/* S - Mode Commands --------------------------------------------------------------------------------------------------- */

phStatus_t
phhalHw_SamAV3_Cmd_SAM_AuthenticatePICC_Part1(phhalHw_SamAV3_DataParams_t *pDataParams,
    uint8_t bOption, uint8_t bKeyNo, uint8_t bKeyVer,
    uint8_t bAuthMode, uint8_t *pDivInput, uint8_t bDivInputLen, uint8_t *pCardResponse,
    uint8_t bCardRespLen, uint8_t **ppSamResponse,
    uint16_t *pSamRespLen)
{
  phStatus_t	PH_MEMLOC_REM wStatus = 0;
  uint8_t		PH_MEMLOC_REM aCmdBuf[PHHAL_HW_SAMAV3_ISO7816_HEADER_LENGTH +
                                            3 /* Key No, Key Ver and AuthMode */ ];
  uint8_t		PH_MEMLOC_REM bCmdLen = 0;

  /* Validate the parameters. */
  PH_ASSERT_NULL_DATA_PARAM(pDataParams, PH_COMP_HAL);
  if (bOption & PHHAL_HW_CMD_SAMAV3_KEY_DIVERSIFICATION_ON) {
    PH_ASSERT_NULL_PARAM(pDivInput, PH_COMP_HAL);
  }
  PH_ASSERT_NULL_PARAM(pCardResponse, PH_COMP_HAL);
  PH_ASSERT_NULL_PARAM(pSamRespLen, PH_COMP_HAL);

  /* Reset the command buffer and its length. */
  bCmdLen = 0;
  memset(aCmdBuf, 0x00, sizeof(aCmdBuf));	/* PRQA S 3200 */

  /* Frame Cmd.SAM_AuthenticatePICC part 1 command information. */
  aCmdBuf[bCmdLen++] = PHHAL_HW_SAMAV3_ISO7816_CLA_BYTE;
  aCmdBuf[bCmdLen++] = PHHAL_HW_SAMAV3_CMD_SAM_AUTHENTICATE_PICC_INS;
  aCmdBuf[bCmdLen++] = bOption;
  aCmdBuf[bCmdLen++] = PHHAL_HW_SAMAV3_ISO7816_DEFAULT_P2_BYTE;
  aCmdBuf[bCmdLen++] = PHHAL_HW_SAMAV3_ISO7816_DEFAULT_LC_BYTE;

  /* Append the Key number and Key version. */
  aCmdBuf[bCmdLen++] = bKeyNo;
  aCmdBuf[bCmdLen++] = bKeyVer;

  /* Add Auth Mode if EV2 Authentication. */
  if (bOption & 0x80) {
    aCmdBuf[bCmdLen++] = bAuthMode;
  }

  /* Buffer the first part of command data. */
  PH_CHECK_SUCCESS_FCT(wStatus, phhalHw_SamAV3_Cmd_7816Exchange(
          pDataParams,
          PH_EXCHANGE_BUFFER_FIRST,
          aCmdBuf,
          bCmdLen,
          NULL,
          NULL));

  /* Buffer the cards response to exchange buffer. */
  PH_CHECK_SUCCESS_FCT(wStatus, phhalHw_SamAV3_Cmd_7816Exchange(
          pDataParams,
          PH_EXCHANGE_BUFFER_CONT,
          pCardResponse,
          bCardRespLen,
          NULL,
          NULL));

  /* Buffer diversification input informationto exchange buffer. */
  PH_CHECK_SUCCESS_FCT(wStatus, phhalHw_SamAV3_Cmd_7816Exchange(
          pDataParams,
          PH_EXCHANGE_BUFFER_CONT,
          pDivInput,
          bDivInputLen,
          NULL,
          NULL));

  /* Update LC. */
  PH_CHECK_SUCCESS_FCT(wStatus, phhalHw_SamAV3_Utils_UpdateLc(pDataParams));

  /* Buffer LE and exchange the bufferred information to Sam hardware. */
  wStatus = phhalHw_SamAV3_Cmd_7816Exchange(
          pDataParams,
          PH_EXCHANGE_BUFFER_LAST,
          gaDefaultLe,
          1,
          ppSamResponse,
          pSamRespLen);

  /* Return the chaining code. */
  if ((wStatus & PH_ERR_MASK) == PHHAL_HW_SAMAV3_ERR_OK_CHAINING_ACTIVE) {
    return PH_ADD_COMPCODE(PH_ERR_SUCCESS_CHAINING, PH_COMP_HAL);
  }

  /* Return the response received from Sam hardware. */
  return wStatus;
}

phStatus_t
phhalHw_SamAV3_Cmd_SAM_AuthenticatePICC_Part2(phhalHw_SamAV3_DataParams_t *pDataParams,
    uint8_t bPiccErrorCode, uint8_t *pCardResponse,
    uint8_t bCardRespLen, uint8_t *pPDcap2, uint8_t *pPCDcap2, uint8_t *pStatusCode)
{
  phStatus_t	PH_MEMLOC_REM wStatus = 0;
  uint8_t		PH_MEMLOC_REM aCmdBuf[PHHAL_HW_SAMAV3_ISO7816_HEADER_LENGTH + 1 /* Picc error code. */];
  uint8_t		PH_MEMLOC_REM bCmdLen = 0;
  uint8_t 	*PH_MEMLOC_REM pResponse = NULL;
  uint16_t	PH_MEMLOC_REM wRespLen = 0;

  /* Validate the parameters. */
  PH_ASSERT_NULL_DATA_PARAM(pDataParams, PH_COMP_HAL);
  if (!bPiccErrorCode) {
    PH_ASSERT_NULL_PARAM(pCardResponse, PH_COMP_HAL);
  }
  PH_ASSERT_NULL_PARAM(pStatusCode, PH_COMP_HAL);

  /* Reset the command buffer and its length. */
  bCmdLen = 0;
  memset(aCmdBuf, 0x00, sizeof(aCmdBuf));	/* PRQA S 3200 */

  /* Frame Cmd.SAM_AuthenticatePICC part 2 command  information. */
  aCmdBuf[bCmdLen++] = PHHAL_HW_SAMAV3_ISO7816_CLA_BYTE;
  aCmdBuf[bCmdLen++] = PHHAL_HW_SAMAV3_CMD_SAM_AUTHENTICATE_PICC_INS;
  aCmdBuf[bCmdLen++] = PHHAL_HW_SAMAV3_ISO7816_DEFAULT_P1_BYTE;
  aCmdBuf[bCmdLen++] = PHHAL_HW_SAMAV3_ISO7816_DEFAULT_P2_BYTE;
  aCmdBuf[bCmdLen++] = PHHAL_HW_SAMAV3_ISO7816_DEFAULT_LC_BYTE;

  /* As per the Ref Arch Lc can be of 1 byte only in case of PICC error */
  if (bPiccErrorCode != 0x00) {
    aCmdBuf[bCmdLen++] = bPiccErrorCode;
  }

  /* Buffer command information to exchange buffer. */
  PH_CHECK_SUCCESS_FCT(wStatus, phhalHw_SamAV3_Cmd_7816Exchange(
          pDataParams,
          PH_EXCHANGE_BUFFER_FIRST,
          aCmdBuf,
          bCmdLen,
          NULL,
          NULL));

  /* Buffer card response to exchange buffer. */
  PH_CHECK_SUCCESS_FCT(wStatus, phhalHw_SamAV3_Cmd_7816Exchange(
          pDataParams,
          PH_EXCHANGE_BUFFER_CONT,
          pCardResponse,
          bCardRespLen,
          NULL,
          NULL));

  /* Update LC. */
  PH_CHECK_SUCCESS_FCT(wStatus, phhalHw_SamAV3_Utils_UpdateLc(pDataParams));

  /* Append Le in either of below 2 cases,
   * Case-1 : In case of error response code from PICC. In this case SAM echoes the DESFire error Status code.
   * Case-2 : In case of EV2 First Authentication is performed. 12 bytes of PCdCap and PDCap data is returned
   */
  if ((bPiccErrorCode != 0x00 /* Picc status code */) ||
      (bCardRespLen == 0x20 /* PICC response Length */)) {
    wStatus = phhalHw_SamAV3_Cmd_7816Exchange(
            pDataParams,
            PH_EXCHANGE_BUFFER_LAST,
            gaDefaultLe,
            1,
            &pResponse,
            &wRespLen);

    /* Extract the PICC error code. */
    if ((wStatus & PH_ERR_MASK) == PHHAL_HW_SAMAV3_ERR_DESFIRE_GEN) {
      *pStatusCode = pResponse[0];
    }

    /* Extract PCD and PD capabilities for EV2 authentication type. */
    if (((wStatus & PH_ERR_MASK) == PH_ERR_SUCCESS) && (wRespLen == 0x0C)) {
      /* Assign the PCD and PD capabilities to the parameter. */
      memcpy(pPDcap2, &pResponse[0], 6);		/* PRQA S 3200 */
      memcpy(pPCDcap2, &pResponse[6], 6);		/* PRQA S 3200 */
    }
  } else {
    /*  No Le byte, Exchange the rest buffered data */
    PH_CHECK_SUCCESS_FCT(wStatus, phhalHw_SamAV3_Cmd_7816Exchange(
            pDataParams,
            PH_EXCHANGE_BUFFER_LAST,
            NULL,
            0x00,
            &pResponse,
            &wRespLen));
  }

  return wStatus;
}

phStatus_t
phhalHw_SamAV3_Cmd_SAM_IsoAuthenticatePICC_Part1(phhalHw_SamAV3_DataParams_t *pDataParams,
    uint8_t bOption, uint8_t bKeyNo, uint8_t bKeyVer,
    uint8_t *pDivInput, uint8_t bDivInputLen, uint8_t *pCardResponse, uint8_t bCardRespLen,
    uint8_t  **ppSamResponse, uint16_t *pSamRespLen)
{
  phStatus_t	PH_MEMLOC_REM wStatus = 0;
  uint8_t		PH_MEMLOC_REM aCmdBuf[PHHAL_HW_SAMAV3_ISO7816_HEADER_LENGTH +
                                            2 /* Key No and Key Ver */ ];
  uint8_t		PH_MEMLOC_REM bCmdLen = 0;

  /* Validate the parameters. */
  PH_ASSERT_NULL_DATA_PARAM(pDataParams, PH_COMP_HAL);
  if (bOption & PHHAL_HW_CMD_SAMAV3_KEY_DIVERSIFICATION_ON) {
    PH_ASSERT_NULL_PARAM(pDivInput, PH_COMP_HAL);
  }
  PH_ASSERT_NULL_PARAM(pCardResponse, PH_COMP_HAL);
  PH_ASSERT_NULL_PARAM(pSamRespLen, PH_COMP_HAL);

  /* Reset the command buffer and its length. */
  bCmdLen = 0;
  memset(aCmdBuf, 0x00, sizeof(aCmdBuf));	/* PRQA S 3200 */

  /* Frame Cmd.SAM_IsoAuthenticatePICC part 1 command  information. */
  aCmdBuf[bCmdLen++] = PHHAL_HW_SAMAV3_ISO7816_CLA_BYTE;
  aCmdBuf[bCmdLen++] = PHHAL_HW_SAMAV3_CMD_SAM_ISO_AUTHENTICATE_PICC_INS;
  aCmdBuf[bCmdLen++] = bOption;
  aCmdBuf[bCmdLen++] = PHHAL_HW_SAMAV3_ISO7816_DEFAULT_P2_BYTE;
  aCmdBuf[bCmdLen++] = PHHAL_HW_SAMAV3_ISO7816_DEFAULT_LC_BYTE;

  /* Append the Key number and Key version. */
  aCmdBuf[bCmdLen++] = bKeyNo;
  aCmdBuf[bCmdLen++] = bKeyVer;

  /* Buffer command informationto exchange buffer. */
  PH_CHECK_SUCCESS_FCT(wStatus, phhalHw_SamAV3_Cmd_7816Exchange(
          pDataParams,
          PH_EXCHANGE_BUFFER_FIRST,
          aCmdBuf,
          bCmdLen,
          NULL,
          NULL));

  /* Buffer card response to exchange buffer. */
  PH_CHECK_SUCCESS_FCT(wStatus, phhalHw_SamAV3_Cmd_7816Exchange(
          pDataParams,
          PH_EXCHANGE_BUFFER_CONT,
          pCardResponse,
          bCardRespLen,
          NULL,
          NULL));

  /* Buffer diversification input information to exchange buffer. */
  PH_CHECK_SUCCESS_FCT(wStatus, phhalHw_SamAV3_Cmd_7816Exchange(
          pDataParams,
          PH_EXCHANGE_BUFFER_CONT,
          pDivInput,
          bDivInputLen,
          NULL,
          NULL));

  /* Update LC. */
  PH_CHECK_SUCCESS_FCT(wStatus, phhalHw_SamAV3_Utils_UpdateLc(pDataParams));

  /* Buffer LE and exchange the bufferred inforamtionto SAM hardware. */
  wStatus = phhalHw_SamAV3_Cmd_7816Exchange(
          pDataParams,
          PH_EXCHANGE_BUFFER_LAST,
          gaDefaultLe,
          1,
          ppSamResponse,
          pSamRespLen);

  /* Return the chaining code. */
  if ((wStatus & PH_ERR_MASK) == PHHAL_HW_SAMAV3_ERR_OK_CHAINING_ACTIVE) {
    return PH_ADD_COMPCODE(PH_ERR_SUCCESS_CHAINING, PH_COMP_HAL);
  }

  /* Return the response received from Sam hardware. */
  return wStatus;
}

phStatus_t
phhalHw_SamAV3_Cmd_SAM_IsoAuthenticatePICC_Part2(phhalHw_SamAV3_DataParams_t *pDataParams,
    uint8_t *pCardResponse, uint8_t bCardRespLen)
{
  phStatus_t	PH_MEMLOC_REM wStatus = 0;
  uint8_t		PH_MEMLOC_REM aCmdBuf[PHHAL_HW_SAMAV3_ISO7816_HEADER_LENGTH];
  uint8_t 	*PH_MEMLOC_REM pResponse = NULL;
  uint16_t	PH_MEMLOC_REM wRespLen = 0;

  /* Validate the parameters. */
  PH_ASSERT_NULL_DATA_PARAM(pDataParams, PH_COMP_HAL);
  PH_ASSERT_NULL_PARAM(pCardResponse, PH_COMP_HAL);

  /* Reset the command buffer. */
  memset(aCmdBuf, 0x00, sizeof(aCmdBuf));	/* PRQA S 3200 */

  /* Frame Cmd.SAM_IsoAuthenticatePICC part 2 command inforamtion. */
  aCmdBuf[PHHAL_HW_SAMAV3_ISO7816_CLA_POS] = PHHAL_HW_SAMAV3_ISO7816_CLA_BYTE;
  aCmdBuf[PHHAL_HW_SAMAV3_ISO7816_INS_POS] = PHHAL_HW_SAMAV3_CMD_SAM_ISO_AUTHENTICATE_PICC_INS;
  aCmdBuf[PHHAL_HW_SAMAV3_ISO7816_P1_POS]	 = PHHAL_HW_SAMAV3_ISO7816_DEFAULT_P1_BYTE;
  aCmdBuf[PHHAL_HW_SAMAV3_ISO7816_P2_POS]	 = PHHAL_HW_SAMAV3_ISO7816_DEFAULT_P2_BYTE;
  aCmdBuf[PHHAL_HW_SAMAV3_ISO7816_LC_POS]	 = PHHAL_HW_SAMAV3_ISO7816_DEFAULT_LC_BYTE;

  /* Buffer command information to exchange buffer. */
  PH_CHECK_SUCCESS_FCT(wStatus, phhalHw_SamAV3_Cmd_7816Exchange(
          pDataParams,
          PH_EXCHANGE_BUFFER_FIRST,
          aCmdBuf,
          PHHAL_HW_SAMAV3_ISO7816_HEADER_LENGTH,
          NULL,
          NULL));

  /* Buffer card response to exchange buffer. */
  PH_CHECK_SUCCESS_FCT(wStatus, phhalHw_SamAV3_Cmd_7816Exchange(
          pDataParams,
          PH_EXCHANGE_BUFFER_CONT,
          pCardResponse,
          bCardRespLen,
          NULL,
          NULL));

  /* Update LC. */
  PH_CHECK_SUCCESS_FCT(wStatus, phhalHw_SamAV3_Utils_UpdateLc(pDataParams));

  /* Exchange the bufferred informationto Sam hardware. */
  PH_CHECK_SUCCESS_FCT(wStatus, phhalHw_SamAV3_Cmd_7816Exchange(
          pDataParams,
          PH_EXCHANGE_BUFFER_LAST,
          NULL,
          0,
          &pResponse,
          &wRespLen));

  return PH_ADD_COMPCODE(PH_ERR_SUCCESS, PH_COMP_HAL);
}

phStatus_t
phhalHw_SamAV3_Cmd_SAM_ChangeKeyPICC(phhalHw_SamAV3_DataParams_t *pDataParams,
    uint8_t bCryptoMethod, uint8_t bConfig, uint8_t bKeySetNo,
    uint8_t bDFKeyNo, uint8_t bCurrKeyNo, uint8_t bCurrKeyVer, uint8_t bNewKeyNo, uint8_t bNewKeyVer,
    uint8_t *pDivInput, uint8_t bDivInputLen,
    uint8_t **ppSamResponse, uint16_t *pSamRespLen)
{
  phStatus_t	PH_MEMLOC_REM wStatus = 0;
  uint8_t		PH_MEMLOC_REM aCmdBuf[PHHAL_HW_SAMAV3_ISO7816_HEADER_LENGTH +
                                            6 /* Key information, PCDcap len. */];
  uint8_t		PH_MEMLOC_REM bCmdLen = 0;

  /* Validate the parameters. */
  PH_ASSERT_NULL_DATA_PARAM(pDataParams, PH_COMP_HAL);
  if (bDivInputLen) {
    PH_ASSERT_NULL_PARAM(pDivInput, PH_COMP_HAL);
  }
  PH_ASSERT_NULL_PARAM(pSamRespLen, PH_COMP_HAL);

  /* Reset the command buffer and its length. */
  bCmdLen = 0;
  memset(aCmdBuf, 0x00, sizeof(aCmdBuf));	/* PRQA S 3200 */

  /* Frame Cmd.SAM_ChangeKeyPICC command information. */
  aCmdBuf[bCmdLen++] = PHHAL_HW_SAMAV3_ISO7816_CLA_BYTE;
  aCmdBuf[bCmdLen++] = PHHAL_HW_SAMAV3_CMD_SAM_CHANGE_KEY_PICC_INS;
  aCmdBuf[bCmdLen++] = bCryptoMethod;
  aCmdBuf[bCmdLen++] = bConfig;
  aCmdBuf[bCmdLen++] = PHHAL_HW_SAMAV3_ISO7816_DEFAULT_LC_BYTE;

  /* Add KeySetNo and DFKeyno for command type as ChangeKeyEV2. */
  if (bConfig & PHHAL_HW_CMD_SAMAV3_CMD_TYPE_CHANGE_KEY_EV2) {
    aCmdBuf[bCmdLen++] = bKeySetNo;
    aCmdBuf[bCmdLen++] = bDFKeyNo;
  } else {
    /* Append the key number. */
    aCmdBuf[PHHAL_HW_SAMAV3_ISO7816_P2_POS] |= bDFKeyNo;
  }

  /* Add key information to command buffer. */
  aCmdBuf[bCmdLen++] = bCurrKeyNo;
  aCmdBuf[bCmdLen++] = bCurrKeyVer;
  aCmdBuf[bCmdLen++] = bNewKeyNo;
  aCmdBuf[bCmdLen++] = bNewKeyVer;

  /* Buffer command information to exchange buffer. */
  PH_CHECK_SUCCESS_FCT(wStatus, phhalHw_SamAV3_Cmd_7816Exchange(
          pDataParams,
          PH_EXCHANGE_BUFFER_FIRST,
          aCmdBuf,
          bCmdLen,
          NULL,
          NULL));

  /* Buffer diversification information to exchange buffer. */
  PH_CHECK_SUCCESS_FCT(wStatus, phhalHw_SamAV3_Cmd_7816Exchange(
          pDataParams,
          PH_EXCHANGE_BUFFER_CONT,
          pDivInput,
          bDivInputLen,
          NULL,
          NULL));

  /* Update LC. */
  PH_CHECK_SUCCESS_FCT(wStatus, phhalHw_SamAV3_Utils_UpdateLc(pDataParams));

  /* Buffer LE and exchange the bufferred information to SAM hardware. */
  PH_CHECK_SUCCESS_FCT(wStatus, phhalHw_SamAV3_Cmd_7816Exchange(
          pDataParams,
          PH_EXCHANGE_BUFFER_LAST,
          gaDefaultLe,
          1,
          ppSamResponse,
          pSamRespLen));

  return PH_ADD_COMPCODE(PH_ERR_SUCCESS, PH_COMP_HAL);
}

phStatus_t
phhalHw_SamAV3_Cmd_SAM_CreateTMFilePICC(phhalHw_SamAV3_DataParams_t *pDataParams, uint8_t bOption,
    uint8_t bKeyNo, uint8_t bKeyVer, uint8_t bFileNo,
    uint8_t bFileOption, uint8_t *pAccessRights, uint8_t bTMKeyOptions, uint8_t *pDivInput,
    uint8_t bDivInputLen, uint8_t **ppSamResponse, uint16_t *pSamRespLen)
{
  phStatus_t	PH_MEMLOC_REM wStatus = 0;
  uint8_t		PH_MEMLOC_REM aCmdBuf[PHHAL_HW_SAMAV3_ISO7816_HEADER_LENGTH +
                                            7 /* TM File information */];
  uint8_t		PH_MEMLOC_REM bCmdLen = 0;

  /* Validate the parameters. */
  PH_ASSERT_NULL_DATA_PARAM(pDataParams, PH_COMP_HAL);
  PH_ASSERT_NULL_PARAM(pAccessRights, PH_COMP_HAL);
  if (bOption) {
    PH_ASSERT_NULL_PARAM(pDivInput, PH_COMP_HAL);
  }
  PH_ASSERT_NULL_PARAM(pSamRespLen, PH_COMP_HAL);

  /* Reset the command buffer and its length. */
  bCmdLen = 0;
  memset(aCmdBuf, 0x00, sizeof(aCmdBuf));	/* PRQA S 3200 */

  /* Frame Cmd.SAM_CreateTMFilePICC command information. */
  aCmdBuf[bCmdLen++] = PHHAL_HW_SAMAV3_ISO7816_CLA_BYTE;
  aCmdBuf[bCmdLen++] = PHHAL_HW_SAMAV3_CMD_SAM_CREATE_TM_FILE_PICC_INS;
  aCmdBuf[bCmdLen++] = bOption;
  aCmdBuf[bCmdLen++] = PHHAL_HW_SAMAV3_ISO7816_DEFAULT_P2_BYTE;
  aCmdBuf[bCmdLen++] = PHHAL_HW_SAMAV3_ISO7816_DEFAULT_LC_BYTE;

  /* Add the payload information. */
  aCmdBuf[bCmdLen++] = bKeyNo;
  aCmdBuf[bCmdLen++] = bKeyVer;
  aCmdBuf[bCmdLen++] = bFileNo;
  aCmdBuf[bCmdLen++] = bFileOption;
  aCmdBuf[bCmdLen++] = pAccessRights[0];
  aCmdBuf[bCmdLen++] = pAccessRights[1];
  aCmdBuf[bCmdLen++] = bTMKeyOptions;

  /* Buffer command information to exchange buffer. */
  PH_CHECK_SUCCESS_FCT(wStatus, phhalHw_SamAV3_Cmd_7816Exchange(
          pDataParams,
          PH_EXCHANGE_BUFFER_FIRST,
          aCmdBuf,
          bCmdLen,
          NULL,
          NULL));

  /* Buffer diversification input to exchange buffer. */
  PH_CHECK_SUCCESS_FCT(wStatus, phhalHw_SamAV3_Cmd_7816Exchange(
          pDataParams,
          PH_EXCHANGE_BUFFER_CONT,
          pDivInput,
          bDivInputLen,
          NULL,
          NULL));

  /* Update LC. */
  PH_CHECK_SUCCESS_FCT(wStatus, phhalHw_SamAV3_Utils_UpdateLc(pDataParams));

  /* Buffer LE and exchange the bufferred information to SAM hardware. */
  PH_CHECK_SUCCESS_FCT(wStatus, phhalHw_SamAV3_Cmd_7816Exchange(
          pDataParams,
          PH_EXCHANGE_BUFFER_LAST,
          gaDefaultLe,
          1,
          ppSamResponse,
          pSamRespLen));

  return PH_ADD_COMPCODE(PH_ERR_SUCCESS, PH_COMP_HAL);
}

/* X - Mode Commands --------------------------------------------------------------------------------------------------- */

phStatus_t
phhalHw_SamAV3_Cmd_DESFire_AuthenticatePICC(phhalHw_SamAV3_DataParams_t *pDataParams,
    uint8_t bOption, uint8_t bISOMode, uint8_t bDFKeyNo,
    uint8_t bKeyNo, uint8_t bKeyVer, uint8_t bPCDcap2InLen, uint8_t *pPCDcap2In, uint8_t *pDivInput,
    uint8_t  bDivInputLen, uint8_t *pPDcap2,
    uint8_t *pPCDcap2, uint8_t *pPiccReturnCode)
{
  phStatus_t	PH_MEMLOC_REM wStatus = 0;
  uint8_t		PH_MEMLOC_REM aCmdBuf[PHHAL_HW_SAMAV3_ISO7816_HEADER_LENGTH +
                                            4 /* Key information, PCDcap len. */];
  uint8_t		PH_MEMLOC_REM bCmdLen = 0;
  uint8_t 	*PH_MEMLOC_REM pResponse = NULL;
  uint16_t	PH_MEMLOC_REM wRespLen = 0;

  /* Validate the parameters. */
  PH_ASSERT_NULL_DATA_PARAM(pDataParams, PH_COMP_HAL);
  if (bOption & PHHAL_HW_CMD_SAMAV3_AUTH_MODE_EV2_FIRST_AUTH) {
    if (bPCDcap2InLen && (bPCDcap2InLen != 0xFF /* Default PCDcap2 usage. */)) {
      PH_ASSERT_NULL_PARAM(pPCDcap2In, PH_COMP_HAL);
    }
    PH_ASSERT_NULL_PARAM(pPDcap2, PH_COMP_HAL);
    PH_ASSERT_NULL_PARAM(pPCDcap2, PH_COMP_HAL);
  }
  if (bOption & PHHAL_HW_CMD_SAMAV3_KEY_DIVERSIFICATION_ON) {
    PH_ASSERT_NULL_PARAM(pDivInput, PH_COMP_HAL);
  }
  PH_ASSERT_NULL_PARAM(pPiccReturnCode, PH_COMP_HAL);

  /* Reset the command buffer and its length. */
  bCmdLen = 0;
  memset(aCmdBuf, 0x00, sizeof(aCmdBuf));	/* PRQA S 3200 */

  /* Frame Cmd.DESFire_AuthenticatePICC command information. */
  aCmdBuf[bCmdLen++] = PHHAL_HW_SAMAV3_ISO7816_CLA_BYTE;
  aCmdBuf[bCmdLen++] = PHHAL_HW_SAMAV3_CMD_DESFIRE_AUTHENTICATE_INS;
  aCmdBuf[bCmdLen++] = bOption;
  aCmdBuf[bCmdLen++] = bISOMode;
  aCmdBuf[bCmdLen++] = PHHAL_HW_SAMAV3_ISO7816_DEFAULT_LC_BYTE;

  /* Add key information to comand buffer. */
  aCmdBuf[bCmdLen++] = bDFKeyNo;
  aCmdBuf[bCmdLen++] = bKeyNo;
  aCmdBuf[bCmdLen++] = bKeyVer;

  /* Add PCDCap length for EV2 authentication type. */
  if (bOption & PHHAL_HW_CMD_SAMAV3_AUTH_MODE_EV2_FIRST_AUTH) {
    aCmdBuf[bCmdLen++] = bPCDcap2InLen;
  }

  /* Buffer command information to exchange buffer. */
  PH_CHECK_SUCCESS_FCT(wStatus, phhalHw_SamAV3_Cmd_7816Exchange(
          pDataParams,
          PH_EXCHANGE_BUFFER_FIRST,
          aCmdBuf,
          bCmdLen,
          NULL,
          NULL));

  /* Buffer PCDcap information to exchange buffer for EV2 authentication type. */
  if ((bOption & PHHAL_HW_CMD_SAMAV3_AUTH_MODE_EV2_FIRST_AUTH) &&
      (bPCDcap2InLen != 0xFF /* Default PCDcap2 usage. */)) {
    PH_CHECK_SUCCESS_FCT(wStatus, phhalHw_SamAV3_Cmd_7816Exchange(
            pDataParams,
            PH_EXCHANGE_BUFFER_CONT,
            pPCDcap2In,
            bPCDcap2InLen,
            NULL,
            NULL));
  }

  /* Buffer diversification input information to exchange buffer. */
  PH_CHECK_SUCCESS_FCT(wStatus, phhalHw_SamAV3_Cmd_7816Exchange(
          pDataParams,
          PH_EXCHANGE_BUFFER_CONT,
          pDivInput,
          bDivInputLen,
          NULL,
          NULL));

  /* Update LC. */
  PH_CHECK_SUCCESS_FCT(wStatus, phhalHw_SamAV3_Utils_UpdateLc(pDataParams));

  /* Buffer LE and exchange the bufferred information to SAM hardware. */
  wStatus = phhalHw_SamAV3_Cmd_7816Exchange(
          pDataParams,
          PH_EXCHANGE_BUFFER_LAST,
          gaDefaultLe,
          1,
          &pResponse,
          &wRespLen);

  /* Extract the PICC error code. */
  if ((wStatus & PH_ERR_MASK) == PHHAL_HW_SAMAV3_ERR_DESFIRE_GEN) {
    /* Assign one byte PICC response code the parameter in case of Native command set. */
    if (bISOMode == PHHAL_HW_CMD_SAMAV3_ISO_MODE_NATIVE) {
      *pPiccReturnCode = pResponse[0];
    }

    /* Assign two byte PICC response code the parameter in case of Native command set. */
    else {
      memcpy(pPiccReturnCode, pResponse, 2);		/* PRQA S 3200 */
    }
  }

  /* Extract PCD and PD capabilities for EV2 authentication type. */
  if (((wStatus & PH_ERR_MASK) == PH_ERR_SUCCESS) &&
      (bOption & PHHAL_HW_CMD_SAMAV3_AUTH_MODE_EV2_FIRST_AUTH)) {
    /* Assign the PCD and PD capabilities to the parameter. */
    memcpy(pPDcap2, &pResponse[0], 6);		/* PRQA S 3200 */
    memcpy(pPCDcap2, &pResponse[6], 6);		/* PRQA S 3200 */
  }

  return wStatus;
}

phStatus_t
phhalHw_SamAV3_Cmd_DESFire_ChangeKeyPICC(phhalHw_SamAV3_DataParams_t *pDataParams,
    uint8_t bKeyCompMeth, uint8_t bConfig, uint8_t bKeySetNo,
    uint8_t bDFKeyNo, uint8_t bCurrKeyNo, uint8_t bCurrKeyVer, uint8_t bNewKeyNo, uint8_t bNewKeyVer,
    uint8_t *pDivInput, uint8_t  bDivInputLen,
    uint8_t *pPiccReturnCode)
{
  phStatus_t	PH_MEMLOC_REM wStatus = 0;
  uint8_t		PH_MEMLOC_REM aCmdBuf[PHHAL_HW_SAMAV3_ISO7816_HEADER_LENGTH +
                                            6 /* Key information, PCDcap len. */];
  uint8_t		PH_MEMLOC_REM bCmdLen = 0;
  uint8_t 	*PH_MEMLOC_REM pResponse = NULL;
  uint16_t	PH_MEMLOC_REM wRespLen = 0;

  /* Validate the parameters. */
  PH_ASSERT_NULL_DATA_PARAM(pDataParams, PH_COMP_HAL);
  if (bDivInputLen) {
    PH_ASSERT_NULL_PARAM(pDivInput, PH_COMP_HAL);
  }
  PH_ASSERT_NULL_PARAM(pPiccReturnCode, PH_COMP_HAL);

  /* Reset the command buffer and its length. */
  bCmdLen = 0;
  memset(aCmdBuf, 0x00, sizeof(aCmdBuf));	/* PRQA S 3200 */

  /* Frame Cmd.DESFire_ChangeKeyPICC command information. */
  aCmdBuf[bCmdLen++] = PHHAL_HW_SAMAV3_ISO7816_CLA_BYTE;
  aCmdBuf[bCmdLen++] = PHHAL_HW_SAMAV3_CMD_DESFIRE_CHANGE_KEY_INS;
  aCmdBuf[bCmdLen++] = bKeyCompMeth;
  aCmdBuf[bCmdLen++] = bConfig;
  aCmdBuf[bCmdLen++] = PHHAL_HW_SAMAV3_ISO7816_DEFAULT_LC_BYTE;

  /* Add KeySetNo and DFKeyno for command type as ChangeKeyEV2. */
  if (bConfig & PHHAL_HW_CMD_SAMAV3_CMD_TYPE_CHANGE_KEY_EV2) {
    aCmdBuf[bCmdLen++] = bKeySetNo;
    aCmdBuf[bCmdLen++] = bDFKeyNo;
  }

  /* Add key information to command buffer. */
  aCmdBuf[bCmdLen++] = bCurrKeyNo;
  aCmdBuf[bCmdLen++] = bCurrKeyVer;
  aCmdBuf[bCmdLen++] = bNewKeyNo;
  aCmdBuf[bCmdLen++] = bNewKeyVer;

  /* Buffer command information to exchange buffer. */
  PH_CHECK_SUCCESS_FCT(wStatus, phhalHw_SamAV3_Cmd_7816Exchange(
          pDataParams,
          PH_EXCHANGE_BUFFER_FIRST,
          aCmdBuf,
          bCmdLen,
          NULL,
          NULL));

  /* Buffer diversification information to exchange buffer. */
  PH_CHECK_SUCCESS_FCT(wStatus, phhalHw_SamAV3_Cmd_7816Exchange(
          pDataParams,
          PH_EXCHANGE_BUFFER_CONT,
          pDivInput,
          bDivInputLen,
          NULL,
          NULL));

  /* Update LC. */
  PH_CHECK_SUCCESS_FCT(wStatus, phhalHw_SamAV3_Utils_UpdateLc(pDataParams));

  /* Buffer LE and exchange the bufferred information to SAM hardware. */
  wStatus = phhalHw_SamAV3_Cmd_7816Exchange(
          pDataParams,
          PH_EXCHANGE_BUFFER_LAST,
          gaDefaultLe,
          1,
          &pResponse,
          &wRespLen);

  /* Extract the PICC error code. */
  if ((wStatus & PH_ERR_MASK) == PHHAL_HW_SAMAV3_ERR_DESFIRE_GEN) {
    /* Assign one byte PICC response code the parameter in case of Native command set. */
    if (bConfig & PHHAL_HW_CMD_SAMAV3_ISO_MODE_ISO7816) {
      memcpy(pPiccReturnCode, pResponse, 2);		/* PRQA S 3200 */
    }

    /* Assign two byte PICC response code the parameter in case of Native command set. */
    else {
      *pPiccReturnCode = pResponse[0];
    }
  }

  return wStatus;
}

phStatus_t
phhalHw_SamAV3_Cmd_DESFire_WriteX(phhalHw_SamAV3_DataParams_t *pDataParams, uint16_t wOption,
    uint8_t bCrypto, uint8_t *pData, uint8_t bDataLen,
    uint8_t *pPiccReturnCode, uint8_t *pErrLen)
{
  phStatus_t	PH_MEMLOC_REM wStatus = 0;
  uint8_t		PH_MEMLOC_REM aCmdBuf[PHHAL_HW_SAMAV3_ISO7816_HEADER_LENGTH];
  uint8_t		PH_MEMLOC_REM bCmdLen = 0;
  uint8_t 	*PH_MEMLOC_REM pResponse = NULL;
  uint16_t	PH_MEMLOC_REM wRespLen = 0;

  /* Validate the parameters. */
  PH_ASSERT_NULL_DATA_PARAM(pDataParams, PH_COMP_HAL);
  PH_ASSERT_NULL_PARAM(pData, PH_COMP_HAL);

  if (((wOption & PH_EXCHANGE_BUFFER_MASK) == PH_EXCHANGE_DEFAULT) ||
      ((wOption & PH_EXCHANGE_BUFFER_MASK) == PH_EXCHANGE_BUFFER_LAST)) {
    PH_ASSERT_NULL_PARAM(pPiccReturnCode, PH_COMP_HAL);
    PH_ASSERT_NULL_PARAM(pErrLen, PH_COMP_HAL);
  }

  /* Reset the command buffer and its length. */
  bCmdLen = 0;
  memset(aCmdBuf, 0x00, sizeof(aCmdBuf));	/* PRQA S 3200 */

  /* Buffer initial information to exchange buffer. */
  if (!(wOption & PH_EXCHANGE_LEAVE_BUFFER_BIT)) {
    /* Frame Cmd.DESFire_WriteX comamnd information. */
    aCmdBuf[bCmdLen++] = PHHAL_HW_SAMAV3_ISO7816_CLA_BYTE;
    aCmdBuf[bCmdLen++] = PHHAL_HW_SAMAV3_CMD_DESFIRE_WRITE_X_INS;
    aCmdBuf[bCmdLen++] = PHHAL_HW_SAMAV3_ISO7816_LAST_FRAME;
    aCmdBuf[bCmdLen++] = bCrypto;
    aCmdBuf[bCmdLen++] = PHHAL_HW_SAMAV3_ISO7816_DEFAULT_LC_BYTE;

    /* Update P1 information if chaining of data is performed. */
    if ((wOption & PH_EXCHANGE_MODE_MASK) == PH_EXCHANGE_TXCHAINING) {
      aCmdBuf[PHHAL_HW_SAMAV3_ISO7816_P1_POS] = PHHAL_HW_SAMAV3_ISO7816_CHAINED_FRAME;
    }

    /* Buffer command information to exchange buffer. */
    PH_CHECK_SUCCESS_FCT(wStatus, phhalHw_SamAV3_Cmd_7816Exchange(
            pDataParams,
            PH_EXCHANGE_BUFFER_FIRST,
            aCmdBuf,
            PHHAL_HW_SAMAV3_ISO7816_HEADER_LENGTH,
            NULL,
            NULL));
  }

  /* Buffer intermediate data to exchange buffer. */
  if (wOption & PH_EXCHANGE_BUFFERED_BIT) {
    PH_CHECK_SUCCESS_FCT(wStatus, phhalHw_SamAV3_Cmd_7816Exchange(
            pDataParams,
            PH_EXCHANGE_BUFFER_CONT,
            pData,
            bDataLen,
            NULL,
            NULL));
  }

  /* Buffer final information to exchange buffer. */
  else {
    /* Buffer data to exchange buffer. */
    PH_CHECK_SUCCESS_FCT(wStatus, phhalHw_SamAV3_Cmd_7816Exchange(
            pDataParams,
            PH_EXCHANGE_BUFFER_CONT,
            pData,
            bDataLen,
            NULL,
            NULL));

    /* Update LC. */
    PH_CHECK_SUCCESS_FCT(wStatus, phhalHw_SamAV3_Utils_UpdateLc(pDataParams));

    /* Buffer LE and exchange the bufferred information to SAM hardware. */
    wStatus = phhalHw_SamAV3_Cmd_7816Exchange(
            pDataParams,
            PH_EXCHANGE_BUFFER_LAST,
            gaDefaultLe,
            1,
            &pResponse,
            &wRespLen);

    /* Return the chaining code. */
    if ((wStatus & PH_ERR_MASK) == PHHAL_HW_SAMAV3_ERR_OK_CHAINING_ACTIVE) {
      return PH_ADD_COMPCODE(PH_ERR_SUCCESS_CHAINING, PH_COMP_HAL);
    }

    /* Extract the PICC error code. */
    if ((wStatus & PH_ERR_MASK) == PHHAL_HW_SAMAV3_ERR_DESFIRE_GEN) {
      /* Assign one byte PICC response code the parameter in case of Native command set. */
      if (wRespLen == 1) {
        *pPiccReturnCode = pResponse[0];
        *pErrLen = 1;
      }

      /* Assign two byte PICC response code the parameter in case of Native command set. */
      else {
        memcpy(pPiccReturnCode, pResponse, 2);		/* PRQA S 3200 */
        *pErrLen = 2;
      }
    }
  }

  return wStatus;
}

phStatus_t
phhalHw_SamAV3_Cmd_DESFire_ReadX(phhalHw_SamAV3_DataParams_t *pDataParams, uint16_t wOption,
    uint8_t bCrypto, uint8_t *pAppData, uint8_t bAppDataLen,
    uint8_t **ppResponse, uint16_t *pRespLen, uint8_t *pPiccReturnCode, uint8_t *pErrLen)
{
  phStatus_t	PH_MEMLOC_REM wStatus = 0;
  uint8_t		PH_MEMLOC_REM aCmdBuf[PHHAL_HW_SAMAV3_ISO7816_HEADER_LENGTH + 3 /* Length */];
  uint8_t		PH_MEMLOC_REM bCmdLen = 0;
  uint8_t 	*PH_MEMLOC_REM pResponse = NULL;
  uint16_t	PH_MEMLOC_REM wRespLen = 0;
  uint8_t		PH_MEMLOC_REM bAppDataOffset = 0;

  /* Validate the parameters. */
  PH_ASSERT_NULL_DATA_PARAM(pDataParams, PH_COMP_HAL);
  PH_ASSERT_NULL_PARAM(pRespLen, PH_COMP_HAL);
  PH_ASSERT_NULL_PARAM(pPiccReturnCode, PH_COMP_HAL);
  PH_ASSERT_NULL_PARAM(pErrLen, PH_COMP_HAL);

  /* Reset the command buffer and its length. */
  bCmdLen = 0;
  memset(aCmdBuf, 0x00, sizeof(aCmdBuf));	/* PRQA S 3200 */

  /* Frame Cmd.DESFire_ReadX comamnd information. */
  aCmdBuf[bCmdLen++] = PHHAL_HW_SAMAV3_ISO7816_CLA_BYTE;
  aCmdBuf[bCmdLen++] = PHHAL_HW_SAMAV3_CMD_DESFIRE_READ_X_INS;
  aCmdBuf[bCmdLen++] = PHHAL_HW_SAMAV3_ISO7816_DEFAULT_P1_BYTE;
  aCmdBuf[bCmdLen++] = bCrypto;

  /* Append LC in cases of Native Chaining  or First frame. */
  if (!(wOption & PHHAL_HW_CMD_SAMAV3_ISO_CHAINING) || !(wOption & PH_EXCHANGE_RXCHAINING)) {
    aCmdBuf[bCmdLen++] = PHHAL_HW_SAMAV3_ISO7816_DEFAULT_LC_BYTE;
  }

  /* If Communication mode is FULL and more data is expected. */
  if ((bCrypto == PHHAL_HW_CMD_SAMAV3_CRYPTO_CONFIG_COMM_MODE_FULL) &&
      !(wOption & PH_EXCHANGE_RXCHAINING)) {
    aCmdBuf[bCmdLen++] = pAppData[bAppDataOffset++];
    aCmdBuf[bCmdLen++] = pAppData[bAppDataOffset++];
    aCmdBuf[bCmdLen++] = pAppData[bAppDataOffset++];
  }

  /* Buffer command information to exchange buffer. */
  PH_CHECK_SUCCESS_FCT(wStatus, phhalHw_SamAV3_Cmd_7816Exchange(
          pDataParams,
          PH_EXCHANGE_BUFFER_FIRST,
          aCmdBuf,
          bCmdLen,
          NULL,
          NULL));

  PH_CHECK_SUCCESS_FCT(wStatus, phhalHw_SamAV3_Cmd_7816Exchange(
          pDataParams,
          PH_EXCHANGE_BUFFER_CONT,
          &pAppData[bAppDataOffset],
          (uint16_t)(bAppDataLen - bAppDataOffset),
          NULL,
          NULL));

  /* Update LC in case of Native Chaining or First frame. */
  if (!(wOption & PHHAL_HW_CMD_SAMAV3_ISO_CHAINING) || !(wOption & PH_EXCHANGE_RXCHAINING)) {
    PH_CHECK_SUCCESS_FCT(wStatus, phhalHw_SamAV3_Utils_UpdateLc(pDataParams));
  }

  /* Send Le byte and perform actual exchange */
  wStatus = phhalHw_SamAV3_Cmd_7816Exchange(
          pDataParams,
          PH_EXCHANGE_BUFFER_LAST,
          gaDefaultLe,
          1,
          &pResponse,
          &wRespLen);

  /* Return the chaining code. */
  if (((wStatus & PH_ERR_MASK) == PHHAL_HW_SAMAV3_ERR_OK_CHAINING_ACTIVE) ||
      ((wStatus & PH_ERR_MASK) == PH_ERR_SUCCESS)) {
    /* Update the response buffer with actual data for Success or Success Chaining. */
    *ppResponse = pResponse;
    *pRespLen = wRespLen;

    /* Return chaining status. */
    if ((wStatus & PH_ERR_MASK) == PHHAL_HW_SAMAV3_ERR_OK_CHAINING_ACTIVE) {
      return PH_ADD_COMPCODE(PH_ERR_SUCCESS_CHAINING, PH_COMP_HAL);
    }
  }

  /* Extract the PICC error code. */
  if ((wStatus & PH_ERR_MASK) == PHHAL_HW_SAMAV3_ERR_DESFIRE_GEN) {
    /* Assign one byte PICC response code the parameter in case of Native command set. */
    if (wRespLen == 1) {
      *pPiccReturnCode = pResponse[0];
      *pErrLen = 1;
    }

    /* Assign two byte PICC response code the parameter in case of Native command set. */
    else {
      memcpy(pPiccReturnCode, pResponse, 2);		/* PRQA S 3200 */
      *pErrLen = 2;
    }
  }

  return wStatus;
}

phStatus_t
phhalHw_SamAV3_Cmd_DESFire_CreateTMFilePICC(phhalHw_SamAV3_DataParams_t *pDataParams,
    uint8_t bOption, uint8_t bISOMode, uint8_t bKeyNo, uint8_t bKeyVer,
    uint8_t bFileNo, uint8_t bFileOption, uint8_t *pAccessRights, uint8_t bTMKeyOptions,
    uint8_t *pDivInput, uint8_t bDivInputLen, uint8_t *pPiccReturnCode)
{
  phStatus_t	PH_MEMLOC_REM wStatus = 0;
  uint8_t		PH_MEMLOC_REM aCmdBuf[PHHAL_HW_SAMAV3_ISO7816_HEADER_LENGTH +
                                            7 /* TM File information */];
  uint8_t		PH_MEMLOC_REM bCmdLen = 0;
  uint8_t 	*PH_MEMLOC_REM pResponse = NULL;
  uint16_t	PH_MEMLOC_REM wRespLen = 0;

  /* Validate the parameters. */
  PH_ASSERT_NULL_DATA_PARAM(pDataParams, PH_COMP_HAL);
  PH_ASSERT_NULL_PARAM(pAccessRights, PH_COMP_HAL);
  if (bOption) {
    PH_ASSERT_NULL_PARAM(pDivInput, PH_COMP_HAL);
  }
  PH_ASSERT_NULL_PARAM(pPiccReturnCode, PH_COMP_HAL);

  /* Reset the command buffer and its length. */
  bCmdLen = 0;
  memset(aCmdBuf, 0x00, sizeof(aCmdBuf));	/* PRQA S 3200 */

  /* Frame Cmd.DESFire_CreateTMFilePICC command information. */
  aCmdBuf[bCmdLen++] = PHHAL_HW_SAMAV3_ISO7816_CLA_BYTE;
  aCmdBuf[bCmdLen++] = PHHAL_HW_SAMAV3_CMD_DESFIRE_CREATE_TM_FILE_INS;
  aCmdBuf[bCmdLen++] = bOption;
  aCmdBuf[bCmdLen++] = bISOMode;
  aCmdBuf[bCmdLen++] = PHHAL_HW_SAMAV3_ISO7816_DEFAULT_LC_BYTE;

  /* Add the payload information. */
  aCmdBuf[bCmdLen++] = bKeyNo;
  aCmdBuf[bCmdLen++] = bKeyVer;
  aCmdBuf[bCmdLen++] = bFileNo;
  aCmdBuf[bCmdLen++] = bFileOption;
  aCmdBuf[bCmdLen++] = pAccessRights[0];
  aCmdBuf[bCmdLen++] = pAccessRights[1];
  aCmdBuf[bCmdLen++] = bTMKeyOptions;

  /* Buffer command information to exchange buffer. */
  PH_CHECK_SUCCESS_FCT(wStatus, phhalHw_SamAV3_Cmd_7816Exchange(
          pDataParams,
          PH_EXCHANGE_BUFFER_FIRST,
          aCmdBuf,
          bCmdLen,
          NULL,
          NULL));

  /* Buffer diversification input to exchange buffer. */
  PH_CHECK_SUCCESS_FCT(wStatus, phhalHw_SamAV3_Cmd_7816Exchange(
          pDataParams,
          PH_EXCHANGE_BUFFER_CONT,
          pDivInput,
          bDivInputLen,
          NULL,
          NULL));

  /* Update LC. */
  PH_CHECK_SUCCESS_FCT(wStatus, phhalHw_SamAV3_Utils_UpdateLc(pDataParams));

  /* Buffer LE and exchange the bufferred information to SAM hardware. */
  wStatus = phhalHw_SamAV3_Cmd_7816Exchange(
          pDataParams,
          PH_EXCHANGE_BUFFER_LAST,
          gaDefaultLe,
          1,
          &pResponse,
          &wRespLen);

  /* Extract the PICC error code. */
  if ((wStatus & PH_ERR_MASK) == PHHAL_HW_SAMAV3_ERR_DESFIRE_GEN) {
    /* Assign one byte PICC response code the parameter in case of Native command set. */
    if (bISOMode & PHHAL_HW_CMD_SAMAV3_ISO_MODE_ISO7816) {
      memcpy(pPiccReturnCode, pResponse, 2);		/* PRQA S 3200 */
    }

    /* Assign two byte PICC response code the parameter in case of Native command set. */
    else {
      *pPiccReturnCode = pResponse[0];
    }
  }

  return wStatus;
}

/*************************************************************************************************************************/
/************************************************* MIFARE Plus Commands **************************************************/
/*************************************************************************************************************************/

/* S - Mode Commands --------------------------------------------------------------------------------------------------- */

phStatus_t
phhalHw_SamAV3_Cmd_SAM_AuthenticateMFP_Part1(phhalHw_SamAV3_DataParams_t *pDataParams,
    uint8_t bOption, uint8_t bKeyNo,
    uint8_t bKeyVer, uint8_t *pPDChal, uint8_t bPDChalLen, uint8_t *pDivInput, uint8_t bDivInputLen,
    uint8_t **ppPCDChalResp,
    uint16_t *pPCDChalRespLen)
{
  phStatus_t	PH_MEMLOC_REM wStatus = 0;
  uint8_t		PH_MEMLOC_REM aCmdBuf[PHHAL_HW_SAMAV3_ISO7816_HEADER_LENGTH + 2 /* Key No and Ver */];
  uint8_t		PH_MEMLOC_REM bCmdLen = 0;

  /* Verify the parameter. */
  PH_ASSERT_NULL_DATA_PARAM(pDataParams, PH_COMP_HAL);
  if (bPDChalLen) {
    PH_ASSERT_NULL_PARAM(pPDChal, PH_COMP_HAL);
  }
  if (bDivInputLen) {
    PH_ASSERT_NULL_PARAM(pDivInput, PH_COMP_HAL);
  }
  PH_ASSERT_NULL_PARAM(pPCDChalRespLen, PH_COMP_HAL);

  /* Reset the command buffer and its length.*/
  bCmdLen = 0;
  memset(aCmdBuf, 0x00, sizeof(aCmdBuf));		/* PRQA S 3200 */

  /* Frame Cmd.SAM_AuthenticateMFP part 1 command information. */
  aCmdBuf[bCmdLen++]	= PHHAL_HW_SAMAV3_ISO7816_CLA_BYTE;
  aCmdBuf[bCmdLen++]	= PHHAL_HW_SAMAV3_CMD_AUTHENTICATE_MFP_INS;
  aCmdBuf[bCmdLen++]	= bOption;
  aCmdBuf[bCmdLen++]	= PHHAL_HW_SAMAV3_ISO7816_DEFAULT_P2_BYTE;
  aCmdBuf[bCmdLen++]	= PHHAL_HW_SAMAV3_ISO7816_DEFAULT_LC_BYTE;

  /* Append Key No */
  aCmdBuf[bCmdLen++] = bKeyNo;

  /* Append Key Ver */
  aCmdBuf[bCmdLen++] = bKeyVer;

  /* Buffer the command information to exchange buffer. */
  PH_CHECK_SUCCESS_FCT(wStatus, phhalHw_SamAV3_Cmd_7816Exchange(
          pDataParams,
          PH_EXCHANGE_BUFFER_FIRST,
          aCmdBuf,
          bCmdLen,
          NULL,
          NULL));

  /* Buffer PDChal information to exchange buffer. */
  PH_CHECK_SUCCESS_FCT(wStatus, phhalHw_SamAV3_Cmd_7816Exchange(
          pDataParams,
          PH_EXCHANGE_BUFFER_CONT,
          pPDChal,
          bPDChalLen,
          NULL,
          NULL));

  /* Buffer Diversification information to exchange buffer. */
  PH_CHECK_SUCCESS_FCT(wStatus, phhalHw_SamAV3_Cmd_7816Exchange(
          pDataParams,
          PH_EXCHANGE_BUFFER_CONT,
          pDivInput,
          bDivInputLen,
          NULL,
          NULL));

  /* Update LC. */
  PH_CHECK_SUCCESS_FCT(wStatus, phhalHw_SamAV3_Utils_UpdateLc(pDataParams));

  /* Buffer LE and exchange the bufferred information to SAM hardware. */
  wStatus = phhalHw_SamAV3_Cmd_7816Exchange(
          pDataParams,
          PH_EXCHANGE_BUFFER_LAST,
          gaDefaultLe,
          1,
          ppPCDChalResp,
          pPCDChalRespLen);

  /* Check for the Chaining active */
  if ((wStatus & PH_ERR_MASK) != PHHAL_HW_SAMAV3_ERR_OK_CHAINING_ACTIVE) {
    return wStatus;
  }

  return PH_ADD_COMPCODE(PH_ERR_SUCCESS_CHAINING, PH_COMP_HAL);
}

phStatus_t
phhalHw_SamAV3_Cmd_SAM_AuthenticateMFP_Part2(phhalHw_SamAV3_DataParams_t *pDataParams,
    uint8_t bPiccErrCode, uint8_t *pPDResp,
    uint8_t bPDRespLen, uint8_t **ppPDCap2, uint8_t **ppPCDCap2, uint8_t *pPiccReturnCode)
{
  phStatus_t	PH_MEMLOC_REM wStatus = 0;
  uint8_t		PH_MEMLOC_REM aCmdBuf[PHHAL_HW_SAMAV3_ISO7816_HEADER_LENGTH];
  uint8_t 	*PH_MEMLOC_REM pResponse = NULL;
  uint16_t	PH_MEMLOC_REM wRespLen = 0;

  /* Verify the parameter. */
  PH_ASSERT_NULL_DATA_PARAM(pDataParams, PH_COMP_HAL);
  if (bPDRespLen) {
    PH_ASSERT_NULL_PARAM(pPDResp, PH_COMP_HAL);
  }

  /* Reset the command buffer.*/
  memset(aCmdBuf, 0x00, sizeof(aCmdBuf));		/* PRQA S 3200 */

  /* Frame Cmd.SAM_AuthenticateMFP part 2 command information. */
  aCmdBuf[PHHAL_HW_SAMAV3_ISO7816_CLA_POS] = PHHAL_HW_SAMAV3_ISO7816_CLA_BYTE;
  aCmdBuf[PHHAL_HW_SAMAV3_ISO7816_INS_POS] = PHHAL_HW_SAMAV3_CMD_AUTHENTICATE_MFP_INS;
  aCmdBuf[PHHAL_HW_SAMAV3_ISO7816_P1_POS]  = PHHAL_HW_SAMAV3_ISO7816_DEFAULT_P1_BYTE;
  aCmdBuf[PHHAL_HW_SAMAV3_ISO7816_P2_POS]  = PHHAL_HW_SAMAV3_ISO7816_DEFAULT_P2_BYTE;
  aCmdBuf[PHHAL_HW_SAMAV3_ISO7816_LC_POS]  = PHHAL_HW_SAMAV3_ISO7816_DEFAULT_LC_BYTE;

  /* Buffer the command information to exchange buffer. */
  PH_CHECK_SUCCESS_FCT(wStatus, phhalHw_SamAV3_Cmd_7816Exchange(
          pDataParams,
          PH_EXCHANGE_BUFFER_FIRST,
          aCmdBuf,
          PHHAL_HW_SAMAV3_ISO7816_HEADER_LENGTH,
          NULL,
          NULL));

  /* Buffer PICC error code to exchange buffer. */
  if (bPiccErrCode != 0x90) {
    PH_CHECK_SUCCESS_FCT(wStatus, phhalHw_SamAV3_Cmd_7816Exchange(
            pDataParams,
            PH_EXCHANGE_BUFFER_CONT,
            &bPiccErrCode,
            1,
            NULL,
            NULL));
  }

  /* Buffer PDResp to exchange buffer. */
  if (bPiccErrCode == 0x90) {
    PH_CHECK_SUCCESS_FCT(wStatus, phhalHw_SamAV3_Cmd_7816Exchange(
            pDataParams,
            PH_EXCHANGE_BUFFER_CONT,
            pPDResp,
            bPDRespLen,
            NULL,
            NULL));
  }

  /* Update LC. */
  PH_CHECK_SUCCESS_FCT(wStatus, phhalHw_SamAV3_Utils_UpdateLc(pDataParams));

  /* Buffer LE and exchange the buffered information to SAM hardwre. */
  wStatus = phhalHw_SamAV3_Cmd_7816Exchange(
          pDataParams,
          PH_EXCHANGE_BUFFER_LAST,
          gaDefaultLe,
          1,
          &pResponse,
          &wRespLen);

  /* Extract the PICC error code. */
  if ((wStatus & PH_ERR_MASK) == PHHAL_HW_SAMAV3_ERR_MIFARE_PLUS_GEN) {
    /* Assign the PICC response code the parameter. */
    *pPiccReturnCode = pResponse[0];
  }

  /* Extract PCD and PD capabilities. */
  if ((wStatus & PH_ERR_MASK) == PH_ERR_SUCCESS) {
    /* Add the received response to reference parameters. */
    if (wRespLen) {
      /*
       * Check if memroy is created because from AL the pointer has a memory allocated from wrapper interface
       * but from HAL the wrapper thinks that the memory will be passed on from C library.
       *
       * Also when the memory is alocated by AL the data is available in the internal interface only and not available
       * in the C generic or wrapper interface. The data returned by C interface is always zero.
       */
      if ((ppPDCap2[0] != NULL) && (ppPCDCap2[0] != NULL)) {
        memcpy(*ppPDCap2, &pResponse[0], 6);
        memcpy(*ppPCDCap2, &pResponse[6], 6);
      } else {
        *ppPDCap2 = &pResponse[0];
        *ppPCDCap2 = &pResponse[6];
      }
    }
  }

  return wStatus;
}

phStatus_t
phhalHw_SamAV3_Cmd_SAM_AuthSectorSwitchMFP_Part1(phhalHw_SamAV3_DataParams_t *pDataParams,
    uint8_t bOption, uint8_t *pPDChal,
    uint8_t bPDChalLen, uint16_t wSSKeyBNr, uint8_t bSSKeyNo, uint8_t bSSKeyVer, uint8_t bMSKeyNo,
    uint8_t bMSKeyVer, uint8_t bSectorCount,
    uint8_t *pKeyBlocks, uint8_t bKeyBlocksLen, uint8_t *pDivInput, uint8_t bDivInputLen,
    uint8_t **ppPCDChalResp, uint16_t *pPCDChalRespLen)
{
  phStatus_t	PH_MEMLOC_REM wStatus = 0;
  uint8_t		PH_MEMLOC_REM aCmdBuf[PHHAL_HW_SAMAV3_ISO7816_HEADER_LENGTH +
                                            2 /* For payload information. */];
  uint8_t		PH_MEMLOC_REM bCmdLen = 0;

  /* Verify the parameter. */
  PH_ASSERT_NULL_DATA_PARAM(pDataParams, PH_COMP_HAL);
  if (bPDChalLen) {
    PH_ASSERT_NULL_PARAM(pPDChal, PH_COMP_HAL);
  }
  if (bKeyBlocksLen) {
    PH_ASSERT_NULL_PARAM(pKeyBlocks, PH_COMP_HAL);
  }
  if (bDivInputLen) {
    PH_ASSERT_NULL_PARAM(pDivInput, PH_COMP_HAL);
  }
  PH_ASSERT_NULL_PARAM(pPCDChalRespLen, PH_COMP_HAL);

  /* Reset the command buffer.*/
  memset(aCmdBuf, 0x00, sizeof(aCmdBuf));		/* PRQA S 3200 */

  /* Frame Cmd.SAM_AuthSectorSwitchMFP part 1 command information. */
  aCmdBuf[PHHAL_HW_SAMAV3_ISO7816_CLA_POS]	= PHHAL_HW_SAMAV3_ISO7816_CLA_BYTE;
  aCmdBuf[PHHAL_HW_SAMAV3_ISO7816_INS_POS]	= PHHAL_HW_SAMAV3_CMD_AUTH_SECTOR_SWITCH_MFP_INS;
  aCmdBuf[PHHAL_HW_SAMAV3_ISO7816_P1_POS]	= bOption;
  aCmdBuf[PHHAL_HW_SAMAV3_ISO7816_P2_POS]	= PHHAL_HW_SAMAV3_ISO7816_DEFAULT_P2_BYTE;
  aCmdBuf[PHHAL_HW_SAMAV3_ISO7816_LC_POS]	= PHHAL_HW_SAMAV3_ISO7816_DEFAULT_LC_BYTE;

  /* Buffer command information to exchange buffer. */
  PH_CHECK_SUCCESS_FCT(wStatus, phhalHw_SamAV3_Cmd_7816Exchange(
          pDataParams,
          PH_EXCHANGE_BUFFER_FIRST,
          aCmdBuf,
          PHHAL_HW_SAMAV3_ISO7816_HEADER_LENGTH,
          NULL,
          NULL));

  /* Buffer PDChal information to exchange buffer. */
  PH_CHECK_SUCCESS_FCT(wStatus, phhalHw_SamAV3_Cmd_7816Exchange(
          pDataParams,
          PH_EXCHANGE_BUFFER_CONT,
          pPDChal,
          bPDChalLen,
          NULL,
          NULL));

  /* Reset the command buffer and its length variable.*/
  bCmdLen = 0;
  memset(aCmdBuf, 0x00, sizeof(aCmdBuf));		/* PRQA S 3200 */

  /* Frame the initial Payload information. */
  aCmdBuf[bCmdLen++] = (uint8_t)(wSSKeyBNr & 0x00FF);
  aCmdBuf[bCmdLen++] = (uint8_t)((wSSKeyBNr & 0xFF00) >> 8);
  aCmdBuf[bCmdLen++] = bSSKeyNo;
  aCmdBuf[bCmdLen++] = bSSKeyVer;

  /* Add Master Key number and version if set in P1.*/
  if ((bOption & PHHAL_HW_SAMAV3_MFP_SSAUTH_MASTER_SECTOR_DIV_ON) ==
      PHHAL_HW_SAMAV3_MFP_SSAUTH_MASTER_SECTOR_DIV_ON) {
    aCmdBuf[bCmdLen++] = bMSKeyNo;
    aCmdBuf[bCmdLen++] = bMSKeyVer;
  }

  /* Add sector count to command buffer. */
  aCmdBuf[bCmdLen++] = bSectorCount;

  /* Buffer intial payload information to exchange buffer. */
  PH_CHECK_SUCCESS_FCT(wStatus, phhalHw_SamAV3_Cmd_7816Exchange(
          pDataParams,
          PH_EXCHANGE_BUFFER_CONT,
          aCmdBuf,
          bCmdLen,
          NULL,
          NULL));

  /* Buffer KeyBlocks information to exchange buffer. */
  PH_CHECK_SUCCESS_FCT(wStatus, phhalHw_SamAV3_Cmd_7816Exchange(
          pDataParams,
          PH_EXCHANGE_BUFFER_CONT,
          pKeyBlocks,
          bKeyBlocksLen,
          NULL,
          NULL));

  /* Buffer Diversification Input information to exchange buffer. */
  PH_CHECK_SUCCESS_FCT(wStatus, phhalHw_SamAV3_Cmd_7816Exchange(
          pDataParams,
          PH_EXCHANGE_BUFFER_CONT,
          pDivInput,
          bDivInputLen,
          NULL,
          NULL));

  /* Update LC. */
  PH_CHECK_SUCCESS_FCT(wStatus, phhalHw_SamAV3_Utils_UpdateLc(pDataParams));

  /* Buffer LE and exchange the bufferred information to SAM hardware. */
  wStatus = phhalHw_SamAV3_Cmd_7816Exchange(
          pDataParams,
          PH_EXCHANGE_BUFFER_LAST,
          gaDefaultLe,
          1,
          ppPCDChalResp,
          pPCDChalRespLen);

  /* Check for the Chaining active */
  if ((wStatus & PH_ERR_MASK) != PHHAL_HW_SAMAV3_ERR_OK_CHAINING_ACTIVE) {
    return wStatus;
  }

  return PH_ADD_COMPCODE(PH_ERR_SUCCESS_CHAINING, PH_COMP_HAL);
}

phStatus_t
phhalHw_SamAV3_Cmd_SAM_AuthSectorSwitchMFP_Part2(phhalHw_SamAV3_DataParams_t *pDataParams,
    uint8_t bPiccErrCode, uint8_t *pPDResp,
    uint8_t bPDRespLen, uint8_t *pPiccReturnCode)
{
  phStatus_t	PH_MEMLOC_REM wStatus = 0;
  uint8_t		PH_MEMLOC_REM aCmdBuf[PHHAL_HW_SAMAV3_ISO7816_HEADER_LENGTH];
  uint8_t 	*PH_MEMLOC_REM pResponse = NULL;
  uint16_t	PH_MEMLOC_REM wRespLen = 0;

  /* Verify the parameter. */
  PH_ASSERT_NULL_DATA_PARAM(pDataParams, PH_COMP_HAL);
  if (bPDRespLen) {
    PH_ASSERT_NULL_PARAM(pPDResp, PH_COMP_HAL);
  }

  /* Reset the command buffer.*/
  memset(aCmdBuf, 0x00, sizeof(aCmdBuf));		/* PRQA S 3200 */

  /* Frame the command Cmd.SAM_AuthSectorSwitchMFP part 2. */
  aCmdBuf[PHHAL_HW_SAMAV3_ISO7816_CLA_POS] = PHHAL_HW_SAMAV3_ISO7816_CLA_BYTE;
  aCmdBuf[PHHAL_HW_SAMAV3_ISO7816_INS_POS] = PHHAL_HW_SAMAV3_CMD_AUTH_SECTOR_SWITCH_MFP_INS;
  aCmdBuf[PHHAL_HW_SAMAV3_ISO7816_P1_POS]  = PHHAL_HW_SAMAV3_ISO7816_DEFAULT_P1_BYTE;
  aCmdBuf[PHHAL_HW_SAMAV3_ISO7816_P2_POS]  = PHHAL_HW_SAMAV3_ISO7816_DEFAULT_P2_BYTE;
  aCmdBuf[PHHAL_HW_SAMAV3_ISO7816_LC_POS]  = PHHAL_HW_SAMAV3_ISO7816_DEFAULT_LC_BYTE;

  /* Buffer the command information to exchange buffer. */
  PH_CHECK_SUCCESS_FCT(wStatus, phhalHw_SamAV3_Cmd_7816Exchange(
          pDataParams,
          PH_EXCHANGE_BUFFER_FIRST,
          aCmdBuf,
          PHHAL_HW_SAMAV3_ISO7816_HEADER_LENGTH,
          NULL,
          NULL));

  /* Buffer PICC error code to exchange buffer. */
  if (bPiccErrCode != 0x90) {
    PH_CHECK_SUCCESS_FCT(wStatus, phhalHw_SamAV3_Cmd_7816Exchange(
            pDataParams,
            PH_EXCHANGE_BUFFER_CONT,
            &bPiccErrCode,
            1,
            NULL,
            NULL));
  }

  /* Buffer PDResp to exchange buffer. */
  if (bPiccErrCode == 0x90) {
    PH_CHECK_SUCCESS_FCT(wStatus, phhalHw_SamAV3_Cmd_7816Exchange(
            pDataParams,
            PH_EXCHANGE_BUFFER_CONT,
            pPDResp,
            bPDRespLen,
            NULL,
            NULL));
  }

  /* Update LC. */
  PH_CHECK_SUCCESS_FCT(wStatus, phhalHw_SamAV3_Utils_UpdateLc(pDataParams));

  /* Exchange the bufferred information to SAM hardware. */
  wStatus = phhalHw_SamAV3_Cmd_7816Exchange(
          pDataParams,
          PH_EXCHANGE_BUFFER_LAST,
          gaDefaultLe,
          1,
          &pResponse,
          &wRespLen);

  /* Extract the PICC error code. */
  if ((wStatus & PH_ERR_MASK) == PHHAL_HW_SAMAV3_ERR_MIFARE_PLUS_GEN) {
    /* Assign the PICC response code the parameter. */
    *pPiccReturnCode = pResponse[0];
  }

  return wStatus;
}

phStatus_t
phhalHw_SamAV3_Cmd_SAM_AuthenticatePDC_Part1(phhalHw_SamAV3_DataParams_t *pDataParams,
    uint8_t bOption, uint8_t bKeyNo,
    uint8_t bKeyVer, uint8_t *pPDChal, uint8_t bPDChalLen, uint8_t *pUpgradeInfo, uint8_t bLen,
    uint8_t *pDivInput,
    uint8_t bDivInputLen, uint8_t **ppPCDChalResp, uint16_t *pPCDChalRespLen)
{
  phStatus_t	PH_MEMLOC_REM wStatus = 0;
  uint8_t		PH_MEMLOC_REM aCmdBuf[PHHAL_HW_SAMAV3_ISO7816_HEADER_LENGTH + 2 /* KeyNo, KeyVer */];
  uint8_t		PH_MEMLOC_REM bCmdLen = 0;

  /* Verify the parameter. */
  PH_ASSERT_NULL_DATA_PARAM(pDataParams, PH_COMP_HAL);
  if (bPDChalLen) {
    PH_ASSERT_NULL_PARAM(pPDChal, PH_COMP_HAL);
  }
  if (bLen) {
    PH_ASSERT_NULL_PARAM(pUpgradeInfo, PH_COMP_HAL);
  }
  PH_ASSERT_NULL_PARAM(pPCDChalRespLen, PH_COMP_HAL);

  /* Reset the command buffer and its length variable.*/
  bCmdLen = 0;
  memset(aCmdBuf, 0x00, sizeof(aCmdBuf));		/* PRQA S 3200 */

  /* Frame Cmd.SAM_AuthenticatePDC part 1 command information. */
  aCmdBuf[bCmdLen++]	= PHHAL_HW_SAMAV3_ISO7816_CLA_BYTE;
  aCmdBuf[bCmdLen++]	= PHHAL_HW_SAMAV3_CMD_AUTHENTICATE_PDC_INS;
  aCmdBuf[bCmdLen++]	= bOption;
  aCmdBuf[bCmdLen++]	= PHHAL_HW_SAMAV3_ISO7816_DEFAULT_P2_BYTE;
  aCmdBuf[bCmdLen++]	= PHHAL_HW_SAMAV3_ISO7816_DEFAULT_LC_BYTE;

  /* Add KeyNo and KeyVer to command buffer. */
  aCmdBuf[bCmdLen++] = bKeyNo;
  aCmdBuf[bCmdLen++] = bKeyVer;

  /* Buffer command information to exchange buffer. */
  PH_CHECK_SUCCESS_FCT(wStatus, phhalHw_SamAV3_Cmd_7816Exchange(
          pDataParams,
          PH_EXCHANGE_BUFFER_FIRST,
          aCmdBuf,
          bCmdLen,
          NULL,
          NULL));

  /* Buffer PDChal information to exchange buffer. */
  PH_CHECK_SUCCESS_FCT(wStatus, phhalHw_SamAV3_Cmd_7816Exchange(
          pDataParams,
          PH_EXCHANGE_BUFFER_CONT,
          pPDChal,
          bPDChalLen,
          NULL,
          NULL));

  /* Buffer Len information to exchange buffer. */
  PH_CHECK_SUCCESS_FCT(wStatus, phhalHw_SamAV3_Cmd_7816Exchange(
          pDataParams,
          PH_EXCHANGE_BUFFER_CONT,
          &bLen,
          1,
          NULL,
          NULL));

  /* Buffer UpgradeInfo information to exchange buffer. */
  PH_CHECK_SUCCESS_FCT(wStatus, phhalHw_SamAV3_Cmd_7816Exchange(
          pDataParams,
          PH_EXCHANGE_BUFFER_CONT,
          pUpgradeInfo,
          bLen,
          NULL,
          NULL));

  /* Buffer Diversification input information to exchange buffer. */
  PH_CHECK_SUCCESS_FCT(wStatus, phhalHw_SamAV3_Cmd_7816Exchange(
          pDataParams,
          PH_EXCHANGE_BUFFER_CONT,
          pDivInput,
          bDivInputLen,
          NULL,
          NULL));

  /* Update LC. */
  PH_CHECK_SUCCESS_FCT(wStatus, phhalHw_SamAV3_Utils_UpdateLc(pDataParams));

  /* Buffer LE and exchange the bufferred information to SAM hardware. */
  wStatus = phhalHw_SamAV3_Cmd_7816Exchange(
          pDataParams,
          PH_EXCHANGE_BUFFER_LAST,
          gaDefaultLe,
          1,
          ppPCDChalResp,
          pPCDChalRespLen);

  /* Check for the Chaining active */
  if ((wStatus & PH_ERR_MASK) != PHHAL_HW_SAMAV3_ERR_OK_CHAINING_ACTIVE) {
    return wStatus;
  }

  return PH_ADD_COMPCODE(PH_ERR_SUCCESS_CHAINING, PH_COMP_HAL);
}

phStatus_t
phhalHw_SamAV3_Cmd_SAM_AuthenticatePDC_Part2(phhalHw_SamAV3_DataParams_t *pDataParams,
    uint8_t bPiccErrCode, uint8_t *pPDResp,
    uint8_t bPDRespLen, uint8_t *pPiccReturnCode)
{
  phStatus_t	PH_MEMLOC_REM wStatus = 0;
  uint8_t		PH_MEMLOC_REM aCmdBuf[PHHAL_HW_SAMAV3_ISO7816_HEADER_LENGTH];
  uint8_t 	*PH_MEMLOC_REM pResponse = NULL;
  uint16_t	PH_MEMLOC_REM wRespLen = 0;

  /* Verify the parameter. */
  PH_ASSERT_NULL_DATA_PARAM(pDataParams, PH_COMP_HAL);
  if (bPDRespLen) {
    PH_ASSERT_NULL_PARAM(pPDResp, PH_COMP_HAL);
  }

  /* Reset the command buffer.*/
  memset(aCmdBuf, 0x00, sizeof(aCmdBuf));		/* PRQA S 3200 */

  /* Frame the command Cmd.SAM_AuthenticatePDC part 2. */
  aCmdBuf[PHHAL_HW_SAMAV3_ISO7816_CLA_POS] = PHHAL_HW_SAMAV3_ISO7816_CLA_BYTE;
  aCmdBuf[PHHAL_HW_SAMAV3_ISO7816_INS_POS] = PHHAL_HW_SAMAV3_CMD_AUTHENTICATE_PDC_INS;
  aCmdBuf[PHHAL_HW_SAMAV3_ISO7816_P1_POS]  = PHHAL_HW_SAMAV3_ISO7816_DEFAULT_P1_BYTE;
  aCmdBuf[PHHAL_HW_SAMAV3_ISO7816_P2_POS]  = PHHAL_HW_SAMAV3_ISO7816_DEFAULT_P2_BYTE;
  aCmdBuf[PHHAL_HW_SAMAV3_ISO7816_LC_POS]  = PHHAL_HW_SAMAV3_ISO7816_DEFAULT_LC_BYTE;

  /* Buffer the command information to exchange buffer. */
  PH_CHECK_SUCCESS_FCT(wStatus, phhalHw_SamAV3_Cmd_7816Exchange(
          pDataParams,
          PH_EXCHANGE_BUFFER_FIRST,
          aCmdBuf,
          PHHAL_HW_SAMAV3_ISO7816_HEADER_LENGTH,
          NULL,
          NULL));

  /* Buffer PICC error code to exchange buffer. */
  if (bPiccErrCode != 0x90) {
    PH_CHECK_SUCCESS_FCT(wStatus, phhalHw_SamAV3_Cmd_7816Exchange(
            pDataParams,
            PH_EXCHANGE_BUFFER_CONT,
            &bPiccErrCode,
            1,
            NULL,
            NULL));
  }

  /* Buffer PDResp to exchange buffer. */
  if (bPiccErrCode == 0x90) {
    PH_CHECK_SUCCESS_FCT(wStatus, phhalHw_SamAV3_Cmd_7816Exchange(
            pDataParams,
            PH_EXCHANGE_BUFFER_CONT,
            pPDResp,
            bPDRespLen,
            NULL,
            NULL));
  }

  /* Update LC. */
  PH_CHECK_SUCCESS_FCT(wStatus, phhalHw_SamAV3_Utils_UpdateLc(pDataParams));

  /* Buffer LE and exchange the buffered information to SAM hardwre. */
  wStatus = phhalHw_SamAV3_Cmd_7816Exchange(
          pDataParams,
          PH_EXCHANGE_BUFFER_LAST,
          gaDefaultLe,
          1,
          &pResponse,
          &wRespLen);

  /* Extract the PICC error code. */
  if ((wStatus & PH_ERR_MASK) == PHHAL_HW_SAMAV3_ERR_MIFARE_GEN) {
    /* Assign the PICC response code the parameter. */
    *pPiccReturnCode = pResponse[0];
  }

  return wStatus;
}

phStatus_t
phhalHw_SamAV3_Cmd_SAM_CombinedReadMFP(phhalHw_SamAV3_DataParams_t *pDataParams, uint8_t bLFI,
    uint16_t wOption, uint8_t *pData,
    uint8_t bDataLen, uint8_t **ppOutput, uint16_t *pOutputLen, uint8_t *pPiccReturnCode)
{
  phStatus_t	PH_MEMLOC_REM wStatus = 0;
  uint8_t		PH_MEMLOC_REM aCmdBuf[PHHAL_HW_SAMAV3_ISO7816_HEADER_LENGTH];

  /* Verify the parameter. */
  PH_ASSERT_NULL_DATA_PARAM(pDataParams, PH_COMP_HAL);
  if (bDataLen) {
    PH_ASSERT_NULL_PARAM(pData, PH_COMP_HAL);
  }
  if (((wOption & PHHAL_HW_SAMAV3_OPTION_COMBINED_READ_MFP_RESPONSE) ==
          PHHAL_HW_SAMAV3_OPTION_COMBINED_READ_MFP_RESPONSE) ||
      ((wOption & PHHAL_HW_SAMAV3_OPTION_COMBINED_READ_MFP_BOTH) ==
          PHHAL_HW_SAMAV3_OPTION_COMBINED_READ_MFP_BOTH)) {
    if (((wOption & PH_EXCHANGE_BUFFER_MASK) == PH_EXCHANGE_DEFAULT) ||
        ((wOption & PH_EXCHANGE_BUFFER_MASK) == PH_EXCHANGE_BUFFER_LAST)) {
      PH_ASSERT_NULL_PARAM(pOutputLen, PH_COMP_HAL);
      PH_ASSERT_NULL_PARAM(pPiccReturnCode, PH_COMP_HAL);
    }
  }

  /* Buffer the command information. */
  if (((wOption & PH_EXCHANGE_BUFFER_MASK) == PH_EXCHANGE_BUFFER_FIRST) ||
      ((wOption & PH_EXCHANGE_BUFFER_MASK) == PH_EXCHANGE_DEFAULT)) {
    /* Reset the command buffer. */
    memset(aCmdBuf, 0x00, sizeof(aCmdBuf));		/* PRQA S 3200 */

    /* Frame  Cmd.SAM_CombinedReadMFP command information. */
    aCmdBuf[PHHAL_HW_SAMAV3_ISO7816_CLA_POS]	= PHHAL_HW_SAMAV3_ISO7816_CLA_BYTE;
    aCmdBuf[PHHAL_HW_SAMAV3_ISO7816_INS_POS]	= PHHAL_HW_SAMAV3_CMD_COMBINED_READ_MFP_INS;
    aCmdBuf[PHHAL_HW_SAMAV3_ISO7816_P1_POS]	= (uint8_t)(wOption &
            PHHAL_HW_SAMAV3_OPTION_COMBINED_READ_MASK);
    aCmdBuf[PHHAL_HW_SAMAV3_ISO7816_P2_POS]	= bLFI;
    aCmdBuf[PHHAL_HW_SAMAV3_ISO7816_LC_POS]	= PHHAL_HW_SAMAV3_ISO7816_DEFAULT_LC_BYTE;

    /* Buffer the command information to exchange buffer. */
    PH_CHECK_SUCCESS_FCT(wStatus, phhalHw_SamAV3_Cmd_7816Exchange(
            pDataParams,
            PH_EXCHANGE_BUFFER_FIRST,
            aCmdBuf,
            PHHAL_HW_SAMAV3_ISO7816_HEADER_LENGTH,
            NULL,
            NULL));

    /* Buffer the data information to exchange buffer. */
    PH_CHECK_SUCCESS_FCT(wStatus, phhalHw_SamAV3_Cmd_7816Exchange(
            pDataParams,
            PH_EXCHANGE_BUFFER_CONT,
            pData,
            bDataLen,
            NULL,
            NULL));
  }

  /* Buffer the intermediate Data information to exchange buffer. */
  if ((wOption & PH_EXCHANGE_BUFFER_MASK) == PH_EXCHANGE_BUFFER_CONT) {
    PH_CHECK_SUCCESS_FCT(wStatus, phhalHw_SamAV3_Cmd_7816Exchange(
            pDataParams,
            PH_EXCHANGE_BUFFER_CONT,
            pData,
            bDataLen,
            NULL,
            NULL));
  }

  /* Buffer the last payload information and exchange bufferred information to SAM hardware. */
  if (((wOption & PH_EXCHANGE_BUFFER_MASK) == PH_EXCHANGE_BUFFER_LAST) ||
      ((wOption & PH_EXCHANGE_BUFFER_MASK) == PH_EXCHANGE_DEFAULT)) {
    /* Buffer the final data. */
    if ((wOption & PH_EXCHANGE_BUFFER_MASK) != PH_EXCHANGE_DEFAULT) {
      PH_CHECK_SUCCESS_FCT(wStatus, phhalHw_SamAV3_Cmd_7816Exchange(
              pDataParams,
              PH_EXCHANGE_BUFFER_CONT,
              pData,
              bDataLen,
              NULL,
              NULL));
    }

    /* Update LC. */
    PH_CHECK_SUCCESS_FCT(wStatus, phhalHw_SamAV3_Utils_UpdateLc(pDataParams));

    /* Buffer LE and exchange the bufferred information to SAM hardware. */
    wStatus = phhalHw_SamAV3_Cmd_7816Exchange(
            pDataParams,
            PH_EXCHANGE_BUFFER_LAST,
            gaDefaultLe,
            1,
            ppOutput,
            pOutputLen);

    /* Extract the PICC error code. */
    if ((wStatus & PH_ERR_MASK) == PHHAL_HW_SAMAV3_ERR_MIFARE_PLUS_GEN) {
      /* Assign the PICC response code the parameter. */
      *pPiccReturnCode = *ppOutput[0];
    }

    /* Set the Status for Chaiining. */
    if ((wStatus & PH_ERR_MASK) == PHHAL_HW_SAMAV3_ERR_OK_CHAINING_ACTIVE) {
      wStatus = PH_ADD_COMPCODE(PH_ERR_SUCCESS_CHAINING, PH_COMP_HAL);
    }
  }

  return wStatus;
}

phStatus_t
phhalHw_SamAV3_Cmd_SAM_CombinedWriteMFP(phhalHw_SamAV3_DataParams_t *pDataParams,
    uint16_t wOption, uint8_t *pData, uint8_t bDataLen,
    uint8_t **ppOutput, uint16_t *pOutputLen, uint8_t *pPiccReturnCode)
{
  phStatus_t  PH_MEMLOC_REM wStatus = 0;
  uint8_t     PH_MEMLOC_REM aCmdBuf[PHHAL_HW_SAMAV3_ISO7816_HEADER_LENGTH];

  /* Verify the parameter. */
  PH_ASSERT_NULL_DATA_PARAM(pDataParams, PH_COMP_HAL);
  if (bDataLen) {
    PH_ASSERT_NULL_PARAM(pData, PH_COMP_HAL);
  }
  if (((wOption & PH_EXCHANGE_BUFFER_MASK) == PH_EXCHANGE_DEFAULT) ||
      ((wOption & PH_EXCHANGE_BUFFER_MASK) == PH_EXCHANGE_BUFFER_LAST)) {
    if ((wOption & PHHAL_HW_SAMAV3_OPTION_COMBINED_WRITE_MFP_RESPONSE) ==
        PHHAL_HW_SAMAV3_OPTION_COMBINED_WRITE_MFP_RESPONSE) {
      PH_ASSERT_NULL_PARAM(pPiccReturnCode, PH_COMP_HAL);
    }
  }

  if (((wOption & PH_EXCHANGE_BUFFER_MASK) == PH_EXCHANGE_DEFAULT) ||
      ((wOption & PH_EXCHANGE_BUFFER_MASK) == PH_EXCHANGE_BUFFER_FIRST)) {
    /* Reset the command buffer.*/
    memset(aCmdBuf, 0x00, sizeof(aCmdBuf));		/* PRQA S 3200 */

    /* Frame Cmd.SAM_CombinedWriteMFP command information. */
    aCmdBuf[PHHAL_HW_SAMAV3_ISO7816_CLA_POS] = PHHAL_HW_SAMAV3_ISO7816_CLA_BYTE;
    aCmdBuf[PHHAL_HW_SAMAV3_ISO7816_INS_POS] = PHHAL_HW_SAMAV3_CMD_COMBINED_WRITE_MFP_INS;
    aCmdBuf[PHHAL_HW_SAMAV3_ISO7816_P1_POS]  = PHHAL_HW_SAMAV3_ISO7816_DEFAULT_P1_BYTE;
    aCmdBuf[PHHAL_HW_SAMAV3_ISO7816_P2_POS]  = PHHAL_HW_SAMAV3_ISO7816_DEFAULT_P2_BYTE;
    aCmdBuf[PHHAL_HW_SAMAV3_ISO7816_LC_POS]  = PHHAL_HW_SAMAV3_ISO7816_DEFAULT_LC_BYTE;

    /* Update P1 information byte.  */
    aCmdBuf[PHHAL_HW_SAMAV3_ISO7816_P1_POS]  |= (uint8_t)(wOption &
            PHHAL_HW_SAMAV3_OPTION_COMBINED_WRITE_MASK);
    aCmdBuf[PHHAL_HW_SAMAV3_ISO7816_P1_POS]  |= (uint8_t)(wOption &
            PHHAL_HW_SAMAV3_OPTION_COMBINED_WRITE_PLIAN_RESPONSE_MASK);

    /* Buffer the command information to exchange buffer. */
    PH_CHECK_SUCCESS_FCT(wStatus, phhalHw_SamAV3_Cmd_7816Exchange(
            pDataParams,
            PH_EXCHANGE_BUFFER_FIRST,
            aCmdBuf,
            PHHAL_HW_SAMAV3_ISO7816_HEADER_LENGTH,
            NULL,
            NULL));

    /* Add the data information to exchange buffer. */
    PH_CHECK_SUCCESS_FCT(wStatus, phhalHw_SamAV3_Cmd_7816Exchange(
            pDataParams,
            PH_EXCHANGE_BUFFER_CONT,
            pData,
            bDataLen,
            NULL,
            NULL));
  }

  /* Buffer intermediate data information to exchange buffer. */
  if ((wOption & PH_EXCHANGE_BUFFER_MASK) == PH_EXCHANGE_BUFFER_CONT) {
    /* Add the data information to exchange buffer. */
    PH_CHECK_SUCCESS_FCT(wStatus, phhalHw_SamAV3_Cmd_7816Exchange(
            pDataParams,
            PH_EXCHANGE_BUFFER_CONT,
            pData,
            bDataLen,
            NULL,
            NULL));
  }

  /* Buffer final data information to exchange buffer and exchange the bufferred information to Sam hardware. */
  if (((wOption & PH_EXCHANGE_BUFFER_MASK) == PH_EXCHANGE_DEFAULT) ||
      ((wOption & PH_EXCHANGE_BUFFER_MASK) == PH_EXCHANGE_BUFFER_LAST)) {
    if ((wOption & PH_EXCHANGE_BUFFER_MASK) != PH_EXCHANGE_DEFAULT) {
      /* Add the data information to exchange buffer. */
      PH_CHECK_SUCCESS_FCT(wStatus, phhalHw_SamAV3_Cmd_7816Exchange(
              pDataParams,
              PH_EXCHANGE_BUFFER_CONT,
              pData,
              bDataLen,
              NULL,
              NULL));
    }

    /* Update LC. */
    PH_CHECK_SUCCESS_FCT(wStatus, phhalHw_SamAV3_Utils_UpdateLc(pDataParams));

    /* Add LE to and exchange the bufferred information to SAM hardware. */
    wStatus = phhalHw_SamAV3_Cmd_7816Exchange(
            pDataParams,
            PH_EXCHANGE_BUFFER_LAST,
            gaDefaultLe,
            1,
            ppOutput,
            pOutputLen);

    /* Extract the PICC error code. */
    if ((wStatus & PH_ERR_MASK) == PHHAL_HW_SAMAV3_ERR_MIFARE_PLUS_GEN) {
      /* Assign the PICC response code the parameter. */
      *pPiccReturnCode = *ppOutput[0];
    }
  }

  return wStatus;
}

phStatus_t
phhalHw_SamAV3_Cmd_SAM_ChangeKeyMFP(phhalHw_SamAV3_DataParams_t *pDataParams, uint8_t bOption,
    uint8_t *pData, uint8_t bDataLen,
    uint8_t **ppProtectedData, uint16_t *pProtectedDataLen, uint8_t *pPiccReturnCode)
{
  phStatus_t	PH_MEMLOC_REM wStatus = 0;
  uint8_t		PH_MEMLOC_REM aCmdBuf[PHHAL_HW_SAMAV3_ISO7816_HEADER_LENGTH];

  /* Verify the parameter. */
  PH_ASSERT_NULL_DATA_PARAM(pDataParams, PH_COMP_HAL);
  if (bDataLen) {
    PH_ASSERT_NULL_PARAM(pData, PH_COMP_HAL);
  }
  PH_ASSERT_NULL_PARAM(pProtectedDataLen, PH_COMP_HAL);
  if ((bOption & PHHAL_HW_SAMAV3_OPTION_MFP_CHANGE_KEY_RESPONSE) ==
      PHHAL_HW_SAMAV3_OPTION_MFP_CHANGE_KEY_RESPONSE) {
    PH_ASSERT_NULL_PARAM(pPiccReturnCode, PH_COMP_HAL);
  }

  /* Reset the command buffer. */
  memset(aCmdBuf, 0x00, sizeof(aCmdBuf));		/* PRQA S 3200 */

  /* Frame Cmd.SAM_ChangeKeyMFP command information. */
  aCmdBuf[PHHAL_HW_SAMAV3_ISO7816_CLA_POS] = PHHAL_HW_SAMAV3_ISO7816_CLA_BYTE;
  aCmdBuf[PHHAL_HW_SAMAV3_ISO7816_INS_POS] = PHHAL_HW_SAMAV3_CMD_CHANGE_KEY_MFP_INS;
  aCmdBuf[PHHAL_HW_SAMAV3_ISO7816_P1_POS]  = bOption;
  aCmdBuf[PHHAL_HW_SAMAV3_ISO7816_P2_POS]  = PHHAL_HW_SAMAV3_ISO7816_DEFAULT_P2_BYTE;
  aCmdBuf[PHHAL_HW_SAMAV3_ISO7816_LC_POS]  = PHHAL_HW_SAMAV3_ISO7816_DEFAULT_LC_BYTE;

  /* Buffer commnad informration to exchange buffer. */
  PH_CHECK_SUCCESS_FCT(wStatus, phhalHw_SamAV3_Cmd_7816Exchange(
          pDataParams,
          PH_EXCHANGE_BUFFER_FIRST,
          aCmdBuf,
          PHHAL_HW_SAMAV3_ISO7816_HEADER_LENGTH,
          NULL,
          NULL));

  /* Buffer commnad informration to exchange buffer. */
  PH_CHECK_SUCCESS_FCT(wStatus, phhalHw_SamAV3_Cmd_7816Exchange(
          pDataParams,
          PH_EXCHANGE_BUFFER_CONT,
          pData,
          bDataLen,
          NULL,
          NULL));

  /* Update LC. */
  PH_CHECK_SUCCESS_FCT(wStatus, phhalHw_SamAV3_Utils_UpdateLc(pDataParams));

  /* Add LE to exchange buffer and exchange the bufferred information to SAM hardware. */
  wStatus = phhalHw_SamAV3_Cmd_7816Exchange(
          pDataParams,
          PH_EXCHANGE_BUFFER_LAST,
          gaDefaultLe,
          1,
          ppProtectedData,
          pProtectedDataLen);

  /* Extract the PICC error code. */
  if ((wStatus & PH_ERR_MASK) == PHHAL_HW_SAMAV3_ERR_MIFARE_PLUS_GEN) {
    /* Assign the PICC response code the parameter. */
    *pPiccReturnCode = *ppProtectedData[0];
  }

  return wStatus;
}

/* X - Mode Commands --------------------------------------------------------------------------------------------------- */

phStatus_t
phhalHw_SamAV3_Cmd_MFP_Authenticate(phhalHw_SamAV3_DataParams_t *pDataParams, uint8_t bOption,
    uint8_t bKeyNo, uint8_t bKeyVer,
    uint16_t wBlockNo, uint8_t *pPcdCapsIn, uint8_t bPcdCapsInLen, uint8_t *pDivInput,
    uint8_t bDivInputLen, uint8_t *pPcdCapsOut,
    uint8_t *pPdCaps, uint8_t *pPiccReturnCode)
{
  phStatus_t	PH_MEMLOC_REM wStatus = 0;
  uint8_t		PH_MEMLOC_REM aCmdBuf[PHHAL_HW_SAMAV3_ISO7816_HEADER_LENGTH +
                                            5 /* KeyNo, KeyVer, BNR, PcdCapInLen */];
  uint8_t		PH_MEMLOC_REM bCmdLen = 0;
  uint8_t 	*PH_MEMLOC_REM pResponse = NULL;
  uint16_t	PH_MEMLOC_REM wRespLen = 0;

  /* Verify the parameter. */
  PH_ASSERT_NULL_DATA_PARAM(pDataParams, PH_COMP_HAL);
  PH_ASSERT_NULL_PARAM(pPcdCapsOut, PH_COMP_HAL);
  PH_ASSERT_NULL_PARAM(pPdCaps, PH_COMP_HAL);
  PH_ASSERT_NULL_PARAM(pPiccReturnCode, PH_COMP_HAL);

  /* Reset the command buffer and its length.*/
  bCmdLen = 0;
  memset(aCmdBuf, 0x00, sizeof(aCmdBuf));		/* PRQA S 3200 */

  /* Frame Cmd.MFP_Authenticate command information. */
  aCmdBuf[bCmdLen++] = PHHAL_HW_SAMAV3_ISO7816_CLA_BYTE;
  aCmdBuf[bCmdLen++] = PHHAL_HW_SAMAV3_CMD_MFP_AUTHENTICATE_INS;
  aCmdBuf[bCmdLen++] = bOption;
  aCmdBuf[bCmdLen++] = PHHAL_HW_SAMAV3_ISO7816_DEFAULT_P2_BYTE;
  aCmdBuf[bCmdLen++] = PHHAL_HW_SAMAV3_ISO7816_DEFAULT_LC_BYTE + bPcdCapsInLen + bDivInputLen +
      5 /* KeyNo, KeyVer, BNR, PcdCapInLen */;

  /* Add the payload information to command buffer. */
  aCmdBuf[bCmdLen++] = bKeyNo;
  aCmdBuf[bCmdLen++] = bKeyVer;
  aCmdBuf[bCmdLen++] = (uint8_t)(wBlockNo & 0x00FF);
  aCmdBuf[bCmdLen++] = (uint8_t)((wBlockNo & 0xFF00) >> 8);
  aCmdBuf[bCmdLen++] = bPcdCapsInLen;

  /* Buffer the command information to exchange buffer. */
  PH_CHECK_SUCCESS_FCT(wStatus, phhalHw_SamAV3_Cmd_7816Exchange(
          pDataParams,
          PH_EXCHANGE_BUFFER_FIRST,
          aCmdBuf,
          bCmdLen,
          NULL,
          NULL));

  /* Buffer PCD capabilites to exchange buffer. */
  if (pPcdCapsIn != NULL) {
    PH_CHECK_SUCCESS_FCT(wStatus, phhalHw_SamAV3_Cmd_7816Exchange(
            pDataParams,
            PH_EXCHANGE_BUFFER_CONT,
            pPcdCapsIn,
            bPcdCapsInLen,
            NULL,
            NULL));
  }

  /* Buffer diversification to exchange buffer. */
  if (pDivInput != NULL) {
    PH_CHECK_SUCCESS_FCT(wStatus, phhalHw_SamAV3_Cmd_7816Exchange(
            pDataParams,
            PH_EXCHANGE_BUFFER_CONT,
            pDivInput,
            bDivInputLen,
            NULL,
            NULL));
  }

  /* Buffer Le to exchange buffer and exchange the bufferred information to SAM hardware. */
  wStatus = phhalHw_SamAV3_Cmd_7816Exchange(
          pDataParams,
          PH_EXCHANGE_BUFFER_LAST,
          gaDefaultLe,
          1,
          &pResponse,
          &wRespLen);

  /* Extract the PICC error code. */
  if ((wStatus & PH_ERR_MASK) == PHHAL_HW_SAMAV3_ERR_MIFARE_PLUS_GEN) {
    /* Assign the PICC response code the parameter. */
    *pPiccReturnCode = pResponse[0];
  }

  /* Extract PCD and PD capabilities. */
  if ((wStatus & PH_ERR_MASK) == PH_ERR_SUCCESS) {
    /* Assign the PCD and PD capabilities to the parameter. */
    memcpy(pPdCaps, &pResponse[0], 6);		/* PRQA S 3200 */
    memcpy(pPcdCapsOut, &pResponse[6], 6);	/* PRQA S 3200 */
  }

  return wStatus;
}

phStatus_t
phhalHw_SamAV3_Cmd_MFP_AuthSectorSwitch(phhalHw_SamAV3_DataParams_t *pDataParams,
    uint16_t wOption, uint16_t wSSKeyBNr, uint8_t bSSKeyNo,
    uint8_t bSSKeyVer, uint8_t bMSKeyNo, uint8_t bMSKeyVer, uint8_t bSectorCount, uint8_t *pKeyBlocks,
    uint8_t bKeyBlocksLen,  uint8_t *pDivInput,
    uint8_t bDivInputLen, uint8_t *pPiccReturnCode)
{
  phStatus_t	PH_MEMLOC_REM wStatus = 0;
  uint8_t		PH_MEMLOC_REM aCmdBuf[PHHAL_HW_SAMAV3_ISO7816_HEADER_LENGTH +
                                            7 /* SSKeyBNr, SSKeyNo, SSKeyVer, MsKeyNo, MSKeyVer, SectorCount */];
  uint8_t		PH_MEMLOC_REM bCmdLen = 0;
  uint8_t 	*PH_MEMLOC_REM pResponse = NULL;
  uint16_t	PH_MEMLOC_REM wRespLen = 0;

  /* Verify the parameter. */
  PH_ASSERT_NULL_DATA_PARAM(pDataParams, PH_COMP_HAL);

  if (((wOption & PH_EXCHANGE_BUFFER_MASK) == PH_EXCHANGE_DEFAULT) ||
      ((wOption & PH_EXCHANGE_BUFFER_MASK) == PH_EXCHANGE_BUFFER_LAST)) {
    PH_ASSERT_NULL_PARAM(pPiccReturnCode, PH_COMP_HAL);
  }

  /* Buffer the command information. */
  if (((wOption & PH_EXCHANGE_BUFFER_MASK) == PH_EXCHANGE_BUFFER_FIRST) ||
      ((wOption & PH_EXCHANGE_BUFFER_MASK) == PH_EXCHANGE_DEFAULT)) {
    /* Reset the command buffer and its length.*/
    bCmdLen = 0;
    memset(aCmdBuf, 0x00, sizeof(aCmdBuf));		/* PRQA S 3200 */

    /* Frame Cmd.MFP_AuthSectorSwitch header. */
    aCmdBuf[bCmdLen++] = PHHAL_HW_SAMAV3_ISO7816_CLA_BYTE;
    aCmdBuf[bCmdLen++] = PHHAL_HW_SAMAV3_CMD_MFP_AUTH_SECTOR_SWITCH_INS;
    aCmdBuf[bCmdLen++] = (uint8_t)(wOption & 0x07 /* Masking out the buffering options. */);
    aCmdBuf[bCmdLen++] = PHHAL_HW_SAMAV3_ISO7816_DEFAULT_P2_BYTE;
    aCmdBuf[bCmdLen++] = PHHAL_HW_SAMAV3_ISO7816_DEFAULT_LC_BYTE;

    /* Add the payload information to command buffer. */
    aCmdBuf[bCmdLen++] = (uint8_t)(wSSKeyBNr & 0x00FF);
    aCmdBuf[bCmdLen++] = (uint8_t)((wSSKeyBNr & 0xFF00) >> 8);
    aCmdBuf[bCmdLen++] = bSSKeyNo;
    aCmdBuf[bCmdLen++] = bSSKeyVer;

    /* Add Master Key number and version if set in P1.*/
    if ((wOption & PHHAL_HW_SAMAV3_MFP_SSAUTH_MASTER_SECTOR_DIV_ON) ==
        PHHAL_HW_SAMAV3_MFP_SSAUTH_MASTER_SECTOR_DIV_ON) {
      aCmdBuf[bCmdLen++] = bMSKeyNo;
      aCmdBuf[bCmdLen++] = bMSKeyVer;
    }

    /* Add Sector count to command buffer. */
    aCmdBuf[bCmdLen++] = bSectorCount;

    /* Buffer the command information to exchange buffer. */
    PH_CHECK_SUCCESS_FCT(wStatus, phhalHw_SamAV3_Cmd_7816Exchange(
            pDataParams,
            PH_EXCHANGE_BUFFER_FIRST,
            aCmdBuf,
            bCmdLen,
            NULL,
            NULL));

    /* Buffer the KeyBlocks information to exchange buffer. */
    PH_CHECK_SUCCESS_FCT(wStatus, phhalHw_SamAV3_Cmd_7816Exchange(
            pDataParams,
            PH_EXCHANGE_BUFFER_CONT,
            pKeyBlocks,
            bKeyBlocksLen,
            NULL,
            NULL));

    /* Update LC. */
    PH_CHECK_SUCCESS_FCT(wStatus, phhalHw_SamAV3_Utils_UpdateLc(pDataParams));
  }

  /* Buffer the intermediate KeyBlocks or DivInput information to exchange buffer. */
  if ((wOption & PH_EXCHANGE_BUFFER_MASK) == PH_EXCHANGE_BUFFER_CONT) {
    /* Buffer KeyBlocks to exchange buffer. */
    if ((wOption & PHHAL_HW_SAMAV3_MFP_SSAUTH_BUFFER_KEY_BLOCKS) ==
        PHHAL_HW_SAMAV3_MFP_SSAUTH_BUFFER_KEY_BLOCKS) {
      PH_CHECK_SUCCESS_FCT(wStatus, phhalHw_SamAV3_Cmd_7816Exchange(
              pDataParams,
              PH_EXCHANGE_BUFFER_CONT,
              pKeyBlocks,
              bKeyBlocksLen,
              NULL,
              NULL));
    }

    /* Buffer DivInput to exchange buffer. */
    if ((wOption & PHHAL_HW_SAMAV3_MFP_SSAUTH_BUFFER_DIV_INPUT) ==
        PHHAL_HW_SAMAV3_MFP_SSAUTH_BUFFER_DIV_INPUT) {
      PH_CHECK_SUCCESS_FCT(wStatus, phhalHw_SamAV3_Cmd_7816Exchange(
              pDataParams,
              PH_EXCHANGE_BUFFER_CONT,
              pDivInput,
              bDivInputLen,
              NULL,
              NULL));
    }

    /* Update LC. */
    PH_CHECK_SUCCESS_FCT(wStatus, phhalHw_SamAV3_Utils_UpdateLc(pDataParams));
  }

  /* Buffer the last payload information and exchange bufferred information to SAM hardware. */
  if (((wOption & PH_EXCHANGE_BUFFER_MASK) == PH_EXCHANGE_BUFFER_LAST) ||
      ((wOption & PH_EXCHANGE_BUFFER_MASK) == PH_EXCHANGE_DEFAULT)) {
    /* Buffer the final data. */
    PH_CHECK_SUCCESS_FCT(wStatus, phhalHw_SamAV3_Cmd_7816Exchange(
            pDataParams,
            PH_EXCHANGE_BUFFER_CONT,
            pDivInput,
            bDivInputLen,
            NULL,
            NULL));

    /* Update LC. */
    PH_CHECK_SUCCESS_FCT(wStatus, phhalHw_SamAV3_Utils_UpdateLc(pDataParams));

    /* Buffer Le to exchange buffer and exchange the bufferred information to SAM hardware. */
    wStatus = phhalHw_SamAV3_Cmd_7816Exchange(
            pDataParams,
            PH_EXCHANGE_BUFFER_LAST,
            gaDefaultLe,
            1,
            &pResponse,
            &wRespLen);

    /* Extract the PICC error code. */
    if ((wStatus & PH_ERR_MASK) == PHHAL_HW_SAMAV3_ERR_MIFARE_PLUS_GEN) {
      /* Assign the PICC response code the parameter. */
      *pPiccReturnCode = pResponse[0];
    }
  }

  return wStatus;
}

phStatus_t
phhalHw_SamAV3_Cmd_PDC_Authenticate(phhalHw_SamAV3_DataParams_t *pDataParams, uint8_t bOption,
    uint8_t bKeyNo, uint8_t bKeyVer,
    uint16_t wUpgradeKey, uint8_t *pUpgradeInfo, uint8_t bLen, uint8_t *pDivInput,
    uint8_t bDivInputLen, uint8_t *pPiccReturnCode)
{
  phStatus_t	PH_MEMLOC_REM wStatus = 0;
  uint8_t		PH_MEMLOC_REM aCmdBuf[PHHAL_HW_SAMAV3_ISO7816_HEADER_LENGTH +
                                            5 /* KeyNo, KeyVer, UpgradeKey, Len */];
  uint8_t		PH_MEMLOC_REM bCmdLen = 0;
  uint8_t 	*PH_MEMLOC_REM pResponse = NULL;
  uint16_t	PH_MEMLOC_REM wRespLen = 0;

  /* Verify the parameter. */
  PH_ASSERT_NULL_DATA_PARAM(pDataParams, PH_COMP_HAL);

  /* Reset the command buffer and its length.*/
  bCmdLen = 0;
  memset(aCmdBuf, 0x00, sizeof(aCmdBuf));		/* PRQA S 3200 */

  /* Frame Cmd.PDC_Authenticate information. */
  aCmdBuf[bCmdLen++] = PHHAL_HW_SAMAV3_ISO7816_CLA_BYTE;
  aCmdBuf[bCmdLen++] = PHHAL_HW_SAMAV3_CMD_PDC_AUTHENTICATE_INS;
  aCmdBuf[bCmdLen++] = bOption;
  aCmdBuf[bCmdLen++] = PHHAL_HW_SAMAV3_ISO7816_DEFAULT_P2_BYTE;
  aCmdBuf[bCmdLen++] = 5 /* KeyNo, KeyVer, UpgradeKey, Len */ + bLen + bDivInputLen;

  /* Add payload information to command buffer. */
  aCmdBuf[bCmdLen++] = bKeyNo;
  aCmdBuf[bCmdLen++] = bKeyVer;
  aCmdBuf[bCmdLen++] = (uint8_t)(wUpgradeKey & 0x00FF);
  aCmdBuf[bCmdLen++] = (uint8_t)((wUpgradeKey & 0xFF00) >> 8);
  aCmdBuf[bCmdLen++] = bLen;

  /* Buffer the command information to exchange buffer. */
  PH_CHECK_SUCCESS_FCT(wStatus, phhalHw_SamAV3_Cmd_7816Exchange(
          pDataParams,
          PH_EXCHANGE_BUFFER_FIRST,
          aCmdBuf,
          bCmdLen,
          NULL,
          NULL));

  /* Buffer UpgradeInfo to exchange buffer */
  if (pUpgradeInfo != NULL) {
    PH_CHECK_SUCCESS_FCT(wStatus, phhalHw_SamAV3_Cmd_7816Exchange(
            pDataParams,
            PH_EXCHANGE_BUFFER_CONT,
            pUpgradeInfo,
            bLen,
            NULL,
            NULL));
  }

  /* Buffer DivInput to exchage buffer */
  if (pDivInput != NULL) {
    PH_CHECK_SUCCESS_FCT(wStatus, phhalHw_SamAV3_Cmd_7816Exchange(
            pDataParams,
            PH_EXCHANGE_BUFFER_CONT,
            pDivInput,
            bDivInputLen,
            NULL,
            NULL));
  }

  /* Buffer Le to exchange buffer and exchange the bufferred information to SAM hardware. */
  wStatus = phhalHw_SamAV3_Cmd_7816Exchange(
          pDataParams,
          PH_EXCHANGE_BUFFER_LAST,
          gaDefaultLe,
          1,
          &pResponse,
          &wRespLen);

  /* Extract the PICC error code. */
  if ((wStatus & PH_ERR_MASK) == PHHAL_HW_SAMAV3_ERR_MIFARE_GEN) {
    /* Assign the PICC response code the parameter. */
    *pPiccReturnCode = pResponse[0];
  }

  return wStatus;
}

phStatus_t
phhalHw_SamAV3_Cmd_MFP_CombinedRead(phhalHw_SamAV3_DataParams_t *pDataParams,  uint16_t wOption,
    uint8_t *pReadCmd,
    uint8_t bReadCmdLen, uint8_t **ppData, uint16_t *pDataLen, uint8_t *pPiccReturnCode)
{
  phStatus_t	PH_MEMLOC_REM wStatus = 0;
  uint8_t		PH_MEMLOC_REM aCmdBuf[PHHAL_HW_SAMAV3_ISO7816_HEADER_LENGTH];
  uint8_t		PH_MEMLOC_REM bCmdLen = 0;

  /* Verify the parameter. */
  PH_ASSERT_NULL_DATA_PARAM(pDataParams, PH_COMP_HAL);
  if (wOption != PH_EXCHANGE_RXCHAINING) {
    PH_ASSERT_NULL_PARAM(pReadCmd, PH_COMP_HAL);
  }
  PH_ASSERT_NULL_PARAM(pDataLen, PH_COMP_HAL);
  PH_ASSERT_NULL_PARAM(pPiccReturnCode, PH_COMP_HAL);

  /* Reset the command buffer and its length. */
  bCmdLen = 0;
  memset(aCmdBuf, 0x00, sizeof(aCmdBuf));	/* PRQA S 3200 */

  /* Frame Cmd.MFP_CombinedRead command information. */
  aCmdBuf[bCmdLen++]	= PHHAL_HW_SAMAV3_ISO7816_CLA_BYTE;
  aCmdBuf[bCmdLen++]	= PHHAL_HW_SAMAV3_CMD_MFP_COMBINED_READ_INS;
  aCmdBuf[bCmdLen++]	= PHHAL_HW_SAMAV3_ISO7816_DEFAULT_P1_BYTE;
  aCmdBuf[bCmdLen++]	= PHHAL_HW_SAMAV3_ISO7816_DEFAULT_P2_BYTE;

  /* Add LC is the option is not chaining. */
  if (wOption != PH_EXCHANGE_RXCHAINING) {
    aCmdBuf[bCmdLen++]	= bReadCmdLen;
  }

  /* Buffer the command information to exchange buffer. */
  PH_CHECK_SUCCESS_FCT(wStatus, phhalHw_SamAV3_Cmd_7816Exchange(
          pDataParams,
          PH_EXCHANGE_BUFFER_FIRST,
          aCmdBuf,
          bCmdLen,
          NULL,
          NULL));

  /* Buffer the ReadCmd information to exchange buffer. */
  PH_CHECK_SUCCESS_FCT(wStatus, phhalHw_SamAV3_Cmd_7816Exchange(
          pDataParams,
          PH_EXCHANGE_BUFFER_CONT,
          pReadCmd,
          bReadCmdLen,
          NULL,
          NULL));

  /* Buffer Le to exchange buffer and exchange the bufferred information to SAM hardware. */
  wStatus = phhalHw_SamAV3_Cmd_7816Exchange(
          pDataParams,
          PH_EXCHANGE_BUFFER_LAST,
          gaDefaultLe,
          1,
          ppData,
          pDataLen);

  /* Extract the PICC error code. */
  if (((wStatus & PH_ERR_MASK) == PHHAL_HW_SAMAV3_ERR_MIFARE_PLUS_GEN) ||
      ((wStatus & PH_ERR_MASK) == PHHAL_HW_SAMAV3_ERR_OK_CHAINING_ACTIVE) ||
      ((wStatus & PH_ERR_MASK) == PH_ERR_SUCCESS)) {
    /* Update the pointer address and length if First Frame. */
    if (wOption != PH_EXCHANGE_RXCHAINING) {
      /* Assign the PICC response code the parameter. */
      *pPiccReturnCode = *ppData[0];

      ppData[0]++;
      *pDataLen = *pDataLen - 1;
    }
  }

  /* Return the chaining code. */
  if ((wStatus & PH_ERR_MASK) == PHHAL_HW_SAMAV3_ERR_OK_CHAINING_ACTIVE) {
    return PH_ADD_COMPCODE(PH_ERR_SUCCESS_CHAINING, PH_COMP_HAL);
  }

  return wStatus;
}

phStatus_t
phhalHw_SamAV3_Cmd_MFP_CombinedWrite(phhalHw_SamAV3_DataParams_t *pDataParams, uint16_t wOption,
    uint8_t *pData, uint8_t bDataLen,
    uint8_t *pTMC, uint8_t *pTMV, uint8_t *pPiccReturnCode)
{
  phStatus_t  PH_MEMLOC_REM wStatus = 0;
  uint8_t     PH_MEMLOC_REM aCmdBuf[PHHAL_HW_SAMAV3_ISO7816_HEADER_LENGTH];
  uint8_t    *PH_MEMLOC_REM pResponse = NULL;
  uint16_t    PH_MEMLOC_REM wRespLen = 0;

  /* Verify the parameter. */
  PH_ASSERT_NULL_DATA_PARAM(pDataParams, PH_COMP_HAL);
  if (bDataLen) {
    PH_ASSERT_NULL_PARAM(pData, PH_COMP_HAL);
  }

  if ((wOption == PH_EXCHANGE_BUFFER_LAST) || (wOption == PH_EXCHANGE_DEFAULT)) {
    PH_ASSERT_NULL_PARAM(pPiccReturnCode, PH_COMP_HAL);
  }

  /* Buffer the command information. */
  if ((wOption == PH_EXCHANGE_BUFFER_FIRST) || (wOption == PH_EXCHANGE_DEFAULT)) {
    /* Reset the command buffer. */
    memset(aCmdBuf, 0x00, sizeof(aCmdBuf));	/* PRQA S 3200 */

    /* Frame Cmd.MFP_CombinedWrite command information. */
    aCmdBuf[PHHAL_HW_SAMAV3_ISO7816_CLA_POS]	= PHHAL_HW_SAMAV3_ISO7816_CLA_BYTE;
    aCmdBuf[PHHAL_HW_SAMAV3_ISO7816_INS_POS]	= PHHAL_HW_SAMAV3_CMD_MFP_COMBINED_WRITE_INS;
    aCmdBuf[PHHAL_HW_SAMAV3_ISO7816_P1_POS]	= PHHAL_HW_SAMAV3_ISO7816_DEFAULT_P1_BYTE;
    aCmdBuf[PHHAL_HW_SAMAV3_ISO7816_P2_POS]	= PHHAL_HW_SAMAV3_ISO7816_DEFAULT_P2_BYTE;
    aCmdBuf[PHHAL_HW_SAMAV3_ISO7816_LC_POS]	= PHHAL_HW_SAMAV3_ISO7816_DEFAULT_LC_BYTE;

    /* Buffer the command information to exchange buffer. */
    PH_CHECK_SUCCESS_FCT(wStatus, phhalHw_SamAV3_Cmd_7816Exchange(
            pDataParams,
            PH_EXCHANGE_BUFFER_FIRST,
            aCmdBuf,
            PHHAL_HW_SAMAV3_ISO7816_HEADER_LENGTH,
            NULL,
            NULL));

    /* Buffer the data information to exchange buffer. */
    PH_CHECK_SUCCESS_FCT(wStatus, phhalHw_SamAV3_Cmd_7816Exchange(
            pDataParams,
            PH_EXCHANGE_BUFFER_CONT,
            pData,
            bDataLen,
            NULL,
            NULL));
  }

  /* Buffer the intermediate payload information to exchange buffer. */
  if (wOption == PH_EXCHANGE_BUFFER_CONT) {
    PH_CHECK_SUCCESS_FCT(wStatus, phhalHw_SamAV3_Cmd_7816Exchange(
            pDataParams,
            PH_EXCHANGE_BUFFER_CONT,
            pData,
            bDataLen,
            NULL,
            NULL));
  }

  /* Buffer the last payload information and exchange bufferred information to SAM hardware. */
  if ((wOption == PH_EXCHANGE_BUFFER_LAST) || (wOption == PH_EXCHANGE_DEFAULT)) {
    if (wOption != PH_EXCHANGE_DEFAULT) {
      /* Buffer the final data. */
      PH_CHECK_SUCCESS_FCT(wStatus, phhalHw_SamAV3_Cmd_7816Exchange(
              pDataParams,
              PH_EXCHANGE_BUFFER_CONT,
              pData,
              bDataLen,
              NULL,
              NULL));
    }

    /* Update LC. */
    PH_CHECK_SUCCESS_FCT(wStatus, phhalHw_SamAV3_Utils_UpdateLc(pDataParams));

    /* Buffer Le to exchange buffer and exchange the bufferred information to SAM hardware. */
    wStatus = phhalHw_SamAV3_Cmd_7816Exchange(
            pDataParams,
            PH_EXCHANGE_BUFFER_LAST,
            gaDefaultLe,
            1,
            &pResponse,
            &wRespLen);

    /* Extract the PICC error code. */
    if (((wStatus & PH_ERR_MASK) == PHHAL_HW_SAMAV3_ERR_MIFARE_PLUS_GEN) ||
        ((wStatus & PH_ERR_MASK) == PH_ERR_SUCCESS)) {
      if (wRespLen) {
        /* Assign the PICC response code the parameter. */
        *pPiccReturnCode = pResponse[0];
      }
    }

    /* Extract TMC and TMV information. */
    if ((wStatus & PH_ERR_MASK) == PH_ERR_SUCCESS) {
      /* Assign the TMC and TMV to the parameter if the block is TM protected block. */
      if (wRespLen > 1) {
        if (pTMC != NULL) {
          memcpy(pTMC, &pResponse[1], 4);			/* PRQA S 3200 */
        }

        if (pTMV != NULL) {
          memcpy(pTMV, &pResponse[5], 8);			/* PRQA S 3200 */
        }
      }
    }
  }

  return wStatus;
}

phStatus_t
phhalHw_SamAV3_Cmd_MFP_ChangeKey(phhalHw_SamAV3_DataParams_t *pDataParams, uint8_t bOption,
    uint8_t bCmdCode, uint16_t wBlockNo,
    uint8_t bKeyNo, uint8_t bKeyVer, uint8_t *pDivInput, uint8_t bDivInputLen,
    uint8_t *pPiccReturnCode)
{
  phStatus_t	PH_MEMLOC_REM wStatus = 0;
  uint8_t		PH_MEMLOC_REM aCmdBuf[PHHAL_HW_SAMAV3_ISO7816_HEADER_LENGTH +
                                            5 /* CmdCode, BlockNo, KeyNo, KeyVer */];
  uint8_t		PH_MEMLOC_REM bCmdLen = 0;
  uint8_t 	*PH_MEMLOC_REM pResponse = NULL;
  uint16_t	PH_MEMLOC_REM wRespLen = 0;

  /* Verify the parameter. */
  PH_ASSERT_NULL_DATA_PARAM(pDataParams, PH_COMP_HAL);
  PH_ASSERT_NULL_PARAM(pPiccReturnCode, PH_COMP_HAL);

  /* Reset the command buffer and its length variable. */
  bCmdLen = 0;
  memset(aCmdBuf, 0x00, sizeof(aCmdBuf));	/* PRQA S 3200 */

  /* Frame Cmd.MFP_ChangeKey command information. */
  aCmdBuf[bCmdLen++] = PHHAL_HW_SAMAV3_ISO7816_CLA_BYTE;
  aCmdBuf[bCmdLen++] = PHHAL_HW_SAMAV3_CMD_MFP_CHANGE_KEY_INS;
  aCmdBuf[bCmdLen++] = (uint8_t)(bOption >> 1);
  aCmdBuf[bCmdLen++] = PHHAL_HW_SAMAV3_ISO7816_DEFAULT_P2_BYTE;
  aCmdBuf[bCmdLen++] = 5 /* CmdCode, BlockNo, KeyNo, KeyVer */ + bDivInputLen;

  /* Add payload information to command buffer. */
  aCmdBuf[bCmdLen++] = bCmdCode;
  aCmdBuf[bCmdLen++] = (uint8_t)(wBlockNo & 0x00FF);
  aCmdBuf[bCmdLen++] = (uint8_t)((wBlockNo & 0xFF00) >> 8);
  aCmdBuf[bCmdLen++] = bKeyNo;
  aCmdBuf[bCmdLen++] = bKeyVer;

  /* Buffer the command information to exchange buffer. */
  PH_CHECK_SUCCESS_FCT(wStatus, phhalHw_SamAV3_Cmd_7816Exchange(
          pDataParams,
          PH_EXCHANGE_BUFFER_FIRST,
          aCmdBuf,
          bCmdLen,
          NULL,
          NULL));

  /* Buffer DivInput to exchange buffer. */
  if (pDivInput != NULL) {
    PH_CHECK_SUCCESS_FCT(wStatus, phhalHw_SamAV3_Cmd_7816Exchange(
            pDataParams,
            PH_EXCHANGE_BUFFER_CONT,
            pDivInput,
            bDivInputLen,
            NULL,
            NULL));
  }

  /* Update LC. */
  PH_CHECK_SUCCESS_FCT(wStatus, phhalHw_SamAV3_Utils_UpdateLc(pDataParams));

  /* Buffer Le to exchange buffer and exchange the bufferred information to SAM hardware. */
  wStatus = phhalHw_SamAV3_Cmd_7816Exchange(
          pDataParams,
          PH_EXCHANGE_BUFFER_LAST,
          gaDefaultLe,
          1,
          &pResponse,
          &wRespLen);

  /* Extract the PICC error code. */
  if ((wStatus & PH_ERR_MASK) == PHHAL_HW_SAMAV3_ERR_MIFARE_PLUS_GEN) {
    /* Assign the PICC response code the parameter. */
    *pPiccReturnCode = pResponse[0];
  }

  return wStatus;
}

phStatus_t
phhalHw_SamAV3_Cmd_MFP_WritePerso(phhalHw_SamAV3_DataParams_t *pDataParams, uint16_t wOption,
    uint8_t *pBlocks, uint8_t bBlocksLen,
    uint8_t *pPiccReturnCode)
{
  phStatus_t  PH_MEMLOC_REM wStatus = 0;
  uint8_t     PH_MEMLOC_REM aCmdBuf[PHHAL_HW_SAMAV3_ISO7816_HEADER_LENGTH];
  uint8_t    *PH_MEMLOC_REM pResponse = NULL;
  uint16_t    PH_MEMLOC_REM wRespLen = 0;

  /* Verify the parameter. */
  PH_ASSERT_NULL_DATA_PARAM(pDataParams, PH_COMP_HAL);
  if ((wOption == PH_EXCHANGE_BUFFER_LAST)) {
    PH_ASSERT_NULL_PARAM(pPiccReturnCode, PH_COMP_HAL);
  }

  /* Buffer the command information. */
  if ((wOption == PH_EXCHANGE_BUFFER_FIRST) || (wOption == PH_EXCHANGE_DEFAULT)) {
    /* Reset the command buffer. */
    memset(aCmdBuf, 0x00, sizeof(aCmdBuf));	/* PRQA S 3200 */

    /* Frame Cmd.MFP_WritePerso command information. */
    aCmdBuf[PHHAL_HW_SAMAV3_ISO7816_CLA_POS]	= PHHAL_HW_SAMAV3_ISO7816_CLA_BYTE;
    aCmdBuf[PHHAL_HW_SAMAV3_ISO7816_INS_POS]	= PHHAL_HW_SAMAV3_CMD_MFP_WRITE_PERSO_INS;
    aCmdBuf[PHHAL_HW_SAMAV3_ISO7816_P1_POS]	= PHHAL_HW_SAMAV3_ISO7816_DEFAULT_P1_BYTE;
    aCmdBuf[PHHAL_HW_SAMAV3_ISO7816_P2_POS]	= PHHAL_HW_SAMAV3_ISO7816_DEFAULT_P2_BYTE;
    aCmdBuf[PHHAL_HW_SAMAV3_ISO7816_LC_POS]	= PHHAL_HW_SAMAV3_ISO7816_DEFAULT_LC_BYTE;

    /* Buffer the command information to exchange buffer. */
    PH_CHECK_SUCCESS_FCT(wStatus, phhalHw_SamAV3_Cmd_7816Exchange(
            pDataParams,
            PH_EXCHANGE_BUFFER_FIRST,
            aCmdBuf,
            PHHAL_HW_SAMAV3_ISO7816_HEADER_LENGTH,
            NULL,
            NULL));

    /* Buffer the data information to exchange buffer. */
    PH_CHECK_SUCCESS_FCT(wStatus, phhalHw_SamAV3_Cmd_7816Exchange(
            pDataParams,
            PH_EXCHANGE_BUFFER_CONT,
            pBlocks,
            bBlocksLen,
            NULL,
            NULL));
  }

  /* Buffer the intermediate payload information to exchange buffer. */
  if (wOption == PH_EXCHANGE_BUFFER_CONT) {
    PH_CHECK_SUCCESS_FCT(wStatus, phhalHw_SamAV3_Cmd_7816Exchange(
            pDataParams,
            PH_EXCHANGE_BUFFER_CONT,
            pBlocks,
            bBlocksLen,
            NULL,
            NULL));
  }

  /* Buffer the last payload information and exchange bufferred information to SAM hardware. */
  if ((wOption == PH_EXCHANGE_BUFFER_LAST) || (wOption == PH_EXCHANGE_DEFAULT)) {
    if (wOption != PH_EXCHANGE_DEFAULT) {
      /* Buffer the final data. */
      PH_CHECK_SUCCESS_FCT(wStatus, phhalHw_SamAV3_Cmd_7816Exchange(
              pDataParams,
              PH_EXCHANGE_BUFFER_CONT,
              pBlocks,
              bBlocksLen,
              NULL,
              NULL));
    }

    /* Update LC. */
    PH_CHECK_SUCCESS_FCT(wStatus, phhalHw_SamAV3_Utils_UpdateLc(pDataParams));

    /* Buffer Le to exchange buffer and exchange the bufferred information to SAM hardware. */
    wStatus = phhalHw_SamAV3_Cmd_7816Exchange(
            pDataParams,
            PH_EXCHANGE_BUFFER_LAST,
            gaDefaultLe,
            1,
            &pResponse,
            &wRespLen);

    /* Extract the PICC error code. */
    if (((wStatus & PH_ERR_MASK) != PH_ERR_SUCCESS) &&
        ((wStatus & PH_ERR_MASK) != PHHAL_HW_SAMAV3_ERR_MIFARE_PLUS_GEN)) {
      return wStatus;
    }

    /* Assign the PICC response code the parameter. */
    *pPiccReturnCode = pResponse[0];
  }

  return wStatus;
}

/*************************************************************************************************************************/
/**************************************************** MIFARE Classic *****************************************************/
/*************************************************************************************************************************/

/* S - Mode Commands --------------------------------------------------------------------------------------------------- */

phStatus_t
phhalHw_SamAV3_Cmd_SAM_AuthenticateMIFARE_Part1(phhalHw_SamAV3_DataParams_t *pDataParams,
    uint8_t bOption, uint8_t *pMFUID,
    uint8_t bKeyNo, uint8_t bKeyVer, uint8_t bKeyType, uint8_t bMFBlockNo, uint8_t bDivBlockNo,
    uint8_t *pNumberRB, uint8_t bNumRBLen,
    uint8_t **ppEncToken, uint16_t *pEncTokenLen)
{
  phStatus_t	PH_MEMLOC_REM wStatus = 0;
  uint8_t		PH_MEMLOC_REM aCmdBuf[19];
  uint8_t		PH_MEMLOC_REM bCmdLen = 0;

  /* Validate the parameters. */
  PH_ASSERT_NULL_DATA_PARAM(pDataParams, PH_COMP_HAL);
  PH_ASSERT_NULL_PARAM(pMFUID, PH_COMP_HAL);
  PH_ASSERT_NULL_PARAM(pNumberRB, PH_COMP_HAL);
  if (bOption > PHHAL_HW_SAMAV3_CMD_AUTHENTICATE_MIFARE_DIV_ON) {
    return PH_ADD_COMPCODE(PH_ERR_INVALID_PARAMETER, PH_COMP_HAL);
  }

  /* Reset the command buffer and its length variable. */
  bCmdLen = 0;
  memset(aCmdBuf, 0x00, sizeof(aCmdBuf));	/* PRQA S 3200 */

  /* Frame Cmd.SAM_AuthenticateMIFARE part1 comamnd information. */
  aCmdBuf[bCmdLen++] = PHHAL_HW_SAMAV3_ISO7816_CLA_BYTE;
  aCmdBuf[bCmdLen++] = PHHAL_HW_SAMAV3_CMD_SAM_AUTHENTICATE_MIFARE_INS;
  aCmdBuf[bCmdLen++] = PHHAL_HW_SAMAV3_ISO7816_DEFAULT_P1_BYTE;
  aCmdBuf[bCmdLen++] = PHHAL_HW_SAMAV3_ISO7816_DEFAULT_P2_BYTE;
  aCmdBuf[bCmdLen++] = PHHAL_HW_SAMAV3_ISO7816_DEFAULT_LC_BYTE;

  /* Add MIFARE UID to command buffer. */
  memcpy(&aCmdBuf[bCmdLen], pMFUID, 4 /* MIFARE Classic UID's last 4 bytes. */);	/* PRQA S 3200 */
  bCmdLen += (uint8_t) 4 /* MIFARE Classic UID's last 4 bytes. */;

  /* Add key no, key version, key type and MIFARE block number to command buffer. */
  aCmdBuf[bCmdLen++] = bKeyNo;
  aCmdBuf[bCmdLen++] = bKeyVer;
  aCmdBuf[bCmdLen++] = bKeyType;
  aCmdBuf[bCmdLen++] = bMFBlockNo;

  /* Add NumberRB command buffer.  */
  memcpy(&aCmdBuf[bCmdLen], pNumberRB, bNumRBLen);	/* PRQA S 3200 */
  bCmdLen += bNumRBLen;

  /* Add Diversification block number if required. */
  if (bOption) {
    aCmdBuf[bCmdLen++] = bDivBlockNo;
  }

  /* Buffer the command information to exchange buffer. */
  PH_CHECK_SUCCESS_FCT(wStatus, phhalHw_SamAV3_Cmd_7816Exchange(
          pDataParams,
          PH_EXCHANGE_BUFFER_FIRST,
          aCmdBuf,
          bCmdLen,
          NULL,
          NULL));

  /* Update LC. */
  PH_CHECK_SUCCESS_FCT(wStatus, phhalHw_SamAV3_Utils_UpdateLc(pDataParams));

  /* Buffer Le to exchange buffer and exchange the bufferred information to Sam hardware. */
  wStatus = phhalHw_SamAV3_Cmd_7816Exchange(
          pDataParams,
          PH_EXCHANGE_BUFFER_LAST,
          gaDefaultLe,
          1,
          ppEncToken,
          pEncTokenLen);

  /* Update with actual chaining code instead of custom error code for chaining response.
   * Update 0x029B to 0x0271
   */
  if (wStatus == PH_ADD_COMPCODE(PHHAL_HW_SAMAV3_ERR_OK_CHAINING_ACTIVE, PH_COMP_HAL)) {
    return PH_ADD_COMPCODE(PH_ERR_SUCCESS_CHAINING, PH_COMP_HAL);
  }

  return wStatus;
}

phStatus_t
phhalHw_SamAV3_Cmd_SAM_AuthenticateMIFARE_Part2(phhalHw_SamAV3_DataParams_t *pDataParams,
    uint8_t  *pEncToken, uint8_t bEncTokenLen)
{
  phStatus_t	PH_MEMLOC_REM wStatus = 0;
  uint8_t		PH_MEMLOC_REM aCmdBuf[PHHAL_HW_SAMAV3_ISO7816_HEADER_LENGTH];
  uint8_t 	*PH_MEMLOC_REM pResponse = NULL;
  uint16_t	PH_MEMLOC_REM wRespLen = 0;

  /* Validate the parameters. */
  PH_ASSERT_NULL_DATA_PARAM(pDataParams, PH_COMP_HAL);
  PH_ASSERT_NULL_PARAM(pEncToken, PH_COMP_HAL);

  /* Reset the command buffer. */
  memset(aCmdBuf, 0x00, sizeof(aCmdBuf));	/* PRQA S 3200 */

  /* Frame Cmd.SAM_AuthenticateMIFARE part2 comamnd information. */
  aCmdBuf[PHHAL_HW_SAMAV3_ISO7816_CLA_POS] = PHHAL_HW_SAMAV3_ISO7816_CLA_BYTE;
  aCmdBuf[PHHAL_HW_SAMAV3_ISO7816_INS_POS] = PHHAL_HW_SAMAV3_CMD_SAM_AUTHENTICATE_MIFARE_INS;
  aCmdBuf[PHHAL_HW_SAMAV3_ISO7816_P1_POS]  = PHHAL_HW_SAMAV3_ISO7816_DEFAULT_P1_BYTE;
  aCmdBuf[PHHAL_HW_SAMAV3_ISO7816_P2_POS]  = PHHAL_HW_SAMAV3_ISO7816_DEFAULT_P2_BYTE;
  aCmdBuf[PHHAL_HW_SAMAV3_ISO7816_LC_POS]  = bEncTokenLen;

  /* Buffer the command information to command buffer. */
  PH_CHECK_SUCCESS_FCT(wStatus, phhalHw_SamAV3_Cmd_7816Exchange(
          pDataParams,
          PH_EXCHANGE_BUFFER_FIRST,
          aCmdBuf,
          PHHAL_HW_SAMAV3_ISO7816_HEADER_LENGTH,
          NULL,
          NULL));

  /* Buffer the command information to command buffer. */
  PH_CHECK_SUCCESS_FCT(wStatus, phhalHw_SamAV3_Cmd_7816Exchange(
          pDataParams,
          PH_EXCHANGE_BUFFER_LAST,
          pEncToken,
          bEncTokenLen,
          &pResponse,
          &wRespLen));

  return PH_ADD_COMPCODE(PH_ERR_SUCCESS, PH_COMP_HAL);
}

phStatus_t
phhalHw_SamAV3_Cmd_SAM_ChangeKeyMIFARE(phhalHw_SamAV3_DataParams_t *pDataParams, uint8_t bOption,
    uint8_t bKeyNo, uint8_t bKeyVerA,
    uint8_t bKeyVerB, uint8_t *pAccCond, uint8_t *pMFUID, uint8_t bDivBlockNo, uint8_t **ppProtData,
    uint16_t *pProtDataLen)
{
  phStatus_t	PH_MEMLOC_REM wStatus = 0;
  uint8_t		PH_MEMLOC_REM aCmdBuf[18];
  uint8_t		PH_MEMLOC_REM bCmdLen = 0;

  /* Validate the parameters. */
  PH_ASSERT_NULL_DATA_PARAM(pDataParams, PH_COMP_HAL);
  PH_ASSERT_NULL_PARAM(pAccCond, PH_COMP_HAL);
  if ((bOption & PHHAL_HW_SAMAV3_CMD_CHANGE_KEY_MIFARE_DIV_A_ON) ||
      (bOption & PHHAL_HW_SAMAV3_CMD_CHANGE_KEY_MIFARE_DIV_B_ON)) {
    PH_ASSERT_NULL_PARAM(pMFUID, PH_COMP_HAL);
  }
  PH_ASSERT_NULL_PARAM(pProtDataLen, PH_COMP_HAL);

  /* Reset the command buffer and its length variable. */
  bCmdLen = 0;
  memset(aCmdBuf, 0x00, sizeof(aCmdBuf));	/* PRQA S 3200 */

  /* Frame Cmd.SAM_AuthenticateMIFARE part1 comamnd information. */
  aCmdBuf[bCmdLen++] = PHHAL_HW_SAMAV3_ISO7816_CLA_BYTE;
  aCmdBuf[bCmdLen++] = PHHAL_HW_SAMAV3_CMD_SAM_CHANGE_KEY_MIFARE_INS;
  aCmdBuf[bCmdLen++] = (uint8_t)(bOption & PHHAL_HW_SAMAV3_CMD_CHANGE_KEY_MIFARE_DIV_MASK);
  aCmdBuf[bCmdLen++] = PHHAL_HW_SAMAV3_ISO7816_DEFAULT_P2_BYTE;
  aCmdBuf[bCmdLen++] = PHHAL_HW_SAMAV3_ISO7816_DEFAULT_LC_BYTE;

  /* Add key no and key version to command buffer. */
  aCmdBuf[bCmdLen++] = bKeyNo;
  aCmdBuf[bCmdLen++] = bKeyVerA;
  aCmdBuf[bCmdLen++] = bKeyVerB;

  /* Add Access coditions to command buffer. */
  memcpy(&aCmdBuf[bCmdLen], pAccCond, 4 /* MIFARE Classic access condition. */);	/* PRQA S 3200 */
  bCmdLen += (uint8_t) 4 /* MIFARE Classic access condition. */;

  /* Add MIFARE UID and diversification block number to command buffer if diverification is enabled. */
  if ((bOption & PHHAL_HW_SAMAV3_CMD_CHANGE_KEY_MIFARE_DIV_A_ON) ||
      (bOption & PHHAL_HW_SAMAV3_CMD_CHANGE_KEY_MIFARE_DIV_B_ON)) {
    /* Add MIFARE UID to command buffer. */
    memcpy(&aCmdBuf[bCmdLen], pMFUID, 4 /* MIFARE Classic UID's last 4 bytes. */);	/* PRQA S 3200 */
    bCmdLen += (uint8_t) 4 /* MIFARE Classic UID's last 4 bytes. */;

    /* Add diversification block number. */
    aCmdBuf[bCmdLen++] = bDivBlockNo;
  }

  /* Buffer the command information to exchange buffer. */
  PH_CHECK_SUCCESS_FCT(wStatus, phhalHw_SamAV3_Cmd_7816Exchange(
          pDataParams,
          PH_EXCHANGE_BUFFER_FIRST,
          aCmdBuf,
          bCmdLen,
          NULL,
          NULL));

  /* Update LC. */
  PH_CHECK_SUCCESS_FCT(wStatus, phhalHw_SamAV3_Utils_UpdateLc(pDataParams));

  /* Buffer Le to exchange buffer and exchange the bufferred information to Sam hardware. */
  PH_CHECK_SUCCESS_FCT(wStatus, phhalHw_SamAV3_Cmd_7816Exchange(
          pDataParams,
          PH_EXCHANGE_BUFFER_LAST,
          gaDefaultLe,
          1,
          ppProtData,
          pProtDataLen));

  return PH_ADD_COMPCODE(PH_ERR_SUCCESS, PH_COMP_HAL);
}

phStatus_t
phhalHw_SamAV3_Cmd_SAM_ChangeKeyMIFAREDump(phhalHw_SamAV3_DataParams_t *pDataParams,
    uint8_t bOption, uint8_t bKeyNo, uint8_t bKeyVer,
    uint8_t bKeyType, uint8_t *pMFUID, uint8_t bDivBlockNo, uint8_t **ppSecretKey,
    uint16_t *pSecretKeyLen)
{
  phStatus_t	PH_MEMLOC_REM wStatus = 0;
  uint8_t		PH_MEMLOC_REM aCmdBuf[13];
  uint8_t		PH_MEMLOC_REM bCmdLen = 0;

  /* Validate the parameters. */
  PH_ASSERT_NULL_DATA_PARAM(pDataParams, PH_COMP_HAL);
  if ((bOption & PHHAL_HW_SAMAV3_CMD_CHANGE_KEY_MIFARE_DIV_A_ON) ||
      (bOption & PHHAL_HW_SAMAV3_CMD_CHANGE_KEY_MIFARE_DIV_B_ON)) {
    PH_ASSERT_NULL_PARAM(pMFUID, PH_COMP_HAL);
  }
  PH_ASSERT_NULL_PARAM(pSecretKeyLen, PH_COMP_HAL);

  /* Reset the command buffer and its length variable. */
  bCmdLen = 0;
  memset(aCmdBuf, 0x00, sizeof(aCmdBuf));	/* PRQA S 3200 */

  /* Frame Cmd.SAM_AuthenticateMIFARE part1 comamnd information. */
  aCmdBuf[bCmdLen++] = PHHAL_HW_SAMAV3_ISO7816_CLA_BYTE;
  aCmdBuf[bCmdLen++] = PHHAL_HW_SAMAV3_CMD_SAM_CHANGE_KEY_MIFARE_INS;
  aCmdBuf[bCmdLen++] = (uint8_t)(bOption & PHHAL_HW_SAMAV3_CMD_CHANGE_KEY_MIFARE_DIV_MASK);
  aCmdBuf[bCmdLen++] = (uint8_t)(bOption & PHHAL_HW_SAMAV3_CMD_CHANGE_KEY_MIFARE_CRYPTO_MASK);
  aCmdBuf[bCmdLen++] = PHHAL_HW_SAMAV3_ISO7816_DEFAULT_LC_BYTE;

  /* Add key no, key version and key type to command buffer. */
  aCmdBuf[bCmdLen++] = bKeyNo;
  aCmdBuf[bCmdLen++] = bKeyVer;
  aCmdBuf[bCmdLen++] = bKeyType;

  /* Add MIFARE UID and diversification block number to command buffer if diverification is enabled. */
  if ((bOption & PHHAL_HW_SAMAV3_CMD_CHANGE_KEY_MIFARE_DIV_A_ON) ||
      (bOption & PHHAL_HW_SAMAV3_CMD_CHANGE_KEY_MIFARE_DIV_B_ON)) {
    /* Add MIFARE UID to command buffer. */
    memcpy(&aCmdBuf[bCmdLen], pMFUID, 4 /* MIFARE Classic UID's last 4 bytes. */);	/* PRQA S 3200 */
    bCmdLen += (uint8_t) 4 /* MIFARE Classic UID's last 4 bytes. */;

    /* Add diversification block number. */
    aCmdBuf[bCmdLen++] = bDivBlockNo;
  }

  /* Buffer the command information to exchange buffer. */
  PH_CHECK_SUCCESS_FCT(wStatus, phhalHw_SamAV3_Cmd_7816Exchange(
          pDataParams,
          PH_EXCHANGE_BUFFER_FIRST,
          aCmdBuf,
          bCmdLen,
          NULL,
          NULL));

  /* Update LC. */
  PH_CHECK_SUCCESS_FCT(wStatus, phhalHw_SamAV3_Utils_UpdateLc(pDataParams));

  /* Buffer Le to exchange buffer and exchange the bufferred information to Sam hardware. */
  PH_CHECK_SUCCESS_FCT(wStatus, phhalHw_SamAV3_Cmd_7816Exchange(
          pDataParams,
          PH_EXCHANGE_BUFFER_LAST,
          gaDefaultLe,
          1,
          ppSecretKey,
          pSecretKeyLen));

  return PH_ADD_COMPCODE(PH_ERR_SUCCESS, PH_COMP_HAL);
}

/* X - Mode Commands --------------------------------------------------------------------------------------------------- */

phStatus_t
phhalHw_SamAV3_Cmd_MF_Authenticate(phhalHw_SamAV3_DataParams_t *pDataParams, uint8_t bOption,
    uint8_t *pMFUID,
    uint8_t bKeyNo, uint8_t bKeyVer, uint8_t bKeyType, uint8_t bMFBlockNo, uint8_t bDivBlockNo)
{
  phStatus_t	PH_MEMLOC_REM wStatus = 0;
  uint8_t		PH_MEMLOC_REM aCmdBuf[14];
  uint8_t		PH_MEMLOC_REM bCmdLen = 0;
  uint8_t		*PH_MEMLOC_REM pResponse = NULL;
  uint16_t	PH_MEMLOC_REM wRespLen = 0;

  /* Validate the parameters. */
  PH_ASSERT_NULL_DATA_PARAM(pDataParams, PH_COMP_HAL);
  PH_ASSERT_NULL_PARAM(pMFUID, PH_COMP_HAL);
  if (bOption > PHHAL_HW_SAMAV3_CMD_AUTHENTICATE_MIFARE_DIV_ON) {
    return PH_ADD_COMPCODE(PH_ERR_INVALID_PARAMETER, PH_COMP_HAL);
  }

  /* Reset the command buffer and its length variable. */
  bCmdLen = 0;
  memset(aCmdBuf, 0x00, sizeof(aCmdBuf));	/* PRQA S 3200 */

  /* Frame Cmd.MF_Authenticate comamnd information. */
  aCmdBuf[bCmdLen++] = PHHAL_HW_SAMAV3_ISO7816_CLA_BYTE;
  aCmdBuf[bCmdLen++] = PHHAL_HW_SAMAV3_CMD_MF_AUTHENTICATE_INS;
  aCmdBuf[bCmdLen++] = PHHAL_HW_SAMAV3_ISO7816_DEFAULT_P1_BYTE;
  aCmdBuf[bCmdLen++] = PHHAL_HW_SAMAV3_ISO7816_DEFAULT_P2_BYTE;
  aCmdBuf[bCmdLen++] = 8;

  /* Add MIFARE UID to command buffer. */
  memcpy(&aCmdBuf[bCmdLen], pMFUID, 4 /* MIFARE Classic UID's last 4 bytes. */);	/* PRQA S 3200 */
  bCmdLen += (uint8_t) 4 /* MIFARE Classic UID's last 4 bytes. */;

  /* Add key no, key version, key type and MIFARE block number to command buffer. */
  aCmdBuf[bCmdLen++] = bKeyNo;
  aCmdBuf[bCmdLen++] = bKeyVer;
  aCmdBuf[bCmdLen++] = bKeyType;
  aCmdBuf[bCmdLen++] = bMFBlockNo;

  /* Add Diversification block number if required. */
  if (bOption) {
    /* Update LC. */
    aCmdBuf[PHHAL_HW_SAMAV3_ISO7816_LC_POS] += (uint8_t) 1 /* Div Block No included. */;

    /* Add diversification block number to command buffer. */
    aCmdBuf[bCmdLen++] = bDivBlockNo;
  }

  /* Exchange the command information to Sam hardware. */
  PH_CHECK_SUCCESS_FCT(wStatus, phhalHw_SamAV3_Cmd_7816Exchange(
          pDataParams,
          PH_EXCHANGE_DEFAULT,
          aCmdBuf,
          bCmdLen,
          &pResponse,
          &wRespLen));

  return PH_ADD_COMPCODE(PH_ERR_SUCCESS, PH_COMP_HAL);
}

phStatus_t
phhalHw_SamAV3_Cmd_MF_Read(phhalHw_SamAV3_DataParams_t *pDataParams, uint8_t *pBlocks,
    uint8_t bBlocksLen,
    uint8_t **ppData, uint16_t *pDataLen)
{
  phStatus_t	PH_MEMLOC_REM wStatus = 0;
  uint8_t		PH_MEMLOC_REM aCmdBuf[PHHAL_HW_SAMAV3_ISO7816_HEADER_LENGTH];

  /* Validate the parameters. */
  PH_ASSERT_NULL_DATA_PARAM(pDataParams, PH_COMP_HAL);
  PH_ASSERT_NULL_PARAM(pBlocks, PH_COMP_HAL);
  PH_ASSERT_NULL_PARAM(pDataLen, PH_COMP_HAL);

  /* Reset the command buffer. */
  memset(aCmdBuf, 0x00, sizeof(aCmdBuf));	/* PRQA S 3200 */

  /* Frame Cmd.MF_Read comamnd information. */
  aCmdBuf[PHHAL_HW_SAMAV3_ISO7816_CLA_POS] = PHHAL_HW_SAMAV3_ISO7816_CLA_BYTE;
  aCmdBuf[PHHAL_HW_SAMAV3_ISO7816_INS_POS] = PHHAL_HW_SAMAV3_CMD_MF_READ_INS;
  aCmdBuf[PHHAL_HW_SAMAV3_ISO7816_P1_POS]  = PHHAL_HW_SAMAV3_ISO7816_DEFAULT_P1_BYTE;
  aCmdBuf[PHHAL_HW_SAMAV3_ISO7816_P2_POS]  = PHHAL_HW_SAMAV3_ISO7816_DEFAULT_P2_BYTE;
  aCmdBuf[PHHAL_HW_SAMAV3_ISO7816_LC_POS]  = bBlocksLen;

  /* Buffer command information to exchange buffer. */
  PH_CHECK_SUCCESS_FCT(wStatus, phhalHw_SamAV3_Cmd_7816Exchange(
          pDataParams,
          PH_EXCHANGE_BUFFER_FIRST,
          aCmdBuf,
          PHHAL_HW_SAMAV3_ISO7816_HEADER_LENGTH,
          NULL,
          NULL));

  /* Buffer the block information to exchange buffer. */
  PH_CHECK_SUCCESS_FCT(wStatus, phhalHw_SamAV3_Cmd_7816Exchange(
          pDataParams,
          PH_EXCHANGE_BUFFER_CONT,
          pBlocks,
          bBlocksLen,
          NULL,
          NULL));

  /* Buffer LE to exchange buffer and exchange the bufferred information to Sam hardware. */
  PH_CHECK_SUCCESS_FCT(wStatus, phhalHw_SamAV3_Cmd_7816Exchange(
          pDataParams,
          PH_EXCHANGE_BUFFER_LAST,
          gaDefaultLe,
          1,
          ppData,
          pDataLen));

  return PH_ADD_COMPCODE(PH_ERR_SUCCESS, PH_COMP_HAL);
}

phStatus_t
phhalHw_SamAV3_Cmd_MF_Write(phhalHw_SamAV3_DataParams_t *pDataParams, uint8_t bOption,
    uint8_t *pData,
    uint8_t bDataLen, uint8_t **ppTMData, uint16_t *pTMDataLen)
{
  phStatus_t	PH_MEMLOC_REM wStatus = 0;
  uint8_t		PH_MEMLOC_REM aCmdBuf[PHHAL_HW_SAMAV3_ISO7816_HEADER_LENGTH];

  /* Validate the parameters. */
  PH_ASSERT_NULL_DATA_PARAM(pDataParams, PH_COMP_HAL);
  PH_ASSERT_NULL_PARAM(pData, PH_COMP_HAL);
  PH_ASSERT_NULL_PARAM(pTMDataLen, PH_COMP_HAL);

  /* Reset the command buffer. */
  memset(aCmdBuf, 0x00, sizeof(aCmdBuf));	/* PRQA S 3200 */

  /* Frame Cmd.MF_Write comamnd information. */
  aCmdBuf[PHHAL_HW_SAMAV3_ISO7816_CLA_POS] = PHHAL_HW_SAMAV3_ISO7816_CLA_BYTE;
  aCmdBuf[PHHAL_HW_SAMAV3_ISO7816_INS_POS] = PHHAL_HW_SAMAV3_CMD_MF_WRITE_INS;
  aCmdBuf[PHHAL_HW_SAMAV3_ISO7816_P1_POS]  = (uint8_t)(bOption & 0x7F);
  aCmdBuf[PHHAL_HW_SAMAV3_ISO7816_P2_POS]  = PHHAL_HW_SAMAV3_ISO7816_DEFAULT_P2_BYTE;
  aCmdBuf[PHHAL_HW_SAMAV3_ISO7816_LC_POS]  = bDataLen;

  /* Buffer command information to exchange buffer. */
  PH_CHECK_SUCCESS_FCT(wStatus, phhalHw_SamAV3_Cmd_7816Exchange(
          pDataParams,
          PH_EXCHANGE_BUFFER_FIRST,
          aCmdBuf,
          PHHAL_HW_SAMAV3_ISO7816_HEADER_LENGTH,
          NULL,
          NULL));

  /* Buffer data information to exchange buffer. */
  PH_CHECK_SUCCESS_FCT(wStatus, phhalHw_SamAV3_Cmd_7816Exchange(
          pDataParams,
          PH_EXCHANGE_BUFFER_CONT,
          pData,
          bDataLen,
          NULL,
          NULL));

  /* Buffer LE to exchange buffer and exchange the bufferred information to Sam hardware. */
  PH_CHECK_SUCCESS_FCT(wStatus, phhalHw_SamAV3_Cmd_7816Exchange(
          pDataParams,
          PH_EXCHANGE_BUFFER_LAST,
          gaDefaultLe,
          (uint16_t)((bOption & PHHAL_HW_SAMAV3_CMD_MF_WRITE_TMDATA_RETURNED) ? 1 : 0),
          ppTMData,
          pTMDataLen));

  return PH_ADD_COMPCODE(PH_ERR_SUCCESS, PH_COMP_HAL);
}

phStatus_t
phhalHw_SamAV3_Cmd_MF_ValueWrite(phhalHw_SamAV3_DataParams_t *pDataParams, uint8_t bOption,
    uint8_t *pBlocks,
    uint8_t bBlocksLen, uint8_t **ppTMData, uint16_t *pTMDataLen)
{
  phStatus_t	PH_MEMLOC_REM wStatus = 0;
  uint8_t		PH_MEMLOC_REM aCmdBuf[PHHAL_HW_SAMAV3_ISO7816_HEADER_LENGTH];

  /* Validate the parameters. */
  PH_ASSERT_NULL_DATA_PARAM(pDataParams, PH_COMP_HAL);
  PH_ASSERT_NULL_PARAM(pBlocks, PH_COMP_HAL);
  PH_ASSERT_NULL_PARAM(pTMDataLen, PH_COMP_HAL);

  /* Reset the command buffer. */
  memset(aCmdBuf, 0x00, sizeof(aCmdBuf));	/* PRQA S 3200 */

  /* Frame Cmd.MF_ValueWrite comamnd information. */
  aCmdBuf[PHHAL_HW_SAMAV3_ISO7816_CLA_POS] = PHHAL_HW_SAMAV3_ISO7816_CLA_BYTE;
  aCmdBuf[PHHAL_HW_SAMAV3_ISO7816_INS_POS] = PHHAL_HW_SAMAV3_CMD_MF_VALUE_WRITE_INS;
  aCmdBuf[PHHAL_HW_SAMAV3_ISO7816_P1_POS] = PHHAL_HW_SAMAV3_ISO7816_DEFAULT_P1_BYTE;
  aCmdBuf[PHHAL_HW_SAMAV3_ISO7816_P2_POS] = PHHAL_HW_SAMAV3_ISO7816_DEFAULT_P2_BYTE;
  aCmdBuf[PHHAL_HW_SAMAV3_ISO7816_LC_POS] = bBlocksLen;

  /* Buffer command information to exchange buffer. */
  PH_CHECK_SUCCESS_FCT(wStatus, phhalHw_SamAV3_Cmd_7816Exchange(
          pDataParams,
          PH_EXCHANGE_BUFFER_FIRST,
          aCmdBuf,
          PHHAL_HW_SAMAV3_ISO7816_HEADER_LENGTH,
          NULL,
          NULL));

  /* Buffer value information to exchange buffer. */
  PH_CHECK_SUCCESS_FCT(wStatus, phhalHw_SamAV3_Cmd_7816Exchange(
          pDataParams,
          PH_EXCHANGE_BUFFER_CONT,
          pBlocks,
          bBlocksLen,
          NULL,
          NULL));

  /* Buffer LE to exchange buffer and exchange the bufferred information to Sam hardware. */
  PH_CHECK_SUCCESS_FCT(wStatus, phhalHw_SamAV3_Cmd_7816Exchange(
          pDataParams,
          PH_EXCHANGE_BUFFER_LAST,
          gaDefaultLe,
          (uint16_t)(bOption ? 1 : 0),
          ppTMData,
          pTMDataLen));

  return PH_ADD_COMPCODE(PH_ERR_SUCCESS, PH_COMP_HAL);
}

phStatus_t
phhalHw_SamAV3_Cmd_MF_Increment(phhalHw_SamAV3_DataParams_t *pDataParams, uint8_t bOption,
    uint8_t *pBlocks,
    uint8_t bBlocksLen, uint8_t **ppTMData, uint16_t *pTMDataLen)
{
  phStatus_t	PH_MEMLOC_REM wStatus = 0;
  uint8_t		PH_MEMLOC_REM aCmdBuf[PHHAL_HW_SAMAV3_ISO7816_HEADER_LENGTH];

  /* Validate the parameters. */
  PH_ASSERT_NULL_DATA_PARAM(pDataParams, PH_COMP_HAL);
  PH_ASSERT_NULL_PARAM(pBlocks, PH_COMP_HAL);
  PH_ASSERT_NULL_PARAM(pTMDataLen, PH_COMP_HAL);

  /* Reset the command buffer. */
  memset(aCmdBuf, 0x00, sizeof(aCmdBuf));	/* PRQA S 3200 */

  /* Frame Cmd.MF_Increment comamnd information. */
  aCmdBuf[PHHAL_HW_SAMAV3_ISO7816_CLA_POS] = PHHAL_HW_SAMAV3_ISO7816_CLA_BYTE;
  aCmdBuf[PHHAL_HW_SAMAV3_ISO7816_INS_POS] = PHHAL_HW_SAMAV3_CMD_MF_INCREMENT_INS;
  aCmdBuf[PHHAL_HW_SAMAV3_ISO7816_P1_POS]  = PHHAL_HW_SAMAV3_ISO7816_DEFAULT_P1_BYTE;
  aCmdBuf[PHHAL_HW_SAMAV3_ISO7816_P2_POS]  = PHHAL_HW_SAMAV3_ISO7816_DEFAULT_P2_BYTE;
  aCmdBuf[PHHAL_HW_SAMAV3_ISO7816_LC_POS]  = bBlocksLen;

  /* Buffer command information to exchange buffer. */
  PH_CHECK_SUCCESS_FCT(wStatus, phhalHw_SamAV3_Cmd_7816Exchange(
          pDataParams,
          PH_EXCHANGE_BUFFER_FIRST,
          aCmdBuf,
          PHHAL_HW_SAMAV3_ISO7816_HEADER_LENGTH,
          NULL,
          NULL));

  /* Buffer value information to exchange buffer. */
  PH_CHECK_SUCCESS_FCT(wStatus, phhalHw_SamAV3_Cmd_7816Exchange(
          pDataParams,
          PH_EXCHANGE_BUFFER_CONT,
          pBlocks,
          bBlocksLen,
          NULL,
          NULL));

  /* Buffer LE to exchange buffer and exchange the bufferred information to Sam hardware. */
  PH_CHECK_SUCCESS_FCT(wStatus, phhalHw_SamAV3_Cmd_7816Exchange(
          pDataParams,
          PH_EXCHANGE_BUFFER_LAST,
          gaDefaultLe,
          (uint16_t)(bOption ? 1 : 0),
          ppTMData,
          pTMDataLen));

  return PH_ADD_COMPCODE(PH_ERR_SUCCESS, PH_COMP_HAL);
}

phStatus_t
phhalHw_SamAV3_Cmd_MF_Decrement(phhalHw_SamAV3_DataParams_t *pDataParams, uint8_t bOption,
    uint8_t *pBlocks,
    uint8_t bBlocksLen, uint8_t **ppTMData, uint16_t *pTMDataLen)
{
  phStatus_t	PH_MEMLOC_REM wStatus = 0;
  uint8_t		PH_MEMLOC_REM aCmdBuf[PHHAL_HW_SAMAV3_ISO7816_HEADER_LENGTH];

  /* Validate the parameters. */
  PH_ASSERT_NULL_DATA_PARAM(pDataParams, PH_COMP_HAL);
  PH_ASSERT_NULL_PARAM(pBlocks, PH_COMP_HAL);
  PH_ASSERT_NULL_PARAM(pTMDataLen, PH_COMP_HAL);

  /* Reset the command buffer. */
  memset(aCmdBuf, 0x00, sizeof(aCmdBuf));	/* PRQA S 3200 */

  /* Frame Cmd.MF_Decrement comamnd information. */
  aCmdBuf[PHHAL_HW_SAMAV3_ISO7816_CLA_POS] = PHHAL_HW_SAMAV3_ISO7816_CLA_BYTE;
  aCmdBuf[PHHAL_HW_SAMAV3_ISO7816_INS_POS] = PHHAL_HW_SAMAV3_CMD_MF_DECREMENT_INS;
  aCmdBuf[PHHAL_HW_SAMAV3_ISO7816_P1_POS]  = PHHAL_HW_SAMAV3_ISO7816_DEFAULT_P1_BYTE;
  aCmdBuf[PHHAL_HW_SAMAV3_ISO7816_P2_POS]  = PHHAL_HW_SAMAV3_ISO7816_DEFAULT_P2_BYTE;
  aCmdBuf[PHHAL_HW_SAMAV3_ISO7816_LC_POS]  = bBlocksLen;

  /* Buffer command information to exchange buffer. */
  PH_CHECK_SUCCESS_FCT(wStatus, phhalHw_SamAV3_Cmd_7816Exchange(
          pDataParams,
          PH_EXCHANGE_BUFFER_FIRST,
          aCmdBuf,
          PHHAL_HW_SAMAV3_ISO7816_HEADER_LENGTH,
          NULL,
          NULL));

  /* Buffer value information to exchange buffer and exchange the bufferred information to Sam hardware. */
  PH_CHECK_SUCCESS_FCT(wStatus, phhalHw_SamAV3_Cmd_7816Exchange(
          pDataParams,
          PH_EXCHANGE_BUFFER_CONT,
          pBlocks,
          bBlocksLen,
          NULL,
          NULL));

  /* Buffer LE to exchange buffer and exchange the bufferred information to Sam hardware. */
  PH_CHECK_SUCCESS_FCT(wStatus, phhalHw_SamAV3_Cmd_7816Exchange(
          pDataParams,
          PH_EXCHANGE_BUFFER_LAST,
          gaDefaultLe,
          (uint16_t)(bOption ? 1 : 0),
          ppTMData,
          pTMDataLen));

  return PH_ADD_COMPCODE(PH_ERR_SUCCESS, PH_COMP_HAL);
}

phStatus_t
phhalHw_SamAV3_Cmd_MF_Restore(phhalHw_SamAV3_DataParams_t *pDataParams, uint8_t bOption,
    uint8_t  *pBlocks,
    uint8_t bBlocksLen, uint8_t **ppTMData, uint16_t *pTMDataLen)
{
  phStatus_t	PH_MEMLOC_REM wStatus = 0;
  uint8_t		PH_MEMLOC_REM aCmdBuf[PHHAL_HW_SAMAV3_ISO7816_HEADER_LENGTH];

  /* Validate the parameters. */
  PH_ASSERT_NULL_DATA_PARAM(pDataParams, PH_COMP_HAL);
  PH_ASSERT_NULL_PARAM(pBlocks, PH_COMP_HAL);
  PH_ASSERT_NULL_PARAM(pTMDataLen, PH_COMP_HAL);

  /* Reset the command buffer. */
  memset(aCmdBuf, 0x00, sizeof(aCmdBuf));	/* PRQA S 3200 */

  /* Frame Cmd.MF_Restore comamnd information. */
  aCmdBuf[PHHAL_HW_SAMAV3_ISO7816_CLA_POS] = PHHAL_HW_SAMAV3_ISO7816_CLA_BYTE;
  aCmdBuf[PHHAL_HW_SAMAV3_ISO7816_INS_POS] = PHHAL_HW_SAMAV3_CMD_MF_RESTORE_INS;
  aCmdBuf[PHHAL_HW_SAMAV3_ISO7816_P1_POS]  = PHHAL_HW_SAMAV3_ISO7816_DEFAULT_P1_BYTE;
  aCmdBuf[PHHAL_HW_SAMAV3_ISO7816_P2_POS]  = PHHAL_HW_SAMAV3_ISO7816_DEFAULT_P2_BYTE;
  aCmdBuf[PHHAL_HW_SAMAV3_ISO7816_LC_POS]  = bBlocksLen;

  /* Buffer command information to exchange buffer. */
  PH_CHECK_SUCCESS_FCT(wStatus, phhalHw_SamAV3_Cmd_7816Exchange(
          pDataParams,
          PH_EXCHANGE_BUFFER_FIRST,
          aCmdBuf,
          PHHAL_HW_SAMAV3_ISO7816_HEADER_LENGTH,
          NULL,
          NULL));

  /* Buffer value information to exchange buffer and exchange the bufferred information to Sam hardware. */
  PH_CHECK_SUCCESS_FCT(wStatus, phhalHw_SamAV3_Cmd_7816Exchange(
          pDataParams,
          PH_EXCHANGE_BUFFER_CONT,
          pBlocks,
          bBlocksLen,
          NULL,
          NULL));

  /* Buffer LE to exchange buffer and exchange the bufferred information to Sam hardware. */
  PH_CHECK_SUCCESS_FCT(wStatus, phhalHw_SamAV3_Cmd_7816Exchange(
          pDataParams,
          PH_EXCHANGE_BUFFER_LAST,
          gaDefaultLe,
          (uint16_t)(bOption ? 1 : 0),
          ppTMData,
          pTMDataLen));

  return PH_ADD_COMPCODE(PH_ERR_SUCCESS, PH_COMP_HAL);
}

phStatus_t
phhalHw_SamAV3_Cmd_MF_AuthenticatedRead(phhalHw_SamAV3_DataParams_t *pDataParams,
    uint16_t wOption, uint8_t *pMFUID,
    uint8_t bCmdSettings, uint8_t bKeyNo, uint8_t bKeyVer, uint8_t bKeyType, uint8_t bAuthBlockNo,
    uint8_t bDivBlockNo,
    uint8_t *pBlocks, uint8_t bBlocksLen, uint8_t **ppData, uint16_t *pDataLen)
{
  phStatus_t	PH_MEMLOC_REM wStatus = 0;
  uint8_t		PH_MEMLOC_REM aCmdBuf[PHHAL_HW_SAMAV3_ISO7816_HEADER_LENGTH];
  uint8_t		PH_MEMLOC_REM aReadDesc[7 /* Loading the read description information. */];
  uint8_t		PH_MEMLOC_REM bReadDescLen = 0;

  /* Validate the parameters. */
  PH_ASSERT_NULL_DATA_PARAM(pDataParams, PH_COMP_HAL);
  if ((wOption == PH_EXCHANGE_DEFAULT) || (wOption == PH_EXCHANGE_BUFFER_FIRST)) {
    PH_ASSERT_NULL_PARAM(pMFUID, PH_COMP_HAL);
  }
  PH_ASSERT_NULL_PARAM(pBlocks, PH_COMP_HAL);

  if ((wOption == PH_EXCHANGE_DEFAULT) || (wOption == PH_EXCHANGE_BUFFER_LAST)) {
    PH_ASSERT_NULL_PARAM(pDataLen, PH_COMP_HAL);
  }

  /* Frame Cmd.MF_AuthenticatedRead comamnd information if first or default option. */
  if ((wOption == PH_EXCHANGE_DEFAULT) || (wOption == PH_EXCHANGE_BUFFER_FIRST)) {
    /* Reset the command buffer. */
    memset(aCmdBuf, 0x00, sizeof(aCmdBuf));	/* PRQA S 3200 */

    /* Frame Cmd.MF_AuthenticatedRead comamnd information. */
    aCmdBuf[PHHAL_HW_SAMAV3_ISO7816_CLA_POS] = PHHAL_HW_SAMAV3_ISO7816_CLA_BYTE;
    aCmdBuf[PHHAL_HW_SAMAV3_ISO7816_INS_POS] = PHHAL_HW_SAMAV3_CMD_MF_AUTHENTICATED_READ_INS;
    aCmdBuf[PHHAL_HW_SAMAV3_ISO7816_P1_POS]  = PHHAL_HW_SAMAV3_ISO7816_DEFAULT_P1_BYTE;
    aCmdBuf[PHHAL_HW_SAMAV3_ISO7816_P2_POS]  = PHHAL_HW_SAMAV3_ISO7816_DEFAULT_P2_BYTE;
    aCmdBuf[PHHAL_HW_SAMAV3_ISO7816_LC_POS]  = PHHAL_HW_SAMAV3_ISO7816_DEFAULT_LC_BYTE;

    /* Exchange the command information to Sam hardware. */
    PH_CHECK_SUCCESS_FCT(wStatus, phhalHw_SamAV3_Cmd_7816Exchange(
            pDataParams,
            PH_EXCHANGE_BUFFER_FIRST,
            aCmdBuf,
            PHHAL_HW_SAMAV3_ISO7816_HEADER_LENGTH,
            NULL,
            NULL));

    /* Add MIFARE UID to command buffer if its first frame. */
    PH_CHECK_SUCCESS_FCT(wStatus, phhalHw_SamAV3_Cmd_7816Exchange(
            pDataParams,
            PH_EXCHANGE_BUFFER_CONT,
            pMFUID,
            4,
            NULL,
            NULL));
  }

  /* Reset the Read description buffer and its length. */
  bReadDescLen = 0;
  memset(aReadDesc, 0x00, sizeof(aReadDesc));	/* PRQA S 3200 */

  /* Add command settings to read description buffer. */
  aReadDesc[bReadDescLen++] = bCmdSettings;

  /* Add key number, version and key type to read description buffer. */
  if ((bCmdSettings & PHHAL_HW_SAMAV3_CMD_MF_AUTH_RW_KEY_INFO_NOT_AVAILABLE) !=
      PHHAL_HW_SAMAV3_CMD_MF_AUTH_RW_KEY_INFO_NOT_AVAILABLE) {
    aReadDesc[bReadDescLen++] = bKeyNo;
    aReadDesc[bReadDescLen++] = bKeyVer;
    aReadDesc[bReadDescLen++] = bKeyType;
  }

  /* Add Authblock number to read description buffer. */
  aReadDesc[bReadDescLen++] = bAuthBlockNo;

  /* Add diversification block number to read description buffer. */
  if ((bCmdSettings & PHHAL_HW_SAMAV3_CMD_MF_AUTH_RW_CMD_SET_DIV_ON) ==
      PHHAL_HW_SAMAV3_CMD_MF_AUTH_RW_CMD_SET_DIV_ON) {
    aReadDesc[bReadDescLen++] = bDivBlockNo;
  }

  /* Add Num of block to read description buffer. */
  aReadDesc[bReadDescLen++] = bBlocksLen;

  /* Buffer the read description buffer to exchange buffer. */
  PH_CHECK_SUCCESS_FCT(wStatus, phhalHw_SamAV3_Cmd_7816Exchange(
          pDataParams,
          PH_EXCHANGE_BUFFER_CONT,
          aReadDesc,
          bReadDescLen,
          NULL,
          NULL));

  /* Add mifare blocks to exchange buffer. */
  PH_CHECK_SUCCESS_FCT(wStatus, phhalHw_SamAV3_Cmd_7816Exchange(
          pDataParams,
          PH_EXCHANGE_BUFFER_CONT,
          pBlocks,
          bBlocksLen,
          NULL,
          NULL));

  /* Exchange the bufferred information to Sam hardware.*/
  if ((wOption == PH_EXCHANGE_DEFAULT) || (wOption == PH_EXCHANGE_BUFFER_LAST)) {
    /* Update LC*/
    PH_CHECK_SUCCESS_FCT(wStatus, phhalHw_SamAV3_Utils_UpdateLc(pDataParams));

    /* Exchange the command information to Sam hardware. */
    PH_CHECK_SUCCESS_FCT(wStatus, phhalHw_SamAV3_Cmd_7816Exchange(
            pDataParams,
            PH_EXCHANGE_BUFFER_LAST,
            gaDefaultLe,
            1,
            ppData,
            pDataLen));
  }

  return PH_ADD_COMPCODE(PH_ERR_SUCCESS, PH_COMP_HAL);
}

phStatus_t
phhalHw_SamAV3_Cmd_MF_AuthenticatedWrite(phhalHw_SamAV3_DataParams_t *pDataParams,
    uint16_t wOption, uint8_t *pMFUID,
    uint8_t bCmdSettings, uint8_t bKeyNo, uint8_t bKeyVer, uint8_t bKeyType, uint8_t bAuthBlockNo,
    uint8_t bDivBlockNo,
    uint8_t *pBlocks, uint8_t bBlocksLen, uint8_t **ppTMData, uint16_t *pTMDataLen)
{
  phStatus_t	PH_MEMLOC_REM wStatus = 0;
  uint8_t		PH_MEMLOC_REM aCmdBuf[PHHAL_HW_SAMAV3_ISO7816_HEADER_LENGTH];
  uint8_t		PH_MEMLOC_REM aWriteDesc[7 /* Loading the write description information. */];
  uint8_t		PH_MEMLOC_REM bWriteDescLen = 0;

  /* Validate the parameters. */
  PH_ASSERT_NULL_DATA_PARAM(pDataParams, PH_COMP_HAL);
  if (((wOption & PH_EXCHANGE_BUFFER_MASK) == PH_EXCHANGE_DEFAULT) ||
      ((wOption & PH_EXCHANGE_BUFFER_MASK) == PH_EXCHANGE_BUFFER_FIRST)) {
    PH_ASSERT_NULL_PARAM(pMFUID, PH_COMP_HAL);
  }
  PH_ASSERT_NULL_PARAM(pBlocks, PH_COMP_HAL);

  if (((wOption & PH_EXCHANGE_BUFFER_MASK) == PH_EXCHANGE_DEFAULT) ||
      ((wOption & PH_EXCHANGE_BUFFER_MASK) == PH_EXCHANGE_BUFFER_LAST)) {
    PH_ASSERT_NULL_PARAM(pTMDataLen, PH_COMP_HAL);
  }

  /* Frame Cmd.MF_AuthenticatedWrite comamnd information if first or default option. */
  if (((wOption & PH_EXCHANGE_BUFFER_MASK) == PH_EXCHANGE_DEFAULT) ||
      ((wOption & PH_EXCHANGE_BUFFER_MASK) == PH_EXCHANGE_BUFFER_FIRST)) {
    /* Reset the command buffer. */
    memset(aCmdBuf, 0x00, sizeof(aCmdBuf));	/* PRQA S 3200 */

    /* Frame Cmd.MF_AuthenticatedWrite comamnd information. */
    aCmdBuf[PHHAL_HW_SAMAV3_ISO7816_CLA_POS] = PHHAL_HW_SAMAV3_ISO7816_CLA_BYTE;
    aCmdBuf[PHHAL_HW_SAMAV3_ISO7816_INS_POS] = PHHAL_HW_SAMAV3_CMD_MF_AUTHENTICATED_WRITE_INS;
    aCmdBuf[PHHAL_HW_SAMAV3_ISO7816_P1_POS] = PHHAL_HW_SAMAV3_ISO7816_DEFAULT_P1_BYTE;
    aCmdBuf[PHHAL_HW_SAMAV3_ISO7816_P2_POS] = PHHAL_HW_SAMAV3_ISO7816_DEFAULT_P2_BYTE;
    aCmdBuf[PHHAL_HW_SAMAV3_ISO7816_LC_POS] = PHHAL_HW_SAMAV3_ISO7816_DEFAULT_LC_BYTE;

    /* Exchange the command information to Sam hardware. */
    PH_CHECK_SUCCESS_FCT(wStatus, phhalHw_SamAV3_Cmd_7816Exchange(
            pDataParams,
            PH_EXCHANGE_BUFFER_FIRST,
            aCmdBuf,
            PHHAL_HW_SAMAV3_ISO7816_HEADER_LENGTH,
            NULL,
            NULL));

    /* Add MIFARE UID to command buffer if its first frame. */
    PH_CHECK_SUCCESS_FCT(wStatus, phhalHw_SamAV3_Cmd_7816Exchange(
            pDataParams,
            PH_EXCHANGE_BUFFER_CONT,
            pMFUID,
            4,
            NULL,
            NULL));
  }

  /* Reset the write description buffer and its length. */
  bWriteDescLen = 0;
  memset(aWriteDesc, 0x00, sizeof(aWriteDesc));	/* PRQA S 3200 */

  /* Add command settings to write description buffer. */
  aWriteDesc[bWriteDescLen++] = bCmdSettings;

  /* Add key number, version and key type to write description buffer. */
  if ((bCmdSettings & PHHAL_HW_SAMAV3_CMD_MF_AUTH_RW_KEY_INFO_NOT_AVAILABLE) !=
      PHHAL_HW_SAMAV3_CMD_MF_AUTH_RW_KEY_INFO_NOT_AVAILABLE) {
    aWriteDesc[bWriteDescLen++] = bKeyNo;
    aWriteDesc[bWriteDescLen++] = bKeyVer;
    aWriteDesc[bWriteDescLen++] = bKeyType;
  }

  /* Add Authblock number to write description buffer. */
  aWriteDesc[bWriteDescLen++] = bAuthBlockNo;

  /* Add diversification block number to write description buffer. */
  if ((bCmdSettings & PHHAL_HW_SAMAV3_CMD_MF_AUTH_RW_CMD_SET_DIV_ON) ==
      PHHAL_HW_SAMAV3_CMD_MF_AUTH_RW_CMD_SET_DIV_ON) {
    aWriteDesc[bWriteDescLen++] = bDivBlockNo;
  }

  /* Add Num of block to write description buffer. */
  aWriteDesc[bWriteDescLen++] = (uint8_t)(bBlocksLen / 17 /* Min 1 Block and its data.*/);

  /* Buffer the write description buffer to exchange buffer. */
  PH_CHECK_SUCCESS_FCT(wStatus, phhalHw_SamAV3_Cmd_7816Exchange(
          pDataParams,
          PH_EXCHANGE_BUFFER_CONT,
          aWriteDesc,
          bWriteDescLen,
          NULL,
          NULL));

  /* Add mifare blocks to exchange buffer. */
  PH_CHECK_SUCCESS_FCT(wStatus, phhalHw_SamAV3_Cmd_7816Exchange(
          pDataParams,
          PH_EXCHANGE_BUFFER_CONT,
          pBlocks,
          bBlocksLen,
          NULL,
          NULL));

  /* Exchange the bufferred information to Sam hardware.*/
  if (((wOption & PH_EXCHANGE_BUFFER_MASK) == PH_EXCHANGE_DEFAULT) ||
      ((wOption & PH_EXCHANGE_BUFFER_MASK) == PH_EXCHANGE_BUFFER_LAST)) {
    /* Update LC*/
    PH_CHECK_SUCCESS_FCT(wStatus, phhalHw_SamAV3_Utils_UpdateLc(pDataParams));

    /* Exchange the command information to Sam hardware. */
    PH_CHECK_SUCCESS_FCT(wStatus, phhalHw_SamAV3_Cmd_7816Exchange(
            pDataParams,
            PH_EXCHANGE_BUFFER_LAST,
            gaDefaultLe,
            (uint16_t)((wOption & PH_EXCHANGE_CUSTOM_BITS_MASK) ? 1 : 0),
            ppTMData,
            pTMDataLen));
  }

  return PH_ADD_COMPCODE(PH_ERR_SUCCESS, PH_COMP_HAL);
}

phStatus_t
phhalHw_SamAV3_Cmd_MF_ChangeKey(phhalHw_SamAV3_DataParams_t *pDataParams, uint8_t bOption,
    uint8_t bKeyNo, uint8_t bKeyVerA,
    uint8_t bKeyVerB, uint8_t bMFBlockNo, uint8_t *pAccCond, uint8_t *pMFUID, uint8_t bDivBlockNo)
{
  phStatus_t	PH_MEMLOC_REM wStatus = 0;
  uint8_t		PH_MEMLOC_REM aCmdBuf[18];
  uint8_t		PH_MEMLOC_REM bCmdLen = 0;
  uint8_t		*PH_MEMLOC_REM pResponse = NULL;
  uint16_t	PH_MEMLOC_REM wRespLen = 0;

  /* Validate the parameters. */
  PH_ASSERT_NULL_DATA_PARAM(pDataParams, PH_COMP_HAL);
  PH_ASSERT_NULL_PARAM(pAccCond, PH_COMP_HAL);
  if ((bOption & PHHAL_HW_SAMAV3_CMD_CHANGE_KEY_MIFARE_DIV_A_ON) ||
      (bOption & PHHAL_HW_SAMAV3_CMD_CHANGE_KEY_MIFARE_DIV_B_ON)) {
    PH_ASSERT_NULL_PARAM(pMFUID, PH_COMP_HAL);
  }

  /* Reset the command buffer and its length variable. */
  bCmdLen = 0;
  memset(aCmdBuf, 0x00, sizeof(aCmdBuf));	/* PRQA S 3200 */

  /* Frame Cmd.SAM_AuthenticateMIFARE part1 comamnd information. */
  aCmdBuf[bCmdLen++] = PHHAL_HW_SAMAV3_ISO7816_CLA_BYTE;
  aCmdBuf[bCmdLen++] = PHHAL_HW_SAMAV3_CMD_MF_CHANGE_KEY_INS;
  aCmdBuf[bCmdLen++] = (uint8_t)(bOption & PHHAL_HW_SAMAV3_CMD_CHANGE_KEY_MIFARE_DIV_MASK);
  aCmdBuf[bCmdLen++] = PHHAL_HW_SAMAV3_ISO7816_DEFAULT_P2_BYTE;
  aCmdBuf[bCmdLen++] = PHHAL_HW_SAMAV3_ISO7816_DEFAULT_LC_BYTE;

  /* Add key no and key version to command buffer. */
  aCmdBuf[bCmdLen++] = bKeyNo;
  aCmdBuf[bCmdLen++] = bKeyVerA;
  aCmdBuf[bCmdLen++] = bKeyVerB;

  /* Add MFBlock number to command buffer. */
  aCmdBuf[bCmdLen++] = bMFBlockNo;

  /* Add Access coditions to command buffer. */
  memcpy(&aCmdBuf[bCmdLen], pAccCond, 4 /* MIFARE Classic access condition. */);	/* PRQA S 3200 */
  bCmdLen += (uint8_t) 4 /* MIFARE Classic access condition. */;

  /* Add MIFARE UID and diversification block number to command buffer if diverification is enabled. */
  if ((bOption & PHHAL_HW_SAMAV3_CMD_CHANGE_KEY_MIFARE_DIV_A_ON) ||
      (bOption & PHHAL_HW_SAMAV3_CMD_CHANGE_KEY_MIFARE_DIV_B_ON)) {
    /* Add MIFARE UID to command buffer. */
    memcpy(&aCmdBuf[bCmdLen], pMFUID, 4 /* MIFARE Classic UID's last 4 bytes. */);	/* PRQA S 3200 */
    bCmdLen += (uint8_t) 4 /* MIFARE Classic UID's last 4 bytes. */;

    /* Add diversification block number. */
    aCmdBuf[bCmdLen++] = bDivBlockNo;
  }

  /* Buffer the command information to exchange buffer. */
  PH_CHECK_SUCCESS_FCT(wStatus, phhalHw_SamAV3_Cmd_7816Exchange(
          pDataParams,
          PH_EXCHANGE_BUFFER_FIRST,
          aCmdBuf,
          bCmdLen,
          NULL,
          NULL));

  /* Update LC. */
  PH_CHECK_SUCCESS_FCT(wStatus, phhalHw_SamAV3_Utils_UpdateLc(pDataParams));

  /* Exchange the bufferred information to Sam hardware. */
  PH_CHECK_SUCCESS_FCT(wStatus, phhalHw_SamAV3_Cmd_7816Exchange(
          pDataParams,
          PH_EXCHANGE_BUFFER_LAST,
          NULL,
          0,
          &pResponse,
          &wRespLen));

  return PH_ADD_COMPCODE(PH_ERR_SUCCESS, PH_COMP_HAL);
}

/*************************************************************************************************************************/
/*************************************************** MIFARE Ultralight ***************************************************/
/*************************************************************************************************************************/

/* S - Mode ------------------------------------------------------------------------------------------------------------ */

phStatus_t
phhalHw_SamAV3_Cmd_SAM_PwdAuthUL_Part1(phhalHw_SamAV3_DataParams_t *pDataParams, uint8_t bKeyNo,
    uint8_t bKeyVer,
    uint8_t *pDivInput, uint8_t bDivInputLen, uint8_t **ppPwd, uint16_t *pPwdLen)
{
  phStatus_t	PH_MEMLOC_REM wStatus = 0;
  uint8_t		PH_MEMLOC_REM aCmdBuf[PHHAL_HW_SAMAV3_ISO7816_HEADER_LENGTH +
                                            2 /* Key No, Key version. */];
  uint8_t		PH_MEMLOC_REM bCmdLen = 0;

  /* Parameter validation. */
  PH_ASSERT_NULL_DATA_PARAM(pDataParams, PH_COMP_HAL);
  if (bDivInputLen) {
    PH_ASSERT_NULL_PARAM(pDivInput, PH_COMP_HAL);
  }
  PH_ASSERT_NULL_PARAM(pPwdLen, PH_COMP_HAL);

  /* Reset the command buffer and its length. */
  bCmdLen = 0;
  memset(aCmdBuf, 0x00, sizeof(aCmdBuf));	/* PRQA S 3200 */

  /* Frame Cmd.SAM_PwdAuthUL part 1 command information . */
  aCmdBuf[bCmdLen++]	= PHHAL_HW_SAMAV3_ISO7816_CLA_BYTE;
  aCmdBuf[bCmdLen++]	= PHHAL_HW_SAMAV3_CMD_SAM_PWD_AUTH_UL_INS;
  aCmdBuf[bCmdLen++]	= (uint8_t)(bDivInputLen ? 0x01 : PHHAL_HW_SAMAV3_ISO7816_DEFAULT_P1_BYTE);
  aCmdBuf[bCmdLen++]	= PHHAL_HW_SAMAV3_ISO7816_DEFAULT_P2_BYTE;
  aCmdBuf[bCmdLen++]	= (uint8_t)(2 /* Key No, Key version. */ +  bDivInputLen);

  /* Append Key No */
  aCmdBuf[bCmdLen++] = bKeyNo;

  /* Append Key Ver */
  aCmdBuf[bCmdLen++] = bKeyVer;

  /* Append Command data to exchange buffer. */
  PH_CHECK_SUCCESS_FCT(wStatus, phhalHw_SamAV3_Cmd_7816Exchange(
          pDataParams,
          PH_EXCHANGE_BUFFER_FIRST,
          aCmdBuf,
          bCmdLen,
          NULL,
          NULL));

  /* Buffer diversification information to exchange buffer. */
  PH_CHECK_SUCCESS_FCT(wStatus, phhalHw_SamAV3_Cmd_7816Exchange(
          pDataParams,
          PH_EXCHANGE_BUFFER_CONT,
          pDivInput,
          bDivInputLen,
          NULL,
          NULL));

  /* Append LE to exchange buffer and perform final exchange with SAM hardware. */
  wStatus = phhalHw_SamAV3_Cmd_7816Exchange(
          pDataParams,
          PH_EXCHANGE_BUFFER_LAST,
          gaDefaultLe,
          1,
          ppPwd,
          pPwdLen);

  /* Return success chaining status code. */
  if (wStatus == PH_ADD_COMPCODE(PHHAL_HW_SAMAV3_ERR_OK_CHAINING_ACTIVE, PH_COMP_HAL)) {
    return PH_ADD_COMPCODE(PH_ERR_SUCCESS_CHAINING, PH_COMP_HAL);
  }

  /* Return the response received from SAM. */
  return wStatus;
}

phStatus_t
phhalHw_SamAV3_Cmd_SAM_PwdAuthUL_Part2(phhalHw_SamAV3_DataParams_t *pDataParams, uint16_t wPack)
{
  phStatus_t	PH_MEMLOC_REM wStatus = 0;
  uint8_t		PH_MEMLOC_REM aCmdBuf[PHHAL_HW_SAMAV3_ISO7816_HEADER_LENGTH + 2 /* Pack information. */];
  uint8_t		PH_MEMLOC_REM bCmdLen = 0;
  uint8_t 	*PH_MEMLOC_REM pResponse = NULL;
  uint16_t	PH_MEMLOC_REM wRespLen = 0;

  /* Parameter validation. */
  PH_ASSERT_NULL_DATA_PARAM(pDataParams, PH_COMP_HAL);

  /* Reset the command buffer and its length. */
  bCmdLen = 0;
  memset(aCmdBuf, 0x00, sizeof(aCmdBuf));	/* PRQA S 3200 */

  /* Frame Cmd.SAM_PwdAuthUL part 2 command information . */
  aCmdBuf[bCmdLen++]	= PHHAL_HW_SAMAV3_ISO7816_CLA_BYTE;
  aCmdBuf[bCmdLen++]	= PHHAL_HW_SAMAV3_CMD_SAM_PWD_AUTH_UL_INS;
  aCmdBuf[bCmdLen++]	= PHHAL_HW_SAMAV3_ISO7816_DEFAULT_P1_BYTE;
  aCmdBuf[bCmdLen++]	= PHHAL_HW_SAMAV3_ISO7816_DEFAULT_P2_BYTE;
  aCmdBuf[bCmdLen++]	= (uint8_t) 2 /* Pack information. */;

  /* Add Pack information to command buffer. */
  aCmdBuf[bCmdLen++] = (uint8_t)((wPack & 0xFF00) >> 8);
  aCmdBuf[bCmdLen++] = (uint8_t)(wPack & 0x00FF);

  /* Append Command data to exchange buffer. */
  PH_CHECK_SUCCESS_FCT(wStatus, phhalHw_SamAV3_Cmd_7816Exchange(
          pDataParams,
          PH_EXCHANGE_DEFAULT,
          aCmdBuf,
          bCmdLen,
          &pResponse,
          &wRespLen));

  /* Return success response. */
  return PH_ADD_COMPCODE(PH_ERR_SUCCESS, PH_COMP_HAL);
}

/* X - Mode ------------------------------------------------------------------------------------------------------------ */

phStatus_t
phhalHw_SamAV3_Cmd_UL_PwdAuthUL(phhalHw_SamAV3_DataParams_t *pDataParams, uint8_t bKeyNo,
    uint8_t bKeyVer,
    uint8_t *pDivInput, uint8_t bDivInputLen, uint8_t *pStatusCode)
{
  phStatus_t	PH_MEMLOC_REM wStatus = 0;
  phStatus_t	PH_MEMLOC_REM bCmdLen = 0;
  uint8_t		PH_MEMLOC_REM aCmdBuf[PHHAL_HW_SAMAV3_ISO7816_HEADER_LENGTH +
                                            2 /* Key number and version. */];
  uint8_t 	*PH_MEMLOC_REM pResponse = NULL;
  uint16_t	PH_MEMLOC_REM wRespLen = 0;

  /* Parameter validation. */
  PH_ASSERT_NULL_DATA_PARAM(pDataParams, PH_COMP_HAL);
  if (bDivInputLen) {
    PH_ASSERT_NULL_PARAM(pDivInput, PH_COMP_HAL);
  }
  PH_ASSERT_NULL_PARAM(pStatusCode, PH_COMP_HAL);

  /* Update the status code to zero by default. */
  *pStatusCode = 0x00;

  /* Reset the command buffer and its length. */
  bCmdLen = 0;
  memset(aCmdBuf, 0x00, sizeof(aCmdBuf));	/* PRQA S 3200 */

  /* Frame Cmd.UL_PwdAuthPICC command information. */
  aCmdBuf[bCmdLen++]	= PHHAL_HW_SAMAV3_ISO7816_CLA_BYTE;
  aCmdBuf[bCmdLen++]	= PHHAL_HW_SAMAV3_CMD_UL_PWD_AUTH_PICC_INS;
  aCmdBuf[bCmdLen++]	= (uint8_t)(bDivInputLen ? 0x01 : PHHAL_HW_SAMAV3_ISO7816_DEFAULT_P1_BYTE);
  aCmdBuf[bCmdLen++]	= PHHAL_HW_SAMAV3_ISO7816_DEFAULT_P2_BYTE;
  aCmdBuf[bCmdLen++]	= (uint8_t)(2 /* Key number and version. */ +  bDivInputLen);

  /* Append Key No */
  aCmdBuf[bCmdLen++] = bKeyNo;

  /* Append Key Ver */
  aCmdBuf[bCmdLen++] = bKeyVer;

  /* Append Command data to exchange buffer. */
  PH_CHECK_SUCCESS_FCT(wStatus, phhalHw_SamAV3_Cmd_7816Exchange(
          pDataParams,
          PH_EXCHANGE_BUFFER_FIRST,
          aCmdBuf,
          bCmdLen,
          NULL,
          NULL));

  PH_CHECK_SUCCESS_FCT(wStatus, phhalHw_SamAV3_Cmd_7816Exchange(
          pDataParams,
          PH_EXCHANGE_BUFFER_CONT,
          pDivInput,
          bDivInputLen,
          &pResponse,
          &wRespLen));

  wStatus = phhalHw_SamAV3_Cmd_7816Exchange(
          pDataParams,
          PH_EXCHANGE_BUFFER_LAST,
          gaDefaultLe,
          0x01,
          &pResponse,
          &wRespLen);

  /* Extract the status code. */
  if ((wStatus & PH_ERR_MASK) == PHHAL_HW_SAMAV3_ERR_MIFARE_GEN) {
    *pStatusCode = pResponse[0];
  }

  return wStatus;
}

phStatus_t
phhalHw_SamAV3_Cmd_ULC_AuthenticatePICC(phhalHw_SamAV3_DataParams_t *pDataParams, uint8_t bOption,
    uint8_t bKeyNo, uint8_t bKeyVer,
    uint8_t *pDivInput, uint8_t bDivInputLen, uint8_t *pStatusCode)
{
  phStatus_t	PH_MEMLOC_REM wStatus = 0;
  phStatus_t	PH_MEMLOC_REM bCmdLen = 0;
  uint8_t		PH_MEMLOC_REM aCmdBuf[PHHAL_HW_SAMAV3_ISO7816_HEADER_LENGTH +
                                            2 /* Key number and version. */];
  uint8_t 	*PH_MEMLOC_REM pResponse = NULL;
  uint16_t	PH_MEMLOC_REM wRespLen = 0;

  /* Parameter validation. */
  PH_ASSERT_NULL_DATA_PARAM(pDataParams, PH_COMP_HAL);
  if (bOption & PHHAL_HW_SAMAV3_CMD_ULC_AUTHENTICATE_DIV_ON) {
    PH_ASSERT_NULL_PARAM(pDivInput, PH_COMP_HAL);
  }
  PH_ASSERT_NULL_PARAM(pStatusCode, PH_COMP_HAL);

  /* Update the status code to zero by default. */
  *pStatusCode = 0x00;

  /* Reset the command buffer and its length. */
  bCmdLen = 0;
  memset(aCmdBuf, 0x00, sizeof(aCmdBuf));	/* PRQA S 3200 */

  /* Frame Cmd.ULC_AuthenticatePICC command information. */
  aCmdBuf[bCmdLen++]	= PHHAL_HW_SAMAV3_ISO7816_CLA_BYTE;
  aCmdBuf[bCmdLen++]	= PHHAL_HW_SAMAV3_CMD_ULC_AUTHENTICATE_PICC_INS;
  aCmdBuf[bCmdLen++]	= bOption;
  aCmdBuf[bCmdLen++]	= PHHAL_HW_SAMAV3_ISO7816_DEFAULT_P2_BYTE;
  aCmdBuf[bCmdLen++]	= (uint8_t)(2 /* Key number and version. */ +  bDivInputLen);

  /* Append Key No */
  aCmdBuf[bCmdLen++] = bKeyNo;

  /* Append Key Ver */
  aCmdBuf[bCmdLen++] = bKeyVer;

  /* Append Command data to exchange buffer. */
  PH_CHECK_SUCCESS_FCT(wStatus, phhalHw_SamAV3_Cmd_7816Exchange(
          pDataParams,
          PH_EXCHANGE_BUFFER_FIRST,
          aCmdBuf,
          bCmdLen,
          NULL,
          NULL));

  /* Buffer diversification input to exchange buffer. */
  PH_CHECK_SUCCESS_FCT(wStatus, phhalHw_SamAV3_Cmd_7816Exchange(
          pDataParams,
          PH_EXCHANGE_BUFFER_CONT,
          pDivInput,
          bDivInputLen,
          &pResponse,
          &wRespLen));

  /* Buffer LE to exchange buffer and exchange the information to Sam hardware. */
  PH_CHECK_SUCCESS_FCT(wStatus, phhalHw_SamAV3_Cmd_7816Exchange(
          pDataParams,
          PH_EXCHANGE_BUFFER_LAST,
          gaDefaultLe,
          (uint8_t)((bOption & PHHAL_HW_SAMAV3_CMD_ULC_AUTHENTICATE_INCLUDE_LE) ? 0x01 : 0x00),
          &pResponse,
          &wRespLen));

  /* Extract the status code. */
  if ((wStatus & PH_ERR_MASK) == PHHAL_HW_SAMAV3_ERR_MIFARE_GEN) {
    *pStatusCode = pResponse[0];
  }

  return wStatus;
}

/*************************************************************************************************************************/
/**************************************************** Common commands ****************************************************/
/*************************************************************************************************************************/

/* S - Mode Commands --------------------------------------------------------------------------------------------------- */

phStatus_t
phhalHw_SamAV3_Cmd_SAM_CommitReaderID_Part1(phhalHw_SamAV3_DataParams_t *pDataParams,
    uint8_t bState, uint16_t wBlockNr,
    uint8_t **ppResponse, uint16_t *pRespLen)
{
  phStatus_t	PH_MEMLOC_REM wStatus = 0;
  uint8_t		PH_MEMLOC_REM bCmdLen = 0;
  uint8_t		PH_MEMLOC_REM aCmdBuf[PHHAL_HW_SAMAV3_ISO7816_HEADER_LENGTH +
                                            2 /* For framing block number */];

  /* Verify the parameters. */
  PH_ASSERT_NULL_DATA_PARAM(pDataParams, PH_COMP_HAL);
  PH_ASSERT_NULL_PARAM(pRespLen, PH_COMP_HAL);

  /* Reset the command buffer and its length. */
  bCmdLen = 0;
  memset(aCmdBuf, 0x00, sizeof(aCmdBuf));	/* PRQA S 3200 */

  /* Frame Cmd.SAM_CommitReaderID_Part1 command information. */
  aCmdBuf[bCmdLen++]	= PHHAL_HW_SAMAV3_ISO7816_CLA_BYTE;
  aCmdBuf[bCmdLen++]	= PHHAL_HW_CMD_SAMAV3_COMMIT_READER_ID_INS;
  aCmdBuf[bCmdLen++]	= PHHAL_HW_SAMAV3_ISO7816_DEFAULT_P1_BYTE;
  aCmdBuf[bCmdLen++]	= PHHAL_HW_SAMAV3_ISO7816_DEFAULT_P2_BYTE;

  /* Append LC and Block number if the state is MFP. */
  if (bState == PHHAL_HW_CMD_SAMAV3_COMMIT_READER_ID_PICC_STATE_MFP) {
    /* Append LC to command buffer. */
    aCmdBuf[bCmdLen++]		= 2 /* Two bytes of block number. */;

    /* Append block number to command buffer. */
    aCmdBuf[bCmdLen++] = (uint8_t)(wBlockNr & 0x00FF);
    aCmdBuf[bCmdLen++] = (uint8_t)((wBlockNr & 0xFF00) >> 8);
  }

  /* Append Command data to exchange buffer. */
  PH_CHECK_SUCCESS_FCT(wStatus, phhalHw_SamAV3_Cmd_7816Exchange(
          pDataParams,
          PH_EXCHANGE_BUFFER_FIRST,
          aCmdBuf,
          bCmdLen,
          NULL,
          NULL));

  /* Append LE to exchange buffer and perform final exchange with SAM hardware. */
  wStatus = phhalHw_SamAV3_Cmd_7816Exchange(
          pDataParams,
          PH_EXCHANGE_BUFFER_LAST,
          gaDefaultLe,
          1,
          ppResponse,
          pRespLen);

  /* Check for the Chaining active. */
  if ((wStatus & PH_ERR_MASK) != PHHAL_HW_SAMAV3_ERR_OK_CHAINING_ACTIVE) {
    return wStatus;
  }

  return PH_ADD_COMPCODE(PH_ERR_SUCCESS_CHAINING, PH_COMP_HAL);
}

phStatus_t
phhalHw_SamAV3_Cmd_SAM_CommitReaderID_Part2(phhalHw_SamAV3_DataParams_t *pDataParams,
    uint8_t bPiccErrCode, uint8_t *pData,
    uint8_t bDataLen, uint8_t *pPiccReturnCode)
{
  phStatus_t	PH_MEMLOC_REM wStatus = 0;
  uint8_t		PH_MEMLOC_REM aCmdBuf[PHHAL_HW_SAMAV3_ISO7816_HEADER_LENGTH];
  uint8_t 	*PH_MEMLOC_REM pResponse = NULL;
  uint16_t	PH_MEMLOC_REM wRespLen = 0;

  /* Verify the parameters. */
  PH_ASSERT_NULL_DATA_PARAM(pDataParams, PH_COMP_HAL);
  if (bDataLen) {
    PH_ASSERT_NULL_PARAM(pData, PH_COMP_HAL);
  }
  PH_ASSERT_NULL_PARAM(pPiccReturnCode, PH_COMP_HAL);

  /* Reset the command buffer. */
  memset(aCmdBuf, 0x00, sizeof(aCmdBuf));	/* PRQA S 3200 */

  /* Frame SAM_CommitReaderID_Part2 command information. */
  aCmdBuf[PHHAL_HW_SAMAV3_ISO7816_CLA_POS] = PHHAL_HW_SAMAV3_ISO7816_CLA_BYTE;
  aCmdBuf[PHHAL_HW_SAMAV3_ISO7816_INS_POS] = PHHAL_HW_CMD_SAMAV3_COMMIT_READER_ID_INS;
  aCmdBuf[PHHAL_HW_SAMAV3_ISO7816_P1_POS]	 = PHHAL_HW_SAMAV3_ISO7816_DEFAULT_P1_BYTE;
  aCmdBuf[PHHAL_HW_SAMAV3_ISO7816_P2_POS]	 = PHHAL_HW_SAMAV3_ISO7816_DEFAULT_P2_BYTE;
  aCmdBuf[PHHAL_HW_SAMAV3_ISO7816_LC_POS]	 = bDataLen + 1 /* Picc Status code. */;

  /* Buffer command information to exchang buffer. */
  PH_CHECK_SUCCESS_FCT(wStatus, phhalHw_SamAV3_Cmd_7816Exchange(
          pDataParams,
          PH_EXCHANGE_BUFFER_FIRST,
          aCmdBuf,
          PHHAL_HW_SAMAV3_ISO7816_HEADER_LENGTH,
          NULL,
          NULL));

  /* Buffer Picc status code to exchang buffer. */
  PH_CHECK_SUCCESS_FCT(wStatus, phhalHw_SamAV3_Cmd_7816Exchange(
          pDataParams,
          PH_EXCHANGE_BUFFER_CONT,
          &bPiccErrCode,
          1,
          NULL,
          NULL));

  /* Buffer payload information to exchange buffer. */
  PH_CHECK_SUCCESS_FCT(wStatus, phhalHw_SamAV3_Cmd_7816Exchange(
          pDataParams,
          PH_EXCHANGE_BUFFER_CONT,
          pData,
          bDataLen,
          NULL,
          NULL));

  /* Append LE to exchange buffer and perform final exchange with SAM hardware. */
  wStatus = phhalHw_SamAV3_Cmd_7816Exchange(
          pDataParams,
          PH_EXCHANGE_BUFFER_LAST,
          gaDefaultLe,
          1,
          &pResponse,
          &wRespLen);

  /* Extract the PICC error code. */
  if ((wStatus & PH_ERR_MASK) == PHHAL_HW_SAMAV3_ERR_MIFARE_GEN) {
    /* Assign the PICC response code the parameter. */
    *pPiccReturnCode = pResponse[0];
  }

  return wStatus;
}

/* X - Mode Commands --------------------------------------------------------------------------------------------------- */

phStatus_t
phhalHw_SamAV3_Cmd_TMRI_CommitReaderID(phhalHw_SamAV3_DataParams_t *pDataParams, uint8_t bISOMode,
    uint8_t bState, uint16_t wBlockNr,
    uint8_t **ppEncTMRI, uint16_t *pEncTMRILen, uint8_t *pStatusCode)
{
  phStatus_t	PH_MEMLOC_REM wStatus = 0;
  uint8_t		PH_MEMLOC_REM aCmdBuf[PHHAL_HW_SAMAV3_ISO7816_HEADER_LENGTH +
                                            2 /* For framing block number */];
  uint8_t		PH_MEMLOC_REM bCmdLen = 0;
  uint8_t 	*PH_MEMLOC_REM pResponse = NULL;
  uint16_t	PH_MEMLOC_REM wRespLen = 0;

  /* Verify the parameters. */
  PH_ASSERT_NULL_DATA_PARAM(pDataParams, PH_COMP_HAL);
  PH_ASSERT_NULL_PARAM(pEncTMRILen, PH_COMP_HAL);

  /* Reset the command buffer and its length variable. */
  bCmdLen = 0;
  memset(aCmdBuf, 0x00, sizeof(aCmdBuf));	/* PRQA S 3200 */

  /* Frame the command Cmd.SAM_PLExec. */
  aCmdBuf[bCmdLen++]	= PHHAL_HW_SAMAV3_ISO7816_CLA_BYTE;
  aCmdBuf[bCmdLen++]	= PHHAL_HW_CMD_SAMAV3_TMRI_COMMIT_READER_ID_INS;
  aCmdBuf[bCmdLen++]	= PHHAL_HW_SAMAV3_ISO7816_DEFAULT_P1_BYTE;
  aCmdBuf[bCmdLen++]	= bISOMode;

  /* Add block number to command buffer is MFP state. */
  if (bState == PHHAL_HW_CMD_SAMAV3_COMMIT_READER_ID_PICC_STATE_MFP) {
    /* Add LC to command buffer. */
    aCmdBuf[bCmdLen++] = 2;

    /* Add Block number to command buffer. */
    aCmdBuf[bCmdLen++] = (uint8_t)(wBlockNr & 0x00FF);
    aCmdBuf[bCmdLen++] = (uint8_t)((wBlockNr & 0xFF00) >> 8);
  }

  /* Buffer the command information to exchnage buffer. */
  PH_CHECK_SUCCESS_FCT(wStatus, phhalHw_SamAV3_Cmd_7816Exchange(
          pDataParams,
          PH_EXCHANGE_BUFFER_FIRST,
          aCmdBuf,
          bCmdLen,
          NULL,
          NULL));

  /* Buffer LE and exchange the bufferred information to Sam hardware. */
  wStatus = phhalHw_SamAV3_Cmd_7816Exchange(
          pDataParams,
          PH_EXCHANGE_BUFFER_LAST,
          gaDefaultLe,
          1,
          &pResponse,
          &wRespLen);

  /* Extract the PICC error code. */
  if ((wStatus & PH_ERR_MASK) == PHHAL_HW_SAMAV3_ERR_MIFARE_GEN) {
    /* Assign the PICC response code the parameter. */
    memcpy(pStatusCode, pResponse, (bISOMode ? 2 : 1));	/* PRQA S 3200 */
  }

  /* Update the response to the parameters if success. */
  if ((wStatus & PH_ERR_MASK) == PH_ERR_SUCCESS) {
    *ppEncTMRI = pResponse;
    *pEncTMRILen = wRespLen;
  }

  return wStatus;
}

/*************************************************************************************************************************/
/*************************************************** ISO / IEC 29167-10 **************************************************/
/*************************************************************************************************************************/

phStatus_t
phhalHw_SamAV3_Cmd_SAM_AuthenticateTAM1(phhalHw_SamAV3_DataParams_t *pDataParams, uint8_t bOption,
    uint8_t bKeyNo, uint8_t bKeyVer,
    uint8_t *pData, uint8_t bDataLen, uint8_t **ppIChallange, uint16_t *pIChallangeLen)
{
  phStatus_t  PH_MEMLOC_REM wStatus = 0;
  uint8_t     PH_MEMLOC_REM aCmdBuf[PHHAL_HW_SAMAV3_ISO7816_HEADER_LENGTH + 2 /* KeyNo, KeyVer */];
  uint8_t		PH_MEMLOC_REM bCmdLen = 0;

  /* Validate the parameters. */
  PH_ASSERT_NULL_DATA_PARAM(pDataParams, PH_COMP_HAL);

  /* Clear all the local variables. */
  bCmdLen = 0;
  memset(aCmdBuf, 0x00, sizeof(aCmdBuf));	/* PRQA S 3200 */

  /* Frame the command to be sent to SAM and receive the TAM1 random number. --------------------------------------- */
  if (bOption == PHHAL_HW_SAMAV3_CMD_TAM_GET_RND) {
    /* Validate the parameters. */
    if (bDataLen) {
      PH_ASSERT_NULL_PARAM(pData, PH_COMP_HAL);
    }
    PH_ASSERT_NULL_PARAM(pIChallangeLen, PH_COMP_HAL);

    aCmdBuf[bCmdLen++] = PHHAL_HW_SAMAV3_ISO7816_CLA_BYTE;
    aCmdBuf[bCmdLen++] = PHHAL_HW_SAMAV3_CMD_AUTHENTICATE_TAM_INS;
    aCmdBuf[bCmdLen++] = (uint8_t)
        PHHAL_HW_SAMAV3_CMD_TAM_CLEAR /* Custom data flag not required for TAM1 Request.*/;
    aCmdBuf[bCmdLen++] = PHHAL_HW_SAMAV3_ISO7816_DEFAULT_P2_BYTE;
    aCmdBuf[bCmdLen++] = PHHAL_HW_SAMAV3_ISO7816_DEFAULT_LC_BYTE + bDataLen;

    /* Set the Bit 0 of P1 if diversification data is present. */
    if (bDataLen) {
      aCmdBuf[PHHAL_HW_SAMAV3_ISO7816_P1_POS] |= 0x01;
    }

    /* Add Key information to command buffer. */
    aCmdBuf[bCmdLen++] = bKeyNo;
    aCmdBuf[bCmdLen++] = bKeyVer;

    /* Buffer command information exchange buffer. */
    PH_CHECK_SUCCESS_FCT(wStatus, phhalHw_SamAV3_Cmd_7816Exchange(
            pDataParams,
            PH_EXCHANGE_BUFFER_FIRST,
            aCmdBuf,
            bCmdLen,
            NULL,
            NULL));

    /* Buffer diversification information exchange buffer. */
    PH_CHECK_SUCCESS_FCT(wStatus, phhalHw_SamAV3_Cmd_7816Exchange(
            pDataParams,
            PH_EXCHANGE_BUFFER_CONT,
            pData,
            bDataLen,
            NULL,
            NULL));

    /* Update LC. */
    PH_CHECK_SUCCESS_FCT(wStatus, phhalHw_SamAV3_Utils_UpdateLc(pDataParams));

    /* Buffer LE and exchange the bufferred inforamtion to Sam hardware. */
    wStatus = phhalHw_SamAV3_Cmd_7816Exchange(
            pDataParams,
            PH_EXCHANGE_BUFFER_LAST,
            gaDefaultLe,
            1,
            ppIChallange,
            pIChallangeLen);

    /* Check for the Chaining active. */
    if ((wStatus & PH_ERR_MASK) != PHHAL_HW_SAMAV3_ERR_OK_CHAINING_ACTIVE) {
      return wStatus;
    }

    return PH_ADD_COMPCODE(PH_ERR_SUCCESS_CHAINING, PH_COMP_HAL);
  }

  /* Frame the command to be sent to SAM for decryption, verification. --------------------------------------------- */
  if (bOption == PHHAL_HW_SAMAV3_CMD_TAM_PROCESS_TRESPONE) {
    /* Validate the parameters. */
    PH_ASSERT_NULL_PARAM(pData, PH_COMP_HAL);

    /* Clear all the local variables. */
    bCmdLen = 0;
    memset(aCmdBuf, 0x00, sizeof(aCmdBuf));	/* PRQA S 3200 */

    aCmdBuf[bCmdLen++] = PHHAL_HW_SAMAV3_ISO7816_CLA_BYTE;
    aCmdBuf[bCmdLen++] = PHHAL_HW_SAMAV3_CMD_AUTHENTICATE_TAM_INS;
    aCmdBuf[bCmdLen++] = PHHAL_HW_SAMAV3_ISO7816_DEFAULT_P1_BYTE;
    aCmdBuf[bCmdLen++] = PHHAL_HW_SAMAV3_ISO7816_DEFAULT_P2_BYTE;
    aCmdBuf[bCmdLen++] = (uint8_t) bDataLen;

    /* Buffer command information exchange buffer. */
    PH_CHECK_SUCCESS_FCT(wStatus, phhalHw_SamAV3_Cmd_7816Exchange(
            pDataParams,
            PH_EXCHANGE_BUFFER_FIRST,
            aCmdBuf,
            bCmdLen,
            NULL,
            NULL));

    /* Buffer TResponse information exchange buffer. */
    PH_CHECK_SUCCESS_FCT(wStatus, phhalHw_SamAV3_Cmd_7816Exchange(
            pDataParams,
            PH_EXCHANGE_BUFFER_CONT,
            pData,
            bDataLen,
            NULL,
            NULL));

    /* Excahgne bufferred information to Sam hardware. */
    PH_CHECK_SUCCESS_FCT(wStatus, phhalHw_SamAV3_Cmd_7816Exchange(
            pDataParams,
            PH_EXCHANGE_BUFFER_LAST,
            NULL,
            0,
            ppIChallange,
            pIChallangeLen));
  }

  return PH_ADD_COMPCODE(PH_ERR_SUCCESS, PH_COMP_HAL);
}

phStatus_t
phhalHw_SamAV3_Cmd_SAM_AuthenticateTAM2(phhalHw_SamAV3_DataParams_t *pDataParams, uint8_t bOption,
    uint16_t wKeyNo, uint16_t wKeyVer,
    uint8_t *pData, uint8_t bDataLen, uint8_t bBlockSize, uint8_t bBlockCount, uint8_t bProtMode,
    uint8_t **ppResponse, uint16_t *pResponseLen)
{
  phStatus_t  PH_MEMLOC_REM wStatus;
  uint8_t		PH_MEMLOC_REM bCustDataLen	= 0;
  uint8_t		PH_MEMLOC_REM bCmdLen = 0;
  uint8_t     PH_MEMLOC_REM aCmdBuf[PHHAL_HW_SAMAV3_CMD_TAM2_COMMAND_SIZE];

  /* Clear all the local variables. */
  memset(aCmdBuf, 0x00, sizeof(aCmdBuf));	/* PRQA S 3200 */

  /* Frame the command to be sent to SAM and receive the TAM1 random number. --------------------------------------- */
  if (bOption == PHHAL_HW_SAMAV3_CMD_TAM_GET_RND) {
    aCmdBuf[PHHAL_HW_SAMAV3_ISO7816_CLA_POS] = PHHAL_HW_SAMAV3_ISO7816_CLA_BYTE;
    aCmdBuf[PHHAL_HW_SAMAV3_ISO7816_INS_POS] = PHHAL_HW_SAMAV3_CMD_AUTHENTICATE_TAM_INS;
    aCmdBuf[PHHAL_HW_SAMAV3_ISO7816_P1_POS] = (uint8_t)((bProtMode << 4) |
            PHHAL_HW_SAMAV3_CMD_TAM_SET /* Custom data flag required for TAM2 Request.*/);

    /* Set the Bit 0 of P1 if diversification data is present. */
    if (bDataLen) {
      aCmdBuf[PHHAL_HW_SAMAV3_ISO7816_P1_POS] |= 0x01;
    }

    aCmdBuf[PHHAL_HW_SAMAV3_ISO7816_P2_POS] = PHHAL_HW_SAMAV3_ISO7816_DEFAULT_P2_BYTE;
    aCmdBuf[PHHAL_HW_SAMAV3_ISO7816_LC_POS] = 2 /* KeyNo + KeyVer */ + bDataLen;

    bCmdLen = PHHAL_HW_SAMAV3_ISO7816_LC_POS + 1;

    aCmdBuf[bCmdLen++] = (uint8_t) wKeyNo;
    aCmdBuf[bCmdLen++] = (uint8_t) wKeyVer;

    /* Update the command buffer with diversification input if provided. */
    if (bDataLen) {
      /* Append the diversification input available in pData to command buffer. */
      memcpy(&aCmdBuf[bCmdLen], pData, bDataLen);	/* PRQA S 3200 */
      bCmdLen += bDataLen;
    }

    /* Append LE byte. */
    aCmdBuf[bCmdLen++] = PHHAL_HW_SAMAV3_ISO7816_DEFAULT_LE_BYTE;

    /* Exchange the command to SAM hardware.
     * As per the data sheet SAM sends Challenge data and sets the status as 0x90AF(Chaining enabled)
     */
    wStatus = phhalHw_SamAV3_Cmd_7816Exchange(
            pDataParams,
            PH_EXCHANGE_DEFAULT,
            aCmdBuf,
            bCmdLen,
            ppResponse,
            pResponseLen);

    /* Check for the Chaining active */
    if ((wStatus & PH_ERR_MASK) != PHHAL_HW_SAMAV3_ERR_OK_CHAINING_ACTIVE) {
      return wStatus;
    }
  }

  /* Frame the command to be sent to SAM for decryption, verification. --------------------------------------------- */
  if (bOption == PHHAL_HW_SAMAV3_CMD_TAM_PROCESS_TRESPONE) {
    /* Clear all the local variables. */
    bCmdLen = 0;
    memset(aCmdBuf, 0x00, sizeof(aCmdBuf));	/* PRQA S 3200 */

    /*
     * Calculate the Custom Data Length. For calculation D
     *		refer
     *			DocumentID		: ISO-IEC_29167-10(E)_AMD1_2015-05-07_red.pdf
     *			Document Name	: Information technology  Automatic identification and data capture techniques 
     *							  Part 10: Crypto suite AES-128 security services for air interface communications - AMD1
     *			PgNo			: 16,
     *			Section			: 10.2 Adding custom data to authentication process
     */
    if (bBlockSize) {
      /*
       * The formula for calculating D for 64 bit block size is as follows.
       * D = ( n + 1 ) / 2 + ( n + 1 ) % 2, Where n = BlockCount ranging from 0 - 15.
       * Because the current BlockCount value range is from 1 - 16, to match it with ISO 29167 protocol, the incrementation
       * of BlockCount in the actual formual is removed as its already incremented. So the new formula to calculate D is
       * D = n / 2 + n % 2, Where n = BlockCount ranging from 1 - 16.
       * Finally mutiplying by 16 because the CustomData is represented as D * 128 => D * 16
       */
      bCustDataLen = (uint8_t)(((bBlockCount / 2) + (bBlockCount % 2)) * 16);
    } else {
      /*
       * The formula for calculating D for 16 bit block size is as follows.
       * D = ( n + 8 ) / 8, Where n = BlockCount ranging from 0 - 15.
       * Because the current BlockCount value range is from 1 - 16, to match it with ISO 29167 protocol, the BlockCount
       * is decremented by 1 in the actual formual. So the new formula to calculate D is
       * D = ( ( n - 1) + 8) / 8, Where n = BlockCount ranging from 1 - 16.
       * Finally mutiplying by 16 because the CustomData is represented as D * 128 => D * 16
       */
      bCustDataLen = (uint8_t)((((bBlockCount - 1) + 8) / 8) * 16);
    }

    aCmdBuf[PHHAL_HW_SAMAV3_ISO7816_CLA_POS] = PHHAL_HW_SAMAV3_ISO7816_CLA_BYTE;
    aCmdBuf[PHHAL_HW_SAMAV3_ISO7816_INS_POS] = PHHAL_HW_SAMAV3_CMD_AUTHENTICATE_TAM_INS;
    aCmdBuf[PHHAL_HW_SAMAV3_ISO7816_P1_POS] = PHHAL_HW_SAMAV3_ISO7816_DEFAULT_P1_BYTE;
    aCmdBuf[PHHAL_HW_SAMAV3_ISO7816_P2_POS] = PHHAL_HW_SAMAV3_ISO7816_DEFAULT_P2_BYTE;
    aCmdBuf[PHHAL_HW_SAMAV3_ISO7816_LC_POS] = bDataLen;

    bCmdLen = PHHAL_HW_SAMAV3_ISO7816_LC_POS + 1;

    aCmdBuf[bCmdLen++] = (uint8_t) bCustDataLen;

    /* Append the TResponse available in pData to command buffer. */
    memcpy(&aCmdBuf[bCmdLen], pData, bDataLen);	/* PRQA S 3200 */
    bCmdLen += bDataLen;

    /* Append LE byte. */
    aCmdBuf[bCmdLen++] = PHHAL_HW_SAMAV3_ISO7816_DEFAULT_LE_BYTE;

    /* Exchange the command to SAM hardware. SAM should send 90 00 for successfull execution. */
    PH_CHECK_SUCCESS_FCT(wStatus, phhalHw_SamAV3_Cmd_7816Exchange(
            pDataParams,
            PH_EXCHANGE_DEFAULT,
            aCmdBuf,
            bCmdLen,
            ppResponse,
            pResponseLen));
  }

  return PH_ADD_COMPCODE(PH_ERR_SUCCESS, PH_COMP_HAL);
}

phStatus_t
phhalHw_SamAV3_Cmd_SAM_AuthenticateMAM1(phhalHw_SamAV3_DataParams_t *pDataParams, uint8_t bKeyNo,
    uint8_t bKeyVer, uint8_t *pData,
    uint8_t bDataLen, uint8_t bPurposeMAM2, uint8_t **ppIChallange, uint16_t *pIChallangeLen)
{
  phStatus_t  PH_MEMLOC_REM wStatus = 0;
  uint8_t     PH_MEMLOC_REM aCmdBuf[PHHAL_HW_SAMAV3_ISO7816_HEADER_LENGTH + 2 /* KeyNo, KeyVer */];
  uint8_t		PH_MEMLOC_REM bCmdLen = 0;

  /* Validate the parameters. */
  PH_ASSERT_NULL_DATA_PARAM(pDataParams, PH_COMP_HAL);
  if (bDataLen) {
    PH_ASSERT_NULL_DATA_PARAM(pData, PH_COMP_HAL);
  }
  PH_ASSERT_NULL_DATA_PARAM(pIChallangeLen, PH_COMP_HAL);

  /* Clear all the local variables. */
  memset(aCmdBuf, 0x00, sizeof(aCmdBuf));	/* PRQA S 3200 */

  /* Frame Cmd.SAM_AuthenticateMAM part 1 command information. */
  aCmdBuf[bCmdLen++] = PHHAL_HW_SAMAV3_ISO7816_CLA_BYTE;
  aCmdBuf[bCmdLen++] = PHHAL_HW_SAMAV3_CMD_AUTHENTICATE_MAM_INS;
  aCmdBuf[bCmdLen++] = (uint8_t)(bPurposeMAM2 << 4);
  aCmdBuf[bCmdLen++] = PHHAL_HW_SAMAV3_ISO7816_DEFAULT_P2_BYTE;
  aCmdBuf[bCmdLen++] = PHHAL_HW_SAMAV3_ISO7816_DEFAULT_LC_BYTE + bDataLen;

  /* Set the Bit 0 of P1 if diversification data is present. */
  if (bDataLen) {
    aCmdBuf[PHHAL_HW_SAMAV3_ISO7816_P1_POS] |= 0x01;
  }

  /* Add Key information to command buffer. */
  aCmdBuf[bCmdLen++] = bKeyNo;
  aCmdBuf[bCmdLen++] = bKeyVer;

  /* Buffer command information exchange buffer. */
  PH_CHECK_SUCCESS_FCT(wStatus, phhalHw_SamAV3_Cmd_7816Exchange(
          pDataParams,
          PH_EXCHANGE_BUFFER_FIRST,
          aCmdBuf,
          bCmdLen,
          NULL,
          NULL));

  /* Buffer diversification information exchange buffer. */
  PH_CHECK_SUCCESS_FCT(wStatus, phhalHw_SamAV3_Cmd_7816Exchange(
          pDataParams,
          PH_EXCHANGE_BUFFER_CONT,
          pData,
          bDataLen,
          NULL,
          NULL));

  /* Update LC. */
  PH_CHECK_SUCCESS_FCT(wStatus, phhalHw_SamAV3_Utils_UpdateLc(pDataParams));

  /* Buffer LE and exchange the bufferred inforamtion to Sam hardware. */
  wStatus = phhalHw_SamAV3_Cmd_7816Exchange(
          pDataParams,
          PH_EXCHANGE_BUFFER_LAST,
          gaDefaultLe,
          1,
          ppIChallange,
          pIChallangeLen);

  /* Check for the Chaining active. */
  if ((wStatus & PH_ERR_MASK) != PHHAL_HW_SAMAV3_ERR_OK_CHAINING_ACTIVE) {
    return wStatus;
  }

  return PH_ADD_COMPCODE(PH_ERR_SUCCESS_CHAINING, PH_COMP_HAL);
}

phStatus_t
phhalHw_SamAV3_Cmd_SAM_AuthenticateMAM2(phhalHw_SamAV3_DataParams_t *pDataParams, uint8_t *pData,
    uint8_t bDataLen, uint8_t **ppIResponse,
    uint16_t *pIResponseLen)
{
  phStatus_t  PH_MEMLOC_REM wStatus = 0;
  uint8_t     PH_MEMLOC_REM aCmdBuf[PHHAL_HW_SAMAV3_ISO7816_HEADER_LENGTH];

  /* Validate the parameters. */
  PH_ASSERT_NULL_DATA_PARAM(pDataParams, PH_COMP_HAL);
  if (bDataLen) {
    PH_ASSERT_NULL_DATA_PARAM(pData, PH_COMP_HAL);
  }
  PH_ASSERT_NULL_DATA_PARAM(pIResponseLen, PH_COMP_HAL);

  /* Clear all the local variables. */
  memset(aCmdBuf, 0x00, sizeof(aCmdBuf));	/* PRQA S 3200 */

  /* Frame Cmd.SAM_AuthenticateMAM part 2 command information. */
  aCmdBuf[PHHAL_HW_SAMAV3_ISO7816_CLA_POS] = PHHAL_HW_SAMAV3_ISO7816_CLA_BYTE;
  aCmdBuf[PHHAL_HW_SAMAV3_ISO7816_INS_POS] = PHHAL_HW_SAMAV3_CMD_AUTHENTICATE_MAM_INS;
  aCmdBuf[PHHAL_HW_SAMAV3_ISO7816_P1_POS]  = PHHAL_HW_SAMAV3_ISO7816_DEFAULT_P1_BYTE;
  aCmdBuf[PHHAL_HW_SAMAV3_ISO7816_P2_POS]  = PHHAL_HW_SAMAV3_ISO7816_DEFAULT_P2_BYTE;
  aCmdBuf[PHHAL_HW_SAMAV3_ISO7816_LC_POS]  = bDataLen;

  /* Buffer command information exchange buffer. */
  PH_CHECK_SUCCESS_FCT(wStatus, phhalHw_SamAV3_Cmd_7816Exchange(
          pDataParams,
          PH_EXCHANGE_BUFFER_FIRST,
          aCmdBuf,
          PHHAL_HW_SAMAV3_ISO7816_HEADER_LENGTH,
          NULL,
          NULL));

  /* Buffer TResponse information exchange buffer. */
  PH_CHECK_SUCCESS_FCT(wStatus, phhalHw_SamAV3_Cmd_7816Exchange(
          pDataParams,
          PH_EXCHANGE_BUFFER_CONT,
          pData,
          bDataLen,
          NULL,
          NULL));

  /* Update LC. */
  PH_CHECK_SUCCESS_FCT(wStatus, phhalHw_SamAV3_Utils_UpdateLc(pDataParams));

  /* Buffer LE and exchange the bufferred inforamtion to Sam hardware. */
  PH_CHECK_SUCCESS_FCT(wStatus, phhalHw_SamAV3_Cmd_7816Exchange(
          pDataParams,
          PH_EXCHANGE_BUFFER_LAST,
          gaDefaultLe,
          1,
          ppIResponse,
          pIResponseLen));

  return PH_ADD_COMPCODE(PH_ERR_SUCCESS, PH_COMP_HAL);
}

/*************************************************************************************************************************/
/****************************************************** EMV commands *****************************************************/
/*************************************************************************************************************************/

phStatus_t
phhalHw_SamAV3_Cmd_EMVCo_RecoverStaticData(phhalHw_SamAV3_DataParams_t *pDataParams,
    uint16_t wOption, uint8_t *pSignedStaticAppData,
    uint8_t bSignedStaticAppDataLen, uint8_t **ppResponse, uint8_t *pRespLen)
{
  phStatus_t	PH_MEMLOC_REM wStatus = 0;
  uint8_t		PH_MEMLOC_REM aCmdBuf[PHHAL_HW_SAMAV3_ISO7816_HEADER_LENGTH];
  uint16_t	PH_MEMLOC_REM wRespLen = 0;

  /* Parameter validation. */
  PH_ASSERT_NULL_DATA_PARAM(pDataParams, PH_COMP_HAL);
  PH_ASSERT_NULL_PARAM(pSignedStaticAppData, PH_COMP_HAL);
  PH_ASSERT_NULL_PARAM(pRespLen, PH_COMP_HAL);

  /* Frame Cmd.SAM_RecoverStaticData command information. */
  aCmdBuf[PHHAL_HW_SAMAV3_ISO7816_CLA_POS] = PHHAL_HW_SAMAV3_ISO7816_CLA_BYTE;
  aCmdBuf[PHHAL_HW_SAMAV3_ISO7816_INS_POS] = PHHAL_HW_SAMAV3_CMD_EMVCO_RECOVER_STATIC_DATA_INS;
  aCmdBuf[PHHAL_HW_SAMAV3_ISO7816_P1_POS]  = PHHAL_HW_SAMAV3_ISO7816_LAST_FRAME;
  aCmdBuf[PHHAL_HW_SAMAV3_ISO7816_P2_POS]  = PHHAL_HW_SAMAV3_ISO7816_DEFAULT_P2_BYTE;
  aCmdBuf[PHHAL_HW_SAMAV3_ISO7816_LC_POS]  = PHHAL_HW_SAMAV3_ISO7816_DEFAULT_LC_BYTE;

  /* Set the Last Frame Indicator flag. */
  if (wOption == PH_EXCHANGE_TXCHAINING) {
    aCmdBuf[PHHAL_HW_SAMAV3_ISO7816_P1_POS]  = PHHAL_HW_SAMAV3_ISO7816_CHAINED_FRAME;
  }

  /* Buffer command information to exchange buffer. */
  PH_CHECK_SUCCESS_FCT(wStatus, phhalHw_SamAV3_Cmd_7816Exchange(
          pDataParams,
          PH_EXCHANGE_BUFFER_FIRST,
          aCmdBuf,
          PHHAL_HW_SAMAV3_ISO7816_HEADER_LENGTH,
          NULL,
          NULL));

  /* Buffer Signed static application data to exchange buffer. */
  PH_CHECK_SUCCESS_FCT(wStatus, phhalHw_SamAV3_Cmd_7816Exchange(
          pDataParams,
          PH_EXCHANGE_BUFFER_CONT,
          pSignedStaticAppData,
          bSignedStaticAppDataLen,
          NULL,
          NULL));

  /* Update LC value. */
  PH_CHECK_SUCCESS_FCT(wStatus, phhalHw_SamAV3_Utils_UpdateLc(pDataParams));

  /* Buffer LE and exchange the bufferred information to Sam hardware. */
  wStatus = phhalHw_SamAV3_Cmd_7816Exchange(
          pDataParams,
          PH_EXCHANGE_BUFFER_LAST,
          gaDefaultLe,
          0x01,
          ppResponse,
          &wRespLen);

  /* Update the response length parameter. */
  *pRespLen = (uint8_t) wRespLen;

  /* Return the chaining code. */
  if ((wStatus & PH_ERR_MASK) == PHHAL_HW_SAMAV3_ERR_OK_CHAINING_ACTIVE) {
    return PH_ADD_COMPCODE(PH_ERR_SUCCESS_CHAINING, PH_COMP_HAL);
  }

  return PH_ADD_COMPCODE(PH_ERR_SUCCESS, PH_COMP_HAL);
}

phStatus_t
phhalHw_SamAV3_Cmd_EMVCo_RecoverDynamicData(phhalHw_SamAV3_DataParams_t *pDataParams,
    uint16_t wOption, uint8_t *pSignedDynamicAppData,
    uint8_t bSignedDynamicAppDataLen, uint8_t **ppResponse, uint8_t *pRespLen)
{
  phStatus_t	PH_MEMLOC_REM wStatus = 0;
  uint8_t		PH_MEMLOC_REM aCmdBuf[PHHAL_HW_SAMAV3_ISO7816_HEADER_LENGTH];
  uint16_t	PH_MEMLOC_REM wRespLen = 0;

  /* Parameter validation. */
  PH_ASSERT_NULL_DATA_PARAM(pDataParams, PH_COMP_HAL);
  PH_ASSERT_NULL_PARAM(pSignedDynamicAppData, PH_COMP_HAL);
  PH_ASSERT_NULL_PARAM(pRespLen, PH_COMP_HAL);

  /* Frame Cmd.SAM_RecoverDynamicData command information. */
  aCmdBuf[PHHAL_HW_SAMAV3_ISO7816_CLA_POS] = PHHAL_HW_SAMAV3_ISO7816_CLA_BYTE;
  aCmdBuf[PHHAL_HW_SAMAV3_ISO7816_INS_POS] = PHHAL_HW_SAMAV3_CMD_EMVCO_RECOVER_DYNAMIC_DATA_INS;
  aCmdBuf[PHHAL_HW_SAMAV3_ISO7816_P1_POS]  = PHHAL_HW_SAMAV3_ISO7816_LAST_FRAME;
  aCmdBuf[PHHAL_HW_SAMAV3_ISO7816_P2_POS]  = PHHAL_HW_SAMAV3_ISO7816_DEFAULT_P2_BYTE;
  aCmdBuf[PHHAL_HW_SAMAV3_ISO7816_LC_POS]  = PHHAL_HW_SAMAV3_ISO7816_DEFAULT_LC_BYTE;

  /* Set the Last Frame Indicator flag. */
  if (wOption == PH_EXCHANGE_TXCHAINING) {
    aCmdBuf[PHHAL_HW_SAMAV3_ISO7816_P1_POS]  = PHHAL_HW_SAMAV3_ISO7816_CHAINED_FRAME;
  }

  /* Buffer command information to exchange buffer. */
  PH_CHECK_SUCCESS_FCT(wStatus, phhalHw_SamAV3_Cmd_7816Exchange(
          pDataParams,
          PH_EXCHANGE_BUFFER_FIRST,
          aCmdBuf,
          PHHAL_HW_SAMAV3_ISO7816_HEADER_LENGTH,
          NULL,
          NULL));

  /* Buffer Signed Dynamic application data to exchange buffer. */
  PH_CHECK_SUCCESS_FCT(wStatus, phhalHw_SamAV3_Cmd_7816Exchange(
          pDataParams,
          PH_EXCHANGE_BUFFER_CONT,
          pSignedDynamicAppData,
          bSignedDynamicAppDataLen,
          NULL,
          NULL));

  /* Update LC value. */
  PH_CHECK_SUCCESS_FCT(wStatus, phhalHw_SamAV3_Utils_UpdateLc(pDataParams));

  /* Buffer LE and exchange the bufferred information to Sam hardware. */
  wStatus = phhalHw_SamAV3_Cmd_7816Exchange(
          pDataParams,
          PH_EXCHANGE_BUFFER_LAST,
          gaDefaultLe,
          0x01,
          ppResponse,
          &wRespLen);

  /* Update the response length parameter. */
  *pRespLen = (uint8_t) wRespLen;

  /* Return the chaining code. */
  if ((wStatus & PH_ERR_MASK) == PHHAL_HW_SAMAV3_ERR_OK_CHAINING_ACTIVE) {
    return PH_ADD_COMPCODE(PH_ERR_SUCCESS_CHAINING, PH_COMP_HAL);
  }

  return PH_ADD_COMPCODE(PH_ERR_SUCCESS, PH_COMP_HAL);
}

phStatus_t
phhalHw_SamAV3_Cmd_EMVCo_EncipherPin(phhalHw_SamAV3_DataParams_t *pDataParams, uint8_t *pPinBlock,
    uint8_t *pIccNum,
    uint8_t **ppResponse, uint8_t *pRespLen)
{
  phStatus_t	PH_MEMLOC_REM wStatus = 0;
  uint8_t		PH_MEMLOC_REM aCmdBuf[PHHAL_HW_SAMAV3_ISO7816_HEADER_LENGTH];
  uint16_t	PH_MEMLOC_REM wRespLen = 0;

  /* Parameter validation. */
  PH_ASSERT_NULL_DATA_PARAM(pDataParams, PH_COMP_HAL);
  PH_ASSERT_NULL_PARAM(pPinBlock, PH_COMP_HAL);
  PH_ASSERT_NULL_PARAM(pIccNum, PH_COMP_HAL);
  PH_ASSERT_NULL_PARAM(pRespLen, PH_COMP_HAL);

  /* Frame Cmd.SAM_EncipherPIN command information. */
  aCmdBuf[PHHAL_HW_SAMAV3_ISO7816_CLA_POS] = PHHAL_HW_SAMAV3_ISO7816_CLA_BYTE;
  aCmdBuf[PHHAL_HW_SAMAV3_ISO7816_INS_POS] = PHHAL_HW_SAMAV3_CMD_EMVCO_RECOVER_ENCIPHER_PIN_INS;
  aCmdBuf[PHHAL_HW_SAMAV3_ISO7816_P1_POS]  = PHHAL_HW_SAMAV3_ISO7816_DEFAULT_P1_BYTE;
  aCmdBuf[PHHAL_HW_SAMAV3_ISO7816_P2_POS]  = PHHAL_HW_SAMAV3_ISO7816_DEFAULT_P2_BYTE;
  aCmdBuf[PHHAL_HW_SAMAV3_ISO7816_LC_POS]  = PHHAL_HW_SAMAV3_ISO7816_DEFAULT_LC_BYTE;

  /* Buffer command information to exchange buffer. */
  PH_CHECK_SUCCESS_FCT(wStatus, phhalHw_SamAV3_Cmd_7816Exchange(
          pDataParams,
          PH_EXCHANGE_BUFFER_FIRST,
          aCmdBuf,
          PHHAL_HW_SAMAV3_ISO7816_HEADER_LENGTH,
          NULL,
          NULL));

  /* Buffer PIN block information to exchange buffer. */
  PH_CHECK_SUCCESS_FCT(wStatus, phhalHw_SamAV3_Cmd_7816Exchange(
          pDataParams,
          PH_EXCHANGE_BUFFER_CONT,
          pPinBlock,
          8,
          NULL,
          NULL));

  /* Buffer ICC Number information to exchange buffer. */
  PH_CHECK_SUCCESS_FCT(wStatus, phhalHw_SamAV3_Cmd_7816Exchange(
          pDataParams,
          PH_EXCHANGE_BUFFER_CONT,
          pIccNum,
          8,
          NULL,
          NULL));

  /* Update LC value. */
  PH_CHECK_SUCCESS_FCT(wStatus, phhalHw_SamAV3_Utils_UpdateLc(pDataParams));

  /* Buffer LE and exchange the bufferred information to Sam hardware. */
  PH_CHECK_SUCCESS_FCT(wStatus, phhalHw_SamAV3_Cmd_7816Exchange(
          pDataParams,
          PH_EXCHANGE_BUFFER_LAST,
          gaDefaultLe,
          0x01,
          ppResponse,
          &wRespLen));

  /* Update the response length parameter. */
  *pRespLen = (uint8_t) wRespLen;

  return PH_ADD_COMPCODE(PH_ERR_SUCCESS, PH_COMP_HAL);
}

/*************************************************************************************************************************/
/*************************************************** Programmable Logic **************************************************/
/*************************************************************************************************************************/

phStatus_t
phhalHw_SamAV3_Cmd_SAM_PLExec(phhalHw_SamAV3_DataParams_t *pDataParams, uint8_t bLFI,
    uint8_t *pPLData,
    uint8_t bPLDataLen, uint8_t **ppPLResp, uint16_t *pPLRespLen)
{
  phStatus_t	PH_MEMLOC_REM wStatus = 0;
  uint8_t		PH_MEMLOC_REM aCmdBuf[PHHAL_HW_SAMAV3_ISO7816_HEADER_LENGTH];

  /* Vaildate the parameters. */
  PH_ASSERT_NULL_DATA_PARAM(pDataParams, PH_COMP_HAL);
  PH_ASSERT_NULL_PARAM(pPLData, PH_COMP_HAL);

  /* Reset the command buffer and its length. */
  memset(aCmdBuf, 0x00, sizeof(aCmdBuf));	/* PRQA S 3200 */

  /* Frame the command Cmd.SAM_PLExec. */
  aCmdBuf[PHHAL_HW_SAMAV3_ISO7816_CLA_POS] = PHHAL_HW_SAMAV3_ISO7816_CLA_BYTE;
  aCmdBuf[PHHAL_HW_SAMAV3_ISO7816_INS_POS] = PHHAL_HW_CMD_SAMAV3_PL_EXEC_INS;
  aCmdBuf[PHHAL_HW_SAMAV3_ISO7816_P1_POS]	 = bLFI;
  aCmdBuf[PHHAL_HW_SAMAV3_ISO7816_P2_POS]	 = PHHAL_HW_SAMAV3_ISO7816_DEFAULT_P2_BYTE;
  aCmdBuf[PHHAL_HW_SAMAV3_ISO7816_LC_POS]	 = bPLDataLen;

  /* Append Command data to exchange buffer. */
  PH_CHECK_SUCCESS_FCT(wStatus, phhalHw_SamAV3_Cmd_7816Exchange(
          pDataParams,
          PH_EXCHANGE_BUFFER_FIRST,
          aCmdBuf,
          PHHAL_HW_SAMAV3_ISO7816_HEADER_LENGTH,
          NULL,
          NULL));

  /* Append PLData to exchange buffer. */
  PH_CHECK_SUCCESS_FCT(wStatus, phhalHw_SamAV3_Cmd_7816Exchange(
          pDataParams,
          PH_EXCHANGE_BUFFER_CONT,
          pPLData,
          bPLDataLen,
          NULL,
          NULL));

  /* Append LE to exchange buffer. */
  wStatus = phhalHw_SamAV3_Cmd_7816Exchange(
          pDataParams,
          PH_EXCHANGE_BUFFER_LAST,
          gaDefaultLe,
          1,
          ppPLResp,
          pPLRespLen);

  /* Return the chaining code. */
  if ((wStatus & PH_ERR_MASK) == PHHAL_HW_SAMAV3_ERR_OK_CHAINING_ACTIVE) {
    return PH_ADD_COMPCODE(PH_ERR_SUCCESS_CHAINING, PH_COMP_HAL);
  }

  /* Return success response. */
  return PH_ADD_COMPCODE(PH_ERR_SUCCESS, PH_COMP_HAL);
}

phStatus_t
phhalHw_SamAV3_Cmd_SAM_PLUpload(phhalHw_SamAV3_DataParams_t *pDataParams, uint8_t bIsFirstFrame,
    uint8_t bIsFinalFrame,
    uint16_t wUploadCtr, uint8_t bKeyNo, uint8_t bKeyVer, uint8_t *pPLCode, uint16_t wPLCodeLen,
    uint8_t *pPLReKey, uint8_t bPLReKeyLen)
{
  phStatus_t	PH_MEMLOC_REM wStatus = 0;
  phStatus_t	PH_MEMLOC_REM wStatus1 = 0;
  uint8_t		PH_MEMLOC_REM aCmdBuf[256];
  uint8_t		PH_MEMLOC_REM bCmdLen = 0;
  uint8_t		PH_MEMLOC_REM bCmdBuffOffset = 0;
  uint8_t		PH_MEMLOC_REM bKeyType = 0;
  uint16_t	PH_MEMLOC_REM wPLCodeOffset = 0;
  uint16_t	PH_MEMLOC_REM wPLCodeChunks = 0;
  uint16_t	PH_MEMLOC_REM wRemPLCodeLen = 0;
  uint16_t	PH_MEMLOC_REM wIteration = 0;
  uint8_t		PH_MEMLOC_REM aSessionKey[PH_CRYPTOSYM_AES256_KEY_SIZE];
  uint8_t		PH_MEMLOC_REM aPLUploadReKey[PH_CRYPTOSYM_AES256_KEY_SIZE *
                                   PH_CRYPTOSYM_KEY_TYPE_AES256];
  uint8_t		PH_MEMLOC_REM aPLUploadMAC[16];
  uint8_t		PH_MEMLOC_REM aRespMAC[PH_CRYPTOSYM_AES128_KEY_SIZE];
  uint8_t		PH_MEMLOC_REM bMacLen = 0;
  uint8_t		*PH_MEMLOC_REM pResponse = NULL;
  uint16_t	PH_MEMLOC_REM wRespLen = 0;
  uint16_t	PH_MEMLOC_REM wFinalPaddLen = 0;
  uint16_t	PH_MEMLOC_REM wPaddOutLen = 0;

  /* Check memory is created for pPLCode. */
  PH_ASSERT_NULL_DATA_PARAM(pDataParams, PH_COMP_HAL);
  PH_ASSERT_NULL_PARAM(pPLCode, PH_COMP_HAL);
  if (!bIsFinalFrame) {
    PH_ASSERT_NULL_PARAM(pPLReKey, PH_COMP_HAL);
  }

  /* Compute the initial Session Keys and load them to crypto params. */
  if (bIsFirstFrame) {
    /* Get Session Upload ENC key. */
    PH_CHECK_SUCCESS_FCT(wStatus, phhalHw_SamAV3_Utils_GetSessionUploadKey(
            pDataParams,
            PHHAL_HW_CMD_SAMAV3_SESSION_KEY_ENC,
            wUploadCtr,
            bKeyNo,
            bKeyVer,
            aSessionKey,
            &bKeyType));

    /* Load the Session Upload ENC key to Crypto. */
    PH_CHECK_SUCCESS_FCT(wStatus, phCryptoSym_LoadKeyDirect(
            pDataParams->pPLUpload_ENCCryptoDataParams,
            aSessionKey,
            bKeyType));

    /* Get Session Upload MAC key. */
    PH_CHECK_SUCCESS_FCT(wStatus, phhalHw_SamAV3_Utils_GetSessionUploadKey(
            pDataParams,
            PHHAL_HW_CMD_SAMAV3_SESSION_KEY_MAC,
            wUploadCtr,
            bKeyNo,
            bKeyVer,
            aSessionKey,
            &bKeyType));

    /* Load the Session Upload MAC key to Crypto. */
    PH_CHECK_SUCCESS_FCT(wStatus, phCryptoSym_LoadKeyDirect(
            pDataParams->pPLUpload_MACCryptoDataParams,
            aSessionKey,
            bKeyType));

    /* Load the initial Session MAC key to internal dataparams. */
    memcpy(pDataParams->aPLUploadSessMAC0, aSessionKey,
        ((bKeyType == PH_CRYPTOSYM_KEY_TYPE_AES128) ? 16 :
            (bKeyType == PH_CRYPTOSYM_KEY_TYPE_AES192) ? 24 : 32));    /* PRQA S 3200 */

    /* Load Zero IV for both the Crypto dataparams. */
    PH_CHECK_SUCCESS_FCT(wStatus, phCryptoSym_LoadIv(
            pDataParams->pPLUpload_ENCCryptoDataParams,
            gaFirstIv,
            PH_CRYPTOSYM_AES_BLOCK_SIZE));

    PH_CHECK_SUCCESS_FCT(wStatus, phCryptoSym_LoadIv(
            pDataParams->pPLUpload_MACCryptoDataParams,
            gaFirstIv,
            PH_CRYPTOSYM_AES_BLOCK_SIZE));

    /* Set the KeepIV flag for both the dataparams. */
    PH_CHECK_SUCCESS_FCT(wStatus, phCryptoSym_SetConfig(
            pDataParams->pPLUpload_ENCCryptoDataParams,
            PH_CRYPTOSYM_CONFIG_KEEP_IV,
            PH_CRYPTOSYM_VALUE_KEEP_IV_ON));

    /* Update the KeyType. */
    pDataParams->bPLUploadKeyType = bKeyType;
  }

  /* Evaluate the PLCode chunks to be exchanged. */
  wPLCodeChunks = (uint16_t)(wPLCodeLen / 128);

  /* Set the remaining code length. */
  wRemPLCodeLen = wPLCodeLen;

  /* Update chunk count if PLCodeChunk is not 1 and not mulitple of 128. */
  if (!wPLCodeChunks || ((uint16_t)(wPLCodeLen % 128))) {
    wPLCodeChunks++;
  }

  /* Set the remaining code length to chunk size. */
  if (wPLCodeLen > 128) {
    wRemPLCodeLen = 128;
  }

  /* Exchagne the information. */
  for (wIteration = 0; wIteration < wPLCodeChunks; wIteration++) {
    /* Reset the command buffer and its length. */
    bCmdLen = 0;
    memset(aCmdBuf, 0x00, sizeof(aCmdBuf));	/* PRQA S 3200 */

    /* Frame the command Cmd.SAM_PLUpload. */
    aCmdBuf[bCmdLen++]	= PHHAL_HW_SAMAV3_ISO7816_CLA_BYTE;
    aCmdBuf[bCmdLen++]	= PHHAL_HW_CMD_SAMAV3_PL_UPLOAD_INS;
    aCmdBuf[bCmdLen++]	= 0xAF;	/* Chaining Frame. */
    aCmdBuf[bCmdLen++]	= 0x01; /* Crypto On-Going. */
    aCmdBuf[bCmdLen++]	= PHHAL_HW_SAMAV3_ISO7816_DEFAULT_LC_BYTE;

    /* Append the Upload_Ctr to command buffer if its first frame. */
    if (bIsFirstFrame && !wIteration) {
      /* Add Upload Counter value to command buffer. */
      aCmdBuf[bCmdLen++] = (uint8_t)((wUploadCtr & 0xFF00) >> 8);
      aCmdBuf[bCmdLen++] = (uint8_t)(wUploadCtr & 0x00FF);
    }

    /* Apply padding for the last chunk. */
    if ((wIteration + 1) == wPLCodeChunks) {
      /* Update the remaining PLCode data. */
      wRemPLCodeLen = (uint16_t)(wPLCodeLen - wPLCodeOffset);

      /* Compute the output padding length. */
      wPaddOutLen = (uint16_t)(wRemPLCodeLen + (16 - wRemPLCodeLen % 16));

      PH_CHECK_SUCCESS_FCT(wStatus, phCryptoSym_ApplyPadding(
              PH_CRYPTOSYM_PADDING_MODE_2,
              &pPLCode[wPLCodeOffset],
              wRemPLCodeLen,
              PH_CRYPTOSYM_AES_BLOCK_SIZE,
              wPaddOutLen,
              pPLCode,
              &wFinalPaddLen));

      /* Reset the Offset pointer. */
      wPLCodeOffset = 0;

      /* Update the remaining code length. */
      wRemPLCodeLen = (uint8_t) wFinalPaddLen;
    }

    /* Encrypt the PLUpload code. */
    PH_CHECK_SUCCESS_FCT(wStatus, phCryptoSym_Encrypt(
            pDataParams->pPLUpload_ENCCryptoDataParams,
            (PH_CRYPTOSYM_CIPHER_MODE_CBC | PH_EXCHANGE_DEFAULT),
            &pPLCode[wPLCodeOffset],
            wRemPLCodeLen,
            &aCmdBuf[bCmdLen]));

    /* Update the command buffer length. */
    bCmdLen += (uint8_t) wRemPLCodeLen;

    /* Compute PLUploadReKeys if its the last chunk and not the final segment. */
    if (((wIteration + 1) == wPLCodeChunks) && !bIsFinalFrame) {
      /* Encrypt the PLUpload code. */
      PH_CHECK_SUCCESS_FCT(wStatus, phCryptoSym_Encrypt(
              pDataParams->pPLUpload_ENCCryptoDataParams,
              (PH_CRYPTOSYM_CIPHER_MODE_CBC | PH_EXCHANGE_DEFAULT),
              pPLReKey,
              bPLReKeyLen,
              aPLUploadReKey));

      /* Buffer the aPLUploadReKey to Command buffer. */
      memcpy(&aCmdBuf[bCmdLen], aPLUploadReKey, bPLReKeyLen);    /* PRQA S 3200 */
      bCmdLen += (uint8_t) bPLReKeyLen;
    }

    /* Update the Offset */
    wPLCodeOffset += 128;

    /* Buffer the command information to exchange buffer. */
    PH_CHECK_SUCCESS_FCT(wStatus, phhalHw_SamAV3_Cmd_7816Exchange(
            pDataParams,
            PH_EXCHANGE_BUFFER_FIRST,
            aCmdBuf,
            bCmdLen,
            NULL,
            NULL));

    /* Copy the command information to PLUpload internal buffer. */
    memcpy(&pDataParams->pPLUploadBuf[pDataParams->wPLUploadBufLen], &aCmdBuf[bCmdBuffOffset],
        bCmdLen - bCmdBuffOffset);
    pDataParams->wPLUploadBufLen += (uint16_t)(bCmdLen - bCmdBuffOffset);

    /* Update the command buffer offset. */
    bCmdBuffOffset = PHHAL_HW_SAMAV3_ISO7816_HEADER_LENGTH;

    /* Exchange the command information if not the last frame. */
    if ((wIteration + 1) < wPLCodeChunks) {
      /* Update LC value. */
      PH_CHECK_SUCCESS_FCT(wStatus, phhalHw_SamAV3_Utils_UpdateLc(pDataParams));

      wStatus = phhalHw_SamAV3_Cmd_7816Exchange(
              pDataParams,
              PH_EXCHANGE_BUFFER_LAST,
              NULL,
              bMacLen,
              &pResponse,
              &wRespLen);

      /* Check if SUCCESS_CHAINING is returned. */
      if ((wStatus & PH_ERR_MASK) != PHHAL_HW_SAMAV3_ERR_OK_CHAINING_ACTIVE) {
        /* Reset the internal PLUpload length variable. */
        pDataParams->wPLUploadBufLen = 0;

        return wStatus;
      }
    }
  }

  /* Buffer LE to command buffer. */
  if (bIsFinalFrame) {
    pDataParams->pPLUploadBuf[pDataParams->wPLUploadBufLen++] = 0x00;
  }

  /* Reset the header bytes. */
  pDataParams->pPLUploadBuf[PHHAL_HW_SAMAV3_ISO7816_P1_POS] = 0x00;
  pDataParams->pPLUploadBuf[PHHAL_HW_SAMAV3_ISO7816_P2_POS] = 0x00;
  pDataParams->pPLUploadBuf[PHHAL_HW_SAMAV3_ISO7816_LC_POS] = 0x00;

  /* Buffer LE for PLUploadMAC computation. */
  PH_CHECK_SUCCESS_FCT(wStatus, phCryptoSym_CalculateMac(
          pDataParams->pPLUpload_MACCryptoDataParams,
          (PH_CRYPTOSYM_MAC_MODE_CMAC | PH_EXCHANGE_DEFAULT),
          pDataParams->pPLUploadBuf,
          pDataParams->wPLUploadBufLen,
          aPLUploadMAC,
          &bMacLen));

  /* Truncate the MAC. */
  PH_CHECK_SUCCESS_FCT(wStatus, phhalHw_SamAV3_Utils_TruncateMacBuffer(aPLUploadMAC, &bMacLen));

  /* Buffer the PLUpload MAC data. */
  PH_CHECK_SUCCESS_FCT(wStatus, phhalHw_SamAV3_Cmd_7816Exchange(
          pDataParams,
          PH_EXCHANGE_BUFFER_CONT,
          aPLUploadMAC,
          bMacLen,
          NULL,
          NULL));

  /* Update P1 information byte for Last frame. */
  if (bIsFinalFrame) {
    PH_CHECK_SUCCESS_FCT(wStatus, phhalHw_SamAV3_Utils_UpdateP1(pDataParams, 0x00));
  }

  /* Update P2 information to Crypto finalization and re-key. */
  PH_CHECK_SUCCESS_FCT(wStatus, phhalHw_SamAV3_Utils_UpdateP2(pDataParams, 0x00));

  /* Update LC value. */
  PH_CHECK_SUCCESS_FCT(wStatus, phhalHw_SamAV3_Utils_UpdateLc(pDataParams));

  /* Append LE if required and perform exchange to SAM hardware. */
  wStatus = phhalHw_SamAV3_Cmd_7816Exchange(
          pDataParams,
          PH_EXCHANGE_BUFFER_LAST,
          gaDefaultLe,
          bIsFinalFrame,
          &pResponse,
          &wRespLen);

  /* Clear the internal buffer and length variable. */
  memset(pDataParams->pPLUploadBuf, 0x00, pDataParams->wPLUploadBufLen);	/* PRQA S 3200 */
  pDataParams->wPLUploadBufLen = 0;

  /* Update the session keys with the new keys. */
  if (!bIsFinalFrame) {
    /* Load the new Session Upload ENC key to Crypto. */
    PH_CHECK_SUCCESS_FCT(wStatus1, phCryptoSym_LoadKeyDirect(
            pDataParams->pPLUpload_ENCCryptoDataParams,
            pPLReKey,
            pDataParams->bPLUploadKeyType));

    /* Load the new Session Upload MAC key to Crypto. */
    PH_CHECK_SUCCESS_FCT(wStatus1, phCryptoSym_LoadKeyDirect(
            pDataParams->pPLUpload_MACCryptoDataParams,
            &pPLReKey[bPLReKeyLen / 2],
            pDataParams->bPLUploadKeyType));
  }

  /* Check if SUCCESS_CHAINING is returned. */
  if ((wStatus & PH_ERR_MASK) == PHHAL_HW_SAMAV3_ERR_OK_CHAINING_ACTIVE) {
    return PH_ADD_COMPCODE(PH_ERR_SUCCESS_CHAINING, PH_COMP_HAL);
  }

  /* Compute MAC on Response and verify with the received one. */
  if (wStatus == PH_ADD_COMPCODE(PH_ERR_SUCCESS, PH_COMP_HAL) && bIsFinalFrame) {
    /* Reset the MAC response buffer and its length. */
    bMacLen = 0;
    memset(aRespMAC, 0x00, sizeof(aRespMAC));	/* PRQA S 3200 */

    /* Load the constant values and INS. */
    aRespMAC[bMacLen++] = (uint8_t)((PHHAL_HW_SAMAV3_RET_CODE_OK & 0xFF00) >> 8);
    aRespMAC[bMacLen++] = (uint8_t)(PHHAL_HW_SAMAV3_RET_CODE_OK & 0x00FF);
    aRespMAC[bMacLen++] = PHHAL_HW_CMD_SAMAV3_PL_UPLOAD_INS;

    aRespMAC[bMacLen++] = (uint8_t)((wUploadCtr & 0xFF00) >> 8);
    aRespMAC[bMacLen++] = (uint8_t)(wUploadCtr & 0x00FF);

    /* Append SAM UID to MAC computation buffer. */
    memcpy(&aRespMAC[bMacLen], pDataParams->bUid, 7);    /* PRQA S 3200 */
    bMacLen += (uint8_t) 7 /* Sam UID Length. */;

    /* Load the Session Upload MAC key to Crypto. */
    PH_CHECK_SUCCESS_FCT(wStatus, phCryptoSym_LoadKeyDirect(
            pDataParams->pPLUpload_MACCryptoDataParams,
            pDataParams->aPLUploadSessMAC0,
            pDataParams->bPLUploadKeyType));

    /* Buffer the Command buffer and UploadCtr (if available) for macing. */
    PH_CHECK_SUCCESS_FCT(wStatus, phCryptoSym_CalculateMac(
            pDataParams->pPLUpload_MACCryptoDataParams,
            (PH_CRYPTOSYM_MAC_MODE_CMAC | PH_EXCHANGE_DEFAULT),
            aRespMAC,
            bMacLen,
            aRespMAC,
            &bMacLen));

    /* Truncate the computed MAC. */
    PH_CHECK_SUCCESS_FCT(wStatus, phhalHw_SamAV3_Utils_TruncateMacBuffer(aRespMAC, &bMacLen));

    /* Compare the computed MAC with the one received in the response. */
    if (memcmp(aRespMAC, pResponse, PHHAL_HW_CMD_SAMAV3_TRUNCATED_MAC_SIZE) != 0x00) {
      return PH_ADD_COMPCODE(PH_ERR_INTEGRITY_ERROR, PH_COMP_HAL);
    }
  }

  return wStatus;
}

/*************************************************************************************************************************/
/****************************************************** Reader Chips *****************************************************/
/*************************************************************************************************************************/

phStatus_t
phhalHw_SamAV3_Cmd_RC_ReadRegister(phhalHw_SamAV3_DataParams_t *pDataParams, uint8_t *pRegAddr,
    uint8_t bRegAddrLen, uint8_t *pValue)
{
  phStatus_t	PH_MEMLOC_REM wStatus = 0;
  uint8_t		PH_MEMLOC_REM aCmdBuf[PHHAL_HW_SAMAV3_ISO7816_HEADER_LENGTH];
  uint8_t 	*PH_MEMLOC_REM pResponse = NULL;
  uint16_t	PH_MEMLOC_REM wRespLen = 0;
  uint16_t	PH_MEMLOC_REM wExpRespLen = 0;

  /* Calculate expected response lengths. */
  wExpRespLen = bRegAddrLen;

  /* Parameter validation. */
  PH_ASSERT_NULL_DATA_PARAM(pDataParams, PH_COMP_HAL);
  PH_ASSERT_NULL_PARAM(pRegAddr, PH_COMP_HAL);
  PH_ASSERT_NULL_PARAM(pValue, PH_COMP_HAL);

  /* Frame Cmd.RC_ReadRegister command information. */
  aCmdBuf[PHHAL_HW_SAMAV3_ISO7816_CLA_POS] = PHHAL_HW_SAMAV3_ISO7816_CLA_BYTE;
  aCmdBuf[PHHAL_HW_SAMAV3_ISO7816_INS_POS] = PHHAL_HW_SAMAV3_CMD_RC_READ_REGISTER_INS;
  aCmdBuf[PHHAL_HW_SAMAV3_ISO7816_P1_POS]  = PHHAL_HW_SAMAV3_ISO7816_DEFAULT_P1_BYTE;
  aCmdBuf[PHHAL_HW_SAMAV3_ISO7816_P2_POS]  = PHHAL_HW_SAMAV3_ISO7816_DEFAULT_P2_BYTE;
  aCmdBuf[PHHAL_HW_SAMAV3_ISO7816_LC_POS]  = bRegAddrLen;

  /* Buffer command information to exchange buffer. */
  PH_CHECK_SUCCESS_FCT(wStatus, phhalHw_SamAV3_Cmd_7816Exchange(
          pDataParams,
          PH_EXCHANGE_BUFFER_FIRST,
          aCmdBuf,
          PHHAL_HW_SAMAV3_ISO7816_HEADER_LENGTH,
          NULL,
          NULL));

  /* Buffer register information to exchange buffer. */
  PH_CHECK_SUCCESS_FCT(wStatus, phhalHw_SamAV3_Cmd_7816Exchange(
          pDataParams,
          PH_EXCHANGE_BUFFER_CONT,
          pRegAddr,
          bRegAddrLen,
          NULL,
          NULL));

  /* Buffer LE and exchange the bufferred information to SAM hardware. */
  PH_CHECK_SUCCESS_FCT(wStatus, phhalHw_SamAV3_Cmd_7816Exchange(
          pDataParams,
          PH_EXCHANGE_BUFFER_LAST,
          gaDefaultLe,
          1,
          &pResponse,
          &wRespLen));

  if (wRespLen != wExpRespLen) {
    return PH_ADD_COMPCODE(PH_ERR_LENGTH_ERROR, PH_COMP_HAL);
  }

  /* Copy the response to the parameter. */
  memcpy(pValue, pResponse, wRespLen);   /* PRQA S 3200 */

  return PH_ADD_COMPCODE(PH_ERR_SUCCESS, PH_COMP_HAL);
}

phStatus_t
phhalHw_SamAV3_Cmd_RC_WriteRegister(phhalHw_SamAV3_DataParams_t *pDataParams, uint8_t *pData,
    uint8_t bDataLen)
{
  phStatus_t	PH_MEMLOC_REM wStatus = 0;
  uint8_t		PH_MEMLOC_REM aCmdBuf[PHHAL_HW_SAMAV3_ISO7816_HEADER_LENGTH];
  uint8_t 	*PH_MEMLOC_REM pResponse = NULL;
  uint16_t	PH_MEMLOC_REM wRespLen = 0;

  /* Parameter validation. */
  PH_ASSERT_NULL_DATA_PARAM(pDataParams, PH_COMP_HAL);
  PH_ASSERT_NULL_PARAM(pData, PH_COMP_HAL);

  /* Frame Cmd.RC_WriteRegister command information. */
  aCmdBuf[PHHAL_HW_SAMAV3_ISO7816_CLA_POS] = PHHAL_HW_SAMAV3_ISO7816_CLA_BYTE;
  aCmdBuf[PHHAL_HW_SAMAV3_ISO7816_INS_POS] = PHHAL_HW_SAMAV3_CMD_RC_WRITE_REGISTER_INS;
  aCmdBuf[PHHAL_HW_SAMAV3_ISO7816_P1_POS]  = PHHAL_HW_SAMAV3_ISO7816_DEFAULT_P1_BYTE;
  aCmdBuf[PHHAL_HW_SAMAV3_ISO7816_P2_POS]  = PHHAL_HW_SAMAV3_ISO7816_DEFAULT_P2_BYTE;
  aCmdBuf[PHHAL_HW_SAMAV3_ISO7816_LC_POS]  = bDataLen;

  /* Buffer Command information to exchange buffer. */
  PH_CHECK_SUCCESS_FCT(wStatus, phhalHw_SamAV3_Cmd_7816Exchange(
          pDataParams,
          PH_EXCHANGE_BUFFER_FIRST,
          aCmdBuf,
          PHHAL_HW_SAMAV3_ISO7816_HEADER_LENGTH,
          NULL,
          NULL));

  /* Buffer Data and exchange the bufferred information to SAM hardware. */
  PH_CHECK_SUCCESS_FCT(wStatus, phhalHw_SamAV3_Cmd_7816Exchange(
          pDataParams,
          PH_EXCHANGE_BUFFER_LAST,
          pData,
          bDataLen,
          &pResponse,
          &wRespLen));

  if (wRespLen != 0x00) {
    return PH_ADD_COMPCODE(PH_ERR_LENGTH_ERROR, PH_COMP_HAL);
  }

  return PH_ADD_COMPCODE(PH_ERR_SUCCESS, PH_COMP_HAL);
}

phStatus_t
phhalHw_SamAV3_Cmd_RC_RFControl(phhalHw_SamAV3_DataParams_t *pDataParams, uint16_t wTime)
{
  phStatus_t	PH_MEMLOC_REM wStatus = 0;
  uint8_t		PH_MEMLOC_REM aCmdBuf[PHHAL_HW_SAMAV3_ISO7816_HEADER_LENGTH + 2 /* Time */ ];
  uint8_t		PH_MEMLOC_REM bCmdLen = 0;
  uint8_t 	*PH_MEMLOC_REM pResponse = NULL;
  uint16_t	PH_MEMLOC_REM wRespLen = 0;

  /* Parameter validation. */
  PH_ASSERT_NULL_DATA_PARAM(pDataParams, PH_COMP_HAL);

  /* Frame Cmd.RC_RFControl command information. */
  aCmdBuf[bCmdLen++] = PHHAL_HW_SAMAV3_ISO7816_CLA_BYTE;
  aCmdBuf[bCmdLen++] = PHHAL_HW_SAMAV3_CMD_RC_RF_CONTROL_INS;
  aCmdBuf[bCmdLen++] = PHHAL_HW_SAMAV3_ISO7816_DEFAULT_P1_BYTE;
  aCmdBuf[bCmdLen++] = PHHAL_HW_SAMAV3_ISO7816_DEFAULT_P2_BYTE;
  aCmdBuf[bCmdLen++] = 0x02;

  /* Add the time information to command buffer. */
  aCmdBuf[bCmdLen++] = (uint8_t)(wTime);
  aCmdBuf[bCmdLen++] = (uint8_t)(wTime >> 8);

  /* Exchange the command information to Sam hardware. */
  PH_CHECK_SUCCESS_FCT(wStatus, phhalHw_SamAV3_Cmd_7816Exchange(
          pDataParams,
          PH_EXCHANGE_DEFAULT,
          aCmdBuf,
          bCmdLen,
          &pResponse,
          &wRespLen));

  return PH_ADD_COMPCODE(PH_ERR_SUCCESS, PH_COMP_HAL);
}

phStatus_t
phhalHw_SamAV3_Cmd_RC_Init(phhalHw_SamAV3_DataParams_t *pDataParams, uint8_t bLoadReg)
{
  phStatus_t	PH_MEMLOC_REM wStatus = 0;
  uint8_t		PH_MEMLOC_REM aCmdBuf[PHHAL_HW_SAMAV3_ISO7816_HEADER_NO_LC_LENGTH];
  uint8_t 	*PH_MEMLOC_REM pResponse = NULL;
  uint16_t	PH_MEMLOC_REM wRespLen = 0;

  /* Parameter validation. */
  PH_ASSERT_NULL_DATA_PARAM(pDataParams, PH_COMP_HAL);

  /* Frame Cmd.RC_Init command information. */
  aCmdBuf[PHHAL_HW_SAMAV3_ISO7816_CLA_POS] = PHHAL_HW_SAMAV3_ISO7816_CLA_BYTE;
  aCmdBuf[PHHAL_HW_SAMAV3_ISO7816_INS_POS] = PHHAL_HW_SAMAV3_CMD_RC_INIT_INS;
  aCmdBuf[PHHAL_HW_SAMAV3_ISO7816_P1_POS]  = bLoadReg;
  aCmdBuf[PHHAL_HW_SAMAV3_ISO7816_P2_POS]  = PHHAL_HW_SAMAV3_ISO7816_DEFAULT_P2_BYTE;

  /* Exchange command information to Sam hardware. */
  PH_CHECK_SUCCESS_FCT(wStatus, phhalHw_SamAV3_Cmd_7816Exchange(
          pDataParams,
          PH_EXCHANGE_DEFAULT,
          aCmdBuf,
          PHHAL_HW_SAMAV3_ISO7816_HEADER_NO_LC_LENGTH,
          &pResponse,
          &wRespLen));

  if (wRespLen != 0x00) {
    return PH_ADD_COMPCODE(PH_ERR_LENGTH_ERROR, PH_COMP_HAL);
  }

  return PH_ADD_COMPCODE(PH_ERR_SUCCESS, PH_COMP_HAL);
}

phStatus_t
phhalHw_SamAV3_Cmd_RC_LoadRegisterValueSet(phhalHw_SamAV3_DataParams_t *pDataParams,
    uint8_t bStoreReg, uint8_t *pData, uint8_t bDataLen)
{
  phStatus_t	PH_MEMLOC_REM wStatus = 0;
  uint8_t		PH_MEMLOC_REM aCmdBuf[PHHAL_HW_SAMAV3_ISO7816_HEADER_LENGTH];
  uint8_t 	*PH_MEMLOC_REM pResponse = NULL;
  uint16_t	PH_MEMLOC_REM wRespLen = 0;

  /* Parameter validation. */
  PH_ASSERT_NULL_DATA_PARAM(pDataParams, PH_COMP_HAL);
  PH_ASSERT_NULL_PARAM(pData, PH_COMP_HAL);

  /* Frame Cmd.RC_LoadRegisterValueSet command information. */
  aCmdBuf[PHHAL_HW_SAMAV3_ISO7816_CLA_POS] = PHHAL_HW_SAMAV3_ISO7816_CLA_BYTE;
  aCmdBuf[PHHAL_HW_SAMAV3_ISO7816_INS_POS] = PHHAL_HW_SAMAV3_CMD_RC_LOAD_REGISTER_VALUE_SET_INS;
  aCmdBuf[PHHAL_HW_SAMAV3_ISO7816_P1_POS]  = bStoreReg;
  aCmdBuf[PHHAL_HW_SAMAV3_ISO7816_P2_POS]  = PHHAL_HW_SAMAV3_ISO7816_DEFAULT_P2_BYTE;
  aCmdBuf[PHHAL_HW_SAMAV3_ISO7816_LC_POS]  = bDataLen;

  /* Buffer command information to exchange buffer. */
  PH_CHECK_SUCCESS_FCT(wStatus, phhalHw_SamAV3_Cmd_7816Exchange(
          pDataParams,
          PH_EXCHANGE_BUFFER_FIRST,
          aCmdBuf,
          PHHAL_HW_SAMAV3_ISO7816_HEADER_LENGTH,
          NULL,
          NULL));

  /* Buffer Data information and exchange the bufferred information to Sam hardware. */
  PH_CHECK_SUCCESS_FCT(wStatus, phhalHw_SamAV3_Cmd_7816Exchange(
          pDataParams,
          PH_EXCHANGE_BUFFER_LAST,
          pData,
          bDataLen,
          &pResponse,
          &wRespLen));

  if (wRespLen != 0x00) {
    return PH_ADD_COMPCODE(PH_ERR_LENGTH_ERROR, PH_COMP_HAL);
  }

  return PH_ADD_COMPCODE(PH_ERR_SUCCESS, PH_COMP_HAL);
}

/*************************************************************************************************************************/
/****************************************************** ISO14443-3 *******************************************************/
/*************************************************************************************************************************/

phStatus_t
phhalHw_SamAV3_Cmd_X_ISO14443_3_RequestA_Wakeup(phhalHw_SamAV3_DataParams_t *pDataParams,
    uint8_t bCmdCode, uint8_t *pAtqa)
{
  phStatus_t	PH_MEMLOC_REM wStatus = 0;
  uint8_t		PH_MEMLOC_REM aCmdBuf[PHHAL_HW_SAMAV3_ISO7816_HEADER_LENGTH +
                                            2 /* Command Code, LE byte */];
  uint8_t		PH_MEMLOC_REM bCmdLen = 0;
  uint8_t 	*PH_MEMLOC_REM pResponse = NULL;
  uint16_t	PH_MEMLOC_REM wRespLen = 0;

  /* Parameter validation. */
  PH_ASSERT_NULL_DATA_PARAM(pDataParams, PH_COMP_HAL);
  PH_ASSERT_NULL_PARAM(pAtqa, PH_COMP_HAL);

  /* Frame Cmd.ISO14443-3_Request_Wakeup command information. */
  aCmdBuf[bCmdLen++] = PHHAL_HW_SAMAV3_ISO7816_CLA_BYTE;
  aCmdBuf[bCmdLen++] = PHHAL_HW_SAMAV3_CMD_ISO14443_3_REQUEST_WAKEUP_INS;
  aCmdBuf[bCmdLen++] = PHHAL_HW_SAMAV3_ISO7816_DEFAULT_P1_BYTE;
  aCmdBuf[bCmdLen++] = PHHAL_HW_SAMAV3_ISO7816_DEFAULT_P2_BYTE;
  aCmdBuf[bCmdLen++] = 1;

  /* Add the ISO14443-3 command code to command buffer. */
  aCmdBuf[bCmdLen++] = bCmdCode;

  /* Add LE to command buffer. */
  aCmdBuf[bCmdLen++] = PHHAL_HW_SAMAV3_ISO7816_DEFAULT_LE_BYTE;

  /* Exchange command information to SAM hardware. */
  PH_CHECK_SUCCESS_FCT(wStatus, phhalHw_SamAV3_Cmd_7816Exchange(
          pDataParams,
          PH_EXCHANGE_DEFAULT,
          aCmdBuf,
          bCmdLen,
          &pResponse,
          &wRespLen));

  /* Finally we can copy the ATQA */
  memcpy(pAtqa, pResponse, 2);  /* PRQA S 3200 */

  return PH_ADD_COMPCODE(PH_ERR_SUCCESS, PH_COMP_HAL);
}

phStatus_t
phhalHw_SamAV3_Cmd_X_ISO14443_3_AnticollisionSelect(phhalHw_SamAV3_DataParams_t *pDataParams,
    uint8_t *pSelCodes, uint8_t bSelCodesLen,
    uint8_t *pSak, uint8_t *pUid, uint8_t *pUidLen)
{
  phStatus_t	PH_MEMLOC_REM wStatus = 0;
  uint8_t		PH_MEMLOC_REM aCmdBuf[PHHAL_HW_SAMAV3_ISO7816_HEADER_LENGTH];
  uint8_t 	*PH_MEMLOC_REM pResponse = NULL;
  uint16_t	PH_MEMLOC_REM wRespLen = 0;

  /* Parameter validation. */
  PH_ASSERT_NULL_DATA_PARAM(pDataParams, PH_COMP_HAL);
  PH_ASSERT_NULL_PARAM(pSelCodes, PH_COMP_HAL);
  PH_ASSERT_NULL_PARAM(pSak, PH_COMP_HAL);
  PH_ASSERT_NULL_PARAM(pUid, PH_COMP_HAL);
  PH_ASSERT_NULL_PARAM(pUidLen, PH_COMP_HAL);

  /* Frame Cmd.ISO14443-3_Anticollision_Select command information. */
  aCmdBuf[PHHAL_HW_SAMAV3_ISO7816_CLA_POS] = PHHAL_HW_SAMAV3_ISO7816_CLA_BYTE;
  aCmdBuf[PHHAL_HW_SAMAV3_ISO7816_INS_POS] = PHHAL_HW_SAMAV3_CMD_ISO14443_3_ANTICOLLSION_SELECT_INS;
  aCmdBuf[PHHAL_HW_SAMAV3_ISO7816_P1_POS]  = PHHAL_HW_SAMAV3_ISO7816_DEFAULT_P1_BYTE;
  aCmdBuf[PHHAL_HW_SAMAV3_ISO7816_P2_POS]  = PHHAL_HW_SAMAV3_ISO7816_DEFAULT_P2_BYTE;
  aCmdBuf[PHHAL_HW_SAMAV3_ISO7816_LC_POS]  = PHHAL_HW_SAMAV3_ISO7816_DEFAULT_LC_BYTE;

  /* Buffer command information to exchange buffer. */
  PH_CHECK_SUCCESS_FCT(wStatus, phhalHw_SamAV3_Cmd_7816Exchange(
          pDataParams,
          PH_EXCHANGE_BUFFER_FIRST,
          aCmdBuf,
          PHHAL_HW_SAMAV3_ISO7816_HEADER_LENGTH,
          NULL,
          NULL));

  /* Buffer selection codes to exchange buffer. */
  PH_CHECK_SUCCESS_FCT(wStatus, phhalHw_SamAV3_Cmd_7816Exchange(
          pDataParams,
          PH_EXCHANGE_BUFFER_CONT,
          pSelCodes,
          bSelCodesLen,
          NULL,
          NULL));

  /* Update LC. */
  PH_CHECK_SUCCESS_FCT(wStatus, phhalHw_SamAV3_Utils_UpdateLc(pDataParams));

  /* Buffer LE and exchange the bufferred information to SAM hardware. */
  wStatus = phhalHw_SamAV3_Cmd_7816Exchange(
          pDataParams,
          PH_EXCHANGE_BUFFER_LAST,
          gaDefaultLe,
          1,
          &pResponse,
          &wRespLen);

  if ((wStatus & PH_ERR_MASK) != PHHAL_HW_SAMAV3_ERR_ISO_UID_INCOMPLETE &&
      (wStatus & PH_ERR_MASK) != PH_ERR_SUCCESS) {
    return wStatus;
  }

  /* Extract the SAK information. */
  *pSak = pResponse[0];

  /* Extract the UID information and its length. */
  *pUidLen = (uint8_t)(wRespLen - 1);
  memcpy(pUid, &pResponse[1], *pUidLen);  /* PRQA S 3200 */

  return wStatus;
}

phStatus_t
phhalHw_SamAV3_Cmd_X_ISO14443_3_ActivateIdle(phhalHw_SamAV3_DataParams_t *pDataParams,
    uint8_t bOption, uint8_t bNumCards, uint16_t wTime,
    uint8_t *pAtqaIn, uint8_t *pSakIn, uint8_t **ppResponse, uint16_t *pRespLen)
{
  phStatus_t	PH_MEMLOC_REM wStatus = 0;
  uint8_t		PH_MEMLOC_REM aCmdBuf[13];
  uint8_t		PH_MEMLOC_REM bCmdLen = 0;

  /* Parameter validation. */
  PH_ASSERT_NULL_DATA_PARAM(pDataParams, PH_COMP_HAL);
  if (bOption & PHHAL_HW_SAMAV3_CMD_ISO14443_3_ACTIVATEIDLE_APPLY_ATQA) {
    PH_ASSERT_NULL_PARAM(pAtqaIn, PH_COMP_HAL);
  }
  if (bOption & PHHAL_HW_SAMAV3_CMD_ISO14443_3_ACTIVATEIDLE_APPLY_SAK) {
    PH_ASSERT_NULL_PARAM(pSakIn, PH_COMP_HAL);
  }
  PH_ASSERT_NULL_PARAM(pRespLen, PH_COMP_HAL);

  /* Frame Cmd.ISO14443-3_ActivateIdle command information. */
  aCmdBuf[bCmdLen++] = PHHAL_HW_SAMAV3_ISO7816_CLA_BYTE;
  aCmdBuf[bCmdLen++] = PHHAL_HW_SAMAV3_CMD_ISO14443_3_ACTIVATE_IDLE_INS;
  aCmdBuf[bCmdLen++] = bNumCards;
  aCmdBuf[bCmdLen++] = (uint8_t)(bOption & 0x03);

  /* Add default LC byte if there is payload data. */
  if (bOption) {
    aCmdBuf[bCmdLen++] = PHHAL_HW_SAMAV3_ISO7816_DEFAULT_LC_BYTE;
  }

  /* Add Time information to command buffer. */
  if (bOption & PHHAL_HW_SAMAV3_CMD_ISO14443_3_ACTIVATEIDLE_APPLY_TIME) {
    aCmdBuf[bCmdLen++] = (uint8_t)(wTime >> 8);
    aCmdBuf[bCmdLen++] = (uint8_t)(wTime);
  }

  /* Add AtqA filter information to command buffer. */
  if (bOption & PHHAL_HW_SAMAV3_CMD_ISO14443_3_ACTIVATEIDLE_APPLY_ATQA) {
    aCmdBuf[bCmdLen++] = pAtqaIn[0];
    aCmdBuf[bCmdLen++] = pAtqaIn[1];
    aCmdBuf[bCmdLen++] = pAtqaIn[2];
    aCmdBuf[bCmdLen++] = pAtqaIn[3];
  }

  /* Add SAK filter information to command buffer. */
  if (bOption & PHHAL_HW_SAMAV3_CMD_ISO14443_3_ACTIVATEIDLE_APPLY_SAK) {
    aCmdBuf[bCmdLen++] = pSakIn[0];
    aCmdBuf[bCmdLen++] = pSakIn[1];
  }

  /* Buffer command information to SAM hardware. */
  PH_CHECK_SUCCESS_FCT(wStatus, phhalHw_SamAV3_Cmd_7816Exchange(
          pDataParams,
          PH_EXCHANGE_BUFFER_FIRST,
          aCmdBuf,
          bCmdLen,
          NULL,
          NULL));

  /* Recalculate the LC information. */
  if (bOption) {
    PH_CHECK_SUCCESS_FCT(wStatus, phhalHw_SamAV3_Utils_UpdateLc(pDataParams));
  }

  /* Exchange command information to SAM hardware. */
  PH_CHECK_SUCCESS_FCT(wStatus, phhalHw_SamAV3_Cmd_7816Exchange(
          pDataParams,
          PH_EXCHANGE_BUFFER_LAST,
          gaDefaultLe,
          1,
          ppResponse,
          pRespLen));

  return PH_ADD_COMPCODE(PH_ERR_SUCCESS, PH_COMP_HAL);
}

phStatus_t
phhalHw_SamAV3_Cmd_X_ISO14443_3_ActivateWakeUp(phhalHw_SamAV3_DataParams_t *pDataParams,
    uint8_t  *pUid, uint8_t bUidLen)
{
  phStatus_t	PH_MEMLOC_REM wStatus = 0;
  uint8_t		PH_MEMLOC_REM aCmdBuf[PHHAL_HW_SAMAV3_ISO7816_HEADER_LENGTH];
  uint8_t 	*PH_MEMLOC_REM pResponse = NULL;
  uint16_t	PH_MEMLOC_REM wRespLen = 0;

  /* Parameter validation. */
  PH_ASSERT_NULL_DATA_PARAM(pDataParams, PH_COMP_HAL);
  PH_ASSERT_NULL_PARAM(pUid, PH_COMP_HAL);

  /* Frame Cmd.ISO14443-3_ActivateWakeup command information. */
  aCmdBuf[PHHAL_HW_SAMAV3_ISO7816_CLA_POS] = PHHAL_HW_SAMAV3_ISO7816_CLA_BYTE;
  aCmdBuf[PHHAL_HW_SAMAV3_ISO7816_INS_POS] = PHHAL_HW_SAMAV3_CMD_ISO14443_3_ACTIVATE_WAKEUP_INS;
  aCmdBuf[PHHAL_HW_SAMAV3_ISO7816_P1_POS]  = PHHAL_HW_SAMAV3_ISO7816_DEFAULT_P1_BYTE;
  aCmdBuf[PHHAL_HW_SAMAV3_ISO7816_P2_POS]  = PHHAL_HW_SAMAV3_ISO7816_DEFAULT_P2_BYTE;
  aCmdBuf[PHHAL_HW_SAMAV3_ISO7816_LC_POS]  = bUidLen;

  /* Buffer command information to exchange buffer. */
  PH_CHECK_SUCCESS_FCT(wStatus, phhalHw_SamAV3_Cmd_7816Exchange(
          pDataParams,
          PH_EXCHANGE_BUFFER_FIRST,
          aCmdBuf,
          PHHAL_HW_SAMAV3_ISO7816_HEADER_LENGTH,
          NULL,
          NULL));

  /* Buffer UID and exchange the bufferred information to SAM hardware. */
  PH_CHECK_SUCCESS_FCT(wStatus, phhalHw_SamAV3_Cmd_7816Exchange(
          pDataParams,
          PH_EXCHANGE_BUFFER_LAST,
          pUid,
          bUidLen,
          &pResponse,
          &wRespLen));

  return PH_ADD_COMPCODE(PH_ERR_SUCCESS, PH_COMP_HAL);
}

phStatus_t
phhalHw_SamAV3_Cmd_X_ISO14443_3_HaltA(phhalHw_SamAV3_DataParams_t *pDataParams)
{
  phStatus_t	PH_MEMLOC_REM wStatus = 0;
  uint8_t		PH_MEMLOC_REM aCmdBuf[PHHAL_HW_SAMAV3_ISO7816_HEADER_NO_LC_LENGTH];
  uint8_t 	*PH_MEMLOC_REM pResponse = NULL;
  uint16_t	PH_MEMLOC_REM wRespLen = 0;

  /* Parameter validation. */
  PH_ASSERT_NULL_DATA_PARAM(pDataParams, PH_COMP_HAL);

  /* Frame Cmd.ISO14443-3_HaltA command information. */
  aCmdBuf[PHHAL_HW_SAMAV3_ISO7816_CLA_POS] = PHHAL_HW_SAMAV3_ISO7816_CLA_BYTE;
  aCmdBuf[PHHAL_HW_SAMAV3_ISO7816_INS_POS] = PHHAL_HW_SAMAV3_CMD_ISO14443_3_HALTA_INS;
  aCmdBuf[PHHAL_HW_SAMAV3_ISO7816_P1_POS]  = PHHAL_HW_SAMAV3_ISO7816_DEFAULT_P1_BYTE;
  aCmdBuf[PHHAL_HW_SAMAV3_ISO7816_P2_POS]  = PHHAL_HW_SAMAV3_ISO7816_DEFAULT_P2_BYTE;

  /* Exchange command information to SAM hardware. */
  PH_CHECK_SUCCESS_FCT(wStatus, phhalHw_SamAV3_Cmd_7816Exchange(
          pDataParams,
          PH_EXCHANGE_DEFAULT,
          aCmdBuf,
          PHHAL_HW_SAMAV3_ISO7816_HEADER_NO_LC_LENGTH,
          &pResponse,
          &wRespLen));

  return PH_ADD_COMPCODE(PH_ERR_SUCCESS, PH_COMP_HAL);
}

phStatus_t
phhalHw_SamAV3_Cmd_X_ISO14443_3_TransparentExchange(phhalHw_SamAV3_DataParams_t *pDataParams,
    uint8_t *pTxBuf, uint8_t bTxLen,
    uint8_t bTxBitLen, uint8_t **ppRxBuf, uint16_t *pRxLen, uint8_t *pRxBitLen)
{
  phStatus_t	PH_MEMLOC_REM wStatus = 0;
  uint8_t		PH_MEMLOC_REM aCmdBuf[PHHAL_HW_SAMAV3_ISO7816_HEADER_LENGTH];

  /* Parameter validation. */
  PH_ASSERT_NULL_DATA_PARAM(pDataParams, PH_COMP_HAL);
  PH_ASSERT_NULL_PARAM(pTxBuf, PH_COMP_HAL);
  PH_ASSERT_NULL_PARAM(pRxLen, PH_COMP_HAL);
  PH_ASSERT_NULL_PARAM(pRxBitLen, PH_COMP_HAL);

  /* Reset response length */
  *pRxLen = 0;

  /* Frame Cmd.ISO14443-3_TransparentExchange command information. */
  aCmdBuf[PHHAL_HW_SAMAV3_ISO7816_CLA_POS] = PHHAL_HW_SAMAV3_ISO7816_CLA_BYTE;
  aCmdBuf[PHHAL_HW_SAMAV3_ISO7816_INS_POS] =
      PHHAL_HW_SAMAV3_CMD_ISO14443_3_TRANSPARENT_EXCHANGE_INS;
  aCmdBuf[PHHAL_HW_SAMAV3_ISO7816_P1_POS]  = bTxBitLen;
  aCmdBuf[PHHAL_HW_SAMAV3_ISO7816_P2_POS]  = PHHAL_HW_SAMAV3_ISO7816_DEFAULT_P2_BYTE;
  aCmdBuf[PHHAL_HW_SAMAV3_ISO7816_LC_POS]  = bTxLen;

  /* Buffer the command information to exchange buffer. */
  PH_CHECK_SUCCESS_FCT(wStatus, phhalHw_SamAV3_Cmd_7816Exchange(
          pDataParams,
          PH_EXCHANGE_BUFFER_FIRST,
          aCmdBuf,
          PHHAL_HW_SAMAV3_ISO7816_HEADER_LENGTH,
          NULL,
          NULL));

  /* Buffer data information to exchange buffer. */
  PH_CHECK_SUCCESS_FCT(wStatus, phhalHw_SamAV3_Cmd_7816Exchange(
          pDataParams,
          PH_EXCHANGE_BUFFER_CONT,
          pTxBuf,
          bTxLen,
          NULL,
          NULL));

  /* Buffer LEl and exchange the bufferred information to SAM hardware. */
  wStatus = phhalHw_SamAV3_Cmd_7816Exchange(
          pDataParams,
          PH_EXCHANGE_BUFFER_LAST,
          gaDefaultLe,
          1,
          ppRxBuf,
          pRxLen);

  /* Check for incomplete byte status code. */
  if ((wStatus & PH_ERR_MASK) != PH_ERR_SUCCESS_INCOMPLETE_BYTE) {
    PH_CHECK_SUCCESS(wStatus);
    *pRxBitLen = 0;
  } else {
    *pRxBitLen = (uint8_t) pDataParams->wAdditionalInfo;
  }

  /* Check length */
  if (*pRxLen > PHHAL_HW_SAMAV3_ISO7816_EXCHANGE_RESPONSE_MAX) {
    return PH_ADD_COMPCODE(PH_ERR_LENGTH_ERROR, PH_COMP_HAL);
  }

  return wStatus;
}

/*************************************************************************************************************************/
/****************************************************** ISO14443-4 *******************************************************/
/*************************************************************************************************************************/

phStatus_t
phhalHw_SamAV3_Cmd_X_ISO14443_4_RATS_PPS(phhalHw_SamAV3_DataParams_t *pDataParams, uint8_t bCidIn,
    uint8_t bDsiIn, uint8_t bDriIn,
    uint8_t *pCidOut, uint8_t *pDsiOut, uint8_t *pDriOut, uint8_t *pAts)
{
  phStatus_t	PH_MEMLOC_REM wStatus = 0;
  uint8_t		PH_MEMLOC_REM aCmdBuf[PHHAL_HW_SAMAV3_ISO7816_HEADER_LE_LENGTH + 3 /* CID, DRI, DSI */];
  uint8_t		PH_MEMLOC_REM bCmdLen = 0;
  uint8_t 	*PH_MEMLOC_REM pResponse = NULL;
  uint16_t	PH_MEMLOC_REM wRespLen = 0;

  /* Parameter validation. */
  PH_ASSERT_NULL_DATA_PARAM(pDataParams, PH_COMP_HAL);
  PH_ASSERT_NULL_PARAM(pCidOut, PH_COMP_HAL);
  PH_ASSERT_NULL_PARAM(pDsiOut, PH_COMP_HAL);
  PH_ASSERT_NULL_PARAM(pDriOut, PH_COMP_HAL);
  PH_ASSERT_NULL_PARAM(pAts, PH_COMP_HAL);

  /* Frame Cmd.ISO14443-4_RATS_PPS command information. */
  aCmdBuf[bCmdLen++] = PHHAL_HW_SAMAV3_ISO7816_CLA_BYTE;
  aCmdBuf[bCmdLen++] = PHHAL_HW_SAMAV3_CMD_ISO14443_4_RATS_PPS_INS;
  aCmdBuf[bCmdLen++] = PHHAL_HW_SAMAV3_ISO7816_DEFAULT_P1_BYTE;
  aCmdBuf[bCmdLen++] = PHHAL_HW_SAMAV3_ISO7816_DEFAULT_P2_BYTE;
  aCmdBuf[bCmdLen++] = 3;

  /* Add the payload information to command buffer. */
  aCmdBuf[bCmdLen++] = bCidIn;
  aCmdBuf[bCmdLen++] = bDriIn;
  aCmdBuf[bCmdLen++] = bDsiIn;

  /* Add LE to command buffer. */
  aCmdBuf[bCmdLen++] = PHHAL_HW_SAMAV3_ISO7816_DEFAULT_LE_BYTE;

  /* Exchange command information to SAM hardware. */
  PH_CHECK_SUCCESS_FCT(wStatus, phhalHw_SamAV3_Cmd_7816Exchange(
          pDataParams,
          PH_EXCHANGE_DEFAULT,
          aCmdBuf,
          bCmdLen,
          &pResponse,
          &wRespLen));

  *pCidOut = pResponse[0];
  *pDriOut = pResponse[1];
  *pDsiOut = pResponse[2];

  /* Copy the ATS information. */
  memcpy(pAts, &pResponse[3], wRespLen - 3);  /* PRQA S 3200 */

  return PH_ADD_COMPCODE(PH_ERR_SUCCESS, PH_COMP_HAL);
}

phStatus_t
phhalHw_SamAV3_Cmd_X_ISO14443_4_Init(phhalHw_SamAV3_DataParams_t *pDataParams, uint8_t bCid,
    uint8_t bDri, uint8_t bDsi, uint8_t bFwi,
    uint8_t bFsci)
{
  phStatus_t	PH_MEMLOC_REM wStatus = 0;
  uint8_t		PH_MEMLOC_REM aCmdBuf[PHHAL_HW_SAMAV3_ISO7816_HEADER_LENGTH +
                                            5 /* CID, DRI, DSI, FWI, FSCI */];
  uint8_t		PH_MEMLOC_REM bCmdLen = 0;
  uint8_t 	*PH_MEMLOC_REM pResponse = NULL;
  uint16_t	PH_MEMLOC_REM wRespLen = 0;

  /* Parameter validation. */
  PH_ASSERT_NULL_DATA_PARAM(pDataParams, PH_COMP_HAL);

  /* Frame Cmd.ISO14443-4_Init command information. */
  aCmdBuf[bCmdLen++] = PHHAL_HW_SAMAV3_ISO7816_CLA_BYTE;
  aCmdBuf[bCmdLen++] = PHHAL_HW_SAMAV3_CMD_ISO14443_4_INIT_INS;
  aCmdBuf[bCmdLen++] = PHHAL_HW_SAMAV3_ISO7816_DEFAULT_P1_BYTE;
  aCmdBuf[bCmdLen++] = PHHAL_HW_SAMAV3_ISO7816_DEFAULT_P2_BYTE;
  aCmdBuf[bCmdLen++] = 5;
  aCmdBuf[bCmdLen++] = bCid;
  aCmdBuf[bCmdLen++] = bDri;
  aCmdBuf[bCmdLen++] = bDsi;
  aCmdBuf[bCmdLen++] = bFwi;
  aCmdBuf[bCmdLen++] = bFsci;

  /* Exchange command information to SAM hardware. */
  PH_CHECK_SUCCESS_FCT(wStatus, phhalHw_SamAV3_Cmd_7816Exchange(
          pDataParams,
          PH_EXCHANGE_DEFAULT,
          aCmdBuf,
          bCmdLen,
          &pResponse,
          &wRespLen));

  return PH_ADD_COMPCODE(PH_ERR_SUCCESS, PH_COMP_HAL);
}

phStatus_t
phhalHw_SamAV3_Cmd_X_ISO14443_4_Exchange(phhalHw_SamAV3_DataParams_t *pDataParams,
    uint16_t wOption, uint8_t *pAppDataIn,
    uint8_t bLenAppData, uint8_t **ppAppDataOut, uint16_t *pAppDataOutLen)
{
  phStatus_t	PH_MEMLOC_REM wStatus = 0;
  uint8_t		PH_MEMLOC_REM aCmdBuf[PHHAL_HW_SAMAV3_ISO7816_HEADER_LENGTH];
  uint8_t 	*PH_MEMLOC_REM pResponse = NULL;
  uint16_t	PH_MEMLOC_REM wRespLen = 0;

  /* Parameter validation. */
  PH_ASSERT_NULL_DATA_PARAM(pDataParams, PH_COMP_HAL);
  PH_ASSERT_NULL_PARAM(pAppDataIn, PH_COMP_HAL);
  PH_ASSERT_NULL_PARAM(pAppDataOutLen, PH_COMP_HAL);

  /* Frame ISO14443-4_Exchange command information. */
  aCmdBuf[PHHAL_HW_SAMAV3_ISO7816_CLA_POS] = PHHAL_HW_SAMAV3_ISO7816_CLA_BYTE;
  aCmdBuf[PHHAL_HW_SAMAV3_ISO7816_INS_POS] = PHHAL_HW_SAMAV3_CMD_ISO14443_4_EXCHANGE_INS;
  aCmdBuf[PHHAL_HW_SAMAV3_ISO7816_P1_POS]  = PHHAL_HW_SAMAV3_ISO7816_LAST_FRAME;
  aCmdBuf[PHHAL_HW_SAMAV3_ISO7816_P2_POS]  = PHHAL_HW_SAMAV3_ISO7816_DEFAULT_P2_BYTE;

  /* Update command information with chaining frame. */
  if (wOption & PH_EXCHANGE_TXCHAINING) {
    aCmdBuf[PHHAL_HW_SAMAV3_ISO7816_P1_POS]  = PHHAL_HW_SAMAV3_ISO7816_CHAINED_FRAME;
  }

  aCmdBuf[PHHAL_HW_SAMAV3_ISO7816_LC_POS]  = bLenAppData;

  /* Buffer coommand information to exchange buffer. */
  PH_CHECK_SUCCESS_FCT(wStatus, phhalHw_SamAV3_Cmd_7816Exchange(
          pDataParams,
          PH_EXCHANGE_BUFFER_FIRST,
          aCmdBuf,
          PHHAL_HW_SAMAV3_ISO7816_HEADER_LENGTH,
          NULL,
          NULL));

  /* Buffer application data information to exchange buffer. */
  PH_CHECK_SUCCESS_FCT(wStatus, phhalHw_SamAV3_Cmd_7816Exchange(
          pDataParams,
          PH_EXCHANGE_BUFFER_CONT,
          pAppDataIn,
          bLenAppData,
          NULL,
          NULL));

  /* Exchagne the bufferred information to SAM hardware. */
  wStatus = phhalHw_SamAV3_Cmd_7816Exchange(
          pDataParams,
          PH_EXCHANGE_BUFFER_LAST,
          gaDefaultLe,
          (uint16_t)((wOption & PH_EXCHANGE_TXCHAINING) ? 0 : 1),
          &pResponse,
          &wRespLen);

  /* Return received data */
  *pAppDataOutLen = wRespLen;
  *ppAppDataOut = pResponse;

  /* Check status */
  if ((wStatus & PH_ERR_MASK) == PHHAL_HW_SAMAV3_ERR_OK_CHAINING_ACTIVE) {
    return PH_ADD_COMPCODE(PH_ERR_SUCCESS_CHAINING, PH_COMP_HAL);
  }

  /* Check length */
  if (wRespLen > (PHHAL_HW_SAMAV3_ISO7816_EXCHANGE_RESPONSE_MAX)) {
    return PH_ADD_COMPCODE(PH_ERR_LENGTH_ERROR, PH_COMP_HAL);
  }

  return wStatus;
}

phStatus_t
phhalHw_SamAV3_Cmd_X_ISO14443_4_PresenceCheck(phhalHw_SamAV3_DataParams_t *pDataParams)
{
  phStatus_t  PH_MEMLOC_REM wStatus = 0;
  uint8_t     PH_MEMLOC_REM aCmdBuf[PHHAL_HW_SAMAV3_ISO7816_HEADER_NO_LC_LENGTH];
  uint8_t    *PH_MEMLOC_REM pResponse = NULL;
  uint16_t    PH_MEMLOC_REM wRespLen = 0;

  /* Parameter validation. */
  PH_ASSERT_NULL_DATA_PARAM(pDataParams, PH_COMP_HAL);

  /* Frame Cmd.ISO14443-4_PresenceCheck command information. */
  aCmdBuf[PHHAL_HW_SAMAV3_ISO7816_CLA_POS] = PHHAL_HW_SAMAV3_ISO7816_CLA_BYTE;
  aCmdBuf[PHHAL_HW_SAMAV3_ISO7816_INS_POS] = PHHAL_HW_SAMAV3_CMD_ISO14443_4_PRESENCE_CHECK_INS;
  aCmdBuf[PHHAL_HW_SAMAV3_ISO7816_P1_POS]  = PHHAL_HW_SAMAV3_ISO7816_DEFAULT_P1_BYTE;
  aCmdBuf[PHHAL_HW_SAMAV3_ISO7816_P2_POS]  = PHHAL_HW_SAMAV3_ISO7816_DEFAULT_P2_BYTE;

  /* Exchange command information to SAM hardware. */
  PH_CHECK_SUCCESS_FCT(wStatus, phhalHw_SamAV3_Cmd_7816Exchange(
          pDataParams,
          PH_EXCHANGE_DEFAULT,
          aCmdBuf,
          PHHAL_HW_SAMAV3_ISO7816_HEADER_NO_LC_LENGTH,
          &pResponse,
          &wRespLen));

  if (wRespLen != 0x00) {
    /* Remapping of return values */
    return PH_ADD_COMPCODE(PH_ERR_LENGTH_ERROR, PH_COMP_HAL);
  }

  return PH_ADD_COMPCODE(PH_ERR_SUCCESS, PH_COMP_HAL);
}

phStatus_t
phhalHw_SamAV3_Cmd_X_ISO14443_4_Deselect(phhalHw_SamAV3_DataParams_t *pDataParams,
    uint8_t bFreeCid)
{
  phStatus_t	PH_MEMLOC_REM wStatus = 0;
  uint8_t		PH_MEMLOC_REM aCmdBuf[PHHAL_HW_SAMAV3_ISO7816_HEADER_NO_LC_LENGTH];
  uint8_t 	*PH_MEMLOC_REM pResponse = NULL;
  uint16_t	PH_MEMLOC_REM wResLen = 0;

  /* Parameter validation. */
  PH_ASSERT_NULL_DATA_PARAM(pDataParams, PH_COMP_HAL);

  /* Frame Cmd.ISO14443-4_Deselect command information. */
  aCmdBuf[PHHAL_HW_SAMAV3_ISO7816_CLA_POS] = PHHAL_HW_SAMAV3_ISO7816_CLA_BYTE;
  aCmdBuf[PHHAL_HW_SAMAV3_ISO7816_INS_POS] = PHHAL_HW_SAMAV3_CMD_ISO14443_4_DESELECT_INS;
  aCmdBuf[PHHAL_HW_SAMAV3_ISO7816_P1_POS]  = bFreeCid;
  aCmdBuf[PHHAL_HW_SAMAV3_ISO7816_P2_POS]  = PHHAL_HW_SAMAV3_ISO7816_DEFAULT_P2_BYTE;

  /* Exchange command information to SAM hardware. */
  PH_CHECK_SUCCESS_FCT(wStatus, phhalHw_SamAV3_Cmd_7816Exchange(
          pDataParams,
          PH_EXCHANGE_DEFAULT,
          aCmdBuf,
          PHHAL_HW_SAMAV3_ISO7816_HEADER_NO_LC_LENGTH,
          &pResponse,
          &wResLen));

  if (wResLen != 0x00) {
    /* Remapping of return values */
    return PH_ADD_COMPCODE(PH_ERR_LENGTH_ERROR, PH_COMP_HAL);
  }

  return PH_ADD_COMPCODE(PH_ERR_SUCCESS, PH_COMP_HAL);
}

phStatus_t
phhalHw_SamAV3_Cmd_X_ISO14443_4_FreeCid(phhalHw_SamAV3_DataParams_t *pDataParams, uint8_t *pCid,
    uint8_t bCidLen)
{
  phStatus_t	PH_MEMLOC_REM wStatus = 0;
  uint8_t		PH_MEMLOC_REM aCmdBuf[PHHAL_HW_SAMAV3_ISO7816_HEADER_LENGTH];
  uint8_t 	*PH_MEMLOC_REM pResponse = NULL;
  uint16_t	PH_MEMLOC_REM wRespLen = 0;

  /* Parameter validation. */
  PH_ASSERT_NULL_DATA_PARAM(pDataParams, PH_COMP_HAL);
  PH_ASSERT_NULL_PARAM(pCid, PH_COMP_HAL);

  /* Frame Cmd.ISO14443-4_FreeCID command information. */
  aCmdBuf[PHHAL_HW_SAMAV3_ISO7816_CLA_POS] = PHHAL_HW_SAMAV3_ISO7816_CLA_BYTE;
  aCmdBuf[PHHAL_HW_SAMAV3_ISO7816_INS_POS] = PHHAL_HW_SAMAV3_CMD_ISO14443_4_FREE_CID_INS;
  aCmdBuf[PHHAL_HW_SAMAV3_ISO7816_P1_POS]  = PHHAL_HW_SAMAV3_ISO7816_DEFAULT_P1_BYTE;
  aCmdBuf[PHHAL_HW_SAMAV3_ISO7816_P2_POS]  = PHHAL_HW_SAMAV3_ISO7816_DEFAULT_P2_BYTE;
  aCmdBuf[PHHAL_HW_SAMAV3_ISO7816_LC_POS]  = bCidLen;

  /* Buffer command information to exchange buffer. */
  PH_CHECK_SUCCESS_FCT(wStatus, phhalHw_SamAV3_Cmd_7816Exchange(
          pDataParams,
          PH_EXCHANGE_BUFFER_FIRST,
          aCmdBuf,
          PHHAL_HW_SAMAV3_ISO7816_HEADER_LENGTH,
          NULL,
          NULL));

  /* Buffer CID information and exchange the bufferred information to SAM hardware. */
  PH_CHECK_SUCCESS_FCT(wStatus, phhalHw_SamAV3_Cmd_7816Exchange(
          pDataParams,
          PH_EXCHANGE_BUFFER_LAST,
          pCid,
          bCidLen,
          &pResponse,
          &wRespLen));

  if (wRespLen != 0x00) {
    /* Remapping of return values */
    return PH_ADD_COMPCODE(PH_ERR_LENGTH_ERROR, PH_COMP_HAL);
  }

  return PH_ADD_COMPCODE(PH_ERR_SUCCESS, PH_COMP_HAL);
}

#endif /* NXPBUILD__PHHAL_HW_SAMAV3 */
