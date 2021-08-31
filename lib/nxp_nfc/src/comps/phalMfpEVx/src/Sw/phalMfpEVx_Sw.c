/*----------------------------------------------------------------------------*/
/* Copyright 2013-2020 NXP                                                    */
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

/** \file
* Software MIFARE Plus EVx contactless IC (Ev1, and future versions) contactless IC Application Component of Reader Library Framework.
* $Author: Rajendran Kumar (nxp99556) $
* $Revision: 5464 $ (v06.11.00)
* $Date: 2019-01-10 19:08:57 +0530 (Thu, 10 Jan 2019) $
*
* History:
*  Kumar GVS: Generated 15. Apr 2013
*
*/

#include <nxp_nfc/ph_Status.h>
#include <nxp_nfc/phhalHw.h>
#include <nxp_nfc/phalMfpEVx.h>
#include <nxp_nfc/phpalMifare.h>

#ifdef NXPBUILD__PH_CRYPTOSYM
#include <nxp_nfc/phCryptoSym.h>
#endif /* NXPBUILD__PH_CRYPTOSYM */
#ifdef NXPBUILD__PH_CRYPTORNG
#include <nxp_nfc/phCryptoRng.h>
#endif /* NXPBUILD__PH_CRYPTORNG */

#include <nxp_nfc/phKeyStore.h>
#include <nxp_nfc/ph_RefDefs.h>
#include <nxp_nfc/phTMIUtils.h>
#include <nxp_nfc/phalVca.h>

#ifdef NXPBUILD__PHAL_MFPEVX_SW

#include "../phalMfpEVx_Int.h"
#include "nxp_nfc/phalMfpEVx_Sw.h"

#ifdef NXPBUILD__PHAL_MFPEVX_NDA
#include "nxp_nfc/phalMfpEVx_Sw_Int.h"
#endif /* NXPBUILD__PHAL_MFPEVX_NDA */

#ifdef NXPBUILD__PHAL_MFPEVX_NDA
static const uint8_t PH_MEMLOC_CONST_ROM phalMfpEVx_Sw_FirstIv[PH_CRYPTOSYM_AES_BLOCK_SIZE] = {0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00};
#endif /* NXPBUILD__PHAL_MFPEVX_NDA */

phStatus_t
phalMfpEVx_Sw_Init(phalMfpEVx_Sw_DataParams_t *pDataParams, uint16_t wSizeOfDataParams,
    void *pPalMifareDataParams,
    void *pKeyStoreDataParams, void *pCryptoDataParamsEnc, void *pCryptoDataParamsMac,
    void *pCryptoRngDataParams,
    void *pCryptoDiversifyDataParams, void *pTMIDataParams, void *pVCADataParams)
{
  phStatus_t PH_MEMLOC_REM statusTmp;

  /* data param check */
  if (sizeof(phalMfpEVx_Sw_DataParams_t) != wSizeOfDataParams) {
    return PH_ADD_COMPCODE_FIXED(PH_ERR_INVALID_DATA_PARAMS, PH_COMP_AL_MFPEVX);
  }
  PH_ASSERT_NULL_DATA_PARAM(pDataParams, PH_COMP_AL_MFPEVX);
  PH_ASSERT_NULL_PARAM(pPalMifareDataParams, PH_COMP_AL_MFPEVX);

#ifdef NXPBUILD__PHAL_MFPEVX_NDA
  PH_ASSERT_NULL_PARAM(pKeyStoreDataParams, PH_COMP_AL_MFPEVX);
  PH_ASSERT_NULL_PARAM(pCryptoDataParamsEnc, PH_COMP_AL_MFPEVX);
  PH_ASSERT_NULL_PARAM(pCryptoDataParamsMac, PH_COMP_AL_MFPEVX);
  PH_ASSERT_NULL_PARAM(pCryptoRngDataParams, PH_COMP_AL_MFPEVX);
#endif /* NXPBUILD__PHAL_MFPEVX_NDA */

  PH_ASSERT_NULL_PARAM(pTMIDataParams, PH_COMP_AL_MFPEVX);
  PH_ASSERT_NULL_PARAM(pVCADataParams, PH_COMP_AL_MFPEVX);

  /* init private data */
  pDataParams->wId                    = PH_COMP_AL_MFPEVX | PHAL_MFPEVX_SW_ID;
  pDataParams->pPalMifareDataParams   = pPalMifareDataParams;
  pDataParams->pKeyStoreDataParams    = pKeyStoreDataParams;
  pDataParams->pCryptoDataParamsEnc   = pCryptoDataParamsEnc;
  pDataParams->pCryptoDataParamsMac   = pCryptoDataParamsMac;
  pDataParams->pCryptoRngDataParams   = pCryptoRngDataParams;
  pDataParams->pCryptoDiversifyDataParams  = pCryptoDiversifyDataParams;
  pDataParams->pTMIDataParams         = pTMIDataParams;
  pDataParams->bWrappedMode           = 0x00;     /* Use native mode by default */
  pDataParams->bExtendedLenApdu       = 0x00;     /* Use short length APDU by default */
  pDataParams->pVCADataParams         = pVCADataParams;
  pDataParams->bAuthMode              = (uint8_t)PHAL_MFPEVX_NOTAUTHENTICATED;
  pDataParams->bSMMode                = (uint8_t)PHAL_MFPEVX_SECURE_MESSAGE_EV0;

  (void)memset(pDataParams->bSesAuthENCKey, 0x00, 16);
  (void)memset(pDataParams->bSesAuthMACKey, 0x00, 16);
  (void)memset(pDataParams->bIv, 0x00, 16);

  /* clear the secure messaging state */
  PH_CHECK_SUCCESS_FCT(statusTmp, phalMfpEVx_Sw_ResetSecMsgState(pDataParams));

  return PH_ERR_SUCCESS;
}

/***************************************************************************************************************************************/
/* Mifare Plus EVx Software command for personalization.                                                                               */
/***************************************************************************************************************************************/
phStatus_t
phalMfpEVx_Sw_WritePerso(phalMfpEVx_Sw_DataParams_t *pDataParams, uint8_t bLayer4Comm,
    uint16_t wBlockNr,
    uint8_t bNumBlocks, uint8_t *pValue)
{
  return phalMfpEVx_Int_WritePerso(pDataParams->pPalMifareDataParams, bLayer4Comm,
          pDataParams->bWrappedMode, pDataParams->bExtendedLenApdu,
          wBlockNr, bNumBlocks, pValue);
}

phStatus_t
phalMfpEVx_Sw_CommitPerso(phalMfpEVx_Sw_DataParams_t *pDataParams, uint8_t bOption,
    uint8_t bLayer4Comm)
{
  return phalMfpEVx_Int_CommitPerso(pDataParams->pPalMifareDataParams, bOption, bLayer4Comm,
          pDataParams->bWrappedMode,
          pDataParams->bExtendedLenApdu);
}

/***************************************************************************************************************************************/
/* Mifare Plus EVx Software command for authentication.                                                                                */
/***************************************************************************************************************************************/
phStatus_t
phalMfpEVx_Sw_AuthenticateMfc(phalMfpEVx_Sw_DataParams_t *pDataParams,
    uint8_t bBlockNo, uint8_t bKeyType, uint16_t wKeyNo,
    uint16_t wKeyVersion, uint8_t *pUid, uint8_t bUidLength)
{
  phStatus_t  PH_MEMLOC_REM statusTmp;
  uint8_t     PH_MEMLOC_REM aKey[PH_KEYSTORE_SW_MAX_KEY_SIZE];
  uint8_t    *PH_MEMLOC_REM pKey = NULL;
  uint16_t    PH_MEMLOC_REM bKeystoreKeyType;

  /* Verify the uid length. */
  if ((bUidLength != PHAL_MFPEVX_UID_LENGTH_4B) &&
      (bUidLength != PHAL_MFPEVX_UID_LENGTH_7B) &&
      (bUidLength != PHAL_MFPEVX_UID_LENGTH_10B)) {
    return PH_ADD_COMPCODE_FIXED(PH_ERR_INVALID_PARAMETER, PH_COMP_AL_MFPEVX);
  }

  /* Return an error if keystore is not initialized. */
  if (pDataParams->pKeyStoreDataParams == NULL) {
    return PH_ADD_COMPCODE_FIXED(PH_ERR_KEY, PH_COMP_AL_MFPEVX);
  }

  /* Check the keytype for KEYA or KEYB. */
  if ((bKeyType != PHHAL_HW_MFC_KEYA) && (bKeyType != PHHAL_HW_MFC_KEYB)) {
    return PH_ADD_COMPCODE_FIXED(PH_ERR_INVALID_PARAMETER, PH_COMP_AL_MFPEVX);
  }

  /* Retrieve KeyA & KeyB value from keystore. */
  PH_CHECK_SUCCESS_FCT(statusTmp, phKeyStore_GetKey(
          pDataParams->pKeyStoreDataParams,
          wKeyNo,
          wKeyVersion,
          sizeof(aKey),
          aKey,
          &bKeystoreKeyType));

  /* Check the key type available in the keystore. */
  if (bKeystoreKeyType != PH_KEYSTORE_KEY_TYPE_MIFARE) {
    return PH_ADD_COMPCODE_FIXED(PH_ERR_KEY, PH_COMP_AL_MFPEVX);
  }

  /* Evaluate which key to use. */
  if ((bKeyType & 0x7FU) == PHHAL_HW_MFC_KEYA) {
    /* Use KeyA */
    pKey = aKey;
  } else if ((bKeyType & 0x7FU) == PHHAL_HW_MFC_KEYB) {
    /* Use KeyB */
    pKey = &aKey[PHHAL_HW_MFC_KEY_LENGTH];
  } else {
    return PH_ADD_COMPCODE_FIXED(PH_ERR_INVALID_PARAMETER, PH_COMP_AL_MFPEVX);
  }

  /* Authenticate in MFC mode. */
  PH_CHECK_SUCCESS_FCT(statusTmp, phpalMifare_MfcAuthenticate(
          pDataParams->pPalMifareDataParams,
          bBlockNo,
          bKeyType,
          pKey,
          &pUid[bUidLength - 4]));

  /* Update the Auth Mode to MIFARE Authenticated. */
  pDataParams->bAuthMode = (uint8_t)PHAL_MFPEVX_SL1_MIFARE_AUTHENTICATED;

  return PH_ERR_SUCCESS;
}

#ifdef NXPBUILD__PHAL_MFPEVX_NDA
phStatus_t
phalMfpEVx_Sw_AuthenticateSL0(phalMfpEVx_Sw_DataParams_t *pDataParams,
    uint8_t bLayer4Comm, uint8_t bFirstAuth, uint16_t wBlockNr,
    uint16_t wKeyNumber, uint16_t wKeyVersion, uint8_t bLenDivInput, uint8_t *pDivInput,
    uint8_t bLenPcdCap2, uint8_t *pPcdCap2In,
    uint8_t *pPcdCap2Out, uint8_t *pPdCap2)
{
  return phalMfpEVx_Sw_AuthenticateGeneral(
          pDataParams,
          bLayer4Comm,
          bFirstAuth,
          wBlockNr,
          wKeyNumber,
          wKeyVersion,
          bLenDivInput,
          pDivInput,
          bLenPcdCap2,
          pPcdCap2In,
          pPcdCap2Out,
          pPdCap2);
}

phStatus_t
phalMfpEVx_Sw_AuthenticateSL1(phalMfpEVx_Sw_DataParams_t *pDataParams,
    uint8_t bLayer4Comm, uint8_t bFirstAuth, uint16_t wBlockNr,
    uint16_t wKeyNumber, uint16_t wKeyVersion, uint8_t bLenDivInput, uint8_t *pDivInput,
    uint8_t bLenPcdCap2, uint8_t *pPcdCap2In,
    uint8_t *pPcdCap2Out, uint8_t *pPdCap2)
{
  phStatus_t  PH_MEMLOC_REM statusTmp = PH_ERR_SUCCESS;

  statusTmp =  phalMfpEVx_Sw_AuthenticateGeneral(
          pDataParams,
          bLayer4Comm,
          bFirstAuth,
          wBlockNr,
          wKeyNumber,
          wKeyVersion,
          bLenDivInput,
          pDivInput,
          bLenPcdCap2,
          pPcdCap2In,
          pPcdCap2Out,
          pPdCap2);

  if (statusTmp == PH_ERR_SUCCESS) {
    /* Not updating the state in case authenticated using special keys. */
    if (((wBlockNr != PHAL_MFPEVX_SL1CARDAUTHKEY) || (bLayer4Comm != 0x00U)) &&
        (wBlockNr != PHAL_MFPEVX_L3SECTORSWITCHKEY) && (wBlockNr != PHAL_MFPEVX_L3SWITCHKEY) &&
        ((wBlockNr <= PHAL_MFPEVX_ORIGINALITY_KEY_FIRST) ||
            (wBlockNr >= PHAL_MFPEVX_ORIGINALITY_KEY_LAST))) {
      pDataParams->bAuthMode = (uint8_t)PHAL_MFPEVX_SL1_MFP_AUTHENTICATED;
    }

    /* Update the authentication state if VCA PC feature is required by the application. */
    if (pDataParams->pVCADataParams != NULL) {
      /* Set the Session key for Virtual Card which is valid for this authentication */
      PH_CHECK_SUCCESS_FCT(statusTmp, phalVca_SetSessionKeyUtility(
              pDataParams->pVCADataParams,
              pDataParams->bSesAuthMACKey,
              pDataParams->bAuthMode));
    }
  }

  return statusTmp;
}

phStatus_t
phalMfpEVx_Sw_AuthenticateSL3(phalMfpEVx_Sw_DataParams_t *pDataParams,
    uint8_t bFirstAuth, uint16_t wBlockNr, uint16_t wKeyNumber,
    uint16_t wKeyVersion, uint8_t bLenDivInput, uint8_t *pDivInput, uint8_t bLenPcdCap2,
    uint8_t *pPcdCap2In, uint8_t *pPcdCap2Out,
    uint8_t *pPdCap2)
{
  phStatus_t  PH_MEMLOC_REM statusTmp = PH_ERR_SUCCESS;

  statusTmp =  phalMfpEVx_Sw_AuthenticateGeneral(
          pDataParams,
          PH_ON, /* Layer 4 */
          bFirstAuth,
          wBlockNr,
          wKeyNumber,
          wKeyVersion,
          bLenDivInput,
          pDivInput,
          bLenPcdCap2,
          pPcdCap2In,
          pPcdCap2Out,
          pPdCap2);

  if (statusTmp == PH_ERR_SUCCESS) {
    pDataParams->bAuthMode = (uint8_t)PHAL_MFPEVX_SL3_MFP_AUTHENTICATED;

    /* Update the authentication state if VCA PC feature is required by the application. */
    if (pDataParams->pVCADataParams != NULL) {
      /* Set the Session key for Virtual Card which is valid for this authentication */
      PH_CHECK_SUCCESS_FCT(statusTmp, phalVca_SetSessionKeyUtility(
              pDataParams->pVCADataParams,
              pDataParams->bSesAuthMACKey,
              pDataParams->bAuthMode));
    }
  }

  return statusTmp;
}

phStatus_t
phalMfpEVx_Sw_SSAuthenticate(phalMfpEVx_Sw_DataParams_t *pDataParams,
    uint16_t wSSKeyBNr, uint16_t wSSKeyNr, uint16_t wSSKeyVer,
    uint8_t bLenDivInputSSKey, uint8_t *pDivInputSSKey, uint8_t  bSecCount, uint16_t *pSectorNos,
    uint16_t *pKeyBKeyNos,
    uint16_t *pKeyBKeyVers, uint8_t bLenDivInputSectorKeyBs, uint8_t *pDivInputSectorKeyBs)
{
  phStatus_t      PH_MEMLOC_REM statusTmp;
  uint8_t        *PH_MEMLOC_REM pResponse = NULL;
  uint16_t        PH_MEMLOC_REM wRxLength = 0;
  uint8_t         PH_MEMLOC_REM aCmd[117];
  uint8_t         PH_MEMLOC_REM bCmdLength = 0;
  uint8_t         PH_MEMLOC_REM aKey[PH_CRYPTOSYM_AES128_KEY_SIZE];
  uint16_t        PH_MEMLOC_REM wKeyType;
  uint8_t         PH_MEMLOC_REM bRndA[PH_CRYPTOSYM_AES_BLOCK_SIZE];
  uint8_t         PH_MEMLOC_REM bRndARet[PH_CRYPTOSYM_AES_BLOCK_SIZE];
  uint8_t         PH_MEMLOC_REM bRndB[PH_CRYPTOSYM_AES_BLOCK_SIZE];
  uint8_t         PH_MEMLOC_REM bRndBOut[PH_CRYPTOSYM_AES_BLOCK_SIZE];
  uint8_t         PH_MEMLOC_REM btempCount = 0;
  int8_t          PH_MEMLOC_REM bIndex = 0;
  uint8_t         PH_MEMLOC_REM bDataBuffer[16];

  /* Minimum sector count is 1, if not return with invalid parameter error */
  if (bSecCount < 1U) {
    return PH_ADD_COMPCODE_FIXED(PH_ERR_INVALID_PARAMETER, PH_COMP_AL_MFPEVX);
  }

  /* Load the command buffer */
  /* with SSAUTH || LMSB(SSKeyBNr) || SectorCount */
  aCmd[bCmdLength++] = PHAL_MFPEVX_CMD_SSAUTH;
  aCmd[bCmdLength++] = (uint8_t)(wSSKeyBNr & 0x00FFU); /* LSB */
  aCmd[bCmdLength++] = (uint8_t)((wSSKeyBNr & 0xFF00U) >> 8U);   /* MSB */
  aCmd[bCmdLength++] = (uint8_t)(bSecCount);

  /*Load the command buffer */
  /* with Key Block Numbers  LMSB(KeyB1BNr) || .. || LMSB(KeyBNBNr)*/
  for (btempCount = 0; btempCount < bSecCount; btempCount++) {
    aCmd[bCmdLength++] = (uint8_t)((pSectorNos[btempCount]) & 0x00FFU);
    aCmd[bCmdLength++] = (uint8_t)((pSectorNos[btempCount] & 0xFF00U) >> 8U);
  }

  /* Check if ISO 7816-4 wapping is required. */
  if (0U != (pDataParams->bWrappedMode)) {
    /* Exchange cmd frame */
    PH_CHECK_SUCCESS_FCT(statusTmp, phalMfpEVx_Int_Send7816Apdu(
            pDataParams->pPalMifareDataParams,
            PH_EXCHANGE_DEFAULT,
            (((uint16_t)bCmdLength) - 1U /* Excluding the command code */),
            pDataParams->bExtendedLenApdu,
            aCmd,
            bCmdLength,     /* Command code is included as part of length. */
            &pResponse,
            &wRxLength));
  } else {
    /* Exchange cmd frame */
    PH_CHECK_SUCCESS_FCT(statusTmp, phpalMifare_ExchangeL4(
            pDataParams->pPalMifareDataParams,
            PH_EXCHANGE_DEFAULT,
            aCmd,
            bCmdLength,
            &pResponse,
            &wRxLength));
  }

  /* Evaluate the response for any errors. */
  PH_CHECK_SUCCESS_FCT(statusTmp, phalMfpEVx_Int_ComputeErrorResponse(wRxLength, pResponse[0],
          PH_ON));

  /* if MFPAuthState is AuthInProgress1 then ERROR */
  /* else check if the length of RcvdChallenge is not 1+16 then ERROR*/
  if ((wRxLength != (1 /* status */ + PH_CRYPTOSYM_AES_BLOCK_SIZE /* ENC(RNDB) */)) ||
      (pResponse[0] != PHAL_MFPEVX_RESP_ACK_ISO4)) {
    return PH_ADD_COMPCODE_FIXED(PH_ERR_PROTOCOL_ERROR, PH_COMP_AL_MFPEVX);
  }
  /* Copy the response data to a local buffer */
  for (bIndex = 0; bIndex < 16 ; bIndex++) {
    bDataBuffer[bIndex] = pResponse[bIndex + 1];
  }

  /* Decrypt the data with the number of AES sector keys passed by the user */
  for (bIndex = (bSecCount - 1); bIndex >= 0; bIndex--) {
    /* Get Key out of the key store object */
    PH_CHECK_SUCCESS_FCT(statusTmp, phKeyStore_GetKey(
            pDataParams->pKeyStoreDataParams,
            pKeyBKeyNos[bIndex],
            pKeyBKeyVers[bIndex],
            (uint8_t)(sizeof(aKey)),
            aKey,
            &wKeyType));

    /* Key type check. It should be AES Type. */
    if (wKeyType != PH_CRYPTOSYM_KEY_TYPE_AES128) {
      return PH_ADD_COMPCODE_FIXED(PH_ERR_KEY, PH_COMP_AL_MFPEVX);
    }

    /* Do we need to diversify the AES Sector B key. */
    if (0U != (bLenDivInputSectorKeyBs)) {
      /* Check if Crypto Params is not null. */
      if (pDataParams->pCryptoDiversifyDataParams == NULL) {
        return PH_ADD_COMPCODE_FIXED(PH_ERR_INVALID_PARAMETER, PH_COMP_AL_MFPEVX);
      }

      /* Check if DivInput buffer is not null for Key B. */
      if (pDivInputSectorKeyBs == NULL) {
        return PH_ADD_COMPCODE_FIXED(PH_ERR_INVALID_PARAMETER, PH_COMP_AL_MFPEVX);
      }

      PH_CHECK_SUCCESS_FCT(statusTmp,
          phCryptoSym_DiversifyDirectKey(pDataParams->pCryptoDiversifyDataParams,
              PH_CRYPTOSYM_DIV_MODE_MIFARE_PLUS,
              aKey,
              wKeyType,
              pDivInputSectorKeyBs,
              bLenDivInputSectorKeyBs,
              aKey));
    }

    /* Load the key*/
    PH_CHECK_SUCCESS_FCT(statusTmp, phCryptoSym_LoadKeyDirect(
            pDataParams->pCryptoDataParamsEnc,
            aKey,
            PH_CRYPTOSYM_KEY_TYPE_AES128));

    /* Load zero IV */
    PH_CHECK_SUCCESS_FCT(statusTmp, phCryptoSym_LoadIv(
            pDataParams->pCryptoDataParamsEnc,
            phalMfpEVx_Sw_FirstIv,
            PH_CRYPTOSYM_AES_BLOCK_SIZE));

    /* Decrypt the data */
    PH_CHECK_SUCCESS_FCT(statusTmp, phCryptoSym_Decrypt(
            pDataParams->pCryptoDataParamsEnc,
            PH_EXCHANGE_DEFAULT | PH_CRYPTOSYM_CIPHER_MODE_CBC,
            bDataBuffer,
            PH_CRYPTOSYM_AES_BLOCK_SIZE,
            bDataBuffer));
  }

  /* Decrypt with the SSKeyBnr, this is the switch key like 0x9006 or 0x9007  */
  PH_CHECK_SUCCESS_FCT(statusTmp, phKeyStore_GetKey(
          pDataParams->pKeyStoreDataParams,
          wSSKeyNr,
          wSSKeyVer,
          (uint8_t)(sizeof(aKey)),
          aKey,
          &wKeyType));

  /* Key type check. It should be of AES TYPE*/
  if (wKeyType != PH_CRYPTOSYM_KEY_TYPE_AES128) {
    return PH_ADD_COMPCODE_FIXED(PH_ERR_KEY, PH_COMP_AL_MFPEVX);
  }

  /* Do we need to diversify the Sector Switch keys. */
  if (0U != (bLenDivInputSSKey)) {
    /* Check if DivInput buffer is not null for Key B. */
    if (pDivInputSSKey == NULL) {
      return PH_ADD_COMPCODE_FIXED(PH_ERR_INVALID_PARAMETER, PH_COMP_AL_MFPEVX);
    }

    PH_CHECK_SUCCESS_FCT(statusTmp,
        phCryptoSym_DiversifyDirectKey(pDataParams->pCryptoDiversifyDataParams,
            PH_CRYPTOSYM_DIV_MODE_MIFARE_PLUS,
            aKey,
            wKeyType,
            pDivInputSSKey,
            bLenDivInputSSKey,
            aKey));
  }

  /* Load the key*/
  PH_CHECK_SUCCESS_FCT(statusTmp, phCryptoSym_LoadKeyDirect(
          pDataParams->pCryptoDataParamsEnc,
          aKey,
          PH_CRYPTOSYM_KEY_TYPE_AES128));

  /* Load 0 IV */
  PH_CHECK_SUCCESS_FCT(statusTmp, phCryptoSym_LoadIv(
          pDataParams->pCryptoDataParamsEnc,
          phalMfpEVx_Sw_FirstIv,
          PH_CRYPTOSYM_AES_BLOCK_SIZE));

  /* Decrypt the data buffer to retrieve RndB*/
  PH_CHECK_SUCCESS_FCT(statusTmp, phCryptoSym_Decrypt(
          pDataParams->pCryptoDataParamsEnc,
          PH_EXCHANGE_DEFAULT | PH_CRYPTOSYM_CIPHER_MODE_CBC,
          bDataBuffer,
          PH_CRYPTOSYM_AES_BLOCK_SIZE,
          bDataBuffer));

  (void)memcpy(bRndB, bDataBuffer, PH_CRYPTOSYM_AES_BLOCK_SIZE);

  /* Generate Random A */
  PH_CHECK_SUCCESS_FCT(statusTmp, phCryptoRng_Rnd(
          pDataParams->pCryptoRngDataParams,
          PH_CRYPTOSYM_AES_BLOCK_SIZE,
          bRndA));

  /* Rotate bRndB by 1 byte left */
  for (bIndex = 0; bIndex < (uint8_t)(PH_CRYPTOSYM_AES_BLOCK_SIZE - 1); bIndex++) {
    bRndBOut[bIndex] = bRndB[bIndex + 1];
  }
  bRndBOut[PH_CRYPTOSYM_AES_BLOCK_SIZE - 1] = bRndB[0];

  /* Place the rotated bytes to Main RndB array */
  (void)memcpy(bRndB, bRndBOut, PH_CRYPTOSYM_AES_BLOCK_SIZE);

  /* Compute second part of the Auth sequence */
  aCmd[0] = PHAL_MFPEVX_CMD_SSAUTHC;

  (void)memcpy(&aCmd[1], bRndA, PH_CRYPTOSYM_AES_BLOCK_SIZE);
  (void)memcpy(&aCmd[1U + PH_CRYPTOSYM_AES_BLOCK_SIZE], bRndB, PH_CRYPTOSYM_AES_BLOCK_SIZE);

  /* Load 0 IV */
  PH_CHECK_SUCCESS_FCT(statusTmp, phCryptoSym_LoadIv(
          pDataParams->pCryptoDataParamsEnc,
          phalMfpEVx_Sw_FirstIv,
          PH_CRYPTOSYM_AES_BLOCK_SIZE));

  /* Encrypt with the SSKeyBnr */
  PH_CHECK_SUCCESS_FCT(statusTmp, phKeyStore_GetKey(
          pDataParams->pKeyStoreDataParams,
          wSSKeyNr,
          wSSKeyVer,
          (uint8_t)(sizeof(aKey)),
          aKey,
          &wKeyType));

  /* Key type check */
  if (wKeyType != PH_CRYPTOSYM_KEY_TYPE_AES128) {
    return PH_ADD_COMPCODE_FIXED(PH_ERR_KEY, PH_COMP_AL_MFPEVX);
  }

  /* Do we need to diversify the Sector Switch keys. */
  if (0U != (bLenDivInputSSKey)) {
    PH_CHECK_SUCCESS_FCT(statusTmp,
        phCryptoSym_DiversifyDirectKey(pDataParams->pCryptoDiversifyDataParams,
            PH_CRYPTOSYM_DIV_MODE_MIFARE_PLUS,
            aKey,
            wKeyType,
            pDivInputSSKey,
            bLenDivInputSSKey,
            aKey));
  }

  /* Load the key*/
  PH_CHECK_SUCCESS_FCT(statusTmp, phCryptoSym_LoadKeyDirect(
          pDataParams->pCryptoDataParamsEnc,
          aKey,
          PH_CRYPTOSYM_KEY_TYPE_AES128));

  /* Encrypt the data key is already loaded. */
  PH_CHECK_SUCCESS_FCT(statusTmp, phCryptoSym_Encrypt(
          pDataParams->pCryptoDataParamsEnc,
          PH_EXCHANGE_DEFAULT | PH_CRYPTOSYM_CIPHER_MODE_CBC,
          &aCmd[1],
          2U * PH_CRYPTOSYM_AES_BLOCK_SIZE,
          &aCmd[1]));

  for (bIndex = 0; bIndex < bSecCount; bIndex++) {
    /* Get Key out of the key store object */
    PH_CHECK_SUCCESS_FCT(statusTmp, phKeyStore_GetKey(
            pDataParams->pKeyStoreDataParams,
            pKeyBKeyNos[bIndex],
            pKeyBKeyVers[bIndex],
            (uint8_t)(sizeof(aKey)),
            aKey,
            &wKeyType));

    /* Key type check. It should be TYOPE*/
    if (wKeyType != PH_CRYPTOSYM_KEY_TYPE_AES128) {
      return PH_ADD_COMPCODE_FIXED(PH_ERR_KEY, PH_COMP_AL_MFPEVX);
    }

    /* Do we need to diversify the AES Sector B key. */
    if (0U != (bLenDivInputSectorKeyBs)) {
      PH_CHECK_SUCCESS_FCT(statusTmp,
          phCryptoSym_DiversifyDirectKey(pDataParams->pCryptoDiversifyDataParams,
              PH_CRYPTOSYM_DIV_MODE_MIFARE_PLUS,
              aKey,
              wKeyType,
              pDivInputSectorKeyBs,
              bLenDivInputSectorKeyBs,
              aKey));
    }

    /* Load the key*/
    PH_CHECK_SUCCESS_FCT(statusTmp, phCryptoSym_LoadKeyDirect(
            pDataParams->pCryptoDataParamsEnc,
            aKey,
            PH_CRYPTOSYM_KEY_TYPE_AES128));

    PH_CHECK_SUCCESS_FCT(statusTmp, phCryptoSym_LoadIv(
            pDataParams->pCryptoDataParamsEnc,
            phalMfpEVx_Sw_FirstIv,
            PH_CRYPTOSYM_AES_BLOCK_SIZE));

    PH_CHECK_SUCCESS_FCT(statusTmp, phCryptoSym_Encrypt(
            pDataParams->pCryptoDataParamsEnc,
            PH_EXCHANGE_DEFAULT | PH_CRYPTOSYM_CIPHER_MODE_CBC,
            &aCmd[1],
            2U * PH_CRYPTOSYM_AES_BLOCK_SIZE,
            &aCmd[1]));
  }

  bCmdLength = 1 + (2U * PH_CRYPTOSYM_AES_BLOCK_SIZE);

  /* command exchange */
  PH_CHECK_SUCCESS_FCT(statusTmp, phpalMifare_ExchangeL4(
          pDataParams->pPalMifareDataParams,
          PH_EXCHANGE_DEFAULT,
          aCmd,
          bCmdLength,
          &pResponse,
          &wRxLength));

  /* Evaluate the response for any errors. */
  PH_CHECK_SUCCESS_FCT(statusTmp, phalMfpEVx_Int_ComputeErrorResponse(wRxLength, pResponse[0],
          PH_ON));

  /* if MFPAuthState is AuthInProgress1 then ERROR */
  /* else check if the length of RcvdChallenge is not 16 then ERROR*/
  if ((wRxLength != (1 /* status */ + PH_CRYPTOSYM_AES_BLOCK_SIZE /* ENC(RNDA') */)) ||
      (pResponse[0] != PHAL_MFPEVX_RESP_ACK_ISO4)) {
    return PH_ADD_COMPCODE_FIXED(PH_ERR_PROTOCOL_ERROR, PH_COMP_AL_MFPEVX);
  }

  (void)memset(bDataBuffer, 0x00, (size_t)sizeof(bDataBuffer));

  for (bIndex = 0; bIndex < 16 ; bIndex++) {
    bDataBuffer[bIndex] = pResponse[bIndex + 1];
  }

  /* Decrypt the response. */
  for (bIndex = (bSecCount - 1); bIndex >= 0U; bIndex--) {
    /* Get Key out of the key store object */
    PH_CHECK_SUCCESS_FCT(statusTmp, phKeyStore_GetKey(
            pDataParams->pKeyStoreDataParams,
            pKeyBKeyNos[bIndex],
            pKeyBKeyVers[bIndex],
            (uint8_t)(sizeof(aKey)),
            aKey,
            &wKeyType));

    /* Key type check. It should be AES TYPE*/
    if (wKeyType != PH_CRYPTOSYM_KEY_TYPE_AES128) {
      return PH_ADD_COMPCODE_FIXED(PH_ERR_KEY, PH_COMP_AL_MFPEVX);
    }

    /* Do we need to diversify the AES Sector B key. */
    if (0U != (bLenDivInputSectorKeyBs)) {
      PH_CHECK_SUCCESS_FCT(statusTmp,
          phCryptoSym_DiversifyDirectKey(pDataParams->pCryptoDiversifyDataParams,
              PH_CRYPTOSYM_DIV_MODE_MIFARE_PLUS,
              aKey,
              wKeyType,
              pDivInputSectorKeyBs,
              bLenDivInputSectorKeyBs,
              aKey));
    }

    /* Load the key*/
    PH_CHECK_SUCCESS_FCT(statusTmp, phCryptoSym_LoadKeyDirect(
            pDataParams->pCryptoDataParamsEnc,
            aKey,
            PH_CRYPTOSYM_KEY_TYPE_AES128));

    PH_CHECK_SUCCESS_FCT(statusTmp, phCryptoSym_LoadIv(
            pDataParams->pCryptoDataParamsEnc,
            phalMfpEVx_Sw_FirstIv,
            PH_CRYPTOSYM_AES_BLOCK_SIZE));

    PH_CHECK_SUCCESS_FCT(statusTmp, phCryptoSym_Decrypt(
            pDataParams->pCryptoDataParamsEnc,
            PH_EXCHANGE_DEFAULT | PH_CRYPTOSYM_CIPHER_MODE_CBC,
            bDataBuffer,
            PH_CRYPTOSYM_AES_BLOCK_SIZE,
            bDataBuffer));
  }

  /* Decrypt with the SSKeyBnr */
  PH_CHECK_SUCCESS_FCT(statusTmp, phKeyStore_GetKey(
          pDataParams->pKeyStoreDataParams,
          wSSKeyNr,
          wSSKeyVer,
          (uint8_t)(sizeof(aKey)),
          aKey,
          &wKeyType));

  /* Key type check. It should be TYPE*/
  if (wKeyType != PH_CRYPTOSYM_KEY_TYPE_AES128) {
    return PH_ADD_COMPCODE_FIXED(PH_ERR_KEY, PH_COMP_AL_MFPEVX);
  }

  /* Do we need to diversify the Sector Switch keys. */
  if (0U != (bLenDivInputSSKey)) {
    PH_CHECK_SUCCESS_FCT(statusTmp,
        phCryptoSym_DiversifyDirectKey(pDataParams->pCryptoDiversifyDataParams,
            PH_CRYPTOSYM_DIV_MODE_MIFARE_PLUS,
            aKey,
            wKeyType,
            pDivInputSSKey,
            bLenDivInputSSKey,
            aKey));
  }

  /* Load the key*/
  PH_CHECK_SUCCESS_FCT(statusTmp, phCryptoSym_LoadKeyDirect(
          pDataParams->pCryptoDataParamsEnc,
          aKey,
          wKeyType));

  PH_CHECK_SUCCESS_FCT(statusTmp, phCryptoSym_LoadIv(
          pDataParams->pCryptoDataParamsEnc,
          phalMfpEVx_Sw_FirstIv,
          PH_CRYPTOSYM_AES_BLOCK_SIZE));

  PH_CHECK_SUCCESS_FCT(statusTmp, phCryptoSym_Decrypt(
          pDataParams->pCryptoDataParamsEnc,
          PH_EXCHANGE_DEFAULT | PH_CRYPTOSYM_CIPHER_MODE_CBC,
          bDataBuffer,
          PH_CRYPTOSYM_AES_BLOCK_SIZE,
          bDataBuffer));

  /* Rotate bRndA by 1 byte right */
  for (bIndex = 1; bIndex < (int8_t) PH_CRYPTOSYM_AES_BLOCK_SIZE; bIndex++) {
    bRndARet[bIndex] = bDataBuffer[bIndex - 1];
  }
  bRndARet[0] = bDataBuffer[PH_CRYPTOSYM_AES_BLOCK_SIZE - 1];

  /* compare with the bRndA with bRndReturned from card */
  if (memcmp(bRndARet, bRndA, PH_CRYPTOSYM_AES_BLOCK_SIZE) != 0) {
    /* RndA and RndA' don't match */
    return PH_ADD_COMPCODE_FIXED(PH_ERR_AUTH_ERROR, PH_COMP_AL_MFPEVX);
  }

  return PH_ERR_SUCCESS;
}

phStatus_t
phalMfpEVx_Sw_AuthenticatePDC(phalMfpEVx_Sw_DataParams_t *pDataParams,
    uint16_t wBlockNr, uint16_t wKeyNumber,
    uint16_t wKeyVersion, uint8_t bLenDivInput, uint8_t *pDivInput, uint8_t bUpgradeInfo)
{
  phStatus_t  PH_MEMLOC_REM statusTmp;
  uint8_t    *PH_MEMLOC_REM pResponse = NULL;
  uint16_t    PH_MEMLOC_REM wRxLength = 0;
  uint8_t     PH_MEMLOC_REM aCmdBuffer[39];
  uint8_t     PH_MEMLOC_REM bCmdBufLen = 0;
  uint8_t     PH_MEMLOC_REM aKey[PH_CRYPTOSYM_AES128_KEY_SIZE];
  uint16_t    PH_MEMLOC_REM wKeyType;
  uint8_t     PH_MEMLOC_REM bRndA[PH_CRYPTOSYM_AES_BLOCK_SIZE];
  uint8_t     PH_MEMLOC_REM bRndB[PH_CRYPTOSYM_AES_BLOCK_SIZE + 1U];
  uint8_t     PH_MEMLOC_REM aUpgradeKey[PH_CRYPTOSYM_AES_BLOCK_SIZE];
  uint8_t     PH_MEMLOC_REM bKeyLen = 0;

  /* UpgradeKey computation uisng CMAC algorithm. */

  /* Get the IC Upgrade Key data form key store. */
  PH_CHECK_SUCCESS_FCT(statusTmp, phKeyStore_GetKey(
          pDataParams->pKeyStoreDataParams,
          wKeyNumber,
          wKeyVersion,
          sizeof(aKey),
          aKey,
          &wKeyType));

  /* Check the key type. */
  if (wKeyType != PH_CRYPTOSYM_KEY_TYPE_AES128) {
    return PH_ADD_COMPCODE_FIXED(PH_ERR_INVALID_PARAMETER, PH_COMP_AL_MFPEVX);
  }

  /* Perform diversification if needed. */
  if (0U != bLenDivInput) {
    if (pDataParams->pCryptoDiversifyDataParams == NULL) {
      return PH_ADD_COMPCODE_FIXED(PH_ERR_UNSUPPORTED_COMMAND, PH_COMP_AL_MFPEVX);
    }

    PH_CHECK_SUCCESS_FCT(statusTmp,
        phCryptoSym_DiversifyDirectKey(pDataParams->pCryptoDiversifyDataParams,
            PH_CRYPTOSYM_DIV_MODE_MIFARE_PLUS,
            aKey,
            wKeyType,
            pDivInput,
            bLenDivInput,
            aKey));
  }

  /* Load the IC Upgrade key. */
  PH_CHECK_SUCCESS_FCT(statusTmp, phCryptoSym_LoadKeyDirect(
          pDataParams->pCryptoDataParamsMac,
          aKey,
          wKeyType));

  /* Load Zero IV. */
  PH_CHECK_SUCCESS_FCT(statusTmp, phCryptoSym_LoadIv(
          pDataParams->pCryptoDataParamsMac,
          phalMfpEVx_Sw_FirstIv,
          PH_CRYPTOSYM_AES_BLOCK_SIZE));

  /* Clear the command buffer to form the data to be maced with IC Upgrade key. */
  (void)memset(aCmdBuffer, 0x00, (size_t)sizeof(aCmdBuffer));

  /* ICUpgradeKey calculation. */
  /* As per artf833930. UpgradeKey = PRF ( ICUpgradeKey, 0x96 || 0x69 || 0x00 || 0x01 || 0x00 || 0x80 || UpgradeInfo )*/
  bCmdBufLen = 0;
  aCmdBuffer[bCmdBufLen++] = 0x96;
  aCmdBuffer[bCmdBufLen++] = 0x69;
  aCmdBuffer[bCmdBufLen++] = 0x00;
  aCmdBuffer[bCmdBufLen++] = 0x01;
  aCmdBuffer[bCmdBufLen++] = 0x00;
  aCmdBuffer[bCmdBufLen++] = 0x80;
  aCmdBuffer[bCmdBufLen++] = bUpgradeInfo;

  /* Compute MAC to perform PRF of the data and arrive at Upgradekey. */
  PH_CHECK_SUCCESS_FCT(statusTmp, phCryptoSym_CalculateMac(
          pDataParams->pCryptoDataParamsMac,
          (PH_CRYPTOSYM_MAC_MODE_CMAC | PH_EXCHANGE_DEFAULT),
          aCmdBuffer,
          bCmdBufLen,
          aUpgradeKey,
          &bKeyLen));

  /* Load the Upgrade key. */
  PH_CHECK_SUCCESS_FCT(statusTmp, phCryptoSym_LoadKeyDirect(
          pDataParams->pCryptoDataParamsEnc,
          aUpgradeKey,
          wKeyType));

  /* Load Zero IV. */
  PH_CHECK_SUCCESS_FCT(statusTmp, phCryptoSym_LoadIv(
          pDataParams->pCryptoDataParamsEnc,
          phalMfpEVx_Sw_FirstIv,
          PH_CRYPTOSYM_AES_BLOCK_SIZE));

  /* Clear the command buffer to frame the first part of the command to be sent AuthenticatePDC. */
  (void)memset(aCmdBuffer, 0x00, (size_t)sizeof(aCmdBuffer));

  /* Frame the command*/
  bCmdBufLen = 0;
  aCmdBuffer[bCmdBufLen++] = PHAL_MFPEVX_CMD_AUTH_PDC;
  aCmdBuffer[bCmdBufLen++] = (uint8_t)(wBlockNr & 0x00FFU);        /* LSB */
  aCmdBuffer[bCmdBufLen++] = (uint8_t)((wBlockNr & 0xFF00U) >> 8U); /* MSB */
  aCmdBuffer[bCmdBufLen++] = 0x01;                                /* Upgrade Info Length */
  aCmdBuffer[bCmdBufLen++] = bUpgradeInfo;                        /* Upgrade Info value */

  /* Exchange command */
  /* Check if ISO 7816-4 wapping is required */
  if (0U != (pDataParams->bWrappedMode)) {
    PH_CHECK_SUCCESS_FCT(statusTmp, phalMfpEVx_Int_Send7816Apdu(
            pDataParams->pPalMifareDataParams,
            PH_EXCHANGE_DEFAULT,
            (uint16_t)(((uint16_t)bCmdBufLen) - 1U)  /* Excluding the command code */,
            pDataParams->bExtendedLenApdu,
            aCmdBuffer,
            bCmdBufLen,     /* Command code is included as part of length. */
            &pResponse,
            &wRxLength));
  } else {
    PH_CHECK_SUCCESS_FCT(statusTmp, phpalMifare_ExchangeL4(
            pDataParams->pPalMifareDataParams,
            PH_EXCHANGE_DEFAULT,
            aCmdBuffer,
            bCmdBufLen,
            &pResponse,
            &wRxLength));
  }

  /* Check the response */
  PH_CHECK_SUCCESS_FCT(statusTmp, phalMfpEVx_Int_ComputeErrorResponse(wRxLength, pResponse[0],
          PH_ON));

  /* Load Zero IV. */
  PH_CHECK_SUCCESS_FCT(statusTmp, phCryptoSym_LoadIv(
          pDataParams->pCryptoDataParamsEnc,
          phalMfpEVx_Sw_FirstIv,
          PH_CRYPTOSYM_AES_BLOCK_SIZE));

  /* Decrypt the data using Upgrade Key and get RndB. */
  PH_CHECK_SUCCESS_FCT(statusTmp, phCryptoSym_Decrypt(
          pDataParams->pCryptoDataParamsEnc,
          (PH_CRYPTOSYM_CIPHER_MODE_CBC | PH_EXCHANGE_DEFAULT),
          &pResponse[1],
          PH_CRYPTOSYM_AES_BLOCK_SIZE,
          bRndB
      ));

  /* Perform a shift on RndB to arrive at RndB'. */
  bRndB[PH_CRYPTOSYM_AES_BLOCK_SIZE] = bRndB[0];

  /* Perform second part of authentication i.e. AuthenticateContinue. */
  /* Generate RndA. */
  PH_CHECK_SUCCESS_FCT(statusTmp, phCryptoRng_Rnd(
          pDataParams->pCryptoRngDataParams,
          PH_CRYPTOSYM_AES_BLOCK_SIZE,
          bRndA
      ));

  /* Load Zero IV. */
  PH_CHECK_SUCCESS_FCT(statusTmp, phCryptoSym_LoadIv(
          pDataParams->pCryptoDataParamsEnc,
          phalMfpEVx_Sw_FirstIv,
          PH_CRYPTOSYM_AES_BLOCK_SIZE));

  /* Form the command for second part of the authhentication sequence. */
  bCmdBufLen = 0;
  aCmdBuffer[bCmdBufLen++] = PHAL_MFPEVX_CMD_AUTH2;

  /* Encrypt RndA and append to the command buffer. */
  PH_CHECK_SUCCESS_FCT(statusTmp, phCryptoSym_Encrypt(
          pDataParams->pCryptoDataParamsEnc,
          PH_EXCHANGE_BUFFER_CONT | PH_CRYPTOSYM_CIPHER_MODE_CBC,
          bRndA,
          PH_CRYPTOSYM_AES_BLOCK_SIZE,
          &aCmdBuffer[bCmdBufLen]
      ));

  bCmdBufLen += PH_CRYPTOSYM_AES_BLOCK_SIZE;

  /* Encrypt shifted RndB */
  PH_CHECK_SUCCESS_FCT(statusTmp, phCryptoSym_Encrypt(
          pDataParams->pCryptoDataParamsEnc,
          PH_EXCHANGE_BUFFER_LAST | PH_CRYPTOSYM_CIPHER_MODE_CBC,
          &bRndB[1],
          PH_CRYPTOSYM_AES_BLOCK_SIZE,
          &aCmdBuffer[bCmdBufLen]
      ));

  bCmdBufLen += PH_CRYPTOSYM_AES_BLOCK_SIZE;

  /* Exchange the second part of the auth command. */
  /* Check if ISO 7816-4 wapping is required */
  if (0U != (pDataParams->bWrappedMode)) {
    /* Exchange frame */
    PH_CHECK_SUCCESS_FCT(statusTmp, phalMfpEVx_Int_Send7816Apdu(
            pDataParams->pPalMifareDataParams,
            PH_EXCHANGE_DEFAULT,
            (uint16_t)(((uint16_t)bCmdBufLen) - 1U /* Excluding the command code */),
            pDataParams->bExtendedLenApdu,
            aCmdBuffer,
            bCmdBufLen,     /* Command code is included as part of length. */
            &pResponse,
            &wRxLength));
  } else {
    PH_CHECK_SUCCESS_FCT(statusTmp, phpalMifare_ExchangeL4(
            pDataParams->pPalMifareDataParams,
            PH_EXCHANGE_DEFAULT,
            aCmdBuffer,
            bCmdBufLen,
            &pResponse,
            &wRxLength));
  }

  /* Check the response */
  PH_CHECK_SUCCESS_FCT(statusTmp, phalMfpEVx_Int_ComputeErrorResponse(wRxLength, pResponse[0],
          PH_ON));

  /* Decrypt the received data to get RndA'. */
  /* Load default init vector */
  PH_CHECK_SUCCESS_FCT(statusTmp, phCryptoSym_LoadIv(
          pDataParams->pCryptoDataParamsEnc,
          phalMfpEVx_Sw_FirstIv,
          PH_CRYPTOSYM_AES_BLOCK_SIZE));

  /* The decryption key available. Decrypt the response  */
  PH_CHECK_SUCCESS_FCT(statusTmp, phCryptoSym_Decrypt(
          pDataParams->pCryptoDataParamsEnc,
          PH_CRYPTOSYM_CIPHER_MODE_CBC,
          &pResponse[1],
          PH_CRYPTOSYM_AES_BLOCK_SIZE << 1U,
          &pResponse[1]
      ));

  /* Shift of RND A */
  pResponse[0] = pResponse[PH_CRYPTOSYM_AES_BLOCK_SIZE];

  /* Now perform the comparison. */
  if (memcmp(bRndA, &pResponse[0], PH_CRYPTOSYM_AES_BLOCK_SIZE) != 0) {
    /* RndA and RndA' don't match */
    return PH_ADD_COMPCODE_FIXED(PH_ERR_AUTH_ERROR, PH_COMP_AL_MFPEVX);
  }

  return PH_ERR_SUCCESS;
}

phStatus_t
phalMfpEVx_Sw_AuthenticateGeneral(phalMfpEVx_Sw_DataParams_t *pDataParams,
    uint8_t bLayer4Comm, uint8_t bFirstAuth, uint16_t wBlockNr,
    uint16_t wKeyNumber, uint16_t wKeyVersion, uint8_t bLenDivInput, uint8_t *pDivInput,
    uint8_t bLenPcdCap2, uint8_t *pPcdCap2In,
    uint8_t *pPcdCap2Out, uint8_t *pPdCap2)
{
  phStatus_t  PH_MEMLOC_REM statusTmp;
  uint8_t    *PH_MEMLOC_REM pResponse = NULL;
  uint16_t    PH_MEMLOC_REM wRxLength = 0;
  uint8_t     PH_MEMLOC_REM pHeader[39];
  uint8_t     PH_MEMLOC_REM bHeaderLength = 0;
  uint8_t     PH_MEMLOC_REM aKey[PH_CRYPTOSYM_AES128_KEY_SIZE];
  uint16_t    PH_MEMLOC_REM wKeyType;
  uint8_t     PH_MEMLOC_REM bRndA[PH_CRYPTOSYM_AES_BLOCK_SIZE];
  uint8_t     PH_MEMLOC_REM bRndB[PH_CRYPTOSYM_AES_BLOCK_SIZE + 1U];
  uint8_t     PH_MEMLOC_REM aIv[PH_CRYPTOSYM_AES_BLOCK_SIZE];
  uint8_t     PH_MEMLOC_REM bTemp[6];

  (void)memset(bTemp, 0x00, (size_t)sizeof(bTemp));

  /* Perform Argument validation */
  if (pPcdCap2In == NULL) {
    /* Work around. Since the next operation will throw Seg fault if NULL is
     * sent by the application
     */
    pPcdCap2In =  &bTemp[0];
  }
  /* Check if PCDCap2[0] consists of value for EV0 and EV1 secure message.
   * As per the ref arch 0.06, Section: 11.3.2.
   * If PcdCap[0] = 0x00, then EV0 secure messaging applies.
   * If PcdCap[0] = 0x01, then EV1 secure messaging applies.
   */
  if (pPcdCap2In[0] > PHAL_MFPEVX_SECURE_MESSAGE_EV1) {
    return PH_ADD_COMPCODE_FIXED(PH_ERR_INVALID_PARAMETER, PH_COMP_AL_MFPEVX);
  }

  /* parameter checking */
  if (((bLenPcdCap2 > 0U) && (pPcdCap2In == NULL)) || (bLenPcdCap2 > 6U)) {
    return PH_ADD_COMPCODE_FIXED(PH_ERR_INVALID_PARAMETER, PH_COMP_AL_MFPEVX);
  }

  /* In case of first auth or layer 3 communication we need to reset the secure messaging layer */
  if ((bFirstAuth != 0U) || (bLayer4Comm == 0U)) {
    PH_CHECK_SUCCESS_FCT(statusTmp, phalMfpEVx_Sw_ResetSecMsgState(pDataParams));
  }

  /* Update the Secure messaging data to internal dataparams. */

  if (0U != (bFirstAuth)) {
    pDataParams->bSMMode = pPcdCap2In[0];
  }

  /* Create First Part of the Message */
  if (bFirstAuth ==  0x01) {
    pHeader[bHeaderLength++] = PHAL_MFPEVX_CMD_AUTH1_FIRST;
  } else if (bFirstAuth == 0x02) {
    pHeader[bHeaderLength++] = PHAL_MFPEVX_CMD_AUTH_FIRST_ALTERNATE;
  } else {
    pHeader[bHeaderLength++] = PHAL_MFPEVX_CMD_AUTH1;
  }

  /* wBlockNr */
  pHeader[bHeaderLength++] = (uint8_t)(wBlockNr & 0xFFU); /* LSB */
  pHeader[bHeaderLength++] = (uint8_t)(wBlockNr >> 8U);   /* MSB */

  /* exchange command/response */
  if (0U != (bLayer4Comm)) {
    /* Add PCDcap length in case of auth first */
    if ((bFirstAuth == 1U) || (bFirstAuth == 2U)) {
      pHeader[bHeaderLength++] = bLenPcdCap2;
    }
    /* No PCDcaps in Non-First authenticate */
    else {
      bLenPcdCap2 = 0;
    }

    /* Check if ISO 7816-4 wapping is required */
    if (0U != (pDataParams->bWrappedMode)) {
      /* buffer the header */
      PH_CHECK_SUCCESS_FCT(statusTmp, phalMfpEVx_Int_Send7816Apdu(
              pDataParams->pPalMifareDataParams,
              PH_EXCHANGE_BUFFER_FIRST,
              (uint16_t)((((uint16_t)bHeaderLength) - 1U /* Excluding the command code */) + ((
                          uint16_t)bLenPcdCap2)),
              pDataParams->bExtendedLenApdu,
              pHeader,
              bHeaderLength,      /* Command code is included as part of length. */
              NULL,
              NULL));

      /* Append the PcdCaps and exchange frame */
      PH_CHECK_SUCCESS_FCT(statusTmp, phalMfpEVx_Int_Send7816Apdu(
              pDataParams->pPalMifareDataParams,
              PH_EXCHANGE_BUFFER_LAST,
              0x00,               /* Lc is zero because the length is updated in the first call. */
              pDataParams->bExtendedLenApdu,
              pPcdCap2In,
              bLenPcdCap2,
              &pResponse,
              &wRxLength));
    } else {
      /* buffer the header */
      PH_CHECK_SUCCESS_FCT(statusTmp, phpalMifare_ExchangeL4(
              pDataParams->pPalMifareDataParams,
              PH_EXCHANGE_BUFFER_FIRST,
              pHeader,
              bHeaderLength,
              NULL,
              NULL));

      /* Append the PcdCaps and exchange frame */
      PH_CHECK_SUCCESS_FCT(statusTmp, phpalMifare_ExchangeL4(
              pDataParams->pPalMifareDataParams,
              PH_EXCHANGE_BUFFER_LAST,
              pPcdCap2In,
              bLenPcdCap2,
              &pResponse,
              &wRxLength));
    }
  } else {
    /* Add PCDcap length (0x00) in case of auth first */
    if ((bFirstAuth == 1U) || (bFirstAuth == 2U)) {
      pHeader[bHeaderLength++] = 0x00;
    }

    /* command exchange */
    PH_CHECK_SUCCESS_FCT(statusTmp, phpalMifare_ExchangeL3(
            pDataParams->pPalMifareDataParams,
            PH_EXCHANGE_DEFAULT,
            pHeader,
            bHeaderLength,
            &pResponse,
            &wRxLength));
  }

  /* Check the response */
  PH_CHECK_SUCCESS_FCT(statusTmp, phalMfpEVx_Int_ComputeErrorResponse(wRxLength, pResponse[0],
          bLayer4Comm));

  if (wRxLength != (1U /* status */ + PH_CRYPTOSYM_AES_BLOCK_SIZE /* ENC(RNDB) */)) {
    return PH_ADD_COMPCODE_FIXED(PH_ERR_PROTOCOL_ERROR, PH_COMP_AL_MFPEVX);
  }

  /* Set first Read Flag to 1 */
  pDataParams->bFirstRead = 1;

  /* We also need to reset the unprocessed read MAC bytes according to specification */
  pDataParams->bNumUnprocessedReadMacBytes = 0;

  /* Get Key out of the key store object */
  PH_CHECK_SUCCESS_FCT(statusTmp, phKeyStore_GetKey(
          pDataParams->pKeyStoreDataParams,
          wKeyNumber,
          wKeyVersion,
          sizeof(aKey),
          aKey,
          &wKeyType));

  /* Key type check */
  if (wKeyType != PH_CRYPTOSYM_KEY_TYPE_AES128) {
    return PH_ADD_COMPCODE_FIXED(PH_ERR_INVALID_PARAMETER, PH_COMP_AL_MFPEVX);
  }

  /* Do we need to diversify the key? */
  if (0U != bLenDivInput) {
    if (pDataParams->pCryptoDiversifyDataParams == NULL) {
      return PH_ADD_COMPCODE_FIXED(PH_ERR_UNSUPPORTED_COMMAND, PH_COMP_AL_MFPEVX);
    }

    PH_CHECK_SUCCESS_FCT(statusTmp,
        phCryptoSym_DiversifyDirectKey(pDataParams->pCryptoDiversifyDataParams,
            PH_CRYPTOSYM_DIV_MODE_MIFARE_PLUS,
            aKey,
            wKeyType,
            pDivInput,
            bLenDivInput,
            aKey));
  }

  /* Load the key*/
  PH_CHECK_SUCCESS_FCT(statusTmp, phCryptoSym_LoadKeyDirect(
          pDataParams->pCryptoDataParamsEnc,
          aKey,
          wKeyType));

  /* EV0 Secure Messaging:
   *      The calculated IV is loaded for Authenticate NonFirst ( AUTHN ) only.
   *      For Authenticate First ( AUTHF ) zero IV should be loaded.
   *
   * EV1 Secure Messaging:
   *      For both Authenticate First ( AUTHF ) and Authenticate NonFirst ( AUTHN ), Zero IV is loaded.
   *
   * bSMMode = 0x00 ( EV0 Secure Messaging ), bFirst = 0x01 ( First Auth ), IV will not be calculated.
   * bSMMode = 0x00 ( EV0 Secure Messaging ), bFirst = 0x00 ( Following Auth ), IV will be calculated.
   *
   * bSMMode = 0x01 ( EV1 Secure Messaging ), bFirst = 0x01 ( First Auth ), IV will not be calculated.
   * bSMMode = 0x01 ( EV1 Secure Messaging ), bFirst = 0x00 ( Following Auth ), IV will not be calculated.
   *
   * Mentioned in the section decribing for computing the IV for command and response in the ref arch.
   */
  if ((bFirstAuth == 0U) && (pDataParams->bSMMode == PHAL_MFPEVX_SECURE_MESSAGE_EV0)) {
    PH_CHECK_SUCCESS_FCT(statusTmp, phalMfpEVx_Sw_Int_ComputeIv(
            pDataParams,
            PH_ON, /* Response */
            pDataParams->bTi,
            pDataParams->wRCtr,
            pDataParams->wWCtr,
            aIv));

    PH_CHECK_SUCCESS_FCT(statusTmp, phCryptoSym_LoadIv(
            pDataParams->pCryptoDataParamsEnc,
            aIv,
            PH_CRYPTOSYM_AES_BLOCK_SIZE));
  } else {
    PH_CHECK_SUCCESS_FCT(statusTmp, phCryptoSym_LoadIv(
            pDataParams->pCryptoDataParamsEnc,
            phalMfpEVx_Sw_FirstIv,
            PH_CRYPTOSYM_AES_BLOCK_SIZE));
  }

  /* Decrypt the data key is already loaded. */
  PH_CHECK_SUCCESS_FCT(statusTmp, phCryptoSym_Decrypt(
          pDataParams->pCryptoDataParamsEnc,
          PH_EXCHANGE_BUFFER_CONT | PH_CRYPTOSYM_CIPHER_MODE_CBC,
          &pResponse[1],
          PH_CRYPTOSYM_AES_BLOCK_SIZE,
          bRndB
      ));

  /* Also perform the shift. */
  bRndB[PH_CRYPTOSYM_AES_BLOCK_SIZE] = bRndB[0];

  /* Start with part 2 of Authenticate MFP */

  /* Compute second part of the Auth sequence */
  bHeaderLength = 0;
  pHeader[bHeaderLength++] = PHAL_MFPEVX_CMD_AUTH2;

  /* Generate RND A */
  PH_CHECK_SUCCESS_FCT(statusTmp, phCryptoRng_Rnd(
          pDataParams->pCryptoRngDataParams,
          PH_CRYPTOSYM_AES_BLOCK_SIZE,
          bRndA
      ));

  /* EV0 Secure Messaging:
   *      The calculated IV is loaded for Authenticate NonFirst ( AUTHN ) only.
   *      For Authenticate First ( AUTHF ) zero IV should be loaded.
   *
   * EV1 Secure Messaging:
   *      For both Authenticate First ( AUTHF ) and Authenticate NonFirst ( AUTHN ), Zero IV is loaded.
   *
   * bSMMode = 0x00 ( EV0 Secure Messaging ), bFirst = 0x01 ( First Auth ), IV will not be calculated.
   * bSMMode = 0x00 ( EV0 Secure Messaging ), bFirst = 0x00 ( Following Auth ), IV will be calculated.
   *
   * bSMMode = 0x01 ( EV1 Secure Messaging ), bFirst = 0x01 ( First Auth ), IV will not be calculated.
   * bSMMode = 0x01 ( EV1 Secure Messaging ), bFirst = 0x00 ( Following Auth ), IV will not be calculated.
   *
   * Mentioned in the section decribing for computing the IV for command and response in the ref arch.
   */
  if ((bFirstAuth == 0U) && (pDataParams->bSMMode == PHAL_MFPEVX_SECURE_MESSAGE_EV0)) {
    PH_CHECK_SUCCESS_FCT(statusTmp, phalMfpEVx_Sw_Int_ComputeIv(
            pDataParams,
            PH_OFF, /* No Response */
            pDataParams->bTi,
            pDataParams->wRCtr,
            pDataParams->wWCtr,
            aIv));

    PH_CHECK_SUCCESS_FCT(statusTmp, phCryptoSym_LoadIv(
            pDataParams->pCryptoDataParamsEnc,
            aIv,
            PH_CRYPTOSYM_AES_BLOCK_SIZE));
  } else {
    PH_CHECK_SUCCESS_FCT(statusTmp, phCryptoSym_LoadIv(
            pDataParams->pCryptoDataParamsEnc,
            phalMfpEVx_Sw_FirstIv,
            PH_CRYPTOSYM_AES_BLOCK_SIZE));
  }

  /* Encrypt RndA */
  PH_CHECK_SUCCESS_FCT(statusTmp, phCryptoSym_Encrypt(
          pDataParams->pCryptoDataParamsEnc,
          PH_EXCHANGE_BUFFER_CONT | PH_CRYPTOSYM_CIPHER_MODE_CBC,
          bRndA,
          PH_CRYPTOSYM_AES_BLOCK_SIZE,
          &pHeader[bHeaderLength]
      ));

  bHeaderLength += PH_CRYPTOSYM_AES_BLOCK_SIZE;

  /* Encrypt shifted RndB */
  PH_CHECK_SUCCESS_FCT(statusTmp, phCryptoSym_Encrypt(
          pDataParams->pCryptoDataParamsEnc,
          PH_EXCHANGE_BUFFER_LAST | PH_CRYPTOSYM_CIPHER_MODE_CBC,
          &bRndB[1],
          PH_CRYPTOSYM_AES_BLOCK_SIZE,
          &pHeader[bHeaderLength]
      ));

  bHeaderLength += PH_CRYPTOSYM_AES_BLOCK_SIZE;

  /* command exchange */
  if (0U != (bLayer4Comm)) {
    /* Check if ISO 7816-4 wapping is required */
    if (0U != (pDataParams->bWrappedMode)) {
      /* Exchange frame */
      PH_CHECK_SUCCESS_FCT(statusTmp, phalMfpEVx_Int_Send7816Apdu(
              pDataParams->pPalMifareDataParams,
              PH_EXCHANGE_DEFAULT,
              (((uint16_t)bHeaderLength) - 1U  /* Excluding the command code */),
              pDataParams->bExtendedLenApdu,
              pHeader,
              bHeaderLength,      /* Command code is included as part of length. */
              &pResponse,
              &wRxLength));
    } else {
      PH_CHECK_SUCCESS_FCT(statusTmp, phpalMifare_ExchangeL4(
              pDataParams->pPalMifareDataParams,
              PH_EXCHANGE_DEFAULT,
              pHeader,
              bHeaderLength,
              &pResponse,
              &wRxLength));
    }
  } else {
    PH_CHECK_SUCCESS_FCT(statusTmp, phpalMifare_ExchangeL3(
            pDataParams->pPalMifareDataParams,
            PH_EXCHANGE_DEFAULT,
            pHeader,
            bHeaderLength,
            &pResponse,
            &wRxLength));
  }

  /* Check the response */
  PH_CHECK_SUCCESS_FCT(statusTmp, phalMfpEVx_Int_ComputeErrorResponse(wRxLength, pResponse[0],
          bLayer4Comm));

  /* EV0 Secure Messaging:
   *      The calculated IV is loaded for Authenticate NonFirst ( AUTHN ) only.
   *      For Authenticate First ( AUTHF ) zero IV should be loaded.
   *
   * EV1 Secure Messaging:
   *      For both Authenticate First ( AUTHF ) and Authenticate NonFirst ( AUTHN ), Zero IV is loaded.
   *
   * bSMMode = 0x00 ( EV0 Secure Messaging ), bFirst = 0x01 ( First Auth ), IV will not be calculated.
   * bSMMode = 0x00 ( EV0 Secure Messaging ), bFirst = 0x00 ( Following Auth ), IV will be calculated.
   *
   * bSMMode = 0x01 ( EV1 Secure Messaging ), bFirst = 0x01 ( First Auth ), IV will not be calculated.
   * bSMMode = 0x01 ( EV1 Secure Messaging ), bFirst = 0x00 ( Following Auth ), IV will not be calculated.
   *
   * Mentioned in the section decribing for computing the IV for command and response in the ref arch.
   */

  if ((bFirstAuth == 0U) && (pDataParams->bSMMode == PHAL_MFPEVX_SECURE_MESSAGE_EV0)) {
    /* Decrypt the data key is already loaded. */
    PH_CHECK_SUCCESS_FCT(statusTmp, phalMfpEVx_Sw_Int_ComputeIv(
            pDataParams,
            PH_ON, /* Response */
            pDataParams->bTi,
            pDataParams->wRCtr,
            pDataParams->wWCtr,
            aIv));

    PH_CHECK_SUCCESS_FCT(statusTmp, phCryptoSym_LoadIv(
            pDataParams->pCryptoDataParamsEnc,
            aIv,
            PH_CRYPTOSYM_AES_BLOCK_SIZE));
  } else {
    PH_CHECK_SUCCESS_FCT(statusTmp, phCryptoSym_LoadIv(
            pDataParams->pCryptoDataParamsEnc,
            phalMfpEVx_Sw_FirstIv,
            PH_CRYPTOSYM_AES_BLOCK_SIZE));
  }

  if (0U != (bFirstAuth)) {
    if (wRxLength != (1U /* status */ + (4U + PH_CRYPTOSYM_AES_BLOCK_SIZE +
                12U) /* ENC(TI | RNDA' | Capabilities) */)) {
      return PH_ADD_COMPCODE_FIXED(PH_ERR_PROTOCOL_ERROR, PH_COMP_AL_MFPEVX);
    }

    /* Decrypt the data key is already loaded, pMac is used as temporary buffer. */
    PH_CHECK_SUCCESS_FCT(statusTmp, phCryptoSym_Decrypt(
            pDataParams->pCryptoDataParamsEnc,
            PH_CRYPTOSYM_CIPHER_MODE_CBC,
            &pResponse[1],
            PH_CRYPTOSYM_AES_BLOCK_SIZE * 2U,
            &pResponse[1]
        ));

    /* First save the TI as we are then going to overwrite */
    (void)memcpy(pDataParams->bTi, &pResponse[1], PHAL_MFPEVX_SIZE_TI);

    /* Shift of RND A */
    pResponse[4] = pResponse[4U + PH_CRYPTOSYM_AES_BLOCK_SIZE];

    /* Now perform the comparison */
    if (memcmp(bRndA, &pResponse[4], PH_CRYPTOSYM_AES_BLOCK_SIZE) != 0) {
      /* RndA and RndA' don't match */
      return PH_ADD_COMPCODE_FIXED(PH_ERR_AUTH_ERROR, PH_COMP_AL_MFPEVX);
    }

    (void)memmove(pPdCap2, &pResponse[21], 6);

    (void)memmove(pPcdCap2Out, &pResponse[27], 6);
  } else {
    /* Check response length */
    if (wRxLength != (1U /* status */ + PH_CRYPTOSYM_AES_BLOCK_SIZE /* ENC(RNDA') */)) {
      return PH_ADD_COMPCODE_FIXED(PH_ERR_PROTOCOL_ERROR, PH_COMP_AL_MFPEVX);
    }

    PH_CHECK_SUCCESS_FCT(statusTmp, phCryptoSym_Decrypt(
            pDataParams->pCryptoDataParamsEnc,
            PH_EXCHANGE_BUFFER_CONT | PH_CRYPTOSYM_CIPHER_MODE_CBC,
            &pResponse[1],
            PH_CRYPTOSYM_AES_BLOCK_SIZE,
            &pResponse[1]
        ));

    /* Shift RNDA' */
    pResponse[0] = pResponse[PH_CRYPTOSYM_AES_BLOCK_SIZE];

    /* Now perform the comparison */
    if (memcmp(bRndA, pResponse, PH_CRYPTOSYM_AES_BLOCK_SIZE) != 0) {
      /* RndA and RndA' don't match */
      return PH_ADD_COMPCODE_FIXED(PH_ERR_AUTH_ERROR, PH_COMP_AL_MFPEVX);
    }
  }

  /* Check if PICC capabilities indicated EV0 and EV1 secure messaging.
   * As per the ref arch 0.06, Section: 11.3.2.
   * If PdCap[0] = 0x00, then EV0 secure messaging applies.
   * If PdCap[0] = 0x01, then EV1 secure messaging applies.
   */

  if ((bFirstAuth != 0U) && (pDataParams->bSMMode == PHAL_MFPEVX_SECURE_MESSAGE_EV0) &&
      (pPdCap2[0] == PHAL_MFPEVX_SECURE_MESSAGE_EV1)) {
    return PH_ADD_COMPCODE_FIXED(PH_ERR_PROTOCOL_ERROR, PH_COMP_AL_MFPEVX);
  }

  if (pDataParams->bSMMode == PHAL_MFPEVX_SECURE_MESSAGE_EV0) {
    PH_CHECK_SUCCESS_FCT(statusTmp, phalMfpEVx_Sw_Int_KDF_EV0(pDataParams, bRndA, bRndB));
  } else {
    PH_CHECK_SUCCESS_FCT(statusTmp, phalMfpEVx_Sw_Int_KDF_EV1(pDataParams, bRndA, bRndB));
  }

  /* Reset the read and write counter in case of First Auth. */
  if ((bFirstAuth == 1U) || (bFirstAuth == 2U)) {
    pDataParams->wWCtr = 0;
    pDataParams->wRCtr = 0;
  }

  /* In case of Originality Key - reset secure messaging */
  if ((wBlockNr >= PHAL_MFPEVX_ORIGINALITY_KEY_FIRST) &&
      (wBlockNr <= PHAL_MFPEVX_ORIGINALITY_KEY_LAST)) {
    PH_CHECK_SUCCESS_FCT(statusTmp, phalMfpEVx_Sw_ResetSecMsgState(pDataParams));
  }

  return PH_ERR_SUCCESS;
}

phStatus_t
phalMfpEVx_Sw_Int_KDF_EV0(phalMfpEVx_Sw_DataParams_t *pDataParams, uint8_t *pRndA,
    uint8_t *pRndB)
{
  phStatus_t  PH_MEMLOC_REM statusTmp;
  uint8_t     PH_MEMLOC_REM bSv[PH_CRYPTOSYM_AES_BLOCK_SIZE];

  /*
   * As per ref arch v0.06, section 11.2.7.1,
   * Session ENC key generation. Below is the data for SV1.
   * Sv1 = RndA[4...0] || RndB[4...0] || RndA[11...7]  xor RndB[11...7]  || 0x11
   * Sv2 = RndA[8...4] || RndB[8...4] || RndA[15...11] xor RndB[15...11] || 0x22
   * Ke (Session ENC key) = PRF(Kx, SV1)
   * Km (Session MAC key) = PRF(Kx, SV2)
   * Kx (AES Key)
   */

  bSv[0] = pRndA[11];
  bSv[1] = pRndA[12];
  bSv[2] = pRndA[13];
  bSv[3] = pRndA[14];
  bSv[4] = pRndA[15];

  bSv[5] = pRndB[11];
  bSv[6] = pRndB[12];
  bSv[7] = pRndB[13];
  bSv[8] = pRndB[14];
  bSv[9] = pRndB[15];

  bSv[10] = pRndA[4] ^ pRndB[4];
  bSv[11] = pRndA[5] ^ pRndB[5];
  bSv[12] = pRndA[6] ^ pRndB[6];
  bSv[13] = pRndA[7] ^ pRndB[7];
  bSv[14] = pRndA[8] ^ pRndB[8];

  bSv[15] = 0x11;

  /* Generate Session ENC key and store it in the global structure. */
  PH_CHECK_SUCCESS_FCT(statusTmp, phCryptoSym_Encrypt(
          pDataParams->pCryptoDataParamsEnc,
          PH_CRYPTOSYM_CIPHER_MODE_ECB,
          &bSv[0],
          PH_CRYPTOSYM_AES_BLOCK_SIZE,
          pDataParams->bSesAuthENCKey
      ));

  /*
   * As per ref arch v0.06, section 11.2.7.1,
   * Session MAC key generation. Below is the data for SV2.
   * Sv1 = RndA[4...0] || RndB[4...0] || RndA[11...7]  xor RndB[11...7]  || 0x11
   * Sv2 = RndA[8...4] || RndB[8...4] || RndA[15...11] xor RndB[15...11] || 0x22
   * Ke (Session ENC key) = PRF(Kx, SV1)
   * Km (Session MAC key) = PRF(Kx, SV2)
   * Kx (AES Key)
   */

  bSv[0] = pRndA[7];
  bSv[1] = pRndA[8];
  bSv[2] = pRndA[9];
  bSv[3] = pRndA[10];
  bSv[4] = pRndA[11];

  bSv[5] = pRndB[7];
  bSv[6] = pRndB[8];
  bSv[7] = pRndB[9];
  bSv[8] = pRndB[10];
  bSv[9] = pRndB[11];

  bSv[10] = pRndA[0] ^ pRndB[0];
  bSv[11] = pRndA[1] ^ pRndB[1];
  bSv[12] = pRndA[2] ^ pRndB[2];
  bSv[13] = pRndA[3] ^ pRndB[3];
  bSv[14] = pRndA[4] ^ pRndB[4];

  bSv[15] = 0x22;

  /* Generate Session MAC key and store it in the global structure. */
  PH_CHECK_SUCCESS_FCT(statusTmp, phCryptoSym_Encrypt(
          pDataParams->pCryptoDataParamsEnc,
          PH_CRYPTOSYM_CIPHER_MODE_ECB,
          &bSv[0],
          PH_CRYPTOSYM_AES_BLOCK_SIZE,
          pDataParams->bSesAuthMACKey
      ));

  /* Load Key SV1 ENC key */
  PH_CHECK_SUCCESS_FCT(statusTmp, phCryptoSym_LoadKeyDirect(
          pDataParams->pCryptoDataParamsEnc,
          pDataParams->bSesAuthENCKey,
          PH_CRYPTOSYM_KEY_TYPE_AES128));

  /* Load Key SV2 MAC key */
  PH_CHECK_SUCCESS_FCT(statusTmp, phCryptoSym_LoadKeyDirect(
          pDataParams->pCryptoDataParamsMac,
          pDataParams->bSesAuthMACKey,
          PH_CRYPTOSYM_KEY_TYPE_AES128));

  return PH_ERR_SUCCESS;
}

phStatus_t
phalMfpEVx_Sw_Int_KDF_EV1(phalMfpEVx_Sw_DataParams_t *pDataParams, uint8_t *pRndA,
    uint8_t *pRndB)
{
  phStatus_t  PH_MEMLOC_REM statusTmp;
  uint8_t     PH_MEMLOC_REM bMacLen = 0;
  uint8_t     PH_MEMLOC_REM bSvLen = 0;
  uint8_t     PH_MEMLOC_REM bSv[PH_CRYPTOSYM_AES_BLOCK_SIZE * 2U];

  /*
   * As per ref arch v0.06, section 11.2.7.2,
   * Session ENC key generation. Below is the data for SV1 and SV2.
   * Sv1 = 0xA5 || 0x5A || 0x00 || 0x01 || 0x00 || 0x80 || RndA[15...14] || (RndA[13...8] xor RndB[15...10]) || RndB[9...0] || RndA[7...0]
   * Sv2 = 0x5A || 0xA5 || 0x00 || 0x01 || 0x00 || 0x80 || RndA[15...14] || (RndA[13...8] xor RndB[15...10]) || RndB[9...0] || RndA[7...0]
   * Ke (Session ENC key)       = PRF(Kx, SV1)
   * Km (Session MAC key)       = PRF(Kx, SV2)
   * Kx (AES Key)
   */
  bSv[bSvLen++] = 0xA5;
  bSv[bSvLen++] = 0x5A;
  bSv[bSvLen++] = 0x00;
  bSv[bSvLen++] = 0x01;
  bSv[bSvLen++] = 0x00;
  bSv[bSvLen++] = 0x80;

  bSv[bSvLen++] = pRndA[0];
  bSv[bSvLen++] = pRndA[1];

  bSv[bSvLen++] = pRndA[2] ^ pRndB[0];
  bSv[bSvLen++] = pRndA[3] ^ pRndB[1];
  bSv[bSvLen++] = pRndA[4] ^ pRndB[2];
  bSv[bSvLen++] = pRndA[5] ^ pRndB[3];
  bSv[bSvLen++] = pRndA[6] ^ pRndB[4];
  bSv[bSvLen++] = pRndA[7] ^ pRndB[5];

  (void)memcpy(&bSv[bSvLen], &pRndB[6], 10);
  bSvLen = bSvLen + 10U;

  (void)memcpy(&bSv[bSvLen], &pRndA[8], 8);
  bSvLen = bSvLen + 8U;

  /* Load IV */
  PH_CHECK_SUCCESS_FCT(statusTmp, phCryptoSym_LoadIv(
          pDataParams->pCryptoDataParamsEnc,
          phalMfpEVx_Sw_FirstIv,
          PHAL_MFPEVX_SIZE_IV));

  /* Generate Session ENC key and store it in the global structure. */
  PH_CHECK_SUCCESS_FCT(statusTmp, phCryptoSym_CalculateMac(
          pDataParams->pCryptoDataParamsEnc,
          (PH_CRYPTOSYM_MAC_MODE_CMAC | PH_EXCHANGE_DEFAULT),
          &bSv[0],
          bSvLen,
          pDataParams->bSesAuthENCKey,
          &bMacLen
      ));

  /*
   * As per ref arch v0.06, section 11.2.7.2,
   * Session MAC key generation. Below is the data for Sv1 and Sv2.
   * Sv1 = 0xA5 || 0x5A || 0x00 || 0x01 || 0x00 || 0x80 || RndA[15...14] || (RndA[13...8] xor RndB[15...10]) || RndB[9...0] || RndA[7...0]
   * Sv2 = 0x5A || 0xA5 || 0x00 || 0x01 || 0x00 || 0x80 || RndA[15...14] || (RndA[13...8] xor RndB[15...10]) || RndB[9...0] || RndA[7...0]
   * Ke (Session ENC key)       = PRF(Kx, SV1)
   * Km (Session MAC key)       = PRF(Kx, SV2)
   * Kx (AES Key)
   */
  bSv[0] = 0x5A;
  bSv[1] = 0xA5;

  /* Load IV */
  PH_CHECK_SUCCESS_FCT(statusTmp, phCryptoSym_LoadIv(
          pDataParams->pCryptoDataParamsEnc,
          phalMfpEVx_Sw_FirstIv,
          PHAL_MFPEVX_SIZE_IV));

  /* Generate Session MAC key and store it in the global structure. */
  PH_CHECK_SUCCESS_FCT(statusTmp, phCryptoSym_CalculateMac(
          pDataParams->pCryptoDataParamsEnc,
          (PH_CRYPTOSYM_MAC_MODE_CMAC | PH_EXCHANGE_DEFAULT),
          &bSv[0],
          bSvLen,
          pDataParams->bSesAuthMACKey,
          &bMacLen
      ));

  /* Load session ENC key */
  PH_CHECK_SUCCESS_FCT(statusTmp, phCryptoSym_LoadKeyDirect(
          pDataParams->pCryptoDataParamsEnc,
          pDataParams->bSesAuthENCKey,
          PH_CRYPTOSYM_KEY_TYPE_AES128));

  /* Load session MAC key */
  PH_CHECK_SUCCESS_FCT(statusTmp, phCryptoSym_LoadKeyDirect(
          pDataParams->pCryptoDataParamsMac,
          pDataParams->bSesAuthMACKey,
          PH_CRYPTOSYM_KEY_TYPE_AES128));

  return PH_ERR_SUCCESS;
}

/***************************************************************************************************************************************/
/* Mifare Plus EVx Software command for data operations.                                                                               */
/***************************************************************************************************************************************/
phStatus_t
phalMfpEVx_Sw_Write(phalMfpEVx_Sw_DataParams_t *pDataParams, uint8_t bEncrypted,
    uint8_t bWriteMaced, uint16_t wBlockNr, uint8_t bNumBlocks,
    uint8_t *pBlocks, uint8_t *pTMC, uint8_t *pTMV)
{
  phStatus_t PH_MEMLOC_REM wStatus = 0;
  uint8_t    PH_MEMLOC_REM aCmd;

  /* Perform Write according to the auth mode.*/
  switch (pDataParams->bAuthMode) {
    /* Perform write command in MIFARE mode. (ISO14443 Layer 3 activated) */
    case PHAL_MFPEVX_NOT_AUTHENTICATED_L3:
    case PHAL_MFPEVX_SL1_MIFARE_AUTHENTICATED:
      PH_CHECK_SUCCESS_FCT(wStatus, phalMfpEVx_Sw_WriteExtMfc(
              pDataParams,
              PHAL_MFPEVX_CMD_MFC_WRITE,
              (uint8_t) wBlockNr,
              pBlocks,
              (((uint16_t)(bNumBlocks)) * PHAL_MFPEVX_DATA_BLOCK_SIZE),
              pTMC,
              pTMV));
      break;

    /* Perform write command in MFP mode. (ISO14443 Layer 4 activated) */
    case PHAL_MFPEVX_NOT_AUTHENTICATED_L4:
    case PHAL_MFPEVX_SL1_MFP_AUTHENTICATED:
    case PHAL_MFPEVX_SL3_MFP_AUTHENTICATED:
      /* If Mac on response is requested. */
      if (0U != (bWriteMaced)) {
        /* Should the data be encrypted. */
        if (0U != (bEncrypted)) {
          /* Write command for Encrypted data and MAC on response. */
          aCmd = PHAL_MFPEVX_CMD_WRITE_EM;
        } else {
          /* Write command for Plain data and MAC on response. */
          aCmd = PHAL_MFPEVX_CMD_WRITE_PM;
        }
      } else {
        /* Should the data be encrypted. */
        if (0U != (bEncrypted)) {
          /* Write command for Encrypted data and No MAC on response. */
          aCmd = PHAL_MFPEVX_CMD_WRITE_EN;
        } else {
          /* Write command for Plain data and No MAC on response. */
          aCmd = PHAL_MFPEVX_CMD_WRITE_PN;
        }
      }

      PH_CHECK_SUCCESS_FCT(wStatus, phalMfpEVx_Sw_WriteExt(
              pDataParams,
              aCmd,
              wBlockNr,
              0x00,
              pBlocks,
              (((uint16_t)(bNumBlocks)) * PHAL_MFPEVX_DATA_BLOCK_SIZE),
              bEncrypted,
              pTMC,
              pTMV));
      break;

    /* Return error in case of not authenticated in any one of the auth mode.*/
    default:
      return PH_ADD_COMPCODE_FIXED(PH_ERR_AUTH_ERROR, PH_COMP_AL_MFPEVX);
  }

  return PH_ERR_SUCCESS;
}

phStatus_t
phalMfpEVx_Sw_Read(phalMfpEVx_Sw_DataParams_t *pDataParams, uint8_t bEncrypted,
    uint8_t bReadMaced, uint8_t bMacOnCmd,
    uint16_t wBlockNr, uint8_t bNumBlocks, uint8_t *pBlocks)
{
  phStatus_t PH_MEMLOC_REM wStatus = 0;

  /* Perform Read according to the auth mode.*/
  switch (pDataParams->bAuthMode) {
    /* Perform read command in MIFARE mode. (ISO14443 Layer 3 activated) */
    case PHAL_MFPEVX_NOT_AUTHENTICATED_L3:
    case PHAL_MFPEVX_SL1_MIFARE_AUTHENTICATED:
      PH_CHECK_SUCCESS_FCT(wStatus, phalMfpEVx_Sw_ReadExtMfc(
              pDataParams,
              (uint8_t) wBlockNr,
              pBlocks));
      break;

    /* Perform read command in MFP mode. (ISO14443 Layer 4 activated) */
    case PHAL_MFPEVX_NOT_AUTHENTICATED_L4:
    case PHAL_MFPEVX_SL1_MFP_AUTHENTICATED:
    case PHAL_MFPEVX_SL3_MFP_AUTHENTICATED:
      PH_CHECK_SUCCESS_FCT(wStatus, phalMfpEVx_Sw_ReadExt(
              pDataParams,
              bEncrypted,
              bReadMaced,
              bMacOnCmd,
              wBlockNr,
              bNumBlocks,
              pBlocks));
      break;

    /* Return error in case of not authenticated in any one of the auth mode.*/
    default:
      return PH_ADD_COMPCODE_FIXED(PH_ERR_AUTH_ERROR, PH_COMP_AL_MFPEVX);
  }

  return PH_ERR_SUCCESS;
}

/***************************************************************************************************************************************/
/* Mifare Plus EVx Software command for value operations.                                                                              */
/***************************************************************************************************************************************/
phStatus_t
phalMfpEVx_Sw_WriteValue(phalMfpEVx_Sw_DataParams_t *pDataParams, uint8_t bEncrypted,
    uint8_t bWriteMaced, uint16_t wBlockNr, uint8_t *pValue,
    uint8_t bAddrData, uint8_t *pTMC, uint8_t *pTMV)
{
  phStatus_t PH_MEMLOC_REM wStatus = 0;
  uint8_t    PH_MEMLOC_REM aCmd;
  uint8_t pBlock[PHAL_MFPEVX_DATA_BLOCK_SIZE];

  /* Form the value to be written in block format.
   *               | 00 01 02 03 | 04 05 06 07 | 08 09 0A 0B |  0C  |    0D  |  0E  |   0F   |
   * Value Block = |    Value    |    ~Value   |    Value    | Addr | ~ Addr | Addr | ~ Addr |
   */
  PH_CHECK_SUCCESS_FCT(wStatus, phalMfpEVx_Int_CreateValueBlock(pValue, bAddrData, pBlock));

  /* Perform Write according to the auth mode. (ISO14443 Layer 3 activated)  */
  switch (pDataParams->bAuthMode) {
    case PHAL_MFPEVX_NOT_AUTHENTICATED_L3:
    case PHAL_MFPEVX_SL1_MIFARE_AUTHENTICATED:
      PH_CHECK_SUCCESS_FCT(wStatus, phalMfpEVx_Sw_WriteExtMfc(
              pDataParams,
              PHAL_MFPEVX_CMD_MFC_WRITE,
              (uint8_t) wBlockNr,
              pBlock,
              PHAL_MFPEVX_DATA_BLOCK_SIZE,
              pTMC,
              pTMV
          ));
      break;

    /* Perform write command in MFP mode. (ISO14443 Layer 4 activated) */
    case PHAL_MFPEVX_NOT_AUTHENTICATED_L4:
    case PHAL_MFPEVX_SL1_MFP_AUTHENTICATED:
    case PHAL_MFPEVX_SL3_MFP_AUTHENTICATED:
      /* If Mac on response is requested. */
      if (0U != (bWriteMaced)) {
        /* Should the data be encrypted. */
        if (0U != (bEncrypted)) {
          /* Write command for Encrypted data and MAC on response. */
          aCmd = PHAL_MFPEVX_CMD_WRITE_EM;
        } else {
          /* Write command for Plain data and MAC on response. */
          aCmd = PHAL_MFPEVX_CMD_WRITE_PM;
        }
      } else {
        /* Should the data be encrypted. */
        if (0U != (bEncrypted)) {
          /* Write command for Encrypted data and No MAC on response. */
          aCmd = PHAL_MFPEVX_CMD_WRITE_EN;
        } else {
          /* Write command for Plain data and No MAC on response. */
          aCmd = PHAL_MFPEVX_CMD_WRITE_PN;
        }
      }
      PH_CHECK_SUCCESS_FCT(wStatus, phalMfpEVx_Sw_WriteExt(
              pDataParams,
              aCmd,
              wBlockNr,
              0x00,
              pBlock,
              PHAL_MFPEVX_DATA_BLOCK_SIZE,
              bEncrypted,
              pTMC,
              pTMV));
      break;

    /* Return error in case of not authenticated in any one of the auth mode.*/
    default:
      return PH_ADD_COMPCODE_FIXED(PH_ERR_AUTH_ERROR, PH_COMP_AL_MFPEVX);
  }

  return PH_ERR_SUCCESS;
}

phStatus_t
phalMfpEVx_Sw_ReadValue(phalMfpEVx_Sw_DataParams_t *pDataParams, uint8_t bEncrypted,
    uint8_t bReadMaced, uint8_t bMacOnCmd,
    uint16_t wBlockNr, uint8_t *pValue, uint8_t *pAddrData)
{
  phStatus_t PH_MEMLOC_REM wStatus = 0;
  uint8_t pData[PHAL_MFPEVX_DATA_BLOCK_SIZE];

  switch (pDataParams->bAuthMode) {
    /* Perform Write according to the auth mode. (ISO14443 Layer 3 activated)  */
    case PHAL_MFPEVX_NOT_AUTHENTICATED_L3:
    case PHAL_MFPEVX_SL1_MIFARE_AUTHENTICATED:
      PH_CHECK_SUCCESS_FCT(wStatus, phalMfpEVx_Sw_ReadExtMfc(
              pDataParams,
              (uint8_t) wBlockNr,
              pData));
      break;

    /* Perform write command in MFP mode. (ISO14443 Layer 4 activated) */
    case PHAL_MFPEVX_NOT_AUTHENTICATED_L4:
    case PHAL_MFPEVX_SL1_MFP_AUTHENTICATED:
    case PHAL_MFPEVX_SL3_MFP_AUTHENTICATED:
      PH_CHECK_SUCCESS_FCT(wStatus, phalMfpEVx_Sw_ReadExt(
              pDataParams,
              bEncrypted,
              bReadMaced,
              bMacOnCmd,
              wBlockNr,
              0x01,
              pData));
      break;

    /* Return error in case of not authenticated in any one of the auth mode.*/
    default:
      return PH_ADD_COMPCODE_FIXED(PH_ERR_AUTH_ERROR, PH_COMP_AL_MFPEVX);
  }

  /* Form the value to be referred back in block format.
   *               | 00 01 02 03 | 04 05 06 07 | 08 09 0A 0B |  0C  |    0D  |  0E  |   0F   |
   * Value Block = |    Value    |    ~Value   |    Value    | Addr | ~ Addr | Addr | ~ Addr |
   */
  PH_CHECK_SUCCESS_FCT(wStatus, phalMfpEVx_Int_CheckValueBlockFormat(pData));

  *pAddrData = pData[12];
  (void)memcpy(pValue, pData, 4);

  return PH_ERR_SUCCESS;
}

phStatus_t
phalMfpEVx_Sw_Increment(phalMfpEVx_Sw_DataParams_t *pDataParams,
    uint8_t bIncrementMaced, uint16_t wBlockNr, uint8_t *pValue)
{
  phStatus_t PH_MEMLOC_REM wStatus = 0;
  uint8_t    PH_MEMLOC_REM aCmd;

  /* Perform increment according to the auth mode.*/
  switch (pDataParams->bAuthMode) {
    /* Perform increment command in MIFARE mode. (ISO14443 Layer 3 activated) */
    case PHAL_MFPEVX_NOT_AUTHENTICATED_L3:
    case PHAL_MFPEVX_SL1_MIFARE_AUTHENTICATED:
      PH_CHECK_SUCCESS_FCT(wStatus, phalMfpEVx_Sw_WriteExtMfc(
              pDataParams,
              PHAL_MFPEVX_CMD_MFC_INCREMENT,
              (uint8_t) wBlockNr,
              pValue,
              PHAL_MFPEVX_VALUE_BLOCK_SIZE,
              NULL,
              NULL));
      break;

    /* Perform increment command in MFP mode. (ISO14443 Layer 4 activated) */
    case PHAL_MFPEVX_NOT_AUTHENTICATED_L4:
    case PHAL_MFPEVX_SL1_MFP_AUTHENTICATED:
    case PHAL_MFPEVX_SL3_MFP_AUTHENTICATED:
      if (0U != (bIncrementMaced)) {
        /* Increment command for Encrypted data and MAC on response. */
        aCmd = PHAL_MFPEVX_CMD_INCR_M;
      } else {
        /* Increment command for Encrypted data and No MAC on response. */
        aCmd = PHAL_MFPEVX_CMD_INCR;
      }

      PH_CHECK_SUCCESS_FCT(wStatus, phalMfpEVx_Sw_WriteExt(
              pDataParams,
              aCmd,
              wBlockNr,
              0x00,
              pValue,
              PHAL_MFPEVX_VALUE_BLOCK_SIZE,
              PH_ON, /* Encrypted */
              NULL,
              NULL));
      break;

    /* Return error in case of not authenticated in any one of the auth mode.*/
    default:
      return PH_ADD_COMPCODE_FIXED(PH_ERR_AUTH_ERROR, PH_COMP_AL_MFPEVX);
  }

  return PH_ERR_SUCCESS;
}

phStatus_t
phalMfpEVx_Sw_Decrement(phalMfpEVx_Sw_DataParams_t *pDataParams,
    uint8_t bDecrementMaced, uint16_t wBlockNr, uint8_t *pValue)
{
  phStatus_t PH_MEMLOC_REM wStatus = 0;
  uint8_t    PH_MEMLOC_REM aCmd;

  /* Perform decrement according to the auth mode.*/
  switch (pDataParams->bAuthMode) {
    /* Perform decrement command in MIFARE mode. (ISO14443 Layer 3 activated) */
    case PHAL_MFPEVX_NOT_AUTHENTICATED_L3:
    case PHAL_MFPEVX_SL1_MIFARE_AUTHENTICATED:
      PH_CHECK_SUCCESS_FCT(wStatus, phalMfpEVx_Sw_WriteExtMfc(
              pDataParams,
              PHAL_MFPEVX_CMD_MFC_DECREMENT,
              (uint8_t) wBlockNr,
              pValue,
              PHAL_MFPEVX_VALUE_BLOCK_SIZE,
              NULL,
              NULL));
      break;

    /* Perform decrement command in MFP mode. (ISO14443 Layer 4 activated) */
    case PHAL_MFPEVX_NOT_AUTHENTICATED_L4:
    case PHAL_MFPEVX_SL1_MFP_AUTHENTICATED:
    case PHAL_MFPEVX_SL3_MFP_AUTHENTICATED:
      if (0U != (bDecrementMaced)) {
        /* Decrement command for Encrypted data and MAC on response. */
        aCmd = PHAL_MFPEVX_CMD_DECR_M;
      } else {
        /* Decrement command for Encrypted data and No MAC on response. */
        aCmd = PHAL_MFPEVX_CMD_DECR;
      }

      PH_CHECK_SUCCESS_FCT(wStatus, phalMfpEVx_Sw_WriteExt(
              pDataParams,
              aCmd,
              wBlockNr,
              0x00,
              pValue,
              PHAL_MFPEVX_VALUE_BLOCK_SIZE,
              PH_ON,/* Encrypted */
              NULL,
              NULL));
      break;

    /* Return error in case of not authenticated in any one of the auth mode.*/
    default:
      return PH_ADD_COMPCODE_FIXED(PH_ERR_AUTH_ERROR, PH_COMP_AL_MFPEVX);
  }

  return PH_ERR_SUCCESS;
}

phStatus_t
phalMfpEVx_Sw_IncrementTransfer(phalMfpEVx_Sw_DataParams_t *pDataParams,
    uint8_t bIncrementTransferMaced, uint16_t wSourceBlockNr,
    uint16_t wDestinationBlockNr, uint8_t *pValue, uint8_t *pTMC, uint8_t *pTMV)
{
  phStatus_t PH_MEMLOC_REM wStatus = 0;
  uint8_t    PH_MEMLOC_REM aCmd;

  /* Perform increment transfer according to the auth mode.*/
  switch (pDataParams->bAuthMode) {
    /* Perform increment transfer command in MIFARE mode. (ISO14443 Layer 3 activated) */
    case PHAL_MFPEVX_NOT_AUTHENTICATED_L3:
    case PHAL_MFPEVX_SL1_MIFARE_AUTHENTICATED:
      PH_CHECK_SUCCESS_FCT(wStatus, phalMfpEVx_Sw_WriteExtMfc(
              pDataParams,
              PHAL_MFPEVX_CMD_MFC_INCREMENT,
              (uint8_t) wSourceBlockNr,
              pValue,
              PHAL_MFPEVX_VALUE_BLOCK_SIZE,
              NULL,
              NULL));

      PH_CHECK_SUCCESS_FCT(wStatus, phalMfpEVx_Sw_WriteExtMfc(
              pDataParams,
              PHAL_MFPEVX_CMD_MFC_TRANSFER,
              (uint8_t) wDestinationBlockNr,
              NULL,
              0,
              pTMC,
              pTMV));
      break;

    /* Perform increment transfer command in MFP mode. (ISO14443 Layer 4 activated) */
    case PHAL_MFPEVX_NOT_AUTHENTICATED_L4:
    case PHAL_MFPEVX_SL1_MFP_AUTHENTICATED:
    case PHAL_MFPEVX_SL3_MFP_AUTHENTICATED:
      if (0U != (bIncrementTransferMaced)) {
        /* Increment transfer command for Encrypted data and MAC on response. */
        aCmd = PHAL_MFPEVX_CMD_INCRTR_M;
      } else {
        /* Increment transfer command for Encrypted data and No MAC on response. */
        aCmd = PHAL_MFPEVX_CMD_INCRTR;
      }

      PH_CHECK_SUCCESS_FCT(wStatus, phalMfpEVx_Sw_WriteExt(
              pDataParams,
              aCmd,
              wSourceBlockNr,
              wDestinationBlockNr,
              pValue,
              PHAL_MFPEVX_VALUE_BLOCK_SIZE,
              PH_ON, /* Encrypted */
              pTMC,
              pTMV));
      break;

    /* Return error in case of not authenticated in any one of the auth mode.*/
    default:
      return PH_ADD_COMPCODE_FIXED(PH_ERR_AUTH_ERROR, PH_COMP_AL_MFPEVX);
  }

  return PH_ERR_SUCCESS;
}

phStatus_t
phalMfpEVx_Sw_DecrementTransfer(phalMfpEVx_Sw_DataParams_t *pDataParams,
    uint8_t bDecrementTransferMaced, uint16_t wSourceBlockNr,
    uint16_t wDestinationBlockNr, uint8_t *pValue, uint8_t *pTMC, uint8_t *pTMV)
{
  phStatus_t PH_MEMLOC_REM wStatus = 0;
  uint8_t    PH_MEMLOC_REM aCmd;

  /* Perform decrement transfer according to the auth mode.*/
  switch (pDataParams->bAuthMode) {
    /* Perform decrement transfer command in MIFARE mode. (ISO14443 Layer 3 activated) */
    case PHAL_MFPEVX_NOT_AUTHENTICATED_L3:
    case PHAL_MFPEVX_SL1_MIFARE_AUTHENTICATED:
      PH_CHECK_SUCCESS_FCT(wStatus, phalMfpEVx_Sw_WriteExtMfc(
              pDataParams,
              PHAL_MFPEVX_CMD_MFC_DECREMENT,
              (uint8_t) wSourceBlockNr,
              pValue,
              PHAL_MFPEVX_VALUE_BLOCK_SIZE,
              NULL,
              NULL));

      PH_CHECK_SUCCESS_FCT(wStatus, phalMfpEVx_Sw_WriteExtMfc(
              pDataParams,
              PHAL_MFPEVX_CMD_MFC_TRANSFER,
              (uint8_t) wDestinationBlockNr,
              NULL,
              0,
              pTMC,
              pTMV));
      break;

    /* Perform decrement transfer command in MFP mode. (ISO14443 Layer 4 activated) */
    case PHAL_MFPEVX_NOT_AUTHENTICATED_L4:
    case PHAL_MFPEVX_SL1_MFP_AUTHENTICATED:
    case PHAL_MFPEVX_SL3_MFP_AUTHENTICATED:
      if (0U != (bDecrementTransferMaced)) {
        /* Decrement transfer command for Encrypted data and MAC on response. */
        aCmd = PHAL_MFPEVX_CMD_DECRTR_M;
      } else {
        /* Decrement transfer command for Encrypted data and No MAC on response. */
        aCmd = PHAL_MFPEVX_CMD_DECRTR;
      }

      PH_CHECK_SUCCESS_FCT(wStatus, phalMfpEVx_Sw_WriteExt(
              pDataParams,
              aCmd,
              wSourceBlockNr,
              wDestinationBlockNr,
              pValue,
              PHAL_MFPEVX_VALUE_BLOCK_SIZE,
              PH_ON,  /* Encrypted */
              pTMC,
              pTMV));
      break;

    /* Return error in case of not authenticated in any one of the auth mode.*/
    default:
      return PH_ADD_COMPCODE_FIXED(PH_ERR_AUTH_ERROR, PH_COMP_AL_MFPEVX);
  }

  return PH_ERR_SUCCESS;
}

phStatus_t
phalMfpEVx_Sw_Transfer(phalMfpEVx_Sw_DataParams_t *pDataParams, uint8_t bTransferMaced,
    uint16_t wBlockNr, uint8_t *pTMC,
    uint8_t *pTMV)
{
  phStatus_t PH_MEMLOC_REM wStatus = 0;
  uint8_t    PH_MEMLOC_REM aCmd;

  /* Perform transfer according to the auth mode.*/
  switch (pDataParams->bAuthMode) {
    /* Perform transfer command in MIFARE mode. (ISO14443 Layer 3 activated) */
    case PHAL_MFPEVX_NOT_AUTHENTICATED_L3:
    case PHAL_MFPEVX_SL1_MIFARE_AUTHENTICATED:
      PH_CHECK_SUCCESS_FCT(wStatus, phalMfpEVx_Sw_WriteExtMfc(
              pDataParams,
              PHAL_MFPEVX_CMD_MFC_TRANSFER,
              (uint8_t) wBlockNr,
              NULL,
              0,
              pTMC,
              pTMV));
      break;

    /* Perform transfer command in MFP mode. (ISO14443 Layer 4 activated) */
    case PHAL_MFPEVX_NOT_AUTHENTICATED_L4:
    case PHAL_MFPEVX_SL1_MFP_AUTHENTICATED:
    case PHAL_MFPEVX_SL3_MFP_AUTHENTICATED:
      if (0U != (bTransferMaced)) {
        /* Transfer command for Encrypted data and MAC on response. */
        aCmd = PHAL_MFPEVX_CMD_TRANS_M;
      } else {
        /* Transfer command for Encrypted data and No MAC on response. */
        aCmd = PHAL_MFPEVX_CMD_TRANS;
      }

      PH_CHECK_SUCCESS_FCT(wStatus, phalMfpEVx_Sw_WriteExt(
              pDataParams,
              aCmd,
              wBlockNr,
              0x00,
              NULL,
              0,
              PH_OFF, /* Plain */
              pTMC,
              pTMV));
      break;

    /* Return error in case of not authenticated in any one of the auth mode.*/
    default:
      return PH_ADD_COMPCODE_FIXED(PH_ERR_AUTH_ERROR, PH_COMP_AL_MFPEVX);
  }

  return PH_ERR_SUCCESS;
}

phStatus_t
phalMfpEVx_Sw_Restore(phalMfpEVx_Sw_DataParams_t *pDataParams, uint8_t bRestoreMaced,
    uint16_t wBlockNr)
{
  phStatus_t PH_MEMLOC_REM wStatus = 0;
  uint8_t    PH_MEMLOC_REM aCmd;

  /* Perform restore according to the auth mode.*/
  switch (pDataParams->bAuthMode) {
    /* Perform restore command in MIFARE mode. (ISO14443 Layer 3 activated) */
    case PHAL_MFPEVX_NOT_AUTHENTICATED_L3:
    case PHAL_MFPEVX_SL1_MIFARE_AUTHENTICATED:
      PH_CHECK_SUCCESS_FCT(wStatus, phalMfpEVx_Sw_WriteExtMfc(
              pDataParams,
              PHAL_MFPEVX_CMD_MFC_RESTORE,
              (uint8_t) wBlockNr,
              NULL,
              0,
              NULL,
              NULL));
      break;

    /* Perform restore command in MFP mode. (ISO14443 Layer 4 activated) */
    case PHAL_MFPEVX_NOT_AUTHENTICATED_L4:
    case PHAL_MFPEVX_SL1_MFP_AUTHENTICATED:
    case PHAL_MFPEVX_SL3_MFP_AUTHENTICATED:
      if (0U != (bRestoreMaced)) {
        /* Restore command for Encrypted data and MAC on response. */
        aCmd = PHAL_MFPEVX_CMD_REST_M;
      } else {
        /* Restore command for Encrypted data and No MAC on response. */
        aCmd = PHAL_MFPEVX_CMD_REST;
      }

      PH_CHECK_SUCCESS_FCT(wStatus, phalMfpEVx_Sw_WriteExt(
              pDataParams,
              aCmd,
              wBlockNr,
              0x00,
              NULL,
              0,
              PH_OFF, /* Plain */
              NULL,
              NULL));
      break;

    /* Return error in case of not authenticated in any one of the auth mode.*/
    default:
      return PH_ADD_COMPCODE_FIXED(PH_ERR_AUTH_ERROR, PH_COMP_AL_MFPEVX);
  }

  return PH_ERR_SUCCESS;
}

phStatus_t
phalMfpEVx_Sw_ReadExt(phalMfpEVx_Sw_DataParams_t *pDataParams, uint8_t bEncrypted,
    uint8_t bReadMaced, uint8_t bMacOnCmd,
    uint16_t wBlockNr, uint8_t bNumBlocks, uint8_t *pBlocks)
{
  phStatus_t  PH_MEMLOC_REM status;
  phStatus_t  PH_MEMLOC_REM statusTmp;
  uint8_t     PH_MEMLOC_REM aCmd;
  uint8_t     PH_MEMLOC_REM bTxBuffer[10];
  uint16_t    PH_MEMLOC_REM wTxLength = 0;
  uint8_t    *PH_MEMLOC_REM pResponse = NULL;
  uint16_t    PH_MEMLOC_REM wRxLength = 0;
  uint8_t     PH_MEMLOC_REM aMac[PH_CRYPTOSYM_AES_BLOCK_SIZE] = {0};
  uint8_t     PH_MEMLOC_REM bMacLength;
  uint8_t    *PH_MEMLOC_REM pResponseTmp = NULL;
  uint16_t    PH_MEMLOC_REM wRxLengthTmp;
  uint16_t    PH_MEMLOC_REM wTotalRxLength = 0;
  uint8_t     PH_MEMLOC_REM aIv[PH_CRYPTOSYM_AES_BLOCK_SIZE];
  uint8_t     PH_MEMLOC_REM pUnprocessedEncData[PH_CRYPTOSYM_AES_BLOCK_SIZE];
  uint8_t     PH_MEMLOC_REM bNumUnprocessedEncData = 0;
  uint16_t    PH_MEMLOC_REM wNumBlocksStartPos = 0;
  uint16_t    PH_MEMLOC_REM wIndex;
  uint8_t     PH_MEMLOC_REM bFinished;
  uint32_t    PH_MEMLOC_REM wTMIStatus = 0;
  uint8_t     PH_MEMLOC_REM bTmp = 0;

  /* Evaluate command code */
  if (0U != (bReadMaced)) {
    if (0U != (bEncrypted)) {
      if (0U != (bMacOnCmd)) {
        aCmd = PHAL_MFPEVX_CMD_READ_EMM;
      } else {
        aCmd = PHAL_MFPEVX_CMD_READ_EMU;
      }
    } else {
      if (0U != (bMacOnCmd)) {
        aCmd = PHAL_MFPEVX_CMD_READ_PMM;
      } else {
        aCmd = PHAL_MFPEVX_CMD_READ_PMU;
      }
    }
  } else {
    if (0U != (bEncrypted)) {
      if (0U != (bMacOnCmd)) {
        aCmd = PHAL_MFPEVX_CMD_READ_ENM;
      } else {
        aCmd = PHAL_MFPEVX_CMD_READ_ENU;
      }
    } else {
      if (0U != (bMacOnCmd)) {
        aCmd = PHAL_MFPEVX_CMD_READ_PNM;
      } else {
        aCmd = PHAL_MFPEVX_CMD_READ_PNU;
      }
    }
  }

  /* Build the command frame */
  wTxLength = 0;
  bTxBuffer[6U + wTxLength++] = aCmd;
  bTxBuffer[6U + wTxLength++] = (uint8_t)(wBlockNr & 0xFFU); /* LSB */
  bTxBuffer[6U + wTxLength++] = (uint8_t)(wBlockNr >> 8U);   /* MSB */
  bTxBuffer[6U + wTxLength++] = bNumBlocks;

  PH_CHECK_SUCCESS_FCT(statusTmp, phTMIUtils_GetConfig((phTMIUtils_t *)pDataParams->pTMIDataParams,
          PH_TMIUTILS_TMI_STATUS,
          &wTMIStatus));

  /* Check TMI Collection Status */
  if (wTMIStatus == PH_ON) {
    PH_CHECK_SUCCESS_FCT(statusTmp, phTMIUtils_CollectTMI((phTMIUtils_t *)pDataParams->pTMIDataParams,
            PH_TMIUTILS_NO_PADDING,
            &bTxBuffer[6],
            wTxLength,
            NULL,
            0,
            PHAL_MFPEVX_DATA_BLOCK_SIZE
        ));
  }

  /* Prepare for MAC on cmd */
  if (0U != (bMacOnCmd)) {
    /* Check if ISO 7816-4 wapping is required. */
    if (0U != (pDataParams->bWrappedMode)) {
      /* command exchange */
      PH_CHECK_SUCCESS_FCT(statusTmp, phalMfpEVx_Int_Send7816Apdu(
              pDataParams->pPalMifareDataParams,
              PH_EXCHANGE_BUFFER_FIRST,
              (uint16_t)((wTxLength - 1U /* Excluding the command code*/) + PHAL_MFPEVX_TRUNCATED_MAC_SIZE),
              pDataParams->bExtendedLenApdu,
              &bTxBuffer[6],
              wTxLength,      /* Command code is included as part of length. */
              &pResponse,
              &wRxLength));
    } else {
      /* command exchange */
      PH_CHECK_SUCCESS_FCT(statusTmp, phpalMifare_ExchangeL4(
              pDataParams->pPalMifareDataParams,
              PH_EXCHANGE_BUFFER_FIRST,
              &bTxBuffer[6],
              wTxLength,
              &pResponse,
              &wRxLength));
    }

    /* Prepare MAC calculation */
    bTxBuffer[0] = aCmd;
    bTxBuffer[1] = (uint8_t)(pDataParams->wRCtr);
    bTxBuffer[2] = (uint8_t)(pDataParams->wRCtr >> 8U);
    (void)memcpy(&bTxBuffer[3], pDataParams->bTi, PHAL_MFPEVX_SIZE_TI);
    wTxLength = (uint16_t)(wTxLength + 2U /* RCtr */ + PHAL_MFPEVX_SIZE_TI /* TI*/);

    /* Load the Session MAC Key. */
    PH_CHECK_SUCCESS_FCT(statusTmp, phCryptoSym_LoadKeyDirect(
            pDataParams->pCryptoDataParamsMac,
            pDataParams->bSesAuthMACKey,
            PH_CRYPTOSYM_KEY_TYPE_AES128));

    /* Now calculate the MAC */
    /* CMAC with Padding */
    PH_CHECK_SUCCESS_FCT(statusTmp, phCryptoSym_CalculateMac(
            pDataParams->pCryptoDataParamsMac,
            PH_CRYPTOSYM_MAC_MODE_CMAC,
            bTxBuffer,
            wTxLength,
            aMac,
            &bMacLength));

    /* Perform MAC truncation */
    phalMfpEVx_Sw_Int_TruncateMac(aMac, aMac);

    /* Check if ISO 7816-4 wapping is required. */
    if (0U != (pDataParams->bWrappedMode)) {
      /* Exchange the command including the MAC */
      status = phalMfpEVx_Int_Send7816Apdu(
              pDataParams->pPalMifareDataParams,
              PH_EXCHANGE_BUFFER_LAST,
              0x00, /* Lc is zero because the length is updated in the first call. */
              pDataParams->bExtendedLenApdu,
              aMac,
              PHAL_MFPEVX_TRUNCATED_MAC_SIZE,
              &pResponse,
              &wRxLength);
    } else {
      /* Exchange the command including the MAC */
      status = phpalMifare_ExchangeL4(
              pDataParams->pPalMifareDataParams,
              PH_EXCHANGE_BUFFER_LAST,
              aMac,
              PHAL_MFPEVX_TRUNCATED_MAC_SIZE,
              &pResponse,
              &wRxLength);
    }
  } else {
    /* Check if ISO 7816-4 wapping is required. */
    if (0U != (pDataParams->bWrappedMode)) {
      /* command exchange */
      status = phalMfpEVx_Int_Send7816Apdu(
              pDataParams->pPalMifareDataParams,
              PH_EXCHANGE_DEFAULT,
              (uint16_t)(wTxLength - 1U  /* Excluding the command code */),
              pDataParams->bExtendedLenApdu,
              &bTxBuffer[6],
              wTxLength,      /* Command code is included as part of length. */
              &pResponse,
              &wRxLength);
    } else {
      /* command exchange */
      status = phpalMifare_ExchangeL4(
              pDataParams->pPalMifareDataParams,
              PH_EXCHANGE_DEFAULT,
              &bTxBuffer[6],
              wTxLength,
              &pResponse,
              &wRxLength);
    }
  }

  /* Ignore success chaining status */
  if ((status & PH_ERR_MASK) != PH_ERR_SUCCESS_CHAINING) {
    PH_CHECK_SUCCESS(status);
  }

  /* Check response */
  PH_CHECK_SUCCESS_FCT(statusTmp, phalMfpEVx_Int_ComputeErrorResponse(wRxLength, pResponse[0],
          PH_ON));

  /* Increment Read Counter */
  pDataParams->wRCtr++;

  /* we also have to decrypt the response */
  if (0U != (bEncrypted)) {
    /* Lets load the ENC IV */
    PH_CHECK_SUCCESS_FCT(statusTmp, phalMfpEVx_Sw_Int_ComputeIv(
            pDataParams,
            PH_ON,
            pDataParams->bTi,
            pDataParams->wRCtr,
            pDataParams->wWCtr,
            aIv));

    PH_CHECK_SUCCESS_FCT(statusTmp, phCryptoSym_LoadIv(
            pDataParams->pCryptoDataParamsEnc,
            aIv,
            PH_CRYPTOSYM_AES_BLOCK_SIZE));
  }

  /* Reset TxLength */
  wTxLength = 0;

  /* In case of FIRST Read, we need to start loading TI and RCtr */
  if (0U != (pDataParams->bFirstRead)) {
    pDataParams->bFirstRead = 0;

    /* Recopy the status code */
    bTxBuffer[wTxLength++] = pResponse[0];

    /* Rearrange the MAC header according to spec */
    bTxBuffer[wTxLength++] = (uint8_t)pDataParams->wRCtr;
    bTxBuffer[wTxLength++] = (uint8_t)(pDataParams->wRCtr >> 8U);

    /* Lets recopy TI */
    (void)memcpy(&bTxBuffer[wTxLength], pDataParams->bTi, PHAL_MFPEVX_SIZE_TI);
    wTxLength = wTxLength + PHAL_MFPEVX_SIZE_TI /* TI*/;

    /* Load first IV*/
    PH_CHECK_SUCCESS_FCT(statusTmp, phCryptoSym_LoadIv(
            pDataParams->pCryptoDataParamsMac,
            phalMfpEVx_Sw_FirstIv,
            PH_CRYPTOSYM_AES_BLOCK_SIZE));
  } else {
    /* Load current IV */
    PH_CHECK_SUCCESS_FCT(statusTmp, phCryptoSym_LoadIv(
            pDataParams->pCryptoDataParamsMac,
            pDataParams->pIntermediateMac,
            PH_CRYPTOSYM_AES_BLOCK_SIZE));
  }

  /* Now we need to copy the BNR and the Ext byte */
  bTxBuffer[wTxLength++] = (uint8_t)(wBlockNr & 0xFFU); /* LSB */
  bTxBuffer[wTxLength++] = (uint8_t)(wBlockNr >> 8U);   /* MSB */
  bTxBuffer[wTxLength++] = bNumBlocks;

  /* Update the response buffer */
  ++pResponse;
  --wRxLength;

  /* Recopy the header into the pending data */
  /* In case the whole header fits into the unprocessed ReadMac Buffer, we can simply recopy. */
  /* Else an intermediate MAC calculation is necessary...*/
  wIndex = (uint16_t)(PH_CRYPTOSYM_AES_BLOCK_SIZE - ((uint16_t)
              pDataParams->bNumUnprocessedReadMacBytes));

  if (wIndex >= wTxLength) {
    /* Just recopy the data */
    (void)memcpy(&pDataParams->pUnprocessedReadMacBuffer[pDataParams->bNumUnprocessedReadMacBytes],
        bTxBuffer, wTxLength);
    pDataParams->bNumUnprocessedReadMacBytes = (uint8_t)(pDataParams->bNumUnprocessedReadMacBytes +
            wTxLength);
  } else {
    /* Perform intermediate MAC calculation and update pUnprocessedReadMacBuffer */

    /* Recopy as many bytes as possible */
    (void)memcpy(&pDataParams->pUnprocessedReadMacBuffer[pDataParams->bNumUnprocessedReadMacBytes],
        bTxBuffer, wIndex);

    /* Update the unprocessed Read MAC bytes */
    pDataParams->bNumUnprocessedReadMacBytes = (uint8_t)(pDataParams->bNumUnprocessedReadMacBytes +
            wIndex);

    /* Perform the MAC calculation inside of the Unprocessed Read Mac Buffer */

    /* Load the Session MAC Key. */
    PH_CHECK_SUCCESS_FCT(statusTmp, phCryptoSym_LoadKeyDirect(
            pDataParams->pCryptoDataParamsMac,
            pDataParams->bSesAuthMACKey,
            PH_CRYPTOSYM_KEY_TYPE_AES128));

    /* CMAC without Padding */
    /* Perform the MAC calculation */
    PH_CHECK_SUCCESS_FCT(statusTmp, phCryptoSym_CalculateMac(
            pDataParams->pCryptoDataParamsMac,
            PH_EXCHANGE_BUFFER_CONT | PH_CRYPTOSYM_MAC_MODE_CMAC,
            pDataParams->pUnprocessedReadMacBuffer,
            pDataParams->bNumUnprocessedReadMacBytes,
            pDataParams->pIntermediateMac,
            &bMacLength));

    /* Recopy the rest of the data into the pUnprocessedReadMacBuffer*/
    (void)memcpy(pDataParams->pUnprocessedReadMacBuffer, &bTxBuffer[wIndex], wTxLength - wIndex);

    /* Update unprocessed Read Mac length */
    pDataParams->bNumUnprocessedReadMacBytes = (uint8_t)(wTxLength - wIndex);
  }

  /* chaining loop */
  wTotalRxLength = 0;
  bFinished = 0;
  do {
    wTotalRxLength = wTotalRxLength + wRxLength;

    /* Length Check */
    if ((status & PH_ERR_MASK) == PH_ERR_SUCCESS) {
      /* Verify the Length - Status Code has already been consumed! */
      if (0U != (bReadMaced)) {
        /* check response length */
        if (wTotalRxLength != (PHAL_MFPEVX_TRUNCATED_MAC_SIZE /* MAC */ + (((uint16_t)(
                            bNumBlocks)) * PHAL_MFPEVX_DATA_BLOCK_SIZE) /* Data */)) {
          return PH_ADD_COMPCODE_FIXED(PH_ERR_PROTOCOL_ERROR, PH_COMP_AL_MFPEVX);
        }

        /* Remove the temporarily received MAC length */
        wRxLength = wRxLength - PHAL_MFPEVX_TRUNCATED_MAC_SIZE;
      } else {
        /* check response length */
        if (wTotalRxLength != (((uint16_t)(bNumBlocks)) * PHAL_MFPEVX_DATA_BLOCK_SIZE) /* Data */) {
          return PH_ADD_COMPCODE_FIXED(PH_ERR_PROTOCOL_ERROR, PH_COMP_AL_MFPEVX);
        }
      }
    }

    /* Initialize helpers */
    pResponseTmp = pResponse;
    wRxLengthTmp = wRxLength;

    /* In case of unprocessed read MAC bytes, we first need to empty the unprocessed read buffer */
    wIndex = (uint16_t)(PH_CRYPTOSYM_AES_BLOCK_SIZE - ((uint16_t)
                pDataParams->bNumUnprocessedReadMacBytes));

    while (wIndex < wRxLengthTmp) {
      /* Recopy as many bytes as possible */
      (void)memcpy(&pDataParams->pUnprocessedReadMacBuffer[pDataParams->bNumUnprocessedReadMacBytes],
          pResponseTmp, wIndex);

      wRxLengthTmp = (uint16_t)(wRxLengthTmp - wIndex);
      pResponseTmp += wIndex;
      pDataParams->bNumUnprocessedReadMacBytes = (uint8_t)(pDataParams->bNumUnprocessedReadMacBytes +
              wIndex);

      /* Load the Session MAC Key. */
      PH_CHECK_SUCCESS_FCT(statusTmp, phCryptoSym_LoadKeyDirect(
              pDataParams->pCryptoDataParamsMac,
              pDataParams->bSesAuthMACKey,
              PH_CRYPTOSYM_KEY_TYPE_AES128));

      /* Perform the MAC calculation */
      /* CMAC without Padding */
      PH_CHECK_SUCCESS_FCT(statusTmp, phCryptoSym_CalculateMac(
              pDataParams->pCryptoDataParamsMac,
              PH_EXCHANGE_BUFFER_CONT | PH_CRYPTOSYM_MAC_MODE_CMAC,
              pDataParams->pUnprocessedReadMacBuffer,
              pDataParams->bNumUnprocessedReadMacBytes,
              pDataParams->pIntermediateMac,
              &bMacLength));

      /* Reset unprocessed MAC bytes */
      pDataParams->bNumUnprocessedReadMacBytes = 0;

      /* In case of unprocessed read MAC bytes, we first need to empty the unprocessed read buffer */
      wIndex = PH_CRYPTOSYM_AES_BLOCK_SIZE;
    }

    /* No complete block to be MACED is available. */
    /* Just recopy the data */
    (void)memcpy(&pDataParams->pUnprocessedReadMacBuffer[pDataParams->bNumUnprocessedReadMacBytes],
        pResponseTmp, wRxLengthTmp);
    pDataParams->bNumUnprocessedReadMacBytes = (uint8_t)(pDataParams->bNumUnprocessedReadMacBytes +
            wRxLengthTmp);
    pResponseTmp += wRxLengthTmp;

    /* now perform the decryption */
    if (0U != (bEncrypted)) {
      wIndex = 0;

      /* Load the Session ENC Key. */
      PH_CHECK_SUCCESS_FCT(statusTmp, phCryptoSym_LoadKeyDirect(
              pDataParams->pCryptoDataParamsEnc,
              pDataParams->bSesAuthENCKey,
              PH_CRYPTOSYM_KEY_TYPE_AES128));

      if (0U != (bNumUnprocessedEncData)) {
        /* Recopy the data */
        wIndex = PH_CRYPTOSYM_AES_BLOCK_SIZE - bNumUnprocessedEncData;
        (void)memcpy(&pUnprocessedEncData[bNumUnprocessedEncData], pResponse, wIndex);
        bNumUnprocessedEncData = 0;

        /* Decrypt the data */
        PH_CHECK_SUCCESS_FCT(statusTmp, phCryptoSym_Decrypt(
                pDataParams->pCryptoDataParamsEnc,
                PH_EXCHANGE_BUFFER_CONT | PH_CRYPTOSYM_CIPHER_MODE_CBC,
                pResponse,
                PH_CRYPTOSYM_AES_BLOCK_SIZE,
                &pBlocks[wNumBlocksStartPos]
            ));

        wNumBlocksStartPos += PH_CRYPTOSYM_AES_BLOCK_SIZE;
      }

      wRxLengthTmp = (uint16_t)(wRxLength - wIndex);
      bNumUnprocessedEncData = (uint8_t)(wRxLengthTmp % PH_CRYPTOSYM_AES_BLOCK_SIZE);
      if (0U != (bNumUnprocessedEncData)) {
        (void)memcpy(pUnprocessedEncData, &pResponse[wRxLength - bNumUnprocessedEncData],
            bNumUnprocessedEncData);
        wRxLengthTmp = wRxLengthTmp - bNumUnprocessedEncData;
      }
      if ((wNumBlocksStartPos + wRxLengthTmp) > (bNumBlocks * PHAL_MFPEVX_DATA_BLOCK_SIZE)) {
        return PH_ADD_COMPCODE_FIXED(PH_ERR_PROTOCOL_ERROR, PH_COMP_AL_MFPEVX);
      }

      /* Decrypt the data */
      PH_CHECK_SUCCESS_FCT(statusTmp, phCryptoSym_Decrypt(
              pDataParams->pCryptoDataParamsEnc,
              PH_EXCHANGE_BUFFER_CONT | PH_CRYPTOSYM_CIPHER_MODE_CBC,
              &pResponse[wIndex],
              wRxLengthTmp,
              &pBlocks[wNumBlocksStartPos]
          ));

      wNumBlocksStartPos = wRxLengthTmp + wNumBlocksStartPos;
    } else {
      if ((wNumBlocksStartPos + wRxLength) > (bNumBlocks * PHAL_MFPEVX_DATA_BLOCK_SIZE)) {
        return PH_ADD_COMPCODE_FIXED(PH_ERR_PROTOCOL_ERROR, PH_COMP_AL_MFPEVX);
      }
      (void)memcpy(&pBlocks[wNumBlocksStartPos], pResponse, wRxLength);
      wNumBlocksStartPos = wRxLength + wNumBlocksStartPos;
    }

    /* Finally let's verify the MAC */
    if ((status & PH_ERR_MASK) == PH_ERR_SUCCESS) {
      /* Did we receive a MAC? Then let's check else remember the part of the response */
      if (0U != (bReadMaced)) {
        /* Load the Session MAC Key. */
        PH_CHECK_SUCCESS_FCT(statusTmp, phCryptoSym_LoadKeyDirect(
                pDataParams->pCryptoDataParamsMac,
                pDataParams->bSesAuthMACKey,
                PH_CRYPTOSYM_KEY_TYPE_AES128));

        /* Calculate the MAC*/
        /* CMAC with Padding */
        PH_CHECK_SUCCESS_FCT(statusTmp, phCryptoSym_CalculateMac(
                pDataParams->pCryptoDataParamsMac,
                PH_EXCHANGE_BUFFER_LAST | PH_CRYPTOSYM_MAC_MODE_CMAC,
                pDataParams->pUnprocessedReadMacBuffer,
                pDataParams->bNumUnprocessedReadMacBytes,
                pDataParams->pIntermediateMac,
                &bMacLength));

        /* Reset to first read */
        pDataParams->bFirstRead = 1;
        pDataParams->bNumUnprocessedReadMacBytes = 0;

        /* Truncate the MAC */
        phalMfpEVx_Sw_Int_TruncateMac(pDataParams->pIntermediateMac, pDataParams->pIntermediateMac);

        /* Compare the result - note that wRxLength has been decremented upfront*/
        if (memcmp(pDataParams->pIntermediateMac, &pResponse[wRxLength],
                PHAL_MFPEVX_TRUNCATED_MAC_SIZE) != 0x00) {
          return PH_ADD_COMPCODE_FIXED(PH_ERR_AUTH_ERROR, PH_COMP_AL_MFPEVX);
        }
      }
      bFinished = 1;
    } else {
      /* Check if ISO 7816-4 wapping is required. */
      if (0U != (pDataParams->bWrappedMode)) {
        /* Continue with next Data block */
        status = phalMfpEVx_Int_Send7816Apdu(
                pDataParams->pPalMifareDataParams,
                PH_EXCHANGE_RXCHAINING,
                0x00,
                pDataParams->bExtendedLenApdu,
                NULL,
                0x00,
                &pResponse,
                &wRxLength);
      } else {
        /* Continue with next Data block */
        status = phpalMifare_ExchangeL4(
                pDataParams->pPalMifareDataParams,
                PH_EXCHANGE_RXCHAINING,
                NULL,
                0,
                &pResponse,
                &wRxLength);
      }

      if ((status & PH_ERR_MASK) != PH_ERR_SUCCESS_CHAINING) {
        PH_CHECK_SUCCESS(status);
      }
    }
  } while (bFinished == 0U);

  /* Check TMI Collection Status */
  if (wTMIStatus == PH_ON) {
    if (wRxLength == 0U) {
      bTmp = PH_TMIUTILS_READ_INS;
    }
    if (status == PH_ERR_SUCCESS) {
      bTmp |= PH_TMIUTILS_NO_PADDING;
    }

    PH_CHECK_SUCCESS_FCT(statusTmp, phTMIUtils_CollectTMI((phTMIUtils_t *)pDataParams->pTMIDataParams,
            bTmp,
            NULL,
            0,
            pBlocks,
            wNumBlocksStartPos,
            PHAL_MFPEVX_DATA_BLOCK_SIZE
        ));

    if ((status == PH_ERR_SUCCESS) && (wRxLength == 0U)) {
      /* Reset wOffsetInTMI to 0 */
      PH_CHECK_SUCCESS_FCT(statusTmp, phTMIUtils_SetConfig((phTMIUtils_t *)pDataParams->pTMIDataParams,
              PH_TMIUTILS_TMI_OFFSET_LENGTH,
              0
          ));
    }
  }
  return PH_ERR_SUCCESS;
}

phStatus_t
phalMfpEVx_Sw_WriteExt(phalMfpEVx_Sw_DataParams_t *pDataParams, uint8_t bCmdCode,
    uint16_t wSrcBnr, uint16_t wDstBnr,
    uint8_t *pData, uint16_t wDataLength, uint8_t bEncrypted, uint8_t *pTMC, uint8_t *pTMV)
{
  phStatus_t  PH_MEMLOC_REM statusTmp;
  uint8_t     PH_MEMLOC_REM aCmdBuf[11U + PHAL_MFPEVX_MAX_WRITE_BLOCK];
  uint16_t    PH_MEMLOC_REM wCmdLength = 0;
  uint16_t    PH_MEMLOC_REM wPartLength = 0;
  uint8_t    *PH_MEMLOC_REM pResponse = NULL;
  uint16_t    PH_MEMLOC_REM wRxLength = 0;
  uint8_t     PH_MEMLOC_REM aIv[PH_CRYPTOSYM_AES_BLOCK_SIZE];
  uint8_t     PH_MEMLOC_REM aMac[PH_CRYPTOSYM_AES_BLOCK_SIZE] = {0};
  uint8_t     PH_MEMLOC_REM bMacLength;
  uint32_t    PH_MEMLOC_REM wTMIStatus = 0;
  uint8_t     PH_MEMLOC_REM wTMProtectBlock = 0;

  /* Build command frame */
  wCmdLength = 0;
  aCmdBuf[6U + wCmdLength++] = bCmdCode;
  aCmdBuf[6U + wCmdLength++] = (uint8_t)(wSrcBnr & 0xFFU); /* LSB */
  aCmdBuf[6U + wCmdLength++] = (uint8_t)(wSrcBnr >> 8U);   /* MSB */

  if ((bCmdCode == PHAL_MFPEVX_CMD_INCRTR) ||
      (bCmdCode == PHAL_MFPEVX_CMD_INCRTR_M) ||
      (bCmdCode == PHAL_MFPEVX_CMD_DECRTR) ||
      (bCmdCode == PHAL_MFPEVX_CMD_DECRTR_M)) {
    aCmdBuf[6U + wCmdLength++] = (uint8_t)(wDstBnr & 0xFFU); /* LSB */
    aCmdBuf[6U + wCmdLength++] = (uint8_t)(wDstBnr >> 8U);   /* MSB */
  }

  PH_CHECK_SUCCESS_FCT(statusTmp, phTMIUtils_GetConfig((phTMIUtils_t *)pDataParams->pTMIDataParams,
          PH_TMIUTILS_TMI_STATUS,
          &wTMIStatus));

  /* Check TMI Collection Status */
  if (wTMIStatus == PH_ON) {
    /* Add number of blocks for write command only. */
    if ((bCmdCode == PHAL_MFPEVX_CMD_WRITE_PN) || (bCmdCode == PHAL_MFPEVX_CMD_WRITE_PM) ||
        (bCmdCode == PHAL_MFPEVX_CMD_WRITE_EN) || (bCmdCode == PHAL_MFPEVX_CMD_WRITE_EM)) {
      /* Adding Number of Blocks (Ext) to command buffer. */
      aCmdBuf[6U + wCmdLength] = (uint8_t)(wDataLength / PHAL_MFPEVX_DATA_BLOCK_SIZE);

      PH_CHECK_SUCCESS_FCT(statusTmp, phTMIUtils_CollectTMI((phTMIUtils_t *)pDataParams->pTMIDataParams,
              PH_TMIUTILS_NO_PADDING,
              &aCmdBuf[6],
              wCmdLength + 1U,
              pData,
              wDataLength,
              PHAL_MFPEVX_DATA_BLOCK_SIZE
          ));
    } else {
      PH_CHECK_SUCCESS_FCT(statusTmp, phTMIUtils_CollectTMI((phTMIUtils_t *)pDataParams->pTMIDataParams,
              PH_TMIUTILS_NO_PADDING,
              &aCmdBuf[6],
              wCmdLength,
              pData,
              wDataLength,
              PHAL_MFPEVX_DATA_BLOCK_SIZE
          ));
    }
  }

  /* Convert data to 16 bytes by padding zero's for plain value data. */
  if (wDataLength == PHAL_MFPEVX_VALUE_BLOCK_SIZE) {
    (void)memcpy(&aCmdBuf[11], pData, PHAL_MFPEVX_VALUE_BLOCK_SIZE);
    pData = &aCmdBuf[11];

    /* Apply Padding */
    PH_CHECK_SUCCESS_FCT(statusTmp, phCryptoSym_ApplyPadding(
            PH_CRYPTOSYM_PADDING_MODE_2,
            &aCmdBuf[11],
            wDataLength,
            PHAL_MFPEVX_DATA_BLOCK_SIZE,
            (uint16_t)(sizeof(aCmdBuf) - 11U),
            &aCmdBuf[11],
            &wDataLength));
  }

  /* Do we need encryption? */
  if ((bEncrypted != PH_OFF) && (pData != NULL)) {
    /* Lets load the ENC IV */
    PH_CHECK_SUCCESS_FCT(statusTmp, phalMfpEVx_Sw_Int_ComputeIv(
            pDataParams,
            PH_OFF, /* No Response*/
            pDataParams->bTi,
            pDataParams->wRCtr,
            pDataParams->wWCtr,
            aIv));

    PH_CHECK_SUCCESS_FCT(statusTmp, phCryptoSym_LoadIv(
            pDataParams->pCryptoDataParamsEnc,
            aIv,
            PH_CRYPTOSYM_AES_BLOCK_SIZE));

    /* No padding should be necessary */
    if (0U != (wDataLength % PH_CRYPTOSYM_AES_BLOCK_SIZE)) {
      return PH_ADD_COMPCODE_FIXED(PH_ERR_INVALID_PARAMETER, PH_COMP_AL_MFPEVX);
    }

    /* load session ENC key */
    PH_CHECK_SUCCESS_FCT(statusTmp, phCryptoSym_LoadKeyDirect(
            pDataParams->pCryptoDataParamsEnc,
            pDataParams->bSesAuthENCKey,
            PH_CRYPTOSYM_KEY_TYPE_AES128));

    /* Perform the Encryption */
    PH_CHECK_SUCCESS_FCT(statusTmp, phCryptoSym_Encrypt(
            pDataParams->pCryptoDataParamsEnc,
            PH_EXCHANGE_BUFFER_CONT | PH_CRYPTOSYM_CIPHER_MODE_CBC,
            pData,
            wDataLength,
            &aCmdBuf[11]
        ));

    pData = &aCmdBuf[11];
  }

  /* Check if ISO 7816-4 wapping is required. */
  if (0U != (pDataParams->bWrappedMode)) {
    /* Buffer the command frame */
    PH_CHECK_SUCCESS_FCT(statusTmp, phalMfpEVx_Int_Send7816Apdu(
            pDataParams->pPalMifareDataParams,
            PH_EXCHANGE_BUFFER_FIRST,
            (uint16_t)((wCmdLength - 1U) +
                (((wDataLength != 0U) && (pData != NULL)) ? wDataLength : 0x00U) +
                PHAL_MFPEVX_TRUNCATED_MAC_SIZE),
            pDataParams->bExtendedLenApdu,
            &aCmdBuf[6],
            wCmdLength,     /* Command code is included as part of length. */
            NULL,
            NULL));

    /* Append and send the data */
    if ((wDataLength != 0U) && (pData != NULL)) {
      PH_CHECK_SUCCESS_FCT(statusTmp, phalMfpEVx_Int_Send7816Apdu(
              pDataParams->pPalMifareDataParams,
              PH_EXCHANGE_BUFFER_CONT,
              0x00, /* Lc is zero because the length is updated in the first call. */
              pDataParams->bExtendedLenApdu,
              pData,
              wDataLength,
              NULL,
              NULL));
    }
  } else {
    /* Buffer the command frame */
    PH_CHECK_SUCCESS_FCT(statusTmp, phpalMifare_ExchangeL4(
            pDataParams->pPalMifareDataParams,
            PH_EXCHANGE_BUFFER_FIRST,
            &aCmdBuf[6],
            wCmdLength,
            &pResponse,
            &wRxLength));

    /* Append and send the data */
    if ((wDataLength != 0U) && (pData != NULL)) {
      PH_CHECK_SUCCESS_FCT(statusTmp, phpalMifare_ExchangeL4(
              pDataParams->pPalMifareDataParams,
              PH_EXCHANGE_BUFFER_CONT,
              pData,
              wDataLength,
              &pResponse,
              &wRxLength));
    }
  }

  /* load session MAC key */
  PH_CHECK_SUCCESS_FCT(statusTmp, phCryptoSym_LoadKeyDirect(
          pDataParams->pCryptoDataParamsMac,
          pDataParams->bSesAuthMACKey,
          PH_CRYPTOSYM_KEY_TYPE_AES128));

  /* Load the default IV */
  PH_CHECK_SUCCESS_FCT(statusTmp, phCryptoSym_LoadIv(
          pDataParams->pCryptoDataParamsMac,
          phalMfpEVx_Sw_FirstIv,
          PH_CRYPTOSYM_AES_BLOCK_SIZE));

  /* Calculate the MAC over the already available data and the current data. */

  /* First the mac consists of CMD || W_CTR || TI || PARAMS || DATA */
  aCmdBuf[0] = bCmdCode;
  aCmdBuf[1] = (uint8_t)(pDataParams->wWCtr);
  aCmdBuf[2] = (uint8_t)(pDataParams->wWCtr >> 8U);
  (void)memcpy(&aCmdBuf[3], pDataParams->bTi, PHAL_MFPEVX_SIZE_TI);
  wCmdLength = (uint16_t)(wCmdLength + 2U /* WCtr */ + PHAL_MFPEVX_SIZE_TI /* TI */);

  if ((wDataLength != 0U) && (pData != NULL)) {
    /* Recopy part of the Data */
    wPartLength = PHAL_MFPEVX_DATA_BLOCK_SIZE - wCmdLength;
    (void)memcpy(&aCmdBuf[wCmdLength], pData, wPartLength);
    pData = &pData[wPartLength];
    wDataLength = wDataLength - wPartLength;

    /* Start with MAC calculation */

    /* CMAC without padding */
    /* Perform the MAC calculation for first block*/
    PH_CHECK_SUCCESS_FCT(statusTmp, phCryptoSym_CalculateMac(
            pDataParams->pCryptoDataParamsMac,
            PH_EXCHANGE_BUFFER_CONT | PH_CRYPTOSYM_MAC_MODE_CMAC,
            aCmdBuf,
            PH_CRYPTOSYM_AES_BLOCK_SIZE,
            aMac,
            &bMacLength));

    /* Perform MAC calculation for all but the last Block */
    /* Calculate the amount of complete blocks in the final data buffer */
    wPartLength = wDataLength - (wDataLength % PH_CRYPTOSYM_AES_BLOCK_SIZE);

    if (0U != (wPartLength)) {
      /* Perform the MAC calculation */
      PH_CHECK_SUCCESS_FCT(statusTmp, phCryptoSym_CalculateMac(
              pDataParams->pCryptoDataParamsMac,
              PH_EXCHANGE_BUFFER_CONT | PH_CRYPTOSYM_MAC_MODE_CMAC,
              pData,
              wPartLength,
              aMac,
              &bMacLength));

      /* Adapt the sizes and also the pointer */
      pData = &pData[wPartLength];
      wDataLength = wDataLength - wPartLength;
    }
  } else {
    /* Set the final data to the cmd buffer */
    pData = aCmdBuf;
    wDataLength = wCmdLength;
  }

  /* Now calculate the MAC */

  /* CMAC Padding*/
  /* Calculate the MAC for the last block */
  PH_CHECK_SUCCESS_FCT(statusTmp, phCryptoSym_CalculateMac(
          pDataParams->pCryptoDataParamsMac,
          PH_EXCHANGE_BUFFER_LAST | PH_CRYPTOSYM_MAC_MODE_CMAC,
          pData,
          wDataLength,
          aMac,
          &bMacLength));

  /* Truncate MAC */
  phalMfpEVx_Sw_Int_TruncateMac(aMac, aMac);

  /* Check if ISO 7816-4 wapping is required. */
  if (0U != (pDataParams->bWrappedMode)) {
    /* Finally exchange the MAC */
    PH_CHECK_SUCCESS_FCT(statusTmp, phalMfpEVx_Int_Send7816Apdu(
            pDataParams->pPalMifareDataParams,
            PH_EXCHANGE_BUFFER_LAST,
            0x00, /* Lc is zero because the length is updated in the first call. */
            pDataParams->bExtendedLenApdu,
            aMac,
            PHAL_MFPEVX_TRUNCATED_MAC_SIZE,
            &pResponse,
            &wRxLength));
  } else {
    /* Finally exchange the MAC */
    PH_CHECK_SUCCESS_FCT(statusTmp, phpalMifare_ExchangeL4(
            pDataParams->pPalMifareDataParams,
            PH_EXCHANGE_BUFFER_LAST,
            aMac,
            PHAL_MFPEVX_TRUNCATED_MAC_SIZE,
            &pResponse,
            &wRxLength));
  }

  PH_CHECK_SUCCESS_FCT(statusTmp, phalMfpEVx_Int_ComputeErrorResponse(wRxLength, pResponse[0],
          PH_ON));

  /* Check for a TM Protected block */
  if (wRxLength > (1 /* Status */ + PHAL_MFPEVX_TRUNCATED_MAC_SIZE /* MAC */)) {
    wTMProtectBlock = 1;

    /* Check if NULL is passed for TMC parameter. */
    if (pTMC == NULL) {
      return PH_ADD_COMPCODE_FIXED(PH_ERR_INVALID_PARAMETER, PH_COMP_AL_MFPEVX);
    }

    /* Check if NULL is passed for TMV parameter. */
    if (pTMV == NULL) {
      return PH_ADD_COMPCODE_FIXED(PH_ERR_INVALID_PARAMETER, PH_COMP_AL_MFPEVX);
    }
  }

  /* Increment Write Counter */
  ++pDataParams->wWCtr;

  /* Check for correctly received length */
  if (0U != (bCmdCode & 0x01U)) { /* MAC on Response */
    /* Check for a TM Protected block */
    if (0U != (wTMProtectBlock)) {
      /* check response length for TM Protected block */
      if (wRxLength != (1 /* Status */ + PHAL_MFPEVX_SIZE_TMC /* TMC */ + PHAL_MFPEVX_SIZE_TMV /* TMV */
              +
              PHAL_MFPEVX_TRUNCATED_MAC_SIZE /* MAC */)) {
        return PH_ADD_COMPCODE_FIXED(PH_ERR_PROTOCOL_ERROR, PH_COMP_AL_MFPEVX);
      }
    } else {
      /* check response length for non TM protected block */
      if (wRxLength != (1 /* Status */ + PHAL_MFPEVX_TRUNCATED_MAC_SIZE /* MAC */)) {
        return PH_ADD_COMPCODE_FIXED(PH_ERR_PROTOCOL_ERROR, PH_COMP_AL_MFPEVX);
      }
    }

    /* Let's Verify the MAC */
    wCmdLength = 0;

    /* For start location of MAC in the response data. This value will be used if the
     * the bolck is not a TMProtectedBlock.
     */
    wDataLength = 1;    /* Response Code */

    aCmdBuf[wCmdLength++] = pResponse[0];
    aCmdBuf[wCmdLength++] = (uint8_t)pDataParams->wWCtr;
    aCmdBuf[wCmdLength++] = (uint8_t)(pDataParams->wWCtr >> 8U);
    (void)memcpy(&aCmdBuf[wCmdLength], pDataParams->bTi, PHAL_MFPEVX_SIZE_TI);
    wCmdLength = wCmdLength /* Response Code + W_Ctr */ + PHAL_MFPEVX_SIZE_TI;

    /* Adds the TMC and TMV value for MAC calculation if targeting a TMPRotectedBlock. */
    if (0U != (wTMProtectBlock)) {
      (void)memcpy(&aCmdBuf[wCmdLength], &pResponse[1], PHAL_MFPEVX_SIZE_TMC);
      wCmdLength = wCmdLength /* Response Code + W_Ctr + TI */ + PHAL_MFPEVX_SIZE_TMC;

      (void)memcpy(&aCmdBuf[wCmdLength], &pResponse[5], PHAL_MFPEVX_SIZE_TMV);
      wCmdLength = wCmdLength /* Response Code + W_Ctr + TI + TMC */ + PHAL_MFPEVX_SIZE_TMV;

      /* For start location of MAC in the response data. This value will be used if the
       * the bolck is a TMProtectedBlock.
       */
      wDataLength = wDataLength /* Response Code */ + PHAL_MFPEVX_SIZE_TMC + PHAL_MFPEVX_SIZE_TMV;
    }

    /* Load default IV */
    PH_CHECK_SUCCESS_FCT(statusTmp, phCryptoSym_LoadIv(
            pDataParams->pCryptoDataParamsMac,
            phalMfpEVx_Sw_FirstIv,
            PH_CRYPTOSYM_AES_BLOCK_SIZE));

    /* CMAC with Padding */
    /* Calculate the MAC */
    PH_CHECK_SUCCESS_FCT(statusTmp, phCryptoSym_CalculateMac(
            pDataParams->pCryptoDataParamsMac,
            PH_CRYPTOSYM_MAC_MODE_CMAC,
            aCmdBuf,
            wCmdLength,
            aMac,
            &bMacLength));

    /* Truncate the MAC */
    phalMfpEVx_Sw_Int_TruncateMac(aMac, aMac);

    /* Compare the result */
    if (memcmp(aMac, &pResponse[wDataLength], PHAL_MFPEVX_TRUNCATED_MAC_SIZE) != 0x00) {
      return PH_ADD_COMPCODE_FIXED(PH_ERR_AUTH_ERROR, PH_COMP_AL_MFPEVX);
    }
  } else { /* No MAC on Response */
    /* Check for a TM Protected block */
    if (0U != (wTMProtectBlock)) {
      /* check response length */
      if (wRxLength != (1 /* Status */ + PHAL_MFPEVX_SIZE_TMC /* TMC */ +
              PHAL_MFPEVX_SIZE_TMV /* TMV */)) {
        return PH_ADD_COMPCODE_FIXED(PH_ERR_PROTOCOL_ERROR, PH_COMP_AL_MFPEVX);
      }
    } else {
      /* check response length */
      if (wRxLength != 1U /* Status */) {
        return PH_ADD_COMPCODE_FIXED(PH_ERR_PROTOCOL_ERROR, PH_COMP_AL_MFPEVX);
      }
    }
  }

  /* Copies the TMC and TMV value from response buffer to the reference parameter
   * if TMProtectedBlock is targeted else make the reference parameter NULL.
   */
  if (0U != (wTMProtectBlock)) {
    (void)memcpy(pTMC, &pResponse[1], PHAL_MFPEVX_SIZE_TMC);
    (void)memcpy(pTMV, &pResponse[PHAL_MFPEVX_SIZE_TMC + 1U], PHAL_MFPEVX_SIZE_TMV);
  } else {
    if ((pTMC != NULL) && (pTMV != NULL)) {
      (void)memset(pTMC, 0x00, PHAL_MFPEVX_SIZE_TMC);
      (void)memset(pTMV, 0x00, PHAL_MFPEVX_SIZE_TMV);
    }
  }

  return PH_ERR_SUCCESS;
}

phStatus_t
phalMfpEVx_Sw_ReadExtMfc(phalMfpEVx_Sw_DataParams_t *pDataParams, uint8_t bBlockNo,
    uint8_t *pBlockData)
{
  phStatus_t  PH_MEMLOC_REM statusTmp;
  uint8_t     PH_MEMLOC_REM aCommand[2];
  uint8_t     PH_MEMLOC_REM bCmdLen = 0;
  uint8_t    *PH_MEMLOC_REM pRxBuffer = NULL;
  uint16_t    PH_MEMLOC_REM wRxLength = 0;
  uint32_t    PH_MEMLOC_REM wTMIStatus = 0;

  /* Frame the command buffer. */
  aCommand[bCmdLen++] = PHAL_MFPEVX_CMD_MFC_READ;
  aCommand[bCmdLen++] = bBlockNo;

  /* Exchange the command. */
  PH_CHECK_SUCCESS_FCT(statusTmp, phpalMifare_ExchangeL3(
          pDataParams->pPalMifareDataParams,
          PH_EXCHANGE_DEFAULT,
          aCommand,
          bCmdLen,
          &pRxBuffer,
          &wRxLength
      ));

  /* Evaluate the response for any errors. */
  PH_CHECK_SUCCESS_FCT(statusTmp, phalMfpEVx_Int_ComputeErrorResponseMfc(wRxLength, pRxBuffer[0]));

  /* Check the received length. */
  if (wRxLength != PHAL_MFPEVX_DATA_BLOCK_SIZE) {
    return PH_ADD_COMPCODE_FIXED(PH_ERR_PROTOCOL_ERROR, PH_COMP_AL_MFPEVX);
  }

  /* Copy the received data to the return parameter. */
  (void)memcpy(pBlockData, pRxBuffer, wRxLength);

  /* Get the status for TMI Collection. */
  PH_CHECK_SUCCESS_FCT(statusTmp, phTMIUtils_GetConfig((phTMIUtils_t *)pDataParams->pTMIDataParams,
          PH_TMIUTILS_TMI_STATUS,
          &wTMIStatus));

  /* Update the contents to TMI buffer. */
  if (wTMIStatus == PH_ON) {
    PH_CHECK_SUCCESS_FCT(statusTmp, phTMIUtils_CollectTMI((phTMIUtils_t *)pDataParams->pTMIDataParams,
            PH_TMIUTILS_NO_PADDING,
            aCommand,
            bCmdLen,
            pBlockData,
            wRxLength,
            PHAL_MFPEVX_DATA_BLOCK_SIZE
        ));
  }

  return PH_ERR_SUCCESS;
}

phStatus_t
phalMfpEVx_Sw_WriteExtMfc(phalMfpEVx_Sw_DataParams_t *pDataParams, uint8_t bCmdCode,
    uint8_t bBlockNo, uint8_t *pData,
    uint16_t wDataLength, uint8_t *pTMC, uint8_t *pTMV)
{
  phStatus_t  PH_MEMLOC_REM status = 0;
  phStatus_t  PH_MEMLOC_REM statusTmp;
  uint8_t     PH_MEMLOC_REM aCommand[2];
  uint8_t     PH_MEMLOC_REM aTmp[4] = { 0x00, 0x00, 0x00, 0x00 };
  uint8_t     PH_MEMLOC_REM bCmdLen = 0;
  uint8_t    *PH_MEMLOC_REM pRxBuffer = NULL;
  uint16_t    PH_MEMLOC_REM wRxLength = 0;
  uint32_t    PH_MEMLOC_REM wTMIStatus = 0;

  /* build command frame */
  aCommand[bCmdLen++] = bCmdCode;
  aCommand[bCmdLen++] = bBlockNo;

  /* Exchange the command frame (first part) */
  PH_CHECK_SUCCESS_FCT(statusTmp, phpalMifare_ExchangeL3(
          pDataParams->pPalMifareDataParams,
          PH_EXCHANGE_DEFAULT,
          aCommand,
          bCmdLen,
          &pRxBuffer,
          &wRxLength
      ));

  if (wRxLength == 1U) {
    /* Evaluate the response for any errors. */
    PH_CHECK_SUCCESS_FCT(statusTmp, phalMfpEVx_Int_ComputeErrorResponseMfc(wRxLength, pRxBuffer[0]));
  } else {
    /* Do not check for Error code if its a Transfer command because Transfer command will return the
     * TMC and TMV data if TM Protected block for first part of command exchange. */
    if (bCmdCode != PHAL_MFPEVX_CMD_MFC_TRANSFER) {
      /* If Response byte is not equal to 1, then it's a PH_ERR_PROTOCOL_ERROR */
      return PH_ADD_COMPCODE_FIXED(PH_ERR_PROTOCOL_ERROR, PH_COMP_PAL_MIFARE);
    }
  }

  if ((bCmdCode == PHAL_MFPEVX_CMD_MFC_WRITE) || (bCmdCode == PHAL_MFPEVX_CMD_MFC_INCREMENT) ||
      (bCmdCode == PHAL_MFPEVX_CMD_MFC_DECREMENT) || (bCmdCode == PHAL_MFPEVX_CMD_MFC_RESTORE)) {
    if (bCmdCode == PHAL_MFPEVX_CMD_MFC_RESTORE) {
      pData = aTmp;
      wDataLength = 4;
    }

    /* Exchange the data (second part) */
    status = phpalMifare_ExchangeL3(
            pDataParams->pPalMifareDataParams,
            PH_EXCHANGE_DEFAULT,
            pData,
            wDataLength,
            &pRxBuffer,
            &wRxLength
        );
  }

  if (bCmdCode == PHAL_MFPEVX_CMD_MFC_RESTORE) {
    pData = NULL;
    wDataLength = 0;
  }

  /* Check for success in the response.
   * The error handling will be performed as follows.
   *    1. If TMC and TMV is not returned, the wRxLength will be one and the error handling will be processed.
   *    2. If TMC and TMV is returned, the wRxLenth will be greater than one. So there will be no error handling
   *       processed rather it will just return.
   */
  PH_CHECK_SUCCESS_FCT(status, phalMfpEVx_Int_ComputeErrorResponseMfc(wRxLength, pRxBuffer[0]));

  /* Check if TMV and TMC is returned for Write and Transfer command. */
  if ((bCmdCode == PHAL_MFPEVX_CMD_MFC_WRITE) || (bCmdCode == PHAL_MFPEVX_CMD_MFC_TRANSFER)) {
    /* If TMC and TMV is returned the RxLength will be greater than 1. */
    if (wRxLength > 1U) {
      /* Check if response equals to sum of TMC and TMV size. */
      if (wRxLength != (PHAL_MFPEVX_SIZE_TMC + PHAL_MFPEVX_SIZE_TMV)) {
        return PH_ADD_COMPCODE_FIXED(PH_ERR_PROTOCOL_ERROR, PH_COMP_AL_MFPEVX);
      }

      /* Check if NULL is passed for TMC parameter. */
      if (pTMC == NULL) {
        return PH_ADD_COMPCODE_FIXED(PH_ERR_INVALID_PARAMETER, PH_COMP_AL_MFPEVX);
      }

      /* Check if NULL is passed for TMV parameter. */
      if (pTMV == NULL) {
        return PH_ADD_COMPCODE_FIXED(PH_ERR_INVALID_PARAMETER, PH_COMP_AL_MFPEVX);
      }

      (void)memcpy(pTMC, pRxBuffer, PHAL_MFPEVX_SIZE_TMC);
      (void)memcpy(pTMV, &pRxBuffer[PHAL_MFPEVX_SIZE_TMC], PHAL_MFPEVX_SIZE_TMV);
    } else {
      if ((pTMC != NULL) && (pTMV != NULL)) {
        (void)memset(pTMC, 0x00, PHAL_MFPEVX_SIZE_TMC);
        (void)memset(pTMV, 0x00, PHAL_MFPEVX_SIZE_TMV);
      }
    }
  }

  /* Get the status for TMI Collection. */
  PH_CHECK_SUCCESS_FCT(statusTmp, phTMIUtils_GetConfig((phTMIUtils_t *)pDataParams->pTMIDataParams,
          PH_TMIUTILS_TMI_STATUS,
          &wTMIStatus));

  /* Update the contents to TMI buffer. */
  if (wTMIStatus == PH_ON) {
    PH_CHECK_SUCCESS_FCT(statusTmp, phTMIUtils_CollectTMI((phTMIUtils_t *)pDataParams->pTMIDataParams,
            PH_TMIUTILS_NO_PADDING,
            aCommand,
            bCmdLen,
            pData,
            wDataLength,
            PHAL_MFPEVX_DATA_BLOCK_SIZE
        ));
  }

  return PH_ERR_SUCCESS;
}
#endif /* NXPBUILD__PHAL_MFPEVX_NDA */

/***************************************************************************************************************************************/
/* Mifare Plus EVx Software command for special operations.                                                                            */
/***************************************************************************************************************************************/
phStatus_t
phalMfpEVx_Sw_GetVersion(phalMfpEVx_Sw_DataParams_t *pDataParams, uint8_t *pResponse)
{
  uint16_t    PH_MEMLOC_REM statusTmp = 0;
  uint8_t     PH_MEMLOC_REM aCmdBuf[PHAL_MFPEVX_VERSION_COMMAND_LENGTH];
  uint8_t     PH_MEMLOC_REM bCmdLen = 0;
  uint8_t    *PH_MEMLOC_REM pRxBuffer = NULL;
  uint16_t    PH_MEMLOC_REM wRxBufLen = 0;
#ifdef NXPBUILD__PHAL_MFPEVX_NDA
  uint8_t     PH_MEMLOC_REM aMac[PH_CRYPTOSYM_AES_BLOCK_SIZE] = {0};
  uint8_t     PH_MEMLOC_REM bMacLen = 0;
#endif /* NXPBUILD__PHAL_MFPEVX_NDA */
  uint8_t     PH_MEMLOC_REM aVersion[PHAL_MFPEVX_VERSION_INFO_LENGTH];
  uint8_t     PH_MEMLOC_REM bVerLen = 0;

  /* Frame the command. */
  aCmdBuf[bCmdLen++] = PHAL_MFPEVX_CMD_GET_VERSION;

#ifdef NXPBUILD__PHAL_MFPEVX_NDA
  /* Check if authenticated in MFP mode to append the MAC to the command. */
  if ((pDataParams->bAuthMode == PHAL_MFPEVX_SL1_MFP_AUTHENTICATED) ||
      (pDataParams->bAuthMode == PHAL_MFPEVX_SL3_MFP_AUTHENTICATED)) {
    aCmdBuf[bCmdLen++] = (uint8_t)(pDataParams->wRCtr);
    aCmdBuf[bCmdLen++] = (uint8_t)(pDataParams->wRCtr >> 8U);

    (void)memcpy(&aCmdBuf[bCmdLen], pDataParams->bTi, PHAL_MFPEVX_SIZE_TI);
    bCmdLen = bCmdLen + PHAL_MFPEVX_SIZE_TI /* TI*/;

    /* Load the Session MAC Key. */
    PH_CHECK_SUCCESS_FCT(statusTmp, phCryptoSym_LoadKeyDirect(
            pDataParams->pCryptoDataParamsMac,
            pDataParams->bSesAuthMACKey,
            PH_CRYPTOSYM_KEY_TYPE_AES128));

    /* Now calculate the MAC */
    PH_CHECK_SUCCESS_FCT(statusTmp, phCryptoSym_CalculateMac(
            pDataParams->pCryptoDataParamsMac,
            (PH_EXCHANGE_DEFAULT | PH_CRYPTOSYM_MAC_MODE_CMAC),
            aCmdBuf,
            bCmdLen,
            aMac,
            &bMacLen));

    /* Truncate the MAC. */
    phalMfpEVx_Sw_Int_TruncateMac(aMac, aMac);

    /* Add the MAC to the command buffer. */
    (void)memcpy(&aCmdBuf[1], aMac, PHAL_MFPEVX_TRUNCATED_MAC_SIZE);

    /* Update the command buffer length. */
    bCmdLen = 1U /* Command Code*/ + PHAL_MFPEVX_TRUNCATED_MAC_SIZE;
  }
#endif /* NXPBUILD__PHAL_MFPEVX_NDA */

  /* Exchange the first part of the command. */
  /* Check if ISO 7816-4 wapping is required. */
  if (0U != (pDataParams->bWrappedMode)) {
    PH_CHECK_SUCCESS_FCT(statusTmp, phalMfpEVx_Int_Send7816Apdu(
            pDataParams->pPalMifareDataParams,
            PH_EXCHANGE_DEFAULT,
            (uint16_t)(((uint16_t)bCmdLen) - 1U), /* Excluding the command code. */
            pDataParams->bExtendedLenApdu,
            aCmdBuf,
            bCmdLen,
            &pRxBuffer,
            &wRxBufLen));
  } else {
    PH_CHECK_SUCCESS_FCT(statusTmp, phpalMifare_ExchangeL4(
            pDataParams->pPalMifareDataParams,
            PH_EXCHANGE_DEFAULT,
            aCmdBuf,
            bCmdLen,
            &pRxBuffer,
            &wRxBufLen));
  }

  /* Check if additional frame byte is available in the response. */
  if ((wRxBufLen != (1U /* Status */ + PHAL_MFPEVX_VERSION_PART1_LENGTH)) &&
      (pRxBuffer[0] != PHAL_MFPEVX_RESP_ADDITIONAL_FRAME)) {
    return phalMfpEVx_Int_ComputeErrorResponse(wRxBufLen, pRxBuffer[0], PH_ON);
  }

  /* Copy the Version A into version buffer and update the version buffer length .*/
  (void)memcpy(&aVersion[bVerLen], &pRxBuffer[1], PHAL_MFPEVX_VERSION_PART1_LENGTH);
  bVerLen = PHAL_MFPEVX_VERSION_PART1_LENGTH;

  /* Update the additional command frame code to command buffer. */
  aCmdBuf[0] = PHAL_MFPEVX_RESP_ADDITIONAL_FRAME;
  bCmdLen = 1;

  /* Exchange the second part of the command. */
  /* Check if ISO 7816-4 wapping is required. */
  if (0U != (pDataParams->bWrappedMode)) {
    PH_CHECK_SUCCESS_FCT(statusTmp, phalMfpEVx_Int_Send7816Apdu(
            pDataParams->pPalMifareDataParams,
            PH_EXCHANGE_DEFAULT,
            (uint16_t)(((uint16_t)bCmdLen) - 1U), /* Excluding the command code. */
            pDataParams->bExtendedLenApdu,
            aCmdBuf,
            bCmdLen,
            &pRxBuffer,
            &wRxBufLen));
  } else {
    PH_CHECK_SUCCESS_FCT(statusTmp, phpalMifare_ExchangeL4(
            pDataParams->pPalMifareDataParams,
            PH_EXCHANGE_DEFAULT,
            aCmdBuf,
            bCmdLen,
            &pRxBuffer,
            &wRxBufLen));
  }

  /* Check if additional frame byte is available in the response. */
  if ((wRxBufLen != (1U /* Status */ + PHAL_MFPEVX_VERSION_PART2_LENGTH)) &&
      (pRxBuffer[0] != PHAL_MFPEVX_RESP_ADDITIONAL_FRAME)) {
    return phalMfpEVx_Int_ComputeErrorResponse(wRxBufLen, pRxBuffer[0], PH_ON);
  }

  /* Copy the Version B into version buffer and update the version buffer length .*/
  (void)memcpy(&aVersion[bVerLen], &pRxBuffer[1], PHAL_MFPEVX_VERSION_PART2_LENGTH);
  bVerLen = bVerLen + PHAL_MFPEVX_VERSION_PART2_LENGTH;

  /* Update the additional command frame code to command buffer. */
  aCmdBuf[0] = PHAL_MFPEVX_RESP_ADDITIONAL_FRAME;
  bCmdLen = 1;

  /* Exchange the third part of the command. */
  /* Check if ISO 7816-4 wapping is required. */
  if (0U != (pDataParams->bWrappedMode)) {
    PH_CHECK_SUCCESS_FCT(statusTmp, phalMfpEVx_Int_Send7816Apdu(
            pDataParams->pPalMifareDataParams,
            PH_EXCHANGE_DEFAULT,
            (uint16_t)(((uint16_t)bCmdLen) - 1U), /* Excluding the command code. */
            pDataParams->bExtendedLenApdu,
            aCmdBuf,
            bCmdLen,
            &pRxBuffer,
            &wRxBufLen));
  } else {
    PH_CHECK_SUCCESS_FCT(statusTmp, phpalMifare_ExchangeL4(
            pDataParams->pPalMifareDataParams,
            PH_EXCHANGE_DEFAULT,
            aCmdBuf,
            bCmdLen,
            &pRxBuffer,
            &wRxBufLen));
  }

  /* Check if authenticated in MFP mode. */
  if ((pDataParams->bAuthMode == PHAL_MFPEVX_SL1_MFP_AUTHENTICATED) ||
      (pDataParams->bAuthMode == PHAL_MFPEVX_SL3_MFP_AUTHENTICATED)) {
#ifdef NXPBUILD__PHAL_MFPEVX_NDA
    /* Check if ISO14443 L4 success byte is available in the response. */
    if ((wRxBufLen != (1U /* Status */ + PHAL_MFPEVX_VERSION_PART3_LENGTH_04B +
                PHAL_MFPEVX_TRUNCATED_MAC_SIZE)) &&
        (wRxBufLen != (1U /* Status */ + PHAL_MFPEVX_VERSION_PART3_LENGTH_07B +
                PHAL_MFPEVX_TRUNCATED_MAC_SIZE)) &&
        (wRxBufLen != (1U /* Status */ + PHAL_MFPEVX_VERSION_PART3_LENGTH_10B +
                PHAL_MFPEVX_TRUNCATED_MAC_SIZE)) &&
        (pRxBuffer[0] != PHAL_MFPEVX_RESP_ACK_ISO4)) {
      return phalMfpEVx_Int_ComputeErrorResponse(wRxBufLen, pRxBuffer[0], PH_ON);
    }

    /* Copy the Version C into version buffer and update the version buffer length .*/
    (void)memcpy(&aVersion[bVerLen], &pRxBuffer[1],
        (wRxBufLen - 1U /* Status */ - PHAL_MFPEVX_TRUNCATED_MAC_SIZE));
    bVerLen = bVerLen + (uint8_t)(wRxBufLen - 1U /* Status code excluded. */ -
            PHAL_MFPEVX_TRUNCATED_MAC_SIZE);

    /* Increment the read counter. */
    pDataParams->wRCtr++;

    /* Verify the received MAC. */
    bCmdLen = 0;
    aCmdBuf[bCmdLen++] = PHAL_MFPEVX_RESP_ACK_ISO4;
    aCmdBuf[bCmdLen++] = (uint8_t)(pDataParams->wRCtr);
    aCmdBuf[bCmdLen++] = (uint8_t)(pDataParams->wRCtr >> 8U);

    (void)memcpy(&aCmdBuf[bCmdLen], pDataParams->bTi, PHAL_MFPEVX_SIZE_TI);
    bCmdLen = bCmdLen + PHAL_MFPEVX_SIZE_TI;

    (void)memcpy(&aCmdBuf[bCmdLen], aVersion, bVerLen);
    bCmdLen = bCmdLen + bVerLen;

    /* Load the Session MAC Key. */
    PH_CHECK_SUCCESS_FCT(statusTmp, phCryptoSym_LoadKeyDirect(
            pDataParams->pCryptoDataParamsMac,
            pDataParams->bSesAuthMACKey,
            PH_CRYPTOSYM_KEY_TYPE_AES128));

    /* Now calculate the MAC */
    PH_CHECK_SUCCESS_FCT(statusTmp, phCryptoSym_CalculateMac(
            pDataParams->pCryptoDataParamsMac,
            (PH_EXCHANGE_DEFAULT | PH_CRYPTOSYM_MAC_MODE_CMAC),
            aCmdBuf,
            bCmdLen,
            aMac,
            &bMacLen));

    /* Truncate the MAC. */
    phalMfpEVx_Sw_Int_TruncateMac(aMac, aMac);

    /* Compare the MAC. */
    if (memcmp(aMac, &pRxBuffer[wRxBufLen - PHAL_MFPEVX_TRUNCATED_MAC_SIZE],
            PHAL_MFPEVX_TRUNCATED_MAC_SIZE) != 0x00) {
      return PH_ADD_COMPCODE_FIXED(PH_ERR_INTEGRITY_ERROR, PH_COMP_AL_MFPEVX);
    }
#endif /* NXPBUILD__PHAL_MFPEVX_NDA */
  } else {
    /* Check if ISO14443 L4 success byte is available in the response. */
    if ((wRxBufLen != (1U /* Status */ + PHAL_MFPEVX_VERSION_PART3_LENGTH_04B)) &&
        (wRxBufLen != (1U /* Status */ + PHAL_MFPEVX_VERSION_PART3_LENGTH_07B)) &&
        (wRxBufLen != (1U /* Status */ + PHAL_MFPEVX_VERSION_PART3_LENGTH_10B)) &&
        (pRxBuffer[0] != PHAL_MFPEVX_RESP_ACK_ISO4)) {
      return phalMfpEVx_Int_ComputeErrorResponse(wRxBufLen, pRxBuffer[0], PH_ON);
    }

    /* Copy the VersionC bytes into version buffer and update the version buffer length .*/
    (void)memcpy(&aVersion[bVerLen], &pRxBuffer[1], (wRxBufLen - 1U /* Status */));
    bVerLen = (uint8_t)(bVerLen + (wRxBufLen -
                1U /* Status code excluded. */)) /* Version C length. */;
  }

  /* Copy the local version buffer to the reference parameter. */
  (void)memcpy(pResponse, aVersion, bVerLen);

  return PH_ERR_SUCCESS;
}

phStatus_t
phalMfpEVx_Sw_ReadSign(phalMfpEVx_Sw_DataParams_t *pDataParams, uint8_t bLayer4Comm,
    uint8_t bAddr, uint8_t **pSignature)
{

  phStatus_t  PH_MEMLOC_REM statusTmp;
  uint8_t     PH_MEMLOC_REM bCmdBuff[1 /* command code */ + 2 /* R_Ctr */ + PHAL_MFPEVX_SIZE_TI +
        1 /* Address */ + PHAL_MFPEVX_SIG_LENGTH_ENC];
  uint8_t    *PH_MEMLOC_REM pResponse = NULL;
  uint16_t    PH_MEMLOC_REM wRxLength = 0;
  uint16_t    PH_MEMLOC_REM wCmdLen = 0;
#ifdef NXPBUILD__PHAL_MFPEVX_NDA
  uint8_t     PH_MEMLOC_REM bMac[PH_CRYPTOSYM_AES_BLOCK_SIZE] = {0};
  uint8_t     PH_MEMLOC_REM bMacLength;
  uint8_t     aIv[PH_CRYPTOSYM_AES_BLOCK_SIZE];
#endif /*NXPBUILD__PHAL_MFPEVX_NDA*/
  /* build command frame */
  bCmdBuff[wCmdLen++] = PHAL_MFPEVX_CMD_READ_SIG;

  /* Req spec(ver 0.06 says),
   * 1. Cmd.Read_Sig shall return the NXPOriginalitySignature as written during wafer test in plain if not authenticated
   * 2. Cmd.Read_Sig shall require MACed command if authenticated.
   */
  /* Exchange command/response after Layer 4 activation */
  if (0U != (bLayer4Comm)) {
    switch (pDataParams->bAuthMode) {
#ifdef NXPBUILD__PHAL_MFPEVX_NDA
      case PHAL_MFPEVX_SL1_MFP_AUTHENTICATED:
      case PHAL_MFPEVX_SL3_MFP_AUTHENTICATED:
        /* MAC on command should to be sent */
        /* Framing the buffer for calculation of MAC */
        bCmdBuff[wCmdLen++] = (uint8_t)(pDataParams->wRCtr & 0x00FFU);
        bCmdBuff[wCmdLen++] = (uint8_t)((pDataParams->wRCtr & 0xFF00U) >> 8U);

        (void)memcpy(&bCmdBuff[wCmdLen], pDataParams->bTi, PHAL_MFPEVX_SIZE_TI);
        wCmdLen += PHAL_MFPEVX_SIZE_TI;
        bCmdBuff[wCmdLen++] = bAddr;

        /* load key */
        PH_CHECK_SUCCESS_FCT(statusTmp, phCryptoSym_LoadKeyDirect(
                pDataParams->pCryptoDataParamsMac,
                pDataParams->bSesAuthMACKey,
                PH_CRYPTOSYM_KEY_TYPE_AES128));

        /* Load Zero Iv */
        PH_CHECK_SUCCESS_FCT(statusTmp, phCryptoSym_LoadIv(
                pDataParams->pCryptoDataParamsMac,
                phalMfpEVx_Sw_FirstIv,
                PH_CRYPTOSYM_AES_BLOCK_SIZE
            ));

        /* As per the ref arch, the read counter should be incremented */
        ++pDataParams->wRCtr;

        /* Load the Session MAC Key. */
        PH_CHECK_SUCCESS_FCT(statusTmp, phCryptoSym_LoadKeyDirect(
                pDataParams->pCryptoDataParamsMac,
                pDataParams->bSesAuthMACKey,
                PH_CRYPTOSYM_KEY_TYPE_AES128));

        /* Caclulate MAC as MAC(Km, 0x3C||LMSB(R_Ctr)||TI||Address) */
        PH_CHECK_SUCCESS_FCT(statusTmp, phCryptoSym_CalculateMac(
                pDataParams->pCryptoDataParamsMac,
                (PH_CRYPTOSYM_MAC_MODE_CMAC | PH_EXCHANGE_DEFAULT),
                bCmdBuff,
                wCmdLen,
                bMac,
                &bMacLength
            ));

        /* perform MAC truncation */
        phalMfpEVx_Sw_Int_TruncateMac(bMac, bMac);

        wCmdLen = 0x01;
        bCmdBuff[wCmdLen++] = bAddr;
        (void)memcpy(&bCmdBuff[wCmdLen], bMac, PHAL_MFPEVX_TRUNCATED_MAC_SIZE);

        wCmdLen += PHAL_MFPEVX_TRUNCATED_MAC_SIZE;
        break;
#endif /* NXPBUILD__PHAL_MFPEVX_NDA */

      case PHAL_MFPEVX_NOTAUTHENTICATED:
      case PHAL_MFPEVX_NOT_AUTHENTICATED_L3:
      case PHAL_MFPEVX_NOT_AUTHENTICATED_L4:
      case PHAL_MFPEVX_SL1_MIFARE_AUTHENTICATED:
        /* PICC not Authenticated */
        bCmdBuff[wCmdLen++] = bAddr;
        break;

      default:
        break;
    }

    /* Check if ISO 7816-4 wrapping is required */
    if (0U != (pDataParams->bWrappedMode)) {
      /* buffer the header */
      PH_CHECK_SUCCESS_FCT(statusTmp, phalMfpEVx_Int_Send7816Apdu(
              pDataParams->pPalMifareDataParams,
              PH_EXCHANGE_DEFAULT,
              wCmdLen - 1U,       /* Excluding the command code */
              pDataParams->bExtendedLenApdu,
              bCmdBuff,
              wCmdLen,        /* Command code is included as part of length. */
              &pResponse,
              &wRxLength));
    } else {
      /* buffer the header */
      PH_CHECK_SUCCESS_FCT(statusTmp, phpalMifare_ExchangeL4(
              pDataParams->pPalMifareDataParams,
              PH_EXCHANGE_DEFAULT,
              bCmdBuff,
              wCmdLen,
              &pResponse,
              &wRxLength));
    }
  } else {
    bCmdBuff[wCmdLen++] = bAddr;
    /* command exchange in layer 3 */
    PH_CHECK_SUCCESS_FCT(statusTmp, phpalMifare_ExchangeL3(
            pDataParams->pPalMifareDataParams,
            PH_EXCHANGE_DEFAULT,
            bCmdBuff,
            wCmdLen,
            &pResponse,
            &wRxLength));

  }

  PH_CHECK_SUCCESS_FCT(statusTmp, phalMfpEVx_Int_ComputeErrorResponse(wRxLength, pResponse[0],
          bLayer4Comm));

  /* Check received length for 64 (Encrypted Signature) + 8 (MAC) bytes */
  switch (pDataParams->bAuthMode) {
#ifdef NXPBUILD__PHAL_MFPEVX_NDA
    case PHAL_MFPEVX_SL1_MFP_AUTHENTICATED:
    case PHAL_MFPEVX_SL3_MFP_AUTHENTICATED:
      /* 64 Bytes Signature data + 8 Bytes MAC + 1 byte status code */
      if (wRxLength != (PHAL_MFPEVX_SIG_LENGTH_ENC + 8U + 1U)) {
        return PH_ADD_COMPCODE_FIXED(PH_ERR_LENGTH_ERROR, PH_COMP_AL_MFPEVX);
      } else {
        wCmdLen = 0;
        /* MAC on response should to be checked */
        /* Framing the buffer for calculation of MAC */
        bCmdBuff[wCmdLen++] = pResponse[0];
        bCmdBuff[wCmdLen++] = (uint8_t)(pDataParams->wRCtr & 0x00FFU);
        bCmdBuff[wCmdLen++] = (uint8_t)((pDataParams->wRCtr & 0xFF00U) >> 8U);
        (void)memcpy(&bCmdBuff[wCmdLen], pDataParams->bTi, PHAL_MFPEVX_SIZE_TI);
        wCmdLen += PHAL_MFPEVX_SIZE_TI;
        bCmdBuff[wCmdLen++] = bAddr;
        /* Adding the response as well in the buffer for MAC calculation as per the ref arch */
        (void)memcpy(&bCmdBuff[wCmdLen], &pResponse[1], PHAL_MFPEVX_SIG_LENGTH_ENC);
        wCmdLen += PHAL_MFPEVX_SIG_LENGTH_ENC;

        /* load session MAC key into crypto params */
        PH_CHECK_SUCCESS_FCT(statusTmp, phCryptoSym_LoadKeyDirect(
                pDataParams->pCryptoDataParamsMac,
                pDataParams->bSesAuthMACKey,
                PH_CRYPTOSYM_KEY_TYPE_AES128));

        /* Load Zero Iv */
        PH_CHECK_SUCCESS_FCT(statusTmp, phCryptoSym_LoadIv(
                pDataParams->pCryptoDataParamsMac,
                phalMfpEVx_Sw_FirstIv,
                PH_CRYPTOSYM_AES_BLOCK_SIZE
            ));

        /* Caclulate MAC as MAC(Km, 0x3C||LMSB(R_Ctr)||TI||Address||E(Ke,NXPOriginalitySignature)) */
        PH_CHECK_SUCCESS_FCT(statusTmp, phCryptoSym_CalculateMac(
                pDataParams->pCryptoDataParamsMac,
                (PH_CRYPTOSYM_MAC_MODE_CMAC | PH_EXCHANGE_DEFAULT),
                bCmdBuff,
                wCmdLen,
                bMac,
                &bMacLength
            ));

        /* perform MAC truncation */
        phalMfpEVx_Sw_Int_TruncateMac(bMac, bMac);

        /* Compare the MAC calculated above with the MAC on Response from PICC */
        if (memcmp(bMac, &pResponse[65], PHAL_MFPEVX_TRUNCATED_MAC_SIZE) != 0) {
          return PH_ADD_COMPCODE_FIXED(PHAL_MFPEVX_ERR_AUTH, PH_COMP_AL_MFPEVX);
        }

        /* load session ENC Key */
        PH_CHECK_SUCCESS_FCT(statusTmp, phCryptoSym_LoadKeyDirect(
                pDataParams->pCryptoDataParamsEnc,
                pDataParams->bSesAuthENCKey,
                PH_CRYPTOSYM_KEY_TYPE_AES128));

        /* Load the ENC IV */
        PH_CHECK_SUCCESS_FCT(statusTmp, phalMfpEVx_Sw_Int_ComputeIv(
                pDataParams,
                PH_ON,
                pDataParams->bTi,
                pDataParams->wRCtr,
                pDataParams->wWCtr,
                aIv));

        PH_CHECK_SUCCESS_FCT(statusTmp, phCryptoSym_LoadIv(
                pDataParams->pCryptoDataParamsEnc,
                aIv,
                PH_CRYPTOSYM_AES_BLOCK_SIZE));

        /* Decrypt the encrypted signature */
        PH_CHECK_SUCCESS_FCT(statusTmp, phCryptoSym_Decrypt(
                pDataParams->pCryptoDataParamsEnc,
                PH_CRYPTOSYM_CIPHER_MODE_CBC | PH_EXCHANGE_DEFAULT,
                &pResponse[1],
                PHAL_MFPEVX_SIG_LENGTH_ENC,
                &pResponse[1]
            ));

        /* Increment receive buffer to point to first byte.
         * then Assign the decrypted response to signature.
         * as the pResponse[0] = status code(90)
         */
        ++pResponse;
        *pSignature = pResponse;
      }
      break;
#endif /* NXPBUILD__PHAL_MFPEVX_NDA */

    case PHAL_MFPEVX_NOTAUTHENTICATED:
    case PHAL_MFPEVX_NOT_AUTHENTICATED_L3:
    case PHAL_MFPEVX_NOT_AUTHENTICATED_L4:
    case PHAL_MFPEVX_SL1_MIFARE_AUTHENTICATED:
      /* Check for 56 bytes of Signature data + 1 byte status code */
      if (wRxLength != (PHAL_MFPEVX_SIG_LENGTH + 1U)) {
        return PH_ADD_COMPCODE_FIXED(PH_ERR_LENGTH_ERROR, PH_COMP_AL_MFPEVX);
      } else {
        /* Increment receive buffer to point to first byte.
        * then Assign the decrypted response to signature
        * as the pResponse[0] = status code(90).
        */
        ++pResponse;
        *pSignature = pResponse;
      }
      break;

    default:
      break;
  }

  return PH_ERR_SUCCESS;
}

phStatus_t
phalMfpEVx_Sw_ResetAuth(phalMfpEVx_Sw_DataParams_t *pDataParams)
{
  phStatus_t  PH_MEMLOC_REM statusTmp = 0;

  /* Perform ResetAuth. */
  PH_CHECK_SUCCESS_FCT(statusTmp, phalMfpEVx_Int_ResetAuth(pDataParams->pPalMifareDataParams,
          pDataParams->bWrappedMode, pDataParams->bExtendedLenApdu));

  /* Reset the crypto layer */
  PH_CHECK_SUCCESS_FCT(statusTmp, phalMfpEVx_ResetSecMsgState(pDataParams));

  /* Update the authentication state if VCA PC feature is required by the application. */
  if (pDataParams->pVCADataParams != NULL) {
    /* Reset VCA session */
    PH_CHECK_SUCCESS_FCT(statusTmp,
        phalVca_SetSessionKeyUtility((phalVca_Sw_DataParams_t *)pDataParams->pVCADataParams,
            pDataParams->bSesAuthENCKey,
            pDataParams->bAuthMode));
  }

  /* return exchange status code */
  return PH_ERR_SUCCESS;
}

phStatus_t
phalMfpEVx_Sw_PersonalizeUid(phalMfpEVx_Sw_DataParams_t *pDataParams, uint8_t bUidType)
{
  return phalMfpEVx_Int_PersonalizeUid(pDataParams->pPalMifareDataParams, bUidType);
}

phStatus_t
phalMfpEVx_Sw_SetConfigSL1(phalMfpEVx_Sw_DataParams_t *pDataParams, uint8_t bOption)
{
  return phalMfpEVx_Int_SetConfigSL1(pDataParams->pPalMifareDataParams, bOption);
}

phStatus_t
phalMfpEVx_Sw_ReadSL1TMBlock(phalMfpEVx_Sw_DataParams_t *pDataParams,
    uint16_t wBlockNr, uint8_t *pBlocks)
{
  return phalMfpEVx_Int_ReadSL1TMBlock(pDataParams->pPalMifareDataParams, wBlockNr, pBlocks);
}

phStatus_t
phalMfpEVx_Sw_VCSupportLastISOL3(phalMfpEVx_Sw_DataParams_t *pDataParams,
    uint8_t *pIid, uint8_t *pPcdCapL3, uint8_t *pInfo)
{
  return phalMfpEVx_Int_VCSupportLastISOL3(pDataParams->pPalMifareDataParams, pIid, pPcdCapL3,
          pInfo);
}

#ifdef NXPBUILD__PHAL_MFPEVX_NDA
phStatus_t
phalMfpEVx_Sw_ChangeKey(phalMfpEVx_Sw_DataParams_t *pDataParams,
    uint8_t bChangeKeyMaced, uint16_t wBlockNr, uint16_t wKeyNumber,
    uint16_t wKeyVersion, uint8_t bLenDivInput, uint8_t *pDivInput)
{
  phStatus_t statusTmp;
  uint8_t aKey[PH_CRYPTOSYM_AES128_KEY_SIZE];
  uint16_t wKeyType;
  uint8_t aCmd;

  if (0U != (bChangeKeyMaced)) {
    aCmd = PHAL_MFPEVX_CMD_WRITE_EM;
  } else {
    aCmd = PHAL_MFPEVX_CMD_WRITE_EN;
  }

  /* Get Key out of the key store object */
  PH_CHECK_SUCCESS_FCT(statusTmp, phKeyStore_GetKey(
          pDataParams->pKeyStoreDataParams,
          wKeyNumber,
          wKeyVersion,
          sizeof(aKey),
          aKey,
          &wKeyType));

  /* Key type check */
  if (wKeyType != PH_CRYPTOSYM_KEY_TYPE_AES128) {
    return PH_ADD_COMPCODE_FIXED(PH_ERR_INVALID_PARAMETER, PH_COMP_AL_MFPEVX);
  }

  if (0U != bLenDivInput) {
    if (pDataParams->pCryptoDiversifyDataParams == NULL) {
      return PH_ADD_COMPCODE_FIXED(PH_ERR_UNSUPPORTED_COMMAND, PH_COMP_AL_MFPEVX);
    }
    PH_CHECK_SUCCESS_FCT(statusTmp,
        phCryptoSym_DiversifyDirectKey(pDataParams->pCryptoDiversifyDataParams,
            PH_CRYPTOSYM_DIV_MODE_MIFARE_PLUS,
            aKey,
            wKeyType,
            pDivInput,
            bLenDivInput,
            aKey));
  }

  /* Perform actual write operation*/
  return phalMfpEVx_Sw_WriteExt(
          pDataParams,
          aCmd,
          wBlockNr,
          0x00,
          aKey,
          PHAL_MFPEVX_DATA_BLOCK_SIZE,
          PH_ON,
          NULL,
          NULL);
}

phStatus_t
phalMfpEVx_Sw_CommitReaderID(phalMfpEVx_Sw_DataParams_t *pDataParams,
    uint16_t wBlockNr, uint8_t *pTMRI, uint8_t *pEncTMRI)
{
  uint16_t    PH_MEMLOC_REM statusTmp;
  uint8_t     PH_MEMLOC_REM aCmd[30];
  uint8_t     PH_MEMLOC_REM wCmdLength = 0;
  uint8_t     PH_MEMLOC_REM *pRecv = NULL;
  uint16_t    PH_MEMLOC_REM wRxLength = 0;
  uint8_t     PH_MEMLOC_REM aCMAC[PH_CRYPTOSYM_AES_BLOCK_SIZE] = {0};
  uint32_t    PH_MEMLOC_REM wTMIStatus = 0;

  /* Write the command to command buffer */
  aCmd[wCmdLength++] = PHAL_MFPEVX_CMD_COMMIT_READER_ID;

  /* Write the LSB and MSB of W_Ctr to command buffer */
  aCmd[wCmdLength++] = (uint8_t)(pDataParams->wWCtr & 0xFFU);  /* LSB */
  aCmd[wCmdLength++] = (uint8_t)(pDataParams->wWCtr >> 8U);    /* MSB */

  /* Copy the TI data to command buffer and update the command buffer length */
  (void)memcpy(&aCmd[wCmdLength], pDataParams->bTi, PHAL_MFPEVX_SIZE_TI);
  wCmdLength += PHAL_MFPEVX_SIZE_TI;

  /* Write the LSB and MSB of block no to command buffer */
  aCmd[wCmdLength++] = (uint8_t)(wBlockNr & 0xFFU);            /* LSB */
  aCmd[wCmdLength++] = (uint8_t)(wBlockNr >> 8U);              /* MSB */

  /* Copy the TMRI data to command buffer and update the command buffer length */
  (void)memcpy(&aCmd[wCmdLength], pTMRI, PHAL_MFPEVX_SIZE_TMRI);
  wCmdLength += PHAL_MFPEVX_SIZE_TMRI;

  /* Load the session auth command key to crypto data params */
  PH_CHECK_SUCCESS_FCT(statusTmp, phCryptoSym_LoadKeyDirect(
          pDataParams->pCryptoDataParamsMac,
          pDataParams->bSesAuthMACKey,
          PH_CRYPTOSYM_KEY_TYPE_AES128));

  /* Backup the IV to be used for encryption later */
  (void)memcpy(pDataParams->bIv,
      ((phCryptoSym_Sw_DataParams_t *)pDataParams->pCryptoDataParamsMac)->pIV,
      PH_CRYPTOSYM_AES128_KEY_SIZE);

  /* Calculate MAC on the data. */
  PH_CHECK_SUCCESS_FCT(statusTmp, phCryptoSym_CalculateMac(
          pDataParams->pCryptoDataParamsMac,
          (PH_CRYPTOSYM_MAC_MODE_CMAC | PH_EXCHANGE_DEFAULT),
          aCmd,
          wCmdLength,
          aCMAC,
          &wCmdLength
      ));

  /* Perform MAC truncation */
  phalMfpEVx_Sw_Int_TruncateMac(aCMAC, aCMAC);

  /* Form the command */
  wCmdLength = 0;
  (void)memset(aCmd, 0x00, (size_t)sizeof(aCmd));

  /* Write the command to command buffer */
  aCmd[wCmdLength++] = PHAL_MFPEVX_CMD_COMMIT_READER_ID;

  /* Write the LSB & MSB of Block no to command buffer */
  aCmd[wCmdLength++] = (uint8_t)(wBlockNr & 0xFFU);        /* LSB */
  aCmd[wCmdLength++] = (uint8_t)(wBlockNr >> 8U);          /* MSB */

  /* Copy the TMRI data to command buffer and update the command buffer length */
  (void)memcpy(&aCmd[wCmdLength], pTMRI, PHAL_MFPEVX_SIZE_TMRI);
  wCmdLength += PHAL_MFPEVX_SIZE_TMRI;

  /* Copy the truncated MAC data to command buffer and update the command buffer length */
  (void)memcpy(&aCmd[wCmdLength], &aCMAC[0], PHAL_MFPEVX_TRUNCATED_MAC_SIZE);
  wCmdLength += PHAL_MFPEVX_TRUNCATED_MAC_SIZE;

  /* Check if ISO 7816-4 wapping is required */
  if (0U != (pDataParams->bWrappedMode)) {
    /* Transfer the data. */
    PH_CHECK_SUCCESS_FCT(statusTmp, phalMfpEVx_Int_Send7816Apdu(
            pDataParams->pPalMifareDataParams,
            PH_EXCHANGE_DEFAULT,
            wCmdLength - 1U, /* Excluding the command code */
            pDataParams->bExtendedLenApdu,
            aCmd,
            wCmdLength,     /* Command code is included as part of length. */
            &pRecv,
            &wRxLength));
  } else {
    /* Transfer the data */
    PH_CHECK_SUCCESS_FCT(statusTmp, phpalMifare_ExchangeL4(
            pDataParams->pPalMifareDataParams,
            PH_EXCHANGE_DEFAULT,
            aCmd,
            wCmdLength, /*Command (1-Byte) + BNr (2-Byte) + TMRI (16-Byte) + MAC (8-Byte) */
            &pRecv,
            &wRxLength));
  }

  /* Increment the write counter */
  ++pDataParams->wWCtr;

  /* Verify for success in response */
  PH_CHECK_SUCCESS_FCT(statusTmp, phalMfpEVx_Int_ComputeErrorResponse(wRxLength, pRecv[0], PH_ON));

  /* Clear the command buffer and command buffer length */
  wCmdLength = 0;
  (void)memset(aCmd, 0x00, (size_t)sizeof(aCmd));

  /* Write the response (0x90) to command buffer */
  aCmd[wCmdLength++] = pRecv[0];

  /* Write the LSB and MSB of W_Ctr to command buffer */
  aCmd[wCmdLength++] = (uint8_t)(pDataParams->wWCtr & 0xFFU);      /* LSB */
  aCmd[wCmdLength++] = (uint8_t)(pDataParams->wWCtr >> 8U);        /* MSB */

  /* Copy the TI data to command buffer and update the command buffer length */
  (void)memcpy(&aCmd[wCmdLength], pDataParams->bTi, PHAL_MFPEVX_SIZE_TI);
  wCmdLength += PHAL_MFPEVX_SIZE_TI;

  /* Copy the response EncTMRI data to command buffer and update the command buffer length */
  (void)memcpy(&aCmd[wCmdLength], &pRecv[1], PHAL_MFPEVX_SIZE_ENCTMRI);
  wCmdLength += PHAL_MFPEVX_SIZE_TMRI;

  /* Load the default IV */
  PH_CHECK_SUCCESS_FCT(statusTmp, phCryptoSym_LoadIv(
          pDataParams->pCryptoDataParamsMac,
          phalMfpEVx_Sw_FirstIv,
          PH_CRYPTOSYM_AES_BLOCK_SIZE));

  /* Calculate command on the data. */
  PH_CHECK_SUCCESS_FCT(statusTmp, phCryptoSym_CalculateMac(
          pDataParams->pCryptoDataParamsMac,
          (PH_CRYPTOSYM_MAC_MODE_CMAC | PH_EXCHANGE_DEFAULT),
          aCmd,
          wCmdLength,
          aCMAC,
          &wCmdLength
      ));

  /* Perform MAC truncation */
  phalMfpEVx_Sw_Int_TruncateMac(aCMAC, aCMAC);

  /* Verify the received MAC */
  if (memcmp(aCMAC, &pRecv[1U + PHAL_MFPEVX_SIZE_ENCTMRI],
          PHAL_MFPEVX_TRUNCATED_MAC_SIZE) != 0x00) {
    return PH_ADD_COMPCODE_FIXED(PH_ERR_INTEGRITY_ERROR, PH_COMP_AL_MFPEVX);
  }

  /* Copy the response EncTMRI data */
  (void)memcpy(pEncTMRI, &pRecv[1], PHAL_MFPEVX_SIZE_ENCTMRI);

  /* Calculate TMI and update to TMIUtils
   * TMI = TMI|| CRI || BNr || TMRICur || EncTMRI
   */
  /* Form the command buffer to update TMI */
  wCmdLength = 0;
  (void)memset(aCmd, 0x00, (size_t)sizeof(aCmd));

  /* Write the command to command buffer */
  aCmd[wCmdLength++] = PHAL_MFPEVX_CMD_COMMIT_READER_ID;

  /* Write the LSB & MSB of Block no to command buffer */
  aCmd[wCmdLength++] = (uint8_t)(wBlockNr & 0xFFU);        /* LSB */
  aCmd[wCmdLength++] = (uint8_t)(wBlockNr >> 8U);          /* MSB */

  /* Copy the TMRI data to command buffer and update the command buffer length */
  (void)memcpy(&aCmd[wCmdLength], pTMRI, PHAL_MFPEVX_SIZE_TMRI);
  wCmdLength += PHAL_MFPEVX_SIZE_TMRI;

  PH_CHECK_SUCCESS_FCT(statusTmp, phTMIUtils_GetConfig((phTMIUtils_t *)pDataParams->pTMIDataParams,
          PH_TMIUTILS_TMI_STATUS,
          &wTMIStatus));

  /* Check TMI Collection Status */
  if (wTMIStatus == PH_ON) {
    PH_CHECK_SUCCESS_FCT(statusTmp, phTMIUtils_CollectTMI((phTMIUtils_t *)pDataParams->pTMIDataParams,
            PH_TMIUTILS_NO_PADDING,
            aCmd,
            wCmdLength,
            pEncTMRI,
            PHAL_MFPEVX_SIZE_ENCTMRI,
            PHAL_MFPEVX_DATA_BLOCK_SIZE
        ));
  }

  /* Load back up Iv */
  PH_CHECK_SUCCESS_FCT(statusTmp, phCryptoSym_LoadIv(
          pDataParams->pCryptoDataParamsMac,
          pDataParams->bIv,
          PH_CRYPTOSYM_AES128_KEY_SIZE));

  return PH_ERR_SUCCESS;
}
#endif /* NXPBUILD__PHAL_MFPEVX_NDA */

/***************************************************************************************************************************************/
/* Mifare Plus EVx Software command for utility operations.                                                                            */
/***************************************************************************************************************************************/
phStatus_t
phalMfpEVx_Sw_ResetSecMsgState(phalMfpEVx_Sw_DataParams_t *pDataParams)
{
  phStatus_t statusTmp;

  pDataParams->wRCtr                          = 0;
  pDataParams->wWCtr                          = 0;
  pDataParams->bNumUnprocessedReadMacBytes    = 0;
  pDataParams->bFirstRead                     = 1;
  pDataParams->bSMMode                        = (uint8_t)PHAL_MFPEVX_SECURE_MESSAGE_EV0;

  /* State machine should be handled in a way where L3 activation or L4 activation shouldnot be lost */
  if ((pDataParams->bAuthMode == PHAL_MFPEVX_SL3_MFP_AUTHENTICATED) ||
      (pDataParams->bAuthMode == PHAL_MFPEVX_SL1_MFP_AUTHENTICATED) ||
      (pDataParams->bAuthMode == PHAL_MFPEVX_NOT_AUTHENTICATED_L4)) {
    pDataParams->bAuthMode = PHAL_MFPEVX_NOT_AUTHENTICATED_L4;
  } else if ((pDataParams->bAuthMode == PHAL_MFPEVX_NOT_AUTHENTICATED_L3) ||
      (pDataParams->bAuthMode == PHAL_MFPEVX_SL1_MIFARE_AUTHENTICATED)) {
    pDataParams->bAuthMode =  PHAL_MFPEVX_NOT_AUTHENTICATED_L3;
  } else {
    pDataParams->bAuthMode = PHAL_MFPEVX_NOTAUTHENTICATED;
  }

  (void)memset(pDataParams->bIv, 0x00, (size_t)sizeof(pDataParams->bIv));
  (void)memset(pDataParams->bSesAuthENCKey, 0x00, (size_t)sizeof(pDataParams->bSesAuthENCKey));
  (void)memset(pDataParams->bSesAuthMACKey, 0x00, (size_t)sizeof(pDataParams->bSesAuthMACKey));

  (void)memset(pDataParams->bTi, 0x00, PHAL_MFPEVX_SIZE_TI);

  statusTmp = phTMIUtils_ActivateTMICollection((phTMIUtils_t *)pDataParams->pTMIDataParams,
          PH_TMIUTILS_RESET_TMI);

  /* Update the authentication state if VCA PC feature is required by the application. */
  if (pDataParams->pVCADataParams != NULL) {
    statusTmp = phalVca_SetSessionKeyUtility(pDataParams->pVCADataParams, pDataParams->bSesAuthMACKey,
            PHAL_MFPEVX_NOTAUTHENTICATED);
  }

  return PH_ADD_COMPCODE(statusTmp, PH_COMP_AL_MFPEVX);
}

phStatus_t
phalMfpEVx_Sw_SetConfig(phalMfpEVx_Sw_DataParams_t *pDataParams, uint16_t wOption,
    uint16_t wValue)
{
  switch (wOption) {
    case PHAL_MFPEVX_WRAPPED_MODE:
      pDataParams->bWrappedMode = (uint8_t)wValue;
      break;

    case PHAL_MFPEVX_EXTENDED_APDU:
      pDataParams->bExtendedLenApdu = (uint8_t)wValue;
      break;

    case PHAL_MFPEVX_AUTH_MODE:
      pDataParams->bAuthMode = (uint8_t) wValue;
      break;

    default:
      return PH_ADD_COMPCODE_FIXED(PH_ERR_UNSUPPORTED_PARAMETER, PH_COMP_AL_MFPEVX);
  }
  return PH_ERR_SUCCESS;
}

phStatus_t
phalMfpEVx_Sw_GetConfig(phalMfpEVx_Sw_DataParams_t *pDataParams, uint16_t wOption,
    uint16_t *pValue)
{
  switch (wOption) {
    case PHAL_MFPEVX_WRAPPED_MODE:
      *pValue = (uint16_t)pDataParams->bWrappedMode;
      break;

    case PHAL_MFPEVX_EXTENDED_APDU:
      *pValue = (uint16_t)pDataParams->bExtendedLenApdu;
      break;

    case PHAL_MFPEVX_AUTH_MODE:
      *pValue = (uint16_t)pDataParams->bAuthMode;
      break;

    default:
      return PH_ADD_COMPCODE_FIXED(PH_ERR_UNSUPPORTED_PARAMETER, PH_COMP_AL_MFPEVX);
  }
  return PH_ERR_SUCCESS;
}

phStatus_t
phalMfpEVx_Sw_SetVCAParams(phalMfpEVx_Sw_DataParams_t *pDataParams,
    void *pAlVCADataParams)
{
  PH_ASSERT_NULL(pDataParams);
  PH_ASSERT_NULL(pAlVCADataParams);

  pDataParams->pVCADataParams = pAlVCADataParams;

  return PH_ERR_SUCCESS;
}

#ifdef NXPBUILD__PHAL_MFPEVX_NDA
phStatus_t
phalMfpEVx_Sw_CalculateTMV(phalMfpEVx_Sw_DataParams_t *pDataParams, uint16_t wOption,
    uint16_t wKeyNoTMACKey, uint16_t wKeyVerTMACKey,
    uint8_t *pDivInput, uint8_t bDivInputLen, uint8_t *pTMC, uint8_t *pUid, uint8_t bUidLen,
    uint8_t  *pTMI, uint16_t wTMILen, uint8_t *pTMV)
{
  phStatus_t  PH_MEMLOC_REM statusTmp;
  uint8_t     PH_MEMLOC_REM bKey[PH_CRYPTOSYM_AES128_KEY_SIZE];
  uint8_t     PH_MEMLOC_REM bTSessionMACKey[PH_CRYPTOSYM_AES128_KEY_SIZE];
  uint8_t     PH_MEMLOC_REM bTmpIV[PH_CRYPTOSYM_AES_BLOCK_SIZE];
  uint8_t     PH_MEMLOC_REM bTMV[PH_CRYPTOSYM_AES_BLOCK_SIZE] = {0};
  uint8_t     PH_MEMLOC_REM bTMVLen = 0;
  uint8_t     PH_MEMLOC_REM bSVMacLen = 0;
  uint16_t    PH_MEMLOC_REM wKeyType;
  uint8_t     PH_MEMLOC_REM bSV[PH_CRYPTOSYM_AES128_KEY_SIZE * 2U];
  uint32_t    PH_MEMLOC_REM dwTMC = 0;
  uint32_t    PH_MEMLOC_REM dwTMCtemp = 0;

  /* Formation of TMC as double word value- TMC shall be communicated LSB first. */
  dwTMC = pTMC[0];
  dwTMCtemp = pTMC[1];
  dwTMC |= (dwTMCtemp << 8U);
  dwTMCtemp = pTMC[2];
  dwTMC |= (dwTMCtemp << 16U);
  dwTMCtemp = pTMC[3];
  dwTMC |= (dwTMCtemp << 24U);

  /* If TMC is 0xFFFFFFFF, then return error */
  if (dwTMC == 0xFFFFFFFFU) {
    return PH_ADD_COMPCODE_FIXED(PH_ERR_PARAMETER_OVERFLOW, PH_COMP_AL_MFPEVX);
  }

  if ((wOption != PHAL_MFPEVX_NO_DIVERSIFICATION) && (bDivInputLen > 31U)) {
    return PH_ADD_COMPCODE_FIXED(PH_ERR_INVALID_PARAMETER, PH_COMP_AL_MFPEVX);
  }

  /* Get Key out of the key store object */
  PH_CHECK_SUCCESS_FCT(statusTmp, phKeyStore_GetKey(
          pDataParams->pKeyStoreDataParams,
          wKeyNoTMACKey,
          wKeyVerTMACKey,
          PH_CRYPTOSYM_AES128_KEY_SIZE,
          bKey,
          &wKeyType
      ));

  /* Invalid key type at wKeyNoTMACKey and wKeyVerTMACKey */
  if (wKeyType != PH_CRYPTOSYM_KEY_TYPE_AES128) {
    return PH_ADD_COMPCODE_FIXED(PH_ERR_KEY, PH_COMP_AL_MFPEVX);
  }

  if ((wOption != PHAL_MFPEVX_NO_DIVERSIFICATION) && (bDivInputLen != 0x00U)) {
    /* Key is diversified and put back in bKey */
    PH_CHECK_SUCCESS_FCT(statusTmp, phCryptoSym_DiversifyDirectKey(
            pDataParams->pCryptoDiversifyDataParams,
            PH_CRYPTOSYM_DIV_MODE_MIFARE_PLUS,
            bKey,
            wKeyType,
            pDivInput,
            bDivInputLen,
            bKey
        ));
  }

  /* Increment dwTMC */
  dwTMC++;

  /* Update bSV buffer SV = 0x5A || 0x00 || 0x01 || 0x00 || 0x80 ||(TMC + 1) || UID [||0x00::0x00] */
  bSV[bSVMacLen++] = 0x5A;
  bSV[bSVMacLen++] = 0x00;
  bSV[bSVMacLen++] = 0x01;
  bSV[bSVMacLen++] = 0x00;
  bSV[bSVMacLen++] = 0x80;
  bSV[bSVMacLen++] = (uint8_t)(dwTMC & 0xFFU);
  bSV[bSVMacLen++] = (uint8_t)((dwTMC >> 8U) & 0xFFU);
  bSV[bSVMacLen++] = (uint8_t)((dwTMC >> 16U) & 0xFFU);
  bSV[bSVMacLen++] = (uint8_t)((dwTMC >> 24U) & 0xFFU);

  /* Copy UID into SV buffer. */
  (void)memcpy(&bSV[bSVMacLen], pUid, bUidLen);

  bSVMacLen += bUidLen;

  /* SV padded with the zero bytes up to a length of multiple of 16 bytes (if needed)*/
  if (bSVMacLen < (PH_CRYPTOSYM_AES128_KEY_SIZE * 2U)) {
    (void)memset(&bSV[bSVMacLen], 0x00,
        ((uint32_t)((PH_CRYPTOSYM_AES128_KEY_SIZE * 2U) - ((uint32_t)bSVMacLen))));
  }

  /* load key */
  PH_CHECK_SUCCESS_FCT(statusTmp, phCryptoSym_LoadKeyDirect(
          pDataParams->pCryptoDataParamsEnc,
          bKey,
          wKeyType));

  /* Create a Back up of the current IV */
  (void)memcpy(bTmpIV, pDataParams->bIv, PH_CRYPTOSYM_AES_BLOCK_SIZE);

  /* Load zero to IV */
  (void)memset(pDataParams->bIv, 0x00, PH_CRYPTOSYM_AES_BLOCK_SIZE);

  /* Load Iv */
  PH_CHECK_SUCCESS_FCT(statusTmp, phCryptoSym_LoadIv(
          pDataParams->pCryptoDataParamsEnc,
          pDataParams->bIv,
          PH_CRYPTOSYM_AES_BLOCK_SIZE
      ));

  /* Encrypt SV to obtain KSesTMMAC */
  PH_CHECK_SUCCESS_FCT(statusTmp, phCryptoSym_CalculateMac(
          pDataParams->pCryptoDataParamsEnc,
          (PH_CRYPTOSYM_MAC_MODE_CMAC | PH_EXCHANGE_DEFAULT),
          bSV,
          (uint16_t)((bUidLen == 0x0AU) ? (PH_CRYPTOSYM_AES_BLOCK_SIZE * 2U) : PH_CRYPTOSYM_AES_BLOCK_SIZE),
          bTSessionMACKey,
          &bSVMacLen
      ));

  /* load KSesTMMAC */
  PH_CHECK_SUCCESS_FCT(statusTmp, phCryptoSym_LoadKeyDirect(
          pDataParams->pCryptoDataParamsMac,
          bTSessionMACKey,
          PH_CRYPTOSYM_KEY_TYPE_AES128));

  /* Load Zero Iv */
  PH_CHECK_SUCCESS_FCT(statusTmp, phCryptoSym_LoadIv(
          pDataParams->pCryptoDataParamsMac,
          phalMfpEVx_Sw_FirstIv,
          PH_CRYPTOSYM_AES_BLOCK_SIZE
      ));

  /* Calculating the TMV data. */
  PH_CHECK_SUCCESS_FCT(statusTmp, phCryptoSym_CalculateMac(
          pDataParams->pCryptoDataParamsMac,
          (PH_CRYPTOSYM_MAC_MODE_CMAC | PH_EXCHANGE_DEFAULT),
          pTMI,
          wTMILen,
          bTMV,
          &bTMVLen
      ));

  /* Truncate the Calculated TMV. */
  phalMfpEVx_Sw_Int_TruncateMac(bTMV, bTMV);

  /* Copy the TMV. */
  (void)memcpy(pTMV, bTMV, PHAL_MFPEVX_TRUNCATED_MAC_SIZE);

  /* Restore back the IV */
  (void)memcpy(pDataParams->bIv, bTmpIV, PH_CRYPTOSYM_AES_BLOCK_SIZE);

  return PH_ERR_SUCCESS;
}

phStatus_t
phalMfpEVx_Sw_DecryptReaderID(phalMfpEVx_Sw_DataParams_t *pDataParams,
    uint16_t wOption, uint16_t wKeyNoTMACKey, uint16_t wKeyVerTMACKey,
    uint8_t *pDivInput, uint8_t bDivInputLen, uint8_t *pTMC, uint8_t *pUid, uint8_t bUidLen,
    uint8_t  *pEncTMRI, uint8_t *pTMRIPrev)
{
  phStatus_t  PH_MEMLOC_REM statusTmp;
  uint8_t     PH_MEMLOC_REM bKey[PH_CRYPTOSYM_AES128_KEY_SIZE];
  uint16_t    PH_MEMLOC_REM wKeyType;
  uint8_t     PH_MEMLOC_REM bSV[PH_CRYPTOSYM_AES128_KEY_SIZE * 2U];
  uint32_t    PH_MEMLOC_REM dwTMC = 0;
  uint32_t    PH_MEMLOC_REM dwTMCtemp = 0;
  uint8_t     PH_MEMLOC_REM bSVMacLen = 0;

  /* Formation of TMC as double word value- TMC shall be communicated LSB first. */
  dwTMC = pTMC[0];
  dwTMCtemp = pTMC[1];
  dwTMC |= (dwTMCtemp << 8U);
  dwTMCtemp = pTMC[2];
  dwTMC |= (dwTMCtemp << 16U);
  dwTMCtemp = pTMC[3];
  dwTMC |= (dwTMCtemp << 24U);

  /* If TMC is 0xFFFFFFFF, then return error */
  if (dwTMC == 0xFFFFFFFFU) {
    return PH_ADD_COMPCODE_FIXED(PH_ERR_PARAMETER_OVERFLOW, PH_COMP_AL_MFPEVX);
  }

  if ((wOption != PHAL_MFPEVX_NO_DIVERSIFICATION) && (bDivInputLen > 31U)) {
    return PH_ADD_COMPCODE_FIXED(PH_ERR_INVALID_PARAMETER, PH_COMP_AL_MFPEVX);
  }

  /* Get Key out of the key store object */
  PH_CHECK_SUCCESS_FCT(statusTmp, phKeyStore_GetKey(
          pDataParams->pKeyStoreDataParams,
          wKeyNoTMACKey,
          wKeyVerTMACKey,
          PH_CRYPTOSYM_AES128_KEY_SIZE,
          bKey,
          &wKeyType
      ));

  /* Invalid key type at wKeyNoTMACKey and wKeyVerTMACKey */
  if (wKeyType != PH_CRYPTOSYM_KEY_TYPE_AES128) {
    return PH_ADD_COMPCODE_FIXED(PH_ERR_KEY, PH_COMP_AL_MFPEVX);
  }

  if ((wOption != PHAL_MFPEVX_NO_DIVERSIFICATION) && (bDivInputLen != 0x00U)) {
    /* Key is diversified and put back in bKey */
    PH_CHECK_SUCCESS_FCT(statusTmp, phCryptoSym_DiversifyDirectKey(
            pDataParams->pCryptoDiversifyDataParams,
            PH_CRYPTOSYM_DIV_MODE_MIFARE_PLUS,
            bKey,
            wKeyType,
            pDivInput,
            bDivInputLen,
            bKey
        ));
  }

  /* Increment dwTMC */
  dwTMC++;

  /* Update bSV buffer SV = 0xA5 || 0x00 || 0x01 || 0x00 || 0x80 ||(TMC + 1) || UID [||0x00::0x00] */
  bSV[bSVMacLen++] = 0xA5;
  bSV[bSVMacLen++] = 0x00;
  bSV[bSVMacLen++] = 0x01;
  bSV[bSVMacLen++] = 0x00;
  bSV[bSVMacLen++] = 0x80;
  bSV[bSVMacLen++] = (uint8_t)(dwTMC & 0xFFU);
  bSV[bSVMacLen++] = (uint8_t)((dwTMC >> 8U) & 0xFFU);
  bSV[bSVMacLen++] = (uint8_t)((dwTMC >> 16U) & 0xFFU);
  bSV[bSVMacLen++] = (uint8_t)((dwTMC >> 24U) & 0xFFU);

  /* Copy UID into SV buffer. */
  (void)memcpy(&bSV[bSVMacLen], pUid, bUidLen);

  bSVMacLen += bUidLen;

  /* SV padded with the zero bytes up to a length of multiple of 16 bytes (if needed)*/
  if (bSVMacLen < (PH_CRYPTOSYM_AES128_KEY_SIZE * 2U)) {
    (void)memset(&bSV[bSVMacLen], 0x00,
        ((uint32_t)((PH_CRYPTOSYM_AES128_KEY_SIZE * 2U) - ((uint32_t)bSVMacLen))));
  }

  /* load key */
  PH_CHECK_SUCCESS_FCT(statusTmp, phCryptoSym_LoadKeyDirect(
          pDataParams->pCryptoDataParamsEnc,
          bKey,
          wKeyType));

  /* Load Zero Iv */
  PH_CHECK_SUCCESS_FCT(statusTmp, phCryptoSym_LoadIv(
          pDataParams->pCryptoDataParamsEnc,
          phalMfpEVx_Sw_FirstIv,
          PH_CRYPTOSYM_AES_BLOCK_SIZE
      ));

  /* Encrypt SV to obtain KSesTMENC */
  PH_CHECK_SUCCESS_FCT(statusTmp, phCryptoSym_CalculateMac(
          pDataParams->pCryptoDataParamsEnc,
          (PH_CRYPTOSYM_MAC_MODE_CMAC | PH_EXCHANGE_DEFAULT),
          bSV,
          (uint16_t)((bUidLen == 0x0AU) ? (PH_CRYPTOSYM_AES_BLOCK_SIZE * 2U) : PH_CRYPTOSYM_AES_BLOCK_SIZE),
          bKey,
          &bSVMacLen
      ));

  /* load KSesTMENC */
  PH_CHECK_SUCCESS_FCT(statusTmp, phCryptoSym_LoadKeyDirect(
          pDataParams->pCryptoDataParamsEnc,
          bKey,
          PH_CRYPTOSYM_KEY_TYPE_AES128));

  PH_CHECK_SUCCESS_FCT(statusTmp, phCryptoSym_Decrypt(
          pDataParams->pCryptoDataParamsEnc,
          PH_CRYPTOSYM_CIPHER_MODE_CBC | PH_EXCHANGE_DEFAULT,
          pEncTMRI,
          PHAL_MFPEVX_SIZE_ENCTMRI,
          pTMRIPrev
      ));

  return PH_ERR_SUCCESS;
}

phStatus_t
phalMfpEVx_Sw_Int_ComputeIv(phalMfpEVx_Sw_DataParams_t *pDataParams,
    uint8_t bIsResponse, uint8_t *pTi, uint16_t wRCtr,
    uint16_t wWCtr, uint8_t *pIv)
{
  phStatus_t statusTmp = 0;
  uint8_t PH_MEMLOC_REM bIvLen = 0;
  uint8_t PH_MEMLOC_REM aIV[20];

  uint8_t PH_MEMLOC_REM bRCtrMsb = (uint8_t)(wRCtr >> 8U);
  uint8_t PH_MEMLOC_REM bRCtrLsb = (uint8_t)(wRCtr & 0x00ffU);
  uint8_t PH_MEMLOC_REM bWCtrMsb = (uint8_t)(wWCtr >> 8U);
  uint8_t PH_MEMLOC_REM bWCtrLsb = (uint8_t)(wWCtr & 0x00ffU);

  /*  Parameter Validation. */
  if ((pTi == NULL) || (pIv == NULL)) {
    return PH_ADD_COMPCODE_FIXED(PH_ERR_INTERNAL_ERROR, PH_COMP_AL_MFPEVX);
  }

  /* IV calculation for EV0 Secure Messaging. */
  switch (pDataParams->bSMMode) {
    case PHAL_MFPEVX_SECURE_MESSAGE_EV0:
      /* IV for Command  = TI | LMSB( R_Ctr )  | LMSB( W_Ctr ) | LMSB( R_Ctr ) | LMSB( W_Ctr ) | LMSB( R_Ctr ) | LMSB( W_Ctr ) */
      /* IV for Response = LMSB( R_Ctr )  | LMSB( W_Ctr ) | LMSB( R_Ctr ) | LMSB( W_Ctr ) | LMSB( R_Ctr ) | LMSB( W_Ctr ) | TI */

      if (0U == (bIsResponse)) {
        aIV[bIvLen++] = pTi[0];
        aIV[bIvLen++] = pTi[1];
        aIV[bIvLen++] = pTi[2];
        aIV[bIvLen++] = pTi[3];
      }

      aIV[bIvLen++] = bRCtrLsb;
      aIV[bIvLen++] = bRCtrMsb;
      aIV[bIvLen++] = bWCtrLsb;
      aIV[bIvLen++] = bWCtrMsb;

      aIV[bIvLen++] = bRCtrLsb;
      aIV[bIvLen++] = bRCtrMsb;
      aIV[bIvLen++] = bWCtrLsb;
      aIV[bIvLen++] = bWCtrMsb;

      aIV[bIvLen++] = bRCtrLsb;
      aIV[bIvLen++] = bRCtrMsb;
      aIV[bIvLen++] = bWCtrLsb;
      aIV[bIvLen++] = bWCtrMsb;

      if (0U != (bIsResponse)) {
        aIV[bIvLen++] = pTi[0];
        aIV[bIvLen++] = pTi[1];
        aIV[bIvLen++] = pTi[2];
        aIV[bIvLen++] = pTi[3];
      }

      (void)memcpy(pIv, aIV, PHAL_MFPEVX_SIZE_IV);
      break;

    case PHAL_MFPEVX_SECURE_MESSAGE_EV1:
      /* IV for Command  = E ( Ke,  0xA5 || 0x5A || TI || LMSB ( R_Ctr ) || LMSB ( W_Ctr ) || 0x000000000000 )
       * IV for Response = E ( Ke,  0x5A || 0xA5 || TI || LMSB ( R_Ctr ) || LMSB ( W_Ctr ) || 0x000000000000 )
       * Where Ke, Session Encryption Key.
       */

      /* Clear the IV buffer. */
      (void)memset(aIV, 0x00, PHAL_MFPEVX_SIZE_IV);

      if (0U != (bIsResponse)) {
        aIV[bIvLen++] = 0x5A;
        aIV[bIvLen++] = 0xA5;
      } else {
        aIV[bIvLen++] = 0xA5;
        aIV[bIvLen++] = 0x5A;
      }

      aIV[bIvLen++] = pTi[0];
      aIV[bIvLen++] = pTi[1];
      aIV[bIvLen++] = pTi[2];
      aIV[bIvLen++] = pTi[3];

      aIV[bIvLen++] = bRCtrLsb;
      aIV[bIvLen++] = bRCtrMsb;
      aIV[bIvLen++] = bWCtrLsb;
      aIV[bIvLen++] = bWCtrMsb;

      /* Load Session Encryption key. */
      PH_CHECK_SUCCESS_FCT(statusTmp, phCryptoSym_LoadKeyDirect(
              pDataParams->pCryptoDataParamsEnc,
              pDataParams->bSesAuthENCKey,
              PH_CRYPTOSYM_KEY_TYPE_AES128));

      /* Generate the encrypted IV. */
      PH_CHECK_SUCCESS_FCT(statusTmp, phCryptoSym_Encrypt(
              pDataParams->pCryptoDataParamsEnc,
              PH_CRYPTOSYM_CIPHER_MODE_ECB,
              aIV,
              PHAL_MFPEVX_SIZE_IV,
              pIv
          ));
      break;

    default:
      return PH_ADD_COMPCODE_FIXED(PH_ERR_INTERNAL_ERROR, PH_COMP_AL_MFPEVX);
  }

  return PH_ERR_SUCCESS;
}
#endif /* NXPBUILD__PHAL_MFPEVX_NDA */

#if defined(NXPBUILD__PHAL_MFPEVX_NDA)
void
phalMfpEVx_Sw_Int_TruncateMac(uint8_t *pMac, uint8_t *pTruncatedMac)
{
#if PHAL_MFPEVX_TAPEOUT_VERSION >= 20

  uint8_t PH_MEMLOC_REM bIndex;

  /* truncated MAC = [1, 3, 5, 7, 9, 11, 13, 15] of the input Mac */
  for (bIndex = 0; bIndex < PHAL_MFPEVX_TRUNCATED_MAC_SIZE; ++bIndex) {
    pTruncatedMac[bIndex] = pMac[1U + (bIndex << 1U)];
  }

#else

  /* truncated MAC = 8 MSB of the input Mac */
  (void)memcpy(pTruncatedMac, pMac, PHAL_MFPEVX_TRUNCATED_MAC_SIZE);

#endif
}
#endif

#endif /* NXPBUILD__PHAL_MFPEVX_SW */
