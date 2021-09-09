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
#include <nxp_nfc/ph_RefDefs.h>
#include <nxp_nfc/ph_TypeDefs.h>
#include <string.h>
#include <nxp_nfc/phTools.h>
#include <nxp_nfc/phKeyStore.h>

#ifdef NXPBUILD__PH_CRYPTOSYM
#include <nxp_nfc/phCryptoSym.h>
#endif /* NXPBUILD__PH_CRYPTOSYM */

#ifdef NXPBUILD__PH_CRYPTORNG
#include <nxp_nfc/phCryptoRng.h>
#endif /* NXPBUILD__PH_CRYPTORNG */

#include <nxp_nfc/phTMIUtils.h>
#include <nxp_nfc/phalVca.h>

#ifdef NXPBUILD__PHAL_MFDFEVX_SW

#include "../phalMfdfEVx_Int.h"
#include "phalMfdfEVx_Sw.h"
#include "phalMfdfEVx_Sw_Int.h"

/* APP level keys are invalid between 0x0D to 0x21. */
#define IS_INVALID_APP_KEY(keyNo) ((((keyNo) & 0x7fU) > 0x0DU)     && (((keyNo) & 0x7fU) < 0x21U))

/* VC keys are invalid after 0x23. */
#define IS_INVALID_VC_KEY(keyNo)   (((keyNo) & 0x7fU) > 0x23U)

#ifdef NXPBUILD__PHAL_MFDFEVX_NDA
static const uint8_t PH_MEMLOC_CONST_ROM phalMfdfEVx_Sw_FirstIv[PH_CRYPTOSYM_AES_BLOCK_SIZE] = {0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00};
#endif /* NXPBUILD__PHAL_MFDFEVX_NDA */

phStatus_t
phalMfdfEVx_Sw_Init(phalMfdfEVx_Sw_DataParams_t *pDataParams,
    uint16_t wSizeOfDataParams, void *pPalMifareDataParams,
    void *pKeyStoreDataParams, void *pCryptoDataParamsEnc, void *pCryptoDataParamsMac,
    void *pCryptoRngDataParams,
    void *pTMIDataParams, void *pVCADataParams, void *pHalDataParams)
{
  /* data param check */
  if (sizeof(phalMfdfEVx_Sw_DataParams_t) != wSizeOfDataParams) {
    return PH_ADD_COMPCODE_FIXED(PH_ERR_INVALID_DATA_PARAMS, PH_COMP_AL_MFDFEVX);
  }
  PH_ASSERT_NULL_DATA_PARAM(pDataParams, PH_COMP_AL_MFDFEVX);
  PH_ASSERT_NULL_PARAM(pPalMifareDataParams, PH_COMP_AL_MFDFEVX);
#ifdef NXPBUILD__PHAL_MFDFEVX_NDA
  PH_ASSERT_NULL_PARAM(pKeyStoreDataParams, PH_COMP_AL_MFDFEVX);
  PH_ASSERT_NULL_PARAM(pCryptoDataParamsEnc, PH_COMP_AL_MFDFEVX);
  PH_ASSERT_NULL_PARAM(pCryptoRngDataParams, PH_COMP_AL_MFDFEVX);
#endif /* NXPBUILD__PHAL_MFDFEVX_NDA */
  PH_ASSERT_NULL_PARAM(pTMIDataParams, PH_COMP_AL_MFDFEVX);
  PH_ASSERT_NULL_PARAM(pVCADataParams, PH_COMP_AL_MFDFEVX);

  /* init private data */
  pDataParams->wId = PH_COMP_AL_MFDFEVX | PHAL_MFDFEVX_SW_ID;
  pDataParams->pPalMifareDataParams = pPalMifareDataParams;
  pDataParams->pKeyStoreDataParams = pKeyStoreDataParams;
  pDataParams->pCryptoDataParamsEnc = pCryptoDataParamsEnc;
  pDataParams->pCryptoDataParamsMac = pCryptoDataParamsMac;
  pDataParams->pCryptoRngDataParams = pCryptoRngDataParams;
  pDataParams->pTMIDataParams = pTMIDataParams;
  pDataParams->pVCADataParams = pVCADataParams;
  pDataParams->pHalDataParams = pHalDataParams;
  /* 2 Byte CRC initial value in Authenticate mode. */
  pDataParams->wCrc = PH_TOOLS_CRC16_PRESET_ISO14443A;

  /* 4 Byte CRC initial value in 0x1A, 0xAA mode. */
  pDataParams->dwCrc = PH_TOOLS_CRC32_PRESET_DF8;

  (void)memset(pDataParams->bSesAuthENCKey, 0x00, 24);
  pDataParams->bKeyNo = 0xFF; /* Set to invalid */
  (void)memset(pDataParams->bIv, 0x00, 16);
  (void)memset(pDataParams->pAid, 0x00, 3);
  pDataParams->bAuthMode = PHAL_MFDFEVX_NOT_AUTHENTICATED; /* Set to invalid */
  pDataParams->bWrappedMode = 0x00; /* Set to false */
  pDataParams->bCryptoMethod = 0xFF; /* No crypto just after init */
  pDataParams->wAdditionalInfo = 0x0000;
  pDataParams->bShortLenApdu =
      0x00; /* By default, extended length APDU format is used for BIG ISO Read */
  pDataParams->dwPayLoadLen = 0;
  pDataParams->wCmdCtr = 0;
  (void)memset(pDataParams->bTi, 0x00, PHAL_MFDFEVX_SIZE_TI);
  (void)memset(pDataParams->bSesAuthMACKey, 0x00, 16);
  (void)memset(pDataParams->pUnprocByteBuff, 0x00, PHAL_MFDFEVX_SIZE_MAC);
  pDataParams->bNoUnprocBytes = 0;
  (void)memset(pDataParams->bLastBlockBuffer, 0x00, 16);
  pDataParams->bLastBlockIndex = 0;
  pDataParams->bCmdCode = PHAL_MFDFEVX_CMD_INVALID;

  return PH_ERR_SUCCESS;
}

#ifdef NXPBUILD__PHAL_MFDFEVX_NDA
/* MIFARE DESFire EVx contactless IC secure messaging related commands. ------------------------------------------------------------------------------- */
phStatus_t
phalMfdfEVx_Sw_Authenticate(phalMfdfEVx_Sw_DataParams_t *pDataParams, uint16_t wOption,
    uint16_t wKeyNo,
    uint16_t wKeyVer, uint8_t bKeyNoCard, uint8_t *pDivInput, uint8_t bDivLen)
{
  uint8_t     PH_MEMLOC_REM bRndA[PH_CRYPTOSYM_DES_BLOCK_SIZE];
  uint8_t     PH_MEMLOC_REM bRndB[PH_CRYPTOSYM_DES_BLOCK_SIZE + 1U];
  phStatus_t  PH_MEMLOC_REM statusTmp;
  uint8_t     PH_MEMLOC_REM bKey[PH_CRYPTOSYM_3K3DES_KEY_SIZE];
  uint16_t    PH_MEMLOC_REM wKeyType;
  uint16_t    PH_MEMLOC_REM status;
  uint8_t     PH_MEMLOC_REM bWorkBuffer[16];
  uint16_t    PH_MEMLOC_REM wRxlen = 0;
  uint8_t     PH_MEMLOC_REM bCmdBuff[32];
  uint8_t     PH_MEMLOC_REM bRndLen;
  uint8_t     PH_MEMLOC_REM bSessKeySize;
  uint8_t     PH_MEMLOC_REM bIvLen;
  uint16_t    PH_MEMLOC_REM wCmdLen = 0;
  uint8_t    *PH_MEMLOC_REM pRecv = NULL;
#ifdef RDR_LIB_PARAM_CHECK
  uint8_t     PH_MEMLOC_REM bAppId[3] = { 0x00, 0x00, 0x00 };
#endif

#ifdef RDR_LIB_PARAM_CHECK
  if ((memcmp(pDataParams->pAid, bAppId, 3)) && ((bKeyNoCard & 0x0FU) > 0x0DU)) {
    return PH_ADD_COMPCODE_FIXED(PH_ERR_INVALID_PARAMETER, PH_COMP_AL_MFDFEVX);
  }
  if ((wOption != PHAL_MFDFEVX_NO_DIVERSIFICATION) &&
      (wOption != (PH_CRYPTOSYM_DIV_MODE_DESFIRE | PH_CRYPTOSYM_DIV_OPTION_2K3DES_HALF)) &&
      (wOption != (PH_CRYPTOSYM_DIV_MODE_DESFIRE | PH_CRYPTOSYM_DIV_OPTION_2K3DES_FULL)) &&
      (wOption != PH_CRYPTOSYM_DIV_MODE_MIFARE_PLUS)) {
    return PH_ADD_COMPCODE_FIXED(PH_ERR_INVALID_PARAMETER, PH_COMP_AL_MFDFEVX);
  }
  if ((wOption != PHAL_MFDFEVX_NO_DIVERSIFICATION) && (bDivLen > 31U)) {
    return PH_ADD_COMPCODE_FIXED(PH_ERR_INVALID_PARAMETER, PH_COMP_AL_MFDFEVX);
  }
#endif

  /* Set the dataparams with command code. */
  pDataParams->bCmdCode = PHAL_MFDFEVX_CMD_AUTHENTICATE;

  /* Get Key out of the key store object */
  PH_CHECK_SUCCESS_FCT(statusTmp, phKeyStore_GetKey(
          pDataParams->pKeyStoreDataParams,
          wKeyNo,
          wKeyVer,
          (uint8_t)(sizeof(bKey)),
          bKey,
          &wKeyType));

  switch (wKeyType) {
    case PH_KEYSTORE_KEY_TYPE_DES:
      bRndLen = PH_CRYPTOSYM_DES_BLOCK_SIZE;
      bSessKeySize = 2u * PH_CRYPTOSYM_DES_BLOCK_SIZE;
      bIvLen = PH_CRYPTOSYM_DES_BLOCK_SIZE;
      (void)memcpy(&bKey[8], bKey, 8);
      wKeyType = PH_KEYSTORE_KEY_TYPE_2K3DES;
      break;

    case PH_KEYSTORE_KEY_TYPE_2K3DES:
      bRndLen = PH_CRYPTOSYM_DES_BLOCK_SIZE;
      bSessKeySize = 2u * PH_CRYPTOSYM_DES_BLOCK_SIZE;
      bIvLen = PH_CRYPTOSYM_DES_BLOCK_SIZE;
      break;

    default:
      /* Wrong key type specified. Auth. will not work */
      return PH_ADD_COMPCODE_FIXED(PH_ERR_KEY, PH_COMP_AL_MFDFEVX);
  }

  if ((wOption != PHAL_MFDFEVX_NO_DIVERSIFICATION) && (bDivLen != 0x00U)) {
    /* Key is diversified and put back in bKey */
    PH_CHECK_SUCCESS_FCT(statusTmp, phCryptoSym_DiversifyDirectKey(
            pDataParams->pCryptoDataParamsEnc,
            wOption,
            bKey,
            wKeyType,
            pDivInput,
            bDivLen,
            bKey
        ));
  }

  /* load key */
  PH_CHECK_SUCCESS_FCT(statusTmp, phCryptoSym_LoadKeyDirect(
          pDataParams->pCryptoDataParamsEnc,
          bKey,
          wKeyType
      ));

  /* Send the cmd and receive the encrypted RndB */
  bCmdBuff[wCmdLen++] = PHAL_MFDFEVX_CMD_AUTHENTICATE;
  bCmdBuff[wCmdLen++] = bKeyNoCard; /* key number card */

  status = phalMfdfEVx_ExchangeCmd(
          pDataParams,
          pDataParams->pPalMifareDataParams,
          pDataParams->bWrappedMode,
          bCmdBuff,
          wCmdLen,
          &pRecv,
          &wRxlen
      );
  if ((status & PH_ERR_MASK) != PH_ERR_SUCCESS_CHAINING) {
    if ((status & PH_ERR_MASK) == PH_ERR_SUCCESS) {
      return PH_ADD_COMPCODE_FIXED(PH_ERR_PROTOCOL_ERROR, PH_COMP_AL_MFDFEVX);
    } else {
      /* If First pass authentication fails, reset the authentication status */
      (void)phalMfdfEVx_Sw_ResetAuthentication(pDataParams);
      return status;
    }
  }
  if (wRxlen != bRndLen) {
    return PH_ADD_COMPCODE_FIXED(PH_ERR_PROTOCOL_ERROR, PH_COMP_AL_MFDFEVX);
  }
  /* Store the unencrypted RndB */
  (void)memcpy(bRndB, pRecv, bRndLen);

  /* Reset IV before start of a crypto operation */
  (void)memset(pDataParams->bIv, 0x00, bIvLen);

  /* Load Iv. Always zero for native mode */
  PH_CHECK_SUCCESS_FCT(statusTmp, phCryptoSym_LoadIv(
          pDataParams->pCryptoDataParamsEnc,
          pDataParams->bIv,
          bIvLen));

  /* Decrypt the RndB received from PICC */
  PH_CHECK_SUCCESS_FCT(statusTmp, phCryptoSym_Decrypt(
          pDataParams->pCryptoDataParamsEnc,
          PH_CRYPTOSYM_CIPHER_MODE_CBC,
          bRndB,
          bRndLen,
          bRndB));

  /* Generate RndA */
  PH_CHECK_SUCCESS_FCT(statusTmp, phCryptoRng_Seed(pDataParams->pCryptoRngDataParams, bRndB,
          bRndLen));

  PH_CHECK_SUCCESS_FCT(statusTmp, phCryptoRng_Rnd(pDataParams->pCryptoRngDataParams, bRndLen,
          bRndA));

  /* Concat RndA and RndB' */
  bCmdBuff[0] = PHAL_MFDFEVX_RESP_ADDITIONAL_FRAME;
  (void)memcpy(&bCmdBuff[1], bRndA, bRndLen);
  (void)memcpy(&bCmdBuff[9], &bRndB[1], bRndLen - 1);
  bCmdBuff[16] = bRndB[0]; /* RndB left shifted by 8 bits */

  /* Load Iv. All zeroes */
  PH_CHECK_SUCCESS_FCT(statusTmp, phCryptoSym_LoadIv(
          pDataParams->pCryptoDataParamsEnc,
          pDataParams->bIv,
          bIvLen));

  /* Encrypt */
  PH_CHECK_SUCCESS_FCT(statusTmp, phCryptoSym_Encrypt(
          pDataParams->pCryptoDataParamsEnc,
          PH_CRYPTOSYM_CIPHER_MODE_CBC_DF4 | PH_EXCHANGE_BUFFER_CONT,
          &bCmdBuff[1],
          2U * bRndLen,
          &bCmdBuff[1]
      ));

  /* reset bIv to zero */
  (void)memset(pDataParams->bIv, 0x00, bIvLen);

  /* Copy the encrypted RndA + RndB'
  (void)memcpy(&bCmdBuff[1], bWorkBuffer, 2 * bRndLen); */

  wCmdLen = (2u * bRndLen) + 1U;

  /* Get the encrypted RndA' into bWorkBuffer */
  PH_CHECK_SUCCESS_FCT(status, phalMfdfEVx_ExchangeCmd(
          pDataParams,
          pDataParams->pPalMifareDataParams,
          pDataParams->bWrappedMode,
          bCmdBuff,
          wCmdLen,
          &pRecv,
          &wRxlen
      ));

  if (wRxlen != bRndLen) {
    return PH_ADD_COMPCODE_FIXED(PH_ERR_PROTOCOL_ERROR, PH_COMP_AL_MFDFEVX);
  }
  (void)memcpy(bWorkBuffer, pRecv, wRxlen);

  /* bWorkBuffer now has the encrypted RndA */
  /* Decrypt the received RndA' */
  PH_CHECK_SUCCESS_FCT(statusTmp, phCryptoSym_LoadIv(
          pDataParams->pCryptoDataParamsEnc,
          pDataParams->bIv,
          bIvLen));

  /* Decrypt RndA'*/
  PH_CHECK_SUCCESS_FCT(statusTmp, phCryptoSym_Decrypt(
          pDataParams->pCryptoDataParamsEnc,
          PH_CRYPTOSYM_CIPHER_MODE_CBC,
          bWorkBuffer,
          bRndLen,
          &bCmdBuff[1]
      ));

  bCmdBuff[0] = bCmdBuff[8]; /* right shift to get back RndA */

  /* Compare RndA and buff */
  if (memcmp(bCmdBuff, bRndA, bRndLen) != 0) {
    /* Authentication failed */
    return PH_ADD_COMPCODE_FIXED(PH_ERR_AUTH_ERROR, PH_COMP_AL_MFDFEVX);
  }

  /* Generate the session key */
  /* If key used for authentication is 2K3DES, Session key would be 16 bytes. */
  (void)memcpy(pDataParams->bSesAuthENCKey, bRndA, 4);
  (void)memcpy(&pDataParams->bSesAuthENCKey[4], bRndB, 4);
  pDataParams->bCryptoMethod = PH_CRYPTOSYM_KEY_TYPE_DES;

  if (memcmp(bKey, &bKey[PH_CRYPTOSYM_DES_KEY_SIZE], PH_CRYPTOSYM_DES_KEY_SIZE) == 0) {
    (void)memcpy(&pDataParams->bSesAuthENCKey[8], bRndA, 4);
    (void)memcpy(&pDataParams->bSesAuthENCKey[12], bRndB, 4);
  } else {
    (void)memcpy(&pDataParams->bSesAuthENCKey[8], &bRndA[4], 4);
    (void)memcpy(&pDataParams->bSesAuthENCKey[12], &bRndB[4], 4);
  }
  pDataParams->bCryptoMethod = PH_CRYPTOSYM_KEY_TYPE_2K3DES;

  pDataParams->bAuthMode = PHAL_MFDFEVX_AUTHENTICATE;
  pDataParams->bKeyNo = bKeyNoCard;

  /* Update the authentication state if VCA PC feature is required by the application. */
  if (pDataParams->pVCADataParams != NULL) {
    /* Set the Session key for Virtual Card which is valid for this authentication */
    PH_CHECK_SUCCESS_FCT(statusTmp, phalVca_SetSessionKeyUtility(
            (phalVca_Sw_DataParams_t *)pDataParams->pVCADataParams,
            pDataParams->bSesAuthENCKey,
            pDataParams->bAuthMode
        ));
  }

  /* satisfy compiler */
  PH_UNUSED_VARIABLE(bSessKeySize);

  return phCryptoSym_LoadKeyDirect(
          pDataParams->pCryptoDataParamsEnc,
          pDataParams->bSesAuthENCKey,
          pDataParams->bCryptoMethod
      );
}

phStatus_t
phalMfdfEVx_Sw_AuthenticateISO(phalMfdfEVx_Sw_DataParams_t *pDataParams,
    uint16_t wOption, uint16_t wKeyNo,
    uint16_t wKeyVer, uint8_t bKeyNoCard, uint8_t *pDivInput, uint8_t bDivLen)
{
  /**
  * The key type can be DES, 3DES, 3K3DES.
  * Random numbers can be 8 or 16 bytes long
  * Init vector can be 8 or 16 bytes long
  * Session key max size is 24 bytes if 3k3DES keys are used.
  *
  */

  uint8_t     PH_MEMLOC_REM bRndA[PH_CRYPTOSYM_AES_BLOCK_SIZE];
  uint8_t     PH_MEMLOC_REM bRndB[PH_CRYPTOSYM_AES_BLOCK_SIZE + 1U];
  phStatus_t  PH_MEMLOC_REM statusTmp;
  uint8_t     PH_MEMLOC_REM bKey[PH_CRYPTOSYM_3K3DES_KEY_SIZE];
  uint16_t    PH_MEMLOC_REM wKeyType;
  uint16_t    PH_MEMLOC_REM wRxlen = 0;
  uint8_t     PH_MEMLOC_REM bCmdBuff[33];
  uint8_t     PH_MEMLOC_REM bWorkBuffer[PH_CRYPTOSYM_AES_BLOCK_SIZE + 1U];
  uint16_t    PH_MEMLOC_REM status;
  uint16_t    PH_MEMLOC_REM wCmdLen = 0;
  uint8_t     PH_MEMLOC_REM bRndLen;
  uint8_t     PH_MEMLOC_REM bSessKeySize;
  uint8_t     PH_MEMLOC_REM bIvSize;
  uint8_t     PH_MEMLOC_REM bIv_bak[PH_CRYPTOSYM_DES_BLOCK_SIZE];
  uint8_t    *PH_MEMLOC_REM pRecv = NULL;
#ifdef RDR_LIB_PARAM_CHECK
  uint8_t     PH_MEMLOC_REM bAppId[3] = { 0x00, 0x00, 0x00 };
#endif

  /* Set the current authentication status to NOT AUTHENTICATED i.e., invalid key number */
  pDataParams->bKeyNo = 0xFF;

#ifdef RDR_LIB_PARAM_CHECK
  if ((memcmp(pDataParams->pAid, bAppId, 3)) && ((bKeyNoCard & 0x0FU) > 0x0DU)) {
    return PH_ADD_COMPCODE_FIXED(PH_ERR_INVALID_PARAMETER, PH_COMP_AL_MFDFEVX);
  }
  if ((wOption != PHAL_MFDFEVX_NO_DIVERSIFICATION) &&
      (wOption != (PH_CRYPTOSYM_DIV_MODE_DESFIRE | PH_CRYPTOSYM_DIV_OPTION_2K3DES_HALF)) &&
      (wOption != (PH_CRYPTOSYM_DIV_MODE_DESFIRE | PH_CRYPTOSYM_DIV_OPTION_2K3DES_FULL)) &&
      (wOption != PH_CRYPTOSYM_DIV_MODE_MIFARE_PLUS)) {
    return PH_ADD_COMPCODE_FIXED(PH_ERR_INVALID_PARAMETER, PH_COMP_AL_MFDFEVX);
  }
  if ((wOption != PHAL_MFDFEVX_NO_DIVERSIFICATION) && (bDivLen > 31U)) {
    return PH_ADD_COMPCODE_FIXED(PH_ERR_INVALID_PARAMETER, PH_COMP_AL_MFDFEVX);
  }
#endif

  /* Set the dataparams with command code. */
  pDataParams->bCmdCode = PHAL_MFDFEVX_CMD_AUTHENTICATE_ISO;

  /* Get Key out of the key store object */
  PH_CHECK_SUCCESS_FCT(statusTmp, phKeyStore_GetKey(
          pDataParams->pKeyStoreDataParams,
          wKeyNo,
          wKeyVer,
          sizeof(bKey),
          bKey,
          &wKeyType
      ));

  switch (wKeyType) {
    case PH_KEYSTORE_KEY_TYPE_DES:
      bRndLen = PH_CRYPTOSYM_DES_BLOCK_SIZE;
      bSessKeySize = 2u * PH_CRYPTOSYM_DES_BLOCK_SIZE;
      bIvSize = PH_CRYPTOSYM_DES_BLOCK_SIZE;
      (void)memcpy(&bKey[8], bKey, 8);
      wKeyType = PH_KEYSTORE_KEY_TYPE_2K3DES;
      break;

    case PH_KEYSTORE_KEY_TYPE_2K3DES:
      bRndLen = PH_CRYPTOSYM_DES_BLOCK_SIZE;
      bSessKeySize = 2u * PH_CRYPTOSYM_DES_BLOCK_SIZE;
      bIvSize = PH_CRYPTOSYM_DES_BLOCK_SIZE;
      break;

    case PH_KEYSTORE_KEY_TYPE_3K3DES:
      bRndLen = 2u * PH_CRYPTOSYM_DES_BLOCK_SIZE;
      bSessKeySize = PH_CRYPTOSYM_3K3DES_KEY_SIZE;
      bIvSize = PH_CRYPTOSYM_DES_BLOCK_SIZE;
      break;

    default:
      /* Wrong key type specified. Auth. will not work */
      return PH_ADD_COMPCODE_FIXED(PH_ERR_KEY, PH_COMP_AL_MFDFEVX);
  }

  if ((wOption != PHAL_MFDFEVX_NO_DIVERSIFICATION) && (bDivLen != 0x00U)) {
    /* Key is diversified and put back in bKey */
    PH_CHECK_SUCCESS_FCT(statusTmp, phCryptoSym_DiversifyDirectKey(
            pDataParams->pCryptoDataParamsEnc,
            wOption,
            bKey,
            wKeyType,
            pDivInput,
            bDivLen,
            bKey
        ));
  }

  /* load key */
  PH_CHECK_SUCCESS_FCT(statusTmp, phCryptoSym_LoadKeyDirect(
          pDataParams->pCryptoDataParamsEnc,
          bKey,
          wKeyType));

  /* Initialize the init vector to all zeors */
  (void)memset(bIv_bak, 0x00, bIvSize);

  /* Send the cmd and receive the encrypted RndB */
  bCmdBuff[wCmdLen++] = PHAL_MFDFEVX_CMD_AUTHENTICATE_ISO;
  bCmdBuff[wCmdLen++] = bKeyNoCard; /* key number card */

  status = phalMfdfEVx_ExchangeCmd(
          pDataParams,
          pDataParams->pPalMifareDataParams,
          pDataParams->bWrappedMode,
          bCmdBuff,
          wCmdLen,
          &pRecv,
          &wRxlen
      );
  if ((status & PH_ERR_MASK) != PH_ERR_SUCCESS_CHAINING) {
    if ((status & PH_ERR_MASK) == PH_ERR_SUCCESS) {
      return PH_ADD_COMPCODE_FIXED(PH_ERR_PROTOCOL_ERROR, PH_COMP_AL_MFDFEVX);
    } else {
      /* If First pass authentication fails, reset the authentication status */
      (void)phalMfdfEVx_Sw_ResetAuthentication(pDataParams);
      return status;
    }
  }
  if (wRxlen != bRndLen) {
    return PH_ADD_COMPCODE_FIXED(PH_ERR_PROTOCOL_ERROR, PH_COMP_AL_MFDFEVX);
  }

  /* Store the unencrypted RndB */
  (void)memcpy(bRndB, pRecv, bRndLen);

  /* Store the IV to be used for encryption later */
  (void)memcpy(bIv_bak, &bRndB[bRndLen - bIvSize], bIvSize);

  /* Reset IV for the first crypto operation */
  (void)memset(pDataParams->bIv, 0x00, bIvSize);

  /* Load Iv.*/
  PH_CHECK_SUCCESS_FCT(statusTmp, phCryptoSym_LoadIv(
          pDataParams->pCryptoDataParamsEnc,
          pDataParams->bIv,
          bIvSize));

  /* Decrypt the RndB received from PICC */
  PH_CHECK_SUCCESS_FCT(statusTmp, phCryptoSym_Decrypt(
          pDataParams->pCryptoDataParamsEnc,
          PH_CRYPTOSYM_CIPHER_MODE_CBC | PH_EXCHANGE_BUFFER_CONT,
          bRndB,
          bRndLen,
          bRndB
      ));

  /* Generate RndA */
  PH_CHECK_SUCCESS_FCT(statusTmp, phCryptoRng_Seed(pDataParams->pCryptoRngDataParams, bRndB,
          bRndLen));

  PH_CHECK_SUCCESS_FCT(statusTmp, phCryptoRng_Rnd(pDataParams->pCryptoRngDataParams, bRndLen,
          bRndA));

  /* Concat RndA and RndB' */
  bCmdBuff[0] = PHAL_MFDFEVX_RESP_ADDITIONAL_FRAME;
  (void)memcpy(&bCmdBuff[1], bRndA, bRndLen);
  (void)memcpy(&bCmdBuff[bRndLen + 1U], &bRndB[1], bRndLen - 1U);
  bCmdBuff[2U * bRndLen] = bRndB[0]; /* RndB left shifted by 8 bits */

  (void)memcpy(pDataParams->bIv, bIv_bak, bIvSize);

  /* Load Iv */
  PH_CHECK_SUCCESS_FCT(statusTmp, phCryptoSym_LoadIv(
          pDataParams->pCryptoDataParamsEnc,
          pDataParams->bIv,
          bIvSize));

  /* Encrypt RndA + RndB' */
  PH_CHECK_SUCCESS_FCT(statusTmp,
      phCryptoSym_Encrypt(pDataParams->pCryptoDataParamsEnc,
          PH_CRYPTOSYM_CIPHER_MODE_CBC | PH_EXCHANGE_BUFFER_CONT,
          &bCmdBuff[1],
          2U * bRndLen,
          &bCmdBuff[1]
      ));

  /* Update command length */
  wCmdLen = (2u * bRndLen) + 1U;

  /* Update Iv */
  (void)memcpy(pDataParams->bIv, &bCmdBuff[wCmdLen - bIvSize], bIvSize);

  /* Get the encrypted RndA' into bWorkBuffer */
  PH_CHECK_SUCCESS_FCT(status, phalMfdfEVx_ExchangeCmd(
          pDataParams,
          pDataParams->pPalMifareDataParams,
          pDataParams->bWrappedMode,
          bCmdBuff,
          wCmdLen,
          &pRecv,
          &wRxlen
      ));
  if (wRxlen != bRndLen) {
    return PH_ADD_COMPCODE_FIXED(PH_ERR_PROTOCOL_ERROR, PH_COMP_AL_MFDFEVX);
  }
  (void)memcpy(bWorkBuffer, pRecv, wRxlen);

  /* bWorkBuffer now has the encrypted RndA' */
  /* Decrypt the received RndA' */
  PH_CHECK_SUCCESS_FCT(statusTmp, phCryptoSym_LoadIv(
          pDataParams->pCryptoDataParamsEnc,
          pDataParams->bIv,
          bIvSize));

  /* Decrypt RndA'*/
  PH_CHECK_SUCCESS_FCT(statusTmp,
      phCryptoSym_Decrypt(
          pDataParams->pCryptoDataParamsEnc,
          PH_CRYPTOSYM_CIPHER_MODE_CBC | PH_EXCHANGE_BUFFER_CONT,
          bWorkBuffer,
          bRndLen,
          &bCmdBuff[1]
      ));

  /* Using bCmdBuff for storage of decrypted RndA */
  bCmdBuff[0] = bCmdBuff[bRndLen]; /* right shift to get back RndA */

  /* Compare RndA and buff */
  if (memcmp(bCmdBuff, bRndA, bRndLen) != 0) {
    /* Authentication failed */
    return PH_ADD_COMPCODE_FIXED(PH_ERR_AUTH_ERROR, PH_COMP_AL_MFDFEVX);
  }

  /* Generate the session key */
  /*
  DES - 8 byte
  2K3DES - 16 bytes
  3K3DES - 24 bytes session key
  */
  (void)memcpy(pDataParams->bSesAuthENCKey, bRndA, 4);
  (void)memcpy(&pDataParams->bSesAuthENCKey[4], bRndB, 4);
  pDataParams->bCryptoMethod = PH_CRYPTOSYM_KEY_TYPE_DES;

  /*
  If first half of bKey is same as the second half it is a single
  DES Key.
  the session key generated is different.
  RndA 1st half + Rnd b 1st half + RndA1st half + RndB 1st half
  */

  if (wKeyType == PH_KEYSTORE_KEY_TYPE_2K3DES) {
    if (memcmp(bKey, &bKey[PH_CRYPTOSYM_DES_KEY_SIZE], PH_CRYPTOSYM_DES_KEY_SIZE) == 0) {
      (void)memcpy(&pDataParams->bSesAuthENCKey[8], bRndA, 4);
      (void)memcpy(&pDataParams->bSesAuthENCKey[12], bRndB, 4);
    } else {
      (void)memcpy(&pDataParams->bSesAuthENCKey[8], &bRndA[4], 4);
      (void)memcpy(&pDataParams->bSesAuthENCKey[12], &bRndB[4], 4);
    }
    pDataParams->bCryptoMethod = PH_CRYPTOSYM_KEY_TYPE_2K3DES;
  }
  if (wKeyType == PH_KEYSTORE_KEY_TYPE_3K3DES) {
    (void)memcpy(&pDataParams->bSesAuthENCKey[8], &bRndA[6], 4);
    (void)memcpy(&pDataParams->bSesAuthENCKey[12], &bRndB[6], 4);

    (void)memcpy(&pDataParams->bSesAuthENCKey[16], &bRndA[12], 4);
    (void)memcpy(&pDataParams->bSesAuthENCKey[20], &bRndB[12], 4);
    pDataParams->bCryptoMethod = PH_CRYPTOSYM_KEY_TYPE_3K3DES;
  }

  /* Session key is generated */
  pDataParams->bAuthMode = PHAL_MFDFEVX_AUTHENTICATEISO;
  pDataParams->bKeyNo = bKeyNoCard;

  /* IV is reset to zero as per the impl. hints document */
  (void)memset(pDataParams->bIv, 0x00, (size_t)sizeof(pDataParams->bIv));

  /* Load the Session key which is valid for this authentication */
  PH_CHECK_SUCCESS_FCT(statusTmp, phCryptoSym_LoadKeyDirect(
          pDataParams->pCryptoDataParamsEnc,
          pDataParams->bSesAuthENCKey,
          pDataParams->bCryptoMethod
      ));

  /* Update the authentication state if VCA PC feature is required by the application. */
  if (pDataParams->pVCADataParams != NULL) {
    /* Set the Session key for Virtual Card which is valid for this authentication */
    PH_CHECK_SUCCESS_FCT(statusTmp, phalVca_SetSessionKeyUtility(
            (phalVca_Sw_DataParams_t *)pDataParams->pVCADataParams,
            pDataParams->bSesAuthENCKey,
            pDataParams->bAuthMode
        ));
  }

  /* satisfy compiler */
  PH_UNUSED_VARIABLE(bSessKeySize);

  /* Need to set the IV on */
  return phCryptoSym_SetConfig(
          pDataParams->pCryptoDataParamsEnc,
          PH_CRYPTOSYM_CONFIG_KEEP_IV,
          PH_CRYPTOSYM_VALUE_KEEP_IV_ON);
}

phStatus_t
phalMfdfEVx_Sw_AuthenticateAES(phalMfdfEVx_Sw_DataParams_t *pDataParams,
    uint16_t wOption, uint16_t wKeyNo,
    uint16_t wKeyVer, uint8_t bKeyNoCard, uint8_t *pDivInput, uint8_t bDivLen)
{
  /**
  * The key type can be AES only.
  * Random numbers are 16 bytes long
  * Init vector is 16 bytes long
  * Session key size is 16 bytes.
  *
  */
  uint8_t     PH_MEMLOC_REM bRndA[PH_CRYPTOSYM_AES_BLOCK_SIZE];
  uint8_t     PH_MEMLOC_REM bRndB[PH_CRYPTOSYM_AES_BLOCK_SIZE + 1U];
  phStatus_t  PH_MEMLOC_REM statusTmp;
  uint8_t     PH_MEMLOC_REM bKey[PH_CRYPTOSYM_AES128_KEY_SIZE];
  uint16_t    PH_MEMLOC_REM wKeyType;
  uint16_t    PH_MEMLOC_REM wRxlen = 0;
  uint8_t     PH_MEMLOC_REM bCmdBuff[33];
  uint16_t    PH_MEMLOC_REM status;
  uint16_t    PH_MEMLOC_REM wCmdLen = 0;
  uint8_t     PH_MEMLOC_REM bRndLen;
  uint8_t     PH_MEMLOC_REM bSessKeySize;
  uint8_t     PH_MEMLOC_REM bIvLen;
  uint8_t     PH_MEMLOC_REM bIv_bak[PH_CRYPTOSYM_AES128_KEY_SIZE];
  uint8_t    *PH_MEMLOC_REM pRecv = NULL;
  uint8_t     PH_MEMLOC_REM bAppId[3] = { 0x00, 0x00, 0x00 };

  /* Set the current authentication status to NOT AUTHENTICATED i.e., invalid key number */
  pDataParams->bKeyNo = 0xFF;

#ifdef RDR_LIB_PARAM_CHECK
  if ((memcmp(pDataParams->pAid, bAppId, 3)) && ((bKeyNoCard & 0x0FU) > 0x0DU)) {
    return PH_ADD_COMPCODE_FIXED(PH_ERR_INVALID_PARAMETER, PH_COMP_AL_MFDFEVX);
  }
  if ((wOption != PHAL_MFDFEVX_NO_DIVERSIFICATION) &&
      (wOption != PH_CRYPTOSYM_DIV_MODE_DESFIRE) &&
      (wOption != PH_CRYPTOSYM_DIV_MODE_MIFARE_PLUS)) {
    return PH_ADD_COMPCODE_FIXED(PH_ERR_INVALID_PARAMETER, PH_COMP_AL_MFDFEVX);
  }
  if ((wOption != PHAL_MFDFEVX_NO_DIVERSIFICATION) && (bDivLen > 31U)) {
    return PH_ADD_COMPCODE_FIXED(PH_ERR_INVALID_PARAMETER, PH_COMP_AL_MFDFEVX);
  }
#endif

  /* Set the dataparams with command code. */
  pDataParams->bCmdCode = PHAL_MFDFEVX_CMD_AUTHENTICATE_AES;

  /* Get Key out of the key store object */
  PH_CHECK_SUCCESS_FCT(statusTmp, phKeyStore_GetKey(
          pDataParams->pKeyStoreDataParams,
          wKeyNo,
          wKeyVer,
          PH_CRYPTOSYM_AES128_KEY_SIZE,
          bKey,
          &wKeyType
      ));

  /* Invalid key type at wKeyNo and wKeyVer */
  if (wKeyType != PH_CRYPTOSYM_KEY_TYPE_AES128) {
    return PH_ADD_COMPCODE_FIXED(PH_ERR_KEY, PH_COMP_AL_MFDFEVX);
  }

  if ((wOption != PHAL_MFDFEVX_NO_DIVERSIFICATION) && (bDivLen != 0x00U)) {
    /* Key is diversified and put back in bKey */
    PH_CHECK_SUCCESS_FCT(statusTmp, phCryptoSym_DiversifyDirectKey(
            pDataParams->pCryptoDataParamsEnc,
            wOption,
            bKey,
            wKeyType,
            pDivInput,
            bDivLen,
            bKey
        ));
  }

  bRndLen = PH_CRYPTOSYM_AES_BLOCK_SIZE;
  bSessKeySize = PH_CRYPTOSYM_AES_BLOCK_SIZE;
  bIvLen = PH_CRYPTOSYM_AES_BLOCK_SIZE;

  /* satisfy compiler */
  PH_UNUSED_VARIABLE(bSessKeySize);

  /* load key */
  PH_CHECK_SUCCESS_FCT(statusTmp, phCryptoSym_LoadKeyDirect(
          pDataParams->pCryptoDataParamsEnc,
          bKey,
          wKeyType));

  (void)memset(bIv_bak, 0x00, bIvLen);

  /* Send the cmd and receive the encrypted RndB */
  bCmdBuff[wCmdLen++] = PHAL_MFDFEVX_CMD_AUTHENTICATE_AES;
  bCmdBuff[wCmdLen++] = bKeyNoCard; /* key number card */

  status = phalMfdfEVx_ExchangeCmd(
          pDataParams,
          pDataParams->pPalMifareDataParams,
          pDataParams->bWrappedMode,
          bCmdBuff,
          wCmdLen,
          &pRecv,
          &wRxlen
      );
  if ((status & PH_ERR_MASK) != PH_ERR_SUCCESS_CHAINING) {
    (void)phalMfdfEVx_Sw_ResetAuthentication(pDataParams);

    if ((status & PH_ERR_MASK) == PH_ERR_SUCCESS) {
      return PH_ADD_COMPCODE_FIXED(PH_ERR_PROTOCOL_ERROR, PH_COMP_AL_MFDFEVX);
    } else {
      return status;
    }
  }
  if (wRxlen != bRndLen) {
    phalMfdfEVx_Sw_ResetAuthentication(pDataParams);
    return PH_ADD_COMPCODE_FIXED(PH_ERR_PROTOCOL_ERROR, PH_COMP_AL_MFDFEVX);
  }

  /* Store the unencrypted RndB */
  (void)memcpy(bRndB, pRecv, bRndLen);

  /* Store the IV to be used for encryption later */
  (void)memcpy(bIv_bak, &bRndB[bRndLen - bIvLen], bIvLen);

  /* Reset IV for the first crypto operation */
  (void)memset(pDataParams->bIv, 0x00, bIvLen);

  /* Load Iv.*/
  PH_CHECK_SUCCESS_FCT(statusTmp, phCryptoSym_LoadIv(
          pDataParams->pCryptoDataParamsEnc,
          pDataParams->bIv,
          bIvLen));

  /* Decrypt the RndB received from PICC */
  PH_CHECK_SUCCESS_FCT(statusTmp, phCryptoSym_Decrypt(
          pDataParams->pCryptoDataParamsEnc,
          PH_CRYPTOSYM_CIPHER_MODE_CBC | PH_EXCHANGE_BUFFER_CONT,
          bRndB,
          bRndLen,
          bRndB
      ));

  /* Generate RndA */
  PH_CHECK_SUCCESS_FCT(statusTmp, phCryptoRng_Seed(pDataParams->pCryptoRngDataParams, bRndB,
          bRndLen));

  PH_CHECK_SUCCESS_FCT(statusTmp, phCryptoRng_Rnd(pDataParams->pCryptoRngDataParams, bRndLen,
          bRndA));

  /* Concat RndA and RndB' */
  bCmdBuff[0] = PHAL_MFDFEVX_RESP_ADDITIONAL_FRAME;
  (void)memcpy(&bCmdBuff[1], bRndA, bRndLen);
  (void)memcpy(&bCmdBuff[bRndLen + 1U], &bRndB[1], bRndLen - 1);
  bCmdBuff[2U * bRndLen] = bRndB[0]; /* RndB left shifted by 8 bits */

  (void)memcpy(pDataParams->bIv, bIv_bak, bIvLen);

  /* Load Iv */
  PH_CHECK_SUCCESS_FCT(statusTmp, phCryptoSym_LoadIv(
          pDataParams->pCryptoDataParamsEnc,
          pDataParams->bIv,
          bIvLen));

  /* Encrypt RndA + RndB' */
  PH_CHECK_SUCCESS_FCT(statusTmp, phCryptoSym_Encrypt(
          pDataParams->pCryptoDataParamsEnc,
          PH_CRYPTOSYM_CIPHER_MODE_CBC | PH_EXCHANGE_BUFFER_CONT,
          &bCmdBuff[1],
          2U * bRndLen,
          &bCmdBuff[1]
      ));

  wCmdLen = (2U * bRndLen) + 1U;

  /* Update Iv */
  (void)memcpy(pDataParams->bIv, &bCmdBuff[wCmdLen - bIvLen], bIvLen);

  /* Get the encrypted RndA' into bWorkBuffer */
  PH_CHECK_SUCCESS_FCT(status, phalMfdfEVx_ExchangeCmd(
          pDataParams,
          pDataParams->pPalMifareDataParams,
          pDataParams->bWrappedMode,
          bCmdBuff,
          wCmdLen,
          &pRecv,
          &wRxlen
      ));
  if (wRxlen != bRndLen) {
    phalMfdfEVx_Sw_ResetAuthentication(pDataParams);
    return PH_ADD_COMPCODE_FIXED(PH_ERR_PROTOCOL_ERROR, PH_COMP_AL_MFDFEVX);
  }

  /* Decrypt the received RndA' */
  PH_CHECK_SUCCESS_FCT(statusTmp, phCryptoSym_LoadIv(
          pDataParams->pCryptoDataParamsEnc,
          pDataParams->bIv,
          bIvLen));

  /* Decrypt RndA'*/
  PH_CHECK_SUCCESS_FCT(statusTmp, phCryptoSym_Decrypt(
          pDataParams->pCryptoDataParamsEnc,
          PH_CRYPTOSYM_CIPHER_MODE_CBC | PH_EXCHANGE_BUFFER_CONT,
          pRecv,
          bRndLen,
          &bCmdBuff[1]
      ));

  bCmdBuff[0] = bCmdBuff[bRndLen]; /* right shift to get back RndA */

  /* Compare RndA and buff */
  if (memcmp(bCmdBuff, bRndA, bRndLen) != 0) {
    (void)phalMfdfEVx_Sw_ResetAuthentication(pDataParams);

    /* Authentication failed */
    return PH_ADD_COMPCODE_FIXED(PH_ERR_AUTH_ERROR, PH_COMP_AL_MFDFEVX);
  }

  /* In case of Originality Key - reset authentication state */
  if ((bKeyNoCard <= PHAL_MFDFEVX_ORIGINALITY_KEY_LAST) &&
      (bKeyNoCard >= PHAL_MFDFEVX_ORIGINALITY_KEY_FIRST) &&
      (memcmp(pDataParams->pAid, bAppId, 3) == 0x00)) {
    phalMfdfEVx_Sw_Int_ResetAuthStatus(pDataParams);
    return PH_ERR_SUCCESS;
  }

  /* Generate the session key */
  (void)memcpy(pDataParams->bSesAuthENCKey, bRndA, 4);
  (void)memcpy(&pDataParams->bSesAuthENCKey[4], bRndB, 4);
  (void)memcpy(&pDataParams->bSesAuthENCKey[8], &bRndA[12], 4);
  (void)memcpy(&pDataParams->bSesAuthENCKey[12], &bRndB[12], 4);

  /* Session key is generated. IV is stored for further crypto operations */
  pDataParams->bAuthMode = PHAL_MFDFEVX_AUTHENTICATEAES;
  pDataParams->bCryptoMethod = PH_CRYPTOSYM_KEY_TYPE_AES128;
  pDataParams->bKeyNo = bKeyNoCard;

  /* Update the authentication state if VCA PC feature is required by the application. */
  if (pDataParams->pVCADataParams != NULL) {
    /* Set the Session key for Virtual Card which is valid for this authentication */
    PH_CHECK_SUCCESS_FCT(statusTmp, phalVca_SetSessionKeyUtility(
            (phalVca_Sw_DataParams_t *)pDataParams->pVCADataParams,
            pDataParams->bSesAuthENCKey,
            pDataParams->bAuthMode
        ));
  }

  /* IV is reset to zero as per the impl. hints document */
  (void)memset(pDataParams->bIv, 0x00, (size_t)sizeof(pDataParams->bIv));

  /* Load the session key */
  PH_CHECK_SUCCESS_FCT(statusTmp, phCryptoSym_LoadKeyDirect(
          pDataParams->pCryptoDataParamsEnc,
          pDataParams->bSesAuthENCKey,
          pDataParams->bCryptoMethod
      ));

  /* Set the keep Iv ON */
  return phCryptoSym_SetConfig(
          pDataParams->pCryptoDataParamsEnc,
          PH_CRYPTOSYM_CONFIG_KEEP_IV,
          PH_CRYPTOSYM_VALUE_KEEP_IV_ON
      );
}

phStatus_t
phalMfdfEVx_Sw_AuthenticateEv2(phalMfdfEVx_Sw_DataParams_t *pDataParams,
    uint8_t bFirstAuth, uint16_t wOption,
    uint16_t wKeyNo, uint16_t wKeyVer, uint8_t bKeyNoCard, uint8_t *pDivInput, uint8_t bDivLen,
    uint8_t bLenPcdCapsIn,
    uint8_t *pPcdCapsIn, uint8_t *pPcdCapsOut, uint8_t *pPdCapsOut)
{
  /* Validate parameters
  * bFirstAuth should be either one or zero.
  * wOption should be validated and interpreted similar to other authenticate
  * functions above.
  * Check that key referenced by wKeyNo and wKeyVer is an AES128 key else throw error (KEY_ERROR)
  * bKeyNoCard cannot be greater than 0xF.
  * if wOption != 0xFFFF then check for bDivLen. If bDivLen is zero, then ignore div input.
  * bLenPcdCapsIn <= 6
  */

  /* Form the command Cmd + bKeyNo + bLenPcdCapsIn + pPcdCapsIn
  * phpalMifare_ExchangeL4(cmdarray);
  * if response != 16+1, return PROTOCOL_ERROR and also first byte should be 0xAF
  * Load the AES 128 key specified by wKeyNo and wKeyVer in the cryptodataparams
  * Decrypt the RndB
  * Insert a seed.
  * Generate RndA
  *
  * Left rotate RndB to generate RndB`
  * Concatenate RndA||RndB` and encrypt this.
  * phpalMifare_ExchangeL4(EXCHANGE_Default, AF || Enc(RndA ||RndB`));
  * if (bFirstAuth) then PD Caps and PCD Caps are returned. Not otherwise.
  * Verify RndA by decrypting the response. Store TI into the pDataParams.
  * As per 4.9.7, Generate SV1 and Sv2
  * The session key generation is according to NIST SP 800-108 [14] in counter mode.
  * The pseudo random function PRF(key, message) applied during the key generation is the the CMAC algorithm
  * Encipher SV1 to generate EncSessionkey
  * Encipher SV2 to generate MACSessionKey.
  * Assign these in pDataParams.
  * Load EncSessionkey and MACSessionkey.
  */
  uint8_t     PH_MEMLOC_REM bRndA[PH_CRYPTOSYM_AES_BLOCK_SIZE];
  uint8_t     PH_MEMLOC_REM bRndB[PH_CRYPTOSYM_AES_BLOCK_SIZE + 1U];
  phStatus_t  PH_MEMLOC_REM statusTmp;
  uint8_t     PH_MEMLOC_REM bKey[PH_CRYPTOSYM_AES128_KEY_SIZE];
  uint16_t    PH_MEMLOC_REM wKeyType;
  uint16_t    PH_MEMLOC_REM wRxlen = 0;
  uint8_t     PH_MEMLOC_REM bCmdBuff[60U];
  uint16_t    PH_MEMLOC_REM status;
  uint16_t    PH_MEMLOC_REM wCmdLen = 0;
  uint8_t     PH_MEMLOC_REM bRndLen;
  uint8_t     PH_MEMLOC_REM bIvLen;
  uint8_t     PH_MEMLOC_REM bSV1[32];
  uint8_t     PH_MEMLOC_REM bTmp;
  uint8_t    *PH_MEMLOC_REM pRecv = NULL;
  uint8_t     PH_MEMLOC_REM bAppId[3] = { 0x00, 0x00, 0x00 };
  uint8_t     PH_MEMLOC_REM bMacLen;

  /* Reset the states and buffers in case. */
  /*if(bFirstAuth)
      PH_CHECK_SUCCESS_FCT(statusTmp, phalMfdfEVx_Sw_ResetAuthentication(pDataParams));   */

  /* Set the current authentication status to NOT AUTHENTICATED i.e., invalid key number */
  pDataParams->bKeyNo = 0xFF;

#ifdef RDR_LIB_PARAM_CHECK
  if (bFirstAuth > 0x01U) {
    return PH_ADD_COMPCODE_FIXED(PH_ERR_INVALID_PARAMETER, PH_COMP_AL_MFDFEVX);
  }
  if ((memcmp(pDataParams->pAid, bAppId, 3)) && ((bKeyNoCard & 0x0FU) > 0x0DU)) {
    return PH_ADD_COMPCODE_FIXED(PH_ERR_INVALID_PARAMETER, PH_COMP_AL_MFDFEVX);
  }
  if ((wOption != PHAL_MFDFEVX_NO_DIVERSIFICATION) &&
      (wOption != PH_CRYPTOSYM_DIV_MODE_DESFIRE) &&
      (wOption != PH_CRYPTOSYM_DIV_MODE_MIFARE_PLUS)) {
    return PH_ADD_COMPCODE_FIXED(PH_ERR_INVALID_PARAMETER, PH_COMP_AL_MFDFEVX);
  }
  if ((wOption != PHAL_MFDFEVX_NO_DIVERSIFICATION) && (bDivLen > 31U)) {
    return PH_ADD_COMPCODE_FIXED(PH_ERR_INVALID_PARAMETER, PH_COMP_AL_MFDFEVX);
  }
#endif

  /* Get Key out of the key store object */
  PH_CHECK_SUCCESS_FCT(statusTmp, phKeyStore_GetKey(
          pDataParams->pKeyStoreDataParams,
          wKeyNo,
          wKeyVer,
          PH_CRYPTOSYM_AES128_KEY_SIZE,
          bKey,
          &wKeyType
      ));

  /* Invalid key type at wKeyNo and wKeyVer */
  if (wKeyType != PH_CRYPTOSYM_KEY_TYPE_AES128) {
    return PH_ADD_COMPCODE_FIXED(PH_ERR_KEY, PH_COMP_AL_MFDFEVX);
  }

  if ((wOption != PHAL_MFDFEVX_NO_DIVERSIFICATION) && (bDivLen != 0x00U)) {
    /* Key is diversified and put back in bKey */
    PH_CHECK_SUCCESS_FCT(statusTmp, phCryptoSym_DiversifyDirectKey(
            pDataParams->pCryptoDataParamsEnc,
            wOption,
            bKey,
            wKeyType,
            pDivInput,
            bDivLen,
            bKey
        ));
  }
  bRndLen = PH_CRYPTOSYM_AES_BLOCK_SIZE;
  bIvLen = PH_CRYPTOSYM_AES_BLOCK_SIZE;

  /* load key */
  PH_CHECK_SUCCESS_FCT(statusTmp, phCryptoSym_LoadKeyDirect(
          pDataParams->pCryptoDataParamsEnc,
          bKey,
          wKeyType));

  /* Send the cmd and receive the encrypted RndB */
  if (0U != (bFirstAuth)) {
    bCmdBuff[wCmdLen++] = PHAL_MFDFEVX_CMD_AUTHENTICATE_EV2_FIRST;

    /* Set the dataparams with command code. */
    pDataParams->bCmdCode = PHAL_MFDFEVX_CMD_AUTHENTICATE_EV2_FIRST;
  } else {
    bCmdBuff[wCmdLen++] = PHAL_MFDFEVX_CMD_AUTHENTICATE_EV2_NON_FIRST;

    /* Set the dataparams with command code. */
    pDataParams->bCmdCode = PHAL_MFDFEVX_CMD_AUTHENTICATE_EV2_NON_FIRST;
  }
  bCmdBuff[wCmdLen++] = bKeyNoCard; /* key number card */
  if (0U != (bFirstAuth)) {
    /* Maximum frame size of card is 64 bytes, so the data should be of max 57 bytes */
    bLenPcdCapsIn = (bLenPcdCapsIn > 57U) ? 57 : bLenPcdCapsIn;

    bCmdBuff[wCmdLen++] = bLenPcdCapsIn; /* PCD Caps In length */
    /* PCD Caps In */
    (void)memcpy(&bCmdBuff[wCmdLen], pPcdCapsIn, bLenPcdCapsIn);
    wCmdLen += bLenPcdCapsIn;
  }

  status = phalMfdfEVx_ExchangeCmd(
          pDataParams,
          pDataParams->pPalMifareDataParams,
          pDataParams->bWrappedMode,
          bCmdBuff,
          wCmdLen,
          &pRecv,
          &wRxlen
      );
  if ((status & PH_ERR_MASK) != PH_ERR_SUCCESS_CHAINING) {
    if (pDataParams->bAuthMode != PHAL_MFDFEVX_NOT_AUTHENTICATED) {
      phalMfdfEVx_Sw_Int_ResetAuthStatus(pDataParams);
    }

    if ((status & PH_ERR_MASK) == PH_ERR_SUCCESS) {
      phalMfdfEVx_Sw_ResetAuthentication(pDataParams);
      return PH_ADD_COMPCODE_FIXED(PH_ERR_PROTOCOL_ERROR, PH_COMP_AL_MFDFEVX);
    } else {
      return status;
    }
  }
  if (wRxlen != bRndLen) {
    phalMfdfEVx_Sw_ResetAuthentication(pDataParams);
    return PH_ADD_COMPCODE_FIXED(PH_ERR_PROTOCOL_ERROR, PH_COMP_AL_MFDFEVX);
  }

  /* Store the unencrypted RndB */
  (void)memcpy(bRndB, pRecv, bRndLen);

  /* Load Zero IV */
  (void)memset(pDataParams->bIv, 0x00, bIvLen);

  /* Load Iv.*/
  PH_CHECK_SUCCESS_FCT(statusTmp, phCryptoSym_LoadIv(
          pDataParams->pCryptoDataParamsEnc,
          pDataParams->bIv,
          bIvLen));

  /* Decrypt the RndB received from PICC */
  PH_CHECK_SUCCESS_FCT(statusTmp, phCryptoSym_Decrypt(
          pDataParams->pCryptoDataParamsEnc,
          PH_CRYPTOSYM_CIPHER_MODE_CBC | PH_EXCHANGE_DEFAULT,
          bRndB,
          bRndLen,
          bRndB
      ));

  /* Generate RndA */
  PH_CHECK_SUCCESS_FCT(statusTmp, phCryptoRng_Seed(pDataParams->pCryptoRngDataParams, bRndB,
          bRndLen));

  PH_CHECK_SUCCESS_FCT(statusTmp, phCryptoRng_Rnd(pDataParams->pCryptoRngDataParams, bRndLen,
          bRndA));

  /* Concat RndA and RndB' */
  bCmdBuff[0] = PHAL_MFDFEVX_RESP_ADDITIONAL_FRAME;
  (void)memcpy(&bCmdBuff[1], bRndA, bRndLen);
  (void)memcpy(&bCmdBuff[bRndLen + 1U], &bRndB[1], bRndLen - 1);
  bCmdBuff[2U * bRndLen] = bRndB[0]; /* RndB left shifted by 8 bits */

  /* Load Iv */
  PH_CHECK_SUCCESS_FCT(statusTmp, phCryptoSym_LoadIv(
          pDataParams->pCryptoDataParamsEnc,
          pDataParams->bIv,
          bIvLen));

  /* Encrypt RndA + RndB' */
  PH_CHECK_SUCCESS_FCT(statusTmp, phCryptoSym_Encrypt(
          pDataParams->pCryptoDataParamsEnc,
          PH_CRYPTOSYM_CIPHER_MODE_CBC | PH_EXCHANGE_DEFAULT,
          &bCmdBuff[1],
          2U * bRndLen,
          &bCmdBuff[1]
      ));

  wCmdLen = (2u * bRndLen) + 1U;

  /* Get the encrypted TI || RndA' || PDCaps || PCDCaps into bWorkBuffer */
  PH_CHECK_SUCCESS_FCT(status, phalMfdfEVx_ExchangeCmd(
          pDataParams,
          pDataParams->pPalMifareDataParams,
          pDataParams->bWrappedMode,
          bCmdBuff,
          wCmdLen,
          &pRecv,
          &wRxlen
      ));

  /* If First Auth, then 32 bytes of data is obtained after exchange */
  if (0U != (bFirstAuth)) {
    if (wRxlen != (2u * bRndLen)) {
      phalMfdfEVx_Sw_ResetAuthentication(pDataParams);
      return PH_ADD_COMPCODE_FIXED(PH_ERR_PROTOCOL_ERROR, PH_COMP_AL_MFDFEVX);
    }
    /* Load IV */
    PH_CHECK_SUCCESS_FCT(statusTmp, phCryptoSym_LoadIv(
            pDataParams->pCryptoDataParamsEnc,
            pDataParams->bIv,
            bIvLen));

    /* Decrypt TI || RndA' || PDCaps || PCDCaps */
    PH_CHECK_SUCCESS_FCT(statusTmp, phCryptoSym_Decrypt(
            pDataParams->pCryptoDataParamsEnc,
            PH_CRYPTOSYM_CIPHER_MODE_CBC | PH_EXCHANGE_DEFAULT,
            pRecv,
            wRxlen,
            bCmdBuff
        ));

    /* Checking the integrity of RndA */
    bTmp = bCmdBuff[3];            /* Store temporarily TI[3] */
    bCmdBuff[3] = bCmdBuff[19];    /* Rotate RndA` to get RndA */

    /* Compare RndA and buff */
    if (memcmp(&bCmdBuff[3], bRndA, PH_CRYPTOSYM_AES128_KEY_SIZE) != 0) {
      phalMfdfEVx_Sw_ResetAuthentication(pDataParams);

      /* Authentication failed */
      return PH_ADD_COMPCODE_FIXED(PH_ERR_AUTH_ERROR, PH_COMP_AL_MFDFEVX);
    }

    bCmdBuff[3] = bTmp;                                            /* Restore TI[3] */
    (void)memcpy(pDataParams->bTi, &bCmdBuff[0],
        PHAL_MFDFEVX_SIZE_TI);   /* Store the Transaction Identifier */
    (void)memcpy(pPcdCapsOut, &bCmdBuff[26], 6);                          /* Update pPcdCapsOut */
    (void)memcpy(pPdCapsOut, &bCmdBuff[20], 6);                          /* Update pPdCapsOut */
  } else {
    /* If Auth is Non First, then 16 bytes of data is expected */
    if (wRxlen != bRndLen) {
      phalMfdfEVx_Sw_ResetAuthentication(pDataParams);
      return PH_ADD_COMPCODE_FIXED(PH_ERR_PROTOCOL_ERROR, PH_COMP_AL_MFDFEVX);
    }

    /* Load IV */
    PH_CHECK_SUCCESS_FCT(statusTmp, phCryptoSym_LoadIv(
            pDataParams->pCryptoDataParamsEnc,
            pDataParams->bIv,
            bIvLen));

    /* Decrypt RndA'*/
    PH_CHECK_SUCCESS_FCT(statusTmp, phCryptoSym_Decrypt(
            pDataParams->pCryptoDataParamsEnc,
            PH_CRYPTOSYM_CIPHER_MODE_CBC | PH_EXCHANGE_BUFFER_CONT,
            pRecv,
            bRndLen,
            &bCmdBuff[1]
        ));

    bCmdBuff[0] = bCmdBuff[bRndLen]; /* Rotate right to get back RndA */

    /* Compare RndA and bCmdBuff */
    if (memcmp(bCmdBuff, bRndA, bRndLen) != 0) {
      (void)phalMfdfEVx_Sw_ResetAuthentication(pDataParams);

      /* Authentication failed */
      return PH_ADD_COMPCODE_FIXED(PH_ERR_AUTH_ERROR, PH_COMP_AL_MFDFEVX);
    }
  }

  /* In case of Originality Key/ MFCKILLKEY - reset authentication state */
  if (((bKeyNoCard <= PHAL_MFDFEVX_ORIGINALITY_KEY_LAST) &&
          (bKeyNoCard >= PHAL_MFDFEVX_ORIGINALITY_KEY_FIRST) &&
          (memcmp(pDataParams->pAid, bAppId, 3) == 0x00)) ||
      ((bKeyNoCard == PHAL_MFDFEVX_MFC_KILL_KEY) && (memcmp(pDataParams->pAid, bAppId, 3) == 0x00))) {
    phalMfdfEVx_Sw_Int_ResetAuthStatus(pDataParams);
    return PH_ERR_SUCCESS;
  }

  /* Generate the session key SV1
   *  SV 1 = 0xA5||0x5A||0x00||0x01||0x00||0x80||RndA[15:14]||(RndA[13::8] XOR RndB[15::8])||RndB[7::0]||RndA[7::0]
   */
  bSV1[0] = 0xA5;
  bSV1[1] = 0x5A;
  bSV1[2] = 0x00;
  bSV1[3] = 0x01;
  bSV1[4] = 0x00;
  bSV1[5] = 0x80;
  bSV1[6] = bRndA[0];
  bSV1[7] = bRndA[1];

  bSV1[8] = bRndA[2] ^ bRndB[0];
  bSV1[9] = bRndA[3] ^ bRndB[1];
  bSV1[10] = bRndA[4] ^ bRndB[2];
  bSV1[11] = bRndA[5] ^ bRndB[3];
  bSV1[12] = bRndA[6] ^ bRndB[4];
  bSV1[13] = bRndA[7] ^ bRndB[5];

  (void)memcpy(&bSV1[14], &bRndB[6], 10);
  (void)memcpy(&bSV1[24], &bRndA[8], 8);

  /* Load Zero IV */
  (void)memset(pDataParams->bIv, 0x00, bIvLen);

  /* Load IV */
  PH_CHECK_SUCCESS_FCT(statusTmp, phCryptoSym_LoadIv(
          pDataParams->pCryptoDataParamsEnc,
          pDataParams->bIv,
          bIvLen));

  /* Start CMAC calculation */
  PH_CHECK_SUCCESS_FCT(statusTmp, phCryptoSym_CalculateMac(
          pDataParams->pCryptoDataParamsEnc,
          (PH_CRYPTOSYM_MAC_MODE_CMAC | PH_EXCHANGE_DEFAULT),
          &bSV1[0],
          32,
          pDataParams->bSesAuthENCKey,
          &bMacLen
      ));

  /* Generate the session key SV2
   *  SV 2 = 0x5A||0xA5||0x00||0x01||0x00||0x80||RndA[15:14]|| (RndA[13::8] XOR RndB[15::10])||RndB[9::0]||RndA[7::0]
   */
  bSV1[0] = 0x5A;
  bSV1[1] = 0xA5;

  /* Load Zero IV */
  (void)memset(pDataParams->bIv, 0x00, bIvLen);

  /* Load IV */
  PH_CHECK_SUCCESS_FCT(statusTmp, phCryptoSym_LoadIv(
          pDataParams->pCryptoDataParamsEnc,
          pDataParams->bIv,
          bIvLen));

  /* Calculate MAC for SV2  */
  PH_CHECK_SUCCESS_FCT(statusTmp, phCryptoSym_CalculateMac(
          pDataParams->pCryptoDataParamsEnc,
          (PH_CRYPTOSYM_MAC_MODE_CMAC | PH_EXCHANGE_DEFAULT),
          &bSV1[0],
          32,
          pDataParams->bSesAuthMACKey,
          &bMacLen
      ));

  /* Session key is generated */
  if (0U != (bFirstAuth)) {
    pDataParams->wCmdCtr = 0x00;
  }

  pDataParams->bAuthMode = PHAL_MFDFEVX_AUTHENTICATEEV2;
  pDataParams->bCryptoMethod = PH_CRYPTOSYM_KEY_TYPE_AES128;
  pDataParams->bKeyNo = bKeyNoCard;

  /* Load the ENC session key */
  PH_CHECK_SUCCESS_FCT(statusTmp, phCryptoSym_LoadKeyDirect(
          pDataParams->pCryptoDataParamsEnc,
          pDataParams->bSesAuthENCKey,
          pDataParams->bCryptoMethod
      ));

  /* Update the authentication state if VCA PC feature is required by the application. */
  if (pDataParams->pVCADataParams != NULL) {
    /* Set the Session key and IV for Virtual Card which is valid for this authentication */
    PH_CHECK_SUCCESS_FCT(statusTmp, phalVca_SetSessionKeyUtility(
            (phalVca_Sw_DataParams_t *)pDataParams->pVCADataParams,
            pDataParams->bSesAuthMACKey,
            pDataParams->bAuthMode
        ));
  }

  /* Load the MAC session key */
  PH_CHECK_SUCCESS_FCT(statusTmp, phCryptoSym_LoadKeyDirect(
          pDataParams->pCryptoDataParamsMac,
          pDataParams->bSesAuthMACKey,
          pDataParams->bCryptoMethod
      ));

  /* Set the keep Iv ON */
  return phCryptoSym_SetConfig(
          pDataParams->pCryptoDataParamsEnc,
          PH_CRYPTOSYM_CONFIG_KEEP_IV,
          PH_CRYPTOSYM_VALUE_KEEP_IV_ON
      );
}
#endif /* NXPBUILD__PHAL_MFDFEVX_NDA */

/* MIFARE DESFire EVx Memory and Configuration mamangement commands. ------------------------------------------------------------------- */
phStatus_t
phalMfdfEVx_Sw_FreeMem(phalMfdfEVx_Sw_DataParams_t *pDataParams, uint8_t *pMemInfo)
{
  phStatus_t  PH_MEMLOC_REM statusTmp;
  uint8_t     PH_MEMLOC_REM bCmdBuff[8];
  uint16_t    PH_MEMLOC_REM wRxlen = 0;
  uint8_t     PH_MEMLOC_REM *pRecv = NULL;

  /* Set the dataparams with command code. */
  pDataParams->bCmdCode = PHAL_MFDFEVX_CMD_FREE_MEM;

  /* form the command */
  bCmdBuff[0] = PHAL_MFDFEVX_CMD_FREE_MEM;
  PH_CHECK_SUCCESS_FCT(statusTmp, phalMfdfEVx_Sw_Int_ReadData_Plain(
          pDataParams,
          (pDataParams->bAuthMode == PHAL_MFDFEVX_AUTHENTICATEEV2) ? PHAL_MFDFEVX_COMMUNICATION_MACD :
          PHAL_MFDFEVX_COMMUNICATION_PLAIN,
          bCmdBuff,
          1,
          &pRecv,
          &wRxlen
      ));

  if (wRxlen != 3U) {
    return PH_ADD_COMPCODE_FIXED(PH_ERR_PROTOCOL_ERROR, PH_COMP_AL_MFDFEVX);
  }

  (void)memcpy(pMemInfo, pRecv, wRxlen);

  return PH_ERR_SUCCESS;
}

#ifdef NXPBUILD__PHAL_MFDFEVX_NDA
phStatus_t
phalMfdfEVx_Sw_Format(phalMfdfEVx_Sw_DataParams_t *pDataParams)
{
  uint8_t PH_MEMLOC_REM bCmdBuff[8];

  /* Set the dataparams with command code. */
  pDataParams->bCmdCode = PHAL_MFDFEVX_CMD_FORMAT;

  /* form the command */
  bCmdBuff[0] = PHAL_MFDFEVX_CMD_FORMAT;

  return phalMfdfEVx_Sw_Int_Write_Plain(pDataParams,
          PHAL_MFDFEVX_DEFAULT_MODE,
          bCmdBuff,
          0x0001,
          (pDataParams->bAuthMode == PHAL_MFDFEVX_AUTHENTICATEEV2) ? PHAL_MFDFEVX_COMMUNICATION_MACD :
          PHAL_MFDFEVX_COMMUNICATION_PLAIN,
          NULL,
          0x0000);
}

phStatus_t
phalMfdfEVx_Sw_SetConfiguration(phalMfdfEVx_Sw_DataParams_t *pDataParams,
    uint8_t bOption, uint8_t *pData,
    uint8_t bDataLen)
{
  uint8_t  PH_MEMLOC_REM bCmdBuff[8];
  uint16_t PH_MEMLOC_REM wCmdLen = 0;
  uint8_t  PH_MEMLOC_REM bPaddingMethod = PH_CRYPTOSYM_PADDING_MODE_1;

  /* Set the dataparams with command code. */
  pDataParams->bCmdCode = PHAL_MFDFEVX_CMD_SET_CONFIG;

  /* form the command */
  bCmdBuff[wCmdLen++] = PHAL_MFDFEVX_CMD_SET_CONFIG;
  bCmdBuff[wCmdLen++] = bOption;
  switch (bOption) {
    /* Data = 1B configuration data */
    case PHAL_MFDFEVX_SET_CONFIG_OPTION0:
    /* Data =  KEY || 1BYTE KEY VERSION    Key data is 25 bytes */
    case PHAL_MFDFEVX_SET_CONFIG_OPTION1:
    /* User defined SAK */
    case PHAL_MFDFEVX_SET_CONFIG_OPTION3:
    /* Secure Messaging Configuration */
    case PHAL_MFDFEVX_SET_CONFIG_OPTION4:
    /* Capability data, consisting of VCTID Override, PDCap1 and PDCap2 */
    case PHAL_MFDFEVX_SET_CONFIG_OPTION5:
    /* Virtual Card Installation Identifier(VCIID) or application ISODFName */
    case PHAL_MFDFEVX_SET_CONFIG_OPTION6:
      break;
    /* User defined ATS */
    case PHAL_MFDFEVX_SET_CONFIG_OPTION2:
      bPaddingMethod = PH_CRYPTOSYM_PADDING_MODE_2;
      break;

    default:
      /* Do not check for Invalid parameter here. */
      break;
  }

  return phalMfdfEVx_Sw_Int_Write_Enc(
          pDataParams,
          PHAL_MFDFEVX_DEFAULT_MODE,
          bCmdBuff,
          wCmdLen,
          bPaddingMethod,
          0x00,
          pData,
          (uint16_t) bDataLen
      );
}
#endif /* NXPBUILD__PHAL_MFDFEVX_NDA */

phStatus_t
phalMfdfEVx_Sw_GetVersion(phalMfdfEVx_Sw_DataParams_t *pDataParams, uint8_t *pVerInfo)
{
  phStatus_t  PH_MEMLOC_REM statusTmp = 0;
  uint8_t     PH_MEMLOC_REM bCmdBuff[8];
  uint16_t    PH_MEMLOC_REM wRxlen = 0;
  uint8_t     PH_MEMLOC_REM *pRecv = NULL;

  /* Set the dataparams with command code. */
  pDataParams->bCmdCode = PHAL_MFDFEVX_CMD_GET_VERSION;

  /* form the command */
  bCmdBuff[0] = PHAL_MFDFEVX_CMD_GET_VERSION;

  PH_CHECK_SUCCESS_FCT(statusTmp, phalMfdfEVx_Sw_Int_ReadData_Plain(
          pDataParams,
          (pDataParams->bAuthMode == PHAL_MFDFEVX_AUTHENTICATEEV2) ? PHAL_MFDFEVX_COMMUNICATION_MACD :
          PHAL_MFDFEVX_COMMUNICATION_PLAIN,
          bCmdBuff,
          1,
          &pRecv,
          &wRxlen
      ));

  /* If received Data length is not equal to 28B(In case of 7BUID) or 30B(In case of 10B UID), 27B(In case of 4B UID)
  * then its a Protocol Error
  */
  if ((wRxlen != PHAL_MFDFEVX_DEF_VERSION_LENGTH) &&
      (wRxlen != PHAL_MFDFEVX_10B_VERSION_LENGTH) &&
      (wRxlen != PHAL_MFDFEVX_4B_VERSION_LENGTH)) {
    return PH_ADD_COMPCODE_FIXED(PH_ERR_PROTOCOL_ERROR, PH_COMP_AL_MFDFEVX);
  }

  (void)memcpy(pVerInfo, pRecv, wRxlen);

  /* Do a Set Config of ADDITIONAL_INFO to set  the length(wLength) of the Version string */
  PH_CHECK_SUCCESS_FCT(statusTmp,
      phalMfdfEVx_Sw_SetConfig((phalMfdfEVx_Sw_DataParams_t *)pDataParams, PHAL_MFDFEVX_ADDITIONAL_INFO,
          wRxlen));

  return PH_ERR_SUCCESS;
}

#ifdef NXPBUILD__PHAL_MFDFEVX_NDA
phStatus_t
phalMfdfEVx_Sw_GetCardUID(phalMfdfEVx_Sw_DataParams_t *pDataParams,
    uint8_t bExchangeOption, uint8_t bOption, uint8_t *pUid, uint8_t *pUidLength)
{
  phStatus_t  PH_MEMLOC_REM statusTmp;
  uint8_t     PH_MEMLOC_REM bCmdBuff[21];
  uint16_t    PH_MEMLOC_REM wRxlen = 0;
  uint16_t    PH_MEMLOC_REM wCmdLen = 0;
  uint8_t     PH_MEMLOC_REM bUidOffset = 0;
  uint8_t     PH_MEMLOC_REM *pRecv = NULL;

  /* Set the dataparams with command code. */
  pDataParams->bCmdCode = PHAL_MFDFEVX_CMD_GET_CARD_UID;

  /* form the command */
  bCmdBuff[wCmdLen++] = PHAL_MFDFEVX_CMD_GET_CARD_UID;

  if (bExchangeOption != 0U) {
    bCmdBuff[wCmdLen++] = bOption;
  }

  PH_CHECK_SUCCESS_FCT(statusTmp, phalMfdfEVx_Sw_Int_ReadData_Enc(
          pDataParams,
          PHAL_MFDFEVX_COMMUNICATION_ENC,
          bCmdBuff,
          wCmdLen,
          &pRecv,
          &wRxlen
      ));

  /* Response will be received as
  * 1. 7 byte UID
  * 2. [1 Byte UID Format] + [1 byte UID Length(0x04)] + 4 byte UID
  * 3. [1 Byte UID Format] + [1 byte UID Length(0x0A)] + 10 byte UID
  */
  if (bExchangeOption == 0U) {
    if (((wRxlen != PHAL_MFDFEVX_DEFAULT_UID_LENGTH) &&
            (wRxlen != PHAL_MFDFEVX_10B_UID_LENGTH) &&
            (wRxlen != PHAL_MFDFEVX_4B_UID_LENGTH))) {
      return PH_ADD_COMPCODE_FIXED(PH_ERR_PROTOCOL_ERROR, PH_COMP_AL_MFDFEVX);
    }
  }

  if (((wRxlen == PHAL_MFDFEVX_10B_UID_LENGTH) || (wRxlen == PHAL_MFDFEVX_4B_UID_LENGTH)) &&
      (bExchangeOption == 0U)) {
    /* In case of 4B/10B UID, strip out first 2 bytes as it contains UID format and UID length */
    wRxlen -= 2U;

    *pUidLength = (uint8_t)wRxlen;

    /* Validate UIDFormat (0x00) for 4byte and 7Byte UID and UIDLength to be equal to real UID */
    if ((pRecv[0] != 0x00U) | (pRecv[1] != *pUidLength)) {
      return PH_ADD_COMPCODE_FIXED(PH_ERR_PROTOCOL_ERROR, PH_COMP_AL_MFDFEVX);
    }
    (void)memcpy(pUid, &pRecv[2], *pUidLength);

    /* Update the UID information to the dataparams. */
    (void)memcpy(pDataParams->bUid, pUid, *pUidLength);
    pDataParams->bUidLength = *pUidLength;

    /* Set the card Length in wAdditionalInfo. This is done to assist C# wrapper as it will not be able
    to recognize the card UID Length */
    PH_CHECK_SUCCESS_FCT(statusTmp, phalMfdfEVx_Sw_SetConfig(pDataParams,
            PHAL_MFDFEVX_ADDITIONAL_INFO, wRxlen));
  } else {
    *pUidLength = (uint8_t)wRxlen;
    (void)memcpy(pUid, pRecv, *pUidLength);

    /* Compute the UIDOffset. */
    bUidOffset = (uint8_t)(((wRxlen == PHAL_MFDFEVX_DEFAULT_UID_LENGTH) ||
                (wRxlen == (PHAL_MFDFEVX_DEFAULT_UID_LENGTH + 4))) ? 0 : 2);

    /* Update the UID information to the dataparams. */
    (void)memcpy(pDataParams->bUid, &pUid[bUidOffset], *pUidLength - bUidOffset);
    pDataParams->bUidLength = *pUidLength - bUidOffset;

    /* Set the card Length in wAdditionalInfo. This is done to assist C# wrapper as it will not be able
    to recognize the card UID Length */
    PH_CHECK_SUCCESS_FCT(statusTmp, phalMfdfEVx_Sw_SetConfig(pDataParams,
            PHAL_MFDFEVX_ADDITIONAL_INFO, wRxlen));
  }

  return PH_ERR_SUCCESS;
}

/* MIFARE DESFire EVx Key mamangement commands. ---------------------------------------------------------------------------------------- */
phStatus_t
phalMfdfEVx_Sw_ChangeKey(phalMfdfEVx_Sw_DataParams_t *pDataParams, uint16_t wOption,
    uint16_t wOldKeyNo,
    uint16_t wOldKeyVer, uint16_t wNewKeyNo, uint16_t wNewKeyVer, uint8_t bKeyNoCard,
    uint8_t *pDivInput, uint8_t bDivLen)
{
  uint16_t    PH_MEMLOC_REM statusTmp;
  uint8_t     PH_MEMLOC_REM bCmdBuff[42];
  uint8_t     PH_MEMLOC_REM bWorkBuffer[42];
  uint8_t     PH_MEMLOC_REM bOldKey[32];
  uint8_t     PH_MEMLOC_REM bNewKey[32];
  uint8_t     PH_MEMLOC_REM bNewKeyLen = 0;
  uint8_t     PH_MEMLOC_REM bIndex;
  uint16_t    PH_MEMLOC_REM wRxlen = 0;
  uint16_t    PH_MEMLOC_REM wOldKeyType;
  uint16_t    PH_MEMLOC_REM wNewKeyType;
  uint16_t    PH_MEMLOC_REM wCmdLen = 0;
  uint8_t     PH_MEMLOC_REM bCMAC[PH_CRYPTOSYM_AES_BLOCK_SIZE];
  uint8_t     PH_MEMLOC_REM bCMacCard[8];
  uint8_t     PH_MEMLOC_REM bMacLen;
  uint8_t     PH_MEMLOC_REM bIvLen = 0;
  uint32_t    PH_MEMLOC_REM dwCrc;
  uint16_t    PH_MEMLOC_REM wCrc;
  uint16_t    PH_MEMLOC_REM wTmp;
  uint16_t    PH_MEMLOC_REM wTmpOption = 0x0000;
  uint8_t     PH_MEMLOC_REM bAppId[3] = { 0x00, 0x00, 0x00 };
  uint8_t    *PH_MEMLOC_REM pRecv = NULL;
  uint16_t    PH_MEMLOC_REM wWorkBufferLen = 0;

#ifdef RDR_LIB_PARAM_CHECK
  /* Change key should also take care of changing other keys at PICC level like
  * the Proximity check key,
  * VCA keys
  * Transaction MAC key
  */
  if (memcmp(pDataParams->pAid, bAppId, 3) == 0x00) {
    /* Only if seleted Aid is 0x000000, PICC level key change is targeted. */
    if (((bKeyNoCard & 0x3FU) != 0x00U) &&

        /* PICC DAMAuthKey, DAMMACKey, DAMEncKey */
        ((bKeyNoCard & 0x3FU) != 0x10U) && ((bKeyNoCard & 0x3FU) != 0x11U) &&
        ((bKeyNoCard & 0x3FU) != 0x12U) &&

        /* PICC NXPDAMAuthKey, NXPDAMMACKey, NXPDAMEncKey */
        ((bKeyNoCard & 0x3FU) != 0x18U) && ((bKeyNoCard & 0x3FU) != 0x19U) &&
        ((bKeyNoCard & 0x3FU) != 0x1AU) &&

        /* PICC VCConfigurationKey, VCProximityKey, VCSelectMACKey, VCSelectENCKey */
        ((bKeyNoCard & 0x3FU) != 0x20U) && ((bKeyNoCard & 0x3FU) != 0x21U) &&
        ((bKeyNoCard & 0x3FU) != 0x22U) && ((bKeyNoCard & 0x3FU) != 0x23U) &&

        /* MFCKillKey, MFCLicenseMACKey */
        ((bKeyNoCard & 0x3FU) != 0x31U) && ((bKeyNoCard & 0x3FU) != 0x32U)) {
      /* Invalid card key number supplied */
      return PH_ADD_COMPCODE_FIXED(PH_ERR_INVALID_PARAMETER, PH_COMP_AL_MFDFEVX);
    } else if (((bKeyNoCard & 0xC0U) != 0x80U) && ((bKeyNoCard & 0xC0U) != 0x40U) &&
        ((bKeyNoCard & 0xC0U) != 0x00U)) {
      /* Invalid card key number supplied */
      return PH_ADD_COMPCODE_FIXED(PH_ERR_INVALID_PARAMETER, PH_COMP_AL_MFDFEVX);
    } else {
      /*Do Nothing. This is for PRQA compliance */
    }
  } else {
    /* Key numbers between 0D and 21 are not allowed for App level, also key numbers above 23 are not allowed.
    if AID 0x000000 is not selected,At application level, VC keys 0x21, 0x22 and 0x23 can be enabled at application creation,
    Refer reference architecture version 13 */
    if (IS_INVALID_APP_KEY(bKeyNoCard) || IS_INVALID_VC_KEY(bKeyNoCard)) {
      /* Invalid application key specified */
      return PH_ADD_COMPCODE_FIXED(PH_ERR_INVALID_PARAMETER, PH_COMP_AL_MFDFEVX);
    }
  }
  if ((wOption == 0x0000U) || (bDivLen > 31U)) {
    return PH_ADD_COMPCODE_FIXED(PH_ERR_INVALID_PARAMETER, PH_COMP_AL_MFDFEVX);
  }
  if (pDataParams->bAuthMode == PHAL_MFDFEVX_NOT_AUTHENTICATED) {
    return PH_ADD_COMPCODE_FIXED(PH_ERR_USE_CONDITION, PH_COMP_AL_MFDFEVX);
  }
#endif
  (void)memset(bWorkBuffer, 0x00, 42);
  (void)memset(bCmdBuff, 0x00, 42);
  /* form the command */
  bCmdBuff[wCmdLen++] = PHAL_MFDFEVX_CMD_CHANGE_KEY;
  bCmdBuff[wCmdLen++] = bKeyNoCard;

  if ((pDataParams->bAuthMode == PHAL_MFDFEVX_AUTHENTICATEAES) ||
      (pDataParams->bAuthMode == PHAL_MFDFEVX_AUTHENTICATEEV2)) {
    bIvLen = PH_CRYPTOSYM_AES_BLOCK_SIZE;
  } else {
    bIvLen = PH_CRYPTOSYM_DES_BLOCK_SIZE;
  }

  /* The IV will be different if AuthMode is AV2. Here the
  * ENC IV has to be computed and used for encryption.
  * The MAC IV is required to generate the MAC and append this to
  * the command before sending to the card.
  */

  if (pDataParams->bAuthMode == PHAL_MFDFEVX_AUTHENTICATEEV2) {
    /* the IV is constructed by encrypting with KeyID.SesAuthENCKey according to the ECB mode
    * As ECB encription doesnot use IV during the encription so we need not backup/ update with zero IV */
    PH_CHECK_SUCCESS_FCT(statusTmp, phalMfdfEVx_Sw_Int_ComputeIv(
            PH_OFF,
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
  }
  /* Load Iv */
  PH_CHECK_SUCCESS_FCT(statusTmp, phCryptoSym_LoadIv(
          pDataParams->pCryptoDataParamsEnc,
          pDataParams->bIv,
          bIvLen
      ));

  PH_CHECK_SUCCESS_FCT(statusTmp, phKeyStore_GetKey(
          pDataParams->pKeyStoreDataParams,
          wOldKeyNo,
          wOldKeyVer,
          sizeof(bOldKey),
          bOldKey,
          &wOldKeyType
      ));

  PH_CHECK_SUCCESS_FCT(statusTmp, phKeyStore_GetKey(
          pDataParams->pKeyStoreDataParams,
          wNewKeyNo,
          wNewKeyVer,
          sizeof(bNewKey),
          bNewKey,
          &wNewKeyType
      ));

  if (wOldKeyType == PH_KEYSTORE_KEY_TYPE_DES) {
    wOldKeyType = PH_KEYSTORE_KEY_TYPE_2K3DES;
    (void)memcpy(&bOldKey[8], bOldKey, 8);
  }
  if (wNewKeyType == PH_KEYSTORE_KEY_TYPE_DES) {
    wNewKeyType = PH_KEYSTORE_KEY_TYPE_2K3DES;
    (void)memcpy(&bNewKey[8], bNewKey, 8);
  }
  /*
  It is allowed to change a key type for PICC master key.
  Old key may not be diversified but new key can be.
  Old key may be diversified with one round but new key can
  be diversified with two rounds.

  Key diversification method (DESFire or MFPlus) cannot be changed
  between old and new key.

  It is assumed that the diversification input specified is the same
  for both old key and new key
  */

  if ((wOption != PHAL_MFDFEVX_NO_DIVERSIFICATION) && (bDivLen != 0x00U)) {
    if (0U != (wOption & PHAL_MFDFEVX_CHGKEY_DIV_NEW_KEY)) {
      if (0U != (wOption & PHAL_MFDFEVX_CHGKEY_DIV_METHOD_CMAC)) {
        wTmpOption = PH_CRYPTOSYM_DIV_MODE_MIFARE_PLUS;
      } else {
        wTmpOption = PH_CRYPTOSYM_DIV_MODE_DESFIRE;
        if (0U != (wOption & PHAL_MFDFEVX_CHGKEY_DIV_NEW_KEY_ONERND)) {
          wTmpOption |= PH_CRYPTOSYM_DIV_OPTION_2K3DES_HALF;
        }
      }
      PH_CHECK_SUCCESS_FCT(statusTmp, phCryptoSym_DiversifyDirectKey(
              pDataParams->pCryptoDataParamsEnc,
              wTmpOption,
              bNewKey,
              wNewKeyType,
              pDivInput,
              bDivLen,
              bNewKey
          ));
    }
    if (0U != (wOption & PHAL_MFDFEVX_CHGKEY_DIV_OLD_KEY)) {
      if (0U != (wOption & PHAL_MFDFEVX_CHGKEY_DIV_METHOD_CMAC)) {
        wTmpOption |= PH_CRYPTOSYM_DIV_MODE_MIFARE_PLUS;
      } else {
        wTmpOption |= PH_CRYPTOSYM_DIV_MODE_DESFIRE;
        if (0U != (wOption & PHAL_MFDFEVX_CHGKEY_DIV_OLD_KEY_ONERND)) {
          wTmpOption |= PH_CRYPTOSYM_DIV_OPTION_2K3DES_HALF;
        }
      }
      PH_CHECK_SUCCESS_FCT(statusTmp, phCryptoSym_DiversifyDirectKey(
              pDataParams->pCryptoDataParamsEnc,
              wTmpOption,
              bOldKey,
              wOldKeyType,
              pDivInput,
              bDivLen,
              bOldKey
          ));
    }

    /* Reload the IV and key since the diversify function has invalidated the key */
    /* Load the Session key which is valid for this authentication */
    PH_CHECK_SUCCESS_FCT(statusTmp, phCryptoSym_LoadKeyDirect(
            pDataParams->pCryptoDataParamsEnc,
            pDataParams->bSesAuthENCKey,
            pDataParams->bCryptoMethod
        ));
    /* The IV will be different if AuthMode is AV2. Here the
    * ENC IV has to be computed and used for encryption.
    * The MAC IV is required to generate the MAC and append this to
    * the command before sending to the card.
    */
    if (pDataParams->bAuthMode == PHAL_MFDFEVX_AUTHENTICATEEV2) {
      /* the IV is constructed by encrypting with KeyID.SesAuthENCKey according to the ECB mode
      * As ECB encription doesnot use IV during the encription so we need not backup/ update with zero IV*/
      PH_CHECK_SUCCESS_FCT(statusTmp, phalMfdfEVx_Sw_Int_ComputeIv(
              PH_OFF,
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
    }
    /* Load Iv */
    PH_CHECK_SUCCESS_FCT(statusTmp, phCryptoSym_LoadIv(
            pDataParams->pCryptoDataParamsEnc,
            pDataParams->bIv,
            bIvLen
        ));

    /* Need to check whether this is required for 0x0A mode also*/
    PH_CHECK_SUCCESS_FCT(statusTmp, phCryptoSym_SetConfig(
            pDataParams->pCryptoDataParamsEnc,
            PH_CRYPTOSYM_CONFIG_KEEP_IV,
            PH_CRYPTOSYM_VALUE_KEEP_IV_ON
        ));
  }

  switch (wNewKeyType) {
    case PH_CRYPTOSYM_KEY_TYPE_AES128:
      bNewKeyLen = PH_CRYPTOSYM_AES128_KEY_SIZE;
      break;

    case PH_CRYPTOSYM_KEY_TYPE_2K3DES:
      bNewKeyLen = PH_CRYPTOSYM_2K3DES_KEY_SIZE;
      break;

    case PH_CRYPTOSYM_KEY_TYPE_3K3DES:
      bNewKeyLen = PH_CRYPTOSYM_3K3DES_KEY_SIZE;
      break;

    default:
      return PH_ADD_COMPCODE_FIXED(PH_ERR_KEY, PH_COMP_AL_MFDFEVX);
  }

  if (pDataParams->bAuthMode == PHAL_MFDFEVX_AUTHENTICATE) {
    /* bKeyNo for PICC masterkey will have key type in the two MS bits
    Should check for : bKeyNo & 3F != bKeyNoCard & 3F
    */
    if ((pDataParams->bKeyNo & 0x3FU) != (bKeyNoCard & 0x3FU)) {
      /* Get the key from the key store using wKeyNo and version */
      /* xored_Data = pNewKey ^ wKey */
      /* xored_Data + CRC16 (xord data) + CRC16(new key)+padding */
      /* Decrypt the above, Cmd+keyno+decrypted data is then sent to card */
      /* Get the key from the key store using wKeyNo and version */

      /* xored_Data = pNewKey ^ wKey */
      for (bIndex = 0; bIndex < bNewKeyLen; bIndex++) {
        bWorkBuffer[bIndex] = bOldKey[bIndex] ^ bNewKey[bIndex];
      }
      /*
      Key version is irrelevant here since in this case, we are
      changing a key different from the one authenticated with.
      In Native authentication mode only DES and 2K3DES are possible.
      AES is not possible and hence the key version that is only applicable
      to AES keys. Key version is relevant when changing PICC master key to
      VC Configuration key which is of type AES always.
      */

      /* Copy the XORd data to the command buffer */
      (void)memcpy(&bCmdBuff[2], bWorkBuffer, bIndex);
      wCmdLen = wCmdLen + bIndex;
      /* If the new key is of type AES then key version needs to be appended to the new key before calculating
      CRC16 */
      if (wNewKeyType == PH_KEYSTORE_KEY_TYPE_AES128) {
        bCmdBuff[wCmdLen++] = (uint8_t)wNewKeyVer;
      }

      /* Calculate CRC16 over XORddata */
      PH_CHECK_SUCCESS_FCT(statusTmp, phTools_CalculateCrc16(
              PH_TOOLS_CRC_OPTION_DEFAULT,
              PH_TOOLS_CRC16_PRESET_ISO14443A,
              PH_TOOLS_CRC16_POLY_ISO14443,
              &bCmdBuff[2],
              wCmdLen - 2u,
              &wCrc
          ));
      /* Append CRC16 of the XORd data */
      (void)memcpy(&bCmdBuff[wCmdLen], &wCrc, 2);

      /* Update Cmd length */
      wCmdLen += 2U;

      /* Calculate CRC for the new key */
      PH_CHECK_SUCCESS_FCT(statusTmp, phTools_CalculateCrc16(
              PH_TOOLS_CRC_OPTION_DEFAULT,
              PH_TOOLS_CRC16_PRESET_ISO14443A,
              PH_TOOLS_CRC16_POLY_ISO14443,
              bNewKey,
              bNewKeyLen,
              &wCrc
          ));
      /* Add CRC16 */
      (void)memcpy(&bCmdBuff[wCmdLen], &wCrc, 2);
      wCmdLen += 2U; /* comm sett + access rights (2b) + 2B CRC */
    } else {
      (void)memcpy(&bCmdBuff[wCmdLen], bNewKey, bNewKeyLen);
      wCmdLen = wCmdLen + bNewKeyLen;
      /* Also check if it is PICC master key and is an AES key. If so then
      key version also needs to be appended to the new key before calculating
      CRC16 */
      if ((bKeyNoCard & 0xC0U) == 0x80U) {
        /* PICC master key is being changed to AES key. Version is relevant */
        bCmdBuff[wCmdLen++] = (uint8_t)wNewKeyVer;
      }
      /* Calculate CRC for the new key and the key version if any */
      PH_CHECK_SUCCESS_FCT(statusTmp, phTools_CalculateCrc16(
              PH_TOOLS_CRC_OPTION_DEFAULT,
              PH_TOOLS_CRC16_PRESET_ISO14443A,
              PH_TOOLS_CRC16_POLY_ISO14443,
              &bCmdBuff[2],
              wCmdLen - 2u,
              &wCrc
          ));
      /* Add CRC16 */
      (void)memcpy(&bCmdBuff[wCmdLen], &wCrc, 2);
      wCmdLen += 2U; /* comm sett + access rights (2b) + 2B CRC */
    }

    /* Apply padding */
    wTmp = wCmdLen - 2u;
    if (0U != (wTmp % bIvLen)) {
      PH_CHECK_SUCCESS_FCT(statusTmp, phCryptoSym_ApplyPadding(
              PH_CRYPTOSYM_PADDING_MODE_1,
              &bCmdBuff[2],
              wTmp,
              bIvLen,
              sizeof(bWorkBuffer),
              bWorkBuffer,
              &wTmp
          ));
    }

    /* DF4 Decrypt */
    PH_CHECK_SUCCESS_FCT(statusTmp, phCryptoSym_Encrypt(
            pDataParams->pCryptoDataParamsEnc,
            PH_CRYPTOSYM_CIPHER_MODE_CBC_DF4 | PH_EXCHANGE_BUFFER_CONT,
            bWorkBuffer,
            wTmp,
            bWorkBuffer
        ));
    /* form the complete command */
    (void)memcpy(&bCmdBuff[2], bWorkBuffer, wTmp);

    /* Update Cmd len */
    wCmdLen = wTmp + 2U;
  } else if ((pDataParams->bAuthMode == PHAL_MFDFEVX_AUTHENTICATEAES) ||
      (pDataParams->bAuthMode == PHAL_MFDFEVX_AUTHENTICATEISO)) {
    if ((pDataParams->bKeyNo & 0x3FU) != (bKeyNoCard & 0x3FU)) {
      /* xored_Data = pNewKey ^ wKey */
      for (bIndex = 0; bIndex < bNewKeyLen; bIndex++) {
        bWorkBuffer[bIndex] = bOldKey[bIndex] ^ bNewKey[bIndex];
      }
      /* If the new key is of type AES then key version needs to be appended to the new key before calculating
      CRC16 */
      if (wNewKeyType == PH_KEYSTORE_KEY_TYPE_AES128) {
        bWorkBuffer[bIndex++] = (uint8_t)wNewKeyVer;
      }
      (void)memcpy(&bCmdBuff[2], bWorkBuffer, bIndex);
      wCmdLen = wCmdLen + bIndex;

      /* Calculate CRC32 over cmd+header+XORddata+[keyversion] */
      PH_CHECK_SUCCESS_FCT(statusTmp, phTools_CalculateCrc32(
              PH_TOOLS_CRC_OPTION_DEFAULT,
              PH_TOOLS_CRC32_PRESET_DF8,
              PH_TOOLS_CRC32_POLY_DF8,
              bCmdBuff,
              wCmdLen,
              &dwCrc
          ));

      (void)memcpy(&bCmdBuff[wCmdLen], &dwCrc, 4);
      wCmdLen += 4U;

      /* Calculate CRC32 over the new key  */
      PH_CHECK_SUCCESS_FCT(statusTmp, phTools_CalculateCrc32(
              PH_TOOLS_CRC_OPTION_DEFAULT,
              PH_TOOLS_CRC32_PRESET_DF8,
              PH_TOOLS_CRC32_POLY_DF8,
              bNewKey,
              bNewKeyLen,
              &dwCrc
          ));
      (void)memcpy(&bCmdBuff[wCmdLen], &dwCrc, 4);
      wCmdLen += 4U;

      wTmp = wCmdLen - 2u;
      if (0U != (wTmp % bIvLen)) {
        /* Apply padding */
        PH_CHECK_SUCCESS_FCT(statusTmp, phCryptoSym_ApplyPadding(
                PH_CRYPTOSYM_PADDING_MODE_1,
                &bCmdBuff[2],
                wTmp,
                bIvLen,
                sizeof(bCmdBuff) - 2,
                &bCmdBuff[2],
                &wTmp
            ));
      }

      /* Encrypt */
      PH_CHECK_SUCCESS_FCT(statusTmp, phCryptoSym_Encrypt(
              pDataParams->pCryptoDataParamsEnc,
              PH_CRYPTOSYM_CIPHER_MODE_CBC | PH_EXCHANGE_BUFFER_CONT,
              &bCmdBuff[2],
              wTmp,
              &bCmdBuff[2]
          ));
      wCmdLen = wTmp + 2U;
    } else {
      (void)memcpy(&bCmdBuff[wCmdLen], bNewKey, bNewKeyLen);
      wCmdLen = wCmdLen + bNewKeyLen;

      /* Also check if it is PICC master key and is an AES key is to be written.
      If so then key version also needs to be appended to the new key before
      calculating CRC */
      if (memcmp(pDataParams->pAid, bAppId, 3) == 0x00) {
        if ((bKeyNoCard & 0xC0U) == 0x80U) {
          /* PICC master key is being changed to AES key. Version is relevant */
          bCmdBuff[wCmdLen++] = (uint8_t)wNewKeyVer;
        }
        /* Case-2: If bKeyNoCard is prepared with bit[0-5] set to 0x20/0x21/0x22/0x23 indicating VC Keys which are at PICC Level,
        * Add Key version to command buffer.
        */
        if (((bKeyNoCard & 0x3FU) == 0x20U) || ((bKeyNoCard & 0x3FU) == 0x21U) ||
            ((bKeyNoCard & 0x3FU) == 0x22U) || ((bKeyNoCard & 0x3FU) == 0x23U)) {
          /* VC keys are being changed to AES key. Version is relevant */
          bCmdBuff[wCmdLen++] = (uint8_t)wNewKeyVer;
        }

        /* Case-3: if bKeyNoCard is DAM keys, and the new KeyType targetted is AES Keys, add the version information */
        if (((bKeyNoCard & 0x3FU) == 0x10U) || ((bKeyNoCard & 0x3FU) == 0x11U) ||
            ((bKeyNoCard & 0x3FU) == 0x12U)) {
          /* If the new key is of type AES then key version needs to be appended to the new key before calculating
          CRC16 */
          if (wNewKeyType == PH_KEYSTORE_KEY_TYPE_AES128) {
            bCmdBuff[wCmdLen++] = (uint8_t)wNewKeyVer;
          }
        }
      } else {
        /* If the new key is of type AES then key version needs to be appended to the new key before calculating
        CRC16 */
        if (wNewKeyType == PH_KEYSTORE_KEY_TYPE_AES128) {
          bCmdBuff[wCmdLen++] = (uint8_t)wNewKeyVer;
        }
      }

      /*  Calculate CRC32 on the Key data */
      PH_CHECK_SUCCESS_FCT(statusTmp, phTools_CalculateCrc32(
              PH_TOOLS_CRC_OPTION_DEFAULT,
              PH_TOOLS_CRC32_PRESET_DF8,
              PH_TOOLS_CRC32_POLY_DF8,
              bCmdBuff,
              wCmdLen,
              &dwCrc
          ));

      /* Add CRC32 */
      (void)memcpy(&bCmdBuff[wCmdLen], &dwCrc, 4);
      wCmdLen += 4U; /* comm sett + access rights (2b) + 4B CRC */

      wTmp = wCmdLen - 2u;
      /* Apply padding */
      PH_CHECK_SUCCESS_FCT(statusTmp, phCryptoSym_ApplyPadding(
              PH_CRYPTOSYM_PADDING_MODE_1,
              &bCmdBuff[2],
              wTmp,
              bIvLen,
              sizeof(bCmdBuff) - 2,
              &bCmdBuff[2],
              &wTmp
          ));

      /* Encrypt */
      PH_CHECK_SUCCESS_FCT(statusTmp, phCryptoSym_Encrypt(
              pDataParams->pCryptoDataParamsEnc,
              PH_CRYPTOSYM_CIPHER_MODE_CBC | PH_EXCHANGE_BUFFER_CONT,
              &bCmdBuff[2],
              wTmp,
              &bCmdBuff[2]
          ));
      /* Update Cmd len */
      wCmdLen = wTmp + 2U;
    }

    /* Update IV */
    (void)memcpy(pDataParams->bIv, &bCmdBuff[wCmdLen - bIvLen], bIvLen);
  }
  /* Need new else if statement for AuthEV2
  * In AuthEV2, it is sent in FULL mode, meaning the Data is encrypted
  * and a MAC is calculated and attached at the end.
  * ENC Session key is used for encryption and MAC session key is
  * used for MAC calculation
  */
  else if (pDataParams->bAuthMode == PHAL_MFDFEVX_AUTHENTICATEEV2) {
    if ((pDataParams->bKeyNo & 0x3FU) != (bKeyNoCard & 0x3FU)) {
      /* Copy bNewKey to the bWorkBuffer */
      for (bIndex = 0; bIndex < bNewKeyLen; bIndex++) {
        bWorkBuffer[bIndex] = bNewKey[bIndex];
      }

      /* Append Key Version */
      bWorkBuffer[bIndex++] = (uint8_t)wNewKeyVer;

      /* Calculate CRC32 over the new key  ie CRC32NK shall be the 4-byte CRC value taken over NewKey */
      PH_CHECK_SUCCESS_FCT(statusTmp, phTools_CalculateCrc32(
              PH_TOOLS_CRC_OPTION_DEFAULT,
              PH_TOOLS_CRC32_PRESET_DF8,
              PH_TOOLS_CRC32_POLY_DF8,
              bWorkBuffer,
              (uint16_t)bIndex - 1,
              &dwCrc
          ));

      /* Key number authenticated with is not the key to be
      * changed
      * xored_Data = pNewKey ^ wKey
      * bWorkBuffer contains pNewKey
      */
      for (bIndex = 0; bIndex < bNewKeyLen; bIndex++) {
        bWorkBuffer[bIndex] = bOldKey[bIndex] ^ bWorkBuffer[bIndex];
      }
      /* xored_Data+ [AES key version] + CRC32 (all prev. data) + CRC32(new key)+padding */
      /* Adding key version should always be true because we are only dealing with
      * AES128 keys here
      */
      bIndex++;   /* Just increment bIndex because it already contains wNewKeyVer */
      (void)memcpy(&bCmdBuff[2], bWorkBuffer, bIndex);
      wCmdLen = wCmdLen + bIndex;

      (void)memcpy(&bCmdBuff[wCmdLen], &dwCrc, 4);
      wCmdLen += 4U;

      wTmp = wCmdLen - 2u;
      if (0U != (wTmp % bIvLen)) {
        /* Apply padding */
        PH_CHECK_SUCCESS_FCT(statusTmp, phCryptoSym_ApplyPadding(
                PH_CRYPTOSYM_PADDING_MODE_2,
                &bCmdBuff[2],
                wTmp,
                bIvLen,
                sizeof(bCmdBuff) - 2,
                &bCmdBuff[2],
                &wTmp
            ));
      }

      /* Encrypt */
      PH_CHECK_SUCCESS_FCT(statusTmp, phCryptoSym_Encrypt(
              pDataParams->pCryptoDataParamsEnc,
              PH_CRYPTOSYM_CIPHER_MODE_CBC | PH_EXCHANGE_BUFFER_CONT,
              &bCmdBuff[2],
              wTmp,
              &bCmdBuff[2]
          ));
      wCmdLen = wTmp + 2U;
    } else {
      (void)memcpy(&bCmdBuff[wCmdLen], bNewKey, bNewKeyLen);
      wCmdLen = wCmdLen + bNewKeyLen;

      /* Also check if it is PICC master key and is an AES key is to be written.
      If so then key version also needs to be appended to the new key before
      calculating CRC */
      if (memcmp(pDataParams->pAid, bAppId, 3) == 0x00) {
        if ((bKeyNoCard & 0xC0U) == 0x80U) {
          /* PICC master key is being changed to AES key. Version is relevant */
          bCmdBuff[wCmdLen++] = (uint8_t)wNewKeyVer;
        }

        /* Case-2: If bKeyNoCard is  0x20/0x21/0x22/0x23 indicating VC Keys which are at PICC Level (0x00),
        * Add Key version to command buffer.
        */
        if (((bKeyNoCard & 0x3FU) == 0x20U) || ((bKeyNoCard & 0x3FU) == 0x21U) ||
            ((bKeyNoCard & 0x3FU) == 0x22U) || ((bKeyNoCard & 0x3FU) == 0x23U)) {
          bCmdBuff[wCmdLen++] = (uint8_t)wNewKeyVer;
        }

        /* Case-3: if bKeyNoCard is DAM keys, and the new KeyType targetted is AES Keys, add the version information */
        if (((bKeyNoCard & 0x3FU) == 0x10U) || ((bKeyNoCard & 0x3FU) == 0x11U) ||
            ((bKeyNoCard & 0x3FU) == 0x12U)) {
          /* If the new key is of type AES then key version needs to be appended to the new key before calculating
          CRC16 */
          if (wNewKeyType == PH_KEYSTORE_KEY_TYPE_AES128) {
            bCmdBuff[wCmdLen++] = (uint8_t)wNewKeyVer;
          }
        }
      } else {
        bCmdBuff[wCmdLen++] = (uint8_t)wNewKeyVer;
      }

      wTmp = wCmdLen - 2u;
      /* Apply padding */
      PH_CHECK_SUCCESS_FCT(statusTmp, phCryptoSym_ApplyPadding(
              PH_CRYPTOSYM_PADDING_MODE_2,
              &bCmdBuff[2],
              wTmp,
              bIvLen,
              sizeof(bCmdBuff) - 2,
              &bCmdBuff[2],
              &wTmp
          ));

      /* Encrypt */
      PH_CHECK_SUCCESS_FCT(statusTmp, phCryptoSym_Encrypt(
              pDataParams->pCryptoDataParamsEnc,
              PH_CRYPTOSYM_CIPHER_MODE_CBC | PH_EXCHANGE_BUFFER_CONT,
              &bCmdBuff[2],
              wTmp,
              &bCmdBuff[2]
          ));
      /* Update Cmd len */
      wCmdLen = wTmp + 2U;
    }

    (void)memset(pDataParams->bIv, 0x00, bIvLen);
    wWorkBufferLen = 0;
    bWorkBuffer[wWorkBufferLen++] = bCmdBuff[0];
    /* Add CmdCtr and TI for MAC calculation */
    bWorkBuffer[wWorkBufferLen++] = (uint8_t)(pDataParams->wCmdCtr);
    bWorkBuffer[wWorkBufferLen++] = (uint8_t)(pDataParams->wCmdCtr >> 8U);
    (void)memcpy(&bWorkBuffer[wWorkBufferLen], pDataParams->bTi, PHAL_MFDFEVX_SIZE_TI);
    wWorkBufferLen += PHAL_MFDFEVX_SIZE_TI;

    (void)memcpy(&bWorkBuffer[wWorkBufferLen], &bCmdBuff[1], (wCmdLen - 1u));
    wWorkBufferLen += (wCmdLen - 1u);

    /* Load Iv */
    PH_CHECK_SUCCESS_FCT(statusTmp, phCryptoSym_LoadIv(
            pDataParams->pCryptoDataParamsMac,
            pDataParams->bIv,
            bIvLen
        ));

    /* Append MAC */
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

    (void)memcpy(&bCmdBuff[wCmdLen], bCMAC, 8);
    wCmdLen += 8U;
  } else {
    /* ERROR: NOT_AUTHENTICATED */
    return PH_ADD_COMPCODE_FIXED(PH_ERR_AUTH_ERROR, PH_COMP_AL_MFDFEVX);
  }

  /* Set the dataparams with command code. */
  pDataParams->bCmdCode = PHAL_MFDFEVX_CMD_CHANGE_KEY;

  /* Send the command */
  statusTmp = phalMfdfEVx_ExchangeCmd(
          pDataParams,
          pDataParams->pPalMifareDataParams,
          pDataParams->bWrappedMode,
          bCmdBuff,
          wCmdLen,
          &pRecv,
          &wRxlen
      );
  if (statusTmp != PH_ERR_SUCCESS) {
    if (pDataParams->bAuthMode != PHAL_MFDFEVX_AUTHENTICATE) {
      phalMfdfEVx_Sw_Int_ResetAuthStatus(pDataParams);
    }
    return statusTmp;
  }

  /* Max 8 byte CMAC is expected nothing more. */
  if (wRxlen > 8U) {
    return PH_ADD_COMPCODE_FIXED(PH_ERR_PROTOCOL_ERROR, PH_COMP_AL_MFDFEVX);
  }

  (void)memcpy(bWorkBuffer, pRecv, wRxlen);

  /* Verification of MAC also required for AuthEV2
  */

  /* Verify the MAC */
  if ((pDataParams->bAuthMode == PHAL_MFDFEVX_AUTHENTICATEISO) ||
      (pDataParams->bAuthMode == PHAL_MFDFEVX_AUTHENTICATEAES)) {
    /* If Master key of the currently selected app is changed, the authentication
    is invalidated. So no CMAC is returned */
    if (wRxlen > 0U) {
      /* copy CMAC received from card */
      (void)memcpy(bCMacCard, &bWorkBuffer[wRxlen - 8U], 8);
      wRxlen -= 8u;

      PH_CHECK_SUCCESS_FCT(statusTmp, phCryptoSym_LoadIv(
              pDataParams->pCryptoDataParamsEnc,
              pDataParams->bIv,
              bIvLen
          ));

      bWorkBuffer[wRxlen] = 0x00; /* Status ok */

      /* Calculate CMAC */
      PH_CHECK_SUCCESS_FCT(statusTmp, phCryptoSym_CalculateMac(
              pDataParams->pCryptoDataParamsEnc,
              (PH_CRYPTOSYM_MAC_MODE_CMAC),
              bWorkBuffer,
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
    }

    /* Reset authentication status only if the key authenticated with
    *  is changed.
    */
    if ((pDataParams->bKeyNo & 0x3FU) == (bKeyNoCard & 0x3FU)) {
      phalMfdfEVx_Sw_Int_ResetAuthStatus(pDataParams);
    }
  } else if (pDataParams->bAuthMode == PHAL_MFDFEVX_AUTHENTICATEEV2) {
    /* reset authentication status if the key authenticated with is changed in
    * this case the card does not return a MAC because authentication is lost
    */
    if ((pDataParams->bKeyNo & 0x3FU) == (bKeyNoCard & 0x3FU)) {
      phalMfdfEVx_Sw_Int_ResetAuthStatus(pDataParams);
    } else {
      if (wRxlen < 8U) { /* If no CMAC received */
        return PH_ADD_COMPCODE_FIXED(PH_ERR_PROTOCOL_ERROR, PH_COMP_AL_MFDFEVX);
      }

      /* Increment the command counter. */
      pDataParams->wCmdCtr++;

      /* Load IV */
      PH_CHECK_SUCCESS_FCT(statusTmp, phCryptoSym_LoadIv(
              pDataParams->pCryptoDataParamsMac,
              pDataParams->bIv,
              bIvLen
          ));

      /* copy CMAC received from card*/
      (void)memcpy(bCMacCard, &bWorkBuffer[wRxlen - 8U], 8);
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
  } else if (pDataParams->bAuthMode == PHAL_MFDFEVX_AUTHENTICATE) {
    /* Reset authentication status only if the key authenticated with
    *  is changed.
    */
    if ((pDataParams->bKeyNo & 0x3FU) == (bKeyNoCard & 0x3FU)) {
      phalMfdfEVx_Sw_Int_ResetAuthStatus(pDataParams);
    }

  } else {
    /*Do Nothing. This is for PRQA compliance */
  }
  return PH_ERR_SUCCESS;
}

phStatus_t
phalMfdfEVx_Sw_ChangeKeyEv2(phalMfdfEVx_Sw_DataParams_t *pDataParams, uint16_t wOption,
    uint16_t wOldKeyNo,
    uint16_t wOldKeyVer, uint16_t wNewKeyNo, uint16_t wNewKeyVer, uint8_t bKeySetNo,
    uint8_t bKeyNoCard, uint8_t *pDivInput,
    uint8_t bDivLen)
{
  uint16_t    PH_MEMLOC_REM statusTmp;
  uint8_t     PH_MEMLOC_REM bCmdBuff[43];
  uint8_t     PH_MEMLOC_REM bWorkBuffer[43];
  uint8_t     PH_MEMLOC_REM bOldKey[32];
  uint8_t     PH_MEMLOC_REM bNewKey[32];
  uint8_t     PH_MEMLOC_REM bNewKeyLen = 0;
  uint8_t     PH_MEMLOC_REM bIndex;
  uint16_t    PH_MEMLOC_REM wRxlen = 0;
  uint16_t    PH_MEMLOC_REM wOldKeyType;
  uint16_t    PH_MEMLOC_REM wNewKeyType;
  uint16_t    PH_MEMLOC_REM wCmdLen = 0;
  uint8_t     PH_MEMLOC_REM bCMAC[PH_CRYPTOSYM_AES_BLOCK_SIZE];
  uint8_t     PH_MEMLOC_REM bCMacCard[8];
  uint8_t     PH_MEMLOC_REM bMacLen;
  uint8_t     PH_MEMLOC_REM bIvLen = 0;
  uint32_t    PH_MEMLOC_REM dwCrc;
  uint16_t    PH_MEMLOC_REM wCrc;
  uint16_t    PH_MEMLOC_REM wTmp;
  uint16_t    PH_MEMLOC_REM wTmpOption = 0x0000;
  uint8_t     PH_MEMLOC_REM bAppId[3] = { 0x00, 0x00, 0x00 };
  uint8_t    *PH_MEMLOC_REM pRecv = NULL;
  uint16_t    PH_MEMLOC_REM wWorkBufferLen = 0;

#ifdef RDR_LIB_PARAM_CHECK
  /* Change key should also take care of changing other keys at PICC level like
  * the Proximity check key,
  * VCA keys
  * Transaction MAC key
  *
  */
  if (memcmp(pDataParams->pAid, bAppId, 3) == 0x00) {
    /* PICC Master key */
    if (((bKeyNoCard & 0x3FU) != 0x00U) &&

        /* PICC DAMAuthKey, DAMMACKey, DAMEncKey */
        ((bKeyNoCard & 0x3FU) != 0x10U) && ((bKeyNoCard & 0x3FU) != 0x11U) &&
        ((bKeyNoCard & 0x3FU) != 0x12U) &&

        /* PICC NXPDAMAuthKey, NXPDAMMACKey, NXPDAMEncKey */
        ((bKeyNoCard & 0x3FU) != 0x18U) && ((bKeyNoCard & 0x3FU) != 0x19U) &&
        ((bKeyNoCard & 0x3FU) != 0x1AU) &&

        /* PICC VCConfigurationKey, VCProximityKey, VCSelectMACKey, VCSelectENCKey */
        ((bKeyNoCard & 0x3FU) != 0x20U) && ((bKeyNoCard & 0x3FU) != 0x21U) &&
        ((bKeyNoCard & 0x3FU) != 0x22U) && ((bKeyNoCard & 0x3FU) != 0x23U) &&

        /* MFCKillKey, MFCLicenseMACKey */
        ((bKeyNoCard & 0x3FU) != 0x31U) && ((bKeyNoCard & 0x3FU) != 0x32U)) {
      /* Invalid card key number supplied */
      return PH_ADD_COMPCODE_FIXED(PH_ERR_INVALID_PARAMETER, PH_COMP_AL_MFDFEVX);
    } else if (((bKeyNoCard & 0xC0U) != 0x80U) && ((bKeyNoCard & 0xC0U) != 0x40U) &&
        ((bKeyNoCard & 0xC0U) != 0x00U)) {
      /* Invalid card key number supplied */
      return PH_ADD_COMPCODE_FIXED(PH_ERR_INVALID_PARAMETER, PH_COMP_AL_MFDFEVX);
    } else {
      /*Do Nothing. This is for PRQA compliance */
    }
  } else {
    if ((bKeyNoCard & 0x7fU) > 0x0D
        && ((bKeyNoCard & 0x3FU) != 0x21U) && ((bKeyNoCard & 0x3FU) != 0x22U) &&
        ((bKeyNoCard & 0x3FU) != 0x23U)) {
      /* Invalid application key specified */
      return PH_ADD_COMPCODE_FIXED(PH_ERR_INVALID_PARAMETER, PH_COMP_AL_MFDFEVX);
    }
  }
  if (bKeySetNo > 0x0FU) {
    /* Invalid KeySetNo specified */
    return PH_ADD_COMPCODE_FIXED(PH_ERR_INVALID_PARAMETER, PH_COMP_AL_MFDFEVX);
  }
  if ((wOption == 0x0000U) || (bDivLen > 31U)) {
    return PH_ADD_COMPCODE_FIXED(PH_ERR_INVALID_PARAMETER, PH_COMP_AL_MFDFEVX);
  }
  if (pDataParams->bAuthMode == PHAL_MFDFEVX_NOT_AUTHENTICATED) {
    return PH_ADD_COMPCODE_FIXED(PH_ERR_USE_CONDITION, PH_COMP_AL_MFDFEVX);
  }
#endif
  (void)memset(bWorkBuffer, 0x00, 42);
  (void)memset(bCmdBuff, 0x00, 42);
  /* form the command */
  bCmdBuff[wCmdLen++] = PHAL_MFDFEVX_CMD_CHANGE_KEY_EV2;
  bCmdBuff[wCmdLen++] = bKeySetNo;
  bCmdBuff[wCmdLen++] = bKeyNoCard;

  if ((pDataParams->bAuthMode == PHAL_MFDFEVX_AUTHENTICATEAES) ||
      (pDataParams->bAuthMode == PHAL_MFDFEVX_AUTHENTICATEEV2)) {
    bIvLen = PH_CRYPTOSYM_AES_BLOCK_SIZE;
  } else {
    bIvLen = PH_CRYPTOSYM_DES_BLOCK_SIZE;
  }

  /* The IV will be different if AuthMode is AV2. Here the
  * ENC IV has to be computed and used for encryption.
  * The MAC IV is required to generate the MAC and append this to
  * the command before sending to the card.
  */

  if (pDataParams->bAuthMode == PHAL_MFDFEVX_AUTHENTICATEEV2) {
    /* the IV is constructed by encrypting with KeyID.SesAuthENCKey according to the ECB mode
    * As ECB encription doesnot use IV during the encription so we need not backup/ update with zero IV*/
    PH_CHECK_SUCCESS_FCT(statusTmp, phalMfdfEVx_Sw_Int_ComputeIv(
            PH_OFF,
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
  }
  /* Load Iv */
  PH_CHECK_SUCCESS_FCT(statusTmp, phCryptoSym_LoadIv(
          pDataParams->pCryptoDataParamsEnc,
          pDataParams->bIv,
          bIvLen
      ));

  PH_CHECK_SUCCESS_FCT(statusTmp, phKeyStore_GetKey(
          pDataParams->pKeyStoreDataParams,
          wOldKeyNo,
          wOldKeyVer,
          sizeof(bOldKey),
          bOldKey,
          &wOldKeyType
      ));

  PH_CHECK_SUCCESS_FCT(statusTmp, phKeyStore_GetKey(
          pDataParams->pKeyStoreDataParams,
          wNewKeyNo,
          wNewKeyVer,
          sizeof(bNewKey),
          bNewKey,
          &wNewKeyType
      ));

  if (wOldKeyType == PH_KEYSTORE_KEY_TYPE_DES) {
    wOldKeyType = PH_KEYSTORE_KEY_TYPE_2K3DES;
    (void)memcpy(&bOldKey[8], bOldKey, 8);
  }
  if (wNewKeyType == PH_KEYSTORE_KEY_TYPE_DES) {
    wNewKeyType = PH_KEYSTORE_KEY_TYPE_2K3DES;
    (void)memcpy(&bNewKey[8], bNewKey, 8);
  }
  /*
  It is allowed to change a key type for PICC master key.
  Old key may not be diversified but new key can be.
  Old key may be diversified with one round but new key can
  be diversified with two rounds.

  Key diversification method (DESFire or MFPlus) cannot be changed
  between old and new key.

  It is assumed that the diversification input specified is the same
  for both old key and new key
  */

  if ((wOption != PHAL_MFDFEVX_NO_DIVERSIFICATION) && (bDivLen != 0x00U)) {
    if (0U != (wOption & PHAL_MFDFEVX_CHGKEY_DIV_NEW_KEY)) {
      if (0U != (wOption & PHAL_MFDFEVX_CHGKEY_DIV_METHOD_CMAC)) {
        wTmpOption = PH_CRYPTOSYM_DIV_MODE_MIFARE_PLUS;
      } else {
        wTmpOption = PH_CRYPTOSYM_DIV_MODE_DESFIRE;
        if (0U != (wOption & PHAL_MFDFEVX_CHGKEY_DIV_NEW_KEY_ONERND)) {
          wTmpOption |= PH_CRYPTOSYM_DIV_OPTION_2K3DES_HALF;
        }
      }
      PH_CHECK_SUCCESS_FCT(statusTmp, phCryptoSym_DiversifyDirectKey(
              pDataParams->pCryptoDataParamsEnc,
              wTmpOption,
              bNewKey,
              wNewKeyType,
              pDivInput,
              bDivLen,
              bNewKey
          ));
    }
    if (0U != (wOption & PHAL_MFDFEVX_CHGKEY_DIV_OLD_KEY)) {
      if (0U != (wOption & PHAL_MFDFEVX_CHGKEY_DIV_METHOD_CMAC)) {
        wTmpOption |= PH_CRYPTOSYM_DIV_MODE_MIFARE_PLUS;
      } else {
        wTmpOption |= PH_CRYPTOSYM_DIV_MODE_DESFIRE;
        if (0U != (wOption & PHAL_MFDFEVX_CHGKEY_DIV_OLD_KEY_ONERND)) {
          wTmpOption |= PH_CRYPTOSYM_DIV_OPTION_2K3DES_HALF;
        }
      }
      PH_CHECK_SUCCESS_FCT(statusTmp, phCryptoSym_DiversifyDirectKey(
              pDataParams->pCryptoDataParamsEnc,
              wTmpOption,
              bOldKey,
              wOldKeyType,
              pDivInput,
              bDivLen,
              bOldKey
          ));
    }

    /* Reload the IV and key since the diversify function has invalidated the key */
    /* Load the Session key which is valid for this authentication */
    PH_CHECK_SUCCESS_FCT(statusTmp, phCryptoSym_LoadKeyDirect(
            pDataParams->pCryptoDataParamsEnc,
            pDataParams->bSesAuthENCKey,
            pDataParams->bCryptoMethod
        ));
    /* The IV will be different if AuthMode is AV2. Here the
    * ENC IV has to be computed and used for encryption.
    * The MAC IV is required to generate the MAC and append this to
    * the command before sending to the card.
    */
    if (pDataParams->bAuthMode == PHAL_MFDFEVX_AUTHENTICATEEV2) {
      /* the IV is constructed by encrypting with KeyID.SesAuthENCKey according to the ECB mode
      * As ECB encription doesnot use IV during the encription so we need not backup/ update with zero IV*/
      PH_CHECK_SUCCESS_FCT(statusTmp, phalMfdfEVx_Sw_Int_ComputeIv(
              PH_OFF,
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
    }
    /* Load Iv */
    PH_CHECK_SUCCESS_FCT(statusTmp, phCryptoSym_LoadIv(
            pDataParams->pCryptoDataParamsEnc,
            pDataParams->bIv,
            bIvLen
        ));

    /* Need to check whether this is required for 0x0A mode also*/
    PH_CHECK_SUCCESS_FCT(statusTmp, phCryptoSym_SetConfig(
            pDataParams->pCryptoDataParamsEnc,
            PH_CRYPTOSYM_CONFIG_KEEP_IV,
            PH_CRYPTOSYM_VALUE_KEEP_IV_ON
        ));
  }

  switch (wNewKeyType) {
    case PH_CRYPTOSYM_KEY_TYPE_AES128:
      bNewKeyLen = PH_CRYPTOSYM_AES128_KEY_SIZE;
      break;

    case PH_CRYPTOSYM_KEY_TYPE_2K3DES:
      bNewKeyLen = PH_CRYPTOSYM_2K3DES_KEY_SIZE;
      break;

    case PH_CRYPTOSYM_KEY_TYPE_3K3DES:
      bNewKeyLen = PH_CRYPTOSYM_3K3DES_KEY_SIZE;
      break;

    default:
      return PH_ADD_COMPCODE_FIXED(PH_ERR_KEY, PH_COMP_AL_MFDFEVX);
  }

  if (pDataParams->bAuthMode == PHAL_MFDFEVX_AUTHENTICATE) {
    /* bKeyNo for PICC masterkey will have key type in the two MS bits
    Should check for : bKeyNo & 3F != bKeyNoCard & 3F
    */
    if (((pDataParams->bKeyNo & 0x3FU) != (bKeyNoCard & 0x3FU)) ||
        ((memcmp(pDataParams->pAid, bAppId, 3) != 0) && (bKeySetNo != 0U))) {
      /* Get the key from the key store using wKeyNo and version */
      /* xored_Data = pNewKey ^ wKey */
      /* xored_Data + CRC16 (xord data) + CRC16(new key)+padding */
      /* Decrypt the above, Cmd+keyno+decrypted data is then sent to card */
      /* Get the key from the key store using wKeyNo and version */

      /* xored_Data = pNewKey ^ wKey */
      for (bIndex = 0; bIndex < bNewKeyLen; bIndex++) {
        bWorkBuffer[bIndex] = bOldKey[bIndex] ^ bNewKey[bIndex];
      }
      /* in AuthenticatedD40, targeting KeyType.AES->
      * (NewKey XOR OldKey)|| KeyVer || CRC16 || CRC16NK
      */
      if (wNewKeyType == PH_KEYSTORE_KEY_TYPE_AES128) {
        bWorkBuffer[bIndex++] = (uint8_t)wNewKeyVer;
      }

      /* Copy the XORd data to the command buffer */
      (void)memcpy(&bCmdBuff[3], bWorkBuffer, bIndex);
      wCmdLen = wCmdLen + bIndex;

      /* Calculate CRC16 over  Cmd|| KeyNo || (NewKey XOR OldKey)|| KeyVer*/
      PH_CHECK_SUCCESS_FCT(statusTmp, phTools_CalculateCrc16(
              PH_TOOLS_CRC_OPTION_DEFAULT,
              PH_TOOLS_CRC16_PRESET_ISO14443A,
              PH_TOOLS_CRC16_POLY_ISO14443,
              bWorkBuffer,
              bIndex,
              &wCrc
          ));

      /* Append CRC16 of the XORd data */
      (void)memcpy(&bCmdBuff[wCmdLen], &wCrc, 2);

      /* Update Cmd length */
      wCmdLen += 2U;

      /* Calculate CRC for the new key */
      PH_CHECK_SUCCESS_FCT(statusTmp, phTools_CalculateCrc16(
              PH_TOOLS_CRC_OPTION_DEFAULT,
              PH_TOOLS_CRC16_PRESET_ISO14443A,
              PH_TOOLS_CRC16_POLY_ISO14443,
              bNewKey,
              bNewKeyLen,
              &wCrc
          ));
      /* Add CRC16 */
      (void)memcpy(&bCmdBuff[wCmdLen], &wCrc, 2);
      wCmdLen += 2U; /* comm sett + access rights (2b) + 2B CRC */
    } else {
      (void)memcpy(&bCmdBuff[wCmdLen], bNewKey, bNewKeyLen);
      wCmdLen = wCmdLen + bNewKeyLen;
      /* Also check if it is PICC master key and is an AES key. If so then
      key version also needs to be appended to the new key before calculating
      CRC16 */
      if (((memcmp(pDataParams->pAid, bAppId, 3) == 0) && ((bKeyNoCard & 0xC0U) == 0x80U) &&
              ((bKeyNoCard & 0x3FU) == 0x00))
          || (wNewKeyType == PH_KEYSTORE_KEY_TYPE_AES128)) {
        /* PICC master key is being changed to AES key. Version is relevant */
        bCmdBuff[wCmdLen++] = (uint8_t)wNewKeyVer;
      }
      /* Calculate CRC for the new key and the key version if any */
      PH_CHECK_SUCCESS_FCT(statusTmp, phTools_CalculateCrc16(
              PH_TOOLS_CRC_OPTION_DEFAULT,
              PH_TOOLS_CRC16_PRESET_ISO14443A,
              PH_TOOLS_CRC16_POLY_ISO14443,
              &bCmdBuff[3],
              wCmdLen - 3u,
              &wCrc
          ));
      /* Add CRC16 */
      (void)memcpy(&bCmdBuff[wCmdLen], &wCrc, 2);
      wCmdLen += 2U; /* comm sett + access rights (2b) + 2B CRC */
    }

    /* Apply padding */
    wTmp = wCmdLen - 3u;
    if (0U != (wTmp % bIvLen)) {
      PH_CHECK_SUCCESS_FCT(statusTmp, phCryptoSym_ApplyPadding(
              PH_CRYPTOSYM_PADDING_MODE_1,
              &bCmdBuff[3],
              wTmp,
              bIvLen,
              sizeof(bWorkBuffer),
              bWorkBuffer,
              &wTmp
          ));
    }

    /* DF4 Decrypt */
    PH_CHECK_SUCCESS_FCT(statusTmp, phCryptoSym_Encrypt(
            pDataParams->pCryptoDataParamsEnc,
            PH_CRYPTOSYM_CIPHER_MODE_CBC_DF4 | PH_EXCHANGE_BUFFER_CONT,
            bWorkBuffer,
            wTmp,
            bWorkBuffer
        ));
    /* form the complete command */
    (void)memcpy(&bCmdBuff[3], bWorkBuffer, wTmp);

    /* Update Cmd len */
    wCmdLen = wTmp + 3U;
  } else if ((pDataParams->bAuthMode == PHAL_MFDFEVX_AUTHENTICATEAES) ||
      (pDataParams->bAuthMode == PHAL_MFDFEVX_AUTHENTICATEISO)) {
    if (((pDataParams->bKeyNo & 0x3FU) != (bKeyNoCard & 0x3FU)) ||
        ((memcmp(pDataParams->pAid, bAppId, 3) != 0U) && (bKeySetNo != 0U))) {
      /* xored_Data = pNewKey ^ wKey */
      for (bIndex = 0; bIndex < bNewKeyLen; bIndex++) {
        bWorkBuffer[bIndex] = bOldKey[bIndex] ^ bNewKey[bIndex];
      }
      /* if targeting KeyType.AES->
      * (NewKey XOR OldKey)|| KeyVer || CRC16 || CRC16NK
      */
      if (wNewKeyType == PH_KEYSTORE_KEY_TYPE_AES128) {
        bWorkBuffer[bIndex++] = (uint8_t)wNewKeyVer;
      }
      (void)memcpy(&bCmdBuff[3], bWorkBuffer, bIndex);
      wCmdLen = wCmdLen + bIndex;

      /* Calculate CRC32 over cmd+header+XORddata+[keyversion] */
      PH_CHECK_SUCCESS_FCT(statusTmp, phTools_CalculateCrc32(
              PH_TOOLS_CRC_OPTION_DEFAULT,
              PH_TOOLS_CRC32_PRESET_DF8,
              PH_TOOLS_CRC32_POLY_DF8,
              bCmdBuff,
              wCmdLen,
              &dwCrc
          ));

      (void)memcpy(&bCmdBuff[wCmdLen], &dwCrc, 4);
      wCmdLen += 4U;

      /* Calculate CRC32 over the new key  */
      PH_CHECK_SUCCESS_FCT(statusTmp, phTools_CalculateCrc32(
              PH_TOOLS_CRC_OPTION_DEFAULT,
              PH_TOOLS_CRC32_PRESET_DF8,
              PH_TOOLS_CRC32_POLY_DF8,
              bNewKey,
              bNewKeyLen,
              &dwCrc
          ));
      (void)memcpy(&bCmdBuff[wCmdLen], &dwCrc, 4);
      wCmdLen += 4U;

      wTmp = wCmdLen - 3u;
      if (0U != (wTmp % bIvLen)) {
        /* Apply padding */
        PH_CHECK_SUCCESS_FCT(statusTmp, phCryptoSym_ApplyPadding(
                PH_CRYPTOSYM_PADDING_MODE_1,
                &bCmdBuff[3],
                wTmp,
                bIvLen,
                sizeof(bCmdBuff) - 3,
                &bCmdBuff[3],
                &wTmp
            ));
      }

      /* Encrypt */
      PH_CHECK_SUCCESS_FCT(statusTmp, phCryptoSym_Encrypt(
              pDataParams->pCryptoDataParamsEnc,
              PH_CRYPTOSYM_CIPHER_MODE_CBC | PH_EXCHANGE_BUFFER_CONT,
              &bCmdBuff[3],
              wTmp,
              &bCmdBuff[3]
          ));
      wCmdLen = wTmp + 3U;
    } else {
      (void)memcpy(&bCmdBuff[wCmdLen], bNewKey, bNewKeyLen);
      wCmdLen = wCmdLen + bNewKeyLen;

      /* Also check if it is PICC master key and is an AES key is to be written.
      If so then key version also needs to be appended to the new key before
      calculating CRC */
      if (((memcmp(pDataParams->pAid, bAppId, 3) == 0) && ((bKeyNoCard & 0xC0U) == 0x80U) &&
              ((bKeyNoCard & 0x3FU) == 0x00))
          || (wNewKeyType == PH_KEYSTORE_KEY_TYPE_AES128)) {
        /* PICC master key is being changed to AES key. Version is relevant */
        bCmdBuff[wCmdLen++] = (uint8_t)wNewKeyVer;
      }

      /*  Calculate CRC32 on the Key data */
      PH_CHECK_SUCCESS_FCT(statusTmp, phTools_CalculateCrc32(
              PH_TOOLS_CRC_OPTION_DEFAULT,
              PH_TOOLS_CRC32_PRESET_DF8,
              PH_TOOLS_CRC32_POLY_DF8,
              bCmdBuff,
              wCmdLen,
              &dwCrc
          ));

      /* Add CRC32 */
      (void)memcpy(&bCmdBuff[wCmdLen], &dwCrc, 4);
      wCmdLen += 4U; /* comm sett + access rights (2b) + 4B CRC */

      wTmp = wCmdLen - 3u;
      /* Apply padding */
      PH_CHECK_SUCCESS_FCT(statusTmp, phCryptoSym_ApplyPadding(
              PH_CRYPTOSYM_PADDING_MODE_1,
              &bCmdBuff[3],
              wTmp,
              bIvLen,
              sizeof(bCmdBuff) - 3,
              &bCmdBuff[3],
              &wTmp
          ));

      /* Encrypt */
      PH_CHECK_SUCCESS_FCT(statusTmp, phCryptoSym_Encrypt(
              pDataParams->pCryptoDataParamsEnc,
              PH_CRYPTOSYM_CIPHER_MODE_CBC | PH_EXCHANGE_BUFFER_CONT,
              &bCmdBuff[3],
              wTmp,
              &bCmdBuff[3]
          ));
      /* Update Cmd len */
      wCmdLen = wTmp + 3U;
    }

    /* Update IV */
    (void)memcpy(pDataParams->bIv, &bCmdBuff[wCmdLen - bIvLen], bIvLen);
  }
  /* Need new else if statement for AuthEV2
  * In AuthEV2, it is sent in FULL mode, meaning the Data is encrypted
  * and a MAC is calculated and attached at the end.
  * ENC Session key is used for encryption and MAC session key is
  * used for MAC calculation
  */
  else if (pDataParams->bAuthMode == PHAL_MFDFEVX_AUTHENTICATEEV2) {
    if (((pDataParams->bKeyNo & 0x3FU) != (bKeyNoCard & 0x3FU)) ||
        ((memcmp(pDataParams->pAid, bAppId, 3) != 0) && (bKeySetNo != 0U))) {
      /* Copy bNewKey to the bWorkBuffer */
      for (bIndex = 0; bIndex < bNewKeyLen; bIndex++) {
        bWorkBuffer[bIndex] = bNewKey[bIndex];
      }

      /* Append Key Version */
      bWorkBuffer[bIndex++] = (uint8_t)wNewKeyVer;

      /* Calculate CRC32 over the new key  ie CRC32NK shall be the 4-byte CRC value taken over NewKey */
      PH_CHECK_SUCCESS_FCT(statusTmp, phTools_CalculateCrc32(
              PH_TOOLS_CRC_OPTION_DEFAULT,
              PH_TOOLS_CRC32_PRESET_DF8,
              PH_TOOLS_CRC32_POLY_DF8,
              bWorkBuffer,
              (uint16_t)bIndex - 1,
              &dwCrc
          ));

      /* Key number authenticated with is not the key to be
      * changed
      * xored_Data = pNewKey ^ wKey
      * bWorkBuffer contains pNewKey
      */
      for (bIndex = 0; bIndex < bNewKeyLen; bIndex++) {
        bWorkBuffer[bIndex] = bOldKey[bIndex] ^ bWorkBuffer[bIndex];
      }
      /* xored_Data+ [AES key version] + CRC32 (all prev. data) + CRC32(new key)+padding */
      /* Adding key version should always be true because we are only dealing with
      * AES128 keys here
      */
      bIndex++;   /* Just increment bIndex because it already contains wNewKeyVer */
      (void)memcpy(&bCmdBuff[3], bWorkBuffer, bIndex);
      wCmdLen = wCmdLen + bIndex;

      (void)memcpy(&bCmdBuff[wCmdLen], &dwCrc, 4);
      wCmdLen += 4U;

      wTmp = wCmdLen - 3u;
      if (0U != (wTmp % bIvLen)) {
        /* Apply padding */
        PH_CHECK_SUCCESS_FCT(statusTmp, phCryptoSym_ApplyPadding(
                PH_CRYPTOSYM_PADDING_MODE_2,
                &bCmdBuff[3],
                wTmp,
                bIvLen,
                sizeof(bCmdBuff) - 3,
                &bCmdBuff[3],
                &wTmp
            ));
      }

      /* Encrypt */
      PH_CHECK_SUCCESS_FCT(statusTmp, phCryptoSym_Encrypt(
              pDataParams->pCryptoDataParamsEnc,
              PH_CRYPTOSYM_CIPHER_MODE_CBC | PH_EXCHANGE_BUFFER_CONT,
              &bCmdBuff[3],
              wTmp,
              &bCmdBuff[3]
          ));
      wCmdLen = wTmp + 3U;
    } else {
      (void)memcpy(&bCmdBuff[wCmdLen], bNewKey, bNewKeyLen);
      wCmdLen = wCmdLen + bNewKeyLen;

      /* Also check if it is PICC master key and is an AES key is to be written.
      If so then key version also needs to be appended to the new key before
      calculating CRC */
      if (((memcmp(pDataParams->pAid, bAppId, 3) == 0) && ((bKeyNoCard & 0xC0U) == 0x80U) &&
              ((bKeyNoCard & 0x3FU) == 0x00))
          || (wNewKeyType == PH_KEYSTORE_KEY_TYPE_AES128)) {
        bCmdBuff[wCmdLen++] = (uint8_t)wNewKeyVer;
      }

      wTmp = wCmdLen - 3u;
      /* Apply padding */
      PH_CHECK_SUCCESS_FCT(statusTmp, phCryptoSym_ApplyPadding(
              PH_CRYPTOSYM_PADDING_MODE_2,
              &bCmdBuff[3],
              wTmp,
              bIvLen,
              sizeof(bCmdBuff) - 3,
              &bCmdBuff[3],
              &wTmp
          ));

      /* Encrypt */
      PH_CHECK_SUCCESS_FCT(statusTmp, phCryptoSym_Encrypt(
              pDataParams->pCryptoDataParamsEnc,
              PH_CRYPTOSYM_CIPHER_MODE_CBC | PH_EXCHANGE_BUFFER_CONT,
              &bCmdBuff[3],
              wTmp,
              &bCmdBuff[3]
          ));
      /* Update Cmd len */
      wCmdLen = wTmp + 3U;
    }

    (void)memset(pDataParams->bIv, 0x00, bIvLen);
    wWorkBufferLen = 0;
    bWorkBuffer[wWorkBufferLen++] = bCmdBuff[0];
    /* Add CmdCtr and TI for MAC calculation */
    bWorkBuffer[wWorkBufferLen++] = (uint8_t)(pDataParams->wCmdCtr);
    bWorkBuffer[wWorkBufferLen++] = (uint8_t)(pDataParams->wCmdCtr >> 8U);
    (void)memcpy(&bWorkBuffer[wWorkBufferLen], pDataParams->bTi, PHAL_MFDFEVX_SIZE_TI);
    wWorkBufferLen += PHAL_MFDFEVX_SIZE_TI;

    (void)memcpy(&bWorkBuffer[wWorkBufferLen], &bCmdBuff[1], (wCmdLen - 1u));
    wWorkBufferLen += (wCmdLen - 1u);

    /* Load Iv */
    PH_CHECK_SUCCESS_FCT(statusTmp, phCryptoSym_LoadIv(
            pDataParams->pCryptoDataParamsMac,
            pDataParams->bIv,
            bIvLen
        ));

    /* Append MAC */
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

    /* Copy truncated MAC to CmdBuff */
    (void)memcpy(&bCmdBuff[wCmdLen], bCMAC, 8);
    wCmdLen += 8U;
  } else {
    /* ERROR: NOT_AUTHENTICATED */
    return PH_ADD_COMPCODE_FIXED(PH_ERR_AUTH_ERROR, PH_COMP_AL_MFDFEVX);
  }

  /* Set the dataparams with command code. */
  pDataParams->bCmdCode = PHAL_MFDFEVX_CMD_CHANGE_KEY_EV2;

  /* Send the command */
  statusTmp = phalMfdfEVx_ExchangeCmd(
          pDataParams,
          pDataParams->pPalMifareDataParams,
          pDataParams->bWrappedMode,
          bCmdBuff,
          wCmdLen,
          &pRecv,
          &wRxlen
      );
  if (statusTmp != PH_ERR_SUCCESS) {
    if (pDataParams->bAuthMode != PHAL_MFDFEVX_AUTHENTICATE) {
      phalMfdfEVx_Sw_Int_ResetAuthStatus(pDataParams);
    }
    return statusTmp;
  }

  /* Max 8 byte CMAC is expected nothing more. */
  if (wRxlen > 8U) {
    return PH_ADD_COMPCODE_FIXED(PH_ERR_PROTOCOL_ERROR, PH_COMP_AL_MFDFEVX);
  }

  (void)memcpy(bWorkBuffer, pRecv, wRxlen);

  /* Verification of MAC also required for AuthEV2
  */

  /* Verify the MAC */
  if ((pDataParams->bAuthMode == PHAL_MFDFEVX_AUTHENTICATEISO) ||
      (pDataParams->bAuthMode == PHAL_MFDFEVX_AUTHENTICATEAES)) {
    /* If Master key of the currently selected app is changed, the authentication
    is invalidated. So no CMAC is returned */
    if (wRxlen > 0U) {
      /* copy CMAC received from card */
      (void)memcpy(bCMacCard, &bWorkBuffer[wRxlen - 8u], 8);
      wRxlen -= 8u;

      PH_CHECK_SUCCESS_FCT(statusTmp, phCryptoSym_LoadIv(
              pDataParams->pCryptoDataParamsEnc,
              pDataParams->bIv,
              bIvLen
          ));

      bWorkBuffer[wRxlen] = 0x00; /* Status ok */

      /* Calculate CMAC */
      PH_CHECK_SUCCESS_FCT(statusTmp, phCryptoSym_CalculateMac(
              pDataParams->pCryptoDataParamsEnc,
              (PH_CRYPTOSYM_MAC_MODE_CMAC),
              bWorkBuffer,
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
    }

    /* Reset authentication status only if the key authenticated with
    *  is changed.
    */
    if (((pDataParams->bKeyNo & 0x3FU) == (bKeyNoCard & 0x3FU)) && ((bKeySetNo & 0x0FU) == 0U)) {
      phalMfdfEVx_Sw_Int_ResetAuthStatus(pDataParams);
    }
  } else if (pDataParams->bAuthMode == PHAL_MFDFEVX_AUTHENTICATEEV2) {

    /* reset authentication status if the key authenticated with is changed in
    * this case the card does not return a MAC because authentication is lost
    */
    if (((pDataParams->bKeyNo & 0x3FU) == (bKeyNoCard & 0x3FU)) && ((bKeySetNo & 0x0FU) == 0U)) {
      phalMfdfEVx_Sw_Int_ResetAuthStatus(pDataParams);
    } else {

      if (wRxlen < 8U) { /* If no CMAC received */

        return PH_ADD_COMPCODE_FIXED(PH_ERR_PROTOCOL_ERROR, PH_COMP_AL_MFDFEVX);
      }

      /* Increment the command counter. */
      pDataParams->wCmdCtr++;

      /* Load IV */
      PH_CHECK_SUCCESS_FCT(statusTmp, phCryptoSym_LoadIv(
              pDataParams->pCryptoDataParamsMac,
              pDataParams->bIv,
              bIvLen
          ));

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
  } else {
    /*Do Nothing. This is for PRQA compliance */
  }
  return PH_ERR_SUCCESS;
}

phStatus_t
phalMfdfEVx_Sw_InitializeKeySet(phalMfdfEVx_Sw_DataParams_t *pDataParams,
    uint8_t bKeySetNo, uint8_t bKeyType)
{
  uint8_t     PH_MEMLOC_REM bCmdBuff[2];
  uint8_t     PH_MEMLOC_REM bDataBuff[3];

#ifdef RDR_LIB_PARAM_CHECK
  if (((bKeySetNo & 0x7fU) > 0x0fU) || (bKeyType > PHAL_MFDFEVX_KEY_TYPE_AES128)) {
    return PH_ADD_COMPCODE_FIXED(PH_ERR_INVALID_PARAMETER, PH_COMP_AL_MFDFEVX);
  }
#endif

  /* Set the dataparams with command code. */
  pDataParams->bCmdCode = PHAL_MFDFEVX_CMD_INITIALIZE_KEY_SET;

  /* Form the command */
  bCmdBuff[0] = PHAL_MFDFEVX_CMD_INITIALIZE_KEY_SET;
  bDataBuff[0] = bKeySetNo;
  bDataBuff[1] = bKeyType;

  return phalMfdfEVx_Sw_Int_Write_Plain(
          pDataParams,
          PHAL_MFDFEVX_DEFAULT_MODE,
          bCmdBuff,
          1,
          (pDataParams->bAuthMode == PHAL_MFDFEVX_AUTHENTICATE) ? PHAL_MFDFEVX_COMMUNICATION_PLAIN :
          PHAL_MFDFEVX_COMMUNICATION_MACD,
          bDataBuff,
          2
      );
}

phStatus_t
phalMfdfEVx_Sw_FinalizeKeySet(phalMfdfEVx_Sw_DataParams_t *pDataParams,
    uint8_t bKeySetNo, uint8_t bKeySetVersion)
{
  uint8_t     PH_MEMLOC_REM bCmdBuff[2];
  uint8_t     PH_MEMLOC_REM bDataBuff[3];

#ifdef RDR_LIB_PARAM_CHECK
  if ((bKeySetNo & 0x7fU) > 0x0fU) {
    return PH_ADD_COMPCODE_FIXED(PH_ERR_INVALID_PARAMETER, PH_COMP_AL_MFDFEVX);
  }
#endif

  /* Set the dataparams with command code. */
  pDataParams->bCmdCode = PHAL_MFDFEVX_CMD_FINALIZE_KEY_SET;

  /* Form the command */
  bCmdBuff[0] = PHAL_MFDFEVX_CMD_FINALIZE_KEY_SET;
  bDataBuff[0] = bKeySetNo;
  bDataBuff[1] = bKeySetVersion;

  return phalMfdfEVx_Sw_Int_Write_Plain(
          pDataParams,
          PHAL_MFDFEVX_DEFAULT_MODE,
          bCmdBuff,
          1,
          (pDataParams->bAuthMode == PHAL_MFDFEVX_AUTHENTICATE) ? PHAL_MFDFEVX_COMMUNICATION_PLAIN :
          PHAL_MFDFEVX_COMMUNICATION_MACD,
          bDataBuff,
          2
      );
}

phStatus_t
phalMfdfEVx_Sw_RollKeySet(phalMfdfEVx_Sw_DataParams_t *pDataParams, uint8_t bKeySetNo)
{
  uint8_t     PH_MEMLOC_REM bCmdBuff[2];
  uint8_t     PH_MEMLOC_REM bDataBuff[2];

#ifdef RDR_LIB_PARAM_CHECK
  if ((bKeySetNo & 0x7FU) > 0x0FU) {
    return PH_ADD_COMPCODE_FIXED(PH_ERR_INVALID_PARAMETER, PH_COMP_AL_MFDFEVX);
  }
#endif

  /* Set the dataparams with command code. */
  pDataParams->bCmdCode = PHAL_MFDFEVX_CMD_ROLL_KEY_SET;

  /* Form the command */
  bCmdBuff[0] = PHAL_MFDFEVX_CMD_ROLL_KEY_SET;
  bDataBuff[0] = bKeySetNo;

  return phalMfdfEVx_Sw_Int_Write_Plain(
          pDataParams,
          PHAL_MFDFEVX_DEFAULT_MODE,
          bCmdBuff,
          1,
          (pDataParams->bAuthMode == PHAL_MFDFEVX_AUTHENTICATE) ? (PHAL_MFDFEVX_AUTHENTICATE_RESET |
              PHAL_MFDFEVX_COMMUNICATION_PLAIN) : (PHAL_MFDFEVX_AUTHENTICATE_RESET |
              PHAL_MFDFEVX_COMMUNICATION_MACD),
          bDataBuff,
          1
      );
}
#endif /* NXPBUILD__PHAL_MFDFEVX_NDA */

phStatus_t
phalMfdfEVx_Sw_GetKeySettings(phalMfdfEVx_Sw_DataParams_t *pDataParams,
    uint8_t *pKeySettings,
    uint8_t *bRespLen)
{
  /**
  * This command can be issued without valid authentication
  */
  uint16_t    PH_MEMLOC_REM statusTmp;
  uint8_t     PH_MEMLOC_REM bCmdBuff[8];
  uint16_t    PH_MEMLOC_REM wRxlen = 0;
  uint8_t     PH_MEMLOC_REM *pRecv = NULL;

  /* Set the dataparams with command code. */
  pDataParams->bCmdCode = PHAL_MFDFEVX_CMD_GET_KEY_SETTINGS;

  /* form the command */
  bCmdBuff[0] = PHAL_MFDFEVX_CMD_GET_KEY_SETTINGS;

  PH_CHECK_SUCCESS_FCT(statusTmp, phalMfdfEVx_Sw_Int_ReadData_Plain(
          pDataParams,
          (pDataParams->bAuthMode == PHAL_MFDFEVX_AUTHENTICATEEV2) ? PHAL_MFDFEVX_COMMUNICATION_MACD :
          PHAL_MFDFEVX_COMMUNICATION_PLAIN,
          bCmdBuff,
          1,
          &pRecv,
          &wRxlen
      ));

  if ((wRxlen != 0x02U) && (wRxlen != 0x06U)) {
    return PH_ADD_COMPCODE_FIXED(PH_ERR_PROTOCOL_ERROR, PH_COMP_AL_MFDFEVX);
  }
  (void)memcpy(pKeySettings, pRecv, wRxlen);
  *bRespLen = (uint8_t) wRxlen;

  return PH_ERR_SUCCESS;
}

#ifdef NXPBUILD__PHAL_MFDFEVX_NDA
phStatus_t
phalMfdfEVx_Sw_ChangeKeySettings(phalMfdfEVx_Sw_DataParams_t *pDataParams,
    uint8_t bKeySettings)
{
  /**
  * This  function will handle all the three authentication modes: 0x0A, 1A and AA.
  * and all crypto modes i.e., DES, 3DES, 3K3DES, AES
  * The previous authentication status including key number and session key is
  * present in the params  structure.
  * Successful auth. with PICC master key is required if AID = 0x00 else
  * an auth. with the application master key is required.
  */
  uint8_t     PH_MEMLOC_REM bCmdBuff[8];

  /* Set the dataparams with command code. */
  pDataParams->bCmdCode = PHAL_MFDFEVX_CMD_CHANGE_KEY_SETTINGS;

  /* form the command */
  bCmdBuff[0] = PHAL_MFDFEVX_CMD_CHANGE_KEY_SETTINGS;
  bCmdBuff[1] = bKeySettings;

  /* COMMUNICATION IS Encrypted */
  return phalMfdfEVx_Sw_Int_Write_Enc(pDataParams,
          PHAL_MFDFEVX_DEFAULT_MODE,
          bCmdBuff,
          0x0001,
          PH_CRYPTOSYM_PADDING_MODE_1,
          0x00,
          &bCmdBuff[1],
          0x0001
      );
}

phStatus_t
phalMfdfEVx_Sw_GetKeyVersion(phalMfdfEVx_Sw_DataParams_t *pDataParams, uint8_t bKeyNo,
    uint8_t bKeySetNo,
    uint8_t *pKeyVersion, uint8_t *bRxLen)
{
  /**
  * This command can be issued without valid authentication
  */
  uint16_t    PH_MEMLOC_REM statusTmp;
  uint8_t     PH_MEMLOC_REM bCmdBuff[20];
  uint16_t    PH_MEMLOC_REM wCmdLen = 0;
  uint16_t    PH_MEMLOC_REM wRxlen = 0;
  uint8_t     PH_MEMLOC_REM *pRecv = NULL;
#ifdef RDR_LIB_PARAM_CHECK
  uint8_t     PH_MEMLOC_REM bAppId[3] = { 0x00, 0x00, 0x00 };
#endif

#ifdef RDR_LIB_PARAM_CHECK
  if (memcmp(pDataParams->pAid, bAppId, 3) && ((bKeyNo & 0x0fU) > 0x0dU)) {
    return PH_ADD_COMPCODE_FIXED(PH_ERR_INVALID_PARAMETER, PH_COMP_AL_MFDFEVX);
  }
#endif

  /* Set the dataparams with command code. */
  pDataParams->bCmdCode = PHAL_MFDFEVX_CMD_GET_KEY_VERSION;

  /* form the command */
  bCmdBuff[wCmdLen++] = PHAL_MFDFEVX_CMD_GET_KEY_VERSION;
  bCmdBuff[wCmdLen++] = bKeyNo;

  /* Check for bit[6] of bKeyNo.
  * if set then pass bKeySetNo in the command buffer as per ref arch.v15 */
  if (0U != (bKeyNo & PHAL_MFDFEVX_KEYSETVERSIONS)) {
    bCmdBuff[wCmdLen++] = bKeySetNo;
  }

  PH_CHECK_SUCCESS_FCT(statusTmp, phalMfdfEVx_Sw_Int_ReadData_Plain(
          pDataParams,
          (pDataParams->bAuthMode == PHAL_MFDFEVX_AUTHENTICATEEV2) ? PHAL_MFDFEVX_COMMUNICATION_MACD :
          PHAL_MFDFEVX_COMMUNICATION_PLAIN,
          bCmdBuff,
          wCmdLen,
          &pRecv,
          &wRxlen
      ));

  /*
  * If Key set version retrieval (KeySetNo[b7] is set), then expected wRxlen can be upto 16 bytes(KeySet version ranges between 2 to 16)
  * Else the wRxlen should be equal to 1(1 byte of KeyVer).
  */
  if (((wRxlen != 0x01U) && ((0U == ((bKeyNo & PHAL_MFDFEVX_KEYSETVERSIONS))))) ||
      ((wRxlen > 16U) && (0U != ((bKeyNo & PHAL_MFDFEVX_KEYSETVERSIONS))))) {
    return PH_ADD_COMPCODE_FIXED(PH_ERR_PROTOCOL_ERROR, PH_COMP_AL_MFDFEVX);
  }
  /* If bit[7] of bKeySetNo is set, then wRxLen must not be equal to 0x01 */
  if ((0U != ((bKeySetNo & 0x80U))) && (wRxlen == 0x01U)) {
    return PH_ADD_COMPCODE_FIXED(PH_ERR_PROTOCOL_ERROR, PH_COMP_AL_MFDFEVX);
  }

  if (memcpy(pKeyVersion, pRecv, wRxlen) == NULL) {
    return PH_ADD_COMPCODE_FIXED(PH_ERR_INTERNAL_ERROR, PH_COMP_AL_MFDFEVX);
  }

  *bRxLen = (uint8_t) wRxlen;

  return PH_ERR_SUCCESS;
}
#endif /* NXPBUILD__PHAL_MFDFEVX_NDA */

/* MIFARE DESFire EVx Application mamangement commands. -------------------------------------------------------------------------------- */
phStatus_t
phalMfdfEVx_Sw_CreateApplication(phalMfdfEVx_Sw_DataParams_t *pDataParams,
    uint8_t bOption, uint8_t *pAid,
    uint8_t bKeySettings1, uint8_t bKeySettings2, uint8_t bKeySettings3, uint8_t *pKeySetValues,
    uint8_t *pISOFileId,
    uint8_t *pISODFName, uint8_t bISODFNameLen)
{
  /*
  If (bKeySettings2 & 0x03)== 00 [DES, 3DES] then pDataParams->bAuthMode can be either
  0x0A or 0x1A.
  If (bKeySettings2 & 0x03)== 01 [3K3DES] then pDataParams->bAuthMode can only be 0x1A.
  If (bKeySettings2 & 0x03)== 10 [AES] then pDataParams->bAuthMode can be 0xAA or AuthEVx.
  */
  uint8_t     PH_MEMLOC_REM bCmdBuff[33];
  uint16_t    PH_MEMLOC_REM wCmdLen = 0;

#ifdef RDR_LIB_PARAM_CHECK
  if ((bISODFNameLen > 16U) || (bOption > 0x03U) || (bOption == 0x02U)) {
    return PH_ADD_COMPCODE_FIXED(PH_ERR_INVALID_PARAMETER, PH_COMP_AL_MFDFEVX);
  }
#endif

  /* Set the dataparams with command code. */
  pDataParams->bCmdCode = PHAL_MFDFEVX_CMD_CREATE_APPLN;

  /* form the command */
  bCmdBuff[wCmdLen++] = PHAL_MFDFEVX_CMD_CREATE_APPLN;

  (void)memcpy(&bCmdBuff[wCmdLen], pAid, 3);
  wCmdLen += 3U;

  bCmdBuff[wCmdLen++] = bKeySettings1;
  bCmdBuff[wCmdLen++] = bKeySettings2;

  if (0U != (bKeySettings2 & PHAL_MFDFEVX_KEYSETT3_PRESENT)) {
    bCmdBuff[wCmdLen++] = bKeySettings3;
    if ((bKeySettings3 & PHAL_MFDFEVX_KEYSETVALUES_PRESENT) && (pKeySetValues != NULL)) {
      /* KeySet Values */
      (void)memcpy(&bCmdBuff[wCmdLen], pKeySetValues, 4);
      wCmdLen += 4U;
    }
  }
  if (0U != (bOption & 0x01U)) {
    /* pISOFileId is present */
    bCmdBuff[wCmdLen++] = pISOFileId[0];
    bCmdBuff[wCmdLen++] = pISOFileId[1];
  }
  if (0U != (bOption & 0x02U)) {
    /* pISODFName is present */
    (void)memcpy(&bCmdBuff[wCmdLen], pISODFName, bISODFNameLen);
    wCmdLen = wCmdLen + bISODFNameLen;
  }

  return phalMfdfEVx_Sw_Int_Write_Plain(
          pDataParams,
          PHAL_MFDFEVX_DEFAULT_MODE,
          bCmdBuff,
          wCmdLen,
          (pDataParams->bAuthMode == PHAL_MFDFEVX_AUTHENTICATEEV2) ? PHAL_MFDFEVX_COMMUNICATION_MACD :
          PHAL_MFDFEVX_COMMUNICATION_PLAIN,
          NULL,
          0x0000
      );
}

phStatus_t
phalMfdfEVx_Sw_DeleteApplication(phalMfdfEVx_Sw_DataParams_t *pDataParams,
    uint8_t *pAid, uint8_t *pDAMMAC, uint8_t bDAMMAC_Len)
{
  uint8_t     PH_MEMLOC_REM bCmdBuff[20];
  uint16_t    PH_MEMLOC_REM wCmdLen = 0;

  /* Set the dataparams with command code. */
  pDataParams->bCmdCode = PHAL_MFDFEVX_CMD_DELETE_APPLN;

  /* form the command */
  bCmdBuff[wCmdLen++] = PHAL_MFDFEVX_CMD_DELETE_APPLN;
  (void)memcpy(&bCmdBuff[wCmdLen], pAid, PHAL_MFDFEVX_DFAPPID_SIZE);
  wCmdLen += PHAL_MFDFEVX_DFAPPID_SIZE;

  /* Append the DAMMAC */
  if (bDAMMAC_Len) {
    (void)memcpy(&bCmdBuff[wCmdLen], pDAMMAC, bDAMMAC_Len);
    wCmdLen += bDAMMAC_Len;
  }

  return phalMfdfEVx_Sw_Int_Write_Plain(
          pDataParams,
          PHAL_MFDFEVX_DEFAULT_MODE,
          bCmdBuff,
          wCmdLen,
          (pDataParams->bAuthMode == PHAL_MFDFEVX_AUTHENTICATEEV2) ? PHAL_MFDFEVX_COMMUNICATION_MACD :
          PHAL_MFDFEVX_COMMUNICATION_PLAIN,
          NULL,
          0x0000
      );
}

phStatus_t
phalMfdfEVx_Sw_CreateDelegatedApplication(phalMfdfEVx_Sw_DataParams_t *pDataParams,
    uint8_t bOption, uint8_t *pAid,
    uint8_t *pDamParams, uint8_t bKeySettings1, uint8_t bKeySettings2, uint8_t bKeySettings3,
    uint8_t  *bKeySetValues,
    uint8_t *pISOFileId, uint8_t *pISODFName, uint8_t bISODFNameLen, uint8_t *pEncK, uint8_t *pDAMMAC)
{
  phStatus_t  PH_MEMLOC_REM status;
  uint8_t     PH_MEMLOC_REM bCmdBuff[43];
  uint16_t    PH_MEMLOC_REM wCmdLen = 0;

#ifdef RDR_LIB_PARAM_CHECK
  if ((bISODFNameLen > 16U) || (bOption > 0x03U) || (bOption == 0x02U)) {
    return PH_ADD_COMPCODE_FIXED(PH_ERR_INVALID_PARAMETER, PH_COMP_AL_MFDFEVX);
  }
#endif

  /* Set the dataparams with command code. */
  pDataParams->bCmdCode = PHAL_MFDFEVX_CMD_CREATE_DELEGATED_APPLN;

  /* form the command */
  bCmdBuff[wCmdLen++] = PHAL_MFDFEVX_CMD_CREATE_DELEGATED_APPLN;

  /* Copy AID */
  (void)memcpy(&bCmdBuff[wCmdLen], pAid, 3);
  wCmdLen += 3U;

  /* Copy DAMSlotNo || DAMSlotVersion || QuotaLimit
   *  Size of DAMSlotNo is changed to 2 byte
   */
  (void)memcpy(&bCmdBuff[wCmdLen], pDamParams, 5);
  wCmdLen += 5U;

  bCmdBuff[wCmdLen++] = bKeySettings1;
  bCmdBuff[wCmdLen++] = bKeySettings2;

  if (0U != (bKeySettings2 & PHAL_MFDFEVX_KEYSETT3_PRESENT)) {
    bCmdBuff[wCmdLen++] = bKeySettings3;
    if ((bKeySettings3 & PHAL_MFDFEVX_KEYSETVALUES_PRESENT) && (bKeySetValues != NULL)) {
      /* KeySet Values */
      (void)memcpy(&bCmdBuff[wCmdLen], bKeySetValues, 4);
      wCmdLen += 4U;
    }
  }
  if (0U != (bOption & 0x01U)) {
    /* pISOFileId is present */
    bCmdBuff[wCmdLen++] = pISOFileId[0];
    bCmdBuff[wCmdLen++] = pISOFileId[1];
  }
  if (0U != (bOption & 0x02U)) {
    /* pISODFName is present */
    (void)memcpy(&bCmdBuff[wCmdLen], pISODFName, bISODFNameLen);
    wCmdLen += bISODFNameLen;
  }

  /* PHAL_MFDFEVX_MAC_DATA_INCOMPLETE should only be ORed for MACD communication mode.
  * For plain this will not be required.
  * First call to phalMfdfEVx_Sw_Int_Write_Plain should
  * get PHAL_MFDFEVX_COMMUNICATION_PLAIN as bCommOption only if D40, else
  * (PHAL_MFDFEVX_COMMUNICATION_MACD | PHAL_MFDFEVX_MAC_DATA_INCOMPLETE)
  */
  status = phalMfdfEVx_Sw_Int_Write_Plain(
          pDataParams,
          PHAL_MFDFEVX_DEFAULT_MODE,
          bCmdBuff,
          wCmdLen,
          PHAL_MFDFEVX_MAC_DATA_INCOMPLETE | ((pDataParams->bAuthMode == PHAL_MFDFEVX_AUTHENTICATEEV2) ?
              PHAL_MFDFEVX_COMMUNICATION_MACD : PHAL_MFDFEVX_COMMUNICATION_PLAIN),
          NULL,
          0x0000
      );

  if ((status & PH_ERR_MASK) != PH_ERR_SUCCESS) {
    return PH_ADD_COMPCODE((status & PH_ERR_MASK), PH_COMP_AL_MFDFEVX);
  }

  bCmdBuff[0] = PHAL_MFDFEVX_RESP_ADDITIONAL_FRAME;

  /* Copy the EncKey */
  (void)memcpy(&bCmdBuff[1], pEncK, 32);
  /* Copy the DAMMAC */
  (void)memcpy(&bCmdBuff[33], pDAMMAC, 8);

  return phalMfdfEVx_Sw_Int_Write_Plain(
          pDataParams,
          PHAL_MFDFEVX_DEFAULT_MODE,
          bCmdBuff,
          1,
          ((pDataParams->bAuthMode == PHAL_MFDFEVX_AUTHENTICATEEV2) ? PHAL_MFDFEVX_COMMUNICATION_MACD :
              PHAL_MFDFEVX_COMMUNICATION_PLAIN),
          &bCmdBuff[1],
          0x0028
      );
}

phStatus_t
phalMfdfEVx_Sw_SelectApplication(phalMfdfEVx_Sw_DataParams_t *pDataParams,
    uint8_t bOption, uint8_t *pAppId,
    uint8_t *pAppId2)
{
  uint16_t  PH_MEMLOC_REM statusTmp;
  uint8_t   PH_MEMLOC_REM bCmdBuff[8];
  uint16_t  PH_MEMLOC_REM wRxlen = 0;
  uint16_t  PH_MEMLOC_REM wCmdLen = 0;
  uint8_t *PH_MEMLOC_REM pRecv = NULL;

  /* Set the dataparams with command code. */
  pDataParams->bCmdCode = PHAL_MFDFEVX_CMD_SELECT_APPLN;

  /* form the command */
  bCmdBuff[0] = PHAL_MFDFEVX_CMD_SELECT_APPLN;
  (void)memcpy(&bCmdBuff[1], pAppId, PHAL_MFDFEVX_DFAPPID_SIZE);
  wCmdLen = PHAL_MFDFEVX_DFAPPID_SIZE + 1U;
  if (bOption == 0x01U) {
    /* Second application Id also provided */
    (void)memcpy(&bCmdBuff[4], pAppId2, PHAL_MFDFEVX_DFAPPID_SIZE);
    wCmdLen += PHAL_MFDFEVX_DFAPPID_SIZE;
  }

  /* Reset Authentication Status here */
  phalMfdfEVx_Sw_Int_ResetAuthStatus(pDataParams);

  /* Send the command */
  PH_CHECK_SUCCESS_FCT(statusTmp, phalMfdfEVx_ExchangeCmd(
          pDataParams,
          pDataParams->pPalMifareDataParams,
          pDataParams->bWrappedMode,
          bCmdBuff,
          wCmdLen,
          &pRecv,
          &wRxlen
      ));

  /* Store the currently selected application Id */
  (void)memcpy(pDataParams->pAid, pAppId, 3);

  /* Select command never returns CMAC */
  return PH_ERR_SUCCESS;
}

phStatus_t
phalMfdfEVx_Sw_GetApplicationIDs(phalMfdfEVx_Sw_DataParams_t *pDataParams,
    uint8_t bOption, uint8_t **pAidBuff,
    uint8_t *pNumAIDs)
{
  /*
  * A PICC can store any number of applications limited by PICC memory
  */
  phStatus_t  PH_MEMLOC_REM status;
  uint8_t     PH_MEMLOC_REM bCmdBuff[8];
  uint16_t    PH_MEMLOC_REM wRxlen = 0;
  uint8_t     PH_MEMLOC_REM *pRecv = NULL;

  /* Initialization */
  *pNumAIDs = 0;

  /* Set the dataparams with command code. */
  pDataParams->bCmdCode = PHAL_MFDFEVX_CMD_GET_APPLN_IDS;

  if ((bOption & 0x0FU) == PH_EXCHANGE_RXCHAINING) {
    bCmdBuff[0] = PHAL_MFDFEVX_RESP_ADDITIONAL_FRAME;
  } else if ((bOption & 0x0FU) == PH_EXCHANGE_DEFAULT) {
    /* form the command */
    bCmdBuff[0] = PHAL_MFDFEVX_CMD_GET_APPLN_IDS;
  } else {
    return PH_ADD_COMPCODE_FIXED(PH_ERR_INVALID_PARAMETER, PH_COMP_AL_MFDFEVX);
  }

  /*
  * If EV2 authenticated, it is actually MAC mode in which this command
  * is sent. This is similar concept as in EV1 but the generated MAC
  * is attached with the command. The ReadData_Plain handles this.
  */
  status = phalMfdfEVx_Sw_Int_ReadData_Plain(
          pDataParams,
          (pDataParams->bAuthMode == PHAL_MFDFEVX_AUTHENTICATEEV2) ? PHAL_MFDFEVX_COMMUNICATION_MACD :
          PHAL_MFDFEVX_COMMUNICATION_PLAIN,
          bCmdBuff,
          1,
          &pRecv,
          &wRxlen
      );

  if (((status & PH_ERR_MASK) == PH_ERR_SUCCESS) ||
      ((status & PH_ERR_MASK) == PH_ERR_SUCCESS_CHAINING)) {
    /* Length should be a multiple of 3. Else return error */
    if (0U != (wRxlen % 3)) {
      return PH_ADD_COMPCODE_FIXED(PH_ERR_PROTOCOL_ERROR, PH_COMP_AL_MFDFEVX);
    }
    *pAidBuff = pRecv;

    /* Update pNumAids and return  */
    *pNumAIDs = (uint8_t)(wRxlen / 3);
  }
  return PH_ADD_COMPCODE(status, PH_COMP_AL_MFDFEVX);
}

#ifdef NXPBUILD__PHAL_MFDFEVX_NDA
phStatus_t
phalMfdfEVx_Sw_GetDFNames(phalMfdfEVx_Sw_DataParams_t *pDataParams, uint8_t bOption,
    uint8_t *pDFBuffer,
    uint8_t *pDFInfoLen)
{
  /**
  Returns AID(3B), FID(2B), DF-Name(1..16B) in one frame.

  Will return PH_EXCHANGE_RXCHAINING if more DF names are present.
  The caller has to call the function with option PH_EXCHANGE_RXCHAINING

  Will not work if authenticated in standard TDES or AES modes as per the
  Implementation Hints document.
  */
  uint16_t    PH_MEMLOC_REM status = 0;
  uint16_t    PH_MEMLOC_REM statusTemp = 0;
  uint8_t     PH_MEMLOC_REM bCmdBuff[24];
  uint16_t    PH_MEMLOC_REM wRxlen = 0;
  uint16_t    PH_MEMLOC_REM wCmdLen = 1;
  uint8_t    *PH_MEMLOC_REM pRecv = NULL;
  uint8_t     PH_MEMLOC_REM bCMAC[PH_CRYPTOSYM_AES_BLOCK_SIZE];
  uint8_t     PH_MEMLOC_REM bCMacCard[8];
  uint8_t     PH_MEMLOC_REM bMacLen = 0;
  uint8_t     PH_MEMLOC_REM bIvLen = 0;
  uint16_t    PH_MEMLOC_REM wTmp = 0;
  uint16_t    PH_MEMLOC_REM wOption = PH_EXCHANGE_BUFFER_CONT;

  (void)memset(bCmdBuff, 0x00, 24);
  (void)memset(bCMAC, 0x00, PH_CRYPTOSYM_AES_BLOCK_SIZE);

  /* Set the dataparams with command code. */
  pDataParams->bCmdCode = PHAL_MFDFEVX_CMD_GET_DF_NAMES;

  if ((pDataParams->bAuthMode == PHAL_MFDFEVX_AUTHENTICATEAES) ||
      (pDataParams->bAuthMode == PHAL_MFDFEVX_AUTHENTICATEEV2)) {
    bIvLen = PH_CRYPTOSYM_AES_BLOCK_SIZE;
  } else {
    bIvLen = PH_CRYPTOSYM_DES_BLOCK_SIZE;
  }

  /* form the command */
  if (bOption == PH_EXCHANGE_RXCHAINING) {
    bCmdBuff[0] = PHAL_MFDFEVX_RESP_ADDITIONAL_FRAME;
  } else if (bOption == PH_EXCHANGE_DEFAULT) {
    bCmdBuff[0] = PHAL_MFDFEVX_CMD_GET_DF_NAMES;

    if (pDataParams->bAuthMode != PHAL_MFDFEVX_AUTHENTICATE) {
      /* Check for 0xAF added above to ensure that we dont update the
      IV or calculate CMAC for cases where in the application has called
      this API with bOption = PH_EXCHANGE_RXCHAINING */
      if ((pDataParams->bAuthMode == PHAL_MFDFEVX_AUTHENTICATEISO) ||
          (pDataParams->bAuthMode == PHAL_MFDFEVX_AUTHENTICATEAES)) {
        /* Load Iv */
        PH_CHECK_SUCCESS_FCT(statusTemp, phCryptoSym_LoadIv(
                pDataParams->pCryptoDataParamsEnc,
                pDataParams->bIv,
                bIvLen
            ));

        /* Calculate MAC to update the init vector */
        PH_CHECK_SUCCESS_FCT(statusTemp, phCryptoSym_CalculateMac(
                pDataParams->pCryptoDataParamsEnc,
                PH_CRYPTOSYM_MAC_MODE_CMAC,
                bCmdBuff,
                1,
                bCMAC,
                &bMacLen
            ));

        /* Store the IV */
        (void)memcpy(pDataParams->bIv, bCMAC, bIvLen);
        bMacLen = 0;
      } else if (pDataParams->bAuthMode == PHAL_MFDFEVX_AUTHENTICATEEV2) {
        (void)memset(pDataParams->bIv, 0x00, bIvLen);
        /* bCmdBuff[0] contains header. now Add CmdCtr and TI for MAC calculation */
        bCmdBuff[wCmdLen++] = (uint8_t)(pDataParams->wCmdCtr);
        bCmdBuff[wCmdLen++] = (uint8_t)(pDataParams->wCmdCtr >> 8U);
        (void)memcpy(&bCmdBuff[wCmdLen], pDataParams->bTi, PHAL_MFDFEVX_SIZE_TI);
        wCmdLen += PHAL_MFDFEVX_SIZE_TI;

        /* Assumed here that a read-like commands cannot in any case have cmd+header+data > 24 bytes */
        /* Load Iv */
        PH_CHECK_SUCCESS_FCT(statusTemp, phCryptoSym_LoadIv(
                pDataParams->pCryptoDataParamsMac,
                pDataParams->bIv,
                bIvLen
            ));

        /* Calculate MAC */
        PH_CHECK_SUCCESS_FCT(statusTemp, phCryptoSym_CalculateMac(
                pDataParams->pCryptoDataParamsMac,
                (PH_CRYPTOSYM_MAC_MODE_CMAC),
                bCmdBuff,
                wCmdLen,
                bCMAC,
                &bMacLen
            ));

        /* Truncate the MAC generated */
        phalMfdfEVx_Sw_Int_TruncateMac(bCMAC);

        /* Get the original command in the work buffer. */
        bCmdBuff[0] = PHAL_MFDFEVX_CMD_GET_DF_NAMES;
        /* Append MAC for EV2 mode. */
        (void)memcpy(&bCmdBuff[1], bCMAC, PHAL_MFDFEVX_TRUNCATED_MAC_SIZE);
        wCmdLen = 1 + PHAL_MFDFEVX_TRUNCATED_MAC_SIZE;
      } else {
        /*Do Nothing. This is for PRQA compliance */
      }
    }
  } else {
    return PH_ADD_COMPCODE_FIXED(PH_ERR_INVALID_PARAMETER, PH_COMP_AL_MFDFEVX);
  }

  /* Send the command */
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
    /* Component code is already added by GetData */

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

  /* check for protocol errors */
  if (((status & PH_ERR_MASK) == PH_ERR_SUCCESS_CHAINING) &&
      (wRxlen == 0U)) {
    return PH_ADD_COMPCODE_FIXED(PH_ERR_PROTOCOL_ERROR, PH_COMP_AL_MFDFEVX);
  }
  /* Should return either zero bytes or more than 4 bytes. Anything inbetween
  is an error */
  if ((status == PH_ERR_SUCCESS) && (wRxlen != 0U) && (wRxlen < 5U)) {
    return PH_ADD_COMPCODE_FIXED(PH_ERR_PROTOCOL_ERROR, PH_COMP_AL_MFDFEVX);
  }
  if (((status & PH_ERR_MASK) == PH_ERR_SUCCESS_CHAINING)
      && (wRxlen < 5U)) {
    return PH_ADD_COMPCODE_FIXED(PH_ERR_PROTOCOL_ERROR, PH_COMP_AL_MFDFEVX);
  }

  /* Verify the MAC */
  if ((pDataParams->bAuthMode == PHAL_MFDFEVX_AUTHENTICATEISO) ||
      (pDataParams->bAuthMode == PHAL_MFDFEVX_AUTHENTICATEAES)) {
    if (bCmdBuff[0] != PHAL_MFDFEVX_RESP_ADDITIONAL_FRAME) {

      PH_CHECK_SUCCESS_FCT(statusTemp, phCryptoSym_LoadIv(
              pDataParams->pCryptoDataParamsEnc,
              pDataParams->bIv,
              bIvLen
          ));

      pDataParams->bNoUnprocBytes = 0;
      wOption = PH_EXCHANGE_BUFFER_FIRST;
    }
    if ((status & PH_ERR_MASK) == PH_ERR_SUCCESS) {
      /* for Qmore compliance below code is added */
      if (wRxlen < 8U) { /* If no CMAC received */
        return PH_ADD_COMPCODE_FIXED(PH_ERR_PROTOCOL_ERROR, PH_COMP_AL_MFDFEVX);
      }
      /* copy mac value */
      (void)memcpy(bCMacCard, &pRecv[wRxlen - 8u], 8);
      wRxlen -= 8u;
      /* update RC  for calculating  mac*/
      pRecv[wRxlen++] = (uint8_t)status;

      /* If receieved data is not multiple of block size */
      wTmp = (bIvLen - pDataParams->bNoUnprocBytes);
      /* */
      if (wTmp >= wRxlen) {
        wTmp = wRxlen;
      }
      (void)memcpy(&pDataParams->pUnprocByteBuff[pDataParams->bNoUnprocBytes], pRecv, wTmp);
      pDataParams->bNoUnprocBytes += (uint8_t)wTmp;

      if (wTmp == wRxlen) {
        /* Calculate CMAC */
        PH_CHECK_SUCCESS_FCT(statusTemp, phCryptoSym_CalculateMac(
                pDataParams->pCryptoDataParamsEnc,
                (PH_CRYPTOSYM_MAC_MODE_CMAC | PH_EXCHANGE_BUFFER_LAST),
                pDataParams->pUnprocByteBuff,
                pDataParams->bNoUnprocBytes,
                bCMAC,
                &bMacLen
            ));
      } else {
        /* Calculate CMAC */
        PH_CHECK_SUCCESS_FCT(statusTemp, phCryptoSym_CalculateMac(
                pDataParams->pCryptoDataParamsEnc,
                (PH_CRYPTOSYM_MAC_MODE_CMAC | wOption),
                pDataParams->pUnprocByteBuff,
                pDataParams->bNoUnprocBytes,
                bCMAC,
                &bMacLen
            ));

        PH_CHECK_SUCCESS_FCT(statusTemp, phCryptoSym_CalculateMac(
                pDataParams->pCryptoDataParamsEnc,
                PH_CRYPTOSYM_MAC_MODE_CMAC | PH_EXCHANGE_BUFFER_LAST,
                &pRecv[wTmp],
                wRxlen - wTmp,
                bCMAC,
                &bMacLen
            ));
      }
      /* Rx length is increased since status byte is added to calculate mac. */
      wRxlen--;

      /* Since end of response is reached reset the pDataParams bNoUnprocBytes member to 0 */
      pDataParams->bNoUnprocBytes = 0;

      if (memcmp(bCMAC, bCMacCard, 8) != 0) {
        /* CMAC validation failed */
        return PH_ADD_COMPCODE_FIXED(PH_ERR_INTEGRITY_ERROR, PH_COMP_AL_MFDFEVX);
      }

      /* Update IV to be used for next commands */
      (void)memcpy(pDataParams->bIv, bCMAC, bIvLen);
    } else {

      if ((pDataParams->bNoUnprocBytes + wRxlen) >= bIvLen) {
        /* copy left over bytes from previous packet */
        wTmp = bIvLen - pDataParams->bNoUnprocBytes;
        (void)memcpy(&pDataParams->pUnprocByteBuff[pDataParams->bNoUnprocBytes], pRecv, wTmp);
        pDataParams->bNoUnprocBytes += (uint8_t)wTmp;

        PH_CHECK_SUCCESS_FCT(statusTemp, phCryptoSym_CalculateMac(
                pDataParams->pCryptoDataParamsEnc,
                (PH_CRYPTOSYM_MAC_MODE_CMAC | wOption),
                pDataParams->pUnprocByteBuff,
                pDataParams->bNoUnprocBytes,
                bCMAC,
                &bMacLen
            ));
        pDataParams->bNoUnprocBytes = 0;
      }

      /* remaing number of bytes are more then IVlength */
      if ((wRxlen - wTmp) >= bIvLen) {
        PH_CHECK_SUCCESS_FCT(statusTemp, phCryptoSym_CalculateMac(
                pDataParams->pCryptoDataParamsEnc,
                (PH_CRYPTOSYM_MAC_MODE_CMAC | wOption),
                &pRecv[wTmp],
                ((wRxlen - wTmp) / bIvLen) * bIvLen,
                bCMAC,
                &bMacLen
            ));
      }

      /* Remaining bytes */
      wTmp = (wRxlen - wTmp) % bIvLen;

      /* Update the UnprocByteBuffer with bytes not used for mac calculation */
      (void)memcpy(&pDataParams->pUnprocByteBuff[pDataParams->bNoUnprocBytes], &pRecv[wRxlen - wTmp],
          wTmp);
      pDataParams->bNoUnprocBytes += (uint8_t)wTmp;

    }
  } else if (pDataParams->bAuthMode == PHAL_MFDFEVX_AUTHENTICATEEV2) {
    if (bCmdBuff[0] != PHAL_MFDFEVX_RESP_ADDITIONAL_FRAME) {
      PH_CHECK_SUCCESS_FCT(statusTemp, phCryptoSym_LoadIv(
              pDataParams->pCryptoDataParamsMac,
              pDataParams->bIv,
              bIvLen
          ));

      /* update the exchange buffer as first */
      wOption = PH_EXCHANGE_BUFFER_FIRST;

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
      /* for Qmore compliance below code is added */
      if (wRxlen < 8U) { /* If no CMAC received */
        return PH_ADD_COMPCODE_FIXED(PH_ERR_PROTOCOL_ERROR, PH_COMP_AL_MFDFEVX);
      }

      (void)memcpy(bCMacCard, &pRecv[wRxlen - 8u], 8);
      wRxlen -= 8u;

      /* If receieved data is not multiple of block size */
      wTmp = (bIvLen - pDataParams->bNoUnprocBytes);

      if (wTmp >= wRxlen) {
        wTmp = wRxlen;
      }
      (void)memcpy(&pDataParams->pUnprocByteBuff[pDataParams->bNoUnprocBytes], pRecv, wTmp);
      pDataParams->bNoUnprocBytes += (uint8_t)wTmp;

      if (wTmp == wRxlen) {
        /* Conclude the CMAC calculation. */
        PH_CHECK_SUCCESS_FCT(statusTemp, phCryptoSym_CalculateMac(
                pDataParams->pCryptoDataParamsMac,
                (PH_CRYPTOSYM_MAC_MODE_CMAC | PH_EXCHANGE_BUFFER_LAST),
                pDataParams->pUnprocByteBuff,
                (pDataParams->bNoUnprocBytes),
                bCMAC,
                &bMacLen
            ));
      } else {
        /* First send the 16 byte block for cmac calculation */
        PH_CHECK_SUCCESS_FCT(statusTemp, phCryptoSym_CalculateMac(
                pDataParams->pCryptoDataParamsMac,
                (PH_CRYPTOSYM_MAC_MODE_CMAC | wOption),
                pDataParams->pUnprocByteBuff,
                (pDataParams->bNoUnprocBytes),
                bCMAC,
                &bMacLen
            ));

        /* Send rest of the received data */
        PH_CHECK_SUCCESS_FCT(statusTemp, phCryptoSym_CalculateMac(
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
      if ((pDataParams->bNoUnprocBytes + wRxlen) >= bIvLen) {
        /* copy left over bytes from previous packet */
        wTmp = bIvLen - pDataParams->bNoUnprocBytes;
        (void)memcpy(&pDataParams->pUnprocByteBuff[pDataParams->bNoUnprocBytes], pRecv, wTmp);
        pDataParams->bNoUnprocBytes += (uint8_t)wTmp;

        /* Start MAC calculation with one full block size data */
        PH_CHECK_SUCCESS_FCT(statusTemp, phCryptoSym_CalculateMac(
                pDataParams->pCryptoDataParamsMac,
                (PH_CRYPTOSYM_MAC_MODE_CMAC | wOption),
                pDataParams->pUnprocByteBuff,
                (pDataParams->bNoUnprocBytes),
                bCMAC,
                &bMacLen
            ));
        pDataParams->bNoUnprocBytes = 0;
      }
      /* remaing number of bytes are more then IV length */
      if ((wRxlen - wTmp) >= bIvLen) {
        PH_CHECK_SUCCESS_FCT(statusTemp, phCryptoSym_CalculateMac(
                pDataParams->pCryptoDataParamsMac,
                (PH_CRYPTOSYM_MAC_MODE_CMAC | wOption),
                &pRecv[wTmp],
                ((wRxlen - wTmp) / bIvLen) * bIvLen,
                bCMAC,
                &bMacLen
            ));
      }

      /* Remaining bytes */
      wTmp = (wRxlen - wTmp) % bIvLen;

      /* Update the UnprocByteBuffer with bytes not used for mac calculation */
      (void)memcpy(&pDataParams->pUnprocByteBuff[pDataParams->bNoUnprocBytes], &pRecv[wRxlen - wTmp],
          wTmp);
      pDataParams->bNoUnprocBytes += (uint8_t)wTmp;

    }
  } else {
    /* Will come here in case data transfer is plain
    and auth mode is 0x0A */
    bIvLen = 0x00;
  }

  (void)memcpy(pDFBuffer, pRecv, wRxlen);
  *pDFInfoLen = (uint8_t)wRxlen;

  return status;
}
#endif /* NXPBUILD__PHAL_MFDFEVX_NDA */

phStatus_t
phalMfdfEVx_Sw_GetDelegatedInfo(phalMfdfEVx_Sw_DataParams_t *pDataParams,
    uint8_t *pDAMSlot, uint8_t *pDamSlotVer,
    uint8_t *pQuotaLimit, uint8_t *pFreeBlocks, uint8_t *pAid)
{
  uint16_t    PH_MEMLOC_REM statusTmp;
  uint8_t     PH_MEMLOC_REM bCmdBuff[8];
  uint16_t    PH_MEMLOC_REM wRxlen = 0;
  uint8_t     PH_MEMLOC_REM *pRecv = NULL;

  /* Set the dataparams with command code. */
  pDataParams->bCmdCode = PHAL_MFDFEVX_CMD_GET_DELEGATED_INFO;

  /* form the command */
  bCmdBuff[0] = PHAL_MFDFEVX_CMD_GET_DELEGATED_INFO;
  (void)memcpy(&bCmdBuff[1], pDAMSlot, 2);

  PH_CHECK_SUCCESS_FCT(statusTmp, phalMfdfEVx_Sw_Int_ReadData_Plain(
          pDataParams,
          (pDataParams->bAuthMode == PHAL_MFDFEVX_AUTHENTICATEEV2) ? PHAL_MFDFEVX_COMMUNICATION_MACD :
          PHAL_MFDFEVX_COMMUNICATION_PLAIN,
          bCmdBuff,
          3,
          &pRecv,
          &wRxlen
      ));

  /* Received data length should be equal to 6 bytes + 2 bytes of FreeBlocks */
  if (wRxlen != 0x08U) {
    return PH_ADD_COMPCODE_FIXED(PH_ERR_PROTOCOL_ERROR, PH_COMP_AL_MFDFEVX);
  }

  (void)memcpy(pDamSlotVer, &pRecv[0], 1);
  (void)memcpy(pQuotaLimit, &pRecv[1], 2);
  (void)memcpy(pFreeBlocks, &pRecv[3], 2);
  (void)memcpy(pAid, &pRecv[5], 3);

  return PH_ERR_SUCCESS;

}

/* MIFARE DESFire EVx File mamangement commands. --------------------------------------------------------------------------------------- */
phStatus_t
phalMfdfEVx_Sw_CreateStdDataFile(phalMfdfEVx_Sw_DataParams_t *pDataParams,
    uint8_t bOption, uint8_t bFileNo,
    uint8_t *pISOFileId, uint8_t bFileOption, uint8_t *pAccessRights, uint8_t *pFileSize)
{
  /*
  If (bKeySettings2 & 0x03)== 00 [DES, 3DES] then pDataParams->bAuthMode can be either
  0x0A or 0x1A.
  If (bKeySettings2 & 0x03)== 01 [3K3DES] then pDataParams->bAuthMode can only be 0x1A.
  If (bKeySettings2 & 0x03)== 10 [AES] then pDataParams->bAuthMode can only be 0xAA.
  */
  uint8_t     PH_MEMLOC_REM bCmdBuff[16];
  uint16_t    PH_MEMLOC_REM wCmdLen = 0;

#ifdef RDR_LIB_PARAM_CHECK
  if (((bFileNo & 0x7fU) > 0x1fU) || (bOption > 0x01U)) {
    return PH_ADD_COMPCODE_FIXED(PH_ERR_INVALID_PARAMETER, PH_COMP_AL_MFDFEVX);
  }

  if (((bFileOption & 0x03U) != (PHAL_MFDFEVX_COMMUNICATION_PLAIN >> 4U)) &&
      ((bFileOption & 0x03U) != (PHAL_MFDFEVX_COMMUNICATION_ENC >> 4U)) &&
      ((bFileOption & 0x03U) != (PHAL_MFDFEVX_COMMUNICATION_MACD >> 4U))) {
    return PH_ADD_COMPCODE_FIXED(PH_ERR_INVALID_PARAMETER, PH_COMP_AL_MFDFEVX);
  }
#endif

  /* Set the dataparams with command code. */
  pDataParams->bCmdCode = PHAL_MFDFEVX_CMD_CREATE_STD_DATAFILE;

  /* form the command */
  bCmdBuff[wCmdLen++] = PHAL_MFDFEVX_CMD_CREATE_STD_DATAFILE;

  /* File Number */
  bCmdBuff[wCmdLen++] = bFileNo;

  /* Copy ISO Filed ID if present */
  if (bOption == 0x01U) {
    bCmdBuff[wCmdLen++] = pISOFileId[0];
    bCmdBuff[wCmdLen++] = pISOFileId[1];
  }

  /* Copy communication settings. */
  bCmdBuff[wCmdLen++] = bFileOption;

  /* Copy Access rights */
  bCmdBuff[wCmdLen++] = pAccessRights[0];
  bCmdBuff[wCmdLen++] = pAccessRights[1];

  /* Copy File size supplied by the user */
  (void)memcpy(&bCmdBuff[wCmdLen], pFileSize, 3);
  wCmdLen += 3U;

  /* COMMUNICATION IS PLAIN */
  return phalMfdfEVx_Sw_Int_Write_Plain(pDataParams,
          PHAL_MFDFEVX_DEFAULT_MODE,
          bCmdBuff,
          wCmdLen,
          (pDataParams->bAuthMode == PHAL_MFDFEVX_AUTHENTICATEEV2) ? PHAL_MFDFEVX_COMMUNICATION_MACD :
          PHAL_MFDFEVX_COMMUNICATION_PLAIN,
          NULL,
          0x0000
      );
}

phStatus_t
phalMfdfEVx_Sw_CreateBackupDataFile(phalMfdfEVx_Sw_DataParams_t *pDataParams,
    uint8_t bOption, uint8_t bFileNo,
    uint8_t *pISOFileId, uint8_t bFileOption, uint8_t *pAccessRights, uint8_t *pFileSize)
{
  uint8_t     PH_MEMLOC_REM bCmdBuff[16];
  uint16_t    PH_MEMLOC_REM wCmdLen = 0;

#ifdef RDR_LIB_PARAM_CHECK
  if (((bFileNo & 0x7fU) > 0x1fU) || (bOption > 0x01U)) {
    return PH_ADD_COMPCODE_FIXED(PH_ERR_INVALID_PARAMETER, PH_COMP_AL_MFDFEVX);
  }
  if (((bFileOption & 0x03U) != (PHAL_MFDFEVX_COMMUNICATION_PLAIN >> 4U)) &&
      ((bFileOption & 0x03U) != (PHAL_MFDFEVX_COMMUNICATION_ENC >> 4U)) &&
      ((bFileOption & 0x03U) != (PHAL_MFDFEVX_COMMUNICATION_MACD >> 4U))) {
    return PH_ADD_COMPCODE_FIXED(PH_ERR_INVALID_PARAMETER, PH_COMP_AL_MFDFEVX);
  }
#endif

  /* Set the dataparams with command code. */
  pDataParams->bCmdCode = PHAL_MFDFEVX_CMD_CREATE_BKUP_DATAFILE;

  /* form the command */
  bCmdBuff[wCmdLen++] = PHAL_MFDFEVX_CMD_CREATE_BKUP_DATAFILE;

  /* File Number */
  bCmdBuff[wCmdLen++] = bFileNo;

  /* Copy ISO Filed ID if present */
  if (bOption == 0x01U) {
    bCmdBuff[wCmdLen++] = pISOFileId[0];
    bCmdBuff[wCmdLen++] = pISOFileId[1];
  }

  /* Copy communication settings. */
  bCmdBuff[wCmdLen++] = bFileOption;

  /* Copy Access rights */
  bCmdBuff[wCmdLen++] = pAccessRights[0];
  bCmdBuff[wCmdLen++] = pAccessRights[1];

  /* Copy File size supplied by the user */
  (void)memcpy(&bCmdBuff[wCmdLen], pFileSize, 3);
  wCmdLen += 3U;

  /* COMMUNICATION IS PLAIN */
  return phalMfdfEVx_Sw_Int_Write_Plain(pDataParams,
          PHAL_MFDFEVX_DEFAULT_MODE,
          bCmdBuff,
          wCmdLen,
          (pDataParams->bAuthMode == PHAL_MFDFEVX_AUTHENTICATEEV2) ? PHAL_MFDFEVX_COMMUNICATION_MACD :
          PHAL_MFDFEVX_COMMUNICATION_PLAIN,
          NULL,
          0x0000
      );
}

phStatus_t
phalMfdfEVx_Sw_CreateValueFile(phalMfdfEVx_Sw_DataParams_t *pDataParams,
    uint8_t bFileNo, uint8_t bCommSett,
    uint8_t *pAccessRights, uint8_t *pLowerLmit, uint8_t *pUpperLmit, uint8_t *pValue,
    uint8_t bLimitedCredit)
{
  uint8_t     PH_MEMLOC_REM bCmdBuff[32];
  uint16_t    PH_MEMLOC_REM wCmdLen = 0;

#ifdef RDR_LIB_PARAM_CHECK
  if ((bFileNo & 0x7fU) > 0x1fU) {
    return PH_ADD_COMPCODE_FIXED(PH_ERR_INVALID_PARAMETER, PH_COMP_AL_MFDFEVX);
  }

  if (((bCommSett & 0x03U) != (PHAL_MFDFEVX_COMMUNICATION_PLAIN >> 4U)) &&
      ((bCommSett & 0x03U) != (PHAL_MFDFEVX_COMMUNICATION_MACD >> 4U)) &&
      ((bCommSett & 0x03U) != (PHAL_MFDFEVX_COMMUNICATION_ENC >> 4U))) {
    return PH_ADD_COMPCODE_FIXED(PH_ERR_INVALID_PARAMETER, PH_COMP_AL_MFDFEVX);
  }
#endif

  /* Set the dataparams with command code. */
  pDataParams->bCmdCode = PHAL_MFDFEVX_CMD_CREATE_VALUE_FILE;

  /* form the command */
  bCmdBuff[wCmdLen++] = PHAL_MFDFEVX_CMD_CREATE_VALUE_FILE;
  bCmdBuff[wCmdLen++] = bFileNo;

  /* Copy communication settings */
  bCmdBuff[wCmdLen++] = bCommSett;

  (void)memcpy(bCmdBuff + wCmdLen, pAccessRights, 2);
  wCmdLen = wCmdLen + 2U;

  (void)memcpy(bCmdBuff + wCmdLen, pLowerLmit, 4);
  wCmdLen = wCmdLen + 4U;

  (void)memcpy(bCmdBuff + wCmdLen, pUpperLmit, 4);
  wCmdLen = wCmdLen + 4U;

  (void)memcpy(bCmdBuff + wCmdLen, pValue, 4);
  wCmdLen = wCmdLen + 4U;

  bCmdBuff[wCmdLen++] = bLimitedCredit;

  /* COMMUNICATION IS PLAIN */
  return phalMfdfEVx_Sw_Int_Write_Plain(pDataParams,
          PHAL_MFDFEVX_DEFAULT_MODE,
          bCmdBuff,
          wCmdLen,
          (pDataParams->bAuthMode == PHAL_MFDFEVX_AUTHENTICATEEV2) ? PHAL_MFDFEVX_COMMUNICATION_MACD :
          PHAL_MFDFEVX_COMMUNICATION_PLAIN,
          NULL,
          0x0000
      );
}

phStatus_t
phalMfdfEVx_Sw_CreateLinearRecordFile(phalMfdfEVx_Sw_DataParams_t *pDataParams,
    uint8_t bOption, uint8_t  bFileNo,
    uint8_t  *pIsoFileId, uint8_t bCommSett, uint8_t *pAccessRights, uint8_t *pRecordSize,
    uint8_t *pMaxNoOfRec)
{
  uint8_t     PH_MEMLOC_REM bCmdBuff[32];
  uint16_t    PH_MEMLOC_REM wCmdLen = 0;

#ifdef RDR_LIB_PARAM_CHECK
  if (((bFileNo & 0x7fU) > 0x1fU) || (bOption > 0x01U)) {
    return PH_ADD_COMPCODE_FIXED(PH_ERR_INVALID_PARAMETER, PH_COMP_AL_MFDFEVX);
  }
  if (((bCommSett & 0x03U) != (PHAL_MFDFEVX_COMMUNICATION_PLAIN >> 4U)) &&
      ((bCommSett & 0x03U) != (PHAL_MFDFEVX_COMMUNICATION_MACD >> 4U)) &&
      ((bCommSett & 0x03U) != (PHAL_MFDFEVX_COMMUNICATION_ENC >> 4U))) {
    return PH_ADD_COMPCODE_FIXED(PH_ERR_INVALID_PARAMETER, PH_COMP_AL_MFDFEVX);
  }
#endif

  /* Set the dataparams with command code. */
  pDataParams->bCmdCode = PHAL_MFDFEVX_CMD_CREATE_LINEAR_RECFILE;

  /* form the command */
  bCmdBuff[wCmdLen++] = PHAL_MFDFEVX_CMD_CREATE_LINEAR_RECFILE;

  /* Copy the value information supplied by the user */
  bCmdBuff[wCmdLen++] = bFileNo;

  if (bOption == 0x01U) {
    bCmdBuff[wCmdLen++] = pIsoFileId[0];
    bCmdBuff[wCmdLen++] = pIsoFileId[1];
  }

  /* Copy communication settings */
  bCmdBuff[wCmdLen++] = bCommSett;

  bCmdBuff[wCmdLen++] = pAccessRights[0];
  bCmdBuff[wCmdLen++] = pAccessRights[1];

  bCmdBuff[wCmdLen++] = pRecordSize[0];
  bCmdBuff[wCmdLen++] = pRecordSize[1];
  bCmdBuff[wCmdLen++] = pRecordSize[2];

  bCmdBuff[wCmdLen++] = pMaxNoOfRec[0];
  bCmdBuff[wCmdLen++] = pMaxNoOfRec[1];
  bCmdBuff[wCmdLen++] = pMaxNoOfRec[2];

  /* COMMUNICATION IS PLAIN */
  return phalMfdfEVx_Sw_Int_Write_Plain(pDataParams,
          PHAL_MFDFEVX_DEFAULT_MODE,
          bCmdBuff,
          wCmdLen,
          (pDataParams->bAuthMode == PHAL_MFDFEVX_AUTHENTICATEEV2) ? PHAL_MFDFEVX_COMMUNICATION_MACD :
          PHAL_MFDFEVX_COMMUNICATION_PLAIN,
          NULL,
          0x0000
      );
}

phStatus_t
phalMfdfEVx_Sw_CreateCyclicRecordFile(phalMfdfEVx_Sw_DataParams_t *pDataParams,
    uint8_t bOption, uint8_t  bFileNo,
    uint8_t  *pIsoFileId, uint8_t bCommSett, uint8_t *pAccessRights, uint8_t *pRecordSize,
    uint8_t *pMaxNoOfRec)
{
  uint8_t     PH_MEMLOC_REM bCmdBuff[32];
  uint16_t    PH_MEMLOC_REM wCmdLen = 0;

#ifdef RDR_LIB_PARAM_CHECK
  if (((bFileNo & 0x7fU) > 0x1fU) || (bOption > 0x01U)) {
    return PH_ADD_COMPCODE_FIXED(PH_ERR_INVALID_PARAMETER, PH_COMP_AL_MFDFEVX);
  }
  if (((bCommSett & 0x03U) != (PHAL_MFDFEVX_COMMUNICATION_PLAIN >> 4U)) &&
      ((bCommSett & 0x03U) != (PHAL_MFDFEVX_COMMUNICATION_MACD >> 4U)) &&
      ((bCommSett & 0x03U) != (PHAL_MFDFEVX_COMMUNICATION_ENC >> 4U))) {
    return PH_ADD_COMPCODE_FIXED(PH_ERR_INVALID_PARAMETER, PH_COMP_AL_MFDFEVX);
  }
#endif

  /* Set the dataparams with command code. */
  pDataParams->bCmdCode = PHAL_MFDFEVX_CMD_CREATE_CYCLIC_RECFILE;

  /* form the command */
  bCmdBuff[wCmdLen++] = PHAL_MFDFEVX_CMD_CREATE_CYCLIC_RECFILE;

  /* Copy the value information supplied by the user */
  bCmdBuff[wCmdLen++] = bFileNo;

  if (bOption == 0x01U) {
    bCmdBuff[wCmdLen++] = pIsoFileId[0];
    bCmdBuff[wCmdLen++] = pIsoFileId[1];
  }

  /* Copy communication settings */
  bCmdBuff[wCmdLen++] = bCommSett;

  bCmdBuff[wCmdLen++] = pAccessRights[0];
  bCmdBuff[wCmdLen++] = pAccessRights[1];

  bCmdBuff[wCmdLen++] = pRecordSize[0];
  bCmdBuff[wCmdLen++] = pRecordSize[1];
  bCmdBuff[wCmdLen++] = pRecordSize[2];

  bCmdBuff[wCmdLen++] = pMaxNoOfRec[0];
  bCmdBuff[wCmdLen++] = pMaxNoOfRec[1];
  bCmdBuff[wCmdLen++] = pMaxNoOfRec[2];

  /* COMMUNICATION IS PLAIN */
  return phalMfdfEVx_Sw_Int_Write_Plain(pDataParams,
          PHAL_MFDFEVX_DEFAULT_MODE,
          bCmdBuff,
          wCmdLen,
          (pDataParams->bAuthMode == PHAL_MFDFEVX_AUTHENTICATEEV2) ? PHAL_MFDFEVX_COMMUNICATION_MACD :
          PHAL_MFDFEVX_COMMUNICATION_PLAIN,
          NULL,
          0x0000
      );
}

#ifdef  NXPBUILD__PHAL_MFDFEVX_NDA
phStatus_t
phalMfdfEVx_Sw_CreateTransactionMacFile(phalMfdfEVx_Sw_DataParams_t *pDataParams,
    uint8_t bFileNo,
    uint8_t bCommSett, uint8_t *pAccessRights, uint8_t bKeyType, uint8_t *bTMKey, uint8_t bTMKeyVer)
{
  /* Communication mode for this file is
  * CommunicationMode.FULL. If not authenticated, then this
  * command should return error
  * bTMKeyOption should be renamed to bKeyType and
  * only KEY_TYPE_AES128 should be valid here. If anything else
  * sent, it should return parameter error.
  *
  * Also should consider providing key number and key version instead of
  * TMKey in the arguments. This will automatically pick up the key
  * from the specified key number, version of the key store.
  */

  /* Q: What should be the padding mode? */
  uint8_t     PH_MEMLOC_REM bCmdBuff[32];
  uint16_t    PH_MEMLOC_REM wCmdLen = 0;

#ifdef RDR_LIB_PARAM_CHECK
  /* Check for valid file no. and KeyType == AES128 */
  if (((bFileNo & 0x7fU) > 0x1fU) || (bKeyType != PHAL_MFDFEVX_KEY_TYPE_AES128)) {
    return PH_ADD_COMPCODE_FIXED(PH_ERR_INVALID_PARAMETER, PH_COMP_AL_MFDFEVX);
  }
  if (((bCommSett & 0x03U) != (PHAL_MFDFEVX_COMMUNICATION_PLAIN >> 4U)) &&
      ((bCommSett & 0x03U) != (PHAL_MFDFEVX_COMMUNICATION_MACD >> 4U)) &&
      ((bCommSett & 0x03U) != (PHAL_MFDFEVX_COMMUNICATION_ENC >> 4U))) {
    return PH_ADD_COMPCODE_FIXED(PH_ERR_INVALID_PARAMETER, PH_COMP_AL_MFDFEVX);
  }
#endif

  /* Set the dataparams with command code. */
  pDataParams->bCmdCode = PHAL_MFDFEVX_CMD_CREATE_TRANSTN_MACFILE;

  /* form the command */
  bCmdBuff[wCmdLen++] = PHAL_MFDFEVX_CMD_CREATE_TRANSTN_MACFILE;
  bCmdBuff[wCmdLen++] = bFileNo;

  /* Copy communication settings. communication settings in the first nibble so right shifting */
  bCmdBuff[wCmdLen++] = bCommSett;

  /* Copy Access rights */
  /* Consider checking KEY TYPE passed here and accordingly
  * update the bits and store in cmd buff. */
  bCmdBuff[wCmdLen++] = pAccessRights[0];
  bCmdBuff[wCmdLen++] = pAccessRights[1];
  bCmdBuff[wCmdLen++] = bKeyType;

  (void)memcpy(&bCmdBuff[wCmdLen], bTMKey, 16);
  wCmdLen += 16U;

  bCmdBuff[wCmdLen++] = bTMKeyVer;

  /* When authenticated, CommMode.Full is applied (this is different compared to
   * the other filetypes which require CommMode.MAC as no data needs to be encrypted).
   * If not authenticated, the command is send in plain of course. */

  if (pDataParams->bAuthMode == PHAL_MFDFEVX_NOT_AUTHENTICATED) {
    /* COMMUNICATION IS PLAIN */
    return phalMfdfEVx_Sw_Int_Write_Plain(pDataParams,
            PHAL_MFDFEVX_DEFAULT_MODE,
            bCmdBuff,
            wCmdLen,
            PHAL_MFDFEVX_COMMUNICATION_PLAIN,
            NULL,
            0x0000
        );
  } else {
    return phalMfdfEVx_Sw_Int_Write_Enc(
            pDataParams,
            PHAL_MFDFEVX_DEFAULT_MODE,
            bCmdBuff,
            6,
            PH_CRYPTOSYM_PADDING_MODE_1,
            0x00,
            &bCmdBuff[6],
            (wCmdLen - 6U)
        );
  }
}
#endif /* NXPBUILD__PHAL_MFDFEVX_NDA */

phStatus_t
phalMfdfEVx_Sw_DeleteFile(phalMfdfEVx_Sw_DataParams_t *pDataParams, uint8_t bFileNo)
{
  uint8_t     PH_MEMLOC_REM bCmdBuff[8];

#ifdef RDR_LIB_PARAM_CHECK
  if ((bFileNo & 0x7fU) > 0x1fU) {
    return PH_ADD_COMPCODE_FIXED(PH_ERR_INVALID_PARAMETER, PH_COMP_AL_MFDFEVX);
  }
#endif

  /* Set the dataparams with command code. */
  pDataParams->bCmdCode = PHAL_MFDFEVX_CMD_DELETE_FILE;

  /* form the command */
  bCmdBuff[0] = PHAL_MFDFEVX_CMD_DELETE_FILE;
  bCmdBuff[1] = bFileNo;

  /* COMMUNICATION IS PLAIN */
  return phalMfdfEVx_Sw_Int_Write_Plain(pDataParams,
          PHAL_MFDFEVX_DEFAULT_MODE,
          bCmdBuff,
          2,
          (pDataParams->bAuthMode == PHAL_MFDFEVX_AUTHENTICATEEV2) ? PHAL_MFDFEVX_COMMUNICATION_MACD :
          PHAL_MFDFEVX_COMMUNICATION_PLAIN,
          NULL,
          0x0000
      );
}

phStatus_t
phalMfdfEVx_Sw_GetFileIDs(phalMfdfEVx_Sw_DataParams_t *pDataParams, uint8_t *pFid,
    uint8_t *bNumFID)
{
  phStatus_t  PH_MEMLOC_REM statusTmp;
  uint8_t     PH_MEMLOC_REM bCmdBuff[8];
  uint16_t    PH_MEMLOC_REM wRxlen = 0;
  uint8_t     PH_MEMLOC_REM *pRecv = NULL;

  /* Set the dataparams with command code. */
  pDataParams->bCmdCode = PHAL_MFDFEVX_CMD_GET_FILE_IDS;

  /* form the command */
  bCmdBuff[0] = PHAL_MFDFEVX_CMD_GET_FILE_IDS;

  PH_CHECK_SUCCESS_FCT(statusTmp, phalMfdfEVx_Sw_Int_ReadData_Plain(
          pDataParams,
          (pDataParams->bAuthMode == PHAL_MFDFEVX_AUTHENTICATEEV2) ? PHAL_MFDFEVX_COMMUNICATION_MACD :
          PHAL_MFDFEVX_COMMUNICATION_PLAIN,
          bCmdBuff,
          1,
          &pRecv,
          &wRxlen
      ));

  (void)memcpy(pFid, pRecv, wRxlen);
  *bNumFID = (uint8_t)wRxlen;

  return PH_ERR_SUCCESS;
}

phStatus_t
phalMfdfEVx_Sw_GetISOFileIDs(phalMfdfEVx_Sw_DataParams_t *pDataParams,
    uint8_t *pFidBuffer, uint8_t *pNumFID)
{
  phStatus_t  PH_MEMLOC_REM statusTmp;
  uint8_t     PH_MEMLOC_REM bCmdBuff[8];
  uint16_t    PH_MEMLOC_REM wRxlen = 0;
  uint8_t     PH_MEMLOC_REM *pRecv = NULL;

  /* Initialization */
  *pNumFID = 0;

  /* Set the dataparams with command code. */
  pDataParams->bCmdCode = PHAL_MFDFEVX_CMD_GET_ISO_FILE_IDS;

  /* form the command */
  bCmdBuff[0] = PHAL_MFDFEVX_CMD_GET_ISO_FILE_IDS;

  PH_CHECK_SUCCESS_FCT(statusTmp, phalMfdfEVx_Sw_Int_ReadData_Plain(
          pDataParams,
          (pDataParams->bAuthMode == PHAL_MFDFEVX_AUTHENTICATEEV2) ? PHAL_MFDFEVX_COMMUNICATION_MACD :
          PHAL_MFDFEVX_COMMUNICATION_PLAIN,
          bCmdBuff,
          1,
          &pRecv,
          &wRxlen
      ));

  /* Length should be multiple of 2 */
  if ((wRxlen != 0U) && (wRxlen % 2U)) {
    return PH_ADD_COMPCODE_FIXED(PH_ERR_PROTOCOL_ERROR, PH_COMP_AL_MFDFEVX);
  }
  (void)memcpy(pFidBuffer, pRecv, wRxlen);

  /* Update pNumAids and return  */
  *pNumFID = (uint8_t)(wRxlen / 2U);

  return PH_ERR_SUCCESS;
}

phStatus_t
phalMfdfEVx_Sw_GetFileSettings(phalMfdfEVx_Sw_DataParams_t *pDataParams,
    uint8_t bFileNo, uint8_t *pFSBuffer,
    uint8_t *pBufferLen)
{
  uint16_t    PH_MEMLOC_REM statusTmp;
  uint8_t     PH_MEMLOC_REM bCmdBuff[8];
  uint16_t    PH_MEMLOC_REM wRxlen = 0;
  uint8_t     PH_MEMLOC_REM *pRecv = NULL;

  /* Set the dataparams with command code. */
  pDataParams->bCmdCode = PHAL_MFDFEVX_CMD_GET_FILE_SETTINGS;

  /* form the command */
  bCmdBuff[0] = PHAL_MFDFEVX_CMD_GET_FILE_SETTINGS;
  bCmdBuff[1] = bFileNo;

  PH_CHECK_SUCCESS_FCT(statusTmp, phalMfdfEVx_Sw_Int_ReadData_Plain(
          pDataParams,
          (pDataParams->bAuthMode == PHAL_MFDFEVX_AUTHENTICATEEV2) ? PHAL_MFDFEVX_COMMUNICATION_MACD :
          PHAL_MFDFEVX_COMMUNICATION_PLAIN,
          bCmdBuff,
          2,
          &pRecv,
          &wRxlen
      ));

  /*
  * File type can be obtained by reading the zeroth index of the receive buffer
  * For Std data file, pRecv[0] = 0x00
  * For Backup data file, pRecv[0] = 0x01
  * For Value file, pRecv[0] = 0x02
  * For Linear Record file, pRecv[0] = 0x03
  * For Cyclic Record file, pRecv[0] = 0x04
  * For Transaction MAC file, pRecv[0] = 0x05
  * For TransactionMAC file wRxLen = 6 if TMCLimit is not available else 10 if TMCLimit is available.
  * For Standard file or Backup file mandatory 7 bytes and optional No. of AAR with AAR are received
  * For Value file mandatory 17 bytes and optional No. of AAR with AAR are received
  * For Linear/Cyclic Record file mandatory 13 bytes and optional No. of AAR with AAR are received
  */

  if ((pRecv[0] == 0x00U) || (pRecv[0] == 0x01U)) {
    if ((pRecv[1] & PHAL_MFDFEVX_FILE_OPTION_SDM_MIRRORING_ENABLED) ==
        PHAL_MFDFEVX_FILE_OPTION_SDM_MIRRORING_ENABLED) {
      /* Do Nothing */
    } else {
      if ((wRxlen < 7U) || ((wRxlen > 7U) && (wRxlen != (8U + (pRecv[7] * 2U))))) {
        return PH_ADD_COMPCODE_FIXED(PH_ERR_PROTOCOL_ERROR, PH_COMP_AL_MFDFEVX);
      }
    }
  } else if (pRecv[0] == 0x02U) {
    if ((wRxlen < 17U) || ((wRxlen > 17U) && (wRxlen != (18U + (pRecv[17] * 2U))))) {
      return PH_ADD_COMPCODE_FIXED(PH_ERR_PROTOCOL_ERROR, PH_COMP_AL_MFDFEVX);
    }
  } else if ((pRecv[0] == 0x03U) || (pRecv[0] == 0x04U)) {
    if ((wRxlen < 13U) || ((wRxlen > 13U) && (wRxlen != (14U + (pRecv[13] * 2U))))) {
      return PH_ADD_COMPCODE_FIXED(PH_ERR_PROTOCOL_ERROR, PH_COMP_AL_MFDFEVX);
    }
  } else if (pRecv[0] == 0x05U) {
    if (wRxlen < 0x06U) {
      return PH_ADD_COMPCODE_FIXED(PH_ERR_PROTOCOL_ERROR, PH_COMP_AL_MFDFEVX);
    }
  } else {
    return PH_ADD_COMPCODE_FIXED(PH_ERR_PROTOCOL_ERROR, PH_COMP_AL_MFDFEVX);
  }

  (void)memcpy(pFSBuffer, pRecv, wRxlen);

  /* Update pBufferLen and return  */
  *pBufferLen = (uint8_t)wRxlen;

  return PH_ERR_SUCCESS;
}

phStatus_t
phalMfdfEVx_Sw_GetFileCounters(phalMfdfEVx_Sw_DataParams_t *pDataParams,
    uint8_t bOption, uint8_t bFileNo,
    uint8_t *pFileCounters, uint8_t *pRxLen)
{
  uint16_t    PH_MEMLOC_REM statusTmp;
  uint8_t     PH_MEMLOC_REM bCmdBuff[20];
  uint16_t    PH_MEMLOC_REM wRxlen = 0;
  uint16_t    PH_MEMLOC_REM wCmdLen = 0;
  uint8_t     PH_MEMLOC_REM *pRecv = NULL;

  /* Set the dataparams with command code. */
  pDataParams->bCmdCode = PHAL_MFDFEVX_CMD_GET_FILE_COUNTERS;

  bCmdBuff[wCmdLen++] = PHAL_MFDFEVX_CMD_GET_FILE_COUNTERS;
  bCmdBuff[wCmdLen++] = bFileNo;

  if (bOption == PHAL_MFDFEVX_COMMUNICATION_PLAIN) {
    PH_CHECK_SUCCESS_FCT(statusTmp, phalMfdfEVx_Sw_Int_ReadData_Plain(
            pDataParams,
            PHAL_MFDFEVX_COMMUNICATION_PLAIN,
            bCmdBuff,
            wCmdLen,
            &pRecv,
            &wRxlen
        ));
  } else {
#ifdef NXPBUILD__PHAL_MFDFEVX_NDA
    PH_CHECK_SUCCESS_FCT(statusTmp, phalMfdfEVx_Sw_Int_ReadData_Enc(
            pDataParams,
            PHAL_MFDFEVX_COMMUNICATION_ENC,
            bCmdBuff,
            wCmdLen,
            &pRecv,
            &wRxlen
        ));
#endif /* NXPBUILD__PHAL_MFDFEVX_NDA */

  }

  *pRxLen = (uint8_t)wRxlen;
  (void)memcpy(pFileCounters, pRecv, wRxlen);

  return PH_ERR_SUCCESS;
}

phStatus_t
phalMfdfEVx_Sw_ChangeFileSettings(phalMfdfEVx_Sw_DataParams_t *pDataParams,
    uint8_t bOption,
    uint8_t bFileNo, uint8_t bFileOption, uint8_t *pAccessRights, uint8_t bAddInfoLen,
    uint8_t *pAddInfo)
{
  uint8_t     PH_MEMLOC_REM aCmdBuff[2];
  uint8_t     PH_MEMLOC_REM bCmdLen = 0;
  uint8_t     PH_MEMLOC_REM aDataBuff[50];
  uint8_t     PH_MEMLOC_REM bDataLen = 0;
  uint8_t     PH_MEMLOC_REM bAddARsLen = 0;

#ifdef RDR_LIB_PARAM_CHECK
  if ((bFileNo & 0x3fU) > 0x1fU) {
    return PH_ADD_COMPCODE_FIXED(PH_ERR_INVALID_PARAMETER, PH_COMP_AL_MFDFEVX);
  }

  if (((bFileOption & 0x03U) != (PHAL_MFDFEVX_COMMUNICATION_PLAIN >> 4U)) &&
      ((bFileOption & 0x03U) != (PHAL_MFDFEVX_COMMUNICATION_ENC >> 4U)) &&
      ((bFileOption & 0x03U) != (PHAL_MFDFEVX_COMMUNICATION_MACD >> 4U))) {
    return PH_ADD_COMPCODE_FIXED(PH_ERR_INVALID_PARAMETER, PH_COMP_AL_MFDFEVX);
  }
#endif

  /* Frame the command. */
  aCmdBuff[bCmdLen++] = PHAL_MFDFEVX_CMD_CHANGE_FILE_SETTINGS;
  aCmdBuff[bCmdLen++] = bFileNo;

  /* Frame the data. */
  aDataBuff[bDataLen++] = bFileOption;
  aDataBuff[bDataLen++] = pAccessRights[0];
  aDataBuff[bDataLen++] = pAccessRights[1];

  /* Exchange the informatio as is to PICC. */
  if (0U != (bOption & PHAL_MFDFEVX_EXCHANGE_ADD_INFO_BUFFER_COMPLETE)) {
    (void)memcpy(&aDataBuff[bDataLen], pAddInfo, bAddInfoLen);
    bDataLen += bAddInfoLen;
  } else {
    if (0U != (bFileOption & PHAL_MFDFEVX_FILE_OPTION_ADDITIONAL_AR_PRESENT)) {
      /* Compute the Additional ACCESS Rights length. */
      bAddARsLen = (uint8_t)((bFileOption & PHAL_MFDFEVX_FILE_OPTION_TMCLIMIT_PRESENT) ?
              (bAddInfoLen - 4) : bAddInfoLen);

      aDataBuff[bDataLen++] = bAddARsLen;
      (void)memcpy(&aDataBuff[bDataLen], pAddInfo, (bAddARsLen * 2U));
      bDataLen += (bAddARsLen * 2U);
    }

    /* TMCLimit buffer in command buffer if Bit5 of File Option is SET. */
    if (0U != (bFileOption & PHAL_MFDFEVX_FILE_OPTION_TMCLIMIT_PRESENT)) {
      (void)memcpy(&aDataBuff[bDataLen], &pAddInfo[bAddARsLen], 4U);
      bDataLen += 4U;
    }
  }

  if (((bOption & 0x30U) == PHAL_MFDFEVX_COMMUNICATION_PLAIN) ||
      ((bOption & 0x30U) == PHAL_MFDFEVX_COMMUNICATION_MACD)) {
    /* Update the payload len. */
    pDataParams->dwPayLoadLen = bDataLen;

    /* COMMUNICATION IS PLAIN */
    return phalMfdfEVx_Sw_Int_Write_Plain(pDataParams, PHAL_MFDFEVX_ISO_CHAINING_MODE, aCmdBuff,
            bCmdLen,
            PHAL_MFDFEVX_COMMUNICATION_PLAIN, aDataBuff, bDataLen);
  }
#ifdef NXPBUILD__PHAL_MFDFEVX_NDA
  else if ((bOption & 0x30U) == PHAL_MFDFEVX_COMMUNICATION_ENC) {
    return phalMfdfEVx_Sw_Int_Write_New(pDataParams, (uint8_t)(bOption & 0x30U), aCmdBuff, bCmdLen,
            aDataBuff, bDataLen);
  }
#endif /* NXPBUILD__PHAL_MFDFEVX_NDA */
  else {
    return PH_ADD_COMPCODE_FIXED(PH_ERR_INVALID_PARAMETER, PH_COMP_AL_MFDFEVX);
  }
}

/* MIFARE DESFire EVx Data mamangement commands. --------------------------------------------------------------------------------------- */
phStatus_t
phalMfdfEVx_Sw_ReadData(phalMfdfEVx_Sw_DataParams_t *pDataParams, uint8_t bOption,
    uint8_t bIns,
    uint8_t bFileNo, uint8_t *pOffset, uint8_t *pLength, uint8_t **ppRxdata, uint16_t *pRxdataLen)
{
  /* The signature of this is changed. We include
  * the bIns as third parameter that will differentiate
  * between application chaining and ISO chaining modes
  */
  phStatus_t  PH_MEMLOC_REM status = 0;
  phStatus_t  PH_MEMLOC_REM statusTmp;
  uint8_t     PH_MEMLOC_REM bCmdBuff[16];
  uint8_t     PH_MEMLOC_REM bTmp = 0;
  uint16_t    PH_MEMLOC_REM wCmdLen = 0;
  uint32_t    PH_MEMLOC_REM dwTMIStatus = 0;
  uint32_t    PH_MEMLOC_REM dwDataLen = 0;
  uint8_t     PH_MEMLOC_REM bShortLengthApduValue = 0;

  /* Set the dataparams with command code. */
  pDataParams->bCmdCode = (uint8_t)(bIns ? PHAL_MFDFEVX_CMD_READ_DATA_ISO :
          PHAL_MFDFEVX_CMD_READ_DATA);

#ifdef RDR_LIB_PARAM_CHECK
  /* bit[1] of bIns will also be used. Hence bIns should be checked for above 0x03*/
  if (((bFileNo & 0x7fU) > 0x1fU) || (bIns > 0x03U)) {
    return PH_ADD_COMPCODE_FIXED(PH_ERR_INVALID_PARAMETER, PH_COMP_AL_MFDFEVX);
  }
#endif
  if ((bOption & 0x0FU) == PH_EXCHANGE_RXCHAINING) {
    bCmdBuff[wCmdLen++] = PHAL_MFDFEVX_RESP_ADDITIONAL_FRAME;
  } else if ((bOption & 0x0FU) == PH_EXCHANGE_DEFAULT) {
    /* copy data length */
    dwDataLen = pLength[2];
    dwDataLen = (dwDataLen << 8U) | pLength[1];
    dwDataLen = (dwDataLen << 8U) | pLength[0];
    /* Set the format of data to be sent as short APDU when,
    * 1. bit[1] of bIns is set. This means user is force sending the data in short APDU format in case of BIGISO read.
    * 2. In case data to be read is not BIGISO(Less than 256 bytes).
    */
    if ((bIns & 0x02U) || ((dwDataLen <= 0xFFU) && (dwDataLen != 0U))) {
      /* Setting parameter 'bShortLenApdu' in EVx data Structure for Short Length APDUs */
      bShortLengthApduValue = 0x01;
      PH_CHECK_SUCCESS_FCT(statusTmp, phalMfdfEVx_Sw_SetConfig(pDataParams,
              PHAL_MFDFEVX_SHORT_LENGTH_APDU,
              bShortLengthApduValue));
      /* Reset Bit[1] of 'bIns' for subsequent operations */
      bIns &= 0xFDU;
    }
    if (bIns == 0x00U) {
      bCmdBuff[wCmdLen++] = PHAL_MFDFEVX_CMD_READ_DATA;
    } else {
      bCmdBuff[wCmdLen++] = PHAL_MFDFEVX_CMD_READ_DATA_ISO;
    }

    bCmdBuff[wCmdLen++] = bFileNo;
    (void)memcpy(&bCmdBuff[wCmdLen], pOffset, 3);
    wCmdLen += 3U;
    (void)memcpy(&bCmdBuff[wCmdLen], pLength, 3);
    wCmdLen += 3U;

    PH_CHECK_SUCCESS_FCT(statusTmp, phTMIUtils_GetConfig((phTMIUtils_t *)pDataParams->pTMIDataParams,
            PH_TMIUTILS_TMI_STATUS,
            &dwTMIStatus));

    /* Check TMI Collection Status */
    if (dwTMIStatus == PH_ON) {
      PH_CHECK_SUCCESS_FCT(statusTmp, phTMIUtils_CollectTMI((phTMIUtils_t *)pDataParams->pTMIDataParams,
              (uint8_t)((dwDataLen == 0U) ? (PH_TMIUTILS_READ_INS | PH_TMIUTILS_ZEROPAD_CMDBUFF) :
                  PH_TMIUTILS_ZEROPAD_CMDBUFF),
              bCmdBuff,
              wCmdLen,
              NULL,
              0,
              PHAL_MFDFEVX_BLOCK_SIZE
          ));
    }
  } else {
    return PH_ADD_COMPCODE_FIXED(PH_ERR_INVALID_PARAMETER, PH_COMP_AL_MFDFEVX);
  }

  if ((bOption & 0xF0U) == PHAL_MFDFEVX_COMMUNICATION_ENC) {
#ifdef NXPBUILD__PHAL_MFDFEVX_NDA
    /* Upload Payload size for proper CRC calculation */
    if ((bOption & 0x0FU) != PH_EXCHANGE_RXCHAINING) {
      pDataParams->dwPayLoadLen = dwDataLen;
    }

    status = phalMfdfEVx_Sw_Int_ReadData_Enc(
            pDataParams,
            bOption | ((bIns == 0x00U) ? PHAL_MFDFEVX_DEFAULT_MODE : PHAL_MFDFEVX_ISO_CHAINING_MODE),
            bCmdBuff,
            wCmdLen,
            ppRxdata,
            pRxdataLen
        );
#endif /* NXPBUILD__PHAL_MFDFEVX_NDA */
  } else if (((bOption & 0xF0U) == PHAL_MFDFEVX_COMMUNICATION_MACD) ||
      ((bOption & 0xF0U) == PHAL_MFDFEVX_COMMUNICATION_PLAIN)) {

    if ((pDataParams->bAuthMode == PHAL_MFDFEVX_AUTHENTICATE) &&
        ((bOption & 0xF0U) == PHAL_MFDFEVX_COMMUNICATION_MACD)) {
      bOption = bOption | PHAL_MFDFEVX_COMMUNICATION_MAC_ON_RC;
    }

    status = phalMfdfEVx_Sw_Int_ReadData_Plain(
            pDataParams,
            bOption | ((bIns == 0x00U) ? PHAL_MFDFEVX_DEFAULT_MODE : PHAL_MFDFEVX_ISO_CHAINING_MODE),
            bCmdBuff,
            wCmdLen,
            ppRxdata,
            pRxdataLen
        );
  } else {
    return PH_ADD_COMPCODE_FIXED(PH_ERR_INVALID_PARAMETER, PH_COMP_AL_MFDFEVX);
  }

  /* Restoring the Extended Length APDU mode */
  bShortLengthApduValue = 0x00;
  PH_CHECK_SUCCESS_FCT(statusTmp, phalMfdfEVx_Sw_SetConfig(pDataParams,
          PHAL_MFDFEVX_SHORT_LENGTH_APDU,
          bShortLengthApduValue));
  if ((status == PH_ERR_SUCCESS) && (bCmdBuff[0] != PHAL_MFDFEVX_RESP_ADDITIONAL_FRAME)) {
    if ((dwDataLen != *pRxdataLen) && (dwDataLen != 0U)) {
      /* Reset authentication status */
      if ((pDataParams->bAuthMode == PHAL_MFDFEVX_AUTHENTICATEISO) ||
          (pDataParams->bAuthMode == PHAL_MFDFEVX_AUTHENTICATEAES) ||
          (pDataParams->bAuthMode == PHAL_MFDFEVX_AUTHENTICATEEV2)) {
        phalMfdfEVx_Sw_Int_ResetAuthStatus(pDataParams);
      }
      return PH_ADD_COMPCODE_FIXED(PH_ERR_PROTOCOL_ERROR, PH_COMP_AL_MFDFEVX);
    }
  }
  /* Check TMI Collection Status */
  if (dwTMIStatus == PH_ON) {
    if (dwDataLen == 0U) {
      bTmp = PH_TMIUTILS_READ_INS;
    }
    if (status == PH_ERR_SUCCESS) {
      bTmp |= PH_TMIUTILS_ZEROPAD_DATABUFF;
    }

    PH_CHECK_SUCCESS_FCT(statusTmp, phTMIUtils_CollectTMI((phTMIUtils_t *)pDataParams->pTMIDataParams,
            bTmp,
            NULL,
            0,
            *ppRxdata,
            *pRxdataLen,
            PHAL_MFDFEVX_BLOCK_SIZE
        ));

    if ((status == PH_ERR_SUCCESS) && (dwDataLen == 0U)) {
      /* Reset wOffsetInTMI to 0 */
      PH_CHECK_SUCCESS_FCT(statusTmp, phTMIUtils_SetConfig((phTMIUtils_t *)pDataParams->pTMIDataParams,
              PH_TMIUTILS_TMI_OFFSET_LENGTH,
              0
          ));
    }
  }
  return status;
}

phStatus_t
phalMfdfEVx_Sw_WriteData(phalMfdfEVx_Sw_DataParams_t *pDataParams, uint8_t bCommOption,
    uint8_t bIns,
    uint8_t bFileNo, uint8_t *pOffset, uint8_t *pData, uint8_t *pDataLen)
{
  /* The signature of this is changed. We include
  * the bIns as third parameter that will differentiate
  * between application chaining and ISO chaining modes
  */
  phStatus_t  PH_MEMLOC_REM statusTmp;
  uint8_t     PH_MEMLOC_REM bCommOptionTemp = bCommOption;
  uint8_t     PH_MEMLOC_REM bLoopData = 1;
#ifdef NXPBUILD__PHAL_MFDFEVX_NDA
  uint8_t     PH_MEMLOC_REM bIvLen = PH_CRYPTOSYM_DES_BLOCK_SIZE;
#endif /* NXPBUILD__PHAL_MFDFEVX_NDA */
  uint8_t     PH_MEMLOC_REM bCmdBuff[16];
  uint16_t    PH_MEMLOC_REM wCmdLen = 0;
  uint16_t    PH_MEMLOC_REM wDataLenTemp;
  uint32_t    PH_MEMLOC_REM dwDataLen;
  uint32_t    PH_MEMLOC_REM dwTMIStatus = 0;
  uint32_t    PH_MEMLOC_REM dwDataWritten = 0;

#ifdef RDR_LIB_PARAM_CHECK
  if (((bFileNo & 0x7fU) > 0x1fU) || (bIns > 0x01U)) {
    return PH_ADD_COMPCODE_FIXED(PH_ERR_INVALID_PARAMETER, PH_COMP_AL_MFDFEVX);
  }
  if ((bCommOption != PHAL_MFDFEVX_COMMUNICATION_PLAIN) &&
      (bCommOption != PHAL_MFDFEVX_COMMUNICATION_ENC) &&
      (bCommOption != PHAL_MFDFEVX_COMMUNICATION_MACD)) {
    return PH_ADD_COMPCODE_FIXED(PH_ERR_INVALID_PARAMETER, PH_COMP_AL_MFDFEVX);
  }
#endif

  /* Set the dataparams with command code. */
  pDataParams->bCmdCode = (uint8_t)(bIns ? PHAL_MFDFEVX_CMD_WRITE_DATA_ISO :
          PHAL_MFDFEVX_CMD_WRITE_DATA);

  /* form the command depending on bIns */
  if (bIns == 0x00U) {
    bCmdBuff[wCmdLen++] = PHAL_MFDFEVX_CMD_WRITE_DATA;
  } else {
    bCmdBuff[wCmdLen++] = PHAL_MFDFEVX_CMD_WRITE_DATA_ISO;
  }
  bCmdBuff[wCmdLen++] = bFileNo;
  (void)memcpy(&bCmdBuff[wCmdLen], pOffset, 3);
  wCmdLen += 3U;
  (void)memcpy(&bCmdBuff[wCmdLen], pDataLen, 3);
  wCmdLen += 3U;

  /* copy data length */
  dwDataLen = pDataLen[2];
  dwDataLen = (dwDataLen << 8U) | pDataLen[1];
  dwDataLen = (dwDataLen << 8U) | pDataLen[0];

  /* to handle 2 MB of data update maximum of data bytes that can be sent in a single loop */
  if (dwDataLen > PHAL_MFDFEVX_MAX_WRITE_SIZE) {
    wDataLenTemp = (uint16_t)PHAL_MFDFEVX_MAX_WRITE_SIZE;
    bLoopData = (uint8_t)(dwDataLen / PHAL_MFDFEVX_MAX_WRITE_SIZE);
    if (0U != (dwDataLen % PHAL_MFDFEVX_MAX_WRITE_SIZE)) {
      bLoopData++;
    }
    bCommOptionTemp = PHAL_MFDFEVX_MAC_DATA_INCOMPLETE | bCommOption;
  } else {
    wDataLenTemp = (uint16_t)dwDataLen;
  }

  /* update the total number of data to be written
  * when INS and wrapped mode is enable, we need to send the total number of bytes with Le */
  pDataParams->dwPayLoadLen = dwDataLen;

  if (pDataParams->bAuthMode == PHAL_MFDFEVX_NOT_AUTHENTICATED) {
    bCommOption = PHAL_MFDFEVX_COMMUNICATION_PLAIN;
  }
#ifdef NXPBUILD__PHAL_MFDFEVX_NDA
  else {
    if ((bCommOption & 0xF0U) == PHAL_MFDFEVX_COMMUNICATION_MACD) {
      pDataParams->dwPayLoadLen = pDataParams->dwPayLoadLen + ((pDataParams->bAuthMode ==
                  PHAL_MFDFEVX_AUTHENTICATE) ? 0x04 : 0x08);
    }
    if ((bCommOption & 0xF0U) == PHAL_MFDFEVX_COMMUNICATION_ENC) {
      if (pDataParams->bAuthMode == PHAL_MFDFEVX_AUTHENTICATEEV2) {
        pDataParams->dwPayLoadLen = 8 + pDataParams->dwPayLoadLen + ((pDataParams->dwPayLoadLen %
                    PH_CRYPTOSYM_AES_BLOCK_SIZE) ?
                (PH_CRYPTOSYM_AES_BLOCK_SIZE - (pDataParams->dwPayLoadLen % PH_CRYPTOSYM_AES_BLOCK_SIZE)) :
                PH_CRYPTOSYM_AES_BLOCK_SIZE);
      } else {
        pDataParams->dwPayLoadLen = pDataParams->dwPayLoadLen + ((pDataParams->bAuthMode ==
                    PHAL_MFDFEVX_AUTHENTICATE) ? 0x02 : 0x04);
        bIvLen = (pDataParams->bAuthMode == PHAL_MFDFEVX_AUTHENTICATEAES) ? PH_CRYPTOSYM_AES_BLOCK_SIZE :
            PH_CRYPTOSYM_DES_BLOCK_SIZE;

        if (0U != (pDataParams->dwPayLoadLen % bIvLen)) {
          pDataParams->dwPayLoadLen = pDataParams->dwPayLoadLen + (bIvLen - (pDataParams->dwPayLoadLen %
                      bIvLen));
        }
      }
    }
  }
#endif /* NXPBUILD__PHAL_MFDFEVX_NDA */

  PH_CHECK_SUCCESS_FCT(statusTmp, phTMIUtils_GetConfig((phTMIUtils_t *)pDataParams->pTMIDataParams,
          PH_TMIUTILS_TMI_STATUS,
          &dwTMIStatus));

  /* Check TMI Collection Status */
  if (dwTMIStatus == PH_ON) {
    PH_CHECK_SUCCESS_FCT(statusTmp, phTMIUtils_CollectTMI((phTMIUtils_t *)pDataParams->pTMIDataParams,
            (PH_TMIUTILS_ZEROPAD_CMDBUFF | PH_TMIUTILS_ZEROPAD_DATABUFF),
            bCmdBuff,
            wCmdLen,
            pData,
            dwDataLen,
            PHAL_MFDFEVX_BLOCK_SIZE
        ));
  }

  do {
    if (bLoopData == 1U) {
      bCommOptionTemp = bCommOption;
      wDataLenTemp = (uint16_t)(dwDataLen - dwDataWritten);
    }
    if ((bCommOption & 0xF0U) == PHAL_MFDFEVX_COMMUNICATION_ENC) {
#ifdef NXPBUILD__PHAL_MFDFEVX_NDA
      statusTmp = phalMfdfEVx_Sw_Int_Write_Enc(
              pDataParams,
              ((bIns == 0x00U) ? PHAL_MFDFEVX_DEFAULT_MODE : PHAL_MFDFEVX_ISO_CHAINING_MODE),
              bCmdBuff,
              wCmdLen,
              PH_CRYPTOSYM_PADDING_MODE_1,
              bCommOptionTemp,
              &pData[dwDataWritten],
              wDataLenTemp
          );
#endif /* NXPBUILD__PHAL_MFDFEVX_NDA */
    } else {
      statusTmp = phalMfdfEVx_Sw_Int_Write_Plain(
              pDataParams,
              ((bIns == 0x00U) ? PHAL_MFDFEVX_DEFAULT_MODE : PHAL_MFDFEVX_ISO_CHAINING_MODE),
              bCmdBuff,
              wCmdLen,
              bCommOptionTemp,
              &pData[dwDataWritten],
              wDataLenTemp
          );
    }

    if ((statusTmp & PH_ERR_MASK) != PH_ERR_SUCCESS_CHAINING) {
      return statusTmp;
    }

    bLoopData--;
    dwDataWritten += wDataLenTemp;

    bCmdBuff[0] = 0xAF;
    wCmdLen = 1;

  } while (bLoopData > 0U);

  return statusTmp;

}

phStatus_t
phalMfdfEVx_Sw_GetValue(phalMfdfEVx_Sw_DataParams_t *pDataParams, uint8_t bCommOption,
    uint8_t bFileNo,
    uint8_t *pValue)
{

  /* If not authenticated, send the data and get the value in plain.
  Else use the mode dictated by the caller of this API
  */
  phStatus_t  PH_MEMLOC_REM statusTmp;
  uint8_t     PH_MEMLOC_REM bCmdBuff[8];
  uint16_t    PH_MEMLOC_REM wRxlen = 0;
  uint8_t     PH_MEMLOC_REM *pRecv = NULL;
  uint32_t    PH_MEMLOC_REM dwTMIStatus = 0;

#ifdef RDR_LIB_PARAM_CHECK
  if ((bFileNo & 0x7fU) > 0x1fU) {
    return PH_ADD_COMPCODE_FIXED(PH_ERR_INVALID_PARAMETER, PH_COMP_AL_MFDFEVX);
  }
  if ((bCommOption != PHAL_MFDFEVX_COMMUNICATION_PLAIN) &&
      (bCommOption != PHAL_MFDFEVX_COMMUNICATION_ENC) &&
      (bCommOption != PHAL_MFDFEVX_COMMUNICATION_MACD)) {
    return PH_ADD_COMPCODE_FIXED(PH_ERR_INVALID_PARAMETER, PH_COMP_AL_MFDFEVX);
  }
#endif

  /* Set the dataparams with command code. */
  pDataParams->bCmdCode = PHAL_MFDFEVX_CMD_GET_VALUE;

  /* form the command */
  bCmdBuff[0] = PHAL_MFDFEVX_CMD_GET_VALUE;
  bCmdBuff[1] = bFileNo;

  if ((bCommOption & 0xF0U) == PHAL_MFDFEVX_COMMUNICATION_ENC) {
#ifdef NXPBUILD__PHAL_MFDFEVX_NDA
    /* Upload Payload size for proper CRC calculation */
    pDataParams->dwPayLoadLen = 4;

    PH_CHECK_SUCCESS_FCT(statusTmp, phalMfdfEVx_Sw_Int_ReadData_Enc(
            pDataParams,
            bCommOption,
            bCmdBuff,
            2,
            &pRecv,
            &wRxlen
        ));
#endif /* NXPBUILD__PHAL_MFDFEVX_NDA */
  } else {
    /* For EV2, bCommOption == MACD means the cmd+MAC is sent to card
    * and a MAC on response is received.
    * Hope this is taken care of in readdata_plain
    */

    if ((pDataParams->bAuthMode == PHAL_MFDFEVX_AUTHENTICATE) &&
        ((bCommOption & 0xF0U) == PHAL_MFDFEVX_COMMUNICATION_MACD)) {
      bCommOption = bCommOption | PHAL_MFDFEVX_COMMUNICATION_MAC_ON_RC;
    }

    PH_CHECK_SUCCESS_FCT(statusTmp, phalMfdfEVx_Sw_Int_ReadData_Plain(
            pDataParams,
            bCommOption,
            bCmdBuff,
            2,
            &pRecv,
            &wRxlen
        ));
  }

  if (wRxlen != 4U) {
    return PH_ADD_COMPCODE_FIXED(PH_ERR_PROTOCOL_ERROR, PH_COMP_AL_MFDFEVX);
  }
  (void)memcpy(pValue, pRecv, wRxlen);

  PH_CHECK_SUCCESS_FCT(statusTmp, phTMIUtils_GetConfig((phTMIUtils_t *)pDataParams->pTMIDataParams,
          PH_TMIUTILS_TMI_STATUS,
          &dwTMIStatus));

  /* Check TMI Collection Status */
  if (dwTMIStatus == PH_ON) {
    PH_CHECK_SUCCESS_FCT(statusTmp, phTMIUtils_CollectTMI((phTMIUtils_t *)pDataParams->pTMIDataParams,
            PH_TMIUTILS_ZEROPAD_DATABUFF,
            bCmdBuff,
            2,
            pValue,
            4,
            PHAL_MFDFEVX_BLOCK_SIZE
        ));
  }

  return PH_ERR_SUCCESS;
}

phStatus_t
phalMfdfEVx_Sw_Credit(phalMfdfEVx_Sw_DataParams_t *pDataParams, uint8_t bCommOption,
    uint8_t bFileNo,
    uint8_t *pValue)
{
  uint8_t     PH_MEMLOC_REM bCmdBuff[8];
  uint16_t    PH_MEMLOC_REM wCmdLen = 0;
  uint32_t    PH_MEMLOC_REM dwTMIStatus = 0;
  phStatus_t  PH_MEMLOC_REM statusTmp;
  phStatus_t status = 0;

#ifdef RDR_LIB_PARAM_CHECK
  if ((bFileNo & 0x7fU) > 0x1fU) {
    return PH_ADD_COMPCODE_FIXED(PH_ERR_INVALID_PARAMETER, PH_COMP_AL_MFDFEVX);
  }
  if ((bCommOption != PHAL_MFDFEVX_COMMUNICATION_PLAIN) &&
      (bCommOption != PHAL_MFDFEVX_COMMUNICATION_ENC) &&
      (bCommOption != PHAL_MFDFEVX_COMMUNICATION_MACD)) {
    return PH_ADD_COMPCODE_FIXED(PH_ERR_INVALID_PARAMETER, PH_COMP_AL_MFDFEVX);
  }
#endif

  /* Set the dataparams with command code. */
  pDataParams->bCmdCode = PHAL_MFDFEVX_CMD_CREDIT;

  /* form the command */
  bCmdBuff[wCmdLen++] = PHAL_MFDFEVX_CMD_CREDIT;
  bCmdBuff[wCmdLen++] = bFileNo;

  (void)memcpy(&bCmdBuff[wCmdLen], pValue, 4);
  wCmdLen += 4U;

  PH_CHECK_SUCCESS_FCT(statusTmp, phTMIUtils_GetConfig((phTMIUtils_t *)pDataParams->pTMIDataParams,
          PH_TMIUTILS_TMI_STATUS,
          &dwTMIStatus));

  /* Check TMI Collection Status */
  if (dwTMIStatus == PH_ON) {
    PH_CHECK_SUCCESS_FCT(statusTmp, phTMIUtils_CollectTMI((phTMIUtils_t *)pDataParams->pTMIDataParams,
            PH_TMIUTILS_ZEROPAD_CMDBUFF,
            bCmdBuff,
            wCmdLen,
            NULL,
            0,
            PHAL_MFDFEVX_BLOCK_SIZE
        ));
  }

  if ((bCommOption & 0xF0U) == PHAL_MFDFEVX_COMMUNICATION_ENC) {
#ifdef NXPBUILD__PHAL_MFDFEVX_NDA
    status = phalMfdfEVx_Sw_Int_Write_Enc(pDataParams,
            PHAL_MFDFEVX_DEFAULT_MODE,
            bCmdBuff,
            0x0002,
            PH_CRYPTOSYM_PADDING_MODE_1,
            0x00,
            &bCmdBuff[2],
            0x0004
        );
#endif /* NXPBUILD__PHAL_MFDFEVX_NDA */
  } else {
    /* COMMUNICATION IS PLAIN */
    /* Need to differentiate between plain and MACD mode
    * for AuthEVX mode
    */
    status = phalMfdfEVx_Sw_Int_Write_Plain(pDataParams,
            PHAL_MFDFEVX_DEFAULT_MODE,
            bCmdBuff,
            0x0002,
            bCommOption,
            &bCmdBuff[2],
            0x0004
        );
  }
  return status;
}

phStatus_t
phalMfdfEVx_Sw_Debit(phalMfdfEVx_Sw_DataParams_t *pDataParams, uint8_t bCommOption,
    uint8_t bFileNo,
    uint8_t *pValue)
{
  uint8_t     PH_MEMLOC_REM bCmdBuff[8];
  uint16_t    PH_MEMLOC_REM wCmdLen = 0;
  uint32_t    PH_MEMLOC_REM dwTMIStatus = 0;
  phStatus_t  PH_MEMLOC_REM statusTmp;
  phStatus_t status = 0;

#ifdef RDR_LIB_PARAM_CHECK
  if ((bFileNo & 0x7fU) > 0x1fU) {
    return PH_ADD_COMPCODE_FIXED(PH_ERR_INVALID_PARAMETER, PH_COMP_AL_MFDFEVX);
  }
  if ((bCommOption != PHAL_MFDFEVX_COMMUNICATION_PLAIN) &&
      (bCommOption != PHAL_MFDFEVX_COMMUNICATION_ENC) &&
      (bCommOption != PHAL_MFDFEVX_COMMUNICATION_MACD)) {
    return PH_ADD_COMPCODE_FIXED(PH_ERR_INVALID_PARAMETER, PH_COMP_AL_MFDFEVX);
  }
#endif

  /* Set the dataparams with command code. */
  pDataParams->bCmdCode = PHAL_MFDFEVX_CMD_DEBIT;

  /* form the command */
  bCmdBuff[wCmdLen++] = PHAL_MFDFEVX_CMD_DEBIT;
  bCmdBuff[wCmdLen++] = bFileNo;

  (void)memcpy(&bCmdBuff[wCmdLen], pValue, 4);
  wCmdLen += 4U;

  PH_CHECK_SUCCESS_FCT(statusTmp, phTMIUtils_GetConfig((phTMIUtils_t *)pDataParams->pTMIDataParams,
          PH_TMIUTILS_TMI_STATUS,
          &dwTMIStatus));

  /* Check TMI Collection Status */
  if (dwTMIStatus == PH_ON) {
    PH_CHECK_SUCCESS_FCT(statusTmp, phTMIUtils_CollectTMI((phTMIUtils_t *)pDataParams->pTMIDataParams,
            PH_TMIUTILS_ZEROPAD_CMDBUFF,
            bCmdBuff,
            wCmdLen,
            NULL,
            0,
            PHAL_MFDFEVX_BLOCK_SIZE
        ));
  }

  if ((bCommOption & 0xF0U) == PHAL_MFDFEVX_COMMUNICATION_ENC) {
#ifdef NXPBUILD__PHAL_MFDFEVX_NDA
    status = phalMfdfEVx_Sw_Int_Write_Enc(pDataParams,
            PHAL_MFDFEVX_DEFAULT_MODE,
            bCmdBuff,
            0x0002,
            PH_CRYPTOSYM_PADDING_MODE_1,
            0x00,
            &bCmdBuff[2],
            0x0004
        );
#endif /* NXPBUILD__PHAL_MFDFEVX_NDA */
  } else {
    /* COMMUNICATION IS PLAIN */
    status = phalMfdfEVx_Sw_Int_Write_Plain(pDataParams,
            PHAL_MFDFEVX_DEFAULT_MODE,
            bCmdBuff,
            0x0002,
            bCommOption,
            &bCmdBuff[2],
            0x0004
        );
  }
  return status;
}

phStatus_t
phalMfdfEVx_Sw_LimitedCredit(phalMfdfEVx_Sw_DataParams_t *pDataParams,
    uint8_t bCommOption, uint8_t bFileNo,
    uint8_t *pValue)
{
  uint8_t     PH_MEMLOC_REM bCmdBuff[8];
  uint16_t    PH_MEMLOC_REM wCmdLen = 0;
  uint32_t    PH_MEMLOC_REM dwTMIStatus = 0;
  phStatus_t  PH_MEMLOC_REM statusTmp;
  phStatus_t status = 0;

#ifdef RDR_LIB_PARAM_CHECK
  if ((bFileNo & 0x7fU) > 0x1fU) {
    return PH_ADD_COMPCODE_FIXED(PH_ERR_INVALID_PARAMETER, PH_COMP_AL_MFDFEVX);
  }
  if ((bCommOption != PHAL_MFDFEVX_COMMUNICATION_PLAIN) &&
      (bCommOption != PHAL_MFDFEVX_COMMUNICATION_ENC) &&
      (bCommOption != PHAL_MFDFEVX_COMMUNICATION_MACD)) {
    return PH_ADD_COMPCODE_FIXED(PH_ERR_INVALID_PARAMETER, PH_COMP_AL_MFDFEVX);
  }
#endif

  /* Set the dataparams with command code. */
  pDataParams->bCmdCode = PHAL_MFDFEVX_CMD_LIMITED_CREDIT;

  /* form the command */
  bCmdBuff[wCmdLen++] = PHAL_MFDFEVX_CMD_LIMITED_CREDIT;
  bCmdBuff[wCmdLen++] = bFileNo;

  (void)memcpy(&bCmdBuff[wCmdLen], pValue, 4);
  wCmdLen += 4U;

  PH_CHECK_SUCCESS_FCT(statusTmp, phTMIUtils_GetConfig((phTMIUtils_t *)pDataParams->pTMIDataParams,
          PH_TMIUTILS_TMI_STATUS,
          &dwTMIStatus));

  /* Check TMI Collection Status */
  if (dwTMIStatus == PH_ON) {
    PH_CHECK_SUCCESS_FCT(statusTmp, phTMIUtils_CollectTMI((phTMIUtils_t *)pDataParams->pTMIDataParams,
            PH_TMIUTILS_ZEROPAD_CMDBUFF,
            bCmdBuff,
            wCmdLen,
            NULL,
            0,
            PHAL_MFDFEVX_BLOCK_SIZE
        ));
  }

  if ((bCommOption & 0xF0U) == PHAL_MFDFEVX_COMMUNICATION_ENC) {
#ifdef NXPBUILD__PHAL_MFDFEVX_NDA
    status = phalMfdfEVx_Sw_Int_Write_Enc(pDataParams,
            PHAL_MFDFEVX_DEFAULT_MODE,
            bCmdBuff,
            0x0002,
            PH_CRYPTOSYM_PADDING_MODE_1,
            0x00,
            &bCmdBuff[2],
            0x0004
        );
#endif /* NXPBUILD__PHAL_MFDFEVX_NDA */
  } else {
    /* COMMUNICATION IS PLAIN */
    status = phalMfdfEVx_Sw_Int_Write_Plain(pDataParams,
            PHAL_MFDFEVX_DEFAULT_MODE,
            bCmdBuff,
            0x0002,
            bCommOption,
            &bCmdBuff[2],
            0x0004
        );
  }
  return status;
}

phStatus_t
phalMfdfEVx_Sw_WriteRecord(phalMfdfEVx_Sw_DataParams_t *pDataParams,
    uint8_t bCommOption, uint8_t bIns, uint8_t bFileNo, uint8_t *pOffset,
    uint8_t *pData, uint8_t *pDataLen)
{
  phStatus_t  PH_MEMLOC_REM statusTmp;
  uint8_t     PH_MEMLOC_REM bCmdBuff[8];
  uint8_t     PH_MEMLOC_REM bCommOptionTemp = bCommOption;
  uint8_t     PH_MEMLOC_REM bLoopData = 1;
#ifdef NXPBUILD__PHAL_MFDFEVX_NDA
  uint8_t     PH_MEMLOC_REM bIvLen = PH_CRYPTOSYM_DES_BLOCK_SIZE;
#endif /*NXPBUILD__PHAL_MFDFEVX_NDA */
  uint16_t    PH_MEMLOC_REM wDataLenTemp;
  uint16_t    PH_MEMLOC_REM wCmdLen = 0;
  uint32_t    PH_MEMLOC_REM dwDataLen;
  uint32_t    PH_MEMLOC_REM dwTMIStatus = 0;
  uint32_t    PH_MEMLOC_REM dwDataWritten = 0;

#ifdef RDR_LIB_PARAM_CHECK
  if (((bFileNo & 0x7fU) > 0x1fU) || (bIns > 0x01U)) {
    return PH_ADD_COMPCODE_FIXED(PH_ERR_INVALID_PARAMETER, PH_COMP_AL_MFDFEVX);
  }
  if ((bCommOption != PHAL_MFDFEVX_COMMUNICATION_PLAIN) &&
      (bCommOption != PHAL_MFDFEVX_COMMUNICATION_ENC) &&
      (bCommOption != PHAL_MFDFEVX_COMMUNICATION_MACD)) {
    return PH_ADD_COMPCODE_FIXED(PH_ERR_INVALID_PARAMETER, PH_COMP_AL_MFDFEVX);
  }
#endif

  /* Set the dataparams with command code. */
  pDataParams->bCmdCode = (uint8_t)(bIns ? PHAL_MFDFEVX_CMD_WRITE_RECORD_ISO :
          PHAL_MFDFEVX_CMD_WRITE_RECORD);

  /* form the command depending on bIns */
  if (bIns == 0x00U) {
    bCmdBuff[wCmdLen++] = PHAL_MFDFEVX_CMD_WRITE_RECORD;
  } else {
    bCmdBuff[wCmdLen++] = PHAL_MFDFEVX_CMD_WRITE_RECORD_ISO;
  }
  bCmdBuff[wCmdLen++] = bFileNo;
  (void)memcpy(&bCmdBuff[wCmdLen], pOffset, 3);
  wCmdLen += 3U;
  (void)memcpy(&bCmdBuff[wCmdLen], pDataLen, 3);
  wCmdLen += 3U;

  /* Assuming here that the size can never go beyond FFFF. */
  dwDataLen = pDataLen[2];
  dwDataLen = (dwDataLen << 8U) | pDataLen[1];
  dwDataLen = (dwDataLen << 8U) | pDataLen[0];

  /* to handle 2 MB of data update maximum of data bytes that can be sent in a single loop */
  if (dwDataLen > PHAL_MFDFEVX_MAX_WRITE_SIZE) {
    wDataLenTemp = (uint16_t)PHAL_MFDFEVX_MAX_WRITE_SIZE;
    bLoopData = (uint8_t)(dwDataLen / PHAL_MFDFEVX_MAX_WRITE_SIZE);
    if (0U != (dwDataLen % PHAL_MFDFEVX_MAX_WRITE_SIZE)) {
      bLoopData++;
    }
    bCommOptionTemp = PHAL_MFDFEVX_MAC_DATA_INCOMPLETE | bCommOption;
  } else {
    wDataLenTemp = (uint16_t)dwDataLen;
  }

  /* update the total number of data to be written
  * when INS and wrapped mode is enable, we need to send the total number of bytes with Le */
  pDataParams->dwPayLoadLen = dwDataLen;

  if (pDataParams->bAuthMode == PHAL_MFDFEVX_NOT_AUTHENTICATED) {
    bCommOption = PHAL_MFDFEVX_COMMUNICATION_PLAIN;
  } else {
#ifdef NXPBUILD__PHAL_MFDFEVX_NDA
    if ((bCommOption & 0xF0U) == PHAL_MFDFEVX_COMMUNICATION_MACD) {
      pDataParams->dwPayLoadLen = pDataParams->dwPayLoadLen + ((pDataParams->bAuthMode ==
                  PHAL_MFDFEVX_AUTHENTICATE) ? 0x04 : 0x08);
    }
    if ((bCommOption & 0xF0U) == PHAL_MFDFEVX_COMMUNICATION_ENC) {
      if (pDataParams->bAuthMode == PHAL_MFDFEVX_AUTHENTICATEEV2) {
        pDataParams->dwPayLoadLen = 8 + pDataParams->dwPayLoadLen + ((pDataParams->dwPayLoadLen %
                    PH_CRYPTOSYM_AES_BLOCK_SIZE) ?
                (PH_CRYPTOSYM_AES_BLOCK_SIZE - (pDataParams->dwPayLoadLen % PH_CRYPTOSYM_AES_BLOCK_SIZE)) :
                PH_CRYPTOSYM_AES_BLOCK_SIZE);
      } else {
        pDataParams->dwPayLoadLen = pDataParams->dwPayLoadLen + ((pDataParams->bAuthMode ==
                    PHAL_MFDFEVX_AUTHENTICATE) ? 0x02 : 0x04);
        bIvLen = (pDataParams->bAuthMode == PHAL_MFDFEVX_AUTHENTICATEAES) ? PH_CRYPTOSYM_AES_BLOCK_SIZE :
            PH_CRYPTOSYM_DES_BLOCK_SIZE;

        if (0U != (pDataParams->dwPayLoadLen % bIvLen)) {
          pDataParams->dwPayLoadLen = pDataParams->dwPayLoadLen + (bIvLen - (pDataParams->dwPayLoadLen %
                      bIvLen));
        }
      }
    }
#endif /* NXPBUILD__PHAL_MFDFEVX_NDA */
  }

  PH_CHECK_SUCCESS_FCT(statusTmp, phTMIUtils_GetConfig((phTMIUtils_t *)pDataParams->pTMIDataParams,
          PH_TMIUTILS_TMI_STATUS,
          &dwTMIStatus));

  /* Check TMI Collection Status */
  if (dwTMIStatus == PH_ON) {
    PH_CHECK_SUCCESS_FCT(statusTmp, phTMIUtils_CollectTMI((phTMIUtils_t *)pDataParams->pTMIDataParams,
            (PH_TMIUTILS_ZEROPAD_CMDBUFF | PH_TMIUTILS_ZEROPAD_DATABUFF),
            bCmdBuff,
            wCmdLen,
            pData,
            dwDataLen,
            PHAL_MFDFEVX_BLOCK_SIZE
        ));
  }

  do {
    if (bLoopData == 1U) {
      bCommOptionTemp = bCommOption;
      wDataLenTemp = (uint16_t)(dwDataLen - dwDataWritten);
    }

    if ((pDataParams->bAuthMode == PHAL_MFDFEVX_NOT_AUTHENTICATED) ||
        (bCommOption == PHAL_MFDFEVX_COMMUNICATION_MACD) ||
        (bCommOption == PHAL_MFDFEVX_COMMUNICATION_PLAIN)) {
      statusTmp = phalMfdfEVx_Sw_Int_Write_Plain(
              pDataParams,
              ((bIns == 0x00U) ? PHAL_MFDFEVX_DEFAULT_MODE : PHAL_MFDFEVX_ISO_CHAINING_MODE),
              bCmdBuff,
              wCmdLen,
              bCommOptionTemp,
              &pData[dwDataWritten],
              wDataLenTemp
          );

    }
#ifdef NXPBUILD__PHAL_MFDFEVX_NDA
    else {
      statusTmp = phalMfdfEVx_Sw_Int_Write_Enc(
              pDataParams,
              ((bIns == 0x00U) ? PHAL_MFDFEVX_DEFAULT_MODE : PHAL_MFDFEVX_ISO_CHAINING_MODE),
              bCmdBuff,
              wCmdLen,
              PH_CRYPTOSYM_PADDING_MODE_1,
              bCommOptionTemp,
              &pData[dwDataWritten],
              wDataLenTemp
          );
    }
#endif /* NXPBUILD__PHAL_MFDFEVX_NDA */

    if ((statusTmp & PH_ERR_MASK) != PH_ERR_SUCCESS_CHAINING) {
      return statusTmp;
    }

    bLoopData--;
    dwDataWritten += wDataLenTemp;

    bCmdBuff[0] = 0xAF;
    wCmdLen = 1;

  } while (bLoopData > 0U);

  return statusTmp;
}

phStatus_t
phalMfdfEVx_Sw_ReadRecords(phalMfdfEVx_Sw_DataParams_t *pDataParams,
    uint8_t bCommOption, uint8_t bIns, uint8_t bFileNo, uint8_t *pRecNo,
    uint8_t *pRecCount, uint8_t *pRecSize, uint8_t **ppRxdata, uint16_t *pRxdataLen)
{
  uint8_t     PH_MEMLOC_REM bCmdBuff[8];
  uint16_t    PH_MEMLOC_REM wCmdLen = 0;
  uint32_t    PH_MEMLOC_REM dwRecLen = 0;
  uint32_t    PH_MEMLOC_REM dwNumRec = 0;
  phStatus_t  PH_MEMLOC_REM status = 0;
  uint32_t    PH_MEMLOC_REM dwTMIStatus = 0;
  phStatus_t  PH_MEMLOC_REM statusTmp;
  uint8_t     PH_MEMLOC_REM bOption = 0;
  uint32_t    PH_MEMLOC_REM dwDataLen = 0;
  uint32_t    PH_MEMLOC_REM dwOffsetTMI = 0;
  uint32_t    PH_MEMLOC_REM dwTMIBufInd = 0;
  uint32_t    PH_MEMLOC_REM dwTotalRecLen = 0;
  uint32_t    PH_MEMLOC_REM dwNumRecCal = 0;

#ifdef RDR_LIB_PARAM_CHECK
  if (((bFileNo & 0x7fU) > 0x1fU) || (bIns > 0x03U)) {
    return PH_ADD_COMPCODE_FIXED(PH_ERR_INVALID_PARAMETER, PH_COMP_AL_MFDFEVX);
  }
#endif
  /* copy size of each record */
  dwRecLen = pRecSize[2];/* MSB */
  dwRecLen = (dwRecLen << 8U) | pRecSize[1];
  dwRecLen = (dwRecLen << 8U) | pRecSize[0];/* LSB */

  /* copy number of records to be read */
  dwNumRec = pRecCount[2];/* MSB */
  dwNumRec = (dwNumRec << 8U) | pRecCount[1];
  dwNumRec = (dwNumRec << 8U) | pRecCount[0];/* LSB */

  /* Set the format of data to be sent as short APDU when,
   * 1. bit[1] of bIns is set. This means user is forcing the data to be sent in short APDU format in case of BIGISO read.
   * 2. In case data to be read is not BIGISO(Less than 256 bytes).
   */
  if ((bIns & 0x02U) || (((dwNumRec * dwRecLen) <= 0xFFU) && (dwNumRec != 0U))) {
    /* Setting parameter 'bShortLenApdu' in EVx data Structure for Short Length APDUs */
    PH_CHECK_SUCCESS_FCT(statusTmp, phalMfdfEVx_SetConfig(pDataParams,
            PHAL_MFDFEVX_SHORT_LENGTH_APDU,
            0x0001));
    /* Reset Bit[1] of 'bIns' for subsequent operations */
    bIns &= 0xFDU;
  }
  if ((bCommOption & 0x0FU) ==  PH_EXCHANGE_RXCHAINING) {
    bCmdBuff[wCmdLen++] = PHAL_MFDFEVX_RESP_ADDITIONAL_FRAME;
  } else if ((bCommOption & 0x0FU) ==  PH_EXCHANGE_DEFAULT) {
    /* form the command depending upon bIns */
    if (bIns == 0x00U) {
      bCmdBuff[wCmdLen++] = PHAL_MFDFEVX_CMD_READ_RECORDS;
    } else {
      bCmdBuff[wCmdLen++] = PHAL_MFDFEVX_CMD_READ_RECORDS_ISO;
    }
    bCmdBuff[wCmdLen++] = bFileNo;

    /* Record No */
    (void)memcpy(&bCmdBuff[wCmdLen], pRecNo, 3);
    wCmdLen += 3U;

    /* Record Count */
    (void)memcpy(&bCmdBuff[wCmdLen], pRecCount, 3);
    wCmdLen += 3U;

    /* Total number of bytes to read */
    dwTotalRecLen = (uint32_t)dwRecLen * dwNumRec;

    PH_CHECK_SUCCESS_FCT(statusTmp, phTMIUtils_GetConfig((phTMIUtils_t *)pDataParams->pTMIDataParams,
            PH_TMIUTILS_TMI_STATUS,
            &dwTMIStatus));

    /* Check TMI Collection Status */
    if (dwTMIStatus == PH_ON) {
      /* Should should provide atleast wRecLen / wNumRec to update in TIM collection */
      if ((0U == dwRecLen) && (0U == dwNumRec)) {
        return PH_ADD_COMPCODE_FIXED(PH_ERR_INVALID_PARAMETER, PH_COMP_AL_MFDFEVX);
      }
      PH_CHECK_SUCCESS_FCT(statusTmp, phTMIUtils_CollectTMI((phTMIUtils_t *)pDataParams->pTMIDataParams,
              (uint8_t)((dwNumRec == 0U) ? (PH_TMIUTILS_READ_INS | PH_TMIUTILS_ZEROPAD_CMDBUFF) :
                  PH_TMIUTILS_ZEROPAD_CMDBUFF),
              bCmdBuff,
              wCmdLen,
              NULL,
              0,
              PHAL_MFDFEVX_BLOCK_SIZE
          ));
    }
  } else {
    return PH_ADD_COMPCODE_FIXED(PH_ERR_INVALID_PARAMETER, PH_COMP_AL_MFDFEVX);
  }

  if ((bCommOption & 0xF0U) == PHAL_MFDFEVX_COMMUNICATION_ENC) {
#ifdef NXPBUILD__PHAL_MFDFEVX_NDA
    /* Upload Payload size for proper CRC calculation */
    if ((bCommOption & 0x0FU) !=  PH_EXCHANGE_RXCHAINING) {
      pDataParams->dwPayLoadLen = dwTotalRecLen;
    }

    status = phalMfdfEVx_Sw_Int_ReadData_Enc(
            pDataParams,
            bCommOption | ((bIns == 0x00U) ? PHAL_MFDFEVX_DEFAULT_MODE : PHAL_MFDFEVX_ISO_CHAINING_MODE),
            bCmdBuff,
            wCmdLen,
            ppRxdata,
            pRxdataLen
        );
#endif /* NXPBUILD__PHAL_MFDFEVX_NDA */
  } else if (((bCommOption & 0xF0U) == PHAL_MFDFEVX_COMMUNICATION_PLAIN) ||
      ((bCommOption & 0xF0U) == PHAL_MFDFEVX_COMMUNICATION_MACD)) {

    if ((pDataParams->bAuthMode == PHAL_MFDFEVX_AUTHENTICATE) &&
        ((bCommOption & 0xF0U) == PHAL_MFDFEVX_COMMUNICATION_MACD)) {
      bCommOption = bCommOption | PHAL_MFDFEVX_COMMUNICATION_MAC_ON_RC;
    }

    status = phalMfdfEVx_Sw_Int_ReadData_Plain(
            pDataParams,
            bCommOption | ((bIns == 0x00U) ? PHAL_MFDFEVX_DEFAULT_MODE : PHAL_MFDFEVX_ISO_CHAINING_MODE),
            bCmdBuff,
            wCmdLen,
            ppRxdata,
            pRxdataLen
        );
  } else {
    return PH_ADD_COMPCODE_FIXED(PH_ERR_INVALID_PARAMETER, PH_COMP_AL_MFDFEVX);
  }
  /* Restoring the Extended Length APDU mode */
  PH_CHECK_SUCCESS_FCT(statusTmp, phalMfdfEVx_SetConfig(pDataParams,
          PHAL_MFDFEVX_SHORT_LENGTH_APDU,
          0x0000));
  if (((status & PH_ERR_MASK) != PH_ERR_SUCCESS) &&
      ((status & PH_ERR_MASK) != PH_ERR_SUCCESS_CHAINING)) {
    return status;
  }

  if ((status == PH_ERR_SUCCESS) && (bCmdBuff[0] != PHAL_MFDFEVX_RESP_ADDITIONAL_FRAME)) {
    /* Can check this case if user has not given num of records
    as 0x000000. If 0x000000, then all records are read */
    if ((dwTotalRecLen != *pRxdataLen) && (dwTotalRecLen != 0U)) {
      /* Reset authentication status */
      if ((pDataParams->bAuthMode == PHAL_MFDFEVX_AUTHENTICATEISO) ||
          (pDataParams->bAuthMode == PHAL_MFDFEVX_AUTHENTICATEAES)) {
        phalMfdfEVx_Sw_Int_ResetAuthStatus(pDataParams);
      }
      return PH_ADD_COMPCODE_FIXED(PH_ERR_PROTOCOL_ERROR, PH_COMP_AL_MFDFEVX);
    }
  }

  /* if function called with PH_EXCHANGE_RXCHAINING */
  PH_CHECK_SUCCESS_FCT(statusTmp, phTMIUtils_GetConfig((phTMIUtils_t *)pDataParams->pTMIDataParams,
          PH_TMIUTILS_TMI_STATUS,
          &dwTMIStatus));

  /* Check TMI Collection Status */
  if (dwTMIStatus == PH_ON) {
    if ((dwNumRec == 0U) && (status == PH_ERR_SUCCESS)) {
      PH_CHECK_SUCCESS_FCT(statusTmp, phTMIUtils_GetConfig((phTMIUtils_t *)pDataParams->pTMIDataParams,
              PH_TMIUTILS_TMI_OFFSET_LENGTH,
              &dwOffsetTMI
          ));
      PH_CHECK_SUCCESS_FCT(statusTmp, phTMIUtils_GetConfig((phTMIUtils_t *)pDataParams->pTMIDataParams,
              PH_TMIUTILS_TMI_BUFFER_INDEX,
              &dwTMIBufInd
          ));

      /* calculate Rx length in case of chaining */
      dwDataLen = *pRxdataLen + dwTMIBufInd - (dwOffsetTMI + 11U);

      /* for Qmore compliance below code is added check is done before itself  */
      if (dwRecLen == 0U) {
        return PH_ADD_COMPCODE_FIXED(PH_ERR_PROTOCOL_ERROR, PH_COMP_AL_MFDFEVX);
      }

      /* if user update worng RecSize, we cant calculate recCnt */
      if (0U != (dwDataLen % dwRecLen)) {
        return PH_ADD_COMPCODE_FIXED(PH_ERR_PROTOCOL_ERROR, PH_COMP_AL_MFDFEVX);
      }

      /* calculate number of records */
      dwNumRecCal = dwDataLen / dwRecLen ;

      /* update record count */
      PH_CHECK_SUCCESS_FCT(statusTmp, phTMIUtils_SetConfig((phTMIUtils_t *)pDataParams->pTMIDataParams,
              PH_TMIUTILS_TMI_OFFSET_VALUE,
              dwNumRecCal
          ));

    }
    if (status == PH_ERR_SUCCESS) {
      bOption = PH_TMIUTILS_ZEROPAD_DATABUFF;
    }

    PH_CHECK_SUCCESS_FCT(statusTmp, phTMIUtils_CollectTMI((phTMIUtils_t *)pDataParams->pTMIDataParams,
            bOption,
            NULL,
            0,
            *ppRxdata,
            *pRxdataLen,
            PHAL_MFDFEVX_BLOCK_SIZE
        ));

    if ((status == PH_ERR_SUCCESS) && (dwNumRec == 0U)) {
      /* Reset wOffsetInTMI to 0 */
      PH_CHECK_SUCCESS_FCT(statusTmp, phTMIUtils_SetConfig((phTMIUtils_t *)pDataParams->pTMIDataParams,
              PH_TMIUTILS_TMI_OFFSET_LENGTH,
              0
          ));
    }
  }
  return status;
}

phStatus_t
phalMfdfEVx_Sw_UpdateRecord(phalMfdfEVx_Sw_DataParams_t *pDataParams,
    uint8_t bCommOption, uint8_t bIns, uint8_t bFileNo, uint8_t *pRecNo,
    uint8_t *pOffset, uint8_t *pData, uint8_t *pDataLen)
{
  phStatus_t  PH_MEMLOC_REM statusTmp;
  uint8_t     PH_MEMLOC_REM bCommOptionTemp = bCommOption;
  uint8_t     PH_MEMLOC_REM bLoopData = 1;
  uint8_t     PH_MEMLOC_REM bCmdBuff[16];
#ifdef NXPBUILD__PHAL_MFDFEVX_NDA
  uint8_t     PH_MEMLOC_REM bIvLen = PH_CRYPTOSYM_DES_BLOCK_SIZE;
#endif /* NXPBUILD__PHAL_MFDFEVX_NDA */
  uint16_t    PH_MEMLOC_REM wCmdLen = 0;
  uint16_t    PH_MEMLOC_REM wDataLenTemp;
  uint32_t    PH_MEMLOC_REM dwDataLen;
  uint32_t    PH_MEMLOC_REM dwTMIStatus = 0;
  uint32_t    PH_MEMLOC_REM dwDataWritten = 0;

#ifdef RDR_LIB_PARAM_CHECK
  if (((bFileNo & 0x7fU) > 0x1fU) || (bIns > 0x01U)) {
    return PH_ADD_COMPCODE_FIXED(PH_ERR_INVALID_PARAMETER, PH_COMP_AL_MFDFEVX);
  }
  if ((bCommOption != PHAL_MFDFEVX_COMMUNICATION_PLAIN) &&
      (bCommOption != PHAL_MFDFEVX_COMMUNICATION_ENC) &&
      (bCommOption != PHAL_MFDFEVX_COMMUNICATION_MACD)) {
    return PH_ADD_COMPCODE_FIXED(PH_ERR_INVALID_PARAMETER, PH_COMP_AL_MFDFEVX);
  }
#endif

  /* Set the dataparams with command code. */
  pDataParams->bCmdCode = (uint8_t)(bIns ? PHAL_MFDFEVX_CMD_UPDATE_RECORD_ISO :
          PHAL_MFDFEVX_CMD_UPDATE_RECORD);

  /* form the command depending on bIns */
  if (bIns == 0x00U) {
    bCmdBuff[wCmdLen++] = PHAL_MFDFEVX_CMD_UPDATE_RECORD;
  } else {
    bCmdBuff[wCmdLen++] = PHAL_MFDFEVX_CMD_UPDATE_RECORD_ISO;
  }
  bCmdBuff[wCmdLen++] = bFileNo;
  (void)memcpy(&bCmdBuff[wCmdLen], pRecNo, 3);
  wCmdLen += 3U;
  (void)memcpy(&bCmdBuff[wCmdLen], pOffset, 3);
  wCmdLen += 3U;
  (void)memcpy(&bCmdBuff[wCmdLen], pDataLen, 3);
  wCmdLen += 3U;

  /* copy data length */
  dwDataLen = pDataLen[2];
  dwDataLen = (dwDataLen << 8U) | pDataLen[1];
  dwDataLen = (dwDataLen << 8U) | pDataLen[0];

  /* to handle 2 MB of data update maximum of data bytes that can be sent in a single loop */
  if (dwDataLen > PHAL_MFDFEVX_MAX_WRITE_SIZE) {
    wDataLenTemp = (uint16_t)PHAL_MFDFEVX_MAX_WRITE_SIZE;
    bLoopData = (uint8_t)(dwDataLen / PHAL_MFDFEVX_MAX_WRITE_SIZE);
    if (0U != (dwDataLen % PHAL_MFDFEVX_MAX_WRITE_SIZE)) {
      bLoopData++;
    }
    bCommOptionTemp = PHAL_MFDFEVX_MAC_DATA_INCOMPLETE | bCommOption;
  } else {
    wDataLenTemp = (uint16_t)dwDataLen;
  }

  /* update the total number of data to be written
  * when INS and wrapped mode is enable, we need to send the total number of bytes with Le */
  pDataParams->dwPayLoadLen = dwDataLen;

  if (pDataParams->bAuthMode == PHAL_MFDFEVX_NOT_AUTHENTICATED) {
    bCommOption = PHAL_MFDFEVX_COMMUNICATION_PLAIN;
  }
#ifdef NXPBUILD__PHAL_MFDFEVX_NDA
  else {
    if ((bCommOption & 0xF0U) == PHAL_MFDFEVX_COMMUNICATION_MACD) {
      pDataParams->dwPayLoadLen = pDataParams->dwPayLoadLen + ((pDataParams->bAuthMode ==
                  PHAL_MFDFEVX_AUTHENTICATE) ? 0x04 : 0x08);
    }
    if ((bCommOption & 0xF0U) == PHAL_MFDFEVX_COMMUNICATION_ENC) {
      if (pDataParams->bAuthMode == PHAL_MFDFEVX_AUTHENTICATEEV2) {
        pDataParams->dwPayLoadLen = 8 + pDataParams->dwPayLoadLen + ((pDataParams->dwPayLoadLen %
                    PH_CRYPTOSYM_AES_BLOCK_SIZE) ?
                (PH_CRYPTOSYM_AES_BLOCK_SIZE - (pDataParams->dwPayLoadLen % PH_CRYPTOSYM_AES_BLOCK_SIZE)) :
                PH_CRYPTOSYM_AES_BLOCK_SIZE);
      } else {
        pDataParams->dwPayLoadLen = pDataParams->dwPayLoadLen + ((pDataParams->bAuthMode ==
                    PHAL_MFDFEVX_AUTHENTICATE) ? 0x02 : 0x04);
        bIvLen = (pDataParams->bAuthMode == PHAL_MFDFEVX_AUTHENTICATEAES) ? PH_CRYPTOSYM_AES_BLOCK_SIZE :
            PH_CRYPTOSYM_DES_BLOCK_SIZE;

        if (0U != (pDataParams->dwPayLoadLen % bIvLen)) {
          pDataParams->dwPayLoadLen = pDataParams->dwPayLoadLen + (bIvLen - (pDataParams->dwPayLoadLen %
                      bIvLen));
        }
      }
    }
  }
#endif /* NXPBUILD__PHAL_MFDFEVX_NDA */

  PH_CHECK_SUCCESS_FCT(statusTmp, phTMIUtils_GetConfig((phTMIUtils_t *)pDataParams->pTMIDataParams,
          PH_TMIUTILS_TMI_STATUS,
          &dwTMIStatus));

  /* Check TMI Collection Status */
  if (dwTMIStatus == PH_ON) {
    PH_CHECK_SUCCESS_FCT(statusTmp, phTMIUtils_CollectTMI((phTMIUtils_t *)pDataParams->pTMIDataParams,
            (PH_TMIUTILS_ZEROPAD_CMDBUFF | PH_TMIUTILS_ZEROPAD_DATABUFF),
            bCmdBuff,
            wCmdLen,
            pData,
            dwDataLen,
            PHAL_MFDFEVX_BLOCK_SIZE
        ));
  }

  do {
    if (bLoopData == 1U) {
      bCommOptionTemp = bCommOption;
      wDataLenTemp = (uint16_t)(dwDataLen - dwDataWritten);
    }

    if ((pDataParams->bAuthMode == PHAL_MFDFEVX_NOT_AUTHENTICATED) ||
        (bCommOption == PHAL_MFDFEVX_COMMUNICATION_MACD) ||
        (bCommOption == PHAL_MFDFEVX_COMMUNICATION_PLAIN)) {
      statusTmp = phalMfdfEVx_Sw_Int_Write_Plain(
              pDataParams,
              ((bIns == 0x00U) ? PHAL_MFDFEVX_DEFAULT_MODE : PHAL_MFDFEVX_ISO_CHAINING_MODE),
              bCmdBuff,
              wCmdLen,
              bCommOptionTemp,
              &pData[dwDataWritten],
              wDataLenTemp
          );
    }
#ifdef NXPBUILD__PHAL_MFDFEVX_NDA
    else {
      statusTmp = phalMfdfEVx_Sw_Int_Write_Enc(
              pDataParams,
              ((bIns == 0x00U) ? PHAL_MFDFEVX_DEFAULT_MODE : PHAL_MFDFEVX_ISO_CHAINING_MODE),
              bCmdBuff,
              wCmdLen,
              PH_CRYPTOSYM_PADDING_MODE_1,
              bCommOptionTemp,
              &pData[dwDataWritten],
              wDataLenTemp
          );
    }
#endif /* NXPBUILD__PHAL_MFDFEVX_NDA */
    /* If chaining send data remaining data */
    if ((statusTmp & PH_ERR_MASK) != PH_ERR_SUCCESS_CHAINING) {
      return statusTmp;
    }

    bLoopData--;
    dwDataWritten += wDataLenTemp;

    bCmdBuff[0] = 0xAF;
    wCmdLen = 1;

  } while (bLoopData > 0U);

  return statusTmp;
}

phStatus_t
phalMfdfEVx_Sw_ClearRecordFile(phalMfdfEVx_Sw_DataParams_t *pDataParams,
    uint8_t bFileNo)
{
  uint8_t PH_MEMLOC_REM bCmdBuff[8];
  uint32_t    PH_MEMLOC_REM dwTMIStatus = 0;
  phStatus_t  PH_MEMLOC_REM statusTmp;

#ifdef RDR_LIB_PARAM_CHECK
  if ((bFileNo & 0x7fU) > 0x1fU) {
    return PH_ADD_COMPCODE_FIXED(PH_ERR_INVALID_PARAMETER, PH_COMP_AL_MFDFEVX);
  }
#endif

  /* Set the dataparams with command code. */
  pDataParams->bCmdCode = PHAL_MFDFEVX_CMD_CLEAR_RECORD_FILE;

  /* form the command */
  bCmdBuff[0] = PHAL_MFDFEVX_CMD_CLEAR_RECORD_FILE;
  bCmdBuff[1] = bFileNo;

  PH_CHECK_SUCCESS_FCT(statusTmp, phTMIUtils_GetConfig((phTMIUtils_t *)pDataParams->pTMIDataParams,
          PH_TMIUTILS_TMI_STATUS,
          &dwTMIStatus));

  /* Check TMI Collection Status */
  if (dwTMIStatus == PH_ON) {
    PH_CHECK_SUCCESS_FCT(statusTmp, phTMIUtils_CollectTMI((phTMIUtils_t *)pDataParams->pTMIDataParams,
            PH_TMIUTILS_ZEROPAD_CMDBUFF,
            bCmdBuff,
            2,
            NULL,
            0,
            PHAL_MFDFEVX_BLOCK_SIZE
        ));
  }

  return phalMfdfEVx_Sw_Int_Write_Plain(pDataParams,
          PHAL_MFDFEVX_DEFAULT_MODE,
          bCmdBuff,
          2,
          (pDataParams->bAuthMode == PHAL_MFDFEVX_AUTHENTICATEEV2) ? PHAL_MFDFEVX_COMMUNICATION_MACD :
          PHAL_MFDFEVX_COMMUNICATION_PLAIN,
          NULL,
          0x0000
      );
}

/* MIFARE DESFire EVx Transaction mamangement commands. -------------------------------------------------------------------------------- */
phStatus_t
phalMfdfEVx_Sw_CommitTransaction(phalMfdfEVx_Sw_DataParams_t *pDataParams,
    uint8_t bOption, uint8_t *pTMC,
    uint8_t *pTMAC)
{
  uint16_t    PH_MEMLOC_REM statusTmp;
  uint8_t     PH_MEMLOC_REM bCmdBuff[8];
  uint16_t    PH_MEMLOC_REM wCmdLen = 0;
  uint8_t     PH_MEMLOC_REM *pRecv = NULL;
  uint16_t    PH_MEMLOC_REM wRxlen = 0;

#ifdef RDR_LIB_PARAM_CHECK
  /* As per ref_arch 0.04 for Cmd.CommitTransaction: simplified to always
   * use CommMode.MAC, so communication mode of response does not depend
   * on File-Type.TransactionMAC anymore.
   */
  if ((bOption & 0x0FU) > 0x01U) {
    return PH_ADD_COMPCODE_FIXED(PH_ERR_INVALID_PARAMETER, PH_COMP_AL_MFDFEVX);
  }
#endif

  /* Set the dataparams with command code. */
  pDataParams->bCmdCode = PHAL_MFDFEVX_CMD_COMMIT_TXN;

  /* form the command */
  bCmdBuff[wCmdLen++] = PHAL_MFDFEVX_CMD_COMMIT_TXN;

  if (0U != (bOption & 0x0FU)) {
    bCmdBuff[wCmdLen++] = (bOption & 0x0FU);
  }

  PH_CHECK_SUCCESS_FCT(statusTmp, phalMfdfEVx_Sw_Int_ReadData_Plain(
          pDataParams,
          (pDataParams->bAuthMode == PHAL_MFDFEVX_AUTHENTICATEEV2) ? PHAL_MFDFEVX_COMMUNICATION_MACD :
          PHAL_MFDFEVX_COMMUNICATION_PLAIN,
          bCmdBuff,
          wCmdLen,
          &pRecv,
          &wRxlen
      ));

  if (((bOption & 0x0FU) == 0x01U) && (wRxlen != 0x0CU)) {
    return PH_ADD_COMPCODE_FIXED(PH_ERR_PROTOCOL_ERROR, PH_COMP_AL_MFDFEVX);
  } else {
    if (NULL != pRecv) {
      (void)memcpy(pTMC, pRecv, 4);
      (void)memcpy(pTMAC, &pRecv[4], 8);
    }
  }

  return PH_ERR_SUCCESS;
}

phStatus_t
phalMfdfEVx_Sw_AbortTransaction(phalMfdfEVx_Sw_DataParams_t *pDataParams)
{
  uint8_t     PH_MEMLOC_REM bCmdBuff[8];

  /* Set the dataparams with command code. */
  pDataParams->bCmdCode = PHAL_MFDFEVX_CMD_ABORT_TXN;

  /* form the command */
  bCmdBuff[0] = PHAL_MFDFEVX_CMD_ABORT_TXN;

  /* COMMUNICATION IS PLAIN */
  return phalMfdfEVx_Sw_Int_Write_Plain(pDataParams,
          PHAL_MFDFEVX_DEFAULT_MODE,
          bCmdBuff,
          1,
          (pDataParams->bAuthMode == PHAL_MFDFEVX_AUTHENTICATEEV2) ? PHAL_MFDFEVX_COMMUNICATION_MACD :
          PHAL_MFDFEVX_COMMUNICATION_PLAIN,
          NULL,
          0x0000
      );
}

phStatus_t
phalMfdfEVx_Sw_CommitReaderID(phalMfdfEVx_Sw_DataParams_t *pDataParams, uint8_t *pTMRI,
    uint8_t *pEncTMRI)
{
  uint16_t    PH_MEMLOC_REM statusTmp;
  uint8_t     PH_MEMLOC_REM bCmdBuff[24];
  uint16_t    PH_MEMLOC_REM wRxlen = 0;
  uint8_t     PH_MEMLOC_REM *pRecv = NULL;
  uint32_t    PH_MEMLOC_REM dwTMIStatus = 0;
  uint8_t     PH_MEMLOC_REM bOption = PHAL_MFDFEVX_COMMUNICATION_PLAIN;
  uint8_t     PH_MEMLOC_REM bEncTMRILocal[16];

  /* Set the dataparams with command code. */
  pDataParams->bCmdCode = PHAL_MFDFEVX_CMD_COMMIT_READER_ID;

  /* form the command */
  bCmdBuff[0] = PHAL_MFDFEVX_CMD_COMMIT_READER_ID;
  (void)memcpy(&bCmdBuff[1], pTMRI, 16);

  /* For d40  PCD->PICC: cmd + cmdData + CMAC(4byte) (Kses, cmdData)
   *           PICC->PCD: RC

   * For Ev1 SM: PCD->PICC: cmd + cmdData ( CMAC (Kses, Cmd||cmdData) Mac is used as IV for next operation)
   *             PICC->PCD: RC + respData + CMAC (Kses, cmdData||RC)
   */
  if ((pDataParams->bAuthMode == PHAL_MFDFEVX_AUTHENTICATE) ||
      (pDataParams->bAuthMode == PHAL_MFDFEVX_AUTHENTICATEISO) ||
      (pDataParams->bAuthMode == PHAL_MFDFEVX_AUTHENTICATEAES)) {
    bOption = PHAL_MFDFEVX_COMMUNICATION_MAC_ON_CMD;
  }

  if (pDataParams->bAuthMode == PHAL_MFDFEVX_AUTHENTICATEEV2) {
    bOption = PHAL_MFDFEVX_COMMUNICATION_MACD;
  }

  statusTmp = phalMfdfEVx_Sw_Int_ReadData_Plain(
          pDataParams,
          bOption,
          bCmdBuff,
          17,
          &pRecv,
          &wRxlen
      );

  /* Force the buffer to NULL in case of failure. */
  if (statusTmp != PH_ERR_SUCCESS) {
    pEncTMRI = NULL;
    return statusTmp;
  }

  /*
   * If Not Authenticated, there should not be any response from PICC.
   * If Authenticated, PICC should response with 16 bytes of information.
   */
  if ((pDataParams->bAuthMode == PHAL_MFDFEVX_NOT_AUTHENTICATED) && (wRxlen != 0)) {
    return PH_ADD_COMPCODE_FIXED(PH_ERR_PROTOCOL_ERROR, PH_COMP_AL_MFDFEVX);
  } else if (((bOption == PHAL_MFDFEVX_COMMUNICATION_MAC_ON_CMD) ||
          (bOption == PHAL_MFDFEVX_COMMUNICATION_MACD)) && (wRxlen != 16)) {
    return PH_ADD_COMPCODE_FIXED(PH_ERR_PROTOCOL_ERROR, PH_COMP_AL_MFDFEVX);
  }

  if (pDataParams->bAuthMode == PHAL_MFDFEVX_NOT_AUTHENTICATED) {
    pEncTMRI = NULL;
  } else {
    (void)memcpy(bEncTMRILocal, pRecv, wRxlen);
    (void)memcpy(pEncTMRI, pRecv, wRxlen);
  }

  /* Do a Set Config of ADDITIONAL_INFO to set  the length(wLength) of the recieved TMRI */
  PH_CHECK_SUCCESS_FCT(statusTmp,
      phalMfdfEVx_Sw_SetConfig((phalMfdfEVx_Sw_DataParams_t *)pDataParams, PHAL_MFDFEVX_ADDITIONAL_INFO,
          wRxlen));

  PH_CHECK_SUCCESS_FCT(statusTmp, phTMIUtils_GetConfig((phTMIUtils_t *)pDataParams->pTMIDataParams,
          PH_TMIUTILS_TMI_STATUS,
          &dwTMIStatus));

  /* Check TMI Collection Status */
  if (dwTMIStatus == PH_ON) {
    /*
    * If authenticated, Cmd.CommitReaderID shall update the Transaction MAC Input TMI as follows:
    * TMI = TMI || Cmd || TMRICur||EncTMRI||ZeroPadding
    */
    if (pDataParams->bAuthMode != PHAL_MFDFEVX_NOT_AUTHENTICATED) {
      PH_CHECK_SUCCESS_FCT(statusTmp, phTMIUtils_CollectTMI((phTMIUtils_t *)pDataParams->pTMIDataParams,
              PH_TMIUTILS_ZEROPAD_DATABUFF,
              bCmdBuff,
              17,
              pEncTMRI,
              wRxlen,
              PHAL_MFDFEVX_BLOCK_SIZE
          ));
      memcpy(pEncTMRI, bEncTMRILocal, 16);
    } else {
      /* If Not authenticated, Cmd.CommitReaderID shall update the Transaction MAC Input TMI as follows:
      * TMI = TMI || Cmd || TMRICur||ZeroPadding
      */
      PH_CHECK_SUCCESS_FCT(statusTmp, phTMIUtils_CollectTMI((phTMIUtils_t *)pDataParams->pTMIDataParams,
              PH_TMIUTILS_ZEROPAD_CMDBUFF,
              bCmdBuff,
              17,
              NULL,
              0x00,
              PHAL_MFDFEVX_BLOCK_SIZE
          ));
      pEncTMRI = '\0';
    }
  }

  return PH_ERR_SUCCESS;
}

/* MIFARE DESFire EVx ISO7816-4 commands. ---------------------------------------------------------------------------------------------- */
phStatus_t
phalMfdfEVx_Sw_IsoSelectFile(phalMfdfEVx_Sw_DataParams_t *pDataParams, uint8_t bOption,
    uint8_t bSelector,
    uint8_t *pFid, uint8_t *pDFname, uint8_t bDFnameLen, uint8_t  bExtendedLenApdu, uint8_t **ppFCI,
    uint16_t *pwFCILen)
{
  phStatus_t  PH_MEMLOC_REM statusTmp;
  uint8_t     PH_MEMLOC_REM bData[24];
  uint32_t     PH_MEMLOC_REM bLc = 0;
  uint32_t     PH_MEMLOC_REM bLe = 0;
  uint8_t     PH_MEMLOC_REM bFileId[3] = { '\0' };
  uint8_t     PH_MEMLOC_REM aPiccDfName[7] = { 0xD2, 0x76, 0x00, 0x00, 0x85, 0x01, 0x00 };
  phStatus_t  PH_MEMLOC_REM status;
  uint16_t    wVal = 0;

#ifdef RDR_LIB_PARAM_CHECK
  if (bDFnameLen > 16U) {
    return PH_ADD_COMPCODE_FIXED(PH_ERR_INVALID_PARAMETER, PH_COMP_AL_MFDFEVX);
  }
  if ((bOption != 0x00U) && (bOption != 0x0CU)) {
    return PH_ADD_COMPCODE_FIXED(PH_ERR_INVALID_PARAMETER, PH_COMP_AL_MFDFEVX);
  }
#endif
  switch (bSelector) {
    case 0x00:  /* Select MF, DF or EF, by file identifier */
    case 0x01:  /* Select child DF */
    case 0x02:  /* Select EF under the current DF, by file identifier */
    case 0x03:  /* Select parent DF of the current DF */
      /* Selection by EF Id*/
      /* Send MSB first to card */
      bFileId[1] = bData[0] = pFid[1];
      bFileId[0] = bData[1] = pFid[0];
      bFileId[2] = 0x00;
      bLc = 2;
      break;

    case 0x04:  /* Select by DF name, see Cmd.ISOSelect for VC selection. */
      /* Selection by DF Name */
      (void)memcpy(bData, pDFname, bDFnameLen);
      bLc = bDFnameLen;
      break;

    default:
      return PH_ADD_COMPCODE_FIXED(PH_ERR_INVALID_PARAMETER, PH_COMP_AL_MFDFEVX);
  }

  statusTmp = phalMfdfEVx_Int_Send7816Apdu(
          pDataParams,
          pDataParams->pPalMifareDataParams,
          0x03,
          PHAL_MFDFEVX_CMD_ISO7816_SELECT_FILE,
          bSelector,
          bOption,
          bLc,
          bExtendedLenApdu,
          bData,
          bLe,
          ppFCI,
          pwFCILen);

  if ((statusTmp & PH_ERR_MASK) == PHAL_MFDFEVX_ERR_DF_7816_GEN_ERROR) {
    status = phalMfdfEVx_GetConfig(pDataParams, PHAL_MFDFEVX_ADDITIONAL_INFO, &wVal);
  }

  if ((statusTmp == PH_ERR_SUCCESS) ||
      (wVal == PHAL_MFDFEVX_ISO7816_ERR_LIMITED_FUNCTIONALITY_INS)) {
    /* Reset Authentication should not be targeted for elementary file selection using file ID */
    if (bSelector != 0x02U) {
      /* Reset Authentication Status here */
      phalMfdfEVx_Sw_Int_ResetAuthStatus(pDataParams);
    }
    /* ISO wrapped mode is on */
    pDataParams->bWrappedMode = 1;

    /* once the selection Success, update the File Id to master data structure if the selection is done through AID */
    if ((bSelector ==  0x00U) || (bSelector == 0x01U) || (bSelector == 0x02U)) {
      (void)memcpy(pDataParams->pAid, bFileId, sizeof(bFileId));
    } else if ((bSelector ==  0x04U)) {
      /* Update the file ID to all zeros if DF Name is of PICC. */
      if (memcmp(pDFname, aPiccDfName, 7) == 0) {
        bFileId[0] = 0x00;
        bFileId[1] = 0x00;
        bFileId[2] = 0x00;
      } else {
        bFileId[0] = 0xff;
        bFileId[1] = 0xff;
        bFileId[2] = 0xff;
      }

      (void)memcpy(pDataParams->pAid, bFileId, sizeof(bFileId));
    }
  } else {
    return statusTmp;
  }

  PH_UNUSED_VARIABLE(status);
  return PH_ERR_SUCCESS;
}

phStatus_t
phalMfdfEVx_Sw_IsoReadBinary(phalMfdfEVx_Sw_DataParams_t *pDataParams,
    uint16_t wOption, uint8_t bOffset,
    uint8_t bSfid, uint32_t dwBytesToRead, uint8_t bExtendedLenApdu, uint8_t **ppRxBuffer,
    uint32_t *pBytesRead)
{
  uint8_t     PH_MEMLOC_REM bP1 = 0;
  uint8_t     PH_MEMLOC_REM bP2 = 0;
  uint8_t     PH_MEMLOC_REM bCmdBuff[8];
  uint16_t    PH_MEMLOC_REM wOffset;
  uint16_t    PH_MEMLOC_REM wCmdLen = 0;
  uint8_t     PH_MEMLOC_REM *pLePtr = NULL;

  if ((wOption & PH_EXCHANGE_MODE_MASK) == PH_EXCHANGE_DEFAULT) {
    if (0U != (bSfid & 0x80U)) {
#ifdef RDR_LIB_PARAM_CHECK
      /* Short file id is supplied */
      if ((bSfid & 0x7FU) > 0x1FU) {
        /* Error condition */
        return PH_ADD_COMPCODE_FIXED(PH_ERR_INVALID_PARAMETER, PH_COMP_AL_MFDFEVX);
      }
#endif
      bP1 = bSfid;
      bP2 = bOffset;
    } else {
      /* P1 and P2 code the offset */
      wOffset = bP1 = bSfid;
      wOffset <<= 8; /* Left shift */
      wOffset |= bOffset;
      bP2 = bOffset;
    }
    pLePtr = (uint8_t *)&dwBytesToRead;
    bCmdBuff[wCmdLen++] = 0x00; /* Class */
    bCmdBuff[wCmdLen++] = PHAL_MFDFEVX_CMD_ISO7816_READ_BINARY; /* Ins */
    bCmdBuff[wCmdLen++] = bP1;
    bCmdBuff[wCmdLen++] = bP2;
    /* Check whether Length Le should be represented in Short APDU or extended length APDU */
    if (bExtendedLenApdu == 0x01U) {
      /*
      * An extended Le field consists of either three bytes (one * byte set to '00' followed by two bytes with any
      * value) if the Lc field is absent, or two bytes (with any * value) if an extended Lc field is present.
      * From '0001' to 'FFFF', the two bytes encode Ne from one
      * to 65 535.
      * If the two bytes are set to '0000', then Ne is 65 536.
      */
      bCmdBuff[wCmdLen++] = 0x00;
      bCmdBuff[wCmdLen++] = *(pLePtr + 1U);
      bCmdBuff[wCmdLen++] = *(pLePtr);
      /* Need to handle the case where the expected data to be read is more than 0xFFFF */
    } else {
      /* Short APDU */
      bCmdBuff[wCmdLen++] = *(pLePtr);
    }
  } else if ((wOption & PH_EXCHANGE_MODE_MASK) == PH_EXCHANGE_RXCHAINING) {
    wCmdLen = 0;
  } else {
    return PH_ADD_COMPCODE_FIXED(PH_ERR_INVALID_PARAMETER, PH_COMP_AL_MFDFEVX);
  }

  /* Set the dataparams with command code. */
  pDataParams->bCmdCode = PHAL_MFDFEVX_CMD_ISO7816_READ_BINARY;

  return phalMfdfEVx_Sw_Int_IsoRead(
          pDataParams,
          wOption,
          bCmdBuff,
          wCmdLen,
          ppRxBuffer,
          pBytesRead
      );
}

phStatus_t
phalMfdfEVx_Sw_IsoUpdateBinary(phalMfdfEVx_Sw_DataParams_t *pDataParams,
    uint8_t bOffset, uint8_t bSfid,
    uint8_t bExtendedLenApdu, uint8_t *pData, uint32_t dwDataLen)

{
  uint8_t     PH_MEMLOC_REM bP1 = 0;
  uint8_t     PH_MEMLOC_REM bP2 = 0;
  uint32_t    PH_MEMLOC_REM bLc = 0;
  uint16_t    PH_MEMLOC_REM wOffset;
  phStatus_t  PH_MEMLOC_REM status;

  if (0U != (bSfid & 0x80U)) {
#ifdef RDR_LIB_PARAM_CHECK
    /* Short file id is supplied */
    if ((bSfid & 0x7FU) > 0x1FU) {
      /* Error condition */
      return PH_ADD_COMPCODE_FIXED(PH_ERR_INVALID_PARAMETER, PH_COMP_AL_MFDFEVX);
    }
#endif
    bP1 = bSfid;
    bP2 = bOffset;
  } else {
    /* P1 and P2 code the offset */
    wOffset = bP1 = bSfid;
    wOffset <<= 8U; /* Left shift */
    wOffset |= bOffset;
    bP2 = bOffset;
  }

  bLc = dwDataLen;
  status = phalMfdfEVx_Int_Send7816Apdu(
          pDataParams,
          pDataParams->pPalMifareDataParams,
          0x01,
          PHAL_MFDFEVX_CMD_ISO7816_UPDATE_BINARY,
          bP1,
          bP2,
          bLc,
          bExtendedLenApdu,
          pData,
          0x00,
          NULL,
          NULL
      );

  if (status != PH_ERR_SUCCESS) {
    /* Reset authentication status */
    phalMfdfEVx_Sw_Int_ResetAuthStatus(pDataParams);
  }

  return status;
}

phStatus_t
phalMfdfEVx_Sw_IsoReadRecords(phalMfdfEVx_Sw_DataParams_t *pDataParams,
    uint16_t wOption, uint8_t bRecNo,
    uint8_t bReadAllFromP1, uint8_t bSfid, uint32_t dwBytesToRead, uint8_t bExtendedLenApdu,
    uint8_t  **ppRxBuffer,
    uint32_t *pBytesRead)

{
  uint8_t     PH_MEMLOC_REM bP1 = 0;
  uint8_t     PH_MEMLOC_REM bP2 = 0;
  uint8_t     PH_MEMLOC_REM bCmdBuff[8];
  uint16_t    PH_MEMLOC_REM wCmdLen = 0;
  uint8_t     PH_MEMLOC_REM *pLePtr = NULL;

  if ((wOption & PH_EXCHANGE_MODE_MASK) == PH_EXCHANGE_DEFAULT) {
    if (bSfid > 0x1FU) {
      /* Invalid Short File Id */
      return PH_ADD_COMPCODE_FIXED(PH_ERR_INVALID_PARAMETER, PH_COMP_AL_MFDFEVX);
    } else {
      /* Valid Sfid */
      bP1 = bRecNo;
      bP2 = bSfid;
      bP2 <<= 3U; /* left shift by 3 bits to move SFID to bits 7 to 3 */
      if (0U != (bReadAllFromP1)) {
        bP2 |= 0x05U; /* Last three bits of P2 = 101 */
      } else {
        bP2 |= 0x04U; /* Last three bits of P2 = 100. Read only record P1 */
      }
    }
    pLePtr = (uint8_t *) &dwBytesToRead;
    bCmdBuff[wCmdLen++] = 0x00; /* Class */
    bCmdBuff[wCmdLen++] = PHAL_MFDFEVX_CMD_ISO7816_READ_RECORDS; /* Ins */
    bCmdBuff[wCmdLen++] = bP1;
    bCmdBuff[wCmdLen++] = bP2;

    /* Check whether Length Le should be represented in Short APDU or extended length APDU */
    if (bExtendedLenApdu == 0x01U) {
      /*
       * An extended Le field consists of either three bytes (one * byte set to '00' followed by two bytes with any
       * value) if the Lc field is absent, or two bytes (with any * value) if an extended Lc field is present.
       * From '0001' to 'FFFF', the two bytes encode Ne from one
       * to 65 535.
       * If the two bytes are set to '0000', then Ne is 65 536.
       */
      bCmdBuff[wCmdLen++] = 0x00;
      bCmdBuff[wCmdLen++] = *(pLePtr + 1U);
      bCmdBuff[wCmdLen++] = *(pLePtr);
      /* Need to handle the case where the expected data to be read is more than 0xFFFF */
    } else {
      /* Short APDU */
      bCmdBuff[wCmdLen++] = *(pLePtr);
    }
  } else if ((wOption & PH_EXCHANGE_MODE_MASK) == PH_EXCHANGE_RXCHAINING) {
    wCmdLen = 0;
  } else {
    return PH_ADD_COMPCODE_FIXED(PH_ERR_INVALID_PARAMETER, PH_COMP_AL_MFDFEVX);
  }

  /* Set the dataparams with command code. */
  pDataParams->bCmdCode = PHAL_MFDFEVX_CMD_ISO7816_READ_RECORDS;

  return phalMfdfEVx_Sw_Int_IsoRead(
          pDataParams,
          wOption,
          bCmdBuff,
          wCmdLen,
          ppRxBuffer,
          pBytesRead
      );
}

phStatus_t
phalMfdfEVx_Sw_IsoAppendRecord(phalMfdfEVx_Sw_DataParams_t *pDataParams, uint8_t bSfid,
    uint8_t bExtendedLenApdu,
    uint8_t *pData, uint32_t dwDataLen)
{
  uint8_t     PH_MEMLOC_REM bP1 = 0;
  uint8_t     PH_MEMLOC_REM bP2 = 0;
  uint32_t    PH_MEMLOC_REM bLc = 0;
  phStatus_t  PH_MEMLOC_REM status;

#ifdef RDR_LIB_PARAM_CHECK
  if (bSfid > 0x1FU) {
    /* Invalid Short File Id */
    return PH_ADD_COMPCODE_FIXED(PH_ERR_INVALID_PARAMETER, PH_COMP_AL_MFDFEVX);
  }
#endif
  bP2 = bSfid;
  bP2 <<= 3U; /* left shift by 3 bits to move SFID to bits 7 to 3 */
  /* Last three bits of P2 = 000 */

  bLc = dwDataLen;
  status = phalMfdfEVx_Int_Send7816Apdu(
          pDataParams,
          pDataParams->pPalMifareDataParams,
          0x01,
          PHAL_MFDFEVX_CMD_ISO7816_APPEND_RECORD,
          bP1,
          bP2,
          bLc,
          bExtendedLenApdu,
          pData,
          0x00,
          NULL,
          NULL
      );
  if (status != PH_ERR_SUCCESS) {
    /* Reset authentication status */
    phalMfdfEVx_Sw_Int_ResetAuthStatus(pDataParams);
  }
  return status;
}

phStatus_t
phalMfdfEVx_Sw_IsoUpdateRecord(phalMfdfEVx_Sw_DataParams_t *pDataParams, uint8_t bIns,
    uint8_t bRecNo,
    uint8_t bSfid, uint8_t bRefCtrl, uint8_t *pData, uint8_t bDataLen)
{
  uint8_t     PH_MEMLOC_REM bP1 = 0;
  uint8_t     PH_MEMLOC_REM bP2 = 0;
  uint8_t     PH_MEMLOC_REM bLc = 0;
  phStatus_t  PH_MEMLOC_REM status;

#ifdef RDR_LIB_PARAM_CHECK
  if (bIns != 0xDCU) {
    if (bIns != 0xDDU) {
      /* Invalid Instruction */
      return PH_ADD_COMPCODE_FIXED(PH_ERR_INVALID_PARAMETER, PH_COMP_AL_MFDFEVX);
    }
  }

  if (bSfid > 0x1FU) {
    /* Invalid Short File Id */
    return PH_ADD_COMPCODE_FIXED(PH_ERR_INVALID_PARAMETER, PH_COMP_AL_MFDFEVX);
  }
#endif
  bP1 = bRecNo;
  bP2 = bSfid;
  bP2 <<= 3U; /* left shift by 3 bits to move SFID to bits 7 to 3 */
  bP2 |= bRefCtrl;

  bLc = bDataLen;
  status = phalMfdfEVx_Int_Send7816Apdu(
          pDataParams,
          pDataParams->pPalMifareDataParams,
          0x01,
          bIns,
          bP1,
          bP2,
          bLc,
          0x00,
          pData,
          0x00,
          NULL,
          NULL
      );
  if (status != PH_ERR_SUCCESS) {
    /* Reset authentication status */
    phalMfdfEVx_Sw_Int_ResetAuthStatus(pDataParams);
  }
  return status;
}

phStatus_t
phalMfdfEVx_Sw_IsoGetChallenge(phalMfdfEVx_Sw_DataParams_t *pDataParams,
    uint16_t wKeyNo, uint16_t wKeyVer,
    uint8_t bExtendedLenApdu, uint32_t dwLe, uint8_t *pRPICC1)
{
  phStatus_t  PH_MEMLOC_REM statusTmp;
  uint16_t    PH_MEMLOC_REM wRxlen = 0;
  uint8_t     PH_MEMLOC_REM *pRecv = NULL;
  uint8_t     PH_MEMLOC_REM bData[24];
  uint16_t    PH_MEMLOC_REM wKeyType;

  PH_CHECK_SUCCESS_FCT(statusTmp, phKeyStore_GetKey(
          pDataParams->pKeyStoreDataParams,
          wKeyNo,
          wKeyVer,
          sizeof(bData),
          bData,
          &wKeyType));

#ifdef RDR_LIB_PARAM_CHECK
  if ((wKeyType == PH_KEYSTORE_KEY_TYPE_AES128) || (wKeyType == PH_KEYSTORE_KEY_TYPE_3K3DES)) {
    if (dwLe != 0x10U) {
      return PH_ADD_COMPCODE_FIXED(PH_ERR_INVALID_PARAMETER, PH_COMP_AL_MFDFEVX);
    }
  } else if ((wKeyType == PH_KEYSTORE_KEY_TYPE_DES) || (wKeyType == PH_KEYSTORE_KEY_TYPE_2K3DES)) {
    if (dwLe != 0x08U) {
      return PH_ADD_COMPCODE_FIXED(PH_ERR_INVALID_PARAMETER, PH_COMP_AL_MFDFEVX);
    }
  } else {
    return PH_ADD_COMPCODE_FIXED(PH_ERR_INVALID_PARAMETER, PH_COMP_AL_MFDFEVX);
  }
#endif
  PH_CHECK_SUCCESS_FCT(statusTmp, phalMfdfEVx_Int_Send7816Apdu(
          pDataParams,
          pDataParams->pPalMifareDataParams,
          0x02,
          PHAL_MFDFEVX_CMD_ISO7816_GET_CHALLENGE,
          0x00,
          0x00,
          0x00,
          bExtendedLenApdu,
          NULL,
          dwLe,
          &pRecv,
          &wRxlen
      ));

  if (wRxlen != dwLe) {
    return PH_ADD_COMPCODE_FIXED(PH_ERR_PROTOCOL_ERROR, PH_COMP_AL_MFDFEVX);
  }

  (void)memcpy(pRPICC1, pRecv, wRxlen);

  /* Reset authentication status */
  phalMfdfEVx_Sw_Int_ResetAuthStatus(pDataParams);

  return PH_ERR_SUCCESS;
}

#ifdef NXPBUILD__PHAL_MFDFEVX_NDA
phStatus_t
phalMfdfEVx_Sw_IsoExternalAuthenticate(phalMfdfEVx_Sw_DataParams_t *pDataParams,
    uint8_t *pInput, uint8_t bInputLen,
    uint8_t bExtendedLenApdu, uint8_t *pDataOut, uint8_t *pOutLen)
{
  phStatus_t  PH_MEMLOC_REM statusTmp;
  uint16_t    PH_MEMLOC_REM wRxlen = 0;
  uint8_t     PH_MEMLOC_REM bIvLen;
  uint8_t     PH_MEMLOC_REM *pRecv = NULL;
  uint8_t     PH_MEMLOC_REM bKey[PH_CRYPTOSYM_3K3DES_KEY_SIZE];
  uint16_t    PH_MEMLOC_REM wKeyType;
  uint8_t     PH_MEMLOC_REM bRndBuff[2U * PH_CRYPTOSYM_AES128_KEY_SIZE];

  uint8_t     PH_MEMLOC_REM bIndex = 0;
  uint8_t     PH_MEMLOC_REM bAlgo;
  uint8_t     PH_MEMLOC_REM bIsDFkey;
  uint8_t     PH_MEMLOC_REM bKeyNoCard;
  uint8_t     PH_MEMLOC_REM bRpicc1[16];
  uint8_t     PH_MEMLOC_REM bRpcd1[16];
  uint8_t     PH_MEMLOC_REM bRndLen;
  uint16_t    PH_MEMLOC_REM wKeyNo;
  uint16_t    PH_MEMLOC_REM wKeyVer;
  uint16_t    PH_MEMLOC_REM bInLen = bInputLen; /* To avoid warning in Release Build */

#ifdef RDR_LIB_PARAM_CHECK
  if ((bInputLen != 24U) && (bInputLen != 40U)) {
    return PH_ADD_COMPCODE_FIXED(PH_ERR_INVALID_PARAMETER, PH_COMP_AL_MFDFEVX);
  }
#endif
  bInLen = 0; /* To avoid warning in Release Build */
  bAlgo = pInput[bIndex++];
  bIsDFkey = pInput[bIndex++];
  bKeyNoCard = pInput[bIndex++];
  bRndLen = pInput[bIndex++];

  (void)memcpy(bRpcd1, &pInput[bIndex], bRndLen);
  bIndex = bIndex + bRndLen;

  (void)memcpy(bRpicc1, &pInput[bIndex], bRndLen);
  bIndex = bIndex + bRndLen;

  (void)memcpy(&wKeyNo, &pInput[bIndex], 2);
  bIndex += 2U;

  (void)memcpy(&wKeyVer, &pInput[bIndex], 2);
  bIndex += 2U;

  if (bKeyNoCard > 0x0dU) {
    return PH_ADD_COMPCODE_FIXED(PH_ERR_INVALID_PARAMETER, PH_COMP_AL_MFDFEVX);
  }

  /* First get the key from key store */
  PH_CHECK_SUCCESS_FCT(statusTmp, phKeyStore_GetKey(
          pDataParams->pKeyStoreDataParams,
          wKeyNo,
          wKeyVer,
          sizeof(bKey),
          bKey,
          &wKeyType
      ));

  if (wKeyType == PH_KEYSTORE_KEY_TYPE_DES) {
    wKeyType = PH_KEYSTORE_KEY_TYPE_2K3DES;
    (void)memcpy(&bKey[8], bKey, 8);
  }

  /* Parameter validation. VAlidating bAlgo and bRndLen */
  switch (bAlgo) {
    case 0x00:
      /* Context defined algo. Based on key type */
      if ((wKeyType == PH_KEYSTORE_KEY_TYPE_2K3DES) && (bRndLen == PH_CRYPTOSYM_DES_KEY_SIZE)) {
        bIvLen = PH_CRYPTOSYM_DES_BLOCK_SIZE;
      } else if ((wKeyType == PH_KEYSTORE_KEY_TYPE_3K3DES) &&
          (bRndLen == PH_CRYPTOSYM_2K3DES_KEY_SIZE)) {
        bIvLen = PH_CRYPTOSYM_DES_BLOCK_SIZE;
      } else if ((wKeyType == PH_KEYSTORE_KEY_TYPE_AES128) &&
          (bRndLen == PH_CRYPTOSYM_AES128_KEY_SIZE)) {
        bIvLen = PH_CRYPTOSYM_AES_BLOCK_SIZE;
      } else {
        /* Either key type or rndlen is invalid */
        return PH_ADD_COMPCODE_FIXED(PH_ERR_INVALID_PARAMETER, PH_COMP_AL_MFDFEVX);
      }
      break;

    case 0x02:
      /* 2K3DES */
      if ((wKeyType != PH_KEYSTORE_KEY_TYPE_2K3DES) || (bRndLen != PH_CRYPTOSYM_DES_BLOCK_SIZE)) {
        return PH_ADD_COMPCODE_FIXED(PH_ERR_INVALID_PARAMETER, PH_COMP_AL_MFDFEVX);
      }
      bIvLen = PH_CRYPTOSYM_DES_BLOCK_SIZE;
      break;

    case 0x04:
      /* 3K3DES */
      if ((wKeyType != PH_KEYSTORE_KEY_TYPE_3K3DES) || (bRndLen != 2u * PH_CRYPTOSYM_DES_BLOCK_SIZE)) {
        return PH_ADD_COMPCODE_FIXED(PH_ERR_INVALID_PARAMETER, PH_COMP_AL_MFDFEVX);
      }
      bIvLen = PH_CRYPTOSYM_DES_BLOCK_SIZE;
      break;

    case 0x09:
      /* AES128 */
      if ((wKeyType != PH_KEYSTORE_KEY_TYPE_AES128) || (bRndLen != PH_CRYPTOSYM_AES_BLOCK_SIZE)) {
        return PH_ADD_COMPCODE_FIXED(PH_ERR_INVALID_PARAMETER, PH_COMP_AL_MFDFEVX);
      }
      bIvLen = PH_CRYPTOSYM_AES_BLOCK_SIZE;
      break;

    default:
      /* Invalid key type */
      return PH_ADD_COMPCODE_FIXED(PH_ERR_INVALID_PARAMETER, PH_COMP_AL_MFDFEVX);
  }

  pDataParams->bCryptoMethod = (uint8_t)wKeyType;

  /* Load Key */
  PH_CHECK_SUCCESS_FCT(statusTmp, phCryptoSym_LoadKeyDirect(
          pDataParams->pCryptoDataParamsEnc,
          bKey,
          wKeyType
      ));
  /* Load Iv */
  PH_CHECK_SUCCESS_FCT(statusTmp, phCryptoSym_LoadIv(
          pDataParams->pCryptoDataParamsEnc,
          pDataParams->bIv,
          bIvLen));

  (void)memcpy(bRndBuff, bRpcd1, bRndLen);
  (void)memcpy(&bRndBuff[bRndLen], bRpicc1, bRndLen);

  /* Encrypt RPCD1 + RPICC1 */
  PH_CHECK_SUCCESS_FCT(statusTmp, phCryptoSym_Encrypt(
          pDataParams->pCryptoDataParamsEnc,
          PH_CRYPTOSYM_CIPHER_MODE_CBC | PH_EXCHANGE_BUFFER_CONT,
          bRndBuff,
          2U * bRndLen,
          bRndBuff
      ));

  /* Store IV */
  (void)memcpy(pDataParams->bIv, &bRndBuff[(2U * bRndLen) - bIvLen], bIvLen);

  *pOutLen = 0; /* Nothing returned in s/w mode of implementation */
  if (NULL != (pDataOut)) {
    pDataOut = 0;
  }

  /* Send the APDU */
  PH_CHECK_SUCCESS_FCT(statusTmp, phalMfdfEVx_Int_Send7816Apdu(
          pDataParams,
          pDataParams->pPalMifareDataParams,
          0x01,
          PHAL_MFDFEVX_CMD_ISO7816_EXT_AUTHENTICATE,
          bAlgo,
          (bIsDFkey << 7U) | bKeyNoCard,
          bRndLen * 2,
          bExtendedLenApdu,
          bRndBuff,
          0x00,
          &pRecv,
          &wRxlen
      ));

  if (wRxlen != 0U) {
    return PH_ADD_COMPCODE_FIXED(PH_ERR_PROTOCOL_ERROR, PH_COMP_AL_MFDFEVX);
  }

  PH_UNUSED_VARIABLE(bInputLen);
  PH_UNUSED_VARIABLE(bInLen);
  return statusTmp;
}

phStatus_t
phalMfdfEVx_Sw_IsoInternalAuthenticate(phalMfdfEVx_Sw_DataParams_t *pDataParams,
    uint8_t *pInput,
    uint8_t bInputLen, uint8_t bExtendedLenApdu, uint8_t *pDataOut, uint8_t *pOutLen)
{
  phStatus_t  PH_MEMLOC_REM statusTmp;
  uint16_t    PH_MEMLOC_REM wRxlen = 0;
  uint8_t     PH_MEMLOC_REM bIvLen;
  uint8_t     PH_MEMLOC_REM *pRecv = NULL;
  uint8_t     PH_MEMLOC_REM bKey[PH_CRYPTOSYM_3K3DES_KEY_SIZE];
  uint16_t    PH_MEMLOC_REM wKeyType;
  uint8_t     PH_MEMLOC_REM bIndex = 0;
  uint8_t     PH_MEMLOC_REM bAlgo;
  uint8_t     PH_MEMLOC_REM bIsDFkey;
  uint8_t     PH_MEMLOC_REM bKeyNoCard;
  uint8_t     PH_MEMLOC_REM bRpcd2[16];
  uint8_t     PH_MEMLOC_REM bRndLen;
  uint16_t    PH_MEMLOC_REM wKeyNo;
  uint16_t    PH_MEMLOC_REM wKeyVer;
  uint16_t    PH_MEMLOC_REM bInLen =  bInputLen; /* To avoid warning in Release Build */

#ifdef RDR_LIB_PARAM_CHECK
  if ((bInLen != 16U) && (bInLen != 24U)) {
    return PH_ADD_COMPCODE_FIXED(PH_ERR_INVALID_PARAMETER, PH_COMP_AL_MFDFEVX);
  }
#endif
  bInLen = 0; /* Assign a value To avoid warning in Release Build */
  bAlgo = pInput[bIndex++];
  bIsDFkey = pInput[bIndex++];
  bKeyNoCard = pInput[bIndex++];
  bRndLen = pInput[bIndex++];

  (void)memcpy(bRpcd2, &pInput[bIndex], bRndLen);
  bIndex = bIndex + bRndLen;

  (void)memcpy(&wKeyNo, &pInput[bIndex], 2);
  bIndex += 2U;

  (void)memcpy(&wKeyVer, &pInput[bIndex], 2);
  bIndex += 2U;

  if (bKeyNoCard > 0x0dU) {
    return PH_ADD_COMPCODE_FIXED(PH_ERR_INVALID_PARAMETER, PH_COMP_AL_MFDFEVX);
  }

  /* First get the key from key store */
  PH_CHECK_SUCCESS_FCT(statusTmp, phKeyStore_GetKey(
          pDataParams->pKeyStoreDataParams,
          wKeyNo,
          wKeyVer,
          sizeof(bKey),
          bKey,
          &wKeyType
      ));

  if (wKeyType == PH_KEYSTORE_KEY_TYPE_DES) {
    wKeyType = PH_KEYSTORE_KEY_TYPE_2K3DES;
    (void)memcpy(&bKey[8], bKey, 8);
  }

  /* Parameter validation. VAlidating bAlgo and bRndLen */
  switch (bAlgo) {
    case 0x00:
      /* Context defined algo. Based on key type */
      if ((wKeyType == PH_KEYSTORE_KEY_TYPE_2K3DES) && (bRndLen == PH_CRYPTOSYM_DES_KEY_SIZE)) {
        bIvLen = PH_CRYPTOSYM_DES_BLOCK_SIZE;
      } else if ((wKeyType == PH_KEYSTORE_KEY_TYPE_3K3DES) &&
          (bRndLen == PH_CRYPTOSYM_2K3DES_KEY_SIZE)) {
        bIvLen = PH_CRYPTOSYM_DES_BLOCK_SIZE;
      } else if ((wKeyType == PH_KEYSTORE_KEY_TYPE_AES128) &&
          (bRndLen == PH_CRYPTOSYM_AES128_KEY_SIZE)) {
        bIvLen = PH_CRYPTOSYM_AES_BLOCK_SIZE;
      } else {
        /* Either key type or rndlen is invalid */
        return PH_ADD_COMPCODE_FIXED(PH_ERR_INVALID_PARAMETER, PH_COMP_AL_MFDFEVX);
      }
      break;

    case 0x02:
      /* 2K3DES */
      if ((wKeyType != PH_KEYSTORE_KEY_TYPE_2K3DES) || (bRndLen != PH_CRYPTOSYM_DES_BLOCK_SIZE)) {
        return PH_ADD_COMPCODE_FIXED(PH_ERR_INVALID_PARAMETER, PH_COMP_AL_MFDFEVX);
      }
      bIvLen = PH_CRYPTOSYM_DES_BLOCK_SIZE;
      break;

    case 0x04:
      /* 3K3DES */
      if ((wKeyType != PH_KEYSTORE_KEY_TYPE_3K3DES) || (bRndLen != 2u * PH_CRYPTOSYM_DES_BLOCK_SIZE)) {
        return PH_ADD_COMPCODE_FIXED(PH_ERR_INVALID_PARAMETER, PH_COMP_AL_MFDFEVX);
      }
      bIvLen = PH_CRYPTOSYM_DES_BLOCK_SIZE;
      break;

    case 0x09:
      /* AES128 */
      if ((wKeyType != PH_KEYSTORE_KEY_TYPE_AES128) || (bRndLen != PH_CRYPTOSYM_AES_BLOCK_SIZE)) {
        return PH_ADD_COMPCODE_FIXED(PH_ERR_INVALID_PARAMETER, PH_COMP_AL_MFDFEVX);
      }
      bIvLen = PH_CRYPTOSYM_AES_BLOCK_SIZE;
      break;

    default:
      /* Invalid key type */
      return PH_ADD_COMPCODE_FIXED(PH_ERR_INVALID_PARAMETER, PH_COMP_AL_MFDFEVX);
  }

  pDataParams->bCryptoMethod = (uint8_t)wKeyType;

  /* Send the APDU */
  PH_CHECK_SUCCESS_FCT(statusTmp, phalMfdfEVx_Int_Send7816Apdu(
          pDataParams,
          pDataParams->pPalMifareDataParams,
          0x03,
          PHAL_MFDFEVX_CMD_ISO7816_INT_AUTHENTICATE,
          bAlgo,
          (bIsDFkey << 7U) | bKeyNoCard,
          bRndLen,
          bExtendedLenApdu,
          bRpcd2,
          2U * bRndLen,
          &pRecv,
          &wRxlen
      ));

  if (wRxlen != (2u * bRndLen)) {
    return PH_ADD_COMPCODE_FIXED(PH_ERR_PROTOCOL_ERROR, PH_COMP_AL_MFDFEVX);
  }

  /* Load Key */
  PH_CHECK_SUCCESS_FCT(statusTmp, phCryptoSym_LoadKeyDirect(
          pDataParams->pCryptoDataParamsEnc,
          bKey,
          wKeyType
      ));
  /* Load Iv */
  PH_CHECK_SUCCESS_FCT(statusTmp, phCryptoSym_LoadIv(
          pDataParams->pCryptoDataParamsEnc,
          pDataParams->bIv,
          bIvLen));

  /* Decrypt RPCD1 + RPICC1 */
  PH_CHECK_SUCCESS_FCT(statusTmp, phCryptoSym_Decrypt(
          pDataParams->pCryptoDataParamsEnc,
          PH_CRYPTOSYM_CIPHER_MODE_CBC | PH_EXCHANGE_BUFFER_CONT,
          pRecv,
          wRxlen,
          pDataOut
      ));

  *pOutLen = 2u * bRndLen;

  /* Reset IV */
  (void)memset(pDataParams->bIv, 0x00, bIvLen);

  /* Session key has to be calculated and this key has to be loaded by the caller */
  if (wKeyType == PH_KEYSTORE_KEY_TYPE_AES128) {
    pDataParams->bAuthMode = PHAL_MFDFEVX_AUTHENTICATEAES;
  } else { /* (wKeyType == PH_KEYSTORE_KEY_TYPE_2K3DES)*/
    pDataParams->bAuthMode = PHAL_MFDFEVX_AUTHENTICATEISO;
  }
  pDataParams->bKeyNo = bKeyNoCard;
  pDataParams->bCryptoMethod = (uint8_t)wKeyType;
  pDataParams->bWrappedMode = 1;

  PH_UNUSED_VARIABLE(bInputLen);
  PH_UNUSED_VARIABLE(bInLen);
  return PH_ERR_SUCCESS;
}

phStatus_t
phalMfdfEVx_Sw_IsoAuthenticate(phalMfdfEVx_Sw_DataParams_t *pDataParams,
    uint16_t wKeyNo, uint16_t wKeyVer,
    uint8_t bKeyNoCard, uint8_t bIsPICCkey)
{
  phStatus_t  PH_MEMLOC_REM statusTmp;
  phStatus_t  PH_MEMLOC_REM status;
  uint8_t     PH_MEMLOC_REM bRndLen;
  uint8_t     PH_MEMLOC_REM bIndex = 0;
  uint8_t     PH_MEMLOC_REM bKey[PH_CRYPTOSYM_3K3DES_KEY_SIZE];
  uint16_t    PH_MEMLOC_REM wKeyType;
  uint8_t     PH_MEMLOC_REM bAlgo;
  uint8_t     PH_MEMLOC_REM bWorkBuffer[40];
  uint8_t     PH_MEMLOC_REM bRpcd1[PH_CRYPTOSYM_AES128_KEY_SIZE];
  uint8_t     PH_MEMLOC_REM bRpcd2[PH_CRYPTOSYM_AES128_KEY_SIZE];
  uint8_t     PH_MEMLOC_REM bRpicc1[PH_CRYPTOSYM_AES128_KEY_SIZE];
  uint8_t     PH_MEMLOC_REM bRpicc2[PH_CRYPTOSYM_AES128_KEY_SIZE];

#ifdef RDR_LIB_PARAM_CHECK
  if (bKeyNoCard > 0x0dU) {
    return PH_ADD_COMPCODE_FIXED(PH_ERR_INVALID_PARAMETER, PH_COMP_AL_MFDFEVX);
  }
#endif
  /* First get the key from key store */
  PH_CHECK_SUCCESS_FCT(statusTmp, phKeyStore_GetKey(
          pDataParams->pKeyStoreDataParams,
          wKeyNo,
          wKeyVer,
          sizeof(bKey),
          bKey,
          &wKeyType
      ));

  switch (wKeyType) {
    case PH_KEYSTORE_KEY_TYPE_2K3DES:
    case PH_KEYSTORE_KEY_TYPE_DES:
      bAlgo = 0x02;
      bRndLen = PH_CRYPTOSYM_DES_KEY_SIZE;
      break;

    case PH_KEYSTORE_KEY_TYPE_3K3DES:
      bAlgo = 0x04;
      bRndLen = PH_CRYPTOSYM_2K3DES_KEY_SIZE;
      break;

    case PH_KEYSTORE_KEY_TYPE_AES128:
      bAlgo = 0x09;
      bRndLen = PH_CRYPTOSYM_AES128_KEY_SIZE;
      break;

    default:
      /* Invalid key type */
      return PH_ADD_COMPCODE_FIXED(PH_ERR_KEY, PH_COMP_AL_MFDFEVX);
  }

  PH_CHECK_SUCCESS_FCT(statusTmp, phalMfdfEVx_Sw_IsoGetChallenge(pDataParams, wKeyNo, wKeyVer, 0x01,
          bRndLen, bRpicc1));

  /* Generate PCD1 */
  PH_CHECK_SUCCESS_FCT(statusTmp, phCryptoRng_Seed(pDataParams->pCryptoRngDataParams, bRpicc1,
          bRndLen));
  PH_CHECK_SUCCESS_FCT(statusTmp, phCryptoRng_Rnd(pDataParams->pCryptoRngDataParams, bRndLen,
          bRpcd1));

  bIndex = 0;
  bWorkBuffer[bIndex++] = bAlgo;
  bWorkBuffer[bIndex++] = !bIsPICCkey;
  bWorkBuffer[bIndex++] = bKeyNoCard;
  bWorkBuffer[bIndex++] = bRndLen;

  (void)memcpy(&bWorkBuffer[bIndex], bRpcd1, bRndLen);
  bIndex = bIndex + bRndLen;

  (void)memcpy(&bWorkBuffer[bIndex], bRpicc1, bRndLen);
  bIndex = bIndex + bRndLen;

  (void)memcpy(&bWorkBuffer[bIndex], &wKeyNo, 2);
  bIndex += 2U;

  (void)memcpy(&bWorkBuffer[bIndex], &wKeyVer, 2);
  bIndex += 2U;

  PH_CHECK_SUCCESS_FCT(statusTmp, phalMfdfEVx_Sw_IsoExternalAuthenticate(
          pDataParams,
          bWorkBuffer,
          bIndex,
          0x01,
          NULL,
          &bIndex
      ));

  /* Generate PCD2 */
  PH_CHECK_SUCCESS_FCT(statusTmp, phCryptoRng_Seed(pDataParams->pCryptoRngDataParams, bRpcd1,
          bRndLen));
  PH_CHECK_SUCCESS_FCT(statusTmp, phCryptoRng_Rnd(pDataParams->pCryptoRngDataParams, bRndLen,
          bRpcd2));

  bIndex = 0;
  bWorkBuffer[bIndex++] = bAlgo;
  bWorkBuffer[bIndex++] = !bIsPICCkey;
  bWorkBuffer[bIndex++] = bKeyNoCard;
  bWorkBuffer[bIndex++] = bRndLen;

  (void)memcpy(&bWorkBuffer[bIndex], bRpcd2, bRndLen);
  bIndex = bIndex + bRndLen;

  (void)memcpy(&bWorkBuffer[bIndex], &wKeyNo, 2);
  bIndex += 2U;

  (void)memcpy(&bWorkBuffer[bIndex], &wKeyVer, 2);
  bIndex += 2U;

  PH_CHECK_SUCCESS_FCT(statusTmp, phalMfdfEVx_Sw_IsoInternalAuthenticate(
          pDataParams,
          bWorkBuffer,
          bIndex,
          0x01,
          bWorkBuffer,
          &bIndex
      ));

  /* Verify bRpcd2. Store bRpicc2. Generate session key */
  if (memcmp(&bWorkBuffer[bRndLen], bRpcd2, bRndLen) == 0) {
    (void)memcpy(bRpicc2, bWorkBuffer, bRndLen);
  } else {
    /* return authentication error*/
    phalMfdfEVx_Sw_Int_ResetAuthStatus(pDataParams);
    return PH_ADD_COMPCODE_FIXED(PH_ERR_AUTH_ERROR, PH_COMP_AL_MFDFEVX);
  }

  switch (wKeyType) {
    case PH_KEYSTORE_KEY_TYPE_DES:
      (void)memcpy(pDataParams->bSesAuthENCKey, bRpcd1, 4);
      (void)memcpy(&pDataParams->bSesAuthENCKey[4], bRpicc2, 4);
      pDataParams->bAuthMode = PHAL_MFDFEVX_AUTHENTICATEISO;
      break;

    case PH_KEYSTORE_KEY_TYPE_2K3DES:
      (void)memcpy(pDataParams->bSesAuthENCKey, bRpcd1, 4);
      (void)memcpy(&pDataParams->bSesAuthENCKey[4], bRpicc2, 4);
      if (memcmp(bKey, &bKey[8], 8) == 0) {
        (void)memcpy(&pDataParams->bSesAuthENCKey[8], pDataParams->bSesAuthENCKey, 8);
      } else {
        (void)memcpy(&pDataParams->bSesAuthENCKey[8], &bRpcd1[4], 4);
        (void)memcpy(&pDataParams->bSesAuthENCKey[12], &bRpicc2[4], 4);
      }
      pDataParams->bAuthMode = PHAL_MFDFEVX_AUTHENTICATEISO;
      break;

    case PH_KEYSTORE_KEY_TYPE_3K3DES:
      (void)memcpy(pDataParams->bSesAuthENCKey, bRpcd1, 4);
      (void)memcpy(&pDataParams->bSesAuthENCKey[4], bRpicc2, 4);
      (void)memcpy(&pDataParams->bSesAuthENCKey[8], &bRpcd1[6], 4);
      (void)memcpy(&pDataParams->bSesAuthENCKey[12], &bRpicc2[6], 4);
      (void)memcpy(&pDataParams->bSesAuthENCKey[16], &bRpcd1[12], 4);
      (void)memcpy(&pDataParams->bSesAuthENCKey[20], &bRpicc2[12], 4);
      pDataParams->bAuthMode = PHAL_MFDFEVX_AUTHENTICATEISO;
      break;

    case PH_KEYSTORE_KEY_TYPE_AES128:
      (void)memcpy(pDataParams->bSesAuthENCKey, bRpcd1, 4);
      (void)memcpy(&pDataParams->bSesAuthENCKey[4], bRpicc2, 4);
      (void)memcpy(&pDataParams->bSesAuthENCKey[8], &bRpcd1[12], 4);
      (void)memcpy(&pDataParams->bSesAuthENCKey[12], &bRpicc2[12], 4);
      pDataParams->bAuthMode = PHAL_MFDFEVX_AUTHENTICATEAES;
      break;

    default:
      /* Invalid key type. This code is not reachable */
      return PH_ADD_COMPCODE_FIXED(PH_ERR_KEY, PH_COMP_AL_MFDFEVX);
  }

  pDataParams->bKeyNo = bKeyNoCard;
  pDataParams->bCryptoMethod = (uint8_t)wKeyType;
  pDataParams->bWrappedMode = 1;

  /* Load session key */
  PH_CHECK_SUCCESS_FCT(status, phCryptoSym_LoadKeyDirect(
          pDataParams->pCryptoDataParamsEnc,
          pDataParams->bSesAuthENCKey,
          pDataParams->bCryptoMethod
      ));

  /* Update the authentication state if VCA PC feature is required by the application. */
  if (pDataParams->pVCADataParams != NULL) {
    /* Set the Session key for Virtual Card which is valid for this authentication */
    PH_CHECK_SUCCESS_FCT(statusTmp, phalVca_SetSessionKeyUtility(
            (phalVca_Sw_DataParams_t *)pDataParams->pVCADataParams,
            pDataParams->bSesAuthENCKey,
            pDataParams->bAuthMode
        ));
  }

  /* Need to set config to keep the IV ON between CMAC calculation */
  return phCryptoSym_SetConfig(
          pDataParams->pCryptoDataParamsEnc,
          PH_CRYPTOSYM_CONFIG_KEEP_IV,
          PH_CRYPTOSYM_VALUE_KEEP_IV_ON
      );
}
#endif /* NXPBUILD__PHAL_MFDFEVX_NDA */

/* MIFARE DESFire EVx Originality Check functions. ------------------------------------------------------------------------------------- */
phStatus_t
phalMfdfEVx_Sw_ReadSign(phalMfdfEVx_Sw_DataParams_t *pDataParams, uint8_t bAddr,
    uint8_t **pSignature)
{

  phStatus_t  PH_MEMLOC_REM statusTmp;
  uint8_t     PH_MEMLOC_REM bCmdBuff[2];
  uint16_t    PH_MEMLOC_REM wCmdLen = 0;
  uint16_t    PH_MEMLOC_REM wRxLength = 0;

  /* Set the dataparams with command code. */
  pDataParams->bCmdCode = PHAL_MFDFEVX_CMD_READ_SIG;

  /* build command frame */
  bCmdBuff[wCmdLen++] = PHAL_MFDFEVX_CMD_READ_SIG;
  bCmdBuff[wCmdLen++] = bAddr;

  /* Req spec(ver 0.14 says),
  * 1. Cmd.Read_Sig shall return the NXPOriginalitySignature as written during wafer test in plain if not authenticated
  * 2. Cmd.Read_Sig shall require MACed command if authenticated.
  */
  if (pDataParams->bAuthMode == PHAL_MFDFEVX_NOT_AUTHENTICATED) {
    PH_CHECK_SUCCESS_FCT(statusTmp, phalMfdfEVx_Sw_Int_ReadData_Plain(
            pDataParams,
            PHAL_MFDFEVX_COMMUNICATION_PLAIN,
            bCmdBuff,
            wCmdLen,
            pSignature,
            &wRxLength
        ));
  }
#ifdef  NXPBUILD__PHAL_MFDFEVX_NDA
  else {
    /* Set the expected data length as 56 bytes */
    pDataParams->dwPayLoadLen = PHAL_MFDFEVX_SIG_LENGTH;

    PH_CHECK_SUCCESS_FCT(statusTmp, phalMfdfEVx_Sw_Int_ReadData_Enc(
            pDataParams,
            PHAL_MFDFEVX_COMMUNICATION_ENC,
            bCmdBuff,
            wCmdLen,
            pSignature,
            &wRxLength
        ));
  }
#endif /* NXPBUILD__PHAL_MFDFEVX_NDA */
  /* check received length :- 56 byte signature */
  if (wRxLength != PHAL_MFDFEVX_SIG_LENGTH) {
    return PH_ADD_COMPCODE_FIXED(PH_ERR_LENGTH_ERROR, PH_COMP_AL_MFDFEVX);
  }

  return PH_ERR_SUCCESS;

}

/* MIFARE DESFire EVx MIFARE Classic contactless IC functions. ---------------------------------------------------------------------------------------- */
phStatus_t
phalMfdfEVx_Sw_CreateMFCMapping(phalMfdfEVx_Sw_DataParams_t *pDataParams,
    uint8_t bComOption, uint8_t bFileNo,
    uint8_t bFileOption, uint8_t *pMFCBlockList, uint8_t bMFCBlocksLen, uint8_t bRestoreSource,
    uint8_t *pMFCLicense,
    uint8_t bMFCLicenseLen, uint8_t *pMFCLicenseMAC)
{
  phStatus_t  PH_MEMLOC_REM wStatus = 0;
  uint8_t     PH_MEMLOC_REM aCmdBuff[210];
  uint8_t     PH_MEMLOC_REM bCmdLen = 0;

  /* Validate the parameters. */
  if ((bComOption != PHAL_MFDFEVX_COMMUNICATION_PLAIN) &&
      (bComOption != PHAL_MFDFEVX_COMMUNICATION_ENC)) {
    return PH_ADD_COMPCODE_FIXED(PH_ERR_INVALID_PARAMETER, PH_COMP_AL_MFDFEVX);
  }

  /* Set the dataparams with command code. */
  pDataParams->bCmdCode = PHAL_MFDFEVX_CMD_CREATE_MFC_MAPPING;

  /* Frame the command information. */
  aCmdBuff[bCmdLen++] = PHAL_MFDFEVX_CMD_CREATE_MFC_MAPPING;
  aCmdBuff[bCmdLen++] = bFileNo;
  aCmdBuff[bCmdLen++] = bFileOption;
  aCmdBuff[bCmdLen++] = bMFCBlocksLen;

  /* Copy the MFCBlockList to command buffer. */
  (void)memcpy(&aCmdBuff[bCmdLen], pMFCBlockList, bMFCBlocksLen);
  bCmdLen += bMFCBlocksLen;

  /* Copy RestoreSource to command buffer. */
  if (0U != (bFileOption & 0x04U)) {
    aCmdBuff[bCmdLen++] = bRestoreSource;
  }

  /* Copy the MFCLicense to command buffer. */
  (void)memcpy(&aCmdBuff[bCmdLen], pMFCLicense, bMFCLicenseLen);
  bCmdLen += bMFCLicenseLen;

  /* Exchange Cmd.CreateMFCMapping information to PICC. */
  PH_CHECK_SUCCESS_FCT(wStatus, phalMfdfEVx_Sw_Int_Write_New(
          pDataParams,
          bComOption,
          aCmdBuff,
          bCmdLen,
          pMFCLicenseMAC,
          8));

  return PH_ERR_SUCCESS;
}

phStatus_t
phalMfdfEVx_Sw_RestoreTransfer(phalMfdfEVx_Sw_DataParams_t *pDataParams,
    uint8_t bCommOption, uint8_t bTargetFileNo, uint8_t bSourceFileNo)
{
  phStatus_t  PH_MEMLOC_REM wStatus = 0;
  uint8_t     PH_MEMLOC_REM aCmdBuff[15];
  uint32_t    PH_MEMLOC_REM dwTMIStatus = 0;

  if ((bCommOption != PHAL_MFDFEVX_COMMUNICATION_PLAIN) &&
      (bCommOption != PHAL_MFDFEVX_COMMUNICATION_PLAIN_1) &&
      (bCommOption != PHAL_MFDFEVX_COMMUNICATION_MACD)) {
    return PH_ADD_COMPCODE_FIXED(PH_ERR_INVALID_PARAMETER, PH_COMP_AL_MFDFEVX);
  }

  /* Set the dataparams with command code. */
  pDataParams->bCmdCode = PHAL_MFDFEVX_CMD_RESTORE_TRANSFER;

  /* Frame the command information. */
  aCmdBuff[0] = PHAL_MFDFEVX_CMD_RESTORE_TRANSFER;
  aCmdBuff[1] = bTargetFileNo;
  aCmdBuff[2] = bSourceFileNo;

  /* Exchange Cmd.RestoreTransfer information to PICC. */
  PH_CHECK_SUCCESS_FCT(wStatus, phalMfdfEVx_Sw_Int_Write_Plain(
          pDataParams,
          PHAL_MFDFEVX_DEFAULT_MODE,
          aCmdBuff,
          1,
          bCommOption,
          &aCmdBuff[1],
          2));

  /* Get the status of the TMI */
  PH_CHECK_SUCCESS_FCT(wStatus, phTMIUtils_GetConfig((phTMIUtils_t *)pDataParams->pTMIDataParams,
          PH_TMIUTILS_TMI_STATUS, &dwTMIStatus));

  /* Check TMI Collection Status */
  if (dwTMIStatus == PH_ON) {
    PH_CHECK_SUCCESS_FCT(wStatus, phTMIUtils_CollectTMI((phTMIUtils_t *) pDataParams->pTMIDataParams,
            PH_TMIUTILS_ZEROPAD_CMDBUFF, aCmdBuff, 3, NULL, 0, PHAL_MFDFEVX_BLOCK_SIZE));
  }

  return PH_ERR_SUCCESS;
}

#ifdef NXPBUILD__PHAL_MFDFEVX_NDA
phStatus_t
phalMfdfEVx_Sw_RestrictMFCUpdate(phalMfdfEVx_Sw_DataParams_t *pDataParams,
    uint8_t bOption, uint8_t *pMFCConfig,
    uint8_t bMFCConfigLen, uint8_t *pMFCLicense, uint8_t bMFCLicenseLen, uint8_t *pMFCLicenseMAC)
{
  phStatus_t  PH_MEMLOC_REM wStatus = 0;
  uint8_t     PH_MEMLOC_REM aCmdBuff[210];
  uint8_t     PH_MEMLOC_REM bCmdLen = 0;

  /* Set the dataparams with command code. */
  pDataParams->bCmdCode = PHAL_MFDFEVX_CMD_RESTRICT_MFC_UPDATE;

  /* Frame the command information. */
  aCmdBuff[bCmdLen++] = PHAL_MFDFEVX_CMD_RESTRICT_MFC_UPDATE;
  aCmdBuff[bCmdLen++] = bOption;

  /* Copy the MFCBlockList to command buffer. */
  (void)memcpy(&aCmdBuff[bCmdLen], pMFCConfig, bMFCConfigLen);
  bCmdLen += bMFCConfigLen;

  /* Copy the MFCLicense to command buffer. */
  (void)memcpy(&aCmdBuff[bCmdLen], pMFCLicense, bMFCLicenseLen);
  bCmdLen += bMFCLicenseLen;

  /* Exchange Cmd.CreateMFCMapping information to PICC. */
  PH_CHECK_SUCCESS_FCT(wStatus, phalMfdfEVx_Sw_Int_Write_New(
          pDataParams,
          PHAL_MFDFEVX_COMMUNICATION_ENC,
          aCmdBuff,
          bCmdLen,
          pMFCLicenseMAC,
          8));

  return PH_ERR_SUCCESS;
}

/* MIFARE DESFire EVx POST Delivery Configuration function. ---------------------------------------------------------------------------- */
phStatus_t
phalMfdfEVx_Sw_AuthenticatePDC(phalMfdfEVx_Sw_DataParams_t *pDataParams, uint8_t bRfu,
    uint8_t bKeyNoCard, uint8_t wKeyNo,
    uint16_t wKeyVer, uint8_t bUpgradeInfo)
{
  phStatus_t  PH_MEMLOC_REM statusTmp;
  uint8_t    *PH_MEMLOC_REM pResponse = NULL;
  uint16_t    PH_MEMLOC_REM wRxLength = 0;
  uint8_t     PH_MEMLOC_REM aCmdBuffer[35];
  uint8_t     PH_MEMLOC_REM bCmdBufLen = 0;
  uint8_t     PH_MEMLOC_REM aKey[PH_CRYPTOSYM_AES128_KEY_SIZE];
  uint16_t    PH_MEMLOC_REM wKeyType;
  uint8_t     PH_MEMLOC_REM bRndA[PH_CRYPTOSYM_AES_BLOCK_SIZE];
  uint8_t     PH_MEMLOC_REM bRndB[PH_CRYPTOSYM_AES_BLOCK_SIZE + 1];
  uint8_t     PH_MEMLOC_REM aUpgradeKey[PH_CRYPTOSYM_AES_BLOCK_SIZE];
  uint8_t     PH_MEMLOC_REM bKeyLen = 0;

  /* UpgradeKey computation uisng CMAC algorithm. */

  /* Get the IC Upgrade Key data form key store. */
  PH_CHECK_SUCCESS_FCT(statusTmp, phKeyStore_GetKey(
          pDataParams->pKeyStoreDataParams,
          wKeyNo,
          wKeyVer,
          sizeof(aKey),
          aKey,
          &wKeyType));

  /* Check the key type. */
  if (wKeyType != PH_CRYPTOSYM_KEY_TYPE_AES128) {
    return PH_ADD_COMPCODE_FIXED(PH_ERR_INVALID_PARAMETER, PH_COMP_AL_MFDFEVX);
  }

  /* Load the IC Upgrade key. */
  PH_CHECK_SUCCESS_FCT(statusTmp, phCryptoSym_LoadKeyDirect(
          pDataParams->pCryptoDataParamsMac,
          aKey,
          wKeyType));

  /* Load Zero IV. */
  PH_CHECK_SUCCESS_FCT(statusTmp, phCryptoSym_LoadIv(
          pDataParams->pCryptoDataParamsMac,
          phalMfdfEVx_Sw_FirstIv,
          PH_CRYPTOSYM_AES_BLOCK_SIZE));

  /* Clear the command buffer to form the data to be maced with IC Upgrade key. */
  (void)memset(aCmdBuffer, 0x00, sizeof(aCmdBuffer));

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

  /* Clear the command buffer to frame the first part of the command to be sent AuthenticatePDC. */
  (void)memset(aCmdBuffer, 0x00, sizeof(aCmdBuffer));

  /* Set the dataparams for validation of similar error codes. */
  pDataParams->bCmdCode = PHAL_MFDFEVX_CMD_AUTH_PDC;

  /* Frame the command*/
  bCmdBufLen = 0;
  aCmdBuffer[bCmdBufLen++] = PHAL_MFDFEVX_CMD_AUTH_PDC;
  aCmdBuffer[bCmdBufLen++] = bRfu;
  aCmdBuffer[bCmdBufLen++] = bKeyNoCard;
  aCmdBuffer[bCmdBufLen++] = 0x01;                                /* Upgrade Info Length */
  aCmdBuffer[bCmdBufLen++] = bUpgradeInfo;                        /* Upgrade Info value */

  /* Exchange command */

  PH_CHECK_SUCCESS_FCT(statusTmp, phalMfdfEVx_ExchangeCmd(
          pDataParams,
          pDataParams->pPalMifareDataParams,
          pDataParams->bWrappedMode,
          aCmdBuffer,
          bCmdBufLen,
          &pResponse,
          &wRxLength
      ));

  /* Load Zero IV. */
  PH_CHECK_SUCCESS_FCT(statusTmp, phCryptoSym_LoadIv(
          pDataParams->pCryptoDataParamsEnc,
          phalMfdfEVx_Sw_FirstIv,
          PH_CRYPTOSYM_AES_BLOCK_SIZE));

  /* Decrypt the data using Upgrade Key and get RndB. */
  PH_CHECK_SUCCESS_FCT(statusTmp, phCryptoSym_Decrypt(
          pDataParams->pCryptoDataParamsEnc,
          (PH_CRYPTOSYM_CIPHER_MODE_CBC | PH_EXCHANGE_DEFAULT),
          pResponse,
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

  /* Form the command for second part of the authhentication sequence. */
  bCmdBufLen = 0;
  aCmdBuffer[bCmdBufLen++] = PHAL_MFDFEVX_CMD_AUTH2;

  /* Load Zero IV. */
  PH_CHECK_SUCCESS_FCT(statusTmp, phCryptoSym_LoadIv(
          pDataParams->pCryptoDataParamsEnc,
          phalMfdfEVx_Sw_FirstIv,
          PH_CRYPTOSYM_AES_BLOCK_SIZE));

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

  PH_CHECK_SUCCESS_FCT(statusTmp, phalMfdfEVx_ExchangeCmd(
          pDataParams,
          pDataParams->pPalMifareDataParams,
          pDataParams->bWrappedMode,
          aCmdBuffer,
          bCmdBufLen,
          &pResponse,
          &wRxLength
      ));

  /* Decrypt the received data to get RndA'. */
  /* Load default init vector */
  PH_CHECK_SUCCESS_FCT(statusTmp, phCryptoSym_LoadIv(
          pDataParams->pCryptoDataParamsEnc,
          phalMfdfEVx_Sw_FirstIv,
          PH_CRYPTOSYM_AES_BLOCK_SIZE));

  /* The decryption key available. Decrypt the response  */
  PH_CHECK_SUCCESS_FCT(statusTmp, phCryptoSym_Decrypt(
          pDataParams->pCryptoDataParamsEnc,
          PH_CRYPTOSYM_CIPHER_MODE_CBC,
          pResponse,
          PH_CRYPTOSYM_AES_BLOCK_SIZE << 1,
          &pResponse[1]
      ));

  /* Shift of RND A */
  pResponse[0] = pResponse[PH_CRYPTOSYM_AES_BLOCK_SIZE];

  /* Now perform the comparison. */
  if (memcmp(bRndA, &pResponse[0], PH_CRYPTOSYM_AES_BLOCK_SIZE) != 0) {
    /* RndA and RndA' don't match */
    return PH_ADD_COMPCODE_FIXED(PH_ERR_AUTH_ERROR, PH_COMP_AL_MFDFEVX);
  }

  return PH_ERR_SUCCESS;
}
#endif /* NXPBUILD__PHAL_MFDFEVX_NDA */

/* MIFARE DESFire EVx Miscellaneous functions. ----------------------------------------------------------------------------------------- */
phStatus_t
phalMfdfEVx_Sw_GetConfig(phalMfdfEVx_Sw_DataParams_t *pDataParams, uint16_t wConfig,
    uint16_t *pValue)
{
  switch (wConfig) {
    case PHAL_MFDFEVX_ADDITIONAL_INFO:
      *pValue = pDataParams->wAdditionalInfo;
      break;

    case PHAL_MFDFEVX_WRAPPED_MODE:
      *pValue = (uint16_t) pDataParams->bWrappedMode;
      break;

    case PHAL_MFDFEVX_SHORT_LENGTH_APDU:
      *pValue = (uint16_t) pDataParams->bShortLenApdu;
      break;

    default:
      return PH_ADD_COMPCODE_FIXED(PH_ERR_UNSUPPORTED_PARAMETER, PH_COMP_AL_MFDFEVX);
  }
  return PH_ERR_SUCCESS;
}

phStatus_t
phalMfdfEVx_Sw_SetConfig(phalMfdfEVx_Sw_DataParams_t *pDataParams, uint16_t wConfig,
    uint16_t wValue)
{
  switch (wConfig) {
    case PHAL_MFDFEVX_ADDITIONAL_INFO:
      pDataParams->wAdditionalInfo = wValue;
      break;

    case PHAL_MFDFEVX_WRAPPED_MODE:
      pDataParams->bWrappedMode = (uint8_t) wValue;
      break;

    case PHAL_MFDFEVX_SHORT_LENGTH_APDU:
      pDataParams->bShortLenApdu = (uint8_t) wValue;
      break;

    default:
      return PH_ADD_COMPCODE_FIXED(PH_ERR_UNSUPPORTED_PARAMETER, PH_COMP_AL_MFDFEVX);
  }
  return PH_ERR_SUCCESS;
}

phStatus_t
phalMfdfEVx_Sw_ResetAuthentication(phalMfdfEVx_Sw_DataParams_t *pDataParams)
{
  phalMfdfEVx_Sw_Int_ResetAuthStatus(pDataParams);

  return PH_ERR_SUCCESS;
}

#ifdef NXPBUILD__PHAL_MFDFEVX_NDA
phStatus_t
phalMfdfEVx_Sw_GenerateDAMEncKey(phalMfdfEVx_Sw_DataParams_t *pDataParams,
    uint16_t wKeyNoDAMEnc, uint16_t wKeyVerDAMEnc,
    uint16_t wKeyNoAppDAMDefault, uint16_t wKeyVerAppDAMDefault, uint8_t bAppDAMDefaultKeyVer,
    uint8_t *pDAMEncKey)
{
  phStatus_t  PH_MEMLOC_REM statusTmp;
  uint8_t     PH_MEMLOC_REM bWorkBuffer[32];
  uint8_t     PH_MEMLOC_REM bKey[PH_CRYPTOSYM_3K3DES_KEY_SIZE];
  uint16_t    PH_MEMLOC_REM wKeyType;
  uint8_t     PH_MEMLOC_REM bWorkBufferLen = 0;
  uint8_t     PH_MEMLOC_REM bTmpIV[PH_CRYPTOSYM_AES_BLOCK_SIZE];
  uint8_t     PH_MEMLOC_REM bIVLength;
  uint8_t     PH_MEMLOC_REM bRndLength = 0x07;

  /* Get Key out of the key store object */
  PH_CHECK_SUCCESS_FCT(statusTmp, phKeyStore_GetKey(
          pDataParams->pKeyStoreDataParams,
          wKeyNoAppDAMDefault,
          wKeyVerAppDAMDefault,
          PH_CRYPTOSYM_3K3DES_KEY_SIZE,
          bKey,
          &wKeyType
      ));
  /* Set the work buffer to all 0s initially */
  (void)memset(bWorkBuffer, 0x00, (size_t)sizeof(bWorkBuffer));

  if (wKeyType == PH_CRYPTOSYM_KEY_TYPE_AES128) {
    bWorkBufferLen +=  bRndLength;
    (void)memcpy(&bWorkBuffer[bWorkBufferLen], bKey,
        PH_CRYPTOSYM_AES128_KEY_SIZE); /*  bWorkBuffer[7-22] = bKey */
    bWorkBufferLen += PH_CRYPTOSYM_AES128_KEY_SIZE;
    bWorkBuffer[bWorkBufferLen++] =
        bAppDAMDefaultKeyVer;                       /* bWorkBuffer[23] = bAppDAMDefaultKeyVer */
  } else if (wKeyType == PH_CRYPTOSYM_KEY_TYPE_DES) {
    bWorkBufferLen +=  bRndLength;
    (void)memcpy(&bWorkBuffer[bWorkBufferLen], bKey,
        PH_CRYPTOSYM_DES_KEY_SIZE);        /* bWorkBuffer[7-14] = bKey */
    bWorkBufferLen +=
        PH_CRYPTOSYM_DES_KEY_SIZE;                                /* bWorkBufferLen = 15 */
    (void)memcpy(&bWorkBuffer[bWorkBufferLen], bKey,
        PH_CRYPTOSYM_DES_KEY_SIZE);        /* bWorkBuffer[15-22] = bKey */
    bWorkBuffer[bWorkBufferLen++] =
        bAppDAMDefaultKeyVer;                       /* bWorkBuffer[23] = bAppDAMDefaultKeyVer */
  } else if (wKeyType == PH_CRYPTOSYM_KEY_TYPE_2K3DES) {
    bWorkBufferLen +=  bRndLength;
    (void)memcpy(&bWorkBuffer[bWorkBufferLen], bKey,
        PH_CRYPTOSYM_AES128_KEY_SIZE); /*  bWorkBuffer[7-22] = bKey */
    bWorkBufferLen += PH_CRYPTOSYM_2K3DES_KEY_SIZE;
    bWorkBuffer[bWorkBufferLen++] =
        bAppDAMDefaultKeyVer;                       /* bWorkBuffer[23] = bAppDAMDefaultKeyVer */
  } else if (wKeyType == PH_CRYPTOSYM_KEY_TYPE_3K3DES) {
    bWorkBufferLen +=  bRndLength;
    (void)memcpy(&bWorkBuffer[bWorkBufferLen], bKey,
        PH_CRYPTOSYM_3K3DES_KEY_SIZE);     /* bWorkBuffer[7-30] =  bKey */
    bWorkBufferLen += PH_CRYPTOSYM_3K3DES_KEY_SIZE;
    bWorkBuffer[bWorkBufferLen++] =
        bAppDAMDefaultKeyVer;                       /* bWorkBuffer[31] = bAppDAMDefaultKeyVer */
  } else {
    return PH_ADD_COMPCODE_FIXED(PH_ERR_KEY, PH_COMP_AL_MFDFEVX);
  }

  /*
   * As per the Ref Arch, 7 bytes random number should be appended for KAppDAMDefault + KeyVerAppDAMDefault. Formula is as given below,
   * EncK = EDAM(KPICCDAMENC,Random(7)||KAppDAMDefault || KeyVerAppDAMDefault).
   *
   * That is, bWorkBuffer[0-6] =  Random number
   */
  PH_CHECK_SUCCESS_FCT(statusTmp, phCryptoRng_Rnd(
          pDataParams->pCryptoRngDataParams,
          bRndLength,
          bWorkBuffer
      ));

  /* Get Key out of the key store object for encyption */
  PH_CHECK_SUCCESS_FCT(statusTmp, phKeyStore_GetKey(
          pDataParams->pKeyStoreDataParams,
          wKeyNoDAMEnc,
          wKeyVerDAMEnc,
          PH_CRYPTOSYM_3K3DES_KEY_SIZE,
          bKey,
          &wKeyType
      ));
  /* relevant is the key type of the key which is used for the encryption */
  if (wKeyType == PH_KEYSTORE_KEY_TYPE_AES128) {
    bIVLength = PH_CRYPTOSYM_AES_BLOCK_SIZE;
  } else {
    bIVLength = PH_CRYPTOSYM_DES_BLOCK_SIZE;
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
          bIVLength
      ));

  /* Encrypt bWorkBuffer to obtain DAMEncKey */
  PH_CHECK_SUCCESS_FCT(statusTmp, phCryptoSym_Encrypt(
          pDataParams->pCryptoDataParamsEnc,
          PH_CRYPTOSYM_CIPHER_MODE_CBC | PH_EXCHANGE_DEFAULT,
          bWorkBuffer,
          (PH_CRYPTOSYM_AES_BLOCK_SIZE * 2U),
          pDAMEncKey
      ));

  /* Restore back the IV */
  (void)memcpy(pDataParams->bIv, bTmpIV, PH_CRYPTOSYM_AES_BLOCK_SIZE);

  if (pDataParams->bAuthMode != PHAL_MFDFEVX_NOT_AUTHENTICATED) {
    /* Load back the session key */
    PH_CHECK_SUCCESS_FCT(statusTmp, phCryptoSym_LoadKeyDirect(
            pDataParams->pCryptoDataParamsEnc,
            pDataParams->bSesAuthENCKey,
            pDataParams->bCryptoMethod
        ));
  }

  return PH_ERR_SUCCESS;
}

phStatus_t
phalMfdfEVx_Sw_GenerateDAMMAC(phalMfdfEVx_Sw_DataParams_t *pDataParams,
    uint8_t bOption, uint16_t wKeyNoDAMMAC,
    uint16_t wKeyVerDAMMAC, uint8_t *pAid, uint8_t *pDamParams, uint8_t bKeySettings1,
    uint8_t bKeySettings2,
    uint8_t bKeySettings3, uint8_t *pKeySetValues, uint8_t *pISOFileId, uint8_t *pISODFName,
    uint8_t bISODFNameLen, uint8_t *pEncK, uint8_t *pDAMMAC)
{
  phStatus_t  PH_MEMLOC_REM statusTmp;
  uint8_t     PH_MEMLOC_REM bWorkBuffer[48]; /* bWorkBuffer should be 33 bytes + copy  EncK */
  uint8_t     PH_MEMLOC_REM bKey[PH_CRYPTOSYM_3K3DES_KEY_SIZE];
  uint8_t     PH_MEMLOC_REM bCMAC[PH_CRYPTOSYM_AES_BLOCK_SIZE] = {0};
  uint8_t     PH_MEMLOC_REM bMacLen = 0;
  uint16_t    PH_MEMLOC_REM wKeyType;
  uint8_t     PH_MEMLOC_REM bWorkBufferLen = 0;
  uint8_t     PH_MEMLOC_REM bTmpIV[PH_CRYPTOSYM_AES_BLOCK_SIZE];
  uint8_t     PH_MEMLOC_REM bTmp = 0;
  uint8_t     PH_MEMLOC_REM bIVLength = PH_CRYPTOSYM_DES_BLOCK_SIZE;

  if (!(bOption & PHAL_MFDFEVX_GENERATE_DAMMAC_DELETE_APPLICATION)) {
    bWorkBuffer[bWorkBufferLen++] = PHAL_MFDFEVX_CMD_CREATE_DELEGATED_APPLN;
  } else {
    bWorkBuffer[bWorkBufferLen++] = PHAL_MFDFEVX_CMD_DELETE_APPLN;
  }

  (void)memcpy(&bWorkBuffer[bWorkBufferLen], pAid, 3);
  bWorkBufferLen += 3U;

  if (!(bOption & PHAL_MFDFEVX_GENERATE_DAMMAC_DELETE_APPLICATION)) {
    /* Size of DAMSlotNo is changed to 2 byte  */
    (void)memcpy(&bWorkBuffer[bWorkBufferLen], pDamParams, 5);
    bWorkBufferLen += 5U;
    bWorkBuffer[bWorkBufferLen++] = bKeySettings1;
    bWorkBuffer[bWorkBufferLen++] = bKeySettings2;
    if (0U != (bKeySettings2 & PHAL_MFDFEVX_KEYSETT3_PRESENT)) {
      bWorkBuffer[bWorkBufferLen++] = bKeySettings3;
      if ((bKeySettings3 & PHAL_MFDFEVX_KEYSETVALUES_PRESENT) && (pKeySetValues != NULL)) {
        (void)memcpy(&bWorkBuffer[bWorkBufferLen], pKeySetValues, 4);
        bWorkBufferLen += 4U;
      }
    }
    if (0U != (bOption & 0x01U)) {
      (void)memcpy(&bWorkBuffer[bWorkBufferLen], pISOFileId, 2);
      bWorkBufferLen += 2U;
    }
    if (0U != (bOption & 0x02U)) {
      (void)memcpy(&bWorkBuffer[bWorkBufferLen], pISODFName, bISODFNameLen);
      bWorkBufferLen += bISODFNameLen;
    }
  }

  /* Get Key out of the key store object */
  PH_CHECK_SUCCESS_FCT(statusTmp, phKeyStore_GetKey(
          pDataParams->pKeyStoreDataParams,
          wKeyNoDAMMAC,
          wKeyVerDAMMAC,
          PH_CRYPTOSYM_3K3DES_KEY_SIZE,
          bKey,
          &wKeyType
      ));

  /* Invalid key type at wKeyNoDAMMAC and wKeyVerDAMMAC */
  if (wKeyType == PH_CRYPTOSYM_KEY_TYPE_AES128) {
    bIVLength = PH_CRYPTOSYM_AES_BLOCK_SIZE;
  }

  if (!(bOption & PHAL_MFDFEVX_GENERATE_DAMMAC_DELETE_APPLICATION)) {
    bTmp = (bIVLength - (bWorkBufferLen % bIVLength));
    (void)memcpy(&bWorkBuffer[bWorkBufferLen], pEncK, bTmp);
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
          bIVLength
      ));

  if (!(bOption & PHAL_MFDFEVX_GENERATE_DAMMAC_DELETE_APPLICATION)) {
    /* Calculate MAC */
    PH_CHECK_SUCCESS_FCT(statusTmp, phCryptoSym_CalculateMac(
            pDataParams->pCryptoDataParamsMac,
            (PH_CRYPTOSYM_MAC_MODE_CMAC | PH_EXCHANGE_BUFFER_FIRST),
            bWorkBuffer,
            (bWorkBufferLen + bTmp),
            bCMAC,
            &bMacLen
        ));

    if (bTmp < 32U) {
      PH_CHECK_SUCCESS_FCT(statusTmp, phCryptoSym_CalculateMac(
              pDataParams->pCryptoDataParamsMac,
              (PH_CRYPTOSYM_MAC_MODE_CMAC | PH_EXCHANGE_BUFFER_LAST),
              &pEncK[bTmp],
              (32u - bTmp),
              bCMAC,
              &bMacLen
          ));
    }
  } else {
    /* Calculate MAC */
    PH_CHECK_SUCCESS_FCT(statusTmp, phCryptoSym_CalculateMac(
            pDataParams->pCryptoDataParamsMac,
            (PH_CRYPTOSYM_MAC_MODE_CMAC),
            bWorkBuffer,
            bWorkBufferLen,
            bCMAC,
            &bMacLen
        ));
  }

  if (wKeyType == PH_CRYPTOSYM_KEY_TYPE_AES128) {
    /* Truncate the Calculated CMAC */
    phalMfdfEVx_Sw_Int_TruncateMac(bCMAC);
  }

  /* Copy the Truncated CMAC into the return buffer */
  (void)memcpy(pDAMMAC, bCMAC, PHAL_MFDFEVX_TRUNCATED_MAC_SIZE);

  /* Restore back the IV */
  (void)memcpy(pDataParams->bIv, bTmpIV, PH_CRYPTOSYM_AES_BLOCK_SIZE);

  if (pDataParams->bAuthMode != PHAL_MFDFEVX_NOT_AUTHENTICATED) {
    /* Load back the session key */
    PH_CHECK_SUCCESS_FCT(statusTmp, phCryptoSym_LoadKeyDirect(
            pDataParams->pCryptoDataParamsMac,
            pDataParams->bSesAuthMACKey,
            pDataParams->bCryptoMethod
        ));
  }

  return PH_ERR_SUCCESS;
}

phStatus_t
phalMfdfEVx_Sw_GenerateDAMMACSetConfig(phalMfdfEVx_Sw_DataParams_t *pDataParams,
    uint16_t wKeyNoDAMMAC,
    uint16_t wKeyVerDAMMAC, uint16_t wOldDFNameLen, uint8_t *pOldISODFName, uint16_t wNewDFNameLen,
    uint8_t *pNewISODFName, uint8_t *pDAMMAC)
{
  phStatus_t  PH_MEMLOC_REM statusTmp;
  uint8_t     PH_MEMLOC_REM bWorkBuffer[34]; /* bWorkBuffer should be 34 bytes */
  uint8_t     PH_MEMLOC_REM bKey[PH_CRYPTOSYM_3K3DES_KEY_SIZE];
  uint8_t     PH_MEMLOC_REM bCMAC[PH_CRYPTOSYM_AES_BLOCK_SIZE] = {0};
  uint8_t     PH_MEMLOC_REM bMacLen = 0;
  uint16_t    PH_MEMLOC_REM wKeyType;
  uint8_t     PH_MEMLOC_REM bWorkBufferLen = 0;

  if ((wOldDFNameLen > 16U) || (wNewDFNameLen > 16U)) {
    return PH_ADD_COMPCODE_FIXED(PH_ERR_INVALID_PARAMETER, PH_COMP_AL_MFDFEVX);
  }
  (void)memset(bWorkBuffer, 0x00, 34);

  /* Creation of working buffer with old DFNameLen and old DFName */
  bWorkBuffer[bWorkBufferLen++] = (uint8_t) wOldDFNameLen;
  (void)memcpy(&bWorkBuffer[bWorkBufferLen], pOldISODFName, wOldDFNameLen);
  bWorkBufferLen += 0x10U;

  /* Creation of working buffer with new DFNameLen and new DFName */
  bWorkBuffer[bWorkBufferLen++] = (uint8_t) wNewDFNameLen;
  (void)memcpy(&bWorkBuffer[bWorkBufferLen], pNewISODFName, wNewDFNameLen);
  bWorkBufferLen += 0x10U;

  /* Get Key out of the key store object */
  PH_CHECK_SUCCESS_FCT(statusTmp, phKeyStore_GetKey(
          pDataParams->pKeyStoreDataParams,
          wKeyNoDAMMAC,
          wKeyVerDAMMAC,
          PH_CRYPTOSYM_3K3DES_KEY_SIZE,
          bKey,
          &wKeyType
      ));

  /* load key */
  PH_CHECK_SUCCESS_FCT(statusTmp, phCryptoSym_LoadKeyDirect(
          pDataParams->pCryptoDataParamsMac,
          bKey,
          wKeyType));

  /* Calculate MAC */
  PH_CHECK_SUCCESS_FCT(statusTmp, phCryptoSym_CalculateMac(
          pDataParams->pCryptoDataParamsMac,
          PH_CRYPTOSYM_MAC_MODE_CMAC,
          bWorkBuffer,
          bWorkBufferLen,
          bCMAC,
          &bMacLen
      ));

  if (wKeyType == PH_CRYPTOSYM_KEY_TYPE_AES128) {
    /* Truncate the Calculated CMAC */
    phalMfdfEVx_Sw_Int_TruncateMac(bCMAC);
  }

  /* Copy the Truncated CMAC into the return buffer */
  (void)memcpy(pDAMMAC, bCMAC, 8);

  if (pDataParams->bAuthMode != PHAL_MFDFEVX_NOT_AUTHENTICATED) {
    /* Load back the session key */
    PH_CHECK_SUCCESS_FCT(statusTmp, phCryptoSym_LoadKeyDirect(
            pDataParams->pCryptoDataParamsMac,
            pDataParams->bSesAuthMACKey,
            pDataParams->bCryptoMethod
        ));
  }

  return PH_ERR_SUCCESS;
}

phStatus_t
phalMfdfEVx_Sw_CalculateTMV(phalMfdfEVx_Sw_DataParams_t *pDataParams, uint16_t wOption,
    uint16_t wKeyNoTMACKey,
    uint16_t wKeyVerTMACKey, uint8_t *pDivInput, uint8_t bDivInputLen, uint8_t *pTMC, uint8_t *pUid,
    uint8_t bUidLen,
    uint8_t *pTMI, uint32_t dwTMILen, uint8_t *pTMV)
{
  phStatus_t  PH_MEMLOC_REM statusTmp;
  uint8_t     PH_MEMLOC_REM bKey[PH_CRYPTOSYM_AES128_KEY_SIZE];
  uint8_t     PH_MEMLOC_REM bMacLen = 0;
  uint8_t     PH_MEMLOC_REM bKeyLen = 0;
  uint8_t     PH_MEMLOC_REM bSVMacLen = 0;
  uint16_t    PH_MEMLOC_REM wKeyType;
  uint16_t    PH_MEMLOC_REM wTmpTMILen = 0;
  uint16_t    PH_MEMLOC_REM bLoopData = 1;
  uint8_t     PH_MEMLOC_REM bTmpIV[PH_CRYPTOSYM_AES_BLOCK_SIZE];
  uint8_t     PH_MEMLOC_REM bSV[PH_CRYPTOSYM_AES128_KEY_SIZE * 2U];
  uint8_t     PH_MEMLOC_REM bCMAC[PH_CRYPTOSYM_AES_BLOCK_SIZE];
  uint32_t    PH_MEMLOC_REM dwTMC = 0;
  uint32_t    PH_MEMLOC_REM dwTMCtemp = 0;
  uint32_t    PH_MEMLOC_REM dwTMILenWritten = 0;
  uint16_t    PH_MEMLOC_REM wCommMode;

  /*OLD this block is replaced by below for Qmore compliance
  dwTMC |= (uint32_t)pTMC[3];
  dwTMC |= (uint32_t)(pTMC[2] << 8);
  dwTMC |= (uint32_t)(pTMC[1] << 16);
  dwTMC |= (uint32_t)(pTMC[0] << 24); */

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
    return PH_ADD_COMPCODE_FIXED(PH_ERR_PARAMETER_OVERFLOW, PH_COMP_AL_MFDFEVX);
  }

  if ((wOption != PHAL_MFDFEVX_NO_DIVERSIFICATION) && (bDivInputLen > 31U)) {
    return PH_ADD_COMPCODE_FIXED(PH_ERR_INVALID_PARAMETER, PH_COMP_AL_MFDFEVX);
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
    return PH_ADD_COMPCODE_FIXED(PH_ERR_KEY, PH_COMP_AL_MFDFEVX);
  }

  if ((wOption != PHAL_MFDFEVX_NO_DIVERSIFICATION) && (bDivInputLen != 0x00U)) {
    /* Key is diversified and put back in bKey */
    PH_CHECK_SUCCESS_FCT(statusTmp, phCryptoSym_DiversifyDirectKey(
            pDataParams->pCryptoDataParamsEnc,
            wOption,
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

  /* Copy UID into SV - UID can be more than 7 bytes.
  * In this case bSV array size needs to be changed
  */
  (void)memcpy(&bSV[bSVMacLen], pUid, bUidLen);

  bSVMacLen += bUidLen;

  /* SV padded with the zero bytes up to a length of multiple of 16 bytes (if needed)*/
  if (bSVMacLen < (PH_CRYPTOSYM_AES128_KEY_SIZE * 2U)) {
    (void)memset(&bSV[bSVMacLen], 0x00, ((PH_CRYPTOSYM_AES128_KEY_SIZE * 2U) - bSVMacLen));
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

  /* Encrypt SV to obtain SesTMMACKey */
  PH_CHECK_SUCCESS_FCT(statusTmp, phCryptoSym_CalculateMac(
          pDataParams->pCryptoDataParamsEnc,
          (PH_CRYPTOSYM_MAC_MODE_CMAC | PH_EXCHANGE_DEFAULT),
          bSV,
          (uint16_t)((bUidLen == 0x0AU) ? (PH_CRYPTOSYM_AES_BLOCK_SIZE * 2U) :
              (PH_CRYPTOSYM_AES_BLOCK_SIZE)),
          bKey,
          &bKeyLen
      ));

  /* Now calculate TMV as TMV = MACtTM(KSesTMMAC; TMI) */
  /* load key -SesTMMACKey*/
  PH_CHECK_SUCCESS_FCT(statusTmp, phCryptoSym_LoadKeyDirect(
          pDataParams->pCryptoDataParamsMac,
          bKey,
          PH_CRYPTOSYM_KEY_TYPE_AES128));

  /* Load Iv */
  PH_CHECK_SUCCESS_FCT(statusTmp, phCryptoSym_LoadIv(
          pDataParams->pCryptoDataParamsMac,
          pDataParams->bIv,
          PH_CRYPTOSYM_AES_BLOCK_SIZE
      ));

  /* to handle 2 MB of data update maximum of data bytes that can be sent in a single loop */
  if (dwTMILen > PHAL_MFDFEVX_MAX_WRITE_SIZE) {
    wTmpTMILen = (uint16_t)PHAL_MFDFEVX_MAX_WRITE_SIZE;
    bLoopData = (uint8_t)(dwTMILen / PHAL_MFDFEVX_MAX_WRITE_SIZE);
    if (0U != (dwTMILen % PHAL_MFDFEVX_MAX_WRITE_SIZE)) {
      bLoopData++;
    }
    wCommMode = PH_EXCHANGE_BUFFER_FIRST;
  } else {
    wTmpTMILen = (uint16_t)dwTMILen;
    wCommMode = PH_EXCHANGE_DEFAULT;
  }

  do {

    if (bLoopData == 1U) {
      wTmpTMILen = (uint16_t)(dwTMILen - dwTMILenWritten);
    }
    /* Encrypt TMI to obtain TMV */
    PH_CHECK_SUCCESS_FCT(statusTmp, phCryptoSym_CalculateMac(
            pDataParams->pCryptoDataParamsMac,
            (PH_CRYPTOSYM_MAC_MODE_CMAC | wCommMode),
            &pTMI[dwTMILenWritten],
            wTmpTMILen,
            bCMAC,
            &bMacLen
        ));
    bLoopData--;
    wCommMode = (bLoopData == 1U) ? PH_EXCHANGE_BUFFER_LAST : PH_EXCHANGE_BUFFER_CONT;
    dwTMILenWritten += wTmpTMILen;
  } while (bLoopData > 0U);

  /* Truncate the Calculated CMAC */
  phalMfdfEVx_Sw_Int_TruncateMac(bCMAC);

  /* Copy the Truncated CMAC into the return buffer */
  (void)memcpy(pTMV, bCMAC, PHAL_MFDFEVX_TRUNCATED_MAC_SIZE);

  /* Restore back the IV */
  (void)memcpy(pDataParams->bIv, bTmpIV, PH_CRYPTOSYM_AES_BLOCK_SIZE);

  if (pDataParams->bAuthMode != PHAL_MFDFEVX_NOT_AUTHENTICATED) {
    /* Load the session key */
    PH_CHECK_SUCCESS_FCT(statusTmp, phCryptoSym_LoadKeyDirect(
            pDataParams->pCryptoDataParamsEnc,
            pDataParams->bSesAuthENCKey,
            pDataParams->bCryptoMethod
        ));

    /* Load the session key */
    PH_CHECK_SUCCESS_FCT(statusTmp, phCryptoSym_LoadKeyDirect(
            pDataParams->pCryptoDataParamsMac,
            pDataParams->bSesAuthMACKey,
            pDataParams->bCryptoMethod
        ));
  }

  return PH_ERR_SUCCESS;
}

phStatus_t
phalMfdfEVx_Sw_DecryptReaderID(phalMfdfEVx_Sw_DataParams_t *pDataParams,
    uint16_t wOption, uint16_t wKeyNoTMACKey,
    uint16_t wKeyVerTMACKey, uint8_t *pDivInput, uint8_t bDivInputLen, uint8_t *pTMC, uint8_t *pUid,
    uint8_t bUidLen,
    uint8_t *pEncTMRI, uint8_t *pTMRIPrev)
{
  phStatus_t  PH_MEMLOC_REM statusTmp;
  uint8_t     PH_MEMLOC_REM bKey[PH_CRYPTOSYM_AES128_KEY_SIZE];
  uint16_t    PH_MEMLOC_REM wKeyType;
  uint8_t     PH_MEMLOC_REM bTmpIV[PH_CRYPTOSYM_AES_BLOCK_SIZE];
  uint8_t     PH_MEMLOC_REM bSV[PH_CRYPTOSYM_AES128_KEY_SIZE * 2U];
  uint32_t    PH_MEMLOC_REM dwTMC = 0;
  uint32_t    PH_MEMLOC_REM dwTMCtemp = 0;
  uint8_t     PH_MEMLOC_REM bSVMacLen = 0;

  /* OLD logic Formation of TMC as double word value
  dwTMC |= (uint32_t)pTMC[3];
  dwTMC |= (uint32_t)(pTMC[2] << 8);
  dwTMC |= (uint32_t)(pTMC[1] << 16);
  dwTMC |= (uint32_t)(pTMC[0] << 24);*/

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
    return PH_ADD_COMPCODE_FIXED(PH_ERR_PARAMETER_OVERFLOW, PH_COMP_AL_MFDFEVX);
  }

  if ((wOption != PHAL_MFDFEVX_NO_DIVERSIFICATION) && (bDivInputLen > 31U)) {
    return PH_ADD_COMPCODE_FIXED(PH_ERR_INVALID_PARAMETER, PH_COMP_AL_MFDFEVX);
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
    return PH_ADD_COMPCODE_FIXED(PH_ERR_KEY, PH_COMP_AL_MFDFEVX);
  }

  if ((wOption != PHAL_MFDFEVX_NO_DIVERSIFICATION) && (bDivInputLen != 0x00U)) {
    /* Key is diversified and put back in bKey */
    PH_CHECK_SUCCESS_FCT(statusTmp, phCryptoSym_DiversifyDirectKey(
            pDataParams->pCryptoDataParamsEnc,
            wOption,
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

  /* Copy UID into SV - UID can be more than 7 bytes.
   * In this case bSV array size needs to be changed
   */
  (void)memcpy(&bSV[bSVMacLen], pUid, bUidLen);

  bSVMacLen += bUidLen;

  /* SV padded with the zero bytes up to a length of multiple of 16 bytes (if needed)*/
  if (bSVMacLen < (PH_CRYPTOSYM_AES128_KEY_SIZE * 2U)) {
    (void)memset(&bSV[bSVMacLen], 0x00, ((PH_CRYPTOSYM_AES128_KEY_SIZE * 2U) - bSVMacLen));
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

  /* Encrypt SV to obtain KSesTMENC */
  PH_CHECK_SUCCESS_FCT(statusTmp, phCryptoSym_CalculateMac(
          pDataParams->pCryptoDataParamsEnc,
          (PH_CRYPTOSYM_MAC_MODE_CMAC | PH_EXCHANGE_DEFAULT),
          bSV,
          (uint16_t)((bUidLen == 0x0AU) ? (PH_CRYPTOSYM_AES_BLOCK_SIZE * 2U) :
              (PH_CRYPTOSYM_AES_BLOCK_SIZE)),
          bKey,
          &bSVMacLen
      ));

  /* load KSesTMENC */
  PH_CHECK_SUCCESS_FCT(statusTmp, phCryptoSym_LoadKeyDirect(
          pDataParams->pCryptoDataParamsEnc,
          bKey,
          PH_CRYPTOSYM_KEY_TYPE_AES128));

  /* Load Iv */
  PH_CHECK_SUCCESS_FCT(statusTmp, phCryptoSym_LoadIv(
          pDataParams->pCryptoDataParamsEnc,
          pDataParams->bIv,
          PH_CRYPTOSYM_AES_BLOCK_SIZE
      ));

  PH_CHECK_SUCCESS_FCT(statusTmp, phCryptoSym_Decrypt(
          pDataParams->pCryptoDataParamsEnc,
          PH_CRYPTOSYM_CIPHER_MODE_CBC | PH_EXCHANGE_DEFAULT,
          pEncTMRI,
          PH_CRYPTOSYM_AES_BLOCK_SIZE,
          pTMRIPrev
      ));

  /* Restore back the IV */
  (void)memcpy(pDataParams->bIv, bTmpIV, PH_CRYPTOSYM_AES_BLOCK_SIZE);

  if (pDataParams->bAuthMode != PHAL_MFDFEVX_NOT_AUTHENTICATED) {
    /* Load the session key */
    PH_CHECK_SUCCESS_FCT(statusTmp, phCryptoSym_LoadKeyDirect(
            pDataParams->pCryptoDataParamsEnc,
            pDataParams->bSesAuthENCKey,
            pDataParams->bCryptoMethod
        ));
  }

  return PH_ERR_SUCCESS;
}

phStatus_t
phalMfdfEVx_Sw_ComputeMFCLicenseMAC(phalMfdfEVx_Sw_DataParams_t *pDataParams,
    uint16_t wOption, uint16_t wMFCLicenseMACKeyNo,
    uint16_t wMFCLicenseMACKeyVer, uint8_t *pInput, uint16_t wInputLen, uint8_t *pDivInput,
    uint8_t bDivInputLen, uint8_t *pMFCLicenseMAC)
{
  phStatus_t  PH_MEMLOC_REM wStatus = 0;
  uint8_t     PH_MEMLOC_REM aKey[PH_CRYPTOSYM_AES128_KEY_SIZE];
  uint8_t     PH_MEMLOC_REM aMac[PH_CRYPTOSYM_AES128_KEY_SIZE];
  uint16_t    PH_MEMLOC_REM wKeyType = 0;
  uint8_t     PH_MEMLOC_REM aIV[16];
  uint8_t     PH_MEMLOC_REM bMFCLicenseMACLen = 0;

  /* Validate the parameters */
  if ((wOption != PHAL_MFDFEVX_NO_DIVERSIFICATION) && (wOption != PHAL_MFDFEVX_DIV_METHOD_CMAC)) {
    return PH_ADD_COMPCODE_FIXED(PH_ERR_INVALID_PARAMETER, PH_COMP_AL_MFDFEVX);
  }

  /* Get the Key value and its type. */
  PH_CHECK_SUCCESS_FCT(wStatus, phKeyStore_GetKey(
          pDataParams->pKeyStoreDataParams,
          wMFCLicenseMACKeyNo,
          wMFCLicenseMACKeyVer,
          PH_CRYPTOSYM_AES128_KEY_SIZE,
          aKey,
          &wKeyType));

  /* Validate the Key type. */
  if (wKeyType != PH_CRYPTOSYM_KEY_TYPE_AES128) {
    return PH_ADD_COMPCODE_FIXED(PH_ERR_KEY, PH_COMP_AL_MFDFEVX);
  }

  /* Create a Backup of the current IV. */
  (void)memcpy(aIV, pDataParams->bIv, PH_CRYPTOSYM_AES_BLOCK_SIZE);

  /* Diversify the Key. */
  if (wOption != PHAL_MFDFEVX_NO_DIVERSIFICATION) {
    PH_CHECK_SUCCESS_FCT(wStatus, phCryptoSym_DiversifyDirectKey(
            pDataParams->pCryptoDataParamsMac,
            wOption,
            aKey,
            wKeyType,
            pDivInput,
            bDivInputLen,
            aKey));
  }

  /* Load the Key for MAC computation. */
  PH_CHECK_SUCCESS_FCT(wStatus, phCryptoSym_LoadKeyDirect(
          pDataParams->pCryptoDataParamsMac,
          aKey,
          PH_CRYPTOSYM_KEY_TYPE_AES128));

  /* Load Iv */
  PH_CHECK_SUCCESS_FCT(wStatus, phCryptoSym_LoadIv(
          pDataParams->pCryptoDataParamsMac,
          phalMfdfEVx_Sw_FirstIv,
          PH_CRYPTOSYM_AES_BLOCK_SIZE));

  /* Compute the MAC for the Input provided. */
  wStatus = phCryptoSym_CalculateMac(
          pDataParams->pCryptoDataParamsMac,
          PH_CRYPTOSYM_MAC_MODE_CMAC,
          pInput,
          wInputLen,
          aMac,
          &bMFCLicenseMACLen);

  /* Reset the SessionMACKey. */
  if (pDataParams->bAuthMode != PHAL_MFDFEVX_NOT_AUTHENTICATED) {
    PH_CHECK_SUCCESS_FCT(wStatus, phCryptoSym_LoadKeyDirect(
            pDataParams->pCryptoDataParamsMac,
            pDataParams->bSesAuthMACKey,
            pDataParams->bCryptoMethod));
  }

  /* Validate Status. */
  PH_CHECK_SUCCESS(wStatus);

  /* Truncate the MAC. */
  phalMfdfEVx_Sw_Int_TruncateMac(aMac);
  (void)memcpy(pMFCLicenseMAC, aMac, 8);

  /* Restore the IV. */
  (void)memcpy(pDataParams->bIv, aIV, PH_CRYPTOSYM_AES_BLOCK_SIZE);

  return PH_ERR_SUCCESS;
}

phStatus_t
phalMfdfEVx_Sw_CalculateMACSDM(phalMfdfEVx_Sw_DataParams_t *pDataParams,
    uint8_t bSdmOption, uint16_t wSDMMacKeyNo,
    uint16_t wSDMMacKeyVer, uint8_t *pUid, uint8_t bUidLen, uint8_t *pSDMReadCtr, uint8_t *pInData,
    uint16_t wInDataLen,
    uint8_t *pRespMac)
{
  phStatus_t  PH_MEMLOC_REM statusTmp = PH_ERR_SUCCESS;
  uint8_t     PH_MEMLOC_REM bTmpIV[PH_CRYPTOSYM_AES_BLOCK_SIZE];
  uint8_t     PH_MEMLOC_REM bCMAC[PH_CRYPTOSYM_AES_BLOCK_SIZE];
  uint8_t     PH_MEMLOC_REM bSVMacLen = 0;
  uint8_t     PH_MEMLOC_REM bSdmSessMacKey[16] = { '\0' };

  PH_CHECK_SUCCESS_FCT(statusTmp, phalMfdfEVx_Sw_Int_ComputeSDMSessionVectors(pDataParams,
          PHAL_MFDFEVX_SESSION_MAC,
          bSdmOption,
          wSDMMacKeyNo,
          wSDMMacKeyVer,
          pUid,
          bUidLen,
          pSDMReadCtr,
          bSdmSessMacKey));

  /* load Key */
  PH_CHECK_SUCCESS_FCT(statusTmp, phCryptoSym_LoadKeyDirect(
          pDataParams->pCryptoDataParamsMac,
          bSdmSessMacKey,
          PH_CRYPTOSYM_KEY_TYPE_AES128));

  /* Load zero to IV */
  (void)memset(pDataParams->bIv, 0x00, PH_CRYPTOSYM_AES_BLOCK_SIZE);

  /* Load Iv */
  PH_CHECK_SUCCESS_FCT(statusTmp, phCryptoSym_LoadIv(
          pDataParams->pCryptoDataParamsMac,
          pDataParams->bIv,
          PH_CRYPTOSYM_AES_BLOCK_SIZE));

  /* Mac The Input Data using K(sessionSDMMacKey) to obtain SDMMac.  */
  PH_CHECK_SUCCESS_FCT(statusTmp, phCryptoSym_CalculateMac(
          pDataParams->pCryptoDataParamsMac,
          (PH_CRYPTOSYM_MAC_MODE_CMAC | PH_EXCHANGE_DEFAULT),
          pInData,
          wInDataLen,
          bCMAC,
          &bSVMacLen));

  /* Truncate the MAC generated */
  phalMfdfEVx_Sw_Int_TruncateMac(bCMAC);

  /* Copy the Truncated CMAC into the return buffer */
  (void)memcpy(pRespMac, bCMAC, PHAL_MFDFEVX_TRUNCATED_MAC_SIZE);

  /*Memsetting the Temporary IV*/
  (void)memset(bTmpIV, 0x00, PH_CRYPTOSYM_AES_BLOCK_SIZE);

  /* Restore back the IV */
  (void)memcpy(pDataParams->bIv, bTmpIV, PH_CRYPTOSYM_AES_BLOCK_SIZE);

  if (pDataParams->bAuthMode != PHAL_MFDFEVX_NOT_AUTHENTICATED) {
    /* Load the session key */
    PH_CHECK_SUCCESS_FCT(statusTmp, phCryptoSym_LoadKeyDirect(
            pDataParams->pCryptoDataParamsMac,
            pDataParams->bSesAuthMACKey,
            pDataParams->bCryptoMethod));
  }

  return PH_ERR_SUCCESS;
}

phStatus_t
phalMfdfEVx_Sw_DecryptSDMENCFileData(phalMfdfEVx_Sw_DataParams_t *pDataParams,
    uint8_t bSdmOption, uint16_t wEncKeyNo,
    uint16_t wEncKeyVer, uint8_t *pUid, uint8_t bUidLen, uint8_t *pSDMReadCtr, uint8_t *pEncdata,
    uint16_t wEncDataLen,
    uint8_t *pPlainData)
{
  phStatus_t  PH_MEMLOC_REM statusTmp = PH_ERR_SUCCESS;
  uint8_t     PH_MEMLOC_REM bSdmSessEncKey[16] = { '\0' };
  uint8_t     PH_MEMLOC_REM bIV[16] = { '\0' };

  /* Generate Session Keys*/
  PH_CHECK_SUCCESS_FCT(statusTmp, phalMfdfEVx_Sw_Int_ComputeSDMSessionVectors(pDataParams,
          PHAL_MFDFEVX_SESSION_ENC,
          bSdmOption,
          wEncKeyNo,
          wEncKeyVer,
          pUid,
          bUidLen,
          pSDMReadCtr,
          bSdmSessEncKey));

  /* Step-2 : Compute IV */
  PH_CHECK_SUCCESS_FCT(statusTmp, phalMfdfEVx_Sw_Int_ComputeSDMIV(pDataParams,
          bSdmSessEncKey,
          pSDMReadCtr,
          bIV));

  /* Step-3 : Decrypyt data */
  PH_CHECK_SUCCESS_FCT(statusTmp, phalMfdfEVx_Sw_Int_DecryptSDMData(pDataParams,
          bSdmSessEncKey,
          bIV,
          pEncdata,
          wEncDataLen));

  /* Copy the OutPut Buffer to Plain data */
  (void)memcpy(pPlainData, pEncdata, wEncDataLen);

  return PH_ERR_SUCCESS;
}

phStatus_t
phalMfdfEVx_Sw_DecryptSDMPICCData(phalMfdfEVx_Sw_DataParams_t *pDataParams,
    uint16_t wKeyNo, uint16_t wKeyVer,
    uint8_t *pIndata, uint16_t wInDataLen, uint8_t *pPlainData)
{
  phStatus_t  PH_MEMLOC_REM statusTmp = PH_ERR_SUCCESS;
  uint8_t     PH_MEMLOC_REM bIV[PH_CRYPTOSYM_AES128_KEY_SIZE] = { '\0' };

  uint8_t   PH_MEMLOC_REM bKey[PH_CRYPTOSYM_AES128_KEY_SIZE];
  uint16_t  PH_MEMLOC_REM wKeyType;

  /*  Get the Keys from SW Key Store */
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

  /* Load zero to IV */
  (void)memset(pDataParams->bIv, 0x00, PH_CRYPTOSYM_AES_BLOCK_SIZE);

  /* Decrypt Data */
  PH_CHECK_SUCCESS_FCT(statusTmp, phalMfdfEVx_Sw_Int_DecryptSDMData(pDataParams,
          bKey,
          bIV,
          pIndata,
          wInDataLen));

  /* Copy the OutPut Buffer to Plain data */
  (void)memcpy(pPlainData, pIndata, wInDataLen);

  return PH_ERR_SUCCESS;
}
#endif /* NXPBUILD__PHAL_MFDFEVX_NDA */

phStatus_t
phalMfdfEVx_Sw_SetVCAParams(phalMfdfEVx_Sw_DataParams_t *pDataParams,
    void *pAlVCADataParams)
{
  PH_ASSERT_NULL(pDataParams);
  PH_ASSERT_NULL(pAlVCADataParams);

  pDataParams->pVCADataParams = pAlVCADataParams;

  return PH_ERR_SUCCESS;
}

#endif /* NXPBUILD__PHAL_MFDFEVX_SW */
