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

#include <nxp_nfc/ph_Status.h>
#include <nxp_nfc/ph_RefDefs.h>
#include <nxp_nfc/phKeyStore.h>
#include <nxp_nfc/phhalHw.h>

#ifdef NXPBUILD__PH_KEYSTORE_SAMAV3

#include "phKeyStore_SamAv3.h"
#include "phKeyStore_SamAv3_Int.h"
#include <nxp_nfc/phhalHw_SamAv3_Cmd.h>

/**
 * Initializes the Sam AV3 Keystore component.
 *
 * Input Parameters:
 *		pDataParams			: Pointer to this layer's parameter structure.
 *		wSizeOfDataParams	: Specifies the size of the data parameter structure.
 *		pHalDataParams		: Pointer to the parameter structure of the underlying HAL layer.
 *
 * Return:
 *			PH_ERR_SUCCESS for successfull operation.
 *			Other Depending on implementation and underlaying component.
 */
phStatus_t
phKeyStore_SamAV3_Init(phKeyStore_SamAV3_DataParams_t *pDataParams, uint16_t wSizeOfDataParams,
    phhalHw_SamAV3_DataParams_t *pHalDataParams)
{
  phStatus_t	PH_MEMLOC_REM wStatus = 0;

  if (sizeof(phKeyStore_SamAV3_DataParams_t) != wSizeOfDataParams) {
    return PH_ADD_COMPCODE(PH_ERR_INVALID_DATA_PARAMS, PH_COMP_KEYSTORE);
  }

  PH_ASSERT_NULL_DATA_PARAM(pDataParams, PH_COMP_KEYSTORE);
  PH_ASSERT_NULL_PARAM(pHalDataParams, PH_COMP_KEYSTORE);

  /* Init private data */
  pDataParams->wId = PH_COMP_KEYSTORE | PH_KEYSTORE_SAMAV3_ID;
  pDataParams->pHalDataParams = pHalDataParams;
  pDataParams->bIsLRPKey = PH_OFF;

  /* Set defaults */
  PH_CHECK_SUCCESS_FCT(wStatus, phKeyStore_SamAV3_SetConfig(
          pDataParams,
          PH_KEYSTORE_CONFIG_SET_DEFAULT, PH_ON));

  return PH_ADD_COMPCODE(PH_ERR_SUCCESS, PH_COMP_KEYSTORE);
}

/**
 * Format a key entry to a new KeyType.
 *
 * The function changes a symmetric key entry of the SAM to a new key type. First the command \ref phhalHw_SamAV3_Cmd_SAM_GetKeyEntry
 * is executed to get the current change key number of the key entry. Afterwards a new key entry is written by the
 * \ref phhalHw_SamAV3_Cmd_SAM_ChangeKeyEntry command. The keys and key versions, of this new entry are set to zero. DF_Aid, DFKeyNo,
 * RefNoKUC, SET, ExtSET, KeyNoCEK, KeyVCEK, KeyNoAEK and KeyVAEK are set according to the configuration parameters. \n
 *
 * In case of a MIFARE key entry the diversification keys for key A and key B of all key versions are set according to the configuration
 * parameters. These parameters can be accessd via #PH_KEYSTORE_SAMAV3_CONFIG_KEYNO_MF_DIV_A and #PH_KEYSTORE_SAMAV3_CONFIG_KEYV_MF_DIV_A
 * resp. #PH_KEYSTORE_SAMAV3_CONFIG_KEYNO_MF_DIV_B and #PH_KEYSTORE_SAMAV3_CONFIG_KEYV_MF_DIV_B.
 *
 * Input Parameters:
 *		pDataParams			: Pointer to this layer's parameter structure.
 *		wKeyNo				: KeyEntry number to be formatted.
 *		wKeyType			: New key type of the KeyEntry (predefined type of KeyType).
 *
 * Return:
 *			PH_ERR_SUCCESS for successfull operation.
 *			Other Depending on implementation and underlaying component.
 */
phStatus_t
phKeyStore_SamAV3_FormatKeyEntry(phKeyStore_SamAV3_DataParams_t *pDataParams, uint16_t wKeyNo,
    uint16_t wKeyType)
{
  phStatus_t						PH_MEMLOC_REM wStatus = 0;
//	uint8_t							PH_MEMLOC_REM bCurrKeyNoCEK = 0; //Set but not used
  uint8_t							PH_MEMLOC_REM bProMas =
      0;	/* For updating the P2 information byte of SAM ChangeKeyEntry command frame. */
  uint8_t							PH_MEMLOC_REM aNullKey[48 /* Max size to allocate 3 AES128 keys. */];
  uint8_t							PH_MEMLOC_REM bKeyLen = 0;
  uint8_t							PH_MEMLOC_REM aKeyEntryBuff[PHHAL_HW_SAMAV3_KEYENTRY_SIZE];
  uint8_t							PH_MEMLOC_REM bKeyEntryLen = 0;
  uint8_t							PH_MEMLOC_REM bIsRamKey = PH_OFF;
  phKeyStore_SamAV3_KeyEntry_t	PH_MEMLOC_REM stKeyEntry;

  /* Check for Invalid Key No. */
  if (wKeyNo == PH_KEYSTORE_INVALID_ID) {
    return PH_ADD_COMPCODE(PH_ERR_INVALID_PARAMETER, PH_COMP_KEYSTORE);
  }

  /* Check if its RAM key. */
  if (wKeyNo > PH_KEYSTORE_SAMAV3_NVM_KEY_MAX) {
    bIsRamKey = PH_ON;
  }

  /* Reset the buffer. */
  memset(aNullKey, 0x00, 48); /* PRQA S 3200 */

  /* Update the null key if key type is MIFAE. */
  if (wKeyType == PH_KEYSTORE_KEY_TYPE_MIFARE) {
    aNullKey[6] = pDataParams->bKeyNoMfDivA;
    aNullKey[7] = pDataParams->bKeyVMfDivA;
    aNullKey[14] = pDataParams->bKeyNoMfDivB;
    aNullKey[15] = pDataParams->bKeyVMfDivB;
  }

  /* Get the current KeyEntry information from SAM. */
  PH_CHECK_SUCCESS_FCT(wStatus, phKeyStore_SamAV3_Int_GetKeyEntry(
          pDataParams,
          (uint8_t) wKeyNo,
          bIsRamKey,
          &stKeyEntry));

  /* Save Current Change Entry key value. */
//	bCurrKeyNoCEK = stKeyEntry.bKeyNoCEK; //Set but not used

  /* Set the key buffers with NullKey buffer. */
  memcpy(stKeyEntry.aKeyData, aNullKey, 48); /* PRQA S 3200 */

  /* Update the retreived Set and ExtSET values to internal KeyEntry structure. */
  stKeyEntry.aSet[0] = pDataParams->aSet[0];
  stKeyEntry.aSet[1] = pDataParams->aSet[1];
  stKeyEntry.aExtSet[0] = pDataParams->aExtSet[0];
  stKeyEntry.aExtSet[1] = pDataParams->aExtSet[1];

  /* RESET old key entry setting */
  stKeyEntry.aSet[0] &= (uint8_t) ~(uint8_t) PH_KEYSTORE_SAMAV3_KEYTYPE_MASK;

  /* Define new Key type and Key B, Key C validity. */
  PH_CHECK_SUCCESS_FCT(wStatus, phKeyStore_SamAV3_Int_SetKeyType(
          &stKeyEntry,
          wKeyType,
          pDataParams->b2K3DESOption,
          pDataParams->bIsLRPKey));

  /* Reset Key version. */
  stKeyEntry.bVersionKeyA = 0x00;
  stKeyEntry.bVersionKeyB = 0x00;
  stKeyEntry.bVersionKeyC = 0x00;

  /* Copy the DFAid and DF_KeyNo to internal KeyEntry structure. */
  memcpy(stKeyEntry.aDFAid, pDataParams->aDFAid, 3); /* PRQA S 3200 */
  stKeyEntry.bDFKeyNo = pDataParams->bDFKeyNo;

  /* Update the internal KeyEntry structure with reference KUC number, CEK, AEK key number and version. */
  stKeyEntry.bKeyNoCEK = pDataParams->bKeyNoCEK;
  stKeyEntry.bKeyVCEK  = pDataParams->bKeyVCEK;
  stKeyEntry.bRefNoKUC = pDataParams->bRefNoKUC;
  stKeyEntry.bKeyNoAEK = pDataParams->bKeyNoAEK;
  stKeyEntry.bKeyVAEK  = pDataParams->bKeyVAEK;

  /* Update the Program mask which will be used for P2 information of ChangeKeyEntry command. */
  if (bIsRamKey) {
    /* Update ProMask for Key A only. */
    bProMas = 0x8F;
  } else {
    bProMas = 0x9F;

    /* Update the Program Mask to include Key B information. */
    if (stKeyEntry.bVersionKeyBValid == PH_ON) {
      bProMas |= 0xDF;
    }

    /* Update the Program Mask to include Key C information. */
    if (stKeyEntry.bVersionKeyCValid == PH_ON) {
      bProMas |= 0xFF;
    }
  }

  /* Update the key length. */
  bKeyLen = (uint8_t)((stKeyEntry.bVersionKeyCValid || stKeyEntry.bVersionKeyBValid) ? 48 : 32);

  /* Convert the KeyEntry information to bytes. */
  PH_CHECK_SUCCESS_FCT(wStatus, phKeyStore_SamAV3_Int_ConvertKeyEntryToBuffer(
          pDataParams,
          &stKeyEntry,
          stKeyEntry.aKeyData,
          bKeyLen,
          aKeyEntryBuff,
          &bKeyEntryLen));

  /* Update the current key information to newly configured key information. */
  PH_CHECK_SUCCESS_FCT(wStatus, phhalHw_SamAV3_Cmd_SAM_ChangeKeyEntry(
          pDataParams->pHalDataParams,
          (uint8_t)wKeyNo,
          bProMas,
          aKeyEntryBuff,
          bKeyEntryLen));

  return PH_ADD_COMPCODE(PH_ERR_SUCCESS, PH_COMP_KEYSTORE);
}

/**
 * Change a key entry at a given version.
 *
 * First the command \ref phhalHw_SamAV3_Cmd_SAM_GetKeyEntry is executed to get the information about the current key entry. If the current
 * key type does not match with wKeyType or if the selected key version wKeyVer is not part of the current key entry the function is
 * aborted. Otherwise the key with the given version is set to pKey and its version is set to wNewKeyVer by the
 * \ref phhalHw_SamAV3_Cmd_SAM_ChangeKeyEntry. DF_Aid, DFKeyNo, RefNoKUC, SET, ExtSET, KeyNoCEK, KeyVCEK, KeyNoAEK and KeyVAEK are set
 * according to the configuration parameters. \n
 *
 * In case of a MIFARE key entry the diversification keys for key A and key B of all key versions are set according to the configuration
 * parameters. These parameters can be accessd via #PH_KEYSTORE_SAMAV3_CONFIG_KEYNO_MF_DIV_A and #PH_KEYSTORE_SAMAV3_CONFIG_KEYV_MF_DIV_A
 * resp. #PH_KEYSTORE_SAMAV3_CONFIG_KEYNO_MF_DIV_B and #PH_KEYSTORE_SAMAV3_CONFIG_KEYV_MF_DIV_B.
 *
 * \return Status code
 * \retval #PH_ERR_SUCCESS Operation successful.
 * \retval Other Depending on implementation and underlaying component.
 *
 * Input Parameters:
 *		pDataParams			: Pointer to this layer's parameter structure.
 *		wKeyNo				: Key number of the key to be loaded.
 *		wKeyVer				: Key version of the key to be loaded.
 *		wKeyType			: New key type of the KeyEntry (predefined type of KeyType).
 *		pNewKey				: The key information to be updated.
 *		wNewKeyVer			: New Key version of the key to be updated.
 *
 * Return:
 *			PH_ERR_SUCCESS for successfull operation.
 *			Other Depending on implementation and underlaying component.
 */
phStatus_t
phKeyStore_SamAV3_SetKey(phKeyStore_SamAV3_DataParams_t *pDataParams, uint16_t wKeyNo,
    uint16_t wKeyVer, uint16_t wKeyType,
    uint8_t *pNewKey, uint16_t wNewKeyVer)
{
  phStatus_t						PH_MEMLOC_REM wStatus = 0;
  uint16_t						PH_MEMLOC_REM wCurKeyType = 0;
  uint8_t							PH_MEMLOC_REM bProMas = 0x01;
  uint8_t							PH_MEMLOC_REM aKeyBuff[48 /* Max size to allocate 3 AES128 keys. */];
  uint8_t							PH_MEMLOC_REM bKeyLen = 0;
  uint8_t							PH_MEMLOC_REM bKeySize = 0;
  uint8_t							PH_MEMLOC_REM aKeyEntryBuff[PHHAL_HW_SAMAV3_KEYENTRY_SIZE];
  uint8_t							PH_MEMLOC_REM bKeyEntryLen = 0;
  uint8_t							PH_MEMLOC_REM bIsLRPKey = 0;
  uint8_t							PH_MEMLOC_REM bIsRamKey = PH_OFF;
  phKeyStore_SamAV3_KeyEntry_t	PH_MEMLOC_REM stKeyEntry;

  /* Check for Invalid Key No. */
  if (wKeyNo == PH_KEYSTORE_INVALID_ID) {
    return PH_ADD_COMPCODE(PH_ERR_INVALID_PARAMETER, PH_COMP_KEYSTORE);
  }

  /* Check if its RAM key. */
  if (wKeyNo > PH_KEYSTORE_SAMAV3_NVM_KEY_MAX) {
    bIsRamKey = PH_ON;
  }

  /* Get the current KeyEntry */
  PH_CHECK_SUCCESS_FCT(wStatus, phKeyStore_SamAV3_Int_GetKeyEntry(
          pDataParams,
          (uint8_t) wKeyNo,
          bIsRamKey,
          &stKeyEntry));

  /* Get the KeyType of the KeyEntry. */
  PH_CHECK_SUCCESS_FCT(wStatus, phKeyStore_SamAV3_Int_GetKeyType(
          &stKeyEntry,
          &wCurKeyType,
          &bIsLRPKey));

  /* The Key Type to be loaded must match with the current keytype format */
  if (wCurKeyType != wKeyType) {
    return PH_ADD_COMPCODE(PH_ERR_INVALID_PARAMETER, PH_COMP_KEYSTORE);
  }

  /* Get the Key Size. */
  PH_CHECK_SUCCESS_FCT(wStatus, phKeyStore_SamAV3_Int_GetKeySize(
          wKeyType,
          &bKeySize));

  /* Reset the internal Key buffer. */
  memset(aKeyBuff, 0, bKeySize);						/* PRQA S 3200 */

  /* Update the internal buffer with the Key information. */
  memcpy(aKeyBuff, pNewKey, 48);					/* PRQA S 3200 */

  /* Mifare keys need to be realigned */
  if (wKeyType == PH_KEYSTORE_KEY_TYPE_MIFARE) {
    memcpy(aKeyBuff, pNewKey, 6);					/* PRQA S 3200 */
    memcpy(&aKeyBuff[8], &pNewKey[6], 6);			/* PRQA S 3200 */

    aKeyBuff[6]  = pDataParams->bKeyNoMfDivA;
    aKeyBuff[7]  = pDataParams->bKeyVMfDivA;
    aKeyBuff[14] = pDataParams->bKeyNoMfDivB;
    aKeyBuff[15] = pDataParams->bKeyVMfDivB;
  }

  /* Check key entry version and change corresponding Key and version*/
  if (!bIsRamKey) {
    if (stKeyEntry.bVersionKeyA == (uint8_t) wKeyVer) {
      memcpy(stKeyEntry.aKeyData, aKeyBuff, bKeySize);
      bKeyLen += bKeySize;

      stKeyEntry.bVersionKeyA = (uint8_t) wNewKeyVer;
      bProMas |= 0x80U;
    } else if ((stKeyEntry.bVersionKeyB == (uint8_t) wKeyVer) &&
        (stKeyEntry.bVersionKeyBValid == PH_ON)) {
      memcpy(stKeyEntry.aKeyData, aKeyBuff, bKeySize);
      bKeyLen += bKeySize;

      stKeyEntry.bVersionKeyB = (uint8_t) wNewKeyVer;
      bProMas |= 0x40U;
    } else if ((stKeyEntry.bVersionKeyC == (uint8_t) wKeyVer) &&
        (stKeyEntry.bVersionKeyCValid == PH_ON)) {
      memcpy(stKeyEntry.aKeyData, aKeyBuff, bKeySize);
      bKeyLen += bKeySize;

      stKeyEntry.bVersionKeyC = (uint8_t) wNewKeyVer;
      bProMas |= 0x20U;
    } else {
      return PH_ADD_COMPCODE(PH_ERR_INVALID_PARAMETER, PH_COMP_KEYSTORE);
    }

    /* Update DFAid and DFKeyNo in KeyEntry. */
    bProMas |= 0x10U;
    memcpy(stKeyEntry.aDFAid, pDataParams->aDFAid, 3); /* PRQA S 3200 */
    stKeyEntry.bDFKeyNo   = pDataParams->bDFKeyNo;
  }

  /* Update KeyNo / Ver CEK in KeyEntry. */
  bProMas |= 0x08U;
  stKeyEntry.bKeyNoCEK  = pDataParams->bKeyNoCEK;
  stKeyEntry.bKeyVCEK   = pDataParams->bKeyVCEK;

  /* Update KUC reference number in KeyEntry. */
  bProMas |= 0x04U;
  stKeyEntry.bRefNoKUC  = pDataParams->bRefNoKUC;

  /* Update SET configuration in KeyEntry. */
  bProMas |= 0x02U;
  stKeyEntry.aSet[0]   &= PH_KEYSTORE_SAMAV3_KEYTYPE_MASK;
  stKeyEntry.aSet[0]   |= pDataParams->aSet[0];
  stKeyEntry.aSet[1]    = pDataParams->aSet[1];
  stKeyEntry.aExtSet[0] = pDataParams->aExtSet[0];
  stKeyEntry.aExtSet[1] = pDataParams->aExtSet[1];

  /* Convert the KeyEntry information to bytes. */
  PH_CHECK_SUCCESS_FCT(wStatus, phKeyStore_SamAV3_Int_ConvertKeyEntryToBuffer(
          pDataParams,
          &stKeyEntry,
          stKeyEntry.aKeyData,
          bKeyLen,
          aKeyEntryBuff,
          &bKeyEntryLen));

  /* Update the ProMask for Ram Key. */
  if (bIsRamKey) {
    bProMas = 0x8F;
  }

  /* Update the current key information to newly configured key information. */
  PH_CHECK_SUCCESS_FCT(wStatus, phhalHw_SamAV3_Cmd_SAM_ChangeKeyEntry(
          pDataParams->pHalDataParams,
          (uint8_t)wKeyNo,
          bProMas,
          aKeyEntryBuff,
          bKeyEntryLen));

  return PH_ADD_COMPCODE(PH_ERR_SUCCESS, PH_COMP_KEYSTORE);
}

/**
 * Get a key.
 *
 * The function returns a key selected by its key version:
 * \li The command is not supported in AV1
 * \li To retrieve a key in AV3 a \ref phhalHw_SamAV3_Cmd_SAM_DumpSecretKey is executed. Therefore the flag
 * 'allow dump secret key' in ExtSet of the key entry has to be enabled. If a DES key is dumped, the key version
 * is encoded into every least significant bit of the first 8 key bytes.
 *
 * Input Parameters:
 *		pDataParams			: Pointer to this layer's parameter structure.
 *		wKeyNo				: Key number of the key to be retrieved.
 *		wKeyVer				: Key version of the key to be retrieved.
 *		bKeyBufSize			: Size of the key.
 *
 * Output Parameters:
 *		pKey				: Size of the key buffer.
 *		pKeyType			: Type of the key.
 *
 * Return:
 *			PH_ERR_SUCCESS for successfull operation.
 *			Other Depending on implementation and underlaying component.
 */
phStatus_t
phKeyStore_SamAV3_GetKey(phKeyStore_SamAV3_DataParams_t *pDataParams, uint16_t wKeyNo,
    uint16_t wKeyVer, uint8_t bKeyBufSize,
    uint8_t *pKey, uint16_t *pKeyType)
{
  phStatus_t						PH_MEMLOC_REM wStatus = 0;
  uint8_t							PH_MEMLOC_REM bKeyLen = 0;
  uint8_t							PH_MEMLOC_REM bIsLRPKey = 0;
  uint8_t							PH_MEMLOC_REM bIsRamKey = PH_OFF;
  phKeyStore_SamAV3_KeyEntry_t	PH_MEMLOC_REM stKeyEntry;

  /* Check for Invalid Key No. */
  if (wKeyNo == PH_KEYSTORE_INVALID_ID) {
    return PH_ADD_COMPCODE(PH_ERR_INVALID_PARAMETER, PH_COMP_KEYSTORE);
  }

  /* Check if its RAM key. */
  if (wKeyNo > PH_KEYSTORE_SAMAV3_NVM_KEY_MAX) {
    bIsRamKey = PH_ON;
  }

  /* Get the current KeyEntry. */
  PH_CHECK_SUCCESS_FCT(wStatus, phKeyStore_SamAV3_Int_GetKeyEntry(
          pDataParams,
          (uint8_t) wKeyNo,
          bIsRamKey,
          &stKeyEntry));

  /* Get the KeyType of the KeyEntry. */
  PH_CHECK_SUCCESS_FCT(wStatus, phKeyStore_SamAV3_Int_GetKeyType(
          &stKeyEntry,
          pKeyType,
          &bIsLRPKey));

  /* Validate information for KeyType as Mifare .*/
  if (*pKeyType == PH_KEYSTORE_KEY_TYPE_MIFARE) {
    /* The Allow Dump MIFARE key flag has to be set. */
    if (!(stKeyEntry.aSet[0] & PH_KEYSTORE_SAMAV3_SET0_ALLOW_DUMP_SESSION_KEY)) {
      return PH_ADD_COMPCODE(PH_ERR_UNSUPPORTED_COMMAND, PH_COMP_KEYSTORE);
    }

    /* Get the Key Entry information from SAM. */
    PH_CHECK_SUCCESS_FCT(wStatus, phhalHw_SamAV3_Cmd_SAM_DumpSessionKey(
            pDataParams->pHalDataParams,
            0x00, /* Plain Dump. */
            pKey,
            &bKeyLen));
  } else {
    /* Check if Secret Key Dump is allowed. */
    if (!(stKeyEntry.aExtSet[0] & PH_KEYSTORE_SAMAV3_EXTSET0_ALLOW_DUMP_SECRET_KEY)) {
      return PH_ADD_COMPCODE(PH_ERR_UNSUPPORTED_COMMAND, PH_COMP_KEYSTORE);
    }

    /* Get the Key Entry information from SAM. */
    PH_CHECK_SUCCESS_FCT(wStatus, phhalHw_SamAV3_Cmd_SAM_DumpSecretKey(
            pDataParams->pHalDataParams,
            0,
            (uint8_t) wKeyNo,
            (uint8_t) wKeyVer,
            NULL,
            0,
            pKey,
            &bKeyLen));
  }

  /* Check if size is equal to the required length. */
  if (bKeyBufSize < bKeyLen) {
    return PH_ADD_COMPCODE(PH_ERR_PARAMETER_OVERFLOW, PH_COMP_KEYSTORE);
  }

  return PH_ADD_COMPCODE(PH_ERR_SUCCESS, PH_COMP_KEYSTORE);
}

/**
 * Change a key entry at the specified position.
 *
 * First the command \ref phhalHw_SamAV3_Cmd_SAM_GetKeyEntry is executed to get the information about the current key entry. If the current
 * key type does not match with wKeyType or if the selected key position is wrong the function is aborted. Otherwise the key at position
 * wPos (00h to 02h) is set to pKey and its version is set to wKeyVer by the \ref phhalHw_SamAV3_Cmd_SAM_ChangeKeyEntry. DF_Aid, DFKeyNo,
 * RefNoKUC, SET, ExtSET, KeyNoCEK, KeyVCEK, KeyNoAEK and KeyVAEK are set according to the configuration parameters. \n
 *
 * In case of a MIFARE key entry the diversification keys for key A and key B of all key versions are set according to the configuration
 * parameters. These parameters can be accessd via #PH_KEYSTORE_SAMAV3_CONFIG_KEYNO_MF_DIV_A and #PH_KEYSTORE_SAMAV3_CONFIG_KEYV_MF_DIV_A
 * resp. #PH_KEYSTORE_SAMAV3_CONFIG_KEYNO_MF_DIV_B and #PH_KEYSTORE_SAMAV3_CONFIG_KEYV_MF_DIV_B.
 *
 * Input Parameters:
 *		pDataParams			: Pointer to this layer's parameter structure.
 *		wKeyNo				: Key number of the key to be loaded.
 *		wPos				: Key position to be updated.
 *		wKeyType			: New key type of the KeyEntry (predefined type of KeyType).
 *		pKey				: The key information to be loaded.
 *		wKeyVer				: Key version of the key to be updated.
 *
 * Return:
 *			PH_ERR_SUCCESS for successfull operation.
 *			Other Depending on implementation and underlaying component.
 */
phStatus_t
phKeyStore_SamAV3_SetKeyAtPos(phKeyStore_SamAV3_DataParams_t *pDataParams, uint16_t wKeyNo,
    uint16_t wPos, uint16_t wKeyType,
    uint8_t *pKey, uint16_t wKeyVer)
{
  phStatus_t						PH_MEMLOC_REM wStatus = 0;
  uint16_t						PH_MEMLOC_REM wCurKeyType = 0;
  uint8_t							PH_MEMLOC_REM bProMas = 0x01;
  uint8_t							PH_MEMLOC_REM aKeyBuff[48 /* Max size to allocate 3 AES128 keys. */];
  uint8_t							PH_MEMLOC_REM bKeyLen = 0;
  uint8_t							PH_MEMLOC_REM bKeySize = 0;
  uint8_t							PH_MEMLOC_REM aKeyEntryBuff[PHHAL_HW_SAMAV3_KEYENTRY_SIZE];
  uint8_t							PH_MEMLOC_REM bKeyEntryLen = 0;
  uint8_t							PH_MEMLOC_REM bIsLRPKey = 0;
  uint8_t							PH_MEMLOC_REM bIsRamKey = PH_OFF;
  phKeyStore_SamAV3_KeyEntry_t	PH_MEMLOC_REM stKeyEntry;

  /* Check for Invalid Key No. */
  if (wKeyNo == PH_KEYSTORE_INVALID_ID) {
    return PH_ADD_COMPCODE(PH_ERR_INVALID_PARAMETER, PH_COMP_KEYSTORE);
  }

  /* Check if its RAM key. */
  if (wKeyNo > PH_KEYSTORE_SAMAV3_NVM_KEY_MAX) {
    bIsRamKey = PH_ON;
  }

  /* Get the current KeyEntry */
  PH_CHECK_SUCCESS_FCT(wStatus, phKeyStore_SamAV3_Int_GetKeyEntry(
          pDataParams,
          (uint8_t) wKeyNo,
          bIsRamKey,
          &stKeyEntry));

  /* Get the KeyType of the KeyEntry. */
  PH_CHECK_SUCCESS_FCT(wStatus, phKeyStore_SamAV3_Int_GetKeyType(
          &stKeyEntry,
          &wCurKeyType,
          &bIsLRPKey));

  /* The Key Type to be loaded must match with the current keytype format */
  if (wKeyType == PH_KEYSTORE_KEY_TYPE_DES) {
    if ((wCurKeyType - 1) != wKeyType) {
      return PH_ADD_COMPCODE(PH_ERR_INVALID_PARAMETER, PH_COMP_KEYSTORE);
    }
  }
  /* Reset of th eKeyTypes */
  else {
    if (wCurKeyType != wKeyType) {
      return PH_ADD_COMPCODE(PH_ERR_INVALID_PARAMETER, PH_COMP_KEYSTORE);
    }
  }

  /* Get the Key Size. */
  PH_CHECK_SUCCESS_FCT(wStatus, phKeyStore_SamAV3_Int_GetKeySize(
          wKeyType,
          &bKeySize));

  /* Reset the internal Key buffer. */
  memset(aKeyBuff, 0, 48);						/* PRQA S 3200 */

  /* Update the internal buffer with the Key information. */
  memcpy(aKeyBuff, pKey, bKeySize);				/* PRQA S 3200 */

  /* Mifare keys need to be realigned */
  if (wKeyType == PH_KEYSTORE_KEY_TYPE_MIFARE) {
    memcpy(aKeyBuff, pKey, 6);					/* PRQA S 3200 */
    memcpy(&aKeyBuff[8], &pKey[6], 6);			/* PRQA S 3200 */

    aKeyBuff[6]  = pDataParams->bKeyNoMfDivA;
    aKeyBuff[7]  = pDataParams->bKeyVMfDivA;
    aKeyBuff[14] = pDataParams->bKeyNoMfDivB;
    aKeyBuff[15] = pDataParams->bKeyVMfDivB;
  }

  /* Check if keys should be updated */
  switch (wPos) {
    case PH_KEYSTORE_SAMAV3_VERSION_POSITION_A:
      memcpy(&stKeyEntry.aKeyData[0], aKeyBuff, bKeySize);
      bKeyLen = bKeySize;

      stKeyEntry.bVersionKeyA = (uint8_t) wKeyVer;
      bProMas |= 0x80U;
      break;

    case PH_KEYSTORE_SAMAV3_VERSION_POSITION_B:
      memcpy(&stKeyEntry.aKeyData[bKeySize], aKeyBuff, bKeySize);
      bKeyLen = (uint8_t)(bKeySize * 2);

      stKeyEntry.bVersionKeyB = (uint8_t) wKeyVer;
      bProMas |= 0x40U;
      break;

    case PH_KEYSTORE_SAMAV3_VERSION_POSITION_C:
      memcpy(&stKeyEntry.aKeyData[bKeySize * 2], aKeyBuff, bKeySize);
      bKeyLen = (uint8_t)(bKeySize * 3);

      stKeyEntry.bVersionKeyC = (uint8_t) wKeyVer;
      bProMas |= 0x20U;
      break;

    default:
      return PH_ADD_COMPCODE(PH_ERR_INVALID_PARAMETER, PH_COMP_KEYSTORE);
  }

  /* Update DFAid and DFKeyNo in KeyEntry. */
  if (!bIsRamKey) {
    bProMas |= 0x10U;
    memcpy(stKeyEntry.aDFAid, pDataParams->aDFAid, 3); /* PRQA S 3200 */
    stKeyEntry.bDFKeyNo   = pDataParams->bDFKeyNo;
  }

  /* Update KeyNo / Ver CEK in KeyEntry. */
  bProMas |= 0x08U;
  stKeyEntry.bKeyNoCEK  = pDataParams->bKeyNoCEK;
  stKeyEntry.bKeyVCEK   = pDataParams->bKeyVCEK;

  /* Update KUC reference number in KeyEntry. */
  bProMas |= 0x04U;
  stKeyEntry.bRefNoKUC  = pDataParams->bRefNoKUC;

  /* Update SET configuration in KeyEntry. */
  bProMas |= 0x02U;
  stKeyEntry.aSet[0]   &= PH_KEYSTORE_SAMAV3_KEYTYPE_MASK;
  stKeyEntry.aSet[0]   |= pDataParams->aSet[0];
  stKeyEntry.aSet[1]    = pDataParams->aSet[1];
  stKeyEntry.aExtSet[0] = pDataParams->aExtSet[0];
  stKeyEntry.aExtSet[1] = pDataParams->aExtSet[1];

  /* Convert the KeyEntry information to bytes. */
  PH_CHECK_SUCCESS_FCT(wStatus, phKeyStore_SamAV3_Int_ConvertKeyEntryToBuffer(
          pDataParams,
          &stKeyEntry,
          stKeyEntry.aKeyData,
          bKeyLen,
          aKeyEntryBuff,
          &bKeyEntryLen));

  /* Update the current key information to newly configured key information. */
  PH_CHECK_SUCCESS_FCT(wStatus, phhalHw_SamAV3_Cmd_SAM_ChangeKeyEntry(
          pDataParams->pHalDataParams,
          (uint8_t)wKeyNo,
          bProMas,
          aKeyEntryBuff,
          bKeyEntryLen));

  return PH_ADD_COMPCODE(PH_ERR_SUCCESS, PH_COMP_KEYSTORE);
}

/**
 * Change the KUC of a key entry.
 *
 * First the command \ref phhalHw_SamAV3_Cmd_SAM_GetKeyEntry is executed to get the change key of the current key entry.
 * Afterwards the reference number of the KUC is set to wRefNoKUC via the \ref phhalHw_SamAV3_Cmd_SAM_ChangeKeyEntry command.
 *
 * Input Parameters:
 *		pDataParams			: Pointer to this layer's parameter structure.
 *		wKeyNo				: Key number of the key to be loaded.
 *		wRefNoKUC			: Reference Number of the key usage counter used together with that key.
 *
 * Return:
 *			PH_ERR_SUCCESS for successfull operation.
 *			Other Depending on implementation and underlaying component.
 */
phStatus_t
phKeyStore_SamAV3_SetKUC(phKeyStore_SamAV3_DataParams_t *pDataParams, uint16_t wKeyNo,
    uint16_t wRefNoKUC)
{
  phStatus_t						PH_MEMLOC_REM wStatus = 0;
//	uint8_t							PH_MEMLOC_REM bCurKeyNoCEK = 0; //Set but not used
  uint8_t							PH_MEMLOC_REM bProMas = 0;
  uint8_t							PH_MEMLOC_REM bKeyLen = 0;
  uint8_t							PH_MEMLOC_REM aKeyEntryBuff[PHHAL_HW_SAMAV3_KEYENTRY_SIZE];
  uint8_t							PH_MEMLOC_REM bKeyEntryLen = 0;
  phKeyStore_SamAV3_KeyEntry_t	PH_MEMLOC_REM stKeyEntry;

  /* Check for Invalid Key No. */
  if (wKeyNo == PH_KEYSTORE_INVALID_ID) {
    return PH_ADD_COMPCODE(PH_ERR_INVALID_PARAMETER, PH_COMP_KEYSTORE);
  }

  /* Get the current KeyEntry */
  PH_CHECK_SUCCESS_FCT(wStatus, phKeyStore_SamAV3_Int_GetKeyEntry(
          pDataParams,
          (uint8_t) wKeyNo,
          PH_OFF,
          &stKeyEntry));

  /* Save the current KeyNoCEK. */
//	bCurKeyNoCEK = stKeyEntry.bKeyNoCEK; //Set but not used

  /* Update the KUC number. */
  stKeyEntry.bRefNoKUC = (uint8_t) wRefNoKUC;

  /* Update the programming mask information. */
  bProMas = 0x05;

  /* Convert the KeyEntry information to bytes. */
  PH_CHECK_SUCCESS_FCT(wStatus, phKeyStore_SamAV3_Int_ConvertKeyEntryToBuffer(
          pDataParams,
          &stKeyEntry,
          stKeyEntry.aKeyData,
          bKeyLen,
          aKeyEntryBuff,
          &bKeyEntryLen));

  /* Update the current reference KUC information to newly configured KUC information. */
  PH_CHECK_SUCCESS_FCT(wStatus, phhalHw_SamAV3_Cmd_SAM_ChangeKeyEntry(
          pDataParams->pHalDataParams,
          (uint8_t)wKeyNo,
          bProMas,
          aKeyEntryBuff,
          bKeyEntryLen));

  return PH_ADD_COMPCODE(PH_ERR_SUCCESS, PH_COMP_KEYSTORE);
}

/**
 * Change a key usage counter entry.
 *
 * The function changes the KUC by using the \ref phhalHw_SamAV3_Cmd_SAM_ChangeKUCEntry command.
 * KeyNoCKUC and KeyVCKUC are set to according to the configuration parameters.
 *
 * Input Parameters:
 *		pDataParams			: Pointer to this layer's parameter structure.
 *		wRefNoKUC			: Number of the key usage counter.
 *		dwLimit				: Limit of the Key Usage Counter.
 *
 * Return:
 *			PH_ERR_SUCCESS for successfull operation.
 *			Other Depending on implementation and underlaying component.
 */
phStatus_t
phKeyStore_SamAV3_ChangeKUC(phKeyStore_SamAV3_DataParams_t *pDataParams, uint16_t wRefNoKUC,
    uint32_t dwLimit)
{
  phStatus_t	PH_MEMLOC_REM wStatus = 0;
  uint8_t		PH_MEMLOC_REM bProMas = 0x00;
  uint8_t		PH_MEMLOC_REM
  aKucData[0x06 /* KUC Limit (4 byte), KeyNoCKUC (1 byte), KeyVCKUC (1 byte) */];

  /* Reset the KucData buffer. */
  memset(aKucData, 0x00, 6);	/* PRQA S 3200 */

  bProMas |= PHHAL_HW_SAMAV3_CMD_UPDATE_LIMIT_MASK;
  aKucData[0] = (uint8_t)(dwLimit >> 0);
  aKucData[1] = (uint8_t)(dwLimit >> 8);
  aKucData[2] = (uint8_t)(dwLimit >> 16);
  aKucData[3] = (uint8_t)(dwLimit >> 24);

  if (pDataParams->bKeyNoCKUC != (PH_KEYSTORE_INVALID_ID & 0xFF)) {
    bProMas |= PHHAL_HW_SAMAV3_CMD_UPDATE_KEYNO_CKUC_MASK;
    aKucData[4] = pDataParams->bKeyNoCKUC;
  }

  if (pDataParams->bKeyVCKUC != (PH_KEYSTORE_INVALID_ID & 0xFF)) {
    bProMas |= PHHAL_HW_SAMAV3_CMD_UPDATE_KEY_VCKUC_MASK;
    aKucData[5] = pDataParams->bKeyVCKUC;
  }

  /* Update the KUCEntry information to SAM. */
  PH_CHECK_SUCCESS_FCT(wStatus, phhalHw_SamAV3_Cmd_SAM_ChangeKUCEntry(
          pDataParams->pHalDataParams,
          (uint8_t)wRefNoKUC,
          bProMas,
          aKucData,
          6));

  return PH_ADD_COMPCODE(PH_ERR_SUCCESS, PH_COMP_KEYSTORE);
}

/**
 * Change a key usage counter entry.
 *
 * The function changes the KUC by using the \ref phhalHw_SamAV3_Cmd_SAM_ChangeKUCEntry command.
 * KeyNoCKUC and KeyVCKUC are set to according to the configuration parameters.
 *
 * Input Parameters:
 *		pDataParams			: Pointer to this layer's parameter structure.
 *		wRefNoKUC			: Number of the key usage counter to be looked at (00h to 0Fh)
 *
 * Input Parameters:
 *		pdwLimit			: Currently set Limit in the KUC.
 *		pdwCurVal			: Currently value in the KUC.
 *
 * Return:
 *			PH_ERR_SUCCESS for successfull operation.
 *			Other Depending on implementation and underlaying component.
 */
phStatus_t
phKeyStore_SamAV3_GetKUC(phKeyStore_SamAV3_DataParams_t *pDataParams, uint16_t wRefNoKUC,
    uint32_t *pdwLimit,
    uint32_t *pdwCurVal)
{
  phStatus_t	PH_MEMLOC_REM wStatus = 0;
  uint8_t		PH_MEMLOC_REM aKucData[10];

  /* Reset the KucData buffer. */
  memset(aKucData, 0x00, 6);	/* PRQA S 3200 */

  /* Get the KUCEntry information from Sam. */
  PH_CHECK_SUCCESS_FCT(wStatus, phhalHw_SamAV3_Cmd_SAM_GetKUCEntry(
          pDataParams->pHalDataParams,
          (uint8_t) wRefNoKUC,
          aKucData));

  /* Update the Limit parameter. */
  *pdwLimit  = (uint32_t)((uint32_t)(aKucData[3]) << 24);
  *pdwLimit |= (uint32_t)((uint32_t)(aKucData[2]) << 16);
  *pdwLimit |= (uint32_t)((uint32_t)(aKucData[1]) << 8);
  *pdwLimit |= (uint32_t)((uint32_t)(aKucData[0]) << 0);

  /* Update the KeyNo and Version to dataparams. */
  pDataParams->bKeyNoCKUC = aKucData[4];
  pDataParams->bKeyVCKUC = aKucData[5];

  /* Update the Current value of Key Usage Counter parameter. */
  *pdwCurVal  = (uint32_t)((uint32_t)(aKucData[9]) << 24);
  *pdwCurVal |= (uint32_t)((uint32_t)(aKucData[8]) << 16);
  *pdwCurVal |= (uint32_t)((uint32_t)(aKucData[7]) << 8);
  *pdwCurVal |= (uint32_t)((uint32_t)(aKucData[6]) << 0);

  return PH_ADD_COMPCODE(PH_ERR_SUCCESS, PH_COMP_KEYSTORE);
}

/**
 * Get a key entry information block.
 *
 * The function returns the key type and all key versions of a key entry. This information
 * is retrieved by the \ref phhalHw_SamAV3_Cmd_SAM_GetKeyEntry command. All additional information
 * which is returned by the \ref phhalHw_SamAV3_Cmd_SAM_GetKeyEntry command is stored in
 * the configuration parameters of this layer. To access these values the function \ref phKeyStore_SamAV3_GetConfig
 * has to be used.
 *
 * Input Parameters:
 *		pDataParams			: Pointer to this layer's parameter structure.
 *		wKeyNo				: Key number of the key entry of interest.
 *
 * Output Parameters:
 *		pKeyVer				: Array for version information.
 *		pKeyVerLen			: Length of valid data in wKeyVer.
 *		pKeyType			: Type of the key.
 *
 * Return:
 *			PH_ERR_SUCCESS for successfull operation.
 *			Other Depending on implementation and underlaying component.
 */
phStatus_t
phKeyStore_SamAV3_GetKeyEntry(phKeyStore_SamAV3_DataParams_t *pDataParams, uint16_t wKeyNo,
    uint16_t *pKeyVer,
    uint16_t *pKeyVerLen, uint16_t *pKeyType)
{
  phStatus_t						PH_MEMLOC_REM wStatus = 0;
  uint8_t							PH_MEMLOC_REM bIsLRPKey = 0;
  uint8_t							PH_MEMLOC_REM bIsRamKey = PH_OFF;
  phKeyStore_SamAV3_KeyEntry_t	PH_MEMLOC_REM stKeyEntry;

  /* Check for Invalid Key No. */
  if (wKeyNo == PH_KEYSTORE_INVALID_ID) {
    return PH_ADD_COMPCODE(PH_ERR_INVALID_PARAMETER, PH_COMP_KEYSTORE);
  }

  /* Check if its RAM key. */
  if (wKeyNo > PH_KEYSTORE_SAMAV3_NVM_KEY_MAX) {
    bIsRamKey = PH_ON;
  }

  /* Update the parameter. */
  *pKeyVerLen = 0x00;

  /* First try to find the correct key position. */
  PH_CHECK_SUCCESS_FCT(wStatus, phKeyStore_SamAV3_Int_GetKeyEntry(
          pDataParams,
          (uint8_t)wKeyNo,
          bIsRamKey,
          &stKeyEntry));

  /* Update the version information. */
  pKeyVer[0] = stKeyEntry.bVersionKeyA;
  pKeyVer[1] = stKeyEntry.bVersionKeyB;
  pKeyVer[2] = stKeyEntry.bVersionKeyC;

  /* Update the version length. */
  *pKeyVerLen = (uint8_t)((stKeyEntry.bVersionKeyCValid) ? 3 : 2);

  /* Get the key type. */
  PH_CHECK_SUCCESS_FCT(wStatus, phKeyStore_SamAV3_Int_GetKeyType(
          &stKeyEntry,
          pKeyType,
          &bIsLRPKey));

  /* Set the DESFire additional option settings. */
  switch (((stKeyEntry.aSet[0] & PH_KEYSTORE_SAMAV3_KEYTYPE_MASK) >> 3)) {
    case PH_KEYSTORE_SAMAV3_KEYTYPE_2K3DES_MASK:
      pDataParams->b2K3DESOption = PH_KEYSTORE_SAMAV3_DES_OPTION_ISO_CRC16;
      break;

    case PH_KEYSTORE_SAMAV3_KEYTYPE_3DESDF4_MASK:
      pDataParams->b2K3DESOption = PH_KEYSTORE_SAMAV3_DES_OPTION_DESFIRE4;
      break;

    case PH_KEYSTORE_SAMAV3_KEYTYPE_2K3DESDF8_MASK:
      pDataParams->b2K3DESOption = PH_KEYSTORE_SAMAV3_DES_OPTION_ISO_CRC32;
      break;
  }

  /* Set the LRP flag. */
  if (bIsLRPKey) {
    pDataParams->bIsLRPKey = bIsLRPKey;
  }

  /* Update SET and ExtSET configuration. */
  pDataParams->aSet[0] = (uint8_t)(stKeyEntry.aSet[0] & ~PH_KEYSTORE_SAMAV3_KEYTYPE_MASK);
  pDataParams->aSet[1] = stKeyEntry.aSet[1];
  pDataParams->aExtSet[0] = stKeyEntry.aExtSet[0];
  pDataParams->aExtSet[1] = stKeyEntry.aExtSet[1];

  /* Update KeyNo and Version of Change Entry Key. */
  pDataParams->bKeyNoCEK = stKeyEntry.bKeyNoCEK;
  pDataParams->bKeyVCEK  = stKeyEntry.bKeyVCEK;

  /* Update DF_AID and KeyNo. */
  if (!bIsRamKey) {
    memcpy(pDataParams->aDFAid, stKeyEntry.aDFAid, 3); /* PRQA S 3200 */
    pDataParams->bDFKeyNo = stKeyEntry.bDFKeyNo;
  }

  /* Update KUC Reference number. */
  pDataParams->bRefNoKUC = stKeyEntry.bRefNoKUC;

  /* Update KeyNo and Version of Access KeyEntry. */
  pDataParams->bKeyNoAEK = stKeyEntry.bKeyNoAEK;
  pDataParams->bKeyVAEK = stKeyEntry.bKeyVAEK;

  return PH_ADD_COMPCODE(PH_ERR_SUCCESS, PH_COMP_KEYSTORE);
}

/**
 * Set configuration parameter.
 *
 * Input Parameters:
 *		pDataParams			: Pointer to this layer's parameter structure.
 *		wConfig				: Configuration Identifier.
 *		pValue				: Configuration Value.
 *
 * Return:
 *			PH_ERR_SUCCESS for successfull operation.
 *			Other Depending on implementation and underlaying component.
 */
phStatus_t
phKeyStore_SamAV3_SetConfig(phKeyStore_SamAV3_DataParams_t *pDataParams, uint16_t wConfig,
    uint16_t wValue)
{
  switch (wConfig) {
    case PH_KEYSTORE_SAMAV3_CONFIG_ALLOW_DUMP_SESSION_KEY:
      if (wValue) {
        pDataParams->aSet[0] |= PH_KEYSTORE_SAMAV3_SET0_ALLOW_DUMP_SESSION_KEY;
      } else {
        pDataParams->aSet[0] = (uint8_t)(pDataParams->aSet[0] &
                (~PH_KEYSTORE_SAMAV3_SET0_ALLOW_DUMP_SESSION_KEY));
      }
      break;

    case PH_KEYSTORE_SAMAV3_CONFIG_KEEP_IV:
      if (wValue) {
        pDataParams->aSet[0] |= PH_KEYSTORE_SAMAV3_SET0_KEEP_IV;
      } else {
        pDataParams->aSet[0] = (uint8_t)(pDataParams->aSet[0] & (~PH_KEYSTORE_SAMAV3_SET0_KEEP_IV));
      }
      break;

    case PH_KEYSTORE_SAMAV3_CONFIG_PL_KEY:
      if (wValue) {
        pDataParams->aSet[0] |= PH_KEYSTORE_SAMAV3_SET0_PL_KEY;
      } else {
        pDataParams->aSet[0] = (uint8_t)(pDataParams->aSet[0] & (~PH_KEYSTORE_SAMAV3_SET0_PL_KEY));
      }
      break;

    case PH_KEYSTORE_SAMAV3_CONFIG_AUTH_KEY:
      if (wValue) {
        pDataParams->aSet[1] |= PH_KEYSTORE_SAMAV3_SET1_AUTH_KEY;
      } else {
        pDataParams->aSet[1] = (uint8_t)(pDataParams->aSet[1] & (~PH_KEYSTORE_SAMAV3_SET1_AUTH_KEY));
      }
      break;

    case PH_KEYSTORE_SAMAV3_CONFIG_DISABLE_KEY_ENTRY:
      if (wValue) {
        pDataParams->aSet[1] |= PH_KEYSTORE_SAMAV3_SET1_DISABLE_KEY_ENTRY;
      } else {
        pDataParams->aSet[1] = (uint8_t)(pDataParams->aSet[1] &
                (~PH_KEYSTORE_SAMAV3_SET1_DISABLE_KEY_ENTRY));
      }
      break;

    case PH_KEYSTORE_SAMAV3_CONFIG_LOCK_KEY:
      if (wValue) {
        pDataParams->aSet[1] |= PH_KEYSTORE_SAMAV3_SET1_LOCK_KEY;
      } else {
        pDataParams->aSet[1] = (uint8_t)(pDataParams->aSet[1] & (~PH_KEYSTORE_SAMAV3_SET1_LOCK_KEY));
      }
      break;

    case PH_KEYSTORE_SAMAV3_CONFIG_DISABLE_CHANGE_KEY_PICC:
      if (wValue) {
        pDataParams->aSet[1] |= PH_KEYSTORE_SAMAV3_SET1_DISABLE_CHANGE_KEY_PICC;
      } else {
        pDataParams->aSet[1] = (uint8_t)(pDataParams->aSet[1] &
                (~PH_KEYSTORE_SAMAV3_SET1_DISABLE_CHANGE_KEY_PICC));
      }
      break;

    case PH_KEYSTORE_SAMAV3_CONFIG_DISABLE_DECRYPTION:
      if (wValue) {
        pDataParams->aSet[1] |= PH_KEYSTORE_SAMAV3_SET1_DISABLE_DECRYPTION;
      } else {
        pDataParams->aSet[1] = (uint8_t)(pDataParams->aSet[1] &
                (~PH_KEYSTORE_SAMAV3_SET1_DISABLE_DECRYPTION));
      }
      break;

    case PH_KEYSTORE_SAMAV3_CONFIG_DISABLE_ENCRYPTION:
      if (wValue) {
        pDataParams->aSet[1] |= PH_KEYSTORE_SAMAV3_SET1_DISABLE_ENCRYPTION;
      } else {
        pDataParams->aSet[1] = (uint8_t)(pDataParams->aSet[1] &
                (~PH_KEYSTORE_SAMAV3_SET1_DISABLE_ENCRYPTION));
      }
      break;

    case PH_KEYSTORE_SAMAV3_CONFIG_DISABLE_VERIFY_MAC:
      if (wValue) {
        pDataParams->aSet[1] |= PH_KEYSTORE_SAMAV3_SET1_DISABLE_VERIFY_MAC;
      } else {
        pDataParams->aSet[1] = (uint8_t)(pDataParams->aSet[1] &
                (~PH_KEYSTORE_SAMAV3_SET1_DISABLE_VERIFY_MAC));
      }
      break;

    case PH_KEYSTORE_SAMAV3_CONFIG_DISABLE_GENERATE_MAC:
      if (wValue) {
        pDataParams->aSet[1] |= PH_KEYSTORE_SAMAV3_SET1_DISABLE_GENERATE_MAC;
      } else {
        pDataParams->aSet[1] = (uint8_t)(pDataParams->aSet[1] &
                (~PH_KEYSTORE_SAMAV3_SET1_DISABLE_GENERATE_MAC));
      }
      break;

    case PH_KEYSTORE_SAMAV3_CONFIG_KEYCLASS:
      pDataParams->aExtSet[0] = (uint8_t)(pDataParams->aExtSet[0] &
              (~PH_KEYSTORE_SAMAV3_KEYCLASS_MASK));
      pDataParams->aExtSet[0] |= (uint8_t) wValue;
      break;

    case PH_KEYSTORE_SAMAV3_CONFIG_ALLOW_DUMP_SECRET_KEY:
      if (wValue) {
        pDataParams->aExtSet[0] |= PH_KEYSTORE_SAMAV3_EXTSET0_ALLOW_DUMP_SECRET_KEY;
      } else {
        pDataParams->aExtSet[0] = (uint8_t)(pDataParams->aExtSet[0] &
                (~PH_KEYSTORE_SAMAV3_EXTSET0_ALLOW_DUMP_SECRET_KEY));
      }
      break;

    case PH_KEYSTORE_SAMAV3_CONFIG_MANDATE_KEY_DIVERSIFICATION:
      if (wValue) {
        pDataParams->aExtSet[0] |= PH_KEYSTORE_SAMAV3_EXTSET0_MANDATE_KEY_DIVERSIFICATION;
      } else {
        pDataParams->aExtSet[0] = (uint8_t)(pDataParams->aExtSet[0] &
                (~PH_KEYSTORE_SAMAV3_EXTSET0_MANDATE_KEY_DIVERSIFICATION));
      }
      break;

    case PH_KEYSTORE_SAMAV3_CONFIG_RESERVED_SAM_PRESONALIZATION:
      if (wValue) {
        pDataParams->aExtSet[0] |= PH_KEYSTORE_SAMAV3_EXTSET0_PERSONALIZATION_SAM;
      } else {
        pDataParams->aExtSet[0] = (uint8_t)(pDataParams->aExtSet[0] &
                (~PH_KEYSTORE_SAMAV3_EXTSET0_PERSONALIZATION_SAM));
      }
      break;

    case PH_KEYSTORE_SAMAV3_CONFIG_KEY_USAGE_INT_HOST:
      if (wValue) {
        pDataParams->aExtSet[1] |= PH_KEYSTORE_SAMAV3_EXTSET1_KEY_USAGE_INT_HOST;
      } else {
        pDataParams->aExtSet[1] = (uint8_t)(pDataParams->aExtSet[1] &
                (~PH_KEYSTORE_SAMAV3_EXTSET1_KEY_USAGE_INT_HOST));
      }
      break;

    case PH_KEYSTORE_SAMAV3_CONFIG_KEY_CHANGE_INT_HOST:
      if (wValue) {
        pDataParams->aExtSet[1] |= PH_KEYSTORE_SAMAV3_EXTSET1_KEY_CHANGE_INT_HOST;
      } else {
        pDataParams->aExtSet[1] = (uint8_t)(pDataParams->aExtSet[1] &
                (~PH_KEYSTORE_SAMAV3_EXTSET1_KEY_CHANGE_INT_HOST));
      }
      break;

    case PH_KEYSTORE_SAMAV3_CONFIG_SESSION_KEY_USAGE_INT_HOST:
      if (wValue) {
        pDataParams->aExtSet[1] |= PH_KEYSTORE_SAMAV3_EXTSET1_SESSION_KEY_USAGE_INT_HOST;
      } else {
        pDataParams->aExtSet[1] = (uint8_t)(pDataParams->aExtSet[1] &
                (~PH_KEYSTORE_SAMAV3_EXTSET1_SESSION_KEY_USAGE_INT_HOST));
      }
      break;

    case PH_KEYSTORE_SAMAV3_CONFIG_ALLOW_DUMP_SECRET_KEY_INT_HOST:
      if (wValue) {
        pDataParams->aExtSet[1] |= PH_KEYSTORE_SAMAV3_EXTSET1_DUMP_SECRET_KEY_INT_HOST;
      } else {
        pDataParams->aExtSet[1] = (uint8_t)(pDataParams->aExtSet[1] &
                (~PH_KEYSTORE_SAMAV3_EXTSET1_DUMP_SECRET_KEY_INT_HOST));
      }
      break;

    case PH_KEYSTORE_SAMAV3_CONFIG_ALLOW_DUMP_SESSION_KEY_INT_HOST:
      if (wValue) {
        pDataParams->aExtSet[1] |= PH_KEYSTORE_SAMAV3_EXTSET1_DUMP_SESSION_KEY_INT_HOST;
      } else {
        pDataParams->aExtSet[1] = (uint8_t)(pDataParams->aExtSet[1] &
                (~PH_KEYSTORE_SAMAV3_EXTSET1_DUMP_SESSION_KEY_INT_HOST));
      }
      break;

    case PH_KEYSTORE_SAMAV3_CONFIG_DF_KEY_NO:
      pDataParams->bDFKeyNo = (uint8_t) wValue;
      break;

    case PH_KEYSTORE_SAMAV3_CONFIG_KEYNO_CEK:
      pDataParams->bKeyNoCEK = (uint8_t) wValue;
      break;

    case PH_KEYSTORE_SAMAV3_CONFIG_KEYV_CEK:
      pDataParams->bKeyVCEK = (uint8_t) wValue;
      break;

    case PH_KEYSTORE_SAMAV3_CONFIG_REF_NO_KUC:
      pDataParams->bRefNoKUC = (uint8_t)wValue;
      break;

    case PH_KEYSTORE_SAMAV3_CONFIG_KEYNO_AEK:
      pDataParams->bKeyNoAEK = (uint8_t)wValue;
      break;

    case PH_KEYSTORE_SAMAV3_CONFIG_KEYV_AEK:
      pDataParams->bKeyVAEK = (uint8_t)wValue;
      break;

    case PH_KEYSTORE_SAMAV3_CONFIG_KEYNO_CKUC:
      pDataParams->bKeyNoCKUC = (uint8_t)wValue;
      break;

    case PH_KEYSTORE_SAMAV3_CONFIG_KEYV_CKUC:
      pDataParams->bKeyVCKUC = (uint8_t)wValue;
      break;

    case PH_KEYSTORE_SAMAV3_CONFIG_DES_KEY_OPTION:
      pDataParams->b2K3DESOption = (uint8_t)wValue;
      break;

    case PH_KEYSTORE_SAMAV3_CONFIG_ENABLE_LRP:
      pDataParams->bIsLRPKey = (uint8_t)wValue;
      break;

    case PH_KEYSTORE_SAMAV3_CONFIG_KEYNO_MF_DIV_A:
      pDataParams->bKeyNoMfDivA = (uint8_t)wValue;
      break;

    case PH_KEYSTORE_SAMAV3_CONFIG_KEYV_MF_DIV_A:
      pDataParams->bKeyVMfDivA = (uint8_t)wValue;
      break;

    case PH_KEYSTORE_SAMAV3_CONFIG_KEYNO_MF_DIV_B:
      pDataParams->bKeyNoMfDivB = (uint8_t)wValue;
      break;

    case PH_KEYSTORE_SAMAV3_CONFIG_KEYV_MF_DIV_B:
      pDataParams->bKeyVMfDivB = (uint8_t)wValue;
      break;

    case PH_KEYSTORE_CONFIG_SET_DEFAULT:
      pDataParams->aSet[0] = 0x00;
      pDataParams->aSet[1] = 0x00;
      pDataParams->aExtSet[0] = 0x00;
      pDataParams->aExtSet[1] = 0x00;
      memset(pDataParams->aDFAid, 0, 3);  /* PRQA S 3200 */
      pDataParams->bDFKeyNo = 0x00;
      pDataParams->b2K3DESOption = 0x00;
      pDataParams->bKeyNoCEK = 0x00;
      pDataParams->bKeyVCEK = 0x00;
      pDataParams->bRefNoKUC = 0xFF;
      pDataParams->bKeyNoCKUC = 0x00;
      pDataParams->bKeyVCKUC = 0x00;
      pDataParams->bKeyNoAEK = 0x00;
      pDataParams->bKeyVAEK = 0x00;
      pDataParams->bKeyNoMfDivA = 0x00;
      pDataParams->bKeyVMfDivA = 0x00;
      pDataParams->bKeyNoMfDivB = 0x00;
      pDataParams->bKeyVMfDivB = 0x00;
      break;

    default:
      return PH_ADD_COMPCODE(PH_ERR_INVALID_PARAMETER, PH_COMP_KEYSTORE);
  }

  return PH_ADD_COMPCODE(PH_ERR_SUCCESS, PH_COMP_KEYSTORE);
}

/**
 * Set configuration parameter.
 *
 * Input Parameters:
 *		pDataParams			: Pointer to this layer's parameter structure.
 *		wConfig				: Configuration Identifier.
 *
 * Output Parameters:
 *		pValue				: Configuration Value.
 *
 * Return:
 *			PH_ERR_SUCCESS for successfull operation.
 *			Other Depending on implementation and underlaying component.
 */
phStatus_t
phKeyStore_SamAV3_GetConfig(phKeyStore_SamAV3_DataParams_t *pDataParams, uint16_t wConfig,
    uint16_t *pValue)
{
  switch (wConfig) {
    case PH_KEYSTORE_SAMAV3_CONFIG_ALLOW_DUMP_SESSION_KEY:
      *pValue = (uint16_t)((pDataParams->aSet[0] & PH_KEYSTORE_SAMAV3_SET0_ALLOW_DUMP_SESSION_KEY) ? 1 :
              0);
      break;

    case PH_KEYSTORE_SAMAV3_CONFIG_KEEP_IV:
      *pValue = (uint16_t)((pDataParams->aSet[0] & PH_KEYSTORE_SAMAV3_SET0_KEEP_IV) ? 1 : 0);
      break;

    case PH_KEYSTORE_SAMAV3_CONFIG_PL_KEY:
      *pValue = (uint16_t)((pDataParams->aSet[0] & PH_KEYSTORE_SAMAV3_SET0_PL_KEY) ? 1 : 0);
      break;

    case PH_KEYSTORE_SAMAV3_CONFIG_AUTH_KEY:
      *pValue = (uint16_t)((pDataParams->aSet[1] & PH_KEYSTORE_SAMAV3_SET1_AUTH_KEY) ? 1 : 0);
      break;

    case PH_KEYSTORE_SAMAV3_CONFIG_DISABLE_KEY_ENTRY:
      *pValue = (uint16_t)((pDataParams->aSet[1] & PH_KEYSTORE_SAMAV3_SET1_DISABLE_KEY_ENTRY) ? 1 : 0);
      break;

    case PH_KEYSTORE_SAMAV3_CONFIG_LOCK_KEY:
      *pValue = (uint16_t)((pDataParams->aSet[1] & PH_KEYSTORE_SAMAV3_SET1_LOCK_KEY) ? 1 : 0);
      break;

    case PH_KEYSTORE_SAMAV3_CONFIG_DISABLE_CHANGE_KEY_PICC:
      *pValue = (uint16_t)((pDataParams->aSet[1] & PH_KEYSTORE_SAMAV3_SET1_DISABLE_CHANGE_KEY_PICC) ?
              1 : 0);
      break;

    case PH_KEYSTORE_SAMAV3_CONFIG_DISABLE_DECRYPTION:
      *pValue = (uint16_t)((pDataParams->aSet[1] & PH_KEYSTORE_SAMAV3_SET1_DISABLE_DECRYPTION) ? 1 : 0);
      break;

    case PH_KEYSTORE_SAMAV3_CONFIG_DISABLE_ENCRYPTION:
      *pValue = (uint16_t)((pDataParams->aSet[1] & PH_KEYSTORE_SAMAV3_SET1_DISABLE_ENCRYPTION) ? 1 : 0);
      break;

    case PH_KEYSTORE_SAMAV3_CONFIG_DISABLE_VERIFY_MAC:
      *pValue = (uint16_t)((pDataParams->aSet[1] & PH_KEYSTORE_SAMAV3_SET1_DISABLE_VERIFY_MAC) ? 1 : 0);
      break;

    case PH_KEYSTORE_SAMAV3_CONFIG_DISABLE_GENERATE_MAC:
      *pValue = (uint16_t)((pDataParams->aSet[1] & PH_KEYSTORE_SAMAV3_SET1_DISABLE_GENERATE_MAC) ? 1 :
              0);
      break;

    case PH_KEYSTORE_SAMAV3_CONFIG_KEYCLASS:
      *pValue = (uint16_t)(pDataParams->aExtSet[0] & PH_KEYSTORE_SAMAV3_KEYCLASS_MASK);
      break;

    case PH_KEYSTORE_SAMAV3_CONFIG_ALLOW_DUMP_SECRET_KEY:
      *pValue = (uint16_t)((pDataParams->aExtSet[0] & PH_KEYSTORE_SAMAV3_EXTSET0_ALLOW_DUMP_SECRET_KEY)
              ? 1 : 0);
      break;

    case PH_KEYSTORE_SAMAV3_CONFIG_MANDATE_KEY_DIVERSIFICATION:
      *pValue = (uint16_t)((pDataParams->aExtSet[0] &
                  PH_KEYSTORE_SAMAV3_EXTSET0_MANDATE_KEY_DIVERSIFICATION) ? 1 : 0);
      break;

    case PH_KEYSTORE_SAMAV3_CONFIG_RESERVED_SAM_PRESONALIZATION:
      *pValue = (uint16_t)((pDataParams->aExtSet[0] & PH_KEYSTORE_SAMAV3_EXTSET0_PERSONALIZATION_SAM) ?
              1 : 0);
      break;

    case PH_KEYSTORE_SAMAV3_CONFIG_KEY_USAGE_INT_HOST:
      *pValue = (uint16_t)((pDataParams->aExtSet[1] & PH_KEYSTORE_SAMAV3_EXTSET1_KEY_USAGE_INT_HOST) ?
              1 : 0);
      break;

    case PH_KEYSTORE_SAMAV3_CONFIG_KEY_CHANGE_INT_HOST:
      *pValue = (uint16_t)((pDataParams->aExtSet[1] & PH_KEYSTORE_SAMAV3_EXTSET1_KEY_CHANGE_INT_HOST) ?
              1 : 0);
      break;

    case PH_KEYSTORE_SAMAV3_CONFIG_SESSION_KEY_USAGE_INT_HOST:
      *pValue = (uint16_t)((pDataParams->aExtSet[1] &
                  PH_KEYSTORE_SAMAV3_EXTSET1_SESSION_KEY_USAGE_INT_HOST) ? 1 : 0);
      break;

    case PH_KEYSTORE_SAMAV3_CONFIG_ALLOW_DUMP_SECRET_KEY_INT_HOST:
      *pValue = (uint16_t)((pDataParams->aExtSet[1] &
                  PH_KEYSTORE_SAMAV3_EXTSET1_DUMP_SECRET_KEY_INT_HOST) ? 1 : 0);
      break;

    case PH_KEYSTORE_SAMAV3_CONFIG_ALLOW_DUMP_SESSION_KEY_INT_HOST:
      *pValue = (uint16_t)((pDataParams->aExtSet[1] &
                  PH_KEYSTORE_SAMAV3_EXTSET1_DUMP_SESSION_KEY_INT_HOST) ? 1 : 0);
      break;

    case PH_KEYSTORE_SAMAV3_CONFIG_DF_KEY_NO:
      *pValue = (uint16_t) pDataParams->bDFKeyNo;
      break;

    case PH_KEYSTORE_SAMAV3_CONFIG_KEYNO_CEK:
      *pValue = (uint16_t)pDataParams->bKeyNoCEK;
      break;

    case PH_KEYSTORE_SAMAV3_CONFIG_KEYV_CEK:
      *pValue = (uint16_t)pDataParams->bKeyVCEK;
      break;

    case PH_KEYSTORE_SAMAV3_CONFIG_REF_NO_KUC:
      *pValue = (uint16_t)pDataParams->bRefNoKUC;
      break;

    case PH_KEYSTORE_SAMAV3_CONFIG_KEYNO_AEK:
      *pValue = (uint16_t)pDataParams->bKeyNoAEK;
      break;

    case PH_KEYSTORE_SAMAV3_CONFIG_KEYV_AEK:
      *pValue = (uint16_t)pDataParams->bKeyVAEK;
      break;

    case PH_KEYSTORE_SAMAV3_CONFIG_KEYNO_CKUC:
      *pValue = (uint16_t)pDataParams->bKeyNoCKUC;
      break;

    case PH_KEYSTORE_SAMAV3_CONFIG_KEYV_CKUC:
      *pValue = (uint16_t)pDataParams->bKeyVCKUC;
      break;

    case PH_KEYSTORE_SAMAV3_CONFIG_DES_KEY_OPTION:
      *pValue = (uint16_t)pDataParams->b2K3DESOption;
      break;

    case PH_KEYSTORE_SAMAV3_CONFIG_ENABLE_LRP:
      *pValue = pDataParams->bIsLRPKey;
      break;

    case PH_KEYSTORE_SAMAV3_CONFIG_KEYNO_MF_DIV_A:
      *pValue = (uint16_t)pDataParams->bKeyNoMfDivA;
      break;

    case PH_KEYSTORE_SAMAV3_CONFIG_KEYV_MF_DIV_A:
      *pValue = (uint16_t)pDataParams->bKeyVMfDivA;
      break;

    case PH_KEYSTORE_SAMAV3_CONFIG_KEYNO_MF_DIV_B:
      *pValue = (uint16_t)pDataParams->bKeyNoMfDivB;
      break;

    case PH_KEYSTORE_SAMAV3_CONFIG_KEYV_MF_DIV_B:
      *pValue = (uint16_t)pDataParams->bKeyVMfDivB;
      break;

    default:
      return PH_ADD_COMPCODE(PH_ERR_INVALID_PARAMETER, PH_COMP_KEYSTORE);
  }

  return PH_ADD_COMPCODE(PH_ERR_SUCCESS, PH_COMP_KEYSTORE);
}

/**
 * Set configuration parameter.
 *
 * Input Parameters:
 *		pDataParams			: Pointer to this layer's parameter structure.
 *		wConfig				: Configuration Identifier, mainly PH_KEYSTORE_SAMAV3_CONFIG_DF_AID.
 *		pBuffer				: Buffer containing the Defire Application Identifier.
 *		wBufferLen			: Length of data available in pBuffer.
 *
 * Return:
 *			PH_ERR_SUCCESS for successfull operation.
 *			Other Depending on implementation and underlaying component.
 */
phStatus_t
phKeyStore_SamAV3_SetConfigStr(phKeyStore_SamAV3_DataParams_t *pDataParams, uint16_t wConfig,
    uint8_t *pBuffer,
    uint16_t wBufferLen)
{
  switch (wConfig) {
    case PH_KEYSTORE_SAMAV3_CONFIG_DF_AID:
      if (wBufferLen != 3) {
        return PH_ADD_COMPCODE(PH_ERR_INVALID_PARAMETER, PH_COMP_KEYSTORE);
      }

      memcpy(pDataParams->aDFAid, pBuffer, 3);   /* PRQA S 3200 */
      break;

    default:
      return PH_ADD_COMPCODE(PH_ERR_INVALID_PARAMETER, PH_COMP_KEYSTORE);
  }

  return PH_ADD_COMPCODE(PH_ERR_SUCCESS, PH_COMP_KEYSTORE);
}

/**
 * Get configuration parameter.
 *
 * Input Parameters:
 *		pDataParams			: Pointer to this layer's parameter structure.
 *		wConfig				: Configuration Identifier, mainly PH_KEYSTORE_SAMAV3_CONFIG_DF_AID.
 *
 * Output Parameters:
 *		ppBuffer			: Buffer containing the Defire Application Identifier.
 *		pBufferLen			: Length of data available in pBuffer.
 *
 * Return:
 *			PH_ERR_SUCCESS for successfull operation.
 *			Other Depending on implementation and underlaying component.
 */
phStatus_t
phKeyStore_SamAV3_GetConfigStr(phKeyStore_SamAV3_DataParams_t *pDataParams, uint16_t wConfig,
    uint8_t **ppBuffer,
    uint16_t *pBufferLen)
{
  switch (wConfig) {
    case PH_KEYSTORE_SAMAV3_CONFIG_DF_AID:
      *ppBuffer = pDataParams->aDFAid;
      *pBufferLen = 3;
      break;

    default:
      return PH_ADD_COMPCODE(PH_ERR_INVALID_PARAMETER, PH_COMP_KEYSTORE);
  }

  return PH_ADD_COMPCODE(PH_ERR_SUCCESS, PH_COMP_KEYSTORE);
}
#endif /* NXPBUILD__PH_KEYSTORE_SAMAV3 */
