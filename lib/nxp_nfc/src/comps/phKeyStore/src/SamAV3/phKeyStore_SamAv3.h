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

#ifndef PHKEYSTORE_SAMAV3_H
#define PHKEYSTORE_SAMAV3_H

#include <nxp_nfc/ph_Status.h>
#include <nxp_nfc/phhalHw.h>
#include <nxp_nfc/phKeyStore.h>

/** \addtogroup phKeyStore_SamAV3
 * @{
 */

/**
 * \brief SamAV3 Key Entry Structure
 */
typedef struct {
  uint8_t  aKeyData[48];								/**< Concatenated KeyA, KeyB, KeyC (used only for ChangeKeyEntry, cleared by GetKeyEntry).*/
  uint8_t  aDFAid[3];									/**< DESfire AID. */
  uint8_t  bDFKeyNo;									/**< Corresponding DESFire key number (of DESFire AID). */
  uint8_t  bKeyNoCEK;									/**< Key reference number of change entry key. */
  uint8_t  bKeyVCEK;									/**< Key version of change entry key. */
  uint8_t  bRefNoKUC;									/**< Reference number of key usage counter. */
  uint8_t  bKeyNoAEK;									/**< Key reference number of Access Key Entry. */
  uint8_t  bKeyVAEK;									/**< Key reference version of Access Key Entry. */
  uint8_t  aSet[2];									/**< Configuration settings of this key entry. */
  uint8_t  bVersionKeyA;								/**< Version of Key A. */
  uint8_t  bVersionKeyB;								/**< Version of Key B. */
  uint8_t  bVersionKeyC;								/**< Version of Key C. */
  uint8_t  aExtSet[2];								/**< Extended configuration settings of this key entry. */
  uint8_t  bVersionKeyBValid;							/**< Indicates whether Key B Version is available or not. */
  uint8_t  bVersionKeyCValid;							/**< Indicates whether Key C Version is available or not. */
} phKeyStore_SamAV3_KeyEntry_t;

/**
 * \brief Format a key entry to a new KeyType.
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
 * \return Status code
 * \retval #PH_ERR_SUCCESS Operation successful.
 * \retval Other Depending on implementation and underlaying component.
 */
phStatus_t phKeyStore_SamAV3_FormatKeyEntry(
    phKeyStore_SamAV3_DataParams_t
    *pDataParams,	/**< [In] Pointer to this layers parameter structure. */
    uint16_t wKeyNo,								/**< [In] KeyEntry number to be formatted. */
    uint16_t wKeyType								/**< [In] New key type of the KeyEntry (predefined type of KeyType). */
);

/**
 * \brief Change a key entry at a given version.
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
 */
phStatus_t phKeyStore_SamAV3_SetKey(
    phKeyStore_SamAV3_DataParams_t
    *pDataParams,	/**< [In] Pointer to this layers parameter structure. */
    uint16_t wKeyNo,								/**< [In] Key number of the key to be loaded. */
    uint16_t wKeyVer,								/**< [In] Key version of the key to be loaded. */
    uint16_t wKeyType,								/**< [In] New key type of the KeyEntry (predefined type of KeyType). */
    uint8_t *pNewKey,								/**< [In] The key information to be updated. */
    uint16_t wNewKeyVer								/**< [In] New Key version of the key to be updated. */
);

/**
 * \brief Change a key entry at the specified position.
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
 * \return Status code
 * \retval #PH_ERR_SUCCESS Operation successful.
 * \retval #PH_ERR_INVALID_PARAMETER KeyType missmatch or wrong wPos.
 * \retval Other Depending on implementation and underlaying component.
 */
phStatus_t phKeyStore_SamAV3_SetKeyAtPos(
    phKeyStore_SamAV3_DataParams_t
    *pDataParams,	/**< [In] Pointer to this layers parameter structure. */
    uint16_t wKeyNo,								/**< [In] Key number of the key to be loaded. */
    uint16_t wPos,									/**< [In] Key position to be updated. */
    uint16_t wKeyType,								/**< [In] New key type of the KeyEntry (predefined type of KeyType). */
    uint8_t *pKey,									/**< [In] The key information to be loaded. */
    uint16_t wKeyVer								/**< [In] Key version of the key to be updated. */
);

/**
 * \brief Change the KUC of a key entry.
 *
 * First the command \ref phhalHw_SamAV3_Cmd_SAM_GetKeyEntry is executed to get the change key of the current key entry.
 * Afterwards the reference number of the KUC is set to wRefNoKUC via the \ref phhalHw_SamAV3_Cmd_SAM_ChangeKeyEntry command.
 *
 * \return Status code
 * \retval #PH_ERR_SUCCESS Operation successful.
 * \retval Other Depending on implementation and underlaying component.
 */
phStatus_t phKeyStore_SamAV3_SetKUC(
    phKeyStore_SamAV3_DataParams_t
    *pDataParams,	/**< [In] Pointer to this layers parameter structure. */
    uint16_t wKeyNo,								/**< [In] Key number of the key to be loaded. */
    uint16_t wRefNoKUC								/**< [In] Reference Number of the key usage counter used together with that key.*/
);

/**
 * \brief Change a full key entry.
 *
 * First the command \ref phhalHw_SamAV3_Cmd_SAM_GetKeyEntry is executed to get the information about the current key entry. If the current
 * key type does not match with wKeyType also all keys of the entry have to be updated. If wNoOfKeys is 01h key A is changed to pKeys, if it
 * is 02h key A and B are changed to pKeys and if it is 03h key A, B and C are changed to pKeys via the \ref phhalHw_SamAV3_Cmd_SAM_ChangeKeyEntry
 * command. If a key is changed also its version is changed to the value listed in pKeyVerList. Keys which are not provided by pKeys are set to zero
 * togheter with its versions. If wNoOfKeys is set to 0 key and version update is skiped. The fields DF_Aid, DFKeyNo, SET, ExtSET, KeyNoCEK, KeyVCEK,
 * KeyNoAEK and KeyVAEK are set according to the configuration parameters.\n
 *
 * In case of a MIFARE key entry the diversification keys for key A and key B of all key versions are set according to the configuration
 * parameters. These parameters can be accessd via #PH_KEYSTORE_SAMAV3_CONFIG_KEYNO_MF_DIV_A and #PH_KEYSTORE_SAMAV3_CONFIG_KEYV_MF_DIV_A
 * resp. #PH_KEYSTORE_SAMAV3_CONFIG_KEYNO_MF_DIV_B and #PH_KEYSTORE_SAMAV3_CONFIG_KEYV_MF_DIV_B.
 *
 *
 * \return Status code
 * \retval #PH_ERR_SUCCESS Operation successful.
 * \retval #PH_ERR_INVALID_PARAMETER KeyType missmatch or wrong wNoOfKeys.
 * \retval Other Depending on implementation and underlaying component.
 */
phStatus_t phKeyStore_SamAV3_SetFullKeyEntry(
    phKeyStore_SamAV3_DataParams_t
    *pDataParams,	/**< [In] Pointer to this layers parameter structure. */
    uint16_t wNoOfKeys,								/**< [In] Number of keys in pNewKeys. */
    uint16_t wKeyNo,								/**< [In] Number of the keys to be changed in the entry. */
    uint16_t wNewRefNoKUC,							/**< [In] Reference number of the key usage counter to be used. */
    uint16_t wNewKeyType,							/**< [In] Key type of the new key. */
    uint8_t *pNewKeys,								/**< [In] Buffer containing the Keys to be updated. This buffer has to be wNoOfKeys * keylength bytes long. */
    uint16_t *pNewKeyVerList						/**< [In] KeyVersionList of the key to be loaded. This buffer has to be wNoOfKeys * 2 bytes long. */
);

/**
 * \brief Get a key entry information block.
 *
 * The function returns the key type and all key versions of a key entry. This information
 * is retrieved by the \ref phhalHw_SamAV3_Cmd_SAM_GetKeyEntry command. All additional information
 * which is returned by the \ref phhalHw_SamAV3_Cmd_SAM_GetKeyEntry command is stored in
 * the configuration parameters of this layer. To access these values the function \ref phKeyStore_SamAV3_GetConfig
 * has to be used.
 *
 * \return Status code
 * \retval #PH_ERR_SUCCESS Operation successful.
 * \retval Other Depending on implementation and underlaying component.
 */
phStatus_t phKeyStore_SamAV3_GetKeyEntry(
    phKeyStore_SamAV3_DataParams_t
    *pDataParams,	/**< [In] Pointer to this layers parameter structure. */
    uint16_t wKeyNo,								/**< [In] Key number of the key entry of interest.*/
    uint16_t *pKeyVer,								/**< [Out] Array for version information.*/
    uint16_t *pKeyVerLen,							/**< [Out] Length of valid data in wKeyVer.*/
    uint16_t *pKeyType								/**< [Out] Type of the key.*/
);

/**
 * \brief Get a key.
 *
 * The function returns a key selected by its key version:
 * \li The command is not supported in AV1
 * \li To retrieve a key in AV3 a \ref phhalHw_SamAV3_Cmd_SAM_DumpSecretKey is executed. Therefore the flag
 * 'allow dump secret key' in ExtSet of the key entry has to be enabled. If a DES key is dumped, the key version
 * is encoded into every least significant bit of the first 8 key bytes.
 *
 * \return Status code
 * \retval #PH_ERR_SUCCESS Operation successful.
 * \retval Other Depending on implementation and underlaying component.
 */
phStatus_t phKeyStore_SamAV3_GetKey(
    phKeyStore_SamAV3_DataParams_t
    *pDataParams,	/**< [In] Pointer to this layers parameter structure. */
    uint16_t wKeyNo,								/**< [In] Key number of the key to be retrieved. */
    uint16_t wKeyVer,								/**< [In] Key version of the key to be retrieved. */
    uint8_t bKeyBufSize,							/**< [In] Size of the key buffer. */
    uint8_t *pKey,									/**< [Out] Pointer to the key itself. */
    uint16_t *pKeyType								/**< [Out] Type of the key. */
);

/**
 * \brief Set configuration parameter.
 * \return Status code
 * \retval #PH_ERR_SUCCESS Operation successful.
 * \retval Other Depending on implementation and underlaying component.
 */
phStatus_t phKeyStore_SamAV3_SetConfig(
    phKeyStore_SamAV3_DataParams_t
    *pDataParams,	/**< [In] Pointer to this layers parameter structure. */
    uint16_t wConfig,								/**< [In] Configuration Identifier */
    uint16_t wValue									/**< [In] Configuration Value */
);

/**
 * \brief Set the Desfire Application Identifier.
 * \return Status code
 * \retval #PH_ERR_SUCCESS Operation successful.
 * \retval Other Depending on implementation and underlaying component.
 */
phStatus_t phKeyStore_SamAV3_SetConfigStr(
    phKeyStore_SamAV3_DataParams_t
    *pDataParams,	/**< [In] Pointer to this layers parameter structure. */
    uint16_t wConfig,								/**< [In] Configuration Identifier, mainly #PH_KEYSTORE_SAMAV3_CONFIG_DF_AID. */
    uint8_t *pBuffer,								/**< [In] Buffer containing the Defire Application Identifier. */
    uint16_t wBufferLen								/**< [In] Length of data available in pBuffer. */
);

/**
 * \brief Get configuration parameter.
 * \return Status code
 * \retval #PH_ERR_SUCCESS Operation successful.
 * \retval Other Depending on implementation and underlaying component.
 */
phStatus_t phKeyStore_SamAV3_GetConfig(
    phKeyStore_SamAV3_DataParams_t
    *pDataParams,	/**< [In] Pointer to this layers parameter structure. */
    uint16_t wConfig,								/**< [In] Configuration Identifier */
    uint16_t *pValue								/**< [Out] Configuration Value */
);

/**
 * \brief Get the Desfire Application Identifier.
 * \return Status code
 * \retval #PH_ERR_SUCCESS Operation successful.
 * \retval Other Depending on implementation and underlaying component.
 */
phStatus_t phKeyStore_SamAV3_GetConfigStr(
    phKeyStore_SamAV3_DataParams_t
    *pDataParams,	/**< [In] Pointer to this layers parameter structure. */
    uint16_t wConfig,								/**< [In] Configuration Identifier, mainly #PH_KEYSTORE_SAMAV3_CONFIG_DF_AID */
    uint8_t **ppBuffer,							/**< [Out] Buffer containing the Defire Application Identifier. */
    uint16_t *pBufferLen							/**< [Out] Length of data available in pBuffer. */
);

/**
 * \brief Change a key usage counter entry.
 *
 * The function changes the KUC by using the \ref phhalHw_SamAV3_Cmd_SAM_ChangeKUCEntry command.
 * KeyNoCKUC and KeyVCKUC are set to according to the configuration parameters.
 *
 * \return Status code
 * \retval #PH_ERR_SUCCESS Operation successful.
 * \retval Other Depending on implementation and underlaying component.
 */
phStatus_t phKeyStore_SamAV3_ChangeKUC(
    phKeyStore_SamAV3_DataParams_t
    *pDataParams,	/**< [In] Pointer to this layers parameter structure. */
    uint16_t wRefNoKUC,								/**< [In] Number of the key usage counter.*/
    uint32_t dwLimit								/**< [In] Limit of the Key Usage Counter. */
);

/**
 * \brief Obtain a key usage counter entry.
 *
 * The function returns the KUC entry retrieved by the \ref phhalHw_SamAV3_Cmd_SAM_GetKUCEntry command.
 * KeyNoCKUC and KeyVCKUC are stored in the configuration parameters and can be accessed via the
 * \ref phKeyStore_SamAV3_GetConfig function.
 *
 * \return Status code
 * \retval #PH_ERR_SUCCESS Operation successful.
 * \retval Other Depending on implementation and underlaying component.
 */
phStatus_t phKeyStore_SamAV3_GetKUC(
    phKeyStore_SamAV3_DataParams_t
    *pDataParams,	/**< [In] Pointer to this layers parameter structure. */
    uint16_t wRefNoKUC,								/**< [In] Number of the key usage counter to be looked at (00h to 0Fh)*/
    uint32_t *pdwLimit,							/**< [Out] Currently set Limit in the KUC. */
    uint32_t *pdwCurVal							/**< [Out] Currently value in the KUC. */
);

/** end of phKeyStore_SamAV3 @} */

#endif /* PHKEYSTORE_SAMAV3_H */
