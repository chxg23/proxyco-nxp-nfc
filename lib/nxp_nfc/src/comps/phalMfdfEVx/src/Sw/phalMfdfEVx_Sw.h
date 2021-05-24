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

#ifndef PHALMFDFEVX_SW_H
#define PHALMFDFEVX_SW_H

#ifdef NXPBUILD__PHAL_MFDFEVX_NDA
/* MIFARE DESFire EVx contactless IC secure messaging related commands. ------------------------------------------------------------------------------- */
phStatus_t phalMfdfEVx_Sw_Authenticate(phalMfdfEVx_Sw_DataParams_t *pDataParams, uint16_t wOption,
    uint16_t wKeyNo,
    uint16_t wKeyVer, uint8_t bKeyNoCard, uint8_t *pDivInput, uint8_t bDivLen);

phStatus_t phalMfdfEVx_Sw_AuthenticateISO(phalMfdfEVx_Sw_DataParams_t *pDataParams,
    uint16_t wOption, uint16_t wKeyNo,
    uint16_t wKeyVer, uint8_t bKeyNoCard, uint8_t *pDivInput, uint8_t bDivLen);

phStatus_t phalMfdfEVx_Sw_AuthenticateAES(phalMfdfEVx_Sw_DataParams_t *pDataParams,
    uint16_t wOption, uint16_t wKeyNo,
    uint16_t wKeyVer, uint8_t bKeyNoCard, uint8_t *pDivInput, uint8_t bDivLen);

phStatus_t phalMfdfEVx_Sw_AuthenticateEv2(phalMfdfEVx_Sw_DataParams_t *pDataParams,
    uint8_t bFirstAuth, uint16_t wOption,
    uint16_t wKeyNo, uint16_t wKeyVer, uint8_t bKeyNoCard, uint8_t *pDivInput, uint8_t bDivLen,
    uint8_t bLenPcdCapsIn,
    uint8_t *pPcdCapsIn, uint8_t *pPcdCapsOut, uint8_t *pPdCapsOut);
#endif /* NXPBUILD__PHAL_MFDFEVX_NDA */

/* MIFARE DESFire EVx Memory and Configuration mamangement commands. ------------------------------------------------------------------- */
phStatus_t phalMfdfEVx_Sw_FreeMem(phalMfdfEVx_Sw_DataParams_t *pDataParams, uint8_t *pMemInfo);

#ifdef NXPBUILD__PHAL_MFDFEVX_NDA
phStatus_t phalMfdfEVx_Sw_Format(phalMfdfEVx_Sw_DataParams_t *pDataParams);

phStatus_t phalMfdfEVx_Sw_SetConfiguration(phalMfdfEVx_Sw_DataParams_t *pDataParams,
    uint8_t bOption, uint8_t *pData,
    uint8_t bDataLen);
#endif /* NXPBUILD__PHAL_MFDFEVX_NDA */

phStatus_t phalMfdfEVx_Sw_GetVersion(phalMfdfEVx_Sw_DataParams_t *pDataParams, uint8_t *pVerInfo);

#ifdef NXPBUILD__PHAL_MFDFEVX_NDA
phStatus_t phalMfdfEVx_Sw_GetCardUID(phalMfdfEVx_Sw_DataParams_t *pDataParams,
    uint8_t bExchangeOption, uint8_t bOption,
    uint8_t *pUid, uint8_t *pUidLength);

/* MIFARE DESFire EVx Key mamangement commands. ---------------------------------------------------------------------------------------- */
phStatus_t phalMfdfEVx_Sw_ChangeKey(phalMfdfEVx_Sw_DataParams_t *pDataParams, uint16_t wOption,
    uint16_t wOldKeyNo,
    uint16_t wOldKeyVer, uint16_t wNewKeyNo, uint16_t wNewKeyVer, uint8_t bKeyNoCard,
    uint8_t *pDivInput, uint8_t bDivLen);

phStatus_t phalMfdfEVx_Sw_ChangeKeyEv2(phalMfdfEVx_Sw_DataParams_t *pDataParams, uint16_t wOption,
    uint16_t wOldKeyNo,
    uint16_t wOldKeyVer, uint16_t wNewKeyNo, uint16_t wNewKeyVer, uint8_t bKeySetNo,
    uint8_t bKeyNoCard, uint8_t *pDivInput,
    uint8_t bDivLen);

phStatus_t phalMfdfEVx_Sw_InitializeKeySet(phalMfdfEVx_Sw_DataParams_t *pDataParams,
    uint8_t bKeySetNo, uint8_t bKeyType);

phStatus_t phalMfdfEVx_Sw_FinalizeKeySet(phalMfdfEVx_Sw_DataParams_t *pDataParams,
    uint8_t bKeySetNo, uint8_t bKeySetVersion);

phStatus_t phalMfdfEVx_Sw_RollKeySet(phalMfdfEVx_Sw_DataParams_t *pDataParams, uint8_t bKeySetNo);
#endif /* NXPBUILD__PHAL_MFDFEVX_NDA */

phStatus_t phalMfdfEVx_Sw_GetKeySettings(phalMfdfEVx_Sw_DataParams_t *pDataParams,
    uint8_t *pKeySettings,
    uint8_t *bRespLen);

#ifdef NXPBUILD__PHAL_MFDFEVX_NDA
phStatus_t phalMfdfEVx_Sw_ChangeKeySettings(phalMfdfEVx_Sw_DataParams_t *pDataParams,
    uint8_t bKeySettings);

phStatus_t phalMfdfEVx_Sw_GetKeyVersion(phalMfdfEVx_Sw_DataParams_t *pDataParams, uint8_t bKeyNo,
    uint8_t bKeySetNo,
    uint8_t *pKeyVersion, uint8_t *bRxLen);
#endif /* NXPBUILD__PHAL_MFDFEVX_NDA */

/* MIFARE DESFire EVx Application mamangement commands. -------------------------------------------------------------------------------- */
phStatus_t phalMfdfEVx_Sw_CreateApplication(phalMfdfEVx_Sw_DataParams_t *pDataParams,
    uint8_t bOption, uint8_t *pAid,
    uint8_t bKeySettings1, uint8_t bKeySettings2, uint8_t bKeySettings3, uint8_t *pKeySetValues,
    uint8_t *pISOFileId,
    uint8_t *pISODFName, uint8_t bISODFNameLen);

phStatus_t phalMfdfEVx_Sw_DeleteApplication(phalMfdfEVx_Sw_DataParams_t *pDataParams,
    uint8_t *pAid, uint8_t *pDAMMAC, uint8_t bDAMMAC_Len);

phStatus_t phalMfdfEVx_Sw_CreateDelegatedApplication(phalMfdfEVx_Sw_DataParams_t *pDataParams,
    uint8_t bOption, uint8_t *pAid,
    uint8_t *pDamParams, uint8_t bKeySettings1, uint8_t bKeySettings2, uint8_t bKeySettings3,
    uint8_t  *bKeySetValues,
    uint8_t *pISOFileId, uint8_t *pISODFName, uint8_t bISODFNameLen, uint8_t *pEncK,
    uint8_t *pDAMMAC);

phStatus_t phalMfdfEVx_Sw_SelectApplication(phalMfdfEVx_Sw_DataParams_t *pDataParams,
    uint8_t bOption, uint8_t *pAppId,
    uint8_t *pAppId2);

phStatus_t phalMfdfEVx_Sw_GetApplicationIDs(phalMfdfEVx_Sw_DataParams_t *pDataParams,
    uint8_t bOption, uint8_t **pAidBuff,
    uint8_t *pNumAIDs);

#ifdef NXPBUILD__PHAL_MFDFEVX_NDA
phStatus_t phalMfdfEVx_Sw_GetDFNames(phalMfdfEVx_Sw_DataParams_t *pDataParams, uint8_t bOption,
    uint8_t *pDFBuffer,
    uint8_t *pDFInfoLen);
#endif /* NXPBUILD__PHAL_MFDFEVX_NDA */

phStatus_t phalMfdfEVx_Sw_GetDelegatedInfo(phalMfdfEVx_Sw_DataParams_t *pDataParams,
    uint8_t *pDAMSlot, uint8_t *pDamSlotVer,
    uint8_t *pQuotaLimit, uint8_t *pFreeBlocks, uint8_t *pAid);

/* MIFARE DESFire EVx File mamangement commands. --------------------------------------------------------------------------------------- */
phStatus_t phalMfdfEVx_Sw_CreateStdDataFile(phalMfdfEVx_Sw_DataParams_t *pDataParams,
    uint8_t bOption, uint8_t bFileNo,
    uint8_t *pISOFileId, uint8_t bFileOption, uint8_t *pAccessRights, uint8_t *pFileSize);

phStatus_t phalMfdfEVx_Sw_CreateBackupDataFile(phalMfdfEVx_Sw_DataParams_t *pDataParams,
    uint8_t bOption, uint8_t bFileNo,
    uint8_t *pISOFileId, uint8_t bFileOption, uint8_t *pAccessRights, uint8_t *pFileSize);

phStatus_t phalMfdfEVx_Sw_CreateValueFile(phalMfdfEVx_Sw_DataParams_t *pDataParams,
    uint8_t bFileNo, uint8_t bCommSett,
    uint8_t *pAccessRights, uint8_t *pLowerLmit, uint8_t *pUpperLmit, uint8_t *pValue,
    uint8_t bLimitedCredit);

phStatus_t phalMfdfEVx_Sw_CreateLinearRecordFile(phalMfdfEVx_Sw_DataParams_t *pDataParams,
    uint8_t bOption, uint8_t  bFileNo,
    uint8_t  *pIsoFileId, uint8_t bCommSett, uint8_t *pAccessRights, uint8_t *pRecordSize,
    uint8_t *pMaxNoOfRec);

phStatus_t phalMfdfEVx_Sw_CreateCyclicRecordFile(phalMfdfEVx_Sw_DataParams_t *pDataParams,
    uint8_t bOption, uint8_t  bFileNo,
    uint8_t  *pIsoFileId, uint8_t bCommSett, uint8_t *pAccessRights, uint8_t *pRecordSize,
    uint8_t *pMaxNoOfRec);

#ifdef  NXPBUILD__PHAL_MFDFEVX_NDA
phStatus_t phalMfdfEVx_Sw_CreateTransactionMacFile(phalMfdfEVx_Sw_DataParams_t *pDataParams,
    uint8_t bFileNo,
    uint8_t bCommSett, uint8_t *pAccessRights, uint8_t bKeyType, uint8_t *bTMKey, uint8_t bTMKeyVer);
#endif /* NXPBUILD__PHAL_MFDFEVX_NDA */

phStatus_t phalMfdfEVx_Sw_DeleteFile(phalMfdfEVx_Sw_DataParams_t *pDataParams, uint8_t bFileNo);

phStatus_t phalMfdfEVx_Sw_GetFileIDs(phalMfdfEVx_Sw_DataParams_t *pDataParams, uint8_t *pFid,
    uint8_t *bNumFID);

phStatus_t phalMfdfEVx_Sw_GetISOFileIDs(phalMfdfEVx_Sw_DataParams_t *pDataParams,
    uint8_t *pFidBuffer, uint8_t *pNumFID);

phStatus_t phalMfdfEVx_Sw_GetFileSettings(phalMfdfEVx_Sw_DataParams_t *pDataParams,
    uint8_t bFileNo, uint8_t *pFSBuffer,
    uint8_t *pBufferLen);

phStatus_t phalMfdfEVx_Sw_GetFileCounters(phalMfdfEVx_Sw_DataParams_t *pDataParams,
    uint8_t bOption, uint8_t bFileNo,
    uint8_t *pFileCounters, uint8_t *pRxLen);

phStatus_t phalMfdfEVx_Sw_ChangeFileSettings(phalMfdfEVx_Sw_DataParams_t *pDataParams,
    uint8_t bOption,
    uint8_t bFileNo, uint8_t bFileOption, uint8_t *pAccessRights, uint8_t bAddInfoLen,
    uint8_t *pAddInfo);

/* MIFARE DESFire EVx Data mamangement commands. --------------------------------------------------------------------------------------- */
phStatus_t phalMfdfEVx_Sw_ReadData(phalMfdfEVx_Sw_DataParams_t *pDataParams, uint8_t bOption,
    uint8_t bIns,
    uint8_t bFileNo, uint8_t *pOffset, uint8_t *pLength, uint8_t **ppRxdata, uint16_t *pRxdataLen);

phStatus_t phalMfdfEVx_Sw_WriteData(phalMfdfEVx_Sw_DataParams_t *pDataParams, uint8_t bCommOption,
    uint8_t bIns,
    uint8_t bFileNo, uint8_t *pOffset, uint8_t *pData, uint8_t *pDataLen);

phStatus_t phalMfdfEVx_Sw_GetValue(phalMfdfEVx_Sw_DataParams_t *pDataParams, uint8_t bCommOption,
    uint8_t bFileNo,
    uint8_t *pValue);

phStatus_t phalMfdfEVx_Sw_Credit(phalMfdfEVx_Sw_DataParams_t *pDataParams, uint8_t bCommOption,
    uint8_t bFileNo,
    uint8_t *pValue);

phStatus_t phalMfdfEVx_Sw_Debit(phalMfdfEVx_Sw_DataParams_t *pDataParams, uint8_t bCommOption,
    uint8_t bFileNo,
    uint8_t *pValue);

phStatus_t phalMfdfEVx_Sw_LimitedCredit(phalMfdfEVx_Sw_DataParams_t *pDataParams,
    uint8_t bCommOption, uint8_t bFileNo,
    uint8_t *pValue);

phStatus_t phalMfdfEVx_Sw_ReadRecords(phalMfdfEVx_Sw_DataParams_t *pDataParams,
    uint8_t bCommOption, uint8_t bIns,
    uint8_t bFileNo, uint8_t *pRecNo, uint8_t *pRecCount, uint8_t *pRecSize, uint8_t **ppRxdata,
    uint16_t *pRxdataLen);

phStatus_t phalMfdfEVx_Sw_WriteRecord(phalMfdfEVx_Sw_DataParams_t *pDataParams,
    uint8_t bCommOption, uint8_t bIns,
    uint8_t bFileNo, uint8_t *pOffset, uint8_t *pData, uint8_t *pDataLen);

phStatus_t phalMfdfEVx_Sw_UpdateRecord(phalMfdfEVx_Sw_DataParams_t *pDataParams,
    uint8_t bCommOption, uint8_t bIns,
    uint8_t bFileNo, uint8_t *pRecNo, uint8_t *pOffset, uint8_t *pData, uint8_t *pDataLen);

phStatus_t phalMfdfEVx_Sw_ClearRecordFile(phalMfdfEVx_Sw_DataParams_t *pDataParams,
    uint8_t bFileNo);

/* MIFARE DESFire EVx Transaction mamangement commands. -------------------------------------------------------------------------------- */
phStatus_t phalMfdfEVx_Sw_CommitTransaction(phalMfdfEVx_Sw_DataParams_t *pDataParams,
    uint8_t bOption, uint8_t *pTMC,
    uint8_t *pTMAC);

phStatus_t phalMfdfEVx_Sw_AbortTransaction(phalMfdfEVx_Sw_DataParams_t *pDataParams);

phStatus_t phalMfdfEVx_Sw_CommitReaderID(phalMfdfEVx_Sw_DataParams_t *pDataParams, uint8_t *pTMRI,
    uint8_t *pEncTMRI);

/* MIFARE DESFire EVx ISO7816-4 commands. ---------------------------------------------------------------------------------------------- */
phStatus_t phalMfdfEVx_Sw_IsoSelectFile(phalMfdfEVx_Sw_DataParams_t *pDataParams, uint8_t bOption,
    uint8_t bSelector,
    uint8_t *pFid, uint8_t *pDFname, uint8_t bDFnameLen, uint8_t  bExtendedLenApdu, uint8_t **ppFCI,
    uint16_t *pwFCILen);

phStatus_t phalMfdfEVx_Sw_IsoReadBinary(phalMfdfEVx_Sw_DataParams_t *pDataParams,
    uint16_t wOption, uint8_t bOffset,
    uint8_t bSfid, uint32_t dwBytesToRead, uint8_t bExtendedLenApdu, uint8_t **ppRxBuffer,
    uint32_t *pBytesRead);

phStatus_t phalMfdfEVx_Sw_IsoUpdateBinary(phalMfdfEVx_Sw_DataParams_t *pDataParams,
    uint8_t bOffset, uint8_t bSfid,
    uint8_t bExtendedLenApdu, uint8_t *pData, uint32_t dwDataLen);

phStatus_t phalMfdfEVx_Sw_IsoReadRecords(phalMfdfEVx_Sw_DataParams_t *pDataParams,
    uint16_t wOption, uint8_t bRecNo,
    uint8_t bReadAllFromP1, uint8_t bSfid, uint32_t dwBytesToRead, uint8_t bExtendedLenApdu,
    uint8_t  **ppRxBuffer,
    uint32_t *pBytesRead);

phStatus_t phalMfdfEVx_Sw_IsoAppendRecord(phalMfdfEVx_Sw_DataParams_t *pDataParams, uint8_t bSfid,
    uint8_t bExtendedLenApdu,
    uint8_t *pData, uint32_t dwDataLen);

phStatus_t phalMfdfEVx_Sw_IsoUpdateRecord(phalMfdfEVx_Sw_DataParams_t *pDataParams, uint8_t bIns,
    uint8_t bRecNo,
    uint8_t bSfid, uint8_t bRefCtrl, uint8_t *pData, uint8_t bDataLen);

phStatus_t phalMfdfEVx_Sw_IsoGetChallenge(phalMfdfEVx_Sw_DataParams_t *pDataParams,
    uint16_t wKeyNo, uint16_t wKeyVer,
    uint8_t bExtendedLenApdu, uint32_t dwLe, uint8_t *pRPICC1);

#ifdef NXPBUILD__PHAL_MFDFEVX_NDA
phStatus_t phalMfdfEVx_Sw_IsoExternalAuthenticate(phalMfdfEVx_Sw_DataParams_t *pDataParams,
    uint8_t *pInput, uint8_t bInputLen,
    uint8_t bExtendedLenApdu, uint8_t *pDataOut, uint8_t *pOutLen);

phStatus_t phalMfdfEVx_Sw_IsoInternalAuthenticate(phalMfdfEVx_Sw_DataParams_t *pDataParams,
    uint8_t *pInput,
    uint8_t bInputLen, uint8_t bExtendedLenApdu, uint8_t *pDataOut, uint8_t *pOutLen);

phStatus_t phalMfdfEVx_Sw_IsoAuthenticate(phalMfdfEVx_Sw_DataParams_t *pDataParams,
    uint16_t wKeyNo, uint16_t wKeyVer,
    uint8_t bKeyNoCard, uint8_t bIsPICCkey);
#endif /* NXPBUILD__PHAL_MFDFEVX_NDA */

/* MIFARE DESFire EVx Originality Check functions. ------------------------------------------------------------------------------------- */
phStatus_t phalMfdfEVx_Sw_ReadSign(phalMfdfEVx_Sw_DataParams_t *pDataParams, uint8_t bAddr,
    uint8_t **pSignature);

/* MIFARE DESFire EVx MIFARE Classic contactless IC functions. ---------------------------------------------------------------------------------------- */
phStatus_t phalMfdfEVx_Sw_CreateMFCMapping(phalMfdfEVx_Sw_DataParams_t *pDataParams,
    uint8_t bComOption, uint8_t bFileNo,
    uint8_t bFileOption, uint8_t *pMFCBlockList, uint8_t bMFCBlocksLen, uint8_t bRestoreSource,
    uint8_t *pMFCLicense,
    uint8_t bMFCLicenseLen, uint8_t *pMFCLicenseMAC);

phStatus_t phalMfdfEVx_Sw_RestoreTransfer(phalMfdfEVx_Sw_DataParams_t *pDataParams,
    uint8_t bCommOption, uint8_t bTargetFileNo, uint8_t bSourceFileNo);

#ifdef NXPBUILD__PHAL_MFDFEVX_NDA
phStatus_t phalMfdfEVx_Sw_RestrictMFCUpdate(phalMfdfEVx_Sw_DataParams_t *pDataParams,
    uint8_t bOption, uint8_t *pMFCConfig,
    uint8_t bMFCConfigLen, uint8_t *pMFCLicense, uint8_t bMFCLicenseLen, uint8_t *pMFCLicenseMAC);

/* MIFARE DESFire EVx POST Delivery Configuration function. ---------------------------------------------------------------------------- */
phStatus_t phalMfdfEVx_Sw_AuthenticatePDC(phalMfdfEVx_Sw_DataParams_t *pDataParams, uint8_t bRfu,
    uint8_t bKeyNoCard, uint8_t wKeyNo,
    uint16_t wKeyVer, uint8_t bUpgradeInfo);
#endif /* NXPBUILD__PHAL_MFDFEVX_NDA */

/* MIFARE DESFire EVx Miscellaneous functions. ----------------------------------------------------------------------------------------- */
phStatus_t phalMfdfEVx_Sw_GetConfig(phalMfdfEVx_Sw_DataParams_t *pDataParams, uint16_t wConfig,
    uint16_t *pValue);

phStatus_t phalMfdfEVx_Sw_SetConfig(phalMfdfEVx_Sw_DataParams_t *pDataParams, uint16_t wConfig,
    uint16_t wValue);

phStatus_t phalMfdfEVx_Sw_ResetAuthentication(phalMfdfEVx_Sw_DataParams_t *pDataParams);

#ifdef NXPBUILD__PHAL_MFDFEVX_NDA
phStatus_t phalMfdfEVx_Sw_GenerateDAMEncKey(phalMfdfEVx_Sw_DataParams_t *pDataParams,
    uint16_t wKeyNoDAMEnc, uint16_t wKeyVerDAMEnc,
    uint16_t wKeyNoAppDAMDefault, uint16_t wKeyVerAppDAMDefault, uint8_t bAppDAMDefaultKeyVer,
    uint8_t *pDAMEncKey);

phStatus_t phalMfdfEVx_Sw_GenerateDAMMAC(phalMfdfEVx_Sw_DataParams_t *pDataParams,
    uint8_t bOption, uint16_t wKeyNoDAMMAC,
    uint16_t wKeyVerDAMMAC, uint8_t *pAid, uint8_t *pDamParams, uint8_t bKeySettings1,
    uint8_t bKeySettings2,
    uint8_t bKeySettings3, uint8_t *pKeySetValues, uint8_t *pISOFileId, uint8_t *pISODFName,
    uint8_t bISODFNameLen, uint8_t *pEncK, uint8_t *pDAMMAC);

phStatus_t phalMfdfEVx_Sw_GenerateDAMMACSetConfig(phalMfdfEVx_Sw_DataParams_t *pDataParams,
    uint16_t wKeyNoDAMMAC,
    uint16_t wKeyVerDAMMAC, uint16_t wOldDFNameLen, uint8_t *pOldISODFName, uint16_t wNewDFNameLen,
    uint8_t *pNewISODFName, uint8_t *pDAMMAC);

phStatus_t phalMfdfEVx_Sw_CalculateTMV(phalMfdfEVx_Sw_DataParams_t *pDataParams, uint16_t wOption,
    uint16_t wKeyNoTMACKey,
    uint16_t wKeyVerTMACKey, uint8_t *pDivInput, uint8_t bDivInputLen, uint8_t *pTMC, uint8_t *pUid,
    uint8_t bUidLen,
    uint8_t *pTMI, uint32_t dwTMILen, uint8_t *pTMV);

phStatus_t phalMfdfEVx_Sw_DecryptReaderID(phalMfdfEVx_Sw_DataParams_t *pDataParams,
    uint16_t wOption, uint16_t wKeyNoTMACKey,
    uint16_t wKeyVerTMACKey, uint8_t *pDivInput, uint8_t bDivInputLen, uint8_t *pTMC, uint8_t *pUid,
    uint8_t bUidLen,
    uint8_t *pEncTMRI, uint8_t *pTMRIPrev);

phStatus_t phalMfdfEVx_Sw_ComputeMFCLicenseMAC(phalMfdfEVx_Sw_DataParams_t *pDataParams,
    uint16_t wOption, uint16_t wMFCLicenseMACKeyNo,
    uint16_t wMFCLicenseMACKeyVer, uint8_t *pInput, uint16_t wInputLen, uint8_t *pDivInput,
    uint8_t bDivInputLen, uint8_t *pMFCLicenseMAC);

phStatus_t phalMfdfEVx_Sw_CalculateMACSDM(phalMfdfEVx_Sw_DataParams_t *pDataParams,
    uint8_t bSdmOption, uint16_t wSDMMacKeyNo,
    uint16_t wSDMMacKeyVer, uint8_t *pUid, uint8_t bUidLen, uint8_t *pSDMReadCtr, uint8_t *pInData,
    uint16_t wInDataLen,
    uint8_t *pRespMac);

phStatus_t phalMfdfEVx_Sw_DecryptSDMENCFileData(phalMfdfEVx_Sw_DataParams_t *pDataParams,
    uint8_t bSdmOption, uint16_t wEncKeyNo,
    uint16_t wEncKeyVer, uint8_t *pUid, uint8_t bUidLen, uint8_t *pSDMReadCtr, uint8_t *pEncdata,
    uint16_t wEncDataLen,
    uint8_t *pPlainData);

phStatus_t phalMfdfEVx_Sw_DecryptSDMPICCData(phalMfdfEVx_Sw_DataParams_t *pDataParams,
    uint16_t wKeyNo, uint16_t wKeyVer,
    uint8_t *pIndata, uint16_t wInDataLen, uint8_t *pPlainData);

#endif /* NXPBUILD__PHAL_MFDFEVX_NDA */

phStatus_t phalMfdfEVx_Sw_SetVCAParams(phalMfdfEVx_Sw_DataParams_t *pDataParams,
    void *pAlVCADataParams);
#endif /* PHALMFDFEVX_SW_H */
