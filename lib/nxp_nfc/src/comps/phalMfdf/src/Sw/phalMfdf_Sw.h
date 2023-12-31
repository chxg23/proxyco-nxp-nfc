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
* Software MIFARE DESFire EV1 contactless IC Application Component of Reader
* Library Framework.
* $Author$
* $Revision$ (v06.11.00)
* $Date$
*/

#ifndef PHALMFDF_SW_H
#define PHALMFDF_SW_H

#ifdef NXPBUILD__PH_NDA_MFDF

/*
*  Authenticate
*/
phStatus_t phalMfdf_Sw_Authenticate(
    phalMfdf_Sw_DataParams_t *pDataParams,
    uint16_t wOption,
    uint16_t wKeyNo,
    uint16_t wKeyVer,
    uint8_t bKeyNoCard,
    uint8_t *pDivInput,
    uint8_t bDivLen
);

/*
*  AuthenticateISO
*/
phStatus_t phalMfdf_Sw_AuthenticateISO(
    phalMfdf_Sw_DataParams_t *pDataParams,
    uint16_t wOption,
    uint16_t wKeyNo,
    uint16_t wKeyVer,
    uint8_t bKeyNoCard,
    uint8_t *pDivInput,
    uint8_t bDivLen
);

/*
*  Authenticate AES
*/
phStatus_t phalMfdf_Sw_AuthenticateAES(
    phalMfdf_Sw_DataParams_t *pDataParams,
    uint16_t wOption,
    uint16_t wKeyNo,
    uint16_t wKeyVer,
    uint8_t bKeyNoCard,
    uint8_t *pDivInput,
    uint8_t bDivLen
);

/*
*  ChangeKeySettings
*/
phStatus_t phalMfdf_Sw_ChangeKeySettings(
    phalMfdf_Sw_DataParams_t *pDataParams,
    uint8_t bKeySettings
);

/*
*  GetKeySettings
*/
phStatus_t phalMfdf_Sw_GetKeySettings(
    phalMfdf_Sw_DataParams_t *pDataParams,
    uint8_t *pResponse
);

/*
*  ChangeKey
*/
phStatus_t phalMfdf_Sw_ChangeKey(
    phalMfdf_Sw_DataParams_t *pDataParams,
    uint16_t wOption,
    uint16_t wOldKeyNo,
    uint16_t wOldKeyVer,
    uint16_t wNewKeyNo,
    uint16_t wNewKeyVer,
    uint8_t bKeyNoCard,
    uint8_t *pDivInput,
    uint8_t bDivLen
);
/*
*  GetKeyVersion
*/
phStatus_t phalMfdf_Sw_GetKeyVersion(
    phalMfdf_Sw_DataParams_t *pDataParams,
    uint8_t bKeyNo,
    uint8_t *pResponse
);
#endif /* NXPBUILD__PH_NDA_MFDF */

/*
*  CreateApplication
*/
phStatus_t phalMfdf_Sw_CreateApplication(
    phalMfdf_Sw_DataParams_t *pDataParams,
    uint8_t bOption,
    uint8_t *pAid,
    uint8_t bKeySettings1,
    uint8_t bKeySettings2,
    uint8_t *pISOFileId,
    uint8_t *pISODFName,
    uint8_t bISODFNameLen
);

#ifdef NXPBUILD__PH_NDA_MFDF

/*
*  DeleteApplication
*/
phStatus_t phalMfdf_Sw_DeleteApplication(
    phalMfdf_Sw_DataParams_t *pDataParams,
    uint8_t *pAppId
);

/*
*  GetApplicationIDs
*/
phStatus_t phalMfdf_Sw_GetApplicationIDs(
    phalMfdf_Sw_DataParams_t *pDataParams,
    uint8_t *pResponse,
    uint8_t *pNumAIDs
);

/*
*  phalMfdf_Sw_GetDFNames
*/
phStatus_t phalMfdf_Sw_GetDFNames(
    phalMfdf_Sw_DataParams_t *pDataParams,
    uint8_t bOption,
    uint8_t *pDFBuffer,
    uint8_t *pDFInfoLen
);

#endif /* NXPBUILD__PH_NDA_MFDF */

/*
*  SelectApplication
*/
phStatus_t phalMfdf_Sw_SelectApplication(
    phalMfdf_Sw_DataParams_t *pDataParams,
    uint8_t *pAppId
);

#ifdef NXPBUILD__PH_NDA_MFDF

/*
*  FormatPICC
*/
phStatus_t phalMfdf_Sw_FormatPICC(
    phalMfdf_Sw_DataParams_t *pDataParams
);

#endif /* NXPBUILD__PH_NDA_MFDF */

/*
*  GetVersion
*/
phStatus_t phalMfdf_Sw_GetVersion(
    phalMfdf_Sw_DataParams_t *pDataParams,
    uint8_t *pResponse
);

#ifdef NXPBUILD__PH_NDA_MFDF

/*
*  Free Memory
*/
phStatus_t phalMfdf_Sw_FreeMem(
    phalMfdf_Sw_DataParams_t *pDataParams,
    uint8_t *pResponse
);

/*
*  Set Configuration
*/
phStatus_t phalMfdf_Sw_SetConfiguration(
    phalMfdf_Sw_DataParams_t *pDataParams,
    uint8_t bOption,
    uint8_t *pData,
    uint8_t bDataLen
);

/*
*  GetCardUID
*/
phStatus_t phalMfdf_Sw_GetCardUID(
    phalMfdf_Sw_DataParams_t *pDataParams,
    uint8_t *pResponse
);

/*
*  GetFileIDs
*/
phStatus_t phalMfdf_Sw_GetFileIDs(
    phalMfdf_Sw_DataParams_t *pDataParams,
    uint8_t *pResponse,
    uint8_t *bNumFIDs
);

/*
*  GetISOFileIDs
*/
phStatus_t phalMfdf_Sw_GetISOFileIDs(
    phalMfdf_Sw_DataParams_t *pDataParams,
    uint8_t *pResponse,
    uint8_t *pNumFIDs
);

/*
*  GetFileSettings
*/
phStatus_t phalMfdf_Sw_GetFileSettings(
    phalMfdf_Sw_DataParams_t *pDataParams,
    uint8_t bFileNo,
    uint8_t *pResponse,
    uint8_t *pBufferLen
);

/*
*  ChangeFileSettings
*/
phStatus_t phalMfdf_Sw_ChangeFileSettings(
    phalMfdf_Sw_DataParams_t *pDataParams,
    uint8_t bOption,
    uint8_t bFileNo,
    uint8_t bCommSett,
    uint8_t *pAccessRights
);

#endif /* NXPBUILD__PH_NDA_MFDF */

/*
*
*  CreateStdDataFile
*/
phStatus_t phalMfdf_Sw_CreateStdDataFile(
    phalMfdf_Sw_DataParams_t *pDataParams,
    uint8_t bOption,
    uint8_t bFileNo,
    uint8_t   *pISOFileId,
    uint8_t bCommSett,
    uint8_t *pAccessRights,
    uint8_t *pFileSize
);

#ifdef NXPBUILD__PH_NDA_MFDF

/*
*  CreateBackupDataFile
*/
phStatus_t phalMfdf_Sw_CreateBackupDataFile(
    phalMfdf_Sw_DataParams_t *pDataParams,
    uint8_t bOption,
    uint8_t bFileNo,
    uint8_t *pISOFileId,
    uint8_t bCommSett,
    uint8_t *pAccessRights,
    uint8_t *pFileSize
);

/*
*  CreateValueFile
*/
phStatus_t phalMfdf_Sw_CreateValueFile(
    phalMfdf_Sw_DataParams_t *pDataParams,
    uint8_t bFileNo,
    uint8_t bCommSett,
    uint8_t *pAccessRights,
    uint8_t *pLowerLmit,
    uint8_t *pUpperLmit,
    uint8_t *pValue,
    uint8_t bLimitedCredit
);
/*
*
*  CreateLinearRecFile
*/
phStatus_t phalMfdf_Sw_CreateLinearRecordFile(
    phalMfdf_Sw_DataParams_t *pDataParams,
    uint8_t bOption,
    uint8_t  bFileNo,
    uint8_t  *pIsoFileId,
    uint8_t bCommSett,
    uint8_t *pAccessRights,
    uint8_t *pRecordSize,
    uint8_t *pMaxNoOfRec
);

/*
*  CreateCyclicRecFile
*/
phStatus_t phalMfdf_Sw_CreateCyclicRecordFile(
    phalMfdf_Sw_DataParams_t *pDataParams,
    uint8_t bOption,
    uint8_t  bFileNo,
    uint8_t  *pIsoFileId,
    uint8_t bCommSett,
    uint8_t *pAccessRights,
    uint8_t *pRecordSize,
    uint8_t *pMaxNoOfRec
);

/*
*  DeleteFile
*
*/
phStatus_t phalMfdf_Sw_DeleteFile(
    phalMfdf_Sw_DataParams_t *pDataParams,
    uint8_t bFileNo
);

/*
*  readdata
*/
phStatus_t phalMfdf_Sw_ReadData(
    phalMfdf_Sw_DataParams_t *pDataParams,
    uint8_t bOption,
    uint8_t bFileNo,
    uint8_t *pOffset,
    uint8_t *pLength,
    uint8_t **ppRxdata,
    uint16_t *pRxdataLen
);

#endif /* NXPBUILD__PH_NDA_MFDF */

/*
*  WriteData
*/
phStatus_t phalMfdf_Sw_WriteData(
    phalMfdf_Sw_DataParams_t *pDataParams,
    uint8_t bCommOption,
    uint8_t bFileNo,
    uint8_t *pOffset,
    uint8_t *pData,
    uint8_t *pDataLen
);

#ifdef NXPBUILD__PH_NDA_MFDF

/*
*  GetValue
*/
phStatus_t phalMfdf_Sw_GetValue(
    phalMfdf_Sw_DataParams_t *pDataParams,
    uint8_t bCommOption,
    uint8_t bFileNo,
    uint8_t *pValue
);

/*
*  Credit
*/
phStatus_t phalMfdf_Sw_Credit(
    phalMfdf_Sw_DataParams_t *pDataParams,
    uint8_t bCommOption,
    uint8_t bFileNo,
    uint8_t *pValue
);

/*
*  debit
*/
phStatus_t phalMfdf_Sw_Debit(
    phalMfdf_Sw_DataParams_t *pDataParams,
    uint8_t bCommOption,
    uint8_t bFileNo,
    uint8_t *pValue
);

/*
*  LimitedCredit
*/

phStatus_t phalMfdf_Sw_LimitedCredit(
    phalMfdf_Sw_DataParams_t *pDataParams,
    uint8_t bCommOption,
    uint8_t bFileNo,
    uint8_t *pValue
);

/*
*  WriteRecord
*/
phStatus_t phalMfdf_Sw_WriteRecord(
    phalMfdf_Sw_DataParams_t *pDataParams,
    uint8_t bCommOption,
    uint8_t bFileNo,
    uint8_t *pOffset,
    uint8_t *pData,
    uint8_t *pDataLen
);

/*
*  ReadRecords
*/
phStatus_t phalMfdf_Sw_ReadRecords(
    phalMfdf_Sw_DataParams_t *pDataParams,
    uint8_t bCommOption,
    uint8_t bFileNo,
    uint8_t *pOffset,
    uint8_t *pNumRec,
    uint8_t *pRecSize,
    uint8_t **ppRxdata,
    uint16_t *pRxdataLen
);

/*
*  ClearRecordFile
*/
phStatus_t phalMfdf_Sw_ClearRecordFile(
    phalMfdf_Sw_DataParams_t *pDataParams,
    uint8_t bFileNo
);

/*
*  CommitTransaction
*/
phStatus_t phalMfdf_Sw_CommitTransaction(
    phalMfdf_Sw_DataParams_t *pDataParams
);

/*
*  AbortTransaction
*/
phStatus_t phalMfdf_Sw_AbortTransaction(
    phalMfdf_Sw_DataParams_t *pDataParams
);

#endif /* NXPBUILD__PH_NDA_MFDF */

/*
*  ISO Select
*/
phStatus_t phalMfdf_Sw_IsoSelectFile(
    phalMfdf_Sw_DataParams_t *pDataParams,
    uint8_t bOption,
    uint8_t bSelector,
    uint8_t *pFid,
    uint8_t *pDFname,
    uint8_t bDFnameLen,
    uint8_t **ppRecv,
    uint16_t *pwRxlen
);

/*
*  ISO Read Binary
*/
phStatus_t phalMfdf_Sw_IsoReadBinary(
    phalMfdf_Sw_DataParams_t *pDataParams,
    uint16_t wOption,
    uint8_t bOffset,
    uint8_t bSfid,
    uint8_t bBytesToRead,
    uint8_t **ppRxBuffer,
    uint16_t *pBytesRead
);

/*
*  ISO Update Binary
*/
phStatus_t phalMfdf_Sw_IsoUpdateBinary(
    phalMfdf_Sw_DataParams_t *pDataParams,
    uint8_t bOffset,
    uint8_t bSfid,
    uint8_t *pData,
    uint8_t bDataLen
);

#ifdef NXPBUILD__PH_NDA_MFDF

/*
*  Read Records
*/
phStatus_t phalMfdf_Sw_IsoReadRecords(
    phalMfdf_Sw_DataParams_t *pDataParams,
    uint16_t wOption,
    uint8_t bRecNo,
    uint8_t bReadAllFromP1,
    uint8_t bSfid,
    uint8_t bBytesToRead,
    uint8_t **ppRxBuffer,
    uint16_t *pBytesRead
);

/*
*  ISO Append Record
*/
phStatus_t phalMfdf_Sw_IsoAppendRecord(
    phalMfdf_Sw_DataParams_t *pDataParams,
    uint8_t bSfid,
    uint8_t *pData,
    uint8_t bDataLen
);

/*
*  GetChallenge
*/
phStatus_t phalMfdf_Sw_IsoGetChallenge(
    phalMfdf_Sw_DataParams_t *pDataParams,
    uint16_t wKeyNo,
    uint16_t wKeyVer,
    uint8_t bLe,
    uint8_t *pRPICC1
);

/*
*  ISO External Authenticate
*/
phStatus_t phalMfdf_Sw_IsoExternalAuthenticate(
    phalMfdf_Sw_DataParams_t *pDataParams,
    uint8_t *pInput,
    uint8_t bInputLen,
    uint8_t *pDataOut,
    uint8_t *pOutLen
);

/*
*  ISO Internal Authenticate
*/
phStatus_t phalMfdf_Sw_IsoInternalAuthenticate(
    phalMfdf_Sw_DataParams_t *pDataParams,
    uint8_t *pInput,
    uint8_t bInputLen,
    uint8_t *pDataOut,
    uint8_t *pOutLen
);

/*
*  Perform ISO authentication
*/
phStatus_t phalMfdf_Sw_IsoAuthenticate(
    phalMfdf_Sw_DataParams_t *pDataParams,
    uint16_t wKeyNo,
    uint16_t wKeyVer,
    uint8_t bKeyNoCard,
    uint8_t bIsPICCkey
);
/*
* Get config
*/

#endif /* NXPBUILD__PH_NDA_MFDF */

phStatus_t phalMfdf_Sw_GetConfig(
    phalMfdf_Sw_DataParams_t *pDataParams,
    uint16_t wConfig,
    uint16_t *pValue
);

phStatus_t phalMfdf_Sw_SetConfig(
    phalMfdf_Sw_DataParams_t *pDataParams,
    uint16_t wConfig,
    uint16_t wValue
);

#ifdef NXPBUILD__PH_NDA_MFDF
/* Reset Authentication Status */
phStatus_t phalMfdf_Sw_ResetAuthStatus(
    phalMfdf_Sw_DataParams_t *pDataParams
);
#endif /* NXPBUILD__PH_NDA_MFDF */

#endif /* PHALMFDF_SW_H */
