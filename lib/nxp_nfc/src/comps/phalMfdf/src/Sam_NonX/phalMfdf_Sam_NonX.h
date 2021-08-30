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

/*
* \file
* Software MIFARE DESFire Application Component of Reader Library Framework.
* $Author: nxp60813 $
* $Revision: 124 $
* $Date: 2013-04-22 12:10:31 +0530 (Mon, 22 Apr 2013) $
*
* History:
*/

#ifndef PHALMFDF_SAMAV3_NONX_H
#define PHALMFDF_SAMAV3_NONX_H

/* MIFARE DESFire security related commands. ----------------------------------------------------------------------------------------- */
phStatus_t phalMfdf_Sam_NonX_Authenticate(void * pDataParams, uint16_t wOption, uint16_t wKeyNo, uint16_t wKeyVer, uint8_t bKeyNoCard, uint8_t * pDivInput,
	uint8_t bDivInputLen);

phStatus_t phalMfdf_Sam_NonX_AuthenticateISO(void * pDataParams, uint16_t wOption, uint16_t wKeyNo, uint16_t wKeyVer, uint8_t bKeyNoCard, uint8_t * pDivInput,
	uint8_t bDivInputLen);

phStatus_t phalMfdf_Sam_NonX_AuthenticateAES(void * pDataParams, uint16_t wOption, uint16_t wKeyNo, uint16_t wKeyVer, uint8_t bKeyNoCard, uint8_t * pDivInput,
	uint8_t bDivInputLen);

phStatus_t phalMfdf_Sam_NonX_ChangeKeySettings(void * pDataParams, uint8_t bKeySettings);

phStatus_t phalMfdf_Sam_NonX_GetKeySettings(void * pDataParams, uint8_t * pKeySettings);

phStatus_t phalMfdf_Sam_NonX_ChangeKey(void * pDataParams, uint16_t wOption, uint16_t wCurrKeyNo, uint16_t wCurrKeyVer, uint16_t wNewKeyNo, uint16_t wNewKeyVer,
	uint8_t bKeyNoCard, uint8_t * pDivInput, uint8_t bDivInputLen);

phStatus_t phalMfdf_Sam_NonX_GetKeyVersion(void * pDataParams, uint8_t bKeyNo, uint8_t * pKeyVersion);

/* MIFARE DESFire PICC level commands. ----------------------------------------------------------------------------------------------- */
phStatus_t phalMfdf_Sam_NonX_CreateApplication(void * pDataParams, uint8_t bOption, uint8_t * pAid, uint8_t bKeySettings1, uint8_t bKeySettings2,
	uint8_t * pISOFileId, uint8_t * pISODFName, uint8_t bISODFNameLen);

phStatus_t phalMfdf_Sam_NonX_DeleteApplication(void * pDataParams, uint8_t * pAid);

phStatus_t phalMfdf_Sam_NonX_GetApplicationIDs(void * pDataParams, uint8_t * pAidBuff, uint8_t * pNumAIDs);

phStatus_t phalMfdf_Sam_NonX_GetDFNames(void * pDataParams, uint8_t bOption, uint8_t * pDFBuffer, uint8_t * bNumOfEntries);

phStatus_t phalMfdf_Sam_NonX_SelectApplication(void * pDataParams, uint8_t * pAppId);

phStatus_t phalMfdf_Sam_NonX_FormatPICC(void * pDataParams);

phStatus_t phalMfdf_Sam_NonX_GetVersion(void * pDataParams, uint8_t * pVerInfo);

phStatus_t phalMfdf_Sam_NonX_FreeMem(void * pDataParams, uint8_t * pMemInfo);

phStatus_t phalMfdf_Sam_NonX_SetConfiguration(void * pDataParams, uint8_t bOption, uint8_t * pData, uint8_t bDataLen);

phStatus_t phalMfdf_Sam_NonX_GetCardUID(void * pDataParams, uint8_t * pUid);

/* MIFARE DESFire Application level commands. ---------------------------------------------------------------------------------------- */
phStatus_t phalMfdf_Sam_NonX_GetFileIDs(void * pDataParams, uint8_t * pFid, uint8_t * pNumFid);

phStatus_t phalMfdf_Sam_NonX_GetISOFileIDs(void * pDataParams, uint8_t * pFidBuffer, uint8_t * pNumFid);

phStatus_t phalMfdf_Sam_NonX_GetFileSettings(void * pDataParams, uint8_t bFileNo, uint8_t * pFSBuffer, uint8_t * bBufferLen);

phStatus_t phalMfdf_Sam_NonX_ChangeFileSettings(void * pDataParams, uint8_t bOption, uint8_t bFileNo, uint8_t bFileOption, uint8_t * pAccessRights);

phStatus_t phalMfdf_Sam_NonX_CreateStdDataFile(void * pDataParams, uint8_t bOption, uint8_t bFileNo, uint8_t * pISOFileId, uint8_t bFileOption, uint8_t * pAccessRights,
	uint8_t * pFileSize);

phStatus_t phalMfdf_Sam_NonX_CreateBackupDataFile(void * pDataParams, uint8_t bOption, uint8_t bFileNo, uint8_t * pISOFileId, uint8_t bFileOption, uint8_t * pAccessRights,
	uint8_t * pFileSize);

phStatus_t phalMfdf_Sam_NonX_CreateValueFile(void * pDataParams, uint8_t bFileNo, uint8_t bFileOption, uint8_t * pAccessRights, uint8_t * pLowerLmit, uint8_t * pUpperLmit,
	uint8_t * pValue, uint8_t bLimitedCredit);

phStatus_t phalMfdf_Sam_NonX_CreateLinearRecordFile(void * pDataParams, uint8_t bOption, uint8_t  bFileNo, uint8_t * pISOFileId, uint8_t bFileOption, uint8_t * pAccessRights,
	uint8_t * pRecordSize, uint8_t * pMaxNoOfRec);

phStatus_t phalMfdf_Sam_NonX_CreateCyclicRecordFile(void * pDataParams, uint8_t bOption, uint8_t  bFileNo, uint8_t * pISOFileId, uint8_t bFileOption, uint8_t * pAccessRights,
	uint8_t * pRecordSize, uint8_t * pMaxNoOfRec);

phStatus_t phalMfdf_Sam_NonX_DeleteFile(void * pDataParams, uint8_t bFileNo);

/* MIFARE DESFire Data Manipulation commands. ---------------------------------------------------------------------------------------- */
phStatus_t phalMfdf_Sam_NonX_ReadData(void * pDataParams, uint8_t bOption, uint8_t bFileNo, uint8_t * pOffset, uint8_t * pLength, uint8_t ** ppResponse,
	uint16_t * pRespLen);

phStatus_t phalMfdf_Sam_NonX_WriteData(void * pDataParams, uint8_t bOption, uint8_t bFileNo, uint8_t * pOffset, uint8_t * pData, uint8_t * pDataLen);

phStatus_t phalMfdf_Sam_NonX_GetValue(void * pDataParams, uint8_t bCommOption, uint8_t bFileNo, uint8_t * pValue);

phStatus_t phalMfdf_Sam_NonX_Credit(void * pDataParams, uint8_t bCommOption, uint8_t bFileNo, uint8_t * pValue);

phStatus_t phalMfdf_Sam_NonX_Debit(void * pDataParams, uint8_t bCommOption, uint8_t bFileNo, uint8_t * pValue);

phStatus_t phalMfdf_Sam_NonX_LimitedCredit(void * pDataParams, uint8_t bCommOption, uint8_t bFileNo, uint8_t * pValue);

phStatus_t phalMfdf_Sam_NonX_WriteRecord(void * pDataParams, uint8_t bOption, uint8_t bFileNo, uint8_t * pOffset, uint8_t * pData, uint8_t * pDataLen);

phStatus_t phalMfdf_Sam_NonX_ReadRecords(void * pDataParams, uint8_t bOption, uint8_t bFileNo, uint8_t * pRecNo, uint8_t * pRecCount, uint8_t * pRecSize,
	uint8_t ** ppResponse, uint16_t * pRespLen);

phStatus_t phalMfdf_Sam_NonX_ClearRecordFile(void * pDataParams, uint8_t bFileNo);

phStatus_t phalMfdf_Sam_NonX_CommitTransaction(void * pDataParams);

phStatus_t phalMfdf_Sam_NonX_AbortTransaction(void * pDataParams);

/* MIFARE DESFire ISO7816 commands. -------------------------------------------------------------------------------------------------- */
phStatus_t phalMfdf_Sam_NonX_IsoSelectFile(void * pDataParams, uint8_t bOption, uint8_t bSelector, uint8_t * pFid, uint8_t * pDFname, uint8_t bDFnameLen,
	uint8_t ** ppFCI, uint16_t * pFCILen);

phStatus_t phalMfdf_Sam_NonX_IsoReadBinary(void * pDataParams, uint16_t wOption, uint8_t bOffset, uint8_t bSfid, uint8_t bBytesToRead,
	uint8_t ** ppResponse, uint16_t * pBytesRead);

phStatus_t phalMfdf_Sam_NonX_IsoUpdateBinary(void * pDataParams, uint8_t bOffset, uint8_t bSfid, uint8_t * pData, uint32_t dwDataLen);

phStatus_t phalMfdf_Sam_NonX_IsoReadRecords(void * pDataParams, uint16_t wOption, uint8_t bRecNo, uint8_t bReadAllFromP1, uint8_t bSfid, uint8_t bBytesToRead,
	uint8_t ** ppResponse, uint16_t * pBytesRead);

phStatus_t phalMfdf_Sam_NonX_IsoAppendRecord(void * pDataParams, uint8_t bSfid, uint8_t * pData, uint32_t dwDataLen);

phStatus_t phalMfdf_Sam_NonX_IsoGetChallenge(void * pDataParams, uint16_t wKeyNo, uint16_t wKeyVer, uint32_t dwLe, uint8_t * pRPICC1);

phStatus_t phalMfdf_Sam_NonX_IsoExternalAuthenticate(void * pDataParams, uint8_t * pDataIn, uint8_t bInputLen, uint8_t * pDataOut, uint8_t * pOutLen);

phStatus_t phalMfdf_Sam_NonX_IsoInternalAuthenticate(void * pDataParams, uint8_t * pDataIn, uint8_t bInputLen, uint8_t * pDataOut, uint8_t * pOutLen);

phStatus_t phalMfdf_Sam_NonX_IsoAuthenticate(void * pDataParams, uint16_t wKeyNo, uint16_t wKeyVer, uint8_t bKeyNoCard, uint8_t bIsPICCkey);




/* MIFARE DESFire Miscellaneous functions. ------------------------------------------------------------------------------------------- */
phStatus_t phalMfdf_Sam_NonX_GetConfig(void * pDataParams, uint16_t wConfig, uint16_t * pValue);

phStatus_t phalMfdf_Sam_NonX_SetConfig(void * pDataParams, uint16_t wConfig, uint16_t wValue);

phStatus_t phalMfdf_Sam_NonX_ResetAuthStatus(void * pDataParams);

#endif /* PHALMFDF_SAMAV3_NONX_H */
