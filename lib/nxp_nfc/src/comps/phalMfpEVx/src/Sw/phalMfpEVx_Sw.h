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
* $Revision: 5464 $ (v06.10.00)
* $Date: 2019-01-10 19:08:57 +0530 (Thu, 10 Jan 2019) $
*
* History:
*  Kumar GVS: Generated 15. Apr 2013
*
*/

#ifndef PHALMFPEVX_SW_H
#define PHALMFPEVX_SW_H

#include <nxp_nfc/ph_Status.h>

phStatus_t phalMfpEVx_Sw_WritePerso(phalMfpEVx_Sw_DataParams_t *pDataParams, uint8_t bLayer4Comm,
    uint16_t wBlockNr, uint8_t bNumBlocks,
    uint8_t *pValue);

phStatus_t phalMfpEVx_Sw_CommitPerso(phalMfpEVx_Sw_DataParams_t *pDataParams, uint8_t bOption,
    uint8_t bLayer4Comm);

phStatus_t phalMfpEVx_Sw_AuthenticateMfc(phalMfpEVx_Sw_DataParams_t *pDataParams,
    uint8_t bBlockNo, uint8_t bKeyType, uint16_t wKeyNumber,
    uint16_t wKeyVersion, uint8_t *pUid, uint8_t bUidLength);

#ifdef NXPBUILD__PHAL_MFPEVX_NDA
phStatus_t phalMfpEVx_Sw_AuthenticateSL0(phalMfpEVx_Sw_DataParams_t *pDataParams,
    uint8_t bLayer4Comm, uint8_t bFirstAuth, uint16_t wBlockNr,
    uint16_t wKeyNumber, uint16_t wKeyVersion, uint8_t bLenDivInput, uint8_t *pDivInput,
    uint8_t bLenPcdCap2, uint8_t *pPcdCap2In,
    uint8_t *pPcdCap2Out, uint8_t *pPdCap2);

phStatus_t phalMfpEVx_Sw_AuthenticateSL1(phalMfpEVx_Sw_DataParams_t *pDataParams,
    uint8_t bLayer4Comm, uint8_t bFirstAuth, uint16_t wBlockNr,
    uint16_t wKeyNumber, uint16_t wKeyVersion, uint8_t bLenDivInput, uint8_t *pDivInput,
    uint8_t bLenPcdCap2, uint8_t *pPcdCap2In,
    uint8_t *pPcdCap2Out, uint8_t *pPdCap2);

phStatus_t phalMfpEVx_Sw_AuthenticateSL3(phalMfpEVx_Sw_DataParams_t *pDataParams,
    uint8_t bFirstAuth, uint16_t wBlockNr, uint16_t wKeyNumber,
    uint16_t wKeyVersion, uint8_t bLenDivInput, uint8_t *pDivInput, uint8_t bLenPcdCap2,
    uint8_t *pPcdCap2In, uint8_t *pPcdCap2Out,
    uint8_t *pPdCap2);

phStatus_t phalMfpEVx_Sw_SSAuthenticate(phalMfpEVx_Sw_DataParams_t *pDataParams,
    uint16_t wSSKeyBNr, uint16_t wSSKeyNr, uint16_t wSSKeyVer,
    uint8_t bLenDivInputSSKey, uint8_t *pDivInputSSKey, uint8_t  bSecCount, uint16_t *pSectorNos,
    uint16_t *pKeyBKeyNos, uint16_t *pKeyBKeyVers,
    uint8_t bLenDivInputSectorKeyBs, uint8_t *pDivInputSectorKeyBs);

phStatus_t phalMfpEVx_Sw_AuthenticatePDC(phalMfpEVx_Sw_DataParams_t *pDataParams,
    uint16_t wBlockNr, uint16_t wKeyNumber, uint16_t wKeyVersion,
    uint8_t bLenDivInput, uint8_t *pDivInput, uint8_t bUpgradeInfo);

phStatus_t phalMfpEVx_Sw_Write(phalMfpEVx_Sw_DataParams_t *pDataParams, uint8_t bEncrypted,
    uint8_t bWriteMaced, uint16_t wBlockNr,
    uint8_t bNumBlocks, uint8_t *pBlocks, uint8_t *pTMC, uint8_t *pTMV);

phStatus_t phalMfpEVx_Sw_Read(phalMfpEVx_Sw_DataParams_t *pDataParams, uint8_t bEncrypted,
    uint8_t bReadMaced, uint8_t bMacOnCmd,
    uint16_t wBlockNr, uint8_t bNumBlocks, uint8_t *pBlocks);

phStatus_t phalMfpEVx_Sw_WriteValue(phalMfpEVx_Sw_DataParams_t *pDataParams, uint8_t bEncrypted,
    uint8_t bWriteMaced, uint16_t wBlockNr,
    uint8_t *pValue, uint8_t bAddrData, uint8_t *pTMC, uint8_t *pTMV);

phStatus_t phalMfpEVx_Sw_ReadValue(phalMfpEVx_Sw_DataParams_t *pDataParams, uint8_t bEncrypted,
    uint8_t bReadMaced, uint8_t bMacOnCmd,
    uint16_t wBlockNr, uint8_t *pValue, uint8_t *pAddrData);

phStatus_t phalMfpEVx_Sw_Increment(phalMfpEVx_Sw_DataParams_t *pDataParams,
    uint8_t bIncrementMaced, uint16_t wBlockNr, uint8_t *pValue);

phStatus_t phalMfpEVx_Sw_Decrement(phalMfpEVx_Sw_DataParams_t *pDataParams,
    uint8_t bDecrementMaced, uint16_t wBlockNr, uint8_t *pValue);

phStatus_t phalMfpEVx_Sw_IncrementTransfer(phalMfpEVx_Sw_DataParams_t *pDataParams,
    uint8_t bIncrementTransferMaced, uint16_t wSourceBlockNr,
    uint16_t wDestinationBlockNr, uint8_t *pValue, uint8_t *pTMC, uint8_t *pTMV);

phStatus_t phalMfpEVx_Sw_DecrementTransfer(phalMfpEVx_Sw_DataParams_t *pDataParams,
    uint8_t bDecrementTransferMaced, uint16_t wSourceBlockNr,
    uint16_t wDestinationBlockNr, uint8_t *pValue, uint8_t *pTMC, uint8_t *pTMV);

phStatus_t phalMfpEVx_Sw_Transfer(phalMfpEVx_Sw_DataParams_t *pDataParams, uint8_t bTransferMaced,
    uint16_t wBlockNr, uint8_t *pTMC,
    uint8_t *pTMV);

phStatus_t phalMfpEVx_Sw_Restore(phalMfpEVx_Sw_DataParams_t *pDataParams, uint8_t bRestoreMaced,
    uint16_t wBlockNr);
#endif /* NXPBUILD__PHAL_MFPEVX_NDA */

phStatus_t phalMfpEVx_Sw_GetVersion(phalMfpEVx_Sw_DataParams_t *pDataParams, uint8_t *pResponse);

phStatus_t phalMfpEVx_Sw_ReadSign(phalMfpEVx_Sw_DataParams_t *pDataParams, uint8_t bLayer4Comm,
    uint8_t bAddr, uint8_t **pSignature);

phStatus_t phalMfpEVx_Sw_ResetAuth(phalMfpEVx_Sw_DataParams_t *pDataParams);

phStatus_t phalMfpEVx_Sw_PersonalizeUid(phalMfpEVx_Sw_DataParams_t *pDataParams,
    uint8_t bUidType);

phStatus_t phalMfpEVx_Sw_SetConfigSL1(phalMfpEVx_Sw_DataParams_t *pDataParams, uint8_t bOption);

phStatus_t phalMfpEVx_Sw_ReadSL1TMBlock(phalMfpEVx_Sw_DataParams_t *pDataParams,
    uint16_t wBlockNr, uint8_t *pBlocks);

phStatus_t phalMfpEVx_Sw_VCSupportLastISOL3(phalMfpEVx_Sw_DataParams_t *pDataParams,
    uint8_t *pIid, uint8_t *pPcdCapL3,
    uint8_t *pInfo);

#ifdef NXPBUILD__PHAL_MFPEVX_NDA
phStatus_t phalMfpEVx_Sw_CommitReaderID(phalMfpEVx_Sw_DataParams_t *pDataParams,
    uint16_t wBlockNr, uint8_t *pTMRI, uint8_t *pEncTMRI);

phStatus_t phalMfpEVx_Sw_ChangeKey(phalMfpEVx_Sw_DataParams_t *pDataParams,
    uint8_t bChangeKeyMaced, uint16_t wBlockNr, uint16_t wKeyNumber,
    uint16_t wKeyVersion, uint8_t bLenDivInput, uint8_t *pDivInput);
#endif /* NXPBUILD__PHAL_MFPEVX_NDA */

phStatus_t phalMfpEVx_Sw_ResetSecMsgState(phalMfpEVx_Sw_DataParams_t *pDataParams);

phStatus_t phalMfpEVx_Sw_SetConfig(phalMfpEVx_Sw_DataParams_t *pDataParams, uint16_t wOption,
    uint16_t wValue);

phStatus_t phalMfpEVx_Sw_GetConfig(phalMfpEVx_Sw_DataParams_t *pDataParams, uint16_t wOption,
    uint16_t *pValue);

phStatus_t phalMfpEVx_Sw_SetVCAParams(phalMfpEVx_Sw_DataParams_t *pDataParams,
    void *pAlVCADataParams);

#ifdef NXPBUILD__PHAL_MFPEVX_NDA
phStatus_t phalMfpEVx_Sw_CalculateTMV(phalMfpEVx_Sw_DataParams_t *pDataParams, uint16_t wOption,
    uint16_t wKeyNoTMACKey, uint16_t wKeyVerTMACKey,
    uint8_t *pDivInput, uint8_t bDivInputLen, uint8_t *pTMC, uint8_t *pUid, uint8_t bUidLen,
    uint8_t  *pTMI, uint16_t wTMILen, uint8_t *pTMV);

phStatus_t phalMfpEVx_Sw_DecryptReaderID(phalMfpEVx_Sw_DataParams_t *pDataParams,
    uint16_t wOption, uint16_t wKeyNoTMACKey, uint16_t wKeyVerTMACKey,
    uint8_t *pDivInput, uint8_t bDivInputLen, uint8_t *pTMC, uint8_t *pUid, uint8_t bUidLen,
    uint8_t  *pEncTMRI, uint8_t *pTMRIPrev);

#endif /* NXPBUILD__PHAL_MFPEVX_NDA */

#endif /* PHALMFPEVX_SW_H */
