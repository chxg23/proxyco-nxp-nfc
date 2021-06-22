/*----------------------------------------------------------------------------*/
/* Copyright 2009-2020 NXP                                                    */
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
* Software MIFARE Plus contactless IC Application Component of Reader Library Framework.
* $Author$
* $Revision$ (v06.11.00)
* $Date$
*
* History:
*  CHu: Generated 31. August 2009
*
*/

#ifndef PHALMFP_SW_H
#define PHALMFP_SW_H

#include <nxp_nfc/ph_Status.h>

phStatus_t phalMfp_Sw_WritePerso(
    phalMfp_Sw_DataParams_t *pDataParams,
    uint8_t bLayer4Comm,
    uint16_t wBlockNr,
    uint8_t *pValue
);

phStatus_t phalMfp_Sw_CommitPerso(
    phalMfp_Sw_DataParams_t *pDataParams,
    uint8_t bLayer4Comm
);

#ifdef NXPBUILD__PH_NDA_MFP
phStatus_t phalMfp_Sw_AuthenticateSL0(
    phalMfp_Sw_DataParams_t *pDataParams,
    uint8_t bLayer4Comm,
    uint8_t bFirstAuth,
    uint16_t wBlockNr,
    uint16_t wKeyNumber,
    uint16_t wKeyVersion,
    uint8_t bLenDivInput,
    uint8_t *pDivInput,
    uint8_t bLenPcdCap2,
    uint8_t *pPcdCap2In,
    uint8_t *pPcdCap2Out,
    uint8_t *pPdCap2
);

phStatus_t phalMfp_Sw_AuthenticateSL1(
    phalMfp_Sw_DataParams_t *pDataParams,
    uint8_t bLayer4Comm,
    uint8_t bFirstAuth,
    uint16_t wBlockNr,
    uint16_t wKeyNumber,
    uint16_t wKeyVersion,
    uint8_t bLenDivInput,
    uint8_t *pDivInput,
    uint8_t bLenPcdCap2,
    uint8_t *pPcdCap2In,
    uint8_t *pPcdCap2Out,
    uint8_t *pPdCap2
);

phStatus_t phalMfp_Sw_AuthenticateSL2(
    phalMfp_Sw_DataParams_t *pDataParams,
    uint8_t bLayer4Comm,
    uint8_t bFirstAuth,
    uint16_t wBlockNr,
    uint16_t wKeyNumber,
    uint16_t wKeyVersion,
    uint8_t bLenDivInput,
    uint8_t *pDivInput,
    uint8_t bLenPcdCap2,
    uint8_t *pPcdCap2In,
    uint8_t *pPcdCap2Out,
    uint8_t *pPdCap2,
    uint8_t *pKmf
);
#endif /* NXPBUILD__PH_NDA_MFP */

phStatus_t phalMfp_Sw_AuthenticateClassicSL2(
    phalMfp_Sw_DataParams_t *pDataParams,
    uint8_t bBlockNo,
    uint8_t bKeyType,
    uint16_t wKeyNo,
    uint16_t wKeyVersion,
    uint8_t *pUid,
    uint8_t bUidLength
);

phStatus_t phalMfp_Sw_MultiBlockRead(
    phalMfp_Sw_DataParams_t *pDataParams,
    uint8_t bBlockNr,
    uint8_t bNumBlocks,
    uint8_t *pBlocks
);

phStatus_t phalMfp_Sw_MultiBlockWrite(
    phalMfp_Sw_DataParams_t *pDataParams,
    uint8_t bBlockNr,
    uint8_t bNumBlocks,
    uint8_t *pBlocks
);
#ifdef NXPBUILD__PH_NDA_MFP
phStatus_t phalMfp_Sw_Write(
    phalMfp_Sw_DataParams_t *pDataParams,
    uint8_t bEncrypted,
    uint8_t bWriteMaced,
    uint16_t wBlockNr,
    uint8_t bNumBlocks,
    uint8_t *pBlocks
);

phStatus_t phalMfp_Sw_WriteValue(
    phalMfp_Sw_DataParams_t *pDataParams,
    uint8_t bEncrypted,
    uint8_t bWriteMaced,
    uint16_t wBlockNr,
    uint8_t *pValue,
    uint8_t bAddrData
);

phStatus_t phalMfp_Sw_ChangeKey(
    phalMfp_Sw_DataParams_t *pDataParams,
    uint8_t bChangeKeyMaced,
    uint16_t wBlockNr,
    uint16_t wKeyNumber,
    uint16_t wKeyVersion,
    uint8_t bLenDivInput,
    uint8_t *pDivInput
);

phStatus_t phalMfp_Sw_AuthenticateSL3(
    phalMfp_Sw_DataParams_t *pDataParams,
    uint8_t bFirstAuth,
    uint16_t wBlockNr,
    uint16_t wKeyNumber,
    uint16_t wKeyVersion,
    uint8_t bLenDivInput,
    uint8_t *pDivInput,
    uint8_t bLenPcdCap2,
    uint8_t *pPcdCap2In,
    uint8_t *pPcdCap2Out,
    uint8_t *pPdCap2
);

phStatus_t phalMfp_Sw_Read(
    phalMfp_Sw_DataParams_t *pDataParams,
    uint8_t bEncrypted,
    uint8_t bReadMaced,
    uint8_t bMacOnCmd,
    uint16_t wBlockNr,
    uint8_t bNumBlocks,
    uint8_t *pBlocks
);

phStatus_t phalMfp_Sw_ReadValue(
    phalMfp_Sw_DataParams_t *pDataParams,
    uint8_t bEncrypted,
    uint8_t bReadMaced,
    uint8_t bMacOnCmd,
    uint16_t wBlockNr,
    uint8_t *pValue,
    uint8_t *pAddrData
);
#endif /* NXPBUILD__PH_NDA_MFP */

phStatus_t phalMfp_Sw_ResetAuth(
    phalMfp_Sw_DataParams_t *pDataParams
);

#ifdef NXPBUILD__PH_NDA_MFP
phStatus_t phalMfp_Sw_Increment(
    phalMfp_Sw_DataParams_t *pDataParams,
    uint8_t bIncrementMaced,
    uint16_t wBlockNr,
    uint8_t *pValue
);

phStatus_t phalMfp_Sw_Decrement(
    phalMfp_Sw_DataParams_t *pDataParams,
    uint8_t bDecrementMaced,
    uint16_t wBlockNr,
    uint8_t *pValue
);

phStatus_t phalMfp_Sw_IncrementTransfer(
    phalMfp_Sw_DataParams_t *pDataParams,
    uint8_t bIncrementTransferMaced,
    uint16_t wSourceBlockNr,
    uint16_t wDestinationBlockNr,
    uint8_t *pValue
);

phStatus_t phalMfp_Sw_DecrementTransfer(
    phalMfp_Sw_DataParams_t *pDataParams,
    uint8_t bDecrementTransferMaced,
    uint16_t wSourceBlockNr,
    uint16_t wDestinationBlockNr,
    uint8_t *pValue
);

phStatus_t phalMfp_Sw_Transfer(
    phalMfp_Sw_DataParams_t *pDataParams,
    uint8_t bTransferMaced,
    uint16_t wBlockNr
);

phStatus_t phalMfp_Sw_Restore(
    phalMfp_Sw_DataParams_t *pDataParams,
    uint8_t bRestoreMaced,
    uint16_t wBlockNr
);

phStatus_t phalMfp_Sw_ProximityCheck(
    phalMfp_Sw_DataParams_t *pDataParams,
    uint8_t bGenerateRndC,
    uint8_t *pRndC,
    uint8_t bPps1,
    uint8_t bNumSteps,
    uint8_t *pUsedRndRC
);
#endif /* NXPBUILD__PH_NDA_MFP */

phStatus_t phalMfp_Sw_ResetSecMsgState(
    phalMfp_Sw_DataParams_t *pDataParams
);

#ifdef NXPBUILD__PH_NDA_MFP
phStatus_t phalMfp_Sw_Cmd_PrepareProximityCheck(
    phalMfp_Sw_DataParams_t *pDataParams
);

phStatus_t phalMfp_Sw_Cmd_ProximityCheck(
    phalMfp_Sw_DataParams_t *pDataParams,
    uint8_t bGenerateRndC,
    uint8_t *pRndC,
    uint8_t bNumSteps,
    uint8_t *pUsedRndRC
);

phStatus_t phalMfp_Sw_Cmd_VerifyProximityCheck(
    phalMfp_Sw_DataParams_t *pDataParams,
    uint8_t *pRndRC,
    uint8_t bPps1
);
#endif /* NXPBUILD__PH_NDA_MFP */

#endif /* PHALMFP_SW_H */
