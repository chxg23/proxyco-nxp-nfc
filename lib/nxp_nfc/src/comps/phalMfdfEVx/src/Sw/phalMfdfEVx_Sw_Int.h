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

#ifndef PHALMFDFEVX_SW_INT_H
#define PHALMFDFEVX_SW_INT_H

phStatus_t phalMfdfEVx_Sw_Int_CardExchange(phalMfdfEVx_Sw_DataParams_t *pDataParams,
    uint16_t wBufferOption, uint16_t wTotDataLen,
    uint8_t bExchangeLE, uint8_t *pData, uint16_t wDataLen, uint8_t **ppResponse, uint16_t *pRespLen,
    uint8_t *pPiccRetCode);

phStatus_t phalMfdfEVx_Sw_Int_SendDataToPICC(phalMfdfEVx_Sw_DataParams_t *pDataParams,
    uint8_t bIns, uint8_t bCommOption,
    uint8_t *pCmd, uint16_t wCmdLen, uint8_t *pData, uint16_t wDataLen, uint8_t *bLastChunk,
    uint16_t wLastChunkLen,
    uint8_t *pResp, uint16_t *pRespLen);

phStatus_t phalMfdfEVx_Sw_Int_SendDataAndAddDataToPICC(phalMfdfEVx_Sw_DataParams_t *pDataParams,
    uint8_t bIns, uint8_t *pCmd,
    uint16_t wCmdLen, uint8_t *pData, uint16_t wDataLen, uint8_t *pAddData, uint16_t wAddDataLen,
    uint8_t *pResp,
    uint16_t *pRespLen);

phStatus_t phalMfdfEVx_Sw_Int_GetData(phalMfdfEVx_Sw_DataParams_t *pDataParams,
    uint8_t *pSendBuff, uint16_t wCmdLen,
    uint8_t **pResponse, uint16_t *pRxlen);

phStatus_t phalMfdfEVx_Sw_Int_ReadData_Plain(phalMfdfEVx_Sw_DataParams_t *pDataParams,
    uint8_t bOption, uint8_t *bCmdBuff,
    uint16_t wCmdLen, uint8_t **ppRxdata, uint16_t *pRxdataLen);

phStatus_t phalMfdfEVx_Sw_Int_Write_Plain(phalMfdfEVx_Sw_DataParams_t *pDataParams, uint8_t bIns,
    uint8_t *bCmdBuff,
    uint16_t wCmdLen, uint8_t bCommOption, uint8_t *pData, uint16_t  wDataLen);

#ifdef NXPBUILD__PHAL_MFDFEVX_NDA
phStatus_t phalMfdfEVx_Sw_Int_ReadData_Enc(phalMfdfEVx_Sw_DataParams_t *UNALIGNED pDataParams,
    uint8_t bPaddingOption,
    uint8_t *bCmdBuff, uint16_t wCmdLen, uint8_t **ppRxdata, uint16_t *pRxdataLen);

phStatus_t phalMfdfEVx_Sw_Int_Write_Enc(phalMfdfEVx_Sw_DataParams_t *pDataParams, uint8_t bIns,
    uint8_t *bCmdBuff,
    uint16_t wCmdLen, uint8_t bPaddingMode, uint8_t bCommOption, uint8_t *pData, uint16_t wDataLen);
#endif /* NXPBUILD__PHAL_MFDFEVX_NDA */

phStatus_t phalMfdfEVx_Sw_Int_Write_New(phalMfdfEVx_Sw_DataParams_t *pDataParams,
    uint8_t bCommOption, uint8_t *pCmdBuff,
    uint16_t wCmdLen, uint8_t *pData, uint16_t wDataLen);

void phalMfdfEVx_Sw_Int_ResetAuthStatus(phalMfdfEVx_Sw_DataParams_t *pDataParams);

phStatus_t phalMfdfEVx_Sw_Int_IsoRead(phalMfdfEVx_Sw_DataParams_t *pDataParams, uint16_t wOption,
    uint8_t *bCmdBuff,
    uint16_t wCmdLen, uint8_t **ppRxBuffer, uint32_t *pBytesRead);

#ifdef NXPBUILD__PHAL_MFDFEVX_NDA
void phalMfdfEVx_Sw_Int_TruncateMac(uint8_t *pMac);

phStatus_t phalMfdfEVx_Sw_Int_ComputeIv(uint8_t bIsResponse, uint8_t *pTi, uint16_t wCmdCtr,
    uint8_t *pIv);
#endif /* NXPBUILD__PHAL_MFDFEVX_NDA */

phStatus_t phalMfdfEVx_Sw_Int_GetFrameLength(phalMfdfEVx_Sw_DataParams_t *pDataParams,
    uint16_t *pFSD, uint16_t *pFSC);

phStatus_t phalMfdfEVx_Sw_Int_ISOGetData(phalMfdfEVx_Sw_DataParams_t *pDataParams,
    uint8_t *pSendBuff, uint16_t wCmdLen,
    uint8_t **pResponse, uint16_t *pRxlen);

#ifdef NXPBUILD__PHAL_MFDFEVX_NDA
phStatus_t phalMfdfEVx_Sw_Int_DecryptSDMData(phalMfdfEVx_Sw_DataParams_t *pDataParams,
    uint8_t *pSessEncKey, uint8_t *pIv,
    uint8_t *pInputOutputData, uint16_t wInputDataLen);

phStatus_t phalMfdfEVx_Sw_Int_ComputeSDMSessionVectors(phalMfdfEVx_Sw_DataParams_t *pDataParams,
    uint8_t bOption,
    uint8_t bSdmOption, uint16_t wSrcKeyNo, uint16_t wSrcKeyVer, uint8_t *pUid, uint8_t bUidLen,
    uint8_t *pSDMReadCtr,
    uint8_t *pSessionKey);

phStatus_t phalMfdfEVx_Sw_Int_GenerateSDMSessionKeysAES(phalMfdfEVx_Sw_DataParams_t *pDataParams,
    uint8_t bSdmOption,
    uint16_t wKeyNo, uint16_t wKeyVer, uint8_t *pSDMReadCtr, uint8_t *pVCUID, uint8_t bUidLen,
    uint8_t *pSessEncKey,
    uint8_t *pSessMacKey);

phStatus_t phalMfdfEVx_Sw_Int_ComputeSDMIV(phalMfdfEVx_Sw_DataParams_t *pDataParams,
    uint8_t *pSessEncKey,
    uint8_t *pSDMReadCtr, uint8_t *pIV);
#endif /* NXPBUILD__PHAL_MFDFEVX_NDA */

#endif /* PHALMFDFEVX_SW_INT_H */
