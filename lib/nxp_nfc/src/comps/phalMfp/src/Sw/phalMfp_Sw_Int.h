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
* Internal functions of Software implementation of MIFARE Plus contactless IC application layer.
* $Author$
* $Revision$ (v06.10.00)
* $Date$
*
* History:
*  CHu: Generated 19. May 2009
*
*/

#ifndef PHALMFP_SW_INT_H
#define PHALMFP_SW_INT_H

#include <nxp_nfc/ph_Status.h>
#include <nxp_nfc/phalMfp.h>

/** \addtogroup ph_Private
* @{
*/

#define PHAL_MFP_TAPEOUT_VERSION            30U

#define PHAL_MFP_ORIGINALITY_KEY_0          0x8000U
#define PHAL_MFP_ORIGINALITY_KEY_1          0x8001U
#define PHAL_MFP_ORIGINALITY_KEY_2          0x8002U
#define PHAL_MFP_ORIGINALITY_KEY_FIRST      PHAL_MFP_ORIGINALITY_KEY_0
#define PHAL_MFP_ORIGINALITY_KEY_LAST       PHAL_MFP_ORIGINALITY_KEY_2

#ifdef NXPBUILD__PH_NDA_MFP
/**
* \brief Perform a complete MIFARE Plus Authentication for either Security Level.
*
* Refer to the respective Authentication function for description.
* \see phalMfp_AuthenticateSL0
* \see phalMfp_AuthenticateSL1
* \see phalMfp_AuthenticateSL2
* \see phalMfp_AuthenticateSL3
* \return Status code
* \retval #PH_ERR_SUCCESS Operation successful.
* \retval Other Depending on implementation and underlying component.
*/
phStatus_t phalMfp_Sw_AuthenticateGeneral(
    phalMfp_Sw_DataParams_t *pDataParams,   /**< [In] Pointer to this layer's parameter structure. */
    uint8_t bLayer4Comm,                    /**< [In] \c 0: use ISO14443-3 protocol; \c 1: use ISO14443-4 protocol; */
    uint8_t bFirstAuth,                     /**< [In] \c 0: Following Authentication; \c 1: First Authentication; */
    uint16_t wBlockNr,                      /**< [In] Key Block number. */
    uint16_t wKeyNumber,                    /**< [In] Key Storage number. */
    uint16_t wKeyVersion,                   /**< [In] Key Storage version. */
    uint8_t bLenDivInput,                   /**< [In] Length of diversification input used to diversify the key. If 0, no diversification is performed. */
    uint8_t *pDivInput,                      /**< [In] Diversification Input used to diversify the key. */
    uint8_t bUseKdfSl2,                     /**< [In] Indicates if a Key derivation for SL2 should be performed. */
    uint8_t bLenPcdCap2,                    /**< [In] Lengh of the supplied PCDCaps. */
    uint8_t *pPcdCap2In,                    /**< [In] Pointer to PCDCaps (bLenPcdCap2 bytes), ignored if bLenPcdCap2 == 0. */
    uint8_t *pPcdCap2Out,                    /**< [In] Pointer to PCDCaps sent from the card (6 bytes). */
    uint8_t *pPdCap2                        /**< [Out] Pointer to PDCaps sent from the card (6 bytes). */
);

/**
* \brief Perform a Write command in all it's flavours.
*
* Refer to the respective Write function for description.
* \see phalMfp_Write
* \see phalMfp_Increment
* \see phalMfp_Decrement
* \see phalMfp_IncrementTransfer
* \see phalMfp_DecrementTransfer
* \see phalMfp_Transfer
* \see phalMfp_Restore
* \return Status code
* \retval #PH_ERR_SUCCESS Operation successful.
* \retval Other Depending on implementation and underlying component.
*/
phStatus_t phalMfp_Sw_WriteExt(
    phalMfp_Sw_DataParams_t *pDataParams,    /**< [In] Pointer to this layer's parameter structure. */
    uint8_t bCmdCode,                        /**< [In] MIFARE Plus Command Code. */
    uint16_t wSrcBnr,                        /**< [In] Source Block number. */
    uint16_t wDstBnr,                        /**< [In] Destination Block number. */
    uint8_t *pData,                          /**< [In] Payload data. */
    uint16_t wDataLength,                    /**< [In] Length of payload data. */
    uint8_t bEncrypted                       /**< [In] indicates whether the data should be encrypted or not. */
);

/**
* \brief Calculate the Init-Vector for encryption from input data.
* \return Status code
* \retval #PH_ERR_SUCCESS Operation successful.
*/
phStatus_t phalMfp_Sw_Int_ComputeIv(
    uint8_t bIsResponse,    /**< [In] Whether this is a response or command or not. */
    uint8_t *pTi,           /**< [In] Transaction Identifier; uint8_t[4]. */
    uint16_t wRCtr,         /**< [In] R_CTR (read counter). */
    uint16_t wWCtr,         /**< [In] W_CTR (write counter). */
    uint8_t *pIv            /**< [Out] Initvector; uint8_t[16]. */
);

/**
* \brief Perform a SL2 Key Derivation Function
*
* This function derives the MIFARE product Sector Key.
* \return Status code
* \retval #PH_ERR_SUCCESS Operation successful.
* \retval Other Depending on implementation and underlying component.
*/
phStatus_t phalMfp_Sw_Int_KdfSl2(
    phalMfp_Sw_DataParams_t
    *pDataParams,      /**< [In] Pointer to this layer's parameter structure. */
    uint8_t *pRndA,                            /**< [In] Pointer to RndA Buffer. */
    uint8_t *pRndB                             /**< [In] Pointer to RndB Buffer. */
);

/**
* \brief Perform a SL3 Key Derivation Function
*
* This function derives the MIFARE product Sector Key.
* \return Status code
* \retval #PH_ERR_SUCCESS Operation successful.
* \retval Other Depending on implementation and underlying component.
*/
phStatus_t phalMfp_Sw_Int_KdfSl3(
    phalMfp_Sw_DataParams_t
    *pDataParams,      /**< [In] Pointer to this layer's parameter structure. */
    uint8_t *pRndA,                            /**< [In] Pointer to RndA Buffer. */
    uint8_t *pRndB                             /**< [In] Pointer to RndB Buffer. */
);

/**
* \brief Perform MIFARE Plus specific MAC truncation.
*/
void phalMfp_Sw_Int_TruncateMac(
    uint8_t *pMac,              /**< [In] MAC; uint8_t[16]. */
    uint8_t *pTruncatedMac      /**< [Out] Truncated MAC; uint8_t[8]. */
);
#endif /* NXPBUILD__PH_NDA_MFP */

/** @}
* end of ph_Private group
*/

#endif /* PHALMFP_SW_INT_H */
