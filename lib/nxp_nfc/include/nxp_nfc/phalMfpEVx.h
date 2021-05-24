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
* Generic MIFARE Plus EVx contactless IC (Ev1, and future versions) contactless IC Application Component of Reader Library Framework.
* $Author: Rajendran Kumar (nxp99556) $
* $Revision: 6140 $ (v06.10.00)
* $Date: 2020-05-26 17:37:50 +0530 (Tue, 26 May 2020) $
*
* History:
*  Kumar GVS: Generated 15. Apr 2013
*
*/

#ifndef PHALMFPEVX_H
#define PHALMFPEVX_H

#include <nxp_nfc/ph_Status.h>
#include <nxp_nfc/phTMIUtils.h>
#include <nxp_nfc/phhalHw.h>
#include <nxp_nfc/phpalMifare.h>

#ifdef __cplusplus
extern "C" {
#endif  /* __cplusplus */

/* Macro to represent the AES block numbers. This macros are for internal use. */
#define PHAL_MFPEVX_ORIGINALITY_KEY_0                               0x8000U /**< Block numbers for Originality Key 0. */
#define PHAL_MFPEVX_ORIGINALITY_KEY_1                               0x8001U /**< Block numbers for Originality Key 1. */
#define PHAL_MFPEVX_ORIGINALITY_KEY_2                               0x8002U /**< Block numbers for Originality Key 2. */
#define PHAL_MFPEVX_ORIGINALITY_KEY_3                               0x8003U /**< Block numbers for Originality Key 3. */
#define PHAL_MFPEVX_L3SWITCHKEY                                     0x9003U /**< Block numbers for Level 3 switch key (SL3 switching) . */
#define PHAL_MFPEVX_SL1CARDAUTHKEY                                  0x9004U /**< Block numbers for SL1 card authentication key. */
#define PHAL_MFPEVX_L3SECTORSWITCHKEY                               0x9006U /**< Block numbers for L3 sector switch key (switching the sector). */
#define PHAL_MFPEVX_L1L3MIXSECTORSWITCHKEY                          0x9007U /**< Block numbers for L1L3 sector switch key (switching the sector to L1L3MIX). */
#define PHAL_MFPEVX_ORIGINALITY_KEY_FIRST   PHAL_MFPEVX_ORIGINALITY_KEY_0   /**< Macro to represent the first block number of originality key. */
#define PHAL_MFPEVX_ORIGINALITY_KEY_LAST    PHAL_MFPEVX_ORIGINALITY_KEY_3   /**< Macro to represent the last block number of originality key. */

#ifdef NXPBUILD__PHAL_MFPEVX_SW
/***************************************************************************************************************************************/
/* Software Dataparams and Initialization Interface.                                                                                   */
/***************************************************************************************************************************************/

#define PHAL_MFPEVX_SW_ID                                           0x01U   /**< ID for Software layer implementation of MIFARE Plus EVx product. */

/* Macro to represent the buffer length. This macros are for internal use. */
#define PHAL_MFPEVX_SIZE_TI                                             4U  /**< Size of Transaction Identifier. */
#define PHAL_MFPEVX_SIZE_TMC                                            4U  /**< Size of the transaction MAC counter */
#define PHAL_MFPEVX_SIZE_TMV                                            8U  /**< Size of the transaction MAC vale */
#define PHAL_MFPEVX_SIZE_IV                                             16U /**< Size of Initialization vector. */
#define PHAL_MFPEVX_SIZE_TMRI                                           16U /**< Size of TMRI */
#define PHAL_MFPEVX_SIZE_ENCTMRI                                        16U /**< Size of encrypted transaction MAC reader ID */
#define PHAL_MFPEVX_SIZE_KEYMODIFIER                                    6U  /**< Size of MIFARE KeyModifier. */
#define PHAL_MFPEVX_SIZE_MAC                                            16U /**< Size of (untruncated) MAC. */

#define PHAL_MFPEVX_VERSION_COMMAND_LENGTH                              41U /**< Version command buffer size. Size = Status(1) + R_Ctr(2) + TI(4) + VersionA(7) + VersionB(7) + VersionC(20) */
#define PHAL_MFPEVX_VERSION_INFO_LENGTH                                 33U /**< Version buffer size to store the complete information. Size = VersionA(7) + VersionB(7) + VersionC(20) */
#define PHAL_MFPEVX_VERSION_PART1_LENGTH                                07U /**< Version part 1 length in the received response. */
#define PHAL_MFPEVX_VERSION_PART2_LENGTH                                07U /**< Version part 2 length in the received response. */

#define PHAL_MFPEVX_VERSION_PART3_LENGTH_04B                            13U /**< Version part 3 length in the received response in case of 4 byte UID. */
#define PHAL_MFPEVX_VERSION_PART3_LENGTH_07B                            14U /**< Version part 3 length in the received response in case of 7 byte UID. */
#define PHAL_MFPEVX_VERSION_PART3_LENGTH_10B                            19U /**< Version part 3 length in the received response in case of 10 byte UID. */

/** \defgroup phalMfpEVx_Sw Component : Software
 * @{
 */

/** \brief MIFARE Plus EVx Software parameter structure. */
typedef struct {
  uint16_t wId;                                                           /**< Layer ID for this component, NEVER MODIFY! */
  void *pPalMifareDataParams;                                             /**< Pointer to the parameter structure of the palMifare component. */
  void *pKeyStoreDataParams;                                              /**< Pointer to the parameter structure of the KeyStore layer. */
  void *pCryptoDataParamsEnc;                                             /**< Pointer to the parameter structure of the Crypto layer for encryption. */
  void *pCryptoDataParamsMac;                                             /**< Pointer to the parameter structure of the Crypto layer for macing. */
  void *pCryptoRngDataParams;                                             /**< Pointer to the parameter structure of the CryptoRng layer. */
  void *pCryptoDiversifyDataParams;                                       /**< Pointer to the parameter structure of the CryptoDiversify layer (can be NULL). */
  void *pTMIDataParams;                                                   /**< Pointer to the parameter structure for collecting TMI. */
  void *pVCADataParams;                                                   /**< Pointer to the parameter structure for Virtual Card. */
  uint16_t wRCtr;                                                         /**< R_CTR (read counter); The PICC's read counter is used for a following authentication. */
  uint16_t wWCtr;                                                         /**< W_CTR (write counter); The PICC's write counter is used for a following authentication. */
  uint8_t bWrappedMode;                                                   /**< Wrapped APDU mode. All native commands need to be sent wrapped in ISO 7816 APDUs. */
  uint8_t bExtendedLenApdu;                                               /**< Extended length APDU. If set the native commands should be wrapped in extended format */
  uint8_t bTi[PHAL_MFPEVX_SIZE_TI];                                       /**< Transaction Identifier; unused if 'bFirstAuth' = 1; uint8_t[4]. */
  uint8_t bNumUnprocessedReadMacBytes;                                    /**< Amount of data in the pUnprocessedReadMacBuffer. */
  uint8_t pUnprocessedReadMacBuffer[PHAL_MFPEVX_SIZE_MAC];                /**< Buffer containing unprocessed bytes for read mac answer stream. */
  uint8_t pIntermediateMac[PHAL_MFPEVX_SIZE_MAC];                         /**< Intermediate MAC for Read Calculation. */
  uint8_t bFirstRead;                                                     /**< Indicates whether the next read is a first read in a read (MACed) sequence or not. */
  uint8_t bIv[16];                                                        /**< Initialization vector. Max size of IV can be 16 bytes */
  uint8_t bSesAuthENCKey[16];                                             /**< Authentication ENC key for the session. */
  uint8_t bSesAuthMACKey[16];                                             /**< Authentication MAC key for the session. */
  uint8_t bAuthMode;                                                      /**< Security level authenticate */
  uint8_t bSMMode;                                                        /**< Secure messaging mode. \c 0: EV0 Mode; \c 1: EVx mode */
} phalMfpEVx_Sw_DataParams_t;

/**
 * \brief Initializes the AL component as software component.
 *
 * \return Status code
 * \retval #PH_ERR_SUCCESS Operation successful.
 * \retval Other Depending on implementation and underlaying component.
 */
phStatus_t phalMfpEVx_Sw_Init(
    phalMfpEVx_Sw_DataParams_t
    *pDataParams,                            /**< [In] Pointer to this layer's parameter structure. */
    uint16_t wSizeOfDataParams,                                         /**< [In] Specifies the size of the data parameter structure. */
    void *pPalMifareDataParams,                                         /**< [In] Pointer to a palMifare data parameter structure. */
    void *pKeyStoreDataParams,                                          /**< [In] Pointer to a KeyStore data parameter structure. */
    void *pCryptoDataParamsEnc,                                         /**< [In] Pointer to a Crypto data parameter structure for encryption. */
    void *pCryptoDataParamsMac,                                         /**< [In] Pointer to a Crypto data parameter structure for Macing. */
    void *pCryptoRngDataParams,                                         /**< [In] Pointer to a CryptoRng data parameter structure. */
    void *pCryptoDiversifyDataParams,                                   /**< [In] Pointer to the parameter structure of the CryptoDiversify layer (can be NULL). */
    void *pTMIDataParams,                                               /**< [In] Pointer to a TMI data parameter structure. */
    void *pVCADataParams                                                /**< [In] Pointer to the parameter structure for Virtual Card. */
);

/**
 * end of group phalMfpEVx_Sw
 * @}
 */
#endif /* NXPBUILD__PHAL_MFPEVX_SW */

/***************************************************************************************************************************************/
/* Mifare Plus EVx Generic command declarations.                                                                                       */
/***************************************************************************************************************************************/
#ifdef NXPBUILD__PHAL_MFPEVX

/** \defgroup phalMfpEVx MIFARE Plus EVx
 * \brief These Components implement the MIFARE Plus (EVx,  EV2, future versions) commands.
 * @{
 */

/** \defgroup phalMfpEVx_Errors ErrorCodes
 * \brief These component implement the MIFARE Plus (EVx,  EV2, future versions) Error codes.
 * @{
 */

/**
 * \defgroup phalMfpEVx_PICC_Errors PICC ErrorCodes
 * \brief These Components implement the actual PICC error codes.
 * These are the values that will not be returned to the user from the interface in case of error.
 * @{
 */
/** \name PICC response codes. */
/** @{ */
#define PHAL_MFPEVX_RESP_NACK0                                  0x00U   /**< MFP NACK 0 (in ISO14443-3 mode). */
#define PHAL_MFPEVX_RESP_NACK1                                  0x01U   /**< MFP NACK 1 (in ISO14443-3 mode). */
#define PHAL_MFPEVX_RESP_NACK4                                  0x04U   /**< MFP NACK 4 (in ISO14443-3 mode). */
#define PHAL_MFPEVX_RESP_NACK5                                  0x05U   /**< MFP NACK 5 (in ISO14443-3 mode). */
#define PHAL_MFPEVX_RESP_ACK_ISO3                               0x0AU   /**< MFP ACK (in ISO14443-3 mode). */
#define PHAL_MFPEVX_RESP_ACK_ISO4                               0x90U   /**< MFP ACK (in ISO14443-4 mode). */
#define PHAL_MFPEVX_RESP_ERR_TM                                 0x05U   /**< MFP Tranaction MAC related Error. */
#define PHAL_MFPEVX_RESP_ERR_AUTH                               0x06U   /**< MFP Authentication Error. */
#define PHAL_MFPEVX_RESP_ERR_CMD_OVERFLOW                       0x07U   /**< MFP Command Overflow Error. */
#define PHAL_MFPEVX_RESP_ERR_MAC_PCD                            0x08U   /**< MFP MAC Error. */
#define PHAL_MFPEVX_RESP_ERR_BNR                                0x09U   /**< MFP Blocknumber Error. */
#define PHAL_MFPEVX_RESP_ERR_EXT                                0x0AU   /**< MFP Extension Error. */
#define PHAL_MFPEVX_RESP_ERR_CMD_INVALID                        0x0BU   /**< MFP Invalid Command Error. */
#define PHAL_MFPEVX_RESP_ERR_FORMAT                             0x0CU   /**< MFP Format Error. */
#define PHAL_MFPEVX_RESP_ERR_NOT_SUP                            0x0DU   /**< MFP Not Supported Error. */
#define PHAL_MFPEVX_RESP_ERR_GEN_FAILURE                        0x0FU   /**< MFP Generic Error. */
#define PHAL_MFPEVX_RESP_ADDITIONAL_FRAME                       0xAFU   /**< MFP Additional data frame is expected to be sent. */
/** @} */

/** \name ISO 7816-4 error codes. */
/** @{ */
#define PHAL_MFPEVX_ISO7816_RESP_SUCCESS                        0x9000U /**< Correct execution. */
#define PHAL_MFPEVX_ISO7816_RESP_ERR_WRONG_LENGTH               0x6700U /**< Wrong length. */
#define PHAL_MFPEVX_ISO7816_RESP_ERR_WRONG_PARAMS               0x6A86U /**< Wrong parameters P1 and/or P2. */
#define PHAL_MFPEVX_ISO7816_RESP_ERR_WRONG_LC                   0x6A87U /**< Lc inconsistent with P1/p2. */
#define PHAL_MFPEVX_ISO7816_RESP_ERR_WRONG_LE                   0x6C00U /**< Wrong Le. */
#define PHAL_MFPEVX_ISO7816_RESP_ERR_WRONG_CLA                  0x6E00U /**< Wrong Class byte. */
/** @} */

/**
 * end of group phalMfpEVx_PICC_Errors
 * @}
 */

/** \defgroup phalMfpEVx_Cust_Errors Custom ErrorCodes
 * \brief These Components implement the custom error codes mapped to PICC return codes.
 * These are the values that will be returned to the user from the interface in case of error.
 * @{
 */

/** \name Custom Error Codes mapping for PICC erro codes. */
/** @{ */
#define PHAL_MFPEVX_ERR_AUTH                    (PH_ERR_CUSTOM_BEGIN + 0U)  /**< MFP EVx Authentication Error. This error represents PICC's #PHAL_MFPEVX_RESP_ERR_AUTH error. */
#define PHAL_MFPEVX_ERR_CMD_OVERFLOW            (PH_ERR_CUSTOM_BEGIN + 1U)  /**< MFP EVx Command Overflow Error. This error represents PICC's #PHAL_MFPEVX_RESP_ERR_CMD_OVERFLOW error. */
#define PHAL_MFPEVX_ERR_MAC_PCD                 (PH_ERR_CUSTOM_BEGIN + 2U)  /**< MFP EVx MAC Error. This error represents PICC's #PHAL_MFPEVX_RESP_ERR_MAC_PCD error. */
#define PHAL_MFPEVX_ERR_BNR                     (PH_ERR_CUSTOM_BEGIN + 3U)  /**< MFP EVx Blocknumber Error. This error represents PICC's #PHAL_MFPEVX_RESP_ERR_BNR error. */
#define PHAL_MFPEVX_ERR_EXT                     (PH_ERR_CUSTOM_BEGIN + 4U)  /**< MFP EVx Extension Error. This error represents PICC's #PHAL_MFPEVX_RESP_ERR_EXT error. */
#define PHAL_MFPEVX_ERR_CMD_INVALID             (PH_ERR_CUSTOM_BEGIN + 5U)  /**< MFP EVx Invalid Command Error. This error represents PICC's #PHAL_MFPEVX_RESP_ERR_CMD_INVALID error. */
#define PHAL_MFPEVX_ERR_FORMAT                  (PH_ERR_CUSTOM_BEGIN + 6U)  /**< MFP EVx Authentication Error. This error represents PICC's #PHAL_MFPEVX_RESP_ERR_FORMAT error. */
#define PHAL_MFPEVX_ERR_GEN_FAILURE             (PH_ERR_CUSTOM_BEGIN + 7U)  /**< MFP EVx Generic Error. This error represents PICC's #PHAL_MFPEVX_RESP_ERR_GEN_FAILURE error. */
#define PHAL_MFPEVX_ERR_TM                      (PH_ERR_CUSTOM_BEGIN + 8U)  /**< MFP EVx Transaction MAC related Error. This error represents PICC's #PHAL_MFPEVX_RESP_ERR_TM error. */
#define PHAL_MFPEVX_ERR_NOT_SUP                 (PH_ERR_CUSTOM_BEGIN + 9U)  /**< MFP EVx Not Supported Error. This error represents PICC's #PHAL_MFPEVX_RESP_ERR_NOT_SUP error. */
#define PHAL_MFPEVX_ISO7816_ERR_WRONG_LENGTH    (PH_ERR_CUSTOM_BEGIN + 10U) /**< MFP EVx 7816 wrong length error. This error represents PICC's #PHAL_MFPEVX_ISO7816_RESP_ERR_WRONG_LENGTH error. */
#define PHAL_MFPEVX_ISO7816_ERR_WRONG_PARAMS    (PH_ERR_CUSTOM_BEGIN + 11U) /**< MFP EVx 7816 wrong params error. This error represents PICC's #PHAL_MFPEVX_ISO7816_RESP_ERR_WRONG_PARAMS error. */
#define PHAL_MFPEVX_ISO7816_ERR_WRONG_LC        (PH_ERR_CUSTOM_BEGIN + 12U) /**< MFP EVx 7816 wrong Lc error. This error represents PICC's #PHAL_MFPEVX_ISO7816_RESP_ERR_WRONG_LC error. */
#define PHAL_MFPEVX_ISO7816_ERR_WRONG_LE        (PH_ERR_CUSTOM_BEGIN + 13U) /**< MFP EVx 7816 wrong LE error. This error represents PICC's #PHAL_MFPEVX_ISO7816_RESP_ERR_WRONG_LE error. */
#define PHAL_MFPEVX_ISO7816_ERR_WRONG_CLA       (PH_ERR_CUSTOM_BEGIN + 14U) /**< MFP EVx 7816 wrong CLA error. This error represents PICC's #PHAL_MFPEVX_ISO7816_RESP_ERR_WRONG_CLA error. */
/** @} */

/**
 * end of group phalMfpEVx_Cust_Errors
 * @}
 */

/**
 * end of group phalMfpEVx_Errors
 * @}
 */

/** \defgroup phalMfpEVx_CommonDefs Common Definitions
 * \brief These are common definitions for most of the Plus commands.
 * @{
 */

/** \name Options to indicate the ISO14443 protocol layer to be used. */
/** @{ */
#define PHAL_MFPEVX_ISO14443_L3                                     0x00U   /**< Option to use Iso14443 Layer 3 protocol. */
#define PHAL_MFPEVX_ISO14443_L4                                     0x01U   /**< Option to use Iso14443 Layer 4 protocol. */
/** @} */

/** \name Options to indicate the communication mode. */
/** @{ */
#define PHAL_MFPEVX_ENCRYPTION_OFF                                  0x00U   /**< Option to indicate the communication between PCD and PICC is plain. */
#define PHAL_MFPEVX_ENCRYPTION_ON                                   0x01U   /**< Option to indicate the communication between PCD and PICC is encrypted. */
/** @} */

/** \name Options to indicate the communication mode as maced for PCD to PICC transfer. */
/** @{ */
#define PHAL_MFPEVX_MAC_ON_COMMAND_OFF                              0x00U   /**< Option to indicate the communication is not maced for PCD to PICC transfer. */
#define PHAL_MFPEVX_MAC_ON_COMMAND_ON                               0x01U   /**< Option to indicate the communication is maced for PCD to PICC transfer. */
/** @} */

/** \name Options to indicate the communication mode as maced for PICC to PCD transfer. */
/** @{ */
#define PHAL_MFPEVX_MAC_ON_RESPONSE_OFF                             0x00U   /**< Option to indicate the communication is not maced for PICC to PCD transfer. */
#define PHAL_MFPEVX_MAC_ON_RESPONSE_ON                              0x01U   /**< Option to indicate the communication is maced for PICC to PCD transfer. */
/** @} */

/**
 * end of group phalMfpEVx_CommonDefs
 * @}
 */

/* Mifare Plus EVx personalization commands. ----------------------------------------------------------------------------------------- */
/** \defgroup phalMfpEVx_Personalization Commands_Personalization
 * \brief These Components implement the MIFARE Plus EVx personalization commands.
 * @{
 */

/**
 * \brief Performs a Write Perso command. The Write Perso command can be executed using the ISO14443-3 communication protocol
 * (after layer 3 activation) or using the ISO14443-4 protocol (after layer 4 activation).
 *
 * \return Status code
 * \retval #PH_ERR_SUCCESS Operation successful.
 * \retval Other Depending on implementation and underlaying component.
 */
phStatus_t phalMfpEVx_WritePerso(
    void *pDataParams,                                                  /**< [In] Pointer to this layer's parameter structure. */
    uint8_t bLayer4Comm,                                                /**< [In] ISO14443 protocol to be used.
                                                                             *          \arg #PHAL_MFPEVX_ISO14443_L3
                                                                             *          \arg #PHAL_MFPEVX_ISO14443_L4
                                                                             */
    uint16_t wBlockNr,                                                  /**< [In] Block number to be personalized. */
    uint8_t bNumBlocks,                                                 /**< [In] Number of blocks to be personalized. \n
                                                                             *          \c 15 block for Native communication if configured as Software component. \n
                                                                             *          \c 15 block for Native communication if configured as Sam NonX component. \n
                                                                             *          \c 13 blocks if configured as Sam X component.
                                                                             */
    uint8_t *pValue                                                    /**< [In] The value for the block mentioned in BlockNr parameter. \n
                                                                             *        If number of blocks is 1, the length should be 16 bytes. \n
                                                                             *        If number of blocks more than 1, the length should be (NoBlocks * 16) bytes.
                                                                             */
);

/** \name Options to switch the Security Level to 1 or 3. */
/** @{ */
#define PHAL_MFPEVX_MAINTIAN_BACKWARD_COMPATIBILITY                 0x00U   /**< Option to maintain the backward compatibility with Mifare Plus PICC. */
#define PHAL_MFPEVX_SWITCH_SECURITY_LEVEL_1                         0x01U   /**< Option to switch the Security Level to 1. */
#define PHAL_MFPEVX_SWITCH_SECURITY_LEVEL_3                         0x03U   /**< Option to switch the Security Level to 3. */
/** @} */

/**
 * \brief Performs a Commit Perso command. The Commit Perso command can be executed using the ISO14443-3 communication protocol
 * (after layer 3 activation) or using the ISO14443-4 protocol (after layer 4 activation). This command commits the written
 * data during WritePerso command and switches the SecurityLevel to 1 or 3 based on the option provided.
 *
 * If the Option parameter is 0, only the command code will be exchanges to PICC. This is to maintain the backward
 * compatibility with Mifare Plus PICC.
 *
 * \return Status code
 * \retval #PH_ERR_SUCCESS Operation successful.
 * \retval Other Depending on implementation and underlaying component.
 */
phStatus_t phalMfpEVx_CommitPerso(
    void *pDataParams,                                                  /**< [In] Pointer to this layer's parameter structure. */
    uint8_t bOption,                                                    /**< [In] Option to be used for Security Level switching.
                                                                             *          \arg #PHAL_MFPEVX_MAINTIAN_BACKWARD_COMPATIBILITY
                                                                             *          \arg #PHAL_MFPEVX_SWITCH_SECURITY_LEVEL_1
                                                                             *          \arg #PHAL_MFPEVX_SWITCH_SECURITY_LEVEL_3
                                                                             */
    uint8_t bLayer4Comm                                                 /**< [In] ISO14443 protocol to be used.
                                                                             *          \arg #PHAL_MFPEVX_ISO14443_L3
                                                                             *          \arg #PHAL_MFPEVX_ISO14443_L4
                                                                             */
);

/**
 * end of group phalMfpEVx_Personalization
 * @}
 */

#ifdef NXPBUILD__PHAL_MFPEVX_NDA
/* Mifare Plus EVx authentication commands. ------------------------------------------------------------------------------------------ */
/** \defgroup phalMfpEVx_Authenticate Commands_Authenticate
 * \brief These Components implement the MIFARE Plus EVx authentication commands.
 * @{
 */

/** \name Key type options for MIFARE Classic contactless IC Authentication. */
/** @{ */
#define PHAL_MFPEVX_KEYA                                            0x0AU   /**< MIFARE(R) Key A. */
#define PHAL_MFPEVX_KEYB                                            0x0BU   /**< MIFARE(R) Key B. */
/** @} */

/**
 * \brief Perform MIFARE Authenticate command in Security Level 1 with MIFARE CLASSIC PICC.
 *
 * \return Status code
 * \retval #PH_ERR_SUCCESS Operation successful.
 * \retval Other Depending on implementation and underlaying component.
 */
phStatus_t phalMfpEVx_AuthenticateMfc(
    void *pDataParams,                                                  /**< [In] Pointer to this layer's parameter structure. */
    uint8_t bBlockNo,                                                   /**< [In] PICC block number to be used for authentication. */
    uint8_t bKeyType,                                                   /**< [In] Authentication key type to be used.
                                                                             *          \arg #PHAL_MFPEVX_KEYA
                                                                             *          \arg #PHAL_MFPEVX_KEYB
                                                                             */
    uint16_t wKeyNumber,                                                /**< [In] Key number to used from software or hardware keystore. */
    uint16_t wKeyVersion,                                               /**< [In] Key version to used from software or hardware keystore. */
    uint8_t *pUid,                                                      /**< [In] UID of the PICC received during anti-collision sequence. */
    uint8_t bUidLength                                                  /**< [In] Length of the UID buffer. */
);

/** \name Options to indicate the Authentication type to be performed. */
/** @{ */
#define PHAL_MFPEVX_AUTHENTICATE_FIRST                              0x01U   /**< Option to indicate the authenticate type as first. */
#define PHAL_MFPEVX_AUTHENTICATE_NON_FIRST                          0x00U   /**< Option to indicate the authenticate type as non-first or following. */
/** @} */

/**
 * \brief Performs a MIFARE Plus Authentication for Security Level 0.This command performs basic Authenticate First / Non-First command execution
 * and also performs the AuthenticateContinue command internally.
 *
 * The following table shows which parameter is relevant depending on the parameters bLayer4Comm and bFirstAuth.\n
 * An "X" encodes that this parameter is relevant. A "-" encodes that this parameter is ignored (if it is an in-parameter) or
 * that it shall be ignored (if it is an out-parameter).\n
 *
 * \verbatim
 * +-------------+-------------+-------------+-------------+-------------+
 * | bFirstAuth  |    AUTHENTICATE_NON_FIRST |     AUTHENTICATE_FIRST    |
 * +-------------+-------------+-------------+-------------+-------------+
 * | bLayer4Comm | ISO14443_L3 | ISO14443_L4 | ISO14443_L3 | ISO14443_L4 |
 * +-------------+-------------+-------------+-------------+-------------+
 * | wBlockNr    |       X     |       X     |       X     |       X     |
 * | wKeyNumber  |       X     |       X     |       X     |       X     |
 * | wKeyVersion |       X     |       X     |       X     |       X     |
 * | bLenPcdCap2 |       -     |       -     |       -     |       X     |
 * | pPcdCap2In  |       -     |       -     |       -     |       X     |
 * | pPcdCap2    |       -     |       -     |       -     |       X     |
 * | pPdCap2     |       -     |       -     |       -     |       X     |
 * +-------------+-------------+-------------+-------------+-------------+
 * \endverbatim
 *
 * \return Status code
 * \retval #PH_ERR_SUCCESS Operation successful.
 * \retval Other Depending on implementation and underlaying component.
 */
phStatus_t phalMfpEVx_AuthenticateSL0(
    void *pDataParams,                                                  /**< [In] Pointer to this layer's parameter structure. */
    uint8_t bLayer4Comm,                                                /**< [In] ISO14443 protocol to be used.
                                                                             *          \arg #PHAL_MFPEVX_ISO14443_L3
                                                                             *          \arg #PHAL_MFPEVX_ISO14443_L4
                                                                             */
    uint8_t bFirstAuth,                                                 /**< [In] Type of authentication to be performed.
                                                                             *          \arg #PHAL_MFPEVX_AUTHENTICATE_FIRST
                                                                             *          \arg #PHAL_MFPEVX_AUTHENTICATE_NON_FIRST
                                                                             */
    uint16_t wBlockNr,                                                  /**< [In] PICC Block number to be used for authentication. */
    uint16_t wKeyNumber,                                                /**< [In] Key number be to used from software or hardware keystore. */
    uint16_t wKeyVersion,                                               /**< [In] Key version be to used from software or hardware keystore. */
    uint8_t bLenDivInput,                                               /**< [In] Length of diversification input used to diversify the key.
                                                                             *        If 0, no diversification is performed.
                                                                             */
    uint8_t *pDivInput,                                                 /**< [In] Diversification Input used to diversify the key. */
    uint8_t bLenPcdCap2,                                                /**< [In] Length of the input PCD capabilities. */
    uint8_t *pPcdCap2In,                                               /**< [In] Buffer containing the Input PCD Capabilities. \n
                                                                             *          \c If length is non zero, PCDCapabilites should be available. \n
                                                                             *          \c If length is zero, PCDCapabilites buffer should be NULL. \n
                                                                             */
    uint8_t *pPcdCap2Out,                                               /**< [Out] Buffer containing the Output PCD capabilities. This will be of 6 bytes. */
    uint8_t *pPdCap2                                                    /**< [Out] Buffer containing the Output PD capabilities. This will be of 6 bytes. */
);

/**
 * \brief Performs a MIFARE Plus Authentication for Security Level 1. This command performs basic Authenticate First / Non-First command execution
 * and also performs the AuthenticateContinue command internally.
 *
 * The following table shows which parameter is relevant depending on the parameters bLayer4Comm and bFirstAuth.\n
 * An "X" encodes that this parameter is relevant. A "-" encodes that this parameter is ignored (if it is an in-parameter) or
 * that it shall be ignored (if it is an out-parameter).\n
 *
 * \verbatim
 * +-------------+-------------+-------------+-------------+-------------+
 * | bFirstAuth  |    AUTHENTICATE_NON_FIRST |     AUTHENTICATE_FIRST    |
 * +-------------+-------------+-------------+-------------+-------------+
 * | bLayer4Comm | ISO14443_L3 | ISO14443_L4 | ISO14443_L3 | ISO14443_L4 |
 * +-------------+-------------+-------------+-------------+-------------+
 * | wBlockNr    |       X     |       X     |       X     |       X     |
 * | wKeyNumber  |       X     |       X     |       X     |       X     |
 * | wKeyVersion |       X     |       X     |       X     |       X     |
 * | bLenPcdCap2 |       -     |       -     |       -     |       X     |
 * | pPcdCap2In  |       -     |       -     |       -     |       X     |
 * | pPcdCap2    |       -     |       -     |       -     |       X     |
 * | pPdCap2     |       -     |       -     |       -     |       X     |
 * +-------------+-------------+-------------+-------------+-------------+
 * \endverbatim
 *
 * \return Status code
 * \retval #PH_ERR_SUCCESS Operation successful.
 * \retval Other Depending on implementation and underlaying component.
 */
phStatus_t phalMfpEVx_AuthenticateSL1(
    void *pDataParams,                                                  /**< [In] Pointer to this layer's parameter structure. */
    uint8_t bLayer4Comm,                                                /**< [In] ISO14443 protocol to be used.
                                                                             *          \arg #PHAL_MFPEVX_ISO14443_L3
                                                                             *          \arg #PHAL_MFPEVX_ISO14443_L4
                                                                             */
    uint8_t bFirstAuth,                                                 /**< [In] Type of authentication to be performed.
                                                                             *          \arg #PHAL_MFPEVX_AUTHENTICATE_FIRST
                                                                             *          \arg #PHAL_MFPEVX_AUTHENTICATE_NON_FIRST
                                                                             */
    uint16_t wBlockNr,                                                  /**< [In] PICC Block number to be used for authentication. */
    uint16_t wKeyNumber,                                                /**< [In] Key number to be used from software or hardware keystore. */
    uint16_t wKeyVersion,                                               /**< [In] Key version to be used from software or hardware keystore. */
    uint8_t bLenDivInput,                                               /**< [In] Length of diversification input used to diversify the key.
                                                                             *        If 0, no diversification is performed.
                                                                             */
    uint8_t *pDivInput,                                                 /**< [In] Diversification Input used to diversify the key. */
    uint8_t bLenPcdCap2,                                                /**< [In] Length of the input PCD capabilities. */
    uint8_t *pPcdCap2In,                                               /**< [In] Buffer containing the Input PCD Capabilities. \n
                                                                             *          \c If length is non zero, PCDCapabilites should be available. \n
                                                                             *          \c If length is zero, PCDCapabilites buffer should be NULL. \n
                                                                             */
    uint8_t *pPcdCap2Out,                                               /**< [Out] Buffer containing the Output PCD capabilities. This will be of 6 bytes. */
    uint8_t *pPdCap2                                                    /**< [Out] Buffer containing the Output PD capabilities. This will be of 6 bytes. */
);

/**
 * \brief Performs a MIFARE Plus Authentication for Security Level 3. This command performs basic Authenticate First / Non-First command execution
 * and also performs the AuthenticateContinue command internally.
 *
 * \return Status code
 * \retval #PH_ERR_SUCCESS Operation successful.
 * \retval Other Depending on implementation and underlaying component.
 */
phStatus_t phalMfpEVx_AuthenticateSL3(
    void *pDataParams,                                                  /**< [In] Pointer to this layer's parameter structure. */
    uint8_t bFirstAuth,                                                 /**< [In] Type of authentication to be performed.
                                                                             *          \arg #PHAL_MFPEVX_AUTHENTICATE_FIRST
                                                                             *          \arg #PHAL_MFPEVX_AUTHENTICATE_NON_FIRST
                                                                             */
    uint16_t wBlockNr,                                                  /**< [In] PICC Block number to be used for authentication. */
    uint16_t wKeyNumber,                                                /**< [In] Key number to be used from software or hardware keystore. */
    uint16_t wKeyVersion,                                               /**< [In] Key version to be used from software or hardware keystore. */
    uint8_t bLenDivInput,                                               /**< [In] Length of diversification input used to diversify the key.
                                                                             *        If 0, no diversification is performed.
                                                                             */
    uint8_t *pDivInput,                                                 /**< [In] Diversification Input used to diversify the key. */
    uint8_t bLenPcdCap2,                                                /**< [In] Length of the input PCD capabilities. */
    uint8_t *pPcdCap2In,                                               /**< [In] Buffer containing the Input PCD Capabilities. \n
                                                                             *          \c If length is non zero, PCDCapabilites should be available. \n
                                                                             *          \c If length is zero, PCDCapabilites buffer should be NULL. \n
                                                                             */
    uint8_t *pPcdCap2Out,                                               /**< [Out] Buffer containing the Output PCD capabilities. This will be of 6 bytes. */
    uint8_t *pPdCap2                                                    /**< [Out] Buffer containing the Output PD capabilities. This will be of 6 bytes. */
);

/** \name Options to indicate the type of diversification to be performed for Sector Switch Authenticate command.
 * All these macros are applicable for Sam X and S mode only. For Software mode, these macros has no meaning even
 * though they are passed.
 */
/** @{ */
#define PHAL_MFPEVX_SS_AUTHENTICATE_NO_DIVERSIFICATION              0x00U   /**< Option to indicate that the diversificationis disabled. */
#define PHAL_MFPEVX_SS_AUTHENTICATE_SECTOR_SWITCH_DIVERSIFICATION   0x01U   /**< Option to indicate that the diversification is enabled for Sector Switch keys (9006 or 9007). */
#define PHAL_MFPEVX_SS_AUTHENTICATE_SECTOR_DIVERSIFICATION          0x02U   /**< Option to indicate that the diversification is enabled for AES Sector keys (4001, 4003, etc...). */
#define PHAL_MFPEVX_SS_AUTHENTICATE_MASTER_SECTOR_DIVERSIFICATION   0x04U   /**< Option to indicate that the diversification is enabled for AES Sector keys (4001, 4003, etc...).
                                                                             *   using a Master key.
                                                                             */
/** @} */

/**
 * \brief Perform MIFARE(R) Sector switch authentication command. This command is valid in Security Level 1 only. This command
 * performs basic Authenticate First / Non-First command execution and also performs the AuthenticateContinue command internally.
 *
 * \return Status code
 * \retval #PH_ERR_SUCCESS Operation successful.
 * \retval Other Depending on implementation and underlaying component.
 *
 */
phStatus_t phalMfpEVx_SSAuthenticate(
    void *pDataParams,                                                  /**< [In] Pointer to this layer's parameter structure. */
    uint8_t bOption,                                                    /**< [In] Options for key diversification. Only applicable for SAM component,
                                                                             *        ignored for Software component.
                                                                             *        \arg #PHAL_MFPEVX_SS_AUTHENTICATE_NO_DIVERSIFICATION
                                                                             *        \arg #PHAL_MFPEVX_SS_AUTHENTICATE_SECTOR_SWITCH_DIVERSIFICATION
                                                                             *        \arg #PHAL_MFPEVX_SS_AUTHENTICATE_SECTOR_DIVERSIFICATION
                                                                             *        \arg #PHAL_MFPEVX_SS_AUTHENTICATE_MASTER_SECTOR_DIVERSIFICATION
                                                                             */
    uint16_t wSSKeyBNr,                                                 /**< [In] PICC block number to be used for Sector Switch authentication. */
    uint16_t wSSKeyNr,                                                  /**< [In] Key number to be used from software or hardware keystore for sector switch key(SSKey) */
    uint16_t wSSKeyVer,                                                 /**< [In] Key number to be used from software or hardware keystore for sector switch key(SSKey) */
    uint8_t bLenDivInputSSKey,                                          /**< [In] Length of diversification input used to diversify the Sector Switch key. \n
                                                                             *        \c In Software, if 0, no diversification is performed.\n
                                                                             *        \c If Sam, ony if #PHAL_MFPEVX_SS_AUTHENTICATE_SECTOR_SWITCH_DIVERSIFICATION is set, diversification
                                                                             *           of Sector Switch key will be performed. In this case, there should be proper length available.
                                                                             */
    uint8_t *pDivInputSSKey,                                            /**< [In] Diversification Input used to diversify the sector switch key. */
    uint8_t bSecCount,                                                  /**< [In] Number of sectors available in SectorNos buffer. */
    uint16_t *pSectorNos,                                               /**< [In] The list of AES sector B key numbers for switching the sectors. */
    uint16_t *pKeyNos,                                                 /**< [In] If Option is set to use the Master sector key, then the master sector key number
                                                                             *        to be used from software or hardware keystore should be passed, else individual
                                                                             *        Sector B key number to be used from software or hardware keystore should be passed.
                                                                             */
    uint16_t *pKeyVers,                                                /**< [In] If Option is set to use the Master sector key, then the master sector key version
                                                                             *        to be used from software or hardware keystore should be passed, else individual
                                                                             *        Sector B key version to be used from software or hardware keystore should be passed.
                                                                             */
    uint8_t bLenDivInputSectorKeyBs,                                    /**< [In] Length of diversification input used to diversify the AES Sector B key. \n
                                                                             *        \c For SAM if length is 0, the diversification input passed for Sector Switch key will be used.\n
                                                                             *        \c For SW if length is 0, no diversification is performed.
                                                                             */
    uint8_t *pDivInputSectorKeyBs                                       /**< [In] Diversification Input used to diversify the AES Sector B key. */
);

/**
 * \brief Perform MIFARE(R) Sector switch authentication command. This command performs the AuthenticateContinue command internally.
 *
 * \verbatim
 * +-----------------+---------------+
 * | CardSize/SubType| bUpgrade Info |
 * +-----------------+---------------+
 * |      0.5k       |      0xX0     |
 * |      1k         |      0xX1     |
 * |      2k         |      0xX2     |
 * |      4k         |      0xX4     |
 * |      8k         |      0xX8     |
 * |      RFU        |   Other data  |
 * +-----------------+---------------+
 * \endverbatim
 *
 * \return Status code
 * \retval #PH_ERR_SUCCESS Operation successful.
 * \retval Other Depending on implementation and underlaying component.
 */
phStatus_t phalMfpEVx_AuthenticatePDC(
    void *pDataParams,                                                  /**< [In] Pointer to this layer's parameter structure. */
    uint16_t wBlockNr,                                                  /**< [In] PICC Block number to be used for authentication. */
    uint16_t wKeyNumber,                                                /**< [In] Key number to used from software or hardware keystore. */
    uint16_t wKeyVersion,                                               /**< [In] Key version to used from software or hardware keystore. */
    uint8_t bLenDivInput,                                               /**< [In] Length of diversification input used to diversify the key.
                                                                             *        If 0, no diversification is performed.
                                                                             */
    uint8_t *pDivInput,                                                 /**< [In] Diversification Input used to diversify the key. */
    uint8_t bUpgradeInfo                                                /**< [In] The upgrade info input. */
);

/**
 * end of group phalMfpEVx_Authenticate
 * @}
 */

/* Mifare Plus EVx data operation commands. ------------------------------------------------------------------------------------------ */
/** \defgroup phalMfpEVx_DataOperation Commands_DataOperations
 * \brief These Components implement the MIFARE Plus EVx data operation commands.
 * @{
 */

/**
 * \brief Performs a Write / Write MACed command. This command writes a 16 byte data to the PICC.
 * The parameter Encrypted, WriteMaced are valid only for MFP authenticated state and not for MFC authenticate state.
 *
 * \return Status code
 * \retval #PH_ERR_SUCCESS Operation successful.
 * \retval Other Depending on implementation and underlaying component.
 */
phStatus_t phalMfpEVx_Write(
    void *pDataParams,                                                  /**< [In] Pointer to this layer's parameter structure. */
    uint8_t bEncrypted,                                                 /**< [In] Type of communication to be used. Based on this flag the command code
                                                                             *        will be updated.
                                                                             *          \arg #PHAL_MFPEVX_ENCRYPTION_OFF
                                                                             *          \arg #PHAL_MFPEVX_ENCRYPTION_ON
                                                                             */
    uint8_t bWriteMaced,                                                /**< [In] Indicate whether the response should be maced. Based on this flag the
                                                                             *        command code will be updated.
                                                                             *          \arg #PHAL_MFPEVX_MAC_ON_RESPONSE_OFF
                                                                             *          \arg #PHAL_MFPEVX_MAC_ON_RESPONSE_ON
                                                                             */
    uint16_t wBlockNr,                                                  /**< [In] PICC block number to which the data should be written. */
    uint8_t bNumBlocks,                                                 /**< [In] Number of blocks to write.\n
                                                                             *          \c 15 block for Native communication if configured as Software component. \n
                                                                             *          \c 13 blocks if configured as Sam X or Sam NonX component.
                                                                             */
    uint8_t *pBlocks,                                                  /**< [In] The data to be written. This buffer should have data equal to NumBlocks * 16,
                                                                             *        where 16 is one block size.
                                                                             */
    uint8_t *pTMC,                                                     /**< [Out] Only available is the block is a TMProtected block. The buffer will have 4
                                                                             *         bytes of Transaction MAC counter information.
                                                                             */
    uint8_t *pTMV                                                      /**< [Out] Only available is the block is a TMProtected block. The buffer will have 8
                                                                             *         bytes of Transaction MAC value.
                                                                             */
);

/**
 * \brief Performs a Read / Read MACed command. The parameter Encrypted, ReadMaced and MacOnCmd are valid only
 * for MFP authenticated state and not for MFC authenticate state.
 *
 * \return Status code
 * \retval #PH_ERR_SUCCESS Operation successful.
 * \retval Other Depending on implementation and underlaying component.
 */
phStatus_t phalMfpEVx_Read(
    void *pDataParams,                                                  /**< [In] Pointer to this layer's parameter structure. */
    uint8_t bEncrypted,                                                 /**< [In] Type of communication to be used. Based on this flag the command code
                                                                             *        will be updated.
                                                                             *          \arg #PHAL_MFPEVX_ENCRYPTION_OFF
                                                                             *          \arg #PHAL_MFPEVX_ENCRYPTION_ON
                                                                             */
    uint8_t bReadMaced,                                                 /**< [In] Indicate whether the response should be maced. Based on this flag the
                                                                             *        command code will be updated.
                                                                             *          \arg #PHAL_MFPEVX_MAC_ON_RESPONSE_OFF
                                                                             *          \arg #PHAL_MFPEVX_MAC_ON_RESPONSE_ON
                                                                             */
    uint8_t bMacOnCmd,                                                  /**< [In] Indicate whether the command should be maced. Based on this flag the
                                                                             *        command code will be updated.
                                                                             *          \arg #PHAL_MFPEVX_MAC_ON_COMMAND_OFF
                                                                             *          \arg #PHAL_MFPEVX_MAC_ON_COMMAND_ON
                                                                             */
    uint16_t wBlockNr,                                                  /**< [In] PICC block number from which the data should be read. */
    uint8_t bNumBlocks,                                                 /**< [In] Number of blocks to be read.\n
                                                                             *          \c 15 block for Native communication if configured as Software component. \n
                                                                             *          \c 13 blocks if configured as Sam X or Sam NonX component.
                                                                             */
    uint8_t *pBlocks                                                   /**< [Out] The data to be read. This buffer should have data equal to ((NumBlocks * 16) + 8),
                                                                             *         where 16 is one block size and 8 bytes is for storing the MAC received form PICC.
                                                                             *         The last 8 bytes will be cleared once returned to the application.
                                                                             */
);
/**
 * end of group phalMfpEVx_DataOperation
 * @}
 */

/* Mifare Plus EVx value operation commands. ----------------------------------------------------------------------------------------- */
/** \defgroup phalMfpEVx_ValueOperation Commands_ValueOperations
 * \brief These Components implement the MIFARE Plus EVx value operation commands.
 * @{
 */

/**
 * \brief Performs a Write / Write MACed command of a value.
 * The parameter Encrypted, WriteMaced are valid only for MFP authenticated state and not for MFC authenticate state.
 *
 * \return Status code
 * \retval #PH_ERR_SUCCESS Operation successful.
 * \retval Other Depending on implementation and underlaying component.
 */
phStatus_t phalMfpEVx_WriteValue(
    void *pDataParams,                                                  /**< [In] Pointer to this layer's parameter structure. */
    uint8_t bEncrypted,                                                 /**< [In] Type of communication to be used. Based on this flag the command code
                                                                             *        will be updated.
                                                                             *          \arg #PHAL_MFPEVX_ENCRYPTION_OFF
                                                                             *          \arg #PHAL_MFPEVX_ENCRYPTION_ON
                                                                             */
    uint8_t bWriteMaced,                                                /**< [In] Indicate whether the response should be maced. Based on this flag the
                                                                             *        command code will be updated.
                                                                             *          \arg #PHAL_MFPEVX_MAC_ON_RESPONSE_OFF
                                                                             *          \arg #PHAL_MFPEVX_MAC_ON_RESPONSE_ON
                                                                             */
    uint16_t wBlockNr,                                                  /**< [In] PICC block number to which the value should be written. */
    uint8_t *pValue,                                                    /**< [In] The value to be written. This buffer should have value equal to 4 bytes. */
    uint8_t bAddrData,                                                  /**< [In] The address to be written. */
    uint8_t *pTMC,                                                     /**< [Out] Only available is the block is a TMProtected block. The buffer will have 4
                                                                             *         bytes of Transaction MAC counter information.
                                                                             */
    uint8_t *pTMV                                                      /**< [Out] Only available is the block is a TMProtected block. The buffer will have 8
                                                                             *         bytes of Transaction MAC value.
                                                                             */
);

/**
 * \brief Performs a Read / Read MACed Value command.
 * The parameter Encrypted, ReadMaced and MacOnCmd are valid only for MFP authenticated state and
 * not for MFC authenticate state.
 *
 * \return Status code
 * \retval #PH_ERR_SUCCESS Operation successful.
 * \retval Other Depending on implementation and underlaying component.
 */
phStatus_t phalMfpEVx_ReadValue(
    void *pDataParams,                                                  /**< [In] Pointer to this layer's parameter structure. */
    uint8_t bEncrypted,                                                 /**< [In] Type of communication to be used. Based on this flag the command code
                                                                             *        will be updated.
                                                                             *          \arg #PHAL_MFPEVX_ENCRYPTION_OFF
                                                                             *          \arg #PHAL_MFPEVX_ENCRYPTION_ON
                                                                             */
    uint8_t bReadMaced,                                                 /**< [In] Indicate whether the response should be maced. Based on this flag the
                                                                             *        command code will be updated.
                                                                             *          \arg #PHAL_MFPEVX_MAC_ON_RESPONSE_OFF
                                                                             *          \arg #PHAL_MFPEVX_MAC_ON_RESPONSE_ON
                                                                             */
    uint8_t bMacOnCmd,                                                  /**< [In] Indicate whether the command should be maced. Based on this flag the
                                                                             *        command code will be updated.
                                                                             *          \arg #PHAL_MFPEVX_MAC_ON_COMMAND_OFF
                                                                             *          \arg #PHAL_MFPEVX_MAC_ON_COMMAND_ON
                                                                             */
    uint16_t wBlockNr,                                                  /**< [In] PICC block number from which the value should be read. */
    uint8_t *pValue,                                                   /**< The value read from the specified block number. The buffer will have 4 bytes
                                                                             *    of value information.
                                                                             */
    uint8_t *pAddrData                                                  /**< [Out] The address from the read value information. */
);

/**
 * \brief Performs an Increment / Increment MACed command.
 * The parameter IncrementMaced is valid only for MFP authenticated state and not for MFC authenticate state.
 *
 * \return Status code
 * \retval #PH_ERR_SUCCESS Operation successful.
 * \retval Other Depending on implementation and underlaying component.
 */
phStatus_t phalMfpEVx_Increment(
    void *pDataParams,                                                  /**< [In] Pointer to this layer's parameter structure. */
    uint8_t bIncrementMaced,                                            /**< [In] Indicate whether the response should be maced. Based on this flag the
                                                                             *        command code will be updated.
                                                                             *          \arg #PHAL_MFPEVX_MAC_ON_RESPONSE_OFF
                                                                             *          \arg #PHAL_MFPEVX_MAC_ON_RESPONSE_ON
                                                                             */
    uint16_t wBlockNr,                                                  /**< [In] PICC block number to be used for incrementing the value. */
    uint8_t *pValue                                                    /**< [In] The value to be incremented. This buffer should have 4 bytes value information.
                                                                             *        The value to be incremented should be LSB first order. \n
                                                                             *        \c For Ex. If the value to be incremented is by 1 times then the pValue buffer will be, \n
                                                                             *           0x01, 0x00, 0x00, 0x00.
                                                                             */
);

/**
 * \brief Performs a Decrement / Decrement MACed command.
 * The parameter DecrementMaced is valid only for MFP authenticated state and not for MFC authenticate state.
 *
 * \return Status code
 * \retval #PH_ERR_SUCCESS Operation successful.
 * \retval Other Depending on implementation and underlaying component.
 */
phStatus_t phalMfpEVx_Decrement(
    void *pDataParams,                                                  /**< [In] Pointer to this layer's parameter structure. */
    uint8_t bDecrementMaced,                                            /**< [In] Indicate whether the response should be maced. Based on this flag the
                                                                             *        command code will be updated.
                                                                             *          \arg #PHAL_MFPEVX_MAC_ON_RESPONSE_OFF
                                                                             *          \arg #PHAL_MFPEVX_MAC_ON_RESPONSE_ON
                                                                             */
    uint16_t wBlockNr,                                                  /**< [In] PICC block number to be used for decrementing the value. */
    uint8_t *pValue                                                    /**< [In] The value to be decremented. This buffer should have 4 bytes value information.
                                                                             *        The value to be decremented should be LSB first order. \n
                                                                             *        \c For Ex. If the value to be decremented is by 1 times then the pValue buffer will be, \n
                                                                             *           0x01, 0x00, 0x00, 0x00.
                                                                             */
);

/**
 * \brief Performs an Increment Transfer / Increment Transfer MACed command.
 * The parameter IncrementTransferMaced is valid only for MFP authenticated state and not for MFC authenticate state.
 *
 * \return Status code
 * \retval #PH_ERR_SUCCESS Operation successful.
 * \retval Other Depending on implementation and underlaying component.
 */
phStatus_t phalMfpEVx_IncrementTransfer(
    void *pDataParams,                                                  /**< [In] Pointer to this layer's parameter structure. */
    uint8_t bIncrementTransferMaced,                                    /**< [In] Indicate whether the response should be maced. Based on this flag the
                                                                             *        command code will be updated.
                                                                             *          \arg #PHAL_MFPEVX_MAC_ON_RESPONSE_OFF
                                                                             *          \arg #PHAL_MFPEVX_MAC_ON_RESPONSE_ON
                                                                             */
    uint16_t wSourceBlockNr,                                            /**< [In] PICC block number to be used for incrementing the value. */
    uint16_t wDestinationBlockNr,                                       /**< [In] PICC block number to be used for transferring the value. */
    uint8_t *pValue,                                                   /**< [In] The value to be incremented and transferred. This buffer should have 4 bytes
                                                                             *        value information. The value to be incremented and transferred should be LSB first order. \n
                                                                             *        \c For Ex. If the value to be incremented is by 1 times then the pValue buffer will be, \n
                                                                             *           0x01, 0x00, 0x00, 0x00.
                                                                             */
    uint8_t *pTMC,                                                     /**< [Out] Only available is the block is a TMProtected block. The buffer will have 4
                                                                             *         bytes of Transaction MAC counter information.
                                                                             */
    uint8_t *pTMV                                                      /**< [Out] Only available is the block is a TMProtected block. The buffer will have 8
                                                                             *         bytes of Transaction MAC value.
                                                                             */
);

/**
 * \brief Performs a Decrement Transfer / Decrement Transfer MACed command.
 * The parameter DecrementTransferMaced is valid only for MFP authenticated state and not for MFC authenticate state.
 *
 * \return Status code
 * \retval #PH_ERR_SUCCESS Operation successful.
 * \retval Other Depending on implementation and underlaying component.
 */
phStatus_t phalMfpEVx_DecrementTransfer(
    void *pDataParams,                                                  /**< [In] Pointer to this layer's parameter structure. */
    uint8_t bDecrementTransferMaced,                                    /**< [In] Indicate whether the response should be maced. Based on this flag the
                                                                             *        command code will be updated.
                                                                             *          \arg #PHAL_MFPEVX_MAC_ON_RESPONSE_OFF
                                                                             *          \arg #PHAL_MFPEVX_MAC_ON_RESPONSE_ON
                                                                             */
    uint16_t wSourceBlockNr,                                            /**< [In] PICC block number to be used for decrementing the value. */
    uint16_t wDestinationBlockNr,                                       /**< [In] PICC block number to be used for transferring the value. */
    uint8_t *pValue,                                                   /**< [In] The value to be decremented and transferred. This buffer should have 4 bytes
                                                                             *        value information. The value to be decremented and transferred should be LSB first order. \n
                                                                             *        \c For Ex. If the value to be decremented is by 1 times then the pValue buffer will be, \n
                                                                             *           0x01, 0x00, 0x00, 0x00.
                                                                             */
    uint8_t *pTMC,                                                     /**< [Out] Only available is the block is a TMProtected block. The buffer will have 4
                                                                             *         bytes of Transaction MAC counter information.
                                                                             */
    uint8_t *pTMV                                                      /**< [Out] Only available is the block is a TMProtected block. The buffer will have 8
                                                                             *         bytes of Transaction MAC value.
                                                                             */
);

/**
* \brief Performs a Transfer / Transfer MACed command.
 * The parameter TransferMaced is valid only for MFP authenticated state and not for MFC authenticate state.
 *
 * \return Status code
 * \retval #PH_ERR_SUCCESS Operation successful.
 * \retval Other Depending on implementation and underlaying component.
*/
phStatus_t phalMfpEVx_Transfer(
    void *pDataParams,                                                  /**< [In] Pointer to this layer's parameter structure. */
    uint8_t bTransferMaced,                                             /**< [In] Indicate whether the response should be maced. Based on this flag the
                                                                             *        command code will be updated.
                                                                             *          \arg #PHAL_MFPEVX_MAC_ON_RESPONSE_OFF
                                                                             *          \arg #PHAL_MFPEVX_MAC_ON_RESPONSE_ON
                                                                             */
    uint16_t wBlockNr,                                                  /**< [In] PICC block number to be used for transferring the value. */
    uint8_t *pTMC,                                                     /**< [Out] Only available is the block is a TMProtected block. The buffer will have 4
                                                                             *         bytes of Transaction MAC counter information.
                                                                             */
    uint8_t *pTMV                                                      /**< [Out] Only available is the block is a TMProtected block. The buffer will have 8
                                                                             *         bytes of Transaction MAC value.
                                                                             */
);

/**
 * \brief Performs a Restore / Restore MACed command.
 * The parameter RestoreMaced is valid only for MFP authenticated state and not for MFC authenticate state.
 *
 * \return Status code
 * \retval #PH_ERR_SUCCESS Operation successful.
 * \retval Other Depending on implementation and underlaying component.
 */
phStatus_t phalMfpEVx_Restore(
    void *pDataParams,                                                  /**< [In] Pointer to this layer's parameter structure. */
    uint8_t bRestoreMaced,                                              /**< [In] Indicate whether the response should be maced. Based on this flag the
                                                                             *        command code will be updated.
                                                                             *          \arg #PHAL_MFPEVX_MAC_ON_RESPONSE_OFF
                                                                             *          \arg #PHAL_MFPEVX_MAC_ON_RESPONSE_ON
                                                                             */
    uint16_t wBlockNr                                                   /**< [In] PICC block number to be used for restoring the value. */
);

/**
 * end of group phalMfpEVx_ValueOperation
 * @}
 */
#endif /* NXPBUILD__PHAL_MFPEVX_NDA */

/* Mifare Plus EVx special commands. ------------------------------------------------------------------------------------------------- */
/** \defgroup phalMfpEVx_Special Commands_Special
 * \brief These Components implement the MIFARE Plus EVx additional feature commands.
 * @{
 */

/**
 * \brief Returns manufacturing related data of the PICC
 *
 * \return Status code
 * \retval #PH_ERR_SUCCESS Operation successful.
 * \retval Other Depending on implementation and underlaying component.
 */
phStatus_t phalMfpEVx_GetVersion(
    void *pDataParams,                                                  /**< [In] Pointer to this layer's parameter structure. */
    uint8_t *pVerInfo                                                  /**< [Out] The version information of the PICC. \n
                                                                             *          \c If UID is 4 bytes, the buffer will have 27 bytes of version information. \n
                                                                             *          \c If UID is 7 bytes, the buffer will have 28 bytes of version information. \n
                                                                             *          \c If UID is 10 bytes, the buffer will have 33 bytes of version information.
                                                                             */
);

/**
 * \brief Read originality Signature from the PICC.
 *
 * \return Status code
 * \retval #PH_ERR_SUCCESS Operation successful.
 * \retval Other Depending on implementation and underlaying component.
 */
phStatus_t phalMfpEVx_ReadSign(
    void *pDataParams,                                                  /**< [In] Pointer to this layer's parameter structure. */
    uint8_t bLayer4Comm,                                                /**< [In] ISO14443 protocol to be used.
                                                                             *          \arg #PHAL_MFPEVX_ISO14443_L3
                                                                             *          \arg #PHAL_MFPEVX_ISO14443_L4
                                                                             */
    uint8_t bAddr,                                                      /**< [In] Targeted ECC originality check signature. */
    uint8_t **pSignature                                               /**< [Out] PICC's orginality signature. The buffer will have 56 bytes of
                                                                             *         signature information.
                                                                             */
);

/**
 * \brief Performs a Reset Auth command.
 *
 * \return Status code
 * \retval #PH_ERR_SUCCESS Operation successful.
 * \retval Other Depending on implementation and underlaying component.
 */
phStatus_t phalMfpEVx_ResetAuth(
    void *pDataParams                                                   /**< [In] Pointer to this layer's parameter structure. */
);

/** \name Options to personalize the UID. */
/** @{ */
#define PHAL_MFPEVX_UID_TYPE_UIDF0                                  0x00U   /**< MIFARE(R) Plus EVx UID type UIDF0. */
#define PHAL_MFPEVX_UID_TYPE_UIDF1                                  0x40U   /**< MIFARE(R) Plus EVx UID type UIDF1. */
#define PHAL_MFPEVX_UID_TYPE_UIDF2                                  0x20U   /**< MIFARE(R) Plus EVx UID type UIDF2. */
#define PHAL_MFPEVX_UID_TYPE_UIDF3                                  0x60U   /**< MIFARE(R) Plus EVx UID type UIDF3. */
/** @} */

/**
 * \brief Perform MIFARE(R) Personalize UID usage command sequence with MIFARE Picc.
 *
 * \return Status code
 * \retval #PH_ERR_SUCCESS Operation successful.
 * \retval Other Depending on implementation and underlaying component.
 */
phStatus_t phalMfpEVx_PersonalizeUid(
    void *pDataParams,                                                  /**< [In] Pointer to this layer's parameter structure. */
    uint8_t bUidType                                                    /**< [In] UID type to be used for personalization.
                                                                             *          \arg #PHAL_MFPEVX_UID_TYPE_UIDF0
                                                                             *          \arg #PHAL_MFPEVX_UID_TYPE_UIDF1
                                                                             *          \arg #PHAL_MFPEVX_UID_TYPE_UIDF2
                                                                             *          \arg #PHAL_MFPEVX_UID_TYPE_UIDF3
                                                                             */
);

/** \name Options to Enable / Disable ISO14443 Layer 4 protocol. */
/** @{ */
#define PHAL_MFPEVX_ENABLE_ISO14443_L4                              0x00U   /**< Option to enable ISO14443 Layer 4 protocol. */
#define PHAL_MFPEVX_DISABLE_ISO14443_L4                             0x01U   /**< Option to disable ISO14443 Layer 4 protocol. */
/** @} */

/**
 * \brief Performs a configuration for ISO1443-4 enabling in Security Level 1.
 *
 * \return Status code
 * \retval #PH_ERR_SUCCESS Operation successful.
 * \retval Other Depending on implementation and underlaying component.
 */
phStatus_t phalMfpEVx_SetConfigSL1(
    void *pDataParams,                                                  /**< [In] Pointer to this layer's parameter structure. */
    uint8_t bOption                                                     /**< [In] Option byte encoding the configuration to be set.
                                                                             *          \arg #PHAL_MFPEVX_ENABLE_ISO14443_L4
                                                                             *          \arg #PHAL_MFPEVX_DISABLE_ISO14443_L4
                                                                             */
);

/**
 * \brief Performs read of the TMAC block in security layer 1 with ISO14443 Layer 3 activated.
 *
 * \return Status code
 * \retval #PH_ERR_SUCCESS Operation successful.
 * \retval Other Depending on implementation and underlaying component.
 */
phStatus_t phalMfpEVx_ReadSL1TMBlock(
    void *pDataParams,                                                  /**< [In] Pointer to this layer's parameter structure. */
    uint16_t wBlockNr,                                                  /**< [In] PICC TM  block number from which the data should be read. */
    uint8_t *pBlocks                                                   /**< [Out] The data read from the specified block number. The buffer will
                                                                             *         contain 16 bytes information.
                                                                             */
);

/**
 * \brief Performs a VCSupportLastISOL3 command operation. This command is a special variant of virtual card operation.
 * This command can be sent after a ISO14443-3 activation.
 *
 * \return Status code
 * \retval #PH_ERR_SUCCESS Operation successful.
 * \retval Other Depending on implementation and underlaying component.
 */
phStatus_t phalMfpEVx_VCSupportLastISOL3(
    void *pDataParams,                                                  /**< [In] Pointer to this layer's parameter structure. */
    uint8_t *pIid,                                                     /**< [In] The (last) IID that the PCD presents to the PD. The buffer
                                                                             *        should have 16 bytes of information.
                                                                             */
    uint8_t *pPcdCapL3,                                                /**< [In] Capability vector of the PCD.  The buffer should have 4 bytes
                                                                             *        of information.
                                                                             */
    uint8_t *pInfo                                                      /**< [Out] One byte Information returned by PICC. */
);

#ifdef NXPBUILD__PHAL_MFPEVX_NDA
/**
 * \brief Performs a Key Change of a MIFARE Plus key. Same as phalMfpEVx_Write, but diversification input can be provided.
 *
 * \return Status code
 * \retval #PH_ERR_SUCCESS Operation successful.
 * \retval Other Depending on implementation and underlaying component.
 */
phStatus_t phalMfpEVx_ChangeKey(
    void *pDataParams,                                                  /**< [In] Pointer to this layer's parameter structure. */
    uint8_t bChangeKeyMaced,                                            /**< [In] Indicate whether the response should be maced. Based on this flag the
                                                                             *        command code will be updated.
                                                                             *          \arg #PHAL_MFPEVX_MAC_ON_RESPONSE_OFF
                                                                             *          \arg #PHAL_MFPEVX_MAC_ON_RESPONSE_ON
                                                                             */
    uint16_t wBlockNr,                                                  /**< [In] PICC block number to which the key should be changed. */
    uint16_t wKeyNumber,                                                /**< [In] Key number to be used from software or hardware keystore. */
    uint16_t wKeyVersion,                                               /**< [In] Key version to be used from software or hardware keystore. */
    uint8_t bLenDivInput,                                               /**< [In] Length of diversification input used to diversify the key.
                                                                             *        If 0, no diversification is performed.
                                                                             */
    uint8_t *pDivInput                                                  /**< [In] Diversification Input used to diversify the key. */
);

/**
 * \brief Secures the transaction by commiting the application to ReaderID specified. The encrypted Transaction MAC Reader Id
 * of the previous transaction is used by the backend that will decrypt this and check if the transaction was reported
 * to be backend or not. This command is always sent with MAC protection.
 *
 * \return Status code
 * \retval #PH_ERR_SUCCESS Operation successful.
 * \retval Other Depending on implementation and underlaying component.
 */
phStatus_t phalMfpEVx_CommitReaderID(
    void *pDataParams,                                                  /**< [In] Pointer to this layer's parameter structure. */
    uint16_t wBlockNr,                                                  /**< [In] PICC's TM protected block number. */
    uint8_t *pTMRI,                                                    /**< [In] The reader ID information to be commited. The buffer should have
                                                                             *        have 16 bytes of ID information.
                                                                             */
    uint8_t *pEncTMRI                                                  /**< [Out] Encrypted Reader ID of the previous transaction. Buffer will contain
                                                                             *         16 bytes of information.
                                                                             */
);
#endif /* NXPBUILD__PHAL_MFPEVX_NDA */

/**
 * end of group phalMfpEVx_Special
 * @}
 */

/* Mifare Plus EVx utilities. -------------------------------------------------------------------------------------------------------- */
/** \defgroup phalMfpEVx_Utilities Utilities
 * \brief These Components implement the utility interfaces required for MIFARE Plus EVx application layer. These are not commands.
 * @{
 */

/**
 * \brief Reset the libraries internal secure messaging state.
 *
 * This function must be called before interacting with the PICC to set the libraries internal card-state back to default.\n
 * E.g. when an error occurred or after a reset of the field.
 *
 * \return Status code
 * \retval #PH_ERR_SUCCESS Operation successful.
 * \retval Other Depending on implementation and underlaying component.
 */
phStatus_t phalMfpEVx_ResetSecMsgState(
    void *pDataParams                                                   /**< [In] Pointer to this layer's parameter structure. */
);

/** \name Option to configure some special operations. */
/** @{ */
#define PHAL_MFPEVX_WRAPPED_MODE                                    0xA1U   /**< Option for GetConfig/SetConfig to get/set current status of command wrapping in ISO 7816-4 APDUs. */
#define PHAL_MFPEVX_EXTENDED_APDU                                   0xA2U   /**< Option for GetConfig/SetConfig to get/set current status of extended wrapping in ISO 7816-4 APDUs. */
#define PHAL_MFPEVX_AUTH_MODE                                       0xA3U   /**< Option to set the auth mode to perform negative testing. */
/** @} */

/** \name Option to enable or disable the Wrapped or Extended APDU options. */
/** @{ */
#define PHAL_MFPEVX_DISABLE                                         0x00U   /**< Option to disable Wrapping or Extended Length APDU feature for ISO7816 support. */
#define PHAL_MFPEVX_ENABLE                                          0x01U   /**< Option to enable Wrapping or Extended Length APDU feature for ISO7816 support. */
#define PHAL_MFPEVX_DEFAULT                             PHAL_MFPEVX_DISABLE /**< Default Option value. This is equal to Disable. */
/** @} */

/** \name Option to configure the Authentication state. */
/** @{ */
#define PHAL_MFPEVX_NOTAUTHENTICATED                                0x00U    /**< Option to indicate the auth mode as MFP EVx not authenticated. */
#define PHAL_MFPEVX_SL1_MIFARE_AUTHENTICATED                        0x01U    /**< Option to indicate the auth mode as MFP EVx SL1 MIFARE Authentication mode. */
#define PHAL_MFPEVX_SL1_MFP_AUTHENTICATED                           0x02U    /**< Option to indicate the auth mode as MFP EVx SL1 Authentication mode. */
#define PHAL_MFPEVX_SL3_MFP_AUTHENTICATED                           0x03U    /**< Option to indicate the auth mode as MFP EVx SL3 Authentication mode. */
#define PHAL_MFPEVX_NOT_AUTHENTICATED_L3                            0x04U    /**< Option to indicate the auth mode as MFP EVx not authenticated in ISO Layer 3. */
#define PHAL_MFPEVX_NOT_AUTHENTICATED_L4                            0x05U    /**< Option to indicate the auth mode as MFP EVx not authenticated in ISO Layer 4. */
/** @} */

/**
 * \brief Perform a SetConfig command.
 *
 * \return Status code
 * \retval #PH_ERR_SUCCESS Operation successful.
 * \retval Other Depending on implementation and underlaying component.
 */
phStatus_t phalMfpEVx_SetConfig(
    void *pDataParams,                                                  /**< [In] Pointer to this layers parameter structure. */
    uint16_t wOption,                                                   /**< [In] Option to set.
                                                                             *          \arg #PHAL_MFPEVX_WRAPPED_MODE
                                                                             *          \arg #PHAL_MFPEVX_EXTENDED_APDU
                                                                             *          \arg #PHAL_MFPEVX_AUTH_MODE
                                                                             */
    uint16_t wValue                                                     /**< [In] Value for the selected option.
                                                                             *          \arg #PHAL_MFPEVX_WRAPPED_MODE
                                                                             *              \c #PHAL_MFPEVX_DISABLE;
                                                                             *              \c #PHAL_MFPEVX_ENABLE;
                                                                             *              \c #PHAL_MFPEVX_DEFAULT;
                                                                             *        \n
                                                                             *          \arg #PHAL_MFPEVX_EXTENDED_APDU
                                                                             *              \c #PHAL_MFPEVX_DISABLE;
                                                                             *              \c #PHAL_MFPEVX_ENABLE;
                                                                             *              \c #PHAL_MFPEVX_DEFAULT;
                                                                             *        \n
                                                                             *          \arg #PHAL_MFPEVX_AUTH_MODE
                                                                             *              \c #PHAL_MFPEVX_NOTAUTHENTICATED;
                                                                             *              \c #PHAL_MFPEVX_SL1_MIFARE_AUTHENTICATED;
                                                                             *              \c #PHAL_MFPEVX_SL1_MFP_AUTHENTICATED;
                                                                             *              \c #PHAL_MFPEVX_SL3_MFP_AUTHENTICATED;
                                                                             *              \c #PHAL_MFPEVX_NOT_AUTHENTICATED_L3;
                                                                             *              \c #PHAL_MFPEVX_NOT_AUTHENTICATED_L4;
                                                                             */
);

/**
 * \brief Perform a GetConfig command.
 *
 * \return Status code
 * \retval #PH_ERR_SUCCESS Operation successful.
 * \retval Other Depending on implementation and underlaying component.
 */
phStatus_t phalMfpEVx_GetConfig(
    void *pDataParams,                                                  /**< [In] Pointer to this layers parameter structure. */
    uint16_t wOption,                                                   /**< [In] Option to get.
                                                                             *          \arg #PHAL_MFPEVX_WRAPPED_MODE
                                                                             *          \arg #PHAL_MFPEVX_EXTENDED_APDU
                                                                             *          \arg #PHAL_MFPEVX_AUTH_MODE
                                                                             */
    uint16_t *pValue                                                   /**< [Out] Value of the selected option.
                                                                             *          \arg #PHAL_MFPEVX_WRAPPED_MODE
                                                                             *              \c #PHAL_MFPEVX_DISABLE;
                                                                             *              \c #PHAL_MFPEVX_ENABLE;
                                                                             *              \c #PHAL_MFPEVX_DEFAULT;
                                                                             *        \n
                                                                             *          \arg #PHAL_MFPEVX_EXTENDED_APDU
                                                                             *              \c #PHAL_MFPEVX_DISABLE;
                                                                             *              \c #PHAL_MFPEVX_ENABLE;
                                                                             *              \c #PHAL_MFPEVX_DEFAULT;
                                                                             *        \n
                                                                             *          \arg #PHAL_MFPEVX_AUTH_MODE
                                                                             *              \c #PHAL_MFPEVX_NOTAUTHENTICATED;
                                                                             *              \c #PHAL_MFPEVX_SL1_MIFARE_AUTHENTICATED;
                                                                             *              \c #PHAL_MFPEVX_SL1_MFP_AUTHENTICATED;
                                                                             *              \c #PHAL_MFPEVX_SL3_MFP_AUTHENTICATED;
                                                                             *              \c #PHAL_MFPEVX_NOT_AUTHENTICATED_L3;
                                                                             *              \c #PHAL_MFPEVX_NOT_AUTHENTICATED_L4;
                                                                             */
);

/**
 * \brief This is a utility API which sets the VCA structure in MFP Ev1 structure params.
 * This interface is mandatory to be called if the Virtual Card and Proximity Check features
 * are required.
 *
 * \return Status code
 * \retval #PH_ERR_SUCCESS Operation successful.
 * \retval Other Depending on implementation and underlaying component.
 */
phStatus_t phalMfpEVx_SetVCAParams(
    void *pDataParams,                                                  /**< [In] Pointer to this layers parameter structure. */
    void *pAlVCADataParams                                              /**< [In] The VCA application layer's dataparams. */
);

#ifdef NXPBUILD__PHAL_MFPEVX_NDA
/** \name Options to diversify the key. */
/** @{ */
#define PHAL_MFPEVX_DIVERSIFICATION_OFF                             0xFFFFU /**< Option to disable key diversification. */
#define PHAL_MFPEVX_DIVERSIFICATION_ON                              0x0000U /**< Option to enable key diversification. */
/** @} */

/**
 * \brief Calculate TMV. This utility is only valid if Mifare Plus EVx is configured as Software.
 *
 * \return Status code
 * \retval #PH_ERR_SUCCESS Operation successful.
 * \retval Other Depending on implementation and underlaying component.
 */
phStatus_t phalMfpEVx_CalculateTMV(
    void *pDataParams,                                                  /**< [In] Pointer to this layers parameter structure. */
    uint16_t wOption,                                                   /**< [In] Diversification option.
                                                                             *          \arg #PHAL_MFPEVX_DIVERSIFICATION_OFF
                                                                             *          \arg #PHAL_MFPEVX_DIVERSIFICATION_ON
                                                                             */
    uint16_t wKeyNoTMACKey,                                             /**< [In] Key number to be used from software keystore. */
    uint16_t wKeyVerTMACKey,                                            /**< [In] Key version to be used from software keystore. */
    uint16_t wRamKeyNo,                                                 /**< [In] Key number of Destination Key where the computed session TMAC key will be stored.
                                                                             *        To be used for SAM AV3 only.
                                                                             */
    uint16_t wRamKeyVer,                                                /**< [In] Key version of Destination Key where the computed session TMAC key will be stored.
                                                                             *        To be used for SAM AV3 only.
                                                                             */
    uint8_t *pDivInput,                                                 /**< [In] Diversification input to diversify TMACKey. */
    uint8_t bDivInputLen,                                               /**< [In] Length of byte available in DivInput buffer. */
    uint8_t *pTMC,                                                     /**< [In] 4 bytes Transaction MAC Counter. It should be 1 time subtracted from
                                                                             *        the actual value and should be LSB first.
                                                                             */
    uint8_t *pUid,                                                      /**< [In] UID of the card. */
    uint8_t bUidLen,                                                    /**< [In] Length of UID supplied. */
    uint8_t *pTMI,                                                      /**< [In] Transaction MAC Input. */
    uint16_t wTMILen,                                                   /**< [In] Length of bytes available in TMI buffer. */
    uint8_t *pTMV                                                       /**< [Out] The computed Transaction MAC Value. */
);

/**
 * \brief Decrypt Reader ID. This utility is only valid if Mifare Plus EVx is configured as Software.
 *
 * \return Status code
 * \retval #PH_ERR_SUCCESS Operation successful.
 * \retval Other Depending on implementation and underlaying component.
 */
phStatus_t phalMfpEVx_DecryptReaderID(
    void *pDataParams,                                                  /**< [In] Pointer to this layers parameter structure. */
    uint16_t wOption,                                                   /**< [In] Diversification option.
                                                                             *          \arg #PHAL_MFPEVX_DIVERSIFICATION_OFF
                                                                             *          \arg #PHAL_MFPEVX_DIVERSIFICATION_ON
                                                                             */
    uint16_t wKeyNoTMACKey,                                             /**< [In] Key number to be used from software keystore. */
    uint16_t wKeyVerTMACKey,                                            /**< [In] Key version to be used from software keystore. */
    uint16_t wRamKeyNo,                                                 /**< [In] Key number of Destination Key where the computed session TMAC key will be stored.
                                                                             *        To be used for SAM AV3 only.
                                                                             */
    uint16_t wRamKeyVer,                                                /**< [In] Key version of Destination Key where the computed session TMAC key will be stored.
                                                                             *        To be used for SAM AV3 only.
                                                                             */
    uint8_t *pDivInput,                                                 /**< [In] Diversification input to diversify TMACKey. */
    uint8_t bDivInputLen,                                               /**< [In] Length of byte available in DivInput buffer. */
    uint8_t *pTMC,                                                     /**< [In] 4 bytes Transaction MAC Counter. It should be 1 time subtracted from
                                                                             *        the actual value and shold be LSB first.
                                                                             */
    uint8_t *pUid,                                                      /**< [In] UID of the card. */
    uint8_t bUidLen,                                                    /**< [In] Length of UID supplied. */
    uint8_t *pEncTMRI,                                                  /**< [In] Encrypted Transaction MAC ReaderID of the latest successful transaction. */
    uint8_t *pTMRIPrev                                                  /**< [Out] Decrypted Reader ID of the last successful transaction. */
);
#endif /* NXPBUILD__PHAL_MFPEVX_NDA */

/**
 * end of group phalMfpEVx_Utilities
 * @}
 */

/**
 * end of group phalMfpEVx
 * @}
 */

#endif /* NXPBUILD__PHAL_MFPEVX */

#ifdef __cplusplus
} /* Extern C */
#endif

#endif /* PHALMFPEVX_H */
