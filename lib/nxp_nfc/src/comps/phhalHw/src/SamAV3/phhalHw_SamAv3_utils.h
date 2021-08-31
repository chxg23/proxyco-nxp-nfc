#ifndef PHHALHW_SAMAV3_UTILS_H
#define PHHALHW_SAMAV3_UTILS_H

#include <assert.h>

#include <nxp_nfc/ph_Status.h>
#include <nxp_nfc/ph_TypeDefs.h>

#define PHHAL_HW_SAMAV3_ISO7816_ASSERT assert

/** \defgroup phhalHw_SamAV3_Utils Utils
 * \brief Utility implementations.
 * @{
 */

/**
 * \brief Get the length of LC and also check is LC and LE are present in the command frame.
 *
 * \return Status code
 * \retval #PH_ERR_SUCCESS Operation successful.
 * \retval Other Depending on implementation and underlaying component.
 */
phStatus_t phhalHw_SamAV3_Utils_GetCheckLcLe(
    uint8_t *pCmd,														/**< [In] Address of buffer that contains the command. */
    uint16_t wCmdLen,													/**< [In] Length of the command. */
    uint8_t *pIsLcPresent,												/**< [Out] LC byte presence indicator. */
    uint8_t *pLcLen,													/**< [Out] Length of the payload of the command. */
    uint8_t *pIsLePresent												/**< [Out] LE byte presence indicator. */
);

/**
 * \brief Truncate a 16-Bytes MAC buffer into a 8-Bytes Buffer
 *
 * \return Status code
 * \retval #PH_ERR_SUCCESS Operation successful.
 * \retval Other Depending on implementation and underlaying component.
 */
phStatus_t phhalHw_SamAV3_Utils_TruncateMacBuffer(
    uint8_t *pIoBuffer,												/**< [In, Out] The 16 bytes of computed MAC as input and  8 bytes of truncated MAC as output. */
    uint8_t *pMacLen													/**< [In, Out] Non-Truncated MAC length as input and Truncated MAC length as output. */
);

/**
 * \brief Update LC byte according to data already available in Buffer
 * \return Status code
 * \retval #PH_ERR_SUCCESS Operation successful.
 * \retval Other Depending on implementation and underlaying component.
 */
phStatus_t phhalHw_SamAV3_Utils_UpdateLc(
    phhalHw_SamAV3_DataParams_t
    *pDataParams							/**< [In] Pointer to this layer's parameter structure. */
);

/**
 * \brief Update P1 byte according to data already available in Buffer
 * \return Status code
 * \retval #PH_ERR_SUCCESS Operation successful.
 * \retval Other Depending on implementation and underlaying component.
 */
phStatus_t phhalHw_SamAV3_Utils_UpdateP1(
    phhalHw_SamAV3_DataParams_t
    *pDataParams,							/**< [In] Pointer to this layer's parameter structure. */
    uint8_t p1															/**< [In] Value for P1. */
);

/**
 * \brief Update P1byte according to data already available in Buffer
 * \return Status code
 * \retval #PH_ERR_SUCCESS Operation successful.
 * \retval Other Depending on implementation and underlaying component.
 */
phStatus_t phhalHw_SamAV3_Utils_UpdateP2(
    phhalHw_SamAV3_DataParams_t
    *pDataParams,							/**< [In] Pointer to this layer's parameter structure. */
    uint8_t p2															/**< [In] Value for P1. */
);

/**
 * \brief Parse Status Word Sw1Sw2 from the SAM and assign a equivalent custom code.
 *
 * \return Status code
 * \retval #PH_ERR_SUCCESS Operation successful.
 */
phStatus_t phhalHw_SamAV3_Utils_ResolveErrorCode(
    uint8_t *pSw1Sw2													/**< [In] Pointer to the status code sent by the SAM. */
);

/**
 * \brief Session key generation for LockUnlock command.
 * \return Status code
 * \retval #PH_ERR_SUCCESS Operation successful.
 */
phStatus_t phhalHw_SamAV3_Utils_GenerateHostAuthSessionKey(
    phhalHw_SamAV3_DataParams_t
    *pDataParams,							/**< [In] Pointer to this layer's parameter structure. */
    uint8_t bKeyType,													/**< [In] The key type to be used (AES128 or AES192) */
    uint8_t *pRnd1,													/**< [In] Pointer to Rnd1 data. */
    uint8_t *pRnd2,													/**< [In] Pointer to Rnd2 data. */
    uint8_t *pSessionKey,												/**< [Out] The generated session key. */
    uint8_t *pKeyLen													/**< [Out] Length of the Session key. */
);

/**
 * \brief Session key generation for AuthenticateHost command.
 * \return Status code
 * \retval #PH_ERR_SUCCESS Operation successful.
 */
phStatus_t phhalHw_SamAV3_Utils_GenerateSessionKey(
    phhalHw_SamAV3_DataParams_t
    *pDataParams,							/**< [In] Pointer to this layer's parameter structure. */
    uint8_t bKeyType,													/**< [In] The key type to be used (AES128 or AES192) */
    uint8_t *pRnd1,													/**< [In] Pointer to Rnd1 data. */
    uint8_t *pRnd2,													/**< [In] Pointer to Rnd2 data. */
    uint8_t *pSessionEncKey,											/**< [Out] The generate session encryption key. */
    uint8_t *pSessionMacKey,											/**< [Out] The generate session mac key. */
    uint8_t *pKeyLen													/**< [Out] Length of the Session key. */
);

/** \name Macros to indicate the method to be used for session key generation. */
/* @{ */
#define PHHAL_HW_CMD_SAMAV3_SESSION_KEY_ENC								0U	/**< Macro to represent the mode to generate Session ENC keys. */
#define PHHAL_HW_CMD_SAMAV3_SESSION_KEY_MAC								1U	/**< Macro to represent the mode to generate Session MAC keys. */
/* @} */

/**
* \brief Session key generation for the command PLUpload.
 *
* \return Status code
* \retval #PH_ERR_SUCCESS Operation successful.
*/
phStatus_t phhalHw_SamAV3_Utils_GetSessionUploadKey(
    phhalHw_SamAV3_DataParams_t
    *pDataParams,							/**< [In] Pointer to this layer's parameter structure. */
    uint8_t bMode,														/**< [In] Mode to use for session key generation. Can be one of the below options.
																			 *		  \arg #PHHAL_HW_CMD_SAMAV3_SESSION_KEY_ENC
																			 *		  \arg #PHHAL_HW_CMD_SAMAV3_SESSION_KEY_MAC
																			 */
    uint16_t wUploadCtr,												/**< [In] The upload counter value. */
    uint8_t bKeyNo,														/**< [In] Key number using which the key will be taken from keystore for macing the session vectors. */
    uint8_t bKeyVer,													/**< [In] Key version to be used. */
    uint8_t *pSessionKey,												/**< [Out] The generated session key. */
    uint8_t *pKeyType													/**< [Out] The type of key used for session key generation. */
);

/**
 * end of phhalHw_SamAV3_Utils
 * @}
 */

#endif /* PHHALHW_SAMAV3_UTILS_H */
