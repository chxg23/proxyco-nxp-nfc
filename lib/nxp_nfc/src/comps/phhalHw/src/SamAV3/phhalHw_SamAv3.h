#ifndef PHHALHW_SAMAV3_H
#define PHHALHW_SAMAV3_H

#include <nxp_nfc/ph_Status.h>
#include <nxp_nfc/phhalHw.h>
#include <nxp_nfc/phbalReg.h>
#include <hal/hal_uart.h>
#include "../../../phbalReg/src/T1SamAV3/phbalReg_ISO7816.h"

#ifdef NXPBUILD__PHHAL_HW_SAMAV3

#define PHHAL_HW_SAMAV3_MAX_TIMER_FREQ_16MHz 			16000000
#define PHHAL_HW_SAMAV3_MAX_TIMER_FREQ_1_778MHz			PHHAL_HW_SAMAV3_MAX_TIMER_FREQ_16MHz/9
#define PHHAL_HW_SAMAV3_ATR_MSG_LENGHT 					28

#define PHHAL_HW_SAMAV3_DEFAULT_TIMEOUT					150U    /**< Default timeout in microseconds. */
#define PHHAL_HW_SAMAV3_HSM_AES_NO_CHAINING				0x00U
#define PHHAL_HW_SAMAV3_HSM_AES_CHAINING_NO_SM			0x0FU
#define PHHAL_HW_SAMAV3_HSM_AES_CHAINING				0xFFU
#define PHHAL_HW_SAMAV3_HSM_AES_NO_SM					0x00U
#define PHHAL_HW_SAMAV3_HSM_AES_MAC						0x0FU
#define PHHAL_HW_SAMAV3_HSM_AES_ENC						0xF0U

#define PHHAL_HW_SAMAV3_KEYENTRY_DESFIRE_AID_POS		48
#define PHHAL_HW_SAMAV3_KEYENTRY_DESFIRE_KEYNUM_POS		51
#define PHHAL_HW_SAMAV3_KEYENTRY_REFNUM_CEK_POS			52
#define PHHAL_HW_SAMAV3_KEYENTRY_KEYVER_CEK_POS			53
#define PHHAL_HW_SAMAV3_KEYENTRY_REFNUM_KUC_POS			54
#define PHHAL_HW_SAMAV3_KEYENTRY_CONFIG_SET_POS			55
#define PHHAL_HW_SAMAV3_KEYENTRY_KEY_A_VERSION_POS		57
#define PHHAL_HW_SAMAV3_KEYENTRY_KEY_B_VERSION_POS		58
#define PHHAL_HW_SAMAV3_KEYENTRY_KEY_C_VERSION_POS		59
#define PHHAL_HW_SAMAV3_KEYENTRY_CONFIG_SET2_POS		60

#define PHHAL_HW_SAMAV3_AUTHMODE_KEYA					0x60
#define PHHAL_HW_SAMAV3_AUTHMODE_KEYB					0x61

phStatus_t phhalHw_SamAV3_Exchange(phhalHw_SamAV3_DataParams_t * pDataParams, uint16_t wOption, uint8_t * pTxBuffer, uint16_t wTxLength,
	uint8_t ** ppRxBuffer, uint16_t * pRxLength);

phStatus_t phhalHw_SamAV3_GetConfig(phhalHw_SamAV3_DataParams_t * pDataParams, uint16_t wConfig, uint16_t * pValue);

phStatus_t phhalHw_SamAV3_SetMinFDT(phhalHw_SamAV3_DataParams_t * pDataParams, uint16_t wValue);

phStatus_t phhalHw_SamAV3_SetConfig(phhalHw_SamAV3_DataParams_t * pDataParams, uint16_t wConfig, uint16_t wValue);

phStatus_t phhalHw_SamAV3_ApplyProtocolSettings(phhalHw_SamAV3_DataParams_t * pDataParams, uint8_t bCardType);

phStatus_t phhalHw_SamAV3_ReadRegister(phhalHw_SamAV3_DataParams_t * pDataParams, uint8_t bAddress, uint8_t * pValue);

phStatus_t phhalHw_SamAV3_WriteRegister(phhalHw_SamAV3_DataParams_t * pDataParams, uint8_t bAddress, uint8_t bValue);

phStatus_t phhalHw_SamAV3_FieldReset(phhalHw_SamAV3_DataParams_t * pDataParams);

phStatus_t phhalHw_SamAV3_FieldOn(phhalHw_SamAV3_DataParams_t * pDataParams);

phStatus_t phhalHw_SamAV3_Wait(phhalHw_SamAV3_DataParams_t * pDataParams, uint8_t bUnit, uint16_t wTimeout);

phStatus_t phhalHw_SamAV3_MfcAuthenticate(phhalHw_SamAV3_DataParams_t * pDataParams, uint8_t bBlockNo, uint8_t bKeyType, uint8_t * pKey,
	uint8_t * pUid);

phStatus_t phhalHw_SamAV3_MfcAuthenticateKeyNo(phhalHw_SamAV3_DataParams_t * pDataParams, uint8_t bBlockNo, uint8_t bKeyType, uint16_t wKeyNo,
	uint16_t wKeyVer, uint8_t * pUid);

void phhalHw_SamAV3_WarmReset(void);

struct samAV3{
//  struct hal_uart uart_node;
	phbalReg_T1SamAV3_DataParams_t *bal_params;
	phhalHw_SamAV3_DataParams_t *hal_params;
	phbalReg_T1SamAV3_tml_t *tml;
};

int samAV3_create_ISO7816_dev(struct samAV3* samAV3, const char *name);

#endif /*NXPBUILD__PHHAL_HW_SAMAV3*/
#endif /* PHHALHW_PN5180_H */
