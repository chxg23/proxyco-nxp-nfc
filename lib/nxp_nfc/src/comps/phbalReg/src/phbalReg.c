/*
*         Copyright (c), NXP Semiconductors Gratkorn / Austria
*
*                     (C)NXP Semiconductors
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
* Generic BAL Component of Reader Library Framework.
* $Author: Rajendran Kumar (nxp99556) $
* $Revision: 5490 $
* $Date: 2019-02-05 15:16:07 +0530 (Tue, 05 Feb 2019) $
*
* History:
*  CHu: Generated 19. May 2009
*
*/

#include <nxp_nfc/ph_Status.h>
#include <nxp_nfc/phbalReg.h>
#include <nxp_nfc/ph_RefDefs.h>
#include <console/console.h>

#ifdef NXPBUILD__PHBAL_REG_T1SAMAV3
#include "T1SamAV3/phbalReg_SamAV3_T1.h"
#endif /* NXPBUILD__PHBAL_REG_T1SAMAV3 */

phStatus_t phbalReg_Init(
	void *pDataParams,     					/**< [In] Pointer to this layer's parameter structure phbalReg_Type_t. */
    uint16_t wSizeOfDataParams,              /**< [In] Size of this layer's parameter structure. */
	void *attr
)
{
    phStatus_t PH_MEMLOC_REM status;
    PH_LOG_HELPER_ALLOCATE_TEXT(bFunctionName, "phbalReg_Init");
    PH_LOG_HELPER_ADDSTRING(PH_LOG_LOGTYPE_INFO, bFunctionName);

    /* Check data parameters */
    if (PH_GET_COMPCODE(pDataParams) != PH_COMP_BAL)
    {
        status = PH_ADD_COMPCODE(PH_ERR_INVALID_DATA_PARAMS, PH_COMP_BAL);

        PH_LOG_HELPER_ADDSTRING(PH_LOG_LOGTYPE_INFO, bFunctionName);
        PH_LOG_HELPER_ADDPARAM_UINT16(PH_LOG_LOGTYPE_INFO, status_log, &status);
        PH_LOG_HELPER_EXECUTE(PH_LOG_OPTION_CATEGORY_LEAVE);

        return status;
    }

    /* perform operation on active layer */
    switch (PH_GET_COMPID(pDataParams))
    {
	#ifdef NXPBUILD__PHBAL_REG_T1SAMAV3
    case PHBAL_REG_T1SAMAV3_ID:
        status = phbalReg_T1SamAv3_Init((phbalReg_T1SamAV3_DataParams_t*)pDataParams, wSizeOfDataParams, (phbalReg_T1SamAV3_tml_t *)attr);
        break;
	#endif /* NXPBUILD__PHBAL_REG_T1SAMAV3 */

    default:
        status = PH_ADD_COMPCODE(PH_ERR_INVALID_DATA_PARAMS, PH_COMP_BAL);
        break;
    }

    PH_LOG_HELPER_ADDSTRING(PH_LOG_LOGTYPE_INFO, bFunctionName);
    PH_LOG_HELPER_ADDPARAM_UINT16(PH_LOG_LOGTYPE_INFO, status_log, &status);
    PH_LOG_HELPER_EXECUTE(PH_LOG_OPTION_CATEGORY_LEAVE);

	return status;
}

phStatus_t phbalReg_Exchange(
    void *pDataParams,     /**< [In] Pointer to this layer's parameter structure. */
    uint16_t wOption,      /**< [In] Option parameter, for future use. */
    uint8_t *pTxBuffer,    /**< [In] Data to transmit. */
    uint16_t wTxLength,    /**< [In] Number of bytes to transmit, if 0 Tx is not performed. */
    uint16_t wRxBufSize,   /**< [In] Size of receive buffer / Number of bytes to receive (depending on implementation). If 0 Rx is not performed.  */
    uint8_t *pRxBuffer,    /**< [Out] Received data. */
    uint16_t *pRxLength    /**< [Out] Number of received data bytes. */
)
{
    phStatus_t PH_MEMLOC_REM status;
    PH_LOG_HELPER_ALLOCATE_TEXT(bFunctionName, "phbalReg_Exchange");
    /*PH_LOG_HELPER_ALLOCATE_PARAMNAME(pDataParams);*/
    PH_LOG_HELPER_ALLOCATE_PARAMNAME(wOption);
    PH_LOG_HELPER_ALLOCATE_PARAMNAME(pTxBuffer);
    PH_LOG_HELPER_ALLOCATE_PARAMNAME(wRxBufSize);
    PH_LOG_HELPER_ALLOCATE_PARAMNAME(pRxBuffer);
    PH_LOG_HELPER_ALLOCATE_PARAMNAME(status);
    PH_LOG_HELPER_ADDSTRING(PH_LOG_LOGTYPE_INFO, bFunctionName);
    PH_LOG_HELPER_ADDPARAM_UINT16(PH_LOG_LOGTYPE_DEBUG, wOption_log, &wOption);
    PH_LOG_HELPER_ADDPARAM_BUFFER(PH_LOG_LOGTYPE_DEBUG, pTxBuffer_log, pTxBuffer, wTxLength);
    PH_LOG_HELPER_ADDPARAM_UINT16(PH_LOG_LOGTYPE_DEBUG, wRxBufSize_log, &wRxBufSize);
    PH_LOG_HELPER_EXECUTE(PH_LOG_OPTION_CATEGORY_ENTER);
    PH_ASSERT_NULL (pDataParams);
    if (wTxLength) PH_ASSERT_NULL (pTxBuffer);

    /* Check data parameters */
    if (PH_GET_COMPCODE(pDataParams) != PH_COMP_BAL)
    {
        status = PH_ADD_COMPCODE(PH_ERR_INVALID_DATA_PARAMS, PH_COMP_BAL);

        PH_LOG_HELPER_ADDSTRING(PH_LOG_LOGTYPE_INFO, bFunctionName);
        PH_LOG_HELPER_ADDPARAM_UINT16(PH_LOG_LOGTYPE_INFO, status_log, &status);
        PH_LOG_HELPER_EXECUTE(PH_LOG_OPTION_CATEGORY_LEAVE);

        return status;
    }

    /* perform operation on active layer */
    switch (PH_GET_COMPID(pDataParams))
    {
#ifdef NXPBUILD__PHBAL_REG_T1SAMAV3
    case PHBAL_REG_T1SAMAV3_ID:
        status = phbalReg_T1SamAV3_Exchange((phbalReg_T1SamAV3_DataParams_t*)pDataParams, wOption, pTxBuffer, wTxLength, wRxBufSize, pRxBuffer, pRxLength);
        break;
#endif /* NXPBUILD__PHBAL_REG_T1SAMAV3 */
    default:
    	status = PH_ADD_COMPCODE(PH_ERR_INVALID_DATA_PARAMS, PH_COMP_BAL);
    	break;
    }

    PH_LOG_HELPER_ADDSTRING(PH_LOG_LOGTYPE_INFO, bFunctionName);
#ifdef NXPBUILD__PH_LOG
    if ((((status & PH_ERR_MASK) == PH_ERR_SUCCESS) ||
        ((status & PH_ERR_MASK) == PH_ERR_SUCCESS_CHAINING) ||
        ((status & PH_ERR_MASK) == PH_ERR_SUCCESS_INCOMPLETE_BYTE))
        &&
        (pRxBuffer != NULL) &&
        (pRxLength != NULL))
    {
        PH_LOG_HELPER_ADDPARAM_BUFFER(PH_LOG_LOGTYPE_DEBUG, pRxBuffer_log, pRxBuffer, *pRxLength);
    }
#endif
    PH_LOG_HELPER_ADDPARAM_UINT16(PH_LOG_LOGTYPE_INFO, status_log, &status);
    PH_LOG_HELPER_EXECUTE(PH_LOG_OPTION_CATEGORY_LEAVE);

    return status;
}
