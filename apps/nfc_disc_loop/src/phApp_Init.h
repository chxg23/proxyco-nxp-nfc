/*----------------------------------------------------------------------------*/
/* Copyright 2016-2020 NXP                                                    */
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
* Example Source abstracting component header specific to HW used in the examples
* This file shall be present in all examples. A customer does not need to touch/modify this file. This file
* purely depends on the phNxpBuild_Lpc.h or phNxpBuild_App.h
* The phAppInit.h externs the component data structures initialized here that is in turn included by the core examples.
* The core example shall not use any other variable defined here except the RdLib component data structures(as explained above)
* The RdLib component initialization requires some user defined data and function pointers.
* These are defined in the respective examples and externed here.
*
* Keystore and Crypto initialization needs to be handled by application.
*
* $Author$
* $Revision$ (v06.11.00)
* $Date$
*
*/

/*
 * @Copyright Proxy
 */
#ifndef PHAPP_INIT_H
#define PHAPP_INIT_H

#include <console/console.h>

/* Status header */
#include <nxp_nfc/ph_Status.h>

/* NFCLIB Header */
#include <nxp_nfc/phNfcLib.h>

/* LLCP header */
#include <nxp_nfc/phlnLlcp.h>

/* SNEP header */
#include <nxp_nfc/phnpSnep.h>

#include <nxp_nfc/phbalReg.h>
/* Check for LPC1769 controller based boards. */
#if defined(PHDRIVER_LPC1769PN5180_BOARD) || \
    defined(PHDRIVER_LPC1769RC663_BOARD)  || \
    defined(PHDRIVER_LPC1769PN5190_BOARD) || \
    defined(PHDRIVER_NRF5340DK_PN5180_BOARD)
#define PHDRIVER_LPC1769
#endif

#define  DEBUG_PRINTF console_printf

/*******************************************************************************
**   Global Variable Declaration
*******************************************************************************/

#define PH_NFCRDLIB_EXAMPLE_LPCD_GUARDTIME      100           /* LPCD Guard time(T4) in milli-seconds configured by application for Rc663. */
#define PH_NFCRDLIB_EXAMPLE_LPCD_RFON_TIME      56            /* LPCD RFON time(T3) in micro-seconds configured by application for Rc663. */

/* HAL & BAL declarations */

extern phbalReg_Type_t sBalParams;

#ifdef NXPBUILD__PHLN_LLCP_SW
extern phlnLlcp_Sw_DataParams_t           slnLlcp;            /* LLCP component */
#endif /* NXPBUILD__PHLN_LLCP_SW */

#ifdef NXPBUILD__PHHAL_HW_PN5180
extern phhalHw_Pn5180_DataParams_t    *pHal;
#endif

#ifdef NXPBUILD__PHHAL_HW_PN5190
extern phhalHw_Pn5190_DataParams_t    *pHal;
#endif

#ifdef NXPBUILD__PHHAL_HW_RC663
extern phhalHw_Rc663_DataParams_t     *pHal;
#endif

#ifdef NXPBUILD__PHHAL_HW_PN7462AU
extern phhalHw_PN7462AU_DataParams_t *pHal;
#endif

/**************************************************Prints if error is detected**************************************************************/
#define DETECT_ERROR 0

#if DETECT_ERROR
#define DEBUG_ERROR_PRINT(x) x
#define PRINT_INFO(...) console_printf(__VA_ARGS__)
#else
#define DEBUG_ERROR_PRINT(x)
#define PRINT_INFO(...)
#endif

#define CHECK_STATUS(x)                                      \
    if ((x) != PH_ERR_SUCCESS)                               \
{                                                            \
    console_printf("Line: %u   Error - (0x%04lX) has occurred : 0xCCEE CC-Component ID, EE-Error code. Refer-ph_Status.h\n", __LINE__, (unsigned long)(x));    \
}

/* prints if error is detected */
#define CHECK_SUCCESS(x)              \
    if ((x) != PH_ERR_SUCCESS)        \
{                                     \
    console_printf("\nLine: %u   Error - (0x%04lX) has occurred : 0xCCEE CC-Component ID, EE-Error code. Refer-ph_Status.h\n ", __LINE__, (unsigned long)(x)); \
    return (x);                       \
}

/* prints if error is detected */
#define CHECK_NFCLIB_STATUS(x)                               \
    if ((x) != PH_NFCLIB_STATUS_SUCCESS)                     \
{                                                            \
    console_printf("\nLine: %u   Error - (0x%04lX) has occurred in NFCLIB\n ", __LINE__, (unsigned long)(x)); \
}

/*********************************************************************************************************************************************/

/*******************************************************************************
**   Function Declarations
*******************************************************************************/
extern phStatus_t phApp_Comp_Init(void *pDiscLoopParams);
extern phStatus_t phApp_HALConfigAutoColl(void);
extern phStatus_t phApp_ConfigureLPCD(void);
extern void phApp_PrintTagInfo(phacDiscLoop_Sw_DataParams_t *pDataParams, uint16_t wNumberOfTags,
    uint16_t wTagsDetected);
extern void phApp_PrintTech(uint8_t TechType);
extern void phApp_Print_Buff(uint8_t *pBuff, uint8_t num);
extern void PrintErrorInfo(phStatus_t wStatus);
extern phStatus_t phApp_Configure_IRQ();

#ifdef PH_PLATFORM_HAS_ICFRONTEND
extern void CLIF_IRQHandler(void);
#endif /* PH_PLATFORM_HAS_ICFRONTEND */

#endif /* PHAPP_INIT_H */
