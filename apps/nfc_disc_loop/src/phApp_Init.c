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
* Example Source abstracting component data structure and code initialization and code specific to HW used in the examples
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

/* Status header */
#include <nxp_nfc/ph_Status.h>
#include "phApp_Init.h"

/* LLCP header */
#include <nxp_nfc/phlnLlcp.h>

#include <console/console.h>

#ifdef PH_PLATFORM_HAS_ICFRONTEND
#include "nxp_nfc/BoardSelection.h"
#endif

/*******************************************************************************
**   Function Declarations
*******************************************************************************/

phStatus_t phApp_Configure_IRQ();

/*******************************************************************************
**   Global Variable Declaration
*******************************************************************************/

#ifdef NXPBUILD__PHLN_LLCP_SW
phlnLlcp_Sw_DataParams_t           slnLlcp;            /* LLCP component */
#endif /* NXPBUILD__PHLN_LLCP_SW */

/* General information bytes to be sent with ATR Request */
#if defined(NXPBUILD__PHPAL_I18092MPI_SW) || defined(NXPBUILD__PHPAL_I18092MT_SW)
uint8_t aLLCPGeneralBytes[36] = { 0x46, 0x66, 0x6D,
        0x01, 0x01, 0x10,     /*VERSION*/
        0x03, 0x02, 0x00, 0x01, /*WKS*/
        0x04, 0x01, 0xF1      /*LTO*/
    };
uint8_t   bLLCPGBLength = 13;
#endif

/* ATR Response or ATS Response holder */
#if defined(NXPBUILD__PHPAL_I14443P4A_SW)     || \
    defined(NXPBUILD__PHPAL_I18092MPI_SW)
uint8_t    aResponseHolder[64];
#endif

#ifndef CHECK_SUCCESS
/* prints if error is detected */
#define CHECK_SUCCESS(x)              \
    if ((x) != PH_ERR_SUCCESS)        \
{                                     \
    console_printf("\nLine: %d   Error - (0x%04X) has occurred : 0xCCEE CC-Component ID, EE-Error code. Refer-ph_Status.h\n ", __LINE__, (x)); \
    return (x);                       \
}
#endif

/*******************************************************************************
**   Function Definitions
*******************************************************************************/

/**
* This function will initialize Reader LIbrary Component
*/
phStatus_t
phApp_Comp_Init(void *pDiscLoopParams)
{
  phStatus_t wStatus = PH_ERR_SUCCESS;
#if defined(NXPBUILD__PHPAL_I18092MPI_SW) || defined(NXPBUILD__PHPAL_I18092MT_SW) || \
    defined(NXPBUILD__PHAC_DISCLOOP_TYPEA_P2P_TAGS) || defined(NXPBUILD__PHAC_DISCLOOP_TYPEA_P2P_ACTIVE) || \
    defined(NXPBUILD__PHAC_DISCLOOP_TYPEA_I3P4_TAGS) || defined(NXPBUILD__PHAC_DISCLOOP_TYPEF_P2P_TAGS) || \
    defined(NXPBUILD__PHAC_DISCLOOP_TYPEF212_P2P_ACTIVE) || defined(NXPBUILD__PHAC_DISCLOOP_TYPEF424_P2P_ACTIVE)

  phacDiscLoop_Sw_DataParams_t *pDiscLoop = (phacDiscLoop_Sw_DataParams_t *)pDiscLoopParams;
#endif

  /* Initialize the LLCP component */
#ifdef NXPBUILD__PHLN_LLCP_SW
  slnLlcp.sLocalLMParams.wMiu = 0x00; /* 128 bytes only */
  slnLlcp.sLocalLMParams.wWks = 0x11; /* SNEP & LLCP */
  slnLlcp.sLocalLMParams.bLto = 100; /* Maximum LTO */
  slnLlcp.sLocalLMParams.bOpt = 0x02;
  slnLlcp.sLocalLMParams.bAvailableTlv = PHLN_LLCP_TLV_MIUX_MASK | PHLN_LLCP_TLV_WKS_MASK |
      PHLN_LLCP_TLV_LTO_MASK | PHLN_LLCP_TLV_OPT_MASK;

  wStatus = phlnLlcp_Sw_Init(
          &slnLlcp,
          sizeof(phlnLlcp_Sw_DataParams_t),
          aLLCPGeneralBytes,
          &bLLCPGBLength);
#endif /* NXPBUILD__PHLN_LLCP_SW */

#ifdef NXPBUILD__PHAC_DISCLOOP_SW
#if defined(NXPBUILD__PHPAL_I18092MPI_SW) || defined(NXPBUILD__PHPAL_I18092MT_SW)
  /* Assign the GI for Type A */
  pDiscLoop->sTypeATargetInfo.sTypeA_P2P.pGi       = (uint8_t *)aLLCPGeneralBytes;
  pDiscLoop->sTypeATargetInfo.sTypeA_P2P.bGiLength = bLLCPGBLength;
  /* Assign the GI for Type F */
  pDiscLoop->sTypeFTargetInfo.sTypeF_P2P.pGi       = (uint8_t *)aLLCPGeneralBytes;
  pDiscLoop->sTypeFTargetInfo.sTypeF_P2P.bGiLength = bLLCPGBLength;
#endif

#if defined(NXPBUILD__PHAC_DISCLOOP_TYPEA_P2P_TAGS) || defined(NXPBUILD__PHAC_DISCLOOP_TYPEA_P2P_ACTIVE)
  /* Assign ATR response for Type A */
  pDiscLoop->sTypeATargetInfo.sTypeA_P2P.pAtrRes   = aResponseHolder;
#endif
#if defined(NXPBUILD__PHAC_DISCLOOP_TYPEF_P2P_TAGS) ||  defined(NXPBUILD__PHAC_DISCLOOP_TYPEF212_P2P_ACTIVE) || \
    defined(NXPBUILD__PHAC_DISCLOOP_TYPEF424_P2P_ACTIVE)
  /* Assign ATR response for Type F */
  pDiscLoop->sTypeFTargetInfo.sTypeF_P2P.pAtrRes   = aResponseHolder;
#endif
#ifdef NXPBUILD__PHAC_DISCLOOP_TYPEA_I3P4_TAGS
  /* Assign ATS buffer for Type A */
  pDiscLoop->sTypeATargetInfo.sTypeA_I3P4.pAts     = aResponseHolder;
#endif /* NXPBUILD__PHAC_DISCLOOP_TYPEA_I3P4_TAGS */
#endif /* NXPBUILD__PHAC_DISCLOOP_SW */
  return wStatus;
}
phStatus_t
phApp_Configure_IRQ()
{
#ifdef PH_PLATFORM_HAS_ICFRONTEND
  int rc = hal_gpio_irq_init(PHDRIVER_PIN_IRQ, (hal_gpio_irq_handler_t)CLIF_IRQHandler, NULL,
          PIN_IRQ_TRIGGER_TYPE, PHDRIVER_PIN_IRQ_PULL_CFG);
  hal_gpio_irq_enable(PHDRIVER_PIN_IRQ);
  if (rc) {
    return PH_ERR_PARAMETER_OVERFLOW;
  }
#endif /* #ifdef PH_PLATFORM_HAS_ICFRONTEND */

  return PH_ERR_SUCCESS;
}
/******************************************************************************
**                            End Of File
******************************************************************************/
