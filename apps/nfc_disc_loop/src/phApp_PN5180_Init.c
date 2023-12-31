/*----------------------------------------------------------------------------*/
/* Copyright 2020 NXP                                                         */
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

/* Status header */
#include <hal/hal_gpio.h>
#include <nxp_nfc/ph_Status.h>
#include "phApp_Init.h"

#ifdef NXPBUILD__PHHAL_HW_PN5180

#include "nxp_nfc/BoardSelection.h"

/* HAL specific headers */
#include <nxp_nfc/phhalHw_Pn5180_Instr.h>

/*******************************************************************************
**   Function Declarations
*******************************************************************************/

/*******************************************************************************
**   Global Variable Declaration
*******************************************************************************/
phbalReg_Type_t                 sBalParams;
phhalHw_Pn5180_DataParams_t    *pHal;

#ifdef NXPBUILD__PHHAL_HW_TARGET
/* Parameters for L3 activation during Autocoll */
extern uint8_t  sens_res[2]    ;
extern uint8_t  nfc_id1[3]     ;
extern uint8_t  sel_res        ;
extern uint8_t  nfc_id3        ;
extern uint8_t  poll_res[18]   ;
#endif /* NXPBUILD__PHHAL_HW_TARGET */

/*******************************************************************************
**   Function Definitions
*******************************************************************************/
/**
* This function will initialize Hal Target Config
*/
phStatus_t
phApp_HALConfigAutoColl(void)
{
#ifdef NXPBUILD__PHHAL_HW_TARGET
  phStatus_t wStatus;
  uint8_t aCmd[1] = {0x01};   /* Enable Random UID feature on Pn5180/Pn5190 FW. */

  /* Set Listen Parameters in HAL Buffer used during Autocoll */
  wStatus = phhalHw_Pn5180_SetListenParameters(
          pHal,
          &sens_res[0],
          &nfc_id1[0],
          sel_res,
          &poll_res[0],
          nfc_id3);
  CHECK_SUCCESS(wStatus);

  if (pHal->wFirmwareVer < 0x308) {
    /* With Pn5180 FW version < 3.8, static UID is supported by default. */
    aCmd[0] = 0x00;
  }
  /* Enabling the Random UID in 5180 EEPROM */
  wStatus = phhalHw_Pn5180_Instr_WriteE2Prom(
          (phhalHw_Pn5180_DataParams_t *) pHal,
          0x58,
          aCmd,
          0x01
      );

  CHECK_SUCCESS(wStatus);
#endif /* NXPBUILD__PHHAL_HW_TARGET */
  return PH_ERR_SUCCESS;
}

/* Configure LPCD (for PN5180) */
phStatus_t
phApp_ConfigureLPCD(void)
{
  /**
   * PHHAL_HW_CONFIG_SET_LPCD_WAKEUPTIME_MS  0x0070U     //< Used value for wakeup counter in msecs, i.e. after this amount of time IC will wakes up from standby.
   * PHHAL_HW_CONFIG_LPCD_MODE               0x0071U     //< Used to set options  PHHAL_HW_PN5180_LPCD_MODE_DEFAULT or PHHAL_HW_PN5180_LPCD_MODE_POWERDOWN_GUARDED
   * PHHAL_HW_CONFIG_LPCD_REF                0x0072U     //< Used to set or get LPCD Ref
   */
  phStatus_t status = PH_ERR_SUCCESS;
  uint16_t wConfig = PHHAL_HW_CONFIG_LPCD_REF;
  uint16_t wValue;
  uint8_t bLPCD_Threshold_EEPROMAddress = 0x37;
  uint8_t bLPCD_Threshold = 0x10;
  wValue = PHHAL_HW_PN5180_LPCD_MODE_POWERDOWN;
  wConfig = PHHAL_HW_CONFIG_LPCD_MODE;

  //status = phhalHw_Pn5180_Int_LPCD_GetConfig(pHal, wConfig, &wValue);
  status = phhalHw_Pn5180_Instr_WriteE2Prom(pHal, bLPCD_Threshold_EEPROMAddress, &bLPCD_Threshold,
          1);
  CHECK_SUCCESS(status);
  status = phhalHw_Pn5180_Int_LPCD_SetConfig(
          pHal,
          wConfig,
          wValue
      );

  return status;
}

void
CLIF_IRQHandler(void)
{
  hal_gpio_irq_disable(PHDRIVER_PIN_IRQ);
  /* Call application registered callback. */
  if (pHal->pRFISRCallback != NULL) {
    pHal->pRFISRCallback(pHal);
  }

  hal_gpio_irq_enable(PHDRIVER_PIN_IRQ);
}
#endif /* NXPBUILD__PHHAL_HW_PN5180 */

/******************************************************************************
**                            End Of File
******************************************************************************/
