/*----------------------------------------------------------------------------*/
/* Copyright 2018-2021 NXP                                                    */
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
* Discovery Loop Activities for VAS (Type A Tech) polling.
* $Author$
* $Revision$ (v06.10.00)
* $Date$
*
*/

/* *****************************************************************************************************************
 * Includes
 * ***************************************************************************************************************** */
#include <nxp_nfc/ph_RefDefs.h>
#include <nxp_nfc/phacDiscLoop.h>
#include <nxp_nfc/phpalI14443p3a.h>

#ifdef NXPBUILD__PHAC_DISCLOOP_SW
#include "phacDiscLoop_Sw_Int.h"
#include "phacDiscLoop_Sw_Int_VAS.h"

/* *****************************************************************************************************************
 * Global and Static Variables
 * ***************************************************************************************************************** */

/* *****************************************************************************************************************
 * Internal Definitions
 * ***************************************************************************************************************** */
phStatus_t phacDiscLoop_Sw_DetTechTypeVAS(
    phacDiscLoop_Sw_DataParams_t *pDataParams
)
{
#if defined (NXPBUILD__PHAC_DISCLOOP_SW_ECP)
  phStatus_t PH_MEMLOC_REM wStatus;

  if ((pDataParams->bVASPollMode == PHAC_DISCLOOP_VAS_IN_COMPATIBILITY_MODE) &&
      (pDataParams->bOpeMode == RD_LIB_MODE_NFC)) {
    return PH_ADD_COMPCODE_FIXED(PH_ERR_UNSUPPORTED_COMMAND, PH_COMP_AC_DISCLOOP);
  }

  /* Reset total tags found */
  pDataParams->sVASTargetInfo.bTotalTagsFound = 0;
  /* Reset Collision Bit for Type VAS */
  pDataParams->bCollPend &= (uint8_t)~(uint8_t)PHAC_DISCLOOP_POS_BIT_MASK_VAS;

  /* Sending VASUP-A command. */
  wStatus = phpalI14443p3a_VASUpA(
          pDataParams->pPal1443p3aDataParams,
          pDataParams->sVASTargetInfo.bFormatByte,
          pDataParams->sVASTargetInfo.pCmdBytes,
          pDataParams->sVASTargetInfo.bLenCmdBytes,
          pDataParams->sVASTargetInfo.aAtva);

  if (0u != (phacDiscLoop_Sw_Int_IsValidPollStatus(wStatus))) {
    if ((wStatus & PH_ERR_MASK) == PH_ERR_COLLISION_ERROR) {
      pDataParams->bCollPend |= PHAC_DISCLOOP_POS_BIT_MASK_VAS;
    }

    (void)phhalHw_SetConfig(pDataParams->pHalDataParams, PHHAL_HW_CONFIG_TXWAIT_US, 500);

    /* Send HALT, if we support NFC Activity 1.1 or if not in NFC mode */
    if (((pDataParams->bNfcActivityVersion == PHAC_DISCLOOP_NFC_ACTIVITY_VERSION_1_1)
            && (pDataParams->bOpeMode == RD_LIB_MODE_NFC))
        || (pDataParams->bOpeMode != RD_LIB_MODE_NFC)) {
      /* Halt the detected cards. */
      PH_CHECK_ABORT_FCT(wStatus, phpalI14443p3a_HaltA(pDataParams->pPal1443p3aDataParams));
    }
    pDataParams->sVASTargetInfo.bTotalTagsFound = 1;
  } else {
    return wStatus;
  }

  return PH_ADD_COMPCODE_FIXED(PHAC_DISCLOOP_TECH_DETECTED, PH_COMP_AC_DISCLOOP);
#else /* NXPBUILD__PHAC_DISCLOOP_SW_ECP */
  return PH_ADD_COMPCODE_FIXED(PH_ERR_UNSUPPORTED_COMMAND, PH_COMP_AC_DISCLOOP);
#endif /* NXPBUILD__PHAC_DISCLOOP_SW_ECP */
}

phStatus_t phacDiscLoop_Sw_Int_CollisionResolutionVAS(
    phacDiscLoop_Sw_DataParams_t *pDataParams
)
{
  /* Not Supported */
  return PH_ADD_COMPCODE_FIXED(PH_ERR_UNSUPPORTED_COMMAND, PH_COMP_AC_DISCLOOP);
}

phStatus_t phacDiscLoop_Sw_Int_ActivateVAS(
    phacDiscLoop_Sw_DataParams_t *pDataParams,
    uint8_t bTypeVASTagIdx
)
{
  /* Not Supported */
  return PH_ADD_COMPCODE_FIXED(PH_ERR_UNSUPPORTED_COMMAND, PH_COMP_AC_DISCLOOP);
}

#endif /* NXPBUILD__PHAC_DISCLOOP_SW */
