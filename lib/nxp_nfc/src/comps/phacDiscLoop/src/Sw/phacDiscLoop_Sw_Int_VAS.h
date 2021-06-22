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
* Discovery Loop Activities for VAS polling.
* $Author$
* $Revision$ (v06.11.00)
* $Date$
*
*/

#ifndef PHACDISCLOOP_SW_INT_VAS_H
#define PHACDISCLOOP_SW_INT_VAS_H

#include <nxp_nfc/ph_Status.h>

#ifdef NXPBUILD__PHAC_DISCLOOP_SW
/* *****************************************************************************************************************
 * Includes
 * ***************************************************************************************************************** */
#include "phacDiscLoop_Sw.h"

/* *****************************************************************************************************************
 * Function Prototypes
 * ***************************************************************************************************************** */
phStatus_t phacDiscLoop_Sw_DetTechTypeVAS(
    phacDiscLoop_Sw_DataParams_t *pDataParams
);

phStatus_t phacDiscLoop_Sw_Int_CollisionResolutionVAS(
    phacDiscLoop_Sw_DataParams_t *pDataParams
);

phStatus_t phacDiscLoop_Sw_Int_ActivateVAS(
    phacDiscLoop_Sw_DataParams_t *pDataParams,
    uint8_t bTypeVASTagIdx
);
#endif /* NXPBUILD__PHAC_DISCLOOP_SW */
#endif /* PHACDISCLOOP_SW_INT_VAS_H */
