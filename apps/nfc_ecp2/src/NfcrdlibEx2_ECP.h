/*----------------------------------------------------------------------------*/
/* Copyright 2021 NXP                                                         */
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
* ECP application header file.
* $Author$
* $Revision$ (v06.10.00)
* $Date$
*/

#ifndef NFCRDLIBEX2_ECP_H
#define NFCRDLIBEX2_ECP_H

#include <nxp_nfc/ph_Status.h>
#include <nxp_nfc/phacDiscLoop.h>

#define LISTEN_PHASE_TIME_MS              ((300 * OS_TICKS_PER_SEC)/1000 + 1)       /* Listen Phase TIME in NFC forum mode */

#ifdef PH_OSAL_FREERTOS
#ifdef PHOSAL_FREERTOS_STATIC_MEM_ALLOCATION
#define ECP_DEMO_TASK_STACK              (1600/4)
#else /* PHOSAL_FREERTOS_STATIC_MEM_ALLOCATION */
#ifdef __PN74XXXX__
#define ECP_DEMO_TASK_STACK              (1600/4)
#else /*  __PN74XXXX__*/
#define ECP_DEMO_TASK_STACK              (1600)
#endif /*  __PN74XXXX__*/
#endif /* PHOSAL_FREERTOS_STATIC_MEM_ALLOCATION */

#define ECP_DEMO_TASK_PRIO                4
#endif /* PH_OSAL_FREERTOS */

#ifdef PH_OSAL_LINUX
#define ECP_DEMO_TASK_STACK                0x20000
#define ECP_DEMO_TASK_PRIO                 0
#endif /* PH_OSAL_LINUX */

#endif /* NFCRDLIBEX2_ECP_H */
