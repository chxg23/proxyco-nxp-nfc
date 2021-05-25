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
* Example Source for NfcrdlibEx2_ECP, that uses Discovery loop implementation to
* demonstrate Enhanced Contactless polling as per Specification v2.0.
* By default Discovery Loop will start polling as per Compatibility mode (similar to
* PN7150) using NFC Forum v1.0 Mode i.e. setting as per NFC Forum Activity Specification v1.0
* will be followed for Collision resolution and activation and both POLL and LISTEN (only
* for Universal device) modes of discovery loop will be enabled.
*
* Displays detected tag information(like UID, SAK, Product
* Type) and prints information when it gets activated as a target by an external Initiator/reader.
*
* By default "ENABLE_ECP_COMPATIBILITY_MODE" macro is enabled to start polling as per
* ECP specification v2.0 and NFC Forum Activity Specification v1.0 to start the polling
* sequence in-line with PN7150 behavior.
*
* NFC Forum Mode: Whenever multiple technologies are detected, example will select first
* detected technology to resolve. Example will activate device at index zero whenever multiple
* device is detected.
*
* For EMVCo profile, this example provide VAS polling in EMVCo polling loop.
*
* Please refer Readme.txt file for Hardware Pin Configuration, Software Configuration and steps to build and
* execute the project which is present in the same project directory.
*
* $Author$
* $Revision$ (v06.10.00)
* $Date$
*/

/*
 * @Copyright Proxy
 */

/* Mynewt Dependencies */
#include "os/mynewt.h"
#include <console/console.h>
#include <log/log.h>
#include <assert.h>
#include <string.h>
#include "modlog/modlog.h"
#include "../../../lib/nxp_nfc/src/comps/phhalHw/src/Pn5180/phhalHw_Pn5180.h"
#include <bsp/bsp.h>

#if MYNEWT_VAL(BUS_DRIVER_PRESENT)
#include "bus/drivers/spi_common.h"
#endif

#ifdef MYNEWT_VAL_PHOSAL_EVQ
struct os_eventq MYNEWT_VAL(PHOSAL_EVQ);
#endif

/**
* Reader Library Headers
*/
#include <phApp_Init.h>
#include <nxp_nfc/phbalReg.h>
#include "NfcrdlibEx2_ECP.h"

#if MYNEWT_VAL(PN5180_ONB) && !MYNEWT_VAL(BOOT_LOADER)
#include "../../../lib/nxp_nfc/src/comps/phhalHw/src/Pn5180/phhalHw_Pn5180.h"
static struct pn5180 g_pn5180;
struct pn5180_itf g_pn5180_itf = {
  .pi_ints = {
    {
      .host_pin = MYNEWT_VAL(PN5180_ONB_INT_PIN),
      .device_pin = MYNEWT_VAL(PN5180_INT1_PIN_DEVICE),
      .active = MYNEWT_VAL(PN5180_INT1_CFG_ACTIVE)
    },
  }
};
#endif

#if MYNEWT_VAL(PN5180_ONB) && !MYNEWT_VAL(BOOT_LOADER)
void
config_pn5180(void)
{
  struct os_dev *dev;
  struct pn5180 *pn5180;

  dev = (struct os_dev *) os_dev_open("pn5180_0", OS_TIMEOUT_NEVER, NULL);
  assert(dev != NULL);

  pn5180 = (struct pn5180 *)dev;
  pn5180->cfg.wId      = PH_COMP_DRIVER;
  pn5180->cfg.bBalType = PHBAL_REG_TYPE_SPI;
}
#endif

static void
pn5180_dev_create(void)
{
#if MYNEWT_VAL(PN5180_ONB) && !MYNEWT_VAL(BOOT_LOADER)
  int rc;
  rc = pn5180_create_spi_dev(&g_pn5180.spi_node, "pn5180_0",
          &pn5180_spi_cfg, &g_pn5180_itf);
  SYSINIT_PANIC_ASSERT(rc == 0);
#endif
}

/* Task 1 */
#define TASK1_PRIO (8)
#define TASK1_STACK_SIZE    OS_STACK_ALIGN(512)
static struct os_task adv_disc_loop;

/*******************************************************************************
**   Global Defines
*******************************************************************************/

phacDiscLoop_Sw_DataParams_t
*pDiscLoop;       /* Pointer to Discovery loop component data-parameter */

/*The below variables needs to be initialized according to example requirements by a customer */
uint8_t  sens_res[2]     = {0x04, 0x00};              /* ATQ bytes - needed for anti-collision */
uint8_t  nfc_id1[3]      = {0xA1, 0xA2, 0xA3};        /* user defined bytes of the UID (one is hardcoded) - needed for anti-collision */
uint8_t  sel_res         = 0x40;
uint8_t  nfc_id3         =
    0xFA;                      /* NFC3 byte - required for anti-collision */
uint8_t  poll_res[18]    = {0x01, 0xFE, 0xB2, 0xB3, 0xB4, 0xB5,
        0xB6, 0xB7, 0xC0, 0xC1, 0xC2, 0xC3,
        0xC4, 0xC5, 0xC6, 0xC7, 0x23, 0x45
    };

#ifdef NXPBUILD__PHAC_DISCLOOP_SW_ECP
/* The below structure shall define the Technology polling sequence used by Discovery Loop in NFC Forum Mode. */
uint8_t baPasTechPollSeq[] = {
  (uint8_t)PHAC_DISCLOOP_TECH_TYPE_A,
  (uint8_t)PHAC_DISCLOOP_TECH_TYPE_B,
#ifdef NXPBUILD__PHAC_DISCLOOP_SW_ECP
  (uint8_t)PHAC_DISCLOOP_TECH_TYPE_VAS,
#endif /* NXPBUILD__PHAC_DISCLOOP_SW_ECP */
  (uint8_t)PHAC_DISCLOOP_TECH_TYPE_F212,
  (uint8_t)PHAC_DISCLOOP_TECH_TYPE_F424,
  (uint8_t)PHAC_DISCLOOP_TECH_TYPE_V,
  (uint8_t)PHAC_DISCLOOP_TECH_TYPE_18000P3M3
};
#endif /* NXPBUILD__PHAC_DISCLOOP_SW_ECP */
/*******************************************************************************
**   Static Defines
*******************************************************************************/

/* This is used to save restore Poll Config.
 * If in case application has update/change PollCfg to resolve Tech
 * when Multiple Tech was detected in previous poll cycle
 */
static uint16_t bSavePollTechCfg;
#ifdef NXPBUILD__PHAC_DISCLOOP_SW_ECP

/* Enable ECP Compatibility mode with NFC Forum Activity v1.0 configuration.
 * Disabling this macro shall enable Polling as per ECP Specification v2.0
 * using NFC Forum Activity Specification v1.1. */

/* #define ENABLE_ECP_COMPATIBILITY_MODE */

/* ECP VASUP-A Format 1 as per ECP v1.0 */
#define VASUP_A_FORMAT_VERSION_1  1U
/* ECP VASUP-A Format 2 as per ECP v2.0 */
#define VASUP_A_FORMAT_VERSION_2  2U

/* Configure the ECP VASUP-A command format version (either 1 or 2). */
#define VASUP_A_FORMAT_SELECTION  VASUP_A_FORMAT_VERSION_2

/* VAS Command used in Polling sequence. */
#if VASUP_A_FORMAT_SELECTION == VASUP_A_FORMAT_VERSION_1
static uint8_t  aVASCmd[3]  = {0xC3, 0x00, 0x00};
#else
static uint8_t  aVASCmd[18] = {0xCF, 0x05, 0x01, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF};
#endif

#endif /* NXPBUILD__PHAC_DISCLOOP_SW_ECP */

/* By default Discovery Loop shall be configured in NFC Forum Mode.
 * To enable EMVCO profile, assign EX2_DISCLOOP_PROFILE macro with 'PHAC_DISCLOOP_PROFILE_EMVCO'.
*/
#define EX2_DISCLOOP_PROFILE    PHAC_DISCLOOP_PROFILE_NFC    /* PHAC_DISCLOOP_PROFILE_NFC - NFC Profile and PHAC_DISCLOOP_PROFILE_EMVCO - EMVCo Profile */

/*******************************************************************************
**   Function Declarations
*******************************************************************************/
void ECP_Demo(void  *pDataParams);
static uint16_t ProcessDiscLoopStatus(uint16_t wEntryPoint, phStatus_t DiscLoopStatus);
static phStatus_t LoadProfile(phacDiscLoop_Profile_t bProfile);

/*******************************************************************************
**   Function Definitions
*******************************************************************************/

/**
 * init_tasks
 *
 * Called by main.c after sysinit(). This function performs initializations
 * that are required before tasks are running.
 *
 * @return int 0 success; error otherwise.
 */
static void
init_tasks(void)
{
  os_stack_t *pstack;

  pstack = malloc(sizeof(os_stack_t) * TASK1_STACK_SIZE);
  assert(pstack);

  os_eventq_init(&MYNEWT_VAL(PHOSAL_EVQ));
  os_task_init(&adv_disc_loop, "ECP_Task", ECP_Demo, pDiscLoop,
      TASK1_PRIO, OS_WAIT_FOREVER, pstack, TASK1_STACK_SIZE);
}

/*******************************************************************************
**   Main Function
*******************************************************************************/
int main(void)
{
  phStatus_t status = PH_ERR_INTERNAL_ERROR;
  phNfcLib_Status_t     dwStatus;
  struct pn5180 *pn5180 = NULL;

  console_printf("\n Enhanced Contactless Polling(ECP) Example: \n");

#ifdef PH_PLATFORM_HAS_ICFRONTEND
  phNfcLib_AppContext_t AppContext = {0};
#endif /* PH_PLATFORM_HAS_ICFRONTEND */

  /* Initialize packages (see: syscfg.yml). */
  sysinit();

  /* Creating a pn5180 device here */
  pn5180_dev_create();

  config_pn5180();
  pn5180 = (struct pn5180 *)os_dev_lookup("pn5180_0");
  assert(pn5180);

  AppContext.pBalDataparams = &(pn5180->cfg);
  dwStatus = phNfcLib_SetContext(&AppContext);
  CHECK_NFCLIB_STATUS(dwStatus);

  /* Initialize library */
  dwStatus = phNfcLib_Init();
  CHECK_NFCLIB_STATUS(dwStatus);
  if (dwStatus != PH_NFCLIB_STATUS_SUCCESS) {
    assert(0);
  }

  /* Set the generic pointer */
  pHal = phNfcLib_GetDataParams(PH_COMP_HAL);
  pDiscLoop = phNfcLib_GetDataParams(PH_COMP_AC_DISCLOOP);

  /* Initialize other components that are not initialized by NFCLIB and configure Discovery Loop. */
  status = phApp_Comp_Init(pDiscLoop);
  CHECK_STATUS(status);
  if (status != PH_ERR_SUCCESS) {
    assert(0);
  }

  /* Perform Platform Init */
  status = phApp_Configure_IRQ();
  CHECK_STATUS(status);
  if (status != PH_ERR_SUCCESS) {
    assert(0);
  }

  init_tasks();

  /*
   * As the last thing, process events from default event queue.
   */
  while (1) {
    os_eventq_run(os_eventq_dflt_get());
  }

  return 0;
}
/**
* This function shall perform ECP Polling and shall detect and reports the NFC technology type detected.
*
* \param   pDataParams      The discovery loop data parameters
* \note    This function will never return
*/
void ECP_Demo(void  *pDataParams)
{
  phStatus_t    status, statustmp;
  uint16_t      wEntryPoint;

  /* Load selected profile for Discovery loop. */
  LoadProfile((phacDiscLoop_Profile_t)EX2_DISCLOOP_PROFILE);

#ifdef NXPBUILD__PHHAL_HW_TARGET
  /* Initialize the setting for Listen Mode */
  status = phApp_HALConfigAutoColl();
  CHECK_STATUS(status);
#endif /* NXPBUILD__PHHAL_HW_TARGET */

  /* Save the Poll Configuration */
  status = phacDiscLoop_GetConfig(pDataParams, PHAC_DISCLOOP_CONFIG_PAS_POLL_TECH_CFG,
          &bSavePollTechCfg);
  CHECK_STATUS(status);

  /* Start in poll mode */
  wEntryPoint = PHAC_DISCLOOP_ENTRY_POINT_POLL;

  /* Switch off RF field */
  statustmp = phhalHw_FieldOff(pHal);
  CHECK_STATUS(statustmp);

  while (1) {
    /* Before polling set Discovery Poll State to Detection, as later in the code it can be changed to e.g. PHAC_DISCLOOP_POLL_STATE_REMOVAL*/
    statustmp = phacDiscLoop_SetConfig(pDataParams, PHAC_DISCLOOP_CONFIG_NEXT_POLL_STATE,
            PHAC_DISCLOOP_POLL_STATE_DETECTION);
    CHECK_STATUS(statustmp);

    if (((phacDiscLoop_Profile_t)EX2_DISCLOOP_PROFILE == PHAC_DISCLOOP_PROFILE_EMVCO) &&
        (wEntryPoint == PHAC_DISCLOOP_ENTRY_POINT_LISTEN)) {
      /* Note: Skip Listen Mode in EMVCo profile */
      /* Start in poll mode only. */
      wEntryPoint = PHAC_DISCLOOP_ENTRY_POINT_POLL;
    }

    /* Start discovery loop operation. */
    status = phacDiscLoop_Run(pDataParams, wEntryPoint);

    wEntryPoint = ProcessDiscLoopStatus(wEntryPoint, status);

    /* Restore Poll Configuration */
    statustmp = phacDiscLoop_SetConfig(pDataParams, PHAC_DISCLOOP_CONFIG_PAS_POLL_TECH_CFG,
            bSavePollTechCfg);
    CHECK_STATUS(statustmp);
  }
}

static uint16_t ProcessDiscLoopStatus(uint16_t wEntryPoint, phStatus_t DiscLoopStatus)
{
  phStatus_t    status = PH_ERR_SUCCESS;
  uint16_t      wTechDetected = 0;
  uint16_t      wNumberOfTags = 0;
  uint16_t      wValue;
  uint8_t       bIndex;
  uint16_t      wReturnEntryPoint;

  /* Process Discovery Loop status based on Entry Mode. */
  if (wEntryPoint == PHAC_DISCLOOP_ENTRY_POINT_POLL) {
    /* Multiple Technology is detected in Technology detection phase of Discovery Loop. */
    if ((DiscLoopStatus & PH_ERR_MASK) == PHAC_DISCLOOP_MULTI_TECH_DETECTED) {
      console_printf(" \n Multiple technology detected: \n");

      status = phacDiscLoop_GetConfig(pDiscLoop, PHAC_DISCLOOP_CONFIG_TECH_DETECTED, &wTechDetected);
      CHECK_STATUS(status);

      if (PHAC_DISCLOOP_CHECK_ANDMASK(wTechDetected, PHAC_DISCLOOP_POS_BIT_MASK_A)) {
        console_printf(" \tType A detected... \n");
      }
      if (PHAC_DISCLOOP_CHECK_ANDMASK(wTechDetected, PHAC_DISCLOOP_POS_BIT_MASK_B)) {
        console_printf(" \tType B detected... \n");
      }
#ifdef NXPBUILD__PHAC_DISCLOOP_SW_ECP
      if (PHAC_DISCLOOP_CHECK_ANDMASK(wTechDetected, PHAC_DISCLOOP_POS_BIT_MASK_VAS)) {
        console_printf(" \tType VAS detected... \n");
      }
#endif /* NXPBUILD__PHAC_DISCLOOP_SW_ECP */
      if (PHAC_DISCLOOP_CHECK_ANDMASK(wTechDetected, PHAC_DISCLOOP_POS_BIT_MASK_F212)) {
        console_printf(" \tType F detected with baud rate 212... \n");
      }
      if (PHAC_DISCLOOP_CHECK_ANDMASK(wTechDetected, PHAC_DISCLOOP_POS_BIT_MASK_F424)) {
        console_printf(" \tType F detected with baud rate 424... \n");
      }
      if (PHAC_DISCLOOP_CHECK_ANDMASK(wTechDetected, PHAC_DISCLOOP_POS_BIT_MASK_V)) {
        console_printf(" \tType V / ISO 15693 / T5T detected... \n");
      }

      /* Select 1st Detected Technology to Resolve*/
      for (bIndex = 0; bIndex < PHAC_DISCLOOP_PASS_POLL_MAX_TECHS_SUPPORTED; bIndex++) {
        if (PHAC_DISCLOOP_CHECK_ANDMASK(wTechDetected, (1 << bIndex))) {
          /* Configure for one of the detected technology */
          status = phacDiscLoop_SetConfig(pDiscLoop, PHAC_DISCLOOP_CONFIG_PAS_POLL_TECH_CFG,
                  (1 << bIndex));
          CHECK_STATUS(status);
          break;
        }
      }

      /* Print the technology resolved */
      phApp_PrintTech((1 << bIndex));

      /* Set Discovery Poll State to collision resolution */
      status = phacDiscLoop_SetConfig(pDiscLoop, PHAC_DISCLOOP_CONFIG_NEXT_POLL_STATE,
              PHAC_DISCLOOP_POLL_STATE_COLLISION_RESOLUTION);
      CHECK_STATUS(status);

      /* Restart discovery loop in poll mode from collision resolution phase */
      DiscLoopStatus = phacDiscLoop_Run(pDiscLoop, wEntryPoint);
    }

    /* Multiple Cards/Peers are detected in Technology detection phase of Discovery Loop. */
    if ((DiscLoopStatus & PH_ERR_MASK) == PHAC_DISCLOOP_MULTI_DEVICES_RESOLVED) {
      /* Get Detected Technology Type */
      status = phacDiscLoop_GetConfig(pDiscLoop, PHAC_DISCLOOP_CONFIG_TECH_DETECTED, &wTechDetected);
      CHECK_STATUS(status);

      /* Get number of tags detected */
      status = phacDiscLoop_GetConfig(pDiscLoop, PHAC_DISCLOOP_CONFIG_NR_TAGS_FOUND, &wNumberOfTags);
      CHECK_STATUS(status);

      console_printf(" \n Multiple cards resolved: %d cards \n", wNumberOfTags);
      phApp_PrintTagInfo(pDiscLoop, wNumberOfTags, wTechDetected);

      if (wNumberOfTags > 1) {
        /* Get 1st Detected Technology and Activate device at index 0 */
        for (bIndex = 0; bIndex < PHAC_DISCLOOP_PASS_POLL_MAX_TECHS_SUPPORTED; bIndex++) {
          if (PHAC_DISCLOOP_CHECK_ANDMASK(wTechDetected, (1 << bIndex))) {
            console_printf("\t Activating one card...\n");
            status = phacDiscLoop_ActivateCard(pDiscLoop, bIndex, 0);
            break;
          }
        }

        if (((status & PH_ERR_MASK) == PHAC_DISCLOOP_DEVICE_ACTIVATED) ||
            ((status & PH_ERR_MASK) == PHAC_DISCLOOP_PASSIVE_TARGET_ACTIVATED) ||
            ((status & PH_ERR_MASK) == PHAC_DISCLOOP_MERGED_SEL_RES_FOUND)) {
          /* Get Detected Technology Type */
          status = phacDiscLoop_GetConfig(pDiscLoop, PHAC_DISCLOOP_CONFIG_TECH_DETECTED, &wTechDetected);
          CHECK_STATUS(status);

          phApp_PrintTagInfo(pDiscLoop, 0x01, wTechDetected);
        } else {
          console_printf("\t\tCard activation failed...\n");
        }
      }
      /* Switch to LISTEN mode after POLL mode */
    }
    /* No Technology is detected in Technology Detection phase of Discovery Loop. */
    else if (((DiscLoopStatus & PH_ERR_MASK) == PHAC_DISCLOOP_NO_TECH_DETECTED) ||
        ((DiscLoopStatus & PH_ERR_MASK) == PHAC_DISCLOOP_NO_DEVICE_RESOLVED)) {
      /* Switch to LISTEN mode after POLL mode */
    } else if ((DiscLoopStatus & PH_ERR_MASK) == PHAC_DISCLOOP_EXTERNAL_RFON) {
      /*
       * If external RF is detected during POLL, return back so that the application
       * can restart the loop in LISTEN mode
       */
    } else if ((DiscLoopStatus & PH_ERR_MASK) == PHAC_DISCLOOP_MERGED_SEL_RES_FOUND) {
      console_printf(" \n Device having T4T and NFC-DEP support detected... \n");

      /* Get Detected Technology Type */
      status = phacDiscLoop_GetConfig(pDiscLoop, PHAC_DISCLOOP_CONFIG_TECH_DETECTED, &wTechDetected);
      CHECK_STATUS(status);

      phApp_PrintTagInfo(pDiscLoop, 1, wTechDetected);

    } else if ((DiscLoopStatus & PH_ERR_MASK) == PHAC_DISCLOOP_DEVICE_ACTIVATED) {
      console_printf(" \n Card detected and activated successfully... \n");
      status = phacDiscLoop_GetConfig(pDiscLoop, PHAC_DISCLOOP_CONFIG_NR_TAGS_FOUND, &wNumberOfTags);
      CHECK_STATUS(status);

      /* Get Detected Technology Type */
      status = phacDiscLoop_GetConfig(pDiscLoop, PHAC_DISCLOOP_CONFIG_TECH_DETECTED, &wTechDetected);
      CHECK_STATUS(status);

      phApp_PrintTagInfo(pDiscLoop, wNumberOfTags, wTechDetected);

    } else if ((DiscLoopStatus & PH_ERR_MASK) == PHAC_DISCLOOP_ACTIVE_TARGET_ACTIVATED) {
      console_printf(" \n Active target detected... \n");

    } else if ((DiscLoopStatus & PH_ERR_MASK) == PHAC_DISCLOOP_PASSIVE_TARGET_ACTIVATED) {
      console_printf(" \n Passive target detected... \n");

      /* Get Detected Technology Type */
      status = phacDiscLoop_GetConfig(pDiscLoop, PHAC_DISCLOOP_CONFIG_TECH_DETECTED, &wTechDetected);
      CHECK_STATUS(status);

      phApp_PrintTagInfo(pDiscLoop, 1, wTechDetected);

    } else {
      if ((DiscLoopStatus & PH_ERR_MASK) == PHAC_DISCLOOP_FAILURE) {
        status = phacDiscLoop_GetConfig(pDiscLoop, PHAC_DISCLOOP_CONFIG_ADDITIONAL_INFO, &wValue);
        CHECK_STATUS(status);
        if (status != PH_ERR_SUCCESS || wValue != 0) {
          PrintErrorInfo(wValue);
        }
      } else {
        if (status != PH_ERR_SUCCESS) {
          PrintErrorInfo(status);
        }
      }
    }

    /* Switch to LISTEN mode after POLL mode.
       Update the Entry point to LISTEN mode. */
    wReturnEntryPoint = PHAC_DISCLOOP_ENTRY_POINT_LISTEN;
  } else {
    if ((DiscLoopStatus & PH_ERR_MASK) == PHAC_DISCLOOP_EXTERNAL_RFOFF) {
      /*
       * Enters here if in the target/card mode and external RF is not available
       * Wait for LISTEN timeout till an external RF is detected.
       * Application may choose to go into standby at this point.
       */
      status = phhalHw_EventConsume(pHal);
      CHECK_STATUS(status);

      status = phhalHw_SetConfig(pHal, PHHAL_HW_CONFIG_RFON_INTERRUPT, PH_ON);
      CHECK_STATUS(status);

      status = phhalHw_EventWait(pHal, LISTEN_PHASE_TIME_MS);
      if ((status & PH_ERR_MASK) == PH_ERR_IO_TIMEOUT) {
        wReturnEntryPoint = PHAC_DISCLOOP_ENTRY_POINT_POLL;
      } else {
        wReturnEntryPoint = PHAC_DISCLOOP_ENTRY_POINT_LISTEN;
      }
    } else {
      if ((DiscLoopStatus & PH_ERR_MASK) == PHAC_DISCLOOP_ACTIVATED_BY_PEER) {
        console_printf(" \n Device activated in listen mode... \n");
      } else if ((DiscLoopStatus & PH_ERR_MASK) == PH_ERR_INVALID_PARAMETER) {
        /* In case of Front end used is RC663, then listen mode is not supported.
         * Switch from listen mode to poll mode. */
      } else {
        if ((DiscLoopStatus & PH_ERR_MASK) == PHAC_DISCLOOP_FAILURE) {
          status = phacDiscLoop_GetConfig(pDiscLoop, PHAC_DISCLOOP_CONFIG_ADDITIONAL_INFO, &wValue);
          CHECK_STATUS(status);
          if (status != PH_ERR_SUCCESS || wValue != 0) {
            PrintErrorInfo(wValue);
            console_printf("status: %x wValue: %x\n", status, wValue);
          }
        } else {
          if (status != PH_ERR_SUCCESS) {
            PrintErrorInfo(status);
          }
        }
      }

      /* On successful activated by Peer, try to switch to Poll mode for demonstrating ECP Poll mode. */
      wReturnEntryPoint = PHAC_DISCLOOP_ENTRY_POINT_POLL;
    }
  }
  return wReturnEntryPoint;
}

/**
* This function will load/configure Discovery loop with default values based on interested profile
 * Application can read these values from EEPROM area and load/configure Discovery loop via SetConfig
* \param   bProfile      Reader Library Profile
* \note    Values used below are default and is for demonstration purpose.
*/
static phStatus_t LoadProfile(phacDiscLoop_Profile_t bProfile)
{
  phStatus_t status = PH_ERR_SUCCESS;
  uint16_t   wPasPollConfig = 0;
  uint16_t   wActPollConfig = 0;  /* Disable the Active Mode Poll configuration. */
  uint16_t   wPasLisConfig = 0;
  uint16_t   wActLisConfig = 0;   /* Disable the Active Mode Listen configuration. */

#ifdef NXPBUILD__PHAC_DISCLOOP_TYPEA_TAGS
  wPasPollConfig |= PHAC_DISCLOOP_POS_BIT_MASK_A;
#endif
#ifdef NXPBUILD__PHAC_DISCLOOP_TYPEB_TAGS
  wPasPollConfig |= PHAC_DISCLOOP_POS_BIT_MASK_B;
#endif
#ifdef NXPBUILD__PHAC_DISCLOOP_SW_ECP
  wPasPollConfig |= PHAC_DISCLOOP_POS_BIT_MASK_VAS;
#endif /* NXPBUILD__PHAC_DISCLOOP_SW_ECP */

  /* Set Active poll bitmap config. */
  status = phacDiscLoop_SetConfig(pDiscLoop, PHAC_DISCLOOP_CONFIG_ACT_POLL_TECH_CFG,
          wActPollConfig);
  CHECK_STATUS(status);

  /* Set Active listen bitmap config. */
  status = phacDiscLoop_SetConfig(pDiscLoop, PHAC_DISCLOOP_CONFIG_ACT_LIS_TECH_CFG, wActLisConfig);
  CHECK_STATUS(status);

#ifdef NXPBUILD__PHAC_DISCLOOP_SW_ECP
  /* Configure the VAS Command bytes that need to be sent as per ECP Spec. */
  pDiscLoop->sVASTargetInfo.pCmdBytes = aVASCmd;
  pDiscLoop->sVASTargetInfo.bLenCmdBytes = sizeof(aVASCmd);

  console_printf("Configure discovery loop for ECP\n");
  /* Configure the VAS Format selection bytes that need to be sent as per ECP Spec. */
  status = phacDiscLoop_SetConfig(pDiscLoop, PHAC_DISCLOOP_CONFIG_VASUP_A_FORAMT_BYTE,
          VASUP_A_FORMAT_SELECTION);
  CHECK_STATUS(status);
#endif /* NXPBUILD__PHAC_DISCLOOP_SW_ECP */

  /* Based on Discovery Loop Profile, configuration shall be performed. */
  if (bProfile == PHAC_DISCLOOP_PROFILE_NFC) {
#ifdef NXPBUILD__PHAC_DISCLOOP_TYPEF_TAGS
    wPasPollConfig |= (PHAC_DISCLOOP_POS_BIT_MASK_F212 | PHAC_DISCLOOP_POS_BIT_MASK_F424);
#endif

#ifdef NXPBUILD__PHAC_DISCLOOP_TYPEA_TARGET_PASSIVE
    wPasLisConfig |= PHAC_DISCLOOP_POS_BIT_MASK_A;
#endif
#ifdef NXPBUILD__PHAC_DISCLOOP_TYPEF212_TARGET_PASSIVE
    wPasLisConfig |= PHAC_DISCLOOP_POS_BIT_MASK_F212;
#endif
#ifdef NXPBUILD__PHAC_DISCLOOP_TYPEF424_TARGET_PASSIVE
    wPasLisConfig |= PHAC_DISCLOOP_POS_BIT_MASK_F424;
#endif

    /* Enable the Bailout bitmap configuration for Type A and B technology. */
    status = phacDiscLoop_SetConfig(pDiscLoop, PHAC_DISCLOOP_CONFIG_BAIL_OUT,
            (PHAC_DISCLOOP_POS_BIT_MASK_A | PHAC_DISCLOOP_POS_BIT_MASK_B));
    CHECK_STATUS(status);

    /* Set Passive poll bitmap config. */
    status = phacDiscLoop_SetConfig(pDiscLoop, PHAC_DISCLOOP_CONFIG_PAS_POLL_TECH_CFG,
            wPasPollConfig);
    CHECK_STATUS(status);

    /* Set Passive listen bitmap config. */
    status = phacDiscLoop_SetConfig(pDiscLoop, PHAC_DISCLOOP_CONFIG_PAS_LIS_TECH_CFG, wPasLisConfig);
    CHECK_STATUS(status);

#ifdef NXPBUILD__PHAC_DISCLOOP_SW_ECP
#ifdef ENABLE_ECP_COMPATIBILITY_MODE
    /* Configure the NFC Activity version 1.0 */
    status = phacDiscLoop_SetConfig(pDiscLoop, PHAC_DISCLOOP_CONFIG_ACTIVITY_VERSION,
            PHAC_DISCLOOP_NFC_ACTIVITY_VERSION_1_0);
    CHECK_STATUS(status);

    console_printf("Configure VAS polling sequence as per ECP in compatibility mode\n");
    /* Configure the VAS Polling as per Compatibility mode (similar to PN7150). */
    status = phacDiscLoop_SetConfig(pDiscLoop, PHAC_DISCLOOP_CONFIG_VAS_POLLING_IN_NFC_MODE,
            PHAC_DISCLOOP_VAS_IN_COMPATIBILITY_MODE);
    CHECK_STATUS(status);
#else /* ENABLE_ECP_COMPATIBILITY_MODE */
    /* Configure the NFC Activity version 1.1 */
    status = phacDiscLoop_SetConfig(pDiscLoop, PHAC_DISCLOOP_CONFIG_ACTIVITY_VERSION,
            PHAC_DISCLOOP_NFC_ACTIVITY_VERSION_1_1);
    CHECK_STATUS(status);

    console_printf("Configure polling as per ECP Specification 2.0\n");
    /* Configure the Polling sequence as per ECP Specification v2.0. */
    status = phacDiscLoop_CfgPollSeq(pDiscLoop, baPasTechPollSeq);
    CHECK_STATUS(status);
#endif /* ENABLE_ECP_COMPATIBILITY_MODE */
#endif /* NXPBUILD__PHAC_DISCLOOP_SW_ECP */

    /* Set Discovery loop Operation mode */
    status = phacDiscLoop_SetConfig(pDiscLoop, PHAC_DISCLOOP_CONFIG_OPE_MODE, RD_LIB_MODE_NFC);
    CHECK_STATUS(status);
  } else if (bProfile == PHAC_DISCLOOP_PROFILE_EMVCO) {
    /* passive Poll bitmap config. */
    status = phacDiscLoop_SetConfig(pDiscLoop, PHAC_DISCLOOP_CONFIG_PAS_POLL_TECH_CFG,
            wPasPollConfig);
    CHECK_STATUS(status);

    /* Passive Listen bitmap config. */
    status = phacDiscLoop_SetConfig(pDiscLoop, PHAC_DISCLOOP_CONFIG_PAS_LIS_TECH_CFG, wPasLisConfig);
    CHECK_STATUS(status);

    /* Configure reader library mode */
    status = phacDiscLoop_SetConfig(pDiscLoop, PHAC_DISCLOOP_CONFIG_OPE_MODE, RD_LIB_MODE_EMVCO);
    CHECK_STATUS(status);
  } else {
    /* Do Nothing */
  }
  return status;
}

/******************************************************************************
**                            End Of File
******************************************************************************/
