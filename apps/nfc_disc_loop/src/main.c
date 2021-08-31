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
* Example Source for NfcrdlibEx1_DiscoveryLoop that uses the Discovery loop implementation.
* By default Discovery Loop will work in NFC Forum v1.1 Mode i.e. setting as per NFC Forum
* Activity Specification v1.1 will be followed which will configure the Reader in both POLL
* and LISTEN (only for Universal device) modes of discovery loop. Displays detected tag
* information(like UID, SAK, Product Type) and prints information when it gets activated as
* a target by an external Initiator/reader.
*
* By enabling "ENABLE_DISC_CONFIG" macro, few of the most common Discovery Loop configuration
* are been updated to values defined in this Example.
* By enabling "ENABLE_EMVCO_PROF", Discovery Loop will be configured as per EMVCo Polling
* specification else the Discovery Loop will still be configured to NFC Forum but user defined
* values as per this Application.
*
* NFC Forum Mode: Whenever multiple technologies are detected, example will select first
* detected technology to resolve. Example will activate device at index zero whenever multiple
* device is detected.
*
* For EMVCo profile, this example provide full EMVCo digital demonstration along with option to
* use different SELECT PPSE Commands.
*
* Please refer Readme.txt file for Hardware Pin Configuration, Software Configuration and steps to build and
* execute the project which is present in the same project directory.
*
* $Author$
* $Revision$ (v06.11.00)
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

#ifdef MYNEWT_VAL_PHOSAL_EVQ
struct os_eventq MYNEWT_VAL(PHOSAL_EVQ);
#endif

/**
* Reader Library Headers
*/
#include <phApp_Init.h>
/* NFC Task */
#define NFC_TASK_PRIO (110)
#define NFC_TASK_STACK_SIZE    OS_STACK_ALIGN(2048)
OS_TASK_STACK_DEFINE(g_nfc_task_stack, NFC_TASK_STACK_SIZE);
static struct os_task disc_loop;

/* Local headers */
#include <NfcrdlibEx1_DiscoveryLoop.h>
#include <NfcrdlibEx1_EmvcoProfile.h>

/*******************************************************************************
**   Global Defines
*******************************************************************************/

phacDiscLoop_Sw_DataParams_t        *pDiscLoop;       /* Discovery loop component */

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

/*******************************************************************************
**   Static Defines
*******************************************************************************/

/* This is used to save restore Poll Config.
 * If in case application has update/change PollCfg to resolve Tech
 * when Multiple Tech was detected in previous poll cycle
 */
static uint16_t bSavePollTechCfg;

/*******************************************************************************
**   Function Declarations
*******************************************************************************/
static void nfc_task_init(void);
void DiscoveryLoop_Demo(void  *arg);
uint16_t NFCForumProcess(uint16_t wEntryPoint, phStatus_t DiscLoopStatus);

#ifdef ENABLE_DISC_CONFIG
static phStatus_t LoadProfile(phacDiscLoop_Profile_t bProfile);
#endif /* ENABLE_DISC_CONFIG */

/*******************************************************************************
**   Function Definitions
*******************************************************************************/

/**
 * Start the NFC discovery loop task.
 */
static void
nfc_task_init(void)
{
#ifdef MYNEWT_VAL_PHOSAL_EVQ
  os_eventq_init(&MYNEWT_VAL(PHOSAL_EVQ));
#endif

  os_task_init(&disc_loop, "nfc", DiscoveryLoop_Demo, pDiscLoop,
      NFC_TASK_PRIO, OS_WAIT_FOREVER, g_nfc_task_stack, NFC_TASK_STACK_SIZE);
}

/*******************************************************************************
**   Main Function
*******************************************************************************/
int
main(void)
{
  phStatus_t status = PH_ERR_INTERNAL_ERROR;
  phNfcLib_Status_t     dwStatus;
#ifdef PH_PLATFORM_HAS_ICFRONTEND
  phNfcLib_AppContext_t AppContext = {0};
#endif /* PH_PLATFORM_HAS_ICFRONTEND */

  /* Perform OSAL Initialization. */
  (void)phOsal_Init();

  console_printf("\n DiscoveryLoop Example: \n");

  struct pn5180 *pn5180 = NULL;

  /* Initialize packages (see: syscfg.yml). */
  sysinit();

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

  nfc_task_init();

  /*
   * As the last thing, process events from default event queue.
   */
  while (1) {
    os_eventq_run(os_eventq_dflt_get());
  }

  return 0;
}

/**
* This function demonstrates the usage of discovery loop.
* The discovery loop can run with default setting Or can be configured as demonstrated and
* is used to detects and reports the NFC technology type.
* \param   pDataParams      The discovery loop data parameters
* \note    This function will never return
*/
void
DiscoveryLoop_Demo(void  *pDataParams)
{
  phStatus_t    status, statustmp;
  uint16_t      wEntryPoint;
  phacDiscLoop_Profile_t bProfile = PHAC_DISCLOOP_PROFILE_UNKNOWN;

#ifdef ENABLE_DISC_CONFIG

#ifndef ENABLE_EMVCO_PROF
  bProfile = PHAC_DISCLOOP_PROFILE_NFC;
#else
  bProfile = PHAC_DISCLOOP_PROFILE_EMVCO;
#endif
  /* Load selected profile for Discovery loop */
  LoadProfile(bProfile);
#endif /* ENABLE_DISC_CONFIG */

#ifdef NXPBUILD__PHHAL_HW_TARGET
  /* Initialize the setting for Listen Mode */
  status = phApp_HALConfigAutoColl();
  CHECK_STATUS(status);
#endif /* NXPBUILD__PHHAL_HW_TARGET */

  /* Get Poll Configuration */
  status = phacDiscLoop_GetConfig(pDataParams, PHAC_DISCLOOP_CONFIG_PAS_POLL_TECH_CFG,
          &bSavePollTechCfg);
  CHECK_STATUS(status);

  /* Start in poll mode */
  wEntryPoint = PHAC_DISCLOOP_ENTRY_POINT_POLL;
  status = PHAC_DISCLOOP_LPCD_NO_TECH_DETECTED;

  /* Switch off RF field */
  statustmp = phhalHw_FieldOff(pHal);
  CHECK_STATUS(statustmp);

  while (1) {
    /* Before polling set Discovery Poll State to Detection , as later in the code it can be changed to e.g. PHAC_DISCLOOP_POLL_STATE_REMOVAL*/
    statustmp = phacDiscLoop_SetConfig(pDataParams, PHAC_DISCLOOP_CONFIG_NEXT_POLL_STATE,
            PHAC_DISCLOOP_POLL_STATE_DETECTION);
    CHECK_STATUS(statustmp);

#if !defined(ENABLE_EMVCO_PROF) && defined(PH_EXAMPLE1_LPCD_ENABLE)

#ifdef NXPBUILD__PHHAL_HW_RC663
    if (wEntryPoint == PHAC_DISCLOOP_ENTRY_POINT_POLL)
#else
    /* Configure LPCD */
    if ((status & PH_ERR_MASK) == PHAC_DISCLOOP_LPCD_NO_TECH_DETECTED)
#endif
    {
      status = phApp_ConfigureLPCD();
      CHECK_STATUS(status);
    }

    /* Bool to enable LPCD feature. */
    status = phacDiscLoop_SetConfig(pDataParams, PHAC_DISCLOOP_CONFIG_ENABLE_LPCD, PH_ON);
    CHECK_STATUS(status);
#endif /* PH_EXAMPLE1_LPCD_ENABLE*/

    /* Start discovery loop */
    status = phacDiscLoop_Run(pDataParams, wEntryPoint);

    if (bProfile == PHAC_DISCLOOP_PROFILE_EMVCO) {
#if defined(ENABLE_EMVCO_PROF)

      EmvcoProfileProcess(pDataParams, status);

#endif /* ENABLE_EMVCO_PROF */
    } else {
      wEntryPoint = NFCForumProcess(wEntryPoint, status);

      /* Set Poll Configuration */
      statustmp = phacDiscLoop_SetConfig(pDataParams, PHAC_DISCLOOP_CONFIG_PAS_POLL_TECH_CFG,
              bSavePollTechCfg);
      CHECK_STATUS(statustmp);

      /* Switch off RF field */
      statustmp = phhalHw_FieldOff(pHal);
      CHECK_STATUS(statustmp);
    }
#ifdef MYNEWT_VAL_PHOSAL_EVQ
    struct os_event *ev;
    struct os_eventq *evq = &MYNEWT_VAL(PHOSAL_EVQ);
    ev = os_eventq_poll(&evq, 1, 0);
    if (ev) {
      assert(ev->ev_cb != NULL);
      ev->ev_cb(ev);
    }
#endif
    int rc;
    os_time_t poll_idle_time_ms;
    rc = os_time_ms_to_ticks(MYNEWT_VAL(POLL_IDLE_TIME_MS), &poll_idle_time_ms);
    assert(rc == OS_OK);
    os_time_delay(poll_idle_time_ms);
  }
}

uint16_t
NFCForumProcess(uint16_t wEntryPoint, phStatus_t DiscLoopStatus)
{
  phStatus_t    status;
  uint16_t      wTechDetected = 0;
  uint16_t      wNumberOfTags = 0;
  uint16_t      wValue;
  uint8_t       bIndex;
  uint16_t      wReturnEntryPoint;

  if (wEntryPoint == PHAC_DISCLOOP_ENTRY_POINT_POLL) {
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
          status = phacDiscLoop_SetConfig(pDiscLoop, PHAC_DISCLOOP_CONFIG_PAS_POLL_TECH_CFG, (1 << bIndex));
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
          PRINT_INFO("\t\tCard activation failed...\n");
        }
      }
      /* Switch to LISTEN mode after POLL mode */
    } else if (((DiscLoopStatus & PH_ERR_MASK) == PHAC_DISCLOOP_NO_TECH_DETECTED) ||
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

      /* Switch to LISTEN mode after POLL mode */
    } else if ((DiscLoopStatus & PH_ERR_MASK) == PHAC_DISCLOOP_DEVICE_ACTIVATED) {
      console_printf(" \n Card detected and activated successfully... \n");
      status = phacDiscLoop_GetConfig(pDiscLoop, PHAC_DISCLOOP_CONFIG_NR_TAGS_FOUND, &wNumberOfTags);
      CHECK_STATUS(status);

      /* Get Detected Technology Type */
      status = phacDiscLoop_GetConfig(pDiscLoop, PHAC_DISCLOOP_CONFIG_TECH_DETECTED, &wTechDetected);
      CHECK_STATUS(status);

      phApp_PrintTagInfo(pDiscLoop, wNumberOfTags, wTechDetected);

      /* Switch to LISTEN mode after POLL mode */
    } else if ((DiscLoopStatus & PH_ERR_MASK) == PHAC_DISCLOOP_ACTIVE_TARGET_ACTIVATED) {
      console_printf(" \n Active target detected... \n");

      /* Switch to LISTEN mode after POLL mode */
    } else if ((DiscLoopStatus & PH_ERR_MASK) == PHAC_DISCLOOP_PASSIVE_TARGET_ACTIVATED) {
      console_printf(" \n Passive target detected... \n");

      /* Get Detected Technology Type */
      status = phacDiscLoop_GetConfig(pDiscLoop, PHAC_DISCLOOP_CONFIG_TECH_DETECTED, &wTechDetected);
      CHECK_STATUS(status);

      phApp_PrintTagInfo(pDiscLoop, 1, wTechDetected);

      /* Switch to LISTEN mode after POLL mode */
    } else if ((DiscLoopStatus & PH_ERR_MASK) == PHAC_DISCLOOP_LPCD_NO_TECH_DETECTED) {
      /* LPCD is succeed but no tag is detected. */
    } else {
      if ((DiscLoopStatus & PH_ERR_MASK) == PHAC_DISCLOOP_FAILURE) {
        status = phacDiscLoop_GetConfig(pDiscLoop, PHAC_DISCLOOP_CONFIG_ADDITIONAL_INFO, &wValue);
        CHECK_STATUS(status);
        DEBUG_ERROR_PRINT(PrintErrorInfo(wValue));
      } else {
        DEBUG_ERROR_PRINT(PrintErrorInfo(status));
      }
    }

    /* Update the Entry point to LISTEN mode. */
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
          console_printf("Error: wValue:%d\n", wValue);
          DEBUG_ERROR_PRINT(PrintErrorInfo(wValue));
        } else {
          DEBUG_ERROR_PRINT(PrintErrorInfo(status));
        }
      }

      /* On successful activated by Peer, switch to LISTEN mode */
      wReturnEntryPoint = PHAC_DISCLOOP_ENTRY_POINT_POLL;
    }
  }
  return wReturnEntryPoint;
}

#ifdef ENABLE_DISC_CONFIG
/**
* This function will load/configure Discovery loop with default values based on interested profile
 * Application can read these values from EEPROM area and load/configure Discovery loop via SetConfig
* \param   bProfile      Reader Library Profile
* \note    Values used below are default and is for demonstration purpose.
*/
static phStatus_t
LoadProfile(phacDiscLoop_Profile_t bProfile)
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
#ifdef NXPBUILD__PHAC_DISCLOOP_TYPEF_TAGS
  wPasPollConfig |= (PHAC_DISCLOOP_POS_BIT_MASK_F212 | PHAC_DISCLOOP_POS_BIT_MASK_F424);
#endif
#ifdef NXPBUILD__PHAC_DISCLOOP_TYPEV_TAGS
  wPasPollConfig |= PHAC_DISCLOOP_POS_BIT_MASK_V;
#endif
#ifdef NXPBUILD__PHAC_DISCLOOP_I18000P3M3_TAGS
  wPasPollConfig |= PHAC_DISCLOOP_POS_BIT_MASK_18000P3M3;
#endif

#ifdef NXPBUILD__PHAC_DISCLOOP_TYPEA_P2P_ACTIVE
  wActPollConfig |= PHAC_DISCLOOP_ACT_POS_BIT_MASK_106;
#endif
#ifdef NXPBUILD__PHAC_DISCLOOP_TYPEF212_P2P_ACTIVE
  wActPollConfig |= PHAC_DISCLOOP_ACT_POS_BIT_MASK_212;
#endif
#ifdef NXPBUILD__PHAC_DISCLOOP_TYPEF424_P2P_ACTIVE
  wActPollConfig |= PHAC_DISCLOOP_ACT_POS_BIT_MASK_424;
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

#ifdef NXPBUILD__PHAC_DISCLOOP_TYPEA_TARGET_ACTIVE
  wActLisConfig |= PHAC_DISCLOOP_POS_BIT_MASK_A;
#endif
#ifdef NXPBUILD__PHAC_DISCLOOP_TYPEF212_TARGET_ACTIVE
  wActLisConfig |= PHAC_DISCLOOP_POS_BIT_MASK_F212;
#endif
#ifdef NXPBUILD__PHAC_DISCLOOP_TYPEF424_TARGET_ACTIVE
  wActLisConfig |= PHAC_DISCLOOP_POS_BIT_MASK_F424;
#endif

  if (bProfile == PHAC_DISCLOOP_PROFILE_NFC) {
    /* passive Bailout bitmap config. */
    status = phacDiscLoop_SetConfig(pDiscLoop, PHAC_DISCLOOP_CONFIG_BAIL_OUT, 0x00);
    CHECK_STATUS(status);

    /* Set Passive poll bitmap config. */
    status = phacDiscLoop_SetConfig(pDiscLoop, PHAC_DISCLOOP_CONFIG_PAS_POLL_TECH_CFG,
            wPasPollConfig);
    CHECK_STATUS(status);

    /* Set Active poll bitmap config. */
    status = phacDiscLoop_SetConfig(pDiscLoop, PHAC_DISCLOOP_CONFIG_ACT_POLL_TECH_CFG,
            wActPollConfig);
    CHECK_STATUS(status);

    /* Set Passive listen bitmap config. */
    status = phacDiscLoop_SetConfig(pDiscLoop, PHAC_DISCLOOP_CONFIG_PAS_LIS_TECH_CFG, wPasLisConfig);
    CHECK_STATUS(status);

    /* Set Active listen bitmap config. */
    status = phacDiscLoop_SetConfig(pDiscLoop, PHAC_DISCLOOP_CONFIG_ACT_LIS_TECH_CFG, wActLisConfig);
    CHECK_STATUS(status);

    /* reset collision Pending */
    status = phacDiscLoop_SetConfig(pDiscLoop, PHAC_DISCLOOP_CONFIG_COLLISION_PENDING, PH_OFF);
    CHECK_STATUS(status);

    /* whether anti-collision is supported or not. */
    status = phacDiscLoop_SetConfig(pDiscLoop, PHAC_DISCLOOP_CONFIG_ANTI_COLL, PH_ON);
    CHECK_STATUS(status);

    /* Poll Mode default state*/
    status = phacDiscLoop_SetConfig(pDiscLoop, PHAC_DISCLOOP_CONFIG_NEXT_POLL_STATE,
            PHAC_DISCLOOP_POLL_STATE_DETECTION);
    CHECK_STATUS(status);

#ifdef  NXPBUILD__PHAC_DISCLOOP_TYPEA_TAGS
    /* Device limit for Type A */
    status = phacDiscLoop_SetConfig(pDiscLoop, PHAC_DISCLOOP_CONFIG_TYPEA_DEVICE_LIMIT, 1);
    CHECK_STATUS(status);

    /* Passive polling Tx Guard times in micro seconds. */
    status = phacDiscLoop_SetConfig(pDiscLoop, PHAC_DISCLOOP_CONFIG_GTA_VALUE_US, 5100);
    CHECK_STATUS(status);
#endif

#ifdef NXPBUILD__PHAC_DISCLOOP_TYPEB_TAGS
    /* Device limit for Type B */
    status = phacDiscLoop_SetConfig(pDiscLoop, PHAC_DISCLOOP_CONFIG_TYPEB_DEVICE_LIMIT, 1);
    CHECK_STATUS(status);

    status = phacDiscLoop_SetConfig(pDiscLoop, PHAC_DISCLOOP_CONFIG_GTB_VALUE_US, 5100);
    CHECK_STATUS(status);
#endif

#ifdef NXPBUILD__PHAC_DISCLOOP_TYPEF_TAGS
    /* Device limit for Type F */
    status = phacDiscLoop_SetConfig(pDiscLoop, PHAC_DISCLOOP_CONFIG_TYPEF_DEVICE_LIMIT, 1);
    CHECK_STATUS(status);

    /* Guard time for Type F. This guard time is applied when Type F poll before Type B */
    status = phacDiscLoop_SetConfig(pDiscLoop, PHAC_DISCLOOP_CONFIG_GTFB_VALUE_US, 20400);
    CHECK_STATUS(status);

    /* Guard time for Type F. This guard time is applied when Type B poll before Type F */
    status = phacDiscLoop_SetConfig(pDiscLoop, PHAC_DISCLOOP_CONFIG_GTBF_VALUE_US, 15300);
    CHECK_STATUS(status);
#endif

#ifdef NXPBUILD__PHAC_DISCLOOP_TYPEV_TAGS
    /* Device limit for Type V (ISO 15693) */
    status = phacDiscLoop_SetConfig(pDiscLoop, PHAC_DISCLOOP_CONFIG_TYPEV_DEVICE_LIMIT, 1);
    CHECK_STATUS(status);

    status = phacDiscLoop_SetConfig(pDiscLoop, PHAC_DISCLOOP_CONFIG_GTV_VALUE_US, 5200);
    CHECK_STATUS(status);
#endif

#ifdef NXPBUILD__PHAC_DISCLOOP_I18000P3M3_TAGS
    /* Device limit for 18000P3M3 */
    status = phacDiscLoop_SetConfig(pDiscLoop, PHAC_DISCLOOP_CONFIG_18000P3M3_DEVICE_LIMIT, 1);
    CHECK_STATUS(status);

    status = phacDiscLoop_SetConfig(pDiscLoop, PHAC_DISCLOOP_CONFIG_GT18000P3M3_VALUE_US, 10000);
    CHECK_STATUS(status);
#endif

    /* NFC Activity version supported */
    status = phacDiscLoop_SetConfig(pDiscLoop, PHAC_DISCLOOP_CONFIG_ACTIVITY_VERSION,
            PHAC_DISCLOOP_NFC_ACTIVITY_VERSION_1_1);
    CHECK_STATUS(status);

    /* Discovery loop Operation mode */
    status = phacDiscLoop_SetConfig(pDiscLoop, PHAC_DISCLOOP_CONFIG_OPE_MODE, RD_LIB_MODE_NFC);
    CHECK_STATUS(status);
  } else if (bProfile == PHAC_DISCLOOP_PROFILE_EMVCO) {
    /* EMVCO */
    /* passive Bailout bitmap config. */
    status = phacDiscLoop_SetConfig(pDiscLoop, PHAC_DISCLOOP_CONFIG_BAIL_OUT, 0x00);
    CHECK_STATUS(status);

    /* passive poll bitmap config. */
    status = phacDiscLoop_SetConfig(pDiscLoop, PHAC_DISCLOOP_CONFIG_PAS_POLL_TECH_CFG,
            (PHAC_DISCLOOP_POS_BIT_MASK_A | PHAC_DISCLOOP_POS_BIT_MASK_B));
    CHECK_STATUS(status);

    /* Active Listen bitmap config. */
    status = phacDiscLoop_SetConfig(pDiscLoop, PHAC_DISCLOOP_CONFIG_PAS_LIS_TECH_CFG, 0x00);
    CHECK_STATUS(status);

    /* Active Listen bitmap config. */
    status = phacDiscLoop_SetConfig(pDiscLoop, PHAC_DISCLOOP_CONFIG_ACT_LIS_TECH_CFG, 0x00);
    CHECK_STATUS(status);

    /* Active Poll bitmap config. */
    status = phacDiscLoop_SetConfig(pDiscLoop, PHAC_DISCLOOP_CONFIG_ACT_POLL_TECH_CFG, 0x00);
    CHECK_STATUS(status);

    /* Bool to enable LPCD feature. */
    status = phacDiscLoop_SetConfig(pDiscLoop, PHAC_DISCLOOP_CONFIG_ENABLE_LPCD, PH_OFF);
    CHECK_STATUS(status);

    /* reset collision Pending */
    status = phacDiscLoop_SetConfig(pDiscLoop, PHAC_DISCLOOP_CONFIG_COLLISION_PENDING, PH_OFF);
    CHECK_STATUS(status);

    /* whether anti-collision is supported or not. */
    status = phacDiscLoop_SetConfig(pDiscLoop, PHAC_DISCLOOP_CONFIG_ANTI_COLL, PH_ON);
    CHECK_STATUS(status);

    /* Poll Mode default state*/
    status = phacDiscLoop_SetConfig(pDiscLoop, PHAC_DISCLOOP_CONFIG_NEXT_POLL_STATE,
            PHAC_DISCLOOP_POLL_STATE_DETECTION);
    CHECK_STATUS(status);

#ifdef NXPBUILD__PHAC_DISCLOOP_TYPEA_TAGS
    /* Device limit for Type A */
    status = phacDiscLoop_SetConfig(pDiscLoop, PHAC_DISCLOOP_CONFIG_TYPEA_DEVICE_LIMIT, 1);
    CHECK_STATUS(status);

    /* Passive polling Tx Guard times in micro seconds. */
    status = phacDiscLoop_SetConfig(pDiscLoop, PHAC_DISCLOOP_CONFIG_GTA_VALUE_US, 5100);
    CHECK_STATUS(status);

    /* Configure FSDI for the 14443P4A tags */
    status = phacDiscLoop_SetConfig(pDiscLoop, PHAC_DISCLOOP_CONFIG_TYPEA_I3P4_FSDI, 0x08);
    CHECK_STATUS(status);

    /* Configure CID for the 14443P4A tags */
    status = phacDiscLoop_SetConfig(pDiscLoop, PHAC_DISCLOOP_CONFIG_TYPEA_I3P4_CID, 0x00);
    CHECK_STATUS(status);

    /* Configure DRI for the 14443P4A tags */
    status = phacDiscLoop_SetConfig(pDiscLoop, PHAC_DISCLOOP_CONFIG_TYPEA_I3P4_DRI, 0x00);
    CHECK_STATUS(status);

    /* Configure DSI for the 14443P4A tags */
    status = phacDiscLoop_SetConfig(pDiscLoop, PHAC_DISCLOOP_CONFIG_TYPEA_I3P4_DSI, 0x00);
    CHECK_STATUS(status);
#endif

#ifdef NXPBUILD__PHAC_DISCLOOP_TYPEB_TAGS
    /* Device limit for Type B */
    status = phacDiscLoop_SetConfig(pDiscLoop, PHAC_DISCLOOP_CONFIG_TYPEB_DEVICE_LIMIT, 1);
    CHECK_STATUS(status);

    status = phacDiscLoop_SetConfig(pDiscLoop, PHAC_DISCLOOP_CONFIG_GTB_VALUE_US, 5100);
    CHECK_STATUS(status);

    /* Configure AFI for the type B tags */
    status = phacDiscLoop_SetConfig(pDiscLoop, PHAC_DISCLOOP_CONFIG_TYPEB_AFI_REQ, 0x00);
    CHECK_STATUS(status);

    /* Configure FSDI for the type B tags */
    status = phacDiscLoop_SetConfig(pDiscLoop, PHAC_DISCLOOP_CONFIG_TYPEB_FSDI, 0x08);
    CHECK_STATUS(status);

    /* Configure CID for the type B tags */
    status = phacDiscLoop_SetConfig(pDiscLoop, PHAC_DISCLOOP_CONFIG_TYPEB_CID, 0x00);
    CHECK_STATUS(status);

    /* Configure DRI for the type B tags */
    status = phacDiscLoop_SetConfig(pDiscLoop, PHAC_DISCLOOP_CONFIG_TYPEB_DRI, 0x00);
    CHECK_STATUS(status);

    /* Configure DSI for the type B tags */
    status = phacDiscLoop_SetConfig(pDiscLoop, PHAC_DISCLOOP_CONFIG_TYPEB_DSI, 0x00);
    CHECK_STATUS(status);

    /* Configure Extended ATQB support for the type B tags */
    status = phacDiscLoop_SetConfig(pDiscLoop, PHAC_DISCLOOP_CONFIG_TYPEB_EXTATQB, 0x00);
    CHECK_STATUS(status);
#endif
    /* Configure reader library mode */
    status = phacDiscLoop_SetConfig(pDiscLoop, PHAC_DISCLOOP_CONFIG_OPE_MODE, RD_LIB_MODE_EMVCO);
    CHECK_STATUS(status);
  } else {
    /* Do Nothing */
  }
  return status;
}
#endif /* ENABLE_DISC_CONFIG */

/******************************************************************************
**                            End Of File
******************************************************************************/
