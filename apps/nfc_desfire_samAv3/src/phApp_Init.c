/* Status header */
#include <nxp_nfc/ph_Status.h>

#include "phApp_Init.h"

/* NFCLIB Header */
#include <nxp_nfc/phNfcLib.h>

/* LLCP header */
#include <nxp_nfc/phlnLlcp.h>

#ifdef PH_PLATFORM_HAS_ICFRONTEND
#include "nxp_nfc/BoardSelection.h"
#endif

#ifdef NXPBUILD__PHHAL_HW_PN5180
/* HAL specific headers */
#include <nxp_nfc/phhalHw_Pn5180_Instr.h>
#endif

#include <nxp_nfc/phDriver_Gpio.h>

#include <console/console.h>

#ifdef PH_PLATFORM_HAS_ICFRONTEND
void CLIF_IRQHandler(void);
#endif

phStatus_t phApp_Configure_IRQ();

/*******************************************************************************
**   Global Variable Declaration
*******************************************************************************/
#ifdef PH_PLATFORM_HAS_ICFRONTEND
phbalReg_Type_t                 sBalParams;
#endif /* PH_PLATFORM_HAS_ICFRONTEND */

#ifdef NXPBUILD__PHHAL_HW_PN5180
phhalHw_Pn5180_DataParams_t    *pHal;
#endif

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

#ifdef NXPBUILD__PHHAL_HW_TARGET
/* Parameters for L3 activation during Autocoll */
extern uint8_t  sens_res[2]    ;
extern uint8_t  nfc_id1[3]     ;
extern uint8_t  sel_res        ;
extern uint8_t  nfc_id3        ;
extern uint8_t  poll_res[18]   ;
#endif /* NXPBUILD__PHHAL_HW_TARGET */

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

/**
* This function will initialize Hal Target Config
*/
phStatus_t
phApp_HALConfigAutoColl(void)
{
#ifdef NXPBUILD__PHHAL_HW_TARGET
  phStatus_t wStatus;
#endif /* NXPBUILD__PHHAL_HW_TARGET */

#if defined(NXPBUILD__PHHAL_HW_PN5180) && defined(NXPBUILD__PHHAL_HW_TARGET)
  uint8_t aCmd[1] = {0x01};   /* Enable Random UID feature on Pn5180 FW. */
#endif

#if defined(NXPBUILD__PHHAL_HW_PN7462AU) && defined(NXPBUILD__PHHAL_HW_TARGET)
  uint8_t bSystemCode[] = {0xFF, 0xFF};
#endif /* NXPBUILD__PHHAL_HW_PN7462AU && NXPBUILD__PHHAL_HW_TARGET */

#if defined(NXPBUILD__PHHAL_HW_PN5180) && defined(NXPBUILD__PHHAL_HW_TARGET)
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
#endif

#if defined(NXPBUILD__PHHAL_HW_PN7462AU) && defined(NXPBUILD__PHHAL_HW_TARGET)
  /* Set Listen Parameters in HAL Buffer used during Autocoll */
  wStatus = phhalHw_PN7462AU_SetListenParam(
          pHal,
          &sens_res[0],
          &nfc_id1[0],
          sel_res,
          (poll_res[0] == 0x02 ? PH_ON : PH_OFF),
          &poll_res[2],
          &poll_res[8],
          bSystemCode);
  CHECK_SUCCESS(wStatus);
#endif

  return PH_ERR_SUCCESS;
}

phStatus_t
phApp_Configure_IRQ()
{
#ifdef PH_PLATFORM_HAS_ICFRONTEND
  int rc = hal_gpio_irq_init(PHDRIVER_PIN_IRQ, (hal_gpio_irq_handler_t)CLIF_IRQHandler, NULL,
          PIN_IRQ_TRIGGER_TYPE, PHDRIVER_PIN_IRQ_PULL_CFG);
  hal_gpio_irq_enable(PHDRIVER_PIN_IRQ);
#endif /* #ifdef PH_PLATFORM_HAS_ICFRONTEND */

  if (!rc) {
    return PH_ERR_SUCCESS;
  } else {
    return PH_ERR_PARAMETER_OVERFLOW;
  }
}

#ifdef PH_PLATFORM_HAS_ICFRONTEND
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
#endif /* PH_PLATFORM_HAS_ICFRONTEND */

#ifdef NXPBUILD__PHHAL_HW_PN5180
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
#endif

/* Print technology being resolved */
void
phApp_PrintTech(uint8_t TechType)
{
  switch (TechType) {
    case PHAC_DISCLOOP_POS_BIT_MASK_A:
      console_printf("\tResolving Type A... \n");
      break;

    case PHAC_DISCLOOP_POS_BIT_MASK_B:
      console_printf("\tResolving Type B... \n");
      break;

    case PHAC_DISCLOOP_POS_BIT_MASK_F212:
      console_printf("\tResolving Type F with baud rate 212... \n");
      break;

    case PHAC_DISCLOOP_POS_BIT_MASK_F424:
      console_printf("\tResolving Type F with baud rate 424... \n");
      break;

    case PHAC_DISCLOOP_POS_BIT_MASK_V:
      console_printf("\tResolving Type V... \n");
      break;

    default:
      break;
  }
}

/**
* This function will print buffer content
* \param   *pBuff   Buffer Reference
* \param   num      data size to be print
*/
void
phApp_Print_Buff(uint8_t *pBuff, uint8_t num)
{
  uint32_t    i;

  for (i = 0; i < num; i++) {
    console_printf(" %02X", pBuff[i]);
  }
}

/**
* This function will print Tag information
* \param   pDataParams      The discovery loop data parameters
* \param   wNumberOfTags    Total number of tags detected
* \param   wTagsDetected    Technology Detected
*/
void
phApp_PrintTagInfo(phacDiscLoop_Sw_DataParams_t *pDataParams, uint16_t wNumberOfTags,
    uint16_t wTagsDetected)
{
#if defined(NXPBUILD__PHAC_DISCLOOP_TYPEA_TAGS) || \
    defined(NXPBUILD__PHAC_DISCLOOP_TYPEA_P2P_ACTIVE) || \
    defined(NXPBUILD__PHAC_DISCLOOP_TYPEB_TAGS) || \
    defined(NXPBUILD__PHAC_DISCLOOP_TYPEF_TAGS) || \
    defined(NXPBUILD__PHAC_DISCLOOP_TYPEV_TAGS) || \
    defined(NXPBUILD__PHAC_DISCLOOP_I18000P3M3_TAGS)
  uint8_t bIndex;
#endif
#if defined(NXPBUILD__PHAC_DISCLOOP_TYPEA_TAGS) || defined(NXPBUILD__PHAC_DISCLOOP_TYPEA_P2P_ACTIVE)
  uint8_t bTagType;
#endif

#if defined(NXPBUILD__PHAC_DISCLOOP_TYPEA_TAGS) || defined(NXPBUILD__PHAC_DISCLOOP_TYPEA_P2P_ACTIVE)
  if (PHAC_DISCLOOP_CHECK_ANDMASK(wTagsDetected, PHAC_DISCLOOP_POS_BIT_MASK_A)) {
    if (pDataParams->sTypeATargetInfo.bT1TFlag) {
      console_printf("\tTechnology  : Type A");
      console_printf("\n\t\tUID :");
      phApp_Print_Buff(pDataParams->sTypeATargetInfo.aTypeA_I3P3[0].aUid,
          pDataParams->sTypeATargetInfo.aTypeA_I3P3[0].bUidSize);
      console_printf("\n\t\tSAK : 0x%02x", pDataParams->sTypeATargetInfo.aTypeA_I3P3[0].aSak);
      console_printf("\n\t\tType: Type 1 Tag\n");
    } else {
      console_printf("\tTechnology  : Type A");
      for (bIndex = 0; bIndex < wNumberOfTags; bIndex++) {
        console_printf("\n\t\tCard: %d", bIndex + 1);
        console_printf("\n\t\tUID :");
        phApp_Print_Buff(pDataParams->sTypeATargetInfo.aTypeA_I3P3[bIndex].aUid,
            pDataParams->sTypeATargetInfo.aTypeA_I3P3[bIndex].bUidSize);
        console_printf("\n\t\tSAK : 0x%02x", pDataParams->sTypeATargetInfo.aTypeA_I3P3[bIndex].aSak);

        if ((pDataParams->sTypeATargetInfo.aTypeA_I3P3[bIndex].aSak & (uint8_t) ~0xFB) == 0) {
          /* Bit b3 is set to zero, [Digital] 4.8.2 */
          /* Mask out all other bits except for b7 and b6 */
          bTagType = (pDataParams->sTypeATargetInfo.aTypeA_I3P3[bIndex].aSak & 0x60);
          bTagType = bTagType >> 5;

          switch (bTagType) {
            case PHAC_DISCLOOP_TYPEA_TYPE2_TAG_CONFIG_MASK:
              console_printf("\n\t\tType: Type 2 Tag\n");
              break;
            case PHAC_DISCLOOP_TYPEA_TYPE4A_TAG_CONFIG_MASK:
              console_printf("\n\t\tType: Type 4A Tag\n");
              break;
            case PHAC_DISCLOOP_TYPEA_TYPE_NFC_DEP_TAG_CONFIG_MASK:
              console_printf("\n\t\tType: P2P\n");
              break;
            case PHAC_DISCLOOP_TYPEA_TYPE_NFC_DEP_TYPE4A_TAG_CONFIG_MASK:
              console_printf("\n\t\tType: Type NFC_DEP and  4A Tag\n");
              break;
            default:
              break;
          }
        }
      }
    }
  }
#endif

#ifdef NXPBUILD__PHAC_DISCLOOP_TYPEB_TAGS
  if (PHAC_DISCLOOP_CHECK_ANDMASK(wTagsDetected, PHAC_DISCLOOP_POS_BIT_MASK_B)) {
    console_printf("\tTechnology  : Type B");
    /* Loop through all the Type B tags detected and print the Pupi */
    for (bIndex = 0; bIndex < wNumberOfTags; bIndex++) {
      console_printf("\n\t\tCard: %d", bIndex + 1);
      console_printf("\n\t\tUID :");
      /* PUPI Length is always 4 bytes */
      phApp_Print_Buff(pDataParams->sTypeBTargetInfo.aTypeB_I3P3[bIndex].aPupi, 0x04);
    }
    console_printf("\n");
  }
#endif

#ifdef NXPBUILD__PHAC_DISCLOOP_TYPEF_TAGS
  if (PHAC_DISCLOOP_CHECK_ANDMASK(wTagsDetected, PHAC_DISCLOOP_POS_BIT_MASK_F212) ||
      PHAC_DISCLOOP_CHECK_ANDMASK(wTagsDetected, PHAC_DISCLOOP_POS_BIT_MASK_F424)) {
    console_printf("\tTechnology  : Type F");

    /* Loop through all the type F tags and print the IDm */
    for (bIndex = 0; bIndex < wNumberOfTags; bIndex++) {
      console_printf("\n\t\tCard: %d", bIndex + 1);
      console_printf("\n\t\tUID :");
      phApp_Print_Buff(pDataParams->sTypeFTargetInfo.aTypeFTag[bIndex].aIDmPMm,
          PHAC_DISCLOOP_FELICA_IDM_LENGTH);
      if ((pDataParams->sTypeFTargetInfo.aTypeFTag[bIndex].aIDmPMm[0] == 0x01) &&
          (pDataParams->sTypeFTargetInfo.aTypeFTag[bIndex].aIDmPMm[1] == 0xFE)) {
        /* This is Type F tag with P2P capabilities */
        console_printf("\n\t\tType: P2P");
      } else {
        /* This is Type F T3T tag */
        console_printf("\n\t\tType: Type 3 Tag");
      }

      if (pDataParams->sTypeFTargetInfo.aTypeFTag[bIndex].bBaud != PHAC_DISCLOOP_CON_BITR_212) {
        console_printf("\n\t\tBit Rate: 424\n");
      } else {
        console_printf("\n\t\tBit Rate: 212\n");
      }
    }
  }
#endif

#ifdef NXPBUILD__PHAC_DISCLOOP_TYPEV_TAGS
  if (PHAC_DISCLOOP_CHECK_ANDMASK(wTagsDetected, PHAC_DISCLOOP_POS_BIT_MASK_V)) {
    console_printf("\tTechnology  : Type V / ISO 15693 / T5T");
    /* Loop through all the Type V tags detected and print the UIDs */
    for (bIndex = 0; bIndex < wNumberOfTags; bIndex++) {
      console_printf("\n\t\tCard: %d", bIndex + 1);
      console_printf("\n\t\tUID :");
      phApp_Print_Buff(pDataParams->sTypeVTargetInfo.aTypeV[bIndex].aUid, 0x08);
    }
    console_printf("\n");
  }
#endif

#ifdef NXPBUILD__PHAC_DISCLOOP_I18000P3M3_TAGS
  if (PHAC_DISCLOOP_CHECK_ANDMASK(wTagsDetected, PHAC_DISCLOOP_POS_BIT_MASK_18000P3M3)) {
    console_printf("\tTechnology  : ISO 18000p3m3 / EPC Gen2");
    /* Loop through all the 18000p3m3 tags detected and print the UII */
    for (bIndex = 0; bIndex < wNumberOfTags; bIndex++) {
      console_printf("\n\t\tCard: %d", bIndex + 1);
      console_printf("\n\t\tUII :");
      phApp_Print_Buff(
          pDataParams->sI18000p3m3TargetInfo.aI18000p3m3[bIndex].aUii,
          (pDataParams->sI18000p3m3TargetInfo.aI18000p3m3[bIndex].wUiiLength / 8));
    }
    console_printf("\n");
  }
#endif
}

/**
* This function will print Error information received from Reader Lib
* \param   wStatus      Error status
*/
void
PrintErrorInfo(phStatus_t wStatus)
{
  console_printf("\n ErrorInfo Comp:");

  switch (wStatus & 0xFF00) {
    case PH_COMP_BAL:
      console_printf("\t PH_COMP_BAL");
      break;
    case PH_COMP_HAL:
      console_printf("\t PH_COMP_HAL");
      break;
    case PH_COMP_PAL_ISO14443P3A:
      console_printf("\t PH_COMP_PAL_ISO14443P3A");
      break;
    case PH_COMP_PAL_ISO14443P3B:
      console_printf("\t PH_COMP_PAL_ISO14443P3B");
      break;
    case PH_COMP_PAL_ISO14443P4A:
      console_printf("\t PH_COMP_PAL_ISO14443P4A");
      break;
    case PH_COMP_PAL_ISO14443P4:
      console_printf("\t PH_COMP_PAL_ISO14443P4");
      break;
    case PH_COMP_PAL_FELICA:
      console_printf("\t PH_COMP_PAL_FELICA");
      break;
    case PH_COMP_PAL_EPCUID:
      console_printf("\t PH_COMP_PAL_EPCUID");
      break;
    case PH_COMP_PAL_SLI15693:
      console_printf("\t PH_COMP_PAL_SLI15693");
      break;
    case PH_COMP_PAL_I18000P3M3:
      console_printf("\t PH_COMP_PAL_I18000P3M3");
      break;
    case PH_COMP_PAL_I18092MPI:
      console_printf("\t PH_COMP_PAL_I18092MPI");
      break;
    case PH_COMP_PAL_I18092MT:
      console_printf("\t PH_COMP_PAL_I18092MT");
      break;
    case PH_COMP_PAL_I14443P4MC:
      console_printf("\t PH_COMP_PAL_I14443P4MC");
      break;
    case PH_COMP_AC_DISCLOOP:
      console_printf("\t PH_COMP_AC_DISCLOOP");
      break;
    case PH_COMP_OSAL:
      console_printf("\t PH_COMP_OSAL");
      break;
    default:
      console_printf("\t 0x%x", (wStatus & PH_COMPID_MASK));
      break;
  }

  console_printf("\t type:");

  switch (wStatus & PH_ERR_MASK) {
    case PH_ERR_SUCCESS_INCOMPLETE_BYTE:
      console_printf("\t PH_ERR_SUCCESS_INCOMPLETE_BYTE");
      break;
    case PH_ERR_IO_TIMEOUT:
      console_printf("\t PH_ERR_IO_TIMEOUT");
      break;
    case PH_ERR_INTEGRITY_ERROR:
      console_printf("\t PH_ERR_INTEGRITY_ERROR");
      break;
    case PH_ERR_COLLISION_ERROR:
      console_printf("\t PH_ERR_COLLISION_ERROR");
      break;
    case PH_ERR_BUFFER_OVERFLOW:
      console_printf("\t PH_ERR_BUFFER_OVERFLOW");
      break;
    case PH_ERR_FRAMING_ERROR:
      console_printf("\t PH_ERR_FRAMING_ERROR");
      break;
    case PH_ERR_PROTOCOL_ERROR:
      console_printf("\t PH_ERR_PROTOCOL_ERROR");
      break;
    case PH_ERR_RF_ERROR:
      console_printf("\t PH_ERR_RF_ERROR");
      break;
    case PH_ERR_EXT_RF_ERROR:
      console_printf("\t PH_ERR_EXT_RF_ERROR");
      break;
    case PH_ERR_NOISE_ERROR:
      console_printf("\t PH_ERR_NOISE_ERROR");
      break;
    case PH_ERR_ABORTED:
      console_printf("\t PH_ERR_ABORTED");
      break;
    case PH_ERR_INTERNAL_ERROR:
      console_printf("\t PH_ERR_INTERNAL_ERROR");
      break;
    case PH_ERR_INVALID_DATA_PARAMS:
      console_printf("\t PH_ERR_INVALID_DATA_PARAMS");
      break;
    case PH_ERR_INVALID_PARAMETER:
      console_printf("\t PH_ERR_INVALID_PARAMETER");
      break;
    case PH_ERR_PARAMETER_OVERFLOW:
      console_printf("\t PH_ERR_PARAMETER_OVERFLOW");
      break;
    case PH_ERR_UNSUPPORTED_PARAMETER:
      console_printf("\t PH_ERR_UNSUPPORTED_PARAMETER");
      break;
    case PH_ERR_OSAL_ERROR:
      console_printf("\t PH_ERR_OSAL_ERROR");
      break;
    case PHAC_DISCLOOP_LPCD_NO_TECH_DETECTED:
      console_printf("\t PHAC_DISCLOOP_LPCD_NO_TECH_DETECTED");
      break;
    case PHAC_DISCLOOP_COLLISION_PENDING:
      console_printf("\t PHAC_DISCLOOP_COLLISION_PENDING");
      break;
    default:
      console_printf("\t 0x%x", (wStatus & PH_ERR_MASK));
      break;
  }
}

/******************************************************************************
**                            End Of File
******************************************************************************/
