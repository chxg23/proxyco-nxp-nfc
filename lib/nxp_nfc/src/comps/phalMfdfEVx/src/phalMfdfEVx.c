/*----------------------------------------------------------------------------*/
/* Copyright 2014-2020 NXP                                                    */
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
* Generic MIFARE DESFire EVx contactless IC (EV1, EV2, EV3, future versions ) Application Component of Reader Library Framework.
* $Author: Rajendran Kumar (nxp99556) $
* $Revision: 6114 $ (v06.10.00)
* $Date: 2020-05-15 18:23:52 +0530 (Fri, 15 May 2020) $
*
*/

#include <nxp_nfc/phalMfdfEVx.h>
#include <nxp_nfc/ph_Status.h>
#include <nxp_nfc/ph_TypeDefs.h>

#ifdef NXPBUILD__PHAL_MFDFEVX_SW
#include "Sw/phalMfdfEVx_Sw.h"
#endif /* NXPBUILD__PHAL_MFDFEVX_SW */

#ifdef NXPBUILD__PHAL_MFDFEVX

#ifdef NXPBUILD__PHAL_MFDFEVX_NDA
/* MIFARE DESFire EVx secure messaging related commands. ------------------------------------------------------------------------------- */
phStatus_t phalMfdfEVx_Authenticate(void *pDataParams, uint16_t wOption, uint16_t wKeyNo,
    uint16_t wKeyVer, uint8_t bKeyNoCard,
    uint8_t *pDivInput, uint8_t bDivLen)
{
  phStatus_t PH_MEMLOC_REM status;

  PH_LOG_HELPER_ALLOCATE_TEXT(bFunctionName, "phalMfdfEVx_Authenticate");
  PH_LOG_HELPER_ALLOCATE_PARAMNAME(wKeyNo);
  PH_LOG_HELPER_ALLOCATE_PARAMNAME(bKeyNoCard);
  PH_LOG_HELPER_ALLOCATE_PARAMNAME(pDivInput);
  PH_LOG_HELPER_ALLOCATE_PARAMNAME(status);
  PH_LOG_HELPER_ADDSTRING(PH_LOG_LOGTYPE_INFO, bFunctionName);
  PH_LOG_HELPER_ADDPARAM_UINT16(PH_LOG_LOGTYPE_DEBUG, wKeyNo_log, &wKeyNo);
  PH_LOG_HELPER_ADDPARAM_UINT8(PH_LOG_LOGTYPE_DEBUG, bKeyNoCard_log, &bKeyNoCard);
  PH_LOG_HELPER_ADDPARAM_BUFFER(PH_LOG_LOGTYPE_DEBUG, pDivInput_log, pDivInput, bDivLen);
  PH_LOG_HELPER_EXECUTE(PH_LOG_OPTION_CATEGORY_ENTER);

  /* Validate the parameters */
  PH_ASSERT_NULL_DATA_PARAM(pDataParams, PH_COMP_AL_MFDFEVX);
  if (bDivLen) {
    PH_ASSERT_NULL_PARAM(pDivInput, PH_COMP_AL_MFDFEVX);
  }

  /* Parameter validation */
  if (PH_GET_COMPCODE(pDataParams) != PH_COMP_AL_MFDFEVX) {
    PH_LOG_HELPER_ADDSTRING(PH_LOG_LOGTYPE_INFO, bFunctionName);
    PH_LOG_HELPER_ADDPARAM_UINT16(PH_LOG_LOGTYPE_INFO, status_log, &status);
    PH_LOG_HELPER_EXECUTE(PH_LOG_OPTION_CATEGORY_LEAVE);
    return PH_ADD_COMPCODE_FIXED(PH_ERR_INVALID_DATA_PARAMS, PH_COMP_AL_MFDFEVX);
  }

  /* Perform operation on active layer */
  switch (PH_GET_COMPID(pDataParams)) {
#ifdef NXPBUILD__PHAL_MFDFEVX_SW
    case PHAL_MFDFEVX_SW_ID:
      status = phalMfdfEVx_Sw_Authenticate((phalMfdfEVx_Sw_DataParams_t *) pDataParams, wOption, wKeyNo,
              wKeyVer,
              bKeyNoCard, pDivInput, bDivLen);
      break;
#endif /* NXPBUILD__PHAL_MFDFEVX_SW */

    default:
      status = PH_ADD_COMPCODE_FIXED(PH_ERR_INVALID_DATA_PARAMS, PH_COMP_AL_MFDFEVX);
      break;
  }

  PH_LOG_HELPER_ADDSTRING(PH_LOG_LOGTYPE_INFO, bFunctionName);
  PH_LOG_HELPER_ADDPARAM_UINT16(PH_LOG_LOGTYPE_INFO, status_log, &status);
  PH_LOG_HELPER_EXECUTE(PH_LOG_OPTION_CATEGORY_LEAVE);

  return status;
}

phStatus_t phalMfdfEVx_AuthenticateISO(void *pDataParams, uint16_t wOption, uint16_t wKeyNo,
    uint16_t wKeyVer, uint8_t bKeyNoCard,
    uint8_t *pDivInput, uint8_t bDivLen)
{
  /**
  * The key type can be DES, 3DES, 3K3DES.
  * Random numbers can be 8 or 16 bytes long
  * Init vector can be 8 or 16 bytes long
  * Session key max size is 24 bytes if 3k3DES keys  are used.
  */
  phStatus_t PH_MEMLOC_REM status;

  PH_LOG_HELPER_ALLOCATE_TEXT(bFunctionName, "phalMfdfEVx_AuthenticateISO");
  PH_LOG_HELPER_ALLOCATE_PARAMNAME(wKeyNo);
  PH_LOG_HELPER_ALLOCATE_PARAMNAME(bKeyNoCard);
  PH_LOG_HELPER_ALLOCATE_PARAMNAME(pDivInput);
  PH_LOG_HELPER_ALLOCATE_PARAMNAME(status);
  PH_LOG_HELPER_ADDSTRING(PH_LOG_LOGTYPE_INFO, bFunctionName);
  PH_LOG_HELPER_ADDPARAM_UINT16(PH_LOG_LOGTYPE_DEBUG, wKeyNo_log, &wKeyNo);
  PH_LOG_HELPER_ADDPARAM_UINT8(PH_LOG_LOGTYPE_DEBUG, bKeyNoCard_log, &bKeyNoCard);
  PH_LOG_HELPER_ADDPARAM_BUFFER(PH_LOG_LOGTYPE_DEBUG, pDivInput_log, pDivInput, bDivLen);
  PH_LOG_HELPER_EXECUTE(PH_LOG_OPTION_CATEGORY_ENTER);

  /* Validate the parameters */
  PH_ASSERT_NULL_DATA_PARAM(pDataParams, PH_COMP_AL_MFDFEVX);
  if (0U != (bDivLen)) {
    PH_ASSERT_NULL_PARAM(pDivInput, PH_COMP_AL_MFDFEVX);
  }

  /* Parameter validation */
  if (PH_GET_COMPCODE(pDataParams) != PH_COMP_AL_MFDFEVX) {
    PH_LOG_HELPER_ADDSTRING(PH_LOG_LOGTYPE_INFO, bFunctionName);
    PH_LOG_HELPER_ADDPARAM_UINT16(PH_LOG_LOGTYPE_INFO, status_log, &status);
    PH_LOG_HELPER_EXECUTE(PH_LOG_OPTION_CATEGORY_LEAVE);
    return PH_ADD_COMPCODE_FIXED(PH_ERR_INVALID_DATA_PARAMS, PH_COMP_AL_MFDFEVX);
  }

  /* Perform operation on active layer */
  switch (PH_GET_COMPID(pDataParams)) {
#ifdef NXPBUILD__PHAL_MFDFEVX_SW
    case PHAL_MFDFEVX_SW_ID:
      status = phalMfdfEVx_Sw_AuthenticateISO((phalMfdfEVx_Sw_DataParams_t *) pDataParams, wOption,
              wKeyNo, wKeyVer,
              bKeyNoCard, pDivInput, bDivLen);
      break;
#endif /* NXPBUILD__PHAL_MFDFEVX_SW */

    default:
      status = PH_ADD_COMPCODE_FIXED(PH_ERR_INVALID_DATA_PARAMS, PH_COMP_AL_MFDFEVX);
      break;
  }

  PH_LOG_HELPER_ADDSTRING(PH_LOG_LOGTYPE_INFO, bFunctionName);
  PH_LOG_HELPER_ADDPARAM_UINT16(PH_LOG_LOGTYPE_INFO, status_log, &status);
  PH_LOG_HELPER_EXECUTE(PH_LOG_OPTION_CATEGORY_LEAVE);

  return status;
}

phStatus_t phalMfdfEVx_AuthenticateAES(void *pDataParams, uint16_t wOption, uint16_t wKeyNo,
    uint16_t wKeyVer, uint8_t bKeyNoCard,
    uint8_t *pDivInput, uint8_t bDivLen)
{
  /**
  * The key type can be AES only.
  * Random numbers are 16 bytes long
  * Init vector is 16 bytes long
  * Session key size is 16 bytes.
  *
  */
  phStatus_t PH_MEMLOC_REM status;

  PH_LOG_HELPER_ALLOCATE_TEXT(bFunctionName, "phalMfdfEVx_AuthenticateAES");
  PH_LOG_HELPER_ALLOCATE_PARAMNAME(wKeyNo);
  PH_LOG_HELPER_ALLOCATE_PARAMNAME(bKeyNoCard);
  PH_LOG_HELPER_ALLOCATE_PARAMNAME(pDivInput);
  PH_LOG_HELPER_ALLOCATE_PARAMNAME(status);
  PH_LOG_HELPER_ADDSTRING(PH_LOG_LOGTYPE_INFO, bFunctionName);
  PH_LOG_HELPER_ADDPARAM_UINT16(PH_LOG_LOGTYPE_DEBUG, wKeyNo_log, &wKeyNo);
  PH_LOG_HELPER_ADDPARAM_UINT8(PH_LOG_LOGTYPE_DEBUG, bKeyNoCard_log, &bKeyNoCard);
  PH_LOG_HELPER_ADDPARAM_BUFFER(PH_LOG_LOGTYPE_DEBUG, pDivInput_log, pDivInput, bDivLen);
  PH_LOG_HELPER_EXECUTE(PH_LOG_OPTION_CATEGORY_ENTER);

  /* Validate the parameters */
  PH_ASSERT_NULL_DATA_PARAM(pDataParams, PH_COMP_AL_MFDFEVX);
  if (0U != (bDivLen)) {
    PH_ASSERT_NULL_PARAM(pDivInput, PH_COMP_AL_MFDFEVX);
  }

  /* Parameter validation */
  if (PH_GET_COMPCODE(pDataParams) != PH_COMP_AL_MFDFEVX) {
    PH_LOG_HELPER_ADDSTRING(PH_LOG_LOGTYPE_INFO, bFunctionName);
    PH_LOG_HELPER_ADDPARAM_UINT16(PH_LOG_LOGTYPE_INFO, status_log, &status);
    PH_LOG_HELPER_EXECUTE(PH_LOG_OPTION_CATEGORY_LEAVE);

    return PH_ADD_COMPCODE_FIXED(PH_ERR_INVALID_DATA_PARAMS, PH_COMP_AL_MFDFEVX);
  }

  /* Perform operation on active layer */
  switch (PH_GET_COMPID(pDataParams)) {
#ifdef NXPBUILD__PHAL_MFDFEVX_SW
    case PHAL_MFDFEVX_SW_ID:
      status = phalMfdfEVx_Sw_AuthenticateAES((phalMfdfEVx_Sw_DataParams_t *) pDataParams, wOption,
              wKeyNo, wKeyVer,
              bKeyNoCard, pDivInput, bDivLen);
      break;
#endif /* NXPBUILD__PHAL_MFDFEVX_SW */

    default:
      status = PH_ADD_COMPCODE_FIXED(PH_ERR_INVALID_DATA_PARAMS, PH_COMP_AL_MFDFEVX);
      break;
  }

  PH_LOG_HELPER_ADDSTRING(PH_LOG_LOGTYPE_INFO, bFunctionName);
  PH_LOG_HELPER_ADDPARAM_UINT16(PH_LOG_LOGTYPE_INFO, status_log, &status);
  PH_LOG_HELPER_EXECUTE(PH_LOG_OPTION_CATEGORY_LEAVE);

  return status;
}

phStatus_t phalMfdfEVx_AuthenticateEv2(void *pDataParams, uint8_t bFirstAuth, uint16_t wOption,
    uint16_t wKeyNo, uint16_t wKeyVer,
    uint8_t bKeyNoCard, uint8_t *pDivInput, uint8_t bDivLen, uint8_t bLenPcdCapsIn,
    uint8_t *bPcdCapsIn, uint8_t *bPcdCapsOut,
    uint8_t *bPdCapsOut)
{
  phStatus_t PH_MEMLOC_REM status;

  PH_LOG_HELPER_ALLOCATE_TEXT(bFunctionName, "phalMfdfEVx_AuthenticateEv2");
  PH_LOG_HELPER_ALLOCATE_PARAMNAME(bFirstAuth);
  PH_LOG_HELPER_ALLOCATE_PARAMNAME(wOption);
  PH_LOG_HELPER_ALLOCATE_PARAMNAME(wKeyNo);
  PH_LOG_HELPER_ALLOCATE_PARAMNAME(wKeyVer);
  PH_LOG_HELPER_ALLOCATE_PARAMNAME(bKeyNoCard);
  PH_LOG_HELPER_ALLOCATE_PARAMNAME(pDivInput);
  PH_LOG_HELPER_ALLOCATE_PARAMNAME(bPcdCapsIn);
  PH_LOG_HELPER_ALLOCATE_PARAMNAME(bPcdCapsOut);
  PH_LOG_HELPER_ALLOCATE_PARAMNAME(bPdCapsOut);
  PH_LOG_HELPER_ALLOCATE_PARAMNAME(status);
  PH_LOG_HELPER_ADDSTRING(PH_LOG_LOGTYPE_INFO, bFunctionName);
  PH_LOG_HELPER_ADDPARAM_UINT8(PH_LOG_LOGTYPE_DEBUG, bFirstAuth_log, &bFirstAuth);
  PH_LOG_HELPER_ADDPARAM_UINT16(PH_LOG_LOGTYPE_DEBUG, wOption_log, &wOption);
  PH_LOG_HELPER_ADDPARAM_UINT16(PH_LOG_LOGTYPE_DEBUG, wKeyNo_log, &wKeyNo);
  PH_LOG_HELPER_ADDPARAM_UINT16(PH_LOG_LOGTYPE_DEBUG, wKeyVer_log, &wKeyVer);
  PH_LOG_HELPER_ADDPARAM_UINT8(PH_LOG_LOGTYPE_DEBUG, bKeyNoCard_log, &bKeyNoCard);
  PH_LOG_HELPER_ADDPARAM_BUFFER(PH_LOG_LOGTYPE_DEBUG, pDivInput_log, pDivInput, bDivLen);
  PH_LOG_HELPER_ADDPARAM_BUFFER(PH_LOG_LOGTYPE_DEBUG, bPcdCapsIn_log, bPcdCapsIn, bLenPcdCapsIn);
  PH_LOG_HELPER_EXECUTE(PH_LOG_OPTION_CATEGORY_ENTER);

  /* Validate the parameters */
  PH_ASSERT_NULL_DATA_PARAM(pDataParams, PH_COMP_AL_MFDFEVX);
  if (0U != (bDivLen)) {
    PH_ASSERT_NULL_PARAM(pDivInput, PH_COMP_AL_MFDFEVX);
  }
  if (0U != (bLenPcdCapsIn)) {
    PH_ASSERT_NULL_PARAM(bPcdCapsIn, PH_COMP_AL_MFDFEVX);
  }

  /* Parameter validation */
  if (PH_GET_COMPCODE(pDataParams) != PH_COMP_AL_MFDFEVX) {
    PH_LOG_HELPER_ADDSTRING(PH_LOG_LOGTYPE_INFO, bFunctionName);
    PH_LOG_HELPER_ADDPARAM_UINT16(PH_LOG_LOGTYPE_INFO, status_log, &status);
    PH_LOG_HELPER_EXECUTE(PH_LOG_OPTION_CATEGORY_LEAVE);

    return PH_ADD_COMPCODE_FIXED(PH_ERR_INVALID_DATA_PARAMS, PH_COMP_AL_MFDFEVX);
  }

  /* Perform operation on active layer */
  switch (PH_GET_COMPID(pDataParams)) {
#ifdef NXPBUILD__PHAL_MFDFEVX_SW
    case PHAL_MFDFEVX_SW_ID:
      status = phalMfdfEVx_Sw_AuthenticateEv2((phalMfdfEVx_Sw_DataParams_t *) pDataParams, bFirstAuth,
              wOption, wKeyNo, wKeyVer,
              bKeyNoCard, pDivInput, bDivLen, bLenPcdCapsIn, bPcdCapsIn, bPcdCapsOut, bPdCapsOut);
      break;
#endif /* NXPBUILD__PHAL_MFDFEVX_SW */

    default:
      status = PH_ADD_COMPCODE_FIXED(PH_ERR_INVALID_DATA_PARAMS, PH_COMP_AL_MFDFEVX);
      break;
  }

  PH_LOG_HELPER_ADDSTRING(PH_LOG_LOGTYPE_INFO, bFunctionName);
  if (0U != (bFirstAuth)) {
    PH_LOG_HELPER_ADDPARAM_BUFFER(PH_LOG_LOGTYPE_DEBUG, bPcdCapsOut_log, bPcdCapsOut, 6);
    PH_LOG_HELPER_ADDPARAM_BUFFER(PH_LOG_LOGTYPE_DEBUG, bPdCapsOut_log, bPdCapsOut, 6);
  }
  PH_LOG_HELPER_ADDPARAM_UINT16(PH_LOG_LOGTYPE_INFO, status_log, &status);
  PH_LOG_HELPER_EXECUTE(PH_LOG_OPTION_CATEGORY_LEAVE);

  return status;
}
#endif /* NXPBUILD__PHAL_MFDFEVX_NDA */

/* MIFARE DESFire EVX Memory and Configuration mamangement commands. ------------------------------------------------------------------- */
phStatus_t phalMfdfEVx_FreeMem(void *pDataParams, uint8_t *pMemInfo)
{
  phStatus_t PH_MEMLOC_REM status;

  PH_LOG_HELPER_ALLOCATE_TEXT(bFunctionName, "phalMfdfEVx_FreeMem");
  PH_LOG_HELPER_ALLOCATE_PARAMNAME(pMemInfo);
  PH_LOG_HELPER_ALLOCATE_PARAMNAME(status);
  PH_LOG_HELPER_ADDSTRING(PH_LOG_LOGTYPE_INFO, bFunctionName);
  PH_LOG_HELPER_EXECUTE(PH_LOG_OPTION_CATEGORY_ENTER);

  /* Validate the parameters */
  PH_ASSERT_NULL_DATA_PARAM(pDataParams, PH_COMP_AL_MFDFEVX);
  PH_ASSERT_NULL_PARAM(pMemInfo, PH_COMP_AL_MFDFEVX);

  /* Parameter validation */
  if (PH_GET_COMPCODE(pDataParams) != PH_COMP_AL_MFDFEVX) {
    PH_LOG_HELPER_ADDSTRING(PH_LOG_LOGTYPE_INFO, bFunctionName);
    PH_LOG_HELPER_ADDPARAM_UINT16(PH_LOG_LOGTYPE_INFO, status_log, &status);
    PH_LOG_HELPER_EXECUTE(PH_LOG_OPTION_CATEGORY_LEAVE);

    return PH_ADD_COMPCODE_FIXED(PH_ERR_INVALID_DATA_PARAMS, PH_COMP_AL_MFDFEVX);
  }

  /* Perform operation on active layer */
  switch (PH_GET_COMPID(pDataParams)) {
#ifdef NXPBUILD__PHAL_MFDFEVX_SW
    case PHAL_MFDFEVX_SW_ID:
      status = phalMfdfEVx_Sw_FreeMem((phalMfdfEVx_Sw_DataParams_t *) pDataParams, pMemInfo);
      break;
#endif /* NXPBUILD__PHAL_MFDFEVX_SW */

    default:
      status = PH_ADD_COMPCODE_FIXED(PH_ERR_INVALID_DATA_PARAMS, PH_COMP_AL_MFDFEVX);
      break;
  }

  PH_LOG_HELPER_ADDSTRING(PH_LOG_LOGTYPE_INFO, bFunctionName);
  PH_LOG_HELPER_ADDPARAM_BUFFER(PH_LOG_LOGTYPE_DEBUG, pMemInfo_log, pMemInfo, 3);
  PH_LOG_HELPER_ADDPARAM_UINT16(PH_LOG_LOGTYPE_INFO, status_log, &status);
  PH_LOG_HELPER_EXECUTE(PH_LOG_OPTION_CATEGORY_LEAVE);

  return status;
}

#ifdef NXPBUILD__PHAL_MFDFEVX_NDA
phStatus_t phalMfdfEVx_Format(void *pDataParams)
{
  phStatus_t  PH_MEMLOC_REM status = 0;

  PH_LOG_HELPER_ALLOCATE_TEXT(bFunctionName, "phalMfdfEVx_Format");
  PH_LOG_HELPER_ALLOCATE_PARAMNAME(status);
  PH_LOG_HELPER_ADDSTRING(PH_LOG_LOGTYPE_INFO, bFunctionName);
  PH_LOG_HELPER_EXECUTE(PH_LOG_OPTION_CATEGORY_ENTER);

  /* Validate the parameters */
  PH_ASSERT_NULL_DATA_PARAM(pDataParams, PH_COMP_AL_MFDFEVX);

  if (PH_GET_COMPCODE(pDataParams) != PH_COMP_AL_MFDFEVX) {
    PH_LOG_HELPER_ADDSTRING(PH_LOG_LOGTYPE_INFO, bFunctionName);
    PH_LOG_HELPER_ADDPARAM_UINT16(PH_LOG_LOGTYPE_INFO, status_log, &status);
    PH_LOG_HELPER_EXECUTE(PH_LOG_OPTION_CATEGORY_LEAVE);
    return PH_ADD_COMPCODE_FIXED(PH_ERR_INVALID_DATA_PARAMS, PH_COMP_AL_MFDFEVX);
  }

  /* Perform operation on active layer */
  switch (PH_GET_COMPID(pDataParams)) {
#ifdef NXPBUILD__PHAL_MFDFEVX_SW
    case PHAL_MFDFEVX_SW_ID:
      status = phalMfdfEVx_Sw_Format((phalMfdfEVx_Sw_DataParams_t *) pDataParams);
      break;
#endif /* NXPBUILD__PHAL_MFDFEVX_SW */

    default:
      status = PH_ADD_COMPCODE_FIXED(PH_ERR_INVALID_DATA_PARAMS, PH_COMP_AL_MFDFEVX);
      break;
  }

  PH_LOG_HELPER_ADDSTRING(PH_LOG_LOGTYPE_INFO, bFunctionName);
  PH_LOG_HELPER_ADDPARAM_UINT16(PH_LOG_LOGTYPE_INFO, status_log, &status);
  PH_LOG_HELPER_EXECUTE(PH_LOG_OPTION_CATEGORY_LEAVE);

  return status;
}

phStatus_t phalMfdfEVx_SetConfiguration(void *pDataParams, uint8_t bOption, uint8_t *pData,
    uint8_t bDataLen)
{
  phStatus_t PH_MEMLOC_REM status;

  PH_LOG_HELPER_ALLOCATE_TEXT(bFunctionName, "phalMfdfEVx_SetConfiguration");
  PH_LOG_HELPER_ALLOCATE_PARAMNAME(bOption);
  PH_LOG_HELPER_ALLOCATE_PARAMNAME(pData);
  PH_LOG_HELPER_ALLOCATE_PARAMNAME(bDataLen);
  PH_LOG_HELPER_ALLOCATE_PARAMNAME(status);
  PH_LOG_HELPER_ADDSTRING(PH_LOG_LOGTYPE_INFO, bFunctionName);
  PH_LOG_HELPER_ADDPARAM_UINT8(PH_LOG_LOGTYPE_DEBUG, bOption_log, &bOption);
  PH_LOG_HELPER_ADDPARAM_UINT8(PH_LOG_LOGTYPE_DEBUG, bDataLen_log, &bDataLen);
  PH_LOG_HELPER_ADDPARAM_BUFFER(PH_LOG_LOGTYPE_DEBUG, pData_log, pData, bDataLen);
  PH_LOG_HELPER_EXECUTE(PH_LOG_OPTION_CATEGORY_ENTER);

  /* Validate the parameters */
  PH_ASSERT_NULL_DATA_PARAM(pDataParams, PH_COMP_AL_MFDFEVX);
  PH_ASSERT_NULL_PARAM(pData, PH_COMP_AL_MFDFEVX);

  /* Parameter validation */
  if (PH_GET_COMPCODE(pDataParams) != PH_COMP_AL_MFDFEVX) {
    PH_LOG_HELPER_ADDSTRING(PH_LOG_LOGTYPE_INFO, bFunctionName);
    PH_LOG_HELPER_ADDPARAM_UINT16(PH_LOG_LOGTYPE_INFO, status_log, &status);
    PH_LOG_HELPER_EXECUTE(PH_LOG_OPTION_CATEGORY_LEAVE);

    return PH_ADD_COMPCODE_FIXED(PH_ERR_INVALID_DATA_PARAMS, PH_COMP_AL_MFDFEVX);
  }

  /* Perform operation on active layer */
  switch (PH_GET_COMPID(pDataParams)) {
#ifdef NXPBUILD__PHAL_MFDFEVX_SW
    case PHAL_MFDFEVX_SW_ID:
      status = phalMfdfEVx_Sw_SetConfiguration((phalMfdfEVx_Sw_DataParams_t *) pDataParams, bOption,
              pData, bDataLen);
      break;
#endif /* NXPBUILD__PHAL_MFDFEVX_SW */

    default:
      status = PH_ADD_COMPCODE_FIXED(PH_ERR_INVALID_DATA_PARAMS, PH_COMP_AL_MFDFEVX);
      break;
  }

  PH_LOG_HELPER_ADDSTRING(PH_LOG_LOGTYPE_INFO, bFunctionName);
  PH_LOG_HELPER_ADDPARAM_UINT16(PH_LOG_LOGTYPE_INFO, status_log, &status);
  PH_LOG_HELPER_EXECUTE(PH_LOG_OPTION_CATEGORY_LEAVE);

  return status;
}
#endif /* NXPBUILD__PHAL_MFDFEVX_NDA */

phStatus_t phalMfdfEVx_GetVersion(void *pDataParams, uint8_t *pVerInfo)
{
  phStatus_t PH_MEMLOC_REM status;

  PH_LOG_HELPER_ALLOCATE_TEXT(bFunctionName, "phalMfdfEVx_GetVersion");
  PH_LOG_HELPER_ALLOCATE_PARAMNAME(pVerInfo);
  PH_LOG_HELPER_ALLOCATE_PARAMNAME(status);
  PH_LOG_HELPER_ADDSTRING(PH_LOG_LOGTYPE_INFO, bFunctionName);
  PH_LOG_HELPER_EXECUTE(PH_LOG_OPTION_CATEGORY_ENTER);

  /* Validate the parameters */
  PH_ASSERT_NULL_DATA_PARAM(pDataParams, PH_COMP_AL_MFDFEVX);
  PH_ASSERT_NULL_PARAM(pVerInfo, PH_COMP_AL_MFDFEVX);

  /* Parameter validation */
  if (PH_GET_COMPCODE(pDataParams) != PH_COMP_AL_MFDFEVX) {
    PH_LOG_HELPER_ADDSTRING(PH_LOG_LOGTYPE_INFO, bFunctionName);
    PH_LOG_HELPER_ADDPARAM_UINT16(PH_LOG_LOGTYPE_INFO, status_log, &status);
    PH_LOG_HELPER_EXECUTE(PH_LOG_OPTION_CATEGORY_LEAVE);
    return PH_ADD_COMPCODE_FIXED(PH_ERR_INVALID_DATA_PARAMS, PH_COMP_AL_MFDFEVX);
  }

  /* Perform operation on active layer */
  switch (PH_GET_COMPID(pDataParams)) {
#ifdef NXPBUILD__PHAL_MFDFEVX_SW
    case PHAL_MFDFEVX_SW_ID:
      status = phalMfdfEVx_Sw_GetVersion((phalMfdfEVx_Sw_DataParams_t *) pDataParams, pVerInfo);
      break;
#endif /* NXPBUILD__PHAL_MFDFEVX_SW */

    default:
      status = PH_ADD_COMPCODE_FIXED(PH_ERR_INVALID_DATA_PARAMS, PH_COMP_AL_MFDFEVX);
      break;
  }

  PH_LOG_HELPER_ADDSTRING(PH_LOG_LOGTYPE_INFO, bFunctionName);
  PH_LOG_HELPER_ADDPARAM_BUFFER(PH_LOG_LOGTYPE_DEBUG, pVerInfo_log, pVerInfo, 28);
  PH_LOG_HELPER_ADDPARAM_UINT16(PH_LOG_LOGTYPE_INFO, status_log, &status);
  PH_LOG_HELPER_EXECUTE(PH_LOG_OPTION_CATEGORY_LEAVE);

  return status;
}

#ifdef NXPBUILD__PHAL_MFDFEVX_NDA
phStatus_t phalMfdfEVx_GetCardUID(void *pDataParams, uint8_t bExchangeOption, uint8_t bOption,
    uint8_t *pUid)
{
  phStatus_t PH_MEMLOC_REM status;
  uint8_t PH_MEMLOC_REM bCardUidLength = 0;

  PH_LOG_HELPER_ALLOCATE_TEXT(bFunctionName, "phalMfdfEVx_GetCardUID");
  PH_LOG_HELPER_ALLOCATE_PARAMNAME(bExchangeOption);
  PH_LOG_HELPER_ALLOCATE_PARAMNAME(bOption);
  PH_LOG_HELPER_ALLOCATE_PARAMNAME(pUid);
  PH_LOG_HELPER_ALLOCATE_PARAMNAME(status);
  PH_LOG_HELPER_ALLOCATE_PARAMNAME(bCardUidLength);
  PH_LOG_HELPER_ADDSTRING(PH_LOG_LOGTYPE_INFO, bFunctionName);
  PH_LOG_HELPER_ADDPARAM_UINT8(PH_LOG_LOGTYPE_DEBUG, bExchangeOption_log, &bExchangeOption);
  PH_LOG_HELPER_ADDPARAM_UINT8(PH_LOG_LOGTYPE_DEBUG, bOption_log, &bOption);
  PH_LOG_HELPER_EXECUTE(PH_LOG_OPTION_CATEGORY_ENTER);

  /* Validate the parameters */
  PH_ASSERT_NULL_DATA_PARAM(pDataParams, PH_COMP_AL_MFDFEVX);
  PH_ASSERT_NULL_PARAM(pUid, PH_COMP_AL_MFDFEVX);

  /* Parameter validation */
  if (PH_GET_COMPCODE(pDataParams) != PH_COMP_AL_MFDFEVX) {
    PH_LOG_HELPER_ADDSTRING(PH_LOG_LOGTYPE_INFO, bFunctionName);
    PH_LOG_HELPER_ADDPARAM_UINT16(PH_LOG_LOGTYPE_INFO, status_log, &status);
    PH_LOG_HELPER_EXECUTE(PH_LOG_OPTION_CATEGORY_LEAVE);

    return PH_ADD_COMPCODE_FIXED(PH_ERR_INVALID_DATA_PARAMS, PH_COMP_AL_MFDFEVX);
  }

  /* Perform operation on active layer */
  switch (PH_GET_COMPID(pDataParams)) {
#ifdef NXPBUILD__PHAL_MFDFEVX_SW
    case PHAL_MFDFEVX_SW_ID:
      status = phalMfdfEVx_Sw_GetCardUID((phalMfdfEVx_Sw_DataParams_t *) pDataParams, bExchangeOption,
              bOption, pUid, &bCardUidLength);
      break;
#endif /* NXPBUILD__PHAL_MFDFEVX_SW */

    default:
      status = PH_ADD_COMPCODE_FIXED(PH_ERR_INVALID_DATA_PARAMS, PH_COMP_AL_MFDFEVX);
      break;
  }

  PH_LOG_HELPER_ADDSTRING(PH_LOG_LOGTYPE_INFO, bFunctionName);
  PH_LOG_HELPER_ADDPARAM_BUFFER(PH_LOG_LOGTYPE_DEBUG, pUid_log, pUid, bCardUidLength);
  PH_LOG_HELPER_ADDPARAM_UINT8(PH_LOG_LOGTYPE_DEBUG, bCardUidLength_log, &bCardUidLength);
  PH_LOG_HELPER_ADDPARAM_UINT16(PH_LOG_LOGTYPE_INFO, status_log, &status);
  PH_LOG_HELPER_EXECUTE(PH_LOG_OPTION_CATEGORY_LEAVE);

  return status;
}
#endif /* NXPBUILD__PHAL_MFDFEVX_NDA */

/* MIFARE DESFire EVX Key mamangement commands. ---------------------------------------------------------------------------------------- */
#ifdef NXPBUILD__PHAL_MFDFEVX_NDA
phStatus_t phalMfdfEVx_ChangeKey(void *pDataParams, uint16_t wOption, uint16_t wOldKeyNo,
    uint16_t wOldKeyVer, uint16_t wNewKeyNo,
    uint16_t wNewKeyVer, uint8_t bKeyNoCard, uint8_t *pDivInput, uint8_t bDivLen)
{
  /**
  * This  function will handle all the three authentication modes: 0x0A, 1A and AA.
  * and all crypto modes i.e., DES, 3DES, 3K3DES, AES
  * The previous authentication status including key number and session key is
  * present in the params  structure.
  * Successful auth. with PICC master key is required if AID = 0x00 else
  * an auth. with the application master key is required.
  */
  phStatus_t PH_MEMLOC_REM status;

  PH_LOG_HELPER_ALLOCATE_TEXT(bFunctionName, "phalMfdfEVx_ChangeKey");
  PH_LOG_HELPER_ALLOCATE_PARAMNAME(wOption);
  PH_LOG_HELPER_ALLOCATE_PARAMNAME(wOldKeyNo);
  PH_LOG_HELPER_ALLOCATE_PARAMNAME(wNewKeyNo);
  PH_LOG_HELPER_ALLOCATE_PARAMNAME(wOldKeyVer);
  PH_LOG_HELPER_ALLOCATE_PARAMNAME(wNewKeyVer);
  PH_LOG_HELPER_ALLOCATE_PARAMNAME(bKeyNoCard);
  PH_LOG_HELPER_ALLOCATE_PARAMNAME(pDivInput);
  PH_LOG_HELPER_ALLOCATE_PARAMNAME(bDivLen);
  PH_LOG_HELPER_ALLOCATE_PARAMNAME(status);
  PH_LOG_HELPER_ADDSTRING(PH_LOG_LOGTYPE_INFO, bFunctionName);
  PH_LOG_HELPER_ADDPARAM_UINT16(PH_LOG_LOGTYPE_DEBUG, wOption_log, &wOption);
  PH_LOG_HELPER_ADDPARAM_UINT16(PH_LOG_LOGTYPE_DEBUG, wOldKeyVer_log, &wOldKeyVer);
  PH_LOG_HELPER_ADDPARAM_UINT16(PH_LOG_LOGTYPE_DEBUG, wNewKeyVer_log, &wNewKeyVer);
  PH_LOG_HELPER_ADDPARAM_BUFFER(PH_LOG_LOGTYPE_DEBUG, pDivInput_log, pDivInput, bDivLen);
  PH_LOG_HELPER_ADDPARAM_UINT16(PH_LOG_LOGTYPE_DEBUG, wOldKeyNo_log, &wOldKeyNo);
  PH_LOG_HELPER_ADDPARAM_UINT16(PH_LOG_LOGTYPE_DEBUG, wNewKeyNo_log, &wNewKeyNo);
  PH_LOG_HELPER_ADDPARAM_UINT8(PH_LOG_LOGTYPE_DEBUG, bKeyNoCard_log, &bKeyNoCard);
  PH_LOG_HELPER_ADDPARAM_UINT8(PH_LOG_LOGTYPE_DEBUG, bDivLen_log, &bDivLen);
  PH_LOG_HELPER_EXECUTE(PH_LOG_OPTION_CATEGORY_ENTER);

  /* Validate the parameters */
  PH_ASSERT_NULL_DATA_PARAM(pDataParams, PH_COMP_AL_MFDFEVX);
  if (bDivLen > 0) {
    PH_ASSERT_NULL_PARAM(pDivInput, PH_COMP_AL_MFDFEVX);
  }

  /* Parameter validation */
  if (PH_GET_COMPCODE(pDataParams) != PH_COMP_AL_MFDFEVX) {
    PH_LOG_HELPER_ADDSTRING(PH_LOG_LOGTYPE_INFO, bFunctionName);
    PH_LOG_HELPER_ADDPARAM_UINT16(PH_LOG_LOGTYPE_INFO, status_log, &status);
    PH_LOG_HELPER_EXECUTE(PH_LOG_OPTION_CATEGORY_LEAVE);
    return PH_ADD_COMPCODE_FIXED(PH_ERR_INVALID_DATA_PARAMS, PH_COMP_AL_MFDFEVX);
  }

  /* Perform operation on active layer */
  switch (PH_GET_COMPID(pDataParams)) {
#ifdef NXPBUILD__PHAL_MFDFEVX_SW
    case PHAL_MFDFEVX_SW_ID:
      status = phalMfdfEVx_Sw_ChangeKey((phalMfdfEVx_Sw_DataParams_t *) pDataParams, wOption, wOldKeyNo,
              wOldKeyVer,
              wNewKeyNo, wNewKeyVer, bKeyNoCard, pDivInput, bDivLen);
      break;
#endif /* NXPBUILD__PHAL_MFDFEVX_SAM_NONX */

    default:
      status = PH_ADD_COMPCODE_FIXED(PH_ERR_INVALID_DATA_PARAMS, PH_COMP_AL_MFDFEVX);
      break;
  }

  PH_LOG_HELPER_ADDSTRING(PH_LOG_LOGTYPE_INFO, bFunctionName);
  PH_LOG_HELPER_ADDPARAM_UINT16(PH_LOG_LOGTYPE_INFO, status_log, &status);
  PH_LOG_HELPER_EXECUTE(PH_LOG_OPTION_CATEGORY_LEAVE);
  return status;
}

phStatus_t phalMfdfEVx_ChangeKeyEv2(void *pDataParams, uint16_t wOption, uint16_t wOldKeyNo,
    uint16_t wOldKeyVer, uint16_t wNewKeyNo,
    uint16_t wNewKeyVer, uint8_t bKeySetNo, uint8_t bKeyNoCard, uint8_t *pDivInput, uint8_t bDivLen)
{
  phStatus_t PH_MEMLOC_REM status;

  PH_LOG_HELPER_ALLOCATE_TEXT(bFunctionName, "phalMfdfEVx_ChangeKeyEv2");
  PH_LOG_HELPER_ALLOCATE_PARAMNAME(wOption);
  PH_LOG_HELPER_ALLOCATE_PARAMNAME(wOldKeyNo);
  PH_LOG_HELPER_ALLOCATE_PARAMNAME(wOldKeyVer);
  PH_LOG_HELPER_ALLOCATE_PARAMNAME(wNewKeyNo);
  PH_LOG_HELPER_ALLOCATE_PARAMNAME(wNewKeyVer);
  PH_LOG_HELPER_ALLOCATE_PARAMNAME(bKeySetNo);
  PH_LOG_HELPER_ALLOCATE_PARAMNAME(bKeyNoCard);
  PH_LOG_HELPER_ALLOCATE_PARAMNAME(pDivInput);
  PH_LOG_HELPER_ALLOCATE_PARAMNAME(status);
  PH_LOG_HELPER_ADDSTRING(PH_LOG_LOGTYPE_INFO, bFunctionName);
  PH_LOG_HELPER_ADDPARAM_UINT16(PH_LOG_LOGTYPE_DEBUG, wOption_log, &wOption);
  PH_LOG_HELPER_ADDPARAM_UINT16(PH_LOG_LOGTYPE_DEBUG, wOldKeyNo_log, &wOldKeyNo);
  PH_LOG_HELPER_ADDPARAM_UINT16(PH_LOG_LOGTYPE_DEBUG, wOldKeyVer_log, &wOldKeyVer);
  PH_LOG_HELPER_ADDPARAM_UINT16(PH_LOG_LOGTYPE_DEBUG, wNewKeyNo_log, &wNewKeyNo);
  PH_LOG_HELPER_ADDPARAM_UINT16(PH_LOG_LOGTYPE_DEBUG, wNewKeyVer_log, &wNewKeyVer);
  PH_LOG_HELPER_ADDPARAM_UINT8(PH_LOG_LOGTYPE_DEBUG, bKeySetNo_log, &bKeySetNo);
  PH_LOG_HELPER_ADDPARAM_UINT8(PH_LOG_LOGTYPE_DEBUG, bKeyNoCard_log, &bKeyNoCard);
  PH_LOG_HELPER_ADDPARAM_BUFFER(PH_LOG_LOGTYPE_DEBUG, pDivInput_log, pDivInput, bDivLen);
  PH_LOG_HELPER_EXECUTE(PH_LOG_OPTION_CATEGORY_ENTER);

  /* Validate the parameters */
  PH_ASSERT_NULL_DATA_PARAM(pDataParams, PH_COMP_AL_MFDFEVX);
  if (0U != (bDivLen)) {
    PH_ASSERT_NULL_PARAM(pDivInput, PH_COMP_AL_MFDFEVX);
  }

  /* Parameter validation */
  if (PH_GET_COMPCODE(pDataParams) != PH_COMP_AL_MFDFEVX) {
    PH_LOG_HELPER_ADDSTRING(PH_LOG_LOGTYPE_INFO, bFunctionName);
    PH_LOG_HELPER_ADDPARAM_UINT16(PH_LOG_LOGTYPE_INFO, status_log, &status);
    PH_LOG_HELPER_EXECUTE(PH_LOG_OPTION_CATEGORY_LEAVE);

    return PH_ADD_COMPCODE_FIXED(PH_ERR_INVALID_DATA_PARAMS, PH_COMP_AL_MFDFEVX);
  }

  /* Perform operation on active layer */
  switch (PH_GET_COMPID(pDataParams)) {
#ifdef NXPBUILD__PHAL_MFDFEVX_SW
    case PHAL_MFDFEVX_SW_ID:
      status = phalMfdfEVx_Sw_ChangeKeyEv2((phalMfdfEVx_Sw_DataParams_t *) pDataParams, wOption,
              wOldKeyNo, wOldKeyVer,
              wNewKeyNo, wNewKeyVer, bKeySetNo, bKeyNoCard, pDivInput, bDivLen);
      break;
#endif /* NXPBUILD__PHAL_MFDFEVX_SW */

    default:
      status = PH_ADD_COMPCODE_FIXED(PH_ERR_INVALID_DATA_PARAMS, PH_COMP_AL_MFDFEVX);
      break;
  }

  PH_LOG_HELPER_ADDSTRING(PH_LOG_LOGTYPE_INFO, bFunctionName);
  PH_LOG_HELPER_ADDPARAM_UINT16(PH_LOG_LOGTYPE_INFO, status_log, &status);
  PH_LOG_HELPER_EXECUTE(PH_LOG_OPTION_CATEGORY_LEAVE);

  return status;
}

phStatus_t phalMfdfEVx_InitializeKeySet(void *pDataParams, uint8_t bKeySetNo, uint8_t bKeyType)
{
  phStatus_t PH_MEMLOC_REM status;

  PH_LOG_HELPER_ALLOCATE_TEXT(bFunctionName, "phalMfdfEVx_InitializeKeySet");
  PH_LOG_HELPER_ALLOCATE_PARAMNAME(bKeySetNo);
  PH_LOG_HELPER_ALLOCATE_PARAMNAME(bKeyType);
  PH_LOG_HELPER_ALLOCATE_PARAMNAME(status);
  PH_LOG_HELPER_ADDSTRING(PH_LOG_LOGTYPE_INFO, bFunctionName);
  PH_LOG_HELPER_ADDPARAM_UINT8(PH_LOG_LOGTYPE_DEBUG, bKeySetNo_log, &bKeySetNo);
  PH_LOG_HELPER_ADDPARAM_UINT8(PH_LOG_LOGTYPE_DEBUG, bKeyType_log, &bKeyType);
  PH_LOG_HELPER_EXECUTE(PH_LOG_OPTION_CATEGORY_ENTER);

  /* Validate the parameters */
  PH_ASSERT_NULL_DATA_PARAM(pDataParams, PH_COMP_AL_MFDFEVX);

  /* Parameter validation */
  if (PH_GET_COMPCODE(pDataParams) != PH_COMP_AL_MFDFEVX) {
    PH_LOG_HELPER_ADDSTRING(PH_LOG_LOGTYPE_INFO, bFunctionName);
    PH_LOG_HELPER_ADDPARAM_UINT16(PH_LOG_LOGTYPE_INFO, status_log, &status);
    PH_LOG_HELPER_EXECUTE(PH_LOG_OPTION_CATEGORY_LEAVE);

    return PH_ADD_COMPCODE_FIXED(PH_ERR_INVALID_DATA_PARAMS, PH_COMP_AL_MFDFEVX);
  }

  /* Perform operation on active layer */
  switch (PH_GET_COMPID(pDataParams)) {
#ifdef NXPBUILD__PHAL_MFDFEVX_SW
    case PHAL_MFDFEVX_SW_ID:
      status = phalMfdfEVx_Sw_InitializeKeySet((phalMfdfEVx_Sw_DataParams_t *) pDataParams, bKeySetNo,
              bKeyType);
      break;
#endif /* NXPBUILD__PHAL_MFDFEVX_SW */

    default:
      status = PH_ADD_COMPCODE_FIXED(PH_ERR_INVALID_DATA_PARAMS, PH_COMP_AL_MFDFEVX);
      break;
  }

  PH_LOG_HELPER_ADDSTRING(PH_LOG_LOGTYPE_INFO, bFunctionName);
  PH_LOG_HELPER_ADDPARAM_UINT16(PH_LOG_LOGTYPE_INFO, status_log, &status);
  PH_LOG_HELPER_EXECUTE(PH_LOG_OPTION_CATEGORY_LEAVE);

  return status;
}

phStatus_t phalMfdfEVx_FinalizeKeySet(void *pDataParams, uint8_t bKeySetNo,
    uint8_t bKeySetVersion)
{
  phStatus_t PH_MEMLOC_REM status;

  PH_LOG_HELPER_ALLOCATE_TEXT(bFunctionName, "phalMfdfEVx_FinalizeKeySet");
  PH_LOG_HELPER_ALLOCATE_PARAMNAME(bKeySetNo);
  PH_LOG_HELPER_ALLOCATE_PARAMNAME(bKeySetVersion);
  PH_LOG_HELPER_ALLOCATE_PARAMNAME(status);
  PH_LOG_HELPER_ADDSTRING(PH_LOG_LOGTYPE_INFO, bFunctionName);
  PH_LOG_HELPER_ADDPARAM_UINT8(PH_LOG_LOGTYPE_DEBUG, bKeySetNo_log, &bKeySetNo);
  PH_LOG_HELPER_ADDPARAM_UINT8(PH_LOG_LOGTYPE_DEBUG, bKeySetVersion_log, &bKeySetVersion);
  PH_LOG_HELPER_EXECUTE(PH_LOG_OPTION_CATEGORY_ENTER);

  /* Validate the parameters */
  PH_ASSERT_NULL_DATA_PARAM(pDataParams, PH_COMP_AL_MFDFEVX);

  /* Parameter validation */
  if (PH_GET_COMPCODE(pDataParams) != PH_COMP_AL_MFDFEVX) {
    PH_LOG_HELPER_ADDSTRING(PH_LOG_LOGTYPE_INFO, bFunctionName);
    PH_LOG_HELPER_ADDPARAM_UINT16(PH_LOG_LOGTYPE_INFO, status_log, &status);
    PH_LOG_HELPER_EXECUTE(PH_LOG_OPTION_CATEGORY_LEAVE);

    return PH_ADD_COMPCODE_FIXED(PH_ERR_INVALID_DATA_PARAMS, PH_COMP_AL_MFDFEVX);
  }

  /* Perform operation on active layer */
  switch (PH_GET_COMPID(pDataParams)) {
#ifdef NXPBUILD__PHAL_MFDFEVX_SW
    case PHAL_MFDFEVX_SW_ID:
      status = phalMfdfEVx_Sw_FinalizeKeySet((phalMfdfEVx_Sw_DataParams_t *) pDataParams, bKeySetNo,
              bKeySetVersion);
      break;
#endif /* NXPBUILD__PHAL_MFDFEVX_SW */

    default:
      status = PH_ADD_COMPCODE_FIXED(PH_ERR_INVALID_DATA_PARAMS, PH_COMP_AL_MFDFEVX);
      break;
  }

  PH_LOG_HELPER_ADDSTRING(PH_LOG_LOGTYPE_INFO, bFunctionName);
  PH_LOG_HELPER_ADDPARAM_UINT16(PH_LOG_LOGTYPE_INFO, status_log, &status);
  PH_LOG_HELPER_EXECUTE(PH_LOG_OPTION_CATEGORY_LEAVE);

  return status;
}

phStatus_t  phalMfdfEVx_RollKeySet(void *pDataParams, uint8_t bKeySetNo)
{
  phStatus_t PH_MEMLOC_REM status;

  PH_LOG_HELPER_ALLOCATE_TEXT(bFunctionName, "phalMfdfEVx_RollKeySet");
  PH_LOG_HELPER_ALLOCATE_PARAMNAME(bKeySetNo);
  PH_LOG_HELPER_ALLOCATE_PARAMNAME(status);
  PH_LOG_HELPER_ADDSTRING(PH_LOG_LOGTYPE_INFO, bFunctionName);
  PH_LOG_HELPER_ADDPARAM_UINT8(PH_LOG_LOGTYPE_DEBUG, bKeySetNo_log, &bKeySetNo);
  PH_LOG_HELPER_EXECUTE(PH_LOG_OPTION_CATEGORY_ENTER);

  /* Validate the parameters */
  PH_ASSERT_NULL_DATA_PARAM(pDataParams, PH_COMP_AL_MFDFEVX);

  /* Parameter validation */
  if (PH_GET_COMPCODE(pDataParams) != PH_COMP_AL_MFDFEVX) {
    PH_LOG_HELPER_ADDSTRING(PH_LOG_LOGTYPE_INFO, bFunctionName);
    PH_LOG_HELPER_ADDPARAM_UINT16(PH_LOG_LOGTYPE_INFO, status_log, &status);
    PH_LOG_HELPER_EXECUTE(PH_LOG_OPTION_CATEGORY_LEAVE);

    return PH_ADD_COMPCODE_FIXED(PH_ERR_INVALID_DATA_PARAMS, PH_COMP_AL_MFDFEVX);
  }

  /* Perform operation on active layer */
  switch (PH_GET_COMPID(pDataParams)) {
#ifdef NXPBUILD__PHAL_MFDFEVX_SW
    case PHAL_MFDFEVX_SW_ID:
      status = phalMfdfEVx_Sw_RollKeySet((phalMfdfEVx_Sw_DataParams_t *) pDataParams, bKeySetNo);
      break;
#endif /* NXPBUILD__PHAL_MFDFEVX_SW */

    default:
      status = PH_ADD_COMPCODE_FIXED(PH_ERR_INVALID_DATA_PARAMS, PH_COMP_AL_MFDFEVX);
      break;
  }

  PH_LOG_HELPER_ADDSTRING(PH_LOG_LOGTYPE_INFO, bFunctionName);
  PH_LOG_HELPER_ADDPARAM_UINT16(PH_LOG_LOGTYPE_INFO, status_log, &status);
  PH_LOG_HELPER_EXECUTE(PH_LOG_OPTION_CATEGORY_LEAVE);

  return status;
}
#endif /* NXPBUILD__PHAL_MFDFEVX_NDA */

phStatus_t phalMfdfEVx_GetKeySettings(void *pDataParams, uint8_t *pKeySettings, uint8_t *bRespLen)
{
  phStatus_t PH_MEMLOC_REM status;

  PH_LOG_HELPER_ALLOCATE_TEXT(bFunctionName, "phalMfdfEVx_GetKeySettings");
  PH_LOG_HELPER_ALLOCATE_PARAMNAME(pKeySettings);
  PH_LOG_HELPER_ALLOCATE_PARAMNAME(bRespLen);
  PH_LOG_HELPER_ALLOCATE_PARAMNAME(status);
  PH_LOG_HELPER_ADDSTRING(PH_LOG_LOGTYPE_INFO, bFunctionName);
  PH_LOG_HELPER_EXECUTE(PH_LOG_OPTION_CATEGORY_ENTER);

  /* Validate the parameters */
  PH_ASSERT_NULL_DATA_PARAM(pDataParams, PH_COMP_AL_MFDFEVX);
  PH_ASSERT_NULL_PARAM(pKeySettings, PH_COMP_AL_MFDFEVX);

  /* Parameter validation */
  if (PH_GET_COMPCODE(pDataParams) != PH_COMP_AL_MFDFEVX) {
    PH_LOG_HELPER_ADDSTRING(PH_LOG_LOGTYPE_INFO, bFunctionName);
    PH_LOG_HELPER_ADDPARAM_UINT16(PH_LOG_LOGTYPE_INFO, status_log, &status);
    PH_LOG_HELPER_EXECUTE(PH_LOG_OPTION_CATEGORY_LEAVE);
    return PH_ADD_COMPCODE_FIXED(PH_ERR_INVALID_DATA_PARAMS, PH_COMP_AL_MFDFEVX);
  }

  /* Perform operation on active layer */
  switch (PH_GET_COMPID(pDataParams)) {
#ifdef NXPBUILD__PHAL_MFDFEVX_SW
    case PHAL_MFDFEVX_SW_ID:
      status = phalMfdfEVx_Sw_GetKeySettings((phalMfdfEVx_Sw_DataParams_t *) pDataParams, pKeySettings,
              bRespLen);
      break;
#endif /* NXPBUILD__PHAL_MFDFEVX_SW */

    default:
      status = PH_ADD_COMPCODE_FIXED(PH_ERR_INVALID_DATA_PARAMS, PH_COMP_AL_MFDFEVX);
      break;
  }

  PH_LOG_HELPER_ADDSTRING(PH_LOG_LOGTYPE_INFO, bFunctionName);
  PH_LOG_HELPER_ADDPARAM_BUFFER(PH_LOG_LOGTYPE_DEBUG, pKeySettings_log, pKeySettings, (*bRespLen));
  PH_LOG_HELPER_ADDPARAM_UINT8(PH_LOG_LOGTYPE_INFO, bRespLen_log, bRespLen);
  PH_LOG_HELPER_ADDPARAM_UINT16(PH_LOG_LOGTYPE_INFO, status_log, &status);
  PH_LOG_HELPER_EXECUTE(PH_LOG_OPTION_CATEGORY_LEAVE);

  return status;
}

#ifdef NXPBUILD__PHAL_MFDFEVX_NDA
phStatus_t phalMfdfEVx_ChangeKeySettings(void *pDataParams, uint8_t bKeySettings)
{
  /**
  * This  function will handle all the three authentication modes: 0x0A, 1A and AA.
  * and all crypto modes i.e., DES, 3DES, 3K3DES, AES
  * The previous authentication status including key number and session key is
  * present in the params  structure.
  * Successful auth. with PICC master key is required if AID = 0x00 else
  * an auth. with the application master key is required.
  */
  phStatus_t PH_MEMLOC_REM status;

  PH_LOG_HELPER_ALLOCATE_TEXT(bFunctionName, "phalMfdfEVx_ChangeKeySettings");
  PH_LOG_HELPER_ALLOCATE_PARAMNAME(bKeySettings);
  PH_LOG_HELPER_ALLOCATE_PARAMNAME(status);

  PH_LOG_HELPER_ADDSTRING(PH_LOG_LOGTYPE_INFO, bFunctionName);
  PH_LOG_HELPER_ADDPARAM_UINT8(PH_LOG_LOGTYPE_DEBUG, bKeySettings_log, &bKeySettings);
  PH_LOG_HELPER_EXECUTE(PH_LOG_OPTION_CATEGORY_ENTER);

  /* Validate the parameters */
  PH_ASSERT_NULL_DATA_PARAM(pDataParams, PH_COMP_AL_MFDFEVX);

  /* Parameter validation */
  if (PH_GET_COMPCODE(pDataParams) != PH_COMP_AL_MFDFEVX) {
    PH_LOG_HELPER_ADDSTRING(PH_LOG_LOGTYPE_INFO, bFunctionName);
    PH_LOG_HELPER_ADDPARAM_UINT16(PH_LOG_LOGTYPE_INFO, status_log, &status);
    PH_LOG_HELPER_EXECUTE(PH_LOG_OPTION_CATEGORY_LEAVE);
    return PH_ADD_COMPCODE_FIXED(PH_ERR_INVALID_DATA_PARAMS, PH_COMP_AL_MFDFEVX);
  }

  /* Perform operation on active layer */
  switch (PH_GET_COMPID(pDataParams)) {
#ifdef NXPBUILD__PHAL_MFDFEVX_SW
    case PHAL_MFDFEVX_SW_ID:
      status = phalMfdfEVx_Sw_ChangeKeySettings((phalMfdfEVx_Sw_DataParams_t *) pDataParams,
              bKeySettings);
      break;
#endif /* NXPBUILD__PHAL_MFDFEVX_SW */

    default:
      status = PH_ADD_COMPCODE_FIXED(PH_ERR_INVALID_DATA_PARAMS, PH_COMP_AL_MFDFEVX);
      break;
  }

  PH_LOG_HELPER_ADDSTRING(PH_LOG_LOGTYPE_INFO, bFunctionName);
  PH_LOG_HELPER_ADDPARAM_UINT16(PH_LOG_LOGTYPE_INFO, status_log, &status);
  PH_LOG_HELPER_EXECUTE(PH_LOG_OPTION_CATEGORY_LEAVE);

  return status;
}

phStatus_t phalMfdfEVx_GetKeyVersion(void *pDataParams, uint8_t bKeyNo, uint8_t bKeySetNo,
    uint8_t *pKeyVersion, uint8_t *bRxLen)
{
  /**
  * This command can be issued without valid authentication
  */
  phStatus_t PH_MEMLOC_REM status;

  PH_LOG_HELPER_ALLOCATE_TEXT(bFunctionName, "phalMfdfEVx_GetKeyVersion");
  PH_LOG_HELPER_ALLOCATE_PARAMNAME(bKeyNo);
  PH_LOG_HELPER_ALLOCATE_PARAMNAME(bKeySetNo);
  PH_LOG_HELPER_ALLOCATE_PARAMNAME(pKeyVersion);
  PH_LOG_HELPER_ALLOCATE_PARAMNAME(bRxLen);
  PH_LOG_HELPER_ALLOCATE_PARAMNAME(status);
  PH_LOG_HELPER_ADDSTRING(PH_LOG_LOGTYPE_INFO, bFunctionName);
  PH_LOG_HELPER_ADDPARAM_UINT8(PH_LOG_LOGTYPE_DEBUG, bKeyNo_log, &bKeyNo);
  PH_LOG_HELPER_ADDPARAM_UINT8(PH_LOG_LOGTYPE_DEBUG, bKeySetNo_log, &bKeySetNo);
  PH_LOG_HELPER_EXECUTE(PH_LOG_OPTION_CATEGORY_ENTER);

  /* Validate the parameters */
  PH_ASSERT_NULL_DATA_PARAM(pDataParams, PH_COMP_AL_MFDFEVX);
  PH_ASSERT_NULL_PARAM(pKeyVersion, PH_COMP_AL_MFDFEVX);

  /* Parameter validation */
  if (PH_GET_COMPCODE(pDataParams) != PH_COMP_AL_MFDFEVX) {
    PH_LOG_HELPER_ADDSTRING(PH_LOG_LOGTYPE_INFO, bFunctionName);
    PH_LOG_HELPER_ADDPARAM_UINT16(PH_LOG_LOGTYPE_INFO, status_log, &status);
    PH_LOG_HELPER_EXECUTE(PH_LOG_OPTION_CATEGORY_LEAVE);

    return PH_ADD_COMPCODE_FIXED(PH_ERR_INVALID_DATA_PARAMS, PH_COMP_AL_MFDFEVX);
  }

  /* Perform operation on active layer */
  switch (PH_GET_COMPID(pDataParams)) {
#ifdef NXPBUILD__PHAL_MFDFEVX_SW
    case PHAL_MFDFEVX_SW_ID:
      status = phalMfdfEVx_Sw_GetKeyVersion((phalMfdfEVx_Sw_DataParams_t *) pDataParams, bKeyNo,
              bKeySetNo,
              pKeyVersion, bRxLen);
      break;
#endif /* NXPBUILD__PHAL_MFDFEVX_SW */

    default:
      status = PH_ADD_COMPCODE_FIXED(PH_ERR_INVALID_DATA_PARAMS, PH_COMP_AL_MFDFEVX);
      break;
  }

  PH_LOG_HELPER_ADDSTRING(PH_LOG_LOGTYPE_INFO, bFunctionName);
  PH_LOG_HELPER_ADDPARAM_BUFFER(PH_LOG_LOGTYPE_DEBUG, pKeyVersion_log, pKeyVersion, *bRxLen);
  PH_LOG_HELPER_ADDPARAM_UINT8(PH_LOG_LOGTYPE_DEBUG, bRxLen_log, bRxLen);
  PH_LOG_HELPER_ADDPARAM_UINT16(PH_LOG_LOGTYPE_INFO, status_log, &status);
  PH_LOG_HELPER_EXECUTE(PH_LOG_OPTION_CATEGORY_LEAVE);

  return status;
}
#endif /* NXPBUILD__PHAL_MFDFEVX_NDA */

/* MIFARE DESFire EVX Application mamangement commands. -------------------------------------------------------------------------------- */
phStatus_t phalMfdfEVx_CreateApplication(void *pDataParams, uint8_t bOption, uint8_t *pAid,
    uint8_t bKeySettings1, uint8_t bKeySettings2,
    uint8_t bKeySettings3, uint8_t *pKeySetValues, uint8_t *pISOFileId, uint8_t *pISODFName,
    uint8_t bISODFNameLen)
{
  phStatus_t PH_MEMLOC_REM status;

  PH_LOG_HELPER_ALLOCATE_TEXT(bFunctionName, "phalMfdfEVx_CreateApplication");
  PH_LOG_HELPER_ALLOCATE_PARAMNAME(bOption);
  PH_LOG_HELPER_ALLOCATE_PARAMNAME(pAid);
  PH_LOG_HELPER_ALLOCATE_PARAMNAME(bKeySettings1);
  PH_LOG_HELPER_ALLOCATE_PARAMNAME(bKeySettings2);
  PH_LOG_HELPER_ALLOCATE_PARAMNAME(bKeySettings3);
  PH_LOG_HELPER_ALLOCATE_PARAMNAME(pKeySetValues);
  PH_LOG_HELPER_ALLOCATE_PARAMNAME(pISOFileId);
  PH_LOG_HELPER_ALLOCATE_PARAMNAME(pISODFName);
  PH_LOG_HELPER_ALLOCATE_PARAMNAME(bISODFNameLen);
  PH_LOG_HELPER_ALLOCATE_PARAMNAME(status);
  PH_LOG_HELPER_ADDSTRING(PH_LOG_LOGTYPE_INFO, bFunctionName);
  PH_LOG_HELPER_ADDPARAM_UINT8(PH_LOG_LOGTYPE_DEBUG, bOption_log, &bOption);
  PH_LOG_HELPER_ADDPARAM_UINT8(PH_LOG_LOGTYPE_DEBUG, bKeySettings1_log, &bKeySettings1);
  PH_LOG_HELPER_ADDPARAM_UINT8(PH_LOG_LOGTYPE_DEBUG, bKeySettings2_log, &bKeySettings2);
  PH_LOG_HELPER_ADDPARAM_UINT8(PH_LOG_LOGTYPE_DEBUG, bKeySettings3_log, &bKeySettings3);
  PH_LOG_HELPER_ADDPARAM_UINT8(PH_LOG_LOGTYPE_DEBUG, bISODFNameLen_log, &bISODFNameLen);
  PH_LOG_HELPER_ADDPARAM_BUFFER(PH_LOG_LOGTYPE_DEBUG, pAid_log, pAid, 3);
  if (bOption & 0x01) {
    PH_LOG_HELPER_ADDPARAM_BUFFER(PH_LOG_LOGTYPE_DEBUG, pISOFileId_log, pISOFileId, 2);
  }
  if ((bKeySettings2 & PHAL_MFDFEVX_KEYSETT3_PRESENT) &&
      (bKeySettings3 & PHAL_MFDFEVX_KEYSETVALUES_PRESENT)) {
    PH_LOG_HELPER_ADDPARAM_BUFFER(PH_LOG_LOGTYPE_DEBUG, pKeySetValues_log, pKeySetValues, 4);
  }
  PH_LOG_HELPER_ADDPARAM_BUFFER(PH_LOG_LOGTYPE_DEBUG, pISODFName_log, pISODFName, bISODFNameLen);
  PH_LOG_HELPER_EXECUTE(PH_LOG_OPTION_CATEGORY_ENTER);

  /* Validate the parameters */
  PH_ASSERT_NULL_DATA_PARAM(pDataParams, PH_COMP_AL_MFDFEVX);
  if (bOption & 0x01) {
    PH_ASSERT_NULL_PARAM(pISOFileId, PH_COMP_AL_MFDFEVX);
  }
  if (bISODFNameLen > 0) {
    PH_ASSERT_NULL_PARAM(pISODFName, PH_COMP_AL_MFDFEVX);
  }
  PH_ASSERT_NULL_PARAM(pAid, PH_COMP_AL_MFDFEVX);

  /* Parameter validation */
  if (PH_GET_COMPCODE(pDataParams) != PH_COMP_AL_MFDFEVX) {
    PH_LOG_HELPER_ADDSTRING(PH_LOG_LOGTYPE_INFO, bFunctionName);
    PH_LOG_HELPER_ADDPARAM_UINT16(PH_LOG_LOGTYPE_INFO, status_log, &status);
    PH_LOG_HELPER_EXECUTE(PH_LOG_OPTION_CATEGORY_LEAVE);
    return PH_ADD_COMPCODE_FIXED(PH_ERR_INVALID_DATA_PARAMS, PH_COMP_AL_MFDFEVX);
  }

  /* Perform operation on active layer */
  switch (PH_GET_COMPID(pDataParams)) {
#ifdef NXPBUILD__PHAL_MFDFEVX_SW
    case PHAL_MFDFEVX_SW_ID:
      status = phalMfdfEVx_Sw_CreateApplication((phalMfdfEVx_Sw_DataParams_t *) pDataParams, bOption,
              pAid, bKeySettings1,
              bKeySettings2, bKeySettings3, pKeySetValues, pISOFileId, pISODFName, bISODFNameLen);
      break;
#endif /* NXPBUILD__PHAL_MFDFEVX_SW */

    default:
      status = PH_ADD_COMPCODE_FIXED(PH_ERR_INVALID_DATA_PARAMS, PH_COMP_AL_MFDFEVX);
      break;
  }

  PH_LOG_HELPER_ADDSTRING(PH_LOG_LOGTYPE_INFO, bFunctionName);
  PH_LOG_HELPER_ADDPARAM_UINT16(PH_LOG_LOGTYPE_INFO, status_log, &status);
  PH_LOG_HELPER_EXECUTE(PH_LOG_OPTION_CATEGORY_LEAVE);

  return status;
}

phStatus_t phalMfdfEVx_DeleteApplication(void *pDataParams, uint8_t *pAid, uint8_t *pDAMMAC,
    uint8_t bDAMMAC_Len)
{
  phStatus_t PH_MEMLOC_REM status;

  PH_LOG_HELPER_ALLOCATE_TEXT(bFunctionName, "phalMfdfEVx_DeleteApplication");
  PH_LOG_HELPER_ALLOCATE_PARAMNAME(pAid);
  PH_LOG_HELPER_ALLOCATE_PARAMNAME(pDAMMAC);
  PH_LOG_HELPER_ALLOCATE_PARAMNAME(status);
  PH_LOG_HELPER_ADDSTRING(PH_LOG_LOGTYPE_INFO, bFunctionName);
  PH_LOG_HELPER_ADDPARAM_BUFFER(PH_LOG_LOGTYPE_DEBUG, pAid_log, pAid, 3);
  PH_LOG_HELPER_ADDPARAM_BUFFER(PH_LOG_LOGTYPE_DEBUG, pDAMMAC_log, pDAMMAC, bDAMMAC_Len);
  PH_LOG_HELPER_EXECUTE(PH_LOG_OPTION_CATEGORY_ENTER);

  /* Validate the parameters */
  PH_ASSERT_NULL_DATA_PARAM(pDataParams, PH_COMP_AL_MFDFEVX);
  PH_ASSERT_NULL_PARAM(pAid, PH_COMP_AL_MFDFEVX);
  if (bDAMMAC_Len) {
    PH_ASSERT_NULL_PARAM(pDAMMAC, PH_COMP_AL_MFDFEVX);
  }

  /* Parameter validation */
  if (PH_GET_COMPCODE(pDataParams) != PH_COMP_AL_MFDFEVX) {
    PH_LOG_HELPER_ADDSTRING(PH_LOG_LOGTYPE_INFO, bFunctionName);
    PH_LOG_HELPER_ADDPARAM_UINT16(PH_LOG_LOGTYPE_INFO, status_log, &status);
    PH_LOG_HELPER_EXECUTE(PH_LOG_OPTION_CATEGORY_LEAVE);

    return PH_ADD_COMPCODE_FIXED(PH_ERR_INVALID_DATA_PARAMS, PH_COMP_AL_MFDFEVX);
  }

  /* Perform operation on active layer */
  switch (PH_GET_COMPID(pDataParams)) {

#ifdef NXPBUILD__PHAL_MFDFEVX_SW
    case PHAL_MFDFEVX_SW_ID:
      status = phalMfdfEVx_Sw_DeleteApplication((phalMfdfEVx_Sw_DataParams_t *) pDataParams, pAid,
              pDAMMAC, bDAMMAC_Len);
      break;
#endif /* NXPBUILD__PHAL_MFDFEVX_SW */

    default:
      status = PH_ADD_COMPCODE_FIXED(PH_ERR_INVALID_DATA_PARAMS, PH_COMP_AL_MFDFEVX);
      break;
  }

  PH_LOG_HELPER_ADDSTRING(PH_LOG_LOGTYPE_INFO, bFunctionName);
  PH_LOG_HELPER_ADDPARAM_UINT16(PH_LOG_LOGTYPE_INFO, status_log, &status);
  PH_LOG_HELPER_EXECUTE(PH_LOG_OPTION_CATEGORY_LEAVE);

  return status;
}

phStatus_t phalMfdfEVx_CreateDelegatedApplication(void *pDataParams, uint8_t bOption,
    uint8_t *pAid, uint8_t *pDamParams, uint8_t bKeySettings1,
    uint8_t bKeySettings2, uint8_t bKeySettings3, uint8_t *bKeySetValues, uint8_t *pISOFileId,
    uint8_t *pISODFName, uint8_t bISODFNameLen,
    uint8_t *pEncK, uint8_t *pDAMMAC)
{
  phStatus_t PH_MEMLOC_REM status;

  PH_LOG_HELPER_ALLOCATE_TEXT(bFunctionName, "phalMfdfEVx_CreateDelegatedApplication");
  PH_LOG_HELPER_ALLOCATE_PARAMNAME(bOption);
  PH_LOG_HELPER_ALLOCATE_PARAMNAME(pAid);
  PH_LOG_HELPER_ALLOCATE_PARAMNAME(pDamParams);
  PH_LOG_HELPER_ALLOCATE_PARAMNAME(bKeySettings1);
  PH_LOG_HELPER_ALLOCATE_PARAMNAME(bKeySettings2);
  PH_LOG_HELPER_ALLOCATE_PARAMNAME(bKeySettings3);
  PH_LOG_HELPER_ALLOCATE_PARAMNAME(bKeySetValues);
  PH_LOG_HELPER_ALLOCATE_PARAMNAME(pISOFileId);
  PH_LOG_HELPER_ALLOCATE_PARAMNAME(pISODFName);
  PH_LOG_HELPER_ALLOCATE_PARAMNAME(bISODFNameLen);
  PH_LOG_HELPER_ALLOCATE_PARAMNAME(pEncK);
  PH_LOG_HELPER_ALLOCATE_PARAMNAME(pDAMMAC);
  PH_LOG_HELPER_ALLOCATE_PARAMNAME(status);
  PH_LOG_HELPER_ADDSTRING(PH_LOG_LOGTYPE_INFO, bFunctionName);
  PH_LOG_HELPER_ADDPARAM_UINT8(PH_LOG_LOGTYPE_DEBUG, bKeySettings1_log, &bKeySettings1);
  PH_LOG_HELPER_ADDPARAM_UINT8(PH_LOG_LOGTYPE_DEBUG, bKeySettings2_log, &bKeySettings2);
  PH_LOG_HELPER_ADDPARAM_UINT8(PH_LOG_LOGTYPE_DEBUG, bKeySettings3_log, &bKeySettings3);
  PH_LOG_HELPER_ADDPARAM_UINT8(PH_LOG_LOGTYPE_DEBUG, bISODFNameLen_log, &bISODFNameLen);
  PH_LOG_HELPER_ADDPARAM_UINT8(PH_LOG_LOGTYPE_DEBUG, bOption_log, &bOption);
  PH_LOG_HELPER_ADDPARAM_BUFFER(PH_LOG_LOGTYPE_DEBUG, pAid_log, pAid, 3);
  PH_LOG_HELPER_ADDPARAM_BUFFER(PH_LOG_LOGTYPE_DEBUG, pDamParams_log, pDamParams, 4);
  PH_LOG_HELPER_ADDPARAM_BUFFER(PH_LOG_LOGTYPE_DEBUG, bKeySetValues_log, bKeySetValues, 4);
  PH_LOG_HELPER_ADDPARAM_BUFFER(PH_LOG_LOGTYPE_DEBUG, pEncK_log, pEncK, 32);
  PH_LOG_HELPER_ADDPARAM_BUFFER(PH_LOG_LOGTYPE_DEBUG, pDAMMAC_log, pDAMMAC, 8);
  if (bOption & 0x01) {
    PH_LOG_HELPER_ADDPARAM_BUFFER(PH_LOG_LOGTYPE_DEBUG, pISOFileId_log, pISOFileId, 2);
  }
  PH_LOG_HELPER_ADDPARAM_BUFFER(PH_LOG_LOGTYPE_DEBUG, pISODFName_log, pISODFName, bISODFNameLen);
  PH_LOG_HELPER_EXECUTE(PH_LOG_OPTION_CATEGORY_ENTER);

  /* Validate the parameters */
  PH_ASSERT_NULL_DATA_PARAM(pDataParams, PH_COMP_AL_MFDFEVX);
  if (bOption & 0x01) {
    PH_ASSERT_NULL_PARAM(pISOFileId, PH_COMP_AL_MFDFEVX);
  }
  if (bISODFNameLen > 0) {
    PH_ASSERT_NULL_PARAM(pISODFName, PH_COMP_AL_MFDFEVX);
  }
  PH_ASSERT_NULL_PARAM(pAid, PH_COMP_AL_MFDFEVX);

  /* Parameter validation */
  if (PH_GET_COMPCODE(pDataParams) != PH_COMP_AL_MFDFEVX) {
    PH_LOG_HELPER_ADDSTRING(PH_LOG_LOGTYPE_INFO, bFunctionName);
    PH_LOG_HELPER_ADDPARAM_UINT16(PH_LOG_LOGTYPE_INFO, status_log, &status);
    PH_LOG_HELPER_EXECUTE(PH_LOG_OPTION_CATEGORY_LEAVE);
    return PH_ADD_COMPCODE_FIXED(PH_ERR_INVALID_DATA_PARAMS, PH_COMP_AL_MFDFEVX);
  }

  /* Perform operation on active layer */
  switch (PH_GET_COMPID(pDataParams)) {
#ifdef NXPBUILD__PHAL_MFDFEVX_SW
    case PHAL_MFDFEVX_SW_ID:
      status = phalMfdfEVx_Sw_CreateDelegatedApplication((phalMfdfEVx_Sw_DataParams_t *) pDataParams,
              bOption, pAid,
              pDamParams, bKeySettings1, bKeySettings2, bKeySettings3, bKeySetValues, pISOFileId, pISODFName,
              bISODFNameLen,
              pEncK, pDAMMAC);
      break;
#endif /* NXPBUILD__PHAL_MFDFEVX_SW */

    default:
      status = PH_ADD_COMPCODE_FIXED(PH_ERR_INVALID_DATA_PARAMS, PH_COMP_AL_MFDFEVX);
      break;
  }

  PH_LOG_HELPER_ADDSTRING(PH_LOG_LOGTYPE_INFO, bFunctionName);
  PH_LOG_HELPER_ADDPARAM_UINT16(PH_LOG_LOGTYPE_INFO, status_log, &status);
  PH_LOG_HELPER_EXECUTE(PH_LOG_OPTION_CATEGORY_LEAVE);

  return status;
}

phStatus_t phalMfdfEVx_SelectApplication(void *pDataParams, uint8_t bOption, uint8_t *pAid,
    uint8_t *pAid2)
{
  phStatus_t  PH_MEMLOC_REM status = 0;

  PH_LOG_HELPER_ALLOCATE_TEXT(bFunctionName, "phalMfdfEVx_SelectApplication");
  PH_LOG_HELPER_ALLOCATE_PARAMNAME(status);
  PH_LOG_HELPER_ALLOCATE_PARAMNAME(bOption);
  PH_LOG_HELPER_ALLOCATE_PARAMNAME(pAid);
  PH_LOG_HELPER_ALLOCATE_PARAMNAME(pAid2);
  PH_LOG_HELPER_ADDSTRING(PH_LOG_LOGTYPE_INFO, bFunctionName);
  PH_LOG_HELPER_ADDPARAM_UINT8(PH_LOG_LOGTYPE_DEBUG, bOption_log, &bOption);
  PH_LOG_HELPER_ADDPARAM_BUFFER(PH_LOG_LOGTYPE_DEBUG, pAid_log, pAid, 3);
  if (bOption == 0x01) {
    PH_LOG_HELPER_ADDPARAM_BUFFER(PH_LOG_LOGTYPE_DEBUG, pAid2_log, pAid2, 3);
  }
  PH_LOG_HELPER_EXECUTE(PH_LOG_OPTION_CATEGORY_ENTER);

  /* Validate the parameters */
  PH_ASSERT_NULL_DATA_PARAM(pDataParams, PH_COMP_AL_MFDFEVX);
  PH_ASSERT_NULL_PARAM(pAid, PH_COMP_AL_MFDFEVX);
  if (bOption) {
    PH_ASSERT_NULL_PARAM(pAid2, PH_COMP_AL_MFDFEVX);
  }

  if (PH_GET_COMPCODE(pDataParams) != PH_COMP_AL_MFDFEVX) {
    PH_LOG_HELPER_ADDSTRING(PH_LOG_LOGTYPE_INFO, bFunctionName);
    PH_LOG_HELPER_ADDPARAM_UINT16(PH_LOG_LOGTYPE_INFO, status_log, &status);
    PH_LOG_HELPER_EXECUTE(PH_LOG_OPTION_CATEGORY_LEAVE);

    return PH_ADD_COMPCODE_FIXED(PH_ERR_INVALID_DATA_PARAMS, PH_COMP_AL_MFDFEVX);
  }

  /* Perform operation on active layer */
  switch (PH_GET_COMPID(pDataParams)) {

#ifdef NXPBUILD__PHAL_MFDFEVX_SW
    case PHAL_MFDFEVX_SW_ID:
      status = phalMfdfEVx_Sw_SelectApplication((phalMfdfEVx_Sw_DataParams_t *) pDataParams, bOption,
              pAid, pAid2);
      break;
#endif /* NXPBUILD__PHAL_MFDFEVX_SW */

    default:
      status = PH_ADD_COMPCODE_FIXED(PH_ERR_INVALID_DATA_PARAMS, PH_COMP_AL_MFDFEVX);
      break;
  }

  PH_LOG_HELPER_ADDSTRING(PH_LOG_LOGTYPE_INFO, bFunctionName);
  PH_LOG_HELPER_ADDPARAM_UINT16(PH_LOG_LOGTYPE_INFO, status_log, &status);
  PH_LOG_HELPER_EXECUTE(PH_LOG_OPTION_CATEGORY_LEAVE);

  return status;
}

phStatus_t phalMfdfEVx_GetApplicationIDs(void *pDataParams, uint8_t bOption, uint8_t **pAidBuff,
    uint8_t *pNumAIDs)
{
  /**
  A PICC can store any number of applications limited by the PICC memory.
  PICC will return AIDs (3 Bytes/AID) until the RxBuffer is full and initimates the
  application of RX_CHAINING. Remaining AIDs can be retreived by sending 0xAF command.
  */
  phStatus_t PH_MEMLOC_REM status;

  PH_LOG_HELPER_ALLOCATE_TEXT(bFunctionName, "phalMfdfEVx_GetApplicationIDs");
  PH_LOG_HELPER_ALLOCATE_PARAMNAME(bOption);
  PH_LOG_HELPER_ALLOCATE_PARAMNAME(pAidBuff);
  PH_LOG_HELPER_ALLOCATE_PARAMNAME(pNumAIDs);
  PH_LOG_HELPER_ALLOCATE_PARAMNAME(status);
  PH_LOG_HELPER_ADDSTRING(PH_LOG_LOGTYPE_INFO, bFunctionName);
  PH_LOG_HELPER_ADDPARAM_UINT8(PH_LOG_LOGTYPE_DEBUG, bOption_log, &bOption);
  PH_LOG_HELPER_EXECUTE(PH_LOG_OPTION_CATEGORY_ENTER);

  /* Validate the parameters */
  PH_ASSERT_NULL_DATA_PARAM(pDataParams, PH_COMP_AL_MFDFEVX);
  PH_ASSERT_NULL_PARAM(pAidBuff, PH_COMP_AL_MFDFEVX);
  PH_ASSERT_NULL_PARAM(pNumAIDs, PH_COMP_AL_MFDFEVX);

  /* Parameter validation */
  if (PH_GET_COMPCODE(pDataParams) != PH_COMP_AL_MFDFEVX) {
    PH_LOG_HELPER_ADDSTRING(PH_LOG_LOGTYPE_INFO, bFunctionName);
    PH_LOG_HELPER_ADDPARAM_UINT16(PH_LOG_LOGTYPE_INFO, status_log, &status);
    PH_LOG_HELPER_EXECUTE(PH_LOG_OPTION_CATEGORY_LEAVE);
    return PH_ADD_COMPCODE_FIXED(PH_ERR_INVALID_DATA_PARAMS, PH_COMP_AL_MFDFEVX);
  }

  /* Perform operation on active layer */
  switch (PH_GET_COMPID(pDataParams)) {
#ifdef NXPBUILD__PHAL_MFDFEVX_SW
    case PHAL_MFDFEVX_SW_ID:
      status = phalMfdfEVx_Sw_GetApplicationIDs((phalMfdfEVx_Sw_DataParams_t *) pDataParams, bOption,
              pAidBuff, pNumAIDs);
      break;
#endif /* NXPBUILD__PHAL_MFDFEVX_SW */

    default:
      status = PH_ADD_COMPCODE_FIXED(PH_ERR_INVALID_DATA_PARAMS, PH_COMP_AL_MFDFEVX);
      break;
  }

  PH_LOG_HELPER_ADDSTRING(PH_LOG_LOGTYPE_INFO, bFunctionName);
  PH_LOG_HELPER_ADDPARAM_BUFFER(PH_LOG_LOGTYPE_DEBUG, pAidBuff_log, pAidBuff, (*pNumAIDs) * 3);
  PH_LOG_HELPER_ADDPARAM_UINT8(PH_LOG_LOGTYPE_DEBUG, pNumAIDs_log, pNumAIDs);
  PH_LOG_HELPER_ADDPARAM_UINT16(PH_LOG_LOGTYPE_INFO, status_log, &status);
  PH_LOG_HELPER_EXECUTE(PH_LOG_OPTION_CATEGORY_LEAVE);

  return status;
}

#ifdef NXPBUILD__PHAL_MFDFEVX_NDA
phStatus_t phalMfdfEVx_GetDFNames(void *pDataParams, uint8_t bOption, uint8_t *pDFBuffer,
    uint8_t  *pDFInfoLen)
{
  /*
  Returns AID(3B), FID(2B), DF-Name(1..16B) in one frame.
  */
  phStatus_t PH_MEMLOC_REM status;

  PH_LOG_HELPER_ALLOCATE_TEXT(bFunctionName, "phalMfdfEVx_GetDFNames");
  PH_LOG_HELPER_ALLOCATE_PARAMNAME(bOption);
  PH_LOG_HELPER_ALLOCATE_PARAMNAME(pDFBuffer);
  PH_LOG_HELPER_ALLOCATE_PARAMNAME(pDFInfoLen);
  PH_LOG_HELPER_ALLOCATE_PARAMNAME(status);
  PH_LOG_HELPER_ADDSTRING(PH_LOG_LOGTYPE_INFO, bFunctionName);
  PH_LOG_HELPER_ADDPARAM_UINT8(PH_LOG_LOGTYPE_DEBUG, bOption_log, &bOption);
  PH_LOG_HELPER_EXECUTE(PH_LOG_OPTION_CATEGORY_ENTER);

  /* Validate the parameters */
  PH_ASSERT_NULL_DATA_PARAM(pDataParams, PH_COMP_AL_MFDFEVX);
  PH_ASSERT_NULL_PARAM(pDFBuffer, PH_COMP_AL_MFDFEVX);
  PH_ASSERT_NULL_PARAM(pDFInfoLen, PH_COMP_AL_MFDFEVX);

  /* Parameter validation */
  if (PH_GET_COMPCODE(pDataParams) != PH_COMP_AL_MFDFEVX) {
    PH_LOG_HELPER_ADDSTRING(PH_LOG_LOGTYPE_INFO, bFunctionName);
    PH_LOG_HELPER_ADDPARAM_UINT16(PH_LOG_LOGTYPE_INFO, status_log, &status);
    PH_LOG_HELPER_EXECUTE(PH_LOG_OPTION_CATEGORY_LEAVE);
    return PH_ADD_COMPCODE_FIXED(PH_ERR_INVALID_DATA_PARAMS, PH_COMP_AL_MFDFEVX);
  }

  /* Perform operation on active layer */
  switch (PH_GET_COMPID(pDataParams)) {
#ifdef NXPBUILD__PHAL_MFDFEVX_SW
    case PHAL_MFDFEVX_SW_ID:
      status = phalMfdfEVx_Sw_GetDFNames((phalMfdfEVx_Sw_DataParams_t *) pDataParams, bOption,
              pDFBuffer, pDFInfoLen);
      break;
#endif /* NXPBUILD__PHAL_MFDFEVX_SW */

    default:
      status = PH_ADD_COMPCODE_FIXED(PH_ERR_INVALID_DATA_PARAMS, PH_COMP_AL_MFDFEVX);
      break;
  }

  PH_LOG_HELPER_ADDSTRING(PH_LOG_LOGTYPE_INFO, bFunctionName);
  PH_LOG_HELPER_ADDPARAM_BUFFER(PH_LOG_LOGTYPE_DEBUG, pDFBuffer_log, pDFBuffer, (*pDFInfoLen));
  PH_LOG_HELPER_ADDPARAM_BUFFER(PH_LOG_LOGTYPE_DEBUG, pDFInfoLen_log, pDFInfoLen, 1);
  PH_LOG_HELPER_ADDPARAM_UINT16(PH_LOG_LOGTYPE_INFO, status_log, &status);
  PH_LOG_HELPER_EXECUTE(PH_LOG_OPTION_CATEGORY_LEAVE);

  return status;
}
#endif /* NXPBUILD__PHAL_MFDFEVX_NDA */

phStatus_t phalMfdfEVx_GetDelegatedInfo(void *pDataParams, uint8_t *pDAMSlot,
    uint8_t *pDamSlotVer, uint8_t *pQuotaLimit,
    uint8_t *pFreeBlocks, uint8_t *pAid)
{
  phStatus_t PH_MEMLOC_REM status;

  PH_LOG_HELPER_ALLOCATE_TEXT(bFunctionName, "phalMfdfEVx_GetDelegatedInfo");
  PH_LOG_HELPER_ALLOCATE_PARAMNAME(pDAMSlot);
  PH_LOG_HELPER_ALLOCATE_PARAMNAME(pDamSlotVer);
  PH_LOG_HELPER_ALLOCATE_PARAMNAME(pQuotaLimit);
  PH_LOG_HELPER_ALLOCATE_PARAMNAME(pFreeBlocks);
  PH_LOG_HELPER_ALLOCATE_PARAMNAME(pAid);
  PH_LOG_HELPER_ALLOCATE_PARAMNAME(status);
  PH_LOG_HELPER_ADDSTRING(PH_LOG_LOGTYPE_INFO, bFunctionName);
  PH_LOG_HELPER_EXECUTE(PH_LOG_OPTION_CATEGORY_ENTER);

  /* Validate the parameters */
  PH_ASSERT_NULL_DATA_PARAM(pDataParams, PH_COMP_AL_MFDFEVX);
  PH_ASSERT_NULL_PARAM(pDAMSlot, PH_COMP_AL_MFDFEVX);
  PH_ASSERT_NULL_PARAM(pDamSlotVer, PH_COMP_AL_MFDFEVX);
  PH_ASSERT_NULL_PARAM(pQuotaLimit, PH_COMP_AL_MFDFEVX);
  PH_ASSERT_NULL_PARAM(pFreeBlocks, PH_COMP_AL_MFDFEVX);
  PH_ASSERT_NULL_PARAM(pAid, PH_COMP_AL_MFDFEVX);

  /* Parameter validation */
  if (PH_GET_COMPCODE(pDataParams) != PH_COMP_AL_MFDFEVX) {
    PH_LOG_HELPER_ADDSTRING(PH_LOG_LOGTYPE_INFO, bFunctionName);
    PH_LOG_HELPER_ADDPARAM_UINT16(PH_LOG_LOGTYPE_INFO, status_log, &status);
    PH_LOG_HELPER_EXECUTE(PH_LOG_OPTION_CATEGORY_LEAVE);
    return PH_ADD_COMPCODE_FIXED(PH_ERR_INVALID_DATA_PARAMS, PH_COMP_AL_MFDFEVX);
  }

  /* Perform operation on active layer */
  switch (PH_GET_COMPID(pDataParams)) {
#ifdef NXPBUILD__PHAL_MFDFEVX_SW
    case PHAL_MFDFEVX_SW_ID:
      status = phalMfdfEVx_Sw_GetDelegatedInfo((phalMfdfEVx_Sw_DataParams_t *) pDataParams, pDAMSlot,
              pDamSlotVer, pQuotaLimit,
              pFreeBlocks, pAid);
      break;
#endif /* NXPBUILD__PHAL_MFDFEVX_SW */

    default:
      status = PH_ADD_COMPCODE_FIXED(PH_ERR_INVALID_DATA_PARAMS, PH_COMP_AL_MFDFEVX);
      break;
  }

  PH_LOG_HELPER_ADDSTRING(PH_LOG_LOGTYPE_INFO, bFunctionName);
  PH_LOG_HELPER_ADDPARAM_BUFFER(PH_LOG_LOGTYPE_DEBUG, pDAMSlot_log, pDAMSlot, 2);
  PH_LOG_HELPER_ADDPARAM_BUFFER(PH_LOG_LOGTYPE_DEBUG, pDamSlotVer_log, pDamSlotVer, 1);
  PH_LOG_HELPER_ADDPARAM_BUFFER(PH_LOG_LOGTYPE_DEBUG, pQuotaLimit_log, pQuotaLimit, 2);
  PH_LOG_HELPER_ADDPARAM_BUFFER(PH_LOG_LOGTYPE_DEBUG, pFreeBlocks_log, pFreeBlocks, 2);
  PH_LOG_HELPER_ADDPARAM_BUFFER(PH_LOG_LOGTYPE_DEBUG, pAid_log, pAid, 3);
  PH_LOG_HELPER_ADDPARAM_UINT16(PH_LOG_LOGTYPE_INFO, status_log, &status);
  PH_LOG_HELPER_EXECUTE(PH_LOG_OPTION_CATEGORY_LEAVE);

  return status;
}

/* MIFARE DESFire EVX File mamangement commands. --------------------------------------------------------------------------------------- */
phStatus_t phalMfdfEVx_CreateStdDataFile(void *pDataParams, uint8_t bOption, uint8_t bFileNo,
    uint8_t *pISOFileId, uint8_t bFileOption,
    uint8_t *pAccessRights, uint8_t *pFileSize)
{
  phStatus_t PH_MEMLOC_REM status;

  PH_LOG_HELPER_ALLOCATE_TEXT(bFunctionName, "phalMfdfEVx_CreateStdDataFile");
  PH_LOG_HELPER_ALLOCATE_PARAMNAME(status);
  PH_LOG_HELPER_ALLOCATE_PARAMNAME(bOption);
  PH_LOG_HELPER_ALLOCATE_PARAMNAME(bFileNo);
  PH_LOG_HELPER_ALLOCATE_PARAMNAME(pISOFileId);
  PH_LOG_HELPER_ALLOCATE_PARAMNAME(bFileOption);
  PH_LOG_HELPER_ALLOCATE_PARAMNAME(pAccessRights);
  PH_LOG_HELPER_ALLOCATE_PARAMNAME(pFileSize);
  PH_LOG_HELPER_ADDSTRING(PH_LOG_LOGTYPE_INFO, bFunctionName);
  PH_LOG_HELPER_ADDPARAM_UINT8(PH_LOG_LOGTYPE_DEBUG, bOption_log, &bOption);
  PH_LOG_HELPER_ADDPARAM_UINT8(PH_LOG_LOGTYPE_DEBUG, bFileNo_log, &bFileNo);
  PH_LOG_HELPER_ADDPARAM_UINT8(PH_LOG_LOGTYPE_DEBUG, bFileOption_log, &bFileOption);
  PH_LOG_HELPER_ADDPARAM_BUFFER(PH_LOG_LOGTYPE_DEBUG, pAccessRights_log, pAccessRights, 2);
  PH_LOG_HELPER_ADDPARAM_BUFFER(PH_LOG_LOGTYPE_DEBUG, pFileSize_log, pFileSize, 3);
  if (bOption == 0x01) {
    PH_LOG_HELPER_ADDPARAM_BUFFER(PH_LOG_LOGTYPE_DEBUG, pISOFileId_log, pISOFileId, 2);
  }

  PH_LOG_HELPER_EXECUTE(PH_LOG_OPTION_CATEGORY_ENTER);

  /* Validate the parameters */
  PH_ASSERT_NULL_DATA_PARAM(pDataParams, PH_COMP_AL_MFDFEVX);
  if (bOption == 0x01) {
    PH_ASSERT_NULL_PARAM(pISOFileId, PH_COMP_AL_MFDFEVX);
  }
  PH_ASSERT_NULL_PARAM(pAccessRights, PH_COMP_AL_MFDFEVX);
  PH_ASSERT_NULL_PARAM(pFileSize, PH_COMP_AL_MFDFEVX);

  /* Parameter validation */
  if (PH_GET_COMPCODE(pDataParams) != PH_COMP_AL_MFDFEVX) {
    PH_LOG_HELPER_ADDSTRING(PH_LOG_LOGTYPE_INFO, bFunctionName);
    PH_LOG_HELPER_ADDPARAM_UINT16(PH_LOG_LOGTYPE_INFO, status_log, &status);
    PH_LOG_HELPER_EXECUTE(PH_LOG_OPTION_CATEGORY_LEAVE);

    return PH_ADD_COMPCODE_FIXED(PH_ERR_INVALID_DATA_PARAMS, PH_COMP_AL_MFDFEVX);
  }

  /* Perform operation on active layer */
  switch (PH_GET_COMPID(pDataParams)) {
#ifdef NXPBUILD__PHAL_MFDFEVX_SW
    case PHAL_MFDFEVX_SW_ID:
      status = phalMfdfEVx_Sw_CreateStdDataFile((phalMfdfEVx_Sw_DataParams_t *) pDataParams, bOption,
              bFileNo,
              pISOFileId, bFileOption, pAccessRights, pFileSize);
      break;
#endif /* NXPBUILD__PHAL_MFDFEVX_SW */

    default:
      status = PH_ADD_COMPCODE_FIXED(PH_ERR_INVALID_DATA_PARAMS, PH_COMP_AL_MFDFEVX);
      break;
  }

  PH_LOG_HELPER_ADDSTRING(PH_LOG_LOGTYPE_INFO, bFunctionName);
  PH_LOG_HELPER_ADDPARAM_UINT16(PH_LOG_LOGTYPE_INFO, status_log, &status);
  PH_LOG_HELPER_EXECUTE(PH_LOG_OPTION_CATEGORY_LEAVE);

  return status;
}

phStatus_t phalMfdfEVx_CreateBackupDataFile(void *pDataParams, uint8_t bOption, uint8_t bFileNo,
    uint8_t *pISOFileId, uint8_t bFileOption,
    uint8_t *pAccessRights, uint8_t *pFileSize)
{
  phStatus_t PH_MEMLOC_REM status;

  PH_LOG_HELPER_ALLOCATE_TEXT(bFunctionName, "phalMfdfEVx_CreateBackupDataFile");
  PH_LOG_HELPER_ALLOCATE_PARAMNAME(status);
  PH_LOG_HELPER_ALLOCATE_PARAMNAME(bOption);
  PH_LOG_HELPER_ALLOCATE_PARAMNAME(bFileNo);
  PH_LOG_HELPER_ALLOCATE_PARAMNAME(pISOFileId);
  PH_LOG_HELPER_ALLOCATE_PARAMNAME(bFileOption);
  PH_LOG_HELPER_ALLOCATE_PARAMNAME(pAccessRights);
  PH_LOG_HELPER_ALLOCATE_PARAMNAME(pFileSize);
  PH_LOG_HELPER_ADDSTRING(PH_LOG_LOGTYPE_INFO, bFunctionName);
  PH_LOG_HELPER_ADDPARAM_UINT8(PH_LOG_LOGTYPE_DEBUG, bOption_log, &bOption);
  PH_LOG_HELPER_ADDPARAM_UINT8(PH_LOG_LOGTYPE_DEBUG, bFileNo_log, &bFileNo);
  PH_LOG_HELPER_ADDPARAM_UINT8(PH_LOG_LOGTYPE_DEBUG, bFileOption_log, &bFileOption);
  PH_LOG_HELPER_ADDPARAM_BUFFER(PH_LOG_LOGTYPE_DEBUG, pAccessRights_log, pAccessRights, 2);
  if (bOption == 0x01) {
    PH_LOG_HELPER_ADDPARAM_BUFFER(PH_LOG_LOGTYPE_DEBUG, pISOFileId_log, pISOFileId, 2);
  }
  PH_LOG_HELPER_ADDPARAM_BUFFER(PH_LOG_LOGTYPE_DEBUG, pFileSize_log, pFileSize, 3);
  PH_LOG_HELPER_EXECUTE(PH_LOG_OPTION_CATEGORY_ENTER);

  /* Validate the parameters */
  PH_ASSERT_NULL_DATA_PARAM(pDataParams, PH_COMP_AL_MFDFEVX);
  if (bOption == 1) {
    PH_ASSERT_NULL_PARAM(pISOFileId, PH_COMP_AL_MFDFEVX);
  }
  PH_ASSERT_NULL_PARAM(pAccessRights, PH_COMP_AL_MFDFEVX);
  PH_ASSERT_NULL_PARAM(pFileSize, PH_COMP_AL_MFDFEVX);

  /* Parameter validation */
  if (PH_GET_COMPCODE(pDataParams) != PH_COMP_AL_MFDFEVX) {
    PH_LOG_HELPER_ADDSTRING(PH_LOG_LOGTYPE_INFO, bFunctionName);
    PH_LOG_HELPER_ADDPARAM_UINT16(PH_LOG_LOGTYPE_INFO, status_log, &status);
    PH_LOG_HELPER_EXECUTE(PH_LOG_OPTION_CATEGORY_LEAVE);
    return PH_ADD_COMPCODE_FIXED(PH_ERR_INVALID_DATA_PARAMS, PH_COMP_AL_MFDFEVX);
  }

  /* Perform operation on active layer */
  switch (PH_GET_COMPID(pDataParams)) {
#ifdef NXPBUILD__PHAL_MFDFEVX_SW
    case PHAL_MFDFEVX_SW_ID:
      status = phalMfdfEVx_Sw_CreateBackupDataFile((phalMfdfEVx_Sw_DataParams_t *) pDataParams, bOption,
              bFileNo,
              pISOFileId, bFileOption, pAccessRights, pFileSize);
      break;
#endif /* NXPBUILD__PHAL_MFDFEVX_SW */

    default:
      status = PH_ADD_COMPCODE_FIXED(PH_ERR_INVALID_DATA_PARAMS, PH_COMP_AL_MFDFEVX);
      break;
  }

  PH_LOG_HELPER_ADDSTRING(PH_LOG_LOGTYPE_INFO, bFunctionName);
  PH_LOG_HELPER_ADDPARAM_UINT16(PH_LOG_LOGTYPE_INFO, status_log, &status);
  PH_LOG_HELPER_EXECUTE(PH_LOG_OPTION_CATEGORY_LEAVE);

  return status;
}

phStatus_t phalMfdfEVx_CreateValueFile(void *pDataParams, uint8_t bFileNo, uint8_t bCommSett,
    uint8_t *pAccessRights, uint8_t *pLowerLmit,
    uint8_t *pUpperLmit, uint8_t *pValue, uint8_t bLimitedCredit)
{
  phStatus_t PH_MEMLOC_REM status;

  PH_LOG_HELPER_ALLOCATE_TEXT(bFunctionName, "phalMfdfEVx_CreateValueFile");
  PH_LOG_HELPER_ALLOCATE_PARAMNAME(bFileNo);
  PH_LOG_HELPER_ALLOCATE_PARAMNAME(bCommSett);
  PH_LOG_HELPER_ALLOCATE_PARAMNAME(pAccessRights);
  PH_LOG_HELPER_ALLOCATE_PARAMNAME(pLowerLmit);
  PH_LOG_HELPER_ALLOCATE_PARAMNAME(pUpperLmit);
  PH_LOG_HELPER_ALLOCATE_PARAMNAME(pValue);
  PH_LOG_HELPER_ALLOCATE_PARAMNAME(bLimitedCredit);
  PH_LOG_HELPER_ALLOCATE_PARAMNAME(status);
  PH_LOG_HELPER_ADDSTRING(PH_LOG_LOGTYPE_INFO, bFunctionName);
  PH_LOG_HELPER_ADDPARAM_UINT8(PH_LOG_LOGTYPE_DEBUG, bFileNo_log, &bFileNo);
  PH_LOG_HELPER_ADDPARAM_UINT8(PH_LOG_LOGTYPE_DEBUG, bCommSett_log, &bCommSett);
  PH_LOG_HELPER_ADDPARAM_BUFFER(PH_LOG_LOGTYPE_DEBUG, pAccessRights_log, pAccessRights, 2);
  PH_LOG_HELPER_ADDPARAM_BUFFER(PH_LOG_LOGTYPE_DEBUG, pLowerLmit_log, pLowerLmit, 4);
  PH_LOG_HELPER_ADDPARAM_BUFFER(PH_LOG_LOGTYPE_DEBUG, pUpperLmit_log, pUpperLmit, 4);
  PH_LOG_HELPER_ADDPARAM_BUFFER(PH_LOG_LOGTYPE_DEBUG, pValue_log, pValue, 4);
  PH_LOG_HELPER_ADDPARAM_UINT8(PH_LOG_LOGTYPE_DEBUG, bLimitedCredit_log, &bLimitedCredit);
  PH_LOG_HELPER_EXECUTE(PH_LOG_OPTION_CATEGORY_ENTER);

  /* Validate the parameters */
  PH_ASSERT_NULL_DATA_PARAM(pDataParams, PH_COMP_AL_MFDFEVX);
  PH_ASSERT_NULL_PARAM(pAccessRights, PH_COMP_AL_MFDFEVX);
  PH_ASSERT_NULL_PARAM(pLowerLmit, PH_COMP_AL_MFDFEVX);
  PH_ASSERT_NULL_PARAM(pUpperLmit, PH_COMP_AL_MFDFEVX);
  PH_ASSERT_NULL_PARAM(pValue, PH_COMP_AL_MFDFEVX);

  /* Parameter validation */
  if (PH_GET_COMPCODE(pDataParams) != PH_COMP_AL_MFDFEVX) {
    PH_LOG_HELPER_ADDSTRING(PH_LOG_LOGTYPE_INFO, bFunctionName);
    PH_LOG_HELPER_ADDPARAM_UINT16(PH_LOG_LOGTYPE_INFO, status_log, &status);
    PH_LOG_HELPER_EXECUTE(PH_LOG_OPTION_CATEGORY_LEAVE);

    return PH_ADD_COMPCODE_FIXED(PH_ERR_INVALID_DATA_PARAMS, PH_COMP_AL_MFDFEVX);
  }

  /* Perform operation on active layer */
  switch (PH_GET_COMPID(pDataParams)) {
#ifdef NXPBUILD__PHAL_MFDFEVX_SW
    case PHAL_MFDFEVX_SW_ID:
      status = phalMfdfEVx_Sw_CreateValueFile((phalMfdfEVx_Sw_DataParams_t *) pDataParams, bFileNo,
              bCommSett, pAccessRights,
              pLowerLmit, pUpperLmit, pValue, bLimitedCredit);
      break;
#endif /* NXPBUILD__PHAL_MFDFEVX_SW */

    default:
      status = PH_ADD_COMPCODE_FIXED(PH_ERR_INVALID_DATA_PARAMS, PH_COMP_AL_MFDFEVX);
      break;
  }

  PH_LOG_HELPER_ADDSTRING(PH_LOG_LOGTYPE_INFO, bFunctionName);
  PH_LOG_HELPER_ADDPARAM_UINT16(PH_LOG_LOGTYPE_INFO, status_log, &status);
  PH_LOG_HELPER_EXECUTE(PH_LOG_OPTION_CATEGORY_LEAVE);

  return status;
}

phStatus_t phalMfdfEVx_CreateLinearRecordFile(void *pDataParams, uint8_t bOption,
    uint8_t  bFileNo, uint8_t  *pIsoFileId, uint8_t bCommSett,
    uint8_t *pAccessRights, uint8_t *pRecordSize, uint8_t *pMaxNoOfRec)

{
  phStatus_t PH_MEMLOC_REM status;

  PH_LOG_HELPER_ALLOCATE_TEXT(bFunctionName, "phalMfdfEVx_CreateLinearRecordFile");
  PH_LOG_HELPER_ALLOCATE_PARAMNAME(bOption);
  PH_LOG_HELPER_ALLOCATE_PARAMNAME(bFileNo);
  PH_LOG_HELPER_ALLOCATE_PARAMNAME(pIsoFileId);
  PH_LOG_HELPER_ALLOCATE_PARAMNAME(bCommSett);
  PH_LOG_HELPER_ALLOCATE_PARAMNAME(pAccessRights);
  PH_LOG_HELPER_ALLOCATE_PARAMNAME(pRecordSize);
  PH_LOG_HELPER_ALLOCATE_PARAMNAME(pMaxNoOfRec);
  PH_LOG_HELPER_ALLOCATE_PARAMNAME(status);
  PH_LOG_HELPER_ADDSTRING(PH_LOG_LOGTYPE_INFO, bFunctionName);
  PH_LOG_HELPER_ADDPARAM_UINT8(PH_LOG_LOGTYPE_DEBUG, bOption_log, &bOption);
  PH_LOG_HELPER_ADDPARAM_UINT8(PH_LOG_LOGTYPE_DEBUG, bFileNo_log, &bFileNo);
  if (bOption == 0x01) {
    PH_LOG_HELPER_ADDPARAM_BUFFER(PH_LOG_LOGTYPE_DEBUG, pIsoFileId_log, pIsoFileId, 2);
  }
  PH_LOG_HELPER_ADDPARAM_UINT8(PH_LOG_LOGTYPE_DEBUG, bCommSett_log, &bCommSett);
  PH_LOG_HELPER_ADDPARAM_BUFFER(PH_LOG_LOGTYPE_DEBUG, pAccessRights_log, pAccessRights, 2);
  PH_LOG_HELPER_ADDPARAM_BUFFER(PH_LOG_LOGTYPE_DEBUG, pRecordSize_log, pRecordSize, 3);
  PH_LOG_HELPER_ADDPARAM_BUFFER(PH_LOG_LOGTYPE_DEBUG, pMaxNoOfRec_log, pMaxNoOfRec, 3);
  PH_LOG_HELPER_EXECUTE(PH_LOG_OPTION_CATEGORY_ENTER);

  /* Validate the parameters */
  PH_ASSERT_NULL_DATA_PARAM(pDataParams, PH_COMP_AL_MFDFEVX);
  if (bOption == 1) {
    PH_ASSERT_NULL_PARAM(pIsoFileId, PH_COMP_AL_MFDFEVX);
  }
  PH_ASSERT_NULL_PARAM(pAccessRights, PH_COMP_AL_MFDFEVX);
  PH_ASSERT_NULL_PARAM(pRecordSize, PH_COMP_AL_MFDFEVX);
  PH_ASSERT_NULL_PARAM(pMaxNoOfRec, PH_COMP_AL_MFDFEVX);

  /* Parameter validation */
  if (PH_GET_COMPCODE(pDataParams) != PH_COMP_AL_MFDFEVX) {
    PH_LOG_HELPER_ADDSTRING(PH_LOG_LOGTYPE_INFO, bFunctionName);
    PH_LOG_HELPER_ADDPARAM_UINT16(PH_LOG_LOGTYPE_INFO, status_log, &status);
    PH_LOG_HELPER_EXECUTE(PH_LOG_OPTION_CATEGORY_LEAVE);

    return PH_ADD_COMPCODE_FIXED(PH_ERR_INVALID_DATA_PARAMS, PH_COMP_AL_MFDFEVX);
  }

  /* Perform operation on active layer */
  switch (PH_GET_COMPID(pDataParams)) {
#ifdef NXPBUILD__PHAL_MFDFEVX_SW
    case PHAL_MFDFEVX_SW_ID:
      status = phalMfdfEVx_Sw_CreateLinearRecordFile((phalMfdfEVx_Sw_DataParams_t *)pDataParams,
              bOption,
              bFileNo, pIsoFileId, bCommSett, pAccessRights, pRecordSize, pMaxNoOfRec);
      break;
#endif /* NXPBUILD__PHAL_MFDFEVX_SW */

    default:
      status = PH_ADD_COMPCODE_FIXED(PH_ERR_INVALID_DATA_PARAMS, PH_COMP_AL_MFDFEVX);
      break;
  }

  PH_LOG_HELPER_ADDSTRING(PH_LOG_LOGTYPE_INFO, bFunctionName);
  PH_LOG_HELPER_ADDPARAM_UINT16(PH_LOG_LOGTYPE_INFO, status_log, &status);
  PH_LOG_HELPER_EXECUTE(PH_LOG_OPTION_CATEGORY_LEAVE);

  return status;
}

phStatus_t phalMfdfEVx_CreateCyclicRecordFile(void *pDataParams, uint8_t bOption,
    uint8_t  bFileNo, uint8_t  *pIsoFileId, uint8_t bCommSett,
    uint8_t *pAccessRights, uint8_t *pRecordSize, uint8_t *pMaxNoOfRec)
{
  phStatus_t PH_MEMLOC_REM status;

  PH_LOG_HELPER_ALLOCATE_TEXT(bFunctionName, "phalMfdfEVx_CreateCyclicRecordFile");
  PH_LOG_HELPER_ALLOCATE_PARAMNAME(bOption);
  PH_LOG_HELPER_ALLOCATE_PARAMNAME(bFileNo);
  PH_LOG_HELPER_ALLOCATE_PARAMNAME(pIsoFileId);
  PH_LOG_HELPER_ALLOCATE_PARAMNAME(bCommSett);
  PH_LOG_HELPER_ALLOCATE_PARAMNAME(pAccessRights);
  PH_LOG_HELPER_ALLOCATE_PARAMNAME(pRecordSize);
  PH_LOG_HELPER_ALLOCATE_PARAMNAME(pMaxNoOfRec);
  PH_LOG_HELPER_ALLOCATE_PARAMNAME(status);
  PH_LOG_HELPER_ADDSTRING(PH_LOG_LOGTYPE_INFO, bFunctionName);
  PH_LOG_HELPER_ADDPARAM_UINT8(PH_LOG_LOGTYPE_DEBUG, bOption_log, &bOption);
  PH_LOG_HELPER_ADDPARAM_UINT8(PH_LOG_LOGTYPE_DEBUG, bFileNo_log, &bFileNo);
  if (bOption == 0x01) {
    PH_LOG_HELPER_ADDPARAM_BUFFER(PH_LOG_LOGTYPE_DEBUG, pIsoFileId_log, pIsoFileId, 2);
  }
  PH_LOG_HELPER_ADDPARAM_UINT8(PH_LOG_LOGTYPE_DEBUG, bCommSett_log, &bCommSett);
  PH_LOG_HELPER_ADDPARAM_BUFFER(PH_LOG_LOGTYPE_DEBUG, pAccessRights_log, pAccessRights, 2);
  PH_LOG_HELPER_ADDPARAM_BUFFER(PH_LOG_LOGTYPE_DEBUG, pRecordSize_log, pRecordSize, 3);
  PH_LOG_HELPER_ADDPARAM_BUFFER(PH_LOG_LOGTYPE_DEBUG, pMaxNoOfRec_log, pMaxNoOfRec, 3);
  PH_LOG_HELPER_EXECUTE(PH_LOG_OPTION_CATEGORY_ENTER);

  /* Validate the parameters */
  PH_ASSERT_NULL_DATA_PARAM(pDataParams, PH_COMP_AL_MFDFEVX);
  PH_ASSERT_NULL_PARAM(pAccessRights, PH_COMP_AL_MFDFEVX);
  if (bOption == 0x01) {
    PH_ASSERT_NULL_PARAM(pIsoFileId, PH_COMP_AL_MFDFEVX);
  }
  PH_ASSERT_NULL_PARAM(pRecordSize, PH_COMP_AL_MFDFEVX);
  PH_ASSERT_NULL_PARAM(pMaxNoOfRec, PH_COMP_AL_MFDFEVX);

  /* Parameter validation */
  if (PH_GET_COMPCODE(pDataParams) != PH_COMP_AL_MFDFEVX) {
    PH_LOG_HELPER_ADDSTRING(PH_LOG_LOGTYPE_INFO, bFunctionName);
    PH_LOG_HELPER_ADDPARAM_UINT16(PH_LOG_LOGTYPE_INFO, status_log, &status);
    PH_LOG_HELPER_EXECUTE(PH_LOG_OPTION_CATEGORY_LEAVE);

    return PH_ADD_COMPCODE_FIXED(PH_ERR_INVALID_DATA_PARAMS, PH_COMP_AL_MFDFEVX);
  }

  /* Perform operation on active layer */
  switch (PH_GET_COMPID(pDataParams)) {
#ifdef NXPBUILD__PHAL_MFDFEVX_SW
    case PHAL_MFDFEVX_SW_ID:
      status = phalMfdfEVx_Sw_CreateCyclicRecordFile((phalMfdfEVx_Sw_DataParams_t *) pDataParams,
              bOption,
              bFileNo, pIsoFileId, bCommSett, pAccessRights, pRecordSize, pMaxNoOfRec);
      break;
#endif /* NXPBUILD__PHAL_MFDFEVX_SW */

    default:
      status = PH_ADD_COMPCODE_FIXED(PH_ERR_INVALID_DATA_PARAMS, PH_COMP_AL_MFDFEVX);
      break;
  }

  PH_LOG_HELPER_ADDSTRING(PH_LOG_LOGTYPE_INFO, bFunctionName);
  PH_LOG_HELPER_ADDPARAM_UINT16(PH_LOG_LOGTYPE_INFO, status_log, &status);
  PH_LOG_HELPER_EXECUTE(PH_LOG_OPTION_CATEGORY_LEAVE);

  return status;
}

#ifdef NXPBUILD__PHAL_MFDFEVX_NDA
phStatus_t phalMfdfEVx_CreateTransactionMacFile(void *pDataParams, uint16_t wOption,
    uint8_t bFileNo, uint8_t bCommSett, uint8_t *pAccessRights,
    uint16_t wKeyNo, uint8_t bKeyType, uint8_t *bTMKey, uint8_t bTMKeyVer, uint8_t *pDivInput,
    uint8_t bDivInputLength)
{
  phStatus_t PH_MEMLOC_REM status;

  PH_LOG_HELPER_ALLOCATE_TEXT(bFunctionName, "phalMfdfEVx_CreateTransactionMacFile");
  PH_LOG_HELPER_ALLOCATE_PARAMNAME(wOption);
  PH_LOG_HELPER_ALLOCATE_PARAMNAME(bFileNo);
  PH_LOG_HELPER_ALLOCATE_PARAMNAME(bCommSett);
  PH_LOG_HELPER_ALLOCATE_PARAMNAME(pAccessRights);
  PH_LOG_HELPER_ALLOCATE_PARAMNAME(wKeyNo);
  PH_LOG_HELPER_ALLOCATE_PARAMNAME(bKeyType);
  PH_LOG_HELPER_ALLOCATE_PARAMNAME(bTMKey);
  PH_LOG_HELPER_ALLOCATE_PARAMNAME(bTMKeyVer);
  PH_LOG_HELPER_ALLOCATE_PARAMNAME(pDivInput);
  PH_LOG_HELPER_ALLOCATE_PARAMNAME(bDivInputLength);
  PH_LOG_HELPER_ALLOCATE_PARAMNAME(status);
  PH_LOG_HELPER_ADDSTRING(PH_LOG_LOGTYPE_INFO, bFunctionName);
  PH_LOG_HELPER_ADDPARAM_UINT16(PH_LOG_LOGTYPE_DEBUG, wOption_log, &wOption);
  PH_LOG_HELPER_ADDPARAM_UINT8(PH_LOG_LOGTYPE_DEBUG, bFileNo_log, &bFileNo);
  PH_LOG_HELPER_ADDPARAM_UINT8(PH_LOG_LOGTYPE_DEBUG, bCommSett_log, &bCommSett);
  PH_LOG_HELPER_ADDPARAM_UINT16(PH_LOG_LOGTYPE_DEBUG, wKeyNo_log, &wKeyNo);
  PH_LOG_HELPER_ADDPARAM_UINT8(PH_LOG_LOGTYPE_DEBUG, bKeyType_log, &bKeyType);
  PH_LOG_HELPER_ADDPARAM_UINT8(PH_LOG_LOGTYPE_DEBUG, bTMKeyVer_log, &bTMKeyVer);
  PH_LOG_HELPER_ADDPARAM_BUFFER(PH_LOG_LOGTYPE_DEBUG, pAccessRights_log, pAccessRights, 2);
  PH_LOG_HELPER_ADDPARAM_BUFFER(PH_LOG_LOGTYPE_DEBUG, bTMKey_log, bTMKey, 16);
  if (pDivInput != NULL) {
    PH_LOG_HELPER_ADDPARAM_BUFFER(PH_LOG_LOGTYPE_DEBUG, pDivInput_log, pDivInput, bDivInputLength);
  }
  PH_LOG_HELPER_ADDPARAM_UINT8(PH_LOG_LOGTYPE_DEBUG, bDivInputLength_log, &bDivInputLength);
  PH_LOG_HELPER_EXECUTE(PH_LOG_OPTION_CATEGORY_ENTER);

  /* Validate the parameters */
  PH_ASSERT_NULL_DATA_PARAM(pDataParams, PH_COMP_AL_MFDFEVX);
  PH_ASSERT_NULL_PARAM(pAccessRights, PH_COMP_AL_MFDFEVX);
  PH_ASSERT_NULL_PARAM(bTMKey, PH_COMP_AL_MFDFEVX);
  if (bDivInputLength) {
    PH_ASSERT_NULL_PARAM(pDivInput, PH_COMP_AL_MFDFEVX);
  }

  /* Parameter validation */
  if (PH_GET_COMPCODE(pDataParams) != PH_COMP_AL_MFDFEVX) {
    PH_LOG_HELPER_ADDSTRING(PH_LOG_LOGTYPE_INFO, bFunctionName);
    PH_LOG_HELPER_ADDPARAM_UINT16(PH_LOG_LOGTYPE_INFO, status_log, &status);
    PH_LOG_HELPER_EXECUTE(PH_LOG_OPTION_CATEGORY_LEAVE);

    return PH_ADD_COMPCODE_FIXED(PH_ERR_INVALID_DATA_PARAMS, PH_COMP_AL_MFDFEVX);
  }

  /* Perform operation on active layer */
  switch (PH_GET_COMPID(pDataParams)) {
#ifdef NXPBUILD__PHAL_MFDFEVX_SW
    case PHAL_MFDFEVX_SW_ID:
      status = phalMfdfEVx_Sw_CreateTransactionMacFile((phalMfdfEVx_Sw_DataParams_t *) pDataParams,
              bFileNo,
              bCommSett, pAccessRights, bKeyType, bTMKey, bTMKeyVer);
      break;
#endif /* NXPBUILD__PHAL_MFDFEVX_SW */

    default:
      status = PH_ADD_COMPCODE_FIXED(PH_ERR_INVALID_DATA_PARAMS, PH_COMP_AL_MFDFEVX);
      break;
  }

  PH_LOG_HELPER_ADDSTRING(PH_LOG_LOGTYPE_INFO, bFunctionName);
  PH_LOG_HELPER_ADDPARAM_UINT16(PH_LOG_LOGTYPE_INFO, status_log, &status);
  PH_LOG_HELPER_EXECUTE(PH_LOG_OPTION_CATEGORY_LEAVE);

  return status;
}
#endif /* NXPBUILD__PHAL_MFDFEVX_NDA */

phStatus_t phalMfdfEVx_DeleteFile(void *pDataParams, uint8_t bFileNo)
{
  phStatus_t PH_MEMLOC_REM status;

  PH_LOG_HELPER_ALLOCATE_TEXT(bFunctionName, "phalMfdfEVx_DeleteFile");
  PH_LOG_HELPER_ALLOCATE_PARAMNAME(status);
  PH_LOG_HELPER_ALLOCATE_PARAMNAME(bFileNo);
  PH_LOG_HELPER_ADDSTRING(PH_LOG_LOGTYPE_INFO, bFunctionName);
  PH_LOG_HELPER_ADDPARAM_UINT8(PH_LOG_LOGTYPE_DEBUG, bFileNo_log, &bFileNo);
  PH_LOG_HELPER_EXECUTE(PH_LOG_OPTION_CATEGORY_ENTER);

  /* Validate the parameters */
  PH_ASSERT_NULL_DATA_PARAM(pDataParams, PH_COMP_AL_MFDFEVX);

  /* Parameter validation */
  if (PH_GET_COMPCODE(pDataParams) != PH_COMP_AL_MFDFEVX) {
    PH_LOG_HELPER_ADDSTRING(PH_LOG_LOGTYPE_INFO, bFunctionName);
    PH_LOG_HELPER_ADDPARAM_UINT16(PH_LOG_LOGTYPE_INFO, status_log, &status);
    PH_LOG_HELPER_EXECUTE(PH_LOG_OPTION_CATEGORY_LEAVE);

    return PH_ADD_COMPCODE_FIXED(PH_ERR_INVALID_DATA_PARAMS, PH_COMP_AL_MFDFEVX);
  }

  /* Perform operation on active layer */
  switch (PH_GET_COMPID(pDataParams)) {
#ifdef NXPBUILD__PHAL_MFDFEVX_SW
    case PHAL_MFDFEVX_SW_ID:
      status = phalMfdfEVx_Sw_DeleteFile((phalMfdfEVx_Sw_DataParams_t *) pDataParams, bFileNo);
      break;
#endif /* NXPBUILD__PHAL_MFDFEVX_SW */

    default:
      status = PH_ADD_COMPCODE_FIXED(PH_ERR_INVALID_DATA_PARAMS, PH_COMP_AL_MFDFEVX);
      break;
  }

  PH_LOG_HELPER_ADDSTRING(PH_LOG_LOGTYPE_INFO, bFunctionName);
  PH_LOG_HELPER_ADDPARAM_UINT16(PH_LOG_LOGTYPE_INFO, status_log, &status);
  PH_LOG_HELPER_EXECUTE(PH_LOG_OPTION_CATEGORY_LEAVE);

  return status;
}

phStatus_t phalMfdfEVx_GetFileIDs(void *pDataParams, uint8_t *pFid, uint8_t *bNumFID)
{
  phStatus_t PH_MEMLOC_REM status;

  PH_LOG_HELPER_ALLOCATE_TEXT(bFunctionName, "phalMfdfEVx_GetFileIDs");
  PH_LOG_HELPER_ALLOCATE_PARAMNAME(status);
  PH_LOG_HELPER_ALLOCATE_PARAMNAME(pFid);
  PH_LOG_HELPER_ALLOCATE_PARAMNAME(bNumFID);
  PH_LOG_HELPER_ADDSTRING(PH_LOG_LOGTYPE_INFO, bFunctionName);
  PH_LOG_HELPER_EXECUTE(PH_LOG_OPTION_CATEGORY_ENTER);

  /* Validate the parameters */
  PH_ASSERT_NULL_DATA_PARAM(pDataParams, PH_COMP_AL_MFDFEVX);
  PH_ASSERT_NULL_PARAM(pFid, PH_COMP_AL_MFDFEVX);
  PH_ASSERT_NULL_PARAM(bNumFID, PH_COMP_AL_MFDFEVX);

  /* Parameter validation */
  if (PH_GET_COMPCODE(pDataParams) != PH_COMP_AL_MFDFEVX) {
    PH_LOG_HELPER_ADDSTRING(PH_LOG_LOGTYPE_INFO, bFunctionName);
    PH_LOG_HELPER_ADDPARAM_UINT16(PH_LOG_LOGTYPE_INFO, status_log, &status);
    PH_LOG_HELPER_EXECUTE(PH_LOG_OPTION_CATEGORY_LEAVE);

    return PH_ADD_COMPCODE_FIXED(PH_ERR_INVALID_DATA_PARAMS, PH_COMP_AL_MFDFEVX);
  }

  /* Perform operation on active layer */
  switch (PH_GET_COMPID(pDataParams)) {
#ifdef NXPBUILD__PHAL_MFDFEVX_SW
    case PHAL_MFDFEVX_SW_ID:
      status = phalMfdfEVx_Sw_GetFileIDs((phalMfdfEVx_Sw_DataParams_t *) pDataParams, pFid, bNumFID);
      break;
#endif /* NXPBUILD__PHAL_MFDFEVX_SW */

    default:
      status = PH_ADD_COMPCODE_FIXED(PH_ERR_INVALID_DATA_PARAMS, PH_COMP_AL_MFDFEVX);
      break;
  }

  PH_LOG_HELPER_ADDSTRING(PH_LOG_LOGTYPE_INFO, bFunctionName);
  PH_LOG_HELPER_ADDPARAM_BUFFER(PH_LOG_LOGTYPE_DEBUG, pFid_log, pFid, (*bNumFID));
  PH_LOG_HELPER_ADDPARAM_BUFFER(PH_LOG_LOGTYPE_DEBUG, bNumFID_log, bNumFID, 1);
  PH_LOG_HELPER_ADDPARAM_UINT16(PH_LOG_LOGTYPE_INFO, status_log, &status);
  PH_LOG_HELPER_EXECUTE(PH_LOG_OPTION_CATEGORY_LEAVE);

  return status;
}

phStatus_t phalMfdfEVx_GetISOFileIDs(void *pDataParams, uint8_t *pFidBuffer, uint8_t *pNumFID)
{
  phStatus_t PH_MEMLOC_REM status;

  PH_LOG_HELPER_ALLOCATE_TEXT(bFunctionName, "phalMfdfEVx_GetISOFileIDs");
  PH_LOG_HELPER_ALLOCATE_PARAMNAME(status);
  PH_LOG_HELPER_ALLOCATE_PARAMNAME(pFidBuffer);
  PH_LOG_HELPER_ALLOCATE_PARAMNAME(pNumFID);
  PH_LOG_HELPER_ADDSTRING(PH_LOG_LOGTYPE_INFO, bFunctionName);
  PH_LOG_HELPER_EXECUTE(PH_LOG_OPTION_CATEGORY_ENTER);

  /* Validate the parameters */
  PH_ASSERT_NULL_DATA_PARAM(pDataParams, PH_COMP_AL_MFDFEVX);
  PH_ASSERT_NULL_PARAM(pFidBuffer, PH_COMP_AL_MFDFEVX);
  PH_ASSERT_NULL_PARAM(pNumFID, PH_COMP_AL_MFDFEVX);

  /* Parameter validation */
  if (PH_GET_COMPCODE(pDataParams) != PH_COMP_AL_MFDFEVX) {
    PH_LOG_HELPER_ADDSTRING(PH_LOG_LOGTYPE_INFO, bFunctionName);
    PH_LOG_HELPER_ADDPARAM_UINT16(PH_LOG_LOGTYPE_INFO, status_log, &status);
    PH_LOG_HELPER_EXECUTE(PH_LOG_OPTION_CATEGORY_LEAVE);

    return PH_ADD_COMPCODE_FIXED(PH_ERR_INVALID_DATA_PARAMS, PH_COMP_AL_MFDFEVX);
  }

  /* Perform operation on active layer */
  switch (PH_GET_COMPID(pDataParams)) {
#ifdef NXPBUILD__PHAL_MFDFEVX_SW
    case PHAL_MFDFEVX_SW_ID:
      status = phalMfdfEVx_Sw_GetISOFileIDs((phalMfdfEVx_Sw_DataParams_t *) pDataParams, pFidBuffer,
              pNumFID);
      break;
#endif /* NXPBUILD__PHAL_MFDFEVX_SW */

    default:
      status = PH_ADD_COMPCODE_FIXED(PH_ERR_INVALID_DATA_PARAMS, PH_COMP_AL_MFDFEVX);
      break;
  }

  PH_LOG_HELPER_ADDSTRING(PH_LOG_LOGTYPE_INFO, bFunctionName);
  PH_LOG_HELPER_ADDPARAM_BUFFER(PH_LOG_LOGTYPE_DEBUG, pFidBuffer_log, pFidBuffer, (*pNumFID) * 2);
  PH_LOG_HELPER_ADDPARAM_BUFFER(PH_LOG_LOGTYPE_DEBUG, pNumFID_log, pNumFID, 1);
  PH_LOG_HELPER_ADDPARAM_UINT16(PH_LOG_LOGTYPE_INFO, status_log, &status);
  PH_LOG_HELPER_EXECUTE(PH_LOG_OPTION_CATEGORY_LEAVE);

  return status;
}

phStatus_t phalMfdfEVx_GetFileSettings(void *pDataParams, uint8_t bFileNo, uint8_t *pFSBuffer,
    uint8_t *bBufferLen)
{
  phStatus_t PH_MEMLOC_REM status;

  PH_LOG_HELPER_ALLOCATE_TEXT(bFunctionName, "phalMfdfEVx_GetFileSettings");
  PH_LOG_HELPER_ALLOCATE_PARAMNAME(status);
  PH_LOG_HELPER_ALLOCATE_PARAMNAME(bFileNo);
  PH_LOG_HELPER_ALLOCATE_PARAMNAME(pFSBuffer);
  PH_LOG_HELPER_ALLOCATE_PARAMNAME(bBufferLen);
  PH_LOG_HELPER_ADDSTRING(PH_LOG_LOGTYPE_INFO, bFunctionName);
  PH_LOG_HELPER_ADDPARAM_UINT8(PH_LOG_LOGTYPE_DEBUG, bFileNo_log, &bFileNo);
  PH_LOG_HELPER_EXECUTE(PH_LOG_OPTION_CATEGORY_ENTER);

  /* Validate the parameters */
  PH_ASSERT_NULL_DATA_PARAM(pDataParams, PH_COMP_AL_MFDFEVX);
  PH_ASSERT_NULL_PARAM(pFSBuffer, PH_COMP_AL_MFDFEVX);
  PH_ASSERT_NULL_PARAM(bBufferLen, PH_COMP_AL_MFDFEVX);

  /* Parameter validation */
  if (PH_GET_COMPCODE(pDataParams) != PH_COMP_AL_MFDFEVX) {
    PH_LOG_HELPER_ADDSTRING(PH_LOG_LOGTYPE_INFO, bFunctionName);
    PH_LOG_HELPER_ADDPARAM_UINT16(PH_LOG_LOGTYPE_INFO, status_log, &status);
    PH_LOG_HELPER_EXECUTE(PH_LOG_OPTION_CATEGORY_LEAVE);
    return PH_ADD_COMPCODE_FIXED(PH_ERR_INVALID_DATA_PARAMS, PH_COMP_AL_MFDFEVX);
  }

  /* Perform operation on active layer */
  switch (PH_GET_COMPID(pDataParams)) {
#ifdef NXPBUILD__PHAL_MFDFEVX_SW
    case PHAL_MFDFEVX_SW_ID:
      status = phalMfdfEVx_Sw_GetFileSettings((phalMfdfEVx_Sw_DataParams_t *) pDataParams, bFileNo,
              pFSBuffer, bBufferLen);
      break;
#endif /* NXPBUILD__PHAL_MFDFEVX_SW */

    default:
      status = PH_ADD_COMPCODE_FIXED(PH_ERR_INVALID_DATA_PARAMS, PH_COMP_AL_MFDFEVX);
      break;
  }

  PH_LOG_HELPER_ADDSTRING(PH_LOG_LOGTYPE_INFO, bFunctionName);
  PH_LOG_HELPER_ADDPARAM_BUFFER(PH_LOG_LOGTYPE_DEBUG, pFSBuffer_log, pFSBuffer, (*bBufferLen));
  PH_LOG_HELPER_ADDPARAM_BUFFER(PH_LOG_LOGTYPE_DEBUG, bBufferLen_log, bBufferLen, 1);
  PH_LOG_HELPER_ADDPARAM_UINT16(PH_LOG_LOGTYPE_INFO, status_log, &status);
  PH_LOG_HELPER_EXECUTE(PH_LOG_OPTION_CATEGORY_LEAVE);

  return status;
}

phStatus_t phalMfdfEVx_GetFileCounters(void *pDataParams, uint8_t bOption, uint8_t bFileNo,
    uint8_t *pFileCounters, uint8_t *pRxLen)
{
  phStatus_t PH_MEMLOC_REM status = 0;

  PH_LOG_HELPER_ALLOCATE_TEXT(bFunctionName, "phalMfdfEVx_GetFileCounters");
  PH_LOG_HELPER_ALLOCATE_PARAMNAME(bOption);
  PH_LOG_HELPER_ALLOCATE_PARAMNAME(bFileNo);
  PH_LOG_HELPER_ALLOCATE_PARAMNAME(pFileCounters);
  PH_LOG_HELPER_ALLOCATE_PARAMNAME(pRxLen);
  PH_LOG_HELPER_ALLOCATE_PARAMNAME(status);
  PH_LOG_HELPER_ADDSTRING(PH_LOG_LOGTYPE_INFO, bFunctionName);
  PH_LOG_HELPER_ADDPARAM_UINT8(PH_LOG_LOGTYPE_DEBUG, bOption_log, &bOption);
  PH_LOG_HELPER_ADDPARAM_UINT8(PH_LOG_LOGTYPE_DEBUG, bFileNo_log, &bFileNo);
  PH_LOG_HELPER_EXECUTE(PH_LOG_OPTION_CATEGORY_ENTER);

  /* Validate the parameters */
  PH_ASSERT_NULL_DATA_PARAM(pDataParams, PH_COMP_AL_MFDFEVX);

  /* Component Code Validation */
  if (PH_GET_COMPCODE(pDataParams) != PH_COMP_AL_MFDFEVX) {
    PH_LOG_HELPER_ADDSTRING(PH_LOG_LOGTYPE_INFO, bFunctionName);
    PH_LOG_HELPER_ADDPARAM_UINT16(PH_LOG_LOGTYPE_INFO, status_log, &status);
    PH_LOG_HELPER_EXECUTE(PH_LOG_OPTION_CATEGORY_LEAVE);
    return PH_ADD_COMPCODE_FIXED(PH_ERR_INVALID_DATA_PARAMS, PH_COMP_AL_MFDFEVX);
  }

  /* Perform operation on active layer */
  switch (PH_GET_COMPID(pDataParams)) {
#ifdef NXPBUILD__PHAL_MFDFEVX_SW
    case PHAL_MFDFEVX_SW_ID:
      status = phalMfdfEVx_Sw_GetFileCounters((phalMfdfEVx_Sw_DataParams_t *) pDataParams, bOption,
              bFileNo,
              pFileCounters, pRxLen);
      break;
#endif /* NXPBUILD__PHAL_MFDFEVX_SW */

    default:
      status = PH_ADD_COMPCODE_FIXED(PH_ERR_INVALID_DATA_PARAMS, PH_COMP_AL_MFDFEVX);
      break;
  }

  PH_LOG_HELPER_ADDSTRING(PH_LOG_LOGTYPE_INFO, bFunctionName);
#ifdef NXPBUILD__PH_LOG
  if ((status & PH_ERR_MASK) == PH_ERR_SUCCESS) {
    PH_LOG_HELPER_ADDPARAM_BUFFER(PH_LOG_LOGTYPE_DEBUG, pFileCounters_log, pFileCounters, (*pRxLen));
    PH_LOG_HELPER_ADDPARAM_BUFFER(PH_LOG_LOGTYPE_DEBUG, pRxLen_log, pRxLen, 1);
  }
#endif
  PH_LOG_HELPER_ADDPARAM_UINT16(PH_LOG_LOGTYPE_INFO, status_log, &status);
  PH_LOG_HELPER_EXECUTE(PH_LOG_OPTION_CATEGORY_LEAVE);

  return status;
}

phStatus_t phalMfdfEVx_ChangeFileSettings(void *pDataParams, uint8_t bOption, uint8_t bFileNo,
    uint8_t bFileOption, uint8_t *pAccessRights,
    uint8_t bAddInfoLen, uint8_t *pAddInfo)
{
  phStatus_t PH_MEMLOC_REM status;

  PH_LOG_HELPER_ALLOCATE_TEXT(bFunctionName, "phalMfdfEVx_ChangeFileSettings");
  PH_LOG_HELPER_ALLOCATE_PARAMNAME(status);
  PH_LOG_HELPER_ALLOCATE_PARAMNAME(bOption);
  PH_LOG_HELPER_ALLOCATE_PARAMNAME(bFileNo);
  PH_LOG_HELPER_ALLOCATE_PARAMNAME(bFileOption);
  PH_LOG_HELPER_ALLOCATE_PARAMNAME(pAccessRights);
  PH_LOG_HELPER_ALLOCATE_PARAMNAME(bAddInfoLen);
  PH_LOG_HELPER_ALLOCATE_PARAMNAME(pAddInfo);
  PH_LOG_HELPER_ADDSTRING(PH_LOG_LOGTYPE_INFO, bFunctionName);
  PH_LOG_HELPER_ADDPARAM_UINT8(PH_LOG_LOGTYPE_DEBUG, bOption_log, &bOption);
  PH_LOG_HELPER_ADDPARAM_UINT8(PH_LOG_LOGTYPE_DEBUG, bFileNo_log, &bFileNo);
  PH_LOG_HELPER_ADDPARAM_UINT8(PH_LOG_LOGTYPE_DEBUG, bFileOption_log, &bFileOption);
  PH_LOG_HELPER_ADDPARAM_UINT8(PH_LOG_LOGTYPE_DEBUG, bAddInfoLen_log, &bAddInfoLen);
  PH_LOG_HELPER_ADDPARAM_BUFFER(PH_LOG_LOGTYPE_DEBUG, pAccessRights_log, pAccessRights, 2);
  PH_LOG_HELPER_ADDPARAM_BUFFER(PH_LOG_LOGTYPE_DEBUG, pAddInfo_log, pAddInfo, bAddInfoLen);
  PH_LOG_HELPER_EXECUTE(PH_LOG_OPTION_CATEGORY_ENTER);

  /* Validate the parameters */
  PH_ASSERT_NULL_DATA_PARAM(pDataParams, PH_COMP_AL_MFDFEVX);
  PH_ASSERT_NULL_PARAM(pAccessRights, PH_COMP_AL_MFDFEVX);
  PH_ASSERT_NULL_PARAM(pAddInfo, PH_COMP_AL_MFDFEVX);

  /* Parameter validation */
  if (PH_GET_COMPCODE(pDataParams) != PH_COMP_AL_MFDFEVX) {
    PH_LOG_HELPER_ADDSTRING(PH_LOG_LOGTYPE_INFO, bFunctionName);
    PH_LOG_HELPER_ADDPARAM_UINT16(PH_LOG_LOGTYPE_INFO, status_log, &status);
    PH_LOG_HELPER_EXECUTE(PH_LOG_OPTION_CATEGORY_LEAVE);

    return PH_ADD_COMPCODE_FIXED(PH_ERR_INVALID_DATA_PARAMS, PH_COMP_AL_MFDFEVX);
  }

  /* Perform operation on active layer */
  switch (PH_GET_COMPID(pDataParams)) {
#ifdef NXPBUILD__PHAL_MFDFEVX_SW
    case PHAL_MFDFEVX_SW_ID:
      status = phalMfdfEVx_Sw_ChangeFileSettings((phalMfdfEVx_Sw_DataParams_t *) pDataParams, bOption,
              bFileNo,
              bFileOption, pAccessRights, bAddInfoLen, pAddInfo);
      break;
#endif /* NXPBUILD__PHAL_MFDFEVX_SW */

    default:
      status = PH_ADD_COMPCODE_FIXED(PH_ERR_INVALID_DATA_PARAMS, PH_COMP_AL_MFDFEVX);
      break;
  }

  PH_LOG_HELPER_ADDSTRING(PH_LOG_LOGTYPE_INFO, bFunctionName);
  PH_LOG_HELPER_ADDPARAM_UINT16(PH_LOG_LOGTYPE_INFO, status_log, &status);
  PH_LOG_HELPER_EXECUTE(PH_LOG_OPTION_CATEGORY_LEAVE);

  return status;
}

/* MIFARE DESFire EVX Data mamangement commands. --------------------------------------------------------------------------------------- */
phStatus_t phalMfdfEVx_ReadData(void *pDataParams, uint8_t bOption, uint8_t bIns, uint8_t bFileNo,
    uint8_t *pOffset, uint8_t *pLength,
    uint8_t **ppRxdata, uint16_t *pRxdataLen)
{
  phStatus_t PH_MEMLOC_REM status;

  PH_LOG_HELPER_ALLOCATE_TEXT(bFunctionName, "phalMfdfEVx_ReadData");
  PH_LOG_HELPER_ALLOCATE_PARAMNAME(status);
  PH_LOG_HELPER_ALLOCATE_PARAMNAME(bOption);
  PH_LOG_HELPER_ALLOCATE_PARAMNAME(bIns);
  PH_LOG_HELPER_ALLOCATE_PARAMNAME(bFileNo);
  PH_LOG_HELPER_ALLOCATE_PARAMNAME(pOffset);
  PH_LOG_HELPER_ALLOCATE_PARAMNAME(pLength);
  PH_LOG_HELPER_ALLOCATE_PARAMNAME(ppRxdata);
  PH_LOG_HELPER_ALLOCATE_PARAMNAME(pRxdataLen);
  PH_LOG_HELPER_ADDSTRING(PH_LOG_LOGTYPE_INFO, bFunctionName);
  PH_LOG_HELPER_ADDPARAM_UINT8(PH_LOG_LOGTYPE_DEBUG, bOption_log, &bOption);
  PH_LOG_HELPER_ADDPARAM_UINT8(PH_LOG_LOGTYPE_DEBUG, bIns_log, &bIns);
  PH_LOG_HELPER_ADDPARAM_UINT8(PH_LOG_LOGTYPE_DEBUG, bFileNo_log, &bFileNo);
  PH_LOG_HELPER_ADDPARAM_BUFFER(PH_LOG_LOGTYPE_DEBUG, pOffset_log, pOffset, 3);
  PH_LOG_HELPER_ADDPARAM_BUFFER(PH_LOG_LOGTYPE_DEBUG, pLength_log, pLength, 3);
  PH_LOG_HELPER_EXECUTE(PH_LOG_OPTION_CATEGORY_ENTER);

  /* Validate the parameters */
  PH_ASSERT_NULL_DATA_PARAM(pDataParams, PH_COMP_AL_MFDFEVX);
  PH_ASSERT_NULL_PARAM(pOffset, PH_COMP_AL_MFDFEVX);
  PH_ASSERT_NULL_PARAM(pLength, PH_COMP_AL_MFDFEVX);
  PH_ASSERT_NULL_PARAM(ppRxdata, PH_COMP_AL_MFDFEVX);
  PH_ASSERT_NULL_PARAM(pRxdataLen, PH_COMP_AL_MFDFEVX);

  /* Parameter validation */
  if (PH_GET_COMPCODE(pDataParams) != PH_COMP_AL_MFDFEVX) {
    PH_LOG_HELPER_ADDSTRING(PH_LOG_LOGTYPE_INFO, bFunctionName);
    PH_LOG_HELPER_ADDPARAM_UINT16(PH_LOG_LOGTYPE_INFO, status_log, &status);
    PH_LOG_HELPER_EXECUTE(PH_LOG_OPTION_CATEGORY_LEAVE);

    return PH_ADD_COMPCODE_FIXED(PH_ERR_INVALID_DATA_PARAMS, PH_COMP_AL_MFDFEVX);
  }

  /* Perform operation on active layer */
  switch (PH_GET_COMPID(pDataParams)) {
#ifdef NXPBUILD__PHAL_MFDFEVX_SW
    case PHAL_MFDFEVX_SW_ID:
      status = phalMfdfEVx_Sw_ReadData((phalMfdfEVx_Sw_DataParams_t *) pDataParams, bOption, bIns,
              bFileNo,
              pOffset, pLength, ppRxdata, pRxdataLen);
      break;
#endif /* NXPBUILD__PHAL_MFDFEVX_SW */

    default:
      status = PH_ADD_COMPCODE_FIXED(PH_ERR_INVALID_DATA_PARAMS, PH_COMP_AL_MFDFEVX);
      break;
  }

  PH_LOG_HELPER_ADDSTRING(PH_LOG_LOGTYPE_INFO, bFunctionName);
  if (*pRxdataLen != 0) {
    PH_LOG_HELPER_ADDPARAM_BUFFER(PH_LOG_LOGTYPE_DEBUG, ppRxdata_log, *ppRxdata, (*pRxdataLen));
  }
  PH_LOG_HELPER_ADDPARAM_UINT16(PH_LOG_LOGTYPE_INFO, pRxdataLen_log, pRxdataLen);
  PH_LOG_HELPER_ADDPARAM_UINT16(PH_LOG_LOGTYPE_INFO, status_log, &status);
  PH_LOG_HELPER_EXECUTE(PH_LOG_OPTION_CATEGORY_LEAVE);

  return status;
}

phStatus_t phalMfdfEVx_WriteData(void *pDataParams, uint8_t bOption, uint8_t bIns,
    uint8_t bFileNo, uint8_t *pOffset, uint8_t *pTxData,
    uint8_t *pTxDataLen)
{
  phStatus_t  PH_MEMLOC_REM status;
  uint16_t    PH_MEMLOC_REM wDataLen;

  PH_LOG_HELPER_ALLOCATE_TEXT(bFunctionName, "phalMfdfEVx_WriteData");
  PH_LOG_HELPER_ALLOCATE_PARAMNAME(status);
  PH_LOG_HELPER_ALLOCATE_PARAMNAME(bOption);
  PH_LOG_HELPER_ALLOCATE_PARAMNAME(bIns);
  PH_LOG_HELPER_ALLOCATE_PARAMNAME(bFileNo);
  PH_LOG_HELPER_ALLOCATE_PARAMNAME(pOffset);
  PH_LOG_HELPER_ALLOCATE_PARAMNAME(pTxData);
  PH_LOG_HELPER_ALLOCATE_PARAMNAME(pTxDataLen);
  PH_LOG_HELPER_ADDSTRING(PH_LOG_LOGTYPE_INFO, bFunctionName);
  PH_LOG_HELPER_ADDPARAM_UINT8(PH_LOG_LOGTYPE_DEBUG, bOption_log, &bOption);
  PH_LOG_HELPER_ADDPARAM_UINT8(PH_LOG_LOGTYPE_DEBUG, bIns_log, &bIns);
  PH_LOG_HELPER_ADDPARAM_UINT8(PH_LOG_LOGTYPE_DEBUG, bFileNo_log, &bFileNo);
  PH_LOG_HELPER_ADDPARAM_BUFFER(PH_LOG_LOGTYPE_DEBUG, pOffset_log, pOffset, 3);

  wDataLen = (uint16_t) pTxDataLen[1];
  wDataLen = wDataLen << 8;
  wDataLen |= pTxDataLen[0];

  PH_LOG_HELPER_ADDPARAM_BUFFER(PH_LOG_LOGTYPE_DEBUG, pTxData_log, pTxData, wDataLen);
  PH_LOG_HELPER_ADDPARAM_BUFFER(PH_LOG_LOGTYPE_DEBUG, pTxDataLen_log, pTxDataLen, 3);
  PH_LOG_HELPER_EXECUTE(PH_LOG_OPTION_CATEGORY_ENTER);

  /* Validate the parameters */
  PH_ASSERT_NULL_DATA_PARAM(pDataParams, PH_COMP_AL_MFDFEVX);
  PH_ASSERT_NULL_PARAM(pOffset, PH_COMP_AL_MFDFEVX);
  PH_ASSERT_NULL_PARAM(pTxData, PH_COMP_AL_MFDFEVX);
  PH_ASSERT_NULL_PARAM(pTxDataLen, PH_COMP_AL_MFDFEVX);

  /* Parameter validation */
  if (PH_GET_COMPCODE(pDataParams) != PH_COMP_AL_MFDFEVX) {
    PH_LOG_HELPER_ADDSTRING(PH_LOG_LOGTYPE_INFO, bFunctionName);
    PH_LOG_HELPER_ADDPARAM_UINT16(PH_LOG_LOGTYPE_INFO, status_log, &status);
    PH_LOG_HELPER_EXECUTE(PH_LOG_OPTION_CATEGORY_LEAVE);

    return PH_ADD_COMPCODE_FIXED(PH_ERR_INVALID_DATA_PARAMS, PH_COMP_AL_MFDFEVX);
  }

  /* Perform operation on active layer */
  switch (PH_GET_COMPID(pDataParams)) {
#ifdef NXPBUILD__PHAL_MFDFEVX_SW
    case PHAL_MFDFEVX_SW_ID:
      status = phalMfdfEVx_Sw_WriteData((phalMfdfEVx_Sw_DataParams_t *) pDataParams, bOption, bIns,
              bFileNo,
              pOffset, pTxData, pTxDataLen);
      break;
#endif /* NXPBUILD__PHAL_MFDFEVX_SW */

    default:
      status = PH_ADD_COMPCODE_FIXED(PH_ERR_INVALID_DATA_PARAMS, PH_COMP_AL_MFDFEVX);
      break;
  }

  PH_LOG_HELPER_ADDSTRING(PH_LOG_LOGTYPE_INFO, bFunctionName);
  PH_LOG_HELPER_ADDPARAM_UINT16(PH_LOG_LOGTYPE_INFO, status_log, &status);
  PH_LOG_HELPER_EXECUTE(PH_LOG_OPTION_CATEGORY_LEAVE);

  return status;
}

phStatus_t phalMfdfEVx_GetValue(void *pDataParams, uint8_t bOption, uint8_t bFileNo,
    uint8_t *pValue)
{
  phStatus_t PH_MEMLOC_REM status;

  PH_LOG_HELPER_ALLOCATE_TEXT(bFunctionName, "phalMfdfEVx_GetValue");
  PH_LOG_HELPER_ALLOCATE_PARAMNAME(bOption);
  PH_LOG_HELPER_ALLOCATE_PARAMNAME(bFileNo);
  PH_LOG_HELPER_ALLOCATE_PARAMNAME(pValue);
  PH_LOG_HELPER_ALLOCATE_PARAMNAME(status);
  PH_LOG_HELPER_ADDSTRING(PH_LOG_LOGTYPE_INFO, bFunctionName);
  PH_LOG_HELPER_ADDPARAM_UINT8(PH_LOG_LOGTYPE_DEBUG, bOption_log, &bOption);
  PH_LOG_HELPER_ADDPARAM_UINT8(PH_LOG_LOGTYPE_DEBUG, bFileNo_log, &bFileNo);
  PH_LOG_HELPER_EXECUTE(PH_LOG_OPTION_CATEGORY_ENTER);

  /* Validate the parameters */
  PH_ASSERT_NULL_DATA_PARAM(pDataParams, PH_COMP_AL_MFDFEVX);
  PH_ASSERT_NULL_PARAM(pValue, PH_COMP_AL_MFDFEVX);

  /* Parameter validation */
  if (PH_GET_COMPCODE(pDataParams) != PH_COMP_AL_MFDFEVX) {
    PH_LOG_HELPER_ADDSTRING(PH_LOG_LOGTYPE_INFO, bFunctionName);
    PH_LOG_HELPER_ADDPARAM_UINT16(PH_LOG_LOGTYPE_INFO, status_log, &status);
    PH_LOG_HELPER_EXECUTE(PH_LOG_OPTION_CATEGORY_LEAVE);

    return PH_ADD_COMPCODE_FIXED(PH_ERR_INVALID_DATA_PARAMS, PH_COMP_AL_MFDFEVX);
  }

  /* Perform operation on active layer */
  switch (PH_GET_COMPID(pDataParams)) {
#ifdef NXPBUILD__PHAL_MFDFEVX_SW
    case PHAL_MFDFEVX_SW_ID:
      status = phalMfdfEVx_Sw_GetValue((phalMfdfEVx_Sw_DataParams_t *) pDataParams, bOption, bFileNo,
              pValue);
      break;
#endif /* NXPBUILD__PHAL_MFDFEVX_SW */

    default:
      status = PH_ADD_COMPCODE_FIXED(PH_ERR_INVALID_DATA_PARAMS, PH_COMP_AL_MFDFEVX);
      break;
  }

  PH_LOG_HELPER_ADDSTRING(PH_LOG_LOGTYPE_INFO, bFunctionName);
  PH_LOG_HELPER_ADDPARAM_BUFFER(PH_LOG_LOGTYPE_DEBUG, pValue_log, pValue, 4);
  PH_LOG_HELPER_ADDPARAM_UINT16(PH_LOG_LOGTYPE_INFO, status_log, &status);
  PH_LOG_HELPER_EXECUTE(PH_LOG_OPTION_CATEGORY_LEAVE);

  return status;
}

phStatus_t phalMfdfEVx_Credit(void *pDataParams, uint8_t bOption, uint8_t bFileNo,
    uint8_t *pValue)
{
  phStatus_t PH_MEMLOC_REM status;

  PH_LOG_HELPER_ALLOCATE_TEXT(bFunctionName, "phalMfdfEVx_Credit");
  PH_LOG_HELPER_ALLOCATE_PARAMNAME(bOption);
  PH_LOG_HELPER_ALLOCATE_PARAMNAME(bFileNo);
  PH_LOG_HELPER_ALLOCATE_PARAMNAME(pValue);
  PH_LOG_HELPER_ALLOCATE_PARAMNAME(status);
  PH_LOG_HELPER_ADDSTRING(PH_LOG_LOGTYPE_INFO, bFunctionName);
  PH_LOG_HELPER_ADDPARAM_UINT8(PH_LOG_LOGTYPE_DEBUG, bOption_log, &bOption);
  PH_LOG_HELPER_ADDPARAM_UINT8(PH_LOG_LOGTYPE_DEBUG, bFileNo_log, &bFileNo);
  PH_LOG_HELPER_EXECUTE(PH_LOG_OPTION_CATEGORY_ENTER);

  /* Validate the parameters */
  PH_ASSERT_NULL_DATA_PARAM(pDataParams, PH_COMP_AL_MFDFEVX);
  PH_ASSERT_NULL_PARAM(pValue, PH_COMP_AL_MFDFEVX);

  /* Parameter validation */
  if (PH_GET_COMPCODE(pDataParams) != PH_COMP_AL_MFDFEVX) {
    PH_LOG_HELPER_ADDSTRING(PH_LOG_LOGTYPE_INFO, bFunctionName);
    PH_LOG_HELPER_ADDPARAM_UINT16(PH_LOG_LOGTYPE_INFO, status_log, &status);
    PH_LOG_HELPER_EXECUTE(PH_LOG_OPTION_CATEGORY_LEAVE);

    return PH_ADD_COMPCODE_FIXED(PH_ERR_INVALID_DATA_PARAMS, PH_COMP_AL_MFDFEVX);
  }

  /* Perform operation on active layer */
  switch (PH_GET_COMPID(pDataParams)) {
#ifdef NXPBUILD__PHAL_MFDFEVX_SW
    case PHAL_MFDFEVX_SW_ID:
      status = phalMfdfEVx_Sw_Credit((phalMfdfEVx_Sw_DataParams_t *) pDataParams, bOption, bFileNo,
              pValue);
      break;
#endif /* NXPBUILD__PHAL_MFDFEVX_SW */

    default:
      status = PH_ADD_COMPCODE_FIXED(PH_ERR_INVALID_DATA_PARAMS, PH_COMP_AL_MFDFEVX);
      break;
  }

  PH_LOG_HELPER_ADDSTRING(PH_LOG_LOGTYPE_INFO, bFunctionName);
  PH_LOG_HELPER_ADDPARAM_BUFFER(PH_LOG_LOGTYPE_DEBUG, pValue_log, pValue, 4);
  PH_LOG_HELPER_ADDPARAM_UINT16(PH_LOG_LOGTYPE_INFO, status_log, &status);
  PH_LOG_HELPER_EXECUTE(PH_LOG_OPTION_CATEGORY_LEAVE);
  return status;

}

phStatus_t phalMfdfEVx_Debit(void *pDataParams, uint8_t bCommOption, uint8_t bFileNo,
    uint8_t *pValue)
{
  phStatus_t PH_MEMLOC_REM status;

  PH_LOG_HELPER_ALLOCATE_TEXT(bFunctionName, "phalMfdfEVx_Debit");
  PH_LOG_HELPER_ALLOCATE_PARAMNAME(bCommOption);
  PH_LOG_HELPER_ALLOCATE_PARAMNAME(bFileNo);
  PH_LOG_HELPER_ALLOCATE_PARAMNAME(pValue);
  PH_LOG_HELPER_ALLOCATE_PARAMNAME(status);
  PH_LOG_HELPER_ADDSTRING(PH_LOG_LOGTYPE_INFO, bFunctionName);
  PH_LOG_HELPER_ADDPARAM_UINT8(PH_LOG_LOGTYPE_DEBUG, bCommOption_log, &bCommOption);
  PH_LOG_HELPER_ADDPARAM_UINT8(PH_LOG_LOGTYPE_DEBUG, bFileNo_log, &bFileNo);
  PH_LOG_HELPER_EXECUTE(PH_LOG_OPTION_CATEGORY_ENTER);

  /* Validate the parameters */
  PH_ASSERT_NULL_DATA_PARAM(pDataParams, PH_COMP_AL_MFDFEVX);
  PH_ASSERT_NULL_PARAM(pValue, PH_COMP_AL_MFDFEVX);

  /* Parameter validation */
  if (PH_GET_COMPCODE(pDataParams) != PH_COMP_AL_MFDFEVX) {
    PH_LOG_HELPER_ADDSTRING(PH_LOG_LOGTYPE_INFO, bFunctionName);
    PH_LOG_HELPER_ADDPARAM_UINT16(PH_LOG_LOGTYPE_INFO, status_log, &status);
    PH_LOG_HELPER_EXECUTE(PH_LOG_OPTION_CATEGORY_LEAVE);

    return PH_ADD_COMPCODE_FIXED(PH_ERR_INVALID_DATA_PARAMS, PH_COMP_AL_MFDFEVX);
  }

  /* Perform operation on active layer */
  switch (PH_GET_COMPID(pDataParams)) {
#ifdef NXPBUILD__PHAL_MFDFEVX_SW
    case PHAL_MFDFEVX_SW_ID:
      status = phalMfdfEVx_Sw_Debit((phalMfdfEVx_Sw_DataParams_t *) pDataParams, bCommOption, bFileNo,
              pValue);
      break;
#endif /* NXPBUILD__PHAL_MFDFEVX_SW */

    default:
      status = PH_ADD_COMPCODE_FIXED(PH_ERR_INVALID_DATA_PARAMS, PH_COMP_AL_MFDFEVX);
      break;
  }

  PH_LOG_HELPER_ADDSTRING(PH_LOG_LOGTYPE_INFO, bFunctionName);
  PH_LOG_HELPER_ADDPARAM_BUFFER(PH_LOG_LOGTYPE_DEBUG, pValue_log, pValue, 4);
  PH_LOG_HELPER_ADDPARAM_UINT16(PH_LOG_LOGTYPE_INFO, status_log, &status);
  PH_LOG_HELPER_EXECUTE(PH_LOG_OPTION_CATEGORY_LEAVE);

  return status;
}

phStatus_t phalMfdfEVx_LimitedCredit(void *pDataParams, uint8_t bCommOption, uint8_t bFileNo,
    uint8_t *pValue)
{
  phStatus_t PH_MEMLOC_REM status;

  PH_LOG_HELPER_ALLOCATE_TEXT(bFunctionName, "phalMfdfEVx_LimitedCredit");
  PH_LOG_HELPER_ALLOCATE_PARAMNAME(bCommOption);
  PH_LOG_HELPER_ALLOCATE_PARAMNAME(bFileNo);
  PH_LOG_HELPER_ALLOCATE_PARAMNAME(pValue);
  PH_LOG_HELPER_ALLOCATE_PARAMNAME(status);
  PH_LOG_HELPER_ADDSTRING(PH_LOG_LOGTYPE_INFO, bFunctionName);
  PH_LOG_HELPER_ADDPARAM_UINT8(PH_LOG_LOGTYPE_DEBUG, bCommOption_log, &bCommOption);
  PH_LOG_HELPER_ADDPARAM_UINT8(PH_LOG_LOGTYPE_DEBUG, bFileNo_log, &bFileNo);
  PH_LOG_HELPER_ADDPARAM_BUFFER(PH_LOG_LOGTYPE_DEBUG, pValue_log, pValue, 4);
  PH_LOG_HELPER_EXECUTE(PH_LOG_OPTION_CATEGORY_ENTER);

  /* Validate the parameters */
  PH_ASSERT_NULL_DATA_PARAM(pDataParams, PH_COMP_AL_MFDFEVX);
  PH_ASSERT_NULL_PARAM(pValue, PH_COMP_AL_MFDFEVX);

  /* Parameter validation */
  if (PH_GET_COMPCODE(pDataParams) != PH_COMP_AL_MFDFEVX) {
    PH_LOG_HELPER_ADDSTRING(PH_LOG_LOGTYPE_INFO, bFunctionName);
    PH_LOG_HELPER_ADDPARAM_UINT16(PH_LOG_LOGTYPE_INFO, status_log, &status);
    PH_LOG_HELPER_EXECUTE(PH_LOG_OPTION_CATEGORY_LEAVE);

    return PH_ADD_COMPCODE_FIXED(PH_ERR_INVALID_DATA_PARAMS, PH_COMP_AL_MFDFEVX);
  }

  /* Perform operation on active layer */
  switch (PH_GET_COMPID(pDataParams)) {
#ifdef NXPBUILD__PHAL_MFDFEVX_SW
    case PHAL_MFDFEVX_SW_ID:
      status = phalMfdfEVx_Sw_LimitedCredit((phalMfdfEVx_Sw_DataParams_t *) pDataParams, bCommOption,
              bFileNo, pValue);
      break;
#endif /* NXPBUILD__PHAL_MFDFEVX_SW */

    default:
      status = PH_ADD_COMPCODE_FIXED(PH_ERR_INVALID_DATA_PARAMS, PH_COMP_AL_MFDFEVX);
      break;
  }

  PH_LOG_HELPER_ADDSTRING(PH_LOG_LOGTYPE_INFO, bFunctionName);
  PH_LOG_HELPER_ADDPARAM_UINT16(PH_LOG_LOGTYPE_INFO, status_log, &status);
  PH_LOG_HELPER_EXECUTE(PH_LOG_OPTION_CATEGORY_LEAVE);

  return status;
}

phStatus_t phalMfdfEVx_WriteRecord(void *pDataParams, uint8_t bCommOption, uint8_t bIns,
    uint8_t bFileNo, uint8_t *pOffset, uint8_t *pData,
    uint8_t *pDataLen)
{
  phStatus_t  PH_MEMLOC_REM status;
  uint16_t    PH_MEMLOC_REM wDataLen;

  PH_LOG_HELPER_ALLOCATE_TEXT(bFunctionName, "phalMfdfEVx_WriteRecord");
  PH_LOG_HELPER_ALLOCATE_PARAMNAME(bCommOption);
  PH_LOG_HELPER_ALLOCATE_PARAMNAME(bIns);
  PH_LOG_HELPER_ALLOCATE_PARAMNAME(bFileNo);
  PH_LOG_HELPER_ALLOCATE_PARAMNAME(pOffset);
  PH_LOG_HELPER_ALLOCATE_PARAMNAME(pData);
  PH_LOG_HELPER_ALLOCATE_PARAMNAME(pDataLen);
  PH_LOG_HELPER_ALLOCATE_PARAMNAME(status);

  PH_LOG_HELPER_ADDSTRING(PH_LOG_LOGTYPE_INFO, bFunctionName);
  PH_LOG_HELPER_ADDPARAM_UINT8(PH_LOG_LOGTYPE_DEBUG, bCommOption_log, &bCommOption);
  PH_LOG_HELPER_ADDPARAM_UINT8(PH_LOG_LOGTYPE_DEBUG, bIns_log, &bIns);
  PH_LOG_HELPER_ADDPARAM_UINT8(PH_LOG_LOGTYPE_DEBUG, bFileNo_log, &bFileNo);
  PH_LOG_HELPER_ADDPARAM_BUFFER(PH_LOG_LOGTYPE_DEBUG, pOffset_log, pOffset, 3);

  wDataLen = (uint16_t) pDataLen[1];
  wDataLen = wDataLen << 8;
  wDataLen |= pDataLen[0];

  PH_LOG_HELPER_ADDPARAM_BUFFER(PH_LOG_LOGTYPE_DEBUG, pData_log, pData, wDataLen);
  PH_LOG_HELPER_ADDPARAM_BUFFER(PH_LOG_LOGTYPE_DEBUG, pDataLen_log, pDataLen, 3);
  PH_LOG_HELPER_EXECUTE(PH_LOG_OPTION_CATEGORY_ENTER);

  /* Validate the parameters */
  PH_ASSERT_NULL_DATA_PARAM(pDataParams, PH_COMP_AL_MFDFEVX);
  PH_ASSERT_NULL_PARAM(pOffset, PH_COMP_AL_MFDFEVX);
  PH_ASSERT_NULL_PARAM(pData, PH_COMP_AL_MFDFEVX);
  PH_ASSERT_NULL_PARAM(pDataLen, PH_COMP_AL_MFDFEVX);

  /* Parameter validation */
  if (PH_GET_COMPCODE(pDataParams) != PH_COMP_AL_MFDFEVX) {
    PH_LOG_HELPER_ADDSTRING(PH_LOG_LOGTYPE_INFO, bFunctionName);
    PH_LOG_HELPER_ADDPARAM_UINT16(PH_LOG_LOGTYPE_INFO, status_log, &status);
    PH_LOG_HELPER_EXECUTE(PH_LOG_OPTION_CATEGORY_LEAVE);

    return PH_ADD_COMPCODE_FIXED(PH_ERR_INVALID_DATA_PARAMS, PH_COMP_AL_MFDFEVX);
  }

  /* Perform operation on active layer */
  switch (PH_GET_COMPID(pDataParams)) {
#ifdef NXPBUILD__PHAL_MFDFEVX_SW
    case PHAL_MFDFEVX_SW_ID:
      status = phalMfdfEVx_Sw_WriteRecord((phalMfdfEVx_Sw_DataParams_t *) pDataParams, bCommOption,
              bIns, bFileNo, pOffset, pData, pDataLen);
      break;
#endif /* NXPBUILD__PHAL_MFDFEVX_SW */

    default:
      status = PH_ADD_COMPCODE_FIXED(PH_ERR_INVALID_DATA_PARAMS, PH_COMP_AL_MFDFEVX);
      break;
  }

  PH_LOG_HELPER_ADDSTRING(PH_LOG_LOGTYPE_INFO, bFunctionName);
  PH_LOG_HELPER_ADDPARAM_UINT16(PH_LOG_LOGTYPE_INFO, status_log, &status);
  PH_LOG_HELPER_EXECUTE(PH_LOG_OPTION_CATEGORY_LEAVE);

  return status;
}

phStatus_t phalMfdfEVx_ReadRecords(void *pDataParams, uint8_t bCommOption, uint8_t bIns,
    uint8_t bFileNo, uint8_t *pRecNo, uint8_t *pRecCount,
    uint8_t *pRecSize, uint8_t **ppRxdata, uint16_t *pRxdataLen)
{
  phStatus_t PH_MEMLOC_REM status;

  PH_LOG_HELPER_ALLOCATE_TEXT(bFunctionName, "phalMfdfEVx_ReadRecords");
  PH_LOG_HELPER_ALLOCATE_PARAMNAME(status);
  PH_LOG_HELPER_ALLOCATE_PARAMNAME(bCommOption);
  PH_LOG_HELPER_ALLOCATE_PARAMNAME(bIns);
  PH_LOG_HELPER_ALLOCATE_PARAMNAME(bFileNo);
  PH_LOG_HELPER_ALLOCATE_PARAMNAME(pRecNo);
  PH_LOG_HELPER_ALLOCATE_PARAMNAME(pRecCount);
  PH_LOG_HELPER_ALLOCATE_PARAMNAME(pRecSize);
  PH_LOG_HELPER_ALLOCATE_PARAMNAME(ppRxdata);
  PH_LOG_HELPER_ALLOCATE_PARAMNAME(pRxdataLen);
  PH_LOG_HELPER_ADDSTRING(PH_LOG_LOGTYPE_INFO, bFunctionName);
  PH_LOG_HELPER_ADDPARAM_UINT8(PH_LOG_LOGTYPE_DEBUG, bCommOption_log, &bCommOption);
  PH_LOG_HELPER_ADDPARAM_UINT8(PH_LOG_LOGTYPE_DEBUG, bIns_log, &bIns);
  PH_LOG_HELPER_ADDPARAM_UINT8(PH_LOG_LOGTYPE_DEBUG, bFileNo_log, &bFileNo);
  PH_LOG_HELPER_ADDPARAM_BUFFER(PH_LOG_LOGTYPE_DEBUG, pRecNo_log, pRecNo, 3);
  PH_LOG_HELPER_ADDPARAM_BUFFER(PH_LOG_LOGTYPE_DEBUG, pRecCount_log, pRecCount, 3);
  PH_LOG_HELPER_ADDPARAM_BUFFER(PH_LOG_LOGTYPE_DEBUG, pRecSize_log, pRecSize, 3);
  PH_LOG_HELPER_EXECUTE(PH_LOG_OPTION_CATEGORY_ENTER);

  /* Validate the parameters */
  PH_ASSERT_NULL_DATA_PARAM(pDataParams, PH_COMP_AL_MFDFEVX);
  PH_ASSERT_NULL_PARAM(pRecNo, PH_COMP_AL_MFDFEVX);
  PH_ASSERT_NULL_PARAM(pRecCount, PH_COMP_AL_MFDFEVX);
  PH_ASSERT_NULL_PARAM(ppRxdata, PH_COMP_AL_MFDFEVX);
  PH_ASSERT_NULL_PARAM(pRxdataLen, PH_COMP_AL_MFDFEVX);
  PH_ASSERT_NULL_PARAM(pRecSize, PH_COMP_AL_MFDFEVX);

  if (PH_GET_COMPCODE(pDataParams) != PH_COMP_AL_MFDFEVX) {
    PH_LOG_HELPER_ADDSTRING(PH_LOG_LOGTYPE_INFO, bFunctionName);
    PH_LOG_HELPER_ADDPARAM_UINT16(PH_LOG_LOGTYPE_INFO, status_log, &status);
    PH_LOG_HELPER_EXECUTE(PH_LOG_OPTION_CATEGORY_LEAVE);

    return PH_ADD_COMPCODE_FIXED(PH_ERR_INVALID_DATA_PARAMS, PH_COMP_AL_MFDFEVX);
  }

  /* Perform operation on active layer */
  switch (PH_GET_COMPID(pDataParams)) {
#ifdef NXPBUILD__PHAL_MFDFEVX_SW
    case PHAL_MFDFEVX_SW_ID:
      status = phalMfdfEVx_Sw_ReadRecords((phalMfdfEVx_Sw_DataParams_t *) pDataParams, bCommOption,
              bIns, bFileNo, pRecNo,
              pRecCount, pRecSize, ppRxdata, pRxdataLen);
      break;
#endif /* NXPBUILD__PHAL_MFDFEVX_SW */

    default:
      status = PH_ADD_COMPCODE_FIXED(PH_ERR_INVALID_DATA_PARAMS, PH_COMP_AL_MFDFEVX);
      break;
  }

  PH_LOG_HELPER_ADDSTRING(PH_LOG_LOGTYPE_INFO, bFunctionName);
  if (*pRxdataLen != 0) {
    PH_LOG_HELPER_ADDPARAM_BUFFER(PH_LOG_LOGTYPE_DEBUG, ppRxdata_log, *ppRxdata, (*pRxdataLen));
    PH_LOG_HELPER_ADDPARAM_UINT16(PH_LOG_LOGTYPE_DEBUG, pRxdataLen_log, pRxdataLen);
  }
  PH_LOG_HELPER_ADDPARAM_UINT16(PH_LOG_LOGTYPE_INFO, status_log, &status);
  PH_LOG_HELPER_EXECUTE(PH_LOG_OPTION_CATEGORY_LEAVE);

  return status;
}

phStatus_t phalMfdfEVx_UpdateRecord(void *pDataParams, uint8_t bCommOption, uint8_t bIns,
    uint8_t bFileNo, uint8_t *pRecNo, uint8_t *pOffset,
    uint8_t *pData, uint8_t *pDataLen)
{
  phStatus_t PH_MEMLOC_REM status;
  uint16_t    PH_MEMLOC_REM wDataLen;

  PH_LOG_HELPER_ALLOCATE_TEXT(bFunctionName, "phalMfdfEVx_UpdateRecord");
  PH_LOG_HELPER_ALLOCATE_PARAMNAME(status);
  PH_LOG_HELPER_ALLOCATE_PARAMNAME(bCommOption);
  PH_LOG_HELPER_ALLOCATE_PARAMNAME(bIns);
  PH_LOG_HELPER_ALLOCATE_PARAMNAME(bFileNo);
  PH_LOG_HELPER_ALLOCATE_PARAMNAME(pRecNo);
  PH_LOG_HELPER_ALLOCATE_PARAMNAME(pOffset);
  PH_LOG_HELPER_ALLOCATE_PARAMNAME(pData);
  PH_LOG_HELPER_ALLOCATE_PARAMNAME(pDataLen);
  PH_LOG_HELPER_ADDSTRING(PH_LOG_LOGTYPE_INFO, bFunctionName);
  PH_LOG_HELPER_ADDPARAM_UINT8(PH_LOG_LOGTYPE_DEBUG, bCommOption_log, &bCommOption);
  PH_LOG_HELPER_ADDPARAM_UINT8(PH_LOG_LOGTYPE_DEBUG, bIns_log, &bIns);
  PH_LOG_HELPER_ADDPARAM_UINT8(PH_LOG_LOGTYPE_DEBUG, bFileNo_log, &bFileNo);
  PH_LOG_HELPER_ADDPARAM_BUFFER(PH_LOG_LOGTYPE_DEBUG, pRecNo_log, pRecNo, 3);
  PH_LOG_HELPER_ADDPARAM_BUFFER(PH_LOG_LOGTYPE_DEBUG, pOffset_log, pOffset, 3);
  PH_LOG_HELPER_EXECUTE(PH_LOG_OPTION_CATEGORY_ENTER);

  wDataLen = (uint16_t) pDataLen[1];
  wDataLen = wDataLen << 8;
  wDataLen |= pDataLen[0];

  PH_LOG_HELPER_ADDPARAM_BUFFER(PH_LOG_LOGTYPE_DEBUG, pData_log, pData, wDataLen);
  PH_LOG_HELPER_ADDPARAM_BUFFER(PH_LOG_LOGTYPE_DEBUG, pDataLen_log, pDataLen, 3);
  PH_LOG_HELPER_EXECUTE(PH_LOG_OPTION_CATEGORY_ENTER);

  /* Validate the parameters */
  PH_ASSERT_NULL_DATA_PARAM(pDataParams, PH_COMP_AL_MFDFEVX);
  PH_ASSERT_NULL_PARAM(pOffset, PH_COMP_AL_MFDFEVX);
  PH_ASSERT_NULL_PARAM(pData, PH_COMP_AL_MFDFEVX);
  PH_ASSERT_NULL_PARAM(pDataLen, PH_COMP_AL_MFDFEVX);

  if (PH_GET_COMPCODE(pDataParams) != PH_COMP_AL_MFDFEVX) {
    PH_LOG_HELPER_ADDSTRING(PH_LOG_LOGTYPE_INFO, bFunctionName);
    PH_LOG_HELPER_ADDPARAM_UINT16(PH_LOG_LOGTYPE_INFO, status_log, &status);
    PH_LOG_HELPER_EXECUTE(PH_LOG_OPTION_CATEGORY_LEAVE);

    return PH_ADD_COMPCODE_FIXED(PH_ERR_INVALID_DATA_PARAMS, PH_COMP_AL_MFDFEVX);
  }

  /* Perform operation on active layer */
  switch (PH_GET_COMPID(pDataParams)) {
#ifdef NXPBUILD__PHAL_MFDFEVX_SW
    case PHAL_MFDFEVX_SW_ID:
      status = phalMfdfEVx_Sw_UpdateRecord((phalMfdfEVx_Sw_DataParams_t *) pDataParams, bCommOption,
              bIns,
              bFileNo, pRecNo, pOffset, pData, pDataLen);
      break;
#endif /* NXPBUILD__PHAL_MFDFEVX_SW */

    default:
      status = PH_ADD_COMPCODE_FIXED(PH_ERR_INVALID_DATA_PARAMS, PH_COMP_AL_MFDFEVX);
      break;
  }

  PH_LOG_HELPER_ADDSTRING(PH_LOG_LOGTYPE_INFO, bFunctionName);
  PH_LOG_HELPER_ADDPARAM_UINT16(PH_LOG_LOGTYPE_INFO, status_log, &status);
  PH_LOG_HELPER_EXECUTE(PH_LOG_OPTION_CATEGORY_LEAVE);

  return status;
}

phStatus_t phalMfdfEVx_ClearRecordFile(void *pDataParams, uint8_t bFileNo)
{
  phStatus_t PH_MEMLOC_REM status;

  PH_LOG_HELPER_ALLOCATE_TEXT(bFunctionName, "phalMfdfEVx_ClearRecordFile");
  PH_LOG_HELPER_ALLOCATE_PARAMNAME(status);
  PH_LOG_HELPER_ALLOCATE_PARAMNAME(bFileNo);
  PH_LOG_HELPER_ADDSTRING(PH_LOG_LOGTYPE_INFO, bFunctionName);
  PH_LOG_HELPER_ADDPARAM_UINT8(PH_LOG_LOGTYPE_DEBUG, bFileNo_log, &bFileNo);
  PH_LOG_HELPER_EXECUTE(PH_LOG_OPTION_CATEGORY_ENTER);

  /* Validate the parameters */
  PH_ASSERT_NULL_DATA_PARAM(pDataParams, PH_COMP_AL_MFDFEVX);

  /* Parameter validation */
  if (PH_GET_COMPCODE(pDataParams) != PH_COMP_AL_MFDFEVX) {
    PH_LOG_HELPER_ADDSTRING(PH_LOG_LOGTYPE_INFO, bFunctionName);
    PH_LOG_HELPER_ADDPARAM_UINT16(PH_LOG_LOGTYPE_INFO, status_log, &status);
    PH_LOG_HELPER_EXECUTE(PH_LOG_OPTION_CATEGORY_LEAVE);

    return PH_ADD_COMPCODE_FIXED(PH_ERR_INVALID_DATA_PARAMS, PH_COMP_AL_MFDFEVX);
  }

  /* Perform operation on active layer */
  switch (PH_GET_COMPID(pDataParams)) {
#ifdef NXPBUILD__PHAL_MFDFEVX_SW
    case PHAL_MFDFEVX_SW_ID:
      status = phalMfdfEVx_Sw_ClearRecordFile((phalMfdfEVx_Sw_DataParams_t *) pDataParams, bFileNo);
      break;
#endif /* NXPBUILD__PHAL_MFDFEVX_SW */

    default:
      status = PH_ADD_COMPCODE_FIXED(PH_ERR_INVALID_DATA_PARAMS, PH_COMP_AL_MFDFEVX);
      break;
  }

  PH_LOG_HELPER_ADDSTRING(PH_LOG_LOGTYPE_INFO, bFunctionName);
  PH_LOG_HELPER_ADDPARAM_UINT16(PH_LOG_LOGTYPE_INFO, status_log, &status);
  PH_LOG_HELPER_EXECUTE(PH_LOG_OPTION_CATEGORY_LEAVE);

  return status;
}

/* MIFARE DESFire EVX Transaction mamangement commands. -------------------------------------------------------------------------------- */
phStatus_t phalMfdfEVx_CommitTransaction(void *pDataParams, uint8_t bOption, uint8_t *pTMC,
    uint8_t *pTMV)
{
  phStatus_t PH_MEMLOC_REM status;

  PH_LOG_HELPER_ALLOCATE_TEXT(bFunctionName, "phalMfdfEVx_CommitTransaction");
  PH_LOG_HELPER_ALLOCATE_PARAMNAME(bOption);
  PH_LOG_HELPER_ALLOCATE_PARAMNAME(pTMC);
  PH_LOG_HELPER_ALLOCATE_PARAMNAME(pTMV);
  PH_LOG_HELPER_ALLOCATE_PARAMNAME(status);
  PH_LOG_HELPER_ADDSTRING(PH_LOG_LOGTYPE_INFO, bFunctionName);
  PH_LOG_HELPER_ADDPARAM_UINT8(PH_LOG_LOGTYPE_INFO, bOption_log, &bOption);
  PH_LOG_HELPER_EXECUTE(PH_LOG_OPTION_CATEGORY_ENTER);

  /* Validate the parameters */
  PH_ASSERT_NULL_DATA_PARAM(pDataParams, PH_COMP_AL_MFDFEVX);
  if (bOption & 0x01) {
    PH_ASSERT_NULL_PARAM(pTMC, PH_COMP_AL_MFDFEVX);
    PH_ASSERT_NULL_PARAM(pTMV, PH_COMP_AL_MFDFEVX);
  }

  /* Parameter validation */
  if (PH_GET_COMPCODE(pDataParams) != PH_COMP_AL_MFDFEVX) {
    PH_LOG_HELPER_ADDSTRING(PH_LOG_LOGTYPE_INFO, bFunctionName);
    PH_LOG_HELPER_ADDPARAM_UINT16(PH_LOG_LOGTYPE_INFO, status_log, &status);
    PH_LOG_HELPER_EXECUTE(PH_LOG_OPTION_CATEGORY_LEAVE);

    return PH_ADD_COMPCODE_FIXED(PH_ERR_INVALID_DATA_PARAMS, PH_COMP_AL_MFDFEVX);
  }

  /* Perform operation on active layer */
  switch (PH_GET_COMPID(pDataParams)) {
#ifdef NXPBUILD__PHAL_MFDFEVX_SW
    case PHAL_MFDFEVX_SW_ID:
      status = phalMfdfEVx_Sw_CommitTransaction((phalMfdfEVx_Sw_DataParams_t *) pDataParams, bOption,
              pTMC, pTMV);
      break;
#endif /* NXPBUILD__PHAL_MFDFEVX_SW */

    default:
      status = PH_ADD_COMPCODE_FIXED(PH_ERR_INVALID_DATA_PARAMS, PH_COMP_AL_MFDFEVX);
      break;
  }

  PH_LOG_HELPER_ADDSTRING(PH_LOG_LOGTYPE_INFO, bFunctionName);
  if (bOption & 0x01) {
    PH_LOG_HELPER_ADDPARAM_BUFFER(PH_LOG_LOGTYPE_DEBUG, pTMC_log, pTMC, 4);
    PH_LOG_HELPER_ADDPARAM_BUFFER(PH_LOG_LOGTYPE_DEBUG, pTMV_log, pTMV, 8);
  }
  PH_LOG_HELPER_ADDPARAM_UINT16(PH_LOG_LOGTYPE_INFO, status_log, &status);
  PH_LOG_HELPER_EXECUTE(PH_LOG_OPTION_CATEGORY_LEAVE);

  return status;
}

phStatus_t phalMfdfEVx_AbortTransaction(void *pDataParams)
{
  phStatus_t PH_MEMLOC_REM status;

  PH_LOG_HELPER_ALLOCATE_TEXT(bFunctionName, "phalMfdfEVx_AbortTransaction");
  PH_LOG_HELPER_ALLOCATE_PARAMNAME(status);
  PH_LOG_HELPER_ADDSTRING(PH_LOG_LOGTYPE_INFO, bFunctionName);
  PH_LOG_HELPER_EXECUTE(PH_LOG_OPTION_CATEGORY_ENTER);

  /* Validate the parameters */
  PH_ASSERT_NULL_DATA_PARAM(pDataParams, PH_COMP_AL_MFDFEVX);

  /* Parameter validation */
  if (PH_GET_COMPCODE(pDataParams) != PH_COMP_AL_MFDFEVX) {
    PH_LOG_HELPER_ADDSTRING(PH_LOG_LOGTYPE_INFO, bFunctionName);
    PH_LOG_HELPER_ADDPARAM_UINT16(PH_LOG_LOGTYPE_INFO, status_log, &status);
    PH_LOG_HELPER_EXECUTE(PH_LOG_OPTION_CATEGORY_LEAVE);

    return PH_ADD_COMPCODE_FIXED(PH_ERR_INVALID_DATA_PARAMS, PH_COMP_AL_MFDFEVX);
  }

  /* Perform operation on active layer */
  switch (PH_GET_COMPID(pDataParams)) {
#ifdef NXPBUILD__PHAL_MFDFEVX_SW
    case PHAL_MFDFEVX_SW_ID:
      status = phalMfdfEVx_Sw_AbortTransaction((phalMfdfEVx_Sw_DataParams_t *) pDataParams);
      break;
#endif /* NXPBUILD__PHAL_MFDFEVX_SW */

    default:
      status = PH_ADD_COMPCODE_FIXED(PH_ERR_INVALID_DATA_PARAMS, PH_COMP_AL_MFDFEVX);
      break;
  }

  PH_LOG_HELPER_ADDSTRING(PH_LOG_LOGTYPE_INFO, bFunctionName);
  PH_LOG_HELPER_ADDPARAM_UINT16(PH_LOG_LOGTYPE_INFO, status_log, &status);
  PH_LOG_HELPER_EXECUTE(PH_LOG_OPTION_CATEGORY_LEAVE);

  return status;
}

phStatus_t phalMfdfEVx_CommitReaderID(void *pDataParams, uint8_t *pTMRI, uint8_t *pEncTMRI)

{
  phStatus_t PH_MEMLOC_REM status;

  PH_LOG_HELPER_ALLOCATE_TEXT(bFunctionName, "phalMfdfEVx_CommitReaderID");
  PH_LOG_HELPER_ALLOCATE_PARAMNAME(pTMRI);
  PH_LOG_HELPER_ALLOCATE_PARAMNAME(pEncTMRI);
  PH_LOG_HELPER_ALLOCATE_PARAMNAME(status);
  PH_LOG_HELPER_ADDSTRING(PH_LOG_LOGTYPE_INFO, bFunctionName);
  {
    PH_LOG_HELPER_ADDPARAM_BUFFER(PH_LOG_LOGTYPE_DEBUG, pTMRI_log, pTMRI, 16);
  }
  PH_LOG_HELPER_EXECUTE(PH_LOG_OPTION_CATEGORY_ENTER);

  /* Validate the parameters */
  PH_ASSERT_NULL_DATA_PARAM(pDataParams, PH_COMP_AL_MFDFEVX);

  {
    PH_ASSERT_NULL_PARAM(pTMRI, PH_COMP_AL_MFDFEVX);
  }
  /* Parameter validation */
  if (PH_GET_COMPCODE(pDataParams) != PH_COMP_AL_MFDFEVX) {
    PH_LOG_HELPER_ADDSTRING(PH_LOG_LOGTYPE_INFO, bFunctionName);
    PH_LOG_HELPER_ADDPARAM_UINT16(PH_LOG_LOGTYPE_INFO, status_log, &status);
    PH_LOG_HELPER_EXECUTE(PH_LOG_OPTION_CATEGORY_LEAVE);

    return PH_ADD_COMPCODE_FIXED(PH_ERR_INVALID_DATA_PARAMS, PH_COMP_AL_MFDFEVX);
  }

  /* Perform operation on active layer */
  switch (PH_GET_COMPID(pDataParams)) {
#ifdef NXPBUILD__PHAL_MFDFEVX_SW
    case PHAL_MFDFEVX_SW_ID:
      status = phalMfdfEVx_Sw_CommitReaderID((phalMfdfEVx_Sw_DataParams_t *) pDataParams, pTMRI,
              pEncTMRI);
      break;
#endif /* NXPBUILD__PHAL_MFDFEVX_SW */

    default:
      status = PH_ADD_COMPCODE_FIXED(PH_ERR_INVALID_DATA_PARAMS, PH_COMP_AL_MFDFEVX);
      break;
  }

  PH_LOG_HELPER_ADDSTRING(PH_LOG_LOGTYPE_INFO, bFunctionName);
  PH_LOG_HELPER_ADDPARAM_BUFFER(PH_LOG_LOGTYPE_DEBUG, pEncTMRI_log, pEncTMRI, 16);
  PH_LOG_HELPER_ADDPARAM_UINT16(PH_LOG_LOGTYPE_INFO, status_log, &status);
  PH_LOG_HELPER_EXECUTE(PH_LOG_OPTION_CATEGORY_LEAVE);

  return status;
}

/* MIFARE DESFire EVX ISO7816-4 commands. ---------------------------------------------------------------------------------------------- */
phStatus_t phalMfdfEVx_IsoSelectFile(void *pDataParams, uint8_t bOption, uint8_t bSelector,
    uint8_t *pFid, uint8_t *pDFname,
    uint8_t bDFnameLen, uint8_t bExtendedLenApdu, uint8_t **ppFCI, uint16_t *pwFCILen)
{
  phStatus_t PH_MEMLOC_REM status;

  PH_LOG_HELPER_ALLOCATE_TEXT(bFunctionName, "phalMfdfEVx_IsoSelectFile");
  PH_LOG_HELPER_ALLOCATE_PARAMNAME(status);
  PH_LOG_HELPER_ALLOCATE_PARAMNAME(bOption);
  PH_LOG_HELPER_ALLOCATE_PARAMNAME(bSelector);
  PH_LOG_HELPER_ALLOCATE_PARAMNAME(pFid);
  PH_LOG_HELPER_ALLOCATE_PARAMNAME(pDFname);
  PH_LOG_HELPER_ALLOCATE_PARAMNAME(bDFnameLen);
  PH_LOG_HELPER_ADDSTRING(PH_LOG_LOGTYPE_INFO, bFunctionName);
  PH_LOG_HELPER_ADDPARAM_UINT8(PH_LOG_LOGTYPE_DEBUG, bOption_log, &bOption);
  PH_LOG_HELPER_ADDPARAM_UINT8(PH_LOG_LOGTYPE_DEBUG, bSelector_log, &bSelector);
  PH_LOG_HELPER_ADDPARAM_BUFFER(PH_LOG_LOGTYPE_DEBUG, pFid_log, pFid, 2);
  PH_LOG_HELPER_ADDPARAM_UINT8(PH_LOG_LOGTYPE_DEBUG, bDFnameLen_log, &bDFnameLen);
  PH_LOG_HELPER_ADDPARAM_BUFFER(PH_LOG_LOGTYPE_DEBUG, pDFname_log, pDFname, (uint16_t) bDFnameLen);
  PH_LOG_HELPER_EXECUTE(PH_LOG_OPTION_CATEGORY_ENTER);

  /* Validate the parameters */
  PH_ASSERT_NULL_DATA_PARAM(pDataParams, PH_COMP_AL_MFDFEVX);

  /* Parameter validation */
  if (PH_GET_COMPCODE(pDataParams) != PH_COMP_AL_MFDFEVX) {
    PH_LOG_HELPER_ADDSTRING(PH_LOG_LOGTYPE_INFO, bFunctionName);
    PH_LOG_HELPER_ADDPARAM_UINT16(PH_LOG_LOGTYPE_INFO, status_log, &status);
    PH_LOG_HELPER_EXECUTE(PH_LOG_OPTION_CATEGORY_LEAVE);

    return PH_ADD_COMPCODE_FIXED(PH_ERR_INVALID_DATA_PARAMS, PH_COMP_AL_MFDFEVX);
  }

  /* Perform operation on active layer */
  switch (PH_GET_COMPID(pDataParams)) {
#ifdef NXPBUILD__PHAL_MFDFEVX_SW
    case PHAL_MFDFEVX_SW_ID:
      status = phalMfdfEVx_Sw_IsoSelectFile((phalMfdfEVx_Sw_DataParams_t *) pDataParams, bOption,
              bSelector,
              pFid, pDFname, bDFnameLen, bExtendedLenApdu, ppFCI, pwFCILen);
      break;
#endif /* NXPBUILD__PHAL_MFDFEVX_SW */

    default:
      status = PH_ADD_COMPCODE_FIXED(PH_ERR_INVALID_DATA_PARAMS, PH_COMP_AL_MFDFEVX);
      break;
  }

  PH_LOG_HELPER_ADDSTRING(PH_LOG_LOGTYPE_INFO, bFunctionName);
  PH_LOG_HELPER_ADDPARAM_UINT16(PH_LOG_LOGTYPE_INFO, status_log, &status);
  PH_LOG_HELPER_EXECUTE(PH_LOG_OPTION_CATEGORY_LEAVE);

  return status;
}

phStatus_t phalMfdfEVx_IsoReadBinary(void *pDataParams, uint16_t wOption, uint8_t bOffset,
    uint8_t bSfid, uint32_t dwBytesToRead,
    uint8_t bExtendedLenApdu, uint8_t **ppRxBuffer, uint32_t *pBytesRead)
{
  phStatus_t PH_MEMLOC_REM status;

  PH_LOG_HELPER_ALLOCATE_TEXT(bFunctionName, "phalMfdfEVx_IsoReadBinary");
  PH_LOG_HELPER_ALLOCATE_PARAMNAME(status);
  PH_LOG_HELPER_ALLOCATE_PARAMNAME(bOffset);
  PH_LOG_HELPER_ALLOCATE_PARAMNAME(bSfid);
  PH_LOG_HELPER_ALLOCATE_PARAMNAME(dwBytesToRead);
  PH_LOG_HELPER_ALLOCATE_PARAMNAME(ppRxBuffer);
  PH_LOG_HELPER_ALLOCATE_PARAMNAME(pBytesRead);
  PH_LOG_HELPER_ADDSTRING(PH_LOG_LOGTYPE_INFO, bFunctionName);
  PH_LOG_HELPER_ADDPARAM_UINT8(PH_LOG_LOGTYPE_DEBUG, bOffset_log, &bOffset);
  PH_LOG_HELPER_ADDPARAM_UINT8(PH_LOG_LOGTYPE_DEBUG, bSfid_log, &bSfid);
  PH_LOG_HELPER_ADDPARAM_UINT32(PH_LOG_LOGTYPE_DEBUG, dwBytesToRead_log, &dwBytesToRead);
  PH_LOG_HELPER_EXECUTE(PH_LOG_OPTION_CATEGORY_ENTER);

  /* Validate the parameters */
  PH_ASSERT_NULL_DATA_PARAM(pDataParams, PH_COMP_AL_MFDFEVX);
  PH_ASSERT_NULL_PARAM(ppRxBuffer, PH_COMP_AL_MFDFEVX);
  PH_ASSERT_NULL_PARAM(pBytesRead, PH_COMP_AL_MFDFEVX);

  /* Parameter validation */
  if (PH_GET_COMPCODE(pDataParams) != PH_COMP_AL_MFDFEVX) {
    PH_LOG_HELPER_ADDSTRING(PH_LOG_LOGTYPE_INFO, bFunctionName);
    PH_LOG_HELPER_ADDPARAM_UINT16(PH_LOG_LOGTYPE_INFO, status_log, &status);
    PH_LOG_HELPER_EXECUTE(PH_LOG_OPTION_CATEGORY_LEAVE);

    return PH_ADD_COMPCODE_FIXED(PH_ERR_INVALID_DATA_PARAMS, PH_COMP_AL_MFDFEVX);
  }

  /* Perform operation on active layer */
  switch (PH_GET_COMPID(pDataParams)) {
#ifdef NXPBUILD__PHAL_MFDFEVX_SW
    case PHAL_MFDFEVX_SW_ID:
      status = phalMfdfEVx_Sw_IsoReadBinary((phalMfdfEVx_Sw_DataParams_t *) pDataParams, wOption,
              bOffset,
              bSfid, dwBytesToRead, bExtendedLenApdu, ppRxBuffer, pBytesRead);
      break;
#endif /* NXPBUILD__PHAL_MFDFEVX_SW */

    default:
      status = PH_ADD_COMPCODE_FIXED(PH_ERR_INVALID_DATA_PARAMS, PH_COMP_AL_MFDFEVX);
      break;
  }

  PH_LOG_HELPER_ADDSTRING(PH_LOG_LOGTYPE_INFO, bFunctionName);
  PH_LOG_HELPER_ADDPARAM_BUFFER(PH_LOG_LOGTYPE_DEBUG, ppRxBuffer_log, *ppRxBuffer,
      (uint16_t)(*pBytesRead));
  PH_LOG_HELPER_ADDPARAM_UINT32(PH_LOG_LOGTYPE_INFO, pBytesRead_log, pBytesRead);
  PH_LOG_HELPER_ADDPARAM_UINT16(PH_LOG_LOGTYPE_INFO, status_log, &status);
  PH_LOG_HELPER_EXECUTE(PH_LOG_OPTION_CATEGORY_LEAVE);

  return status;
}

phStatus_t phalMfdfEVx_IsoUpdateBinary(void *pDataParams, uint8_t bOffset, uint8_t bSfid,
    uint8_t bExtendedLenApdu, uint8_t *pData,
    uint32_t dwDataLen)
{
  phStatus_t PH_MEMLOC_REM status;

  PH_LOG_HELPER_ALLOCATE_TEXT(bFunctionName, "phalMfdfEVx_IsoUpdateBinary");
  PH_LOG_HELPER_ALLOCATE_PARAMNAME(status);
  PH_LOG_HELPER_ALLOCATE_PARAMNAME(bOffset);
  PH_LOG_HELPER_ALLOCATE_PARAMNAME(bSfid);
  PH_LOG_HELPER_ALLOCATE_PARAMNAME(pData);
  PH_LOG_HELPER_ALLOCATE_PARAMNAME(dwDataLen);
  PH_LOG_HELPER_ADDSTRING(PH_LOG_LOGTYPE_INFO, bFunctionName);

  PH_LOG_HELPER_ADDPARAM_UINT8(PH_LOG_LOGTYPE_DEBUG, bOffset_log, &bOffset);
  PH_LOG_HELPER_ADDPARAM_UINT8(PH_LOG_LOGTYPE_DEBUG, bSfid_log, &bSfid);
  PH_LOG_HELPER_ADDPARAM_BUFFER(PH_LOG_LOGTYPE_DEBUG, pData_log, pData, (uint16_t) dwDataLen);
  PH_LOG_HELPER_ADDPARAM_UINT32(PH_LOG_LOGTYPE_INFO, dwDataLen_log, &dwDataLen);
  PH_LOG_HELPER_EXECUTE(PH_LOG_OPTION_CATEGORY_ENTER);

  /* Validate the parameters */
  PH_ASSERT_NULL_DATA_PARAM(pDataParams, PH_COMP_AL_MFDFEVX);
  PH_ASSERT_NULL_PARAM(pData, PH_COMP_AL_MFDFEVX);

  /* Parameter validation */
  if (PH_GET_COMPCODE(pDataParams) != PH_COMP_AL_MFDFEVX) {
    PH_LOG_HELPER_ADDSTRING(PH_LOG_LOGTYPE_INFO, bFunctionName);
    PH_LOG_HELPER_ADDPARAM_UINT16(PH_LOG_LOGTYPE_INFO, status_log, &status);
    PH_LOG_HELPER_EXECUTE(PH_LOG_OPTION_CATEGORY_LEAVE);

    return PH_ADD_COMPCODE_FIXED(PH_ERR_INVALID_DATA_PARAMS, PH_COMP_AL_MFDFEVX);
  }

  /* Perform operation on active layer */
  switch (PH_GET_COMPID(pDataParams)) {
#ifdef NXPBUILD__PHAL_MFDFEVX_SW
    case PHAL_MFDFEVX_SW_ID:
      status = phalMfdfEVx_Sw_IsoUpdateBinary((phalMfdfEVx_Sw_DataParams_t *) pDataParams, bOffset,
              bSfid,
              bExtendedLenApdu, pData, dwDataLen);
      break;
#endif /* NXPBUILD__PHAL_MFDFEVX_SW */

    default:
      status = PH_ADD_COMPCODE_FIXED(PH_ERR_INVALID_DATA_PARAMS, PH_COMP_AL_MFDFEVX);
      break;
  }

  PH_LOG_HELPER_ADDSTRING(PH_LOG_LOGTYPE_INFO, bFunctionName);
  PH_LOG_HELPER_ADDPARAM_UINT16(PH_LOG_LOGTYPE_INFO, status_log, &status);
  PH_LOG_HELPER_EXECUTE(PH_LOG_OPTION_CATEGORY_LEAVE);

  return status;
}

phStatus_t phalMfdfEVx_IsoReadRecords(void *pDataParams, uint16_t wOption, uint8_t bRecNo,
    uint8_t bReadAllFromP1, uint8_t bSfid,
    uint32_t dwBytesToRead, uint8_t bExtendedLenApdu, uint8_t **ppRxBuffer, uint32_t *pBytesRead)
{
  phStatus_t PH_MEMLOC_REM status;

  PH_LOG_HELPER_ALLOCATE_TEXT(bFunctionName, "phalMfdfEVx_IsoReadRecords");
  PH_LOG_HELPER_ALLOCATE_PARAMNAME(status);
  PH_LOG_HELPER_ALLOCATE_PARAMNAME(bRecNo);
  PH_LOG_HELPER_ALLOCATE_PARAMNAME(bReadAllFromP1);
  PH_LOG_HELPER_ALLOCATE_PARAMNAME(bSfid);
  PH_LOG_HELPER_ALLOCATE_PARAMNAME(dwBytesToRead);
  PH_LOG_HELPER_ALLOCATE_PARAMNAME(ppRxBuffer);
  PH_LOG_HELPER_ALLOCATE_PARAMNAME(pBytesRead);
  PH_LOG_HELPER_ADDSTRING(PH_LOG_LOGTYPE_INFO, bFunctionName);
  PH_LOG_HELPER_ADDPARAM_UINT8(PH_LOG_LOGTYPE_DEBUG, bRecNo_log, &bRecNo);
  PH_LOG_HELPER_ADDPARAM_UINT8(PH_LOG_LOGTYPE_DEBUG, bReadAllFromP1_log, &bReadAllFromP1);
  PH_LOG_HELPER_ADDPARAM_UINT8(PH_LOG_LOGTYPE_DEBUG, bSfid_log, &bSfid);
  PH_LOG_HELPER_ADDPARAM_UINT32(PH_LOG_LOGTYPE_DEBUG, dwBytesToRead_log, &dwBytesToRead);
  PH_LOG_HELPER_EXECUTE(PH_LOG_OPTION_CATEGORY_ENTER);

  /* Validate the parameters */
  PH_ASSERT_NULL_DATA_PARAM(pDataParams, PH_COMP_AL_MFDFEVX);
  PH_ASSERT_NULL_PARAM(ppRxBuffer, PH_COMP_AL_MFDFEVX);
  PH_ASSERT_NULL_PARAM(pBytesRead, PH_COMP_AL_MFDFEVX);

  /* Parameter validation */
  if (PH_GET_COMPCODE(pDataParams) != PH_COMP_AL_MFDFEVX) {
    PH_LOG_HELPER_ADDSTRING(PH_LOG_LOGTYPE_INFO, bFunctionName);
    PH_LOG_HELPER_ADDPARAM_UINT16(PH_LOG_LOGTYPE_INFO, status_log, &status);
    PH_LOG_HELPER_EXECUTE(PH_LOG_OPTION_CATEGORY_LEAVE);

    return PH_ADD_COMPCODE_FIXED(PH_ERR_INVALID_DATA_PARAMS, PH_COMP_AL_MFDFEVX);
  }

  /* Perform operation on active layer */
  switch (PH_GET_COMPID(pDataParams)) {
#ifdef NXPBUILD__PHAL_MFDFEVX_SW
    case PHAL_MFDFEVX_SW_ID:
      status = phalMfdfEVx_Sw_IsoReadRecords((phalMfdfEVx_Sw_DataParams_t *) pDataParams, wOption,
              bRecNo, bReadAllFromP1,
              bSfid, dwBytesToRead, bExtendedLenApdu, ppRxBuffer, pBytesRead);
      break;
#endif /* NXPBUILD__PHAL_MFDFEVX_SW */

    default:
      status = PH_ADD_COMPCODE_FIXED(PH_ERR_INVALID_DATA_PARAMS, PH_COMP_AL_MFDFEVX);
      break;
  }

  PH_LOG_HELPER_ADDSTRING(PH_LOG_LOGTYPE_INFO, bFunctionName);
  PH_LOG_HELPER_ADDPARAM_BUFFER(PH_LOG_LOGTYPE_DEBUG, ppRxBuffer_log, *ppRxBuffer,
      (uint16_t)(*pBytesRead));
  PH_LOG_HELPER_ADDPARAM_UINT32(PH_LOG_LOGTYPE_DEBUG, pBytesRead_log, pBytesRead);
  PH_LOG_HELPER_ADDPARAM_UINT16(PH_LOG_LOGTYPE_INFO, status_log, &status);
  PH_LOG_HELPER_EXECUTE(PH_LOG_OPTION_CATEGORY_LEAVE);

  return status;
}

phStatus_t phalMfdfEVx_IsoAppendRecord(void *pDataParams, uint8_t bSfid, uint8_t *pData,
    uint32_t dwDataLen, uint8_t bExtendedLenApdu)
{
  phStatus_t PH_MEMLOC_REM status;

  PH_LOG_HELPER_ALLOCATE_TEXT(bFunctionName, "phalMfdfEVx_IsoAppendRecord");
  PH_LOG_HELPER_ALLOCATE_PARAMNAME(status);
  PH_LOG_HELPER_ALLOCATE_PARAMNAME(bSfid);
  PH_LOG_HELPER_ALLOCATE_PARAMNAME(pData);
  PH_LOG_HELPER_ALLOCATE_PARAMNAME(dwDataLen);
  PH_LOG_HELPER_ADDSTRING(PH_LOG_LOGTYPE_INFO, bFunctionName);
  PH_LOG_HELPER_ADDPARAM_UINT8(PH_LOG_LOGTYPE_DEBUG, bSfid_log, &bSfid);
  PH_LOG_HELPER_ADDPARAM_BUFFER(PH_LOG_LOGTYPE_DEBUG, pData_log, pData, (uint16_t) dwDataLen);
  PH_LOG_HELPER_ADDPARAM_UINT32(PH_LOG_LOGTYPE_DEBUG, dwDataLen_log, &dwDataLen);
  PH_LOG_HELPER_EXECUTE(PH_LOG_OPTION_CATEGORY_ENTER);

  /* Validate the parameters */
  PH_ASSERT_NULL_DATA_PARAM(pDataParams, PH_COMP_AL_MFDFEVX);
  PH_ASSERT_NULL_PARAM(pData, PH_COMP_AL_MFDFEVX);

  /* Parameter validation */
  if (PH_GET_COMPCODE(pDataParams) != PH_COMP_AL_MFDFEVX) {
    PH_LOG_HELPER_ADDSTRING(PH_LOG_LOGTYPE_INFO, bFunctionName);
    PH_LOG_HELPER_ADDPARAM_UINT16(PH_LOG_LOGTYPE_INFO, status_log, &status);
    PH_LOG_HELPER_EXECUTE(PH_LOG_OPTION_CATEGORY_LEAVE);

    return PH_ADD_COMPCODE_FIXED(PH_ERR_INVALID_DATA_PARAMS, PH_COMP_AL_MFDFEVX);
  }

  /* Perform operation on active layer */
  switch (PH_GET_COMPID(pDataParams)) {
#ifdef NXPBUILD__PHAL_MFDFEVX_SW
    case PHAL_MFDFEVX_SW_ID:
      status = phalMfdfEVx_Sw_IsoAppendRecord((phalMfdfEVx_Sw_DataParams_t *) pDataParams, bSfid,
              bExtendedLenApdu,
              pData, dwDataLen);
      break;
#endif /* NXPBUILD__PHAL_MFDFEVX_SW */

    default:
      status = PH_ADD_COMPCODE_FIXED(PH_ERR_INVALID_DATA_PARAMS, PH_COMP_AL_MFDFEVX);
      break;
  }

  PH_LOG_HELPER_ADDSTRING(PH_LOG_LOGTYPE_INFO, bFunctionName);
  PH_LOG_HELPER_ADDPARAM_UINT16(PH_LOG_LOGTYPE_INFO, status_log, &status);
  PH_LOG_HELPER_EXECUTE(PH_LOG_OPTION_CATEGORY_LEAVE);

  return status;
}

phStatus_t phalMfdfEVx_IsoUpdateRecord(void *pDataParams, uint8_t bIns, uint8_t bRecNo,
    uint8_t bSfid, uint8_t bRefCtrl, uint8_t *pData,
    uint8_t bDataLen)
{
  phStatus_t PH_MEMLOC_REM status;

  PH_LOG_HELPER_ALLOCATE_TEXT(bFunctionName, "phalMfdfEVx_IsoUpdateRecord");
  PH_LOG_HELPER_ALLOCATE_PARAMNAME(status);
  PH_LOG_HELPER_ALLOCATE_PARAMNAME(bIns);
  PH_LOG_HELPER_ALLOCATE_PARAMNAME(bRecNo);
  PH_LOG_HELPER_ALLOCATE_PARAMNAME(bSfid);
  PH_LOG_HELPER_ALLOCATE_PARAMNAME(bRefCtrl);
  PH_LOG_HELPER_ALLOCATE_PARAMNAME(pData);
  PH_LOG_HELPER_ALLOCATE_PARAMNAME(bDataLen);
  PH_LOG_HELPER_ADDSTRING(PH_LOG_LOGTYPE_INFO, bFunctionName);
  PH_LOG_HELPER_ADDPARAM_UINT8(PH_LOG_LOGTYPE_DEBUG, bIns_log, &bIns);
  PH_LOG_HELPER_ADDPARAM_UINT8(PH_LOG_LOGTYPE_DEBUG, bRecNo_log, &bRecNo);
  PH_LOG_HELPER_ADDPARAM_UINT8(PH_LOG_LOGTYPE_DEBUG, bSfid_log, &bSfid);
  PH_LOG_HELPER_ADDPARAM_UINT8(PH_LOG_LOGTYPE_DEBUG, bRefCtrl_log, &bRefCtrl);
  PH_LOG_HELPER_ADDPARAM_BUFFER(PH_LOG_LOGTYPE_DEBUG, pData_log, pData, bDataLen);
  PH_LOG_HELPER_ADDPARAM_UINT8(PH_LOG_LOGTYPE_DEBUG, bDataLen_log, &bDataLen);
  PH_LOG_HELPER_EXECUTE(PH_LOG_OPTION_CATEGORY_ENTER);

  /* Validate the parameters */
  PH_ASSERT_NULL_DATA_PARAM(pDataParams, PH_COMP_AL_MFDFEVX);
  PH_ASSERT_NULL_PARAM(pData, PH_COMP_AL_MFDFEVX);

  /* Parameter validation */
  if (PH_GET_COMPCODE(pDataParams) != PH_COMP_AL_MFDFEVX) {
    PH_LOG_HELPER_ADDSTRING(PH_LOG_LOGTYPE_INFO, bFunctionName);
    PH_LOG_HELPER_ADDPARAM_UINT16(PH_LOG_LOGTYPE_INFO, status_log, &status);
    PH_LOG_HELPER_EXECUTE(PH_LOG_OPTION_CATEGORY_LEAVE);

    return PH_ADD_COMPCODE_FIXED(PH_ERR_INVALID_DATA_PARAMS, PH_COMP_AL_MFDFEVX);
  }

  /* Perform operation on active layer */
  switch (PH_GET_COMPID(pDataParams)) {
#ifdef NXPBUILD__PHAL_MFDFEVX_SW
    case PHAL_MFDFEVX_SW_ID:
      status = phalMfdfEVx_Sw_IsoUpdateRecord((phalMfdfEVx_Sw_DataParams_t *) pDataParams, bIns, bRecNo,
              bSfid, bRefCtrl, pData, bDataLen);
      break;
#endif /* NXPBUILD__PHAL_MFDFEVX_SW */

    default:
      status = PH_ADD_COMPCODE_FIXED(PH_ERR_INVALID_DATA_PARAMS, PH_COMP_AL_MFDFEVX);
      break;
  }

  PH_LOG_HELPER_ADDSTRING(PH_LOG_LOGTYPE_INFO, bFunctionName);
  PH_LOG_HELPER_ADDPARAM_UINT16(PH_LOG_LOGTYPE_INFO, status_log, &status);
  PH_LOG_HELPER_EXECUTE(PH_LOG_OPTION_CATEGORY_LEAVE);

  return status;
}

phStatus_t phalMfdfEVx_IsoGetChallenge(void *pDataParams, uint16_t wKeyNo, uint16_t wKeyVer,
    uint8_t bExtendedLenApdu, uint32_t dwLe,
    uint8_t *pRPICC1)
{
  phStatus_t PH_MEMLOC_REM status;

  PH_LOG_HELPER_ALLOCATE_TEXT(bFunctionName, "phalMfdfEVx_IsoGetChallenge");
  PH_LOG_HELPER_ALLOCATE_PARAMNAME(status);
  PH_LOG_HELPER_ALLOCATE_PARAMNAME(wKeyNo);
  PH_LOG_HELPER_ALLOCATE_PARAMNAME(wKeyVer);
  PH_LOG_HELPER_ALLOCATE_PARAMNAME(dwLe);
  PH_LOG_HELPER_ALLOCATE_PARAMNAME(pRPICC1);
  PH_LOG_HELPER_ADDSTRING(PH_LOG_LOGTYPE_INFO, bFunctionName);
  PH_LOG_HELPER_ADDPARAM_UINT16(PH_LOG_LOGTYPE_DEBUG, wKeyNo_log, &wKeyNo);
  PH_LOG_HELPER_ADDPARAM_UINT16(PH_LOG_LOGTYPE_DEBUG, wKeyVer_log, &wKeyVer);
  PH_LOG_HELPER_ADDPARAM_UINT32(PH_LOG_LOGTYPE_DEBUG, dwLe_log, &dwLe);
  PH_LOG_HELPER_EXECUTE(PH_LOG_OPTION_CATEGORY_ENTER);

  /* Validate the parameters */
  PH_ASSERT_NULL_DATA_PARAM(pDataParams, PH_COMP_AL_MFDFEVX);
  PH_ASSERT_NULL_PARAM(pRPICC1, PH_COMP_AL_MFDFEVX);

  /* Parameter validation */
  if (PH_GET_COMPCODE(pDataParams) != PH_COMP_AL_MFDFEVX) {
    PH_LOG_HELPER_ADDSTRING(PH_LOG_LOGTYPE_INFO, bFunctionName);
    PH_LOG_HELPER_ADDPARAM_UINT16(PH_LOG_LOGTYPE_INFO, status_log, &status);
    PH_LOG_HELPER_EXECUTE(PH_LOG_OPTION_CATEGORY_LEAVE);

    return PH_ADD_COMPCODE_FIXED(PH_ERR_INVALID_DATA_PARAMS, PH_COMP_AL_MFDFEVX);
  }

  /* Perform operation on active layer */
  switch (PH_GET_COMPID(pDataParams)) {
#ifdef NXPBUILD__PHAL_MFDFEVX_SW
    case PHAL_MFDFEVX_SW_ID:
      status = phalMfdfEVx_Sw_IsoGetChallenge((phalMfdfEVx_Sw_DataParams_t *) pDataParams, wKeyNo,
              wKeyVer, bExtendedLenApdu,
              dwLe, pRPICC1);
      break;
#endif /* NXPBUILD__PHAL_MFDFEVX_SW */

    default:
      status = PH_ADD_COMPCODE_FIXED(PH_ERR_INVALID_DATA_PARAMS, PH_COMP_AL_MFDFEVX);
      break;
  }

  PH_LOG_HELPER_ADDSTRING(PH_LOG_LOGTYPE_INFO, bFunctionName);
  PH_LOG_HELPER_ADDPARAM_BUFFER(PH_LOG_LOGTYPE_INFO, pRPICC1_log, pRPICC1, 8);
  PH_LOG_HELPER_ADDPARAM_UINT16(PH_LOG_LOGTYPE_INFO, status_log, &status);
  PH_LOG_HELPER_EXECUTE(PH_LOG_OPTION_CATEGORY_LEAVE);

  return status;
}

#ifdef NXPBUILD__PHAL_MFDFEVX_NDA
phStatus_t phalMfdfEVx_IsoExternalAuthenticate(void *pDataParams, uint8_t *pInput,
    uint8_t bInputLen, uint8_t bExtendedLenApdu,
    uint8_t *pDataOut, uint8_t *pOutLen)
{
  phStatus_t PH_MEMLOC_REM status;

  PH_LOG_HELPER_ALLOCATE_TEXT(bFunctionName, "phalMfdfEVx_IsoExternalAuthenticate");
  PH_LOG_HELPER_ALLOCATE_PARAMNAME(status);
  PH_LOG_HELPER_ALLOCATE_PARAMNAME(bInputLen);
  PH_LOG_HELPER_ADDSTRING(PH_LOG_LOGTYPE_INFO, bFunctionName);
  PH_LOG_HELPER_ADDPARAM_UINT8(PH_LOG_LOGTYPE_DEBUG, bInputLen_log, &bInputLen);
  PH_LOG_HELPER_EXECUTE(PH_LOG_OPTION_CATEGORY_ENTER);

  /* Validate the parameters */
  PH_ASSERT_NULL_DATA_PARAM(pDataParams, PH_COMP_AL_MFDFEVX);
  PH_ASSERT_NULL_PARAM(pInput, PH_COMP_AL_MFDFEVX);

  /* Parameter validation */
  if (PH_GET_COMPCODE(pDataParams) != PH_COMP_AL_MFDFEVX) {
    PH_LOG_HELPER_ADDSTRING(PH_LOG_LOGTYPE_INFO, bFunctionName);
    PH_LOG_HELPER_ADDPARAM_UINT16(PH_LOG_LOGTYPE_INFO, status_log, &status);
    PH_LOG_HELPER_EXECUTE(PH_LOG_OPTION_CATEGORY_LEAVE);

    return PH_ADD_COMPCODE_FIXED(PH_ERR_INVALID_DATA_PARAMS, PH_COMP_AL_MFDFEVX);
  }

  /* Perform operation on active layer */
  switch (PH_GET_COMPID(pDataParams)) {
#ifdef NXPBUILD__PHAL_MFDFEVX_SW
    case PHAL_MFDFEVX_SW_ID:
      status = phalMfdfEVx_Sw_IsoExternalAuthenticate((phalMfdfEVx_Sw_DataParams_t *) pDataParams,
              pInput, bInputLen,
              bExtendedLenApdu, pDataOut, pOutLen);
      break;
#endif /* NXPBUILD__PHAL_MFDFEVX_SW */

    default:
      status = PH_ADD_COMPCODE_FIXED(PH_ERR_INVALID_DATA_PARAMS, PH_COMP_AL_MFDFEVX);
      break;
  }

  PH_LOG_HELPER_ADDSTRING(PH_LOG_LOGTYPE_INFO, bFunctionName);
  PH_LOG_HELPER_ADDPARAM_UINT16(PH_LOG_LOGTYPE_INFO, status_log, &status);
  PH_LOG_HELPER_EXECUTE(PH_LOG_OPTION_CATEGORY_LEAVE);

  return status;
}

phStatus_t phalMfdfEVx_IsoInternalAuthenticate(void *pDataParams, uint8_t *pInput,
    uint8_t bInputLen, uint8_t bExtendedLenApdu,
    uint8_t *pDataOut, uint8_t *pOutLen)
{
  phStatus_t PH_MEMLOC_REM status;

  PH_LOG_HELPER_ALLOCATE_TEXT(bFunctionName, "phalMfdfEVx_IsoInternalAuthenticate");
  PH_LOG_HELPER_ALLOCATE_PARAMNAME(status);
  PH_LOG_HELPER_ALLOCATE_PARAMNAME(bInputLen);
  PH_LOG_HELPER_ADDSTRING(PH_LOG_LOGTYPE_INFO, bFunctionName);
  PH_LOG_HELPER_ADDPARAM_UINT8(PH_LOG_LOGTYPE_DEBUG, bInputLen_log, &bInputLen);
  PH_LOG_HELPER_EXECUTE(PH_LOG_OPTION_CATEGORY_ENTER);

  /* Validate the parameters */
  PH_ASSERT_NULL_DATA_PARAM(pDataParams, PH_COMP_AL_MFDFEVX);
  PH_ASSERT_NULL_PARAM(pInput, PH_COMP_AL_MFDFEVX);

  /* Parameter validation */
  if (PH_GET_COMPCODE(pDataParams) != PH_COMP_AL_MFDFEVX) {
    PH_LOG_HELPER_ADDSTRING(PH_LOG_LOGTYPE_INFO, bFunctionName);
    PH_LOG_HELPER_ADDPARAM_UINT16(PH_LOG_LOGTYPE_INFO, status_log, &status);
    PH_LOG_HELPER_EXECUTE(PH_LOG_OPTION_CATEGORY_LEAVE);

    return PH_ADD_COMPCODE_FIXED(PH_ERR_INVALID_DATA_PARAMS, PH_COMP_AL_MFDFEVX);
  }

  /* Perform operation on active layer */
  switch (PH_GET_COMPID(pDataParams)) {
#ifdef NXPBUILD__PHAL_MFDFEVX_SW
    case PHAL_MFDFEVX_SW_ID:
      status = phalMfdfEVx_Sw_IsoInternalAuthenticate((phalMfdfEVx_Sw_DataParams_t *) pDataParams,
              pInput, bInputLen,
              bExtendedLenApdu, pDataOut, pOutLen);
      break;
#endif /* NXPBUILD__PHAL_MFDFEVX_SW */

    default:
      status = PH_ADD_COMPCODE_FIXED(PH_ERR_INVALID_DATA_PARAMS, PH_COMP_AL_MFDFEVX);
      break;
  }

  PH_LOG_HELPER_ADDSTRING(PH_LOG_LOGTYPE_INFO, bFunctionName);
  PH_LOG_HELPER_ADDPARAM_UINT16(PH_LOG_LOGTYPE_INFO, status_log, &status);
  PH_LOG_HELPER_EXECUTE(PH_LOG_OPTION_CATEGORY_LEAVE);

  return status;
}

phStatus_t phalMfdfEVx_IsoAuthenticate(void *pDataParams, uint16_t wKeyNo, uint16_t wKeyVer,
    uint8_t bKeyNoCard, uint8_t bIsPICCkey)
{
  phStatus_t PH_MEMLOC_REM status;

  PH_LOG_HELPER_ALLOCATE_TEXT(bFunctionName, "phalMfdfEVx_IsoAuthenticate");
  PH_LOG_HELPER_ALLOCATE_PARAMNAME(wKeyNo);
  PH_LOG_HELPER_ALLOCATE_PARAMNAME(wKeyVer);
  PH_LOG_HELPER_ALLOCATE_PARAMNAME(bKeyNoCard);
  PH_LOG_HELPER_ALLOCATE_PARAMNAME(bIsPICCkey);
  PH_LOG_HELPER_ALLOCATE_PARAMNAME(status);
  PH_LOG_HELPER_ADDSTRING(PH_LOG_LOGTYPE_INFO, bFunctionName);

  PH_LOG_HELPER_ADDPARAM_UINT16(PH_LOG_LOGTYPE_DEBUG, wKeyNo_log, &wKeyNo);
  PH_LOG_HELPER_ADDPARAM_UINT16(PH_LOG_LOGTYPE_DEBUG, wKeyVer_log, &wKeyVer);
  PH_LOG_HELPER_ADDPARAM_UINT8(PH_LOG_LOGTYPE_DEBUG, bKeyNoCard_log, &bKeyNoCard);
  PH_LOG_HELPER_ADDPARAM_UINT8(PH_LOG_LOGTYPE_DEBUG, bIsPICCkey_log, &bIsPICCkey);
  PH_LOG_HELPER_EXECUTE(PH_LOG_OPTION_CATEGORY_ENTER);

  /* Validate the parameters */
  PH_ASSERT_NULL_DATA_PARAM(pDataParams, PH_COMP_AL_MFDFEVX);

  /* Parameter validation */
  if (PH_GET_COMPCODE(pDataParams) != PH_COMP_AL_MFDFEVX) {
    PH_LOG_HELPER_ADDSTRING(PH_LOG_LOGTYPE_INFO, bFunctionName);
    PH_LOG_HELPER_ADDPARAM_UINT16(PH_LOG_LOGTYPE_INFO, status_log, &status);
    PH_LOG_HELPER_EXECUTE(PH_LOG_OPTION_CATEGORY_LEAVE);

    return PH_ADD_COMPCODE_FIXED(PH_ERR_INVALID_DATA_PARAMS, PH_COMP_AL_MFDFEVX);
  }

  /* Perform operation on active layer */
  switch (PH_GET_COMPID(pDataParams)) {
#ifdef NXPBUILD__PHAL_MFDFEVX_SW
    case PHAL_MFDFEVX_SW_ID:
      status = phalMfdfEVx_Sw_IsoAuthenticate((phalMfdfEVx_Sw_DataParams_t *) pDataParams, wKeyNo,
              wKeyVer,
              bKeyNoCard, bIsPICCkey);
      break;
#endif /* NXPBUILD__PHAL_MFDFEVX_SW */

    default:
      status = PH_ADD_COMPCODE_FIXED(PH_ERR_INVALID_DATA_PARAMS, PH_COMP_AL_MFDFEVX);
      break;
  }

  PH_LOG_HELPER_ADDSTRING(PH_LOG_LOGTYPE_INFO, bFunctionName);
  PH_LOG_HELPER_ADDPARAM_UINT16(PH_LOG_LOGTYPE_INFO, status_log, &status);
  PH_LOG_HELPER_EXECUTE(PH_LOG_OPTION_CATEGORY_LEAVE);

  return status;
}
#endif /* NXPBUILD__PHAL_MFDFEVX_NDA */

/* MIFARE DESFire EVX Originality Check functions. ------------------------------------------------------------------------------------- */
phStatus_t phalMfdfEVx_ReadSign(void *pDataParams, uint8_t bAddr, uint8_t **pSignature)
{
  phStatus_t PH_MEMLOC_REM status = 0;
  PH_LOG_HELPER_ALLOCATE_TEXT(bFunctionName, "phalMfdfEVx_ReadSign");
  PH_LOG_HELPER_ALLOCATE_PARAMNAME(bAddr);
  PH_LOG_HELPER_ALLOCATE_PARAMNAME(pSignature);
  PH_LOG_HELPER_ALLOCATE_PARAMNAME(status);
  PH_LOG_HELPER_ADDSTRING(PH_LOG_LOGTYPE_INFO, bFunctionName);
  PH_LOG_HELPER_ADDPARAM_UINT8(PH_LOG_LOGTYPE_DEBUG, bAddr_log, &bAddr);
  PH_LOG_HELPER_EXECUTE(PH_LOG_OPTION_CATEGORY_ENTER);

  /* Validate the parameters */
  PH_ASSERT_NULL_DATA_PARAM(pDataParams, PH_COMP_AL_MFDFEVX);
  PH_ASSERT_NULL_PARAM(pSignature, PH_COMP_AL_MFDFEVX);

  if (PH_GET_COMPCODE(pDataParams) != PH_COMP_AL_MFDFEVX) {
    PH_LOG_HELPER_ADDSTRING(PH_LOG_LOGTYPE_INFO, bFunctionName);
    PH_LOG_HELPER_ADDPARAM_UINT16(PH_LOG_LOGTYPE_INFO, status_log, &status);
    PH_LOG_HELPER_EXECUTE(PH_LOG_OPTION_CATEGORY_LEAVE);

    return  PH_ADD_COMPCODE_FIXED(PH_ERR_INVALID_DATA_PARAMS, PH_COMP_AL_MFDFEVX);
  }

  /* Perform operation on active layer */
  switch (PH_GET_COMPID(pDataParams)) {
#ifdef NXPBUILD__PHAL_MFDFEVX_SW
    case PHAL_MFDFEVX_SW_ID:
      status = phalMfdfEVx_Sw_ReadSign((phalMfdfEVx_Sw_DataParams_t *) pDataParams, bAddr, pSignature);
      break;
#endif /* NXPBUILD__PHAL_MFDFEVX_SW */

    default:
      status = PH_ADD_COMPCODE_FIXED(PH_ERR_INVALID_DATA_PARAMS, PH_COMP_AL_MFDFEVX);
      break;
  }

  PH_LOG_HELPER_ADDSTRING(PH_LOG_LOGTYPE_INFO, bFunctionName);
  PH_LOG_HELPER_ADDPARAM_BUFFER(PH_LOG_LOGTYPE_DEBUG, pSignature_log, pSignature, 56);
  PH_LOG_HELPER_ADDPARAM_UINT16(PH_LOG_LOGTYPE_INFO, status_log, &status);
  PH_LOG_HELPER_EXECUTE(PH_LOG_OPTION_CATEGORY_LEAVE);

  return status;
}

/* MIFARE DESFire EVX MIFARE Classic contactless IC functions. ---------------------------------------------------------------------------------------- */
phStatus_t phalMfdfEVx_CreateMFCMapping(void *pDataParams, uint8_t bCommOption, uint8_t bFileNo,
    uint8_t bFileOption, uint8_t *pMFCBlockList,
    uint8_t bMFCBlocksLen, uint8_t bRestoreSource, uint8_t *pMFCLicense, uint8_t bMFCLicenseLen,
    uint8_t *pMFCLicenseMAC)
{
  phStatus_t PH_MEMLOC_REM status;

  PH_LOG_HELPER_ALLOCATE_TEXT(bFunctionName, "phalMfdfEVx_CreateMFCMapping");
  PH_LOG_HELPER_ALLOCATE_PARAMNAME(bCommOption);
  PH_LOG_HELPER_ALLOCATE_PARAMNAME(bFileNo);
  PH_LOG_HELPER_ALLOCATE_PARAMNAME(bFileOption);
  PH_LOG_HELPER_ALLOCATE_PARAMNAME(pMFCBlockList);
  PH_LOG_HELPER_ALLOCATE_PARAMNAME(bMFCBlocksLen);
  PH_LOG_HELPER_ALLOCATE_PARAMNAME(bRestoreSource);
  PH_LOG_HELPER_ALLOCATE_PARAMNAME(pMFCLicense);
  PH_LOG_HELPER_ALLOCATE_PARAMNAME(bMFCLicenseLen);
  PH_LOG_HELPER_ALLOCATE_PARAMNAME(pMFCLicenseMAC);
  PH_LOG_HELPER_ALLOCATE_PARAMNAME(status);

  /* Validate the parameters. */
  PH_ASSERT_NULL_DATA_PARAM(pDataParams, PH_COMP_AL_MFDFEVX);
  PH_ASSERT_NULL_DATA_PARAM(pMFCBlockList, PH_COMP_AL_MFDFEVX);
  PH_ASSERT_NULL_DATA_PARAM(pMFCLicense, PH_COMP_AL_MFDFEVX);
  PH_ASSERT_NULL_DATA_PARAM(pMFCLicenseMAC, PH_COMP_AL_MFDFEVX);

  /* Log the information. */
  PH_LOG_HELPER_ADDSTRING(PH_LOG_LOGTYPE_INFO, bFunctionName);
  PH_LOG_HELPER_ADDPARAM_UINT8(PH_LOG_LOGTYPE_DEBUG, PH_LOG_VAR(bCommOption), &bCommOption);
  PH_LOG_HELPER_ADDPARAM_UINT8(PH_LOG_LOGTYPE_DEBUG, PH_LOG_VAR(bFileNo), &bFileNo);
  PH_LOG_HELPER_ADDPARAM_UINT8(PH_LOG_LOGTYPE_DEBUG, PH_LOG_VAR(bFileOption), &bFileOption);
  PH_LOG_HELPER_ADDPARAM_BUFFER(PH_LOG_LOGTYPE_DEBUG, PH_LOG_VAR(pMFCBlockList), pMFCBlockList,
      bMFCBlocksLen);
  PH_LOG_HELPER_ADDPARAM_UINT8(PH_LOG_LOGTYPE_DEBUG, PH_LOG_VAR(bMFCBlocksLen), &bMFCBlocksLen);
  PH_LOG_HELPER_ADDPARAM_UINT8(PH_LOG_LOGTYPE_DEBUG, PH_LOG_VAR(bRestoreSource), &bRestoreSource);
  PH_LOG_HELPER_ADDPARAM_BUFFER(PH_LOG_LOGTYPE_DEBUG, PH_LOG_VAR(pMFCLicense), pMFCLicense,
      bMFCLicenseLen);
  PH_LOG_HELPER_ADDPARAM_UINT8(PH_LOG_LOGTYPE_DEBUG, PH_LOG_VAR(bMFCLicenseLen), &bMFCLicenseLen);
  PH_LOG_HELPER_ADDPARAM_BUFFER(PH_LOG_LOGTYPE_DEBUG, PH_LOG_VAR(pMFCLicenseMAC), pMFCLicenseMAC,
      8);
  PH_LOG_HELPER_EXECUTE(PH_LOG_OPTION_CATEGORY_ENTER);

  /* Component Code Validation */
  if (PH_GET_COMPCODE(pDataParams) != PH_COMP_AL_MFDFEVX) {
    PH_LOG_HELPER_ADDSTRING(PH_LOG_LOGTYPE_INFO, bFunctionName);
    PH_LOG_HELPER_ADDPARAM_UINT16(PH_LOG_LOGTYPE_INFO, status_log, &status);
    PH_LOG_HELPER_EXECUTE(PH_LOG_OPTION_CATEGORY_LEAVE);
    return PH_ADD_COMPCODE_FIXED(PH_ERR_INVALID_DATA_PARAMS, PH_COMP_AL_MFDFEVX);
  }

  /* Perform operation on active layer */
  switch (PH_GET_COMPID(pDataParams)) {
#ifdef NXPBUILD__PHAL_MFDFEVX_SW
    case PHAL_MFDFEVX_SW_ID:
      status = phalMfdfEVx_Sw_CreateMFCMapping((phalMfdfEVx_Sw_DataParams_t *) pDataParams, bCommOption,
              bFileNo, bFileOption, pMFCBlockList,
              bMFCBlocksLen, bRestoreSource, pMFCLicense, bMFCLicenseLen, pMFCLicenseMAC);
      break;
#endif /* NXPBUILD__PHAL_MFDFEVX_SW */

    default:
      status = PH_ADD_COMPCODE_FIXED(PH_ERR_INVALID_DATA_PARAMS, PH_COMP_AL_MFDFEVX);
      break;
  }

  PH_LOG_HELPER_ADDSTRING(PH_LOG_LOGTYPE_INFO, bFunctionName);
  PH_LOG_HELPER_ADDPARAM_UINT16(PH_LOG_LOGTYPE_INFO, PH_LOG_VAR(status), &status);
  PH_LOG_HELPER_EXECUTE(PH_LOG_OPTION_CATEGORY_LEAVE);

  return status;
}

phStatus_t phalMfdfEVx_RestoreTransfer(void *pDataParams, uint8_t bCommOption,
    uint8_t bTargetFileNo, uint8_t bSourceFileNo)
{
  phStatus_t PH_MEMLOC_REM status;

  PH_LOG_HELPER_ALLOCATE_TEXT(bFunctionName, "phalMfdfEVx_RestoreTransfer");
  PH_LOG_HELPER_ALLOCATE_PARAMNAME(bCommOption);
  PH_LOG_HELPER_ALLOCATE_PARAMNAME(bTargetFileNo);
  PH_LOG_HELPER_ALLOCATE_PARAMNAME(bSourceFileNo);
  PH_LOG_HELPER_ALLOCATE_PARAMNAME(status);

  /* Validate the parameters. */
  PH_ASSERT_NULL_DATA_PARAM(pDataParams, PH_COMP_AL_MFDFEVX);

  /* Log the information. */
  PH_LOG_HELPER_ADDSTRING(PH_LOG_LOGTYPE_INFO, bFunctionName);
  PH_LOG_HELPER_ADDPARAM_UINT8(PH_LOG_LOGTYPE_DEBUG, bCommOption_log, &bCommOption);
  PH_LOG_HELPER_ADDPARAM_UINT8(PH_LOG_LOGTYPE_DEBUG, PH_LOG_VAR(bTargetFileNo), &bTargetFileNo);
  PH_LOG_HELPER_ADDPARAM_UINT8(PH_LOG_LOGTYPE_DEBUG, PH_LOG_VAR(bSourceFileNo), &bSourceFileNo);
  PH_LOG_HELPER_EXECUTE(PH_LOG_OPTION_CATEGORY_ENTER);

  /* Component Code Validation */
  if (PH_GET_COMPCODE(pDataParams) != PH_COMP_AL_MFDFEVX) {
    PH_LOG_HELPER_ADDSTRING(PH_LOG_LOGTYPE_INFO, bFunctionName);
    PH_LOG_HELPER_ADDPARAM_UINT16(PH_LOG_LOGTYPE_INFO, status_log, &status);
    PH_LOG_HELPER_EXECUTE(PH_LOG_OPTION_CATEGORY_LEAVE);
    return PH_ADD_COMPCODE_FIXED(PH_ERR_INVALID_DATA_PARAMS, PH_COMP_AL_MFDFEVX);
  }

  /* Perform operation on active layer */
  switch (PH_GET_COMPID(pDataParams)) {
#ifdef NXPBUILD__PHAL_MFDFEVX_SW
    case PHAL_MFDFEVX_SW_ID:
      status = phalMfdfEVx_Sw_RestoreTransfer((phalMfdfEVx_Sw_DataParams_t *) pDataParams, bCommOption,
              bTargetFileNo, bSourceFileNo);
      break;
#endif /* NXPBUILD__PHAL_MFDFEVX_SW */

    default:
      status = PH_ADD_COMPCODE_FIXED(PH_ERR_INVALID_DATA_PARAMS, PH_COMP_AL_MFDFEVX);
      break;
  }

  PH_LOG_HELPER_ADDSTRING(PH_LOG_LOGTYPE_INFO, bFunctionName);
  PH_LOG_HELPER_ADDPARAM_UINT16(PH_LOG_LOGTYPE_INFO, status_log, &status);
  PH_LOG_HELPER_EXECUTE(PH_LOG_OPTION_CATEGORY_LEAVE);

  return status;
}

#ifdef NXPBUILD__PHAL_MFDFEVX_NDA
phStatus_t phalMfdfEVx_RestrictMFCUpdate(void *pDataParams, uint8_t bOption, uint8_t *pMFCConfig,
    uint8_t bMFCConfigLen,
    uint8_t *pMFCLicense, uint8_t bMFCLicenseLen, uint8_t *pMFCLicenseMAC)
{
  phStatus_t PH_MEMLOC_REM status;

  PH_LOG_HELPER_ALLOCATE_TEXT(bFunctionName, "phalMfdfEVx_RestrictMFCUpdate");
  PH_LOG_HELPER_ALLOCATE_PARAMNAME(bOption);
  PH_LOG_HELPER_ALLOCATE_PARAMNAME(pMFCConfig);
  PH_LOG_HELPER_ALLOCATE_PARAMNAME(bMFCConfigLen);
  PH_LOG_HELPER_ALLOCATE_PARAMNAME(pMFCLicense);
  PH_LOG_HELPER_ALLOCATE_PARAMNAME(bMFCLicenseLen);
  PH_LOG_HELPER_ALLOCATE_PARAMNAME(pMFCLicenseMAC);
  PH_LOG_HELPER_ALLOCATE_PARAMNAME(status);

  /* Validate the parameters. */
  PH_ASSERT_NULL_DATA_PARAM(pDataParams, PH_COMP_AL_MFDFEVX);
  PH_ASSERT_NULL_DATA_PARAM(pMFCConfig, PH_COMP_AL_MFDFEVX);
  PH_ASSERT_NULL_DATA_PARAM(pMFCLicense, PH_COMP_AL_MFDFEVX);
  PH_ASSERT_NULL_DATA_PARAM(pMFCLicenseMAC, PH_COMP_AL_MFDFEVX);

  /* Log the information. */
  PH_LOG_HELPER_ADDSTRING(PH_LOG_LOGTYPE_INFO, bFunctionName);
  PH_LOG_HELPER_ADDPARAM_UINT8(PH_LOG_LOGTYPE_DEBUG, PH_LOG_VAR(bOption), &bOption);
  PH_LOG_HELPER_ADDPARAM_BUFFER(PH_LOG_LOGTYPE_DEBUG, PH_LOG_VAR(pMFCConfig), pMFCConfig,
      bMFCConfigLen);
  PH_LOG_HELPER_ADDPARAM_UINT8(PH_LOG_LOGTYPE_DEBUG, PH_LOG_VAR(bMFCConfigLen), &bMFCConfigLen);
  PH_LOG_HELPER_ADDPARAM_BUFFER(PH_LOG_LOGTYPE_DEBUG, PH_LOG_VAR(pMFCLicense), pMFCLicense,
      bMFCLicenseLen);
  PH_LOG_HELPER_ADDPARAM_UINT8(PH_LOG_LOGTYPE_DEBUG, PH_LOG_VAR(bMFCLicenseLen), &bMFCLicenseLen);
  PH_LOG_HELPER_ADDPARAM_BUFFER(PH_LOG_LOGTYPE_DEBUG, PH_LOG_VAR(pMFCLicenseMAC), pMFCLicenseMAC,
      8);
  PH_LOG_HELPER_EXECUTE(PH_LOG_OPTION_CATEGORY_ENTER);

  /* Component Code Validation */
  if (PH_GET_COMPCODE(pDataParams) != PH_COMP_AL_MFDFEVX) {
    PH_LOG_HELPER_ADDSTRING(PH_LOG_LOGTYPE_INFO, bFunctionName);
    PH_LOG_HELPER_ADDPARAM_UINT16(PH_LOG_LOGTYPE_INFO, status_log, &status);
    PH_LOG_HELPER_EXECUTE(PH_LOG_OPTION_CATEGORY_LEAVE);
    return PH_ADD_COMPCODE_FIXED(PH_ERR_INVALID_DATA_PARAMS, PH_COMP_AL_MFDFEVX);
  }

  /* Perform operation on active layer */
  switch (PH_GET_COMPID(pDataParams)) {
#ifdef NXPBUILD__PHAL_MFDFEVX_SW
    case PHAL_MFDFEVX_SW_ID:
      status = phalMfdfEVx_Sw_RestrictMFCUpdate((phalMfdfEVx_Sw_DataParams_t *) pDataParams, bOption,
              pMFCConfig,
              bMFCConfigLen, pMFCLicense, bMFCLicenseLen, pMFCLicenseMAC);
      break;
#endif /* NXPBUILD__PHAL_MFDFEVX_SW */

    default:
      status = PH_ADD_COMPCODE_FIXED(PH_ERR_INVALID_DATA_PARAMS, PH_COMP_AL_MFDFEVX);
      break;
  }

  PH_LOG_HELPER_ADDSTRING(PH_LOG_LOGTYPE_INFO, bFunctionName);
  PH_LOG_HELPER_ADDPARAM_UINT16(PH_LOG_LOGTYPE_INFO, status_log, &status);
  PH_LOG_HELPER_EXECUTE(PH_LOG_OPTION_CATEGORY_LEAVE);

  return status;
}

/* MIFARE DESFire EVX POST Delivery Configuration function. ---------------------------------------------------------------------------- */
phStatus_t phalMfdfEVx_AuthenticatePDC(void *pDataParams, uint8_t bRfu, uint8_t bKeyNoCard,
    uint8_t wKeyNo, uint16_t wKeyVer,
    uint8_t bUpgradeInfo)
{
  phStatus_t PH_MEMLOC_REM status;

  PH_LOG_HELPER_ALLOCATE_TEXT(bFunctionName, "phalMfdfEVx_AuthenticatePDC");
  PH_LOG_HELPER_ALLOCATE_PARAMNAME(bKeyNoCard);
  PH_LOG_HELPER_ALLOCATE_PARAMNAME(wKeyNo);
  PH_LOG_HELPER_ALLOCATE_PARAMNAME(wKeyVer);
  PH_LOG_HELPER_ALLOCATE_PARAMNAME(bUpgradeInfo);
  PH_LOG_HELPER_ALLOCATE_PARAMNAME(status);
  PH_LOG_HELPER_ADDSTRING(PH_LOG_LOGTYPE_INFO, bFunctionName);
  PH_LOG_HELPER_ADDPARAM_UINT8(PH_LOG_LOGTYPE_DEBUG, bKeyNoCard_log, &bKeyNoCard);
  PH_LOG_HELPER_ADDPARAM_UINT8(PH_LOG_LOGTYPE_DEBUG, wKeyNo_log, &wKeyNo);
  PH_LOG_HELPER_ADDPARAM_UINT16(PH_LOG_LOGTYPE_DEBUG, wKeyVer_log, &wKeyVer);
  PH_LOG_HELPER_ADDPARAM_UINT8(PH_LOG_LOGTYPE_DEBUG, bUpgradeInfo_log, &bUpgradeInfo);
  PH_LOG_HELPER_EXECUTE(PH_LOG_OPTION_CATEGORY_ENTER);

  /* Validate the parameters */
  PH_ASSERT_NULL_DATA_PARAM(pDataParams, PH_COMP_AL_MFDFEVX);

  /* Component Code Validation */
  if (PH_GET_COMPCODE(pDataParams) != PH_COMP_AL_MFDFEVX) {
    status = PH_ADD_COMPCODE_FIXED(PH_ERR_INVALID_DATA_PARAMS, PH_COMP_AL_MFDFEVX);

    PH_LOG_HELPER_ADDSTRING(PH_LOG_LOGTYPE_INFO, bFunctionName);
    PH_LOG_HELPER_ADDPARAM_UINT16(PH_LOG_LOGTYPE_INFO, status_log, &status);
    PH_LOG_HELPER_EXECUTE(PH_LOG_OPTION_CATEGORY_LEAVE);

    return status;
  }

  /* Perform operation on active layer */
  switch (PH_GET_COMPID(pDataParams)) {
#ifdef NXPBUILD__PHAL_MFDFEVX_SW
    case PHAL_MFDFEVX_SW_ID:
      status = phalMfdfEVx_Sw_AuthenticatePDC((phalMfdfEVx_Sw_DataParams_t *) pDataParams, bRfu,
              bKeyNoCard, wKeyNo,
              wKeyVer, bUpgradeInfo);
      break;
#endif /* NXPBUILD__PHAL_MFDFEVX_SW */

    default:
      status = PH_ADD_COMPCODE_FIXED(PH_ERR_INVALID_DATA_PARAMS, PH_COMP_AL_MFDFEVX);
      break;
  }

  PH_LOG_HELPER_ADDSTRING(PH_LOG_LOGTYPE_INFO, bFunctionName);
  PH_LOG_HELPER_ADDPARAM_UINT16(PH_LOG_LOGTYPE_INFO, status_log, &status);
  PH_LOG_HELPER_EXECUTE(PH_LOG_OPTION_CATEGORY_LEAVE);

  /* Resetting the state. */
  PH_CHECK_SUCCESS(phalMfdfEVx_ResetAuthentication(pDataParams));

  return status;
}
#endif /* NXPBUILD__PHAL_MFDFEVX_NDA */

/* MIFARE DESFire EVX Miscellaneous functions. ----------------------------------------------------------------------------------------- */
phStatus_t phalMfdfEVx_GetConfig(void *pDataParams, uint16_t wConfig, uint16_t *pValue)
{
  phStatus_t PH_MEMLOC_REM status;

  PH_LOG_HELPER_ALLOCATE_TEXT(bFunctionName, "phalMfdfEVx_GetConfig");
  PH_LOG_HELPER_ALLOCATE_PARAMNAME(wConfig);
  PH_LOG_HELPER_ALLOCATE_PARAMNAME(pValue);
  PH_LOG_HELPER_ALLOCATE_PARAMNAME(status);
  PH_LOG_HELPER_ADDSTRING(PH_LOG_LOGTYPE_INFO, bFunctionName);
  PH_LOG_HELPER_ADDPARAM_UINT16(PH_LOG_LOGTYPE_DEBUG, wConfig_log, &wConfig);
  PH_LOG_HELPER_EXECUTE(PH_LOG_OPTION_CATEGORY_ENTER);

  /* Validate the parameters */
  PH_ASSERT_NULL_DATA_PARAM(pDataParams, PH_COMP_AL_MFDFEVX);
  PH_ASSERT_NULL_PARAM(pValue, PH_COMP_AL_MFDFEVX);

  /* Check data parameters */
  if (PH_GET_COMPCODE(pDataParams) != PH_COMP_AL_MFDFEVX) {
    PH_LOG_HELPER_ADDSTRING(PH_LOG_LOGTYPE_INFO, bFunctionName);
    PH_LOG_HELPER_ADDPARAM_UINT16(PH_LOG_LOGTYPE_INFO, status_log, &status);
    PH_LOG_HELPER_EXECUTE(PH_LOG_OPTION_CATEGORY_LEAVE);
    return PH_ADD_COMPCODE_FIXED(PH_ERR_INVALID_DATA_PARAMS, PH_COMP_AL_MFDFEVX);
  }

  /* Perform operation on active layer */
  switch (PH_GET_COMPID(pDataParams)) {
#ifdef NXPBUILD__PHAL_MFDFEVX_SW
    case PHAL_MFDFEVX_SW_ID:
      status = phalMfdfEVx_Sw_GetConfig((phalMfdfEVx_Sw_DataParams_t *) pDataParams, wConfig, pValue);
      break;
#endif /* NXPBUILD__PHAL_MFDFEVX_SW */

    default:
      status = PH_ADD_COMPCODE_FIXED(PH_ERR_INVALID_DATA_PARAMS, PH_COMP_AL_MFDFEVX);
      break;
  }

  PH_LOG_HELPER_ADDSTRING(PH_LOG_LOGTYPE_INFO, bFunctionName);
#ifdef NXPBUILD__PH_LOG
  if ((status & PH_ERR_MASK) == PH_ERR_SUCCESS) {
    PH_LOG_HELPER_ADDPARAM_UINT16(PH_LOG_LOGTYPE_DEBUG, pValue_log, pValue);
  }
#endif
  PH_LOG_HELPER_ADDPARAM_UINT16(PH_LOG_LOGTYPE_INFO, status_log, &status);
  PH_LOG_HELPER_EXECUTE(PH_LOG_OPTION_CATEGORY_LEAVE);

  return status;
}

phStatus_t phalMfdfEVx_SetConfig(void *pDataParams, uint16_t wConfig, uint16_t wValue)
{
  phStatus_t PH_MEMLOC_REM status;

  PH_LOG_HELPER_ALLOCATE_TEXT(bFunctionName, "phalMfdfEVx_SetConfig");
  PH_LOG_HELPER_ALLOCATE_PARAMNAME(wConfig);
  PH_LOG_HELPER_ALLOCATE_PARAMNAME(wValue);
  PH_LOG_HELPER_ALLOCATE_PARAMNAME(status);
  PH_LOG_HELPER_ADDSTRING(PH_LOG_LOGTYPE_INFO, bFunctionName);
  PH_LOG_HELPER_ADDPARAM_UINT16(PH_LOG_LOGTYPE_DEBUG, wConfig_log, &wConfig);
  PH_LOG_HELPER_ADDPARAM_UINT16(PH_LOG_LOGTYPE_DEBUG, wValue_log, &wValue);
  PH_LOG_HELPER_EXECUTE(PH_LOG_OPTION_CATEGORY_ENTER);

  /* Validate the parameters */
  PH_ASSERT_NULL_DATA_PARAM(pDataParams, PH_COMP_AL_MFDFEVX);

  /* Check data parameters */
  if (PH_GET_COMPCODE(pDataParams) != PH_COMP_AL_MFDFEVX) {
    PH_LOG_HELPER_ADDSTRING(PH_LOG_LOGTYPE_INFO, bFunctionName);
    PH_LOG_HELPER_ADDPARAM_UINT16(PH_LOG_LOGTYPE_INFO, status_log, &status);
    PH_LOG_HELPER_EXECUTE(PH_LOG_OPTION_CATEGORY_LEAVE);
    return PH_ADD_COMPCODE_FIXED(PH_ERR_INVALID_DATA_PARAMS, PH_COMP_AL_MFDFEVX);
  }

  /* Perform operation on active layer */
  switch (PH_GET_COMPID(pDataParams)) {
#ifdef NXPBUILD__PHAL_MFDFEVX_SW
    case PHAL_MFDFEVX_SW_ID:
      status = phalMfdfEVx_Sw_SetConfig((phalMfdfEVx_Sw_DataParams_t *) pDataParams, wConfig, wValue);
      break;
#endif /* NXPBUILD__PHAL_MFDFEVX_SW */

    default:
      status = PH_ADD_COMPCODE_FIXED(PH_ERR_INVALID_DATA_PARAMS, PH_COMP_AL_MFDFEVX);
      break;
  }

  PH_LOG_HELPER_ADDSTRING(PH_LOG_LOGTYPE_INFO, bFunctionName);

  PH_LOG_HELPER_ADDPARAM_UINT16(PH_LOG_LOGTYPE_INFO, status_log, &status);
  PH_LOG_HELPER_EXECUTE(PH_LOG_OPTION_CATEGORY_LEAVE);

  return status;
}

phStatus_t phalMfdfEVx_ResetAuthentication(void *pDataParams)
{
  phStatus_t PH_MEMLOC_REM status;

  PH_LOG_HELPER_ALLOCATE_TEXT(bFunctionName, "phalMfdfEVx_ResetAuthentication");
  PH_LOG_HELPER_ALLOCATE_PARAMNAME(status);
  PH_LOG_HELPER_ADDSTRING(PH_LOG_LOGTYPE_INFO, bFunctionName);
  PH_LOG_HELPER_EXECUTE(PH_LOG_OPTION_CATEGORY_ENTER);

  /* Validate the parameters */
  PH_ASSERT_NULL_DATA_PARAM(pDataParams, PH_COMP_AL_MFDFEVX);

  /* Check data parameters */
  if (PH_GET_COMPCODE(pDataParams) != PH_COMP_AL_MFDFEVX) {
    PH_LOG_HELPER_ADDSTRING(PH_LOG_LOGTYPE_INFO, bFunctionName);
    PH_LOG_HELPER_ADDPARAM_UINT16(PH_LOG_LOGTYPE_INFO, status_log, &status);
    PH_LOG_HELPER_EXECUTE(PH_LOG_OPTION_CATEGORY_LEAVE);
    return PH_ADD_COMPCODE_FIXED(PH_ERR_INVALID_DATA_PARAMS, PH_COMP_AL_MFDFEVX);
  }

  /* Perform operation on active layer */
  switch (PH_GET_COMPID(pDataParams)) {
#ifdef NXPBUILD__PHAL_MFDFEVX_SW
    case PHAL_MFDFEVX_SW_ID:
      status = phalMfdfEVx_Sw_ResetAuthentication((phalMfdfEVx_Sw_DataParams_t *) pDataParams);
      break;
#endif /* NXPBUILD__PHAL_MFDFEVX_SW */

    default:
      status = PH_ADD_COMPCODE_FIXED(PH_ERR_INVALID_DATA_PARAMS, PH_COMP_AL_MFDFEVX);
      break;
  }
  PH_LOG_HELPER_ADDSTRING(PH_LOG_LOGTYPE_INFO, bFunctionName);

  PH_LOG_HELPER_ADDPARAM_UINT16(PH_LOG_LOGTYPE_INFO, status_log, &status);
  PH_LOG_HELPER_EXECUTE(PH_LOG_OPTION_CATEGORY_LEAVE);

  return status;
}

#ifdef NXPBUILD__PHAL_MFDFEVX_NDA
phStatus_t phalMfdfEVx_GenerateDAMEncKey(void *pDataParams, uint16_t wKeyNoDAMEnc,
    uint16_t wKeyVerDAMEnc, uint16_t wKeyNoAppDAMDefault,
    uint16_t wKeyVerAppDAMDefault, uint8_t bAppDAMDefaultKeyVer, uint8_t *pDAMEncKey)
{
  phStatus_t PH_MEMLOC_REM status;

  PH_LOG_HELPER_ALLOCATE_TEXT(bFunctionName, "phalMfdfEVx_GenerateDAMEncKey");
  PH_LOG_HELPER_ALLOCATE_PARAMNAME(wKeyNoDAMEnc);
  PH_LOG_HELPER_ALLOCATE_PARAMNAME(wKeyVerDAMEnc);
  PH_LOG_HELPER_ALLOCATE_PARAMNAME(wKeyNoAppDAMDefault);
  PH_LOG_HELPER_ALLOCATE_PARAMNAME(wKeyVerAppDAMDefault);
  PH_LOG_HELPER_ALLOCATE_PARAMNAME(bAppDAMDefaultKeyVer);
  PH_LOG_HELPER_ALLOCATE_PARAMNAME(pDAMEncKey);
  PH_LOG_HELPER_ALLOCATE_PARAMNAME(status);
  PH_LOG_HELPER_ADDSTRING(PH_LOG_LOGTYPE_INFO, bFunctionName);
  PH_LOG_HELPER_ADDPARAM_UINT16(PH_LOG_LOGTYPE_DEBUG, wKeyNoDAMEnc_log, &wKeyNoDAMEnc);
  PH_LOG_HELPER_ADDPARAM_UINT16(PH_LOG_LOGTYPE_DEBUG, wKeyVerDAMEnc_log, &wKeyVerDAMEnc);
  PH_LOG_HELPER_ADDPARAM_UINT16(PH_LOG_LOGTYPE_DEBUG, wKeyNoAppDAMDefault_log,
      &wKeyNoAppDAMDefault);
  PH_LOG_HELPER_ADDPARAM_UINT16(PH_LOG_LOGTYPE_DEBUG, wKeyVerAppDAMDefault_log,
      &wKeyVerAppDAMDefault);
  PH_LOG_HELPER_ADDPARAM_UINT8(PH_LOG_LOGTYPE_DEBUG, bAppDAMDefaultKeyVer_log,
      &bAppDAMDefaultKeyVer);
  PH_LOG_HELPER_EXECUTE(PH_LOG_OPTION_CATEGORY_ENTER);

  /* Validate the parameters */
  PH_ASSERT_NULL_DATA_PARAM(pDataParams, PH_COMP_AL_MFDFEVX);
  PH_ASSERT_NULL_PARAM(pDAMEncKey, PH_COMP_AL_MFDFEVX);

  /* Check data parameters */
  if (PH_GET_COMPCODE(pDataParams) != PH_COMP_AL_MFDFEVX) {
    PH_LOG_HELPER_ADDSTRING(PH_LOG_LOGTYPE_INFO, bFunctionName);
    PH_LOG_HELPER_ADDPARAM_UINT16(PH_LOG_LOGTYPE_INFO, status_log, &status);
    PH_LOG_HELPER_EXECUTE(PH_LOG_OPTION_CATEGORY_LEAVE);
    return PH_ADD_COMPCODE_FIXED(PH_ERR_INVALID_DATA_PARAMS, PH_COMP_AL_MFDFEVX);
  }

  /* Perform operation on active layer */
  switch (PH_GET_COMPID(pDataParams)) {
#ifdef NXPBUILD__PHAL_MFDFEVX_SW
    case PHAL_MFDFEVX_SW_ID:
      status = phalMfdfEVx_Sw_GenerateDAMEncKey((phalMfdfEVx_Sw_DataParams_t *) pDataParams,
              wKeyNoDAMEnc, wKeyVerDAMEnc,
              wKeyNoAppDAMDefault, wKeyVerAppDAMDefault, bAppDAMDefaultKeyVer, pDAMEncKey);
      break;
#endif /* NXPBUILD__PHAL_MFDFEVX_SW */

    default:
      status = PH_ADD_COMPCODE_FIXED(PH_ERR_INVALID_DATA_PARAMS, PH_COMP_AL_MFDFEVX);
      break;
  }

  PH_LOG_HELPER_ADDSTRING(PH_LOG_LOGTYPE_INFO, bFunctionName);
  PH_LOG_HELPER_ADDPARAM_BUFFER(PH_LOG_LOGTYPE_DEBUG, pDAMEncKey_log, pDAMEncKey, 32);
  PH_LOG_HELPER_ADDPARAM_UINT16(PH_LOG_LOGTYPE_INFO, status_log, &status);
  PH_LOG_HELPER_EXECUTE(PH_LOG_OPTION_CATEGORY_LEAVE);

  return status;
}

phStatus_t phalMfdfEVx_GenerateDAMMAC(void *pDataParams, uint8_t bOption, uint16_t wKeyNoDAMMAC,
    uint16_t wKeyVerDAMMAC, uint8_t *pAid,
    uint8_t *pDamParams, uint8_t bKeySettings1, uint8_t bKeySettings2, uint8_t bKeySettings3,
    uint8_t  *pKeySetValues, uint8_t *pISOFileId,
    uint8_t *pISODFName, uint8_t bISODFNameLen, uint8_t *pEncK, uint8_t *pDAMMAC)
{
  phStatus_t PH_MEMLOC_REM status;

  PH_LOG_HELPER_ALLOCATE_TEXT(bFunctionName, "phalMfdfEVx_GenerateDAMMAC");
  PH_LOG_HELPER_ALLOCATE_PARAMNAME(bOption);
  PH_LOG_HELPER_ALLOCATE_PARAMNAME(wKeyNoDAMMAC);
  PH_LOG_HELPER_ALLOCATE_PARAMNAME(wKeyVerDAMMAC);
  PH_LOG_HELPER_ALLOCATE_PARAMNAME(pAid);
  PH_LOG_HELPER_ALLOCATE_PARAMNAME(pDamParams);
  PH_LOG_HELPER_ALLOCATE_PARAMNAME(bKeySettings1);
  PH_LOG_HELPER_ALLOCATE_PARAMNAME(bKeySettings2);
  PH_LOG_HELPER_ALLOCATE_PARAMNAME(bKeySettings3);
  PH_LOG_HELPER_ALLOCATE_PARAMNAME(pKeySetValues);
  PH_LOG_HELPER_ALLOCATE_PARAMNAME(pISOFileId);
  PH_LOG_HELPER_ALLOCATE_PARAMNAME(pISODFName);
  PH_LOG_HELPER_ALLOCATE_PARAMNAME(bISODFNameLen);
  PH_LOG_HELPER_ALLOCATE_PARAMNAME(pEncK);
  PH_LOG_HELPER_ALLOCATE_PARAMNAME(pDAMMAC);
  PH_LOG_HELPER_ALLOCATE_PARAMNAME(status);
  PH_LOG_HELPER_ADDSTRING(PH_LOG_LOGTYPE_INFO, bFunctionName);
  PH_LOG_HELPER_ADDPARAM_UINT8(PH_LOG_LOGTYPE_DEBUG, bOption_log, &bOption);
  PH_LOG_HELPER_ADDPARAM_UINT16(PH_LOG_LOGTYPE_DEBUG, wKeyNoDAMMAC_log, &wKeyNoDAMMAC);
  PH_LOG_HELPER_ADDPARAM_UINT16(PH_LOG_LOGTYPE_DEBUG, wKeyVerDAMMAC_log, &wKeyVerDAMMAC);
  PH_LOG_HELPER_ADDPARAM_BUFFER(PH_LOG_LOGTYPE_DEBUG, pAid_log, pAid, 3);

  if (!(bOption & PHAL_MFDFEVX_GENERATE_DAMMAC_DELETE_APPLICATION)) {
    PH_LOG_HELPER_ADDPARAM_UINT8(PH_LOG_LOGTYPE_DEBUG, bKeySettings1_log, &bKeySettings1);
    PH_LOG_HELPER_ADDPARAM_UINT8(PH_LOG_LOGTYPE_DEBUG, bKeySettings2_log, &bKeySettings2);
    PH_LOG_HELPER_ADDPARAM_UINT8(PH_LOG_LOGTYPE_DEBUG, bKeySettings3_log, &bKeySettings3);
    PH_LOG_HELPER_ADDPARAM_UINT8(PH_LOG_LOGTYPE_DEBUG, bISODFNameLen_log, &bISODFNameLen);
    PH_LOG_HELPER_ADDPARAM_BUFFER(PH_LOG_LOGTYPE_DEBUG, pDamParams_log, pDamParams, 4);
    if ((bKeySettings2 & PHAL_MFDFEVX_KEYSETT3_PRESENT) &&
        (bKeySettings3 & PHAL_MFDFEVX_KEYSETVALUES_PRESENT)) {
      PH_LOG_HELPER_ADDPARAM_BUFFER(PH_LOG_LOGTYPE_DEBUG, pKeySetValues_log, pKeySetValues, 4);
    }
    if (bOption & 0x01) {
      PH_LOG_HELPER_ADDPARAM_BUFFER(PH_LOG_LOGTYPE_DEBUG, pISOFileId_log, pISOFileId, 2);
    }
    if (bOption & 0x02) {
      PH_LOG_HELPER_ADDPARAM_BUFFER(PH_LOG_LOGTYPE_DEBUG, pISODFName_log, pISODFName, bISODFNameLen);
    }
    PH_LOG_HELPER_ADDPARAM_BUFFER(PH_LOG_LOGTYPE_DEBUG, pEncK_log, pEncK, 32);
  }
  PH_LOG_HELPER_EXECUTE(PH_LOG_OPTION_CATEGORY_ENTER);

  /* Validate the parameters */
  PH_ASSERT_NULL_DATA_PARAM(pDataParams, PH_COMP_AL_MFDFEVX);
  PH_ASSERT_NULL_PARAM(pAid, PH_COMP_AL_MFDFEVX);
  if (!(bOption & PHAL_MFDFEVX_GENERATE_DAMMAC_DELETE_APPLICATION)) {
    PH_ASSERT_NULL_PARAM(pDamParams, PH_COMP_AL_MFDFEVX);
  }
  /* if((bKeySettings2 & PHAL_MFDFEVX_KEYSETT3_PRESENT) && (bKeySettings3 & PHAL_MFDFEVX_KEYSETVALUES_PRESENT))
      PH_ASSERT_NULL_PARAM (pKeySetValues); */
  if (bOption & 0x01) {
    PH_ASSERT_NULL_PARAM(pISOFileId, PH_COMP_AL_MFDFEVX);
  }
  if (bOption & 0x02) {
    PH_ASSERT_NULL_PARAM(pISODFName, PH_COMP_AL_MFDFEVX);
  }
  if (!(bOption & PHAL_MFDFEVX_GENERATE_DAMMAC_DELETE_APPLICATION)) {
    PH_ASSERT_NULL_PARAM(pEncK, PH_COMP_AL_MFDFEVX);
  }

  /* Check data parameters */
  if (PH_GET_COMPCODE(pDataParams) != PH_COMP_AL_MFDFEVX) {
    PH_LOG_HELPER_ADDSTRING(PH_LOG_LOGTYPE_INFO, bFunctionName);
    PH_LOG_HELPER_ADDPARAM_UINT16(PH_LOG_LOGTYPE_INFO, status_log, &status);
    PH_LOG_HELPER_EXECUTE(PH_LOG_OPTION_CATEGORY_LEAVE);
    return PH_ADD_COMPCODE_FIXED(PH_ERR_INVALID_DATA_PARAMS, PH_COMP_AL_MFDFEVX);
  }

  /* Perform operation on active layer */
  switch (PH_GET_COMPID(pDataParams)) {
#ifdef NXPBUILD__PHAL_MFDFEVX_SW
    case PHAL_MFDFEVX_SW_ID:
      status = phalMfdfEVx_Sw_GenerateDAMMAC((phalMfdfEVx_Sw_DataParams_t *) pDataParams, bOption,
              wKeyNoDAMMAC, wKeyVerDAMMAC,
              pAid, pDamParams, bKeySettings1, bKeySettings2, bKeySettings3, pKeySetValues, pISOFileId,
              pISODFName, bISODFNameLen,
              pEncK, pDAMMAC);
      break;
#endif /* NXPBUILD__PHAL_MFDFEVX_SW */

    default:
      status = PH_ADD_COMPCODE_FIXED(PH_ERR_INVALID_DATA_PARAMS, PH_COMP_AL_MFDFEVX);
      break;
  }

  PH_LOG_HELPER_ADDSTRING(PH_LOG_LOGTYPE_INFO, bFunctionName);
  PH_LOG_HELPER_ADDPARAM_BUFFER(PH_LOG_LOGTYPE_DEBUG, pDAMMAC_log, pDAMMAC, 8);
  PH_LOG_HELPER_ADDPARAM_UINT16(PH_LOG_LOGTYPE_INFO, status_log, &status);
  PH_LOG_HELPER_EXECUTE(PH_LOG_OPTION_CATEGORY_LEAVE);

  return status;
}

phStatus_t phalMfdfEVx_GenerateDAMMACSetConfig(void   *pDataParams, uint16_t wKeyNoDAMMAC,
    uint16_t wKeyVerDAMMAC, uint16_t wOldDFNameLen,
    uint8_t *pOldISODFName, uint16_t wNewDFNameLen, uint8_t *pNewISODFName, uint8_t *pDAMMAC)
{
  phStatus_t PH_MEMLOC_REM status;

  PH_LOG_HELPER_ALLOCATE_TEXT(bFunctionName, "phalMfdfEVx_GenerateDAMMACSetConfig");
  PH_LOG_HELPER_ALLOCATE_PARAMNAME(wKeyNoDAMMAC);
  PH_LOG_HELPER_ALLOCATE_PARAMNAME(wKeyVerDAMMAC);
  PH_LOG_HELPER_ALLOCATE_PARAMNAME(wOldDFNameLen);
  PH_LOG_HELPER_ALLOCATE_PARAMNAME(wNewDFNameLen);
  PH_LOG_HELPER_ALLOCATE_PARAMNAME(pDAMMAC);
  PH_LOG_HELPER_ALLOCATE_PARAMNAME(status);
  PH_LOG_HELPER_ADDSTRING(PH_LOG_LOGTYPE_INFO, bFunctionName);
  PH_LOG_HELPER_ADDPARAM_UINT16(PH_LOG_LOGTYPE_DEBUG, wKeyNoDAMMAC_log, &wKeyNoDAMMAC);
  PH_LOG_HELPER_ADDPARAM_UINT16(PH_LOG_LOGTYPE_DEBUG, wKeyVerDAMMAC_log, &wKeyVerDAMMAC);
  PH_LOG_HELPER_ADDPARAM_UINT16(PH_LOG_LOGTYPE_DEBUG, wOldDFNameLen_log, &wOldDFNameLen);
  PH_LOG_HELPER_ADDPARAM_UINT16(PH_LOG_LOGTYPE_DEBUG, wNewDFNameLen_log, &wNewDFNameLen);
  PH_LOG_HELPER_EXECUTE(PH_LOG_OPTION_CATEGORY_ENTER);

  /* Validate the parameters */
  PH_ASSERT_NULL_DATA_PARAM(pDataParams, PH_COMP_AL_MFDFEVX);
  PH_ASSERT_NULL_PARAM(pOldISODFName, PH_COMP_AL_MFDFEVX);
  PH_ASSERT_NULL_PARAM(pNewISODFName, PH_COMP_AL_MFDFEVX);
  PH_ASSERT_NULL_PARAM(pDAMMAC, PH_COMP_AL_MFDFEVX);

  /* Check data parameters */
  if (PH_GET_COMPCODE(pDataParams) != PH_COMP_AL_MFDFEVX) {
    PH_LOG_HELPER_ADDSTRING(PH_LOG_LOGTYPE_INFO, bFunctionName);
    PH_LOG_HELPER_ADDPARAM_UINT16(PH_LOG_LOGTYPE_INFO, status_log, &status);
    PH_LOG_HELPER_EXECUTE(PH_LOG_OPTION_CATEGORY_LEAVE);
    return PH_ADD_COMPCODE_FIXED(PH_ERR_INVALID_DATA_PARAMS, PH_COMP_AL_MFDFEVX);
  }

  /* Perform operation on active layer */
  switch (PH_GET_COMPID(pDataParams)) {
#ifdef NXPBUILD__PHAL_MFDFEVX_SW
    case PHAL_MFDFEVX_SW_ID:
      status = phalMfdfEVx_Sw_GenerateDAMMACSetConfig((phalMfdfEVx_Sw_DataParams_t *) pDataParams,
              wKeyNoDAMMAC,
              wKeyVerDAMMAC, wOldDFNameLen, pOldISODFName, wNewDFNameLen, pNewISODFName, pDAMMAC);
      break;
#endif /* NXPBUILD__PHAL_MFDFEVX_SW */

    default:
      status = PH_ADD_COMPCODE_FIXED(PH_ERR_INVALID_DATA_PARAMS, PH_COMP_AL_MFDFEVX);
      break;
  }

  PH_LOG_HELPER_ADDSTRING(PH_LOG_LOGTYPE_INFO, bFunctionName);
  PH_LOG_HELPER_ADDPARAM_BUFFER(PH_LOG_LOGTYPE_DEBUG, pDAMMAC_log, pDAMMAC, 8);
  PH_LOG_HELPER_ADDPARAM_UINT16(PH_LOG_LOGTYPE_INFO, status_log, &status);
  PH_LOG_HELPER_EXECUTE(PH_LOG_OPTION_CATEGORY_LEAVE);

  return status;
}

phStatus_t phalMfdfEVx_CalculateTMV(void *pDataParams, uint16_t wOption, uint16_t wKeyNoTMACKey,
    uint16_t wKeyVerTMACKey,
    uint16_t wRamKeyNo, uint16_t wRamKeyVer, uint8_t *pDivInput, uint8_t bDivInputLen, uint8_t *pTMC,
    uint8_t *pUid,
    uint8_t bUidLen, uint8_t *pTMI, uint32_t dwTMILen, uint8_t *pTMV)
{
  phStatus_t PH_MEMLOC_REM status;

  PH_LOG_HELPER_ALLOCATE_TEXT(bFunctionName, "phalMfdfEVx_CalculateTMV");
  PH_LOG_HELPER_ALLOCATE_PARAMNAME(wOption);
  PH_LOG_HELPER_ALLOCATE_PARAMNAME(wKeyNoTMACKey);
  PH_LOG_HELPER_ALLOCATE_PARAMNAME(wKeyVerTMACKey);
  PH_LOG_HELPER_ALLOCATE_PARAMNAME(wRamKeyNo);
  PH_LOG_HELPER_ALLOCATE_PARAMNAME(wRamKeyVer);
  PH_LOG_HELPER_ALLOCATE_PARAMNAME(pDivInput);
  PH_LOG_HELPER_ALLOCATE_PARAMNAME(bDivInputLen);
  PH_LOG_HELPER_ALLOCATE_PARAMNAME(pTMC);
  PH_LOG_HELPER_ALLOCATE_PARAMNAME(pUid);
  PH_LOG_HELPER_ALLOCATE_PARAMNAME(bUidLen);
  PH_LOG_HELPER_ALLOCATE_PARAMNAME(pTMI);
  PH_LOG_HELPER_ALLOCATE_PARAMNAME(dwTMILen);
  PH_LOG_HELPER_ALLOCATE_PARAMNAME(pTMV);
  PH_LOG_HELPER_ALLOCATE_PARAMNAME(status);
  PH_LOG_HELPER_ADDSTRING(PH_LOG_LOGTYPE_INFO, bFunctionName);
  PH_LOG_HELPER_ADDPARAM_UINT16(PH_LOG_LOGTYPE_DEBUG, wOption_log, &wOption);
  PH_LOG_HELPER_ADDPARAM_UINT16(PH_LOG_LOGTYPE_DEBUG, wKeyNoTMACKey_log, &wKeyNoTMACKey);
  PH_LOG_HELPER_ADDPARAM_UINT16(PH_LOG_LOGTYPE_DEBUG, wKeyVerTMACKey_log, &wKeyVerTMACKey);
  PH_LOG_HELPER_ADDPARAM_UINT16(PH_LOG_LOGTYPE_DEBUG, wRamKeyNo_log, &wRamKeyNo);
  PH_LOG_HELPER_ADDPARAM_UINT16(PH_LOG_LOGTYPE_DEBUG, wRamKeyVer_log, &wRamKeyVer);
  PH_LOG_HELPER_ADDPARAM_UINT8(PH_LOG_LOGTYPE_DEBUG, bDivInputLen_log, &bDivInputLen);
  PH_LOG_HELPER_ADDPARAM_UINT8(PH_LOG_LOGTYPE_DEBUG, bUidLen_log, &bUidLen);
  PH_LOG_HELPER_ADDPARAM_UINT32(PH_LOG_LOGTYPE_DEBUG, dwTMILen_log, &dwTMILen);
  PH_LOG_HELPER_ADDPARAM_BUFFER(PH_LOG_LOGTYPE_DEBUG, pDivInput_log, pDivInput, bDivInputLen);
  PH_LOG_HELPER_ADDPARAM_BUFFER(PH_LOG_LOGTYPE_DEBUG, pTMC_log, pTMC, 4);
  PH_LOG_HELPER_ADDPARAM_BUFFER(PH_LOG_LOGTYPE_DEBUG, pUid_log, pUid, bUidLen);
  PH_LOG_HELPER_ADDPARAM_BUFFER(PH_LOG_LOGTYPE_DEBUG, pTMI_log, pTMI, (uint16_t) dwTMILen);
  PH_LOG_HELPER_EXECUTE(PH_LOG_OPTION_CATEGORY_ENTER);

  /* Validate the parameters */
  PH_ASSERT_NULL_DATA_PARAM(pDataParams, PH_COMP_AL_MFDFEVX);
  if (bDivInputLen) {
    PH_ASSERT_NULL_PARAM(pDivInput, PH_COMP_AL_MFDFEVX);
  }
  PH_ASSERT_NULL_PARAM(pTMC, PH_COMP_AL_MFDFEVX);
  if (bUidLen) {
    PH_ASSERT_NULL_PARAM(pUid, PH_COMP_AL_MFDFEVX);
  }
  if (dwTMILen) {
    PH_ASSERT_NULL_PARAM(pTMI, PH_COMP_AL_MFDFEVX);
  }

  /* Parameter validation */
  if (PH_GET_COMPCODE(pDataParams) != PH_COMP_AL_MFDFEVX) {
    PH_LOG_HELPER_ADDSTRING(PH_LOG_LOGTYPE_INFO, bFunctionName);
    PH_LOG_HELPER_ADDPARAM_UINT16(PH_LOG_LOGTYPE_INFO, status_log, &status);
    PH_LOG_HELPER_EXECUTE(PH_LOG_OPTION_CATEGORY_LEAVE);
    return PH_ADD_COMPCODE_FIXED(PH_ERR_INVALID_DATA_PARAMS, PH_COMP_AL_MFDFEVX);
  }

  /* Perform operation on active layer */
  switch (PH_GET_COMPID(pDataParams)) {
#ifdef NXPBUILD__PHAL_MFDFEVX_SW
    case PHAL_MFDFEVX_SW_ID:
      status = phalMfdfEVx_Sw_CalculateTMV((phalMfdfEVx_Sw_DataParams_t *) pDataParams, wOption,
              wKeyNoTMACKey, wKeyVerTMACKey, pDivInput,
              bDivInputLen, pTMC, pUid, bUidLen, pTMI, dwTMILen, pTMV);
      break;
#endif /* NXPBUILD__PHAL_MFDFEVX_SW */

    default:
      status = PH_ADD_COMPCODE_FIXED(PH_ERR_INVALID_DATA_PARAMS, PH_COMP_AL_MFDFEVX);
      break;
  }

  PH_LOG_HELPER_ADDSTRING(PH_LOG_LOGTYPE_INFO, bFunctionName);
  PH_LOG_HELPER_ADDPARAM_BUFFER(PH_LOG_LOGTYPE_DEBUG, pTMV_log, pTMV, 8);
  PH_LOG_HELPER_ADDPARAM_UINT16(PH_LOG_LOGTYPE_INFO, status_log, &status);
  PH_LOG_HELPER_EXECUTE(PH_LOG_OPTION_CATEGORY_LEAVE);

  return status;
}

phStatus_t phalMfdfEVx_DecryptReaderID(void *pDataParams, uint16_t wOption,
    uint16_t wKeyNoTMACKey, uint16_t wKeyVerTMACKey,
    uint16_t wRamKeyNo, uint16_t wRamKeyVer, uint8_t *pDivInput, uint8_t bDivInputLen, uint8_t *pTMC,
    uint8_t *pUid,
    uint8_t bUidLen, uint8_t *pEncTMRI, uint8_t *pTMRIPrev)
{
  phStatus_t PH_MEMLOC_REM status;

  PH_LOG_HELPER_ALLOCATE_TEXT(bFunctionName, "phalMfdfEVx_DecryptReaderID");
  PH_LOG_HELPER_ALLOCATE_PARAMNAME(wOption);
  PH_LOG_HELPER_ALLOCATE_PARAMNAME(wKeyNoTMACKey);
  PH_LOG_HELPER_ALLOCATE_PARAMNAME(wKeyVerTMACKey);
  PH_LOG_HELPER_ALLOCATE_PARAMNAME(wRamKeyNo);
  PH_LOG_HELPER_ALLOCATE_PARAMNAME(wRamKeyVer);
  PH_LOG_HELPER_ALLOCATE_PARAMNAME(pDivInput);
  PH_LOG_HELPER_ALLOCATE_PARAMNAME(bDivInputLen);
  PH_LOG_HELPER_ALLOCATE_PARAMNAME(pTMC);
  PH_LOG_HELPER_ALLOCATE_PARAMNAME(pUid);
  PH_LOG_HELPER_ALLOCATE_PARAMNAME(bUidLen);
  PH_LOG_HELPER_ALLOCATE_PARAMNAME(pEncTMRI);
  PH_LOG_HELPER_ALLOCATE_PARAMNAME(pTMRIPrev);
  PH_LOG_HELPER_ALLOCATE_PARAMNAME(status);
  PH_LOG_HELPER_ADDSTRING(PH_LOG_LOGTYPE_INFO, bFunctionName);
  PH_LOG_HELPER_ADDPARAM_UINT16(PH_LOG_LOGTYPE_DEBUG, wOption_log, &wOption);
  PH_LOG_HELPER_ADDPARAM_UINT16(PH_LOG_LOGTYPE_DEBUG, wKeyNoTMACKey_log, &wKeyNoTMACKey);
  PH_LOG_HELPER_ADDPARAM_UINT16(PH_LOG_LOGTYPE_DEBUG, wKeyVerTMACKey_log, &wKeyVerTMACKey);
  PH_LOG_HELPER_ADDPARAM_UINT16(PH_LOG_LOGTYPE_DEBUG, wRamKeyNo_log, &wRamKeyNo);
  PH_LOG_HELPER_ADDPARAM_UINT16(PH_LOG_LOGTYPE_DEBUG, wRamKeyVer_log, &wRamKeyVer);
  PH_LOG_HELPER_ADDPARAM_UINT8(PH_LOG_LOGTYPE_DEBUG, bDivInputLen_log, &bDivInputLen);
  PH_LOG_HELPER_ADDPARAM_UINT8(PH_LOG_LOGTYPE_DEBUG, bUidLen_log, &bUidLen);
  PH_LOG_HELPER_ADDPARAM_BUFFER(PH_LOG_LOGTYPE_DEBUG, pDivInput_log, pDivInput, bDivInputLen);
  PH_LOG_HELPER_ADDPARAM_BUFFER(PH_LOG_LOGTYPE_DEBUG, pTMC_log, pTMC, 4);
  PH_LOG_HELPER_ADDPARAM_BUFFER(PH_LOG_LOGTYPE_DEBUG, pUid_log, pUid, bUidLen);
  PH_LOG_HELPER_ADDPARAM_BUFFER(PH_LOG_LOGTYPE_DEBUG, pEncTMRI_log, pEncTMRI, 16);
  PH_LOG_HELPER_EXECUTE(PH_LOG_OPTION_CATEGORY_ENTER);

  /* Validate the parameters */
  PH_ASSERT_NULL_DATA_PARAM(pDataParams, PH_COMP_AL_MFDFEVX);
  if (bDivInputLen) {
    PH_ASSERT_NULL_PARAM(pDivInput, PH_COMP_AL_MFDFEVX);
  }
  PH_ASSERT_NULL_PARAM(pTMC, PH_COMP_AL_MFDFEVX);
  if (bUidLen) {
    PH_ASSERT_NULL_PARAM(pUid, PH_COMP_AL_MFDFEVX);
  }
  PH_ASSERT_NULL_PARAM(pEncTMRI, PH_COMP_AL_MFDFEVX);

  /* Parameter validation */
  if (PH_GET_COMPCODE(pDataParams) != PH_COMP_AL_MFDFEVX) {
    PH_LOG_HELPER_ADDSTRING(PH_LOG_LOGTYPE_INFO, bFunctionName);
    PH_LOG_HELPER_ADDPARAM_UINT16(PH_LOG_LOGTYPE_INFO, status_log, &status);
    PH_LOG_HELPER_EXECUTE(PH_LOG_OPTION_CATEGORY_LEAVE);
    return PH_ADD_COMPCODE_FIXED(PH_ERR_INVALID_DATA_PARAMS, PH_COMP_AL_MFDFEVX);
  }

  /* Perform operation on active layer */
  switch (PH_GET_COMPID(pDataParams)) {
#ifdef NXPBUILD__PHAL_MFDFEVX_SW
    case PHAL_MFDFEVX_SW_ID:
      status = phalMfdfEVx_Sw_DecryptReaderID((phalMfdfEVx_Sw_DataParams_t *) pDataParams, wOption,
              wKeyNoTMACKey, wKeyVerTMACKey, pDivInput,
              bDivInputLen, pTMC, pUid, bUidLen, pEncTMRI, pTMRIPrev);
      break;
#endif /* NXPBUILD__PHAL_MFDFEVX_SW */

    default:
      status = PH_ADD_COMPCODE_FIXED(PH_ERR_INVALID_DATA_PARAMS, PH_COMP_AL_MFDFEVX);
      break;
  }

  PH_LOG_HELPER_ADDSTRING(PH_LOG_LOGTYPE_INFO, bFunctionName);
  PH_LOG_HELPER_ADDPARAM_BUFFER(PH_LOG_LOGTYPE_DEBUG, pTMRIPrev_log, pTMRIPrev, 16);
  PH_LOG_HELPER_ADDPARAM_UINT16(PH_LOG_LOGTYPE_INFO, status_log, &status);
  PH_LOG_HELPER_EXECUTE(PH_LOG_OPTION_CATEGORY_LEAVE);

  return status;
}

phStatus_t phalMfdfEVx_ComputeMFCLicenseMAC(void *pDataParams, uint16_t wOption,
    uint16_t wMFCLicenseMACKeyNo, uint16_t wMFCLicenseMACKeyVer,
    uint8_t *pInput, uint16_t wInputLen, uint8_t *pDivInput, uint8_t bDivInputLen,
    uint8_t *pMFCLicenseMAC)
{
  phStatus_t PH_MEMLOC_REM status;

  PH_LOG_HELPER_ALLOCATE_TEXT(bFunctionName, "phalMfdfEVx_ComputeMFCLicenseMAC");
  PH_LOG_HELPER_ALLOCATE_PARAMNAME(wOption);
  PH_LOG_HELPER_ALLOCATE_PARAMNAME(wMFCLicenseMACKeyNo);
  PH_LOG_HELPER_ALLOCATE_PARAMNAME(wMFCLicenseMACKeyVer);
  PH_LOG_HELPER_ALLOCATE_PARAMNAME(pInput);
  PH_LOG_HELPER_ALLOCATE_PARAMNAME(wInputLen);
  PH_LOG_HELPER_ALLOCATE_PARAMNAME(pDivInput);
  PH_LOG_HELPER_ALLOCATE_PARAMNAME(bDivInputLen);
  PH_LOG_HELPER_ALLOCATE_PARAMNAME(pMFCLicenseMAC);
  PH_LOG_HELPER_ALLOCATE_PARAMNAME(status);

  /* Validate the parameters. */
  PH_ASSERT_NULL_DATA_PARAM(pDataParams, PH_COMP_AL_MFDFEVX);
  PH_ASSERT_NULL_DATA_PARAM(pInput, PH_COMP_AL_MFDFEVX);
  if (wOption != 0xFFFF) {
    PH_ASSERT_NULL_DATA_PARAM(pDivInput, PH_COMP_AL_MFDFEVX);
  }
  PH_ASSERT_NULL_DATA_PARAM(pMFCLicenseMAC, PH_COMP_AL_MFDFEVX);

  /* Log the information. */
  PH_LOG_HELPER_ADDSTRING(PH_LOG_LOGTYPE_INFO, bFunctionName);
  PH_LOG_HELPER_ADDPARAM_UINT16(PH_LOG_LOGTYPE_DEBUG, PH_LOG_VAR(wOption), &wOption);
  PH_LOG_HELPER_ADDPARAM_UINT16(PH_LOG_LOGTYPE_DEBUG, PH_LOG_VAR(wMFCLicenseMACKeyNo),
      &wMFCLicenseMACKeyNo);
  PH_LOG_HELPER_ADDPARAM_UINT16(PH_LOG_LOGTYPE_DEBUG, PH_LOG_VAR(wMFCLicenseMACKeyVer),
      &wMFCLicenseMACKeyVer);
  PH_LOG_HELPER_ADDPARAM_BUFFER(PH_LOG_LOGTYPE_DEBUG, PH_LOG_VAR(pInput), pInput, wInputLen);
  PH_LOG_HELPER_ADDPARAM_UINT16(PH_LOG_LOGTYPE_DEBUG, PH_LOG_VAR(wInputLen), &wInputLen);
  PH_LOG_HELPER_ADDPARAM_BUFFER(PH_LOG_LOGTYPE_DEBUG, PH_LOG_VAR(pDivInput), pDivInput,
      bDivInputLen);
  PH_LOG_HELPER_ADDPARAM_UINT8(PH_LOG_LOGTYPE_DEBUG, PH_LOG_VAR(bDivInputLen), &bDivInputLen);
  PH_LOG_HELPER_EXECUTE(PH_LOG_OPTION_CATEGORY_ENTER);

  /* Component Code Validation */
  if (PH_GET_COMPCODE(pDataParams) != PH_COMP_AL_MFDFEVX) {
    PH_LOG_HELPER_ADDSTRING(PH_LOG_LOGTYPE_INFO, bFunctionName);
    PH_LOG_HELPER_ADDPARAM_UINT16(PH_LOG_LOGTYPE_INFO, status_log, &status);
    PH_LOG_HELPER_EXECUTE(PH_LOG_OPTION_CATEGORY_LEAVE);
    return PH_ADD_COMPCODE_FIXED(PH_ERR_INVALID_DATA_PARAMS, PH_COMP_AL_MFDFEVX);
  }

  /* Perform operation on active layer */
  switch (PH_GET_COMPID(pDataParams)) {
#ifdef NXPBUILD__PHAL_MFDFEVX_SW
    case PHAL_MFDFEVX_SW_ID:
      status = phalMfdfEVx_Sw_ComputeMFCLicenseMAC((phalMfdfEVx_Sw_DataParams_t *) pDataParams, wOption,
              wMFCLicenseMACKeyNo, wMFCLicenseMACKeyVer,
              pInput, wInputLen, pDivInput, bDivInputLen, pMFCLicenseMAC);
      break;
#endif /* NXPBUILD__PHAL_MFDFEVX_SW */

    default:
      status = PH_ADD_COMPCODE_FIXED(PH_ERR_INVALID_DATA_PARAMS, PH_COMP_AL_MFDFEVX);
      break;
  }

  PH_LOG_HELPER_ADDSTRING(PH_LOG_LOGTYPE_INFO, bFunctionName);
  PH_LOG_HELPER_ADDPARAM_BUFFER(PH_LOG_LOGTYPE_DEBUG, PH_LOG_VAR(pMFCLicenseMAC), pMFCLicenseMAC,
      8);
  PH_LOG_HELPER_ADDPARAM_UINT16(PH_LOG_LOGTYPE_INFO, PH_LOG_VAR(status), &status);
  PH_LOG_HELPER_EXECUTE(PH_LOG_OPTION_CATEGORY_LEAVE);

  return status;
}

phStatus_t phalMfdfEVx_CalculateMACSDM(void *pDataParams, uint8_t bSdmOption,
    uint16_t wSDMMacKeyNo, uint16_t wSDMMacKeyVer,
    uint16_t wRamKeyNo, uint16_t wRamKeyVer, uint8_t *pUid, uint8_t bUidLen, uint8_t *pSDMReadCtr,
    uint8_t *pInData, uint16_t wInDataLen, uint8_t *pRespMac)
{

  phStatus_t PH_MEMLOC_REM status;

  PH_LOG_HELPER_ALLOCATE_TEXT(bFunctionName, "phalMfdfEVx_CalculateMACSDM");
  PH_LOG_HELPER_ALLOCATE_PARAMNAME(bSdmOption);
  PH_LOG_HELPER_ALLOCATE_PARAMNAME(wSDMMacKeyNo);
  PH_LOG_HELPER_ALLOCATE_PARAMNAME(wSDMMacKeyVer);
  PH_LOG_HELPER_ALLOCATE_PARAMNAME(wRamKeyNo);
  PH_LOG_HELPER_ALLOCATE_PARAMNAME(wRamKeyVer);
  PH_LOG_HELPER_ALLOCATE_PARAMNAME(pUid);
  PH_LOG_HELPER_ALLOCATE_PARAMNAME(bUidLen);
  PH_LOG_HELPER_ALLOCATE_PARAMNAME(pSDMReadCtr);
  PH_LOG_HELPER_ALLOCATE_PARAMNAME(pInData);
  PH_LOG_HELPER_ALLOCATE_PARAMNAME(wInDataLen);
  PH_LOG_HELPER_ALLOCATE_PARAMNAME(pRespMac);
  PH_LOG_HELPER_ALLOCATE_PARAMNAME(status);

  PH_LOG_HELPER_ADDSTRING(PH_LOG_LOGTYPE_INFO, bFunctionName);
  PH_LOG_HELPER_ADDPARAM_UINT8(PH_LOG_LOGTYPE_DEBUG, bSdmOption_log, &bSdmOption);
  PH_LOG_HELPER_ADDPARAM_UINT16(PH_LOG_LOGTYPE_DEBUG, wSDMMacKeyNo_log, &wSDMMacKeyNo);
  PH_LOG_HELPER_ADDPARAM_UINT16(PH_LOG_LOGTYPE_DEBUG, wSDMMacKeyVer_log, &wSDMMacKeyVer);
  PH_LOG_HELPER_ADDPARAM_UINT16(PH_LOG_LOGTYPE_DEBUG, wRamKeyNo_log, &wRamKeyNo);
  PH_LOG_HELPER_ADDPARAM_UINT16(PH_LOG_LOGTYPE_DEBUG, wRamKeyVer_log, &wRamKeyVer);
  PH_LOG_HELPER_ADDPARAM_UINT8(PH_LOG_LOGTYPE_DEBUG, bUidLen_log, &bUidLen);

  if (pSDMReadCtr != NULL) {
    PH_LOG_HELPER_ADDPARAM_BUFFER(PH_LOG_LOGTYPE_DEBUG, pSDMReadCtr_log, pSDMReadCtr, 3);
  }
  PH_LOG_HELPER_ADDPARAM_UINT16(PH_LOG_LOGTYPE_DEBUG, wInDataLen_log, &wInDataLen);
  if (pInData != NULL) {
    PH_LOG_HELPER_ADDPARAM_BUFFER(PH_LOG_LOGTYPE_DEBUG, pInData_log, pInData, wInDataLen);
  }
  if (pUid != NULL) {
    PH_LOG_HELPER_ADDPARAM_BUFFER(PH_LOG_LOGTYPE_DEBUG, pUid_log, pUid, bUidLen);
  }
  PH_LOG_HELPER_EXECUTE(PH_LOG_OPTION_CATEGORY_ENTER);

  /* Validate the parameters */
  PH_ASSERT_NULL_DATA_PARAM(pDataParams, PH_COMP_AL_MFDFEVX);
  PH_ASSERT_NULL_PARAM(pInData, PH_COMP_AL_MFDFEVX);

  /* Component Code Validation */
  if (PH_GET_COMPCODE(pDataParams) != PH_COMP_AL_MFDFEVX) {
    PH_LOG_HELPER_ADDSTRING(PH_LOG_LOGTYPE_INFO, bFunctionName);
    PH_LOG_HELPER_ADDPARAM_UINT16(PH_LOG_LOGTYPE_INFO, status_log, &status);
    PH_LOG_HELPER_EXECUTE(PH_LOG_OPTION_CATEGORY_LEAVE);
    return PH_ADD_COMPCODE_FIXED(PH_ERR_INVALID_DATA_PARAMS, PH_COMP_AL_MFDFEVX);
  }

  /* Perform operation on active layer */
  switch (PH_GET_COMPID(pDataParams)) {
#ifdef NXPBUILD__PHAL_MFDFEVX_SW
    case PHAL_MFDFEVX_SW_ID:
      status = phalMfdfEVx_Sw_CalculateMACSDM((phalMfdfEVx_Sw_DataParams_t *) pDataParams, bSdmOption,
              wSDMMacKeyNo,
              wSDMMacKeyVer, pUid, bUidLen, pSDMReadCtr, pInData, wInDataLen, pRespMac);
      break;
#endif /* NXPBUILD__PHAL_MFDFEVX_SW */

    default:
      status = PH_ADD_COMPCODE_FIXED(PH_ERR_INVALID_DATA_PARAMS, PH_COMP_AL_MFDFEVX);
      break;
  }

  PH_LOG_HELPER_ADDSTRING(PH_LOG_LOGTYPE_INFO, bFunctionName);
  PH_LOG_HELPER_ADDPARAM_BUFFER(PH_LOG_LOGTYPE_DEBUG, pRespMac_log, pRespMac, 8);
  PH_LOG_HELPER_ADDPARAM_UINT16(PH_LOG_LOGTYPE_INFO, status_log, &status);
  PH_LOG_HELPER_EXECUTE(PH_LOG_OPTION_CATEGORY_LEAVE);

  return status;
}

phStatus_t phalMfdfEVx_DecryptSDMENCFileData(void *pDataParams, uint8_t bSdmOption,
    uint16_t wEncKeyNo, uint16_t wEncKeyVer,
    uint16_t wRamKeyNo, uint16_t wRamKeyVer, uint8_t *pUid, uint8_t bUidLen, uint8_t *pSDMReadCtr,
    uint8_t *pEncdata,
    uint16_t wEncDataLen, uint8_t *pPlainData)
{
  phStatus_t PH_MEMLOC_REM status;

  PH_LOG_HELPER_ALLOCATE_TEXT(bFunctionName, "phalMfdfEVx_DecryptSDMENCFileData");
  PH_LOG_HELPER_ALLOCATE_PARAMNAME(bSdmOption);
  PH_LOG_HELPER_ALLOCATE_PARAMNAME(wEncKeyNo);
  PH_LOG_HELPER_ALLOCATE_PARAMNAME(wEncKeyVer);
  PH_LOG_HELPER_ALLOCATE_PARAMNAME(pUid);
  PH_LOG_HELPER_ALLOCATE_PARAMNAME(bUidLen);
  PH_LOG_HELPER_ALLOCATE_PARAMNAME(pSDMReadCtr);
  PH_LOG_HELPER_ALLOCATE_PARAMNAME(pEncdata);
  PH_LOG_HELPER_ALLOCATE_PARAMNAME(wEncDataLen);
  PH_LOG_HELPER_ALLOCATE_PARAMNAME(pPlainData);
  PH_LOG_HELPER_ALLOCATE_PARAMNAME(status);
  PH_LOG_HELPER_ADDSTRING(PH_LOG_LOGTYPE_INFO, bFunctionName);
  PH_LOG_HELPER_ADDPARAM_UINT8(PH_LOG_LOGTYPE_DEBUG, bSdmOption_log, &bSdmOption);
  PH_LOG_HELPER_ADDPARAM_UINT16(PH_LOG_LOGTYPE_DEBUG, wEncKeyNo_log, &wEncKeyNo);
  PH_LOG_HELPER_ADDPARAM_UINT16(PH_LOG_LOGTYPE_DEBUG, wEncKeyVer_log, &wEncKeyVer);
  PH_LOG_HELPER_ADDPARAM_UINT8(PH_LOG_LOGTYPE_DEBUG, bUidLen_log, &bUidLen);
  if (pUid != NULL) {
    PH_LOG_HELPER_ADDPARAM_BUFFER(PH_LOG_LOGTYPE_DEBUG, pUid_log, pUid, bUidLen);
  }

  if (pSDMReadCtr != NULL) {
    PH_LOG_HELPER_ADDPARAM_BUFFER(PH_LOG_LOGTYPE_DEBUG, pSDMReadCtr_log, pSDMReadCtr, 3);
  }
  PH_LOG_HELPER_ADDPARAM_UINT16(PH_LOG_LOGTYPE_DEBUG, wEncDataLen_log, &wEncDataLen);
  if (pEncdata != NULL) {
    PH_LOG_HELPER_ADDPARAM_BUFFER(PH_LOG_LOGTYPE_DEBUG, pEncdata_log, pEncdata, wEncDataLen);
  }
  PH_LOG_HELPER_EXECUTE(PH_LOG_OPTION_CATEGORY_ENTER);

  /* Validate the parameters */
  PH_ASSERT_NULL_DATA_PARAM(pDataParams, PH_COMP_AL_MFDFEVX);
  PH_ASSERT_NULL_PARAM(pSDMReadCtr, PH_COMP_AL_MFDFEVX);
  PH_ASSERT_NULL_PARAM(pEncdata, PH_COMP_AL_MFDFEVX);
  PH_ASSERT_NULL_PARAM(pUid, PH_COMP_AL_MFDFEVX);

  /* Component Code Validation */
  if (PH_GET_COMPCODE(pDataParams) != PH_COMP_AL_MFDFEVX) {
    PH_LOG_HELPER_ADDSTRING(PH_LOG_LOGTYPE_INFO, bFunctionName);
    PH_LOG_HELPER_ADDPARAM_UINT16(PH_LOG_LOGTYPE_INFO, status_log, &status);
    PH_LOG_HELPER_EXECUTE(PH_LOG_OPTION_CATEGORY_LEAVE);
    return PH_ADD_COMPCODE_FIXED(PH_ERR_INVALID_DATA_PARAMS, PH_COMP_AL_MFDFEVX);
  }

  /* Perform operation on active layer */
  switch (PH_GET_COMPID(pDataParams)) {
#ifdef NXPBUILD__PHAL_MFDFEVX_SW
    case PHAL_MFDFEVX_SW_ID:
      status = phalMfdfEVx_Sw_DecryptSDMENCFileData((phalMfdfEVx_Sw_DataParams_t *) pDataParams,
              bSdmOption, wEncKeyNo,
              wEncKeyVer, pUid, bUidLen, pSDMReadCtr, pEncdata, wEncDataLen, pPlainData);
      break;
#endif /* NXPBUILD__PHAL_MFDFEVX_SW */

    default:
      status = PH_ADD_COMPCODE_FIXED(PH_ERR_INVALID_DATA_PARAMS, PH_COMP_AL_MFDFEVX);
      break;
  }

  PH_LOG_HELPER_ADDSTRING(PH_LOG_LOGTYPE_INFO, bFunctionName);
  PH_LOG_HELPER_ADDPARAM_BUFFER(PH_LOG_LOGTYPE_DEBUG, pPlainData_log, pPlainData, wEncDataLen);
  PH_LOG_HELPER_ADDPARAM_UINT16(PH_LOG_LOGTYPE_INFO, status_log, &status);
  PH_LOG_HELPER_EXECUTE(PH_LOG_OPTION_CATEGORY_LEAVE);

  return status;
}

phStatus_t phalMfdfEVx_DecryptSDMPICCData(void *pDataParams, uint16_t wKeyNo, uint16_t wKeyVer,
    uint8_t *pEncdata, uint16_t wEncDataLen,
    uint8_t *pPlainData)
{
  phStatus_t PH_MEMLOC_REM status;

  PH_LOG_HELPER_ALLOCATE_TEXT(bFunctionName, "phalMfdfEVx_DecryptSDMPICCData");
  PH_LOG_HELPER_ALLOCATE_PARAMNAME(wKeyNo);
  PH_LOG_HELPER_ALLOCATE_PARAMNAME(wKeyVer);
  PH_LOG_HELPER_ALLOCATE_PARAMNAME(pEncdata);
  PH_LOG_HELPER_ALLOCATE_PARAMNAME(wEncDataLen);
  PH_LOG_HELPER_ALLOCATE_PARAMNAME(pPlainData);
  PH_LOG_HELPER_ALLOCATE_PARAMNAME(status);

  PH_LOG_HELPER_ADDSTRING(PH_LOG_LOGTYPE_INFO, bFunctionName);
  PH_LOG_HELPER_ADDPARAM_UINT16(PH_LOG_LOGTYPE_DEBUG, wKeyNo_log, &wKeyNo);
  PH_LOG_HELPER_ADDPARAM_UINT16(PH_LOG_LOGTYPE_DEBUG, wKeyVer_log, &wKeyVer);

  PH_LOG_HELPER_ADDPARAM_UINT16(PH_LOG_LOGTYPE_DEBUG, wEncDataLen_log, &wEncDataLen);
  PH_LOG_HELPER_ADDPARAM_BUFFER(PH_LOG_LOGTYPE_DEBUG, pEncdata_log, pEncdata, wEncDataLen);
  PH_LOG_HELPER_EXECUTE(PH_LOG_OPTION_CATEGORY_ENTER);

  /* Validate the parameters */
  PH_ASSERT_NULL_DATA_PARAM(pDataParams, PH_COMP_AL_MFDFEVX);
  PH_ASSERT_NULL_PARAM(pEncdata, PH_COMP_AL_MFDFEVX);

  /* Component Code Validation */
  if (PH_GET_COMPCODE(pDataParams) != PH_COMP_AL_MFDFEVX) {
    PH_LOG_HELPER_ADDSTRING(PH_LOG_LOGTYPE_INFO, bFunctionName);
    PH_LOG_HELPER_ADDPARAM_UINT16(PH_LOG_LOGTYPE_INFO, status_log, &status);
    PH_LOG_HELPER_EXECUTE(PH_LOG_OPTION_CATEGORY_LEAVE);
    return PH_ADD_COMPCODE_FIXED(PH_ERR_INVALID_DATA_PARAMS, PH_COMP_AL_MFDFEVX);
  }

  /* Perform operation on active layer */
  switch (PH_GET_COMPID(pDataParams)) {
#ifdef NXPBUILD__PHAL_MFDFEVX_SW
    case PHAL_MFDFEVX_SW_ID:
      status = phalMfdfEVx_Sw_DecryptSDMPICCData((phalMfdfEVx_Sw_DataParams_t *) pDataParams, wKeyNo,
              wKeyVer,
              pEncdata, wEncDataLen, pPlainData);
      break;
#endif /* NXPBUILD__PHAL_MFDFEVX_SW */

    default:
      status = PH_ADD_COMPCODE_FIXED(PH_ERR_INVALID_DATA_PARAMS, PH_COMP_AL_MFDFEVX);
      break;
  }

  PH_LOG_HELPER_ADDSTRING(PH_LOG_LOGTYPE_INFO, bFunctionName);
  PH_LOG_HELPER_ADDPARAM_BUFFER(PH_LOG_LOGTYPE_DEBUG, pPlainData_log, pPlainData, 16);
  PH_LOG_HELPER_ADDPARAM_UINT16(PH_LOG_LOGTYPE_INFO, status_log, &status);
  PH_LOG_HELPER_EXECUTE(PH_LOG_OPTION_CATEGORY_LEAVE);

  return status;
}
#endif /* NXPBUILD__PHAL_MFDFEVX_NDA */

phStatus_t phalMfdfEVx_SetVCAParams(void *pDataParams, void *pAlVCADataParams)
{
  phStatus_t PH_MEMLOC_REM status = 0;

  PH_LOG_HELPER_ALLOCATE_TEXT(bFunctionName, "phalMfdfEVx_SetVCAParams");
  PH_LOG_HELPER_ALLOCATE_PARAMNAME(status);
  PH_LOG_HELPER_ADDSTRING(PH_LOG_LOGTYPE_INFO, bFunctionName);
  PH_LOG_HELPER_EXECUTE(PH_LOG_OPTION_CATEGORY_ENTER);

  /* Validate the parameters */
  PH_ASSERT_NULL_DATA_PARAM(pDataParams, PH_COMP_AL_MFDFEVX);
  PH_ASSERT_NULL_PARAM(pAlVCADataParams, PH_COMP_AL_MFDFEVX);

  if (PH_GET_COMPCODE(pDataParams) != PH_COMP_AL_MFDFEVX) {
    PH_LOG_HELPER_ADDSTRING(PH_LOG_LOGTYPE_INFO, bFunctionName);
    PH_LOG_HELPER_ADDPARAM_UINT16(PH_LOG_LOGTYPE_INFO, status_log, &status);
    PH_LOG_HELPER_EXECUTE(PH_LOG_OPTION_CATEGORY_LEAVE);

    return  PH_ADD_COMPCODE_FIXED(PH_ERR_INVALID_DATA_PARAMS, PH_COMP_AL_MFDFEVX);
  }

  /* Perform operation on active layer */
  switch (PH_GET_COMPID(pDataParams)) {
#ifdef NXPBUILD__PHAL_MFDFEVX_SW
    case PHAL_MFDFEVX_SW_ID:
      status = phalMfdfEVx_Sw_SetVCAParams((phalMfdfEVx_Sw_DataParams_t *) pDataParams,
              pAlVCADataParams);
      break;
#endif /* NXPBUILD__PHAL_MFDFEVX_SW */

    default:
      status = PH_ADD_COMPCODE_FIXED(PH_ERR_INVALID_DATA_PARAMS, PH_COMP_AL_MFDFEVX);
      break;
  }

  PH_LOG_HELPER_ADDSTRING(PH_LOG_LOGTYPE_INFO, bFunctionName);
  PH_LOG_HELPER_ADDPARAM_UINT16(PH_LOG_LOGTYPE_INFO, status_log, &status);
  PH_LOG_HELPER_EXECUTE(PH_LOG_OPTION_CATEGORY_LEAVE);

  return status;
}

#endif /* NXPBUILD__PHAL_MFDFEVX */
