/*
*         Copyright (c), NXP Semiconductors Gratkorn / Austria
*
*                     (C)NXP Semiconductors
*       All rights are reserved. Reproduction in whole or in part is
*      prohibited without the written consent of the copyright owner.
*  NXP reserves the right to make changes without notice at any time.
* NXP makes no warranty, expressed, implied or statutory, including but
* not limited to any implied warranty of merchantability or fitness for any
*particular purpose, or that the use will not infringe any third party patent,
* copyright or trademark. NXP must not be liable for any loss or damage
*                          arising from its use.
*/

/** \file
* Software specific Crypto-Component of Reader Library Framework.
* $Author$
* $Revision$ (v06.10.00)
* $Date$
*
* History:
*  CHu: Generated 19. May 2009
*
*/

#include <nxp_nfc/ph_Status.h>
#include <nxp_nfc/phCryptoRng.h>
#include <nxp_nfc/phCryptoSym.h>
#include <nxp_nfc/ph_RefDefs.h>

#ifdef NXPBUILD__PH_CRYPTORNG_SW

#include "phCryptoRng_Sw.h"
#include "phCryptoRng_Sw_Int.h"

/**
* \brief Increment the 16 byte value V by 1 mod 2^128.
* \return None
*/
static void phCryptoRng_Sw_IncrementV(
    phCryptoRng_Sw_DataParams_t *pDataParams  /**< [In] Pointer to this layers parameter structure. */
);

static const uint8_t PH_CRYPTOSYM_SW_CONST_ROM
phCryptoRng_Sw_BlockCipherDf_DefaultKey[PHCRYPTORNG_SW_KEYLEN] =
{0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F};

phStatus_t phCryptoRng_Sw_Init(
    phCryptoRng_Sw_DataParams_t *pDataParams,
    uint16_t wSizeOfDataParams,
    void *pCryptoDataParams
)
{
  if (sizeof(phCryptoRng_Sw_DataParams_t) != wSizeOfDataParams) {
    return PH_ADD_COMPCODE_FIXED(PH_ERR_INVALID_DATA_PARAMS, PH_COMP_CRYPTORNG);
  }
  PH_ASSERT_NULL(pDataParams);
  PH_ASSERT_NULL(pCryptoDataParams);

  /* Init. private data */
  pDataParams->wId                = PH_COMP_CRYPTORNG | PH_CRYPTORNG_SW_ID;
  pDataParams->pCryptoDataParams = pCryptoDataParams;
  (void)memset(pDataParams->V, 0, (size_t)sizeof(pDataParams->V));
  pDataParams->bState = PHCRYPTORNG_SW_STATE_INIT;

  return PH_ERR_SUCCESS;
}

phStatus_t phCryptoRng_Sw_Seed(
    phCryptoRng_Sw_DataParams_t *pDataParams,
    uint8_t *pSeed,
    uint8_t bSeedLength
)
{
  phStatus_t  PH_MEMLOC_REM statusTmp;
  uint8_t     PH_MEMLOC_REM aSeed[PHCRYPTORNG_SW_SEEDLEN];

  /* we do not set the seed to 0 as we like randomness in here... */

  if (bSeedLength > PHCRYPTORNG_SW_SEEDLEN) {
    (void)memcpy(aSeed, pSeed, PHCRYPTORNG_SW_SEEDLEN);
  } else {
    (void)memcpy(aSeed, pSeed, bSeedLength);
  }

  if (pDataParams->bState == PHCRYPTORNG_SW_STATE_INIT) {
    statusTmp = phCryptoRng_Sw_Instantiate(
            pDataParams,
            aSeed,
            (uint16_t)sizeof(aSeed),
            NULL,
            0,
            NULL,
            0);
  } else {
    statusTmp = phCryptoRng_Sw_Reseed(
            pDataParams,
            aSeed,
            (uint16_t)sizeof(aSeed),
            NULL,
            0);
  }

  return PH_ADD_COMPCODE(statusTmp, PH_COMP_CRYPTORNG);
}

phStatus_t phCryptoRng_Sw_Rnd(
    phCryptoRng_Sw_DataParams_t *pDataParams,
    uint16_t  wNoOfRndBytes,  /**< [In] number of random bytes to generate */
    uint8_t *pRnd             /**< [Out] generated bytes; uint8_t[dwNumBytes] */
)
{
  return phCryptoRng_Sw_Generate(
          pDataParams,
          NULL,
          wNoOfRndBytes,
          pRnd);
}

phStatus_t phCryptoRng_Sw_Update(
    phCryptoRng_Sw_DataParams_t *pDataParams,
    uint8_t *pProvidedData
)
{
  phStatus_t  PH_MEMLOC_REM statusTmp;
  uint8_t     PH_MEMLOC_REM bIndex;
  uint8_t     PH_MEMLOC_REM aKey[PHCRYPTORNG_SW_KEYLEN];

  /* Note: as a prerequirement, the "old key" is already loaded in the crypto data params */

  /* 1. temp = Null. */
  /* 2. While (len (temp) < seedlen) do */
  /* NOTE: as seedlen == 2*PH_CRYPTOSYN_AES_BLOCK_SIZE, the loop is unrolled in this implementation. */
  /* NOTE: First iteration: Generate new key, second iteration: Generate new V. */
  /* For further details refer to sec. 10.2.1.1. of NIST SP 800-90 */

  /* 2.1 V = (V + 1U) mod 2 exp outlen.*/
  phCryptoRng_Sw_IncrementV(pDataParams);

  /* 2.2 output_block = Block_Encrypt (Key, V). */
  /* 2.3 temp = temp || ouput_block. */
  /* Note: Encrypt V to get Key using ECB mode */
  PH_CHECK_SUCCESS_FCT(statusTmp, phCryptoSym_Encrypt(pDataParams->pCryptoDataParams,
          PH_CRYPTOSYM_CIPHER_MODE_ECB,
          pDataParams->V,
          PHCRYPTORNG_SW_OUTLEN,
          aKey));

  /*  3. temp = Leftmost seedlen bits of temp. */
  /*  4 temp = temp xor provided_data. */
  /*  5. Key = Leftmost keylen bits of temp. */
  /* Note: Xor Key with provided data to get the key to be later used in the crypto unit. */
  /* Note: We must not load the key immediately, as the updated value of V shall be encrypted using the old key */
  if (pProvidedData != NULL) {
    for (bIndex = 0; bIndex < PHCRYPTORNG_SW_KEYLEN; ++bIndex) {
      aKey[bIndex] ^= pProvidedData[bIndex];
    }
  }

  /* NOTE: Second iteration of the loop */
  /* 2.1 V = (V + 1U) mod 2 exp outlen.*/
  phCryptoRng_Sw_IncrementV(pDataParams);

  /* 2.2 output_block = Block_Encrypt (Key, V). */
  /* 2.3 temp = temp || ouput_block. */
  /* NOTE: Encrypt V to get V' using ECB mode */
  PH_CHECK_SUCCESS_FCT(statusTmp, phCryptoSym_Encrypt(pDataParams->pCryptoDataParams,
          PH_CRYPTOSYM_CIPHER_MODE_ECB,
          pDataParams->V,
          PHCRYPTORNG_SW_OUTLEN,
          pDataParams->V));

  /* 3. temp = Leftmost seedlen bits of temp. */
  /* 4 temp = temp xor provided_data. */
  /* 6. V = Rightmost outlen bits of temp. */
  /* NOTE: Xor V' with provided data */
  if (pProvidedData != NULL) {
    for (bIndex = 0; bIndex < PHCRYPTORNG_SW_OUTLEN; ++bIndex) {
      pDataParams->V[bIndex] ^= pProvidedData[bIndex + PHCRYPTORNG_SW_KEYLEN];
    }
  }

#ifndef PH_CRYPTOSYM_SW_AES
#error "No valid cipher available"
#else
  /* Load the new key into the Crypto Data Params structure */
  PH_CHECK_SUCCESS_FCT(statusTmp, phCryptoSym_LoadKeyDirect(
          pDataParams->pCryptoDataParams,
          aKey,
          PH_CRYPTOSYM_KEY_TYPE_AES128));
#endif /* PH_CRYPTOSYM_SW_AES */

  /* Clear aKey for security reasons */
  (void)memset(aKey, 0x00, (size_t)sizeof(aKey));
  return PH_ERR_SUCCESS;
}

phStatus_t phCryptoRng_Sw_Instantiate(
    phCryptoRng_Sw_DataParams_t *pDataParams,
    uint8_t *pEntropyInput,
    uint16_t wEntropyInputLength,
    uint8_t *pNonce,
    uint8_t bNonceLength,
    uint8_t *pPersonalizationString,
    uint8_t bPersonalizationString
)
{
  phStatus_t  PH_MEMLOC_REM statusTmp;
  uint8_t     PH_MEMLOC_REM aSeedMaterial[PHCRYPTORNG_SW_SEEDLEN];

  /* Reset state to be init again. */
  pDataParams->bState = PHCRYPTORNG_SW_STATE_INIT;

  /* do we have a wrong input data length? */
  /* Comment: Ensure that the length of the seed_material is exactly seedlen bits. */
  if (PHCRYPTORNG_SW_SEEDLEN != (wEntropyInputLength + bNonceLength + bPersonalizationString)) {
    return PH_ADD_COMPCODE_FIXED(PH_ERR_INVALID_PARAMETER, PH_COMP_CRYPTORNG);
  }

  /* NOTE: Prepare seed Material */
  /* 1. seed_material = entropy_input || nonce || personalization_string. */
  (void)memcpy(aSeedMaterial, pEntropyInput, wEntropyInputLength);
  (void)memcpy(&aSeedMaterial[wEntropyInputLength], pNonce, bNonceLength);
  (void)memcpy(&aSeedMaterial[wEntropyInputLength + bNonceLength], pPersonalizationString,
      bPersonalizationString);

  /* Note: Encrypt the seed value */
  /* 2. seed_material = Block_Cipher_df (seed_material, seedlen). */

  PH_CHECK_SUCCESS_FCT(statusTmp, phCryptoRng_Sw_BlockCipherDf(
          pDataParams,
          aSeedMaterial));

  /* Note: Reset the Key and the V-Value. */
  /* 4. V = 0 expoutlen. Comment: outlen bits of zeros. */
  (void)memset(pDataParams->V, 0, PHCRYPTORNG_SW_OUTLEN);
#ifndef PH_CRYPTOSYM_SW_AES
#error "No valid cipher available"
#else
  /* 3. Key = 0 exp keylen. Comment: keylen bits of zeros. */
  /* Also reset the key, this can be done by loading V into the key register, as we set it to 0 before. */
  PH_CHECK_SUCCESS_FCT(statusTmp, phCryptoSym_LoadKeyDirect(
          pDataParams->pCryptoDataParams,
          pDataParams->V,
          PH_CRYPTOSYM_KEY_TYPE_AES128));
#endif /* PH_CRYPTOSYM_SW_AES */

  /* Update using aSeedMaterial as the personalization string. */
  /* 5. (Key, V) = Update (seed_material, Key, V). */
  PH_CHECK_SUCCESS_FCT(statusTmp, phCryptoRng_Sw_Update(pDataParams, aSeedMaterial));

  /* Set the counter again to 1. */
  /* 6. reseed_counter = 1. */
  pDataParams->dwRequestCounter = 1;

  /* Set the correct state */
  /* 7. Return V, Key, and reseed_counter as the initial_working_state. */
  pDataParams->bState = PHCRYPTORNG_SW_STATE_WORKING;

  /* Clear seed material for security reasons */
  (void)memset(aSeedMaterial, 0x00, (size_t)sizeof(aSeedMaterial));

  return PH_ERR_SUCCESS;
}

phStatus_t phCryptoRng_Sw_Reseed(
    phCryptoRng_Sw_DataParams_t *pDataParams,
    uint8_t *pEntropyInput,
    uint16_t wEntropyInputLength,
    uint8_t *pAdditionalInput,
    uint8_t bAdditionalInputLength
)
{
  phStatus_t  PH_MEMLOC_REM statusTmp;
  uint8_t     PH_MEMLOC_REM aSeedMaterial[PHCRYPTORNG_SW_SEEDLEN];

  /* Check for operational state */
  if (pDataParams->bState != PHCRYPTORNG_SW_STATE_WORKING) {
    return PH_ADD_COMPCODE_FIXED(PH_ERR_USE_CONDITION, PH_COMP_CRYPTORNG);
  }

  /* Comment: Ensure that the length of the seed_material is exactly seedlen bits. */
  if (PHCRYPTORNG_SW_SEEDLEN != (wEntropyInputLength + bAdditionalInputLength)) {
    return PH_ADD_COMPCODE_FIXED(PH_ERR_INVALID_PARAMETER, PH_COMP_CRYPTORNG);
  }

  /* Prepare seed Material */
  /* 1. seed_material = entropy_input || additional_input. */
  (void)memcpy(aSeedMaterial, pEntropyInput, wEntropyInputLength);
  (void)memcpy(&aSeedMaterial[wEntropyInputLength], pAdditionalInput, bAdditionalInputLength);

  /* Encrypt the seed value */
  /* 2. seed_material = Block_Cipher_df (seed_material, seedlen). */
  PH_CHECK_SUCCESS_FCT(statusTmp, phCryptoRng_Sw_BlockCipherDf(
          pDataParams,
          aSeedMaterial));

  /* Update using aSeedMaterial as the personalization string. */
  /* 3. (Key, V) = Update (seed_material, Key, V). */
  PH_CHECK_SUCCESS_FCT(statusTmp, phCryptoRng_Sw_Update(pDataParams, aSeedMaterial));

  /* Set the counter again to 1. */
  /* 4. reseed_counter = 1. */
  pDataParams->dwRequestCounter = 1;

  /* 5. Return V, Key, and reseed_counter as the new_working_state. */

  /* Clear seed material for security reasons */
  (void)memset(aSeedMaterial, 0x00, (size_t)sizeof(aSeedMaterial));

  return PH_ERR_SUCCESS;
}

phStatus_t phCryptoRng_Sw_Generate(
    phCryptoRng_Sw_DataParams_t *pDataParams,
    uint8_t *pAdditionalInput,
    uint16_t wNumBytesRequested,
    uint8_t *pRndBytes
)
{
  phStatus_t  PH_MEMLOC_REM statusTmp;
  uint16_t    PH_MEMLOC_REM wIndex;

  /* Check for operational state */
  if (pDataParams->bState != PHCRYPTORNG_SW_STATE_WORKING) {
    return PH_ADD_COMPCODE_FIXED(PH_ERR_USE_CONDITION, PH_COMP_CRYPTORNG);
  }

  /* 1. If reseed_counter > reseed_interval, then return an indication that a reseed is required. */
  if (pDataParams->dwRequestCounter == PHCRYPTORNG_SW_MAX_REQUESTS) {
    return PH_ADD_COMPCODE_FIXED(PH_ERR_INTERNAL_ERROR, PH_COMP_CRYPTORNG);
  }

  /* 2. If (additional_input ? Null), then */
  if (pAdditionalInput != NULL) {
    /* 2.1 additional_input = Block_Cipher_df (additional_input, seedlen). */
    PH_CHECK_SUCCESS_FCT(statusTmp, phCryptoRng_Sw_BlockCipherDf(
            pDataParams,
            pAdditionalInput));

    /* 2.2 (Key, V) = Update (additional_input, Key, V). */
    PH_CHECK_SUCCESS_FCT(statusTmp, phCryptoRng_Sw_Update(pDataParams, pAdditionalInput));
  }

  /* 3. temp = Null. */
  /* 4. While (len (temp) < requested_number_of_bits) do: */
  wIndex = 0;
  while (0U != wNumBytesRequested) {
    /* Increment V */
    /* 4.1 V = (V + 1U) mod 2 exp outlen. */
    phCryptoRng_Sw_IncrementV(pDataParams);

    /* 4.2 output_block = Block_Encrypt (Key, V). */
    PH_CHECK_SUCCESS_FCT(statusTmp, phCryptoSym_Encrypt(pDataParams->pCryptoDataParams,
            PH_CRYPTOSYM_CIPHER_MODE_ECB,
            pDataParams->V,
            PHCRYPTORNG_SW_OUTLEN,
            pDataParams->V));

    /* 4.3 temp = temp || output_block. */
    if (wNumBytesRequested >= PHCRYPTORNG_SW_OUTLEN) {
      (void)memcpy(&pRndBytes[wIndex], pDataParams->V, PHCRYPTORNG_SW_OUTLEN);
      wNumBytesRequested = wNumBytesRequested - PHCRYPTORNG_SW_OUTLEN;
    } else {
      (void)memcpy(&pRndBytes[wIndex], pDataParams->V, wNumBytesRequested);
      wNumBytesRequested = 0;
    }
    wIndex = wIndex + PHCRYPTORNG_SW_OUTLEN;
  }

  /* 5. returned_bits = Leftmost requested_number_of_bits of temp. */
  /* Comment: Update for backtracking resistance. */
  /* 6. (Key, V) = Update (additional_input, Key, V). */
  PH_CHECK_SUCCESS_FCT(statusTmp, phCryptoRng_Sw_Update(pDataParams,  NULL));

  /* 7. reseed_counter = reseed_counter + 1. */
  pDataParams->dwRequestCounter++;

  /* 8. Return SUCCESS and returned_bits; also return Key, V, and reseed_counter as the new_working_state. */
  return PH_ERR_SUCCESS;
}

phStatus_t phCryptoRng_Sw_BlockCipherDf(
    phCryptoRng_Sw_DataParams_t *pDataParams,
    uint8_t *pIoString
)
{
  phStatus_t  PH_MEMLOC_REM statusTmp;
  uint8_t     PH_MEMLOC_REM aCipher[4U * PHCRYPTORNG_SW_OUTLEN];
  uint8_t     PH_MEMLOC_REM bMacLength;

  /* The cipher consists of IV || L || N || Input String || padding and needs to be done twice for IV = 0 and IV = 1*/

#ifndef PH_CRYPTOSYM_SW_AES
#error "No valid cipher available"
#else
  /* Then we load the default key */
  /* 8. K = Leftmost keylen bits of 0x00010203...1D1E1F. */
  PH_CHECK_SUCCESS_FCT(statusTmp, phCryptoSym_LoadKeyDirect(
          pDataParams->pCryptoDataParams,
          phCryptoRng_Sw_BlockCipherDf_DefaultKey,
          PH_CRYPTOSYM_KEY_TYPE_AES128));
#endif /* PH_CRYPTOSYM_SW_AES */

  /* First clear the cipher buffer*/
  (void)memset(aCipher, 0x00, (size_t)sizeof(aCipher));

  /* Prepare the cipher */
  /* We use the integers in LSB FIRST format - length is always 32 bits*/
  /* S = L || N || input_string || 0x80. */
  /* 2. L = len (input_string)/8. */
  aCipher[PHCRYPTORNG_SW_OUTLEN] = 0x20;
  /* 3. N = number_of_bits_to_return/8. */
  aCipher[PHCRYPTORNG_SW_OUTLEN + 4U] = 0x20;
  /* 4. S = L || N || input_string || 0x80. */
  (void)memcpy(&aCipher[PHCRYPTORNG_SW_OUTLEN + 8U], pIoString, PHCRYPTORNG_SW_SEEDLEN);
  /* Add Padding */
  aCipher[PHCRYPTORNG_SW_OUTLEN + 8U + PHCRYPTORNG_SW_SEEDLEN] = 0x80;

  /* The cipher now needs to be CBC-Maced twice. Both times using an IV of zero */
  /* FIRST ITERATION */
  /* NOTE: For simplicity, the loop is unrolled. */
  /* 9. While len (temp) < keylen + outlen, do */

  /* Set IV to zero according to specification of BCC (note: at this moment, first part of aCipher is 0 (16 bytes) */
  /* 1. chaining_value = 0 exp outlen. Comment: Set the first chaining value to outlen zeros. */
  PH_CHECK_SUCCESS_FCT(statusTmp, phCryptoSym_LoadIv(pDataParams->pCryptoDataParams, aCipher, 16));

  /* 9.1 IV = i || 0 exp (outlen - len (i)). */
  /* 9.2 temp = temp || BCC (K, (IV || S)). */
  /* NOTE: BCC SPEC: */
  /* 4. For i = 1 to n do  */
  /* 4.1 input_block = chaining_value xor block_i.  */
  /* 4.2 chaining_value = Block_Encrypt (Key, input_block).  */
  /* 5. output_block = chaining_value.  */
  /* Set the MAC mode to CBC mac which is equal to BCC*/

  PH_CHECK_SUCCESS_FCT(statusTmp, phCryptoSym_CalculateMac(
          pDataParams->pCryptoDataParams,
          PH_CRYPTOSYM_MAC_MODE_CBCMAC,
          aCipher,
          (4U * PHCRYPTORNG_SW_OUTLEN),
          pIoString,
          &bMacLength));

  /* SECOND ITERATION */
  /* Note: IV is still zero */

  /* 9.1 IV = i || 0 exp (outlen - len (i)). */
  /* 9.2 temp = temp || BCC (K, (IV || S)). */
  /* NOTE: BCC SPEC: */
  /* 4. For i = 1 to n do  */
  /* 4.1 input_block = chaining_value xor block_i.  */
  /* 4.2 chaining_value = Block_Encrypt (Key, input_block).  */
  /* 5. output_block = chaining_value.  */
  /* Set the MAC mode to CBC mac which is equal to BCC*/
  aCipher[0] = 0x01;
  PH_CHECK_SUCCESS_FCT(statusTmp, phCryptoSym_CalculateMac(pDataParams->pCryptoDataParams,
          PH_CRYPTOSYM_MAC_MODE_CBCMAC,
          aCipher,
          (4U * PHCRYPTORNG_SW_OUTLEN),
          &pIoString[bMacLength],
          &bMacLength));

  /* Finally we have calculated the Key */
  /* 10. K = Leftmost keylen bits of temp. */
#ifndef PH_CRYPTOSYM_SW_AES
#error "No valid cipher available"
#else
  /* We can load the newly created key */
  PH_CHECK_SUCCESS_FCT(statusTmp, phCryptoSym_LoadKeyDirect(
          pDataParams->pCryptoDataParams,
          pIoString,
          PH_CRYPTOSYM_KEY_TYPE_AES128));
#endif /* PH_CRYPTOSYM_SW_AES */

  /* 11. X = Next outlen bits of temp. */
  /* 13.1 X = Block_Encrypt (K, X). */
  /* 13.2 temp = temp || X. */
  /* Encrypt X (which is upper part of pIoString) into lower part of pIoString. */
  PH_CHECK_SUCCESS_FCT(statusTmp, phCryptoSym_Encrypt(pDataParams->pCryptoDataParams,
          PH_CRYPTOSYM_CIPHER_MODE_ECB,
          &pIoString[PHCRYPTORNG_SW_KEYLEN],
          PHCRYPTORNG_SW_OUTLEN,
          pIoString));

  /* 11. X = Next outlen bits of temp. */
  /* 13.1 X = Block_Encrypt (K, X). */
  /* 13.2 temp = temp || X. */
  /* Encrypt X (which is now lower part of pIoString) into upper part of pIoString. */
  PH_CHECK_SUCCESS_FCT(statusTmp, phCryptoSym_Encrypt(pDataParams->pCryptoDataParams,
          PH_CRYPTOSYM_CIPHER_MODE_ECB,
          pIoString,
          PHCRYPTORNG_SW_OUTLEN,
          &pIoString[PHCRYPTORNG_SW_KEYLEN]));

  return PH_ERR_SUCCESS;
}

static void phCryptoRng_Sw_IncrementV(phCryptoRng_Sw_DataParams_t *pDataParams)
{
  uint8_t PH_MEMLOC_REM bIndex;

  /* Increment the V value of the pDataParams structure by 1 mod 2^128. Note: LSB is stored in position 0. */
  for (bIndex = 0; bIndex < PHCRYPTORNG_SW_OUTLEN; ++bIndex) {
    if (pDataParams->V[bIndex] < 0xFFU) {
      ++pDataParams->V[bIndex];
      break;
    } else {
      pDataParams->V[bIndex] = 0x00;
    }
  }
}

#endif /* NXPBUILD__PHCRYPTORNG_SW */
