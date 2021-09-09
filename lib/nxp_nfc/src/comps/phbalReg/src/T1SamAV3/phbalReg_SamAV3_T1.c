#include "os/mynewt.h"
#include <stdint.h>
#include <stdbool.h>
#include <nxp_nfc/phbalReg.h>
#include <nxp_nfc/ph_TypeDefs.h>
#include <console/console.h>

#ifdef NXPBUILD__PHBAL_REG_T1SAMAV3
#include "phbalReg_SamAV3_T1.h"
#include "phbalReg_SamAV3_error.h"

#define PHBAL_REG_T1SAMAV3__MPOT_INCR_STEP 	0 //increment MPOT delay in 10ms at consecutive retries
#define PHBAL_REG_T1SAMAV3__MPOT_DELAY(ctx, retry) if (ctx->mpot > 0) phbalReg_T1SamAV3_delay(ctx->mpot + (retry * PHBAL_REG_T1SAMAV3__MPOT_INCR_STEP))
#define PHBAL_REG_T1SAMAV3__SEGT_DELAY(ctx) if (ctx->segt > 0) phbalReg_T1SamAV3_delay(ctx->segt)

#define PHBAL_REG_T1SAMAV3_HD_TO_SE_NAD 		0x00
#define PHBAL_REG_T1SAMAV3_SE_TO_HD_NAD 		0x00
#define PHBAL_REG_T1SAMAV3__M_BIT 				0x20

#define PHBAL_REG_T1SAMAV3__DFLT_ISFC			254
#define PHBAL_REG_T1SAMAV3__DFLT_MPOT			100
#define PHBAL_REG_T1SAMAV3__DFLT_SEGT			1 //10

#define PHBAL_REG_T1SAMAV3__MIN_MPOT			1 //5
#define PHBAL_REG_T1SAMAV3__MIN_SEGT			1

#define PHBAL_REG_T1SAMAV3_RBLOCK_ACK			0x0
#define PHBAL_REG_T1SAMAV3_RBLOCK_LRC_ERR		0x1
#define PHBAL_REG_T1SAMAV3_RBLOCK_OTHER_ERR		0x2

/* Functions definition */
void
phbalReg_T1SamAV3_delay(uint8_t ms)
{
  os_time_t ticks;
  if (OS_EINVAL != os_time_ms_to_ticks(ms, &ticks)) {
    os_time_delay(ticks);
  }
}

static uint8_t
phbalReg_T1SamAV3_seq(phbalReg_T1SamAV3_DataParams_t *ctx)
{
  uint8_t ret = ctx->next_seq;
  if (ctx->next_seq == 0x0) {
    ctx->next_seq = 0x1;
  } else {
    ctx->next_seq = 0x0;
  }
  return ret;
}

static uint8_t
phbalReg_T1SamAV3_lrc(const uint8_t *data, uint8_t data_len)
{
  uint8_t CAL_LRC = 0x00, i = 0;

  PH_ASSERT_NULL(data);

  for (i = 0; i < data_len; i++) {
    CAL_LRC ^= data[i];
  }

  return CAL_LRC;
}

static phbalReg_T1SamAV3_error_t
phbalReg_T1SamAV3_handle_rblock(phbalReg_T1SamAV3_DataParams_t *ctx, uint8_t *rblock)
{
  phbalReg_T1SamAV3_error_t err;

  /* NAD, LEN and PCB should be already checked before. Also true for the LRC, which we can skip */
  PHBAL_REG_T1SAMAV3_ASSERT(rblock[0] == PHBAL_REG_T1SAMAV3_HD_TO_SE_NAD);
  PHBAL_REG_T1SAMAV3_ASSERT((rblock[1] & 0xC0) == 0x80);
  PHBAL_REG_T1SAMAV3_ASSERT(rblock[2] == 0);

  /* Check error code */
  switch (rblock[1] & 0x3) {
    case PHBAL_REG_T1SAMAV3_RBLOCK_ACK:
      err = PHBAL_REG_T1SAMAV3_SUCCESS;
      break;

    case PHBAL_REG_T1SAMAV3_RBLOCK_LRC_ERR:
      err = PHBAL_REG_T1SAMAV3_RCV_LRC_ERR;
      break;

    case PHBAL_REG_T1SAMAV3_RBLOCK_OTHER_ERR:
      err = PHBAL_REG_T1SAMAV3_RCV_OTHER_ERR;
      break;

    default:
      err = PHBAL_REG_T1SAMAV3_RCV_INVALID_ERR;
  }
  return err;
}

static phbalReg_T1SamAV3_error_t
phbalReg_T1SamAV3_transceive(
    phbalReg_T1SamAV3_DataParams_t *ctx,
    uint8_t pcb,
    const uint8_t *inf,
    uint16_t inf_len
)
{
  PN5180_LOG_INFO("%s: Transceiving data\n", __func__);
  phbalReg_T1SamAV3_error_t err = PHBAL_REG_T1SAMAV3_SUCCESS;
  uint8_t *ptr = ctx->block;
  uint16_t lrc;
  uint16_t expected_lrc;
  uint16_t full_packet_len;
  uint16_t resp_len;

  *ptr++ = PHBAL_REG_T1SAMAV3_HD_TO_SE_NAD;
  *ptr++ = pcb;
  *ptr++ = inf_len;

  if (inf_len) {
    memcpy(ptr, inf, inf_len);
  }

  ptr += inf_len;

  lrc = phbalReg_T1SamAV3_lrc(ctx->block, ptr - ctx->block);

  *ptr++ = lrc & 0xff;

  PN5180_LOG_INFO("%s: Sending:\n 0x ", __func__);
  for (uint16_t i = 0; i < (ptr - ctx->block); i++) {
    PN5180_LOG_INFO("%02X ", ctx->block[i]);
  }
  PN5180_LOG_INFO("\n");

  if ((err = ctx->tml->transceive(ctx->block, ptr - ctx->block,
                  &resp_len)) != PHBAL_REG_T1SAMAV3_SUCCESS) {
    PN5180_LOG_ERROR("%s: Error transceiving data: %lX \n 0x ", __func__, err);
    phbalReg_T1SamAV3_seq(ctx);
    PHBAL_REG_T1SAMAV3__SEGT_DELAY(ctx);
    goto exit;
  }

  // Check packet integrity
  PN5180_LOG_INFO("%s: Received APDU: \n 0x ", __func__);
  for (uint16_t i = 0; i < resp_len; i++) {
    PN5180_LOG_INFO("%02X ", ctx->block[i]);
  }
  PN5180_LOG_INFO("\n");

  /* NAD */
  if (ctx->block[0] != PHBAL_REG_T1SAMAV3_SE_TO_HD_NAD) {
    err = PHBAL_REG_T1SAMAV3_RCV_UNEXPECTED_NAD;
    goto exit;
  }

  /* LRC check */
  full_packet_len = PHBAL_REG_T1SAMAV3_HEADER_LEN + PHBAL_REG_T1SAMAV3_LRC_LEN +  ctx->block[2];
  lrc = ctx->block[full_packet_len - 1];
  expected_lrc = phbalReg_T1SamAV3_lrc(ctx->block, full_packet_len - 1);

  if (lrc != expected_lrc) {
    err = PHBAL_REG_T1SAMAV3_RCV_UNEXPECTED_LRC;
    goto exit;
  }

  if ((ctx->block[1] & 0xC0) == 0x80) {
    // R-block
    err = phbalReg_T1SamAV3_handle_rblock(ctx, ctx->block);
  } else if ((ctx->block[1] & 0xC0) == 0xC0) {

  }

exit:
  return err;
}

phStatus_t
phbalReg_T1SamAV3_Exchange(
    phbalReg_T1SamAV3_DataParams_t *ctx,		 		/**< [In] Pointer to this layer's parameter structure. */
    uint16_t wOption,      								/**< [In] Option parameter, for future use. */
    uint8_t *pTxBuffer,    								/**< [In] Data to transmit. */
    uint16_t wTxLength,    								/**< [In] Number of bytes to transmit, if 0 Tx is not performed. */
    uint16_t wRxBufSize,   								/**< [In] Size of receive buffer / Number of bytes to receive (depending on implementation). If 0 Rx is not performed.  */
    uint8_t *pRxBuffer,    								/**< [Out] Received data. */
    uint16_t *pRxLength    								/**< [Out] Number of received data bytes. */
)
{
  phbalReg_T1SamAV3_error_t err;
  uint8_t pcb;

  /* Check options */
  if (wOption != PH_EXCHANGE_DEFAULT) {
    return PH_ADD_COMPCODE(PH_ERR_INVALID_PARAMETER, PH_COMP_BAL);
  }
  /* Reset receive length */
  *pRxLength = 0;
  memset(ctx->block, 0x00, sizeof(ctx->block));

  PN5180_LOG_INFO("%s: Starting APDU transmission\n", __func__);
  pcb = phbalReg_T1SamAV3_seq(ctx) << 6;
  err = phbalReg_T1SamAV3_transceive(ctx, pcb, pTxBuffer, wTxLength);
  if (err != PHBAL_REG_T1SAMAV3_SUCCESS) {
    PN5180_LOG_ERROR("%s: Error during transceive %lX \n", __func__, err);
    goto exit;
  }

  *pRxLength = ctx->block[2];
  for (int i = 0; i < ctx->block[2]; i++) {
    pRxBuffer[i] = ctx->block[3 + i];
  }

  PN5180_LOG_INFO("%s: Received DATA: \n 0x ", __func__);
  for (uint16_t i = 0; i < *pRxLength; i++) {
    PN5180_LOG_INFO("%02X ", pRxBuffer[i]);
  }
  PN5180_LOG_INFO("\n");

exit:
  if (err == PHBAL_REG_T1SAMAV3_SUCCESS) {
    return PH_ADD_COMPCODE(PH_ERR_SUCCESS, PH_COMP_BAL);
  } else {
    return PH_ADD_COMPCODE(PH_ERR_SUCCESS, PH_ERR_MASK);
  };
}

phbalReg_T1SamAV3_error_t
phbalReg_T1SamAV3_uninit(phbalReg_T1SamAV3_DataParams_t *ctx)
{
  phbalReg_T1SamAV3_error_t err = PHBAL_REG_T1SAMAV3_SUCCESS;

  PHBAL_REG_T1SAMAV3_ASSERT(ctx);

  if (ctx->tml && ctx->tml->uninit) {
    err = ctx->tml->uninit();
  }

  return err;
}

phStatus_t
phbalReg_T1SamAv3_Init(
    phbalReg_T1SamAV3_DataParams_t
    *pDataParams,     	/**< [In] Pointer to this layer's parameter structure phbalReg_Type_t. */
    uint16_t wSizeOfDataParams,              			/**< [In] Size of this layer's parameter structure. */
    phbalReg_T1SamAV3_tml_t *tml
)
{
  if (sizeof(phbalReg_T1SamAV3_DataParams_t) != wSizeOfDataParams) {
    return PH_ADD_COMPCODE(PH_ERR_INVALID_DATA_PARAMS, PH_COMP_BAL);
  }
  PH_ASSERT_NULL(pDataParams);
  PH_ASSERT_NULL(tml);

  tml->init();

  pDataParams->wId 		= PH_COMP_BAL | PHBAL_REG_T1SAMAV3_ID;
  pDataParams->state 		= PHBAL_REG_T1SAMAV3_IDLE;
  pDataParams->tml 		= tml;
  pDataParams->next_seq 	= 0;
  pDataParams->ifsc 		= PHBAL_REG_T1SAMAV3__DFLT_ISFC;
  pDataParams->mpot 		= PHBAL_REG_T1SAMAV3__DFLT_MPOT;
  pDataParams->segt 		= PHBAL_REG_T1SAMAV3__DFLT_SEGT;

  return PH_ADD_COMPCODE(PH_ERR_SUCCESS, PH_COMP_BAL);
}

#endif /* NXPBUILD__PHBAL_REG_T1SAMAV3 */
