#include "os/mynewt.h"
#include <modlog/modlog.h>

#ifdef NXPBUILD__PHBAL_REG_T1SAMAV3
#include <nrfx.h>
#include <nrfx_uarte.h>
#include <nxp_nfc/phbalReg.h>
#include "phbalReg_ISO7816.h"
#include "phbalReg_SamAV3_error.h"

#define PPS_MSG_LEN (4)
/* Start delay (in ticks) after peripheral init */
#define ISO7816_START_DELAY (10)

struct iso7816_cfg {
  nrfx_pwm_t *pwm_inst;
  nrfx_uarte_t *uart_inst;
  uint32_t baud_rate;
};

static struct iso7816_cfg g_iso7816_cfg;
static uint8_t uarte_RX_data [PHBAL_REG_T1SAMAV3_MAX_APDU_LEN + PHBAL_REG_T1SAMAV3_HEADER_LEN +
                                    PHBAL_REG_T1SAMAV3_LRC_LEN];
static uint8_t ppsMsg[PPS_MSG_LEN] = {0xff, 0x11, 0x01, 0xef};

static phbalReg_T1SamAV3_error_t
phbalReg_T1SamAV3_ISO7816_init(void)
{
  nrfx_err_t error;
  uint8_t e = 0;
  /* PWM configuration */
  nrfx_pwm_config_t pwmCfg = {
    .output_pins = {
      MYNEWT_VAL(MF4SAM3_ONB_CLK_PIN) | NRFX_PWM_PIN_INVERTED,
      NRFX_PWM_PIN_NOT_USED,
      NRFX_PWM_PIN_NOT_USED,
      NRFX_PWM_PIN_NOT_USED
    },
    .irq_priority = NRFX_PWM_DEFAULT_CONFIG_IRQ_PRIORITY,
    .base_clock = NRF_PWM_CLK_16MHz,
    .count_mode = NRF_PWM_MODE_UP,
    /* 9 clock counts for having 1.778 MHz */
    .top_value = MYNEWT_VAL(SAMAV3_PWM_COUNT),
    .load_mode = NRF_PWM_LOAD_COMMON,
    .step_mode = NRF_PWM_STEP_AUTO
  };

  /**
   * Initialize and configure UARTE for reading the ATR after
   * power cycling the board.
   * IO1 and IO2 can be the same or different based on configuration.
   * Start comms with SAM at 4800 bit/s,
   */
  nrfx_uarte_config_t uarteCfg = {
    .pseltxd            = MYNEWT_VAL(MF4SAM3_ONB_IO1_PIN),
    .pselrxd            = MYNEWT_VAL(MF4SAM3_ONB_IO2_PIN),
    .pselcts            = NRF_UARTE_PSEL_DISCONNECTED,
    .pselrts            = NRF_UARTE_PSEL_DISCONNECTED,
    .p_context          = NULL,
    .baudrate           = g_iso7816_cfg.baud_rate,
    .interrupt_priority = NRFX_UARTE_DEFAULT_CONFIG_IRQ_PRIORITY,
    .hal_cfg.hwfc       = NRF_UARTE_HWFC_DISABLED,
    .hal_cfg.parity     = NRF_UARTE_PARITY_INCLUDED,
    .hal_cfg.stop		= NRF_UARTE_STOP_TWO,
    .hal_cfg.paritytype	= NRF_UARTE_PARITYTYPE_EVEN,
  };

  error = nrfx_pwm_init(g_iso7816_cfg.pwm_inst, &pwmCfg, NULL, NULL);
  if (error != NRFX_SUCCESS) {
    return PHBAL_REG_T1SAMAV3_ISO7816_CLK_INVALID_INIT;
  }

  /* Sequence value definition */
  static nrf_pwm_values_common_t pwmValues[] = {MYNEWT_VAL(SAMAV3_PWM_DUTY_CYCLE)};
  nrf_pwm_sequence_t const pwmSequence = {
    .values.p_common	 	= pwmValues,
    .length          		= NRF_PWM_VALUES_LENGTH(pwmValues),
    .repeats         		= 0,
    .end_delay       		= 0
  };

  error = nrfx_uarte_init(g_iso7816_cfg.uart_inst, &uarteCfg, NULL);
  if (error != NRFX_SUCCESS) {
    if (error == NRFX_ERROR_INVALID_STATE) {
      return PHBAL_REG_T1SAMAV3_ISO7816_UART_INVALID_INIT;
    } else if (error == NRFX_ERROR_BUSY) {
      return PHBAL_REG_T1SAMAV3_ISO7816_UART_BUSY;
    } else {
      return PHBAL_REG_T1SAMAV3_BASE_ERR;
    }
  }

  /* Start PWM based clock */
  error = nrfx_pwm_simple_playback(g_iso7816_cfg.pwm_inst, &pwmSequence, 1, NRFX_PWM_FLAG_LOOP);
  assert(error == 0);

  /* Transceive PPS */
  os_time_delay(ISO7816_START_DELAY);
  nrfx_uarte_tx(g_iso7816_cfg.uart_inst, ppsMsg, PPS_MSG_LEN);
  nrfx_uarte_rx(g_iso7816_cfg.uart_inst, uarte_RX_data, PPS_MSG_LEN);
  nrfx_uarte_rx_abort(g_iso7816_cfg.uart_inst);

  PN5180_LOG_INFO("%s: PPS exchange response: 0x ", __func__);
  for (int i = 0; i < PPS_MSG_LEN; i++) {
    PN5180_LOG_INFO("%02X ", uarte_RX_data[i]);
    if (uarte_RX_data[i] != ppsMsg[i]) {
      e ++;
    }
  }

  if (e == 0) {
    PN5180_LOG_INFO("%s: PPS exchange is correct\n", __func__);
  } else {
    PN5180_LOG_ERROR("%s: Error in PPS exchange\n", __func__);
    return PHBAL_REG_T1SAMAV3_ISO7816_UART_INVALID_INIT;
  }

  return PHBAL_REG_T1SAMAV3_SUCCESS;
}

phbalReg_T1SamAV3_error_t
phbalReg_T1SamAV3_ISO7816_uinit(void)
{
  nrfx_uarte_uninit(g_iso7816_cfg.uart_inst);
  nrfx_pwm_uninit(g_iso7816_cfg.pwm_inst);
  return PHBAL_REG_T1SAMAV3_SUCCESS;
}

phbalReg_T1SamAV3_error_t
phbalReg_T1SamAV3_ISO7816_snd_blocking(
    void *data,
    uint16_t len)
{
  nrfx_err_t error;

  error = nrfx_uarte_tx(g_iso7816_cfg.uart_inst, (uint8_t *)data, len);

  switch (error) {
    case NRFX_ERROR_BUSY:
      return PHBAL_REG_T1SAMAV3_ISO7816_UART_TX_BUSY;
      break;
    case NRFX_ERROR_FORBIDDEN:
      return PHBAL_REG_T1SAMAV3_ISO7816_UART_TX_ABORTED;
      break;
    case NRFX_ERROR_INVALID_ADDR:
      return PHBAL_REG_T1SAMAV3_ISO7816_UART_TX_INVALID_ADD;
      break;
    default:
      break;
  }

  return PHBAL_REG_T1SAMAV3_SUCCESS;
}

phbalReg_T1SamAV3_error_t
phbalReg_T1SamAV3_ISO7816_rcv_blocking(
    void *data,
    uint16_t expected_bytes,
    uint16_t *received_bytes)
{
  nrfx_err_t error = NRFX_SUCCESS;
  *received_bytes = 0;

  error = nrfx_uarte_rx(g_iso7816_cfg.uart_inst, data, expected_bytes);

  PN5180_LOG_ERROR("%s: Reading UART error %lX \n", __func__,
      nrfx_uarte_errorsrc_get(g_iso7816_cfg.uart_inst));
  PN5180_LOG_INFO("%s: Read bytes: 0x ", __func__);
  for (int i = 0; i < expected_bytes ; i++) {
    PN5180_LOG_INFO("%02X ", ((uint8_t *)data)[i]);
  }
  PN5180_LOG_INFO("\n");

  switch (error) {
    case NRFX_SUCCESS:
      *received_bytes = expected_bytes;
      break;
    case NRFX_ERROR_BUSY:
      return PHBAL_REG_T1SAMAV3_ISO7816_UART_RX_BUSY;
      break;
    case NRFX_ERROR_FORBIDDEN:
      return PHBAL_REG_T1SAMAV3_ISO7816_UART_RX_ABORTED;
      break;
    case NRFX_ERROR_INTERNAL:
      return PHBAL_REG_T1SAMAV3_ISO7816_UART_RX_INTERNAL;
      break;
    case NRFX_ERROR_INVALID_ADDR:
      return PHBAL_REG_T1SAMAV3_ISO7816_UART_RX_INVALID_ADD;
      break;
    default:
      break;
  }

  return PHBAL_REG_T1SAMAV3_SUCCESS;
}

static void
nrfx_uarte_rx_flush(nrfx_uarte_t const *p_instance)
{
  nrf_uarte_task_trigger(p_instance->p_reg, NRF_UARTE_TASK_FLUSHRX);
}

static void
phbalReg_T1SamAV3_ISO7816_flush_rx(void)
{
  nrfx_uarte_rx_abort(g_iso7816_cfg.uart_inst);
  while (!nrfx_uarte_rx_ready(g_iso7816_cfg.uart_inst));
  nrfx_uarte_rx_flush(g_iso7816_cfg.uart_inst);
  while (!nrfx_uarte_rx_ready(g_iso7816_cfg.uart_inst));
}

phbalReg_T1SamAV3_error_t
phbalReg_T1SamAV3_ISO7816_transceive_blocking(
    void *data,
    uint16_t txLen,
    uint16_t *received_bytes)
{
  phbalReg_T1SamAV3_error_t error;
  uint16_t resp_len = 0;
  uint16_t expected_resp_len = 4;
  uint16_t next_read_size = 4;
  uint8_t retry = 0;
  uint16_t read_bytes = 0;

  /* Transmit data */
  while (!nrfx_uarte_rx_ready(g_iso7816_cfg.uart_inst));

  error = phbalReg_T1SamAV3_ISO7816_snd_blocking(data, txLen);
  if (error != PHBAL_REG_T1SAMAV3_SUCCESS) {
    return error;
  }

  phbalReg_T1SamAV3_ISO7816_flush_rx();

  /* Receive data */
  memset((uint8_t *)data, 0x00, sizeof(data));

  while (retry < PHBAL_REG_T1SAMAV3_MAX_UART_READ_RETRIES && resp_len < expected_resp_len) {
    error = phbalReg_T1SamAV3_ISO7816_rcv_blocking(&((uint8_t *)data)[resp_len], next_read_size,
            &read_bytes);

    if (resp_len < PHBAL_REG_T1SAMAV3_INF_LEN_FIELD_OFFSET
        && resp_len + read_bytes >= PHBAL_REG_T1SAMAV3_INF_LEN_FIELD_OFFSET) {
      /* Inf len was read in this chunk, so we can update the expected block length */
      expected_resp_len += ((uint8_t *)data)[PHBAL_REG_T1SAMAV3_INF_LEN_FIELD_OFFSET];
    }
    resp_len += read_bytes;

    if (error == PHBAL_REG_T1SAMAV3_SUCCESS) {
      retry = 0;
    } else if (read_bytes == 0) {
      /**
       * Make as many as PHBAL_REG_T1SAMAV3_MAX_UART_READ_RETRIES consecutive
       * attempts where 0 bytes can be read from the SAM
       */
      PN5180_LOG_ERROR("UARTE rcv error : %04lx\n", error);
      retry++;
    }

    /* Try to read as many bytes as possible on the next iteration */
    next_read_size = expected_resp_len - resp_len;
  }

  if (retry >= PHBAL_REG_T1SAMAV3_MAX_UART_READ_RETRIES) {
    *received_bytes = 0;
    error = PHBAL_REG_T1SAMAV3_ISO7816_UART_RX;
  } else {
    *received_bytes = resp_len;
    error = PHBAL_REG_T1SAMAV3_SUCCESS;
  }

  phbalReg_T1SamAV3_ISO7816_flush_rx();
  return error;
}

phStatus_t
phbalReg_T1SamAV3_tml_ISO7816_init(
    phbalReg_T1SamAV3_tml_t *tml,
    nrfx_pwm_t *pwmDrv,
    nrfx_uarte_t *uarteDrv,
    uint32_t baudRate
)
{
  g_iso7816_cfg.pwm_inst = pwmDrv;
  g_iso7816_cfg.uart_inst = uarteDrv;
  g_iso7816_cfg.baud_rate = baudRate;

  tml->init = phbalReg_T1SamAV3_ISO7816_init;
  tml->uninit = phbalReg_T1SamAV3_ISO7816_uinit;
  tml->rcv_blocking = phbalReg_T1SamAV3_ISO7816_rcv_blocking;
  tml->snd_blocking = phbalReg_T1SamAV3_ISO7816_snd_blocking;
  tml->transceive = phbalReg_T1SamAV3_ISO7816_transceive_blocking;

  return PH_ERR_SUCCESS;
}

#endif /* NXPBUILD__PHBAL_REG_T1SAMAV3 */
