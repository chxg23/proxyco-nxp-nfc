/*
 * @Copyright Proxy
 *
 * Author: Vipul Rahane <vipul@proxy.com>
 */

/** \file
* Generic phDriver Component of Reader Library Framework.
* $Author$
* $Revision$
* $Date$
*/

#ifndef BOARD_NRF5340DK_PN5180_H
#define BOARD_NRF5340DK_PN5180_H

#include <hal/hal_gpio.h>

/******************************************************************
 * Board Pin/Gpio configurations
 ******************************************************************/
#define PHDRIVER_PIN_RESET         (MYNEWT_VAL(PHDRIVER_PIN_RESET)) /**< Reset pin */
#define PHDRIVER_PIN_IRQ           (MYNEWT_VAL(PHDRIVER_PIN_IRQ))   /**< Interrupt pin from Frontend to Host*/
#define PHDRIVER_PIN_BUSY          (MYNEWT_VAL(PHDRIVER_PIN_BUSY))  /**< Frontend's Busy Status */
#define PHDRIVER_PIN_DWL           (MYNEWT_VAL(PHDRIVER_PIN_DWL))   /**< Download mode pin of Frontend */

/******************************************************************
 * PIN Pull-Up/Pull-Down configurations.
 ******************************************************************/
#define PHDRIVER_PIN_RESET_PULL_CFG    HAL_GPIO_PULL_UP
#define PHDRIVER_PIN_IRQ_PULL_CFG      HAL_GPIO_PULL_UP
#define PHDRIVER_PIN_BUSY_PULL_CFG     HAL_GPIO_PULL_UP
#define PHDRIVER_PIN_DWL_PULL_CFG      HAL_GPIO_PULL_UP
#define PHDRIVER_PIN_NSS_PULL_CFG      HAL_GPIO_PULL_UP

/******************************************************************
 * IRQ PIN NVIC settings
 ******************************************************************/
#define PIN_IRQ_TRIGGER_TYPE    HAL_GPIO_TRIG_RISING  /**< IRQ pin RISING edge interrupt */
#define EINT_PRIORITY           5                     /**< Interrupt priority. */
#define EINT_IRQn               GPIOTE_IRQn           /**< NVIC IRQ */

/*****************************************************************
 * Front End Reset logic level settings
 ****************************************************************/
#define PH_DRIVER_SET_HIGH            1          /**< Logic High. */
#define PH_DRIVER_SET_LOW             0          /**< Logic Low. */
#define RESET_POWERDOWN_LEVEL PH_DRIVER_SET_LOW
#define RESET_POWERUP_LEVEL   PH_DRIVER_SET_HIGH

/******************************************************************/
#define PHDRIVER_PIN_SSEL     (MYNEWT_VAL(PN5180_ONB_CS))

#endif /* BOARD_NRF5340DK_PN5180_H */
