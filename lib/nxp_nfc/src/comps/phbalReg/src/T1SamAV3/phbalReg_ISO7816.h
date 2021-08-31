#ifndef PHBALREG_T1SAMAV3_TML_ISO7816_H
#define PHBALREG_T1SAMAV3_TML_ISO7816_H

#include <nxp_nfc/phbalReg.h>
#include <nxp_nfc/ph_Status.h>
#include <nrfx/drivers/include/nrfx_pwm.h>
#include <nrfx/drivers/include/nrfx_uarte.h>

phStatus_t phbalReg_T1SamAV3_tml_ISO7816_init(
    phbalReg_T1SamAV3_tml_t *tml,
    nrfx_pwm_t *pwmDrv,
    nrfx_uarte_t *uarteDrv,
    uint32_t baudRate
);

#endif /* PHBALREG_T1SAMAV3_TML_ISO7816_H */
