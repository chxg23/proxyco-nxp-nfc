#ifndef PHBALREG_T1SAMAV3_H
#define PHBALREG_T1SAMAV3_H

#include <nxp_nfc/ph_Status.h>
#include <nxp_nfc/phbalReg.h>
#include <stdint.h>

phStatus_t phbalReg_T1SamAV3_Exchange(
    phbalReg_T1SamAV3_DataParams_t
    *pDataParams, 		/**< [In] Pointer to this layer's parameter structure. */
    uint16_t wOption,      								/**< [In] Option parameter, for future use. */
    uint8_t *pTxBuffer,    								/**< [In] Data to transmit. */
    uint16_t wTxLength,    								/**< [In] Number of bytes to transmit, if 0 Tx is not performed. */
    uint16_t wRxBufSize,   								/**< [In] Size of receive buffer / Number of bytes to receive (depending on implementation). If 0 Rx is not performed.  */
    uint8_t *pRxBuffer,    								/**< [Out] Received data. */
    uint16_t *pRxLength    								/**< [Out] Number of received data bytes. */
);

#endif /* PHBALREG_T1SAMAV3_H */
