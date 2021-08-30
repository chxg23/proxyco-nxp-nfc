/* Mynewt Dependencies */
#include "os/mynewt.h"
#include <console/console.h>
#include <log/log.h>
#include <assert.h>
#include <string.h>
#include "modlog/modlog.h"
#include "../../../lib/nxp_nfc/src/comps/phhalHw/src/Pn5180/phhalHw_Pn5180.h"
#include "../../../lib/nxp_nfc/src/comps/phhalHw/src/SamAV3/phhalHw_SamAv3.h"
#include <bsp/bsp.h>

#ifdef MYNEWT_VAL_PHOSAL_EVQ
struct os_eventq MYNEWT_VAL(PHOSAL_EVQ);
#endif

/**
* Reader Library Headers
*/
#include <phApp_Init.h>
#include <nxp_nfc/phbalReg.h>
#include "NfcrdlibEx_SamAv3.h"

#include <nxp_nfc/phKeyStore.h>
#include <nxp_nfc/phCryptoRng.h>
#include <nxp_nfc/phCryptoSym.h>
#include <nxp_nfc/phpalI14443p3a.h>
#include <nxp_nfc/phpalI14443p4a.h>
#include <nxp_nfc/phpalI14443p4.h>
#include <nxp_nfc/phpalMifare.h>
#include <nxp_nfc/phhalHw.h>
#include <nxp_nfc/phhalHw_SamAv3_Cmd.h>

/* SAM configuration*/
#define SAM_MASTER_KEY_ADDRESS					0
#define SAM_MASTER_KEY_VERSION					0
#define SAM_MASTER_KEY							0x00

#define PH_EXMFCRYPTO_MFDFCRYPTO_MIFAREDESFIRE_SAK      0x20
#define KEYCOUNT                21
#define KEYVERSIONS              1
#define DES_KEY_ADDRESS_0       10       /* PICC Key entry number in key store. */
#define DES_KEY_ADDRESS_1       11       /* PICC Key entry number in key store. */
#define DES_KEY_ADDRESS_2       12       /* PICC Key entry number in key store. */
#define DES_KEY_VERSION         00       /* PICC Key entry number in key store. */
#define AES_KEY_ADDRESS_0      	13       /* PICC Key entry number in key store. */
#define AES_KEY_ADDRESS_1      	14       /* PICC Key entry number in key store. */
#define AES_KEY_ADDRESS_2      	15       /* PICC Key entry number in key store. */
#define AES_KEY_VERSION      	00       /* PICC Key entry number in key store. */

#define PICC_MASTER_KEY          0
#define APP_MASTER_KEY           0
#define STDDATAFILE1             1       /* File number of Standard data file 1. */
#define TMAC_FILE                2       /* File number of Transaction MAC file 1. */

/* NFC Task */
#define NFC_TASK_PRIO 			(110)
#define NFC_TASK_STACK_SIZE    	OS_STACK_ALIGN(2048)
OS_TASK_STACK_DEFINE(g_nfc_task_stack, NFC_TASK_STACK_SIZE);
static struct os_task desf_detect;

//volatile int loop = 1;

/* Global variables */
phacDiscLoop_Sw_DataParams_t*	pDiscLoop;       /* Discovery loop component */
phpalI14443p3a_Sw_DataParams_t* I14443p3a;
phpalI14443p4a_Sw_DataParams_t*	I14443p4a;
phpalI14443p4_Sw_DataParams_t* 	I14443p4;
phpalMifare_Sw_DataParams_t* 	palMifare;
phKeyStore_Sw_DataParams_t * 	pKeyStore;
phalMfdf_Sw_DataParams_t *		palMfdf;

phKeyStore_Sw_KeyEntry_t       keyEntry[KEYCOUNT];
phKeyStore_Sw_KeyVersionPair_t keyVersion[KEYCOUNT * KEYVERSIONS];
phKeyStore_Sw_KUCEntry_t       keyUsage[KEYCOUNT];

static uint8_t aPICC_MasterKey_DES_0[16] = {
	0x01, 0x23, 0x45, 0x67, 0x89, 0xAB, 0xCD, 0xEF,
	0xFE, 0xDC, 0xBA, 0x98, 0x76, 0x54, 0x32, 0x10
};
static uint8_t aPICC_MasterKey_DES_1[16] = {
	0xFE, 0xDC, 0xBA, 0x98, 0x76, 0x54, 0x32, 0x10,
	0x01, 0x23, 0x45, 0x67, 0x89, 0xAB, 0xCD, 0xEF
};
static uint8_t aPICC_MasterKey_DES_2[16] = {
	0x76, 0x54, 0x32, 0x10, 0xFE, 0xDC, 0xBA, 0x98,
	0x89, 0xAB, 0xCD, 0xEF, 0x01, 0x23, 0x45, 0x67
};
static uint8_t aPICC_MasterKey_AES_0[16] = {
	0x89, 0xAB, 0xCD, 0xEF, 0x01, 0x23, 0x45, 0x67,
	0x76, 0x54, 0x32, 0x10, 0xFE, 0xDC, 0xBA, 0x98
};
static uint8_t aPICC_MasterKey_AES_1[16] = {
	0x11, 0x11, 0x22, 0x22, 0x33, 0x33, 0x44, 0x44,
	0xFF, 0xFF, 0xEE, 0xEE, 0xDD, 0xDD, 0xCC, 0xCC
};
static uint8_t aPICC_MasterKey_AES_2[16] = {
	0xFF, 0xFF, 0xEE, 0xEE, 0xDD, 0xDD, 0xCC, 0xCC,
	0x11, 0x11, 0x22, 0x22, 0x33, 0x33, 0x44, 0x44
};
static uint8_t aHostAuthKey[16] = {
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00
};

/*******************************************************************************
**   Static Defines
*******************************************************************************/
static uint16_t bSavePollTechCfg;
static struct samAV3 g_samAV3;
static phbalReg_T1SamAV3_tml_t g_tml;

/*******************************************************************************
**   Function Declarations
*******************************************************************************/
static void nfc_task_init(void);
void Desfire_Detection_Demo(void *arg);
phStatus_t keyStore_Config (void);
static phStatus_t LoadProfile(phacDiscLoop_Profile_t bProfile);
phStatus_t Test_PlainText (void);
phStatus_t Test_DES_SW_keyStore(void);
phStatus_t Test_AES_SW_keyStore(void);
phStatus_t Test_DES_SAM_keyStore(void);
phStatus_t Test_AES_SAM_keyStore(void);
phStatus_t discoveryDetection(void *pDataParams);
phStatus_t nfcCardDetection(void);

/*******************************************************************************
**   Function Definitions
*******************************************************************************/

/**
* This function demonstrates the usage of DESFire Demo
* \param   pDataParams      The discovery loop data parameters
* \note    This function will never return
*/
void Desfire_Detection_Demo(void *pDataParams)
{
	console_printf("\n starting demo task: \n");

	uint8_t versionBuffer[31];
	uint8_t versionLen = 0;
	int rc = 0;
	phStatus_t status;

	console_printf("\n %s: Start creating SAM device\n", __func__);

	g_samAV3.hal_params = (phhalHw_SamAV3_DataParams_t *)  phNfcLib_GetDataParams(PH_COMP_HAL | PHHAL_HW_SAMAV3_ID);
	if(g_samAV3.hal_params == NULL)
		console_printf("\n SAM AV3 HAL Data Params is NULL: \n");

	g_samAV3.bal_params = (phbalReg_T1SamAV3_DataParams_t *) phNfcLib_GetDataParams(PH_COMP_BAL | PHBAL_REG_T1SAMAV3_ID);
	if(g_samAV3.hal_params == NULL)
		console_printf("\n SAM AV3 BAL Data Params is NULL: \n");

	g_samAV3.tml = &g_tml;

	rc = samAV3_create_ISO7816_dev(&g_samAV3, "samAV3_0");
	SYSINIT_PANIC_ASSERT(rc == 0);

	status = phKeyStore_FormatKeyEntry(pKeyStore, SAM_MASTER_KEY_ADDRESS, PH_CRYPTOSYM_KEY_TYPE_AES128);
	CHECK_STATUS(status);
	status = phKeyStore_SetKeyAtPos(pKeyStore, SAM_MASTER_KEY_ADDRESS, 0x00, PH_CRYPTOSYM_KEY_TYPE_AES128, aHostAuthKey, SAM_MASTER_KEY_VERSION);
	CHECK_STATUS(status);

	//Get version
	os_time_delay(50);
	console_printf("\n starting SAM AV3 GetVersion\n");
	status = phhalHw_SamAV3_Cmd_SAM_GetVersion(g_samAV3.hal_params, versionBuffer, &versionLen);
	CHECK_STATUS(status);

	console_printf("\n SAM AV3 GetVersion response: \n 0x ");
	for(uint8_t i=0; i<versionLen; i++)
		console_printf("%02X ", versionBuffer[i]);
	console_printf("\n ");

	//Check if SAM AV3 is activated
	if(versionBuffer[versionLen - 1] == 0x03){
		os_time_delay(10);
		console_printf("\n Activating SAM AV3 \n");
		status = phhalHw_SamAV3_Cmd_SAM_LockUnlock(g_samAV3.hal_params, PHHAL_HW_SAMAV3_CMD_SAM_LOCK_UNLOCK_TYPE_ACTIVATE_SAM,
				SAM_MASTER_KEY_ADDRESS, SAM_MASTER_KEY_VERSION, SAM_MASTER_KEY, 0, 0, 0, 0);
		CHECK_STATUS(status);
		//Check if activation was successful
		os_time_delay(10);
		memset(versionBuffer, 0x00, sizeof(versionBuffer));
		console_printf("\n starting SAM AV3 GetVersion to see if SAM AV3 activation was done properly\n");
		status = phhalHw_SamAV3_Cmd_SAM_GetVersion(g_samAV3.hal_params, versionBuffer, &versionLen);
		CHECK_STATUS(status);
		if(versionBuffer[versionLen - 1] == 0xA3)
			console_printf("\n SAM AV3 is activated \n");
		else
			console_printf("\n SAM AV3 is not active \n");
	}
	else if(versionBuffer[versionLen - 1] == 0xA3){
		console_printf("\n SAM AV3 is activated \n");
	}

//	discoveryDetection(pDataParams);
	nfcCardDetection();

}

phStatus_t Test_PlainText (void){
	//Select application 12345 and R/W/R in File 1

	return PH_ERR_SUCCESS;
}

phStatus_t Test_DES_SW_keyStore(void){
	//Select application 12345

	return PH_ERR_SUCCESS;
}

phStatus_t Test_AES_SW_keyStore(void){
	//Select application 789ABC

	return PH_ERR_SUCCESS;
}

phStatus_t Test_DES_SAM_keyStore(void){
	//Select application 12345

	return PH_ERR_SUCCESS;
}

phStatus_t Test_AES_SAM_keyStore(void){
	//Select application 789ABC

	return PH_ERR_SUCCESS;
}

/**
 * nfc_task_init Initializes task in the app
 *
 * Called by main.c after sysinit(). This function performs initializations
 * that are required before tasks are running.
 *
 * @return int 0 success; error otherwise.
 */
static void
nfc_task_init(void)
{

#ifdef MYNEWT_VAL_PHOSAL_EVQ
  os_eventq_init(&MYNEWT_VAL(PHOSAL_EVQ));
#endif

  os_task_init(&desf_detect, "desfire", Desfire_Detection_Demo, pDiscLoop,
      NFC_TASK_PRIO, OS_WAIT_FOREVER, g_nfc_task_stack, NFC_TASK_STACK_SIZE);
}

/*******************************************************************************
**   Main Function
*******************************************************************************/
int main(void)
{
    phNfcLib_AppContext_t AppContext = {0};
	phStatus_t status 	= PH_ERR_INTERNAL_ERROR;
	phNfcLib_Status_t dwStatus;

	console_printf("\n MIFARE DESFIRE example started: \n");
	/* Initialize packages (see: syscfg.yml). */
	sysinit();

	/* Initialize reader component: HAL + BAL*/
	//pn5180
	struct pn5180 *pn5180 = NULL;
	config_pn5180();
	pn5180 = (struct pn5180 *)os_dev_lookup("pn5180_0");
	assert(pn5180);
	AppContext.pBalDataparams = &(pn5180->cfg);
	dwStatus = phNfcLib_SetContext(&AppContext);
	CHECK_NFCLIB_STATUS(dwStatus);
	console_printf("\n pn5180 configured: %ld \n", dwStatus - PH_NFCLIB_STATUS_SUCCESS);

	/* Initialize library */
	dwStatus = phNfcLib_Init();
	console_printf("\n Libraries initialized: %ld\n", dwStatus - PH_NFCLIB_STATUS_SUCCESS);
	CHECK_NFCLIB_STATUS(dwStatus);
	if (dwStatus != PH_NFCLIB_STATUS_SUCCESS) {
		assert(0);
	}

	/* Set the generic pointer */
	pHal = phNfcLib_GetDataParams(PH_COMP_HAL);
	pDiscLoop = phNfcLib_GetDataParams(PH_COMP_AC_DISCLOOP);
	pKeyStore = (phKeyStore_Sw_DataParams_t *)  phNfcLib_GetDataParams(PH_COMP_KEYSTORE);
	palMfdf = (phalMfdf_Sw_DataParams_t *) phNfcLib_GetDataParams(PH_COMP_AL_MFDF);
	I14443p3a = (phpalI14443p3a_Sw_DataParams_t *) phNfcLib_GetDataParams(PH_COMP_PAL_ISO14443P3A);
	I14443p4a = (phpalI14443p4a_Sw_DataParams_t *) phNfcLib_GetDataParams(PH_COMP_PAL_ISO14443P4A);
	I14443p4 = (phpalI14443p4_Sw_DataParams_t *) phNfcLib_GetDataParams(PH_COMP_PAL_ISO14443P4);
	palMifare = (phpalMifare_Sw_DataParams_t*) phNfcLib_GetDataParams(PH_COMP_PAL_MIFARE);

	if(pKeyStore == NULL)
		console_printf("\n No Keystore included in NFC lib. Check system defines\n");
	if(palMfdf == NULL)
		console_printf("\n No MIFARE DESFire PAL component included in NFC lib. Check system defines\n");
	if(palMifare == NULL)
		console_printf("\n No MIFARE PAL component included in NFC lib. Check system defines\n");
	if(I14443p4 == NULL)
		console_printf("\n No ISO 14443P4 PAL component included in NFC lib. Check system defines\n");
	if(I14443p4a == NULL)
		console_printf("\n No ISO 14443P4A PAL component included in NFC lib. Check system defines\n");
	if(I14443p3a == NULL)
		console_printf("\n No ISO 14443P3A PAL component included in NFC lib. Check system defines\n");

    /* Initialize other components that are not initialized by NFCLIB and configure Discovery Loop. */
    status = phApp_Comp_Init(pDiscLoop);
    CHECK_STATUS(status);
    if(status != PH_ERR_SUCCESS){ return -1;}

    /* Configure the IRQ */
    status = phApp_Configure_IRQ();
    CHECK_STATUS(status);
    if(status != PH_ERR_SUCCESS) { return -1;}

    console_printf("\n system initialization ended successfully: \n");

    nfc_task_init();
    /*
     * As the last thing, process events from default event queue.
     */
    while (1) {
      os_eventq_run(os_eventq_dflt_get());
    }
    return 0;
}

phStatus_t keyStore_Config (void){
	phStatus_t status = PH_ERR_SUCCESS;

	/* Init and configure keyStore */
    status = phKeyStore_Sw_Init(pKeyStore,
        sizeof(phKeyStore_Sw_DataParams_t),
        keyEntry,
        KEYCOUNT,
        keyVersion,
        KEYVERSIONS,
        keyUsage,
        KEYCOUNT);
    CHECK_SUCCESS(status);

    /* Set keys */
    status = phKeyStore_FormatKeyEntry(pKeyStore, DES_KEY_ADDRESS_0, PH_CRYPTOSYM_KEY_TYPE_2K3DES);
    CHECK_SUCCESS(status);
    status = phKeyStore_SetKeyAtPos(pKeyStore, DES_KEY_ADDRESS_0, 0x00, PH_CRYPTOSYM_KEY_TYPE_2K3DES, aPICC_MasterKey_DES_0, DES_KEY_VERSION);
    CHECK_SUCCESS(status);
    status = phKeyStore_FormatKeyEntry(pKeyStore, DES_KEY_ADDRESS_1, PH_CRYPTOSYM_KEY_TYPE_2K3DES);
    CHECK_SUCCESS(status);
    status = phKeyStore_SetKeyAtPos(pKeyStore, DES_KEY_ADDRESS_1, 0x00, PH_CRYPTOSYM_KEY_TYPE_2K3DES, aPICC_MasterKey_DES_1, DES_KEY_VERSION);
    CHECK_SUCCESS(status);
    status = phKeyStore_FormatKeyEntry(pKeyStore, DES_KEY_ADDRESS_2, PH_CRYPTOSYM_KEY_TYPE_2K3DES);
    CHECK_SUCCESS(status);
    status = phKeyStore_SetKeyAtPos(pKeyStore, DES_KEY_ADDRESS_2, 0x00, PH_CRYPTOSYM_KEY_TYPE_2K3DES, aPICC_MasterKey_DES_2, DES_KEY_VERSION);
    CHECK_SUCCESS(status);
    //
    status = phKeyStore_FormatKeyEntry(pKeyStore, AES_KEY_ADDRESS_0, PH_CRYPTOSYM_KEY_TYPE_AES128);
    CHECK_SUCCESS(status);
    status = phKeyStore_SetKeyAtPos(pKeyStore, AES_KEY_ADDRESS_0, 0x00, PH_CRYPTOSYM_KEY_TYPE_AES128, aPICC_MasterKey_AES_0, AES_KEY_VERSION);
    CHECK_SUCCESS(status);
    status = phKeyStore_FormatKeyEntry(pKeyStore, AES_KEY_ADDRESS_1, PH_CRYPTOSYM_KEY_TYPE_AES128);
    CHECK_SUCCESS(status);
    status = phKeyStore_SetKeyAtPos(pKeyStore, AES_KEY_ADDRESS_1, 0x00, PH_CRYPTOSYM_KEY_TYPE_AES128, aPICC_MasterKey_AES_1, AES_KEY_VERSION);
    CHECK_SUCCESS(status);
    status = phKeyStore_FormatKeyEntry(pKeyStore, AES_KEY_ADDRESS_2, PH_CRYPTOSYM_KEY_TYPE_AES128);
    CHECK_SUCCESS(status);
    status = phKeyStore_SetKeyAtPos(pKeyStore, AES_KEY_ADDRESS_2, 0x00, PH_CRYPTOSYM_KEY_TYPE_AES128, aPICC_MasterKey_AES_2, AES_KEY_VERSION);
    CHECK_SUCCESS(status);

    console_printf("\n keystore is configured. Starting reading files.");
    console_printf("\n Test 1:reading plain file. \n");

    return status;
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
  uint16_t   wActPollConfig = 0;
  uint16_t   wPasLisConfig = 0;
  uint16_t   wActLisConfig = 0;

#ifdef NXPBUILD__PHAC_DISCLOOP_TYPEA_TAGS
  wPasPollConfig |= PHAC_DISCLOOP_POS_BIT_MASK_A;
#endif

#ifdef NXPBUILD__PHAC_DISCLOOP_TYPEA_P2P_ACTIVE
  wActPollConfig |= PHAC_DISCLOOP_ACT_POS_BIT_MASK_106;
#endif

#ifdef NXPBUILD__PHAC_DISCLOOP_TYPEA_TARGET_PASSIVE
  wPasLisConfig |= PHAC_DISCLOOP_POS_BIT_MASK_A;
#endif

#ifdef NXPBUILD__PHAC_DISCLOOP_TYPEA_TARGET_ACTIVE
  wActLisConfig |= PHAC_DISCLOOP_POS_BIT_MASK_A;
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

    /* Configure reader library mode */
    status = phacDiscLoop_SetConfig(pDiscLoop, PHAC_DISCLOOP_CONFIG_OPE_MODE, RD_LIB_MODE_EMVCO);
    CHECK_STATUS(status);
  } else {
    /* Do Nothing */
  }
  return status;
}

phStatus_t discoveryDetection(void *pDataParams){
	uint16_t    wTechDetected = 0;
	uint8_t     bTagType;
	uint16_t    wTagsDetected = 0;
	uint8_t * pResponse = NULL;
	uint8_t * pNumAIDs = NULL;
	phStatus_t status;

	/* Load NFC profile for Discovery loop */
	LoadProfile(PHAC_DISCLOOP_PROFILE_NFC);
//	status = phApp_HALConfigAutoColl();
//	CHECK_STATUS(status);

	/* Get Poll Configuration */
	status = phacDiscLoop_GetConfig(pDataParams, PHAC_DISCLOOP_CONFIG_PAS_POLL_TECH_CFG, &bSavePollTechCfg);
	CHECK_STATUS(status);

	/* Start in poll mode */
	while(1){
		do{
			/* Switch off RF field */
			status = phhalHw_FieldOff(pHal);
			CHECK_STATUS(status);
			status = phhalHw_Wait(pHal,PHHAL_HW_TIME_MICROSECONDS, 5100);
			CHECK_STATUS(status);

			/* Configure Discovery loop for tag detection */
			status = phacDiscLoop_SetConfig(pDataParams, PHAC_DISCLOOP_CONFIG_NEXT_POLL_STATE, PHAC_DISCLOOP_POLL_STATE_DETECTION);
			CHECK_STATUS(status);

			status = phacDiscLoop_SetConfig(pDataParams, PHAC_DISCLOOP_CONFIG_PAS_POLL_TECH_CFG, bSavePollTechCfg);
			CHECK_STATUS(status);
			/* Run Discovery loop in poll mode to detect Card. */
			status = phacDiscLoop_Run(pDiscLoop, PHAC_DISCLOOP_ENTRY_POINT_POLL);
		}
		while((status & PH_ERR_MASK) != PHAC_DISCLOOP_DEVICE_ACTIVATED);

		/* Card detected */
		status = phacDiscLoop_GetConfig(pDiscLoop, PHAC_DISCLOOP_CONFIG_TECH_DETECTED, &wTechDetected);
		if ((status & PH_ERR_MASK) == PH_ERR_SUCCESS)
		{
			/* Check for Type A tag detection */
			if (PHAC_DISCLOOP_CHECK_ANDMASK(wTechDetected, PHAC_DISCLOOP_POS_BIT_MASK_A))
			{
				/* Bit b3 is set to zero, [Digital] 4.8.2 */
				/* Mask out all other bits except for b7 and b6 */
				bTagType = (pDiscLoop->sTypeATargetInfo.aTypeA_I3P3[0].aSak & 0x60);
				bTagType = bTagType >> 5;

				status = keyStore_Config();
				CHECK_STATUS(status);

				status = phacDiscLoop_SetConfig(pDataParams, PHAC_DISCLOOP_CONFIG_PAS_POLL_TECH_CFG, PHAC_DISCLOOP_TECH_TYPE_A);
				CHECK_STATUS(status);
				phApp_PrintTech(wTechDetected);
				console_printf("\t Activating detected card...\n");
				status = phacDiscLoop_ActivateCard(pDataParams, PHAC_DISCLOOP_TECH_TYPE_A, 0);
				if (((status & PH_ERR_MASK) == PHAC_DISCLOOP_DEVICE_ACTIVATED) ||
					((status & PH_ERR_MASK) == PHAC_DISCLOOP_PASSIVE_TARGET_ACTIVATED) ||
					((status & PH_ERR_MASK) == PHAC_DISCLOOP_MERGED_SEL_RES_FOUND)) {
				status = phacDiscLoop_GetConfig(pDiscLoop, PHAC_DISCLOOP_CONFIG_TECH_DETECTED, &wTagsDetected);
				CHECK_STATUS(status);
				phApp_PrintTagInfo(pDataParams, 0x01, wTagsDetected);

				/* Check if the detected tag is MIFARE DESFire. */
				if (pDiscLoop->sTypeATargetInfo.aTypeA_I3P3[0].aSak == PH_EXMFCRYPTO_MFDFCRYPTO_MIFAREDESFIRE_SAK){
					console_printf("\t DESFire card detected...\n");
					/* Authenticate PICC Master Application. */
					status = phalMfdf_GetApplicationIDs(palMfdf, pResponse, pNumAIDs);
					CHECK_STATUS(status);
					if(((pNumAIDs != NULL) && (pResponse != NULL))){
						console_printf("\n List applications ");
						for(int i=0; i<(*pNumAIDs)*3; i++)
							console_printf("0x%2X ", pResponse[i]);
					}
					else
						console_printf("\n No applications detected ");

					uint8_t selectedID = 0x00;
					uint8_t offset[3] = {0x00, 0x00, 0x00};
					uint8_t length[3] = {0x64, 0x00, 0x00};
					uint8_t * pRxData = NULL;
					uint16_t wRxLen = 0;

					status = phalMfdf_SelectApplication(palMfdf, &selectedID);
					CHECK_STATUS(status);
//					status = phalMfdf_Authenticate(palMfdf, PHAL_MFDF_NO_DIVERSIFICATION, DES_KEY_ADDRESS_0, DES_KEY_VERSION, PICC_MASTER_KEY, NULL, 0);
//					CHECK_STATUS(status);
					status = phalMfdf_ReadData(palMfdf, PHAL_MFDF_COMMUNICATION_PLAIN, 0x00, &offset[0], &length[0], &pRxData, &wRxLen);
					CHECK_STATUS(status);
				}
				else
					console_printf("\nThe detected card does not seem to be MIFARE DESFire Card. Aborting.\n\n");

				} else {
					console_printf("\t\tCard activation failed...\n");
				}
				/* Field reset */
				status = phhalHw_FieldReset(pHal);
				CHECK_STATUS(status);
			}
			else{
				console_printf("\n Non A type card detected: \n");
			}
		}
	}
}

phStatus_t nfcCardDetection(void){
	uint8_t bUid[10];
	uint8_t bSak[1];
	uint8_t pAts[255];
	uint8_t bLength;
	uint8_t bMoreCardsAvaliable;
	uint8_t bCidEnable, bCid, bNadSupported, bFwi, bFsdi, bFsci;
	phStatus_t status;

	while(1){
		console_printf("\n Start Card detection loop: \n");

		/* Switch on the field */
		status = phhalHw_FieldOn(pHal);
		CHECK_STATUS(status);
	    /* Configure HAL for Type-A cards */
	    status = phhalHw_ApplyProtocolSettings(pHal, PHHAL_HW_CARDTYPE_ISO14443A);
	    CHECK_SUCCESS(status);

	    /* Activate Layer 3 card. In loop till a card is detected. */
	    do{
	        status = phpalI14443p3a_ActivateCard(I14443p3a, NULL, 0x00, bUid, &bLength, bSak, &bMoreCardsAvaliable);
	    } while (status != PH_ERR_SUCCESS);
	    CHECK_SUCCESS(status);

	    console_printf("\n Card detected: \n");

	    /* switch on time mesaurement */
	    status = phhalHw_SetConfig(pHal, PHHAL_HW_CONFIG_TIMING_MODE, PHHAL_HW_TIMING_MODE_COMM);
	    CHECK_SUCCESS(status);

	    /* Send RATS */
	    status = phpalI14443p4a_Rats(I14443p4a, 0x08, 0x01, pAts);
	    CHECK_SUCCESS(status);
	    console_printf("\n Rats performed \n");

	    status = phpalI14443p4a_GetProtocolParams(I14443p4a, &bCidEnable, &bCid, &bNadSupported, &bFwi, &bFsdi, &bFsci);
	    CHECK_SUCCESS(status);

	    status = phpalI14443p4_SetProtocol(I14443p4, bCidEnable, bCid, bNadSupported, 0, bFwi, bFsdi, bFsci);
	    CHECK_SUCCESS(status);
	}
}
