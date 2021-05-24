/*
 * @Copyright Proxy
 */

#include <nxp_nfc/phOsal.h>

#ifdef PH_OSAL_MYNEWT
#include <os/mynewt.h>
#include "phOsal_mynewt.h"

#ifndef TickType_t
#define TickType_t os_time_t
#endif

#ifndef BaseType_t
#define BaseType_t uint32_t
#define pdFALSE			( ( BaseType_t ) 0 )
#define pdTRUE			( ( BaseType_t ) 1 )

#define pdPASS			( pdTRUE )
#define pdFAIL			( pdFALSE )
#endif

#ifndef StaticTask_t
#define StaticTask_t struct os_task
#endif

#ifdef MYNEWT_VAL_PHOSAL_EVQ
extern struct os_eventq MYNEWT_VAL(PHOSAL_EVQ);
#endif

/* *****************************************************************************************************************
 * Internal Definitions
 * ***************************************************************************************************************** */

/* *****************************************************************************************************************
 * Type Definitions
 * ***************************************************************************************************************** */

/* *****************************************************************************************************************
 * Global and Static Variables
 * Total Size: NNNbytes
 * ***************************************************************************************************************** */
#ifdef PHOSAL_MYNEWT_STATIC_MEM_ALLOCATION
static struct os_task sTaskBuffer[PH_OSAL_CONFIG_MAX_NUM_TASKS];
static volatile uint32_t dwTotalTasksCreated;
static volatile uint32_t dwTaskBitMap;

static struct os_sem sEventGroup[PH_OSAL_CONFIG_MAX_NUM_EVENTS];
static volatile uint32_t dwTotalEventsCreated;
static volatile uint32_t dwEventBitMap;

static struct os_sem sSemaphoreBuff[PH_OSAL_CONFIG_MAX_NUM_SEMAPHORE];
static volatile uint32_t dwTotalSemCreated;
static volatile uint32_t dwSemBitMap;

static struct os_mutex sMutexBuff[PH_OSAL_CONFIG_MAX_NUM_MUTEX];
static volatile uint32_t dwTotalMutexCreated;
static volatile uint32_t dwMutexBitMap;

static struct os_callout sTimerBuffer[PH_OSAL_CONFIG_MAX_NUM_TIMERS];
static volatile uint32_t dwTotalTimersCreated;
static volatile uint32_t dwTimerBitMap;
#endif /* PHOSAL_MYNEWT_STATIC_MEM_ALLOCATION */
/* *****************************************************************************************************************
 * Private Functions Prototypes
 * ***************************************************************************************************************** */
#ifdef PHOSAL_MYNEWT_STATIC_MEM_ALLOCATION
static phStatus_t phOsal_mynewt_GetFreeIndex(uint32_t *dwFreeIndex, uint32_t dwBitMap,
    uint32_t dwMaxLimit);
#endif /* PHOSAL_MYNEWT_STATIC_MEM_ALLOCATION */
static phStatus_t phOsal_TimeToTick(phOsal_TimerPeriodObj_t timerObj, os_time_t *TimerPeriod);
/* *****************************************************************************************************************
 * Public Functions
 * ***************************************************************************************************************** */
phStatus_t phOsal_Init(void)
{
#ifdef PHOSAL_MYNEWT_STATIC_MEM_ALLOCATION

  dwTotalTasksCreated         = 0;
  dwTaskBitMap                = 0;

  dwTotalEventsCreated        = 0;
  dwEventBitMap               = 0;

  dwTotalSemCreated           = 0;
  dwSemBitMap                 = 0;

  dwTotalMutexCreated         = 0;
  dwMutexBitMap               = 0;

  dwTotalTimersCreated        = 0;
  dwTimerBitMap               = 0;

#if MYNEWT_VAL_PHOSAL_EVQ
  os_eventq_init(&MYNEWT_VAL(PHOSAL_EVQ));
#endif

#endif /* PHOSAL_MYNEWT_STATIC_MEM_ALLOCATION */
  return PH_OSAL_SUCCESS;
}

phStatus_t phOsal_ThreadCreate(phOsal_Thread_t *threadHandle, const pphOsal_ThreadObj_t threadObj,
    pphOsal_StartFunc_t startFunc, void *arg)
{
  BaseType_t status;
  uint32_t dwFreeIndex;

  if ((threadHandle == NULL) || (threadObj == NULL) || (startFunc == NULL)) {
    return PH_OSAL_ADD_COMPCODE(PH_OSAL_ERROR, PH_COMP_OSAL);
  }

  if (threadObj->stackSizeInNum) {
    PH_OSAL_CHECK_SUCCESS(phOsal_mynewt_GetFreeIndex(&dwFreeIndex, dwTaskBitMap,
            PH_OSAL_CONFIG_MAX_NUM_TASKS));

    memset(&sTaskBuffer[dwFreeIndex], 0, sizeof(StaticTask_t));

    os_task_init(&sTaskBuffer[dwFreeIndex],
        (const char *)(threadObj->pTaskName), startFunc, arg, threadObj->priority, OS_WAIT_FOREVER,
        threadObj->pStackBuffer, threadObj->stackSizeInNum);

    status = pdPASS;
    *threadHandle = &sTaskBuffer[dwFreeIndex];
  }

  if (status != pdPASS) {
    return PH_OSAL_ADD_COMPCODE(PH_OSAL_FAILURE, PH_COMP_OSAL);
  }

  threadObj->ThreadHandle = *threadHandle;

  if (threadObj->stackSizeInNum) {
    threadObj->dwThreadIndex = dwFreeIndex;
    dwTaskBitMap |= (1 << dwFreeIndex);
    dwTotalTasksCreated++;
  }

  return PH_OSAL_SUCCESS;
}

phStatus_t phOsal_ThreadChangePrio(phOsal_Thread_t *threadHandle, uint32_t newPrio)
{
  return PH_OSAL_SUCCESS;
}

phStatus_t phOsal_ThreadExit(void)
{
  return PH_OSAL_SUCCESS;
}

phStatus_t phOsal_ThreadDelete(phOsal_Thread_t *threadHandle)
{
  return PH_OSAL_SUCCESS;
}

phStatus_t phOsal_ThreadDelay(phOsal_Ticks_t ticksToSleep)
{
  os_time_delay(ticksToSleep);

  return PH_OSAL_SUCCESS;
}

phStatus_t phOsal_EventCreate(phOsal_Event_t *eventHandle, pphOsal_EventObj_t eventObj)
{
  uint32_t dwFreeIndex;
  os_error_t err;

  PH_OSAL_CHECK_SUCCESS(phOsal_mynewt_GetFreeIndex(&dwFreeIndex, dwEventBitMap,
          PH_OSAL_CONFIG_MAX_NUM_EVENTS));

  memset(&sEventGroup[dwFreeIndex], 0, sizeof(struct os_event));

  *eventHandle = &sEventGroup[dwFreeIndex];

  err = os_sem_init((struct os_sem *)eventHandle, 0);
  if (err) {
    return PH_OSAL_ERROR;
  }

  eventObj->EventHandle = *eventHandle;
  eventObj->intialValue = 0;

  eventObj->dwEventIndex = dwFreeIndex;
  dwTotalEventsCreated++;
  dwEventBitMap |= (1 << dwFreeIndex);

  return PH_OSAL_SUCCESS;
}

phStatus_t phOsal_EventPend(volatile phOsal_Event_t *eventHandle, phOsal_EventOpt_t options,
    phOsal_Ticks_t ticksToWait, phOsal_EventBits_t FlagsToWait, phOsal_EventBits_t *pCurrFlags)
{
  if (eventHandle == NULL) {
    return (PH_OSAL_ERROR | PH_COMP_OSAL);
  }

  os_error_t err;

  err = os_sem_pend((struct os_sem *)eventHandle, ticksToWait);
  if (err && err == OS_TIMEOUT) {
    return PH_OSAL_IO_TIMEOUT;
  } else if (err) {
    return PH_OSAL_ERROR;
  }

  return PH_OSAL_SUCCESS;
}

phStatus_t phOsal_EventPost(phOsal_Event_t *eventHandle, phOsal_EventOpt_t options,
    phOsal_EventBits_t FlagsToPost, phOsal_EventBits_t *pCurrFlags)
{
  os_error_t err;

  if ((eventHandle == NULL) || ((*eventHandle) == NULL)) {
    return (PH_OSAL_ERROR | PH_COMP_OSAL);
  }

  err = os_sem_release((struct os_sem *)eventHandle);
  if (err) {
    return PH_OSAL_ERROR;
  }

  return PH_OSAL_SUCCESS;
}

phStatus_t phOsal_EventClear(phOsal_Event_t *eventHandle, phOsal_EventOpt_t options,
    phOsal_EventBits_t FlagsToClear, phOsal_EventBits_t *pCurrFlags)
{
  return PH_OSAL_SUCCESS;
}

phStatus_t phOsal_EventGet(phOsal_Event_t *eventHandle, phOsal_EventBits_t *pCurrFlags)
{
  return PH_OSAL_SUCCESS;
}

phStatus_t phOsal_EventDelete(phOsal_Event_t *eventHandle)
{
  return PH_OSAL_SUCCESS;
}

phStatus_t phOsal_SemCreate(phOsal_Semaphore_t *semHandle, pphOsal_SemObj_t semObj,
    phOsal_SemOpt_t opt)
{
  os_error_t rc;
  uint32_t dwFreeIndex;

  if (semHandle == NULL) {
    return PH_OSAL_ADD_COMPCODE(PH_OSAL_FAILURE, PH_COMP_OSAL);
  }

  PH_OSAL_CHECK_SUCCESS(phOsal_mynewt_GetFreeIndex(&dwFreeIndex, dwSemBitMap,
          PH_OSAL_CONFIG_MAX_NUM_SEMAPHORE));

  memset(&sSemaphoreBuff[dwFreeIndex], 0, sizeof(struct os_sem));

  if (opt == E_OS_SEM_OPT_COUNTING_SEM) {
    rc = os_sem_init(&sSemaphoreBuff[dwFreeIndex], semObj->semMaxCount);
    if (rc) {
      return PH_OSAL_ADD_COMPCODE(PH_OSAL_FAILURE, PH_COMP_OSAL);
    }
    *semHandle = &sSemaphoreBuff[dwFreeIndex];
  } else {
    rc = os_sem_init(&sSemaphoreBuff[dwFreeIndex], 0);
    if (rc) {
      return PH_OSAL_ADD_COMPCODE(PH_OSAL_FAILURE, PH_COMP_OSAL);
    }
    *semHandle = &sSemaphoreBuff[dwFreeIndex];
  }

  semObj->SemHandle = *semHandle;

#ifdef PHOSAL_MYNEWT_STATIC_MEM_ALLOCATION

  semObj->dwSemIndex = dwFreeIndex;
  dwTotalSemCreated++;
  dwSemBitMap |= (1 << dwFreeIndex);

#endif /* PHOSAL_MYNEWT_STATIC_MEM_ALLOCATION */
  return PH_OSAL_SUCCESS;
}

phStatus_t phOsal_SemPend(phOsal_Semaphore_t *semHandle, phOsal_TimerPeriodObj_t timePeriodToWait)
{
  os_error_t statusTmp;
  TickType_t TimerPeriod;

  if ((semHandle == NULL) || ((*semHandle) == NULL)) {
    return (PH_OSAL_ERROR | PH_COMP_OSAL);
  }

  if (timePeriodToWait.period == PHOSAL_MAX_DELAY) {
    TimerPeriod = timePeriodToWait.period;
  } else {
    PH_OSAL_CHECK_SUCCESS(phOsal_TimeToTick(timePeriodToWait, &TimerPeriod));
  }

  statusTmp = os_sem_pend(*semHandle, TimerPeriod);
  if (!statusTmp) {
    return PH_OSAL_SUCCESS;
  } else {
    return (PH_OSAL_IO_TIMEOUT | PH_COMP_OSAL);
  }
}

phStatus_t phOsal_SemPost(phOsal_Semaphore_t *semHandle, phOsal_SemOpt_t opt)
{
  os_error_t statusTmp;

  if ((semHandle == NULL) || ((*semHandle) == NULL)) {
    return (PH_OSAL_ERROR | PH_COMP_OSAL);
  }

  statusTmp = os_sem_release(*semHandle);

  if (!statusTmp) {
    return PH_OSAL_SUCCESS;
  } else {
    return (PH_OSAL_FAILURE | PH_COMP_OSAL);
  }
}

phStatus_t phOsal_SemDelete(phOsal_Semaphore_t *semHandle)
{
  (void)*semHandle;
  return PH_OSAL_SUCCESS;
}

phStatus_t phOsal_MutexCreate(phOsal_Mutex_t *mutexHandle, pphOsal_MutexObj_t mutexObj)
{
  uint32_t dwFreeIndex;
  os_error_t rc;

  if (mutexHandle == NULL) {
    return (PH_OSAL_FAILURE | PH_COMP_OSAL);
  }

  PH_OSAL_CHECK_SUCCESS(phOsal_mynewt_GetFreeIndex(&dwFreeIndex, dwMutexBitMap,
          PH_OSAL_CONFIG_MAX_NUM_MUTEX));

  memset(&sMutexBuff[dwFreeIndex], 0, sizeof(struct os_mutex));

  rc = os_mutex_init(&sMutexBuff[dwFreeIndex]);
  if (rc) {
    return (PH_OSAL_FAILURE | PH_COMP_OSAL);
  }

  *mutexHandle = &sMutexBuff[dwFreeIndex];

  mutexObj->MutexHandle = *mutexHandle;

  mutexObj->dwMutexIndex = dwFreeIndex;
  dwTotalMutexCreated++;
  dwMutexBitMap |= (1 << dwFreeIndex);

  return PH_OSAL_SUCCESS;
}

phStatus_t phOsal_MutexLock(phOsal_Mutex_t *mutexHandle, phOsal_TimerPeriodObj_t timePeriodToWait)
{
  if ((mutexHandle == NULL) || ((*mutexHandle) == NULL)) {
    return (PH_OSAL_ERROR | PH_COMP_OSAL);
  }

  if (!os_mutex_pend(*mutexHandle, OS_TIMEOUT_NEVER)) {
    return PH_OSAL_SUCCESS;
  } else {
    return (PH_OSAL_FAILURE | PH_COMP_OSAL);
  }
}

phStatus_t phOsal_MutexUnLock(phOsal_Mutex_t *mutexHandle)
{
  if ((mutexHandle == NULL) || ((*mutexHandle) == NULL)) {
    return (PH_OSAL_ERROR | PH_COMP_OSAL);
  }

  if (!os_mutex_release(*mutexHandle)) {
    return PH_OSAL_SUCCESS;
  } else {
    return (PH_OSAL_FAILURE | PH_COMP_OSAL);
  }
}

phStatus_t phOsal_MutexDelete(phOsal_Mutex_t *mutexHandle)
{
  return PH_OSAL_SUCCESS;
}

phStatus_t phOsal_TimerCreate(phOsal_Timer_t *timerHandle, pphOsal_TimerObj_t timerObj)
{
  TickType_t TimerPeriod;

  PH_OSAL_CHECK_SUCCESS(phOsal_TimeToTick(timerObj->timePeriod, &TimerPeriod));

  uint32_t dwFreeIndex;

  if (timerHandle == NULL) {
    return (PH_OSAL_FAILURE | PH_COMP_OSAL);
  }

  dwFreeIndex = 0;

  PH_OSAL_CHECK_SUCCESS(phOsal_mynewt_GetFreeIndex(&dwFreeIndex, dwTimerBitMap,
          PH_OSAL_CONFIG_MAX_NUM_TIMERS));

  memset(&sTimerBuffer[dwFreeIndex], 0, sizeof(struct os_callout));

#ifdef MYNEWT_VAL_PHOSAL_EVQ
  os_callout_init(&sTimerBuffer[dwFreeIndex], &MYNEWT_VAL(PHOSAL_EVQ),
      (os_event_fn *)timerObj->timerCb, timerObj->arg);
#else
  os_callout_init(&sTimerBuffer[dwFreeIndex], os_eventq_dflt_get(),
      (os_event_fn *)timerObj->timerCb, timerObj->arg);
#endif

  timerObj->TimerHandle = &sTimerBuffer[dwFreeIndex];

  timerObj->dwTimerIndex = dwFreeIndex;
  dwTimerBitMap |= (1 << dwFreeIndex);
  dwTotalTimersCreated++;

  return PH_OSAL_SUCCESS;
}

phStatus_t phOsal_TimerStart(phOsal_Timer_t *timerHandle)
{
  int rc = os_callout_reset(*timerHandle, 0);
  if (rc) {
    return (PH_OSAL_FAILURE | PH_COMP_OSAL);
  }
  return PH_OSAL_SUCCESS;
}

phStatus_t phOsal_TimerStop(phOsal_Timer_t *timerHandle)
{
  os_callout_stop(*timerHandle);

  return PH_OSAL_SUCCESS;
}

phStatus_t phOsal_TimerGetCurrent(phOsal_Timer_t *timerHandle, uint32_t *pdwGetElapsedTime)
{
  *pdwGetElapsedTime =  os_callout_remaining_ticks(*timerHandle, os_time_get());
  return (PH_OSAL_SUCCESS);
}

phStatus_t phOsal_TimerModify(phOsal_Timer_t *timerHandle, pphOsal_TimerObj_t timerObj)
{
  os_time_t period = 0;
  int rc;

  if (timerObj->timePeriod.unitPeriod == OS_TIMER_UNIT_MSEC) {
    rc = os_time_ms_to_ticks(timerObj->timePeriod.period, &period);
    if (rc) {
      return PH_OSAL_FAILURE;
    }
  } else if (timerObj->timePeriod.unitPeriod == OS_TIMER_UNIT_SEC) {
    rc = os_time_ms_to_ticks(timerObj->timePeriod.period * 1000, &period);
    if (rc) {
      return PH_OSAL_FAILURE;
    }
  } else {
    period = (os_time_t)timerObj->timePeriod.period;
  }

  rc = os_callout_reset(*timerHandle, (os_time_t)timerObj->timePeriod.period);
  if (rc) {
    return (PH_OSAL_FAILURE | PH_COMP_OSAL);
  }

  return PH_OSAL_SUCCESS;
}

phStatus_t phOsal_TimerDelete(phOsal_Timer_t *timerHandle)
{
  return PH_OSAL_SUCCESS;
}

void phOsal_StartScheduler(void)
{

}
/* *****************************************************************************************************************
 * Private Functions
 * ***************************************************************************************************************** */
#ifdef PHOSAL_MYNEWT_STATIC_MEM_ALLOCATION

static phStatus_t phOsal_mynewt_GetFreeIndex(uint32_t *dwFreeIndex, uint32_t dwBitMap,
    uint32_t dwMaxLimit)
{
  phStatus_t status;

  (*dwFreeIndex) = 0;

  while (((1 << (*dwFreeIndex)) & dwBitMap) && ((*dwFreeIndex) < dwMaxLimit)) {
    (*dwFreeIndex)++;
  }

  if (*dwFreeIndex == dwMaxLimit) {
    status = PH_OSAL_FAILURE | PH_COMP_OSAL;
  } else {
    status = PH_OSAL_SUCCESS;
  }

  return status;
}

#endif /* PHOSAL_MYNEWT_STATIC_MEM_ALLOCATION */

static phStatus_t phOsal_TimeToTick(phOsal_TimerPeriodObj_t timerObj, TickType_t *TimerPeriod)
{
  phStatus_t status;

  status = PH_OSAL_SUCCESS;
  *TimerPeriod = 1;

  switch (timerObj.unitPeriod) {
    case OS_TIMER_UNIT_MSEC:
      *TimerPeriod = timerObj.period;
      break;
    case OS_TIMER_UNIT_SEC:
      *TimerPeriod = timerObj.period * 1000;
      break;
    default:
      status = PH_OSAL_ERROR;
      break;
  }

  os_time_ticks_to_ms(*TimerPeriod, TimerPeriod);

  return PH_OSAL_ADD_COMPCODE(status, PH_COMP_OSAL);
}

#endif  /* NXPBUILD__PH_OSAL_MYNEWT */
