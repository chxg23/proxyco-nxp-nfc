/*
 * phOsal_mynewt.h
 *
 * @Copyright Proxy
 *
 * Author: Vipul Rahane <vipul@proxy.com>
 */

#ifndef PHOSAL_MYNEWT_H
#define PHOSAL_MYNEWT_H

#include <os/mynewt.h>
#include <os/os_time.h>

#define PHOSAL_MYNEWT_ALL_EVENTS      0x00FFFFFF

#define PHOSAL_MAX_DELAY    OS_TIME_MAX

#if( configSUPPORT_STATIC_ALLOCATION == 1 )
#define PHOSAL_MYNEWT_STATIC_MEM_ALLOCATION
#endif /* ( configSUPPORT_STATIC_ALLOCATION == 1 ) */

#endif /* PHOSAL_MYNEWT_H */
