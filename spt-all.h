#ifndef QEMU_SPT_ALL_H
#define QEMU_SPT_ALL_H
#include "config.h"

#ifdef CONFIG_SPT
#if defined(TARGET_ARM) && defined(HOST_X86_64) && (CONFIG_LINUX == 1)
//#define FILL_SPT_AT_TIMESLOT_START 1
//#define SPT_PROFILE 1
#ifdef FILL_SPT_AT_TIMESLOT_START
#define SPT_FILL_NUM_PROFILE 1
#endif
#define PRIVATE_SPT 1

#ifdef PRIVATE_SPT
//#define ASID_MANAGE 1
#endif

extern bool spt_allowed;
#define spt_enabled() spt_allowed
#else
#define spt_enabled() (0)
#define spt_allowed() (0)
#endif

#else//undefined CONFIG_SPT
#define spt_enabled() (0)
#define spt_allowed() (0)
#endif

#endif
