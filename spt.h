#ifndef QEMU_SPT_H
#define QEMU_SPT_H

#include <sys/time.h>
#include "spt-all.h"
#include "cpu.h"

#define GUEST_VIRTUAL_SPACE_SIZE 0X100000000ULL
#define SPT_L1_PAGE_SIZE (1<<20)
#define SPT_L2_PAGE_SIZE (1<<12)

#define PAGE_FLAG_NOTDIRTY (1<<0)
#define PAGE_FLAG_MMIO (1<<1)
extern bool spt_allowed;

extern unsigned long long total_invalid_time;

extern unsigned long long gs_change_time;
extern unsigned long long gs_change_count;


#if 1//def SPT_PROFILE
extern unsigned long spt_invalid_count;
extern unsigned long repeated_invalid_count;
extern unsigned long ttbr0_count;
extern unsigned long ttbcr_count;

extern unsigned long long sigsegv_count;
extern unsigned long long smc_sigsegv_count;
extern unsigned long long spt_sigsegv_count;
extern unsigned long long guest_pt_fault_count;
extern struct timeval spt_start;
extern struct timeval spt_clear_count_time;

extern unsigned long long static_fill_time;
extern unsigned long long static_fill_count;
extern unsigned long long sigsegv_time;
extern unsigned long long spt_invalid_time;

//TLB flush reason profile
extern unsigned long long cpuCommonLoad;
extern unsigned long long physMemReg;
extern unsigned long long cpuReset;
extern unsigned long long sysctl;
extern unsigned long long dacr;
extern unsigned long long tlbiall;
extern unsigned long long tlbiasid;
extern unsigned long long tlbimvaasid;
extern unsigned long long fcse;
extern unsigned long long contextID;
#endif

typedef struct SHM_FILE {
    char name[256];
    int fd;
    unsigned long size;
    struct SHM_FILE *next;
} shm_file;
extern shm_file *shm_file_list_head; 
shm_file *spt_mmap_shm_file(void *mmap_addr, unsigned long size);
void spt_del_one_shm_file(shm_file *file);
void spt_del_all_shm_files();

#define SPT_GUEST_MIN_PAGEBITS 12
#define SPT_GUEST_MIN_PAGESIZE (1<<SPT_GUEST_MIN_PAGEBITS)
#define SPT_GUEST_MIN_PAGE_MASK (SPT_GUEST_MIN_PAGESIZE - 1)
#define SPT_GUEST_PHYS_PAGE_NUM (1<<20)

#define GUEST_ENTRY_EMPTY_OR_FAULT (1<<0)

//For the handling of SMC
//struct RMap is used to record the reverse Map of SPT, recording the List of gva pages that each gpa page is mapped to.
#ifdef PRIVATE_SPT
	typedef struct ReverseMapInfo {
		uint32 addr;
		uint32 asid;
		uint32 timestamp;
	}RMapInfo;
	typedef struct ReverseMap{
		int vpages_slots_start_index;
		int count;
		int capacity;
	}RMap;
#else
	typedef uint32 RMapInfo;
	typedef struct ReverseMap{
		int vpages_slots_start_index;
		int timestamp;
		int count;
		int capacity;
	}RMap;
#endif
extern RMap *spt_reverse_map;
extern unsigned long spt_guest_base;


#ifdef FILL_SPT_AT_TIMESLOT_START
//total gva page num is 1<<20, we need 1<<20 bit to record each page, so  we need 1<<14 of dword 
//typedef uint64 SPT_BitMap[1<<14];
typedef struct HashBitMap{
	uint32 count;
	uint16_t start_dword;
	uint16_t end_dword;
	uint64 bitmap[1<<14];
}SPT_BitMap;
//we use the guest  pt base to record each guest process 
//bits (14-N)~31 in ttbr0 represent guest page table base. N is usually 0, 
//therefore, the max possible guest page table base num is 1<<18
//except for the high 5-bits, we use the low 13 bits of these 18 bits to form a hash value;
//see func spt_bitmap_hash()
#define SPT_BITMAP_NUM (1<<13)
#endif
extern unsigned long spt_setup_base_seg(unsigned long value);
void spt_init(void);
//void spt_set_entry_staticly(uint32_t guest_va, target_ulong page_size, int prot, uint32_t phys_addr, int flag);
//target_ulong spt_update_entry(CPUARMState *env, uint32_t guest_va);
//int spt_further_limit_prot(CPUState *env, uint32_t address, uint32_t phys_addr, int *prot);
//int spt_check_mmio_or_dirty(target_ulong vaddr, int *prot, target_ulong addr_read, target_ulong addr_write, target_ulong addr_code);

// map each asid to an spt
#ifdef PRIVATE_SPT
typedef struct PrivateSPTInfo {
	uint32 timestamp;
	bool dirty;
	int map_count;
	//uint64_t spt_guest_base;
}PSPTInfo;
extern PSPTInfo *private_spts;
#define asid_count (0x100)
#define PRIVATE_SPT_COUNT (asid_count)
extern bool spt_cleared_for_asid_0;

#define spt_g2h(b, x) ((void *)((unsigned long)(x) +(unsigned long)(b)))
#if HOST_LONG_BITS <= TARGET_VIRT_ADDR_SPACE_BITS
#define spt_h2g_valid(b, x) 1
#else
#define spt_h2g_valid(b, x) ({ \
    unsigned long __guest = (unsigned long)(x) - (unsigned long)(b); \
    __guest < (1ul << TARGET_VIRT_ADDR_SPACE_BITS); \
})
#endif
#define spt_h2g(b, x) ({ \
    unsigned long __ret = (unsigned long)(x) - (unsigned long)(b); \
    /* Check if given address fits target address space */ \
    assert(spt_h2g_valid(b, x)); \
    __ret; \
})
#ifdef ASID_MANAGE
extern void invalid_all_private_spts_by_manage(CPUState *env);
extern void invalid_private_spt_on_asid_by_manage(CPUState *env, uint8_t asid, char *invalid_reason, unsigned long long *invalid_count);
extern void invalid_single_entry_of_private_spt_by_mange(CPUState *env, uint32_t mva, uint8_t asid);
extern void private_spt_change_asid_by_manage(uint32 old_asid, uint32 new_asid);
#else
extern void invalid_all_private_spts(CPUState *env);
extern void invalid_private_spt_on_asid(CPUState *env, uint8_t asid, char *invalid_reason, unsigned long long *invalid_count);
extern void invalid_single_entry_of_private_spt(CPUState *env, uint32_t mva, uint8_t asid);
extern void private_spt_change_asid(uint32 old_asid, uint32 new_asid);
#endif

#else // shared_spt
#define spt_g2h(x) ((void *)((unsigned long)(x) + spt_guest_base))
#if HOST_LONG_BITS <= TARGET_VIRT_ADDR_SPACE_BITS
#define spt_h2g_valid(x) 1
#else
#define spt_h2g_valid(x) ({ \
		    unsigned long __guest = (unsigned long)(x) - spt_guest_base; \
		    __guest < (1ul << TARGET_VIRT_ADDR_SPACE_BITS); \
		})
#endif
#define spt_h2g(x) ({ \
    unsigned long __ret = (unsigned long)(x) - spt_guest_base; \
    /* Check if given address fits target address space */ \
    assert(spt_h2g_valid(x)); \
    __ret; \
})

void spt_invalid(CPUState *env);
void spt_invalid_by_mva(CPUState *env, uint32_t mva);
#endif

#ifdef SPT_FILL_NUM_PROFILE
extern void spt_sigill_handler(int signum);
extern void spt_sigfpe_handler(int signum);
#endif

void spt_sigsegv_handler(int host_signum, siginfo_t *info, void *puc);
#endif

