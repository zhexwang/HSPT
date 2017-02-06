#include <unistd.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/mman.h>
#include <fcntl.h>
#include <sys/time.h>
#include <time.h>
#include <pthread.h>

#include <stdarg.h>
#include <errno.h>
#include <assert.h>
#include <sys/ucontext.h>
#include <sys/resource.h>
#include "config.h"
#include "exec-all.h"
#include "spt.h"
#include "qemu-common.h"
#include "qemu-log.h"

#include "exec.h"

bool spt_allowed = false;

unsigned long long gs_change_time = 0;
unsigned long long gs_change_count = 0;
unsigned long long total_invalid_time = 0;
unsigned long long total_invalid_count = 0;


unsigned long ttbr0_count = 0;
unsigned long long sysctl = 0;
unsigned long long dacr = 0;
unsigned long long fcse = 0;
unsigned long long tlbiasid = 0;

int shm_fd = -1;
// map too much handle
unsigned long long total_map_count = 0;
// some definations for profiling
#if 1//def SPT_PROFILE
unsigned long spt_invalid_count = 0;
unsigned long repeated_invalid_count = 0;
unsigned long ttbcr_count = 0;
// files for profiling

FILE *segv_log = NULL;
#if 0
FILE *count_log = NULL;
FILE *spt_invalid_log = NULL;
FILE *tlb_flush_log = NULL;
#endif
// profile sigsegv count
unsigned long long sigsegv_count = 0;
unsigned long long smc_sigsegv_count = 0;
unsigned long long spt_sigsegv_count = 0;
unsigned long long guest_pt_fault_count = 0;
struct timeval spt_start;
struct timeval spt_clear_count_time;

unsigned long long static_fill_time = 0ull;
unsigned long long static_fill_count = 0ull;
unsigned long long sigsegv_time = 0ull;
unsigned long long spt_invalid_time = 0ull;
#endif

static void get_current_time(){
      static char timestr[40];
      time_t t;
      struct tm *nowtime;
      time(&t);
      nowtime = localtime(&t);
      strftime(timestr,sizeof(timestr),"%H:%M:%S",nowtime);
      fprintf(stderr, "%s\n", timestr); 
}

// record the shm_files that we have created, thus we can del them when MR was destroyed or when QEMU exits!
shm_file *shm_file_list_head = NULL; 
static shm_file *spt_add_to_shm_file_list(char *name, int fd, unsigned long size) {
    shm_file *new_file = (shm_file *)(qemu_malloc(sizeof(shm_file)));
    strcpy(new_file->name, name); 
    new_file->fd = fd;
    new_file->size = size;
    new_file->next = shm_file_list_head;
    shm_file_list_head = new_file;
    
    return new_file;
}

/* filename is like: "/dev/shm/pid_microsec". */
static inline void spt_get_new_shm_filename(char *filename) {
    pid_t pid = getpid();
    sprintf(filename, "%d", pid);
    strcat(filename, "_");
    
    struct timeval tv;
    int ret = gettimeofday(&tv, NULL);
    if(ret != 0) {
        perror("gettimeofday\n");
        assert(0);
    }
    unsigned long micro_seconds = tv.tv_sec*1000000 + tv.tv_usec;
    sprintf(filename+strlen(filename), "%lx", micro_seconds);
}

static shm_file *spt_create_shm_file(unsigned long size) {
    // get a new filename
    char filename[256];
    spt_get_new_shm_filename(filename);
    // open the file
    int fd = shm_open(filename, O_CREAT|O_RDWR|O_EXCL, S_IRWXU);
    if(fd<0){
        perror("open failed");
        assert(0);
    }
	
#ifdef DEBUG_SPT
	fprintf(stderr, "SHM_FILE fd = %d\t", fd);
#endif
    // truncate file size
    int ret = ftruncate(fd, size);
    if(ret){
        perror("ftruncate failed");
        assert(0);
    }
    //record the new created file in list
    shm_file *shmf = spt_add_to_shm_file_list(filename, fd, size);
    //return fd
    return shmf;
}

shm_file *spt_mmap_shm_file(void *mmap_addr, unsigned long size) {
    shm_file *file = spt_create_shm_file(size);
	
    void *map_ret = mmap(mmap_addr, size, PROT_READ|PROT_WRITE|PROT_EXEC, MAP_FIXED|MAP_SHARED, file->fd, 0);

    shm_fd = file->fd;
#ifdef DEBUG_SPT
	fprintf(stderr, "mmap_addr: %p, size:0x%lx\n", mmap_addr, size);
#endif
	if(map_ret == MAP_FAILED) {
        perror("shm_file map failed!");
        assert(0);
    }
    
    return file;
}
void spt_del_one_shm_file(shm_file *file) {
    assert(file != NULL);
    
    // Find this file in the list    
    shm_file *p_curr = shm_file_list_head;
    shm_file *p_prev = NULL;
    while(p_curr != NULL) {
        if(p_curr == file)
            break;
        p_prev = p_curr;
        p_curr = p_curr->next; 
    }
    if(p_curr == NULL) {/*the file corresponding to fd not found!*/
        fprintf(stderr, "ERROR!!! del_shm_file: file not found!\n");
        assert(0);
    }
    
    //close and unlink file
    int ret = shm_unlink(p_curr->name);
    if(ret) {
        perror("close shm_file failed!");
        assert(0);
    }

    // delete from list
    if(p_curr == shm_file_list_head) { /*is head node*/
        assert(p_prev == NULL);
        shm_file_list_head = p_curr->next;
    }
    else {
        assert(p_prev != NULL);
        p_prev->next = p_curr->next;
    }
    
    qemu_free((void *)p_curr);
}

void spt_del_all_shm_files(void) {

    shm_file *pfile = shm_file_list_head;
    shm_file_list_head = NULL;
    
    while (pfile != NULL){
        int ret = shm_unlink(pfile->name);
        if(ret) {
            perror("close shm_file failed!");
            assert(0);
        }
        shm_file *pnext = pfile->next;
        qemu_free((void *)pfile);
        pfile = pnext;
    }
}

#if defined(__x86_64__) && defined(__linux__)
# include <asm/prctl.h>
# include <sys/prctl.h>
int arch_prctl(int code, unsigned long addr);
unsigned long spt_setup_base_seg(unsigned long value)
{
	int ret = arch_prctl(ARCH_SET_GS, value);
	assert(ret == 0);
	return 0;
}
static unsigned long spt_get_base_seg() {
	unsigned long orig_gs = 0;
	int ret = arch_prctl(ARCH_GET_GS, &orig_gs);
	return orig_gs;
}
#else
unsigned long spt_setup_base_seg(unsigned long value) { return 0;}
unsigned long spt_get_base_seg() { assert(0);}

#endif /* SOFTMMU */

// definations for spt reverse map
RMap *spt_reverse_map = NULL;
RMapInfo *memory_pool = NULL;
uint32 next_slot_index = 0;
uint32 slot_capacity = 0;
#define MEMORY_SLOT_NUM (1<<24)

unsigned long spt_guest_base = 0;
unsigned long mmap_count = 0;

#ifdef PRIVATE_SPT
PSPTInfo *private_spts = NULL;
bool all_private_spts_cleared = true;
#else
int SPT_timestamp = 1;
bool spt_cleared = true;
#endif

// definations for recording  mapped pages in SPT for each process
#ifdef FILL_SPT_AT_TIMESLOT_START
SPT_BitMap *spt_bitmaps = NULL;
SPT_BitMap *SPT_bitmap=NULL;//record the pages already filled in SPT now
#endif

static void *mmap_new_guest_virtual_space() {
	void *allocated_start = mmap(NULL, GUEST_VIRTUAL_SPACE_SIZE, PROT_NONE, MAP_PRIVATE|MAP_ANONYMOUS, -1, 0);
	if(allocated_start == MAP_FAILED) {
        perror("mmap_guest_virtual_space: ");
        assert(0);
    }
	return allocated_start;
}

#ifdef SPT_FILL_NUM_PROFILE
int FILL_SPT_WINDOW_SIZE = 0;
unsigned long long SEGV_NUM = 0;
unsigned long long FILL_NUM = 0;
void spt_sigill_handler(int signum){
	assert(signum==4);
	// 1.obtain fill size
	FILE *fill_num_file = fopen("/home/wz/spt_fill_num.ctrl", "r" );
	assert(fill_num_file);
	fscanf(fill_num_file, "%d", &FILL_SPT_WINDOW_SIZE);
	fclose(fill_num_file);
	SEGV_NUM = FILL_NUM = 0;
	memset((void *)spt_bitmaps, 0, sizeof(SPT_BitMap) * SPT_BITMAP_NUM);
	fprintf(stderr, "Modfy FILL_SPT_WINDOW_SIZE = %d, Reset SEGV_NUM and FILL_NUM\n", FILL_SPT_WINDOW_SIZE);
	// 2.send message to script-file
	FILE *fill_sync_file = fopen("/home/wz/android_sync.ctrl", "w" );
	assert(fill_sync_file);
	fprintf(fill_sync_file, "1");
	fclose(fill_sync_file);
}
void spt_sigfpe_handler(int signum){
	assert(signum==8);
	// 1.record profile data
	FILE *spec_log_file = fopen("/home/wz/android-spec2006.result", "a");
	fprintf(spec_log_file, "SEGV_SUM:  %llu\nFILL_SUM:  %llu\n", SEGV_NUM, FILL_NUM);
	fprintf(stderr, "Write Log!Record SEGV_NUM and FILL_NUM\n");
	fclose(spec_log_file);
	// 2.send message to script-file
	FILE *fill_sync_file = fopen("/home/wz/android_sync.ctrl", "w" );
	assert(fill_sync_file);
	fprintf(fill_sync_file, "1");
	fclose(fill_sync_file);
}

#endif

#ifdef ASID_MANAGE
#if 0
#define ASID_DEBUG_LOG(msg, ...)  do{fprintf(stderr, msg, ##__VA_ARGS__);}while(0)
#else
#define ASID_DEBUG_LOG(msg, ...)
#endif
#define SET_ASID_SUM 32 //must be more than 1(0 has been occupied)
int asid_table[SET_ASID_SUM];
int asid_reverse_table[asid_count];
int current_asid;
enum  LRU_POINTER_TYPE{
	LRU_PRE = 0,
	LRU_BEH,
	LRU_POINTER_NUM,
};
#define LRU_LEN (asid_count+1)
#define end_asid (asid_count)
int LRU_table[LRU_LEN][LRU_POINTER_NUM];//double linked list, the last element is to record the lately(tail) and farthest(head) asid
#define LRU_TAIL LRU_table[end_asid][LRU_PRE] //lately asid
#define LRU_HEAD LRU_table[end_asid][LRU_BEH] //farthest asid
#define LRU_ASID_PRE(asid) LRU_table[asid][LRU_PRE]
#define LRU_ASID_BEH(asid) LRU_table[asid][LRU_BEH]
#endif
static inline int total_private_spt(){
#ifdef ASID_MANAGE
	return SET_ASID_SUM;
#else
	return PRIVATE_SPT_COUNT;
#endif
}

static inline uint32 get_current_asid(CPUState *env){
#ifdef ASID_MANAGE
	return current_asid;
#else
	return env->cp15.c13_context&0xff;
#endif
}
#ifdef ASID_MANAGE
static void dump_asid_table(){
	fprintf(stderr,"===>dump asid table\n");
	int idx;
	for(idx=0; idx<total_private_spt();idx++)
		fprintf(stderr, "ASID_TABLE[%d]=%d\n", idx, asid_table[idx]);
}

void invalid_all_private_spts(CPUState *env);
void invalid_private_spt_on_asid(CPUState *env, uint8_t asid, char *invalid_reason, unsigned long long *invalid_count);
void invalid_single_entry_of_private_spt(CPUState *env, uint32_t mva, uint8_t asid);
void private_spt_change_asid(uint32 old_asid, uint32 new_asid);
//LRU design (0 is ignored)
void LRU_insert_asid(int asid){
	// 1.do not handle asid_0
	if(asid==0)
		return ;
	// 2.update LRU queue
	if(LRU_ASID_BEH(asid)==-1){
		assert(LRU_ASID_PRE(asid)==-1);
		//current asid is not in the queue, then add it to the queue
		int tail_asid = LRU_TAIL;
		LRU_ASID_BEH(tail_asid) = asid;
		LRU_ASID_PRE(asid) = tail_asid;
		LRU_ASID_BEH(asid) = end_asid;
		LRU_TAIL = asid;
	}else{
		assert(LRU_ASID_PRE(asid)!=-1);
		//current asid is in the queue
		int front_asid = LRU_ASID_PRE(asid);
		int succ_asid = LRU_ASID_BEH(asid);
		LRU_ASID_BEH(front_asid) = succ_asid;
		LRU_ASID_PRE(succ_asid) = front_asid;
		int tail_asid = LRU_TAIL;
		LRU_ASID_PRE(asid) = tail_asid;
		LRU_ASID_BEH(asid) = end_asid;
		LRU_ASID_BEH(tail_asid) = asid;
		LRU_TAIL = asid;
	}	
}
void LRU_clear_all(){
	int idx;
	for(idx=1;idx<LRU_LEN;idx++){
		LRU_table[idx][LRU_PRE] = -1;
		LRU_table[idx][LRU_BEH] = -1;
	}
	LRU_TAIL = end_asid;//last asid is double linked list
	LRU_HEAD = end_asid;
	LRU_table[0][LRU_PRE] = 0;//asid_0
	LRU_table[0][LRU_BEH] = 0;//asid_0
}
void LRU_clear_asid(int asid){
	// 1.do not handle asid 0
	if(asid==0)
		return ;
	// 2.delete asid
	int front_asid = LRU_ASID_PRE(asid);
	int succ_asid = LRU_ASID_BEH(asid);
	if(front_asid==-1){
		assert(succ_asid==-1);
		return ;
	}
	LRU_ASID_BEH(front_asid) = succ_asid;
	LRU_ASID_PRE(succ_asid) = front_asid;
	// 3.clear
	LRU_ASID_PRE(asid) = -1;
	LRU_ASID_BEH(asid) = -1;
}
void LRU_dump(){
	fprintf(stderr, "dump LRU queue: old=>");
	int head_asid = LRU_HEAD;
	while(head_asid!=end_asid){
		fprintf(stderr, "%d=>", head_asid);
		head_asid = LRU_ASID_BEH(head_asid);
	}
	fprintf(stderr, "new\n");
}
//this asid must be in asid_table
int substitute_a_asid_by_manage(int new_asid){
	assert(new_asid!=0);
	//need free one to allocate, this one must be in asid_table
	int head_asid = LRU_HEAD;
	while(head_asid!=end_asid){
		int ret = asid_reverse_table[head_asid];
		if(ret!=-1){
			assert(asid_table[ret]==head_asid);
			ASID_DEBUG_LOG("substitue asid_table[%d]=%d\n", ret, head_asid);
			return ret;
		}
		head_asid = LRU_ASID_BEH(head_asid);
	}
	dump_asid_table();
	assert(0);
}
void recycle_asid(){
	int idx;
	for(idx=1; idx<total_private_spt();idx++){
		int asid = asid_table[idx];
		if(asid!=-1 && idx!=current_asid){
			PSPTInfo *curr_spt = private_spts + idx;
			if(curr_spt->dirty == false){
				ASID_DEBUG_LOG("Recycle check find one notdirty asid_table[%d]=%d\n", idx, asid);
				asid_reverse_table[asid] = -1;
				asid_table[idx] = -1;
			}
		}
	}
}

//wrapper asid 
void invalid_all_private_spts_by_manage(CPUState *env){
	ASID_DEBUG_LOG("invalid all\n");
	invalid_all_private_spts(env);
	int idx;
	for(idx=1; idx<total_private_spt();idx++)
		asid_table[idx] = -1;
	asid_table[0] = 0;
	for(idx=1; idx<asid_count; idx++)
		asid_reverse_table[idx] = -1;
	asid_reverse_table[0] = 0;
	LRU_clear_all();
}
void invalid_private_spt_on_asid_by_manage(CPUState *env, uint8_t asid, char *invalid_reason, unsigned long long *invalid_count){
	int asid_table_idx = asid_reverse_table[asid];
	if(asid_table_idx != -1){
		invalid_private_spt_on_asid(env, asid_table_idx, invalid_reason, invalid_count);
		if(asid_table_idx!=current_asid && asid_table_idx!=0){
			asid_table[asid_table_idx] = -1;
			assert(asid!=0);
			asid_reverse_table[asid] = -1;
			LRU_clear_asid(asid);
			ASID_DEBUG_LOG("invalid other asid_table[%d]=%d\n", asid_table_idx, asid);
			return ;
		}
		ASID_DEBUG_LOG("invalid self asid_table[%d]=%d\n", asid_table_idx, asid);
		return ;
	}
	ASID_DEBUG_LOG("invalid asid_table[none]=%d\n",asid);	
}
void invalid_single_entry_of_private_spt_by_mange(CPUState *env, uint32_t mva, uint8_t asid){
	int asid_table_idx = asid_reverse_table[asid];
	if(asid_table_idx != -1){
		ASID_DEBUG_LOG("invalid entry asid_table[%d]=%d\n", asid_table_idx, asid);
		invalid_single_entry_of_private_spt(env, mva, asid_table_idx);
		return ;
	}	
	ASID_DEBUG_LOG("invalid entry asid_table[none]=%d\n",asid);
}
void private_spt_change_asid_by_manage(uint32 old_asid, uint32 new_asid){
	//record asid and recycle some empty asid
	LRU_insert_asid(new_asid);
	recycle_asid();
	// 1. find it exist
	int asid_table_idx = asid_reverse_table[new_asid];
	if(asid_table_idx != -1){
		ASID_DEBUG_LOG("Change to asid_table[%d]=%d\n", asid_table_idx, new_asid);
		private_spt_change_asid(old_asid, asid_table_idx);
		current_asid = asid_table_idx;
		return ;
	}
	// 2. find a free
	int idx;
	for(idx=0; idx<total_private_spt();idx++){
		if(asid_table[idx]==-1){
			ASID_DEBUG_LOG("Find a free asid, change to asid_table[%d]=%d\n", idx, new_asid);
			private_spt_change_asid(old_asid, idx);
			asid_table[idx] = new_asid;
			assert(new_asid!=0);
			asid_reverse_table[new_asid] = idx;
			current_asid = idx;
			return ;
		}
	}
	// 3. free one to use
	int r = substitute_a_asid_by_manage(new_asid);
	ASID_DEBUG_LOG("Free one to use , change to asid_table[%d]=%d\n", r, new_asid);
	invalid_private_spt_on_asid(NULL,r,NULL,NULL);
	assert(asid_table[r]!=0);
	asid_reverse_table[asid_table[r]] = -1;
	private_spt_change_asid(old_asid, r);
	asid_table[r] = new_asid;
	assert(asid_table[r]!=0);
	asid_reverse_table[new_asid] = r;
	current_asid = r;	
}
#endif

void spt_init (void ) {	
#ifdef ASID_MANAGE
	int idx;
	//init asid_table
	for(idx=1;idx<SET_ASID_SUM; idx++)
		asid_table[idx] = -1;
	asid_table[0] = 0;
	//init reverse table
	for(idx=1;idx<asid_count;idx++)
		asid_reverse_table[idx] = -1;
	asid_reverse_table[0] = 0;
	//init current_asid
	current_asid = -1;
	//init LRU
	LRU_clear_all();
#endif

#ifdef PRIVATE_SPT
	if(private_spts == NULL) {
		private_spts = (PSPTInfo *)malloc(sizeof(PSPTInfo) * total_private_spt());
		if(private_spts == NULL){
			perror("spt_init:");
			assert(0);
		}
		memset((void *)private_spts, 0, sizeof(PSPTInfo) * total_private_spt());
	}
	
	void *allocated_start = mmap(NULL, GUEST_VIRTUAL_SPACE_SIZE*total_private_spt(), PROT_NONE, MAP_PRIVATE|MAP_ANONYMOUS, -1, 0);
	if(allocated_start == MAP_FAILED) {
	        perror("mmap_all_guest_virtual_space: ");
	        assert(0);
    	}
	spt_guest_base = allocated_start;
	all_private_spts_cleared = true;
	
#else//shared shadow page table
	// alloc guest vitual address space. (4G)
	void *allocated_start = mmap_new_guest_virtual_space();
	fprintf(stderr, "\nSPT_init: allocated_start = %p\n\n", allocated_start);
	spt_guest_base = (unsigned long)allocated_start;
	spt_cleared = true;
#endif
	// set reg GS 
	spt_setup_base_seg((unsigned long)allocated_start);
	
	// init the spt_reverse_map. (32M)
	if(spt_reverse_map == NULL){
		spt_reverse_map = (RMap *)malloc(sizeof(RMap) * SPT_GUEST_PHYS_PAGE_NUM);
		assert(spt_reverse_map != NULL);
	}
	memset((void *)spt_reverse_map, 0, sizeof(RMap) * SPT_GUEST_PHYS_PAGE_NUM);

	// init the memory pool. ()
	if(memory_pool == NULL) {
		memory_pool = (RMapInfo*)malloc(sizeof(RMapInfo) * MEMORY_SLOT_NUM);
		assert(memory_pool != NULL);
		next_slot_index = 0;
		slot_capacity = MEMORY_SLOT_NUM;
	}
	memset((void *)memory_pool, 0, sizeof(RMapInfo) * MEMORY_SLOT_NUM);

#ifdef FILL_SPT_AT_TIMESLOT_START
	// init the process bitmaps. (1G)
	if(spt_bitmaps ==  NULL) {
		spt_bitmaps = (SPT_BitMap *)malloc(sizeof(SPT_BitMap) * SPT_BITMAP_NUM);
		assert(spt_bitmaps != NULL);
	}
	memset((void *)spt_bitmaps, 0, sizeof(SPT_BitMap) * SPT_BITMAP_NUM);
#endif	
}
static int spt_get_memory_slot(int count){
	assert((memory_pool != NULL) && (count > 0));
	if((next_slot_index+count) > slot_capacity) {
		fprintf(stderr, "Warning!!!slot_capacity (0x%x)is not enough! realloc!\n", slot_capacity);
		assert(0);
		slot_capacity *= 2;
		memory_pool = (RMapInfo *)realloc((void *)memory_pool, sizeof(RMapInfo)*slot_capacity);
		assert(memory_pool != NULL);
	}
	if((next_slot_index+count) >= slot_capacity){
		fprintf(stderr, "next: 0x%x\t count: 0x%x\t slot_capacity: 0x%x\n", next_slot_index, count, slot_capacity);
		assert(0);
	}
	int next = next_slot_index;
	next_slot_index += count;
	return next;
}
extern int spt_get_guest_page_size(CPUState *env, uint32_t address, uint32 *phys_addr);
static inline uint32_t spt_convert_guest_mva_to_va (CPUState *env, uint32_t mva) {
    uint32_t guest_va = mva;

    if((mva & 0xf7000000) == env->cp15.c13_fcse)
        guest_va = (mva & 0x1ffffff);
    return guest_va;
}

#ifdef PRIVATE_SPT
static void delete_invalid_reverse_map(RMap *rmaps) {
	RMapInfo *rmap_start = memory_pool + rmaps->vpages_slots_start_index;
	RMapInfo *rmap_end = rmap_start + rmaps->count;
	RMapInfo *i_rmap = rmap_start;
	RMapInfo *j_rmap = rmap_end - 1;
	while(i_rmap <= j_rmap) {
		// find first invalid rmap from start
		while((i_rmap<=j_rmap) &&
			(i_rmap->timestamp == private_spts[i_rmap->asid].timestamp)){
			i_rmap ++;
		}
		// find first valid rmap from tail
		while((i_rmap<=j_rmap) && 
			(j_rmap->timestamp<private_spts[j_rmap->asid].timestamp)){
			j_rmap--;
		}
		//cp the valid j_rmap to replace the invalid i_rmap 
		if(i_rmap < j_rmap) {
			i_rmap->addr = j_rmap->addr;
			i_rmap->asid = j_rmap->asid;
			i_rmap->timestamp = j_rmap->timestamp;
			// move to next
			i_rmap++;
			j_rmap--;
		}
	}		
	// update count
	if(j_rmap >= rmap_start){
		rmaps->count = j_rmap - rmap_start + 1;
	}
	else
		rmaps->count = 0;
}

void spt_add_reverse_map(uint8_t new_rmap_asid, uint32_t gva_page, target_ulong size, uint32 prot, uint32_t phys_page){
	assert((size & SPT_GUEST_MIN_PAGE_MASK) == 0);
	// if this map in SPT has no write prot, we don't add it into the reverse_map
	// reverse map only concerns the map that has write prot. (SMC related)
	if(!(prot & PAGE_WRITE)) {
		return;
	}

	// add this reverse map
	for(; size>0; size-=SPT_GUEST_MIN_PAGESIZE, gva_page+=SPT_GUEST_MIN_PAGESIZE, phys_page+=SPT_GUEST_MIN_PAGESIZE) {
		RMap *rmaps = spt_reverse_map + (phys_page >> SPT_GUEST_MIN_PAGEBITS);
#ifdef DEBUG_SPT
		fprintf(stderr, "Adding Rmap, phys: 0x%x, gva:0x%x, asid:%d, prot:0x%x,  ", phys_page, gva_page, new_rmap_asid, prot);
		fprintf(stderr, "count:%d, capacity:%d, start:0x%x\n", rmaps->count, rmaps->capacity, rmaps->vpages_slots_start_index);
#endif
		// this phys page has no reverse maps, alloc memory slots
		if(rmaps->capacity == 0) {
			rmaps->vpages_slots_start_index = spt_get_memory_slot(16);
			assert(rmaps->count == 0);
			rmaps->capacity = 16;
		}
		// check whether this new reverse map to be added already existed.
		RMapInfo *rmap_start = memory_pool + rmaps->vpages_slots_start_index;
		RMapInfo *rmap_end = rmap_start + rmaps->count;
		RMapInfo *i_rmap = rmap_start;
		bool  found = false;
		while(i_rmap < rmap_end) {
			if((i_rmap->timestamp == private_spts[i_rmap->asid].timestamp) 
				&& ((i_rmap->addr & ~(SPT_GUEST_MIN_PAGE_MASK))==gva_page)
				&& (i_rmap->asid == new_rmap_asid)) {
				//fprintf(stderr, "\tRepeated adding rmap!gva:0x%x, asid:%d\n", gva_page, new_rmap_asid);
				if((i_rmap->addr & (SPT_GUEST_MIN_PAGE_MASK)) != prot){
					fprintf(stderr, "Repeated Rmap, but prot is different! old: %d, new: %d\n", (i_rmap->addr & (SPT_GUEST_MIN_PAGE_MASK)), prot);
					i_rmap->addr = (gva_page | prot);
				}
				found = true;
				break;
			}
			i_rmap ++;
		}
		if(found == true)
			continue;
		// check whether there is any empty slots, if no, realloc slots
		if(rmaps->count >= rmaps->capacity) {
			delete_invalid_reverse_map(rmaps);
			if(rmaps->count >= rmaps->capacity) {
				assert(rmaps->count == rmaps->capacity);
				rmaps->vpages_slots_start_index = spt_get_memory_slot(rmaps->capacity * 2);
				memcpy((void *)(memory_pool+rmaps->vpages_slots_start_index), rmap_start, sizeof(RMapInfo)*(rmaps->capacity));
				rmaps->capacity *= 2;
			}
		}
		// Finally, add this new reverse map
		assert(rmaps->count < rmaps->capacity);
		RMapInfo *new_rmap = memory_pool + rmaps->vpages_slots_start_index + rmaps->count;
		new_rmap->asid = new_rmap_asid;
		new_rmap->addr = gva_page | prot;
		new_rmap->timestamp = private_spts[new_rmap_asid].timestamp;
		rmaps->count ++;
	}
}
void spt_del_reverse_map(uint8_t asid, uint32_t gva_page, target_ulong size, uint32_t gpa_page) {
	assert((size & SPT_GUEST_MIN_PAGE_MASK) == 0);
	
	for(; size>0; size-=SPT_GUEST_MIN_PAGESIZE, gva_page+=SPT_GUEST_MIN_PAGESIZE, gpa_page+=SPT_GUEST_MIN_PAGESIZE) {
		RMap *rmaps = spt_reverse_map + (gpa_page >> SPT_GUEST_MIN_PAGEBITS);
		// find this Rmap to be deleted, and replace it with the last entry
		RMapInfo *rmap_start = memory_pool + rmaps->vpages_slots_start_index;
		RMapInfo *rmap_end = rmap_start + rmaps->count;
		RMapInfo *i_rmap = rmap_start;
		for(; i_rmap<rmap_end; i_rmap++){
			if((i_rmap->asid == asid) && 
				((i_rmap->addr &(~SPT_GUEST_MIN_PAGE_MASK)) == gva_page)){
				if(i_rmap != rmap_end-1){
					i_rmap->asid = (rmap_end-1)->asid;
					i_rmap->timestamp = (rmap_end-1)->timestamp;
					i_rmap->addr = (rmap_end-1)->addr;
				}
				rmaps->count--;
				break;
			}
		}
	}
}

static inline void spt_update_range(unsigned long start, uint64_t size, int prot){
    int ret = mprotect((void *)start, size, prot);
    if(ret) {
        perror("spt_update_range: mprotect failed!");
        assert(0);
    }
}

inline unsigned long get_spt_base(uint8_t asid){
	unsigned long guest_base = spt_guest_base + (asid)*GUEST_VIRTUAL_SPACE_SIZE;
	return guest_base;
}

inline void Invalid_guest_virtual_space(uint8_t asid) {
	unsigned long space_start = get_spt_base(asid);	
	void *mmap_ret = mmap(space_start, GUEST_VIRTUAL_SPACE_SIZE, PROT_NONE, MAP_FIXED|MAP_PRIVATE|MAP_ANONYMOUS, -1, 0);
	if(mmap_ret == MAP_FAILED){
		perror("mmap failed!");
		assert(0);
	}	
}

void spt_smc_protect_page(CPUARMState *env, ram_addr_t start, ram_addr_t end) {
	start &= (~SPT_GUEST_MIN_PAGE_MASK);
	if((end & SPT_GUEST_MIN_PAGE_MASK))
		end = (end+SPT_GUEST_MIN_PAGESIZE) & (~SPT_GUEST_MIN_PAGE_MASK);
	unsigned long phys_page = start;
	for(; phys_page<end; phys_page+=SPT_GUEST_MIN_PAGESIZE) {
		RMap *rmap = spt_reverse_map + (phys_page >> SPT_GUEST_MIN_PAGEBITS);
		if(rmap->count == 0)
			continue;
		RMapInfo *beg = memory_pool + rmap->vpages_slots_start_index;
		RMapInfo *end = beg + rmap->count;
		RMapInfo *rmap_info = beg;
		int found_valid_count = 0;
		for(; rmap_info < end; rmap_info++){
			PSPTInfo *curr_spt = private_spts + rmap_info->asid;
			assert(rmap_info->timestamp <= curr_spt->timestamp);
			if(rmap_info->timestamp == curr_spt->timestamp) {
				int prot = rmap_info->addr & SPT_GUEST_MIN_PAGE_MASK;
				assert(prot & PAGE_WRITE);	
				found_valid_count++;
				unsigned long guest_base = get_spt_base(rmap_info->asid);
				prot &= (~PAGE_WRITE);
				uint32 gva = (rmap_info->addr) & (~SPT_GUEST_MIN_PAGE_MASK);
				spt_update_range((unsigned long)spt_g2h(guest_base, gva), SPT_GUEST_MIN_PAGESIZE, prot);
			}
		}
		rmap->count = 0;
	}
}

static void unset_rmap_timestamp_on_asid(uint8_t asid){
	RMap *rmap = NULL;
	uint32 page_index = 0;
	for(; page_index<SPT_GUEST_PHYS_PAGE_NUM; page_index++){
		rmap = spt_reverse_map + page_index;
		if(rmap->count == 0)
			continue;
		else {
			RMapInfo *start = memory_pool + rmap->vpages_slots_start_index;
			RMapInfo *end = start + rmap->count;
			RMapInfo *p_rmap = start;
			for(; p_rmap < end; p_rmap++){
				if(p_rmap->asid == asid)
					p_rmap->timestamp = 0;
			}
		}
	}
}

static inline void increase_timestamp_of_private_spt(uint8 asid){
	PSPTInfo *curr_spt = private_spts + asid;
	if(curr_spt->timestamp == UINT_MAX) {
		curr_spt->timestamp = 1;
		unset_rmap_timestamp_on_asid(asid);
		fprintf(stderr, "\n\ntimestamp of asid %d overflow!!!\n", asid);
	}
	else 
		curr_spt->timestamp ++;
}

static inline int gather_spt_space(uint8_t curr_asid) {
	int asid_index = 0;
	int spt_count = 0;
	for(; asid_index<total_private_spt(); asid_index++) {
		if(asid_index == curr_asid)
			continue;
		// if there is invalidated spt, we remap it to get a consistent space
		if(private_spts[asid_index].dirty == false) {
			Invalid_guest_virtual_space(asid_index);
			spt_count ++;
		}
	}
	return spt_count;
}

void invalid_all_private_spts(CPUState *env){
	if(all_private_spts_cleared){
		return;
	}
	all_private_spts_cleared = true;
	assert(get_current_asid(env) == 0);
	int asid_index = 0;
	int spt_count = 0;
	for(; asid_index<total_private_spt(); asid_index++) {
		if(private_spts[asid_index].dirty == true) {
			Invalid_guest_virtual_space(asid_index);
			private_spts[asid_index].dirty = false;
			private_spts[asid_index].map_count = 0;
			increase_timestamp_of_private_spt(asid_index);
			spt_count ++;
		}
	}
	total_map_count = 0;
}

void invalid_private_spt_on_asid(CPUState *env, uint8_t asid, char *invalid_reason, unsigned long long *invalid_count){
	PSPTInfo *curr_spt = private_spts + asid;
	if(curr_spt->dirty == false) 
		return;

	if(asid == 0)
		assert(0);

	//invalid private spt
	Invalid_guest_virtual_space(asid);
	//set not dirty
	curr_spt->dirty = false;
	//increase timestamp on this asid
	increase_timestamp_of_private_spt(asid);
	total_map_count -= curr_spt->map_count;
	curr_spt->map_count = 0;
}

void invalid_single_entry_of_private_spt(CPUState *env, uint32_t mva, uint8_t asid){
	mva &= (~(qemu_host_page_size - 1));
	PSPTInfo *target_spt = private_spts + asid;
	if(target_spt->dirty == false)
		return;
	//convert mva to va
	uint32_t gva = spt_convert_guest_mva_to_va(env, mva);
	//TODO: maybe wrong if gva!= mva
	//assert(gva == mva);

	uint32_t invalid_size = SPT_L2_PAGE_SIZE;

	if(get_current_asid(env)== asid){
		uint32 phys_addr = 0xffffffff;
		invalid_size = spt_get_guest_page_size(env, gva, &phys_addr);
		assert(invalid_size >= qemu_host_page_size);
		// del this map from reverse map
		if(phys_addr != 0xffffffff)
			spt_del_reverse_map(asid, gva, invalid_size, phys_addr);
	}else {// We cann't get the env that this mva and asid belong to, so we use the default invalid_size, and we leave RMap undeleted
		;//fprintf(stderr, "\n\t\t!!!Invalid mva:0x%x on asid:%d, But env->asid: %d\n", mva, asid, env->cp15.c13_context&0xff);
	}

	// invalid this entry
	unsigned long spt_base = get_spt_base(asid);
	spt_update_range((unsigned long)spt_g2h(spt_base, gva), invalid_size, PROT_NONE);
}
void private_spt_change_asid(uint32 old_asid, uint32 new_asid){
#ifdef ASID_MANAGE
	unsigned long spt_base = get_spt_base(new_asid);
	// setup register GS
	spt_setup_base_seg(spt_base);
#else
	if(new_asid != 0) {
		unsigned long spt_base = get_spt_base(new_asid);
		// setup register GS
		spt_setup_base_seg(spt_base);
	}
#endif
}

#else//shared method
void spt_add_reverse_map(uint32_t gva_page, target_ulong size, uint32 prot, uint32_t phys_page){
	assert((size & SPT_GUEST_MIN_PAGE_MASK) == 0);
	// if this map in SPT has no write prot, we don't add it into the reverse_map
	// reverse map only concerns the map that has write prot. (SMC related)
	if(!(prot & PAGE_WRITE))
		return;
	// add this reverse map
	for(; size>0; size-=SPT_GUEST_MIN_PAGESIZE, gva_page+=SPT_GUEST_MIN_PAGESIZE, phys_page+=SPT_GUEST_MIN_PAGESIZE) {
		RMap *map = &(spt_reverse_map[phys_page >> SPT_GUEST_MIN_PAGEBITS]);
		if(map->timestamp < SPT_timestamp) { // already invalidated
			map->vpages_slots_start_index = spt_get_memory_slot(8);
			map->timestamp = SPT_timestamp;
			map->capacity = 8;
			map->count=0;
		}
		
		uint32 entry = gva_page | prot;
		int j = map->vpages_slots_start_index;
		int j_end = j+map->count;
		bool found = false;
		for(; j< j_end; j++) {
			if(memory_pool[j] == entry){
				//fprintf(stderr, "Repeated add reverse map!\n");
				found = true;
				break;
			}
		}
		if(found)
			continue;
		
		// add this new rmap
		if(map->count >= map->capacity) {
			fprintf(stderr, "rmap count:%d more than capacity %d! phys=0x%x remalloc!\n", map->count, map->capacity, phys_page);
			int i =map->vpages_slots_start_index;
			int end = i+map->count;
			for(; i<end;i++){
				fprintf(stderr, "addr: 0x%x,",memory_pool[i]);
			}
			fprintf(stderr, "\n");
			
			RMapInfo *orig_mapinfo = &(memory_pool[map->vpages_slots_start_index]);
			map->vpages_slots_start_index = spt_get_memory_slot(map->capacity * 2);
			memcpy((void *)(memory_pool+map->vpages_slots_start_index), orig_mapinfo, sizeof(RMapInfo)*map->capacity);
			map->capacity *= 2;
		}
		assert(map->count < map->capacity);
		memory_pool[map->vpages_slots_start_index+map->count] = entry;
		map->count++;
	}
}

void spt_del_reverse_map(uint32_t gva_page, target_ulong size, uint32_t gpa_page) {
	assert((size & SPT_GUEST_MIN_PAGE_MASK) == 0);
	for(; size>0; size-=SPT_GUEST_MIN_PAGESIZE, gva_page+=SPT_GUEST_MIN_PAGESIZE, gpa_page+=SPT_GUEST_MIN_PAGESIZE) {
		RMap *map = &(spt_reverse_map[gpa_page >> SPT_GUEST_MIN_PAGEBITS]);
		assert(map->timestamp <= SPT_timestamp);
		if(map->timestamp == SPT_timestamp) {// this rmap is valid
			int j = map->vpages_slots_start_index;
			int end = map->vpages_slots_start_index+map->count;
			int k=j;
			for(; j<end; j++){
				if((memory_pool[j] & (~SPT_GUEST_MIN_PAGE_MASK)) != gva_page) {
					if(k != j) {
						memory_pool[k] = memory_pool[j];
					}
					k++;
				}
			}
			map->count = k - map->vpages_slots_start_index;
		}
	}
}

void spt_clear_reverse_map() {
	next_slot_index = 0;
	// increse spt timestamp
	if(SPT_timestamp == INT_MAX) {
		SPT_timestamp = 1;
		memset((void *)memory_pool, 0, sizeof(RMapInfo)*slot_capacity);
	}
	else {
		SPT_timestamp++;
	}
}

void spt_invalid_by_mva(CPUState *env, uint32_t mva) {
	if(spt_cleared)
		return;
    uint32_t guest_va = spt_convert_guest_mva_to_va(env, mva);
    uint32 phys_addr = 0xffffffff;
    uint32_t invalid_size = spt_get_guest_page_size(env, guest_va, &phys_addr);

    assert((guest_va & (qemu_host_page_size - 1)) == 0);
    assert(invalid_size >= qemu_host_page_size);
	spt_invalid_range(guest_va, invalid_size, phys_addr);
}

void spt_update_range(uint32_t start_va, uint64_t size, int prot){
    int ret = mprotect((void *)spt_g2h(start_va), size, prot);
    if(ret) {
        perror("spt_update_range: mprotect failed!");
        assert(0);
    }
#ifdef FILL_SPT_AT_TIMESLOT_START
	if(prot == 0) 		
		spt_del_map(start_va, size);
#endif
}

void spt_invalid_range(uint32_t start_va, uint64_t size, uint32_t phys_addr){
    int ret = mprotect((void *)spt_g2h(start_va), size, PROT_NONE);
    if(ret) {
        perror("spt_invalid_range: mprotect failed!");
        assert(0);
    }
#ifdef FILL_SPT_AT_TIMESLOT_START
	// del the bitmap
	spt_del_map(start_va&(~SPT_GUEST_MIN_PAGE_MASK), size);
#endif
    // del  the reverse map from the list
    if(phys_addr != 0xffffffff)
	    spt_del_reverse_map(start_va&(~SPT_GUEST_MIN_PAGE_MASK), size, phys_addr&(~SPT_GUEST_MIN_PAGE_MASK));
}

void spt_invalid(CPUState *env) {
	if(spt_cleared)
		return;
	
	spt_cleared = true;

	//invalid
	int ret = mprotect((void *)spt_guest_base, GUEST_VIRTUAL_SPACE_SIZE, PROT_NONE);
	if(ret) {
	    perror("spt_invalid: mprotect failed!");
	    assert(0);
	}
	// copy bitmap in curr timeslot to spt_bitmaps corresponding to this table_base
	//fill entries accessed by this process in history timeslot
#ifdef FILL_SPT_AT_TIMESLOT_START
	SPT_bitmap = NULL;
#endif
	// clear spt_reverse_map
	spt_clear_reverse_map();
}

void spt_smc_protect_page(CPUARMState *env, ram_addr_t start, ram_addr_t end) {
	if(spt_cleared)
		return;
	start &= (~SPT_GUEST_MIN_PAGE_MASK);
	if((end & SPT_GUEST_MIN_PAGE_MASK))
		end = (end+SPT_GUEST_MIN_PAGESIZE) & (~SPT_GUEST_MIN_PAGE_MASK);
	
	for(; start<end; start+=SPT_GUEST_MIN_PAGESIZE) {
		RMap *map = &(spt_reverse_map[start >> SPT_GUEST_MIN_PAGEBITS]);
		assert(map->timestamp <= SPT_timestamp);
		if(map->timestamp == SPT_timestamp) {
			int b = map->vpages_slots_start_index;
			int e = b + map->count;
			int j;
			for(j=b; j<e; j++){
				int prot = (memory_pool[j]) & SPT_GUEST_MIN_PAGE_MASK;
				assert(prot & PAGE_WRITE);
				prot &= (~PAGE_WRITE);
				uint32 gva = (memory_pool[j]) & (~SPT_GUEST_MIN_PAGE_MASK);
				spt_update_range(gva, SPT_GUEST_MIN_PAGESIZE, prot);
			}
			map->count = 0;
		}
	}
}
void spt_dump_reverse_map() {
	if(spt_reverse_map != NULL) {
		FILE *maplogfile = fopen("/tmp/rmap.log", "w");
		assert(maplogfile != NULL);
		int i;
		for(i=0; i<SPT_GUEST_PHYS_PAGE_NUM; i++){
			RMap *map = &(spt_reverse_map[i]);
			fprintf(maplogfile,"0x%x, count: %d -- timestamp: %d -- ", i*SPT_GUEST_MIN_PAGESIZE, map->count, map->timestamp);
			if(map->timestamp == SPT_timestamp) {
				int j=map->vpages_slots_start_index;
				int end = map->vpages_slots_start_index + map->count;
				for(; j<end;j++)
					fprintf(maplogfile, "addr: 0x%x\tprot: 0x%x\t", (memory_pool[j])&(~SPT_GUEST_MIN_PAGE_MASK)
						,(memory_pool[j]) & SPT_GUEST_MIN_PAGE_MASK);
				fprintf(maplogfile, "\n");
			}
		}
		fclose(maplogfile);
	}
}

#endif
#ifdef FILL_SPT_AT_TIMESLOT_START
uint32_t spt_bitmap_hash(uint32_t base){
	return ((base & 0x07ffc000)>>14);
}

void spt_unset_bitmap(uint32_t va){
	uint32 dword_index = va >> 18; // 12+6
	uint32 bit_index = ((va >> 12)&0x3f);
	uint64 value = SPT_bitmap->bitmap[dword_index] & ((uint64)(1ull<<bit_index));
	if(value != 0) {
		SPT_bitmap->count--;
		SPT_bitmap->bitmap[dword_index] &= ~((uint64)(1ull<<bit_index));// clear this bit in bitmap
	}
}

void spt_set_bitmap(uint32_t va){
	uint32 dword_index = va >> 18; // 12+6
	uint32 bit_index = ((va >> 12)&0x3f);
	uint64 value = SPT_bitmap->bitmap[dword_index] & ((uint64)(1ull<<bit_index));
	if(value == 0){
		SPT_bitmap->count++;
		SPT_bitmap->bitmap[dword_index] |= (uint64)(1ull<<bit_index);// set this bit in bitmap
		//update bitmap start and end index
		if(SPT_bitmap->count == 1){ // the first entry
			SPT_bitmap->start_dword = dword_index;
			SPT_bitmap->end_dword = dword_index+1;
		}
		else if(dword_index < SPT_bitmap->start_dword)
			SPT_bitmap->start_dword = dword_index;
		else if(dword_index >= SPT_bitmap->end_dword)
			SPT_bitmap->end_dword = dword_index+1;
	}
}

bool spt_bitmap_set(uint32_t va) {
	uint32 dword_index = va >> 18; // 12+6
	uint32 bit_index = ((va >> 12)&0x3f);
	uint64 value = SPT_bitmap->bitmap[dword_index] & ((uint64)(1ull<<bit_index));
	if(value == 0)
		return false;
	else
		return true;
}

void spt_clear_bitmap() {
	int start=SPT_bitmap->start_dword;
	int end = SPT_bitmap->end_dword;
	memset(&(SPT_bitmap->bitmap[start]), 0, (end-start)*sizeof(uint64));
	SPT_bitmap->count=0;
	SPT_bitmap->start_dword = SPT_bitmap->end_dword = 0;
}

static bool spt_updated(uint32 va) {
	uint32 dword_index = va >> 18; // 12+6
	uint32 bit_index = ((va >> 12)&0x3f);
	uint64 val = SPT_bitmap->bitmap[dword_index] & (0x1ull << bit_index);
	if(val == 0)
		return false;
	else
		return true;
}

void spt_add_map(uint32_t gva_page, target_ulong size) {
	uint32 end = gva_page + size;
	uint32 va = gva_page;
	for(; va<end; va+=SPT_GUEST_MIN_PAGESIZE) {
		spt_set_bitmap(va);
	}
}

void spt_del_map(uint32_t gva_page, target_ulong size) {
	uint32 end = gva_page + size;
	uint32 va = gva_page;
	//fprintf(stderr, "del map: 0x%x\n", gva_page);
	for(; va<end; va+=SPT_GUEST_MIN_PAGESIZE) {
		spt_unset_bitmap(va);
	}
}
#endif
//only for x86 64
#ifdef __NetBSD__
#define PC_sig(context)       _UC_MACHINE_PC(context)
#define TRAP_sig(context)     ((context)->uc_mcontext.__gregs[_REG_TRAPNO])
#define ERROR_sig(context)    ((context)->uc_mcontext.__gregs[_REG_ERR])
#define MASK_sig(context)     ((context)->uc_sigmask)
#elif defined(__OpenBSD__)
#define PC_sig(context)       ((context)->sc_rip)
#define TRAP_sig(context)     ((context)->sc_trapno)
#define ERROR_sig(context)    ((context)->sc_err)
#define MASK_sig(context)     ((context)->sc_mask)
#elif defined(__FreeBSD__) || defined(__DragonFly__)
#include <ucontext.h>

#define PC_sig(context)  (*((unsigned long *)&(context)->uc_mcontext.mc_rip))
#define TRAP_sig(context)     ((context)->uc_mcontext.mc_trapno)
#define ERROR_sig(context)    ((context)->uc_mcontext.mc_err)
#define MASK_sig(context)     ((context)->uc_sigmask)
#else
#define PC_sig(context)       ((context)->uc_mcontext.gregs[16])
#define TRAP_sig(context)     ((context)->uc_mcontext.gregs[REG_TRAPNO])
#define ERROR_sig(context)    ((context)->uc_mcontext.gregs[REG_ERR])
#define MASK_sig(context)     ((context)->uc_sigmask)
#endif

//define access type
enum ac_type {
	AC_READ = 0,
	AC_WRITE = 1,
	AC_EXEC = 2,
};
static const char *signal_name[65] = {"", "SIGHUP",	 "SIGINT", "SIGQUIT", "SIGILL", "SIGTRAP",
      "SIGABRT", "SIGBUS", "SIGFPE", "SIGKILL", "SIGUSR1", "SIGSEGV", "SIGUSR2", "SIGPIPE", "SIGALRM", "SIGTERM",
      "SIGSTKFLT", "SIGCHLD", "SIGCONT", "SIGSTOP", "SIGTSTP", "SIGTTIN", "SIGTTOU", "SIGURG", "SIGXCPU", "SIGXFSZ",
      "SIGVTALRM", "SIGPROF", "SIGWINCH", "SIGIO", "SIGPWR", "SIGSYS", "SIGRTMIN", "SIGRTMIN+1", "SIGRTMIN+2", "SIGRTMIN+3",
      "SIGRTMIN+4", "SIGRTMIN+5", "SIGRTMIN+6", "SIGRTMIN+7", "SIGRTMIN+8", "SIGRTMIN+9", "SIGRTMIN+10", "SIGRTMIN+11", "SIGRTMIN+12",
      "IGRTMIN+13", "SIGRTMIN+14", "SIGRTMIN+15", "SIGRTMAX-14", "SIGRTMAX-13", "SIGRTMAX-12", "SIGRTMAX-11", "SIGRTMAX-10", "SIGRTMAX-9",
      "SIGRTMAX-8", "SIGRTMAX-7", "SIGRTMAX-6", "SIGRTMAX-5", "SIGRTMAX-4", "SIGRTMAX-3", "SIGRTMAX-2", "SIGRTMAX-1", "SIGRTMAX"};

/* check the input addr_read/write/exec, return the flag that records whether this page is MMIO or NOT_DIRTY*/
static int spt_check_mmio_or_dirty(uint32_t vaddr, int *prot, CPUTLBEntry te, int access_type) {
    target_ulong addr_read = te.addr_read;
    target_ulong addr_write = te.addr_write;
    target_ulong addr_code = te.addr_code;
    
    int flag = 0;
    if((*prot & PAGE_BITS) == 0)
        return flag;

    /*read*/
    if((*prot & PAGE_READ) && (addr_read != vaddr)) {
        (*prot) &= ~PAGE_READ;
        //check MMIO
        if(addr_read & TLB_MMIO)
            flag |= PAGE_FLAG_MMIO;
    }
    /*write*/
    if((*prot & PAGE_WRITE) && (addr_write != vaddr)) {
        (*prot) &= ~PAGE_WRITE;
        
        if(addr_write & TLB_MMIO) 
            flag |= PAGE_FLAG_MMIO;
        if((addr_write & TLB_NOTDIRTY) && (access_type == AC_WRITE))
            flag |= PAGE_FLAG_NOTDIRTY;
    }
    /*exec*/
    if((*prot & PAGE_EXEC) && (addr_code != vaddr)) {
        (*prot) &= ~PAGE_EXEC;
        
        //check MMIO
        if(addr_code & TLB_MMIO)
            flag |= PAGE_FLAG_MMIO;
    }
    /*return flag*/
    return flag;
}

static void spt_get_tlb_entry(CPUARMState *env, uint32_t address, uint32_t phys_addr, int prot, CPUTLBEntry *te){
    int mmu_index = MMU_USER_IDX;
    int is_softmmu = 1;
    tlb_set_page(env, address, phys_addr, prot, mmu_index, is_softmmu, te);
}

static int spt_further_limit_prot(CPUARMState *env, uint32_t address, uint32_t phys_addr, int *prot, int access_type){
    if((*prot & PAGE_BITS) == 0)
        return 0;
    
    //further limit prot, we finish this according to the way that tlb_set_page

    address &= ~(uint32_t)0x3ff;
    phys_addr &= ~(uint32_t)0x3ff;
    
    /* Check MMIO or NOT_DIRTY in the way that set TLB*/
    CPUTLBEntry te;
    spt_get_tlb_entry(env, address, phys_addr, *prot, &te);

    /* Get the right prot considering mmio or not_dirty */
    int flag = spt_check_mmio_or_dirty(address, prot, te, access_type);
    
    return flag;
}

extern int get_phys_addr(CPUState * env, uint32_t address, int access_type, int is_user,
							uint32_t * phys_ptr, int * prot, target_ulong * page_size);
extern void spt_smc_invalid(CPUARMState *env, TranslationBlock *current_tb,
						target_phys_addr_t start);
extern int h2g_pc_convertion_and_restore(CPUState * env,uintptr_t searched_pc,TranslationBlock * * tb);
static void spt_smc_handler(CPUARMState *env, int is_user, uintptr_t pc)
{
    uint32_t pc_phys_addr;
    target_ulong pc_page_size;
    int prot;            
    TranslationBlock* tb = NULL;
	// get curr_tb and arm_pc
    uint32_t ret = h2g_pc_convertion_and_restore(env, pc, &tb);
    if (ret!=0) {
        fprintf(stderr, "restore cpu state failed!\n");
        assert(0);
    }
	// get the ram_addr corresponding to pc
    uint32_t arm_pc = env->regs[15];
    ret = get_phys_addr(env, arm_pc, 2, is_user, &pc_phys_addr, &prot, &pc_page_size);
    if (ret!=0) {
        fprintf(stderr, "arm_pc=0x%x obtain phys_addr failed!!!\n", arm_pc);
        assert(0);
    }
    spt_smc_invalid(env, tb, pc_phys_addr);
}
#ifdef PRIVATE_SPT
static int need_accelerate_count = 0;
static uint8_t last_asid = 0;
static void handle_map_too_much(uint8_t asid){
	PSPTInfo *curr_spt = private_spts + asid;
	if(curr_spt->map_count>3000){
		//fprintf(stderr, "ASID[%d], curr_spt= %d && sum=%d!\n", asid, curr_spt->map_count, total_map_count);
		if(last_asid!=asid){
			last_asid = asid;
			need_accelerate_count = 0;
		}else
			need_accelerate_count++;

		if(need_accelerate_count<=20)
			invalid_private_spt_on_asid(env, asid, NULL, NULL);
		else
			fprintf(stderr, "find spec!\n");
	}
}
#endif
RAMBlock *qemu_get_ram_block(uint32_t paddr, unsigned long *offset);
#ifdef FILL_SPT_AT_TIMESLOT_START
static void spt_set_entry(uint32_t guest_va, target_ulong page_size, int prot, uint32_t phys_addr, bool add_to_bitmap)
#elif defined(PRIVATE_SPT)
static void spt_set_entry(CPUARMState *env, uint32_t guest_va, target_ulong page_size, int prot, uint32_t phys_addr)
#else
static void spt_set_entry(uint32_t guest_va, target_ulong page_size, int prot, uint32_t phys_addr)
#endif
{   
	assert((page_size & (qemu_real_host_page_size-1)) == 0);
    guest_va &= qemu_host_page_mask;
    phys_addr &= qemu_host_page_mask;
#ifdef FILL_SPT_AT_TIMESLOT_START
#if 0 //delete by wz
	if(add_to_bitmap){
		spt_add_map(guest_va, page_size);
		SEGV_NUM++;
	}
	FILL_NUM++;
#else
	if(add_to_bitmap){//judge whether is staticly fill or not
		SEGV_NUM++;
		FILL_NUM++;
		//judge the num of current map entries
		if(SPT_bitmap->count >= FILL_SPT_WINDOW_SIZE)
			spt_clear_bitmap();
		else
			spt_add_map(guest_va, page_size);
	}else
		FILL_NUM++;
#endif
#endif

#ifdef PRIVATE_SPT
	uint8_t asid = get_current_asid(env);
	PSPTInfo *curr_spt = private_spts + asid;
	curr_spt->map_count++;
	total_map_count++;

	handle_map_too_much(asid);
	curr_spt->dirty = true;
	all_private_spts_cleared = false;
	// add the reverse map
	spt_add_reverse_map(asid, guest_va, page_size, prot, phys_addr);	
	// convert gva to host gva in SPT
	unsigned long spt_base = get_spt_base(asid);
	unsigned long real_gva = (unsigned long)spt_g2h(spt_base, guest_va);
#else
	spt_cleared = false;
	// add the reverse map
	spt_add_reverse_map(guest_va, page_size, prot, phys_addr);
	// convert gva to real host gva
	unsigned long real_gva = (unsigned long)spt_g2h(guest_va);
#endif
	
	// set SPT
    unsigned long offset = 0;
    RAMBlock *block = qemu_get_ram_block(phys_addr, &offset);
    if(block == NULL) {
        fprintf(stderr, "Can't find RAMBlock! va: 0x%lx, phys: 0x%x, prot: %d, page_size: 0x%x\n",
            real_gva, phys_addr, prot, page_size);
        assert(0);
    }
    /*check shm_fd */
    shm_file *shmf = block->shmf;
    if(shmf == NULL){
        /* when the program actually access va in runtime, this case shouldn't happen! assert(0)!*/
        fprintf(stderr, "set_entry: shm_file=NULL!!! va=0x%lx, phys=0x%x, prot=%d, page_size=0x%x\n",
                real_gva, phys_addr, prot, page_size);
        assert(0);
    }
    /*Ordernary ram access goes here~*/
    //fprintf(stderr, "\tset_entry: va: 0x%lx, host_gva: 0x%lx, prot: %d, page_size: 0x%x\n", guest_va, real_gva, prot, page_size);
	mmap_count ++;
	void *ret = mmap((void *)(real_gva), page_size, prot, MAP_SHARED|MAP_FIXED, shmf->fd, offset);
    if(ret == MAP_FAILED) {
        perror("spt_set_entry_in_sigsegv");
		fprintf(stderr, "\n\n[%lld]Map failed!! host_gva:0x%lx, gva:0x%x, prot:0x%x, shm_fd:%d, offset:0x%x\n\n",
			mmap_count,real_gva,guest_va, prot, shmf->fd, offset);
		assert(0);
		//int gathered_spt_count = gather_spt_space(asid);
		//assert(gathered_spt_count != 0);
		//ret = mmap((void *)(real_gva), page_size, prot, MAP_SHARED|MAP_FIXED, shmf->fd, offset);
    }
}


#ifdef FILL_SPT_AT_TIMESLOT_START
extern void spt_get_guest_pt_entry(CPUARMState *env, uint32_t address,
                          ram_addr_t *phys_ptr, int *prot, target_ulong *page_size);

static bool spt_set_entry_staticly(CPUARMState *env, int64_t start, int64_t end, bool set_bitmap) {
	bool set = false;
	assert((start & SPT_GUEST_MIN_PAGE_MASK) == 0);
	int64_t va = start;
	for( ; va < end; va+=SPT_GUEST_MIN_PAGESIZE) {
		if(va < 0 || va >= 0x100000000ull)
			continue;
		ram_addr_t phys_addr;
		int prot = 0;
		target_ulong page_size=0;
		spt_get_guest_pt_entry(env, (uint32_t)va, &phys_addr, &prot, &page_size);
		if((prot & PAGE_BITS) == 0){
			continue;
		}
		/*further limit the page_prot in case of IO or SMC,
		here we use the same interface with that used in tlb_set_page() */
		int flag = spt_further_limit_prot(env, (uint32_t)va, phys_addr, &prot, AC_WRITE);
		/* update spt according to the info we final got */
		if((prot & PAGE_BITS) == 0) {
			continue;
			fprintf(stderr, "Skip! Prot none after further limit!\n");
		}
		spt_set_entry(va, page_size, prot, phys_addr, set_bitmap);
		set = true;
	}
	return set;
}
bool spt_fill_entries_of_history_timeslot(CPUARMState *env, uint32_t segv_va) {
	// if the num of entries in bitmap has surpress N, we should no longer use all the history information
	//in the bitmap. Thus, we use these record this time, but without set it in the bitmap so that the record
	// before this time would be dropped.
	uint32_t hash_index = spt_bitmap_hash(env->cp15.c2_base0);
	SPT_bitmap = &(spt_bitmaps[hash_index]);
	uint32_t count = SPT_bitmap->count;
	bool this_segv_handled = false;
	
	//return this_segv_handled;
#if 0 // delete by wz
	if(count >= FILL_SPT_WINDOW_SIZE) {
		spt_clear_bitmap();
		return this_segv_handled;
	}
#endif
	// check whether this segv va is in the bitmap
	this_segv_handled = spt_bitmap_set(segv_va);
	int real_fill_count = 0;
	// update each page
	uint16_t start = SPT_bitmap->start_dword;
	uint16_t end = SPT_bitmap->end_dword;
	int i=start, found_count=0;
	for(;((i<end));i++){
		if(SPT_bitmap->bitmap[i] == 0)
			continue;
		uint64 dword = SPT_bitmap->bitmap[i];
		int j=0;
		for(;(j<64);j++){
			if((dword & (0x1ull<<j)) == 0)
				continue;
			uint32 va=(i*64+j)<<SPT_GUEST_MIN_PAGEBITS;
			//fprintf(stderr, "\t0x%x", va);
			found_count++;
			if(spt_set_entry_staticly(env,(int64_t)va, va+SPT_GUEST_MIN_PAGESIZE, false))
				real_fill_count++;
		}
	}
	return this_segv_handled;
}
#endif
static int spt_check_arm_mmu_fault(CPUARMState *env, uint32_t address, int access_type, uintptr_t pc, int* flag)
{
    uint32_t phys_addr;
    target_ulong page_size = 0;
    int prot = 0;

    //walk guest page_table
    int is_user = 1; //we've already checked that it is in user mode now;
    int ret = get_phys_addr(env, address, access_type, is_user, &phys_addr, &prot, &page_size);
    /*Set guest exception or update SPT*/
	// not guest exception
	if (ret == 0) {
        assert(page_size >= qemu_real_host_page_size);
        assert((prot & PAGE_BITS) != 0);
		
        //qemu_log("Before qma_further_limit_prot : prot=%d\n", prot);
        *flag = spt_further_limit_prot(env, address, phys_addr, &prot, access_type);

        if(*flag & PAGE_FLAG_MMIO) {
            fprintf(stderr, "SIGSEGV: IO!!! va=0x%x, phys=0x%x, prot=%d, page_size=0x%x, access_type: %d\n",
                            address, phys_addr, prot, page_size, access_type);
            fprintf(stderr, "This May be a watchpoint that we didn't handle now in SPT opt\n");
            // Since we only use SPT in user mode and IO should only occur in previledge_mode, so this shouldn't happen.
            assert(0);
        }
        else if(*flag & PAGE_FLAG_NOTDIRTY) {
            //assert(0);
            //fprintf(stderr, "[%lld/%lld]SMC!!! x86_pc: 0x%lx, mem: 0x%x, phys: 0x%x", smc_sigsegv_count, sigsegv_count, pc, address, phys_addr);
            spt_smc_handler(env, is_user, pc);
        }
        else {
            /* not mmio or SMC!! then update spt according to the info we final got */
			if((prot & PAGE_BITS) == 0) {
				fprintf(stderr, "SIGSEGV! Not guest except, Not IO, Not dirty!!\n");
				assert(0);
			}
			// update SPT in different ways
#ifdef FILL_SPT_AT_TIMESLOT_START
			bool this_segv_handled = false;
			if(spt_cleared) {
				//fprintf(stderr, "First SEGV after spt_invalid, fill all entries of last timeslot!\n");
				this_segv_handled = spt_fill_entries_of_history_timeslot(env, address&qemu_host_page_mask);
			}
			//fprintf(stderr, "\tsegv fill! va: 0x%x, prot: 0x%x, acc_type: 0x%x, phys: 0x%x\n", address, prot, access_type, phys_addr);
			if(!this_segv_handled)
				spt_set_entry(address, page_size, prot, phys_addr, true);
#elif defined(PRIVATE_SPT)
			if(get_current_asid(env)== 0){
				fprintf(stderr, "\nSEGV on ASID = 0!!!\n");
			}
			spt_set_entry(env, address, page_size, prot, phys_addr);
#else // shared spt
			spt_set_entry(address, page_size, prot, phys_addr);
#endif
        }
    }
    else {
        if (access_type == 2) {
            env->cp15.c5_insn = ret;
            env->cp15.c6_insn = address;
            env->exception_index = EXCP_PREFETCH_ABORT;
        } else {
            env->cp15.c5_data = ret;
            if (access_type == 1 && arm_feature(env, ARM_FEATURE_V6))
                env->cp15.c5_data |= (1 << 11);
            env->cp15.c6_data = address;
            env->exception_index = EXCP_DATA_ABORT;
        }
    }
    /*return*/
    return ret;
}
extern void raise_exception(int tt);
static inline void spt_sigsegv_handler_internal(unsigned long pc, 
                        void *address, int access_type, sigset_t *old_set, void *puc)
{
    //see if it is an guest MMU fault 
       int flag;
	CPUState *saved_env;
	saved_env = env;
	env = cpu_single_env; // this code copied from tlb_fill

    	int ret = spt_check_arm_mmu_fault(env, (uint32_t)((uint64_t)address), access_type, pc, &flag);
	sigsegv_count++;
	if (unlikely(ret)) {
       assert(pc);
       TranslationBlock *tb = tb_find_pc(pc);
       assert(tb!=NULL);
       cpu_restore_state(tb, env, pc);
       // we restore the process signal mask as the sigreturn should do it (XXX: use sigsetjmp) 
       sigprocmask(SIG_SETMASK, old_set, NULL);
       raise_exception(env->exception_index);
    }
	// handle SMC, jmp to execute the newest native code
    if (flag & PAGE_FLAG_NOTDIRTY) {
        //qemu_log("SMC:arm_pc=0x%x, address=%p\n",cpu_single_env->regs[15], address);
        sigprocmask(SIG_SETMASK, old_set, NULL);
        cpu_resume_from_signal(env, NULL);
    } 
	env = saved_env;
    // never comes here 
    return;
}

static const char *print_si_codes[3] = {"", "SEGV_MAPERR", "SEGV_ACCERR"};
static const char *print_access_type[3] = {"read", "write", "execute"};
extern bool in_native_code(unsigned long pc);
void spt_sigsegv_handler(int host_signum, siginfo_t *info, void *puc)
{
    if (host_signum != SIGSEGV  || info->si_code <= 0) {
        fprintf(stderr, "\nQEMU got signal %s, si_code = %d. We did not handle it!\n", signal_name[host_signum], info->si_code);
        return;
    }
	//fprintf(stderr, "\n\nSIGSEGV happened!\n");
	
    //handle SIGSEGV
#if defined(__NetBSD__) || defined(__FreeBSD__) || defined(__DragonFly__)
    ucontext_t *uc = puc;
#elif defined(__OpenBSD__)
    struct sigcontext *uc = puc;
#else
    struct ucontext *uc = puc;
#endif
    // 1. get access_type
    int access_type;// access_type: 0 for read, 1 for write, 2 for execute
    if (TRAP_sig(uc) != 0xe) {
        fprintf(stderr, "\nQEMU receive SIGSEGV, trap_no=0x%x(we expect value=0xe)\n", (int)TRAP_sig(uc));
        return;
    }
    else{
        /* copy from Linux/arch/x86/mm/fault.c
         20  * Page fault error code bits:
         21  *
         22  *   bit 0 ==    0: no page found       1: protection fault
         23  *   bit 1 ==    0: read access         1: write access
         24  *   bit 2 ==    0: kernel-mode access  1: user-mode access
         25  *   bit 3 ==                           1: use of reserved bit detected
         26  *   bit 4 ==                           1: fault was an instruction fetch
         27  
         28 enum x86_pf_error_code {
         29 
         30         PF_PROT         =               1 << 0,
         31         PF_WRITE        =               1 << 1,
         32         PF_USER         =               1 << 2,
         33         PF_RSVD         =               1 << 3,
         34         PF_INSTR        =               1 << 4,
         35 };
         36 */
        enum host_pf_error_code {
            PF_PROT = 1<<0,
            PF_WRITE = 1<<1,
            PF_USER = 1<<2,
            PF_RSVD = 1<<3,
            PF_INSTR = 1<<4,
        };
        int error_code = ERROR_sig(uc);
        assert(error_code & PF_USER);// QEMU runs in host user mode
        if(error_code & PF_INSTR) {
            access_type = AC_EXEC;
        }   
        else if(error_code & PF_WRITE) {
            access_type = AC_WRITE;
        }
        else{ 
            access_type = AC_READ;
        }
    }

    // 2. Check SIGSEGV PC. 
    long long address = (long long)(info->si_addr);
    unsigned long pc = PC_sig(uc);
    if(!in_native_code(pc)) {
        fprintf(stderr, "\nSIGSEGV outside CODE CACHE!! pc: 0x%lx, access_type: 0x%d, mem_address: 0x%lx!\n",(uint64_t)pc,access_type, (uint64_t)address);
		assert(0);
		return;
    }
    else {
		;
    	//fprintf(stderr, "\t\t\tSIGSEGV x86_pc: 0x%lx, mem_address:0x%lx!!!!!\n", (uint64_t)pc, (uint64_t)address);
    }

    //CPUState *saved_env = env;
    //env = cpu_single_env;
    // 3. Make sure that this SIGSEGV occurred in user mode
    int is_user;
    if (arm_feature(cpu_single_env, ARM_FEATURE_M)) {
        is_user = (cpu_single_env->v7m.exception == 0) && (cpu_single_env->v7m.control & 1);
    } else {
        is_user = ((cpu_single_env->uncached_cpsr & CPSR_M) == ARM_CPU_MODE_USR);
    }
    //Currently we only use spt at user mode. Maybe we will use it at systerm mode in the future 
    if(!is_user) {
        fprintf(stderr, "OOPS!!! SIGSEGV in system mode!!,x86_pc: 0x%lx, mem_address:0x%lx!!!!!\n", (uint64_t)pc, (uint64_t)address);
		fprintf(stderr, "uncached_cpsr: %d, exception: %d, control: %d\n",cpu_single_env->uncached_cpsr,cpu_single_env->v7m.exception,cpu_single_env->v7m.control);
		assert(0);
        return;
    }
    
    // 4. Check SIGSEGV mem_addr
#ifdef PRIVATE_SPT
	uint8_t asid = get_current_asid(cpu_single_env);

	if(asid == 0)
		assert(0);

	unsigned long guest_base = get_spt_base(asid);
	unsigned long gs_value = spt_get_base_seg();
	if(gs_value != guest_base){
		fprintf(stderr, "GS: 0x%lx, guest_base: 0x%lx, asid: %d, address: 0x%llx\n",
			gs_value, guest_base, asid, address);
		assert(0);
	}

	int IsGuestMemorySpace = spt_h2g_valid(guest_base, address);
	if (IsGuestMemorySpace) {
		unsigned long guest_va = spt_h2g(guest_base, address);
        spt_sigsegv_handler_internal(pc, guest_va, access_type, &MASK_sig(uc), puc);
	}
    else {
        fprintf(stderr, "\n!!!SIGSEGV outside guest_memory_space!asid=%d pc=0x%lx can't %s memory addr=0x%llx!, base: 0x%llx\n", asid,pc, print_access_type[access_type], address, guest_base);
		assert(0);
	}		
#else
	int IsGuestMemorySpace = spt_h2g_valid(address);
	if (IsGuestMemorySpace){
		unsigned long guest_va = spt_h2g(address);
        spt_sigsegv_handler_internal(pc, guest_va, access_type, &MASK_sig(uc), puc);
	}
	else {
        fprintf(stderr, "\n!!!SIGSEGV outside guest_memory_space! pc=0x%lx can't %s memory addr=0x%llx!\n", pc, print_access_type[access_type], address);
    }
#endif
    
    //env = saved_env;
    return;
}

//#ifdef _APP_DEFINE_GNU
//#undef __USE_GNU
//#endif
