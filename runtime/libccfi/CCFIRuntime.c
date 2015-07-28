
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>
#include <sys/syscall.h>
#include <unistd.h>
#include <err.h>

#include <sys/mman.h>

// #define DEBUG_CHECKPTR 1

#define CCFI_HASHTBL_BASE	0x6000000000
#define CCFI_HASHTBL_SIZE	(32ULL * 0x10000000ULL)

static bool __ccfi_ready = false;

struct hash_list {
	uint64_t	 slot[4];
	uint64_t	 addr;
	struct hash_list *next;
};

__attribute__((constructor))
void __ccfi_init(void)
{
    if (syscall(SYS_msync, (void*)CCFI_HASHTBL_BASE, 4096, 0) != -1) {
        __ccfi_ready = true;
        return;
    }

    void *rc = mmap((void*)CCFI_HASHTBL_BASE, CCFI_HASHTBL_SIZE,
         PROT_READ | PROT_WRITE,
         MAP_PRIVATE | MAP_ANON | MAP_FIXED,
         -1,
         0);

    if (rc == MAP_FAILED || rc != (void*)CCFI_HASHTBL_BASE)
	err(1, "death\n");
}

static void*
check_collision(uint64_t addr, uint64_t hashSlot)
{
    struct hash_list **hl = (struct hash_list**) hashSlot;
    struct hash_list *h = *hl;

    while (h) {
	if (h->addr == addr)
		return h->slot;

        printf("COLLISION %lx %lx\n", addr, h->addr);

	hl = &h->next;
	h  = h->next;
    }

    assert(!*hl);

    h = *hl = malloc(sizeof(*h));
    assert(h);

    memset(h, 0, sizeof(*h));
    h->addr = addr;

    return h->slot;
}

static void *
ccfi_hash(uint64_t addr)
{
    uint64_t hashSlot;

    hashSlot = addr ^ (addr >> 32);
    hashSlot = hashSlot * (hashSlot + 3);
    hashSlot = hashSlot & 0x0FFFFFFF;
    hashSlot = hashSlot << 5;
    hashSlot = hashSlot + 0x0000006000000000;

#ifdef DEBUG_CHECKPTR
    return check_collision(addr, hashSlot);
#endif

    return (void*) hashSlot;
}

static void
ccfi_mac(uint64_t *out, uint64_t fp, uint64_t addr)
{
	*out++ = fp + 1;
	*out++ = addr + 1;
}

uint64_t
__ccfi_debug_checkptr(uint64_t fp, uint64_t addr)
{
    uint64_t *slot = ccfi_hash(addr);
    uint64_t mac[2];

//  printf("checking %lx %lx\n", fp, addr);

    ccfi_mac(mac, fp, addr);

    if (memcmp(mac, slot, sizeof(mac)) != 0)
    	return 0;

    return 1;
}

uint64_t
__ccfi_debug_macptr(uint64_t fp, uint64_t addr)
{
    uint64_t *slot = ccfi_hash(addr);

//  printf("macptr %lx %lx\n", fp, addr);

    ccfi_mac(slot, fp, addr);
    slot += 2;

    *slot++ = fp;
    *slot++ = addr;

    return 0;
}

void
__ccfi_addmac_global(void *memaddr)
{
    void *fp = (void*)(*((uint64_t*)memaddr));

    if (!__ccfi_ready)
        __ccfi_init();

#ifdef DEBUG_CHECKPTR
    __ccfi_debug_macptr((uint64_t) fp, (uint64_t) memaddr);
    return;
#endif    

    __builtin_ccfi_macptr((uint64_t)fp, (uint64_t)memaddr);
}

void
__ccfi_failure(uint64_t func, uint64_t addr)
{
    uint64_t *hash;

    printf("CCFI runtime pointer failure!\n");
    printf("Function %016lx stored at %016lx\n", func, addr);

    hash = ccfi_hash(addr);

    printf("Found:\n");
    printf("Hash Slot: %016lx\n", (uint64_t) hash);
    printf("Hash Found: %08lx%08lx\n", hash[0], hash[1]); 
    printf("Function %016lx stored at %016lx\n", hash[2], hash[3]);

    if (addr != hash[3]) {
	printf("Possible hash collision!\n");
    }

    abort();
}

void
__ccfi_memcpy(void *dst, void *src, size_t sz)
{
    unsigned char *s = src;
    unsigned char *d = dst;
    size_t i;

    for (i = 0; i < sz; i++) {
            unsigned long addr = (unsigned long) (s + i);
            uint64_t *hash = ccfi_hash(addr);

	    if (*hash == 0)
		continue;

//	    printf("Found FP at %p [i = %lu]\n", (s + i), i);

            __ccfi_addmac_global(d + i);
    }
}
