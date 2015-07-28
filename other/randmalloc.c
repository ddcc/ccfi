#include <stdlib.h>
#include <dlfcn.h>
#include <string.h>

static void *(*_malloc_cb)(size_t);
static void (*_free_cb)(void *ptr);
static void *(*_calloc_cb)(size_t number, size_t size);
static void *(*_realloc_cb)(void *ptr, size_t size);

static void malloc_init(void) __attribute__ ((constructor));

static void malloc_init(void)
{
	_malloc_cb  = dlsym(RTLD_NEXT, "malloc");
	_free_cb    = dlsym(RTLD_NEXT, "free");
	_calloc_cb  = dlsym(RTLD_NEXT, "calloc");
	_realloc_cb = dlsym(RTLD_NEXT, "realloc");
}

static __inline__ unsigned long long rdtsc(void)
{
  unsigned hi, lo;
  __asm__ __volatile__ ("rdtsc" : "=a"(lo), "=d"(hi));
  return ( (unsigned long long)lo)|( ((unsigned long long)hi)<<32 );
}

static inline unsigned long rnd(void)
{
	unsigned long r = (rdtsc() & 0xf0) >> 4;

	if (r == 0)
		r++;

	r *= 0x100;

	return r;
}

static inline void *malloc_to_off(void *p, unsigned long r)
{
	unsigned long *off;

	if (!p)
		return p;

	off = (unsigned long*) ((unsigned long) p + r - sizeof(*off));
	*off++ = r;

	return off;
}

static inline void *off_to_malloc(void *p)
{
	unsigned long *off;

	if (!p)
		return p;

	off = (unsigned long*) ((unsigned long) p - sizeof(*off));

	return (void*) ((unsigned long) p - *off);
}

void *malloc(size_t size)
{
	unsigned long *off;
	unsigned long r = rnd();

	size += r + sizeof(*off);

	off = _malloc_cb(size);

	return malloc_to_off(off, r);
}

void free(void *ptr)
{
	ptr = off_to_malloc(ptr);
	
	_free_cb(ptr);
}

void *calloc(size_t number, size_t size)
{
	unsigned long *off;
	unsigned long r = rnd();
	unsigned long need = r + sizeof(*off);

	number += need / size;
	number++;

	off = _calloc_cb(number, size);
	
	return malloc_to_off(off, r);
}

void *realloc(void *ptr, size_t size)
{
	void *n = malloc(size);
	if (!n)
		return n;

	if (!ptr)
		return n;

	memmove(n, ptr, size);

	return n;
}
