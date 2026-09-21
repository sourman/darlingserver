#include <darlingserver/duct-tape/stubs.h>
#include <darlingserver/duct-tape/memory.h>
#include <darlingserver/duct-tape/task.h>
#include <darlingserver/duct-tape/hooks.internal.h>
#include <darlingserver/duct-tape/thread.h>
#include <darlingserver/duct-tape/log.h>
#include <darlingserver/duct-tape/locks.h>

#include <kern/zalloc.h>
#include <kern/kalloc.h>
#include <kern/ipc_kobject.h>
#include <vm/vm_kern.h>
#include <vm/vm_map.h>
#include <mach/memory_object_types.h>

#include <stdlib.h>
#include <string.h>

#include <mach_debug/mach_debug.h>

struct zone {
	const char* name;
	vm_size_t size;
};

// stub
struct kalloc_heap KHEAP_DEFAULT[1];
// stub
struct kalloc_heap KHEAP_DATA_BUFFERS[1];

// Empty PHYSICAL_COPY OOL (IOServiceOpen propertiesCnt=0) must not take the
// "large physical copy" path. XNU sets this from the kalloc heap; a zero
// value makes MSG_OOL_SIZE_SMALL=0, so size 0 is treated as a large copy and
// the wrap check `space_needed + round_page(0) <= space_needed` returns
// MACH_MSG_VM_KERNEL (0x400). Match MSG_OOL_SIZE_SMALL_MAX (2*PAGE_SIZE).
vm_size_t kalloc_max_prerounded = 8192;

void* calloc(size_t count, size_t size);
void* aligned_alloc(size_t alignment, size_t size);

void* mmap(void* addr, size_t length, int prot, int flags, int fd, long int offset);
long pread(int fd, void* buf, unsigned long count, long offset);
long pwrite(int fd, const void* buf, unsigned long count, long offset);
int munmap(void* addr, size_t length);
long sysconf(int name);

int memfd_create(const char *name, unsigned int flags);
void dtape_rls_wp_arm(uint32_t nsid, int memfd, uintptr_t addr);
void dtape_rls_wp_drain(void);
extern int dtape_host_cmdline_is_network(unsigned nsid);
__attribute__((used)) static const char dtape_rls_fe_wp_network_only_v1[] =
	"rls_fe_wp_v1 network-only";
__attribute__((used)) static const char dtape_rls_fe_wp_disabled_v1[] =
	"rls_fe_wp_v1 disabled";

int close(int fd);
int ftruncate(int fd, off_t length);
int memcmp(const void* s1, const void* s2, unsigned long n);
void dtape_task_release(dtape_task_t* task);
uint64_t mach_absolute_time(void);
void absolutetime_to_nanoseconds(uint64_t abstime, uint64_t* result);

#define MAP_ANONYMOUS 0x20
#define MAP_SHARED 0x01
#define MAP_PRIVATE 0x02
#define MAP_FIXED 0x10
#define MAP_FIXED_NOREPLACE 0x100000
#define MAP_POPULATE 0x8000

#define PROT_READ 0x1
#define PROT_WRITE 0x2
#define PROT_EXEC 0x4

#define MAP_FAILED ((void*)-1)

#define _SC_PAGESIZE 30

#define MFD_CLOEXEC 0x1

void dtape_memory_init(void) {

};

static uint64_t dtape_byte_count_to_page_count_round_up(uint64_t byte_count) {
	return (byte_count + (sysconf(_SC_PAGESIZE) - 1)) / sysconf(_SC_PAGESIZE);
};

static uint64_t dtape_byte_count_to_page_count_round_down(uint64_t byte_count) {
	return byte_count / sysconf(_SC_PAGESIZE);
};

static int dtape_map_shared_entry_compare(dtape_map_shared_entry_t* first, dtape_map_shared_entry_t* second) {
	if (first->address < second->address) {
		return -1;
	} else if (first->address > second->address) {
		return 1;
	} else {
		return 0;
	}
};

RB_PROTOTYPE_SC(static, dtape_map_shared_entry_head, dtape_map_shared_entry, link, dtape_map_shared_entry_compare);
RB_GENERATE(dtape_map_shared_entry_head, dtape_map_shared_entry, link, dtape_map_shared_entry_compare);

vm_map_t dtape_vm_map_create(struct dtape_task* task) {
	vm_map_t map = malloc(sizeof(struct _vm_map));
	if (!map) {
		return map;
	}

	os_ref_init(&map->map_refcnt, NULL);

	map->max_offset = MACH_VM_MAX_ADDRESS;
	map->dtape_page_shift = __builtin_ctzl(sysconf(_SC_PAGESIZE));

	map->dtape_task = task;

	RB_INIT(&map->shared_entries);
	dtape_mutex_init(&map->shared_entry_lock);

	return map;
};

static dtape_map_shared_descriptor_t* dtape_map_shared_descriptor_create(int memfd, uint64_t size) {
	dtape_map_shared_descriptor_t* desc = malloc(sizeof(dtape_map_shared_descriptor_t));
	if (!desc) {
		return NULL;
	}

	os_ref_init(&desc->refcount, NULL);

	desc->memfd = memfd;
	desc->size = size;

	return desc;
};

static void dtape_map_shared_descriptor_retain(dtape_map_shared_descriptor_t* desc) {
	os_ref_retain(&desc->refcount);
};

static void dtape_map_shared_descriptor_release(dtape_map_shared_descriptor_t* desc) {
	if (os_ref_release(&desc->refcount) != 0) {
		return;
	}

	close(desc->memfd);
	free(desc);
};

static dtape_map_shared_entry_t* dtape_map_shared_entry_create(uint64_t address, uint64_t size, uint64_t page_offset, dtape_map_shared_descriptor_t* descriptor) {
	dtape_map_shared_entry_t* shared_entry = malloc(sizeof(dtape_map_shared_entry_t));
	if (!shared_entry) {
		return NULL;
	}

	shared_entry->address = address;
	shared_entry->size = size;
	shared_entry->page_offset = page_offset;
	shared_entry->descriptor = descriptor;
	shared_entry->map_refs = 1;

	dtape_map_shared_descriptor_retain(descriptor);

	return shared_entry;
};

static void dtape_map_shared_entry_destroy(dtape_map_shared_entry_t* shared_entry) {
	dtape_map_shared_descriptor_release(shared_entry->descriptor);
	free(shared_entry);
};

static void dtape_map_insert_shared_entry_locked(dtape_map_t* map, dtape_map_shared_entry_t* shared_entry, int overwrite) {
	dtape_map_shared_entry_t* old;
	int same_fd;

	old = RB_FIND(dtape_map_shared_entry_head, &map->shared_entries, shared_entry);
	if (old != NULL && old != shared_entry) {
		same_fd = (old->descriptor && shared_entry->descriptor &&
		    old->descriptor->memfd == shared_entry->descriptor->memfd);
		/*
		 * ANYWHERE must not steal a VA the child already mapped as
		 * buffer0. Same-memfd remaps are the same physical pages.
		 * A 4k punch of NodeLinkMemory used to replace the 128k
		 * tracking entry, so later CAS on next_sublink_id @+8 and
		 * the 0x400 free-list missed the live object.
		 * Different-memfd at the same VA: the live mapping already
		 * replaced the pages. Keep only a larger same-fd object, or
		 * a 128k NodeLink when a 4k named-entry tries to punch it.
		 */
		if (!overwrite && same_fd && old->size >= shared_entry->size) {
			if (old->size >= 131072) {
				old->map_refs++;
			}
			dtape_log_error("shared_entry_keep_v1 addr=0x%lx keep_memfd=%d keep_sz=%llu skip_memfd=%d skip_sz=%llu refs=%u",
			    (unsigned long)shared_entry->address,
			    old->descriptor ? old->descriptor->memfd : -1,
			    (unsigned long long)old->size,
			    shared_entry->descriptor ? shared_entry->descriptor->memfd : -1,
			    (unsigned long long)shared_entry->size,
			    old->map_refs);
			dtape_map_shared_entry_destroy(shared_entry);
			return;
		}
		if (!overwrite && !same_fd && old->size >= 131072 &&
		    shared_entry->size < 131072) {
			dtape_log_error("shared_entry_keep_v1 addr=0x%lx keep_memfd=%d keep_sz=%llu skip_memfd=%d skip_sz=%llu refs=%u",
			    (unsigned long)shared_entry->address,
			    old->descriptor ? old->descriptor->memfd : -1,
			    (unsigned long long)old->size,
			    shared_entry->descriptor ? shared_entry->descriptor->memfd : -1,
			    (unsigned long long)shared_entry->size,
			    old->map_refs);
			dtape_map_shared_entry_destroy(shared_entry);
			return;
		}
		dtape_log_error("shared_entry_replace_v1 addr=0x%lx old_memfd=%d old_sz=%llu new_memfd=%d new_sz=%llu",
		    (unsigned long)shared_entry->address,
		    old->descriptor ? old->descriptor->memfd : -1,
		    (unsigned long long)old->size,
		    shared_entry->descriptor ? shared_entry->descriptor->memfd : -1,
		    (unsigned long long)shared_entry->size);
		RB_REMOVE(dtape_map_shared_entry_head, &map->shared_entries, old);
		dtape_map_shared_entry_destroy(old);
	}
	RB_INSERT(dtape_map_shared_entry_head, &map->shared_entries, shared_entry);
};

static void dtape_map_insert_shared_entry(dtape_map_t* map, dtape_map_shared_entry_t* shared_entry, int overwrite) {
	dtape_mutex_lock(&map->shared_entry_lock);
	dtape_map_insert_shared_entry_locked(map, shared_entry, overwrite);
	dtape_mutex_unlock(&map->shared_entry_lock);
};

static uint64_t dtape_page_size(void) {
	long page_size = sysconf(_SC_PAGESIZE);
	if (page_size <= 0) {
		return 4096;
	}
	return (uint64_t)page_size;
};

static uint64_t dtape_round_page(uint64_t size) {
	uint64_t page_size = dtape_page_size();
	return (size + page_size - 1) & ~(page_size - 1);
};

static kern_return_t dtape_task_unmap_bytes(vm_map_t map, uintptr_t addr, uint64_t size) {
	if (size == 0) {
		return KERN_SUCCESS;
	}

	if (map == kernel_map) {
		if (munmap((void*)addr, (size_t)size) < 0) {
			return KERN_FAILURE;
		}
		return KERN_SUCCESS;
	}

	if (dtape_hooks->task_free_pages(map->dtape_task->context, addr, dtape_byte_count_to_page_count_round_down(size)) < 0) {
		return KERN_FAILURE;
	}
	return KERN_SUCCESS;
};

static uintptr_t dtape_task_map_memfd(vm_map_t map, int memfd, uint64_t size, int prot, uintptr_t hint, uint64_t byte_offset, dtape_memory_flags_t memflags) {
	size_t page_count;
	size_t page_offset;

	if (size == 0) {
		return 0;
	}

	page_count = dtape_byte_count_to_page_count_round_up(size);
	page_offset = dtape_byte_count_to_page_count_round_down(byte_offset);

	if (map == kernel_map) {
		int linux_flags = MAP_SHARED;
		void* mapped;

		if ((memflags & dtape_memory_flag_fixed) && (memflags & dtape_memory_flag_overwrite)) {
			linux_flags |= MAP_FIXED;
		} else if (memflags & dtape_memory_flag_fixed) {
			linux_flags |= MAP_FIXED_NOREPLACE;
		}

		mapped = mmap((void*)hint, (size_t)size, prot, linux_flags, memfd, (long int)byte_offset);
		if (mapped == MAP_FAILED) {
			return 0;
		}
		return (uintptr_t)mapped;
	}

	return dtape_hooks->task_map_file(map->dtape_task->context, memfd, page_count, prot, hint, page_offset, memflags);
};

static uintptr_t dtape_task_reserve_anonymous(vm_map_t map, uint64_t size, int prot, uintptr_t hint) {
	if (map == kernel_map) {
		void* mapped = mmap((void*)hint, (size_t)size, prot, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
		if (mapped == MAP_FAILED) {
			return 0;
		}
		return (uintptr_t)mapped;
	}

	return dtape_hooks->task_allocate_pages(map->dtape_task->context, dtape_byte_count_to_page_count_round_up(size), prot, hint, dtape_memory_flag_none);
};

static size_t dtape_map_find_shared_entries_locked(dtape_map_t* map, uint64_t address, uint64_t size, dtape_map_shared_entry_t** out_entries, size_t entry_count);

/*
 * Pick a free VA without an S2C mmap. A reserve-then-MAP_FIXED sequence
 * sent a second S2C mmap with an FD and the guest aborted ("no FD, but
 * expected one"), which panics dserver in _s2cPerform. Walk /proc maps
 * plus shared_entries instead, then one MAP_FIXED_NOREPLACE of the memfd.
 */
static uintptr_t dtape_map_find_free_va(vm_map_t map, uint64_t size, uintptr_t hint) {
	uintptr_t cursor;
	uintptr_t next;
	dtape_memory_region_info_t info;
	uint64_t page;
	uint32_t nsid = 0;
	int try;

	if (map == VM_MAP_NULL || map == kernel_map || map->dtape_task == NULL) {
		return 0;
	}

	nsid = map->dtape_task->saved_pid;
	page = dtape_page_size();
	cursor = hint;
	if (cursor < 0x100000000UL) {
		cursor = 0x7f0000000000UL;
	}

	for (try = 0; try < 1024; try++) {
		dtape_map_shared_entry_t* hits[8];
		size_t n;
		unsigned char probe[16];
		uintptr_t skip;

		cursor = (cursor + page - 1) & ~(page - 1);

		dtape_mutex_lock(&map->shared_entry_lock);
		n = dtape_map_find_shared_entries_locked(map, cursor, size, hits, 8);
		dtape_mutex_unlock(&map->shared_entry_lock);
		if (n != 0) {
			cursor = hits[0]->address + hits[0]->size;
			continue;
		}

		if (dtape_hooks->task_get_memory_region_info(map->dtape_task->context, cursor, &info)) {
			cursor = info.start_address + info.page_count * page;
			continue;
		}

		next = dtape_hooks->task_get_next_region(map->dtape_task->context, cursor);
		if (next != 0 && next < cursor + size) {
			cursor = next;
			continue;
		}

		/*
		 * /proc maps miss Darling S2C memfd maps. keep_va left those
		 * pages live; MAP_FIXED_NOREPLACE onto them made the guest
		 * abort S2C mmap (no FD) and paniced dserver in _s2cPerform.
		 * process_vm_readv sees readable pins. PROT_NONE cages do not
		 * read; jump to the next /proc VMA instead of +128KiB (that
		 * exhausted 256 tries inside a 16GiB cage → KERN_NO_SPACE).
		 * Do not MAP_POPULATE / 4K-pin.
		 */
		if (dtape_hooks->task_read_memory &&
		    dtape_hooks->task_read_memory(map->dtape_task->context, cursor, probe, sizeof(probe))) {
			skip = (size > (2ULL * 1024ULL * 1024ULL)) ? (uintptr_t)size : (uintptr_t)(2ULL * 1024ULL * 1024ULL);
			if (next > cursor && next - cursor > skip)
				skip = next - cursor;
			dtape_log_error("s2c_mmap_liveva_v2 nsid=%u skip_live=0x%lx size=%llu skip=0x%lx",
			    nsid, (unsigned long)cursor, (unsigned long long)size, (unsigned long)skip);
			cursor += skip;
			continue;
		}

		dtape_log_error("vm_map_named_anywhere_noreplace_v2 nsid=%u reserve=0x%lx size=%llu try=%d",
		    nsid, (unsigned long)cursor, (unsigned long long)size, try);
		return cursor;
	}

	dtape_log_error("vm_map_named_anywhere_noreplace_v2 nsid=%u size=%llu -> no hole",
	    nsid, (unsigned long long)size);
	return 0;
};

__attribute__((used)) static const char dtape_named_entry_reuse_va_v1[] = "named_entry_reuse_va_v1";

static int dtape_named_entry_va_live(vm_map_t map, dtape_map_shared_entry_t* entry, uint64_t need_size, int need_prot) {
	unsigned char probe[16];
	uintptr_t off;

	(void)need_prot;
	if (map == VM_MAP_NULL || map == kernel_map || map->dtape_task == NULL || map->dtape_task->context == NULL) {
		return 0;
	}
	if (need_size < sizeof(probe) || dtape_hooks->task_read_memory == NULL) {
		return 0;
	}
	/*
	 * /proc/<pid>/maps misses Darling S2C memfd maps at 0x7f0000000000,
	 * so task_get_memory_region_info reports hollow while process_vm_readv
	 * still succeeds. Probe the guest VA; that is what AdoptFragment uses.
	 */
	if (!dtape_hooks->task_read_memory(map->dtape_task->context, (uintptr_t)entry->address, probe, sizeof(probe))) {
		return 0;
	}
	off = (uintptr_t)entry->address + (uintptr_t)need_size - sizeof(probe);
	if (!dtape_hooks->task_read_memory(map->dtape_task->context, off, probe, sizeof(probe))) {
		return 0;
	}
	return 1;
};

/*
 * Chrome Map()s the same NodeLinkMemory named entry twice. The first
 * mach_vm_map returns 0x7f0000001000; a second ANYWHERE map used to
 * land at +size and the first Mapping destructor munmapped it. ipcz
 * AdoptFragment at 0x4c0 then read a hollow VA. Reuse the live mapping
 * and pin it with map_refs so deallocate of the alias is a no-op.
 */
static int dtape_map_reuse_named_locked(vm_map_t map, int memfd, uint64_t size, uint64_t page_offset, int prot, uintptr_t* out_addr) {
	dtape_map_shared_entry_t* entry;
	uint32_t nsid = 0;

	(void)dtape_named_entry_reuse_va_v1;

	if (map == VM_MAP_NULL || map == kernel_map) {
		return 0;
	}
	if (map->dtape_task) {
		nsid = map->dtape_task->saved_pid;
	}
	if (size < 131072) {
		return 0;
	}

	RB_FOREACH(entry, dtape_map_shared_entry_head, &map->shared_entries) {
		if (entry->descriptor == NULL || entry->descriptor->memfd != memfd) {
			continue;
		}
		if (entry->page_offset != page_offset || entry->size < size) {
			continue;
		}
		if (!dtape_named_entry_va_live(map, entry, size, prot)) {
			/*
			 * Leave the tracking row so find_free_va skips this
			 * hole. drop_hollow used to untrack then remap the
			 * same VA; Chrome's first Mapping destructor then
			 * munmapped the live alias (no 992×722 window).
			 */
			dtape_log_error("named_entry_reuse_va_v1 nsid=%u memfd=%d skip_hollow addr=0x%lx size=%llu",
			    nsid, memfd, (unsigned long)entry->address,
			    (unsigned long long)entry->size);
			continue;
		}
		entry->map_refs++;
		*out_addr = (uintptr_t)entry->address;
		dtape_log_error("named_entry_reuse_va_v1 nsid=%u memfd=%d addr=0x%lx size=%llu refs=%u",
		    nsid, memfd, (unsigned long)entry->address,
		    (unsigned long long)entry->size, entry->map_refs);
		return 1;
	}
	return 0;
};

/*
 * Map a named-entry memfd like XNU: ANYWHERE claims a free hole (never
 * Linux MAP_FIXED onto a live mapping), then copy the trap's over-map/trim
 * for mask alignment without shifting the memfd page offset.
 */
static kern_return_t dtape_map_memfd_aligned(vm_map_t map, int memfd, uint64_t size, int prot, uintptr_t hint, uint64_t byte_offset, mach_vm_offset_t mask, dtape_memory_flags_t memflags, uintptr_t* out_addr) {
	uintptr_t addr;
	uintptr_t iaddr;
	uintptr_t boundary;
	uintptr_t q;
	uintptr_t next_hint;

	if (!(memflags & dtape_memory_flag_fixed)) {
		uint64_t reserve_size = size;
		int try;

		if (mask != 0) {
			reserve_size = size + (uint64_t)mask + 1;
		}

		next_hint = hint;
		for (try = 0; try < 32; try++) {
			iaddr = dtape_map_find_free_va(map, reserve_size, next_hint);
			if (!iaddr) {
				return KERN_NO_SPACE;
			}

			if (mask != 0 && (iaddr & mask) != 0) {
				boundary = (uintptr_t)mask + 1;
				q = (iaddr + (boundary - 1)) / boundary * boundary;
				if (q + size > iaddr + reserve_size) {
					next_hint = iaddr + reserve_size;
					continue;
				}
				iaddr = q;
			}

			addr = dtape_task_map_memfd(map, memfd, size, prot, iaddr, byte_offset,
			    dtape_memory_flag_fixed);
			if (addr == iaddr) {
				*out_addr = addr;
				return KERN_SUCCESS;
			}
			if (addr) {
				dtape_task_unmap_bytes(map, addr, size);
			}
			/* MAP_FIXED_NOREPLACE missed a PROT_NONE / S2C hole.
			 * Advance at least 2MiB so we do not retry the same VA. */
			next_hint = iaddr + reserve_size;
			if (reserve_size < (2ULL * 1024ULL * 1024ULL))
				next_hint = iaddr + (2ULL * 1024ULL * 1024ULL);
		}
		return KERN_NO_SPACE;
	}

	addr = dtape_task_map_memfd(map, memfd, size, prot, hint, byte_offset, memflags);
	if (!addr) {
		return KERN_NO_SPACE;
	}

	*out_addr = addr;
	return KERN_SUCCESS;
};

static kern_return_t dtape_named_copy_attach_memfd(vm_map_copy_t copy, uint64_t map_size) {
	int memfd;
	void* mapped = NULL;
	dtape_map_shared_descriptor_t* desc;
	uint64_t backing_size = map_size;

	if (copy == NULL) {
		return KERN_INVALID_ARGUMENT;
	}
	if (copy->dtape_descriptor != NULL) {
		return KERN_SUCCESS;
	}

	if (backing_size < copy->size) {
		backing_size = copy->size;
	}
	backing_size = dtape_round_page(backing_size);

	memfd = memfd_create("darling-named-entry", MFD_CLOEXEC);
	if (memfd < 0) {
		return KERN_RESOURCE_SHORTAGE;
	}

	if (backing_size > 0 && ftruncate(memfd, (off_t)backing_size) < 0) {
		close(memfd);
		return KERN_RESOURCE_SHORTAGE;
	}

	if (copy->cpy_kdata && copy->size > 0) {
		mapped = mmap(NULL, (size_t)backing_size, PROT_READ | PROT_WRITE, MAP_SHARED, memfd, 0);
		if (mapped == MAP_FAILED) {
			close(memfd);
			return KERN_RESOURCE_SHORTAGE;
		}
		memcpy(mapped, copy->cpy_kdata, (size_t)copy->size);
		if (munmap(mapped, (size_t)backing_size) < 0) {
			dtape_log_error("failed to unmap named-entry memfd staging mapping");
		}
	}

	desc = dtape_map_shared_descriptor_create(memfd, backing_size);
	if (!desc) {
		close(memfd);
		return KERN_RESOURCE_SHORTAGE;
	}

	copy->dtape_descriptor = desc;
	return KERN_SUCCESS;
};

static size_t dtape_map_find_shared_entries_locked(dtape_map_t* map, uint64_t address, uint64_t size, dtape_map_shared_entry_t** out_entries, size_t entry_count);

/*
 * XNU mach_make_memory_entry with parent_entry == NULL (or MAP_MEM_VM_SHARE)
 * extracts the live VM object. Darling used to memcpy into a fresh memfd and
 * leave the source on private pages, so ipcz NodeLinkMemory never shared.
 * Remap the source onto the named-entry memfd, the same way
 * mach_vm_remap_external_shared already does.
 */
__attribute__((used)) static const char dtape_named_entry_share_v1[] = "named_entry_share_v1";
__attribute__((used)) static const char dtape_rls_peek_v1[] = "rls_peek_v1";
__attribute__((used)) static const char dtape_shared_entry_replace_v1[] = "shared_entry_replace_v1";
__attribute__((used)) static const char dtape_shared_entry_keep_v1[] = "shared_entry_keep_v1";
__attribute__((used)) static const char dtape_vm_map_named_anywhere_noreplace_v1[] = "vm_map_named_anywhere_noreplace_v1";
__attribute__((used)) static const char dtape_rls_coherent_v1[] = "rls_coherent_v1";
__attribute__((used)) static const char dtape_rls_cas_v1[] = "rls_cas_v1";

static kern_return_t dtape_named_entry_share_source(vm_map_t map, memory_object_offset_t offset, vm_map_size_t map_size, vm_map_copy_t copy) {
	dtape_map_shared_entry_t* shared_entry;
	dtape_map_shared_descriptor_t* desc;
	dtape_memory_region_info_t region_info;
	uint64_t page_size;
	uintptr_t start;
	uintptr_t end;
	uint64_t share_size;
	uintptr_t mapped;
	uint32_t nsid = 0;
	int prot = PROT_READ | PROT_WRITE;

	if (map == VM_MAP_NULL || map == kernel_map || copy == NULL || map_size == 0) {
		return KERN_SUCCESS;
	}
	if (map->dtape_task == NULL) {
		return KERN_SUCCESS;
	}

	desc = copy->dtape_descriptor;
	if (desc == NULL) {
		return KERN_INVALID_ARGUMENT;
	}

	page_size = dtape_page_size();
	start = (uintptr_t)(offset & ~(page_size - 1));
	end = (uintptr_t)((offset + map_size + page_size - 1) & ~(page_size - 1));
	share_size = end - start;
	if (share_size == 0) {
		return KERN_SUCCESS;
	}

	nsid = map->dtape_task->saved_pid;

	dtape_mutex_lock(&map->shared_entry_lock);
	{
		dtape_map_shared_entry_t* container = NULL;
		dtape_map_shared_entry_t* overlap = NULL;
		dtape_map_shared_entry_t* entry;

		/*
		 * XNU mach_make_memory_entry on a subrange of a shared VM
		 * object keeps that object and records an offset. A 4K named
		 * entry punched out of ipcz NodeLinkMemory used to memcpy a
		 * fresh memfd and MAP_FIXED over those pages, so parent and
		 * child RouterLinkState / BlockAllocator / parcel queues
		 * diverged. After BypassPeerWithLink the ChildProcessHost
		 * Ping on decaying sublink 2 is flushed onto that central
		 * link; a split mapping leaves the Mojom trap unreadable.
		 *
		 * Walk the whole tree: a cap of 8 hits missed the 128k
		 * buffer0 under a handful of 4k punches, and the snapshot
		 * path then overwrote next_sublink_id @+8 / the 0x400 pool.
		 */
		RB_FOREACH(entry, dtape_map_shared_entry_head, &map->shared_entries) {
			if (entry->address + entry->size <= start ||
			    entry->address >= start + share_size) {
				continue;
			}
			if (overlap == NULL || entry->size > overlap->size) {
				overlap = entry;
			}
			if (entry->address <= start &&
			    entry->address + entry->size >= start + share_size) {
				if (container == NULL || entry->size < container->size) {
					container = entry;
				}
			}
		}
		if (container == NULL) {
			container = overlap;
		}
		if (container != NULL && container->descriptor != NULL) {
			dtape_map_shared_descriptor_t* live = container->descriptor;
			uint64_t byte_off;

			byte_off = (start - container->address) +
			    container->page_offset * page_size;
			dtape_map_shared_descriptor_retain(live);
			dtape_mutex_unlock(&map->shared_entry_lock);
			dtape_map_shared_descriptor_release(desc);
			copy->dtape_descriptor = live;
			copy->offset = byte_off;
			dtape_log_error("named_entry_share_v1 nsid=%u addr=0x%lx size=%llu memfd=%d reused=1 kr=0 off=%llu contain=0x%lx contain_sz=%llu",
			    nsid, (unsigned long)start, (unsigned long long)share_size, live->memfd,
			    (unsigned long long)byte_off, (unsigned long)container->address,
			    (unsigned long long)container->size);
			return KERN_SUCCESS;
		}
	}
	dtape_mutex_unlock(&map->shared_entry_lock);

	if (dtape_hooks->task_get_memory_region_info(map->dtape_task->context, (uintptr_t)offset, &region_info)) {
		prot = 0;
		if (region_info.protection & dtape_memory_protection_read) {
			prot |= PROT_READ;
		}
		if (region_info.protection & dtape_memory_protection_write) {
			prot |= PROT_WRITE;
		}
		if (region_info.protection & dtape_memory_protection_execute) {
			prot |= PROT_EXEC;
		}
		if (prot == 0) {
			prot = PROT_READ | PROT_WRITE;
		}
	}

	mapped = dtape_task_map_memfd(map, desc->memfd, share_size, prot, start, 0,
	    dtape_memory_flag_fixed | dtape_memory_flag_overwrite);
	if (mapped != start) {
		dtape_log_error("named_entry_share_v1 nsid=%u addr=0x%lx size=%llu memfd=%d reused=0 kr=1",
		    nsid, (unsigned long)start, (unsigned long long)share_size, desc->memfd);
		return KERN_FAILURE;
	}

	shared_entry = dtape_map_shared_entry_create(start, share_size, 0, desc);
	if (!shared_entry) {
		return KERN_RESOURCE_SHORTAGE;
	}
	dtape_mutex_lock(&map->shared_entry_lock);
	dtape_map_insert_shared_entry_locked(map, shared_entry, 1);
	dtape_mutex_unlock(&map->shared_entry_lock);
	dtape_log_error("named_entry_share_v1 nsid=%u addr=0x%lx size=%llu memfd=%d reused=0 kr=0",
	    nsid, (unsigned long)start, (unsigned long long)share_size, desc->memfd);
	(void)dtape_named_entry_share_v1;
	(void)dtape_rls_peek_v1;
	(void)dtape_shared_entry_replace_v1;
	(void)dtape_shared_entry_keep_v1;
	(void)dtape_vm_map_named_anywhere_noreplace_v1;
	(void)dtape_rls_coherent_v1;
	(void)dtape_rls_cas_v1;
	(void)dtape_named_entry_reuse_va_v1;
	return KERN_SUCCESS;
};

/**
 * Returns entries in-order.
 * If the number of entries returned is equal to the space provided and the address of the last entry returned still falls
 * within the target region, there may be additional entries intersecting the region. You can call this function again with
 * the address just after the last entry to continue searching.
 */
static size_t dtape_map_find_shared_entries_locked(dtape_map_t* map, uint64_t address, uint64_t size, dtape_map_shared_entry_t** out_entries, size_t entry_count) {
	dtape_map_shared_entry_t* entry;
	size_t count = 0;

	if (entry_count == 0) {
		return count;
	}

	RB_FOREACH(entry, dtape_map_shared_entry_head, &map->shared_entries) {
		if (entry->address + entry->size <= address || entry->address >= address + size) {
			continue;
		}

		out_entries[count++] = entry;

		if (count == entry_count) {
			break;
		}
	}

	return count;
};

// TODO: we should have the process inform us when it unmaps a shared entry that we remapped;
//       right now, we only close the memfd when the process dies (so the memory is potentially in-use needlessly).

void dtape_vm_map_destroy(vm_map_t map) {
	if (os_ref_release(&map->map_refcnt) != 0) {
		panic("VM map still in-use at destruction");
	}

	dtape_map_shared_entry_t* entry;
	dtape_map_shared_entry_t* tmp;

	dtape_mutex_lock(&map->shared_entry_lock);
	RB_FOREACH_SAFE(entry, dtape_map_shared_entry_head, &map->shared_entries, tmp) {
		RB_REMOVE(dtape_map_shared_entry_head, &map->shared_entries, entry);
		dtape_map_shared_entry_destroy(entry);
	}
	dtape_mutex_unlock(&map->shared_entry_lock);

	free(map);
};

void vm_map_reference(vm_map_t map) {
	os_ref_retain(&map->map_refcnt);
};

void vm_map_deallocate(vm_map_t map) {
	os_ref_release_live(&map->map_refcnt);
};

// TODO: zone-based allocations could be optimized to not just use malloc

zone_t zone_create(const char* name, vm_size_t size, zone_create_flags_t flags) {
	zone_t zone = malloc(sizeof(struct zone));
	if (!zone) {
		return ZONE_NULL;
	}
	zone->name = name;
	zone->size = size;
	return zone;
};

void zdestroy(zone_t zone) {
	free(zone);
};

void* zalloc(zone_or_view_t zone_or_view) {
	return malloc(zone_or_view.zov_zone->size);
};

void* zalloc_flags(zone_or_view_t zone_or_view, zalloc_flags_t flags) {
	void* ptr = zalloc(zone_or_view);
	if (!ptr) {
		return ptr;
	}

	if (flags & Z_ZERO) {
		memset(ptr, 0, zone_or_view.zov_zone->size);
	}

	return ptr;
};

void (zfree)(zone_or_view_t zone_or_view, void* elem) {
	free(elem);
};

void zone_id_require(zone_id_t zone_id, vm_size_t elem_size, void* addr) {
	dtape_stub_safe();
};

void zone_require(zone_t zone, void* addr) {
	dtape_stub_safe();
};

zone_t zinit(vm_size_t size, vm_size_t max, vm_size_t alloc, const char* name) {
	return zone_create(name, size, 0);
};

void (kheap_free)(kalloc_heap_t kheap, void* addr, vm_size_t size) {
	free(addr);
};

void (kheap_free_addr)(kalloc_heap_t kheap, void* addr) {
	kheap_free(kheap, addr, 0);
};

void (kfree)(void* addr, vm_size_t size) {
	free(addr);
};

struct kalloc_result kalloc_ext(kalloc_heap_t kheap, vm_size_t req_size, zalloc_flags_t flags, vm_allocation_site_t* site) {
	if (flags & Z_ZERO) {
		return (struct kalloc_result) { .addr = calloc(1, req_size), .size = req_size };
	} else {
		return (struct kalloc_result) { .addr = malloc(req_size), .size = req_size };
	}
};

const char* zone_heap_name(zone_t zone) {
	dtape_stub_safe();
	return "";
};

const char* zone_name(zone_t zone) {
	return zone->name;
};

void* zalloc_permanent(vm_size_t size, vm_offset_t align_mask) {
	size_t power_of_2 = (sizeof(long long) * 8) - __builtin_clzll(align_mask);
	void* memory = aligned_alloc(1 << power_of_2, size);
	if (!memory) {
		return memory;
	}

	memset(memory, 0, sizeof(size));
	return memory;
};

void vm_page_free_reserve(int pages) {
	dtape_stub_safe();
};

kern_return_t kernel_memory_allocate(vm_map_t map, vm_offset_t* addrp, vm_size_t size, vm_offset_t mask, kma_flags_t flags, vm_tag_t tag) {
	void* ptr = mmap(NULL, size, PROT_READ | PROT_WRITE, MAP_ANONYMOUS | MAP_PRIVATE, -1, 0);
	if (ptr == MAP_FAILED) {
		return KERN_FAILURE;
	}

	*addrp = (vm_offset_t)ptr;
	return KERN_SUCCESS;
};

kern_return_t vm_deallocate(vm_map_t map, vm_offset_t start, vm_size_t size) {
	return munmap((void*)start, size) == 0;
};

kern_return_t vm_allocate_kernel(vm_map_t map, vm_offset_t* addr, vm_size_t size, int flags, vm_tag_t tag) {
	mach_vm_offset_t tmp;
	kern_return_t status = mach_vm_allocate_kernel(map, &tmp, size, flags, tag);
	if (status == KERN_SUCCESS) {
		*addr = tmp;
	}
	return status;
};

kern_return_t kmem_alloc(vm_map_t map, vm_offset_t* addrp, vm_size_t size, vm_tag_t tag) {
	return kernel_memory_allocate(map, addrp, size, 0, 0, tag);
};

void kmem_free(vm_map_t map, vm_offset_t addr, vm_size_t size) {
	vm_deallocate(map, addr, size);
};

kern_return_t copyoutmap(vm_map_t map, void* fromdata, vm_map_address_t toaddr, vm_size_t length) {
	if (map == kernel_map) {
		memmove((void*)toaddr, fromdata, length);
		return KERN_SUCCESS;
	} else {
		return dtape_hooks->task_write_memory(map->dtape_task->context, toaddr, fromdata, length) ? KERN_SUCCESS : KERN_FAILURE;
	}
};

kern_return_t copyinmap(vm_map_t map, vm_map_offset_t fromaddr, void* todata, vm_size_t length) {
	if (map == kernel_map) {
		memmove(todata, (const void*)fromaddr, length);
		return KERN_SUCCESS;
	} else {
		return dtape_hooks->task_read_memory(map->dtape_task->context, fromaddr, todata, length) ? KERN_SUCCESS : KERN_FAILURE;
	}
};

int (copyin)(const user_addr_t user_addr, void* kernel_addr, vm_size_t nbytes) {
	return (copyinmap(current_map(), user_addr, kernel_addr, nbytes) == KERN_SUCCESS) ? 0 : 1;
};

int (copyout)(const void* kernel_addr, user_addr_t user_addr, vm_size_t nbytes) {
	// it doesn't actually modify kernel_addr
	return (copyoutmap(current_map(), (void*)kernel_addr, user_addr, nbytes) == KERN_SUCCESS) ? 0 : 1;
};

int copyinmsg(const user_addr_t user_addr, char* kernel_addr, mach_msg_size_t nbytes) {
	return (copyin)(user_addr, kernel_addr, nbytes);
};

int copyoutmsg(const char* kernel_addr, user_addr_t user_addr, mach_msg_size_t nbytes) {
	return (copyout)(kernel_addr, user_addr, nbytes);
};

kern_return_t kmem_suballoc(vm_map_t parent, vm_offset_t* addr, vm_size_t size, boolean_t pageable, int flags, vm_map_kernel_flags_t vmk_flags, vm_tag_t tag, vm_map_t* new_map) {
	// this is enough to satisfy ipc_init
	dtape_stub();
	*new_map = parent;
	return KERN_SUCCESS;
};

boolean_t vm_kernel_map_is_kernel(vm_map_t map) {
	return map == kernel_map || map == ipc_kernel_map;
};

void vm_map_copy_discard(vm_map_copy_t copy) {
	if (copy == VM_MAP_COPY_NULL) {
		return;
	}
	if (copy->dtape_descriptor) {
		dtape_map_shared_descriptor_release(copy->dtape_descriptor);
		copy->dtape_descriptor = NULL;
	}
	free(copy);
};

kern_return_t vm_map_copyin_common(vm_map_t src_map, vm_map_address_t src_addr, vm_map_size_t len, boolean_t src_destroy, boolean_t src_volatile, vm_map_copy_t* copy_result, boolean_t use_maxprot) {
	// XNU only performs a kernel buffer copy when the data is sufficiently small;
	// however, we always perform a kernel buffer copy just to make it easier for ourselves

	// this code has been adapted from vm_map_copyin_kernel_buffer() in osfmk/vm/vm_map.c

	kern_return_t kr;

	vm_map_copy_t copy = malloc(sizeof(struct vm_map_copy) + len);
	if (copy == NULL) {
		return KERN_RESOURCE_SHORTAGE;
	}

	copy->type = VM_MAP_COPY_KERNEL_BUFFER;
	copy->size = len;
	copy->offset = 0;
	copy->cpy_kdata = copy->dtape_copy_data;
	copy->dtape_descriptor = NULL;

	kr = copyinmap(src_map, src_addr, copy->cpy_kdata, (vm_size_t)len);
	if (kr != KERN_SUCCESS) {
		free(copy);
		return kr;
	}

	if (src_destroy) {
		vm_map_remove(src_map, vm_map_trunc_page(src_addr, VM_MAP_PAGE_MASK(src_map)), vm_map_round_page(src_addr + len, VM_MAP_PAGE_MASK(src_map)), 0);
	}

	*copy_result = copy;
	return KERN_SUCCESS;
};

static kern_return_t vm_map_copyout_kernel_buffer(vm_map_t map, vm_map_address_t* addr, vm_map_copy_t copy, vm_map_size_t copy_size, boolean_t overwrite, boolean_t consume_on_success) {
	kern_return_t kr = KERN_SUCCESS;

	if (!overwrite) {
		// we need to allocate memory for this copy

		if (map == kernel_map) {
			*addr = (uintptr_t)mmap(NULL, copy_size, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
			if (*addr == (uintptr_t)MAP_FAILED) {
				return KERN_RESOURCE_SHORTAGE;
			}
		} else {
			*addr = dtape_hooks->task_allocate_pages(map->dtape_task->context, dtape_byte_count_to_page_count_round_up(copy_size), PROT_READ | PROT_WRITE, 0, 0);
			if (*addr == 0) {
				return KERN_RESOURCE_SHORTAGE;
			}
		}
	}

	if (copyoutmap(map, copy->cpy_kdata, *addr, (vm_size_t)copy_size)) {
		kr = KERN_INVALID_ADDRESS;
	}

	if (kr != KERN_SUCCESS) {
		if (!overwrite) {
			// clean up the space we allocate earlier
			vm_map_remove(map, vm_map_trunc_page(*addr, VM_MAP_PAGE_MASK(map)), vm_map_round_page((*addr + vm_map_round_page(copy_size, VM_MAP_PAGE_MASK(map))), VM_MAP_PAGE_MASK(map)), 0);
			*addr = 0;
		}
	} else {
		// copy was successful
		if (consume_on_success) {
			free(copy);
		}
	}

	return kr;
};

kern_return_t vm_map_copy_overwrite(vm_map_t dst_map, vm_map_offset_t dst_addr, vm_map_copy_t copy, vm_map_size_t copy_size, boolean_t interruptible) {
	if (copy == VM_MAP_COPY_NULL) {
		return KERN_SUCCESS;
	}

	return vm_map_copyout_kernel_buffer(dst_map, &dst_addr, copy, copy->size, TRUE, TRUE);
};

kern_return_t vm_map_copyout_size(vm_map_t dst_map, vm_map_address_t* dst_addr, vm_map_copy_t copy, vm_map_size_t copy_size) {
	if (copy == VM_MAP_COPY_NULL) {
		*dst_addr = 0;
		return KERN_SUCCESS;
	}

	if (copy->size != copy_size) {
		*dst_addr = 0;
		return KERN_FAILURE;
	}

	return vm_map_copyout_kernel_buffer(dst_map, dst_addr, copy, copy_size, FALSE, TRUE);
};

kern_return_t vm_map_copyout(vm_map_t dst_map, vm_map_address_t* dst_addr, vm_map_copy_t copy) {
	return vm_map_copyout_size(dst_map, dst_addr, copy, copy ? copy->size : 0);
};

boolean_t vm_map_copy_validate_size(vm_map_t dst_map, vm_map_copy_t copy, vm_map_size_t* size) {
	if (copy == VM_MAP_COPY_NULL) {
		return FALSE;
	}
	return *size == copy->size;
};

kern_return_t vm_map_remove(vm_map_t map, vm_map_offset_t start, vm_map_offset_t end, boolean_t flags) {
	dtape_map_shared_entry_t* entry;
	dtape_map_shared_entry_t* tmp;
	struct {
		uint64_t lo;
		uint64_t hi;
	} pins[8];
	size_t npin = 0;
	size_t i;
	uint64_t cursor;
	uint32_t nsid = 0;
	kern_return_t kr = KERN_SUCCESS;

	if (map == kernel_map) {
		if (munmap((void*)start, end - start) < 0) {
			return KERN_FAILURE;
		}
		return KERN_SUCCESS;
	}

	if (map->dtape_task) {
		nsid = map->dtape_task->saved_pid;
	}

	dtape_mutex_lock(&map->shared_entry_lock);
	RB_FOREACH_SAFE(entry, dtape_map_shared_entry_head, &map->shared_entries, tmp) {
		uint64_t lo;
		uint64_t hi;

		if (entry->address + entry->size <= start || entry->address >= end) {
			continue;
		}
		if (!(entry->map_refs > 1 || entry->size >= 131072)) {
			if (entry->address >= start && entry->address + entry->size <= end) {
				RB_REMOVE(dtape_map_shared_entry_head, &map->shared_entries, entry);
				dtape_map_shared_entry_destroy(entry);
			}
			continue;
		}
		if (entry->map_refs > 1) {
			entry->map_refs--;
		}
		lo = entry->address < start ? start : entry->address;
		hi = entry->address + entry->size > end ? end : entry->address + entry->size;
		dtape_log_error("named_entry_reuse_va_v1 nsid=%u keep_va=0x%lx size=%llu refs=%u dealloc=0x%lx-0x%lx pin=0x%lx-0x%lx",
		    nsid, (unsigned long)entry->address,
		    (unsigned long long)entry->size, entry->map_refs,
		    (unsigned long)start, (unsigned long)end,
		    (unsigned long)lo, (unsigned long)hi);
		if (npin < sizeof(pins) / sizeof(pins[0]) && hi > lo) {
			pins[npin].lo = lo;
			pins[npin].hi = hi;
			npin++;
		}
	}
	dtape_mutex_unlock(&map->shared_entry_lock);

	cursor = start;
	for (i = 0; i < npin; i++) {
		if (pins[i].lo > cursor) {
			if (dtape_hooks->task_free_pages(map->dtape_task->context, cursor,
			    dtape_byte_count_to_page_count_round_down(pins[i].lo - cursor)) < 0) {
				kr = KERN_FAILURE;
				break;
			}
		}
		if (pins[i].hi > cursor) {
			cursor = pins[i].hi;
		}
	}
	if (kr == KERN_SUCCESS && cursor < end) {
		if (dtape_hooks->task_free_pages(map->dtape_task->context, cursor,
		    dtape_byte_count_to_page_count_round_down(end - cursor)) < 0) {
			kr = KERN_FAILURE;
		}
	}
	return kr;
};

kern_return_t mach_vm_allocate_kernel(vm_map_t map, mach_vm_offset_t* addr, mach_vm_size_t size, int flags, vm_tag_t tag) {
	if (map == kernel_map) {
		vm_offset_t tmp;
		kern_return_t kr = kernel_memory_allocate(map, &tmp, size, VM_MAP_PAGE_MASK(map), flags, tag);
		if (kr == KERN_SUCCESS) {
			*addr = tmp;
		}
		return kr;
	} else {
		// mach_vm_allocate_kernel allocates with default protection
		uintptr_t tmp = dtape_hooks->task_allocate_pages(map->dtape_task->context, dtape_byte_count_to_page_count_round_up(size), PROT_READ | PROT_WRITE, 0, 0);
		if (tmp == 0) {
			return KERN_RESOURCE_SHORTAGE;
		}
		*addr = tmp;
		return KERN_SUCCESS;
	}
};

kern_return_t _mach_make_memory_entry(vm_map_t target_map, memory_object_size_t* size, memory_object_offset_t offset, vm_prot_t permission, ipc_port_t* object_handle, ipc_port_t parent_entry) {
	vm_named_entry_t user_entry;
	ipc_port_t user_handle;
	vm_map_copy_t copy = VM_MAP_COPY_NULL;
	memory_object_size_t requested;
	vm_map_size_t map_size;
	long page_size;

	(void)parent_entry;

	if (size == NULL || object_handle == NULL) {
		return KERN_INVALID_ARGUMENT;
	}

	requested = *size;
	page_size = sysconf(_SC_PAGESIZE);
	if (page_size <= 0) {
		return KERN_FAILURE;
	}

	map_size = (requested + (memory_object_size_t)(page_size - 1)) & ~((memory_object_size_t)page_size - 1);

	user_entry = (vm_named_entry_t) kalloc(sizeof(*user_entry));
	if (user_entry == NULL) {
		return KERN_FAILURE;
	}
	memset(user_entry, 0, sizeof(*user_entry));
	named_entry_lock_init(user_entry);

	if ((permission & MAP_MEM_NAMED_CREATE) || requested == 0 || target_map == VM_MAP_NULL) {
		copy = malloc(sizeof(struct vm_map_copy));
		if (copy == NULL) {
			named_entry_lock_destroy(user_entry);
			kfree(user_entry, sizeof(*user_entry));
			return KERN_RESOURCE_SHORTAGE;
		}
		memset(copy, 0, sizeof(struct vm_map_copy));
		copy->type = VM_MAP_COPY_KERNEL_BUFFER;
		copy->size = map_size;
		copy->offset = 0;
		copy->cpy_kdata = NULL;
		if (dtape_named_copy_attach_memfd(copy, map_size) != KERN_SUCCESS) {
			free(copy);
			named_entry_lock_destroy(user_entry);
			kfree(user_entry, sizeof(*user_entry));
			return KERN_RESOURCE_SHORTAGE;
		}
	} else {
		kern_return_t kr = vm_map_copyin_common(target_map, offset, requested, FALSE, FALSE, &copy, FALSE);
		if (kr != KERN_SUCCESS) {
			named_entry_lock_destroy(user_entry);
			kfree(user_entry, sizeof(*user_entry));
			return kr;
		}
		map_size = copy->size;
		kr = dtape_named_copy_attach_memfd(copy, map_size);
		if (kr != KERN_SUCCESS) {
			vm_map_copy_discard(copy);
			named_entry_lock_destroy(user_entry);
			kfree(user_entry, sizeof(*user_entry));
			return kr;
		}
		if ((permission & MAP_MEM_VM_COPY) == 0) {
			kr = dtape_named_entry_share_source(target_map, offset, map_size, copy);
			if (kr != KERN_SUCCESS) {
				vm_map_copy_discard(copy);
				named_entry_lock_destroy(user_entry);
				kfree(user_entry, sizeof(*user_entry));
				return kr;
			}
		}
	}

	user_entry->backing.copy = copy;
	user_entry->is_object = FALSE;
	user_entry->is_sub_map = FALSE;
	/*
	 * is_copy names the vm_map_copy backing, not MAP_MEM_VM_COPY.
	 * vm_map_named_v1 only attaches the live memfd on this path, so
	 * ipcz NodeLinkMemory / RouterLinkState stay MAP_SHARED. A false
	 * here used to fall through to anonymous pages and the parent
	 * never copyin-replied ChildProcessHost Ping on sublink 2.
	 */
	user_entry->is_copy = TRUE;
	user_entry->internal = TRUE;
	user_entry->size = map_size;
	user_entry->offset = copy->offset;
	user_entry->data_offset = 0;
	user_entry->protection = permission & VM_PROT_ALL;
	user_entry->ref_count = 1;

	user_handle = ipc_kobject_alloc_port((ipc_kobject_t)user_entry, IKOT_NAMED_ENTRY,
	    IPC_KOBJECT_ALLOC_MAKE_SEND | IPC_KOBJECT_ALLOC_NSREQUEST);

	*object_handle = user_handle;
	*size = map_size;
	return KERN_SUCCESS;
};

kern_return_t mach_memory_entry_access_tracking(ipc_port_t entry_port, int* access_tracking, uint32_t* access_tracking_reads, uint32_t* access_tracking_writes) {
	dtape_stub_unsafe();
};

kern_return_t mach_memory_entry_ownership(ipc_port_t entry_port, task_t owner, int ledger_tag, int ledger_flags) {
	dtape_stub_unsafe();
};

kern_return_t mach_memory_entry_purgable_control(ipc_port_t entry_port, vm_purgable_t control, int* state) {
	dtape_stub_unsafe();
};

kern_return_t mach_memory_info(host_priv_t host, mach_zone_name_array_t* namesp, mach_msg_type_number_t* namesCntp, mach_zone_info_array_t* infop, mach_msg_type_number_t* infoCntp, mach_memory_info_array_t* memoryInfop, mach_msg_type_number_t* memoryInfoCntp) {
	dtape_stub_unsafe();
};

kern_return_t mach_memory_object_memory_entry(host_t host, boolean_t internal, vm_size_t size, vm_prot_t permission, memory_object_t pager, ipc_port_t* entry_handle) {
	dtape_stub_unsafe();
};

kern_return_t mach_memory_object_memory_entry_64(host_t host, boolean_t internal, vm_object_offset_t size, vm_prot_t permission, memory_object_t pager, ipc_port_t* entry_handle) {
	dtape_stub_unsafe();
};

void pmap_require(pmap_t pmap) {
	dtape_stub_safe();
};

kern_return_t vm_allocate_cpm(host_priv_t host_priv, vm_map_t map, vm_address_t* addr, vm_size_t size, int flags) {
	dtape_stub_unsafe();
};

kern_return_t vm32_mapped_pages_info(vm_map_t map, page_address_array_t* pages, mach_msg_type_number_t* pages_count) {
	dtape_stub_unsafe();
};

kern_return_t vm32_region_info(vm_map_t map, vm32_offset_t address, vm_info_region_t* regionp, vm_info_object_array_t* objectsp, mach_msg_type_number_t* objectsCntp) {
	dtape_stub_unsafe();
};

kern_return_t vm32_region_info_64(vm_map_t map, vm32_offset_t address, vm_info_region_64_t* regionp, vm_info_object_array_t* objectsp, mach_msg_type_number_t* objectsCntp) {
	dtape_stub_unsafe();
};

memory_object_t convert_port_to_memory_object(mach_port_t port) {
	dtape_stub_unsafe();
};

kern_return_t mach_vm_behavior_set(vm_map_t map, mach_vm_offset_t start, mach_vm_size_t size, vm_behavior_t new_behavior) {
	dtape_stub_unsafe();
};

kern_return_t mach_vm_inherit(vm_map_t map, mach_vm_offset_t start, mach_vm_size_t size, vm_inherit_t new_inheritance) {
	dtape_stub_unsafe();
};

kern_return_t mach_vm_machine_attribute(vm_map_t map, mach_vm_address_t addr, mach_vm_size_t size, vm_machine_attribute_t attribute, vm_machine_attribute_val_t* value) {
	dtape_stub_unsafe();
};

#define DTAPE_RLS_WATCH 48
struct dtape_rls_watch {
	int memfd;
	uint32_t nsid;
	uintptr_t addr;
	uint64_t size;
	void* context;
};
static struct dtape_rls_watch dtape_rls_watch_tab[DTAPE_RLS_WATCH];
static unsigned dtape_rls_watch_n;
void dtape_nodelink_invite_dump(const char *why, uint32_t dest_nsid);

static void dtape_hex16(const unsigned char* b, int n, char* out) {
	static const char hx[] = "0123456789abcdef";
	int i;
	for (i = 0; i < n && i < 16; i++) {
		out[i * 2] = hx[b[i] >> 4];
		out[i * 2 + 1] = hx[b[i] & 0xf];
	}
	out[i * 2] = 0;
};

__attribute__((used)) static const char dtape_rls_frag_v1[] = "rls_frag_v1";
__attribute__((used)) static const char dtape_named_entry_populate_v1[] = "named_entry_populate_v1";
__attribute__((used)) static const char dtape_rls_alias_whole_v1[] = "rls_alias_whole_v1";

static const uint64_t dtape_rls_frag_offs[] = {
	0x180, 0x400, 0x4c0, 0x600, 0x680, 0x6c0, 0x700, 0x740, 0x780, 0x7c0,
	0x800, 0x840, 0x880, 0x8c0, 0x900
};

static void dtape_rls_coherent_note(vm_map_t map, int memfd, uintptr_t addr, uint64_t size) {
	unsigned char mbuf[16];
	unsigned char vbuf[16];
	char mhex[33];
	char vhex[33];
	uint32_t nsid = 0;
	long nread;
	int match;
	unsigned i;
	unsigned oi;

	(void)dtape_rls_frag_v1;
	(void)dtape_named_entry_populate_v1;
	(void)dtape_rls_alias_whole_v1;

	if (size < 0x180 + 16) {
		return;
	}
	if (map && map->dtape_task) {
		nsid = map->dtape_task->saved_pid;
	}

	for (oi = 0; oi < sizeof(dtape_rls_frag_offs) / sizeof(dtape_rls_frag_offs[0]); oi++) {
		uint64_t off = dtape_rls_frag_offs[oi];

		if (size < off + 16) {
			continue;
		}
		memset(mbuf, 0, sizeof(mbuf));
		memset(vbuf, 0, sizeof(vbuf));
		nread = pread(memfd, mbuf, 16, (long)off);
		if (map && map != kernel_map && map->dtape_task && map->dtape_task->context) {
			dtape_hooks->task_read_memory(map->dtape_task->context,
			    addr + (uintptr_t)off, vbuf, 16);
		}
		match = (nread == 16) && (memcmp(mbuf, vbuf, 16) == 0);
		dtape_hex16(mbuf, 16, mhex);
		dtape_hex16(vbuf, 16, vhex);
		dtape_log_error("rls_coherent_v1 nsid=%u memfd=%d off=0x%llx va=0x%lx size=%llu match=%d memfd_hex=%s va_hex=%s",
		    nsid, memfd, (unsigned long long)off, (unsigned long)addr,
		    (unsigned long long)size, match, mhex, vhex);
	}
	if (size >= 0x400 + 16) {
		unsigned char idbuf[8];
		unsigned char pool[16];
		char idhex[17];
		char poolhex[33];
		uint64_t nsid_val = 0;

		memset(idbuf, 0, sizeof(idbuf));
		memset(pool, 0, sizeof(pool));
		pread(memfd, idbuf, 8, 8);
		pread(memfd, pool, 16, 0x400);
		memcpy(&nsid_val, idbuf, 8);
		dtape_hex16(idbuf, 8, idhex);
		dtape_hex16(pool, 16, poolhex);
		dtape_log_error("rls_cas_v1 nsid=%u memfd=%d next_sublink=%llu id_hex=%s pool400_hex=%s",
		    nsid, memfd, (unsigned long long)nsid_val, idhex, poolhex);
	}

	for (i = 0; i < dtape_rls_watch_n && i < DTAPE_RLS_WATCH; i++) {
		if (dtape_rls_watch_tab[i].memfd == memfd && dtape_rls_watch_tab[i].nsid != nsid) {
			dtape_log_error("rls_coherent_v1 pair memfd=%d this_nsid=%u this_va=0x%lx other_nsid=%u other_va=0x%lx",
			    memfd, nsid, (unsigned long)addr,
			    dtape_rls_watch_tab[i].nsid, (unsigned long)dtape_rls_watch_tab[i].addr);
		}
	}

	/*
	 * NodeLinkMemory primary buffer is exactly 128KB. 256KB+ named
	 * entries (field-trial, perfetto) share the 0x7f window and
	 * drowned sl=2 Accept peeks of the live RLS at 0x180.
	 */
	if (size == 131072 && dtape_rls_watch_n < DTAPE_RLS_WATCH) {
		dtape_rls_watch_tab[dtape_rls_watch_n].memfd = memfd;
		dtape_rls_watch_tab[dtape_rls_watch_n].nsid = nsid;
		dtape_rls_watch_tab[dtape_rls_watch_n].addr = addr;
		dtape_rls_watch_tab[dtape_rls_watch_n].size = size;
		dtape_rls_watch_tab[dtape_rls_watch_n].context =
		    (map && map->dtape_task) ? map->dtape_task->context : NULL;
		/*
		 * Do not arm hardware watchpoints. Network-only bp
		 * killed prefix dserver 1534266 (guest RPC -111)
		 * before proto=4 Ping. RLS is a breadcrumb only.
		 */
		(void)dtape_rls_fe_wp_network_only_v1;
		(void)dtape_rls_fe_wp_disabled_v1;
		(void)dtape_rls_wp_arm;
		dtape_log_error(
		    "rls_fe_wp_v1 disabled killed dserver 1534266 RPC -111 nsid=%u memfd=%d",
		    nsid, memfd);
		dtape_rls_watch_n++;
	}
};

void
dtape_rls_frag_copyout_note(uint32_t frag_off)
{
	unsigned char mbuf[16];
	unsigned char vbuf[16];
	char mhex[33];
	char vhex[33];
	uint32_t nsid = 0;
	task_t t = current_task();
	dtape_task_t *dt = NULL;
	unsigned i;
	long nread;
	int match;

	if (frag_off == 0) {
		return;
	}
	if (t != NULL) {
		dt = dtape_task_for_xnu_task(t);
		if (dt) {
			nsid = dt->saved_pid;
		}
	}
	for (i = 0; i < dtape_rls_watch_n && i < DTAPE_RLS_WATCH; i++) {
		if (dtape_rls_watch_tab[i].nsid != nsid) {
			continue;
		}
		if (dtape_rls_watch_tab[i].size < (uint64_t)frag_off + 16) {
			continue;
		}
		memset(mbuf, 0, sizeof(mbuf));
		memset(vbuf, 0, sizeof(vbuf));
		nread = pread(dtape_rls_watch_tab[i].memfd, mbuf, 16, (long)frag_off);
		if (dt && dt->context) {
			dtape_hooks->task_read_memory(dt->context,
			    dtape_rls_watch_tab[i].addr + (uintptr_t)frag_off, vbuf, 16);
		}
		match = (nread == 16) && (memcmp(mbuf, vbuf, 16) == 0);
		dtape_hex16(mbuf, 16, mhex);
		dtape_hex16(vbuf, 16, vhex);
		dtape_log_error("rls_frag_v1 nsid=%u memfd=%d off=0x%x va=0x%lx match=%d memfd_hex=%s va_hex=%s",
		    nsid, dtape_rls_watch_tab[i].memfd, frag_off,
		    (unsigned long)dtape_rls_watch_tab[i].addr, match, mhex, vhex);
	}
	/*
	 * Same memfd, other process: AdoptFragment on flags=0x2 needs that
	 * VA to alias this memfd, not a CoW first page.
	 */
	for (i = 0; i < dtape_rls_watch_n && i < DTAPE_RLS_WATCH; i++) {
		unsigned j;

		if (dtape_rls_watch_tab[i].nsid == nsid) {
			continue;
		}
		if (dtape_rls_watch_tab[i].size < (uint64_t)frag_off + 16) {
			continue;
		}
		for (j = 0; j < dtape_rls_watch_n && j < DTAPE_RLS_WATCH; j++) {
			unsigned char obuf[16];
			char ohex[33];
			int pair;
			int va_ok;

			if (dtape_rls_watch_tab[j].nsid != nsid) {
				continue;
			}
			if (dtape_rls_watch_tab[j].memfd != dtape_rls_watch_tab[i].memfd) {
				continue;
			}
			memset(mbuf, 0, sizeof(mbuf));
			memset(obuf, 0, sizeof(obuf));
			nread = pread(dtape_rls_watch_tab[i].memfd, mbuf, 16, (long)frag_off);
			va_ok = 0;
			if (dtape_rls_watch_tab[i].context && dtape_hooks->task_read_memory) {
				va_ok = dtape_hooks->task_read_memory(dtape_rls_watch_tab[i].context,
				    dtape_rls_watch_tab[i].addr + (uintptr_t)frag_off, obuf, 16) ? 1 : 0;
			}
			pair = va_ok && (nread == 16) && (memcmp(mbuf, obuf, 16) == 0);
			dtape_hex16(mbuf, 16, mhex);
			dtape_hex16(obuf, 16, ohex);
			dtape_log_error("rls_frag_v1 pair memfd=%d off=0x%x this_nsid=%u this_va=0x%lx other_nsid=%u other_va=0x%lx match=%d va_ok=%d memfd_hex=%s other_hex=%s",
			    dtape_rls_watch_tab[i].memfd, frag_off,
			    nsid, (unsigned long)dtape_rls_watch_tab[j].addr,
			    dtape_rls_watch_tab[i].nsid,
			    (unsigned long)dtape_rls_watch_tab[i].addr,
			    pair, va_ok, mhex, ohex);
		}
	}
}

__attribute__((used)) static const char dtape_rls_accept_peek_v1[] = "rls_accept_peek_v1";
__attribute__((used)) static const char dtape_rls_ping_link_v1[] = "rls_ping_link_v1";

/*
 * Peek RouterLinkState after sl=2 AcceptInbound, not only at map time.
 * 0x180 is initial portal 2; 0x440 is the first 64-byte allocated RLS.
 */
void
dtape_rls_accept_peek(uint64_t sublink, uint32_t seq)
{
	unsigned char mbuf[16];
	unsigned char vbuf[16];
	char mhex[33];
	char vhex[33];
	uint32_t nsid = 0;
	task_t t = current_task();
	dtape_task_t *dt = NULL;
	unsigned i;
	unsigned oi;
	long nread;
	int match;
	static const uint64_t peek_offs[] = { 0x180, 0x184, 0x440, 0x480, 0x4c0, 0x600, 0x680, 0x6c0, 0x700, 0x740, 0x780 };

	(void)dtape_rls_accept_peek_v1;
	(void)dtape_rls_ping_link_v1;

	if (sublink == 0) {
		return;
	}
	if (t != NULL) {
		dt = dtape_task_for_xnu_task(t);
		if (dt) {
			nsid = dt->saved_pid;
		}
	}
	for (i = 0; i < dtape_rls_watch_n && i < DTAPE_RLS_WATCH; i++) {
		if (dtape_rls_watch_tab[i].nsid != nsid) {
			continue;
		}
		if (dtape_rls_watch_tab[i].size < 0x180 + 16) {
			continue;
		}
		for (oi = 0; oi < sizeof(peek_offs) / sizeof(peek_offs[0]); oi++) {
			uint64_t off = peek_offs[oi];

			if (dtape_rls_watch_tab[i].size < off + 16) {
				continue;
			}
			memset(mbuf, 0, sizeof(mbuf));
			memset(vbuf, 0, sizeof(vbuf));
			nread = pread(dtape_rls_watch_tab[i].memfd, mbuf, 16, (long)off);
			if (dt && dt->context) {
				dtape_hooks->task_read_memory(dt->context,
				    dtape_rls_watch_tab[i].addr + (uintptr_t)off, vbuf, 16);
			}
			match = (nread == 16) && (memcmp(mbuf, vbuf, 16) == 0);
			dtape_hex16(mbuf, 16, mhex);
			dtape_hex16(vbuf, 16, vhex);
			dtape_log_error("rls_accept_peek_v1 nsid=%u sl=%llu seq=%u memfd=%d off=0x%llx va=0x%lx match=%d status=0x%x memfd_hex=%s va_hex=%s",
			    nsid, (unsigned long long)sublink, seq,
			    dtape_rls_watch_tab[i].memfd, (unsigned long long)off,
			    (unsigned long)dtape_rls_watch_tab[i].addr, match,
			    (unsigned)(mbuf[0] | (mbuf[1] << 8) | (mbuf[2] << 16) | (mbuf[3] << 24)),
			    mhex, vhex);
		}
	}
	/*
	 * Headline the NodeLink that is actually paired (browser+helper
	 * share the memfd). memfd 52 is GPU; Ping lives on the network
	 * pair (memfd 55 last run), not the GPU zeros.
	 */
	for (i = 0; i < dtape_rls_watch_n && i < DTAPE_RLS_WATCH; i++) {
		unsigned j;
		unsigned char sbuf[16];
		char shex[33];
		long nr;

		if (dtape_rls_watch_tab[i].nsid != nsid) {
			continue;
		}
		for (j = 0; j < dtape_rls_watch_n && j < DTAPE_RLS_WATCH; j++) {
			if (dtape_rls_watch_tab[j].memfd != dtape_rls_watch_tab[i].memfd) {
				continue;
			}
			if (dtape_rls_watch_tab[j].nsid == nsid) {
				continue;
			}
			memset(sbuf, 0, sizeof(sbuf));
			nr = pread(dtape_rls_watch_tab[i].memfd, sbuf, 16, 0x180);
			dtape_hex16(sbuf, 16, shex);
			dtape_log_error("rls_ping_link_v1 nsid=%u sl=%llu seq=%u memfd=%d pair_nsid=%u status=0x%x nread=%ld hex=%s",
			    nsid, (unsigned long long)sublink, seq,
			    dtape_rls_watch_tab[i].memfd,
			    dtape_rls_watch_tab[j].nsid,
			    (unsigned)(sbuf[0] | (sbuf[1] << 8) | (sbuf[2] << 16) | (sbuf[3] << 24)),
			    nr, shex);
			break;
		}
	}
}

/*
 * Portal-2 RLS at 0x180 on the 128KB NodeLinkMemory the helper shares
 * with the browser. status 0 = kUnstable; 0xfffffffe = decaying/live
 * (storage). Used to sit helper→browser sl=2 Accept until Bypass 34.
 */
int
dtape_rls_portal2_status(uint32_t nsid, uint32_t *status_out)
{
	unsigned i;
	unsigned j;
	unsigned char sbuf[4];
	long nr;
	int found = 0;
	uint32_t st = 0;

	if (status_out) {
		*status_out = 0;
	}
	if (nsid == 0) {
		return 0;
	}
	for (i = 0; i < dtape_rls_watch_n && i < DTAPE_RLS_WATCH; i++) {
		int paired = 0;

		if (dtape_rls_watch_tab[i].nsid != nsid) {
			continue;
		}
		if (dtape_rls_watch_tab[i].size != 131072) {
			continue;
		}
		for (j = 0; j < dtape_rls_watch_n && j < DTAPE_RLS_WATCH; j++) {
			if (dtape_rls_watch_tab[j].memfd != dtape_rls_watch_tab[i].memfd) {
				continue;
			}
			if (dtape_rls_watch_tab[j].nsid == nsid) {
				continue;
			}
			paired = 1;
			break;
		}
		memset(sbuf, 0, sizeof(sbuf));
		nr = pread(dtape_rls_watch_tab[i].memfd, sbuf, 4, 0x180);
		if (nr != 4) {
			continue;
		}
		st = (uint32_t)sbuf[0] | ((uint32_t)sbuf[1] << 8) |
		    ((uint32_t)sbuf[2] << 16) | ((uint32_t)sbuf[3] << 24);
		found = 1;
		if (paired) {
			break;
		}
	}
	if (status_out) {
		*status_out = st;
	}
	return found;
}

__attribute__((used)) static const char dtape_nodelink_invite_v1[] =
	"nodelink_invite_v1";

/*
 * arch16: ChildProcess invitation is ipcz initial portals in
 * NodeLinkMemory (128KB memfd), not Mach descriptors on sl=2 seq 0-3.
 * PrimaryBuffer: next_buffer_id@0, next_sublink_id@8 (starts at 12),
 * portal i RLS at 0x100+i*0x40 (ref_count@+0 unmanaged, status@+4).
 * Public Chromium: p0=BaseSharedMemoryService, p1=ChildProcess
 * (attachment 0), p2=ChildProcessHost (attachment 1). Initial portals
 * are unmanaged so ref_count==0 is not "uninstalled". Do not steal
 * memfd. Do not dest-bind.
 */
void
dtape_nodelink_invite_dump(const char *why, uint32_t dest_nsid)
{
	uint32_t cur = 0;
	unsigned i, pi;
	unsigned n128 = 0;
	static unsigned nlog;
	task_t t = current_task();
	dtape_task_t *dt = NULL;

	(void)dtape_nodelink_invite_v1;
	if (nlog >= 120) {
		return;
	}
	if (why == NULL) {
		why = "?";
	}
	if (t != NULL) {
		dt = dtape_task_for_xnu_task(t);
		if (dt) {
			cur = dt->saved_pid;
		}
	}
	for (i = 0; i < dtape_rls_watch_n && i < DTAPE_RLS_WATCH; i++) {
		unsigned char hdr[16];
		uint64_t next_buf = 0, next_sl = 0;
		uint32_t pair = 0;
		unsigned j;
		unsigned n_live = 0;
		char hex0[17];
		char hex1[17];
		char hex2[17];
		uint32_t pref[12], pst[12];
		long nr;
		int ping_why;

		if (dtape_rls_watch_tab[i].size != 131072) {
			continue;
		}
		n128++;
		for (j = 0; j < dtape_rls_watch_n && j < DTAPE_RLS_WATCH; j++) {
			if (dtape_rls_watch_tab[j].memfd != dtape_rls_watch_tab[i].memfd) {
				continue;
			}
			if (dtape_rls_watch_tab[j].nsid == dtape_rls_watch_tab[i].nsid) {
				continue;
			}
			pair = dtape_rls_watch_tab[j].nsid;
			break;
		}
		memset(hdr, 0, sizeof(hdr));
		memset(hex0, 0, sizeof(hex0));
		memset(hex1, 0, sizeof(hex1));
		memset(hex2, 0, sizeof(hex2));
		nr = pread(dtape_rls_watch_tab[i].memfd, hdr, 16, 0);
		(void)nr;
		memcpy(&next_buf, hdr, 8);
		memcpy(&next_sl, hdr + 8, 8);
		/*
		 * NodeLinkMemory::AllocateMemory stores next_sl=12 and
		 * next_buf=1. Other 128KB maps (block pages) must not
		 * be treated as invitation primary buffers.
		 */
		if (next_sl < 12 || next_sl > 100000ull ||
		    next_buf == 0 || next_buf > 4096ull) {
			continue;
		}
		ping_why = (why[0] == 'p' && why[1] == 'i');
		if (ping_why && dest_nsid != 0 &&
		    dtape_rls_watch_tab[i].nsid != cur &&
		    dtape_rls_watch_tab[i].nsid != dest_nsid &&
		    pair != dest_nsid && pair != cur) {
			continue;
		}
		for (pi = 0; pi < 12; pi++) {
			unsigned char slot[16];

			memset(slot, 0, sizeof(slot));
			pread(dtape_rls_watch_tab[i].memfd, slot, 16,
			    0x100 + (long)pi * 0x40);
			memcpy(&pref[pi], slot, 4);
			memcpy(&pst[pi], slot + 4, 4);
			if (pi == 0) {
				dtape_hex16(slot, 8, hex0);
			} else if (pi == 1) {
				dtape_hex16(slot, 8, hex1);
			} else if (pi == 2) {
				dtape_hex16(slot, 8, hex2);
			}
			if (pst[pi] != 0) {
				n_live++;
			}
		}
		nlog++;
		dtape_log_error(
		    "nodelink_invite_v1 why=%s cur=%u dest=%u owner=%u memfd=%d pair=%u va=0x%lx next_buf=%llu next_sl=%llu n_live=%u p0_shm_st=0x%x p1_child_st=0x%x p2_host_st=0x%x p3_st=0x%x p0_installed=%d p1_installed=%d p2_installed=%d sl23_alloc=%d",
		    why, cur, dest_nsid, dtape_rls_watch_tab[i].nsid,
		    dtape_rls_watch_tab[i].memfd, pair,
		    (unsigned long)dtape_rls_watch_tab[i].addr,
		    (unsigned long long)next_buf, (unsigned long long)next_sl,
		    n_live, pst[0], pst[1], pst[2], pst[3],
		    pst[0] != 0, pst[1] != 0, pst[2] != 0, next_sl > 23);
		dtape_log_error(
		    "nodelink_invite_v1 why=%s owner=%u memfd=%d p0_ref=0x%x p1_ref=0x%x p2_ref=0x%x hex0=%s hex1=%s hex2=%s p4_st=0x%x p5_st=0x%x p6_st=0x%x p7_st=0x%x",
		    why, dtape_rls_watch_tab[i].nsid,
		    dtape_rls_watch_tab[i].memfd,
		    pref[0], pref[1], pref[2], hex0, hex1, hex2,
		    pst[4], pst[5], pst[6], pst[7]);
		{
			unsigned char va_hdr[16];
			unsigned char pair_hdr[16];
			uint64_t va_next_sl = 0;
			uint64_t pair_next_sl = 0;
			int va_ok = 0;
			int va_match = 0;
			int pair_ok = 0;
			int pair_match = 0;
			unsigned pj;

			memset(va_hdr, 0, sizeof(va_hdr));
			memset(pair_hdr, 0, sizeof(pair_hdr));
			if (dtape_rls_watch_tab[i].context &&
			    dtape_hooks->task_read_memory) {
				va_ok = dtape_hooks->task_read_memory(
				    dtape_rls_watch_tab[i].context,
				    dtape_rls_watch_tab[i].addr, va_hdr, 16);
				if (va_ok) {
					memcpy(&va_next_sl, va_hdr + 8, 8);
					va_match = (memcmp(hdr, va_hdr, 16) == 0);
				}
			}
			if (pair != 0) {
				for (pj = 0; pj < dtape_rls_watch_n &&
				    pj < DTAPE_RLS_WATCH; pj++) {
					if (dtape_rls_watch_tab[pj].nsid != pair) {
						continue;
					}
					if (dtape_rls_watch_tab[pj].memfd !=
					    dtape_rls_watch_tab[i].memfd) {
						continue;
					}
					if (dtape_rls_watch_tab[pj].context &&
					    dtape_hooks->task_read_memory) {
						pair_ok = dtape_hooks->task_read_memory(
						    dtape_rls_watch_tab[pj].context,
						    dtape_rls_watch_tab[pj].addr,
						    pair_hdr, 16);
						if (pair_ok) {
							memcpy(&pair_next_sl,
							    pair_hdr + 8, 8);
							pair_match = (memcmp(hdr,
							    pair_hdr, 16) == 0);
						}
					}
					break;
				}
			}
			dtape_log_error(
			    "nodelink_invite_v1 why=%s owner=%u memfd=%d va_ok=%d va_match=%d va_next_sl=%llu pair=%u pair_ok=%d pair_match=%d pair_next_sl=%llu memfd_next_sl=%llu",
			    why, dtape_rls_watch_tab[i].nsid,
			    dtape_rls_watch_tab[i].memfd, va_ok, va_match,
			    (unsigned long long)va_next_sl, pair, pair_ok,
			    pair_match, (unsigned long long)pair_next_sl,
			    (unsigned long long)next_sl);
		}
	}
	if (n128 == 0) {
		nlog++;
		dtape_log_error(
		    "nodelink_invite_v1 why=%s cur=%u dest=%u NO_128K_MAP watch_n=%u",
		    why, cur, dest_nsid, dtape_rls_watch_n);
	}
}

/*
 * arch15: 0x180 is portal-2 RLS. 0xffffffff is sentinel, not decaying.
 * The store of 0xfffffffe is a userspace write (watch rls_fe_wp_v1).
 * Flush the mapping so a private/stale view does not hide Chrome's
 * already-written word from the browser at Ping. Do not invent
 * 0xfffffffe. Do not occupancy pwrite. Do not rotate more msgids.
 */
__attribute__((used)) static const char dtape_rls_fe_store_v1[] = "rls_fe_store_v1";

static void
dtape_rls_fe_msync_va(void *context, uintptr_t addr)
{
	uintptr_t page;

	if (context == NULL || addr == 0 || dtape_hooks->task_sync_memory == NULL) {
		return;
	}
	page = (addr + 0x180) & ~(uintptr_t)0xfff;
	(void)dtape_hooks->task_sync_memory(context, page, 0x1000, 4);
}

void
dtape_rls_fe_observe(const char *why, unsigned msgid, uint32_t frag_off)
{
	unsigned i;
	unsigned j;
	uint32_t nsid = 0;
	task_t t = current_task();
	dtape_task_t *dt = NULL;
	static uint32_t last_st[DTAPE_RLS_WATCH];
	static int last_inited;

	(void)dtape_rls_fe_store_v1;
	if (why == NULL) {
		why = "?";
	}
	if (!last_inited) {
		memset(last_st, 0xff, sizeof(last_st));
		last_inited = 1;
	}
	if (t != NULL) {
		dt = dtape_task_for_xnu_task(t);
		if (dt) {
			nsid = dt->saved_pid;
		}
	}
	dtape_rls_wp_drain();
	for (i = 0; i < dtape_rls_watch_n && i < DTAPE_RLS_WATCH; i++) {
		if (dtape_rls_watch_tab[i].size == 131072) {
			dtape_rls_fe_msync_va(dtape_rls_watch_tab[i].context,
			    dtape_rls_watch_tab[i].addr);
		}
	}
	for (i = 0; i < dtape_rls_watch_n && i < DTAPE_RLS_WATCH; i++) {
		unsigned char mbuf[16];
		unsigned char vthis[16];
		unsigned char vpeer[16];
		char mhex[33];
		char thex[33];
		char phex[33];
		uint32_t mst;
		uint32_t tst;
		uint32_t pst;
		int peer_i = -1;
		int paired = 0;
		long nr;
		int this_ok = 0;
		int peer_ok = 0;

		if (dtape_rls_watch_tab[i].size != 131072) {
			continue;
		}
		if (dtape_rls_watch_tab[i].nsid != nsid) {
			continue;
		}
		for (j = 0; j < dtape_rls_watch_n && j < DTAPE_RLS_WATCH; j++) {
			if (dtape_rls_watch_tab[j].memfd != dtape_rls_watch_tab[i].memfd) {
				continue;
			}
			if (dtape_rls_watch_tab[j].nsid == nsid) {
				continue;
			}
			peer_i = (int)j;
			paired = 1;
			break;
		}
		if (!paired) {
			continue;
		}
		memset(mbuf, 0, sizeof(mbuf));
		memset(vthis, 0, sizeof(vthis));
		memset(vpeer, 0, sizeof(vpeer));
		nr = pread(dtape_rls_watch_tab[i].memfd, mbuf, 16, 0x180);
		if (nr != 16) {
			continue;
		}
		if (dtape_rls_watch_tab[i].context && dtape_hooks->task_read_memory) {
			this_ok = dtape_hooks->task_read_memory(dtape_rls_watch_tab[i].context,
			    dtape_rls_watch_tab[i].addr + 0x180, vthis, 16) ? 1 : 0;
		}
		if (dtape_rls_watch_tab[peer_i].context && dtape_hooks->task_read_memory) {
			peer_ok = dtape_hooks->task_read_memory(dtape_rls_watch_tab[peer_i].context,
			    dtape_rls_watch_tab[peer_i].addr + 0x180, vpeer, 16) ? 1 : 0;
		}
		mst = (uint32_t)mbuf[0] | ((uint32_t)mbuf[1] << 8) |
		    ((uint32_t)mbuf[2] << 16) | ((uint32_t)mbuf[3] << 24);
		tst = (uint32_t)vthis[0] | ((uint32_t)vthis[1] << 8) |
		    ((uint32_t)vthis[2] << 16) | ((uint32_t)vthis[3] << 24);
		pst = (uint32_t)vpeer[0] | ((uint32_t)vpeer[1] << 8) |
		    ((uint32_t)vpeer[2] << 16) | ((uint32_t)vpeer[3] << 24);
		dtape_hex16(mbuf, 16, mhex);
		dtape_hex16(vthis, 16, thex);
		dtape_hex16(vpeer, 16, phex);
		if (last_st[i] != mst) {
			dtape_log_error("rls_fe_store_v1 trans why=%s msgid=%u nsid=%u memfd=%d off=0x180 old=0x%x memfd=0x%x this_va=0x%x peer_nsid=%u peer_va=0x%x w1=0x%x w2=0x%x this_ok=%d peer_ok=%d memfd_hex=%s this_hex=%s peer_hex=%s frag=0x%x",
			    why, msgid, nsid, dtape_rls_watch_tab[i].memfd,
			    last_st[i], mst, tst,
			    dtape_rls_watch_tab[peer_i].nsid, pst,
			    (uint32_t)mbuf[4] | ((uint32_t)mbuf[5] << 8) |
			    ((uint32_t)mbuf[6] << 16) | ((uint32_t)mbuf[7] << 24),
			    (uint32_t)mbuf[8] | ((uint32_t)mbuf[9] << 8) |
			    ((uint32_t)mbuf[10] << 16) | ((uint32_t)mbuf[11] << 24),
			    this_ok, peer_ok, mhex, thex, phex, frag_off);
			last_st[i] = mst;
			last_st[peer_i] = mst;
		} else {
			dtape_log_error("rls_fe_store_v1 peek why=%s msgid=%u nsid=%u memfd=%d off=0x180 memfd=0x%x this_va=0x%x peer_nsid=%u peer_va=0x%x w1=0x%x w2=0x%x this_ok=%d peer_ok=%d frag=0x%x",
			    why, msgid, nsid, dtape_rls_watch_tab[i].memfd,
			    mst, tst, dtape_rls_watch_tab[peer_i].nsid, pst,
			    (uint32_t)mbuf[4] | ((uint32_t)mbuf[5] << 8) |
			    ((uint32_t)mbuf[6] << 16) | ((uint32_t)mbuf[7] << 24),
			    (uint32_t)mbuf[8] | ((uint32_t)mbuf[9] << 8) |
			    ((uint32_t)mbuf[10] << 16) | ((uint32_t)mbuf[11] << 24),
			    this_ok, peer_ok, frag_off);
		}
		/*
		 * Occupancy copy gone. Do not task_write_memory the
		 * 16-byte RLS into a stale peer VA. Watch rls_fe_wp_v1
		 * for the userspace 0xfffffffe store.
		 */
		(void)tst;
		(void)pst;
		(void)this_ok;
		(void)peer_ok;
		if (frag_off != 0 && frag_off != 0x180 &&
		    dtape_rls_watch_tab[i].size >= (uint64_t)frag_off + 16) {
			unsigned char fbuf[16];
			char fhex[33];
			uint32_t fst;
			long nrf;

			memset(fbuf, 0, sizeof(fbuf));
			nrf = pread(dtape_rls_watch_tab[i].memfd, fbuf, 16, (long)frag_off);
			dtape_hex16(fbuf, 16, fhex);
			fst = (uint32_t)fbuf[0] | ((uint32_t)fbuf[1] << 8) |
			    ((uint32_t)fbuf[2] << 16) | ((uint32_t)fbuf[3] << 24);
			dtape_log_error("rls_fe_store_v1 frag why=%s msgid=%u nsid=%u memfd=%d off=0x%x status=0x%x nread=%ld hex=%s",
			    why, msgid, nsid, dtape_rls_watch_tab[i].memfd,
			    frag_off, fst, nrf, fhex);
		}
	}
}

/*
 * Fable: decay-before-Ping is the macOS path. Do not poison the 64-byte
 * pool and do not delay TryAllocateRouterLinkState. Bypass RLS lives at
 * 0x180 (initial portal-2). outgoing_length==0 is shared-state lying,
 * not something to paper over by starving AllocateRouterLinkState.
 */
__attribute__((used)) static const char dtape_rls_defer_bypass_off_v1[] = "rls_defer_bypass_off_v1";

#define DTAPE_RLS_DEFER 8
#define DTAPE_RLS_DEFER_NS (2000ull * 1000000ull)
#define DTAPE_RLS_POOL64_OFF 0x400

struct dtape_rls_defer {
	int memfd;
	uint32_t helper_nsid;
	uint32_t saved_hdr;
	int used;
	uint64_t hold_ns;
};

static struct dtape_rls_defer dtape_rls_defer_tab[DTAPE_RLS_DEFER];
static dtape_mutex_t dtape_rls_defer_lock;
static int dtape_rls_defer_lock_inited;

static void
dtape_rls_defer_lock_ensure(void)
{
	if (!dtape_rls_defer_lock_inited) {
		dtape_mutex_init(&dtape_rls_defer_lock);
		dtape_rls_defer_lock_inited = 1;
	}
}

static uint64_t
dtape_rls_defer_now_ns(void)
{
	uint64_t ns = 0;

	absolutetime_to_nanoseconds(mach_absolute_time(), &ns);
	return ns;
}

static void
dtape_rls_defer_write_hdr(int memfd, uint32_t hdr)
{
	unsigned char buf[4];

	buf[0] = (unsigned char)(hdr & 0xff);
	buf[1] = (unsigned char)((hdr >> 8) & 0xff);
	buf[2] = (unsigned char)((hdr >> 16) & 0xff);
	buf[3] = (unsigned char)((hdr >> 24) & 0xff);
	(void)pwrite(memfd, buf, 4, DTAPE_RLS_POOL64_OFF);
}

static int
dtape_rls_defer_read_hdr(int memfd, uint32_t *hdr_out)
{
	unsigned char buf[4];
	long nread;

	memset(buf, 0, sizeof(buf));
	nread = pread(memfd, buf, 4, DTAPE_RLS_POOL64_OFF);
	if (nread != 4) {
		return 0;
	}
	*hdr_out = (uint32_t)buf[0] | ((uint32_t)buf[1] << 8) |
	    ((uint32_t)buf[2] << 16) | ((uint32_t)buf[3] << 24);
	return 1;
}

static uint32_t
dtape_rls_defer_empty_hdr(uint32_t old_hdr)
{
	uint16_t version = (uint16_t)(old_hdr & 0xffff);
	int16_t next = -1;

	version++;
	return (uint32_t)version | ((uint32_t)(uint16_t)next << 16);
}

static void
dtape_rls_defer_restore_slot(struct dtape_rls_defer *slot)
{
	if (!slot->used) {
		return;
	}
	dtape_rls_defer_write_hdr(slot->memfd, slot->saved_hdr);
	dtape_log_error("rls_defer_bypass_v1 restore helper=%u memfd=%d hdr=0x%x",
	    slot->helper_nsid, slot->memfd, slot->saved_hdr);
	slot->used = 0;
	slot->memfd = -1;
	slot->helper_nsid = 0;
	slot->saved_hdr = 0;
	slot->hold_ns = 0;
}

void
dtape_rls_defer_bypass(uint32_t helper_nsid)
{
	(void)helper_nsid;
	(void)dtape_rls_defer_bypass_off_v1;
	(void)dtape_rls_defer_read_hdr;
	(void)dtape_rls_defer_empty_hdr;
}

#if 0
void
dtape_rls_defer_bypass_poison(uint32_t helper_nsid)
{
	unsigned i;
	unsigned oi;
	int memfds[DTAPE_RLS_WATCH];
	unsigned nfd = 0;
	uint32_t old_hdr;
	uint32_t empty_hdr;
	int slot;
	uint64_t now;

	if (helper_nsid == 0) {
		return;
	}
	dtape_rls_defer_lock_ensure();
	dtape_mutex_lock(&dtape_rls_defer_lock);
	for (i = 0; i < dtape_rls_watch_n && i < DTAPE_RLS_WATCH; i++) {
		if (dtape_rls_watch_tab[i].nsid != helper_nsid) {
			continue;
		}
		if (dtape_rls_watch_tab[i].size != 131072) {
			continue;
		}
		for (oi = 0; oi < nfd; oi++) {
			if (memfds[oi] == dtape_rls_watch_tab[i].memfd) {
				break;
			}
		}
		if (oi == nfd && nfd < DTAPE_RLS_WATCH) {
			memfds[nfd++] = dtape_rls_watch_tab[i].memfd;
		}
	}
	now = dtape_rls_defer_now_ns();
	for (i = 0; i < nfd; i++) {
		slot = -1;
		for (oi = 0; oi < DTAPE_RLS_DEFER; oi++) {
			if (dtape_rls_defer_tab[oi].used &&
			    dtape_rls_defer_tab[oi].memfd == memfds[i]) {
				slot = -2;
				break;
			}
			if (slot < 0 && !dtape_rls_defer_tab[oi].used) {
				slot = (int)oi;
			}
		}
		if (slot < 0) {
			continue;
		}
		if (!dtape_rls_defer_read_hdr(memfds[i], &old_hdr)) {
			continue;
		}
		empty_hdr = dtape_rls_defer_empty_hdr(old_hdr);
		dtape_rls_defer_write_hdr(memfds[i], empty_hdr);
		dtape_rls_defer_tab[slot].memfd = memfds[i];
		dtape_rls_defer_tab[slot].helper_nsid = helper_nsid;
		dtape_rls_defer_tab[slot].saved_hdr = old_hdr;
		dtape_rls_defer_tab[slot].used = 1;
		dtape_rls_defer_tab[slot].hold_ns = now;
		dtape_log_error("rls_defer_bypass_v1 poison helper=%u memfd=%d old=0x%x empty=0x%x",
		    helper_nsid, memfds[i], old_hdr, empty_hdr);
	}
	if (nfd == 0) {
		dtape_log_error("rls_defer_bypass_v1 no_memfd helper=%u watch_n=%u",
		    helper_nsid, dtape_rls_watch_n);
	}
	dtape_mutex_unlock(&dtape_rls_defer_lock);
}
#endif

void
dtape_rls_allow_bypass(uint32_t helper_nsid)
{
	unsigned i;

	dtape_rls_defer_lock_ensure();
	dtape_mutex_lock(&dtape_rls_defer_lock);
	for (i = 0; i < DTAPE_RLS_DEFER; i++) {
		if (!dtape_rls_defer_tab[i].used) {
			continue;
		}
		if (helper_nsid != 0 &&
		    dtape_rls_defer_tab[i].helper_nsid != helper_nsid) {
			continue;
		}
		dtape_rls_defer_restore_slot(&dtape_rls_defer_tab[i]);
	}
	dtape_mutex_unlock(&dtape_rls_defer_lock);
}

void
dtape_rls_allow_bypass_expire(void)
{
	unsigned i;
	uint64_t now;

	dtape_rls_defer_lock_ensure();
	dtape_mutex_lock(&dtape_rls_defer_lock);
	now = dtape_rls_defer_now_ns();
	for (i = 0; i < DTAPE_RLS_DEFER; i++) {
		if (!dtape_rls_defer_tab[i].used) {
			continue;
		}
		if (now - dtape_rls_defer_tab[i].hold_ns < DTAPE_RLS_DEFER_NS) {
			continue;
		}
		dtape_log_error("rls_defer_bypass_v1 expire helper=%u memfd=%d",
		    dtape_rls_defer_tab[i].helper_nsid,
		    dtape_rls_defer_tab[i].memfd);
		dtape_rls_defer_restore_slot(&dtape_rls_defer_tab[i]);
	}
	dtape_mutex_unlock(&dtape_rls_defer_lock);
}

int
dtape_rls_defer_active(uint32_t pid)
{
	unsigned i;
	int active = 0;

	if (pid == 0) {
		return 0;
	}
	dtape_rls_defer_lock_ensure();
	dtape_mutex_lock(&dtape_rls_defer_lock);
	for (i = 0; i < DTAPE_RLS_DEFER; i++) {
		if (dtape_rls_defer_tab[i].used &&
		    dtape_rls_defer_tab[i].helper_nsid == pid) {
			active = 1;
			break;
		}
	}
	dtape_mutex_unlock(&dtape_rls_defer_lock);
	return active;
}

__attribute__((used)) static const char dtape_named_entry_prot_check_v1[] = "dtape_named_entry_prot_check_v1";
__attribute__((used)) static const char dtape_vm_map_named_v1[] = "dtape_vm_map_named_v1";
__attribute__((used)) static const char dtape_vm_map_mask_align_v1[] = "vm_map_mask_align_v1";
__attribute__((used)) static const char dtape_vm_map_mask_align_v2[] = "vm_map_mask_align_v2";
__attribute__((used)) static const char dtape_vm_map_mask_align_v3[] = "vm_map_mask_align_v3";
__attribute__((used)) static const char dtape_vm_map_prot_none_keep_v1[] = "vm_map_prot_none_keep_v1";
__attribute__((used)) static const char dtape_vm_map_named_anywhere_noreplace_v2[] = "vm_map_named_anywhere_noreplace_v2";
__attribute__((used)) static const char dtape_vm_remap_fixed_meta_v1[] = "vm_remap_fixed_meta_v1";

/*
 * XNU mach_vm_map mask requires (addr & mask) == 0. PartitionAlloc asks
 * for 2MiB superpages; the anonymous S2C mmap path used to ignore mask,
 * so PA's tagged-pointer walk ImmediateCrashed (ud2 / SIGTRAP) after
 * ipcz msgid 35. Honor mask by mapping size+align then trimming
 * prefix/suffix. Do not reshape existing VMAs.
 */
static uintptr_t dtape_map_anon_mask(vm_map_t map, uint64_t size, int prot, mach_vm_offset_t mask, dtape_memory_flags_t memflags, uintptr_t hint, uint32_t nsid) {
	uint64_t page;
	uint64_t extra;
	uint64_t alloc_size;
	uintptr_t raw;
	uintptr_t aligned;
	uintptr_t alloc_end;
	uintptr_t keep_end;

	(void)dtape_vm_map_mask_align_v1;
	(void)dtape_vm_map_mask_align_v2;
	(void)dtape_vm_map_mask_align_v3;
	(void)dtape_vm_map_prot_none_keep_v1;
	(void)dtape_vm_map_named_anywhere_noreplace_v2;
	page = dtape_page_size();

	/* Bump 2MiB masks to the PA pool stride for 8/16GiB cages, including
	 * lengths that are not 2MiB multiples (16GiB ± 2 superpage guards). */
	{
		uint64_t slop = 8ULL * 1024ULL * 1024ULL;
		uint64_t eight = 1ULL << 33;
		uint64_t sixteen = 1ULL << 34;
		if ((size + slop >= eight && size <= eight + slop) ||
		    (size + slop >= sixteen && size <= sixteen + slop)) {
			if ((mask + 1) < sixteen)
				mask = (mach_vm_offset_t)(sixteen - 1);
		} else if (size >= (2ULL * 1024ULL * 1024ULL) &&
	    (size & ((2ULL * 1024ULL * 1024ULL) - 1ULL)) == 0) {
		uint64_t a = 2ULL * 1024ULL * 1024ULL;
		uint64_t cap = 1ULL << 34;
		while ((a << 1) <= size && (a << 1) <= cap && (size & a) == 0)
			a <<= 1;
		if (a > 1 && (mask + 1) < a)
			mask = (mach_vm_offset_t)(a - 1);
		}
	}

	if (mask == 0 || mask < page - 1) {
		return dtape_hooks->task_allocate_pages(map->dtape_task->context,
		    dtape_byte_count_to_page_count_round_up(size), prot, hint, memflags);
	}

	/* 16GiB cages: probe 1TiB-aligned holes with FIXED_NOREPLACE. A 32GiB
	 * over-map from a high 0x7f… first hit straddled kPtrTagMask. */
	if ((uint64_t)mask + 1 >= (1ULL << 30) &&
	    !(memflags & dtape_memory_flag_fixed)) {
		uint64_t align = (uint64_t)mask + 1;
		uint64_t bases[3];
		uint64_t h;
		int b, n;
		dtape_memory_flags_t probe_flags = memflags | dtape_memory_flag_fixed;

		probe_flags &= ~(dtape_memory_flags_t)dtape_memory_flag_overwrite;
		bases[0] = 1ULL << 40;
		bases[1] = align;
		bases[2] = (1ULL << 40) + 96ULL * align;
		for (b = 0; b < 3; b++) {
			h = bases[b] & ~(align - 1ULL);
			if (h < align)
				h = align;
			for (n = 0; n < 96; n++, h += align) {
				uintptr_t got;

				if (h < align || size > (~0ULL - h) || h >= 0x700000000000ULL)
					break;
				if (align >= (1ULL << 34) && size <= (1ULL << 34) &&
				    (h & ~((1ULL << 34) - 1ULL)) !=
				    ((h + size - 1ULL) & ~((1ULL << 34) - 1ULL)))
					continue;
				got = dtape_hooks->task_allocate_pages(map->dtape_task->context,
				    dtape_byte_count_to_page_count_round_up(size), prot, h, probe_flags);
				if (got == h) {
					dtape_log_error("vm_map_mask_align_v3 nsid=%u probe=0x%lx size=0x%llx mask=0x%llx",
					    nsid, (unsigned long)got, (unsigned long long)size,
					    (unsigned long long)mask);
					return got;
				}
				if (got != 0)
					dtape_hooks->task_free_pages(map->dtape_task->context, got,
					    dtape_byte_count_to_page_count_round_up(size));
			}
		}
	}

	extra = (uint64_t)mask + 1;
	alloc_size = size + extra;
	raw = dtape_hooks->task_allocate_pages(map->dtape_task->context,
	    dtape_byte_count_to_page_count_round_up(alloc_size), prot, 0,
	    memflags & ~(dtape_memory_flags_t)dtape_memory_flag_fixed);
	if (raw == 0) {
		dtape_log_error("vm_map_mask_align_v1 nsid=%u size=0x%llx mask=0x%llx -> shortage",
		    nsid, (unsigned long long)size, (unsigned long long)mask);
		return 0;
	}

	aligned = (raw + (uintptr_t)mask) & ~(uintptr_t)mask;
	alloc_end = raw + (uintptr_t)(dtape_byte_count_to_page_count_round_up(alloc_size) * page);
	keep_end = aligned + (uintptr_t)size;
	if (aligned < raw || keep_end > alloc_end || (aligned & (uintptr_t)mask) != 0) {
		dtape_hooks->task_free_pages(map->dtape_task->context, raw,
		    dtape_byte_count_to_page_count_round_up(alloc_size));
		dtape_log_error("vm_map_mask_align_v1 nsid=%u raw=0x%lx align_fail mask=0x%llx",
		    nsid, (unsigned long)raw, (unsigned long long)mask);
		return 0;
	}

	if (aligned > raw) {
		dtape_task_unmap_bytes(map, raw, (uint64_t)(aligned - raw));
	}
	if (keep_end < alloc_end) {
		dtape_task_unmap_bytes(map, keep_end, (uint64_t)(alloc_end - keep_end));
	}
	dtape_log_error("vm_map_mask_align_v1 nsid=%u raw=0x%lx addr=0x%lx size=0x%llx mask=0x%llx",
	    nsid, (unsigned long)raw, (unsigned long)aligned,
	    (unsigned long long)size, (unsigned long long)mask);
	return aligned;
}

kern_return_t mach_vm_map_external(vm_map_t target_map, mach_vm_offset_t* address, mach_vm_size_t initial_size, mach_vm_offset_t mask, int flags, ipc_port_t port, vm_object_offset_t offset, boolean_t copy, vm_prot_t cur_protection, vm_prot_t max_protection, vm_inherit_t inheritance) {
	dtape_memory_flags_t memflags = 0;
	int prot = 0;
	uintptr_t addr;
	vm_named_entry_t named_entry = NULL;
	vm_map_copy_t named_copy = VM_MAP_COPY_NULL;
	dtape_map_shared_descriptor_t* descriptor = NULL;
	uint64_t map_offset = offset;
	uintptr_t hint;
	unsigned kotype = 0;
	uint32_t nsid = 0;
	kern_return_t kr;

	(void)copy;
	(void)inheritance;

	if (target_map == VM_MAP_NULL || address == NULL) {
		return KERN_INVALID_ARGUMENT;
	}

	if (target_map->dtape_task) {
		nsid = target_map->dtape_task->saved_pid;
	}

	if (cur_protection & VM_PROT_READ) {
		prot |= PROT_READ;
	}
	if (cur_protection & VM_PROT_WRITE) {
		prot |= PROT_WRITE;
	}
	if (cur_protection & VM_PROT_EXECUTE) {
		prot |= PROT_EXEC;
	}
	/*
	 * Anonymous VM_PROT_NONE is a PartitionAlloc cage. Coercing it to RW
	 * made encoded-freelist walks see kPtrTagMask and ImmediateCrash.
	 * Named entries with no VM_PROT bits stay fully mappable, matching XNU.
	 */
	if (prot == 0 && IP_VALID(port)) {
		prot = PROT_READ | PROT_WRITE;
	}

	if (!(flags & VM_FLAGS_ANYWHERE)) {
		memflags |= dtape_memory_flag_fixed;
	}
	if (flags & VM_FLAGS_OVERWRITE) {
		memflags |= dtape_memory_flag_overwrite;
	}

	hint = (uintptr_t)*address;

	if (IP_VALID(port)) {
		kotype = ip_kotype(port);
	}

	if (IP_VALID(port) && kotype == IKOT_NAMED_ENTRY) {
		named_entry = (vm_named_entry_t) ip_get_kobject(port);
		if (named_entry) {
			vm_prot_t entry_prot = named_entry->protection & VM_PROT_ALL;
			/*
			 * MAP_MEM_* flags live in the same permission word.
			 * A create with no VM_PROT bits yields entry_prot=0;
			 * treat that as fully mappable, matching XNU's
			 * "requested must be a subset of entry" when the
			 * entry carries no restriction.
			 */
			if (entry_prot == 0) {
				entry_prot = VM_PROT_ALL;
			}
			if ((entry_prot & max_protection) != max_protection ||
			    (entry_prot & cur_protection) != cur_protection) {
				dtape_log_error("vm_map_named_v1 nsid=%u port=%p kotype=%u nprot=0x%x cur=0x%x max=0x%x size=%llu off=%llu -> INVALID_RIGHT",
				    nsid, port, kotype, (unsigned)named_entry->protection,
				    (unsigned)cur_protection, (unsigned)max_protection,
				    (unsigned long long)named_entry->size,
				    (unsigned long long)offset);
				return KERN_INVALID_RIGHT;
			}
		}
		if (named_entry && named_entry->is_copy) {
			named_copy = named_entry->backing.copy;
			if (named_copy) {
				named_entry_lock(named_entry);
				descriptor = named_copy->dtape_descriptor;
				if (descriptor == NULL) {
					uint64_t attach_size = named_entry->size;
					if (attach_size < named_copy->size) {
						attach_size = named_copy->size;
					}
					if (dtape_named_copy_attach_memfd(named_copy, attach_size) == KERN_SUCCESS) {
						descriptor = named_copy->dtape_descriptor;
						dtape_log_error("vm_map_named_v1 nsid=%u port=%p attached_memfd=%d size=%llu",
						    nsid, port,
						    descriptor ? descriptor->memfd : -1,
						    (unsigned long long)attach_size);
					}
				}
				named_entry_unlock(named_entry);
			}
			map_offset = named_entry->offset + offset;
			if (offset >= named_entry->size) {
				return KERN_INVALID_ARGUMENT;
			}
			if (initial_size == 0) {
				initial_size = named_entry->size - offset;
			}
		}
	}

	if (descriptor) {
		dtape_map_shared_entry_t* shared_entry;
		uint64_t mapped_size;
		uint64_t page_size = dtape_page_size();

		if ((map_offset & (page_size - 1)) != 0) {
			return KERN_INVALID_ARGUMENT;
		}

		if (initial_size == 0) {
			*address = 0;
			return KERN_SUCCESS;
		}

		mapped_size = dtape_round_page(initial_size);

		if (!(memflags & dtape_memory_flag_fixed) && target_map != kernel_map && mapped_size >= 131072) {
			uintptr_t reused = 0;

			dtape_mutex_lock(&target_map->shared_entry_lock);
			if (dtape_map_reuse_named_locked(target_map, descriptor->memfd, mapped_size,
			    dtape_byte_count_to_page_count_round_down(map_offset), prot, &reused)) {
				dtape_mutex_unlock(&target_map->shared_entry_lock);
				dtape_log_error("vm_map_named_v1 nsid=%u port=%p kotype=%u memfd=%d size=%llu off=%llu cur=0x%x max=0x%x kr=0 addr=0x%lx flags=0x%x fixed=0 overwrite=0 hint=0x%lx reused=1",
				    nsid, port, kotype, descriptor->memfd,
				    (unsigned long long)mapped_size, (unsigned long long)map_offset,
				    (unsigned)cur_protection, (unsigned)max_protection,
				    (unsigned long)reused, (unsigned)flags, (unsigned long)hint);
				if (mapped_size >= 0x180 + 16) {
					dtape_rls_coherent_note(target_map, descriptor->memfd, reused, mapped_size);
				}
				*address = reused;
				return KERN_SUCCESS;
			}
			dtape_mutex_unlock(&target_map->shared_entry_lock);
		}

		kr = dtape_map_memfd_aligned(target_map, descriptor->memfd, mapped_size, prot, hint, map_offset, mask, memflags, &addr);
		dtape_log_error("vm_map_named_v1 nsid=%u port=%p kotype=%u memfd=%d size=%llu off=%llu cur=0x%x max=0x%x kr=%d addr=0x%lx flags=0x%x fixed=%d overwrite=%d hint=0x%lx",
		    nsid, port, kotype, descriptor->memfd,
		    (unsigned long long)mapped_size, (unsigned long long)map_offset,
		    (unsigned)cur_protection, (unsigned)max_protection, kr, (unsigned long)addr,
		    (unsigned)flags,
		    (memflags & dtape_memory_flag_fixed) ? 1 : 0,
		    (memflags & dtape_memory_flag_overwrite) ? 1 : 0,
		    (unsigned long)hint);
		if (kr == KERN_SUCCESS && mapped_size >= 4096) {
			unsigned char peek[64];
			long nread;
			int i;
			char hex[129];
			static const char hx[] = "0123456789abcdef";
			uint64_t peek_offs[7] = { 0, 0x180, 0x400, 0x600, 0x680, 0x6c0, 0x740 };
			unsigned po;

			for (po = 0; po < sizeof(peek_offs) / sizeof(peek_offs[0]); po++) {
				if (peek_offs[po] + 64 > mapped_size && peek_offs[po] != 0) {
					continue;
				}
				nread = pread(descriptor->memfd, peek, sizeof(peek), (long)peek_offs[po]);
				if (nread <= 0) {
					continue;
				}
				for (i = 0; i < (int)nread && i < 32; i++) {
					hex[i * 2] = hx[peek[i] >> 4];
					hex[i * 2 + 1] = hx[peek[i] & 0xf];
				}
				hex[((nread > 32) ? 32 : (int)nread) * 2] = 0;
				dtape_log_error("rls_peek_v1 nsid=%u memfd=%d off=0x%llx nread=%ld hex=%s",
				    nsid, descriptor->memfd,
				    (unsigned long long)peek_offs[po], nread, hex);
			}
		}
		if (kr != KERN_SUCCESS) {
			return kr;
		}

		if (target_map != kernel_map) {
			shared_entry = dtape_map_shared_entry_create(addr, mapped_size, dtape_byte_count_to_page_count_round_down(map_offset), descriptor);
			if (!shared_entry) {
				dtape_task_unmap_bytes(target_map, addr, mapped_size);
				return KERN_RESOURCE_SHORTAGE;
			}
			dtape_map_insert_shared_entry(target_map, shared_entry,
			    (memflags & dtape_memory_flag_overwrite) ? 1 : 0);
		}

		if (mapped_size >= 0x180 + 16) {
			dtape_rls_coherent_note(target_map, descriptor->memfd, addr, mapped_size);
		}

		*address = addr;
		return KERN_SUCCESS;
	}

	/*
	 * A valid port that is not a named entry with a memfd is not
	 * anonymous memory. XNU returns KERN_INVALID_OBJECT here; falling
	 * through used to hand ipcz a private mapping of the wrong object.
	 */
	if (IP_VALID(port)) {
		dtape_log_error("vm_map_named_v1 nsid=%u port=%p kotype=%u size=%llu off=%llu -> INVALID_OBJECT (no memfd)",
		    nsid, port, kotype, (unsigned long long)initial_size,
		    (unsigned long long)offset);
		return KERN_INVALID_OBJECT;
	}

	if (target_map == kernel_map) {
		void* mapped = mmap((void*)((flags & VM_FLAGS_ANYWHERE) ? 0 : (uintptr_t)*address), (size_t)initial_size, prot, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
		if (mapped == MAP_FAILED) {
			return KERN_RESOURCE_SHORTAGE;
		}
		addr = (uintptr_t)mapped;
	} else if (flags & VM_FLAGS_ANYWHERE) {
		addr = dtape_map_anon_mask(target_map, initial_size, prot, mask, memflags, 0, nsid);
		if (addr == 0) {
			return KERN_RESOURCE_SHORTAGE;
		}
	} else {
		addr = dtape_hooks->task_allocate_pages(target_map->dtape_task->context, dtape_byte_count_to_page_count_round_up(initial_size), prot, (flags & VM_FLAGS_ANYWHERE) ? 0 : *address, memflags);
		if (addr == 0) {
			return KERN_RESOURCE_SHORTAGE;
		}
	}

	*address = addr;
	return KERN_SUCCESS;
};

kern_return_t mach_vm_msync(vm_map_t map, mach_vm_offset_t address, mach_vm_size_t size, vm_sync_t sync_flags) {
	int linux_flags = 0;

	// TODO: give the Linux bits names/macros

	if (sync_flags & VM_SYNC_ASYNCHRONOUS) {
		linux_flags |= 1 << 0;
	}

	if (sync_flags & VM_SYNC_SYNCHRONOUS) {
		linux_flags |= 1 << 2;
	}

	if (sync_flags & VM_SYNC_INVALIDATE) {
		linux_flags |= 1 << 1;
	}

	if (!dtape_hooks->task_sync_memory(map->dtape_task->context, address, size, linux_flags)) {
		return KERN_FAILURE;
	}

	return KERN_SUCCESS;
};

kern_return_t mach_vm_page_info(vm_map_t map, mach_vm_address_t address, vm_page_info_flavor_t flavor, vm_page_info_t info, mach_msg_type_number_t* count) {
	dtape_stub_unsafe();
};

kern_return_t mach_vm_page_query(vm_map_t map, mach_vm_offset_t offset, int* disposition, int* ref_count) {
	dtape_stub_unsafe();
};

kern_return_t mach_vm_page_range_query(vm_map_t map, mach_vm_offset_t address, mach_vm_size_t size, mach_vm_address_t dispositions_addr, mach_vm_size_t* dispositions_count) {
	dtape_stub_unsafe();
};

kern_return_t mach_vm_protect(vm_map_t map, mach_vm_offset_t start, mach_vm_size_t size, boolean_t set_maximum, vm_prot_t new_protection) {
	// we ignore `set_maximum`

	int prot = 0;

	uintptr_t end_memaddr = mach_vm_round_page(start + size);
	uintptr_t start_memaddr = mach_vm_trunc_page(start);
	size_t protect_size = end_memaddr - start_memaddr;

	if (new_protection & VM_PROT_READ) {
		prot |= PROT_READ;
	}
	if (new_protection & VM_PROT_WRITE) {
		prot |= PROT_WRITE;
	}
	if (new_protection & VM_PROT_EXECUTE) {
		prot |= PROT_EXEC;
	}

	if (!dtape_hooks->task_change_protection(map->dtape_task->context, start_memaddr, dtape_byte_count_to_page_count_round_up(protect_size), prot)) {
		return KERN_FAILURE;
	}

	return KERN_SUCCESS;
};

kern_return_t mach_vm_purgable_control(vm_map_t map, mach_vm_offset_t address, vm_purgable_t control, int* state) {
	dtape_stub_unsafe();
};

kern_return_t mach_vm_read_list(vm_map_t map, mach_vm_read_entry_t data_list, natural_t count) {
	dtape_stub_unsafe();
};

kern_return_t mach_vm_region(vm_map_t map, mach_vm_offset_t* address, mach_vm_size_t* size, vm_region_flavor_t flavor, vm_region_info_t info, mach_msg_type_number_t* count, mach_port_t* object_name) {
	switch (flavor) {
		case VM_REGION_BASIC_INFO:
		case VM_REGION_BASIC_INFO_64: {
			kern_return_t kr = KERN_FAILURE;
			dtape_memory_region_info_t region_info;

			uintptr_t addr_to_check = *address;

			if (!dtape_hooks->task_get_memory_region_info(map->dtape_task->context, addr_to_check, &region_info)) {
				addr_to_check = dtape_hooks->task_get_next_region(map->dtape_task->context, addr_to_check);
				if (addr_to_check == 0) {
					kr = KERN_NO_SPACE;
					goto region_info_out;
				}
				if (!dtape_hooks->task_get_memory_region_info(map->dtape_task->context, addr_to_check, &region_info)) {
					kr = KERN_FAILURE;
					goto region_info_out;
				}
			}

			*address = region_info.start_address;
			*size = region_info.page_count * sysconf(_SC_PAGESIZE);

			if (flavor == VM_REGION_BASIC_INFO_64) {
				vm_region_basic_info_64_t out = (vm_region_basic_info_64_t)info;

				if (*count < VM_REGION_BASIC_INFO_COUNT_64) {
					kr = KERN_INVALID_ARGUMENT;
					goto region_info_out;
				}
				*count = VM_REGION_BASIC_INFO_COUNT_64;

				out->protection = 0;

				if (region_info.protection & dtape_memory_protection_read)
					out->protection |= VM_PROT_READ;
				if (region_info.protection & dtape_memory_protection_write)
					out->protection |= VM_PROT_WRITE;
				if (region_info.protection & dtape_memory_protection_execute)
					out->protection |= VM_PROT_EXECUTE | VM_PROT_READ;
				/* LLDB RX hack: suspended processes map dyld RX segments as RWX.
				 * Apply only when the Linux mapping is not writable so malloc-zone
				 * and PartitionAlloc cage pages keep VM_PROT_WRITE. */
				if ((region_info.protection & dtape_memory_protection_execute) &&
				    !(region_info.protection & dtape_memory_protection_write))
					out->protection = VM_PROT_EXECUTE | VM_PROT_READ;

				out->offset = region_info.map_offset;
				out->shared = region_info.shared;
				out->behavior = VM_BEHAVIOR_DEFAULT;
				out->user_wired_count = 0;
				out->inheritance = 0;
				out->max_protection = VM_PROT_READ | VM_PROT_WRITE | VM_PROT_EXECUTE;
				out->reserved = FALSE;
			} else {
				vm_region_basic_info_t out = (vm_region_basic_info_t)info;

				if (*count < VM_REGION_BASIC_INFO_COUNT) {
					kr = KERN_INVALID_ARGUMENT;
					goto region_info_out;
				}
				*count = VM_REGION_BASIC_INFO_COUNT;

				out->protection = 0;

				if (region_info.protection & dtape_memory_protection_read)
					out->protection |= VM_PROT_READ;
				if (region_info.protection & dtape_memory_protection_write)
					out->protection |= VM_PROT_WRITE;
				if (region_info.protection & dtape_memory_protection_execute)
					out->protection |= VM_PROT_EXECUTE | VM_PROT_READ;
				/* LLDB RX hack: skip writable malloc-zone / PA cage pages. */
				if ((region_info.protection & dtape_memory_protection_execute) &&
				    !(region_info.protection & dtape_memory_protection_write))
					out->protection = VM_PROT_EXECUTE | VM_PROT_READ;

				out->offset = region_info.map_offset;
				out->shared = region_info.shared;
				out->behavior = VM_BEHAVIOR_DEFAULT;
				out->user_wired_count = 0;
				out->inheritance = 0;
				out->max_protection = VM_PROT_READ | VM_PROT_WRITE | VM_PROT_EXECUTE;
				out->reserved = FALSE;
			}

			kr = KERN_SUCCESS;

region_info_out:
			if (object_name)
				*object_name = IP_NULL;

			return kr;
		};
		default:
			dtape_stub_unsafe("Unimplemented flavor");
	}
};

kern_return_t mach_vm_region_recurse(vm_map_t map, mach_vm_address_t* address, mach_vm_size_t* size, uint32_t* depth, vm_region_recurse_info_t info, mach_msg_type_number_t* infoCnt) {
	kern_return_t kr = KERN_FAILURE;
	dtape_memory_region_info_t region_info;

	if (depth != NULL) {
		*depth = 0;
	}

	uintptr_t addr_to_check = *address;

	if (!dtape_hooks->task_get_memory_region_info(map->dtape_task->context, addr_to_check, &region_info)) {
		addr_to_check = dtape_hooks->task_get_next_region(map->dtape_task->context, addr_to_check);
		if (addr_to_check == 0) {
			kr = KERN_NO_SPACE;
			goto out;
		}
		if (!dtape_hooks->task_get_memory_region_info(map->dtape_task->context, addr_to_check, &region_info)) {
			kr = KERN_FAILURE;
			goto out;
		}
	}

	*address = region_info.start_address;
	*size = region_info.page_count * sysconf(_SC_PAGESIZE);

	if (*infoCnt == VM_REGION_SUBMAP_SHORT_INFO_COUNT_64) {
		vm_region_submap_info_64_t out = (vm_region_submap_info_64_t)info;

		memset(out, 0, sizeof(*out));

		if (region_info.protection & dtape_memory_protection_read) {
			out->protection |= VM_PROT_READ;
		}
		if (region_info.protection & dtape_memory_protection_write) {
			out->protection |= VM_PROT_WRITE;
		}
		if (region_info.protection & dtape_memory_protection_execute) {
			out->protection |= VM_PROT_EXECUTE;
		}

		out->offset = region_info.map_offset;
		out->share_mode = region_info.shared ? SM_SHARED : SM_PRIVATE;
		out->max_protection = VM_PROT_READ | VM_PROT_WRITE | VM_PROT_EXECUTE;
	} else {
		// in the LKM, only VM_REGION_SUBMAP_SHORT_INFO_COUNT_64 was implemented and everything was fine,
		// so it's fine to return KERN_INVALID_ARGUMENT here; log a message just in case, though.
		dtape_stub_safe("unsupported structure size");
		kr = KERN_INVALID_ARGUMENT;
	}

	kr = KERN_SUCCESS;

out:
	return kr;
};

static kern_return_t mach_vm_remap_external_shared(vm_map_t target_map, mach_vm_offset_t* address, mach_vm_size_t size, mach_vm_offset_t mask, int flags, vm_map_t src_map, mach_vm_offset_t memory_address, vm_prot_t* cur_protection, vm_prot_t* max_protection, vm_inherit_t inheritance) {
	kern_return_t kr = KERN_SUCCESS;
	int memfd = -1;
	void* mapped_addr = NULL;
	dtape_memory_region_info_t region_info;
	int prot = 0;
	vm_map_address_t target_addr = 0;
	vm_prot_t vm_prot = VM_PROT_NONE;
	dtape_map_shared_descriptor_t* descriptor = NULL;
	dtape_map_shared_entry_t* src_shared_entry = NULL;
	dtape_map_shared_entry_t* target_shared_entry = NULL;
	dtape_map_shared_entry_t* src_existing_entries[8];
	size_t src_existing_entry_count = 0;
	int src_none = 0;

	uintptr_t end_memaddr = mach_vm_round_page(memory_address + size);
	uintptr_t start_memaddr = mach_vm_trunc_page(memory_address);
	size_t map_size = end_memaddr - start_memaddr;

	if (!dtape_hooks->task_get_memory_region_info(src_map->dtape_task->context, memory_address, &region_info)) {
		kr = KERN_FAILURE;
		goto out;
	}

	if (region_info.protection & dtape_memory_protection_read) {
		prot |= PROT_READ;
		vm_prot |= VM_PROT_READ;
	}
	if (region_info.protection & dtape_memory_protection_write) {
		prot |= PROT_WRITE;
		vm_prot |= VM_PROT_WRITE;
	}
	if (region_info.protection & dtape_memory_protection_execute) {
		prot |= PROT_EXEC;
		vm_prot |= VM_PROT_EXECUTE;
	}
	/*
	 * XNU vm_remap copy=FALSE of inaccessible SuperPage metadata
	 * first-commits RW zeros. PROT_NONE here left the island unwritable
	 * so Initialize never stored occupancy.
	 */
	src_none = (prot == 0);
	if (src_none) {
		prot = PROT_READ | PROT_WRITE;
		vm_prot = VM_PROT_READ | VM_PROT_WRITE;
	}

	dtape_mutex_lock(&src_map->shared_entry_lock);

	src_existing_entry_count = dtape_map_find_shared_entries_locked(src_map, start_memaddr, map_size, src_existing_entries, sizeof(src_existing_entries) / sizeof(*src_existing_entries));

	if (src_existing_entry_count == 1 && src_existing_entries[0]->address == start_memaddr && src_existing_entries[0]->size >= map_size) {
		// special case for what LLDB does with dyld info
		dtape_map_shared_descriptor_retain(src_existing_entries[0]->descriptor);
		descriptor = src_existing_entries[0]->descriptor;
		dtape_mutex_unlock(&src_map->shared_entry_lock);
		goto src_setup_done;
	} else if (src_existing_entry_count != 0) {
		// TODO: handle this case gracefully
		dtape_stub_unsafe("Cannot complexly remap existing shared regions yet");
	}

	dtape_mutex_unlock(&src_map->shared_entry_lock);

	memfd = memfd_create("darling-remapped", MFD_CLOEXEC);
	if (memfd < 0) {
		kr = KERN_RESOURCE_SHORTAGE;
		goto out;
	}

	if (ftruncate(memfd, map_size) < 0) {
		kr = KERN_RESOURCE_SHORTAGE;
		goto out;
	}

	mapped_addr = mmap(NULL, map_size, PROT_READ | PROT_WRITE, MAP_SHARED, memfd, 0);
	if (mapped_addr == MAP_FAILED) {
		mapped_addr = NULL;
		kr = KERN_RESOURCE_SHORTAGE;
		goto out;
	}

	descriptor = dtape_map_shared_descriptor_create(memfd, map_size);
	if (!descriptor) {
		kr = KERN_RESOURCE_SHORTAGE;
		goto out;
	}
	memfd = -1; // the descriptor now owns the memfd

	// FIXME: there's a race here between us reading the memory from the source process into the memfd and
	//        when we actually replace the mapping in the source process with our shared version.
	//        in that short window, other threads in the source process may be modifying the region
	//        and any changes they make during that time will be lost when we replace it with our shared version.
	//
	//        even if we refactor this code to perform the memfd creation and setup within the source process,
	//        there would still be a race since we can't actually prevent other threads from accessing that memory.

	kr = copyinmap(src_map, start_memaddr, mapped_addr, map_size);
	if (kr != KERN_SUCCESS) {
		if (!src_none) {
			goto out;
		}
		/* Inaccessible first-commit: Darwin zeros, not KERN_FAILURE. */
		memset(mapped_addr, 0, map_size);
		kr = KERN_SUCCESS;
	}

	if (dtape_hooks->task_map_file(src_map->dtape_task->context, descriptor->memfd, dtape_byte_count_to_page_count_round_up(map_size), prot, start_memaddr, 0, dtape_memory_flag_fixed | dtape_memory_flag_overwrite) != start_memaddr) {
		kr = KERN_FAILURE;
		goto out;
	}

	src_shared_entry = dtape_map_shared_entry_create(start_memaddr, map_size, 0, descriptor);
	if (!src_shared_entry) {
		kr = KERN_RESOURCE_SHORTAGE;
		goto out;
	}

	dtape_map_insert_shared_entry(src_map, src_shared_entry, 1);
	src_shared_entry = NULL; // the map now owns the shared entry

src_setup_done:
	{
		dtape_memory_flags_t tflags = 0;
		uintptr_t thint = 0;

		(void)dtape_vm_remap_fixed_meta_v1;
		if (!(flags & VM_FLAGS_ANYWHERE) && *address != 0) {
			tflags |= dtape_memory_flag_fixed;
			thint = (uintptr_t)*address;
		}
		if (flags & VM_FLAGS_OVERWRITE) {
			tflags |= dtape_memory_flag_overwrite;
		}
		target_addr = dtape_hooks->task_map_file(target_map->dtape_task->context, descriptor->memfd, dtape_byte_count_to_page_count_round_up(map_size), prot, thint, 0, tflags);
		if (!target_addr && (tflags & dtape_memory_flag_fixed)) {
			target_addr = dtape_hooks->task_map_file(target_map->dtape_task->context, descriptor->memfd, dtape_byte_count_to_page_count_round_up(map_size), prot, 0, 0, dtape_memory_flag_none);
		}
	}
	if (!target_addr) {
		kr = KERN_FAILURE;
		goto out;
	}

	target_shared_entry = dtape_map_shared_entry_create(target_addr, map_size, 0, descriptor);
	if (!target_shared_entry) {
		kr = KERN_RESOURCE_SHORTAGE;
		goto out;
	}

	dtape_map_insert_shared_entry(target_map, target_shared_entry,
	    map_size >= 131072 ? 1 : 0);
	target_shared_entry = NULL; // the map now owns the shared entry

	*max_protection = VM_PROT_ALL;
	*cur_protection = vm_prot;
	*address = target_addr;

	if (flags & VM_FLAGS_RETURN_DATA_ADDR) {
		*address += memory_address - start_memaddr;
	}

out:
	if (mapped_addr) {
		if (munmap(mapped_addr, map_size) < 0) {
			dtape_log_error("failed to unmap memfd");
		}
	}

	if (descriptor) {
		dtape_map_shared_descriptor_release(descriptor);
	}

	if (src_shared_entry) {
		dtape_map_shared_entry_destroy(src_shared_entry);
	}

	if (target_shared_entry) {
		dtape_map_shared_entry_destroy(target_shared_entry);
	}

	if (memfd >= 0) {
		close(memfd);
	}

	return kr;
};

kern_return_t mach_vm_remap_external(vm_map_t target_map, mach_vm_offset_t* address, mach_vm_size_t size, mach_vm_offset_t mask, int flags, vm_map_t src_map, mach_vm_offset_t memory_address, boolean_t copy, vm_prot_t* cur_protection, vm_prot_t* max_protection, vm_inherit_t inheritance) {
	kern_return_t kr = KERN_SUCCESS;
	vm_map_copy_t mem_copy = NULL;
	vm_map_address_t addr = 0;
	bool dealloc = false;

	if (!copy) {
		return mach_vm_remap_external_shared(target_map, address, size, mask, flags, src_map, memory_address, cur_protection, max_protection, inheritance);
	}

	kr = vm_map_copyin(src_map, memory_address, size, FALSE, &mem_copy);
	if (kr != KERN_SUCCESS) {
		goto out;
	}

	dtape_memory_flags_t memflags = 0;
	if (!(flags & VM_FLAGS_ANYWHERE)) {
		memflags |= dtape_memory_flag_fixed;
	}
	if (flags & VM_FLAGS_OVERWRITE) {
		memflags |= dtape_memory_flag_overwrite;
	}

	int prot = PROT_READ | PROT_WRITE;

	// TODO: properly determine when to make memory executable by looking at the protection of the source region;
	//       for now, we just always make it executable for compatibility with libobjc's trampolines
	prot |= PROT_EXEC;

	addr = dtape_hooks->task_allocate_pages(target_map->dtape_task->context, dtape_byte_count_to_page_count_round_up(size), prot, (flags & VM_FLAGS_ANYWHERE) ? 0 : *address, memflags);
	if (!addr) {
		kr = KERN_RESOURCE_SHORTAGE;
		goto out;
	}

	dealloc = true;

	kr = vm_map_copy_overwrite(target_map, addr, mem_copy, mem_copy->size, TRUE);
	if (kr != KERN_SUCCESS) {
		goto out;
	}

	dealloc = false;

	// a successful copy-out consumes the copy
	mem_copy = NULL;

	dtape_stub_safe("Determine correct protections for copied memory");
	*max_protection = VM_PROT_ALL;
	// LLDB doesn't like it when we tell it that memory is executable;
	// so don't tell it that it's executable, even if it is
	*cur_protection = VM_PROT_READ | VM_PROT_WRITE;
	*address = addr;

out:
	if (mem_copy) {
		vm_map_copy_discard(mem_copy);
	}
	if (dealloc) {
		dtape_hooks->task_free_pages(target_map->dtape_task->context, addr, dtape_byte_count_to_page_count_round_up(size));
	}
	return kr;
};

// Code copied from xnu/osfmk/vm/vm_user.c
kern_return_t mach_vm_remap_new_external(vm_map_t target_map, mach_vm_offset_t* address, mach_vm_size_t size, mach_vm_offset_t mask, int flags, mach_port_t src_tport, mach_vm_offset_t memory_address, boolean_t copy, vm_prot_t* cur_protection, vm_prot_t* max_protection, vm_inherit_t inheritance) {
	vm_tag_t tag;
	vm_map_offset_t         map_addr;
	kern_return_t           kr;
	vm_map_t src_map;

	flags |= VM_FLAGS_RETURN_DATA_ADDR;
	VM_GET_FLAGS_ALIAS(flags, tag);

	/* filter out any kernel-only flags */
	if (flags & ~VM_FLAGS_USER_REMAP) {
		return KERN_INVALID_ARGUMENT;
	}

	if (target_map == VM_MAP_NULL) {
		return KERN_INVALID_ARGUMENT;
	}

	if ((*cur_protection & ~VM_PROT_ALL) ||
	    (*max_protection & ~VM_PROT_ALL) ||
	    (*cur_protection & *max_protection) != *cur_protection) {
		return KERN_INVALID_ARGUMENT;
	}
	if ((*max_protection & (VM_PROT_WRITE | VM_PROT_EXECUTE)) ==
	    (VM_PROT_WRITE | VM_PROT_EXECUTE)) {
		/*
		 * XXX FBDP TODO
		 * enforce target's "wx" policies
		 */
		return KERN_PROTECTION_FAILURE;
	}

	if (copy || *max_protection == VM_PROT_READ || *max_protection == VM_PROT_NONE) {
		src_map = convert_port_to_map_read(src_tport);
	} else {
		src_map = convert_port_to_map(src_tport);
	}

	if (src_map == VM_MAP_NULL) {
		return KERN_INVALID_ARGUMENT;
	}

	map_addr = (vm_map_offset_t)*address;
	
	// I wasn't able to find an reimplementation of vm_map_remap in darlingserver,
	// so we will use mach_vm_remap_external for the time being.
	kr = mach_vm_remap_external(target_map,
	    &map_addr,
	    size,
	    mask,
	    flags,
	    src_map,
	    memory_address,
	    copy,
	    cur_protection,    /* IN/OUT */
	    max_protection,    /* IN/OUT */
	    inheritance);

	*address = map_addr;
	vm_map_deallocate(src_map);

	if (kr == KERN_SUCCESS) {
		ipc_port_release_send(src_tport);  /* consume on success */
	}
	return kr;
};

kern_return_t mach_vm_wire_external(host_priv_t host_priv, vm_map_t map, mach_vm_offset_t start, mach_vm_size_t size, vm_prot_t access) {
	dtape_stub_unsafe();
};

kern_return_t mach_zone_force_gc(host_t host) {
	dtape_stub_unsafe();
};

kern_return_t mach_zone_get_btlog_records(host_priv_t host, mach_zone_name_t name, zone_btrecord_array_t* recsp, mach_msg_type_number_t* recsCntp) {
	dtape_stub_safe();
	return KERN_FAILURE;
};

kern_return_t mach_zone_get_zlog_zones(host_priv_t host, mach_zone_name_array_t* namesp, mach_msg_type_number_t* namesCntp) {
	dtape_stub_safe();
	return KERN_FAILURE;
};

kern_return_t mach_zone_info(host_priv_t host, mach_zone_name_array_t* namesp, mach_msg_type_number_t* namesCntp, mach_zone_info_array_t* infop, mach_msg_type_number_t* infoCntp) {
	dtape_stub_unsafe();
};

kern_return_t mach_zone_info_for_largest_zone(host_priv_t host, mach_zone_name_t* namep, mach_zone_info_t* infop) {
	dtape_stub_unsafe();
};

kern_return_t mach_zone_info_for_zone(host_priv_t host, mach_zone_name_t name, mach_zone_info_t* infop) {
	dtape_stub_unsafe();
};

kern_return_t vm_map_page_query_internal(vm_map_t target_map, vm_map_offset_t offset, int* disposition, int* ref_count) {
	dtape_stub_unsafe();
};

kern_return_t vm_map_purgable_control(vm_map_t map, vm_map_offset_t address, vm_purgable_t control, int* state) {
	dtape_stub_unsafe();
};

kern_return_t vm_map_region(vm_map_t map, vm_map_offset_t* address, vm_map_size_t* size, vm_region_flavor_t flavor, vm_region_info_t info, mach_msg_type_number_t* count, mach_port_t* object_name) {
	dtape_stub_unsafe();
};

kern_return_t vm_map_region_recurse_64(vm_map_t map, vm_map_offset_t* address, vm_map_size_t* size, natural_t* nesting_depth, vm_region_submap_info_64_t submap_info, mach_msg_type_number_t* count) {
	dtape_stub_unsafe();
};

kern_return_t vm_map_unwire(vm_map_t map, vm_map_offset_t start, vm_map_offset_t end, boolean_t user_wire) {
	dtape_stub_safe();
	return KERN_SUCCESS;
};

kern_return_t vm_map_wire_kernel(vm_map_t map, vm_map_offset_t start, vm_map_offset_t end, vm_prot_t caller_prot, vm_tag_t tag, boolean_t user_wire) {
	dtape_stub_safe();
	return KERN_SUCCESS;
};

kern_return_t vm32__task_wire(vm_map_t map, boolean_t must_wire) {
	dtape_stub_safe();
	return KERN_SUCCESS;
};

kern_return_t vm32__map_exec_lockdown(vm_map_t map) {
	dtape_stub_unsafe();
};

// <copied from="xnu://7195.141.2/osfmk/vm/vm_user.c">

/*
 *	mach_vm_allocate allocates "zero fill" memory in the specfied
 *	map.
 */
kern_return_t
mach_vm_allocate_external(
	vm_map_t                map,
	mach_vm_offset_t        *addr,
	mach_vm_size_t  size,
	int                     flags)
{
	vm_tag_t tag;

	VM_GET_FLAGS_ALIAS(flags, tag);
	return mach_vm_allocate_kernel(map, addr, size, flags, tag);
}

/*
 *	vm_wire -
 *	Specify that the range of the virtual address space
 *	of the target task must not cause page faults for
 *	the indicated accesses.
 *
 *	[ To unwire the pages, specify VM_PROT_NONE. ]
 */
kern_return_t
vm_wire(
	host_priv_t             host_priv,
	vm_map_t                map,
	vm_offset_t             start,
	vm_size_t               size,
	vm_prot_t               access)
{
	kern_return_t           rc;

	if (host_priv == HOST_PRIV_NULL) {
		return KERN_INVALID_HOST;
	}

	if (map == VM_MAP_NULL) {
		return KERN_INVALID_TASK;
	}

	if ((access & ~VM_PROT_ALL) || (start + size < start)) {
		return KERN_INVALID_ARGUMENT;
	}

	if (size == 0) {
		rc = KERN_SUCCESS;
	} else if (access != VM_PROT_NONE) {
		rc = vm_map_wire_kernel(map,
		    vm_map_trunc_page(start,
		    VM_MAP_PAGE_MASK(map)),
		    vm_map_round_page(start + size,
		    VM_MAP_PAGE_MASK(map)),
		    access, VM_KERN_MEMORY_OSFMK,
		    TRUE);
	} else {
		rc = vm_map_unwire(map,
		    vm_map_trunc_page(start,
		    VM_MAP_PAGE_MASK(map)),
		    vm_map_round_page(start + size,
		    VM_MAP_PAGE_MASK(map)),
		    TRUE);
	}
	return rc;
}

/*
 *	mach_vm_deallocate -
 *	deallocates the specified range of addresses in the
 *	specified address map.
 */
kern_return_t
mach_vm_deallocate(
	vm_map_t                map,
	mach_vm_offset_t        start,
	mach_vm_size_t  size)
{
	if ((map == VM_MAP_NULL) || (start + size < start)) {
		return KERN_INVALID_ARGUMENT;
	}

	if (size == (mach_vm_offset_t) 0) {
		return KERN_SUCCESS;
	}

	return vm_map_remove(map,
	           vm_map_trunc_page(start,
	           VM_MAP_PAGE_MASK(map)),
	           vm_map_round_page(start + size,
	           VM_MAP_PAGE_MASK(map)),
	           VM_MAP_REMOVE_NO_FLAGS);
}

/*
 * mach_vm_copy -
 * Overwrite one range of the specified map with the contents of
 * another range within that same map (i.e. both address ranges
 * are "over there").
 */
kern_return_t
mach_vm_copy(
	vm_map_t                map,
	mach_vm_address_t       source_address,
	mach_vm_size_t  size,
	mach_vm_address_t       dest_address)
{
	vm_map_copy_t copy;
	kern_return_t kr;

	if (map == VM_MAP_NULL) {
		return KERN_INVALID_ARGUMENT;
	}

	kr = vm_map_copyin(map, (vm_map_address_t)source_address,
	    (vm_map_size_t)size, FALSE, &copy);

	if (KERN_SUCCESS == kr) {
		if (copy) {
			assertf(copy->size == (vm_map_size_t) size, "Req size: 0x%llx, Copy size: 0x%llx\n", (uint64_t) size, (uint64_t) copy->size);
		}

		kr = vm_map_copy_overwrite(map,
		    (vm_map_address_t)dest_address,
		    copy, (vm_map_size_t) size, FALSE /* interruptible XXX */);

		if (KERN_SUCCESS != kr) {
			vm_map_copy_discard(copy);
		}
	}
	return kr;
}

/*
 * mach_vm_read -
 * Read/copy a range from one address space and return it to the caller.
 *
 * It is assumed that the address for the returned memory is selected by
 * the IPC implementation as part of receiving the reply to this call.
 * If IPC isn't used, the caller must deal with the vm_map_copy_t object
 * that gets returned.
 *
 * JMM - because of mach_msg_type_number_t, this call is limited to a
 * single 4GB region at this time.
 *
 */
kern_return_t
mach_vm_read(
	vm_map_t                map,
	mach_vm_address_t       addr,
	mach_vm_size_t  size,
	pointer_t               *data,
	mach_msg_type_number_t  *data_size)
{
	kern_return_t   error;
	vm_map_copy_t   ipc_address;

	if (map == VM_MAP_NULL) {
		return KERN_INVALID_ARGUMENT;
	}

	if ((mach_msg_type_number_t) size != size) {
		return KERN_INVALID_ARGUMENT;
	}

	error = vm_map_copyin(map,
	    (vm_map_address_t)addr,
	    (vm_map_size_t)size,
	    FALSE,              /* src_destroy */
	    &ipc_address);

	if (KERN_SUCCESS == error) {
		*data = (pointer_t) ipc_address;
		*data_size = (mach_msg_type_number_t) size;
		assert(*data_size == size);
	}
	return error;
}

/*
 * mach_vm_read_overwrite -
 * Overwrite a range of the current map with data from the specified
 * map/address range.
 *
 * In making an assumption that the current thread is local, it is
 * no longer cluster-safe without a fully supportive local proxy
 * thread/task (but we don't support cluster's anymore so this is moot).
 */

kern_return_t
mach_vm_read_overwrite(
	vm_map_t                map,
	mach_vm_address_t       address,
	mach_vm_size_t  size,
	mach_vm_address_t       data,
	mach_vm_size_t  *data_size)
{
	kern_return_t   error;
	vm_map_copy_t   copy;

	if (map == VM_MAP_NULL) {
		return KERN_INVALID_ARGUMENT;
	}

	error = vm_map_copyin(map, (vm_map_address_t)address,
	    (vm_map_size_t)size, FALSE, &copy);

	if (KERN_SUCCESS == error) {
		if (copy) {
			assertf(copy->size == (vm_map_size_t) size, "Req size: 0x%llx, Copy size: 0x%llx\n", (uint64_t) size, (uint64_t) copy->size);
		}

		error = vm_map_copy_overwrite(current_thread()->map,
		    (vm_map_address_t)data,
		    copy, (vm_map_size_t) size, FALSE);
		if (KERN_SUCCESS == error) {
			*data_size = size;
			return error;
		}
		vm_map_copy_discard(copy);
	}
	return error;
}

/*
 * mach_vm_write -
 * Overwrite the specified address range with the data provided
 * (from the current map).
 */
kern_return_t
mach_vm_write(
	vm_map_t                        map,
	mach_vm_address_t               address,
	pointer_t                       data,
	mach_msg_type_number_t          size)
{
	if (map == VM_MAP_NULL) {
		return KERN_INVALID_ARGUMENT;
	}

	return vm_map_copy_overwrite(map, (vm_map_address_t)address,
	           (vm_map_copy_t) data, size, FALSE /* interruptible XXX */);
}

/*
 * mach_destroy_memory_entry:
 *
 * Drops a reference on a memory entry and destroys the memory entry if
 * there are no more references on it.
 * NOTE: This routine should not be called to destroy a memory entry from the
 * kernel, as it will not release the Mach port associated with the memory
 * entry.  The proper way to destroy a memory entry in the kernel is to
 * call mach_memort_entry_port_release() to release the kernel's send-right on
 * the memory entry's port.  When the last send right is released, the memory
 * entry will be destroyed via ipc_kobject_destroy().
 */
void
mach_destroy_memory_entry(
	ipc_port_t      port)
{
	vm_named_entry_t        named_entry;
#if MACH_ASSERT
	assert(ip_kotype(port) == IKOT_NAMED_ENTRY);
#endif /* MACH_ASSERT */
	named_entry = (vm_named_entry_t) ip_get_kobject(port);

	named_entry_lock(named_entry);
	named_entry->ref_count -= 1;

	if (named_entry->ref_count == 0) {
		if (named_entry->is_sub_map) {
			vm_map_deallocate(named_entry->backing.map);
		} else if (named_entry->is_copy) {
			vm_map_copy_discard(named_entry->backing.copy);
		} else if (named_entry->is_object) {
#ifndef __DARLING__
			assert(named_entry->backing.copy->cpy_hdr.nentries == 1);
#endif // __DARLING__
			vm_map_copy_discard(named_entry->backing.copy);
		} else {
			assert(named_entry->backing.copy == VM_MAP_COPY_NULL);
		}

		named_entry_unlock(named_entry);
		named_entry_lock_destroy(named_entry);

#if VM_NAMED_ENTRY_LIST
		lck_mtx_lock_spin(&vm_named_entry_list_lock_data);
		queue_remove(&vm_named_entry_list, named_entry,
		    vm_named_entry_t, named_entry_list);
		assert(vm_named_entry_count > 0);
		vm_named_entry_count--;
		lck_mtx_unlock(&vm_named_entry_list_lock_data);
#endif /* VM_NAMED_ENTRY_LIST */

		kfree(named_entry, sizeof(struct vm_named_entry));
	} else {
		named_entry_unlock(named_entry);
	}
}

// </copied>

// <copied from="xnu://7195.141.2/osfmk/vm/vm_map.c">

void
vm_map_read_deallocate(
	vm_map_read_t      map)
{
	vm_map_deallocate((vm_map_t)map);
}

/*
 *	Routine:	convert_port_entry_to_map
 *	Purpose:
 *		Convert from a port specifying an entry or a task
 *		to a map. Doesn't consume the port ref; produces a map ref,
 *		which may be null.  Unlike convert_port_to_map, the
 *		port may be task or a named entry backed.
 *	Conditions:
 *		Nothing locked.
 */


vm_map_t
convert_port_entry_to_map(
	ipc_port_t      port)
{
	vm_map_t map;
	vm_named_entry_t        named_entry;
	uint32_t        try_failed_count = 0;

	if (IP_VALID(port) && (ip_kotype(port) == IKOT_NAMED_ENTRY)) {
		while (TRUE) {
			ip_lock(port);
			if (ip_active(port) && (ip_kotype(port)
			    == IKOT_NAMED_ENTRY)) {
				named_entry =
				    (vm_named_entry_t) ip_get_kobject(port);
				if (!(lck_mtx_try_lock(&(named_entry)->Lock))) {
					ip_unlock(port);

					try_failed_count++;
					mutex_pause(try_failed_count);
					continue;
				}
				named_entry->ref_count++;
				lck_mtx_unlock(&(named_entry)->Lock);
				ip_unlock(port);
				if ((named_entry->is_sub_map) &&
				    (named_entry->protection
				    & VM_PROT_WRITE)) {
					map = named_entry->backing.map;
#ifndef __DARLING__
					if (map->pmap != PMAP_NULL) {
						if (map->pmap == kernel_pmap) {
							panic("userspace has access "
							    "to a kernel map %p", map);
						}
						pmap_require(map->pmap);
					}
#endif // __DARLING__
				} else {
					mach_destroy_memory_entry(port);
					return VM_MAP_NULL;
				}
				vm_map_reference(map);
				mach_destroy_memory_entry(port);
				break;
			} else {
				return VM_MAP_NULL;
			}
		}
	} else {
		map = convert_port_to_map(port);
	}

	return map;
}

// </copied>
