/*
 * arch15: one hardware watchpoint on the network memfd only
 * (portal-2 RouterLinkState +0x180). Caller (memory.c) arms only
 * NetworkService. Multiplexing 4 fds missed the 0xfffffffe store.
 * Do not invent decaying. Do not patch Comet.
 */
#define _GNU_SOURCE
#include <linux/perf_event.h>
#include <linux/hw_breakpoint.h>
#include <sys/syscall.h>
#include <sys/mman.h>
#include <sys/ioctl.h>
#include <sys/uio.h>
#include <poll.h>
#include <pthread.h>
#include <unistd.h>
#include <fcntl.h>
#include <errno.h>
#include <stdint.h>
#include <string.h>
#include <stdio.h>
#include <stdlib.h>

extern "C" void dtape_log(int level, const char *format, ...);

#define RLS_WP_ERR 3
#define RLS_WP_MAX 48
#define RLS_WP_MMAP_PAGES 8

__attribute__((used)) static const char rls_fe_wp_v1[] = "rls_fe_wp_v1";

struct rls_wp_slot {
	int fd;
	int memfd;
	uint32_t nsid;
	uintptr_t addr;
	void *ring;
	size_t ring_sz;
	uint64_t last_head;
};

static struct rls_wp_slot g_wp[RLS_WP_MAX];
static unsigned g_wp_n;
static pthread_mutex_t g_wp_mu = PTHREAD_MUTEX_INITIALIZER;
static pthread_t g_wp_thr;
static int g_wp_thr_on;
static int g_wp_log_n;

static long
sys_perf_event_open(struct perf_event_attr *attr, pid_t pid, int cpu,
    int group_fd, unsigned long flags)
{
	return syscall(__NR_perf_event_open, attr, pid, cpu, group_fd, flags);
}

static void
rls_wp_maps(uint32_t nsid, uint64_t rip, char *out, size_t n)
{
	char path[64];
	char line[512];
	FILE *fp;
	unsigned long start, end, off;
	char perm[8];
	char file[256];

	if (out == NULL || n == 0) {
		return;
	}
	out[0] = 0;
	snprintf(path, sizeof(path), "/proc/%u/maps", nsid);
	fp = fopen(path, "r");
	if (fp == NULL) {
		snprintf(out, n, "maps_fail");
		return;
	}
	while (fgets(line, sizeof(line), fp)) {
		file[0] = 0;
		if (sscanf(line, "%lx-%lx %7s %lx %*s %*s %255s",
		    &start, &end, perm, &off, file) < 4) {
			continue;
		}
		if (rip >= (uint64_t)start && rip < (uint64_t)end) {
			snprintf(out, n, "%s+0x%llx perm=%s",
			    file[0] ? file : "[anon]",
			    (unsigned long long)(rip - (uint64_t)start + off),
			    perm);
			fclose(fp);
			return;
		}
	}
	fclose(fp);
	snprintf(out, n, "unmapped");
}

static uint32_t
rls_wp_read4(uint32_t nsid, uintptr_t va)
{
	struct iovec local, remote;
	unsigned char buf[4];
	ssize_t n;

	memset(buf, 0, sizeof(buf));
	local.iov_base = buf;
	local.iov_len = 4;
	remote.iov_base = (void *)va;
	remote.iov_len = 4;
	n = process_vm_readv((pid_t)nsid, &local, 1, &remote, 1, 0);
	if (n != 4) {
		return 0;
	}
	return (uint32_t)buf[0] | ((uint32_t)buf[1] << 8) |
	    ((uint32_t)buf[2] << 16) | ((uint32_t)buf[3] << 24);
}

static void
rls_wp_note(struct rls_wp_slot *s, uint64_t rip, uint32_t pid, uint32_t tid,
    uint64_t addr)
{
	char near[320];
	uint32_t w0, w1, w2, w3;
	uintptr_t base;

	(void)rls_fe_wp_v1;
	if (g_wp_log_n >= 256) {
		return;
	}
	g_wp_log_n++;
	base = s->addr + 0x180;
	w0 = rls_wp_read4(s->nsid, base);
	w1 = rls_wp_read4(s->nsid, base + 4);
	w2 = rls_wp_read4(s->nsid, base + 8);
	w3 = rls_wp_read4(s->nsid, base + 12);
	rls_wp_maps(pid ? pid : s->nsid, rip, near, sizeof(near));
	dtape_log(RLS_WP_ERR,
	    "rls_fe_wp_v1 store pid=%u tid=%u nsid=%u memfd=%d off=0x180 va=0x%lx rip=0x%llx addr=0x%llx near=%s w0=0x%x w1=0x%x w2=0x%x w3=0x%x fe=%d",
	    pid, tid, s->nsid, s->memfd, (unsigned long)s->addr,
	    (unsigned long long)rip, (unsigned long long)addr, near,
	    w0, w1, w2, w3, (w0 == 0xfffffffeu || w1 == 0xfffffffeu) ? 1 : 0);
}

static void
rls_wp_consume(struct rls_wp_slot *s)
{
	struct perf_event_mmap_page *meta;
	uint64_t head, tail, mask;
	unsigned char *data;
	size_t data_sz;

	if (s == NULL || s->ring == NULL || s->fd < 0) {
		return;
	}
	meta = (struct perf_event_mmap_page *)s->ring;
	data_sz = s->ring_sz - sysconf(_SC_PAGESIZE);
	data = (unsigned char *)s->ring + sysconf(_SC_PAGESIZE);
	mask = data_sz - 1;
	head = meta->data_head;
	__sync_synchronize();
	tail = s->last_head;
	while (tail != head) {
		struct perf_event_header hdr;
		uint64_t off = tail & mask;
		unsigned char tmp[128];
		size_t i;
		uint64_t rip = 0, tsc = 0, rec_addr = 0;
		uint32_t pid = 0, tid = 0;
		unsigned char *p;

		if (off + sizeof(hdr) <= data_sz) {
			memcpy(&hdr, data + off, sizeof(hdr));
		} else {
			for (i = 0; i < sizeof(hdr); i++) {
				((unsigned char *)&hdr)[i] =
				    data[(off + i) & mask];
			}
		}
		if (hdr.size == 0 || hdr.size > sizeof(tmp)) {
			break;
		}
		if (off + hdr.size <= data_sz) {
			memcpy(tmp, data + off, hdr.size);
		} else {
			for (i = 0; i < hdr.size; i++) {
				tmp[i] = data[(off + i) & mask];
			}
		}
		p = tmp + sizeof(hdr);
		if (hdr.type == PERF_RECORD_SAMPLE) {
			memcpy(&rip, p, 8);
			p += 8;
			memcpy(&pid, p, 4);
			memcpy(&tid, p + 4, 4);
			p += 8;
			memcpy(&tsc, p, 8);
			p += 8;
			memcpy(&rec_addr, p, 8);
			(void)tsc;
			rls_wp_note(s, rip, pid, tid, rec_addr);
		}
		tail += hdr.size;
	}
	s->last_head = head;
	__sync_synchronize();
	meta->data_tail = head;
}

static void *
rls_wp_thread(void *arg)
{
	(void)arg;
	for (;;) {
		struct pollfd pfd[RLS_WP_MAX];
		unsigned n = 0;
		unsigned i;
		int idx[RLS_WP_MAX];

		pthread_mutex_lock(&g_wp_mu);
		for (i = 0; i < g_wp_n && i < RLS_WP_MAX; i++) {
			if (g_wp[i].fd < 0 || g_wp[i].ring == NULL) {
				continue;
			}
			pfd[n].fd = g_wp[i].fd;
			pfd[n].events = POLLIN;
			pfd[n].revents = 0;
			idx[n] = (int)i;
			n++;
		}
		pthread_mutex_unlock(&g_wp_mu);
		if (n == 0) {
			usleep(20000);
			continue;
		}
		if (poll(pfd, n, 200) <= 0) {
			pthread_mutex_lock(&g_wp_mu);
			for (i = 0; i < g_wp_n && i < RLS_WP_MAX; i++) {
				rls_wp_consume(&g_wp[i]);
			}
			pthread_mutex_unlock(&g_wp_mu);
			continue;
		}
		pthread_mutex_lock(&g_wp_mu);
		for (i = 0; i < n; i++) {
			if (pfd[i].revents & (POLLIN | POLLERR | POLLHUP)) {
				rls_wp_consume(&g_wp[idx[i]]);
			}
		}
		pthread_mutex_unlock(&g_wp_mu);
	}
	return NULL;
}

extern "C" void
dtape_rls_wp_drain(void)
{
	unsigned i;

	pthread_mutex_lock(&g_wp_mu);
	for (i = 0; i < g_wp_n && i < RLS_WP_MAX; i++) {
		rls_wp_consume(&g_wp[i]);
	}
	pthread_mutex_unlock(&g_wp_mu);
}

extern "C" void
dtape_rls_wp_arm(uint32_t nsid, int memfd, uintptr_t addr)
{
	struct perf_event_attr pe;
	struct rls_wp_slot *s;
	long fd;
	size_t pg;
	size_t map_sz;
	unsigned i;

	if (nsid == 0 || addr == 0) {
		return;
	}
	pthread_mutex_lock(&g_wp_mu);
	for (i = 0; i < g_wp_n && i < RLS_WP_MAX; i++) {
		if (g_wp[i].nsid == nsid && g_wp[i].memfd == memfd &&
		    g_wp[i].addr == addr) {
			pthread_mutex_unlock(&g_wp_mu);
			return;
		}
	}
	if (g_wp_n >= RLS_WP_MAX) {
		pthread_mutex_unlock(&g_wp_mu);
		return;
	}
	memset(&pe, 0, sizeof(pe));
	pe.type = PERF_TYPE_BREAKPOINT;
	pe.size = sizeof(pe);
	pe.config = 0;
	pe.bp_type = HW_BREAKPOINT_W;
	pe.bp_addr = (unsigned long)(addr + 0x180);
	pe.bp_len = HW_BREAKPOINT_LEN_8;
	pe.sample_period = 1;
	pe.sample_type = PERF_SAMPLE_IP | PERF_SAMPLE_TID | PERF_SAMPLE_TIME |
	    PERF_SAMPLE_ADDR;
	pe.wakeup_events = 1;
	pe.disabled = 0;
	pe.exclude_kernel = 1;
	pe.exclude_hv = 1;
	pe.precise_ip = 2;
	fd = sys_perf_event_open(&pe, (pid_t)nsid, -1, -1, 0);
	if (fd < 0) {
		pe.precise_ip = 0;
		pe.bp_len = HW_BREAKPOINT_LEN_4;
		fd = sys_perf_event_open(&pe, (pid_t)nsid, -1, -1, 0);
	}
	s = &g_wp[g_wp_n];
	memset(s, 0, sizeof(*s));
	s->fd = (int)fd;
	s->memfd = memfd;
	s->nsid = nsid;
	s->addr = addr;
	s->ring = NULL;
	s->ring_sz = 0;
	s->last_head = 0;
	if (fd < 0) {
		dtape_log(RLS_WP_ERR,
		    "rls_fe_wp_v1 perf_fail nsid=%u memfd=%d va=0x%lx errno=%d",
		    nsid, memfd, (unsigned long)addr, errno);
		g_wp_n++;
		pthread_mutex_unlock(&g_wp_mu);
		return;
	}
	pg = (size_t)sysconf(_SC_PAGESIZE);
	map_sz = pg * (1 + RLS_WP_MMAP_PAGES);
	s->ring = mmap(NULL, map_sz, PROT_READ | PROT_WRITE, MAP_SHARED, (int)fd, 0);
	if (s->ring == MAP_FAILED) {
		dtape_log(RLS_WP_ERR,
		    "rls_fe_wp_v1 mmap_fail nsid=%u memfd=%d errno=%d",
		    nsid, memfd, errno);
		s->ring = NULL;
		close((int)fd);
		s->fd = -1;
		g_wp_n++;
		pthread_mutex_unlock(&g_wp_mu);
		return;
	}
	s->ring_sz = map_sz;
	fcntl((int)fd, F_SETFL, O_NONBLOCK);
	ioctl((int)fd, PERF_EVENT_IOC_ENABLE, 0);
	g_wp_n++;
	dtape_log(RLS_WP_ERR,
	    "rls_fe_wp_v1 network-only arm nsid=%u memfd=%d va=0x%lx wp=0x%lx fd=%ld",
	    nsid, memfd, (unsigned long)addr,
	    (unsigned long)(addr + 0x180), fd);
	if (!g_wp_thr_on) {
		g_wp_thr_on = 1;
		pthread_mutex_unlock(&g_wp_mu);
		pthread_create(&g_wp_thr, NULL, rls_wp_thread, NULL);
		pthread_detach(g_wp_thr);
		return;
	}
	pthread_mutex_unlock(&g_wp_mu);
}
