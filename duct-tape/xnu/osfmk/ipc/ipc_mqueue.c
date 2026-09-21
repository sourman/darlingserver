/*
 * Copyright (c) 2000-2007 Apple Inc. All rights reserved.
 *
 * @APPLE_OSREFERENCE_LICENSE_HEADER_START@
 *
 * This file contains Original Code and/or Modifications of Original Code
 * as defined in and that are subject to the Apple Public Source License
 * Version 2.0 (the 'License'). You may not use this file except in
 * compliance with the License. The rights granted to you under the License
 * may not be used to create, or enable the creation or redistribution of,
 * unlawful or unlicensed copies of an Apple operating system, or to
 * circumvent, violate, or enable the circumvention or violation of, any
 * terms of an Apple operating system software license agreement.
 *
 * Please obtain a copy of the License at
 * http://www.opensource.apple.com/apsl/ and read it before using this file.
 *
 * The Original Code and all software distributed under the License are
 * distributed on an 'AS IS' basis, WITHOUT WARRANTY OF ANY KIND, EITHER
 * EXPRESS OR IMPLIED, AND APPLE HEREBY DISCLAIMS ALL SUCH WARRANTIES,
 * INCLUDING WITHOUT LIMITATION, ANY WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE, QUIET ENJOYMENT OR NON-INFRINGEMENT.
 * Please see the License for the specific language governing rights and
 * limitations under the License.
 *
 * @APPLE_OSREFERENCE_LICENSE_HEADER_END@
 */
/*
 * @OSF_FREE_COPYRIGHT@
 */
/*
 * Mach Operating System
 * Copyright (c) 1991,1990,1989 Carnegie Mellon University
 * All Rights Reserved.
 *
 * Permission to use, copy, modify and distribute this software and its
 * documentation is hereby granted, provided that both the copyright
 * notice and this permission notice appear in all copies of the
 * software, derivative works or modified versions, and any portions
 * thereof, and that both notices appear in supporting documentation.
 *
 * CARNEGIE MELLON ALLOWS FREE USE OF THIS SOFTWARE IN ITS "AS IS"
 * CONDITION.  CARNEGIE MELLON DISCLAIMS ANY LIABILITY OF ANY KIND FOR
 * ANY DAMAGES WHATSOEVER RESULTING FROM THE USE OF THIS SOFTWARE.
 *
 * Carnegie Mellon requests users of this software to return to
 *
 *  Software Distribution Coordinator  or  Software.Distribution@CS.CMU.EDU
 *  School of Computer Science
 *  Carnegie Mellon University
 *  Pittsburgh PA 15213-3890
 *
 * any improvements or extensions that they make and grant Carnegie Mellon
 * the rights to redistribute these changes.
 */
/*
 */
/*
 *	File:	ipc/ipc_mqueue.c
 *	Author:	Rich Draves
 *	Date:	1989
 *
 *	Functions to manipulate IPC message queues.
 */
/*
 * NOTICE: This file was modified by SPARTA, Inc. in 2006 to introduce
 * support for mandatory and extensible security protections.  This notice
 * is included in support of clause 2.2 (b) of the Apple Public License,
 * Version 2.0.
 */


#include <mach/port.h>
#include <mach/message.h>
#include <mach/sync_policy.h>

#include <kern/assert.h>
#include <kern/counter.h>
#include <kern/sched_prim.h>
#include <kern/ipc_kobject.h>
#include <kern/ipc_mig.h>       /* XXX - for mach_msg_receive_continue */
#include <kern/misc_protos.h>
#include <kern/task.h>
#include <kern/thread.h>
#include <kern/waitq.h>

#include <ipc/port.h>
#include <ipc/ipc_mqueue.h>
#include <ipc/ipc_kmsg.h>
#include <ipc/ipc_port.h>
#include <ipc/ipc_pset.h>
#include <ipc/ipc_space.h>

#if MACH_FLIPC
#include <ipc/flipc.h>
#endif

#ifdef __LP64__
#include <vm/vm_map.h>
#endif

#include <sys/event.h>
#include <stddef.h>

#ifdef __DARLING__
#include <kern/kalloc.h>
#include <kern/thread.h>
#include <darlingserver/duct-tape/log.h>
#include <darlingserver/duct-tape/task.h>
#include <darlingserver/duct-tape/thread.h>
#include <darlingserver/duct-tape/locks.h>
extern int usleep(unsigned int);
extern void dtape_kqchan_notify_mqueue(ipc_mqueue_t mqueue);
extern bool dtape_thread_is_kqchan_waitq_waiter(thread_t thread);
extern int dtape_ipcz_peek(const mach_msg_header_t *hdr, int user_hdr,
    unsigned *msgid_out, unsigned *seq_out, uint64_t *sublink_out);
extern int dtape_host_cmdline_is_gpu(unsigned nsid);
extern int dtape_host_cmdline_is_network(unsigned nsid);
extern int dtape_gpu_alive_10s_crgpu(void);
extern void dtape_gpu_hs20_arm_after_alive(uint32_t dest_pid);
extern void dtape_net_ping_arm_after_alive(uint32_t dest_pid);
extern int dtape_ipcz_is_childprocess_ping(const mach_msg_header_t *hdr, int user_hdr);
extern unsigned dtape_mqueue_kqchan_owner_pid(ipc_mqueue_t mqueue);
extern unsigned dtape_mqueue_kqchan_network_owner_pid(ipc_mqueue_t mqueue);
extern void dtape_rls_defer_bypass(uint32_t helper_nsid);
extern void dtape_rls_allow_bypass(uint32_t helper_nsid);
extern void dtape_rls_allow_bypass_expire(void);
extern int dtape_rls_defer_active(uint32_t pid);
extern int dtape_rls_portal2_status(uint32_t nsid, uint32_t *status_out);
#endif

extern char     *proc_name_address(void *p);

int ipc_mqueue_full;            /* address is event for queue space */
int ipc_mqueue_rcv;             /* address is event for message arrival */

#ifdef __DARLING__
/*
 * Hold BypassPeerWithLink (msgid 34) until ChildProcess Ping seq 4 is
 * copyout'd to the browser. Sender-side decay starts before the send
 * returns, but StopProxyingToLocalPeer (35) is what finishes decay /
 * Deactivate. Delivering 35 before seq 4 copyout drops Ping on the
 * decaying LocalRouterLink (no reply on 52/56).
 *
 * Do not block the send syscall (same Chrome_IOThread receives Ping).
 * Park the kmsg after copyin; release on seq 4 copyout from that dest.
 */
__attribute__((used)) const char dtape_bypass34_hold_v1[] = "bypass34_hold_v1";
__attribute__((used)) const char dtape_bypass34_hold_off_v1[] = "bypass34_hold_off_v1";
__attribute__((used)) const char dtape_mqueue_fifo_v1[] = "mqueue_fifo_v1";
__attribute__((used)) const char dtape_mqueue_fifo_head_v1[] =
	"mqueue_fifo_head_v1";
__attribute__((used)) const char dtape_mqueue_remain_count_v1[] = "mqueue_remain_count_v1";

#define DTAPE_HOLD34_MAX 24
#define DTAPE_SEQ4_MAX 32
#define DTAPE_HOLD34_NS (500ull * 1000000ull)
#define DTAPE_MEMHOLD_NS (2000ull * 1000000ull)

struct dtape_hold34 {
	ipc_kmsg_t kmsg;
	ipc_mqueue_t mqueue;
	uint32_t dest_pid;
	uint32_t src_pid;
	uint64_t hold_ns;
	int used;
};

static struct dtape_hold34 dtape_hold34_slots[DTAPE_HOLD34_MAX];
static ipc_kmsg_t dtape_seq4_kmsg[DTAPE_SEQ4_MAX];
static uint32_t dtape_seq4_pid[DTAPE_SEQ4_MAX];
static uint32_t dtape_seq4_seen[DTAPE_SEQ4_MAX];
static unsigned dtape_seq4_seen_n;
static uint32_t dtape_ping_wait_sender[DTAPE_SEQ4_MAX];
static uint32_t dtape_ping_wait_recip[DTAPE_SEQ4_MAX];
static thread_t dtape_ping_wait_thread[DTAPE_SEQ4_MAX];
static unsigned dtape_ping_wait_n;
static dtape_mutex_t dtape_hold34_lock;
static int dtape_hold34_lock_inited;
static __thread int dtape_hold34_repost;

static void
dtape_hold34_lock_ensure(void)
{
	if (!dtape_hold34_lock_inited) {
		dtape_mutex_init(&dtape_hold34_lock);
		dtape_hold34_lock_inited = 1;
	}
}

static uint64_t
dtape_hold34_now_ns(void)
{
	uint64_t ns = 0;

	absolutetime_to_nanoseconds(mach_absolute_time(), &ns);
	return ns;
}

static uint32_t
dtape_mqueue_dest_pid(ipc_mqueue_t mqueue)
{
	ipc_object_t object = imq_to_object(mqueue);

	if (io_otype(object) != IOT_PORT) {
		return 0;
	}
	{
		ipc_port_t port = ip_from_mq(mqueue);

		if (port->ip_receiver && port->ip_receiver->is_task) {
			dtape_task_t *task = dtape_task_for_xnu_task(port->ip_receiver->is_task);

			if (task) {
				return task->saved_pid;
			}
		}
	}
	return 0;
}

static uint32_t
dtape_current_pid(void)
{
	task_t t = current_task();
	dtape_task_t *dt;

	if (t == NULL) {
		return 0;
	}
	dt = dtape_task_for_xnu_task(t);
	return dt ? dt->saved_pid : 0;
}

static int
dtape_seq4_seen_pid(uint32_t pid)
{
	unsigned i;

	for (i = 0; i < dtape_seq4_seen_n && i < DTAPE_SEQ4_MAX; i++) {
		if (dtape_seq4_seen[i] == pid) {
			return 1;
		}
	}
	return 0;
}

static void
dtape_seq4_mark_seen(uint32_t pid)
{
	if (pid == 0 || dtape_seq4_seen_pid(pid)) {
		return;
	}
	if (dtape_seq4_seen_n < DTAPE_SEQ4_MAX) {
		dtape_seq4_seen[dtape_seq4_seen_n++] = pid;
	}
}

static void dtape_hold34_do_release(uint32_t dest_pid, int expire_all);
static void dtape_sit_until_34_expire(void);
static int dtape_sit_inbound20_until_34(ipc_mqueue_t mqueue, ipc_kmsg_t kmsg);

void
dtape_bypass34_note_seq4_copyin(ipc_kmsg_t kmsg)
{
	unsigned i;
	uint32_t pid;

	if (kmsg == IKM_NULL) {
		return;
	}
	pid = dtape_current_pid();
	dtape_hold34_lock_ensure();
	dtape_mutex_lock(&dtape_hold34_lock);
	for (i = 0; i < DTAPE_SEQ4_MAX; i++) {
		if (dtape_seq4_kmsg[i] == NULL) {
			dtape_seq4_kmsg[i] = kmsg;
			dtape_seq4_pid[i] = pid;
			break;
		}
	}
	dtape_mutex_unlock(&dtape_hold34_lock);
	(void)dtape_rls_defer_bypass;
	(void)pid;
}

void
dtape_bypass34_note_seq4_copyout(ipc_kmsg_t kmsg)
{
	unsigned i;
	uint32_t sender = 0;
	uint32_t recip;

	recip = dtape_current_pid();
	dtape_hold34_lock_ensure();
	dtape_mutex_lock(&dtape_hold34_lock);
	for (i = 0; i < DTAPE_SEQ4_MAX; i++) {
		if (dtape_seq4_kmsg[i] == kmsg) {
			sender = dtape_seq4_pid[i];
			dtape_seq4_kmsg[i] = NULL;
			dtape_seq4_pid[i] = 0;
			break;
		}
	}
	if (sender && recip && dtape_ping_wait_n < DTAPE_SEQ4_MAX) {
		dtape_ping_wait_sender[dtape_ping_wait_n] = sender;
		dtape_ping_wait_recip[dtape_ping_wait_n] = recip;
		dtape_ping_wait_thread[dtape_ping_wait_n] = current_thread();
		dtape_ping_wait_n++;
	}
	if (sender) {
		dtape_seq4_mark_seen(sender);
	}
	dtape_mutex_unlock(&dtape_hold34_lock);
	if (sender) {
		dtape_log_error("bypass34_hold_v1 ping_copyout sender_pid=%u recip=%u",
		    sender, recip);
		/* seq4_seen[sender] releases browser→helper 34 so 52/56 can
		 * come up. helper→browser 34 stays held (src=sender) until
		 * reply_copyin or 500ms expire. Do not post from copyout. */
	}
}

void
dtape_bypass34_note_reply_copyin(ipc_kmsg_t kmsg)
{
	unsigned i;
	unsigned msgid = 0, seq = 0;
	uint64_t sub = 0;
	uint32_t pid;
	int hit = 0;
	uint32_t sender = 0;
	thread_t self;

	if (kmsg == IKM_NULL || kmsg->ikm_header == NULL) {
		return;
	}
	if (!dtape_ipcz_peek(kmsg->ikm_header, 0, &msgid, &seq, &sub) ||
	    msgid != 20 || sub != 2) {
		return;
	}
	pid = dtape_current_pid();
	self = current_thread();
	if (pid == 0 || self == THREAD_NULL) {
		return;
	}
	dtape_hold34_lock_ensure();
	dtape_mutex_lock(&dtape_hold34_lock);
	for (i = 0; i < dtape_ping_wait_n && i < DTAPE_SEQ4_MAX; ) {
		if (dtape_ping_wait_recip[i] == pid &&
		    dtape_ping_wait_thread[i] == self) {
			sender = dtape_ping_wait_sender[i];
			dtape_seq4_mark_seen(sender);
			dtape_ping_wait_sender[i] = dtape_ping_wait_sender[dtape_ping_wait_n - 1];
			dtape_ping_wait_recip[i] = dtape_ping_wait_recip[dtape_ping_wait_n - 1];
			dtape_ping_wait_thread[i] = dtape_ping_wait_thread[dtape_ping_wait_n - 1];
			dtape_ping_wait_n--;
			hit = 1;
			continue;
		}
		i++;
	}
	dtape_mutex_unlock(&dtape_hold34_lock);
	if (hit) {
		dtape_log_error("bypass34_hold_v1 reply_copyin recip=%u sender=%u",
		    pid, sender);
		dtape_rls_allow_bypass(sender);
	}
}

static void
dtape_hold34_do_release(uint32_t dest_pid, int expire_all)
{
	struct dtape_hold34 local[DTAPE_HOLD34_MAX];
	unsigned n = 0;
	unsigned i;
	uint64_t now;

	dtape_hold34_lock_ensure();
	dtape_mutex_lock(&dtape_hold34_lock);
	now = dtape_hold34_now_ns();
	for (i = 0; i < DTAPE_HOLD34_MAX; i++) {
		int take = 0;

		if (!dtape_hold34_slots[i].used) {
			continue;
		}
		if (expire_all) {
			take = 1;
		} else if (dest_pid != 0 && dtape_hold34_slots[i].dest_pid == dest_pid) {
			take = 1;
		} else if (dtape_seq4_seen_pid(dtape_hold34_slots[i].dest_pid)) {
			take = 1;
		} else if (now - dtape_hold34_slots[i].hold_ns >= DTAPE_HOLD34_NS) {
			take = 1;
		}
		if (!take) {
			continue;
		}
		local[n++] = dtape_hold34_slots[i];
		dtape_hold34_slots[i].used = 0;
		dtape_hold34_slots[i].kmsg = IKM_NULL;
		dtape_hold34_slots[i].mqueue = IMQ_NULL;
	}
	dtape_mutex_unlock(&dtape_hold34_lock);

	for (i = 0; i < n; i++) {
		ipc_mqueue_t mq = local[i].mqueue;
		ipc_kmsg_t kmsg = local[i].kmsg;

		if (mq == IMQ_NULL || kmsg == IKM_NULL) {
			continue;
		}
		imq_lock(mq);
		if (imq_valid(mq)) {
			mq->imq_msgcount++;
		}
		imq_unlock(mq);
		dtape_hold34_repost++;
		ipc_mqueue_post(mq, kmsg, MACH_SEND_ALWAYS);
		dtape_hold34_repost--;
		dtape_log_error("rls_defer_bypass_v1 memhold_release dest_pid=%u expire=%d",
		    local[i].dest_pid, expire_all);
	}
}

static int
dtape_bypass34_try_hold(ipc_mqueue_t mqueue, ipc_kmsg_t kmsg)
{
	unsigned msgid = 0, seq = 0;
	uint64_t sub = 0;
	uint32_t dest_pid;
	uint32_t src_pid;
	unsigned i;
	int slot = -1;

	/*
	 * StartSelfBypassToLocalPeer decays LocalRouterLink in-process
	 * before msgid 34 copyin. Parking 34 cannot rewind that.
	 * RequestMemory/ProvideMemory holds stalled the UI. Never hold 34.
	 * Pool poison (rls_defer_bypass_v1) remains the delay for TryAllocate.
	 */
	dtape_rls_allow_bypass_expire();
	dtape_sit_until_34_expire();
	(void)mqueue;
	(void)kmsg;
	(void)msgid;
	(void)seq;
	(void)sub;
	(void)dest_pid;
	(void)src_pid;
	(void)i;
	(void)slot;
	(void)dtape_bypass34_hold_off_v1;
	return 0;
}

/*
 * Fable inbound flush: helper sl=2 msgid 20 (Accept seq 0–3 + Ping)
 * must sit on the browser Channel while IOThread SENDs Bypass 34.
 * Storage got 34 before that burst; network flooded 20s first, so
 * IOThread copyout'd them and never sent 34 — portal-2 RLS stayed
 * kUnstable. Enqueue honestly. Skip only the wake. Helper knote
 * still notifies (hold_off). Do not hold 34. 21ms then notify.
 */
__attribute__((used)) static const char dtape_rls_sit_until_34_v1[] =
	"rls_sit_until_34_v1";

#define DTAPE_SIT34_MAX 8
#define DTAPE_SIT34_NS (21ull * 1000000ull)

struct dtape_sit34 {
	ipc_mqueue_t mqueue;
	uint32_t dest_pid;
	uint32_t src_pid;
	uint64_t hold_ns;
	int used;
};

static struct dtape_sit34 dtape_sit34_slots[DTAPE_SIT34_MAX];
static dtape_mutex_t dtape_sit34_lock;
static int dtape_sit34_lock_inited;

static void
dtape_sit34_lock_ensure(void)
{
	if (!dtape_sit34_lock_inited) {
		dtape_mutex_init(&dtape_sit34_lock);
		dtape_sit34_lock_inited = 1;
	}
}

static void
dtape_sit_until_34_expire(void)
{
	ipc_mqueue_t local[DTAPE_SIT34_MAX];
	uint32_t dest[DTAPE_SIT34_MAX];
	uint32_t src[DTAPE_SIT34_MAX];
	unsigned n = 0;
	unsigned i;
	uint64_t now;

	dtape_sit34_lock_ensure();
	dtape_mutex_lock(&dtape_sit34_lock);
	now = dtape_hold34_now_ns();
	for (i = 0; i < DTAPE_SIT34_MAX; i++) {
		if (!dtape_sit34_slots[i].used) {
			continue;
		}
		if (now - dtape_sit34_slots[i].hold_ns < DTAPE_SIT34_NS) {
			continue;
		}
		local[n] = dtape_sit34_slots[i].mqueue;
		dest[n] = dtape_sit34_slots[i].dest_pid;
		src[n] = dtape_sit34_slots[i].src_pid;
		dtape_sit34_slots[i].used = 0;
		dtape_sit34_slots[i].mqueue = IMQ_NULL;
		n++;
	}
	dtape_mutex_unlock(&dtape_sit34_lock);

	for (i = 0; i < n; i++) {
		dtape_log_error(
		    "rls_sit_until_34_v1 expire dest_pid=%u src_pid=%u",
		    dest[i], src[i]);
		if (local[i] != IMQ_NULL) {
			dtape_kqchan_notify_mqueue(local[i]);
		}
	}
}

static int
dtape_sit_inbound20_until_34(ipc_mqueue_t mqueue, ipc_kmsg_t kmsg)
{
	unsigned msgid = 0, seq = 0;
	uint64_t sub = 0;
	uint32_t dest_pid;
	uint32_t src_pid;
	uint32_t status = 0;
	unsigned i;
	int slot = -1;
	int already = 0;

	(void)dtape_rls_sit_until_34_v1;
	/*
	 * Fable: rls_sit_until_34 did not fire; helper sent 34
	 * itself. Do not sit/hold inbound 20s as fake sequencing.
	 */
	return 0;
	if (kmsg == IKM_NULL || kmsg->ikm_header == NULL || mqueue == IMQ_NULL) {
		return 0;
	}
	if (!dtape_ipcz_peek(kmsg->ikm_header, 0, &msgid, &seq, &sub) ||
	    msgid != 20 || sub != 2) {
		return 0;
	}
	src_pid = dtape_current_pid();
	dest_pid = dtape_mqueue_dest_pid(mqueue);
	if (!dtape_host_cmdline_is_network(src_pid)) {
		return 0;
	}
	if (dtape_host_cmdline_is_network(dest_pid) ||
	    dtape_host_cmdline_is_gpu(dest_pid)) {
		return 0;
	}
	if (!dtape_rls_portal2_status(src_pid, &status) || status != 0) {
		return 0;
	}

	dtape_sit34_lock_ensure();
	dtape_mutex_lock(&dtape_sit34_lock);
	for (i = 0; i < DTAPE_SIT34_MAX; i++) {
		if (dtape_sit34_slots[i].used &&
		    dtape_sit34_slots[i].mqueue == mqueue) {
			already = 1;
			break;
		}
		if (slot < 0 && !dtape_sit34_slots[i].used) {
			slot = (int)i;
		}
	}
	if (!already && slot >= 0) {
		dtape_sit34_slots[slot].mqueue = mqueue;
		dtape_sit34_slots[slot].dest_pid = dest_pid;
		dtape_sit34_slots[slot].src_pid = src_pid;
		dtape_sit34_slots[slot].hold_ns = dtape_hold34_now_ns();
		dtape_sit34_slots[slot].used = 1;
	}
	dtape_mutex_unlock(&dtape_sit34_lock);

	if (!already && slot < 0) {
		return 0;
	}
	dtape_log_error(
	    "rls_sit_until_34_v1 sit dest_pid=%u src_pid=%u seq=%u status=0x%x already=%d",
	    dest_pid, src_pid, seq, status, already);
	return 1;
}

__attribute__((used)) const char dtape_gpu_channel_nopost_v1[] =
	"kqchan_gpu_channel_nopost_v1";
__attribute__((used)) const char dtape_gpu_bind_through_v1[] =
	"kqchan_gpu_bind_through_v1";
__attribute__((used)) const char dtape_gpu_hs_through_v1[] =
	"kqchan_gpu_hs_through_v1";
__attribute__((used)) const char dtape_gpu_hs20_drain_v1[] =
	"kqchan_gpu_hs20_drain_v1";
__attribute__((used)) const char dtape_gpu_hs35_after20_v1[] =
	"kqchan_gpu_hs35_after20_v1";
__attribute__((used)) const char dtape_gpu_hs20_until_alive_v1[] =
	"kqchan_gpu_hs20_until_alive_v1";
__attribute__((used)) const char dtape_gpu_hs35_delay_alive_v1[] =
	"kqchan_gpu_hs35_after20_v1 delay";
__attribute__((used)) const char dtape_gpu_hs20_park_cap_v1[] =
	"kqchan_gpu_hs20_park_cap_v1";
__attribute__((used)) const char dtape_net_ping_dest_v1[] =
	"kqchan_net_ping_dest_v1";
__attribute__((used)) const char dtape_helper_rx_ping_v1[] =
	"helper_rx_ping_v1";
__attribute__((used)) const char dtape_net_remain_v1[] =
	"kqchan_net_remain_v1";
__attribute__((used)) const char dtape_handshake_drain_bind_v1[] =
	"handshake_drain_bind_v1";
__attribute__((used)) const char dtape_handshake_drain_bind_browser_v1[] =
	"handshake_drain_bind_v1 browser Channel";
__attribute__((used)) const char dtape_handshake_bind_burst_v1[] =
	"handshake_bind_burst_v1";
__attribute__((used)) const char dtape_handshake_drain_offer_v1[] =
	"handshake_drain_offer_v1";
__attribute__((used)) const char dtape_handshake_drain_34_v1[] =
	"handshake_drain_34_v1";
__attribute__((used)) const char dtape_handshake_drain_34_rot_v1[] =
	"rotate msgid 34 ahead of inbound 20s";
__attribute__((used)) const char dtape_handshake_drain_34_browser_v1[] =
	"rotate msgid 34 after Bind ahead of inbound 20s browser Channel";
__attribute__((used)) const char dtape_handshake_drain_34_reverted_v1[] =
	"rotate-34-ahead-of-20s reverted";
__attribute__((used)) const char dtape_rls_fe_ahead_v1[] =
	"rls_fe_ahead_v1";
__attribute__((used)) const char dtape_rls_fe_ahead_rot_v1[] =
	"rotate 35/36 ahead of inbound 20s";
__attribute__((used)) const char dtape_rls_fe_ahead_browser_v1[] =
	"rls_fe_ahead_v1 browser Channel";
__attribute__((used)) const char dtape_channelmac_nested_timeout0_v1[] =
	"channelmac_nested_timeout0_v1";

extern void dtape_channel_ipcz_dump(const char *dir, mach_msg_header_t *hdr,
    int user_hdr, int user_desc);
extern mach_msg_return_t mach_msg_receive_results(mach_msg_size_t *sizep);
extern kern_return_t mach_vm_allocate_kernel(vm_map_t map,
    mach_vm_offset_t *addr, mach_vm_size_t size, int flags, vm_tag_t tag);

static ipc_mqueue_t dtape_nested_bounce_mq;
static mach_vm_address_t dtape_nested_bounce_addr;
static mach_msg_size_t dtape_nested_bounce_size;
static uint32_t dtape_nested_bounce_pid;

static int dtape_ipcz_is_channel_offer(const mach_msg_header_t *hdr);
static void dtape_handshake_drain_offer_ahead(ipc_mqueue_t mqueue);
static void dtape_handshake_drain_34_ahead(ipc_mqueue_t mqueue);
static void dtape_handshake_drain_bind_posted(ipc_mqueue_t mqueue, ipc_kmsg_t kmsg);

/*
 * GPU Channel attach still MACH_RCV_MSG-fills if occupancy parcels
 * sit in the mqueue. kqchan_notify_ack_nofill restores the latch
 * only; guest copyout notify then timeout-0 mach_msg drains nmsg
 * 2→11 (ROOT98CHK). Host-cmdline already matched the opener.
 *
 * code197–200 destroyed msgid 20 (nopost) and EnsureConnected
 * still killed ChildThread. Handshake 22/34/36 copyout was not
 * enough. Drain occupancy: one msgid 20 on the mqueue, extras
 * parked (not destroyed). nofill ACK posts the next parked 20
 * so timeout-0 cannot empty a pile.
 *
 * ChannelMac ACK is notify-only: sitting=1 means the in-flight
 * parcel is still queued (code201 skipped and left eight parked).
 * Do not post onto that (sitting would be 2, or an ACK loop dumps
 * the park list). Wait until copyout empties it, then post one.
 * sitting>=2 is a pile; do not add. Nested ACK is ignored via a
 * process-wide busy flag (not __thread: ACK is monitor, post is
 * kernelAsync). code203 posted from the monitor thread at
 * sitting=1 and killed dserver before any release log.
 * Network Ping/Pong dest is not GPU — those still post.
 *
 * StopProxyingToLocalPeer (35) after Bypass decays the proxy
 * before occupancy is seen. Park 35 until this dest copyouts
 * msgid 20 AND gpu-alive-10s + CrGpuMain (code205 posted 35
 * at Channel attach ~2s and NativeWidget never mapped).
 * Occupancy 20 still handshake-drains at Channel attach
 * (~2s Bind 22 / hs 34). Network Ping is parked until
 * gpu-alive-10s so Channel handshake can notify without
 * delaying GPU Bind. Never hold msgid 34 (bypass34_hold_off).
 *
 * code208 Bind 0.80s parked six occupancy 20s; first copyout
 * remain=6 during PA (ROOT98CHK packed=0). Cap parked 20s at 2
 * so drain is 2→1→0 (one in-flight, rest off-queue). Extra 20s
 * beyond the cap are dropped, not posted (a queue pile is nmsg).
 * HS 34 still posts at Bind; do not wait for 35 at 10s.
 *
 * dest_pid is ip_receiver. After MOVE_RECEIVE that can still name
 * storage/launchd while the GPU knote owns the mqueue (code199 Bind
 * copyout went to storage). Match host-cmdline GPU on knote owner
 * too. Prefer a GPU knote when several knotes share the mqueue
 * (code202 first knote was storage/browser, dest missed GPU).
 * Record the mqueue at MOVE_RECEIVE/kqchan attach when dest is
 * host-cmdline --type=gpu-process. Do not dest-bind COMPLEX onto
 * another port. Network Ping uses the same owner/recorded match
 * on the network receive port (code208 dest miss: dest_pid was
 * not NetworkService).
 */
#define DTAPE_HS_PARK_MAX 96
#define DTAPE_HS20_SEEN_MAX 32
#define DTAPE_HS20_PARK_CAP 2
#define DTAPE_NET_MQ_MAX 32

struct dtape_hs_park {
	ipc_kmsg_t kmsg;
	ipc_mqueue_t mqueue;
	uint32_t dest_pid;
	unsigned msgid;
	unsigned seq;
	int used;
};

static struct dtape_hs_park dtape_hs_park_slots[DTAPE_HS_PARK_MAX];
static dtape_mutex_t dtape_hs_park_lock;
static int dtape_hs_park_lock_inited;
static __thread int dtape_hs_repost;
static int dtape_hs_ack_busy;
static uint32_t dtape_gpu20_copyout_pid[DTAPE_HS20_SEEN_MAX];
static unsigned dtape_gpu20_copyout_n;
#define DTAPE_GPU_MQ_MAX 32
static ipc_mqueue_t dtape_gpu_mq[DTAPE_GPU_MQ_MAX];
static uint32_t dtape_gpu_mq_pid[DTAPE_GPU_MQ_MAX];
static unsigned dtape_gpu_mq_n;
static ipc_mqueue_t dtape_net_mq[DTAPE_NET_MQ_MAX];
static uint32_t dtape_net_mq_pid[DTAPE_NET_MQ_MAX];
static unsigned dtape_net_mq_n;

static void
dtape_hs_park_lock_ensure(void)
{
	if (!dtape_hs_park_lock_inited) {
		dtape_mutex_init(&dtape_hs_park_lock);
		dtape_hs_park_lock_inited = 1;
	}
}

static int
dtape_gpu20_copyout_seen(uint32_t pid)
{
	unsigned i;

	if (pid == 0) {
		return 0;
	}
	for (i = 0; i < dtape_gpu20_copyout_n && i < DTAPE_HS20_SEEN_MAX; i++) {
		if (dtape_gpu20_copyout_pid[i] == pid) {
			return 1;
		}
	}
	return 0;
}

static void
dtape_gpu20_copyout_mark(uint32_t pid)
{
	if (pid == 0 || dtape_gpu20_copyout_seen(pid)) {
		return;
	}
	if (dtape_gpu20_copyout_n < DTAPE_HS20_SEEN_MAX) {
		dtape_gpu20_copyout_pid[dtape_gpu20_copyout_n++] = pid;
	}
}

void
dtape_note_gpu_channel_mqueue(ipc_mqueue_t mqueue, uint32_t pid)
{
	unsigned i;

	if (mqueue == IMQ_NULL || pid == 0 || !dtape_host_cmdline_is_gpu(pid)) {
		return;
	}
	dtape_hs_park_lock_ensure();
	dtape_mutex_lock(&dtape_hs_park_lock);
	for (i = 0; i < dtape_gpu_mq_n && i < DTAPE_GPU_MQ_MAX; i++) {
		if (dtape_gpu_mq[i] == mqueue) {
			dtape_gpu_mq_pid[i] = pid;
			dtape_mutex_unlock(&dtape_hs_park_lock);
			return;
		}
	}
	if (dtape_gpu_mq_n < DTAPE_GPU_MQ_MAX) {
		dtape_gpu_mq[dtape_gpu_mq_n] = mqueue;
		dtape_gpu_mq_pid[dtape_gpu_mq_n] = pid;
		dtape_gpu_mq_n++;
	}
	dtape_mutex_unlock(&dtape_hs_park_lock);
}

uint32_t
dtape_gpu_channel_mqueue_pid(ipc_mqueue_t mqueue)
{
	unsigned i;
	uint32_t pid = 0;

	if (mqueue == IMQ_NULL) {
		return 0;
	}
	dtape_hs_park_lock_ensure();
	dtape_mutex_lock(&dtape_hs_park_lock);
	for (i = 0; i < dtape_gpu_mq_n && i < DTAPE_GPU_MQ_MAX; i++) {
		if (dtape_gpu_mq[i] == mqueue) {
			pid = dtape_gpu_mq_pid[i];
			break;
		}
	}
	dtape_mutex_unlock(&dtape_hs_park_lock);
	return pid;
}

void
dtape_note_net_channel_mqueue(ipc_mqueue_t mqueue, uint32_t pid)
{
	unsigned i;

	if (mqueue == IMQ_NULL || pid == 0 || !dtape_host_cmdline_is_network(pid)) {
		return;
	}
	dtape_hs_park_lock_ensure();
	dtape_mutex_lock(&dtape_hs_park_lock);
	for (i = 0; i < dtape_net_mq_n && i < DTAPE_NET_MQ_MAX; i++) {
		if (dtape_net_mq[i] == mqueue) {
			dtape_net_mq_pid[i] = pid;
			dtape_mutex_unlock(&dtape_hs_park_lock);
			return;
		}
	}
	if (dtape_net_mq_n < DTAPE_NET_MQ_MAX) {
		dtape_net_mq[dtape_net_mq_n] = mqueue;
		dtape_net_mq_pid[dtape_net_mq_n] = pid;
		dtape_net_mq_n++;
	}
	dtape_mutex_unlock(&dtape_hs_park_lock);
}

uint32_t
dtape_net_channel_mqueue_pid(ipc_mqueue_t mqueue)
{
	unsigned i;
	uint32_t pid = 0;

	if (mqueue == IMQ_NULL) {
		return 0;
	}
	dtape_hs_park_lock_ensure();
	dtape_mutex_lock(&dtape_hs_park_lock);
	for (i = 0; i < dtape_net_mq_n && i < DTAPE_NET_MQ_MAX; i++) {
		if (dtape_net_mq[i] == mqueue) {
			pid = dtape_net_mq_pid[i];
			break;
		}
	}
	dtape_mutex_unlock(&dtape_hs_park_lock);
	return pid;
}

static unsigned
dtape_mqueue_msgid20_count(ipc_mqueue_t mqueue)
{
	ipc_kmsg_t cur;
	unsigned n = 0;
	unsigned msgid = 0, seq = 0;
	uint64_t sub = 0;

	if (mqueue == IMQ_NULL) {
		return 0;
	}
	imq_lock(mqueue);
	for (cur = ipc_kmsg_queue_first(&mqueue->imq_messages);
	    cur != IKM_NULL;
	    cur = ipc_kmsg_queue_next(&mqueue->imq_messages, cur)) {
		msgid = 0;
		seq = 0;
		sub = 0;
		if (cur->ikm_header &&
		    dtape_ipcz_peek(cur->ikm_header, 0, &msgid, &seq, &sub) &&
		    msgid == 20) {
			n++;
		}
	}
	imq_unlock(mqueue);
	return n;
}

static int
dtape_hs_park_put(ipc_mqueue_t mqueue, ipc_kmsg_t kmsg, uint32_t dest_pid,
    unsigned msgid, unsigned seq)
{
	unsigned i;
	int slot = -1;

	dtape_hs_park_lock_ensure();
	dtape_mutex_lock(&dtape_hs_park_lock);
	for (i = 0; i < DTAPE_HS_PARK_MAX; i++) {
		if (!dtape_hs_park_slots[i].used) {
			slot = (int)i;
			break;
		}
	}
	if (slot < 0) {
		dtape_mutex_unlock(&dtape_hs_park_lock);
		return 0;
	}
	dtape_hs_park_slots[slot].kmsg = kmsg;
	dtape_hs_park_slots[slot].mqueue = mqueue;
	dtape_hs_park_slots[slot].dest_pid = dest_pid;
	dtape_hs_park_slots[slot].msgid = msgid;
	dtape_hs_park_slots[slot].seq = seq;
	dtape_hs_park_slots[slot].used = 1;
	dtape_mutex_unlock(&dtape_hs_park_lock);
	return 1;
}

static unsigned
dtape_hs_park_count(uint32_t dest_pid, unsigned msgid)
{
	unsigned i;
	unsigned n = 0;

	dtape_hs_park_lock_ensure();
	dtape_mutex_lock(&dtape_hs_park_lock);
	for (i = 0; i < DTAPE_HS_PARK_MAX; i++) {
		if (dtape_hs_park_slots[i].used &&
		    dtape_hs_park_slots[i].dest_pid == dest_pid &&
		    dtape_hs_park_slots[i].msgid == msgid) {
			n++;
		}
	}
	dtape_mutex_unlock(&dtape_hs_park_lock);
	return n;
}

static int
dtape_hs_park_match(const struct dtape_hs_park *slot, uint32_t dest_pid,
    unsigned msgid, ipc_mqueue_t only_mq)
{
	if (!slot->used) {
		return 0;
	}
	if (slot->dest_pid != dest_pid || slot->msgid != msgid) {
		return 0;
	}
	if (only_mq != IMQ_NULL && slot->mqueue != only_mq) {
		return 0;
	}
	return 1;
}

static void
dtape_hs_park_release(uint32_t dest_pid, unsigned msgid, int one_only,
    ipc_mqueue_t only_mq)
{
	struct dtape_hs_park local[DTAPE_HS_PARK_MAX];
	unsigned n = 0;
	unsigned i;
	unsigned remain = 0;
	int best = -1;
	unsigned best_seq = ~0u;

	dtape_hs_park_lock_ensure();
	dtape_mutex_lock(&dtape_hs_park_lock);
	if (one_only) {
		for (i = 0; i < DTAPE_HS_PARK_MAX; i++) {
			if (!dtape_hs_park_match(&dtape_hs_park_slots[i],
			    dest_pid, msgid, only_mq)) {
				continue;
			}
			remain++;
			if (dtape_hs_park_slots[i].seq < best_seq) {
				best = (int)i;
				best_seq = dtape_hs_park_slots[i].seq;
			}
		}
		if (best >= 0) {
			local[n++] = dtape_hs_park_slots[best];
			dtape_hs_park_slots[best].used = 0;
			dtape_hs_park_slots[best].kmsg = IKM_NULL;
			dtape_hs_park_slots[best].mqueue = IMQ_NULL;
			remain--;
		} else if (only_mq != IMQ_NULL) {
			remain = 0;
			best_seq = ~0u;
			for (i = 0; i < DTAPE_HS_PARK_MAX; i++) {
				if (!dtape_hs_park_match(&dtape_hs_park_slots[i],
				    dest_pid, msgid, IMQ_NULL)) {
					continue;
				}
				remain++;
				if (dtape_hs_park_slots[i].seq < best_seq) {
					best = (int)i;
					best_seq = dtape_hs_park_slots[i].seq;
				}
			}
			if (best >= 0) {
				local[n++] = dtape_hs_park_slots[best];
				dtape_hs_park_slots[best].used = 0;
				dtape_hs_park_slots[best].kmsg = IKM_NULL;
				dtape_hs_park_slots[best].mqueue = IMQ_NULL;
				remain--;
			}
		}
	} else {
		for (i = 0; i < DTAPE_HS_PARK_MAX; i++) {
			if (!dtape_hs_park_match(&dtape_hs_park_slots[i],
			    dest_pid, msgid, only_mq)) {
				continue;
			}
			local[n++] = dtape_hs_park_slots[i];
			dtape_hs_park_slots[i].used = 0;
			dtape_hs_park_slots[i].kmsg = IKM_NULL;
			dtape_hs_park_slots[i].mqueue = IMQ_NULL;
		}
	}
	dtape_mutex_unlock(&dtape_hs_park_lock);

	for (i = 0; i < n; i++) {
		ipc_mqueue_t mq = local[i].mqueue;
		ipc_kmsg_t kmsg = local[i].kmsg;

		if (mq == IMQ_NULL || kmsg == IKM_NULL) {
			continue;
		}
		if (local[i].msgid == 35) {
			dtape_log_error(
			    "kqchan_gpu_hs35_after20_v1 release dest_pid=%u seq=%u n=%u after gpu-alive-10s CrGpuMain",
			    local[i].dest_pid, local[i].seq, n);
		} else {
			dtape_log_error(
			    "kqchan_gpu_hs20_drain_v1 release dest_pid=%u msgid=%u seq=%u n=%u remain=%u",
			    local[i].dest_pid, local[i].msgid, local[i].seq, n,
			    remain);
		}
		imq_lock(mq);
		if (imq_valid(mq)) {
			mq->imq_msgcount++;
		}
		imq_unlock(mq);
		dtape_hs_repost++;
		ipc_mqueue_post(mq, kmsg, MACH_SEND_ALWAYS);
		dtape_hs_repost--;
	}
}

void
dtape_gpu_hs20_note_copyout(void)
{
	uint32_t pid;
	static int log_n;

	pid = dtape_current_pid();
	if (pid == 0 || !dtape_host_cmdline_is_gpu(pid)) {
		return;
	}
	(void)dtape_gpu_hs20_drain_v1;
	dtape_hs_park_lock_ensure();
	dtape_mutex_lock(&dtape_hs_park_lock);
	dtape_gpu20_copyout_mark(pid);
	dtape_mutex_unlock(&dtape_hs_park_lock);
	if (log_n < 32) {
		log_n++;
		dtape_log_error(
		    "kqchan_gpu_hs20_drain_v1 copyout dest_pid=%u src=host-cmdline",
		    pid);
	}
	(void)dtape_gpu_hs35_after20_v1;
	if (dtape_gpu_alive_10s_crgpu()) {
		dtape_hs_park_release(pid, 35, 0, IMQ_NULL);
	} else {
		(void)dtape_gpu_hs35_delay_alive_v1;
		dtape_log_error(
		    "kqchan_gpu_hs35_after20_v1 delay dest_pid=%u until gpu-alive-10s CrGpuMain copyout-hold",
		    pid);
		dtape_gpu_hs20_arm_after_alive(pid);
	}
	/*
	 * GPU copyout emptied the in-flight 20. Post one parked 20
	 * here (syscall thread has current_thread). Do not spin ACK
	 * 10s sitting=1 into EnsureConnected.
	 */
	dtape_hs_park_release(pid, 20, 1, IMQ_NULL);
}

void
dtape_gpu_hs20_ack_release(ipc_mqueue_t mqueue, uint32_t dest_pid)
{
	unsigned sitting;

	if (mqueue == IMQ_NULL || dest_pid == 0) {
		return;
	}
	if (!dtape_host_cmdline_is_gpu(dest_pid)) {
		return;
	}
	if (current_thread() == THREAD_NULL) {
		dtape_log_error(
		    "kqchan_gpu_hs20_drain_v1 ack skip no-thread dest_pid=%u",
		    dest_pid);
		return;
	}
	dtape_hs_park_lock_ensure();
	dtape_mutex_lock(&dtape_hs_park_lock);
	if (dtape_hs_ack_busy) {
		dtape_mutex_unlock(&dtape_hs_park_lock);
		return;
	}
	dtape_hs_ack_busy = 1;
	dtape_mutex_unlock(&dtape_hs_park_lock);

	sitting = dtape_mqueue_msgid20_count(mqueue);
	if (sitting >= 2) {
		dtape_log_error(
		    "kqchan_gpu_hs20_drain_v1 ack wait dest_pid=%u n20=%u",
		    dest_pid, sitting);
		goto out;
	}
	if (sitting == 1) {
		dtape_log_error(
		    "kqchan_gpu_hs20_drain_v1 ack wait dest_pid=%u n20=1 no-spin copyout-refill",
		    dest_pid);
		goto out;
	}
	dtape_log_error(
	    "kqchan_gpu_hs20_drain_v1 ack drain dest_pid=%u n20=%u",
	    dest_pid, sitting);
	dtape_hs_park_release(dest_pid, 20, 1, mqueue);
out:
	dtape_mutex_lock(&dtape_hs_park_lock);
	dtape_hs_ack_busy = 0;
	dtape_mutex_unlock(&dtape_hs_park_lock);
}

void
dtape_gpu_hs20_alive_release(uint32_t dest_pid)
{
	if (dest_pid == 0 || !dtape_host_cmdline_is_gpu(dest_pid)) {
		return;
	}
	if (current_thread() == THREAD_NULL) {
		dtape_log_error(
		    "kqchan_gpu_hs35_after20_v1 skip no-thread dest_pid=%u",
		    dest_pid);
		return;
	}
	(void)dtape_gpu_hs20_until_alive_v1;
	(void)dtape_gpu_hs35_delay_alive_v1;
	dtape_log_error(
	    "kqchan_gpu_hs35_after20_v1 post dest_pid=%u after gpu-alive-10s CrGpuMain",
	    dest_pid);
	dtape_hs_park_release(dest_pid, 35, 0, IMQ_NULL);
}

void
dtape_net_ping_alive_release(uint32_t dest_pid)
{
	if (dest_pid == 0 || !dtape_host_cmdline_is_network(dest_pid)) {
		return;
	}
	if (current_thread() == THREAD_NULL) {
		dtape_log_error(
		    "kqchan_net_after_gpu_alive skip no-thread dest_pid=%u",
		    dest_pid);
		return;
	}
	dtape_log_error(
	    "kqchan_net_after_gpu_alive post dest_pid=%u ping after gpu-alive-10s CrGpuMain",
	    dest_pid);
	dtape_hs_park_release(dest_pid, 20, 0, IMQ_NULL);
}

static void
dtape_net_remain_notify(ipc_mqueue_t mqueue, mach_port_msgcount_t remain)
{
	uint32_t pid;
	unsigned msgid = 0, seq = 0;
	uint64_t sub = 0;
	ipc_kmsg_t k;

	if (mqueue == IMQ_NULL || remain == 0) {
		return;
	}
	(void)dtape_net_remain_v1;
	pid = dtape_current_pid();
	if (!dtape_host_cmdline_is_network(pid) ||
	    dtape_host_cmdline_is_gpu(pid)) {
		return;
	}
	k = ipc_kmsg_queue_first(&mqueue->imq_messages);
	if (k != IKM_NULL && k->ikm_header != NULL) {
		(void)dtape_ipcz_peek(k->ikm_header, 0, &msgid, &seq, &sub);
	}
	/*
	 * Handshake drain Offer/mjhs/Connect/Bind. Sitting leftover
	 * Offer until Bind deadlocks (Bind needs Connect needs Offer).
	 * Yield/timeout-0-hide is the same deadlock. Drain Offer
	 * leftover so mjhs is not allowed to complete with Offer
	 * still queued; drain mjhs leftover after Offer copyout.
	 */
	dtape_log_error(
	    "kqchan_net_remain_v1 remain=%u pid=%u head_msgid=%u after copyout",
	    remain, pid, msgid);
	{
		int drain = 0;
		int offer = 0;
		int mjhs = 0;

		if (k != IKM_NULL && k->ikm_header != NULL &&
		    k->ikm_header->msgh_id == 0x6d6a6873) {
			mjhs = 1;
			drain = 1;
		}
		if (k != IKM_NULL && k->ikm_header != NULL &&
		    dtape_ipcz_is_channel_offer(k->ikm_header)) {
			offer = 1;
			drain = 1;
		}
		if (msgid == 22 || msgid == 1) {
			drain = 1;
		}
		if (drain) {
			static int drain_n;

			if (msgid == 22) {
				(void)dtape_handshake_drain_bind_v1;
			}
			if (offer || mjhs || msgid == 0) {
				(void)dtape_handshake_drain_offer_v1;
			}
			if (drain_n < 32) {
				drain_n++;
				dtape_log_error(
				    "handshake_drain_offer_v1 remain=%u pid=%u head_msgid=%u offer=%d mjhs=%d after copyout",
				    remain, pid, msgid, offer, mjhs);
				if (msgid == 22) {
					dtape_log_error(
					    "handshake_drain_bind_v1 remain=%u pid=%u msgid=22 seq=%u sl=%llu after copyout",
					    remain, pid, seq, (unsigned long long)sub);
				}
			}
			dtape_kqchan_notify_mqueue(mqueue);
			return;
		}
	}
}

static ipc_mqueue_t dtape_net_bind_seen_mq[DTAPE_NET_MQ_MAX];
static unsigned dtape_net_bind_seen_n;

static int
dtape_net_bind_mq_seen(ipc_mqueue_t mqueue)
{
	unsigned i;

	if (mqueue == IMQ_NULL) {
		return 0;
	}
	dtape_hs_park_lock_ensure();
	dtape_mutex_lock(&dtape_hs_park_lock);
	for (i = 0; i < dtape_net_bind_seen_n && i < DTAPE_NET_MQ_MAX; i++) {
		if (dtape_net_bind_seen_mq[i] == mqueue) {
			dtape_mutex_unlock(&dtape_hs_park_lock);
			return 1;
		}
	}
	dtape_mutex_unlock(&dtape_hs_park_lock);
	return 0;
}

static void
dtape_net_bind_note_mq(ipc_mqueue_t mqueue)
{
	unsigned i;

	if (mqueue == IMQ_NULL) {
		return;
	}
	dtape_hs_park_lock_ensure();
	dtape_mutex_lock(&dtape_hs_park_lock);
	for (i = 0; i < dtape_net_bind_seen_n && i < DTAPE_NET_MQ_MAX; i++) {
		if (dtape_net_bind_seen_mq[i] == mqueue) {
			dtape_mutex_unlock(&dtape_hs_park_lock);
			return;
		}
	}
	if (dtape_net_bind_seen_n < DTAPE_NET_MQ_MAX) {
		dtape_net_bind_seen_mq[dtape_net_bind_seen_n++] = mqueue;
	}
	dtape_mutex_unlock(&dtape_hs_park_lock);
}

static int
dtape_ipcz_is_channel_offer(const mach_msg_header_t *hdr)
{
	unsigned msgid = 0, seq = 0;
	uint64_t sub = 0;
	uint32_t bits = 0;
	mach_msg_size_t msg_size = 0, hsz, ndesc = 0;

	if (hdr == NULL) {
		return 0;
	}
	if (!dtape_ipcz_peek(hdr, 0, &msgid, &seq, &sub) || msgid != 0) {
		return 0;
	}
	memcpy(&bits, hdr, 4);
	memcpy(&msg_size, (const unsigned char *)hdr + 4, 4);
	hsz = (mach_msg_size_t)sizeof(mach_msg_header_t);
	if (msg_size >= hsz + sizeof(mach_msg_body_t)) {
		const mach_msg_body_t *body =
		    (const mach_msg_body_t *)((const unsigned char *)hdr + hsz);

		ndesc = body->msgh_descriptor_count;
	}
	if ((bits & 0x80000000u) == 0 && ndesc == 0) {
		return 0;
	}
	return 1;
}

static int
dtape_kmsg_is_mjhs(ipc_kmsg_t kmsg)
{
	return kmsg != IKM_NULL && kmsg->ikm_header != NULL &&
	    kmsg->ikm_header->msgh_id == 0x6d6a6873;
}

/*
 * mqueue locked. Network Channel queues mjhs ahead of leftover
 * Offer (msgid=0 COMPLEX). FIFO then copyouts mjhs first; timeout-0
 * OnOffers during Connect; Accept+Ping before Bind. Storage has no
 * leftover Offer at mjhs. Handshake drain: Offer copyout before
 * mjhs is allowed — rotate Offer to head, keep FIFO otherwise.
 * Do not steal occupancy 20 from behind Connect/Bind.
 */
static void
dtape_handshake_drain_offer_ahead(ipc_mqueue_t mqueue)
{
	ipc_kmsg_t head;
	ipc_kmsg_t cur;
	ipc_kmsg_t offer = IKM_NULL;
	uint32_t pid;
	static int rot_n;

	if (mqueue == IMQ_NULL) {
		return;
	}
	pid = dtape_current_pid();
	if (pid == 0 || !dtape_host_cmdline_is_network(pid) ||
	    dtape_host_cmdline_is_gpu(pid)) {
		return;
	}
	head = ipc_kmsg_queue_first(&mqueue->imq_messages);
	if (!dtape_kmsg_is_mjhs(head)) {
		return;
	}
	for (cur = ipc_kmsg_queue_next(&mqueue->imq_messages, head);
	    cur != IKM_NULL && cur != head;
	    cur = ipc_kmsg_queue_next(&mqueue->imq_messages, cur)) {
		if (cur->ikm_header != NULL &&
		    dtape_ipcz_is_channel_offer(cur->ikm_header)) {
			offer = cur;
			break;
		}
	}
	if (offer == IKM_NULL) {
		return;
	}
	ipc_kmsg_rmqueue(&mqueue->imq_messages, offer);
	(void)ipc_kmsg_enqueue_qos(&mqueue->imq_messages, offer);
	mqueue->imq_messages.ikmq_base = offer;
	(void)dtape_handshake_drain_offer_v1;
	if (rot_n < 32) {
		rot_n++;
		dtape_log_error(
		    "handshake_drain_offer_v1 rotate Offer ahead of mjhs pid=%u nmsg=%u",
		    pid, mqueue->imq_msgcount);
	}
}

/*
 * Rotate-34-ahead-of-20s was a fake sequencer (code238): splicing
 * BypassPeer 34 in front of leftover AcceptParcels closed decaying
 * inbound before Ping copyout, so NodeLink dropped proto=4.
 * Reverted. Honest FIFO: leftover 20s + Ping seq 4, then msgid 34.
 * rls_fe_ahead 35/36 rotate is also off. Offer-ahead-of-mjhs stays.
 * Do not hold 34 in the mqueue. Do not rewrite sl=2.
 */
static void
dtape_handshake_drain_34_ahead(ipc_mqueue_t mqueue)
{
	static int once;

	/*
	 * Rotate-34-ahead-of-20s closed decaying inbound before Ping
	 * copyout, so NodeLink dropped proto=4 (inbound_n=0 /
	 * GetRouter(sl=2) decaying). FIFO: leftover AcceptParcels +
	 * Ping (seq 4) copyout before msgid 34 BypassPeer. Do not
	 * splice 34 in front of 20s. Do not rotate 35/36. Offer-ahead
	 * of mjhs still runs. Do not hold 34 in the mqueue.
	 */
	(void)mqueue;
	(void)dtape_handshake_drain_34_v1;
	(void)dtape_handshake_drain_34_rot_v1;
	(void)dtape_handshake_drain_34_browser_v1;
	(void)dtape_handshake_drain_34_reverted_v1;
	(void)dtape_rls_fe_ahead_v1;
	(void)dtape_rls_fe_ahead_rot_v1;
	(void)dtape_rls_fe_ahead_browser_v1;
	if (once < 8) {
		once++;
		dtape_log_error(
		    "handshake_drain_34_v1 rotate-34-ahead-of-20s reverted fifo leftover 20s then 34");
	}
}

/*
 * Channel Offer (msgid=0 COMPLEX memfd) is posted ~1.4s before the
 * helper owns the receive right, so dest_pid is not NetworkService
 * yet. Do not park Offer. Handshake drain rotates it ahead of mjhs
 * at copyout so timeout-0 cannot OnOffer during Connect.
 */
static int
dtape_net_offer_hold(ipc_mqueue_t mqueue, ipc_kmsg_t kmsg)
{
	if (kmsg == IKM_NULL || kmsg->ikm_header == NULL || mqueue == IMQ_NULL) {
		return 0;
	}
	/*
	 * Park-at-post deadlocks. Offer is posted ~1.4s before the
	 * helper owns the receive right (dest_pid is the browser).
	 * Pulling it off the mqueue means MOVE_RECEIVE delivers an
	 * empty Channel: helper never copyouts Offer, never Connect,
	 * Bind never posts, unpark never runs (ch2parkmq). Offer
	 * copyout is required for Connect; Bind is a reaction to
	 * Connect. Cannot withhold Offer until Bind. Chrome timeout-0
	 * still drains leftover Offer on the mjhs wakeup. Network
	 * Accept+Ping is sent during Offer HandleRequest (~6ms into
	 * the map), before Bind posts (~45ms after Connect send).
	 *
	 * timeout-0 yield of leftover Offer (ch2offeryield) sent
	 * Connect from mjhs then hid Offer: browser copyout'd Connect
	 * and never posted Bind (zero msgid=22 on the network helper).
	 * Offer copyout is required for Bind. Storage has no leftover
	 * Offer at mjhs so OnOffer is not in that window. Do not park
	 * or timeout-0-hide Offer. Drain Offer before mjhs copyout
	 * (dtape_handshake_drain_offer_ahead).
	 */
	(void)dtape_handshake_drain_offer_v1;
	return 0;
}

/*
 * Bind is queued before Ping send (code221: 0.2ms). ChannelMac
 * copyout waited for remain-after-copyout / next kevent (~9ms)
 * so Ping won. Handshake-drain msgid=22 at post so helper
 * copyout lands before Ping copyin. Do not park Ping.
 */
/*
 * Network helper ChannelMac nested timeout-0 receive during
 * Accept+Ping send (storage path). Do not enable 1ns in
 * --type=gpu-process. Do not park Ping. User-space
 * OnMachMessageReceived (libkqueue mach_msg interpose)
 * consumes Bind on this same send before Ping copyin.
 * Bounce is fallback if that dispatch does not run.
 */
void
dtape_channelmac_nested_timeout0_during_send(void)
{
	uint32_t pid;
	unsigned i;
	unsigned n;
	static int nest_n;
	thread_t self;
	ipc_mqueue_t mq;
	ipc_kmsg_t kmsg;
	ipc_object_t object;
	unsigned msgid = 0, seq = 0;
	uint64_t sub = 0;
	mach_vm_offset_t bounce = 0;
	mach_msg_size_t rcv_size = 256 * 1024;
	mach_msg_return_t mr;
	kern_return_t kr;

	pid = dtape_current_pid();
	if (pid == 0 || dtape_host_cmdline_is_gpu(pid)) {
		return;
	}
	if (!dtape_host_cmdline_is_network(pid)) {
		return;
	}
	(void)dtape_channelmac_nested_timeout0_v1;
	if (dtape_nested_bounce_pid == pid && dtape_nested_bounce_addr != 0) {
		return;
	}

	dtape_hs_park_lock_ensure();
	dtape_mutex_lock(&dtape_hs_park_lock);
	n = dtape_net_mq_n;
	if (n > DTAPE_NET_MQ_MAX) {
		n = DTAPE_NET_MQ_MAX;
	}
	for (i = 0; i < n; i++) {
		if (dtape_net_mq_pid[i] != pid) {
			continue;
		}
		mq = dtape_net_mq[i];
		dtape_mutex_unlock(&dtape_hs_park_lock);

		imq_lock(mq);
		kmsg = ipc_kmsg_queue_first(&mq->imq_messages);
		msgid = 0;
		seq = 0;
		sub = 0;
		if (kmsg != IKM_NULL && kmsg->ikm_header != NULL) {
			(void)dtape_ipcz_peek(kmsg->ikm_header, 0, &msgid, &seq, &sub);
		}
		imq_unlock(mq);
		if (msgid != 22) {
			dtape_mutex_lock(&dtape_hs_park_lock);
			continue;
		}

		object = imq_to_object(mq);
		io_reference(object);
		kr = mach_vm_allocate_kernel(current_map(), &bounce, rcv_size,
		    1 /* VM_FLAGS_ANYWHERE */, 0);
		if (kr != KERN_SUCCESS || bounce == 0) {
			io_release(object);
			if (nest_n < 32) {
				nest_n++;
				dtape_log_error(
				    "channelmac_nested_timeout0_v1 network not gpu pid=%u msgid=22 bounce_alloc kr=0x%x",
				    pid, kr);
			}
			dtape_kqchan_notify_mqueue(mq);
			return;
		}

		self = current_thread();
		self->ith_msg_addr = bounce;
		self->ith_object = object;
		self->ith_rsize = rcv_size;
		self->ith_msize = 0;
		self->ith_option = MACH_RCV_MSG | MACH_RCV_TIMEOUT;
		self->ith_receiver_name = MACH_PORT_NULL;
		self->ith_continuation = NULL;
		self->ith_knote = ITH_KNOTE_NULL;

		ipc_mqueue_receive(mq, MACH_RCV_MSG | MACH_RCV_TIMEOUT, rcv_size,
		    0, THREAD_ABORTSAFE);
		mr = mach_msg_receive_results(&self->ith_msize);
		if (nest_n < 32) {
			nest_n++;
			dtape_log_error(
			    "channelmac_nested_timeout0_v1 network not gpu pid=%u msgid=22 seq=%u sl=%llu nmsg=%u nested timeout-0 during send mr=0x%x bounce=0x%llx msize=%u",
			    pid, seq, (unsigned long long)sub,
			    mq->imq_msgcount, mr,
			    (unsigned long long)bounce,
			    (unsigned)self->ith_msize);
		}
		if (mr == MACH_MSG_SUCCESS) {
			dtape_nested_bounce_mq = mq;
			dtape_nested_bounce_addr = bounce;
			dtape_nested_bounce_size = self->ith_msize != 0 ?
			    self->ith_msize : rcv_size;
			dtape_nested_bounce_pid = pid;
		}
		dtape_kqchan_notify_mqueue(mq);
		return;
	}
	dtape_mutex_unlock(&dtape_hs_park_lock);
}

int
dtape_channelmac_nested_timeout0_take(ipc_mqueue_t mqueue,
    mach_vm_address_t rcv_addr, mach_msg_size_t rcv_size, mach_msg_size_t *out_size)
{
	char *kbuf;
	uint32_t pid;
	int kr;

	pid = dtape_current_pid();
	if (mqueue == IMQ_NULL || dtape_nested_bounce_addr == 0 ||
	    dtape_nested_bounce_mq != mqueue ||
	    dtape_nested_bounce_pid != pid) {
		return 0;
	}
	if (rcv_addr == 0 || rcv_size < 32) {
		return 0;
	}
	if (dtape_nested_bounce_size > rcv_size) {
		dtape_nested_bounce_size = rcv_size;
	}
	kbuf = kalloc(dtape_nested_bounce_size);
	if (kbuf == NULL) {
		return 0;
	}
	kr = copyin(dtape_nested_bounce_addr, kbuf, dtape_nested_bounce_size);
	if (kr != 0) {
		kfree(kbuf, dtape_nested_bounce_size);
		return 0;
	}
	kr = copyout(kbuf, rcv_addr, dtape_nested_bounce_size);
	kfree(kbuf, dtape_nested_bounce_size);
	if (kr != 0) {
		return 0;
	}
	if (out_size != NULL) {
		*out_size = dtape_nested_bounce_size;
	}
	dtape_log_error(
	    "channelmac_nested_timeout0_v1 take pid=%u size=%u bounce=0x%llx",
	    pid, (unsigned)dtape_nested_bounce_size,
	    (unsigned long long)dtape_nested_bounce_addr);
	dtape_nested_bounce_mq = IMQ_NULL;
	dtape_nested_bounce_addr = 0;
	dtape_nested_bounce_size = 0;
	dtape_nested_bounce_pid = 0;
	return 1;
}

static void
dtape_handshake_drain_bind_posted(ipc_mqueue_t mqueue, ipc_kmsg_t kmsg)
{
	unsigned msgid = 0, seq = 0;
	uint64_t sub = 0;
	uint32_t dest_pid;
	uint32_t owner_pid;
	uint32_t src_pid;
	int browser_chan;
	static int post_n;

	if (mqueue == IMQ_NULL || kmsg == IKM_NULL || kmsg->ikm_header == NULL) {
		return;
	}
	if (!dtape_ipcz_peek(kmsg->ikm_header, 0, &msgid, &seq, &sub) ||
	    (msgid != 22 && msgid != 1)) {
		return;
	}
	dest_pid = dtape_mqueue_dest_pid(mqueue);
	owner_pid = dtape_mqueue_kqchan_network_owner_pid(mqueue);
	src_pid = dtape_current_pid();
	if (dtape_host_cmdline_is_gpu(dest_pid) ||
	    dtape_host_cmdline_is_gpu(owner_pid)) {
		return;
	}
	browser_chan = dtape_host_cmdline_is_network(src_pid) &&
	    dest_pid != 0 &&
	    !dtape_host_cmdline_is_network(dest_pid) &&
	    !dtape_host_cmdline_is_gpu(dest_pid);
	if (!dtape_host_cmdline_is_network(dest_pid) &&
	    !dtape_host_cmdline_is_network(owner_pid) &&
	    !browser_chan) {
		return;
	}
	(void)dtape_handshake_drain_bind_v1;
	if (browser_chan) {
		(void)dtape_handshake_drain_bind_browser_v1;
	}
	if (post_n < 32) {
		post_n++;
		if (browser_chan) {
			dtape_log_error(
			    "handshake_drain_bind_v1 browser Channel dest_pid=%u owner_pid=%u src_pid=%u msgid=%u seq=%u sl=%llu nmsg=%u",
			    dest_pid, owner_pid, src_pid, msgid, seq,
			    (unsigned long long)sub, mqueue->imq_msgcount);
		} else {
			dtape_log_error(
			    "handshake_drain_bind_v1 posted immediately dest_pid=%u owner_pid=%u msgid=%u seq=%u sl=%llu nmsg=%u",
			    dest_pid, owner_pid, msgid, seq,
			    (unsigned long long)sub, mqueue->imq_msgcount);
		}
	}
	dtape_kqchan_notify_mqueue(mqueue);
}

static ipc_kmsg_t
dtape_net_offer_take(ipc_mqueue_t mqueue, uint32_t dest_pid)
{
	unsigned i;
	ipc_kmsg_t kmsg = IKM_NULL;

	if (mqueue == IMQ_NULL) {
		return IKM_NULL;
	}
	dtape_hs_park_lock_ensure();
	dtape_mutex_lock(&dtape_hs_park_lock);
	for (i = 0; i < DTAPE_HS_PARK_MAX; i++) {
		if (!dtape_hs_park_slots[i].used ||
		    dtape_hs_park_slots[i].msgid != 0) {
			continue;
		}
		if (dtape_hs_park_slots[i].mqueue != mqueue) {
			continue;
		}
		if (dest_pid != 0 &&
		    dtape_hs_park_slots[i].dest_pid != 0 &&
		    dtape_hs_park_slots[i].dest_pid != dest_pid) {
			continue;
		}
		kmsg = dtape_hs_park_slots[i].kmsg;
		dtape_hs_park_slots[i].used = 0;
		dtape_hs_park_slots[i].kmsg = IKM_NULL;
		dtape_hs_park_slots[i].mqueue = IMQ_NULL;
		break;
	}
	dtape_mutex_unlock(&dtape_hs_park_lock);
	return kmsg;
}

static int
dtape_net_ping_hold(ipc_mqueue_t mqueue, ipc_kmsg_t kmsg)
{
	uint32_t dest_pid;
	uint32_t owner_pid;
	uint32_t recorded;
	uint32_t src_pid;
	static int park_n;
	static int miss_n;

	if (kmsg == IKM_NULL || kmsg->ikm_header == NULL || mqueue == IMQ_NULL) {
		return 0;
	}
	if (dtape_hs_repost) {
		return 0;
	}
	if (!dtape_ipcz_is_childprocess_ping(kmsg->ikm_header, 0) &&
	    !dtape_ipcz_is_childprocess_ping(kmsg->ikm_header, 1)) {
		return 0;
	}
	/*
	 * Fable arch13/14: do not park Ping. dest-match / park-on-port
	 * recoupled Bind and left browser→helper Ping sitting while the
	 * helper skipped 1ns. Post honestly onto the receive port.
	 */
	(void)dtape_net_ping_dest_v1;
	(void)dtape_helper_rx_ping_v1;
	dest_pid = dtape_mqueue_dest_pid(mqueue);
	owner_pid = dtape_mqueue_kqchan_network_owner_pid(mqueue);
	recorded = dtape_net_channel_mqueue_pid(mqueue);
	src_pid = dtape_current_pid();
	if (dtape_host_cmdline_is_network(dest_pid)) {
		static int rx_n;
		mach_port_name_t dest_name = 0;
		ipc_object_t object = imq_to_object(mqueue);

		if (io_otype(object) == IOT_PORT) {
			dest_name = ip_from_mq(mqueue)->ip_receiver_name;
		}
		if (rx_n < 32) {
			rx_n++;
			dtape_log_error(
			    "helper_rx_ping_v1 copyin dest_pid=%u dest_name=0x%x owner_pid=%u recorded=%u src_pid=%u msgid=20 sl=2 not parked",
			    dest_pid, dest_name, owner_pid, recorded, src_pid);
		}
		dtape_note_net_channel_mqueue(mqueue, dest_pid);
		return 0;
	}
	if (miss_n < 16) {
		miss_n++;
		dtape_log_error(
		    "kqchan_net_ping_dest_v1 dest_pid=%u owner_pid=%u recorded=%u src_pid=%u msgid=20 seq=4 sl=2 src=host-cmdline miss (no dest-match)",
		    dest_pid, owner_pid, recorded, src_pid);
	}
	(void)park_n;
	return 0;
}

static int
dtape_gpu_channel_nopost(ipc_mqueue_t mqueue, ipc_kmsg_t kmsg)
{
	unsigned msgid = 0, seq = 0;
	uint64_t sub = 0;
	uint32_t dest_pid;
	uint32_t owner_pid;
	uint32_t port_name = 0;
	static int log_n;
	static int bind_log_n;
	static int hs_log_n;
	static int miss_log_n;
	static int park20_n;
	static int park35_n;
	static int post20_n;
	unsigned sitting;

	if (kmsg == IKM_NULL || kmsg->ikm_header == NULL || mqueue == IMQ_NULL) {
		return 0;
	}
	if (!dtape_ipcz_peek(kmsg->ikm_header, 0, &msgid, &seq, &sub)) {
		return 0;
	}
	dest_pid = dtape_mqueue_dest_pid(mqueue);
	owner_pid = dtape_mqueue_kqchan_owner_pid(mqueue);
	{
		ipc_object_t object = imq_to_object(mqueue);

		if (io_otype(object) == IOT_PORT) {
			port_name = ip_from_mq(mqueue)->ip_receiver_name;
		}
	}
	if (!dtape_host_cmdline_is_gpu(dest_pid)) {
		uint32_t recorded;

		if (dtape_host_cmdline_is_gpu(owner_pid)) {
			dest_pid = owner_pid;
		} else {
			recorded = dtape_gpu_channel_mqueue_pid(mqueue);
			if (dtape_host_cmdline_is_gpu(recorded)) {
				dest_pid = recorded;
			} else {
				if (msgid == 22 && miss_log_n < 16) {
					miss_log_n++;
					dtape_log_error(
					    "kqchan_gpu_bind_through_v1 dest_pid=%u owner_pid=%u port=%u msgid=22 seq=%u sub=%llu nmsg=%u src=host-cmdline miss",
					    dest_pid, owner_pid, port_name, seq,
					    (unsigned long long)sub, mqueue->imq_msgcount);
				}
				return 0;
			}
		}
	}
	dtape_note_gpu_channel_mqueue(mqueue, dest_pid);
	if (dtape_hs_repost) {
		return 0;
	}
	if (msgid == 20) {
		unsigned parked;

		(void)dtape_gpu_hs20_drain_v1;
		(void)dtape_gpu_hs20_park_cap_v1;
		sitting = dtape_mqueue_msgid20_count(mqueue);
		if (sitting == 0) {
			if (post20_n < 32) {
				post20_n++;
				dtape_log_error(
				    "%s drain-not-destroy dest_pid=%u port=%u msgid=20 seq=%u sub=%llu nmsg=%u src=host-cmdline",
				    dtape_gpu_channel_nopost_v1, dest_pid, port_name, seq,
				    (unsigned long long)sub, mqueue->imq_msgcount);
			}
			return 0;
		}
		parked = dtape_hs_park_count(dest_pid, 20);
		if (parked >= DTAPE_HS20_PARK_CAP) {
			if (log_n < 32) {
				log_n++;
				dtape_log_error(
				    "kqchan_gpu_hs20_park_cap_v1 drop dest_pid=%u port=%u msgid=20 seq=%u sitting=%u parked=%u nmsg=%u src=host-cmdline",
				    dest_pid, port_name, seq, sitting, parked,
				    mqueue->imq_msgcount);
			}
			ipc_kmsg_destroy(kmsg);
			return 1;
		}
		if (dtape_hs_park_put(mqueue, kmsg, dest_pid, msgid, seq)) {
			if (park20_n < 32) {
				park20_n++;
				dtape_log_error(
				    "kqchan_gpu_hs20_drain_v1 park dest_pid=%u port=%u msgid=20 seq=%u sitting=%u parked=%u nmsg=%u src=host-cmdline",
				    dest_pid, port_name, seq, sitting, parked + 1,
				    mqueue->imq_msgcount);
			}
			return 1;
		}
		if (log_n < 8) {
			log_n++;
			dtape_log_error(
			    "kqchan_gpu_hs20_drain_v1 park_full dest_pid=%u seq=%u sitting=%u",
			    dest_pid, seq, sitting);
		}
		return 0;
	}
	if (msgid == 35) {
		int seen;
		int ready;

		ready = dtape_gpu_alive_10s_crgpu();
		dtape_hs_park_lock_ensure();
		dtape_mutex_lock(&dtape_hs_park_lock);
		seen = dtape_gpu20_copyout_seen(dest_pid);
		dtape_mutex_unlock(&dtape_hs_park_lock);
		if (!ready || !seen) {
			(void)dtape_gpu_hs35_after20_v1;
			(void)dtape_gpu_hs35_delay_alive_v1;
			if (dtape_hs_park_put(mqueue, kmsg, dest_pid, msgid, seq)) {
				if (park35_n < 16) {
					park35_n++;
					if (!ready) {
						dtape_log_error(
						    "kqchan_gpu_hs35_after20_v1 delay dest_pid=%u port=%u msgid=35 seq=%u sub=%llu nmsg=%u until gpu-alive-10s CrGpuMain src=host-cmdline",
						    dest_pid, port_name, seq,
						    (unsigned long long)sub,
						    mqueue->imq_msgcount);
					} else {
						dtape_log_error(
						    "kqchan_gpu_hs35_after20_v1 park dest_pid=%u port=%u msgid=35 seq=%u sub=%llu nmsg=%u src=host-cmdline",
						    dest_pid, port_name, seq,
						    (unsigned long long)sub,
						    mqueue->imq_msgcount);
					}
				}
				if (!ready) {
					dtape_gpu_hs20_arm_after_alive(dest_pid);
				}
				return 1;
			}
			return 0;
		}
		if (hs_log_n < 32) {
			hs_log_n++;
			dtape_log_error(
			    "kqchan_gpu_hs35_after20_v1 post dest_pid=%u port=%u msgid=35 seq=%u nmsg=%u after gpu-alive-10s CrGpuMain src=host-cmdline",
			    dest_pid, port_name, seq, mqueue->imq_msgcount);
		}
	}
	if (msgid == 22) {
		(void)dtape_gpu_bind_through_v1;
		if (bind_log_n < 16) {
			bind_log_n++;
			dtape_log_error(
			    "kqchan_gpu_bind_through_v1 dest_pid=%u owner_pid=%u port=%u msgid=22 seq=%u sub=%llu nmsg=%u src=host-cmdline",
			    dest_pid, owner_pid, port_name, seq, (unsigned long long)sub,
			    mqueue->imq_msgcount);
		}
		return 0;
	}
	(void)dtape_gpu_hs_through_v1;
	if (hs_log_n < 32) {
		hs_log_n++;
		dtape_log_error(
		    "kqchan_gpu_hs_through_v1 dest_pid=%u port=%u msgid=%u seq=%u sub=%llu nmsg=%u src=host-cmdline",
		    dest_pid, port_name, msgid, seq, (unsigned long long)sub,
		    mqueue->imq_msgcount);
	}
	return 0;
}

#endif /* __DARLING__ */

/* forward declarations */
static void ipc_mqueue_receive_results(wait_result_t result);
static void ipc_mqueue_peek_on_thread(
	ipc_mqueue_t        port_mq,
	mach_msg_option_t   option,
	thread_t            thread);

mach_port_msgcount_t
ipc_mqueue_queued_msgcount(ipc_mqueue_t mqueue)
{
	ipc_kmsg_queue_t q = &mqueue->imq_messages;
	ipc_kmsg_t kmsg;
	mach_port_msgcount_t n = 0;

	kmsg = ipc_kmsg_queue_first(q);
	while (kmsg != IKM_NULL) {
		n++;
		kmsg = ipc_kmsg_queue_next(q, kmsg);
		if (n >= MACH_PORT_QLIMIT_KERNEL) {
			break;
		}
	}
	return n;
}

/*
 *	Routine:	ipc_mqueue_init
 *	Purpose:
 *		Initialize a newly-allocated message queue.
 */
void
ipc_mqueue_init(
	ipc_mqueue_t            mqueue,
	ipc_mqueue_kind_t       kind)
{
	switch (kind) {
	case IPC_MQUEUE_KIND_SET:
		waitq_set_init(&mqueue->imq_set_queue,
		    SYNC_POLICY_FIFO | SYNC_POLICY_PREPOST,
		    NULL, NULL);
		break;
	case IPC_MQUEUE_KIND_NONE: /* cheat: we really should have "no" mqueue */
	case IPC_MQUEUE_KIND_PORT:
		waitq_init(&mqueue->imq_wait_queue,
		    SYNC_POLICY_FIFO | SYNC_POLICY_TURNSTILE_PROXY);
		ipc_kmsg_queue_init(&mqueue->imq_messages);
		mqueue->imq_seqno = 0;
		mqueue->imq_msgcount = 0;
		mqueue->imq_qlimit = MACH_PORT_QLIMIT_DEFAULT;
		mqueue->imq_context = 0;
		mqueue->imq_fullwaiters = FALSE;
#if MACH_FLIPC
		mqueue->imq_fport = FPORT_NULL;
#endif
		break;
	}
	klist_init(&mqueue->imq_klist);
}

void
ipc_mqueue_deinit(
	ipc_mqueue_t            mqueue)
{
	boolean_t is_set = imq_is_set(mqueue);

	if (is_set) {
		waitq_set_deinit(&mqueue->imq_set_queue);
	} else {
		waitq_deinit(&mqueue->imq_wait_queue);
	}
}

/*
 *	Routine:	imq_reserve_and_lock
 *	Purpose:
 *		Atomically lock an ipc_mqueue_t object and reserve
 *		an appropriate number of prepost linkage objects for
 *		use in wakeup operations.
 *	Conditions:
 *		mq is unlocked
 */
void
imq_reserve_and_lock(ipc_mqueue_t mq, uint64_t *reserved_prepost)
{
	*reserved_prepost = waitq_prepost_reserve(&mq->imq_wait_queue, 0,
	    WAITQ_KEEP_LOCKED);
}


/*
 *	Routine:	imq_release_and_unlock
 *	Purpose:
 *		Unlock an ipc_mqueue_t object, re-enable interrupts,
 *		and release any unused prepost object reservations.
 *	Conditions:
 *		mq is locked
 */
void
imq_release_and_unlock(ipc_mqueue_t mq, uint64_t reserved_prepost)
{
	waitq_unlock(&mq->imq_wait_queue);
	waitq_prepost_release_reserve(reserved_prepost);
}


/*
 *	Routine:	ipc_mqueue_member
 *	Purpose:
 *		Indicate whether the (port) mqueue is a member of
 *		this portset's mqueue.  We do this by checking
 *		whether the portset mqueue's waitq is an member of
 *		the port's mqueue waitq.
 *	Conditions:
 *		the portset's mqueue is not already a member
 *		this may block while allocating linkage structures.
 */

boolean_t
ipc_mqueue_member(
	ipc_mqueue_t            port_mqueue,
	ipc_mqueue_t            set_mqueue)
{
	struct waitq *port_waitq = &port_mqueue->imq_wait_queue;
	struct waitq_set *set_waitq = &set_mqueue->imq_set_queue;

	return waitq_member(port_waitq, set_waitq);
}

/*
 *	Routine:	ipc_mqueue_remove
 *	Purpose:
 *		Remove the association between the queue and the specified
 *		set message queue.
 */

kern_return_t
ipc_mqueue_remove(
	ipc_mqueue_t      mqueue,
	ipc_mqueue_t      set_mqueue)
{
	struct waitq *mq_waitq = &mqueue->imq_wait_queue;
	struct waitq_set *set_waitq = &set_mqueue->imq_set_queue;

	return waitq_unlink(mq_waitq, set_waitq);
}

/*
 *	Routine:	ipc_mqueue_remove_from_all
 *	Purpose:
 *		Remove the mqueue from all the sets it is a member of
 *	Conditions:
 *		Nothing locked.
 *	Returns:
 *		mqueue unlocked and set links deallocated
 */
void
ipc_mqueue_remove_from_all(ipc_mqueue_t mqueue)
{
	struct waitq *mq_waitq = &mqueue->imq_wait_queue;
	kern_return_t kr;

	imq_lock(mqueue);

	assert(waitq_valid(mq_waitq));
	kr = waitq_unlink_all_unlock(mq_waitq);
	/* mqueue unlocked and set links deallocated */
}

/*
 *	Routine:	ipc_mqueue_remove_all
 *	Purpose:
 *		Remove all the member queues from the specified set.
 *		Also removes the queue from any containing sets.
 *	Conditions:
 *		Nothing locked.
 *	Returns:
 *		mqueue unlocked all set links deallocated
 */
void
ipc_mqueue_remove_all(ipc_mqueue_t      mqueue)
{
	struct waitq_set *mq_setq = &mqueue->imq_set_queue;

	imq_lock(mqueue);
	assert(waitqs_is_set(mq_setq));
	waitq_set_unlink_all_unlock(mq_setq);
	/* mqueue unlocked set links deallocated */
}


/*
 *	Routine:	ipc_mqueue_add
 *	Purpose:
 *		Associate the portset's mqueue with the port's mqueue.
 *		This has to be done so that posting the port will wakeup
 *		a portset waiter.  If there are waiters on the portset
 *		mqueue and messages on the port mqueue, try to match them
 *		up now.
 *	Conditions:
 *		May block.
 */
kern_return_t
ipc_mqueue_add(
	ipc_mqueue_t    port_mqueue,
	ipc_mqueue_t    set_mqueue,
	uint64_t        *reserved_link,
	uint64_t        *reserved_prepost)
{
	struct waitq     *port_waitq = &port_mqueue->imq_wait_queue;
	struct waitq_set *set_waitq = &set_mqueue->imq_set_queue;
	ipc_kmsg_queue_t kmsgq;
	ipc_kmsg_t       kmsg, next;
	kern_return_t    kr;

	assert(reserved_link && *reserved_link != 0);
	assert(waitqs_is_linked(set_waitq));

	imq_lock(port_mqueue);

	/*
	 * The link operation is now under the same lock-hold as
	 * message iteration and thread wakeup, but doesn't have to be...
	 */
	kr = waitq_link(port_waitq, set_waitq, WAITQ_ALREADY_LOCKED, reserved_link);
	if (kr != KERN_SUCCESS) {
		imq_unlock(port_mqueue);
		return kr;
	}

	/*
	 * Now that the set has been added to the port, there may be
	 * messages queued on the port and threads waiting on the set
	 * waitq.  Lets get them together.
	 */
	kmsgq = &port_mqueue->imq_messages;
	for (kmsg = ipc_kmsg_queue_first(kmsgq);
	    kmsg != IKM_NULL;
	    kmsg = next) {
		next = ipc_kmsg_queue_next(kmsgq, kmsg);

		for (;;) {
			thread_t th;
			mach_msg_size_t msize;
			spl_t th_spl;

			th = waitq_wakeup64_identify_locked(
				port_waitq,
				IPC_MQUEUE_RECEIVE,
				THREAD_AWAKENED, &th_spl,
				reserved_prepost, WAITQ_ALL_PRIORITIES,
				WAITQ_KEEP_LOCKED);
			/* waitq/mqueue still locked, thread locked */

			if (th == THREAD_NULL) {
				goto leave;
			}

			/*
			 * If the receiver waited with a facility not directly
			 * related to Mach messaging, then it isn't prepared to get
			 * handed the message directly.  Just set it running, and
			 * go look for another thread that can.
			 */
			if (th->ith_state != MACH_RCV_IN_PROGRESS) {
				if (th->ith_state == MACH_PEEK_IN_PROGRESS) {
					/*
					 * wakeup the peeking thread, but
					 * continue to loop over the threads
					 * waiting on the port's mqueue to see
					 * if there are any actual receivers
					 */
					ipc_mqueue_peek_on_thread(port_mqueue,
					    th->ith_option,
					    th);
				}
				thread_unlock(th);
				splx(th_spl);
				continue;
			}

			/*
			 * Found a receiver. see if they can handle the message
			 * correctly (the message is not too large for them, or
			 * they didn't care to be informed that the message was
			 * too large).  If they can't handle it, take them off
			 * the list and let them go back and figure it out and
			 * just move onto the next.
			 */
			msize = ipc_kmsg_copyout_size(kmsg, th->map);
			if (th->ith_rsize <
			    (msize + REQUESTED_TRAILER_SIZE(thread_is_64bit_addr(th), th->ith_option))) {
				th->ith_state = MACH_RCV_TOO_LARGE;
				th->ith_msize = msize;
				if (th->ith_option & MACH_RCV_LARGE) {
					/*
					 * let him go without message
					 */
					th->ith_receiver_name = port_mqueue->imq_receiver_name;
					th->ith_kmsg = IKM_NULL;
					th->ith_seqno = 0;
					thread_unlock(th);
					splx(th_spl);
					continue; /* find another thread */
				}
			} else {
				th->ith_state = MACH_MSG_SUCCESS;
			}

			/*
			 * This thread is going to take this message,
			 * so give it to him.
			 */
			ipc_kmsg_rmqueue(kmsgq, kmsg);
#if MACH_FLIPC
			mach_node_t  node = kmsg->ikm_node;
#endif
			ipc_mqueue_release_msgcount(port_mqueue, IMQ_NULL);

			th->ith_kmsg = kmsg;
			th->ith_seqno = port_mqueue->imq_seqno++;
			thread_unlock(th);
			splx(th_spl);
#if MACH_FLIPC
			if (MACH_NODE_VALID(node) && FPORT_VALID(port_mqueue->imq_fport)) {
				flipc_msg_ack(node, port_mqueue, TRUE);
			}
#endif
			break;  /* go to next message */
		}
	}
leave:
	imq_unlock(port_mqueue);
	return KERN_SUCCESS;
}


/*
 *	Routine:	ipc_mqueue_has_klist
 *	Purpose:
 *		Returns whether the given mqueue imq_klist field can be used as a klist.
 */
static inline bool
ipc_mqueue_has_klist(ipc_mqueue_t mqueue)
{
	ipc_object_t object = imq_to_object(mqueue);
	if (io_otype(object) != IOT_PORT) {
		return true;
	}
	ipc_port_t port = ip_from_mq(mqueue);
	if (port->ip_specialreply) {
		return false;
	}
	return port->ip_sync_link_state == PORT_SYNC_LINK_ANY;
}

#ifdef __DARLING__
static void
ipc_mqueue_post_log(ipc_mqueue_t mqueue, thread_t receiver, bool has_klist, const char* knote_action)
{
	uint32_t port_name = 0;
	uint32_t nsid = 0;
	uint32_t rec_nstid = 0;
	unsigned rcv_state = receiver ? receiver->ith_state : 0;
	ipc_object_t object = imq_to_object(mqueue);

	if (io_otype(object) == IOT_PORT) {
		ipc_port_t port = ip_from_mq(mqueue);
		port_name = port->ip_receiver_name;
		if (port->ip_receiver && port->ip_receiver->is_task) {
			dtape_task_t* task = dtape_task_for_xnu_task(port->ip_receiver->is_task);
			if (task) {
				nsid = task->saved_pid;
			}
		}
	}
	if (receiver) {
		rec_nstid = (uint32_t)receiver->thread_id;
	}
	if (nsid != 78 && port_name != 18947 && port_name != 14083) {
		return;
	}
	dtape_log_debug("ipc_mqueue_post port=%u waitq=%p receiver_nstid=%u ith_state=0x%x has_klist=%d imq_msgcount=%u knote=%s posted=%p",
	    port_name, &mqueue->imq_wait_queue, rec_nstid, rcv_state, has_klist ? 1 : 0,
	    mqueue->imq_msgcount, knote_action, mqueue);
}
#endif

/*
 *	Routine:	ipc_mqueue_changed
 *	Purpose:
 *		Wake up receivers waiting in a message queue.
 *	Conditions:
 *		The message queue is locked.
 */
void
ipc_mqueue_changed(
	ipc_space_t     space,
	ipc_mqueue_t    mqueue)
{
	if (ipc_mqueue_has_klist(mqueue) && SLIST_FIRST(&mqueue->imq_klist)) {
		/*
		 * Indicate that this message queue is vanishing
		 *
		 * When this is called, the associated receive right may be in flight
		 * between two tasks: the one it used to live in, and the one that armed
		 * a port destroyed notification for it.
		 *
		 * The new process may want to register the port it gets back with an
		 * EVFILT_MACHPORT filter again, and may have pending sync IPC on this
		 * port pending already, in which case we want the imq_klist field to be
		 * reusable for nefarious purposes.
		 *
		 * Fortunately, we really don't need this linkage anymore after this
		 * point as EV_VANISHED / EV_EOF will be the last thing delivered ever.
		 *
		 * Note: we don't have the space lock here, however, this covers the
		 *       case of when a task is terminating the space, triggering
		 *       several knote_vanish() calls.
		 *
		 *       We don't need the lock to observe that the space is inactive as
		 *       we just deactivated it on the same thread.
		 *
		 *       We still need to call knote_vanish() so that the knote is
		 *       marked with EV_VANISHED or EV_EOF so that the detach step
		 *       in filt_machportdetach is skipped correctly.
		 */
		assert(space);
		knote_vanish(&mqueue->imq_klist, is_active(space));
	}

	if (io_otype(imq_to_object(mqueue)) == IOT_PORT) {
		ipc_port_adjust_sync_link_state_locked(ip_from_mq(mqueue), PORT_SYNC_LINK_ANY, NULL);
	} else {
		klist_init(&mqueue->imq_klist);
	}

	waitq_wakeup64_all_locked(&mqueue->imq_wait_queue,
	    IPC_MQUEUE_RECEIVE,
	    THREAD_RESTART,
	    NULL,
	    WAITQ_ALL_PRIORITIES,
	    WAITQ_KEEP_LOCKED);
}




/*
 *	Routine:	ipc_mqueue_send
 *	Purpose:
 *		Send a message to a message queue.  The message holds a reference
 *		for the destination port for this message queue in the
 *		msgh_remote_port field.
 *
 *		If unsuccessful, the caller still has possession of
 *		the message and must do something with it.  If successful,
 *		the message is queued, given to a receiver, or destroyed.
 *	Conditions:
 *		mqueue is locked.
 *	Returns:
 *		MACH_MSG_SUCCESS	The message was accepted.
 *		MACH_SEND_TIMED_OUT	Caller still has message.
 *		MACH_SEND_INTERRUPTED	Caller still has message.
 */
mach_msg_return_t
ipc_mqueue_send(
	ipc_mqueue_t            mqueue,
	ipc_kmsg_t              kmsg,
	mach_msg_option_t       option,
	mach_msg_timeout_t  send_timeout)
{
	int wresult;

	/*
	 *  Don't block if:
	 *	1) We're under the queue limit.
	 *	2) Caller used the MACH_SEND_ALWAYS internal option.
	 *	3) Message is sent to a send-once right.
	 */
	if (!imq_full(mqueue) ||
	    (!imq_full_kernel(mqueue) &&
	    ((option & MACH_SEND_ALWAYS) ||
	    (MACH_MSGH_BITS_REMOTE(kmsg->ikm_header->msgh_bits) ==
	    MACH_MSG_TYPE_PORT_SEND_ONCE)))) {
		mqueue->imq_msgcount++;
		assert(mqueue->imq_msgcount > 0);
		imq_unlock(mqueue);
	} else {
		thread_t cur_thread = current_thread();
		ipc_port_t port = ip_from_mq(mqueue);
		struct turnstile *send_turnstile = TURNSTILE_NULL;
		uint64_t deadline;

		/*
		 * We have to wait for space to be granted to us.
		 */
		if ((option & MACH_SEND_TIMEOUT) && (send_timeout == 0)) {
			imq_unlock(mqueue);
			return MACH_SEND_TIMED_OUT;
		}
		if (imq_full_kernel(mqueue)) {
			imq_unlock(mqueue);
			return MACH_SEND_NO_BUFFER;
		}
		mqueue->imq_fullwaiters = TRUE;

		if (option & MACH_SEND_TIMEOUT) {
			clock_interval_to_deadline(send_timeout, 1000 * NSEC_PER_USEC, &deadline);
		} else {
			deadline = 0;
		}

		thread_set_pending_block_hint(cur_thread, kThreadWaitPortSend);

		send_turnstile = turnstile_prepare((uintptr_t)port,
		    port_send_turnstile_address(port),
		    TURNSTILE_NULL, TURNSTILE_SYNC_IPC);

		ipc_port_send_update_inheritor(port, send_turnstile,
		    TURNSTILE_DELAYED_UPDATE);

		wresult = waitq_assert_wait64_leeway(
			&send_turnstile->ts_waitq,
			IPC_MQUEUE_FULL,
			THREAD_ABORTSAFE,
			TIMEOUT_URGENCY_USER_NORMAL,
			deadline,
			TIMEOUT_NO_LEEWAY);

		imq_unlock(mqueue);
		turnstile_update_inheritor_complete(send_turnstile,
		    TURNSTILE_INTERLOCK_NOT_HELD);

		if (wresult == THREAD_WAITING) {
			wresult = thread_block(THREAD_CONTINUE_NULL);
		}

		/* Call turnstile complete with interlock held */
		imq_lock(mqueue);
		turnstile_complete((uintptr_t)port, port_send_turnstile_address(port), NULL, TURNSTILE_SYNC_IPC);
		imq_unlock(mqueue);

		/* Call cleanup after dropping the interlock */
		turnstile_cleanup();

		switch (wresult) {
		case THREAD_AWAKENED:
			/*
			 * we can proceed - inherited msgcount from waker
			 * or the message queue has been destroyed and the msgcount
			 * has been reset to zero (will detect in ipc_mqueue_post()).
			 */
			break;

		case THREAD_TIMED_OUT:
			assert(option & MACH_SEND_TIMEOUT);
			return MACH_SEND_TIMED_OUT;

		case THREAD_INTERRUPTED:
			return MACH_SEND_INTERRUPTED;

		case THREAD_RESTART:
			/* mqueue is being destroyed */
			return MACH_SEND_INVALID_DEST;
		default:
			panic("ipc_mqueue_send");
		}
	}

	ipc_mqueue_post(mqueue, kmsg, option);
	return MACH_MSG_SUCCESS;
}

/*
 *	Routine:	ipc_mqueue_override_send
 *	Purpose:
 *		Set an override qos on the first message in the queue
 *		(if the queue is full). This is a send-possible override
 *		that will go away as soon as we drain a message from the
 *		queue.
 *
 *	Conditions:
 *		The message queue is not locked.
 *		The caller holds a reference on the message queue.
 */
void
ipc_mqueue_override_send(
	ipc_mqueue_t        mqueue,
	mach_msg_qos_t      qos_ovr)
{
	boolean_t __unused full_queue_empty = FALSE;

	imq_lock(mqueue);
	assert(imq_valid(mqueue));
	assert(!imq_is_set(mqueue));

	if (imq_full(mqueue)) {
		ipc_kmsg_t first = ipc_kmsg_queue_first(&mqueue->imq_messages);

		if (first && ipc_kmsg_override_qos(&mqueue->imq_messages, first, qos_ovr)) {
			ipc_object_t object = imq_to_object(mqueue);
			assert(io_otype(object) == IOT_PORT);
			ipc_port_t port = ip_object_to_port(object);
			if (ip_active(port) &&
			    port->ip_receiver_name != MACH_PORT_NULL &&
			    is_active(port->ip_receiver) &&
			    ipc_mqueue_has_klist(mqueue)) {
				KNOTE(&mqueue->imq_klist, 0);
			}
		}
		if (!first) {
			full_queue_empty = TRUE;
		}
	}
	imq_unlock(mqueue);

#if DEVELOPMENT || DEBUG
	if (full_queue_empty) {
		ipc_port_t port = ip_from_mq(mqueue);
		int dst_pid = 0;
		dst_pid = ipc_port_get_receiver_task(port, NULL);
	}
#endif
}

/*
 *	Routine:	ipc_mqueue_release_msgcount
 *	Purpose:
 *		Release a message queue reference in the case where we
 *		found a waiter.
 *
 *	Conditions:
 *		The message queue is locked.
 *		The message corresponding to this reference is off the queue.
 *		There is no need to pass reserved preposts because this will
 *		never prepost to anyone
 */
void
ipc_mqueue_release_msgcount(ipc_mqueue_t port_mq, ipc_mqueue_t set_mq)
{
	struct turnstile *send_turnstile = port_send_turnstile(ip_from_mq(port_mq));
	(void)set_mq;
	imq_held(port_mq);
#ifdef __DARLING__
	{
		mach_port_msgcount_t queued;

		/*
		 * FIFO middle-rmqueue and kqchan skip can leave imq_msgcount
		 * at 1 while sl=2 seq 1–7 still sit on the list. Sync to the
		 * real kmsg count before the decrement so mps_msgcount and
		 * ChannelMac timeout-0 mach_msg still see them.
		 */
		queued = ipc_mqueue_queued_msgcount(port_mq);
		if (port_mq->imq_msgcount < queued + 1) {
			port_mq->imq_msgcount = queued + 1;
		}
	}
#else
	assert(port_mq->imq_msgcount > 1 || ipc_kmsg_queue_empty(&port_mq->imq_messages));
#endif

	port_mq->imq_msgcount--;

	if (!imq_full(port_mq) && port_mq->imq_fullwaiters &&
	    send_turnstile != TURNSTILE_NULL) {
		/*
		 * boost the priority of the awoken thread
		 * (WAITQ_PROMOTE_PRIORITY) to ensure it uses
		 * the message queue slot we've just reserved.
		 *
		 * NOTE: this will never prepost
		 *
		 * The wakeup happens on a turnstile waitq
		 * which will wakeup the highest priority waiter.
		 * A potential downside of this would be starving low
		 * priority senders if there is a constant churn of
		 * high priority threads trying to send to this port.
		 */
		if (waitq_wakeup64_one(&send_turnstile->ts_waitq,
		    IPC_MQUEUE_FULL,
		    THREAD_AWAKENED,
		    WAITQ_PROMOTE_PRIORITY) != KERN_SUCCESS) {
			port_mq->imq_fullwaiters = FALSE;
		} else {
			/* gave away our slot - add reference back */
			port_mq->imq_msgcount++;
		}
	}

	if (ipc_kmsg_queue_empty(&port_mq->imq_messages)) {
		/* no more msgs: invalidate the port's prepost object */
		waitq_clear_prepost_locked(&port_mq->imq_wait_queue);
	}
}

/*
 *	Routine:	ipc_mqueue_post
 *	Purpose:
 *		Post a message to a waiting receiver or enqueue it.  If a
 *		receiver is waiting, we can release our reserved space in
 *		the message queue.
 *
 *	Conditions:
 *		mqueue is unlocked
 *		If we need to queue, our space in the message queue is reserved.
 */
void
ipc_mqueue_post(
	ipc_mqueue_t               mqueue,
	ipc_kmsg_t                 kmsg,
	mach_msg_option_t __unused option)
{
	uint64_t reserved_prepost = 0;
	boolean_t destroy_msg = FALSE;

#ifdef __DARLING__
	uint32_t burst_dest = 0;
	ipc_kmsg_t burst_offers[8];
	unsigned burst_n = 0;

	if (dtape_bypass34_try_hold(mqueue, kmsg)) {
		return;
	}
	if (dtape_net_ping_hold(mqueue, kmsg)) {
		imq_lock(mqueue);
		if (mqueue->imq_msgcount > 0) {
			mqueue->imq_msgcount--;
		}
		imq_unlock(mqueue);
		return;
	}
	if (dtape_gpu_channel_nopost(mqueue, kmsg)) {
		imq_lock(mqueue);
		if (mqueue->imq_msgcount > 0) {
			mqueue->imq_msgcount--;
		}
		imq_unlock(mqueue);
		return;
	}
	if (dtape_net_offer_hold(mqueue, kmsg)) {
		imq_lock(mqueue);
		if (mqueue->imq_msgcount > 0) {
			mqueue->imq_msgcount--;
		}
		imq_unlock(mqueue);
		return;
	}
	if (kmsg != IKM_NULL && kmsg->ikm_header != NULL) {
		unsigned pmid = 0, pseq = 0;
		uint64_t psub = 0;

		if (dtape_ipcz_peek(kmsg->ikm_header, 0, &pmid, &pseq, &psub) &&
		    pmid == 22) {
			ipc_kmsg_t offer;

			burst_dest = dtape_mqueue_dest_pid(mqueue);
			dtape_net_bind_note_mq(mqueue);
			while (burst_n < 8) {
				offer = dtape_net_offer_take(mqueue, 0);
				if (offer == IKM_NULL) {
					break;
				}
				burst_offers[burst_n++] = offer;
			}
		}
	}
#endif

	ipc_kmsg_trace_send(kmsg, option);

	/*
	 *	While the msg queue	is locked, we have control of the
	 *  kmsg, so the ref in	it for the port is still good.
	 *
	 *	Check for a receiver for the message.
	 */
	imq_reserve_and_lock(mqueue, &reserved_prepost);

	/* we may have raced with port destruction! */
	if (!imq_valid(mqueue)) {
		destroy_msg = TRUE;
#ifdef __DARLING__
		{
			unsigned bi;

			for (bi = 0; bi < burst_n; bi++) {
				if (burst_offers[bi] != IKM_NULL) {
					ipc_kmsg_destroy(burst_offers[bi]);
					burst_offers[bi] = IKM_NULL;
				}
			}
			burst_n = 0;
		}
#endif
		goto out_unlock;
	}

#ifdef __DARLING__
	{
		unsigned bi;

		for (bi = 0; bi < burst_n; bi++) {
			ipc_kmsg_t offer = burst_offers[bi];
			mach_port_msgcount_t queued;
			unsigned first_msgid = 0, first_seq = 0;
			uint64_t first_sub = 0;

			burst_offers[bi] = IKM_NULL;
			if (offer == IKM_NULL) {
				continue;
			}
			if (!ipc_kmsg_enqueue_qos(&mqueue->imq_messages, offer)) {
				ipc_kmsg_destroy(offer);
				continue;
			}
			queued = ipc_mqueue_queued_msgcount(mqueue);
			if (mqueue->imq_msgcount < queued) {
				mqueue->imq_msgcount = queued;
			} else {
				mqueue->imq_msgcount++;
			}
			if (offer->ikm_header != NULL) {
				(void)dtape_ipcz_peek(offer->ikm_header, 0,
				    &first_msgid, &first_seq, &first_sub);
			}
			dtape_log_error(
			    "handshake_bind_burst_v1 unpark Offer dest_pid=%u first_msgid=%u nmsg=%u then Bind",
			    burst_dest, first_msgid, mqueue->imq_msgcount);
		}
		burst_n = 0;
	}
#endif

	for (;;) {
		struct waitq *waitq = &mqueue->imq_wait_queue;
		spl_t th_spl;
		thread_t receiver;
		mach_msg_size_t msize;

		receiver = waitq_wakeup64_identify_locked(waitq,
		    IPC_MQUEUE_RECEIVE,
		    THREAD_AWAKENED,
		    &th_spl,
		    &reserved_prepost,
		    WAITQ_ALL_PRIORITIES,
		    WAITQ_KEEP_LOCKED);
		/* waitq still locked, thread locked */

		if (receiver == THREAD_NULL) {
			/*
			 * WaitableEvent Wait uses EVFILT_MACHPORT/kqchan, not
			 * mach_msg_receive, so there is no waitq receiver.
			 * Always enqueue (even when imq_msgcount==0) so kqchan
			 * recvmsg wakes. Do not destroy. Honor enqueue_qos
			 * failure. KNOTE only if imq_klist is a real klist
			 * (invalid when the field is a turnstile). When the
			 * klist is a turnstile, notify via the kqchan object.
			 */
			if (ipc_kmsg_enqueue_qos(&mqueue->imq_messages, kmsg)) {
				mach_port_msgcount_t queued;

				/*
				 * imq_msgcount can lag the real kmsg list
				 * (MOVE receive, kqchan skip). Pollers key
				 * off mps_msgcount; keep the counter at
				 * least the queued length.
				 */
				queued = ipc_mqueue_queued_msgcount(mqueue);
				if (mqueue->imq_msgcount < queued) {
					mqueue->imq_msgcount = queued;
				}
				ipc_object_t object = imq_to_object(mqueue);
				bool did_knote = false;
#ifdef __DARLING__
				int sit34 = dtape_sit_inbound20_until_34(mqueue, kmsg);
#else
				int sit34 = 0;
#endif
				if (!sit34 && io_otype(object) == IOT_PORT) {
					ipc_port_t port = ip_object_to_port(object);
					if (ip_active(port) &&
					    port->ip_receiver_name != MACH_PORT_NULL &&
					    is_active(port->ip_receiver) &&
					    ipc_mqueue_has_klist(mqueue) &&
					    SLIST_FIRST(&mqueue->imq_klist)) {
						KNOTE(&mqueue->imq_klist, 0);
						did_knote = true;
					}
				} else if (!sit34 && ipc_mqueue_has_klist(mqueue) &&
				    SLIST_FIRST(&mqueue->imq_klist)) {
					KNOTE(&mqueue->imq_klist, 0);
					did_knote = true;
				}
#ifdef __DARLING__
				/* Always wake dtape kqchans on this mqueue.
				 * KNOTE only walks imq_klist; a turnstile-overlaid
				 * or empty klist used to skip notify and left
				 * bootstrap_check_in receive rights unserved.
				 * Sit helper→browser sl=2 Accept while RLS is
				 * kUnstable so IOThread can SEND msgid 34. */
				if (!sit34) {
					dtape_handshake_drain_34_ahead(mqueue);
					dtape_kqchan_notify_mqueue(mqueue);
					dtape_handshake_drain_bind_posted(mqueue, kmsg);
				}
				ipc_mqueue_post_log(mqueue, THREAD_NULL, ipc_mqueue_has_klist(mqueue),
				    sit34 ? "sit_until_34" :
				    (did_knote ? "klist+kqchan" : "kqchan_object"));
#endif
			}
#ifdef __DARLING__
			else {
				ipc_mqueue_post_log(mqueue, THREAD_NULL, ipc_mqueue_has_klist(mqueue), "enqueue_failed");
			}
#endif
			break;
		}

		/*
		 * If a thread is attempting a "peek" into the message queue
		 * (MACH_PEEK_IN_PROGRESS), then we enqueue the message and set the
		 * thread running.  A successful peek is essentially the same as
		 * message delivery since the peeking thread takes responsibility
		 * for delivering the message and (eventually) removing it from
		 * the mqueue.  Only one thread can successfully use the peek
		 * facility on any given port, so we exit the waitq loop after
		 * encountering such a thread.
		 */
		if (receiver->ith_state == MACH_PEEK_IN_PROGRESS) {
			mach_port_msgcount_t queued;

			ipc_kmsg_enqueue_qos(&mqueue->imq_messages, kmsg);
			queued = ipc_mqueue_queued_msgcount(mqueue);
			if (mqueue->imq_msgcount < queued) {
				mqueue->imq_msgcount = queued;
			}
			ipc_mqueue_peek_on_thread(mqueue, receiver->ith_option, receiver);
			thread_unlock(receiver);
			splx(th_spl);
#ifdef __DARLING__
			ipc_mqueue_post_log(mqueue, receiver, ipc_mqueue_has_klist(mqueue), "peek");
#endif
			break; /* Message was posted, so break out of loop */
		}

		/*
		 * If the receiver waited with a facility not directly related
		 * to Mach messaging, then it isn't prepared to get handed the
		 * message directly. Just set it running, and go look for
		 * another thread that can.
		 *
		 * knote_link_waitq kernel threads must never be treated as
		 * MACH_RCV_IN_PROGRESS waiters — they would steal the kmsg
		 * and skip KNOTE.
		 */
#ifdef __DARLING__
		if (dtape_thread_is_kqchan_waitq_waiter(receiver) ||
		    receiver->ith_state != MACH_RCV_IN_PROGRESS) {
			ipc_mqueue_post_log(mqueue, receiver, ipc_mqueue_has_klist(mqueue),
			    dtape_thread_is_kqchan_waitq_waiter(receiver) ? "skip_kqchan_waiter" : "skip_non_rcv");
			thread_unlock(receiver);
			splx(th_spl);
			continue;
		}
#else
		if (receiver->ith_state != MACH_RCV_IN_PROGRESS) {
			thread_unlock(receiver);
			splx(th_spl);
			continue;
		}
#endif


		/*
		 * We found a waiting thread.
		 * If the message is too large or the scatter list is too small
		 * the thread we wake up will get that as its status.
		 */
		msize = ipc_kmsg_copyout_size(kmsg, receiver->map);
		if (receiver->ith_rsize <
		    (msize + REQUESTED_TRAILER_SIZE(thread_is_64bit_addr(receiver), receiver->ith_option))) {
			receiver->ith_msize = msize;
			receiver->ith_state = MACH_RCV_TOO_LARGE;
		} else {
			receiver->ith_state = MACH_MSG_SUCCESS;
		}

		/*
		 * If there is no problem with the upcoming receive, or the
		 * receiver thread didn't specifically ask for special too
		 * large error condition, go ahead and select it anyway.
		 */
		if ((receiver->ith_state == MACH_MSG_SUCCESS) ||
		    !(receiver->ith_option & MACH_RCV_LARGE)) {
			receiver->ith_kmsg = kmsg;
			receiver->ith_seqno = mqueue->imq_seqno++;
#if MACH_FLIPC
			mach_node_t node = kmsg->ikm_node;
#endif
			thread_unlock(receiver);
			splx(th_spl);

			/* we didn't need our reserved spot in the queue */
			ipc_mqueue_release_msgcount(mqueue, IMQ_NULL);

#if MACH_FLIPC
			if (MACH_NODE_VALID(node) && FPORT_VALID(mqueue->imq_fport)) {
				flipc_msg_ack(node, mqueue, TRUE);
			}
#endif
#ifdef __DARLING__
			/*
			 * A real mach_msg waiter took the kmsg. Still wake the
			 * dtape knote via the kqchan object — do not treat a
			 * turnstile-overlaid imq_klist as a klist.
			 */
			dtape_kqchan_notify_mqueue(mqueue);
			ipc_mqueue_post_log(mqueue, receiver, ipc_mqueue_has_klist(mqueue), "waiter+kqchan_object");
#endif
			break;
		}

		/*
		 * Otherwise, this thread needs to be released to run
		 * and handle its error without getting the message.  We
		 * need to go back and pick another one.
		 */
		receiver->ith_receiver_name = mqueue->imq_receiver_name;
		receiver->ith_kmsg = IKM_NULL;
		receiver->ith_seqno = 0;
		thread_unlock(receiver);
		splx(th_spl);
	}

out_unlock:
	/* clear the waitq boost we may have been given */
	waitq_clear_promotion_locked(&mqueue->imq_wait_queue, current_thread());
	imq_release_and_unlock(mqueue, reserved_prepost);
	if (destroy_msg) {
		ipc_kmsg_destroy(kmsg);
	}

	current_task()->messages_sent++;
#ifdef __DARLING__
	if (!dtape_hold34_repost) {
		dtape_hold34_do_release(0, 0);
	}
#endif
	return;
}


static void
ipc_mqueue_receive_results(wait_result_t saved_wait_result)
{
	thread_t                self = current_thread();
	mach_msg_option_t       option = self->ith_option;

	/*
	 * why did we wake up?
	 */
	switch (saved_wait_result) {
	case THREAD_TIMED_OUT:
		self->ith_state = MACH_RCV_TIMED_OUT;
		return;

	case THREAD_INTERRUPTED:
#ifdef __DARLING__
		/*
		 * Keep a real handed-off kmsg only. ith_kmsg shares a union with
		 * ith_ppriority/ith_qos_override; a non-NULL overlay during
		 * MACH_RCV_IN_PROGRESS is not a kmsg. Stock XNU then sets
		 * MACH_RCV_INTERRUPTED.
		 */
		if (ipc_thread_owns_kmsg(self)) {
			dtape_log_debug("ipc_mqueue_receive_results: THREAD_INTERRUPTED but owns kmsg=%p ith_state=0x%x; keeping handed-off message",
			    self->ith_kmsg, self->ith_state);
			return;
		}
#endif
		self->ith_state = MACH_RCV_INTERRUPTED;
		return;

	case THREAD_RESTART:
		/* something bad happened to the port/set */
		self->ith_state = MACH_RCV_PORT_CHANGED;
		return;

	case THREAD_AWAKENED:
		/*
		 * We do not need to go select a message, somebody
		 * handed us one (or a too-large indication).
		 */
		switch (self->ith_state) {
		case MACH_RCV_SCATTER_SMALL:
		case MACH_RCV_TOO_LARGE:
			/*
			 * Somebody tried to give us a too large
			 * message. If we indicated that we cared,
			 * then they only gave us the indication,
			 * otherwise they gave us the indication
			 * AND the message anyway.
			 */
			if (option & MACH_RCV_LARGE) {
				return;
			}
			return;
		case MACH_MSG_SUCCESS:
			return;
		case MACH_PEEK_READY:
			return;

		default:
			panic("ipc_mqueue_receive_results: strange ith_state");
		}

	default:
		panic("ipc_mqueue_receive_results: strange wait_result");
	}
}

void
ipc_mqueue_receive_continue(
	__unused void *param,
	wait_result_t wresult)
{
#ifdef __DARLING__
	thread_t self = current_thread();
	if (ipc_thread_owns_kmsg(self)) {
		wresult = THREAD_AWAKENED;
	}
	if (wresult == THREAD_WAITING) {
		thread_lock(self);
		self->state |= TH_WAIT;
		thread_unlock(self);
		thread_block(ipc_mqueue_receive_continue);
		/* NOTREACHED */
	}
#endif
	ipc_mqueue_receive_results(wresult);
	mach_msg_receive_continue();  /* hard-coded for now */
}

/*
 *	Routine:	ipc_mqueue_receive
 *	Purpose:
 *		Receive a message from a message queue.
 *
 *	Conditions:
 *		Our caller must hold a reference for the port or port set
 *		to which this queue belongs, to keep the queue
 *		from being deallocated.
 *
 *		The kmsg is returned with clean header fields
 *		and with the circular bit turned off through the ith_kmsg
 *		field of the thread's receive continuation state.
 *	Returns:
 *		MACH_MSG_SUCCESS	Message returned in ith_kmsg.
 *		MACH_RCV_TOO_LARGE	Message size returned in ith_msize.
 *		MACH_RCV_TIMED_OUT	No message obtained.
 *		MACH_RCV_INTERRUPTED	No message obtained.
 *		MACH_RCV_PORT_DIED	Port/set died; no message.
 *		MACH_RCV_PORT_CHANGED	Port moved into set; no msg.
 *
 */

void
ipc_mqueue_receive(
	ipc_mqueue_t            mqueue,
	mach_msg_option_t       option,
	mach_msg_size_t         max_size,
	mach_msg_timeout_t      rcv_timeout,
	int                     interruptible)
{
	wait_result_t           wresult;
	thread_t                self = current_thread();

	imq_lock(mqueue);
	wresult = ipc_mqueue_receive_on_thread(mqueue, option, max_size,
	    rcv_timeout, interruptible,
	    self);
	/* mqueue unlocked */
	if (wresult == THREAD_NOT_WAITING) {
		return;
	}

	if (wresult == THREAD_WAITING) {
		if (self->ith_continuation) {
			thread_block(ipc_mqueue_receive_continue);
		}
		/* NOTREACHED */

		wresult = thread_block(THREAD_CONTINUE_NULL);
	}
	ipc_mqueue_receive_results(wresult);
}

static int
mqueue_process_prepost_receive(void *ctx, struct waitq *waitq,
    struct waitq_set *wqset)
{
	ipc_mqueue_t     port_mq, *pmq_ptr;

	(void)wqset;
	port_mq = (ipc_mqueue_t)waitq;

	/*
	 * If there are no messages on this queue, skip it and remove
	 * it from the prepost list
	 */
	if (ipc_kmsg_queue_empty(&port_mq->imq_messages)) {
		return WQ_ITERATE_INVALIDATE_CONTINUE;
	}

	/*
	 * There are messages waiting on this port.
	 * Instruct the prepost iteration logic to break, but keep the
	 * waitq locked.
	 */
	pmq_ptr = (ipc_mqueue_t *)ctx;
	if (pmq_ptr) {
		*pmq_ptr = port_mq;
	}
	return WQ_ITERATE_BREAK_KEEP_LOCKED;
}

/*
 *	Routine:	ipc_mqueue_receive_on_thread
 *	Purpose:
 *		Receive a message from a message queue using a specified thread.
 *		If no message available, assert_wait on the appropriate waitq.
 *
 *	Conditions:
 *		Assumes thread is self.
 *		Called with mqueue locked.
 *		Returns with mqueue unlocked.
 *		May have assert-waited. Caller must block in those cases.
 */
wait_result_t
ipc_mqueue_receive_on_thread(
	ipc_mqueue_t            mqueue,
	mach_msg_option_t       option,
	mach_msg_size_t         max_size,
	mach_msg_timeout_t      rcv_timeout,
	int                     interruptible,
	thread_t                thread)
{
	wait_result_t           wresult;
	uint64_t                deadline;
	struct turnstile        *rcv_turnstile = TURNSTILE_NULL;

	/* called with mqueue locked */

	/* no need to reserve anything: we never prepost to anyone */

	if (!imq_valid(mqueue)) {
		/* someone raced us to destroy this mqueue/port! */
		imq_unlock(mqueue);
		/*
		 * ipc_mqueue_receive_results updates the thread's ith_state
		 * TODO: differentiate between rights being moved and
		 * rights/ports being destroyed (21885327)
		 */
		return THREAD_RESTART;
	}

	if (imq_is_set(mqueue)) {
		ipc_mqueue_t port_mq = IMQ_NULL;

		(void)waitq_set_iterate_preposts(&mqueue->imq_set_queue,
		    &port_mq,
		    mqueue_process_prepost_receive);

		if (port_mq != IMQ_NULL) {
			/*
			 * We get here if there is at least one message
			 * waiting on port_mq. We have instructed the prepost
			 * iteration logic to leave both the port_mq and the
			 * set mqueue locked.
			 *
			 * TODO: previously, we would place this port at the
			 *       back of the prepost list...
			 */
			imq_unlock(mqueue);

			/*
			 * Continue on to handling the message with just
			 * the port mqueue locked.
			 */
			if (option & MACH_PEEK_MSG) {
				ipc_mqueue_peek_on_thread(port_mq, option, thread);
				imq_unlock(port_mq);
			} else {
				mach_port_msgcount_t remain;

				ipc_mqueue_select_on_thread(port_mq, mqueue, option,
				    max_size, thread);
				remain = ipc_mqueue_queued_msgcount(port_mq);
				imq_unlock(port_mq);
#ifdef __DARLING__
				dtape_net_remain_notify(port_mq, remain);
#endif
			}
			return THREAD_NOT_WAITING;
		}
	} else if (imq_is_queue(mqueue) || imq_is_turnstile_proxy(mqueue)) {
		ipc_kmsg_queue_t kmsgs;

		/*
		 * Receive on a single port. Just try to get the messages.
		 */
		kmsgs = &mqueue->imq_messages;
		if (ipc_kmsg_queue_first(kmsgs) != IKM_NULL) {
			if (option & MACH_PEEK_MSG) {
				ipc_mqueue_peek_on_thread(mqueue, option, thread);
				imq_unlock(mqueue);
			} else {
				mach_port_msgcount_t remain;

				ipc_mqueue_select_on_thread(mqueue, IMQ_NULL, option,
				    max_size, thread);
				remain = ipc_mqueue_queued_msgcount(mqueue);
				imq_unlock(mqueue);
#ifdef __DARLING__
				dtape_net_remain_notify(mqueue, remain);
#endif
			}
			return THREAD_NOT_WAITING;
		}
	} else {
		panic("Unknown mqueue type 0x%x: likely memory corruption!\n",
		    mqueue->imq_wait_queue.waitq_type);
	}

	/*
	 * Looks like we'll have to block.  The mqueue we will
	 * block on (whether the set's or the local port's) is
	 * still locked.
	 */
	if (option & MACH_RCV_TIMEOUT) {
		if (rcv_timeout == 0) {
			imq_unlock(mqueue);
			thread->ith_state = MACH_RCV_TIMED_OUT;
			return THREAD_NOT_WAITING;
		}
	}

	thread->ith_option = option;
	thread->ith_rsize = max_size;
	thread->ith_msize = 0;

	if (option & MACH_PEEK_MSG) {
		thread->ith_state = MACH_PEEK_IN_PROGRESS;
	} else {
#ifdef __DARLING__
		thread->ith_kmsg = IKM_NULL;
#endif
		thread->ith_state = MACH_RCV_IN_PROGRESS;
	}

	if (option & MACH_RCV_TIMEOUT) {
		clock_interval_to_deadline(rcv_timeout, 1000 * NSEC_PER_USEC, &deadline);
	} else {
		deadline = 0;
	}

	/*
	 * Threads waiting on a reply port (not portset)
	 * will wait on its receive turnstile.
	 *
	 * Donate waiting thread's turnstile and
	 * setup inheritor for special reply port.
	 * Based on the state of the special reply
	 * port, the inheritor would be the send
	 * turnstile of the connection port on which
	 * the send of sync ipc would happen or
	 * workloop's turnstile who would reply to
	 * the sync ipc message.
	 *
	 * Pass in mqueue wait in waitq_assert_wait to
	 * support port set wakeup. The mqueue waitq of port
	 * will be converted to to turnstile waitq
	 * in waitq_assert_wait instead of global waitqs.
	 */
	if (imq_is_turnstile_proxy(mqueue)) {
		ipc_port_t port = ip_from_mq(mqueue);
		rcv_turnstile = turnstile_prepare((uintptr_t)port,
		    port_rcv_turnstile_address(port),
		    TURNSTILE_NULL, TURNSTILE_SYNC_IPC);

		ipc_port_recv_update_inheritor(port, rcv_turnstile,
		    TURNSTILE_DELAYED_UPDATE);
	}

	thread_set_pending_block_hint(thread, kThreadWaitPortReceive);
	wresult = waitq_assert_wait64_locked(&mqueue->imq_wait_queue,
	    IPC_MQUEUE_RECEIVE,
	    interruptible,
	    TIMEOUT_URGENCY_USER_NORMAL,
	    deadline,
	    TIMEOUT_NO_LEEWAY,
	    thread);
	/* preposts should be detected above, not here */
	if (wresult == THREAD_AWAKENED) {
		panic("ipc_mqueue_receive_on_thread: sleep walking");
	}

	imq_unlock(mqueue);

	/* Check if its a port mqueue and if it needs to call turnstile_update_inheritor_complete */
	if (rcv_turnstile != TURNSTILE_NULL) {
		turnstile_update_inheritor_complete(rcv_turnstile, TURNSTILE_INTERLOCK_NOT_HELD);
	}
	/* Its callers responsibility to call turnstile_complete to get the turnstile back */

	return wresult;
}


/*
 *	Routine:	ipc_mqueue_peek_on_thread
 *	Purpose:
 *		A receiver discovered that there was a message on the queue
 *		before he had to block. Tell a thread about the message queue,
 *		but don't pick off any messages.
 *	Conditions:
 *		port_mq locked
 *		at least one message on port_mq's message queue
 *
 *	Returns: (on thread->ith_state)
 *		MACH_PEEK_READY		ith_peekq contains a message queue
 */
void
ipc_mqueue_peek_on_thread(
	ipc_mqueue_t        port_mq,
	mach_msg_option_t   option,
	thread_t            thread)
{
	(void)option;
	assert(option & MACH_PEEK_MSG);
	assert(ipc_kmsg_queue_first(&port_mq->imq_messages) != IKM_NULL);

	/*
	 * Take a reference on the mqueue's associated port:
	 * the peeking thread will be responsible to release this reference
	 * using ip_release_mq()
	 */
	ip_reference_mq(port_mq);
	thread->ith_peekq = port_mq;
	thread->ith_state = MACH_PEEK_READY;
}

/*
 *	Routine:	ipc_mqueue_select_on_thread
 *	Purpose:
 *		A receiver discovered that there was a message on the queue
 *		before he had to block.  Pick the message off the queue and
 *		"post" it to thread.
 *	Conditions:
 *		mqueue locked.
 *              thread not locked.
 *		There is a message.
 *		No need to reserve prepost objects - it will never prepost
 *
 *	Returns:
 *		MACH_MSG_SUCCESS	Actually selected a message for ourselves.
 *		MACH_RCV_TOO_LARGE  May or may not have pull it, but it is large
 */
void
ipc_mqueue_select_on_thread(
	ipc_mqueue_t            port_mq,
	ipc_mqueue_t            set_mq,
	mach_msg_option_t       option,
	mach_msg_size_t         max_size,
	thread_t                thread)
{
	ipc_kmsg_t kmsg;
	mach_msg_return_t mr = MACH_MSG_SUCCESS;
	mach_msg_size_t msize;

	/*
	 * Do some sanity checking of our ability to receive
	 * before pulling the message off the queue.
	 */
	kmsg = ipc_kmsg_queue_first(&port_mq->imq_messages);
	assert(kmsg != IKM_NULL);

#ifdef __DARLING__
	/*
	 * Handshake drain Offer before mjhs. Rotate leftover Channel
	 * Offer to head so timeout-0 cannot OnOffer during Connect.
	 * True FIFO otherwise. Do not steal occupancy 20 from behind
	 * Connect/Bind.
	 */
	dtape_handshake_drain_offer_ahead(port_mq);
	dtape_handshake_drain_34_ahead(port_mq);
	kmsg = ipc_kmsg_queue_first(&port_mq->imq_messages);
	assert(kmsg != IKM_NULL);
	{
		unsigned msgid = 0, seq = 0;
		uint64_t sub = 0;
		static int keep_n;

		(void)dtape_mqueue_fifo_v1;
		(void)dtape_mqueue_fifo_head_v1;
		if (kmsg->ikm_header != NULL &&
		    dtape_ipcz_peek(kmsg->ikm_header, 0, &msgid, &seq, &sub) &&
		    (msgid == 1 || msgid == 22 || msgid == 20 || msgid == 34) &&
		    keep_n < 64) {
			keep_n++;
			dtape_log_error(
			    "mqueue_fifo_head_v1 keep msgid=%u seq=%u sl=%llu nmsg=%u",
			    msgid, seq, (unsigned long long)sub,
			    port_mq->imq_msgcount);
		}
	}
#endif

	/*
	 * If we really can't receive it, but we had the
	 * MACH_RCV_LARGE option set, then don't take it off
	 * the queue, instead return the appropriate error
	 * (and size needed).
	 */
	msize = ipc_kmsg_copyout_size(kmsg, thread->map);
	if (msize + REQUESTED_TRAILER_SIZE(thread_is_64bit_addr(thread), option) > max_size) {
		mr = MACH_RCV_TOO_LARGE;
		if (option & MACH_RCV_LARGE) {
			thread->ith_receiver_name = port_mq->imq_receiver_name;
			thread->ith_kmsg = IKM_NULL;
			thread->ith_msize = msize;
			thread->ith_seqno = 0;
			thread->ith_state = mr;
			return;
		}
	}

	ipc_kmsg_rmqueue(&port_mq->imq_messages, kmsg);
#if MACH_FLIPC
	if (MACH_NODE_VALID(kmsg->ikm_node) && FPORT_VALID(port_mq->imq_fport)) {
		flipc_msg_ack(kmsg->ikm_node, port_mq, TRUE);
	}
#endif
	ipc_mqueue_release_msgcount(port_mq, set_mq);
	thread->ith_seqno = port_mq->imq_seqno++;
	thread->ith_kmsg = kmsg;
	thread->ith_state = mr;

#ifdef __DARLING__
	/*
	 * Honest mps_msgcount after dequeue so libkqueue's same-port 1ns
	 * re-arm (and EV_DISPATCH enable) can see remaining kmsgs.
	 * Do not dtape_kqchan_notify_mqueue here: remain-notify on every
	 * mqueue (and even msgid-20-only) stormed remain=52 and GPU
	 * ImmediateCrash 0x9105218 came back. ChannelMac is notify-only
	 * and does not loop; remaining seq 1–7 wake via that knote only.
	 */
	{
		mach_port_msgcount_t remain;

		(void)dtape_mqueue_remain_count_v1;
		remain = ipc_mqueue_queued_msgcount(port_mq);
		if (port_mq->imq_msgcount < remain) {
			port_mq->imq_msgcount = remain;
		}
	}
#endif

	current_task()->messages_received++;
	return;
}

/*
 *	Routine:	ipc_mqueue_peek_locked
 *	Purpose:
 *		Peek at a (non-set) message queue to see if it has a message
 *		matching the sequence number provided (if zero, then the
 *		first message in the queue) and return vital info about the
 *		message.
 *
 *	Conditions:
 *		The ipc_mqueue_t is locked by callers.
 *		Other locks may be held by callers, so this routine cannot block.
 *		Caller holds reference on the message queue.
 */
unsigned
ipc_mqueue_peek_locked(ipc_mqueue_t mq,
    mach_port_seqno_t * seqnop,
    mach_msg_size_t * msg_sizep,
    mach_msg_id_t * msg_idp,
    mach_msg_max_trailer_t * msg_trailerp,
    ipc_kmsg_t *kmsgp)
{
	ipc_kmsg_queue_t kmsgq;
	ipc_kmsg_t kmsg;
	mach_port_seqno_t seqno, msgoff;
	unsigned res = 0;

	assert(!imq_is_set(mq));

	seqno = 0;
	if (seqnop != NULL) {
		seqno = *seqnop;
	}

	if (seqno == 0) {
		seqno = mq->imq_seqno;
		msgoff = 0;
	} else {
		mach_port_msgcount_t queued = ipc_mqueue_queued_msgcount(mq);

		if (seqno >= mq->imq_seqno &&
		    seqno < mq->imq_seqno + queued) {
			msgoff = seqno - mq->imq_seqno;
		} else {
			goto out;
		}
	}

	/* look for the message that would match that seqno */
	kmsgq = &mq->imq_messages;
	kmsg = ipc_kmsg_queue_first(kmsgq);
	while (msgoff-- && kmsg != IKM_NULL) {
		kmsg = ipc_kmsg_queue_next(kmsgq, kmsg);
	}
	if (kmsg == IKM_NULL) {
		goto out;
	}

	/* found one - return the requested info */
	if (seqnop != NULL) {
		*seqnop = seqno;
	}
	if (msg_sizep != NULL) {
		*msg_sizep = kmsg->ikm_header->msgh_size;
	}
	if (msg_idp != NULL) {
		*msg_idp = kmsg->ikm_header->msgh_id;
	}
	if (msg_trailerp != NULL) {
		memcpy(msg_trailerp,
		    (mach_msg_max_trailer_t *)((vm_offset_t)kmsg->ikm_header +
		    mach_round_msg(kmsg->ikm_header->msgh_size)),
		    sizeof(mach_msg_max_trailer_t));
	}
	if (kmsgp != NULL) {
		*kmsgp = kmsg;
	}

	res = 1;

out:
	return res;
}


/*
 *	Routine:	ipc_mqueue_peek
 *	Purpose:
 *		Peek at a (non-set) message queue to see if it has a message
 *		matching the sequence number provided (if zero, then the
 *		first message in the queue) and return vital info about the
 *		message.
 *
 *	Conditions:
 *		The ipc_mqueue_t is unlocked.
 *		Locks may be held by callers, so this routine cannot block.
 *		Caller holds reference on the message queue.
 */
unsigned
ipc_mqueue_peek(ipc_mqueue_t mq,
    mach_port_seqno_t * seqnop,
    mach_msg_size_t * msg_sizep,
    mach_msg_id_t * msg_idp,
    mach_msg_max_trailer_t * msg_trailerp,
    ipc_kmsg_t *kmsgp)
{
	unsigned res;

	imq_lock(mq);

	res = ipc_mqueue_peek_locked(mq, seqnop, msg_sizep, msg_idp,
	    msg_trailerp, kmsgp);

	imq_unlock(mq);
	return res;
}

/*
 *	Routine:	ipc_mqueue_release_peek_ref
 *	Purpose:
 *		Release the reference on an mqueue's associated port which was
 *		granted to a thread in ipc_mqueue_peek_on_thread (on the
 *		MACH_PEEK_MSG thread wakeup path).
 *
 *	Conditions:
 *		The ipc_mqueue_t should be locked on entry.
 *		The ipc_mqueue_t will be _unlocked_ on return
 *			(and potentially invalid!)
 *
 */
void
ipc_mqueue_release_peek_ref(ipc_mqueue_t mq)
{
	assert(!imq_is_set(mq));
	imq_held(mq);

	/*
	 * clear any preposts this mq may have generated
	 * (which would cause subsequent immediate wakeups)
	 */
	waitq_clear_prepost_locked(&mq->imq_wait_queue);

	imq_unlock(mq);

	/*
	 * release the port reference: we need to do this outside the lock
	 * because we might be holding the last port reference!
	 **/
	ip_release_mq(mq);
}

/*
 * peek at the contained port message queues, break prepost iteration as soon
 * as we spot a message on one of the message queues referenced by the set's
 * prepost list.  No need to lock each message queue, as only the head of each
 * queue is checked. If a message wasn't there before we entered here, no need
 * to find it (if we do, great).
 */
static int
mqueue_peek_iterator(void *ctx, struct waitq *waitq,
    struct waitq_set *wqset)
{
	ipc_mqueue_t port_mq = (ipc_mqueue_t)waitq;
	ipc_kmsg_queue_t kmsgs = &port_mq->imq_messages;

	(void)ctx;
	(void)wqset;

	if (ipc_kmsg_queue_first(kmsgs) != IKM_NULL) {
		return WQ_ITERATE_BREAK; /* break out of the prepost iteration */
	}
	return WQ_ITERATE_CONTINUE;
}

/*
 *	Routine:	ipc_mqueue_set_peek
 *	Purpose:
 *		Peek at a message queue set to see if it has any ports
 *		with messages.
 *
 *	Conditions:
 *		Locks may be held by callers, so this routine cannot block.
 *		Caller holds reference on the message queue.
 */
unsigned
ipc_mqueue_set_peek(ipc_mqueue_t mq)
{
	int ret;

	imq_lock(mq);

	/*
	 * We may have raced with port destruction where the mqueue is marked
	 * as invalid. In that case, even though we don't have messages, we
	 * have an end-of-life event to deliver.
	 */
	if (!imq_is_valid(mq)) {
		return 1;
	}

	ret = waitq_set_iterate_preposts(&mq->imq_set_queue, NULL,
	    mqueue_peek_iterator);

	imq_unlock(mq);

	return ret == WQ_ITERATE_BREAK;
}

/*
 *	Routine:	ipc_mqueue_set_gather_member_names
 *	Purpose:
 *		Discover all ports which are members of a given port set.
 *		Because the waitq linkage mechanism was redesigned to save
 *		significan amounts of memory, it no longer keeps back-pointers
 *		from a port set to a port. Therefore, we must iterate over all
 *		ports within a given IPC space and individually query them to
 *		see if they are members of the given set. Port names of ports
 *		found to be members of the given set will be gathered into the
 *		provided 'names' array.  Actual returned names are limited to
 *		maxnames entries, but we keep counting the actual number of
 *		members to let the caller decide to retry if necessary.
 *
 *	Conditions:
 *		Locks may be held by callers, so this routine cannot block.
 *		Caller holds reference on the message queue (via port set).
 */
void
ipc_mqueue_set_gather_member_names(
	ipc_space_t space,
	ipc_mqueue_t set_mq,
	ipc_entry_num_t maxnames,
	mach_port_name_t *names,
	ipc_entry_num_t *actualp)
{
	ipc_entry_t table;
	ipc_entry_num_t tsize;
	struct waitq_set *wqset;
	ipc_entry_num_t actual = 0;

	assert(set_mq != IMQ_NULL);
	wqset = &set_mq->imq_set_queue;

	assert(space != IS_NULL);
	is_read_lock(space);
	if (!is_active(space)) {
		is_read_unlock(space);
		goto out;
	}

	if (!waitq_set_is_valid(wqset)) {
		is_read_unlock(space);
		goto out;
	}

	table = space->is_table;
	tsize = space->is_table_size;
	for (ipc_entry_num_t idx = 0; idx < tsize; idx++) {
		ipc_entry_t entry = &table[idx];

		/* only receive rights can be members of port sets */
		if ((entry->ie_bits & MACH_PORT_TYPE_RECEIVE) != MACH_PORT_TYPE_NONE) {
			ipc_port_t port = ip_object_to_port(entry->ie_object);
			ipc_mqueue_t mq = &port->ip_messages;

			assert(IP_VALID(port));
			if (ip_active(port) &&
			    waitq_member(&mq->imq_wait_queue, wqset)) {
				if (actual < maxnames) {
					names[actual] = mq->imq_receiver_name;
				}
				actual++;
			}
		}
	}

	is_read_unlock(space);

out:
	*actualp = actual;
}


/*
 *	Routine:	ipc_mqueue_destroy_locked
 *	Purpose:
 *		Destroy a (non-set) message queue.
 *		Set any blocked senders running.
 *	        Destroy the kmsgs in the queue.
 *	Conditions:
 *		mqueue locked
 *		Receivers were removed when the receive right was "changed"
 */
boolean_t
ipc_mqueue_destroy_locked(ipc_mqueue_t mqueue)
{
	ipc_kmsg_queue_t kmqueue;
	ipc_kmsg_t kmsg;
	boolean_t reap = FALSE;
	struct turnstile *send_turnstile = port_send_turnstile(ip_from_mq(mqueue));

	assert(!imq_is_set(mqueue));

	/*
	 *	rouse all blocked senders
	 *	(don't boost anyone - we're tearing this queue down)
	 *	(never preposts)
	 */
	mqueue->imq_fullwaiters = FALSE;

	if (send_turnstile != TURNSTILE_NULL) {
		waitq_wakeup64_all(&send_turnstile->ts_waitq,
		    IPC_MQUEUE_FULL,
		    THREAD_RESTART,
		    WAITQ_ALL_PRIORITIES);
	}

	/*
	 * Move messages from the specified queue to the per-thread
	 * clean/drain queue while we have the mqueue lock.
	 */
	kmqueue = &mqueue->imq_messages;
	while ((kmsg = ipc_kmsg_dequeue(kmqueue)) != IKM_NULL) {
#if MACH_FLIPC
		if (MACH_NODE_VALID(kmsg->ikm_node) && FPORT_VALID(mqueue->imq_fport)) {
			flipc_msg_ack(kmsg->ikm_node, mqueue, TRUE);
		}
#endif
		boolean_t first;
		first = ipc_kmsg_delayed_destroy(kmsg);
		if (first) {
			reap = first;
		}
	}

	/*
	 * Wipe out message count, both for messages about to be
	 * reaped and for reserved space for (previously) woken senders.
	 * This is the indication to them that their reserved space is gone
	 * (the mqueue was destroyed).
	 */
	mqueue->imq_msgcount = 0;

	/* invalidate the waitq for subsequent mqueue operations */
	waitq_invalidate_locked(&mqueue->imq_wait_queue);

	/* clear out any preposting we may have done */
	waitq_clear_prepost_locked(&mqueue->imq_wait_queue);

	/*
	 * assert that we are destroying / invalidating a queue that's
	 * not a member of any other queue.
	 */
	assert(mqueue->imq_preposts == 0);
	assert(mqueue->imq_in_pset == 0);

	return reap;
}

/*
 *	Routine:	ipc_mqueue_set_qlimit
 *	Purpose:
 *		Changes a message queue limit; the maximum number
 *		of messages which may be queued.
 *	Conditions:
 *		Port is locked.
 */

void
ipc_mqueue_set_qlimit(
	ipc_mqueue_t                   mqueue,
	mach_port_msgcount_t   qlimit)
{
	assert(qlimit <= MACH_PORT_QLIMIT_MAX);

	/* wake up senders allowed by the new qlimit */
	imq_lock(mqueue);
	if (qlimit > mqueue->imq_qlimit) {
		mach_port_msgcount_t i, wakeup;
		struct turnstile *send_turnstile = port_send_turnstile(ip_from_mq(mqueue));

		/* caution: wakeup, qlimit are unsigned */
		wakeup = qlimit - mqueue->imq_qlimit;

		for (i = 0; i < wakeup; i++) {
			/*
			 * boost the priority of the awoken thread
			 * (WAITQ_PROMOTE_PRIORITY) to ensure it uses
			 * the message queue slot we've just reserved.
			 *
			 * NOTE: this will never prepost
			 */
			if (send_turnstile == TURNSTILE_NULL ||
			    waitq_wakeup64_one(&send_turnstile->ts_waitq,
			    IPC_MQUEUE_FULL,
			    THREAD_AWAKENED,
			    WAITQ_PROMOTE_PRIORITY) == KERN_NOT_WAITING) {
				mqueue->imq_fullwaiters = FALSE;
				break;
			}
			mqueue->imq_msgcount++;  /* give it to the awakened thread */
		}
	}
	mqueue->imq_qlimit = (uint16_t)qlimit;
	imq_unlock(mqueue);
}

/*
 *	Routine:	ipc_mqueue_set_seqno
 *	Purpose:
 *		Changes an mqueue's sequence number.
 *	Conditions:
 *		Caller holds a reference to the queue's containing object.
 */
void
ipc_mqueue_set_seqno(
	ipc_mqueue_t            mqueue,
	mach_port_seqno_t       seqno)
{
	imq_lock(mqueue);
	mqueue->imq_seqno = seqno;
	imq_unlock(mqueue);
}


/*
 *	Routine:	ipc_mqueue_copyin
 *	Purpose:
 *		Convert a name in a space to a message queue.
 *	Conditions:
 *		Nothing locked.  If successful, the caller gets a ref for
 *		for the object.	This ref ensures the continued existence of
 *		the queue.
 *	Returns:
 *		MACH_MSG_SUCCESS	Found a message queue.
 *		MACH_RCV_INVALID_NAME	The space is dead.
 *		MACH_RCV_INVALID_NAME	The name doesn't denote a right.
 *		MACH_RCV_INVALID_NAME
 *			The denoted right is not receive or port set.
 *		MACH_RCV_IN_SET		Receive right is a member of a set.
 */

mach_msg_return_t
ipc_mqueue_copyin(
	ipc_space_t             space,
	mach_port_name_t        name,
	ipc_mqueue_t            *mqueuep,
	ipc_object_t            *objectp)
{
	ipc_entry_t entry;
	ipc_entry_bits_t bits;
	ipc_object_t object;
	ipc_mqueue_t mqueue;

	is_read_lock(space);
	if (!is_active(space)) {
		is_read_unlock(space);
		return MACH_RCV_INVALID_NAME;
	}

	entry = ipc_entry_lookup(space, name);
	if (entry == IE_NULL) {
		is_read_unlock(space);
		return MACH_RCV_INVALID_NAME;
	}

	bits = entry->ie_bits;
	object = entry->ie_object;

	if (bits & MACH_PORT_TYPE_RECEIVE) {
		ipc_port_t port = ip_object_to_port(object);

		assert(port != IP_NULL);

		ip_lock(port);
		require_ip_active(port);
		assert(port->ip_receiver_name == name);
		assert(port->ip_receiver == space);
		is_read_unlock(space);
		mqueue = &port->ip_messages;
	} else if (bits & MACH_PORT_TYPE_PORT_SET) {
		ipc_pset_t pset = ips_object_to_pset(object);

		assert(pset != IPS_NULL);

		ips_lock(pset);
		assert(ips_active(pset));
		is_read_unlock(space);

		mqueue = &pset->ips_messages;
	} else {
		is_read_unlock(space);
		/* guard exception if we never held the receive right in this entry */
		if ((bits & MACH_PORT_TYPE_EX_RECEIVE) == 0) {
			mach_port_guard_exception(name, 0, 0, kGUARD_EXC_RCV_INVALID_NAME);
		}
		return MACH_RCV_INVALID_NAME;
	}

	/*
	 *	At this point, the object is locked and active,
	 *	the space is unlocked, and mqueue is initialized.
	 */

	io_reference(object);
	io_unlock(object);

	*objectp = object;
	*mqueuep = mqueue;
	return MACH_MSG_SUCCESS;
}

void
imq_lock(ipc_mqueue_t mq)
{
	ipc_object_t object = imq_to_object(mq);
	ipc_object_validate(object);
	waitq_lock(&(mq)->imq_wait_queue);
}

unsigned int
imq_lock_try(ipc_mqueue_t mq)
{
	ipc_object_t object = imq_to_object(mq);
	ipc_object_validate(object);
	return waitq_lock_try(&(mq)->imq_wait_queue);
}
