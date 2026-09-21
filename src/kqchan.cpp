#include <darlingserver/kqchan.hpp>
#include <darlingserver/server.hpp>
#include <darlingserver/rpc-supplement.h>
#include <darlingserver/thread.hpp>
#include <darlingserver/process.hpp>
#include <darlingserver/logging.hpp>

#include <sys/socket.h>
#include <fcntl.h>
#include <unistd.h>
#include <dirent.h>
#include <time.h>
#include <atomic>
#include <cstring>
#include <cstdio>
#include <stdio.h>

/*
 * ChannelMac WatchMachReceivePort is notify-only (no MACH_RCV_MSG).
 * kqchan mach_port_read used to filt_machportprocess/fill on the
 * opener's Chrome_IOThread; that raced timeout-0 mach_msg and left
 * network ChannelMac stuck at nmsg=21 after 7 peeks.
 */
#ifndef MACH_RCV_MSG
#define MACH_RCV_MSG 0x00000002u
#endif

__attribute__((used)) static const char kqchan_notify_ack_nofill_v1[] =
	"kqchan_notify_ack_nofill_v1";
__attribute__((used)) static const char kqchan_notify_ack_nofill_gpu_notif0[] =
	"kqchan_notify_ack_nofill_v1 gpu notif=0";
__attribute__((used)) static const char kqchan_gpu_cage_hold_v1[] =
	"kqchan_gpu_cage_hold_v1";
__attribute__((used)) static const char kqchan_net_after_cage_v1[] =
	"kqchan_net_after_cage_v1";
__attribute__((used)) static const char kqchan_net_hold_until_cage_v1[] =
	"kqchan_net_hold_until_cage_v1";
__attribute__((used)) static const char kqchan_net_after_crgpumain_v1[] =
	"kqchan_net_after_crgpumain_v1";
__attribute__((used)) static const char kqchan_net_hold_until_crgpumain_v1[] =
	"kqchan_net_hold_until_crgpumain_v1";
__attribute__((used)) static const char kqchan_net_after_gpu_alive_v1[] =
	"kqchan_net_after_gpu_alive";
__attribute__((used)) static const char kqchan_net_hold_until_gpu_alive_v1[] =
	"kqchan_net_hold_until_gpu_alive";
__attribute__((used)) static const char kqchan_gpu_alive_10s_v1[] =
	"gpu-alive-10s";
__attribute__((used)) static const char kqchan_gpu_detect_v1[] =
	"kqchan_gpu_detect_v1";
__attribute__((used)) static const char kqchan_gpu_copyout_drop_v1[] =
	"kqchan_gpu_copyout_drop_v1";
__attribute__((used)) static const char kqchan_gpu_hs20_drain_v1[] =
	"kqchan_gpu_hs20_drain_v1";
__attribute__((used)) static const char kqchan_gpu_hs20_until_alive_v1[] =
	"kqchan_gpu_hs20_until_alive_v1";
__attribute__((used)) static const char kqchan_gpu_hs35_after20_v1[] =
	"kqchan_gpu_hs35_after20_v1";
__attribute__((used)) static const char kqchan_gpu_hs35_delay_alive_v1[] =
	"kqchan_gpu_hs35_after20_v1 delay";
__attribute__((used)) static const char kqchan_gpu_hs20_park_cap_v1[] =
	"kqchan_gpu_hs20_park_cap_v1";
__attribute__((used)) static const char kqchan_net_ping_dest_v1[] =
	"kqchan_net_ping_dest_v1";
__attribute__((used)) static const char kqchan_net_hold_off_v1[] =
	"kqchan_net_hold_off_v1";
__attribute__((used)) static const char kqchan_net_remain_v1[] =
	"kqchan_net_remain_v1";
__attribute__((used)) static const char kqchan_handshake_drain_bind_v1[] =
	"handshake_drain_bind_v1";
__attribute__((used)) static const char kqchan_handshake_bind_burst_v1[] =
	"handshake_bind_burst_v1";
__attribute__((used)) static const char kqchan_handshake_drain_offer_v1[] =
	"handshake_drain_offer_v1";
__attribute__((used)) static const char kqchan_handshake_drain_bind_browser_v1[] =
	"handshake_drain_bind_v1 browser Channel";

static DarlingServer::Log kqchanLog("kqchan");
static DarlingServer::Log kqchanMachPortLog("kqchan:mach_port");
static DarlingServer::Log kqchanProcLog("kqchan:proc");
static std::atomic_uint64_t kqchanDebugIDCounter = 0;
static std::atomic<int> g_gpuPaSurvived{0};
static std::atomic<pid_t> g_gpuHelperPid{0};
static std::atomic<time_t> g_gpuHelperSeen{0};
static std::atomic<long> g_gpuAgeAtRelease{0};
static std::atomic<const char*> g_gpuReleaseWhy{""};
static std::atomic<int> g_hs20AliveArmed{0};
static std::atomic<int> g_netPingArmed{0};
/*
 * Ping (msgid 20 proto=4 sl=2) waits for gpu-alive-10s. GPU Channel
 * Bind 22 / hs 34 / occupancy 20 do not. Holding every network
 * _sendNotification until that latch delayed Bind ~10s (code207).
 * One notify on Ping release (do not dump nmsg=18 as 18 events).
 */
static const long kGpuPaSurviveSec = 10;

enum {
	KQCHAN_ROLE_OTHER = 0,
	KQCHAN_ROLE_NETWORK = 1,
	KQCHAN_ROLE_GPU = 2,
	KQCHAN_ROLE_STORAGE = 3,
};

static int
cmdlineTokenIsGpu(const char *s)
{
	if (s == NULL || s[0] == '\0') {
		return 0;
	}
	if (strcmp(s, "--type=gpu-process") == 0) {
		return 1;
	}
	if (std::strstr(s, "Helper (GPU)") != NULL) {
		return 1;
	}
	return 0;
}

static int
cmdlineChannelRole(pid_t pid)
{
	char path[64];
	char buf[4096];
	ssize_t n;
	ssize_t i;
	int fd;
	int role = KQCHAN_ROLE_OTHER;
	const char *argv0 = "";
	const char *hit = NULL;
	static std::atomic<int> gpu_hit_log_n{0};

	snprintf(path, sizeof(path), "/proc/%d/cmdline", (int)pid);
	fd = open(path, O_RDONLY | O_CLOEXEC);
	if (fd < 0) {
		return KQCHAN_ROLE_OTHER;
	}
	n = read(fd, buf, sizeof(buf) - 1);
	close(fd);
	if (n <= 0) {
		return KQCHAN_ROLE_OTHER;
	}
	buf[n] = '\0';
	argv0 = buf;
	for (i = 0; i < n; ) {
		if (cmdlineTokenIsGpu(buf + i)) {
			hit = buf + i;
			role = KQCHAN_ROLE_GPU;
			break;
		}
		if (std::strstr(buf + i, "network.mojom.NetworkService") != NULL) {
			role = KQCHAN_ROLE_NETWORK;
		}
		if (std::strstr(buf + i, "storage.mojom.StorageService") != NULL &&
		    role != KQCHAN_ROLE_NETWORK) {
			role = KQCHAN_ROLE_STORAGE;
		}
		i += (ssize_t)strlen(buf + i) + 1;
	}
	if (role == KQCHAN_ROLE_GPU) {
		g_gpuHelperPid.store(pid);
		if (hit != NULL && gpu_hit_log_n.fetch_add(1) < 16) {
			(void)kqchan_gpu_detect_v1;
			kqchanMachPortLog.error()
				<< "gpu detect hit pid=" << pid
				<< " src=host-cmdline argv0=" << argv0
				<< " arg=" << hit
				<< kqchanMachPortLog.endLog;
		}
	}
	return role;
}

/*
 * ipc_mqueue_post handshake-drains GPU Channel occupancy
 * (msgid 20): one parcel sits, extras park. Handshake/control
 * still posts: Bind (22), BypassPeerWithLink (34), msgid 36.
 * StopProxying (35) waits for msgid-20 copyout and
 * gpu-alive-10s + CrGpuMain. Guest evfilt_machport_copyout
 * still delivers when nmsg>0 even after
 * kqchan_notify_ack_nofill; parked extras (not a notify
 * storm) keep nmsg small.
 */
extern "C" int
dtape_host_cmdline_is_gpu(unsigned nsid)
{
	int role;

	if (nsid == 0) {
		return 0;
	}
	if (g_gpuHelperPid.load() == (pid_t)nsid) {
		return 1;
	}
	role = cmdlineChannelRole((pid_t)nsid);
	return role == KQCHAN_ROLE_GPU;
}

extern "C" int
dtape_host_cmdline_is_network(unsigned nsid)
{
	if (nsid == 0) {
		return 0;
	}
	return cmdlineChannelRole((pid_t)nsid) == KQCHAN_ROLE_NETWORK;
}

extern "C" int
dtape_host_cmdline_is_storage(unsigned nsid)
{
	if (nsid == 0) {
		return 0;
	}
	return cmdlineChannelRole((pid_t)nsid) == KQCHAN_ROLE_STORAGE;
}

static bool
gpuHelperPidAlive(pid_t pid)
{
	char path[64];
	char buf[64];
	int fd;
	ssize_t n;

	if (pid <= 0) {
		return false;
	}
	snprintf(path, sizeof(path), "/proc/%d/cmdline", (int)pid);
	fd = open(path, O_RDONLY | O_CLOEXEC);
	if (fd < 0) {
		return false;
	}
	n = read(fd, buf, sizeof(buf) - 1);
	close(fd);
	return n > 0;
}

static long
gpuHelperAgeSec(time_t now)
{
	time_t seen = g_gpuHelperSeen.load();

	if (seen == 0 || now < seen) {
		return 0;
	}
	return (long)(now - seen);
}

static void
maybeLatchGpuPaSurvived(pid_t pid, time_t now)
{
	long age;

	if (pid <= 0 || !gpuHelperPidAlive(pid)) {
		return;
	}
	if (g_gpuHelperSeen.load() == 0) {
		g_gpuHelperSeen.store(now);
	}
	age = gpuHelperAgeSec(now);
	/*
	 * Do not latch on CrGpuMain/llvmpipe. code193 saw CrGpuMain
	 * at GPU age 0 during PA and ROOT98CHK'd packed=0 ~2s.
	 */
	if (age >= kGpuPaSurviveSec) {
		(void)kqchan_gpu_alive_10s_v1;
		g_gpuReleaseWhy.store(kqchan_gpu_alive_10s_v1);
		g_gpuAgeAtRelease.store(age);
		g_gpuPaSurvived.store(1);
	}
}

static void
refreshGpuPaSurvived(void)
{
	pid_t cached;
	time_t now;

	if (g_gpuPaSurvived.load() > 0) {
		return;
	}
	now = time(NULL);
	cached = g_gpuHelperPid.load();
	if (cached > 0) {
		if (!gpuHelperPidAlive(cached)) {
			g_gpuHelperPid.store(0);
			g_gpuHelperSeen.store(0);
		} else {
			maybeLatchGpuPaSurvived(cached, now);
			return;
		}
	}
	auto procs = DarlingServer::processRegistry().copyEntries();
	for (const auto& proc : procs) {
		if (!proc || proc->isDead()) {
			continue;
		}
		if (cmdlineChannelRole(proc->id()) != KQCHAN_ROLE_GPU) {
			continue;
		}
		g_gpuHelperPid.store(proc->id());
		maybeLatchGpuPaSurvived(proc->id(), now);
		return;
	}
}

static int
gpuHelperHasCrGpuMain(void)
{
	pid_t pid;
	DIR *d;
	struct dirent *de;
	char path[64];
	char name[32];
	FILE *fp;

	pid = g_gpuHelperPid.load();
	if (pid <= 0) {
		return 0;
	}
	snprintf(path, sizeof(path), "/proc/%d/task", (int)pid);
	d = opendir(path);
	if (!d) {
		return 0;
	}
	while ((de = readdir(d)) != NULL) {
		char *nl;

		if (de->d_name[0] == '.') {
			continue;
		}
		snprintf(path, sizeof(path), "/proc/%d/task/%s/comm",
			(int)pid, de->d_name);
		fp = fopen(path, "r");
		if (!fp) {
			continue;
		}
		if (fgets(name, sizeof(name), fp) == NULL) {
			fclose(fp);
			continue;
		}
		fclose(fp);
		nl = strchr(name, '\n');
		if (nl) {
			*nl = '\0';
		}
		if (strncmp(name, "CrGpuMain", 9) == 0) {
			closedir(d);
			return 1;
		}
	}
	closedir(d);
	return 0;
}

extern "C" int
dtape_gpu_alive_10s_crgpu(void)
{
	refreshGpuPaSurvived();
	if (g_gpuPaSurvived.load() <= 0) {
		return 0;
	}
	return gpuHelperHasCrGpuMain();
}

extern "C" void dtape_gpu_hs20_alive_release(uint32_t dest_pid);
extern "C" void dtape_net_ping_alive_release(uint32_t dest_pid);

extern "C" void
dtape_net_ping_arm_after_alive(uint32_t dest_pid)
{
	if (dest_pid == 0) {
		return;
	}
	if (g_netPingArmed.exchange(1) != 0) {
		return;
	}
	(void)kqchan_net_hold_until_gpu_alive_v1;
	kqchanMachPortLog.error()
		<< "kqchan_net_hold_until_gpu_alive dest_pid=" << dest_pid
		<< " ping until gpu-alive-10s"
		<< kqchanMachPortLog.endLog;
	DarlingServer::Thread::kernelAsync([dest_pid]() {
		for (int i = 0; i < 800; i++) {
			usleep(50000);
			if (dtape_gpu_alive_10s_crgpu()) {
				kqchanMachPortLog.error()
					<< "kqchan_net_after_gpu_alive dest_pid="
					<< dest_pid
					<< " ping after gpu-alive-10s CrGpuMain"
					<< kqchanMachPortLog.endLog;
				dtape_net_ping_alive_release(dest_pid);
				return;
			}
		}
		kqchanMachPortLog.error()
			<< "kqchan_net_hold_until_gpu_alive timeout dest_pid="
			<< dest_pid
			<< kqchanMachPortLog.endLog;
	});
}

extern "C" void
dtape_gpu_hs20_arm_after_alive(uint32_t dest_pid)
{
	if (dest_pid == 0) {
		return;
	}
	if (g_hs20AliveArmed.exchange(1) != 0) {
		return;
	}
	(void)kqchan_gpu_hs20_until_alive_v1;
	(void)kqchan_gpu_hs35_delay_alive_v1;
	kqchanMachPortLog.error()
		<< "kqchan_gpu_hs35_after20_v1 delay dest_pid=" << dest_pid
		<< " until gpu-alive-10s CrGpuMain"
		<< kqchanMachPortLog.endLog;
	DarlingServer::Thread::kernelAsync([dest_pid]() {
		for (int i = 0; i < 800; i++) {
			usleep(50000);
			if (dtape_gpu_alive_10s_crgpu()) {
				kqchanMachPortLog.error()
					<< "kqchan_gpu_hs35_after20_v1 post dest_pid="
					<< dest_pid
					<< " after gpu-alive-10s CrGpuMain"
					<< kqchanMachPortLog.endLog;
				dtape_gpu_hs20_alive_release(dest_pid);
				return;
			}
		}
		kqchanMachPortLog.error()
			<< "kqchan_gpu_hs35_after20_v1 timeout dest_pid="
			<< dest_pid
			<< kqchanMachPortLog.endLog;
	});
}

//
// base class
//

DarlingServer::Kqchan::Kqchan(std::shared_ptr<DarlingServer::Process> process):
	_debugID(kqchanDebugIDCounter++),
	_process(process)
{
	kqchanLog.debug() << *this << ": Constructing kqchan" << kqchanLog.endLog;
};

DarlingServer::Kqchan::~Kqchan() {
	kqchanLog.debug() << *this << ": Destroying kqchan" << kqchanLog.endLog;
};

uintptr_t DarlingServer::Kqchan::_idForProcess() const {
	throw std::runtime_error("must be overridden in derived class");
};

void DarlingServer::Kqchan::_processMessages() {
	throw std::runtime_error("must be overridden in derived class");
};

std::shared_ptr<DarlingServer::Kqchan> DarlingServer::Kqchan::sharedFromRoot() {
	throw std::runtime_error("must be overridden in derived class");
};

int DarlingServer::Kqchan::setup() {
	int fds[2];

	kqchanLog.debug() << *this << ": Setting up kqchan" << kqchanLog.endLog;

	if (socketpair(AF_UNIX, SOCK_SEQPACKET | SOCK_CLOEXEC, 0, fds) < 0) {
		int ret = errno;
		kqchanLog.debug() << "Failed to create socket pair" << kqchanLog.endLog;
		throw std::system_error(ret, std::generic_category());
	}

	// we'll keep fds[0] and give fds[1] away
	_socket = std::make_shared<FD>(fds[0]);

	kqchanLog.debug() << *this << ": Keeping socket " << fds[0] << " and giving away " << fds[1] << kqchanLog.endLog;

	// set O_NONBLOCK on our socket
	int flags = fcntl(_socket->fd(), F_GETFL);
	if (flags < 0) {
		int ret = errno;
		throw std::system_error(ret, std::generic_category());
	}
	if (fcntl(_socket->fd(), F_SETFL, flags | O_NONBLOCK) < 0) {
		int ret = errno;
		throw std::system_error(ret, std::generic_category());
	}

	std::weak_ptr<Kqchan> weakThis = sharedFromRoot();

	_outbox.setMessageArrivalNotificationCallback([weakThis]() {
		auto self = weakThis.lock();

		if (!self) {
			return;
		}

		std::unique_lock lock(self->_sendingMutex);

		kqchanLog.debug() << *self << ": Got messages to send, attempting to send them" << kqchanLog.endLog;

		// we probably won't be sending very many messages at once;
		// we can send all the messages in the same context that they were pushed
		do {
			self->_canSend = self->_outbox.sendMany(self->_socket->fd());
		} while (self->_canSend && !self->_outbox.empty());
	});

	_monitor = std::make_shared<Monitor>(_socket, Monitor::Event::Readable | Monitor::Event::Writable | Monitor::Event::HangUp, true, false, [weakThis](std::shared_ptr<Monitor> monitor, Monitor::Event event) {
		auto self = weakThis.lock();

		if (!self) {
			return;
		}

		kqchanLog.debug() << *self << ": Got event(s) on socket: " << static_cast<uint64_t>(event) << kqchanLog.endLog;

		if (static_cast<uint64_t>(event & Monitor::Event::HangUp) != 0) {
			// socket hangup (peer closed their socket)

			kqchanLog.debug() << *self << ": Peer hung up their socket; cleaning up monitor and kqchan" << kqchanLog.endLog;

			// stop monitoring the socket (we're not gonna get any more events out of it)
			Server::sharedInstance().removeMonitor(monitor);

			// and unregister ourselves from the process (if it still exists)
			// (which means the instance should be freed once we return)
			if (auto process = self->_process.lock()) {
				process->unregisterKqchan(self);
			}

			// no need to process any other events that may have occurred
			return;
		}

		if (static_cast<uint64_t>(event & Monitor::Event::Readable) != 0) {
			// incoming messages

			kqchanLog.debug() << *self << ": socket has pending incoming messages" << kqchanLog.endLog;

			// receive them all
			while (self->_inbox.receiveMany(self->_socket->fd()));

			// process the messages
			self->_processMessages();
		}

		if (static_cast<uint64_t>(event & Monitor::Event::Writable) != 0) {
			// we can now send messages again;
			// send as many messages as we can

			std::unique_lock lock(self->_sendingMutex);

			kqchanLog.debug() << *self << ": socket is now writable; sending all pending outgoing messages" << kqchanLog.endLog;
			do {
				self->_canSend = self->_outbox.sendMany(self->_socket->fd());
			} while (self->_canSend  && !self->_outbox.empty());
		}
	});

	DarlingServer::Server::sharedInstance().addMonitor(_monitor);

	return fds[1];
};

void DarlingServer::Kqchan::_sendNotification() {
	std::unique_lock lock(_notificationMutex);

	kqchanLog.debug() << *this << ": received request to send notification" << kqchanLog.endLog;

	if (!_canSendNotification) {
		// we've already sent our peer a notification that they haven't acknowledged yet;
		// let's not send another and needlessly clog up the socket
		kqchanLog.debug() << *this << ": earlier notification has not yet been acknowledged; not sending another notification" << kqchanLog.endLog;
		return;
	}

	kqchanLog.debug() << *this << ": sending notification " << _notificationCount << kqchanLog.endLog;

	// now that we're sending the notification, we shouldn't send another one until our peer acknowledges this one
	_canSendNotification = false;

	Message msg(sizeof(dserver_kqchan_call_notification_t), 0);

	auto notification = reinterpret_cast<dserver_kqchan_call_notification_t*>(msg.data().data());
	notification->header.number = dserver_kqchan_msgnum_notification;
	notification->header.pid = 0;
	notification->header.tid = 0;

	if (_deferNotification) {
		_deferredNotification = std::move(msg);
	} else {
		lock.unlock(); // the outbox has its own lock
		_outbox.push(std::move(msg));
	}
};

void DarlingServer::Kqchan::_sendDeferredNotification() {
	std::unique_lock lock(_notificationMutex);

	_deferNotification = false;

	if (_deferredNotification) {
		Message notification(std::move(*_deferredNotification));
		_deferredNotification = std::nullopt;

		lock.unlock(); // the outbox has its own lock
		_outbox.push(std::move(notification));
	}
};

void DarlingServer::Kqchan::logToStream(Log::Stream& stream) const {
	auto proc = _process.lock();
	stream << "[KQ:" << _debugID << ":";
	if (proc) {
		stream << *proc;
	} else {
		stream << "<null>";
	}
	stream << "]";
};

//
// mach port
//

DarlingServer::Kqchan::MachPort::MachPort(std::shared_ptr<DarlingServer::Process> process, uint32_t port, uint64_t receiveBuffer, uint64_t receiveBufferSize, uint64_t savedFilterFlags):
	Kqchan(process),
	_port(port),
	_receiveBuffer(receiveBuffer),
	_receiveBufferSize(receiveBufferSize),
	_savedFilterFlags(savedFilterFlags)
{
	kqchanMachPortLog.debug() << *this << ": Constructing Mach port kqchan" << kqchanMachPortLog.endLog;
};

DarlingServer::Kqchan::MachPort::~MachPort() {
	kqchanMachPortLog.debug() << *this << ": Destroying Mach port kqchan" << kqchanMachPortLog.endLog;

	if (_dtapeKqchan) {
		auto kqchan = _dtapeKqchan;

		// disable notifications so that `this` won't be used after we're destroyed
		dtape_kqchan_mach_port_disable_notifications(kqchan);

		// and schedule the duct-taped kqchan to be destroyed on a microthread
		auto debugID = _debugID;
		Thread::kernelAsync([=]() {
			kqchanMachPortLog.debug() << "Destroying duct-taped Mach port kqchan with ID " << debugID << kqchanMachPortLog.endLog;
			dtape_kqchan_mach_port_destroy(kqchan);
		});
	}
};

uintptr_t DarlingServer::Kqchan::MachPort::_idForProcess() const {
	return reinterpret_cast<uintptr_t>(this);
};

std::shared_ptr<DarlingServer::Kqchan> DarlingServer::Kqchan::MachPort::sharedFromRoot() {
	return shared_from_this();
};

static std::shared_ptr<DarlingServer::Thread> threadOfProcess(std::shared_ptr<DarlingServer::Process> proc, pid_t preferredNstid = 0) {
	if (!proc) {
		return nullptr;
	}
	if (preferredNstid) {
		auto maybeThread = DarlingServer::threadRegistry().lookupEntryByNSID(preferredNstid);
		if (maybeThread) {
			auto candidate = *maybeThread;
			if (candidate && candidate->process() && candidate->process()->nsid() == proc->nsid()) {
				return candidate;
			}
		}
	}
	auto current = DarlingServer::Thread::currentThread();
	if (current && current->process() && current->process()->nsid() == proc->nsid()) {
		return current;
	}
	auto threads = proc->threads();
	if (!threads.empty()) {
		return threads.front();
	}
	return nullptr;
}

int DarlingServer::Kqchan::MachPort::setup() {
	auto proc = _process.lock();

	if (!proc) {
		throw std::system_error(ESRCH, std::generic_category());
	}

	kqchanMachPortLog.debug() << *this << ": Setting up Mach port kqchan" << kqchanMachPortLog.endLog;

	auto opener = threadOfProcess(proc);
	if (!opener) {
		throw std::system_error(ESRCH, std::generic_category());
	}

	kqchanMachPortLog.debug() << *this << ": attaching EVFILT_MACHPORT nsid=" << proc->nsid()
		<< " port=" << _port << " opener_nstid=" << opener->nsid() << kqchanMachPortLog.endLog;

	if (_channelRole < 0) {
		_channelRole = cmdlineChannelRole(proc->id());
	}

	// NOTE: the duct-taped kqchan will never notify us after we die
	//       since we disable notifications upon destruction,
	//       so using `this` here is safe.
	// Impersonate the opener so filt_machportattach's current_space() is the
	// opener's ipc space. If we are already on the opener (processCall),
	// create directly to avoid impersonate/defer deadlock.
	auto doCreate = [&]() {
		auto runner = Thread::currentThread();
		bool impersonated = false;
		if (runner && runner.get() != opener.get()) {
			runner->impersonate(opener);
			impersonated = true;
		}
		_dtapeKqchan = dtape_kqchan_mach_port_create(proc->_dtapeTask, _port, _receiveBuffer, _receiveBufferSize, _savedFilterFlags, [](void* context) {
			auto self = reinterpret_cast<MachPort*>(context);
			self->_notify();
		}, this);
		if (impersonated) {
			runner->impersonate(nullptr);
		}
	};

	if (Thread::currentThread() && Thread::currentThread().get() == opener.get()) {
		doCreate();
	} else {
		Thread::kernelSync(doCreate);
	}
	if (!_dtapeKqchan) {
		kqchanMachPortLog.debug() << *this << ": Failed to create duct-taped Mach port kqchan for port " << _port << kqchanMachPortLog.endLog;
		throw std::system_error(ESRCH, std::generic_category());
	}

	int fd = Kqchan::setup();

	if (dtape_kqchan_mach_port_has_events(_dtapeKqchan)) {
		// if we already have an event, notify the kqchan;
		// this will simply enqueue a message to be sent to the peer.
		// since our libkqueue filter uses level-triggered epoll,
		// our peer will immediately see there's an event available when it starts waiting.
		_notify();
	}

	return fd;
};

void DarlingServer::Kqchan::MachPort::_processMessages() {
	while (auto msg = _inbox.pop()) {
		if (msg->data().size() < sizeof(dserver_kqchan_callhdr_t)) {
			throw std::invalid_argument("Message buffer was too small for kqchan call header");
		}

		auto callhdr = reinterpret_cast<dserver_kqchan_callhdr_t*>(msg->data().data());

		switch (callhdr->number) {
			case dserver_kqchan_msgnum_mach_port_modify: {
				if (msg->data().size() < sizeof(dserver_kqchan_call_mach_port_modify_t)) {
					throw std::invalid_argument("Message buffer was too small for dserver_kqchan_msgnum_mach_port_modify");
				}

				auto modify = reinterpret_cast<dserver_kqchan_call_mach_port_modify_t*>(callhdr);

				_modify(modify->receive_buffer, modify->receive_buffer_size, modify->saved_filter_flags, modify->header.tid);
			} break;

			case dserver_kqchan_msgnum_mach_port_read: {
				if (msg->data().size() < sizeof(dserver_kqchan_call_mach_port_read_t)) {
					throw std::invalid_argument("Message buffer was too small for dserver_kqchan_call_mach_port_read");
				}

				auto read = reinterpret_cast<dserver_kqchan_call_mach_port_read_t*>(callhdr);

				_read(read->default_buffer, read->default_buffer_size, read->header.tid);
			} break;

			case dserver_kqchan_msgnum_mach_port_notify_ack: {
				static std::atomic<int> ack_log_n{0};
				int gpu_notif0;

				if (_channelRole < 0) {
					if (auto proc = _process.lock()) {
						_channelRole = cmdlineChannelRole(proc->id());
					}
				}
				gpu_notif0 = (_channelRole == KQCHAN_ROLE_GPU &&
					(_savedFilterFlags & MACH_RCV_MSG) == 0);
				std::unique_lock lock(_notificationMutex);
				_canSendNotification = true;
				lock.unlock();
				(void)kqchan_notify_ack_nofill_v1;
				(void)kqchan_notify_ack_nofill_gpu_notif0;
				if (gpu_notif0 || ack_log_n.fetch_add(1) < 32) {
					kqchanMachPortLog.error() << *this
						<< ": "
						<< (gpu_notif0 ? kqchan_notify_ack_nofill_gpu_notif0
							: kqchan_notify_ack_nofill_v1)
						<< " port=" << _port
						<< " flags=" << _savedFilterFlags
						<< kqchanMachPortLog.endLog;
				}
				/*
				 * Restore the latch only. Pumping remaining kmsgs
				 * (_checkForEventsAsync) drained GPU Channel during
				 * PA (nmsg 2→11, CheckFreeList packed=0).
				 * Handshake-drain: post the next parked occupancy
				 * 20 after this ACK so timeout-0 cannot empty a pile.
				 * code203 called ipc_mqueue_post here on the
				 * monitor thread (no dtape current_thread) and
				 * killed prefix dserver at sitting=1. Post on
				 * a kernel microthread. sitting=1 wait/copyout
				 * lives in dtape_gpu_hs20_ack_release.
				 */
				if (gpu_notif0 && _dtapeKqchan) {
					auto self = shared_from_this();
					Thread::kernelAsync([self]() {
						if (!self->_dtapeKqchan) {
							return;
						}
						(void)kqchan_gpu_hs20_drain_v1;
						kqchanMachPortLog.error() << *self
							<< ": kqchan_gpu_hs20_drain_v1 ack kernelAsync port="
							<< self->_port
							<< kqchanMachPortLog.endLog;
						dtape_kqchan_gpu_hs20_ack(self->_dtapeKqchan);
					});
				} else if (_channelRole == KQCHAN_ROLE_NETWORK &&
				    (_savedFilterFlags & MACH_RCV_MSG) == 0) {
					unsigned first_msgid = 0;

					/*
					 * Helpers skip 1ns. Handshake drain
					 * leftover Offer before mjhs, then
					 * mjhs, Connect, Bind. Do not sit
					 * Offer until Bind.
					 */
					if (_dtapeKqchan) {
						first_msgid = dtape_kqchan_mach_port_first_msgid(
						    _dtapeKqchan);
					}
					{
						int first_offer = 0;
						int first_mjhs = 0;

						if (_dtapeKqchan) {
							first_offer = dtape_kqchan_mach_port_first_is_offer(
							    _dtapeKqchan);
							first_mjhs = dtape_kqchan_mach_port_first_is_mjhs(
							    _dtapeKqchan);
						}
						if (first_offer || first_mjhs ||
						    first_msgid == 22 ||
						    first_msgid == 1) {
							(void)kqchan_handshake_drain_bind_v1;
							_checkForEventsAsync();
						}
					}
				} else if (_channelRole == KQCHAN_ROLE_OTHER &&
				    (_savedFilterFlags & MACH_RCV_MSG) == 0) {
					unsigned first_msgid = 0;

					/*
					 * Browser Channel: Connect/Bind sits
					 * un-copyout'd while IOThread SENDs.
					 * ACK leftover only for msgid 1/22.
					 * Do not global remain-notify. Do not
					 * FIFO-drain inbound 20s.
					 */
					if (_dtapeKqchan) {
						first_msgid = dtape_kqchan_mach_port_first_msgid(
						    _dtapeKqchan);
					}
					if (first_msgid == 1 || first_msgid == 22) {
						(void)kqchan_handshake_drain_bind_browser_v1;
						_checkForEventsAsync();
					}
				}
			} break;

			default:
				throw std::invalid_argument("Unknown/invalid kqchan msgnum");
		}
	}
};

void DarlingServer::Kqchan::MachPort::_modify(uint64_t receiveBuffer, uint64_t receiveBufferSize, uint64_t savedFilterFlags, pid_t nstid) {
	_receiveBuffer = receiveBuffer;
	_receiveBufferSize = receiveBufferSize;
	_savedFilterFlags = savedFilterFlags;
	kqchanMachPortLog.debug() << *this << ": Received modification request with {receiveBuffer=" << receiveBuffer << ",receiveBufferSize=" << receiveBufferSize << ",savedFilterFlags=" << savedFilterFlags << "}" << kqchanMachPortLog.endLog;

	auto maybeThread = threadRegistry().lookupEntryByNSID(nstid);

	if (!maybeThread) {
		throw std::runtime_error("No thread for Mach port kqchan modification?");
	}

	auto thread = *maybeThread;

	auto self = shared_from_this();
	Thread::kernelAsync([self, thread, receiveBuffer, receiveBufferSize, savedFilterFlags]() {
		kqchanMachPortLog.debug() << *self << ": Handling modification request in microthread" << kqchanMachPortLog.endLog;

		Thread::currentThread()->impersonate(thread);
		dtape_kqchan_mach_port_modify(self->_dtapeKqchan, receiveBuffer, receiveBufferSize, savedFilterFlags);
		Thread::currentThread()->impersonate(nullptr);

		Message msg(sizeof(dserver_kqchan_reply_mach_port_modify_t), 0, self->_checkForEventsAsyncFactory());

		auto reply = reinterpret_cast<dserver_kqchan_reply_mach_port_modify_t*>(msg.data().data());

		reply->header.number = dserver_kqchan_msgnum_mach_port_modify;
		reply->header.code = 0;

		kqchanMachPortLog.debug() << *self << ": Sending modification reply/acknowledgement" << kqchanMachPortLog.endLog;

		self->_outbox.push(std::move(msg));
	});
};

void DarlingServer::Kqchan::MachPort::_read(uint64_t defaultBuffer, uint64_t defaultBufferSize, pid_t nstid) {
	kqchanMachPortLog.debug() << *this << ": received read request with {defaultBuffer=" << defaultBuffer << ",defaultBufferSize=" << defaultBufferSize << "}" << kqchanMachPortLog.endLog;

	if (_channelRole < 0) {
		if (auto proc = _process.lock()) {
			_channelRole = cmdlineChannelRole(proc->id());
		}
	}
	if (_channelRole == KQCHAN_ROLE_GPU && (_savedFilterFlags & MACH_RCV_MSG) == 0) {
		static std::atomic<int> read_nofill_n{0};
		std::unique_lock lock(_notificationMutex);
		_canSendNotification = true;
		lock.unlock();
		(void)kqchan_notify_ack_nofill_v1;
		(void)kqchan_notify_ack_nofill_gpu_notif0;
		if (read_nofill_n.fetch_add(1) < 32) {
			kqchanMachPortLog.error() << *this
				<< ": kqchan_notify_ack_nofill_v1 gpu notif=0 via=read port="
				<< _port << kqchanMachPortLog.endLog;
		}
		auto self = shared_from_this();
		Thread::kernelAsync([self]() {
			Message msg(sizeof(dserver_kqchan_reply_mach_port_read_t), 0);
			auto reply = reinterpret_cast<dserver_kqchan_reply_mach_port_read_t*>(msg.data().data());
			reply->header.code = 0xdead;
			reply->header.number = dserver_kqchan_msgnum_mach_port_read;
			self->_outbox.push(std::move(msg));
		});
		return;
	}

	{
		// our peer has acknowledged our notification by asking for the pending messages;
		// we can now send a notification again if we receive more data
		std::unique_lock lock(_notificationMutex);
		kqchanMachPortLog.debug() << *this << ": received acknowledgement (implicitly via read) for notification " << _notificationCount++ << "; notifications may now be sent" << kqchanMachPortLog.endLog;
		_canSendNotification = true;

		// defer future notifications until we send our reply.
		// we do it this way because:
		// 1) if we don't defer them and just send them right now,
		//    a notification may be sent before we send our reply,
		//    leading to out-of-order messages in the channel (which
		//    causes an abort on the client side).
		// 2) if we instead move the `_canSendNotification` update to after
		//    we send the reply, we may miss a notification for an event
		//    that occurred right after we generated the reply but before
		//    we updated `_canSendNotification`.
		// with this approach (notification deferral), channel messages are kept in-order
		// and we don't miss any notifications. worst case scenario, we might send
		// a duplicate notification for an event that occurred right after this update
		// but before we generate the reply; in that case, the client will simply try to read
		// the duplicate event but we won't have anything and we'll tell it to drop the event.
		_deferNotification = true;
	}

	auto thread = threadOfProcess(_process.lock(), nstid);

	if (!thread) {
		throw std::runtime_error("No thread of kqchan process for Mach port kqchan read?");
	}

	auto self = shared_from_this();
	Thread::kernelAsync([self, thread, defaultBuffer, defaultBufferSize]() {
		Message msg(sizeof(dserver_kqchan_reply_mach_port_read_t), 0, self->_checkForEventsAsyncFactory());

		kqchanMachPortLog.debug() << *self << ": handling read request in microthread" << kqchanMachPortLog.endLog;

		auto reply = reinterpret_cast<dserver_kqchan_reply_mach_port_read_t*>(msg.data().data());

		reply->header.code = 0xdead;
		reply->header.number = dserver_kqchan_msgnum_mach_port_read;

		try {
			Thread::currentThread()->impersonate(thread);
			if (!dtape_kqchan_mach_port_fill(self->_dtapeKqchan, reply, defaultBuffer, defaultBufferSize)) {
				kqchanMachPortLog.debug() << *self << ": no events to read" << kqchanMachPortLog.endLog;
				reply->header.code = 0xdead;
			} else {
				reply->header.code = 0;
			}
		} catch (const std::exception& e) {
			kqchanMachPortLog.warning() << *self << ": mach_port fill failed (" << e.what() << "); pushing 0xdead reply" << kqchanMachPortLog.endLog;
			reply->header.code = 0xdead;
		} catch (...) {
			kqchanMachPortLog.warning() << *self << ": mach_port fill failed; pushing 0xdead reply" << kqchanMachPortLog.endLog;
			reply->header.code = 0xdead;
		}
		if (auto current = Thread::currentThread()) {
			current->impersonate(nullptr);
		}

		self->_outbox.push(std::move(msg));

		// now let's send any deferred notifications we might have
		self->_sendDeferredNotification();
	});
};

void DarlingServer::Kqchan::MachPort::_notify() {
	if (_channelRole < 0) {
		if (auto proc = _process.lock()) {
			_channelRole = cmdlineChannelRole(proc->id());
		}
	}
	if (_channelRole == KQCHAN_ROLE_GPU && (_savedFilterFlags & MACH_RCV_MSG) == 0) {
		pid_t pid = 0;
		unsigned nmsg = 0;
		unsigned msgid = 0;

		if (auto proc = _process.lock()) {
			pid = proc->id();
		}
		(void)kqchan_gpu_cage_hold_v1;
		if (_dtapeKqchan) {
			nmsg = dtape_kqchan_mach_port_msgcount(_dtapeKqchan);
			msgid = dtape_kqchan_mach_port_first_msgid(_dtapeKqchan);
		}
		/*
		 * Handshake-drain occupancy 20: one parcel sits and
		 * must notify so it copyouts. Extra 20s are parked
		 * off-queue. Drop only if nmsg already high so a
		 * leak cannot 2→11 ROOT98CHK. Handshake (22/34/36)
		 * and non-ipcz (rendezvous) still notify so the GPU
		 * knote is the Channel dest. Not a cage-hold.
		 * Not dest-bind COMPLEX.
		 *
		 * Occupancy 20 notifies at Channel attach (~2s).
		 * msgid 35 is parked in ipc_mqueue_post until
		 * gpu-alive-10s + CrGpuMain. Bind 22 / hs 34 still
		 * notify. Do not skip 20 until 10s (code206 delayed
		 * attach and dumped remain=7). nmsg max 4 so a leak
		 * cannot remain=6 ROOT98CHK during PA.
		 */
		if (msgid == 20 && nmsg >= 4) {
			static std::atomic<int> drop_log_n{0};
			(void)kqchan_gpu_copyout_drop_v1;
			(void)kqchan_gpu_hs20_park_cap_v1;
			if (drop_log_n.fetch_add(1) < 32) {
				kqchanMachPortLog.error() << *this
					<< ": copyout drop notif=0 gpu src=host-cmdline port="
					<< _port << " pid=" << pid
					<< " msgid=" << msgid
					<< " nmsg=" << nmsg
					<< kqchanMachPortLog.endLog;
			}
			return;
		}
		if (msgid == 0 && nmsg == 0) {
			return;
		}
		if (msgid == 20) {
			static std::atomic<int> hs20_notify_n{0};
			(void)kqchan_gpu_hs20_drain_v1;
			(void)kqchan_gpu_hs35_after20_v1;
			if (hs20_notify_n.fetch_add(1) < 32) {
				kqchanMachPortLog.error() << *this
					<< ": kqchan_gpu_hs20_drain_v1 notify port="
					<< _port << " pid=" << pid
					<< " msgid=" << msgid
					<< " nmsg=" << nmsg
					<< kqchanMachPortLog.endLog;
			}
		} else {
			static std::atomic<int> hs_notify_n{0};
			if (hs_notify_n.fetch_add(1) < 32) {
				kqchanMachPortLog.error() << *this
					<< ": kqchan_gpu_hs_through_v1 notify msgid="
					<< msgid << " nmsg=" << nmsg
					<< " port=" << _port << " pid=" << pid
					<< kqchanMachPortLog.endLog;
			}
		}
	} else if (_channelRole == KQCHAN_ROLE_NETWORK && (_savedFilterFlags & MACH_RCV_MSG) == 0) {
		unsigned nmsg = 0;
		int first_ping = 0;
		static std::atomic<int> off_log_n{0};

		/*
		 * Fable arch13/14: Channel-wide network notify hold is
		 * the slider, not the Pong wall. Helper-skip-1ns means
		 * this knote is the only wake for browser→helper Ping.
		 * Notify honestly. Do not park-on-port.
		 */
		(void)kqchan_net_ping_dest_v1;
		(void)kqchan_net_hold_off_v1;
		(void)kqchan_net_hold_until_gpu_alive_v1;
		(void)kqchan_net_hold_until_crgpumain_v1;
		(void)kqchan_net_hold_until_cage_v1;
		(void)kqchan_net_after_gpu_alive_v1;
		(void)kqchan_net_after_crgpumain_v1;
		(void)kqchan_net_after_cage_v1;
		unsigned first_msgid = 0;

		if (_dtapeKqchan) {
			nmsg = dtape_kqchan_mach_port_msgcount(_dtapeKqchan);
			first_ping = dtape_kqchan_mach_port_first_is_ping(_dtapeKqchan);
			first_msgid = dtape_kqchan_mach_port_first_msgid(_dtapeKqchan);
		}
		if (off_log_n.fetch_add(1) < 32) {
			kqchanMachPortLog.error() << *this
				<< ": kqchan_net_hold_off_v1 notify port=" << _port
				<< " nmsg=" << nmsg
				<< " first_msgid=" << first_msgid
				<< " first_ping=" << first_ping
				<< " notify_count=" << 1
				<< kqchanMachPortLog.endLog;
		}
		if ((first_msgid == 22 || first_msgid == 1 ||
		    first_msgid == 0 ||
		    dtape_kqchan_mach_port_first_is_offer(_dtapeKqchan) ||
		    dtape_kqchan_mach_port_first_is_mjhs(_dtapeKqchan)) &&
		    nmsg > 0) {
			static std::atomic<int> drain_n{0};
			(void)kqchan_handshake_drain_bind_v1;
			if (drain_n.fetch_add(1) < 32) {
				kqchanMachPortLog.error() << *this
					<< ": handshake_drain_offer_v1 notify port="
					<< _port << " nmsg=" << nmsg
					<< " first_msgid=" << first_msgid
					<< kqchanMachPortLog.endLog;
			}
		}
		/*
		 * Helper-skip-1ns: after mjhs copyout the latch is
		 * false. Restore when remain>0 so Bind's post can
		 * wake. Handshake drain Offer/mjhs/Connect/Bind
		 * leftovers. Not a global remain-notify storm.
		 *
		 * msgid=22 at post: force the latch even if a prior
		 * notify is un-ACKed so ChannelMac copyout of Bind
		 * is not 9ms behind Ping copyin.
		 */
		{
			std::unique_lock lock(_notificationMutex);
			if (first_msgid == 22 && nmsg > 0) {
				_canSendNotification = true;
				lock.unlock();
				(void)kqchan_handshake_drain_bind_v1;
				kqchanMachPortLog.error() << *this
					<< ": handshake_drain_bind_v1 posted immediately port="
					<< _port << " nmsg=" << nmsg
					<< kqchanMachPortLog.endLog;
			} else if (!_canSendNotification && nmsg > 0) {
				_canSendNotification = true;
				lock.unlock();
				(void)kqchan_net_remain_v1;
				kqchanMachPortLog.error() << *this
					<< ": kqchan_net_remain_v1 latch restore port="
					<< _port << " nmsg=" << nmsg
					<< " first_msgid=" << first_msgid
					<< kqchanMachPortLog.endLog;
			}
		}
	} else if (_channelRole == KQCHAN_ROLE_OTHER &&
	    (_savedFilterFlags & MACH_RCV_MSG) == 0) {
		unsigned nmsg = 0;
		unsigned first_msgid = 0;

		/*
		 * Browser Channel: Connect (1) / Bind (22) sits
		 * un-copyout'd while IOThread SENDs 20s, so helper
		 * Ping copyin beats browser 34. Force the notify
		 * latch for sitting Connect/Bind only. Do not
		 * global remain-notify. Do not FIFO-drain 20s.
		 */
		if (_dtapeKqchan) {
			nmsg = dtape_kqchan_mach_port_msgcount(_dtapeKqchan);
			first_msgid = dtape_kqchan_mach_port_first_msgid(
			    _dtapeKqchan);
		}
		if ((first_msgid == 1 || first_msgid == 22) && nmsg > 0) {
			std::unique_lock lock(_notificationMutex);
			_canSendNotification = true;
			lock.unlock();
			(void)kqchan_handshake_drain_bind_browser_v1;
			kqchanMachPortLog.error() << *this
				<< ": handshake_drain_bind_v1 browser Channel port="
				<< _port << " nmsg=" << nmsg
				<< " first_msgid=" << first_msgid
				<< kqchanMachPortLog.endLog;
		}
	}
	_sendNotification();
};

void DarlingServer::Kqchan::MachPort::_checkForEventsAsync() {
	Thread::kernelAsync([weakSelf = weak_from_this()]() {
		auto self = weakSelf.lock();
		if (!self) {
			return;
		}
		if (dtape_kqchan_mach_port_has_events(self->_dtapeKqchan)) {
			self->_notify();
		}
	});
};

std::function<void()> DarlingServer::Kqchan::MachPort::_checkForEventsAsyncFactory() {
	return [weakSelf = weak_from_this()]() {
		auto self = weakSelf.lock();
		if (!self) {
			return;
		}
		self->_checkForEventsAsync();
	};
};

//
// process
//
// TODO: NOTE_REAP and NOTE_SIGNAL
//

DarlingServer::Kqchan::Process::Process(std::shared_ptr<DarlingServer::Process> process, pid_t nspid, uint32_t flags):
	Kqchan(process),
	_nspid(nspid),
	_flags(flags)
{
	kqchanProcLog.debug() << *this << ": Constructing process kqchan" << kqchanProcLog.endLog;
};

DarlingServer::Kqchan::Process::~Process() {
	kqchanProcLog.debug() << *this << ": Destroying process kqchan" << kqchanProcLog.endLog;

	if (auto targetProcess = _targetProcess.lock()) {
		targetProcess->unregisterListeningKqchan(_idForProcess());
	}
};

uintptr_t DarlingServer::Kqchan::Process::_idForProcess() const {
	return reinterpret_cast<uintptr_t>(this);
};

std::shared_ptr<DarlingServer::Kqchan> DarlingServer::Kqchan::Process::sharedFromRoot() {
	return shared_from_this();
};

int DarlingServer::Kqchan::Process::setup() {
	kqchanProcLog.debug() << *this << ": Setting up process kqchan" << kqchanProcLog.endLog;

	auto maybeTargetProcess = processRegistry().lookupEntryByNSID(_nspid);
	if (!maybeTargetProcess) {
		kqchanProcLog.debug() << *this << ": Failed to create process kqchan for PID " << _nspid << kqchanProcLog.endLog;
		throw std::system_error(ESRCH, std::generic_category());
	}

	auto targetProcess = *maybeTargetProcess;

	_targetProcess = targetProcess;

	int fd = Kqchan::setup();

	{
		std::unique_lock lock(_mutex);
		if (!_attached) {
			targetProcess->registerListeningKqchan(shared_from_this());
			_attached = true;
		}
		if (!_events.empty()) {
			_sendNotification();
		}
	}

	return fd;
};

void DarlingServer::Kqchan::Process::_processMessages() {
	while (auto msg = _inbox.pop()) {
		if (msg->data().size() < sizeof(dserver_kqchan_callhdr_t)) {
			throw std::invalid_argument("Message buffer was too small for kqchan call header");
		}

		auto callhdr = reinterpret_cast<dserver_kqchan_callhdr_t*>(msg->data().data());

		switch (callhdr->number) {
			case dserver_kqchan_msgnum_proc_modify: {
				if (msg->data().size() < sizeof(dserver_kqchan_call_proc_modify_t)) {
					throw std::invalid_argument("Message buffer was too small for dserver_kqchan_call_proc_modify_");
				}

				auto modify = reinterpret_cast<dserver_kqchan_call_proc_modify_t*>(callhdr);

				_modify(modify->flags);
			} break;

			case dserver_kqchan_msgnum_proc_read: {
				if (msg->data().size() < sizeof(dserver_kqchan_call_proc_read_t)) {
					throw std::invalid_argument("Message buffer was too small for dserver_kqchan_call_proc_read");
				}

				auto read = reinterpret_cast<dserver_kqchan_call_proc_read_t*>(callhdr);

				_read();
			} break;

			default:
				throw std::invalid_argument("Unknown/invalid kqchan msgnum");
		}
	}
};

void DarlingServer::Kqchan::Process::_modify(uint32_t flags) {
	std::unique_lock lock(_mutex);

	_flags = flags;

	Message msg(sizeof(dserver_kqchan_reply_proc_modify_t), 0, _checkForEventsAsyncFactory());

	auto reply = reinterpret_cast<dserver_kqchan_reply_proc_modify_t*>(msg.data().data());

	reply->header.number = dserver_kqchan_msgnum_proc_modify;
	reply->header.code = 0;

	kqchanProcLog.debug() << *this << ": Sending modification reply/acknowledgement" << kqchanProcLog.endLog;

	lock.unlock(); // the outbox has its own lock
	_outbox.push(std::move(msg));
};

void DarlingServer::Kqchan::Process::_read() {
	auto listeningProcess = _process.lock();

	if (!listeningProcess) {
		// if the listening process is dead, log it and ignore the request (no one's listening for the reply anyways)
		kqchanProcLog.warning() << *this << ": received read request after listening process died" << kqchanProcLog.endLog;
		return;
	}

	kqchanProcLog.debug() << *this << ": received read request" << kqchanProcLog.endLog;

	{
		// our peer has acknowledged our notification by asking for the pending messages;
		// we can now send a notification again if we receive more data
		std::unique_lock lock(_notificationMutex);
		kqchanProcLog.debug() << *this << ": received acknowledgement (implicitly via read) for notification " << _notificationCount++ << "; notifications may now be sent" << kqchanProcLog.endLog;
		_canSendNotification = true;

		// see MachPort::_read() for why we defer notifications
		_deferNotification = true;
	}

	std::unique_lock lock(_mutex, std::defer_lock);
	Message msg(sizeof(dserver_kqchan_reply_proc_read_t), 0, _checkForEventsAsyncFactory());
	auto reply = reinterpret_cast<dserver_kqchan_reply_proc_read_t*>(msg.data().data());

	reply->header.number = dserver_kqchan_msgnum_proc_read;
	reply->header.code = 0;
	reply->data = 0;
	reply->fflags = 0;

	while (true) {
		lock.lock();

		if (_events.empty()) {
			lock.unlock();

			// if we don't have any events, tell our peer
			kqchanProcLog.debug() << *this << ": no events to read" << kqchanProcLog.endLog;

			reply->header.code = 0xdead;
			break;
		} else {
			auto event = std::move(_events.front());
			_events.pop_front();

			auto savedFlags = _flags;

			// drop the lock; we don't need it to set up the new kqchan or to discard it, nor to push the message to the outbox.
			// additionally, we don't want to hold it if we decide to drop the new kqchan, since that takes its own set of locks
			// when dying (and the fewer active locks we hold concurrently, the better)
			lock.unlock();

			reply->data = event.data;
			reply->fflags = event.events & savedFlags;

			if (reply->fflags == 0) {
				// if this event contains no events that the user is interested in, drop it
				kqchanProcLog.debug() << *this << ": event does not contain any events the user is interested in; dropping event" << kqchanProcLog.endLog;
				continue;
			}

			if (savedFlags & NOTE_TRACK) {
				if (event.newKqchan) {
					try {
						FD newKqchanSocket(event.newKqchan->setup());

						// no errors SHOULD be thrown from this point forward

						// give the new kqchan the most recent flags we have
						{
							std::unique_lock lock(event.newKqchan->_mutex);
							event.newKqchan->_flags = savedFlags;
						}

						listeningProcess->registerKqchan(event.newKqchan);
						msg.pushDescriptor(newKqchanSocket.extract());

						kqchanProcLog.debug() << *this << ": new process kqchan setup for child process and being returned" << kqchanProcLog.endLog;
					} catch (...) {
						kqchanProcLog.error() << *this << ": failed to setup new kqchan for child process" << kqchanProcLog.endLog;
						reply->fflags |= NOTE_TRACKERR;
					}
				} else if (event.events & NOTE_FORK) {
					kqchanProcLog.error() << *this << ": read NOTE_FORK event and user has requested NOTE_TRACK, but no new kqchan was associated with event" << kqchanProcLog.endLog;
					reply->fflags |= NOTE_TRACKERR;
				}
			} else if (event.newKqchan) {
				kqchanProcLog.info() << *this << ": event contains new kqchan, but user has not requested NOTE_TRACK; dropping new kqchan" << kqchanProcLog.endLog;
			}

			break;
		}
	}

	_outbox.push(std::move(msg));

	// now let's send any deferred notifications we might have
	_sendDeferredNotification();
};

void DarlingServer::Kqchan::Process::_notify(uint32_t event, int64_t data) {
	Event newEvent;

	kqchanProcLog.debug() << *this << ": notified with {event=" << event << ",data=" << data << "}" << kqchanProcLog.endLog;

	newEvent.data = data;
	newEvent.events = event;
	newEvent.newKqchan = nullptr;

	if (event == NOTE_FORK) {
		// NOTE: we always setup a new kqchan regardless of whether or not the user has currently requested NOTE_TRACK or not,
		//       in case the user does have NOTE_TRACK when reading the event.

		auto listeningProcess = _process.lock();

		if (!listeningProcess) {
			return;
		}

		auto maybeChild = processRegistry().lookupEntryByNSID(data & NOTE_PDATAMASK);

		if (!maybeChild) {
			kqchanProcLog.debug() << *this << ": notified with NOTE_FORK (and wanted NOTE_TRACK), but couldn't find child" << kqchanProcLog.endLog;
		} else {
			auto child = *maybeChild;

			auto newKqchan = std::make_shared<Process>(listeningProcess, data & NOTE_PDATAMASK, _flags);

			child->registerListeningKqchan(newKqchan);
			{
				std::unique_lock newLock(newKqchan->_mutex);
				newKqchan->_targetProcess = child;
				newKqchan->_attached = true;
			}

			auto childParent = child->parentProcess();

			newKqchan->_notify(NOTE_CHILD, (childParent ? childParent->nsid() : 0) & NOTE_PDATAMASK);

			newEvent.newKqchan = newKqchan;
		}
	}

	{
		std::unique_lock lock(_mutex);
		_events.push_back(std::move(newEvent));
		if (_socket) {
			_sendNotification();
		}
	}
};

void DarlingServer::Kqchan::Process::_checkForEventsAsync() {
	Thread::kernelAsync([weakSelf = weak_from_this()]() {
		auto self = weakSelf.lock();
		if (!self) {
			return;
		}
		// if we have more events ready, tell our peer
		if (!self->_events.empty()) {
			self->_sendNotification();
		}
	});
};

std::function<void()> DarlingServer::Kqchan::Process::_checkForEventsAsyncFactory() {
	return [weakSelf = weak_from_this()]() {
		auto self = weakSelf.lock();
		if (!self) {
			return;
		}
		self->_checkForEventsAsync();
	};
};

void DarlingServer::Kqchan::Process::logToStream(Log::Stream& stream) const {
	auto proc = _targetProcess.lock();

	Kqchan::logToStream(stream);

	stream << ":";
	if (proc) {
		stream << *proc;
	} else {
		stream << "<null>";
	}
};
