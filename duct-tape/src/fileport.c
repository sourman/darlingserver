#include <darlingserver/duct-tape.h>
#include <darlingserver/duct-tape/log.h>

#include <mach/mach_types.h>
#include <mach/port.h>
#include <mach/message.h>
#include <mach/kern_return.h>
#include <ipc/ipc_port.h>
#include <ipc/ipc_object.h>
#include <ipc/ipc_space.h>
#include <kern/ipc_misc.h>
#include <kern/task.h>

#include <stdlib.h>

int close(int fd);
int dup(int fd);
int fcntl(int fd, int cmd, ...);
int getsockopt(int fd, int level, int optname, void* optval, unsigned int* optlen);

#ifndef EBADF
#define EBADF 9
#endif
#ifndef EINVAL
#define EINVAL 22
#endif
#ifndef ENOMEM
#define ENOMEM 12
#endif
#ifndef EMFILE
#define EMFILE 24
#endif

#ifndef F_GETFD
#define F_GETFD 1
#endif
#ifndef F_GETFL
#define F_GETFL 3
#endif
#ifndef SOL_SOCKET
#define SOL_SOCKET 1
#endif
#ifndef SO_TYPE
#define SO_TYPE 3
#endif

/*
 * Darling has no BSD fileglob. The kobject pointer for IKOT_FILEPORT is
 * this wrapper. Darwin fileport_releasefg() drops a fileglob ref; existing
 * fds keep the file. Closing the Linux fd here races SCM_RIGHTS to the child
 * (no-senders fires inside makefd's release_send) and kills the handle the
 * child still needs.
 */
struct darling_fileport {
	int fd;
};

/* Overlay confirm: nsenter strings on the darlingserver binary. */
static const char comet_fileport_dserver_v3[] = "comet_fileport_dserver_v3";

static void
fileport_fdinfo(int fd, int* getfd, int* getfl, int* so_type)
{
	unsigned int slen;
	int stype;

	*getfd = (fd >= 0) ? fcntl(fd, F_GETFD) : -1;
	*getfl = (fd >= 0) ? fcntl(fd, F_GETFL) : -1;
	stype = -1;
	slen = sizeof(stype);
	if (fd >= 0 && getsockopt(fd, SOL_SOCKET, SO_TYPE, &stype, &slen) != 0)
		stype = -1;
	*so_type = stype;
}

int
dtape_fileport_peek_fd(void* kobject)
{
	struct darling_fileport* fp = (struct darling_fileport*)kobject;

	if (!fp)
		return -1;
	return fp->fd;
}

int dtape_fileport_makeport(int fd, uint32_t* out_name)
{
	struct darling_fileport* fp;
	ipc_port_t port;
	mach_port_name_t name;
	int getfd, getfl, so_type;

	(void)comet_fileport_dserver_v3;

	if (out_name) {
		*out_name = MACH_PORT_NULL;
	}

	if (fd < 0) {
		return EBADF;
	}

	fp = malloc(sizeof(*fp));
	if (!fp) {
		close(fd);
		return ENOMEM;
	}
	fp->fd = fd;

	port = fileport_alloc((struct fileglob*)fp);
	name = ipc_port_copyout_send(port, current_space());
	if (!MACH_PORT_VALID(name)) {
		dtape_log_error("fileport_makeport_v3 fd=%d copyout failed", fd);
		return EINVAL;
	}

	fileport_fdinfo(fd, &getfd, &getfl, &so_type);
	dtape_log_error("fileport_makeport_v3 fd=%d name=0x%x port=%p srights=%u getfd=%d getfl=%d so_type=%d",
	    fd, name, port, IP_VALID(port) ? port->ip_srights : 0u,
	    getfd, getfl, so_type);

	if (out_name) {
		*out_name = name;
	}
	return 0;
}

int dtape_fileport_makefd(uint32_t port_name, int* out_fd)
{
	ipc_port_t port = IPC_PORT_NULL;
	struct fileglob* fg;
	struct darling_fileport* fp;
	kern_return_t kr;
	int newfd;
	unsigned srights_copyin;
	int src_getfd, src_getfl, src_so;
	int new_getfd, new_getfl, new_so;

	if (out_fd) {
		*out_fd = -1;
	}

	kr = ipc_object_copyin(current_space(), port_name,
	    MACH_MSG_TYPE_COPY_SEND, (ipc_object_t*)&port, 0, NULL,
	    IPC_OBJECT_COPYIN_FLAGS_ALLOW_IMMOVABLE_SEND);
	if (kr != KERN_SUCCESS) {
		dtape_log_error("fileport_makefd_v3 name=0x%x copyin kr=%d", port_name, kr);
		return EINVAL;
	}

	srights_copyin = IP_VALID(port) ? port->ip_srights : 0u;

	fg = fileport_port_to_fileglob(port);
	if (!fg) {
		dtape_log_error("fileport_makefd_v3 name=0x%x not fileport kotype=%u srights=%u",
		    port_name, IP_VALID(port) ? (unsigned)ip_kotype(port) : 0u,
		    srights_copyin);
		ipc_port_release_send(port);
		return EINVAL;
	}

	fp = (struct darling_fileport*)fg;
	fileport_fdinfo(fp->fd, &src_getfd, &src_getfl, &src_so);
	newfd = dup(fp->fd);
	fileport_fdinfo(newfd, &new_getfd, &new_getfl, &new_so);
	dtape_log_error("fileport_makefd_v3 name=0x%x srcfd=%d newfd=%d srights=%u kotype=%u src_getfd=%d src_getfl=%d src_so=%d new_getfd=%d new_getfl=%d new_so=%d",
	    port_name, fp->fd, newfd, srights_copyin,
	    (unsigned)ip_kotype(port),
	    src_getfd, src_getfl, src_so, new_getfd, new_getfl, new_so);

	/*
	 * COPY_SEND extra must be dropped, but no-senders must not close the
	 * Linux fd: Chrome deallocates the send right after makefd, and in
	 * Darling that notification also runs here when srights hits 0.
	 */
	ipc_port_release_send(port);
	if (newfd < 0) {
		dtape_log_error("fileport_makefd_v3 name=0x%x dup failed srcfd=%d", port_name, fp->fd);
		return EMFILE;
	}

	if (out_fd) {
		*out_fd = newfd;
	}
	return 0;
}

void fileport_releasefg(struct fileglob* fg)
{
	struct darling_fileport* fp = (struct darling_fileport*)fg;
	int getfd, getfl, so_type;

	if (!fp) {
		return;
	}
	fileport_fdinfo(fp->fd, &getfd, &getfl, &so_type);
	dtape_log_error("fileport_releasefg_v3 fd=%d keep getfd=%d getfl=%d so_type=%d",
	    fp->fd, getfd, getfl, so_type);
	fp->fd = -1;
	free(fp);
}
