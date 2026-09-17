#include <darlingserver/duct-tape.h>

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

/*
 * Darling has no BSD fileglob. The kobject pointer for IKOT_FILEPORT is
 * this wrapper; fileport_releasefg() closes the Linux fd when the port dies.
 */
struct darling_fileport {
	int fd;
};

/* Overlay confirm: nsenter strings on the darlingserver binary. */
static const char comet_fileport_dserver_v1[] = "comet_fileport_dserver_v1";

int dtape_fileport_makeport(int fd, uint32_t* out_name)
{
	struct darling_fileport* fp;
	ipc_port_t port;
	mach_port_name_t name;

	(void)comet_fileport_dserver_v1;

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
		return EINVAL;
	}

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

	if (out_fd) {
		*out_fd = -1;
	}

	kr = ipc_object_copyin(current_space(), port_name,
	    MACH_MSG_TYPE_COPY_SEND, (ipc_object_t*)&port, 0, NULL,
	    IPC_OBJECT_COPYIN_FLAGS_ALLOW_IMMOVABLE_SEND);
	if (kr != KERN_SUCCESS) {
		return EINVAL;
	}

	fg = fileport_port_to_fileglob(port);
	if (!fg) {
		ipc_port_release_send(port);
		return EINVAL;
	}

	fp = (struct darling_fileport*)fg;
	newfd = dup(fp->fd);
	ipc_port_release_send(port);
	if (newfd < 0) {
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

	if (!fp) {
		return;
	}
	if (fp->fd >= 0) {
		close(fp->fd);
	}
	free(fp);
}
