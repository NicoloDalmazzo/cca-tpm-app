#include <sys/socket.h>
#include <sys/un.h>
#include <sys/types.h>
#include <linux/vtpm_proxy.h>
#include <sys/ioctl.h>

#include <unistd.h>
#include <poll.h>
#include <fcntl.h>
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <signal.h>
#include <time.h>

#include "cca-tpm-relay.h"

static uint32_t be_to_le_32(const uint8_t *p)
{
	return ((uint32_t)p[0] << 24) | ((uint32_t)p[1] << 16) |
	       ((uint32_t)p[2] << 8) | p[3];
}
 
static void le_to_be_32(uint8_t *p, uint32_t v)
{
	p[0] = v >> 24;
	p[1] = v >> 16;
	p[2] = v >> 8;
	p[3] = v;
}

static double now_ms(void)
{
	struct timespec ts;
 
	clock_gettime(CLOCK_MONOTONIC, &ts);
	return ts.tv_sec * 1000.0 + ts.tv_nsec / 1e6;
}
 
/* Read exactly n bytes; timeout_ms applies to each wait for data. */
static int read_full(int fd, uint8_t *buf, size_t n, int timeout_ms)
{
	size_t off = 0;
 
	while (off < n) {
		struct pollfd p = { .fd = fd, .events = POLLIN };
		ssize_t k;
		int r = poll(&p, 1, timeout_ms);
 
		if (r < 0) {
			if (errno == EINTR)
				continue;
			return -1;
		}
		if (r == 0) {
			errno = ETIMEDOUT;
			return -1;
		}
		k = read(fd, buf + off, n - off);
		if (k < 0) {
			if (errno == EINTR || errno == EAGAIN)
				continue;
			return -1;
		}
		if (k == 0) {
			errno = ECONNRESET;
			return -1;
		}
		off += k;
	}
	return 0;
}
 
static int write_full(int fd, const uint8_t *buf, size_t n)
{
	size_t off = 0;
 
	while (off < n) {
		ssize_t k = write(fd, buf + off, n - off);
 
		if (k < 0) {
			if (errno == EINTR)
				continue;
			return -1;
		}
		off += k;
	}
	return 0;
}
 
/* Send one command to the realm and read exactly one response. */
static int transact(int sock, const uint8_t *cmd, size_t cmd_len,
		    uint8_t *rsp, size_t *rsp_len, int timeout_ms)
{
	uint32_t size;
    double t0;
 
	if (write_full(sock, cmd, cmd_len))
		return -1;

    t0 = now_ms();

	if (read_full(sock, rsp, TPM_HDR_SIZE, timeout_ms))
		return -1;
     
	size = be_to_le_32(rsp + 2);
	if (size < TPM_HDR_SIZE || size > TPM_BUFSIZE) {
		errno = EPROTO;
		return -1;
	}
	if (read_full(sock, rsp + TPM_HDR_SIZE, size - TPM_HDR_SIZE, timeout_ms))
		return -1;
 
	*rsp_len = size;
	return 0;
}

int wait_realm_tpm(int sock){
    
    int fd_tpm_ready;
    uint8_t tpm_ready_signal;
    
    fd_tpm_ready = open("/dev/cca-tpm-wait",O_RDONLY);
    
    if(fd_tpm_ready<0){
        perror("Error during opening cca-tpm-wait");
        return -1;
    }
    /*
     * Blocking read until Realm notify
     * resulting in unlocking a variable in the host
     */
    size_t ret = read(fd_tpm_ready, &tpm_ready_signal,
            sizeof(tpm_ready_signal));
    
    close(fd_tpm_ready);

    if (ret != 0) {
        perror("read");
        fprintf(stderr, "read error");
        return -1;
    }
    
    return 0;
}


/*
 * Unlock both realm and host to finish their boot
 * @fd_signal_realm is a vsocket port to send READY
 * command to Realm
 */
static int vtpm_ready(int fd_signal_realm, int proxy_fd)
{
	static const char proxy_ready[] = "READY\n";
	pid_t pid = fork();

	if (pid < 0) {
		perror("fork");
		return -1;
    }
	/* Parent: back to the relay loop */
    if (pid > 0)
		return 0;               

	/*
     * Child closes proxy_fd,
     * only parent services proxy
     */
	close(proxy_fd);
    
    /*
     * ima driver to communicate to ima
     * to finish inizialization
     */
	int fd_ima = open("/sys/kernel/security/ima/tpm_init", O_WRONLY);
	if (fd_ima < 0 || write(fd_ima, "1", 1) != 1) {
		perror("ima tpm_init");
		_exit(1);
	}
	close(fd_ima);                  
    
    /*
     * FIFO to restart init process
     */
	int fd_host = open("/tmp/cca-tpm-ready", O_WRONLY);
	if (fd_host < 0 || write(fd_host, "1", 1) != 1) {
		perror("host fifo");
		_exit(1);
	}
	close(fd_host);

	/*
     * Signal to realm to finish its boot
     */
    if (write_full(fd_signal_realm, (const uint8_t *)proxy_ready,
		       sizeof(proxy_ready) - 1) < 0) {
		perror("write to realm ready");
		_exit(1);
	}
	_exit(0);
}

static size_t make_error_rsp(const uint8_t *cmd, uint8_t *rsp)
{
	memcpy(rsp, cmd, 2);			/* same tag as the command */
	le_to_be_32(rsp + 2, TPM_HDR_SIZE);
	le_to_be_32(rsp + 6, TPM_RC_FAILURE);
	return TPM_HDR_SIZE;
}


int connect_socket(struct sockaddr_un addr){
    
    int fd;

    while (1) {
        fd = socket(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC, 0);
        if (fd < 0) {
            perror("socket");
            return -1;
        }

        
        if (connect(fd, (struct sockaddr *)&addr, sizeof(addr)) == 0) {
            fprintf(stderr, "Connected to %s\n", addr.sun_path);
            break;
        }

        /*
         * The socket does not exist yet, or QEMU is not
         * accepting connections yet.
         */
        if (errno == ENOENT || errno == ECONNREFUSED) {
            close(fd);
            usleep(100000);   /* 100 ms */
            continue;
        }

        perror("connect");
        close(fd);
        return -1;
    }

    return fd;

}

int main(void)
{
    int fd, fd_ctl;
    struct sockaddr_un addr, addr_ctl;
    uint8_t cmd[TPM_BUFSIZE], rsp[TPM_BUFSIZE];
    size_t rsp_len;
    ssize_t n;
    int res, proxy_fd, signalled = 0;
    unsigned int tpm_num;
    double t0;
    char devpath[32];

    memset(&addr, 0, sizeof(addr));
    addr.sun_family = AF_UNIX;
    strncpy(addr.sun_path, SOCKET_PATH, sizeof(addr.sun_path) - 1);
    
    memset(&addr_ctl, 0, sizeof(addr_ctl));
    addr_ctl.sun_family = AF_UNIX;
    strncpy(addr_ctl.sun_path, CTL_SOCKET_PATH, sizeof(addr_ctl.sun_path) - 1);
    
    signal(SIGPIPE,SIG_IGN);
    signal(SIGCHLD,SIG_IGN);

    fd = connect_socket(addr);
    if ( fd < 0)
        return EXIT_FAILURE;

    fd_ctl = connect_socket(addr_ctl);
    if ( fd_ctl < 0)
        return EXIT_FAILURE;
    
    if ( wait_realm_tpm(fd) < 0 )
        return EXIT_FAILURE;
    
    struct vtpm_proxy_new_dev cca_tpm_dev_proxy = { .flags = VTPM_PROXY_FLAG_TPM2 };
    int ctl = open("/dev/vtpmx",O_RDWR | O_CLOEXEC);

    if (ctl < 0){
        perror("open /dev/vtpmx");
        close(ctl);
        return -1;
    }
    
    if( ioctl(ctl, VTPM_PROXY_IOC_NEW_DEV, &cca_tpm_dev_proxy) < 0){
        perror("VPTM_PROXY_IOC_NEW_DEV");
        close(ctl);
        return -1;
    }

    close(ctl);

    if ( cca_tpm_dev_proxy.fd < 0)
        return EXIT_FAILURE;

    proxy_fd = cca_tpm_dev_proxy.fd;
    tpm_num = cca_tpm_dev_proxy.tpm_num;
    snprintf(devpath, sizeof(devpath), "/dev/tpm%u", tpm_num);

    struct pollfd p = { .fd = proxy_fd, .events = POLLIN };
     

    for(;;){
        
        res = poll(&p, 1, 200);

        if (res < 0) {
			if (errno == EINTR)
				continue;
			perror("poll");
			return EXIT_FAILURE;
		}
    
        if (p.revents & (POLLERR | POLLHUP | POLLNVAL)) {
			fprintf(stderr, "cca-tpm-relay: proxy device closed\n");
			return EXIT_FAILURE;
		}
        if (!signalled && access(devpath, F_OK) == 0) {
            fprintf(stderr, "cca-relay: %s ready\n", devpath);
            if ( vtpm_ready(fd_ctl, proxy_fd) < 0)
                return EXIT_FAILURE;
            signalled = 1;
        }
        if ( res == 0 )
            continue;
        
        n = read(proxy_fd, cmd, sizeof(cmd));
		if (n < 0) {
			if (errno == EINTR || errno == EAGAIN)
				continue;
			perror("read proxy");
			return 1;
		}
		
        if (n < TPM_HDR_SIZE)
			continue;

        t0 = now_ms(); 
        
        if ( transact(fd, cmd, n, rsp, &rsp_len,
                    RESPONSE_TIMEOUT_MS)){
            fprintf(stderr, "cca-tpm-relay: realm link failed: %s\n",
				strerror(errno));
            rsp_len = make_error_rsp(cmd, rsp);
            if (write_full(proxy_fd, rsp, rsp_len))
				perror("write proxy");
			return 1;
        }
        
        /*
         * fprintf(stderr, "cca-tpm-relay: cc 0x%08x -> rc 0x%x (%.0f ms)\n",
		 *          be_to_le_32(cmd + 6), be_to_le_32(rsp + 6), now_ms() - t0);
		*/
        
        if (write_full(proxy_fd, rsp, rsp_len)) {
		    if ( errno == EPIPE){
                fprintf(stderr, "cca-tpm-relay: the kernel closed the proxy device "
					"(command timed out or chip registration failed); "
					"late response dropped\n");
            }else
                perror("write proxy");
			return 1;
        }
    }
    close(fd);
    return EXIT_SUCCESS;
}
