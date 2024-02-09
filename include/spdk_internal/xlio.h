/*   SPDX-License-Identifier: BSD-3-Clause
 *   Copyright (c) 2024 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
 */

#ifndef __SPDK_XLIO_H__
#define __SPDK_XLIO_H__

#include <sys/epoll.h>
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wstrict-prototypes"
#pragma GCC diagnostic ignored "-Wold-style-definition"
#include <mellanox/xlio_extra.h>
#pragma GCC diagnostic pop
#include <mellanox/xlio.h>
#include "spdk/config.h"

#ifdef __cplusplus
extern "C" {
#endif

int spdk_xlio_init(void);
void spdk_xlio_fini(void);

#ifdef SPDK_CONFIG_STATIC_XLIO

/* Statically linked libxlio */

#define xlio_getaddrinfo(...) getaddrinfo(__VA_ARGS__)
#define xlio_freeaddrinfo(...) freeaddrinfo(__VA_ARGS__)
#define xlio_gai_strerror(...) gai_strerror(__VA_ARGS__)

#else

/* Dynamically loaded shared libxlio */

struct spdk_sock_xlio_ops {
	int (*socket)(int domain, int type, int protocol);
	int (*bind)(int sockfd, const struct sockaddr *addr, socklen_t addrlen);
	int (*listen)(int sockfd, int backlog);
	int (*connect)(int sockfd, const struct sockaddr *addr, socklen_t addrlen);
	int (*accept)(int sockfd, struct sockaddr *restrict addr, socklen_t *restrict addrlen);
	int (*close)(int fd);
	ssize_t (*readv)(int fd, const struct iovec *iov, int iovcnt);
	ssize_t (*writev)(int fd, const struct iovec *iov, int iovcnt);
	ssize_t (*recv)(int sockfd, void *buf, size_t len, int flags);
	ssize_t (*recvmsg)(int sockfd, struct msghdr *msg, int flags);
	ssize_t (*sendmsg)(int sockfd, const struct msghdr *msg, int flags);
	int (*fcntl)(int fd, int cmd, ... /* arg */);
	int (*ioctl)(int fd, unsigned long request, ...);
	int (*getsockopt)(int sockfd, int level, int optname, void *restrict optval,
			  socklen_t *restrict optlen);
	int (*setsockopt)(int sockfd, int level, int optname, const void *optval, socklen_t optlen);
	int (*getsockname)(int sockfd, struct sockaddr *restrict addr, socklen_t *restrict addrlen);
	int (*getpeername)(int sockfd, struct sockaddr *restrict addr, socklen_t *restrict addrlen);
	int (*getaddrinfo)(const char *restrict node,
			   const char *restrict service,
			   const struct addrinfo *restrict hints,
			   struct addrinfo **restrict res);
	void (*freeaddrinfo)(struct addrinfo *res);
	const char *(*gai_strerror)(int errcode);
};

extern struct spdk_sock_xlio_ops g_xlio_ops;
extern struct xlio_api_t *g_xlio_api;

#define xlio_socket(...) g_xlio_ops.socket(__VA_ARGS__)
#define xlio_bind(...) g_xlio_ops.bind(__VA_ARGS__)
#define xlio_listen(...) g_xlio_ops.listen(__VA_ARGS__)
#define xlio_connect(...) g_xlio_ops.connect(__VA_ARGS__)
#define xlio_accept(...) g_xlio_ops.accept(__VA_ARGS__)
#define xlio_close(...) g_xlio_ops.close(__VA_ARGS__)
#define xlio_readv(...) g_xlio_ops.readv(__VA_ARGS__)
#define xlio_writev(...) g_xlio_ops.writev(__VA_ARGS__)
#define xlio_recv(...) g_xlio_ops.recv(__VA_ARGS__)
#define xlio_recvmsg(...) g_xlio_ops.recvmsg(__VA_ARGS__)
#define xlio_sendmsg(...) g_xlio_ops.sendmsg(__VA_ARGS__)
#define xlio_fcntl(...) g_xlio_ops.fcntl(__VA_ARGS__)
#define xlio_ioctl(...) g_xlio_ops.ioctl(__VA_ARGS__)
#define xlio_getsockopt(...) g_xlio_ops.getsockopt(__VA_ARGS__)
#define xlio_setsockopt(...) g_xlio_ops.setsockopt(__VA_ARGS__)
#define xlio_getsockname(...) g_xlio_ops.getsockname(__VA_ARGS__)
#define xlio_getpeername(...) g_xlio_ops.getpeername(__VA_ARGS__)
#define xlio_getaddrinfo(...) g_xlio_ops.getaddrinfo(__VA_ARGS__)
#define xlio_freeaddrinfo(...) g_xlio_ops.freeaddrinfo(__VA_ARGS__)
#define xlio_gai_strerror(...) g_xlio_ops.gai_strerror(__VA_ARGS__)
#define xlio_socketxtreme_poll(...) g_xlio_api->socketxtreme_poll(__VA_ARGS__)
#define xlio_socketxtreme_free_packets(...) g_xlio_api->socketxtreme_free_packets(__VA_ARGS__)
#define xlio_get_socket_rings_fds(...) g_xlio_api->get_socket_rings_fds(__VA_ARGS__)
#define xlio_extra_ioctl(...) g_xlio_api->ioctl(__VA_ARGS__)

#endif

#ifdef __cplusplus
}
#endif

#endif /* __SPDK_XLIO_H__ */
