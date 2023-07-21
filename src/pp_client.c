/*
 * Ping Pong Client
 * */

#define _GNU_SOURCE

#include <stdlib.h>
#include <stdio.h>
#include <errno.h>

#include <arpa/inet.h>
#include <linux/in.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>

#include <sys/types.h>
#include <sys/socket.h>

#include <sys/ioctl.h>
#include <sys/fcntl.h>
#include <signal.h>
#include <assert.h>


#define TIMESTAMP_SIZE 8
#define MINIMUM_PAYLOAD_SIZE (2 + TIMESTAMP_SIZE)
#define HEADER 0x11
#define TRAILER 0xFF

enum parser_state {
	LOOKING_FOR_HEADER,
	WAITING_FOR_TIMESTAMP,
	LOOKING_FOR_TRAILER,
};

int set_sock_opt(int sk_fd)
{

	int ret;
	int opt_val;
	opt_val = 1;

	ret = setsockopt(sk_fd, SOL_SOCKET, SO_REUSEPORT, &opt_val, sizeof(opt_val));
	if (ret)
		return ret;

	ret = setsockopt(sk_fd, SOL_SOCKET, SO_REUSEADDR, &opt_val, sizeof(opt_val));
	if (ret)
		return ret;

	ret = setsockopt(sk_fd, SOL_TCP, TCP_NODELAY, &opt_val, sizeof(opt_val));
	if (ret)
		return ret;

	return 0;
}

int main(int argc, char *argv[])
{

	char *target_ip = "192.168.1.1";
	short target_port = 8008;
	int window_size = 32;
	int msg_size = 500;

	enum parser_state state;
	int ret;
	int sk_fd;
	char *msg, *recv_buf;
	struct sockaddr_in sk_addr;
	socklen_t sk_size = sizeof(sk_addr);
	inet_pton(AF_INET, target_ip, &(sk_addr.sin_addr));

	sk_fd = socket(AF_INET, SOCK_STREAM, 0);
	assert(sk_fd >= 0);
	ret = set_sock_opt(sk_fd);
	assert(ret == 0);
	ret = connect(sk_fd, &sk_addr, sizeof(sk_addr));
	assert(ret == 0);

	msg = malloc(msg_size);
	assert(msg != NULL);
	recv_buf = malloc(msg_size);
	assert(recv_buf != NULL);

	memset(msg, 0xAB, msg_size);
	msg[0] = HEADER;
	(uint64_t *)(&msg[1]) = get_ns();
	msg[msg_size - 1] = TRAILER;

	for (int i = 0; i < window_size; i++) {
		ret = send(sk_fd, msg, msg_size, 0);
		/* TODO: if less than the message size is sent, it means that I
		 * need to retry to send the rest of the message.
		 * */
		assert(ret == msg_size);
	}

	int ts_byte_count;
	long long int recv_ts;
	while (true) {
		ret = recv(sk_fd, recv_buf, msg_size, 0);
		assert(ret >= 0);
		for (int i = 0; i < ret; i++) {
			switch(state) {
				case LOOKING_FOR_HEADER:
					if (recv_buf[i] == HEADER) {
						state = WAITING_FOR_TIMESTAMP;
						ts_byte_count = 0;
						recv_ts = 0;
					} else {
						/* Unexpected value ! */
					}
					break;
				case WAITING_FOR_TIMESTAMP:
					recv_ts = recv_ts << 1;
					recv_ts = recv_ts | recv_buf[i];
					ts_byte_count += 1;
					if (ts_byte_count == TIMESTAMP_SIZE) {
						state = LOOKING_FOR_TRAILER;
					}
					break;
				case LOOKING_FOR_TRAILER:
					if (recv_buf[i] == TRAILER) {
						/* end of a round trip */
						state = LOOKING_FOR_HEADER;
					}
					break;
				default:
					break;
			}
			if (recv_buf[i
		}
	}
	return 0;
}
