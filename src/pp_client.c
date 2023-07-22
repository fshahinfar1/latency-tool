/*
 * Ping Pong Client
 * */

#define _GNU_SOURCE

#include <stdlib.h>
#include <stdio.h>
#include <errno.h>
#include <string.h>
#include <time.h>

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


typedef unsigned long long int timestamp;
#define TIMESTAMP_SIZE sizeof(timestamp)
#define MINIMUM_PAYLOAD_SIZE (2 + TIMESTAMP_SIZE)
#define HEADER 0x11
#define TRAILER 0xFF
#define MAX_MEASUREMENTS 1000000000LL

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

static int sk_fd;
static int run;
void handle_interrupt(int sig)
{
	run = 0;
	close(sk_fd);
}

static timestamp get_ns()
{
	int ret;
	struct timespec ts;
	ret = clock_gettime(CLOCK_MONOTONIC, &ts);
	assert(ret == 0);
	return ts.tv_sec * 1000000000LL + ts.tv_nsec;
}

int main(int argc, char *argv[])
{
	signal(SIGINT, handle_interrupt);
	signal(SIGTERM, handle_interrupt);

	/* TODO: get these values from CLI */
	char *target_ip = "192.168.1.2";
	short target_port = 8080;
	int window_size = 4;
	int msg_size = 30;
	/* warm up time in nanosecond */
	timestamp warm_up = 1000000000LL;

	size_t measurement_index = 0;
	timestamp *measurements = malloc(MAX_MEASUREMENTS);

	enum parser_state state = LOOKING_FOR_HEADER;
	int ret;
	unsigned char *msg, *recv_buf;
	struct sockaddr_in sk_addr;

	run = 1;
	const timestamp start_ts = get_ns();

	size_t send_count = 0;
	timestamp prev_tp_report = 0;

	sk_addr.sin_family = AF_INET;
	sk_addr.sin_port = htons(target_port);
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
	*(timestamp *)(&msg[1]) = start_ts;
	msg[msg_size - 1] = TRAILER;

	for (int i = 0; i < window_size; i++) {
		ret = send(sk_fd, msg, msg_size, 0);
		/* TODO: if less than the message size is sent, it means that I
		 * need to retry to send the rest of the message.
		 * */
		assert(ret == msg_size);
	}
	send_count += window_size;

	unsigned int ts_byte_count = 0;
	unsigned char recv_ts[TIMESTAMP_SIZE] = {};
	timestamp now = 0;
	timestamp lat = 0;
	while (run) {
		ret = recv(sk_fd, recv_buf, msg_size, 0);
		if (ret < 0) {
			run = 0;
			break;
		}
		now = get_ns();
		/* printf("recv something\n"); */
		for (int i = 0; i < ret; i++) {
			switch(state) {
				case LOOKING_FOR_HEADER:
					if (recv_buf[i] == HEADER) {
						state = WAITING_FOR_TIMESTAMP;
						ts_byte_count = 0;
						*(timestamp *)recv_ts = 0;
						/* printf("found header\n"); */
					} else {
						/* Unexpected value ! */
					}
					break;
				case WAITING_FOR_TIMESTAMP:
					recv_ts[ts_byte_count] = recv_buf[i];
					ts_byte_count += 1;
					if (ts_byte_count == TIMESTAMP_SIZE) {
						state = LOOKING_FOR_TRAILER;
						/* printf("found ts (%lld - %d bytes)\n", recv_ts, ts_byte_count); */
					}
					break;
				case LOOKING_FOR_TRAILER:
					/* printf("%x\n", (unsigned int)recv_buf[i]); */
					if (recv_buf[i] == TRAILER) {
						/* printf("found trailer\n"); */
						/* end of a round trip */
						state = LOOKING_FOR_HEADER;
						if (now  >= start_ts + warm_up) {
							lat = now - *(timestamp *)recv_ts;
							/* printf("lat: %llu (%llu - %llu)\n", lat, now, *(timestamp *)recv_ts); */
							measurements[measurement_index++] = lat;
							if (measurement_index >= MAX_MEASUREMENTS) {
								fprintf(stderr, "Maximum number of measurements reached\n");
								run = 0;
								break;
							}
						}
						/* send a new requst */
						*(timestamp *)(&msg[1]) = get_ns();
						ret = send(sk_fd, msg, msg_size, 0);
						if (ret < 0) {
							break;
							run = 0;
						}
						if (ret != msg_size) {
							fprintf(stderr, "Unexpected: failed to send whole message!\n");
							return 1;
						}
						send_count += 1;
					} else {
						/* It should be the body of the response */
					}
					break;
				default:
					assert(0);
					break;
			}
		}

		double delta = now - prev_tp_report;
		if (delta > 2000000000L) {
			delta *= 0.000000001;
			prev_tp_report = now;
			printf("send: %f\n", send_count / delta);
			send_count = 0;
		}
	}
	close(sk_fd);

	/* Report the results */
	char file_path[255];
	snprintf(file_path, 254, "/tmp/pp_client_lat_%lld.txt", get_ns());
	int outfile_fd = open(file_path,
			O_CREAT | O_RDWR,
			S_IRUSR | S_IWUSR | S_IROTH | S_IWOTH | S_IRGRP | S_IWGRP);
	assert(outfile_fd >= 0);
	for (size_t i = 0; i < measurement_index; i++) {
		dprintf(outfile_fd, "%lld\n", measurements[i]);
	}
	close(outfile_fd);
	printf("output file: %s\n", file_path);
	printf("Done!\n");
	return 0;
}
