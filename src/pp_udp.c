/*
 * Ping Pong Client
 * */

#define _GNU_SOURCE

#include <stdlib.h>
#include <stdio.h>
#include <errno.h>
#include <string.h>
#include <time.h>
#include <getopt.h>

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

struct params {
	char *target_ip;
	short target_port;
	int window_size;
	int msg_size;
	timestamp warm_up;
};

static struct params args;

void usage()
{
	printf("Usage: pp [Options] <ip> <port>\n"
		"Options:\n"
		"--msg-size -m: message size       (default: 500 byte)\n"
		"--wnd-size -w: window size        (default: 1)\n"
		"--warm-up    : warm up time       (default: 1 sec)\n"
	);
}

int parse_args(int argc, char *argv[])
{
	int ret;
	/* Default values */
	args.msg_size = 500;
	args.window_size = 1;
	args.warm_up = 1000000000LL;
	/* TODO: get these values from CLI */
	args.target_ip = "192.168.1.2";
	args.target_port = 8080;

	enum opts {
		HELP = 100,
		MSG_SIZE,
		WND_SIZE,
		WARM_UP,
	};
	struct option long_opts[] = {
		{"help", no_argument, NULL, HELP},
		{"msg-size", required_argument, NULL, MSG_SIZE},
		{"wnd-size", required_argument, NULL, WND_SIZE},
		{"warm-up", required_argument, NULL, WARM_UP},
		{NULL, 0, NULL, 0},
	};
	while (1) {
		ret = getopt_long(argc, argv, "hm:w:", long_opts, NULL);
		if (ret == -1)
			break;
		switch (ret) {
			case MSG_SIZE:
				args.msg_size = atoi(optarg);
				break;
			case WND_SIZE:
				args.window_size = atoi(optarg);
				break;
			case WARM_UP:
				args.warm_up = atol(optarg) * 1000000000L;
				break;
			case HELP:
				usage();
				exit(0);
			default:
				usage(argv[0]);
				exit(EXIT_FAILURE);
				break;
		}
	}
	if (argc - optind < 2) {
		usage(argv[0]);
		exit(EXIT_FAILURE);
	}
	args.target_ip = strdup(argv[optind]);
	args.target_port = atoi(argv[optind+1]);
	return 0;
}

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

	int ret;
	ret = parse_args(argc, argv);
	assert(ret == 0);
	int msg_size = args.msg_size;
	timestamp warm_up = args.warm_up;

	size_t measurement_index = 0;
	timestamp *measurements = malloc(MAX_MEASUREMENTS);

	unsigned char *msg, *recv_buf;
	struct sockaddr_in sk_addr;

	run = 1;
	const timestamp start_ts = get_ns();

	size_t send_count = 0;
	timestamp prev_tp_report = 0;

	sk_addr.sin_family = AF_INET;
	sk_addr.sin_port = htons(args.target_port);
	inet_pton(AF_INET, args.target_ip, &(sk_addr.sin_addr));

	sk_fd = socket(AF_INET, SOCK_DGRAM, 0);
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

	for (int i = 0; i < args.window_size; i++) {
		ret = send(sk_fd, msg, msg_size, 0);
		/* TODO: if less than the message size is sent, it means that I
		 * need to retry to send the rest of the message.
		 * */
		assert(ret == msg_size);
	}
	send_count += args.window_size;

	timestamp recv_ts;
	timestamp now = 0;
	timestamp lat = 0;
	while (run) {
		ret = recv(sk_fd, recv_buf, msg_size, 0);
		if (ret < 0) {
			run = 0;
			break;
		}
		/* UDP is message oriented */
		assert (ret == msg_size);
		now = get_ns();
		/* printf("recv something\n"); */
		recv_ts = *(timestamp *)&recv_buf[1];

		/* end of a round trip */
		if (now  >= start_ts + warm_up) {
			lat = now - recv_ts;
			/* printf("lat: %llu (%llu - %llu)\n", lat, now, recv_ts); */
			measurements[measurement_index++] = lat;
			if (measurement_index >= MAX_MEASUREMENTS) {
				fprintf(stderr, "Maximum number of measurements reached\n");
				run = 0;
				break;
			}
		}
		/* send a new requst */
		*(timestamp *)(&msg[1]) = now;
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
	snprintf(file_path, 254, "/tmp/pp_udp_lat_%lld.txt", get_ns());
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
