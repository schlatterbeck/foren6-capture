#include "interface_pcap.h"

#include <stdio.h>
#include <stdlib.h>
#include <fcntl.h>
#include <unistd.h>
#include <pcap/pcap.h>
#include <pthread.h>
#include <string.h>


static const char *interface_name = "pcap";

typedef struct {
	pcap_t *pc;
	bool capture_packets;
	pthread_t thread;
} interface_handle_t; //*ifreader_t

static void interface_init();
static ifreader_t interface_open(const char *target, int channel);
static bool interface_start(ifreader_t handle);
static void interface_stop(ifreader_t handle);
static void interface_close(ifreader_t handle);
static void *interface_thread_process_input(void *data);
static void interface_packet_handler(u_char *param, const struct pcap_pkthdr *header, const u_char *pkt_data);

interface_t interface_register() {
	interface_t interface;

	memset(&interface, 0, sizeof(interface));

	interface.interface_name = interface_name;
	interface.init = &interface_init;
	interface.open = &interface_open;
	interface.close = &interface_close;
	interface.start = &interface_start;
	interface.stop = &interface_stop;

	return interface;
}

static void interface_init() {
	desc_poll_init();
	fprintf(stderr, "%s interface initialized\n", interface_name);
}

static ifreader_t interface_open(const char *target, int channel) {
	interface_handle_t *handle;
	char errbuf[PCAP_ERRBUF_SIZE];

	handle = (interface_handle_t*) calloc(1, sizeof(interface_handle_t));
	if(!handle)
		return NULL;

	handle->capture_packets = false;

	handle->pc = pcap_open_offline(target, errbuf);
	if(handle->pc == NULL) {
		fprintf(stderr, "Cannot open target %s: %s\n", target, errbuf);
		free(handle);
		return NULL;
	}

	return handle;
}

static bool interface_start(ifreader_t handle) {
	interface_handle_t *descriptor = (interface_handle_t*)handle;
	if(descriptor->capture_packets == false) {
		descriptor->capture_packets = true;
		pthread_create(&descriptor->thread, NULL, &interface_thread_process_input, handle);
	}

	return true;
}

static void interface_stop(ifreader_t handle) {
	interface_handle_t *descriptor = (interface_handle_t*)handle;
	if(descriptor->capture_packets == true) {
		descriptor->capture_packets = false;
		pthread_join(descriptor->thread, NULL);
	}
}

static void interface_close(ifreader_t handle) {
	interface_handle_t *descriptor = (interface_handle_t*)handle;

	interface_stop(handle);

	pcap_close(descriptor->pc);
	free(descriptor);
}

static void* interface_thread_process_input(void *data) {
	interface_handle_t *descriptor = (interface_handle_t*)data;
	int pcap_result;

	fprintf(stderr, "PCAP reader started\n");

	while(1) {
		pcap_result = pcap_dispatch(descriptor->pc, 1, &interface_packet_handler, NULL);
		if(!descriptor->capture_packets || pcap_result < 1) {
			fprintf(stderr, "PCAP reader stopped\n");
			pcap_perror(descriptor->pc, "PCAP end result");
			return NULL;
		}
	}
}

static void interface_packet_handler(u_char *param, const struct pcap_pkthdr *header, const u_char *pkt_data) {
	if(header->caplen == header->len)
		sniffer_parser_parse_data(pkt_data, header->caplen-2, header->ts);  //Never include the FCS in packets
	else sniffer_parser_parse_data(pkt_data, header->caplen, header->ts);
}
