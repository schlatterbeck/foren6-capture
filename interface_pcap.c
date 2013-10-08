#include "interface_pcap.h"

#include <stdio.h>
#include <stdlib.h>
#include <fcntl.h>
#include <unistd.h>
#include <pcap/pcap.h>
#include <pthread.h>
#include <string.h>
#include <errno.h>

#if __APPLE__
#define pthread_timedjoin_np(...) (1)
#endif

static const char *interface_name = "pcap";

typedef struct {
    FILE *pf;
	pcap_t *pc;
	bool capture_packets;
	pthread_t thread;
	long first_offset;
} interface_handle_t; //*ifreader_t

static void interface_init();
static ifreader_t interface_open(const char *target, int channel);
static bool interface_start(ifreader_t handle);
static void interface_stop(ifreader_t handle);
static void interface_close(ifreader_t handle);
static void *interface_thread_process_input(void *data);
static void interface_packet_handler(u_char *param, const struct pcap_pkthdr *header, const u_char *pkt_data);

int interface_get_version() {
	return 1;
}

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

	handle->pf = fopen(target, "r");
    if(handle->pf == NULL) {
        fprintf(stderr, "Cannot open target %s: %s\n", target, strerror(errno));
        free(handle);
        return NULL;
    }
	handle->pc = pcap_fopen_offline(handle->pf, errbuf);
	if(handle->pc == NULL) {
		fprintf(stderr, "Cannot read target %s: %s\n", target, errbuf);
		fclose(handle->pf);
		free(handle);
		return NULL;
	}

	ifreader_t instance = interfacemgr_create_handle(target);
	instance->interface_data = handle;

    if (pcap_datalink (handle->pc) == DLT_EN10MB)
    {
      instance->ethernet = true;
    }
    else if (pcap_datalink (handle->pc) != DLT_IEEE802_15_4)
	{
        fprintf (stderr, "This program only supports 802.15.4 and Ethernet encapsulated 802.15.4 sniffers (DLT: %d)\n", pcap_datalink (handle->pc));
        free(handle);
        return NULL;
	 }
    handle->first_offset = ftell(handle->pf);
	return instance;
}

static bool interface_start(ifreader_t handle) {
	interface_handle_t *descriptor = handle->interface_data;
	if(descriptor->capture_packets == false) {
		descriptor->capture_packets = true;
		if ( fseek(descriptor->pf, descriptor->first_offset, SEEK_SET) == -1) {
	        fprintf(stderr, "warning, fseek() failed : %s\n", strerror(errno));
		}
		pthread_create(&descriptor->thread, NULL, &interface_thread_process_input, handle);
	}

	return true;
}

static void interface_stop(ifreader_t handle) {
	interface_handle_t *descriptor = handle->interface_data;
	if(descriptor->capture_packets == true) {
		struct timespec timeout = {3, 0};

		descriptor->capture_packets = false;

		if(pthread_timedjoin_np(descriptor->thread, NULL, &timeout) != 0) {
			pthread_cancel(descriptor->thread);
			pthread_join(descriptor->thread, NULL);
		}
	}
}

static void interface_close(ifreader_t handle) {
	interface_handle_t *descriptor = handle->interface_data;

	interface_stop(handle);

	pcap_close(descriptor->pc);
	fclose(descriptor->pf);
	free(descriptor);
	interfacemgr_destroy_handle(handle);
}

static void* interface_thread_process_input(void *data) {
	ifreader_t handle = (ifreader_t)data;
	interface_handle_t *descriptor = handle->interface_data;
	int pcap_result;

	fprintf(stderr, "PCAP reader started\n");

	while(1) {
		pcap_result = pcap_dispatch(descriptor->pc, 1, &interface_packet_handler, (u_char*)handle);
		if(!descriptor->capture_packets || pcap_result < 0) {
			fprintf(stderr, "PCAP reader stopped\n");
			pcap_perror(descriptor->pc, "PCAP end result");
			return NULL;
		}
		if(pcap_result == 0)
			usleep(100000);
	}
}

static void interface_packet_handler(u_char *param, const struct pcap_pkthdr *header, const u_char *pkt_data) {
	ifreader_t descriptor = (ifreader_t)param;

	const u_char * pkt_data_802_15_4 = descriptor->ethernet ? pkt_data + 14 : pkt_data;
	int len = header->caplen == header->len ? header->caplen-2 : header->caplen;  //Never include the FCS in packets
	if ( descriptor->ethernet ) {
	    len -= 14;
	}
    if (descriptor->ethernet && (pkt_data[12] != 0x80 || pkt_data[13] != 0x9a)) {
      return;
    }
    interfacemgr_process_packet(descriptor, pkt_data_802_15_4, len, header->ts);
}
