#include "interface_telos.h"

#include <circular_buffer.h>
#include <sniffer_packet_parser.h>
#include <descriptor_poll.h>

#include <stdio.h>
#include <fcntl.h>
#include <termios.h>
#include <string.h>
#include <unistd.h>
#include <stdlib.h>

static const char expected_magic[4] = "SNIF";
static const unsigned char enable_sniffer_cmd[3] = { 0xFA, 0x3A, '\n' };

#define FIELD_CRC        1
#define FIELD_CRC_OK     2
#define FIELD_RSSI       4
#define FIELD_LQI        8
#define FIELD_TIMESTAMP 16
	
typedef enum {
	PRS_Magic,
	PRS_Type,
	PRS_Len,
	PRS_Data,
	PRS_Crc,
	PRS_CrcOk,
	PRS_Rssi,
	PRS_Lqi,
	PRS_TimeStamp,
	PRS_Done
} packet_read_state_e;

typedef struct {
	circular_buffer_t input_buffer;
	int serial_line;
	
	//states
	packet_read_state_e current_state;
	packet_read_state_e last_state;
	packet_read_state_e before_switch_state;
	
	//current packet data
	
	char           pkt_magic[4];
	unsigned char  pkt_type;
	unsigned char  pkt_len;
	unsigned char  pkt_data[256];
	unsigned short pkt_crc;
	unsigned char  pkt_crc_ok;
	unsigned char  pkt_rssi;
	unsigned char  pkt_lqi;
	unsigned short pkt_timestamp;

	int pkt_received_index;
} interface_handle_t; //*ifreader_t

static void sniffer_interface_init();
static ifreader_t sniffer_interface_open(const char *target);
static bool sniffer_interface_start(ifreader_t handle);
static void sniffer_interface_stop(ifreader_t handle);
static void sniffer_interface_close(ifreader_t handle);

static void process_input(int fd, void* handle);
static bool read_input(interface_handle_t* descriptor);
static bool can_read_byte(interface_handle_t* descriptor);
static unsigned char get_byte(interface_handle_t* descriptor);
static void set_serial_attribs(int fd, int baudrate, int parity);

interface_t interface_register() {
	interface_t interface;
	
	memset(&interface, 0, sizeof(interface));
	
	interface.interface_name = "telos";
	interface.init = &sniffer_interface_init;
	interface.open = &sniffer_interface_open;
	interface.close = &sniffer_interface_close;
	interface.start = &sniffer_interface_start;
	interface.stop = &sniffer_interface_stop;
	
	return interface;
}

static void sniffer_interface_init() {
	desc_poll_init();
	fprintf(stderr, "telos interface initialized\n");
}

static ifreader_t sniffer_interface_open(const char *target) {
	interface_handle_t *handle;

	handle = (interface_handle_t*) calloc(1, sizeof(interface_handle_t));
	if(!handle)
		return NULL;
	
	fprintf(stderr, "Opening %s\n", target);
	if((handle->serial_line = open(target, O_RDWR | O_NOCTTY | O_SYNC)) < 0) {
		perror("Cannot open interface");
		return;
	}
	
	set_serial_attribs(handle->serial_line, B115200, 0);
	
	write(handle->serial_line, enable_sniffer_cmd, 3);	//Enable sniffer

	handle->input_buffer = circular_buffer_create(32, 1);
	if(handle->input_buffer == NULL)
		fprintf(stderr, "FATAL: can't allocate input buffer\n");
	
	handle->current_state = PRS_Magic;
	handle->last_state = PRS_Done;
	
}

static bool sniffer_interface_start(ifreader_t handle) {
	interface_handle_t *descriptor = (interface_handle_t*)handle;
	desc_poll_add(descriptor->serial_line, &process_input, descriptor);
}

static void sniffer_interface_stop(ifreader_t handle) {
	interface_handle_t *descriptor = (interface_handle_t*)handle;
	desc_poll_del(descriptor->serial_line);
}

static void sniffer_interface_close(ifreader_t handle) {
	interface_handle_t *descriptor = (interface_handle_t*)handle;
	
	sniffer_interface_stop(handle);
	
	circular_buffer_delete(descriptor->input_buffer);
	close(descriptor->serial_line);
	free(descriptor);
}

static void process_input(int fd, void* handle) {
	interface_handle_t *descriptor = (interface_handle_t*)handle;
	
	//Pars input until there is no more data to parse
	do {
		
/*
		if(descriptor->last_state != descriptor->current_state)
			fprintf(stderr, "state changed, %d -> %d\n", descriptor->last_state, descriptor->current_state);
*/

		descriptor->before_switch_state = descriptor->current_state;
	
		//Read input until our buffer is full or there is no more data to read
		while(read_input(descriptor) == true);

		switch(descriptor->current_state) {
			case PRS_Magic:
				if(descriptor->last_state != descriptor->current_state)
					descriptor->pkt_received_index = 0;

				if(can_read_byte(descriptor))
					descriptor->pkt_magic[descriptor->pkt_received_index] = get_byte(descriptor);
				else break;

				if(descriptor->pkt_magic[descriptor->pkt_received_index] != expected_magic[descriptor->pkt_received_index])
					descriptor->pkt_received_index = 0;  //Invalid magic number -> reset received packet getByte(serial_line) until we have a "SNIF"
				else descriptor->pkt_received_index++;

				if(descriptor->pkt_received_index >= 4)
					descriptor->current_state = PRS_Type;
				break;

			case PRS_Type:
				if(can_read_byte(descriptor))
					descriptor->pkt_type = get_byte(descriptor);
				else break;

				descriptor->current_state = PRS_Len;
				break;

			case PRS_Len:
				if(can_read_byte(descriptor))
					descriptor->pkt_len = get_byte(descriptor);
				else break;

				descriptor->current_state = PRS_Data;
				break;

			case PRS_Data:
				if(descriptor->last_state != descriptor->current_state)
					descriptor->pkt_received_index = 0;

				if(descriptor->pkt_received_index >= descriptor->pkt_len)
					descriptor->current_state = PRS_Crc;
				else {
					if(can_read_byte(descriptor))
						descriptor->pkt_data[descriptor->pkt_received_index] = get_byte(descriptor);
					else break;

					descriptor->pkt_received_index++;
				}
				break;

			case PRS_Crc:
				if(descriptor->pkt_type & FIELD_CRC) {
					if(descriptor->last_state != descriptor->current_state) {
						descriptor->pkt_received_index = 0;
						descriptor->pkt_crc = 0;
					}

					if(can_read_byte(descriptor))
						descriptor->pkt_crc |= (uint16_t) get_byte(descriptor) << (8*descriptor->pkt_received_index);
					else break;

					descriptor->pkt_received_index++;

					if(descriptor->pkt_received_index >= 2)
						descriptor->current_state = PRS_CrcOk;
				} else {
					descriptor->current_state = PRS_CrcOk;
				}
				break;

			case PRS_CrcOk:
				if(descriptor->pkt_type & FIELD_CRC_OK) {
					if(can_read_byte(descriptor))
						descriptor->pkt_crc_ok = get_byte(descriptor);
					else break;
				} else {
					descriptor->pkt_crc_ok = 1;
				}
				descriptor->current_state = PRS_Rssi;
				break;

			case PRS_Rssi:
				if(descriptor->pkt_type & FIELD_RSSI) {
					if(can_read_byte(descriptor))
						descriptor->pkt_rssi = get_byte(descriptor);
					else break;
				}
				descriptor->current_state = PRS_Lqi;
				break;

			case PRS_Lqi:
				if(descriptor->pkt_type & FIELD_LQI) {
					if(can_read_byte(descriptor))
						descriptor->pkt_lqi = get_byte(descriptor);
					else break;
				}
				descriptor->current_state = PRS_TimeStamp;
				break;

			case PRS_TimeStamp:
				if(descriptor->pkt_type & FIELD_TIMESTAMP) {
					if(descriptor->last_state != descriptor->current_state) {
						descriptor->pkt_received_index = 0;
						descriptor->pkt_timestamp = 0;
					}

					if(can_read_byte(descriptor))
						descriptor->pkt_timestamp |= get_byte(descriptor) << (8*descriptor->pkt_received_index);
					else break;

					descriptor->pkt_received_index++;

					if(descriptor->pkt_received_index >= 2)
						descriptor->current_state = PRS_Done;
				} else {
					descriptor->current_state = PRS_Done;
				}
				break;

			case PRS_Done:
				if(descriptor->pkt_len > 0 && descriptor->pkt_crc_ok) {      //Discard bad packet and packet without data captured
					sniffer_parser_parse_data(descriptor->pkt_data, descriptor->pkt_len);
				}
				descriptor->current_state = PRS_Magic;
				break;
		}

		descriptor->last_state = descriptor->before_switch_state;
	} while(can_read_byte(descriptor));
}

static bool read_input(interface_handle_t* descriptor) {
	unsigned char data;

	if(!circular_buffer_is_full(descriptor->input_buffer) && (read(descriptor->serial_line, &data, 1) == 1)) {
		//fprintf(stderr, "Received data 0x%02X\n", data);
		circular_buffer_push_front(descriptor->input_buffer, &data);
		return true;
	}

	return false;
}

static bool can_read_byte(interface_handle_t* descriptor) {
	return !circular_buffer_is_empty(descriptor->input_buffer);
}

static unsigned char get_byte(interface_handle_t* descriptor) {
	unsigned char *data;
	
	data = (unsigned char*) circular_buffer_pop_back(descriptor->input_buffer);
	
	if(data) {
		//fprintf(stderr, "Read data from buffer 0x%02X\n", *data);
		return *data;
	} else {
		fprintf(stderr, "empty buffer !\n");
		return 0;
	}
}

static void set_serial_attribs(int fd, int baudrate, int parity)
{
	struct termios tty;
	memset(&tty, 0, sizeof(tty));
	if (tcgetattr (fd, &tty) != 0)
	{
		perror("Can't get serial line attributes");
		//Probably just a file ... so set it non blocking as expected
		fcntl(fd, F_SETFL, fcntl(fd, F_GETFL, 0) | O_NONBLOCK);
		return;
	}

	cfsetospeed (&tty, baudrate);
	cfsetispeed (&tty, baudrate);

	tty.c_cflag = (tty.c_cflag & ~CSIZE) | CS8;     // 8-bit chars
	// disable IGNBRK for mismatched speed tests; otherwise receive break
	// as \000 chars
	tty.c_iflag &= ~IGNBRK;         // ignore break signal
	tty.c_lflag = 0;                // no signaling chars, no echo,
									// no canonical processing
	tty.c_oflag = 0;                // no remapping, no delays
	tty.c_cc[VMIN]  = 0;            // read doesn't block
	tty.c_cc[VTIME] = 0;            // 0 seconds read timeout

	tty.c_iflag &= ~(IXON | IXOFF | IXANY); // shut off xon/xoff ctrl

	tty.c_cflag |= (CLOCAL | CREAD);// ignore modem controls,
									// enable reading
	tty.c_cflag &= ~(PARENB | PARODD);      // shut off parity
	tty.c_cflag |= parity;
	tty.c_cflag &= ~CSTOPB;
	tty.c_cflag &= ~CRTSCTS;

	if (tcsetattr (fd, TCSANOW, &tty) != 0)
		perror("Can't set serial line attributes");
}