#include "interface_telos.h"

#include <circular_buffer.h>
#include <sniffer_packet_parser.h>
#include <descriptor_poll.h>

#include <stdio.h>
#include <fcntl.h>
#include <termios.h>
#include <string.h>
#include <unistd.h>

static const char expected_magic[4] = "SNIF";
static const unsigned char enable_sniffer_cmd[3] = { 0xFA, 0x3A, '\n' };

#define FIELD_CRC        1
#define FIELD_CRC_OK     2
#define FIELD_RSSI       4
#define FIELD_LQI        8
#define FIELD_TIMESTAMP 16
	
static circular_buffer_t input_buffer;
static int serial_line;

static void sniffer_interface_init(const char* interface_name);
static void process_input(int fd);
static bool read_input(int file);
static bool can_read_byte();
static unsigned char get_byte();
static void set_serial_attribs(int fd, int baudrate, int parity);

interface_t interface_register() {
	interface_t interface;
	
	interface.interface_name = "telos";
	interface.init = &sniffer_interface_init;
	
	return interface;
}

static void sniffer_interface_init(const char* interface_name) {
	fprintf(stderr, "Opening %s\n", interface_name);
	if((serial_line = open(interface_name, O_RDWR | O_NOCTTY | O_SYNC)) < 0) {
		perror("Cannot open interface");
		return;
	}
	
	set_serial_attribs(serial_line, B115200, 0);
	
	write(serial_line, enable_sniffer_cmd, 3);	//Enable sniffer

	input_buffer = circular_buffer_create(32, 1);
	if(input_buffer == NULL)
		fprintf(stderr, "FATAL: can't allocate input buffer\n");
	
	desc_poll_add(serial_line, &process_input);
}

static void process_input(int fd) {
	static char           pkt_magic[4];
	static unsigned char  pkt_type;
	static unsigned char  pkt_len;
	static unsigned char  pkt_data[256];
	static unsigned short pkt_crc;
	static unsigned char  pkt_crc_ok;
	static unsigned char  pkt_rssi;
	static unsigned char  pkt_lqi;
	static unsigned short pkt_timestamp;

	static int pkt_received_index;
	

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

	static packet_read_state_e current_state = PRS_Magic;
	static packet_read_state_e last_state = PRS_Done;
	static packet_read_state_e before_switch_state;
	
	//Pars input until there is no more data to parse
	do {
		
/*
		if(last_state != current_state)
			fprintf(stderr, "state changed, %d -> %d\n", last_state, current_state);
*/

		before_switch_state = current_state;
	
		//Read input until our buffer is full or there is no more data to read
		while(read_input(serial_line) == true);

		switch(current_state) {
			case PRS_Magic:
				if(last_state != current_state)
					pkt_received_index = 0;

				if(can_read_byte())
					pkt_magic[pkt_received_index] = get_byte(serial_line);
				else break;

				if(pkt_magic[pkt_received_index] != expected_magic[pkt_received_index])
					pkt_received_index = 0;  //Invalid magic number -> reset received packet getByte(serial_line) until we have a "SNIF"
				else pkt_received_index++;

				if(pkt_received_index >= 4)
					current_state = PRS_Type;
				break;

			case PRS_Type:
				if(can_read_byte())
					pkt_type = get_byte(serial_line);
				else break;

				current_state = PRS_Len;
				break;

			case PRS_Len:
				if(can_read_byte())
					pkt_len = get_byte(serial_line);
				else break;

				current_state = PRS_Data;
				break;

			case PRS_Data:
				if(last_state != current_state)
					pkt_received_index = 0;

				if(pkt_received_index >= pkt_len)
					current_state = PRS_Crc;
				else {
					if(can_read_byte())
						pkt_data[pkt_received_index] = get_byte(serial_line);
					else break;

					pkt_received_index++;
				}
				break;

			case PRS_Crc:
				if(pkt_type & FIELD_CRC) {
					if(last_state != current_state) {
						pkt_received_index = 0;
						pkt_crc = 0;
					}

					if(can_read_byte())
						pkt_crc |= (uint16_t) get_byte(serial_line) << (8*pkt_received_index);
					else break;

					pkt_received_index++;

					if(pkt_received_index >= 2)
						current_state = PRS_CrcOk;
				} else {
					current_state = PRS_CrcOk;
				}
				break;

			case PRS_CrcOk:
				if(pkt_type & FIELD_CRC_OK) {
					if(can_read_byte())
						pkt_crc_ok = get_byte(serial_line);
					else break;
				} else {
					pkt_crc_ok = 1;
				}
				current_state = PRS_Rssi;
				break;

			case PRS_Rssi:
				if(pkt_type & FIELD_RSSI) {
					if(can_read_byte())
						pkt_rssi = get_byte(serial_line);
					else break;
				}
				current_state = PRS_Lqi;
				break;

			case PRS_Lqi:
				if(pkt_type & FIELD_LQI) {
					if(can_read_byte())
						pkt_lqi = get_byte(serial_line);
					else break;
				}
				current_state = PRS_TimeStamp;
				break;

			case PRS_TimeStamp:
				if(pkt_type & FIELD_TIMESTAMP) {
					if(last_state != current_state) {
						pkt_received_index = 0;
						pkt_timestamp = 0;
					}

					if(can_read_byte())
						pkt_timestamp |= get_byte(serial_line) << (8*pkt_received_index);
					else break;

					pkt_received_index++;

					if(pkt_received_index >= 2)
						current_state = PRS_Done;
				} else {
					current_state = PRS_Done;
				}
				break;

			case PRS_Done:
				if(pkt_len > 0 && pkt_crc_ok) {      //Discard bad packet and packet without data captured
					sniffer_parser_parse_data(pkt_data, pkt_len);
				}
				current_state = PRS_Magic;
				break;
		}

		last_state = before_switch_state;
	} while(can_read_byte());
}

static bool read_input(int file) {
	unsigned char data;

	if(!circular_buffer_is_full(input_buffer) && (read(file, &data, 1) == 1)) {
		//fprintf(stderr, "Received data 0x%02X\n", data);
		circular_buffer_push_front(input_buffer, &data);
		return true;
	}

	return false;
}

static bool can_read_byte() {
	return !circular_buffer_is_empty(input_buffer);
}

static unsigned char get_byte() {
	unsigned char *data;
	
	data = (unsigned char*) circular_buffer_pop_back(input_buffer);
	
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