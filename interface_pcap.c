/*
 * This file is part of Foren6, a 6LoWPAN Diagnosis Tool
 * Copyright (C) 2013, CETIC
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 *
 */

/**
 * \file
 *         PCAP input interface
 * \author
 *         Foren6 Team <foren6@cetic.be>
 */

// _GNU_SOURCE needed for some pthread functions
#define _GNU_SOURCE
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

#ifndef DLT_IEEE802_15_4_NOFCS
#define DLT_IEEE802_15_4_NOFCS 230
#endif

static const char *interface_name = "pcap";
static const unsigned int interface_parameters = INTERFACE_DEVICE;

typedef struct {
    FILE *pf;
    pcap_t *pc;
    bool capture_packets;
    pthread_t thread;
    long first_offset;
} interface_handle_t;           //*ifreader_t

static void interface_init();
static ifreader_t interface_open(const char *target, int channel, int baudrate);
static bool interface_start(ifreader_t handle);
static void interface_stop(ifreader_t handle);
static void interface_close(ifreader_t handle);
static void *interface_thread_process_input(void *data);
static void interface_packet_handler(u_char * param,
                                     const struct pcap_pkthdr *header,
                                     const u_char * pkt_data);

int
interface_get_version()
{
    return 1;
}

interface_t
interface_register()
{
    interface_t interface;

    memset(&interface, 0, sizeof(interface));

    interface.interface_name = interface_name;
    interface.parameters = interface_parameters;
    interface.init = &interface_init;
    interface.open = &interface_open;
    interface.close = &interface_close;
    interface.start = &interface_start;
    interface.stop = &interface_stop;

    return interface;
}

static void
interface_init()
{
    fprintf(stderr, "%s interface initialized\n", interface_name);
}

static ifreader_t
interface_open(const char *target, int channel, int baudrate)
{
    interface_handle_t *handle;
    char errbuf[PCAP_ERRBUF_SIZE];

    (void) channel;
    (void) baudrate;

    handle = (interface_handle_t *) calloc(1, sizeof(interface_handle_t));
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

    if (pcap_datalink(handle->pc) == DLT_EN10MB || pcap_datalink(handle->pc) == DLT_LINUX_SLL) {
        instance->encap_dlt = pcap_datalink(handle->pc);
    } else if(pcap_datalink(handle->pc) == DLT_IEEE802_15_4) {
        instance->encap_dlt = -1;
        instance->fcs = true;
    } else if (pcap_datalink(handle->pc) == DLT_IEEE802_15_4_NOFCS) {
        instance->encap_dlt = -1;
        instance->fcs = false;
    } else {
        fprintf(stderr,
                "This program only supports 802.15.4 and Ethernet or Linux \"cooked\" "
                "encapsulated 802.15.4 sniffers (DLT: %d)\n",
                pcap_datalink(handle->pc));
        interfacemgr_destroy_handle(instance);
        free(handle);
        return NULL;
    }
    handle->first_offset = ftell(handle->pf);
    return instance;
}

static bool
interface_start(ifreader_t handle)
{
    interface_handle_t *descriptor = handle->interface_data;

    if(descriptor->capture_packets == false) {
        descriptor->capture_packets = true;
        if(fseek(descriptor->pf, descriptor->first_offset, SEEK_SET) == -1) {
            fprintf(stderr, "warning, fseek() failed : %s\n", strerror(errno));
        }
        pthread_create(&descriptor->thread, NULL, &interface_thread_process_input, handle);
    }
    return true;
}

static void
interface_stop(ifreader_t handle)
{
    interface_handle_t *descriptor = handle->interface_data;

    if(descriptor->capture_packets == true) {
        struct timespec timeout = { 3, 0 };

        descriptor->capture_packets = false;

        if(pthread_timedjoin_np(descriptor->thread, NULL, &timeout) != 0) {
            pthread_cancel(descriptor->thread);
            pthread_join(descriptor->thread, NULL);
        }
    }
}

static void
interface_close(ifreader_t handle)
{
    interface_handle_t *descriptor = handle->interface_data;

    interface_stop(handle);

    pcap_close(descriptor->pc);
    free(descriptor);
    interfacemgr_destroy_handle(handle);
}

static void *
interface_thread_process_input(void *data)
{
    ifreader_t handle = (ifreader_t) data;
    interface_handle_t *descriptor = handle->interface_data;
    int pcap_result;
    int counter = 0;

    fprintf(stderr, "PCAP reader started\n");

    while(1) {
        pcap_result = pcap_dispatch(descriptor->pc, 1, &interface_packet_handler, (u_char *) handle);
        if(!descriptor->capture_packets || pcap_result < 0) {
            fprintf(stderr, "PCAP reader stopped\n");
            pcap_perror(descriptor->pc, "PCAP end result");
            return NULL;
        }
        if(pcap_result == 0) {
            usleep(100000);
        } else {
            counter++;
            if(counter % 100 == 0)
                usleep(1000);
        }
    }
}

inline int _get_encap_header_size(int encap_dlt) {
    switch (encap_dlt) {
        case DLT_EN10MB:
            return 14;
        case DLT_LINUX_SLL:
            return 16;
        default:
            return 0;
    }
}

/* Stolen from wireshark */
typedef unsigned short uint16;
static const uint16 crc16_ccitt_table_reverse[256] =
{
    0x0000, 0x1189, 0x2312, 0x329B, 0x4624, 0x57AD, 0x6536, 0x74BF,
    0x8C48, 0x9DC1, 0xAF5A, 0xBED3, 0xCA6C, 0xDBE5, 0xE97E, 0xF8F7,
    0x1081, 0x0108, 0x3393, 0x221A, 0x56A5, 0x472C, 0x75B7, 0x643E,
    0x9CC9, 0x8D40, 0xBFDB, 0xAE52, 0xDAED, 0xCB64, 0xF9FF, 0xE876,
    0x2102, 0x308B, 0x0210, 0x1399, 0x6726, 0x76AF, 0x4434, 0x55BD,
    0xAD4A, 0xBCC3, 0x8E58, 0x9FD1, 0xEB6E, 0xFAE7, 0xC87C, 0xD9F5,
    0x3183, 0x200A, 0x1291, 0x0318, 0x77A7, 0x662E, 0x54B5, 0x453C,
    0xBDCB, 0xAC42, 0x9ED9, 0x8F50, 0xFBEF, 0xEA66, 0xD8FD, 0xC974,
    0x4204, 0x538D, 0x6116, 0x709F, 0x0420, 0x15A9, 0x2732, 0x36BB,
    0xCE4C, 0xDFC5, 0xED5E, 0xFCD7, 0x8868, 0x99E1, 0xAB7A, 0xBAF3,
    0x5285, 0x430C, 0x7197, 0x601E, 0x14A1, 0x0528, 0x37B3, 0x263A,
    0xDECD, 0xCF44, 0xFDDF, 0xEC56, 0x98E9, 0x8960, 0xBBFB, 0xAA72,
    0x6306, 0x728F, 0x4014, 0x519D, 0x2522, 0x34AB, 0x0630, 0x17B9,
    0xEF4E, 0xFEC7, 0xCC5C, 0xDDD5, 0xA96A, 0xB8E3, 0x8A78, 0x9BF1,
    0x7387, 0x620E, 0x5095, 0x411C, 0x35A3, 0x242A, 0x16B1, 0x0738,
    0xFFCF, 0xEE46, 0xDCDD, 0xCD54, 0xB9EB, 0xA862, 0x9AF9, 0x8B70,
    0x8408, 0x9581, 0xA71A, 0xB693, 0xC22C, 0xD3A5, 0xE13E, 0xF0B7,
    0x0840, 0x19C9, 0x2B52, 0x3ADB, 0x4E64, 0x5FED, 0x6D76, 0x7CFF,
    0x9489, 0x8500, 0xB79B, 0xA612, 0xD2AD, 0xC324, 0xF1BF, 0xE036,
    0x18C1, 0x0948, 0x3BD3, 0x2A5A, 0x5EE5, 0x4F6C, 0x7DF7, 0x6C7E,
    0xA50A, 0xB483, 0x8618, 0x9791, 0xE32E, 0xF2A7, 0xC03C, 0xD1B5,
    0x2942, 0x38CB, 0x0A50, 0x1BD9, 0x6F66, 0x7EEF, 0x4C74, 0x5DFD,
    0xB58B, 0xA402, 0x9699, 0x8710, 0xF3AF, 0xE226, 0xD0BD, 0xC134,
    0x39C3, 0x284A, 0x1AD1, 0x0B58, 0x7FE7, 0x6E6E, 0x5CF5, 0x4D7C,
    0xC60C, 0xD785, 0xE51E, 0xF497, 0x8028, 0x91A1, 0xA33A, 0xB2B3,
    0x4A44, 0x5BCD, 0x6956, 0x78DF, 0x0C60, 0x1DE9, 0x2F72, 0x3EFB,
    0xD68D, 0xC704, 0xF59F, 0xE416, 0x90A9, 0x8120, 0xB3BB, 0xA232,
    0x5AC5, 0x4B4C, 0x79D7, 0x685E, 0x1CE1, 0x0D68, 0x3FF3, 0x2E7A,
    0xE70E, 0xF687, 0xC41C, 0xD595, 0xA12A, 0xB0A3, 0x8238, 0x93B1,
    0x6B46, 0x7ACF, 0x4854, 0x59DD, 0x2D62, 0x3CEB, 0x0E70, 0x1FF9,
    0xF78F, 0xE606, 0xD49D, 0xC514, 0xB1AB, 0xA022, 0x92B9, 0x8330,
    0x7BC7, 0x6A4E, 0x58D5, 0x495C, 0x3DE3, 0x2C6A, 0x1EF1, 0x0F78
};
static const uint16 crc16_ccitt_xorout = 0xFFFF;

static uint16 crc16_reflected(const u_char *buf, size_t len,
                                uint16 crc_in, const uint16 table[])
{
    uint16 crc16 = crc_in;

    while( len-- != 0 )
       crc16 = table[(crc16 ^ *buf++) & 0xff] ^ (crc16 >> 8);

    return crc16;
}
uint16 crc16_ccitt_seed(const u_char *buf, size_t len, uint16 seed)
{
    return crc16_reflected(buf,len,seed,crc16_ccitt_table_reverse)
       ^ crc16_ccitt_xorout;
}

/* Stolen from wireshark */
#define IEEE802154_CRC_SEED     0x0000
#define IEEE802154_CRC_XOROUT   0xFFFF
#define ieee802154_crc(buf, len)   (crc16_ccitt_seed(buf, len, IEEE802154_CRC_SEED) ^ IEEE802154_CRC_XOROUT)


static void
interface_packet_handler(u_char * param, const struct pcap_pkthdr *header, const u_char * pkt_data)
{
    int len;
    ifreader_t descriptor = (ifreader_t) param;
    size_t enc_size = _get_encap_header_size (descriptor->encap_dlt);

    const u_char *pkt_data_802_15_4 = pkt_data + enc_size;


    // Packet consists of header only
    if (header->caplen <= enc_size) {
        return;
    }
    //FCS truncation, if present
    if(descriptor->fcs){
        if (header->caplen <= enc_size + 2) {
            return;
        }
        /* If packet has invalid FCS we continue */
        if (header->caplen == header->len) {
            int fcs = ieee802154_crc
                (pkt_data_802_15_4, header->len - enc_size - 2);
            int fcsh =
                ( (pkt_data_802_15_4 [header->len - 2 - enc_size])
                + (pkt_data_802_15_4 [header->len - 2 + 1 - enc_size] << 8)
                );
            len = header->caplen - 2;
            // Check FCS and only pass on valid frames
            if (fcs != fcsh) {
                return;
            }
            // Special capture format "TC CC24xx": Only uses one bit for
            // correct FCS. No way to distinguish both formats
            // automatically at present.  This format is used by sensniff.
            // Maybe make this a command-line option when parsing pcap
            // files?
//            if ((fcsh & 0x8000) == 0) {
//                return;
//            }
        } else {
            len = header->caplen;
        }
    }
    else{
        len = header->caplen;
    }

    len -= enc_size;
    switch (descriptor->encap_dlt) {
        case DLT_EN10MB:
            if (pkt_data[12] != 0x80 || pkt_data[13] != 0x9a) {
                return;
            }
            break;
        case DLT_LINUX_SLL:
            if (pkt_data[15] != 0xf6) {
                return;
            }
            break;
    }
    interfacemgr_process_packet(descriptor, pkt_data_802_15_4, len, header->ts);
}
