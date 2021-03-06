#ifndef __AHCI_FIS_H__
#define __AHCI_FIS_H__

#include <stdint.h>
#include <stddef.h>

enum fis_type {
    FIS_TYPE_REG_H2D	= 0x27,
    FIS_TYPE_REG_D2H	= 0x34,
    FIS_TYPE_DMA_ACT	= 0x39,
    FIS_TYPE_DMA_SETUP	= 0x41,
    FIS_TYPE_DATA		= 0x46,
    FIS_TYPE_BIST		= 0x58,    
    FIS_TYPE_PIO_SETUP	= 0x5F,	
    FIS_TYPE_DEV_BITS	= 0xA1,
};

struct fis_regh2d_t {
    uint8_t  fis_type;
    uint8_t  pmport:4;
    uint8_t  rsv0:3;		// Reserved
    uint8_t  c:1;		// 1: Command, 0: Control
    uint8_t  command;	// Command register
    uint8_t  featurel;	// Feature register, 7:0
    uint8_t  lba0;		// LBA low register, 7:0
    uint8_t  lba1;		// LBA mid register, 15:8
    uint8_t  lba2;		// LBA high register, 23:16
    uint8_t  device;		// Device register

    // DWORD 2
    uint8_t  lba3;		// LBA register, 31:24
    uint8_t  lba4;		// LBA register, 39:32
    uint8_t  lba5;		// LBA register, 47:40
    uint8_t  featureh;	// Feature register, 15:8

    // DWORD 3
    uint8_t  countl;		// Count register, 7:0
    uint8_t  counth;		// Count register, 15:8
    uint8_t  icc;		// Isochronous command completion
    uint8_t  control;	// Control register

    // DWORD 4
    uint8_t  rsv1[4];	// Reserved
};

struct fis_regd2h_t {
    // DWORD 0
    uint8_t  fis_type;    // FIS_TYPE_REG_D2H

    uint8_t  pmport:4;    // Port multiplier
    uint8_t  rsv0:2;      // Reserved
    uint8_t  i:1;         // Interrupt bit
    uint8_t  rsv1:1;      // Reserved

    uint8_t  status;      // Status register
    uint8_t  error;       // Error register

    // DWORD 1
    uint8_t  lba0;        // LBA low register, 7:0
    uint8_t  lba1;        // LBA mid register, 15:8
    uint8_t  lba2;        // LBA high register, 23:16
    uint8_t  device;      // Device register

    // DWORD 2
    uint8_t  lba3;        // LBA register, 31:24
    uint8_t  lba4;        // LBA register, 39:32
    uint8_t  lba5;        // LBA register, 47:40
    uint8_t  rsv2;        // Reserved

    // DWORD 3
    uint8_t  countl;      // Count register, 7:0
    uint8_t  counth;      // Count register, 15:8
    uint8_t  rsv3[2];     // Reserved

    // DWORD 4
    uint8_t  rsv4[4];     // Reserved
};

struct fis_data_t {
    // DWORD 0
    uint8_t  fis_type;	// FIS_TYPE_DATA

    uint8_t  pmport:4;	// Port multiplier
    uint8_t  rsv0:4;		// Reserved

    uint8_t  rsv1[2];	// Reserved

    // DWORD 1 ~ N
    uint32_t data[1];	// Payload
};

struct fis_pio_setup_t {
    // DWORD 0
    uint8_t  fis_type;	// FIS_TYPE_PIO_SETUP

    uint8_t  pmport:4;	// Port multiplier
    uint8_t  rsv0:1;		// Reserved
    uint8_t  d:1;		// Data transfer direction, 1 - device to host
    uint8_t  i:1;		// Interrupt bit
    uint8_t  rsv1:1;

    uint8_t  status;		// Status register
    uint8_t  error;		// Error register

    // DWORD 1
    uint8_t  lba0;		// LBA low register, 7:0
    uint8_t  lba1;		// LBA mid register, 15:8
    uint8_t  lba2;		// LBA high register, 23:16
    uint8_t  device;		// Device register

    // DWORD 2
    uint8_t  lba3;		// LBA register, 31:24
    uint8_t  lba4;		// LBA register, 39:32
    uint8_t  lba5;		// LBA register, 47:40
    uint8_t  rsv2;		// Reserved

    // DWORD 3
    uint8_t  countl;		// Count register, 7:0
    uint8_t  counth;		// Count register, 15:8
    uint8_t  rsv3;		// Reserved
    uint8_t  e_status;	// New value of status register

    // DWORD 4
    uint16_t tc;		// Transfer count
    uint8_t  rsv4[2];	// Reserved
};

struct fis_data_setup_t {
    uint8_t  fis_type;
    uint8_t  pmport : 4;
    uint8_t  rsvd0 : 1;
    uint8_t  d : 1;
    uint8_t  i : 1;
    uint8_t  a : 1;
    uint8_t  rsvd1[2];
    uint64_t dma_buffer_id;
    uint32_t rsvd2;
    uint32_t dma_buf_offset;
    uint32_t transfer_count;
    uint32_t rsvd3;
}; 

#endif
