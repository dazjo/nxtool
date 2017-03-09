#ifndef _NRR_H_
#define _NRR_H_

#include <stdio.h>
#include "types.h"
#include "settings.h"

typedef struct {
	u8 magic[4];
	u8 reserved1[28];
	u8 titleid_mask[8];
	u8 titleid_pattern[8];
	u8 modulus[0x100];
	u8 start_signature[0x100];
	u8 end_signature[0x100];
	u8 titleid[8];
	u8 size[4];
	u8 reserved3[4];
	u8 hash_offset[4];
	u8 hash_count[4];
	u8 reserved4[8];
} nrr_header;

typedef struct
{
	int haveread;
	FILE* file;
	const char* name;
	u8* buffer;
	settings* usersettings;
	u64 offset;
	u64 size;
	nrr_header* header;
	int sigcheck[2];
} nrr_context;

void nrr_init(nrr_context* ctx);
void nrr_set_file(nrr_context* ctx, FILE* file);
void nrr_set_name(nrr_context* ctx, const char* name);
void nrr_set_buffer(nrr_context* ctx, u8* buffer);
void nrr_set_offset(nrr_context* ctx, u64 offset);
void nrr_set_size(nrr_context* ctx, u64 size);
void nrr_set_usersettings(nrr_context* ctx, settings* usersettings);
void nrr_read(nrr_context* ctx, u32 actions);
int nrr_process(nrr_context* ctx, u32 actions);
void nrr_print(nrr_context* ctx, u32 actions);
void nrr_verify(nrr_context* ctx, u32 actions);

#endif // _NRR_H_