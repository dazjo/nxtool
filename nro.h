#ifndef _NRO_H_
#define _NRO_H_

#include <stdio.h>
#include "types.h"
#include "settings.h"

#include "mod.h"

typedef struct {
	u8 magic[4];
	u8 unknown1[4];
	u8 size[4];
	u8 unknown2[4];
	u8 text_memoffset[4];
	u8 text_size[4];
	u8 ro_memoffset[4];
	u8 ro_size[4];
	u8 data_memoffset[4];
	u8 data_size[4];
	u8 bss_size[4];
	u8 unknown3[72];
} nro_header;

typedef struct {
	u8 unused[4];
	u8 module_memoffset[4];
	u8 padding[8];
} nro_start;

typedef struct
{
	int haveread;
	FILE* file;
	const char* name;
	u8* buffer;
	settings* usersettings;
	u64 offset;
	u64 size;
	nro_header* header;
	u8* module;
	u32 module_size;
	u8* text;
	u8* ro;
	u8* data;
} nro_context;

void nro_init(nro_context* ctx);
void nro_set_file(nro_context* ctx, FILE* file);
void nro_set_name(nro_context* ctx, const char* name);
void nro_set_buffer(nro_context* ctx, u8* buffer);
void nro_set_offset(nro_context* ctx, u64 offset);
void nro_set_size(nro_context* ctx, u64 size);
void nro_set_usersettings(nro_context* ctx, settings* usersettings);
void nro_read(nro_context* ctx, u32 actions);
int nro_process(nro_context* ctx, u32 actions);
void nro_print(nro_context* ctx, u32 actions);

#endif // _NRO_H_