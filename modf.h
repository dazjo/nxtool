#ifndef _MODF_H_
#define _MODF_H_

#include <stdio.h>
#include "types.h"
#include "settings.h"

#include "mod.h"

typedef struct {
	u8 branch[4];
	u8 module_memoffset[4];
} modf_start;

typedef struct
{
	int haveread;
	FILE* file;
	const char* name;
	u8* buffer;
	settings* usersettings;
	u64 offset;
	u64 size;
	mod_header* mod;
	mod_meta meta;
	u8* module;
	u32 module_size;
	u8* text;
	u8* ro;
	u8* data;
} modf_context;

void modf_init(modf_context* ctx);
void modf_set_file(modf_context* ctx, FILE* file);
void modf_set_name(modf_context* ctx, const char* name);
void modf_set_buffer(modf_context* ctx, u8* buffer);
void modf_set_offset(modf_context* ctx, u64 offset);
void modf_set_size(modf_context* ctx, u64 size);
void modf_set_usersettings(modf_context* ctx, settings* usersettings);
void modf_read(modf_context* ctx, u32 actions);
int modf_process(modf_context* ctx, u32 actions);
void modf_print(modf_context* ctx, u32 actions);

#endif // _MODF_H_
