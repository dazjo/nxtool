#ifndef _MOD_H_
#define _MOD_H_

#include <stdio.h>
#include "types.h"
#include "settings.h"

#ifdef __cplusplus
extern "C" {
#endif

typedef struct
{
	u8 magic[4];
	u8 dynamic[4];
	u8 bss_start[4];
	u8 bss_end[4];
	u8 unwind_start[4];
	u8 unwind_end[4];
	u8 mod_object[4];
} mod_header;

typedef struct {
	u8 next[8];
	u8 prev[8];
	u8 relplt[8];
	u8 reldyn[8];
	u8 base[8];
	u8 dynamic[8];
	u8 is_rela[8];
	u8 relplt_size[8];
	u8 init[8];
	u8 fini[8];
	u8 bucket[8];
	u8 chain[8];
	u8 strtab[8];
	u8 symtab[8];
	u8 strtab_size[8];
	u8 got[8];
	u8 reladyn_size[8];
	u8 reldyn_size[8];
	u8 relcount[8];
	u8 relacount[8];
	u8 nchain[8];
	u8 nbucket[8];
	u8 got_value[8];
} mod_object;

typedef struct {
	s32 mod_offset;
	s32 text_offset;
	s32 text_size;
	s32 ro_offset;
	s32 ro_size;
	s32 data_offset;
	s32 data_size;
	s32 bss_size;
} mod_meta;

typedef struct
{
	int haveread;
	const char* name;
	u8* buffer;
	settings* usersettings;
	void* elf;
	u64 size;
	int discover;
	mod_meta* meta;
	mod_header* header;
	u8* text;
	u8* ro;
	u8* data;
	u8* dynamic;
} mod_context;

void mod_init(mod_context* ctx);
void mod_set_name(mod_context* ctx, const char* name);
void mod_set_header(mod_context* ctx, mod_header* header);
void mod_set_meta(mod_context* ctx, mod_meta* meta);
void mod_set_buffer(mod_context* ctx, u8* buffer);
void mod_set_size(mod_context* ctx, u64 size);
void mod_set_usersettings(mod_context* ctx, settings* usersettings);
void mod_set_discover(mod_context* ctx, int discover);
void mod_read(mod_context* ctx, u32 actions);
int mod_process(mod_context* ctx, u32 actions);
void mod_print(mod_context* ctx, u32 actions);

#ifdef __cplusplus
}
#endif

#endif // _MOD_H_