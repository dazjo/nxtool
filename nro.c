#include <stdbool.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>

#include "types.h"
#include "nro.h"
#include "nx.h"
#include "utils.h"
#include <inttypes.h>

void nro_init(nro_context* ctx)
{
	memset(ctx, 0, sizeof(nro_context));
}

void nro_set_file(nro_context* ctx, FILE* file)
{
	ctx->file = file;
}

void nro_set_name(nro_context* ctx, const char* name)
{
	ctx->name = name;
}

void nro_set_buffer(nro_context* ctx, u8* buffer)
{
	ctx->buffer = buffer;
}

void nro_set_offset(nro_context* ctx, u64 offset)
{
	ctx->offset = offset;
}

void nro_set_size(nro_context* ctx, u64 size)
{
	ctx->size = size;
}

void nro_set_usersettings(nro_context* ctx, settings* usersettings)
{
	ctx->usersettings = usersettings;
}

void nro_read(nro_context* ctx, u32 actions)
{
	if (ctx->haveread == 0)
	{
		if (!ctx->buffer)
		{
			ctx->buffer = malloc(ctx->size);
			if (!ctx->buffer) return;

			fseeko64(ctx->file, ctx->offset, SEEK_SET);
			fread(ctx->buffer, ctx->size, 1, ctx->file);
		}

		ctx->header = (nro_header*)(ctx->buffer + sizeof(nro_start));
		nro_header* header = ctx->header;

		ctx->module_size = getle32(header->data_memoffset) + getle32(header->data_size) + getle32(header->bss_size);
		if (ctx->module_size - getle32(header->bss_size) <= ctx->size)
		{
			ctx->module = malloc(ctx->module_size);
			if (!ctx->module) return;
			memset(ctx->module, 0, ctx->module_size);

			ctx->text = ctx->module + getle32(header->text_memoffset);
			ctx->ro = ctx->module + getle32(header->ro_memoffset);
			ctx->data = ctx->module + getle32(header->data_memoffset);

			memcpy(ctx->module, ctx->buffer, getle32(header->data_memoffset) + getle32(header->data_size));
		}

		ctx->haveread = 1;
	}
}

int nro_process(nro_context* ctx, u32 actions)
{
	nro_read(ctx, actions);

	if (actions & InfoFlag)
		nro_print(ctx, actions);

	if (!ctx->module) return 0;

	mod_context mod;
	mod_init(&mod);

	mod_set_buffer(&mod, ctx->module);
	mod_set_size(&mod, ctx->module_size);
	mod_set_name(&mod, ctx->name);
	mod_set_usersettings(&mod, ctx->usersettings);

	nro_header* header = ctx->header;
	nro_start* start = (nro_start*)ctx->buffer;
	mod_meta meta = {
		.mod_offset = getle32(start->module_memoffset),
		.text_offset = getle32(header->text_memoffset),
		.text_size = getle32(header->text_size),
		.ro_offset = getle32(header->ro_memoffset),
		.ro_size = getle32(header->ro_size),
		.data_offset = getle32(header->data_memoffset),
		.data_size = getle32(header->data_size),
		.bss_size = getle32(header->bss_size),
	};
	mod_set_meta(&mod, &meta);

	mod_process(&mod, actions);

	if (ctx->buffer && ctx->file)
	{
		free(ctx->buffer);
		ctx->buffer = NULL;
	}

	free(ctx->module);
	ctx->module = NULL;

	return 1;
}

void nro_print(nro_context* ctx, u32 actions)
{
	nro_header* header = ctx->header;

	if (ctx->module_size - getle32(header->bss_size) > ctx->size)
		fprintf(stdout, "Warning: NRO binary is incomplete. 0x%"PRIX64" bytes missing.\n", (ctx->module_size - getle32(header->bss_size)) - ctx->size);

	fprintf(stdout, "\nNRO %s:\n\n", ctx->name);

	fprintf(stdout, "Header:                 %.4s\n", header->magic);
	fprintf(stdout, "Size:                   0x%"PRIX32" bytes\n", getle32(header->size));

	fprintf(stdout, "\nSegments:\n");
	fprintf(stdout, " > .text:               0x%08"PRIX32" (0x%"PRIX32" bytes)\n", getle32(header->text_memoffset), getle32(header->text_size));
	fprintf(stdout, " > .rodata:             0x%08"PRIX32" (0x%"PRIX32" bytes)\n", getle32(header->ro_memoffset), getle32(header->ro_size));
	fprintf(stdout, " > .data:               0x%08"PRIX32" (0x%"PRIX32" bytes)\n", getle32(header->data_memoffset), getle32(header->data_size));
	fprintf(stdout, " > .bss:                0x%08"PRIX32" (0x%"PRIX32" bytes)\n\n", getle32(header->data_memoffset) + getle32(header->data_size), getle32(header->bss_size));

	if (ctx->module)
	{
		u8 hash[0x20] = { 0 };
		nx_sha256(ctx->buffer, getle32(header->size), hash);

		memdump(stdout, "Hash:                   ", hash, sizeof(hash));
	}
}
