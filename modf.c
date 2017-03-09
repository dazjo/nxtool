#include <stdbool.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>

#include "types.h"
#include "modf.h"
#include "nx.h"
#include "utils.h"
#include <inttypes.h>

void modf_init(modf_context* ctx)
{
	memset(ctx, 0, sizeof(modf_context));
}

void modf_set_file(modf_context* ctx, FILE* file)
{
	ctx->file = file;
}

void modf_set_name(modf_context* ctx, const char* name)
{
	ctx->name = name;
}

void modf_set_buffer(modf_context* ctx, u8* buffer)
{
	ctx->buffer = buffer;
}

void modf_set_offset(modf_context* ctx, u64 offset)
{
	ctx->offset = offset;
}

void modf_set_size(modf_context* ctx, u64 size)
{
	ctx->size = size;
}

void modf_set_usersettings(modf_context* ctx, settings* usersettings)
{
	ctx->usersettings = usersettings;
}

void modf_read(modf_context* ctx, u32 actions)
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

		modf_start* start = (modf_start*)ctx->buffer;
		u32 mod_offset = getle32(start->module_memoffset);
		if (mod_offset + sizeof(mod_header) > ctx->size) return;

		mod_header* mod = (mod_header*)(ctx->buffer + mod_offset);
		if (memcmp(mod->magic, "MOD", 3) != 0) return;

		ctx->mod = mod;

		mod_context mod_discover;
		mod_init(&mod_discover);

		mod_set_buffer(&mod_discover, ctx->buffer);
		mod_set_size(&mod_discover, ctx->size);
		mod_set_name(&mod_discover, ctx->name);
		mod_set_usersettings(&mod_discover, ctx->usersettings);

		memset(&ctx->meta, 0, sizeof(ctx->meta));
		ctx->meta.mod_offset = getle32(start->module_memoffset);

		mod_set_meta(&mod_discover, &ctx->meta);
		mod_set_discover(&mod_discover, true);

		mod_process(&mod_discover, actions);

		ctx->module_size = ctx->size;
		ctx->module = ctx->buffer;

		ctx->text = ctx->buffer + ctx->meta.text_offset;
		ctx->ro = ctx->buffer + ctx->meta.ro_offset;
		ctx->data = ctx->buffer + ctx->meta.data_offset;

		ctx->haveread = 1;
	}
}

int modf_process(modf_context* ctx, u32 actions)
{
	modf_read(ctx, actions);
	if (!ctx->module) return 0;

	if (actions & InfoFlag)
		modf_print(ctx, actions);

	mod_context mod;
	mod_init(&mod);

	mod_set_buffer(&mod, ctx->module);
	mod_set_size(&mod, ctx->module_size);
	mod_set_name(&mod, ctx->name);
	mod_set_usersettings(&mod, ctx->usersettings);

	mod_set_meta(&mod, &ctx->meta);

	mod_process(&mod, actions);

	if (ctx->buffer && ctx->file)
	{
		free(ctx->buffer);
		ctx->buffer = NULL;
	}

	return 1;
}

void modf_print(modf_context* ctx, u32 actions)
{
	mod_header* mod = ctx->mod;

	fprintf(stdout, "\nMOD (dump) %s:\n\n", ctx->name);

	fprintf(stdout, "Header:                 %.4s\n", mod->magic);

	fprintf(stdout, "\nSegments:\n");
	fprintf(stdout, " > .text:               0x%08"PRIX32" (0x%"PRIX32" bytes)\n", ctx->meta.text_offset, ctx->meta.text_size);
	fprintf(stdout, " > .rodata:             0x%08"PRIX32" (0x%"PRIX32" bytes)\n", ctx->meta.ro_offset, ctx->meta.ro_size);
	fprintf(stdout, " > .data:               0x%08"PRIX32" (0x%"PRIX32" bytes)\n", ctx->meta.data_offset, ctx->meta.data_size);
	fprintf(stdout, " > .bss:                0x%08"PRIX32" (0x%"PRIX32" bytes)\n\n", ctx->meta.data_offset + ctx->meta.data_size, ctx->meta.bss_size);
}
