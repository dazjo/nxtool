#include <stdbool.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>

#include "types.h"
#include "nrr.h"
#include "nx.h"
#include "utils.h"
#include <inttypes.h>

void nrr_init(nrr_context* ctx)
{
	memset(ctx, 0, sizeof(nrr_context));
}

void nrr_set_file(nrr_context* ctx, FILE* file)
{
	ctx->file = file;
}

void nrr_set_name(nrr_context* ctx, const char* name)
{
	ctx->name = name;
}

void nrr_set_buffer(nrr_context* ctx, u8* buffer)
{
	ctx->buffer = buffer;
}

void nrr_set_offset(nrr_context* ctx, u64 offset)
{
	ctx->offset = offset;
}

void nrr_set_size(nrr_context* ctx, u64 size)
{
	ctx->size = size;
}

void nrr_set_usersettings(nrr_context* ctx, settings* usersettings)
{
	ctx->usersettings = usersettings;
}

void nrr_read(nrr_context* ctx, u32 actions)
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

		ctx->header = (nrr_header*)ctx->buffer;

		ctx->haveread = 1;
	}
}

void nrr_verify(nrr_context* ctx, u32 actions)
{
	nrr_header* header = ctx->header;

	u8 hash[0x20] = { 0 };

	rsakey* key1 = settings_get_nrrrsakey(ctx->usersettings);
	if (!key1) fprintf(stdout, "Warning: NRR RSA key missing. Cannot verify main signature.\n");

	rsakey key2;
	nx_rsa_init_key_pubmodulus(&key2, header->modulus, RSASIZE_2048);

	if (key1)
	{
		nx_sha256(ctx->buffer + offsetof(nrr_header, titleid_mask), offsetof(nrr_header, start_signature) - offsetof(nrr_header, titleid_mask), hash);
		ctx->sigcheck[0] = nx_rsa_verify_hash(header->start_signature, hash, key1, MBEDTLS_RSA_PKCS_V21);
	}

	nx_sha256(ctx->buffer + offsetof(nrr_header, titleid), getle32(header->size) - offsetof(nrr_header, titleid), hash);
	ctx->sigcheck[1] = nx_rsa_verify_hash(header->end_signature, hash, &key2, MBEDTLS_RSA_PKCS_V21);
}

int nrr_process(nrr_context* ctx, u32 actions)
{
	nrr_read(ctx, actions);

	if (actions & VerifyFlag)
		nrr_verify(ctx, actions);

	if (actions & InfoFlag)
		nrr_print(ctx, actions);

	if (ctx->buffer && ctx->file)
	{
		free(ctx->buffer);
		ctx->buffer = NULL;
	}

	return 1;
}

void nrr_print(nrr_context* ctx, u32 actions)
{
	nrr_header* header = ctx->header;

	fprintf(stdout, "\nNRR %s:\n\n", ctx->name);

	fprintf(stdout, "Header:                 %.4s\n", header->magic);

	if (ctx->sigcheck[0] == Unchecked)
		memdump(stdout, "Main signature:         ", header->start_signature, sizeof(header->start_signature));
	else if (ctx->sigcheck[0] == Good)
		memdump(stdout, "Main signature (GOOD):  ", header->start_signature, sizeof(header->start_signature));
	else if (ctx->sigcheck[0] == Fail)
		memdump(stdout, "Main signature (FAIL):  ", header->start_signature, sizeof(header->start_signature));

	memdump(stdout, "Modulus:                ", header->modulus, sizeof(header->modulus));

	fprintf(stdout, "\nTitle ID mask:          %016"PRIX64"\n", getle64(header->titleid_mask));
	fprintf(stdout, "Title ID pattern:       %016"PRIX64"\n\n", getle64(header->titleid_pattern));

	if (ctx->sigcheck[1] == Unchecked)
		memdump(stdout, "Sub signature:          ", header->end_signature, sizeof(header->end_signature));
	else if (ctx->sigcheck[1] == Good)
		memdump(stdout, "Sub signature (GOOD):   ", header->end_signature, sizeof(header->end_signature));
	else if (ctx->sigcheck[1] == Fail)
		memdump(stdout, "Sub signature (FAIL):   ", header->end_signature, sizeof(header->end_signature));


	fprintf(stdout, "\nTitle ID:               %016"PRIX64"\n", getle64(header->titleid));
	fprintf(stdout, "Size:                   0x%"PRIX32"\n", getle32(header->size));
	

	fprintf(stdout, "\nHash count:             %d\n", getle32(header->hash_count));
	u8* hash = ctx->buffer + getle32(header->hash_offset);
	for (int i = 0; i < getle32(header->hash_count); i++)
	{
		fprintf(stdout, " > Hash %d:              ", i);
		memdump(stdout, "", hash, 0x20);
		hash += 0x20;
	}
}
