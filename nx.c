#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <time.h>

#include "nx.h"
#include "utils.h"

void nx_set_iv(nx_cbc_context* ctx,
	u8 iv[16])
{
	memcpy(ctx->iv, iv, 16);
}

void nx_init_cbc_encrypt(nx_cbc_context* ctx,
	u8 key[16],
	u8 iv[16])
{
	mbedtls_aes_setkey_enc(&ctx->aes, key, 128);
	nx_set_iv(ctx, iv);
}

void nx_init_cbc_decrypt(nx_cbc_context* ctx,
	u8 key[16],
	u8 iv[16])
{
	mbedtls_aes_setkey_dec(&ctx->aes, key, 128);
	nx_set_iv(ctx, iv);
}

void nx_encrypt_cbc(nx_cbc_context* ctx,
	u8* input,
	u8* output,
	u32 size)
{
	mbedtls_aes_crypt_cbc(&ctx->aes, MBEDTLS_AES_ENCRYPT, size, ctx->iv, input, output);
}

void nx_decrypt_cbc(nx_cbc_context* ctx,
	u8* input,
	u8* output,
	u32 size)
{
	mbedtls_aes_crypt_cbc(&ctx->aes, MBEDTLS_AES_DECRYPT, size, ctx->iv, input, output);
}

void nx_add_ctr(nx_ctr_context* ctx,
	u32 block_num)
{
	u32 ctr[4];
	ctr[3] = getbe32(&ctx->ctr[0]);
	ctr[2] = getbe32(&ctx->ctr[4]);
	ctr[1] = getbe32(&ctx->ctr[8]);
	ctr[0] = getbe32(&ctx->ctr[12]);

	for (u32 i = 0; i < 4; i++) {
		u64 total = ctr[i] + block_num;
		// if there wasn't a wrap around, add the two together and exit
		if (total <= 0xffffffff) {
			ctr[i] += block_num;
			break;
		}

		// add the difference
		ctr[i] = (u32)(total - 0x100000000);
		// carry to next word
		block_num = (u32)(total >> 32);
	}

	putbe32(ctx->ctr + 0x00, ctr[3]);
	putbe32(ctx->ctr + 0x04, ctr[2]);
	putbe32(ctx->ctr + 0x08, ctr[1]);
	putbe32(ctx->ctr + 0x0C, ctr[0]);
}

void nx_set_ctr(nx_ctr_context* ctx,
	u8 ctr[16])
{
	memcpy(ctx->ctr, ctr, 16);
}

void nx_init_ctr(nx_ctr_context* ctx,
	u8 key[16], u8 ctr[16])
{
	mbedtls_aes_setkey_enc(&ctx->aes, key, 128);
	if (ctr) nx_set_ctr(ctx, ctr);
}

void nx_crypt_ctr_block(nx_ctr_context* ctx,
	u8 input[16],
	u8 output[16])
{
	int i;
	u8 stream[16];


	mbedtls_aes_crypt_ecb(&ctx->aes, MBEDTLS_AES_ENCRYPT, ctx->ctr, stream);


	if (input)
	{
		for (i = 0; i<16; i++)
		{
			output[i] = stream[i] ^ input[i];
		}
	}
	else
	{
		for (i = 0; i<16; i++)
			output[i] = stream[i];
	}

	nx_add_ctr(ctx, 1);
}


void nx_crypt_ctr(nx_ctr_context* ctx,
	u8* input,
	u8* output,
	u32 size)
{
	u8 stream[16];
	u32 i;

	while (size >= 16)
	{
		nx_crypt_ctr_block(ctx, input, output);

		if (input)
			input += 16;
		if (output)
			output += 16;

		size -= 16;
	}

	if (size)
	{
		memset(stream, 0, 16);
		nx_crypt_ctr_block(ctx, stream, stream);

		if (input)
		{
			for (i = 0; i<size; i++)
				output[i] = input[i] ^ stream[i];
		}
		else
		{
			memcpy(output, stream, size);
		}
	}
}

void nx_sha256(const u8* data,
	u32 size,
	u8 hash[0x20])
{
	mbedtls_sha256(data, size, hash, 0);
}

int nx_sha256_verify(const u8* data,
	u32 size,
	const u8 checkhash[0x20])
{
	u8 hash[0x20];

	mbedtls_sha256(data, size, hash, 0);

	if (memcmp(hash, checkhash, 0x20) == 0)
		return Good;
	else
		return Fail;
}

void nx_sha256_init(nx_sha256_context* ctx)
{
	mbedtls_sha256_starts(&ctx->sha, 0);
}

void nx_sha256_update(nx_sha256_context* ctx,
	const u8* data,
	u32 size)
{
	mbedtls_sha256_update(&ctx->sha, data, size);
}


void nx_sha256_finish(nx_sha256_context* ctx,
	u8 hash[0x20])
{
	mbedtls_sha256_finish(&ctx->sha, hash);
}

void nx_rsa_init_key_pubmodulus(rsakey* key, u8* modulus, int size)
{
	u8 exponent[3] = { 0x01, 0x00, 0x01 };

	nx_rsa_init_key_pub(key, modulus, exponent, size);
}

void nx_rsa_init_key_pub(rsakey* key, u8* modulus, u8 exponent[3], int size)
{
	key->keytype = RSAKEY_PUB;
	key->keysize = size;
	memcpy(key->n, modulus, sizeof(key->n) / size);
	memcpy(key->e, exponent, sizeof(key->e));
}

int nx_rsa_init(nx_rsa_context* ctx, rsakey* key, int padding)
{
	mbedtls_rsa_init(&ctx->rsa, padding, 0);
	ctx->rsa.len = sizeof(key->n) / key->keysize;

	if (key->keytype == RSAKEY_INVALID)
		goto clean;

	if (mbedtls_mpi_read_binary(&ctx->rsa.N, key->n, sizeof(key->n) / key->keysize))
		goto clean;
	if (mbedtls_mpi_read_binary(&ctx->rsa.E, key->e, sizeof(key->e)))
		goto clean;
	if (mbedtls_rsa_check_pubkey(&ctx->rsa))
		goto clean;

	if (key->keytype == RSAKEY_PRIV)
	{
		if (mbedtls_mpi_read_binary(&ctx->rsa.D, key->d, sizeof(key->d) / key->keysize))
			goto clean;
		if (mbedtls_mpi_read_binary(&ctx->rsa.P, key->p, sizeof(key->p) / key->keysize))
			goto clean;
		if (mbedtls_mpi_read_binary(&ctx->rsa.Q, key->q, sizeof(key->q) / key->keysize))
			goto clean;
		if (mbedtls_mpi_read_binary(&ctx->rsa.DP, key->dp, sizeof(key->dp) / key->keysize))
			goto clean;
		if (mbedtls_mpi_read_binary(&ctx->rsa.DQ, key->dq, sizeof(key->dq) / key->keysize))
			goto clean;
		if (mbedtls_mpi_read_binary(&ctx->rsa.QP, key->qp, sizeof(key->qp) / key->keysize))
			goto clean;
		if (mbedtls_rsa_check_privkey(&ctx->rsa))
			goto clean;
	}

	return 1;
clean:
	return 0;
}

void nx_rsa_free(nx_rsa_context* ctx)
{
	mbedtls_rsa_free(&ctx->rsa);
}

int nx_rsa_public(const u8* signature, u8* output, rsakey* key, int padding)
{
	nx_rsa_context ctx;
	u32 result;

	nx_rsa_init(&ctx, key, padding);

	result = mbedtls_rsa_public(&ctx.rsa, signature, output);

	nx_rsa_free(&ctx);

	if (result == 0)
		return 1;
	else
		return 0;
}

int nx_rsa_verify_hash(const u8* signature, const u8 hash[0x20], rsakey* key, int padding)
{
	nx_rsa_context ctx;
	u32 result;
//	u8 output[0x200];

	if (key->keytype == RSAKEY_INVALID)
		return Fail;

	nx_rsa_init(&ctx, key, padding);
//	memset(output, 0, sizeof(output));
//	result = nx_rsa_public(signature, output, key, padding);
//	printf("Result = %d\n", result);
//	memdump(stdout, "output: ", output, sizeof(output) / key->keysize);

	mbedtls_entropy_context entropy;
	mbedtls_entropy_init(&entropy);

	result = mbedtls_rsa_pkcs1_verify(&ctx.rsa, mbedtls_entropy_func, &entropy, MBEDTLS_RSA_PUBLIC, MBEDTLS_MD_SHA256, 0x20, hash, (u8*)signature);

	nx_rsa_free(&ctx);

	if (result == 0)
		return Good;
	else
		return Fail;
}