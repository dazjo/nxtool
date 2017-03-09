#ifndef _NX_H_
#define _NX_H_

#include "mbedtls/aes.h"
#include "mbedtls/rsa.h"
#include "mbedtls/sha256.h"
#include "mbedtls/entropy.h"
#include "mbedtls/md.h"
#include "types.h"
#include "keyset.h"

typedef enum
{
	FILETYPE_UNKNOWN = 0,
	FILETYPE_MODF,
	FILETYPE_NRO,
	FILETYPE_NRR,
} nx_filetypes;

typedef struct
{
	mbedtls_rsa_context rsa;
} nx_rsa_context;

typedef struct
{
	u8 ctr[16];
	mbedtls_aes_context aes;
} nx_ctr_context;

typedef struct
{
	u8 iv[16];
	mbedtls_aes_context aes;
} nx_cbc_context;

typedef struct
{
	mbedtls_sha256_context sha;
} nx_sha256_context;

#ifdef __cplusplus
extern "C" {
#endif

void nx_set_iv(nx_cbc_context* ctx,
	u8 iv[16]);

void nx_init_cbc_encrypt(nx_cbc_context* ctx,
	u8 key[16],
	u8 iv[16]);

void nx_init_cbc_decrypt(nx_cbc_context* ctx,
	u8 key[16],
	u8 iv[16]);

void nx_encrypt_cbc(nx_cbc_context* ctx,
	u8* input,
	u8* output,
	u32 size);

void nx_decrypt_cbc(nx_cbc_context* ctx,
	u8* input,
	u8* output,
	u32 size);

void nx_add_ctr(nx_ctr_context* ctx,
	u32 block_num);

void nx_set_ctr(nx_ctr_context* ctx,
	u8 ctr[16]);

void nx_init_ctr(nx_ctr_context* ctx,
	u8 key[16], u8 ctr[16]);

void nx_crypt_ctr_block(nx_ctr_context* ctx,
	u8 input[16],
	u8 output[16]);

void nx_crypt_ctr(nx_ctr_context* ctx,
	u8* input,
	u8* output,
	u32 size);

void nx_sha256(const u8* data,
	u32 size,
	u8 hash[0x20]);

int nx_sha256_verify(const u8* data,
	u32 size,
	const u8 checkhash[0x20]);

void nx_sha256_init(nx_sha256_context* ctx);

void nx_sha256_update(nx_sha256_context* ctx,
	const u8* data,
	u32 size);

void nx_sha256_finish(nx_sha256_context* ctx,
	u8 hash[0x20]);

void nx_rsa_init_key_pubmodulus(rsakey* key, u8* modulus, int size);
void nx_rsa_init_key_pub(rsakey* key, u8* modulus, u8 exponent[3], int size);

int nx_rsa_init(nx_rsa_context* ctx, rsakey* key, int padding);
void nx_rsa_free(nx_rsa_context* ctx);

int nx_rsa_public(const u8* signature, u8* output, rsakey* key, int padding);
int nx_rsa_verify_hash(const u8* signature, const u8 hash[0x20], rsakey* key, int padding);

#ifdef __cplusplus
}
#endif

#endif // _NX_H_
