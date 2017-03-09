#ifndef _KEYSET_H_
#define _KEYSET_H_

#include "types.h"

#ifdef __cplusplus
extern "C" {
#endif

typedef enum
{
	KEY_ERR_LEN_MISMATCH,
	KEY_ERR_INVALID_NODE,
	KEY_OK
} keystatus;

typedef enum
{
	RSAKEY_INVALID,
	RSAKEY_PRIV,
	RSAKEY_PUB
} rsakeytype;

typedef enum
{
	RSASIZE_INVALID,
	RSASIZE_4096,
	RSASIZE_2048,
} rsakeysize;

typedef struct
{
	int index;
	unsigned char n[512];
	unsigned char e[3];
	unsigned char d[512];
	unsigned char p[256];
	unsigned char q[256];
	unsigned char dp[256];
	unsigned char dq[256];
	unsigned char qp[256];
	rsakeytype keytype;
	rsakeysize keysize;
} rsakey;

typedef struct
{
	int index;
	unsigned char data[16];
	int valid;
} key128;

typedef struct {
	int index;
	unsigned char tweak[16];
	unsigned char crypt[16];
	int valid;
} xtskey128;


typedef struct
{
	rsakey nrrrsakey;
} keyset;

void keyset_init(keyset* keys);
int keyset_load(keyset* keys, const char* fname, int verbose);
void keyset_merge(keyset* keys, keyset* src);
void keyset_dump(keyset* keys);

#ifdef __cplusplus
}
#endif


#endif // _KEYSET_H_
