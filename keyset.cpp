#include <stdio.h>
#include "keyset.h"
#include "utils.h"
#include "tinyxml/tinyxml.h"

static void keyset_set_key128(key128* key, unsigned char* keydata);
static void keyset_parse_key128(key128* key, char* keytext, int keylen);
static int keyset_parse_key(const char* text, unsigned int textlen, unsigned char* key, unsigned int size, int* valid);
static int keyset_load_rsakey(TiXmlElement* elem, rsakey* key);
static int keyset_load_rsakey2048(TiXmlElement* elem, rsakey* key);
static int keyset_load_rsakey4096(TiXmlElement* elem, rsakey* key);
static int keyset_load_key128(TiXmlHandle node, key128* key);
static int keyset_load_key(TiXmlHandle node, unsigned char* key, unsigned int maxsize, int* valid);

static int ishex(char c)
{
	if (c >= '0' && c <= '9')
		return 1;
	if (c >= 'A' && c <= 'F')
		return 1;
	if (c >= 'a' && c <= 'f')
		return 1;
	return 0;

}

static unsigned char hextobin(char c)
{
	if (c >= '0' && c <= '9')
		return c-'0';
	if (c >= 'A' && c <= 'F')
		return c-'A'+0xA;
	if (c >= 'a' && c <= 'f')
		return c-'a'+0xA;
	return 0;
}

void keyset_init(keyset* keys)
{
	memset(keys, 0, sizeof(keyset));
}

int keyset_load_key(TiXmlHandle node, unsigned char* key, unsigned int size, int* valid)
{
	TiXmlElement* elem = node.ToElement();

	if (valid)
		*valid = 0;

	if (!elem)
		return 0;

	const char* text = elem->GetText();
	unsigned int textlen = strlen(text);

	int status = keyset_parse_key(text, textlen, key, size, valid);

	if (status == KEY_ERR_LEN_MISMATCH)
	{
		fprintf(stderr, "Error size mismatch for key \"%s/%s\"\n", elem->Parent()->Value(), elem->Value());
		return 0;
	}
	
	return 1;
}


int keyset_parse_key(const char* text, unsigned int textlen, unsigned char* key, unsigned int size, int* valid)
{
	unsigned int i, j;
	unsigned int hexcount = 0;


	if (valid)
		*valid = 0;

	for(i=0; i<textlen; i++)
	{
		if (ishex(text[i]))
			hexcount++;
	}

	if (hexcount != size*2)
	{
		fprintf(stdout, "Error, expected %d hex characters when parsing text \"", size*2);
		for(i=0; i<textlen; i++)
			fprintf(stdout, "%c", text[i]);
		fprintf(stdout, "\"\n");
		
		return KEY_ERR_LEN_MISMATCH;
	}

	for(i=0, j=0; i<textlen; i++)
	{
		if (ishex(text[i]))
		{
			if ( (j&1) == 0 )
				key[j/2] = hextobin(text[i])<<4;
			else
				key[j/2] |= hextobin(text[i]);
			j++;
		}
	}

	if (valid)
		*valid = 1;
	
	return KEY_OK;
}

int keyset_load_key128(TiXmlHandle node, key128* key)
{
	return keyset_load_key(node, key->data, sizeof(key->data), &key->valid);
}

int keyset_load_xtskey128(TiXmlHandle node, xtskey128* key)
{
	key->valid = 0;

	if (!keyset_load_key(node.FirstChild("TWEAK"), key->tweak, sizeof(key->tweak), 0))
		goto clean;
	if (!keyset_load_key(node.FirstChild("CRYPT"), key->crypt, sizeof(key->crypt), 0))
		goto clean;

	key->valid = 1;
clean:
	return (key->valid != 0);
}

int keyset_load_rsakey(TiXmlHandle node, rsakey* key)
{
	key->keytype = RSAKEY_INVALID;

	if (!keyset_load_key(node.FirstChild("N"), key->n, sizeof(key->n) / key->keysize, 0))
		goto clean;
	if (!keyset_load_key(node.FirstChild("E"), key->e, sizeof(key->e), 0))
		goto clean;
	key->keytype = RSAKEY_PUB;

	if (!keyset_load_key(node.FirstChild("D"), key->d, sizeof(key->d) / key->keysize, 0))
		goto clean;
	if (!keyset_load_key(node.FirstChild("P"), key->p, sizeof(key->p) / key->keysize, 0))
		goto clean;
	if (!keyset_load_key(node.FirstChild("Q"), key->q, sizeof(key->q) / key->keysize, 0))
		goto clean;
	if (!keyset_load_key(node.FirstChild("DP"), key->dp, sizeof(key->dp) / key->keysize, 0))
		goto clean;
	if (!keyset_load_key(node.FirstChild("DQ"), key->dq, sizeof(key->dq) / key->keysize, 0))
		goto clean;
	if (!keyset_load_key(node.FirstChild("QP"), key->qp, sizeof(key->qp) / key->keysize, 0))
		goto clean;

	key->keytype = RSAKEY_PRIV;
clean:
	return (key->keytype != RSAKEY_INVALID);
}

int keyset_load_rsakey2048(TiXmlHandle node, rsakey* key)
{
	key->keysize = RSASIZE_2048;

	return keyset_load_rsakey(node, key);
}

int keyset_load_rsakey4096(TiXmlHandle node, rsakey* key)
{
	key->keysize = RSASIZE_4096;

	return keyset_load_rsakey(node, key);
}

int keyset_load(keyset* keys, const char* fname, int verbose)
{
	TiXmlDocument doc(fname);
	bool loadOkay = doc.LoadFile();

	if (!loadOkay)
	{
		if (verbose)
			fprintf(stderr, "Could not load keyset file \"%s\", error: %s.\n", fname, doc.ErrorDesc() );

		return 0;
	}

	TiXmlHandle root = doc.FirstChild("keys");

	keyset_load_rsakey2048(root.FirstChild("NrrRsaKey"), &keys->nrrrsakey);

	return 1;
}


void keyset_merge(keyset* keys, keyset* src)
{
	return;
}

void keyset_set_key128(key128* key, unsigned char* keydata)
{
	memcpy(key->data, keydata, 16);
	key->valid = 1;
}

void keyset_parse_key128(key128* key, char* keytext, int keylen)
{
	keyset_parse_key(keytext, keylen, key->data, 16, &key->valid);
}

void keyset_dump_rsakey(rsakey* key, const char* keytitle)
{
	if (key->keytype == RSAKEY_INVALID)
		return;


	fprintf(stdout, "%s\n", keytitle);

	memdump(stdout, "Modulus: ", key->n, sizeof(key->n) / key->keysize);
	memdump(stdout, "Exponent: ", key->e, sizeof(key->e));

	if (key->keytype == RSAKEY_PRIV)
	{
		memdump(stdout, "P: ", key->p, sizeof(key->p) / key->keysize);
		memdump(stdout, "Q: ", key->q, sizeof(key->q) / key->keysize);
	}
	fprintf(stdout, "\n");
}

void keyset_dump_key128(key128* key, const char* keytitle)
{
	if (key->valid)
	{
		fprintf(stdout, "%s\n", keytitle);
		memdump(stdout, "", key->data, 16);
		fprintf(stdout, "\n");
	}
}

void keyset_dump(keyset* keys)
{
	fprintf(stdout, "Current keyset:          \n");

	keyset_dump_rsakey(&keys->nrrrsakey, "NRR RSA KEY");

	fprintf(stdout, "\n");
}

