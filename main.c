#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <getopt.h>

#include "utils.h"
#include "keyset.h"
#include "settings.h"
#include "nx.h"

#include "modf.h"
#include "nro.h"
#include "nrr.h"

typedef struct
{
	int actions;
	u32 filetype;
	FILE* infile;
	const char* infilename;
	u64 infilesize;
	settings usersettings;
} toolcontext;

static void usage(const char *argv0)
{
	fprintf(stderr,
		   "nxtool (c) Dazzozo\n"
		   "Built: %s %s\n"
           "\n"
		   "Usage: %s [options...] <file>\n"
           "Options:\n"
           "  -i, --info            Show file info.\n"
		   "                             This is the default action.\n"
           "  -x, --extract         Extract data from file.\n"
		   "                             This is also the default action.\n"
		   "  -p, --plain           Extract data without decrypting.\n"
		   "  -r, --raw             Keep raw data, don't unpack.\n"
		   "  -k, --keyset=file     Specify keyset file.\n"
		   "  -v, --verbose         Give verbose output.\n"
		   "  -y, --verify          Verify hashes and signatures.\n"
		   "  --showkeys            Show the keys being used.\n"
		   "  -t, --intype=type     Specify input file type [modf, nro, nrr]\n"
		   "\n"
		   "MOD options:\n"
		   "  --elf=file            Specify ELF file path.\n"
           "\n",
		   __TIME__, __DATE__, argv0);
   exit(1);
}


int main(int argc, char* argv[])
{
	toolcontext ctx;
	u8 magic[4];
	char infname[512];
	int c;
	char keysetfname[512] = "keys.xml";
	keyset tmpkeys;
	unsigned int checkkeysetfile = 0;

	memset(&ctx, 0, sizeof(toolcontext));
	ctx.actions = InfoFlag | ExtractFlag;
	ctx.filetype = FILETYPE_UNKNOWN;

	settings_init(&ctx.usersettings);
	keyset_init(&ctx.usersettings.keys);
	keyset_init(&tmpkeys);

	while (1)
	{
		int option_index;
		static struct option long_options[] =
		{
			{"extract", 0, NULL, 'x'},
			{"plain", 0, NULL, 'p'},
			{"info", 0, NULL, 'i'},
			{"elf", 1, NULL, 1},
			{"keyset", 1, NULL, 'k'},
			{"verbose", 0, NULL, 'v'},
			{"verify", 0, NULL, 'y'},
			{"raw", 0, NULL, 'r'},
			{"showkeys", 0, NULL, 10},
			{"intype", 1, NULL, 't'},
			{NULL},
		};

		c = getopt_long(argc, argv, "ryxivpk:n:t:", long_options, &option_index);
		if (c == -1)
			break;

		switch (c) 
		{
			case 'x':
				ctx.actions |= ExtractFlag;
			break;

			case 'v':
				ctx.actions |= VerboseFlag;
			break;

			case 'y':
				ctx.actions |= VerifyFlag;
			break;

			case 'p':
				ctx.actions |= PlainFlag;
			break;

			case 'r':
				ctx.actions |= RawFlag;
			break;

			case 'i':
				ctx.actions |= InfoFlag;
			break;

			case 'k':
				strncpy(keysetfname, optarg, sizeof(keysetfname));
				checkkeysetfile = 1;
			break;

			case 't':
				if (!strcmp(optarg, "modf"))
					ctx.filetype = FILETYPE_MODF;
				else if (!strcmp(optarg, "nro"))
					ctx.filetype = FILETYPE_NRO;
				else if (!strcmp(optarg, "nrr"))
					ctx.filetype = FILETYPE_NRR;
			break;

			case 1: settings_set_elf_path(&ctx.usersettings, optarg); break;
			case 10: ctx.actions |= ShowKeysFlag; break;

			default: usage(argv[0]);
		}
	}

	if (optind == argc - 1) 
	{
		// Exactly one extra argument - an input file
		strncpy(infname, argv[optind], sizeof(infname));
	} 
	else if ( (optind < argc) || (argc == 1) )
	{
		// Too many extra args
		usage(argv[0]);
	}

#ifdef _WIN32
	const char* homedir = getenv("USERPROFILE");
#else
	const char* homedir = getenv("HOME");
#endif

	char tmpname[512];
	const char* keyset = NULL;
	if (homedir)
	{
		sprintf(tmpname, "%s/.nx/%s", homedir, keysetfname);
		FILE* keysetfile = fopen(tmpname, "r");
		if (keysetfile) keyset = tmpname;
	}
	if (!keyset) keyset = keysetfname;

	keyset_load(&ctx.usersettings.keys, keyset, (ctx.actions & VerboseFlag) | checkkeysetfile);
	keyset_merge(&ctx.usersettings.keys, &tmpkeys);
	if (ctx.actions & ShowKeysFlag)
		keyset_dump(&ctx.usersettings.keys);

	ctx.infilesize = _fsize(infname);
	ctx.infile = fopen(infname, "rb");

	if (ctx.infile == 0) 
	{
		fprintf(stderr, "Error: could not open input file.\n");
		exit(1);
	}

	const char* name = strrchr(infname, '/');
	if (strrchr(infname, '\\') > name)
		name = strrchr(infname, '\\');
	if (name) name++;
	else name = infname;

	ctx.infilename = name;

	if (ctx.filetype == FILETYPE_UNKNOWN)
	{
		fseeko64(ctx.infile, 0x10, SEEK_SET);
		fread(magic, 1, 4, ctx.infile);

		if (memcmp(magic, "NRO", 3) == 0)
			ctx.filetype = FILETYPE_NRO;
	}

	if (ctx.filetype == FILETYPE_UNKNOWN)
	{
		fseeko64(ctx.infile, 0, SEEK_SET);
		fread(magic, 1, 4, ctx.infile);

		if (memcmp(magic, "NRR", 3) == 0)
			ctx.filetype = FILETYPE_NRR;
	}

	if (ctx.filetype == FILETYPE_UNKNOWN)
	{
		u8 mod_pointer[4] = {0};

		fseeko64(ctx.infile, 0x4, SEEK_SET);
		fread(mod_pointer, 1, 4, ctx.infile);

		u32 mod_offset = getle32(mod_pointer);
		if (mod_offset + sizeof(mod_header) <= ctx.infilesize)
		{
			fseeko64(ctx.infile, mod_offset, SEEK_SET);
			fread(magic, 1, 4, ctx.infile);

			if (memcmp(magic, "MOD", 3) == 0)
				ctx.filetype = FILETYPE_MODF;
		}
	}

	if (ctx.filetype == FILETYPE_UNKNOWN)
	{
		fprintf(stdout, "Error: unknown file.\n");
		exit(1);
	}

	switch(ctx.filetype)
	{
		// Probably not really a file type.
		case FILETYPE_MODF:
		{
			modf_context modfctx;

			modf_init(&modfctx);
			modf_set_file(&modfctx, ctx.infile);
			modf_set_size(&modfctx, ctx.infilesize);
			modf_set_name(&modfctx, ctx.infilename);

			modf_set_usersettings(&modfctx, &ctx.usersettings);
			modf_process(&modfctx, ctx.actions);

			break;
		}

		case FILETYPE_NRO:
		{
			nro_context nroctx;

			nro_init(&nroctx);
			nro_set_file(&nroctx, ctx.infile);
			nro_set_size(&nroctx, ctx.infilesize);
			nro_set_name(&nroctx, ctx.infilename);

			nro_set_usersettings(&nroctx, &ctx.usersettings);
			nro_process(&nroctx, ctx.actions);

			break;
		}

		case FILETYPE_NRR:
		{
			nrr_context nrrctx;

			nrr_init(&nrrctx);
			nrr_set_file(&nrrctx, ctx.infile);
			nrr_set_size(&nrrctx, ctx.infilesize);
			nrr_set_name(&nrrctx, ctx.infilename);

			nrr_set_usersettings(&nrrctx, &ctx.usersettings);
			nrr_process(&nrrctx, ctx.actions);

			break;
		}
	}
	
	if (ctx.infile)
		fclose(ctx.infile);

	return 0;
}
