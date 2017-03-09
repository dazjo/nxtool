#define __STDC_FORMAT_MACROS
#include <inttypes.h>
#include <stdbool.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>

#include "types.h"
#include "mod.h"
#include "elfio/elfio.hpp"
#include "elfio/elfio_dump.hpp"
#include "nx.h"
#include "utils.h"

using namespace ELFIO;

void mod_init(mod_context* ctx)
{
	memset(ctx, 0, sizeof(mod_context));
}

void mod_set_header(mod_context* ctx, mod_header* header)
{
	ctx->header = header;
}

void mod_set_name(mod_context* ctx, const char* name)
{
	ctx->name = name;
}

void mod_set_buffer(mod_context* ctx, u8* buffer)
{
	ctx->buffer = buffer;
}

void mod_set_size(mod_context* ctx, u64 size)
{
	ctx->size = size;
}

void mod_set_discover(mod_context* ctx, int discover)
{
	ctx->discover = discover;
}

void mod_set_meta(mod_context* ctx, mod_meta* meta)
{
	ctx->meta = meta;
}

void mod_set_usersettings(mod_context* ctx, settings* usersettings)
{
	ctx->usersettings = usersettings;
}

u64 eh_value_decode(mod_context* ctx, u8 encoding, const u8** stream, u64 hdr_offset)
{
	const u8* start = *stream;
	u64 pc_offset = start - ctx->buffer;

	// DW_EH_PE_omit
	if (encoding == 0xFF) return 0;

	u8 application = encoding & 0xF0;
	u8 format = encoding & 0x0F;

	bool sign = false;
	u64 value_unsigned = 0;
	s64 value_signed = 0;

	switch (format)
	{
		// DW_EH_PE_uleb128
		case 0x1:
		{
			value_unsigned = getuleb128(stream);
			break;
		}
		// DW_EH_PE_udata2
		case 0x2:
		{
			value_unsigned = getle16(*stream);
			*stream += sizeof(u16);
			break;
		}
		// DW_EH_PE_udata4
		case 0x3:
		{
			value_unsigned = getle32(*stream);
			*stream += sizeof(u32);
			break;
		}
		// DW_EH_PE_udata8
		case 0x4:
		{
			value_unsigned = getle64(*stream);
			*stream += sizeof(u64);
			break;
		}

		// DW_EH_PE_sleb128
		case 0x9:
		{
			sign = true;
			value_signed = getsleb128(stream);
			break;
		}
		// DW_EH_PE_sdata2
		case 0xA:
		{
			sign = true;
			value_signed = (s64)getle16(*stream);
			*stream += sizeof(s16);
			break;
		}
		// DW_EH_PE_sdata4
		case 0xB:
		{
			sign = true;
			value_signed = (s64)getle32(*stream);
			*stream += sizeof(s32);
			break;
		}
		// DW_EH_PE_sdata8
		case 0xC:
		{
			sign = true;
			value_signed = (s64)getle64(*stream);
			*stream += sizeof(s64);
			break;
		}
	}

	u64 value = 0;

	switch (application & 0x70)
	{
		// DW_EH_PE_absptr
		case 0x00:
			value = sign ? value_signed : value_unsigned;
			break;
		// DW_EH_PE_pcrel
		case 0x10:
			value = sign ? (s64)pc_offset + value_signed : pc_offset + value_unsigned;
			break;
		// DW_EH_PE_datarel
		case 0x30:
			value = sign ? (s64)hdr_offset + value_signed : hdr_offset + value_unsigned;
			break;
	}

	// DW_EH_PE_indirect
	if (application & 0x80)
		value = getle64(ctx->buffer + value);

	return value;
}

typedef struct {
	u64 size;
	u8 lpstart_encoding;
	u8 types_encoding;
	u8 cs_encoding;
	u64 lpstart;
	u64 types_offset;
	u64 cs_size;
	const u8* action_table;
	const u8* types_table;
} lsda_data;

int eh_lsda_parse(mod_context* ctx, const u8* lsda, lsda_data* data)
{
	const u8* start = lsda;
	memset(data, 0, sizeof(lsda_data));

	data->lpstart_encoding = *lsda++;
	if (data->lpstart_encoding != 0xFF)
		data->lpstart = getuleb128(&lsda);

	data->types_encoding = *lsda++;
	if (data->types_encoding != 0xFF)
	{
		data->types_offset = getuleb128(&lsda);
		data->types_table = lsda + data->types_offset;
	}

	data->cs_encoding = *lsda++;
	if (data->cs_encoding != 0xFF)
		data->cs_size = getuleb128(&lsda);

	data->action_table = lsda + data->cs_size;

	while (lsda < data->action_table)
	{
		u64 cs_start = eh_value_decode(ctx, data->cs_encoding, &lsda, 0);
		u64 cs_len = eh_value_decode(ctx, data->cs_encoding, &lsda, 0);
		u64 cs_lp = eh_value_decode(ctx, data->cs_encoding, &lsda, 0);
		u64 cs_action = getuleb128(&lsda);
	}

	if (lsda != data->action_table)
		return -1;

	while (true)
	{
		s64 type_filter = getsleb128(&lsda);
		s64 next_entry = getsleb128(&lsda);
		if (next_entry == 0) break;
	}

	data->size = lsda - start;
	if (data->types_table)
		data->size = data->types_table - start;

	return 0;
}

typedef struct {
	u64 size;
	u8 version;
	bool aug_data_present;
	bool eh_data_present;
	const char* aug_string;
	const u8* aug_data;
	u64 aug_size;
	u64 eh_data;
	u64 return_register;
	u64 code_factor;
	u64 data_factor;
	u8 lsda_encoding;
	u8 fde_encoding;
	u8 p_encoding;
	u64 p_routine;
} cie_data;

typedef struct {
	cie_data* cie;
	u64 size;
	u64 pc_begin;
	u64 pc_range;
	const char* aug_string;
	const u8* aug_data;
	u64 aug_size;
	u64 lsda_address;
} fde_data;

int eh_frame_parse(mod_context* ctx, const u8* frame, u64 hdr_offset, cie_data* cie, fde_data* fde)
{
	const u8* start = frame;

	u32 size32 = getle32(frame);
	if (size32 == 0) return 0;

	frame += sizeof(size32);
	u64 size = size32 + sizeof(size32);

	// Uses extended size.
	if (size32 == 0xFFFFFFFF)
	{
		size = getle64(frame) + sizeof(size32);
		frame += sizeof(size);
	}

	u32 cie_id = getle32(frame);
	frame += sizeof(cie_id);

	// If zero, this entry is a CIE, otherwise this value is a pointer to the CIE.
	if (cie_id == 0)
	{
		memset(cie, 0, sizeof(cie_data));

		cie->size = size;
		cie->version = *frame++;

		cie->aug_string = (const char*)frame;

		cie->aug_data_present = false;
		cie->eh_data_present = false;

		if (strlen((const char*)cie->aug_string) != 0)
		{
			if (strcmp((const char*)cie->aug_string, "eh") == 0)
				cie->eh_data_present = true;
			else if (*cie->aug_string == 'z')
				cie->aug_data_present = true;
		}

		frame += strlen(cie->aug_string) + 1;

		if (cie->eh_data_present)
		{
			cie->eh_data = getle64(frame);
			frame += sizeof(u64);
		}

		cie->code_factor = getuleb128(&frame);
		cie->data_factor = getsleb128(&frame);

		cie->return_register = getuleb128(&frame);

		if (cie->aug_data_present)
		{
			cie->aug_size = getuleb128(&frame);
			cie->aug_data = frame;

			const char* string_cursor = cie->aug_string;
			const u8* data_cursor = cie->aug_data;

			while (strlen(string_cursor) != 0)
			{
				switch (*string_cursor)
				{
					case 'L':
						cie->lsda_encoding = *data_cursor++;
						break;
					case 'R':
						cie->fde_encoding = *data_cursor++;
						break;
					case 'P':
						cie->p_encoding = *data_cursor++;
						cie->p_routine = eh_value_decode(ctx, cie->p_encoding, &data_cursor, hdr_offset);
						break;

				}

				string_cursor++;
			}

			frame += cie->aug_size;
		}

		return 1;
	}

	// Process FDE.
	else
	{
		memset(fde, 0, sizeof(fde_data));

		fde->size = size;

		// Read the CIE for this FDE.
		const u8* cie_frame = start + sizeof(size32) - cie_id;
		int res = eh_frame_parse(ctx, cie_frame, hdr_offset, cie, fde);

		// CIE is not a CIE?
		if (res != 1) return -1;

		fde->cie = cie;

		fde->pc_begin = eh_value_decode(ctx, cie->fde_encoding, &frame, hdr_offset);
		fde->pc_range = eh_value_decode(ctx, cie->fde_encoding, &frame, hdr_offset);

		if (cie->aug_data_present)
		{
			fde->aug_size = getuleb128(&frame);
			fde->aug_data = frame;

			const char* string_cursor = cie->aug_string;
			const u8* data_cursor = fde->aug_data;

			while (strlen(string_cursor) != 0)
			{
				switch (*string_cursor)
				{
					case 'L':
						fde->lsda_address = eh_value_decode(ctx, cie->lsda_encoding, &data_cursor, hdr_offset);
						break;
				}

				string_cursor++;
			}

			frame += fde->aug_size;
		}

		return 2;
	}
}

int dt_get(dynamic_section_accessor dynamic, Elf_Xword tag, Elf_Xword* value)
{
	for (int i = 0; i < dynamic.get_entries_num(); ++i)
	{
		Elf_Xword _tag = 0;
		Elf_Xword _value = 0;
		std::string _str;
		dynamic.get_entry(i, _tag, _value, _str);

		if (tag == _tag)
		{
			*value = _value;
			return 0;
		}
	}

	return -1;
}

void mod_convert_elf(mod_context* ctx)
{
	elfio* elf = (elfio*)ctx->elf;
	mod_header* header = ctx->header;

	// This converts the module (NSO/NRO) back to an ELF, in order to aid reverse engineering.
	// Note that the original conversion to NSO/NRO is lossy - ELF segment/section headers are lost.
	// Despite this, we are able to recover a vast majority of the sections produced by the official toolchain
	// thanks to the module header and the .dynamic section.

	elf->create(ELFCLASS64, ELFDATA2LSB);
	elf->set_os_abi(ELFOSABI_NONE);
	elf->set_type(ET_DYN);
	elf->set_machine(EM_AARCH64);
	elf->set_entry(0);

	u64 base = 0;
	s32 mod_offset = ctx->meta->mod_offset + (s32)getle32(header->mod_object);
	mod_object* obj = (mod_object*)(ctx->buffer + mod_offset);
	base = getle64(obj->base);

	segment* text_seg = elf->segments.add();
	{
		text_seg->set_type(PT_LOAD);

		text_seg->set_flags(PF_R | PF_X);
		text_seg->set_align(0x10000);

		text_seg->set_virtual_address(base + ctx->meta->text_offset);
		text_seg->set_physical_address(ctx->meta->text_offset);

		text_seg->set_memory_size(ctx->meta->text_size);
		text_seg->set_file_size(ctx->meta->text_size);
	}

	segment* ro_seg = elf->segments.add();
	{
		ro_seg->set_type(PT_LOAD);

		ro_seg->set_flags(PF_R);
		ro_seg->set_align(0x10000);

		ro_seg->set_virtual_address(base + ctx->meta->ro_offset);
		ro_seg->set_physical_address(ctx->meta->ro_offset);

		ro_seg->set_memory_size(ctx->meta->ro_size);
		ro_seg->set_file_size(ctx->meta->ro_size);
	}

	segment* data_seg = elf->segments.add();
	{
		data_seg->set_type(PT_LOAD);

		data_seg->set_flags(PF_R | PF_W);
		data_seg->set_align(0x10000);

		data_seg->set_virtual_address(base + ctx->meta->data_offset);
		data_seg->set_physical_address(ctx->meta->data_offset);

		data_seg->set_memory_size(ctx->meta->data_size);
		data_seg->set_file_size(ctx->meta->data_size);
	}

	segment* bss_seg = elf->segments.add();
	{
		bss_seg->set_type(PT_LOAD);

		bss_seg->set_flags(PF_R | PF_W);
		bss_seg->set_align(0x10000);

		bss_seg->set_virtual_address(base + ctx->meta->data_offset + ctx->meta->data_size);
		bss_seg->set_physical_address(ctx->meta->data_offset + ctx->meta->data_size);

		bss_seg->set_memory_size(ctx->meta->bss_size);
		bss_seg->set_file_size(0);
	}

	segment* dynamic_seg = elf->segments.add();
	{
		dynamic_seg->set_type(PT_DYNAMIC);

		dynamic_seg->set_flags(PF_R | PF_W);
		dynamic_seg->set_align(4);

		dynamic_seg->set_virtual_address(base + ctx->meta->mod_offset + (s32)getle32(header->dynamic));
		dynamic_seg->set_physical_address(ctx->meta->mod_offset + (s32)getle32(header->dynamic));

		dynamic_seg->set_overlay(data_seg->get_index());
	}

	section* text_sec = elf->sections.add(".text");
	{
		text_sec->set_type(SHT_PROGBITS);
		text_sec->set_flags(SHF_ALLOC | SHF_EXECINSTR);

		text_sec->set_address(base + ctx->meta->text_offset);

		text_sec->set_addr_align(4);
	}

	section* ro_sec = elf->sections.add(".rodata");
	{
		ro_sec->set_type(SHT_PROGBITS);
		ro_sec->set_flags(SHF_ALLOC);

		ro_sec->set_address(base + ctx->meta->ro_offset);

		ro_sec->set_addr_align(4);
	}

	section* data_sec = elf->sections.add(".data");
	{
		data_sec->set_type(SHT_PROGBITS);
		data_sec->set_flags(SHF_ALLOC | SHF_WRITE);

		data_sec->set_address(base + ctx->meta->data_offset);

		data_sec->set_addr_align(4);
	}

	section* bss_sec = elf->sections.add(".bss");
	{
		bss_sec->set_type(SHT_NOBITS);
		bss_sec->set_flags(SHF_ALLOC | SHF_WRITE);

		bss_sec->set_address(base + ctx->meta->data_offset + ctx->meta->data_size);

		bss_sec->set_addr_align(4);
	}

	section* strtab_sec = elf->sections.add(".dynstr");
	{
		strtab_sec->set_type(SHT_STRTAB);
		strtab_sec->set_flags(SHF_ALLOC);

		strtab_sec->set_overlay(ro_sec->get_index());
		strtab_sec->set_addr_align(1);
	}

	section* symtab_sec = elf->sections.add(".dynsym");
	{
		symtab_sec->set_type(SHT_DYNSYM);
		symtab_sec->set_flags(SHF_ALLOC);
		symtab_sec->set_entry_size(elf->get_default_entry_size(SHT_SYMTAB));

		symtab_sec->set_link(strtab_sec->get_index());
		symtab_sec->set_overlay(ro_sec->get_index());
		symtab_sec->set_addr_align(8);
	}

	section* dynamic_sec = elf->sections.add(".dynamic");
	{
		dynamic_sec->set_type(SHT_DYNAMIC);
		dynamic_sec->set_flags(SHF_ALLOC | SHF_WRITE);
		dynamic_sec->set_link(strtab_sec->get_index());
		dynamic_sec->set_overlay(data_sec->get_index());

		dynamic_sec->set_entry_size(elf->get_default_entry_size(SHT_DYNAMIC));

		// We don't have the true size for the .dynamic section, but it will always end on a DT_NULL.
		u32 dynamic_size = 0;
		u8* dynamic_buffer = ctx->dynamic;
		while (true)
		{
			u64 tag = getle64(dynamic_buffer);
			dynamic_size += elf->get_default_entry_size(SHT_DYNAMIC);
			if (tag == DT_NULL) break;
			dynamic_buffer += elf->get_default_entry_size(SHT_DYNAMIC);
		}

		// Set the actual data so that accessors work.
		dynamic_sec->set_data((const char*)ctx->dynamic, dynamic_size);
		dynamic_sec->set_address(base + ctx->meta->mod_offset + (s32)getle32(header->dynamic));

		dynamic_seg->set_memory_size(dynamic_size);
		dynamic_seg->set_file_size(dynamic_size);

		dynamic_sec->set_addr_align(8);

		dynamic_seg->add_section_index(dynamic_sec->get_index(), dynamic_sec->get_addr_align());
	}

	section* hash_sec = elf->sections.add(".hash");
	{
		hash_sec->set_type(SHT_HASH);
		hash_sec->set_flags(SHF_ALLOC);
		hash_sec->set_entry_size(sizeof(u32));

		hash_sec->set_link(symtab_sec->get_index());
		hash_sec->set_overlay(ro_sec->get_index());
		hash_sec->set_addr_align(8);
	}

	section* got_sec = elf->sections.add(".got");
	{
		got_sec->set_type(SHT_PROGBITS);
		got_sec->set_flags(SHF_ALLOC | SHF_WRITE);
		got_sec->set_entry_size(sizeof(u64));

		got_sec->set_overlay(data_sec->get_index());
		got_sec->set_addr_align(8);
	}

	section* plt_sec = elf->sections.add(".plt");
	{
		plt_sec->set_type(SHT_PROGBITS);
		plt_sec->set_flags(SHF_ALLOC | SHF_EXECINSTR);
		plt_sec->set_entry_size(4 * sizeof(u32));

		plt_sec->set_overlay(text_sec->get_index());
		plt_sec->set_addr_align(4);
	}

	dynamic_section_accessor dynamic(*elf, dynamic_sec);

	section* gnuhash_sec = NULL;

	section* reldyn_sec = NULL;
	section* relplt_sec = NULL;

	section* initarray_sec = NULL;
	section* finiarray_sec = NULL;
	section* preinitarray_sec = NULL;

	Elf_Xword plt_rel = 0;
	Elf_Xword plt_entry = 0;

	Elf_Xword dt_value = 0;

	if (!dt_get(dynamic, DT_PLTREL, &plt_rel))
	{
		if (plt_rel == DT_REL)
		{
			plt_entry = elf->get_default_entry_size(SHT_REL);

			if (base == 0)
			{
				reldyn_sec = elf->sections.add(".rel.dyn");
				reldyn_sec->set_type(SHT_REL);
				reldyn_sec->set_entry_size(plt_entry);

				relplt_sec = elf->sections.add(".rel.plt");
				relplt_sec->set_type(SHT_REL);
				relplt_sec->set_entry_size(plt_entry);
			}
		}
		else if (plt_rel == DT_RELA)
		{
			plt_entry = elf->get_default_entry_size(SHT_RELA);

			if (base == 0)
			{
				reldyn_sec = elf->sections.add(".rela.dyn");
				reldyn_sec->set_type(SHT_RELA);
				reldyn_sec->set_entry_size(plt_entry);

				relplt_sec = elf->sections.add(".rela.plt");
				relplt_sec->set_type(SHT_RELA);
				relplt_sec->set_entry_size(plt_entry);
			}
		}

		if (base == 0)
		{
			reldyn_sec->set_flags(SHF_ALLOC);
			reldyn_sec->set_link(symtab_sec->get_index());
			reldyn_sec->set_overlay(ro_sec->get_index());
			reldyn_sec->set_addr_align(8);

			relplt_sec->set_flags(SHF_ALLOC | SHF_INFO_LINK);
			relplt_sec->set_info(got_sec->get_index());
			relplt_sec->set_link(symtab_sec->get_index());
			relplt_sec->set_overlay(ro_sec->get_index());
			relplt_sec->set_addr_align(8);
		}
	}

	if (!dt_get(dynamic, DT_GNU_HASH, &dt_value))
	{
		gnuhash_sec = elf->sections.add(".gnu.hash");
		gnuhash_sec->set_type(SHT_GNU_HASH);
		gnuhash_sec->set_flags(SHF_ALLOC);

		gnuhash_sec->set_link(symtab_sec->get_index());
		gnuhash_sec->set_overlay(ro_sec->get_index());
		gnuhash_sec->set_addr_align(8);
	}

	if (!dt_get(dynamic, DT_INIT_ARRAY, &dt_value))
	{
		initarray_sec = elf->sections.add(".init_array");
		initarray_sec->set_type(SHT_INIT_ARRAY);
		initarray_sec->set_flags(SHF_ALLOC | SHF_WRITE);
		initarray_sec->set_overlay(data_sec->get_index());
		initarray_sec->set_addr_align(8);
		initarray_sec->set_address(base + dt_value);
	}

	if (!dt_get(dynamic, DT_FINI_ARRAY, &dt_value))
	{
		finiarray_sec = elf->sections.add(".fini_array");
		finiarray_sec->set_type(SHT_FINI_ARRAY);
		finiarray_sec->set_flags(SHF_ALLOC | SHF_WRITE);
		finiarray_sec->set_overlay(data_sec->get_index());
		finiarray_sec->set_addr_align(8);
		finiarray_sec->set_address(base + dt_value);
	}

	if (!dt_get(dynamic, DT_PREINIT_ARRAY, &dt_value))
	{
		preinitarray_sec = elf->sections.add(".preinit_array");
		preinitarray_sec->set_type(SHT_PREINIT_ARRAY);
		preinitarray_sec->set_flags(SHF_ALLOC | SHF_WRITE);
		preinitarray_sec->set_overlay(data_sec->get_index());
		preinitarray_sec->set_addr_align(8);
		preinitarray_sec->set_address(base + dt_value);
	}

	if (!dt_get(dynamic, DT_STRTAB, &dt_value))
		strtab_sec->set_address(base + dt_value);

	if (!dt_get(dynamic, DT_STRSZ, &dt_value))
		strtab_sec->set_size(dt_value);

	if (!dt_get(dynamic, DT_SYMTAB, &dt_value))
		symtab_sec->set_address(base + dt_value);

	if (!dt_get(dynamic, DT_HASH, &dt_value))
	{
		u32 nbucket = getle32(ctx->buffer + dt_value);
		u32 nchain = getle32(ctx->buffer + dt_value + sizeof(nbucket));

		symtab_sec->set_size(nchain * symtab_sec->get_entry_size());
		hash_sec->set_address(base + dt_value);
		hash_sec->set_size(sizeof(nbucket) + sizeof(nchain) + (nbucket * sizeof(u32)) + (nchain * sizeof(u32)));
	}

	if (!dt_get(dynamic, DT_PLTGOT, &dt_value))
		got_sec->set_address(base + dt_value);

	u32 plt_prologue_size = 8 * sizeof(u32);

	if (!dt_get(dynamic, DT_GNU_HASH, &dt_value))
	{
		gnuhash_sec->set_address(base + dt_value);
		u32 dynsymcount = symtab_sec->get_size() / symtab_sec->get_entry_size();

		u32 nbuckets = getle32(ctx->buffer + dt_value);
		u32 symndx = getle32(ctx->buffer + dt_value + sizeof(nbuckets));
		u32 maskwords = getle32(ctx->buffer + dt_value + sizeof(nbuckets) + sizeof(symndx));

		u32 header_size = sizeof(nbuckets) + sizeof(symndx) + sizeof(maskwords) + sizeof(u32);
		u32 bloom_filter_size = sizeof(u64) * maskwords;
		u32 buckets_size = sizeof(u32) * nbuckets;
		u32 values_size = sizeof(u32) * (dynsymcount - symndx);

		gnuhash_sec->set_size(header_size + bloom_filter_size + buckets_size + values_size);
	}

	u64 relplt_start = 0;
	u64 relplt_size = 0;

	u64 reldyn_start = 0;
	u64 reldyn_size = 0;

	if (!dt_get(dynamic, DT_JMPREL, &dt_value))
		relplt_start = base + dt_value;

	if(base == 0) relplt_sec->set_address(relplt_start);

	s64 plt_start = 0;

	s64 plt_search = ctx->meta->text_offset;
	while (plt_search < ctx->meta->data_offset)
	{
		u8* code = ctx->buffer + plt_search;

		u32 buffer[] = { 0xA9BF7BF0, 0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF, 0xD61F0220, 0xD503201F, 0xD503201F, 0xD503201F };
		int buffer_words = buffer_words = sizeof(buffer) / sizeof(u32);

		bool fail = false;

		for (int i = 0; i < buffer_words; i++)
		{
			if (buffer[i] == 0xFFFFFFFF)
			{
				code += sizeof(u32);
				continue;
			}

			if (getle32(code) != buffer[i]) fail = true;
			code += sizeof(u32);
		}

		if (!fail)
		{
			plt_start = plt_search;
			break;
		}

		plt_search += sizeof(u32);
	}

	if (!dt_get(dynamic, DT_PLTRELSZ, &dt_value))
	{
		relplt_size = dt_value;
		if(base == 0) relplt_sec->set_size(dt_value);
		u32 entries = dt_value / plt_entry;

		plt_sec->set_size((entries * plt_sec->get_entry_size()) + plt_prologue_size);
		plt_sec->set_address(base + plt_start);
	}

	if (!dt_get(dynamic, DT_REL, &dt_value) || !dt_get(dynamic, DT_RELA, &dt_value))
		reldyn_start = base + dt_value;
	if (base == 0) reldyn_sec->set_address(reldyn_start);

	if (!dt_get(dynamic, DT_RELSZ, &dt_value) || !dt_get(dynamic, DT_RELASZ, &dt_value))
		reldyn_size = dt_value;
	if (base == 0) reldyn_sec->set_size(reldyn_size);

	if (!dt_get(dynamic, DT_INIT_ARRAYSZ, &dt_value))
		initarray_sec->set_size(dt_value);

	if (!dt_get(dynamic, DT_FINI_ARRAYSZ, &dt_value))
		finiarray_sec->set_size(dt_value);

	if (!dt_get(dynamic, DT_PREINIT_ARRAYSZ, &dt_value))
		preinitarray_sec->set_size(dt_value);

	struct {
		u8* rel;
		u64 rel_size;
	} rel_sections[] = {
		{ ctx->buffer + relplt_start - base, relplt_size },
		{ ctx->buffer + reldyn_start - base, reldyn_size },

		{ NULL, 0 },
	};

	u64 max = 0;

	// Glorious hack to find the end of .got.
	for (int i = 0; rel_sections[i].rel != NULL; i++)
	{
		while (rel_sections[i].rel_size != 0)
		{
			Elf64_Rela* rel64 = (Elf64_Rela*)rel_sections[i].rel;

			u64 offset = getle64((u8*)&rel64->r_offset);
			if (offset > max) max = offset;

			if (plt_rel == DT_REL)
			{
				rel_sections[i].rel += sizeof(Elf64_Rel);
				rel_sections[i].rel_size -= sizeof(Elf64_Rel);
			}
			else
			{
				rel_sections[i].rel += sizeof(Elf64_Rela);
				rel_sections[i].rel_size -= sizeof(Elf64_Rela);
			}
		}
	}

	max += sizeof(u64);
	got_sec->set_size(max - (got_sec->get_address() - base));

	if (base == 0)
	{
		reldyn_sec->set_data((const char*)ctx->buffer + reldyn_start - base, reldyn_size);
		relplt_sec->set_data((const char*)ctx->buffer + relplt_start - base, relplt_size);
	}

	u8* dyn = ctx->buffer + dynamic_sec->get_address() - base;
	u64 dyn_size = dynamic_sec->get_size();

	while (dyn_size != 0)
	{
		u64 tag = 0;
		u64 value = 0;

		tag = getle64(dyn);
		dyn += sizeof(u64);
		dyn_size -= sizeof(u64);

		value = getle64(dyn);

		switch (tag)
		{
			case DT_INIT:
			case DT_FINI:
			case DT_INIT_ARRAY:
			case DT_FINI_ARRAY:
			case DT_PREINIT_ARRAY:
			case DT_HASH:
			case DT_GNU_HASH:
			case DT_STRTAB:
			case DT_SYMTAB:
			case DT_PLTGOT:
			case DT_JMPREL:
			case DT_REL:
			case DT_RELA:
			case DT_VERDEF:
			case DT_VERSYM:
				value += base;
				break;

			default: break;
		}

		putle64(dyn, value);
		dyn += sizeof(u64);
		dyn_size -= sizeof(u64);
	}

	dynamic_sec->set_data((const char*)ctx->buffer + dynamic_sec->get_address() - base, dynamic_sec->get_size());

	// Fix up symbol section indices.
	u8* sym = ctx->buffer + symtab_sec->get_address() - base;
	u64 sym_size = symtab_sec->get_size();

	int sym_index = 0;
	int sym_non_local = -1;
	while (sym_size != 0)
	{
		Elf64_Sym* sym64 = (Elf64_Sym*)sym;
		u64 value = getle64((u8*)&sym64->st_value);
		u16 index = getle16((u8*)&sym64->st_shndx);

		if (ELF_ST_BIND(sym64->st_info) != STB_LOCAL && sym_non_local == -1)
			sym_non_local = sym_index;

		if (index != 0)
		{
			if (value >= ctx->meta->text_offset && value <= ctx->meta->text_offset + ctx->meta->text_size)
				putle16((u8*)&sym64->st_shndx, text_sec->get_index());
			else if (value >= ctx->meta->ro_offset && value <= ctx->meta->ro_offset + ctx->meta->ro_size)
				putle16((u8*)&sym64->st_shndx, ro_sec->get_index());
			else if (value >= ctx->meta->data_offset && value <= ctx->meta->data_offset + ctx->meta->data_size)
				putle16((u8*)&sym64->st_shndx, data_sec->get_index());
			else if (value >= ctx->meta->data_offset + ctx->meta->data_size && value <= ctx->meta->data_offset + ctx->meta->data_size + ctx->meta->bss_size)
				putle16((u8*)&sym64->st_shndx, bss_sec->get_index());
		}

		if (value != 0 && value < base)
		{
			value += base;
			putle64((u8*)&sym64->st_value, value);
		}

		sym += sizeof(Elf64_Sym);
		sym_size -= sizeof(Elf64_Sym);

		sym_index++;
	}
	symtab_sec->set_info(sym_non_local);

	// Set the actual data so that accessors work.
	strtab_sec->set_data((const char*)ctx->buffer + strtab_sec->get_address() - base, strtab_sec->get_size());
	symtab_sec->set_data((const char*)ctx->buffer + symtab_sec->get_address() - base, symtab_sec->get_size());

	symbol_section_accessor symtab(*elf, symtab_sec);

	section* framehdr_sec = NULL;
	section* frame_sec = NULL;
	section* except_sec = NULL;

	section* exidx_sec = NULL;
	section* extab_sec = NULL;

	framehdr_sec = elf->sections.add(".eh_frame_hdr");
	{
		framehdr_sec->set_type(SHT_PROGBITS);
		framehdr_sec->set_flags(SHF_ALLOC);
	
		framehdr_sec->set_address(base + ctx->meta->mod_offset + (s32)getle32(header->unwind_start));
		framehdr_sec->set_size((s32)getle32(header->unwind_end) - (s32)getle32(header->unwind_start));

		framehdr_sec->set_overlay(ro_sec->get_index());
		framehdr_sec->set_addr_align(4);
	}

	bool fail = false;

	const u8* framehdr = ctx->buffer + framehdr_sec->get_address() - base;

	u8 version = *framehdr++;
	u8 eh_frame_ptr_enc = *framehdr++;
	u8 fde_count_enc = *framehdr++;
	u8 table_enc = *framehdr++;

	if (version != 1 || eh_frame_ptr_enc == 0xFF)
		fail = true;

	u8* frame = NULL;

	if (!fail)
	{
		u64 out = eh_value_decode(ctx, eh_frame_ptr_enc, &framehdr, framehdr_sec->get_address() - base);
		frame = ctx->buffer + out;

		frame_sec = elf->sections.add(".eh_frame");
		{
			frame_sec->set_type(SHT_PROGBITS);
			frame_sec->set_flags(SHF_ALLOC);

			frame_sec->set_address(base + (frame - ctx->buffer));

			u8* entry = frame;
			while (true)
			{
				u32 size32 = getle32(entry);
				entry += sizeof(size32);

				u64 size = size32;

				if (size32 == 0xFFFFFFFF)
					size = getle64(entry);

				entry += size;
				if (size == 0) break;
			}
			frame_sec->set_size(entry - frame);

			frame_sec->set_overlay(ro_sec->get_index());
			frame_sec->set_addr_align(0x10);
		}
	}

	if (!fail)
	{
		// We can locate the start of .gcc_except_table by looking for the lowest LSDA address.
		// To find the end, we get the highest address, and then process the LSDA at that address to figure out its size.
		const u8* start = frame;
		u64 hdr_offset = start - ctx->buffer;

		cie_data cie;
		fde_data fde;
		lsda_data lsda;

		u64 lowest = U64_MAX;
		u64 highest = 0;

		fail = true;

		while (true)
		{
			int res = eh_frame_parse(ctx, frame, hdr_offset, &cie, &fde);

			// Entry size was zero. End of section.
			if (res == 0) break;

			else if (res == -1)
			{
				fail = true;
				break;
			}

			// Entry was CIE.
			else if (res == 1)
				frame += cie.size;

			// Entry was FDE.
			else if (res == 2)
				frame += fde.size;

			// FDE with an LSDA address.
			if (res == 2 && fde.lsda_address != 0)
			{
				if (fde.lsda_address < lowest)
					lowest = fde.lsda_address;
				if (fde.lsda_address > highest)
					highest = fde.lsda_address;
				fail = false;
			}
		}

		if (!fail)
		{
			int res = eh_lsda_parse(ctx, ctx->buffer + highest, &lsda);
			if (res == 0)
			{
				except_sec = elf->sections.add(".gcc_except_table");
				{
					except_sec->set_type(SHT_PROGBITS);
					except_sec->set_flags(SHF_ALLOC);

					except_sec->set_address(base + lowest);
					except_sec->set_size((highest + lsda.size) - lowest);

					except_sec->set_overlay(ro_sec->get_index());
					except_sec->set_addr_align(4);
				}
			}
		}
	}

	// Finalize main sections.
	{
		text_sec->set_data((const char*)ctx->text, ctx->meta->text_size);
		text_seg->add_section_index(text_sec->get_index(), text_sec->get_addr_align());

		ro_sec->set_data((const char*)ctx->ro, ctx->meta->ro_size);
		ro_seg->add_section_index(ro_sec->get_index(), ro_sec->get_addr_align());

		data_sec->set_data((const char*)ctx->data, ctx->meta->data_size);
		data_seg->add_section_index(data_sec->get_index(), data_sec->get_addr_align());

		bss_sec->set_size(ctx->meta->bss_size);
		bss_seg->add_section_index(bss_sec->get_index(), bss_sec->get_addr_align());
	}

	// Finalize overlay sections.
	{
		ro_seg->add_section_index(strtab_sec->get_index(), strtab_sec->get_addr_align());
		ro_seg->add_section_index(symtab_sec->get_index(), symtab_sec->get_addr_align());

		data_seg->add_section_index(dynamic_sec->get_index(), dynamic_sec->get_addr_align());

		ro_seg->add_section_index(hash_sec->get_index(), hash_sec->get_addr_align());
		data_seg->add_section_index(got_sec->get_index(), got_sec->get_addr_align());
		text_seg->add_section_index(plt_sec->get_index(), plt_sec->get_addr_align());

		if (base == 0)
		{
			ro_seg->add_section_index(reldyn_sec->get_index(), reldyn_sec->get_addr_align());
			ro_seg->add_section_index(relplt_sec->get_index(), relplt_sec->get_addr_align());
		}

		if (gnuhash_sec) ro_seg->add_section_index(gnuhash_sec->get_index(), gnuhash_sec->get_addr_align());

		if (initarray_sec) data_seg->add_section_index(initarray_sec->get_index(), initarray_sec->get_addr_align());
		if (finiarray_sec) data_seg->add_section_index(finiarray_sec->get_index(), finiarray_sec->get_addr_align());
		if (preinitarray_sec) data_seg->add_section_index(preinitarray_sec->get_index(), preinitarray_sec->get_addr_align());

		ro_seg->add_section_index(framehdr_sec->get_index(), framehdr_sec->get_addr_align());
		if (frame_sec) ro_seg->add_section_index(frame_sec->get_index(), frame_sec->get_addr_align());
		if (except_sec) ro_seg->add_section_index(except_sec->get_index(), except_sec->get_addr_align());
	}
}

void mod_discover(mod_context* ctx)
{
	elfio* elf = (elfio*)ctx->elf;
	mod_header* header = ctx->header;

	// This is what we want.
	s64 text_start = 0;
	s64 rodata_start = 0;
	s64 data_start = 0;
	s64 bss_start = 0;
	s64 bss_end = 0;

	elf->create(ELFCLASS64, ELFDATA2LSB);
	elf->set_os_abi(ELFOSABI_NONE);
	elf->set_type(ET_DYN);
	elf->set_machine(EM_AARCH64);
	elf->set_entry(0);

	section* dynamic_sec = elf->sections.add(".dynamic");
	{
		dynamic_sec->set_type(SHT_DYNAMIC);
		dynamic_sec->set_flags(SHF_ALLOC | SHF_WRITE);

		dynamic_sec->set_entry_size(elf->get_default_entry_size(SHT_DYNAMIC));

		// We don't have the true size for the .dynamic section, but it will always end on a DT_NULL.
		u32 dynamic_size = 0;
		u8* dynamic_buffer = ctx->dynamic;
		while (true)
		{
			u64 tag = getle64(dynamic_buffer);
			dynamic_size += elf->get_default_entry_size(SHT_DYNAMIC);
			if (tag == DT_NULL) break;
			dynamic_buffer += elf->get_default_entry_size(SHT_DYNAMIC);
		}

		// Set the actual data so that accessors work.
		dynamic_sec->set_data((const char*)ctx->dynamic, dynamic_size);
		dynamic_sec->set_address(ctx->meta->mod_offset + (s32)getle32(header->dynamic));

		dynamic_sec->set_addr_align(8);
	}

	dynamic_section_accessor dynamic(*elf, dynamic_sec);

	s64 framehdr_address = ctx->meta->mod_offset + (s32)getle32(header->unwind_start);
	s64 framehdr_size = (s32)getle32(header->unwind_end) - (s32)getle32(header->unwind_start);

	s64 frame_address = 0;
	s64 frame_size = 0;

	bool fail = false;

	const u8* framehdr = ctx->buffer + framehdr_address;

	u8 version = *framehdr++;
	u8 eh_frame_ptr_enc = *framehdr++;
	u8 fde_count_enc = *framehdr++;
	u8 table_enc = *framehdr++;

	if (version != 1 || eh_frame_ptr_enc == 0xFF)
		fail = true;

	u8* frame = NULL;

	if (!fail)
	{
		u64 out = eh_value_decode(ctx, eh_frame_ptr_enc, &framehdr, framehdr_address);
		frame = ctx->buffer + out;

		frame_address = frame - ctx->buffer;

		u8* entry = frame;
		while (true)
		{
			u32 size32 = getle32(entry);
			entry += sizeof(size32);

			u64 size = size32;

			if (size32 == 0xFFFFFFFF)
				size = getle64(entry);

			entry += size;
			if (size == 0) break;
		}

		frame_size = entry - frame;
	}

	data_start = frame_address + frame_size;
	if (memcmp(ctx->buffer + data_start, "MOD", 3) == 0)
		data_start += sizeof(mod_header);

	data_start = align64(data_start, 0x1000);

	bss_start = ctx->meta->mod_offset + (s32)getle32(header->bss_start);

	s64 plt_start = 0;
	s64 plt_size = 0;

	s64 offset = text_start;
	s64 end = data_start;
	while (offset < end)
	{
		u8* code = ctx->buffer + offset;

		u32 buffer[] = {0xA9BF7BF0, 0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF, 0xD61F0220, 0xD503201F, 0xD503201F, 0xD503201F};
		int buffer_words = sizeof(buffer) / sizeof(u32);

		bool fail = false;

		for (int i = 0; i < buffer_words; i++)
		{
			if (buffer[i] == 0xFFFFFFFF)
			{
				code += sizeof(u32);
				continue;
			}

			if (getle32(code) != buffer[i]) fail = true;
			code += sizeof(u32);
		}

		if (!fail)
		{
			plt_start = offset;
			break;
		}

		offset += sizeof(u32);
	}

	Elf_Xword dt_value = 0;

	u64 plt_entry_size = 4 * sizeof(u32);
	u64 relplt_entry_size = 0;

	if (!dt_get(dynamic, DT_PLTREL, &dt_value))
	{
		if (dt_value == DT_REL)
			relplt_entry_size = elf->get_default_entry_size(SHT_REL);
		else if (dt_value == DT_RELA)
			relplt_entry_size = elf->get_default_entry_size(SHT_RELA);
	}

	u32 plt_prologue_size = 8 * sizeof(u32);

	if (!dt_get(dynamic, DT_PLTRELSZ, &dt_value))
	{
		u32 entries = dt_value / relplt_entry_size;
		plt_size = (entries * plt_entry_size) + plt_prologue_size;
	}

	rodata_start = plt_start + plt_size;
	rodata_start = align64(rodata_start, 0x1000);

	ctx->meta->text_offset = text_start,
	ctx->meta->text_size = rodata_start - text_start;
	ctx->meta->ro_offset = rodata_start;
	ctx->meta->ro_size = data_start - rodata_start;
	ctx->meta->data_offset = data_start;
	ctx->meta->data_size = bss_start - data_start;
	ctx->meta->bss_size = ctx->size - bss_start;

	ctx->elf = NULL;
}

void mod_read(mod_context* ctx, u32 actions)
{
	if (ctx->haveread == 0)
	{
		if (!ctx->buffer) return;

		ctx->header = (mod_header*)(ctx->buffer + ctx->meta->mod_offset);
		ctx->dynamic = ctx->buffer + ctx->meta->mod_offset + (s32)getle32(ctx->header->dynamic);

		if (ctx->discover)
		{
			mod_discover(ctx);
			return;
		}

		ctx->text = ctx->buffer + ctx->meta->text_offset;
		ctx->ro = ctx->buffer + ctx->meta->ro_offset;
		ctx->data = ctx->buffer + ctx->meta->data_offset;

		mod_convert_elf(ctx);

		ctx->haveread = 1;
	}
}

void mod_save(mod_context* ctx, u32 actions)
{
	filepath* path = settings_get_elf_path(ctx->usersettings);
	if (path == 0 || path->valid == 0)
		return;

	fprintf(stdout, "Saving ELF to %s...\n", path->pathname);

	elfio* elf = (elfio*)ctx->elf;
	elf->save(path->pathname);
}

int mod_process(mod_context* ctx, u32 actions)
{
	elfio elf;
	ctx->elf = &elf;

	mod_read(ctx, actions);
	if (ctx->haveread == 0) return 0;

	if (actions & InfoFlag)
		mod_print(ctx, actions);

	if (actions & ExtractFlag)
		mod_save(ctx, actions);

	ctx->elf = NULL;

	return 1;
}

void mod_print(mod_context* ctx, u32 actions)
{
	fprintf(stdout, "\nModule %s:\n\n", ctx->name);

	mod_header* header = ctx->header;
	elfio* elf = (elfio*)ctx->elf;

	fprintf(stdout, "Header:                 %.4s\n", header->magic);

	fprintf(stdout, "Module object:          0x%08" PRIX32 "\n", ctx->meta->mod_offset + (s32)getle32(header->mod_object));
	fprintf(stdout, ".dynamic:               0x%08" PRIX32 "\n", ctx->meta->mod_offset + (s32)getle32(header->dynamic));
	fprintf(stdout, ".bss:                   0x%08" PRIX32 " (0x%" PRIX32 " bytes)\n", ctx->meta->mod_offset + (s32)getle32(header->bss_start), (s32)getle32(header->bss_end) - (s32)getle32(header->bss_start));
	fprintf(stdout, ".eh_frame_hdr:          0x%08" PRIX32 " (0x%" PRIX32 " bytes)\n\n", ctx->meta->mod_offset + (s32)getle32(header->unwind_start), (s32)getle32(header->unwind_end) - (s32)getle32(header->unwind_start));

	dump::header(std::cout, *elf);
	dump::segment_headers(std::cout, *elf);
	dump::section_headers(std::cout, *elf);
	if (actions & VerboseFlag)
		dump::symbol_tables(std::cout, *elf);
}
