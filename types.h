#ifndef __TYPES_H__
#define __TYPES_H__

#include <stdint.h>
#include <inttypes.h>

typedef uint8_t			u8;
typedef uint16_t		u16;
typedef uint32_t		u32;
typedef uint64_t		u64;

typedef int8_t			s8;
typedef int16_t			s16;
typedef int32_t			s32;
typedef int64_t			s64;

#ifndef U64_MAX
#define U8_MAX			((u8)~0U)
#define S8_MAX			((s8)(U8_MAX >> 1))
#define S8_MIN			((s8)(-S8_MAX - 1))
#define U16_MAX			((u16)~0U)
#define S16_MAX			((s16)(U16_MAX >> 1))
#define S16_MIN			((s16)(-S16_MAX - 1))
#define U32_MAX			((u32)~0U)
#define S32_MAX			((s32)(U32_MAX >> 1))
#define S32_MIN			((s32)(-S32_MAX - 1))
#define U64_MAX			((u64)~0ULL)
#define S64_MAX			((s64)(U64_MAX >> 1))
#define S64_MIN			((s64)(-S64_MAX - 1))
#endif

enum flags
{
	ExtractFlag = (1<<0),
	InfoFlag = (1<<1),
	PlainFlag = (1<<2),
	VerboseFlag = (1<<3),
	VerifyFlag = (1<<4),
	RawFlag = (1<<5),
	ShowKeysFlag = (1<<6),
};

enum validstate
{
	Unchecked = 0,
	Good = 1,
	Fail = 2,
};

enum sizeunits
{
	sizeKB = 0x400,
	sizeMB = 0x100000,
};

#endif
