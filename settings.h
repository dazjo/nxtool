#ifndef _SETTINGS_H_
#define _SETTINGS_H_

#include "filepath.h"
#include "types.h"
#include "keyset.h"

#ifdef __cplusplus
extern "C" {
#endif

typedef struct
{
	keyset keys;
	filepath elfpath;
} settings;

void settings_init(settings* usersettings);

filepath* settings_get_elf_path(settings* usersettings);

rsakey* settings_get_nrrrsakey(settings* usersettings);

void settings_set_elf_path(settings* usersettings, const char* path);

#ifdef __cplusplus
}
#endif

#endif // _SETTINGS_H_
