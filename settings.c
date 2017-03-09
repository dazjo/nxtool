#include <stdio.h>
#include <string.h>
#include "settings.h"

void settings_init(settings* usersettings)
{
	memset(usersettings, 0, sizeof(settings));
}

filepath* settings_get_elf_path(settings* usersettings)
{
	if (usersettings)
		return &usersettings->elfpath;
	else
		return 0;
}

rsakey* settings_get_nrrrsakey(settings* usersettings)
{
	if (usersettings && usersettings->keys.nrrrsakey.keytype != RSAKEY_INVALID && usersettings->keys.nrrrsakey.keysize != RSASIZE_INVALID)
		return &usersettings->keys.nrrrsakey;
	else
		return 0;
}
void settings_set_elf_path(settings* usersettings, const char* path)
{
	filepath_set(&usersettings->elfpath, path);
}
