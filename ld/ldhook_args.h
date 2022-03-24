#ifndef LDHOOK_ARGS_H
#define LDHOOK_ARGS_H

#include "sysdep.h"
#include "bfd.h"
#include "safe-ctype.h"
#include "libiberty.h"
#include "progress.h"
#include "bfdlink.h"
#include "ctf-api.h"
#include "filenames.h"
#include "elf/common.h"
#include <limits.h>
#include "obstack.h"

#include "ld.h"
#include "ldmain.h"
#include "ldexp.h"
#include "ldlang.h"

#include <stdio.h>

void input_file_hook(char* name);
void option_hook(void);
void script_hook(char* name);
void main_init_hook(int argc, char **argv);


#endif