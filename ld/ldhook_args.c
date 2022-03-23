#include "sqlite3.h"
#include "ldhook_args.h"

void input_file_hook(char* name) {
    printf("input_file_name: %s\n", name);
}

FILE *saved_script_handle;
FILE *previous_script_handle;
bool force_make_executable;

char *default_target;
const char *output_filename;

/* Name this program was invoked by.  */
char *program_name;

/* The prefix for system library directories.  */
const char *ld_sysroot;

/* The canonical representation of ld_sysroot.  */
char *ld_canon_sysroot;
int ld_canon_sysroot_len;

/* Set by -G argument, for targets like MIPS ELF.  */
int g_switch_value;

/* Nonzero means print names of input files as processed.  */
unsigned int trace_files;

bool verbose;

bool version_printed;

bool demangling;

args_type command_line;

ld_config_type config;

sort_type sort_section;

void option_hook()
{
  printf("saved_script_handle:%p\n, previous_script_handle:%p\nforce_make_executable: %d\n"
         "output_filename: %s\nprogram_name: %s\nld_sysroot: %s\nld_canon_sysroot: %s\n"
         "ld_canon_sysroot_len: %d\ng_switch_value: %d\ntrace_files: %d\nverbose: %d\nversion_printed: %d\n"
         "demangling: %d\n",
         saved_script_handle, previous_script_handle, force_make_executable, output_filename, program_name, ld_sysroot, ld_canon_sysroot, ld_canon_sysroot_len, g_switch_value, trace_files, verbose, version_printed, demangling);
}