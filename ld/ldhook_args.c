#include "ldhook_args.h"

#include <sqlite3.h>
#include <cjson/cJSON.h>

#define __log(...)                  \
    do                              \
    {                               \
        fprintf(stderr,##__VA_ARGS__);        \
    } while(0)      
 
#define __format(__fmt__) "[-] %s: %d " __fmt__ "\n"
 
#define log(__fmt__, ...)                                  \
    do                                                     \
    {                                                      \
        __log(__format(__fmt__),__FILE__,__LINE__,##__VA_ARGS__);  \
    }while(0)

#define CHECK(exp)                                        \
    do                                                    \
    {                                                     \
        if(!(exp))                                        \
        {                                                 \
            log("check failed: %s", #exp);                \
            return;                                    \
        }                                                 \
    }while(0)



#define CREATE_TABLE "CREATE TABLE IF NOT EXISTS t_commands(\
                        id INTEGER PRIMARY KEY AUTOINCREMENT, \
                        runtime_uuid TEXT, \
                        timestamp INTEGER, \
                        output TEXT, \
                        cmdline TEXT, \
                        arg_idx INTEGER, \
                        opt_idx INTEGER, \
                        opt_name TEXT, \
                        warn_message TEXT, \
                        arg TEXT, \
                        orig_option_with_args_text TEXT, \
                        canonical_option_0 TEXT, \
                        canonical_option_1 TEXT, \
                        canonical_option_2 TEXT, \
                        canonical_option_3 TEXT, \
                        canonical_option_num_elements INTEGER, \
                        value TEXT, \
                        errors TEXT)"

sqlite3 *db;
cJSON *json;

cJSON* cJSON_AddStringOtherwiseNullToObject(cJSON * const object, const char * const name, const char * const string);
cJSON* cJSON_AddStringOtherwiseNullToObject(cJSON * const object, const char * const name, const char * const string) {
    if (string) {
        return cJSON_AddStringToObject(object, name, string);
    } else {
        return cJSON_AddNullToObject(object, name);
    }
}


void new_db()
{
  db = sqlite3_open("test.db", &db);
}

void input_file_hook(char *name)
{
  printf("input_file_name: %s\n", name);
}

void option_hook()
{
  cJSON *command_line_obj;
  cJSON *auxiliary_filters_arr;
  cJSON *config_obj;
  /* if json not exist, create it */
  if (!json) {
    CHECK(json = cJSON_CreateObject());
  }


  /* add elements with basic types */
  CHECK(cJSON_AddBoolToObject(json, "force_make_executable", force_make_executable));
  CHECK(cJSON_AddStringOtherwiseNullToObject(json, "default_target", default_target));
  CHECK(cJSON_AddStringOtherwiseNullToObject(json, "output_filename", output_filename));
  CHECK(cJSON_AddStringOtherwiseNullToObject(json, "program_name", program_name));
  CHECK(cJSON_AddStringOtherwiseNullToObject(json, "ld_sysroot", ld_sysroot));
  CHECK(cJSON_AddStringOtherwiseNullToObject(json, "ld_canon_sysroot", ld_canon_sysroot));
  CHECK(cJSON_AddNumberToObject(json, "ld_canon_sysroot_len", ld_canon_sysroot_len));
  CHECK(cJSON_AddNumberToObject(json, "g_switch_value", g_switch_value));
  CHECK(cJSON_AddNumberToObject(json, "trace_files", trace_files));
  CHECK(cJSON_AddBoolToObject(json, "verbose", verbose));
  CHECK(cJSON_AddBoolToObject(json, "version_printed", version_printed));
  CHECK(cJSON_AddBoolToObject(json, "demangling", demangling));
  CHECK(cJSON_AddNumberToObject(json,"sort_section", sort_section));

  /* serialize args_type command_line */
  CHECK(command_line_obj = cJSON_CreateObject());
  cJSON_AddItemToObject(json, "command_line", command_line_obj);
  CHECK(cJSON_AddBoolToObject(command_line_obj, "force_common_definition", command_line.force_common_definition));
  CHECK(cJSON_AddBoolToObject(command_line_obj, "embedded_relocs", command_line.embedded_relocs));
  CHECK(cJSON_AddBoolToObject(command_line_obj, "force_exe_suffix", command_line.force_exe_suffix));
  CHECK(cJSON_AddBoolToObject(command_line_obj, "cref", command_line.cref));
  CHECK(cJSON_AddBoolToObject(command_line_obj, "warn_mismatch", command_line.warn_mismatch));
  CHECK(cJSON_AddBoolToObject(command_line_obj, "warn_search_mismatch", command_line.warn_search_mismatch));
  CHECK(cJSON_AddNumberToObject(command_line_obj, "check_section_addresses", command_line.check_section_addresses));
  CHECK(cJSON_AddBoolToObject(command_line_obj, "accept_unknown_input_arch", command_line.accept_unknown_input_arch));
  CHECK(cJSON_AddStringOtherwiseNullToObject(command_line_obj, "out_implib_filename", command_line.out_implib_filename));
  CHECK(cJSON_AddBoolToObject(command_line_obj, "print_output_format", command_line.print_output_format));
  CHECK(cJSON_AddBoolToObject(command_line_obj, "print_memory_usage", command_line.print_memory_usage));
  CHECK(cJSON_AddBoolToObject(command_line_obj, "force_group_allocation", command_line.force_group_allocation));
  CHECK(cJSON_AddNumberToObject(command_line_obj, "endian_enum", command_line.endian));
  CHECK(cJSON_AddStringOtherwiseNullToObject(command_line_obj, "interpreter", command_line.interpreter));
  CHECK(cJSON_AddStringOtherwiseNullToObject(command_line_obj, "soname", command_line.soname));
  CHECK(cJSON_AddStringOtherwiseNullToObject(command_line_obj, "rpath", command_line.rpath));
  CHECK(cJSON_AddStringOtherwiseNullToObject(command_line_obj, "rpath_link", command_line.rpath_link));
  CHECK(cJSON_AddStringOtherwiseNullToObject(command_line_obj, "filter_shlib", command_line.filter_shlib));
  CHECK(auxiliary_filters_arr = cJSON_AddArrayToObject(command_line_obj, "auxiliary_filters"));
  for(char** iter = command_line.auxiliary_filters; iter && *iter; iter++) {
    cJSON *auxiliary_filter;
    CHECK(auxiliary_filter = cJSON_CreateString(*iter));
    cJSON_AddItemToArray(auxiliary_filters_arr, auxiliary_filter);
  }
  CHECK(cJSON_AddStringOtherwiseNullToObject(command_line_obj, "version_exports_section", command_line.version_exports_section));
  CHECK(cJSON_AddStringOtherwiseNullToObject(command_line_obj, "default_script", command_line.default_script));

  /* serialize ld_config_type config */
  CHECK(config_obj = cJSON_CreateObject());
  cJSON_AddItemToObject(json, "config", config_obj);
  CHECK(cJSON_AddBoolToObject(config_obj, "magic_demand_paged", config.magic_demand_paged));
  CHECK(cJSON_AddBoolToObject(config_obj, "make_executable", config.make_executable));
  CHECK(cJSON_AddBoolToObject(config_obj, "has_shared", config.has_shared));
  CHECK(cJSON_AddBoolToObject(config_obj, "build_constructors", config.build_constructors));
  CHECK(cJSON_AddBoolToObject(config_obj, "warn_constructors", config.warn_constructors));
  CHECK(cJSON_AddBoolToObject(config_obj, "warn_common", config.warn_common));
  CHECK(cJSON_AddBoolToObject(config_obj, "warn_once", config.warn_once));
  CHECK(cJSON_AddNumberToObject(config_obj, "orphan_handling", config.orphan_handling));
  CHECK(cJSON_AddBoolToObject(config_obj, "warn_multiple_gp", config.warn_multiple_gp));
  CHECK(cJSON_AddBoolToObject(config_obj, "warn_section_align", config.warn_section_align));
  CHECK(cJSON_AddBoolToObject(config_obj, "fatal_warnings", config.fatal_warnings));
  CHECK(cJSON_AddNumberToObject(config_obj, "sort_common", config.sort_common));
  CHECK(cJSON_AddBoolToObject(config_obj, "text_read_only", config.text_read_only));
  CHECK(cJSON_AddBoolToObject(config_obj, "stats", config.stats));
  CHECK(cJSON_AddBoolToObject(config_obj, "unique_orphan_sections", config.unique_orphan_sections));
  CHECK(cJSON_AddBoolToObject(config_obj, "only_cmd_line_lib_dirs", config.only_cmd_line_lib_dirs));
  CHECK(cJSON_AddBoolToObject(config_obj, "sane_expr", config.sane_expr));
  CHECK(cJSON_AddBoolToObject(config_obj, "separate_code", config.separate_code));
  CHECK(cJSON_AddNumberToObject(config_obj, "rpath_separator", config.rpath_separator));
  CHECK(cJSON_AddStringOtherwiseNullToObject(config_obj, "map_filename", config.map_filename));
  CHECK(cJSON_AddStringOtherwiseNullToObject(config_obj, "dependency_file", config.dependency_file));
  CHECK(cJSON_AddNumberToObject(config_obj, "split_by_reloc", config.split_by_reloc));
  CHECK(cJSON_AddNumberToObject(config_obj, "split_by_file", config.split_by_file));
  CHECK(cJSON_AddNumberToObject(config_obj, "hash_table_size", config.hash_table_size));
  CHECK(cJSON_AddBoolToObject(config_obj, "print_map_discarded", config.print_map_discarded));
  CHECK(cJSON_AddBoolToObject(config_obj, "ctf_variables", config.ctf_variables));
  CHECK(cJSON_AddBoolToObject(config_obj, "ctf_share_duplicated", config.ctf_share_duplicated));

  /* for test */
  puts(cJSON_Print(json));

}

void script_hook(char *name)
{
  cJSON *script_files_arr;
  cJSON *script_file_name;

  /* if json not exist, create it */
  if (!json) {
    CHECK(json = cJSON_CreateObject());
  }

  /* if array not existing, create it */
  if (!(script_files_arr = cJSON_GetObjectItem(json, "script_files"))) {
    CHECK(script_files_arr = cJSON_AddArrayToObject(json, "script_files"));
  }
  CHECK(script_file_name = cJSON_CreateString(name));
  cJSON_AddItemToArray(script_files_arr, script_file_name);
}