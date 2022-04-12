
#include "ldhook_args.h"
#include "sqlite3.h"
#include "cJSON.h"
#include "uuid4.h"

#define LDHOOK_DEBUG

#ifdef LDHOOK_DEBUG
#define __log(...)                  \
    do                              \
    {                               \
        fprintf(stderr,##__VA_ARGS__);        \
    } while(0)      
#else
#define __log(...) \
  do  \
  { \
    ; \
  } while (0)
#endif
 
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
            ldhook_status = failed; \
            return;                                    \
        }                                                 \
    }while(0)



#define CREATE_TABLE "CREATE TABLE IF NOT EXISTS t_link(\
                        id INTEGER PRIMARY KEY AUTOINCREMENT, \
                        runtime_uuid TEXT, \
                        timestamp INTEGER, \
                        pwd TEXT, \
                        proj_root TEXT, \
                        output TEXT, \
                        cmdline TEXT, \
                        traced BOOLEAN, \
                        gcc_runtime_uuid TEXT, \
                        json TEXT)"

#ifdef CLEAN_SQL
#define CLEAN(str)                                                \
    char *clean_##str;                                             \
    CHECK(clean_##str = sql_clean_string(str)); 
#endif

char *dbpath;
sqlite3 *db;
cJSON *json;
char runtime_uuid[UUID4_LEN];
uint64_t runtime_timestamp;
char *cmd;
char *proj_root;
int traced;
char *gcc_runtime_uuid;
char *archive;
enum LDHOOK_STATUS ldhook_status;


int maybe_init_ldhook(){
  if(ldhook_status == uninitialized){
    // See if COMPILE_COMMANDS_DB is set
    dbpath = getenv("COMPILE_COMMANDS_DB");
    if(dbpath == NULL){
      ldhook_status = blocked;
      return -1;
    }

    // See if we are being traced
    gcc_runtime_uuid = getenv("GCC_RUNTIME_UUID");
    if(gcc_runtime_uuid == NULL){
      traced = 0;
      gcc_runtime_uuid = malloc(0x10);
      memset(gcc_runtime_uuid, 0, 0x10);
    }
    else{
      traced = 1;
    }

    // See if PROJ_ROOT is set
    proj_root = getenv("PROJ_ROOT");
    if(proj_root==NULL){
      proj_root = malloc(0x10);
      memset(proj_root, 0, 0x10);
    }

    // See if ARCHIVE is set
    archive = getenv("ARCHIVE");
    if (archive == NULL){
      archive = malloc(0x10);
      memset(archive, 0, 0x10);
    }

    ldhook_status = initialized;
  }
  else if(ldhook_status == initialized){
    return 1;
  }
  else if(ldhook_status == blocked){
    return -1;
  }
  else if(ldhook_status == failed){
    return -1;
  }
  else{
    log("unknown ldhook_status: %d", ldhook_status);
    return -1;
  }
}

cJSON* cJSON_AddStringOtherwiseNullToObject(cJSON * const object, const char * const name, const char * const string);
cJSON* cJSON_AddStringOtherwiseNullToObject(cJSON * const object, const char * const name, const char * const string) {
    if (string) {
        return cJSON_AddStringToObject(object, name, string);
    } else {
        return cJSON_AddNullToObject(object, name);
    }
}

/* Get the absolute path of input file, return value should be freed manually*/
char * get_absolute_path(const char *path) {
  char *abspath;
  int is_lib;
  while (*path == ' ') {
    path++;
  }
  if (*path == '/') {
    CHECK(abspath = strdup(path));
    return abspath;
  }
  if(!memcmp(path, "-l", 2)) {
    is_lib = 1;
    path += 2;
    // FIXME: should resolve to absolute path
    CHECK(abspath = strdup(path));
    return abspath;
  }
  else
  {
    is_lib = 0;
    CHECK(abspath = (char *)calloc(PATH_MAX, 1));
    CHECK(getcwd(abspath, PATH_MAX));
    CHECK(strlen(abspath) + strlen(path) + 1 < PATH_MAX);
    strcat(abspath, "/");
    strcat(abspath, path);
    return abspath;
  }
}

/* Generate a runtime_uuid */
void gen_uuid()
{
  uuid4_init();
  uuid4_generate(runtime_uuid);
  return;
}

/* Get the current timestamp */
void get_timestamp() { 
    struct timeval tv;
    gettimeofday(&tv, NULL);
    runtime_timestamp = tv.tv_sec * 1000 + tv.tv_usec / 1000;
  return;
}

int arg_hook_sqlite_busy_handler(void *data, int n_retries){
    int sleep = (rand() % 10) * 1000;
    usleep(sleep);
    return 1;
}

int db_init()
{
  srand(time(NULL));
  int rc = sqlite3_open(dbpath, &db);
  if (rc != SQLITE_OK) {
    log("SQL error: Can't open database: %s", sqlite3_errmsg(db));
    sqlite3_close(db);
    return 0;
  }

  sqlite3_busy_handler(db, arg_hook_sqlite_busy_handler, NULL);

  rc = sqlite3_exec(db, CREATE_TABLE, NULL, NULL, NULL);
  if (rc != SQLITE_OK) {
    log("SQL error: Can't create table");
    sqlite3_close(db);
    return 0;
  }
  return 1;
}


void input_file_hook(char *name)
{
  if(maybe_init_ldhook() == -1){
    return;
  }
  // TODO
  // printf("input_file_name: %s\n", name);
}

#ifdef CLEAN_SQL
char *sql_clean_string(const char *string) {
  char *clean_string = (char *)calloc(strlen(string) * 2 + 1, 1);
  CHECK(clean_string != NULL);
  int i = 0, j = 0;
  for (i = 0; i < strlen(string); i++, j++) {
    if (string[i] == '\'') {
      clean_string[j++] = '\'';
      clean_string[j] = '\'';
    } else if (string[i] == '\"') {
      clean_string[j++] = '\"';
      clean_string[j] = '\"';
    } else {
      clean_string[j] = string[i];
    }
  }
  return clean_string;
}
#endif


void option_hook()
{
  cJSON *command_line_obj;
  cJSON *auxiliary_filters_arr;
  cJSON *config_obj;
  cJSON *link_info_obj;
  cJSON *input_file_arr;
  lang_input_statement_type *search;

  if(maybe_init_ldhook() == -1){
    return;
  }

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

  /* serialize bfd_link_info link_info */
  CHECK(link_info_obj = cJSON_CreateObject());
  cJSON_AddItemToObject(json, "link_info", link_info_obj);
  CHECK(cJSON_AddNumberToObject(link_info_obj, "type", link_info.type));
  CHECK(cJSON_AddBoolToObject(link_info_obj, "symbolic", link_info.symbolic));
  CHECK(cJSON_AddBoolToObject(link_info_obj, "export_dynamic", link_info.export_dynamic));
  CHECK(cJSON_AddBoolToObject(link_info_obj, "create_default_symver", link_info.create_default_symver));
  CHECK(cJSON_AddBoolToObject(link_info_obj, "gc_sections", link_info.gc_sections));
  CHECK(cJSON_AddBoolToObject(link_info_obj, "gc_keep_exported", link_info.gc_keep_exported));
  CHECK(cJSON_AddBoolToObject(link_info_obj, "notice_all", link_info.notice_all));
  CHECK(cJSON_AddBoolToObject(link_info_obj, "lto_plugin_active", link_info.lto_plugin_active));
  CHECK(cJSON_AddBoolToObject(link_info_obj, "lto_all_symbols_read", link_info.lto_all_symbols_read));
  CHECK(cJSON_AddBoolToObject(link_info_obj, "strip_discarded", link_info.strip_discarded));
  CHECK(cJSON_AddBoolToObject(link_info_obj, "dynamic_data", link_info.dynamic_data));
  CHECK(cJSON_AddBoolToObject(link_info_obj, "resolve_section_groups", link_info.resolve_section_groups));
  CHECK(cJSON_AddBoolToObject(link_info_obj, "big_endian", link_info.big_endian));
  CHECK(cJSON_AddNumberToObject(link_info_obj, "strip", link_info.strip));
  CHECK(cJSON_AddNumberToObject(link_info_obj, "discard", link_info.discard));
  CHECK(cJSON_AddNumberToObject(link_info_obj, "elf_stt_common", link_info.elf_stt_common));
  CHECK(cJSON_AddNumberToObject(link_info_obj, "common_skip_ar_symbols", link_info.common_skip_ar_symbols));
  CHECK(cJSON_AddNumberToObject(link_info_obj, "unresolved_syms_in_objects", link_info.unresolved_syms_in_objects));
  CHECK(cJSON_AddNumberToObject(link_info_obj, "unresolved_syms_in_shared_libs", link_info.unresolved_syms_in_shared_libs));
  CHECK(cJSON_AddBoolToObject(link_info_obj, "warn_unresolved_syms", link_info.warn_unresolved_syms));
  CHECK(cJSON_AddBoolToObject(link_info_obj, "static_link", link_info.static_link));
  CHECK(cJSON_AddBoolToObject(link_info_obj, "keep_memory", link_info.keep_memory));
  CHECK(cJSON_AddBoolToObject(link_info_obj, "emitrelocations", link_info.emitrelocations));
  CHECK(cJSON_AddBoolToObject(link_info_obj, "relro", link_info.relro));
  CHECK(cJSON_AddBoolToObject(link_info_obj, "enable_dt_relr", link_info.enable_dt_relr));
  CHECK(cJSON_AddBoolToObject(link_info_obj, "separate_code", link_info.separate_code));
  CHECK(cJSON_AddNumberToObject(link_info_obj, "eh_frame_hdr_type", link_info.eh_frame_hdr_type));
  CHECK(cJSON_AddNumberToObject(link_info_obj, "textrel_check", link_info.textrel_check));
  CHECK(cJSON_AddBoolToObject(link_info_obj, "emit_hash", link_info.emit_hash));
  CHECK(cJSON_AddBoolToObject(link_info_obj, "emit_gnu_hash", link_info.emit_gnu_hash));
  CHECK(cJSON_AddBoolToObject(link_info_obj, "reduce_memory_overheads", link_info.reduce_memory_overheads));
  CHECK(cJSON_AddBoolToObject(link_info_obj, "traditional_format", link_info.traditional_format));
  CHECK(cJSON_AddBoolToObject(link_info_obj, "combreloc", link_info.combreloc));
  CHECK(cJSON_AddBoolToObject(link_info_obj, "default_imported_symver", link_info.default_imported_symver));
  CHECK(cJSON_AddBoolToObject(link_info_obj, "new_dtags", link_info.new_dtags));
  CHECK(cJSON_AddBoolToObject(link_info_obj, "no_ld_generated_unwind_info", link_info.no_ld_generated_unwind_info));
  CHECK(cJSON_AddBoolToObject(link_info_obj, "task_link", link_info.task_link));
  CHECK(cJSON_AddBoolToObject(link_info_obj, "allow_multiple_definition", link_info.allow_multiple_definition));
  CHECK(cJSON_AddBoolToObject(link_info_obj, "prohibit_multiple_definition_absolute", link_info.prohibit_multiple_definition_absolute));
  CHECK(cJSON_AddBoolToObject(link_info_obj, "warn_multiple_definition", link_info.warn_multiple_definition));
  CHECK(cJSON_AddBoolToObject(link_info_obj, "allow_undefined_version", link_info.allow_undefined_version));
  CHECK(cJSON_AddBoolToObject(link_info_obj, "dynamic", link_info.dynamic));
  CHECK(cJSON_AddBoolToObject(link_info_obj, "execstack", link_info.execstack));
  CHECK(cJSON_AddBoolToObject(link_info_obj, "noexecstack", link_info.noexecstack));
  CHECK(cJSON_AddBoolToObject(link_info_obj, "optimize", link_info.optimize));
  CHECK(cJSON_AddBoolToObject(link_info_obj, "print_gc_sections", link_info.print_gc_sections));
  CHECK(cJSON_AddBoolToObject(link_info_obj, "warn_alternate_em", link_info.warn_alternate_em));
  CHECK(cJSON_AddBoolToObject(link_info_obj, "user_phdrs", link_info.user_phdrs));
  CHECK(cJSON_AddBoolToObject(link_info_obj, "load_phdrs", link_info.load_phdrs));
  CHECK(cJSON_AddBoolToObject(link_info_obj, "check_relocs_after_open_input", link_info.check_relocs_after_open_input));
  CHECK(cJSON_AddBoolToObject(link_info_obj, "nointerp", link_info.nointerp));
  CHECK(cJSON_AddBoolToObject(link_info_obj, "inhibit_common_definition", link_info.inhibit_common_definition));
  CHECK(cJSON_AddBoolToObject(link_info_obj, "has_map_file", link_info.has_map_file));
  CHECK(cJSON_AddBoolToObject(link_info_obj, "non_contiguous_regions", link_info.non_contiguous_regions));
  CHECK(cJSON_AddBoolToObject(link_info_obj, "non_contiguous_regions_warnings", link_info.non_contiguous_regions_warnings));
  CHECK(cJSON_AddBoolToObject(link_info_obj, "unique_symbol", link_info.unique_symbol));
  CHECK(cJSON_AddBoolToObject(link_info_obj, "maxpagesize_is_set", link_info.maxpagesize_is_set));
  CHECK(cJSON_AddBoolToObject(link_info_obj, "commonpagesize_is_set", link_info.commonpagesize_is_set));
  CHECK(cJSON_AddNumberToObject(link_info_obj, "wrap_char", link_info.wrap_char));
  CHECK(cJSON_AddNumberToObject(link_info_obj, "path_separator", link_info.path_separator));
  CHECK(cJSON_AddNumberToObject(link_info_obj, "compress_debug", link_info.compress_debug));
  CHECK(cJSON_AddNumberToObject(link_info_obj, "stacksize", link_info.stacksize));
  CHECK(cJSON_AddNumberToObject(link_info_obj, "disable_target_specific_optimizations", link_info.disable_target_specific_optimizations));
  // some vtables and bfd struct is not dumped here
  CHECK(cJSON_AddNumberToObject(link_info_obj,"relax_pass", link_info.relax_pass));
  CHECK(cJSON_AddNumberToObject(link_info_obj,"relax_trip", link_info.relax_trip));
  CHECK(cJSON_AddNumberToObject(link_info_obj,"extern_protected_data", link_info.extern_protected_data));
  CHECK(cJSON_AddNumberToObject(link_info_obj,"dynamic_undefined_weak", link_info.dynamic_undefined_weak));
  CHECK(cJSON_AddNumberToObject(link_info_obj,"pei386_auto_import", link_info.pei386_auto_import));
  CHECK(cJSON_AddNumberToObject(link_info_obj,"pei386_runtime_pseudo_reloc", link_info.pei386_runtime_pseudo_reloc));
  CHECK(cJSON_AddNumberToObject(link_info_obj, "spare_dynamic_tags", link_info.spare_dynamic_tags));
  CHECK(cJSON_AddNumberToObject(link_info_obj, "indirect_extern_access", link_info.indirect_extern_access));
  CHECK(cJSON_AddNumberToObject(link_info_obj, "nocopyreloc", link_info.nocopyreloc));
  CHECK(cJSON_AddNumberToObject(link_info_obj, "flags", link_info.flags));
  CHECK(cJSON_AddNumberToObject(link_info_obj, "flags_1", link_info.flags_1));
  CHECK(cJSON_AddNumberToObject(link_info_obj, "gnu_flags_1", link_info.gnu_flags_1));
  CHECK(cJSON_AddNumberToObject(link_info_obj, "start_stop_gc", link_info.start_stop_gc));
  CHECK(cJSON_AddNumberToObject(link_info_obj, "start_stop_visibility", link_info.start_stop_visibility));
  CHECK(cJSON_AddNumberToObject(link_info_obj, "maxpagesize", link_info.maxpagesize));
  CHECK(cJSON_AddNumberToObject(link_info_obj, "commonpagesize", link_info.commonpagesize));
  CHECK(cJSON_AddNumberToObject(link_info_obj, "relro_start", link_info.relro_start));
  CHECK(cJSON_AddNumberToObject(link_info_obj, "relro_end", link_info.relro_end));
  CHECK(cJSON_AddNumberToObject(link_info_obj, "cache_size", link_info.cache_size));
  CHECK(cJSON_AddNumberToObject(link_info_obj, "max_cache_size", link_info.max_cache_size));

  /* serialize input_files */
  CHECK(input_file_arr =  cJSON_AddArrayToObject(json, "input_files"));

  for (search = (void *)input_file_chain.head;
       search != NULL;
       search = search->next_real_file)
  {
    cJSON *input_file;
    if (search->local_sym_name)
    {
      CHECK(input_file = cJSON_CreateString(search->local_sym_name));
      cJSON_AddItemToArray(input_file_arr, input_file);
    }
  }

  /* generate json string */
  char *json_str = cJSON_PrintUnformatted(json);

  /* generate runtime uuid */
  gen_uuid();

  /* get timestamp */
  get_timestamp();

  /* initialize database */
  db_init();

  CHECK(json_str && cmd && runtime_uuid && runtime_timestamp && output_filename);
  char *abs_output_filename;
  // FIXME: get abs output filename later 
  CHECK(abs_output_filename = strdup(output_filename));

  char *sql = "INSERT INTO t_link "  \
              "VALUES (NULL, '%s', %lu, '%s', '%s', '%s', '%s', %d, '%s', '%s'); "; 
  char *sql_full;

  char *pwd = getcwd(NULL, PATH_MAX);
#ifdef CLEAN_SQL
  CLEAN(abs_output_filename);
  CLEAN(cmd)
  CLEAN(json_str)
  CHECK(sql_full = (char *)malloc(strlen(sql) + strlen(runtime_uuid) + 20 + strlen(clean_abs_output_filename) + strlen(clean_cmd) + strlen(clean_json_str) + 1));
  sprintf(sql_full, sql, runtime_uuid, runtime_timestamp, clean_abs_output_filename, clean_cmd, clean_json_str);
#else
  CHECK(sql_full = (char *)malloc(strlen(sql) + strlen(runtime_uuid) + 20 + strlen(pwd) + strlen(proj_root) + strlen(abs_output_filename) + strlen(cmd) + strlen(json_str) + strlen(gcc_runtime_uuid) + 0x100 + 1));
  sprintf(sql_full, sql, runtime_uuid, runtime_timestamp, pwd, proj_root, abs_output_filename, cmd, traced, gcc_runtime_uuid, json_str);
#endif



  /* insert into database */
  int rc = sqlite3_exec(db, sql_full, NULL, NULL, NULL);
  if(rc != SQLITE_OK) {
    log("SQL error: exec");
    sqlite3_close(db);
    return;
  }

  /* copy input object files to ARCHIVE */
  cJSON *tmp_file;
  char *tmp_cmd_buf;
  CHECK(tmp_cmd_buf = (char *)malloc(41 + PATH_MAX + strlen(archive) + strlen(runtime_uuid) + 1));
  int n_array = cJSON_GetArraySize(input_file_arr);
  for (int i = 0; i < n_array; i++) {
    tmp_file = cJSON_GetArrayItem(input_file_arr, i);
    if (tmp_file->valuestring[0] == '-' && tmp_file->valuestring[1] == 'l') {
      continue;
    }
    sprintf(tmp_cmd_buf, "mkdir -p %2$s/%3$s && cp %1$s %2$s/%3$s/", tmp_file->valuestring, archive, runtime_uuid);
    system(tmp_cmd_buf);
  }

  /* close database */
  sqlite3_close(db);

  /* free memory */
  free(sql_full);
  free(cmd);
  free(tmp_cmd_buf);

  cJSON_Delete(json);
  json = NULL;
}

void script_hook(char *name)
{
  cJSON *script_files_arr;
  cJSON *script_file_name;

  if(maybe_init_ldhook() == -1)
    return;

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

void main_init_hook(int argc, char **argv) {
  unsigned int cmd_len = 0;
  if(maybe_init_ldhook() == -1)
    return;
  for (int i = 0; i < argc; i++) {
    cmd_len += strlen(argv[i]) + 1;
  }
  cmd_len += 1;
  CHECK(cmd = (char *)calloc(cmd_len, 1));
  for (int i = 0; i < argc; i++)
  {
    strcat(cmd, argv[i]);
    strcat(cmd, " ");
  }
}

void fini_hook() {
  char *tmp_cmd_buf;

  if(maybe_init_ldhook() == -1){
    return;
  }
  CHECK(tmp_cmd_buf = (char *)malloc(55 + PATH_MAX + strlen(archive)*2 + strlen(runtime_uuid)*2 + 1));
  sprintf(tmp_cmd_buf, "mkdir -p %2$s/%3$s/output && cp %1$s %2$s/%3$s/output/", output_filename, archive, runtime_uuid);
  system(tmp_cmd_buf);
  free(tmp_cmd_buf);
}