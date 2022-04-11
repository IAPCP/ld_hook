#include "arhook.h"
#include "sqlite3.h"
#include "cJSON.h"
#include "uuid4.h"

#define ARHOOK_DEBUG

#ifdef ARHOOK_DEBUG
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
            return;                                    \
        }                                                 \
    }while(0)



#define CREATE_TABLE "CREATE TABLE IF NOT EXISTS t_ar(\
                        id INTEGER PRIMARY KEY AUTOINCREMENT, \
                        runtime_uuid TEXT, \
                        timestamp INTEGER, \
                        pwd TEXT, \
                        proj_root TEXT, \
                        output TEXT, \
                        cmdline TEXT, \
                        json TEXT)"

char *dbpath;
sqlite3 *db;
cJSON *json;
char runtime_uuid[UUID4_LEN];
uint64_t runtime_timestamp;
char *cmd;
char *proj_root;

// static cJSON* cJSON_AddStringOtherwiseNullToObject(cJSON * const object, const char * const name, const char * const string);
static cJSON* cJSON_AddStringOtherwiseNullToObject(cJSON * const object, const char * const name, const char * const string) {
    if (string) {
        return cJSON_AddStringToObject(object, name, string);
    } else {
        return cJSON_AddNullToObject(object, name);
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


/* vars from ar.c */
extern int is_ranlib;
extern int silent_create;
extern int verbose;
extern int display_offsets;
extern int preserve_dates;
extern int newer_only;
extern int write_armap;
extern int deterministic;			
extern char *posname;

extern enum operations
  {
    none = 0, del, replace, print_table,
    print_files, extract, move, quick_append
  } operation;

extern enum pos
  {
    pos_default, pos_before, pos_after, pos_end
  } postype;

extern bool operation_alters_arch;

extern bool counted_name_mode;
extern int counted_name_counter;
extern bool ar_truncate;
extern bool full_pathname;
extern bool make_thin_archive;
extern char * libdeps;
extern const char * output_filename;

/* ar hook main */
void ar_hook() {
    CHECK(dbpath = getenv("COMPILE_COMMANDS_DB"));
    CHECK(proj_root = getenv("PROJ_ROOT"));

    /* if json not exist, create it */
    if (!json) {
      CHECK(json = cJSON_CreateObject());
    }

    CHECK(cJSON_AddNumberToObject(json, "is_ranlib", is_ranlib));
    CHECK(cJSON_AddNumberToObject(json, "silent_create", silent_create));
    CHECK(cJSON_AddNumberToObject(json, "verbose", verbose));
    CHECK(cJSON_AddNumberToObject(json, "display_offsets", display_offsets));
    CHECK(cJSON_AddNumberToObject(json, "preserve_dates", preserve_dates));
    CHECK(cJSON_AddNumberToObject(json, "newer_only", newer_only));
    CHECK(cJSON_AddNumberToObject(json, "write_armap", write_armap));
    CHECK(cJSON_AddNumberToObject(json, "deterministic", deterministic));
    CHECK(cJSON_AddStringOtherwiseNullToObject(json, "posname", posname));
    CHECK(cJSON_AddNumberToObject(json, "operation", operation));
    CHECK(cJSON_AddNumberToObject(json, "postype", postype));
    CHECK(cJSON_AddBoolToObject(json, "operation_alters_arch", operation_alters_arch));
    CHECK(cJSON_AddBoolToObject(json, "counted_name_mode", counted_name_mode));
    CHECK(cJSON_AddNumberToObject(json, "counted_name_counter", counted_name_counter));
    CHECK(cJSON_AddBoolToObject(json, "ar_truncate", ar_truncate));
    CHECK(cJSON_AddBoolToObject(json, "full_pathname", full_pathname));
    CHECK(cJSON_AddBoolToObject(json, "make_thin_archive", make_thin_archive));
    CHECK(cJSON_AddStringOtherwiseNullToObject(json, "libdeps", libdeps));

    /* generate json string */
    char *json_str = cJSON_PrintUnformatted(json);

    /* generate runtime uuid */
    gen_uuid();

    /* get timestamp */
    get_timestamp();

    /* initialize database */
    db_init();

    if (!output_filename) {
      output_filename = "NULL";
    }

    CHECK(json_str && cmd && runtime_uuid && runtime_timestamp && output_filename);
    char *sql = "INSERT INTO t_ar "  \
                "VALUES (NULL, '%s', %lu, '%s', '%s', '%s', '%s', '%s'); "; 

    char *sql_full;
    char *pwd = getcwd(NULL, PATH_MAX);
    CHECK(sql_full = (char *)malloc(strlen(sql) + strlen(runtime_uuid) + 20 + strlen(pwd) + strlen(proj_root) + strlen(output_filename) + strlen(cmd) + strlen(json_str) + 1));
    sprintf(sql_full, sql, runtime_uuid, runtime_timestamp, pwd, proj_root, output_filename, cmd, json_str);

    /* insert into database */
    int rc = sqlite3_exec(db, sql_full, NULL, NULL, NULL);
    if(rc != SQLITE_OK) {
      log("SQL error: exec");
      sqlite3_close(db);
      return;
    }
  
    /* close database */
    sqlite3_close(db);

    /* free memory */
    free(sql_full);
    free(cmd);

    cJSON_Delete(json);

    json = NULL;

}

/* hook origin argv */
void main_init_hook(int argc, char **argv) {
  unsigned int cmd_len = 0;
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
