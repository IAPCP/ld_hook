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

cJSON* cJSON_AddStringOtherwiseNullToObject(cJSON * const object, const char * const name, const char * const string);
cJSON* cJSON_AddStringOtherwiseNullToObject(cJSON * const object, const char * const name, const char * const string) {
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

/* ar hook main */
void ar_hook() {
    CHECK(dbpath = getenv("COMPILE_COMMANDS_DB"));
    CHECK(proj_root = getenv("PROJ_ROOT");)

    // TODO
}

/* hook origin argv */
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