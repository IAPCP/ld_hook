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

// char *dbpath;
// sqlite3 *db;
// cJSON *json;
// char runtime_uuid[UUID4_LEN];
// uint64_t runtime_timestamp;
// char *cmd;
// char *proj_root;


void ar_hook() {
    printf("ar_hook\n");
}