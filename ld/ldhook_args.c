#include <stdio.h>
#include "sqlite3.h"

void input_file_hook(char* name) {
    printf("input_file_name: %s\n", name);
}