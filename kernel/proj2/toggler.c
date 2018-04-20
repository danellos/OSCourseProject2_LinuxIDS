#include "toggler.h"

int is_on = 0;

int toggle_ids_logger(int value) {
    is_on = value;
}

int is_ids_logger_on(void) {
    return is_on != 0;
}
