/*
Name: Trevor Philip
Student Number: NL10252
Date: 4/19/2018
Course: CMSC 421 Spring 2018
Purpose: Contains the additional system calls needed for the IDS logger.
*/

#include "toggler.h"
#include <linux/kernel.h>

asmlinkage long sys_ids_log_on(void) {
    if (is_ids_logger_on()) {
        printk("PROJ2: The system call tracker was already turned on!");
    } else {
        toggle_ids_logger(1);
    }
}

asmlinkage long sys_ids_log_off(void) {
    if (!is_ids_logger_on()) {
        printk("PROJ2: The system call tracker was already turned off!");
    } else {
        toggle_ids_logger(0);
    }
}

asmlinkage long sys_ids_log_format(unsigned char* format) {
    printk("PROJ2 ERROR: sys_ids_log_format not implemented!");
}
