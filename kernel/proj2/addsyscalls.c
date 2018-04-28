/*
Name: Trevor Philip
Student Number: NL10252
Date: 4/19/2018
Course: CMSC 421 Spring 2018
Purpose: Contains the additional system calls needed for the IDS logger.
*/

#include "toggler.h"
#include <linux/kernel.h>

asmlinkage long sys_ids_log_on(int process_id) {
    if (0) {
        printk("PROJ2: The system call tracker was already turned on!");
    } else {
	printk("PROJ2: Logging system calls for process ID %i", process_id);
        toggle_ids_logger(1, process_id);
    }
}

asmlinkage long sys_ids_log_off(int process_id) {
    if (!is_ids_logger_on()) {
        printk("PROJ2: The system call tracker was already turned off!");
    } else {
	printk("PROJ2: Stopped logging system calls for process ID %i", process_id);
        toggle_ids_logger(0, process_id);
    }
}

asmlinkage long sys_ids_log_format(unsigned char* format) {
    printk("PROJ2 ERROR: sys_ids_log_format not implemented!");
}
