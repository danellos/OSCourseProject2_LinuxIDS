/*
Name: Trevor Philip
Student Number: NL10252
Date: 4/19/2018
Course: CMSC 421 Spring 2018
Purpose: Contains the additional system calls needed for the IDS logger.
*/

#include "toggler.h"
#include <linux/kernel.h>
#include <linux/string.h>
#include <linux/uaccess.h>

/*
Turns the IDS logger on for a given process ID.
*/
asmlinkage long sys_ids_log_on(unsigned int process_id) {
	if (process_id == 0) {
		printk("Proj2: Invalid process_id passed");
		return -1;
	}

	printk("PROJ2: Logging system calls for process ID %u", process_id);
	toggle_ids_logger(true, process_id);
	return 0;
}

/*
Disables the IDS logger for a given process ID. It gets
removes from the list of tracked processes.
*/
asmlinkage long sys_ids_log_off(unsigned int process_id)
{
        if (process_id == 0) {
                printk("Proj2: Invalid process_id passed");
                return -1;
        }

	printk("PROJ2: Stopped logging system calls for process ID %u", process_id);
	toggle_ids_logger(false, process_id);
	return 0;
}

/*
Reads the state of the IDS logger to a user space pointer.
This pointer must be malloc'd in user space already with a buffer
size of 100.
*/
asmlinkage long sys_ids_log_read(unsigned int process_id, unsigned char *log_data) {
	struct tracked_process *data;
        int i;
	char buffer[100];

	if (process_id == 0 || log_data == 0) {
                printk("Proj2: Invalid process_id or log_data pointer passed");
                return -1; //replace with error code appropriate
        }

	data = get_node(process_id);
	data->is_on = false;

	snprintf(buffer, 100,
                "%u,%i,%i,%i,%i,%i,%i,%i,%i,%i,%i",
                data->pid,
                data->syscalls[0],
                data->syscalls[1],
                data->syscalls[2],
                data->syscalls[3],
                data->syscalls[4],
                data->syscalls[5],
                data->syscalls[6],
                data->syscalls[7],
                data->syscalls[8],
                data->syscalls[9]);

	copy_to_user(log_data,buffer,strlen(buffer));

	for (i = 0; i < IDS_MAXLEN; i++) {
		data->syscalls[i] = -1;
	}
	data->syscall_len = 0;

	data->is_on = true;

	return 0;
}
