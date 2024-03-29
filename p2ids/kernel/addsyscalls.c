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
#include <linux/slab.h>
#include <linux/cred.h>
#include <asm/errno.h>

int is_root(void);

/*
Returns TRUE if we are a root user, FALSE otherwise.
*/
int is_root()
{
	kuid_t rootUid;

	rootUid.val = 0;
	return uid_eq(get_current_cred()->uid, rootUid);
}


/*
Turns the IDS logger on for a given process ID.
*/
asmlinkage long sys_ids_log_on(unsigned int process_id) {
	if (!is_root()) {
		printk(KERN_ERR "PROJ2: Only root user can access this!");
		return -EPERM;
	}
	if (process_id == 0) {
		printk(KERN_ERR "PROJ2: Invalid process_id passed");
		return -EINVAL;
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
        if (!is_root()) {
                printk(KERN_ERR "PROJ2: Only root user can access this!");
                return -EPERM;
        }
        if (process_id == 0) {
                printk(KERN_ERR "PROJ2: Invalid process_id passed");
                return -EINVAL;
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
	char * buffer;

	if (!is_root()) {
                printk(KERN_ERR "PROJ2: Only root user can access this!");
                return -EPERM;
        }

	if (process_id == 0 || !access_ok(WRITE_OK, log_data, 100)) {
                printk(KERN_ERR "Proj2: Invalid process_id or log_data pointer passed");
                return -EINVAL;
        }

	buffer = (char *)kmalloc(sizeof(char) * 500, GFP_KERNEL);
	 if (buffer == 0) {
            // malloc failed, handle
            printk(KERN_ERR "Proj2: Kmalloc failed on buffer for sys_ids_log_read");
            return -EINVAL;
        }
		
	data = get_node(process_id);

	if (data == NULL) {
		printk(KERN_ERR "PROJ2: Invalid process_id");
	}

	data->is_on = false;

	snprintf(buffer, 500,
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
	
	kfree(buffer);

	return 0;
}
