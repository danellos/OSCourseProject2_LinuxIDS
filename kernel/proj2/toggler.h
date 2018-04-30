#pragma once

#include <linux/types.h>

/*
Name: Trevor Philip
Student ID: NL10252
Date: 4/25/2018
Purpose: Contains header definitions for The Toggler/Logger system
*/

/*
Structure definition for a tracked process.
*/
typedef struct tracked_process {
	/* the process ID as an unsigned int */
	unsigned int pid;
	/* flag for turning the logging on the process on or off */
	bool is_on;
	/* pointer to the next process in list */
	struct tracked_process *next;

} tracked_process;

/* Toggles the IDS logger. */
int toggle_ids_logger(bool value, unsigned int process_id);

/* Determines if the IDS logger is turned on or off. */
bool is_ids_logger_on(void);

/*
Performs a logging operation on a given syscall ID.
Will break out early if the current process is not
being tracked.
*/
int do_logging(unsigned long syscall_id);
