/*
Name: Trevor Philip
Student number: NL10252
Date: 5/2/2018
CMSC 421 Spring 2018

Purpose: Retrieves the system call logs from kernel memory, which can then
	 be used by the Intrusion Detection System written in C# to train
	 or try to detect malformed processes.

*/

#include <sys/syscall.h>
#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <signal.h>
#include <sys/time.h>
#include <ctype.h>
#include <limits.h>

/*
Starts the tracking by sending a system call to the kernel.
*/
void start_tracking(unsigned int process_id)
{
	if (process_id > 0) {
		if (syscall(333, process_id) < 0) {
			printf("\nFailed to execute syscall 333. The process ID could not be tracked.\n");
		}
		else {
			printf("\nThe process ID %ld is now being tracked.\n\n", process_id);
		}
	}
	else {
		printf("\nThe process ID provided must be larger than 0.\n");
	}
}

/*
Tells the kernel to stop tracking a certain system call.
*/
void stop_tracking(unsigned int process_id)
{
	if (process_id > 0) {
		if (syscall(334, process_id) < 0) {
			printf("\nFailed to execute syscall 334. The process ID could be halted in tracking.\n");
		}
		else {
			printf("\nThe process ID %ld is no longer being tracked.\n", process_id);
		}
	}
	else {
		printf("\nThe process ID provided must be larger than 0.\n");
	}
}

/*
Writes the logs of a process ID that is having its system calls tracked by the kernel.
*/
void do_logging(unsigned int process_id, int stagger)
{
	FILE * fp;
	char * buff;
	char * buff_full;
	char fileName[40];
	struct timeval tp;
	unsigned long m_tval;
	struct stat st = {0};
	char * proc_exe;
	char * real_path;
	int is_access;
	int len;

	/* make this logging directory if it does not exist */
	if (stat("logs", &st) == -1) {
		mkdir("logs", 0777);
	}

	/* endlessly iterate until the user ends it with CTRL+C */
	while (1) {
		/* log file gets named after the unix time in microsecods */
		gettimeofday(&tp, 0);
		m_tval = 1000000 * tp.tv_sec + tp.tv_usec;
		snprintf(fileName, 40, "logs/%lu.log", m_tval);

		/* malloc the data we need */
		buff = (char *)malloc(sizeof(char) * 500);
		buff_full = (char *)malloc(sizeof(char) * (PATH_MAX + 500));
		proc_exe = (char *)malloc(sizeof(char) * 25);
		real_path = (char *)malloc(sizeof(char) * (PATH_MAX + 1));

		/* verify that the process is actually running */
		snprintf(proc_exe, 25, "/proc/%lu/exe", process_id);
		is_access = access(proc_exe, F_OK) != 1;

		/* Make sure the syscall is returning correctly */
		if (syscall(335, process_id, buff) < 0) {
			printf("\nCall to syscall 335 failed. This usually happens if the provided process ID is invalid.\n");
			printf("%u -- %s\n", process_id, buff);
			break;
		}

		/* if the process is being tracked but not running, we shouldnt */
		if (!is_access) {
			printf("\nThe process of PID %lu is not running. Recommend running './ids_logger untrack %lu' to stop tracking it!\n", process_id, process_id);
			break;
		}

		/* this prevents us from writing extraneous logs */
		if (strstr(buff, "-1,-1,-1,-1,-1,-1,-1,-1,-1,-1") != NULL) {
			usleep(stagger * 1000);
			free(buff);
			free(buff_full);
			free(proc_exe);
			free(real_path);
			continue;
		}

		/* verify that proc/exe is running */
		len = readlink(proc_exe, real_path, PATH_MAX);
		if (len == -1) {
			printf("Could not get the real file location for %s\n, the process might have ended.", proc_exe);
			printf("The /proc/ alias will be used instead, but you must specify an alias manually in the IDS program.\n");
			strcpy(real_path, proc_exe);
		}

		/* merge the real location into buffer, then wrtie file*/
		snprintf(buff_full, (PATH_MAX + 100), "%s,%s", real_path, buff);
		fp = fopen(fileName, "w");
		fprintf(fp, "%s", buff_full);
		fclose(fp);

		/* clear memory */
		free(buff);
		free(buff_full);
		free(proc_exe);
		free(real_path);
		printf("Created log file %s\n", fileName);
		usleep(stagger * 1000);
	}
}

/*
If no arguments are passed to the console, the user is prompted with this.
*/
void do_prompt()
{
	char buff_choice[1];
	unsigned int process_id;
	unsigned int stagger;

	while (1) {
		printf("What would you like to do?\n");
		printf("1. Add a process ID to be logged.\n");
		printf("2. Remove a process ID from being logged.\n");
		printf("3. Output syscalls to file by process ID\n");
		printf("4. Exit.\n\n");
		printf("Choice: ");
		scanf("%s", buff_choice);

		if (strcmp(buff_choice, "1") == 0) {
			printf("\n Input the Process ID to be tracked: ");
			scanf("%u", &process_id);
			start_tracking(process_id);
		}
		else if (strcmp(buff_choice, "2") == 0) {
			printf("\n Input the Process ID to be removed: ");
			scanf("%u", &process_id);
			stop_tracking(process_id);
		}
		else if (strcmp(buff_choice, "3") == 0) {
			printf("\n Input the Process ID to be logged: ");
			scanf("%u", &process_id);
			printf("\n Please enter the value in milliseconds for sleeping this thread: ");
			scanf("%u", &stagger);
			do_logging(process_id, stagger);
		}
		else if (strcmp(buff_choice, "4") == 0) {
			exit(0);
		}
		else {
			printf("\nInvalid choice! Try again.\n\n");
		}
	}
}

/*
Prints a message that there are too few arguments and returns 1;
*/
int too_few_args()
{
	printf("Too few arguments for this function! See README file for help.\n");
        return 1;
}

int convert(char* str)
{
	int size;
	int i;
	if (!str) {
		printf("String is not a number!");
		exit(1);
	}
	size = strlen(str);
	for (i = 0; i < size; i++) {
		if (!isdigit(str[i])) {
			printf("String is not a number!");
			exit(1);
		}
	}

	return (strtoul(str, NULL, 10));
}

int main(int argc, char **argv)
{
	/*char buff_choice[1];*/
	unsigned int stagger = 150;
	unsigned int process_id;

	if (geteuid() != 0) {
		printf("ERROR! You must run this logger as root.\n");
		return 1;
	}

	printf("\nWelcome to Trevor Philip's Intrustion Detection System!\n");

	if (argc == 1) {
		/* user specified no arguments, so prompt them */
		do_prompt();
	} else {
		/* user specified arguments, make sure there are enough */
		if (argc < 3) {
			return too_few_args();
		}

		/* The second argument will always be the process ID. */

		process_id = convert(argv[2]);

		if (strcmp(argv[1], "track") == 0) {
			start_tracking(process_id);
		} else if (strcmp(argv[1], "untrack") == 0) {
			stop_tracking(process_id);
		} else if (strcmp(argv[1], "log") == 0) {
			if (argc > 3) {
				stagger = convert(argv[3]);
			} else {
				printf("\nNote: The stagger was not specified. Defaulting to 150 msec\n\n");
			}
			do_logging(process_id, stagger);
		} else {
			printf("Unknown command!\n");
			return 1;
		}
	}

	return 0;
}
