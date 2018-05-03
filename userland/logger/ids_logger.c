/*
Name: Trevor Philip
Student number: NL10252
DateL 5/2/2018
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
	char fileName[40];
	struct timeval tp;
	unsigned long m_tval;
	struct stat st = {0};

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
		buff = (char *)malloc(sizeof(char) * 100);
		if (syscall(335, process_id, buff) < 0) {
			printf("\nCall to syscall 335 failed. This usually happens if the provided process ID is invalid.\n");
			break;
		}
		/* this prevents us from writing extraneous logs */
		if (strstr(buff, "-1,-1,-1,-1,-1,-1,-1,-1,-1,-1") != NULL) {
			usleep(stagger * 1000);
			continue;
		}
		fp = fopen(fileName, "w");
		fprintf(fp, "%s", buff);
		fclose(fp);
		free(buff);
		printf("Created log file %s\n", fileName);
		usleep(stagger * 1000);
	}
}

int main(int argc, char **argv)
{
	char buff_choice[1];
	unsigned int stagger;
	unsigned int process_id;

	printf("\nWelcome to Trevor Philip's Intrustion Detection System!\n\n");

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
			scanf("%ld", &process_id);
			start_tracking(process_id);
		}
		else if (strcmp(buff_choice, "2") == 0) {
			printf("\n Input the Process ID to be removed: ");
			scanf("%ld", &process_id);
			stop_tracking(process_id);
		}
		else if (strcmp(buff_choice, "3") == 0) {
			printf("\n Input the Process ID to be logged: ");
			scanf("%ld", &process_id);
			printf("\n Please enter the value in milliseconds for sleeping this thread: ");
			scanf("%ld", &stagger);
			do_logging(process_id, stagger);
		}
		else if (strcmp(buff_choice, "4") == 0) {
			exit(0);
		}
		else {
			printf("\nInvalid choice! Try again.\n\n");
		}
	}

	return 0;
}
