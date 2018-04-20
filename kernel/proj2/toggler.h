/*
This is a simple switch for toggling the syscall
tracking system or toggling it off. If FALSE, the
syscalls are not being logged. If TRUE, the syscalls
are being logged from the dispatcher.
*/
//static int proj2_syscall_tracker_on = 0;


int toggle_ids_logger (int value);
int is_ids_logger_on(void);
