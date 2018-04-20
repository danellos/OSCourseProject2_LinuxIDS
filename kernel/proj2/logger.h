#include <linux/kernel.h>
#include <linux/stddef.h>
#include <linux/ptrace.h> /* for pt_regs */

int do_logging(struct pt_regs *regs);
