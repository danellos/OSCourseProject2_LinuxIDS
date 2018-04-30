#include "toggler.h"
#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/proc_fs.h>
#include <linux/sched.h>
#include <linux/types.h>
#include <linux/slab.h>

/*
Some parts of Linked List implementation is similar to: https://www.tutorialspoint.com/learn_c_by_examples/simple_linked_list_program_in_c.htm
*/

struct tracked_process *head = NULL;
bool started = false;

tracked_process * get_node(unsigned int process_id)
{
	struct tracked_process *ptr = head;

	if (ptr != NULL) {
		while(ptr != NULL) {
			if (ptr->pid == process_id) {
				return ptr;
			}
			ptr = ptr->next;
		}
	}

	return ptr;
}

void add_node(unsigned int process_id)
{
	struct tracked_process *new_node;

	if (get_node(process_id) != NULL) {
		printk(KERN_INFO "PROJ2: Attempted to add tracked process that was already added: %u", process_id);
		return;
	}

	new_node = (struct tracked_process*) kmalloc(sizeof(struct tracked_process), GFP_KERNEL);
	new_node->pid = process_id;
	new_node->is_on = true;
	new_node->next = head;
	head = new_node;
	printk(KERN_INFO "PROJ2: Process with id %u was added to the tracking list and is now being tracked.", process_id);
}

void remove_node(unsigned int process_id)
{
	struct tracked_process *ptr = head;
	struct tracked_process *tmp = NULL;

	if (ptr != NULL) {
		if (ptr->pid == process_id) {
			/* This means that the first item in the list is the one we want */
			kfree(ptr);
			head = NULL;
			return;
		}

		while (ptr != NULL) {
			if (ptr->next != NULL && ptr->next->pid == process_id) {
				/* We found what we wanted */
				tmp = ptr->next;
				ptr->next = tmp->next;
				kfree(tmp);
				printk(KERN_INFO "PROJ2: Process with id %u was removed from tracking and is no longer being tracked.", process_id);
				return;
			}
			ptr = ptr->next;
		}

	}

   printk(KERN_INFO "PROJ2: Attempted to REMOVE tracked process that does not exist in the list: %u", process_id);
}

void update_node(bool is_on, unsigned int process_id)
{
	struct tracked_process *ptr ;
	ptr = get_node(process_id);

	if (ptr == NULL) {
		add_node(process_id);
		ptr = get_node(process_id);
		/* If we crash the kernel after this step, then we have failed massively */
	}

	ptr->is_on = is_on;
}

int toggle_ids_logger(bool value, unsigned int process_id)
{
	if (!started) {
		started = true;
	}

	update_node(value, process_id);

	return 0;
}

bool is_ids_logger_on(void)
{
	return started;
}

int do_logging(unsigned long syscall_id)
{
	int i_syscall_id = (int)syscall_id;
	struct tracked_process* tracked = get_node(current->pid);

	if (!started || tracked == NULL || !tracked->is_on) {
		return 0;
	}

	printk(KERN_INFO "PROJ2: Process %i called %i", current->pid, i_syscall_id);
	// todo: log the above to file

	return 0;
}
