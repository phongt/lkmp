// SPDX-License-Identifier: GPL-2.0
#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/rcupdate.h>
#include <linux/debugfs.h>
#include <linux/slab.h>
#include <linux/mutex.h>
#include <linux/list.h>
#include <linux/kthread.h>
#include <linux/delay.h>

struct foo {
	int a;
	int b;
	int c;
};

static struct foo __rcu *gbl_ptr;

static DEFINE_MUTEX(gbl_foo_lock);

static struct dentry *debugfsrootdir = NULL;

struct task_struct_type {
	struct task_struct *task;
	int cycle;
	struct list_head tasklist;
};

static LIST_HEAD(task_head);
#define NUMBER_READERS 5

static int thread_fn(void *data)
{
	/* get the data putting from kthread_run() */
	int cycle = *((int *)(data));
	while (!kthread_should_stop()) {
		int val;
		rcu_read_lock();
		val = rcu_dereference(gbl_ptr)->a;
		rcu_read_unlock();
		schedule();
		msleep_interruptible(cycle * 1000);
	}
	return 0;
}
static int foo_set_a(void *data, u64 val)
{
	struct foo *ptr;
	/*rcu update side: get the value from userspace*/
	mutex_lock(&gbl_foo_lock);
	ptr = rcu_dereference_protected(gbl_ptr,
					lockdep_is_held(&gbl_foo_lock));
	ptr->a = val;
	mutex_unlock(&gbl_foo_lock);
	synchronize_rcu();
	return 0;
}

DEFINE_SIMPLE_ATTRIBUTE(foo_debugfs_fops, NULL, foo_set_a, "%llu\n");

static int __init rcu_example_init(void)
{
	struct foo *tmp;
	int i;
	/*Init RCU protected pointer*/
	tmp = kzalloc(sizeof(struct foo), GFP_KERNEL);
	RCU_INIT_POINTER(gbl_ptr, tmp);

	/* create the debugfs for userspace interaction*/
	debugfsrootdir = debugfs_create_dir("rcuexample", NULL);
	if (IS_ERR(debugfsrootdir))
		pr_err("RCU create dbgfs fail!\n");

	debugfs_create_file("foo_a", S_IWUGO, debugfsrootdir, NULL,
			    &foo_debugfs_fops);

	/* thread for reading */
	for (i = 0; i < NUMBER_READERS; ++i) {
		struct task_struct_type *type =
			kzalloc(sizeof(struct task_struct_type), GFP_KERNEL);
		struct task_struct *task = NULL;
		type->cycle = i + 1;
		task = kthread_run(thread_fn, (void *)(&type->cycle), "task-%d", i);
		type->task = task;
		list_add(&type->tasklist, &task_head);
	}

	return 0;
}

static void __exit rcu_example_exit(void)
{
	struct foo *free_foo_ptr;
	struct task_struct_type *it = NULL;
	struct task_struct_type *ittemp = NULL;

	/* free the rcu ptr */
	mutex_lock(&gbl_foo_lock);
	free_foo_ptr = rcu_dereference_protected(
		gbl_ptr, lockdep_is_held(&gbl_foo_lock));
	if (free_foo_ptr)
		kfree(free_foo_ptr);
	mutex_unlock(&gbl_foo_lock);
	synchronize_rcu();

	/* free the list task */
	list_for_each_entry_safe (it, ittemp, &task_head, tasklist) {
		if (it->task != NULL) {
			kthread_stop(it->task);
		}
		kfree(it);
	}

	/* remove the debugfs file */
	debugfs_remove_recursive(debugfsrootdir);
}

module_init(rcu_example_init);
module_exit(rcu_example_exit);
MODULE_LICENSE("GPL");

