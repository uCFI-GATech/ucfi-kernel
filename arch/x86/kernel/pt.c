#include <linux/module.h>
#include <linux/mm.h>
#include <linux/mmu_context.h>
#include <linux/mman.h>
#include <linux/debugfs.h>
#include <linux/uaccess.h>
#include <linux/slab.h>
#include <linux/vmalloc.h>
#include <linux/spinlock.h>
#include <linux/interrupt.h>
#include <linux/wait.h>
#include <asm/fpu/internal.h>
#include <asm/msr.h>
#include <linux/pt.h>

#define pt_print(fmt, ...) printk(KERN_INFO "pt: " fmt, ## __VA_ARGS__)

#define MSR_IA32_RTIT_ADDR0_A 0x580
#define MSR_IA32_RTIT_ADDR0_B 0x581
#define MSR_IA32_RTIT_ADDR1_A 0x582
#define MSR_IA32_RTIT_ADDR1_B 0x583

#define RTIT_CTL_ADDR0_CFG (1UL << 32)
#define RTIT_CTL_ADDR1_CFG (1UL << 36)

#define RTIT_CTL_DIS_RETC (1UL << 11)

#define PT_XSTATE_CTL 0
#define PT_XSTATE_OUTPUT_BASE 1
#define PT_XSTATE_OUTPUT_MASK 2
#define PT_XSTATE_STATUS 3
#define PT_XSTATE_CR3_MATCH 4
#define PT_XSTATE_ADDR0_A 5
#define PT_XSTATE_ADDR0_B 6
#define PT_XSTATE_ADDR1_A 7
#define PT_XSTATE_ADDR1_B 8

#define TOPA_ENTRY_SIZE_4K 0
#define TOPA_ENTRY_SIZE_8K 1
#define TOPA_ENTRY_SIZE_16K 2
#define TOPA_ENTRY_SIZE_32K 3
#define TOPA_ENTRY_SIZE_64K 4
#define TOPA_ENTRY_SIZE_128K 5
#define TOPA_ENTRY_SIZE_256K 6
#define TOPA_ENTRY_SIZE_512K 7
#define TOPA_ENTRY_SIZE_1M 8
#define TOPA_ENTRY_SIZE_2M 9
#define TOPA_ENTRY_SIZE_4M 10
#define TOPA_ENTRY_SIZE_8M 11
#define TOPA_ENTRY_SIZE_16M 12
#define TOPA_ENTRY_SIZE_32M 13
#define TOPA_ENTRY_SIZE_64M 14
#define TOPA_ENTRY_SIZE_128M 15
#define TOPA_ENTRY_SIZE_CHOICE TOPA_ENTRY_SIZE_2M
#define TOPA_BUFFER_SIZE (1 << (12 + TOPA_ENTRY_SIZE_CHOICE))

#define pt_resume() wrmsrl(MSR_IA32_RTIT_CTL, \
		native_read_msr(MSR_IA32_RTIT_CTL) | RTIT_CTL_TRACEEN)

#define pt_pause() wrmsrl(MSR_IA32_RTIT_CTL, \
		native_read_msr(MSR_IA32_RTIT_CTL) & ~RTIT_CTL_TRACEEN)

#define pt_topa_base() native_read_msr(MSR_IA32_RTIT_OUTPUT_BASE)

#define pt_topa_index() ((native_read_msr(MSR_IA32_RTIT_OUTPUT_MASK) \
			& 0xffffffff) >> 7)

#define pt_topa_offset() (native_read_msr(MSR_IA32_RTIT_OUTPUT_MASK) >> 32)

#define pt_status() (native_read_msr(MSR_IA32_RTIT_STATUS))

struct topa_entry {
	u64 end:1;
	u64 rsvd0:1;
	u64 intr:1;
	u64 rsvd1:1;
	u64 stop:1;
	u64 rsvd2:1;
	u64 size:4;
	u64 rsvd3:2;
	u64 base:36;
	u64 rsvd4:16;
};

#define TOPA_ENTRY(_base, _size, _stop, _intr, _end) (struct topa_entry) { \
	.base = (_base) >> 12, \
	.size = (_size), \
	.stop = (_stop), \
	.intr = (_intr), \
	.end = (_end), \
}

struct topa {
	struct topa_entry entries[3];
	char *raw;
	struct task_struct *task;
	struct list_head buffer_list;
	spinlock_t buffer_list_sl;
	bool failed;
	int index;
};

struct pt_buffer {
	struct work_struct work;
	struct tasklet_struct tasklet;
	struct list_head entry;
	struct topa *topa;
	struct topa *child_topa;
	struct completion *notifier;
	char *raw;
	u32 size;
	int index;
};

#define pt_fail_topa(topa, fmt, ...) if (!test_and_set_bit(0, \
			(unsigned long *) &topa->failed)) \
	pt_print("[pid:%d] failed: " fmt "\n", \
			(topa)->task->pid, ## __VA_ARGS__)

static char pt_monitor[PATH_MAX];
static char tmp_buffer[PATH_MAX];
static struct dentry *pt_monitor_dentry;
static struct dentry *pt_monitor_output;
static struct dentry *pt_monitor_conf;

#define CONF_BUF_MAX 16
static uint64_t conf_flags = 0;

struct output_entry {
	void *ptr;
	ssize_t size;
	ssize_t offset;
	bool is_pt_buf;
	struct list_head list;
};

struct outputs_list {
	struct output_entry *output_list;
	pid_t pid;
	struct dentry *file;
	wait_queue_head_t syscall_queue;
	struct list_head list;
};

static DECLARE_WAIT_QUEUE_HEAD(output_read_wait);
static DECLARE_WAIT_QUEUE_HEAD(output_start_wait);

static uint64_t filter_start, filter_end = 0;

static uint64_t root_pid;
static struct outputs_list monitor_outputs_list;

static struct kmem_cache *pt_monitor_output_cache = NULL;
static struct kmem_cache *pt_buffer_cache = NULL;
static struct kmem_cache *pt_trace_cache = NULL;

static struct workqueue_struct *pt_wq;
static struct workqueue_struct *pt_debugfs_wq;

static atomic64_t pt_has_flown = ATOMIC_INIT(0);
static atomic64_t pt_flying_tasks = ATOMIC_INIT(0);

static DEFINE_MUTEX(pt_logfile_mtx);

struct outputs_list *find_outputs_list(pid_t pid)
{
	struct list_head *ptr;
	struct outputs_list *list;

	list_for_each(ptr, &monitor_outputs_list.list) {
		list = list_entry(ptr, struct outputs_list, list);
		if (list->pid == pid)
			return list;
	}

	return NULL;
}

void pt_log(void* buf, ssize_t count, pid_t pid, bool no_cpy)
{
	struct outputs_list *list;
	struct output_entry *tmp, *head;
	list = find_outputs_list(pid);
	if (!list) {
		pt_print("Failed to find list for pid %d, dropping data\n", pid);
		return;
	}
	head = list->output_list;
	tmp = kmem_cache_alloc(pt_monitor_output_cache, GFP_KERNEL);
	if (!tmp) {
		pt_print("No memory\n");
		return;
	}
	if (no_cpy) {
		tmp->ptr = buf;
		tmp->is_pt_buf = 1;
	} else {
		tmp->ptr = kmalloc(count, GFP_KERNEL);
		tmp->is_pt_buf = 0;
		memcpy(tmp->ptr, buf, count);
	}
	tmp->size = count;
	tmp->offset = 0;
	list_add_tail(&(tmp->list), &(head->list));
	wake_up_interruptible(&output_read_wait);
}

void pt_clear_log(void)
{
	struct list_head *pos, *entry, *q, *r;
	struct outputs_list *list_tmp;
	struct output_entry *entry_tmp;

	mutex_lock(&pt_logfile_mtx);
	root_pid = 0;
	list_for_each_safe(pos, q, &monitor_outputs_list.list) {
		list_tmp = list_entry(pos, struct outputs_list, list);
		wake_up_interruptible(&list_tmp->syscall_queue);
		list_for_each_safe(entry, r, &(list_tmp->output_list->list)) {
			entry_tmp = list_entry(entry, struct output_entry, list);
			list_del(entry);
			if (entry_tmp->ptr) {
				if (entry_tmp->is_pt_buf) {
					kmem_cache_free(pt_trace_cache, entry_tmp->ptr);
				} else {
					kfree(entry_tmp->ptr);
				}
				entry_tmp->ptr = NULL;
			}
			if (entry_tmp != list_tmp->output_list)
				kmem_cache_free(pt_monitor_output_cache, entry_tmp);
		}
		if (list_tmp->file)
			debugfs_remove(list_tmp->file);
		list_del(pos);
		if (list_tmp != &monitor_outputs_list)
			kfree(list_tmp);
	}
	INIT_LIST_HEAD(&monitor_outputs_list.list);
	mutex_unlock(&pt_logfile_mtx);
}

#pragma pack(push)

enum pt_logitem_kind {
	PT_LOGITEM_BUFFER,
	PT_LOGITEM_PROCESS,
	PT_LOGITEM_THREAD,
	PT_LOGITEM_IMAGE,
	PT_LOGITEM_XPAGE,
	PT_LOGITEM_UNMAP,
	PT_LOGITEM_FORK,
	PT_LOGITEM_SECTION,
	PT_LOGITEM_THREAD_END,
};

struct pt_logitem_header {
	enum pt_logitem_kind kind;
	u32 size;
};

struct pt_logitem_buffer {
	struct pt_logitem_header header;
	u64 tgid;
	u64 pid;
	u64 sequence;
	u64 size;
};

static void pt_log_buffer(struct pt_buffer *buf)
{
	struct pt_logitem_buffer item = {
		.header = {
			.kind = PT_LOGITEM_BUFFER,
			.size = sizeof(struct pt_logitem_buffer) + buf->size
		},
		.tgid = buf->topa->task->tgid,
		.pid = buf->topa->task->pid,
		.sequence = 0, /* depricated */
		.size = buf->size,
	};

	mutex_lock(&pt_logfile_mtx);
	pt_log(&item, sizeof(item), item.pid, 0);
	pt_log(buf->raw, buf->size, item.pid, 1);
	mutex_unlock(&pt_logfile_mtx);
}

struct pt_logitem_process {
	struct pt_logitem_header header;
	u64 tgid;
	u64 cmd_size;
};

struct pt_logitem_thread {
	struct pt_logitem_header header;
	u64 tgid;
	u64 pid;
};

static void pt_log_thread(struct task_struct *task)
{
	struct pt_logitem_thread item = {
		.header = {
			.kind = PT_LOGITEM_THREAD,
			.size = sizeof(struct pt_logitem_thread),
		},
		.tgid = task->tgid,
		.pid = task->pid,
	};

	mutex_lock(&pt_logfile_mtx);
	pt_log(&item, sizeof(item), item.pid, 0);
	mutex_unlock(&pt_logfile_mtx);
}

static void pt_log_process(struct task_struct *task)
{
	struct pt_logitem_process item = {
		.header = {
			.kind = PT_LOGITEM_PROCESS,
			.size = sizeof(struct pt_logitem_process)
		},
		.tgid = task->tgid,
		.cmd_size = 0,
	};

	mutex_lock(&pt_logfile_mtx);
	pt_log(&item, sizeof(item), task->pid, 0);
	mutex_unlock(&pt_logfile_mtx);

	pt_log_thread(task);
}

struct pt_logitem_fork {
	struct pt_logitem_header header;
	u64 parent_tgid;
	u64 parent_pid;
	u64 child_tgid;
	u64 child_pid;
};

static void pt_log_fork(struct task_struct *parent,
		struct task_struct *child)
{
	struct pt_logitem_fork item = {
		.header = {
			.kind = PT_LOGITEM_FORK,
			.size = sizeof(struct pt_logitem_fork),
		},
		.parent_tgid = parent->tgid,
		.parent_pid = parent->pid,
		.child_tgid = child->tgid,
		.child_pid = child->pid,
	};

	mutex_lock(&pt_logfile_mtx);
	pt_log(&item, item.header.size, item.parent_pid, 0);
	mutex_unlock(&pt_logfile_mtx);
}

#pragma pack(pop)

static ssize_t
pt_monitor_read(struct file *file, char __user *buf,
		size_t count, loff_t *ppos)
{
	return simple_read_from_buffer(buf, count, ppos, pt_monitor,
			strlen(pt_monitor));
}

static ssize_t
pt_monitor_write(struct file *filp, const char __user *buf,
		size_t count, loff_t *ppos)
{
	if (count >= PATH_MAX)
		return -ENOMEM;
	if (*ppos != 0)
		return -EINVAL;
	if (atomic64_read(&pt_flying_tasks))
		return -EBUSY;

	memset(pt_monitor, 0, PATH_MAX);
	memset(tmp_buffer, 0, PATH_MAX);
	if (copy_from_user(tmp_buffer, buf, count))
		return -EINVAL;

	// Valid formats: <program>
	//                <filter_start_hex>|<filter_end_hex>|<program>
	if (strchr(tmp_buffer, '|')) {
		sscanf(tmp_buffer, "%llx|%llx|%s", &filter_start, &filter_end, pt_monitor);
	} else {
		strncpy(pt_monitor, tmp_buffer, PATH_MAX);
		filter_start = 0;
		filter_end = 0;
	}

	pt_clear_log();
	atomic64_set(&pt_has_flown, 0);

	pt_print("%s registered, filter[%llx-%llx]\n", pt_monitor, filter_start, filter_end);

	return count;
}

static ssize_t
pt_monitor_output_read(struct file *file, char __user *buf,
		size_t count, loff_t *ppos)
{
	if (*ppos)
		return 0;

	if (!atomic64_read(&pt_has_flown)) {
		// Nothing has been traced yet so we don't know what
		// the root pid will be. Wait for it.
		DECLARE_WAITQUEUE(wait, current);
		add_wait_queue(&output_start_wait, &wait);
		current->state = TASK_INTERRUPTIBLE;
		schedule();
		current->state = TASK_RUNNING;
		remove_wait_queue(&output_start_wait, &wait);
	}

	if (copy_to_user(buf, &root_pid, sizeof(pid_t)))
		return -EFAULT;

	*ppos += sizeof(pid_t);
	return sizeof(pid_t);
}

static ssize_t
pt_monitor_pid_read(struct file *file, char __user *buf,
		size_t count, loff_t *ppos)
{
	struct outputs_list *list;
	struct output_entry *tmp, *head;
	ssize_t stored;
	ssize_t copied = 0;
	void *dst_ptr = buf;
	pid_t pid = (pid_t) ((uintptr_t) file->f_path.dentry->d_inode->i_private);
	DECLARE_WAITQUEUE(wait, current);

	mutex_lock(&pt_logfile_mtx);

	list = find_outputs_list(pid);
	if (!list) {
		mutex_unlock(&pt_logfile_mtx);
		return copied;
	}
	head = list->output_list;

	while (list_empty(&head->list) && (!atomic64_read(&pt_has_flown) || atomic64_read(&pt_flying_tasks))) {
		// There's no data, but we're expecting something to be traced,
		// so wait for data to appear.
		wake_up_interruptible(&list->syscall_queue);
		add_wait_queue(&output_read_wait, &wait);
		current->state = TASK_INTERRUPTIBLE;
		mutex_unlock(&pt_logfile_mtx);
		schedule();
		current->state = TASK_RUNNING;
		remove_wait_queue(&output_read_wait, &wait);
		mutex_lock(&pt_logfile_mtx);
		list = find_outputs_list(pid);
		if (!list) {
			mutex_unlock(&pt_logfile_mtx);
			return copied;
		}
		head = list->output_list;
	}

	while (copied < count) {
		if (list_empty(&(head->list))) {
			wake_up_interruptible(&list->syscall_queue);
			break;
		}
		tmp = list_first_entry(&head->list, struct output_entry, list);
		stored = tmp->size - tmp->offset;
		if ((stored + copied) <= count) {
			if (copy_to_user(dst_ptr, tmp->ptr + tmp->offset, stored))
			{
				mutex_unlock(&pt_logfile_mtx);
				return -EFAULT;
			}
			list_del(&tmp->list);
			copied += stored;
			dst_ptr += stored;
			if (tmp->ptr)
			{
				if (tmp->is_pt_buf) {
					kmem_cache_free(pt_trace_cache, tmp->ptr);
				} else {
					kfree(tmp->ptr);
				}
				tmp->ptr = NULL;
			}
			kmem_cache_free(pt_monitor_output_cache, tmp);
		} else {
			if (copy_to_user(dst_ptr, tmp->ptr + tmp->offset, count - copied))
			{
				mutex_unlock(&pt_logfile_mtx);
				return -EFAULT;
			}
			tmp->offset += count - copied;
			copied += (count - copied);
			dst_ptr += (count - copied);
			break;
		}
	}
	mutex_unlock(&pt_logfile_mtx);

	*ppos += copied;
	return copied;
}

static ssize_t
pt_monitor_output_write(struct file *filp, const char __user *buf,
		size_t count, loff_t *ppos)
{
	return 0;
}

static ssize_t
pt_monitor_conf_read(struct file *file, char __user *buf,
		size_t count, loff_t *ppos)
{
	if (*ppos)
		return 0;

	if (copy_to_user(buf, &conf_flags, sizeof(uint64_t)))
		return -EFAULT;

	*ppos += sizeof(uint64_t);
	return sizeof(uint64_t);
}

static ssize_t
pt_monitor_conf_write(struct file *filp, const char __user *buf,
		size_t count, loff_t *ppos)
{
	char kbuf[CONF_BUF_MAX];

	if (count >= CONF_BUF_MAX)
		return -ENOMEM;
	if (*ppos != 0)
		return -EINVAL;
	if (atomic64_read(&pt_flying_tasks))
		return -EBUSY;

	memset(kbuf, 0, CONF_BUF_MAX);
	if (copy_from_user(kbuf, buf, count))
		return -EINVAL;

	// For now, only disable return compression can be configured
	// 0: Use return compression
	// 1: Do *not* use return compression
	switch (kbuf[0]) {
		case '1':
			pt_print("Return compression disabled\n");
			conf_flags = RTIT_CTL_DIS_RETC;
			break;
		case '0':
			pt_print("Return compression enabled\n");
			conf_flags = 0;
			break;
		default:
			return -EINVAL;
	}

	return count;
}

static const struct file_operations pt_monitor_fops = {
	.write = pt_monitor_write,
	.read = pt_monitor_read,
};

static const struct file_operations pt_monitor_output_fops = {
	.write = pt_monitor_output_write,
	.read = pt_monitor_output_read,
};

static const struct file_operations pt_monitor_output_pid_fops = {
	.write = pt_monitor_output_write,
	.read = pt_monitor_pid_read,
};

static const struct file_operations pt_monitor_conf_fops = {
	.write = pt_monitor_conf_write,
	.read = pt_monitor_conf_read,
};

static struct dentry *pt_pid_setup(pid_t pid)
{
	char name[64];
	struct dentry *pid_file;

	snprintf(name, 64, "pt_%d", pid);
	pid_file = debugfs_create_file(name, 0600, NULL, (void *) ((uintptr_t) pid),
			&pt_monitor_output_pid_fops);
	if (!pid_file)
		pt_print("failed to create %s\n", name);
	return pid_file;
}

static int pt_monitor_setup(void)
{
	pt_monitor_dentry = debugfs_create_file("pt_monitor",
			0600, NULL, NULL, &pt_monitor_fops);
	if (!pt_monitor_dentry) {
		pt_print("unable to create pt_monitor\n");
		return -ENOMEM;
	}

	pt_monitor_output = debugfs_create_file("pt_output",
			0600, NULL, NULL, &pt_monitor_output_fops);
	if (!pt_monitor_output) {
		pt_print("unable to create pt_output\n");
		if (pt_monitor_dentry)
			debugfs_remove(pt_monitor_dentry);
		return -ENOMEM;
	}

	pt_monitor_conf = debugfs_create_file("pt_conf",
			0600, NULL, NULL, &pt_monitor_conf_fops);
	if (!pt_monitor_conf) {
		pt_print("unable to create pt_conf\n");
		if (pt_monitor_output)
			debugfs_remove(pt_monitor_output);
		if (pt_monitor_dentry)
			debugfs_remove(pt_monitor_dentry);
		return -ENOMEM;
	}

	return 0;
}

static void pt_monitor_destroy(void)
{
	if (pt_monitor_dentry)
		debugfs_remove(pt_monitor_dentry);

	if (pt_monitor_output)
		debugfs_remove(pt_monitor_output);

	if (pt_monitor_conf)
		debugfs_remove(pt_monitor_conf);
}

static int pt_debugfs_wq_setup(void)
{
	int err = -ENOMEM;
	struct workqueue_attrs *attrs;

	pt_debugfs_wq = alloc_workqueue("pt_debugfs_wq", WQ_UNBOUND | WQ_HIGHPRI, 1);
	if (!pt_debugfs_wq)
		goto fail;

	attrs = alloc_workqueue_attrs(GFP_ATOMIC);
	if (!attrs)
		goto destroy_wq;

	err = apply_workqueue_attrs(pt_debugfs_wq, attrs);
	free_workqueue_attrs(attrs);
	if (err < 0)
		goto destroy_wq;

	return 0;

destroy_wq:
	destroy_workqueue(pt_debugfs_wq);
fail:
	return err;
}

static int pt_wq_setup(void)
{
	int err = -ENOMEM;
	struct workqueue_attrs *attrs;

	pt_wq = alloc_workqueue("pt_wq", WQ_UNBOUND | WQ_HIGHPRI, 1);
	if (!pt_wq)
		goto fail;

	attrs = alloc_workqueue_attrs(GFP_ATOMIC);
	if (!attrs)
		goto destroy_wq;

	err = apply_workqueue_attrs(pt_wq, attrs);
	free_workqueue_attrs(attrs);
	if (err < 0)
		goto destroy_wq;

	return 0;

destroy_wq:
	destroy_workqueue(pt_wq);
fail:
	return err;
}

static void pt_wq_destroy(void)
{
	flush_workqueue(pt_wq);
	destroy_workqueue(pt_wq);
}

static void do_setup_topa(struct topa *topa, void *raw)
{
	/* setup topa entries */
	topa->entries[0] = TOPA_ENTRY(virt_to_phys(raw),
			TOPA_ENTRY_SIZE_CHOICE, 0, 1, 0);
	topa->entries[1] = TOPA_ENTRY(virt_to_phys(raw + TOPA_BUFFER_SIZE),
			TOPA_ENTRY_SIZE_4K, 0, 1, 0);
	topa->entries[2] = TOPA_ENTRY(virt_to_phys(topa), 0, 0, 0, 1);

	topa->raw = raw;
}

static void pt_setup_topa(struct topa *topa, void *raw, struct task_struct *task)
{
	topa->task = task;
	INIT_LIST_HEAD(&topa->buffer_list);
	spin_lock_init(&topa->buffer_list_sl);
	topa->failed = false;
	topa->index = 0;

	do_setup_topa(topa, raw);
}

static void pt_setup_msr(struct topa *topa)
{
	wrmsrl(MSR_IA32_RTIT_STATUS, 0);
	wrmsrl(MSR_IA32_RTIT_OUTPUT_BASE, virt_to_phys(topa));
	wrmsrl(MSR_IA32_RTIT_OUTPUT_MASK, 0);
	if (filter_start && filter_end) {
		wrmsrl(MSR_IA32_RTIT_ADDR0_A, filter_start);
		wrmsrl(MSR_IA32_RTIT_ADDR0_B, filter_end);
		wrmsrl(MSR_IA32_RTIT_CTL, RTIT_CTL_TRACEEN | RTIT_CTL_TOPA
				| RTIT_CTL_BRANCH_EN | RTIT_CTL_USR
				| ((TOPA_ENTRY_SIZE_64K + 1) << 24) | RTIT_CTL_ADDR0_CFG
				| conf_flags);
	} else {
		wrmsrl(MSR_IA32_RTIT_ADDR0_A, 0);
		wrmsrl(MSR_IA32_RTIT_ADDR0_B, 0);
		wrmsrl(MSR_IA32_RTIT_CTL, RTIT_CTL_TRACEEN | RTIT_CTL_TOPA
				| RTIT_CTL_BRANCH_EN | RTIT_CTL_USR
				| ((TOPA_ENTRY_SIZE_64K + 1) << 24)
				| conf_flags);
	}
}

static void pt_setup_xsave(struct topa *topa, struct xregs_state *xsave)
{
	u64 *xregs = (u64 *) get_xsave_addr(xsave, XSTATE_INTEL_PT);

	xregs[PT_XSTATE_STATUS] = 0;
	xregs[PT_XSTATE_OUTPUT_BASE] = virt_to_phys(topa);
	xregs[PT_XSTATE_OUTPUT_MASK] = 0;
	if (filter_start && filter_end) {
		xregs[PT_XSTATE_ADDR0_A] = filter_start;
		xregs[PT_XSTATE_ADDR0_B] = filter_end;
		xregs[PT_XSTATE_CTL] = RTIT_CTL_TRACEEN | RTIT_CTL_TOPA
			| RTIT_CTL_BRANCH_EN | RTIT_CTL_USR
			| ((TOPA_ENTRY_SIZE_64K + 1) << 24) | RTIT_CTL_ADDR0_CFG
			| conf_flags;
	} else {
		xregs[PT_XSTATE_ADDR0_A] = 0;
		xregs[PT_XSTATE_ADDR0_B] = 0;
		xregs[PT_XSTATE_CTL] = RTIT_CTL_TRACEEN | RTIT_CTL_TOPA
			| RTIT_CTL_BRANCH_EN | RTIT_CTL_USR
			| ((TOPA_ENTRY_SIZE_64K + 1) << 24)
			| conf_flags;
	}
}

static void pt_work(struct work_struct *work)
{
	struct pt_buffer *buf = (struct pt_buffer *) work;

	pt_log_buffer(buf);
	if (buf->notifier)
		complete(buf->notifier);
	kmem_cache_free(pt_buffer_cache, buf);
}

static void pt_tasklet(unsigned long data)
{
	struct pt_buffer *buf = (struct pt_buffer *) data;

	queue_work(pt_wq, &buf->work);
}

static int pt_move_trace_to_work(struct topa *topa, u32 size,
		struct topa *child_topa, bool waiting)
{
	struct pt_buffer *buf;
	DECLARE_COMPLETION(notifier);

	buf = kmem_cache_alloc(pt_buffer_cache, GFP_ATOMIC);
	if (!buf)
		goto fail;

	INIT_WORK(&buf->work, pt_work);
	tasklet_init(&buf->tasklet, pt_tasklet, (unsigned long) buf);
	INIT_LIST_HEAD(&buf->entry);
	buf->topa = topa;
	buf->child_topa = child_topa;
	buf->notifier = waiting? &notifier: NULL;
	buf->size = size;
	buf->index = 0;
	buf->raw = topa->raw;

	tasklet_schedule(&buf->tasklet);

	if (waiting)
		wait_for_completion(&notifier);

	return 0;

fail:
	return -ENOMEM;
}

static void pt_flush_trace(struct topa *child_topa, bool waiting)
{
	u32 size;
	struct topa *topa;
	void *new_buffer;

	topa = phys_to_virt(pt_topa_base());
	if (topa->failed && !child_topa && !waiting)
		goto end;

	size = pt_topa_offset() + (pt_topa_index()? TOPA_BUFFER_SIZE: 0);

	new_buffer = (void *) kmem_cache_alloc(pt_trace_cache, GFP_ATOMIC);
	if (!new_buffer)
		goto failed;

	if (pt_move_trace_to_work(topa, size, child_topa, waiting) < 0)
		goto free_new_buffer;

	do_setup_topa(topa, new_buffer);

end:
	wrmsrl(MSR_IA32_RTIT_STATUS, 0);
	wrmsrl(MSR_IA32_RTIT_OUTPUT_MASK, 0);
	return;

free_new_buffer:
	kmem_cache_free(pt_trace_cache, new_buffer);
failed:
	pt_fail_topa(topa, "Out of memory, dropping PT data\n");
	goto end;
}

static struct topa *pt_alloc_topa(struct task_struct *task)
{
	struct topa *topa;
	void *raw;

	topa = (struct topa *) __get_free_pages(GFP_KERNEL, 1);
	if (!topa)
		goto fail;

	raw = (void *) kmem_cache_alloc(pt_trace_cache, GFP_KERNEL);
	if (!raw)
		goto free_topa;

	pt_setup_topa(topa, raw, task);

	return topa;

free_topa:
	free_pages((unsigned long) topa, 1);
fail:
	return NULL;
}

static bool pt_should_monitor(struct task_struct *task)
{
	char *path, *buf;
	size_t path_len, monitor_len;
	struct mm_struct *mm;
	bool monitored = false;

	monitor_len = strlen(pt_monitor);
	if (!monitor_len)
		return false;

	mm = task->mm;
	if (!mm)
		return false;

	down_read(&mm->mmap_sem);

	if (!mm->exe_file)
		goto up_read_sem;

	buf = kmalloc(PATH_MAX, GFP_KERNEL);
	if (!buf)
		goto up_read_sem;

	path = d_path(&task->mm->exe_file->f_path, buf, PATH_MAX);
	path_len = strlen(path);

	if (monitor_len > path_len)
		goto free_buf;

	monitored = strncmp(path + (path_len - monitor_len),
			pt_monitor, monitor_len) == 0;

free_buf:
	kfree(buf);
up_read_sem:
	up_read(&mm->mmap_sem);
	return monitored;
}

void pt_pre_execve(void)
{
	if (!pt_enabled())
		return;

	pt_pause();
	pt_flush_trace(NULL, true);
	pt_resume();
}

static void pt_clear_rlimit(struct task_struct *task)
{
	task->signal->rlim[RLIMIT_MEMLOCK] = (struct rlimit) {
		RLIM64_INFINITY, RLIM64_INFINITY
	};

	task->signal->rlim[RLIMIT_AS] = (struct rlimit) {
		RLIM64_INFINITY, RLIM64_INFINITY
	};
}

struct pt_debugfs_work {
	struct work_struct work;
	pid_t pid;
	struct outputs_list *list;
};

static void do_pt_debugfs_work(struct work_struct *work)
{
	struct pt_debugfs_work *debug_work = (struct pt_debugfs_work *) work;
	mutex_lock(&pt_logfile_mtx);
	debug_work->list->file = pt_pid_setup(debug_work->pid);
	// If the PID we just created a pseudo-file for is the root process,
	// wake up anyone waiting for tracing to start.
	if (debug_work->pid == root_pid)
		wake_up_interruptible(&output_start_wait);
	mutex_unlock(&pt_logfile_mtx);
}

static void pt_create_list(pid_t pid)
{
	struct output_entry *entry;
	struct outputs_list *list;
	struct pt_debugfs_work *work;

	mutex_lock(&pt_logfile_mtx);
	// If there are no output lists, this is the root process.
	// The debugfs worker will wake up threads in the output_start_wait queue.
	if (list_empty(&monitor_outputs_list.list))
		root_pid = pid;
	if (!find_outputs_list(pid)) {
		// This process doesn't have an output list, create it.
		list = (struct outputs_list *) kmalloc(sizeof(struct outputs_list), GFP_KERNEL);
		entry = kmem_cache_alloc(pt_monitor_output_cache, GFP_KERNEL);
		if (!entry) {
			pt_print("Failed to create output list for PID %d, out of memory\n", pid);
			mutex_unlock(&pt_logfile_mtx);
			return;
		}
		INIT_LIST_HEAD(&(entry->list));
		entry->ptr = NULL;
		entry->is_pt_buf = 0;
		list->output_list = entry;
		list->pid = pid;
		list->file = NULL;
		init_waitqueue_head(&list->syscall_queue);
		list_add_tail(&(list->list), &monitor_outputs_list.list);
		// list->file will be initialized by the following worker because pseudo-files can't
		// be created in syscall context.
		work = (struct pt_debugfs_work *) kmalloc(sizeof(struct pt_debugfs_work), GFP_KERNEL);
		INIT_WORK((struct work_struct *) work, do_pt_debugfs_work);
		work->pid = pid;
		work->list = list;
		queue_work(pt_debugfs_wq, (struct work_struct *) work);
	}
	mutex_unlock(&pt_logfile_mtx);
}

static inline struct topa *pt_attach(struct task_struct *task)
{
	struct topa *topa = pt_alloc_topa(task);

	if (task == current)
		pt_setup_msr(topa);
	else
		pt_setup_xsave(topa, &task->thread.fpu.state.xsave);

	atomic64_inc(&pt_flying_tasks);
	if (!atomic64_read(&pt_has_flown))
		atomic64_set(&pt_has_flown, 1);

	return topa;
}

static inline void pt_detach(void)
{
	struct topa *topa;

	pt_pause();

	topa = phys_to_virt(pt_topa_base());

	pt_move_trace_to_work(topa, pt_topa_offset(), NULL, true);

	free_pages((unsigned long) topa, 1);

	atomic64_dec(&pt_flying_tasks);

	if (!atomic64_read(&pt_flying_tasks)) {
		mutex_lock(&pt_logfile_mtx);
		wake_up_interruptible(&output_read_wait);
		mutex_unlock(&pt_logfile_mtx);
	}
}

void pt_on_execve(void)
{
	if (pt_enabled()) // execve()'ed from a task under tracing
		pt_detach();

	if (!pt_should_monitor(current))
		return;

	pt_create_list(current->pid);
	pt_log_process(current);

	pt_clear_rlimit(current);

	pt_attach(current);
}

void pt_on_exit(void)
{
	if (!pt_enabled())
		return;

	pt_detach();
}

int pt_on_interrupt(struct pt_regs *regs)
{
	int pt_on;
	u64 *xregs;

	if (!strlen(pt_monitor))
		return -ENOSYS;

	pt_on = pt_enabled();
	if (pt_on) /* off if triggered upon disabling PT */
		pt_pause();

	pt_flush_trace(NULL, false);

#define is_xsaves(ip) ((*(unsigned int *)(ip) & 0xffffff) == 0x2fc70f)
	if (pt_on) {
		pt_resume();
	} else if (is_xsaves(regs->ip - 3)) {
		xregs = (u64 *) get_xsave_addr((struct xregs_state *) regs->di,
				XSTATE_INTEL_PT);
		xregs[PT_XSTATE_STATUS] = 0;
		xregs[PT_XSTATE_OUTPUT_MASK] = 0;
	}

	return 0;
}

void pt_on_clone(struct task_struct *child)
{
	struct topa *child_topa, *topa;

	if (!pt_enabled())
		return;

	child_topa = pt_attach(child);

	if (child->tgid == child->pid) {
		/* setup initial sequence numbers */
		topa = phys_to_virt(pt_topa_base());
		/* flush the parent's trace */
		pt_pause();
		pt_flush_trace(child_topa, 1);
		pt_resume();
	}

	pt_create_list(current->pid);
	pt_create_list(child->pid);
	if (child->tgid == child->pid) {
		pt_log_fork(current, child);
		pt_log_process(child);
	} else {
		pt_log_thread(child);
	}

	pt_clear_rlimit(current);
	pt_clear_rlimit(child);
}

void pt_on_syscall(struct pt_regs *regs)
{
	struct outputs_list *list;

	if (!pt_enabled())
		return;

	switch (regs->orig_ax) {
	case __NR_mmap:
	case __NR_mprotect:
		if (!(regs->dx & PROT_EXEC))
			return;
		break;
	case __NR_sendmsg:
	case __NR_sendmmsg:
	case __NR_sendto:
		break;
	default:
		return;
	}

	pt_pause();
	pt_flush_trace(NULL, true);
	pt_resume();

	mutex_lock(&pt_logfile_mtx);
	list = find_outputs_list(current->pid);
	if (list && !list_empty(&list->output_list->list)) {
		// Some PT data for this process hasn't be consumed and we're
		// at an enforcement point. Sleep until analyst is caught up.
		DECLARE_WAITQUEUE(wait, current);
		add_wait_queue(&list->syscall_queue, &wait);
		current->state = TASK_INTERRUPTIBLE;
		mutex_unlock(&pt_logfile_mtx);
		schedule();
		current->state = TASK_RUNNING;
		remove_wait_queue(&list->syscall_queue, &wait);
		mutex_lock(&pt_logfile_mtx);
	}
	mutex_unlock(&pt_logfile_mtx);
}

static int __init pt_init(void)
{
	int ret = -ENOMEM;

	if (!pt_avail())
		return -ENXIO;

	INIT_LIST_HEAD(&monitor_outputs_list.list);

	/* create a cache for monitor output list items */
	pt_monitor_output_cache = kmem_cache_create("pt_monitor_output_cache",
			sizeof(struct output_entry), 0, 0, NULL);
	if (!pt_monitor_output_cache)
		goto fail;

	/* create a cache for buffers to enable dynamic (de)allocation */
	pt_buffer_cache = kmem_cache_create("pt_buffer_cache",
			sizeof(struct pt_buffer), 0, 0, NULL);
	if (!pt_buffer_cache)
		goto destroy_monitor_output_cache;

	/* create a cache for filled traces */
	pt_trace_cache = kmem_cache_create("pt_trace_cache",
			TOPA_BUFFER_SIZE + PAGE_SIZE, TOPA_BUFFER_SIZE,
			0, NULL);
	if (!pt_trace_cache)
		goto destroy_buffer_cache;

	/* setup the workqueue for async computation */
	ret = pt_wq_setup();
	if (ret < 0)
		goto destroy_trace_cache;

	/* setup the workqueue for debugfs */
	ret = pt_debugfs_wq_setup();
	if (ret < 0)
		goto destroy_wq;

	/* create pt_monitor file */
	ret = pt_monitor_setup();
	if (ret < 0)
		goto destroy_wq;

	memset(pt_monitor, 0, PATH_MAX);

	return ret;

destroy_wq:
	pt_wq_destroy();
destroy_trace_cache:
	kmem_cache_destroy(pt_trace_cache);
destroy_buffer_cache:
	kmem_cache_destroy(pt_buffer_cache);
destroy_monitor_output_cache:
	kmem_cache_destroy(pt_monitor_output_cache);
fail:
	return ret;
}

static void __exit pt_exit(void)
{
	pt_monitor_destroy();
	pt_wq_destroy();
	kmem_cache_destroy(pt_trace_cache);
	kmem_cache_destroy(pt_buffer_cache);
	kmem_cache_destroy(pt_monitor_output_cache);
}

module_init(pt_init);
module_exit(pt_exit);
MODULE_LICENSE("GPL");
