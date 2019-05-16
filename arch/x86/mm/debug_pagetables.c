// SPDX-License-Identifier: GPL-2.0-only
#include <linux/debugfs.h>
#include <linux/efi.h>
#include <linux/sched/task.h>
#include <linux/module.h>
#include <linux/seq_file.h>
#include <asm/pgtable.h>

static int ptdump_show(struct seq_file *m, void *v)
{
	ptdump_walk_pgd_level_debugfs(m, NULL, false);
	return 0;
}

DEFINE_SHOW_ATTRIBUTE(ptdump);

static int ptdump_curknl_show(struct seq_file *m, void *v)
{
	if (current->mm->pgd) {
		down_read(&current->mm->mmap_sem);
		ptdump_walk_pgd_level_debugfs(m, current->mm->pgd, false);
		up_read(&current->mm->mmap_sem);
	}
	return 0;
}

DEFINE_SHOW_ATTRIBUTE(ptdump_curknl);

#ifdef CONFIG_PAGE_TABLE_ISOLATION
static struct dentry *pe_curusr;

static int ptdump_curusr_show(struct seq_file *m, void *v)
{
	if (current->mm->pgd) {
		down_read(&current->mm->mmap_sem);
		ptdump_walk_pgd_level_debugfs(m, current->mm->pgd, true);
		up_read(&current->mm->mmap_sem);
	}
	return 0;
}

DEFINE_SHOW_ATTRIBUTE(ptdump_curusr);
#endif

#if defined(CONFIG_EFI) && defined(CONFIG_X86_64)
static struct dentry *pe_efi;

static int ptdump_efi_show(struct seq_file *m, void *v)
{
	if (efi_mm.pgd)
		ptdump_walk_pgd_level_debugfs(m, efi_mm.pgd, false);
	return 0;
}

DEFINE_SHOW_ATTRIBUTE(ptdump_efi);
#endif

pid_t sysctl_dump_pt_pid __read_mostly = -1;
static struct dentry *pe_pid;

static int ptdump_pid_show(struct seq_file *m, void *v)
{
	struct task_struct *tsk;
	struct pid *pid;

	pid = find_get_pid(sysctl_dump_pt_pid);
	if (!pid)
		return 0;
	tsk = get_pid_task(pid, PIDTYPE_PID);
	if (!tsk) {
		put_pid(pid);
		return 0;
	}

	if (tsk->mm->pgd) {
		down_read(&tsk->mm->mmap_sem);
		ptdump_walk_pgd_level_debugfs(m, tsk->mm->pgd, true);
		up_read(&tsk->mm->mmap_sem);
	}
	put_task_struct(tsk);
	put_pid(pid);
	return 0;
}

DEFINE_SHOW_ATTRIBUTE(ptdump_pid);

static struct dentry *dir, *pe_knl, *pe_curknl, *pe_pid;

static int __init pt_dump_debug_init(void)
{
	dir = debugfs_create_dir("page_tables", NULL);
	if (!dir)
		return -ENOMEM;

	pe_knl = debugfs_create_file("kernel", 0400, dir, NULL,
				     &ptdump_fops);
	if (!pe_knl)
		goto err;

	pe_curknl = debugfs_create_file("current_kernel", 0400,
					dir, NULL, &ptdump_curknl_fops);
	if (!pe_curknl)
		goto err;

#ifdef CONFIG_PAGE_TABLE_ISOLATION
	pe_curusr = debugfs_create_file("current_user", 0400,
					dir, NULL, &ptdump_curusr_fops);
	if (!pe_curusr)
		goto err;
#endif

#if defined(CONFIG_EFI) && defined(CONFIG_X86_64)
	pe_efi = debugfs_create_file("efi", 0400, dir, NULL, &ptdump_efi_fops);
	if (!pe_efi)
		goto err;
#endif
	pe_pid = debugfs_create_file("dump_pid", 0400, dir, NULL, &ptdump_pid_fops);
	if (!pe_pid)
		goto err;

	return 0;
err:
	debugfs_remove_recursive(dir);
	return -ENOMEM;
}

static void __exit pt_dump_debug_exit(void)
{
	debugfs_remove_recursive(dir);
}

module_init(pt_dump_debug_init);
module_exit(pt_dump_debug_exit);
MODULE_LICENSE("GPL");
MODULE_AUTHOR("Arjan van de Ven <arjan@linux.intel.com>");
MODULE_DESCRIPTION("Kernel debugging helper that dumps pagetables");
