#include <linux/kernel.h>
#include <linux/module.h>

int init_module(void)
{
	printk("%s is saying:\n"
	       "Hello, I'm the parasite.\n"
	       "I'm willing to attend H2HC 2018 conference.\n", KBUILD_MODNAME);
	return -EINVAL;
}

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Ilya V. Matveychikov");