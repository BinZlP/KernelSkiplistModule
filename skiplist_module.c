#include <linux/kernel.h>

MODULE_LICENSE("GPL");

static int __init skiplist_module_init(void)
{

    return 0;
}

static void __exit skiplist_module_exit(void)
{

}

module_init(skiplist_module_init);
module_exit(skiplist_module_exit);