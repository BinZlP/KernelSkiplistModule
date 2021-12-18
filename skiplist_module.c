#include <linux/init.h>
#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/debugfs.h>
#include <linux/uaccess.h>
#include <linux/fs.h>

#include "skiplist_api.h"

#define LEVEL_COUNT 16

#define DBFS_DIR "skiplist"
#define DBFS_OUTPUT "output"

MODULE_LICENSE("GPL");

static struct dentry *dir, *output;

static int skiplist_put(int node_id, void *blk_addr) {
    int result;
    
    result = f2fs_kv_put(node_id, blk_addr);

    
    return result;
}

static void *skiplist_get(int node_id) {
    void *result = f2fs_kv_get(node_id);
    return result;
}

ssize_t skiplist_read(struct file *fp, char __user *user_buffer,
        size_t length, loff_t *position) {
    
    int result;
    void *result_buf;
    NAT_Entry entry;
    result = copy_from_user(&entry, user_buffer, length);
    if(result < 0) {
        printk(KERN_ERR "copy_from_user() failed: %d\n", result);
        return -result;
    }

    if(entry.blk_addr == 0) {
        result_buf = skiplist_get(entry.node_id);
        result = copy_to_user(user_buffer + sizeof(NAT_Entry) + sizeof(int),
            &result_buf, sizeof(void *));
        if(result < 0) printk(KERN_ERR "copy_to_user() failed: %d\n", result);
    } else {
        result = skiplist_put(entry.node_id, entry.blk_addr);
        if(result < 0) return result;
        result = copy_to_user(user_buffer + sizeof(NAT_Entry), &result, sizeof(int));
        if(result < 0) printk(KERN_ERR "copy_to_user() failed: %d\n", result);
    }
    return -result;
}

static const struct file_operations dbfs_slops = {
    .read = skiplist_read
};

static int __init skiplist_module_init(void)
{
    dir = debugfs_create_dir(DBFS_DIR, NULL);
    if(!dir) {
        printk(KERN_ERR "Cannot create directory: %s\n", DBFS_DIR);
        return -1;
    }

    output = debugfs_create_file(DBFS_OUTPUT, 0644, dir, NULL, &dbfs_slops);

    f2fs_kv_init(LEVEL_COUNT);
    return 0;
}

static void __exit skiplist_module_exit(void)
{
    debugfs_remove(dir);
    dir = NULL;
    f2fs_kv_destroy();
}

module_init(skiplist_module_init);
module_exit(skiplist_module_exit);