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

static int skiplist_put(__u32 node_id, F2FS_NAT_Entry entry) {
    int result;

    result = f2fs_kv_put(node_id, entry);

    
    return result;
}

static F2FS_NAT_Entry skiplist_get(__u32 node_id) {
    F2FS_NAT_Entry result = f2fs_kv_get(node_id);
    return result;
}

ssize_t skiplist_read(struct file *fp, char __user *user_buffer,
        size_t length, loff_t *position) {
    
    int result;
    F2FS_NAT_Entry result_nat;
    // NAT_Entry entry;
    // F2FS_NAT_Entry entry;
    Skiplist_Entry entry;
    result = copy_from_user(&entry, user_buffer, sizeof(entry));
    if(result < 0) {
        printk(KERN_ERR "copy_from_user() failed: %d\n", result);
        return -result;
    }
    printk("Skiplist | Received data from user: %d - %d %d %d\n", entry.nid, entry.nat_entry.ino, entry.nat_entry.block_addr, entry.nat_entry.version);

    if(entry.nat_entry.block_addr == 0) {
        result_nat = skiplist_get(entry.nid);
        entry.nat_entry = result_nat;
        result = copy_to_user(user_buffer + sizeof(Skiplist_Entry),
            &entry, sizeof(Skiplist_Entry));
        if(result < 0) printk(KERN_ERR "copy_to_user() failed: %d\n", result);
        else printk("entry data: %d - %d %d %d\n", entry.nid, entry.nat_entry.ino, 
                        entry.nat_entry.block_addr, entry.nat_entry.version);
    } else {
        result = skiplist_put(entry.nid, entry.nat_entry);
        if(result < 0) return result;
        result = copy_to_user(user_buffer + sizeof(F2FS_NAT_Entry) + sizeof(__u8), &result, sizeof(int));
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