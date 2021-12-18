#include <linux/string.h>

#include "skiplist_api.h"

MultiSkiplist *global_skiplist;

static int f2fs_kv_compare_func(const void *p1, const void *p2) {
    // NAT_Entry *e1 = (NAT_Entry *)p1;
    // NAT_Entry *e2 = (NAT_Entry *)p2;
    // F2FS_NAT_Entry *e1 = (F2FS_NAT_Entry *)p1;
    // F2FS_NAT_Entry *e2 = (F2FS_NAT_Entry *)p2;
    Skiplist_Entry *e1 = (Skiplist_Entry *)p1;
    Skiplist_Entry *e2 = (Skiplist_Entry *)p2;

    return e1->nid - e2->nid;
}

static void f2fs_kv_free_func(void *ptr) {
    kfree(ptr);
}

int f2fs_kv_init(const int level_count) {
    int result;

    fast_mblock_manager_init();

    global_skiplist = kmalloc(sizeof(MultiSkiplist), GFP_KERNEL);
    
    result = multi_skiplist_init(global_skiplist, level_count, 
                f2fs_kv_compare_func, f2fs_kv_free_func);

    if(result == 0) {
#ifdef _SKIPLIST_API_DEBUG
        printk("SKiplist | Initialized.\n");
#endif
    } else {
#ifdef _SKIPLIST_API_DEBUG
        printk("Skiplist | Initialization failed.\n");
#endif
    }

    return -result;
}
EXPORT_SYMBOL(f2fs_kv_init);


F2FS_NAT_Entry f2fs_kv_get(__u32 node_id) {
    Skiplist_Entry entry;
    entry.nid = node_id;
    void *ret = multi_skiplist_find(global_skiplist, (void *)(&entry));
#ifdef _SKIPLIST_API_DEBUG
    if(ret != NULL) {
        // printk("Skiplist | node found - ID: %d\n", ((NAT_Entry *)ret)->node_id);
        printk("Skiplist | node found - INODE: %d\n", ((F2FS_NAT_Entry *)ret)->ino);
    } else {
        printk("Skiplist | node %d not found\n", node_id);
    }
#endif
    if(ret != NULL) 
        memcpy(&entry, ret, sizeof(Skiplist_Entry));

    return entry.nat_entry;
}
EXPORT_SYMBOL(f2fs_kv_get);


int f2fs_kv_put(__u32 node_id, F2FS_NAT_Entry entry) {
    int result = 0;
    void *ret;

    // NAT_Entry *entry = (NAT_Entry *)kmalloc(sizeof(NAT_Entry), GFP_KERNEL);
    // F2FS_NAT_Entry *entry = (F2FS_NAT_Entry *)kmalloc(sizeof(F2FS_NAT_Entry), GFP_KERNEL);
    Skiplist_Entry *s_entry = (Skiplist_Entry *)kmalloc(sizeof(Skiplist_Entry), GFP_KERNEL);
    s_entry->nid = node_id;
    s_entry->nat_entry.ino = entry.ino;
    s_entry->nat_entry.block_addr = entry.block_addr;
    s_entry->nat_entry.version = entry.version;
    
    ret = multi_skiplist_find(global_skiplist, (void *)(&s_entry));
    if(ret) { // Update data
        ((Skiplist_Entry *)ret)->nat_entry = entry;
    } else { // Insert new data
        result = multi_skiplist_insert(global_skiplist, (void *)s_entry);
    }
    
#ifdef _SKIPLIST_API_DEBUG
    if(result == 0) {
        if(ret)
            printk("Skiplist | Updated node %d\n", node_id);
        else
            printk("Skiplist | Inserted node %d\n", node_id);
    } else {
        printk("Skiplist | Failed to insert node %d. errno: %d, errmsg: %s\n", 
                node_id, result, STRERROR(result));
    }
#endif
    return -result;
}
EXPORT_SYMBOL(f2fs_kv_put);


void f2fs_kv_destroy(void) {
    multi_skiplist_destroy(global_skiplist);
    kfree(global_skiplist);
#ifdef _SKIPLIST_API_DEBUG
    printk("Skiplist | destroyed\n");
#endif
}
EXPORT_SYMBOL(f2fs_kv_destroy);