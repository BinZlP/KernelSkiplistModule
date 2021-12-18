#include "skiplist_api.h"

MultiSkiplist *global_skiplist;

static int f2fs_kv_compare_func(const void *p1, const void *p2) {
    NAT_Entry *e1 = (NAT_Entry *)p1;
    NAT_Entry *e2 = (NAT_Entry *)p2;

    return e1->node_id - e2->node_id;
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
        printk("SKiplist | initialized\n");
#endif
    } else {
#ifdef _SKIPLIST_API_DEBUG
        printk("Skiplist | initialization failed\n");
#endif
    }

    return -result;
}
EXPORT_SYMBOL(f2fs_kv_init);


void *f2fs_kv_get(int node_id) {
    void *ret = multi_skiplist_find(global_skiplist, (void *)(&node_id));
#ifdef _SKIPLIST_API_DEBUG
    if(ret != NULL) {
        printk("Skiplist | node found - ID: %d\n", ((NAT_Entry *)ret)->node_id);
    } else {
        printk("Skiplist | node %d not found\n", node_id);
    }
#endif
    return ret;
}
EXPORT_SYMBOL(f2fs_kv_get);


int f2fs_kv_put(int node_id, void *blk_addr) {
    int result;
    NAT_Entry *entry = (NAT_Entry *)kmalloc(sizeof(NAT_Entry), GFP_KERNEL);
    entry->node_id = node_id;
    entry->blk_addr = blk_addr;
    
    result = multi_skiplist_insert(global_skiplist, (void *)entry);
#ifdef _SKIPLIST_API_DEBUG
    if(result == 0) {
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