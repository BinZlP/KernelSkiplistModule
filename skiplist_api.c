#include <linux/string.h>
#include <linux/mutex.h>
#include "skiplist_api.h"

typedef struct {
    MultiSkiplist *sl;
    ThreadNode *node;
}ThreadArgs;

typedef struct _PendingSLEntry {
    MultiSkiplist *sl_addr;
    struct _PendingSLEntry *next;
    struct _PendingSLEntry *prev;
} PendingSLEntry;

typedef struct {
    PendingSLEntry *sl_head;
    struct mutex list_lock;
} PendingSLManager;

int sl_max_level;
MultiSkiplist *global_skiplist;
int cur_entry_num, flush_count;
BlockAddressNode *flushed_head;
// ThreadNode *kthread_head;
struct mutex check_lock;

PendingSLManager pending_sl;

static inline PendingSLEntry *pending_sl_insert_head(MultiSkiplist *sl) {
    PendingSLEntry *entry = (PendingSLEntry *)kmalloc(sizeof(PendingSLEntry), GFP_KERNEL);
    entry->sl_addr = sl;
    entry->prev = NULL;

    mutex_lock(&(pending_sl.list_lock));
    if(pending_sl.sl_head == NULL) {
        entry->next = NULL;
        pending_sl.sl_head = entry;
    } else {
        pending_sl.sl_head->prev = entry;
        entry->next = pending_sl.sl_head;
        pending_sl.sl_head = entry;
    }
    mutex_unlock(&(pending_sl.list_lock));

    return entry;
}

static inline void pending_sl_remove_from_list(PendingSLEntry *entry) {
    PendingSLEntry *tmp;

    mutex_lock(&(pending_sl.list_lock));
    if(entry == pending_sl.sl_head) {
        if(entry->next == NULL) // if entry is head & no other entries in list
            pending_sl.sl_head = NULL;
        else { // there're some entries behind
            entry->next->prev = NULL;
            pending_sl.sl_head = entry->next;
        }
    } else {
        entry->prev->next = entry->next;
        if(entry->next != NULL) // If this entry is not a tail
            entry->next->prev = entry->prev;
    }

    mutex_unlock(&(pending_sl.list_lock));

    multi_skiplist_destroy(entry->sl_addr);
    kfree(entry->sl_addr);
    kfree(entry);
}

static inline Skiplist_Entry pending_sl_get_entry(Skiplist_Entry *target) {
    PendingSLEntry *it;
    Skiplist_Entry *find_ret;
    Skiplist_Entry ret = {0, {0,0,0}};

    mutex_lock(&(pending_sl.list_lock));
#ifdef _SKIPLIST_API_DEBUG
    it = pending_sl.sl_head;
    printk("PendSL | Search start. Head: %px\n", it);
    while(it != NULL) {
        it = it->next;
        ("PendSL | it->next: %px\n", it);
    }
#endif

    it = pending_sl.sl_head;
    while(it != NULL) {
        find_ret = multi_skiplist_find(it->sl_addr, (void *)target);
        if(find_ret != NULL) {
            ret = *find_ret;
            break;
        }
    }
    mutex_unlock(&(pending_sl.list_lock));

    return ret;
}

/*
 * Superblock information object from the F2FS node manager initialization.
 * We only have this single instance which means we only support for single
 * mount file system for now.
 */

void f2fs_kv_flush(void *s, void *arr, int size, unsigned int *blkaddr);
void f2fs_kv_read(struct page *page, void *s, unsigned int blkaddr);
static struct f2fs_sb_info *sbi;


const char *f2fs_kv_entry_to_string(void *data, char *buff, const int size) {
    Skiplist_Entry *entry = (Skiplist_Entry *)data;
    snprintf(buff, 1024, "NodeID: %d {INO: %d, BLK_ADDR: %px, Ver: %d}", 
        entry->nid, entry->nat_entry.ino, entry->nat_entry.block_addr, entry->nat_entry.version);
    return buff;
}

int f2fs_kv_compare_func(const void *p1, const void *p2) {
    // NAT_Entry *e1 = (NAT_Entry *)p1;
    // NAT_Entry *e2 = (NAT_Entry *)p2;
    // F2FS_NAT_Entry *e1 = (F2FS_NAT_Entry *)p1;
    // F2FS_NAT_Entry *e2 = (F2FS_NAT_Entry *)p2;
    Skiplist_Entry *e1 = (Skiplist_Entry *)p1;
    Skiplist_Entry *e2 = (Skiplist_Entry *)p2;

    return e1->nid - e2->nid;
}

void f2fs_kv_free_func(void *ptr) {
    kfree(ptr);
}

int f2fs_kv_flush_thread(void *arg) {
    MultiSkiplist *sl = ((MultiSkiplist *)arg);
    // ThreadNode *my_node = ((ThreadArgs *)arg)->node;
    // ThreadNode *tnode_it;
    BlockAddressNode *node;
    PendingSLEntry *psl_entry;
    u32 blkaddr;
    int arr_size = 0, i;
    int nr_pages = max(DATA_ARRAY_SIZE / PAGE_SIZE, 1);
    struct page *page;
    void *array;
#ifdef _SKIPLIST_API_DEBUG
    Skiplist_Entry tmp_entry;
    printk("Flush | Entered flush thread, arg: sl=%px\n", sl);
#endif

    psl_entry = pending_sl_insert_head(sl);
#ifdef _SKIPLIST_API_DEBUG
    printk("Flush | Insertion to pending sl list completed\n");
#endif

    nr_pages = max(ilog2(nr_pages), 1);
    page = alloc_pages(GFP_KERNEL, max(ilog2(nr_pages), 1));
    nr_pages = 1 << nr_pages;

    array = page_address(page);
#ifdef _SKIPLIST_API_DEBUG
    printk("Flush |  array: %px / sl=%px\n", array, sl);
#endif

    arr_size = multi_skiplist_to_array(sl, array);
#ifdef _SKIPLIST_API_DEBUG
    printk("Flush | Flush skiplist : \n");
    for(i=0; i<arr_size/sizeof(Skiplist_Entry); i++) {
        tmp_entry = ((Skiplist_Entry *)array)[i];
        printk("  [%d] %d - %d %px %d\n", i, tmp_entry.nid, tmp_entry.nat_entry.ino, 
                    tmp_entry.nat_entry.block_addr, tmp_entry.nat_entry.version);
    }
#endif

#ifdef _SKIPLIST_API_F2FS
    f2fs_kv_flush(sbi, array, nr_pages, &blkaddr);
#else
    blkaddr = (void *)0xdeadbeef;
#endif

    // Add BlockAddressNode to the global linked list's head
    node = (BlockAddressNode *)kmalloc(sizeof(BlockAddressNode), GFP_KERNEL);
    node->block_address = (void *) blkaddr;
    node->size = arr_size;
    node->prev = NULL;
    
    trace_printk("KV flushed to blkaddr=0x%x\n", blkaddr);

    if(flushed_head != NULL) {
        node->next = flushed_head;
        flushed_head->prev = node;
    } else {
        node->next = NULL;
    }
    flushed_head = node;

    // multi_skiplist_destroy(sl);
    // kfree(sl);
    pending_sl_remove_from_list(psl_entry);
    kfree(array);

    // Stop finished threads
    // my_node->is_done = true;
    // tnode_it = my_node->next;
    // while(tnode_it != NULL) {
    //     if(tnode_it->is_done) {
    //         kthread_stop(tnode_it->task);
    //         my_node->next = tnode_it->next;
    //         kfree(tnode_it);
    //     } else { // Thread not done
    //         tnode_it->prev = my_node;
    //         break;
    //     }
    //     tnode_it = my_node->next;
    // }
    // my_node->next = tnode_it;
    
    printk("Flush thread end\n");
    return 0;
}



int f2fs_kv_init(const int level_count) {
    int result;

    fast_mblock_manager_init();

    global_skiplist = kmalloc(sizeof(MultiSkiplist), GFP_KERNEL);
    
    result = multi_skiplist_init(global_skiplist, level_count, 
                f2fs_kv_compare_func, f2fs_kv_free_func);

    sl_max_level = level_count;
    cur_entry_num = 0;
    flush_count = 0;
    flushed_head = NULL;

    mutex_init(&(pending_sl.list_lock));
    pending_sl.sl_head = NULL;

    if(result == 0) {
#ifdef _SKIPLIST_API_DEBUG
        printk("Skiplist | Initialized.\n");
        printk("sl: %px, top: %px\n", global_skiplist, global_skiplist->top);
#endif
    } else {
#ifdef _SKIPLIST_API_DEBUG
        printk("Skiplist | Initialization failed.\n");
#endif
    }

    return -result;
}
EXPORT_SYMBOL(f2fs_kv_init);

int f2fs_kv_init_sbi(const int level_count, void *_sbi)
{
	sbi = _sbi;
	return f2fs_kv_init(level_count);
}


F2FS_NAT_Entry f2fs_kv_get(__u32 node_id) {
    Skiplist_Entry entry = {0, {0,0,0}}, p_entry = {0, {0,0,0}};
    void *ret, *blk_buf;
    int i;
    BlockAddressNode *it;
    bool is_found = false;
#ifdef _SKIPLIST_API_F2FS
    struct page *page;
    Skiplist_Entry *e;
#endif

    entry.nid = node_id;
    ret = multi_skiplist_find(global_skiplist, (void *)(&entry));

    if(ret != NULL) { // If target node found
        memcpy(&entry, ret, sizeof(Skiplist_Entry));
        is_found = true;
    } else { // Read data from block addresses & search
        p_entry = pending_sl_get_entry(&entry);

        if(p_entry.nat_entry.block_addr == 0) {// if entry not found in pending list
            it = flushed_head;
#ifdef _SKIPLIST_API_DEBUG
            printk("Skiplist | flushed_head = %px\n", it);
#endif
            while(it != NULL && !is_found) {
#ifdef _SKIPLIST_API_DEBUG
                printk("Skiplist | Try to read block_addr %px\n", it->block_address);
#endif
#ifdef _SKIPLIST_API_F2FS
                page = alloc_pages(GFP_KERNEL, 0);
                f2fs_kv_read(page, sbi, it->block_address);
                blk_buf = page_address(page);
                e = blk_buf;
#else
                blk_buf = 0;

                if(blk_buf != 0)
#endif
                for(i=0; i<(it->size/sizeof(Skiplist_Entry)); i++) {
                    if(((Skiplist_Entry *)blk_buf)[i].nid == node_id) {
                        ret = (Skiplist_Entry *)blk_buf + i;
                        entry = ((Skiplist_Entry *)blk_buf)[i];
                        is_found = true;
                        break;
                    }
                }
                it = it->next;
            }
        } else { // if entry found in pending list
            printk("Found entry in the pending skiplist\n");
            is_found = true;
            entry = p_entry;
        }
    }

#ifdef _SKIPLIST_API_DEBUG
    if(is_found) {
        // printk("Skiplist | node found - ID: %d\n", ((NAT_Entry *)ret)->node_id);
        printk("Skiplist | node found - INODE: %d\n", ((Skiplist_Entry *)ret)->nid);
    } else {
        printk("Skiplist | node %d not found\n", node_id);
    }

#endif

    kfree(blk_buf);
    trace_printk("KV GET: key=0x%x, value.version=%d, value.ino=0x%x, value.block_addr=0x%x\n",
		    node_id, entry.nat_entry.version,
		    entry.nat_entry.ino, entry.nat_entry.block_addr);


    return entry.nat_entry;
}
EXPORT_SYMBOL(f2fs_kv_get);


int f2fs_kv_put(__u32 node_id, F2FS_NAT_Entry entry) {
    int result = 0;
    void *ret;

    // ThreadNode *new_tnode;
    // ThreadArgs *kth_args = (ThreadArgs *)kmalloc(sizeof(ThreadArgs), GFP_KERNEL);
    // NAT_Entry *entry = (NAT_Entry *)kmalloc(sizeof(NAT_Entry), GFP_KERNEL);
    // F2FS_NAT_Entry *entry = (F2FS_NAT_Entry *)kmalloc(sizeof(F2FS_NAT_Entry), GFP_KERNEL);
    Skiplist_Entry *s_entry = (Skiplist_Entry *)kmalloc(sizeof(Skiplist_Entry), GFP_KERNEL);
    s_entry->nid = node_id;
    s_entry->nat_entry = entry;
    
    ret = multi_skiplist_find(global_skiplist, (void *)(s_entry));
    if(ret != NULL) { // Update data
        ((Skiplist_Entry *)ret)->nat_entry = entry;
    } else {
        // Check the list is immutable
        mutex_lock(&check_lock);
        if(cur_entry_num == IMMUTABLE_ENTRY_NUM) {
            // new_tnode = (ThreadNode *)kmalloc(sizeof(ThreadNode), GFP_KERNEL);
            // printk("In mutex - net_tnode=%px\n", new_tnode);
            // new_tnode->prev = NULL;
            // if(kthread_head == NULL) {
            //     new_tnode->next = NULL;
            // } else {
            //     kthread_head->prev = new_tnode;
            //     new_tnode->next = kthread_head;
            // }
            // kthread_head = new_tnode;

            // kth_args->sl = global_skiplist;
            // kth_args->node = new_tnode;
            // new_tnode->task = kthread_run(f2fs_kv_flush_thread, kth_args, "flush-thread-%d", flush_count);
            kthread_run(f2fs_kv_flush_thread, (void *)global_skiplist, "flush-thread-%d", flush_count);
            flush_count++;
#ifdef _SKIPLIST_API_DEBUG
            // if(new_tnode->task == ERR_PTR(-ENOMEM) || new_tnode->task == ERR_PTR(-EINTR))
            //     printk(KERN_ERR "kthread_create() failed, flush-thread-%d\n", flush_count-1); 
#endif

            global_skiplist = (MultiSkiplist *)kmalloc(sizeof(MultiSkiplist), GFP_ATOMIC);
            result = multi_skiplist_init(global_skiplist, sl_max_level, 
                f2fs_kv_compare_func, f2fs_kv_free_func);
            if(result != 0) {
                printk(KERN_ERR "Global skiplist init. failed: %d\n", result);
            } else {
                printk("Global skiplist init. success, sl: %px, top: %px\n", global_skiplist, global_skiplist->top);
            }
            cur_entry_num = 0;
        }
        cur_entry_num++;
        mutex_unlock(&check_lock);

        // Insert new data
        result = multi_skiplist_insert(global_skiplist, (void *)s_entry);
    }

    trace_printk("KV PUT: key=0x%x, value.version=%d, value.ino=0x%x, value.block_addr=0x%x\n",
	    node_id, entry.version, entry.ino, entry.block_addr);
    
#ifdef _SKIPLIST_API_DEBUG
    if(result == 0) {
        if(ret != NULL)
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

void f2fs_kv_print(void) {
    multi_skiplist_print(global_skiplist, f2fs_kv_entry_to_string);
}
EXPORT_SYMBOL(f2fs_kv_print);


void f2fs_kv_destroy(void) {
    // ThreadNode *cur = kthread_head, *next;
    BlockAddressNode *blk_cur = flushed_head, *blk_next;
    // while(cur != NULL) {
    //     kthread_stop(cur->task);
    //     next = cur->next;
    //     kfree(cur);
    //     cur = next;
    // }
    // TODO: save block addresses for next mount
    while(blk_cur != NULL) {
        blk_next = blk_cur->next;
        kfree(blk_cur);
        blk_cur = blk_next;
    }

    multi_skiplist_destroy(global_skiplist);
    kfree(global_skiplist);
#ifdef _SKIPLIST_API_DEBUG
    printk("Skiplist | destroyed\n");
#endif
}
EXPORT_SYMBOL(f2fs_kv_destroy);
