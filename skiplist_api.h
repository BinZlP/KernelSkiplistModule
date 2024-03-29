#ifndef _SKIPLIST_API_H
#define _SKIPLIST_API_H

#define _SKIPLIST_API_DEBUG // Debug flag
//#define _SKIPLIST_API_F2FS

#include <linux/kernel.h>
#include <linux/slab.h>
#include <linux/kthread.h>
#include <linux/types.h>
#include <linux/mm.h>
#include <linux/workqueue.h>

#include "multi_skiplist.h"
#include "common_define.h"

#ifdef _SKIPLIST_API_F2FS
#include <linux/f2fs_fs.h>
#endif


typedef struct {
    int node_id;
    void *blk_addr;
}NAT_Entry;

#ifndef _SKIPLIST_API_F2FS
struct f2fs_nat_entry {
    __u8 version;
    __u32 ino;
    __u32 block_addr;
};
#endif
typedef struct f2fs_nat_entry F2FS_NAT_Entry;

typedef struct {
    int nid;
    F2FS_NAT_Entry nat_entry;
} Skiplist_Entry;

#define IMMUTABLE_ENTRY_NUM DATA_ARRAY_SIZE/sizeof(Skiplist_Entry)

typedef struct _BlockAddressNode{
    void *block_address;
    int size;
    struct _BlockAddressNode *prev;
    struct _BlockAddressNode *next;
} BlockAddressNode;

typedef struct _ThreadNode{
    struct task_struct *task;
    bool is_done;
    struct _ThreadNode *prev;
    struct _ThreadNode *next;
} ThreadNode;

/**
 * @brief Initialize a global skiplist.
 * 
 * @param level_count   Level of the skiplist. 
 * @return int, < 0 if failed.
 */
int f2fs_kv_init(const int level_count);
int f2fs_kv_init_sbi(const int level_count, void *_sbi);

/**
 * @brief Destroy global skiplist.
 * 
 */
void f2fs_kv_destroy(void);

/**
 * @brief Get node's data from skiplist.
 * 
 * @param node_id The id of target node.
 * @return struct f2fs_nat_entry filled with target node data. 
 * If not found, whole return data is filled with 0.
 */
F2FS_NAT_Entry f2fs_kv_get(__u32 node_id);


/**
 * @brief Insert or update the target node's data.
 * 
 * @param node_id The id of the node
 * @param entry struct f2fs_nat_entry which is filled with data
 * @return int, < 0 if failed.
 */
int f2fs_kv_put(__u32 node_id, F2FS_NAT_Entry entry);


/**
 * @brief print entries in skiplist
 * 
 */
void f2fs_kv_print(void);

#endif
