#ifndef _SKIPLIST_API_H
#define _SKIPLIST_API_H

#define _SKIPLIST_API_DEBUG // Debug flag

#include <linux/kernel.h>
#include <linux/slab.h>
#include "multi_skiplist.h"
#include "common_define.h"

typedef struct {
    int node_id;
    void *blk_addr;
}NAT_Entry;

/**
 * @brief Initialize a global skiplist.
 * 
 * @param level_count   Level of the skiplist. 
 * @return int, < 0 if failed.
 */
int f2fs_kv_init(const int level_count);

/**
 * @brief Destroy global skiplist.
 * 
 */
void f2fs_kv_destroy();

/**
 * @brief Get node's data from skiplist.
 * 
 * @param node_id The id of target node.
 * @return void* pointer of the found element. NULL if not found.
 */
void *f2fs_kv_get(int node_id);


/**
 * @brief Insert node into skiplist.
 * 
 * @param node_id The id of target node.
 * @param blk_addr The address of block.
 * @return int, < 0 if failed.
 */
int f2fs_kv_put(int node_id, void *blk_addr);

#endif