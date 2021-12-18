/*
 * Copyright (c) 2020 YuQing <384681@qq.com>
 *
 * This program is free software: you can use, redistribute, and/or modify
 * it under the terms of the Lesser GNU General Public License, version 3
 * or later ("LGPL"), as published by the Free Software Foundation.
 *
 * This program is distributed in the hope that it will be useful, but WITHOUT
 * ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
 * FITNESS FOR A PARTICULAR PURPOSE.
 *
 * You should have received a copy of the Lesser GNU General Public License
 * along with this program. If not, see <https://www.gnu.org/licenses/>.
 */

// This is modified version for linux kernel module use.
// The original source code is able to access at:
// https://github.com/happyfish100/libfastcommon
// Author: BinZlP (https://github.com/BinZlP)

//fast_mblock.c

#include <linux/kernel.h>
#include <linux/kthread.h>
#include <linux/errno.h>

#include "common_define.h"
#include "fast_mblock.h"

#define LOG_ERR 3

struct _fast_mblock_manager
{
    bool is_init;
    int count;
    struct fast_mblock_man head;
	struct mutex lock;
};

#define INIT_HEAD(head) (head)->next = (head)->prev = head
#define IS_EMPTY(head) ((head)->next == head)

static struct _fast_mblock_manager mblock_manager = {false, 0};


#define fast_mblock_get_trunk_size(mblock, block_size, element_count) \
    (sizeof(struct fast_mblock_malloc) + block_size * element_count)

int fast_mblock_manager_init(void)
{
    // int result;
	// if ((result=init_pthread_lock(&(mblock_manager.lock))) != 0)
	// {
	// 	printk(KERN_ERR " file: "__FILE__", line: %d, " 
	// 		"init_pthread_lock fail, errno: %d, error info: %s", 
	// 		__LINE__, result, STRERROR(result));
	// 	return result;
	// }
    mutex_init(&(mblock_manager.lock));

    INIT_HEAD(&mblock_manager.head);
    mblock_manager.is_init = true;

    return 0;
}

static int cmp_mblock_info(struct fast_mblock_man *mb1, struct fast_mblock_man *mb2)
{
    int result;
    result = strcmp(mb1->info.name, mb2->info.name);
    if (result != 0)
    {
        return result;
    }

    return mb1->info.element_size - mb2->info.element_size;
}

static void add_to_mblock_list(struct fast_mblock_man *mblock)
{
    struct fast_mblock_man *cursor;
    if (!mblock_manager.is_init)
    {
        return;
    }

    if (*mblock->info.name == '\0')
    {
        snprintf(mblock->info.name, sizeof(mblock->info.name),
                "size-%d", mblock->info.element_size);
    }
    mutex_lock(&(mblock_manager.lock));
    cursor = mblock_manager.head.next;
    while (cursor != &mblock_manager.head)
    {
        if (cmp_mblock_info(mblock, cursor) <= 0)
        {
            break;
        }
        cursor = cursor->next;
    }

    mblock->next = cursor;
    mblock->prev = cursor->prev;
    cursor->prev->next = mblock;
    cursor->prev = mblock;
    mblock_manager.count++;

    mutex_unlock(&(mblock_manager.lock));
}

static void delete_from_mblock_list(struct fast_mblock_man *mblock)
{
    if (!mblock_manager.is_init || IS_EMPTY(mblock))
    {
        return;
    }

    mutex_lock(&(mblock_manager.lock));
    mblock->prev->next = mblock->next;
    mblock->next->prev = mblock->prev;
    mblock_manager.count--;
    mutex_unlock(&(mblock_manager.lock));

    INIT_HEAD(mblock);
}

#define STAT_DUP(pStat, cursor, copy_name) \
    do { \
        if (copy_name) { \
            strcpy(pStat->name, cursor->info.name);          \
            pStat->trunk_size = cursor->info.trunk_size;     \
            pStat->element_size = cursor->info.element_size; \
        } \
        pStat->element_total_count += cursor->info.element_total_count;  \
        pStat->element_used_count += cursor->info.element_used_count;    \
        pStat->delay_free_elements += cursor->info.delay_free_elements;  \
        pStat->trunk_total_count += cursor->info.trunk_total_count;  \
        pStat->trunk_used_count += cursor->info.trunk_used_count;    \
        pStat->instance_count += cursor->info.instance_count;  \
        /* logInfo("name: %s, element_size: %d, total_count: %d, "  \
           "used_count: %d", pStat->name, pStat->element_size, \
           pStat->element_total_count, pStat->element_used_count); */ \
    } while (0)

int fast_mblock_manager_stat(struct fast_mblock_info *stats,
        const int size, int *count)
{
    int result;
    struct fast_mblock_man *cursor;
    struct fast_mblock_info *pStat;

    if (!mblock_manager.is_init)
    {
        *count = 0;
        return EFAULT;
    }

    if (size <= 0)
    {
        *count = 0;
        return EOVERFLOW;
    }

    result = 0;
    pStat = stats;
    memset(stats, 0, sizeof(struct fast_mblock_info) * size);
    mutex_lock(&(mblock_manager.lock));
    cursor = mblock_manager.head.next;
    while (cursor != &mblock_manager.head)
    {
        if (cursor->prev != &mblock_manager.head)
        {
            if (cmp_mblock_info(cursor, cursor->prev) != 0)
            {
                if (size <= (int)(pStat - stats))
                {
                    result = EOVERFLOW;
                    break;
                }
                STAT_DUP(pStat, cursor->prev, true);
                pStat++;
            }
            else
            {
                STAT_DUP(pStat, cursor->prev, false);
            }
        }
        cursor = cursor->next;
    }

    if (!IS_EMPTY(&mblock_manager.head))
    {
        if (size <= (int)(pStat - stats))
        {
            result = EOVERFLOW;
        }
        else
        {
            STAT_DUP(pStat, cursor->prev, true);
            pStat++;
        }
    }
    mutex_unlock(&(mblock_manager.lock));

    *count = (int)(pStat - stats);
    return result;
}

//desc order
static int fast_mblock_info_cmp_by_alloc_bytes(const void *p1, const void *p2)
{
	struct fast_mblock_info *pStat1;
	struct fast_mblock_info *pStat2;
    int64_t sub;

	pStat1 = (struct fast_mblock_info *)p1;
	pStat2 = (struct fast_mblock_info *)p2;
	sub = (int64_t)pStat2->trunk_size * pStat2->trunk_total_count -
		(int64_t)pStat1->trunk_size * pStat1->trunk_total_count;
    return (sub == 0) ? 0 : (sub < 0 ? -1 : 1);
}

//desc order
static int fast_mblock_info_cmp_by_element_size(const void *p1, const void *p2)
{
	struct fast_mblock_info *pStat1;
	struct fast_mblock_info *pStat2;

	pStat1 = (struct fast_mblock_info *)p1;
	pStat2 = (struct fast_mblock_info *)p2;
	return pStat2->element_size - pStat1->element_size;
}

//swap function for fast_mblock_info
static void fast_mblock_info_swap(void *p1, void *p2, int size) {
    struct fast_mblock_info *pStat1;
	struct fast_mblock_info *pStat2;
    struct fast_mblock_info pTemp;

	pStat1 = (struct fast_mblock_info *)p1;
	pStat2 = (struct fast_mblock_info *)p2;
	
    pTemp = *pStat1;
    *pStat1 = *pStat2;
    *pStat2 = pTemp;
}

int fast_mblock_manager_stat_print_ex(const bool hide_empty, const int order_by)
{
    int result;
    int count;
    int alloc_size;
    struct fast_mblock_info *stats;
    struct fast_mblock_info *pStat;
    struct fast_mblock_info *stat_end;

    stats = NULL;
    count = 0;
    alloc_size = 64;
    result = EOVERFLOW;
    while (result == EOVERFLOW)
    {
        alloc_size *= 2;
        stats = fc_realloc(stats, sizeof(struct fast_mblock_info) * alloc_size);
        if (stats == NULL)
        {
            return ENOMEM;
        }
        result = fast_mblock_manager_stat(stats,
                alloc_size, &count);
    }

    if (result == 0)
    {
        int64_t alloc_mem;
        int64_t used_mem;
        int64_t amem;
        int64_t delay_free_mem;
        char alloc_mem_str[32];
        char used_mem_str[32];
        char delay_free_mem_str[32];
        // double element_percentage;

        if (order_by == FAST_MBLOCK_ORDER_BY_ALLOC_BYTES)
        {
            sort(stats, count, sizeof(struct fast_mblock_info),
                    fast_mblock_info_cmp_by_alloc_bytes,
                    fast_mblock_info_swap);
        }
        else
        {
            sort(stats, count, sizeof(struct fast_mblock_info),
                    fast_mblock_info_cmp_by_element_size,
                    fast_mblock_info_swap);
        }

        alloc_mem = 0;
        used_mem = 0;
        delay_free_mem = 0;
        printk("%20s %8s %8s %12s %11s %10s %10s %10s %10s %12s",
                "name", "el_size", "instance", "alloc_bytes",
                "trunc_alloc", "trunk_used", "el_alloc",
                "el_used", "delay_free", "used_ratio");
        stat_end = stats + count;
        for (pStat=stats; pStat<stat_end; pStat++)
        {
            if (pStat->trunk_total_count > 0)
            {
                amem = (int64_t)pStat->trunk_size * pStat->trunk_total_count;
                alloc_mem += amem;
                used_mem += GET_BLOCK_SIZE(*pStat) *
                    pStat->element_used_count;
                delay_free_mem += GET_BLOCK_SIZE(*pStat) *
                    pStat->delay_free_elements;
            }
            else
            {
                amem = 0;
                if (hide_empty)
                {
                    continue;
                }
            }

            // element_percentage = pStat->element_total_count > 0 ? 100.00 * (double)(pStat->element_used_count) / (double)(pStat->element_total_count) : 0.00;
            // printk("%20s %8d %8d %12lld %11lld %10lld %10lld %10lld %10lld %11.2f%%\n",
            printk("%20s %8d %8d %12lld %11lld %10lld %10lld %10lld %10lld\n",
                    pStat->name, pStat->element_size, pStat->instance_count,
                    amem, pStat->trunk_total_count, pStat->trunk_used_count,
                    pStat->element_total_count, pStat->element_used_count,
                    pStat->delay_free_elements);
        }

        // if (alloc_mem < 1024)
        // {
            sprintf(alloc_mem_str, "%lld bytes", alloc_mem);
            sprintf(used_mem_str, "%lld bytes", used_mem);
            sprintf(delay_free_mem_str, "%lld bytes", delay_free_mem);
        // }
        // else if (alloc_mem < 1024 * 1024)
        // {
        //     sprintf(alloc_mem_str, "%.3f KB", (double)alloc_mem / 1024);
        //     sprintf(used_mem_str, "%.3f KB", (double)used_mem / 1024);
        //     sprintf(delay_free_mem_str, "%.3f KB",
        //             (double)delay_free_mem / 1024);
        // }
        // else if (alloc_mem < 1024 * 1024 * 1024)
        // {
        //     sprintf(alloc_mem_str, "%.3f MB",
        //             (double)alloc_mem / (1024 * 1024));
        //     sprintf(used_mem_str, "%.3f MB",
        //             (double)used_mem / (1024 * 1024));
        //     sprintf(delay_free_mem_str, "%.3f MB",
        //             (double)delay_free_mem / (1024 * 1024));
        // }
        // else
        // {
        //     sprintf(alloc_mem_str, "%.3f GB",
        //             (double)alloc_mem / (1024 * 1024 * 1024));
        //     sprintf(used_mem_str, "%.3f GB",
        //             (double)used_mem / (1024 * 1024 * 1024));
        //     sprintf(delay_free_mem_str, "%.3f GB",
        //             (double)delay_free_mem / (1024 * 1024 * 1024));
        // }

        // printk("mblock entry count: %d, memory stat => { alloc : %s, "
        //         "used: %s (%.2f%%), delay free: %s (%.2f%%) }",
        //         count, alloc_mem_str, used_mem_str, alloc_mem > 0 ?
        //         100.00 * (double)used_mem / alloc_mem : 0.00,
        //         delay_free_mem_str, alloc_mem > 0 ? 100.00 *
        //             (double)delay_free_mem / alloc_mem : 0.00);
        printk("mblock entry count: %d, memory stat => { alloc : %s, "
                "used: %s , delay free: %s }\n",
                count, alloc_mem_str, used_mem_str,
                delay_free_mem_str);
    }

    if (stats != NULL) kfree(stats);
    return 0;
}

int fast_mblock_init_ex(struct fast_mblock_man *mblock,
        const int element_size, const int alloc_elements_once,
        const int64_t alloc_elements_limit,
        fast_mblock_alloc_init_func init_func, void *init_args,
        const bool need_lock)
{
    return fast_mblock_init_ex2(mblock, NULL, element_size,
            alloc_elements_once, alloc_elements_limit, init_func,
            init_args, need_lock, NULL, NULL, NULL);
}

int fast_mblock_init_ex2(struct fast_mblock_man *mblock, const char *name,
        const int element_size, const int alloc_elements_once,
        const int64_t alloc_elements_limit,
        fast_mblock_alloc_init_func init_func,
        void *init_args, const bool need_lock,
        fast_mblock_malloc_trunk_check_func malloc_trunk_check,
        fast_mblock_malloc_trunk_notify_func malloc_trunk_notify,
        void *malloc_trunk_args)
{
	// int result;

	if (element_size <= 0)
	{
		printk(KERN_ERR "file: "__FILE__", line: %d, " \
			"invalid block size: %d", \
			__LINE__, element_size);
		return EINVAL;
	}

	mblock->info.element_size = MEM_ALIGN(element_size);
    mblock->alloc_elements.limit = alloc_elements_limit;
	mblock->info.block_size = fast_mblock_get_block_size(mblock);
	if (alloc_elements_once > 0)
	{
		mblock->alloc_elements.once = alloc_elements_once;
	}
	else
	{
		mblock->alloc_elements.once = (1024 * 1024) / mblock->info.block_size;
	}
    if (mblock->alloc_elements.limit > 0 && mblock->alloc_elements.once >
            mblock->alloc_elements.limit)
    {
        mblock->alloc_elements.once = mblock->alloc_elements.limit;
    }

	// if (need_lock && (result=init_pthread_lock_cond_pair(&(mblock->lcp))) != 0)
	// {
	// 	printk(KERN_ERR "file: "__FILE__", line: %d, " 
	// 		"init_pthread_lock fail, errno: %d, error info: %s", 
	// 		__LINE__, result, STRERROR(result));
	// 	return result;
	// }
    if(need_lock) {
        mutex_init(&(mblock->lcp.lock));
        init_waitqueue_head(&(mblock->lcp.q));
        mblock->lcp.cond = 0;
    }

    mblock->alloc_init_func = init_func;
    mblock->init_args = init_args;
    INIT_HEAD(&mblock->trunks.head);
    mblock->info.trunk_total_count = 0;
    mblock->info.trunk_used_count = 0;
    mblock->info.delay_free_elements = 0;
    mblock->free_chain_head = NULL;
    mblock->delay_free_chain.head = NULL;
    mblock->delay_free_chain.tail = NULL;
    mblock->info.element_total_count = 0;
    mblock->info.element_used_count = 0;
    mblock->info.instance_count = 1;
    mblock->info.trunk_size = fast_mblock_get_trunk_size(mblock,
            mblock->info.block_size, mblock->alloc_elements.once);
    mblock->need_lock = need_lock;
    mblock->alloc_elements.need_wait = false;
    mblock->alloc_elements.pcontinue_flag = NULL;
    mblock->alloc_elements.exceed_log_level = LOG_ERR;
    mblock->malloc_trunk_callback.check_func = malloc_trunk_check;
    mblock->malloc_trunk_callback.notify_func = malloc_trunk_notify;
    mblock->malloc_trunk_callback.args = malloc_trunk_args;

    if (name != NULL)
    {
        snprintf(mblock->info.name, sizeof(mblock->info.name), "%s", name);
    }
    else
    {
        *mblock->info.name = '\0';
    }
    add_to_mblock_list(mblock);

    return 0;
}

static int fast_mblock_prealloc(struct fast_mblock_man *mblock)
{
	struct fast_mblock_node *pNode;
	struct fast_mblock_malloc *pMallocNode;
	char *pNew;
	char *pTrunkStart;
	char *p;
	char *pLast;
	int result;
    int trunk_size;
    int alloc_count;

    if (mblock->alloc_elements.limit > 0)
    {
        int64_t avail_count;
        avail_count = mblock->alloc_elements.limit -
            mblock->info.element_total_count;
        if (avail_count <= 0)
        {
            printk("file: "__FILE__", line: %d, "
                    "allocated elements exceed limit: %lld",
                    __LINE__, mblock->alloc_elements.limit);
            return EOVERFLOW;
        }

        alloc_count = avail_count > mblock->alloc_elements.once ?
            mblock->alloc_elements.once : avail_count;
        trunk_size = fast_mblock_get_trunk_size(mblock,
                mblock->info.block_size, alloc_count);
    }
    else
    {
        alloc_count = mblock->alloc_elements.once;
        trunk_size = mblock->info.trunk_size;
    }

	if (mblock->malloc_trunk_callback.check_func != NULL &&
		mblock->malloc_trunk_callback.check_func(trunk_size,
            mblock->malloc_trunk_callback.args) != 0)
	{
		return ENOMEM;
	}

	pNew = (char *)fc_malloc(trunk_size);
	if (pNew == NULL)
	{
		return ENOMEM;
	}
	memset(pNew, 0, trunk_size);

	pMallocNode = (struct fast_mblock_malloc *)pNew;
	pTrunkStart = pNew + sizeof(struct fast_mblock_malloc);
	pLast = pNew + (trunk_size - mblock->info.block_size);
	for (p=pTrunkStart; p<=pLast; p += mblock->info.block_size)
	{
		pNode = (struct fast_mblock_node *)p;
        if (mblock->alloc_init_func != NULL)
        {
            if ((result=mblock->alloc_init_func(pNode->data,
                            mblock->init_args)) != 0)
            {
                kfree(pNew);
                return result;
            }
        }

        pNode->offset = (int)(p - pNew);
        pNode->next = (struct fast_mblock_node *)(p + mblock->info.block_size);

#ifdef FAST_MBLOCK_MAGIC_CHECK
        pNode->index = (p - pTrunkStart) / mblock->info.block_size;
        pNode->magic = FAST_MBLOCK_MAGIC_NUMBER;
#endif
	}

    ((struct fast_mblock_node *)pLast)->next = NULL;
	mblock->free_chain_head = (struct fast_mblock_node *)pTrunkStart;

    pMallocNode->ref_count = 0;
    pMallocNode->alloc_count = alloc_count;
    pMallocNode->trunk_size = trunk_size;
    pMallocNode->prev = mblock->trunks.head.prev;
	pMallocNode->next = &mblock->trunks.head;
    mblock->trunks.head.prev->next = pMallocNode;
    mblock->trunks.head.prev = pMallocNode;

    mblock->info.trunk_total_count++;
    mblock->info.element_total_count += alloc_count;
    mblock->lcp.cond += alloc_count;

    if (mblock->malloc_trunk_callback.notify_func != NULL)
    {
        mblock->malloc_trunk_callback.notify_func(trunk_size,
                mblock->malloc_trunk_callback.args);
    }

    return 0;
}

static inline void fast_mblock_remove_trunk(struct fast_mblock_man *mblock,
        struct fast_mblock_malloc *pMallocNode)
{
    pMallocNode->prev->next = pMallocNode->next;
	pMallocNode->next->prev = pMallocNode->prev;
    mblock->info.trunk_total_count--;
    mblock->info.element_total_count -= pMallocNode->alloc_count;
    mblock->lcp.cond -= pMallocNode->alloc_count;

    if (mblock->malloc_trunk_callback.notify_func != NULL)
    {
	   mblock->malloc_trunk_callback.notify_func(-1 * pMallocNode->trunk_size,
	   mblock->malloc_trunk_callback.args);
    }
}

#define FAST_MBLOCK_GET_TRUNK(pNode) \
    (struct fast_mblock_malloc *)((char *)pNode - pNode->offset)

static inline void fast_mblock_ref_counter_op(struct fast_mblock_man *mblock,
        struct fast_mblock_node *pNode, const bool is_inc)
{
	struct fast_mblock_malloc *pMallocNode;

#ifdef FAST_MBLOCK_MAGIC_CHECK
    int calc_offset;

    calc_offset = sizeof(struct fast_mblock_malloc) +
        pNode->index * mblock->info.block_size;
    if (pNode->magic != FAST_MBLOCK_MAGIC_NUMBER ||
            pNode->offset != calc_offset)
    {
        logCrit("file: "__FILE__", line: %d, "
                "magic check for %s %s fail, node: %p, index: %d, offset: %d, "
                "offset by index: %d, magic number: %d, expect magic: %d",
                __LINE__, (is_inc ? "alloc" : "free"), mblock->info.name,
                pNode, pNode->index, pNode->offset, calc_offset,
                pNode->magic, FAST_MBLOCK_MAGIC_NUMBER);
        return;
    }
#endif

    pMallocNode = FAST_MBLOCK_GET_TRUNK(pNode);
    if (is_inc)
    {
        if (pMallocNode->ref_count == 0)
        {
            mblock->info.trunk_used_count++;
        }
        pMallocNode->ref_count++;
    }
    else
    {
        pMallocNode->ref_count--;
        if (pMallocNode->ref_count == 0)
        {
            mblock->info.trunk_used_count--;
        }
    }
}

#define fast_mblock_ref_counter_inc(mblock, pNode) \
    fast_mblock_ref_counter_op(mblock, pNode, true)

#define fast_mblock_ref_counter_dec(mblock, pNode) \
    fast_mblock_ref_counter_op(mblock, pNode, false)

void fast_mblock_destroy(struct fast_mblock_man *mblock)
{
	struct fast_mblock_malloc *pMallocNode;
	struct fast_mblock_malloc *pMallocTmp;

	if (IS_EMPTY(&mblock->trunks.head))
	{
        delete_from_mblock_list(mblock);
		return;
	}

	pMallocNode = mblock->trunks.head.next;
	while (pMallocNode != &mblock->trunks.head)
	{
		pMallocTmp = pMallocNode;
		pMallocNode = pMallocNode->next;

		kfree(pMallocTmp);
	}

    INIT_HEAD(&mblock->trunks.head);
    mblock->info.trunk_total_count = 0;
    mblock->info.trunk_used_count = 0;
    mblock->free_chain_head = NULL;
    mblock->info.element_used_count = 0;
    mblock->info.delay_free_elements = 0;
    mblock->info.element_total_count = 0;

    if (mblock->need_lock) {
        // destroy_pthread_lock_cond_pair(&(mblock->lcp));
        mutex_destroy(&(mblock->lcp.lock));
    }
    delete_from_mblock_list(mblock);
}

static inline struct fast_mblock_node *alloc_node(
        struct fast_mblock_man *mblock)
{
    int result;
	struct fast_mblock_node *pNode;

    while (1)
    {
        if (mblock->free_chain_head != NULL)
        {
            pNode = mblock->free_chain_head;
            mblock->free_chain_head = pNode->next;
            break;
        }

        if (mblock->delay_free_chain.head != NULL &&
                mblock->delay_free_chain.head->
                recycle_timestamp <= get_current_time())
        {
            pNode = mblock->delay_free_chain.head;
            mblock->delay_free_chain.head = pNode->next;
            if (mblock->delay_free_chain.tail == pNode)
            {
                mblock->delay_free_chain.tail = NULL;
            }

            mblock->info.delay_free_elements--;
            break;
        }

        if ((result=fast_mblock_prealloc(mblock)) == 0)
        {
            pNode = mblock->free_chain_head;
            mblock->free_chain_head = pNode->next;
            break;
        }

        if (!mblock->alloc_elements.need_wait)
        {
            pNode = NULL;
            break;
        }

        // pthread_cond_wait(&mblock->lcp.cond, &mblock->lcp.lock);
        wait_event_interruptible(mblock->lcp.q, condition_check(&(mblock->lcp)));
        if (!*(mblock->alloc_elements.pcontinue_flag))
        {
            pNode = NULL;
            break;
        }
    }

    if (pNode != NULL)
    {
        mblock->info.element_used_count++;
        mblock->lcp.cond--;
        fast_mblock_ref_counter_inc(mblock, pNode);
    }

	return pNode;
}

struct fast_mblock_node *fast_mblock_alloc(struct fast_mblock_man *mblock)
{
	struct fast_mblock_node *pNode;
	// int result;

	// if (mblock->need_lock && (result=pthread_mutex_lock(
    //                 &mblock->lcp.lock)) != 0)
	// {
	// 	printk("file: "__FILE__", line: %d, "
	// 		"call pthread_mutex_lock fail, "
	// 		"errno: %d, error info: %s",
	// 		__LINE__, result, STRERROR(result));
	// 	return NULL;
	// }
    if(mblock->need_lock) {
        mutex_lock(&(mblock->lcp.lock));
    }

    pNode = alloc_node(mblock);

	// if (mblock->need_lock && (result=pthread_mutex_unlock(
    //                 &mblock->lcp.lock)) != 0)
	// {
	// 	logError("file: "__FILE__", line: %d, " 
	// 		"call pthread_mutex_unlock fail, " 
	// 		"errno: %d, error info: %s", 
	// 		__LINE__, result, STRERROR(result));
	// }
    if(mblock->need_lock) {
        mutex_unlock(&(mblock->lcp.lock));
    }

	return pNode;
}

int fast_mblock_free(struct fast_mblock_man *mblock,
		     struct fast_mblock_node *pNode)
{
	// int result;
    bool notify;

	// if (mblock->need_lock && (result=pthread_mutex_lock(
    //                 &mblock->lcp.lock)) != 0)
	// {
	// 	logError("file: "__FILE__", line: %d, " 
	// 		"call pthread_mutex_lock fail, " 
	// 		"errno: %d, error info: %s", 
	// 		__LINE__, result, STRERROR(result));
	// 	return result;
	// }
    if(mblock->need_lock) {
        mutex_lock(&(mblock->lcp.lock));
    }

    notify = (mblock->free_chain_head == NULL);
	pNode->next = mblock->free_chain_head;
	mblock->free_chain_head = pNode;
    mblock->info.element_used_count--;
    mblock->lcp.cond++;
    fast_mblock_ref_counter_dec(mblock, pNode);

    if (mblock->alloc_elements.need_wait && notify)
    {
        // pthread_cond_signal(&mblock->lcp.cond);
        wake_up_interruptible(&(mblock->lcp.q));
    }

	// if (mblock->need_lock && (result=pthread_mutex_unlock(
    //                 &mblock->lcp.lock)) != 0)
    // {
    //     logError("file: "__FILE__", line: %d, "
    //             "call pthread_mutex_unlock fail, "
    //             "errno: %d, error info: %s",
    //             __LINE__, result, STRERROR(result));
    // }
    if (mblock->need_lock) {
        mutex_unlock(&(mblock->lcp.lock));
    }

	return 0;
}

static inline void batch_free(struct fast_mblock_man *mblock,
        struct fast_mblock_chain *chain)
{
    bool notify;
    struct fast_mblock_node *pNode;

    pNode = chain->head;
    while (pNode != NULL)
    {
        mblock->info.element_used_count--;
        mblock->lcp.cond++;
        fast_mblock_ref_counter_dec(mblock, pNode);
        pNode = pNode->next;
    }

    notify = (mblock->free_chain_head == NULL);
    chain->tail->next = mblock->free_chain_head;
    mblock->free_chain_head = chain->head;
    if (mblock->alloc_elements.need_wait && notify)
    {
        // pthread_cond_broadcast(&mblock->lcp.cond);
        wake_up_interruptible_all(&(mblock->lcp.q));
    }
}

struct fast_mblock_node *fast_mblock_batch_alloc(
        struct fast_mblock_man *mblock, const int count)
{
    struct fast_mblock_chain chain;
	struct fast_mblock_node *pNode;
    int i;
	// int result;

	// if (mblock->need_lock && (result=pthread_mutex_lock(
    //                 &mblock->lcp.lock)) != 0)
	// {
	// 	logError("file: "__FILE__", line: %d, "
	// 		"call pthread_mutex_lock fail, "
	// 		"errno: %d, error info: %s",
	// 		__LINE__, result, STRERROR(result));
	// 	return NULL;
	// }
    if(mblock->need_lock) {
        mutex_lock(&(mblock->lcp.lock));
    }

    if ((chain.head=alloc_node(mblock)) != NULL)
    {
        chain.tail = chain.head;
        for (i=1; i<count; i++)
        {
            if ((pNode=alloc_node(mblock)) == NULL)
            {
                break;
            }
            chain.tail->next = pNode;
            chain.tail = pNode;
        }
        chain.tail->next = NULL;

        if (i != count) {  //fail
            batch_free(mblock, &chain);
            chain.head = NULL;
        }
    }

	// if (mblock->need_lock && (result=pthread_mutex_unlock(
    //                 &mblock->lcp.lock)) != 0)
    // {
    //     logError("file: "__FILE__", line: %d, " 
    //             "call pthread_mutex_unlock fail, " 
    //             "errno: %d, error info: %s", 
    //             __LINE__, result, STRERROR(result));
    // }
    if(mblock->need_lock) {
        mutex_unlock(&(mblock->lcp.lock));
    }

	return chain.head;
}

int fast_mblock_batch_free(struct fast_mblock_man *mblock,
        struct fast_mblock_chain *chain)
{
	// int result;

    if (chain->head == NULL) {
        return ENOENT;
    }

	// if (mblock->need_lock && (result=pthread_mutex_lock(
    //                 &mblock->lcp.lock)) != 0)
	// {
	// 	logError("file: "__FILE__", line: %d, " 
	// 		"call pthread_mutex_lock fail, " 
	// 		"errno: %d, error info: %s", 
	// 		__LINE__, result, STRERROR(result));
	// 	return result;
	// }
    if(mblock->need_lock) {
        mutex_lock(&(mblock->lcp.lock));
    }

    batch_free(mblock, chain);

	// if (mblock->need_lock && (result=pthread_mutex_unlock(
    //                 &mblock->lcp.lock)) != 0)
    // {
    //     logError("file: "__FILE__", line: %d, "
    //             "call pthread_mutex_unlock fail, "
    //             "errno: %d, error info: %s",
    //             __LINE__, result, STRERROR(result));
    // }
    if(mblock->need_lock) {
        mutex_unlock(&(mblock->lcp.lock));
    }

	return 0;
}

void fast_mblock_free_objects(struct fast_mblock_man *mblock,
        void **objs, const int count)
{
    void **obj;
    void **end;
    struct fast_mblock_node *previous;
    struct fast_mblock_node *cursor;
    struct fast_mblock_chain chain;

    if (count == 0) {
        return;
    }

    chain.head = previous = fast_mblock_to_node_ptr(objs[0]);
    end = objs + count;
    for (obj=objs+1; obj<end; obj++) {
        cursor = fast_mblock_to_node_ptr(*obj);
        previous->next = cursor;
        previous = cursor;
    }

    previous->next = NULL;
    chain.tail = previous;
    fast_mblock_batch_free(mblock, &chain);
}

int fast_mblock_delay_free(struct fast_mblock_man *mblock,
		     struct fast_mblock_node *pNode, const int deley)
{
	// int result;

	// if (mblock->need_lock && (result=pthread_mutex_lock(
    //                 &mblock->lcp.lock)) != 0)
	// {
	// 	logError("file: "__FILE__", line: %d, " 
	// 		"call pthread_mutex_lock fail, " 
	// 		"errno: %d, error info: %s", 
	// 		__LINE__, result, STRERROR(result));
	// 	return result;
	// }
    if(mblock->need_lock) {
        mutex_lock(&(mblock->lcp.lock));
    }

    pNode->recycle_timestamp = get_current_time() + deley;
	if (mblock->delay_free_chain.head == NULL)
    {
        mblock->delay_free_chain.head = pNode;
    }
    else
    {
        mblock->delay_free_chain.tail->next = pNode;
    }
    mblock->delay_free_chain.tail = pNode;
    pNode->next = NULL;

    mblock->info.element_used_count--;
    mblock->info.delay_free_elements++;
    mblock->lcp.cond++;
    fast_mblock_ref_counter_dec(mblock, pNode);

	// if (mblock->need_lock && (result=pthread_mutex_unlock(
    //                 &mblock->lcp.lock)) != 0)
	// {
	// 	logError("file: "__FILE__", line: %d, " 
	// 		"call pthread_mutex_unlock fail, " 
	// 		"errno: %d, error info: %s", 
	// 		__LINE__, result, STRERROR(result));
	// }
    if(mblock->need_lock) {
        mutex_unlock(&(mblock->lcp.lock));
    }

	return 0;
}

static int fast_mblock_chain_count(struct fast_mblock_man *mblock,
        struct fast_mblock_node *head)
{
	struct fast_mblock_node *pNode;
	int count;
	// int result;

	// if (mblock->need_lock && (result=pthread_mutex_lock(
    //                 &mblock->lcp.lock)) != 0)
	// {
	// 	logError("file: "__FILE__", line: %d, " 
	// 		"call pthread_mutex_lock fail, " 
	// 		"errno: %d, error info: %s", 
	// 		__LINE__, result, STRERROR(result));
	// 	return -1;
	// }
    if (mblock->need_lock) {
        mutex_lock(&(mblock->lcp.lock));
    }

	count = 0;
	pNode = head;
	while (pNode != NULL)
	{
		pNode = pNode->next;
		count++;
	}

	// if (mblock->need_lock && (result=pthread_mutex_unlock(
    //                 &mblock->lcp.lock)) != 0)
	// {
	// 	logError("file: "__FILE__", line: %d, " 
	// 		"call pthread_mutex_unlock fail, " 
	// 		"errno: %d, error info: %s", 
	// 		__LINE__, result, STRERROR(result));
	// }
    if (mblock->need_lock) {
        mutex_unlock(&(mblock->lcp.lock));
    }

	return count;
}

int fast_mblock_free_count(struct fast_mblock_man *mblock)
{
    return fast_mblock_chain_count(mblock, mblock->free_chain_head);
}

int fast_mblock_delay_free_count(struct fast_mblock_man *mblock)
{
    return fast_mblock_chain_count(mblock, mblock->delay_free_chain.head);
}

static int fast_mblock_do_reclaim(struct fast_mblock_man *mblock,
        const int reclaim_target, int *reclaim_count,
        struct fast_mblock_malloc **ppFreelist)
{
    struct fast_mblock_node *pPrevious;
    struct fast_mblock_node *pCurrent;
    struct fast_mblock_malloc *pMallocNode;
    struct fast_mblock_malloc *freelist;
    bool lookup_done;

    lookup_done = false;
    *reclaim_count = 0;
    freelist = NULL;
    pPrevious = NULL;
	pCurrent = mblock->free_chain_head;
    mblock->free_chain_head = NULL;
	while (pCurrent != NULL)
	{
        pMallocNode = FAST_MBLOCK_GET_TRUNK(pCurrent);
        if (pMallocNode->ref_count > 0 ||
                (pMallocNode->ref_count == 0 && lookup_done))
        {    //keep in free chain

            if (pPrevious != NULL)
            {
                pPrevious->next = pCurrent;
            }
            else
            {
                mblock->free_chain_head = pCurrent;
            }

            pPrevious = pCurrent;
            pCurrent = pCurrent->next;
            if (pCurrent == NULL)
            {
                goto OUTER;
            }
            pMallocNode = FAST_MBLOCK_GET_TRUNK(pCurrent);

            while (pMallocNode->ref_count > 0 ||
                    (pMallocNode->ref_count == 0 && lookup_done))
            {
                pPrevious = pCurrent;
                pCurrent = pCurrent->next;
                if (pCurrent == NULL)
                {
                    goto OUTER;
                }
                pMallocNode = FAST_MBLOCK_GET_TRUNK(pCurrent);
            }
        }

        while (pMallocNode->ref_count < 0 ||
                (pMallocNode->ref_count == 0 && !lookup_done))
        {
            if (pMallocNode->ref_count == 0) //trigger by the first node
            {
                fast_mblock_remove_trunk(mblock, pMallocNode);
                pMallocNode->ref_count = -1;

                pMallocNode->next = freelist;
                freelist = pMallocNode;
                (*reclaim_count)++;
                if (reclaim_target > 0 && *reclaim_count == reclaim_target)
                {
                    lookup_done = true;
                }
            }

            pCurrent = pCurrent->next;
            if (pCurrent == NULL)
            {
                goto OUTER;
            }
            pMallocNode = FAST_MBLOCK_GET_TRUNK(pCurrent);
        }
	}


OUTER:
    if (pPrevious != NULL)
    {
        pPrevious->next = NULL;
    }


    {
        bool old_need_lock;
        old_need_lock = mblock->need_lock;
        mblock->need_lock = false;
        printk("file: "__FILE__", line: %d, "
                "reclaim trunks for %px, reclaimed trunks: %d, "
                "free node count: %d", __LINE__,
                mblock, *reclaim_count, fast_mblock_free_count(mblock));
        mblock->need_lock = old_need_lock;
    }

    *ppFreelist = freelist;
    return (freelist != NULL ? 0 : ENOENT);
}

void fast_mblock_free_trunks(struct fast_mblock_man *mblock,
        struct fast_mblock_malloc *freelist)
{
    struct fast_mblock_malloc *pDeleted;
    int count;
    count = 0;
    while (freelist != NULL)
    {
        pDeleted = freelist;
        freelist = freelist->next;
        kfree(pDeleted);
        count++;
    }
    printk("file: "__FILE__", line: %d, "
            "free_trunks for %px, free trunks: %d", __LINE__,
            mblock, count);
}

int fast_mblock_reclaim(struct fast_mblock_man *mblock,
        const int reclaim_target, int *reclaim_count,
        fast_mblock_free_trunks_func free_trunks_func)
{
    int result;
    struct fast_mblock_malloc *freelist;

    if (reclaim_target < 0 || mblock->info.trunk_total_count -
		mblock->info.trunk_used_count <= 0)
    {
        *reclaim_count = 0;
        return EINVAL;
    }

	// if (mblock->need_lock && (result=pthread_mutex_lock(
    //                 &mblock->lcp.lock)) != 0)
    // {
    //     logError("file: "__FILE__", line: %d, " 
    //             "call pthread_mutex_lock fail, " 
    //             "errno: %d, error info: %s", 
    //             __LINE__, result, STRERROR(result));
    //     *reclaim_count = 0;
    //     return result;
    // }
    if(mblock->need_lock) {
        mutex_lock(&(mblock->lcp.lock));
    }

    if (reclaim_target > 0 && mblock->info.trunk_total_count -
		mblock->info.trunk_used_count < reclaim_target)
    {
        *reclaim_count = 0;
        result = E2BIG;
        freelist = NULL;
    }
    else
    {
        result = fast_mblock_do_reclaim(mblock, reclaim_target,
                reclaim_count, &freelist);
    }

	// if (mblock->need_lock && (result=pthread_mutex_unlock(
    //                 &mblock->lcp.lock)) != 0)
	// {
	// 	logError("file: "__FILE__", line: %d, " 
	// 		"call pthread_mutex_unlock fail, " 
	// 		"errno: %d, error info: %s", 
	// 		__LINE__, result, STRERROR(result));
	// }
    if (mblock->need_lock) {
        mutex_unlock(&(mblock->lcp.lock));
    }

    if (result == 0)
    {
        if (free_trunks_func != NULL)
        {
            free_trunks_func(mblock, freelist);
        }
        else
        {
            fast_mblock_free_trunks(mblock, freelist);
        }
    }

    return result;
}

int get_current_time(void) {
    struct timespec64 ts;
    ktime_get_ts64(&ts);
    return ts.tv_sec;
}

bool condition_check(thread_lock_cond_pair_t *lcp) {
    bool ret;
    // mutex_lock(&(lcp->lock));
    ret = lcp->cond > 0;
    //if(ret) lcp->cond--;
    // mutex_unlock(&(lcp->lock));
    return ret;
}