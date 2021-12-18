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

//multi_skiplist.c

#include <linux/kernel.h>
#include <linux/string.h>
#include <linux/random.h>

#include "multi_skiplist.h"
#include "skiplist_api.h"

int multi_skiplist_init_ex(MultiSkiplist *sl, const int level_count,
        skiplist_compare_func compare_func,
        skiplist_free_func free_func,
        const int min_alloc_elements_once)
{
    const int64_t alloc_elements_limit = 0;
    char name[64];
    int bytes;
    int element_size;
    int i;
    int alloc_elements_once;
    int result;
    struct fast_mblock_man *top_mblock;

    if (level_count <= 0) {
        printk(KERN_ERR "file: "__FILE__", line: %d, "
                "invalid level count: %d",
                __LINE__, level_count);
        return EINVAL;
    }

    if (level_count > 30) {
        printk(KERN_ERR "file: "__FILE__", line: %d, "
                "level count: %d is too large",
                __LINE__, level_count);
        return E2BIG;
    }

    bytes = sizeof(MultiSkiplistNode *) * level_count;
    sl->tmp_previous = (MultiSkiplistNode **)fc_malloc(bytes);
    if (sl->tmp_previous == NULL) {
        return ENOMEM;
    }

    bytes = sizeof(struct fast_mblock_man) * level_count;
    sl->mblocks = (struct fast_mblock_man *)fc_malloc(bytes);
    if (sl->mblocks == NULL) {
        return ENOMEM;
    }
    memset(sl->mblocks, 0, bytes);

    alloc_elements_once = min_alloc_elements_once;
    if (alloc_elements_once <= 0) {
        alloc_elements_once = SKIPLIST_DEFAULT_MIN_ALLOC_ELEMENTS_ONCE;
    }
    else if (alloc_elements_once > 1024) {
        alloc_elements_once = 1024;
    }

    for (i=level_count-1; i>=0; i--) {
        sprintf(name, "multi-sl-level%02d", i);
        element_size = sizeof(MultiSkiplistNode) +
            sizeof(MultiSkiplistNode *) * (i + 1);
        if ((result=fast_mblock_init_ex1(sl->mblocks + i, name,
            element_size, alloc_elements_once, alloc_elements_limit,
            NULL, NULL, false)) != 0)
        {
            return result;
        }
        if (i % 2 == 0 && alloc_elements_once < 64 * 1024) {
            alloc_elements_once *= 2;
        }
    }

    sl->top_level_index = level_count - 1;
    top_mblock = sl->mblocks + sl->top_level_index;
    sl->top = (MultiSkiplistNode *)fast_mblock_alloc_object(top_mblock);
    if (sl->top == NULL) {
        return ENOMEM;
    }
    memset(sl->top, 0, top_mblock->info.element_size);

    sl->tail = (MultiSkiplistNode *)fast_mblock_alloc_object(sl->mblocks + 0);
    if (sl->tail == NULL) {
        return ENOMEM;
    }
    memset(sl->tail, 0, sl->mblocks[0].info.element_size);

    if ((result=fast_mblock_init_ex1(&sl->data_mblock, "multi-sl-data",
                    sizeof(MultiSkiplistData), alloc_elements_once,
                    alloc_elements_limit, NULL, NULL, false)) != 0)
    {
        return result;
    }

    for (i=0; i<level_count; i++) {
        sl->top->links[i] = sl->tail;
    }

    sl->level_count = level_count;
    sl->compare_func = compare_func;
    sl->free_func = free_func;

    sl->is_immutable = false;

    // srand(time(NULL));
    return 0;
}

void multi_skiplist_destroy(MultiSkiplist *sl)
{
    int i;
    MultiSkiplistNode *node;
    MultiSkiplistNode *deleted;
    MultiSkiplistData *dataCurrent;
    MultiSkiplistData *dataNode;

    if (sl->mblocks == NULL) {
        return;
    }

    if (sl->free_func != NULL) {
        node = sl->top->links[0];
        while (node != sl->tail) {
            deleted = node;
            node = node->links[0];

            dataCurrent = deleted->head;
            while (dataCurrent != NULL) {
                dataNode = dataCurrent;
                dataCurrent = dataCurrent->next;

                sl->free_func(dataNode->data);
            }
        }
    }

    for (i=0; i<sl->level_count; i++) {
        fast_mblock_destroy(sl->mblocks + i);
    }
    fast_mblock_destroy(&sl->data_mblock);

    kfree(sl->mblocks);
    sl->mblocks = NULL;
}

static MultiSkiplistNode *multi_skiplist_get_previous(MultiSkiplist *sl, void *data,
        int *level_index)
{
    int i;
    int cmp;
    MultiSkiplistNode *previous;

    previous = sl->top;
    for (i=sl->top_level_index; i>=0; i--) {
        while (previous->links[i] != sl->tail) {
            cmp = sl->compare_func(data, previous->links[i]->head->data);
            if (cmp < 0) {
                break;
            }
            else if (cmp == 0) {
                *level_index = i;
                return previous;
            }

            previous = previous->links[i];
        }
    }

    return NULL;
}

static MultiSkiplistNode *multi_skiplist_get_first_larger_or_equal(
        MultiSkiplist *sl, void *data)
{
    int i;
    int cmp;
    MultiSkiplistNode *previous;

    previous = sl->top;
    for (i=sl->top_level_index; i>=0; i--) {
        while (previous->links[i] != sl->tail) {
            cmp = sl->compare_func(data, previous->links[i]->head->data);
            if (cmp < 0) {
                break;
            }
            else if (cmp == 0) {
                return previous->links[i];
            }

            previous = previous->links[i];
        }
    }

    return previous->links[0];
}

static MultiSkiplistNode *multi_skiplist_get_first_larger(
        MultiSkiplist *sl, void *data)
{
    int i;
    int cmp;
    MultiSkiplistNode *previous;

    previous = sl->top;
    for (i=sl->top_level_index; i>=0; i--) {
        while (previous->links[i] != sl->tail) {
            cmp = sl->compare_func(data, previous->links[i]->head->data);
            if (cmp < 0) {
                break;
            }
            else if (cmp == 0) {
                return previous->links[i]->links[0];
            }

            previous = previous->links[i];
        }
    }

    return previous->links[0];
}

static inline void multi_skiplist_free_data_node(MultiSkiplist *sl,
        MultiSkiplistData *dataNode)
{
    if (sl->free_func != NULL) {
        sl->free_func(dataNode->data);
    }
    fast_mblock_free_object(&sl->data_mblock, dataNode);
}

static inline int multi_skiplist_get_level_index(MultiSkiplist *sl)
{
    int i;
    unsigned int rand_num;

    for (i=0; i<sl->top_level_index; i++) {
        get_random_bytes(&rand_num, sizeof(rand_num));
        if (rand_num % 2) {
            break;
        }
    }

    return i;
}

int multi_skiplist_insert(MultiSkiplist *sl, void *data)
{
    int i;
    int level_index;
    MultiSkiplistData *dataNode;
    MultiSkiplistNode *node;
    MultiSkiplistNode *previous;

    dataNode = (MultiSkiplistData *)fast_mblock_alloc_object(&sl->data_mblock);
    if (dataNode == NULL) {
        return ENOMEM;
    }
    dataNode->data = data;
    dataNode->next = NULL;

    previous = multi_skiplist_get_previous(sl, data, &level_index);
    if (previous != NULL) {
        node = previous->links[level_index];
        node->tail->next = dataNode;
        node->tail = dataNode;
        return 0;
    }

    level_index = multi_skiplist_get_level_index(sl);
    node = (MultiSkiplistNode *)fast_mblock_alloc_object(sl->mblocks + level_index);
    if (node == NULL) {
        fast_mblock_free_object(&sl->data_mblock, dataNode);
        return ENOMEM;
    }

    previous = sl->top;
    for (i=sl->top_level_index; i>level_index; i--) {
        while (previous->links[i] != sl->tail && sl->compare_func(data,
                    previous->links[i]->head->data) > 0)
        {
            previous = previous->links[i];
        }
    }

    while (i >= 0) {
        while (previous->links[i] != sl->tail && sl->compare_func(data,
                    previous->links[i]->head->data) > 0)
        {
            previous = previous->links[i];
        }

        sl->tmp_previous[i] = previous;
        i--;
    }

    node->head = dataNode;
    node->tail = dataNode;

    //thread safe for one write with many read model
    for (i=0; i<=level_index; i++) {
        node->links[i] = sl->tmp_previous[i]->links[i];
        sl->tmp_previous[i]->links[i] = node;
    }

    return 0;
}

int multi_skiplist_do_delete(MultiSkiplist *sl, void *data,
        const bool delete_all, int *delete_count)
{
    int i;
    int level_index;
    MultiSkiplistNode *previous;
    MultiSkiplistNode *deleted;
    MultiSkiplistData *dataNode;
    MultiSkiplistData *dataCurrent;

    *delete_count = 0;
    previous = multi_skiplist_get_previous(sl, data, &level_index);
    if (previous == NULL) {
        return ENOENT;
    }

    deleted = previous->links[level_index];
    if (!delete_all) {
        if (deleted->head->next != NULL) {
            dataNode = deleted->head;
            deleted->head = dataNode->next;

            multi_skiplist_free_data_node(sl, dataNode);
            *delete_count = 1;
            return 0;
        }
    }

    for (i=level_index; i>=0; i--) {
        while (previous->links[i] != sl->tail &&
                previous->links[i] != deleted)
        {
            previous = previous->links[i];
        }

        // assert(previous->links[i] == deleted);
        if(previous->links[i] == deleted) {
            printk(KERN_ERR "Error on deleting skiplist entry.\n");
            return -1;
        }
        previous->links[i] = previous->links[i]->links[i];
    }

    dataCurrent = deleted->head;
    while (dataCurrent != NULL) {
        dataNode = dataCurrent;
        dataCurrent = dataCurrent->next;

        (*delete_count)++;
        multi_skiplist_free_data_node(sl, dataNode);
    }

    fast_mblock_free_object(sl->mblocks + level_index, deleted);
    return 0;
}

int multi_skiplist_delete(MultiSkiplist *sl, void *data)
{
    int delete_count;
    return multi_skiplist_do_delete(sl, data, true, &delete_count);
}

int multi_skiplist_delete_all(MultiSkiplist *sl, void *data, int *delete_count)
{
    return multi_skiplist_do_delete(sl, data, true, delete_count);
}

void *multi_skiplist_find(MultiSkiplist *sl, void *data)
{
    int level_index;
    MultiSkiplistNode *previous;

    previous = multi_skiplist_get_previous(sl, data, &level_index);
    return (previous != NULL) ? previous->links[level_index]->head->data : NULL;
}

int multi_skiplist_find_all(MultiSkiplist *sl, void *data,
        MultiSkiplistIterator *iterator)
{
    int level_index;
    MultiSkiplistNode *previous;

    iterator->cursor.data = NULL;
    previous = multi_skiplist_get_previous(sl, data, &level_index);
    if (previous == NULL) {
        iterator->cursor.node = sl->tail;
        iterator->tail = sl->tail;
        return ENOENT;
    }
    else {
        iterator->cursor.node = previous->links[level_index];
        iterator->tail = iterator->cursor.node->links[0];
        iterator->cursor.data = iterator->cursor.node->head;
        return 0;
    }
}

void *multi_skiplist_find_ge(MultiSkiplist *sl, void *data)
{
    MultiSkiplistNode *node;
    node = multi_skiplist_get_first_larger_or_equal(sl, data);
    if (node == sl->tail) {
        return NULL;
    }
    return node->head->data;
}

int multi_skiplist_find_range(MultiSkiplist *sl, void *start_data, void *end_data,
        MultiSkiplistIterator *iterator)
{
    if (sl->compare_func(start_data, end_data) > 0) {
        iterator->cursor.node = sl->tail;
        iterator->cursor.data = NULL;
        iterator->tail = sl->tail;
        return EINVAL;
    }

    iterator->cursor.node = multi_skiplist_get_first_larger_or_equal(sl, start_data);
    if (iterator->cursor.node == sl->tail) {
        iterator->cursor.data = NULL;
        iterator->tail = sl->tail;
        return ENOENT;
    }

    iterator->tail = multi_skiplist_get_first_larger(sl, end_data);
    if (iterator->cursor.node != iterator->tail) {
        iterator->cursor.data = iterator->cursor.node->head;
        return 0;
    } else {
        iterator->cursor.data = NULL;
        return ENOENT;
    }
}

static inline int multi_skiplist_to_array(MultiSkiplist *sl, void *array_buf) {
    MultiSkiplistNode *cursor;
    char *buf = (char *)array_buf;
    int total_write = 0;

    cursor = sl->top->links[0];
    while(cursor != sl->tail) {
        memcpy(cursor->head->data, buf + total_write, sizeof(Skiplist_Entry));
        cursor = cursor->links[0];
        total_write += sizeof(Skiplist_Entry);
    }

    return total_write;
}
