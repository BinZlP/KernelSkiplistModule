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

//multi_skiplist.h, support duplicated entries, and support stable sort  :)

#ifndef _MULTI_SKIPLIST_H
#define _MULTI_SKIPLIST_H

#include <linux/kernel.h>
#include <linux/string.h>
#include <linux/types.h>

#include "common_define.h"
#include "fast_mblock.h"
#include "skiplist_common.h"

typedef struct multi_skiplist_data
{
    void *data;
    struct multi_skiplist_data *next;
} MultiSkiplistData;

typedef struct multi_skiplist_node
{
    MultiSkiplistData *head;
    MultiSkiplistData *tail;
    struct multi_skiplist_node *links[0];
} MultiSkiplistNode;

typedef struct multi_skiplist
{
    int level_count;
    int top_level_index;
    skiplist_compare_func compare_func;
    skiplist_free_func free_func;
    struct fast_mblock_man data_mblock; //data node allocators
    struct fast_mblock_man *mblocks;  //node allocators
    MultiSkiplistNode *top;   //the top node
    MultiSkiplistNode *tail;  //the tail node for terminate
    MultiSkiplistNode **tmp_previous;  //thread safe for insert
} MultiSkiplist;

typedef struct multi_skiplist_iterator {
    MultiSkiplistNode *tail;
    struct {
        MultiSkiplistNode *node;
        MultiSkiplistData *data;
    } cursor;
} MultiSkiplistIterator;

#ifdef __cplusplus
extern "C" {
#endif

#define multi_skiplist_init(sl, level_count, compare_func, free_func) \
    multi_skiplist_init_ex(sl, level_count, compare_func, free_func,  \
    SKIPLIST_DEFAULT_MIN_ALLOC_ELEMENTS_ONCE)

int multi_skiplist_init_ex(MultiSkiplist *sl, const int level_count,
        skiplist_compare_func compare_func,
        skiplist_free_func free_func,
        const int min_alloc_elements_once);

void multi_skiplist_destroy(MultiSkiplist *sl);

int multi_skiplist_insert(MultiSkiplist *sl, void *data);
int multi_skiplist_delete(MultiSkiplist *sl, void *data);
int multi_skiplist_delete_all(MultiSkiplist *sl, void *data, int *delete_count);
void *multi_skiplist_find(MultiSkiplist *sl, void *data);
int multi_skiplist_find_all(MultiSkiplist *sl, void *data,
        MultiSkiplistIterator *iterator);
int multi_skiplist_find_range(MultiSkiplist *sl, void *start_data, void *end_data,
        MultiSkiplistIterator *iterator);
void *multi_skiplist_find_ge(MultiSkiplist *sl, void *data);

static inline void multi_skiplist_iterator(MultiSkiplist *sl,
        MultiSkiplistIterator *iterator)
{
    iterator->tail = sl->tail;
    iterator->cursor.node = sl->top->links[0];
    if (iterator->cursor.node != sl->tail) {
        iterator->cursor.data = iterator->cursor.node->head;
    }
    else {
        iterator->cursor.data = NULL;
    }
}

static inline void *multi_skiplist_next(MultiSkiplistIterator *iterator)
{
    void *data;

    if (iterator->cursor.data == NULL) {
        if (iterator->cursor.node == iterator->tail ||
                iterator->cursor.node->links[0] == iterator->tail)
        {
            return NULL;
        }

        iterator->cursor.node = iterator->cursor.node->links[0];
        iterator->cursor.data = iterator->cursor.node->head;
    }

    data = iterator->cursor.data->data;
    iterator->cursor.data = iterator->cursor.data->next;
    return data;
}

static inline void *multi_skiplist_get_first(MultiSkiplist *sl)
{
    if (sl->top->links[0] != sl->tail) {
        return sl->top->links[0]->head->data;
    } else {
        return NULL;
    }
}

static inline char multi_skiplist_empty(MultiSkiplist *sl)
{
    return sl->top->links[0] == sl->tail;
}

typedef const char * (*multi_skiplist_tostring_func)(void *data, char *buff, const int size);

static inline void multi_skiplist_print(MultiSkiplist *sl, multi_skiplist_tostring_func tostring_func)
{
    int i;
    MultiSkiplistNode *cursor;
    char buff[1024] = {0,};

    printk("###################\n");
    for (i=sl->top_level_index; i>=0; i--) {
        printk(" - level %d - \n", i);
        cursor = sl->top->links[i];
        while (cursor != sl->tail) {
            printk("%s\n", tostring_func(cursor->head->data, buff, sizeof(buff)));
            cursor = cursor->links[i];
        }
        printk("\n");
    }
    printk("###################\n");
    printk("\n");
}

#ifdef __cplusplus
}
#endif

#endif
