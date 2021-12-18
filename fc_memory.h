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

//fc_memory.h

#ifndef _FC_MEMORY_H
#define _FC_MEMORY_H

#include <linux/kernel.h>
#include <linux/slab.h>
#include <linux/string.h>
#include <linux/errno.h>

#include "common_define.h"

typedef void (*fc_memory_oom_notify_func)(const size_t curr_size);

#ifdef __cplusplus
extern "C" {
#endif

    extern fc_memory_oom_notify_func g_oom_notify;

    static inline void *fc_malloc_ex(const char *file,
            const int line, size_t size)
    {
        void *ptr;
        ptr = kmalloc(size, GFP_KERNEL);
        if (ptr == NULL) {
            printk(KERN_ERR "file: %s, line: %d, malloc %ld bytes fail\n",
                    file, line, size);
            if (g_oom_notify != NULL) {
                g_oom_notify(size);
            }
        }

        return ptr;
    }

    static inline void *fc_realloc_ex(const char *file,
            const int line, void *ptr, size_t size)
    {
        void *new_ptr = NULL;
        new_ptr = krealloc(ptr, size, GFP_KERNEL);

        if (new_ptr == NULL) {
            printk(KERN_ERR "file: %s, line: %d, realloc %ld bytes fail\n",
                    file, line, size);
            if (g_oom_notify != NULL) {
                g_oom_notify(size);
            }
        }

        return new_ptr;
    }

    static inline char *fc_strdup_ex(const char *file,
            const int line, const char *str)
    {
        char *output;
        int len;

        len = strlen(str);
        output = (char *)fc_malloc_ex(file, line, len + 1);
        if (output == NULL) {
            return NULL;
        }

        if (len > 0) {
            memcpy(output, str, len);
        }
        *(output + len) = '\0';
        return output;
    }

    static inline void *fc_calloc_ex(const char *file,
            const int line, size_t count, size_t size)
    {
        void *ptr;
        ptr = kmalloc_array(count, size, GFP_KERNEL);

        if (ptr == NULL) {
            printk(KERN_ERR "file: %s, line: %d, malloc %ld bytes fail\n", 
                    file, line, (count * size));
            if (g_oom_notify != NULL) {
                g_oom_notify(count * size);
            }
        }

        return ptr;
    }

#define fc_malloc(size)  fc_malloc_ex(__FILE__, __LINE__, size)
#define fc_realloc(ptr, size)  fc_realloc_ex(__FILE__, __LINE__, ptr, size)
#define fc_calloc(count, size)  fc_calloc_ex(__FILE__, __LINE__, count, size)
#define fc_strdup(str)  fc_strdup_ex(__FILE__, __LINE__, str)

#ifdef __cplusplus
}
#endif

#endif
