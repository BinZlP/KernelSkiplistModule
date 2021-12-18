//common_define.h
#ifndef _COMMON_DEFINE_H
#define _COMMON_DEFINE_H

typedef long long int64_t;

#define true 1
#define false 0

#define MEM_ALIGN_FLOOR(x, align_size) ((x) & (~(align_size - 1)))
#define MEM_ALIGN_CEIL(x, align_size) \
    (((x) + (align_size - 1)) & (~(align_size - 1)))
#define MEM_ALIGN(x)  MEM_ALIGN_CEIL(x, 8)

// Return error description
char *strerr(int error);

#define STRERROR(no) (strerr(no) != NULL ? strerr(no) : "Unkown error")

#endif