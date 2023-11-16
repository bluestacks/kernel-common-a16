/*
 *  linux/fs/bst_hooks.c
 *
 *  This file contains BlueStacks specific hook functions.
 */
#include <linux/export.h>
#ifdef CONFIG_PROC_FS
#include "proc/internal.h"
#endif

unsigned int is_aga_mode = 1;
EXPORT_SYMBOL(is_aga_mode);

