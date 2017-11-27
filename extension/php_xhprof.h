/*
 *  Copyright (c) 2009 Facebook
 *
 *  Licensed under the Apache License, Version 2.0 (the "License");
 *  you may not use this file except in compliance with the License.
 *  You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 *  Unless required by applicable law or agreed to in writing, software
 *  distributed under the License is distributed on an "AS IS" BASIS,
 *  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 *  See the License for the specific language governing permissions and
 *  limitations under the License.
 *
 */

#ifndef PHP_XHPROF_H
#define PHP_XHPROF_H

extern zend_module_entry xhprof_module_entry;
#define phpext_xhprof_ptr &xhprof_module_entry

#ifdef PHP_WIN32
#define PHP_XHPROF_API __declspec(dllexport)
#else
#define PHP_XHPROF_API
#endif

#ifdef ZTS
#include "TSRM.h"
#endif

#include <sys/time.h>
#include <sys/resource.h>

/* XHProf version */
#define XHPROF_VERSION "0.9.2"

/* Fictitious function name to represent top of the call tree. The paranthesis
 * in the name is to ensure we don't conflict with user function names. */
#define ROOT_SYMBOL "main()"

/* Size of a temp scratch buffer */
#define SCRATCH_BUF_LEN 512

/* Profiling flags.
 *
 * Note: Function call counts and wall (elapsed) time are always profiled.
 * The following optional flags can be used to control other aspects of
 * profiling.
 */

/* do not profile builtins */
#define XHPROF_FLAGS_NO_BUILTINS 0x0001
/* gather CPU times for funcs */
#define XHPROF_FLAGS_CPU 0x0002
/* gather memory usage for funcs */
#define XHPROF_FLAGS_MEMORY 0x0004

/* Constant for ignoring functions, transparent to hierarchical profile */
#define XHPROF_MAX_IGNORED_FUNCTIONS 256
#define XHPROF_IGNORED_FUNCTION_FILTER_SIZE ((XHPROF_MAX_IGNORED_FUNCTIONS + 7)/8)

#if !defined(uint64)
typedef unsigned long long uint64;
#endif
#if !defined(uint32)
typedef unsigned int uint32;
#endif
#if !defined(uint8)
typedef unsigned char uint8;
#endif

PHP_MINIT_FUNCTION(xhprof);
PHP_MSHUTDOWN_FUNCTION(xhprof);
PHP_RINIT_FUNCTION(xhprof);
PHP_RSHUTDOWN_FUNCTION(xhprof);
PHP_MINFO_FUNCTION(xhprof);

PHP_FUNCTION(xhprof_enable);
PHP_FUNCTION(xhprof_disable);

/* XHProf maintains a stack of entries being profiled. The memory for the entry
 * is passed by the layer that invokes BEGIN_PROFILING(), e.g. the hp_execute()
 * function. Often, this is just C-stack memory.
 *
 * This structure is a convenient place to track start time of a particular
 * profile operation, recursion depth, and the name of the function being
 * profiled. */
typedef struct hp_entry_t {
    /* function name */
    zend_string *name_hprof;
    /* recursion level for function */
    int rlvl_hprof;
    /* start value for timer */
    uint64 timer_start;
    /* memory usage */
    long int mu_start_hprof;
    /* peak memory usage */
    long int pmu_start_hprof;
    /* user/sys time start */
    struct rusage ru_start_hprof;
    /* ptr to prev entry being profiled */
    struct hp_entry_t *prev_hprof;
    /* hash_code for the function name */
    uint8 hash_code;
} hp_entry_t;

/* Xhprof's global state. */
typedef struct hp_global_t {
    /*           ----------     Global attributes:  -----------             */

    /* Indicates if xhprof is currently enabled */
    int enabled;

    /* Indicates if xhprof was ever enabled during this request */
    int ever_enabled;

    /* Holds all the xhprof statistics */
    zval *stats_count;

    /* Top of the profile stack */
    hp_entry_t *entries;

    /* freelist of hp_entry_t chunks for reuse... */
    hp_entry_t *entry_free_list;

    /*           ----------     Mode specific attributes:  -----------           */

    /* XHProf flags */
    uint32 xhprof_flags;

    /* counter table indexed by hash value of function names. */
    uint8 func_hash_counters[256];

    /* Table of ignored function names and their filter */
    char **ignored_function_names;
    uint8 ignored_function_filter[XHPROF_IGNORED_FUNCTION_FILTER_SIZE];

} hp_global_t;

/* Bloom filter for function names to be ignored */
#define INDEX_2_BYTE(index) (index >> 3)
#define INDEX_2_BIT(index) (1 << (index & 0x7))

/**
 * ***************************
 * XHPROF DUMMY CALLBACKS
 * ***************************
 */

/* Pointer to the original execute function */
static void (*_zend_execute_ex) (zend_execute_data *execute_data);

/* Pointer to the origianl execute_internal function */
static void (*_zend_execute_internal) (zend_execute_data *data, zval *ret);

ZEND_DLEXPORT void hp_execute_internal(zend_execute_data *execute_data, zval* ret);

ZEND_DLEXPORT void hp_execute_ex(zend_execute_data *execute_data);

ZEND_DLEXPORT zend_op_array* hp_compile_file(zend_file_handle *file_handle, int type);
/**
 * ****************************
 * STATIC FUNCTION DECLARATIONS
 * ****************************
 */
static void hp_register_constants(INIT_FUNC_ARGS);

static void hp_stop();

static inline uint64 cycle_timer();

static void hp_free_list();
static hp_entry_t *hp_fast_alloc_hprof_entry();
static void hp_fast_free_hprof_entry(hp_entry_t *p);
static inline uint8 hp_inline_hash(char * str, size_t len);
static long get_us_interval(struct timeval *start, struct timeval *end);

#endif /* PHP_XHPROF_H */
