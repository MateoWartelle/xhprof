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

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include "php.h"
#include "php_ini.h"
#include "ext/standard/info.h"
#include "php_xhprof.h"
#include "zend_smart_str.h"

#include "zend_compile.h"

#include <stdlib.h>
#include <unistd.h>

/**
 * ***********************
 * GLOBAL STATIC VARIABLES
 * ***********************
 */
/* XHProf global state */
static hp_global_t hp_globals;

/* Pointer to the original compile function */
static zend_op_array * (*_zend_compile_file) (zend_file_handle *file_handle, int type);

/* {{{ arginfo */
ZEND_BEGIN_ARG_INFO_EX(arginfo_xhprof_enable, 0, 0, 0)
    ZEND_ARG_INFO(0, flags)
    ZEND_ARG_INFO(0, options)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_INFO(arginfo_xhprof_disable, 0)
ZEND_END_ARG_INFO()

/* }}} */

/**
 * *********************
 * PHP EXTENSION GLOBALS
 * *********************
 */
/* List of functions implemented/exposed by xhprof */
zend_function_entry xhprof_functions[] = {
    PHP_FE(xhprof_enable, arginfo_xhprof_enable)
    PHP_FE(xhprof_disable, arginfo_xhprof_disable)
    {NULL, NULL, NULL}
};

/* Callback functions for the xhprof extension */
zend_module_entry xhprof_module_entry = {
    STANDARD_MODULE_HEADER,
    "xhprof",
    xhprof_functions,
    PHP_MINIT(xhprof),
    PHP_MSHUTDOWN(xhprof),
    PHP_RINIT(xhprof),
    PHP_RSHUTDOWN(xhprof),
    PHP_MINFO(xhprof),
    XHPROF_VERSION,
    STANDARD_MODULE_PROPERTIES
};

PHP_INI_BEGIN()

/* output directory:
 * Currently this is not used by the extension itself.
 * But some implementations of iXHProfRuns interface might
 * choose to save/restore XHProf profiler runs in the
 * directory specified by this ini setting.
 */
PHP_INI_ENTRY("xhprof.output_dir", "", PHP_INI_ALL, NULL)

PHP_INI_END()

/* Init module */
ZEND_GET_MODULE(xhprof)

/*
 * Start profiling - called just before calling the actual function
 */
static zend_always_inline void begin_profiling(zend_string *symbol) {
    hp_entry_t *p, *cur_entry = hp_globals.entry_free_list;
    unsigned int recurse_level = 0;

    if (cur_entry) {
        hp_globals.entry_free_list = cur_entry->prev_hprof;
        if (cur_entry->name_hprof) {
            zend_string_free(cur_entry->name_hprof);
            cur_entry->name_hprof = NULL;
        }
    } else {
        cur_entry = malloc(sizeof(hp_entry_t));
        cur_entry->name_hprof = NULL;
    }

    cur_entry->hash_code = hp_inline_hash(ZSTR_VAL(symbol), ZSTR_LEN(symbol));
    cur_entry->name_hprof = symbol;
    cur_entry->prev_hprof = hp_globals.entries;

    if (hp_globals.func_hash_counters[cur_entry->hash_code] > 0) {
        /* Find this symbols recurse level */
        for (p = hp_globals.entries; p; p = p->prev_hprof) {
            if (!strcmp(ZSTR_VAL(cur_entry->name_hprof), ZSTR_VAL(p->name_hprof))) {
                recurse_level = (p->rlvl_hprof) + 1;
                break;
            }
        }
    }
    hp_globals.func_hash_counters[cur_entry->hash_code]++;

    /* Init current function's recurse level */
    cur_entry->rlvl_hprof = recurse_level;

    /* Get CPU usage */
    if (hp_globals.xhprof_flags & XHPROF_FLAGS_CPU) {
        struct rusage usage;
        getrusage(RUSAGE_SELF, &usage);
        cur_entry->ru_start_hprof.tv_sec = usage.ru_utime.tv_sec + usage.ru_stime.tv_sec;
        cur_entry->ru_start_hprof.tv_usec = usage.ru_utime.tv_usec + usage.ru_stime.tv_usec;
    }

    /* Get memory usage */
    if (hp_globals.xhprof_flags & XHPROF_FLAGS_MEMORY) {
        cur_entry->mu_start_hprof = zend_memory_usage(0);
        cur_entry->pmu_start_hprof = zend_memory_peak_usage(0);
    }

    /* Update entries linked list */
    hp_globals.entries = cur_entry;

    cur_entry->timer_start = cycle_timer();
}

/*
 * Stop profiling - called just after calling the actual function
 */
static zend_always_inline void end_profiling() {
    hp_entry_t *cur_entry;
    /* Call the mode's endfn callback. */

    hp_entry_t *top = hp_globals.entries;
    struct rusage ru_end;
    smart_str symbol = {0};

    zval count_val;
    zval *counts, *data;

    /* Bail if something is goofy */
    if (hp_globals.stats_count) {
        /* Get the stat array */
        if (top->prev_hprof) {
            /* Take care of ancestor first */
            smart_str_appendl(&symbol, ZSTR_VAL(top->prev_hprof->name_hprof), ZSTR_LEN(top->prev_hprof->name_hprof));
            /* Add '@recurse_level' if required */
            if (top->prev_hprof->rlvl_hprof) {
                smart_str_appendc(&symbol, '@');
                smart_str_append_long(&symbol, top->prev_hprof->rlvl_hprof);
            }

            smart_str_appendl(&symbol, "==>", sizeof("==>") - 1);
        }

        /* Append the current function name */
        smart_str_appendl(&symbol, ZSTR_VAL(top->name_hprof), ZSTR_LEN(top->name_hprof));
        /* Add '@recurse_level' if required */
        if (top->rlvl_hprof) {
            smart_str_appendc(&symbol, '@');
            smart_str_append_long(&symbol, top->rlvl_hprof);
        }

        smart_str_0(&symbol);

        /* Lookup our hash table */
        if ((counts = zend_hash_str_find(Z_ARRVAL_P(hp_globals.stats_count), ZSTR_VAL(symbol.s), ZSTR_LEN(symbol.s))) == NULL) {
            /* Add symbol to hash table */
            counts = &count_val;
            array_init(counts);
            add_assoc_zval_ex(hp_globals.stats_count, ZSTR_VAL(symbol.s), ZSTR_LEN(symbol.s), counts);
        }

        /* Bump stats in the counts hashtable */

        if ((data = zend_hash_str_find(Z_ARRVAL_P(counts), "ct", 2)) != NULL) {
            ++Z_LVAL_P(data);
            Z_LVAL_P(zend_hash_str_find(Z_ARRVAL_P(counts), "wt", 2)) += (cycle_timer() - top->timer_start) / 1000;

            if (hp_globals.xhprof_flags & XHPROF_FLAGS_CPU) {
                getrusage(RUSAGE_SELF, &ru_end);

                Z_LVAL_P(zend_hash_str_find(Z_ARRVAL_P(counts), "cpu", 3)) +=
                    (ru_end.ru_utime.tv_sec + ru_end.ru_stime.tv_sec - top->ru_start_hprof.tv_sec) * 1000000 + ru_end.ru_utime.tv_usec + ru_end.ru_stime.tv_usec - top->ru_start_hprof.tv_usec;
            }

            if (hp_globals.xhprof_flags & XHPROF_FLAGS_MEMORY) {
                Z_LVAL_P(zend_hash_str_find(Z_ARRVAL_P(counts), "mu", 2)) += zend_memory_usage(0) - top->mu_start_hprof;
                Z_LVAL_P(zend_hash_str_find(Z_ARRVAL_P(counts), "pmu", 3)) += zend_memory_peak_usage(0) - top->pmu_start_hprof;
            }
        } else {
            add_assoc_long_ex(counts, "ct", 2, 1);
            add_assoc_long_ex(counts, "wt", 2, (cycle_timer() - top->timer_start) / 1000);

            if (hp_globals.xhprof_flags & XHPROF_FLAGS_CPU) {
                getrusage(RUSAGE_SELF, &ru_end);

                add_assoc_long_ex(counts, "cpu", 3,
                    (ru_end.ru_utime.tv_sec + ru_end.ru_stime.tv_sec - top->ru_start_hprof.tv_sec) * 1000000 + ru_end.ru_utime.tv_usec + ru_end.ru_stime.tv_usec - top->ru_start_hprof.tv_usec
                );
            }

            if (hp_globals.xhprof_flags & XHPROF_FLAGS_MEMORY) {
                add_assoc_long_ex(counts, "mu", 2, zend_memory_usage(0) - top->mu_start_hprof);
                add_assoc_long_ex(counts, "pmu", 3, zend_memory_peak_usage(0) - top->pmu_start_hprof);
            }
        }
    }

    cur_entry = top;

    /* Call the universal callback */
    hp_globals.func_hash_counters[cur_entry->hash_code]--;

    /* Free top entry and update entries linked list */
    hp_globals.entries = top->prev_hprof;

    /* we use/overload the prev_hprof field in the structure to link entries in
     * the free list. */
    cur_entry->prev_hprof = hp_globals.entry_free_list;
    hp_globals.entry_free_list = cur_entry;

    smart_str_free(&symbol);
}

/**
 * **********************************
 * PHP EXTENSION FUNCTION DEFINITIONS
 * **********************************
 */

/**
 * Start XHProf profiling
 *
 * @param long $flags flags
 */
PHP_FUNCTION(xhprof_enable) {
    /* XHProf flags */
    long xhprof_flags = 0;
    zend_string *root_symbol;

    if (zend_parse_parameters(ZEND_NUM_ARGS(), "|l", &xhprof_flags) == FAILURE) {
        return;
    }

    if (!hp_globals.enabled) {
        hp_globals.enabled = 1;
        hp_globals.xhprof_flags = (uint32)xhprof_flags;

        /* Setup globals */
        if (!hp_globals.ever_enabled) {
            hp_globals.ever_enabled = 1;
            hp_globals.entries = NULL;
        }

        /* Init stats_count */
        if (hp_globals.stats_count) {
            zval_ptr_dtor(hp_globals.stats_count);
            efree(hp_globals.stats_count);
        }

        hp_globals.stats_count = (zval *)emalloc(sizeof(zval));
        array_init(hp_globals.stats_count);

        root_symbol = zend_string_init(ROOT_SYMBOL, sizeof(ROOT_SYMBOL) - 1, 0);

        begin_profiling(root_symbol);
    }
}

/**
 * Stops XHProf from profiling anymore and returns the profile info.
 *
 * @return array hash-array of XHProf's profile info
 */
PHP_FUNCTION(xhprof_disable) {
    if (hp_globals.enabled) {
        hp_stop();
        RETURN_ZVAL(hp_globals.stats_count, 1, 0);
    }
    /* else null is returned */
}

/**
 * Module init callback.
 */
PHP_MINIT_FUNCTION(xhprof) {
    int i;

    REGISTER_INI_ENTRIES();

    hp_register_constants(INIT_FUNC_ARGS_PASSTHRU);

    hp_globals.stats_count = NULL;

    for (i = 0; i < 256; i++) {
        hp_globals.func_hash_counters[i] = 0;
    }

#if defined(DEBUG)
    /* To make it random number generator repeatable to ease testing. */
    srand(0);
#endif

    return SUCCESS;
}

/**
 * Module shutdown callback.
 */
PHP_MSHUTDOWN_FUNCTION(xhprof) {
    UNREGISTER_INI_ENTRIES();

    return SUCCESS;
}

/**
 * Request init callback. Nothing to do yet!
 */
PHP_RINIT_FUNCTION(xhprof) {
    /* no free hp_entry_t structures to start with */
    hp_globals.entry_free_list = NULL;

    _zend_compile_file = zend_compile_file;
    zend_compile_file = hp_compile_file;

    /* Replace zend_execute with our proxy */
    _zend_execute_ex = zend_execute_ex;
    zend_execute_ex = hp_execute_ex;

    /* Replace zend_execute_internal with our proxy */
    _zend_execute_internal = zend_execute_internal;
    zend_execute_internal = hp_execute_internal;

    return SUCCESS;
}

/**
 * Request shutdown callback. Stop profiling and return.
 */
PHP_RSHUTDOWN_FUNCTION(xhprof) {
    /* Bail if not ever enabled */
    if (hp_globals.ever_enabled) {
        /* Stop profiler if enabled */
        if (hp_globals.enabled) {
            hp_stop();
        }

        /* Clean up state */
        if (hp_globals.stats_count) {
            zval_ptr_dtor(hp_globals.stats_count);
            efree(hp_globals.stats_count);
            hp_globals.stats_count = NULL;
        }

        hp_globals.entries = NULL;
        hp_globals.ever_enabled = 0;
    }

    /* free any remaining items */
    hp_free_list(hp_globals.entry_free_list);
    hp_free_list(hp_globals.entries);

    zend_execute_ex = _zend_execute_ex;
    zend_execute_internal = _zend_execute_internal;

    zend_compile_file = _zend_compile_file;
    return SUCCESS;
}

/**
 * Module info callback. Returns the xhprof version.
 */
PHP_MINFO_FUNCTION(xhprof)
{
    php_info_print_table_start();
    php_info_print_table_header(2, "xhprof", XHPROF_VERSION);

    php_info_print_table_end();
}

/**
 * ***************************************************
 * COMMON HELPER FUNCTION DEFINITIONS AND LOCAL MACROS
 * ***************************************************
 */

static void hp_register_constants(INIT_FUNC_ARGS) {
    REGISTER_LONG_CONSTANT("XHPROF_FLAGS_NO_BUILTINS", XHPROF_FLAGS_NO_BUILTINS, CONST_CS | CONST_PERSISTENT);
    REGISTER_LONG_CONSTANT("XHPROF_FLAGS_CPU", XHPROF_FLAGS_CPU, CONST_CS | CONST_PERSISTENT);
    REGISTER_LONG_CONSTANT("XHPROF_FLAGS_MEMORY", XHPROF_FLAGS_MEMORY, CONST_CS | CONST_PERSISTENT);
}

/**
 * Inspired by zend_inline_hash_func()
 */
static zend_always_inline uint8 hp_inline_hash(char * str, size_t len) {
    register zend_ulong h = Z_UL(5381);

    /* variant with the hash unrolled eight times */
    for (; len >= 8; len -= 8) {
        h = ((h << 5) + h) + *str++;
        h = ((h << 5) + h) + *str++;
        h = ((h << 5) + h) + *str++;
        h = ((h << 5) + h) + *str++;
        h = ((h << 5) + h) + *str++;
        h = ((h << 5) + h) + *str++;
        h = ((h << 5) + h) + *str++;
        h = ((h << 5) + h) + *str++;
    }
    switch (len) {
        case 7: h = ((h << 5) + h) + *str++; /* fallthrough... */
        case 6: h = ((h << 5) + h) + *str++; /* fallthrough... */
        case 5: h = ((h << 5) + h) + *str++; /* fallthrough... */
        case 4: h = ((h << 5) + h) + *str++; /* fallthrough... */
        case 3: h = ((h << 5) + h) + *str++; /* fallthrough... */
        case 2: h = ((h << 5) + h) + *str++; /* fallthrough... */
        case 1: h = ((h << 5) + h) + *str++; break;
        case 0: break;
EMPTY_SWITCH_DEFAULT_CASE()
    }

    return h % 256;
}

/**
 * Takes an input of the form /a/b/c/d/foo.php and returns
 * a pointer to one-level directory and basefile name
 * (d/foo.php) in the same string.
 */
static const char *hp_get_base_filename(const char *filename) {
    const char *ptr;
    int found = 0;

    if (!filename)
        return "";

    /* reverse search for "/" and return a ptr to the next char */
    for (ptr = filename + strlen(filename) - 1; ptr >= filename; ptr--) {
        if (*ptr == '/') {
            found++;
        }
        if (found == 2) {
            return ptr + 1;
        }
    }

    /* no "/" char found, so return the whole string */
    return filename;
}


/**
 * Free any items in the free list.
 */
static void hp_free_list(hp_entry_t *p) {
    hp_entry_t *cur;

    while (p) {
        cur = p;
        p = p->prev_hprof;
        if (cur->name_hprof) {
            zend_string_free(cur->name_hprof);
            cur->name_hprof = NULL;
        }
        free(cur);
    }
}

/**
 * ***********************
 * High precision timer related functions.
 * ***********************
 */

/**
 * Get monotonic time stamp.
 *
 * @return 64 bit unsigned integer
 */
static zend_always_inline uint64 cycle_timer() {
    struct timespec s;
    clock_gettime(CLOCK_MONOTONIC, &s);

    return s.tv_sec * 1000000000 + s.tv_nsec;
}

/**
 * Get time delta in microseconds.
 */
static zend_always_inline zend_long get_us_interval(const struct timeval *start, const struct timeval *end) {
    return (((end->tv_sec - start->tv_sec) * 1000000) + (end->tv_usec - start->tv_usec));
}

/**
 * ***************************
 * PHP EXECUTE/COMPILE PROXIES
 * ***************************
 */

/**
 * XHProf enable replaced the zend_execute function with this
 * new execute function. We can do whatever profiling we need to
 * before and after calling the actual zend_execute().
 */
ZEND_DLEXPORT void hp_execute_ex(zend_execute_data *execute_data) {
    zend_string *func = NULL;
    zend_class_entry *called_scope;
    size_t class_name_len;

    if (hp_globals.enabled == 0) {
        _zend_execute_ex(execute_data);
        return;
    }

    called_scope = zend_get_called_scope(execute_data);

    func = execute_data->func->common.function_name;
    /* check if was in a class */
    if (called_scope != NULL && func != NULL) {
        zend_string *func_name = func;

        class_name_len = ZSTR_LEN(called_scope->name);
        func = zend_string_init(ZSTR_VAL(called_scope->name), class_name_len + 2 + ZSTR_LEN(func_name), 0);
        memcpy(ZSTR_VAL(func) + class_name_len, "::", 2);
        memcpy(ZSTR_VAL(func) + class_name_len + 2, ZSTR_VAL(func_name), ZSTR_LEN(func_name));
    } else if (func) {
        //just do the copy;
        func = zend_string_init(ZSTR_VAL(func), ZSTR_LEN(func), 0);
    }

    if (func) {
        begin_profiling(func);
    }
    _zend_execute_ex(execute_data);
    if (func && hp_globals.entries) {
        end_profiling();
    }
}

#undef EX
#define EX(element) ((execute_data)->element)

/**
 * Very similar to hp_execute. Proxy for zend_execute_internal().
 * Applies to zend builtin functions.
 */

ZEND_DLEXPORT void hp_execute_internal(zend_execute_data *execute_data, zval *ret) {
    zend_string *func = NULL;

    if (!hp_globals.enabled || (hp_globals.xhprof_flags & XHPROF_FLAGS_NO_BUILTINS)) {
        execute_internal(execute_data, ret);
        return;
    }

    func = execute_data->func->common.function_name;

    //check is a class method
    if (execute_data->func->op_array.scope != NULL) {
        zend_string *func_name = func;

        int class_name_len = ZSTR_LEN(execute_data->func->op_array.scope->name);
        func = zend_string_init(ZSTR_VAL(execute_data->func->op_array.scope->name), class_name_len + 2 + ZSTR_LEN(func_name), 0);
        memcpy(ZSTR_VAL(func) + class_name_len, "::", 2);
        memcpy(ZSTR_VAL(func) + class_name_len + 2, ZSTR_VAL(func_name), ZSTR_LEN(func_name));
    } else if (func) {
        //just do the copy;
        func = zend_string_init(ZSTR_VAL(func), ZSTR_LEN(func), 0);
    }

    if (func) {
        begin_profiling(func);
    }

    if (!_zend_execute_internal) {
        /* no old override to begin with. so invoke the builtin's implementation */

        execute_data ->func ->internal_function.handler(execute_data, ret);

    } else {
        /* call the old override */
        _zend_execute_internal(execute_data, ret);
    }

    if (func && hp_globals.entries) {
        end_profiling();
    }
}

/**
 * Proxy for zend_compile_file(). Used to profile PHP compilation time.
 */
ZEND_DLEXPORT zend_op_array* hp_compile_file(zend_file_handle *file_handle, int type) {
    const char *filename;
    size_t len;
    zend_op_array *ret;
    zend_string *func_name;

    filename = hp_get_base_filename(file_handle->filename);
    len = sizeof("load::") - 1 + strlen(filename);

    func_name = zend_string_alloc(len, 0);

    ZSTR_LEN(func_name) = snprintf(ZSTR_VAL(func_name), len + 1, "load::%s", filename);

    begin_profiling(func_name);
    ret = _zend_compile_file(file_handle, type);
    if (hp_globals.entries) {
        end_profiling();
    }

    return ret;
}

static void hp_stop() {
    /* End any unfinished calls */
    while (hp_globals.entries) {
        end_profiling();
    }

    /* Stop profiling */
    hp_globals.enabled = 0;
}
