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

static zend_always_inline int hp_ignore_entry(const uint8 hash_code, const char *curr_func) {
    int i;
    char *name;

    /* First check if ignoring functions is enabled */
    if (hp_globals.ignored_function_names == NULL) {
        return 0;
    }

    if (hp_globals.ignored_function_filter[INDEX_2_BYTE(hash_code)] & INDEX_2_BIT(hash_code)) {
        for (i = 0; hp_globals.ignored_function_names[i] != NULL; ++i) {
            name = hp_globals.ignored_function_names[i];
            if (!strcmp(curr_func, name)) {
                return 1;
            }
        }
    }

    return 0;
}

/**
 * begin function callback
 */
static zend_always_inline void hp_mode_beginfn_cb(hp_entry_t *current) {
    current->timer_start = cycle_timer();

    /* Get CPU usage */
    if (hp_globals.xhprof_flags & XHPROF_FLAGS_CPU) {
        getrusage(RUSAGE_SELF, &(current->ru_start_hprof));
    }

    /* Get memory usage */
    if (hp_globals.xhprof_flags & XHPROF_FLAGS_MEMORY) {
        current->mu_start_hprof = zend_memory_usage(0);
        current->pmu_start_hprof = zend_memory_peak_usage(0);
    }
}

/**
 * XHPROF universal begin function.
 * This function is called for all modes before the
 * mode's specific begin_function callback is called.
 *
 * @param hp_entry_t **entries linked list (stack) of hprof entries
 * @param hp_entry_t *current hprof entry for the current fn
 */
static zend_always_inline void hp_mode_common_beginfn(hp_entry_t **entries, hp_entry_t *current) {
    hp_entry_t *p;

    /* This symbol's recursive level */
    int recurse_level = 0;

    if (hp_globals.func_hash_counters[current->hash_code] > 0) {
        /* Find this symbols recurse level */
        for(p = (*entries); p; p = p->prev_hprof) {
            if (!strcmp(ZSTR_VAL(current->name_hprof), ZSTR_VAL(p->name_hprof))) {
                recurse_level = (p->rlvl_hprof) + 1;
                break;
            }
        }
    }
    hp_globals.func_hash_counters[current->hash_code]++;

    /* Init current function's recurse level */
    current->rlvl_hprof = recurse_level;
}

/*
 * Start profiling - called just before calling the actual function
 */
#define BEGIN_PROFILING(entries, symbol, profile_curr)                    \
    do {                                                                  \
        /* Use a hash code to filter most of the string comparisons. */   \
        uint8 hash_code = hp_inline_hash(ZSTR_VAL(symbol), ZSTR_LEN(symbol)); \
        profile_curr = !hp_ignore_entry(hash_code, ZSTR_VAL(symbol));     \
        if (profile_curr) {                                               \
            hp_entry_t *cur_entry = hp_fast_alloc_hprof_entry();          \
            (cur_entry)->hash_code = hash_code;                           \
            (cur_entry)->name_hprof = symbol;                             \
            (cur_entry)->prev_hprof = (*(entries));                       \
            /* Call the universal callback */                             \
            hp_mode_common_beginfn((entries), (cur_entry));               \
            /* Call the mode's beginfn callback */                        \
            hp_mode_beginfn_cb(cur_entry);                                \
            /* Update entries linked list */                              \
            (*(entries)) = (cur_entry);                                   \
        } else {                                                          \
            zend_string_free(symbol);                                     \
            symbol = NULL;                                                \
        }                                                                 \
    } while (0)

/*
 * Stop profiling - called just after calling the actual function
 */
#define END_PROFILING(entries, profile_curr)                              \
    do {                                                                  \
        if (profile_curr) {                                               \
            hp_entry_t *cur_entry;                                        \
            /* Call the mode's endfn callback. */                         \
            hp_mode_endfn_cb((entries));                                  \
            cur_entry = (*(entries));                                     \
            /* Call the universal callback */                             \
            hp_globals.func_hash_counters[(cur_entry)->hash_code]--;      \
            /* Free top entry and update entries linked list */           \
            (*(entries)) = (*(entries))->prev_hprof;                      \
            hp_fast_free_hprof_entry(cur_entry);                          \
        }                                                                 \
    } while (0)

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
    /* optional array arg: for future use */
    zval *optional_array = NULL;
    zend_string *root_symbol;

    if (zend_parse_parameters(ZEND_NUM_ARGS(), "|lz", &xhprof_flags, &optional_array) == FAILURE) {
        return;
    }

    if (!hp_globals.enabled) {
        int hp_profile_flag = 1;

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

        /* Set up filter of functions which may be ignored during profiling */
        if (hp_globals.ignored_function_names != NULL) {
            int i = 0;
            for(; hp_globals.ignored_function_names[i] != NULL; i++) {
                char *str = hp_globals.ignored_function_names[i];
                uint8 hash = hp_inline_hash(str, strlen(str));
                int idx = INDEX_2_BYTE(hash);
                hp_globals.ignored_function_filter[idx] |= INDEX_2_BIT(hash);
            }
        }

        root_symbol = zend_string_init(ROOT_SYMBOL, sizeof(ROOT_SYMBOL) - 1, 0);

        BEGIN_PROFILING(&hp_globals.entries, root_symbol, hp_profile_flag);
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

        hp_globals.ignored_function_names = NULL;
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
 * Fast allocate a hp_entry_t structure. Picks one from the
 * free list if available, else does an actual allocate.
 *
 * Doesn't bother initializing allocated memory.
 */
static zend_always_inline hp_entry_t *hp_fast_alloc_hprof_entry() {
    hp_entry_t *p;

    p = hp_globals.entry_free_list;

    if (p) {
        hp_globals.entry_free_list = p->prev_hprof;
        if (p->name_hprof) {
            zend_string_free(p->name_hprof);
            p->name_hprof = NULL;
        }
        return p;
    } else {
        hp_entry_t *tmp = malloc(sizeof(hp_entry_t));
        tmp->name_hprof = NULL;
        return tmp;
    }
}

/**
 * Fast free a hp_entry_t structure. Simply returns back
 * the hp_entry_t to a free list and doesn't actually
 * perform the free.
 */
static zend_always_inline void hp_fast_free_hprof_entry(hp_entry_t *p) {

    /* we use/overload the prev_hprof field in the structure to link entries in
     * the free list. */
    p->prev_hprof = hp_globals.entry_free_list;
    hp_globals.entry_free_list = p;
}

/**
 * Increment the count of the given stat with the given count
 * If the stat was not set before, inits the stat to the given count
 *
 * @param zval *counts Zend hash table pointer
 * @param char *name Name of the stat
 * @param long count Value of the stat to incr by
 */
static zend_always_inline void hp_inc_count(zval *counts, const char *name, size_t len, long count) {
    zval *data;

    if ((data = zend_hash_str_find(Z_ARRVAL_P(counts), name, len)) != NULL) {
        Z_LVAL_P(data) += count;
    } else {
        add_assoc_long_ex(counts, name, len, count);
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

    return s.tv_sec * 1000000 + s.tv_nsec / 1000;
}

/**
 * Get time delta in microseconds.
 */
static zend_always_inline long get_us_interval(struct timeval *start, struct timeval *end) {
    return (((end->tv_sec - start->tv_sec) * 1000000) + (end->tv_usec - start->tv_usec));
}

/**
 * **********************************
 * XHPROF END FUNCTION CALLBACKS
 * **********************************
 */

/**
 * end function callback
 */
static zend_always_inline void hp_mode_endfn_cb(hp_entry_t **entries) {
    hp_entry_t *top = (*entries);
    struct rusage ru_end;
    smart_str symbol = {0};

    /********/
    zval count_val;
    zval *counts, *data;

    /* Bail if something is goofy */
    if (!hp_globals.stats_count) {
        return;
    }

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
        Z_LVAL_P(zend_hash_str_find(Z_ARRVAL_P(counts), "wt", 2)) += cycle_timer() - top->timer_start;

        if (hp_globals.xhprof_flags & XHPROF_FLAGS_CPU) {
            getrusage(RUSAGE_SELF, &ru_end);

            Z_LVAL_P(zend_hash_str_find(Z_ARRVAL_P(counts), "cpu", 3)) +=
                get_us_interval(&(top->ru_start_hprof.ru_utime), &(ru_end.ru_utime)) +
                get_us_interval(&(top->ru_start_hprof.ru_stime), &(ru_end.ru_stime));
        }

        if (hp_globals.xhprof_flags & XHPROF_FLAGS_MEMORY) {
            Z_LVAL_P(zend_hash_str_find(Z_ARRVAL_P(counts), "mu", 2)) += zend_memory_usage(0) - top->mu_start_hprof;
            Z_LVAL_P(zend_hash_str_find(Z_ARRVAL_P(counts), "pmu", 3)) += zend_memory_peak_usage(0) - top->pmu_start_hprof;
        }
    } else {
        add_assoc_long_ex(counts, "ct", 2, 1);
        add_assoc_long_ex(counts, "wt", 2, cycle_timer() - top->timer_start);

        if (hp_globals.xhprof_flags & XHPROF_FLAGS_CPU) {
            getrusage(RUSAGE_SELF, &ru_end);

            add_assoc_long_ex(counts, "cpu", 3,
                get_us_interval(&(top->ru_start_hprof.ru_utime), &(ru_end.ru_utime)) +
                get_us_interval(&(top->ru_start_hprof.ru_stime), &(ru_end.ru_stime)));
        }

        if (hp_globals.xhprof_flags & XHPROF_FLAGS_MEMORY) {
            add_assoc_long_ex(counts, "mu", 2, zend_memory_usage(0) - top->mu_start_hprof);
            add_assoc_long_ex(counts, "pmu", 3, zend_memory_peak_usage(0) - top->pmu_start_hprof);
        }
    }

    smart_str_free(&symbol);
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
    int hp_profile_flag = 1;

    zend_class_entry *called_scope;
    called_scope = zend_get_called_scope(execute_data);

    func = execute_data->func->common.function_name;
    /* check if was in a class */
    if (called_scope != NULL && func != NULL) {
        zend_string *func_name = func;

        int class_name_len = ZSTR_LEN(called_scope->name);
        func = zend_string_init(ZSTR_VAL(called_scope->name), class_name_len + 2 + ZSTR_LEN(func_name), 0);
        memcpy(ZSTR_VAL(func) + class_name_len, "::", 2);
        memcpy(ZSTR_VAL(func) + class_name_len + 2, ZSTR_VAL(func_name), ZSTR_LEN(func_name));
    } else if (func) {
        //just do the copy;
        func = zend_string_init(ZSTR_VAL(func), ZSTR_LEN(func), 0);
    } else if (execute_data->literals->u1.type_info == 4) {

        //could include, not sure others has the same value
        //This is fucking dam ugly
        zend_string *filename = execute_data->func->op_array.filename;

        const int run_init_len = sizeof("run_init::") - 1;
        func = zend_string_init("run_init::", run_init_len + ZSTR_LEN(filename), 0);
        memcpy(ZSTR_VAL(func) + run_init_len, ZSTR_VAL(filename), ZSTR_LEN(filename));
    }

    if (!func || hp_globals.enabled == 0) {
        if (func) zend_string_free(func);
        _zend_execute_ex(execute_data);
        return;
    }

    BEGIN_PROFILING(&hp_globals.entries, func, hp_profile_flag);
    _zend_execute_ex(execute_data);
    if (hp_globals.entries) {
        END_PROFILING(&hp_globals.entries, hp_profile_flag);
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
    int hp_profile_flag = 1;

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
        BEGIN_PROFILING(&hp_globals.entries, func, hp_profile_flag);
    }

    if (!_zend_execute_internal) {
        /* no old override to begin with. so invoke the builtin's implementation */

        execute_data ->func ->internal_function.handler(execute_data, ret);

    } else {
        /* call the old override */
        _zend_execute_internal(execute_data, ret);
    }

    if (func && hp_globals.entries) {
        END_PROFILING(&hp_globals.entries, hp_profile_flag);
    }
}

/**
 * Proxy for zend_compile_file(). Used to profile PHP compilation time.
 */
ZEND_DLEXPORT zend_op_array* hp_compile_file(zend_file_handle *file_handle, int type) {
    const char *filename;
    size_t len;
    zend_op_array *ret;
    int hp_profile_flag = 1;
    zend_string *func_name;

    filename = hp_get_base_filename(file_handle->filename);
    len = sizeof("load::") - 1 + strlen(filename);

    func_name = zend_string_alloc(len, 0);

    ZSTR_LEN(func_name) = snprintf(ZSTR_VAL(func_name), len + 1, "load::%s", filename);

    BEGIN_PROFILING(&hp_globals.entries, func_name, hp_profile_flag);
    ret = _zend_compile_file(file_handle, type);
    if (hp_globals.entries) {
        END_PROFILING(&hp_globals.entries, hp_profile_flag);
    }

    return ret;
}

static void hp_stop() {
    int hp_profile_flag = 1;

    /* End any unfinished calls */
    while (hp_globals.entries) {
        END_PROFILING(&hp_globals.entries, hp_profile_flag);
    }

    /* Stop profiling */
    hp_globals.enabled = 0;
}
