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

static inline int hp_ignore_entry(uint8 hash_code, char *curr_func) {
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
void hp_mode_beginfn_cb(hp_entry_t **entries, hp_entry_t *current) {
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
void hp_mode_common_beginfn(hp_entry_t **entries, hp_entry_t *current) {
    hp_entry_t *p;

    /* This symbol's recursive level */
    int recurse_level = 0;

    if (hp_globals.func_hash_counters[current->hash_code] > 0) {
        /* Find this symbols recurse level */
        for(p = (*entries); p; p = p->prev_hprof) {
            if (!strcmp(current->name_hprof->val, p->name_hprof->val)) {
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
#define BEGIN_PROFILING(entries, symbol, profile_curr)                                  \
    do {                                                                                                                                    \
        /* Use a hash code to filter most of the string comparisons. */         \
        uint8 hash_code = hp_inline_hash(symbol->val);                                          \
        profile_curr = !hp_ignore_entry(hash_code, symbol->val);                        \
        if (profile_curr) {                                                                                                 \
            hp_entry_t *cur_entry = hp_fast_alloc_hprof_entry();                            \
            (cur_entry)->hash_code = hash_code;                                                             \
            (cur_entry)->name_hprof = symbol;                                                                   \
            (cur_entry)->prev_hprof = (*(entries));                                                     \
            /* Call the universal callback */                                                                   \
            hp_mode_common_beginfn((entries), (cur_entry));                                     \
            /* Call the mode's beginfn callback */                                                      \
            hp_mode_beginfn_cb((entries), (cur_entry));                                             \
            /* Update entries linked list */                                                                    \
            (*(entries)) = (cur_entry);                                                                             \
        } else {                                                                                                                        \
            zend_string_free(symbol);                                                                                   \
            symbol = NULL;                                                                                                      \
        }                                                                                                                                       \
    } while (0)

/*
 * Stop profiling - called just after calling the actual function
 */
#define END_PROFILING(entries, profile_curr)                                                        \
    do {                                                                                                                                    \
        if (profile_curr) {                                                                                                 \
            hp_entry_t *cur_entry;                                                                                      \
            /* Call the mode's endfn callback. */                                                           \
            hp_mode_endfn_cb((entries));                                                                            \
            cur_entry = (*(entries));                                                                                   \
            /* Call the universal callback */                                                                   \
            hp_globals.func_hash_counters[(cur_entry)->hash_code]--;                    \
            /* Free top entry and update entries linked list */                             \
            (*(entries)) = (*(entries))->prev_hprof;                                                    \
            hp_fast_free_hprof_entry(cur_entry);                                                            \
        }                                                                                                                                       \
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
                uint8 hash = hp_inline_hash(str);
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
 * A hash function to calculate a 8-bit hash code for a function name.
 * This is based on a small modification to 'zend_inline_hash_func' by summing
 * up all bytes of the ulong returned by 'zend_inline_hash_func'.
 *
 * @param str, char *, string to be calculated hash code for.
 */
static inline uint8 hp_inline_hash(char * str) {
    ulong h = 5381;
    uint i = 0;
    uint8 res = 0;

    while (*str) {
        h += (h << 5);
        h ^= (ulong) *str++;
    }

    for (i = 0; i < sizeof(ulong); i++) {
        res += ((uint8 *)&h)[i];
    }
    return res;
}

/**
 * Returns formatted function name
 *
 * @param entryhp_entry
 * @param result_buf ptr to result buf
 * @param result_len max size of result buf
 * @return total size of the function name returned in result_buf
 */
void hp_get_entry_name(hp_entry_t *entry, smart_str *result) {
    smart_str_appendl(result, ZSTR_VAL(entry->name_hprof), ZSTR_LEN(entry->name_hprof));
    /* Add '@recurse_level' if required */
    if (entry->rlvl_hprof) {
        smart_str_appendc(result, '@');
        smart_str_append_long(result, entry->rlvl_hprof);
    }

    smart_str_0(result);
}

/**
 * Build a caller qualified name for a callee.
 *
 * For example, if A() is caller for B(), then it returns "A==>B".
 * Recursive invokations are denoted with @<n> where n is the recursion
 * depth.
 *
 * For example, "foo==>foo@1", and "foo@2==>foo@3" are examples of direct
 * recursion. And "bar==>foo@1" is an example of an indirect recursive
 * call to foo (implying the foo() is on the call stack some levels
 * above).
 */
void hp_get_function_stack(hp_entry_t *entry, int level, smart_str *result) {
    /* End recursion if we dont need deeper levels or we dont have any deeper
     * levels */
    if (!entry->prev_hprof || (level <= 1)) {
        hp_get_entry_name(entry, result);
        return;
    }

    /* Take care of all ancestors first */
    hp_get_function_stack(entry->prev_hprof, level - 1, result);

    /* Add delimiter only if entry had ancestors */
    if (result->a > 0) {
        smart_str_appendl(result, "==>", sizeof("==>") - 1);
    }

    /* Append the current function name */
    hp_get_entry_name(entry, result);
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
static hp_entry_t *hp_fast_alloc_hprof_entry() {
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
static void hp_fast_free_hprof_entry(hp_entry_t *p) {

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
void hp_inc_count(zval *counts, char *name, size_t len, long count) {
    zval *data;

    if (!counts) return;

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
static inline uint64 cycle_timer() {
    struct timespec s;
    clock_gettime(CLOCK_MONOTONIC, &s);

    return s.tv_sec * 1000000 + s.tv_nsec / 1000;
}

/**
 * Get time delta in microseconds.
 */
static long get_us_interval(struct timeval *start, struct timeval *end) {
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
void hp_mode_endfn_cb(hp_entry_t **entries) {
    hp_entry_t *top = (*entries);
    struct rusage ru_end;
    smart_str symbol = {0};
    long int mu_end;
    long int pmu_end;

    /********/
    zval count_val;
    zval *counts;
    uint64 timer_end;
    HashTable *ht;

    /* Bail if something is goofy */
    if (!hp_globals.stats_count || !(ht = HASH_OF(hp_globals.stats_count))) {
        return;
    }

    /* Get the stat array */
    hp_get_function_stack(top, 2, &symbol);

    timer_end = cycle_timer();

    /* Lookup our hash table */
    if ((counts = zend_hash_str_find(ht, ZSTR_VAL(symbol.s), ZSTR_LEN(symbol.s))) == NULL) {
        /* Add symbol to hash table */
        counts = &count_val;
        array_init(counts);
        add_assoc_zval_ex(hp_globals.stats_count, ZSTR_VAL(symbol.s), ZSTR_LEN(symbol.s), counts);
    }

    /* Bump stats in the counts hashtable */
    hp_inc_count(counts, "ct", 2, 1);
    hp_inc_count(counts, "wt", 2, timer_end - top->timer_start);

    if (hp_globals.xhprof_flags & XHPROF_FLAGS_CPU) {
        /* Get CPU usage */
        getrusage(RUSAGE_SELF, &ru_end);

        /* Bump CPU stats in the counts hashtable */
        hp_inc_count(counts, "cpu", 3,
            (
                get_us_interval(&(top->ru_start_hprof.ru_utime), &(ru_end.ru_utime)) +
                get_us_interval(&(top->ru_start_hprof.ru_stime), &(ru_end.ru_stime))
            )
        );
    }

    if (hp_globals.xhprof_flags & XHPROF_FLAGS_MEMORY) {
        /* Get Memory usage */
        mu_end = zend_memory_usage(0);
        pmu_end = zend_memory_peak_usage(0);

        /* Bump Memory stats in the counts hashtable */

        hp_inc_count(counts, "mu", 2, mu_end - top->mu_start_hprof);
        hp_inc_count(counts, "pmu", 3, pmu_end - top->pmu_start_hprof);
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
        //this is a class method;
        zend_string *class_name = called_scope->name;
        zend_string *func_name = func;

        int class_name_len = class_name->len;
        func = zend_string_init(class_name->val, class_name_len + 2 + func_name->len, 0);
        memcpy(func->val + class_name_len, "::", 2);
        memcpy(func->val + class_name_len + 2, func_name->val, func_name->len);
    } else if (func) {
        //just do the copy;
        func = zend_string_init(func->val, func->len, 0);
    } else if (execute_data->literals->u1.type_info == 4) {

        //could include, not sure others has the same value
        //This is fucking dam ugly
        zend_string *filename = execute_data->func->op_array.filename;

        int run_init_len = sizeof("run_init::") - 1;
        func = zend_string_init("run_init::", run_init_len + filename->len, 0);
        memcpy(func->val + run_init_len, filename->val, filename->len);
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
        zend_string *class_name = execute_data->func->op_array.scope->name;
        zend_string *func_name = func;

        int class_name_len = class_name->len;
        func = zend_string_init(class_name->val, class_name_len + 2 + func_name->len, 0);
        memcpy(func->val + class_name_len, "::", 2);
        memcpy(func->val + class_name_len + 2, func_name->val, func_name->len);
    } else if (func) {
        //just do the copy;
        func = zend_string_init(func->val, func->len, 0);
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
