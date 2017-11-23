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

#include "zend_compile.h"

#include <sys/time.h>
#include <sys/resource.h>
#include <stdlib.h>
#include <unistd.h>


/**
 * **********************
 * GLOBAL MACRO CONSTANTS
 * **********************
 */

/* XHProf version                           */
#define XHPROF_VERSION       "0.9.2"

/* Fictitious function name to represent top of the call tree. The paranthesis
 * in the name is to ensure we don't conflict with user function names.  */
#define ROOT_SYMBOL                "main()"

/* Size of a temp scratch buffer            */
#define SCRATCH_BUF_LEN            512

/* Profiling flags.
 *
 * Note: Function call counts and wall (elapsed) time are always profiled.
 * The following optional flags can be used to control other aspects of
 * profiling.
 */
#define XHPROF_FLAGS_NO_BUILTINS   0x0001         /* do not profile builtins */
#define XHPROF_FLAGS_CPU           0x0002      /* gather CPU times for funcs */
#define XHPROF_FLAGS_MEMORY        0x0004   /* gather memory usage for funcs */

/* Constant for ignoring functions, transparent to hierarchical profile */
#define XHPROF_MAX_IGNORED_FUNCTIONS  256
#define XHPROF_IGNORED_FUNCTION_FILTER_SIZE                           \
               ((XHPROF_MAX_IGNORED_FUNCTIONS + 7)/8)

#if !defined(uint64)
typedef unsigned long long uint64;
#endif
#if !defined(uint32)
typedef unsigned int uint32;
#endif
#if !defined(uint8)
typedef unsigned char uint8;
#endif


/**
 * *****************************
 * GLOBAL DATATYPES AND TYPEDEFS
 * *****************************
 */

/* XHProf maintains a stack of entries being profiled. The memory for the entry
 * is passed by the layer that invokes BEGIN_PROFILING(), e.g. the hp_execute()
 * function. Often, this is just C-stack memory.
 *
 * This structure is a convenient place to track start time of a particular
 * profile operation, recursion depth, and the name of the function being
 * profiled. */
typedef struct hp_entry_t {
  zend_string             *name_hprof;                       /* function name */
  int                     rlvl_hprof;        /* recursion level for function */
  uint64                  timer_start;              /* start value for timer */
  long int                mu_start_hprof;                    /* memory usage */
  long int                pmu_start_hprof;              /* peak memory usage */
  struct rusage           ru_start_hprof;             /* user/sys time start */
  struct hp_entry_t      *prev_hprof;    /* ptr to prev entry being profiled */
  uint8                   hash_code;     /* hash_code for the function name  */
} hp_entry_t;

/* Xhprof's global state.
 *
 * This structure is instantiated once.  Initialize defaults for attributes in
 * hp_init_profiler_state() Cleanup/free attributes in
 * hp_clean_profiler_state() */
typedef struct hp_global_t {

  /*       ----------   Global attributes:  -----------       */

  /* Indicates if xhprof is currently enabled */
  int              enabled;

  /* Indicates if xhprof was ever enabled during this request */
  int              ever_enabled;

  /* Holds all the xhprof statistics */
  zval            *stats_count;

  /* Top of the profile stack */
  hp_entry_t      *entries;

  /* freelist of hp_entry_t chunks for reuse... */
  hp_entry_t      *entry_free_list;

  /*       ----------   Mode specific attributes:  -----------       */

  /* XHProf flags */
  uint32 xhprof_flags;

  /* counter table indexed by hash value of function names. */
  uint8  func_hash_counters[256];

  /* Table of ignored function names and their filter */
  char  **ignored_function_names;
  uint8   ignored_function_filter[XHPROF_IGNORED_FUNCTION_FILTER_SIZE];

} hp_global_t;


/**
 * ***********************
 * GLOBAL STATIC VARIABLES
 * ***********************
 */
/* XHProf global state */
static hp_global_t       hp_globals;


/* Pointer to the original compile function */
static zend_op_array * (*_zend_compile_file) (zend_file_handle *file_handle, int type);

/* Bloom filter for function names to be ignored */
#define INDEX_2_BYTE(index)  (index >> 3)
#define INDEX_2_BIT(index)   (1 << (index & 0x7));

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

ZEND_DLEXPORT void hp_execute_ex (zend_execute_data *execute_data);

ZEND_DLEXPORT zend_op_array* hp_compile_file(zend_file_handle *file_handle, int type);
/**
 * ****************************
 * STATIC FUNCTION DECLARATIONS
 * ****************************
 */
static void hp_register_constants(INIT_FUNC_ARGS);

static void hp_begin(long xhprof_flags);
static void hp_stop();
static void hp_end();

static inline uint64 cycle_timer();

static void hp_free_the_free_list();
static hp_entry_t *hp_fast_alloc_hprof_entry();
static void hp_fast_free_hprof_entry(hp_entry_t *p);
static inline uint8 hp_inline_hash(char * str);
static long get_us_interval(struct timeval *start, struct timeval *end);

static void hp_ignored_functions_filter_init();

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
  "xhprof",                        /* Name of the extension */
  xhprof_functions,                /* List of functions exposed */
  PHP_MINIT(xhprof),               /* Module init callback */
  PHP_MSHUTDOWN(xhprof),           /* Module shutdown callback */
  PHP_RINIT(xhprof),               /* Request init callback */
  PHP_RSHUTDOWN(xhprof),           /* Request shutdown callback */
  PHP_MINFO(xhprof),               /* Module info callback */
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


/**
 * **********************************
 * PHP EXTENSION FUNCTION DEFINITIONS
 * **********************************
 */

/**
 * Start XHProf profiling
 *
 * @param  long $flags  flags
 * @return void
 * @author kannan
 */
PHP_FUNCTION(xhprof_enable) {
  long  xhprof_flags = 0;                                    /* XHProf flags */
  zval *optional_array = NULL;         /* optional array arg: for future use */

  if (zend_parse_parameters(ZEND_NUM_ARGS(), "|lz", &xhprof_flags, &optional_array) == FAILURE) {
    return;
  }

  hp_begin(xhprof_flags);
}

/**
 * Stops XHProf from profiling anymore and returns the profile info.
 *
 * @param  void
 * @return array  hash-array of XHProf's profile info
 * @author kannan, hzhao
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
 *
 * @author cjiang
 */
PHP_MINIT_FUNCTION(xhprof) {
  int i;

  REGISTER_INI_ENTRIES();

  hp_register_constants(INIT_FUNC_ARGS_PASSTHRU);

  hp_globals.stats_count = NULL;

  /* no free hp_entry_t structures to start with */
  hp_globals.entry_free_list = NULL;

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
  /* free any remaining items in the free list */
  hp_free_the_free_list();

  UNREGISTER_INI_ENTRIES();

  return SUCCESS;
}

/**
 * Request init callback. Nothing to do yet!
 */
PHP_RINIT_FUNCTION(xhprof) {
 
  _zend_compile_file = zend_compile_file;
  zend_compile_file  = hp_compile_file;

  /* Replace zend_execute with our proxy */
  _zend_execute_ex = zend_execute_ex;
  zend_execute_ex  = hp_execute_ex;

  /* Replace zend_execute_internal with our proxy */
  _zend_execute_internal = zend_execute_internal;
  zend_execute_internal = hp_execute_internal;
  
  return SUCCESS;
}

/**
 * Request shutdown callback. Stop profiling and return.
 */
PHP_RSHUTDOWN_FUNCTION(xhprof) {
  hp_end();
  zend_execute_ex       = _zend_execute_ex;
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
  REGISTER_LONG_CONSTANT("XHPROF_FLAGS_NO_BUILTINS",
                         XHPROF_FLAGS_NO_BUILTINS,
                         CONST_CS | CONST_PERSISTENT);

  REGISTER_LONG_CONSTANT("XHPROF_FLAGS_CPU",
                         XHPROF_FLAGS_CPU,
                         CONST_CS | CONST_PERSISTENT);

  REGISTER_LONG_CONSTANT("XHPROF_FLAGS_MEMORY",
                         XHPROF_FLAGS_MEMORY,
                         CONST_CS | CONST_PERSISTENT);
}

/**
 * A hash function to calculate a 8-bit hash code for a function name.
 * This is based on a small modification to 'zend_inline_hash_func' by summing
 * up all bytes of the ulong returned by 'zend_inline_hash_func'.
 *
 * @param str, char *, string to be calculated hash code for.
 *
 * @author cjiang
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
 * Initialize filter for ignored functions using bit vector.
 *
 * @author mpal
 */
static void hp_ignored_functions_filter_init() {
  if (hp_globals.ignored_function_names != NULL) {
    int i = 0;
    for(; hp_globals.ignored_function_names[i] != NULL; i++) {
      char *str  = hp_globals.ignored_function_names[i];
      uint8 hash = hp_inline_hash(str);
      int   idx  = INDEX_2_BYTE(hash);
      hp_globals.ignored_function_filter[idx] |= INDEX_2_BIT(hash);
    }
  }
}

/**
 * Check if function collides in filter of functions to be ignored.
 *
 * @author mpal
 */
int hp_ignored_functions_filter_collision(uint8 hash) {
  uint8 mask = INDEX_2_BIT(hash);
  return hp_globals.ignored_function_filter[INDEX_2_BYTE(hash)] & mask;
}

/**
 * Initialize profiler state
 *
 * @author kannan, veeve
 */
void hp_init_profiler_state() {
  /* Setup globals */
  if (!hp_globals.ever_enabled) {
    hp_globals.ever_enabled  = 1;
    hp_globals.entries = NULL;
  }

  /* Init stats_count */
  if (hp_globals.stats_count) {
    efree(hp_globals.stats_count);
  }
  
  hp_globals.stats_count = (zval *)emalloc(sizeof(zval));
  array_init(hp_globals.stats_count);

  /* Set up filter of functions which may be ignored during profiling */
  hp_ignored_functions_filter_init();
}

/**
 * Cleanup profiler state
 *
 * @author kannan, veeve
 */
void hp_clean_profiler_state() {
  /* Clear globals */
  if (hp_globals.stats_count) {
	zval_ptr_dtor(hp_globals.stats_count);
    efree(hp_globals.stats_count);
    hp_globals.stats_count = NULL;
  }
  hp_globals.entries = NULL;
  hp_globals.ever_enabled = 0;

  hp_globals.ignored_function_names = NULL;
}

/*
 * Start profiling - called just before calling the actual function
 */
#define BEGIN_PROFILING(entries, symbol, profile_curr)                  \
  do {                                                                  \
    /* Use a hash code to filter most of the string comparisons. */     \
    uint8 hash_code  = hp_inline_hash(symbol->val);                     \
    profile_curr = !hp_ignore_entry(hash_code, symbol->val);            \
    if (profile_curr) {                                                 \
      hp_entry_t *cur_entry = hp_fast_alloc_hprof_entry();              \
      (cur_entry)->hash_code = hash_code;                               \
      (cur_entry)->name_hprof = symbol;                                 \
      (cur_entry)->prev_hprof = (*(entries));                           \
      /* Call the universal callback */                                 \
      hp_mode_common_beginfn((entries), (cur_entry));                   \
      /* Call the mode's beginfn callback */                            \
      hp_mode_beginfn_cb((entries), (cur_entry));                       \
      /* Update entries linked list */                                  \
      (*(entries)) = (cur_entry);                                       \
    }                                                                   \
  } while (0)

/*
 * Stop profiling - called just after calling the actual function
 */
#define END_PROFILING(entries, profile_curr)                            \
  do {                                                                  \
    if (profile_curr) {                                                 \
      hp_entry_t *cur_entry;                                            \
      /* Call the mode's endfn callback. */                             \
      /* NOTE(cjiang): we want to call this 'endfn_cb' before */        \
      /* 'hp_mode_common_endfn' to avoid including the time in */       \
      /* 'hp_mode_common_endfn' in the profiling results.      */       \
      hp_mode_endfn_cb((entries));                                      \
      cur_entry = (*(entries));                                         \
      /* Call the universal callback */                                 \
      hp_mode_common_endfn((entries), (cur_entry));                     \
      /* Free top entry and update entries linked list */               \
      (*(entries)) = (*(entries))->prev_hprof;                          \
      hp_fast_free_hprof_entry(cur_entry);                              \
    }                                                                   \
  } while (0)


/**
 * Returns formatted function name
 *
 * @param  entry        hp_entry
 * @param  result_buf   ptr to result buf
 * @param  result_len   max size of result buf
 * @return total size of the function name returned in result_buf
 * @author veeve
 */
size_t hp_get_entry_name(hp_entry_t  *entry,
                         /*char           *result_buf,
                         size_t          result_len*/
                        zend_string *result
                        ) {

  /* Validate result_len */
  if (result->len <= 1) {
    /* Insufficient result_bug. Bail! */
    return 0;
  }

  /* Add '@recurse_level' if required */
  /* NOTE:  Dont use snprintf's return val as it is compiler dependent */
  if (entry->rlvl_hprof) {
    snprintf(result->val+strlen(result->val), result->len,
             "%s@%d",
             entry->name_hprof->val, entry->rlvl_hprof);
  }
  else {
    snprintf(result->val + strlen(result->val), result->len,
             "%s",
             entry->name_hprof->val);
  }

  /* Force null-termination at MAX */
  result->val[result->len - 1] = 0;
  return strlen(result->val);
}

/**
 * Check if this entry should be ignored, first with a conservative Bloomish
 * filter then with an exact check against the function names.
 *
 * @author mpal
 */
int  hp_ignore_entry_work(uint8 hash_code, char *curr_func) {
  int ignore = 0;
  if (hp_ignored_functions_filter_collision(hash_code)) {
    int i = 0;
    for (; hp_globals.ignored_function_names[i] != NULL; i++) {
      char *name = hp_globals.ignored_function_names[i];
      if ( !strcmp(curr_func, name)) {
        ignore++;
        break;
      }
    }
  }

  return ignore;
}

static inline int  hp_ignore_entry(uint8 hash_code, char *curr_func) {
  /* First check if ignoring functions is enabled */
  return hp_globals.ignored_function_names != NULL &&
         hp_ignore_entry_work(hash_code, curr_func);
}

/**
 * Build a caller qualified name for a callee.
 *
 * For example, if A() is caller for B(), then it returns "A==>B".
 * Recursive invokations are denoted with @<n> where n is the recursion
 * depth.
 *
 * For example, "foo==>foo@1", and "foo@2==>foo@3" are examples of direct
 * recursion. And  "bar==>foo@1" is an example of an indirect recursive
 * call to foo (implying the foo() is on the call stack some levels
 * above).
 *
 * @author kannan, veeve
 */
size_t hp_get_function_stack(hp_entry_t *entry,
                             int            level,
                             zend_string *result
                             ) {
  size_t         len = 0;

  /* End recursion if we dont need deeper levels or we dont have any deeper
   * levels */
  if (!entry->prev_hprof || (level <= 1)) {
    return hp_get_entry_name(entry, result);
  }

  /* Take care of all ancestors first */
  len = hp_get_function_stack(entry->prev_hprof,
                              level - 1,
                              result
                              );

  /* Append the delimiter */
# define    HP_STACK_DELIM        "==>"
# define    HP_STACK_DELIM_LEN    (sizeof(HP_STACK_DELIM) - 1)

  if (result->len < (len + HP_STACK_DELIM_LEN)) {
    /* Insufficient result_buf. Bail out! */
    return len;
  }

  /* Add delimiter only if entry had ancestors */
  if (len) {
    strncat(result->val + len,
            HP_STACK_DELIM,
            result->len - len);
    len += HP_STACK_DELIM_LEN;
  }

# undef     HP_STACK_DELIM_LEN
# undef     HP_STACK_DELIM

  /* Append the current function name */
  return len + hp_get_entry_name(entry, result);
}

/**
 * Takes an input of the form /a/b/c/d/foo.php and returns
 * a pointer to one-level directory and basefile name
 * (d/foo.php) in the same string.
 */
static const char *hp_get_base_filename(const char *filename) {
  const char *ptr;
  int   found = 0;

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
static void hp_free_the_free_list() {
  hp_entry_t *p = hp_globals.entry_free_list;
  hp_entry_t *cur;

  while (p) {
    cur = p;
    p = p->prev_hprof;
    free(cur);
  }
}

/**
 * Fast allocate a hp_entry_t structure. Picks one from the
 * free list if available, else does an actual allocate.
 *
 * Doesn't bother initializing allocated memory.
 *
 * @author kannan
 */
static hp_entry_t *hp_fast_alloc_hprof_entry() {
  hp_entry_t *p;

  p = hp_globals.entry_free_list;

  if (p) {
    hp_globals.entry_free_list = p->prev_hprof;
    return p;
  } else {
    hp_entry_t *tmp = malloc(sizeof(hp_entry_t));
    return tmp;
  }
}

/**
 * Fast free a hp_entry_t structure. Simply returns back
 * the hp_entry_t to a free list and doesn't actually
 * perform the free.
 *
 * @author kannan
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
 * @param  zval *counts   Zend hash table pointer
 * @param  char *name     Name of the stat
 * @param  long  count    Value of the stat to incr by
 * @return void
 * @author kannan
 */
void hp_inc_count(zval *counts, zend_string *name, long count) {
  HashTable *ht;
  zval *data;

  if (!counts) return;
  ht = HASH_OF(counts);
  if (!ht) return;

  if ((data = zend_hash_find(ht, name)) != NULL) {
    ZVAL_LONG(data, Z_LVAL_P(data) + count);
  } else {
    add_assoc_long(counts, name->val, count);
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
  return (((end->tv_sec - start->tv_sec) * 1000000)
          + (end->tv_usec - start->tv_usec));
}

/**
 * ****************************
 * XHPROF COMMON CALLBACKS
 * ****************************
 */
/**
 * XHPROF universal begin function.
 * This function is called for all modes before the
 * mode's specific begin_function callback is called.
 *
 * @param  hp_entry_t **entries  linked list (stack)
 *                                  of hprof entries
 * @param  hp_entry_t  *current  hprof entry for the current fn
 * @return void
 * @author kannan, veeve
 */
void hp_mode_common_beginfn(hp_entry_t **entries, hp_entry_t  *current) {
  hp_entry_t   *p;

  /* This symbol's recursive level */
  int    recurse_level = 0;

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

/**
 * XHPROF universal end function.  This function is called for all modes after
 * the mode's specific end_function callback is called.
 *
 * @param  hp_entry_t **entries  linked list (stack) of hprof entries
 * @return void
 * @author kannan, veeve
 */
void hp_mode_common_endfn(hp_entry_t **entries, hp_entry_t *current) {
  hp_globals.func_hash_counters[current->hash_code]--;
}


/**
 * ************************************
 * XHPROF BEGIN FUNCTION CALLBACKS
 * ************************************
 */

/**
 * begin function callback
 *
 * @author kannan
 */
void hp_mode_beginfn_cb(hp_entry_t **entries, hp_entry_t  *current) {
  current->timer_start = cycle_timer();

  /* Get CPU usage */
  if (hp_globals.xhprof_flags & XHPROF_FLAGS_CPU) {
    getrusage(RUSAGE_SELF, &(current->ru_start_hprof));
  }

  /* Get memory usage */
  if (hp_globals.xhprof_flags & XHPROF_FLAGS_MEMORY) {
    current->mu_start_hprof  = zend_memory_usage(0);
    current->pmu_start_hprof = zend_memory_peak_usage(0);
  }
}

/**
 * **********************************
 * XHPROF END FUNCTION CALLBACKS
 * **********************************
 */

/**
 * end function callback
 *
 * @author kannan
 */
void hp_mode_endfn_cb(hp_entry_t **entries) {
  hp_entry_t   *top = (*entries);
  struct rusage    ru_end;
  zend_string      *symbol;
  long int         mu_end;
  long int         pmu_end;

  /********/
  zval counts;
  zval *countsp;
  uint64 timer_end;
  HashTable *ht;

  /* Get the stat array */
  symbol = zend_string_alloc(SCRATCH_BUF_LEN, 0);
  ZSTR_VAL(symbol)[0] = '\000';
  hp_get_function_stack(top, 2, symbol);

  timer_end = cycle_timer();

  /* Get the stat array */
  /* Bail if something is goofy */
  if (!hp_globals.stats_count || !(ht = HASH_OF(hp_globals.stats_count))) {
    efree(symbol);
    return;
  }

  /* Lookup our hash table */
  if ((countsp = zend_hash_str_find(ht, symbol->val, strlen(symbol->val))) == NULL) {
    /* Add symbol to hash table */
    countsp = &counts;
    array_init(countsp);
    add_assoc_zval(hp_globals.stats_count, symbol->val, countsp);
  }

  /* Bump stats in the counts hashtable */
  hp_inc_count(countsp, zend_string_init("ct", sizeof("ct") - 1, 1), 1);

  hp_inc_count(countsp, zend_string_init("wt", sizeof("wt") - 1, 1), timer_end - top->timer_start);

  if (hp_globals.xhprof_flags & XHPROF_FLAGS_CPU) {
    /* Get CPU usage */
    getrusage(RUSAGE_SELF, &ru_end);

    /* Bump CPU stats in the counts hashtable */
    hp_inc_count(countsp, zend_string_init("cpu", sizeof("cpu") - 1, 1), (get_us_interval(&(top->ru_start_hprof.ru_utime),
                                              &(ru_end.ru_utime)) +
                              get_us_interval(&(top->ru_start_hprof.ru_stime),
                                              &(ru_end.ru_stime))));
  }

  if (hp_globals.xhprof_flags & XHPROF_FLAGS_MEMORY) {
    /* Get Memory usage */
    mu_end  = zend_memory_usage(0);
    pmu_end = zend_memory_peak_usage(0);

    /* Bump Memory stats in the counts hashtable */

    hp_inc_count(countsp, zend_string_init("mu", sizeof("mu") - 1, 1),  mu_end - top->mu_start_hprof);
    hp_inc_count(countsp, zend_string_init("pmu", sizeof("pmu") - 1, 1), pmu_end - top->pmu_start_hprof);
  }

  zend_string_free(symbol);
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
 *
 * @author hzhao, kannan, Jason
 */
ZEND_DLEXPORT void hp_execute_ex (zend_execute_data *execute_data) {
  zend_string   *func = NULL;
  int hp_profile_flag = 1;
  
  zend_class_entry *called_scope;
  called_scope = zend_get_called_scope(execute_data);

  func = execute_data->func->internal_function.function_name;
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
  if (func) {
  
  	zend_string_free(func);
  }
}

#undef EX
#define EX(element) ((execute_data)->element)

/**
 * Very similar to hp_execute. Proxy for zend_execute_internal().
 * Applies to zend builtin functions.
 *
 * @author hzhao, kannan, Jason
 */

ZEND_DLEXPORT void hp_execute_internal(zend_execute_data *execute_data, zval *ret) {
  zend_execute_data *current_data;
  zend_string   *func = NULL;
  int    hp_profile_flag = 1;

  current_data = EG(current_execute_data);
  func = current_data->func->op_array.function_name ;

  //check is a class method
  if(current_data->func->op_array.scope != NULL) {
	  zend_string *class_name = current_data->func->op_array.scope->name;
	  zend_string *func_name = func;

	  int class_name_len = class_name->len;
	  func = zend_string_init(class_name->val, class_name_len + 2 + func_name->len, 0); 
	  memcpy(func->val + class_name_len, "::", 2);
	  memcpy(func->val + class_name_len + 2, func_name->val, func_name->len);
  } else if (func) {
	  //just do the copy;
	  func = zend_string_init(func->val, func->len, 0);
  }

  if (func && strcmp("xhprof_enable", func->val) != 0) {
    if (hp_globals.enabled == 1) {
      BEGIN_PROFILING(&hp_globals.entries, func, hp_profile_flag);
    }
  }

  if (!_zend_execute_internal) {
    /* no old override to begin with. so invoke the builtin's implementation  */

    execute_data ->func ->internal_function.handler(execute_data, ret);
  
  } else {
    /* call the old override */
    _zend_execute_internal(execute_data, ret);
  }

  if (func && strcmp("xhprof_enable", func->val) != 0) {
    if (hp_globals.entries) {
      END_PROFILING(&hp_globals.entries, hp_profile_flag);
    }
  }

  if (func) {
	  zend_string_free(func);
  }

}

/**
 * Proxy for zend_compile_file(). Used to profile PHP compilation time.
 *
 * @author kannan, hzhao
 */
ZEND_DLEXPORT zend_op_array* hp_compile_file(zend_file_handle *file_handle, int type) {
  const char     *filename;
  int             len;
  zend_op_array  *ret;
  int             hp_profile_flag = 1;
  zend_string	 *func_name;

  filename = hp_get_base_filename(file_handle->filename);
  len      = strlen("load::") + strlen(filename);

  func_name = zend_string_init(filename, len, 0); 
 
  snprintf(func_name->val, len + 1, "load::%s", filename);

  BEGIN_PROFILING(&hp_globals.entries, func_name, hp_profile_flag);
  ret = _zend_compile_file(file_handle, type);
  if (hp_globals.entries) {
    END_PROFILING(&hp_globals.entries, hp_profile_flag);
  }

  zend_string_free(func_name);
  return ret;
}

/**
 * **************************
 * MAIN XHPROF CALLBACKS
 * **************************
 */

/**
 * This function gets called once when xhprof gets enabled.
 * It replaces all the functions like zend_execute, zend_execute_internal,
 * etc that needs to be instrumented with their corresponding proxies.
 */
static void hp_begin(long xhprof_flags) {
  if (!hp_globals.enabled) {
    int hp_profile_flag = 1;

    hp_globals.enabled      = 1;
    hp_globals.xhprof_flags = (uint32)xhprof_flags;
    hp_init_profiler_state();
    
    BEGIN_PROFILING(&hp_globals.entries, zend_string_init(ROOT_SYMBOL, sizeof(ROOT_SYMBOL) - 1, 1), hp_profile_flag);
  }
}

/**
 * Called at request shutdown time. Cleans the profiler's global state.
 */
static void hp_end() {
  /* Bail if not ever enabled */
  if (!hp_globals.ever_enabled) {
    return;
  }

  /* Stop profiler if enabled */
  if (hp_globals.enabled) {
    hp_stop();
  }

  /* Clean up state */
  hp_clean_profiler_state();
}

/**
 * Called from xhprof_disable(). Removes all the proxies setup by
 * hp_begin() and restores the original values.
 */
static void hp_stop() {
  int   hp_profile_flag = 1;

  /* End any unfinished calls */
  while (hp_globals.entries) {
    END_PROFILING(&hp_globals.entries, hp_profile_flag);
  }
    
  /* Stop profiling */
  hp_globals.enabled = 0;
}
