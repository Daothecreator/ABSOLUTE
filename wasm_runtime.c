/*
 * WebAssembly Runtime Core
 * Isolated execution environment for STLC policy engine
 * 
 * License: MIT
 * Version: 1.0 (April 2026)
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <stdbool.h>
#include <wasmtime.h>
#include "../core/stlc_policy_engine.h"

/* === WebAssembly Module Structure === */

/* Wasm value types */
typedef enum {
    WASM_I32 = 0x7f,
    WASM_I64 = 0x7e,
    WASM_F32 = 0x7d,
    WASM_F64 = 0x7c,
    WASM_V128 = 0x7b,
    WASM_FUNCREF = 0x70,
    WASM_EXTERNREF = 0x6f
} wasm_valtype_t;

/* Wasm runtime context */
typedef struct wasm_runtime_s {
    wasm_engine_t *engine;
    wasm_store_t *store;
    wasm_module_t *module;
    wasm_instance_t *instance;
    wasm_memory_t *memory;
    
    /* STLC context */
    context_t *policy_context;
    ontology_t *ontology;
    
    /* Callbacks to host */
    void (*on_violation)(policy_decision_t *decision);
    void (*on_alert)(const char *message);
} wasm_runtime_t;

/* === Host Functions (imported to Wasm) === */

/* Host function: Log message */
static wasm_trap_t* host_log(void *env, 
                              const wasm_val_vec_t *args,
                              wasm_val_vec_t *results) {
    (void)env;
    (void)results;
    
    int32_t ptr = args->data[0].of.i32;
    int32_t len = args->data[1].of.i32;
    
    wasm_runtime_t *runtime = (wasm_runtime_t*)env;
    if (runtime && runtime->memory) {
        char *msg = (char*)wasm_memory_data(runtime->memory) + ptr;
        printf("[WASM] %.*s\n", len, msg);
    }
    
    return NULL;
}

/* Host function: Check policy */
static wasm_trap_t* host_check_policy(void *env,
                                       const wasm_val_vec_t *args,
                                       wasm_val_vec_t *results) {
    wasm_runtime_t *runtime = (wasm_runtime_t*)env;
    if (!runtime) return NULL;
    
    /* Arguments from Wasm */
    int32_t subject_pid = args->data[0].of.i32;
    int32_t object_type = args->data[1].of.i32;
    int32_t operation = args->data[2].of.i32;
    
    /* Find entities in ontology */
    entity_t *subject = ontology_find_by_pid(runtime->ontology, subject_pid);
    entity_t *object = ontology_add_entity(runtime->ontology, "resource", 
                                            object_type, 0);
    
    if (subject && object) {
        policy_decision_t *decision = policy_check_access(
            runtime->policy_context, subject, object, operation);
        
        /* Return result to Wasm */
        results->data[0].of.i32 = decision->allowed ? 1 : 0;
        
        /* Trigger violation callback if denied */
        if (!decision->allowed && runtime->on_violation) {
            runtime->on_violation(decision);
        }
        
        free(decision);
    } else {
        results->data[0].of.i32 = 0; /* Deny if entities not found */
    }
    
    return NULL;
}

/* Host function: Block process */
static wasm_trap_t* host_block_process(void *env,
                                        const wasm_val_vec_t *args,
                                        wasm_val_vec_t *results) {
    (void)results;
    
    wasm_runtime_t *runtime = (wasm_runtime_t*)env;
    int32_t pid = args->data[0].of.i32;
    int32_t reason_ptr = args->data[1].of.i32;
    int32_t reason_len = args->data[2].of.i32;
    
    if (runtime && runtime->memory) {
        char *reason = (char*)wasm_memory_data(runtime->memory) + reason_ptr;
        char reason_str[256];
        snprintf(reason_str, sizeof(reason_str), "%.*s", reason_len, reason);
        
        printf("[WASM] Blocking process %d: %s\n", pid, reason_str);
        
        /* Call to enforcement layer */
        policy_block_process(pid, reason_str);
    }
    
    return NULL;
}

/* === Runtime Lifecycle === */

wasm_runtime_t* wasm_runtime_create(void) {
    wasm_runtime_t *runtime = calloc(1, sizeof(wasm_runtime_t));
    if (!runtime) return NULL;
    
    /* Initialize Wasmtime */
    wasm_config_t *config = wasm_config_new();
    wasm_config_wasm_multi_value_set(config, true);
    wasm_config_wasm_simd_set(config, false);
    wasm_config_wasm_threads_set(config, false);
    
    runtime->engine = wasm_engine_new_with_config(config);
    if (!runtime->engine) {
        free(runtime);
        return NULL;
    }
    
    runtime->store = wasm_store_new(runtime->engine);
    if (!runtime->store) {
        wasm_engine_delete(runtime->engine);
        free(runtime);
        return NULL;
    }
    
    /* Initialize STLC context */
    runtime->policy_context = context_create();
    runtime->ontology = ontology_create();
    
    return runtime;
}

void wasm_runtime_destroy(wasm_runtime_t *runtime) {
    if (!runtime) return;
    
    if (runtime->instance) wasm_instance_delete(runtime->instance);
    if (runtime->module) wasm_module_delete(runtime->module);
    if (runtime->store) wasm_store_delete(runtime->store);
    if (runtime->engine) wasm_engine_delete(runtime->engine);
    
    context_free(runtime->policy_context);
    ontology_free(runtime->ontology);
    
    free(runtime);
}

/* === Module Loading === */

int wasm_runtime_load_module(wasm_runtime_t *runtime, 
                              const uint8_t *wasm_bytes,
                              size_t wasm_size) {
    if (!runtime || !wasm_bytes) return -1;
    
    wasm_byte_vec_t binary;
    wasm_byte_vec_new_uninitialized(&binary, wasm_size);
    memcpy(binary.data, wasm_bytes, wasm_size);
    
    runtime->module = wasm_module_new(runtime->store, &binary);
    wasm_byte_vec_delete(&binary);
    
    if (!runtime->module) {
        fprintf(stderr, "Failed to compile Wasm module\n");
        return -1;
    }
    
    /* Create host function imports */
    wasm_functype_t *log_type = wasm_functype_new_2_0(
        wasm_valtype_new_i32(), wasm_valtype_new_i32()
    );
    wasm_func_t *log_func = wasm_func_new(runtime->store, log_type, host_log);
    wasm_functype_delete(log_type);
    
    wasm_functype_t *policy_type = wasm_functype_new_3_1(
        wasm_valtype_new_i32(), wasm_valtype_new_i32(), wasm_valtype_new_i32(),
        wasm_valtype_new_i32()
    );
    wasm_func_t *policy_func = wasm_func_new(runtime->store, policy_type, host_check_policy);
    wasm_functype_delete(policy_type);
    
    wasm_functype_t *block_type = wasm_functype_new_3_0(
        wasm_valtype_new_i32(), wasm_valtype_new_i32(), wasm_valtype_new_i32()
    );
    wasm_func_t *block_func = wasm_func_new(runtime->store, block_type, host_block_process);
    wasm_functype_delete(block_type);
    
    /* Create import array */
    wasm_extern_t *imports[3] = {
        wasm_func_as_extern(log_func),
        wasm_func_as_extern(policy_func),
        wasm_func_as_extern(block_func)
    };
    
    /* Instantiate module */
    wasm_extern_vec_t import_vec = {3, imports};
    runtime->instance = wasm_instance_new(runtime->store, runtime->module, 
                                          &import_vec, NULL);
    
    wasm_func_delete(log_func);
    wasm_func_delete(policy_func);
    wasm_func_delete(block_func);
    
    if (!runtime->instance) {
        fprintf(stderr, "Failed to instantiate Wasm module\n");
        return -1;
    }
    
    /* Get memory export */
    wasm_extern_vec_t exports;
    wasm_instance_exports(runtime->instance, &exports);
    
    for (size_t i = 0; i < exports.size; i++) {
        wasm_extern_t *export_ = exports.data[i];
        if (wasm_extern_kind(export_) == WASM_EXTERN_MEMORY) {
            runtime->memory = wasm_extern_as_memory(export_);
            break;
        }
    }
    
    return 0;
}

/* === Policy Execution === */

int wasm_runtime_evaluate_policy(wasm_runtime_t *runtime,
                                  entity_t *subject,
                                  entity_t *object,
                                  int operation) {
    if (!runtime || !runtime->instance) return 0;
    
    /* Find the evaluate_policy export */
    wasm_extern_vec_t exports;
    wasm_instance_exports(runtime->instance, &exports);
    
    wasm_func_t *eval_func = NULL;
    for (size_t i = 0; i < exports.size; i++) {
        wasm_extern_t *export_ = exports.data[i];
        if (wasm_extern_kind(export_) == WASM_EXTERN_FUNC) {
            eval_func = wasm_extern_as_func(export_);
            break;
        }
    }
    
    if (!eval_func) return 0;
    
    /* Prepare arguments */
    wasm_val_t args[3] = {
        {.kind = WASM_I32, .of = {.i32 = subject->pid}},
        {.kind = WASM_I32, .of = {.i32 = object->resource_type}},
        {.kind = WASM_I32, .of {.i32 = operation}}
    };
    wasm_val_vec_t args_vec = {3, args};
    
    wasm_val_t results[1];
    wasm_val_vec_t results_vec = {1, results};
    
    /* Call the function */
    wasm_trap_t *trap = wasm_func_call(eval_func, &args_vec, &results_vec);
    
    if (trap) {
        wasm_name_t message;
        wasm_trap_message(trap, &message);
        fprintf(stderr, "Wasm trap: %.*s\n", (int)message.size, message.data);
        wasm_name_delete(&message);
        wasm_trap_delete(trap);
        return 0;
    }
    
    return results[0].of.i32;
}

/* === Callback Registration === */

void wasm_runtime_set_violation_callback(wasm_runtime_t *runtime,
                                          void (*callback)(policy_decision_t*)) {
    if (runtime) {
        runtime->on_violation = callback;
    }
}

void wasm_runtime_set_alert_callback(wasm_runtime_t *runtime,
                                      void (*callback)(const char*)) {
    if (runtime) {
        runtime->on_alert = callback;
    }
}
