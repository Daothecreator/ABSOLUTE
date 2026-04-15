/*
 * Core Test Suite
 * Tests for STLC policy engine and utilities
 * 
 * Part of Sovereign Privacy Widget
 * License: MIT
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>

#include "core/stlc_policy_engine.h"
#include "utils/crypto_utils.h"
#include "utils/hash_table.h"
#include "utils/ring_buffer.h"

#define TEST(name) printf("  Testing %s... ", name);
#define PASS() printf("PASSED\n")
#define FAIL(msg) do { printf("FAILED: %s\n", msg); return 1; } while(0)

/* === Type Tests === */

int test_type_creation() {
    TEST("type creation");
    
    type_t* base = type_create_base(RESOURCE_PROCESS, CONF_INTERNAL);
    if (!base) FAIL("failed to create base type");
    if (base->kind != TYPE_BASE) FAIL("wrong type kind");
    if (base->data.base.resource != RESOURCE_PROCESS) FAIL("wrong resource type");
    if (base->data.base.level != CONF_INTERNAL) FAIL("wrong confidentiality level");
    
    type_free(base);
    PASS();
    return 0;
}

int test_arrow_type() {
    TEST("arrow type");
    
    type_t* domain = type_create_base(RESOURCE_FILESYSTEM, CONF_CONFIDENTIAL);
    type_t* codomain = type_create_base(RESOURCE_NETWORK, CONF_PUBLIC);
    type_t* arrow = type_create_arrow(domain, codomain);
    
    if (!arrow) FAIL("failed to create arrow type");
    if (arrow->kind != TYPE_ARROW) FAIL("wrong type kind");
    
    type_free(arrow);
    type_free(domain);
    type_free(codomain);
    PASS();
    return 0;
}

int test_type_equality() {
    TEST("type equality");
    
    type_t* t1 = type_create_base(RESOURCE_PROCESS, CONF_INTERNAL);
    type_t* t2 = type_create_base(RESOURCE_PROCESS, CONF_INTERNAL);
    type_t* t3 = type_create_base(RESOURCE_NETWORK, CONF_INTERNAL);
    
    if (!type_equals(t1, t2)) FAIL("equal types should be equal");
    if (type_equals(t1, t3)) FAIL("different types should not be equal");
    
    type_free(t1);
    type_free(t2);
    type_free(t3);
    PASS();
    return 0;
}

/* === Term Tests === */

int test_var_term() {
    TEST("variable term");
    
    term_t* var = term_create_var(0);
    if (!var) FAIL("failed to create variable");
    if (var->type != TERM_VAR) FAIL("wrong term type");
    if (var->data.var_index != 0) FAIL("wrong variable index");
    
    term_free(var);
    PASS();
    return 0;
}

int test_abs_term() {
    TEST("abstraction term");
    
    type_t* param_type = type_create_base(RESOURCE_PROCESS, CONF_INTERNAL);
    term_t* body = term_create_var(0);
    term_t* abs = term_create_abs(param_type, body);
    
    if (!abs) FAIL("failed to create abstraction");
    if (abs->type != TERM_ABS) FAIL("wrong term type");
    
    term_free(abs);
    type_free(param_type);
    PASS();
    return 0;
}

int test_app_term() {
    TEST("application term");
    
    term_t* func = term_create_var(0);
    term_t* arg = term_create_var(1);
    term_t* app = term_create_app(func, arg);
    
    if (!app) FAIL("failed to create application");
    if (app->type != TERM_APP) FAIL("wrong term type");
    
    term_free(app);
    PASS();
    return 0;
}

/* === Context Tests === */

int test_context_operations() {
    TEST("context operations");
    
    context_t* ctx = context_create();
    if (!ctx) FAIL("failed to create context");
    
    type_t* t1 = type_create_base(RESOURCE_PROCESS, CONF_INTERNAL);
    type_t* t2 = type_create_base(RESOURCE_NETWORK, CONF_PUBLIC);
    
    if (!context_append(ctx, t1)) FAIL("failed to append to context");
    if (!context_append(ctx, t2)) FAIL("failed to append to context");
    if (ctx->count != 2) FAIL("wrong context count");
    
    type_t* looked_up = context_lookup(ctx, 0);
    if (!looked_up) FAIL("failed to lookup in context");
    if (!type_equals(looked_up, t1)) FAIL("wrong type looked up");
    
    context_free(ctx);
    type_free(t1);
    type_free(t2);
    PASS();
    return 0;
}

/* === Type Checking Tests === */

int test_type_checking_var() {
    TEST("type checking variable");
    
    context_t* ctx = context_create();
    type_t* t = type_create_base(RESOURCE_PROCESS, CONF_INTERNAL);
    context_append(ctx, t);
    
    term_t* var = term_create_var(0);
    
    if (!has_type(ctx, var, t)) FAIL("variable should have type");
    
    type_t* wrong_type = type_create_base(RESOURCE_NETWORK, CONF_PUBLIC);
    if (has_type(ctx, var, wrong_type)) FAIL("variable should not have wrong type");
    
    context_free(ctx);
    term_free(var);
    type_free(t);
    type_free(wrong_type);
    PASS();
    return 0;
}

/* === Ontology Tests === */

int test_ontology_creation() {
    TEST("ontology creation");
    
    ontology_t* ont = ontology_create();
    if (!ont) FAIL("failed to create ontology");
    if (ont->entity_count != 0) FAIL("new ontology should be empty");
    
    ontology_free(ont);
    PASS();
    return 0;
}

int test_entity_addition() {
    TEST("entity addition");
    
    ontology_t* ont = ontology_create();
    entity_t* entity = ontology_add_entity(ont, "test_process", RESOURCE_PROCESS, 1234);
    
    if (!entity) FAIL("failed to add entity");
    if (ont->entity_count != 1) FAIL("wrong entity count");
    if (strcmp(entity->name, "test_process") != 0) FAIL("wrong entity name");
    if (entity->pid != 1234) FAIL("wrong entity PID");
    
    ontology_free(ont);
    PASS();
    return 0;
}

int test_entity_lookup() {
    TEST("entity lookup");
    
    ontology_t* ont = ontology_create();
    ontology_add_entity(ont, "proc1", RESOURCE_PROCESS, 1000);
    ontology_add_entity(ont, "proc2", RESOURCE_PROCESS, 2000);
    
    entity_t* found = ontology_find_by_pid(ont, 1000);
    if (!found) FAIL("failed to find entity");
    if (found->pid != 1000) FAIL("wrong entity found");
    
    entity_t* not_found = ontology_find_by_pid(ont, 9999);
    if (not_found) FAIL("should not find non-existent entity");
    
    ontology_free(ont);
    PASS();
    return 0;
}

/* === Hash Table Tests === */

int test_hash_table_basic() {
    TEST("hash table basic operations");
    
    hash_table_t* ht = hash_table_create(16, HT_STRING_KEYS);
    if (!ht) FAIL("failed to create hash table");
    
    int value1 = 42;
    int value2 = 100;
    
    if (hash_table_insert_string(ht, "key1", &value1, sizeof(value1)) != 0)
        FAIL("failed to insert");
    
    if (hash_table_insert_string(ht, "key2", &value2, sizeof(value2)) != 0)
        FAIL("failed to insert");
    
    size_t len;
    int* retrieved = hash_table_lookup_string(ht, "key1", &len);
    if (!retrieved) FAIL("failed to lookup");
    if (*retrieved != 42) FAIL("wrong value retrieved");
    
    if (hash_table_delete_string(ht, "key1") != 0)
        FAIL("failed to delete");
    
    if (hash_table_lookup_string(ht, "key1", NULL))
        FAIL("deleted key should not exist");
    
    hash_table_destroy(ht);
    PASS();
    return 0;
}

/* === Ring Buffer Tests === */

int test_ring_buffer_basic() {
    TEST("ring buffer basic operations");
    
    ring_buffer_t* rb = ring_buffer_create(8, sizeof(int));
    if (!rb) FAIL("failed to create ring buffer");
    
    if (!ring_buffer_empty(rb)) FAIL("new buffer should be empty");
    
    int value = 42;
    if (!ring_buffer_push(rb, &value)) FAIL("failed to push");
    
    if (ring_buffer_empty(rb)) FAIL("buffer should not be empty");
    
    int retrieved;
    if (!ring_buffer_pop(rb, &retrieved)) FAIL("failed to pop");
    if (retrieved != 42) FAIL("wrong value retrieved");
    
    if (!ring_buffer_empty(rb)) FAIL("buffer should be empty after pop");
    
    ring_buffer_destroy(rb);
    PASS();
    return 0;
}

int test_ring_buffer_full() {
    TEST("ring buffer full condition");
    
    ring_buffer_t* rb = ring_buffer_create(4, sizeof(int));
    if (!rb) FAIL("failed to create ring buffer");
    
    /* Fill buffer (capacity-1 due to full/empty distinction) */
    for (int i = 0; i < 3; i++) {
        if (!ring_buffer_push(rb, &i)) FAIL("failed to push");
    }
    
    if (!ring_buffer_full(rb)) FAIL("buffer should be full");
    
    /* Try to push to full buffer */
    int value = 999;
    if (ring_buffer_push(rb, &value)) FAIL("should not push to full buffer");
    
    ring_buffer_destroy(rb);
    PASS();
    return 0;
}

/* === Crypto Tests === */

int test_crypto_hash() {
    TEST("crypto hash");
    
    if (crypto_init() != 0) FAIL("failed to init crypto");
    
    uint8_t data[] = "test data";
    uint8_t hash[32];
    
    if (crypto_hash_sha256(data, sizeof(data), hash) != 0)
        FAIL("failed to hash");
    
    /* Hash should not be all zeros */
    int all_zero = 1;
    for (int i = 0; i < 32; i++) {
        if (hash[i] != 0) {
            all_zero = 0;
            break;
        }
    }
    if (all_zero) FAIL("hash should not be all zeros");
    
    PASS();
    return 0;
}

/* === Main === */

int main() {
    printf("\n=== Sovereign Privacy Widget Test Suite ===\n\n");
    
    int failures = 0;
    
    printf("Type Tests:\n");
    failures += test_type_creation();
    failures += test_arrow_type();
    failures += test_type_equality();
    
    printf("\nTerm Tests:\n");
    failures += test_var_term();
    failures += test_abs_term();
    failures += test_app_term();
    
    printf("\nContext Tests:\n");
    failures += test_context_operations();
    
    printf("\nType Checking Tests:\n");
    failures += test_type_checking_var();
    
    printf("\nOntology Tests:\n");
    failures += test_ontology_creation();
    failures += test_entity_addition();
    failures += test_entity_lookup();
    
    printf("\nHash Table Tests:\n");
    failures += test_hash_table_basic();
    
    printf("\nRing Buffer Tests:\n");
    failures += test_ring_buffer_basic();
    failures += test_ring_buffer_full();
    
    printf("\nCrypto Tests:\n");
    failures += test_crypto_hash();
    
    printf("\n========================================\n");
    if (failures == 0) {
        printf("All tests PASSED!\n");
    } else {
        printf("%d test(s) FAILED\n", failures);
    }
    printf("========================================\n\n");
    
    return failures;
}
