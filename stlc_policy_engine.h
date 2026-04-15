/*
 * STLC Policy Engine Core Header
 * Simply Typed Lambda Calculus with de Bruijn indices
 * Formally verified privacy policy enforcement
 * 
 * Extracted from Coq proof (lambda_ont_debruijn_full.v)
 * License: MIT
 * Version: 1.0 (April 2026)
 */

#ifndef STLC_POLICY_ENGINE_H
#define STLC_POLICY_ENGINE_H

#include <stdint.h>
#include <stdbool.h>
#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

/* === Core Types === */

/* Resource types (TBase in Coq) */
typedef enum {
    RESOURCE_FILESYSTEM = 0,
    RESOURCE_NETWORK,
    RESOURCE_CAMERA,
    RESOURCE_MICROPHONE,
    RESOURCE_LOCATION,
    RESOURCE_CONTACTS,
    RESOURCE_CALENDAR,
    RESOURCE_PHOTOS,
    RESOURCE_BLUETOOTH,
    RESOURCE_USB,
    RESOURCE_PROCESS,
    RESOURCE_MEMORY,
    RESOURCE_CERTIFICATE,
    RESOURCE_KEYCHAIN,
    RESOURCE_SCREEN,
    RESOURCE_KEYBOARD,
    RESOURCE_CLIPBOARD,
    RESOURCE_NOTIFICATION,
    RESOURCE_BACKGROUND_TASK,
    RESOURCE_SYSTEM_CALL,
    RESOURCE_COUNT
} resource_type_t;

/* Confidentiality levels */
typedef enum {
    CONF_PUBLIC = 0,
    CONF_INTERNAL,
    CONF_CONFIDENTIAL,
    CONF_SECRET,
    CONF_TOP_SECRET
} confidentiality_level_t;

/* Term types (de Bruijn indices) */
typedef enum {
    TERM_VAR = 0,
    TERM_ABS,
    TERM_APP
} term_type_t;

/* Process state */
typedef enum {
    PROC_STATE_PENDING = 0,
    PROC_STATE_AUTHORIZED,
    PROC_STATE_DENIED,
    PROC_STATE_BLOCKED,
    PROC_STATE_TERMINATED
} process_state_t;

/* === Data Structures === */

/* Type representation (ty in Coq) */
typedef struct type_s {
    enum {
        TYPE_BASE,
        TYPE_ARROW
    } kind;
    union {
        struct {
            resource_type_t resource;
            confidentiality_level_t level;
            uint32_t flags;
        } base;
        struct {
            struct type_s* domain;
            struct type_s* codomain;
        } arrow;
    } data;
} type_t;

/* Term representation (term in Coq) */
typedef struct term_s {
    term_type_t type;
    union {
        uint32_t var_index;           /* tVar */
        struct {                      /* tAbs */
            type_t* param_type;
            struct term_s* body;
        } abs;
        struct {                      /* tApp */
            struct term_s* func;
            struct term_s* arg;
        } app;
    } data;
} term_t;

/* Context (Gamma) - list of types */
typedef struct context_s {
    type_t** types;
    size_t count;
    size_t capacity;
} context_t;

/* System entity (E in Ont) */
typedef struct entity_s {
    uint64_t id;
    char name[256];
    resource_type_t resource_type;
    confidentiality_level_t level;
    uint32_t pid;
    uint32_t ppid;
    uint64_t hash;           /* Binary hash */
    uint64_t cert_hash;      /* Certificate SPKI hash */
    bool is_hidden;
    bool is_system;
    struct entity_s* parent;
} entity_t;

/* Relation (R in Ont) */
typedef struct relation_s {
    entity_t* from;
    entity_t* to;
    enum {
        REL_PARENT,
        REL_COMMUNICATES,
        REL_ACCESSES,
        REL_DELEGATES
    } kind;
} relation_t;

/* Privacy proposition (P in Ont) */
typedef struct proposition_s {
    entity_t* entity;
    enum {
        PROP_ENCRYPTED,
        PROP_USER_CONSENT,
        PROP_EXPLICIT_ALLOW,
        PROP_IMPLICIT_DENY,
        PROP_AUDIT_REQUIRED
    } kind;
    bool value;
    uint64_t timestamp;
} proposition_t;

/* Ontology structure */
typedef struct ontology_s {
    entity_t** entities;
    size_t entity_count;
    relation_t** relations;
    size_t relation_count;
    proposition_t** propositions;
    size_t proposition_count;
} ontology_t;

/* UCAN capability token */
typedef struct ucan_token_s {
    char issuer_did[128];
    char audience_did[128];
    uint64_t issued_at;
    uint64_t expires_at;
    type_t* capability;
    uint8_t signature[64];
    struct ucan_token_s** proofs;
    size_t proof_count;
} ucan_token_t;

/* Policy decision */
typedef struct policy_decision_s {
    bool allowed;
    process_state_t state;
    char reason[512];
    uint64_t decision_time;
    term_t* proof_term;
} policy_decision_t;

/* === Function Declarations === */

/* Type operations */
type_t* type_create_base(resource_type_t resource, confidentiality_level_t level);
type_t* type_create_arrow(type_t* domain, type_t* codomain);
void type_free(type_t* type);
bool type_equals(type_t* a, type_t* b);
char* type_to_string(type_t* type);

/* Term operations */
term_t* term_create_var(uint32_t index);
term_t* term_create_abs(type_t* param_type, term_t* body);
term_t* term_create_app(term_t* func, term_t* arg);
void term_free(term_t* term);
term_t* term_shift(uint32_t d, uint32_t c, term_t* t);
term_t* term_subst(uint32_t j, term_t* s, term_t* t);
term_t* term_subst_top(term_t* s, term_t* t);
char* term_to_string(term_t* term);

/* Context operations */
context_t* context_create(void);
void context_free(context_t* ctx);
bool context_append(context_t* ctx, type_t* type);
type_t* context_lookup(context_t* ctx, uint32_t n);
context_t* context_shift(context_t* ctx, uint32_t d);

/* Type checking (has_type in Coq) */
bool has_type(context_t* gamma, term_t* term, type_t* type);
bool is_value(term_t* term);

/* Semantics (step in Coq) */
bool term_step(term_t* t1, term_t** t2);
bool term_multistep(term_t* t1, term_t** t2, uint32_t max_steps);

/* Ontology operations */
ontology_t* ontology_create(void);
void ontology_free(ontology_t* ont);
entity_t* ontology_add_entity(ontology_t* ont, const char* name, 
                               resource_type_t type, uint32_t pid);
relation_t* ontology_add_relation(ontology_t* ont, entity_t* from, 
                                   entity_t* to, int kind);
proposition_t* ontology_add_proposition(ontology_t* ont, entity_t* entity, 
                                         int kind, bool value);
entity_t* ontology_find_by_pid(ontology_t* ont, uint32_t pid);
entity_t* ontology_find_hidden(ontology_t* ont);

/* UCAN operations */
ucan_token_t* ucan_create(const char* issuer, const char* audience, 
                          type_t* capability, uint64_t expiry);
bool ucan_verify(ucan_token_t* token, const uint8_t* public_key);
bool ucan_delegate(ucan_token_t* parent, ucan_token_t* child);
context_t* ucan_to_context(ucan_token_t** tokens, size_t count);

/* Policy enforcement */
policy_decision_t* policy_check_access(context_t* gamma, entity_t* subject,
                                        entity_t* object, int operation);
policy_decision_t* policy_check_syscall(context_t* gamma, uint32_t pid,
                                         int syscall_nr, void* args);
bool policy_block_process(uint32_t pid, const char* reason);
bool policy_terminate_process(uint32_t pid);

/* Real-time enrichment */
void policy_enrich_entity(entity_t* entity);
void policy_update_ontology(ontology_t* ont);

/* === Constants === */

/* Syscall numbers (x86_64 Linux) */
#define SYS_READ        0
#define SYS_WRITE       1
#define SYS_OPEN        2
#define SYS_CLOSE       3
#define SYS_SOCKET      41
#define SYS_CONNECT     42
#define SYS_ACCEPT      43
#define SYS_SENDTO      44
#define SYS_RECVFROM    45
#define SYS_EXECVE      59
#define SYS_EXIT        60
#define SYS_KILL        62
#define SYS_OPENAT      257
#define SYS_EXECVEAT    322

/* Resource flags */
#define RES_FLAG_READ       0x01
#define RES_FLAG_WRITE      0x02
#define RES_FLAG_EXECUTE    0x04
#define RES_FLAG_CREATE     0x08
#define RES_FLAG_DELETE     0x10
#define RES_FLAG_HIDDEN     0x20
#define RES_FLAG_SYSTEM     0x40

/* === Verification Theorems (from Coq) === */

/* Theorem preservation: If Γ ⊢ t : T and t --> t', then Γ ⊢ t' : T */
bool theorem_preservation(context_t* gamma, term_t* t, term_t* t_prime, type_t* T);

/* Theorem progress: If Γ ⊢ t : T, then either t is a value or t --> t' */
bool theorem_progress(context_t* gamma, term_t* t, type_t* T, 
                      bool* is_val, term_t** t_prime);

/* Weakening lemma */
bool lemma_weakening(context_t* gamma, term_t* t, type_t* T,
                     type_t* U, term_t* shifted_t);

/* Substitution lemma */
bool lemma_substitution(context_t* gamma, term_t* t, type_t* T,
                        term_t* s, type_t* U, term_t* result);

#ifdef __cplusplus
}
#endif

#endif /* STLC_POLICY_ENGINE_H */
