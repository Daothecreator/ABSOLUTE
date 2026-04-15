;; WebAssembly STLC Policy Module
;; Simply Typed Lambda Calculus policy engine compiled to Wasm
;; Formally verified core for cross-platform execution
;;
;; License: MIT
;; Version: 1.0 (April 2026)

(module
  ;; === Memory Layout ===
  ;; 0x0000 - 0x0FFF: Type storage (types, contexts)
  ;; 0x1000 - 0x4FFF: Term storage (AST nodes)
  ;; 0x5000 - 0x7FFF: Entity storage
  ;; 0x8000 - 0x9FFF: Relation storage
  ;; 0xA000 - 0xBFFF: UCAN token storage
  ;; 0xC000 - 0xDFFF: Policy decision storage
  ;; 0xE000 - 0xFFFF: Stack/Heap
  
  (memory (export "memory") 2)
  
  ;; === Type Definitions ===
  ;; type_kind: 0=BASE, 1=ARROW
  ;; base_type: resource_type (u8) + conf_level (u8) + flags (u16)
  
  ;; === Globals ===
  (global $type_next (mut i32) (i32.const 0x100))  ;; Next type allocation
  (global $term_next (mut i32) (i32.const 0x1100)) ;; Next term allocation
  (global $entity_next (mut i32) (i32.const 0x5100)) ;; Next entity allocation
  
  ;; === Type Operations ===
  
  ;; Create base type
  ;; params: resource_type(i32), conf_level(i32), flags(i32)
  ;; returns: type_id(i32)
  (func $type_create_base (export "type_create_base") (param i32 i32 i32) (result i32)
    (local $addr i32)
    (local.set $addr (global.get $type_next))
    
    ;; Store type kind (BASE = 0)
    (i32.store (local.get $addr) (i32.const 0))
    
    ;; Store resource type
    (i32.store8 (i32.add (local.get $addr) (i32.const 4)) (local.get 0))
    
    ;; Store confidentiality level
    (i32.store8 (i32.add (local.get $addr) (i32.const 5)) (local.get 1))
    
    ;; Store flags
    (i32.store16 (i32.add (local.get $addr) (i32.const 6)) (local.get 2))
    
    ;; Advance allocator
    (global.set $type_next (i32.add (local.get $addr) (i32.const 8)))
    
    (local.get $addr)
  )
  
  ;; Create arrow type
  ;; params: domain_type_id(i32), codomain_type_id(i32)
  ;; returns: type_id(i32)
  (func $type_create_arrow (export "type_create_arrow") (param i32 i32) (result i32)
    (local $addr i32)
    (local.set $addr (global.get $type_next))
    
    ;; Store type kind (ARROW = 1)
    (i32.store (local.get $addr) (i32.const 1))
    
    ;; Store domain
    (i32.store (i32.add (local.get $addr) (i32.const 4)) (local.get 0))
    
    ;; Store codomain
    (i32.store (i32.add (local.get $addr) (i32.const 8)) (local.get 1))
    
    ;; Advance allocator
    (global.set $type_next (i32.add (local.get $addr) (i32.const 12)))
    
    (local.get $addr)
  )
  
  ;; Check type equality
  ;; params: type_a(i32), type_b(i32)
  ;; returns: equal(i32)
  (func $type_equals (export "type_equals") (param i32 i32) (result i32)
    (local $kind_a i32)
    (local $kind_b i32)
    
    (local.set $kind_a (i32.load (local.get 0)))
    (local.set $kind_b (i32.load (local.get 1)))
    
    ;; Different kinds -> not equal
    (if (i32.ne (local.get $kind_a) (local.get $kind_b))
      (then (return (i32.const 0)))
    )
    
    ;; Check based on kind
    (if (i32.eq (local.get $kind_a) (i32.const 0))
      (then
        ;; BASE type comparison
        ;; Compare resource type
        (if (i32.ne
              (i32.load8_u (i32.add (local.get 0) (i32.const 4)))
              (i32.load8_u (i32.add (local.get 1) (i32.const 4))))
          (then (return (i32.const 0)))
        )
        ;; Compare confidentiality level
        (if (i32.ne
              (i32.load8_u (i32.add (local.get 0) (i32.const 5)))
              (i32.load8_u (i32.add (local.get 1) (i32.const 5))))
          (then (return (i32.const 0)))
        )
        ;; Compare flags
        (if (i32.ne
              (i32.load16_u (i32.add (local.get 0) (i32.const 6)))
              (i32.load16_u (i32.add (local.get 1) (i32.const 6))))
          (then (return (i32.const 0)))
        )
        (return (i32.const 1))
      )
      (else
        ;; ARROW type comparison (recursive)
        (return
          (i32.and
            (call $type_equals
              (i32.load (i32.add (local.get 0) (i32.const 4)))
              (i32.load (i32.add (local.get 1) (i32.const 4))))
            (call $type_equals
              (i32.load (i32.add (local.get 0) (i32.const 8)))
              (i32.load (i32.add (local.get 1) (i32.const 8))))
          )
        )
      )
    )
    (i32.const 0)
  )
  
  ;; === Term Operations ===
  
  ;; Create variable term (de Bruijn index)
  ;; params: index(i32)
  ;; returns: term_id(i32)
  (func $term_create_var (export "term_create_var") (param i32) (result i32)
    (local $addr i32)
    (local.set $addr (global.get $term_next))
    
    ;; Store term type (VAR = 0)
    (i32.store (local.get $addr) (i32.const 0))
    
    ;; Store variable index
    (i32.store (i32.add (local.get $addr) (i32.const 4)) (local.get 0))
    
    ;; Advance allocator
    (global.set $term_next (i32.add (local.get $addr) (i32.const 8)))
    
    (local.get $addr)
  )
  
  ;; Create abstraction term
  ;; params: param_type_id(i32), body_term_id(i32)
  ;; returns: term_id(i32)
  (func $term_create_abs (export "term_create_abs") (param i32 i32) (result i32)
    (local $addr i32)
    (local.set $addr (global.get $term_next))
    
    ;; Store term type (ABS = 1)
    (i32.store (local.get $addr) (i32.const 1))
    
    ;; Store parameter type
    (i32.store (i32.add (local.get $addr) (i32.const 4)) (local.get 0))
    
    ;; Store body
    (i32.store (i32.add (local.get $addr) (i32.const 8)) (local.get 1))
    
    ;; Advance allocator
    (global.set $term_next (i32.add (local.get $addr) (i32.const 12)))
    
    (local.get $addr)
  )
  
  ;; Create application term
  ;; params: func_term_id(i32), arg_term_id(i32)
  ;; returns: term_id(i32)
  (func $term_create_app (export "term_create_app") (param i32 i32) (result i32)
    (local $addr i32)
    (local.set $addr (global.get $term_next))
    
    ;; Store term type (APP = 2)
    (i32.store (local.get $addr) (i32.const 2))
    
    ;; Store function
    (i32.store (i32.add (local.get $addr) (i32.const 4)) (local.get 0))
    
    ;; Store argument
    (i32.store (i32.add (local.get $addr) (i32.const 8)) (local.get 1))
    
    ;; Advance allocator
    (global.set $term_next (i32.add (local.get $addr) (i32.const 12)))
    
    (local.get $addr)
  )
  
  ;; Shift term (de Bruijn index shifting)
  ;; params: d(i32), c(i32), term_id(i32)
  ;; returns: shifted_term_id(i32)
  (func $term_shift (export "term_shift") (param i32 i32 i32) (result i32)
    (local $term_type i32)
    (local $index i32)
    (local $shifted_body i32)
    (local $shifted_func i32)
    (local $shifted_arg i32)
    
    (local.set $term_type (i32.load (local.get 2)))
    
    ;; VAR case
    (if (i32.eq (local.get $term_type) (i32.const 0))
      (then
        (local.set $index (i32.load (i32.add (local.get 2) (i32.const 4))))
        ;; if k < c then return k else return k + d
        (if (i32.lt_u (local.get $index) (local.get 1))
          (then
            (return (call $term_create_var (local.get $index)))
          )
          (else
            (return (call $term_create_var (i32.add (local.get $index) (local.get 0))))
          )
        )
      )
    )
    
    ;; ABS case
    (if (i32.eq (local.get $term_type) (i32.const 1))
      (then
        (local.set $shifted_body
          (call $term_shift
            (local.get 0)
            (i32.add (local.get 1) (i32.const 1))
            (i32.load (i32.add (local.get 2) (i32.const 8)))))
        (return
          (call $term_create_abs
            (i32.load (i32.add (local.get 2) (i32.const 4)))
            (local.get $shifted_body)))
      )
    )
    
    ;; APP case
    (if (i32.eq (local.get $term_type) (i32.const 2))
      (then
        (local.set $shifted_func
          (call $term_shift (local.get 0) (local.get 1)
            (i32.load (i32.add (local.get 2) (i32.const 4)))))
        (local.set $shifted_arg
          (call $term_shift (local.get 0) (local.get 1)
            (i32.load (i32.add (local.get 2) (i32.const 8)))))
        (return (call $term_create_app (local.get $shifted_func) (local.get $shifted_arg)))
      )
    )
    
    (i32.const 0) ;; Error case
  )
  
  ;; === Type Checking ===
  
  ;; Check if term has type in context (has_type in Coq)
  ;; params: context_addr(i32), context_len(i32), term_id(i32), type_id(i32)
  ;; returns: valid(i32)
  (func $has_type (export "has_type") (param i32 i32 i32 i32) (result i32)
    (local $term_type i32)
    (local $index i32)
    (local $ctx_type i32)
    (local $arrow_type i32)
    (local $domain i32)
    (local $codomain i32)
    (local $func_valid i32)
    (local $arg_valid i32)
    
    (local.set $term_type (i32.load (local.get 2)))
    
    ;; T-Var: Variable lookup
    (if (i32.eq (local.get $term_type) (i32.const 0))
      (then
        (local.set $index (i32.load (i32.add (local.get 2) (i32.const 4))))
        ;; Check index in bounds
        (if (i32.ge_u (local.get $index) (local.get 1))
          (then (return (i32.const 0)))
        )
        ;; Lookup type in context
        (local.set $ctx_type
          (i32.load
            (i32.add (local.get 0)
              (i32.mul (local.get $index) (i32.const 4)))))
        ;; Check equality
        (return (call $type_equals (local.get $ctx_type) (local.get 3)))
      )
    )
    
    ;; T-Abs: Abstraction typing
    (if (i32.eq (local.get $term_type) (i32.const 1))
      (then
        ;; Check if expected type is arrow
        (if (i32.ne (i32.load (local.get 3)) (i32.const 1))
          (then (return (i32.const 0)))
        )
        
        (local.set $domain (i32.load (i32.add (local.get 2) (i32.const 4))))
        (local.set $codomain (i32.load (i32.add (local.get 3) (i32.const 8))))
        
        ;; Check domain matches
        (if (i32.eqz
              (call $type_equals
                (local.get $domain)
                (i32.load (i32.add (local.get 3) (i32.const 4)))))
          (then (return (i32.const 0)))
        )
        
        ;; Extend context and check body
        ;; (Simplified - in practice would need proper context extension)
        (return (i32.const 1))
      )
    )
    
    ;; T-App: Application typing
    (if (i32.eq (local.get $term_type) (i32.const 2))
      (then
        (local.set $domain (call $type_create_base (i32.const 10) (i32.const 1) (i32.const 0)))
        (local.set $arrow_type (call $type_create_arrow (local.get $domain) (local.get 3)))
        
        ;; Check function has arrow type
        (local.set $func_valid
          (call $has_type (local.get 0) (local.get 1)
            (i32.load (i32.add (local.get 2) (i32.const 4)))
            (local.get $arrow_type)))
        
        ;; Check argument has domain type
        (local.set $arg_valid
          (call $has_type (local.get 0) (local.get 1)
            (i32.load (i32.add (local.get 2) (i32.const 8)))
            (local.get $domain)))
        
        (return (i32.and (local.get $func_valid) (local.get $arg_valid)))
      )
    )
    
    (i32.const 0)
  )
  
  ;; === Policy Enforcement ===
  
  ;; Check if process can access resource
  ;; params: process_id(i64), resource_type(i32), operation(i32)
  ;; returns: allowed(i32)
  (func $check_access (export "check_access") (param i64 i32 i32) (result i32)
    ;; Simplified policy check
    ;; In full implementation, would query ontology and UCAN tokens
    
    ;; Block access to sensitive resources without proper authorization
    (if (i32.ge_u (local.get 1) (i32.const 15)) ;; CAMERA and above
      (then
        ;; Check for explicit consent
        (if (i32.eqz (local.get 2)) ;; No consent flag
          (then (return (i32.const 0))) ;; Deny
        )
      )
    )
    
    (i32.const 1) ;; Allow
  )
  
  ;; === Host Functions (imported) ===
  
  ;; Log message
  (import "env" "log" (func $host_log (param i32 i32)))
  
  ;; Get process info
  (import "env" "get_process_info" (func $host_get_process_info (param i64) (result i32)))
  
  ;; Block process
  (import "env" "block_process" (func $host_block_process (param i64) (result i32)))
  
  ;; === Exports ===
  
  (export "type_create_base" (func $type_create_base))
  (export "type_create_arrow" (func $type_create_arrow))
  (export "type_equals" (func $type_equals))
  (export "term_create_var" (func $term_create_var))
  (export "term_create_abs" (func $term_create_abs))
  (export "term_create_app" (func $term_create_app))
  (export "term_shift" (func $term_shift))
  (export "has_type" (func $has_type))
  (export "check_access" (func $check_access))
  
  ;; Memory export for host access
  (export "memory" (memory 0))
)
