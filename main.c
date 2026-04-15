/*
 * Sovereign Privacy Widget - Main Integration
 * Cross-platform privacy monitoring and enforcement system
 * 
 * Based on formally verified STLC core (Coq-extracted)
 * Uses eBPF/ESF/WFP for kernel monitoring
 * WebAssembly for portable execution
 * UCAN for decentralized authorization
 * IPFS for distribution
 * 
 * License: MIT
 * Version: 1.0 (April 2026)
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <signal.h>
#include <unistd.h>
#include <getopt.h>
#include <errno.h>
#include <sys/stat.h>

#include "core/stlc_policy_engine.h"
#include "utils/logger.h"
#include "utils/config_parser.h"
#include "utils/crypto_utils.h"

/* Platform detection */
#if defined(__linux__)
    #define PLATFORM_LINUX
    #include "ebpf/ebpf_loader.h"
#elif defined(__APPLE__)
    #define PLATFORM_MACOS
    #include "platform/macos/endpoint_security.h"
#elif defined(_WIN32)
    #define PLATFORM_WINDOWS
    #include "platform/windows/wfp_driver.h"
#endif

#include "wasm/wasm_runtime.h"
#include "ucan/ucan_auth.h"
#include "ui/framebuffer_ui.h"
#include "enforcement/process_enforcer.h"
#include "distribution/ipfs_distribution.h"

/* === Version Info === */

#define SOVEREIGN_VERSION "1.0.0"
#define SOVEREIGN_NAME "Sovereign Privacy Widget"
#define SOVEREIGN_CONFIG_PATH "/etc/sovereign-widget/sovereign-widget.conf"
#define SOVEREIGN_PID_FILE "/var/run/sovereign-widget.pid"

/* === Global State === */

static volatile bool g_running = true;
static config_t* g_config = NULL;
static wasm_runtime_t* g_runtime = NULL;
static ucan_store_t* g_ucan_store = NULL;
static fb_context_t* g_fb = NULL;
static ipfs_distribution_t* g_distribution = NULL;
static ontology_t* g_ontology = NULL;
static context_t* g_policy_context = NULL;

/* Platform-specific handles */
#ifdef PLATFORM_LINUX
static int g_ebpf_initialized = 0;
#elif defined(PLATFORM_MACOS)
static int g_es_initialized = 0;
#elif defined(PLATFORM_WINDOWS)
static int g_wfp_initialized = 0;
#endif

/* === Signal Handlers === */

static void signal_handler(int sig) {
    LOGF_INFO("Received signal %d, initiating shutdown...", sig);
    g_running = false;
}

static void setup_signal_handlers(void) {
    struct sigaction sa;
    memset(&sa, 0, sizeof(sa));
    sa.sa_handler = signal_handler;
    sigemptyset(&sa.sa_mask);
    
    sigaction(SIGINT, &sa, NULL);
    sigaction(SIGTERM, &sa, NULL);
    sigaction(SIGHUP, &sa, NULL);
    
    /* Ignore SIGPIPE */
    signal(SIGPIPE, SIG_IGN);
}

/* === Event Handlers === */

static void on_policy_violation(policy_decision_t* decision) {
    if (!decision) return;
    
    LOG_STRUCT(LOG_WARN, "policy_violation",
               "allowed", decision->allowed ? "true" : "false",
               "state", decision->state == PROC_STATE_BLOCKED ? "blocked" : 
                        decision->state == PROC_STATE_DENIED ? "denied" : "other",
               "reason", decision->reason,
               NULL);
    
    /* Render alert on framebuffer */
    if (g_fb && g_config && g_config->alert_on_violation) {
        alert_info_t alert = {
            .severity = decision->state == PROC_STATE_BLOCKED ? ALERT_CRITICAL : ALERT_WARNING,
            .pid = 0,
            .timestamp = decision->decision_time
        };
        
        strncpy(alert.title, "PRIVACY VIOLATION", sizeof(alert.title));
        strncpy(alert.process_name, "Unknown Process", sizeof(alert.process_name));
        strncpy(alert.violation_type, "Unauthorized Access", sizeof(alert.violation_type));
        strncpy(alert.description, decision->reason, sizeof(alert.description));
        strncpy(alert.resource, "System Resource", sizeof(alert.resource));
        
        fb_render_alert(g_fb, &alert);
    }
    
    /* Auto-block if configured */
    if (g_config && g_config->auto_block_violations && !decision->allowed) {
        LOGF_INFO("Auto-blocking violating process");
        /* Process blocking handled by enforcer */
    }
}

#ifdef PLATFORM_LINUX
static void on_ebpf_event(void* event, size_t size) {
    (void)size;
    
    struct {
        uint32_t type;
        uint32_t pid;
        uint64_t timestamp;
        uint64_t syscall_nr;
        char comm[16];
    } *header = event;
    
    LOGF_DEBUG("eBPF event: type=%u pid=%u syscall=%lu comm=%s",
               header->type, header->pid, header->syscall_nr, header->comm);
    
    /* Process event through STLC policy engine */
    if (g_runtime && g_ontology) {
        entity_t* process = ontology_find_by_pid(g_ontology, header->pid);
        
        if (!process) {
            char name[32];
            snprintf(name, sizeof(name), "proc:%s", header->comm);
            process = ontology_add_entity(g_ontology, name,
                                          RESOURCE_PROCESS, header->pid);
            LOGF_DEBUG("New process added to ontology: %s (PID %u)", name, header->pid);
        }
        
        /* Check if syscall is allowed */
        type_t* syscall_type = type_create_base(RESOURCE_SYSTEM_CALL, CONF_INTERNAL);
        entity_t* syscall_entity = ontology_add_entity(g_ontology, "syscall", 
                                                        RESOURCE_SYSTEM_CALL, 0);
        
        policy_decision_t* decision = policy_check_access(
            g_policy_context,
            process,
            syscall_entity,
            (int)header->syscall_nr
        );
        
        if (!decision->allowed) {
            on_policy_violation(decision);
            enforce_policy_decision(decision, process);
        }
        
        free(decision);
        type_free(syscall_type);
    }
}
#endif

#ifdef PLATFORM_MACOS
static void on_es_event(const es_event_t* event, void* context) {
    (void)context;
    
    LOGF_DEBUG("ES event: type=%d pid=%d", event->type, event->pid);
    
    switch (event->type) {
        case ES_EVENT_PROCESS_EXEC:
        case ES_EVENT_PROCESS_EXEC_AUTH:
            LOG_STRUCT(LOG_INFO, "process_exec",
                       "pid", event->pid,
                       "path", event->data.exec.path,
                       "signing_id", event->data.exec.signing_id,
                       "allowed", event->data.exec.allowed ? "true" : "false",
                       NULL);
            break;
            
        case ES_EVENT_FILE_OPEN:
            LOG_STRUCT(LOG_DEBUG, "file_open",
                       "pid", event->pid,
                       "path", event->data.file.path,
                       "allowed", event->data.file.allowed ? "true" : "false",
                       NULL);
            break;
            
        case ES_EVENT_HIDDEN_PROCESS_DETECTED:
            LOG_STRUCT(LOG_ERROR, "hidden_process",
                       "pid", event->pid,
                       "reason", "Process not visible to Endpoint Security",
                       NULL);
            if (g_fb) {
                alert_info_t alert = {
                    .severity = ALERT_CRITICAL,
                    .pid = event->pid,
                    .timestamp = event->timestamp
                };
                strncpy(alert.title, "HIDDEN PROCESS DETECTED", sizeof(alert.title));
                strncpy(alert.process_name, "Unknown", sizeof(alert.process_name));
                strncpy(alert.violation_type, "Hidden Process", sizeof(alert.violation_type));
                strncpy(alert.description, "Process not visible to security framework", 
                        sizeof(alert.description));
                fb_render_alert(g_fb, &alert);
            }
            break;
            
        default:
            break;
    }
}
#endif

#ifdef PLATFORM_WINDOWS
static void on_wfp_event(const wfp_event_t* event, void* context) {
    (void)context;
    
    LOGF_DEBUG("WFP event: type=%d pid=%lu", event->type, event->pid);
    
    switch (event->type) {
        case WFP_EVENT_CONNECTION_ATTEMPT:
            LOG_STRUCT(LOG_DEBUG, "connection_attempt",
                       "pid", event->pid,
                       "remote_port", event->data.connection.remote_port,
                       NULL);
            break;
            
        case WFP_EVENT_PROCESS_BLOCKED:
            LOG_STRUCT(LOG_WARN, "process_blocked",
                       "pid", event->pid,
                       "reason", event->reason,
                       NULL);
            break;
            
        case WFP_EVENT_HIDDEN_PROCESS_DETECTED:
            LOG_STRUCT(LOG_ERROR, "hidden_process",
                       "pid", event->pid,
                       NULL);
            break;
            
        default:
            break;
    }
}
#endif

/* === Initialization === */

static int init_logging(void) {
    const char* log_file = config_get_string(g_config, "log_file", NULL);
    log_level_t level = config_get_int(g_config, "log_level", LOG_INFO);
    
    if (logger_init(log_file, level) < 0) {
        fprintf(stderr, "Failed to initialize logger\n");
        return -1;
    }
    
    LOGF_INFO("Logging initialized (level: %s)", logger_level_to_string(level));
    return 0;
}

static int init_crypto(void) {
    LOGF_INFO("Initializing cryptography...");
    
    if (crypto_init() < 0) {
        LOGF_ERROR("Failed to initialize cryptography");
        return -1;
    }
    
    LOGF_INFO("Cryptography initialized");
    return 0;
}

static int init_stlc_core(void) {
    LOGF_INFO("Initializing STLC policy engine...");
    
    /* Create ontology */
    g_ontology = ontology_create();
    if (!g_ontology) {
        LOGF_ERROR("Failed to create ontology");
        return -1;
    }
    
    /* Create policy context */
    g_policy_context = context_create();
    if (!g_policy_context) {
        LOGF_ERROR("Failed to create policy context");
        return -1;
    }
    
    /* Initialize UCAN */
    if (ucan_init() < 0) {
        LOGF_ERROR("Failed to initialize UCAN");
        return -1;
    }
    
    /* Create owner DID */
    did_t* owner = ucan_did_create();
    if (!owner) {
        LOGF_ERROR("Failed to create owner DID");
        return -1;
    }
    
    LOGF_INFO("Owner DID: %s", owner->id);
    
    /* Create UCAN store */
    g_ucan_store = ucan_store_create(owner);
    if (!g_ucan_store) {
        LOGF_ERROR("Failed to create UCAN store");
        ucan_did_destroy(owner);
        return -1;
    }
    
    LOGF_INFO("STLC core initialized");
    return 0;
}

static int init_wasm_runtime(void) {
    if (!g_config || !g_config->enable_wasm) {
        LOGF_INFO("Wasm runtime disabled");
        return 0;
    }
    
    LOGF_INFO("Initializing WebAssembly runtime...");
    
    g_runtime = wasm_runtime_create();
    if (!g_runtime) {
        LOGF_ERROR("Failed to create Wasm runtime");
        return -1;
    }
    
    /* Set violation callback */
    wasm_runtime_set_violation_callback(g_runtime, on_policy_violation);
    
    LOGF_INFO("Wasm runtime initialized");
    return 0;
}

static int init_platform_monitoring(void) {
    LOGF_INFO("Initializing platform-specific monitoring...");
    
#ifdef PLATFORM_LINUX
    if (!g_config || !g_config->enable_ebpf) {
        LOGF_INFO("eBPF monitoring disabled");
        return 0;
    }
    
    if (getuid() != 0) {
        LOGF_WARN("Not running as root - eBPF monitoring requires root privileges");
        return 0;
    }
    
    if (ebpf_init(on_ebpf_event) < 0) {
        LOGF_WARN("Failed to initialize eBPF - continuing without kernel monitoring");
        return 0;
    }
    
    g_ebpf_initialized = 1;
    LOGF_INFO("eBPF monitoring active");
    
#elif defined(PLATFORM_MACOS)
    if (es_init() < 0) {
        LOGF_WARN("Failed to initialize Endpoint Security");
        return 0;
    }
    
    if (es_subscribe_process_events() < 0) {
        LOGF_WARN("Failed to subscribe to process events");
        es_cleanup();
        return 0;
    }
    
    if (es_subscribe_file_events() < 0) {
        LOGF_WARN("Failed to subscribe to file events");
    }
    
    es_set_event_callback(on_es_event, NULL);
    g_es_initialized = 1;
    LOGF_INFO("Endpoint Security monitoring active");
    
#elif defined(PLATFORM_WINDOWS)
    if (wfp_init() < 0) {
        LOGF_WARN("Failed to initialize WFP");
        return 0;
    }
    
    if (wfp_install_network_filters() < 0) {
        LOGF_WARN("Failed to install network filters");
    }
    
    if (wfp_install_process_monitor() < 0) {
        LOGF_WARN("Failed to install process monitor");
    }
    
    wfp_set_event_callback(on_wfp_event, NULL);
    g_wfp_initialized = 1;
    LOGF_INFO("WFP monitoring active");
#endif
    
    return 0;
}

static int init_framebuffer_ui(void) {
    if (!g_config || !g_config->enable_ui) {
        LOGF_INFO("UI disabled");
        return 0;
    }
    
    LOGF_INFO("Initializing framebuffer UI...");
    
    g_fb = fb_init();
    if (!g_fb) {
        LOGF_WARN("Failed to initialize framebuffer - continuing without UI");
        return 0;
    }
    
    LOGF_INFO("Framebuffer UI initialized: %dx%d", g_fb->screen_width, g_fb->screen_height);
    return 0;
}

static int init_ipfs_distribution(void) {
    LOGF_INFO("Initializing IPFS distribution...");
    
    g_distribution = ipfs_distribution_create();
    if (!g_distribution) {
        LOGF_WARN("Failed to create IPFS distribution");
        return 0;
    }
    
    ipfs_distribution_connect_bootstrap(g_distribution);
    
    LOGF_INFO("IPFS distribution initialized");
    return 0;
}

/* === Cleanup === */

static void cleanup(void) {
    LOGF_INFO("Cleaning up...");
    
#ifdef PLATFORM_LINUX
    if (g_ebpf_initialized) {
        ebpf_cleanup();
    }
#elif defined(PLATFORM_MACOS)
    if (g_es_initialized) {
        es_cleanup();
    }
#elif defined(PLATFORM_WINDOWS)
    if (g_wfp_initialized) {
        wfp_cleanup();
    }
#endif
    
    if (g_fb) {
        fb_cleanup(g_fb);
    }
    
    if (g_runtime) {
        wasm_runtime_destroy(g_runtime);
    }
    
    if (g_ucan_store) {
        ucan_store_destroy(g_ucan_store);
    }
    
    if (g_distribution) {
        ipfs_distribution_destroy(g_distribution);
    }
    
    if (g_ontology) {
        ontology_free(g_ontology);
    }
    
    if (g_policy_context) {
        context_free(g_policy_context);
    }
    
    logger_cleanup();
    
    if (g_config) {
        config_free(g_config);
    }
    
    /* Remove PID file */
    unlink(SOVEREIGN_PID_FILE);
    
    printf("[Sovereign] Shutdown complete\n");
}

/* === Main Loop === */

static void main_loop(void) {
    LOGF_INFO("Entering main monitoring loop");
    
    /* Show startup notification */
    if (g_fb) {
        alert_info_t startup = {
            .severity = ALERT_INFO,
            .timestamp = time(NULL)
        };
        strncpy(startup.title, "SOVEREIGN PRIVACY WIDGET", sizeof(startup.title));
        strncpy(startup.process_name, "System", sizeof(startup.process_name));
        strncpy(startup.violation_type, "Startup", sizeof(startup.violation_type));
        strncpy(startup.description, "Privacy monitoring active", sizeof(startup.description));
        strncpy(startup.resource, "All System Resources", sizeof(startup.resource));
        
        fb_render_alert(g_fb, &startup);
        sleep(3);
        fb_clear(g_fb);
    }
    
    int poll_count = 0;
    
    while (g_running) {
        /* Poll platform events */
#ifdef PLATFORM_LINUX
        if (g_ebpf_initialized) {
            ebpf_poll();
        }
#elif defined(PLATFORM_MACOS)
        /* ES events are delivered via callback */
        /* Periodically check for hidden processes */
        if (++poll_count % 1000 == 0) {
            es_detect_hidden_processes();
        }
#elif defined(PLATFORM_WINDOWS)
        /* WFP events are delivered via callback */
#endif
        
        /* Periodic tasks */
        if (++poll_count % 500 == 0) {
            /* Update ontology with current process list */
            if (g_ontology) {
                policy_update_ontology(g_ontology);
            }
        }
        
        /* Check for config reload (SIGHUP) */
        /* Handled in signal handler */
        
        usleep(10000); /* 10ms */
    }
    
    LOGF_INFO("Main loop exiting");
}

/* === Daemon Mode === */

static int daemonize(void) {
    LOGF_INFO("Daemonizing...");
    
    pid_t pid = fork();
    if (pid < 0) {
        LOGF_ERROR("Failed to fork: %s", strerror(errno));
        return -1;
    }
    if (pid > 0) {
        /* Parent exits */
        exit(0);
    }
    
    /* Child process */
    if (setsid() < 0) {
        LOGF_ERROR("Failed to create new session: %s", strerror(errno));
        return -1;
    }
    
    /* Fork again to prevent acquiring controlling terminal */
    pid = fork();
    if (pid < 0) {
        LOGF_ERROR("Failed to fork: %s", strerror(errno));
        return -1;
    }
    if (pid > 0) {
        exit(0);
    }
    
    /* Change to root directory */
    chdir("/");
    
    /* Close file descriptors */
    close(STDIN_FILENO);
    close(STDOUT_FILENO);
    close(STDERR_FILENO);
    
    /* Write PID file */
    FILE* pid_file = fopen(SOVEREIGN_PID_FILE, "w");
    if (pid_file) {
        fprintf(pid_file, "%d\n", getpid());
        fclose(pid_file);
    }
    
    LOGF_INFO("Daemon running (PID: %d)", getpid());
    return 0;
}

/* === Command Line Interface === */

static void print_usage(const char* prog) {
    printf("Usage: %s [options]\n", prog);
    printf("\n%s v%s - Cross-platform privacy monitoring system\n", 
           SOVEREIGN_NAME, SOVEREIGN_VERSION);
    printf("Based on formally verified STLC core\n\n");
    printf("Options:\n");
    printf("  -h, --help          Show this help message\n");
    printf("  -v, --version       Show version information\n");
    printf("  -d, --daemon        Run as daemon\n");
    printf("  -c, --config FILE   Use config file (default: %s)\n", SOVEREIGN_CONFIG_PATH);
    printf("  --cid CID           Load widget from IPFS CID\n");
    printf("  -w, --wasm FILE     Load Wasm module from file\n");
    printf("  -p, --pid PID       Monitor specific process\n");
    printf("  -b, --block         Block mode (terminate violations)\n");
    printf("  -n, --notify        Show UI notifications\n");
    printf("  --no-ui             Disable UI even if config enables it\n");
    printf("  --no-ebpf           Disable eBPF even if config enables it\n");
    printf("\n");
}

static void print_version(void) {
    printf("%s v%s\n", SOVEREIGN_NAME, SOVEREIGN_VERSION);
    printf("Cross-platform privacy monitoring system\n");
    printf("Based on formally verified STLC core (Coq-extracted)\n");
    printf("\nFeatures:\n");
#ifdef PLATFORM_LINUX
    printf("  - eBPF kernel monitoring\n");
#elif defined(PLATFORM_MACOS)
    printf("  - Endpoint Security Framework\n");
#elif defined(PLATFORM_WINDOWS)
    printf("  - Windows Filtering Platform\n");
#endif
    printf("  - WebAssembly runtime\n");
    printf("  - UCAN authorization\n");
    printf("  - IPFS distribution\n");
    printf("  - Framebuffer UI\n");
    printf("\n");
}

/* === Main Entry Point === */

int main(int argc, char* argv[]) {
    int opt;
    char* config_path = SOVEREIGN_CONFIG_PATH;
    char* cid = NULL;
    char* wasm_file = NULL;
    uint32_t target_pid = 0;
    bool daemon_mode = false;
    bool block_mode = false;
    bool notify_mode = false;
    bool no_ui = false;
    bool no_ebpf = false;
    
    static struct option long_options[] = {
        {"help", no_argument, 0, 'h'},
        {"version", no_argument, 0, 'v'},
        {"daemon", no_argument, 0, 'd'},
        {"config", required_argument, 0, 'c'},
        {"cid", required_argument, 0, 'C'},
        {"wasm", required_argument, 0, 'w'},
        {"pid", required_argument, 0, 'p'},
        {"block", no_argument, 0, 'b'},
        {"notify", no_argument, 0, 'n'},
        {"no-ui", no_argument, 0, 'U'},
        {"no-ebpf", no_argument, 0, 'E'},
        {0, 0, 0, 0}
    };
    
    while ((opt = getopt_long(argc, argv, "hvdc:C:w:p:bnUE", long_options, NULL)) != -1) {
        switch (opt) {
            case 'h':
                print_usage(argv[0]);
                return 0;
            case 'v':
                print_version();
                return 0;
            case 'd':
                daemon_mode = true;
                break;
            case 'c':
                config_path = optarg;
                break;
            case 'C':
                cid = optarg;
                break;
            case 'w':
                wasm_file = optarg;
                break;
            case 'p':
                target_pid = atoi(optarg);
                break;
            case 'b':
                block_mode = true;
                break;
            case 'n':
                notify_mode = true;
                break;
            case 'U':
                no_ui = true;
                break;
            case 'E':
                no_ebpf = true;
                break;
            default:
                print_usage(argv[0]);
                return 1;
        }
    }
    
    /* Print banner */
    printf("\n");
    printf("========================================\n");
    printf("  %s\n", SOVEREIGN_NAME);
    printf("  Version %s\n", SOVEREIGN_VERSION);
    printf("========================================\n");
    printf("\n");
    
    /* Load configuration */
    g_config = config_load(config_path);
    if (!g_config) {
        fprintf(stderr, "Failed to load configuration\n");
        return 1;
    }
    
    /* Override config with command line options */
    if (no_ui) g_config->enable_ui = false;
    if (no_ebpf) g_config->enable_ebpf = false;
    if (notify_mode) g_config->alert_on_violation = true;
    if (block_mode) g_config->auto_block_violations = true;
    
    /* Initialize logging first */
    if (init_logging() < 0) {
        fprintf(stderr, "Failed to initialize logging\n");
        config_free(g_config);
        return 1;
    }
    
    LOGF_INFO("Starting %s v%s", SOVEREIGN_NAME, SOVEREIGN_VERSION);
    
    /* Set up signal handlers */
    setup_signal_handlers();
    
    /* Daemonize if requested */
    if (daemon_mode || g_config->daemon_mode) {
        if (daemonize() < 0) {
            LOGF_ERROR("Failed to daemonize");
            cleanup();
            return 1;
        }
    }
    
    /* Initialize components */
    if (init_crypto() < 0) {
        LOGF_ERROR("Failed to initialize crypto");
        cleanup();
        return 1;
    }
    
    if (init_stlc_core() < 0) {
        LOGF_ERROR("Failed to initialize STLC core");
        cleanup();
        return 1;
    }
    
    if (init_wasm_runtime() < 0) {
        LOGF_WARN("Failed to initialize Wasm runtime");
        /* Continue without Wasm */
    }
    
    if (init_platform_monitoring() < 0) {
        LOGF_WARN("Platform monitoring not fully available");
    }
    
    if (init_framebuffer_ui() < 0) {
        LOGF_WARN("UI not available");
    }
    
    if (init_ipfs_distribution() < 0) {
        LOGF_WARN("IPFS distribution not available");
    }
    
    /* Load Wasm module if specified */
    if (wasm_file && g_runtime) {
        LOGF_INFO("Loading Wasm module: %s", wasm_file);
        
        FILE* f = fopen(wasm_file, "rb");
        if (f) {
            fseek(f, 0, SEEK_END);
            size_t size = ftell(f);
            fseek(f, 0, SEEK_SET);
            
            uint8_t* wasm = malloc(size);
            fread(wasm, 1, size, f);
            fclose(f);
            
            wasm_runtime_load_module(g_runtime, wasm, size);
            free(wasm);
            
            LOGF_INFO("Wasm module loaded");
        } else {
            LOGF_ERROR("Failed to load Wasm file: %s", wasm_file);
        }
    }
    
    /* Fetch from IPFS if CID specified */
    if (cid && g_distribution) {
        LOGF_INFO("Fetching widget from IPFS: %s", cid);
        
        ipfs_dag_t* dag = ipfs_distribution_fetch(g_distribution, cid);
        if (dag) {
            LOGF_INFO("Widget loaded from IPFS");
        } else {
            LOGF_ERROR("Failed to fetch from IPFS");
        }
    }
    
    /* Monitor specific process if specified */
    if (target_pid > 0 && g_ontology) {
        LOGF_INFO("Monitoring PID: %u", target_pid);
        
        entity_t* target = ontology_add_entity(g_ontology, "target_process",
                                                RESOURCE_PROCESS, target_pid);
        if (target) {
            LOGF_INFO("Target process registered");
        }
    }
    
    /* Run main loop */
    main_loop();
    
    /* Cleanup */
    cleanup();
    
    return 0;
}
