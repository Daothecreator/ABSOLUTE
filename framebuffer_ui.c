/*
 * Framebuffer UI Renderer
 * Direct pixel rendering for isolated privacy alerts
 * No dependency on OS GUI frameworks
 * 
 * License: MIT
 * Version: 1.0 (April 2026)
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <stdbool.h>
#include <fcntl.h>
#include <unistd.h>
#include <sys/mman.h>
#include <sys/ioctl.h>
#include <linux/fb.h>
#include <linux/input.h>
#include "../core/stlc_policy_engine.h"

/* === Constants === */

#define FB_DEVICE "/dev/fb0"
#define INPUT_DEVICE "/dev/input/event0"

/* Colors (ARGB) */
#define COLOR_BLACK     0xFF000000
#define COLOR_WHITE     0xFFFFFFFF
#define COLOR_RED       0xFFFF0000
#define COLOR_GREEN     0xFF00FF00
#define COLOR_BLUE      0xFF0000FF
#define COLOR_YELLOW    0xFFFFFF00
#define COLOR_ORANGE    0xFFFFA500
#define COLOR_GRAY      0xFF808080
#define COLOR_DARK_RED  0xFF8B0000

/* UI Dimensions */
#define ALERT_WIDTH     600
#define ALERT_HEIGHT    400
#define BORDER_WIDTH    4
#define PADDING         20
#define TITLE_HEIGHT    40
#define LINE_HEIGHT     20

/* Font (8x8 bitmap for ASCII) */
#define FONT_WIDTH  8
#define FONT_HEIGHT 8

/* === Data Structures === */

typedef struct fb_context_s {
    int fb_fd;
    int input_fd;
    
    uint8_t *fb_mem;
    size_t fb_size;
    
    struct fb_var_screeninfo vinfo;
    struct fb_fix_screeninfo finfo;
    
    uint32_t screen_width;
    uint32_t screen_height;
    uint32_t bytes_per_pixel;
    uint32_t line_length;
    
    bool is_active;
} fb_context_t;

typedef struct alert_info_s {
    char title[128];
    char process_name[256];
    uint32_t pid;
    char violation_type[128];
    char description[512];
    char resource[128];
    uint32_t severity;  /* 1-5 */
    uint64_t timestamp;
} alert_info_t;

/* === 8x8 Font Bitmap (simplified ASCII) === */

static const uint8_t font_8x8[128][8] = {
    /* Space */ {0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00},
    /* ! */     {0x18, 0x18, 0x18, 0x18, 0x18, 0x00, 0x18, 0x00},
    /* " */     {0x66, 0x66, 0x66, 0x00, 0x00, 0x00, 0x00, 0x00},
    /* # */     {0x66, 0x66, 0xFF, 0x66, 0xFF, 0x66, 0x66, 0x00},
    /* $ */     {0x18, 0x3E, 0x60, 0x3C, 0x06, 0x7C, 0x18, 0x00},
    /* % */     {0x62, 0x66, 0x0C, 0x18, 0x30, 0x66, 0x46, 0x00},
    /* & */     {0x3C, 0x66, 0x3C, 0x38, 0x67, 0x66, 0x3F, 0x00},
    /* ' */     {0x06, 0x0C, 0x18, 0x00, 0x00, 0x00, 0x00, 0x00},
    /* ( */     {0x0C, 0x18, 0x30, 0x30, 0x30, 0x18, 0x0C, 0x00},
    /* ) */     {0x30, 0x18, 0x0C, 0x0C, 0x0C, 0x18, 0x30, 0x00},
    /* * */     {0x00, 0x66, 0x3C, 0xFF, 0x3C, 0x66, 0x00, 0x00},
    /* + */     {0x00, 0x18, 0x18, 0x7E, 0x18, 0x18, 0x00, 0x00},
    /* , */     {0x00, 0x00, 0x00, 0x00, 0x00, 0x18, 0x18, 0x30},
    /* - */     {0x00, 0x00, 0x00, 0x7E, 0x00, 0x00, 0x00, 0x00},
    /* . */     {0x00, 0x00, 0x00, 0x00, 0x00, 0x18, 0x18, 0x00},
    /* / */     {0x00, 0x03, 0x06, 0x0C, 0x18, 0x30, 0x60, 0x00},
    /* 0-9 */
    {0x3C, 0x66, 0x6E, 0x76, 0x66, 0x66, 0x3C, 0x00}, /* 0 */
    {0x18, 0x38, 0x18, 0x18, 0x18, 0x18, 0x7E, 0x00}, /* 1 */
    {0x3C, 0x66, 0x06, 0x0C, 0x30, 0x60, 0x7E, 0x00}, /* 2 */
    {0x3C, 0x66, 0x06, 0x1C, 0x06, 0x66, 0x3C, 0x00}, /* 3 */
    {0x06, 0x0E, 0x1E, 0x66, 0x7F, 0x06, 0x06, 0x00}, /* 4 */
    {0x7E, 0x60, 0x7C, 0x06, 0x06, 0x66, 0x3C, 0x00}, /* 5 */
    {0x3C, 0x66, 0x60, 0x7C, 0x66, 0x66, 0x3C, 0x00}, /* 6 */
    {0x7E, 0x06, 0x0C, 0x18, 0x30, 0x30, 0x30, 0x00}, /* 7 */
    {0x3C, 0x66, 0x66, 0x3C, 0x66, 0x66, 0x3C, 0x00}, /* 8 */
    {0x3C, 0x66, 0x66, 0x3E, 0x06, 0x66, 0x3C, 0x00}, /* 9 */
    /* : */     {0x00, 0x18, 0x18, 0x00, 0x00, 0x18, 0x18, 0x00},
    /* ; */     {0x00, 0x18, 0x18, 0x00, 0x00, 0x18, 0x18, 0x30},
    /* < */     {0x0E, 0x18, 0x30, 0x60, 0x30, 0x18, 0x0E, 0x00},
    /* = */     {0x00, 0x00, 0x7E, 0x00, 0x7E, 0x00, 0x00, 0x00},
    /* > */     {0x70, 0x18, 0x0C, 0x06, 0x0C, 0x18, 0x70, 0x00},
    /* ? */     {0x3C, 0x66, 0x06, 0x0C, 0x18, 0x00, 0x18, 0x00},
    /* @ */     {0x3C, 0x66, 0x6E, 0x6E, 0x60, 0x62, 0x3C, 0x00},
    /* A-Z */
    {0x18, 0x3C, 0x66, 0x7E, 0x66, 0x66, 0x66, 0x00}, /* A */
    {0x7C, 0x66, 0x66, 0x7C, 0x66, 0x66, 0x7C, 0x00}, /* B */
    {0x3C, 0x66, 0x60, 0x60, 0x60, 0x66, 0x3C, 0x00}, /* C */
    {0x78, 0x6C, 0x66, 0x66, 0x66, 0x6C, 0x78, 0x00}, /* D */
    {0x7E, 0x60, 0x60, 0x78, 0x60, 0x60, 0x7E, 0x00}, /* E */
    {0x7E, 0x60, 0x60, 0x78, 0x60, 0x60, 0x60, 0x00}, /* F */
    {0x3C, 0x66, 0x60, 0x6E, 0x66, 0x66, 0x3C, 0x00}, /* G */
    {0x66, 0x66, 0x66, 0x7E, 0x66, 0x66, 0x66, 0x00}, /* H */
    {0x3C, 0x18, 0x18, 0x18, 0x18, 0x18, 0x3C, 0x00}, /* I */
    {0x1E, 0x0C, 0x0C, 0x0C, 0x0C, 0x6C, 0x38, 0x00}, /* J */
    {0x66, 0x6C, 0x78, 0x70, 0x78, 0x6C, 0x66, 0x00}, /* K */
    {0x60, 0x60, 0x60, 0x60, 0x60, 0x60, 0x7E, 0x00}, /* L */
    {0x63, 0x77, 0x7F, 0x6B, 0x63, 0x63, 0x63, 0x00}, /* M */
    {0x66, 0x76, 0x7E, 0x7E, 0x6E, 0x66, 0x66, 0x00}, /* N */
    {0x3C, 0x66, 0x66, 0x66, 0x66, 0x66, 0x3C, 0x00}, /* O */
    {0x7C, 0x66, 0x66, 0x7C, 0x60, 0x60, 0x60, 0x00}, /* P */
    {0x3C, 0x66, 0x66, 0x66, 0x66, 0x3C, 0x0E, 0x00}, /* Q */
    {0x7C, 0x66, 0x66, 0x7C, 0x78, 0x6C, 0x66, 0x00}, /* R */
    {0x3C, 0x66, 0x60, 0x3C, 0x06, 0x66, 0x3C, 0x00}, /* S */
    {0x7E, 0x18, 0x18, 0x18, 0x18, 0x18, 0x18, 0x00}, /* T */
    {0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x3C, 0x00}, /* U */
    {0x66, 0x66, 0x66, 0x66, 0x66, 0x3C, 0x18, 0x00}, /* V */
    {0x63, 0x63, 0x63, 0x6B, 0x7F, 0x77, 0x63, 0x00}, /* W */
    {0x66, 0x66, 0x3C, 0x18, 0x3C, 0x66, 0x66, 0x00}, /* X */
    {0x66, 0x66, 0x66, 0x3C, 0x18, 0x18, 0x18, 0x00}, /* Y */
    {0x7E, 0x06, 0x0C, 0x18, 0x30, 0x60, 0x7E, 0x00}, /* Z */
    /* [ */     {0x3C, 0x30, 0x30, 0x30, 0x30, 0x30, 0x3C, 0x00},
    /* \ */     {0x00, 0x60, 0x30, 0x18, 0x0C, 0x06, 0x03, 0x00},
    /* ] */     {0x3C, 0x0C, 0x0C, 0x0C, 0x0C, 0x0C, 0x3C, 0x00},
    /* ^ */     {0x18, 0x3C, 0x66, 0x00, 0x00, 0x00, 0x00, 0x00},
    /* _ */     {0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xFF},
    /* ` */     {0x30, 0x18, 0x0C, 0x00, 0x00, 0x00, 0x00, 0x00},
    /* a-z (lowercase) */
    {0x00, 0x00, 0x3C, 0x06, 0x3E, 0x66, 0x3E, 0x00}, /* a */
    {0x00, 0x60, 0x60, 0x7C, 0x66, 0x66, 0x7C, 0x00}, /* b */
    {0x00, 0x00, 0x3C, 0x60, 0x60, 0x60, 0x3C, 0x00}, /* c */
    {0x00, 0x06, 0x06, 0x3E, 0x66, 0x66, 0x3E, 0x00}, /* d */
    {0x00, 0x00, 0x3C, 0x66, 0x7E, 0x60, 0x3C, 0x00}, /* e */
    {0x00, 0x0E, 0x18, 0x3E, 0x18, 0x18, 0x18, 0x00}, /* f */
    {0x00, 0x00, 0x3E, 0x66, 0x66, 0x3E, 0x06, 0x7C}, /* g */
    {0x00, 0x60, 0x60, 0x7C, 0x66, 0x66, 0x66, 0x00}, /* h */
    {0x00, 0x18, 0x00, 0x38, 0x18, 0x18, 0x3C, 0x00}, /* i */
    {0x00, 0x06, 0x00, 0x06, 0x06, 0x06, 0x06, 0x3C}, /* j */
    {0x00, 0x60, 0x60, 0x6C, 0x78, 0x6C, 0x66, 0x00}, /* k */
    {0x00, 0x38, 0x18, 0x18, 0x18, 0x18, 0x3C, 0x00}, /* l */
    {0x00, 0x00, 0x66, 0x7F, 0x7F, 0x6B, 0x63, 0x00}, /* m */
    {0x00, 0x00, 0x7C, 0x66, 0x66, 0x66, 0x66, 0x00}, /* n */
    {0x00, 0x00, 0x3C, 0x66, 0x66, 0x66, 0x3C, 0x00}, /* o */
    {0x00, 0x00, 0x7C, 0x66, 0x66, 0x7C, 0x60, 0x60}, /* p */
    {0x00, 0x00, 0x3E, 0x66, 0x66, 0x3E, 0x06, 0x06}, /* q */
    {0x00, 0x00, 0x7C, 0x66, 0x60, 0x60, 0x60, 0x00}, /* r */
    {0x00, 0x00, 0x3E, 0x60, 0x3C, 0x06, 0x7C, 0x00}, /* s */
    {0x00, 0x18, 0x7E, 0x18, 0x18, 0x18, 0x0E, 0x00}, /* t */
    {0x00, 0x00, 0x66, 0x66, 0x66, 0x66, 0x3E, 0x00}, /* u */
    {0x00, 0x00, 0x66, 0x66, 0x66, 0x3C, 0x18, 0x00}, /* v */
    {0x00, 0x00, 0x63, 0x6B, 0x7F, 0x3E, 0x36, 0x00}, /* w */
    {0x00, 0x00, 0x66, 0x3C, 0x18, 0x3C, 0x66, 0x00}, /* x */
    {0x00, 0x00, 0x66, 0x66, 0x66, 0x3E, 0x0C, 0x78}, /* y */
    {0x00, 0x00, 0x7E, 0x0C, 0x18, 0x30, 0x7E, 0x00}, /* z */
};

/* === Framebuffer Operations === */

fb_context_t* fb_init(void) {
    fb_context_t *ctx = calloc(1, sizeof(fb_context_t));
    if (!ctx) return NULL;
    
    /* Open framebuffer device */
    ctx->fb_fd = open(FB_DEVICE, O_RDWR);
    if (ctx->fb_fd < 0) {
        fprintf(stderr, "Failed to open framebuffer: %s\n", FB_DEVICE);
        free(ctx);
        return NULL;
    }
    
    /* Get fixed screen info */
    if (ioctl(ctx->fb_fd, FBIOGET_FSCREENINFO, &ctx->finfo) < 0) {
        perror("FBIOGET_FSCREENINFO");
        close(ctx->fb_fd);
        free(ctx);
        return NULL;
    }
    
    /* Get variable screen info */
    if (ioctl(ctx->fb_fd, FBIOGET_VSCREENINFO, &ctx->vinfo) < 0) {
        perror("FBIOGET_VSCREENINFO");
        close(ctx->fb_fd);
        free(ctx);
        return NULL;
    }
    
    ctx->screen_width = ctx->vinfo.xres;
    ctx->screen_height = ctx->vinfo.yres;
    ctx->bytes_per_pixel = ctx->vinfo.bits_per_pixel / 8;
    ctx->line_length = ctx->finfo.line_length;
    
    /* Map framebuffer memory */
    ctx->fb_size = ctx->finfo.smem_len;
    ctx->fb_mem = mmap(NULL, ctx->fb_size, 
                       PROT_READ | PROT_WRITE, MAP_SHARED,
                       ctx->fb_fd, 0);
    
    if (ctx->fb_mem == MAP_FAILED) {
        perror("mmap");
        close(ctx->fb_fd);
        free(ctx);
        return NULL;
    }
    
    ctx->is_active = true;
    
    printf("[UI] Framebuffer: %dx%d, %d bpp\n",
           ctx->screen_width, ctx->screen_height, ctx->vinfo.bits_per_pixel);
    
    return ctx;
}

void fb_cleanup(fb_context_t *ctx) {
    if (!ctx) return;
    
    if (ctx->fb_mem != MAP_FAILED) {
        munmap(ctx->fb_mem, ctx->fb_size);
    }
    
    if (ctx->fb_fd >= 0) {
        close(ctx->fb_fd);
    }
    
    free(ctx);
}

/* === Drawing Functions === */

static void fb_set_pixel(fb_context_t *ctx, uint32_t x, uint32_t y, uint32_t color) {
    if (!ctx || !ctx->fb_mem) return;
    if (x >= ctx->screen_width || y >= ctx->screen_height) return;
    
    uint32_t offset = (y * ctx->line_length) + (x * ctx->bytes_per_pixel);
    
    if (ctx->bytes_per_pixel == 4) {
        *(uint32_t*)(ctx->fb_mem + offset) = color;
    } else if (ctx->bytes_per_pixel == 2) {
        *(uint16_t*)(ctx->fb_mem + offset) = (uint16_t)color;
    }
}

static void fb_draw_rect(fb_context_t *ctx, uint32_t x, uint32_t y,
                         uint32_t w, uint32_t h, uint32_t color) {
    for (uint32_t dy = 0; dy < h && (y + dy) < ctx->screen_height; dy++) {
        for (uint32_t dx = 0; dx < w && (x + dx) < ctx->screen_width; dx++) {
            fb_set_pixel(ctx, x + dx, y + dy, color);
        }
    }
}

static void fb_draw_char(fb_context_t *ctx, uint32_t x, uint32_t y,
                         char c, uint32_t color) {
    if (c < 0 || c > 127) c = '?';
    
    const uint8_t *bitmap = font_8x8[(int)c];
    
    for (int row = 0; row < FONT_HEIGHT; row++) {
        for (int col = 0; col < FONT_WIDTH; col++) {
            if (bitmap[row] & (1 << (7 - col))) {
                fb_set_pixel(ctx, x + col, y + row, color);
            }
        }
    }
}

static void fb_draw_string(fb_context_t *ctx, uint32_t x, uint32_t y,
                           const char *str, uint32_t color) {
    uint32_t cx = x;
    
    while (*str) {
        if (*str == '\n') {
            y += FONT_HEIGHT + 2;
            cx = x;
        } else {
            fb_draw_char(ctx, cx, y, *str, color);
            cx += FONT_WIDTH;
        }
        str++;
    }
}

/* === Alert Rendering === */

void fb_render_alert(fb_context_t *ctx, alert_info_t *alert) {
    if (!ctx || !alert) return;
    
    /* Calculate alert position (centered) */
    uint32_t alert_x = (ctx->screen_width - ALERT_WIDTH) / 2;
    uint32_t alert_y = (ctx->screen_height - ALERT_HEIGHT) / 2;
    
    /* Determine color based on severity */
    uint32_t border_color, bg_color;
    switch (alert->severity) {
        case 1: /* INFO */
            border_color = COLOR_BLUE;
            bg_color = 0xFF001133;
            break;
        case 2: /* LOW */
            border_color = COLOR_GREEN;
            bg_color = 0xFF003300;
            break;
        case 3: /* MEDIUM */
            border_color = COLOR_YELLOW;
            bg_color = 0xFF333300;
            break;
        case 4: /* HIGH */
            border_color = COLOR_ORANGE;
            bg_color = 0xFF331900;
            break;
        case 5: /* CRITICAL */
        default:
            border_color = COLOR_RED;
            bg_color = COLOR_DARK_RED;
            break;
    }
    
    /* Draw border */
    fb_draw_rect(ctx, alert_x, alert_y, ALERT_WIDTH, ALERT_HEIGHT, border_color);
    
    /* Draw background */
    fb_draw_rect(ctx, alert_x + BORDER_WIDTH, alert_y + BORDER_WIDTH,
                 ALERT_WIDTH - 2 * BORDER_WIDTH, ALERT_HEIGHT - 2 * BORDER_WIDTH,
                 bg_color);
    
    /* Draw title bar */
    fb_draw_rect(ctx, alert_x + BORDER_WIDTH, alert_y + BORDER_WIDTH,
                 ALERT_WIDTH - 2 * BORDER_WIDTH, TITLE_HEIGHT, border_color);
    
    /* Draw title */
    uint32_t text_x = alert_x + BORDER_WIDTH + PADDING;
    uint32_t text_y = alert_y + BORDER_WIDTH + 10;
    fb_draw_string(ctx, text_x, text_y, alert->title, COLOR_WHITE);
    
    /* Draw content */
    text_y += TITLE_HEIGHT + PADDING;
    
    char line[256];
    
    snprintf(line, sizeof(line), "Process: %s (PID: %u)", 
             alert->process_name, alert->pid);
    fb_draw_string(ctx, text_x, text_y, line, COLOR_WHITE);
    text_y += LINE_HEIGHT + 5;
    
    snprintf(line, sizeof(line), "Violation: %s", alert->violation_type);
    fb_draw_string(ctx, text_x, text_y, line, COLOR_WHITE);
    text_y += LINE_HEIGHT + 5;
    
    snprintf(line, sizeof(line), "Resource: %s", alert->resource);
    fb_draw_string(ctx, text_x, text_y, line, COLOR_WHITE);
    text_y += LINE_HEIGHT + 10;
    
    fb_draw_string(ctx, text_x, text_y, "Description:", COLOR_WHITE);
    text_y += LINE_HEIGHT + 2;
    fb_draw_string(ctx, text_x, text_y, alert->description, COLOR_WHITE);
    text_y += LINE_HEIGHT * 2 + 10;
    
    /* Draw action buttons */
    fb_draw_rect(ctx, text_x, text_y, 120, 30, COLOR_RED);
    fb_draw_string(ctx, text_x + 10, text_y + 8, "[BLOCK]", COLOR_WHITE);
    
    fb_draw_rect(ctx, text_x + 140, text_y, 120, 30, COLOR_GRAY);
    fb_draw_string(ctx, text_x + 150, text_y + 8, "[ALLOW]", COLOR_WHITE);
}

void fb_clear(fb_context_t *ctx) {
    if (!ctx) return;
    memset(ctx->fb_mem, 0, ctx->fb_size);
}

/* === Alert Creation === */

alert_info_t* alert_create_from_decision(policy_decision_t *decision,
                                          entity_t *subject,
                                          entity_t *object) {
    if (!decision) return NULL;
    
    alert_info_t *alert = calloc(1, sizeof(alert_info_t));
    if (!alert) return NULL;
    
    strncpy(alert->title, "PRIVACY VIOLATION DETECTED", sizeof(alert->title) - 1);
    
    if (subject) {
        strncpy(alert->process_name, subject->name, sizeof(alert->process_name) - 1);
        alert->pid = subject->pid;
    }
    
    strncpy(alert->violation_type, "Unauthorized Access Attempt", 
            sizeof(alert->violation_type) - 1);
    strncpy(alert->description, decision->reason, sizeof(alert->description) - 1);
    
    if (object) {
        strncpy(alert->resource, object->name, sizeof(alert->resource) - 1);
    }
    
    alert->severity = 4; /* HIGH */
    alert->timestamp = decision->decision_time;
    
    return alert;
}
