/*
 * vim:ts=4:sw=4:expandtab
 *
 * © 2010 Michael Stapelberg
 *
 * See LICENSE for licensing information
 *
 */
#include <stdbool.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <math.h>
#include <xcb/xcb.h>
#include <xkbcommon/xkbcommon.h>
#include <ev.h>
#include <cairo.h>
#include <cairo/cairo-xcb.h>

#include "i3lock.h"
#include "xcb.h"
#include "unlock_indicator.h"
#include "randr.h"
#include "dpi.h"

#define BUTTON_RADIUS 90
#define BUTTON_SPACE (BUTTON_RADIUS + 5)
#define BUTTON_CENTER (BUTTON_RADIUS + 5)
#define BUTTON_DIAMETER (2 * BUTTON_SPACE)
#define PAM_TEXT_ELLIPSIS "..."
#define PAM_PANEL_MAX_WIDTH 560.0
#define PAM_PANEL_EDGE_MARGIN 24.0
#define PAM_PANEL_VERTICAL_EDGE_MARGIN 8.0
#define PAM_PANEL_PADDING_X 12.0
#define PAM_PANEL_PADDING_Y 10.0
#define PAM_PANEL_GAP 14.0
#define PAM_PANEL_CORNER_RADIUS 6.0
#define PAM_PANEL_MAX_LINES 5
#define PAM_PANEL_STATUS_MAX_LINES 3
#define PAM_PANEL_PROMPT_MAX_LINES 2
#define PAM_PANEL_STATUS_FONT_SIZE 13.0
#define PAM_PANEL_PROMPT_FONT_SIZE 15.0
#define PAM_PANEL_STATUS_LINE_HEIGHT 17.0
#define PAM_PANEL_PROMPT_LINE_HEIGHT 20.0
#define PAM_PANEL_LINE_GAP 3.0
#define PAM_PANEL_SECTION_GAP 5.0

/*******************************************************************************
 * Variables defined in i3lock.c.
 ******************************************************************************/

extern bool debug_mode;

/* The current position in the input buffer. Useful to determine if any
 * characters of the password have already been entered or not. */
extern int input_position;

/* The lock window. */
extern xcb_window_t win;

/* The current resolution of the X11 root window. */
extern uint32_t last_resolution[2];

/* Whether the unlock indicator is enabled (defaults to true). */
extern bool unlock_indicator;

/* List of pressed modifiers, or NULL if none are pressed. */
extern char *modifier_string;
/* Name of the current keyboard layout or NULL if not initialized. */
char *layout_string = NULL;

/* A Cairo surface containing the specified image (-i), if any. */
extern cairo_surface_t *img;

/* Whether the image should be tiled. */
extern bool tile;
/* The background color to use (in hex). */
extern char color[7];

/* Whether the failed attempts should be displayed. */
extern bool show_failed_attempts;
/* Whether keyboard layout should be displayed. */
extern bool show_keyboard_layout;
/* Number of failed unlock attempts. */
extern int failed_attempts;

extern struct xkb_keymap *xkb_keymap;
extern struct xkb_state *xkb_state;

/*******************************************************************************
 * Variables defined in xcb.c.
 ******************************************************************************/

/* The root screen, to determine the DPI. */
extern xcb_screen_t *screen;

/*******************************************************************************
 * Local variables.
 ******************************************************************************/

/* Cache the screen’s visual, necessary for creating a Cairo context. */
static xcb_visualtype_t *vistype;

/* Maintain the current unlock/PAM state to draw the appropriate unlock
 * indicator. */
unlock_state_t unlock_state;
auth_state_t auth_state;

static void string_append(char **string_ptr, const char *appended) {
    char *tmp = NULL;
    if (*string_ptr == NULL) {
        if (asprintf(&tmp, "%s", appended) != -1) {
            *string_ptr = tmp;
        }
    } else if (asprintf(&tmp, "%s, %s", *string_ptr, appended) != -1) {
        free(*string_ptr);
        *string_ptr = tmp;
    }
}

static void display_button_text(
    cairo_t *ctx, const char *text, double y_offset, bool use_dark_text) {
    cairo_text_extents_t extents;
    double x, y;

    cairo_text_extents(ctx, text, &extents);
    x = BUTTON_CENTER - ((extents.width / 2) + extents.x_bearing);
    y = BUTTON_CENTER - ((extents.height / 2) + extents.y_bearing) + y_offset;

    cairo_move_to(ctx, x, y);
    if (use_dark_text) {
        cairo_set_source_rgb(ctx, 0., 0., 0.);
    } else {
        cairo_set_source_rgb(ctx, 1., 1., 1.);
    }
    cairo_show_text(ctx, text);
    cairo_close_path(ctx);
}

static bool is_utf8_continuation_byte(unsigned char byte) {
    return (byte & 0xC0) == 0x80;
}

static size_t utf8_truncate_to_char_boundary(const char *s, size_t len) {
    while (len > 0 && is_utf8_continuation_byte((unsigned char)s[len])) {
        len--;
    }
    return len;
}

static void truncate_text_to_width(cairo_t *ctx, const char *text, double max_width, char *output, size_t output_size) {
    cairo_text_extents_t extents;
    const size_t ellipsis_len = strlen(PAM_TEXT_ELLIPSIS);
    size_t len;

    if (output_size == 0) {
        return;
    }

    snprintf(output, output_size, "%s", text);
    cairo_text_extents(ctx, output, &extents);
    if (extents.width <= max_width) {
        return;
    }

    if (output_size <= ellipsis_len + 1) {
        output[0] = '\0';
        return;
    }

    len = strlen(text);
    if (len > output_size - ellipsis_len - 1) {
        len = output_size - ellipsis_len - 1;
    }

    while (len > 0) {
        len = utf8_truncate_to_char_boundary(text, len);
        memcpy(output, text, len);
        output[len] = '\0';
        strncat(output, PAM_TEXT_ELLIPSIS, output_size - strlen(output) - 1);
        cairo_text_extents(ctx, output, &extents);
        if (extents.width <= max_width) {
            return;
        }
        len--;
    }

    snprintf(output, output_size, "%s", PAM_TEXT_ELLIPSIS);
}

static void display_button_text_bounded(cairo_t *ctx,
                                        const char *text,
                                        double y_offset,
                                        bool use_dark_text,
                                        double max_width) {
    char bounded_text[I3LOCK_PAM_VISIBLE_INPUT_MAX + sizeof(PAM_TEXT_ELLIPSIS)];

    truncate_text_to_width(ctx, text, max_width, bounded_text, sizeof(bounded_text));
    display_button_text(ctx, bounded_text, y_offset, use_dark_text);
}

typedef enum {
    PAM_PANEL_STATUS_LINE,
    PAM_PANEL_PROMPT_LINE,
} pam_panel_line_kind_t;

typedef struct {
    char text[I3LOCK_PAM_DISPLAY_TEXT_MAX + sizeof(PAM_TEXT_ELLIPSIS)];
    pam_panel_line_kind_t kind;
} pam_panel_line_t;

typedef struct {
    pam_panel_line_t lines[PAM_PANEL_MAX_LINES];
    int line_count;
    double width;
    double height;
} pam_panel_layout_t;

typedef struct {
    pam_panel_layout_t panel;
    bool has_panel;
    double width;
    double height;
    double circle_x;
    double circle_y;
    double panel_x;
    double panel_y;
} indicator_layout_t;

static bool pam_panel_is_visible(const pam_display_state_t *pam_display) {
    return pam_display->status_text[0] != '\0' ||
           pam_display->prompt_text[0] != '\0';
}

static bool is_ascii_wrap_space(char character) {
    return character == ' ' || character == '\t';
}

static size_t utf8_next_char_boundary(const char *text, size_t pos, size_t len) {
    if (pos >= len) {
        return len;
    }
    pos++;
    while (pos < len && is_utf8_continuation_byte((unsigned char)text[pos])) {
        pos++;
    }
    return pos;
}

static void copy_text_range(char *output,
                            size_t output_size,
                            const char *text,
                            size_t start,
                            size_t end) {
    size_t length = end - start;

    if (output_size == 0) {
        return;
    }
    if (length >= output_size) {
        length = output_size - 1;
        length = utf8_truncate_to_char_boundary(text + start, length);
    }
    memcpy(output, text + start, length);
    output[length] = '\0';
}

static bool text_range_fits(cairo_t *ctx,
                            const char *text,
                            size_t start,
                            size_t end,
                            double max_width) {
    char candidate[I3LOCK_PAM_DISPLAY_TEXT_MAX];
    cairo_text_extents_t extents;

    copy_text_range(candidate, sizeof(candidate), text, start, end);
    cairo_text_extents(ctx, candidate, &extents);
    return extents.width <= max_width;
}

/* Copies one visual line and returns the next byte to process. Explicit
 * newlines consume one line, and an oversized word is split only as a last
 * resort so that layout always makes progress. */
static size_t wrap_next_text_line(cairo_t *ctx,
                                  const char *text,
                                  size_t len,
                                  size_t start,
                                  double max_width,
                                  char *output,
                                  size_t output_size) {
    if (start < len && text[start] == '\n') {
        output[0] = '\0';
        return start + 1;
    }

    size_t paragraph_end = start;
    while (paragraph_end < len && text[paragraph_end] != '\n') {
        paragraph_end++;
    }

    size_t pos = start;
    size_t fitting_end = start;
    size_t word_break = start;
    while (pos < paragraph_end) {
        size_t next = utf8_next_char_boundary(text, pos, paragraph_end);
        if (!text_range_fits(ctx, text, start, next, max_width)) {
            break;
        }
        fitting_end = next;
        if (is_ascii_wrap_space(text[pos])) {
            word_break = pos;
        }
        pos = next;
    }

    size_t line_end;
    size_t next_start;
    if (fitting_end == paragraph_end) {
        line_end = paragraph_end;
        next_start = paragraph_end < len ? paragraph_end + 1 : paragraph_end;
    } else if (word_break > start) {
        line_end = word_break;
        next_start = word_break + 1;
        while (next_start < paragraph_end && is_ascii_wrap_space(text[next_start])) {
            next_start++;
        }
    } else {
        line_end = fitting_end;
        if (line_end == start) {
            line_end = utf8_next_char_boundary(text, start, paragraph_end);
        }
        next_start = line_end;
    }

    while (line_end > start && is_ascii_wrap_space(text[line_end - 1])) {
        line_end--;
    }
    copy_text_range(output, output_size, text, start, line_end);
    return next_start;
}

static void append_ellipsis_to_line(cairo_t *ctx, char *line, double max_width) {
    char original[I3LOCK_PAM_DISPLAY_TEXT_MAX + sizeof(PAM_TEXT_ELLIPSIS)];
    char candidate[I3LOCK_PAM_DISPLAY_TEXT_MAX + sizeof(PAM_TEXT_ELLIPSIS)];
    cairo_text_extents_t extents;
    size_t len;

    snprintf(original, sizeof(original), "%s", line);
    len = strlen(original);
    while (true) {
        size_t prefix_len = utf8_truncate_to_char_boundary(original, len);
        snprintf(candidate,
                 sizeof(candidate),
                 "%.*s%s",
                 (int)prefix_len,
                 original,
                 PAM_TEXT_ELLIPSIS);
        cairo_text_extents(ctx, candidate, &extents);
        if (extents.width <= max_width || prefix_len == 0) {
            snprintf(line, I3LOCK_PAM_DISPLAY_TEXT_MAX + sizeof(PAM_TEXT_ELLIPSIS), "%s", candidate);
            return;
        }
        len = prefix_len - 1;
    }
}

static void set_panel_font(cairo_t *ctx, pam_panel_line_kind_t kind) {
    cairo_select_font_face(ctx,
                           "sans-serif",
                           CAIRO_FONT_SLANT_NORMAL,
                           kind == PAM_PANEL_PROMPT_LINE ? CAIRO_FONT_WEIGHT_BOLD : CAIRO_FONT_WEIGHT_NORMAL);
    cairo_set_font_size(ctx,
                        kind == PAM_PANEL_PROMPT_LINE ? PAM_PANEL_PROMPT_FONT_SIZE : PAM_PANEL_STATUS_FONT_SIZE);
}

static double max_explicit_line_width(cairo_t *ctx, const char *text) {
    const size_t text_len = strlen(text);
    double max_width = 0.0;
    size_t start = 0;

    while (start <= text_len) {
        char line[I3LOCK_PAM_DISPLAY_TEXT_MAX];
        cairo_text_extents_t extents;
        size_t end = start;
        while (end < text_len && text[end] != '\n') {
            end++;
        }
        copy_text_range(line, sizeof(line), text, start, end);
        cairo_text_extents(ctx, line, &extents);
        max_width = fmax(max_width, extents.width);
        if (end == text_len) {
            return max_width;
        }
        start = end + 1;
    }
    return max_width;
}

static double pam_panel_natural_width(cairo_t *ctx, const pam_display_state_t *pam_display) {
    double text_width = 0.0;

    if (pam_display->status_text[0] != '\0') {
        set_panel_font(ctx, PAM_PANEL_STATUS_LINE);
        text_width = fmax(text_width, max_explicit_line_width(ctx, pam_display->status_text));
    }
    if (pam_display->prompt_text[0] != '\0') {
        set_panel_font(ctx, PAM_PANEL_PROMPT_LINE);
        text_width = fmax(text_width, max_explicit_line_width(ctx, pam_display->prompt_text));
    }
    return text_width + (2 * PAM_PANEL_PADDING_X);
}

static double panel_line_height(pam_panel_line_kind_t kind) {
    return kind == PAM_PANEL_PROMPT_LINE ? PAM_PANEL_PROMPT_LINE_HEIGHT : PAM_PANEL_STATUS_LINE_HEIGHT;
}

static void append_wrapped_panel_lines(pam_panel_layout_t *layout,
                                       cairo_t *ctx,
                                       const char *text,
                                       pam_panel_line_kind_t kind,
                                       int max_lines) {
    const size_t text_len = strlen(text);
    const double text_width = layout->width - (2 * PAM_PANEL_PADDING_X);
    size_t offset = 0;

    if (text_len == 0 || max_lines == 0) {
        return;
    }

    set_panel_font(ctx, kind);
    for (int line = 0; line < max_lines && layout->line_count < PAM_PANEL_MAX_LINES; line++) {
        pam_panel_line_t *panel_line = &layout->lines[layout->line_count++];
        panel_line->kind = kind;
        offset = wrap_next_text_line(ctx,
                                     text,
                                     text_len,
                                     offset,
                                     text_width,
                                     panel_line->text,
                                     sizeof(panel_line->text));
        if (offset >= text_len) {
            return;
        }
        if (line == max_lines - 1) {
            append_ellipsis_to_line(ctx, panel_line->text, text_width);
            return;
        }
    }
}

static pam_panel_layout_t build_pam_panel_layout(cairo_t *ctx,
                                                 const pam_display_state_t *pam_display,
                                                 double panel_width) {
    pam_panel_layout_t layout = {
        .width = panel_width,
    };
    const bool has_status = pam_display->status_text[0] != '\0';
    const bool has_prompt = pam_display->prompt_text[0] != '\0';

    append_wrapped_panel_lines(&layout,
                               ctx,
                               pam_display->status_text,
                               PAM_PANEL_STATUS_LINE,
                               has_prompt ? PAM_PANEL_STATUS_MAX_LINES : PAM_PANEL_MAX_LINES);
    append_wrapped_panel_lines(&layout,
                               ctx,
                               pam_display->prompt_text,
                               PAM_PANEL_PROMPT_LINE,
                               has_status ? PAM_PANEL_PROMPT_MAX_LINES : PAM_PANEL_MAX_LINES);

    layout.height = 2 * PAM_PANEL_PADDING_Y;
    for (int line = 0; line < layout.line_count; line++) {
        layout.height += panel_line_height(layout.lines[line].kind);
        if (line + 1 < layout.line_count) {
            layout.height += layout.lines[line].kind == layout.lines[line + 1].kind
                                 ? PAM_PANEL_LINE_GAP
                                 : PAM_PANEL_SECTION_GAP;
        }
    }
    return layout;
}

static indicator_layout_t build_indicator_layout(cairo_t *ctx,
                                                 const pam_display_state_t *pam_display,
                                                 double output_width) {
    indicator_layout_t layout = {
        .width = BUTTON_DIAMETER,
        .height = BUTTON_DIAMETER,
        .circle_x = 0,
        .circle_y = 0,
    };

    layout.has_panel = pam_panel_is_visible(pam_display);
    if (!layout.has_panel) {
        return layout;
    }

    const double available_width = fmax(1.0, output_width - (2 * PAM_PANEL_EDGE_MARGIN));
    const double maximum_panel_width = fmin(PAM_PANEL_MAX_WIDTH, available_width);
    const double natural_panel_width = pam_panel_natural_width(ctx, pam_display);
    const double panel_width = fmin(maximum_panel_width,
                                    fmax(2 * PAM_PANEL_PADDING_X, natural_panel_width));
    layout.panel = build_pam_panel_layout(ctx, pam_display, panel_width);
    layout.width = fmax(BUTTON_DIAMETER, layout.panel.width);
    layout.height = BUTTON_DIAMETER + PAM_PANEL_GAP + layout.panel.height;
    layout.circle_x = (layout.width - BUTTON_DIAMETER) / 2;
    layout.panel_x = (layout.width - layout.panel.width) / 2;
    layout.panel_y = 0;
    layout.circle_y = layout.panel.height + PAM_PANEL_GAP;
    return layout;
}

static void draw_rounded_rectangle(cairo_t *ctx, double x, double y, double width, double height, double radius) {
    const double clamped_radius = fmin(radius, fmin(width, height) / 2);

    cairo_new_sub_path(ctx);
    cairo_arc(ctx, x + width - clamped_radius, y + clamped_radius, clamped_radius, -M_PI / 2, 0);
    cairo_arc(ctx, x + width - clamped_radius, y + height - clamped_radius, clamped_radius, 0, M_PI / 2);
    cairo_arc(ctx, x + clamped_radius, y + height - clamped_radius, clamped_radius, M_PI / 2, M_PI);
    cairo_arc(ctx, x + clamped_radius, y + clamped_radius, clamped_radius, M_PI, 3 * M_PI / 2);
    cairo_close_path(ctx);
}

static void draw_pam_panel(cairo_t *ctx,
                           const pam_panel_layout_t *layout,
                           const pam_display_state_t *pam_display,
                           double x,
                           double y) {
    bool drew_error_accent = false;
    double baseline = y + PAM_PANEL_PADDING_Y;

    draw_rounded_rectangle(ctx, x, y, layout->width, layout->height, PAM_PANEL_CORNER_RADIUS);
    cairo_set_source_rgba(ctx, 20.0 / 255, 22.0 / 255, 25.0 / 255, 0.86);
    cairo_fill_preserve(ctx);
    cairo_set_source_rgba(ctx, 1.0, 1.0, 1.0, 0.18);
    cairo_set_line_width(ctx, 1.0);
    cairo_stroke(ctx);

    for (int line = 0; line < layout->line_count; line++) {
        const pam_panel_line_t *panel_line = &layout->lines[line];
        cairo_font_extents_t extents;
        const double line_height = panel_line_height(panel_line->kind);

        set_panel_font(ctx, panel_line->kind);
        cairo_font_extents(ctx, &extents);
        baseline += ((line_height - extents.height) / 2) + extents.ascent;
        if (panel_line->kind == PAM_PANEL_STATUS_LINE && pam_display->status_is_error) {
            cairo_set_source_rgb(ctx, 1.0, 123.0 / 255, 114.0 / 255);
            if (!drew_error_accent) {
                cairo_rectangle(ctx, x, y + PAM_PANEL_CORNER_RADIUS, 3.0, layout->height - (2 * PAM_PANEL_CORNER_RADIUS));
                cairo_fill(ctx);
                drew_error_accent = true;
            }
        } else if (panel_line->kind == PAM_PANEL_PROMPT_LINE) {
            cairo_set_source_rgb(ctx, 1.0, 1.0, 1.0);
        } else {
            cairo_set_source_rgb(ctx, 242.0 / 255, 244.0 / 255, 247.0 / 255);
        }
        cairo_move_to(ctx, x + PAM_PANEL_PADDING_X, baseline);
        cairo_show_text(ctx, panel_line->text);
        baseline += line_height - (((line_height - extents.height) / 2) + extents.ascent);
        if (line + 1 < layout->line_count) {
            baseline += panel_line->kind == layout->lines[line + 1].kind
                            ? PAM_PANEL_LINE_GAP
                            : PAM_PANEL_SECTION_GAP;
        }
    }
}

static void update_layout_string() {
    if (layout_string) {
        free(layout_string);
        layout_string = NULL;
    }
    xkb_layout_index_t num_layouts = xkb_keymap_num_layouts(xkb_keymap);
    for (xkb_layout_index_t i = 0; i < num_layouts; ++i) {
        if (xkb_state_layout_index_is_active(xkb_state, i, XKB_STATE_LAYOUT_EFFECTIVE)) {
            const char *name = xkb_keymap_layout_get_name(xkb_keymap, i);
            if (name) {
                string_append(&layout_string, name);
            }
        }
    }
}

/* check_modifier_keys describes the currently active modifiers (Caps Lock, Alt,
   Num Lock or Super) in the modifier_string variable. */
static void check_modifier_keys(void) {
    xkb_mod_index_t idx, num_mods;
    const char *mod_name;

    num_mods = xkb_keymap_num_mods(xkb_keymap);

    for (idx = 0; idx < num_mods; idx++) {
        if (!xkb_state_mod_index_is_active(xkb_state, idx, XKB_STATE_MODS_EFFECTIVE)) {
            continue;
        }

        mod_name = xkb_keymap_mod_get_name(xkb_keymap, idx);
        if (mod_name == NULL) {
            continue;
        }

        /* Replace certain xkb names with nicer, human-readable ones. */
        if (strcmp(mod_name, XKB_MOD_NAME_CAPS) == 0) {
            mod_name = "Caps Lock";
        } else if (strcmp(mod_name, XKB_MOD_NAME_NUM) == 0) {
            mod_name = "Num Lock";
        } else {
            /* Show only Caps Lock and Num Lock, other modifiers (e.g. Shift)
             * leak state about the password. */
            continue;
        }
        string_append(&modifier_string, mod_name);
    }
}

/*
 * Draws global image with fill color onto a pixmap with the given
 * resolution and returns it.
 *
 */
static void draw_unlock_circle(cairo_t *ctx,
                               const pam_display_state_t *pam_display,
                               bool panel_visible) {
    /* Draw a (centered) circle with transparent background. */
    cairo_new_path(ctx);
    cairo_set_line_width(ctx, 10.0);
    cairo_arc(ctx,
              BUTTON_CENTER /* x */,
              BUTTON_CENTER /* y */,
              BUTTON_RADIUS /* radius */,
              0 /* start */,
              2 * M_PI /* end */);

    /* Use the appropriate color for the different PAM states
     * (currently verifying, wrong password, or default). */
    switch (auth_state) {
        case STATE_AUTH_VERIFY:
        case STATE_AUTH_LOCK:
            cairo_set_source_rgba(ctx, 0, 114.0 / 255, 255.0 / 255, 0.75);
            break;
        case STATE_AUTH_WRONG:
        case STATE_I3LOCK_LOCK_FAILED:
            cairo_set_source_rgba(ctx, 250.0 / 255, 0, 0, 0.75);
            break;
        default:
            if (unlock_state == STATE_NOTHING_TO_DELETE) {
                cairo_set_source_rgba(ctx, 250.0 / 255, 0, 0, 0.75);
                break;
            }
            cairo_set_source_rgba(ctx, 0, 0, 0, 0.75);
            break;
    }
    cairo_fill_preserve(ctx);

    bool use_dark_text = true;

    switch (auth_state) {
        case STATE_AUTH_VERIFY:
        case STATE_AUTH_LOCK:
            cairo_set_source_rgb(ctx, 51.0 / 255, 0, 250.0 / 255);
            break;
        case STATE_AUTH_WRONG:
        case STATE_I3LOCK_LOCK_FAILED:
            cairo_set_source_rgb(ctx, 125.0 / 255, 51.0 / 255, 0);
            break;
        case STATE_AUTH_IDLE:
            if (unlock_state == STATE_NOTHING_TO_DELETE) {
                cairo_set_source_rgb(ctx, 125.0 / 255, 51.0 / 255, 0);
                break;
            }

            cairo_set_source_rgb(ctx, 51.0 / 255, 125.0 / 255, 0);
            use_dark_text = false;
            break;
    }
    cairo_stroke(ctx);

    /* Draw an inner separator line. */
    cairo_set_source_rgb(ctx, 0, 0, 0);
    cairo_set_line_width(ctx, 2.0);
    cairo_arc(ctx,
              BUTTON_CENTER /* x */,
              BUTTON_CENTER /* y */,
              BUTTON_RADIUS - 5 /* radius */,
              0,
              2 * M_PI);
    cairo_stroke(ctx);

    cairo_set_line_width(ctx, 10.0);

    /* Display the existing authentication state or echo-on input in the
     * circle. PAM prompts and status belong to the separate passive panel. */
    const char *text = NULL;
    bool text_is_visible_input = false;
    char buf[4];

    cairo_set_source_rgb(ctx, 0, 0, 0);
    cairo_select_font_face(ctx, "sans-serif", CAIRO_FONT_SLANT_NORMAL, CAIRO_FONT_WEIGHT_NORMAL);
    cairo_set_font_size(ctx, 28.0);
    switch (auth_state) {
        case STATE_AUTH_VERIFY:
            text = "Verifying…";
            break;
        case STATE_AUTH_LOCK:
            text = "Locking…";
            break;
        case STATE_AUTH_WRONG:
            text = "Wrong!";
            break;
        case STATE_I3LOCK_LOCK_FAILED:
            text = "Lock failed!";
            break;
        default:
            if (unlock_state == STATE_NOTHING_TO_DELETE) {
                text = "No input";
            }
            if (show_failed_attempts && failed_attempts > 0) {
                if (failed_attempts > 999) {
                    text = "> 999";
                } else {
                    snprintf(buf, sizeof(buf), "%d", failed_attempts);
                    text = buf;
                }
                cairo_set_source_rgb(ctx, 1, 0, 0);
                cairo_set_font_size(ctx, 32.0);
            }
            if (pam_display->prompt_echo_on && pam_display->visible_input[0] != '\0') {
                text = pam_display->visible_input;
                text_is_visible_input = true;
                cairo_set_font_size(ctx, 16.0);
            }
            break;
    }

    if (text != NULL) {
        if (text_is_visible_input) {
            display_button_text_bounded(ctx,
                                        text,
                                        0.0,
                                        use_dark_text,
                                        BUTTON_DIAMETER - 28.0);
        } else {
            display_button_text(ctx, text, 0.0, use_dark_text);
        }
    }

    if (modifier_string != NULL && !panel_visible) {
        cairo_set_font_size(ctx, 14.0);
        display_button_text(ctx, modifier_string, 28.0, use_dark_text);
    }
    if (show_keyboard_layout && layout_string != NULL && !panel_visible) {
        cairo_set_font_size(ctx, 14.0);
        display_button_text(ctx, layout_string, -28.0, use_dark_text);
    }

    /* After the user pressed any valid key or the backspace key, highlight a
     * random part of the unlock indicator to confirm the keypress. */
    if (unlock_state == STATE_KEY_ACTIVE ||
        unlock_state == STATE_BACKSPACE_ACTIVE) {
        cairo_new_sub_path(ctx);
        const double highlight_start = (rand() % (int)(2 * M_PI * 100)) / 100.0;
        cairo_arc(ctx,
                  BUTTON_CENTER /* x */,
                  BUTTON_CENTER /* y */,
                  BUTTON_RADIUS /* radius */,
                  highlight_start,
                  highlight_start + (M_PI / 3.0));
        if (unlock_state == STATE_KEY_ACTIVE) {
            cairo_set_source_rgb(ctx, 51.0 / 255, 219.0 / 255, 0);
        } else {
            cairo_set_source_rgb(ctx, 219.0 / 255, 51.0 / 255, 0);
        }
        cairo_stroke(ctx);

        cairo_set_source_rgb(ctx, 0, 0, 0);
        cairo_arc(ctx,
                  BUTTON_CENTER /* x */,
                  BUTTON_CENTER /* y */,
                  BUTTON_RADIUS /* radius */,
                  highlight_start,
                  highlight_start + (M_PI / 128.0));
        cairo_stroke(ctx);
        cairo_arc(ctx,
                  BUTTON_CENTER /* x */,
                  BUTTON_CENTER /* y */,
                  BUTTON_RADIUS /* radius */,
                  (highlight_start + (M_PI / 3.0)) - (M_PI / 128.0),
                  highlight_start + (M_PI / 3.0));
        cairo_stroke(ctx);
    }
}

static void draw_indicator_on_output(cairo_t *xcb_ctx,
                                     const pam_display_state_t *pam_display,
                                     double scaling_factor,
                                     int output_x,
                                     int output_y,
                                     uint32_t output_width,
                                     uint32_t output_height) {
    cairo_surface_t *measure_surface = cairo_image_surface_create(CAIRO_FORMAT_ARGB32, 1, 1);
    cairo_t *measure_ctx = cairo_create(measure_surface);
    const double logical_width = output_width / scaling_factor;
    const double logical_height = output_height / scaling_factor;
    const indicator_layout_t layout =
        build_indicator_layout(measure_ctx, pam_display, logical_width);
    cairo_destroy(measure_ctx);
    cairo_surface_destroy(measure_surface);

    const double available_width = fmax(1.0, logical_width - (2 * PAM_PANEL_EDGE_MARGIN));
    const double available_height = fmax(1.0,
                                         logical_height - (2 * PAM_PANEL_VERTICAL_EDGE_MARGIN));
    const double content_scaling_factor =
        fmin(1.0, fmin(available_width / layout.width, available_height / layout.height));
    const double render_scaling_factor = scaling_factor * content_scaling_factor;
    const int surface_width = (int)ceil(render_scaling_factor * layout.width);
    const int surface_height = (int)ceil(render_scaling_factor * layout.height);
    cairo_surface_t *output =
        cairo_image_surface_create(CAIRO_FORMAT_ARGB32, surface_width, surface_height);
    cairo_t *ctx = cairo_create(output);

    cairo_scale(ctx, render_scaling_factor, render_scaling_factor);
    if (layout.has_panel) {
        draw_pam_panel(ctx, &layout.panel, pam_display, layout.panel_x, layout.panel_y);
    }

    cairo_save(ctx);
    cairo_translate(ctx, layout.circle_x, layout.circle_y);
    draw_unlock_circle(ctx, pam_display, layout.has_panel);
    cairo_restore(ctx);

    const int x = output_x + ((int)output_width - surface_width) / 2;
    const int y = output_y + ((int)output_height - surface_height) / 2;
    cairo_set_source_surface(xcb_ctx, output, x, y);
    cairo_rectangle(xcb_ctx, x, y, surface_width, surface_height);
    cairo_fill(xcb_ctx);

    cairo_destroy(ctx);
    cairo_surface_destroy(output);
}

/*
 * Draws global image with fill color onto a pixmap with the given
 * resolution and returns it.
 *
 */
void draw_image(xcb_pixmap_t bg_pixmap, uint32_t *resolution) {
    const double scaling_factor = get_dpi_value() / 96.0;
    DEBUG("scaling_factor is %.2f\n", scaling_factor);

    if (!vistype) {
        vistype = get_root_visual_type(screen);
    }

    cairo_surface_t *xcb_output =
        cairo_xcb_surface_create(conn, bg_pixmap, vistype, resolution[0], resolution[1]);
    cairo_t *xcb_ctx = cairo_create(xcb_output);

    /* After the first iteration, the pixmap will still contain the previous
     * contents. Explicitly clear the entire pixmap with the background color
     * first to get back into a defined state. */
    char strgroups[3][3] = {{color[0], color[1], '\0'},
                            {color[2], color[3], '\0'},
                            {color[4], color[5], '\0'}};
    uint32_t rgb16[3] = {(strtol(strgroups[0], NULL, 16)),
                         (strtol(strgroups[1], NULL, 16)),
                         (strtol(strgroups[2], NULL, 16))};
    cairo_set_source_rgb(xcb_ctx, rgb16[0] / 255.0, rgb16[1] / 255.0, rgb16[2] / 255.0);
    cairo_rectangle(xcb_ctx, 0, 0, resolution[0], resolution[1]);
    cairo_fill(xcb_ctx);

    if (img) {
        if (!tile) {
            cairo_set_source_surface(xcb_ctx, img, 0, 0);
            cairo_paint(xcb_ctx);
        } else {
            cairo_pattern_t *pattern = cairo_pattern_create_for_surface(img);
            cairo_set_source(xcb_ctx, pattern);
            cairo_pattern_set_extend(pattern, CAIRO_EXTEND_REPEAT);
            cairo_rectangle(xcb_ctx, 0, 0, resolution[0], resolution[1]);
            cairo_fill(xcb_ctx);
            cairo_pattern_destroy(pattern);
        }
    }

    if (unlock_indicator &&
        (unlock_state >= STATE_KEY_PRESSED || auth_state > STATE_AUTH_IDLE)) {
        const pam_display_state_t *pam_display = get_pam_display_state();

        if (xr_screens > 0) {
            for (int screen = 0; screen < xr_screens; screen++) {
                draw_indicator_on_output(xcb_ctx,
                                         pam_display,
                                         scaling_factor,
                                         xr_resolutions[screen].x,
                                         xr_resolutions[screen].y,
                                         xr_resolutions[screen].width,
                                         xr_resolutions[screen].height);
            }
        } else {
            draw_indicator_on_output(xcb_ctx,
                                     pam_display,
                                     scaling_factor,
                                     0,
                                     0,
                                     resolution[0],
                                     resolution[1]);
        }
    }

    cairo_surface_destroy(xcb_output);
    cairo_destroy(xcb_ctx);
}

static xcb_pixmap_t bg_pixmap = XCB_NONE;

/*
 * Releases the current background pixmap so that the next redraw_screen() call
 * will allocate a new one with the updated resolution.
 *
 */
void free_bg_pixmap(void) {
    xcb_free_pixmap(conn, bg_pixmap);
    bg_pixmap = XCB_NONE;
}

/*
 * Calls draw_image on a new pixmap and swaps that with the current pixmap
 *
 */
void redraw_screen(void) {
    DEBUG("redraw_screen(unlock_state = %d, auth_state = %d)\n", unlock_state, auth_state);

    if (modifier_string) {
        free(modifier_string);
        modifier_string = NULL;
    }
    check_modifier_keys();
    update_layout_string();

    if (bg_pixmap == XCB_NONE) {
        DEBUG("allocating pixmap for %d x %d px\n", last_resolution[0], last_resolution[1]);
        bg_pixmap = create_bg_pixmap(conn, screen, last_resolution, color);
    }

    draw_image(bg_pixmap, last_resolution);
    xcb_change_window_attributes(conn, win, XCB_CW_BACK_PIXMAP, (uint32_t[1]){bg_pixmap});
    /* XXX: Possible optimization: Only update the area in the middle of the
     * screen instead of the whole screen. */
    xcb_clear_area(conn, 0, win, 0, 0, last_resolution[0], last_resolution[1]);
    xcb_flush(conn);
}

/*
 * Hides the unlock indicator completely when there is no content in the
 * password buffer.
 *
 */
void clear_indicator(void) {
    if (input_position == 0) {
        unlock_state = STATE_STARTED;
    } else {
        unlock_state = STATE_KEY_PRESSED;
    }
    redraw_screen();
}
