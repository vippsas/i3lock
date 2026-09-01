#ifndef _UNLOCK_INDICATOR_H
#define _UNLOCK_INDICATOR_H

#include <stdbool.h>
#include <xcb/xcb.h>

#include "i3lock.h"

#define I3LOCK_PAM_VISIBLE_INPUT_MAX 256

typedef struct {
    char status_text[I3LOCK_PAM_DISPLAY_TEXT_MAX];
    char prompt_text[I3LOCK_PAM_DISPLAY_TEXT_MAX];
    char visible_input[I3LOCK_PAM_VISIBLE_INPUT_MAX];
    bool status_is_error;
    bool prompt_echo_on;
} pam_display_state_t;

/* The main event loop owns this state. The renderer only observes it while
 * drawing, keeping PAM presentation details out of renderer globals. */
const pam_display_state_t* get_pam_display_state(void);

typedef enum {
    STATE_STARTED = 0,           /* default state */
    STATE_KEY_PRESSED = 1,       /* key was pressed, show unlock indicator */
    STATE_KEY_ACTIVE = 2,        /* a key was pressed recently, highlight part
                                   of the unlock indicator. */
    STATE_BACKSPACE_ACTIVE = 3,  /* backspace was pressed recently, highlight
                                   part of the unlock indicator in red. */
    STATE_NOTHING_TO_DELETE = 4, /* backspace was pressed, but there is nothing to delete. */
} unlock_state_t;

typedef enum {
    STATE_AUTH_IDLE = 0,          /* no authenticator interaction at the moment */
    STATE_AUTH_VERIFY = 1,        /* currently verifying the password via authenticator */
    STATE_AUTH_LOCK = 2,          /* currently locking the screen */
    STATE_AUTH_WRONG = 3,         /* the password was wrong */
    STATE_I3LOCK_LOCK_FAILED = 4, /* i3lock failed to load */
} auth_state_t;

void free_bg_pixmap(void);
void draw_image(xcb_pixmap_t bg_pixmap, uint32_t* resolution);
void redraw_screen(void);
void clear_indicator(void);

#endif
