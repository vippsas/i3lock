#ifndef _I3LOCK_H
#define _I3LOCK_H

/* PAM messages may be long. Keep the controller event and renderer buffers
 * bounded by the same 1 KiB limit so that presentation code, rather than an
 * incidental intermediate copy, decides what is elided. */
#define I3LOCK_PAM_DISPLAY_TEXT_MAX 1024

/* This macro will only print debug output when started with --debug.
 * This is important because xautolock (for example) closes stdout/stderr by
 * default, so just printing something to stdout will lead to the data ending
 * up on the X11 socket (!). */
#define DEBUG(fmt, ...)                                            \
    do {                                                           \
        if (debug_mode) {                                          \
            fprintf(stderr, "[i3lock-debug] " fmt, ##__VA_ARGS__); \
        }                                                          \
    } while (0)

#endif
