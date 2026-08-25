#ifndef _PAM_CONTROLLER_H
#define _PAM_CONTROLLER_H

#ifndef __OpenBSD__

#include <stdint.h>

typedef enum {
    PAM_EVENT_AUTH_READY,
    PAM_EVENT_AUTH_SUCCESS,
    PAM_EVENT_AUTH_FAILURE,
    PAM_EVENT_AUTH_FATAL,
} pam_event_type_t;

typedef struct {
    pam_event_type_t type;
    uint64_t transaction_id;
    uint64_t prompt_id;
} pam_event_t;

/*
 * Initialize the PAM controller: create worker thread, pipe, secure
 * storage, and PAM handle.  Must be called exactly once, after all
 * forks are complete.  Aborts on failure.
 *
 * username and display are copied internally.
 */
void pam_controller_init(const char *username, const char *display);

/*
 * Stage the password and start authentication.  The password is copied
 * into mlocked storage; the caller should wipe its own copy afterward.
 * Returns the transaction ID of the new authentication attempt, or 0 if
 * the controller has not been initialized yet.
 */
uint64_t pam_controller_start_auth(const char *password);

/*
 * Returns the file descriptor that the main event loop should watch for
 * readability.  When readable, call pam_controller_drain_events().
 */
int pam_controller_get_fd(void);

/*
 * Drain all pending events from the worker thread.  Calls the provided
 * callback for each event.  Returns the number of events processed.
 */
int pam_controller_drain_events(void (*callback)(const pam_event_t *event));

/*
 * Shut down the controller: signal the worker to exit, join the thread,
 * call pam_end, and free resources.
 */
void pam_controller_cleanup(void);

#endif /* !__OpenBSD__ */
#endif /* _PAM_CONTROLLER_H */
