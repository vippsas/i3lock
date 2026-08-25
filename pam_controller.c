/*
 * Fork-safe PAM controller for i3lock.
 *
 * The controller owns a dedicated worker thread that holds the PAM
 * handle and runs pam_authenticate, pam_setcred, and pam_end. The
 * main thread communicates with the worker through a mutex-protected
 * command slot and receives results through an event queue drained via
 * a libev-watched pipe.
 *
 * Credential copies owned by the controller live in a single mlock()ed
 * region. The worker returns a credential to PAM only after ownership has
 * transferred to the pam_response array, then immediately wipes the
 * controller-owned copy.
 */

#include <config.h>

#include <errno.h>
#include <fcntl.h>
#include <pthread.h>
#include <security/pam_appl.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <unistd.h>
#ifdef HAVE_EXPLICIT_BZERO
#include <strings.h>
#endif

#include "i3lock.h"
#include "pam_controller.h"

#define MAX_EVENTS 16
#define SECURE_BUFFER_SIZE 512

/* secure wiping */

static void secure_wipe(void *buf, size_t len) {
#ifdef HAVE_EXPLICIT_BZERO
    explicit_bzero(buf, len);
#else
    volatile char *p = buf;
    for (size_t i = 0; i < len; i++) {
        p[i] = 0;
    }
#endif
}

/* secure storage (mlocked) */

struct secure_storage {
    char deferred_input[SECURE_BUFFER_SIZE];
    /* Reserved for the sequential prompt state machine. */
    char pending_response[SECURE_BUFFER_SIZE];
};

/* controller state */

static struct {
    /* Thread synchronisation. */
    pthread_t worker;
    pthread_mutex_t mutex;
    pthread_cond_t cond;

    /* Event queue: worker to main thread. */
    pam_event_t events[MAX_EVENTS];
    int event_count;

    /* Wake-up pipe: worker writes [1], main reads [0]. */
    int pipe_fds[2];

    /* Worker command slot: main to worker. */
    bool auth_requested;
    bool auth_in_progress;
    bool shutdown_requested;
    bool cancellation_requested;
    bool waiting_for_answer;
    bool answer_submitted;
    bool fatal_error;

    /* Transaction tracking. */
    uint64_t next_transaction_id;
    uint64_t next_prompt_id;
    uint64_t active_transaction_id;
    uint64_t waiting_prompt_id;
    int prompts_seen;

    /* PAM handle: exclusively owned by the worker. */
    pam_handle_t *pam_handle;
    struct pam_conv pam_conv;

    /* Initialisation parameters (copied). */
    char *username;
    char *display;

    /* Credential storage: mlocked. */
    struct secure_storage *secure;

    bool initialised;
} ctrl;

/* internal helpers */

/* Post an event and wake the main event loop. Must be called with
 * ctrl.mutex held. */
static void post_event_locked(pam_event_t event) {
    if (ctrl.event_count < MAX_EVENTS) {
        ctrl.events[ctrl.event_count++] = event;
    } else {
        ctrl.events[MAX_EVENTS - 1] = (pam_event_t){
            .type = PAM_EVENT_AUTH_FATAL,
            .transaction_id = event.transaction_id,
            .prompt_id = event.prompt_id,
        };
    }
    char byte = 0;
    (void)write(ctrl.pipe_fds[1], &byte, 1);
}

static void free_replies(struct pam_response *reply, int count) {
    if (reply == NULL) {
        return;
    }
    for (int i = 0; i < count; i++) {
        if (reply[i].resp != NULL) {
            secure_wipe(reply[i].resp, strlen(reply[i].resp));
            free(reply[i].resp);
        }
    }
    free(reply);
}

static int copy_secure_value_to_response(char **response, const char *value) {
    *response = strdup(value);
    if (*response == NULL) {
        return PAM_BUF_ERR;
    }
    return PAM_SUCCESS;
}

static void event_set_text(pam_event_t *event, const char *text) {
    if (text == NULL) {
        event->text[0] = '\0';
        return;
    }
    snprintf(event->text, sizeof(event->text), "%s", text);
}

static int worker_conv_callback(int num_msg,
                                const struct pam_message **msg,
                                struct pam_response **resp,
                                void *appdata_ptr);

static int start_pam_handle(void) {
    ctrl.pam_conv = (struct pam_conv){worker_conv_callback, NULL};
    int ret = pam_start("i3lock", ctrl.username, &ctrl.pam_conv, &ctrl.pam_handle);
    if (ret != PAM_SUCCESS) {
        fprintf(stderr, "[i3lock] PAM worker: pam_start failed (%d)\n", ret);
        ctrl.pam_handle = NULL;
        return ret;
    }

    if (ctrl.display != NULL) {
        ret = pam_set_item(ctrl.pam_handle, PAM_TTY, ctrl.display);
        if (ret != PAM_SUCCESS) {
            fprintf(stderr, "[i3lock] PAM worker: pam_set_item(PAM_TTY) failed (%d)\n", ret);
            pam_end(ctrl.pam_handle, ret);
            ctrl.pam_handle = NULL;
            return ret;
        }
    }

    return PAM_SUCCESS;
}

static void end_pam_handle(int status) {
    if (ctrl.pam_handle != NULL) {
        pam_end(ctrl.pam_handle, status);
        ctrl.pam_handle = NULL;
    }
}

/* pam_conv callback, running in the worker thread */

static int worker_conv_callback(int num_msg,
                                const struct pam_message **msg,
                                struct pam_response **resp,
                                void *appdata_ptr) {
    (void)appdata_ptr;

    if (num_msg <= 0) {
        return PAM_CONV_ERR;
    }

    struct pam_response *reply = calloc((size_t)num_msg, sizeof(*reply));
    if (reply == NULL) {
        return PAM_BUF_ERR;
    }

    pthread_mutex_lock(&ctrl.mutex);
    for (int i = 0; i < num_msg; i++) {
        if (ctrl.shutdown_requested || ctrl.cancellation_requested) {
            pthread_mutex_unlock(&ctrl.mutex);
            free_replies(reply, num_msg);
            return PAM_CONV_ERR;
        }

        int style = msg[i]->msg_style;
        if (style == PAM_PROMPT_ECHO_OFF || style == PAM_PROMPT_ECHO_ON) {
            ctrl.prompts_seen++;
            bool use_deferred = ctrl.prompts_seen == 1 &&
                                style == PAM_PROMPT_ECHO_OFF &&
                                ctrl.secure->deferred_input[0] != '\0';

            if (use_deferred) {
                int result = copy_secure_value_to_response(&reply[i].resp,
                                                           ctrl.secure->deferred_input);
                secure_wipe(ctrl.secure->deferred_input, SECURE_BUFFER_SIZE);
                if (result != PAM_SUCCESS) {
                    pthread_mutex_unlock(&ctrl.mutex);
                    free_replies(reply, num_msg);
                    return result;
                }
                reply[i].resp_retcode = 0;
                continue;
            }

            secure_wipe(ctrl.secure->deferred_input, SECURE_BUFFER_SIZE);
            uint64_t prompt_id = ctrl.next_prompt_id++;
            ctrl.waiting_prompt_id = prompt_id;
            ctrl.waiting_for_answer = true;
            ctrl.answer_submitted = false;
            pam_event_t event = {
                .type = PAM_EVENT_AUTH_PROMPT,
                .transaction_id = ctrl.active_transaction_id,
                .prompt_id = prompt_id,
                .echo_on = style == PAM_PROMPT_ECHO_ON,
            };
            event_set_text(&event, msg[i]->msg);
            post_event_locked(event);

            while (!ctrl.answer_submitted &&
                   !ctrl.cancellation_requested &&
                   !ctrl.shutdown_requested) {
                pthread_cond_wait(&ctrl.cond, &ctrl.mutex);
            }

            if (ctrl.shutdown_requested || ctrl.cancellation_requested) {
                ctrl.waiting_for_answer = false;
                ctrl.answer_submitted = false;
                ctrl.waiting_prompt_id = 0;
                secure_wipe(ctrl.secure->pending_response, SECURE_BUFFER_SIZE);
                pthread_mutex_unlock(&ctrl.mutex);
                free_replies(reply, num_msg);
                return PAM_CONV_ERR;
            }

            int result = copy_secure_value_to_response(&reply[i].resp,
                                                       ctrl.secure->pending_response);
            secure_wipe(ctrl.secure->pending_response, SECURE_BUFFER_SIZE);
            ctrl.waiting_for_answer = false;
            ctrl.answer_submitted = false;
            ctrl.waiting_prompt_id = 0;
            reply[i].resp_retcode = 0;
            if (result != PAM_SUCCESS) {
                pthread_mutex_unlock(&ctrl.mutex);
                free_replies(reply, num_msg);
                return result;
            }
        } else if (style == PAM_TEXT_INFO || style == PAM_ERROR_MSG) {
            pam_event_t event = {
                .type = PAM_EVENT_AUTH_STATUS,
                .transaction_id = ctrl.active_transaction_id,
                .prompt_id = 0,
                .echo_on = 0,
                .is_error = style == PAM_ERROR_MSG,
            };
            event_set_text(&event, msg[i]->msg);
            post_event_locked(event);
        } else {
            pthread_mutex_unlock(&ctrl.mutex);
            free_replies(reply, num_msg);
            return PAM_CONV_ERR;
        }
        /* INFO and ERROR: reply[i] stays zeroed (resp=NULL, retcode=0). */
    }
    pthread_mutex_unlock(&ctrl.mutex);

    *resp = reply;
    return PAM_SUCCESS;
}

/* worker thread */

static void *worker_main(void *arg) {
    (void)arg;

    /* Initialise the PAM handle. The worker owns it exclusively. */
    int ret = start_pam_handle();
    if (ret != PAM_SUCCESS) {
        pthread_mutex_lock(&ctrl.mutex);
        post_event_locked((pam_event_t){
            .type = PAM_EVENT_AUTH_FATAL,
            .transaction_id = 0,
            .prompt_id = 0,
        });
        pthread_mutex_unlock(&ctrl.mutex);
        return NULL;
    }

    pthread_mutex_lock(&ctrl.mutex);
    post_event_locked((pam_event_t){
        .type = PAM_EVENT_AUTH_READY,
        .transaction_id = 0,
        .prompt_id = 0,
    });
    while (!ctrl.shutdown_requested) {
        /* Wait for an authentication request or shutdown. */
        while (!ctrl.auth_requested && !ctrl.shutdown_requested) {
            pthread_cond_wait(&ctrl.cond, &ctrl.mutex);
        }
        if (ctrl.shutdown_requested) {
            break;
        }

        ctrl.auth_requested = false;
        ctrl.auth_in_progress = true;
        ctrl.cancellation_requested = false;
        ctrl.waiting_for_answer = false;
        ctrl.answer_submitted = false;
        ctrl.waiting_prompt_id = 0;
        ctrl.prompts_seen = 0;
        uint64_t txn = ctrl.active_transaction_id;
        pthread_mutex_unlock(&ctrl.mutex);

        /* pam_authenticate blocks and invokes worker_conv_callback. */
        ret = pam_authenticate(ctrl.pam_handle, 0);

        pthread_mutex_lock(&ctrl.mutex);
        secure_wipe(ctrl.secure->deferred_input, SECURE_BUFFER_SIZE);
        secure_wipe(ctrl.secure->pending_response, SECURE_BUFFER_SIZE);
        ctrl.auth_in_progress = false;
        ctrl.waiting_for_answer = false;
        ctrl.answer_submitted = false;
        ctrl.waiting_prompt_id = 0;
        if (ctrl.cancellation_requested) {
            ctrl.cancellation_requested = false;
            post_event_locked((pam_event_t){
                .type = PAM_EVENT_AUTH_CANCELLED,
                .transaction_id = txn,
                .prompt_id = 0,
                .echo_on = 0,
            });
        } else if (ret == PAM_SUCCESS) {
            /* Refresh credentials (Kerberos tickets, etc.).
             * Do not downgrade a successful authentication if
             * credential refresh fails. */
            pam_setcred(ctrl.pam_handle, PAM_REFRESH_CRED);
            post_event_locked((pam_event_t){
                .type = PAM_EVENT_AUTH_SUCCESS,
                .transaction_id = txn,
                .prompt_id = 0,
                .echo_on = 0,
            });
        } else if (ret == PAM_ABORT) {
            pam_event_t event = {
                .type = PAM_EVENT_AUTH_FATAL,
                .transaction_id = txn,
                .prompt_id = 0,
                .echo_on = 0,
                .is_error = 1,
            };
            event_set_text(&event, "Authentication service failed");
            ctrl.fatal_error = true;
            post_event_locked(event);
            pthread_mutex_unlock(&ctrl.mutex);
            end_pam_handle(ret);
            pthread_mutex_lock(&ctrl.mutex);
        } else if (ret == PAM_SYSTEM_ERR || ret == PAM_SERVICE_ERR) {
            pam_event_t event = {
                .type = PAM_EVENT_AUTH_FAILURE,
                .transaction_id = txn,
                .prompt_id = 0,
                .echo_on = 0,
                .is_error = 1,
            };
            event_set_text(&event, "Authentication service error");
            post_event_locked(event);

            pthread_mutex_unlock(&ctrl.mutex);
            end_pam_handle(ret);
            ret = start_pam_handle();
            pthread_mutex_lock(&ctrl.mutex);
            if (ret == PAM_SUCCESS) {
                post_event_locked((pam_event_t){
                    .type = PAM_EVENT_AUTH_READY,
                    .transaction_id = 0,
                    .prompt_id = 0,
                    .echo_on = 0,
                });
            } else {
                pam_event_t fatal = {
                    .type = PAM_EVENT_AUTH_FATAL,
                    .transaction_id = 0,
                    .prompt_id = 0,
                    .echo_on = 0,
                    .is_error = 1,
                };
                event_set_text(&fatal, "Authentication service failed");
                ctrl.fatal_error = true;
                post_event_locked(fatal);
            }
        } else {
            post_event_locked((pam_event_t){
                .type = PAM_EVENT_AUTH_FAILURE,
                .transaction_id = txn,
                .prompt_id = 0,
                .echo_on = 0,
            });
        }
    }
    pthread_mutex_unlock(&ctrl.mutex);

    end_pam_handle(PAM_SUCCESS);
    return NULL;
}

/* public API */

void pam_controller_init(const char *username, const char *display) {
    if (ctrl.initialised) {
        return;
    }

    /* Copy configuration strings. */
    ctrl.username = strdup(username);
    if (ctrl.username == NULL) {
        perror("strdup");
        exit(EXIT_FAILURE);
    }
    if (display != NULL) {
        ctrl.display = strdup(display);
        if (ctrl.display == NULL) {
            perror("strdup");
            exit(EXIT_FAILURE);
        }
    }

    /* Allocate and mlock secure storage. */
    ctrl.secure = calloc(1, sizeof(*ctrl.secure));
    if (ctrl.secure == NULL) {
        perror("calloc");
        exit(EXIT_FAILURE);
    }
#if defined(__linux__)
    if (mlock(ctrl.secure, sizeof(*ctrl.secure)) != 0) {
        perror("mlock(secure storage)");
        exit(EXIT_FAILURE);
    }
#endif

    /* Create the wake-up pipe. The read end is non-blocking so that
     * drain_events never stalls the event loop. */
    if (pipe(ctrl.pipe_fds) != 0) {
        perror("pipe");
        exit(EXIT_FAILURE);
    }
    int flags = fcntl(ctrl.pipe_fds[0], F_GETFL);
    if (flags == -1 || fcntl(ctrl.pipe_fds[0], F_SETFL, flags | O_NONBLOCK) == -1) {
        perror("fcntl(O_NONBLOCK)");
        exit(EXIT_FAILURE);
    }
    flags = fcntl(ctrl.pipe_fds[1], F_GETFL);
    if (flags == -1 || fcntl(ctrl.pipe_fds[1], F_SETFL, flags | O_NONBLOCK) == -1) {
        perror("fcntl(O_NONBLOCK)");
        exit(EXIT_FAILURE);
    }

    /* Initialise synchronisation primitives. */
    if (pthread_mutex_init(&ctrl.mutex, NULL) != 0 ||
        pthread_cond_init(&ctrl.cond, NULL) != 0) {
        fprintf(stderr, "[i3lock] could not initialise mutex/condvar\n");
        exit(EXIT_FAILURE);
    }

    ctrl.next_transaction_id = 1;
    ctrl.next_prompt_id = 1;
    ctrl.initialised = true;

    /* Start the worker thread. */
    if (pthread_create(&ctrl.worker, NULL, worker_main, NULL) != 0) {
        perror("pthread_create");
        exit(EXIT_FAILURE);
    }
}

uint64_t pam_controller_start_auth(const char *password) {
    if (!ctrl.initialised) {
        return 0;
    }

    pthread_mutex_lock(&ctrl.mutex);
    if (ctrl.auth_requested ||
        ctrl.auth_in_progress ||
        ctrl.shutdown_requested ||
        ctrl.fatal_error) {
        pthread_mutex_unlock(&ctrl.mutex);
        return 0;
    }

    /* Stage the password in mlocked storage. */
    size_t len = strlen(password);
    if (len >= SECURE_BUFFER_SIZE) {
        len = SECURE_BUFFER_SIZE - 1;
    }
    memcpy(ctrl.secure->deferred_input, password, len);
    ctrl.secure->deferred_input[len] = '\0';

    uint64_t txn = ctrl.next_transaction_id++;
    ctrl.active_transaction_id = txn;
    ctrl.auth_requested = true;
    ctrl.cancellation_requested = false;
    ctrl.waiting_for_answer = false;
    ctrl.answer_submitted = false;
    ctrl.waiting_prompt_id = 0;
    ctrl.prompts_seen = 0;

    pthread_cond_signal(&ctrl.cond);
    pthread_mutex_unlock(&ctrl.mutex);

    return txn;
}

int pam_controller_submit_answer(uint64_t transaction_id,
                                 uint64_t prompt_id,
                                 const char *answer) {
    if (!ctrl.initialised) {
        return 0;
    }

    pthread_mutex_lock(&ctrl.mutex);
    if (ctrl.shutdown_requested ||
        ctrl.cancellation_requested ||
        !ctrl.waiting_for_answer ||
        ctrl.active_transaction_id != transaction_id ||
        ctrl.waiting_prompt_id != prompt_id) {
        pthread_mutex_unlock(&ctrl.mutex);
        return 0;
    }

    size_t len = strlen(answer);
    if (len >= SECURE_BUFFER_SIZE) {
        len = SECURE_BUFFER_SIZE - 1;
    }
    memcpy(ctrl.secure->pending_response, answer, len);
    ctrl.secure->pending_response[len] = '\0';
    ctrl.answer_submitted = true;

    pthread_cond_signal(&ctrl.cond);
    pthread_mutex_unlock(&ctrl.mutex);
    return 1;
}

void pam_controller_cancel_auth(uint64_t transaction_id) {
    if (!ctrl.initialised || transaction_id == 0) {
        return;
    }

    pthread_mutex_lock(&ctrl.mutex);
    if (ctrl.active_transaction_id == transaction_id &&
        (ctrl.auth_requested || ctrl.auth_in_progress)) {
        ctrl.cancellation_requested = true;
        ctrl.auth_requested = false;
        secure_wipe(ctrl.secure->deferred_input, SECURE_BUFFER_SIZE);
        secure_wipe(ctrl.secure->pending_response, SECURE_BUFFER_SIZE);
        pthread_cond_signal(&ctrl.cond);
    }
    pthread_mutex_unlock(&ctrl.mutex);
}

int pam_controller_get_fd(void) {
    if (!ctrl.initialised) {
        return -1;
    }
    return ctrl.pipe_fds[0];
}

int pam_controller_drain_events(void (*callback)(const pam_event_t *event)) {
    /* Drain the pipe so that libev stops signalling readability. */
    char buf[64];
    ssize_t nread;
    do {
        nread = read(ctrl.pipe_fds[0], buf, sizeof(buf));
    } while (nread > 0 || (nread == -1 && errno == EINTR));

    pthread_mutex_lock(&ctrl.mutex);
    int count = ctrl.event_count;
    pam_event_t snapshot[MAX_EVENTS];
    if (count > 0) {
        memcpy(snapshot, ctrl.events, (size_t)count * sizeof(pam_event_t));
        ctrl.event_count = 0;
    }
    pthread_mutex_unlock(&ctrl.mutex);

    for (int i = 0; i < count; i++) {
        callback(&snapshot[i]);
    }
    return count;
}

void pam_controller_cleanup(void) {
    if (!ctrl.initialised) {
        return;
    }

    /* Tell the worker to exit and wait for it. */
    pthread_mutex_lock(&ctrl.mutex);
    ctrl.shutdown_requested = true;
    pthread_cond_signal(&ctrl.cond);
    pthread_mutex_unlock(&ctrl.mutex);

    pthread_join(ctrl.worker, NULL);

    /* Wipe and free secure storage. */
    if (ctrl.secure != NULL) {
        secure_wipe(ctrl.secure, sizeof(*ctrl.secure));
#if defined(__linux__)
        munlock(ctrl.secure, sizeof(*ctrl.secure));
#endif
        free(ctrl.secure);
        ctrl.secure = NULL;
    }

    close(ctrl.pipe_fds[0]);
    close(ctrl.pipe_fds[1]);
    pthread_mutex_destroy(&ctrl.mutex);
    pthread_cond_destroy(&ctrl.cond);
    free(ctrl.username);
    free(ctrl.display);
    ctrl.username = NULL;
    ctrl.display = NULL;

    ctrl.initialised = false;
}
