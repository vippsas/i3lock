/*
 * Fork-safe PAM controller for i3lock.
 *
 * The controller owns a dedicated worker thread that creates a fresh PAM
 * handle per authentication attempt and runs pam_authenticate,
 * pam_acct_mgmt, pam_setcred, and pam_end. The
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
#include <signal.h>
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
#define PAM_MESSAGE_INPUT_MAX 4096

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
    bool deferred_input_submitted;
    bool fatal_error;
    bool terminal_ack_pending;
    bool pipe_created;
    bool secure_mlocked;
    bool mutex_initialised;
    bool cond_initialised;

    /* Transaction tracking. */
    uint64_t next_transaction_id;
    uint64_t next_prompt_id;
    uint64_t active_transaction_id;
    uint64_t terminal_transaction_id;
    uint64_t waiting_prompt_id;
    int prompts_seen;

    /* PAM conversation structure: passed to every per-attempt handle. */
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
static bool event_is_terminal(pam_event_type_t type) {
    return type == PAM_EVENT_AUTH_SUCCESS ||
           type == PAM_EVENT_AUTH_FAILURE ||
           type == PAM_EVENT_AUTH_CANCELLED ||
           type == PAM_EVENT_AUTH_FATAL;
}

static void remove_event_at_locked(int index) {
    if (index < 0 || index >= ctrl.event_count) {
        return;
    }
    if (index < ctrl.event_count - 1) {
        memmove(ctrl.events + index,
                ctrl.events + index + 1,
                (size_t)(ctrl.event_count - index - 1) * sizeof(ctrl.events[0]));
    }
    ctrl.event_count--;
}

static bool post_event_locked(pam_event_t event) {
    if (ctrl.event_count < MAX_EVENTS) {
        ctrl.events[ctrl.event_count++] = event;
    } else {
        int drop_index = -1;
        for (int i = 0; i < ctrl.event_count; i++) {
            if (ctrl.events[i].type == PAM_EVENT_AUTH_STATUS) {
                drop_index = i;
                break;
            }
        }
        if (drop_index == -1 && event_is_terminal(event.type)) {
            for (int i = 0; i < ctrl.event_count; i++) {
                if (!event_is_terminal(ctrl.events[i].type)) {
                    drop_index = i;
                    break;
                }
            }
        }
        if (drop_index == -1) {
            if (event_is_terminal(event.type)) {
                drop_index = 0;
            } else {
                return event.type == PAM_EVENT_AUTH_STATUS;
            }
        }
        remove_event_at_locked(drop_index);
        ctrl.events[ctrl.event_count++] = event;
    }
    char byte = 0;
    ssize_t written;
    do {
        written = write(ctrl.pipe_fds[1], &byte, 1);
    } while (written == -1 && errno == EINTR);
    return true;
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

static bool pam_message_text_is_valid(const char *text) {
    if (text == NULL) {
        return true;
    }
    return strnlen(text, PAM_MESSAGE_INPUT_MAX) < PAM_MESSAGE_INPUT_MAX;
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

static int start_pam_handle(pam_handle_t **handle) {
    *handle = NULL;
    int ret = pam_start("i3lock", ctrl.username, &ctrl.pam_conv, handle);
    if (ret != PAM_SUCCESS) {
        fprintf(stderr, "[i3lock] PAM worker: pam_start failed (%d)\n", ret);
        return ret;
    }

    if (ctrl.display != NULL) {
        ret = pam_set_item(*handle, PAM_TTY, ctrl.display);
        if (ret != PAM_SUCCESS) {
            fprintf(stderr, "[i3lock] PAM worker: pam_set_item(PAM_TTY) failed (%d)\n", ret);
            pam_end(*handle, ret);
            *handle = NULL;
            return ret;
        }
    }

    return PAM_SUCCESS;
}

static void end_pam_handle(pam_handle_t *handle, int status) {
    if (handle != NULL) {
        pam_end(handle, status);
    }
}

static bool cancellation_requested_locked_read(void) {
    bool cancelled;
    pthread_mutex_lock(&ctrl.mutex);
    cancelled = ctrl.cancellation_requested || ctrl.shutdown_requested;
    pthread_mutex_unlock(&ctrl.mutex);
    return cancelled;
}

static void reset_controller_init_state(void) {
    if (ctrl.secure != NULL) {
        secure_wipe(ctrl.secure, sizeof(*ctrl.secure));
#if defined(__linux__)
        if (ctrl.secure_mlocked) {
            munlock(ctrl.secure, sizeof(*ctrl.secure));
        }
#endif
        free(ctrl.secure);
    }
    if (ctrl.pipe_created) {
        close(ctrl.pipe_fds[0]);
        close(ctrl.pipe_fds[1]);
    }
    if (ctrl.cond_initialised) {
        pthread_cond_destroy(&ctrl.cond);
    }
    if (ctrl.mutex_initialised) {
        pthread_mutex_destroy(&ctrl.mutex);
    }
    free(ctrl.username);
    free(ctrl.display);
    memset(&ctrl, 0, sizeof(ctrl));
}

/* pam_conv callback, running in the worker thread */

static int worker_conv_callback(int num_msg,
                                const struct pam_message **msg,
                                struct pam_response **resp,
                                void *appdata_ptr) {
    (void)appdata_ptr;

    if (num_msg <= 0 ||
        num_msg > PAM_MAX_NUM_MSG ||
        msg == NULL ||
        resp == NULL) {
        return PAM_CONV_ERR;
    }
    *resp = NULL;

    for (int i = 0; i < num_msg; i++) {
        if (msg[i] == NULL || !pam_message_text_is_valid(msg[i]->msg)) {
            return PAM_CONV_ERR;
        }
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
                                ctrl.deferred_input_submitted;

            if (use_deferred) {
                int result = copy_secure_value_to_response(&reply[i].resp,
                                                           ctrl.secure->deferred_input);
                secure_wipe(ctrl.secure->deferred_input, SECURE_BUFFER_SIZE);
                ctrl.deferred_input_submitted = false;
                if (result != PAM_SUCCESS) {
                    pthread_mutex_unlock(&ctrl.mutex);
                    free_replies(reply, num_msg);
                    return result;
                }
                reply[i].resp_retcode = 0;
                continue;
            }

            secure_wipe(ctrl.secure->deferred_input, SECURE_BUFFER_SIZE);
            ctrl.deferred_input_submitted = false;
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
            if (!post_event_locked(event)) {
                ctrl.waiting_for_answer = false;
                ctrl.answer_submitted = false;
                ctrl.waiting_prompt_id = 0;
                pthread_mutex_unlock(&ctrl.mutex);
                free_replies(reply, num_msg);
                return PAM_CONV_ERR;
            }

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
            (void)post_event_locked(event);
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

    pam_handle_t *handle = NULL;

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

        int ret = start_pam_handle(&handle);
        int terminal_status = ret;
        if (ret == PAM_SUCCESS) {
            /* pam_authenticate blocks and invokes worker_conv_callback. */
            ret = pam_authenticate(handle, 0);
            terminal_status = ret;
        }

        if (ret == PAM_SUCCESS && !cancellation_requested_locked_read()) {
            int acct_ret = pam_acct_mgmt(handle, 0);
            if (acct_ret != PAM_SUCCESS) {
                fprintf(stderr,
                        "[i3lock] PAM worker: pam_acct_mgmt() failed (%d)\n",
                        acct_ret);
                terminal_status = acct_ret;
            }
        }

        if (ret == PAM_SUCCESS && !cancellation_requested_locked_read()) {
            int setcred_ret = pam_setcred(handle, PAM_REFRESH_CRED);
            if (setcred_ret != PAM_SUCCESS) {
                fprintf(stderr,
                        "[i3lock] PAM worker: pam_setcred(PAM_REFRESH_CRED) failed (%d)\n",
                        setcred_ret);
                terminal_status = setcred_ret;
            }
        }

        if (cancellation_requested_locked_read()) {
            terminal_status = PAM_CONV_ERR;
        }
        end_pam_handle(handle, terminal_status);
        handle = NULL;

        pthread_mutex_lock(&ctrl.mutex);
        secure_wipe(ctrl.secure->deferred_input, SECURE_BUFFER_SIZE);
        ctrl.deferred_input_submitted = false;
        secure_wipe(ctrl.secure->pending_response, SECURE_BUFFER_SIZE);
        ctrl.waiting_for_answer = false;
        ctrl.answer_submitted = false;
        ctrl.waiting_prompt_id = 0;
        if (ctrl.cancellation_requested) {
            ctrl.cancellation_requested = false;
            ctrl.terminal_ack_pending = true;
            ctrl.terminal_transaction_id = txn;
            (void)post_event_locked((pam_event_t){
                .type = PAM_EVENT_AUTH_CANCELLED,
                .transaction_id = txn,
                .prompt_id = 0,
                .echo_on = 0,
            });
        } else if (ret == PAM_SUCCESS) {
            ctrl.terminal_ack_pending = true;
            ctrl.terminal_transaction_id = txn;
            (void)post_event_locked((pam_event_t){
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
            ctrl.terminal_ack_pending = true;
            ctrl.terminal_transaction_id = txn;
            (void)post_event_locked(event);
        } else if (ret == PAM_SYSTEM_ERR || ret == PAM_SERVICE_ERR) {
            pam_event_t event = {
                .type = PAM_EVENT_AUTH_FAILURE,
                .transaction_id = txn,
                .prompt_id = 0,
                .echo_on = 0,
                .is_error = 1,
            };
            event_set_text(&event, "Authentication service error");
            ctrl.terminal_ack_pending = true;
            ctrl.terminal_transaction_id = txn;
            (void)post_event_locked(event);
        } else {
            ctrl.terminal_ack_pending = true;
            ctrl.terminal_transaction_id = txn;
            (void)post_event_locked((pam_event_t){
                .type = PAM_EVENT_AUTH_FAILURE,
                .transaction_id = txn,
                .prompt_id = 0,
                .echo_on = 0,
            });
        }

        while (ctrl.terminal_ack_pending && !ctrl.shutdown_requested) {
            pthread_cond_wait(&ctrl.cond, &ctrl.mutex);
        }
        if (!ctrl.shutdown_requested) {
            ctrl.auth_in_progress = false;
        }
    }
    pthread_mutex_unlock(&ctrl.mutex);

    return NULL;
}

/* public API */

int pam_controller_init(const char *username, const char *display) {
    if (ctrl.initialised) {
        return 1;
    }

    /* Copy configuration strings. */
    ctrl.username = strdup(username);
    if (ctrl.username == NULL) {
        perror("strdup");
        reset_controller_init_state();
        return 0;
    }
    if (display != NULL) {
        ctrl.display = strdup(display);
        if (ctrl.display == NULL) {
            perror("strdup");
            reset_controller_init_state();
            return 0;
        }
    }

    /* Allocate and mlock secure storage. */
    ctrl.secure = calloc(1, sizeof(*ctrl.secure));
    if (ctrl.secure == NULL) {
        perror("calloc");
        reset_controller_init_state();
        return 0;
    }
#if defined(__linux__)
    if (mlock(ctrl.secure, sizeof(*ctrl.secure)) != 0) {
        perror("mlock(secure storage)");
        reset_controller_init_state();
        return 0;
    }
    ctrl.secure_mlocked = true;
#endif

    /* Create the wake-up pipe. The read end is non-blocking so that
     * drain_events never stalls the event loop. */
    if (pipe(ctrl.pipe_fds) != 0) {
        perror("pipe");
        reset_controller_init_state();
        return 0;
    }
    ctrl.pipe_created = true;
    int flags = fcntl(ctrl.pipe_fds[0], F_GETFL);
    if (flags == -1 || fcntl(ctrl.pipe_fds[0], F_SETFL, flags | O_NONBLOCK) == -1) {
        perror("fcntl(O_NONBLOCK)");
        reset_controller_init_state();
        return 0;
    }
    flags = fcntl(ctrl.pipe_fds[1], F_GETFL);
    if (flags == -1 || fcntl(ctrl.pipe_fds[1], F_SETFL, flags | O_NONBLOCK) == -1) {
        perror("fcntl(O_NONBLOCK)");
        reset_controller_init_state();
        return 0;
    }

    /* Initialise synchronisation primitives. */
    if (pthread_mutex_init(&ctrl.mutex, NULL) != 0) {
        fprintf(stderr, "[i3lock] could not initialise mutex\n");
        reset_controller_init_state();
        return 0;
    }
    ctrl.mutex_initialised = true;
    if (pthread_cond_init(&ctrl.cond, NULL) != 0) {
        fprintf(stderr, "[i3lock] could not initialise condvar\n");
        reset_controller_init_state();
        return 0;
    }
    ctrl.cond_initialised = true;

    ctrl.next_transaction_id = 1;
    ctrl.next_prompt_id = 1;
    ctrl.pam_conv = (struct pam_conv){worker_conv_callback, NULL};

    struct sigaction action = {
        .sa_handler = SIG_IGN,
    };
    sigemptyset(&action.sa_mask);
    sigaction(SIGPIPE, &action, NULL);

    /* Start the worker thread. */
    if (pthread_create(&ctrl.worker, NULL, worker_main, NULL) != 0) {
        perror("pthread_create");
        reset_controller_init_state();
        return 0;
    }
    ctrl.initialised = true;
    return 1;
}

uint64_t pam_controller_start_auth(const char *password) {
    if (!ctrl.initialised) {
        return 0;
    }

    pthread_mutex_lock(&ctrl.mutex);
    if (ctrl.auth_requested ||
        ctrl.auth_in_progress ||
        ctrl.shutdown_requested ||
        ctrl.fatal_error ||
        ctrl.terminal_ack_pending) {
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
    ctrl.deferred_input_submitted = true;

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
    if (ctrl.terminal_ack_pending &&
        ctrl.terminal_transaction_id == transaction_id) {
        ctrl.terminal_ack_pending = false;
        ctrl.terminal_transaction_id = 0;
        ctrl.auth_in_progress = false;
        pthread_cond_signal(&ctrl.cond);
    }
    if (ctrl.active_transaction_id == transaction_id &&
        (ctrl.auth_requested || ctrl.auth_in_progress)) {
        ctrl.cancellation_requested = true;
        ctrl.auth_requested = false;
        secure_wipe(ctrl.secure->deferred_input, SECURE_BUFFER_SIZE);
        ctrl.deferred_input_submitted = false;
        secure_wipe(ctrl.secure->pending_response, SECURE_BUFFER_SIZE);
        pthread_cond_signal(&ctrl.cond);
    }
    pthread_mutex_unlock(&ctrl.mutex);
}

void pam_controller_ack_terminal(uint64_t transaction_id) {
    if (!ctrl.initialised) {
        return;
    }

    pthread_mutex_lock(&ctrl.mutex);
    if (ctrl.terminal_ack_pending &&
        ctrl.terminal_transaction_id == transaction_id) {
        ctrl.terminal_ack_pending = false;
        ctrl.terminal_transaction_id = 0;
        ctrl.auth_in_progress = false;
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
