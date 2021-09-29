/**
 * @file tsh.c
 * @brief A tiny shell program with job control
 * This simple Linux shell program, tsh (tiny shell), that supports a simple
 * form of job control and I/O redirection. The shell is an interactive
 * command-line interpreter that runs programs on behalf of the user. The shell
 * repeatedly prints a prompt, waits for a command line on stdin, and then
 * carries out some action, as directed by the contents of the command line.
 * Built-in commands run within the shell's process.
 *
 * @author Tao Wang <taowang@andrew.cmu.edu>
 */

#include "csapp.h"
#include "tsh_helper.h"

#include <assert.h>
#include <ctype.h>
#include <errno.h>
#include <fcntl.h>
#include <getopt.h>
#include <signal.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/wait.h>
#include <unistd.h>

/*
 * If DEBUG is defined, enable contracts and printing on dbg_printf.
 */
#ifdef DEBUG
/* When debugging is enabled, these form aliases to useful functions */
#define dbg_printf(...) printf(__VA_ARGS__)
#define dbg_requires(...) assert(__VA_ARGS__)
#define dbg_assert(...) assert(__VA_ARGS__)
#define dbg_ensures(...) assert(__VA_ARGS__)
#else
/* When debugging is disabled, no code gets generated for these */
#define dbg_printf(...)
#define dbg_requires(...)
#define dbg_assert(...)
#define dbg_ensures(...)
#endif

/* Function prototypes */
void eval(const char *cmdline);
void sigchld_handler(int sig);
void sigtstp_handler(int sig);
void sigint_handler(int sig);
void sigquit_handler(int sig);
void cleanup(void);

/* Wrapper functions */
pid_t Fork(void);
int Sigprocmask(int how, const sigset_t *set, sigset_t *oldset);
pid_t Wait(pid_t pid, int *status, int options);
int Sigemptyset(sigset_t *set);
int Sigfillset(sigset_t *set);
int Sigaddset(sigset_t *set, int signum);
int Sigdelset(sigset_t *set, int signum);
int Sigsuspend(const sigset_t *mask);
int Setpgid(pid_t pid, pid_t pgid);
int Open(char *filename, int flags);
int Close(int fd);

/* Helper functions */
void set_job_state(parseline_return type, job_state *cur_state);
int get_id(char *s, bool *is_job);
void fgbg(struct cmdline_tokens token, bool is_fg);

// global variable
volatile sig_atomic_t fg_pid; // Foreground job pid

/**
 * @brief "Each function should be prefaced with a comment describing the
 * purpose of the function (in a sentence or two), the function's arguments and
 *  return value, any error cases that are relevant to the caller,
 *  any pertinent side effects, and any assumptions that the function makes."
 */
int main(int argc, char **argv) {
    char c;
    char cmdline[MAXLINE_TSH]; // Cmdline for fgets
    bool emit_prompt = true;   // Emit prompt (default)

    // Redirect stderr to stdout (so that driver will get all output
    // on the pipe connected to stdout)
    if (dup2(STDOUT_FILENO, STDERR_FILENO) < 0) {
        perror("dup2 error");
        exit(1);
    }

    // Parse the command line
    while ((c = getopt(argc, argv, "hvp")) != EOF) {
        switch (c) {
        case 'h': // Prints help message
            usage();
            break;
        case 'v': // Emits additional diagnostic info
            verbose = true;
            break;
        case 'p': // Disables prompt printing
            emit_prompt = false;
            break;
        default:
            usage();
        }
    }

    // Create environment variable
    if (putenv("MY_ENV=42") < 0) {
        perror("putenv error");
        exit(1);
    }

    // Set buffering mode of stdout to line buffering.
    // This prevents lines from being printed in the wrong order.
    if (setvbuf(stdout, NULL, _IOLBF, 0) < 0) {
        perror("setvbuf error");
        exit(1);
    }

    // Initialize the job list
    init_job_list();

    // Register a function to clean up the job list on program termination.
    // The function may not run in the case of abnormal termination (e.g. when
    // using exit or terminating due to a signal handler), so in those cases,
    // we trust that the OS will clean up any remaining resources.
    if (atexit(cleanup) < 0) {
        perror("atexit error");
        exit(1);
    }

    // Install the signal handlers
    Signal(SIGINT, sigint_handler);   // Handles Ctrl-C
    Signal(SIGTSTP, sigtstp_handler); // Handles Ctrl-Z
    Signal(SIGCHLD, sigchld_handler); // Handles terminated or stopped child

    Signal(SIGTTIN, SIG_IGN);
    Signal(SIGTTOU, SIG_IGN);

    Signal(SIGQUIT, sigquit_handler);

    // Execute the shell's read/eval loop
    while (true) {
        if (emit_prompt) {
            printf("%s", prompt);

            // We must flush stdout since we are not printing a full line.
            fflush(stdout);
        }

        if ((fgets(cmdline, MAXLINE_TSH, stdin) == NULL) && ferror(stdin)) {
            perror("fgets error");
            exit(1);
        }

        if (feof(stdin)) {
            // End of file (Ctrl-D)
            printf("\n");
            return 0;
        }

        // Remove any trailing newline
        char *newline = strchr(cmdline, '\n');
        if (newline != NULL) {
            *newline = '\0';
        }

        // Evaluate the command line
        eval(cmdline);
    }

    return -1; // control never reaches here
}

/**
 * @brief tsh repeatly calls the function in a loop, so tsh is able to prompt
 * the message to let users input commands.
 *
 * @param[in] the input command line from users.
 */
void eval(const char *cmdline) {
    // Init
    parseline_return parse_result;
    struct cmdline_tokens token;
    sigset_t mask, prev, mask_all, prev_all;
    pid_t pid;
    int in_fd = -1, out_fd = -1;

    // Set masks
    Sigemptyset(&mask);
    Sigfillset(&mask_all);
    Sigaddset(&mask, SIGCHLD);
    Sigaddset(&mask, SIGINT);
    Sigaddset(&mask, SIGTSTP);

    // Parse command line
    parse_result = parseline(cmdline, &token);

    // Prompt again when there is no valid message or error message.
    if (parse_result == PARSELINE_ERROR || parse_result == PARSELINE_EMPTY) {
        return;
    }

    if (token.builtin == BUILTIN_NONE) {
        job_state cur_state;
        jid_t job_id;
        Sigprocmask(SIG_BLOCK, &mask, &prev);
        if ((pid = Fork()) == 0) { /* Child runs user job */
            // I/O Redirection
            if (token.infile) {
                in_fd = Open(token.infile, O_RDONLY);
                if (in_fd < 0)
                    _exit(0);
                dup2(in_fd, STDIN_FILENO);
            }
            if (token.outfile) {
                out_fd = Open(token.outfile, O_WRONLY | O_CREAT | O_TRUNC);
                if (out_fd < 0)
                    _exit(0);
                dup2(out_fd, STDOUT_FILENO);
            }

            Sigprocmask(SIG_SETMASK, &prev, NULL);
            Setpgid(getpid(), 0);
            if (execve(token.argv[0], token.argv, environ) < 0) {
                sio_printf("%s: %s\n", token.argv[0], strerror(errno));
                if (token.infile)
                    Close(in_fd);
                if (token.outfile)
                    Close(out_fd);
                _exit(0);
            }
        }

        Sigprocmask(SIG_BLOCK, &mask_all, &prev_all);
        set_job_state(parse_result, &cur_state);
        job_id = add_job(pid, cur_state, cmdline);
        if (cur_state == BG)
            sio_printf("[%d] (%d) %s\n", job_id, pid, cmdline);
        Sigprocmask(SIG_SETMASK, &prev_all, NULL);

        if (parse_result == PARSELINE_FG) {
            fg_pid = 0;
            while (!fg_pid) {
                Sigsuspend(&prev);
            }
        }
        Sigprocmask(SIG_SETMASK, &prev, NULL);

    } else if (token.builtin == BUILTIN_QUIT) {
        cleanup();
        _exit(0);
    } else if (token.builtin == BUILTIN_JOBS) {
        if (token.outfile) {
            out_fd = Open(token.outfile, O_WRONLY | O_CREAT | O_TRUNC);
            if (out_fd < 0)
                return;
        } else {
            out_fd = STDOUT_FILENO;
        }
        Sigprocmask(SIG_SETMASK, &mask_all, &prev_all);
        list_jobs(out_fd);
        Sigprocmask(SIG_SETMASK, &prev_all, NULL);
        if (out_fd != STDOUT_FILENO)
            Close(out_fd);
    } else if (token.builtin == BUILTIN_BG) {
        fgbg(token, false);
    } else if (token.builtin == BUILTIN_FG) {
        fgbg(token, true);
    }
}

/*******************
 * Signal handlers *
 *******************/

/**
 * @brief When the shell has received SIGCHLD signal, then handle the
 * signal properly by this handler function.
 */
void sigchld_handler(int sig) {
    int olderrno = errno;
    sigset_t mask_all, prev_all;
    int status;
    jid_t jid = 0;
    pid_t pid;

    Sigfillset(&mask_all);
    Sigprocmask(SIG_SETMASK, &mask_all, &prev_all);
    while ((pid = Wait(-1, &status, WNOHANG | WUNTRACED)) > 0) {
        jid = job_from_pid(pid);
        if (job_get_state(jid) == FG)
            fg_pid = pid;

        if (WIFSTOPPED(status)) {
            job_set_state(jid, ST);
            sio_printf("Job [%d] (%d) stopped by signal %d\n", jid, pid,
                       WSTOPSIG(status));
        } else {
            if (WIFSIGNALED(status))
                sio_printf("Job [%d] (%d) terminated by signal %d\n", jid, pid,
                           WTERMSIG(status));
            delete_job(jid);
        }
    }
    Sigprocmask(SIG_SETMASK, &prev_all, NULL);
    errno = olderrno;
}

/**
 * @brief When the shell has received SIGINT signal, then handle the
 * signal properly by this handler function.
 */
void sigint_handler(int sig) {
    int olderrno = errno;
    sigset_t mask_all, prev_all;
    Sigfillset(&mask_all);
    Sigprocmask(SIG_SETMASK, &mask_all, &prev_all);
    jid_t jid = fg_job();
    if (jid > 0) {
        pid_t pid = job_get_pid(jid);
        killpg(pid, SIGINT);
    }
    Sigprocmask(SIG_SETMASK, &prev_all, NULL);
    errno = olderrno;
}

/**
 * @brief When the shell has received SIGTSTP signal, handle the
 * signal properly by this handler function.
 */
void sigtstp_handler(int sig) {
    int olderrno = errno;
    sigset_t mask_all, prev_all;
    Sigfillset(&mask_all);
    Sigprocmask(SIG_SETMASK, &mask_all, &prev_all);
    jid_t jid = fg_job();
    if (jid > 0) {
        pid_t pid = job_get_pid(jid);
        killpg(pid, SIGTSTP);
    }
    Sigprocmask(SIG_SETMASK, &prev_all, NULL);
    errno = olderrno;
}
/**
 * @brief Attempt to clean up global resources when the program exits.
 *
 * In particular, the job list must be freed at this time, since it may
 * contain leftover buffers from existing or even deleted jobs.
 */
void cleanup(void) {
    // Signals handlers need to be removed before destroying the joblist
    Signal(SIGINT, SIG_DFL);  // Handles Ctrl-C
    Signal(SIGTSTP, SIG_DFL); // Handles Ctrl-Z
    Signal(SIGCHLD, SIG_DFL); // Handles terminated or stopped child

    destroy_job_list();
}

/***********************************
 *    Helpper  Functions  Begin    *
 ***********************************/

/**
 * @brief Print error message, then exit the calling process.
 *
 * Use this function when a fatal event happen, which would exit the calling
 * process. Not alway appropriate to exit when something goes wrong.
 *
 * @param[in] Message needs to be printed out
 */
void unix_error(char *msg) {
    sio_dprintf(STDERR_FILENO, "%s: %s\n", msg, strerror(errno));
    _exit(-1);
}

/**
 * @brief Set the job state by the parseline_return type.
 *
 * @param[in] one parseline_return type
 * @param[in] one job state
 */
void set_job_state(parseline_return type, job_state *cur_state) {
    if (type == PARSELINE_FG)
        *cur_state = FG;
    else
        *cur_state = BG;
}

/**
 * @brief Parse a string into a JID or PID.
 *
 * Use this function when a fatal event happen, which would exit the calling
 * process. Not alway appropriate to exit when something goes wrong.
 *
 * @param[in] A valid string to be parsed.
 * @param[in] This value can help us to know is this a JID or PID
 * @param[out] PID or JID
 */
int get_id(char *s, bool *is_job) {
    if (s[0] == '%') {
        *is_job = true;
        return atoi(s + 1);
    }

    *is_job = false;
    return atoi(s);
}

/**
 * @brief Send SIGCONT to the entire process group.
 *
 * When use the foreground or backgroud builtin command, Send SIGCONT to the
 * entire process group of a process.
 *
 * @param[in] Command line information
 * @param[in] foreground or backgroud builtin command
 */
void fgbg(struct cmdline_tokens token, bool is_fg) {
    bool is_job;
    int id; // JID or PID
    pid_t pid = 0;
    jid_t jid = 0;

    // Not a JID/PID number
    if (token.argc == 1) {
        if (is_fg)
            sio_printf("%s\n", "fg command requires PID or %jobid argument");
        else
            sio_printf("%s\n", "bg command requires PID or %jobid argument");
        return;
    }

    id = get_id(token.argv[1], &is_job);

    // Not a valid arguement
    if (id == 0) {
        if (is_fg)
            sio_printf("%s\n", "fg: argument must be a PID or %jobid");
        else
            sio_printf("%s\n", "bg: argument must be a PID or %jobid");
        return;
    }

    sigset_t mask_all, prev_all;

    Sigfillset(&mask_all);
    Sigprocmask(SIG_SETMASK, &mask_all, &prev_all);

    // Get PID and JID
    if (is_job) {
        if (job_exists(id)) {
            jid = id;
            pid = job_get_pid(jid);
        } else {
            sio_printf("%s: No such job\n", token.argv[1]);
            Sigprocmask(SIG_SETMASK, &prev_all, NULL);
            return;
        }
    } else {
        pid = id;
        jid = job_from_pid(pid);
    }

    // Send SIGCONT to a group of process
    if (!is_fg) {
        job_set_state(jid, BG);
        sio_printf("[%d] (%d) %s\n", jid, pid, job_get_cmdline(jid));
        kill(-pid, SIGCONT);
    } else {
        job_set_state(jid, FG);
        fg_pid = 0;
        kill(-pid, SIGCONT);
        while (!fg_pid)
            Sigsuspend(&prev_all);
    }
    Sigprocmask(SIG_SETMASK, &prev_all, NULL);
}

/***********************************
 *    Wrapper  Functions  Begin    *
 ***********************************/

/**
 * @brief A wrapper function for the system call - fork()
 *        This wrapper function helps handing error.
 */
pid_t Fork(void) {
    pid_t pid;
    if ((pid = fork()) < 0)
        unix_error("Fork error");
    return pid;
}

/**
 * @brief A wrapper function for the system call - sigprocmask
 *        This wrapper function helps handing error.
 */
int Sigprocmask(int how, const sigset_t *set, sigset_t *oldset) {
    int retval;
    if ((retval = sigprocmask(how, set, oldset)) < 0)
        unix_error("Sigprocmask error");
    return retval;
}

/**
 * @brief A wrapper function for the system call - waitpid
 *        This wrapper function helps handing error.
 */
pid_t Wait(pid_t pid, int *status, int options) {
    int olderrno = errno;
    pid_t wpid;
    if ((wpid = waitpid(pid, status, options)) < 0) {
        if (!WIFEXITED(*status) && errno != ECHILD) {
            unix_error("Wait error");
        }
    }
    errno = olderrno;
    return wpid;
}

/**
 * @brief A wrapper function for the system call - sigemptyset
 *        This wrapper function helps handing error.
 */
int Sigemptyset(sigset_t *set) {
    int retval;
    if ((retval = sigemptyset(set)) < 0)
        unix_error("Sigemptyset error");
    return retval;
}

/**
 * @brief A wrapper function for the system call - sigfillset
 *        This wrapper function helps handing error.
 */
int Sigfillset(sigset_t *set) {
    int retval;
    if ((retval = sigfillset(set)) < 0)
        unix_error("Sigfillset error");
    return retval;
}

/**
 * @brief A wrapper function for the system call - sigaddset
 *        This wrapper function helps handing error.
 */
int Sigaddset(sigset_t *set, int signum) {
    int retval;
    if ((retval = sigaddset(set, signum)) < 0)
        unix_error("Sigaddset error");
    return retval;
}

/**
 * @brief A wrapper function for the system call - sigaddset
 *        This wrapper function helps handing error.
 */
int Sigdelset(sigset_t *set, int signum) {
    int retval;
    if ((retval = sigdelset(set, signum)) < 0)
        unix_error("Sigdelset error");
    return retval;
}

/**
 * @brief A wrapper function for the system call - sigsuspend
 *        This wrapper function helps handing error.
 */
int Sigsuspend(const sigset_t *mask) {
    int olderrno = errno;
    int retval = sigsuspend(mask);
    if (errno == EFAULT)
        unix_error("Sigsuspend error");
    errno = olderrno;
    return retval;
}

/**
 * @brief A wrapper function for the system call - setpgid
 *        This wrapper function helps handing error.
 */
int Setpgid(pid_t pid, pid_t pgid) {
    int retval;
    if ((retval = setpgid(pid, pgid)) < 0)
        unix_error("Setpgid error");
    return retval;
}

/**
 * @brief A wrapper function for the system call - open
 *        This wrapper function helps handing error.
 */
int Open(char *filename, int flags) {
    int fd;
    if ((fd = open(filename, flags, DEF_MODE)) < 0) {
        sio_printf("%s: %s\n", filename, strerror(errno));
    }
    return fd;
}

/**
 * @brief A wrapper function for the system call - close
 *        This wrapper function helps handing error.
 */
int Close(int fd) {
    int retval;
    if ((retval = close(fd)) < 0) {
        if (errno == EBADF)
            sio_printf("Close error: %s\n", strerror(errno));
    }
    return retval;
}