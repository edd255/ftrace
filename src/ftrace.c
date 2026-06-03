#include <errno.h>
#include <fcntl.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/ptrace.h>
#include <sys/user.h>
#include <sys/wait.h>

#include "functools.h"
#include "logging.h"
#include "ptrace.h"
#include "readelf.h"

#define SIG_LEN 100

typedef struct callstack {
    char sig[SIG_LEN];
    struct callstack* prev;
} callstack_t;

const uint8_t trap_inst = 0xCC;

const char* blacklist[] = {
    "",
    "frame_dummy",
    "register_tm_clones",
    "deregister_tm_clones",
    "__do_global_dtors_aux"
};

void usage(char* prog);

void add_call(char sig[SIG_LEN]);
char* get_call(void);
void delete_call(void);

int add_breakpoint(void* addr);
int restore_code(void* addr, int len, struct elf* e);

bool in_blacklist(char* name);
int register_functions(struct elf* e);

void print_depth(int d);
void trace(pid_t pid);
void traced(void);

format_t* func_fmts = NULL;
callstack_t* call_stack = NULL;

// globals from command line arguments
bool show_ret = false;
char** traced_argv;
char* call_fmt = "%s\n";
char* ret_fmt = NULL;

pid_t child;

void usage(char* prog) {
    printf(
        "Usage: %s <program> [arg 1] [arg2] ...\n\n"

        "Optional parameters:\n"
        "  -C          - adds colored output\n"
        "  -H <file>   - header file to use for function logging\n"
        "  -R          - display function return values\n"
        "  -o <file>   - specifies output file (replaces stderr)\n"
        "  -h          - display this message\n\n",

        prog
    );
    exit(1);
}

void add_call(char sig[SIG_LEN]) {
    callstack_t* new_call = malloc(sizeof(*new_call));
    memcpy(new_call->sig, sig, SIG_LEN);
    new_call->prev = call_stack;
    call_stack = new_call;
}

char* get_call(void) {
    if (call_stack == NULL) {
        return NULL;
    } else {
        return call_stack->sig;
    }
}

void delete_call(void) {
    if (call_stack == NULL) {
        return;
    }

    callstack_t* tmp = call_stack;
    call_stack = call_stack->prev;
    free(tmp);
}

int add_breakpoint(void* addr) {
    uint8_t bp[1] = {trap_inst};
    return write_data(child, addr, bp, sizeof(bp));
}

int restore_code(void* addr, int len, struct elf* e) {
    return write_data(
        child,
        addr,
        bytes_from_addr_in_section(e, addr, ".text"),
        len
    );
}

bool in_blacklist(char* name) {
    for (int i = 0; i < sizeof(blacklist) / sizeof(blacklist[0]); i++) {
        if (!strcmp(name, blacklist[i])) {
            return true;
        }
    }

    return false;
}

int register_functions(struct elf* e) {
    for (int i = 0; i < e->n_syms; i++) {
        if (sym_in_section(e, i, ".text")
            && !in_blacklist(get_sym_name(e, i))) {
            if (add_breakpoint(get_sym_addr(e, i)) == -1) {
                return -1;
            }
            func_fmts = add_format(func_fmts, get_sym_addr(e, i), i, NULL);
        }
    }

    return 0;
}

void print_depth(int d) {
    while (d--) {
        trace_print(RESET, " ");
    }
}

void trace(pid_t pid) {
    child = pid;

    int fd = open(traced_argv[0], O_RDONLY);
    if (fd == -1) {
        error("failed to open file");
    }

    struct elf* e = readelf(fd);
    if (e == NULL) {
        kill(child, SIGKILL);
        waitpid(child, NULL, 0);
        error("failed to read elf file for symbols");
    }

    int status;
    wait(&status);

    if (register_functions(e) == -1) {
        kill(child, SIGKILL);
        waitpid(child, NULL, 0);
        error("failed to register function breakpoints");
    }
    ptrace(PTRACE_CONT, child, NULL, NULL);

    int depth = 0;
    while (1) {
        wait(&status);

        if (WIFEXITED(status) || WIFSIGNALED(status)) {
            // printf("child exited of signal %d\n", WSTOPSIG(status));
            break;
        }

        if (WSTOPSIG(status) == SIGTRAP) {
            struct user_regs_struct regs;
            if (ptrace(PTRACE_GETREGS, child, NULL, &regs) == -1) {
                error("error getting regs");
            }

            void* bp_addr = (void*)(regs.rip - 1);
            int sym_i = at_symbol(
                e,
                bp_addr
            );  // minus 1 because int 3 already executed

            if (sym_i == -1) {
                // we are returning from a local function call
                depth -= 1;

                if (ret_fmt != NULL) {
                    print_depth(depth * 2);
                    trace_print(RED, ret_fmt, get_call(), regs.rax);
                }

                delete_call();
            } else {
                // sym_i != -1 therefore we are at a function breakpoint
                format_t* fmt = get_format(func_fmts, bp_addr);

                if (!fmt->fancy) {
                    char fmt_buf[FMT_LEN];
                    memset(fmt_buf, 0, sizeof(fmt_buf));
                    fancy_func_fmt(
                        e,
                        fmt->sym_i,
                        fmt_buf,
                        sizeof(fmt_buf),
                        child
                    );
                    update_format(func_fmts, fmt->addr, fmt_buf);
                    fmt->fancy = true;
                }

                char sig[SIG_LEN];
                snprintf(
                    sig,
                    SIG_LEN - 1,
                    fmt->str,
                    regs.rdi,
                    regs.rsi,
                    regs.rdx
                );
                add_call(sig);

                print_depth(depth * 2);
                trace_print(GREEN, call_fmt, sig);

                void* ret_addr =
                    (void*)ptrace(PTRACE_PEEKTEXT, child, regs.rsp, NULL);
                if (addr_in_section(e, ret_addr, ".text")) {
                    add_breakpoint(ret_addr);
                    depth += 1;
                }
            }

            regs.rip -= 1;
            ptrace(PTRACE_SETREGS, child, NULL, &regs);
            restore_code(bp_addr, 1, e);

            ptrace(PTRACE_SINGLESTEP, child, NULL, NULL);
            wait(&status);

            add_breakpoint(bp_addr);

            ptrace(PTRACE_CONT, child, NULL, NULL);
        } else {
            // wasn't our breakpoint -- deliver signal to child
            ptrace(PTRACE_CONT, child, NULL, WSTOPSIG(status));
        }
    }
}

void traced(void) {
    if (ptrace(PTRACE_TRACEME, NULL, NULL, NULL) == -1) {
        error("traceme failed");
    }
    if (execvp(traced_argv[0], traced_argv) == -1) {
        error("could not execute file");
    }
}

int main(int argc, char** argv) {
    if (argc == 1) {
        usage(argv[0]);
    }

    int opt;
    while ((opt = getopt(argc, argv, "+CH:Ro:h")) != -1) {
        switch (opt) {
            case 'C':
                colored = true;
                break;
            case 'H':
                // read in header file and set formats accordingly
                error("Option 'H' not yet supported sorry!");
                break;
            case 'R':
                call_fmt = ">> %s\n";
                ret_fmt = "<< %s = %d\n";
                break;
            case 'o':
                trace_fd = open(optarg, O_WRONLY | O_CREAT | O_TRUNC, 0666);
                if (trace_fd == -1) {
                    error("Couldn't open output file %s", optarg);
                }
                break;
            case 'h':
            default:
                usage(argv[0]);
                break;
        }
    }

    traced_argv = argv + optind;

    if (access(traced_argv[0], R_OK | X_OK) == -1) {
        error("Unable to open %s", traced_argv[0]);
    }

    pid_t pid = fork();
    if (pid == -1) {
        error("failed to fork");
    }

    if (pid == 0) {
        traced();
    } else {
        trace(pid);
    }

    return 0;
}
