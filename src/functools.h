#pragma once

#include <capstone/capstone.h>
#include <errno.h>
#include <string.h>

#include "logging.h"
#include "ptrace.h"
#include "readelf.h"

#define FMT_LEN 100

typedef enum reg_state { REG_UNDEF, REG_WRITTEN, REG_READ } reg_state;

typedef struct format {
    void* addr;
    int sym_i;
    char str[FMT_LEN];
    bool fancy;
    struct format* next;
} format_t;

format_t* add_format(format_t* fmt, void* addr, int sym_i, char* str) {
    format_t* new_fmt = malloc(sizeof(*new_fmt));
    if (new_fmt == NULL) {
        return NULL;
    }

    new_fmt->addr = addr;
    new_fmt->sym_i = sym_i;
    if (str == NULL) {
        new_fmt->str[0] = 0;
    } else {
        snprintf(new_fmt->str, sizeof(new_fmt->str), "%s", str);
    }
    new_fmt->fancy = false;
    new_fmt->next = fmt;

    return new_fmt;
}

format_t* get_format(format_t* fmt, void* addr) {
    while (fmt != NULL) {
        if (fmt->addr == addr) {
            return fmt;
        }
        fmt = fmt->next;
    }

    return NULL;
}

bool update_format(format_t* fmt, void* addr, char* str) {
    while (fmt != NULL) {
        if (fmt->addr == addr) {
            snprintf(fmt->str, sizeof(fmt->str), "%s", str);
            return true;
        }
        fmt = fmt->next;
    }

    return false;
}

void print_formats(format_t* fmt) {
    if (fmt == NULL) {
        return;
    }
    printf("[%p] ", fmt->addr);
    puts(fmt->str);
    print_formats(fmt->next);
}

int get_reg_arg_index(x86_reg reg) {
    switch (reg) {
        case X86_REG_RDI:
        case X86_REG_EDI:
            return 0;
        case X86_REG_RSI:
        case X86_REG_ESI:
            return 1;
        case X86_REG_RDX:
        case X86_REG_EDX:
            return 2;
        case X86_REG_RCX:
        case X86_REG_ECX:
            return 3;
        default:
            return -1;
    }
}

int n_args_from_regs(reg_state* arg_regs, int n) {
    int i = 0;
    for (; i < n; i++) {
        if (arg_regs[i] != REG_READ) {
            return i;
        }
    }

    return i;
}

// gets number of arguments for x86_64 system v abi assuming no passing structs
// by value
int n_func_args(struct elf* e, int sym_i) {
    void* func = get_sym_addr(e, sym_i);
    uint8_t* code = bytes_from_addr_in_section(e, get_sym_addr(e, sym_i), ".text");
    size_t size = get_sym_size(e, sym_i);

    if (size == 0) {
        printf("no size information for %s\n", get_sym_name(e, sym_i));
        return -1;
    }

    csh handle;
    if (cs_open(CS_ARCH_X86, CS_MODE_64, &handle) != CS_ERR_OK) {
        printf("unable to initilize handle\n");
        return -1;
    }

    cs_option(handle, CS_OPT_DETAIL, CS_OPT_ON);

    cs_insn* all_insn;
    size_t count = cs_disasm(handle, code, size, (uint64_t)func, 0, &all_insn);

    // printf("%s [%p] size: %lx, count: %lx\n",
    // 	get_sym_name(e, sym_i), func, size, count);

    reg_state arg_regs[] = {REG_UNDEF, REG_UNDEF, REG_UNDEF, REG_UNDEF};
    for (size_t i = 0; i < count; i++) {
        cs_insn* insn = &all_insn[i];
        cs_regs regs_read, regs_written;
        uint8_t read_count, write_count;

        if (cs_regs_access(
                handle,
                insn,
                regs_read,
                &read_count,
                regs_written,
                &write_count
            )) {
            return -1;
        }
        // printf("\t%s %s [r: %u, w: %u]\n", insn->mnemonic, insn->op_str, read_count, write_count);
        // if (read_count > 0) printf("\t\tread:\n");
        // for (n = 0; n < read_count; n++) {
        // 	printf("\t\t\t%d\n", get_reg_arg_index(regs_read[n]));
        // }
        for (size_t n = 0; n < read_count; n++) {
            int reg_i = get_reg_arg_index(regs_read[n]);
            if (reg_i == -1) {
                continue;
            }
            if (arg_regs[reg_i] != REG_WRITTEN) {
                arg_regs[reg_i] = REG_READ;
            }
        }
        for (size_t n = 0; n < write_count; n++) {
            int reg_i = get_reg_arg_index(regs_written[n]);
            if (reg_i == -1) {
                continue;
            }
            if (arg_regs[reg_i] != REG_READ) {
                arg_regs[reg_i] = REG_WRITTEN;
            }
        }
    }

    return n_args_from_regs(arg_regs, 4);
}

int basic_func_fmt(struct elf* e, int sym_i, char* buf, int n) {
    strncat(buf, get_sym_name(e, sym_i), n);
    strncat(buf, "(", n);

    int n_args = n_func_args(e, sym_i);

    int i = 0;
    for (; i < n_args - 1; i++) {
        strncat(buf, "0x%lx, ", n);
    }
    if (n_args > 0) {
        strncat(buf, "0x%lx", n);
    }
    strncat(buf, ")", n);

    return 0;
}

uint64_t get_n_arg(struct user_regs_struct* regs, int n) {
    switch (n) {
        case 0:
            return regs->rdi;
        case 1:
            return regs->rsi;
        case 2:
            return regs->rdx;
        case 3:
            return regs->rcx;
        default:
            return (uint64_t)-1;
    }
}

#define MAX_READ 20

char* get_arg_fmt(uint64_t arg, pid_t pid) {
    errno = 0;
    ptrace(PTRACE_PEEKDATA, pid, arg, NULL);
    if (errno != 0) {
        return "%lu";
    }

    // read_data(pid, (void *) arg, buf, sizeof(buf));

    // if (buf[0] == '4') {
    // 	puts((char *) buf);
    // 	return "\"%s\"";
    // }

    return "*%p";
}

int fancy_func_fmt(struct elf* e, int sym_i, char* buf, int n, pid_t pid) {
    strncat(buf, get_sym_name(e, sym_i), n);
    strncat(buf, "(", n);

    struct user_regs_struct regs;
    ptrace(PTRACE_GETREGS, pid, NULL, &regs);

    int n_args = n_func_args(e, sym_i);

    int i = 0;
    for (; i < n_args - 1; i++) {
        strncat(buf, get_arg_fmt(get_n_arg(&regs, i), pid), n);
        strncat(buf, ", ", n);
    }
    if (n_args > 0) {
        strncat(buf, get_arg_fmt(get_n_arg(&regs, i), pid), n);
    }
    strncat(buf, ")", n);

    return 0;
}
