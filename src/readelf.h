#pragma once

#include <elf.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

struct elf {
    uint8_t* file;
    Elf64_Ehdr ehdr;
    Elf64_Phdr* phdrs;
    int n_phdrs;
    Elf64_Shdr* shdrs;
    int n_shdrs;
    char* shdr_names;
    Elf64_Sym* syms;
    int n_syms;
    char* sym_names;
};

char* get_shdr_name(struct elf* e, int i) {
    return &e->shdr_names[e->shdrs[i].sh_name];
}

void* get_sym_addr(struct elf* e, int i) {
    return (void*)e->syms[i].st_value;
}

char* get_sym_name(struct elf* e, int i) {
    return &e->sym_names[e->syms[i].st_name];
}

size_t get_sym_size(struct elf* e, int i) {
    return e->syms[i].st_size;
}

int get_sym_index(struct elf* e, char* name) {
    for (int i = 0; i < e->n_syms; i++) {
        if (!strcmp(name, get_sym_name(e, i))) {
            return i;
        }
    }

    return -1;
}

int at_symbol(struct elf* e, void* addr) {
    for (int i = 0; i < e->n_syms; i++) {
        if (get_sym_addr(e, i) == addr) {
            return i;
        }
    }

    return -1;
}

Elf64_Shdr* get_shdr(struct elf* e, char* name) {
    for (int i = 0; i < e->n_shdrs; i++) {
        if (!strcmp(name, get_shdr_name(e, i))) {
            return &e->shdrs[i];
        }
    }

    return NULL;
}

bool addr_in_section(struct elf* e, void* addr, char* name) {
    Elf64_Shdr* shdr = get_shdr(e, name);
    uint64_t sec_start = shdr->sh_addr;
    uint64_t sec_end = sec_start + shdr->sh_size;

    return (uint64_t)addr >= sec_start && (uint64_t)addr < sec_end;
}

bool sym_in_section(struct elf* e, int i, char* name) {
    return addr_in_section(e, get_sym_addr(e, i), name);
}

uint8_t* bytes_from_addr_in_section(struct elf* e, void* addr, char* name) {
    Elf64_Shdr* shdr = get_shdr(e, name);

    return &e->file[(uint64_t)addr - (uint64_t)shdr->sh_addr + shdr->sh_offset];
}

struct elf* readelf(int fd) {
    struct stat st;
    struct elf* e = malloc(sizeof(*e));

    fstat(fd, &st);
    size_t file_size = st.st_size;
    e->file = malloc(file_size);

    size_t total = 0;
    while (total < file_size) {
        ssize_t nread = read(fd, e->file + total, file_size - total);
        if (nread <= 0) {
            free(e->file);
            free(e);
            return NULL;
        }
        total += nread;
    }

    e->ehdr = *(Elf64_Ehdr*)e->file;

    e->phdrs = (Elf64_Phdr*)&e->file[e->ehdr.e_phoff];
    e->n_phdrs = e->ehdr.e_phnum;

    e->shdrs = (Elf64_Shdr*)&e->file[e->ehdr.e_shoff];
    e->n_shdrs = e->ehdr.e_shnum;
    e->shdr_names = (char*)&e->file[e->shdrs[e->ehdr.e_shstrndx].sh_offset];

    Elf64_Shdr* sym_hdr = get_shdr(e, ".symtab");

    e->syms = (Elf64_Sym*)&e->file[sym_hdr->sh_offset];
    e->n_syms = sym_hdr->sh_size / sym_hdr->sh_entsize;
    e->sym_names = (char*)&e->file[e->shdrs[sym_hdr->sh_link].sh_offset];

    return e;
}
