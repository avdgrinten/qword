#include <stdint.h>
#include <stddef.h>
#include <klib.h>
#include <smp.h>
#include <task.h>
#include <lock.h>
#include <fs.h>
#include <task.h>
#include <mm.h>

/* Prototype syscall: int syscall_name(struct ctx_t *ctx) */

/* Conventional argument passing: rdi, rsi, rdx, r10, r8, r9 */

int syscall_set_fs_base(struct ctx_t *ctx) {
    // rdi: new fs base

    pid_t current_task = cpu_locals[current_cpu].current_task;

    struct thread_t *thread = task_table[current_task];

    thread->fs_base = ctx->rdi;
    load_fs_base(ctx->rdi);

    return 0;
}

void *syscall_alloc_at(struct ctx_t *ctx) {
    // rdi: virtual address / 0 for sbrk-like allocation
    // rsi: page count

    pid_t current_process = cpu_locals[current_cpu].current_process;

    struct process_t *process = process_table[current_process];

    size_t base_address;
    if (ctx->rdi) {
        base_address = ctx->rdi;
    } else {
        base_address = process->cur_brk;
        process->cur_brk += ctx->rsi * PAGE_SIZE;
    }

    for (size_t i = 0; i < ctx->rsi; i++) {
        void *ptr = pmm_alloc(1);
        if (!ptr)
            return (void *)0;
//        kprint(KPRN_INFO, "Mapping %X to %X", ptr, base_address + i * PAGE_SIZE);
        if (map_page(process->pagemap, (size_t)ptr, base_address + i * PAGE_SIZE, 0x07))
            return (void *)0;
    }

    return (void *)base_address;
}

#define AT_ENTRY 10
#define AT_PHDR 20
#define AT_PHENT 21
#define AT_PHNUM 22

int syscall_getauxval(struct ctx_t *ctx) {
    pid_t proc = cpu_locals[current_cpu].current_process;

    switch (ctx->rdi) {
        case AT_ENTRY:
            return process_table[proc]->auxval.at_entry;
        case AT_PHDR:
            return process_table[proc]->auxval.at_phdr;
        case AT_PHENT:
            return process_table[proc]->auxval.at_phent;
        case AT_PHNUM:
            return process_table[proc]->auxval.at_phnum;
        default:
            return -1;
    }
}

int syscall_debug_print(struct ctx_t *ctx) {
    // rdi: print type
    // rsi: string

    // Make sure the type isn't invalid
    if (ctx->rdi > KPRN_MAX_TYPE)
        return -1;

    // Make sure we're not trying to print memory that doesn't belong to us
    //TODO:privilege_check_string((const char *)ctx->rsi);

    kprint(ctx->rdi, "[%u:%u:%u] %s",
           cpu_locals[current_cpu].current_process,
           cpu_locals[current_cpu].current_thread,
           current_cpu,
           ctx->rsi);

    return 0;
}

int syscall_open(struct ctx_t *ctx) {
    // rdi: path
    // rsi: mode
    // rdx: perms

    // TODO lock this stuff properly

    pid_t current_process = cpu_locals[current_cpu].current_process;

    struct process_t *process = process_table[current_process];

    int local_fd;

    for (local_fd = 0; process->file_handles[local_fd] != -1; local_fd++)
        if (local_fd + 1 == MAX_FILE_HANDLES)
            return -1;

    //TODO:privilege_check_string((const char *)ctx->rdi);

    int fd = open((const char *)ctx->rdi, ctx->rsi, ctx->rdx);
    if (fd == -1)
        return -1;

    process->file_handles[local_fd] = fd;

    return local_fd;
}

int syscall_close(struct ctx_t *ctx) {
    // rdi: fd

    // TODO lock this stuff properly

    pid_t current_process = cpu_locals[current_cpu].current_process;

    struct process_t *process = process_table[current_process];

    if (close(process->file_handles[ctx->rdi]) == -1)
        return -1;

    process->file_handles[ctx->rdi] = -1;

    return 0;
}

int syscall_read(struct ctx_t *ctx) {
    // rdi: fd
    // rsi: buf
    // rdx: len

    //TODO:privilege_check_buf((const void *)ctx->rsi, ctx->rdx);

    // TODO lock this stuff properly

    pid_t current_process = cpu_locals[current_cpu].current_process;

    struct process_t *process = process_table[current_process];

    if (process->file_handles[ctx->rdi] == -1)
        return -1;

    return read(process->file_handles[ctx->rdi], (void *)ctx->rsi, ctx->rdx);
}

int syscall_write(struct ctx_t *ctx) {
    // rdi: fd
    // rsi: buf
    // rdx: len

    //TODO:privilege_check_buf((const void *)ctx->rsi, ctx->rdx);

    // TODO lock this stuff properly

    pid_t current_process = cpu_locals[current_cpu].current_process;

    struct process_t *process = process_table[current_process];

    if (process->file_handles[ctx->rdi] == -1)
        return -1;

    return write(process->file_handles[ctx->rdi], (const void *)ctx->rsi, ctx->rdx);
}
