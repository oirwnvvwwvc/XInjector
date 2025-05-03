#include <pthread.h>
#include <mach/port.h>
#include <mach/mach_types.h>
#include <mach-o/dyld_images.h>
#include <mach-o/loader.h>
#include <mach-o/nlist.h>
#include <dlfcn.h>

#define LIB_KERNEL "/usr/lib/system/libsystem_kernel.dylib"
#define LIB_PTHREAD "/usr/lib/system/libsystem_pthread.dylib"
#define LIB_DYLD "/usr/lib/system/libdyld.dylib"
#ifdef __x86_64__
#define ptrauth_sign_unauthenticated(ptr, key, data) ((void *)(ptr))
#define ptrauth_strip(ptr, key) ((void *)(ptr))
#elif __arm64__

#include <ptrauth.h>

#endif

typedef struct {
    char *stoken;
    char *dylib_path;
    mach_port_name_t msg_port;
    thread_t mach_thread;
    struct dyld_all_image_infos *image_infos;
} pthread_args;

int str_cmp(const char *s1, const char *s2);

void *get_symbol(struct dyld_all_image_infos *image_infos, const char *target_path, const char *symbol);

void *get_symbol_f(struct dyld_all_image_infos *image_infos, const char *target_path, const char *symbol);

void mach_entry(struct dyld_all_image_infos *image_infos, char *dylib_path, char *stoken);

void *pthread_entry(pthread_args *pargs);

typedef void *(*dlsym_t)(void *handle, const char *symbol);

typedef kern_return_t (*mach_port_allocate_t)(ipc_space_t task, mach_port_right_t right, mach_port_name_t *name);

typedef int (*pthread_create_from_mach_thread_t)(pthread_t *, const pthread_attr_t *, void *(* )(void *), void *);

typedef ssize_t (*write_t)(int fd, const void *buf, size_t nbyte);

typedef int (*printf_t)(const char *, ...);

typedef mach_msg_return_t (*mach_msg_t)(mach_msg_header_t *msg, mach_msg_option_t option, mach_msg_size_t send_size,
                                        mach_msg_size_t rcv_size, mach_port_name_t rcv_name, mach_msg_timeout_t timeout,
                                        mach_port_name_t notify);

typedef pthread_t (*pthread_self_t)();

typedef uint32_t (*sleep_t)(uint32_t);

typedef int (*pthread_detach_t)(pthread_t);

typedef kern_return_t (*mach_port_mod_refs_t)(ipc_space_t task, mach_port_name_t name, mach_port_right_t right, mach_port_delta_t delta);

typedef kern_return_t (*thread_terminate_t)(thread_act_t target_act);

typedef mach_port_t (*mach_thread_self_t)();

typedef int64_t (*sandbox_extension_consume_t)(const char *extension_token);

typedef char *(*sandbox_extension_issue_file_to_process_t)(const char *extension_class, const char *path, uint32_t flags, audit_token_t);

typedef char *(*sandbox_extension_issue_file_t)(const char *extension_class, const char *path, uint32_t flags);

typedef char *(*sandbox_extension_issue_file_to_self_t)(const char *extension_class, const char *path, uint32_t flags);

typedef kern_return_t (*task_info_t1)(task_name_t target_task, task_flavor_t flavor, task_info_t task_info_out,
                                      mach_msg_type_number_t *task_info_outCnt);

typedef char *(*mach_error_string_t)(mach_error_t error_value);

typedef void *(*dlopen_t)(const char *path, int mode);


void mach_entry(struct dyld_all_image_infos *image_infos, char *dylib_path, char *stoken) {
    write_t write_func = get_symbol_f(image_infos, LIB_KERNEL, "_write");
    mach_port_allocate_t mach_port_allocate_func = (mach_port_allocate_t)
            get_symbol_f(image_infos, LIB_KERNEL, "_mach_port_allocate");
    mach_port_t task = *(mach_port_t *) get_symbol(image_infos, LIB_KERNEL, "_mach_task_self_");
    pthread_create_from_mach_thread_t pthread_create_func = (pthread_create_from_mach_thread_t)
            get_symbol_f(image_infos, LIB_PTHREAD, "_pthread_create_from_mach_thread");
    mach_msg_t mach_msg_func = (mach_msg_t) get_symbol_f(image_infos, LIB_KERNEL, "_mach_msg");
    mach_thread_self_t mach_thread_self_func = (mach_thread_self_t)
            get_symbol_f(image_infos, LIB_KERNEL, "_mach_thread_self");

    write_func(1, "mach start\n", 11);

    mach_port_name_t msg_port;
    mach_port_allocate_func(task, MACH_PORT_RIGHT_RECEIVE, &msg_port);

    pthread_t pthread;
    pthread_args pargs;
    pargs.dylib_path = dylib_path;
    pargs.stoken = stoken;
    pargs.msg_port = msg_port;
    pargs.image_infos = image_infos;
    pargs.mach_thread = mach_thread_self_func();

    pthread_create_func(&pthread, NULL, (void *(*)(void *)) pthread_entry, &pargs);

    struct {
        mach_msg_header_t header;
    } message;

    while (1) {
        mach_msg_func(&message.header, MACH_PORT_RIGHT_SEND_ONCE, 0, sizeof(message), msg_port, MACH_MSG_TIMEOUT_NONE, MACH_PORT_NULL);
    }
}

void *pthread_entry(pthread_args *pargs) {
    struct dyld_all_image_infos *image_infos = pargs->image_infos;

    dlsym_t dlsym_func = (dlsym_t) get_symbol_f(image_infos, LIB_DYLD, "_dlsym");
    printf_t printf_func = (printf_t) dlsym_func(RTLD_DEFAULT, "printf");
    dlopen_t dlopen_func = (dlopen_t) dlsym_func(RTLD_DEFAULT, "dlopen");
    sleep_t sleep_func = (sleep_t) dlsym_func(RTLD_DEFAULT, "sleep");
    pthread_detach_t pthread_detach_func = (pthread_detach_t) dlsym_func(RTLD_DEFAULT, "pthread_detach");
    pthread_self_t pthread_self_func = (pthread_self_t) dlsym_func(RTLD_DEFAULT, "pthread_self");
    thread_terminate_t thread_terminate_func = (thread_terminate_t) dlsym_func(RTLD_DEFAULT, "thread_terminate");
    mach_port_t task = *(mach_port_t *) (dlsym_func(RTLD_DEFAULT, "mach_task_self_"));
    mach_port_mod_refs_t mach_port_mod_refs_func = (mach_port_mod_refs_t) dlsym_func(RTLD_DEFAULT, "mach_port_mod_refs");
    mach_error_string_t mach_error_string_func = (mach_error_string_t) dlsym_func(RTLD_DEFAULT, "mach_error_string");
    task_info_t1 task_info_func = (task_info_t1) dlsym_func(RTLD_DEFAULT, "task_info");
    sandbox_extension_consume_t sandbox_extension_consume_func = (sandbox_extension_consume_t)
            dlsym_func(RTLD_DEFAULT, "sandbox_extension_consume");


    sandbox_extension_consume_func(pargs->stoken);
    printf_func("dylib path --> %s\n", pargs->dylib_path);
    dlopen_func(pargs->dylib_path, RTLD_NOW);

    printf_func("sleep test\n");
    sleep_func(3);

    printf_func("call pthread_detach\n");
    pthread_detach_func(pthread_self_func());
    printf_func("call thread_terminate\n");
    thread_terminate_func(pargs->mach_thread);

    mach_port_mod_refs_func(task, pargs->msg_port, MACH_PORT_RIGHT_RECEIVE, -1);
    return 0;
}

void *get_symbol(struct dyld_all_image_infos *image_infos, const char *target_path, const char *symbol) {
    const struct mach_header_64 *header = NULL;
    for (int i = 0; i < image_infos->infoArrayCount; i++) {
        const char *image_path = image_infos->infoArray[i].imageFilePath;
        if (str_cmp(image_path, target_path) == 0) {
            header = (const struct mach_header_64 *) image_infos->infoArray[i].imageLoadAddress;
            break;
        }
    }
    if (header == NULL) {
        return NULL;
    }
    struct segment_command_64 *textseg = NULL;
    struct segment_command_64 *linkedit = NULL;
    struct symtab_command *symtab = NULL;

    uint64_t cmd_addr = (uint64_t) header + sizeof(struct mach_header_64);
    for (int j = 0; j < header->ncmds; j++) {
        const struct load_command *lc = (const struct load_command *) cmd_addr;
        if (lc->cmd == LC_SEGMENT_64) {
            struct segment_command_64 *seg = (struct segment_command_64 *) lc;
            if (str_cmp(seg->segname, SEG_TEXT) == 0) {
                textseg = seg;
            } else if (str_cmp(seg->segname, SEG_LINKEDIT) == 0) {
                linkedit = seg;
            }
        } else if (lc->cmd == LC_SYMTAB) {
            symtab = (struct symtab_command *) lc;
        }
        if (textseg && linkedit && symtab) {
            break;
        }
        cmd_addr += lc->cmdsize;
    }
    if (!textseg || !linkedit || !symtab) {
        return NULL;
    }
    uint64_t slide = (uint64_t) header - textseg->vmaddr;
    uint64_t linkedit_base = linkedit->vmaddr + slide - linkedit->fileoff;
    struct nlist_64 *symbols = (struct nlist_64 *) (linkedit_base + symtab->symoff);
    char *strtab = (char *) (linkedit_base + symtab->stroff);

    for (int k = 0; k < symtab->nsyms; k++) {
        struct nlist_64 *sym = &symbols[k];
        if (sym->n_un.n_strx != 0 && (sym->n_type & N_TYPE) == N_SECT) {
            char *name = strtab + sym->n_un.n_strx;
            if (str_cmp(name, symbol) == 0) {
                return (void *) sym->n_value + slide;
            }
        }
    }
    return NULL;
}

void *get_symbol_f(struct dyld_all_image_infos *image_infos, const char *target_path, const char *symbol) {
    void *ret = get_symbol(image_infos, target_path, symbol);
    return ptrauth_sign_unauthenticated(ret, ptrauth_key_function_pointer, 0);
}

int str_cmp(const char *s1, const char *s2) {
    while (*s1 == *s2++) {
        if (*s1++ == 0)
            return (0);
    }
    return (*(const unsigned char *) s1 - *(const unsigned char *) (s2 - 1));
}