#undef NDEBUG

#include <mach/mach.h>
#include <mach/mach_vm.h>
#include <dlfcn.h>
#include <stdio.h>
#include <unistd.h>
#include <pthread_spis.h>
#include <dispatch/dispatch.h>
#include <assert.h>
#include <sys/proc_info.h>
#include <libproc.h>
#include <mach-o/dyld_images.h>
#include <objc/runtime.h>
#include <sys/sysctl.h>
#include <errno.h>


#ifdef __x86_64__
#define ptrauth_sign_unauthenticated(ptr, key, data) ((void *)(ptr))
#define ptrauth_strip(ptr, key) ((void *)(ptr))
#elif __arm64__

#include <ptrauth.h>

#endif


struct proc_archinfo {
    cpu_type_t p_cputype;
    cpu_subtype_t p_cpusubtype;
};

void proc_arch_info(struct proc_archinfo *arch_info, pid_t pid);

void mach_entry(struct dyld_all_image_infos *image_infos, char *dylib_path, char *stoken);

int64_t sandbox_extension_consume(const char *extension_token);

char *sandbox_extension_issue_file_to_process(const char *extension_class, const char *path, uint32_t flags, audit_token_t);

pid_t get_pid_for_process_name(const char *procname);

void write_data_to_task(task_t task, uint64_t *address, void *data, size_t data_size);

void write_code_to_task(task_t task, uint64_t *address, void *code, size_t code_size);

bool proc_is_translated(pid_t pid);

bool is_translated();

extern const char *APP_SANDBOX_READ;
extern const uint32_t SANDBOX_EXTENSION_DEFAULT;

int main(int argc, char **argv) {
    char *dylib_path = argv[1];
    char *name = argv[2];

    kern_return_t kr;
    mach_port_t self_task = mach_task_self();
    mach_port_t target_task;
    pid_t pid = get_pid_for_process_name(name);
    assert(pid != -1);

    bool own_is_translated = is_translated();
    bool target_is_translated = proc_is_translated(pid);

    struct proc_archinfo own_arch_info;
    proc_arch_info(&own_arch_info, getpid());
    struct proc_archinfo target_arch_info;
    proc_arch_info(&target_arch_info, pid);

#ifdef __x86_64__
    if (target_arch_info.p_cputype != CPU_TYPE_X86_64) {
        exit(0);
    }
#elif __arm64__
    if (target_is_translated || ((own_arch_info.p_cpusubtype & ~CPU_SUBTYPE_MASK) == CPU_SUBTYPE_ARM64_ALL &&
                                 (target_arch_info.p_cpusubtype & ~CPU_SUBTYPE_MASK) != CPU_SUBTYPE_ARM64_ALL)) {
        exit(0);
    }
#endif


    kr = task_for_pid(self_task, pid, &target_task);
    assert(kr == KERN_SUCCESS);

    Dl_info info;
    assert(dladdr(&mach_entry, &info) != 0 && info.dli_fbase != NULL);
    uint64_t base_addr = (uint64_t) info.dli_fbase;

    uint64_t region_addr = base_addr;
    mach_vm_size_t region_size;
    vm_region_basic_info_data_64_t vinfo;
    mach_msg_type_number_t vinfo_count = VM_REGION_BASIC_INFO_COUNT_64;
    mach_port_t object_name = MACH_PORT_NULL;
    kr = mach_vm_region(self_task, &region_addr, &region_size, VM_REGION_BASIC_INFO_64,
                        (vm_region_info_t) &vinfo, &vinfo_count, &object_name);
    assert(kr == KERN_SUCCESS);

    uint64_t code_addr;
    write_code_to_task(target_task, &code_addr, (void *) region_addr, region_size);

    uint64_t mach_entry_offset = (uint64_t) ptrauth_strip(&mach_entry, 0) - base_addr;
    uint64_t new_mach_entry = code_addr + mach_entry_offset;

    printf("code_addr --> 0x%llx\n", code_addr);
    printf("mach_entry_offset --> 0x%llx\n", mach_entry_offset);
    printf("new_mach_entry --> 0x%llx\n", new_mach_entry);

    audit_token_t audit_token;
    mach_msg_type_number_t info_count = TASK_AUDIT_TOKEN_COUNT;
    kr = task_info(target_task, TASK_AUDIT_TOKEN, (task_info_t) &audit_token, &info_count);
    assert(kr == KERN_SUCCESS);
    char *stoken = sandbox_extension_issue_file_to_process(APP_SANDBOX_READ, dylib_path, SANDBOX_EXTENSION_DEFAULT, audit_token);

    uint64_t stoken_addr;
    write_data_to_task(target_task, &stoken_addr, stoken, strlen(stoken) + 1);

    uint64_t dylib_path_addr;
    write_data_to_task(target_task, &dylib_path_addr, dylib_path, strlen(dylib_path) + 1);

    task_dyld_info_data_t dyld_info;
    mach_msg_type_number_t dyld_info_count = TASK_DYLD_INFO_COUNT;
    kr = task_info(target_task, TASK_DYLD_INFO, (task_info_t) &dyld_info, &dyld_info_count);
    assert(kr == KERN_SUCCESS);

    uint64_t stack_addr;
    mach_vm_size_t stack_size = vm_page_size;
    kr = mach_vm_allocate(target_task, &stack_addr, stack_size, VM_FLAGS_ANYWHERE);
    assert(kr == KERN_SUCCESS);
    uint64_t stack_top = stack_addr + stack_size;

    thread_t mach_thread;

#ifdef __x86_64__
    x86_thread_state64_t state = {};
    state.__rip = new_mach_entry;
    state.__rsp = stack_top;

    state.__rdi = (uint64_t) dyld_info.all_image_info_addr;
    state.__rsi = (uint64_t) dylib_path_addr;
    state.__rdx = (uint64_t) stoken_addr;
    if (own_is_translated) {
        void *oah_handle = dlopen("/usr/lib/liboah.dylib", RTLD_NOW);
        kern_return_t (*oah_thread_create_running)(
                task_t parent_task,
                thread_state_flavor_t flavor,
                thread_state_t new_state,
                mach_msg_type_number_t new_stateCnt,
                thread_act_t *child_act
        );
        oah_thread_create_running = (kern_return_t (*)(task_t, thread_state_flavor_t, thread_state_t, mach_msg_type_number_t,
                                                       thread_act_t *))
                dlsym(oah_handle, "oah_thread_create_running");

        printf("oah_thread_create_running --> %p\n", oah_thread_create_running);
        kr = oah_thread_create_running(target_task, x86_THREAD_STATE64, (thread_state_t) &state,
                                       x86_THREAD_STATE64_COUNT, &mach_thread);
        dlclose(oah_handle);
    } else {
        kr = thread_create_running(target_task, x86_THREAD_STATE64, (thread_state_t) &state,
                                   x86_THREAD_STATE64_COUNT, &mach_thread);
    }
    printf("thread_create_running --> %s\n", mach_error_string(kr));
    assert(kr == KERN_SUCCESS);
#elif __arm64__
    arm_thread_state64_t state = {};
    arm_thread_state64_set_pc_fptr(state, ptrauth_sign_unauthenticated((void *) new_mach_entry, ptrauth_key_function_pointer, 0));
    arm_thread_state64_set_sp(state, stack_top);
    state.__x[0] = (uint64_t) dyld_info.all_image_info_addr;
    state.__x[1] = (uint64_t) dylib_path_addr;
    state.__x[2] = (uint64_t) stoken_addr;

    thread_array_t act_list;
    mach_msg_type_number_t act_listCnt;
    kr = task_threads(target_task, &act_list, &act_listCnt);
    assert(kr == KERN_SUCCESS);

    mach_msg_type_number_t out_cnt = ARM_THREAD_STATE64_COUNT;
    kr = thread_convert_thread_state(*act_list, THREAD_CONVERT_THREAD_STATE_FROM_SELF, ARM_THREAD_STATE64, (thread_state_t) &state,
                                     ARM_THREAD_STATE64_COUNT, (thread_state_t) &state, &out_cnt);
    assert(kr == KERN_SUCCESS);

    kr = thread_create_running(target_task, ARM_THREAD_STATE64, (thread_state_t) &state, ARM_THREAD_STATE64_COUNT, &mach_thread);
    printf("thread_create_running --> %s\n", mach_error_string(kr));
    assert(kr == KERN_SUCCESS);
#endif

    dispatch_queue_t global_queue = dispatch_get_global_queue(DISPATCH_QUEUE_PRIORITY_DEFAULT, 0);
    dispatch_source_t thread_source = dispatch_source_create(
            DISPATCH_SOURCE_TYPE_MACH_SEND,
            mach_thread,
            DISPATCH_MACH_SEND_DEAD,
            global_queue
    );
    dispatch_semaphore_t semaphore = dispatch_semaphore_create(0);
    dispatch_source_set_event_handler(thread_source, ^{
        printf("mach_thread stopped\n");
        dispatch_source_cancel(thread_source);

    });
    dispatch_source_set_cancel_handler(thread_source, ^{
        dispatch_release(thread_source);
        dispatch_semaphore_signal(semaphore);
    });

    dispatch_resume(thread_source);
    dispatch_semaphore_wait(semaphore, DISPATCH_TIME_FOREVER);
    return 0;
}

pid_t get_pid_for_process_name(const char *procname) {
    int process_count = proc_listpids(PROC_ALL_PIDS, 0, NULL, 0) / (int) sizeof(pid_t);
    if (process_count < 1) {
        return -1;
    }

    int all_pids_size = (int) sizeof(pid_t) * (process_count + 3);
    pid_t *all_pids = (pid_t *) malloc(all_pids_size);

    process_count = proc_listpids(PROC_ALL_PIDS, 0, all_pids, all_pids_size) / (int) sizeof(pid_t);

    pid_t highest_pid = 0;
    int match_count = 0;
    for (int i = 1; i < process_count; i++) {
        char name[NAME_MAX];
        int len = proc_name(all_pids[i], name, sizeof(name));
        if (len == 0) { continue; }
        if (strcmp(procname, name) == 0) {
            match_count++;
            if (all_pids[i] > highest_pid) { highest_pid = all_pids[i]; }
        }
    }
    free(all_pids);
    if (match_count == 0) {
        return -1;
    }
    if (match_count > 1) {
        return -1;
    }
    return highest_pid;
}


void write_data_to_task(task_t task, uint64_t *address, void *data, size_t data_size) {
    kern_return_t kr;
    kr = mach_vm_allocate(task, address, data_size, VM_FLAGS_ANYWHERE);
    assert(kr == KERN_SUCCESS);
    kr = mach_vm_write(task, *address, (vm_offset_t) data, data_size);
    assert(kr == KERN_SUCCESS);
}

void write_code_to_task(task_t task, uint64_t *address, void *code, size_t code_size) {
    write_data_to_task(task, address, code, code_size);
    kern_return_t kr;
    kr = mach_vm_protect(task, *address, code_size, FALSE, VM_PROT_READ | VM_PROT_EXECUTE);
    assert(kr == KERN_SUCCESS);
}

bool proc_is_translated(pid_t pid) {
    int mib[] = {CTL_KERN, KERN_PROC, KERN_PROC_PID, pid};
    struct kinfo_proc info;
    size_t size = sizeof(info);
    if (sysctl(mib, (unsigned) (sizeof(mib) / sizeof(int)),
               &info, &size, NULL, 0) == 0 && size >= sizeof(info)) {
        return info.kp_proc.p_flag & P_TRANSLATED;
    }
    return false;
}


bool is_translated() {
    int ret = 0;
    size_t size = sizeof(ret);
    if (sysctlbyname("sysctl.proc_translated", &ret, &size, NULL, 0) == -1) {
        if (errno == ENOENT)
            return 0;
        return -1;
    }
    return ret;
}


void proc_arch_info(struct proc_archinfo *arch_info, pid_t pid) {
#define PROC_PIDARCHINFO 19
    proc_pidinfo(pid, PROC_PIDARCHINFO, 0, arch_info, sizeof(struct proc_archinfo));
}