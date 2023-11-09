#include <stdio.h>
#include <err.h>
#include <string.h>
#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/ioctl.h>
#include <sys/mman.h>
#include <unistd.h>
#include <fcntl.h>
#include <linux/types.h>
#include <linux/kvm.h>
#include <linux/kcov.h>
#include <linux/ptrace.h>
#include <sys/sysinfo.h>

#define __USE_GNU
#define _GNU_SOURCE
#include <sched.h>

// This file shows an example PKVM proxy use to boot a simple non-protected VM.
// This also contains useful functions to interact with the proxy that can be
// easily reused.

#define __KVM_HOST_SMCCC_FUNC___kvm_hyp_init			0

enum __kvm_host_smccc_func {
	/* Hypercalls available only prior to pKVM finalisation */
	/* __KVM_HOST_SMCCC_FUNC___kvm_hyp_init */
	__KVM_HOST_SMCCC_FUNC___kvm_get_mdcr_el2 =
		__KVM_HOST_SMCCC_FUNC___kvm_hyp_init + 1,
	__KVM_HOST_SMCCC_FUNC___pkvm_init,
	__KVM_HOST_SMCCC_FUNC___pkvm_create_private_mapping,
	__KVM_HOST_SMCCC_FUNC___pkvm_cpu_set_vector,
	__KVM_HOST_SMCCC_FUNC___kvm_enable_ssbs,
	__KVM_HOST_SMCCC_FUNC___vgic_v3_init_lrs,
	__KVM_HOST_SMCCC_FUNC___vgic_v3_get_gic_config,
	__KVM_HOST_SMCCC_FUNC___kvm_flush_vm_context,
	__KVM_HOST_SMCCC_FUNC___kvm_tlb_flush_vmid_ipa,
	__KVM_HOST_SMCCC_FUNC___kvm_tlb_flush_vmid, /* 10 */
	__KVM_HOST_SMCCC_FUNC___kvm_flush_cpu_context,
	__KVM_HOST_SMCCC_FUNC___pkvm_prot_finalize,

	/* Hypercalls available after pKVM finalisation */
	__KVM_HOST_SMCCC_FUNC___pkvm_host_share_hyp,
	__KVM_HOST_SMCCC_FUNC___pkvm_host_unshare_hyp,
	__KVM_HOST_SMCCC_FUNC___pkvm_host_reclaim_page,
	__KVM_HOST_SMCCC_FUNC___pkvm_host_map_guest,
	__KVM_HOST_SMCCC_FUNC___kvm_adjust_pc,
	__KVM_HOST_SMCCC_FUNC___kvm_vcpu_run,
	__KVM_HOST_SMCCC_FUNC___kvm_timer_set_cntvoff,
	__KVM_HOST_SMCCC_FUNC___vgic_v3_save_vmcr_aprs, /* 20 */
	__KVM_HOST_SMCCC_FUNC___vgic_v3_restore_vmcr_aprs,
	__KVM_HOST_SMCCC_FUNC___pkvm_init_vm,
	__KVM_HOST_SMCCC_FUNC___pkvm_init_vcpu,
	__KVM_HOST_SMCCC_FUNC___pkvm_teardown_vm,
	__KVM_HOST_SMCCC_FUNC___pkvm_vcpu_load,
	__KVM_HOST_SMCCC_FUNC___pkvm_vcpu_put,
	__KVM_HOST_SMCCC_FUNC___pkvm_vcpu_sync_state,
};

#define HPROX_HVC_TYPE 'h'
#define HPROX_STRUCTS_TYPE 's'
#define HPROX_ALLOC_TYPE 'a'
#define HPROX_MEMCACHE_TYPE 'm'


// Perform the HVC numbered hvcnum, with this number of arguments.
// The ioctl parameter is an array containing the arguments
#define HVC_PROXY_IOCTL(hvcnum, numarg) \
	_IOC(_IOC_WRITE, HPROX_HVC_TYPE, hvcnum, 8 * numarg)


// All those ioctl return a size or an offset as return value.
#define HPROX_STRUCT_KVM_GET_SIZE _IO(HPROX_STRUCTS_TYPE, 0)
// The argument must be a: enum struct_kvm_fields
#define HPROX_STRUCT_KVM_GET_OFFSET _IO(HPROX_STRUCTS_TYPE, 1)
#define HPROX_HYP_VM_GET_SIZE _IO(HPROX_STRUCTS_TYPE, 2)
#define HPROX_PGD_GET_SIZE _IO(HPROX_STRUCTS_TYPE, 3)
#define HPROX_STRUCT_KVM_VCPU_GET_SIZE _IO(HPROX_STRUCTS_TYPE, 4)
// The argument must be a: enum struct_kvm_vcpu_fields
#define HPROX_STRUCT_KVM_VCPU_GET_OFFSET _IO(HPROX_STRUCTS_TYPE, 5)
#define HPROX_HYP_VCPU_GET_SIZE _IO(HPROX_STRUCTS_TYPE, 6)

enum struct_kvm_fields {
	HPROX_NR_MEM_SLOT_PAGES, /* unsigned long */
	HPROX_VCPU_ARRAY, /* xarray */
	HPROX_MAX_VCPUS, /* int */
	HPROX_CREATED_VCPUS, /* int */
	HPROX_ARCH_PKVM_ENABLED, /* bool */
	HPROX_ARCH_PKVM_TEARDOWN_MC, /* struct hprox_memcache */
};

enum struct_kvm_vcpu_fields {
	HPROX_VCPU_ID, /* int */
	HPROX_VCPU_IDX, /* int */
	HPROX_VCPU_CFLAGS, /* 8 bits bitfield */
	HPROX_VCPU_IFLAGS, /* 8 bits bitfield */
	HPROX_VCPU_FEATURES, /* KVM_VCPU_MAX_FEATURES bits bitfield */
	HPROX_VCPU_HCR_EL2, /* u64 */
	HPROX_VCPU_FAULT, /* struct hprox_vcpu_fault_info */
	HPROX_VCPU_REGS, /* struct user_pt_regs */
	HPROX_VCPU_FP_REGS, /* struct user_fpsimd_state */
	HPROX_VCPU_MEMCACHE, /* struct hprox_memcache */
	// TODO add SVE state, for now SVE-less guests only
};

struct hprox_vcpu_fault_info {
	__u64 esr_el2; /* Hyp Syndrom Register */
	__u64 far_el2; /* Hyp Fault Address Register */
	__u64 hpfar_el2; /* Hyp IPA Fault Address Register */
	__u64 disr_el1; /* Deferred [SError] Status Register */
};

// Need to match up kvm_hyp_memcache
struct hprox_memcache {
        __u64 head; // kernel address, might not be accessible, if not
			    // donated from a hprox_alloc region.
	unsigned long nr_pages;
};
enum hprox_alloc_type { HPROX_VMALLOC, HPROX_PAGES_EXACT };

// the ioctl parameter is the size of the allocation
#define HPROX_ALLOC(alloc) _IO(HPROX_ALLOC_TYPE, alloc)
#define HPROX_ALLOC_PAGES HPROX_ALLOC(HPROX_PAGES_EXACT)

// ioctl on the mmapable fd from the HPROX_ALLOC ioctl
#define HPROX_ALLOC_KADDR _IOR('A',0, __u64)
#define HPROX_ALLOC_PHYS _IOR('A', 1, __u64)
#define HPROX_ALLOC_RELEASE _IO('A', 2)
#define HPROX_ALLOC_FREE _IO('A', 3)

// memcache ioctl, free is encoded as topup 0
#define HPROX_MEMCACHE_FREE \
	_IOWR(HPROX_MEMCACHE_TYPE, 0, struct hprox_memcache)
#define HPROX_MEMCACHE_TOPUP(n) \
	_IOWR(HPROX_MEMCACHE_TYPE, (n), struct hprox_memcache)

#define MAX_NUM_CPU 16
#define NUM_VCPU 1
#define PAGE_SHIFT 12
#define PAGE_SIZE (1 << PAGE_SHIFT)

// The hyp proxy file descriptor.
// This is just a stateless ioctl gateway so it can be global
int proxy_fd;

// Representation of a kernel memory allocation done through the hyp proxy.
struct kernel_region {
    int size;
    int fd;
    void* mmap; // Not mmap if zero
    ulong kaddr; // Kernel address
    ulong phys; // physical address
};

// Allocates a kernel region of size given by ret->size.
// Stores the region in ret.
void alloc_kernel_region(struct kernel_region* ret)
{
    ret->mmap = NULL;
    ret->fd = ioctl(proxy_fd, HPROX_ALLOC_PAGES, ret->size);
    if (ret->fd < 0)
        err(1, "Can't allocate kernel_region");

    if(ioctl(ret->fd, HPROX_ALLOC_KADDR, &ret->kaddr))
        err(1, "Can't get kernel region address");
    printf("Allocated region at %lx of size 0x%x bytes\n",
           ret->kaddr, ret->size);

    if (ioctl(ret->fd, HPROX_ALLOC_PHYS, &ret->phys))
        err(1, "Can't get kernel region physical address");
    printf("Phys is %lx\n", ret->phys);
}

// Map a kernel region in this program address space. Fills reg->mmap.
// WARNING: If the memory was also given to the hypervisor, (before or after the
// mmap), then any access will lead to a kernel fault which may trigger a panic
// or just segfault the current program.
void kernel_region_mmap(struct kernel_region* reg)
{
    printf("Trying to mmap kernel address %lx fd %d\n", reg->kaddr, reg->fd);
    reg->mmap = mmap(NULL, reg->size, PROT_READ | PROT_WRITE,
                    MAP_SHARED, reg->fd, 0);
    if ((void*)reg->mmap == MAP_FAILED)
        err(1, "Can't mmap kernel region");
}

// Release this kernel region. This means that won't be automatically freed
// when the corresponding file descriptor (reg->fd) is closed.
// WARNING: This need to be done before donating or sharing any memory with
// the hypervisor (or a KVM guest), otherwise the kernel may become unstable.
void kernel_region_release(struct kernel_region *reg) {
    printf("Trying to release kernel address %lx fd %d\n", reg->kaddr, reg->fd);
    if (ioctl(reg->fd, HPROX_ALLOC_RELEASE))
        err(1, "Can't release kernel region");
}

// Release this kernel region. This means that won't be automatically freed
// when the corresponding file descriptor (reg->fd) is closed.
//
// WARNING: Only free memory fully owned by the kernel. Freeing memory shared or
// donated away will lead to kernel instability
void kernel_region_free(struct kernel_region *reg) {
    printf("Trying to free kernel address %lx fd %d\n", reg->kaddr, reg->fd);
    if (ioctl(reg->fd, HPROX_ALLOC_FREE))
        err(1, "Can't free kernel region");
}

// Share this region with the hypervisor
void kernel_region_share_hyp(struct kernel_region *reg) {
    ulong nr_pages = (reg->size + PAGE_SIZE - 1) / PAGE_SIZE;
    ulong pfn = reg->phys >> PAGE_SHIFT;
    int ret;
    for (int i = 0; i < nr_pages; ++i) {
        unsigned long args[1] = {pfn + i};
        ret = ioctl(
            proxy_fd,
            HVC_PROXY_IOCTL(__KVM_HOST_SMCCC_FUNC___pkvm_host_share_hyp, 1),
            args);
        if (ret < 0)
          err(1, "pkvm_proxy host_share_hyp failed");
    }
}

// Unshare memory previously shared with the hypervisor
void kernel_region_unshare_hyp(struct kernel_region *reg) {
    ulong nr_pages = (reg->size + PAGE_SIZE - 1) / PAGE_SIZE;
    ulong pfn = reg->phys >> PAGE_SHIFT;
    int ret;
    for (int i = 0; i < nr_pages; ++i) {
        unsigned long args[1] = {pfn + i};
        ret = ioctl(
            proxy_fd,
            HVC_PROXY_IOCTL(__KVM_HOST_SMCCC_FUNC___pkvm_host_unshare_hyp, 1),
            args);
        if (ret < 0)
            err(1, "pkvm_proxy host_unshare_hyp failed");
    }
}

// Reclaim memory donated to a guest after guest teardown. Such as memory
// donated by map_region_guest (later in this file)
void kernel_region_reclaim(struct kernel_region *reg) {
    ulong nr_pages = (reg->size + PAGE_SIZE - 1) / PAGE_SIZE;
    ulong pfn = reg->phys >> PAGE_SHIFT;
    int ret;
    for (int i = 0; i < nr_pages; ++i) {
        unsigned long args[1] = {pfn + i};
        ret = ioctl(
            proxy_fd,
            HVC_PROXY_IOCTL(__KVM_HOST_SMCCC_FUNC___pkvm_host_reclaim_page, 1),
            args);
        if (ret < 0)
            err(1, "pkvm_proxy host_reclaim_page failed");
    }
}

// Get the pointer to the fault information o a vcpu
volatile struct hprox_vcpu_fault_info* get_fault_info(
    struct kernel_region* vcpu) {
    int fault_info_offset;
    fault_info_offset =
        ioctl(proxy_fd, HPROX_STRUCT_KVM_VCPU_GET_OFFSET, HPROX_VCPU_FAULT);
    if (fault_info_offset < 0)
        err(1, "Can't get fault_info offset");
    return (vcpu->mmap + fault_info_offset);
}

// Get the pointer to a vcpu register list
volatile struct user_pt_regs* get_regs(struct kernel_region* vcpu) {
    int regs_offset;
    regs_offset =
        ioctl(proxy_fd, HPROX_STRUCT_KVM_VCPU_GET_OFFSET, HPROX_VCPU_REGS);
    if (regs_offset < 0) err(1, "Can't get regs offset");
    return (vcpu->mmap + regs_offset);
}

// Get the point to the teardown memcache of a VM.
// This is filled with a set of pages given back to the kernel after VM teardown
volatile struct hprox_memcache* get_vm_teardown_mc(struct kernel_region *vm) {
    int memcache_offset;
    memcache_offset =
        ioctl(proxy_fd, HPROX_STRUCT_KVM_GET_OFFSET, HPROX_ARCH_PKVM_TEARDOWN_MC);
    if (memcache_offset < 0) err(1, "Can't get vm teardown memcache offset");
    return (vm->mmap + memcache_offset);
}

// Get the point to the vcpu memcache, this must be filled before donating
// memory to a vcpu, or before loading it
volatile struct hprox_memcache* get_vcpu_memcache(struct kernel_region* vcpu) {
    int memcache_offset;
    memcache_offset =
        ioctl(proxy_fd, HPROX_STRUCT_KVM_VCPU_GET_OFFSET, HPROX_VCPU_MEMCACHE);
    if (memcache_offset < 0) err(1, "Can't get vcpu memcache offset");
    return (vcpu->mmap + memcache_offset);
}

// Initialize a VM into the host_kvm region (Including allocating it)
// Return a handle to the VM
int init_vm(struct kernel_region* host_kvm) {

    struct kernel_region hyp_kvm, pgd, last_ran;
    int host_kvm_created_vcpus_offset;
    volatile int* host_kvm_created_vcpus;
    int vm_handle;

    host_kvm->size = ioctl(proxy_fd, HPROX_STRUCT_KVM_GET_SIZE);
    if (host_kvm->size < 0) err(1, "Can't get host_kvm size");
    printf("Got struct kvm size %x\n", host_kvm->size);
    alloc_kernel_region(host_kvm);
    kernel_region_mmap(host_kvm);
    memset(host_kvm->mmap, 0, host_kvm->size);
    kernel_region_release(host_kvm);
    kernel_region_share_hyp(host_kvm);

    host_kvm_created_vcpus_offset =
        ioctl(proxy_fd, HPROX_STRUCT_KVM_GET_OFFSET, HPROX_CREATED_VCPUS);
    if (host_kvm_created_vcpus_offset < 0)
        err(1, "Can't get host_kvm created_vcpus offset");
    host_kvm_created_vcpus =
        (int*)(host_kvm->mmap + host_kvm_created_vcpus_offset);
    *host_kvm_created_vcpus = NUM_VCPU;

    hyp_kvm.size = ioctl(proxy_fd, HPROX_HYP_VM_GET_SIZE);
    if (hyp_kvm.size < 0) err(1, "Can't get hyp_kvm size");
    hyp_kvm.size += NUM_VCPU * sizeof(void*);
    alloc_kernel_region(&hyp_kvm);
    printf("hyp_kvm kernel address %lx and size %x\n",
           hyp_kvm.kaddr, hyp_kvm.size);

    pgd.size = ioctl(proxy_fd, HPROX_PGD_GET_SIZE);
    if (pgd.size < 0) err(1, "Can't get pgd size");
    alloc_kernel_region(&pgd);
    printf("pgd kernel address %lx and size %x\n", pgd.kaddr, pgd.size);

    last_ran.size = MAX_NUM_CPU * sizeof(int);
    alloc_kernel_region(&last_ran);
    printf("last_ran kernel address %lx and size %x\n",
           last_ran.kaddr, last_ran.size);


    // About to donate to pKVM, so release
    kernel_region_release(&hyp_kvm);
    kernel_region_release(&pgd);
    kernel_region_release(&last_ran);

    unsigned long args[4] = {
        host_kvm->kaddr, hyp_kvm.kaddr, pgd.kaddr, last_ran.kaddr
    };

    vm_handle = ioctl(
        proxy_fd,
        HVC_PROXY_IOCTL(__KVM_HOST_SMCCC_FUNC___pkvm_init_vm, 4),
        args);
    if(vm_handle < 0) err(1, "pkvm_proxy init_vm failed");

    return vm_handle;
}

// Initialize a vcpu in VM `handle` at index `idx` into the host_vcpu region
// (including allocating the region)
void init_vcpu(int handle, int idx, struct kernel_region *host_vcpu)
{
    struct kernel_region hyp_vcpu;
    int host_vcpu_idx_offset;
    volatile int* host_vcpu_idx;
    int hcr_offset;
    volatile ulong* hcr;
    int ret;

    host_vcpu->size = ioctl(proxy_fd, HPROX_STRUCT_KVM_VCPU_GET_SIZE);
    if (host_vcpu->size < 0) err(1, "Can't get host_vcpu size");
    alloc_kernel_region(host_vcpu);
    kernel_region_mmap(host_vcpu);
    memset(host_vcpu->mmap, 0, host_vcpu->size);
    kernel_region_release(host_vcpu);
    kernel_region_share_hyp(host_vcpu);
    printf("host_vcpu kernel address %lx and size %x\n", host_vcpu->kaddr,
           host_vcpu->size);

    host_vcpu_idx_offset =
        ioctl(proxy_fd, HPROX_STRUCT_KVM_VCPU_GET_OFFSET, HPROX_VCPU_IDX);
    if (host_vcpu_idx_offset < 0)
        err(1, "Can't get host_vcpu idx offset");
    host_vcpu_idx = (int *)(host_vcpu->mmap + host_vcpu_idx_offset);
    *host_vcpu_idx = idx;

    hcr_offset =
        ioctl(proxy_fd, HPROX_STRUCT_KVM_VCPU_GET_OFFSET, HPROX_VCPU_HCR_EL2);
    if (hcr_offset < 0)
        err(1, "Can't get HCR_EL2 offset");
    hcr = (ulong *)(host_vcpu->mmap + hcr_offset);
    *hcr = (1ul << 31);

    hyp_vcpu.size = ioctl(proxy_fd, HPROX_HYP_VCPU_GET_SIZE);
    if (hyp_vcpu.size < 0)
        err(1, "Can't get hyp_vcpu size");
    hyp_vcpu.size += NUM_VCPU * sizeof(void *);
    alloc_kernel_region(&hyp_vcpu);
    printf("hyp_vcpu kernel address %lx and size %x\n", hyp_vcpu.kaddr,
           hyp_vcpu.size);

    kernel_region_release(&hyp_vcpu);

    unsigned long args[3] = {
        handle, host_vcpu->kaddr, hyp_vcpu.kaddr
    };

    ret = ioctl(
        proxy_fd, HVC_PROXY_IOCTL(__KVM_HOST_SMCCC_FUNC___pkvm_init_vcpu, 3), args);
    if(ret < 0) err(1, "pkvm_proxy init_vcpu failed");
}

// Mark a vcpu as dirty which will trigger a reload of the register on the next
// load. (Only for unprotected VMs ofc)
void set_vcpu_dirty(struct kernel_region* vcpu){
    int iflags_offset;
    volatile __u8* iflags;
    iflags_offset =
        ioctl(proxy_fd, HPROX_STRUCT_KVM_VCPU_GET_OFFSET, HPROX_VCPU_IFLAGS);
    if (iflags_offset < 0) err(1, "Can't get iflags offset");
    iflags = (__u8*)(vcpu->mmap + iflags_offset);
    *iflags = ((__u8)1) << 7;
}

// Loads a vcpu by VM handle and VCPU index
int load_vcpu(int handle, int idx) {
    int ret;

    unsigned long args[3] = {
        handle, idx, 0 /* HCR_EL2 */
    };

    ret = ioctl(proxy_fd, HVC_PROXY_IOCTL(__KVM_HOST_SMCCC_FUNC___pkvm_vcpu_load, 3),
                args);
    if (ret < 0) err(1, "pkvm_proxy vcpu_load failed");

    return ret;
}

// Runs a vcpu (needs the vcpu kernel address, even if redundant)
int run_vcpu(ulong vcpu_kaddr) {
    int ret;

    unsigned long args[1] = {
        vcpu_kaddr
    };

    ret = ioctl(proxy_fd, HVC_PROXY_IOCTL(__KVM_HOST_SMCCC_FUNC___kvm_vcpu_run, 1),
                args);
    if (ret < 0) err(1, "pkvm_proxy vcpu_run failed");

    return ret;
}

// Puts a vcpu
int put_vcpu() {
    int ret;

    ret = ioctl(proxy_fd, HVC_PROXY_IOCTL(__KVM_HOST_SMCCC_FUNC___pkvm_vcpu_put, 0),
                NULL);
    if (ret < 0) err(1, "pkvm_proxy vcpu_put failed");

    return ret;
}

// Empty an hypervisor memcache, giving back the memory to the kernel allocator
// This memory may have been allocated either with alloc_kernel_region or
// topup_hyp_memcache
void free_hyp_memcache(volatile struct hprox_memcache *mc) {
    int ret;
    ret = ioctl(proxy_fd, HPROX_MEMCACHE_FREE, mc);
    if (ret < 0)
        err(1, "pkvm_proxy free memcache failed");
}

// Tops up a hypervisor memcache to the specified minimum number of pages.
// Those new pages won't be accessible to usermode
void topup_hyp_memcache(volatile struct hprox_memcache *mc,
                        unsigned long min_pages) {
    int ret;
    ret = ioctl(proxy_fd, HPROX_MEMCACHE_TOPUP(min_pages), mc);
    if (ret < 0)
        err(1, "pkvm_proxy topup memcache failed");
}

// Teardown a VM by handle, need the correct kernel region representing the VM.
int teardown_vm(int handle, struct kernel_region *vm) {
    int ret;

    volatile struct hprox_memcache *teardown_mc = get_vm_teardown_mc(vm);


    unsigned long args[1] = {
        handle,
    };

    ret = ioctl(proxy_fd,
                HVC_PROXY_IOCTL(__KVM_HOST_SMCCC_FUNC___pkvm_teardown_vm, 1),
                args);
    if (ret < 0) err(1, "pkvm_proxy teardown_vm failed");

    free_hyp_memcache(teardown_mc);
    kernel_region_unshare_hyp(vm);
    kernel_region_free(vm);

    return ret;
}

// Donate memory region mem to VCPU in `vcpu` at guest address `gphys`. The VCPU
// must be loaded.
void map_region_guest(struct kernel_region* vcpu, struct kernel_region* mem, ulong gphys){
    int ret;
    for(ulong mapped_size =0; mapped_size < mem->size; mapped_size += PAGE_SIZE){
        topup_hyp_memcache(get_vcpu_memcache(vcpu), 5);
        unsigned long args[2] = {
            (mem->phys + mapped_size) >> PAGE_SHIFT,
            (gphys + mapped_size) >> PAGE_SHIFT,
        };
        ret = ioctl(
            proxy_fd, HVC_PROXY_IOCTL(__KVM_HOST_SMCCC_FUNC___pkvm_host_map_guest, 2),
            args);
        if (ret < 0) err(1, "pkvm_proxy couldn't give memory to guest");
    }
}

int main(int argc, char** argv)
{
    struct kernel_region vm;
    struct kernel_region vcpu;
    volatile struct hprox_vcpu_fault_info *fault_info;
    volatile struct user_pt_regs *regs;
    volatile struct hprox_memcache *vcpu_mc;
    int ret;
    int vm_handle;

    // We want to run on only one CPU: CPU 0 */
    cpu_set_t cpu_set;
    CPU_ZERO(&cpu_set);
    CPU_SET(0, &cpu_set);
    sched_setaffinity(0, sizeof(cpu_set_t), &cpu_set);

    const uint8_t code[] = {
        0x20, 0x00, 0x00, 0x8b, /* add x0, x1, x0 */
        0x40, 0x00, 0x00, 0xf9, /* str x0, [x2]*/
        0x00, 0x00, 0x20, 0xd4, /* brk */
    };

    // A single fd descriptor allows coverage collection on a single thread.
    proxy_fd = open("/sys/kernel/debug/pkvm_proxy", O_RDWR);
    if (proxy_fd == -1)
        err(1, "pkvm_proxy open");

    printf("Opened pkvm_proxy fd %d\n", proxy_fd);

    vm_handle = init_vm(&vm);
    printf ("Initialized VM with handle %d\n", vm_handle);

    init_vcpu(vm_handle, 0, &vcpu);
    printf("Initialized VCPU 0 \n");
    fault_info = get_fault_info(&vcpu);
    regs = get_regs(&vcpu);
    regs->pc = 0x1000;
    regs->regs[0] = 0x11;
    regs->regs[1] = 0x1100;
    regs->regs[2] = 0x123456;
    set_vcpu_dirty(&vcpu);

    vcpu_mc = get_vcpu_memcache(&vcpu);
    topup_hyp_memcache(vcpu_mc, 10);

    load_vcpu(vm_handle, 0);
    printf("Loaded VCPU 0 \n");

    struct kernel_region gcode;
    gcode.size = PAGE_SIZE;
    alloc_kernel_region(&gcode);
    kernel_region_mmap(&gcode);
    memcpy(gcode.mmap, code, 12);
    kernel_region_release(&gcode);
    map_region_guest(&vcpu, &gcode, regs->pc);

    int exit_code = run_vcpu(vcpu.kaddr);
    printf("Ran VCPU 0 with exit code %d\n", exit_code);
    printf("Fault info\n\tesr: %llx\n\tfar: %llx\n\thpfar: %llx\n\tdisr: %llx\n",
           fault_info->esr_el2,
           fault_info->far_el2,
           fault_info->hpfar_el2,
           fault_info->disr_el1);

    put_vcpu();
    printf("Unloaded VCPU 0 \n");

    teardown_vm(vm_handle, &vm);
    printf("Teared down VM \n");

    kernel_region_unshare_hyp(&vcpu);
    kernel_region_free(&vcpu);

    kernel_region_reclaim(&gcode);
    kernel_region_free(&gcode);

    return 0;
}

