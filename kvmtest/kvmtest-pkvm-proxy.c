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
	__KVM_HOST_SMCCC_FUNC___pkvm_hello_world,
};


#include <linux/types.h>

#define HPROX_HVC_TYPE 0
#define HPROX_STRUCTS_TYPE 1
#define HPROX_ALLOC_TYPE 2


#define HVC_PROXY_IOCTL(hvcnum, numarg) \
	_IOC(_IOC_WRITE, HPROX_HVC_TYPE, hvcnum, 8 * numarg)


#define HPROX_STRUCT_KVM_GET_SIZE _IO(HPROX_STRUCTS_TYPE, 0)
#define HPROX_STRUCT_KVM_GET_OFFSET _IO(HPROX_STRUCTS_TYPE, 1)
#define HPROX_HYP_VM_GET_SIZE _IO(HPROX_STRUCTS_TYPE, 2)
#define HPROX_PGD_GET_SIZE _IO(HPROX_STRUCTS_TYPE, 3)
#define HPROX_STRUCT_KVM_VCPU_GET_SIZE _IO(HPROX_STRUCTS_TYPE, 4)
#define HPROX_STRUCT_KVM_VCPU_GET_OFFSET _IO(HPROX_STRUCTS_TYPE, 5)
#define HPROX_HYP_VCPU_GET_SIZE _IO(HPROX_STRUCTS_TYPE, 6)

enum struct_kvm_fields {
	HPROX_NR_MEM_SLOT_PAGES,
	HPROX_VCPU_ARRAY,
	HPROX_MAX_VCPUS,
	HPROX_CREATED_VCPUS,
	HPROX_ARCH_PKVM_ENABLED,
	HPROX_ARCH_PKVM_TEARDOWN_MC,
};

enum struct_kvm_vcpu_fields {
	HPROX_VCPU_ID, /* int */
	HPROX_VCPU_IDX, /* int */
        HPROX_VCPU_CFLAGS, /* u8 */
	HPROX_VCPU_IFLAGS, /* u8 */
	HPROX_VCPU_FEATURES,
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

#define HPROX_ALLOC(alloc) _IO(HPROX_ALLOC_TYPE, alloc)
#define HPROX_ALLOC_PAGES HPROX_ALLOC(HPROX_PAGES_EXACT)

// ioctl on the mmapable fd from the HPROX_ALLOC ioctl
#define HPROX_ALLOC_KADDR _IOR(0,0, void*)
#define HPROX_ALLOC_PHYS _IOR(0, 1, void *)
#define HPROX_ALLOC_RELEASE _IO(0, 2)


#define MAX_NUM_CPU 16
#define NUM_VCPU 1
#define PAGE_SHIFT 12
#define PAGE_SIZE (1 << PAGE_SHIFT)

struct kernel_region {
    int size;
    int fd;
    void* mmap;
    ulong kaddr;
    ulong phys;
};

void alloc_kernel_region(int prox_fd, struct kernel_region* ret)
{
    ret->fd = ioctl(prox_fd, HPROX_ALLOC_PAGES, ret->size);
    if (ret->fd < 0)
        err(1, "Can't allocate kernel_region");

    if(ioctl(ret->fd, HPROX_ALLOC_KADDR, &ret->kaddr))
        err(1, "Can't get kernel region address");
    printf("Allocated region at %lx of size 0x%x bytes\n",
           ret->kaddr, ret->size);

    if (ioctl(ret->fd, HPROX_ALLOC_PHYS, &ret->phys))
        err(1, "Can't get kernel region physical address");
}

void kernel_region_mmap(int prox_fd, struct kernel_region* reg)
{
    printf("Try to mmap kernel address %lx fd %d\n", reg->kaddr, reg->fd);
    reg->mmap = mmap(NULL, reg->size, PROT_READ | PROT_WRITE,
                    MAP_SHARED, reg->fd, 0);
    if ((void*)reg->mmap == MAP_FAILED)
        err(1, "Can't mmap kernel region");
}

void kernel_region_share_hyp(int fd, struct kernel_region* reg)
{
    ulong nr_pages = (reg->size + PAGE_SIZE - 1) / PAGE_SIZE;
    ulong pfn = reg->phys >> PAGE_SHIFT;
    int ret;
    for (int i = 0; i < nr_pages; ++i){
        unsigned long args[1] = {pfn + i};
        ret = ioctl(
            fd, HVC_PROXY_IOCTL(__KVM_HOST_SMCCC_FUNC___pkvm_host_share_hyp, 1), args);
        if (ret < 0) err(1, "pkvm_proxy host_share_hyp failed");
    }
}

volatile struct hprox_vcpu_fault_info* get_fault_info(int fd, struct kernel_region* vcpu) {
    int fault_info_offset;
    fault_info_offset =
        ioctl(fd, HPROX_STRUCT_KVM_VCPU_GET_OFFSET, HPROX_VCPU_FAULT);
    if (fault_info_offset < 0)
        err(1, "Can't get fault_info offset");
    return (vcpu->mmap + fault_info_offset);
}

volatile struct user_pt_regs* get_regs(int fd, struct kernel_region* vcpu) {
    int regs_offset;
    regs_offset =
        ioctl(fd, HPROX_STRUCT_KVM_VCPU_GET_OFFSET, HPROX_VCPU_REGS);
    if (regs_offset < 0) err(1, "Can't get regs offset");
    return (vcpu->mmap + regs_offset);
}

volatile struct hprox_memcache* get_vcpu_memcache(int fd, struct kernel_region* vcpu) {
    int memcache_offset;
    memcache_offset = ioctl(fd, HPROX_STRUCT_KVM_VCPU_GET_OFFSET, HPROX_VCPU_MEMCACHE);
    if (memcache_offset < 0) err(1, "Can't get vcpu memcache offset");
    return (vcpu->mmap + memcache_offset);
}

// returns handle
int init_vm(int fd) {
    struct kernel_region skvm, hkvm, pgd, last_ran;
    int skvm_created_vcpus_offset;
    volatile int* skvm_created_vcpus;
    int vm_handle;

    skvm.size = ioctl(fd, HPROX_STRUCT_KVM_GET_SIZE, 0);
    if (skvm.size < 0) err(1, "Can't get skvm size");
    alloc_kernel_region(fd, &skvm);
    kernel_region_mmap(fd, &skvm);
    memset(skvm.mmap, 0, skvm.size);
    kernel_region_share_hyp(fd, &skvm);

    skvm_created_vcpus_offset = ioctl(fd, HPROX_STRUCT_KVM_GET_OFFSET, HPROX_CREATED_VCPUS);
    if (skvm_created_vcpus_offset < 0)
        err(1, "Can't get skvm created_vcpus offset");
    skvm_created_vcpus = (int*)(skvm.mmap + skvm_created_vcpus_offset);
    *skvm_created_vcpus = NUM_VCPU;

    hkvm.size = ioctl(fd, HPROX_HYP_VM_GET_SIZE, 0);
    if (hkvm.size < 0) err(1, "Can't get hkvm size");
    hkvm.size += NUM_VCPU * sizeof(void*);
    alloc_kernel_region(fd, &hkvm);
    printf("hkvm kernel address %lx and size %x\n", hkvm.kaddr, hkvm.size);

    pgd.size = ioctl(fd, HPROX_PGD_GET_SIZE, 0);
    if (pgd.size < 0) err(1, "Can't get pgd size");
    alloc_kernel_region(fd, &pgd);
    printf("pgd kernel address %lx and size %x\n", pgd.kaddr, pgd.size);

    last_ran.size = MAX_NUM_CPU * sizeof(int);
    alloc_kernel_region(fd, &last_ran);
    printf("last_ran kernel address %lx and size %x\n", last_ran.kaddr, last_ran.size);

    unsigned long args[4] = {
        skvm.kaddr, hkvm.kaddr, pgd.kaddr, last_ran.kaddr
    };

    vm_handle = ioctl(
        fd, HVC_PROXY_IOCTL(__KVM_HOST_SMCCC_FUNC___pkvm_init_vm, 4), args);
    if(vm_handle < 0) err(1, "pkvm_proxy init_vm failed");

    return vm_handle;
}

int init_vcpu(int fd, int handle, int idx, struct kernel_region *host_vcpu)
{
    struct kernel_region hyp_vcpu;
    int host_vcpu_idx_offset;
    volatile int* host_vcpu_idx;
    int hcr_offset;
    volatile ulong* hcr;
    int ret;

    host_vcpu->size = ioctl(fd, HPROX_STRUCT_KVM_VCPU_GET_SIZE, 0);
    if (host_vcpu->size < 0) err(1, "Can't get host_vcpu size");
    alloc_kernel_region(fd, host_vcpu);
    kernel_region_mmap(fd, host_vcpu);
    memset(host_vcpu->mmap, 0, host_vcpu->size);
    kernel_region_share_hyp(fd, host_vcpu);
    printf("host_vcpu kernel address %lx and size %x\n", host_vcpu->kaddr,
           host_vcpu->size);

    host_vcpu_idx_offset = ioctl(fd, HPROX_STRUCT_KVM_VCPU_GET_OFFSET, HPROX_VCPU_IDX);
    if (host_vcpu_idx_offset < 0)
        err(1, "Can't get host_vcpu idx offset");
    host_vcpu_idx = (int*)(host_vcpu->mmap + host_vcpu_idx_offset);
    *host_vcpu_idx = idx;

    hcr_offset =
        ioctl(fd, HPROX_STRUCT_KVM_VCPU_GET_OFFSET, HPROX_VCPU_HCR_EL2);
    if (hcr_offset < 0) err(1, "Can't get HCR_EL2 offset");
    hcr = (ulong*)(host_vcpu->mmap + hcr_offset);
    *hcr = (1ul << 31);

    hyp_vcpu.size = ioctl(fd, HPROX_HYP_VCPU_GET_SIZE, 0);
    if (hyp_vcpu.size < 0) err(1, "Can't get hyp_vcpu size");
    hyp_vcpu.size += NUM_VCPU * sizeof(void*);
    alloc_kernel_region(fd, &hyp_vcpu);
    printf("hyp_vcpu kernel address %lx and size %x\n", hyp_vcpu.kaddr, hyp_vcpu.size);

    unsigned long args[3] = {
        handle, host_vcpu->kaddr, hyp_vcpu.kaddr
    };

    ret = ioctl(
        fd, HVC_PROXY_IOCTL(__KVM_HOST_SMCCC_FUNC___pkvm_init_vcpu, 3), args);
    if(ret < 0) err(1, "pkvm_proxy init_vcpu failed");

    return ret;
}

int set_vcpu_dirty(int fd, struct kernel_region* vcpu){
    int iflags_offset;
    volatile __u8* iflags;
    iflags_offset =
        ioctl(fd, HPROX_STRUCT_KVM_VCPU_GET_OFFSET, HPROX_VCPU_IFLAGS);
    if (iflags_offset < 0) err(1, "Can't get iflags offset");
    iflags = (__u8*)(vcpu->mmap + iflags_offset);
    *iflags = ((__u8)1) << 7;
}

int load_vcpu(int fd, int handle, int idx) {
    int ret;

    unsigned long args[3] = {
        handle, idx, 0 /* HCR_EL2 */
    };

    ret = ioctl(fd, HVC_PROXY_IOCTL(__KVM_HOST_SMCCC_FUNC___pkvm_vcpu_load, 3),
                args);
    if (ret < 0) err(1, "pkvm_proxy vcpu_load failed");

    return ret;
}

int run_vcpu(int fd, ulong vcpu_kaddr) {
    int ret;

    unsigned long args[1] = {
        vcpu_kaddr
    };

    ret = ioctl(fd, HVC_PROXY_IOCTL(__KVM_HOST_SMCCC_FUNC___kvm_vcpu_run, 1),
                args);
    if (ret < 0) err(1, "pkvm_proxy vcpu_run failed");

    return ret;
}

int put_vcpu(int fd) {
    int ret;

    ret = ioctl(fd, HVC_PROXY_IOCTL(__KVM_HOST_SMCCC_FUNC___pkvm_vcpu_put, 0),
                NULL);
    if (ret < 0) err(1, "pkvm_proxy vcpu_put failed");

    return ret;
}

int teardown_vm(int fd, int handle) {
    int ret;

    unsigned long args[1] = {
        handle,
    };

    ret = ioctl(fd,
                HVC_PROXY_IOCTL(__KVM_HOST_SMCCC_FUNC___pkvm_teardown_vm, 1),
                args);
    if (ret < 0) err(1, "pkvm_proxy teardown_vm failed");

    return ret;
}

int topup_hyp_memcache(int fd, volatile struct hprox_memcache* mc, unsigned long min_pages){
    while (mc->nr_pages < min_pages){
        printf("Adding a page to memcache\n");
        struct kernel_region page;
        page.size = PAGE_SIZE;
        alloc_kernel_region(fd, &page);
        kernel_region_mmap(fd, &page);
        *(__u64*)page.mmap = mc->head;
        mc->head = page.phys;
        mc->nr_pages++;
    }
}

int map_region_guest(int fd, struct kernel_region* vcpu, struct kernel_region* mem, ulong gphys){
    int ret;
    for(ulong mapped_size =0; mapped_size < mem->size; mapped_size += PAGE_SIZE){
        topup_hyp_memcache(fd,get_vcpu_memcache(fd, vcpu), 5);
        unsigned long args[2] = {
            (mem->phys + mapped_size) >> PAGE_SHIFT,
            (gphys + mapped_size) >> PAGE_SHIFT,
        };
        ret = ioctl(
            fd, HVC_PROXY_IOCTL(__KVM_HOST_SMCCC_FUNC___pkvm_host_map_guest, 2),
            args);
        if (ret < 0) err(1, "pkvm_proxy couldn't give memory to guest");
    }
}

int main(int argc, char** argv)
{
    struct kernel_region vcpu;
    volatile struct hprox_vcpu_fault_info *fault_info;
    volatile struct user_pt_regs* regs;
    volatile struct hprox_memcache* vcpu_mc;
    int fd, ret;
    int vm_handle;

    const uint8_t code[] = {
        0x20, 0x00, 0x00, 0x8b, /* add x0, x1, x0 */
        0x40, 0x00, 0x00, 0xf9, /* str x0, [x2]*/
        0x00, 0x00, 0x20, 0xd4, /* brk */
    };

    // A single fd descriptor allows coverage collection on a single thread.
    fd = open("/sys/kernel/debug/pkvm_proxy", O_RDWR);
    if (fd == -1) err(1, "pkvm_proxy open");

    printf("Opened pkvm_proxy fd %d\n", fd);

    vm_handle = init_vm(fd);
    printf ("Initialized VM with handle %d\n", vm_handle);

    init_vcpu(fd, vm_handle, 0, &vcpu);
    printf("Initialized VCPU 0 \n");
    fault_info = get_fault_info(fd, &vcpu);
    regs = get_regs(fd, &vcpu);
    regs->pc = 0x1000;
    regs->regs[0] = 0x11;
    regs->regs[1] = 0x1100;
    regs->regs[2] = 0x123456;
    set_vcpu_dirty(fd, &vcpu);

    vcpu_mc = get_vcpu_memcache(fd, &vcpu);
    topup_hyp_memcache(fd, vcpu_mc, 10);

    load_vcpu(fd, vm_handle, 0);
    printf("Loaded VCPU 0 \n");

    struct kernel_region gcode;
    gcode.size = PAGE_SIZE;
    alloc_kernel_region(fd, &gcode);
    kernel_region_mmap(fd, &gcode);
    memcpy(gcode.mmap, code, 8);
    map_region_guest(fd, &vcpu, &gcode, 0x1000);

    int exit_code = run_vcpu(fd, vcpu.kaddr);
    printf("Ran VCPU 0 with exit code %d\n", exit_code);
    printf("Fault info\n\tesr: %llx\n\tfar: %llx\n\thpfar: %llx\n\tdisr: %llx\n",
           fault_info->esr_el2,
           fault_info->far_el2,
           fault_info->hpfar_el2,
           fault_info->disr_el1);

    put_vcpu(fd);
    printf("Unloaded VCPU 0 \n");

    teardown_vm(fd, vm_handle);
    printf("Teared down VM \n");

    return 0;
}

