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
	__KVM_HOST_SMCCC_FUNC___kvm_tlb_flush_vmid,
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
	__KVM_HOST_SMCCC_FUNC___vgic_v3_save_vmcr_aprs,
	__KVM_HOST_SMCCC_FUNC___vgic_v3_restore_vmcr_aprs,
	__KVM_HOST_SMCCC_FUNC___pkvm_init_vm,
	__KVM_HOST_SMCCC_FUNC___pkvm_init_vcpu,
	__KVM_HOST_SMCCC_FUNC___pkvm_teardown_vm,
	__KVM_HOST_SMCCC_FUNC___pkvm_vcpu_load,
	__KVM_HOST_SMCCC_FUNC___pkvm_vcpu_put,
	__KVM_HOST_SMCCC_FUNC___pkvm_vcpu_sync_state,
	__KVM_HOST_SMCCC_FUNC___pkvm_hello_world,
};

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
	HPROX_VCPU_ID,
	HPROX_VCPU_IDX,
	HPROX_ARCH_CFLAGS,
	HPROX_ARCH_FEATURES,
	HPROX_ARCH_HCR_EL2,
	// TODO add SVE state, for now SVE-less guests only
};

// Need to match up kvm_hyp_memcache
struct hprox_hyp_memcache {
	unsigned long head; // kernel address, might not be accessible, if not
			    // donated from a hprox_alloc region.
	unsigned long nr_pages;
};
enum hprox_alloc_type { HPROX_VMALLOC, HPROX_PAGES_EXACT };

#define HPROX_ALLOC(alloc) _IO(HPROX_ALLOC_TYPE, alloc)
#define HPROX_ALLOC_PAGES HPROX_ALLOC(HPROX_PAGES_EXACT)

// ioctl on the mmapable fd from the HPROX_ALLOC ioctl
#define HPROX_ALLOC_KADDR _IOR(0,0, void*)
#define HPROX_ALLOC_PHYS _IOR(0, 1, void *)



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

    if (ioctl(ret->fd, HPROX_ALLOC_PHYS, &ret->phys))
        err(1, "Can't get kernel region physical address");
}

void kernel_region_mmap(int prox_fd, struct kernel_region* reg)
{
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

// returns handle
int init_vm(int fd)
{
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

    pgd.size = ioctl(fd, HPROX_PGD_GET_SIZE, 0);
    if (pgd.size < 0) err(1, "Can't get pgd size");
    alloc_kernel_region(fd, &pgd);

    last_ran.size = MAX_NUM_CPU * sizeof(int);
    alloc_kernel_region(fd, &last_ran);

    unsigned long args[4] = {
        skvm.kaddr, hkvm.kaddr, pgd.kaddr, last_ran.kaddr
    };

    vm_handle = ioctl(
        fd, HVC_PROXY_IOCTL(__KVM_HOST_SMCCC_FUNC___pkvm_init_vm, 4), args);
    if(vm_handle < 0) err(1, "pkvm_proxy init_vm failed");

    return vm_handle;

}



int init_vcpu(int fd, int handle, int idx) // TODO WIP, not running
{
    struct kernel_region host_vcpu, hyp_vcpu;
    int host_vcpu_idx_offset;
    volatile int* host_vcpu_idx;
    int ret;

    host_vcpu.size = ioctl(fd, HPROX_STRUCT_KVM_VCPU_GET_SIZE, 0);
    if (host_vcpu.size < 0) err(1, "Can't get host_vcpu size");
    alloc_kernel_region(fd, &host_vcpu);
    kernel_region_mmap(fd, &host_vcpu);

    memset(host_vcpu.mmap, 0, host_vcpu.size);

    host_vcpu_idx_offset = ioctl(fd, HPROX_STRUCT_KVM_VCPU_GET_OFFSET, HPROX_VCPU_IDX);
    if (host_vcpu_idx_offset < 0)
        err(1, "Can't get host_vcpu idx offset");
    host_vcpu_idx = (int*)(host_vcpu.mmap + host_vcpu_idx_offset);
    *host_vcpu_idx = idx;
    kernel_region_share_hyp(fd, &host_vcpu);

    hyp_vcpu.size = ioctl(fd, HPROX_HYP_VM_GET_SIZE, 0);
    if (hyp_vcpu.size < 0) err(1, "Can't get hyp_vcpu size");
    hyp_vcpu.size += NUM_VCPU * sizeof(void*);
    alloc_kernel_region(fd, &hyp_vcpu);

    unsigned long args[3] = {
        handle, host_vcpu.kaddr, hyp_vcpu.kaddr
    };

    ret = ioctl(
        fd, HVC_PROXY_IOCTL(__KVM_HOST_SMCCC_FUNC___pkvm_init_vcpu, 3), args);
    if(ret < 0) err(1, "pkvm_proxy init_vm failed");

    return ret;

}

int main(int argc, char** argv)
{
    int fd, ret;
    int vm_handle;

    // A single fd descriptor allows coverage collection on a single thread.
    fd = open("/sys/kernel/debug/pkvm_proxy", O_RDWR);
    if (fd == -1) err(1, "pkvm_proxy open");

    printf("Opened pkvm_proxy fd %d\n", fd);

    vm_handle = init_vm(fd);

    // Simple teardown for now
    unsigned long targs[1] = {vm_handle};
    ret = ioctl(
        fd, HVC_PROXY_IOCTL(__KVM_HOST_SMCCC_FUNC___pkvm_teardown_vm, 1), targs);
    if (ret < 0) err(1, "pkvm_proxy init_vm failed");

    printf("Returned from hvc\n");
    return 0;
}

