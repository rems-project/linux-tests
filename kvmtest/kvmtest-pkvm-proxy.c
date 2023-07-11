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

// #define KCOV_INIT_TRACE _IOR('c', 1, unsigned long)
#define KCOV_INIT_HYP_TRACE _IOR('c', 2, unsigned long)
// #define KCOV_ENABLE _IO('c', 100)
// #define KCOV_DISABLE _IO('c', 101)

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


#define PKVM_PROXY_HVC_IOC_TYPE 0
#define PKVM_PROXY_HELPER_IOC_TYPE 0

#define HVC_PROXY_IOCTL(hvcnum, numarg)                         \
  _IOC(_IOC_WRITE, PKVM_PROXY_HVC_IOC_TYPE, hvcnum, 8 * numarg)

int main(int argc, char **argv)
{
    int fd;
    unsigned long n, i;
    unsigned int j, size;


    // A single fd descriptor allows coverage collection on a single thread.
    fd = open("/sys/kernel/debug/pkvm_proxy", O_RDWR);
    if (fd == -1)
        err(1, "pkvm_proxy open");

    printf("Opened pkvm_proxy fd %d\n", fd);

    unsigned long args[1] = {
      0x42
    };

    /* Setup trace mode and trace size. */
    if (ioctl(fd, HVC_PROXY_IOCTL(__KVM_HOST_SMCCC_FUNC___pkvm_hello_world, 1), args))
        err(1, "pkvm_proxy hello world");
    printf("Returned from hvc\n");
    return 0;
}

