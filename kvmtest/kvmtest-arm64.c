/*
 *
 * This is an Arm64 port of the x86 code accompanying "Using the KVM API"
 * (https://lwn.net/Articles/658511/).
 *
 * Original x86 code in the file kvmtest.c and https://lwn.net/Articles/658512/.
 *
 * Copyright (C) 2020 Google LLC
 * Author: Fuad Tabba <tabba@google.com>
 */

/* Sample code for /dev/kvm API
 *
 * Copyright (c) 2015 Intel Corporation
 * Author: Josh Triplett <josh@joshtriplett.org>
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to
 * deal in the Software without restriction, including without limitation the
 * rights to use, copy, modify, merge, publish, distribute, sublicense, and/or
 * sell copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in
 * all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING
 * FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS
 * IN THE SOFTWARE.
 */
#include <err.h>
#include <fcntl.h>
#include <linux/kvm.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <sys/types.h>

int main(void)
{
    int kvm, vmfd, vcpufd, ret;

    /* Add x0 to x1 and outputs the result to MMIO at address in x2. */
    const uint8_t code[] = {
        0x20, 0x00, 0x00, 0x8b, /* add x0, x1, x0 */
        0x40, 0x00, 0x00, 0xf9, /* str x0, [x2]*/
        0x00, 0x00, 0x20, 0xd4, /* brk */
    };
    const uint64_t code_address = 0x1000;
    const uint64_t mmio_address = 0x2000;
    uint8_t *mem_code = NULL;
    size_t mmap_size;
    struct kvm_run *run = NULL;

    kvm = open("/dev/kvm", O_RDWR | O_CLOEXEC);
    if (kvm < 0)
        err(1, "/dev/kvm");

    /* Ensure this is the stable version of the KVM API (defined as 12) */
    ret = ioctl(kvm, KVM_GET_API_VERSION, NULL);
    if (ret < 0)
        err(1, "KVM_GET_API_VERSION");
    if (ret != 12)
        errx(1, "KVM_GET_API_VERSION %d, expected 12", ret);

    vmfd = ioctl(kvm, KVM_CREATE_VM, (unsigned long)0);
    if (vmfd < 0)
        err(1, "KVM_CREATE_VM");

    /* Allocate one aligned page of guest memory to hold the code. */
    mem_code = mmap(NULL, 0x1000,
        PROT_READ | PROT_WRITE, MAP_SHARED | MAP_ANONYMOUS, -1, 0);
    if (!mem_code)
        err(1, "allocating guest memory");
    memcpy(mem_code, code, sizeof(code));

    /* Map code memory to the second page frame. */
    struct kvm_userspace_memory_region region = {
        .slot = 0,
        .guest_phys_addr = code_address,
        .memory_size = 0x1000,
        .userspace_addr = (uint64_t)mem_code,
    };
    ret = ioctl(vmfd, KVM_SET_USER_MEMORY_REGION, &region);
    if (ret < 0)
        err(1, "KVM_SET_USER_MEMORY_REGION");

    /* Use third page frame of guest memory to simulate MMIO. */
    region.flags = KVM_MEM_READONLY; /* triggers KVM_EXIT_MEMIO on write */
    region.slot = 1;
    region.guest_phys_addr = mmio_address;
    region.userspace_addr = 0ULL;
    ret = ioctl(vmfd, KVM_SET_USER_MEMORY_REGION, &region);
    if (ret < 0)
        err(1, "KVM_SET_USER_MEMORY_REGION");

    /* Create one CPU to run in the VM. */
    vcpufd = ioctl(vmfd, KVM_CREATE_VCPU, (unsigned long)0);
    if (vcpufd < 0)
        err(1, "KVM_CREATE_VCPU");

    /* Map the shared kvm_run structure and following data. */
    ret = ioctl(kvm, KVM_GET_VCPU_MMAP_SIZE, NULL);
    if (ret < 0)
        err(1, "KVM_GET_VCPU_MMAP_SIZE");
    mmap_size = ret;
    if (mmap_size < sizeof(*run))
        errx(1, "KVM_GET_VCPU_MMAP_SIZE unexpectedly small");
    run = mmap(NULL, mmap_size, PROT_READ | PROT_WRITE, MAP_SHARED, vcpufd, 0);
    if (!run)
        err(1, "mmap vcpu");

    /* Query KVM for preferred CPU target type that can be emulated. */
    struct kvm_vcpu_init vcpu_init;
    ret = ioctl(vmfd, KVM_ARM_PREFERRED_TARGET, &vcpu_init);
    if (ret < 0)
        err(1, "KVM_PREFERRED_TARGET");

    /* Initialize VCPU with the preferred type obtained above. */
    ret = ioctl(vcpufd, KVM_ARM_VCPU_INIT, &vcpu_init);
    if (ret < 0)
        err(1, "KVM_ARM_VCPU_INIT");

    /* Prepare the kvm_one_reg structure to use for populating registers. */
    uint64_t reg_data;
    struct kvm_one_reg reg;
    reg.addr = (__u64) &reg_data;

    // Initialize input registers (x0 and x1) to 2.
    reg_data = 2;
    reg.id = 0x6030000000100000; // x0 id
    ret = ioctl(vcpufd, KVM_SET_ONE_REG, &reg);
    if (ret != 0)
        err(1, "KVM_SET_ONE_REG");
    reg.id = 0x6030000000100002; // x1 id
    ret = ioctl(vcpufd, KVM_SET_ONE_REG, &reg);
    if (ret != 0)
        err(1, "KVM_SET_ONE_REG");

    // Initialize x3 to point to the simulated MMIO region.
    reg.id = 0x6030000000100004; // x3 id
    reg_data = mmio_address;
    ret = ioctl(vcpufd, KVM_SET_ONE_REG, &reg);
    if (ret != 0)
        err(1, "KVM_SET_ONE_REG");

    // Initialize the PC to point to the start of the code.
    reg.id = 0x6030000000100040; // pc id
    reg_data = code_address;
    ret = ioctl(vcpufd, KVM_SET_ONE_REG, &reg);
    if (ret != 0)
        err(1, "KVM_SET_ONE_REG");

    // Enable debug so that brk instruction would exit KVM_RUN (KVM_EXIT_DEBUG).
    struct kvm_guest_debug debug = {
        .control = KVM_GUESTDBG_ENABLE,
    };
    ret = ioctl(vcpufd, KVM_SET_GUEST_DEBUG, &debug);
    if (ret < 0)
        err(1, "KVM_SET_GUEST_DEBUG");

    /* Repeatedly run code and handle VM exits. */
    for (;;) {
        ret = ioctl(vcpufd, KVM_RUN, NULL);
        if (ret < 0)
            err(1, "KVM_RUN");
        switch (run->exit_reason) {
        case KVM_EXIT_DEBUG:
            puts("KVM_EXIT_DEBUG");
            return 0;
        case KVM_EXIT_MMIO:
        {
            uint64_t payload = *(uint64_t*)(run->mmio.data); /* sorry */
            printf("KVM_EXIT_MMIO: addr = 0x%llx, len = %u, is_write = %u, data = 0x%08llx\n",
                run->mmio.phys_addr, run->mmio.len, run->mmio.is_write,
                payload);
            break;
        }
        case KVM_EXIT_FAIL_ENTRY:
            errx(1, "KVM_EXIT_FAIL_ENTRY: hardware_entry_failure_reason = 0x%llx",
                 (unsigned long long)run->fail_entry.hardware_entry_failure_reason);
        case KVM_EXIT_INTERNAL_ERROR:
            errx(1, "KVM_EXIT_INTERNAL_ERROR: suberror = 0x%x",
                run->internal.suberror);
        default:
            errx(1, "exit_reason = 0x%x", run->exit_reason);
        }
    }
}
