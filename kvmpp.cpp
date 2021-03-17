#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <fcntl.h>
#include <errno.h>
#include <sys/ioctl.h>
#include <linux/kvm.h>
#include <sys/mman.h>
#include <string.h>

#include <iostream>
#include <sstream>
#include <system_error>
#include <exception>

#include "kvmpp.h"

kvm_vcpu::kvm_vcpu(int fd)
	: fd(fd)
{
	std::cout << "VCPU fd: " << fd << '\n';
	run_mmap = get_kvm_run();
}

kvm_vcpu::~kvm_vcpu()
{
	close(fd);
}

struct kvm_regs kvm_vcpu::get_regs()
{
	struct kvm_regs regs;

	get_regs(regs);

	return regs;
}

void kvm_vcpu::get_regs(struct kvm_regs& regs)
{
	if (ioctl(fd, KVM_GET_REGS, &regs) < 0)
	{
		throw std::system_error(errno, std::generic_category());
	}
}

void kvm_vcpu::set_regs(struct kvm_regs& regs)
{
	if (ioctl(fd, KVM_SET_REGS, &regs) < 0)
	{
		throw std::system_error(errno, std::generic_category());
	}
}

struct kvm_sregs kvm_vcpu::get_sregs()
{
	struct kvm_sregs sregs;

	get_sregs(sregs);

	return sregs;
}

void kvm_vcpu::get_sregs(struct kvm_sregs& sregs)
{
	if (ioctl(fd, KVM_GET_SREGS, &sregs) < 0)
	{
		throw std::system_error(errno, std::generic_category());
	}
}

void kvm_vcpu::set_sregs(struct kvm_sregs& sregs)
{
	if (ioctl(fd, KVM_SET_SREGS, &sregs) < 0)
	{
		throw std::system_error(errno, std::generic_category());
	}
}

struct kvm_run* kvm_vcpu::run()
{
	if (ioctl(fd, KVM_RUN, 0) < 0)
	{
		throw std::system_error(errno, std::generic_category());
	}

	return run_mmap;
}

struct kvm_run* kvm_vcpu::get_kvm_run()
{
	int size = kvm::get_instance()->get_mmap_size();

	std::cout << "size: " << size << '\n';

	struct kvm_run* p = (struct kvm_run*)
		mmap(NULL, size, PROT_READ | PROT_WRITE, MAP_SHARED, fd, 0);
	if (p == MAP_FAILED)
	{
		throw std::system_error(errno, std::generic_category());
	}

	return p;
}

kvm_machine::kvm_machine(int fd)
	: fd(fd)
{
	if (ioctl(fd, KVM_SET_TSS_ADDR, 0xfffbd000) < 0)
	{
		throw std::system_error(errno, std::generic_category());
	}

	std::cout << "Machine fd: " << fd << '\n';
}

void kvm_machine::set_user_memory_region(
		__u32 slot, __u32 flags, __u64 guest_phys_addr, __u64 memory_size, void* userspace_addr)
{
	struct kvm_userspace_memory_region memreg;

	memreg.slot = slot;
	memreg.flags = flags;
	memreg.guest_phys_addr = guest_phys_addr;
	memreg.memory_size = memory_size;
	memreg.userspace_addr = (__u64) userspace_addr;

	set_user_memory_region(memreg);
}

void kvm_machine::set_user_memory_region(struct kvm_userspace_memory_region& memreg)
{
	if (ioctl(fd, KVM_SET_USER_MEMORY_REGION, &memreg) < 0)
	{
		throw std::system_error(errno, std::generic_category());
	}
}

std::unique_ptr<kvm_vcpu> kvm_machine::create_vcpu()
{
	int vcpu_fd = ioctl(fd, KVM_CREATE_VCPU, 0);
	if (vcpu_fd < 0)
	{
		throw std::system_error(errno, std::generic_category());
	}

	return std::make_unique<kvm_vcpu>(vcpu_fd);
}

kvm_machine::~kvm_machine()
{
	close(fd);
}

int kvm::get_api_version()
{
	int api_ver = ioctl(fd, KVM_GET_API_VERSION, 0);
	if (api_ver < 0)
	{
		throw std::system_error(errno, std::generic_category());
	}

	return api_ver;
}

kvm* kvm::instance = nullptr;
kvm* kvm::get_instance()
{
	if (instance == nullptr)
	{
		instance = new kvm();
	}

	return instance;
}

void kvm::destroy()
{
	if (instance == nullptr)
	{
		return;
	}

	delete instance;
	instance = nullptr;
}

kvm::kvm()
{
	fd = open("/dev/kvm", O_RDWR);
	if (fd < 0)
	{
		throw std::system_error(errno, std::generic_category());
	}

	int api_ver = get_api_version();
	if (api_ver != KVM_API_VERSION)
	{
		std::ostringstream ss;
		ss << "Got KVM api version " << api_ver << ", expected " << KVM_API_VERSION;

		throw kvm_exception(ss.str());
	}

	std::cout << "KVM fd: " << fd << '\n';
}

std::unique_ptr<kvm_machine> kvm::create_vm()
{
	int vm_fd = ioctl(fd, KVM_CREATE_VM, 0);
	if (vm_fd < 0)
	{
		throw std::system_error(errno, std::generic_category());
	}

	return std::make_unique<kvm_machine>(vm_fd);
}

int kvm::get_mmap_size()
{
	int size = ioctl(fd, KVM_GET_VCPU_MMAP_SIZE, 0);
	if (size < 0)
	{
		throw std::system_error(errno, std::generic_category());
	}

	return size;
}

kvm::~kvm()
{
	close(fd);
}

#define CR0_PE 1u
#define CR0_MP (1U << 1)
#define CR0_EM (1U << 2)
#define CR0_TS (1U << 3)
#define CR0_ET (1U << 4)
#define CR0_NE (1U << 5)
#define CR0_WP (1U << 16)
#define CR0_AM (1U << 18)
#define CR0_NW (1U << 29)
#define CR0_CD (1U << 30)
#define CR0_PG (1U << 31)
#define CR4_VME 1
#define CR4_PVI (1U << 1)
#define CR4_TSD (1U << 2)
#define CR4_DE (1U << 3)
#define CR4_PSE (1U << 4)
#define CR4_PAE (1U << 5)
#define CR4_MCE (1U << 6)
#define CR4_PGE (1U << 7)
#define CR4_PCE (1U << 8)
#define CR4_OSFXSR (1U << 8)
#define CR4_OSXMMEXCPT (1U << 10)
#define CR4_UMIP (1U << 11)
#define CR4_VMXE (1U << 13)
#define CR4_SMXE (1U << 14)
#define CR4_FSGSBASE (1U << 16)
#define CR4_PCIDE (1U << 17)
#define CR4_OSXSAVE (1U << 18)
#define CR4_SMEP (1U << 20)
#define CR4_SMAP (1U << 21)
#define EFER_SCE 1
#define EFER_LME (1U << 8)
#define EFER_LMA (1U << 10)
#define EFER_NXE (1U << 11)
#define PDE32_PRESENT 1
#define PDE32_RW (1U << 1)
#define PDE32_USER (1U << 2)
#define PDE32_PS (1U << 7)
#define PDE64_PRESENT 1
#define PDE64_RW (1U << 1)
#define PDE64_USER (1U << 2)
#define PDE64_ACCESSED (1U << 5)
#define PDE64_DIRTY (1U << 6)
#define PDE64_PS (1U << 7)
#define PDE64_G (1U << 8)

static void setup_64bit_code_segment(struct kvm_sregs *sregs)
{
	struct kvm_segment seg;
	seg.base = 0;
	seg.limit = 0xffffffff;
	seg.selector = 1 << 3;
	seg.present = 1;
	seg.type = 11; /* Code: execute; read; accessed */
	seg.dpl = 0;
	seg.db = 0;
	seg.s = 1; /* Code/data */
	seg.l = 1;
	seg.g = 1; /* 4KB granularity */

	sregs->cs = seg;

	seg.type = 3; /* Data: read/write, accessed */
	seg.selector = 2 << 3;
	sregs->ds = sregs->es = sregs->fs = sregs->gs = sregs->ss = seg;
}

static void setup_long_mode(void *mem_p, struct kvm_sregs *sregs)
{   
	char* mem = (char*) mem_p;

	uint64_t pml4_addr = 0x2000;
	uint64_t *pml4 = (uint64_t *)(mem + pml4_addr);

	uint64_t pdpt_addr = 0x3000;
	uint64_t *pdpt = (uint64_t *)(mem + pdpt_addr);

	uint64_t pd_addr = 0x4000;
	uint64_t *pd = (uint64_t *)(mem + pd_addr);

	pml4[0] = PDE64_PRESENT | PDE64_RW | PDE64_USER | pdpt_addr;
	pdpt[0] = PDE64_PRESENT | PDE64_RW | PDE64_USER | pd_addr;
	pd[0] = PDE64_PRESENT | PDE64_RW | PDE64_USER | PDE64_PS;

	sregs->cr3 = pml4_addr;
	sregs->cr4 = CR4_PAE;
	sregs->cr0
		= CR0_PE | CR0_MP | CR0_ET | CR0_NE | CR0_WP | CR0_AM | CR0_PG;
	sregs->efer = EFER_LME | EFER_LMA;

	setup_64bit_code_segment(sregs);
}


int main()
{
	auto kvm = kvm::get_instance();

	auto machine = kvm->create_vm();

	/* Put some memory in the machine */
	size_t mem_size = 2048 * 1024;
	void* mem = mmap(NULL, mem_size, PROT_READ | PROT_WRITE,
			MAP_PRIVATE | MAP_ANONYMOUS | MAP_NORESERVE, -1, 0);
	if (mem == MAP_FAILED)
	{
		throw std::system_error(errno, std::generic_category());
	}

	madvise(mem, mem_size, MADV_MERGEABLE);

	machine->set_user_memory_region(0, 0, 0, mem_size, mem);

	/* Setup the VCPU */
	auto vcpu = machine->create_vcpu();

	struct kvm_sregs sregs;
	struct kvm_regs regs;

	vcpu->get_sregs(sregs);
	setup_long_mode(mem, &sregs);
	vcpu->set_sregs(sregs);

	memset(&regs, 0, sizeof(regs));
	/* Clear all FLAGS bits, except bit 1 which is always set. */
	regs.rflags = 2;
	regs.rip = 0;
	/* Create stack at top of 2 MB page and grow down. */
	regs.rsp = 2 << 20;

	vcpu->set_regs(regs);

	*((unsigned char*) mem) = 0xf4; // HLT

	auto run = vcpu->run();

	std::cout << "Reason: " << run->exit_reason << '\n';

	kvm->destroy();

	return 0;
}
