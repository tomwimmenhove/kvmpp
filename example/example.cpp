#include <string.h>
#include <iostream>
#include <sys/mman.h>

#include "../src/kvmpp.h"
#include "cpudefs.h"

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
	/* Get the KVM instance */
	auto kvm = kvm::get_instance();

	/* Create a virtual machine instance */
	auto machine = kvm->create_vm();

	/* Allocate memory for the machine */
	size_t mem_size = 2048 * 1024;
	void* mem = mmap(NULL, mem_size, PROT_READ | PROT_WRITE,
			MAP_PRIVATE | MAP_ANONYMOUS | MAP_NORESERVE, -1, 0);
	if (mem == MAP_FAILED)
	{
		throw std::system_error(errno, std::generic_category());
	}

	madvise(mem, mem_size, MADV_MERGEABLE);

	/* Stick it in slot 0 */
	machine->set_user_memory_region(0, 0, 0, mem_size, mem);


	/* Create a virtual CPU instance on the virtual machine */
	auto vcpu = machine->create_vcpu();

	/* Setup the special registers */
	struct kvm_sregs sregs;
	vcpu->get_sregs(sregs);
	setup_long_mode(mem, &sregs);
	vcpu->set_sregs(sregs);

	/* Set up the general registers */
	struct kvm_regs regs;
	memset(&regs, 0, sizeof(regs));
	/* Clear all FLAGS bits, except bit 1 which is always set. */
	regs.rflags = 2;
	regs.rip = 42;
	/* Create stack at top of 2 MB page and grow down. */
	regs.rsp = 2 << 20;
	vcpu->set_regs(regs);

	/* Write a halt instruction to where the instruction pointers points */
	*((unsigned char*) mem + regs.rip) = 0xf4;

	/* Run the CPU */
	auto run = vcpu->run();

	if (run->exit_reason != KVM_EXIT_HLT)
	{
		std::cout << "VCPU exited with reason: " << run->exit_reason << ", expected " << KVM_EXIT_HLT << '\n';
	}
	else
	{
		std::cout << "Success!\n";
	}

	kvm->destroy();

	return 0;
}
