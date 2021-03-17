#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <fcntl.h>
#include <errno.h>
#include <sys/ioctl.h>
#include <linux/kvm.h>
#include <sys/mman.h>

#include <iostream>
#include <sstream>
#include <system_error>
#include <exception>

#include "kvmpp.h"

kvm_vcpu::kvm_vcpu(int fd)
	: fd(fd)
{
	std::cout << "VCPU fd: " << fd << '\n';
	run = get_kvm_run();
}

kvm_vcpu::~kvm_vcpu()
{
	close(fd);
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
		__u32 slot, __u32 flags, __u64 guest_phys_addr, __u64 memory_size, __u64 userspace_addr)
{
	struct kvm_userspace_memory_region memreg;

	memreg.slot = slot;
	memreg.flags = flags;
	memreg.guest_phys_addr = guest_phys_addr;
	memreg.memory_size = memory_size;
	memreg.userspace_addr = userspace_addr;

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

int main()
{
	auto kvm = kvm::get_instance();

	auto machine = kvm->create_vm();
	auto vcpu = machine->create_vcpu();

	kvm->destroy();

	return 0;
}
