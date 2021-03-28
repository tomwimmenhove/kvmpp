/* 
 * This file is part of the kvmpp distribution (https://github.com/tomwimmenhove/kvmpp);
 * Copyright (c) 2021 Tom Wimmenhove.
 * 
 * This program is free software: you can redistribute it and/or modify  
 * it under the terms of the GNU General Public License as published by  
 * the Free Software Foundation, version 3.
 *
 * This program is distributed in the hope that it will be useful, but 
 * WITHOUT ANY WARRANTY; without even the implied warranty of 
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU 
 * General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License 
 * along with this program. If not, see <http://www.gnu.org/licenses/>.
 */
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <fcntl.h>
#include <errno.h>
#include <sys/ioctl.h>
#include <sys/mman.h>

#include <sstream>
#include <system_error>
#include <exception>

#include "kvmpp.h"

kvm_vcpu::kvm_vcpu(int fd)
	: fd(fd)
{
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

std::unique_ptr<kvm_vcpu> kvm_machine::create_vcpu(int id)
{
	int vcpu_fd = ioctl(fd, KVM_CREATE_VCPU, id);
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
