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
#ifndef KVMPP_H
#define KVMPP_H

#include <linux/kvm.h>
#include <memory>

class kvm_exception : public std::exception
{
public:
	kvm_exception(std::string message)
		: message(message)
	{ }

	const char* what() const noexcept
	{
		return message.c_str();
	}

private:
	std::string message;
};

class kvm;
class kvm_machine;

class kvm_vcpu
{
public:
	kvm_vcpu(int fd);

	virtual ~kvm_vcpu();

	struct kvm_regs get_regs();
	void set_regs(struct kvm_regs& regs);
	void get_regs(struct kvm_regs& regs);

	struct kvm_sregs get_sregs();
	void set_sregs(struct kvm_sregs& sregs);
	void get_sregs(struct kvm_sregs& sregs);

	template<typename T>
	T read_from_run(uint64_t offset)
	{   
		return *(T*) ((uintptr_t) run_mmap + run_mmap->io.data_offset);
	}

	uint8_t read_io8_from_run() { return read_from_run<uint8_t>(run_mmap->io.data_offset); }
	uint8_t read_io16_from_run() { return read_from_run<uint16_t>(run_mmap->io.data_offset); }
	uint8_t read_io32_from_run() { return read_from_run<uint32_t>(run_mmap->io.data_offset); }

	uint32_t read_io_from_run()
	{
		switch (run_mmap->io.size)
		{   
			case sizeof(uint8_t): return read_io8_from_run();
			case sizeof(uint16_t): return read_io16_from_run();
			case sizeof(uint32_t): return read_io32_from_run();
		}

		throw std::invalid_argument("Invalid I/O size");
	}

	struct kvm_run* run();

private:
	struct kvm_run* get_kvm_run();

	int fd;
	struct kvm_run* run_mmap;
};

class kvm_machine
{
public:
	kvm_machine(int fd);

	void set_user_memory_region(
			__u32 slot, __u32 flags, __u64 guest_phys_addr, __u64 memory_size, void* userspace_addr);
	void set_user_memory_region(struct kvm_userspace_memory_region& memreg);
	std::unique_ptr<kvm_vcpu> create_vcpu(int id = 0);
	virtual ~kvm_machine();

private:
	int fd;
};

class kvm
{
public:
	static kvm* get_instance();

	void destroy();
	virtual ~kvm();

	std::unique_ptr<kvm_machine> create_vm();
	int get_mmap_size();

private:
	int get_api_version();
	kvm();

	static kvm* instance;
	int fd;
};

#endif /* KVMPP_H */
