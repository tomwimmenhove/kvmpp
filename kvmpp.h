#ifndef KVMPP_H
#define KVMPP_H

#include "memory"

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

private:
	struct kvm_run* get_kvm_run();

	int fd;
	struct kvm_run* run;
};

class kvm_machine
{
public:
	kvm_machine(int fd);

	void set_user_memory_region(
			__u32 slot, __u32 flags, __u64 guest_phys_addr, __u64 memory_size, __u64 userspace_addr);
	void set_user_memory_region(struct kvm_userspace_memory_region& memreg);
	kvm_vcpu create_vcpu();
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

	kvm_machine create_vm();
	int get_mmap_size();

private:
	int get_api_version();
	kvm();

	static kvm* instance;
	int fd;
};

#endif /* KVMPP_H */
