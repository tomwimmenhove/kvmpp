#ifndef KVMPP_H
#define KVMPP_H

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
	kvm_vcpu(kvm* kvm_inst, kvm_machine* kvm_machine_inst, int fd);

	virtual ~kvm_vcpu();

private:
	struct kvm_run* get_kvm_run();

	kvm* kvm_inst;
	kvm_machine* kvm_machine_inst;
	int fd;
	struct kvm_run* run;
};

class kvm_machine
{
public:
	kvm_machine(kvm* kvm_inst, int fd);

	void set_user_memory_region(
			__u32 slot, __u32 flags, __u64 guest_phys_addr, __u64 memory_size, __u64 userspace_addr);
	void set_user_memory_region(struct kvm_userspace_memory_region& memreg);
	kvm_vcpu create_vcpu();
	virtual ~kvm_machine();

private:
	kvm* kvm_inst;
	int fd;
};

class kvm
{
public:
	kvm();

	kvm_machine create_vm();
	int get_mmap_size();
	virtual ~kvm();

private:
	int get_api_version();

	int fd;
};

#endif /* KVMPP_H */
