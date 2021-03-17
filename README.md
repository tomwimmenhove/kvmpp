# KVMPP

A simple C++ wrapper for Linux's KVM API. Largely (especially the test.cpp example) based on https://github.com/dpw/kvm-hello-world

## Building and running the example
```
git clone https://github.com/tomwimmenhove/kvmpp
cd kvmpp/example
g++ -o example ../src/kvmpp.cpp test.cpp
./example
```
