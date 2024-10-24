native_packages:=fcmp_pp_rust_deps
packages:=boost openssl zeromq expat unbound sodium

hardware_packages := hidapi protobuf libusb
hardware_native_packages := native_protobuf

android_native_packages = android_ndk $(hardware_native_packages)
android_packages = ncurses readline protobuf

darwin_native_packages = $(hardware_native_packages)
darwin_packages = ncurses readline $(hardware_packages)

# not really native...
freebsd_native_packages = freebsd_base $(hardware_native_packages)
freebsd_packages = ncurses readline protobuf libusb

linux_packages = eudev ncurses readline $(hardware_packages)
linux_native_packages = $(hardware_native_packages)

ifeq ($(build_tests),ON)
packages += gtest
endif

mingw32_packages = $(hardware_packages)
mingw32_native_packages = $(hardware_native_packages)

ifneq ($(build_os),darwin)
darwin_native_packages += darwin_sdk
endif

ifeq ($(GUIX_ENVIRONMENT),)
ifeq ($(host_arch),riscv64)
native_packages += native_binutils
endif
ifeq ($(host_os),mingw32)
native_packages += native_binutils
endif
endif
