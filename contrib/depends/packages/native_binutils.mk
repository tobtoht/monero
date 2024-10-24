package=native_binutils
$(package)_version=2.40
$(package)_download_path=https://ftp.gnu.org/gnu/binutils
$(package)_file_name=binutils-$($(package)_version).tar.bz2
$(package)_sha256_hash=f8298eb153a4b37d112e945aa5cb2850040bcf26a3ea65b5a715c83afe05e48a

define $(package)_config_cmds
  $($(package)_autoconf) --target $(host)
endef

# MAKEINFO=true : skip documentation generation

define $(package)_build_cmds
  $(MAKE) MAKEINFO=true
endef

define $(package)_stage_cmds
  $(MAKE) MAKEINFO=true DESTDIR=$($(package)_staging_dir) install
endef

define $(package)_postprocess_cmds
  mv bin/riscv64-linux-gnu-ld bin/real-ld
endef
