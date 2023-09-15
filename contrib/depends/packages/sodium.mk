package=sodium
$(package)_version=1.0.19
$(package)_download_path=https://download.libsodium.org/libsodium/releases/
$(package)_file_name=libsodium-$($(package)_version).tar.gz
$(package)_sha256_hash=b8abea95ea00a22d63b1634c5f2c9c1316715b9cac6ea63168d5e962b89a197b
$(package)_patches=disable-glibc-getrandom-getentropy.patch fix-whitespace.patch

define $(package)_set_vars
$(package)_config_opts=--enable-static --disable-shared
$(package)_config_opts+=--prefix=$(host_prefix)
endef

define $(package)_preprocess_cmds
  patch -p1 < $($(package)_patch_dir)/disable-glibc-getrandom-getentropy.patch &&\
  autoconf &&\
  patch -p1 < $($(package)_patch_dir)/fix-whitespace.patch
endef

define $(package)_config_cmds
  $($(package)_autoconf) AR_FLAGS=$($(package)_arflags)
endef

define $(package)_build_cmds
  $(MAKE)
endef

define $(package)_stage_cmds
  $(MAKE) DESTDIR=$($(package)_staging_dir) install
endef

define $(package)_postprocess_cmds
  rm lib/*.la
endef

