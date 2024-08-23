package=rustc
$(package)_version=1.77.1
$(package)_download_path=https://static.rust-lang.org/dist
$(package)_file_name=rustc-$($(package)_version)-src.tar.gz
$(package)_sha256_hash=ee106e4c569f52dba3b5b282b105820f86bd8f6b3d09c06b8dce82fb1bb3a4a1
$(package)_patches=config.toml
$(package)_freebsd_dependencies=freebsd_base native_binutils

define $(package)_set_vars
$(package)_stage_env_freebsd=AR_x86_64_unknown_freebsd=x86_64-unknown-freebsd11-ar
$(package)_stage_env_freebsd+=CC_x86_64_unknown_freebsd=x86_64-unknown-freebsd11-clang
$(package)_stage_env_freebsd+=CXX_x86_64_unknown_freebsd=x86_64-unknown-freebsd11-clang++
endef

define $(package)_config_cmds
endef

# Remove blobs from source
# TODO: script here could be less messy

define $(package)_preprocess_cmds
  rm -rf src/llvm-project && \
  find . -type f -regex ".*\.\(a\|dll\|exe\|lib\)$$$$" -delete && \
  find . -type f -name ".cargo-checksum.json" -print0 | xargs -0 -I% sh -c 'echo "{\"files\":{}}" > "%"' && \
  find . -type f -name "Cargo.lock" -delete && \
  sed -i 's/args.append("--frozen")/pass/g' src/bootstrap/bootstrap.py && \
  sed -i 's/cargo.arg("--frozen");//g' src/bootstrap/src/core/builder.rs && \
  cp $($(package)_patch_dir)/config.toml . && \
  sed -i "s/TARGET/${RUST_TARGET}/g" config.toml && \
  sed -i "s#PREFIX#$($(package)_staging_prefix_dir)#g" config.toml
endef

define $(package)_stage_cmds
  python3 ./x.py install
endef
