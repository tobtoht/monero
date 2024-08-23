package=fcmp_pp_rust
$(package)_version=0.0.0
$(package)_download_path=
$(package)_file_name=fcmp_pp_rust.tar.gz
$(package)_sha256_hash=1fd2eaab44b4f7363df8a18897f17ce4728506b8c52c5590f9d634a9000a83fe
$(package)_dependencies=fcmp_pp_rust_deps rustc
$(package)_patches=cargo.config

# TODO: Unused, exists for testing purposes, delete later.

define $(package)_config_cmds
  mkdir -p /home/user/.cargo && \
  cp $($(package)_patch_dir)/cargo.config /home/user/.cargo/config && \
  sed -i "s/TARGET/${HOST}/g" /home/user/.cargo/config
endef

define $(package)_build_cmds
    RUSTC="/monero/contrib/depends/${HOST}/native/bin/rustc" cargo build --target ${RUST_TARGET} --release
endef

define $(package)_stage_cmds
    mkdir -p $($(package)_staging_prefix_dir)/lib/ && \
    cp ./target/${RUST_TARGET}/release/libfcmp_pp_rust.* $($(package)_staging_prefix_dir)/lib/
endef
