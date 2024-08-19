package=fcmp_pp_rust_deps
$(package)_version=0.0.0
$(package)_download_path=https://featherwallet.org/files/sources
$(package)_file_name=fcmp_pp_rust-$($(package)_version)-deps.tar.gz
$(package)_sha256_hash=b25a4b18e18923faf3e8e8508dd72154ed4824a5a50d82b1cec7884fd850710d

define $(package)_stage_cmds
  mkdir -p $($(package)_staging_prefix_dir)/cargo &&\
  mv * $($(package)_staging_prefix_dir)/cargo
endef
