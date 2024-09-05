package=rustc
$(package)_version=1.77.1
$(package)_download_path=https://static.rust-lang.org/dist
$(package)_file_name=rustc-$($(package)_version)-src.tar.gz
$(package)_sha256_hash=ee106e4c569f52dba3b5b282b105820f86bd8f6b3d09c06b8dce82fb1bb3a4a1
$(package)_patches=deblob.sh

define $(package)_preprocess_cmds
  bash $($(package)_patch_dir)/deblob.sh
endef

define $(package)_stage_cmds
  mkdir -p $($(package)_staging_prefix_dir)/rust &&\
  mv * $($(package)_staging_prefix_dir)/rust
endef
