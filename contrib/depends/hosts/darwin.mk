OSX_MIN_VERSION=10.8
LD64_VERSION=609
ifeq (aarch64, $(host_arch))
CC_target=arm64-apple-$(host_os)
else
CC_target=$(host)
endif

OSX_SDK=$(host_prefix)/native/SDK

darwin_CC=clang -target $(CC_target) -mmacosx-version-min=$(OSX_MIN_VERSION) --sysroot $(host_prefix)/native/SDK/ -mlinker-version=$(LD64_VERSION) -B$(host_prefix)/native/bin/$(host)-
darwin_CXX=clang++ -target $(CC_target) -mmacosx-version-min=$(OSX_MIN_VERSION) --sysroot $(host_prefix)/native/SDK/ -mlinker-version=$(LD64_VERSION) -stdlib=libc++ -B$(host_prefix)/native/bin/$(host)-

cctools_TOOLS=AR RANLIB STRIP NM LIBTOOL OTOOL INSTALL_NAME_TOOL DSYMUTIL

# Make-only lowercase function
lc = $(subst A,a,$(subst B,b,$(subst C,c,$(subst D,d,$(subst E,e,$(subst F,f,$(subst G,g,$(subst H,h,$(subst I,i,$(subst J,j,$(subst K,k,$(subst L,l,$(subst M,m,$(subst N,n,$(subst O,o,$(subst P,p,$(subst Q,q,$(subst R,r,$(subst S,s,$(subst T,t,$(subst U,u,$(subst V,v,$(subst W,w,$(subst X,x,$(subst Y,y,$(subst Z,z,$1))))))))))))))))))))))))))

# For well-known tools provided by cctools, make sure that their well-known
# variable is set to the full path of the tool, just like how AC_PATH_{TOO,PROG}
# would.
$(foreach TOOL,$(cctools_TOOLS),$(eval darwin_$(TOOL) = $$(build_prefix)/bin/$$(host)-$(call lc,$(TOOL))))

darwin_CFLAGS=-pipe
darwin_CXXFLAGS=$(darwin_CFLAGS)
darwin_ARFLAGS=cr

darwin_release_CFLAGS=-O1
darwin_release_CXXFLAGS=$(darwin_release_CFLAGS)

darwin_debug_CFLAGS=-O1
darwin_debug_CXXFLAGS=$(darwin_debug_CFLAGS)

darwin_native_toolchain=native_cctools darwin_sdk

darwin_cmake_system=Darwin