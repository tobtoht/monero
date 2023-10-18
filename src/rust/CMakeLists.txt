# Copyright (c) 2016-2023, The Monero Project
#
# All rights reserved.
#
# Redistribution and use in source and binary forms, with or without modification, are
# permitted provided that the following conditions are met:
#
# 1. Redistributions of source code must retain the above copyright notice, this list of
#    conditions and the following disclaimer.
#
# 2. Redistributions in binary form must reproduce the above copyright notice, this list
#    of conditions and the following disclaimer in the documentation and/or other
#    materials provided with the distribution.
#
# 3. Neither the name of the copyright holder nor the names of its contributors may be
#    used to endorse or promote products derived from this software without specific
#    prior written permission.
#
# THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND ANY
# EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF
# MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL
# THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
# SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO,
# PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
# INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT,
# STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF
# THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.

if (CMAKE_BUILD_TYPE STREQUAL "Debug")
  set(CARGO_CMD cargo build)
  set(TARGET_DIR "debug")
else ()
  set(CARGO_CMD cargo build --release)
  set(TARGET_DIR "release")
endif ()

set(MONERO_RUST_CXX "${CMAKE_CURRENT_BINARY_DIR}/monero_rust.cc")
set(MONERO_RUST_HEADER_DIR "${MONERO_GENERATED_HEADERS_DIR}/rust")
set(MONERO_RUST_HEADER "${MONERO_RUST_HEADER_DIR}/monero_rust.h")

# Removing OUTPUT files makes sure custom command runs every time
file(REMOVE_RECURSE "${MONERO_RUST_CXX}")
file(REMOVE_RECURSE "${MONERO_RUST_HEADER_DIR}")
file(MAKE_DIRECTORY "${MONERO_RUST_HEADER_DIR}")

add_custom_command(
  COMMENT "Building monero rust"
  OUTPUT ${MONERO_RUST_CXX} ${MONERO_RUST_HEADER}
  COMMAND CARGO_TARGET_DIR=${CMAKE_CURRENT_BINARY_DIR} ${CARGO_CMD}
  COMMAND cp ${CMAKE_CURRENT_BINARY_DIR}/cxxbridge/monero_rust/src/lib.rs.cc ${MONERO_RUST_CXX}
  COMMAND cp ${CMAKE_CURRENT_BINARY_DIR}/cxxbridge/monero_rust/src/lib.rs.h ${MONERO_RUST_HEADER}
  WORKING_DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR}
  VERBATIM
)

set(monero_rust_sources ${MONERO_RUST_CXX})

monero_find_all_headers(monero_rust_headers, "${MONERO_RUST_HEADER}")

monero_add_library(monero_rust
  ${monero_rust_sources}
  ${monero_rust_headers})

set(MONERO_RUST_LIB "${CMAKE_CURRENT_BINARY_DIR}/${TARGET_DIR}/libmonero_rust.a")
target_link_libraries(monero_rust dl ${MONERO_RUST_LIB})
