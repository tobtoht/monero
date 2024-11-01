#!/usr/bin/env bash
export LC_ALL=C
set -e -o pipefail

check_string() {
    local binary="$1"
    local string="$2"

    if strings "$binary" | grep -q "${string}"; then
        echo "ERR: ${binary} contains unexpected string: \"${string}\""
        exit 1
    fi
}

check_rpath() {
    local binary="$1"

    rpath=$(patchelf --print-rpath "$binary")
    if [ ! -z "$rpath" ]; then
        echo "ERR: ${binary} contains unexpected rpath: ${rpath}"
        exit 1
    fi
}

check_interpreter() {
    local binary="$1"
    local allowed_interpreter="$2"

    interpreter=$(patchelf --print-interpreter "$binary")
    if [ "$interpreter" != "$allowed_interpreter" ]; then
        echo "ERR: ${binary} contains unexpected interpreter: ${interpreter}, should be: ${allowed_interpreter}"
        exit 1
    fi
}

check_libraries() {
    local binary="$1"
    shift
    allowed_dynamic_libraries=("$@")

    dynamic_libraries=($(objdump -p "$binary" | grep "NEEDED" | awk '{print $2}'))

    for library in "${dynamic_libraries[@]}"; do
        found=0
        for allowed_library in "${allowed_dynamic_libraries[@]}"; do
            if [[ "$library" == "$allowed_library" ]]; then
                found=1
                break
            fi
        done
        if [ "$found" -eq 0 ]; then
            echo "ERR: ${binary} links against unexpected library: ${library}"
            exit 1
        fi
    done
}

check_glibc() {
    local binary="$1"
    local major_max="$2"
    local minor_max="$3"

    # We don't have access to perl regexp (-P) here
    required_glibc=$(objdump -T "$binary" | grep -o -E 'GLIBC_[0-9]\.[0-9]{1,}' | sort -V | tail -n 1 | sed 's/^GLIBC_//')

    major="${required_glibc%.*}"
    minor="${required_glibc#*.}"

    failure=0
    if [[ "$major" -gt "$major_max" ]]; then
        failure=1
    fi
    if [[ "$major" -eq "$major_max" && "$minor" -gt "$minor_max" ]]; then
        failure=1
    fi

    if [[ "$failure" -eq 1 ]]; then
        echo "ERR: ${binary} glibc version too recent: ${required_glibc}, maximum allowed: ${major_max}.${minor_max}"
        exit 1
    fi
}
