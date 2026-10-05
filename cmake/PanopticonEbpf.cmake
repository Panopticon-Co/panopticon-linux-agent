# eBPF process provider build support (ADR 006).
#
# Sets PANOPTICON_EBPF_ENABLED and, when enabled, defines:
#   panopticon-libbpf          static libbpf built from the pinned third_party/libbpf submodule
#   PANOPTICON_EBPF_OBJECT_CPP generated C++ source embedding the compiled BPF object
# When anything required is missing it explains why and leaves the provider disabled: the
# sensor still builds and runs, with netlink_proc and procfs providing process telemetry.
option(PANOPTICON_ENABLE_EBPF "Build the eBPF process provider (needs clang, libelf, zlib)" ON)
set(PANOPTICON_EBPF_ENABLED OFF)

function(panopticon_ebpf_disabled reason)
    message(STATUS "eBPF provider disabled: ${reason}")
endfunction()

if(NOT PANOPTICON_ENABLE_EBPF)
    panopticon_ebpf_disabled("PANOPTICON_ENABLE_EBPF=OFF")
    return()
endif()

if(CMAKE_SYSTEM_PROCESSOR MATCHES "^(x86_64|AMD64)$")
    set(PANOPTICON_BPF_ARCH x86)
    set(PANOPTICON_VMLINUX_DIR x86_64)
elseif(CMAKE_SYSTEM_PROCESSOR MATCHES "^(aarch64|arm64)$")
    set(PANOPTICON_BPF_ARCH arm64)
    set(PANOPTICON_VMLINUX_DIR aarch64)
else()
    panopticon_ebpf_disabled("unsupported architecture ${CMAKE_SYSTEM_PROCESSOR}")
    return()
endif()

set(PANOPTICON_VMLINUX_H "${CMAKE_CURRENT_SOURCE_DIR}/bpf/vmlinux/${PANOPTICON_VMLINUX_DIR}/vmlinux.h")
if(NOT EXISTS "${PANOPTICON_VMLINUX_H}")
    panopticon_ebpf_disabled("no vmlinux.h for ${PANOPTICON_VMLINUX_DIR} (generate with: bpftool btf dump file /sys/kernel/btf/vmlinux format c)")
    return()
endif()
if(NOT EXISTS "${CMAKE_CURRENT_SOURCE_DIR}/third_party/libbpf/src/libbpf.c")
    panopticon_ebpf_disabled("third_party/libbpf is empty (git submodule update --init)")
    return()
endif()

find_program(PANOPTICON_BPF_CLANG NAMES clang clang-18 clang-17 clang-16 clang-15 clang-14 clang-13 clang-12)
find_program(PANOPTICON_LLVM_STRIP NAMES llvm-strip llvm-strip-18 llvm-strip-17 llvm-strip-16 llvm-strip-15 llvm-strip-14)
find_library(PANOPTICON_ELF_LIBRARY NAMES elf)
find_path(PANOPTICON_ELF_INCLUDE_DIR NAMES libelf.h gelf.h)
find_package(ZLIB QUIET)
if(NOT PANOPTICON_BPF_CLANG)
    panopticon_ebpf_disabled("clang (>= 12) not found")
    return()
endif()
if(NOT PANOPTICON_ELF_LIBRARY OR NOT PANOPTICON_ELF_INCLUDE_DIR)
    panopticon_ebpf_disabled("libelf development files not found (libelf-dev / elfutils-libelf-devel)")
    return()
endif()
if(NOT ZLIB_FOUND)
    panopticon_ebpf_disabled("zlib development files not found (zlib1g-dev / zlib-devel)")
    return()
endif()

enable_language(C)

# ---- libbpf (static, from the pinned submodule) ------------------------------------------------
set(PANOPTICON_LIBBPF_DIR "${CMAKE_CURRENT_SOURCE_DIR}/third_party/libbpf")
set(PANOPTICON_LIBBPF_INCLUDE "${CMAKE_CURRENT_BINARY_DIR}/libbpf-include")
foreach(header bpf.h libbpf.h btf.h libbpf_common.h libbpf_legacy.h libbpf_version.h bpf_helpers.h
               bpf_helper_defs.h bpf_tracing.h bpf_endian.h bpf_core_read.h skel_internal.h usdt.bpf.h)
    configure_file("${PANOPTICON_LIBBPF_DIR}/src/${header}" "${PANOPTICON_LIBBPF_INCLUDE}/bpf/${header}" COPYONLY)
endforeach()

add_library(panopticon-libbpf STATIC
    ${PANOPTICON_LIBBPF_DIR}/src/bpf.c
    ${PANOPTICON_LIBBPF_DIR}/src/bpf_prog_linfo.c
    ${PANOPTICON_LIBBPF_DIR}/src/btf.c
    ${PANOPTICON_LIBBPF_DIR}/src/btf_dump.c
    ${PANOPTICON_LIBBPF_DIR}/src/btf_iter.c
    ${PANOPTICON_LIBBPF_DIR}/src/btf_relocate.c
    ${PANOPTICON_LIBBPF_DIR}/src/elf.c
    ${PANOPTICON_LIBBPF_DIR}/src/features.c
    ${PANOPTICON_LIBBPF_DIR}/src/gen_loader.c
    ${PANOPTICON_LIBBPF_DIR}/src/hashmap.c
    ${PANOPTICON_LIBBPF_DIR}/src/libbpf.c
    ${PANOPTICON_LIBBPF_DIR}/src/libbpf_errno.c
    ${PANOPTICON_LIBBPF_DIR}/src/libbpf_probes.c
    ${PANOPTICON_LIBBPF_DIR}/src/linker.c
    ${PANOPTICON_LIBBPF_DIR}/src/netlink.c
    ${PANOPTICON_LIBBPF_DIR}/src/nlattr.c
    ${PANOPTICON_LIBBPF_DIR}/src/relo_core.c
    ${PANOPTICON_LIBBPF_DIR}/src/ringbuf.c
    ${PANOPTICON_LIBBPF_DIR}/src/str_error.c
    ${PANOPTICON_LIBBPF_DIR}/src/strset.c
    ${PANOPTICON_LIBBPF_DIR}/src/usdt.c
    ${PANOPTICON_LIBBPF_DIR}/src/zip.c
)
set_target_properties(panopticon-libbpf PROPERTIES C_STANDARD 11 C_EXTENSIONS ON POSITION_INDEPENDENT_CODE ON)
# Vendored third-party code: built with its own warnings policy, not ours.
target_compile_options(panopticon-libbpf PRIVATE -w -fvisibility=hidden)
target_compile_definitions(panopticon-libbpf PRIVATE _LARGEFILE64_SOURCE _FILE_OFFSET_BITS=64 _GNU_SOURCE)
# libbpf's own kernel UAPI headers come first: the system's may predate the enums it uses.
target_include_directories(panopticon-libbpf PRIVATE
    ${PANOPTICON_LIBBPF_DIR}/include/uapi
    ${PANOPTICON_LIBBPF_DIR}/include
    ${PANOPTICON_LIBBPF_DIR}/src
    ${PANOPTICON_ELF_INCLUDE_DIR})
target_include_directories(panopticon-libbpf SYSTEM BEFORE INTERFACE
    ${PANOPTICON_LIBBPF_DIR}/include/uapi
    ${PANOPTICON_LIBBPF_INCLUDE})
target_link_libraries(panopticon-libbpf PUBLIC ${PANOPTICON_ELF_LIBRARY} ZLIB::ZLIB)

# ---- the BPF object, embedded into the sensor --------------------------------------------------
set(PANOPTICON_BPF_OBJECT "${CMAKE_CURRENT_BINARY_DIR}/panopticon.bpf.o")
set(PANOPTICON_BPF_STRIP_COMMAND ${CMAKE_COMMAND} -E true)
if(PANOPTICON_LLVM_STRIP)
    # Drop DWARF but keep .BTF/.BTF.ext, which CO-RE relocation needs.
    set(PANOPTICON_BPF_STRIP_COMMAND ${PANOPTICON_LLVM_STRIP} -g ${PANOPTICON_BPF_OBJECT})
endif()
add_custom_command(
    OUTPUT ${PANOPTICON_BPF_OBJECT}
    COMMAND ${PANOPTICON_BPF_CLANG} -g -O2 -target bpf -mcpu=v3 -Wall
            -D__TARGET_ARCH_${PANOPTICON_BPF_ARCH}
            -I${CMAKE_CURRENT_SOURCE_DIR}/bpf
            -I${CMAKE_CURRENT_SOURCE_DIR}/bpf/vmlinux/${PANOPTICON_VMLINUX_DIR}
            -I${PANOPTICON_LIBBPF_INCLUDE}
            -c ${CMAKE_CURRENT_SOURCE_DIR}/bpf/panopticon.bpf.c -o ${PANOPTICON_BPF_OBJECT}
    COMMAND ${PANOPTICON_BPF_STRIP_COMMAND}
    DEPENDS ${CMAKE_CURRENT_SOURCE_DIR}/bpf/panopticon.bpf.c
            ${CMAKE_CURRENT_SOURCE_DIR}/bpf/panopticon_events.h
            ${PANOPTICON_VMLINUX_H}
    COMMENT "Compiling eBPF programs (CO-RE, target ${PANOPTICON_BPF_ARCH})"
    VERBATIM)

set(PANOPTICON_EBPF_OBJECT_CPP "${CMAKE_CURRENT_BINARY_DIR}/panopticon_bpf_object.cpp")
add_custom_command(
    OUTPUT ${PANOPTICON_EBPF_OBJECT_CPP}
    COMMAND ${CMAKE_COMMAND} -DINPUT=${PANOPTICON_BPF_OBJECT} -DOUTPUT=${PANOPTICON_EBPF_OBJECT_CPP}
            -DSYMBOL=panopticon_bpf_object -P ${CMAKE_CURRENT_SOURCE_DIR}/cmake/embed_binary.cmake
    DEPENDS ${PANOPTICON_BPF_OBJECT} ${CMAKE_CURRENT_SOURCE_DIR}/cmake/embed_binary.cmake
    COMMENT "Embedding the eBPF object"
    VERBATIM)

set(PANOPTICON_EBPF_ENABLED ON)
message(STATUS "eBPF provider enabled: clang=${PANOPTICON_BPF_CLANG} arch=${PANOPTICON_BPF_ARCH} libbpf=${PANOPTICON_LIBBPF_DIR}")
