# Turns a binary file into a C++ translation unit defining
#   extern const unsigned char <SYMBOL>[];  extern const std::size_t <SYMBOL>_size;
# Run in script mode:
#   cmake -DINPUT=<file> -DOUTPUT=<cpp> -DSYMBOL=<name> -P embed_binary.cmake
# Used to embed the compiled eBPF object into the sensor (ADR 006), so nothing has to be
# installed next to the binary and nothing is read from disk at run time.
if(NOT INPUT OR NOT OUTPUT OR NOT SYMBOL)
    message(FATAL_ERROR "embed_binary.cmake needs -DINPUT, -DOUTPUT and -DSYMBOL")
endif()

file(READ "${INPUT}" contents HEX)
string(LENGTH "${contents}" hex_length)
math(EXPR byte_count "${hex_length} / 2")
string(REGEX REPLACE "([0-9a-f][0-9a-f])" "0x\\1," bytes "${contents}")
file(WRITE "${OUTPUT}"
    "// Generated from ${INPUT}; do not edit.\n"
    "#include <cstddef>\n"
    "extern const unsigned char ${SYMBOL}[] = {${bytes}};\n"
    "extern const std::size_t ${SYMBOL}_size = ${byte_count}U;\n")
