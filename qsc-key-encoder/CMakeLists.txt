cmake_minimum_required(VERSION 3.5)
project(qsc-key-encoder LANGUAGES C VERSION 0.1.0)

set(CMAKE_C_STANDARD 99)

set (
    LIBRARY_ENCODING_FILES
    src/encoding_qsc.c
    src/encoding_kyber.c
    src/encoding_dilithium.c
    src/encoding_falcon.c
    src/encoding_sphincsplus.c
    src/encoding_asn1.c
)

set(CMAKE_C_FLAGS_ASAN
    "-fsanitize=address -fno-optimize-sibling-calls -fsanitize-address-use-after-scope -fno-omit-frame-pointer -g -O1"
    CACHE STRING "Flags used by the C compiler during AddressSanitizer builds."
    FORCE)

include_directories(include)

add_library(qsc_key_encoder STATIC ${LIBRARY_ENCODING_FILES})

install(TARGETS qsc_key_encoder DESTINATION lib)
install(FILES include/qsc_encoding.h DESTINATION include)

include (CTest)

enable_testing()

add_subdirectory(test)
