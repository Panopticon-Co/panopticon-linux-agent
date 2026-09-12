cmake_minimum_required(VERSION 3.20)

project(panopticon_linux_agent VERSION 0.1.0 LANGUAGES CXX)

include(CTest)

option(PANOPTICON_ENABLE_ASAN "Enable AddressSanitizer" OFF)
option(PANOPTICON_ENABLE_UBSAN "Enable UndefinedBehaviorSanitizer" OFF)

add_library(panopticon-linux-core STATIC
    src/identity.cpp
    src/spool.cpp
    src/command.cpp
    src/procfs.cpp
    src/event.cpp
    src/network.cpp
    src/config.cpp
    src/transport.cpp
    src/file_collection.cpp
    src/audit.cpp
    src/health.cpp
    src/host.cpp
)
target_include_directories(panopticon-linux-core PUBLIC include)
target_compile_features(panopticon-linux-core PUBLIC cxx_std_20)
find_package(CURL QUIET)
if(CURL_FOUND)
    target_link_libraries(panopticon-linux-core PUBLIC CURL::libcurl)
    target_compile_definitions(panopticon-linux-core PRIVATE PANOPTICON_HAVE_CURL=1)
endif()

if(MSVC)
    target_compile_options(panopticon-linux-core PRIVATE /W4 /WX /permissive- /EHsc /utf-8)
else()
    target_compile_options(panopticon-linux-core PRIVATE -Wall -Wextra -Wpedantic -Werror)
endif()

if(CMAKE_CXX_COMPILER_ID MATCHES "Clang|GNU")
    if(PANOPTICON_ENABLE_ASAN)
        target_compile_options(panopticon-linux-core PUBLIC -fsanitize=address -fno-omit-frame-pointer)
        target_link_options(panopticon-linux-core PUBLIC -fsanitize=address)
    endif()
    if(PANOPTICON_ENABLE_UBSAN)
        target_compile_options(panopticon-linux-core PUBLIC -fsanitize=undefined -fno-omit-frame-pointer)
        target_link_options(panopticon-linux-core PUBLIC -fsanitize=undefined)
    endif()
endif()

add_executable(panopticon-linux-agent src/main.cpp)
target_link_libraries(panopticon-linux-agent PRIVATE panopticon-linux-core)

if(BUILD_TESTING)
    add_executable(panopticon-linux-core-tests tests/core_tests.cpp)
    target_link_libraries(panopticon-linux-core-tests PRIVATE panopticon-linux-core)
    add_test(NAME panopticon-linux-core-tests COMMAND panopticon-linux-core-tests)
endif()

install(TARGETS panopticon-linux-agent RUNTIME DESTINATION bin)
install(FILES systemd/panopticon-linux-agent.service DESTINATION lib/systemd/system)
