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
    src/quarantine.cpp
    src/replay_ledger.cpp
    src/isolation.cpp
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

# ADR 004 de-risking spike: proves libmnl/libnftnl netlink calls work before
# the isolation helper is built on top of them. Standalone, not linked into
# panopticon-linux-core or the agent binary. Only built when both libraries
# are actually available (Linux-only; CI installs them explicitly).
find_package(PkgConfig QUIET)
if(PkgConfig_FOUND)
    pkg_check_modules(LIBMNL QUIET libmnl)
    pkg_check_modules(LIBNFTNL QUIET libnftnl)
endif()
if(LIBMNL_FOUND AND LIBNFTNL_FOUND)
    add_executable(isolation-namespace-spike tests/e2e/isolation_namespace_spike.cpp)
    target_compile_features(isolation-namespace-spike PRIVATE cxx_std_20)
    target_include_directories(isolation-namespace-spike PRIVATE ${LIBMNL_INCLUDE_DIRS} ${LIBNFTNL_INCLUDE_DIRS})
    target_link_libraries(isolation-namespace-spike PRIVATE ${LIBMNL_LIBRARIES} ${LIBNFTNL_LIBRARIES})
    target_link_directories(isolation-namespace-spike PRIVATE ${LIBMNL_LIBRARY_DIRS} ${LIBNFTNL_LIBRARY_DIRS})

    # The privileged isolation helper (ADR 004). Deliberately its own
    # executable, not linked into panopticon-linux-core or the agent binary
    # -- CAP_NET_ADMIN never reaches the unprivileged main agent process.
    # identity.cpp is linked directly (not the whole panopticon-linux-core)
    # for is_valid_identifier() -- deliberately not pulling libcurl or any
    # other core-library dependency into this minimal privileged process.
    add_executable(panopticon-isolation-helper src/isolation_helper_main.cpp src/isolation_ruleset.cpp src/isolation.cpp src/identity.cpp)
    target_include_directories(panopticon-isolation-helper PRIVATE include ${LIBMNL_INCLUDE_DIRS} ${LIBNFTNL_INCLUDE_DIRS})
    target_compile_features(panopticon-isolation-helper PRIVATE cxx_std_20)
    target_link_libraries(panopticon-isolation-helper PRIVATE ${LIBMNL_LIBRARIES} ${LIBNFTNL_LIBRARIES})
    target_link_directories(panopticon-isolation-helper PRIVATE ${LIBMNL_LIBRARY_DIRS} ${LIBNFTNL_LIBRARY_DIRS})
    if(NOT MSVC)
        target_compile_options(panopticon-isolation-helper PRIVATE -Wall -Wextra -Wpedantic -Werror)
    endif()
    install(TARGETS panopticon-isolation-helper RUNTIME DESTINATION bin)
    install(FILES systemd/panopticon-isolation-helper.service DESTINATION lib/systemd/system)

    add_executable(isolation-client-tool tests/e2e/isolation_client_tool.cpp src/isolation.cpp src/identity.cpp)
    target_include_directories(isolation-client-tool PRIVATE include)
    target_compile_features(isolation-client-tool PRIVATE cxx_std_20)
endif()
