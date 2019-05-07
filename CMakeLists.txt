cmake_minimum_required(VERSION 3.0.0)
project(SuperFunkyChat VERSION 1.0.1 DESCRIPTION "mylib description")
include(FindPkgConfig)
find_package(PkgConfig)
#  set_module_info(SuperFunkyChat 0 0 0 0)
add_library(SuperFunkyChat SHARED superfunkychat.c)
pkg_check_modules(WIRESHARK REQUIRED wireshark)
target_link_libraries(SuperFunkyChat ${WIRESHARK_LIBRARIES})
target_include_directories(SuperFunkyChat PUBLIC ${WIRESHARK_INCLUDE_DIRS})
target_compile_options(SuperFunkyChat PUBLIC ${WIRESHARK_CFLAGS_OTHER})


