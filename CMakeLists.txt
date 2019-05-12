cmake_minimum_required(VERSION 3.0.0)
project(SuperFunkyChat VERSION 1.0.1 DESCRIPTION "Superfunkychat dissector")

find_package(Wireshark CONFIG REQUIRED)
if(NOT Wireshark_PLUGINS_ENABLED)
	message(FATAL_ERROR "Wireshark was compiled without support for plugins")
endif()


#  set_module_info(SuperFunkyChat 0 0 0 0)
add_library(SuperFunkyChat MODULE superfunkychat.c)

set_target_properties(SuperFunkyChat PROPERTIES PREFIX "" DEFINE_SYMBOL "")
target_link_libraries(SuperFunkyChat epan)

install(TARGETS SuperFunkyChat
	LIBRARY DESTINATION "${Wireshark_PLUGIN_INSTALL_DIR}/epan" NAMELINK_SKIP
)


