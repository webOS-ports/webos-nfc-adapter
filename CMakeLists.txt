# @@@LICENSE
#
# Copyright (c) 2026 Herman van Hazendonk <github.com@herrie.org>
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
# http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
#
# LICENSE@@@

cmake_minimum_required(VERSION 2.8.7)

project(webos-nfc-adapter C)

include(webOS/webOS)
webos_modules_init(1 0 0 QUALIFIER RC2)
webos_component(0 1 0)

include(FindPkgConfig)

pkg_check_modules(GLIB2 REQUIRED glib-2.0)
include_directories(${GLIB2_INCLUDE_DIRS})
webos_add_compiler_flags(ALL ${GLIB2_CFLAGS})

pkg_check_modules(GIO2 REQUIRED gio-2.0)
include_directories(${GIO2_INCLUDE_DIRS})
webos_add_compiler_flags(ALL ${GIO2_CFLAGS})

pkg_check_modules(GIO-UNIX REQUIRED gio-unix-2.0)
include_directories(${GIO-UNIX_INCLUDE_DIRS})
webos_add_compiler_flags(ALL ${GIO-UNIX_CFLAGS_OTHER})

pkg_check_modules(GOBJECT2 REQUIRED gobject-2.0)
include_directories(${GOBJECT2_INCLUDE_DIRS})
webos_add_compiler_flags(ALL ${GOBJECT2_CFLAGS})

pkg_check_modules(LUNASERVICE2 REQUIRED luna-service2)
include_directories(${LUNASERVICE2_INCLUDE_DIRS})
webos_add_compiler_flags(ALL ${LUNASERVICE2_CFLAGS})

pkg_check_modules(PBNJSON_C REQUIRED pbnjson_c)
include_directories(${PBNJSON_C_INCLUDE_DIRS})
webos_add_compiler_flags(ALL ${PBNJSON_C_CFLAGS_OTHER})

# BAC (passport/eID) key derivation and secure messaging: 3DES, SHA-1
pkg_check_modules(LIBCRYPTO REQUIRED libcrypto)
include_directories(${LIBCRYPTO_INCLUDE_DIRS})
webos_add_compiler_flags(ALL ${LIBCRYPTO_CFLAGS_OTHER})

find_program(GDBUS_CODEGEN_EXECUTABLE NAMES gdbus-codegen DOC "gdbus-codegen executable")
if(NOT GDBUS_CODEGEN_EXECUTABLE)
	message(FATAL_ERROR "Executable gdbus-codegen not found")
endif(GDBUS_CODEGEN_EXECUTABLE)

set(GDBUS_IF_DIR ${WEBOS_BINARY_CONFIGURED_DIR}/src)

file (MAKE_DIRECTORY ${GDBUS_IF_DIR})

execute_process(COMMAND ${GDBUS_CODEGEN_EXECUTABLE} --c-namespace NfcdInterface --generate-c-code
						${GDBUS_IF_DIR}/nfcd-interface --interface-prefix org.sailfishos.nfc.
						${CMAKE_CURRENT_SOURCE_DIR}/files/xml/nfcd.xml
						RESULT_VARIABLE codegen_failed)
if(codegen_failed)
		message(FATAL_ERROR "Error in generating code for nfcd interface using gdbus-codegen")
endif()

include_directories(src ${GDBUS_IF_DIR})
file(GLOB SOURCE_FILES src/*.c ${GDBUS_IF_DIR}/nfcd-interface.c)

webos_add_compiler_flags(ALL -Wall)
webos_add_linker_options(ALL --no-undefined)

add_executable(webos-nfc-adapter ${SOURCE_FILES})
target_link_libraries(webos-nfc-adapter
    ${GLIB2_LDFLAGS} ${LUNASERVICE2_LDFLAGS} ${PBNJSON_C_LDFLAGS}
    ${GIO2_LDFLAGS} ${GIO-UNIX_LDFLAGS} ${GOBJECT2_LDFLAGS} ${LIBCRYPTO_LDFLAGS}
    rt pthread)

webos_build_daemon()
webos_build_system_bus_files()
