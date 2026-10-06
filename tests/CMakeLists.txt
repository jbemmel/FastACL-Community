# SPDX-License-Identifier: Apache-2.0
find_package(Threads REQUIRED)

foreach(test_name bloomfilter bloom_config)
  add_executable(test_${test_name}
    test_${test_name}.c
    ${PROJECT_SOURCE_DIR}/src/plugins/fastacl/members_only/bloomfilter.c)
  target_compile_options(test_${test_name} PRIVATE -UNDEBUG -Wall -Wextra)
  target_link_libraries(test_${test_name} PRIVATE m Threads::Threads)
  add_test(NAME ${test_name} COMMAND test_${test_name})
endforeach()

# VPP development packages may provide headers and dangling library symlinks
# without the runtime packages. Keep standalone tests usable in that setup.
set(FASTACL_TEST_VPP_LIBRARY_DIR "" CACHE PATH "Optional VPP runtime library directory for CLI tests")
find_library(FASTACL_TEST_VLIB NAMES vlib HINTS ${FASTACL_TEST_VPP_LIBRARY_DIR})
find_library(FASTACL_TEST_VNET NAMES vnet HINTS ${FASTACL_TEST_VPP_LIBRARY_DIR})
find_library(FASTACL_TEST_VPPINFRA NAMES vppinfra HINTS ${FASTACL_TEST_VPP_LIBRARY_DIR})
if(EXISTS "${FASTACL_TEST_VLIB}" AND EXISTS "${FASTACL_TEST_VNET}" AND EXISTS "${FASTACL_TEST_VPPINFRA}")
  add_executable(test_members_only_cli test_members_only_cli.c
    ${PROJECT_SOURCE_DIR}/src/plugins/fastacl/members_only/bloomfilter.c)
  target_compile_options(test_members_only_cli PRIVATE -UNDEBUG)
  target_link_libraries(test_members_only_cli PRIVATE
    ${FASTACL_TEST_VNET} ${FASTACL_TEST_VLIB} ${FASTACL_TEST_VPPINFRA} m)
  add_test(NAME members_only_cli COMMAND test_members_only_cli)
else()
  message(STATUS "VPP runtime libraries unavailable: skipping members-only CLI harness")
endif()
