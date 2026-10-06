# SPDX-License-Identifier: Apache-2.0
# Copyright (c) 2026 FastNetMon (fastnetmon.com)

add_vpp_plugin(fastacl
  SOURCES
  fastacl.c
  fastacl_api.c
  fastacl_cli.c
  fastacl_counters.c
  fastacl_psample.c
  fastacl_format.c
  fastacl_rule.c
  fastacl_tss.c
  fastacl_node.c
  members_only/bloomfilter.c
  members_only/members_only.c

  MULTIARCH_SOURCES
  fastacl_node.c

  API_FILES
  fastacl.api

  INSTALL_HEADERS
  fastacl.h
  fastacl_format.h
  fastacl_types.h
  fastacl_tss.h
  fastacl_match_inline.h
  fastacl_flowspec.h
  members_only/bloomfilter.h
  members_only/members_only.h
)

vpp_find_path(LIBNL3_INCLUDE_DIR NAMES libnl3/netlink/genl/ctrl.h)
if(NOT LIBNL3_INCLUDE_DIR)
  message(FATAL_ERROR
    "libnl-3 headers not found — install libnl-3-dev / libnl3-devel "
    "(VPP's own `make install-dep` installs them)")
endif()
vpp_plugin_find_library(fastacl LIBNL3_LIB libnl-3.so)
vpp_plugin_find_library(fastacl LIBNL3_GENL_LIB libnl-genl-3.so)
include_directories(${LIBNL3_INCLUDE_DIR}/libnl3)
target_link_libraries(fastacl_plugin ${LIBNL3_LIB} ${LIBNL3_GENL_LIB} m)

# Production mode is CMake's Release configuration. VPP creates separate object
# targets for CPU variants; they must receive the same optimization policy.
option(FASTACL_PRODUCTION_OPTIMIZATION
  "Enable aggressive plugin optimization in Release builds" ON)

if(FASTACL_PRODUCTION_OPTIMIZATION)
  if(CMAKE_C_COMPILER_ID MATCHES "GNU|Clang")
    get_property(fastacl_build_targets DIRECTORY PROPERTY BUILDSYSTEM_TARGETS)
    set(fastacl_production_targets fastacl_plugin)
    foreach(fastacl_target IN LISTS fastacl_build_targets)
      get_target_property(fastacl_target_type ${fastacl_target} TYPE)
      if(fastacl_target MATCHES "^fastacl_plugin_" AND
         fastacl_target_type STREQUAL "OBJECT_LIBRARY")
        list(APPEND fastacl_production_targets ${fastacl_target})
      endif()
    endforeach()
    foreach(fastacl_target IN LISTS fastacl_production_targets)
      target_compile_options(${fastacl_target} PRIVATE
        $<$<CONFIG:Release>:-O3>
        $<$<CONFIG:Release>:-funroll-loops>
        $<$<CONFIG:Release>:-fomit-frame-pointer>)
    endforeach()

    if(CMAKE_BUILD_TYPE STREQUAL "Release" OR
       "Release" IN_LIST CMAKE_CONFIGURATION_TYPES)
      include(CheckIPOSupported)
      check_ipo_supported(RESULT fastacl_ipo_supported
        OUTPUT fastacl_ipo_error LANGUAGES C)
      if(fastacl_ipo_supported)
        foreach(fastacl_target IN LISTS fastacl_production_targets)
          set_property(TARGET ${fastacl_target}
            PROPERTY INTERPROCEDURAL_OPTIMIZATION_RELEASE TRUE)
        endforeach()
        message(STATUS "FastACL Release optimization: -O3, loop unrolling, LTO")
      else()
        message(WARNING "FastACL Release LTO unavailable: ${fastacl_ipo_error}")
      endif()
    endif()
  else()
    message(STATUS "FastACL: using compiler defaults for ${CMAKE_C_COMPILER_ID}")
  endif()
endif()
