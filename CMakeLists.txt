cmake_minimum_required(VERSION 2.6.3)

project(ZeekPluginDpdk)
include(ZeekPlugin)
find_package(dpdk)

if ( dpdk_FOUND )

    if (dpdk_FOUND)
        set(DPDK_C_FLAGS "-march=native")
        set(DPDK_LIB dpdk rt m numa dl)
        set(CMAKE_C_FLAGS ${CMAKE_C_FLAGS} ${DPDK_C_FLAGS})
        include_directories(AFTER ${dpdk_INCLUDE_DIRS})
        link_directories(AFTER ${dpdk_LIBRARIES})
        set(PCAP_LINK_LIBRARIES ${PCAP_LINK_LIBRARIES} ${dpdk_LIBRARIES})
        set(PROJECT_SOURCE_LIST_C ${PROJECT_SOURCE_LIST_C} pcap-dpdk.c)
        zeek_plugin_begin(Zeek Dpdk)
        zeek_plugin_cc(src/Plugin.cc)
        zeek_plugin_cc(src/Dpdk.cc)
        zeek_plugin_link_library(${dpdk_LIBRARIES})
        zeek_plugin_dist_files(README.md VERSION)
        zeek_plugin_end()

    endif()

    file(STRINGS "${CMAKE_CURRENT_SOURCE_DIR}/VERSION" VERSION LIMIT_COUNT 1)

    if ("${PROJECT_SOURCE_DIR}" STREQUAL "${CMAKE_SOURCE_DIR}")
        # Allows building rpm/deb packages via "make package" in build dir.
        include(ConfigurePackaging)
        ConfigurePackaging(${VERSION})
    endif ()

    message(STATUS "dpdk prefix      : ${dpdk_ROOT_DIR}")
else ()
    message(FATAL_ERROR "DPDK library and/or headers not found.")
endif ()