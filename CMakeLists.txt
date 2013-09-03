cmake_minimum_required(VERSION 2.8)
project(capture)

if(COMMAND cmake_policy)
	cmake_policy(SET CMP0003 NEW)
endif(COMMAND cmake_policy)

add_definitions(-D_CRT_SECURE_NO_WARNINGS)

SET(EXECUTABLE_OUTPUT_PATH ${PROJECT_BINARY_DIR}/../bin)
SET(LIBRARY_OUTPUT_PATH ${PROJECT_BINARY_DIR}/../bin)

set(ANALYZER_SOURCE_DIR "${PROJECT_SOURCE_DIR}/../analyzer" CACHE PATH "Path to analyzer source folder")
if(APPLE)
set(ANALYZER_LIBRARY_FILE "${PROJECT_SOURCE_DIR}/../analyzer/dist/Debug/GNU-Linux-x86/libanalyzer.dylib" CACHE FILEPATH "Path to the analyzer library folder")
else()
set(ANALYZER_LIBRARY_FILE "${PROJECT_SOURCE_DIR}/../analyzer/dist/Debug/GNU-Linux-x86/libanalyzer.so" CACHE FILEPATH "Path to the analyzer library folder")
endif()

include_directories(${ANALYZER_SOURCE_DIR})

file(GLOB capture_shared_objects_src RELATIVE ${CMAKE_CURRENT_SOURCE_DIR} *.c)
foreach(srcfile ${capture_shared_objects_src})
	string(REPLACE ".c" "" sofile ${srcfile})
	message("Found interface to compile: " ${sofile})
	add_library(${sofile} SHARED ${srcfile})
	target_link_libraries(${sofile} ${ANALYZER_LIBRARY_FILE} pcap pthread)
	install(TARGETS ${sofile} DESTINATION ./)
endforeach()
