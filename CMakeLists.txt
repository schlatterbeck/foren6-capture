cmake_minimum_required(VERSION 2.8)
project(rplcapture)

if(COMMAND cmake_policy)
	cmake_policy(SET CMP0003 NEW)
endif(COMMAND cmake_policy)

add_definitions(-D_CRT_SECURE_NO_WARNINGS)

SET(EXECUTABLE_OUTPUT_PATH ${PROJECT_BINARY_DIR}/../bin)
SET(LIBRARY_OUTPUT_PATH ${PROJECT_BINARY_DIR}/../bin)

if(EXISTS "${PROJECT_SOURCE_DIR}/../analyzer/src")
  set(RPLANALYZER_INCLUDE_DIRS "${PROJECT_SOURCE_DIR}/../analyzer/src" CACHE PATH "Path to analyzer source folder")
  if(APPLE)
	set(RPLANALYZER_LIBRARIES "${PROJECT_SOURCE_DIR}/../analyzer/dist/Debug/GNU-Linux-x86/librplanalyzer.dylib" CACHE FILEPATH "Path to the analyzer library folder")
  else()
	set(RPLANALYZER_LIBRARIES "${PROJECT_SOURCE_DIR}/../analyzer/dist/Debug/GNU-Linux-x86/librplanalyzer.so" CACHE FILEPATH "Path to the analyzer library folder")
  endif()
else()
  find_package(RplAnalyzer)
endif()


message("Using ${RPLANALYZER_LIBRARIES}")

include_directories(${RPLANALYZER_INCLUDE_DIRS})

file(GLOB capture_shared_objects_src RELATIVE ${CMAKE_CURRENT_SOURCE_DIR} *.c)
foreach(srcfile ${capture_shared_objects_src})
	string(REPLACE ".c" "" sofile ${srcfile})
	message("Found interface to compile: " ${sofile})
	add_library(${sofile} SHARED ${srcfile})
	target_link_libraries(${sofile} ${RPLANALYZER_LIBRARIES} pcap pthread)
	install(TARGETS ${sofile} DESTINATION lib/rplanalyzer)
endforeach()
