cmake_minimum_required(VERSION 3.17)

project(llvm_unroller)

set(CMAKE_CXX_STANDARD 17)
set(LLVM_CONFIG ${LLVM_HOME}/bin/llvm-config)
set(EXECUTABLE_TARGET "llvm-unroller")
file(GLOB_RECURSE PASS_SRC src/*.cpp)
add_executable(${EXECUTABLE_TARGET} ${PASS_SRC})

execute_process(
  COMMAND ${LLVM_CONFIG} --cxxflags
  OUTPUT_VARIABLE LLVM_CXX_FLAGS)
separate_arguments(flag_list UNIX_COMMAND ${LLVM_CXX_FLAGS})
foreach(flag ${flag_list})
  message(STATUS "Add LLVM C++ Flags: ${flag}")
  target_compile_options(${EXECUTABLE_TARGET} PRIVATE ${flag})
endforeach()

execute_process(
  COMMAND ${LLVM_CONFIG} --libs
  OUTPUT_VARIABLE LLVM_SHARED_LIBS
  OUTPUT_STRIP_TRAILING_WHITESPACE)
separate_arguments(lib_list UNIX_COMMAND ${LLVM_SHARED_LIBS})
foreach(lib ${lib_list})
  string(LENGTH ${lib} len)
  string(SUBSTRING ${lib} 2 ${len} sliced)
  message(STATUS "Link LLVM lib: " ${sliced})
  target_link_libraries(${EXECUTABLE_TARGET} PRIVATE ${sliced})
endforeach()

execute_process(
  COMMAND ${LLVM_CONFIG} --system-libs
  OUTPUT_VARIABLE LLVM_SYS_LIBS
  OUTPUT_STRIP_TRAILING_WHITESPACE)
separate_arguments(lib_list UNIX_COMMAND ${LLVM_SYS_LIBS})
foreach(lib ${lib_list})
  string(LENGTH ${lib} len)
  string(SUBSTRING ${lib} 2 ${len} sliced)
  message(STATUS "Link system lib required by LLVM: " ${sliced})
  target_link_libraries(${EXECUTABLE_TARGET} PRIVATE ${sliced})
endforeach()

execute_process(
  COMMAND ${LLVM_CONFIG} --includedir
  OUTPUT_VARIABLE LLVM_INCLUDE
  OUTPUT_STRIP_TRAILING_WHITESPACE)
message(STATUS "Include LLVM headers ${LLVM_INCLUDE}")
target_include_directories(${EXECUTABLE_TARGET} PRIVATE ${LLVM_INCLUDE})
target_include_directories(${EXECUTABLE_TARGET} PRIVATE include/)

execute_process(
  COMMAND ${LLVM_CONFIG} --libdir
  OUTPUT_VARIABLE LLVM_LIBDIR
  OUTPUT_STRIP_TRAILING_WHITESPACE)
message(STATUS "Link directory ${LLVM_LIBDIR}")
target_link_directories(${EXECUTABLE_TARGET} PRIVATE ${LLVM_LIBDIR})
target_link_directories(${EXECUTABLE_TARGET} PRIVATE /usr/lib)
