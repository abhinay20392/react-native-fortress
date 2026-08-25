cmake_minimum_required(VERSION 3.13)
project(fortress)

set(FORTRESS_CPP_DIR "${CMAKE_CURRENT_SOURCE_DIR}/../cpp")

add_library(
  fortress
  SHARED
  ${FORTRESS_CPP_DIR}/fortress_scoring.cpp
  ${FORTRESS_CPP_DIR}/fortress_crypto.cpp
  src/main/jni/fortress_jni.cpp
)

target_include_directories(
  fortress
  PUBLIC
  ${FORTRESS_CPP_DIR}
)

target_compile_features(fortress PRIVATE cxx_std_17)

find_library(log-lib log)
target_link_libraries(fortress ${log-lib})
