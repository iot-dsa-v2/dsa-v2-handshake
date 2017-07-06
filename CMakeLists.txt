cmake_minimum_required(VERSION 3.7)
project (HandshakeDemo)

set(PROJECT_SOURCE_DIR src)

option(USE_SSL "use secure tcp" OFF)

if (USE_SSL)
  add_definitions(-DUSE_SSL=true)
endif(USE_SSL)

add_subdirectory("${PROJECT_SOURCE_DIR}/crypto")
add_subdirectory("${PROJECT_SOURCE_DIR}/server")
add_subdirectory("${PROJECT_SOURCE_DIR}/client")
