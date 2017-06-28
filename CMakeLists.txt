cmake_minimum_required(VERSION 3.8)
project (HandshakeDemo)

set(PROJECT_SOURCE_DIR src)

add_subdirectory("${PROJECT_SOURCE_DIR}/crypto")
add_subdirectory("${PROJECT_SOURCE_DIR}/server")
add_subdirectory("${PROJECT_SOURCE_DIR}/client")
