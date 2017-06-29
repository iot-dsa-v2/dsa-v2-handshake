cmake_minimum_required(VERSION 3.8)
project(server)

set(CMAKE_CXX_STANDARD 11)

find_package(Threads)
set(EXTRA_LIBS ${EXTRA_LIBS} ${CMAKE_THREAD_LIBS_INIT})

# set(BOOST_ROOT "/usr/local/Cellar/boost/1.64.0_1")
set(BOOST_INCLUDEDIR "/usr/local/Cellar/boost/1.64.0_1/include")
set(BOOST_LIBRARYDIR "/usr/local/Cellar/boost/1.64.0_1/lib")
find_package(Boost 1.6 REQUIRED COMPONENTS system thread)
include_directories(${Boost_INCLUDE_DIRS})
set(EXTRA_LIBS ${EXTRA_LIBS} ${Boost_LIBRARIES})

include_directories(${CMAKE_SOURCE_DIR}/src/crypto)
set(EXTRA_LIBS ${EXTRA_LIBS} crypto)

set(SOURCE_FILES 
  main.cpp
  server.cpp
  session.cpp)

add_executable(server ${SOURCE_FILES})
target_link_libraries(server ${EXTRA_LIBS})
target_compile_features(server PRIVATE cxx_range_for)

install(TARGETS server RUNTIME DESTINATION bin)
