cmake_minimum_required(VERSION 3.7)
project(client)

set(CMAKE_CXX_STANDARD 11)

find_package(Threads) 
set(EXTRA_LIBS ${EXTRA_LIBS} ${CMAKE_THREAD_LIBS_INIT})

# set(OPENSSL_ROOT_DIR "/usr/local/Cellar/openssl/1.0.2l")
find_package(OpenSSL REQUIRED)
# include_directories(${OPENSSL_INCLUDE_DIR})
set(EXTRA_LIBS ${EXTRA_LIBS} ${OPENSSL_LIBRARIES})

# set(BOOST_ROOT "/usr/local/Cellar/boost/1.64.0_1")
find_package(Boost 1.6 REQUIRED COMPONENTS system thread date_time)
include_directories(${Boost_INCLUDE_DIRS})
set(EXTRA_LIBS ${EXTRA_LIBS} ${Boost_LIBRARIES})

include_directories(${CMAKE_SOURCE_DIR}/src/crypto)
set(EXTRA_LIBS ${EXTRA_LIBS} crypto)

set(SOURCE_FILES 
  main.cpp
  client.cpp)

add_executable(client ${SOURCE_FILES})
target_link_libraries(client ${EXTRA_LIBS})
target_compile_features(client PRIVATE cxx_range_for)

install(TARGETS client RUNTIME DESTINATION bin)
