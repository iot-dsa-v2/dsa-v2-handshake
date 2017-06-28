set(OPENSSL_ROOT_DIR "/usr/local")
find_package(OpenSSL REQUIRED)
include_directories(${OPENSSL_INCLUDE_DIR})
set(EXTRA_LIBS ${EXTRA_LIBS} ${OPENSSL_LIBRARIES})

add_library(crypto ECDH.cpp Hash.cpp)
target_link_libraries(crypto ${EXTRA_LIBS})
install (TARGETS crypto
  LIBRARY DESTINATION lib
  ARCHIVE DESTINATION lib)