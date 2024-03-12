cmake_minimum_required(VERSION 3.20)
project(HelloC LANGUAGES C)

find_package(OpenSSL)
find_package(OpenGL)
if(OpenSSL_FOUND)
  message("found OpenSSL in ${OpenSSL_INCLUDE_DIRS}")
endif()

if(OpenGL_FOUND)
  message("found opengl in ${OpenGL_INCLUDE_DIRS}")
endif()

add_executable(main main.c)
# target_link_libraries(main OpenSSL::crypto)
