cmake_minimum_required(VERSION 3.0)
project(stun_client)

if (MSCV)
  add_compile_optionscl(/W4 /WX)
else()
  add_compile_options(-Wall -Wextra)
endif()

set(CMAKE_CXX_STANDARD 17)

add_library(stun_client STATIC stun_client.cpp)
add_executable(stunclient main.cpp)
add_dependencies(stunclient stun_client)
target_link_libraries(stunclient stun_client)
