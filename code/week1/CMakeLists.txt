cmake_minimum_required(VERSION 3.0)
project(week1)
set(CMAKE_CXX_STANDARD 11)
set(CMAKE_CXX_FLAGS "-Wall")
add_executable(decipher
  decipher.cpp
  main.cpp
)

target_link_libraries(decipher
  glog
)