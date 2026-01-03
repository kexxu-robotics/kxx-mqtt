cmake_minimum_required(VERSION 4.1)

# Please make build/ dir before messing up the git thank you git bless.
if(PROJECT_SOURCE_DIR STREQUAL PROJECT_BINARY_DIR)
  message(
    FATAL_ERROR
    "Do not build here, maka a build/ dir.\n"
    "Build with:\n"
    "cmake -S . -B build -DCMAKE_BUILD_TYPE=Release\n"
    "cmake --build build\n"
    "ctest --test-dir build --output-on-failure"
  )
endif()

project(kxx-mqtt-app VERSION 1.0)

set(CMAKE_CXX_STANDARD 23)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

find_package(OpenSSL REQUIRED)

add_executable(mqtt_app src/main.cpp)

target_include_directories(mqtt_app PUBLIC include)

target_link_libraries(mqtt_app PRIVATE OpenSSL::SSL OpenSSL::Crypto)

