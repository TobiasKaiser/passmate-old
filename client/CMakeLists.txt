
set (MACOSX_DEPLOYMENT_TARGET 10.9)
project(passmate)
cmake_minimum_required(VERSION 2.8)
aux_source_directory(. SRC_LIST)


IF(${CMAKE_SYSTEM_NAME} MATCHES "Darwin")
    SET(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -std=c++11 -stdlib=libc++ -mmacosx-version-min=10.9")
    SET(CMAKE_EXE_LINKER_FLAGS "${CMAKE_EXE_LINKER_FLAGS} -stdlib=libc++ -mmacosx-version-min=10.9")
ENDIF()
 
set(wxWidgets_CONFIGURATION mswu)
find_package(wxWidgets COMPONENTS core base REQUIRED)
include(${wxWidgets_USE_FILE})
 
add_executable(${PROJECT_NAME} ${SRC_LIST})
set_property(TARGET passmate PROPERTY CXX_STANDARD 11)
target_link_libraries(${PROJECT_NAME} ${wxWidgets_LIBRARIES})
target_link_libraries(${PROJECT_NAME} scrypt)
target_link_libraries(${PROJECT_NAME} mbedtls mbedcrypto mbedx509)

target_include_directories(passmate PRIVATE include)
target_include_directories(passmate SYSTEM PRIVATE /usr/local/include)

