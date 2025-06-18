cmake_minimum_required(VERSION 3.10)

project(RadixCoreV1 CXX)

set(CMAKE_CXX_STANDARD 14)
set(CMAKE_CXX_STANDARD_REQUIRED True)

# Directorio de los archivos fuente
set(SOURCE_DIR ${CMAKE_CURRENT_SOURCE_DIR}/src)

# Incluir RandomX headers
find_path(RANDOMX_INCLUDE_DIR randomx.h
          PATHS /usr/local/include /usr/include
          NO_DEFAULT_PATH)
if(NOT RANDOMX_INCLUDE_DIR)
    message(FATAL_ERROR "randomx.h no encontrado. Asegúrese de que RandomX esté instalado.")
endif()
include_directories(${RANDOMX_INCLUDE_DIR})

# Enlazar la librería RandomX
find_library(RANDOMX_LIBRARY randomx
             PATHS /usr/local/lib /usr/lib /lib
             NO_DEFAULT_PATH)
if(NOT RANDOMX_LIBRARY)
    message(FATAL_ERROR "Librería RandomX no encontrada. Asegúrese de que RandomX esté instalado.")
endif()

# Añadir los archivos fuente
add_executable(radix_core
    ${SOURCE_DIR}/main.cpp
    ${SOURCE_DIR}/randomx_util.cpp
    ${SOURCE_DIR}/block.cpp
    ${SOURCE_DIR}/blockchain.cpp
    ${SOURCE_DIR}/transaction.cpp
    ${SOURCE_DIR}/merkle_tree.cpp 
)

# Enlazar la librería RandomX al ejecutable
target_link_libraries(radix_core ${RANDOMX_LIBRARY})

# Configurar el directorio de salida del ejecutable
set_target_properties(radix_core PROPERTIES
    RUNTIME_OUTPUT_DIRECTORY "${CMAKE_CURRENT_SOURCE_DIR}/bin"
)