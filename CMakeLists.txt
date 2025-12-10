cmake_minimum_required(VERSION 3.10)
project(RadixBlockchain CXX)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED True)

# Directorios de inclusión
include_directories(
    src
)

# --- Configuración manual para RandomX si find_package falla ---

# Buscar el directorio de inclusión de RandomX
find_path(RANDOMX_INCLUDE_DIR randomx.h
          PATHS /usr/local/include /usr/include
          # NO_DEFAULT_PATH # Si RandomX está en una ruta muy inusual, podrías necesitar eliminar esta línea.
          )
if(NOT RANDOMX_INCLUDE_DIR)
    message(FATAL_ERROR "randomx.h no encontrado. Asegúrese de que RandomX esté instalado y en una ruta accesible.")
endif()
include_directories(${RANDOMX_INCLUDE_DIR})

# Buscar la biblioteca RandomX (asegúrate que el nombre sea correcto, puede ser randomx o librandomx)
find_library(RANDOMX_LIBRARY NAMES randomx librandomx # Prueba con ambos nombres comunes
             PATHS /usr/local/lib /usr/lib
             # NO_DEFAULT_PATH # Si RandomX está en una ruta muy inusual, podrías necesitar eliminar esta línea.
             )
if(NOT RANDOMX_LIBRARY)
    message(FATAL_ERROR "librandomx no encontrada. Asegúrese de que RandomX esté instalado y en una ruta accesible.")
endif()



# Encontrar y enlazar OpenSSL
find_package(OpenSSL REQUIRED)

# ============================================================================
# RADIX CORE LIBRARY (shared between main executable and tests)
# ============================================================================
add_library(radix_core STATIC
    src/blockchain.cpp
    src/block.cpp
    src/transaction.cpp
    src/crypto.cpp
    src/merkle_tree.cpp
    src/randomx_util.cpp
    src/base58.cpp
    src/money_util.cpp
    src/persistence_util.cpp
    src/networking/Node.cpp
    src/networking/Peer.cpp
    src/wallet.cpp
    src/api/RpcServer.cpp
    src/config.cpp
    src/api/RateLimiter.cpp
    src/api/ApiKeyManager.cpp
)

# Link libraries to core
target_link_libraries(radix_core
    ${RANDOMX_LIBRARY}
    ${OPENSSL_LIBRARIES}
    nlohmann_json::nlohmann_json
)

# ============================================================================
# MAIN EXECUTABLE
# ============================================================================
add_executable(radix_blockchain
    src/main.cpp
)

# Enlazar con radix_core library
target_link_libraries(radix_blockchain
    radix_core
)

# ============================================================================
# THIRD-PARTY LIBRARIES
# ============================================================================
include(FetchContent)

# Download nlohmann/json (for config file parsing)
FetchContent_Declare(
  json
  URL https://github.com/nlohmann/json/releases/download/v3.11.3/json.tar.xz
)
FetchContent_MakeAvailable(json)

# Download Google Test
FetchContent_Declare(
  googletest
  URL https://github.com/google/googletest/archive/03597a01ee50ed33e9dfd640b249b4be3799d395.zip
)
# For Windows: Prevent overriding parent project's compiler/linker settings
set(gtest_force_shared_crt ON CACHE BOOL "" FORCE)
FetchContent_MakeAvailable(googletest)

# Enable testing
enable_testing()

# Add tests subdirectory
add_subdirectory(tests)

# Si OpenSSL no se encuentra automáticamente, puedes intentar especificar los directorios manualmente:
# set(OPENSSL_ROOT_DIR "/usr/local/opt/openssl@1.1") # Ejemplo para macOS con Homebrew
# set(OPENSSL_LIBRARIES "${OPENSSL_ROOT_DIR}/lib/libssl.dylib;${OPENSSL_ROOT_DIR}/lib/libcrypto.dylib")
# set(OPENSSL_INCLUDE_DIR "${OPENSSL_ROOT_DIR}/include")