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

# Añadir ejecutables
add_executable(radix_blockchain
    src/main.cpp
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
)

# Enlazar bibliotecas
target_link_libraries(radix_blockchain
    ${RANDOMX_LIBRARY} #
    ${OPENSSL_LIBRARIES} # Enlace a las bibliotecas de OpenSSL
)

# Si OpenSSL no se encuentra automáticamente, puedes intentar especificar los directorios manualmente:
# set(OPENSSL_ROOT_DIR "/usr/local/opt/openssl@1.1") # Ejemplo para macOS con Homebrew
# set(OPENSSL_LIBRARIES "${OPENSSL_ROOT_DIR}/lib/libssl.dylib;${OPENSSL_ROOT_DIR}/lib/libcrypto.dylib")
# set(OPENSSL_INCLUDE_DIR "${OPENSSL_ROOT_DIR}/include")