#include <iostream>
#include <stdexcept>
#include "blockchain.h"
#include "randomx_util.h"

int main() {
    std::cout << "Iniciando Radix (RDX) - Core Minimal\n" << std::endl;

    Radix::RandomXContext rxContext;
    Radix::Blockchain radixChain;

    try {
        // Paso 1: Minar el bloque Génesis
        // El bloque génesis es especial, su `prevBlockHash` es todo ceros.
        // Lo minaremos una vez.
        std::cout << "Creando y minando el Bloque Génesis..." << std::endl;
        radixChain.createGenesisBlock(rxContext);
        std::cout << "\nBloque Génesis minado y añadido a la cadena." << std::endl;
        std::cout << radixChain.getLastBlock().toString() << std::endl;

        // Paso 2: Minar y añadir algunos bloques de demostración
        int numBlocksToMine = 3;
        for (int i = 0; i < numBlocksToMine; ++i) {
            std::cout << "\nMinando Bloque #" << radixChain.getLastBlock().header.nonce + 1 << "..." << std::endl;
            std::unique_ptr<Radix::Block> newBlock = radixChain.mineNewBlock(rxContext);
            if (newBlock) {
                if (radixChain.addBlock(std::move(newBlock))) {
                    std::cout << "Bloque #" << radixChain.getLastBlock().header.nonce << " añadido a la cadena." << std::endl;
                    std::cout << radixChain.getLastBlock().toString() << std::endl;
                } else {
                    std::cerr << "Error: No se pudo añadir el bloque a la cadena." << std::endl;
                    break;
                }
            } else {
                std::cerr << "Error: No se pudo minar un nuevo bloque." << std::endl;
                break;
            }
        }

    } catch (const std::exception& e) {
        std::cerr << "Ocurrió un error: " << e.what() << std::endl;
        return 1;
    }

    std::cout << "\nDemostración de Radix (RDX) finalizada." << std::endl;
    return 0;
}