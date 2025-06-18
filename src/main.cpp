#include <iostream>
#include <stdexcept>
#include <vector> // Para std::vector
#include "blockchain.h"
#include "randomx_util.h"
#include "transaction.h"

int main() {
    std::cout << "Iniciando Radix (RDX) - Core Minimal con Transacciones y Merkle Tree\n" << std::endl;

    Radix::RandomXContext rxContext;
    Radix::Blockchain radixChain;

    try {
        // Paso 1: Minar el bloque Génesis
        // El bloque génesis es especial, su `prevBlockHash` es todo ceros.
        // Lo minaremos una vez.
        std::cout << "Creando y minando el Bloque Génesis..." << std::endl;
        radixChain.createGenesisBlock(rxContext);
        //std::cout << "\nBloque Génesis minado y añadido a la cadena." << std::endl;
        std::cout << radixChain.getLastBlock().toString() << std::endl;

        // Paso 2: Minar y añadir algunos bloques de demostración  con transacciones
        int numBlocksToMine = 3;
        for (int i = 0; i < numBlocksToMine; ++i) {
            std::vector<std::string> pendingTxData;
            if (i == 0) { // Bloque #1
                pendingTxData.push_back(".). Banks");
                pendingTxData.push_back(".). Bitcoin");
            } else if (i == 1) { // Bloque #2
                pendingTxData.push_back(".). Bitcoin");
                pendingTxData.push_back(".). Bitcoin");
                pendingTxData.push_back(".). Banks");
            }
            // Puedes añadir más lógica para variar las transacciones

            std::cout << "\nMinando Bloque #" << radixChain.getLastBlock().header.nonce + 1 << "..." << std::endl;
            std::unique_ptr<Radix::Block> newBlock = radixChain.mineNewBlock(rxContext, pendingTxData);
            if (newBlock) {
                //std::vector<std::string>();
                if (radixChain.addBlock(std::move(newBlock), rxContext, std::vector<std::string>())) { //pasar rxContext a addBlock
                    std::cout << "Bloque #" << (radixChain.getLastBlock().header.nonce + 1) << " añadido a la cadena." << std::endl;
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