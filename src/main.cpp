#include "blockchain.h"
#include "block.h" // Incluimos block.h ya que usamos objetos Block directamente
#include "transaction.h" // Incluimos transaction.h
#include "randomx_util.h" // Incluimos randomx_util.h
#include <iostream>
#include <vector>
#include <string>
#include <memory> // Para std::unique_ptr
#include <chrono> // Para usar std::chrono::seconds
#include <thread>

// Usamos el namespace Radix para simplificar
using namespace Radix;

int main() {
    std::cout << "Iniciando Radix (RDX) - Core Minimal con Transacciones y Merkle Tree\n" << std::endl;

    // 1. Crear un contexto RandomX
    // NOTA: La creación del contexto RandomX puede tomar tiempo y consumir memoria.
    // Solo se debe hacer una vez y reutilizarlo.
    std::cout << "Inicializando RandomX context (esto puede tardar unos segundos a minutos)..." << std::endl;
    RandomXContext rxContext;
    std::cout << "RandomX context inicializado." << std::endl;

    // 2. Crear una instancia de la Blockchain
    Blockchain radixBlockchain;

    // 3. Crear el Bloque Génesis
    std::cout << "\nCreando y minando el Bloque Génesis..." << std::endl;
    radixBlockchain.createGenesisBlock(rxContext);
    
    // El mensaje de éxito del génesis se imprime dentro de createGenesisBlock ahora.

    // 4. Mostrar información del Bloque Génesis
    const Block& genesisBlock = radixBlockchain.getLastBlock();
    std::cout << "\n--- Información del Bloque Génesis ---" << std::endl;
    std::cout << genesisBlock.toString() << std::endl;
    // El hash del bloque ya está en genesisBlock.header.blockHash

    // 5. Simular la adición de varios bloques con transacciones
    int numBlocksToMine = 3; // Cuántos bloques adicionales queremos minar

    for (int i = 0; i < numBlocksToMine; ++i) {
        std::cout << "\nMinando Bloque #" << radixBlockchain.getChainSize() << "..." << std::endl;

        // Simular algunas transacciones pendientes para el siguiente bloque
        std::vector<std::string> pendingTransactions;
        pendingTransactions.push_back("Alice sends 10 RDX to Bob");
        pendingTransactions.push_back("Charlie sends 5 RDX to David");

        // Añadir una transacción extra para el tercer bloque
        if (i == 2) { // En la iteración 2 (para el tercer bloque minado)
            pendingTransactions.push_back("Gale sends 7 RDX to Heidi");
        }
        
        // Simular un retraso en la adición de transacciones (para timestamps diferentes)
        std::this_thread::sleep_for(std::chrono::seconds(1));

        // Minar un nuevo bloque con transacciones pendientes
        std::unique_ptr<Block> newBlock = radixBlockchain.mineNewBlock(rxContext, pendingTransactions);

        if (newBlock) {
            // No necesitamos imprimir "intentando añadirlo a la cadena..." porque addBlock ya lo hace.
            if (radixBlockchain.addBlock(std::move(newBlock), rxContext, pendingTransactions)) { // currentPendingTxData no se usa en addBlock en esta fase, pero la pasamos.
                const Block& addedBlock = radixBlockchain.getLastBlock();
                std::cout << "\n--- Información del Bloque #" << radixBlockchain.getChainSize() - 1 << " ---" << std::endl;
                std::cout << addedBlock.toString() << std::endl;
            } else {
                std::cerr << "Error: No se pudo añadir el nuevo bloque a la cadena." << std::endl;
            }
        } else {
            std::cerr << "Error: No se pudo minar el nuevo bloque." << std::endl;
        }
    }

    std::cout << "\nDemostración de Radix (RDX) finalizada." << std::endl;

    return 0;
}