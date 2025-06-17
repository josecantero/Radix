#include "blockchain.h"
#include <iostream>
#include <limits> // Para numeric_limits
#include <algorithm> // Para std::reverse
#include <chrono> 

namespace Radix {

Blockchain::Blockchain() {
    // Definimos un objetivo de dificultad muy alto para el bloque génesis,
    // que es simplemente un valor fijo.
    // En Bitcoin, esto es 0x00000000FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF
    // Para simplificar, usaremos un número de 32 bits. Cuanto más pequeño, más difícil.
    // Un valor muy grande aquí para que el hash sea casi cero.
    // Target para RandomX es un poco diferente; un hash bajo es bueno.
    // Así que queremos que los primeros bytes del hash sean cero.
    // Por ejemplo, 0x0000FFFF para 2 bytes iniciales a cero.
    // O 0x000000FF para 3 bytes iniciales a cero.
    // Cuanto más ceros iniciales, más difícil.
    // Usemos un target que requiera que los primeros 2 bytes del hash sean cero para empezar.
    //genesisBlockTargetHash.fill(0);
    // Por ejemplo, para que los primeros 2 bytes sean cero:
    // genesisBlockTargetHash[0] = 0;
    // genesisBlockTargetHash[1] = 0;
    // El objetivo real se compara byte por byte desde el principio del hash.
    // Si el hash del bloque es menor o igual al objetivo, es válido.
    // Para un objetivo de dificultad que sea 0x0000FFFF..., necesitamos que los bytes del hash
    // sean 0x00, 0x00, ...
    // Un target como 0x00000F... significa que los dos primeros bytes deben ser 0.
    // Ajustar el objetivo para que sea algo alcanzable para la demo.
    // Queremos que el hash sea menor que el target.
    // Un target de 0x00000000FFFFFFFF... significa que los primeros 4 bytes deben ser cero.
    // Para esta demo, simplemente definiremos el "target" como los 2 primeros bytes del hash que deben ser cero.
    // Opcionalmente, podemos definir un target numérico:
    // Por ejemplo, un hash debe ser menor que 2^256 / Dificultad.
    // La dificultad de Bitcoin es inversa a este target.
    // Para simplificar, nuestro `difficultyTarget` indicará el número de ceros iniciales en el hash.
    // Para el Génesis, pediremos 1 byte inicial a cero para que sea rápido de minar.
}

void Blockchain::createGenesisBlock(RandomXContext& rxContext) {
    Block genesisBlock;
    genesisBlock.header.version = 1;
    genesisBlock.header.prevBlockHash.fill(0); // El hash del bloque anterior es cero para el génesis
    genesisBlock.header.merkleRoot.fill(0);   // Placeholder
    genesisBlock.header.timestamp = static_cast<uint32_t>(std::chrono::duration_cast<std::chrono::seconds>(
        std::chrono::system_clock::now().time_since_epoch()).count());
    genesisBlock.header.difficultyTarget = getCurrentDifficultyTarget(); // Por ejemplo, 0x0000FFFF

    std::cout << "Minando bloque Génesis..." << std::endl;
    // Minar el bloque génesis
    while (true) {
        genesisBlock.header.nonce++;
        Radix::RandomXHash blockHash = genesisBlock.calculateHash(rxContext);

        if (checkDifficulty(blockHash, genesisBlock.header.difficultyTarget)) {
            std::cout << "Bloque Génesis minado exitosamente con Nonce: " << genesisBlock.header.nonce << std::endl;
            genesisBlock.header.prevBlockHash = blockHash; // En Bitcoin, el hash del bloque es su propio identificador
            // Y no es el prevBlockHash. Aquí lo usamos para la semilla de RandomX del siguiente bloque.
            // Para el *siguiente* bloque, el prevBlockHash será el hash de este bloque génesis.
            chain.push_back(genesisBlock);
            return;
        }
        // Evitar bucle infinito si el target es demasiado difícil o el nonce desborda
        if (genesisBlock.header.nonce == std::numeric_limits<uint32_t>::max()) {
            std::cerr << "Advertencia: Nonce desbordado para el bloque Génesis. Incrementando dificultad o ajustando el objetivo." << std::endl;
            // Reiniciar Nonce y quizás ajustar timestamp o algo para cambiar el hash y seguir buscando.
            genesisBlock.header.nonce = 0;
            genesisBlock.header.timestamp++; // Cambiar timestamp para variar el hash
        }
    }
}

bool Blockchain::addBlock(std::unique_ptr<Block> newBlock) {
    if (chain.empty()) {
        // El primer bloque debe ser el génesis (manejado por createGenesisBlock)
        // No debería llegar aquí si el génesis ya se creó.
        return false;
    }

    const Block& lastBlock = getLastBlock();

    // 1. Verificar que el prevBlockHash del nuevo bloque coincida con el hash del último bloque
    //    En nuestra simulación, prevBlockHash es la semilla para RandomX.
    //    Si el hash del último bloque no se propaga como `prevBlockHash` del siguiente,
    //    RandomX tendrá la misma semilla para todos los bloques. Lo correcto es usar el hash
    //    del bloque anterior como semilla para RandomX del bloque actual.
    //    Por lo tanto, el prevBlockHash del nuevo bloque debe ser el hash calculado del *último* bloque.

    // Calculate the hash of the last block to verify prevBlockHash
    // This requires a RandomXContext, but we don't have one here directly
    // This means `addBlock` would need to take a `RandomXContext&` as well,
    // or the Block itself needs to be able to re-calculate its own hash given a context.
    // For now, we will simply assume the `prevBlockHash` in `newBlock->header` is correct.
    // In a real system, you would pass the rxContext here and verify:
    // RandomXHash lastBlockHash = lastBlock.calculateHash(rxContext_passed_in);
    // if (newBlock->header.prevBlockHash != lastBlockHash) { ... }

    // Por ahora, solo comprobaremos que el target de dificultad sea el actual
    if (newBlock->header.difficultyTarget != getCurrentDifficultyTarget()) {
        std::cerr << "Error: El objetivo de dificultad del nuevo bloque no coincide." << std::endl;
        return false;
    }

    // 2. Recalcular el hash del nuevo bloque y verificar la dificultad
    //    NOTA: Esto requeriría una instancia de RandomXContext aquí también.
    //    Por simplicidad para esta demo, asumiremos que el bloque ya fue minado correctamente
    //    y solo comprobamos que el target sea correcto.
    //    En un sistema real:
    //    RandomXHash calculatedHash = newBlock->calculateHash(rxContext);
    //    if (!checkDifficulty(calculatedHash, newBlock->header.difficultyTarget)) {
    //        std::cerr << "Error: El hash del nuevo bloque no cumple la dificultad." << std::endl;
    //        return false;
    //    }

    chain.push_back(*newBlock); // Añadir el bloque a la cadena
    return true;
}

const Block& Blockchain::getLastBlock() const {
    if (chain.empty()) {
        throw std::runtime_error("La cadena está vacía. No hay último bloque.");
    }
    return chain.back();
}

std::unique_ptr<Block> Blockchain::mineNewBlock(RandomXContext& rxContext) {
    if (chain.empty()) {
        // Si la cadena está vacía, necesitamos minar el bloque génesis primero.
        // Esto podría ser un error si mineNewBlock se llama antes de createGenesisBlock.
        std::cerr << "Error: No se puede minar un bloque nuevo sin un bloque génesis." << std::endl;
        return nullptr;
    }

    Block lastBlock = getLastBlock(); // Copia del último bloque para evitar problemas de referencia
    RandomXHash lastBlockHash = lastBlock.calculateHash(rxContext); // Hash del bloque anterior para la semilla de RandomX

    std::unique_ptr<Block> newBlock = std::make_unique<Block>();
    newBlock->header.version = 1;
    newBlock->header.prevBlockHash = lastBlockHash; // La semilla de RandomX para este nuevo bloque
    newBlock->header.merkleRoot.fill(0); // Placeholder
    newBlock->header.timestamp = static_cast<uint32_t>(std::chrono::duration_cast<std::chrono::seconds>(
        std::chrono::system_clock::now().time_since_epoch()).count());
    newBlock->header.difficultyTarget = getCurrentDifficultyTarget();
    newBlock->header.nonce = 0; // Reiniciar nonce para el minado

    std::cout << "Minando nuevo bloque con Prev Hash: " << toHexString(newBlock->header.prevBlockHash) << std::endl;

    while (true) {
        newBlock->header.nonce++;
        Radix::RandomXHash blockHash = newBlock->calculateHash(rxContext);

        if (checkDifficulty(blockHash, newBlock->header.difficultyTarget)) {
            std::cout << "Bloque minado exitosamente con Nonce: " << newBlock->header.nonce << std::endl;
            std::cout << "Hash del bloque: " << toHexString(blockHash) << std::endl;
            return newBlock;
        }

        // Evitar bucle infinito si el nonce desborda antes de encontrar el hash
        if (newBlock->header.nonce == std::numeric_limits<uint32_t>::max()) {
            std::cerr << "Advertencia: Nonce desbordado. Cambiando timestamp para variar el hash." << std::endl;
            newBlock->header.nonce = 0;
            newBlock->header.timestamp++; // Incrementa el timestamp para cambiar el hash de entrada a RandomX
        }
    }
}

uint32_t Blockchain::getCurrentDifficultyTarget() const {
    // Esto es muy simplificado. En Bitcoin, la dificultad se ajusta cada 2016 bloques.
    // Para esta demo, haremos que el target sea fijo y fácil de alcanzar:
    // Que el primer byte del hash sea 0.
    // Un target de 0x00FFFFFFFF... significa que el primer byte debe ser 0.
    return 0x00FFFFFF; // Target que requiere un byte inicial de 0 en el hash
}

bool Blockchain::checkDifficulty(const RandomXHash& hash, uint32_t target) const {
    // En Bitcoin, el hash debe ser menor que el target.
    // Convertimos el hash (32 bytes) a un número grande y lo comparamos con el target.
    // Para esta demo simplificada, interpretaremos el target como:
    // Si target = 0x00FFFFFFFF..., significa que el primer byte del hash debe ser 0.
    // Si target = 0x0000FFFFFFFF..., significa que los dos primeros bytes del hash deben ser 0.

    // Interpretación simple: el `target` representa un prefijo de ceros.
    // Por ejemplo, si target es 0x00FFFFFF, el hash[0] debe ser 0.
    // Si target es 0x0000FFFF, hash[0] y hash[1] deben ser 0.
    // Esto no es una comparación numérica de 256 bits, sino una verificación de prefijo.

    // Para una comparación numérica real:
    // Creamos un número grande a partir del hash y comparamos.
    // Necesitaríamos una librería para números grandes (como Boost.Multiprecision o OpenSSL BIGNUM).
    // Sin embargo, para una demostración mínima, podemos verificar los bits más significativos.
    // Un hash es válido si es menor que el target.

    // Para un target de ejemplo `0x00FFFFFF` (1 byte inicial a cero):
    if (hash[0] != 0x00) return false;
    // Si queremos 2 bytes iniciales a cero (target `0x0000FFFF`):
    // if (hash[0] != 0x00 || hash[1] != 0x00) return false;

    // Para el target actual (0x00FFFFFF), solo verificamos el primer byte.
    // Un hash es válido si es numéricamente menor que el target.
    // Interpretamos el target como un número grande.
    // Aquí, para simplificar, usaremos un prefijo de ceros.

    // Convierte el hash a un número grande y lo compara con el target.
    // Esto requiere una función de comparación de números grandes.
    // Dado que no tenemos una librería de números grandes aquí,
    // podemos simularlo comparando los bytes de manera lexicográfica,
    // o simplemente esperando un cierto número de ceros iniciales como Bitcoin.
    // Bitcoin compara un hash de 256 bits (target hash) con el hash del bloque.

    // Implementación simplificada: el hash debe ser menor que el target numéricamente.
    // Un hash de 32 bytes (256 bits).
    // Un target de 32 bytes (256 bits), donde los primeros bytes suelen ser 0 para alta dificultad.

    // Para esta etapa, vamos a hacer una comparación byte por byte desde el principio.
    // El objetivo es que el hash sea menor que el target.
    // Asumimos que `target` es un número donde los primeros bytes son ceros y luego hay un valor.
    // Por ejemplo, si `target` es 0x00000FFF... (los dos primeros bytes son 0),
    // el hash debe comenzar con 0x00, 0x00 y luego ser menor o igual que 0x0F...
    // O simplemente, el hash numéricamente debe ser menor que el target.

    // Vamos a convertir el target (uint32_t) a un RandomXHash para comparación.
    RandomXHash targetHashConverted;
    targetHashConverted.fill(0); // Rellenar con ceros
    // El target se interpreta como un número de 256 bits con el valor en el extremo derecho.
    // Para Bitcoin, el target es un `compact` que se expande a 256 bits.
    // Por ejemplo, si `target` es 0x1d00FFFF, el exponente es 0x1d (29).
    // Significa que el número es FFFF y luego 29-3=26 bytes de ceros.
    // 0x00000000FFFF0000000000000000000000000000000000000000000000000000

    // Para nuestra demostración, `difficultyTarget` será un número de 32 bits.
    // Queremos que el hash de 256 bits sea menor que un número target de 256 bits.
    // El target real debería ser un RandomXHash.

    // Para esta etapa, la forma más fácil de verificar la dificultad es
    // pedir un cierto número de ceros iniciales en el hash.
    // El `difficultyTarget` podría ser el número de bytes iniciales que deben ser cero.
    // Si `difficultyTarget` es 1, el hash[0] debe ser 0.
    // Si `difficultyTarget` es 2, hash[0] y hash[1] deben ser 0.

    // Cambiemos `difficultyTarget` a `uint8_t zerosPrefixCount;`
    // Para mantenerlo como uint32_t, asumamos que `target` es un valor binario que
    // debe ser mayor que el hash resultante.

    // Para una implementación "real" sin librerías de números grandes:
    // Compara el hash (RandomXHash) byte a byte con un target de 32 bytes (RandomXHash).
    // El `difficultyTarget` de la cabecera es un "compact target" como en Bitcoin.
    // Para simplificar, aquí lo haremos como un prefijo de ceros.
    // Por ejemplo, si `target = 0x0000FFFF`: significa que los 2 primeros bytes del hash deben ser 0.

    if ((hash[0] & 0xFF) > (target >> 24)) return false; // Comparar byte más significativo del hash con el target
    if ((hash[0] & 0xFF) < (target >> 24)) return true; // Si es menor, ya cumple

    // Si el primer byte es igual, compara el segundo
    if ((hash[1] & 0xFF) > ((target >> 16) & 0xFF)) return false;
    if ((hash[1] & 0xFF) < ((target >> 16) & 0xFF)) return true;

    // Y así sucesivamente para los 4 bytes de target. Esto es una simplificación MUY GRANDE.
    // Una comparación numérica real de 256 bits es necesaria para una criptomoneda funcional.
    // Para esta demo, simplemente diremos que el primer byte del hash debe ser 0.
    // Por eso el `difficultyTarget` de 0x00FFFFFF.
    return hash[0] == 0x00; // Requiere que el primer byte del hash sea 0
}

} // namespace Radix