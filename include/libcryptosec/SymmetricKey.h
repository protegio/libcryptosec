#ifndef SYMMETRICKEY_H_
#define SYMMETRICKEY_H_

#include <libcryptosec/Macros.h>

#include <string>

class ByteArray;

/**
 * Representa chaves simétricas.
 *
 * Objetos dessa classe implementam funcionalidades de chaves simétricas
 * usadas nos diferentes tipos de algorítmos de mesmo tipo.
 *
 * @ingroup Symmetric
 **/

class SymmetricKey
{
	
public:

	/**
	 * @enum Algorithm
	 *
	 * Tipos de algoritmos simétricos suportados.
	 **/	 
	DECLARE_ENUM( Algorithm, 3,
		AES_128,	/*!< para chaves AES de 128 bytes */
		AES_192,	/*!< para chaves AES de 192 bytes */
		AES_256 	/*!< para chaves AES de 256 bytes */
	);
	
	/**
	 * @brief Construtor para criação de chave.
	 *
	 * Gera uma chae simétrica para o algoritmo passado utilizando o gerador de números aleatórios interno.
	 *
	 * @param algorithm O algoritmo da chave.
	 */
	SymmetricKey(SymmetricKey::Algorithm algorithm);

	/**
	 * @brief Construtor recebendo a chave no seu formato binário e o seu tipo.
	 *
	 * @param key a chave no formato binário.
	 * @param algorithm o algoritmo ao qual a chave se destina.
	 *
	 * @see SymmetricKeyGenerator para a geração de chaves simétricas.
	 **/
	SymmetricKey(const ByteArray &keyData, SymmetricKey::Algorithm algorithm);
	
	/**
	 * @brief Construtor de cópia.
	 *
	 * @param symmetricKey referência para a chave simétrica a ser copiada.
	 **/
	SymmetricKey(const SymmetricKey &symmetricKey);
	
	/**
	 * @brief Destrutor padrão.
	 **/
	virtual ~SymmetricKey();
	
	/**
	 * @brief Retorna a chave no formato binário.
	 *
	 * @return a chave na sua representação binária.
	 **/
	const ByteArray* getEncoded() const;
	
	/**
	 * @brief Retorna o algoritmo da chave.
	 *
	 * @return o algoritmo ao qual a chave se destina.
	 **/
	SymmetricKey::Algorithm getAlgorithm() const;
	
	/**
	 * @brief Retorna co tamanho da chave.
	 *
	 * @return o tamanho da chave. 
	 **/
	int getSize();
	
	/**
	 * @brief Operador de atribuição sobrescrito.
	 *
	 * @param value a chave a ser atribuída.
	 *
	 * @return uma cópia da chave representada pela referência value.
	 **/
	SymmetricKey& operator =(const SymmetricKey& value);
	
	/**
	 * @brief Retorna o nome do algoritmo simétrico na sua forma textual.
	 *
	 * @param algorithm o algoritmo cujo nome se deseja obter.
	 *
	 * @return o nome do algoritmo passado como parâmetro na forma de texto.
	 **/
	static std::string getAlgorithmName(SymmetricKey::Algorithm algorithm);

	/**
	 * @brief Retorna o tamanho de bloco do algoritmo simétrico.
	 *
	 * @param algorithm O algoritmo cujo tamanho de bloco se deseja obter.
	 *
	 * @return O tamanho de bloco.
	 **/
	static unsigned int getAlgorithmBlockSize(SymmetricKey::Algorithm algorithm);

	/**
	 * @brief Retorna o tamanho do vetor de inicialização do algoritmo simétrico.
	 *
	 * @param algorithm O algoritmo cujo tamanho do vetor de inicialização se deseja obter.
	 *
	 * @return O tamanho do vetor de inicialização.
	 **/
	static unsigned int getAlgorithmIvSize(SymmetricKey::Algorithm algorithm);

private:

	/**
	 * Chave no formato binário.
	 **/
	ByteArray* keyData;
	
	/**
	 * Tipo de algoritmo a que a chave se destina.
	 **/
	SymmetricKey::Algorithm algorithm;
};

#endif /*SYMMETRICKEY_H_*/
