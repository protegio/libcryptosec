#ifndef MESSAGEDIGEST_H_
#define MESSAGEDIGEST_H_

#include <libcryptosec/Macros.h>

#include <openssl/evp.h>

#include <string>

class ByteArray;
class Engine;

/**
 * @defgroup Util Classes Relacionadas Utilitárias de Criptografia
 */

/**
 * @brief Implementa as funcionalidades de resumo criptográfico.
 * Antes de utilizar os algortimos de resumo devem-se carregá-los através de init(Algorithm) ou de loadMessageDigestAlgorithms().
 * @ingroup Util
 */

class MessageDigest
{
public:

	/**
	 * @enum MessageDigest::Algorithm.
	 * Possíveis algoritmos de resumo.
	 */
	DECLARE_ENUM( Algorithm, 10,
		NO_ALGORITHM,
		MD4,
		MD5,
		RIPEMD160,
		SHA,
		SHA1,
		SHA224,
		SHA256,
		SHA384,
		SHA512
	);

	/**
	 * Construtor padrão.
	 * Controi objeto MessageDigest não inicializado.
	 */
	MessageDigest();
	
	/**
	 * Construtor
	 * Constroi um objeto MessageDigest.
	 * @param algorithm algoritmo de resumo.
	 * @throw MessageDigestException caso ocorra erro ao inicializar a estrutura de resumos do OpenSSL. 
	 */
	MessageDigest(MessageDigest::Algorithm algorithm);
	
	/**
	 * Construtor
	 * Constroi um objeto MessageDigest utilizando uma engine.
	 * @param algorithm algoritmo de resumo.
	 * @param engine objeto Engine.
	 * @throw MessageDigestException caso ocorra erro ao inicializar a estrutura de resumos do OpenSSL. 
	 */
	MessageDigest(MessageDigest::Algorithm algorithm, Engine &engine);
	
	/**
	 * Destrutor.
	 */
	virtual ~MessageDigest();
	
	/**
	 * Inicializa estruturas de resumos do OpenSSL.
	 * @param algorithm algoritmo de resumo.
	 * @throw MessageDigestException caso ocorra erro ao inicializar a estrutura de resumos do OpenSSL. 
	 */
	void init(MessageDigest::Algorithm algorithm);
	
	/**
	 * Inicializa estruturas de resumos do OpenSSL utilizando uma engine.
	 * @param algorithm algoritmo de resumo.
	 * @param engine objeto Engine.
	 * @throw MessageDigestException caso ocorra erro ao inicializar a estrutura de resumos do OpenSSL. 
	 */
	void init(MessageDigest::Algorithm algorithm, Engine& engine);

	/**
	 * Define o conteúdo de entrada função de resumo.
	 * @param data conteúdo para resumo.
	 * @throw MessageDigestException caso ocorra erro ao atualizar o contexto de resumo do OpenSSL.
	 * @throw InvalidStateException caso o objeto MessageDigest não tenha sido inicializado corretamente.
	 */
	void update(const ByteArray& data);

	/**
	 * Define o conteúdo de entrada função de resumo.
	 * @param data conteúdo para resumo.
	 * @throw MessageDigestException caso ocorra erro ao atualizar o contexto de resumo do OpenSSL.
	 * @throw InvalidStateException caso o objeto MessageDigest não tenha sido inicializado corretamente.
	 */
	void update(const std::string& data);

	/**
	 * @brief Atualiza o conteúdo da função de resumo.
	 *
	 * @param data conteúdo para resumo.
	 *
	 * @throw MessageDigestException caso ocorra erro ao atualizar o contexto de resumo do OpenSSL.
	 * @throw InvalidStateException caso o objeto MessageDigest não tenha sido inicializado corretamente.
	 */
	void update(const unsigned char* data, unsigned int size);

	/**
	 * Realiza resumo criptográfico.
	 * @return bytes que representam o resumo calculado.
	 * @throw MessageDigestException caso ocorra erro ao finalizar o contexto de resumo do OpenSSL.
	 * @throw InvalidStateException caso o objeto MessageDigest não tenha sido inicializado corretamente ou caso não tenha sido passado o conteúdo para calculo do resumo. 
	 */
	ByteArray* doFinal();

	/**
	 * @brief Realiza o resumo criptográfico.
	 *
	 * @param output Buffer onde será escrito o hash.
	 * @param size O tamanho do buffer.
	 *
	 * @return bytes que representam o resumo calculado.
	 * @throw MessageDigestException caso ocorra erro ao finalizar o contexto de resumo do OpenSSL.
	 * @throw InvalidStateException caso o objeto MessageDigest não tenha sido inicializado corretamente ou caso não tenha sido passado o conteúdo para calculo do resumo.
	 */
	void doFinal(unsigned char* hash, unsigned int* size);

	/**
	 * Realiza atualização do contexto e faz resumo criptográfico.
	 * Equivalente a executar MessageDigest::update(ByteArray &data) e, em seguida, MessageDigest::doFinal().
	 * @param data conteúdo para resumo.
	 * @return bytes que representam o resumo calculado.
	 * @throw MessageDigestException caso ocorra erro ao finalizar o contexto de resumo do OpenSSL.
	 * @throw InvalidStateException caso o objeto MessageDigest não tenha sido inicializado corretamente ou caso não tenha sido passado o conteúdo para calculo do resumo. 
	 */	
	ByteArray* doFinal(const ByteArray& data);

	/**
	 * Realiza atualização do contexto e faz resumo criptográfico.
	 * Equivalente a executar MessageDigest::update(ByteArray &data) e, em seguida, MessageDigest::doFinal().
	 * @param data conteúdo para resumo.
	 * @return bytes que representam o resumo calculado.
	 * @throw MessageDigestException caso ocorra erro ao finalizar o contexto de resumo do OpenSSL.
	 * @throw InvalidStateException caso o objeto MessageDigest não tenha sido inicializado corretamente ou caso não tenha sido passado o conteúdo para calculo do resumo. 
	 */	
	ByteArray* doFinal(const std::string& data);
	
	/**
	 * Retorna algoritmo de resumo selecionado.
	 * @return algoritmo de resumo selecionado.
	 * @throw InvalidStateException caso o objeto MessageDigest não tenha sido inicializado corretamente.
	 */
	MessageDigest::Algorithm getAlgorithm();
	
	
	/**
	 * Retorna a estrutura do OpenSSL que representa o algoritmo de resumo desejado.
	 * @return objeto EVP_MD referente ao algoritmo passado.
	 * @throw MessageDigestException if MessageDigest::NO_ALGORITHM is passed.
	 */
	static const EVP_MD* getMessageDigest(MessageDigest::Algorithm algorithm);
	
	/**
	 * Obtem algoritmo de resumo a partir do identificador numérico do algoritmo no OpenSSL
	 * @return objeto MessageDigest::Algorithm relativo ao identificador passado.
	 * @throw MessageDigestException caso o identificador passado seja inválido.
	 */
	static MessageDigest::Algorithm getMessageDigest(int algorithmNid);
	
	
	/**
	 * Carrega todos os algoritmos de resumo.
	 */
	static void loadMessageDigestAlgorithms();

protected:

	/**
	 * @enum MessageDigest::State
	 * Define o estado do objeto MessageDigest.
	 * @var NO_INIT estado inicial, enquanto as estruturas de resumo ainda forem inicializadas.
	 * @var INIT estado intermediário, após as estruturas de resumo serem inicializadas, porém o conteúdo para cálculo de resumo ainda não foi passado.
	 * @var UPDATE estado final, todas os requisitos cumplidos para se calcular o resumo.
	 * @see MessageDigest::init(MessageDigest::Algorithm algorithm).
	 * @see MessageDigest::update(ByteArray &data).
	 * @see MessageDigest::doFinal().
	 */
	DECLARE_ENUM( State, 3,
		NO_INIT,
		INIT,
		UPDATE
	);
	
	/**
	 * Algoritmo selecionado
	 */
	MessageDigest::Algorithm algorithm;
	
	/**
	 * Estado das estruturas de resumo.
	 */
	MessageDigest::State state;
	
	/**
	 * Estrutura OpenSSL que representa o algoritmo de resumo.
	 */
	EVP_MD_CTX* ctx;
};

#endif /*MESSAGEDIGEST_H_*/
