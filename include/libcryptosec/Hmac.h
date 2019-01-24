#ifndef HMAC_H_
#define HMAC_H_

#include <openssl/hmac.h>
#include <libcryptosec/ByteArray.h>
#include <libcryptosec/MessageDigest.h>
#include <libcryptosec/Engine.h>
#include <libcryptosec/exception/InvalidStateException.h>
#include <libcryptosec/exception/HmacException.h>
#include <vector>

/**
 * @defgroup Util Classes Relacionadas Utilitárias de Criptografia
 */

/**
 * @brief Implementa as funcionalidades de um Hmac.
 * Antes de utilizar o Hmac, o algoritmo de resumo (hash) deve ser carregado.
 * @ingroup Util
 */
class Hmac {

public:
	/**
	 * Construtor padrão.
	 * Controi um objeto Hmac não inicializado.
	 */
	Hmac();

	/**
	 * Construtor.
	 * Constroi um objeto Hmac.
	 * @param key chave secreta.
	 * @param algorithm algoritmo de resumo.
	 * @throw HmacException caso ocorra erro ao inicializar a estrutura do hmac do OpenSSL.
	 */
	Hmac(const std::string& key, MessageDigest::Algorithm algorithm);

	/**
	 * Construtor.
	 * Constroi um objeto Hmac.
	 * @param key chave secreta.
	 * @param algorithm algoritmo de resumo.
	 * @throw HmacException caso ocorra erro ao inicializar a estrutura do hmac do OpenSSL.
	 */
	Hmac(const ByteArray& key, MessageDigest::Algorithm algorithm);

	/**
	 * Construtor.
	 * Constroi um objeto Hmac.
	 * @param key chave secreta.
	 * @param algorithm algoritmo de resumo.
	 * @param engine objeto Engine.
	 * @throw HmacException caso ocorra erro ao inicializar a estrutura do hmac do OpenSSL.
	 */
	Hmac(const std::string& key, MessageDigest::Algorithm algorithm, Engine &engine);

	/**
	 * Construtor.
	 * Constroi um objeto Hmac.
	 * @param key chave secreta.
	 * @param algorithm algoritmo de resumo.
	 * @param engine objeto Engine.
	 * @throw HmacException caso ocorra erro ao inicializar a estrutura do hmac do OpenSSL.
	 */
	Hmac(const ByteArray& key, MessageDigest::Algorithm algorithm, Engine &engine);

	/**
	 * Destrutor.
	 */
	virtual ~Hmac();

	/**
	 * Inicializar a operação do hmac.
	 * @param key chave secreta.
	 * @param algorithm algoritmo de resumo.
	 * @throw HmacException caso ocorra erro ao inicializar a estrutura do hmac do OpenSSL.
	 */
	void init(const ByteArray &key, MessageDigest::Algorithm algorithm);

	/**
	 * Inicializar a operação do hmac.
	 * @param key chave secreta.
	 * @param algorithm algoritmo de resumo.
	 * @param engine objeto Engine.
	 * @throw HmacException caso ocorra erro ao inicializar a estrutura do hmac do OpenSSL.
	 */
	void init(const ByteArray &key, MessageDigest::Algorithm algorithm, Engine &engine);

	/**
	 * Inicializar a operação do hmac.
	 *
	 * @param key chave secreta.
	 * @param algorithm algoritmo de resumo.
	 * @throw HmacException caso ocorra erro ao inicializar a estrutura do hmac do OpenSSL.
	 */
	void init(const std::string& key, MessageDigest::Algorithm algorithm);

	/**
	 * @brief Inicializar a operação do hmac.
	 *
	 * @param key chave secreta.
	 * @param algorithm algoritmo de resumo.
	 * @param engine objeto Engine.
	 *
	 * @throw HmacException caso ocorra erro ao inicializar a estrutura do hmac do OpenSSL.
	 */
	void init(const std::string& key, MessageDigest::Algorithm algorithm, Engine &engine);

	/**
	 * Inicializar a operação do hmac.
	 *
	 * @param key O ponteiro para a chave secreta.
	 * @param size O tamanho em bytes da chave.
	 * @param algorithm O algoritmo de resumo.
	 * @param engine A engine OpenSSL.
	 *
	 * @throw HmacException caso ocorra erro ao inicializar a estrutura do hmac do OpenSSL.
	 */
	void init(const unsigned char* key, unsigned int size, MessageDigest::Algorithm algorithm, Engine* engine = NULL);

	/**
	 * Atualizar/concatenar o conteúdo de entrada do hmac.
	 * @param data conteúdo para geração do hmac.
	 * @throw HmacException caso ocorra erro ao atualizar o contexto do hmac do OpenSSL.
	 * @throw InvalidStateException caso o objeto Hmac não tenha sido inicializado corretamente.
	 */
	void update(const ByteArray& data);

	/**
	 * @brief Atualizar/concatenar o conteúdo de entrada do hmac.
	 *
	 * Essa função inclui o terminador nulo (\0) da string no cálculo do hmac.
	 *
	 * @param data conteúdo para geração do hmac.
	 *
	 * @throw HmacException caso ocorra erro ao atualizar o contexto do hmac do OpenSSL.
	 * @throw InvalidStateException caso o objeto Hmac não tenha sido inicializado corretamente.
	 */
	void update(const std::string& data);

	/**
	 * Atualizar/concatenar o conteúdo de entrada do hmac.
	 * @param data conteúdo para geração do hmac usando vector<string>.
	 * @throw HmacException caso ocorra erro ao atualizar o contexto do hmac do OpenSSL.
	 * @throw InvalidStateException caso o objeto Hmac não tenha sido inicializado corretamente.
	 */
	void update(const std::vector<std::string>& data);

	/**
	 * Atualizar/concatenar o conteúdo de entrada do hmac.
	 * @param data conteúdo para geração do hmac usando vector<ByteArray>.
	 * @throw HmacException caso ocorra erro ao atualizar o contexto do hmac do OpenSSL.
	 * @throw InvalidStateException caso o objeto Hmac não tenha sido inicializado corretamente.
	 */
	void update(const std::vector<ByteArray>& data);

	/**
	 * Atualizar/concatenar o conteúdo de entrada do hmac.
	 * @param data conteúdo para geração do hmac.
	 * @throw HmacException caso ocorra erro ao atualizar o contexto do hmac do OpenSSL.
	 * @throw InvalidStateException caso o objeto Hmac não tenha sido inicializado corretamente.
	 */
	void update(const unsigned char* data, unsigned int size);

	/**
	 * Gerar o hmac
	 * @param data conteúdo para geração do hmac.
	 * @return bytes que representam o hmac.
	 * @throw HmacException caso ocorra erro ao finalizar o contexto do hmac do OpenSSL.
	 * @throw InvalidStateException caso o objeto Hmac não tenha sido inicializado corretamente ou caso não tenha sido passado o conteúdo para calculo do hmac.
	 */
	ByteArray* doFinal(const ByteArray& data);

	/**
	 * Gerar o hmac
	 * @param data conteúdo para geração do hmac.
	 * @return bytes que representam o hmac.
	 * @throw HmacException caso ocorra erro ao finalizar o contexto do hmac do OpenSSL.
	 * @throw InvalidStateException caso o objeto Hmac não tenha sido inicializado corretamente ou caso não tenha sido passado o conteúdo para calculo do hmac.
	 */
	ByteArray* doFinal(const std::string& data);

	/**
	 * Gerar o hmac
	 * @return bytes que representam o hmac.
	 * @throw HmacException caso ocorra erro ao finalizar o contexto do hmac do OpenSSL.
	 * @throw InvalidStateException caso o objeto Hmac não tenha sido inicializado corretamente ou caso não tenha sido passado o conteúdo para calculo do hmac.
	 */
	ByteArray* doFinal();

	/**
	 * Gerar o hmac
	 *
	 * @param hmac Buffer para escrever o hmac.
	 * @param size Tamanho do buffer.
	 *
	 * @return bytes que representam o hmac.
	 * @throw HmacException caso ocorra erro ao finalizar o contexto do hmac do OpenSSL.
	 * @throw InvalidStateException caso o objeto Hmac não tenha sido inicializado corretamente ou caso não tenha sido passado o conteúdo para calculo do hmac.
	 */
	void doFinal(unsigned char* hmac, unsigned int* size);

protected:
	/**
	 * @enum Hmac::State
	 * Define o estado do objeto Hmac.
	 * @var NO_INIT estado inicial, enquanto a estrutura do Hmac ainda não foi inicializada.
	 * @var INIT estado intermediário, após a estrutura do Hmac ser inicializada, porém o conteúdo para cálculo do Hmac ainda não foi passado.
	 * @var UPDATE estado final, todas os requisitos cumpridos para se calcular o Hmac.
	 * @see Hmac::init(std::string key, Hmac::Algorithm algorithm).
	 * @see Hmac::update(ByteArray &data).
	 * @see Hmac::doFinal().
	 */
	enum State {
		NO_INIT,
		INIT,
		UPDATE,
	};

	/**
	 * Algoritmo selecionado.
	 */
	MessageDigest::Algorithm algorithm;

	/**
	 * Estado das estruturas de resumo.
	 */
	State state;

	/**
	 * Estrutura OpenSSL que representa o Hmac.
	 */
	HMAC_CTX* ctx;

};

#endif
