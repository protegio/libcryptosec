#ifndef SYMMETRICCIPHER_H_
#define SYMMETRICCIPHER_H_

#include <libcryptosec/SymmetricKey.h>
#include <libcryptosec/exception/SymmetricCipherException.h>
#include <libcryptosec/exception/InvalidStateException.h>

#include <openssl/evp.h>

#include <string>

/**
 * @defgroup Symmetric Classes envolvidas no uso da criptografia simétrica. 
 **/

/**
 * Implementa as funcionalidades de um cifrador de bloco simétrico.
 * Essa classe implementa o padrão de projetos Builder e implementa as operações
 * de um cifrador simétrico como cifragem e decifragem de dados.
 * @ingroup Symmetric
 **/

class SymmetricCipher
{
	
public:

	/**
	 * @enum OperationMode
	 *
	 * Modos de operação suportados pelo cifrador.
	 **/
	DECLARE_ENUM( OperationMode, 5,
		NO_MODE,	/*!< quando o cifrador possuir um único modo de operação */
		CBC,		/*!< para usar o modo cipher block chaining */
		ECB,		/*!< para usar o modo eletronic code book */
		CFB,		/*!< para usar o modo cipher feedback mode */
		OFB			/*!< para usar o modo output feedback mode */
	);
	
	/**
	 * @enum Operation
	 *
	 * Tipos de operações possíveis no cifrador.
	 **/
	DECLARE_ENUM( Operation, 3,
		NO_OPERATION,	/*!< quando o cifrador não tiver sido inicializado */
		ENCRYPT,		/*!< na cifragem de dados */
		DECRYPT,		/*!< na decifragem de dados */
	);
	
	/**
	 * Construtor padrão.
	 **/
	SymmetricCipher();
	
	/**
	 * @brief Inicializa o cifrador para uso.
	 *
	 * @param key		A chave simétrica a ser usada na operação.
	 * @param iv		O vetor de inicialização do cifrador.
	 * @param operation Determina se é uma operação de cifração ou decifração.
	 * @param mode 		Determina o modo de cifração (operação de bloco).
	 *
	 * @throw SymmetricCipherException caso ocorra algum erro na inicialização do cifrador.
	 **/
	SymmetricCipher(const SymmetricKey &key, const ByteArray& iv, SymmetricCipher::Operation operation, SymmetricCipher::OperationMode mode);
	
	/**
	 * Destrutor padrão.
	 **/
	virtual ~SymmetricCipher();
	
	/**
	 * @brief Inicializa o cifrador para uso.
	 *
	 * Essa função deve ser usada caso o objeto tenha sido instanciado com o construtor padrão.
	 *
	 * @param key		A chave simétrica a ser usada na operação.
	 * @param iv		O vetor de inicialização do cifrador.
	 * @param operation Determina se é uma operação de cifração ou decifração.
	 * @param mode 		Determina o modo de cifração (operação de bloco).
	 *
	 * @throw SymmetricCipherException caso ocorra algum erro na inicialização do cifrador.
	 **/
	void init(const SymmetricKey& key, const ByteArray& iv, SymmetricCipher::Operation operation, SymmetricCipher::OperationMode mode);
	
	/**
	 * @brief Atualiza o cifrador com os dados passados.
	 *
	 * Essa função inclui o terminador nulo (\0) da string.
	 *
	 * @param data Os dados para serem inseridos no cifrador.
	 *
	 * @return O bloco cifrado. O bloco pode retornar vazio se não houver dados suficientes para fechar um bloco.
	 * @throw SymmetricCipherException
	 */
	ByteArray* update(const std::string& data);

	/**
	 * @brief Atualiza o cifrador com os dados passados.
	 *
	 * @param data Os dados para serem inseridos no cifrador.
	 *
	 * @return O bloco cifrado. O bloco pode retornar vazio se não houver dados suficientes para fechar um bloco.
	 * @throw SymmetricCipherException
	 */
	ByteArray* update(const ByteArray& data);
	
	/**
	 * @brief Atualiza o cifrador com os dados passados.
	 *
	 * @param data Os dados para serem inseridos no cifrador.
	 * @param size O número de bytes a serem inseridos.
	 *
	 * @return O bloco cifrado. O bloco pode retornar vazio se não houver dados suficientes para fechar um bloco.
	 * @throw SymmetricCipherException
	 */
	ByteArray* update(const unsigned char* data, unsigned int size);

	/**
	 * @brief Atualiza o cifrador com os dados passados.
	 *
	 * @param out						Buffer de saída dos dados cifrados.
	 * @param numberOfEncryptedBytes	O número de bytes cifrados.
	 * @param data						Os dados para serem inseridos no cifrador.
	 * @param size						O número de bytes a serem inseridos.
	 *
	 * @return O bloco cifrado. O bloco pode retornar vazio se não houver dados suficientes para fechar um bloco.
	 * @throw SymmetricCipherException
	 */
	void update(unsigned char* out, int* numberOfEncryptedBytes, const unsigned char* data, int size);

	/**
	 * @brief Finaliza o cifrador e retorna o último bloco cifrado/decifrado.
	 *
	 * @return O último bloco cifrado/decifrado. Esse bloco nunca é vazio.
	 * @throw SymmetricCipherException Caso ocorra algum erro na finalização do cifrador.
	 **/	
	ByteArray* doFinal();
	
	/**
	 * @brief Finaliza o cifrador e retorna o último bloco cifrado/decifrado.
	 *
	 * @param out						O buffer pra escrever o último bloco.
	 * @param numberOfEncryptedBytes	O número de bytes cifrados.
	 *
	 * @throw SymmetricCipherException Caso ocorra algum erro na finalização do cifrador.
	 **/
	void doFinal(unsigned char* out, int* numberOfEncryptedBytes);

	/**
	 * @brief Atualiza, finaliza o cifrador e retorna o último bloco cifrado/decifrado.
	 *
	 * Essa função inclui o terminador nulo (\0) da string.
	 *
	 * @param data Os dados para serem inseridos no cifrador.
	 *
	 * @return Os últimos blocos cifrados/decifrados. Esse bloco nunca é vazio.
	 * @throw SymmetricCipherException Caso ocorra algum erro na atualização ou finalização do cifrador.
	 **/
	ByteArray* doFinal(const std::string &data);
	
	/**
	 * @brief Atualiza, finaliza o cifrador e retorna o último bloco cifrado/decifrado.
	 *
	 * @param data Os dados para serem inseridos no cifrador.
	 *
	 * @return Os últimos blocos cifrados/decifrados. Esse bloco nunca é vazio.
	 * @throw SymmetricCipherException Caso ocorra algum erro na atualização ou finalização do cifrador.
	 **/
	ByteArray* doFinal(const ByteArray &data);

	/**
	 * Retorna o modo de operação do cifrador.
	 * @return o modo de operação do cifrador.
	 * @throw InvalidStateException não esteja no esteja no estado apropriado (State::INIT).
	 **/
	SymmetricCipher::OperationMode getOperationMode();
	
	/**
	 * Retorna o tipo de operação do cifrador.
	 * @return o tipo de operação para que o cifrador foi inicializado.
	 * @throw InvalidStateException não esteja no esteja no estado apropriado (State::INIT).
	 **/
	SymmetricCipher::Operation getOperation();
	
	/**
	 * Retorna o nome do modo de operação passado como parâmetro.
	 * @return o nome do modo de operação passado como parâmetro.
	 **/
	static std::string getOperationModeName(SymmetricCipher::OperationMode mode);
	
	/**
	 * Retorna a estrutura OpenSSL que representa um cifrador.
	 * @param algorithm o algoritmo que o cifrador deverá utilizar.
	 * @param mode o modo de operação do algoritmo.
	 * @throw SymmetricCipherException caso ocorra algum erro na criação da estrutura.
	 **/	
	static const EVP_CIPHER* getCipher(SymmetricKey::Algorithm algorithm, SymmetricCipher::OperationMode mode);
	
	/**
	 * Método utilizado para carregar os algoritmos disponíveis na biblioteca OpenSSL.
	 **/
	static void loadSymmetricCiphersAlgorithms();

private:

	/**
	 * @enum State
	 *
	 *  Possíveis estados do builder. 
	 **/
	enum State
	{
		NO_INIT, /*!< estado inicial, quando o builder ainda não foi inicializado. */
		INIT, /*!< estado em que o builder foi inicializado, mas ainda não recebeu dados. */
		UPDATE /*!< estado em que o builder já possui condições para finalizar a operação */
	};
	
	
	/**
	 * Controla o estado do builder.
	 **/
	SymmetricCipher::State state;

	/**
	 * Modo de operação do cifrador.
	 **/
	SymmetricCipher::OperationMode mode;

	/**
	 * Tipo de operação do cifrador.
	 */
	SymmetricCipher::Operation operation;

	/**
	 * Estrutura interna OpenSSL.
	 **/
	EVP_CIPHER_CTX* ctx;

	/**
	 * @brief Gera uma chave e um vetor de incialização.
	 *
	 * Essa função funciona como uma função de derivação de chave (KDF). Ela deriva a chave e o iv
	 * a partir do conteúdo de \p key. A chave e o iv gerados serão compatíveis com o cifrador \p
	 * cipher.
	 *
	 * TODO: Essa função precisa ser revisada para utilizar uma KDF padrão e mais confiável (i.e: PBKDF2).
	 *
	 * @param key		Os dados que serão utilizado para derivar a chave e iv. Normalmente, uma senha.
	 * @param cipher	O cifrador no qual será utilizada a chave e iv derivados. Apenas para definir as regras de formato da chave e iv.
	 * @param md		A função de hash que será utilizada no processo de derivação.
	 * @param salt		O salt para ser usado na derivação (útil contra ataques de rainbow tables pré-calculadas).
	 * @param count		O número de iterações da derivação (útil contra ataques de rainbow tables directionadas).
	 * @return 			Um par contendo a chave e o iv gerados na primeira e segunda posição, respectivamente.
	 **/
	std::pair<ByteArray*, ByteArray*> keyToKeyIv(const ByteArray &key, const EVP_CIPHER *cipher, const EVP_MD* md = EVP_md5(), const unsigned char* salt=0, int count=1);

};

#endif /*SYMMETRICCIPHER_H_*/
