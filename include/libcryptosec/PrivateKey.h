#ifndef PRIVATEKEY_H_
#define PRIVATEKEY_H_

#include <libcryptosec/SymmetricCipher.h>
#include <libcryptosec/AsymmetricKey.h>

class SymmetricKey;
class ByteArray;

/**
 * @brief Representa uma chave privada.
 *
 * Para a criação de chaves assimetricas a classe KeyPair deve ser consultada.
 *
 * @see KeyPair 
 * @ingroup AsymmetricKeys
 **/

class PrivateKey : public AsymmetricKey
{
	
public:

	/**
	 * @brief Constrói uma PrivateKey a partir de uma EVP_PKEY.
	 *
	 * Esse construtor toma conta da referência em \p key e o desaloca no destrutor.
	 *
	 * @param key Ponteiro para a estrutura OpenSSL EVP_PKEY.
	 *
	 * @throw AsymmetricKeyException Caso a estrutura EVP_PKEY não seja uma estrutura
	 * OpenSSL válida ou ocorra algum problema na sua carga.
	 **/
	PrivateKey(const EVP_PKEY *key);

	/**
	 * @brief Constrói uma PrivateKey a partir de uma chave codifica em DER.
	 *
	 * @param key derEncoded Chave privada codificada no formato DER.
	 *
	 * @throw EncodeException Caso não seja possível decodificar a chave.
	 **/
	PrivateKey(const ByteArray& derEncoded);
		
	/**
	 * @brief Constrói uma PrivateKey a partir de uma chave codifica em PEM.
	 *
	 * @param key pemEncoded Chave privada codificada no formato PEM.
	 *
	 * @throw EncodeException Caso não seja possível decodificar a chave.
	 **/
	PrivateKey(const std::string& pemEncoded);
			
	/**
	 * @brief Constrói uma PrivateKey a partir de uma chave codifica em PEM
	 * em formato cifrado por senha.
	 *
	 * @param key pemEncoded Chave privada codificada no formato PEM.
	 * @param passphrase senha que permitirá a decodificação e abertura da chave.
	 *
	 * @throw EncodeException Caso não seja possível decodificar a chave.
	 **/
	PrivateKey(const std::string& pemEncoded, const ByteArray& passphrase);
			
	/**
	 * @brief Destrutor padrão, desaloca a estrutura interna EVP_PKEY
	 **/
	virtual ~PrivateKey();
	
	/**
	 * @brief Retorna a representação da chave no formato PEM.
	 *
	 * @return a chave privada codificada em PEM.
	 * @throw EncodeException caso ocorra um erro na codificação da chave.
	 **/	
	std::string getPemEncoded();
	
	/**
	 * @brief Retorna a representação da chave no formato PEM cifrada com uma chave simétrica.
	 *
	 * @param passphrase A senha que cifrará a chave codificada em PEM.
	 * @param mode O algoritmo simétrico que será usado para proteger a chave privada.
	 *
	 * @return A chave privada codificada em PEM.
	 * @throw EncodeException Caso ocorra um erro na codificação da chave.
	 * @throw SymmetricCipherException Caso o algoritmo escolhido não seja suportado ou seja
	 * inválido.
	 */
	std::string getPemEncoded(const SymmetricKey& symmetricKey, SymmetricCipher::OperationMode mode);
	
	/**
	 * @brief Retorna a representação da chave no formato DER.
	 *
	 * @return a chave privada codificada em DER.
	 * @throw EncodeException caso ocorra um erro na codificação da chave.
	 **/
	ByteArray* getDerEncoded();
		
protected:

	/**
	 * Método usado em formas alternativas de obter a senha para abrir a chave privada.
	 * @param buf
	 * @param size
	 * @param rwflag
	 * @param u
	 **/
	static int passphraseCallBack(char* buf, int size, int rwflag, void* u);

};

#endif /*PRIVATEKEY_H_*/
