#ifndef PUBLICKEY_H_
#define PUBLICKEY_H_

#include <libcryptosec/asymmetric/AsymmetricKey.h>

#include <libcryptosec/ByteArray.h>

#include <string>

#include <openssl/evp.h>


/**
 * Representa uma chave pública.
 * Para a criação de chaves assimetricas a classe KeyPair deve ser consultada.
 * @see KeyPair
 * @ingroup AsymmetricKeys
 **/

class PublicKey : public AsymmetricKey
{
	
public:

	/**
	 * Construtor para uso interno recebendo um ponteiro para a estrutura OpenSSL EVP_PKEY.
	 * @param key ponteiro para a estrutura OpenSSL EVP_PKEY.
	 * @throw AsymmetricKeyException caso a estrutura EVP_PKEY não seja uma estrutura
	 * OpenSSL válida ou ocorra algum problema na sua carga.
	 **/
	PublicKey(const EVP_PKEY* key);

	/**
	 * Construtor recebendo a representação da chave pública no formato DER.
	 * @param derEncoded chave pública codificada no formato DER.
	 * @throw EncodeException caso tenha ocorrido um erro com a decodificação do DER.
	 **/
	PublicKey(const ByteArray& derEncoded);

	/**
	 * Construtor recebendo a representação da chave pública no formato PEM.
	 * @param pemEncoded chave pública codificada no formato PEM.
	 * @throw EncodeException caso tenha ocorrido um erro com a decodificação do PEM.
	 **/	
	PublicKey(const std::string& pemEncoded);

	/**
	 * Destrutor padrão, limpa a estrutura interna EVP_PKEY
	 **/
	virtual ~PublicKey();

	/**
	 * Retorna a representação da chave no formato PEM.
	 * @return a chave pública codificada em PEM.
	 * @throw EncodeException caso ocorra um erro na codificação da chave.
	 **/
	std::string getPemEncoded() const;

	/**
	 * Retorna a representação da chave no formato DER.
	 * @return a chave pública codificada em DER.
	 * @throw EncodeException caso ocorra um erro na codificação da chave.
	 **/
	ByteArray getDerEncoded() const;

	/**
	 * @return hash sha1 da chave. 
	 */	
	ByteArray getKeyIdentifier() const;
};

#endif /*PUBLICKEY_H_*/
