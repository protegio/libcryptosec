#ifndef ECDSAPUBLICKEY_H_
#define ECDSAPUBLICKEY_H_

#include <libcryptosec/PublicKey.h>

#include <string>

class ByteArray;

/**
 * @brief Representa uma chave pública ECDSA.
 *
 * Para a criação de chaves assimetricas a classe KeyPair deve ser consultada.
 *
 * @see KeyPair
 * @ingroup AsymmetricKeys
 **/

class ECDSAPublicKey : public PublicKey
{
	
public:

	/**
	 * Construtor para uso interno recebendo um ponteiro para a estrutura OpenSSL EVP_PKEY.
	 * @param key ponteiro para a estrutura OpenSSL EVP_PKEY. 
	 * @throw AsymmetricKeyException caso a estrutura EVP_PKEY não seja uma estrutura
	 * OpenSSL válida ou ocorra algum problema na sua carga.
	 **/
	ECDSAPublicKey(EVP_PKEY* key);

	/**
	 * Construtor recebendo a representação da chave pública no formato DER.
	 * @param derEncoded chave pública codificada no formato DER.
	 * @throw EncodeException caso tenha ocorrido um erro com a decodificação do DER.
	 * @throw AsymmetricKeyException caso ocorra um erro na criação da chave.
	 **/
	ECDSAPublicKey(const ByteArray& derEncoded);

	/**
	 * Construtor recebendo a representação da chave pública no formato PEM.
	 * @param pemEncoded chave pública codificada no formato PEM.
	 * @throw EncodeException caso tenha ocorrido um erro com a decodificação do PEM.
	 * @throw AsymmetricKeyException caso ocorra um erro na criação da chave.
	 **/
	ECDSAPublicKey(const std::string& pemEncoded);
	
	/**
	 * Destrutor padrão, limpa a estrutura interna EVP_PKEY
	 **/
	virtual ~ECDSAPublicKey();

};

#endif /*ECDSAPUBLICKEY_H_*/
