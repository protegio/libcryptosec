#ifndef RSAPUBLICKEY_H_
#define RSAPUBLICKEY_H_

#include <libcryptosec/PublicKey.h>

#include <string>

class ByteArray;

/**
 * @brief Representa uma chave pública RSA.
 *
 * Para a criação de chaves assimetricas a classe KeyPair deve ser consultada.
 *
 * @see KeyPair
 * @ingroup AsymmetricKeys
 **/

class RSAPublicKey : public PublicKey
{
	
public:

	/**
	 * @brief Construtor para uso interno recebendo um ponteiro para a estrutura OpenSSL EVP_PKEY.
	 *
	 * @param key Ponteiro para a estrutura OpenSSL EVP_PKEY.
	 *
	 * @throw AsymmetricKeyException Caso a estrutura EVP_PKEY não seja uma estrutura
	 * OpenSSL válida ou ocorra algum problema na sua carga.
	 **/
	RSAPublicKey(const EVP_PKEY* key);
	
	/**
	 * @brief Construtor recebendo a representação da chave pública no formato DER.
	 *
	 * @param derEncoded Chave pública codificada no formato DER.
	 *
	 * @throw EncodeException Caso tenha ocorrido um erro com a decodificação do DER.
	 * @throw AsymmetricKeyException Caso ocorra um erro na criação da chave.
	 **/
	RSAPublicKey(ByteArray &derEncoded);
	
	/**
	 * @brief Construtor recebendo a representação da chave pública no formato PEM.
	 *
	 * @param pemEncoded Chave pública codificada no formato PEM.
	 *
	 * @throw EncodeException Caso tenha ocorrido um erro com a decodificação do PEM.
	 * @throw AsymmetricKeyException Caso ocorra um erro na criação da chave.
	 **/			
	RSAPublicKey(std::string &pemEncoded);
	
	/**
	 * @brief Destrutor padrão, limpa a estrutura interna EVP_PKEY.
	 **/		
	virtual ~RSAPublicKey();
};

#endif /*RSAPUBLICKEY_H_*/
