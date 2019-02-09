#ifndef NETSCAPESPKIBUILDER_H_
#define NETSCAPESPKIBUILDER_H_

#include <libcryptosec/certificate/NetscapeSPKI.h>
#include <libcryptosec/asymmetric/PrivateKey.h>
#include <libcryptosec/MessageDigest.h>

/**
 * @defgroup SPKI Classes Relacionadas ao Padrão Netscape SPKI
 */
 
 /**
  * @brief Implementa o padrão builder para a criação de objetos NetscapeSPKI.
  * Estes implementam o padrão de chave pública SPKI da Netscape. 
  * @see NetscapeSPKI.
  *  
  * @ingroup SPKI
  */
 
class NetscapeSPKIBuilder : public NetscapeSPKI
{
public:

	/**
	 * Construtor padrão.
	 * Constroi um objeto NetscapeSPKIBuilder.
	 */
	NetscapeSPKIBuilder();

	/**
	 * Construtor.
	 * Constroi um objeto NetscapeSPKIBuilder a partir de um objeto NetscapeSPKI.
	 * @param NetscapeSPKIBuilder objeto NetscapeSPKI em formato base64.
	 */
	NetscapeSPKIBuilder(const std::string& netscapeSPKIBase64);

	/**
	 * Destrutor.
	 */		
	virtual ~NetscapeSPKIBuilder();
	
	/**
	 * Define chave pública para o objeto NetscapeSPKI.
	 * @param publicKey objeto que representa uma chave pública.
	 */
	void setPublicKey(const PublicKey& publicKey);
	
	/**
	 * Define o desafio do objeto NetscapeSPKI
	 * @param challenge desafio.
	 */
	void setChallenge(const std::string& challenge);
	
	/**
	 * Cria um objeto NetscapeSPKI
	 * @param privateKey chave privada.
	 * @param messageDigest algoritmo de resumo.
	 * @throw NetscapeSPKIException caso ocorra erro interno do OpenSSL ao assinar o objeto NetscapePKI
	 */
	NetscapeSPKI sign(const PrivateKey& privateKey, MessageDigest::Algorithm messageDigest);
};

#endif /*NETSCAPESPKIBUILDER_H_*/
