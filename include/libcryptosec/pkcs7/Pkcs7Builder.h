#ifndef PKCS7BUILDER_H_
#define PKCS7BUILDER_H_

#include <libcryptosec/certificate/CertificateRevocationList.h>
#include <libcryptosec/certificate/Certificate.h>
#include <libcryptosec/MessageDigest.h>
#include <libcryptosec/SymmetricKey.h>
#include <libcryptosec/ByteArray.h>

#include <openssl/bio.h>
#include <openssl/pkcs7.h>
#include <openssl/pem.h>

#include <string>

/**
 * Implementa o padrão builder para a criação de um pacote PKCS7. Essa classe
 * deve ser usada como uma classe abstrata, pois não pussui um método init. 
 * 
 * @see Pkcs7EnvelopedDataBuilder
 * @see Pkcs7SignedDataBuilder
 * @ingroup PKCS7
 **/
class Pkcs7Builder
{
	
public:

	/**
	 * @brief Construtor padrão.
	 *
	 * Cria uma nova estrutura PKCS7.
	 **/	
	Pkcs7Builder();
	
	/**
	 * @brief Destrutor padrão.
	 *
	 * Limpa a estrutura PKCS7.
	 **/
	virtual ~Pkcs7Builder();

	void initData();
	void initDigest(MessageDigest::Algorithm messageDigestAlgorithm);
	void initEncrypted();
	void initSigned(MessageDigest::Algorithm messageDigestAlgorithm);
	void initEnveloped(MessageDigest::Algorithm messageDigestAlgorithm, SymmetricKey::Algorithm symmetricCipherAlgorithm);
	void initEnvelopedAndSigned();

	void addCertificate(const Certificate& certificate);
	void addCrl(const CertificateRevocationList& crl);
	void addSigner(const Certificate& signerCertificate, const PrivateKey& signerPrivateKey);
	void addRecipient(const Certificate& recipientCertificate);

	/**
	 * @brief Concatena novos dados ao pacote PKCS7.
	 *
	 * O terminador nulo (\0) da string também é concatenado.
	 *
	 * @param data Os dados a serem concatenados.
	 *
	 * @throw OperationException Caso ocorra algum erro no procedimento de empacotamento.
	 *
	 * @see State
	 * @see Pkcs7EnvelopedDataBuilder::init()
	 * @see Pkcs7SignedDataBuilder::init()
	 **/
	void update(const std::string& data);
	
	/**
	 * @brief Concatena novos dados ao pacote PKCS7.
	 *
	 * @param data Os dados a serem concatenados.
	 *
	 * @throw OperationException Caso ocorra algum erro no procedimento de empacotamento.
	 *
	 * @see State
	 * @see Pkcs7EnvelopedDataBuilder::init()
	 * @see Pkcs7SignedDataBuilder::init()
	 **/
	void update(const ByteArray& data);
	
	/**
	 * @brief Concatena novos dados ao pacote PKCS7.
	 *
	 * @param data Os dados a serem concatenados.
	 * @param size O numero de bytes a serem concatenados.
	 *
	 * @throw OperationException Caso ocorra algum erro no procedimento de empacotamento.
	 *
	 * @see State
	 * @see Pkcs7EnvelopedDataBuilder::init()
	 * @see Pkcs7SignedDataBuilder::init()
	 **/
	void update(const unsigned char* data, unsigned int size);

	/**
	 * @brief Gera um pacote PKCS7 a partir de de um stream de entrada e escreve o
	 * pacote gerado no formato PEM em um stream de saída.
	 *
	 * @param in Stream de entrada de onde será lido o conteúdo que será adicionado ao pacote PKCS7.
	 * @param out Stream de saída onde será escrito o pacote PKCS7 no formato PEM.
	 *
	 * @throw OperationException caso ocorra algum erro no procedimento de empacotamento.
	 *
	 * @see State
	 * @see Pkcs7EnvelopedDataBuilder::init()
	 * @see Pkcs7SignedDataBuilder::init()
	 **/
	void doFinal(std::istream* in, std::ostream* out);

	/**
	 * @brief Reinicia o estado do objeto.
	 *
	 * Todos buffer são limpos e o estado vai para NO_INIT.
	 */
	virtual void reset();

protected:

	/**
	 * @enum State
	 **/
	/**
	 *  Possíveis estados do builder. 
	 **/
	enum State
	{
		NO_INIT,	/*!< estado inicial, quando o builder ainda não foi inicializado.*/
		INIT,		/*!< estado em que o builder foi inicializado, mas ainda não recebeu dados para adicionar ao pacote PKCS7.*/
		UPDATE,		/*!< estado em que o builder já possui condições para finalizar a criação do pacote através da chamada Pkcs7Builder::doFinal().*/
	};
	
	/**
	 * Estrutura OpenSSL que representa o pacote PKCS7 
	 **/
	PKCS7 *pkcs7;
	
	/**
	 * Estrutura OpenSSL usada na geração do pacote PKCS7
	 **/
	BIO *p7bio;
	
	/**
	 * Estado atual do builder
	 **/
	Pkcs7Builder::State state;

};

#endif /*PKCS7BUILDER_H_*/
