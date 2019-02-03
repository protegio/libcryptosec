#ifndef PKCS7SIGNEDDATABUILDER_H_
#define PKCS7SIGNEDDATABUILDER_H_

#include <libcryptosec/pkcs7/Pkcs7Builder.h>

#include <libcryptosec/certificate/Certificate.h>
#include <libcryptosec/pkcs7/Pkcs7SignedData.h>
#include <libcryptosec/MessageDigest.h>

/**
 * Implementa o padrão builder para criação de um pacote PKCS7 assinado digitalmente.
 * @ingroup PKCS7
 **/

class Pkcs7SignedDataBuilder : public Pkcs7Builder
{
	
public:

	/**
	 * Construtor recebendo os parâmetros necessários à assinatura dos dados a serem adicionados
	 * ao pacote. O método Pkcs7SignedDataBuilder::init() é invocado nesse construtor.
	 *
	 * @param messageDigestAlgorithm o algoritmo de hash que será usado na assinatura do pacote.
	 * @param signerCertificate referência para o certificado que será usado para assinar o conteúdo do PKCS7
	 * e irá compor o pacote.
	 * @param signerPrivateKey chave privada que será usada na assinatura do pacote.
	 * @param attached se true, o conteúdo do pacote estará contido no mesmo, caso contrário apenas
	 * a assinatura do conteúdo estará presente.
	 *
	 * @throw Pkcs7Exception caso ocorra algum problema na geração do pacote PKCS7.
	 * @see Pkcs7SignedDataBuilder::init()
	 **/
	Pkcs7SignedDataBuilder(
			MessageDigest::Algorithm messageDigestAlgorithm,
			const Certificate& signerCertificate,
			const PrivateKey& signerPrivateKey,
			bool attached);
				
	
	/**
	 * Destrutor padrão.
	 **/			
	virtual ~Pkcs7SignedDataBuilder();
	
	/**
	 * Método responsável pela inicialização do builder. Após sua invocação, o builder estará pronto
	 * para receber os dados a serem empacotados. Pode ser usado também para reinicializar o mesmo
	 * com a mudança de um ou mais parâmetros.
	 *
	 * @param messageDigestAlgorithm o algoritmo de hash que será usado na assinatura do pacote.
	 * @param signerCertificate referência para o certificado que será usado para assinar o conteúdo do PKCS7
	 * e irá compor o pacote.
	 * @param signerPrivateKey chave privada que será usada na assinatura do pacote.
	 * @param attached se true, o conteúdo do pacote estará contido no mesmo, caso contrário apenas
	 * a assinatura do conteúdo estará presente.
	 *
	 * @throw Pkcs7Exception caso ocorra algum problema na criação do pacote PKCS7.
	 **/	
	void init(
			MessageDigest::Algorithm messageDigestAlgorithm,
			const Certificate& signerCertificate,
			const PrivateKey& signerPrivateKey,
			bool attached);

	/**
	 * Permite a co-assinatura do pacote por mais de uma chave privada.
	 *
	 * @param messageDigestAlgorithm o algoritmo de hash que será usado na assinatura do pacote.
	 * @param signerCertificate referência para o novo certificado que será adicionado como
	 * assinador do pacote.
	 * @param signerPrivateKey chave privada que será usada na co-assinatura do pacote.
	 *
	 * @throw InvalidStateException no caso do builder não ter sido inicializado ainda.
	 * @throw Pkcs7Exception caso tenha ocorrido um erro ao adicionar o certificado ao pacote PKCS7.
	 **/	
	void addSigner(
			MessageDigest::Algorithm messageDigestAlgorithm,
			const Certificate& signerCertificate,
			const PrivateKey& signerPrivateKey);
	
	/**
	 * Permite adicionar certificados adicionais.
	 *
	 * @param cert referência para certificado que será adicionado.
	 *
	 * @throw InvalidStateException no caso do builder não ter sido inicializado ainda.
	 * @throw Pkcs7Exception caso tenha ocorrido um erro ao adicionar o certificado ao pacote PKCS7.
	 */
	void addCertificate(const Certificate& certificate);
	
	/**
	* Permite adicionar lista de certificados revogados
	* @param crl referência para a CRL que será adicionada
	* @throw InvalidStateException no caso do builder não ter sido inicializado ainda.
	* @throw Pkcs7Exception caso tenha ocorrido um erro ao adicionar o certificado ao pacote PKCS7.
	*/
	void addCrl(const CertificateRevocationList& crl);
	
	/**
	 * Especifica o uso das funções da superclasse Pkcs7Builder::doFinal(), recebendo um inputstream e
	 * um outputstream como parâmetros. 
	 * @see Pkcs7Builder::doFinal()
	 **/
	using Pkcs7Builder::doFinal;

	/**
	 * Implementa uma versão distinta do método Pkcs7Builder::doFinal() para gerar o pacote assinado.
	 * @return Pkcs7EnvelopedData o pacote PKCS7 criado.
	 * @throw InvalidStateException caso o builder não esteja no estado apropriado no momento da invocação.
 	 * @throw Pkcs7Exception caso tenha ocorrido um erro na geração do pacote PKCS7.
	 **/	
	Pkcs7SignedData doFinal();

	/**
	 * Implementa uma versão distinta do método Pkcs7Builder::doFinal() para gerar o pacote assinado.
	 * @param data contendo dados a serem concatenados ao conteudo do pacote antes da sua criação definitiva.
	 * @return Pkcs7EnvelopedData o pacote PKCS7 criado.
	 * @throw InvalidStateException caso o builder não esteja no estado apropriado no momento da invocação.
 	 * @throw Pkcs7Exception caso tenha ocorrido um erro na geração do pacote PKCS7.
	 **/	
	Pkcs7SignedData doFinal(const std::string& data);

	/**
	 * Implementa uma versão distinta do método Pkcs7Builder::doFinal() para gerar o pacote assinado.
	 * @param data contendo dados a serem concatenados ao conteudo do pacote antes da sua criação definitiva.
	 * @return Pkcs7EnvelopedData o pacote PKCS7 criado.
	 * @throw InvalidStateException caso o builder não esteja no estado apropriado no momento da invocação.
 	 * @throw Pkcs7Exception caso tenha ocorrido um erro na geração do pacote PKCS7.
	 **/		
	Pkcs7SignedData doFinal(const ByteArray& data);
};

#endif /*PKCS7SIGNEDDATABUILDER_H_*/
