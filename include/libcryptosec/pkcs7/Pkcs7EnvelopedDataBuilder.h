#ifndef PKCS7ENVELOPEDDATABUILDER_H_
#define PKCS7ENVELOPEDDATABUILDER_H_

#include <libcryptosec/pkcs7/Pkcs7Builder.h>
#include <libcryptosec/pkcs7/Pkcs7EnvelopedData.h>
#include <libcryptosec/SymmetricKey.h>
#include <libcryptosec/SymmetricCipher.h>

#include <string>

class Certificate;
class ByteArray;


/**
 * Implementa o padrão builder para criação de um pacote PKCS7 envelopado com o uso de criptografia.
 * @ingroup PKCS7
 **/
class Pkcs7EnvelopedDataBuilder : public Pkcs7Builder
{
	
public:

	/**
	 * Construtor de iniciaização.
	 *
	 * Chama o método Pkcs7EnvelopedDataBuilder::init().
	 *
	 * @param cert Certificado que será usado para proteger o conteúdo do PKCS7.
	 * @param symAlgorithm O algoritmo simétrico que everá ser usado na envelopagem do pacote.
	 * @param symOperationMode O modo de operação necessário para alguns cifradores, deve ser
	 * 	SymmetricCipher::NO_MODE para algoritmos que não precisem desse parâmetro.
	 *
 	 * @throw OperationException Caso ocorra um erro na inicialização.
	 *
	 * @see Pkcs7EnvelopedDataBuilder::init()
	 **/	 
	Pkcs7EnvelopedDataBuilder(
			const Certificate& cert,
			SymmetricKey::Algorithm symAlgorithm,
			SymmetricCipher::OperationMode symOperationMode);
			
	/**
	 * Destrutor padrão.
	 **/		
	virtual ~Pkcs7EnvelopedDataBuilder();
		
	/**
	 * @brief Inicializa o builder.
	 *
	 * Método responsável pela inicialização do builder. Após sua invocação, o builder estará pronto
	 * para receber os dados a serem empacotados. Pode ser usado também para reinicializar o mesmo
	 * com a mudança de um ou mais parâmetros.
	 *
	 * @param cert Certificado que será usado para proteger o conteúdo do PKCS7.
	 * @param symAlgorithm O algoritmo simétrico que everá ser usado na envelopagem do pacote.
	 * @param symOperationMode O modo de operação necessário para alguns cifradores, deve ser
	 * 	SymmetricCipher::NO_MODE para algoritmos que não precisem desse parâmetro.
	 *
 	 * @throw OperationException Caso ocorra um erro na inicialização.
	 *
	 * @see Pkcs7EnvelopedDataBuilder::init()
	 **/	
	void init(
			const Certificate& cert,
			SymmetricKey::Algorithm symAlgorithm,
			SymmetricCipher::OperationMode symOperationMode);
	
	/**
	 * @brief Adiciona um certificado para cifrar o pacote PKCS7.
	 *
	 * Permite a adição de novos certificados cujas chaves privadas correspondentes estarão aptas a 
	 * abrir o pacote PKCS7.
	 *
	 * @param certificate referência para o novo certificado que estará apto a abrir o pacote.
	 *
 	 * @throw OperationException Caso ocorra um erro na adição do certificado cifrador.
	 **/		
	void addCipher(const Certificate& certificate);
	
	/**
	 * Especifica o uso das funções da superclasse Pkcs7Builder::doFinal(), recebendo um inputstream e
	 * um outputstream como parâmetros. 
	 *
	 * @see Pkcs7Builder::doFinal()
	 **/
	using Pkcs7Builder::doFinal;
	
	/**
	 * Implementa uma versão distinta do método Pkcs7Builder::doFinal() para gerar o pacote envelopado.
	 *
	 * @return Pkcs7EnvelopedData o pacote PKCS7 criado.
	 *
 	 * @throw OperationException Caso ocorra um erro na geração do pacote PKCS7.
	 **/
	Pkcs7EnvelopedData doFinal();
	
	/**
	 * Implementa uma versão distinta do método Pkcs7Builder::doFinal() para gerar o pacote envelopado.
	 *
	 * @param data Dados a serem concatenados ao conteudo do pacote antes da sua criação definitiva.
	 *
	 * @return Pkcs7EnvelopedData O pacote PKCS7 criado.
	 *
 	 * @throw OperationException Caso ocorra um erro na geração do pacote PKCS7.
	 **/		
	Pkcs7EnvelopedData doFinal(const std::string& data);
			
	/**
	 * Implementa uma versão distinta do método Pkcs7Builder::doFinal() para gerar o pacote envelopado.
	 *
	 * @param data Dados a serem concatenados ao conteudo do pacote antes da sua criação definitiva.
	 *
	 * @return Pkcs7EnvelopedData O pacote PKCS7 criado.
	 *
 	 * @throw OperationException Caso ocorra um erro na geração do pacote PKCS7.
	 **/
	Pkcs7EnvelopedData doFinal(const ByteArray& data);
			
};

#endif /*PKCS7ENVELOPEDDATABUILDER_H_*/
