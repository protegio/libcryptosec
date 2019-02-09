#ifndef PKCS7_H_
#define PKCS7_H_

#include <libcryptosec/certificate/CertificateRevocationList.h>
#include <libcryptosec/certificate/Certificate.h>
#include <libcryptosec/certificate/CertPathValidatorResult.h>
#include <libcryptosec/certificate/ValidationFlags.h>
#include <libcryptosec/ByteArray.h>

#include <openssl/pem.h>
#include <openssl/pkcs7.h>

#include <string>
#include <vector>

/**
 * @defgroup PKCS7 Classes relacionadas ao uso de pacotes PKCS7
 **/
 
 /** 
 * Classe abstrata que implementa a especificação PKCS#7 para empacotamento de conteúdo 
 * utilizando criptografia assimétrica. 
 * @see Pkcs7Factory
 * @see Pkcs7EnvelopedData
 * @see Pkcs7SignedData
 * @see Pkcs7Builder
 * @see Pkcs7EnvelopedDataBuilder 
 * @see Pkcs7SignedDataBuilder 
 * @ingroup PKCS7
 **/
 
class Pkcs7
{

public:

	/**
	 * @enum Type
	 **/
	/**
	 * Determina o tipo de procedimento criptográfico aplicado ao pacote, podendo ser SIGNED
	 * caso o conteúdo esteja assinado ou ENVELOPED caso o conteúdo esteja criptografado.
	 **/
	enum Type
	{
		SIGNED = NID_pkcs7_signed, /*!< O pacote é assinado */
		ENVELOPED = NID_pkcs7_enveloped, /*!< O pacote é envelopado */
		SIGNED_AND_ENVELOPED = NID_pkcs7_signedAndEnveloped, /*!< O pacote é assinado e envelopado */
		ENCRYPTED = NID_pkcs7_encrypted, /*!< O pacote é cifrado */
		DATA = NID_pkcs7_data, /*!< O pacote é em claro */
		DIGESTED = NID_pkcs7_digest /*!< O pacote inclui o hash dos dados */
	};
	
	/**
	 * @brief Construtor de inicialização por atribuição.
	 *
	 * O argumento \p pkcs7 não deve ser desalocado após a construção do objeto.
	 *
	 * @param pkcs7 A estrutura PKCS7 que será atribuída ao objeto.
	 */
	Pkcs7(PKCS7* pkcs7);
	
	/**
	 * @brief Construtor de inicialização por cópia.
	 *
	 * O argumento \p pkcs7 pode ser desalocado após a construção do objeto.
	 *
	 * @param pkcs7 A estrutura PKCS7 que será copiada.
	 */
	Pkcs7(const PKCS7* pkcs7);

	/**
	 * @brief Inicializa o objeto a partir de um PKCS7 codificado em PEM.
	 *
	 * @param pemEncoded O PKCS7 codificado em PEM.
	 */
	Pkcs7(const std::string& pemEncoded);

	/**
	 * @brief Inicializa o objeto a partir de um PKCS7 codificado em DER.
	 *
	 * @param derEncoded O PKCS7 codificado em DER.
	 */
	Pkcs7(const ByteArray& derEncoded);

	/**
	 * @brief Construtor de cópia.
	 *
	 * @param pkcs7 O objeto Pkcs7 a ser copiado.
	 */
	Pkcs7(const Pkcs7& pkcs7);

	/**
	 * @brief Construtor por movimentação de atributos.
	 *
	 * @param pkcs7 O objeto Pkcs7 que terá os atributos movidos.
	 */
	Pkcs7(Pkcs7&& pkcs7);

	/**
	 * @brief Destrutor padrão.
	 *
	 * Desaloca a estrutura OpenSSL PKCS7 da memória.
	 **/
	virtual ~Pkcs7();

	/**
	 * @brief Operador de atribuição por cópia.
	 *
	 * @param pkcs7 O objeto Pkcs7 a ser copiado.
	 *
	 * @return A cópia do objeto Pkcs7.
	 */
	Pkcs7& operator=(const Pkcs7& pkcs7);

	/**
	 * @brief Operador de atribuição por movimentação de atributos.
	 *
	 * @param pkcs7 O objeto Pkcs7 a ser movido.
	 *
	 * @return O objeto Pkcs7 com os atributos movidos.
	 */
	Pkcs7& operator=(Pkcs7&& pkcs7);

	/**
	 * @return O tipo do PKCS7.
	 *
	 * @see Pkcs7::Type
	 **/
	virtual Pkcs7::Type getType() const;
	
	/**
	 * @return O PKCS7 codificado em PEM.
	 **/
	std::string getPemEncoded() const;
	
	/**
	 * @return O PKCS7 codificado em DER.
	 **/
	ByteArray getDerEncoded() const;

	/*
	 * @brief Extrai o texto plano contido no pacote PKCS7.
	 *
	 * @param out A stream onde será escrito o texto extraído.
	 */
	void extract(std::ostream& out);

	/**
	 * @brief Decifra o pacote usando os parâmetros certificate e privateKey e escreve o resultado
	 * no stream de saída \p out.
	 *
	 * @param certificate O certificado contendo a chave ou uma das chaves que cifraram o pacote.
	 * @param privateKey A chave privada correspondente ao certificado.
	 * @param out O stream de saída onde será escrito o resultado da decifragem.
	 **/
	void decrypt(const Certificate& certificate, const PrivateKey& privateKey, std::ostream& out);

	/**
	 * @brief Decifra um PKCS7 do tipo ENCRYPTED.
	 *
	 * @param key A chave simétrica para ser usada na decifração.
	 */
	void decrypt(const SymmetricKey& key, std::ostream& out);

	/*
	 * Verifica a assinatura e/ou a integridade do pacote PKCS7
	 * @return true se o pacote é íntegro e/ou suas assinaturas são válidas
	 * @param checkSignerCert true para verificar as assinaturas do pacote, false caso contrário
	 * @param trusted certificados confiáveis
	 * @param cpvr objeto resultado da verificação das assinaturas
	 * @flags opções de validação (ver CertPathValidator::ValidationFlags)
	 */
	bool verify(
			bool checkSignerCert = false,
			const std::vector<Certificate>& trusted = std::vector<Certificate>(),
			CertPathValidatorResult **cpvr = NULL,
			const std::vector<ValidationFlags>& flags = std::vector<ValidationFlags>());

	bool verify(
			const Certificate& certificate,
			const PrivateKey& privateKey,
			bool checkSignerCert = false,
			const std::vector<Certificate>& trusted = std::vector<Certificate>(),
			CertPathValidatorResult **cpvr = NULL,
			const std::vector<ValidationFlags>& flags = std::vector<ValidationFlags>());

	/**
	 * Verifica a integridade do pacote PKCS7 e extrai seu conteúdo para o stream de saída
	 * passado como parâmetro.
	 * @param out o stream que receberá o conteúdo extraído.
	 * @return false se o pacote tiver sido corrompido, true caso contrário.
	 * @throw Pkcs7Exception caso a estrutura PKCS7 seja inválida.
	 **/
	bool verifyAndExtract(
			std::ostream& out,
			bool checkSignerCert = false,
			const std::vector<Certificate>& trusted = std::vector<Certificate>(),
			CertPathValidatorResult **cpvr = NULL,
			const std::vector<ValidationFlags>& flags = std::vector<ValidationFlags>());

	/**
	 * @return A lista de certificados contida no PKCS7.
	 */
	std::vector<Certificate> getCertificates() const;

	/**
	 * @return A lista de CRLs contida no PKCS7.
	 */
	std::vector<CertificateRevocationList> getCrls() const;

	/**
	 * @brief Função callback de tratamento de erro de validação de assinaturas.
	 *
	 * @param ok resultado da verificação
	 * @param ctx contexto de certificado
	 *
	 * @return 1 para warning 0 para erro.
	 */
	static int callback(int ok, X509_STORE_CTX *ctx);

protected:

	/**
	 * @brief Returns a BIO to read the PKCS7's decryted data from.
	 *
	 * This functions is based on OpenSSL's PKCS7_dataDecode function (pkcs7_doit.c file).
	 * Different from PKCS7_dataDecode, this functions is strictly used for decrypting
	 * ENCRYPTED PKCS7. We have to implement this functions because Openssl doesnt't
	 * provide a decrypt function for ENCRYPTED PKCS7.
	 *
	 * @param pkcs7 The pkcs7 to be decrypted.
	 * @param in_bio The recipients's private key.
	 * @param key The detached data to be decrypted. Use NULL if the data is attached to the PKCS7.
	 * @param keySize The recipient's certificate.
	 *
	 * @return The BIO to read the decryted data from or NULL if an error occurs.
	 */
	BIO* decryptInit(PKCS7 *p7, BIO *in_bio, unsigned char* key, unsigned int keySize) const;

	/**
	 *
	 */
	int verify(const Certificate& certificate, const PrivateKey& privateKey,
			PKCS7 *p7, STACK_OF(X509) *certs, X509_STORE *store,
			BIO *indata, BIO *out, int flags) const;

	X509_STORE* newX509Store(
			const std::vector<Certificate>& trusted,
			CertPathValidatorResult **cpvr,
			const std::vector<ValidationFlags>& flags);

	STACK_OF(X509)* getSigners(PKCS7* p7, STACK_OF(X509)* certs, int flags) const;

	/**
	 * Ponteiro para a estrutura PKCS7 da biblioteca OpenSSL
	 **/
	PKCS7 *pkcs7;
	
	static CertPathValidatorResult cpvr;

};

#endif /*PKCS7_H_*/
