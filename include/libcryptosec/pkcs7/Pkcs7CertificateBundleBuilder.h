#ifndef PKCS7CERTIFICATEBUNDLEBUILDER_H_
#define PKCS7CERTIFICATEBUNDLEBUILDER_H_

#include <libcryptosec/pkcs7/Pkcs7CertificateBundle.h>
#include <libcryptosec/pkcs7/Pkcs7Builder.h>
#include <libcryptosec/certificate/Certificate.h>
#include <libcryptosec/ByteArray.h>

#include <openssl/bio.h>
#include <openssl/pkcs7.h>
#include <openssl/pem.h>
#include <openssl/ssl.h>

#include <string>
#include <vector>

/**
 * Implementa o padrão builder para criação de um pacote PKCS7 para disseminação
 * de certificados. De acordo com o openssl, para implementar essa
 * estrutura deve se usar o tipo PKCS7 signed sem incluir signatários. Também serve para
 * guardar apenas dados em texto plano no formato PKCS7
 * @ingroup PKCS7
 **/

class Pkcs7CertificateBundleBuilder : public Pkcs7Builder
{
public:
	/*
	 * @brief Construtor padrão.
	 *
	 * Inicializa os atributos essenciais para a criação do pacote de disseminação.
	 */
	Pkcs7CertificateBundleBuilder();

	/**
	 * @brief Destrutor padrão.
	 */
	virtual ~Pkcs7CertificateBundleBuilder();

	/*
	 * @brief Reinicializa os atributos essenciais para a criação do pacote de
	 * disseminação.
	 */
	void init();

	/*
	 * @brief Adiciona um certificado na pilha.
	 */
	void addCertificate(const Certificate &cert);

	/*
	 * @brief Gera o pacote PKCS7 final
	 */
	Pkcs7CertificateBundle doFinal() const;

private:
	std::vector<Certificate> certificates;
};

#endif /* PKCS7CERTIFICATEBUNDLEBUILDER_H_ */
