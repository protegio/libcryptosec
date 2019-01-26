#ifndef EXTENDEDKEYUSAGEEXTENSION_H_
#define EXTENDEDKEYUSAGEEXTENSION_H_

#include <libcryptosec/certificate/extension/Extension.h>
#include <libcryptosec/certificate/ObjectIdentifier.h>

#include <openssl/x509.h>

#include <vector>

/**
 * Extended key usage extension abstraction.
 */
class ExtendedKeyUsageExtension : public Extension
{
public:

	/**
	 * @brief Construtor padrão.
	 */
	ExtendedKeyUsageExtension();

	/**
	 * @brief Construtor baseado em uma estrutura X509_EXTENSION.
	 *
	 * @throw CertificationException se a estrutura X509_EXTENSION não representar
	 * 	uma extensão do tipo Extended Key Usage.
	 */
	ExtendedKeyUsageExtension(X509_EXTENSION *ext);

	/**
	 * @brief Destrutor padrão.
	 */
	virtual ~ExtendedKeyUsageExtension();

	/**
	 * @return Retorna apenas o valor da extensão codificado em XML.
	 */
	virtual std::string extValue2Xml(const std::string& tab = "") const;

	/**
	 * @brief Adiciona um OID na lista de extended key usage.
	 *
	 * TODO: validar o OID antes de inserir? usar um enum? verificar RFC5280.
	 *
	 * @param objectIdentifier O OID para ser adicionado.
	 */
	void addUsage(const ObjectIdentifier& objectIdentifier);

	/**
	 * @return Retorna uma cópia da lista e extended key usage.
	 */
	std::vector<ObjectIdentifier> getUsages() const;

	/**
	 * @return Retorna a extensão representada em uma estrutura X509_EXTENSION.
	 */
	X509_EXTENSION* getX509Extension() const;

protected:
	std::vector<ObjectIdentifier> usages;
};

#endif /*EXTENDEDKEYUSAGEEXTENSION_H_*/
