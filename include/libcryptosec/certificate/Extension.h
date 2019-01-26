#ifndef EXTENSION_H_
#define EXTENSION_H_

#include <libcryptosec/certificate/ObjectIdentifier.h>
#include <libcryptosec/ByteArray.h>

#include <openssl/x509.h>

#include <string>

class Extension
{
public:
	enum Name
	{
		UNKNOWN,
		KEY_USAGE,
		EXTENDED_KEY_USAGE,
		AUTHORITY_KEY_IDENTIFIER,
		CRL_DISTRIBUTION_POINTS,
		AUTHORITY_INFORMATION_ACCESS,
		BASIC_CONSTRAINTS,
		CERTIFICATE_POLICIES,
		ISSUER_ALTERNATIVE_NAME,
		SUBJECT_ALTERNATIVE_NAME,
		SUBJECT_INFORMATION_ACCESS,
		SUBJECT_KEY_IDENTIFIER,
		CRL_NUMBER,
		DELTA_CRL_INDICATOR
	};
	
	/**
	 * @brief Inicializa a extensão a partir uma estrutura X509_EXTENSION.
	 *
	 * @param ext A estrutura X509_EXTENSION para ser usada na construção.
	 */
	Extension(const X509_EXTENSION *ext);

	/**
	 * @brief Inicializa a extensão a partir dos campos passados.
	 *
	 * @param oid O OID da extensão.
	 * @param critical Identifica se a extensão deve ser marcada como crítica ou não.
	 * @param valueBase64 O valor da extensão codificado em base 64.
	 */
	Extension(const std::string& oid, bool critical, const std::string& valueBase64);

	/**
	 * @brief Destrutor padrão.
	 */
	virtual ~Extension();
	
	/**
	 * @deprecated
	 * Retorna o conteudo da extensão em formato XML.
	 * Esta função será substituida por toXml().
	 * */
	virtual std::string getXmlEncoded(const std::string& tab = "") const;
	std::string toXml(const std::string& tab = "") const;

	virtual std::string extValue2Xml(const std::string& tab = "") const;
	ObjectIdentifier getObjectIdentifier() const;
	std::string getName() const;
	Extension::Name getTypeName() const;
	ByteArray getValue() const;
	std::string getBase64Value() const;
	void setCritical(bool critical);
	bool isCritical() const;
	virtual X509_EXTENSION* getX509Extension() const;
	static Extension::Name getName(int nid);
	static Extension::Name getName(X509_EXTENSION *ext);

protected:
	Extension();

	ObjectIdentifier objectIdentifier;
	bool critical;
	ByteArray value;
};

#endif /*EXTENSION_H_*/
