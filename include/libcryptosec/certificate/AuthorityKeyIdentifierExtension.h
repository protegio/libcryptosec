#ifndef AUTHORITYKEYIDENTIFIEREXTENSION_H_
#define AUTHORITYKEYIDENTIFIEREXTENSION_H_

#include <libcryptosec/certificate/Extension.h>
#include <libcryptosec/certificate/GeneralNames.h>

#include <openssl/x509.h>

#include <string>

class AuthorityKeyIdentifierExtension : public Extension
{
public:
	AuthorityKeyIdentifierExtension();
	AuthorityKeyIdentifierExtension(X509_EXTENSION *ext);
	virtual ~AuthorityKeyIdentifierExtension();
	/**
	 * @deprecated
	 * Retorna o conteudo da extensão em formato XML.
	 * Esta função será substituida por toXml().
	 * */
	std::string getXmlEncoded();
	std::string getXmlEncoded(std::string tab);
	std::string extValue2Xml(std::string tab = "");
	void setKeyIdentifier(ByteArray keyIdentifier);
	ByteArray getKeyIdentifier();
	void setAuthorityCertIssuer(GeneralNames &generalNames);
	GeneralNames getAuthorityCertIssuer();
	void setAuthorityCertSerialNumber(long serialNumber);
	long getAuthorityCertSerialNumber();
	X509_EXTENSION* getX509Extension();
protected:
	ByteArray keyIdentifier;
	GeneralNames authorityCertIssuer;
	long serialNumber;
};

#endif /*AUTHORITYKEYIDENTIFIEREXTENSION_H_*/
