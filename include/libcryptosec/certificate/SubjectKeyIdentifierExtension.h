#ifndef SUBJECTKEYIDENTIFIEREXTENSION_H_
#define SUBJECTKEYIDENTIFIEREXTENSION_H_

#include <libcryptosec/certificate/Extension.h>

class SubjectKeyIdentifierExtension : public Extension
{
public:
	SubjectKeyIdentifierExtension();
	SubjectKeyIdentifierExtension(X509_EXTENSION *ext);
	virtual ~SubjectKeyIdentifierExtension();
	/**
	 * @deprecated
	 * Retorna o conteudo da extensão em formato XML.
	 * Esta função será substituida por toXml().
	 * */
	std::string getXmlEncoded();
	std::string getXmlEncoded(std::string tab);
	virtual std::string extValue2Xml(std::string tab = "");
	void setKeyIdentifier(ByteArray keyIdentifier);
	ByteArray getKeyIdentifier() const;
	X509_EXTENSION* getX509Extension();
protected:
	ByteArray keyIdentifier;
};

#endif /*SUBJECTKEYIDENTIFIEREXTENSION_H_*/
