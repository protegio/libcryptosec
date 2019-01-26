#ifndef SUBJECTKEYIDENTIFIEREXTENSION_H_
#define SUBJECTKEYIDENTIFIEREXTENSION_H_

#include <libcryptosec/certificate/extension/Extension.h>

class SubjectKeyIdentifierExtension : public Extension
{
public:
	SubjectKeyIdentifierExtension();
	SubjectKeyIdentifierExtension(const X509_EXTENSION* ext);
	SubjectKeyIdentifierExtension(const SubjectKeyIdentifierExtension& ext);
	SubjectKeyIdentifierExtension(SubjectKeyIdentifierExtension&& ext);

	virtual ~SubjectKeyIdentifierExtension();

	SubjectKeyIdentifierExtension& operator=(const SubjectKeyIdentifierExtension& ext);
	SubjectKeyIdentifierExtension& operator=(SubjectKeyIdentifierExtension&& ext);

	void setKeyIdentifier(const ByteArray& keyIdentifier);
	const ByteArray& getKeyIdentifier() const;

	/**
	 * @deprecated
	 * Retorna o conteudo da extensão em formato XML.
	 * Esta função será substituida por toXml().
	 * */
	std::string getXmlEncoded(const std::string& tab = "") const;
	virtual std::string extValue2Xml(const std::string& tab = "") const;

	X509_EXTENSION* getX509Extension() const;

protected:
	ByteArray keyIdentifier;
};

#endif /*SUBJECTKEYIDENTIFIEREXTENSION_H_*/
