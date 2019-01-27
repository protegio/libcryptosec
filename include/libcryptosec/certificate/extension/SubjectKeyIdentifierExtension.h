#ifndef SUBJECTKEYIDENTIFIEREXTENSION_H_
#define SUBJECTKEYIDENTIFIEREXTENSION_H_

#include <libcryptosec/certificate/extension/Extension.h>

class SubjectKeyIdentifierExtension : public Extension
{
public:
	SubjectKeyIdentifierExtension();
	SubjectKeyIdentifierExtension(const X509_EXTENSION* ext);
	virtual ~SubjectKeyIdentifierExtension();

	void setKeyIdentifier(const ByteArray& keyIdentifier);
	const ByteArray& getKeyIdentifier() const;

	virtual std::string extValue2Xml(const std::string& tab = "") const;

	virtual X509_EXTENSION* getX509Extension() const;

protected:
	ByteArray keyIdentifier;
};

#endif /*SUBJECTKEYIDENTIFIEREXTENSION_H_*/
