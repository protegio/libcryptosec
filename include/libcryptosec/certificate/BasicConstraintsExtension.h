#ifndef BASICCONSTRAINTSEXTENSION_H_
#define BASICCONSTRAINTSEXTENSION_H_

#include <openssl/x509.h>

#include <libcryptosec/certificate/Extension.h>

#include <string>

class BasicConstraintsExtension : public Extension
{
public:
	BasicConstraintsExtension();
	BasicConstraintsExtension(X509_EXTENSION *ext);
	virtual ~BasicConstraintsExtension();

	virtual std::string extValue2Xml(const std::string& tab = "");
	virtual std::string getXmlEncoded(const std::string& tab = "");

	void setCa(bool value);
	bool isCa() const;

	void setPathLen(long value);
	long getPathLen() const;

	X509_EXTENSION* getX509Extension() const;

protected:
	bool ca;
	long pathLen;
};

#endif /*BASICCONSTRAINTSEXTENSION_H_*/
