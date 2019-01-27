#ifndef BASICCONSTRAINTSEXTENSION_H_
#define BASICCONSTRAINTSEXTENSION_H_

#include <libcryptosec/certificate/extension/Extension.h>

class BasicConstraintsExtension : public Extension
{
public:
	BasicConstraintsExtension();
	BasicConstraintsExtension(const X509_EXTENSION* ext);

	virtual ~BasicConstraintsExtension();

	void setCa(bool value);
	bool isCa() const;

	void setPathLen(long value);
	long getPathLen() const;

	virtual std::string extValue2Xml(const std::string& tab = "") const;

	virtual X509_EXTENSION* getX509Extension() const;

protected:
	bool ca;
	long pathLen;
};

#endif /*BASICCONSTRAINTSEXTENSION_H_*/
