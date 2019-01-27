#ifndef CRLNUMBEREXTENSION_H_
#define CRLNUMBEREXTENSION_H_

#include <libcryptosec/certificate/extension/Extension.h>

#include <libcryptosec/BigInteger.h>

class CRLNumberExtension : public Extension
{
public:
	CRLNumberExtension(const BigInteger& serial = 0);
	CRLNumberExtension(const X509_EXTENSION* ext);

	virtual ~CRLNumberExtension();

	void setSerial(const BigInteger& serial);
	const BigInteger& getSerial() const;

	virtual std::string extValue2Xml(const std::string& tab = "") const;

	virtual X509_EXTENSION* getX509Extension() const;
	
protected:
	BigInteger serial;
};

#endif /*CRLNUMBEREXTENSION_H_*/
