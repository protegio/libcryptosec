#ifndef AUTHORITYKEYIDENTIFIEREXTENSION_H_
#define AUTHORITYKEYIDENTIFIEREXTENSION_H_

#include <libcryptosec/certificate/extension/Extension.h>
#include <libcryptosec/certificate/GeneralNames.h>
#include <libcryptosec/BigInteger.h>

class AuthorityKeyIdentifierExtension : public Extension
{
public:
	AuthorityKeyIdentifierExtension();
	AuthorityKeyIdentifierExtension(const X509_EXTENSION* ext);

	virtual ~AuthorityKeyIdentifierExtension();

	void setKeyIdentifier(const ByteArray& keyIdentifier);
	const ByteArray& getKeyIdentifier() const;

	void setAuthorityCertIssuer(const GeneralNames& generalNames);
	const GeneralNames& getAuthorityCertIssuer() const;

	void setAuthorityCertSerialNumber(const BigInteger& serialNumber);
	const BigInteger& getAuthorityCertSerialNumber() const;

	virtual std::string extValue2Xml(const std::string& tab = "") const;

	virtual X509_EXTENSION* getX509Extension() const;

protected:
	ByteArray keyIdentifier;
	GeneralNames authorityCertIssuer;
	BigInteger serialNumber;
};

#endif /*AUTHORITYKEYIDENTIFIEREXTENSION_H_*/
