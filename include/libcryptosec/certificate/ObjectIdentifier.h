#ifndef OBJECTIDENTIFIER_H_
#define OBJECTIDENTIFIER_H_

#include <openssl/asn1.h>
#include <openssl/objects.h>

#include <string>

#include <libcryptosec/exception/CertificationException.h>

class ObjectIdentifier
{
public:
	ObjectIdentifier();
	ObjectIdentifier(ASN1_OBJECT *asn1Object);
	ObjectIdentifier(const ASN1_OBJECT *asn1Object);
	ObjectIdentifier(const ObjectIdentifier& objectIdentifier);
	ObjectIdentifier(ObjectIdentifier&& objectIdentifier);

	virtual ~ObjectIdentifier();

	ObjectIdentifier& operator=(const ObjectIdentifier& value);
	ObjectIdentifier& operator=(ObjectIdentifier&& value);

	std::string getXmlEncoded(const std::string& tab = "") const;

	std::string getOid() const;
	int getNid() const;
	std::string getName() const;
	ASN1_OBJECT* getObjectIdentifier() const;

protected:
	ASN1_OBJECT *asn1Object;
};

#endif /*OBJECTIDENTIFIER_H_*/
