#ifndef OBJECTIDENTIFIER_H_
#define OBJECTIDENTIFIER_H_

#include <openssl/asn1.h>
#include <openssl/objects.h>

#include <string>

/**
 * TODO: implement set functions
 */
class ObjectIdentifier
{
protected:
	ObjectIdentifier(ASN1_OBJECT *asn1Object);

public:
	ObjectIdentifier();
	ObjectIdentifier(const ASN1_OBJECT *asn1Object);

	ObjectIdentifier(const ObjectIdentifier& objectIdentifier);
	ObjectIdentifier(ObjectIdentifier&& objectIdentifier);

	virtual ~ObjectIdentifier();

	ObjectIdentifier& operator=(const ObjectIdentifier& value);
	ObjectIdentifier& operator=(ObjectIdentifier&& value);

	/**
	 * @return The OID's short name. If there is no short name, the OID's string representation is returned instead.
	 */
	std::string getShortName() const;

	/**
	 * @return The OID's long name. If there is no long name, the OID's string representation is returned instead.
	 */
	std::string getLongName() const;

	/**
	 * @return The OID's NID. If there is no NID, NID_undef is returned instead.
	 */
	int getNid() const;

	/**
	 * @return The internal reference to ASN1_OBJECT.
	 */
	const ASN1_OBJECT* getAsn1Object() const;

	/**
	 * @return A new ASN1_OBJECT instance.
	 */
	ASN1_OBJECT* getSslObject() const;

	/**
	 * @return The oid numbers as a string.
	 */
	std::string toString() const;
	std::string toXml(const std::string& tab = "") const;

	static ObjectIdentifier fromString(const std::string& oid);
	static ObjectIdentifier fromNid(int nid);
	static ObjectIdentifier fromShortName(const std::string& name);
	static ObjectIdentifier fromLongName(const std::string& name);

protected:
	ASN1_OBJECT *asn1Object;
};

#endif /*OBJECTIDENTIFIER_H_*/
