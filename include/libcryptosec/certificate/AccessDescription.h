#ifndef ACCESSDESCRIPTION_H_
#define ACCESSDESCRIPTION_H_

#include <openssl/x509v3.h>
#include <libcryptosec/certificate/ObjectIdentifier.h>
#include <libcryptosec/certificate/GeneralName.h>

class AccessDescription {
public:
	AccessDescription();
	AccessDescription(const ACCESS_DESCRIPTION* accessDescription);

	virtual ~AccessDescription();

	void setAccessLocation(const GeneralName& accessLocation);
	void setAccessMethod(const ObjectIdentifier& accessMethod);

	const GeneralName& getAccessLocation() const;
	const ObjectIdentifier& getAccessMethod() const;
	
	virtual std::string getXmlEncoded(const std::string& tab = "") const;
	ACCESS_DESCRIPTION* getSslObject() const;

private:
	GeneralName accessLocation;
	ObjectIdentifier accessMethod;
};

#endif /* ACCESSDESCRIPTION_H_ */
