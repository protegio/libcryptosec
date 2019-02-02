#ifndef POLICYQUALIFIERINFO_H_
#define POLICYQUALIFIERINFO_H_

#include <openssl/asn1.h>
#include <openssl/x509.h>
#include <openssl/x509v3.h>

#include <string>

#include <libcryptosec/certificate/ObjectIdentifier.h>
#include <libcryptosec/certificate/UserNotice.h>

class PolicyQualifierInfo
{
public:
	enum Type
	{
		UNDEFINED,
		CPS_URI,
		USER_NOTICE,
	};

	PolicyQualifierInfo();
	PolicyQualifierInfo(const POLICYQUALINFO *policyQualInfo);

	virtual ~PolicyQualifierInfo();
	
	const ObjectIdentifier& getObjectIdentifier() const;

	void setCpsUri(const std::string& cpsUri);
	const std::string& getCpsUri() const;

	void setUserNotice(const UserNotice& userNotice);
	const UserNotice& getUserNotice() const;

	PolicyQualifierInfo::Type getType() const;

	POLICYQUALINFO* getSslObject() const;

	std::string toXml(const std::string& tab = "") const;
protected:
	PolicyQualifierInfo::Type type;
	ObjectIdentifier objectIdentifier;
	UserNotice userNotice;
	std::string cpsUri;
	
	void setObjectIdentifier(const ObjectIdentifier& objectIdentifier);
};

#endif /*POLICYQUALIFIERINFO_H_*/
