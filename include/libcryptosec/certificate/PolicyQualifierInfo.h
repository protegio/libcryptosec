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
	
	std::string getXmlEncoded(const std::string& tab = "") const;
	ObjectIdentifier getObjectIdentifier();
	void setCpsUri(std::string cpsUri);
	std::string getCpsUri();
	void setUserNotice(UserNotice userNotice);
	UserNotice getUserNotice();
	PolicyQualifierInfo::Type getType();
	POLICYQUALINFO* getPolicyQualInfo() const;
protected:
	PolicyQualifierInfo::Type type;
	ObjectIdentifier objectIdentifier;
	UserNotice userNotice;
	std::string cpsUri;
	
	void setObjectIdentifier(ObjectIdentifier objectIdentifier);
};

#endif /*POLICYQUALIFIERINFO_H_*/
