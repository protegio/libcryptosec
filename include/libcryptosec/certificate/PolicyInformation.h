#ifndef POLICYINFORMATION_H_
#define POLICYINFORMATION_H_

#include <libcryptosec/certificate/ObjectIdentifier.h>
#include <libcryptosec/certificate/PolicyQualifierInfo.h>

#include <openssl/asn1.h>
#include <openssl/pem.h>
#include <openssl/x509v3.h>

#include <vector>
#include <string>

class PolicyInformation
{
public:
	PolicyInformation();
	PolicyInformation(const POLICYINFO *policyInfo);

	virtual ~PolicyInformation();
	
	void setPolicyIdentifier(const ObjectIdentifier& policyIdentifier);
	const ObjectIdentifier& getPolicyIdentifier() const;

	void addPolicyQualifierInfo(const PolicyQualifierInfo& policyQualifierInfo);
	const std::vector<PolicyQualifierInfo>& getPoliciesQualifierInfo() const;

	POLICYINFO* getSslObject() const;

	std::string toXml(const std::string& tab = "") const;

protected:
	ObjectIdentifier policyIdentifier;
	std::vector<PolicyQualifierInfo> policyQualifiers; 
};

#endif /*POLICYINFORMATION_H_*/
