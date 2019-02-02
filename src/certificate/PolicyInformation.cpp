#include <libcryptosec/certificate/PolicyInformation.h>

#include <libcryptosec/Macros.h>
#include <libcryptosec/exception/CertificationException.h>

PolicyInformation::PolicyInformation()
{
}

PolicyInformation::PolicyInformation(const POLICYINFO *policyInfo)
{
	THROW_DECODE_ERROR_IF(policyInfo == NULL);

	this->policyIdentifier = ObjectIdentifier((const ASN1_OBJECT*) policyInfo->policyid);

	int num = sk_POLICYQUALINFO_num(policyInfo->qualifiers);
	for (int i = 0; i < num; i++) {
		const POLICYQUALINFO *sslObject = sk_POLICYQUALINFO_value(policyInfo->qualifiers, i);
		THROW_DECODE_ERROR_IF(sslObject == NULL);
		PolicyQualifierInfo policyQualifierInfo(sslObject);
		this->policyQualifiers.push_back(std::move(policyQualifierInfo));
	}
}

PolicyInformation::~PolicyInformation()
{
}

void PolicyInformation::setPolicyIdentifier(const ObjectIdentifier& policyIdentifier)
{
	this->policyIdentifier = policyIdentifier;
}

const ObjectIdentifier& PolicyInformation::getPolicyIdentifier() const
{
	return this->policyIdentifier;
}

void PolicyInformation::addPolicyQualifierInfo(const PolicyQualifierInfo& policyQualifierInfo)
{
	this->policyQualifiers.push_back(policyQualifierInfo);
}

const std::vector<PolicyQualifierInfo>& PolicyInformation::getPoliciesQualifierInfo() const
{
	return this->policyQualifiers;
}

POLICYINFO* PolicyInformation::getSslObject() const
{
	POLICYINFO *ret = POLICYINFO_new();
	THROW_ENCODE_ERROR_IF(ret == NULL);

	try {
		ret->policyid = this->policyIdentifier.getSslObject();
	} catch (...) {
		POLICYINFO_free(ret);
		throw;
	}

	ret->qualifiers = sk_POLICYQUALINFO_new_null();
	THROW_ENCODE_ERROR_AND_FREE_IF(ret->qualifiers == NULL,
			POLICYINFO_free(ret);
	);

	for (auto policyQualifier : this->policyQualifiers) {
		POLICYQUALINFO *policyQualInfo = NULL;

		try {
			policyQualInfo = policyQualifier.getPolicyQualInfo();
		} catch (...) {
			POLICYINFO_free(ret);
			throw;
		}

		int rc = sk_POLICYQUALINFO_push(ret->qualifiers, policyQualInfo);
		THROW_ENCODE_ERROR_AND_FREE_IF(rc == 0,
				POLICYINFO_free(ret);
				POLICYQUALINFO_free(policyQualInfo);
		);
	}

	return ret;
}

std::string PolicyInformation::toXml(const std::string& tab) const
{
	std::string ret;
	ret = tab + "<policyInformation>\n";
	ret += this->policyIdentifier.toXml(tab + "\t");
	for (auto policyQualifier : this->policyQualifiers) {
		ret += policyQualifier.getXmlEncoded(tab + "\t");
	}
	ret += tab + "</policyInformation>\n";
	return ret;
}

