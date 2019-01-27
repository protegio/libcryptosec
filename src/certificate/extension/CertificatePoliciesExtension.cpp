#include <libcryptosec/certificate/extension/CertificatePoliciesExtension.h>

#include <libcryptosec/exception/CertificationException.h>

CertificatePoliciesExtension::CertificatePoliciesExtension() :
		Extension()
{
	this->objectIdentifier = ObjectIdentifierFactory::getObjectIdentifier(NID_certificate_policies);
}

CertificatePoliciesExtension::CertificatePoliciesExtension(const X509_EXTENSION* ext) :
		Extension(ext)
{
	THROW_EXTENSION_DECODE_IF(this->getName() != Extension::CERTIFICATE_POLICIES);

	CERTIFICATEPOLICIES *sslObjectStack = (CERTIFICATEPOLICIES*) X509V3_EXT_d2i((X509_EXTENSION*) ext);
	THROW_EXTENSION_DECODE_IF(sslObjectStack == NULL);

	int num = sk_POLICYINFO_num(sslObjectStack);
	for (int i = 0; i < num; i++) {
		const POLICYINFO *sslObject = sk_POLICYINFO_value(sslObjectStack, i);
		THROW_EXTENSION_DECODE_AND_FREE_IF(sslObject == NULL,
				CERTIFICATEPOLICIES_free(sslObjectStack);
		);

		try {
			PolicyInformation policyInformation(sslObject);
			this->policiesInformation.push_back(std::move(policyInformation));
		} catch (...) {
			CERTIFICATEPOLICIES_free(sslObjectStack);
			throw;
		}
	}

	CERTIFICATEPOLICIES_free(sslObjectStack);
}

CertificatePoliciesExtension::~CertificatePoliciesExtension()
{
}

void CertificatePoliciesExtension::addPolicyInformation(const PolicyInformation& policyInformation)
{
	this->policiesInformation.push_back(policyInformation);
}

const std::vector<PolicyInformation>& CertificatePoliciesExtension::getPoliciesInformation() const
{
	return this->policiesInformation;
}

std::string CertificatePoliciesExtension::extValue2Xml(const std::string& tab) const
{
	std::string ret, string;
	for (auto policeInformation : this->policiesInformation) {
		ret += policeInformation.getXmlEncoded(tab);
	}
	return ret;
}

X509_EXTENSION* CertificatePoliciesExtension::getX509Extension() const
{
	CERTIFICATEPOLICIES *sslObjectStack = CERTIFICATEPOLICIES_new();
	THROW_EXTENSION_ENCODE_IF(sslObjectStack == NULL);

	for (auto policeInformation : this->policiesInformation) {
		POLICYINFO *sslObject = NULL;

		try {
			sslObject = policeInformation.getPolicyInfo();
		} catch (...) {
			CERTIFICATEPOLICIES_free(sslObjectStack);
			throw;
		}

		int rc = sk_POLICYINFO_push(sslObjectStack, sslObject);
		THROW_EXTENSION_ENCODE_AND_FREE_IF(rc == 0,
				POLICYINFO_free(sslObject);
				CERTIFICATEPOLICIES_free(sslObjectStack);
		);
	}

	X509_EXTENSION *ret = X509V3_EXT_i2d(NID_certificate_policies, this->critical ? 1 : 0, (void*) sslObjectStack);
	CERTIFICATEPOLICIES_free(sslObjectStack);
	THROW_EXTENSION_ENCODE_IF(ret == NULL);

	return ret;
}
