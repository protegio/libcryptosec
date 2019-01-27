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
	ASN1_OBJECT *object = X509_EXTENSION_get_object((X509_EXTENSION*) ext);
	if (object == NULL) {
		throw CertificationException("" /* TODO */);
	}

	int nid = OBJ_obj2nid(object);
	if (nid != NID_certificate_policies) {
		throw CertificationException(CertificationException::INVALID_TYPE, "CertificatePoliciesExtension::CertificatePoliciesExtension");
	}

	CERTIFICATEPOLICIES *certificatePolicies = (CERTIFICATEPOLICIES*) X509V3_EXT_d2i((X509_EXTENSION*) ext);
	if (certificatePolicies == NULL) {
		throw CertificationException("" /* TODO */);
	}

	int num = sk_POLICYINFO_num(certificatePolicies);
	for (int i = 0; i < num; i++) {
		PolicyInformation policyInformation(sk_POLICYINFO_value(certificatePolicies, i));
		this->policiesInformation.push_back(std::move(policyInformation));
	}

	CERTIFICATEPOLICIES_free(certificatePolicies);
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


std::string CertificatePoliciesExtension::getXmlEncoded(const std::string& tab) const
{
	unsigned int i;
	std::string ret, string;
	ret = tab + "<certificatePolicies>\n";
		ret += tab + "\t<extnID>" + this->getName() + "</extnID>\n";
		string = (this->isCritical())?"yes":"no";
		ret += tab + "\t<critical>" + string + "</critical>\n";
		ret += tab + "\t<extnValue>\n";
			for (auto policeInformation : this->policiesInformation) {
				ret += policeInformation.getXmlEncoded(tab + "\t\t");
			}
		ret += tab + "\t</extnValue>\n";
	ret += tab + "</certificatePolicies>\n";
	return ret;
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
	CERTIFICATEPOLICIES *certificatePolicies = CERTIFICATEPOLICIES_new();
	if (certificatePolicies == NULL) {
		throw CertificationException("" /* TODO */);
	}

	for (auto policeInformation : this->policiesInformation) {
		sk_POLICYINFO_push(certificatePolicies, policeInformation.getPolicyInfo());
	}

	X509_EXTENSION *ret = X509V3_EXT_i2d(NID_certificate_policies, this->critical ? 1 : 0, (void*) certificatePolicies);
	if (ret == NULL) {
		throw CertificationException("" /* TODO */);
	}

	sk_POLICYINFO_pop_free(certificatePolicies, POLICYINFO_free);

	return ret;
}
