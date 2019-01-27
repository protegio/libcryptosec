#ifndef CERTIFICATEPOLICIESEXTENSION_H_
#define CERTIFICATEPOLICIESEXTENSION_H_

#include <libcryptosec/certificate/extension/Extension.h>

#include <libcryptosec/certificate/PolicyInformation.h>

class CertificatePoliciesExtension : public Extension
{
public:
	CertificatePoliciesExtension();
	CertificatePoliciesExtension(const X509_EXTENSION* ext);

	virtual ~CertificatePoliciesExtension();
	
	void addPolicyInformation(const PolicyInformation& policyInformation);
	const std::vector<PolicyInformation>& getPoliciesInformation() const;

	/**
	 * @deprecated
	 * Retorna o conteudo da extensão em formato XML.
	 * Esta função será substituida por toXml().
	 * */
	virtual std::string getXmlEncoded(const std::string& tab = "") const;
	virtual std::string extValue2Xml(const std::string& tab = "") const;

	virtual X509_EXTENSION* getX509Extension() const;

protected:
	std::vector<PolicyInformation> policiesInformation;
};

#endif /*CERTIFICATEPOLICIESEXTENSION_H_*/
