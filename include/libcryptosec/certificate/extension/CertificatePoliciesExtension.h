#ifndef CERTIFICATEPOLICIESEXTENSION_H_
#define CERTIFICATEPOLICIESEXTENSION_H_

#include <libcryptosec/certificate/extension/Extension.h>

#include <libcryptosec/certificate/PolicyInformation.h>

class CertificatePoliciesExtension : public Extension
{
public:
	CertificatePoliciesExtension();
	CertificatePoliciesExtension(X509_EXTENSION *ext);
	virtual ~CertificatePoliciesExtension();
	
	/**
	 * @deprecated
	 * Retorna o conteudo da extensão em formato XML.
	 * Esta função será substituida por toXml().
	 * */
	std::string getXmlEncoded();
	std::string getXmlEncoded(std::string tab);
	virtual std::string extValue2Xml(std::string tab = "");
	void addPolicyInformation(PolicyInformation &policyInformation);
	std::vector<PolicyInformation> getPoliciesInformation();
	X509_EXTENSION* getX509Extension();
protected:
	std::vector<PolicyInformation> policiesInformation;
};

#endif /*CERTIFICATEPOLICIESEXTENSION_H_*/
