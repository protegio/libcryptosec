#ifndef AUTHORITYINFORMATIONACCESSEXTENSION_H_
#define AUTHORITYINFORMATIONACCESSEXTENSION_H_

#include <libcryptosec/certificate/extension/Extension.h>

#include <libcryptosec/certificate/AccessDescription.h>

class AuthorityInformationAccessExtension : public Extension {
public:
	enum AccessMethod
	{
		CA_ISSUER = NID_ad_ca_issuers,
		OCSP = NID_ad_OCSP,
	};

	AuthorityInformationAccessExtension();
	AuthorityInformationAccessExtension(const X509_EXTENSION *ext);

	virtual ~AuthorityInformationAccessExtension();

	void addAccessDescription(const AccessDescription& accessDescription);
	const std::vector<AccessDescription>& getAccessDescriptions() const;

	virtual std::string extValue2Xml(const std::string& tab = "") const;

	// TODO: implementar
	virtual X509_EXTENSION* getX509Extension() const;

protected:
	std::vector<AccessDescription> accessDescriptions;
};

#endif /* AUTHORITYINFORMATIONACCESSEXTENSION_H_ */
