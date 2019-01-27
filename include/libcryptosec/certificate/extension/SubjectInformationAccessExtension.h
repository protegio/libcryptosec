#ifndef SUBJECTINFORMATIONACCESSEXTENSION_H_
#define SUBJECTINFORMATIONACCESSEXTENSION_H_

#include <libcryptosec/certificate/extension/Extension.h>

#include <libcryptosec/certificate/AccessDescription.h>

class SubjectInformationAccessExtension : public Extension
{
public:
	enum AccessMethod
	{
		CA_REPOSITORY = NID_caRepository,
		TIME_STAMPING = NID_ad_timeStamping,
	};

	SubjectInformationAccessExtension();
	SubjectInformationAccessExtension(const X509_EXTENSION* ext);

	virtual ~SubjectInformationAccessExtension();

	void addAccessDescription(const AccessDescription& accessDescription);
	const std::vector<AccessDescription>& getAccessDescriptions() const;

	virtual std::string extValue2Xml(const std::string& tab = "") const;

	virtual X509_EXTENSION* getX509Extension() const;

protected:
	std::vector<AccessDescription> accessDescriptions;
};

#endif /* SUBJECTINFORMATIONACCESSEXTENSION_H_ */
