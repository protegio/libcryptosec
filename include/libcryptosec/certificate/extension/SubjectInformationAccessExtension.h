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
	SubjectInformationAccessExtension(const SubjectInformationAccessExtension& ext);
	SubjectInformationAccessExtension(SubjectInformationAccessExtension&& ext);

	virtual ~SubjectInformationAccessExtension();

	SubjectInformationAccessExtension& operator=(const SubjectInformationAccessExtension& ext);
	SubjectInformationAccessExtension& operator=(SubjectInformationAccessExtension&& ext);

	void addAccessDescription(const AccessDescription& accessDescription);
	const std::vector<AccessDescription>& getAccessDescriptions() const;

	/**
	 * @deprecated
	 * Retorna o conteudo da extensão em formato XML.
	 * Esta função será substituida por toXml().
	 * */
	std::string getXmlEncoded(const std::string& tab = "") const;
	virtual std::string extValue2Xml(const std::string& tab = "") const;

	X509_EXTENSION* getX509Extension() const;

protected:
	std::vector<AccessDescription> accessDescriptions;
};

#endif /* SUBJECTINFORMATIONACCESSEXTENSION_H_ */
