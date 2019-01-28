#include <libcryptosec/certificate/extension/AuthorityInformationAccessExtension.h>

#include <libcryptosec/certificate/ObjectIdentifierFactory.h>
#include <libcryptosec/exception/CertificationException.h>

AuthorityInformationAccessExtension::AuthorityInformationAccessExtension() :
		Extension()
{
	this->objectIdentifier = ObjectIdentifierFactory::getObjectIdentifier(NID_info_access);
}

AuthorityInformationAccessExtension::AuthorityInformationAccessExtension(const X509_EXTENSION* ext) :
		Extension(ext)
{
	THROW_DECODE_ERROR_IF(this->getName() != Extension::AUTHORITY_INFORMATION_ACCESS);

	AUTHORITY_INFO_ACCESS *sslObjectStack = (AUTHORITY_INFO_ACCESS*) X509V3_EXT_d2i((X509_EXTENSION*) ext);
	THROW_DECODE_ERROR_IF(sslObjectStack == NULL);

	int num = sk_ACCESS_DESCRIPTION_num(sslObjectStack);
	for (int i = 0; i < num; i++) {
		const ACCESS_DESCRIPTION *sslObject = (const ACCESS_DESCRIPTION*) sk_ACCESS_DESCRIPTION_value(sslObjectStack, i);
		THROW_DECODE_ERROR_AND_FREE_IF(sslObject == NULL,
				AUTHORITY_INFO_ACCESS_free(sslObjectStack);
		);

		try {
			AccessDescription accessDescription(sslObject);
			this->accessDescriptions.push_back(std::move(accessDescription));
		} catch (...) {
			AUTHORITY_INFO_ACCESS_free(sslObjectStack);
			throw;
		}
	}

	AUTHORITY_INFO_ACCESS_free(sslObjectStack);
}

AuthorityInformationAccessExtension::~AuthorityInformationAccessExtension() {
}


void AuthorityInformationAccessExtension::addAccessDescription(const AccessDescription& accessDescription)
{
	this->accessDescriptions.push_back(accessDescription);
}

const std::vector<AccessDescription>& AuthorityInformationAccessExtension::getAccessDescriptions() const
{
	return this->accessDescriptions;
}

std::string AuthorityInformationAccessExtension::extValue2Xml(const std::string& tab) const
{
	std::string ret, string;
	ret = tab + "<accessDescriptions>\n";
	for (auto accessDescription : this->accessDescriptions) {
		string = accessDescription.getXmlEncoded(tab + "\t");
		ret += string;
	}
	ret += tab + "</accessDescriptions>\n";
	return ret;
}

X509_EXTENSION* AuthorityInformationAccessExtension::getX509Extension() const
{
	AUTHORITY_INFO_ACCESS *sslObjectStack = AUTHORITY_INFO_ACCESS_new();
	THROW_ENCODE_ERROR_IF(sslObjectStack == NULL);

	for (auto accessDescription : this->accessDescriptions) {
		ACCESS_DESCRIPTION *sslObject = NULL;

		try {
			sslObject = accessDescription.getSslObject();
		} catch (...) {
			AUTHORITY_INFO_ACCESS_free(sslObjectStack);
			throw;
		}

		int rc = sk_ACCESS_DESCRIPTION_push(sslObjectStack, sslObject);
		THROW_ENCODE_ERROR_AND_FREE_IF(rc == 0,
				ACCESS_DESCRIPTION_free(sslObject);
				AUTHORITY_INFO_ACCESS_free(sslObjectStack);
		);
	}

	X509_EXTENSION *ret = X509V3_EXT_i2d(NID_info_access, this->critical ? 1 : 0, (void*) sslObjectStack);
	AUTHORITY_INFO_ACCESS_free(sslObjectStack);
	THROW_ENCODE_ERROR_IF(ret == NULL);

	return ret;
}
