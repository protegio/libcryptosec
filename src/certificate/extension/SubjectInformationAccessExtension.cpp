#include <libcryptosec/certificate/extension/SubjectInformationAccessExtension.h>

#include <libcryptosec/certificate/ObjectIdentifier.h>
#include <libcryptosec/Macros.h>
#include <libcryptosec/exception/CertificationException.h>

SubjectInformationAccessExtension::SubjectInformationAccessExtension() :
		Extension()
{
	this->objectIdentifier = ObjectIdentifier::fromNid(NID_sinfo_access);
}

SubjectInformationAccessExtension::SubjectInformationAccessExtension(const X509_EXTENSION *ext) :
		Extension(ext)
{
	THROW_DECODE_ERROR_IF(this->getName() != Extension::SUBJECT_INFORMATION_ACCESS);

	STACK_OF(ACCESS_DESCRIPTION) *sslObjectStack = (STACK_OF(ACCESS_DESCRIPTION) *) X509V3_EXT_d2i((X509_EXTENSION*) ext);
	THROW_DECODE_ERROR_IF(sslObjectStack == NULL);

	int num = sk_ACCESS_DESCRIPTION_num(sslObjectStack);
	for (int i = 0; i < num; i++) {
		const ACCESS_DESCRIPTION *sslObject = (const ACCESS_DESCRIPTION*) sk_ACCESS_DESCRIPTION_value(sslObjectStack, i);
		THROW_DECODE_ERROR_AND_FREE_IF(sslObject == NULL,
				sk_ACCESS_DESCRIPTION_pop_free(sslObjectStack, ACCESS_DESCRIPTION_free);
		);

		try {
			AccessDescription accessDescription(sslObject);
			this->accessDescriptions.push_back(std::move(accessDescription));
		} catch (...) {
			sk_ACCESS_DESCRIPTION_pop_free(sslObjectStack, ACCESS_DESCRIPTION_free);
			throw;
		}
	}

	sk_ACCESS_DESCRIPTION_pop_free(sslObjectStack, ACCESS_DESCRIPTION_free);
}

SubjectInformationAccessExtension::~SubjectInformationAccessExtension() {
}

void SubjectInformationAccessExtension::addAccessDescription(const AccessDescription& accessDescription) {
	accessDescriptions.push_back(accessDescription);
}

const std::vector<AccessDescription>& SubjectInformationAccessExtension::getAccessDescriptions() const {
	return accessDescriptions;
}

std::string SubjectInformationAccessExtension::extValue2Xml(const std::string& tab) const
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

X509_EXTENSION* SubjectInformationAccessExtension::getX509Extension() const {
	STACK_OF(ACCESS_DESCRIPTION) *sslObjectStack = sk_ACCESS_DESCRIPTION_new_null();
	THROW_ENCODE_ERROR_IF(sslObjectStack == NULL);

	for (auto accessDescription : this->accessDescriptions) {
		ACCESS_DESCRIPTION *sslObject = NULL;

		try {
			sslObject = accessDescription.getSslObject();
		} catch (...) {
			sk_ACCESS_DESCRIPTION_pop_free(sslObjectStack, ACCESS_DESCRIPTION_free);
			throw;
		}

		int rc = sk_ACCESS_DESCRIPTION_push(sslObjectStack, sslObject);
		THROW_ENCODE_ERROR_AND_FREE_IF(rc == 0,
				ACCESS_DESCRIPTION_free(sslObject);
				sk_ACCESS_DESCRIPTION_pop_free(sslObjectStack, ACCESS_DESCRIPTION_free);
		);
	}

	X509_EXTENSION *ret = X509V3_EXT_i2d(NID_sinfo_access, this->critical ? 1 : 0, (void*) sslObjectStack);
	sk_ACCESS_DESCRIPTION_pop_free(sslObjectStack, ACCESS_DESCRIPTION_free);
	THROW_ENCODE_ERROR_IF(ret == NULL);

	return ret;
}
