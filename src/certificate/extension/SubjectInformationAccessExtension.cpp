#include <libcryptosec/certificate/extension/SubjectInformationAccessExtension.h>

#include <libcryptosec/certificate/ObjectIdentifierFactory.h>
#include <libcryptosec/exception/CertificationException.h>

SubjectInformationAccessExtension::SubjectInformationAccessExtension() :
		Extension()
{
	this->objectIdentifier = ObjectIdentifierFactory::getObjectIdentifier(NID_sinfo_access);
}

SubjectInformationAccessExtension::SubjectInformationAccessExtension(const X509_EXTENSION *ext) :
		Extension(ext)
{
	const ASN1_OBJECT* object = X509_EXTENSION_get_object((X509_EXTENSION*) ext);
	int nid = OBJ_obj2nid(object);
	if (nid != NID_sinfo_access) {
		throw CertificationException(CertificationException::INVALID_TYPE, "SubjectInformationAccessExtension::SubjectInformationAccessExtension");
	}

	STACK_OF(ACCESS_DESCRIPTION) *subjectInfoAccess = (STACK_OF(ACCESS_DESCRIPTION) *) X509V3_EXT_d2i((X509_EXTENSION*) ext);
	if (subjectInfoAccess == NULL) {
		throw CertificationException("" /* TODO */);
	}

	int num = sk_ACCESS_DESCRIPTION_num(subjectInfoAccess);
	for (int i = 0; i < num; i++) {
		AccessDescription accessDescription((ACCESS_DESCRIPTION *)sk_ACCESS_DESCRIPTION_value(subjectInfoAccess, i));
		this->accessDescriptions.push_back(std::move(accessDescription));
	}

	sk_ACCESS_DESCRIPTION_free(subjectInfoAccess);
}

SubjectInformationAccessExtension::SubjectInformationAccessExtension(const SubjectInformationAccessExtension& ext) :
		Extension(ext), accessDescriptions(ext.accessDescriptions)
{

}

SubjectInformationAccessExtension::SubjectInformationAccessExtension(SubjectInformationAccessExtension&& ext) :
		Extension(std::move(ext)), accessDescriptions(std::move(ext.accessDescriptions))
{

}

SubjectInformationAccessExtension::~SubjectInformationAccessExtension() {
}

SubjectInformationAccessExtension& SubjectInformationAccessExtension::operator=(const SubjectInformationAccessExtension& ext) {
	if (&ext == this) {
		return *this;
	}

	this->accessDescriptions = ext.accessDescriptions;
	return static_cast<SubjectInformationAccessExtension&>(Extension::operator=(ext));
}

SubjectInformationAccessExtension& SubjectInformationAccessExtension::operator=(SubjectInformationAccessExtension&& ext) {
	if (&ext == this) {
		return *this;
	}

	this->accessDescriptions = std::move(ext.accessDescriptions);
	return static_cast<SubjectInformationAccessExtension&>(Extension::operator=(std::move(ext)));
}

void SubjectInformationAccessExtension::addAccessDescription(const AccessDescription& accessDescription) {
	accessDescriptions.push_back(accessDescription);
}

const std::vector<AccessDescription>& SubjectInformationAccessExtension::getAccessDescriptions() const {
	return accessDescriptions;
}

std::string SubjectInformationAccessExtension::getXmlEncoded(const std::string& tab) const
{
	std::string ret, string;
	ret = tab + "<subjectInformationAccess>\n";
		ret += tab + "\t<extnID>" + this->getName() + "</extnID>\n";
		string = (this->isCritical())?"yes":"no";
		ret += tab + "\t<critical>" + string + "</critical>\n";
		ret += tab + "\t<extnValue>\n";
			ret += tab + "\t\t<accessDescriptions>\n";
			for (auto accessDescription : this->accessDescriptions) {
				string = accessDescription.getXmlEncoded(tab + "\t\t\t");
				ret += string;
			}
			ret += tab + "\t\t</accessDescriptions>\n";
		ret += tab + "\t</extnValue>\n";
	ret += tab + "</subjectInformationAccess>\n";
	return ret;
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
	STACK_OF(ACCESS_DESCRIPTION) *subjectInfoAccess = sk_ACCESS_DESCRIPTION_new_null();
	if (subjectInfoAccess == NULL) {
		throw CertificationException("" /* TODO */);
	}

	for (auto accessDescription : this->accessDescriptions) {
		int rc = sk_ACCESS_DESCRIPTION_push(subjectInfoAccess, accessDescription.getAccessDescription());
		if (rc == 0) {
			throw CertificationException("" /* TODO */);
		}
	}

	X509_EXTENSION *ret = X509V3_EXT_i2d(NID_sinfo_access, this->critical ? 1 : 0, (void*) subjectInfoAccess);
	sk_ACCESS_DESCRIPTION_free(subjectInfoAccess);

	return ret;
}
