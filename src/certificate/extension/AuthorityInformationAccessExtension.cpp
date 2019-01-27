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
	ASN1_OBJECT *object = X509_EXTENSION_get_object((X509_EXTENSION*) ext);
	if (object == NULL) {
		throw CertificationException("" /* TODO */);
	}

	int nid = OBJ_obj2nid(object);
	if (nid != NID_info_access) {
		throw CertificationException(CertificationException::INVALID_TYPE, "AuthorityInformationAccessExtension::AuthorityInformationAccessExtension");
	}

	AUTHORITY_INFO_ACCESS *authorityInfoAccess = (AUTHORITY_INFO_ACCESS *) X509V3_EXT_d2i((X509_EXTENSION*) ext);
	if (authorityInfoAccess == NULL) {
		throw CertificationException("" /* TODO */);
	}

	int num = sk_ACCESS_DESCRIPTION_num(authorityInfoAccess);
	for (int i = 0; i < num; i++) {
		ACCESS_DESCRIPTION *sslAccessDescription = (ACCESS_DESCRIPTION *) sk_ACCESS_DESCRIPTION_value(authorityInfoAccess, i);
		if (sslAccessDescription == NULL) {
			throw CertificationException("" /* TODO */);
		}

		AccessDescription accessDescription(sslAccessDescription);
		this->accessDescriptions.push_back(accessDescription);
	}

	AUTHORITY_INFO_ACCESS_free(authorityInfoAccess);
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

std::string AuthorityInformationAccessExtension::getXmlEncoded(const std::string& tab) const
{
	std::string ret, string;
	ret = tab + "<authorityInformationAccess>\n";
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
	ret += tab + "</authorityInformationAccess>\n";
	return ret;
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
	AUTHORITY_INFO_ACCESS *authorityInfoAccess = AUTHORITY_INFO_ACCESS_new();
	if (authorityInfoAccess == NULL) {
		throw CertificationException("" /* TODO */);
	}

	for (auto accessDescription : this->accessDescriptions) {
		sk_ACCESS_DESCRIPTION_push(authorityInfoAccess, accessDescription.getAccessDescription());
	}

	X509_EXTENSION *ret = X509V3_EXT_i2d(NID_info_access, this->critical?1:0, (void *)authorityInfoAccess);
	if (ret == NULL) {
		throw CertificationException("" /* TODO */);
	}

	AUTHORITY_INFO_ACCESS_free(authorityInfoAccess);
	return ret;
}
