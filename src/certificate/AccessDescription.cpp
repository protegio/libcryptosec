#include <libcryptosec/certificate/AccessDescription.h>

AccessDescription::AccessDescription() {
}

AccessDescription::AccessDescription(const ACCESS_DESCRIPTION* accessDescription) {
	if(accessDescription->method) {
		const ASN1_OBJECT *oid = accessDescription->method;
		this->accessMethod = ObjectIdentifier(oid);
	}

	if(accessDescription->location) {
		const GENERAL_NAME *generalName = accessDescription->location;
		this->accessLocation = GeneralName(generalName);
	}
}

AccessDescription::~AccessDescription() {
}


void AccessDescription::setAccessLocation(const GeneralName& accessLocation)
{
    this->accessLocation = accessLocation;
}

void AccessDescription::setAccessMethod(const ObjectIdentifier& accessMethod)
{
    this->accessMethod = accessMethod;
}

const GeneralName& AccessDescription::getAccessLocation() const
{
    return accessLocation;
}

const ObjectIdentifier& AccessDescription::getAccessMethod() const
{
    return accessMethod;
}

std::string AccessDescription::getXmlEncoded(const std::string& tab) const
{
	std::string ret;
	ret = tab + "<accessDescription>\n";
	ret += this->accessMethod.getXmlEncoded(tab + "\t");
	ret += this->accessLocation.getXmlEncoded(tab + "\t");
	ret += tab + "</accessDescription>\n";
	return ret;
}

ACCESS_DESCRIPTION* AccessDescription::getAccessDescription() const {
	ACCESS_DESCRIPTION* accessDescription = ACCESS_DESCRIPTION_new();
	accessDescription->method = accessMethod.getObjectIdentifier();
	accessDescription->location = accessLocation.getGeneralName();
	return accessDescription;
}

