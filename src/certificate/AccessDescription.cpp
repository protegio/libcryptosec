#include <libcryptosec/certificate/AccessDescription.h>

#include <libcryptosec/Macros.h>
#include <libcryptosec/exception/CertificationException.h>

AccessDescription::AccessDescription() {
}

AccessDescription::AccessDescription(const ACCESS_DESCRIPTION* accessDescription)
{
	THROW_DECODE_ERROR_IF(accessDescription == NULL);

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
	ret += this->accessMethod.toXml(tab + "\t");
	ret += this->accessLocation.toXml(tab + "\t");
	ret += tab + "</accessDescription>\n";
	return ret;
}

ACCESS_DESCRIPTION* AccessDescription::getSslObject() const {
	ACCESS_DESCRIPTION* sslObject = ACCESS_DESCRIPTION_new();
	THROW_ENCODE_ERROR_IF(sslObject == NULL);
	sslObject->method = this->accessMethod.getSslObject();
	sslObject->location = this->accessLocation.getSslObject();
	return sslObject;
}

