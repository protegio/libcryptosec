#include <libcryptosec/certificate/ObjectIdentifier.h>

ObjectIdentifier::ObjectIdentifier() :
		asn1Object(ASN1_OBJECT_new())
{
}

ObjectIdentifier::ObjectIdentifier(const ASN1_OBJECT *asn1Object) :
		asn1Object(OBJ_dup(asn1Object))
{
}

ObjectIdentifier::ObjectIdentifier(ASN1_OBJECT *asn1Object) :
		asn1Object(asn1Object)
{
}

ObjectIdentifier::ObjectIdentifier(const ObjectIdentifier& objectIdentifier) :
		asn1Object(OBJ_dup(objectIdentifier.asn1Object))
{
}

ObjectIdentifier::ObjectIdentifier(ObjectIdentifier&& objectIdentifier) :
		asn1Object(objectIdentifier.asn1Object)
{
	objectIdentifier.asn1Object = nullptr;
}

ObjectIdentifier::~ObjectIdentifier()
{
	if (this->asn1Object) {
		ASN1_OBJECT_free(this->asn1Object);
	}
}

ObjectIdentifier& ObjectIdentifier::operator=(const ObjectIdentifier& value)
{
	if (&value == this) {
		return *this;
	}

	if (this->asn1Object) {
		ASN1_OBJECT_free(this->asn1Object);
	}

	this->asn1Object = OBJ_dup(value.asn1Object);

	return *this;
}

ObjectIdentifier& ObjectIdentifier::operator=(ObjectIdentifier&& value)
{
	if (&value == this) {
		return *this;
	}

	if (this->asn1Object) {
		ASN1_OBJECT_free(this->asn1Object);
	}

	this->asn1Object = value.asn1Object;
	value.asn1Object = nullptr;

	return *this;
}

std::string ObjectIdentifier::getXmlEncoded(const std::string& tab) const
{
	std::string ret, oid;
	try {
		oid = this->getOid();
	} catch (...) {
		oid = "";
	}
	ret = tab + "<oid>" + oid + "</oid>\n";
	return ret;
}

std::string ObjectIdentifier::getOid() const
{
	char data[30];
	if (!OBJ_get0_data(this->asn1Object)) {
		throw CertificationException(CertificationException::SET_NO_VALUE, "ObjectIdentifier::getOid");
	}
	OBJ_obj2txt(data, 30, this->asn1Object, 1);
	return std::string(data);
}

int ObjectIdentifier::getNid() const
{
	return OBJ_obj2nid(this->asn1Object);
}

std::string ObjectIdentifier::getName() const
{
	std::string ret;
	if (!OBJ_get0_data(this->asn1Object)) {
		return "undefined";
	}

	int nid = OBJ_obj2nid(this->asn1Object);
	if (nid != NID_undef) {
		ret = OBJ_nid2sn(nid);
	} else {
		ret = this->getOid();
	}

	return ret;
}

ASN1_OBJECT* ObjectIdentifier::getObjectIdentifier() const
{
	return OBJ_dup(this->asn1Object);
}
