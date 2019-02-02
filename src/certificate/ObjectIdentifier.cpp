#include <libcryptosec/certificate/ObjectIdentifier.h>

#include <libcryptosec/Macros.h>
#include <libcryptosec/exception/CertificationException.h>

ObjectIdentifier::ObjectIdentifier(ASN1_OBJECT *asn1Object) :
		asn1Object(asn1Object)
{
	THROW_DECODE_ERROR_IF(this->asn1Object == NULL);
}

ObjectIdentifier::ObjectIdentifier() :
		asn1Object(ASN1_OBJECT_new())
{
	THROW_DECODE_ERROR_IF(this->asn1Object == NULL);
}

ObjectIdentifier::ObjectIdentifier(const ASN1_OBJECT *asn1Object) :
		asn1Object(OBJ_dup(asn1Object))
{
	THROW_DECODE_ERROR_IF(this->asn1Object == NULL);
}

ObjectIdentifier::ObjectIdentifier(const ObjectIdentifier& objectIdentifier) :
		asn1Object(OBJ_dup(objectIdentifier.asn1Object))
{
	THROW_DECODE_ERROR_IF(this->asn1Object == NULL);
}

ObjectIdentifier::ObjectIdentifier(ObjectIdentifier&& objectIdentifier) :
		asn1Object(objectIdentifier.asn1Object)
{
	THROW_DECODE_ERROR_IF(this->asn1Object == NULL);
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

	ASN1_OBJECT *oid = OBJ_dup(value.asn1Object);
	THROW_DECODE_ERROR_IF(oid == NULL);

	if (this->asn1Object) {
		ASN1_OBJECT_free(this->asn1Object);
	}

	this->asn1Object = oid;

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

int ObjectIdentifier::getNid() const
{
	return OBJ_obj2nid(this->asn1Object);
}

std::string ObjectIdentifier::getShortName() const
{
	const unsigned char *data = OBJ_get0_data(this->asn1Object);
	if (data == NULL) {
		return "undefined";
	}

	int nid = OBJ_obj2nid(this->asn1Object);
	// The next function returns NULL if nid == NID_undef

	const char *shortName = OBJ_nid2sn(nid);
	if (data == NULL) {
		return this->toString();
	} else {
		return std::string(shortName);
	}
}

std::string ObjectIdentifier::getLongName() const
{
	const unsigned char *data = OBJ_get0_data(this->asn1Object);
	if (data == NULL) {
		return "undefined";
	}

	int nid = OBJ_obj2nid(this->asn1Object);
	// The next function returns NULL if nid == NID_undef

	const char *longName = OBJ_nid2ln(nid);
	if (data == NULL) {
		return this->toString();
	} else {
		return std::string(longName);
	}
}

const ASN1_OBJECT* ObjectIdentifier::getAsn1Object() const
{
	return this->asn1Object;
}

ASN1_OBJECT* ObjectIdentifier::getSslObject() const
{
	ASN1_OBJECT *oid =  OBJ_dup(this->asn1Object);
	THROW_ENCODE_ERROR_IF(oid == NULL);
	return oid;
}

std::string ObjectIdentifier::toString() const
{
	const unsigned char *data = OBJ_get0_data(this->asn1Object);
	THROW_DECODE_ERROR_IF(data == NULL);
	int size = OBJ_obj2txt(0, 0, this->asn1Object, 1);
	char str[size];
	OBJ_obj2txt(str, size, this->asn1Object, 1);
	return std::string((const char*) data);
}

std::string ObjectIdentifier::toXml(const std::string& tab) const
{
	std::string ret, oid;
	try {
		oid = this->toString();
	} catch (...) {
		oid = "";
	}
	ret = tab + "<oid>" + oid + "</oid>\n";
	return ret;
}


ObjectIdentifier ObjectIdentifier::fromString(const std::string& oid)
{
	ASN1_OBJECT *asn1Obj = OBJ_txt2obj(oid.c_str(), 1);
	THROW_DECODE_ERROR_IF(asn1Obj == NULL);
	return ObjectIdentifier(asn1Obj);
}

ObjectIdentifier ObjectIdentifier::fromNid(int nid)
{
	ASN1_OBJECT *asn1Obj = OBJ_nid2obj(nid);
	THROW_DECODE_ERROR_IF(asn1Obj == NULL);
	return ObjectIdentifier(asn1Obj);
}

ObjectIdentifier ObjectIdentifier::fromShortName(const std::string& name)
{
	int nid = OBJ_sn2nid(name.c_str());
	return ObjectIdentifier::fromNid(nid);
}

ObjectIdentifier ObjectIdentifier::fromLongName(const std::string& name)
{
	int nid = OBJ_ln2nid(name.c_str());
	return ObjectIdentifier::fromNid(nid);
}

