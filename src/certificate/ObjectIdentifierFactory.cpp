#include <libcryptosec/certificate/ObjectIdentifierFactory.h>

#include <libcryptosec/exception/CertificationException.h>

#include <openssl/objects.h>

ObjectIdentifier ObjectIdentifierFactory::getObjectIdentifier(const std::string& oid)
{
	ASN1_OBJECT *asn1Obj = NULL;
	asn1Obj = OBJ_txt2obj(oid.c_str(), 1);
	if (!asn1Obj) {
		throw CertificationException(CertificationException::UNKNOWN_OID, "ObjectIdentifierFactory::getObjectIdentifier");
	}
	return std::move(ObjectIdentifier(asn1Obj));
}

ObjectIdentifier ObjectIdentifierFactory::getObjectIdentifier(int nid)
{
	ASN1_OBJECT *asn1Obj = OBJ_nid2obj(nid);
	if (!asn1Obj) {
		throw CertificationException(CertificationException::UNKNOWN_OID, "ObjectIdentifierFactory::getObjectIdentifier");
	}
	return std::move(ObjectIdentifier(asn1Obj));
}

// TODO: Isso parece errado. Pra que serve essa função?
ObjectIdentifier ObjectIdentifierFactory::createObjectIdentifier(const std::string& oid, const std::string& name)
{
	ASN1_OBJECT *asn1Obj = NULL;
	int nid = 0;

	ObjectIdentifierFactory::getObjectIdentifier(oid);

	nid = OBJ_create(oid.c_str(), name.c_str(), name.c_str());
	
	if (nid == NID_undef) {
		throw CertificationException(CertificationException::INTERNAL_ERROR, "ObjectIdentifierFactory::createObjectIdentifier");
	}

	asn1Obj = OBJ_nid2obj(nid);
	if (!asn1Obj) {
		throw CertificationException(CertificationException::INTERNAL_ERROR, "ObjectIdentifierFactory::createObjectIdentifier");
	}

	return ObjectIdentifier(asn1Obj);
}
